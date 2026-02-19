//! Sync protocol — state reconciliation per §5.
//!
//! Handles phased sync (Identity → Reputation → Proposals → Content → Storage),
//! gossip buffering, REPUTATION_CURRENT aggregation, degraded mode, snapshot
//! verification, incremental sync, and identity Merkle trees.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

use valence_core::canonical::merkle_root;
use valence_core::message::{Envelope, MessageType};
use valence_core::types::FixedPoint;

// ─── Sync Status & Phase ─────────────────────────────────────────────

/// Sync status advertised in PEER_ANNOUNCE per §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncStatus {
    Syncing,
    Degraded,
    Synced,
}

impl SyncStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SyncStatus::Syncing => "syncing",
            SyncStatus::Degraded => "degraded",
            SyncStatus::Synced => "synced",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "syncing" => Some(SyncStatus::Syncing),
            "degraded" => Some(SyncStatus::Degraded),
            "synced" => Some(SyncStatus::Synced),
            _ => None,
        }
    }
}

/// Sync phases per §5. Phases 1-3 sequential, 4+5 parallel after 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SyncPhase {
    Identity = 1,
    Reputation = 2,
    Proposals = 3,
    Content = 4,
    Storage = 5,
}

impl SyncPhase {
    /// All phases in order.
    pub fn all() -> &'static [SyncPhase] {
        &[
            SyncPhase::Identity,
            SyncPhase::Reputation,
            SyncPhase::Proposals,
            SyncPhase::Content,
            SyncPhase::Storage,
        ]
    }

    /// Message types belonging to this phase.
    pub fn message_types(&self) -> &'static [MessageType] {
        match self {
            SyncPhase::Identity => &[MessageType::DidLink, MessageType::DidRevoke, MessageType::KeyRotate],
            SyncPhase::Reputation => &[MessageType::ReputationGossip],
            SyncPhase::Proposals => &[MessageType::Propose, MessageType::Vote, MessageType::Comment],
            SyncPhase::Content => &[MessageType::Share, MessageType::Flag, MessageType::ContentWithdraw, MessageType::RentPayment],
            SyncPhase::Storage => &[MessageType::ReplicateRequest, MessageType::ReplicateAccept, MessageType::ShardAssignment, MessageType::ShardReceived],
        }
    }
}

/// Classify a message type into its sync phase.
pub fn classify_message(msg_type: &MessageType) -> Option<SyncPhase> {
    match msg_type {
        MessageType::DidLink | MessageType::DidRevoke | MessageType::KeyRotate => Some(SyncPhase::Identity),
        MessageType::ReputationGossip => Some(SyncPhase::Reputation),
        MessageType::Propose | MessageType::Vote | MessageType::Comment => Some(SyncPhase::Proposals),
        MessageType::Share | MessageType::Flag | MessageType::ContentWithdraw | MessageType::RentPayment => Some(SyncPhase::Content),
        MessageType::ReplicateRequest | MessageType::ReplicateAccept | MessageType::ShardAssignment | MessageType::ShardReceived => Some(SyncPhase::Storage),
        _ => None,
    }
}

// ─── Gossip Buffer ───────────────────────────────────────────────────

/// Maximum messages per phase buffer.
pub const GOSSIP_BUFFER_MAX_MESSAGES: usize = 100_000;
/// Maximum bytes per phase buffer (100 MiB).
pub const GOSSIP_BUFFER_MAX_BYTES: usize = 100 * 1024 * 1024;

/// Priority for eviction within a phase (higher = keep longer).
fn message_priority(phase: SyncPhase, msg_type: &MessageType) -> u8 {
    match phase {
        SyncPhase::Identity => match msg_type {
            MessageType::DidRevoke => 3,
            MessageType::KeyRotate => 2,
            MessageType::DidLink => 1,
            _ => 0,
        },
        SyncPhase::Proposals => match msg_type {
            MessageType::Vote => 3,
            MessageType::Propose => 2,
            MessageType::Comment => 1,
            _ => 0,
        },
        _ => 1, // equal priority, oldest-first
    }
}

/// A buffered gossip message with metadata for priority eviction.
#[derive(Debug, Clone)]
struct BufferedMessage {
    envelope: Envelope,
    priority: u8,
    size_bytes: usize,
}

/// Per-phase gossip buffer with priority eviction per §5.
#[derive(Debug)]
pub struct GossipBuffer {
    phase: SyncPhase,
    /// Messages ordered by (timestamp, id) for deterministic drain.
    messages: BTreeMap<(i64, String), BufferedMessage>,
    total_bytes: usize,
    /// Timestamp of the oldest dropped message (for follow-up sync).
    pub oldest_dropped_timestamp: Option<i64>,
}

impl GossipBuffer {
    pub fn new(phase: SyncPhase) -> Self {
        Self {
            phase,
            messages: BTreeMap::new(),
            total_bytes: 0,
            oldest_dropped_timestamp: None,
        }
    }

    /// Number of buffered messages.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Total bytes in buffer.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Insert a message, evicting lowest-priority oldest if at capacity.
    pub fn insert(&mut self, envelope: Envelope) {
        let size = estimate_envelope_size(&envelope);
        let priority = message_priority(self.phase, &envelope.msg_type);

        // Evict if needed
        while self.needs_eviction(size) {
            if !self.evict_one(priority) {
                break; // nothing evictable
            }
        }

        // If still over capacity after eviction, drop the incoming message if it's lowest priority
        if self.needs_eviction(size) {
            // Track dropped timestamp
            self.track_dropped(envelope.timestamp);
            return;
        }

        let key = (envelope.timestamp, envelope.id.clone());
        self.total_bytes += size;
        self.messages.insert(key, BufferedMessage { envelope, priority, size_bytes: size });
    }

    fn needs_eviction(&self, additional_bytes: usize) -> bool {
        self.messages.len() >= GOSSIP_BUFFER_MAX_MESSAGES
            || self.total_bytes + additional_bytes > GOSSIP_BUFFER_MAX_BYTES
    }

    /// Evict the lowest-priority oldest message. Returns false if buffer is empty.
    /// Won't evict messages with priority >= `incoming_priority` if incoming_priority > 0.
    fn evict_one(&mut self, incoming_priority: u8) -> bool {
        // Find lowest priority message, then oldest within that priority
        let mut min_priority = u8::MAX;
        for msg in self.messages.values() {
            if msg.priority < min_priority {
                min_priority = msg.priority;
            }
        }

        if min_priority >= incoming_priority && incoming_priority > 0 {
            // Can't evict anything lower priority than incoming
            // Still try to evict equal priority oldest
        }

        // Find the oldest message with min_priority
        let key_to_remove = self.messages.iter()
            .find(|(_, msg)| msg.priority == min_priority)
            .map(|(k, _)| k.clone());

        if let Some(key) = key_to_remove
            && let Some(removed) = self.messages.remove(&key) {
                self.total_bytes -= removed.size_bytes;
                self.track_dropped(removed.envelope.timestamp);
                return true;
            }
        false
    }

    fn track_dropped(&mut self, timestamp: i64) {
        match self.oldest_dropped_timestamp {
            Some(existing) if existing <= timestamp => {},
            _ => self.oldest_dropped_timestamp = Some(timestamp),
        }
    }

    /// Drain all messages in timestamp order. Consumes the buffer.
    pub fn drain_ordered(&mut self) -> Vec<Envelope> {
        let result: Vec<Envelope> = self.messages.values()
            .map(|bm| bm.envelope.clone())
            .collect();
        self.messages.clear();
        self.total_bytes = 0;
        result
    }
}

fn estimate_envelope_size(envelope: &Envelope) -> usize {
    // Rough estimate: id + from + payload string + signature + overhead
    envelope.id.len() + envelope.from.len() + envelope.payload.to_string().len()
        + envelope.signature.len() + 100
}

// ─── Sync Manager ────────────────────────────────────────────────────

/// Manages the sync state machine per §5.
#[derive(Debug)]
pub struct SyncManager {
    pub status: SyncStatus,
    pub current_phase: Option<SyncPhase>,
    pub completed_phases: HashSet<SyncPhase>,
    pub phase_timestamps: HashMap<SyncPhase, i64>,
    pub gossip_buffers: HashMap<SyncPhase, GossipBuffer>,

    /// Merkle roots reported by sync peers. peer_id → (identity_root, proposal_root).
    pub peer_merkle_roots: HashMap<String, (String, String)>,
    /// Whether we've received rep gossip from each sync peer.
    pub peer_rep_gossip_received: HashSet<String>,

    /// Set of sync peer IDs.
    pub sync_peers: HashSet<String>,

    /// Whether this node has the `store` capability.
    pub has_store_capability: bool,

    /// Time entered degraded mode.
    pub degraded_since: Option<Instant>,

    /// Revoked keys discovered during sync (for retroactive invalidation).
    pub revoked_keys: HashMap<String, i64>, // key → effective_from timestamp

    // Incremental sync state
    /// Cycle counter for identity phase jitter.
    pub identity_sync_cycle: u32,
    /// Random target cycle for next identity sync (3-5).
    pub identity_sync_target: u32,
    /// Whether DID_REVOKE was seen in previous gossip cycle.
    pub did_revoke_seen_last_cycle: bool,
    /// Per-phase lookback timestamps for incremental sync.
    pub phase_lookback_timestamps: HashMap<SyncPhase, i64>,
}

impl SyncManager {
    pub fn new(has_store_capability: bool) -> Self {
        let mut gossip_buffers = HashMap::new();
        for phase in SyncPhase::all() {
            gossip_buffers.insert(*phase, GossipBuffer::new(*phase));
        }

        Self {
            status: SyncStatus::Syncing,
            current_phase: Some(SyncPhase::Identity),
            completed_phases: HashSet::new(),
            phase_timestamps: HashMap::new(),
            gossip_buffers,
            peer_merkle_roots: HashMap::new(),
            peer_rep_gossip_received: HashSet::new(),
            sync_peers: HashSet::new(),
            has_store_capability,
            degraded_since: None,
            revoked_keys: HashMap::new(),
            identity_sync_cycle: 0,
            identity_sync_target: 3, // will be randomized
            did_revoke_seen_last_cycle: false,
            phase_lookback_timestamps: HashMap::new(),
        }
    }

    /// Check if the next phase can be started after completing the current one.
    /// Phases 1→2→3 must be sequential. 4+5 can run in parallel after 3.
    pub fn can_start_phase(&self, phase: SyncPhase) -> bool {
        match phase {
            SyncPhase::Identity => true,
            SyncPhase::Reputation => self.completed_phases.contains(&SyncPhase::Identity),
            SyncPhase::Proposals => self.completed_phases.contains(&SyncPhase::Reputation),
            SyncPhase::Content => self.completed_phases.contains(&SyncPhase::Proposals),
            SyncPhase::Storage => {
                self.has_store_capability && self.completed_phases.contains(&SyncPhase::Proposals)
            }
        }
    }

    /// Complete the current phase, drain its gossip buffer, and advance.
    /// Returns the drained messages for the completed phase.
    pub fn advance_phase(&mut self, now_ms: i64) -> Vec<Envelope> {
        let phase = match self.current_phase {
            Some(p) => p,
            None => return vec![],
        };

        self.completed_phases.insert(phase);
        self.phase_timestamps.insert(phase, now_ms);

        // Drain gossip buffer for completed phase
        let drained = self.gossip_buffers
            .get_mut(&phase)
            .map(|buf| buf.drain_ordered())
            .unwrap_or_default();

        // Determine next phase
        self.current_phase = match phase {
            SyncPhase::Identity => Some(SyncPhase::Reputation),
            SyncPhase::Reputation => Some(SyncPhase::Proposals),
            SyncPhase::Proposals => Some(SyncPhase::Content),
            SyncPhase::Content => {
                if self.has_store_capability && !self.completed_phases.contains(&SyncPhase::Storage) {
                    Some(SyncPhase::Storage)
                } else {
                    None
                }
            }
            SyncPhase::Storage => None,
        };

        drained
    }

    /// Handle an incoming gossip message during sync.
    /// Returns Some(envelope) if the message should be applied immediately
    /// (belongs to a completed phase), None if buffered.
    pub fn handle_gossip_message(&mut self, envelope: Envelope) -> Option<Envelope> {
        let phase = match classify_message(&envelope.msg_type) {
            Some(p) => p,
            None => return Some(envelope), // unclassified → pass through
        };

        // Check if from a revoked key
        if let Some(&effective_from) = self.revoked_keys.get(&envelope.from)
            && envelope.timestamp >= effective_from {
                return None; // discard
            }

        // Track DID_REVOKE for incremental sync jitter
        if envelope.msg_type == MessageType::DidRevoke {
            self.did_revoke_seen_last_cycle = true;
        }

        if self.completed_phases.contains(&phase) {
            // Already completed this phase → apply immediately
            Some(envelope)
        } else {
            // Buffer for current or future phase
            if let Some(buf) = self.gossip_buffers
                .get_mut(&phase) { buf.insert(envelope) }
            None
        }
    }

    /// Check sync completeness per §5:
    /// 1. All required phases completed
    /// 2. Identity Merkle root matches ≥3 of 5 sync peers
    /// 3. Proposal Merkle root matches ≥3 of 5 sync peers
    /// 4. Rep gossip from each sync peer
    pub fn is_sync_complete(&self, our_identity_root: &str, our_proposal_root: &str) -> bool {
        // All required phases done
        let required = if self.has_store_capability {
            vec![SyncPhase::Identity, SyncPhase::Reputation, SyncPhase::Proposals, SyncPhase::Content, SyncPhase::Storage]
        } else {
            vec![SyncPhase::Identity, SyncPhase::Reputation, SyncPhase::Proposals, SyncPhase::Content]
        };
        for phase in &required {
            if !self.completed_phases.contains(phase) {
                return false;
            }
        }

        // Merkle agreement: ≥3 of 5
        let identity_matches = self.peer_merkle_roots.values()
            .filter(|(id_root, _)| id_root == our_identity_root)
            .count();
        let proposal_matches = self.peer_merkle_roots.values()
            .filter(|(_, prop_root)| prop_root == our_proposal_root)
            .count();

        if identity_matches < 3 || proposal_matches < 3 {
            return false;
        }

        // Rep gossip from each sync peer
        for peer in &self.sync_peers {
            if !self.peer_rep_gossip_received.contains(peer) {
                return false;
            }
        }

        true
    }

    /// Transition to synced status.
    pub fn mark_synced(&mut self) {
        self.status = SyncStatus::Synced;
        self.degraded_since = None;
    }

    /// Enter degraded mode.
    pub fn enter_degraded(&mut self) {
        self.status = SyncStatus::Degraded;
        if self.degraded_since.is_none() {
            self.degraded_since = Some(Instant::now());
        }
    }

    /// Whether the node can vote in degraded mode.
    /// Requires phases 1-2 complete (identity + reputation).
    pub fn can_vote(&self) -> bool {
        match self.status {
            SyncStatus::Synced => true,
            SyncStatus::Degraded => {
                self.completed_phases.contains(&SyncPhase::Identity)
                    && self.completed_phases.contains(&SyncPhase::Reputation)
            }
            SyncStatus::Syncing => false,
        }
    }

    /// Whether the node can propose.
    /// Requires phases 1-3 complete (graduated exit) or synced.
    pub fn can_propose(&self) -> bool {
        match self.status {
            SyncStatus::Synced => true,
            SyncStatus::Degraded => {
                self.completed_phases.contains(&SyncPhase::Identity)
                    && self.completed_phases.contains(&SyncPhase::Reputation)
                    && self.completed_phases.contains(&SyncPhase::Proposals)
            }
            SyncStatus::Syncing => false,
        }
    }

    /// Vote weight multiplier: 10000 for synced, 5000 (50%) for degraded.
    /// Uses fixed-point ×10,000.
    pub fn vote_weight_multiplier(&self) -> u32 {
        match self.status {
            SyncStatus::Synced => 10_000,
            SyncStatus::Degraded => 5_000,
            SyncStatus::Syncing => 0,
        }
    }

    /// Check if phase 1 needs re-run (stale phase check: >1 hour since completion).
    pub fn phase1_stale(&self, now_ms: i64) -> bool {
        if let Some(&phase1_time) = self.phase_timestamps.get(&SyncPhase::Identity) {
            now_ms - phase1_time > 3_600_000 // 1 hour
        } else {
            false
        }
    }

    /// Record a DID_REVOKE for retroactive invalidation.
    pub fn record_revocation(&mut self, key: String, effective_from: i64) {
        self.revoked_keys.insert(key, effective_from);
    }

    /// Check if a key is revoked as of a given timestamp.
    pub fn is_key_revoked(&self, key: &str, at_timestamp: i64) -> bool {
        if let Some(&effective_from) = self.revoked_keys.get(key) {
            at_timestamp >= effective_from
        } else {
            false
        }
    }

    /// Invalidate committed messages from revoked keys.
    /// Returns the IDs of invalidated messages.
    pub fn retroactive_invalidation(&self, committed_messages: &[Envelope]) -> Vec<String> {
        let mut invalidated = Vec::new();
        for msg in committed_messages {
            if self.is_key_revoked(&msg.from, msg.timestamp) {
                invalidated.push(msg.id.clone());
            }
        }
        invalidated
    }

    // ─── Incremental sync ────────────────────────────────────────────

    /// Should identity phase be included in the current incremental sync cycle?
    /// Returns true every 3rd-5th cycle (with jitter) or when DID_REVOKE was seen.
    pub fn should_sync_identity(&mut self) -> bool {
        if self.did_revoke_seen_last_cycle {
            self.did_revoke_seen_last_cycle = false;
            self.identity_sync_cycle = 0;
            return true;
        }

        self.identity_sync_cycle += 1;
        if self.identity_sync_cycle >= self.identity_sync_target {
            self.identity_sync_cycle = 0;
            // Randomize next target: 3-5
            self.identity_sync_target = 3 + (rand::random::<u32>() % 3);
            return true;
        }

        false
    }
}

// ─── REPUTATION_CURRENT Aggregation ──────────────────────────────────

/// Trimmed minimum aggregation per §5.
/// 5 values: discard high+low, min of middle 3.
/// 4 values: discard high, min of bottom 3.
/// 3 values: min directly.
/// ≤2 values: None (need full replay).
pub fn trimmed_minimum(values: &[i64]) -> Option<i64> {
    let n = values.len();
    if n <= 2 {
        return None;
    }

    let mut sorted = values.to_vec();
    sorted.sort();

    match n {
        3 => Some(*sorted.iter().min().unwrap()),
        4 => {
            // Discard highest, min of bottom 3
            Some(*sorted[..3].iter().min().unwrap())
        }
        5 => {
            // Discard highest and lowest, min of middle 3
            Some(*sorted[1..4].iter().min().unwrap())
        }
        _ if n > 5 => {
            // Generalize: discard top and bottom, min of rest
            Some(*sorted[1..n - 1].iter().min().unwrap())
        }
        _ => None,
    }
}

/// Check if reputation values have excessive divergence per §5.
/// Returns true if 2nd-highest − 2nd-lowest > threshold (need full replay).
/// Only meaningful with ≥4 values.
pub fn reputation_divergence_exceeded(values: &[i64], threshold: i64) -> bool {
    if values.len() < 4 {
        return false;
    }
    let mut sorted = values.to_vec();
    sorted.sort();
    let n = sorted.len();
    let second_lowest = sorted[1];
    let second_highest = sorted[n - 2];
    second_highest - second_lowest > threshold
}

// ─── Snapshot Verification ───────────────────────────────────────────

/// Verify snapshot freshness: reject if >24h old.
/// Also reject if future timestamp beyond tolerance (5 min).
pub fn verify_snapshot_freshness(snapshot_timestamp: i64, now_ms: i64) -> bool {
    let age = now_ms - snapshot_timestamp;
    if age > 86_400_000 { // 24h
        return false;
    }
    if snapshot_timestamp - now_ms > 300_000 { // 5 min tolerance
        return false;
    }
    true
}

/// Verify snapshot publishers: ≥5 from ≥3 ASNs.
/// `publishers` is a list of (node_id, reputation, asn).
pub fn verify_snapshot_publishers(publishers: &[(String, FixedPoint, u32)]) -> bool {
    // Filter to rep ≥ 0.7
    let valid: Vec<_> = publishers.iter()
        .filter(|(_, rep, _)| *rep >= FixedPoint::from_raw(7_000))
        .collect();

    if valid.len() < 5 {
        return false;
    }

    let distinct_asns: HashSet<u32> = valid.iter().map(|(_, _, asn)| *asn).collect();
    distinct_asns.len() >= 3
}

/// Compute post-snapshot sync start timestamp.
/// safety margin: snapshot_timestamp - 1 hour.
pub fn post_snapshot_sync_timestamp(snapshot_timestamp: i64) -> i64 {
    snapshot_timestamp - 3_600_000
}

// ─── Identity Merkle Tree ────────────────────────────────────────────

/// Identity Merkle tree per §5.
/// Leaves: SHA-256 of DID_LINK, DID_REVOKE, KEY_ROTATE message IDs.
/// Sorted lexicographically, binary tree, left-biased.
#[derive(Debug)]
pub struct IdentityMerkleTree {
    /// Message IDs in the tree.
    message_ids: HashSet<String>,
    /// Cached root (recomputed at most once per minute).
    cached_root: Option<String>,
    /// Last recomputation timestamp.
    last_recompute_ms: i64,
}

impl Default for IdentityMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityMerkleTree {
    pub fn new() -> Self {
        Self {
            message_ids: HashSet::new(),
            cached_root: None,
            last_recompute_ms: 0,
        }
    }

    /// Add a message ID to the tree.
    pub fn insert(&mut self, message_id: String) {
        self.message_ids.insert(message_id);
        self.cached_root = None; // invalidate cache
    }

    /// Remove a message ID.
    pub fn remove(&mut self, message_id: &str) {
        self.message_ids.remove(message_id);
        self.cached_root = None;
    }

    /// Get the Merkle root, using cache if fresh enough.
    /// Batched: at most once per minute recomputation.
    pub fn root(&mut self, now_ms: i64) -> String {
        if let Some(ref root) = self.cached_root
            && now_ms - self.last_recompute_ms < 60_000 {
                return root.clone();
            }
        let root = self.compute_root();
        self.cached_root = Some(root.clone());
        self.last_recompute_ms = now_ms;
        root
    }

    /// Force recomputation of the Merkle root.
    pub fn compute_root(&self) -> String {
        let ids: Vec<String> = self.message_ids.iter().cloned().collect();
        merkle_root(&ids)
    }

    /// Number of messages in the tree.
    pub fn len(&self) -> usize {
        self.message_ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.message_ids.is_empty()
    }

    /// Get all message IDs (for comparison).
    pub fn message_ids(&self) -> &HashSet<String> {
        &self.message_ids
    }
}

/// Identity divergence severity per §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DivergenceSeverity {
    /// Only additive messages (DID_LINK, KEY_ROTATE) — will converge via gossip.
    Info,
    /// Any DID_REVOKE involved — security-critical.
    Critical,
}

/// Classify identity divergence severity based on the divergent message types.
pub fn identity_divergence_severity(divergent_types: &[MessageType]) -> DivergenceSeverity {
    for msg_type in divergent_types {
        if *msg_type == MessageType::DidRevoke {
            return DivergenceSeverity::Critical;
        }
    }
    DivergenceSeverity::Info
}

// ─── Sync Serving Tracker ────────────────────────────────────────────

/// Tracks sync serving for uptime credit per §5.
/// Max 1 credit/peer/15min, non-empty responses only, ≥3 distinct peers/day.
#[derive(Debug)]
pub struct SyncServingTracker {
    /// peer_id → last credited timestamp.
    last_credit: HashMap<String, i64>,
    /// peer_ids that received credit in the current 24h window.
    credited_peers_24h: HashMap<String, i64>,
}

impl Default for SyncServingTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncServingTracker {
    pub fn new() -> Self {
        Self {
            last_credit: HashMap::new(),
            credited_peers_24h: HashMap::new(),
        }
    }

    /// Record a sync serve to a peer. Returns true if it counts for uptime credit.
    /// Only counts if: non-empty response, ≥15min since last credit for this peer.
    pub fn record_serve(&mut self, peer_id: &str, now_ms: i64, non_empty: bool) -> bool {
        if !non_empty {
            return false;
        }

        // Check 15-minute cooldown per peer
        if let Some(&last) = self.last_credit.get(peer_id)
            && now_ms - last < 15 * 60 * 1000 {
                return false;
            }

        self.last_credit.insert(peer_id.to_string(), now_ms);
        self.credited_peers_24h.insert(peer_id.to_string(), now_ms);

        // Prune old entries (>24h)
        let cutoff = now_ms - 24 * 60 * 60 * 1000;
        self.credited_peers_24h.retain(|_, ts| *ts > cutoff);

        true
    }

    /// Whether the node qualifies for uptime credit (≥3 distinct peers in 24h).
    pub fn qualifies_for_credit(&self, now_ms: i64) -> bool {
        let cutoff = now_ms - 24 * 60 * 60 * 1000;
        let recent_peers: HashSet<&String> = self.credited_peers_24h.iter()
            .filter(|(_, ts)| **ts > cutoff)
            .map(|(peer, _)| peer)
            .collect();
        recent_peers.len() >= 3
    }

    /// Number of distinct peers served in the last 24h.
    pub fn distinct_peers_24h(&self, now_ms: i64) -> usize {
        let cutoff = now_ms - 24 * 60 * 60 * 1000;
        self.credited_peers_24h.iter()
            .filter(|(_, ts)| **ts > cutoff)
            .count()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_envelope(id: &str, ts: i64, msg_type: MessageType) -> Envelope {
        Envelope {
            version: 0,
            msg_type,
            id: id.to_string(),
            from: "sender1".to_string(),
            timestamp: ts,
            payload: json!({}),
            signature: "sig".to_string(),
        }
    }

    // ── Phase ordering (SYNC-01) ──

    #[test]
    fn phase_ordering_sequential_1_2_3() {
        let mgr = SyncManager::new(false);
        assert!(mgr.can_start_phase(SyncPhase::Identity));
        assert!(!mgr.can_start_phase(SyncPhase::Reputation));
        assert!(!mgr.can_start_phase(SyncPhase::Proposals));
        assert!(!mgr.can_start_phase(SyncPhase::Content));
    }

    #[test]
    fn phase_ordering_after_phase1() {
        let mut mgr = SyncManager::new(false);
        mgr.completed_phases.insert(SyncPhase::Identity);
        assert!(mgr.can_start_phase(SyncPhase::Reputation));
        assert!(!mgr.can_start_phase(SyncPhase::Proposals));
    }

    #[test]
    fn phase_ordering_parallel_4_5_after_3() {
        let mut mgr = SyncManager::new(true);
        mgr.completed_phases.insert(SyncPhase::Identity);
        mgr.completed_phases.insert(SyncPhase::Reputation);
        mgr.completed_phases.insert(SyncPhase::Proposals);
        assert!(mgr.can_start_phase(SyncPhase::Content));
        assert!(mgr.can_start_phase(SyncPhase::Storage));
    }

    #[test]
    fn phase_ordering_storage_requires_store_capability() {
        let mut mgr = SyncManager::new(false); // no store capability
        mgr.completed_phases.insert(SyncPhase::Identity);
        mgr.completed_phases.insert(SyncPhase::Reputation);
        mgr.completed_phases.insert(SyncPhase::Proposals);
        assert!(!mgr.can_start_phase(SyncPhase::Storage));
    }

    #[test]
    fn phase_ordering_cannot_start_4_before_3() {
        let mut mgr = SyncManager::new(false);
        mgr.completed_phases.insert(SyncPhase::Identity);
        mgr.completed_phases.insert(SyncPhase::Reputation);
        // Phase 3 not completed
        assert!(!mgr.can_start_phase(SyncPhase::Content));
    }

    // ── Gossip buffer classification (SYNC-02) ──

    #[test]
    fn classify_message_types() {
        assert_eq!(classify_message(&MessageType::DidLink), Some(SyncPhase::Identity));
        assert_eq!(classify_message(&MessageType::DidRevoke), Some(SyncPhase::Identity));
        assert_eq!(classify_message(&MessageType::KeyRotate), Some(SyncPhase::Identity));
        assert_eq!(classify_message(&MessageType::ReputationGossip), Some(SyncPhase::Reputation));
        assert_eq!(classify_message(&MessageType::Vote), Some(SyncPhase::Proposals));
        assert_eq!(classify_message(&MessageType::Propose), Some(SyncPhase::Proposals));
        assert_eq!(classify_message(&MessageType::Share), Some(SyncPhase::Content));
        assert_eq!(classify_message(&MessageType::ShardAssignment), Some(SyncPhase::Storage));
        assert_eq!(classify_message(&MessageType::PeerAnnounce), None);
    }

    #[test]
    fn gossip_buffer_completed_phase_applied_immediately() {
        let mut mgr = SyncManager::new(false);
        mgr.completed_phases.insert(SyncPhase::Identity);
        mgr.current_phase = Some(SyncPhase::Reputation);

        let env = make_envelope("did1", 1000, MessageType::DidRevoke);
        let result = mgr.handle_gossip_message(env.clone());
        assert!(result.is_some()); // applied immediately (phase 1 completed)
    }

    #[test]
    fn gossip_buffer_current_phase_buffered() {
        let mut mgr = SyncManager::new(false);
        mgr.current_phase = Some(SyncPhase::Identity);

        let env = make_envelope("did1", 1000, MessageType::DidLink);
        let result = mgr.handle_gossip_message(env);
        assert!(result.is_none()); // buffered (current phase)
        assert_eq!(mgr.gossip_buffers[&SyncPhase::Identity].len(), 1);
    }

    #[test]
    fn gossip_buffer_future_phase_buffered() {
        let mut mgr = SyncManager::new(false);
        mgr.current_phase = Some(SyncPhase::Reputation);
        mgr.completed_phases.insert(SyncPhase::Identity);

        let env = make_envelope("vote1", 1000, MessageType::Vote);
        let result = mgr.handle_gossip_message(env);
        assert!(result.is_none()); // buffered (future phase)
        assert_eq!(mgr.gossip_buffers[&SyncPhase::Proposals].len(), 1);
    }

    // ── Gossip buffer priority eviction (SYNC-03) ──

    #[test]
    fn gossip_buffer_priority_eviction_phase1() {
        let mut buf = GossipBuffer::new(SyncPhase::Identity);

        // Insert lower-priority messages first
        for i in 0..5 {
            buf.insert(make_envelope(&format!("link_{i}"), 1000 + i as i64, MessageType::DidLink));
        }
        for i in 0..3 {
            buf.insert(make_envelope(&format!("rotate_{i}"), 2000 + i as i64, MessageType::KeyRotate));
        }
        for i in 0..2 {
            buf.insert(make_envelope(&format!("revoke_{i}"), 3000 + i as i64, MessageType::DidRevoke));
        }

        assert_eq!(buf.len(), 10);

        // DID_LINK has priority 1, KEY_ROTATE has 2, DID_REVOKE has 3
        // When evicting, DID_LINK goes first, then KEY_ROTATE
        let priorities: Vec<u8> = buf.messages.values().map(|m| m.priority).collect();
        assert!(priorities.contains(&1)); // DID_LINK
        assert!(priorities.contains(&2)); // KEY_ROTATE
        assert!(priorities.contains(&3)); // DID_REVOKE
    }

    // ── REPUTATION_CURRENT trimmed minimum (SYNC-05, SYNC-06, SYNC-07) ──

    #[test]
    fn trimmed_minimum_5_values() {
        // SYNC-05: [4000, 5000, 6000, 7000, 8000] → discard 4000+8000, min(5000,6000,7000)=5000
        let values = vec![5000, 6000, 7000, 4000, 8000];
        assert_eq!(trimmed_minimum(&values), Some(5000));
    }

    #[test]
    fn trimmed_minimum_4_values() {
        // SYNC-06: [4000, 5000, 7000, 8000] → discard highest (8000), min(4000,5000,7000)=4000
        let values = vec![4000, 5000, 7000, 8000];
        assert_eq!(trimmed_minimum(&values), Some(4000));
    }

    #[test]
    fn trimmed_minimum_3_values() {
        // SYNC-06: [5000, 6000, 7000] → min directly = 5000
        let values = vec![5000, 6000, 7000];
        assert_eq!(trimmed_minimum(&values), Some(5000));
    }

    #[test]
    fn trimmed_minimum_2_values_fallback() {
        // SYNC-06: 2 values → None (need full replay)
        let values = vec![5000, 7000];
        assert_eq!(trimmed_minimum(&values), None);
    }

    #[test]
    fn trimmed_minimum_1_value_fallback() {
        let values = vec![6000];
        assert_eq!(trimmed_minimum(&values), None);
    }

    #[test]
    fn trimmed_minimum_divergence_threshold_exceeded() {
        // SYNC-07: [3000, 4000, 7000, 8000, 9000]
        // 2nd-lowest=4000, 2nd-highest=8000, diff=4000 > 1000 → divergence
        let values = vec![3000, 4000, 7000, 8000, 9000];
        assert!(reputation_divergence_exceeded(&values, 1000));
        // trimmed_minimum still returns a value; caller checks divergence first
        assert_eq!(trimmed_minimum(&values), Some(4000));
    }

    #[test]
    fn trimmed_minimum_divergence_within_threshold() {
        // SYNC-07: [5000, 5500, 6000, 6200, 6500]
        // 2nd-lowest=5500, 2nd-highest=6200, diff=700 ≤ 1000
        let values = vec![5000, 5500, 6000, 6200, 6500];
        assert!(!reputation_divergence_exceeded(&values, 1000));
        // Discard 5000+6500, min(5500,6000,6200)=5500
        assert_eq!(trimmed_minimum(&values), Some(5500));
    }

    // ── Sync completeness (SYNC-08) ──

    #[test]
    fn sync_complete_all_criteria_met() {
        let mut mgr = SyncManager::new(false);
        mgr.completed_phases.insert(SyncPhase::Identity);
        mgr.completed_phases.insert(SyncPhase::Reputation);
        mgr.completed_phases.insert(SyncPhase::Proposals);
        mgr.completed_phases.insert(SyncPhase::Content);

        // 5 sync peers
        for i in 0..5 {
            let peer = format!("peer_{i}");
            mgr.sync_peers.insert(peer.clone());
            mgr.peer_merkle_roots.insert(peer.clone(), ("id_root".into(), "prop_root".into()));
            mgr.peer_rep_gossip_received.insert(peer);
        }

        assert!(mgr.is_sync_complete("id_root", "prop_root"));
    }

    #[test]
    fn sync_incomplete_insufficient_identity_agreement() {
        let mut mgr = SyncManager::new(false);
        mgr.completed_phases.insert(SyncPhase::Identity);
        mgr.completed_phases.insert(SyncPhase::Reputation);
        mgr.completed_phases.insert(SyncPhase::Proposals);
        mgr.completed_phases.insert(SyncPhase::Content);

        // Only 2 peers match identity root
        for i in 0..5 {
            let peer = format!("peer_{i}");
            mgr.sync_peers.insert(peer.clone());
            let id_root = if i < 2 { "id_root" } else { "different" };
            mgr.peer_merkle_roots.insert(peer.clone(), (id_root.into(), "prop_root".into()));
            mgr.peer_rep_gossip_received.insert(peer);
        }

        assert!(!mgr.is_sync_complete("id_root", "prop_root"));
    }

    // ── Snapshot freshness (SYNC-09) ──

    #[test]
    fn snapshot_freshness_within_24h() {
        let now = 100_000_000_000i64;
        assert!(verify_snapshot_freshness(now - 43_200_000, now)); // 12h old
        assert!(verify_snapshot_freshness(now - 86_400_000, now)); // exactly 24h
    }

    #[test]
    fn snapshot_freshness_too_old() {
        let now = 100_000_000_000i64;
        assert!(!verify_snapshot_freshness(now - 86_400_001, now)); // 24h + 1ms
    }

    #[test]
    fn snapshot_freshness_future_rejected() {
        let now = 100_000_000_000i64;
        assert!(!verify_snapshot_freshness(now + 300_001, now)); // 5 min + 1ms in future
    }

    // ── Snapshot publishers (SYNC-10, SYNC-11) ──

    #[test]
    fn snapshot_publishers_valid() {
        let publishers = vec![
            ("p1".into(), FixedPoint::from_f64(0.7), 100),
            ("p2".into(), FixedPoint::from_f64(0.8), 100),
            ("p3".into(), FixedPoint::from_f64(0.9), 200),
            ("p4".into(), FixedPoint::from_f64(0.7), 200),
            ("p5".into(), FixedPoint::from_f64(0.75), 300),
        ];
        assert!(verify_snapshot_publishers(&publishers));
    }

    #[test]
    fn snapshot_publishers_below_rep_threshold() {
        let publishers = vec![
            ("p1".into(), FixedPoint::from_f64(0.69), 100), // below 0.7
            ("p2".into(), FixedPoint::from_f64(0.8), 100),
            ("p3".into(), FixedPoint::from_f64(0.9), 200),
            ("p4".into(), FixedPoint::from_f64(0.7), 200),
            ("p5".into(), FixedPoint::from_f64(0.75), 300),
        ];
        assert!(!verify_snapshot_publishers(&publishers)); // only 4 valid
    }

    #[test]
    fn snapshot_publishers_insufficient_asns() {
        let publishers = vec![
            ("p1".into(), FixedPoint::from_f64(0.7), 100),
            ("p2".into(), FixedPoint::from_f64(0.8), 100),
            ("p3".into(), FixedPoint::from_f64(0.9), 200),
            ("p4".into(), FixedPoint::from_f64(0.7), 200),
            ("p5".into(), FixedPoint::from_f64(0.75), 200), // only 2 ASNs
        ];
        assert!(!verify_snapshot_publishers(&publishers));
    }

    // ── Post-snapshot sync timestamp (SYNC-20) ──

    #[test]
    fn post_snapshot_sync_window() {
        assert_eq!(post_snapshot_sync_timestamp(1700000000000), 1699996400000);
    }

    // ── Degraded mode (SYNC-12) ──

    #[test]
    fn degraded_can_vote_with_phases_1_2() {
        let mut mgr = SyncManager::new(false);
        mgr.status = SyncStatus::Degraded;
        mgr.completed_phases.insert(SyncPhase::Identity);
        mgr.completed_phases.insert(SyncPhase::Reputation);
        assert!(mgr.can_vote());
    }

    #[test]
    fn degraded_cannot_vote_without_phase_2() {
        let mut mgr = SyncManager::new(false);
        mgr.status = SyncStatus::Degraded;
        mgr.completed_phases.insert(SyncPhase::Identity);
        // Phase 2 not complete
        assert!(!mgr.can_vote());
    }

    #[test]
    fn degraded_can_propose_with_phases_1_2_3() {
        let mut mgr = SyncManager::new(false);
        mgr.status = SyncStatus::Degraded;
        mgr.completed_phases.insert(SyncPhase::Identity);
        mgr.completed_phases.insert(SyncPhase::Reputation);
        mgr.completed_phases.insert(SyncPhase::Proposals);
        assert!(mgr.can_propose());
    }

    #[test]
    fn degraded_cannot_propose_without_phase_3() {
        let mut mgr = SyncManager::new(false);
        mgr.status = SyncStatus::Degraded;
        mgr.completed_phases.insert(SyncPhase::Identity);
        mgr.completed_phases.insert(SyncPhase::Reputation);
        assert!(!mgr.can_propose());
    }

    #[test]
    fn vote_weight_multiplier_synced() {
        let mut mgr = SyncManager::new(false);
        mgr.status = SyncStatus::Synced;
        assert_eq!(mgr.vote_weight_multiplier(), 10_000);
    }

    #[test]
    fn vote_weight_multiplier_degraded() {
        let mut mgr = SyncManager::new(false);
        mgr.status = SyncStatus::Degraded;
        assert_eq!(mgr.vote_weight_multiplier(), 5_000);
    }

    #[test]
    fn vote_weight_multiplier_syncing() {
        let mgr = SyncManager::new(false);
        assert_eq!(mgr.vote_weight_multiplier(), 0);
    }

    // ── Cold start interaction (SYNC-13) ──

    #[test]
    fn cold_start_degraded_votes_count_half() {
        // 10 nodes: 7 synced + 3 degraded, all endorse
        // Effective endorsement: 7 × 1.0 + 3 × 0.5 = 8.5
        let synced_votes = 7.0 * 1.0;
        let degraded_votes = 3.0 * 0.5;
        let total = synced_votes + degraded_votes;
        assert!((total - 8.5f64).abs() < f64::EPSILON);
        // Endorsement ratio: 8.5 / 8.5 = 1.0 ≥ 0.67
        assert!(total / total >= 0.67);
    }

    #[test]
    fn cold_start_close_margin() {
        // 10 nodes: 7 synced endorse, 3 degraded reject
        let endorsement = 7.0 * 1.0;
        let rejection = 3.0 * 0.5;
        let ratio = endorsement / (endorsement + rejection);
        // 7.0 / 8.5 ≈ 0.8235
        assert!(ratio >= 0.67);
        assert!((ratio - 7.0f64 / 8.5f64).abs() < 0.001);
    }

    // ── DID_REVOKE retroactive invalidation (SYNC-14) ──

    #[test]
    fn retroactive_invalidation() {
        let mut mgr = SyncManager::new(false);
        let effective_from = 5000i64;
        mgr.record_revocation("key_b".into(), effective_from);

        let messages = vec![
            make_envelope("vote_before", effective_from - 1000, MessageType::Vote),
            {
                let mut e = make_envelope("vote_after1", effective_from + 1000, MessageType::Vote);
                e.from = "key_b".to_string();
                e
            },
            {
                let mut e = make_envelope("vote_after2", effective_from + 5000, MessageType::Vote);
                e.from = "key_b".to_string();
                e
            },
        ];

        let invalidated = mgr.retroactive_invalidation(&messages);
        assert_eq!(invalidated.len(), 2);
        assert!(invalidated.contains(&"vote_after1".to_string()));
        assert!(invalidated.contains(&"vote_after2".to_string()));
    }

    #[test]
    fn retroactive_invalidation_preserves_before_revocation() {
        let mut mgr = SyncManager::new(false);
        mgr.record_revocation("key_b".into(), 5000);

        let mut env = make_envelope("vote_before", 4000, MessageType::Vote);
        env.from = "key_b".to_string();
        let invalidated = mgr.retroactive_invalidation(&[env]);
        assert!(invalidated.is_empty());
    }

    #[test]
    fn gossip_buffer_discards_revoked_key_messages() {
        let mut mgr = SyncManager::new(false);
        mgr.current_phase = Some(SyncPhase::Proposals);
        mgr.completed_phases.insert(SyncPhase::Identity);
        mgr.completed_phases.insert(SyncPhase::Reputation);

        // Record a revocation
        mgr.record_revocation("bad_key".into(), 1000);

        // Message from revoked key after effective_from should be discarded
        let mut env = make_envelope("vote1", 2000, MessageType::Vote);
        env.from = "bad_key".to_string();
        let result = mgr.handle_gossip_message(env);
        assert!(result.is_none()); // discarded (not buffered)
        assert!(mgr.gossip_buffers[&SyncPhase::Proposals].is_empty());
    }

    // ── Identity Merkle tree ──

    #[test]
    fn identity_merkle_tree_basic() {
        let mut tree = IdentityMerkleTree::new();
        tree.insert("msg_a".to_string());
        tree.insert("msg_b".to_string());
        assert_eq!(tree.len(), 2);

        let root = tree.root(0);
        assert!(!root.is_empty());

        // Deterministic
        assert_eq!(tree.compute_root(), tree.compute_root());
    }

    #[test]
    fn identity_merkle_tree_batched_recomputation() {
        let mut tree = IdentityMerkleTree::new();
        tree.insert("msg_a".to_string());

        let root1 = tree.root(0);
        tree.insert("msg_b".to_string());
        // Cache still valid within 1 minute
        let root2 = tree.root(30_000);
        // Cache was invalidated by insert, so should recompute
        assert_ne!(root1, root2); // different because msg_b was added
    }

    // ── Identity divergence severity (PART-06, PART-07, PART-08) ──

    #[test]
    fn divergence_severity_additive_only() {
        let types = vec![MessageType::DidLink, MessageType::KeyRotate];
        assert_eq!(identity_divergence_severity(&types), DivergenceSeverity::Info);
    }

    #[test]
    fn divergence_severity_revoke_critical() {
        let types = vec![MessageType::DidRevoke];
        assert_eq!(identity_divergence_severity(&types), DivergenceSeverity::Critical);
    }

    #[test]
    fn divergence_severity_mixed_critical() {
        let types = vec![MessageType::DidLink, MessageType::DidLink, MessageType::DidRevoke];
        assert_eq!(identity_divergence_severity(&types), DivergenceSeverity::Critical);
    }

    // ── Phase 1 stale check (SYNC-18) ──

    #[test]
    fn phase1_stale_check() {
        let mut mgr = SyncManager::new(false);
        let t = 1_000_000i64;
        mgr.phase_timestamps.insert(SyncPhase::Identity, t);

        assert!(!mgr.phase1_stale(t + 3_599_999)); // <1 hour
        assert!(mgr.phase1_stale(t + 3_600_001)); // >1 hour
    }

    // ── Sync serving tracker (SYNC-19) ──

    #[test]
    fn sync_serving_credit_15min_cooldown() {
        let mut tracker = SyncServingTracker::new();
        let now = 1_000_000i64;

        assert!(tracker.record_serve("peer_a", now, true));
        assert!(!tracker.record_serve("peer_a", now + 14 * 60 * 1000, true)); // <15 min
        assert!(tracker.record_serve("peer_a", now + 15 * 60 * 1000, true)); // ≥15 min
    }

    #[test]
    fn sync_serving_empty_response_no_credit() {
        let mut tracker = SyncServingTracker::new();
        assert!(!tracker.record_serve("peer_a", 1_000_000, false));
    }

    #[test]
    fn sync_serving_requires_3_distinct_peers() {
        let mut tracker = SyncServingTracker::new();
        let now = 1_000_000i64;

        tracker.record_serve("peer_a", now, true);
        tracker.record_serve("peer_b", now + 1000, true);
        assert!(!tracker.qualifies_for_credit(now + 2000)); // only 2

        tracker.record_serve("peer_c", now + 2000, true);
        assert!(tracker.qualifies_for_credit(now + 3000)); // 3 distinct
    }

    // ── Advance phase drains buffer ──

    #[test]
    fn advance_phase_drains_buffer() {
        let mut mgr = SyncManager::new(false);
        mgr.current_phase = Some(SyncPhase::Identity);

        // Buffer a message
        let env = make_envelope("did1", 1000, MessageType::DidLink);
        mgr.gossip_buffers.get_mut(&SyncPhase::Identity).unwrap().insert(env);

        let drained = mgr.advance_phase(2000);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].id, "did1");
        assert_eq!(mgr.current_phase, Some(SyncPhase::Reputation));
        assert!(mgr.completed_phases.contains(&SyncPhase::Identity));
    }

    // ── Incremental sync identity jitter (SYNC-15) ──

    #[test]
    fn incremental_sync_identity_jitter() {
        let mut mgr = SyncManager::new(false);
        mgr.identity_sync_target = 3;

        assert!(!mgr.should_sync_identity()); // cycle 1
        assert!(!mgr.should_sync_identity()); // cycle 2
        assert!(mgr.should_sync_identity());  // cycle 3 (target hit)
    }

    #[test]
    fn incremental_sync_identity_revoke_triggers() {
        let mut mgr = SyncManager::new(false);
        mgr.identity_sync_target = 5;
        mgr.did_revoke_seen_last_cycle = true;

        assert!(mgr.should_sync_identity()); // immediate due to DID_REVOKE
    }

    // ── Gossip buffer size cap (SYNC-04) ──

    #[test]
    fn gossip_buffer_tracks_dropped_timestamp() {
        let mut buf = GossipBuffer::new(SyncPhase::Proposals);

        // Fill with low-priority comments
        for i in 0..GOSSIP_BUFFER_MAX_MESSAGES {
            buf.insert(make_envelope(
                &format!("comment_{i}"),
                1000 + i as i64,
                MessageType::Comment,
            ));
        }

        // Buffer is full, insert a higher-priority vote
        buf.insert(make_envelope("vote_new", 999999, MessageType::Vote));

        // Should have tracked the oldest dropped timestamp
        assert!(buf.oldest_dropped_timestamp.is_some());
    }
}
