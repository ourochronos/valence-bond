//! Gossip protocol — push via GossipSub, pull via sync per §5.
//! Includes message validation, age checking, dedup, sync pagination,
//! capability ramp validation, and rate limiting.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use valence_core::constants;
use valence_core::message::{Envelope, MessageType};
use valence_core::types::FixedPoint;
use valence_crypto::signing::verify_envelope;

/// Sync request per §5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    pub since_timestamp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<MessageType>,
    pub limit: usize,
    /// Merkle tree to narrow (identity or proposal) per §5.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_tree: Option<String>,
    /// Depth for Merkle narrowing per §5.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
    /// Binary path from root for subtree narrowing per §5.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtree_path: Option<Vec<u8>>,
}

/// Merkle node in a narrowing response per §5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    pub path: Vec<u8>,
    pub hash: String,
}

/// Sync response per §5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub messages: Vec<Envelope>,
    pub has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<String>,
    /// Merkle nodes for narrowing response per §5.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_nodes: Option<Vec<MerkleNode>>,
}

/// Peer list request per §4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerListRequest {
    pub limit: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

/// Peer entry in peer list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub node_id: String,
    pub addresses: Vec<String>,
}

/// Peer list response per §4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerListResponse {
    pub peers: Vec<PeerEntry>,
    pub has_more: bool,
}

/// Peer announcement payload per §4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAnnounce {
    pub addresses: Vec<String>,
    pub capabilities: Vec<String>,
    pub version: u32,
    pub uptime_seconds: u64,
    pub vdf_proof: serde_json::Value,
    /// Storage capacity (§6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageCapacity>,
    /// Sync status per §5.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_status: Option<String>,
}

/// Storage capacity advertised in peer announcements per §6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageCapacity {
    /// Total allocated storage in bytes.
    pub allocated_bytes: u64,
    /// Available (free) storage in bytes.
    pub available_bytes: u64,
    /// Number of shards currently stored.
    pub shard_count: u32,
}

/// Result of validating an incoming gossip message.
#[derive(Debug, PartialEq, Eq)]
pub enum GossipValidation {
    /// Message is valid, should be propagated.
    Accept,
    /// Message is a duplicate (already seen).
    Duplicate,
    /// Message is too old for GossipSub (>24h, §5).
    TooOld,
    /// Message has a future timestamp beyond tolerance (§2).
    FutureTimestamp,
    /// Signature verification failed.
    InvalidSignature,
    /// Payload too large (§2).
    PayloadTooLarge,
    /// Unknown or malformed message.
    Malformed,
}

/// Validate an incoming GossipSub message per §2 and §5.
pub fn validate_gossip_message(envelope: &Envelope, now_ms: i64) -> GossipValidation {
    // §5: Time-based rejection — messages older than 24h via GossipSub MUST be rejected.
    // Does NOT apply to sync protocol messages.
    let age = now_ms - envelope.timestamp;
    if age > constants::GOSSIP_MAX_AGE_MS {
        return GossipValidation::TooOld;
    }

    // §2: Reject future timestamps beyond tolerance.
    if envelope.timestamp - now_ms > constants::TIMESTAMP_TOLERANCE_MS {
        return GossipValidation::FutureTimestamp;
    }

    // §2: Payload size limit.
    let payload_str = envelope.payload.to_string();
    if payload_str.len() > constants::MAX_PAYLOAD_SIZE {
        return GossipValidation::PayloadTooLarge;
    }

    // §2: Signature and content address verification.
    if !verify_envelope(envelope) {
        return GossipValidation::InvalidSignature;
    }

    GossipValidation::Accept
}

/// Full gossip validation pipeline: dedup check + message validation.
/// Use this instead of calling `validate_gossip_message` directly.
pub fn validate_and_dedup(
    envelope: &Envelope,
    now_ms: i64,
    dedup: &mut crate::transport::DedupCache,
) -> GossipValidation {
    // §5: Dedup first (cheapest check).
    if dedup.check_and_insert(&envelope.id) {
        return GossipValidation::Duplicate;
    }

    validate_gossip_message(envelope, now_ms)
}

/// Additional validation for messages that require capability checks per §9.
/// Returns None if valid, Some(rejection reason) if invalid.
pub fn validate_capability(
    msg_type: &MessageType,
    sender_reputation: FixedPoint,
) -> Option<&'static str> {
    use valence_core::constants::*;
    match msg_type {
        MessageType::Propose => {
            if sender_reputation < MIN_REP_TO_PROPOSE {
                Some("rep below 0.3 to propose")
            } else {
                None
            }
        }
        MessageType::Vote => {
            if sender_reputation < MIN_REP_TO_VOTE {
                Some("rep below 0.3 to vote")
            } else {
                None
            }
        }
        MessageType::ReplicateRequest => {
            if sender_reputation < MIN_REP_TO_REPLICATE {
                Some("rep below 0.3 to replicate")
            } else {
                None
            }
        }
        MessageType::Flag => {
            // Check minimum (0.3 for dispute); severity-specific checks happen at a higher layer.
            if sender_reputation < MIN_REP_TO_FLAG_DISPUTE {
                Some("rep below 0.3 to flag")
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Compute the hourly comment rate allowed for a given reputation.
///
/// Linear interpolation: `floor(1 + 12.5 × (rep - 0.3))` capped at \[1, 10\].
/// - Rep 0.3 → 1/hour
/// - Rep 0.5 → 5/hour
/// - Rep 0.8+ → 10/hour
pub fn comment_rate_for_rep(reputation: FixedPoint) -> usize {
    let rep = reputation.to_f64();
    let rate = (1.0 + 12.5 * (rep - 0.3)).floor() as i64;
    rate.clamp(1, 10) as usize
}

/// Rate limiter for various message types per identity.
#[derive(Debug, Default)]
pub struct MessageRateLimiter {
    /// SHARE broadcasts per identity: timestamps (ms).
    share_broadcasts: HashMap<String, Vec<i64>>,
    /// COMMENT per (identity, proposal_id): timestamps (ms).
    comments: HashMap<(String, String), Vec<i64>>,
    /// COMMENT per (identity, proposal_id) for 24h per-proposal limit: timestamps (ms).
    comments_per_proposal: HashMap<(String, String), Vec<i64>>,
    /// SHARD_QUERY per sender: timestamps (ms).
    shard_queries: HashMap<String, Vec<i64>>,
    /// Unknown type per sender: timestamps (ms).
    unknown_types: HashMap<String, Vec<i64>>,
}

impl MessageRateLimiter {
    /// Create a new rate limiter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a SHARE broadcast is within rate limit (10/hour per identity).
    /// Returns true if allowed.
    pub fn check_share(&mut self, identity: &str, now_ms: i64) -> bool {
        let one_hour_ago = now_ms - 3_600_000;
        let timestamps = self.share_broadcasts.entry(identity.to_string()).or_default();
        timestamps.retain(|&t| t > one_hour_ago);
        if timestamps.len() >= constants::SHARE_RATE_LIMIT_PER_HOUR {
            return false;
        }
        timestamps.push(now_ms);
        true
    }

    /// Check if a COMMENT is within rate limits.
    ///
    /// Two limits apply:
    /// 1. Per-identity hourly rate scaled by reputation (1–10/hour).
    /// 2. Per-identity per-proposal limit of 3 per rolling 24 hours (§7).
    ///
    /// Returns true if allowed.
    pub fn check_comment(
        &mut self,
        identity: &str,
        target_id: &str,
        reputation: FixedPoint,
        now_ms: i64,
    ) -> bool {
        let one_hour_ago = now_ms - 3_600_000;
        let one_day_ago = now_ms - 24 * 3_600_000;

        // Per-proposal 24h limit (3/proposal/24h).
        let key_proposal = (identity.to_string(), target_id.to_string());
        let per_proposal = self.comments_per_proposal.entry(key_proposal).or_default();
        per_proposal.retain(|&t| t > one_day_ago);
        if per_proposal.len() >= constants::COMMENT_PER_PROPOSAL_LIMIT {
            return false;
        }

        // Hourly rate limit scaled by reputation.
        let max_per_hour = comment_rate_for_rep(reputation);
        let key_hourly = (identity.to_string(), String::new());
        let hourly = self.comments.entry(key_hourly).or_default();
        hourly.retain(|&t| t > one_hour_ago);
        if hourly.len() >= max_per_hour {
            return false;
        }

        // Both checks passed — record.
        let per_proposal = self
            .comments_per_proposal
            .entry((identity.to_string(), target_id.to_string()))
            .or_default();
        per_proposal.push(now_ms);
        let hourly = self
            .comments
            .entry((identity.to_string(), String::new()))
            .or_default();
        hourly.push(now_ms);
        true
    }

    /// Check SHARD_QUERY rate (10/sender/minute).
    /// Returns true if allowed.
    pub fn check_shard_query(&mut self, sender: &str, now_ms: i64) -> bool {
        let one_minute_ago = now_ms - 60_000;
        let timestamps = self.shard_queries.entry(sender.to_string()).or_default();
        timestamps.retain(|&t| t > one_minute_ago);
        if timestamps.len() >= constants::SYNC_REQUEST_RATE_LIMIT {
            return false;
        }
        timestamps.push(now_ms);
        true
    }

    /// Check unknown type rate (10/sender/hour per §14).
    /// Returns true if allowed.
    pub fn check_unknown_type(&mut self, sender: &str, now_ms: i64) -> bool {
        let one_hour_ago = now_ms - 3_600_000;
        let timestamps = self.unknown_types.entry(sender.to_string()).or_default();
        timestamps.retain(|&t| t > one_hour_ago);
        if timestamps.len() >= constants::UNKNOWN_TYPE_RATE_LIMIT {
            return false;
        }
        timestamps.push(now_ms);
        true
    }
}

// --- Content-related message validation (§6) ---

/// Validation result for content-related gossip messages.
#[derive(Debug, PartialEq, Eq)]
pub enum ContentValidation {
    /// Message is valid.
    Valid,
    /// SHARE message has too many entries.
    TooManyEntries { max: usize, got: usize },
    /// SHARE entry has invalid fields.
    InvalidShareEntry(String),
    /// FLAG severity requires higher reputation.
    InsufficientRepForFlag { required: valence_core::types::FixedPoint, actual: valence_core::types::FixedPoint },
    /// FLAG details too large.
    FlagDetailsTooLarge { max: usize, got: usize },
    /// RENT_PAYMENT has invalid structure.
    InvalidRentPayment(String),
}

/// Validate a SHARE message payload per §6.
pub fn validate_share(payload: &serde_json::Value) -> ContentValidation {
    use valence_core::constants::*;

    let entries = match payload.get("entries").and_then(|e| e.as_array()) {
        Some(e) => e,
        None => return ContentValidation::InvalidShareEntry("missing 'entries' array".into()),
    };

    if entries.len() > SHARE_MAX_ENTRIES {
        return ContentValidation::TooManyEntries { max: SHARE_MAX_ENTRIES, got: entries.len() };
    }

    for (i, entry) in entries.iter().enumerate() {
        // Required fields
        if entry.get("content_hash").and_then(|v| v.as_str()).is_none() {
            return ContentValidation::InvalidShareEntry(format!("entry {i}: missing content_hash"));
        }
        if entry.get("content_type").and_then(|v| v.as_str()).is_none() {
            return ContentValidation::InvalidShareEntry(format!("entry {i}: missing content_type"));
        }
        if entry.get("content_size").and_then(|v| v.as_u64()).is_none() {
            return ContentValidation::InvalidShareEntry(format!("entry {i}: missing or invalid content_size"));
        }

        // Tag limits
        if let Some(tags) = entry.get("tags").and_then(|v| v.as_array()) {
            if tags.len() > SHARE_MAX_TAGS {
                return ContentValidation::InvalidShareEntry(
                    format!("entry {i}: too many tags ({} > {})", tags.len(), SHARE_MAX_TAGS),
                );
            }
            for tag in tags {
                if let Some(s) = tag.as_str()
                    && s.len() > SHARE_MAX_TAG_BYTES {
                        return ContentValidation::InvalidShareEntry(
                            format!("entry {i}: tag exceeds {} bytes", SHARE_MAX_TAG_BYTES),
                        );
                    }
            }
        }
    }

    ContentValidation::Valid
}

/// Validate a FLAG message payload per §6.
/// Checks severity thresholds against sender reputation.
pub fn validate_flag(
    payload: &serde_json::Value,
    sender_reputation: valence_core::types::FixedPoint,
) -> ContentValidation {
    use valence_core::constants::*;

    match payload.get("severity").and_then(|v| v.as_str()) {
        Some("dispute") => {
            if sender_reputation < MIN_REP_TO_FLAG_DISPUTE {
                return ContentValidation::InsufficientRepForFlag {
                    required: MIN_REP_TO_FLAG_DISPUTE,
                    actual: sender_reputation,
                };
            }
            
        }
        Some("illegal") => {
            if sender_reputation < MIN_REP_TO_FLAG_ILLEGAL {
                return ContentValidation::InsufficientRepForFlag {
                    required: MIN_REP_TO_FLAG_ILLEGAL,
                    actual: sender_reputation,
                };
            }
        }
        _ => return ContentValidation::InvalidShareEntry("missing or invalid severity".into()),
    };

    // Check content_hash
    if payload.get("content_hash").and_then(|v| v.as_str()).is_none() {
        return ContentValidation::InvalidShareEntry("missing content_hash".into());
    }

    // Check details size
    if let Some(details) = payload.get("details").and_then(|v| v.as_str())
        && details.len() > FLAG_DETAILS_MAX_BYTES {
            return ContentValidation::FlagDetailsTooLarge {
                max: FLAG_DETAILS_MAX_BYTES,
                got: details.len(),
            };
        }

    // category is required
    match payload.get("category").and_then(|v| v.as_str()) {
        Some("dmca" | "spam" | "malware" | "csam" | "other") => {}
        _ => return ContentValidation::InvalidShareEntry("missing or invalid category".into()),
    }

    ContentValidation::Valid
}

/// Validate a RENT_PAYMENT message payload per §6.
pub fn validate_rent_payment(payload: &serde_json::Value) -> ContentValidation {
    if payload.get("content_hash").and_then(|v| v.as_str()).is_none() {
        return ContentValidation::InvalidRentPayment("missing content_hash".into());
    }
    if payload.get("billing_cycle").and_then(|v| v.as_u64()).is_none() {
        return ContentValidation::InvalidRentPayment("missing or invalid billing_cycle".into());
    }
    if payload.get("amount").and_then(|v| v.as_i64()).is_none() {
        return ContentValidation::InvalidRentPayment("missing or invalid amount".into());
    }
    match payload.get("providers").and_then(|v| v.as_array()) {
        Some(providers) => {
            for (i, p) in providers.iter().enumerate() {
                if p.get("node_id").and_then(|v| v.as_str()).is_none() {
                    return ContentValidation::InvalidRentPayment(
                        format!("provider {i}: missing node_id"),
                    );
                }
                if p.get("shards_held").and_then(|v| v.as_u64()).is_none() {
                    return ContentValidation::InvalidRentPayment(
                        format!("provider {i}: missing or invalid shards_held"),
                    );
                }
                if p.get("amount").and_then(|v| v.as_i64()).is_none() {
                    return ContentValidation::InvalidRentPayment(
                        format!("provider {i}: missing or invalid amount"),
                    );
                }
            }
        }
        None => return ContentValidation::InvalidRentPayment("missing providers array".into()),
    }

    ContentValidation::Valid
}

/// Message store for the local node. Stores envelopes indexed by (timestamp, id)
/// for efficient cursor-based sync pagination per §5.
#[derive(Debug, Default)]
pub struct MessageStore {
    /// Messages indexed by (timestamp, id) for deterministic ordering.
    messages: BTreeMap<(i64, String), Envelope>,
    /// Quick lookup by message ID.
    by_id: std::collections::HashMap<String, i64>,
}

impl MessageStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a message. Returns false if already present.
    pub fn insert(&mut self, envelope: Envelope) -> bool {
        let id = envelope.id.clone();
        let ts = envelope.timestamp;

        if self.by_id.contains_key(&id) {
            return false;
        }

        self.by_id.insert(id.clone(), ts);
        self.messages.insert((ts, id), envelope);
        true
    }

    /// Get a message by ID.
    pub fn get(&self, id: &str) -> Option<&Envelope> {
        if let Some(&ts) = self.by_id.get(id) {
            self.messages.get(&(ts, id.to_string()))
        } else {
            None
        }
    }

    /// Handle a sync request per §5 pagination semantics.
    /// Sort order: ascending by timestamp, then ascending lexicographic by id.
    /// Include messages where (timestamp > since_timestamp) OR
    /// (timestamp == since_timestamp AND id > since_id).
    pub fn query(&self, request: &SyncRequest) -> SyncResponse {
        let cursor = match &request.since_id {
            Some(id) => (request.since_timestamp, id.clone()),
            None => (request.since_timestamp, String::new()),
        };

        let mut messages: Vec<Envelope> = self
            .messages
            .range(cursor..)
            .filter(|((ts, id), _)| {
                // Exclude the cursor itself
                if *ts == request.since_timestamp {
                    match &request.since_id {
                        Some(since_id) => id.as_str() > since_id.as_str(),
                        None => true,
                    }
                } else {
                    true
                }
            })
            .filter(|(_, env)| {
                request.types.is_empty() || request.types.contains(&env.msg_type)
            })
            .map(|(_, env)| env.clone())
            .take(request.limit + 1) // take one extra to detect has_more
            .collect();

        let has_more = messages.len() > request.limit;
        if has_more {
            messages.truncate(request.limit);
        }

        let (next_timestamp, next_id) = if has_more {
            messages.last().map(|m| (Some(m.timestamp), Some(m.id.clone()))).unwrap_or((None, None))
        } else {
            (None, None)
        };

        // Compute Merkle root checkpoint
        let checkpoint = if !messages.is_empty() {
            Some(Self::compute_merkle_root(&messages))
        } else {
            None
        };

        SyncResponse {
            messages,
            has_more,
            next_timestamp,
            next_id,
            checkpoint,
            merkle_nodes: None,
        }
    }

    /// Number of stored messages.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Compute a Merkle root from message IDs for checkpoint verification.
    /// 
    /// Algorithm: Sort message IDs lexicographically, then iteratively hash pairs
    /// with SHA-256 until a single root hash remains.
    fn compute_merkle_root(messages: &[Envelope]) -> String {
        use sha2::{Digest, Sha256};

        if messages.is_empty() {
            return hex::encode(Sha256::digest(b""));
        }

        // Collect and sort message IDs
        let mut hashes: Vec<Vec<u8>> = messages
            .iter()
            .map(|m| Sha256::digest(m.id.as_bytes()).to_vec())
            .collect();
        hashes.sort();

        // Iteratively hash pairs until we have a single root
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            let mut i = 0;
            while i < hashes.len() {
                if i + 1 < hashes.len() {
                    // Hash pair
                    let mut hasher = Sha256::new();
                    hasher.update(&hashes[i]);
                    hasher.update(&hashes[i + 1]);
                    next_level.push(hasher.finalize().to_vec());
                    i += 2;
                } else {
                    // Odd one out: hash with itself
                    let mut hasher = Sha256::new();
                    hasher.update(&hashes[i]);
                    hasher.update(&hashes[i]);
                    next_level.push(hasher.finalize().to_vec());
                    i += 1;
                }
            }
            hashes = next_level;
        }

        hex::encode(&hashes[0])
    }

    /// Remove messages older than a threshold (for archival per §11).
    pub fn prune_before(&mut self, timestamp: i64) -> usize {
        let to_remove: Vec<(i64, String)> = self
            .messages
            .range(..=(timestamp, String::new()))
            .map(|(k, _)| k.clone())
            .collect();

        let count = to_remove.len();
        for key in to_remove {
            if let Some(env) = self.messages.remove(&key) {
                self.by_id.remove(&env.id);
            }
        }
        count
    }
}

/// Auth challenge per §3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    /// Random 32-byte nonce, hex-encoded.
    pub nonce: String,
    /// Initiator's public key, hex-encoded.
    pub initiator_key: String,
}

/// Auth response per §3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    /// Signature over nonce||initiator_key, hex-encoded.
    pub signature: String,
    /// Responder's public key, hex-encoded.
    pub public_key: String,
    /// VDF proof for sybil resistance.
    pub vdf_proof: serde_json::Value,
}

impl AuthChallenge {
    /// Create a new auth challenge with a random nonce.
    pub fn new(initiator_key: &str) -> Self {
        let nonce_bytes: [u8; 32] = rand::random();
        Self {
            nonce: hex::encode(nonce_bytes),
            initiator_key: initiator_key.to_string(),
        }
    }

    /// Get the bytes that the responder must sign: nonce || initiator_key.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = hex::decode(&self.nonce).unwrap_or_default();
        bytes.extend_from_slice(&hex::decode(&self.initiator_key).unwrap_or_default());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use valence_crypto::identity::NodeIdentity;
    use valence_crypto::signing::sign_message;

    /// Make a fake envelope (no valid signature) for store/pagination tests.
    fn make_envelope(id: &str, ts: i64, msg_type: MessageType) -> Envelope {
        Envelope {
            version: 0,
            msg_type,
            id: id.to_string(),
            from: "aabbccdd".to_string(),
            timestamp: ts,
            payload: json!({}),
            signature: "deadbeef".to_string(),
        }
    }

    /// Make a properly signed envelope for validation tests.
    fn make_signed_envelope(ts: i64, msg_type: MessageType) -> Envelope {
        let identity = NodeIdentity::from_seed(&[1u8; 32]);
        sign_message(&identity, msg_type, json!({"test": true}), ts)
    }

    #[test]
    fn gossip_validation_accept_signed() {
        let env = make_signed_envelope(1000, MessageType::Propose);
        assert_eq!(validate_gossip_message(&env, 1000), GossipValidation::Accept);
    }

    #[test]
    fn gossip_validation_invalid_signature() {
        // Fake envelope with bogus signature should fail
        let env = make_envelope("msg1", 1000, MessageType::Propose);
        assert_eq!(validate_gossip_message(&env, 1000), GossipValidation::InvalidSignature);
    }

    #[test]
    fn gossip_validation_too_old() {
        let old_ts = 0i64;
        let now = constants::GOSSIP_MAX_AGE_MS + 1;
        let env = make_signed_envelope(old_ts, MessageType::Propose);
        assert_eq!(validate_gossip_message(&env, now), GossipValidation::TooOld);
    }

    #[test]
    fn gossip_validation_future() {
        let future_ts = 1_000_000i64;
        let now = future_ts - constants::TIMESTAMP_TOLERANCE_MS - 1;
        let env = make_signed_envelope(future_ts, MessageType::Propose);
        assert_eq!(validate_gossip_message(&env, now), GossipValidation::FutureTimestamp);
    }

    #[test]
    fn validate_and_dedup_returns_duplicate() {
        use crate::transport::DedupCache;
        let env = make_signed_envelope(1000, MessageType::Propose);
        let mut dedup = DedupCache::new(100);

        // First time: Accept
        assert_eq!(validate_and_dedup(&env, 1000, &mut dedup), GossipValidation::Accept);
        // Second time: Duplicate
        assert_eq!(validate_and_dedup(&env, 1000, &mut dedup), GossipValidation::Duplicate);
    }

    #[test]
    fn initial_sync_includes_all() {
        let mut store = MessageStore::new();
        store.insert(make_envelope("a", 0, MessageType::Propose));
        store.insert(make_envelope("b", 1, MessageType::Propose));

        // Initial sync with since_timestamp=0, since_id=None should get everything
        let resp = store.query(&SyncRequest {
            since_timestamp: 0,
            since_id: None,
            types: vec![],
            limit: 100,
        merkle_tree: None, depth: None, subtree_path: None,
        });
        assert_eq!(resp.messages.len(), 2);
        assert_eq!(resp.messages[0].id, "a");
        assert_eq!(resp.messages[1].id, "b");
    }

    #[test]
    fn message_store_insert_and_get() {
        let mut store = MessageStore::new();
        let env = make_envelope("msg1", 1000, MessageType::Propose);
        assert!(store.insert(env.clone()));
        assert!(!store.insert(env)); // duplicate
        assert_eq!(store.len(), 1);
        assert!(store.get("msg1").is_some());
    }

    #[test]
    fn message_store_sync_pagination() {
        let mut store = MessageStore::new();

        // Insert 5 messages
        for i in 0..5 {
            store.insert(make_envelope(&format!("msg_{i:02}"), 1000 + i, MessageType::Propose));
        }

        // First page: limit 2
        let resp = store.query(&SyncRequest {
            since_timestamp: 0,
            since_id: None,
            types: vec![],
            limit: 2,
        merkle_tree: None, depth: None, subtree_path: None,
        });
        assert_eq!(resp.messages.len(), 2);
        assert!(resp.has_more);
        assert_eq!(resp.messages[0].id, "msg_00");
        assert_eq!(resp.messages[1].id, "msg_01");

        // Second page using cursor
        let resp2 = store.query(&SyncRequest {
            since_timestamp: resp.next_timestamp.unwrap(),
            since_id: resp.next_id.clone(),
            types: vec![],
            limit: 2,
        merkle_tree: None, depth: None, subtree_path: None,
        });
        assert_eq!(resp2.messages.len(), 2);
        assert!(resp2.has_more);
        assert_eq!(resp2.messages[0].id, "msg_02");

        // Third page — only 1 left
        let resp3 = store.query(&SyncRequest {
            since_timestamp: resp2.next_timestamp.unwrap(),
            since_id: resp2.next_id.clone(),
            types: vec![],
            limit: 2,
        merkle_tree: None, depth: None, subtree_path: None,
        });
        assert_eq!(resp3.messages.len(), 1);
        assert!(!resp3.has_more);
    }

    #[test]
    fn message_store_type_filter() {
        let mut store = MessageStore::new();
        store.insert(make_envelope("p1", 1000, MessageType::Propose));
        store.insert(make_envelope("v1", 1001, MessageType::Vote));
        store.insert(make_envelope("p2", 1002, MessageType::Propose));

        let resp = store.query(&SyncRequest {
            since_timestamp: 0,
            since_id: None,
            types: vec![MessageType::Vote],
            limit: 100,
        merkle_tree: None, depth: None, subtree_path: None,
        });
        assert_eq!(resp.messages.len(), 1);
        assert_eq!(resp.messages[0].id, "v1");
    }

    #[test]
    fn message_store_same_timestamp_ordering() {
        let mut store = MessageStore::new();
        // §5: same timestamp — sort by id lexicographically
        store.insert(make_envelope("zzz", 1000, MessageType::Propose));
        store.insert(make_envelope("aaa", 1000, MessageType::Propose));
        store.insert(make_envelope("mmm", 1000, MessageType::Propose));

        let resp = store.query(&SyncRequest {
            since_timestamp: 0,
            since_id: None,
            types: vec![],
            limit: 100,
        merkle_tree: None, depth: None, subtree_path: None,
        });
        assert_eq!(resp.messages.len(), 3);
        assert_eq!(resp.messages[0].id, "aaa");
        assert_eq!(resp.messages[1].id, "mmm");
        assert_eq!(resp.messages[2].id, "zzz");
    }

    #[test]
    fn message_store_prune() {
        let mut store = MessageStore::new();
        store.insert(make_envelope("old", 100, MessageType::Propose));
        store.insert(make_envelope("new", 200, MessageType::Propose));

        let pruned = store.prune_before(150);
        assert_eq!(pruned, 1);
        assert_eq!(store.len(), 1);
        assert!(store.get("old").is_none());
        assert!(store.get("new").is_some());
    }

    #[test]
    fn auth_challenge_signing_bytes() {
        let challenge = AuthChallenge {
            nonce: "aa".to_string(),
            initiator_key: "bb".to_string(),
        };
        let bytes = challenge.signing_bytes();
        assert_eq!(bytes, vec![0xaa, 0xbb]);
    }

    #[test]
    fn auth_challenge_binding() {
        // §3: Binding initiator's key prevents replay
        let challenge = AuthChallenge::new("abcd1234");
        let bytes = challenge.signing_bytes();
        // Last bytes should be the initiator key
        assert!(bytes.len() >= 4); // nonce (32) + key bytes
    }

    // ── validate_capability tests ──

    #[test]
    fn capability_propose_boundary() {
        assert!(validate_capability(&MessageType::Propose, FixedPoint::from_f64(0.29)).is_some());
        assert!(validate_capability(&MessageType::Propose, FixedPoint::from_f64(0.30)).is_none());
        assert!(validate_capability(&MessageType::Propose, FixedPoint::from_f64(0.50)).is_none());
    }

    #[test]
    fn capability_vote_boundary() {
        assert!(validate_capability(&MessageType::Vote, FixedPoint::from_f64(0.29)).is_some());
        assert!(validate_capability(&MessageType::Vote, FixedPoint::from_f64(0.30)).is_none());
    }

    #[test]
    fn capability_replicate_boundary() {
        assert!(validate_capability(&MessageType::ReplicateRequest, FixedPoint::from_f64(0.29)).is_some());
        assert!(validate_capability(&MessageType::ReplicateRequest, FixedPoint::from_f64(0.30)).is_none());
    }

    #[test]
    fn capability_flag_boundary() {
        assert!(validate_capability(&MessageType::Flag, FixedPoint::from_f64(0.29)).is_some());
        assert!(validate_capability(&MessageType::Flag, FixedPoint::from_f64(0.30)).is_none());
    }

    #[test]
    fn capability_other_types_always_pass() {
        assert!(validate_capability(&MessageType::Share, FixedPoint::from_f64(0.0)).is_none());
        assert!(validate_capability(&MessageType::PeerAnnounce, FixedPoint::from_f64(0.0)).is_none());
    }

    // ── comment_rate_for_rep tests ──

    #[test]
    fn comment_rate_at_boundaries() {
        assert_eq!(comment_rate_for_rep(FixedPoint::from_f64(0.3)), 1);
        assert_eq!(comment_rate_for_rep(FixedPoint::from_f64(0.5)), 3); // floor(1 + 12.5*0.2) = floor(3.5) = 3
        assert_eq!(comment_rate_for_rep(FixedPoint::from_f64(0.8)), 7); // floor(1 + 12.5*0.5) = floor(7.25) = 7
        assert_eq!(comment_rate_for_rep(FixedPoint::from_f64(1.0)), 9); // floor(1 + 12.5*0.7) = floor(9.75) = 9
        // Below 0.3 still gets clamped to 1
        assert_eq!(comment_rate_for_rep(FixedPoint::from_f64(0.1)), 1);
    }

    // ── MessageRateLimiter tests ──

    #[test]
    fn rate_limiter_share_10_per_hour() {
        let mut limiter = MessageRateLimiter::new();
        let now = 1_000_000i64;
        for i in 0..10 {
            assert!(limiter.check_share("alice", now + i), "share {i} should be allowed");
        }
        assert!(!limiter.check_share("alice", now + 10), "11th share should be rejected");
        // Different identity is fine
        assert!(limiter.check_share("bob", now + 10));
        // After an hour, alice can share again
        assert!(limiter.check_share("alice", now + 3_600_001));
    }

    #[test]
    fn rate_limiter_comment_per_proposal_limit() {
        let mut limiter = MessageRateLimiter::new();
        let now = 1_000_000i64;
        let rep = FixedPoint::from_f64(1.0); // high rep, won't hit hourly limit with 3

        for i in 0..3 {
            assert!(limiter.check_comment("alice", "prop1", rep, now + i));
        }
        // 4th comment on same proposal within 24h rejected
        assert!(!limiter.check_comment("alice", "prop1", rep, now + 3));
        // Different proposal is fine
        assert!(limiter.check_comment("alice", "prop2", rep, now + 4));
    }

    #[test]
    fn rate_limiter_comment_hourly_by_rep() {
        let mut limiter = MessageRateLimiter::new();
        let now = 1_000_000i64;
        let low_rep = FixedPoint::from_f64(0.3); // 1/hour

        // 1 comment allowed
        assert!(limiter.check_comment("alice", "prop1", low_rep, now));
        // 2nd comment (different proposal to avoid per-proposal limit) rejected by hourly limit
        assert!(!limiter.check_comment("alice", "prop2", low_rep, now + 1));
    }

    #[test]
    fn rate_limiter_shard_query_10_per_minute() {
        let mut limiter = MessageRateLimiter::new();
        let now = 1_000_000i64;
        for i in 0..10 {
            assert!(limiter.check_shard_query("alice", now + i));
        }
        assert!(!limiter.check_shard_query("alice", now + 10));
        // After a minute, allowed again
        assert!(limiter.check_shard_query("alice", now + 60_001));
    }

    #[test]
    fn rate_limiter_unknown_type_10_per_hour() {
        let mut limiter = MessageRateLimiter::new();
        let now = 1_000_000i64;
        for i in 0..10 {
            assert!(limiter.check_unknown_type("alice", now + i));
        }
        assert!(!limiter.check_unknown_type("alice", now + 10));
        assert!(limiter.check_unknown_type("alice", now + 3_600_001));
    }

    // ── StorageCapacity serde tests ──

    #[test]
    fn peer_announce_with_storage_roundtrip() {
        let announce = PeerAnnounce {
            addresses: vec!["127.0.0.1:9000".into()],
            capabilities: vec!["store".into()],
            version: 0,
            uptime_seconds: 3600,
            vdf_proof: serde_json::json!({}),
            storage: Some(StorageCapacity {
                allocated_bytes: 1_073_741_824,
                available_bytes: 536_870_912,
                shard_count: 42,
            }),
            sync_status: Some("synced".into()),
        };
        let json = serde_json::to_string(&announce).unwrap();
        let decoded: PeerAnnounce = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.storage.as_ref().unwrap().shard_count, 42);
    }

    #[test]
    fn peer_announce_without_storage_omits_field() {
        let announce = PeerAnnounce {
            addresses: vec![],
            capabilities: vec![],
            version: 0,
            uptime_seconds: 0,
            vdf_proof: serde_json::json!({}),
            storage: None,
            sync_status: None,
        };
        let json = serde_json::to_string(&announce).unwrap();
        assert!(!json.contains("storage"));
    }

    // --- Content validation tests ---

    #[test]
    fn validate_share_valid() {
        let payload = json!({
            "entries": [{
                "content_hash": "abc123",
                "content_type": "text/plain",
                "content_size": 1024,
                "tags": ["test"]
            }]
        });
        assert_eq!(validate_share(&payload), ContentValidation::Valid);
    }

    #[test]
    fn validate_share_too_many_entries() {
        let entries: Vec<_> = (0..51).map(|i| json!({
            "content_hash": format!("hash_{i}"),
            "content_type": "text/plain",
            "content_size": 100
        })).collect();
        let payload = json!({ "entries": entries });
        assert!(matches!(validate_share(&payload), ContentValidation::TooManyEntries { .. }));
    }

    #[test]
    fn validate_share_missing_content_hash() {
        let payload = json!({
            "entries": [{"content_type": "text/plain", "content_size": 100}]
        });
        assert!(matches!(validate_share(&payload), ContentValidation::InvalidShareEntry(_)));
    }

    #[test]
    fn validate_share_too_many_tags() {
        let tags: Vec<_> = (0..21).map(|i| format!("tag{i}")).collect();
        let payload = json!({
            "entries": [{"content_hash": "abc", "content_type": "text/plain", "content_size": 100, "tags": tags}]
        });
        assert!(matches!(validate_share(&payload), ContentValidation::InvalidShareEntry(_)));
    }

    #[test]
    fn validate_share_tag_too_long() {
        let long_tag = "x".repeat(65);
        let payload = json!({
            "entries": [{"content_hash": "abc", "content_type": "text/plain", "content_size": 100, "tags": [long_tag]}]
        });
        assert!(matches!(validate_share(&payload), ContentValidation::InvalidShareEntry(_)));
    }

    #[test]
    fn validate_share_missing_entries() {
        let payload = json!({});
        assert!(matches!(validate_share(&payload), ContentValidation::InvalidShareEntry(_)));
    }

    #[test]
    fn validate_flag_dispute_sufficient_rep() {
        let payload = json!({
            "content_hash": "abc",
            "severity": "dispute",
            "category": "spam",
            "details": "spam content"
        });
        assert_eq!(
            validate_flag(&payload, valence_core::types::FixedPoint::from_f64(0.3)),
            ContentValidation::Valid
        );
    }

    #[test]
    fn validate_flag_dispute_insufficient_rep() {
        let payload = json!({
            "content_hash": "abc",
            "severity": "dispute",
            "category": "spam",
            "details": "spam"
        });
        assert!(matches!(
            validate_flag(&payload, valence_core::types::FixedPoint::from_f64(0.29)),
            ContentValidation::InsufficientRepForFlag { .. }
        ));
    }

    #[test]
    fn validate_flag_illegal_requires_05() {
        let payload = json!({
            "content_hash": "abc",
            "severity": "illegal",
            "category": "csam",
            "details": "detected"
        });
        assert!(matches!(
            validate_flag(&payload, valence_core::types::FixedPoint::from_f64(0.49)),
            ContentValidation::InsufficientRepForFlag { .. }
        ));
        assert_eq!(
            validate_flag(&payload, valence_core::types::FixedPoint::from_f64(0.5)),
            ContentValidation::Valid
        );
    }

    #[test]
    fn validate_flag_details_too_large() {
        let big_details = "x".repeat(10 * 1024 + 1);
        let payload = json!({
            "content_hash": "abc",
            "severity": "dispute",
            "category": "spam",
            "details": big_details
        });
        assert!(matches!(
            validate_flag(&payload, valence_core::types::FixedPoint::from_f64(0.5)),
            ContentValidation::FlagDetailsTooLarge { .. }
        ));
    }

    #[test]
    fn validate_flag_missing_category() {
        let payload = json!({
            "content_hash": "abc",
            "severity": "dispute",
            "details": "missing category"
        });
        assert!(matches!(
            validate_flag(&payload, valence_core::types::FixedPoint::from_f64(0.5)),
            ContentValidation::InvalidShareEntry(_)
        ));
    }

    #[test]
    fn validate_flag_invalid_severity() {
        let payload = json!({
            "content_hash": "abc",
            "severity": "unknown",
            "category": "spam",
            "details": "test"
        });
        assert!(matches!(
            validate_flag(&payload, valence_core::types::FixedPoint::from_f64(0.5)),
            ContentValidation::InvalidShareEntry(_)
        ));
    }

    #[test]
    fn validate_rent_payment_valid() {
        let payload = json!({
            "content_hash": "abc",
            "billing_cycle": 1,
            "amount": 100,
            "providers": [
                {"node_id": "node1", "shards_held": 3, "amount": 80}
            ]
        });
        assert_eq!(validate_rent_payment(&payload), ContentValidation::Valid);
    }

    #[test]
    fn validate_rent_payment_missing_content_hash() {
        let payload = json!({
            "billing_cycle": 1,
            "amount": 100,
            "providers": []
        });
        assert!(matches!(validate_rent_payment(&payload), ContentValidation::InvalidRentPayment(_)));
    }

    #[test]
    fn validate_rent_payment_missing_billing_cycle() {
        let payload = json!({
            "content_hash": "abc",
            "amount": 100,
            "providers": []
        });
        assert!(matches!(validate_rent_payment(&payload), ContentValidation::InvalidRentPayment(_)));
    }

    #[test]
    fn validate_rent_payment_bad_provider() {
        let payload = json!({
            "content_hash": "abc",
            "billing_cycle": 1,
            "amount": 100,
            "providers": [{"node_id": "x"}]
        });
        assert!(matches!(validate_rent_payment(&payload), ContentValidation::InvalidRentPayment(_)));
    }

    #[test]
    fn validate_rent_payment_missing_providers() {
        let payload = json!({
            "content_hash": "abc",
            "billing_cycle": 1,
            "amount": 100
        });
        assert!(matches!(validate_rent_payment(&payload), ContentValidation::InvalidRentPayment(_)));
    }
}
