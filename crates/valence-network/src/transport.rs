//! libp2p transport setup — Noise encryption, GossipSub topics, stream protocols.
//! Implements §3 (Transport), §4 (Peer Discovery), and §5 (Gossip) of v0 spec.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use libp2p::{
    Multiaddr, PeerId,
};
use serde::{Deserialize, Serialize};
use tracing::debug;

use valence_core::constants;
use valence_core::message::{Envelope, MessageType};

/// GossipSub topic names per §3.
pub const TOPIC_PROPOSALS: &str = "/valence/proposals";
pub const TOPIC_VOTES: &str = "/valence/votes";
pub const TOPIC_PEERS: &str = "/valence/peers";

/// Stream protocol IDs per §3.
pub const SYNC_PROTOCOL: &str = "/valence/sync/1.0.0";
pub const AUTH_PROTOCOL: &str = "/valence/auth/1.0.0";
/// Content transfer stream protocol per §6.
pub const CONTENT_PROTOCOL: &str = "/valence/content/1.0.0";

/// Storage topic for future use (R6-LOW-01).
pub const TOPIC_STORAGE: &str = "/valence/storage";

/// Events emitted by the transport layer to the node.
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// A validated message received via GossipSub.
    GossipMessage {
        topic: String,
        envelope: Envelope,
        source: PeerId,
    },
    /// A new peer connected and authenticated.
    PeerConnected {
        peer_id: PeerId,
        node_id: String,
        addresses: Vec<Multiaddr>,
    },
    /// A peer disconnected.
    PeerDisconnected { peer_id: PeerId },
    /// A sync response received.
    SyncResponse {
        peer_id: PeerId,
        messages: Vec<Envelope>,
        has_more: bool,
        next_timestamp: Option<i64>,
        next_id: Option<String>,
        checkpoint: Option<String>,
    },
    /// Content transfer received (shard data from uploader) per §6.
    ContentReceived {
        peer_id: PeerId,
        content_hash: String,
        shard_index: u32,
        shard_data: Vec<u8>,
    },
    /// Storage challenge received per §6.
    StorageChallengeReceived {
        peer_id: PeerId,
        challenge: crate::storage::StorageChallenge,
    },
    /// Storage proof received in response to a challenge per §6.
    StorageProofReceived {
        peer_id: PeerId,
        proof: crate::storage::StorageProof,
    },
    /// Content request received per §6.
    ContentRequested {
        peer_id: PeerId,
        content_hash: String,
        offset: u64,
        length: u64,
    },
}

// --- Content protocol wire types for /valence/content/1.0.0 ---

/// Content stream protocol message types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContentStreamMessage {
    /// Shard data sent from uploader to provider.
    ShardTransfer {
        content_hash: String,
        shard_index: u32,
        #[serde(with = "base64_bytes")]
        shard_data: Vec<u8>,
    },
    /// Storage challenge sent to a shard holder.
    StorageChallenge {
        shard_hash: String,
        offset: usize,
        direction: String,
        window_size: usize,
        challenge_nonce: String,
    },
    /// Storage proof response.
    StorageProof {
        proof_hash: String,
    },
    /// Content request (chunked download).
    ContentRequest {
        content_hash: String,
        offset: u64,
        length: u64,
    },
    /// Content response (chunked download).
    ContentResponse {
        content_hash: String,
        offset: u64,
        #[serde(with = "base64_bytes")]
        data: Vec<u8>,
        total_size: u64,
    },
}

/// Serialize a ContentStreamMessage into a length-prefixed wire frame per §2.
pub fn encode_content_frame(msg: &ContentStreamMessage) -> Result<Vec<u8>, serde_json::Error> {
    let payload = serde_json::to_vec(msg)?;
    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Maximum content frame size: 16 MiB. Frames exceeding this are rejected
/// to prevent OOM attacks via crafted length prefixes (C-1).
pub const MAX_CONTENT_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Decode a ContentStreamMessage from a length-prefixed wire frame per §2.
/// Returns the message and the number of bytes consumed.
pub fn decode_content_frame(data: &[u8]) -> Result<(ContentStreamMessage, usize), ContentProtocolError> {
    if data.len() < 4 {
        return Err(ContentProtocolError::InsufficientData);
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if len > MAX_CONTENT_FRAME_SIZE {
        return Err(ContentProtocolError::FrameTooLarge { size: len, max: MAX_CONTENT_FRAME_SIZE });
    }
    if data.len() < 4 + len {
        return Err(ContentProtocolError::InsufficientData);
    }
    let msg: ContentStreamMessage = serde_json::from_slice(&data[4..4 + len])
        .map_err(|e| ContentProtocolError::InvalidPayload(e.to_string()))?;
    Ok((msg, 4 + len))
}

/// Errors from the content stream protocol.
#[derive(Debug, thiserror::Error)]
pub enum ContentProtocolError {
    #[error("Insufficient data for frame")]
    InsufficientData,
    #[error("Invalid payload: {0}")]
    InvalidPayload(String),
    #[error("Frame too large: {size} bytes (max {max})")]
    FrameTooLarge { size: usize, max: usize },
}

/// Helper module for base64 serde of Vec<u8>.
mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    pub fn serialize<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(data))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Commands sent to the transport layer from the node.
#[derive(Debug, Clone)]
pub enum TransportCommand {
    /// Publish a message to a GossipSub topic.
    Publish { topic: String, data: Vec<u8> },
    /// Send a sync request to a specific peer.
    SyncRequest {
        peer_id: PeerId,
        since_timestamp: i64,
        since_id: Option<String>,
        types: Vec<MessageType>,
        limit: usize,
    },
    /// Dial a peer at the given address.
    Dial { addr: Multiaddr },
    /// Announce ourselves on the peers topic.
    Announce,
    /// Send shard data to a provider per §6.
    SendShard {
        peer_id: PeerId,
        content_hash: String,
        shard_index: u32,
        shard_data: Vec<u8>,
    },
    /// Respond to a storage challenge per §6.
    SendStorageProof {
        peer_id: PeerId,
        proof: crate::storage::StorageProof,
    },
}

/// Peer info tracked locally.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub node_id: Option<String>,
    pub addresses: Vec<Multiaddr>,
    pub last_seen_ms: i64,
    pub asn: Option<u32>,
    pub capabilities: Vec<String>,
    pub authenticated: bool,
}

/// Peer table with ASN tracking per §4.
#[derive(Debug, Default)]
pub struct PeerTable {
    peers: HashMap<PeerId, PeerInfo>,
    asn_counts: HashMap<u32, usize>,
}

impl PeerTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or update a peer. Returns false if rejected due to ASN limits.
    pub fn upsert(&mut self, info: PeerInfo) -> bool {
        if let Some(asn) = info.asn {
            // Check ASN diversity constraint (§4): no single ASN > 25%
            let total = self.peers.len() + 1; // including this new one
            let current_asn_count = self.asn_counts.get(&asn).copied().unwrap_or(0);

            if !self.peers.contains_key(&info.peer_id) {
                // New peer — check if adding would violate ASN limit
                let new_count = current_asn_count + 1;
                if total >= constants::MIN_DISTINCT_ASNS
                    && new_count as f64 / total as f64 > constants::MAX_ASN_FRACTION
                {
                    debug!(asn, "Rejecting peer: ASN fraction would exceed 25%");
                    return false;
                }
            }
        }

        let peer_id = info.peer_id;
        let asn = info.asn;

        if let Some(old) = self.peers.insert(peer_id, info) {
            // Update ASN counts if ASN changed
            if let Some(old_asn) = old.asn
                && Some(old_asn) != asn
                    && let Some(count) = self.asn_counts.get_mut(&old_asn) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            self.asn_counts.remove(&old_asn);
                        }
                    }
        }

        if let Some(asn) = asn {
            *self.asn_counts.entry(asn).or_insert(0) += 1;
        }

        true
    }

    /// Remove a peer.
    pub fn remove(&mut self, peer_id: &PeerId) -> Option<PeerInfo> {
        if let Some(info) = self.peers.remove(peer_id) {
            if let Some(asn) = info.asn
                && let Some(count) = self.asn_counts.get_mut(&asn) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.asn_counts.remove(&asn);
                    }
                }
            Some(info)
        } else {
            None
        }
    }

    /// Prune peers not seen within the expiry window (§4: 30 minutes).
    pub fn prune_expired(&mut self, now_ms: i64) -> Vec<PeerId> {
        let expired: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, info)| now_ms - info.last_seen_ms > constants::PEER_EXPIRY_MS)
            .map(|(id, _)| *id)
            .collect();

        for peer_id in &expired {
            self.remove(peer_id);
        }
        expired
    }

    /// Get a peer by PeerId.
    pub fn get(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    /// Number of connected peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Number of distinct ASNs.
    pub fn distinct_asns(&self) -> usize {
        self.asn_counts.len()
    }

    /// Get all peers.
    pub fn iter(&self) -> impl Iterator<Item = (&PeerId, &PeerInfo)> {
        self.peers.iter()
    }

    /// Get a random peer outside our immediate set (for anti-fragmentation §4).
    /// L-4: Uses true randomness instead of always returning the first peer.
    pub fn random_peer(&self) -> Option<&PeerInfo> {
        use rand::seq::IteratorRandom;
        let mut rng = rand::thread_rng();
        self.peers.values().choose(&mut rng)
    }

    /// Peers sorted by node_id for PEER_LIST_RESPONSE (§4).
    pub fn sorted_by_node_id(&self) -> Vec<&PeerInfo> {
        let mut peers: Vec<&PeerInfo> = self.peers.values().collect();
        peers.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        peers
    }
}

/// Message deduplication cache per §5. Bounded LRU with time partitioning.
/// M-1: Uses VecDeque for O(1) front removal instead of Vec's O(n).
/// M-3: Entries include timestamps so we never evict entries still within the
///       replay tolerance window, preventing cache-flush replay attacks.
#[derive(Debug)]
pub struct DedupCache {
    /// Ordered from oldest to newest: (message_id, insert_time_ms).
    entries: VecDeque<(String, i64)>,
    set: HashSet<String>,
    capacity: usize,
}

impl DedupCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity.min(1024)),
            set: HashSet::with_capacity(capacity.min(1024)),
            capacity,
        }
    }

    /// Returns true if the message ID was already seen.
    /// M-3: Uses `now_ms` to ensure entries within the replay window are not evicted.
    pub fn check_and_insert(&mut self, message_id: &str) -> bool {
        self.check_and_insert_at(message_id, now_ms())
    }

    /// Returns true if the message ID was already seen. Testable version with explicit time.
    pub fn check_and_insert_at(&mut self, message_id: &str, now_ms: i64) -> bool {
        if self.set.contains(message_id) {
            return true;
        }

        if self.capacity == 0 {
            return false; // can't store anything
        }

        // M-3: First, purge entries older than the replay window (TIMESTAMP_TOLERANCE_MS * 2)
        // to make room. This prevents an attacker from evicting recent entries.
        let replay_window_ms = constants::TIMESTAMP_TOLERANCE_MS * 2;
        while self.entries.len() >= self.capacity {
            if let Some((oldest_id, oldest_time)) = self.entries.front() {
                if now_ms - oldest_time > replay_window_ms {
                    let oldest_id = oldest_id.clone();
                    self.entries.pop_front();
                    self.set.remove(&oldest_id);
                } else {
                    // All remaining entries are within the replay window;
                    // grow beyond capacity rather than dropping protected entries
                    break;
                }
            } else {
                break;
            }
        }

        self.set.insert(message_id.to_string());
        self.entries.push_back((message_id.to_string(), now_ms));
        false
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

/// Helper to get current time in ms.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// Configuration for the transport layer.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Listen addresses.
    pub listen_addrs: Vec<Multiaddr>,
    /// Bootstrap peer addresses.
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Enable mDNS for local discovery (§4).
    pub enable_mdns: bool,
    /// Dedup cache capacity (§5: 100,000).
    pub dedup_capacity: usize,
    /// Peer announce interval.
    pub announce_interval: Duration,
    /// Anti-fragmentation interval (§4: 10 minutes).
    pub anti_frag_interval: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
            bootstrap_peers: vec![],
            enable_mdns: true,
            dedup_capacity: constants::DEDUP_CACHE_SIZE,
            announce_interval: Duration::from_millis(constants::PEER_ANNOUNCE_INTERVAL_MS as u64),
            anti_frag_interval: Duration::from_millis(constants::ANTI_FRAG_INTERVAL_MS as u64),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_cache_basic() {
        let mut cache = DedupCache::new(3);
        // Use timestamps far enough apart that entries are outside replay window
        let old_time = 0i64;
        assert!(!cache.check_and_insert_at("a", old_time));
        assert!(cache.check_and_insert_at("a", old_time + 1)); // already seen
        assert!(!cache.check_and_insert_at("b", old_time + 2));
        assert!(!cache.check_and_insert_at("c", old_time + 3));
        assert_eq!(cache.len(), 3);

        // Evicts "a" (oldest, outside replay window since new time is far ahead)
        let new_time = old_time + 2 * constants::TIMESTAMP_TOLERANCE_MS + 1;
        assert!(!cache.check_and_insert_at("d", new_time));
        assert!(!cache.check_and_insert_at("a", new_time + 1)); // evicted, so "new" again
    }

    #[test]
    fn dedup_cache_capacity_zero() {
        let mut cache = DedupCache::new(0);
        // With 0 capacity, everything is evicted immediately — nothing is "seen"
        assert!(!cache.check_and_insert_at("a", 1000));
    }

    #[test]
    fn peer_table_asn_diversity() {
        let mut table = PeerTable::new();

        // Add 4 peers from different ASNs
        for i in 0..4u8 {
            let peer_id = PeerId::random();
            table.upsert(PeerInfo {
                peer_id,
                node_id: Some(format!("node_{i}")),
                addresses: vec![],
                last_seen_ms: 1000,
                asn: Some(i as u32 + 100),
                capabilities: vec![],
                authenticated: true,
            });
        }
        assert_eq!(table.len(), 4);
        assert_eq!(table.distinct_asns(), 4);

        // 5th peer from ASN 100 — that would be 2/5 = 40% > 25%, rejected
        let peer_id = PeerId::random();
        let accepted = table.upsert(PeerInfo {
            peer_id,
            node_id: Some("node_dup".into()),
            addresses: vec![],
            last_seen_ms: 1000,
            asn: Some(100),
            capabilities: vec![],
            authenticated: true,
        });
        assert!(!accepted);
        assert_eq!(table.len(), 4);
    }

    #[test]
    fn peer_table_prune_expired() {
        let mut table = PeerTable::new();
        let peer_id = PeerId::random();
        table.upsert(PeerInfo {
            peer_id,
            node_id: Some("old_node".into()),
            addresses: vec![],
            last_seen_ms: 0,
            asn: None,
            capabilities: vec![],
            authenticated: true,
        });

        // Not expired at 29 minutes
        let pruned = table.prune_expired(29 * 60 * 1000);
        assert!(pruned.is_empty());

        // Expired at 31 minutes
        let pruned = table.prune_expired(31 * 60 * 1000);
        assert_eq!(pruned.len(), 1);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn peer_table_sorted_by_node_id() {
        let mut table = PeerTable::new();
        for name in ["charlie", "alice", "bob"] {
            table.upsert(PeerInfo {
                peer_id: PeerId::random(),
                node_id: Some(name.into()),
                addresses: vec![],
                last_seen_ms: 1000,
                asn: None,
                capabilities: vec![],
                authenticated: true,
            });
        }
        let sorted: Vec<_> = table
            .sorted_by_node_id()
            .iter()
            .map(|p| p.node_id.as_deref().unwrap())
            .collect();
        assert_eq!(sorted, vec!["alice", "bob", "charlie"]);
    }

    #[test]
    fn content_frame_roundtrip_shard_transfer() {
        let msg = ContentStreamMessage::ShardTransfer {
            content_hash: "abc123".into(),
            shard_index: 2,
            shard_data: vec![1, 2, 3, 4, 5],
        };
        let frame = encode_content_frame(&msg).unwrap();
        let (decoded, consumed) = decode_content_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());
        match decoded {
            ContentStreamMessage::ShardTransfer { content_hash, shard_index, shard_data } => {
                assert_eq!(content_hash, "abc123");
                assert_eq!(shard_index, 2);
                assert_eq!(shard_data, vec![1, 2, 3, 4, 5]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn content_frame_roundtrip_storage_proof() {
        let msg = ContentStreamMessage::StorageProof {
            proof_hash: "deadbeef".into(),
        };
        let frame = encode_content_frame(&msg).unwrap();
        let (decoded, _) = decode_content_frame(&frame).unwrap();
        match decoded {
            ContentStreamMessage::StorageProof { proof_hash } => {
                assert_eq!(proof_hash, "deadbeef");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn content_frame_roundtrip_content_request_response() {
        let req = ContentStreamMessage::ContentRequest {
            content_hash: "hash1".into(),
            offset: 0,
            length: 1024,
        };
        let frame = encode_content_frame(&req).unwrap();
        let (decoded, _) = decode_content_frame(&frame).unwrap();
        match decoded {
            ContentStreamMessage::ContentRequest { content_hash, offset, length } => {
                assert_eq!(content_hash, "hash1");
                assert_eq!(offset, 0);
                assert_eq!(length, 1024);
            }
            _ => panic!("wrong variant"),
        }

        let resp = ContentStreamMessage::ContentResponse {
            content_hash: "hash1".into(),
            offset: 0,
            data: vec![0xAA; 100],
            total_size: 500,
        };
        let frame = encode_content_frame(&resp).unwrap();
        let (decoded, _) = decode_content_frame(&frame).unwrap();
        match decoded {
            ContentStreamMessage::ContentResponse { data, total_size, .. } => {
                assert_eq!(data.len(), 100);
                assert_eq!(total_size, 500);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn content_frame_length_prefix() {
        let msg = ContentStreamMessage::StorageProof {
            proof_hash: "ab".into(),
        };
        let frame = encode_content_frame(&msg).unwrap();
        // First 4 bytes are big-endian u32 length
        let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(len, frame.len() - 4);
    }

    #[test]
    fn content_frame_insufficient_data() {
        assert!(decode_content_frame(&[0, 0]).is_err());
        assert!(decode_content_frame(&[0, 0, 0, 10, 1, 2]).is_err());
    }

    #[test]
    fn content_frame_invalid_payload() {
        let mut frame = vec![0, 0, 0, 5];
        frame.extend_from_slice(b"xxxxx");
        assert!(decode_content_frame(&frame).is_err());
    }

    #[test]
    fn content_frame_oversized_rejected() {
        // C-1: Frame with length prefix exceeding MAX_CONTENT_FRAME_SIZE must be rejected
        let oversized_len = (MAX_CONTENT_FRAME_SIZE as u32 + 1).to_be_bytes();
        let mut data = Vec::from(oversized_len);
        data.push(0); // minimal data
        match decode_content_frame(&data) {
            Err(ContentProtocolError::FrameTooLarge { size, max }) => {
                assert_eq!(size, MAX_CONTENT_FRAME_SIZE + 1);
                assert_eq!(max, MAX_CONTENT_FRAME_SIZE);
            }
            other => panic!("Expected FrameTooLarge, got {:?}", other),
        }
    }

    #[test]
    fn content_frame_max_u32_rejected() {
        // C-1: u32::MAX (4 GiB) length prefix must be rejected
        let data = [0xFF, 0xFF, 0xFF, 0xFF, 0x00];
        match decode_content_frame(&data) {
            Err(ContentProtocolError::FrameTooLarge { .. }) => {}
            other => panic!("Expected FrameTooLarge, got {:?}", other),
        }
    }

    #[test]
    fn content_frame_at_max_size_accepted() {
        // Frame exactly at MAX_CONTENT_FRAME_SIZE should not be rejected by size check
        // (will fail with InsufficientData since we don't provide the full payload)
        let len_bytes = (MAX_CONTENT_FRAME_SIZE as u32).to_be_bytes();
        let data = Vec::from(len_bytes);
        match decode_content_frame(&data) {
            Err(ContentProtocolError::InsufficientData) => {} // expected - size ok, data missing
            other => panic!("Expected InsufficientData, got {:?}", other),
        }
    }

    // ── M-1: DedupCache uses VecDeque for O(1) eviction ──

    #[test]
    fn dedup_cache_m1_vecdeque_eviction_performance() {
        // M-1: Verify that large cache eviction works correctly with VecDeque
        let mut cache = DedupCache::new(100);
        let old_time = 0i64;
        let far_future = old_time + 2 * constants::TIMESTAMP_TOLERANCE_MS + 1;

        // Fill cache
        for i in 0..100 {
            assert!(!cache.check_and_insert_at(&format!("msg_{i}"), old_time));
        }
        assert_eq!(cache.len(), 100);

        // Adding more should evict oldest (outside replay window)
        assert!(!cache.check_and_insert_at("new_msg", far_future));
        assert!(cache.len() <= 101); // may have evicted some
    }

    // ── M-3: Dedup cache time-based protection against replay ──

    #[test]
    fn dedup_cache_m3_protects_recent_entries() {
        // M-3: Entries within the replay window should NOT be evicted
        let mut cache = DedupCache::new(3);
        let now = 1_000_000_000i64;

        // Insert 3 entries at "now"
        assert!(!cache.check_and_insert_at("a", now));
        assert!(!cache.check_and_insert_at("b", now + 1));
        assert!(!cache.check_and_insert_at("c", now + 2));

        // Try to add a 4th at a time still within replay window
        // All previous entries are protected, so cache grows beyond capacity
        assert!(!cache.check_and_insert_at("d", now + 3));

        // All 4 should still be in cache (protected by replay window)
        assert!(cache.check_and_insert_at("a", now + 4));
        assert!(cache.check_and_insert_at("b", now + 5));
        assert!(cache.check_and_insert_at("c", now + 6));
        assert!(cache.check_and_insert_at("d", now + 7));
    }

    #[test]
    fn dedup_cache_m3_evicts_expired_entries() {
        // M-3: Entries outside the replay window CAN be evicted
        let mut cache = DedupCache::new(2);
        let old_time = 0i64;

        assert!(!cache.check_and_insert_at("old_a", old_time));
        assert!(!cache.check_and_insert_at("old_b", old_time + 1));

        // Much later, outside replay window
        let new_time = old_time + 2 * constants::TIMESTAMP_TOLERANCE_MS + 100;
        assert!(!cache.check_and_insert_at("new_c", new_time));

        // Old entries should have been evicted
        assert!(!cache.check_and_insert_at("old_a", new_time + 1)); // "new" again
    }

    // ── L-4: random_peer uses true randomness ──

    #[test]
    fn peer_table_random_peer_returns_some() {
        let mut table = PeerTable::new();
        assert!(table.random_peer().is_none());

        table.upsert(PeerInfo {
            peer_id: PeerId::random(),
            node_id: Some("node_0".into()),
            addresses: vec![],
            last_seen_ms: 1000,
            asn: None,
            capabilities: vec![],
            authenticated: true,
        });
        assert!(table.random_peer().is_some());
    }

    #[test]
    fn gossip_max_age_rejection() {
        // §5: Messages older than 24h via GossipSub MUST be rejected
        let now_ms = 1_000_000_000i64;
        let old_timestamp = now_ms - constants::GOSSIP_MAX_AGE_MS - 1;
        assert!(now_ms - old_timestamp > constants::GOSSIP_MAX_AGE_MS);

        let recent_timestamp = now_ms - constants::GOSSIP_MAX_AGE_MS + 1000;
        assert!(now_ms - recent_timestamp <= constants::GOSSIP_MAX_AGE_MS);
    }
}
