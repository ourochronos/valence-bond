//! Gossip protocol — push via GossipSub, pull via sync per §5.
//! Includes message validation, age checking, dedup, and sync pagination.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use valence_core::constants;
use valence_core::message::{Envelope, MessageType};
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

        // TODO: Compute Merkle root checkpoint
        SyncResponse {
            messages,
            has_more,
            next_timestamp,
            next_id,
            checkpoint: None,
        }
    }

    /// Number of stored messages.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
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
}
