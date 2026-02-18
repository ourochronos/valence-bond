//! Message envelope types per §2.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::types::{MessageId, NodeId, Timestamp};

/// All message types defined in v0.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MessageType {
    // §1 Identity
    KeyRotate,
    KeyConflict,
    DidLink,
    DidRevoke,
    // §3 Transport
    AuthChallenge,
    AuthResponse,
    // §4 Peer discovery
    PeerAnnounce,
    PeerListRequest,
    PeerListResponse,
    // §5 Gossip
    SyncRequest,
    SyncResponse,
    // §6 Proposals
    Request,
    Propose,
    Withdraw,
    Adopt,
    // §6 Storage
    StorageChallenge,
    StorageProof,
    ShardQuery,
    ShardQueryResponse,
    ChallengeResult,
    // §7 Votes
    Vote,
    // §8 Reputation
    ReputationGossip,
}

impl MessageType {
    /// Whether this message type uses GossipSub (vs stream protocol).
    pub fn is_gossipsub(&self) -> bool {
        matches!(
            self,
            MessageType::PeerAnnounce
                | MessageType::Request
                | MessageType::Propose
                | MessageType::Withdraw
                | MessageType::Adopt
                | MessageType::ChallengeResult
                | MessageType::Vote
                | MessageType::ReputationGossip
                | MessageType::KeyRotate
                | MessageType::KeyConflict
                | MessageType::DidLink
                | MessageType::DidRevoke
        )
    }

    /// GossipSub topic for this message type (None for stream-only messages).
    pub fn gossipsub_topic(&self) -> Option<&'static str> {
        match self {
            MessageType::PeerAnnounce
            | MessageType::ReputationGossip
            | MessageType::KeyRotate
            | MessageType::KeyConflict
            | MessageType::DidLink
            | MessageType::DidRevoke => Some("/valence/peers"),

            MessageType::Request
            | MessageType::Propose
            | MessageType::Withdraw
            | MessageType::Adopt
            | MessageType::ChallengeResult => Some("/valence/proposals"),

            MessageType::Vote => Some("/valence/votes"),

            _ => None,
        }
    }
}

/// Signed message envelope per §2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Protocol version. MUST be 0 for v0.
    pub version: u32,
    /// Message type.
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    /// SHA-256 hex of the signing body. Content address.
    pub id: MessageId,
    /// Hex-encoded Ed25519 public key of sender.
    pub from: NodeId,
    /// Unix time in milliseconds.
    pub timestamp: Timestamp,
    /// Type-specific payload.
    pub payload: Value,
    /// Hex-encoded Ed25519 signature over signing body.
    pub signature: String,
}

/// Vote stance per §7.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VoteStance {
    Endorse,
    Reject,
    Abstain,
}

/// Proposal tier per §7.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProposalTier {
    Standard,
    Constitutional,
}

/// Erasure coding level per §6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ErasureCoding {
    Minimal,
    Standard,
    Resilient,
}

impl ErasureCoding {
    pub fn data_shards(&self) -> usize {
        match self {
            ErasureCoding::Minimal => 3,
            ErasureCoding::Standard => 5,
            ErasureCoding::Resilient => 8,
        }
    }

    pub fn parity_shards(&self) -> usize {
        match self {
            ErasureCoding::Minimal => 2,
            ErasureCoding::Standard => 3,
            ErasureCoding::Resilient => 4,
        }
    }
}
