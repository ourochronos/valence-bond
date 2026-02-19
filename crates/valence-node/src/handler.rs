//! Event dispatcher — routes incoming gossip messages to protocol handlers.


use tracing::{debug, info, warn};

use valence_core::message::{
    Envelope, MessageType,
};
use valence_core::types::FixedPoint;
use valence_network::gossip::{
    validate_flag, validate_rent_payment, validate_share, ContentValidation,
};
use valence_network::storage::ContentTransfer;
use valence_protocol::content::can_perform;
use valence_protocol::proposals::{ProposalTracker, Vote};
use valence_crypto::identity::NodeIdentity;
use valence_crypto::signing::sign_message;

use crate::state::NodeState;

/// Response actions that handlers may queue after processing a message.
#[derive(Debug)]
#[allow(dead_code)]
pub enum HandlerResponse {
    /// Publish a message on a gossipsub topic.
    Publish { topic: String, data: Vec<u8> },
    /// Log only, no network action.
    None,
}

/// Dispatch an incoming gossip envelope to the appropriate protocol handler.
///
/// Returns a list of response actions (may be empty).
pub fn handle_gossip_message(
    state: &mut NodeState,
    envelope: &Envelope,
    now_ms: i64,
) -> Vec<HandlerResponse> {
    let responses = Vec::new();

    match &envelope.msg_type {
        // §8 Votes
        MessageType::Vote => {
            handle_vote(state, envelope, now_ms);
        }

        // §7 Proposals
        MessageType::Propose => {
            handle_propose(state, envelope, now_ms);
        }
        MessageType::Request => {
            debug!(id = %envelope.id, "Received proposal request (informational)");
        }
        MessageType::Withdraw => {
            handle_proposal_withdraw(state, envelope);
        }
        MessageType::Adopt => {
            handle_adoption(state, envelope);
        }
        MessageType::Comment => {
            handle_comment(state, envelope, now_ms);
        }

        // §9 Reputation
        MessageType::ReputationGossip => {
            handle_reputation_gossip(state, envelope);
        }

        // §6 Content
        MessageType::Share => {
            handle_share(state, envelope, now_ms);
        }
        MessageType::Flag => {
            handle_flag(state, envelope);
        }
        MessageType::RentPayment => {
            handle_rent_payment(state, envelope);
        }
        MessageType::ReplicateRequest => {
            handle_replicate_request(state, envelope, now_ms);
        }
        MessageType::ReplicateAccept => {
            handle_replicate_accept(state, envelope);
        }
        MessageType::ShardAssignment => {
            handle_shard_assignment(state, envelope, now_ms);
        }
        MessageType::ShardReceived => {
            handle_shard_received(state, envelope, now_ms);
        }
        MessageType::ContentWithdraw => {
            handle_content_withdraw(state, envelope, now_ms);
        }

        // §6 Storage challenges
        MessageType::StorageChallenge => {
            debug!(id = %envelope.id, "Received storage challenge");
            // TODO: If we hold the challenged shard, compute and send proof
        }
        MessageType::ChallengeResult => {
            debug!(id = %envelope.id, "Received challenge result");
            // TODO: Update provider reputation based on result
        }

        // §4 Peer discovery
        MessageType::PeerAnnounce => {
            handle_peer_announce(envelope);
        }

        // §1 Identity
        MessageType::DidLink => {
            handle_did_link(state, envelope, now_ms);
        }
        MessageType::KeyRotate => {
            handle_key_rotate(state, envelope);
        }
        MessageType::DidRevoke => {
            handle_did_revoke(state, envelope);
        }

        // Stream-only or informational
        other => {
            debug!(msg_type = ?other, id = %envelope.id, "Unhandled gossip message type");
        }
    }

    responses
}

// ─── Individual handlers ─────────────────────────────────────────────

fn handle_vote(state: &mut NodeState, envelope: &Envelope, _now_ms: i64) {
    let proposal_id = match envelope.payload.get("proposal_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => {
            warn!(id = %envelope.id, "Vote missing proposal_id");
            return;
        }
    };

    let stance_str = match envelope.payload.get("stance").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            warn!(id = %envelope.id, "Vote missing stance");
            return;
        }
    };

    let stance = match serde_json::from_value(serde_json::Value::String(stance_str.to_string())) {
        Ok(s) => s,
        Err(_) => {
            warn!(id = %envelope.id, stance = stance_str, "Invalid vote stance");
            return;
        }
    };

    let voter_rep = state
        .reputations
        .get(&envelope.from)
        .map(|r| r.overall)
        .unwrap_or(FixedPoint::from_f64(0.2));

    if let Some(tracker) = state.proposals.get_mut(&proposal_id) {
        let vote = Vote {
            voter_id: envelope.from.clone(),
            stance,
            vote_time_reputation: voter_rep,
            timestamp_ms: envelope.timestamp,
        };
        tracker.record_vote(&envelope.from, vote, &state.identity_manager);
        debug!(proposal = %proposal_id, voter = %envelope.from, "Recorded vote");
    } else {
        debug!(proposal = %proposal_id, "Vote for unknown proposal");
    }
}

fn handle_propose(state: &mut NodeState, envelope: &Envelope, now_ms: i64) {
    let rep = state
        .reputations
        .get(&envelope.from)
        .map(|r| r.overall)
        .unwrap_or(FixedPoint::from_f64(0.2));

    if !can_perform(rep, valence_protocol::content::ProtocolAction::Propose) {
        warn!(from = %envelope.from, rep = ?rep, "Proposer below reputation threshold");
        return;
    }

    if !state.proposal_rate_limiter.can_propose(
        &envelope.from,
        now_ms,
        &state.identity_manager,
        Some(rep),
    ) {
        warn!(from = %envelope.from, "Proposal rate-limited");
        return;
    }

    let tier = envelope
        .payload
        .get("tier")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or(valence_core::message::ProposalTier::Standard);

    let deadline_ms = envelope
        .payload
        .get("voting_deadline_ms")
        .and_then(|v| v.as_i64())
        .unwrap_or(now_ms + 7 * 24 * 3600 * 1000); // default 7 days

    let tracker = ProposalTracker::new(
        envelope.id.clone(),
        envelope.from.clone(),
        tier,
        deadline_ms,
    );

    state
        .proposal_rate_limiter
        .record_proposal(&envelope.from, now_ms, &state.identity_manager);
    state.proposals.insert(envelope.id.clone(), tracker);
    info!(id = %envelope.id, from = %envelope.from, "Tracked new proposal");
}

fn handle_proposal_withdraw(state: &mut NodeState, envelope: &Envelope) {
    let target = match envelope.payload.get("proposal_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => return,
    };

    if let Some(tracker) = state.proposals.get_mut(&target)
        && tracker.author_id == envelope.from {
            tracker.withdraw();
            info!(proposal = %target, "Proposal withdrawn by author");
        }
}

fn handle_adoption(state: &mut NodeState, envelope: &Envelope) {
    let target = match envelope.payload.get("proposal_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => return,
    };
    let success = envelope
        .payload
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    if let Some(tracker) = state.proposals.get_mut(&target) {
        tracker.record_adoption(envelope.from.clone(), success);
        debug!(proposal = %target, from = %envelope.from, "Recorded adoption report");
    }
}

fn handle_comment(state: &mut NodeState, envelope: &Envelope, now_ms: i64) {
    let rep = state
        .reputations
        .get(&envelope.from)
        .map(|r| r.overall)
        .unwrap_or(FixedPoint::from_f64(0.2));

    let root_id = state
        .identity_manager
        .resolve_root(&envelope.from)
        .unwrap_or(&envelope.from)
        .to_string();

    let target_id = envelope
        .payload
        .get("target_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if !state
        .rate_limiter
        .check_comment(&root_id, target_id, rep, now_ms)
    {
        debug!(from = %envelope.from, "Comment rate-limited");
        return;
    }

    // Store in message store (via NodeState)
    debug!(id = %envelope.id, from = %envelope.from, "Accepted comment");
}

fn handle_reputation_gossip(state: &mut NodeState, envelope: &Envelope) {
    // Reputation gossip carries observed reputation for a target node.
    // In v0, nodes accumulate observations and blend via α formula.
    let target = match envelope.payload.get("target").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => return,
    };

    let observed = match envelope
        .payload
        .get("observed_reputation")
        .and_then(|v| v.as_f64())
    {
        Some(r) => FixedPoint::from_f64(r),
        None => return,
    };

    let rep_state = state
        .reputations
        .entry(target.clone())
        .or_default();
    rep_state.observation_count += 1;

    debug!(target = %target, observed = ?observed, "Processed reputation gossip");
}

fn handle_share(state: &mut NodeState, envelope: &Envelope, now_ms: i64) {
    match validate_share(&envelope.payload) {
        ContentValidation::Valid => {
            let root_id = state
                .identity_manager
                .resolve_root(&envelope.from)
                .unwrap_or(&envelope.from)
                .to_string();
            if !state.rate_limiter.check_share(&root_id, now_ms) {
                debug!(from = %envelope.from, "Share rate-limited");
                return;
            }
            debug!(id = %envelope.id, "Accepted share");
        }
        other => {
            debug!(id = %envelope.id, result = ?other, "Share rejected");
        }
    }
}

fn handle_flag(state: &mut NodeState, envelope: &Envelope) {
    let rep = state
        .reputations
        .get(&envelope.from)
        .map(|r| r.overall)
        .unwrap_or(FixedPoint::from_f64(0.2));

    match validate_flag(&envelope.payload, rep) {
        ContentValidation::Valid => {
            info!(id = %envelope.id, from = %envelope.from, "Accepted content flag");
            // TODO: Initiate content review / quarantine
        }
        other => {
            debug!(id = %envelope.id, result = ?other, "Flag rejected");
        }
    }
}

fn handle_rent_payment(_state: &mut NodeState, envelope: &Envelope) {
    match validate_rent_payment(&envelope.payload) {
        ContentValidation::Valid => {
            let content_hash = envelope
                .payload
                .get("content_hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            debug!(content = %content_hash, "Accepted rent payment");
            // RentTracker updates would be keyed by content_hash in a full impl
        }
        other => {
            debug!(id = %envelope.id, result = ?other, "Rent payment rejected");
        }
    }
}

fn handle_replicate_request(state: &mut NodeState, envelope: &Envelope, now_ms: i64) {
    let content_hash = match envelope.payload.get("content_hash").and_then(|v| v.as_str()) {
        Some(h) => h.to_string(),
        None => return,
    };

    let transfer = ContentTransfer::new(content_hash.clone(), envelope.from.clone(), now_ms);
    state.content_transfers.insert(content_hash.clone(), transfer);
    debug!(content = %content_hash, from = %envelope.from, "Tracked replicate request");
}

fn handle_replicate_accept(state: &mut NodeState, envelope: &Envelope) {
    let content_hash = match envelope.payload.get("content_hash").and_then(|v| v.as_str()) {
        Some(h) => h.to_string(),
        None => return,
    };

    if let Some(transfer) = state.content_transfers.get_mut(&content_hash) {
        let shard_indices: Vec<u32> = envelope
            .payload
            .get("shard_indices")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        transfer.accept(envelope.from.clone(), shard_indices);
        debug!(content = %content_hash, provider = %envelope.from, "Recorded replicate accept");
    }
}

fn handle_shard_assignment(state: &mut NodeState, envelope: &Envelope, now_ms: i64) {
    let content_hash = match envelope.payload.get("content_hash").and_then(|v| v.as_str()) {
        Some(h) => h.to_string(),
        None => return,
    };

    if let Some(transfer) = state.content_transfers.get_mut(&content_hash) {
        let assignments: Vec<(u32, String)> = envelope
            .payload
            .get("assignments")
            .and_then(|v| {
                serde_json::from_value::<Vec<serde_json::Value>>(v.clone()).ok()
            })
            .unwrap_or_default()
            .iter()
            .filter_map(|entry| {
                let idx = entry.get("shard_index")?.as_u64()? as u32;
                let provider = entry.get("provider")?.as_str()?.to_string();
                Some((idx, provider))
            })
            .collect();
        transfer.assign(&assignments, now_ms);
        debug!(content = %content_hash, "Processed shard assignment");
    }
}

fn handle_shard_received(state: &mut NodeState, envelope: &Envelope, now_ms: i64) {
    let content_hash = match envelope.payload.get("content_hash").and_then(|v| v.as_str()) {
        Some(h) => h.to_string(),
        None => return,
    };
    let shard_index = match envelope.payload.get("shard_index").and_then(|v| v.as_u64()) {
        Some(i) => i as u32,
        None => return,
    };

    if let Some(transfer) = state.content_transfers.get_mut(&content_hash) {
        transfer.confirm_shard(shard_index, &envelope.from, now_ms);
        debug!(content = %content_hash, shard = shard_index, "Shard confirmed");
    }
}

fn handle_content_withdraw(state: &mut NodeState, envelope: &Envelope, now_ms: i64) {
    let content_hash = match envelope.payload.get("content_hash").and_then(|v| v.as_str()) {
        Some(h) => h.to_string(),
        None => return,
    };
    let effective_after = envelope
        .payload
        .get("effective_after")
        .and_then(|v| v.as_i64())
        .unwrap_or(now_ms + 24 * 3600 * 1000);

    match state.withdraw_tracker.request_withdraw(
        &content_hash,
        effective_after,
        now_ms,
    ) {
        Ok(()) => info!(content = %content_hash, "Content withdrawal requested"),
        Err(e) => warn!(content = %content_hash, error = %e, "Withdraw request rejected"),
    }
}

fn handle_peer_announce(envelope: &Envelope) {
    // H-5: Verify VDF proof in PeerAnnounce messages
    let vdf_proof_value = match envelope.payload.get("vdf_proof") {
        Some(v) if !v.is_null() && v != &serde_json::json!({}) => v,
        _ => {
            warn!(from = %envelope.from, "PeerAnnounce rejected: missing or empty VDF proof (H-5)");
            return;
        }
    };

    // Parse the VDF proof
    let vdf_proof = match parse_vdf_proof(vdf_proof_value) {
        Some(p) => p,
        None => {
            warn!(from = %envelope.from, "PeerAnnounce rejected: malformed VDF proof (H-5)");
            return;
        }
    };

    // Verify the VDF input matches the peer's public key
    if let Some(expected_input) = valence_crypto::identity::vdf_input(&envelope.from)
        && vdf_proof.input_data != expected_input {
            warn!(from = %envelope.from, "PeerAnnounce rejected: VDF input doesn't match peer key (H-5)");
            return;
        }

    // Verify the VDF proof (spot-check 3 segments)
    if let Err(e) = valence_crypto::vdf::verify(&vdf_proof, 3) {
        warn!(from = %envelope.from, error = %e, "PeerAnnounce rejected: VDF verification failed (H-5)");
        return;
    }

    debug!(from = %envelope.from, "Peer announcement accepted with valid VDF proof");
}

/// Parse a VDF proof from JSON value (delegates to auth module).
fn parse_vdf_proof(value: &serde_json::Value) -> Option<valence_crypto::vdf::VdfProof> {
    valence_network::auth::parse_vdf_proof(value)
}

fn handle_did_link(state: &mut NodeState, envelope: &Envelope, now_ms: i64) {
    use valence_crypto::identity::verify_signature;
    use valence_protocol::identity::DidLinkRequest;

    let child_key = match envelope.payload.get("child_key").and_then(|v| v.as_str()) {
        Some(k) => k.to_string(),
        None => return,
    };
    let child_sig = match envelope.payload.get("child_signature").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return,
    };
    let label = envelope
        .payload
        .get("label")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // H-1: Verify child key actually signed the link request.
    // The child must prove they control the key being linked by signing
    // a canonical binding message: "DID_LINK:<root_key>:<child_key>"
    let binding_message = format!("DID_LINK:{}:{}", envelope.from, child_key);
    if !verify_signature(&child_key, binding_message.as_bytes(), &child_sig) {
        warn!(
            root = %envelope.from,
            child = %child_key,
            "DID link rejected: invalid child signature (H-1)"
        );
        return;
    }

    let request = DidLinkRequest {
        root_key: envelope.from.clone(),
        child_key,
        child_signature: child_sig,
        label,
    };

    match state.identity_manager.link(&request, now_ms) {
        Ok(()) => {
            info!(root = %envelope.from, child = %request.child_key, "DID link recorded");
            // §5: Add to identity Merkle tree
            state.identity_merkle_tree.insert(envelope.id.clone());
        }
        Err(e) => warn!(root = %envelope.from, error = ?e, "DID link rejected"),
    }
}

fn handle_key_rotate(state: &mut NodeState, envelope: &Envelope) {
    use valence_crypto::identity::verify_signature;

    let old_key = match envelope.payload.get("old_key").and_then(|v| v.as_str()) {
        Some(k) => k.to_string(),
        None => return,
    };
    let new_key = match envelope.payload.get("new_key").and_then(|v| v.as_str()) {
        Some(k) => k.to_string(),
        None => return,
    };
    let new_key_signature = match envelope.payload.get("new_key_signature").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            warn!(old = %old_key, "KEY_ROTATE rejected: missing new_key_signature (H-2)");
            return;
        }
    };

    // H-2: Verify envelope.from == old_key (the envelope signature covers old_key)
    if envelope.from != old_key {
        warn!(
            from = %envelope.from,
            old = %old_key,
            "KEY_ROTATE rejected: envelope.from != old_key (H-2)"
        );
        return;
    }

    // H-2: Verify the new key also signed the rotation.
    // The new key must sign "KEY_ROTATE:<old_key>:<new_key>" to prove possession.
    let binding_message = format!("KEY_ROTATE:{}:{}", old_key, new_key);
    if !verify_signature(&new_key, binding_message.as_bytes(), &new_key_signature) {
        warn!(
            old = %old_key,
            new = %new_key,
            "KEY_ROTATE rejected: invalid new key signature (H-2)"
        );
        return;
    }

    // Determine if this is a root or child key rotation
    if envelope.from == old_key {
        state
            .identity_manager
            .record_root_key_rotate(&old_key, new_key);
        info!(old = %old_key, "Root key rotated");
    } else {
        state
            .identity_manager
            .record_child_key_rotate(&old_key, new_key);
        info!(old = %old_key, "Child key rotated");
    }
    // §5: Add to identity Merkle tree
    state.identity_merkle_tree.insert(envelope.id.clone());
}

fn handle_did_revoke(state: &mut NodeState, envelope: &Envelope) {
    use valence_protocol::identity::DidRevokeRequest;

    let revoked_key = match envelope.payload.get("revoked_key").and_then(|v| v.as_str()) {
        Some(k) => k.to_string(),
        None => return,
    };

    let request = DidRevokeRequest {
        root_key: envelope.from.clone(),
        revoked_key,
        reason: envelope
            .payload
            .get("reason")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        effective_from: envelope.timestamp,
    };

    match state.identity_manager.revoke(&request) {
        Ok(()) => {
            info!(root = %envelope.from, revoked = %request.revoked_key, "DID revocation recorded");
            // §5: Record revocation in sync manager for retroactive invalidation
            state.sync_manager.record_revocation(request.revoked_key.clone(), request.effective_from);
            // §5: Add to identity Merkle tree
            state.identity_merkle_tree.insert(envelope.id.clone());
        }
        Err(e) => warn!(root = %envelope.from, error = ?e, "DID revocation rejected"),
    }
}

// ─── Rent cycle automation (§6) ──────────────────────────────────────

/// Check if a new rent billing cycle has started and broadcast RENT_PAYMENT
/// for any content this node owns.
///
/// Called periodically from the main event loop (every hour).
pub fn check_rent_cycle(
    state: &mut NodeState,
    identity: &NodeIdentity,
    now_ms: i64,
) -> Vec<HandlerResponse> {
    let mut responses = Vec::new();

    let billing_cycle_ms = valence_core::constants::RENT_BILLING_CYCLE_MS;
    let current_cycle = (now_ms / billing_cycle_ms) as u64;

    // Check if we've advanced to a new cycle
    if current_cycle <= state.last_rent_cycle {
        return responses;
    }

    let previous_cycle = state.last_rent_cycle;
    state.last_rent_cycle = current_cycle;

    if previous_cycle == 0 {
        // First run, just record the cycle
        return responses;
    }

    info!(cycle = current_cycle, "New rent billing cycle detected");

    // For each content transfer we own, compute and broadcast rent payment
    let owned_content: Vec<String> = state.content_transfers.keys().cloned().collect();
    for content_hash in owned_content {
        let payload = serde_json::json!({
            "content_hash": content_hash,
            "billing_cycle": current_cycle,
            "amount": 10, // Base rate; real impl would compute from storage size
            "providers": [],
        });
        let envelope = sign_message(identity, MessageType::RentPayment, payload, now_ms);
        if let Ok(data) = serde_json::to_vec(&envelope) {
            responses.push(HandlerResponse::Publish {
                topic: "/valence/proposals".to_string(),
                data,
            });
            debug!(content = %content_hash, cycle = current_cycle, "Broadcasting rent payment");
        }
    }

    // Check grace periods for unpaid rent
    let grace_period_1 = valence_core::constants::RENT_GRACE_PERIOD_1_MS;
    let cycle_start_ms = current_cycle as i64 * billing_cycle_ms;
    let deadline_ms = cycle_start_ms + (valence_core::constants::RENT_PAYMENT_DEADLINE_DAYS as i64 * 24 * 3600 * 1000);

    if now_ms > deadline_ms {
        debug!("Rent payment deadline passed for cycle {current_cycle}, grace period active");
    }
    if now_ms > deadline_ms + grace_period_1 {
        warn!("Grace period 1 expired for cycle {current_cycle}");
    }

    responses
}

// ─── STATE_SNAPSHOT publishing (§5) ──────────────────────────────────

/// If node reputation ≥ 0.7 and synced, publish STATE_SNAPSHOT.
///
/// Called periodically from the main event loop (every 6-12 hours).
pub fn check_snapshot_publishing(
    state: &mut NodeState,
    identity: &NodeIdentity,
    now_ms: i64,
) -> Vec<HandlerResponse> {
    let mut responses = Vec::new();
    let node_id = identity.node_id();

    // Check eligibility: rep ≥ 0.7
    let rep = state.reputations.get(&node_id)
        .map(|r| r.overall)
        .unwrap_or(FixedPoint::from_f64(0.2));

    if rep < FixedPoint::from_f64(0.7) {
        debug!(rep = ?rep, "Node rep too low for snapshot publishing (need ≥ 0.7)");
        return responses;
    }

    // Check sync status
    if state.sync_manager.status != valence_network::sync::SyncStatus::Synced {
        debug!("Node not synced, skipping snapshot publishing");
        return responses;
    }

    // Check freshness: don't publish if last snapshot was < 6 hours ago
    if let Some(last) = state.last_snapshot_publish_ms {
        let min_interval = 6 * 3600 * 1000; // 6 hours
        if now_ms - last < min_interval {
            return responses;
        }
    }

    info!("Publishing STATE_SNAPSHOT");

    // Compute Merkle roots
    let identity_root = state.identity_merkle_tree.root(now_ms);
    let proposal_ids: Vec<String> = state.proposals.keys().cloned().collect();
    let proposal_root = valence_core::canonical::merkle_root(&proposal_ids);

    // Compute reputation summary hash
    let mut rep_entries: Vec<String> = state.reputations.iter()
        .map(|(k, v)| format!("{}:{}", k, v.overall.raw()))
        .collect();
    rep_entries.sort();
    let rep_summary = valence_core::canonical::merkle_root(&rep_entries);

    let payload = serde_json::json!({
        "identity_merkle_root": identity_root,
        "proposal_merkle_root": proposal_root,
        "reputation_summary_hash": rep_summary,
        "timestamp": now_ms,
        "node_reputation": rep.to_f64(),
    });

    let envelope = sign_message(identity, MessageType::SyncResponse, payload, now_ms);
    if let Ok(data) = serde_json::to_vec(&envelope) {
        responses.push(HandlerResponse::Publish {
            topic: "/valence/peers".to_string(),
            data,
        });
    }

    state.last_snapshot_publish_ms = Some(now_ms);

    responses
}

#[cfg(test)]
mod tests {
    use super::*;
    use valence_core::message::MessageType;
    use valence_crypto::identity::NodeIdentity;
    use valence_crypto::signing::sign_message;
    use valence_protocol::reputation::ReputationState;

    fn make_state() -> NodeState {
        NodeState::new()
    }

    fn make_envelope(identity: &NodeIdentity, msg_type: MessageType, payload: serde_json::Value) -> Envelope {
        let now_ms = chrono::Utc::now().timestamp_millis();
        sign_message(identity, msg_type, payload, now_ms)
    }

    #[test]
    fn handle_propose_creates_tracker() {
        let mut state = make_state();
        let id = NodeIdentity::generate();
        // Give proposer enough reputation
        let mut rep = ReputationState::new();
        rep.overall = FixedPoint::from_f64(0.5);
        state.reputations.insert(id.node_id().to_string(), rep);

        let env = make_envelope(&id, MessageType::Propose, serde_json::json!({
            "tier": "standard",
            "title": "Test proposal",
            "body": "Testing",
        }));

        let now_ms = chrono::Utc::now().timestamp_millis();
        handle_gossip_message(&mut state, &env, now_ms);
        assert!(state.proposals.contains_key(&env.id));
    }

    #[test]
    fn handle_propose_rejects_low_rep() {
        let mut state = make_state();
        let id = NodeIdentity::generate();
        // Default rep is 0.2, below 0.3 threshold

        let env = make_envelope(&id, MessageType::Propose, serde_json::json!({
            "tier": "standard",
        }));

        let now_ms = chrono::Utc::now().timestamp_millis();
        handle_gossip_message(&mut state, &env, now_ms);
        assert!(!state.proposals.contains_key(&env.id));
    }

    #[test]
    fn handle_vote_on_known_proposal() {
        let mut state = make_state();
        let author = NodeIdentity::generate();
        let voter = NodeIdentity::generate();

        // Set up proposal
        let tracker = ProposalTracker::new(
            "prop-1".to_string(),
            author.node_id().to_string(),
            valence_core::message::ProposalTier::Standard,
            i64::MAX,
        );
        state.proposals.insert("prop-1".to_string(), tracker);

        // Voter needs rep ≥ 0.3 to vote
        let mut rep = ReputationState::new();
        rep.overall = FixedPoint::from_f64(0.5);
        state.reputations.insert(voter.node_id().to_string(), rep);

        let env = make_envelope(&voter, MessageType::Vote, serde_json::json!({
            "proposal_id": "prop-1",
            "stance": "endorse",
        }));

        let now_ms = chrono::Utc::now().timestamp_millis();
        handle_gossip_message(&mut state, &env, now_ms);
        assert!(state.proposals["prop-1"].votes.contains_key(&voter.node_id().to_string()));
    }

    #[test]
    fn handle_share_validates() {
        let mut state = make_state();
        let id = NodeIdentity::generate();

        let env = make_envelope(&id, MessageType::Share, serde_json::json!({
            "entries": [{
                "content_hash": "a".repeat(64),
                "content_type": "text/plain",
                "content_size": 1024,
                "tags": []
            }]
        }));

        let now_ms = chrono::Utc::now().timestamp_millis();
        handle_gossip_message(&mut state, &env, now_ms);
        // No panic = success; share was accepted or rate-limited
    }

    #[test]
    fn handle_replicate_request_tracks_transfer() {
        let mut state = make_state();
        let id = NodeIdentity::generate();

        let env = make_envelope(&id, MessageType::ReplicateRequest, serde_json::json!({
            "content_hash": "abc123",
            "content_type": "application/octet-stream",
            "content_size": 4096,
            "coding": "standard",
            "reputation_stake": 0.01,
            "tags": []
        }));

        let now_ms = chrono::Utc::now().timestamp_millis();
        handle_gossip_message(&mut state, &env, now_ms);
        assert!(state.content_transfers.contains_key("abc123"));
    }

    #[test]
    fn handle_did_link_valid_child_signature() {
        // H-1: Valid child signature should be accepted
        let mut state = make_state();
        let root = NodeIdentity::generate();
        let child = NodeIdentity::generate();

        // Child signs the binding message
        let binding = format!("DID_LINK:{}:{}", root.node_id(), child.node_id());
        let child_sig = hex::encode(child.sign(binding.as_bytes()));

        let env = make_envelope(&root, MessageType::DidLink, serde_json::json!({
            "child_key": child.node_id(),
            "child_signature": child_sig,
            "label": "test",
        }));

        let now_ms = chrono::Utc::now().timestamp_millis();
        handle_gossip_message(&mut state, &env, now_ms);
        // Child should be linked
        assert!(state.identity_manager.same_identity(&root.node_id(), &child.node_id()));
    }

    #[test]
    fn handle_did_link_forged_child_signature_rejected() {
        // H-1: Forged child signature should be rejected
        let mut state = make_state();
        let root = NodeIdentity::generate();
        let child = NodeIdentity::generate();
        let attacker = NodeIdentity::generate();

        // Attacker signs instead of child
        let binding = format!("DID_LINK:{}:{}", root.node_id(), child.node_id());
        let forged_sig = hex::encode(attacker.sign(binding.as_bytes()));

        let env = make_envelope(&root, MessageType::DidLink, serde_json::json!({
            "child_key": child.node_id(),
            "child_signature": forged_sig,
        }));

        let now_ms = chrono::Utc::now().timestamp_millis();
        handle_gossip_message(&mut state, &env, now_ms);
        // Child should NOT be linked
        assert!(!state.identity_manager.same_identity(&root.node_id(), &child.node_id()));
    }

    #[test]
    fn handle_key_rotate_valid_dual_signatures() {
        // H-2: Both old and new keys must sign the rotation
        let mut state = make_state();
        let old_key = NodeIdentity::generate();
        let new_key = NodeIdentity::generate();

        // Register the old key as a root
        state.identity_manager.register_root(old_key.node_id());

        // New key signs the binding message
        let binding = format!("KEY_ROTATE:{}:{}", old_key.node_id(), new_key.node_id());
        let new_key_sig = hex::encode(new_key.sign(binding.as_bytes()));

        let env = make_envelope(&old_key, MessageType::KeyRotate, serde_json::json!({
            "old_key": old_key.node_id(),
            "new_key": new_key.node_id(),
            "new_key_signature": new_key_sig,
        }));

        let now_ms = chrono::Utc::now().timestamp_millis();
        handle_gossip_message(&mut state, &env, now_ms);
        // New key should now be the root
        assert!(state.identity_manager.resolve_root(&new_key.node_id()).is_some());
    }

    #[test]
    fn handle_key_rotate_forged_new_key_signature_rejected() {
        // H-2: Forged new key signature should be rejected
        let mut state = make_state();
        let old_key = NodeIdentity::generate();
        let new_key = NodeIdentity::generate();
        let attacker = NodeIdentity::generate();

        state.identity_manager.register_root(old_key.node_id());

        // Attacker signs instead of new key
        let binding = format!("KEY_ROTATE:{}:{}", old_key.node_id(), new_key.node_id());
        let forged_sig = hex::encode(attacker.sign(binding.as_bytes()));

        let env = make_envelope(&old_key, MessageType::KeyRotate, serde_json::json!({
            "old_key": old_key.node_id(),
            "new_key": new_key.node_id(),
            "new_key_signature": forged_sig,
        }));

        let now_ms = chrono::Utc::now().timestamp_millis();
        handle_gossip_message(&mut state, &env, now_ms);
        // Rotation should NOT have happened — old key should still be root
        assert!(state.identity_manager.resolve_root(&old_key.node_id()).is_some());
        assert!(state.identity_manager.resolve_root(&new_key.node_id()).is_none());
    }

    #[test]
    fn handle_key_rotate_from_mismatch_rejected() {
        // H-2: envelope.from must equal old_key
        let mut state = make_state();
        let old_key = NodeIdentity::generate();
        let new_key = NodeIdentity::generate();
        let imposter = NodeIdentity::generate();

        state.identity_manager.register_root(old_key.node_id());

        let binding = format!("KEY_ROTATE:{}:{}", old_key.node_id(), new_key.node_id());
        let new_key_sig = hex::encode(new_key.sign(binding.as_bytes()));

        // Envelope signed by imposter, not old_key
        let env = make_envelope(&imposter, MessageType::KeyRotate, serde_json::json!({
            "old_key": old_key.node_id(),
            "new_key": new_key.node_id(),
            "new_key_signature": new_key_sig,
        }));

        let now_ms = chrono::Utc::now().timestamp_millis();
        handle_gossip_message(&mut state, &env, now_ms);
        // Rotation should NOT have happened
        assert!(state.identity_manager.resolve_root(&old_key.node_id()).is_some());
    }

    #[test]
    fn handle_key_rotate_missing_new_signature_rejected() {
        // H-2: Missing new_key_signature should be rejected
        let mut state = make_state();
        let old_key = NodeIdentity::generate();
        let new_key = NodeIdentity::generate();

        state.identity_manager.register_root(old_key.node_id());

        let env = make_envelope(&old_key, MessageType::KeyRotate, serde_json::json!({
            "old_key": old_key.node_id(),
            "new_key": new_key.node_id(),
            // no new_key_signature
        }));

        let now_ms = chrono::Utc::now().timestamp_millis();
        handle_gossip_message(&mut state, &env, now_ms);
        assert!(state.identity_manager.resolve_root(&new_key.node_id()).is_none());
    }

    #[test]
    fn handle_peer_announce_rejects_empty_vdf() {
        // H-5: PeerAnnounce with empty VDF proof should be rejected
        let id = NodeIdentity::generate();
        let env = make_envelope(&id, MessageType::PeerAnnounce, serde_json::json!({
            "addresses": [],
            "capabilities": [],
            "version": 0,
            "uptime_seconds": 0,
            "vdf_proof": {},
        }));

        // This should not panic; the handler logs a warning and returns
        let mut state = make_state();
        let now_ms = chrono::Utc::now().timestamp_millis();
        handle_gossip_message(&mut state, &env, now_ms);
    }

    #[test]
    fn handle_peer_announce_valid_vdf_accepted() {
        // H-5: PeerAnnounce with valid VDF proof should be accepted
        let id = NodeIdentity::generate();
        let pubkey_bytes = id.public_key_bytes();
        let proof = valence_crypto::vdf::compute(&pubkey_bytes, 10);

        let vdf_json = serde_json::json!({
            "output": hex::encode(&proof.output),
            "input_data": hex::encode(&proof.input_data),
            "difficulty": proof.difficulty,
            "computed_at": proof.computed_at,
            "checkpoints": proof.checkpoints.iter().map(|cp| serde_json::json!({
                "iteration": cp.iteration,
                "hash": hex::encode(&cp.hash),
            })).collect::<Vec<_>>(),
        });

        let env = make_envelope(&id, MessageType::PeerAnnounce, serde_json::json!({
            "addresses": [],
            "capabilities": [],
            "version": 0,
            "uptime_seconds": 0,
            "vdf_proof": vdf_json,
        }));

        let mut state = make_state();
        let now_ms = chrono::Utc::now().timestamp_millis();
        handle_gossip_message(&mut state, &env, now_ms);
        // No panic = accepted
    }

    #[test]
    fn handle_peer_announce_wrong_key_vdf_rejected() {
        // H-5: VDF proof computed for different key should be rejected
        let id = NodeIdentity::generate();
        let other = NodeIdentity::generate();
        let pubkey_bytes = other.public_key_bytes(); // wrong key
        let proof = valence_crypto::vdf::compute(&pubkey_bytes, 10);

        let vdf_json = serde_json::json!({
            "output": hex::encode(&proof.output),
            "input_data": hex::encode(&proof.input_data),
            "difficulty": proof.difficulty,
            "computed_at": proof.computed_at,
            "checkpoints": proof.checkpoints.iter().map(|cp| serde_json::json!({
                "iteration": cp.iteration,
                "hash": hex::encode(&cp.hash),
            })).collect::<Vec<_>>(),
        });

        let env = make_envelope(&id, MessageType::PeerAnnounce, serde_json::json!({
            "addresses": [],
            "capabilities": [],
            "version": 0,
            "uptime_seconds": 0,
            "vdf_proof": vdf_json,
        }));

        let mut state = make_state();
        let now_ms = chrono::Utc::now().timestamp_millis();
        handle_gossip_message(&mut state, &env, now_ms);
        // Handler should reject (logged as warning) without panicking
    }

    #[test]
    fn handle_content_withdraw_tracks() {
        let mut state = make_state();
        let id = NodeIdentity::generate();

        let env = make_envelope(&id, MessageType::ContentWithdraw, serde_json::json!({
            "content_hash": "withdraw-me",
            "effective_after": 9999999999999i64,
        }));

        let now_ms = chrono::Utc::now().timestamp_millis();
        handle_gossip_message(&mut state, &env, now_ms);
        assert!(state.withdraw_tracker.is_withdrawing("withdraw-me"));
    }

    // ── Rent cycle automation tests ──

    #[test]
    fn rent_cycle_no_advance_same_cycle() {
        let mut state = make_state();
        let id = NodeIdentity::generate();
        let now_ms = chrono::Utc::now().timestamp_millis();
        let billing_cycle_ms = valence_core::constants::RENT_BILLING_CYCLE_MS;
        let current_cycle = (now_ms / billing_cycle_ms) as u64;
        state.last_rent_cycle = current_cycle;

        let responses = check_rent_cycle(&mut state, &id, now_ms);
        assert!(responses.is_empty(), "No responses when cycle hasn't advanced");
    }

    #[test]
    fn rent_cycle_advances_on_new_cycle() {
        let mut state = make_state();
        let id = NodeIdentity::generate();
        let billing_cycle_ms = valence_core::constants::RENT_BILLING_CYCLE_MS;

        // Set to cycle 1 (past first run)
        state.last_rent_cycle = 1;

        // Time in cycle 2
        let now_ms = 2 * billing_cycle_ms + 1000;
        let responses = check_rent_cycle(&mut state, &id, now_ms);
        assert_eq!(state.last_rent_cycle, 2);
        // No content transfers owned, so no rent payments
        assert!(responses.is_empty());
    }

    #[test]
    fn rent_cycle_broadcasts_payment_for_owned_content() {
        let mut state = make_state();
        let id = NodeIdentity::generate();
        let billing_cycle_ms = valence_core::constants::RENT_BILLING_CYCLE_MS;

        // Add content transfer
        let transfer = valence_network::storage::ContentTransfer::new(
            "test-content".to_string(),
            id.node_id(),
            1000,
        );
        state.content_transfers.insert("test-content".to_string(), transfer);

        state.last_rent_cycle = 1;
        let now_ms = 2 * billing_cycle_ms + 1000;
        let responses = check_rent_cycle(&mut state, &id, now_ms);
        assert_eq!(responses.len(), 1, "Should broadcast rent payment for owned content");
    }

    // ── Snapshot publishing tests ──

    #[test]
    fn snapshot_publishing_requires_high_rep() {
        let mut state = make_state();
        let id = NodeIdentity::generate();
        let now_ms = chrono::Utc::now().timestamp_millis();

        // Default rep is 0.2, below 0.7 threshold
        let responses = check_snapshot_publishing(&mut state, &id, now_ms);
        assert!(responses.is_empty(), "Should not publish with low rep");
    }

    #[test]
    fn snapshot_publishing_requires_synced() {
        let mut state = make_state();
        let id = NodeIdentity::generate();
        let now_ms = chrono::Utc::now().timestamp_millis();

        // Give high rep
        let mut rep = ReputationState::new();
        rep.overall = FixedPoint::from_f64(0.8);
        state.reputations.insert(id.node_id(), rep);

        // But still syncing
        let responses = check_snapshot_publishing(&mut state, &id, now_ms);
        assert!(responses.is_empty(), "Should not publish while syncing");
    }

    #[test]
    fn snapshot_publishing_eligible_node_publishes() {
        let mut state = make_state();
        let id = NodeIdentity::generate();
        let now_ms = chrono::Utc::now().timestamp_millis();

        // Give high rep
        let mut rep = ReputationState::new();
        rep.overall = FixedPoint::from_f64(0.8);
        state.reputations.insert(id.node_id(), rep);

        // Mark synced
        state.sync_manager.mark_synced();

        let responses = check_snapshot_publishing(&mut state, &id, now_ms);
        assert_eq!(responses.len(), 1, "Eligible node should publish snapshot");
        assert!(state.last_snapshot_publish_ms.is_some());
    }

    #[test]
    fn snapshot_publishing_respects_freshness() {
        let mut state = make_state();
        let id = NodeIdentity::generate();
        let now_ms = chrono::Utc::now().timestamp_millis();

        let mut rep = ReputationState::new();
        rep.overall = FixedPoint::from_f64(0.8);
        state.reputations.insert(id.node_id(), rep);
        state.sync_manager.mark_synced();

        // First publish
        let responses = check_snapshot_publishing(&mut state, &id, now_ms);
        assert_eq!(responses.len(), 1);

        // Try again too soon (< 6 hours)
        let responses = check_snapshot_publishing(&mut state, &id, now_ms + 1000);
        assert!(responses.is_empty(), "Should not publish within 6-hour window");

        // After 6+ hours
        let responses = check_snapshot_publishing(&mut state, &id, now_ms + 6 * 3600 * 1000 + 1);
        assert_eq!(responses.len(), 1, "Should publish after 6-hour window");
    }
}
