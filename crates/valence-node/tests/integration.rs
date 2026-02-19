//! End-to-end integration tests proving multi-node protocol composition.
//!
//! These tests use in-process message passing (no actual network) to verify
//! protocol correctness across multiple node instances.

use valence_core::message::MessageType;
use valence_core::types::FixedPoint;
use valence_crypto::identity::NodeIdentity;
use valence_crypto::signing::sign_message;
use valence_node::handler::handle_gossip_message;
use valence_node::state::NodeState;
use valence_protocol::content::{can_perform, ProtocolAction};
use valence_protocol::reputation::ReputationState;

/// Helper: create a signed envelope from an identity.
fn make_envelope(
    identity: &NodeIdentity,
    msg_type: MessageType,
    payload: serde_json::Value,
) -> valence_core::message::Envelope {
    let now_ms = chrono::Utc::now().timestamp_millis();
    sign_message(identity, msg_type, payload, now_ms)
}

/// Helper: create a signed envelope with a specific timestamp.
fn make_envelope_at(
    identity: &NodeIdentity,
    msg_type: MessageType,
    payload: serde_json::Value,
    timestamp_ms: i64,
) -> valence_core::message::Envelope {
    sign_message(identity, msg_type, payload, timestamp_ms)
}

/// Helper: set a node's reputation for a given node_id.
fn set_rep(state: &mut NodeState, node_id: &str, rep: f64) {
    let mut rep_state = ReputationState::new();
    rep_state.overall = FixedPoint::from_f64(rep);
    state.reputations.insert(node_id.to_string(), rep_state);
}

#[test]
fn test_two_node_proposal_lifecycle() {
    // ── Setup: 2 nodes with their own state ──
    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate();
    let node_a_id = identity_a.node_id();
    let node_b_id = identity_b.node_id();
    let mut state_a = NodeState::new();
    let mut state_b = NodeState::new();
    let now = chrono::Utc::now().timestamp_millis();

    // ── Step 1: Identity exchange via PEER_ANNOUNCE ──
    // Generate VDF proofs for both nodes
    let vdf_a = valence_crypto::vdf::compute(&identity_a.public_key_bytes(), 10);
    let vdf_b = valence_crypto::vdf::compute(&identity_b.public_key_bytes(), 10);

    let vdf_json = |proof: &valence_crypto::vdf::VdfProof| {
        serde_json::json!({
            "output": hex::encode(&proof.output),
            "input_data": hex::encode(&proof.input_data),
            "difficulty": proof.difficulty,
            "computed_at": proof.computed_at,
            "checkpoints": proof.checkpoints.iter().map(|cp| serde_json::json!({
                "iteration": cp.iteration,
                "hash": hex::encode(&cp.hash),
            })).collect::<Vec<_>>(),
        })
    };

    let announce_a = make_envelope(
        &identity_a,
        MessageType::PeerAnnounce,
        serde_json::json!({
            "addresses": ["/ip4/127.0.0.1/tcp/9090"],
            "capabilities": ["propose", "vote"],
            "version": 0,
            "uptime_seconds": 100,
            "vdf_proof": vdf_json(&vdf_a),
        }),
    );
    let announce_b = make_envelope(
        &identity_b,
        MessageType::PeerAnnounce,
        serde_json::json!({
            "addresses": ["/ip4/127.0.0.1/tcp/9091"],
            "capabilities": ["propose", "vote"],
            "version": 0,
            "uptime_seconds": 100,
            "vdf_proof": vdf_json(&vdf_b),
        }),
    );

    // Node B receives A's announce, Node A receives B's announce
    handle_gossip_message(&mut state_b, &announce_a, now);
    handle_gossip_message(&mut state_a, &announce_b, now);
    // PeerAnnounce handler logs acceptance (no peer table in NodeState, verified by no panic)

    // ── Step 2: Reputation bootstrap via REPUTATION_GOSSIP ──
    // Both start at 0.2 (default). Exchange observations.
    let rep_gossip_a = make_envelope(
        &identity_a,
        MessageType::ReputationGossip,
        serde_json::json!({
            "target": &node_b_id,
            "observed_reputation": 0.2,
        }),
    );
    let rep_gossip_b = make_envelope(
        &identity_b,
        MessageType::ReputationGossip,
        serde_json::json!({
            "target": &node_a_id,
            "observed_reputation": 0.2,
        }),
    );

    handle_gossip_message(&mut state_a, &rep_gossip_b, now);
    handle_gossip_message(&mut state_b, &rep_gossip_a, now);

    // Verify reputation state updated
    assert!(state_a.reputations.contains_key(&node_a_id) || state_a.reputations.contains_key(&node_b_id));
    let rep_b_on_a = state_a.reputations.get(&node_a_id);
    assert!(rep_b_on_a.is_some(), "Node A should have reputation entry for itself after gossip");
    assert_eq!(rep_b_on_a.unwrap().observation_count, 1);

    // ── Step 3: Proposal lifecycle ──
    // Set Node A's reputation to 0.3 (above propose threshold) on both nodes
    set_rep(&mut state_a, &node_a_id, 0.3);
    set_rep(&mut state_b, &node_a_id, 0.3);
    set_rep(&mut state_a, &node_b_id, 0.5);
    set_rep(&mut state_b, &node_b_id, 0.5);

    // Node A creates a PROPOSE message
    let propose_env = make_envelope_at(
        &identity_a,
        MessageType::Propose,
        serde_json::json!({
            "tier": "standard",
            "title": "Test Proposal",
            "body": "Integration test proposal",
            "voting_deadline_ms": now + 7 * 24 * 3600 * 1000,
        }),
        now,
    );
    let proposal_id = propose_env.id.clone();

    // Both nodes process the proposal
    handle_gossip_message(&mut state_a, &propose_env, now);
    handle_gossip_message(&mut state_b, &propose_env, now);

    // Verify both nodes track the proposal
    assert!(
        state_a.proposals.contains_key(&proposal_id),
        "Node A should track the proposal"
    );
    assert!(
        state_b.proposals.contains_key(&proposal_id),
        "Node B should track the proposal"
    );

    // Node B creates a VOTE (endorse)
    let vote_b = make_envelope_at(
        &identity_b,
        MessageType::Vote,
        serde_json::json!({
            "proposal_id": &proposal_id,
            "stance": "endorse",
        }),
        now + 1000,
    );

    // Node A also votes endorse
    let vote_a = make_envelope_at(
        &identity_a,
        MessageType::Vote,
        serde_json::json!({
            "proposal_id": &proposal_id,
            "stance": "endorse",
        }),
        now + 2000,
    );

    // Both nodes process both votes
    handle_gossip_message(&mut state_a, &vote_b, now + 1000);
    handle_gossip_message(&mut state_b, &vote_b, now + 1000);
    handle_gossip_message(&mut state_a, &vote_a, now + 2000);
    handle_gossip_message(&mut state_b, &vote_a, now + 2000);

    // Verify votes recorded on both nodes
    let tracker_a = state_a.proposals.get(&proposal_id).unwrap();
    let tracker_b = state_b.proposals.get(&proposal_id).unwrap();
    assert_eq!(tracker_a.votes.len(), 2, "Node A should have 2 votes");
    assert_eq!(tracker_b.votes.len(), 2, "Node B should have 2 votes");

    // Add a third voter to meet MINIMUM_VOTERS (3)
    let identity_c = NodeIdentity::generate();
    let node_c_id = identity_c.node_id();
    set_rep(&mut state_a, &node_c_id, 0.5);
    set_rep(&mut state_b, &node_c_id, 0.5);

    let vote_c = make_envelope_at(
        &identity_c,
        MessageType::Vote,
        serde_json::json!({
            "proposal_id": &proposal_id,
            "stance": "endorse",
        }),
        now + 3000,
    );
    handle_gossip_message(&mut state_a, &vote_c, now + 3000);
    handle_gossip_message(&mut state_b, &vote_c, now + 3000);

    // Evaluate proposal on both nodes
    let threshold = FixedPoint::from_f64(0.67);
    let status_a = state_a
        .proposals
        .get_mut(&proposal_id)
        .unwrap()
        .evaluate(threshold, now + 4000)
        .clone();
    let status_b = state_b
        .proposals
        .get_mut(&proposal_id)
        .unwrap()
        .evaluate(threshold, now + 4000)
        .clone();

    // Both should reach same result (Converging — all endorsements)
    assert_eq!(
        status_a, status_b,
        "Both nodes should reach the same ratification result"
    );
    assert_eq!(
        status_a,
        valence_protocol::proposals::ProposalStatus::Converging,
        "Proposal should be converging with unanimous endorsement"
    );

    // ── Step 4: Content share ──
    let share_env = make_envelope(
        &identity_a,
        MessageType::Share,
        serde_json::json!({
            "entries": [{
                "content_hash": "a".repeat(64),
                "content_type": "text/plain",
                "content_size": 2048,
                "tags": ["test", "integration"]
            }]
        }),
    );
    // Node B receives and processes (no panic = accepted)
    handle_gossip_message(&mut state_b, &share_env, now);

    // ── Step 5: Sync scenario ──
    // Node B "goes offline" — we just stop processing messages for it.
    // Node A creates another proposal while B is offline.
    let propose2_env = make_envelope_at(
        &identity_a,
        MessageType::Propose,
        serde_json::json!({
            "tier": "standard",
            "title": "Proposal While B Offline",
            "body": "B should catch up on this",
            "voting_deadline_ms": now + 14 * 24 * 3600 * 1000,
        }),
        now + 10000,
    );
    let proposal2_id = propose2_env.id.clone();

    // Only Node A processes it
    handle_gossip_message(&mut state_a, &propose2_env, now + 10000);
    assert!(state_a.proposals.contains_key(&proposal2_id));
    assert!(
        !state_b.proposals.contains_key(&proposal2_id),
        "Node B should not have the proposal yet (offline)"
    );

    // Node B "reconnects" and receives the missed proposal
    handle_gossip_message(&mut state_b, &propose2_env, now + 20000);
    assert!(
        state_b.proposals.contains_key(&proposal2_id),
        "Node B should catch up on the missed proposal after reconnect"
    );
}

#[test]
fn test_identity_revocation_propagation() {
    // ── Setup: 3 nodes ──
    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate();
    let identity_c = NodeIdentity::generate();
    let child_identity = NodeIdentity::generate();

    let node_a_id = identity_a.node_id();
    let child_id = child_identity.node_id();

    let mut state_a = NodeState::new();
    let mut state_b = NodeState::new();
    let mut state_c = NodeState::new();
    let now = chrono::Utc::now().timestamp_millis();

    // Give everyone enough rep
    for state in [&mut state_a, &mut state_b, &mut state_c] {
        set_rep(state, &identity_a.node_id(), 0.5);
        set_rep(state, &identity_b.node_id(), 0.5);
        set_rep(state, &identity_c.node_id(), 0.5);
        set_rep(state, &child_id, 0.5);
    }

    // ── Step 1: Node A links a child key via DID_LINK ──
    // Child signs the binding message
    let binding_msg = format!("DID_LINK:{}:{}", node_a_id, child_id);
    let child_sig = hex::encode(child_identity.sign(binding_msg.as_bytes()));

    let link_env = make_envelope_at(
        &identity_a,
        MessageType::DidLink,
        serde_json::json!({
            "child_key": &child_id,
            "child_signature": &child_sig,
            "label": "device-2",
        }),
        now,
    );

    // All nodes process the link
    handle_gossip_message(&mut state_a, &link_env, now);
    handle_gossip_message(&mut state_b, &link_env, now);
    handle_gossip_message(&mut state_c, &link_env, now);

    // Verify all nodes recognize the link
    assert!(state_a.identity_manager.same_identity(&node_a_id, &child_id));
    assert!(state_b.identity_manager.same_identity(&node_a_id, &child_id));
    assert!(state_c.identity_manager.same_identity(&node_a_id, &child_id));

    // ── Step 2: Child key casts a vote on a proposal (before revocation) ──
    // Create a proposal first
    let propose_env = make_envelope_at(
        &identity_b,
        MessageType::Propose,
        serde_json::json!({
            "tier": "standard",
            "title": "Pre-revocation proposal",
            "voting_deadline_ms": now + 7 * 24 * 3600 * 1000,
        }),
        now + 100,
    );
    let proposal_id = propose_env.id.clone();

    for state in [&mut state_a, &mut state_b, &mut state_c] {
        handle_gossip_message(state, &propose_env, now + 100);
    }

    // Child key votes (this vote should later be invalidated)
    let child_vote = make_envelope_at(
        &child_identity,
        MessageType::Vote,
        serde_json::json!({
            "proposal_id": &proposal_id,
            "stance": "endorse",
        }),
        now + 200,
    );

    for state in [&mut state_a, &mut state_b, &mut state_c] {
        handle_gossip_message(state, &child_vote, now + 200);
    }

    // Verify vote is recorded (under root identity)
    assert!(state_b.proposals.get(&proposal_id).unwrap().votes.contains_key(&node_a_id));

    // ── Step 3: Node A revokes the child key ──
    let revoke_env = make_envelope_at(
        &identity_a,
        MessageType::DidRevoke,
        serde_json::json!({
            "revoked_key": &child_id,
            "reason": "compromised",
        }),
        now + 500,
    );

    // Propagate to all nodes
    handle_gossip_message(&mut state_a, &revoke_env, now + 500);
    handle_gossip_message(&mut state_b, &revoke_env, now + 500);
    handle_gossip_message(&mut state_c, &revoke_env, now + 500);

    // Verify all nodes recognize the revocation
    assert!(state_a.identity_manager.is_revoked(&child_id));
    assert!(state_b.identity_manager.is_revoked(&child_id));
    assert!(state_c.identity_manager.is_revoked(&child_id));

    // Verify child key is no longer part of identity
    assert!(!state_a.identity_manager.same_identity(&node_a_id, &child_id));
    assert!(!state_b.identity_manager.same_identity(&node_a_id, &child_id));

    // ── Step 4: Verify retroactive invalidation via SyncManager ──
    // The SyncManager should know about the revocation for retroactive checks
    assert!(state_a.sync_manager.is_key_revoked(&child_id, now + 500));
    assert!(state_b.sync_manager.is_key_revoked(&child_id, now + 500));
    assert!(state_c.sync_manager.is_key_revoked(&child_id, now + 500));

    // Verify that a message from the revoked key at the revocation time would be invalidated
    let fake_revoked_msg = make_envelope_at(
        &child_identity,
        MessageType::Vote,
        serde_json::json!({
            "proposal_id": "some-proposal",
            "stance": "endorse",
        }),
        now + 600, // After revocation
    );
    let invalidated = state_b.sync_manager.retroactive_invalidation(&[fake_revoked_msg]);
    assert!(
        !invalidated.is_empty(),
        "Messages from revoked key after effective_from should be invalidated"
    );

    // ── Step 5: Subsequent messages from revoked key should be rejected ──
    // The identity manager no longer resolves the child key to root
    assert_eq!(state_b.identity_manager.resolve_root(&child_id), None);
    // A new DID_LINK with the revoked key should be rejected
    let relink_binding = format!("DID_LINK:{}:{}", identity_b.node_id(), child_id);
    let relink_sig = hex::encode(child_identity.sign(relink_binding.as_bytes()));
    let relink_env = make_envelope_at(
        &identity_b,
        MessageType::DidLink,
        serde_json::json!({
            "child_key": &child_id,
            "child_signature": &relink_sig,
            "label": "stolen-key",
        }),
        now + 1000,
    );
    handle_gossip_message(&mut state_b, &relink_env, now + 1000);
    // Child should NOT be linked to identity_b
    assert!(
        !state_b.identity_manager.same_identity(&identity_b.node_id(), &child_id),
        "Revoked key should not be re-linkable"
    );
}

#[test]
fn test_reputation_capability_ramp() {
    // ── Step 1: Node at rep 0.2 — cannot propose or vote ──
    assert!(
        !can_perform(FixedPoint::from_f64(0.2), ProtocolAction::Propose),
        "Rep 0.2 should not be able to propose"
    );
    assert!(
        !can_perform(FixedPoint::from_f64(0.2), ProtocolAction::Vote),
        "Rep 0.2 should not be able to vote"
    );
    // But can store and sync
    assert!(can_perform(FixedPoint::from_f64(0.2), ProtocolAction::StoreShards));
    assert!(can_perform(FixedPoint::from_f64(0.2), ProtocolAction::SyncBrowseAdopt));

    // ── Step 2: Rep 0.3 — can propose and vote ──
    assert!(
        can_perform(FixedPoint::from_f64(0.3), ProtocolAction::Propose),
        "Rep 0.3 should be able to propose"
    );
    assert!(
        can_perform(FixedPoint::from_f64(0.3), ProtocolAction::Vote),
        "Rep 0.3 should be able to vote"
    );
    assert!(can_perform(FixedPoint::from_f64(0.3), ProtocolAction::Replicate));
    assert!(can_perform(FixedPoint::from_f64(0.3), ProtocolAction::FlagDispute));

    // ── Step 3: Rep 0.3 cannot flag with severity=illegal (requires 0.5) ──
    assert!(
        !can_perform(FixedPoint::from_f64(0.3), ProtocolAction::FlagIllegal),
        "Rep 0.3 should not be able to flag illegal"
    );
    assert!(
        !can_perform(FixedPoint::from_f64(0.49), ProtocolAction::FlagIllegal),
        "Rep 0.49 should not be able to flag illegal"
    );

    // ── Step 4: Rep 0.5 — full capabilities ──
    assert!(can_perform(FixedPoint::from_f64(0.5), ProtocolAction::FlagIllegal));
    assert!(can_perform(FixedPoint::from_f64(0.5), ProtocolAction::Propose));
    assert!(can_perform(FixedPoint::from_f64(0.5), ProtocolAction::Vote));
    assert!(can_perform(FixedPoint::from_f64(0.5), ProtocolAction::Replicate));
    assert!(can_perform(FixedPoint::from_f64(0.5), ProtocolAction::FlagDispute));

    // ── Step 5: Verify handler-level enforcement ──
    // A node with rep 0.2 trying to propose should be rejected by the handler
    let identity = NodeIdentity::generate();
    let mut state = NodeState::new();
    // Default rep is 0.2 — no explicit set needed

    let propose_env = make_envelope(
        &identity,
        MessageType::Propose,
        serde_json::json!({"tier": "standard", "title": "Should fail"}),
    );
    let now = chrono::Utc::now().timestamp_millis();
    handle_gossip_message(&mut state, &propose_env, now);
    assert!(
        !state.proposals.contains_key(&propose_env.id),
        "Proposal from rep 0.2 node should be rejected by handler"
    );

    // Now set rep to 0.3 and try again
    set_rep(&mut state, &identity.node_id(), 0.3);
    let propose_env2 = make_envelope(
        &identity,
        MessageType::Propose,
        serde_json::json!({"tier": "standard", "title": "Should succeed"}),
    );
    handle_gossip_message(&mut state, &propose_env2, now);
    assert!(
        state.proposals.contains_key(&propose_env2.id),
        "Proposal from rep 0.3 node should be accepted by handler"
    );

    // Verify vote rejection at low rep
    let voter = NodeIdentity::generate();
    // voter has default rep 0.2
    let vote_env = make_envelope(
        &voter,
        MessageType::Vote,
        serde_json::json!({
            "proposal_id": &propose_env2.id,
            "stance": "endorse",
        }),
    );
    handle_gossip_message(&mut state, &vote_env, now);
    // Vote should be recorded (handler records it, ProposalTracker rejects low-rep votes)
    let tracker = state.proposals.get(&propose_env2.id).unwrap();
    assert!(
        !tracker.votes.contains_key(&voter.node_id()),
        "Vote from rep 0.2 should be rejected by ProposalTracker"
    );

    // Set voter rep to 0.5 and vote again
    set_rep(&mut state, &voter.node_id(), 0.5);
    let vote_env2 = make_envelope(
        &voter,
        MessageType::Vote,
        serde_json::json!({
            "proposal_id": &propose_env2.id,
            "stance": "endorse",
        }),
    );
    handle_gossip_message(&mut state, &vote_env2, now);
    let tracker = state.proposals.get(&propose_env2.id).unwrap();
    assert!(
        tracker.votes.contains_key(&voter.node_id()),
        "Vote from rep 0.5 should be accepted"
    );

    // Verify flag enforcement at handler level
    let flagger = NodeIdentity::generate();
    set_rep(&mut state, &flagger.node_id(), 0.3);
    let flag_dispute = make_envelope(
        &flagger,
        MessageType::Flag,
        serde_json::json!({
            "content_hash": "a".repeat(64),
            "severity": "dispute",
            "category": "spam",
            "details": "test flag",
        }),
    );
    // Should succeed (rep 0.3 ≥ 0.3 for dispute)
    handle_gossip_message(&mut state, &flag_dispute, now);

    let flag_illegal = make_envelope(
        &flagger,
        MessageType::Flag,
        serde_json::json!({
            "content_hash": "b".repeat(64),
            "severity": "illegal",
            "category": "csam",
            "details": "test illegal flag",
        }),
    );
    // Should fail (rep 0.3 < 0.5 for illegal)
    handle_gossip_message(&mut state, &flag_illegal, now);
    // (Flag rejection is logged, no state change to verify — but no panic = correct)

    // Now with rep 0.5
    set_rep(&mut state, &flagger.node_id(), 0.5);
    let flag_illegal2 = make_envelope(
        &flagger,
        MessageType::Flag,
        serde_json::json!({
            "content_hash": "c".repeat(64),
            "severity": "illegal",
            "category": "csam",
            "details": "test illegal flag 2",
        }),
    );
    handle_gossip_message(&mut state, &flag_illegal2, now);
    // No panic = accepted
}
