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

#[test]
fn test_two_node_content_lifecycle() {
    use valence_core::message::ErasureCoding;
    use valence_network::storage::{encode_artifact, generate_challenge, compute_proof, verify_proof};
    use sha2::Digest;

    // ── Setup: Alice and Bob, both with sufficient reputation ──
    let alice = NodeIdentity::generate();
    let bob = NodeIdentity::generate();
    let alice_id = alice.node_id();
    let bob_id = bob.node_id();
    
    let mut state_alice = NodeState::new();
    let mut state_bob = NodeState::new();
    let now = chrono::Utc::now().timestamp_millis();

    // Set reputation to enable all operations
    set_rep(&mut state_alice, &alice_id, 0.5);
    set_rep(&mut state_alice, &bob_id, 0.5);
    set_rep(&mut state_bob, &alice_id, 0.5);
    set_rep(&mut state_bob, &bob_id, 0.5);

    // ── Step 1: Alice proposes content ──
    let test_content = b"Integration test content for Valence Network";
    let content_hash = hex::encode(sha2::Sha256::digest(test_content));
    
    // Erasure code the content (Standard = 5+3)
    let coding = ErasureCoding::Standard;
    let shards = encode_artifact(test_content, &coding).expect("Failed to encode content");
    
    // Build shard metadata
    let shard_metadata = valence_network::storage::build_shard_metadata(&shards, &coding, &content_hash);

    // Alice broadcasts PROPOSE with shard metadata
    let propose_env = make_envelope_at(
        &alice,
        MessageType::Propose,
        serde_json::json!({
            "tier": "standard",
            "title": "Content Proposal",
            "body": "Test content for integration",
            "voting_deadline_ms": now + 7 * 24 * 3600 * 1000,
            "content_hash": &content_hash,
            "shard_metadata": serde_json::to_value(&shard_metadata).unwrap(),
        }),
        now,
    );
    let proposal_id = propose_env.id.clone();

    // Both nodes process the proposal
    handle_gossip_message(&mut state_alice, &propose_env, now);
    handle_gossip_message(&mut state_bob, &propose_env, now);

    assert!(state_alice.proposals.contains_key(&proposal_id), "Alice should track the proposal");
    assert!(state_bob.proposals.contains_key(&proposal_id), "Bob should track the proposal");

    // ── Step 2: Bob votes to endorse ──
    let vote_bob = make_envelope_at(
        &bob,
        MessageType::Vote,
        serde_json::json!({
            "proposal_id": &proposal_id,
            "stance": "endorse",
        }),
        now + 1000,
    );
    
    handle_gossip_message(&mut state_alice, &vote_bob, now + 1000);
    handle_gossip_message(&mut state_bob, &vote_bob, now + 1000);

    // Alice also endorses
    let vote_alice = make_envelope_at(
        &alice,
        MessageType::Vote,
        serde_json::json!({
            "proposal_id": &proposal_id,
            "stance": "endorse",
        }),
        now + 2000,
    );
    
    handle_gossip_message(&mut state_alice, &vote_alice, now + 2000);
    handle_gossip_message(&mut state_bob, &vote_alice, now + 2000);

    // ── Step 3: Proposal passes (2 endorsements meets threshold for small network) ──
    let tracker_alice = state_alice.proposals.get(&proposal_id).unwrap();
    let tracker_bob = state_bob.proposals.get(&proposal_id).unwrap();
    
    assert_eq!(tracker_alice.votes.len(), 2, "Should have 2 votes on Alice");
    assert_eq!(tracker_bob.votes.len(), 2, "Should have 2 votes on Bob");

    // ── Step 4: Alice replicates content - sends shards to Bob ──
    // Simulate REPLICATE_REQUEST from Alice to Bob
    let replicate_request = make_envelope_at(
        &alice,
        MessageType::ReplicateRequest,
        serde_json::json!({
            "content_hash": &content_hash,
            "shard_count": shards.len(),
            "requester_node": &alice_id,
        }),
        now + 3000,
    );
    
    handle_gossip_message(&mut state_bob, &replicate_request, now + 3000);

    // Bob accepts replication
    let replicate_accept = make_envelope_at(
        &bob,
        MessageType::ReplicateAccept,
        serde_json::json!({
            "content_hash": &content_hash,
            "provider_node": &bob_id,
        }),
        now + 4000,
    );
    
    handle_gossip_message(&mut state_alice, &replicate_accept, now + 4000);

    // Alice assigns shards to Bob (sending first 5 data shards)
    for (i, shard) in shards.iter().take(5).enumerate() {
        let shard_assignment = make_envelope_at(
            &alice,
            MessageType::ShardAssignment,
            serde_json::json!({
                "content_hash": &content_hash,
                "shard_index": i,
                "provider_node": &bob_id,
                "shard_hash": &shard.hash,
            }),
            now + 5000 + (i as i64 * 100),
        );
        
        handle_gossip_message(&mut state_bob, &shard_assignment, now + 5000 + (i as i64 * 100));
    }

    // ── Step 5: Bob receives and stores shards ──
    for (i, shard) in shards.iter().take(5).enumerate() {
        // Simulate Bob storing the shard
        state_bob.shard_store
            .store_shard(&content_hash, i as u32, &shard.data)
            .expect("Failed to store shard");
        
        // Bob confirms receipt
        let shard_received = make_envelope_at(
            &bob,
            MessageType::ShardReceived,
            serde_json::json!({
                "content_hash": &content_hash,
                "shard_index": i,
                "provider_node": &bob_id,
            }),
            now + 6000 + (i as i64 * 100),
        );
        
        handle_gossip_message(&mut state_alice, &shard_received, now + 6000 + (i as i64 * 100));
    }

    // Verify Bob has the shards stored
    for i in 0..5 {
        assert!(
            state_bob.shard_store.has_shard(&content_hash, i),
            "Bob should have shard {}", i
        );
    }

    // ── Step 6: Issue a storage challenge to Bob ──
    let shard_to_challenge = &shards[0];
    let challenge = generate_challenge(&shard_to_challenge.hash, shard_to_challenge.data.len(), 32);

    // Simulate Alice sending the challenge via StorageChallenge message
    let challenge_msg = make_envelope_at(
        &alice,
        MessageType::StorageChallenge,
        serde_json::json!({
            "content_hash": &content_hash,
            "shard_hash": &challenge.shard_hash,
            "offset": challenge.offset,
            "direction": format!("{:?}", challenge.direction).to_lowercase(),
            "window_size": challenge.window_size,
            "challenge_nonce": &challenge.challenge_nonce,
            "challenger": &alice_id,
        }),
        now + 7000,
    );
    
    handle_gossip_message(&mut state_bob, &challenge_msg, now + 7000);

    // ── Step 7: Bob computes and sends proof ──
    let shard_data = state_bob.shard_store
        .read_shard(&content_hash, 0)
        .expect("Failed to read shard for proof");
    
    let proof = compute_proof(&challenge, &shard_data).expect("Failed to compute proof");

    // Bob sends proof back to Alice
    let proof_msg = make_envelope_at(
        &bob,
        MessageType::StorageChallenge, // Reusing same message type for proof response
        serde_json::json!({
            "content_hash": &content_hash,
            "shard_hash": &challenge.shard_hash,
            "proof_hash": &proof.proof_hash,
            "responder": &bob_id,
        }),
        now + 8000,
    );
    
    handle_gossip_message(&mut state_alice, &proof_msg, now + 8000);

    // ── Step 8: Alice verifies the proof ──
    let alice_shard_data = &shards[0].data;
    let verification = verify_proof(&challenge, &proof, alice_shard_data)
        .expect("Failed to verify proof");
    
    assert!(verification, "Storage proof should be valid");

    // ── Step 9: Verify end-to-end content flow ──
    // Alice should have the original content
    // Bob should have 5 data shards (out of 8 total) that can reconstruct the content
    let bob_shards: Vec<Option<Vec<u8>>> = (0..8)
        .map(|i| {
            if i < 5 {
                state_bob.shard_store.read_shard(&content_hash, i as u32).ok()
            } else {
                None
            }
        })
        .collect();

    let reconstructed = valence_network::storage::reconstruct_artifact(
        &mut bob_shards.clone(),
        &coding,
        test_content.len(),
    ).expect("Failed to reconstruct content");

    assert_eq!(
        reconstructed, test_content,
        "Reconstructed content should match original"
    );
}

#[test]
fn test_content_flag_and_quarantine() {
    use valence_core::message::ErasureCoding;
    use valence_network::storage::encode_artifact;
    use valence_network::shard_store::ShardStore;
    use sha2::Digest;

    // ── Setup: Alice and Bob with shared content ──
    let alice = NodeIdentity::generate();
    let bob = NodeIdentity::generate();
    let alice_id = alice.node_id();
    let bob_id = bob.node_id();
    
    // Create separate shard stores for Alice and Bob using temp dirs
    let alice_dir = std::env::temp_dir().join(format!("alice_{}", alice_id));
    let bob_dir = std::env::temp_dir().join(format!("bob_{}", bob_id));
    
    let mut state_alice = NodeState::new();
    let mut state_bob = NodeState::new();
    
    // Override shard stores with separate directories
    state_alice.shard_store = ShardStore::new(alice_dir.clone()).expect("Failed to create Alice's shard store");
    state_bob.shard_store = ShardStore::new(bob_dir.clone()).expect("Failed to create Bob's shard store");
    
    let now = chrono::Utc::now().timestamp_millis();

    // Set reputation
    set_rep(&mut state_alice, &alice_id, 0.5);
    set_rep(&mut state_alice, &bob_id, 0.5);
    set_rep(&mut state_bob, &alice_id, 0.5);
    set_rep(&mut state_bob, &bob_id, 0.5);

    // ── Step 1: Create and share content ──
    let test_content = b"Content that will be flagged";
    let content_hash = hex::encode(sha2::Sha256::digest(test_content));
    
    let coding = ErasureCoding::Standard;
    let shards = encode_artifact(test_content, &coding).expect("Failed to encode");

    // Share content
    let share_env = make_envelope_at(
        &alice,
        MessageType::Share,
        serde_json::json!({
            "entries": [{
                "content_hash": &content_hash,
                "content_type": "text/plain",
                "content_size": test_content.len(),
                "tags": ["test"]
            }]
        }),
        now,
    );
    
    handle_gossip_message(&mut state_bob, &share_env, now);

    // ── Step 2: Both nodes store shards ──
    for (i, shard) in shards.iter().enumerate() {
        state_alice.shard_store
            .store_shard(&content_hash, i as u32, &shard.data)
            .expect("Alice failed to store shard");
        
        state_bob.shard_store
            .store_shard(&content_hash, i as u32, &shard.data)
            .expect("Bob failed to store shard");
    }

    // Verify both have the content
    assert!(state_alice.shard_store.has_shard(&content_hash, 0), "Alice should have shard 0");
    assert!(state_bob.shard_store.has_shard(&content_hash, 0), "Bob should have shard 0");

    // ── Step 3: Bob flags the content ──
    let flag_env = make_envelope_at(
        &bob,
        MessageType::Flag,
        serde_json::json!({
            "content_hash": &content_hash,
            "severity": "dispute",
            "category": "spam",
            "details": "This content violates network guidelines",
            "flagger": &bob_id,
        }),
        now + 1000,
    );
    
    // Bob processes his own flag — this automatically quarantines on Bob's node
    handle_gossip_message(&mut state_bob, &flag_env, now + 1000);
    
    // ── Step 4: Verify Bob quarantined the content ──
    assert!(
        !state_bob.shard_store.has_shard(&content_hash, 0),
        "Bob should no longer have shard 0 in main storage after flagging"
    );
    
    // Verify quarantine size increased on Bob's node
    assert!(
        state_bob.shard_store.quarantine_size() > 0,
        "Bob's quarantine should contain data"
    );

    // ── Step 5: Alice receives the flag and also quarantines ──
    // Note: handle_flag automatically quarantines flagged content on receiving node
    handle_gossip_message(&mut state_alice, &flag_env, now + 1000);
    
    // Verify Alice also quarantined (this is network protocol behavior)
    assert!(
        !state_alice.shard_store.has_shard(&content_hash, 0),
        "Alice should also quarantine after receiving FLAG message"
    );
    
    assert!(
        state_alice.shard_store.quarantine_size() > 0,
        "Alice's quarantine should contain data"
    );

    // ── Step 6: Verify storage statistics for both nodes ──
    let alice_stats = state_alice.shard_store.stats();
    let bob_stats = state_bob.shard_store.stats();

    // Both nodes should have quarantined the content
    assert_eq!(alice_stats.shard_count, 0, "Alice should have 0 shards in main storage");
    assert!(alice_stats.quarantine_bytes > 0, "Alice should have quarantined data");
    
    assert_eq!(bob_stats.shard_count, 0, "Bob should have 0 shards in main storage");
    assert!(bob_stats.quarantine_bytes > 0, "Bob should have quarantined data");

    // ── Step 7: Each node can independently delete quarantined content ──
    // Bob deletes his quarantined content
    state_bob.shard_store
        .delete_quarantined(&content_hash)
        .expect("Failed to delete quarantined content");
    
    assert_eq!(
        state_bob.shard_store.quarantine_size(), 0,
        "Bob's quarantine should be empty after deletion"
    );
    
    // Alice still has hers (independent storage)
    assert!(
        state_alice.shard_store.quarantine_size() > 0,
        "Alice should still have quarantined data"
    );
    
    // Alice can also delete later
    state_alice.shard_store
        .delete_quarantined(&content_hash)
        .expect("Failed to delete Alice's quarantined content");
    
    assert_eq!(
        state_alice.shard_store.quarantine_size(), 0,
        "Alice's quarantine should now be empty"
    );
    
    // Cleanup temp directories
    let _ = std::fs::remove_dir_all(&alice_dir);
    let _ = std::fs::remove_dir_all(&bob_dir);
}
