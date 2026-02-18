//! Proposal lifecycle per §6 and vote evaluation per §7.

use std::collections::HashMap;

use valence_core::constants;
use valence_core::types::FixedPoint;
use valence_core::message::{VoteStance, ProposalTier};

use crate::identity::IdentityManager;

/// Proposal status (local per-node view, no global state machine).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalStatus {
    /// Proposal exists, votes accumulating, deadline not reached.
    Open,
    /// Weighted endorsement exceeds local threshold.
    Converging,
    /// Node considers the proposal accepted by the network.
    Ratified,
    /// Weighted rejection exceeds threshold or deadline passed without ratification.
    Rejected,
    /// This node has applied the proposal locally.
    Adopted,
    /// Voting deadline passed.
    Expired,
    /// Author withdrew.
    Withdrawn,
}

/// A vote cast on a proposal.
#[derive(Debug, Clone)]
pub struct Vote {
    /// The voter's root identity (not key, the identity).
    pub voter_id: String,
    /// Vote stance.
    pub stance: VoteStance,
    /// Voter's reputation at the time the vote was created.
    pub vote_time_reputation: FixedPoint,
    /// Timestamp of the vote message.
    pub timestamp_ms: i64,
}

/// Local proposal tracker for a single proposal.
#[derive(Debug, Clone)]
pub struct ProposalTracker {
    pub proposal_id: String,
    pub author_id: String,
    pub tier: ProposalTier,
    pub voting_deadline_ms: i64,
    pub status: ProposalStatus,
    /// One vote per identity (latest supersedes).
    pub votes: HashMap<String, Vote>,
    /// Whether the author has withdrawn this proposal.
    pub withdrawn: bool,
    /// Adoption reports (voter_id → success).
    pub adoptions: HashMap<String, bool>,
}

impl ProposalTracker {
    pub fn new(
        proposal_id: String,
        author_id: String,
        tier: ProposalTier,
        voting_deadline_ms: i64,
    ) -> Self {
        Self {
            proposal_id,
            author_id,
            tier,
            voting_deadline_ms,
            status: ProposalStatus::Open,
            votes: HashMap::new(),
            withdrawn: false,
            adoptions: HashMap::new(),
        }
    }

    /// Record a vote. Later votes from the same identity supersede earlier ones (§7).
    /// The `voter_key` is resolved to root identity via `identity_mgr` before storing.
    pub fn record_vote(&mut self, voter_key: &str, vote: Vote, identity_mgr: &IdentityManager) {
        if self.withdrawn {
            return; // §6: Stop counting votes for withdrawn proposals
        }
        
        // Resolve voter key to root identity (§1 Identity Linking)
        let root_id = identity_mgr.resolve_root(voter_key)
            .unwrap_or(voter_key); // If not found, use key as-is
        
        let existing = self.votes.get(root_id);
        if let Some(existing) = existing {
            if vote.timestamp_ms <= existing.timestamp_ms {
                return; // Old vote, ignore
            }
        }
        
        // Store vote under root identity, not signing key
        let mut resolved_vote = vote;
        resolved_vote.voter_id = root_id.to_string();
        self.votes.insert(root_id.to_string(), resolved_vote);
    }

    /// Mark as withdrawn.
    pub fn withdraw(&mut self) {
        self.withdrawn = true;
        self.status = ProposalStatus::Withdrawn;
    }

    /// Record an adoption report.
    pub fn record_adoption(&mut self, voter_id: String, success: bool) {
        self.adoptions.insert(voter_id, success);
    }

    /// Evaluate the proposal status per §7.
    /// `local_threshold`: suggested 0.67 for standard, 0.80 for protocol changes.
    /// `now_ms`: current time for deadline checking.
    pub fn evaluate(&mut self, local_threshold: FixedPoint, now_ms: i64) -> &ProposalStatus {
        if self.withdrawn {
            return &self.status;
        }

        if self.status == ProposalStatus::Adopted {
            return &self.status;
        }

        // Check deadline
        if now_ms > self.voting_deadline_ms {
            if self.status != ProposalStatus::Ratified {
                self.status = ProposalStatus::Expired;
            }
            return &self.status;
        }

        let eval = self.compute_vote_weights();

        // §7: All three conditions for ratification
        let min_voters_met = eval.distinct_voters >= constants::MINIMUM_VOTERS;
        let threshold_met = if eval.weighted_endorse.raw() + eval.weighted_reject.raw() > 0 {
            let ratio = eval.weighted_endorse.div(
                eval.weighted_endorse.saturating_add(eval.weighted_reject)
            );
            ratio.raw() >= local_threshold.raw()
        } else {
            false
        };

        // Quorum check is done separately via quorum module
        // Here we just check voter count and threshold
        if min_voters_met && threshold_met {
            self.status = ProposalStatus::Converging;
            // Note: actual ratification requires quorum check from the quorum module
        } else if min_voters_met && eval.weighted_reject.raw() > 0 {
            // Check if rejection threshold met
            let reject_ratio = eval.weighted_reject.div(
                eval.weighted_endorse.saturating_add(eval.weighted_reject)
            );
            if reject_ratio.raw() >= local_threshold.raw() {
                self.status = ProposalStatus::Rejected;
            } else {
                self.status = ProposalStatus::Open;
            }
        } else {
            self.status = ProposalStatus::Open;
        }

        &self.status
    }

    /// Compute vote weight totals.
    pub fn compute_vote_weights(&self) -> VoteEvaluation {
        let mut weighted_endorse = FixedPoint::ZERO;
        let mut weighted_reject = FixedPoint::ZERO;
        let mut weighted_abstain = FixedPoint::ZERO;
        let mut distinct_voters = 0usize;

        for vote in self.votes.values() {
            distinct_voters += 1;
            match vote.stance {
                VoteStance::Endorse => {
                    weighted_endorse = weighted_endorse.saturating_add(vote.vote_time_reputation);
                }
                VoteStance::Reject => {
                    weighted_reject = weighted_reject.saturating_add(vote.vote_time_reputation);
                }
                VoteStance::Abstain => {
                    weighted_abstain = weighted_abstain.saturating_add(vote.vote_time_reputation);
                }
            }
        }

        VoteEvaluation {
            weighted_endorse,
            weighted_reject,
            weighted_abstain,
            total_weight: weighted_endorse
                .saturating_add(weighted_reject)
                .saturating_add(weighted_abstain),
            distinct_voters,
        }
    }
}

/// Vote weight totals for evaluation.
#[derive(Debug, Clone)]
pub struct VoteEvaluation {
    pub weighted_endorse: FixedPoint,
    pub weighted_reject: FixedPoint,
    pub weighted_abstain: FixedPoint,
    pub total_weight: FixedPoint,
    pub distinct_voters: usize,
}

/// Rate limiter for proposals per §6: 3 per 7-day rolling window.
#[derive(Debug, Clone, Default)]
pub struct ProposalRateLimiter {
    /// Timestamps of recent proposals per identity.
    proposals: HashMap<String, Vec<i64>>,
}

impl ProposalRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a key (resolved to root identity) can submit a proposal.
    /// The `key` parameter is resolved to root identity before checking.
    pub fn can_propose(&self, key: &str, now_ms: i64, identity_mgr: &IdentityManager) -> bool {
        // Resolve to root identity per §1 Identity Linking
        let identity_id = identity_mgr.resolve_root(key).unwrap_or(key);
        
        let cutoff = now_ms - constants::PROPOSAL_RATE_WINDOW_MS;
        match self.proposals.get(identity_id) {
            Some(timestamps) => {
                let recent = timestamps.iter().filter(|&&t| t > cutoff).count();
                recent < constants::PROPOSAL_RATE_LIMIT
            }
            None => true,
        }
    }

    /// Record a proposal submission. The `key` is resolved to root identity before recording.
    pub fn record_proposal(&mut self, key: &str, timestamp_ms: i64, identity_mgr: &IdentityManager) {
        // Resolve to root identity per §1 Identity Linking
        let identity_id = identity_mgr.resolve_root(key).unwrap_or(key);
        
        let entry = self.proposals.entry(identity_id.to_string()).or_default();
        entry.push(timestamp_ms);

        // Prune old entries
        let cutoff = timestamp_ms - constants::PROPOSAL_RATE_WINDOW_MS;
        entry.retain(|&t| t > cutoff);
    }

    /// Transfer rate limit from old key to new key (for KEY_ROTATE per §6).
    pub fn transfer(&mut self, old_identity: &str, new_identity: &str) {
        if let Some(proposals) = self.proposals.remove(old_identity) {
            self.proposals.insert(new_identity.to_string(), proposals);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vote(voter: &str, stance: VoteStance, rep: f64, ts: i64) -> Vote {
        Vote {
            voter_id: voter.to_string(),
            stance,
            vote_time_reputation: FixedPoint::from_f64(rep),
            timestamp_ms: ts,
        }
    }

    fn make_identity_mgr() -> IdentityManager {
        IdentityManager::new()
    }

    #[test]
    fn vote_supersession() {
        let mut tracker = ProposalTracker::new(
            "p1".into(), "author".into(), ProposalTier::Standard, i64::MAX,
        );
        let mgr = make_identity_mgr();

        // First vote: endorse
        tracker.record_vote("voter1", make_vote("voter1", VoteStance::Endorse, 0.5, 1000), &mgr);
        assert_eq!(tracker.votes.len(), 1);

        // Second vote from same voter: reject (supersedes)
        tracker.record_vote("voter1", make_vote("voter1", VoteStance::Reject, 0.5, 2000), &mgr);
        assert_eq!(tracker.votes.len(), 1);
        assert_eq!(tracker.votes["voter1"].stance, VoteStance::Reject);
    }

    #[test]
    fn old_vote_ignored() {
        let mut tracker = ProposalTracker::new(
            "p1".into(), "author".into(), ProposalTier::Standard, i64::MAX,
        );
        let mgr = make_identity_mgr();
        tracker.record_vote("voter1", make_vote("voter1", VoteStance::Endorse, 0.5, 2000), &mgr);
        tracker.record_vote("voter1", make_vote("voter1", VoteStance::Reject, 0.5, 1000), &mgr); // older
        assert_eq!(tracker.votes["voter1"].stance, VoteStance::Endorse); // kept
    }

    #[test]
    fn withdrawn_stops_counting() {
        let mut tracker = ProposalTracker::new(
            "p1".into(), "author".into(), ProposalTier::Standard, i64::MAX,
        );
        let mgr = make_identity_mgr();
        tracker.record_vote("voter1", make_vote("voter1", VoteStance::Endorse, 0.5, 1000), &mgr);
        tracker.withdraw();
        tracker.record_vote("voter2", make_vote("voter2", VoteStance::Endorse, 0.5, 2000), &mgr);
        assert_eq!(tracker.votes.len(), 1); // voter2's vote not counted
    }

    #[test]
    fn evaluation_converging() {
        let mut tracker = ProposalTracker::new(
            "p1".into(), "author".into(), ProposalTier::Standard, i64::MAX,
        );
        let mgr = make_identity_mgr();
        // 3 endorsements with good reputation
        for i in 0..3 {
            let voter = format!("v{i}");
            tracker.record_vote(&voter, make_vote(&voter, VoteStance::Endorse, 0.5, 1000), &mgr);
        }
        let threshold = FixedPoint::from_f64(0.67);
        tracker.evaluate(threshold, 500);
        assert_eq!(tracker.status, ProposalStatus::Converging);
    }

    #[test]
    fn evaluation_rejected() {
        let mut tracker = ProposalTracker::new(
            "p1".into(), "author".into(), ProposalTier::Standard, i64::MAX,
        );
        let mgr = make_identity_mgr();
        // 3 rejections
        for i in 0..3 {
            let voter = format!("v{i}");
            tracker.record_vote(&voter, make_vote(&voter, VoteStance::Reject, 0.5, 1000), &mgr);
        }
        let threshold = FixedPoint::from_f64(0.67);
        tracker.evaluate(threshold, 500);
        assert_eq!(tracker.status, ProposalStatus::Rejected);
    }

    #[test]
    fn evaluation_expired() {
        let mut tracker = ProposalTracker::new(
            "p1".into(), "author".into(), ProposalTier::Standard, 1000,
        );
        let mgr = make_identity_mgr();
        tracker.record_vote("v1", make_vote("v1", VoteStance::Endorse, 0.5, 500), &mgr);
        let threshold = FixedPoint::from_f64(0.67);
        tracker.evaluate(threshold, 2000); // past deadline
        assert_eq!(tracker.status, ProposalStatus::Expired);
    }

    #[test]
    fn abstain_doesnt_affect_ratio() {
        let mut tracker = ProposalTracker::new(
            "p1".into(), "author".into(), ProposalTier::Standard, i64::MAX,
        );
        let mgr = make_identity_mgr();
        tracker.record_vote("v1", make_vote("v1", VoteStance::Endorse, 0.5, 1000), &mgr);
        tracker.record_vote("v2", make_vote("v2", VoteStance::Endorse, 0.5, 1000), &mgr);
        tracker.record_vote("v3", make_vote("v3", VoteStance::Abstain, 0.5, 1000), &mgr);

        let eval = tracker.compute_vote_weights();
        assert_eq!(eval.distinct_voters, 3);
        // Ratio should be 1.0/1.0 = 100% (abstain not in ratio)
        let ratio = eval.weighted_endorse.div(
            eval.weighted_endorse.saturating_add(eval.weighted_reject)
        );
        assert_eq!(ratio, FixedPoint::ONE);
    }

    #[test]
    fn rate_limiter_allows_three() {
        let mut limiter = ProposalRateLimiter::new();
        let mgr = make_identity_mgr();
        let now = 1_000_000i64;

        assert!(limiter.can_propose("alice", now, &mgr));
        limiter.record_proposal("alice", now, &mgr);
        limiter.record_proposal("alice", now + 1000, &mgr);
        limiter.record_proposal("alice", now + 2000, &mgr);
        assert!(!limiter.can_propose("alice", now + 3000, &mgr));

        // Different identity not affected
        assert!(limiter.can_propose("bob", now, &mgr));
    }

    #[test]
    fn rate_limiter_window_expires() {
        let mut limiter = ProposalRateLimiter::new();
        let mgr = make_identity_mgr();
        let now = 1_000_000i64;

        limiter.record_proposal("alice", now, &mgr);
        limiter.record_proposal("alice", now + 1000, &mgr);
        limiter.record_proposal("alice", now + 2000, &mgr);
        assert!(!limiter.can_propose("alice", now + 3000, &mgr));

        // After 7 days, old proposals expire
        let later = now + constants::PROPOSAL_RATE_WINDOW_MS + 1;
        assert!(limiter.can_propose("alice", later, &mgr));
    }

    #[test]
    fn rate_limiter_transfer() {
        let mut limiter = ProposalRateLimiter::new();
        let mgr = make_identity_mgr();
        let now = 1_000_000i64;

        limiter.record_proposal("old_key", now, &mgr);
        limiter.record_proposal("old_key", now + 1000, &mgr);

        limiter.transfer("old_key", "new_key");

        // After transfer, old_key's record is gone — it CAN propose again
        assert!(limiter.can_propose("old_key", now + 2000, &mgr));
        // But new_key inherited the 2 proposals
        limiter.record_proposal("new_key", now + 2000, &mgr);
        assert!(!limiter.can_propose("new_key", now + 3000, &mgr)); // 3 proposals now
    }

    #[test]
    fn identity_resolution_in_voting() {
        use crate::identity::{IdentityManager, DidLinkRequest};

        let mut mgr = IdentityManager::new();
        let mut tracker = ProposalTracker::new(
            "p1".into(), "author".into(), ProposalTier::Standard, i64::MAX,
        );

        // Link identity A→B
        mgr.register_root("identity_a".into());
        mgr.link(&DidLinkRequest {
            root_key: "identity_a".into(),
            child_key: "child_b".into(),
            child_signature: "sig".into(),
            label: Some("relay".into()),
        }, 1000).unwrap();

        // Vote with child key B
        tracker.record_vote("child_b", make_vote("child_b", VoteStance::Endorse, 0.7, 2000), &mgr);

        // Verify vote is stored under root identity A, not child B
        assert_eq!(tracker.votes.len(), 1);
        assert!(tracker.votes.contains_key("identity_a"));
        assert!(!tracker.votes.contains_key("child_b"));
        assert_eq!(tracker.votes["identity_a"].stance, VoteStance::Endorse);
        assert_eq!(tracker.votes["identity_a"].vote_time_reputation, FixedPoint::from_f64(0.7));

        // Later vote from root supersedes child's vote
        tracker.record_vote("identity_a", make_vote("identity_a", VoteStance::Reject, 0.7, 3000), &mgr);
        assert_eq!(tracker.votes.len(), 1);
        assert_eq!(tracker.votes["identity_a"].stance, VoteStance::Reject);
    }

    #[test]
    fn rate_limiter_identity_resolution() {
        use crate::identity::{IdentityManager, DidLinkRequest};

        let mut mgr = IdentityManager::new();
        let mut limiter = ProposalRateLimiter::new();
        let now = 1_000_000i64;

        // Link identity root_a → child_b
        mgr.register_root("root_a".into());
        mgr.link(&DidLinkRequest {
            root_key: "root_a".into(),
            child_key: "child_b".into(),
            child_signature: "sig".into(),
            label: Some("cloud-relay".into()),
        }, 1000).unwrap();

        // Child submits 2 proposals
        assert!(limiter.can_propose("child_b", now, &mgr));
        limiter.record_proposal("child_b", now, &mgr);
        limiter.record_proposal("child_b", now + 1000, &mgr);

        // Root tries to submit — should see 2 already (shared limit)
        limiter.record_proposal("root_a", now + 2000, &mgr);
        // Identity now has 3 proposals — limit reached
        assert!(!limiter.can_propose("root_a", now + 3000, &mgr));
        assert!(!limiter.can_propose("child_b", now + 3000, &mgr));

        // Different identity unaffected
        mgr.register_root("unrelated".into());
        assert!(limiter.can_propose("unrelated", now + 3000, &mgr));
    }
}
