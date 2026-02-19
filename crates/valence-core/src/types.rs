//! Core types for the Valence Network v0 protocol.

use serde::{Deserialize, Serialize};

/// Fixed-point reputation value (×10,000 internally).
/// Multiply by 10,000 and truncate per §2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FixedPoint(i64);

impl FixedPoint {
    pub const SCALE: i64 = 10_000;
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(10_000);

    /// Create from float, truncating toward zero (not rounding) per §2.
    /// L-5: For negative values, truncation is toward zero (e.g., -0.67891 → -6789).
    /// This matches Rust's default `as i64` cast behavior.
    pub fn from_f64(val: f64) -> Self {
        Self((val * Self::SCALE as f64) as i64)
    }

    /// Create from float, flooring toward negative infinity.
    /// Use when floor semantics are needed for negative values.
    pub fn from_f64_floor(val: f64) -> Self {
        Self((val * Self::SCALE as f64).floor() as i64)
    }

    /// Create from raw scaled integer.
    pub const fn from_raw(raw: i64) -> Self {
        Self(raw)
    }

    /// Get the raw scaled integer value.
    pub const fn raw(self) -> i64 {
        self.0
    }

    /// Convert to f64 (for display/debugging only — not for protocol computation).
    pub fn to_f64(self) -> f64 {
        self.0 as f64 / Self::SCALE as f64
    }

    /// Add two fixed-point values.
    pub fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Subtract two fixed-point values.
    pub fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }

    /// Multiply two fixed-point values. Intermediate uses i128 to avoid overflow.
    /// Truncation only on final result per §2/§8.
    #[allow(clippy::should_implement_trait)]
    pub fn mul(self, other: Self) -> Self {
        let result = (self.0 as i128 * other.0 as i128) / Self::SCALE as i128;
        Self(result as i64)
    }

    /// Divide two fixed-point values. Intermediate uses i128.
    /// M-4: Returns None on division by zero instead of silently returning ZERO.
    pub fn checked_div(self, other: Self) -> Option<Self> {
        if other.0 == 0 {
            return None;
        }
        let result = (self.0 as i128 * Self::SCALE as i128) / other.0 as i128;
        Some(Self(result as i64))
    }

    /// Divide two fixed-point values. Intermediate uses i128.
    /// Logs a warning on division by zero and returns ZERO (M-4).
    #[allow(clippy::should_implement_trait)]
    pub fn div(self, other: Self) -> Self {
        if other.0 == 0 {
            #[cfg(debug_assertions)]
            eprintln!("WARNING: FixedPoint::div called with zero divisor, returning ZERO");
            return Self::ZERO;
        }
        let result = (self.0 as i128 * Self::SCALE as i128) / other.0 as i128;
        Self(result as i64)
    }

    /// Clamp to [min, max].
    pub fn clamp(self, min: Self, max: Self) -> Self {
        Self(self.0.clamp(min.0, max.0))
    }
}

impl std::fmt::Display for FixedPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.4}", self.to_f64())
    }
}

/// Node identity — hex-encoded Ed25519 public key.
pub type NodeId = String;

/// Message ID — SHA-256 hex digest of the signing body.
pub type MessageId = String;

/// Unix timestamp in milliseconds.
pub type Timestamp = i64;

/// Protocol constants from v0 spec.
pub mod constants {
    use super::FixedPoint;

    // §1 Identity
    /// Grace period for key rotation (1 hour).
    pub const KEY_ROTATION_GRACE_PERIOD_MS: i64 = 3_600_000;
    /// Gain dampening exponent for reputation increases.
    pub const GAIN_DAMPENING_EXPONENT: f64 = 0.75;
    /// Voting cooldown after DID revocation (60 days).
    pub const DID_REVOKE_VOTING_COOLDOWN_MS: i64 = 60 * 24 * 60 * 60 * 1000;
    /// Identity re-broadcast interval (30 days).
    pub const IDENTITY_REBROADCAST_MS: i64 = 30 * 24 * 60 * 60 * 1000;
    /// Sync request rate limit per peer per minute.
    pub const SYNC_REQUEST_RATE_LIMIT: usize = 10;

    // §2 Message format
    /// Maximum payload size (8 MiB).
    pub const MAX_PAYLOAD_SIZE: usize = 8 * 1024 * 1024;
    /// Timestamp tolerance for message acceptance (5 minutes).
    pub const TIMESTAMP_TOLERANCE_MS: i64 = 5 * 60 * 1000;
    /// Inline content limit (1 MiB).
    pub const INLINE_CONTENT_LIMIT: usize = 1024 * 1024;

    // §4 Peer discovery
    /// Peer announce interval (5 minutes).
    pub const PEER_ANNOUNCE_INTERVAL_MS: i64 = 5 * 60 * 1000;
    /// Peer expiry timeout (30 minutes).
    pub const PEER_EXPIRY_MS: i64 = 30 * 60 * 1000;
    /// Anti-fragmentation interval (10 minutes).
    pub const ANTI_FRAG_INTERVAL_MS: i64 = 10 * 60 * 1000;
    /// Maximum fraction of peers from a single ASN.
    pub const MAX_ASN_FRACTION: f64 = 0.25;
    /// Minimum distinct ASNs for peer diversity.
    pub const MIN_DISTINCT_ASNS: usize = 4;

    // §5 Gossip
    /// Dedup cache size for message IDs.
    pub const DEDUP_CACHE_SIZE: usize = 100_000;
    /// Maximum age for gossip messages (24 hours).
    pub const GOSSIP_MAX_AGE_MS: i64 = 24 * 60 * 60 * 1000;

    // §6 Content
    /// Maximum entries in a SHARE message.
    pub const SHARE_MAX_ENTRIES: usize = 50;
    /// Maximum SHARE broadcasts per hour per identity.
    pub const SHARE_RATE_LIMIT_PER_HOUR: usize = 10;
    /// Maximum tags per content entry.
    pub const SHARE_MAX_TAGS: usize = 20;
    /// Maximum bytes per tag.
    pub const SHARE_MAX_TAG_BYTES: usize = 64;
    /// SHARE re-broadcast interval (30 minutes).
    pub const SHARE_REBROADCAST_MS: i64 = 30 * 60 * 1000;
    /// Content transfer chunk size (1 MiB).
    pub const CONTENT_CHUNK_SIZE: usize = 1024 * 1024;
    /// Maximum bytes for FLAG details field (10 KiB).
    pub const FLAG_DETAILS_MAX_BYTES: usize = 10 * 1024;
    /// Maximum bytes for CONTENT_WITHDRAW reason (1 KiB).
    pub const CONTENT_WITHDRAW_REASON_MAX_BYTES: usize = 1024;
    /// Minimum delay before content withdrawal takes effect (24 hours).
    pub const CONTENT_WITHDRAW_DELAY_MS: i64 = 24 * 60 * 60 * 1000;
    /// Window for providers to accept replication requests (48 hours).
    pub const REPLICATION_ACCEPT_WINDOW_MS: i64 = 48 * 60 * 60 * 1000;

    // §6 Storage economics
    /// Base storage rate (0.001 per MiB/month).
    pub const STORAGE_BASE_RATE: FixedPoint = FixedPoint::from_raw(10);
    /// Free storage allowance in MiB.
    pub const STORAGE_BASE_ALLOWANCE_MIB: u64 = 10;
    /// Rent billing cycle duration (30 days).
    pub const RENT_BILLING_CYCLE_MS: i64 = 30 * 24 * 60 * 60 * 1000;
    /// First grace period for missed rent (7 days).
    pub const RENT_GRACE_PERIOD_1_MS: i64 = 7 * 24 * 60 * 60 * 1000;
    /// Second grace period for missed rent (3 days).
    pub const RENT_GRACE_PERIOD_2_MS: i64 = 3 * 24 * 60 * 60 * 1000;
    /// Third grace period — immediate (0).
    pub const RENT_GRACE_PERIOD_3_MS: i64 = 0;
    /// Window for repeat grace period evaluation (90 days).
    pub const RENT_GRACE_REPEAT_WINDOW_MS: i64 = 90 * 24 * 60 * 60 * 1000;
    /// Deadline to submit RENT_PAYMENT within a billing cycle (7 days).
    pub const RENT_PAYMENT_DEADLINE_DAYS: u32 = 7;
    /// Number of cycles for full market rate convergence.
    pub const RENT_CONVERGENCE_CYCLES: i64 = 5;
    /// Divergence threshold for accelerated convergence (>10×).
    pub const RENT_CONVERGENCE_ACCEL_THRESHOLD: i64 = 10;
    /// Maximum scarcity multiplier (100.0).
    pub const SCARCITY_MULTIPLIER_CAP: FixedPoint = FixedPoint::from_raw(1_000_000);

    // §6 Storage validation
    /// Provider share of rent payments (80%).
    pub const PROVIDER_RENT_SHARE: FixedPoint = FixedPoint::from_raw(8_000);
    /// Validator share of rent payments (20%).
    pub const VALIDATOR_RENT_SHARE: FixedPoint = FixedPoint::from_raw(2_000);
    /// Minimum storage challenges per billing cycle.
    pub const MIN_CHALLENGES_PER_CYCLE: usize = 10;
    /// Minimum distinct ASNs for validator set.
    pub const MIN_VALIDATOR_ASNS: usize = 2;
    /// Maximum validator earnings per content per cycle.
    pub const VALIDATOR_EARNINGS_CAP: usize = 30;
    /// Window for challenge corroboration (24 hours).
    pub const CHALLENGE_CORROBORATION_WINDOW_MS: i64 = 24 * 60 * 60 * 1000;
    /// Maximum storage challenges per peer per day.
    pub const STORAGE_CHALLENGE_MAX_PER_PEER_PER_DAY: usize = 10;
    /// Penalty for accepting replication then abandoning (-0.002).
    pub const ACCEPT_ABANDON_PENALTY: FixedPoint = FixedPoint::from_raw(20);

    // §6 Content flagging
    /// Reputation stake for dispute-level flags (-0.005).
    pub const FLAG_STAKE_DISPUTE: FixedPoint = FixedPoint::from_raw(50);
    /// Reputation stake for illegal-level flags (-0.02).
    pub const FLAG_STAKE_ILLEGAL: FixedPoint = FixedPoint::from_raw(200);
    /// Penalty for false severe flags (-0.05).
    pub const FLAG_FALSE_SEVERE_PENALTY: FixedPoint = FixedPoint::from_raw(500);
    /// Minimum flags for illegal content action.
    pub const ILLEGAL_FLAG_MIN_COUNT: usize = 5;
    /// Minimum distinct ASNs for illegal content action.
    pub const ILLEGAL_FLAG_MIN_ASNS: usize = 3;
    /// Minimum hash matches for illegal content action.
    pub const ILLEGAL_HASH_MATCH_MIN: usize = 2;
    /// Minimum flags for content suspension.
    pub const SUSPENSION_FLAG_MIN_COUNT: usize = 3;
    /// Minimum distinct ASNs for content suspension.
    pub const SUSPENSION_FLAG_MIN_ASNS: usize = 2;

    // §6 Provenance
    /// Proposer share of provenance rewards (70%).
    pub const PROVENANCE_PROPOSER_SHARE: FixedPoint = FixedPoint::from_raw(7_000);
    /// Host share of provenance rewards (30%).
    pub const PROVENANCE_HOST_SHARE: FixedPoint = FixedPoint::from_raw(3_000);
    /// Cap on provenance rewards when host is below reputation threshold (0.002).
    pub const PROVENANCE_BELOW_THRESHOLD_CAP: FixedPoint = FixedPoint::from_raw(20);

    // §7 Proposals
    /// Default voting deadline (14 days).
    pub const VOTING_DEADLINE_DEFAULT_MS: i64 = 14 * 24 * 60 * 60 * 1000;
    /// Maximum voting deadline (90 days).
    pub const VOTING_DEADLINE_MAX_MS: i64 = 90 * 24 * 60 * 60 * 1000;
    /// Proposal rate limit per 7-day window.
    pub const PROPOSAL_RATE_LIMIT: usize = 3;
    /// Proposal rate limit window (7 days).
    pub const PROPOSAL_RATE_WINDOW_MS: i64 = 7 * 24 * 60 * 60 * 1000;
    /// Maximum comments per proposal per identity per rolling 24h.
    pub const COMMENT_PER_PROPOSAL_LIMIT: usize = 3;
    /// Maximum entries in a claims list.
    pub const CLAIMS_MAX_ENTRIES: usize = 50;
    /// Maximum bytes per claim (2 KiB).
    pub const CLAIMS_MAX_BYTES: usize = 2048;

    // §8 Votes
    /// Minimum number of voters for a valid vote.
    pub const MINIMUM_VOTERS: usize = 3;
    /// Standard proposal approval threshold (0.67).
    pub const STANDARD_THRESHOLD: FixedPoint = FixedPoint::from_raw(6_700);
    /// Constitutional proposal approval threshold (0.90).
    pub const CONSTITUTIONAL_THRESHOLD: FixedPoint = FixedPoint::from_raw(9_000);
    /// Constitutional quorum fraction (0.30).
    pub const CONSTITUTIONAL_QUORUM_FRACTION: FixedPoint = FixedPoint::from_raw(3_000);
    /// Cold start period (30 days).
    pub const COLD_START_DAYS: i64 = 30;
    /// Cold start headcount floor (0.50).
    pub const COLD_START_HEADCOUNT_FLOOR: FixedPoint = FixedPoint::from_raw(5_000);
    /// Minimum nodes for governance activation.
    pub const GOVERNANCE_MIN_NODES: usize = 16;
    /// Minimum nodes for constitutional amendments.
    pub const CONSTITUTIONAL_MIN_NODES: usize = 1024;
    /// Constitutional sustain period (30 days).
    pub const CONSTITUTIONAL_SUSTAIN_DAYS: i64 = 30;
    /// Minimum constitutional vote duration (90 days).
    pub const CONSTITUTIONAL_VOTE_MIN_MS: i64 = 90 * 24 * 60 * 60 * 1000;
    /// Constitutional amendment cooling period (30 days).
    pub const CONSTITUTIONAL_COOLING_MS: i64 = 30 * 24 * 60 * 60 * 1000;
    /// Close margin threshold for extended confirmation (±0.02).
    pub const CLOSE_MARGIN_THRESHOLD: FixedPoint = FixedPoint::from_raw(200);
    /// Close margin confirmation period (7 days).
    pub const CLOSE_MARGIN_CONFIRMATION_MS: i64 = 7 * 24 * 60 * 60 * 1000;

    // §9 Reputation
    /// Initial reputation for new nodes (0.2).
    pub const INITIAL_REPUTATION: FixedPoint = FixedPoint::from_raw(2_000);
    /// Minimum reputation floor (0.1).
    pub const REPUTATION_FLOOR: FixedPoint = FixedPoint::from_raw(1_000);
    /// Maximum reputation cap (1.0).
    pub const REPUTATION_CAP: FixedPoint = FixedPoint::from_raw(10_000);
    /// Maximum daily reputation gain (0.02).
    pub const MAX_DAILY_GAIN: FixedPoint = FixedPoint::from_raw(200);
    /// Maximum weekly reputation gain (0.08).
    pub const MAX_WEEKLY_GAIN: FixedPoint = FixedPoint::from_raw(800);
    /// Inactivity decay rate (0.02 per month).
    pub const INACTIVITY_DECAY: FixedPoint = FixedPoint::from_raw(200);
    /// Inactivity threshold before decay applies (30 days).
    pub const INACTIVITY_THRESHOLD_MS: i64 = 30 * 24 * 60 * 60 * 1000;
    /// Maximum alpha weight for peer assessment (0.6).
    pub const ALPHA_MAX: FixedPoint = FixedPoint::from_raw(6_000);
    /// Alpha ramp divisor for peer assessment convergence.
    pub const ALPHA_RAMP_DIVISOR: i64 = 10;
    /// Minimum assessors for peer-informed cap.
    pub const PEER_INFORMED_CAP_MIN_ASSESSORS: usize = 3;
    /// Reputation gossip interval (15 minutes).
    pub const REP_GOSSIP_INTERVAL_MS: i64 = 15 * 60 * 1000;
    /// Reputation gossip batch size.
    pub const REP_GOSSIP_BATCH: usize = 10;

    // §9 Capability ramp thresholds
    /// Minimum reputation to propose (0.3).
    pub const MIN_REP_TO_PROPOSE: FixedPoint = FixedPoint::from_raw(3_000);
    /// Minimum reputation to vote (0.3).
    pub const MIN_REP_TO_VOTE: FixedPoint = FixedPoint::from_raw(3_000);
    /// Minimum reputation to replicate content (0.3).
    pub const MIN_REP_TO_REPLICATE: FixedPoint = FixedPoint::from_raw(3_000);
    /// Minimum reputation to flag dispute (0.3).
    pub const MIN_REP_TO_FLAG_DISPUTE: FixedPoint = FixedPoint::from_raw(3_000);
    /// Minimum reputation to flag illegal content (0.5).
    pub const MIN_REP_TO_FLAG_ILLEGAL: FixedPoint = FixedPoint::from_raw(5_000);
    /// Minimum reputation for provenance rewards (0.3).
    pub const PROVENANCE_MIN_REP: FixedPoint = FixedPoint::from_raw(3_000);

    // §9 Reputation rewards
    /// Reward per adoption (+0.005).
    pub const ADOPTION_REWARD_PER_ADOPT: FixedPoint = FixedPoint::from_raw(50);
    /// Cap on total adoption rewards (+0.05).
    pub const ADOPTION_REWARD_CAP: FixedPoint = FixedPoint::from_raw(500);
    /// Reward for verified claim (+0.001).
    pub const CLAIM_VERIFIED_REWARD: FixedPoint = FixedPoint::from_raw(10);
    /// Reward for discovering false claim (+0.005).
    pub const CLAIM_FALSE_REWARD: FixedPoint = FixedPoint::from_raw(50);
    /// Bonus for first contradiction found (+0.01).
    pub const FIRST_CONTRADICTION_BONUS: FixedPoint = FixedPoint::from_raw(100);
    /// Uptime reward per day (+0.001).
    pub const UPTIME_REWARD_PER_DAY: FixedPoint = FixedPoint::from_raw(10);
    /// Penalty for making a false claim (-0.003).
    pub const FALSE_CLAIM_PENALTY: FixedPoint = FixedPoint::from_raw(30);
    /// Penalty for failed storage challenge (-0.01).
    pub const FAILED_STORAGE_PENALTY: FixedPoint = FixedPoint::from_raw(100);
    /// Penalty for content being flagged (-0.05).
    pub const CONTENT_FLAGGED_PENALTY: FixedPoint = FixedPoint::from_raw(500);

    // §10 Sybil resistance
    /// VDF difficulty target.
    pub const VDF_DIFFICULTY: u64 = 1_000_000;
    /// VDF checkpoint interval.
    pub const VDF_CHECKPOINT_INTERVAL: u64 = 100_000;
    /// Minimum VDF verify segments.
    pub const VDF_MIN_VERIFY_SEGMENTS: usize = 5;
    /// Maximum VDF verifications per day.
    pub const VDF_MAX_VERIFICATIONS_PER_DAY: usize = 50;
    /// Maximum new peers accepted per hour.
    pub const MAX_NEW_PEERS_PER_HOUR: usize = 5;

    // §11 Anti-gaming
    /// Vote correlation threshold for collusion detection.
    pub const VOTE_CORRELATION_THRESHOLD: f64 = 0.95;
    /// Minimum proposals for correlation analysis.
    pub const VOTE_CORRELATION_MIN_PROPOSALS: usize = 20;
    /// Penalty for detected collusion (-0.05).
    pub const COLLUSION_PENALTY: FixedPoint = FixedPoint::from_raw(500);
    /// Tenure penalty onset (cycles).
    pub const TENURE_PENALTY_ONSET: usize = 6;
    /// Tenure penalty factor (0.95).
    pub const TENURE_PENALTY_FACTOR: FixedPoint = FixedPoint::from_raw(9_500);
    /// Voting cycle duration (30 days).
    pub const VOTING_CYCLE_MS: i64 = 30 * 24 * 60 * 60 * 1000;

    // §12 Partition detection
    /// Archive delay for expired proposals (7 days).
    pub const EXPIRED_PROPOSAL_ARCHIVE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
    /// Archive delay for withdrawn proposals (7 days).
    pub const WITHDRAWN_PROPOSAL_ARCHIVE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
    /// Archive delay for rejected proposals (30 days).
    pub const REJECTED_PROPOSAL_ARCHIVE_MS: i64 = 30 * 24 * 60 * 60 * 1000;
    /// Archive delay for ratified proposals (180 days).
    pub const RATIFIED_PROPOSAL_ARCHIVE_MS: i64 = 180 * 24 * 60 * 60 * 1000;

    // §13 Protocol evolution
    /// Minimum EOL period for minor versions (30 days).
    pub const MINOR_EOL_MIN_MS: i64 = 30 * 24 * 60 * 60 * 1000;
    /// Minimum EOL period for major versions (90 days).
    pub const MAJOR_EOL_MIN_MS: i64 = 90 * 24 * 60 * 60 * 1000;

    // §14 Error handling
    /// Rate limit for unknown message types per sender per hour.
    pub const UNKNOWN_TYPE_RATE_LIMIT: usize = 10;
    /// Maximum peer backoff duration (10 minutes).
    pub const PEER_BACKOFF_MAX_MS: i64 = 10 * 60 * 1000;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_point_from_f64_truncates() {
        // §2: truncate, not round
        assert_eq!(FixedPoint::from_f64(0.67891).raw(), 6789);
        assert_eq!(FixedPoint::from_f64(0.8).raw(), 8000);
        assert_eq!(FixedPoint::from_f64(0.67).raw(), 6700);
        assert_eq!(FixedPoint::from_f64(1.0).raw(), 10000);
        assert_eq!(FixedPoint::from_f64(0.0).raw(), 0);
    }

    #[test]
    fn fixed_point_mul() {
        let a = FixedPoint::from_f64(0.6);
        let b = FixedPoint::from_f64(0.5);
        let result = a.mul(b);
        assert_eq!(result.raw(), 3000); // 0.6 × 0.5 = 0.3
    }

    #[test]
    fn fixed_point_div() {
        let a = FixedPoint::from_f64(0.6);
        let b = FixedPoint::from_f64(0.3);
        let result = a.div(b);
        assert_eq!(result.raw(), 20000); // 0.6 / 0.3 = 2.0
    }

    // ── M-4: checked_div returns None on zero ──

    #[test]
    fn fixed_point_checked_div_zero_returns_none() {
        let a = FixedPoint::from_f64(1.0);
        assert_eq!(a.checked_div(FixedPoint::ZERO), None);
    }

    #[test]
    fn fixed_point_checked_div_normal() {
        let a = FixedPoint::from_f64(0.6);
        let b = FixedPoint::from_f64(0.3);
        let result = a.checked_div(b).unwrap();
        assert_eq!(result.raw(), 20000); // 2.0
    }

    // ── L-5: from_f64_floor for negative values ──

    #[test]
    fn fixed_point_from_f64_truncates_toward_zero_for_negatives() {
        // L-5: Document that from_f64 truncates toward zero
        assert_eq!(FixedPoint::from_f64(-0.67891).raw(), -6789);
        assert_eq!(FixedPoint::from_f64(-1.5).raw(), -15000);
    }

    #[test]
    fn fixed_point_from_f64_floor_floors_toward_neg_infinity() {
        // L-5: from_f64_floor uses floor semantics
        assert_eq!(FixedPoint::from_f64_floor(-0.67891).raw(), -6790);
        assert_eq!(FixedPoint::from_f64_floor(-1.5).raw(), -15000); // -1.5 floors to -1.5 exactly
        assert_eq!(FixedPoint::from_f64_floor(0.67891).raw(), 6789); // positive same as truncate
    }

    #[test]
    fn fixed_point_clamp() {
        let val = FixedPoint::from_f64(1.5);
        let clamped = val.clamp(constants::REPUTATION_FLOOR, constants::REPUTATION_CAP);
        assert_eq!(clamped, constants::REPUTATION_CAP);

        let val = FixedPoint::from_f64(0.05);
        let clamped = val.clamp(constants::REPUTATION_FLOOR, constants::REPUTATION_CAP);
        assert_eq!(clamped, constants::REPUTATION_FLOOR);
    }
}
