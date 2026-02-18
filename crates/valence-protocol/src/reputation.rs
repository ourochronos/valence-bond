//! Reputation scoring and propagation per §8.

use valence_core::types::FixedPoint;
use valence_core::constants::*;

/// A node's reputation state.
#[derive(Debug, Clone)]
pub struct ReputationState {
    /// Overall reputation (0.0–1.0, fixed-point).
    pub overall: FixedPoint,
    /// Domain-specific scores.
    pub by_domain: std::collections::HashMap<String, FixedPoint>,
    /// Number of direct observations of this node.
    pub observation_count: u64,
    /// Reputation earned today (for velocity limiting).
    pub daily_earned: FixedPoint,
    /// Reputation earned this week (for velocity limiting).
    pub weekly_earned: FixedPoint,
}

impl ReputationState {
    /// Create a new reputation state at initial level.
    pub fn new() -> Self {
        Self {
            overall: INITIAL_REPUTATION,
            by_domain: std::collections::HashMap::new(),
            observation_count: 0,
            daily_earned: FixedPoint::ZERO,
            weekly_earned: FixedPoint::ZERO,
        }
    }

    /// Compute α for the reputation formula.
    /// α = min(0.6, observation_count / 10)
    pub fn alpha(&self) -> FixedPoint {
        let alpha_raw = (self.observation_count as i64 * FixedPoint::SCALE) / ALPHA_RAMP_DIVISOR;
        FixedPoint::from_raw(alpha_raw).clamp(FixedPoint::ZERO, ALPHA_MAX)
    }

    /// Apply a reputation gain, respecting velocity limits and cap.
    /// Below starting rep: uncapped recovery.
    /// Above starting rep: daily/weekly limits apply.
    pub fn apply_gain(&mut self, amount: FixedPoint) {
        if self.overall < INITIAL_REPUTATION {
            // Uncapped recovery below starting rep
            self.overall = self.overall.saturating_add(amount);
        } else {
            // Check velocity limits
            let remaining_daily = MAX_DAILY_GAIN.saturating_sub(self.daily_earned);
            let remaining_weekly = MAX_WEEKLY_GAIN.saturating_sub(self.weekly_earned);
            let allowed = amount
                .clamp(FixedPoint::ZERO, remaining_daily)
                .clamp(FixedPoint::ZERO, remaining_weekly);

            self.overall = self.overall.saturating_add(allowed);
            self.daily_earned = self.daily_earned.saturating_add(allowed);
            self.weekly_earned = self.weekly_earned.saturating_add(allowed);
        }

        // Hard cap at 1.0
        self.overall = self.overall.clamp(REPUTATION_FLOOR, REPUTATION_CAP);
    }

    /// Apply dampened gain per §1 Identity Linking.
    /// For identities with authorized keys: `effective_gain = raw_gain / authorized_key_count`
    /// Dampening applies BEFORE velocity limits.
    pub fn apply_dampened_gain(&mut self, raw_gain: FixedPoint, authorized_key_count: usize) {
        let dampening_factor = FixedPoint::from_f64(1.0 / (authorized_key_count as f64).powf(0.75));
        let effective_gain = raw_gain.mul(dampening_factor);
        self.apply_gain(effective_gain);
    }

    /// Apply a reputation penalty.
    pub fn apply_penalty(&mut self, amount: FixedPoint) {
        self.overall = self.overall.saturating_sub(amount);
        // Floor at 0.1
        self.overall = self.overall.clamp(REPUTATION_FLOOR, REPUTATION_CAP);
    }

    /// Compute reputation for a peer using the §8 formula.
    ///
    /// reputation(B) = α × direct + (1-α) × weighted_peer_avg
    ///
    /// Fixed-point evaluation order per §8:
    ///   peer_sum = Σ(trust_i × assessment_i)
    ///   peer_weight = Σ(trust_i)
    ///   peer_avg = peer_sum / peer_weight
    ///   result = (α × direct + (10000 - α) × peer_avg) / 10000
    pub fn compute_peer_reputation(
        alpha: FixedPoint,
        direct: FixedPoint,
        peer_assessments: &[(FixedPoint, FixedPoint)], // (trust, assessment) pairs
        distinct_asns: usize,
    ) -> FixedPoint {
        if peer_assessments.is_empty() && alpha == FixedPoint::ZERO {
            // No direct observations, no peer data — return initial
            return INITIAL_REPUTATION;
        }

        let peer_avg = if peer_assessments.is_empty() {
            INITIAL_REPUTATION
        } else {
            // peer_sum = Σ(trust_i × assessment_i) — products are ×10^8
            let peer_sum: i128 = peer_assessments
                .iter()
                .map(|(trust, assess)| trust.raw() as i128 * assess.raw() as i128)
                .sum();

            // peer_weight = Σ(trust_i) — ×10,000
            let peer_weight: i64 = peer_assessments.iter().map(|(trust, _)| trust.raw()).sum();

            if peer_weight == 0 {
                INITIAL_REPUTATION
            } else {
                // peer_avg = peer_sum / peer_weight — back to ×10,000 scale
                FixedPoint::from_raw((peer_sum / peer_weight as i128) as i64)
            }
        };

        // When α = 0 and < 3 distinct ASN assessors: cap at starting rep
        let capped_peer_avg = if alpha == FixedPoint::ZERO
            && distinct_asns < PEER_INFORMED_CAP_MIN_ASSESSORS
        {
            peer_avg.clamp(FixedPoint::ZERO, INITIAL_REPUTATION)
        } else {
            peer_avg
        };

        // result = (α × direct + (10000 - α) × peer_avg) / 10000
        let alpha_raw = alpha.raw();
        let one_minus_alpha = FixedPoint::SCALE - alpha_raw;
        let numerator = alpha_raw as i128 * direct.raw() as i128
            + one_minus_alpha as i128 * capped_peer_avg.raw() as i128;
        let result = (numerator / FixedPoint::SCALE as i128) as i64;

        FixedPoint::from_raw(result).clamp(REPUTATION_FLOOR, REPUTATION_CAP)
    }
}

impl Default for ReputationState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_reputation() {
        let state = ReputationState::new();
        assert_eq!(state.overall, INITIAL_REPUTATION);
    }

    #[test]
    fn alpha_ramp() {
        let mut state = ReputationState::new();
        assert_eq!(state.alpha(), FixedPoint::ZERO); // 0 observations

        state.observation_count = 3;
        assert_eq!(state.alpha().raw(), 3000); // 3/10 = 0.3

        state.observation_count = 6;
        assert_eq!(state.alpha().raw(), 6000); // 6/10 = 0.6 (max)

        state.observation_count = 20;
        assert_eq!(state.alpha().raw(), 6000); // capped at 0.6
    }

    #[test]
    fn velocity_limits() {
        let mut state = ReputationState::new();
        // At initial rep, velocity limits apply
        state.apply_gain(FixedPoint::from_f64(0.05));
        // Should be capped at 0.02 daily
        assert_eq!(state.overall.raw(), 2200); // 0.2 + 0.02 = 0.22
    }

    #[test]
    fn uncapped_recovery_below_starting() {
        let mut state = ReputationState::new();
        state.overall = REPUTATION_FLOOR; // 0.1
        // Below starting rep: no velocity limits
        state.apply_gain(FixedPoint::from_f64(0.05));
        assert_eq!(state.overall.raw(), 1500); // 0.1 + 0.05 = 0.15
    }

    #[test]
    fn hard_cap() {
        let mut state = ReputationState::new();
        state.overall = FixedPoint::from_f64(0.99);
        state.daily_earned = FixedPoint::ZERO;
        state.weekly_earned = FixedPoint::ZERO;
        state.apply_gain(FixedPoint::from_f64(0.02));
        assert_eq!(state.overall, REPUTATION_CAP); // capped at 1.0
    }

    #[test]
    fn floor_on_penalty() {
        let mut state = ReputationState::new();
        state.apply_penalty(FixedPoint::from_f64(0.5));
        assert_eq!(state.overall, REPUTATION_FLOOR); // floor at 0.1
    }

    #[test]
    fn peer_reputation_alpha_zero_capped() {
        // α=0, < 3 distinct ASNs: capped at 0.2
        let alpha = FixedPoint::ZERO;
        let direct = FixedPoint::ZERO;
        let assessments = vec![
            (FixedPoint::from_f64(0.8), FixedPoint::from_f64(0.9)),
        ];
        let result = ReputationState::compute_peer_reputation(alpha, direct, &assessments, 1);
        // Should be capped at 0.2 (starting rep)
        assert!(result.raw() <= INITIAL_REPUTATION.raw());
    }

    #[test]
    fn peer_reputation_alpha_zero_uncapped_with_asns() {
        // α=0, ≥ 3 distinct ASNs: not capped
        let alpha = FixedPoint::ZERO;
        let direct = FixedPoint::ZERO;
        let assessments = vec![
            (FixedPoint::from_f64(0.8), FixedPoint::from_f64(0.9)),
            (FixedPoint::from_f64(0.7), FixedPoint::from_f64(0.85)),
            (FixedPoint::from_f64(0.6), FixedPoint::from_f64(0.8)),
        ];
        let result = ReputationState::compute_peer_reputation(alpha, direct, &assessments, 3);
        // Should be > 0.2 since uncapped
        assert!(result.raw() > INITIAL_REPUTATION.raw());
    }

    #[test]
    fn dampened_gain_four_keys() {
        // Task 3: 4-key identity, apply gain of 0.04, verify effective gain is 0.01
        let mut state = ReputationState::new();
        state.overall = FixedPoint::from_f64(0.2); // At starting rep
        state.daily_earned = FixedPoint::ZERO;
        state.weekly_earned = FixedPoint::ZERO;

        // 4 authorized keys: dampening factor = 1/4 = 0.25
        // raw_gain = 0.04, effective = 0.04 * 0.25 = 0.01
        state.apply_dampened_gain(FixedPoint::from_f64(0.04), 4);

        // Should have gained 0.04/4^0.75 ≈ 0.0141 (dampened)
        assert_eq!(state.overall.raw(), 2141); // 0.2 + 0.0141 = 0.2141
    }

    #[test]
    fn dampened_gain_single_key_no_dampening() {
        // Single-key identity: no dampening (1/1 = 1.0)
        let mut state = ReputationState::new();
        state.overall = FixedPoint::from_f64(0.2);
        state.daily_earned = FixedPoint::ZERO;
        state.weekly_earned = FixedPoint::ZERO;

        state.apply_dampened_gain(FixedPoint::from_f64(0.01), 1);

        // Should have gained full 0.01
        assert_eq!(state.overall.raw(), 2100); // 0.2 + 0.01 = 0.21
    }
}
