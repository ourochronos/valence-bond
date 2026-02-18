//! Anti-gaming mechanisms per §10.

use std::collections::{HashMap, HashSet};

use valence_core::constants;
use valence_core::types::FixedPoint;

/// A vote record for collusion analysis.
#[derive(Debug, Clone)]
pub struct VoteRecord {
    pub node_id: String,
    pub proposal_id: String,
    /// true = endorse, false = reject (abstain excluded from correlation)
    pub endorsed: bool,
}

/// Collusion detection severity per §10.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CollusionSeverity {
    None,
    Warning,
    High,
}

/// A detected collusion group.
#[derive(Debug, Clone)]
pub struct CollusionGroup {
    pub node_ids: Vec<String>,
    pub correlation: f64,
    pub proposals_analyzed: usize,
    pub severity: CollusionSeverity,
}

/// Compute pairwise vote correlation between two nodes.
/// Only considers proposals where both voted (endorse or reject, not abstain).
/// Returns (correlation, shared_proposal_count).
pub fn vote_correlation(
    votes_a: &[VoteRecord],
    votes_b: &[VoteRecord],
) -> (f64, usize) {
    // Index by proposal_id
    let a_by_proposal: HashMap<&str, bool> = votes_a.iter()
        .map(|v| (v.proposal_id.as_str(), v.endorsed))
        .collect();

    let mut agree = 0usize;
    let mut total = 0usize;

    for vote_b in votes_b {
        if let Some(&endorsed_a) = a_by_proposal.get(vote_b.proposal_id.as_str()) {
            total += 1;
            if endorsed_a == vote_b.endorsed {
                agree += 1;
            }
        }
    }

    if total == 0 {
        return (0.0, 0);
    }

    (agree as f64 / total as f64, total)
}

/// Detect collusion groups from voting records per §10.
/// Flags groups of 3+ nodes with >95% correlation over 20+ proposals.
pub fn detect_vote_collusion(
    all_votes: &[VoteRecord],
    exempt_identity_groups: &[HashSet<String>],
) -> Vec<CollusionGroup> {
    // Group votes by node
    let mut by_node: HashMap<&str, Vec<&VoteRecord>> = HashMap::new();
    for vote in all_votes {
        by_node.entry(vote.node_id.as_str()).or_default().push(vote);
    }

    let node_ids: Vec<&str> = by_node.keys().copied().collect();
    let mut high_correlation_pairs: Vec<(&str, &str, f64, usize)> = Vec::new();

    // Check all pairs
    for i in 0..node_ids.len() {
        for j in (i + 1)..node_ids.len() {
            let a = node_ids[i];
            let b = node_ids[j];

            // Skip pairs within the same identity group (§1 exemption)
            if exempt_identity_groups.iter().any(|group| group.contains(a) && group.contains(b)) {
                continue;
            }

            let votes_a: Vec<VoteRecord> = by_node[a].iter().map(|v| (*v).clone()).collect();
            let votes_b: Vec<VoteRecord> = by_node[b].iter().map(|v| (*v).clone()).collect();
            let (corr, count) = vote_correlation(&votes_a, &votes_b);

            if corr > constants::VOTE_CORRELATION_THRESHOLD
                && count >= constants::VOTE_CORRELATION_MIN_PROPOSALS
            {
                high_correlation_pairs.push((a, b, corr, count));
            }
        }
    }

    // Build groups via connected components of high-correlation pairs
    let mut groups: Vec<CollusionGroup> = Vec::new();
    let mut visited: HashSet<&str> = HashSet::new();

    for (a, b, corr, count) in &high_correlation_pairs {
        if visited.contains(a) || visited.contains(b) {
            // Find existing group and potentially merge
            if let Some(group) = groups.iter_mut().find(|g| {
                g.node_ids.iter().any(|n| n == a || n == b)
            }) {
                if !group.node_ids.iter().any(|n| n == *a) {
                    group.node_ids.push(a.to_string());
                }
                if !group.node_ids.iter().any(|n| n == *b) {
                    group.node_ids.push(b.to_string());
                }
                group.correlation = group.correlation.min(*corr); // Conservative
                group.proposals_analyzed = group.proposals_analyzed.max(*count);
                visited.insert(a);
                visited.insert(b);
                continue;
            }
        }

        visited.insert(a);
        visited.insert(b);
        groups.push(CollusionGroup {
            node_ids: vec![a.to_string(), b.to_string()],
            correlation: *corr,
            proposals_analyzed: *count,
            severity: CollusionSeverity::Warning,
        });
    }

    // Only report groups of 3+ per §10
    groups.retain(|g| g.node_ids.len() >= 3);

    // Assign severity
    for group in &mut groups {
        group.severity = if group.correlation > 0.99 && group.node_ids.len() >= 5 {
            CollusionSeverity::High
        } else {
            CollusionSeverity::Warning
        };
    }

    groups
}

/// Tenure tracking per §10.
/// A voting cycle is a rolling 30-day window.
#[derive(Debug, Clone)]
pub struct TenureTracker {
    /// Number of consecutive active cycles.
    pub consecutive_cycles: usize,
    /// Whether the node was active in the current cycle.
    pub active_current_cycle: bool,
}

impl TenureTracker {
    pub fn new() -> Self {
        Self {
            consecutive_cycles: 0,
            active_current_cycle: false,
        }
    }

    /// Mark the node as active in the current cycle.
    pub fn mark_active(&mut self) {
        if !self.active_current_cycle {
            self.active_current_cycle = true;
        }
    }

    /// Advance to the next cycle.
    pub fn advance_cycle(&mut self) {
        if self.active_current_cycle {
            self.consecutive_cycles += 1;
        } else {
            // §10: Skipping a cycle decays by 1, not full reset
            self.consecutive_cycles = self.consecutive_cycles.saturating_sub(1);
        }
        self.active_current_cycle = false;
    }

    /// Compute vote weight multiplier based on tenure per §10.
    /// 5% reduction per cycle after the 6th.
    pub fn vote_weight_multiplier(&self) -> FixedPoint {
        if self.consecutive_cycles <= constants::TENURE_PENALTY_ONSET {
            FixedPoint::ONE
        } else {
            let excess = self.consecutive_cycles - constants::TENURE_PENALTY_ONSET;
            let mut multiplier = FixedPoint::ONE;
            for _ in 0..excess {
                multiplier = multiplier.mul(constants::TENURE_PENALTY_FACTOR);
            }
            multiplier
        }
    }
}

impl Default for TenureTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Registration timing analysis per §10.
/// Flag 3+ nodes whose VDF proofs were computed within a 24-hour window.
pub fn detect_registration_timing_clusters(
    registrations: &[(String, i64)], // (node_id, registration_timestamp_ms)
    exempt_identity_groups: &[HashSet<String>],
) -> Vec<Vec<String>> {
    let window_ms: i64 = 24 * 60 * 60 * 1000;
    let mut clusters: Vec<Vec<String>> = Vec::new();

    // Sort by timestamp
    let mut sorted = registrations.to_vec();
    sorted.sort_by_key(|(_, ts)| *ts);

    // Sliding window
    let mut i = 0;
    while i < sorted.len() {
        let mut group: Vec<String> = vec![sorted[i].0.clone()];
        let start_ts = sorted[i].1;

        let mut j = i + 1;
        while j < sorted.len() && sorted[j].1 - start_ts <= window_ms {
            group.push(sorted[j].0.clone());
            j += 1;
        }

        if group.len() >= 3 {
            // Remove nodes in the same identity group
            let mut filtered = group.clone();
            for exempt in exempt_identity_groups {
                let exempt_in_group: Vec<_> = filtered.iter()
                    .filter(|n| exempt.contains(n.as_str()))
                    .cloned()
                    .collect();
                if exempt_in_group.len() > 1 {
                    // Keep only one representative from each identity group
                    for node in exempt_in_group.iter().skip(1) {
                        filtered.retain(|n| n != node);
                    }
                }
            }
            if filtered.len() >= 3 {
                clusters.push(filtered);
            }
        }

        i += 1;
    }

    // Deduplicate overlapping clusters (keep largest)
    clusters.sort_by(|a, b| b.len().cmp(&a.len()));
    let mut seen: HashSet<String> = HashSet::new();
    clusters.retain(|group| {
        let new_nodes: Vec<_> = group.iter().filter(|n| !seen.contains(n.as_str())).collect();
        if new_nodes.len() >= 3 {
            for n in group {
                seen.insert(n.clone());
            }
            true
        } else {
            false
        }
    });

    clusters
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_votes(node: &str, proposals: &[(&str, bool)]) -> Vec<VoteRecord> {
        proposals.iter().map(|(pid, endorsed)| VoteRecord {
            node_id: node.to_string(),
            proposal_id: pid.to_string(),
            endorsed: *endorsed,
        }).collect()
    }

    #[test]
    fn perfect_correlation() {
        let votes_a = make_votes("a", &[("p1", true), ("p2", false), ("p3", true)]);
        let votes_b = make_votes("b", &[("p1", true), ("p2", false), ("p3", true)]);
        let (corr, count) = vote_correlation(&votes_a, &votes_b);
        assert_eq!(corr, 1.0);
        assert_eq!(count, 3);
    }

    #[test]
    fn zero_correlation() {
        let votes_a = make_votes("a", &[("p1", true), ("p2", true)]);
        let votes_b = make_votes("b", &[("p1", false), ("p2", false)]);
        let (corr, count) = vote_correlation(&votes_a, &votes_b);
        assert_eq!(corr, 0.0);
        assert_eq!(count, 2);
    }

    #[test]
    fn no_shared_proposals() {
        let votes_a = make_votes("a", &[("p1", true)]);
        let votes_b = make_votes("b", &[("p2", true)]);
        let (corr, count) = vote_correlation(&votes_a, &votes_b);
        assert_eq!(corr, 0.0);
        assert_eq!(count, 0);
    }

    #[test]
    fn collusion_detection_requires_3_nodes() {
        // 21 proposals with 3 perfectly correlated nodes
        let proposals: Vec<(&str, bool)> = (0..21).map(|i| {
            // Leak the string by leaking into a Box — test-only
            let s: &str = Box::leak(format!("p{i}").into_boxed_str());
            (s, true)
        }).collect();

        let mut all_votes = Vec::new();
        for node in ["a", "b", "c"] {
            all_votes.extend(make_votes(node, &proposals));
        }

        let groups = detect_vote_collusion(&all_votes, &[]);
        assert!(!groups.is_empty());
        assert!(groups[0].node_ids.len() >= 3);
    }

    #[test]
    fn collusion_exempt_identity_group() {
        // 3 nodes perfectly correlated, but all in same identity group — exempt
        let proposals: Vec<(&str, bool)> = (0..21).map(|i| {
            let s: &str = Box::leak(format!("p{i}").into_boxed_str());
            (s, true)
        }).collect();

        let mut all_votes = Vec::new();
        for node in ["a", "b", "c"] {
            all_votes.extend(make_votes(node, &proposals));
        }

        let exempt = vec![HashSet::from(["a".to_string(), "b".to_string(), "c".to_string()])];
        let groups = detect_vote_collusion(&all_votes, &exempt);
        assert!(groups.is_empty());
    }

    #[test]
    fn tenure_no_penalty_under_threshold() {
        let mut tracker = TenureTracker::new();
        for _ in 0..6 {
            tracker.mark_active();
            tracker.advance_cycle();
        }
        assert_eq!(tracker.consecutive_cycles, 6);
        assert_eq!(tracker.vote_weight_multiplier(), FixedPoint::ONE);
    }

    #[test]
    fn tenure_penalty_after_threshold() {
        let mut tracker = TenureTracker::new();
        for _ in 0..8 {
            tracker.mark_active();
            tracker.advance_cycle();
        }
        assert_eq!(tracker.consecutive_cycles, 8);
        // 2 cycles past onset: 0.95^2 = 0.9025
        let weight = tracker.vote_weight_multiplier();
        assert!(weight.to_f64() > 0.90 && weight.to_f64() < 0.91);
    }

    #[test]
    fn tenure_decay_on_skip() {
        let mut tracker = TenureTracker::new();
        // 6 active cycles
        for _ in 0..6 {
            tracker.mark_active();
            tracker.advance_cycle();
        }
        assert_eq!(tracker.consecutive_cycles, 6);

        // Skip 2 cycles → decays by 2
        tracker.advance_cycle(); // skip
        tracker.advance_cycle(); // skip
        assert_eq!(tracker.consecutive_cycles, 4);
    }

    #[test]
    fn tenure_full_reset_requires_many_skips() {
        let mut tracker = TenureTracker::new();
        for _ in 0..6 {
            tracker.mark_active();
            tracker.advance_cycle();
        }
        // Need 6 skips for full reset (§10: "6 months of inactivity")
        for _ in 0..6 {
            tracker.advance_cycle();
        }
        assert_eq!(tracker.consecutive_cycles, 0);
    }

    #[test]
    fn registration_timing_cluster_detection() {
        let window = 24 * 60 * 60 * 1000i64; // 24h
        let registrations = vec![
            ("a".to_string(), 1000),
            ("b".to_string(), 2000),
            ("c".to_string(), 3000),
            ("d".to_string(), window + 100_000), // well outside window
        ];

        let clusters = detect_registration_timing_clusters(&registrations, &[]);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].len(), 3);
        assert!(clusters[0].contains(&"a".to_string()));
    }

    #[test]
    fn registration_timing_exempt_identity() {
        let registrations = vec![
            ("a".to_string(), 1000),
            ("b".to_string(), 2000),
            ("c".to_string(), 3000),
        ];

        // a and b are the same identity — reduces to 2 distinct, below threshold
        let exempt = vec![HashSet::from(["a".to_string(), "b".to_string()])];
        let clusters = detect_registration_timing_clusters(&registrations, &exempt);
        assert!(clusters.is_empty());
    }
}
