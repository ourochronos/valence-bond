//! Erasure-coded content storage and challenges per §6.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use reed_solomon_erasure::galois_8::ReedSolomon;

use valence_core::message::ErasureCoding;

/// A content shard — one piece of an erasure-coded artifact.
#[derive(Debug, Clone)]
pub struct Shard {
    /// Index in the shard set (0..data_shards+parity_shards).
    pub index: usize,
    /// The shard data.
    pub data: Vec<u8>,
    /// SHA-256 hash of the shard data.
    pub hash: String,
}

impl Shard {
    pub fn new(index: usize, data: Vec<u8>) -> Self {
        let hash = hex::encode(Sha256::digest(&data));
        Self { index, data, hash }
    }
}

/// Shard metadata for a proposal per §6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardMetadata {
    pub coding: ErasureCoding,
    pub data_shards: usize,
    pub parity_shards: usize,
    pub shard_hashes: Vec<String>,
    pub shard_size: usize,
    pub manifest_hash: String,
}

/// Compute the manifest hash per §6:
/// SHA-256 of: shard_count as 4-byte big-endian integer, then shard_hashes sorted
/// lexicographically as hex strings concatenated without delimiters, then content_hash
/// hex string — shard_count is raw bytes, the rest is UTF-8 bytes.
pub fn compute_manifest_hash(shard_count: u32, shard_hashes: &[String], content_hash: &str) -> String {
    let mut sorted = shard_hashes.to_vec();
    sorted.sort();

    let mut hasher = Sha256::new();
    // shard_count as 4-byte big-endian
    hasher.update(shard_count.to_be_bytes());
    // shard_hashes sorted, concatenated as UTF-8
    for h in &sorted {
        hasher.update(h.as_bytes());
    }
    // content_hash as UTF-8
    hasher.update(content_hash.as_bytes());

    hex::encode(hasher.finalize())
}

/// Erasure-code an artifact into shards.
pub fn encode_artifact(data: &[u8], coding: &ErasureCoding) -> Result<Vec<Shard>, StorageError> {
    let data_count = coding.data_shards();
    let parity_count = coding.parity_shards();

    if data.is_empty() {
        return Err(StorageError::EmptyArtifact);
    }

    let rs = ReedSolomon::new(data_count, parity_count)
        .map_err(|e| StorageError::ReedSolomon(format!("{e}")))?;

    // Pad data to be evenly divisible by data_count
    let shard_size = data.len().div_ceil(data_count);
    let mut padded = data.to_vec();
    padded.resize(shard_size * data_count, 0);

    // Split into data shards
    let mut shards: Vec<Vec<u8>> = padded
        .chunks(shard_size)
        .map(|c| c.to_vec())
        .collect();

    // Add empty parity shards
    for _ in 0..parity_count {
        shards.push(vec![0u8; shard_size]);
    }

    // Encode parity
    rs.encode(&mut shards)
        .map_err(|e| StorageError::ReedSolomon(format!("{e}")))?;

    // Wrap in Shard structs
    let result: Vec<Shard> = shards
        .into_iter()
        .enumerate()
        .map(|(i, data)| Shard::new(i, data))
        .collect();

    Ok(result)
}

/// Reconstruct an artifact from shards. Needs at least `data_shards` valid shards.
/// Missing shards should be passed as None.
pub fn reconstruct_artifact(
    shard_data: &mut [Option<Vec<u8>>],
    coding: &ErasureCoding,
    original_size: usize,
) -> Result<Vec<u8>, StorageError> {
    let data_count = coding.data_shards();
    let parity_count = coding.parity_shards();

    if shard_data.len() != data_count + parity_count {
        return Err(StorageError::WrongShardCount {
            expected: data_count + parity_count,
            got: shard_data.len(),
        });
    }

    let available = shard_data.iter().filter(|s| s.is_some()).count();
    if available < data_count {
        return Err(StorageError::InsufficientShards {
            needed: data_count,
            available,
        });
    }

    let rs = ReedSolomon::new(data_count, parity_count)
        .map_err(|e| StorageError::ReedSolomon(format!("{e}")))?;

    // reed-solomon-erasure wants &mut [Option<Vec<u8>>] (which we already have) but via shards
    rs.reconstruct(shard_data)
        .map_err(|e| StorageError::ReedSolomon(format!("{e}")))?;

    // Concatenate data shards and truncate to original size
    let mut result = Vec::with_capacity(original_size);
    for data in shard_data.iter().take(data_count).flatten() {
        result.extend_from_slice(data);
    }
    result.truncate(original_size);

    Ok(result)
}

/// Build shard metadata for a proposal.
pub fn build_shard_metadata(
    shards: &[Shard],
    coding: &ErasureCoding,
    content_hash: &str,
) -> ShardMetadata {
    let shard_hashes: Vec<String> = shards.iter().map(|s| s.hash.clone()).collect();
    let shard_size = shards.first().map(|s| s.data.len()).unwrap_or(0);
    let shard_count = shards.len() as u32;
    let manifest_hash = compute_manifest_hash(shard_count, &shard_hashes, content_hash);

    ShardMetadata {
        coding: coding.clone(),
        data_shards: coding.data_shards(),
        parity_shards: coding.parity_shards(),
        shard_hashes,
        shard_size,
        manifest_hash,
    }
}

// --- Storage Challenges (§6) ---

/// Storage challenge per §6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageChallenge {
    pub shard_hash: String,
    pub offset: usize,
    pub direction: ChallengeDirection,
    pub window_size: usize,
    pub challenge_nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeDirection {
    Before,
    After,
}

/// Storage proof per §6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProof {
    pub proof_hash: String,
}

/// Generate a storage challenge for a shard.
pub fn generate_challenge(shard_hash: &str, shard_size: usize, window_size: usize) -> StorageChallenge {
    let nonce_bytes: [u8; 32] = rand::random();
    // Pick a random offset that allows a full window
    let max_offset = shard_size.saturating_sub(window_size);
    let offset = if max_offset > 0 {
        (rand::random::<usize>()) % max_offset
    } else {
        0
    };
    let direction = if rand::random::<bool>() {
        ChallengeDirection::Before
    } else {
        ChallengeDirection::After
    };

    StorageChallenge {
        shard_hash: shard_hash.to_string(),
        offset,
        direction,
        window_size,
        challenge_nonce: hex::encode(nonce_bytes),
    }
}

/// Compute a storage proof per §6: SHA256(challenge_nonce || window_bytes).
pub fn compute_proof(challenge: &StorageChallenge, shard_data: &[u8]) -> Result<StorageProof, StorageError> {
    let window = extract_window(shard_data, challenge)?;

    let nonce_bytes = hex::decode(&challenge.challenge_nonce)
        .map_err(|_| StorageError::InvalidNonce)?;

    let mut hasher = Sha256::new();
    hasher.update(&nonce_bytes);
    hasher.update(&window);
    let proof_hash = hex::encode(hasher.finalize());

    Ok(StorageProof { proof_hash })
}

/// Verify a storage proof against the challenger's own copy.
pub fn verify_proof(
    challenge: &StorageChallenge,
    proof: &StorageProof,
    shard_data: &[u8],
) -> Result<bool, StorageError> {
    let expected = compute_proof(challenge, shard_data)?;
    Ok(expected.proof_hash == proof.proof_hash)
}

/// Extract the window bytes from a shard based on the challenge.
fn extract_window(shard_data: &[u8], challenge: &StorageChallenge) -> Result<Vec<u8>, StorageError> {
    let len = shard_data.len();
    let (start, end) = match challenge.direction {
        ChallengeDirection::Before => {
            let end = challenge.offset;
            let start = end.saturating_sub(challenge.window_size);
            (start, end)
        }
        ChallengeDirection::After => {
            let start = challenge.offset;
            let end = (start + challenge.window_size).min(len);
            (start, end)
        }
    };

    if end > len || start > len {
        return Err(StorageError::InvalidOffset {
            offset: challenge.offset,
            shard_size: len,
        });
    }

    Ok(shard_data[start..end].to_vec())
}

// --- Shard Query (§6) ---

/// Shard query per §6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardQuery {
    pub content_hash: String,
}

/// Shard query response per §6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardQueryResponse {
    pub available_shards: Vec<usize>,
    pub shard_hashes: Vec<String>,
}

// --- Content Transfer Protocol (§6) ---

/// State of a shard assignment within a content transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShardAssignmentState {
    /// Shard has been assigned but not yet confirmed.
    Pending { assigned_at_ms: i64 },
    /// Provider confirmed receipt via SHARD_RECEIVED.
    Confirmed { confirmed_at_ms: i64 },
    /// Assignment timed out (24h without SHARD_RECEIVED).
    Failed { reason: String },
}

/// Manages the shard distribution flow for a single content replication.
///
/// Tracks: REPLICATE_REQUEST → REPLICATE_ACCEPT handshake,
/// SHARD_ASSIGNMENT → SHARD_RECEIVED two-phase confirmation,
/// and 24h timeout for unconfirmed assignments.
#[derive(Debug)]
pub struct ContentTransfer {
    /// SHA-256 hex of the content being replicated.
    pub content_hash: String,
    /// Node ID of the uploader.
    pub uploader: String,
    /// Timestamp when REPLICATE_REQUEST was broadcast.
    pub requested_at_ms: i64,
    /// Providers that have sent REPLICATE_ACCEPT, keyed by node_id.
    /// Value is the list of shard indices the provider is willing to store.
    pub accepted_providers: std::collections::HashMap<String, Vec<u32>>,
    /// Per-shard assignment state, keyed by (shard_index, provider_node_id).
    pub assignments: std::collections::HashMap<(u32, String), ShardAssignmentState>,
    /// Whether shard assignments have been broadcast.
    pub assigned: bool,
}

/// Timeout for shard assignments without SHARD_RECEIVED (24h).
pub const SHARD_ASSIGNMENT_TIMEOUT_MS: i64 = 24 * 60 * 60 * 1000;

impl ContentTransfer {
    /// Create a new content transfer from a REPLICATE_REQUEST.
    pub fn new(content_hash: String, uploader: String, requested_at_ms: i64) -> Self {
        Self {
            content_hash,
            uploader,
            requested_at_ms,
            accepted_providers: std::collections::HashMap::new(),
            assignments: std::collections::HashMap::new(),
            assigned: false,
        }
    }

    /// Record a REPLICATE_ACCEPT from a provider.
    pub fn accept(&mut self, provider: String, shard_indices: Vec<u32>) {
        self.accepted_providers.insert(provider, shard_indices);
    }

    /// Record shard assignments (from SHARD_ASSIGNMENT broadcast).
    /// Each entry maps a shard_index to a provider node_id.
    pub fn assign(&mut self, assignments: &[(u32, String)], now_ms: i64) {
        for (shard_index, provider) in assignments {
            self.assignments.insert(
                (*shard_index, provider.clone()),
                ShardAssignmentState::Pending { assigned_at_ms: now_ms },
            );
        }
        self.assigned = true;
    }

    /// Record SHARD_RECEIVED confirmation from a provider.
    /// Returns true if the assignment existed and was pending.
    pub fn confirm_shard(&mut self, shard_index: u32, provider: &str, now_ms: i64) -> bool {
        let key = (shard_index, provider.to_string());
        if let Some(state) = self.assignments.get_mut(&key)
            && matches!(state, ShardAssignmentState::Pending { .. }) {
                *state = ShardAssignmentState::Confirmed { confirmed_at_ms: now_ms };
                return true;
            }
        false
    }

    /// Check for timed-out assignments (24h without SHARD_RECEIVED) and mark them failed.
    /// Returns the number of assignments that timed out.
    pub fn expire_stale(&mut self, now_ms: i64) -> usize {
        let mut count = 0;
        for state in self.assignments.values_mut() {
            if let ShardAssignmentState::Pending { assigned_at_ms } = *state
                && now_ms - assigned_at_ms >= SHARD_ASSIGNMENT_TIMEOUT_MS {
                    *state = ShardAssignmentState::Failed {
                        reason: "24h timeout without SHARD_RECEIVED".to_string(),
                    };
                    count += 1;
                }
        }
        count
    }

    /// Count confirmed shards.
    pub fn confirmed_count(&self) -> usize {
        self.assignments.values()
            .filter(|s| matches!(s, ShardAssignmentState::Confirmed { .. }))
            .count()
    }

    /// Count pending shards.
    pub fn pending_count(&self) -> usize {
        self.assignments.values()
            .filter(|s| matches!(s, ShardAssignmentState::Pending { .. }))
            .count()
    }

    /// Count failed shards.
    pub fn failed_count(&self) -> usize {
        self.assignments.values()
            .filter(|s| matches!(s, ShardAssignmentState::Failed { .. }))
            .count()
    }

    /// Whether the 48h acceptance window has expired.
    pub fn accept_window_expired(&self, now_ms: i64) -> bool {
        now_ms - self.requested_at_ms >= valence_core::constants::REPLICATION_ACCEPT_WINDOW_MS
    }
}

// --- Rent Payment Coordination (§6) ---

/// Tracks rent obligations for a piece of replicated content.
#[derive(Debug)]
pub struct RentTracker {
    /// SHA-256 hex of the content.
    pub content_hash: String,
    /// Uploader node ID.
    pub uploader: String,
    /// Content size in bytes.
    pub content_size_bytes: u64,
    /// Scarcity multiplier locked at replication time.
    pub locked_multiplier: valence_core::types::FixedPoint,
    /// Timestamp when replication completed.
    pub replication_timestamp_ms: i64,
    /// Current billing cycle number (0-indexed).
    pub current_cycle: u32,
    /// Timestamp when the node joined mid-cycle (for pro-rating), if applicable.
    pub joined_at_ms: Option<i64>,
    /// Per-provider challenge pass counts for the current cycle.
    pub provider_challenges: std::collections::HashMap<String, u32>,
    /// Provider shard counts.
    pub provider_shards: std::collections::HashMap<String, u32>,
    /// Total shards for this content.
    pub total_shards: u32,
}

impl RentTracker {
    /// Create a new rent tracker when content is replicated.
    pub fn new(
        content_hash: String,
        uploader: String,
        content_size_bytes: u64,
        locked_multiplier: valence_core::types::FixedPoint,
        replication_timestamp_ms: i64,
        total_shards: u32,
    ) -> Self {
        Self {
            content_hash,
            uploader,
            content_size_bytes,
            locked_multiplier,
            replication_timestamp_ms,
            current_cycle: 0,
            joined_at_ms: None,
            provider_challenges: std::collections::HashMap::new(),
            provider_shards: std::collections::HashMap::new(),
            total_shards,
        }
    }

    /// Compute the billing cycle number for a given timestamp.
    pub fn cycle_for_timestamp(&self, now_ms: i64) -> u32 {
        let elapsed = now_ms - self.replication_timestamp_ms;
        if elapsed < 0 { return 0; }
        (elapsed / valence_core::constants::RENT_BILLING_CYCLE_MS) as u32
    }

    /// Start of cycle N in milliseconds.
    pub fn cycle_start_ms(&self, cycle: u32) -> i64 {
        self.replication_timestamp_ms + (cycle as i64 * valence_core::constants::RENT_BILLING_CYCLE_MS)
    }

    /// Compute monthly rent for the current cycle using convergence formula.
    pub fn rent_for_cycle(&self, cycle: u32, current_multiplier: valence_core::types::FixedPoint) -> valence_core::types::FixedPoint {
        let effective = valence_protocol::content::effective_multiplier(
            self.locked_multiplier,
            current_multiplier,
            cycle,
        );
        valence_protocol::content::monthly_rent(self.content_size_bytes, effective)
    }

    /// Compute pro-rated rent for a mid-cycle join.
    /// Returns the fraction of a full cycle's rent.
    pub fn prorated_rent(
        &self,
        cycle: u32,
        current_multiplier: valence_core::types::FixedPoint,
    ) -> valence_core::types::FixedPoint {
        let full_rent = self.rent_for_cycle(cycle, current_multiplier);
        if let Some(joined) = self.joined_at_ms {
            let cycle_start = self.cycle_start_ms(cycle);
            let cycle_end = cycle_start + valence_core::constants::RENT_BILLING_CYCLE_MS;
            let active_ms = cycle_end - joined.max(cycle_start);
            if active_ms <= 0 {
                return valence_core::types::FixedPoint::ZERO;
            }
            let fraction = active_ms as i128 * valence_core::types::FixedPoint::SCALE as i128
                / valence_core::constants::RENT_BILLING_CYCLE_MS as i128;
            let prorated = full_rent.raw() as i128 * fraction
                / valence_core::types::FixedPoint::SCALE as i128;
            valence_core::types::FixedPoint::from_raw(prorated as i64)
        } else {
            full_rent
        }
    }

    /// Record a provider passing a challenge.
    pub fn record_challenge_pass(&mut self, provider: &str) {
        *self.provider_challenges.entry(provider.to_string()).or_insert(0) += 1;
    }

    /// Set shard count for a provider.
    pub fn set_provider_shards(&mut self, provider: &str, count: u32) {
        self.provider_shards.insert(provider.to_string(), count);
    }

    /// Advance to the next billing cycle, clearing per-cycle state.
    pub fn advance_cycle(&mut self) {
        self.current_cycle += 1;
        self.provider_challenges.clear();
    }

    /// Whether a RENT_PAYMENT is late (>7 days into the cycle).
    pub fn is_payment_late(&self, now_ms: i64) -> bool {
        let cycle_start = self.cycle_start_ms(self.current_cycle);
        let deadline = cycle_start + (valence_core::constants::RENT_PAYMENT_DEADLINE_DAYS as i64 * 24 * 60 * 60 * 1000);
        now_ms > deadline
    }
}

// --- CONTENT_WITHDRAW Flow (§6) ---

/// Tracks pending content withdrawals.
#[derive(Debug)]
pub struct WithdrawTracker {
    /// Pending withdrawals: content_hash → (effective_after_ms, withdrawn_at_ms).
    pending: std::collections::HashMap<String, (i64, i64)>,
    /// Content hashes with active proposals (voting_deadline not yet passed).
    active_proposals: std::collections::HashSet<String>,
}

impl Default for WithdrawTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl WithdrawTracker {
    pub fn new() -> Self {
        Self {
            pending: std::collections::HashMap::new(),
            active_proposals: std::collections::HashSet::new(),
        }
    }

    /// Register an active proposal referencing content.
    pub fn add_active_proposal(&mut self, content_hash: &str) {
        self.active_proposals.insert(content_hash.to_string());
    }

    /// Remove an active proposal (voting deadline passed or withdrawn).
    pub fn remove_active_proposal(&mut self, content_hash: &str) {
        self.active_proposals.remove(content_hash);
    }

    /// Attempt to register a CONTENT_WITHDRAW.
    /// Returns Err if:
    /// - `effective_after` is less than 24h from `timestamp`
    /// - Content has any active proposal
    pub fn request_withdraw(
        &mut self,
        content_hash: &str,
        effective_after: i64,
        timestamp: i64,
    ) -> Result<(), StorageError> {
        // §6: effective_after MUST be ≥ 24h from message timestamp
        if effective_after - timestamp < valence_core::constants::CONTENT_WITHDRAW_DELAY_MS {
            return Err(StorageError::WithdrawTooSoon {
                minimum_delay_ms: valence_core::constants::CONTENT_WITHDRAW_DELAY_MS,
            });
        }
        // §6: blocked by ANY active proposal
        if self.active_proposals.contains(content_hash) {
            return Err(StorageError::WithdrawBlockedByProposal {
                content_hash: content_hash.to_string(),
            });
        }
        self.pending.insert(content_hash.to_string(), (effective_after, timestamp));
        Ok(())
    }

    /// Check if a PROPOSE should be rejected because CONTENT_WITHDRAW has been seen.
    pub fn is_withdrawing(&self, content_hash: &str) -> bool {
        self.pending.contains_key(content_hash)
    }

    /// Check if a withdrawal is now effective.
    pub fn is_effective(&self, content_hash: &str, now_ms: i64) -> bool {
        if let Some(&(effective_after, _)) = self.pending.get(content_hash) {
            now_ms >= effective_after
        } else {
            false
        }
    }

    /// Remove a completed or cancelled withdrawal.
    pub fn remove(&mut self, content_hash: &str) {
        self.pending.remove(content_hash);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Empty artifact")]
    EmptyArtifact,
    #[error("Reed-Solomon error: {0}")]
    ReedSolomon(String),
    #[error("Wrong shard count: expected {expected}, got {got}")]
    WrongShardCount { expected: usize, got: usize },
    #[error("Insufficient shards: need {needed}, have {available}")]
    InsufficientShards { needed: usize, available: usize },
    #[error("Invalid offset {offset} for shard size {shard_size}")]
    InvalidOffset { offset: usize, shard_size: usize },
    #[error("Invalid challenge nonce")]
    InvalidNonce,
    #[error("Content withdrawal too soon: minimum delay is {minimum_delay_ms}ms")]
    WithdrawTooSoon { minimum_delay_ms: i64 },
    #[error("Content withdrawal blocked by active proposal for {content_hash}")]
    WithdrawBlockedByProposal { content_hash: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_minimal() {
        let data = b"Hello, Valence Network! This is a test artifact for erasure coding.";
        let coding = ErasureCoding::Minimal; // 3 data, 2 parity

        let shards = encode_artifact(data, &coding).unwrap();
        assert_eq!(shards.len(), 5); // 3 + 2

        // Reconstruct from all shards
        let mut shard_data: Vec<Option<Vec<u8>>> = shards.iter().map(|s| Some(s.data.clone())).collect();
        let recovered = reconstruct_artifact(&mut shard_data, &coding, data.len()).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn encode_decode_with_missing_shards() {
        let data = b"Test data for reconstruction with missing shards";
        let coding = ErasureCoding::Standard; // 5 data, 3 parity

        let shards = encode_artifact(data, &coding).unwrap();
        assert_eq!(shards.len(), 8);

        // Remove 3 shards (we can tolerate up to parity_shards missing)
        let mut shard_data: Vec<Option<Vec<u8>>> = shards.iter().map(|s| Some(s.data.clone())).collect();
        shard_data[0] = None;
        shard_data[2] = None;
        shard_data[6] = None;

        let recovered = reconstruct_artifact(&mut shard_data, &coding, data.len()).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn encode_decode_resilient() {
        let data = vec![42u8; 10_000]; // 10KB artifact
        let coding = ErasureCoding::Resilient; // 8 data, 4 parity

        let shards = encode_artifact(data.as_slice(), &coding).unwrap();
        assert_eq!(shards.len(), 12);

        // Remove 4 shards (max tolerable)
        let mut shard_data: Vec<Option<Vec<u8>>> = shards.iter().map(|s| Some(s.data.clone())).collect();
        shard_data[1] = None;
        shard_data[3] = None;
        shard_data[5] = None;
        shard_data[11] = None;

        let recovered = reconstruct_artifact(&mut shard_data, &coding, data.len()).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn insufficient_shards_fails() {
        let data = b"test";
        let coding = ErasureCoding::Minimal; // 3 data, 2 parity

        let shards = encode_artifact(data, &coding).unwrap();
        let mut shard_data: Vec<Option<Vec<u8>>> = shards.iter().map(|s| Some(s.data.clone())).collect();

        // Remove 3 shards — need 3, only have 2
        shard_data[0] = None;
        shard_data[1] = None;
        shard_data[2] = None;

        let result = reconstruct_artifact(&mut shard_data, &coding, data.len());
        assert!(matches!(result, Err(StorageError::InsufficientShards { .. })));
    }

    #[test]
    fn empty_artifact_fails() {
        let result = encode_artifact(b"", &ErasureCoding::Minimal);
        assert!(matches!(result, Err(StorageError::EmptyArtifact)));
    }

    #[test]
    fn manifest_hash_deterministic() {
        let hashes = vec!["cccc".to_string(), "aaaa".to_string(), "bbbb".to_string()];
        let content_hash = "dddd";

        let h1 = compute_manifest_hash(3, &hashes, content_hash);
        let h2 = compute_manifest_hash(3, &hashes, content_hash);
        assert_eq!(h1, h2);

        // Order shouldn't matter (sorted internally)
        let reordered = vec!["bbbb".to_string(), "cccc".to_string(), "aaaa".to_string()];
        let h3 = compute_manifest_hash(3, &reordered, content_hash);
        assert_eq!(h1, h3);
    }

    #[test]
    fn manifest_hash_different_with_different_content() {
        let hashes = vec!["aaaa".to_string()];
        let h1 = compute_manifest_hash(1, &hashes, "content1");
        let h2 = compute_manifest_hash(1, &hashes, "content2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn manifest_hash_different_with_different_shard_count() {
        let hashes = vec!["aaaa".to_string(), "bbbb".to_string()];
        let h1 = compute_manifest_hash(2, &hashes, "content");
        let h2 = compute_manifest_hash(3, &hashes, "content");
        assert_ne!(h1, h2);
    }

    #[test]
    fn manifest_hash_includes_shard_count_prefix() {
        // Verify the hash includes the 4-byte big-endian shard_count prefix
        // by checking it differs from a hash without it.
        let hashes = vec!["aaaa".to_string()];
        let with_prefix = compute_manifest_hash(1, &hashes, "test");

        // Manually compute without prefix for comparison
        let mut no_prefix = String::new();
        no_prefix.push_str("aaaa");
        no_prefix.push_str("test");
        let without_prefix = hex::encode(Sha256::digest(no_prefix.as_bytes()));

        assert_ne!(with_prefix, without_prefix);
    }

    #[test]
    fn storage_challenge_proof_roundtrip() {
        let shard_data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let challenge = StorageChallenge {
            shard_hash: "test_hash".to_string(),
            offset: 3,
            direction: ChallengeDirection::After,
            window_size: 4,
            challenge_nonce: hex::encode([0xABu8; 32]),
        };

        let proof = compute_proof(&challenge, &shard_data).unwrap();
        assert!(verify_proof(&challenge, &proof, &shard_data).unwrap());
    }

    #[test]
    fn storage_proof_fails_with_wrong_data() {
        let real_data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let fake_data = vec![9u8, 9, 9, 9, 9, 9, 9, 9];
        let challenge = StorageChallenge {
            shard_hash: "test_hash".to_string(),
            offset: 0,
            direction: ChallengeDirection::After,
            window_size: 4,
            challenge_nonce: hex::encode([0xCDu8; 32]),
        };

        let proof = compute_proof(&challenge, &fake_data).unwrap();
        // Verify against real data — should fail
        assert!(!verify_proof(&challenge, &proof, &real_data).unwrap());
    }

    #[test]
    fn storage_challenge_nonce_prevents_replay() {
        let shard_data = vec![1u8, 2, 3, 4, 5];
        let challenge1 = StorageChallenge {
            shard_hash: "test".to_string(),
            offset: 0,
            direction: ChallengeDirection::After,
            window_size: 3,
            challenge_nonce: hex::encode([0x01u8; 32]),
        };
        let challenge2 = StorageChallenge {
            shard_hash: "test".to_string(),
            offset: 0,
            direction: ChallengeDirection::After,
            window_size: 3,
            challenge_nonce: hex::encode([0x02u8; 32]),
        };

        let proof1 = compute_proof(&challenge1, &shard_data).unwrap();
        let proof2 = compute_proof(&challenge2, &shard_data).unwrap();

        // Different nonces → different proofs (can't replay)
        assert_ne!(proof1.proof_hash, proof2.proof_hash);

        // Each proof only valid for its own challenge
        assert!(verify_proof(&challenge1, &proof1, &shard_data).unwrap());
        assert!(!verify_proof(&challenge2, &proof1, &shard_data).unwrap());
    }

    #[test]
    fn shard_metadata_roundtrip() {
        let data = b"artifact for metadata test";
        let coding = ErasureCoding::Standard;
        let shards = encode_artifact(data, &coding).unwrap();
        let content_hash = hex::encode(Sha256::digest(data));

        let meta = build_shard_metadata(&shards, &coding, &content_hash);
        assert_eq!(meta.data_shards, 5);
        assert_eq!(meta.parity_shards, 3);
        assert_eq!(meta.shard_hashes.len(), 8);
        assert!(!meta.manifest_hash.is_empty());

        // Verify manifest hash matches recomputation
        let recomputed = compute_manifest_hash(
            (meta.data_shards + meta.parity_shards) as u32,
            &meta.shard_hashes,
            &content_hash,
        );
        assert_eq!(meta.manifest_hash, recomputed);
    }

    #[test]
    fn parity_shard_challenge() {
        // §6: Parity shards can be challenged via reconstruction
        let data = b"parity shard challenge test data";
        let coding = ErasureCoding::Minimal;
        let shards = encode_artifact(data, &coding).unwrap();

        // Challenge a parity shard (index 3 or 4)
        let parity_shard = &shards[3];
        let challenge = StorageChallenge {
            shard_hash: parity_shard.hash.clone(),
            offset: 0,
            direction: ChallengeDirection::After,
            window_size: 4.min(parity_shard.data.len()),
            challenge_nonce: hex::encode([0xFFu8; 32]),
        };

        let proof = compute_proof(&challenge, &parity_shard.data).unwrap();
        assert!(verify_proof(&challenge, &proof, &parity_shard.data).unwrap());
    }

    // --- ContentTransfer tests ---

    #[test]
    fn content_transfer_accept_and_assign() {
        let mut ct = ContentTransfer::new("abc123".into(), "uploader1".into(), 1000);
        ct.accept("provider_a".into(), vec![0, 1]);
        ct.accept("provider_b".into(), vec![2, 3]);
        assert_eq!(ct.accepted_providers.len(), 2);
        assert!(!ct.assigned);

        ct.assign(&[(0, "provider_a".into()), (2, "provider_b".into())], 2000);
        assert!(ct.assigned);
        assert_eq!(ct.pending_count(), 2);
        assert_eq!(ct.confirmed_count(), 0);
    }

    #[test]
    fn content_transfer_confirm_shard() {
        let mut ct = ContentTransfer::new("abc".into(), "up".into(), 1000);
        ct.assign(&[(0, "prov_a".into()), (1, "prov_b".into())], 2000);

        assert!(ct.confirm_shard(0, "prov_a", 3000));
        assert_eq!(ct.confirmed_count(), 1);
        assert_eq!(ct.pending_count(), 1);

        // Can't confirm twice
        assert!(!ct.confirm_shard(0, "prov_a", 4000));
        // Can't confirm non-existent
        assert!(!ct.confirm_shard(99, "prov_a", 4000));
    }

    #[test]
    fn content_transfer_expire_stale() {
        let mut ct = ContentTransfer::new("abc".into(), "up".into(), 1000);
        ct.assign(&[(0, "prov_a".into()), (1, "prov_b".into())], 1000);

        // Confirm one
        ct.confirm_shard(0, "prov_a", 2000);

        // Expire at 24h + 1ms
        let expired = ct.expire_stale(1000 + SHARD_ASSIGNMENT_TIMEOUT_MS);
        assert_eq!(expired, 1); // prov_b timed out
        assert_eq!(ct.failed_count(), 1);
        assert_eq!(ct.confirmed_count(), 1);
    }

    #[test]
    fn content_transfer_no_expire_before_timeout() {
        let mut ct = ContentTransfer::new("abc".into(), "up".into(), 1000);
        ct.assign(&[(0, "prov_a".into())], 1000);

        let expired = ct.expire_stale(1000 + SHARD_ASSIGNMENT_TIMEOUT_MS - 1);
        assert_eq!(expired, 0);
    }

    #[test]
    fn content_transfer_accept_window() {
        let ct = ContentTransfer::new("abc".into(), "up".into(), 1000);
        assert!(!ct.accept_window_expired(1000 + valence_core::constants::REPLICATION_ACCEPT_WINDOW_MS - 1));
        assert!(ct.accept_window_expired(1000 + valence_core::constants::REPLICATION_ACCEPT_WINDOW_MS));
    }

    // --- RentTracker tests ---

    #[test]
    fn rent_tracker_cycle_computation() {
        let rt = RentTracker::new(
            "hash".into(), "up".into(), 1_048_576, // 1 MiB
            valence_core::types::FixedPoint::ONE,
            0, 5,
        );
        assert_eq!(rt.cycle_for_timestamp(0), 0);
        assert_eq!(rt.cycle_for_timestamp(valence_core::constants::RENT_BILLING_CYCLE_MS - 1), 0);
        assert_eq!(rt.cycle_for_timestamp(valence_core::constants::RENT_BILLING_CYCLE_MS), 1);
        assert_eq!(rt.cycle_for_timestamp(valence_core::constants::RENT_BILLING_CYCLE_MS * 3), 3);
    }

    #[test]
    fn rent_tracker_rent_for_cycle_0() {
        let rt = RentTracker::new(
            "hash".into(), "up".into(), 1_048_576,
            valence_core::types::FixedPoint::ONE, 0, 5,
        );
        // Cycle 0, current multiplier same as locked → rent = base_rate
        let rent = rt.rent_for_cycle(0, valence_core::types::FixedPoint::ONE);
        assert_eq!(rent.raw(), valence_core::constants::STORAGE_BASE_RATE.raw());
    }

    #[test]
    fn rent_tracker_prorated_half_cycle() {
        let cycle_ms = valence_core::constants::RENT_BILLING_CYCLE_MS;
        let mut rt = RentTracker::new(
            "hash".into(), "up".into(), 1_048_576,
            valence_core::types::FixedPoint::ONE, 0, 5,
        );
        // Joined halfway through cycle 0
        rt.joined_at_ms = Some(cycle_ms / 2);
        let prorated = rt.prorated_rent(0, valence_core::types::FixedPoint::ONE);
        let full = rt.rent_for_cycle(0, valence_core::types::FixedPoint::ONE);
        // Should be approximately half
        assert!((prorated.raw() - full.raw() / 2).abs() <= 1);
    }

    #[test]
    fn rent_tracker_prorated_no_join() {
        let rt = RentTracker::new(
            "hash".into(), "up".into(), 1_048_576,
            valence_core::types::FixedPoint::ONE, 0, 5,
        );
        let prorated = rt.prorated_rent(0, valence_core::types::FixedPoint::ONE);
        let full = rt.rent_for_cycle(0, valence_core::types::FixedPoint::ONE);
        assert_eq!(prorated, full);
    }

    #[test]
    fn rent_tracker_challenge_tracking() {
        let mut rt = RentTracker::new(
            "hash".into(), "up".into(), 1_048_576,
            valence_core::types::FixedPoint::ONE, 0, 5,
        );
        rt.record_challenge_pass("prov_a");
        rt.record_challenge_pass("prov_a");
        rt.record_challenge_pass("prov_b");
        assert_eq!(rt.provider_challenges.get("prov_a"), Some(&2));
        assert_eq!(rt.provider_challenges.get("prov_b"), Some(&1));

        rt.advance_cycle();
        assert_eq!(rt.current_cycle, 1);
        assert!(rt.provider_challenges.is_empty());
    }

    #[test]
    fn rent_tracker_payment_late() {
        let rt = RentTracker::new(
            "hash".into(), "up".into(), 1_048_576,
            valence_core::types::FixedPoint::ONE, 0, 5,
        );
        let deadline = valence_core::constants::RENT_PAYMENT_DEADLINE_DAYS as i64 * 24 * 60 * 60 * 1000;
        assert!(!rt.is_payment_late(deadline - 1));
        assert!(rt.is_payment_late(deadline + 1));
    }

    // --- WithdrawTracker tests ---

    #[test]
    fn withdraw_enforces_24h_delay() {
        let mut wt = WithdrawTracker::new();
        let timestamp = 1_000_000i64;
        let too_soon = timestamp + valence_core::constants::CONTENT_WITHDRAW_DELAY_MS - 1;
        let ok_time = timestamp + valence_core::constants::CONTENT_WITHDRAW_DELAY_MS;

        assert!(wt.request_withdraw("abc", too_soon, timestamp).is_err());
        assert!(wt.request_withdraw("abc", ok_time, timestamp).is_ok());
    }

    #[test]
    fn withdraw_blocked_by_active_proposal() {
        let mut wt = WithdrawTracker::new();
        let ts = 1_000_000i64;
        let effective = ts + valence_core::constants::CONTENT_WITHDRAW_DELAY_MS;

        wt.add_active_proposal("abc");
        assert!(matches!(
            wt.request_withdraw("abc", effective, ts),
            Err(StorageError::WithdrawBlockedByProposal { .. })
        ));

        wt.remove_active_proposal("abc");
        assert!(wt.request_withdraw("abc", effective, ts).is_ok());
    }

    #[test]
    fn withdraw_blocks_propose() {
        let mut wt = WithdrawTracker::new();
        let ts = 1_000_000i64;
        let effective = ts + valence_core::constants::CONTENT_WITHDRAW_DELAY_MS;

        assert!(!wt.is_withdrawing("abc"));
        wt.request_withdraw("abc", effective, ts).unwrap();
        assert!(wt.is_withdrawing("abc"));
    }

    #[test]
    fn withdraw_effective_timing() {
        let mut wt = WithdrawTracker::new();
        let ts = 1_000_000i64;
        let effective = ts + valence_core::constants::CONTENT_WITHDRAW_DELAY_MS;

        wt.request_withdraw("abc", effective, ts).unwrap();
        assert!(!wt.is_effective("abc", effective - 1));
        assert!(wt.is_effective("abc", effective));
        assert!(wt.is_effective("abc", effective + 1000));
    }

    #[test]
    fn withdraw_remove() {
        let mut wt = WithdrawTracker::new();
        let ts = 1_000_000i64;
        let effective = ts + valence_core::constants::CONTENT_WITHDRAW_DELAY_MS;
        wt.request_withdraw("abc", effective, ts).unwrap();
        assert!(wt.is_withdrawing("abc"));
        wt.remove("abc");
        assert!(!wt.is_withdrawing("abc"));
    }
}
