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
/// SHA-256 of: shard_hashes sorted lexicographically as hex strings,
/// concatenated without delimiters, then appended with content_hash hex string — all as UTF-8 bytes.
pub fn compute_manifest_hash(shard_hashes: &[String], content_hash: &str) -> String {
    let mut sorted = shard_hashes.to_vec();
    sorted.sort();
    let mut input = String::new();
    for h in &sorted {
        input.push_str(h);
    }
    input.push_str(content_hash);
    hex::encode(Sha256::digest(input.as_bytes()))
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
    let shard_size = (data.len() + data_count - 1) / data_count;
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
    for shard in shard_data.iter().take(data_count) {
        if let Some(data) = shard {
            result.extend_from_slice(data);
        }
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
    let manifest_hash = compute_manifest_hash(&shard_hashes, content_hash);

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
    let max_offset = if shard_size > window_size { shard_size - window_size } else { 0 };
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

        let h1 = compute_manifest_hash(&hashes, content_hash);
        let h2 = compute_manifest_hash(&hashes, content_hash);
        assert_eq!(h1, h2);

        // Order shouldn't matter (sorted internally)
        let reordered = vec!["bbbb".to_string(), "cccc".to_string(), "aaaa".to_string()];
        let h3 = compute_manifest_hash(&reordered, content_hash);
        assert_eq!(h1, h3);
    }

    #[test]
    fn manifest_hash_different_with_different_content() {
        let hashes = vec!["aaaa".to_string()];
        let h1 = compute_manifest_hash(&hashes, "content1");
        let h2 = compute_manifest_hash(&hashes, "content2");
        assert_ne!(h1, h2);
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
        let recomputed = compute_manifest_hash(&meta.shard_hashes, &content_hash);
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
}
