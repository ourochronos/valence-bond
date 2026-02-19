//! Verifiable Delay Function per §9.
//!
//! v0 uses iterated SHA-256:
//!   h[0] = SHA-256(public_key_bytes)
//!   h[i] = SHA-256(h[i-1])  for i = 1..difficulty
//!   output = h[difficulty]
//!   checkpoint[k] = h[k × checkpoint_interval]

use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};
use valence_core::constants::{VDF_CHECKPOINT_INTERVAL, VDF_DIFFICULTY};

/// Get current unix timestamp in milliseconds.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// A VDF proof with intermediate checkpoints.
#[derive(Debug, Clone)]
pub struct VdfProof {
    /// Final output hash.
    pub output: Vec<u8>,
    /// Input data (public key bytes).
    pub input_data: Vec<u8>,
    /// Difficulty (number of iterations).
    pub difficulty: u64,
    /// When the VDF computation began (unix milliseconds) per §9.
    pub computed_at: i64,
    /// Checkpoint hashes at every checkpoint_interval iterations.
    pub checkpoints: Vec<VdfCheckpoint>,
}

#[derive(Debug, Clone)]
pub struct VdfCheckpoint {
    pub iteration: u64,
    pub hash: Vec<u8>,
}

/// Compute a VDF proof over the given input.
pub fn compute(input: &[u8], difficulty: u64) -> VdfProof {
    let computed_at = now_ms();
    let checkpoint_interval = if difficulty >= VDF_CHECKPOINT_INTERVAL {
        VDF_CHECKPOINT_INTERVAL
    } else {
        // For low-difficulty tests, checkpoint every iteration
        1
    };

    let mut h = Sha256::digest(input).to_vec();
    let mut checkpoints = Vec::new();

    for i in 1..=difficulty {
        h = Sha256::digest(&h).to_vec();
        if i % checkpoint_interval == 0 {
            checkpoints.push(VdfCheckpoint {
                iteration: i,
                hash: h.clone(),
            });
        }
    }

    VdfProof {
        output: h,
        input_data: input.to_vec(),
        difficulty,
        computed_at,
        checkpoints,
    }
}

/// Compute with standard difficulty.
pub fn compute_standard(public_key_bytes: &[u8]) -> VdfProof {
    compute(public_key_bytes, VDF_DIFFICULTY)
}

/// Verify a VDF proof by spot-checking segments.
/// Returns Ok(()) if valid, Err with description if invalid.
/// Per §9: rejects proofs where `computed_at` is older than 24 hours or >5 minutes in the future.
pub fn verify(proof: &VdfProof, min_segments: usize) -> Result<(), String> {
    if proof.checkpoints.is_empty() {
        return Err("No checkpoints in proof".to_string());
    }

    // Timestamp validation per §9
    let now = now_ms();
    let age_ms = now - proof.computed_at;
    let max_age_ms = 24 * 60 * 60 * 1000; // 24 hours
    let max_future_ms = 5 * 60 * 1000;    // 5 minutes

    if age_ms > max_age_ms {
        return Err(format!(
            "VDF proof too old: computed_at {} is {} hours old (max 24 hours)",
            proof.computed_at,
            age_ms / (60 * 60 * 1000)
        ));
    }

    if age_ms < -max_future_ms {
        return Err(format!(
            "VDF proof timestamp too far in future: computed_at {} is {} minutes ahead (max 5 minutes)",
            proof.computed_at,
            -age_ms / (60 * 1000)
        ));
    }

    // Verify input_data matches (caller should check this is the node's public key)
    let h0 = Sha256::digest(&proof.input_data).to_vec();

    // L-1: Randomly select segments to verify (not just the first N).
    // This prevents attackers from computing only the first segments honestly.
    let mut segment_indices: Vec<usize> = (0..proof.checkpoints.len()).collect();
    {
        let mut rng = rand::thread_rng();
        segment_indices.shuffle(&mut rng);
    }
    segment_indices.truncate(min_segments);
    segment_indices.sort(); // Sort for sequential access efficiency

    // Verify selected segments
    for &seg_idx in &segment_indices {
        let start_hash = if seg_idx == 0 {
            &h0
        } else {
            &proof.checkpoints[seg_idx - 1].hash
        };

        let start_iter = if seg_idx == 0 {
            0
        } else {
            proof.checkpoints[seg_idx - 1].iteration
        };

        let end = &proof.checkpoints[seg_idx];

        // Recompute from start to end
        let mut h = start_hash.clone();
        for _ in (start_iter + 1)..=end.iteration {
            h = Sha256::digest(&h).to_vec();
        }

        // Note: start_iter is 0-indexed from h[0], iterations start from h[1]
        // h[0] = SHA-256(input), so iteration 1 = SHA-256(h[0])
        // We need to compute from h[start_iter] to h[end.iteration]

        if h != end.hash {
            return Err(format!(
                "Segment verification failed at checkpoint iteration {}",
                end.iteration
            ));
        }
    }

    // Verify output matches last checkpoint (if difficulty aligns with checkpoint interval)
    if let Some(last) = proof.checkpoints.last()
        && last.iteration == proof.difficulty && last.hash != proof.output {
            return Err("Output doesn't match last checkpoint".to_string());
        }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vdf_01_iteration_semantics() {
        // Conformance test VDF-01: difficulty=10 with keypair A
        let pubkey = hex::decode("4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29").unwrap();
        let proof = compute(&pubkey, 10);

        // Verify against conformance test vectors
        let expected_hashes = [
            "d111c750e50313ec88ef003a46b2e75bb439740c9145e7c8871e0a92f2e4f71e", // h[1]
            "36bf77dd9b62b1f6de5d69e36716c317290f3ade523de1ff07aaed38e541bd3f", // h[2]
            "258f310ec5d92fe424cf05afb208ffa9161575d51940af6dfa3fb876930418b5", // h[3]
            "18a99c7ec36bd99d88cf34e6efa39ba2ce6304e8e94375796c43a1882a181536", // h[4]
            "a02a25c25b7ea445d9f8e64d42e96c9e8e18cfe59b6b70aac4ece4b6033929ca", // h[5]
            "1c7fc0d6447423192601d6013088f1b9eb0a090dad041805d142731f09d5362a", // h[6]
            "7f66ccd286f0650d5b3160352bd9befe35337ea21287deb4a5a98ee2e1220682", // h[7]
            "fa8f34e4825e5855ee980e87f790ec2be08195ff116aa863ee637a54086764a0", // h[8]
            "47d8b22fe73482b8c2fc6bef4d3a878f0b42ed1cd874de3cd1b086d7bc89e495", // h[9]
            "449bcdcf7459a1bb9b5ad418b3c2f96623fbf19080d30bcacccb664bab6abaa3", // h[10]
        ];

        assert_eq!(proof.checkpoints.len(), 10);
        for (i, cp) in proof.checkpoints.iter().enumerate() {
            assert_eq!(hex::encode(&cp.hash), expected_hashes[i], "Mismatch at h[{}]", i + 1);
        }

        assert_eq!(
            hex::encode(&proof.output),
            "449bcdcf7459a1bb9b5ad418b3c2f96623fbf19080d30bcacccb664bab6abaa3"
        );
    }

    #[test]
    fn vdf_compute_and_verify() {
        let input = b"test_public_key_bytes_here_32byt";
        let proof = compute(input, 100);
        assert!(verify(&proof, 5).is_ok());
    }

    #[test]
    fn vdf_tampered_proof_fails() {
        let input = b"test_public_key_bytes_here_32byt";
        let mut proof = compute(input, 10);
        // Tamper with a checkpoint
        if let Some(cp) = proof.checkpoints.get_mut(3) {
            cp.hash[0] ^= 0xff;
        }
        // Verify all segments to deterministically catch the tampered checkpoint
        assert!(verify(&proof, 10).is_err());
    }

    #[test]
    fn vdf_proof_timestamp_too_old() {
        let input = b"test_public_key_bytes_here_32byt";
        let mut proof = compute(input, 10);
        // Set timestamp to 25 hours ago
        proof.computed_at = now_ms() - (25 * 60 * 60 * 1000);
        let result = verify(&proof, 5);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too old"));
    }

    #[test]
    fn vdf_proof_timestamp_too_far_future() {
        let input = b"test_public_key_bytes_here_32byt";
        let mut proof = compute(input, 10);
        // Set timestamp to 6 minutes in the future
        proof.computed_at = now_ms() + (6 * 60 * 1000);
        let result = verify(&proof, 5);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("future"));
    }

    // ── L-1: Random segment verification ──

    #[test]
    fn vdf_verify_catches_tampering_in_later_segments() {
        // L-1: Tamper with a later segment (not the first few) — random
        // sampling should eventually catch it
        let input = b"test_public_key_bytes_here_32byt";
        let mut proof = compute(input, 10);
        // Tamper with the last checkpoint
        if let Some(cp) = proof.checkpoints.last_mut() {
            cp.hash[0] ^= 0xff;
        }
        // Verify with enough segments to cover all checkpoints
        let result = verify(&proof, 10);
        assert!(result.is_err(), "Tampering in last segment should be caught");
    }

    #[test]
    fn vdf_proof_timestamp_valid_recent() {
        let input = b"test_public_key_bytes_here_32byt";
        let proof = compute(input, 10);
        // Fresh proof should pass
        assert!(verify(&proof, 5).is_ok());
    }
}
