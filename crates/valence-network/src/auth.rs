//! Mutual authentication handshake per §3.
//!
//! After a libp2p connection is established, peers exchange signed challenges:
//! 1. Initiator sends AUTH_CHALLENGE with random nonce + initiator's public key
//! 2. Responder signs (nonce || initiator_key) with their key, sends AUTH_RESPONSE
//! 3. Initiator verifies the signature
//! 4. Roles reverse: responder challenges initiator
//!
//! Unauthenticated peers are disconnected after AUTH_TIMEOUT.

use std::time::Duration;

use valence_crypto::identity::{verify_signature, NodeIdentity};

use crate::gossip::{AuthChallenge, AuthResponse};

/// Timeout for auth handshake completion.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of pending (unauthenticated) connections.
pub const MAX_PENDING_AUTH: usize = 64;

/// Result of verifying an auth response.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthResult {
    /// Authentication succeeded. Contains the verified node ID (hex public key).
    Authenticated(String),
    /// Signature verification failed.
    InvalidSignature,
    /// Challenge nonce mismatch.
    NonceMismatch,
    /// Response public key is empty or malformed.
    MalformedKey,
}

/// Create a new auth challenge for the given identity.
pub fn create_challenge(identity: &NodeIdentity) -> AuthChallenge {
    AuthChallenge::new(&identity.node_id())
}

/// Create an auth response: sign the challenge with our identity.
pub fn create_response(
    identity: &NodeIdentity,
    challenge: &AuthChallenge,
    vdf_proof: serde_json::Value,
) -> AuthResponse {
    let signing_bytes = challenge.signing_bytes();
    let signature = identity.sign(&signing_bytes);
    AuthResponse {
        signature: hex::encode(signature),
        public_key: identity.node_id(),
        vdf_proof,
    }
}

/// Verify an auth response against the original challenge.
pub fn verify_response(
    challenge: &AuthChallenge,
    response: &AuthResponse,
) -> AuthResult {
    if response.public_key.is_empty() {
        return AuthResult::MalformedKey;
    }

    // Verify hex key is valid
    if hex::decode(&response.public_key).map(|b| b.len()).unwrap_or(0) != 32 {
        return AuthResult::MalformedKey;
    }

    let signing_bytes = challenge.signing_bytes();

    if verify_signature(&response.public_key, &signing_bytes, &response.signature) {
        AuthResult::Authenticated(response.public_key.clone())
    } else {
        AuthResult::InvalidSignature
    }
}

/// Parse a VDF proof from a JSON value.
pub fn parse_vdf_proof(value: &serde_json::Value) -> Option<valence_crypto::vdf::VdfProof> {
    let output = hex::decode(value.get("output")?.as_str()?).ok()?;
    let input_data = hex::decode(value.get("input_data")?.as_str()?).ok()?;
    let difficulty = value.get("difficulty")?.as_u64()?;
    let computed_at = value.get("computed_at")?.as_i64()?;

    let checkpoints = value.get("checkpoints")?.as_array()?.iter().filter_map(|cp| {
        Some(valence_crypto::vdf::VdfCheckpoint {
            iteration: cp.get("iteration")?.as_u64()?,
            hash: hex::decode(cp.get("hash")?.as_str()?).ok()?,
        })
    }).collect();

    Some(valence_crypto::vdf::VdfProof {
        output,
        input_data,
        difficulty,
        computed_at,
        checkpoints,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_handshake_valid() {
        let initiator = NodeIdentity::generate();
        let responder = NodeIdentity::generate();

        // Initiator creates challenge
        let challenge = create_challenge(&initiator);

        // Responder signs it
        let response = create_response(&responder, &challenge, serde_json::json!({}));

        // Initiator verifies
        let result = verify_response(&challenge, &response);
        assert_eq!(result, AuthResult::Authenticated(responder.node_id()));
    }

    #[test]
    fn auth_handshake_wrong_key_fails() {
        let initiator = NodeIdentity::generate();
        let responder = NodeIdentity::generate();
        let imposter = NodeIdentity::generate();

        let challenge = create_challenge(&initiator);

        // Imposter signs, but claims to be responder
        let mut response = create_response(&imposter, &challenge, serde_json::json!({}));
        response.public_key = responder.node_id(); // claim to be responder

        let result = verify_response(&challenge, &response);
        assert_eq!(result, AuthResult::InvalidSignature);
    }

    #[test]
    fn auth_handshake_tampered_nonce_fails() {
        let initiator = NodeIdentity::generate();
        let responder = NodeIdentity::generate();

        let challenge = create_challenge(&initiator);
        let response = create_response(&responder, &challenge, serde_json::json!({}));

        // Tamper with the challenge nonce before verifying
        let mut tampered_challenge = challenge;
        tampered_challenge.nonce = "00".repeat(32);

        let result = verify_response(&tampered_challenge, &response);
        assert_eq!(result, AuthResult::InvalidSignature);
    }

    #[test]
    fn auth_handshake_empty_key_rejected() {
        let initiator = NodeIdentity::generate();
        let challenge = create_challenge(&initiator);

        let response = AuthResponse {
            signature: "ab".repeat(64),
            public_key: String::new(),
            vdf_proof: serde_json::json!({}),
        };

        assert_eq!(verify_response(&challenge, &response), AuthResult::MalformedKey);
    }

    #[test]
    fn auth_handshake_malformed_key_rejected() {
        let initiator = NodeIdentity::generate();
        let challenge = create_challenge(&initiator);

        let response = AuthResponse {
            signature: "ab".repeat(64),
            public_key: "not-hex".to_string(),
            vdf_proof: serde_json::json!({}),
        };

        assert_eq!(verify_response(&challenge, &response), AuthResult::MalformedKey);
    }

    #[test]
    fn auth_mutual_handshake() {
        // Full mutual auth: both sides challenge and respond
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();

        // Alice challenges Bob
        let challenge_ab = create_challenge(&alice);
        let response_ba = create_response(&bob, &challenge_ab, serde_json::json!({}));
        assert_eq!(
            verify_response(&challenge_ab, &response_ba),
            AuthResult::Authenticated(bob.node_id())
        );

        // Bob challenges Alice
        let challenge_ba = create_challenge(&bob);
        let response_ab = create_response(&alice, &challenge_ba, serde_json::json!({}));
        assert_eq!(
            verify_response(&challenge_ba, &response_ab),
            AuthResult::Authenticated(alice.node_id())
        );
    }
}
