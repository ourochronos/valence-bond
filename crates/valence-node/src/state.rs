//! Aggregated node state with persistence for crash recovery.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use valence_network::gossip::MessageRateLimiter;
use valence_network::storage::{ContentTransfer, WithdrawTracker};
use valence_network::sync::{IdentityMerkleTree, SyncManager, SyncServingTracker};
use valence_protocol::identity::IdentityManager;
use valence_protocol::proposals::{ProposalRateLimiter, ProposalTracker};
use valence_protocol::reputation::ReputationState;

/// Default checkpoint interval in seconds.
const CHECKPOINT_INTERVAL_SECS: u64 = 300; // 5 minutes
/// Default event threshold for checkpointing.
const CHECKPOINT_EVENT_THRESHOLD: u64 = 100;

/// Aggregated protocol state for the node.
pub struct NodeState {
    // Protocol managers
    pub reputations: HashMap<String, ReputationState>,
    pub proposals: HashMap<String, ProposalTracker>,
    pub identity_manager: IdentityManager,
    pub content_transfers: HashMap<String, ContentTransfer>,
    pub withdraw_tracker: WithdrawTracker,
    pub proposal_rate_limiter: ProposalRateLimiter,
    pub rate_limiter: MessageRateLimiter,

    // Sync protocol (§5)
    pub sync_manager: SyncManager,
    pub identity_merkle_tree: IdentityMerkleTree,
    #[allow(dead_code)]
    pub sync_serving_tracker: SyncServingTracker,

    // Rent cycle tracking (§6)
    pub last_rent_cycle: u64,

    // Snapshot publishing tracking (§5)
    pub last_snapshot_publish_ms: Option<i64>,

    // Persistence tracking
    events_since_checkpoint: u64,
    last_checkpoint: Instant,
}

impl Default for NodeState {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeState {
    /// Create a fresh node state with default initial values.
    pub fn new() -> Self {
        Self {
            reputations: HashMap::new(),
            proposals: HashMap::new(),
            identity_manager: IdentityManager::new(),
            content_transfers: HashMap::new(),
            withdraw_tracker: WithdrawTracker::new(),
            proposal_rate_limiter: ProposalRateLimiter::new(),
            rate_limiter: MessageRateLimiter::new(),
            sync_manager: SyncManager::new(false),
            identity_merkle_tree: IdentityMerkleTree::new(),
            sync_serving_tracker: SyncServingTracker::new(),
            last_rent_cycle: 0,
            last_snapshot_publish_ms: None,
            events_since_checkpoint: 0,
            last_checkpoint: Instant::now(),
        }
    }

    /// Record an event and check if we should checkpoint.
    pub fn record_event(&mut self) -> bool {
        self.events_since_checkpoint += 1;
        self.should_checkpoint()
    }

    /// Check if a checkpoint is due (by time or event count).
    pub fn should_checkpoint(&self) -> bool {
        self.events_since_checkpoint >= CHECKPOINT_EVENT_THRESHOLD
            || self.last_checkpoint.elapsed().as_secs() >= CHECKPOINT_INTERVAL_SECS
    }

    /// Reset checkpoint counters after a successful save.
    pub fn mark_checkpointed(&mut self) {
        self.events_since_checkpoint = 0;
        self.last_checkpoint = Instant::now();
    }
}

// ─── Persistence via a serializable snapshot ─────────────────────────

/// Serializable snapshot of the parts of state we persist.
/// Not all state is persisted — rate limiters and in-flight transfers
/// are ephemeral and rebuilt on restart.
#[derive(Debug, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Known identity groups (root → child keys).
    pub identities: Vec<IdentitySnapshot>,
    /// Proposal IDs we're tracking (lightweight — full state rebuilt from gossip).
    pub tracked_proposals: Vec<String>,
    /// Content hashes with active withdrawal requests.
    pub withdrawals: Vec<WithdrawalSnapshot>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentitySnapshot {
    pub root_key: String,
    pub children: Vec<String>,
    pub revoked: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WithdrawalSnapshot {
    pub content_hash: String,
    pub effective_after: i64,
    /// M-7: Original request timestamp, preserved for correct restoration.
    #[serde(default)]
    pub request_timestamp: i64,
}

/// State directory layout under the base path:
///
/// ```text
/// <base>/
///   identity.key       — 32-byte Ed25519 seed
///   state.json         — latest state snapshot
///   state.json.bak     — previous snapshot (crash safety)
/// ```
pub struct StatePersistence {
    base_dir: PathBuf,
}

impl StatePersistence {
    /// Create persistence manager for the given base directory.
    /// Creates the directory if it doesn't exist.
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&base_dir)
            .with_context(|| format!("Failed to create state dir: {}", base_dir.display()))?;
        Ok(Self { base_dir })
    }

    /// Default base directory: ~/.valence-node/
    pub fn default_dir() -> PathBuf {
        dirs_path().join("valence-node")
    }

    pub fn state_path(&self) -> PathBuf {
        self.base_dir.join("state.json")
    }

    pub fn backup_path(&self) -> PathBuf {
        self.base_dir.join("state.json.bak")
    }

    pub fn identity_path(&self) -> PathBuf {
        self.base_dir.join("identity.key")
    }

    pub fn vdf_proof_path(&self) -> PathBuf {
        self.base_dir.join("vdf_proof.json")
    }

    /// Save VDF proof to disk.
    pub fn save_vdf_proof(&self, proof: &valence_crypto::vdf::VdfProof) -> Result<()> {
        let path = self.vdf_proof_path();
        let json = serde_json::json!({
            "output": hex::encode(&proof.output),
            "input_data": hex::encode(&proof.input_data),
            "difficulty": proof.difficulty,
            "computed_at": proof.computed_at,
            "checkpoints": proof.checkpoints.iter().map(|cp| serde_json::json!({
                "iteration": cp.iteration,
                "hash": hex::encode(&cp.hash),
            })).collect::<Vec<_>>(),
        });
        let data = serde_json::to_string_pretty(&json)?;
        std::fs::write(&path, &data)
            .with_context(|| format!("Failed to write VDF proof to {}", path.display()))?;
        info!(path = %path.display(), "VDF proof saved");
        Ok(())
    }

    /// Load VDF proof from disk.
    pub fn load_vdf_proof(&self) -> Result<Option<serde_json::Value>> {
        let path = self.vdf_proof_path();
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read VDF proof from {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&data)
            .context("Failed to parse VDF proof")?;
        Ok(Some(value))
    }

    /// Save state snapshot to disk with atomic rename for crash safety.
    pub fn save(&self, snapshot: &StateSnapshot) -> Result<()> {
        let path = self.state_path();
        let backup = self.backup_path();

        let data =
            serde_json::to_string_pretty(snapshot).context("Failed to serialize state snapshot")?;

        // Rotate current → backup
        if path.exists() {
            std::fs::copy(&path, &backup).ok();
        }

        // L-6: Write via temp file with fsync for true crash-safe atomicity
        let tmp = self.base_dir.join("state.json.tmp");
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&tmp)
                .context("Failed to create temp state file")?;
            file.write_all(data.as_bytes())
                .context("Failed to write temp state file")?;
            file.sync_all()
                .context("Failed to fsync temp state file")?;
        }
        std::fs::rename(&tmp, &path).context("Failed to rename temp state file")?;
        // Fsync the directory to ensure the rename is durable
        if let Ok(dir) = std::fs::File::open(&self.base_dir) {
            let _ = dir.sync_all();
        }

        debug!(path = %path.display(), bytes = data.len(), "State checkpoint saved");
        Ok(())
    }

    /// Load state snapshot from disk.
    pub fn load(&self) -> Result<Option<StateSnapshot>> {
        let path = self.state_path();
        if !path.exists() {
            return Ok(None);
        }

        let data = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read state from {}", path.display()))?;

        let snapshot: StateSnapshot =
            serde_json::from_str(&data).context("Failed to parse state snapshot")?;

        info!(path = %path.display(), "Loaded state snapshot");
        Ok(Some(snapshot))
    }

    /// Load identity seed from disk, or return None.
    /// Checks file permissions on Unix and refuses to load world-readable keys (C-3).
    pub fn load_identity_seed(&self) -> Result<Option<[u8; 32]>> {
        let path = self.identity_path();
        if !path.exists() {
            return Ok(None);
        }

        // C-3: Check permissions before loading
        self.check_identity_permissions()?;

        let bytes = std::fs::read(&path)
            .with_context(|| format!("Failed to read identity from {}", path.display()))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Identity file must be exactly 32 bytes"))?;
        Ok(Some(seed))
    }

    /// Save identity seed to disk with restricted permissions (0600).
    pub fn save_identity_seed(&self, seed: &[u8; 32]) -> Result<()> {
        let path = self.identity_path();
        std::fs::write(&path, seed)
            .with_context(|| format!("Failed to write identity to {}", path.display()))?;

        // C-3: Set permissions to 0600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("Failed to set permissions on {}", path.display()))?;
        }

        info!(path = %path.display(), "Identity seed saved (mode 0600)");
        Ok(())
    }

    /// Load identity seed from disk, checking file permissions.
    /// Refuses to load if the key file is world-readable (C-3).
    pub fn check_identity_permissions(&self) -> Result<()> {
        let path = self.identity_path();
        if !path.exists() {
            return Ok(());
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&path)
                .with_context(|| format!("Failed to read metadata for {}", path.display()))?;
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                anyhow::bail!(
                    "Identity key file {} has insecure permissions {:04o}. \
                     Expected 0600 (owner read/write only). \
                     Fix with: chmod 600 {}",
                    path.display(),
                    mode,
                    path.display()
                );
            }
        }

        Ok(())
    }
}

/// Platform-appropriate home directory.
fn dirs_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home)
    } else {
        PathBuf::from(".")
    }
}

/// Apply a loaded snapshot to a NodeState, restoring persistent data.
pub fn restore_from_snapshot(state: &mut NodeState, snapshot: &StateSnapshot) {
    // Restore identities
    for id_snap in &snapshot.identities {
        state
            .identity_manager
            .register_root(id_snap.root_key.clone());
        // Note: Full child key restoration would require storing DidLinkRequests.
        // For now we record the root; children are re-learned from gossip.
    }

    // Restore withdrawal tracking
    for w in &snapshot.withdrawals {
        // We can't fully restore without the owner, but we mark as withdrawing
        // by using an empty string owner — the real owner re-announces on reconnect.
        // M-7: Use the stored original request timestamp instead of 0
        let _ = state.withdraw_tracker.request_withdraw(
            &w.content_hash,
            w.effective_after,
            w.request_timestamp,
        );
    }

    info!(
        identities = snapshot.identities.len(),
        withdrawals = snapshot.withdrawals.len(),
        "Restored state from snapshot"
    );
}

/// Create a snapshot from the current NodeState.
pub fn create_snapshot(state: &NodeState) -> StateSnapshot {
    // M-8: Persist ALL identities including solo roots (not just groups with children)
    let identities = state
        .identity_manager
        .all_identities()
        .map(|id| {
            IdentitySnapshot {
                root_key: id.root_key.clone(),
                children: id.children.keys().cloned().collect(),
                revoked: id.revoked.iter().cloned().collect(),
            }
        })
        .collect();

    let tracked_proposals = state.proposals.keys().cloned().collect();

    // Withdrawals — we'd need to expose internals of WithdrawTracker.
    // For now, produce an empty list; a proper impl would iterate the tracker.
    let withdrawals = vec![];

    StateSnapshot {
        identities,
        tracked_proposals,
        withdrawals,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn node_state_new_defaults() {
        let state = NodeState::new();
        assert!(state.reputations.is_empty());
        assert!(state.proposals.is_empty());
        assert!(!state.should_checkpoint());
    }

    #[test]
    fn checkpoint_triggers_on_event_count() {
        let mut state = NodeState::new();
        for _ in 0..99 {
            assert!(!state.record_event());
        }
        assert!(state.record_event()); // 100th event
    }

    #[test]
    fn persistence_save_and_load() {
        let tmp = TempDir::new().unwrap();
        let persist = StatePersistence::new(tmp.path().to_path_buf()).unwrap();

        let snapshot = StateSnapshot {
            identities: vec![IdentitySnapshot {
                root_key: "abc".into(),
                children: vec!["def".into()],
                revoked: vec![],
            }],
            tracked_proposals: vec!["prop-1".into()],
            withdrawals: vec![],
        };

        persist.save(&snapshot).unwrap();
        let loaded = persist.load().unwrap().unwrap();
        assert_eq!(loaded.identities.len(), 1);
        assert_eq!(loaded.identities[0].root_key, "abc");
        assert_eq!(loaded.tracked_proposals, vec!["prop-1"]);
    }

    #[test]
    fn persistence_identity_seed_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let persist = StatePersistence::new(tmp.path().to_path_buf()).unwrap();

        let seed = [42u8; 32];
        persist.save_identity_seed(&seed).unwrap();
        let loaded = persist.load_identity_seed().unwrap().unwrap();
        assert_eq!(loaded, seed);
    }

    #[cfg(unix)]
    #[test]
    fn identity_seed_saved_with_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let persist = StatePersistence::new(tmp.path().to_path_buf()).unwrap();

        let seed = [42u8; 32];
        persist.save_identity_seed(&seed).unwrap();

        let metadata = std::fs::metadata(persist.identity_path()).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "Key file should have mode 0600, got {:04o}", mode);
    }

    #[cfg(unix)]
    #[test]
    fn identity_seed_refuses_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let persist = StatePersistence::new(tmp.path().to_path_buf()).unwrap();

        let seed = [42u8; 32];
        // Write with insecure permissions
        let path = persist.identity_path();
        std::fs::write(&path, seed).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let result = persist.load_identity_seed();
        assert!(result.is_err(), "Should refuse to load world-readable key");
        assert!(result.unwrap_err().to_string().contains("insecure permissions"));
    }

    #[test]
    fn persistence_load_missing_returns_none() {
        let tmp = TempDir::new().unwrap();
        let persist = StatePersistence::new(tmp.path().to_path_buf()).unwrap();
        assert!(persist.load().unwrap().is_none());
        assert!(persist.load_identity_seed().unwrap().is_none());
    }

    #[test]
    fn snapshot_roundtrip_via_state() {
        let mut state = NodeState::new();
        state.identity_manager.register_root("root1".to_string());

        let snapshot = create_snapshot(&state);
        assert!(snapshot.tracked_proposals.is_empty());

        let mut state2 = NodeState::new();
        restore_from_snapshot(&mut state2, &snapshot);
    }

    // ── M-7: WithdrawalSnapshot preserves request_timestamp ──

    #[test]
    fn withdrawal_snapshot_preserves_request_timestamp() {
        let snapshot = StateSnapshot {
            identities: vec![],
            tracked_proposals: vec![],
            withdrawals: vec![WithdrawalSnapshot {
                content_hash: "abc".into(),
                effective_after: 2_000_000,
                request_timestamp: 1_000_000,
            }],
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let loaded: StateSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.withdrawals[0].request_timestamp, 1_000_000);
    }

    #[test]
    fn withdrawal_snapshot_defaults_request_timestamp() {
        // M-7: Old snapshots without request_timestamp should default to 0
        let json = r#"{"identities":[],"tracked_proposals":[],"withdrawals":[{"content_hash":"abc","effective_after":2000000}]}"#;
        let loaded: StateSnapshot = serde_json::from_str(json).unwrap();
        assert_eq!(loaded.withdrawals[0].request_timestamp, 0);
    }

    // ── M-8: Snapshot persists solo root identities ──

    #[test]
    fn snapshot_persists_solo_root_identities() {
        let mut state = NodeState::new();
        state.identity_manager.register_root("solo_root".to_string());

        let snapshot = create_snapshot(&state);
        // M-8: Solo root without children should now be persisted
        assert_eq!(snapshot.identities.len(), 1);
        assert_eq!(snapshot.identities[0].root_key, "solo_root");
        assert!(snapshot.identities[0].children.is_empty());

        // Verify roundtrip
        let mut state2 = NodeState::new();
        restore_from_snapshot(&mut state2, &snapshot);
        assert_eq!(state2.identity_manager.identity_count(), 1);
    }

    // ── L-6: Atomic save with fsync ──

    #[test]
    fn persistence_save_creates_file_with_content() {
        let tmp = TempDir::new().unwrap();
        let persist = StatePersistence::new(tmp.path().to_path_buf()).unwrap();

        let snapshot = StateSnapshot {
            identities: vec![],
            tracked_proposals: vec!["p1".into()],
            withdrawals: vec![],
        };

        persist.save(&snapshot).unwrap();

        // L-6: File should exist and have non-zero content
        let content = std::fs::read_to_string(persist.state_path()).unwrap();
        assert!(!content.is_empty());
        assert!(content.contains("p1"));
    }

    // ── VDF proof persistence tests ──

    #[test]
    fn vdf_proof_save_and_load() {
        use valence_crypto::identity::NodeIdentity;

        let tmp = TempDir::new().unwrap();
        let persist = StatePersistence::new(tmp.path().to_path_buf()).unwrap();

        let identity = NodeIdentity::generate();
        let proof = valence_crypto::vdf::compute(&identity.public_key_bytes(), 10);
        persist.save_vdf_proof(&proof).unwrap();

        let loaded = persist.load_vdf_proof().unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(
            loaded.get("output").unwrap().as_str().unwrap(),
            hex::encode(&proof.output)
        );
        assert_eq!(
            loaded.get("difficulty").unwrap().as_u64().unwrap(),
            proof.difficulty
        );
    }

    #[test]
    fn vdf_proof_load_missing_returns_none() {
        let tmp = TempDir::new().unwrap();
        let persist = StatePersistence::new(tmp.path().to_path_buf()).unwrap();
        assert!(persist.load_vdf_proof().unwrap().is_none());
    }

    #[test]
    fn vdf_proof_roundtrip_verifiable() {
        use valence_crypto::identity::NodeIdentity;

        let tmp = TempDir::new().unwrap();
        let persist = StatePersistence::new(tmp.path().to_path_buf()).unwrap();

        let identity = NodeIdentity::generate();
        let proof = valence_crypto::vdf::compute(&identity.public_key_bytes(), 10);
        persist.save_vdf_proof(&proof).unwrap();

        // Load and parse back into a VdfProof
        let loaded_json = persist.load_vdf_proof().unwrap().unwrap();
        let parsed = valence_network::auth::parse_vdf_proof(&loaded_json).unwrap();

        // Verify the loaded proof
        assert!(valence_crypto::vdf::verify(&parsed, 5).is_ok());
        assert_eq!(parsed.input_data, identity.public_key_bytes().to_vec());
    }
}
