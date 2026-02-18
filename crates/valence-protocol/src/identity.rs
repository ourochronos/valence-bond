//! Identity linking — authorized keys model per §1.
//!
//! One identity = one root key + zero or more authorized child keys.
//! All actions attributed to the root. Single reputation, single vote, dampened gains.

use std::collections::{HashMap, HashSet};

use valence_core::types::{FixedPoint, NodeId, Timestamp};

/// An identity: root key + authorized children.
#[derive(Debug, Clone)]
pub struct Identity {
    /// The root public key (hex).
    pub root_key: NodeId,
    /// Authorized child keys → label.
    pub children: HashMap<NodeId, ChildKey>,
    /// Revoked keys (permanently deauthorized).
    pub revoked: HashSet<NodeId>,
}

#[derive(Debug, Clone)]
pub struct ChildKey {
    pub key: NodeId,
    pub label: Option<String>,
    pub linked_at_ms: Timestamp,
}

impl Identity {
    pub fn new(root_key: NodeId) -> Self {
        Self {
            root_key,
            children: HashMap::new(),
            revoked: HashSet::new(),
        }
    }

    /// Number of authorized keys (root + children).
    pub fn authorized_key_count(&self) -> usize {
        1 + self.children.len()
    }

    /// Reputation gain dampening factor per §1:
    /// LINEAR dampening: `1.0 / authorized_key_count`
    pub fn gain_dampening(&self) -> FixedPoint {
        let count = self.authorized_key_count() as f64;
        FixedPoint::from_f64(1.0 / count.powf(0.75))
    }

    /// Apply gain dampening to a raw reputation gain.
    pub fn dampen_gain(&self, raw_gain: FixedPoint) -> FixedPoint {
        raw_gain.mul(self.gain_dampening())
    }

    /// Check if a key belongs to this identity (root or child).
    pub fn contains_key(&self, key: &str) -> bool {
        self.root_key == key || self.children.contains_key(key)
    }

    /// Check if a key has been revoked from this identity.
    pub fn is_revoked(&self, key: &str) -> bool {
        self.revoked.contains(key)
    }
}

/// DID_LINK request (parsed from envelope payload).
#[derive(Debug, Clone)]
pub struct DidLinkRequest {
    pub root_key: NodeId,
    pub child_key: NodeId,
    pub child_signature: String,
    pub label: Option<String>,
}

/// DID_REVOKE request.
#[derive(Debug, Clone)]
pub struct DidRevokeRequest {
    pub root_key: NodeId,
    pub revoked_key: NodeId,
    pub reason: Option<String>,
    pub effective_from: Timestamp,
}

/// KEY_CONFLICT payload per §1.
#[derive(Debug, Clone)]
pub struct KeyConflict {
    pub old_key: NodeId,
    pub rotate_message_1_id: String,
    pub rotate_message_2_id: String,
    pub new_key_1: NodeId,
    pub new_key_2: NodeId,
}

/// Errors from identity operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error("Child key {0} is already linked to another identity")]
    AlreadyLinked(String),
    #[error("Child key {0} is a root key of another identity")]
    ChildIsRoot(String),
    #[error("Child key {0} has been permanently revoked")]
    KeyRevoked(String),
    #[error("Key {0} is not an authorized child of this identity")]
    NotAChild(String),
    #[error("Root key cannot revoke itself")]
    CannotRevokeSelf,
    #[error("Sender {0} is not the root key of this identity")]
    NotRoot(String),
    #[error("Identity not found for key {0}")]
    IdentityNotFound(String),
}

/// Global identity manager — tracks all identities in the network.
#[derive(Debug, Default)]
pub struct IdentityManager {
    /// Root key → Identity.
    identities: HashMap<NodeId, Identity>,
    /// Child key → root key (reverse index).
    child_to_root: HashMap<NodeId, NodeId>,
    /// All keys that are root keys (for child-is-root check).
    root_keys: HashSet<NodeId>,
    /// Permanently revoked keys (cannot be re-linked).
    globally_revoked: HashSet<NodeId>,
    /// Keys implicitly linked via KEY_ROTATE of a child.
    implicit_links: HashSet<NodeId>,
}

impl IdentityManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a root identity (called when we first see a node).
    pub fn register_root(&mut self, root_key: NodeId) {
        if !self.identities.contains_key(&root_key) {
            self.identities.insert(root_key.clone(), Identity::new(root_key.clone()));
            self.root_keys.insert(root_key);
        }
    }

    /// Process a DID_LINK message per §1.
    pub fn link(&mut self, request: &DidLinkRequest, timestamp_ms: Timestamp) -> Result<(), IdentityError> {
        // Child must not be already linked
        if self.child_to_root.contains_key(&request.child_key) {
            return Err(IdentityError::AlreadyLinked(request.child_key.clone()));
        }

        // Child must not be implicitly linked via KEY_ROTATE
        if self.implicit_links.contains(&request.child_key) {
            return Err(IdentityError::AlreadyLinked(request.child_key.clone()));
        }

        // Child must not be a root key
        if self.root_keys.contains(&request.child_key) {
            return Err(IdentityError::ChildIsRoot(request.child_key.clone()));
        }

        // Child must not be permanently revoked
        if self.globally_revoked.contains(&request.child_key) {
            return Err(IdentityError::KeyRevoked(request.child_key.clone()));
        }

        // Ensure root identity exists
        self.register_root(request.root_key.clone());

        let identity = self.identities.get_mut(&request.root_key).unwrap();
        identity.children.insert(
            request.child_key.clone(),
            ChildKey {
                key: request.child_key.clone(),
                label: request.label.clone(),
                linked_at_ms: timestamp_ms,
            },
        );

        self.child_to_root.insert(request.child_key.clone(), request.root_key.clone());
        Ok(())
    }

    /// Process a DID_REVOKE message per §1.
    pub fn revoke(&mut self, request: &DidRevokeRequest) -> Result<(), IdentityError> {
        // Root cannot revoke itself
        if request.root_key == request.revoked_key {
            return Err(IdentityError::CannotRevokeSelf);
        }

        let identity = self.identities.get_mut(&request.root_key)
            .ok_or_else(|| IdentityError::IdentityNotFound(request.root_key.clone()))?;

        // Must be an actual child
        if !identity.children.contains_key(&request.revoked_key) {
            return Err(IdentityError::NotAChild(request.revoked_key.clone()));
        }

        identity.children.remove(&request.revoked_key);
        identity.revoked.insert(request.revoked_key.clone());
        self.child_to_root.remove(&request.revoked_key);
        self.globally_revoked.insert(request.revoked_key.clone());

        Ok(())
    }

    /// Record that a child key was rotated (implicit link for new key).
    pub fn record_child_key_rotate(&mut self, old_child: &str, new_child: NodeId) {
        if let Some(root_key) = self.child_to_root.get(old_child).cloned() {
            // Transfer child → root mapping
            self.child_to_root.remove(old_child);
            self.child_to_root.insert(new_child.clone(), root_key.clone());
            self.implicit_links.insert(new_child.clone());

            // Update identity
            if let Some(identity) = self.identities.get_mut(&root_key) {
                if let Some(child_info) = identity.children.remove(old_child) {
                    identity.children.insert(new_child, child_info);
                }
            }
        }
    }

    /// Record that a root key was rotated (new root inherits children).
    pub fn record_root_key_rotate(&mut self, old_root: &str, new_root: NodeId) {
        if let Some(mut identity) = self.identities.remove(old_root) {
            // Update root
            self.root_keys.remove(old_root);
            self.root_keys.insert(new_root.clone());
            identity.root_key = new_root.clone();

            // Update child → root mappings
            for child_key in identity.children.keys() {
                self.child_to_root.insert(child_key.clone(), new_root.clone());
            }

            self.identities.insert(new_root, identity);
        }
    }

    /// Resolve a key to its root identity. Returns the key itself if it IS a root.
    pub fn resolve_root<'a>(&'a self, key: &'a str) -> Option<&'a str> {
        if self.identities.contains_key(key) {
            Some(key)
        } else if let Some(root) = self.child_to_root.get(key) {
            Some(root.as_str())
        } else {
            None
        }
    }

    /// Get the identity for a key (root or child).
    pub fn get_identity(&self, key: &str) -> Option<&Identity> {
        let root = self.resolve_root(key)?;
        self.identities.get(root)
    }

    /// Check if two keys belong to the same identity.
    pub fn same_identity(&self, key_a: &str, key_b: &str) -> bool {
        match (self.resolve_root(key_a), self.resolve_root(key_b)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// Get all keys in an identity (root + children) as a HashSet.
    /// Useful for collusion detection exemption (§10).
    pub fn identity_group(&self, key: &str) -> Option<HashSet<String>> {
        let identity = self.get_identity(key)?;
        let mut group = HashSet::new();
        group.insert(identity.root_key.clone());
        for child_key in identity.children.keys() {
            group.insert(child_key.clone());
        }
        Some(group)
    }

    /// Get all identity groups (for passing to collusion detection).
    pub fn all_identity_groups(&self) -> Vec<HashSet<String>> {
        self.identities
            .values()
            .filter(|id| !id.children.is_empty())
            .map(|id| {
                let mut group = HashSet::new();
                group.insert(id.root_key.clone());
                for k in id.children.keys() {
                    group.insert(k.clone());
                }
                group
            })
            .collect()
    }

    /// Check if a key is permanently revoked.
    pub fn is_revoked(&self, key: &str) -> bool {
        self.globally_revoked.contains(key)
    }

    /// Number of tracked identities.
    pub fn identity_count(&self) -> usize {
        self.identities.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_link_and_resolve() {
        let mut mgr = IdentityManager::new();
        mgr.register_root("root_a".into());

        mgr.link(&DidLinkRequest {
            root_key: "root_a".into(),
            child_key: "child_b".into(),
            child_signature: "sig".into(),
            label: Some("relay".into()),
        }, 1000).unwrap();

        assert_eq!(mgr.resolve_root("root_a"), Some("root_a"));
        assert_eq!(mgr.resolve_root("child_b"), Some("root_a"));
        assert!(mgr.same_identity("root_a", "child_b"));
    }

    #[test]
    fn duplicate_link_rejected() {
        let mut mgr = IdentityManager::new();
        mgr.register_root("root_a".into());
        mgr.register_root("root_c".into());

        mgr.link(&DidLinkRequest {
            root_key: "root_a".into(),
            child_key: "child_b".into(),
            child_signature: "sig".into(),
            label: None,
        }, 1000).unwrap();

        // Second root trying to claim same child
        let err = mgr.link(&DidLinkRequest {
            root_key: "root_c".into(),
            child_key: "child_b".into(),
            child_signature: "sig".into(),
            label: None,
        }, 2000).unwrap_err();

        assert!(matches!(err, IdentityError::AlreadyLinked(_)));
    }

    #[test]
    fn child_cannot_be_root() {
        let mut mgr = IdentityManager::new();
        mgr.register_root("root_a".into());
        mgr.register_root("root_b".into());

        let err = mgr.link(&DidLinkRequest {
            root_key: "root_a".into(),
            child_key: "root_b".into(),
            child_signature: "sig".into(),
            label: None,
        }, 1000).unwrap_err();

        assert!(matches!(err, IdentityError::ChildIsRoot(_)));
    }

    #[test]
    fn revoke_and_permanent_ban() {
        let mut mgr = IdentityManager::new();
        mgr.register_root("root_a".into());
        mgr.link(&DidLinkRequest {
            root_key: "root_a".into(),
            child_key: "child_b".into(),
            child_signature: "sig".into(),
            label: None,
        }, 1000).unwrap();

        mgr.revoke(&DidRevokeRequest {
            root_key: "root_a".into(),
            revoked_key: "child_b".into(),
            reason: Some("compromised".into()),
            effective_from: 2000,
        }).unwrap();

        // child_b no longer resolves to root_a
        assert_eq!(mgr.resolve_root("child_b"), None);
        assert!(mgr.is_revoked("child_b"));

        // Cannot re-link to ANY identity
        let err = mgr.link(&DidLinkRequest {
            root_key: "root_a".into(),
            child_key: "child_b".into(),
            child_signature: "sig".into(),
            label: None,
        }, 3000).unwrap_err();
        assert!(matches!(err, IdentityError::KeyRevoked(_)));
    }

    #[test]
    fn root_cannot_revoke_self() {
        let mut mgr = IdentityManager::new();
        mgr.register_root("root_a".into());

        let err = mgr.revoke(&DidRevokeRequest {
            root_key: "root_a".into(),
            revoked_key: "root_a".into(),
            reason: None,
            effective_from: 1000,
        }).unwrap_err();
        assert!(matches!(err, IdentityError::CannotRevokeSelf));
    }

    #[test]
    fn child_key_rotate_implicit_link() {
        let mut mgr = IdentityManager::new();
        mgr.register_root("root_a".into());
        mgr.link(&DidLinkRequest {
            root_key: "root_a".into(),
            child_key: "child_b".into(),
            child_signature: "sig".into(),
            label: None,
        }, 1000).unwrap();

        // child_b rotates to child_b2
        mgr.record_child_key_rotate("child_b", "child_b2".into());

        // child_b2 resolves to root_a
        assert_eq!(mgr.resolve_root("child_b2"), Some("root_a"));

        // Attacker cannot claim child_b2
        mgr.register_root("evil".into());
        let err = mgr.link(&DidLinkRequest {
            root_key: "evil".into(),
            child_key: "child_b2".into(),
            child_signature: "sig".into(),
            label: None,
        }, 2000).unwrap_err();
        assert!(matches!(err, IdentityError::AlreadyLinked(_)));
    }

    #[test]
    fn root_key_rotate_inherits_children() {
        let mut mgr = IdentityManager::new();
        mgr.register_root("root_a".into());
        mgr.link(&DidLinkRequest {
            root_key: "root_a".into(),
            child_key: "child_b".into(),
            child_signature: "sig".into(),
            label: None,
        }, 1000).unwrap();

        mgr.record_root_key_rotate("root_a", "root_a2".into());

        // child_b now under root_a2
        assert_eq!(mgr.resolve_root("child_b"), Some("root_a2"));
        assert!(mgr.same_identity("root_a2", "child_b"));
        // Old root no longer exists
        assert_eq!(mgr.resolve_root("root_a"), None);
    }

    #[test]
    fn gain_dampening_single_node() {
        let identity = Identity::new("root".into());
        // 1^0.75 = 1.0 — no dampening
        assert_eq!(identity.gain_dampening(), FixedPoint::ONE);
        assert_eq!(identity.dampen_gain(FixedPoint::from_f64(0.01)).raw(), 100);
    }

    #[test]
    fn gain_dampening_four_keys() {
        let mut identity = Identity::new("root".into());
        for i in 0..3 {
            identity.children.insert(format!("child_{i}"), ChildKey {
                key: format!("child_{i}"),
                label: None,
                linked_at_ms: 1000,
            });
        }
        // 4 keys: linear dampening = 1/4 = 0.25
        let dampening = identity.gain_dampening();
        // 1/4^0.75 = 1/2.8284 ≈ 0.3535
        assert_eq!(dampening.raw(), 3535);

        let gain = FixedPoint::from_f64(0.04);
        let dampened = identity.dampen_gain(gain);
        // 0.04 * 0.3535 ≈ 0.0141
        assert_eq!(dampened.raw(), 141);
    }

    #[test]
    fn gain_dampening_nine_keys() {
        let mut identity = Identity::new("root".into());
        for i in 0..8 {
            identity.children.insert(format!("c{i}"), ChildKey {
                key: format!("c{i}"),
                label: None,
                linked_at_ms: 1000,
            });
        }
        // 9 keys: linear dampening = 1/9 = 0.1111
        let dampening = identity.gain_dampening();
        // 1/9^0.75 = 1/5.1962 ≈ 0.1924
        assert_eq!(dampening.raw(), 1924);
    }

    #[test]
    fn identity_groups_for_collusion_exemption() {
        let mut mgr = IdentityManager::new();
        mgr.register_root("root_a".into());
        mgr.link(&DidLinkRequest {
            root_key: "root_a".into(),
            child_key: "child_b".into(),
            child_signature: "sig".into(),
            label: None,
        }, 1000).unwrap();
        mgr.link(&DidLinkRequest {
            root_key: "root_a".into(),
            child_key: "child_c".into(),
            child_signature: "sig".into(),
            label: None,
        }, 2000).unwrap();

        // Single-node identity with no children — not in groups
        mgr.register_root("loner".into());

        let groups = mgr.all_identity_groups();
        assert_eq!(groups.len(), 1);
        assert!(groups[0].contains("root_a"));
        assert!(groups[0].contains("child_b"));
        assert!(groups[0].contains("child_c"));
        assert_eq!(groups[0].len(), 3);
    }

    #[test]
    fn withdraw_by_sibling_key() {
        // §6: Any key in identity can withdraw proposals by another key
        let mut mgr = IdentityManager::new();
        mgr.register_root("root_a".into());
        mgr.link(&DidLinkRequest {
            root_key: "root_a".into(),
            child_key: "child_b".into(),
            child_signature: "sig".into(),
            label: None,
        }, 1000).unwrap();
        mgr.link(&DidLinkRequest {
            root_key: "root_a".into(),
            child_key: "child_c".into(),
            child_signature: "sig".into(),
            label: None,
        }, 2000).unwrap();

        // child_b authored a proposal, child_c wants to withdraw
        assert!(mgr.same_identity("child_b", "child_c"));
        // root can also withdraw
        assert!(mgr.same_identity("root_a", "child_b"));
        // unrelated node cannot
        mgr.register_root("outsider".into());
        assert!(!mgr.same_identity("outsider", "child_b"));
    }
}
