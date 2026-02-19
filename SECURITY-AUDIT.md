# Security Audit — Valence Network v0 (Rust)

**Date:** 2026-02-18  
**Auditor:** Claude (automated, adversarial review)  
**Scope:** All source in `crates/valence-{crypto,core,protocol,network,node}/src/`  
**Threat model:** Public node on open internet, malicious peers sending crafted messages

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 4 |
| HIGH     | 8 |
| MEDIUM   | 9 |
| LOW      | 7 |
| INFO     | 5 |
| **Total** | **33** |

**Verdict: NOT safe to run publicly in current state.** The CRITICAL and HIGH findings must be addressed first. The node has solid protocol logic and good use of Rust's type system, but the network-facing attack surface has several exploitable gaps.

---

## CRITICAL

### C-1: No frame size limit on content protocol — OOM crash
**Location:** `valence-network/src/transport.rs:102-112` (`decode_content_frame`)  
**Description:** The length-prefixed frame decoder reads a `u32` length from the wire and trusts it. An attacker can send `[0xFF, 0xFF, 0xFF, 0xFF]` as the length prefix (4 GiB), causing the caller to attempt a 4 GiB allocation when buffering the frame, crashing the node via OOM.  
**Exploit:** Connect to the `/valence/content/1.0.0` stream protocol, send 4 bytes `FF FF FF FF`, node panics or is killed by OOM.  
**Fix:** Add `const MAX_CONTENT_FRAME_SIZE: usize = 16 * 1024 * 1024;` and reject frames where `len > MAX_CONTENT_FRAME_SIZE` before attempting to read/allocate.

### C-2: API server has no request size limit — OOM via HTTP
**Location:** `valence-node/src/api.rs:282-284` (`handle_connection`)  
**Description:** The HTTP handler reads into a fixed 8192-byte buffer, which limits the *initial read*. However, the `Content-Length` header is never checked, and there's no protection against slow-loris or chunked-encoding attacks. More critically, serde deserialization of the body has no size guard — a carefully crafted JSON body within 8192 bytes can contain deeply nested structures causing stack overflow or excessive allocations.  
**Exploit:** Send a POST with deeply nested JSON `{"a":{"a":{"a":...}}}` to `/propose`. Also, the fixed 8KB buffer means legitimate large requests are silently truncated, causing partial JSON parsing that could produce unexpected behavior.  
**Fix:** (1) Set a max body size and reject oversized requests. (2) Use `serde_json::from_str` with a depth limit or use `serde_json::StreamDeserializer` with bounds. (3) Read the full `Content-Length` worth of data, not just one 8KB read.

### C-3: Identity key file has no permissions enforcement
**Location:** `valence-node/src/state.rs:161-168` (`save_identity_seed`)  
**Description:** The 32-byte Ed25519 seed (the node's private key) is written to `identity.key` with default filesystem permissions (typically `0644` — world-readable). Any user on the system can read the private key and impersonate the node.  
**Exploit:** `cat ~/.valence-node/identity.key` from any user account on the machine.  
**Fix:** Set file permissions to `0600` immediately after creation:
```rust
#[cfg(unix)]
{
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
}
```

### C-4: No authentication on localhost API
**Location:** `valence-node/src/api.rs` (entire module)  
**Description:** The HTTP API binds to `127.0.0.1:9091` with zero authentication. Any process on the machine can submit proposals, cast votes, announce content, and trigger replication — all signed with the node's private key. On shared hosting or any multi-user system, this is full node compromise.  
**Exploit:** `curl -X POST http://127.0.0.1:9091/propose -d '{"title":"Malicious","body":"Takeover","tier":"constitutional"}'`  
**Fix:** Add at minimum a bearer token (generated at init, saved alongside identity.key with 0600 permissions). For defense in depth, also bind to a Unix domain socket instead of TCP.

---

## HIGH

### H-1: DID_LINK does not verify child key signature
**Location:** `valence-node/src/handler.rs:233-254` (`handle_did_link`)  
**Description:** The handler extracts `child_signature` from the payload but never verifies it. The spec (§1) requires the child key to co-sign the DID_LINK message to prove the child consents to linking. Without this check, any root key can claim any unlinked key as its child — identity theft.  
**Exploit:** Broadcast a DID_LINK with `child_key` set to a victim's key and a fake `child_signature`. The victim's key is now linked to the attacker's identity, and the attacker controls the victim's vote and reputation.  
**Fix:** In `handle_did_link`, verify that `child_signature` is a valid Ed25519 signature by `child_key` over the DID_LINK envelope's signing body (or a canonical binding message).

### H-2: KEY_ROTATE does not verify dual signatures
**Location:** `valence-node/src/handler.rs:256-271` (`handle_key_rotate`)  
**Description:** The handler accepts KEY_ROTATE messages and immediately updates the identity manager without verifying that both the old key AND new key signed the rotation. An attacker who compromises the old key can rotate to any new key without proving possession of the new key. More critically, the handler doesn't verify that `envelope.from` matches `old_key`.  
**Exploit:** Forge a KEY_ROTATE message claiming any `old_key` → attacker's `new_key`. Since only the envelope signature (from `envelope.from`) is verified, if `envelope.from` != `old_key`, the rotation is illegitimate but accepted.  
**Fix:** (1) Require `envelope.from == old_key`. (2) Verify a second signature from `new_key` in the payload. (3) Implement the grace period from §1 before finalizing rotation.

### H-3: Proposal WITHDRAW only checks `author_id`, not identity group
**Location:** `valence-node/src/handler.rs:168-178` (`handle_proposal_withdraw`)  
**Description:** The withdraw handler checks `tracker.author_id == envelope.from`, but per §6 any key in the same identity group should be able to withdraw. More critically, the check uses string equality on the signing key rather than resolving through the identity manager. If the author rotated their key, they can never withdraw their own proposals.  
**Exploit:** Author rotates key → can never withdraw proposals. Conversely, the spec says sibling keys should be able to withdraw, but they can't.  
**Fix:** Use `state.identity_manager.same_identity(&envelope.from, &tracker.author_id)` instead of direct string comparison.

### H-4: GossipSub messages from unauthenticated peers silently dropped but connections not closed
**Location:** `valence-network/src/swarm.rs:183-186` (`handle_gossipsub_message`)  
**Description:** Messages from unauthenticated peers are silently dropped, but the connection remains open. The auth handshake (§3: AUTH_CHALLENGE/AUTH_RESPONSE) is marked as `// TODO` and never implemented. This means **all peers are permanently unauthenticated** — no gossip messages are ever processed in the current code. The node is deaf to the network.  
**Exploit:** The node currently cannot participate in the network at all. When auth is implemented, the gap between connection establishment and authentication allows resource consumption from unauthenticated peers.  
**Fix:** Implement the AUTH_CHALLENGE/AUTH_RESPONSE handshake. Add a timeout (e.g., 30s) for peers to authenticate after connection, disconnecting those that don't.

### H-5: VDF proof not verified during peer authentication
**Location:** `valence-network/src/swarm.rs` and `gossip.rs` (`AuthResponse`)  
**Description:** The `AuthResponse` struct includes a `vdf_proof` field, but no code verifies it. The VDF is the primary sybil resistance mechanism (§9/§10). Without verification, any node can join the network instantly without performing the computational work, enabling trivial sybil attacks.  
**Exploit:** Connect with `vdf_proof: {}` (empty JSON object). No verification occurs. Spin up thousands of nodes.  
**Fix:** After receiving `AuthResponse`, call `vdf::verify()` on the proof, checking that `input_data` matches the peer's public key.

### H-6: `PeerAnnounce` storage capacity claims are never validated
**Location:** `valence-network/src/gossip.rs:50-61` (`PeerAnnounce`, `StorageCapacity`)  
**Description:** Peers self-report their storage capacity in `PeerAnnounce` messages. These claims are never verified. A malicious peer can claim 1 PiB of available storage, attracting shard assignments, then fail to serve data.  
**Exploit:** Announce `available_bytes: 1_000_000_000_000_000`. Get assigned shards for all content. Never store them. Content becomes unrecoverable.  
**Fix:** (1) Don't trust announced capacity for shard assignment — require successful storage challenge history. (2) Track `SHARD_RECEIVED` confirmation rates per provider. (3) Apply `ACCEPT_ABANDON_PENALTY` for providers who accept then fail.

### H-7: No rate limit on incoming connections / peer acceptance
**Location:** `valence-network/src/swarm.rs:197-215` (connection handling)  
**Description:** There's no limit on how many connections the node accepts. The spec defines `MAX_NEW_PEERS_PER_HOUR: 5` but this is never enforced. An attacker can open thousands of TCP connections, exhausting file descriptors and memory.  
**Exploit:** Open 10,000 TCP connections to the node's listen port. Node runs out of FDs and becomes unresponsive.  
**Fix:** (1) Configure libp2p's `ConnectionLimits` behaviour. (2) Enforce `MAX_NEW_PEERS_PER_HOUR`. (3) Set `with_idle_connection_timeout` to a shorter duration for unauthenticated peers.

### H-8: State deserialization trusts on-disk JSON without validation
**Location:** `valence-node/src/state.rs:140-152` (`load`)  
**Description:** `serde_json::from_str` deserializes state from disk without any integrity check. A corrupted or maliciously modified `state.json` could inject arbitrary identity relationships, fake withdrawals, or other state corruption. The atomic save uses `rename` which is good, but there's no checksum or MAC to detect tampering.  
**Exploit:** Modify `state.json` to add fake identity links, then restart the node. The node now believes crafted identity relationships.  
**Fix:** (1) Add a HMAC (keyed by the identity seed) over the snapshot contents. (2) Verify on load. (3) Fall back to backup if primary fails validation.

---

## MEDIUM

### M-1: DedupCache uses O(n) eviction
**Location:** `valence-network/src/transport.rs:196-197`  
**Description:** `self.entries.remove(0)` on a `Vec` is O(n). With `DEDUP_CACHE_SIZE = 100,000`, each eviction shifts up to 100K elements. Under high message throughput, this becomes a CPU DoS vector.  
**Fix:** Use `VecDeque` instead of `Vec` for O(1) front removal, or use an LRU cache crate.

### M-2: Content hash path traversal in API
**Location:** `valence-node/src/api.rs:311-315` (`/content/:hash` route)  
**Description:** The content hash is extracted from the URL path via string slicing (`&p["/content/".len()..]`). While currently only used as a HashMap key, if content serving is added later, a hash like `../../etc/passwd` could enable path traversal. The hash is not validated as hex.  
**Fix:** Validate that the hash is a 64-character hex string: `if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) { return 404; }`

### M-3: Timestamp tolerance allows 5-minute replay window
**Location:** `valence-crypto/src/signing.rs:52` (`TIMESTAMP_TOLERANCE_MS = 300,000`)  
**Description:** Messages are accepted if their timestamp is within ±5 minutes of local time. Combined with the dedup cache, this is mostly safe, but if an attacker can evict a message ID from the dedup cache (by flooding 100,000 unique messages), they can replay the original message within the 5-minute window.  
**Exploit:** Send 100,001 unique messages to flush the dedup cache, then replay a previously-seen message that's still within the 5-minute tolerance.  
**Fix:** (1) Increase dedup cache size or add time-based partitioning. (2) Persist message IDs for the tolerance window. (3) Consider dedup cache per-sender to prevent cross-sender eviction.

### M-4: FixedPoint division by zero returns ZERO silently
**Location:** `valence-core/src/types.rs:51-55` (`div`)  
**Description:** `FixedPoint::div` returns `ZERO` when dividing by zero instead of returning an error or panicking. This could mask bugs where division by zero indicates an unexpected state (e.g., no voters, no shards). In reputation calculations, silently returning 0 could zero out a node's reputation.  
**Fix:** Return `Result<FixedPoint, ArithmeticError>` or at minimum log a warning. Review all call sites to ensure zero-division is handled explicitly.

### M-5: No node privilege dropping
**Location:** `valence-node/src/main.rs` (entire `cmd_run`)  
**Description:** The node daemon never drops privileges after binding to ports. If started as root (common for privileged ports), it continues running as root, increasing the blast radius of any exploit.  
**Fix:** After binding sockets, drop to a non-root user via `nix::unistd::setuid()` / `setgid()`.

### M-6: Sync protocol not implemented — no catch-up mechanism
**Location:** `valence-network/src/swarm.rs:253` (`SyncRequest` handler)  
**Description:** `TransportCommand::SyncRequest` logs a warning and does nothing. A node that goes offline briefly cannot catch up on missed messages. This means network partitions cause permanent state divergence in practice.  
**Impact:** Not a direct exploit, but severely impacts availability and correctness for a public node.

### M-7: `restore_from_snapshot` calls `request_withdraw` with timestamp 0
**Location:** `valence-node/src/state.rs:186-190`  
**Description:** When restoring withdrawals from a snapshot, `request_withdraw` is called with `timestamp = 0`. Since `effective_after - 0 >= CONTENT_WITHDRAW_DELAY_MS` is likely true for any real `effective_after`, this bypasses the 24h minimum delay validation. But if `effective_after` is small, it would incorrectly reject the restoration.  
**Fix:** Store the original request timestamp in `WithdrawalSnapshot` and use it during restoration.

### M-8: Snapshot only persists identity groups with children
**Location:** `valence-node/src/state.rs:201-213` (`create_snapshot`)  
**Description:** `all_identity_groups()` only returns identities that have children. Solo root identities (the common case for new nodes) are not persisted. On restart, reputation data associated with solo identities is lost.  
**Fix:** Iterate all identities in the manager, not just those with children.

### M-9: No response size limit on API
**Location:** `valence-node/src/api.rs` (all handlers)  
**Description:** API responses have no size limit. A node tracking many proposals could return an unbounded `/status` response. More concerning, if content metadata grows large, `/content/:hash` responses could be huge.  
**Fix:** Add pagination to list endpoints. Set maximum response size.

---

## LOW

### L-1: VDF verify only checks first N segments sequentially
**Location:** `valence-crypto/src/vdf.rs:79-80`  
**Description:** `verify()` always checks the first `min_segments` segments rather than randomly sampling. An attacker could compute only the first few segments honestly and fake the rest. The comment says "for spot-check, select randomly" but the implementation doesn't.  
**Fix:** Use random segment selection: `let indices: Vec<usize> = (0..checkpoints.len()).choose_multiple(&mut rng, min_segments);`

### L-2: `scarcity_multiplier` can produce negative utilization
**Location:** `valence-protocol/src/content.rs:35`  
**Description:** When `total_available > total_allocated`, utilization becomes negative, which is clamped to 0. This is handled correctly, but the function semantics are confusing — `total_available` seems like it should be ≤ `total_allocated`, but there's no assertion.  
**Fix:** Add a debug assertion or document the expected relationship.

### L-3: Collusion detection memory grows unboundedly
**Location:** `valence-protocol/src/anti_gaming.rs:50-80`  
**Description:** `detect_vote_collusion` takes all votes ever cast and computes O(n²) pairwise correlations. With many nodes, this becomes both a memory and CPU concern.  
**Fix:** Window the analysis to recent voting cycles. Implement incremental correlation tracking.

### L-4: `PeerTable::random_peer` is not random
**Location:** `valence-network/src/transport.rs:257`  
**Description:** `random_peer()` returns `self.peers.values().next()` — always the same peer. The comment acknowledges this. For anti-fragmentation (§4), this should be truly random.  
**Fix:** Use `rand::seq::IteratorRandom::choose`.

### L-5: `from_f64` truncation behavior on negative values
**Location:** `valence-core/src/types.rs:18`  
**Description:** `FixedPoint::from_f64` uses `as i64` cast which truncates toward zero for both positive and negative values. For negative values, this means `-0.67891` becomes `-6789` (truncating toward zero), not `-6790` (truncating toward negative infinity). The spec says "truncate" but doesn't specify direction for negative values.  
**Fix:** Document the truncation direction. If floor is intended, use `.floor()` before casting.

### L-6: Atomic save is not truly atomic on all filesystems
**Location:** `valence-node/src/state.rs:130-137`  
**Description:** The save uses write-to-temp + `rename`, which is atomic on most POSIX filesystems. However, without `fsync` on both the file and its directory, the rename may not be durable on crash. On power loss, the file could be zero-length.  
**Fix:** Call `file.sync_all()` before rename, and `File::open(dir).sync_all()` after rename.

### L-7: Signal handling doesn't use all POSIX signals
**Location:** `valence-node/src/main.rs:130`  
**Description:** Only `ctrl_c` (SIGINT) triggers graceful shutdown. SIGTERM (the standard daemon stop signal) is not handled. On `systemd` stop or Docker stop, the node won't save its final checkpoint.  
**Fix:** Also handle SIGTERM via `tokio::signal::unix::signal(SignalKind::terminate())`.

---

## INFO

### I-1: Ed25519 implementation uses constant-time operations (GOOD)
**Location:** `valence-crypto/src/identity.rs`  
**Description:** The `ed25519-dalek` crate provides constant-time signature verification, mitigating timing side-channels. OsRng is used for key generation, which is cryptographically secure. No issues found.

### I-2: SHA-256 used for content addressing and VDF (ACCEPTABLE)
**Location:** `valence-core/src/canonical.rs`, `valence-crypto/src/vdf.rs`  
**Description:** SHA-256 is collision-resistant for all practical purposes. The iterated-SHA-256 VDF is simple but weaker than algebraic VDFs (e.g., Wesolowski). Acceptable for v0 but should be upgraded before high-value governance decisions are made.

### I-3: No TLS on localhost API (ACCEPTABLE for localhost)
**Location:** `valence-node/src/api.rs`  
**Description:** The API uses plaintext HTTP. Since it binds to `127.0.0.1`, this is acceptable — localhost traffic isn't routable. However, if someone changes the bind address to `0.0.0.0`, credentials would be exposed. Add a guard preventing non-localhost binding without TLS.

### I-4: Canonicalization follows RFC 8785 correctly (GOOD)
**Location:** `valence-core/src/canonical.rs`  
**Description:** JCS canonicalization is implemented correctly with sorted keys, no whitespace, null preservation, and recursive application. Float handling has a fallback path but the protocol avoids floats. Conformance tests pass.

### I-5: FixedPoint arithmetic uses i128 intermediates (GOOD)
**Location:** `valence-core/src/types.rs:40-55`  
**Description:** Multiplication and division use `i128` intermediates, preventing overflow in the `i64 × i64` products that fixed-point multiplication requires. Saturation is used for addition/subtraction. No integer overflow vulnerabilities found.

---

## Recommendations — Priority Order

1. **Implement auth handshake** (H-4, H-5) — without this, the node literally cannot function
2. **Fix identity key permissions** (C-3) — trivial fix, critical impact
3. **Add API authentication** (C-4) — trivial fix, critical impact
4. **Add frame size limits** (C-1) — trivial fix, prevents instant crash
5. **Verify DID_LINK child signatures** (H-1) — identity theft vector
6. **Verify KEY_ROTATE dual signatures** (H-2) — identity theft vector
7. **Rate limit incoming connections** (H-7) — DoS vector
8. **Fix API request handling** (C-2) — DoS vector
9. **Add state file integrity checks** (H-8) — persistence tampering
10. **Fix DedupCache performance** (M-1) — performance DoS

---

*This audit covers the source code as of 2026-02-18. Dynamic analysis (fuzzing, integration testing with adversarial peers) is recommended before public deployment.*
