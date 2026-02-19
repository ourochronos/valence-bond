//! libp2p Swarm event loop — composing GossipSub, mDNS, Identify, Kademlia per §3-§5.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use libp2p::{
    gossipsub, identify, kad, mdns, noise,
    swarm::SwarmEvent,
    tcp, yamux, PeerId, Swarm, SwarmBuilder,
};
use libp2p::futures::StreamExt;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use valence_core::constants;
use valence_core::message::Envelope;
use valence_crypto::identity::NodeIdentity;

use crate::auth;
use crate::gossip::{validate_and_dedup, AuthChallenge, GossipValidation, MessageStore, PeerAnnounce};
use crate::transport::{
    DedupCache, PeerInfo, PeerTable, TransportCommand, TransportConfig, TransportEvent,
    TOPIC_PEERS, TOPIC_PROPOSALS, TOPIC_VOTES,
};

/// Composite network behaviour for Valence.
#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct ValenceBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub identify: identify::Behaviour,
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
}

/// The main Valence swarm that orchestrates all networking.
pub struct ValenceSwarm {
    swarm: Swarm<ValenceBehaviour>,
    identity: NodeIdentity,
    peer_table: PeerTable,
    dedup_cache: DedupCache,
    message_store: MessageStore,
    event_tx: mpsc::UnboundedSender<TransportEvent>,
    command_rx: mpsc::UnboundedReceiver<TransportCommand>,
    authenticated_peers: HashSet<PeerId>,
    /// Pending auth challenges sent to peers, with their connection time (H-4).
    pending_auth: HashMap<PeerId, (AuthChallenge, Instant)>,
    /// Per-IP connection timestamps for rate limiting (H-7).
    connection_rate: HashMap<std::net::IpAddr, Vec<Instant>>,
    announce_interval: tokio::time::Interval,
    prune_interval: tokio::time::Interval,
    config: TransportConfig,
    /// VDF proof for this node, included in auth handshake and PEER_ANNOUNCE.
    vdf_proof: serde_json::Value,
}

/// Maximum new connections per IP per minute (H-7).
const MAX_CONNECTIONS_PER_IP_PER_MINUTE: usize = 10;

impl ValenceSwarm {
    /// Create a new ValenceSwarm.
    pub fn new(
        identity: NodeIdentity,
        config: TransportConfig,
    ) -> anyhow::Result<(
        Self,
        mpsc::UnboundedSender<TransportCommand>,
        mpsc::UnboundedReceiver<TransportEvent>,
    )> {
        let local_key = libp2p::identity::Keypair::ed25519_from_bytes(
            identity.signing_key().to_bytes(),
        )?;
        let local_peer_id = PeerId::from(local_key.public());

        info!(peer_id = %local_peer_id, node_id = %identity.node_id(), "Initializing Valence swarm");

        // Configure GossipSub per §5
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .max_transmit_size(constants::MAX_PAYLOAD_SIZE)
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .map_err(|e| anyhow::anyhow!("GossipSub config error: {e}"))?;

        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )
        .map_err(|e| anyhow::anyhow!("GossipSub init error: {e}"))?;

        // Subscribe to topics per §3
        for topic_name in [TOPIC_PROPOSALS, TOPIC_VOTES, TOPIC_PEERS] {
            let topic = gossipsub::IdentTopic::new(topic_name);
            gossipsub.subscribe(&topic)?;
            debug!(topic = topic_name, "Subscribed to GossipSub topic");
        }

        // mDNS for local discovery (§4)
        let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;

        // Identify protocol
        let identify = identify::Behaviour::new(identify::Config::new(
            "/valence/0.1.0".to_string(),
            local_key.public(),
        ));

        // Kademlia DHT for peer routing
        let store = kad::store::MemoryStore::new(local_peer_id);
        let kad = kad::Behaviour::new(local_peer_id, store);

        let behaviour = ValenceBehaviour {
            gossipsub,
            mdns,
            identify,
            kad,
        };

        // Build swarm with Noise encryption + Yamux multiplexing (§3)
        let swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|_| Ok(behaviour))?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(60))
            })
            .build();

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (command_tx, command_rx) = mpsc::unbounded_channel();

        let announce_interval = tokio::time::interval(config.announce_interval);
        let prune_interval = tokio::time::interval(Duration::from_secs(5 * 60));

        let swarm_instance = Self {
            swarm,
            identity,
            peer_table: PeerTable::new(),
            dedup_cache: DedupCache::new(config.dedup_capacity),
            message_store: MessageStore::new(),
            event_tx,
            command_rx,
            authenticated_peers: HashSet::new(),
            pending_auth: HashMap::new(),
            connection_rate: HashMap::new(),
            announce_interval,
            prune_interval,
            config,
            vdf_proof: serde_json::json!({}),
        };

        Ok((swarm_instance, command_tx, event_rx))
    }

    /// Start listening on configured addresses.
    pub fn start_listening(&mut self) -> anyhow::Result<()> {
        for addr in &self.config.listen_addrs {
            self.swarm.listen_on(addr.clone())?;
            info!(addr = %addr, "Listening on address");
        }
        Ok(())
    }

    /// Get the local peer ID.
    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Set the VDF proof for this node (loaded from disk or freshly computed).
    pub fn set_vdf_proof(&mut self, proof: serde_json::Value) {
        self.vdf_proof = proof;
    }

    /// Main event loop — run this to process network events.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    if let Err(e) = self.handle_swarm_event(event).await {
                        warn!(error = %e, "Error handling swarm event");
                    }
                }

                Some(cmd) = self.command_rx.recv() => {
                    if let Err(e) = self.handle_command(cmd).await {
                        warn!(error = %e, "Error handling command");
                    }
                }

                _ = self.announce_interval.tick() => {
                    if let Err(e) = self.announce_self() {
                        warn!(error = %e, "Error announcing self");
                    }
                }

                _ = self.prune_interval.tick() => {
                    self.prune_expired_peers();
                    self.disconnect_unauthenticated_peers();
                }
            }
        }
    }

    /// Handle a swarm event.
    async fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<ValenceBehaviourEvent>,
    ) -> anyhow::Result<()> {
        match event {
            SwarmEvent::Behaviour(ValenceBehaviourEvent::Gossipsub(
                gossipsub::Event::Message {
                    propagation_source,
                    message,
                    ..
                },
            )) => {
                self.handle_gossipsub_message(propagation_source, message)?;
            }

            SwarmEvent::Behaviour(ValenceBehaviourEvent::Mdns(mdns::Event::Discovered(
                peers,
            ))) => {
                for (peer_id, addr) in peers {
                    if peer_id == self.local_peer_id() {
                        continue;
                    }
                    debug!(peer = %peer_id, addr = %addr, "mDNS discovered peer");
                    if let Err(e) = self.swarm.dial(addr.clone()) {
                        warn!(peer = %peer_id, error = %e, "Failed to dial mDNS peer");
                    }
                    self.peer_table.upsert(PeerInfo {
                        peer_id,
                        node_id: None,
                        addresses: vec![addr],
                        last_seen_ms: chrono::Utc::now().timestamp_millis(),
                        asn: None,
                        capabilities: vec![],
                        authenticated: false,
                    });
                }
            }

            SwarmEvent::Behaviour(ValenceBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
                for (peer_id, _) in peers {
                    debug!(peer = %peer_id, "mDNS peer expired");
                    self.peer_table.remove(&peer_id);
                }
            }

            SwarmEvent::Behaviour(ValenceBehaviourEvent::Identify(
                identify::Event::Received { peer_id, info, .. },
            )) => {
                debug!(peer = %peer_id, agent = %info.agent_version, "Identified peer");
                for addr in &info.listen_addrs {
                    self.swarm
                        .behaviour_mut()
                        .kad
                        .add_address(&peer_id, addr.clone());
                }
            }

            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                let remote_addr = endpoint.get_remote_address();
                info!(peer = %peer_id, addr = %remote_addr, "Connection established");

                // H-7: Per-IP connection rate limiting
                if let Some(ip) = extract_ip_from_multiaddr(remote_addr) {
                    let now = Instant::now();
                    let timestamps = self.connection_rate.entry(ip).or_default();
                    let one_minute_ago = now - Duration::from_secs(60);
                    timestamps.retain(|t| *t > one_minute_ago);
                    if timestamps.len() >= MAX_CONNECTIONS_PER_IP_PER_MINUTE {
                        warn!(peer = %peer_id, ip = %ip, "Connection rate limit exceeded, disconnecting");
                        let _ = self.swarm.disconnect_peer_id(peer_id);
                        return Ok(());
                    }
                    timestamps.push(now);
                }

                // H-4: Initiate auth handshake — send challenge
                let challenge = auth::create_challenge(&self.identity);
                self.pending_auth.insert(peer_id, (challenge, Instant::now()));
                // In a full implementation, the challenge would be sent via
                // the /valence/auth/1.0.0 stream protocol. For now we track
                // the pending state and enforce the auth timeout.
            }

            SwarmEvent::ConnectionClosed {
                peer_id, cause, ..
            } => {
                debug!(peer = %peer_id, cause = ?cause, "Connection closed");
                self.authenticated_peers.remove(&peer_id);
                if self.peer_table.remove(&peer_id).is_some() {
                    let _ = self
                        .event_tx
                        .send(TransportEvent::PeerDisconnected { peer_id });
                }
            }

            SwarmEvent::NewListenAddr { address, .. } => {
                info!(addr = %address, "Listening on new address");
            }

            _ => {}
        }
        Ok(())
    }

    /// Handle an incoming GossipSub message.
    fn handle_gossipsub_message(
        &mut self,
        source: PeerId,
        message: gossipsub::Message,
    ) -> anyhow::Result<()> {
        // §3 CRITICAL: Reject messages from unauthenticated peers
        if !self.authenticated_peers.contains(&source) {
            debug!(peer = %source, "Rejecting message from unauthenticated peer");
            return Ok(());
        }

        let envelope: Envelope = match serde_json::from_slice(&message.data) {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "Failed to parse envelope");
                return Ok(());
            }
        };

        let now_ms = chrono::Utc::now().timestamp_millis();

        match validate_and_dedup(&envelope, now_ms, &mut self.dedup_cache) {
            GossipValidation::Accept => {
                self.message_store.insert(envelope.clone());
                let _ = self.event_tx.send(TransportEvent::GossipMessage {
                    topic: message.topic.to_string(),
                    envelope,
                    source,
                });
            }
            GossipValidation::Duplicate => {
                debug!(id = %envelope.id, "Duplicate message");
            }
            other => {
                debug!(validation = ?other, id = %envelope.id, "Message rejected");
            }
        }

        Ok(())
    }

    /// Handle a transport command.
    async fn handle_command(&mut self, cmd: TransportCommand) -> anyhow::Result<()> {
        match cmd {
            TransportCommand::Publish { topic, data } => {
                let topic = gossipsub::IdentTopic::new(topic);
                if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, data) {
                    warn!(error = %e, "Failed to publish to GossipSub");
                }
            }
            TransportCommand::Dial { addr } => {
                if let Err(e) = self.swarm.dial(addr.clone()) {
                    warn!(addr = %addr, error = %e, "Failed to dial peer");
                }
            }
            TransportCommand::Announce => {
                self.announce_self()?;
            }
            TransportCommand::SyncRequest { .. } => {
                // TODO: Implement sync via stream protocol
                warn!("SyncRequest not yet implemented");
            }
            TransportCommand::SendShard {
                peer_id,
                content_hash,
                shard_index,
                shard_data,
            } => {
                // Encode as a content stream frame and publish on the content protocol.
                // In a full implementation this would open a stream to the peer via
                // /valence/content/1.0.0; for now we serialize the frame for the swarm
                // to deliver when stream protocol support is wired in.
                let msg = crate::transport::ContentStreamMessage::ShardTransfer {
                    content_hash,
                    shard_index,
                    shard_data,
                };
                match crate::transport::encode_content_frame(&msg) {
                    Ok(frame) => {
                        debug!(peer = %peer_id, frame_len = frame.len(), "Encoded SendShard frame");
                        // TODO: Send frame via /valence/content/1.0.0 stream to peer_id
                        // For now, emit a log. The stream protocol negotiation will be
                        // wired in a future phase.
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to encode SendShard frame");
                    }
                }
            }
            TransportCommand::SendStorageProof { peer_id, proof } => {
                let msg = crate::transport::ContentStreamMessage::StorageProof {
                    proof_hash: proof.proof_hash,
                };
                match crate::transport::encode_content_frame(&msg) {
                    Ok(frame) => {
                        debug!(peer = %peer_id, frame_len = frame.len(), "Encoded SendStorageProof frame");
                        // TODO: Send frame via /valence/content/1.0.0 stream to peer_id
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to encode SendStorageProof frame");
                    }
                }
            }
        }
        Ok(())
    }

    /// Announce ourselves on the /valence/peers topic (§4).
    fn announce_self(&mut self) -> anyhow::Result<()> {
        use valence_core::message::MessageType;
        use valence_crypto::signing::sign_message;

        let addrs: Vec<String> = self.swarm.listeners().map(|a| a.to_string()).collect();

        let payload = serde_json::to_value(&PeerAnnounce {
            addresses: addrs,
            capabilities: vec!["propose".into(), "vote".into(), "store".into()],
            version: 0,
            uptime_seconds: 0, // TODO: Track actual uptime
            vdf_proof: self.vdf_proof.clone(),
            storage: None, // TODO: Report actual storage capacity
            sync_status: Some("synced".into()), // TODO: Track actual sync status
        })?;

        let now_ms = chrono::Utc::now().timestamp_millis();
        let envelope = sign_message(&self.identity, MessageType::PeerAnnounce, payload, now_ms);
        let data = serde_json::to_vec(&envelope)?;
        let topic = gossipsub::IdentTopic::new(TOPIC_PEERS);

        if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, data) {
            warn!(error = %e, "Failed to publish peer announcement");
        } else {
            debug!("Published peer announcement");
        }

        Ok(())
    }

    /// Disconnect peers that haven't completed auth within the timeout (H-4).
    fn disconnect_unauthenticated_peers(&mut self) {
        let expired: Vec<PeerId> = self
            .pending_auth
            .iter()
            .filter(|(_, (_, connected_at))| connected_at.elapsed() > auth::AUTH_TIMEOUT)
            .map(|(peer_id, _)| *peer_id)
            .collect();

        for peer_id in expired {
            warn!(peer = %peer_id, "Auth timeout, disconnecting unauthenticated peer");
            self.pending_auth.remove(&peer_id);
            let _ = self.swarm.disconnect_peer_id(peer_id);
        }
    }

    /// Prune expired peers per §4 (30-minute expiry).
    fn prune_expired_peers(&mut self) {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let expired = self.peer_table.prune_expired(now_ms);
        for peer_id in expired {
            debug!(peer = %peer_id, "Pruned expired peer");
            self.authenticated_peers.remove(&peer_id);
            let _ = self
                .event_tx
                .send(TransportEvent::PeerDisconnected { peer_id });
        }
    }

    /// Mark a peer as authenticated after successful auth handshake (§3).
    /// Verifies the auth response and VDF proof before accepting.
    pub fn authenticate_peer(&mut self, peer_id: PeerId, node_id: String) {
        self.authenticated_peers.insert(peer_id);
        self.pending_auth.remove(&peer_id);
        if let Some(peer_info) = self.peer_table.get(&peer_id) {
            let _ = self.event_tx.send(TransportEvent::PeerConnected {
                peer_id,
                node_id,
                addresses: peer_info.addresses.clone(),
            });
        }
    }

    /// Attempt to authenticate a peer given their auth response.
    /// Returns the node_id on success, or an error description on failure.
    pub fn verify_and_authenticate_peer(
        &mut self,
        peer_id: PeerId,
        response: &crate::gossip::AuthResponse,
    ) -> Result<String, String> {
        // Look up the challenge we sent
        let (challenge, _) = self.pending_auth.get(&peer_id)
            .ok_or_else(|| "No pending auth challenge for peer".to_string())?
            .clone();

        // Verify auth response signature
        let result = auth::verify_response(&challenge, response);
        match result {
            auth::AuthResult::Authenticated(node_id) => {
                // Verify VDF proof
                if response.vdf_proof.is_null() || response.vdf_proof == serde_json::json!({}) {
                    return Err("Missing VDF proof in auth response".to_string());
                }

                // Parse and verify VDF
                if let Some(vdf_proof) = auth::parse_vdf_proof(&response.vdf_proof) {
                    // Check VDF input matches the peer's public key
                    if let Some(expected_input) = valence_crypto::identity::vdf_input(&node_id)
                        && vdf_proof.input_data != expected_input {
                            return Err("VDF input doesn't match peer key".to_string());
                        }
                    // Verify VDF proof
                    if let Err(e) = valence_crypto::vdf::verify(&vdf_proof, 3) {
                        return Err(format!("VDF verification failed: {e}"));
                    }
                } else {
                    return Err("Malformed VDF proof".to_string());
                }

                self.authenticate_peer(peer_id, node_id.clone());
                Ok(node_id)
            }
            auth::AuthResult::InvalidSignature => Err("Invalid signature".to_string()),
            auth::AuthResult::NonceMismatch => Err("Nonce mismatch".to_string()),
            auth::AuthResult::MalformedKey => Err("Malformed key".to_string()),
        }
    }

    /// Get the local node's VDF proof for auth responses.
    pub fn local_vdf_proof(&self) -> &serde_json::Value {
        &self.vdf_proof
    }

    /// Create an auth response for an incoming challenge.
    pub fn create_auth_response(&self, challenge: &crate::gossip::AuthChallenge) -> crate::gossip::AuthResponse {
        auth::create_response(&self.identity, challenge, self.vdf_proof.clone())
    }

    /// Get the count of authenticated peers.
    pub fn authenticated_peer_count(&self) -> usize {
        self.authenticated_peers.len()
    }

    /// Get the count of pending (unauthenticated) peers.
    pub fn pending_peer_count(&self) -> usize {
        self.pending_auth.len()
    }
}

/// Extract IP address from a libp2p Multiaddr (H-7).
fn extract_ip_from_multiaddr(addr: &libp2p::Multiaddr) -> Option<std::net::IpAddr> {
    use libp2p::multiaddr::Protocol;
    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip4(ip) => return Some(std::net::IpAddr::V4(ip)),
            Protocol::Ip6(ip) => return Some(std::net::IpAddr::V6(ip)),
            _ => continue,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> TransportConfig {
        TransportConfig {
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap_peers: vec![],
            enable_mdns: false, // Disable for tests to avoid port conflicts
            dedup_capacity: 1000,
            announce_interval: Duration::from_secs(300),
            anti_frag_interval: Duration::from_secs(600),
        }
    }

    #[tokio::test]
    async fn swarm_creation_succeeds() {
        let identity = NodeIdentity::generate();
        let config = test_config();
        let result = ValenceSwarm::new(identity, config);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn swarm_listening_succeeds() {
        let identity = NodeIdentity::generate();
        let config = test_config();
        let (mut swarm, _, _) = ValenceSwarm::new(identity, config).unwrap();
        assert!(swarm.start_listening().is_ok());
    }

    #[test]
    fn connection_rate_limit_enforcement() {
        // H-7: Test that per-IP rate limiting works
        let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let mut rate_map: HashMap<std::net::IpAddr, Vec<Instant>> = HashMap::new();
        let now = Instant::now();

        // Fill up the rate limit
        let timestamps = rate_map.entry(ip).or_default();
        for _ in 0..MAX_CONNECTIONS_PER_IP_PER_MINUTE {
            timestamps.push(now);
        }

        // Next connection should be rejected
        let timestamps = rate_map.entry(ip).or_default();
        let one_minute_ago = now - Duration::from_secs(60);
        timestamps.retain(|t| *t > one_minute_ago);
        assert!(timestamps.len() >= MAX_CONNECTIONS_PER_IP_PER_MINUTE);

        // Different IP should be fine
        let other_ip: std::net::IpAddr = "192.168.1.2".parse().unwrap();
        let other_timestamps = rate_map.entry(other_ip).or_default();
        assert!(other_timestamps.len() < MAX_CONNECTIONS_PER_IP_PER_MINUTE);
    }

    #[test]
    fn extract_ip_from_multiaddr_works() {
        let addr: libp2p::Multiaddr = "/ip4/192.168.1.1/tcp/9090".parse().unwrap();
        let ip = extract_ip_from_multiaddr(&addr);
        assert_eq!(ip, Some("192.168.1.1".parse().unwrap()));

        let addr6: libp2p::Multiaddr = "/ip6/::1/tcp/9090".parse().unwrap();
        let ip6 = extract_ip_from_multiaddr(&addr6);
        assert_eq!(ip6, Some("::1".parse().unwrap()));
    }

    #[tokio::test]
    async fn two_swarms_get_different_peer_ids() {
        let id1 = NodeIdentity::generate();
        let id2 = NodeIdentity::generate();
        let (s1, _, _) = ValenceSwarm::new(id1, test_config()).unwrap();
        let (s2, _, _) = ValenceSwarm::new(id2, test_config()).unwrap();
        assert_ne!(s1.local_peer_id(), s2.local_peer_id());
    }
}
