//! libp2p Swarm event loop — composing GossipSub, mDNS, Identify, Kademlia per §3-§5.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use libp2p::{
    gossipsub, identify, kad, mdns, noise, request_response,
    swarm::SwarmEvent,
    tcp, yamux, PeerId, Swarm, SwarmBuilder, StreamProtocol,
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

/// Auth protocol request/response types for `/valence/auth/1.0.0`.
pub type AuthBehaviour = request_response::cbor::Behaviour<
    crate::gossip::AuthChallenge,
    crate::gossip::AuthResponse,
>;

/// Content protocol request/response types for `/valence/content/1.0.0`.
pub type ContentBehaviour = request_response::cbor::Behaviour<
    crate::transport::ContentStreamMessage,
    ContentAck,
>;

/// Simple acknowledgment for content protocol messages.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContentAck {
    pub success: bool,
}

/// Composite network behaviour for Valence.
#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct ValenceBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub identify: identify::Behaviour,
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    pub auth: AuthBehaviour,
    pub content: ContentBehaviour,
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
    /// Start time for uptime tracking.
    start_time: Instant,
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

        // Auth handshake via request-response protocol (§3, F-2)
        let auth = request_response::cbor::Behaviour::new(
            [(StreamProtocol::new("/valence/auth/1.0.0"), request_response::ProtocolSupport::Full)],
            request_response::Config::default()
                .with_request_timeout(auth::AUTH_TIMEOUT),
        );

        // Content stream protocol for shard transfer and storage proofs (§6)
        let content = request_response::cbor::Behaviour::new(
            [(StreamProtocol::new("/valence/content/1.0.0"), request_response::ProtocolSupport::Full)],
            request_response::Config::default(),
        );

        let behaviour = ValenceBehaviour {
            gossipsub,
            mdns,
            identify,
            kad,
            auth,
            content,
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
            start_time: Instant::now(),
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

            // F-2: Handle auth request-response protocol events
            SwarmEvent::Behaviour(ValenceBehaviourEvent::Auth(event)) => {
                self.handle_auth_event(event);
            }

            // Handle content stream protocol events (§6)
            SwarmEvent::Behaviour(ValenceBehaviourEvent::Content(event)) => {
                self.handle_content_event(event);
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

                // H-4 / F-2: Initiate auth handshake — send challenge via request-response protocol
                let challenge = auth::create_challenge(&self.identity);
                self.pending_auth.insert(peer_id, (challenge.clone(), Instant::now()));
                self.swarm.behaviour_mut().auth.send_request(&peer_id, challenge);
                debug!(peer = %peer_id, "Sent AUTH_CHALLENGE via /valence/auth/1.0.0");
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

    /// Handle auth request-response protocol events (F-2).
    fn handle_auth_event(&mut self, event: request_response::Event<crate::gossip::AuthChallenge, crate::gossip::AuthResponse>) {
        match event {
            // We received an auth challenge from a peer — respond with our signed response
            request_response::Event::Message {
                peer,
                message: request_response::Message::Request { request, channel, .. },
                ..
            } => {
                debug!(peer = %peer, "Received AUTH_CHALLENGE, sending response");
                let response = self.create_auth_response(&request);
                let _ = self.swarm.behaviour_mut().auth.send_response(channel, response);
            }

            // We received an auth response to our challenge — verify it
            request_response::Event::Message {
                peer,
                message: request_response::Message::Response { response, .. },
                ..
            } => {
                match self.verify_and_authenticate_peer(peer, &response) {
                    Ok(node_id) => {
                        info!(peer = %peer, node_id = %node_id, "Peer authenticated via /valence/auth/1.0.0");
                    }
                    Err(e) => {
                        warn!(peer = %peer, error = %e, "Auth verification failed, disconnecting");
                        let _ = self.swarm.disconnect_peer_id(peer);
                    }
                }
            }

            request_response::Event::OutboundFailure { peer, error, .. } => {
                warn!(peer = %peer, error = %error, "Auth outbound failure, disconnecting");
                self.pending_auth.remove(&peer);
                let _ = self.swarm.disconnect_peer_id(peer);
            }

            request_response::Event::InboundFailure { peer, error, .. } => {
                warn!(peer = %peer, error = %error, "Auth inbound failure");
            }

            _ => {}
        }
    }

    /// Handle content stream protocol events (§6).
    fn handle_content_event(&mut self, event: request_response::Event<crate::transport::ContentStreamMessage, ContentAck>) {
        use crate::transport::ContentStreamMessage;

        match event {
            // Incoming content request
            request_response::Event::Message {
                peer,
                message: request_response::Message::Request { request, channel, .. },
                ..
            } => {
                debug!(peer = %peer, "Received content stream request");
                
                // Emit appropriate transport event based on message type
                match request {
                    ContentStreamMessage::ShardTransfer { content_hash, shard_index, shard_data } => {
                        let _ = self.event_tx.send(TransportEvent::ContentReceived {
                            peer_id: peer,
                            content_hash,
                            shard_index,
                            shard_data,
                        });
                    }
                    ContentStreamMessage::StorageChallenge { .. } => {
                        // TODO: Parse and emit StorageChallengeReceived event
                        debug!(peer = %peer, "Received storage challenge (not yet implemented)");
                    }
                    ContentStreamMessage::StorageProof { proof_hash } => {
                        let _ = self.event_tx.send(TransportEvent::StorageProofReceived {
                            peer_id: peer,
                            proof: crate::storage::StorageProof { proof_hash },
                        });
                    }
                    ContentStreamMessage::ContentRequest { content_hash, offset, length } => {
                        let _ = self.event_tx.send(TransportEvent::ContentRequested {
                            peer_id: peer,
                            content_hash,
                            offset,
                            length,
                        });
                    }
                    ContentStreamMessage::ContentResponse { .. } => {
                        debug!(peer = %peer, "Received content response");
                    }
                }

                // Send ack
                let ack = ContentAck { success: true };
                let _ = self.swarm.behaviour_mut().content.send_response(channel, ack);
            }

            // Response to our content request
            request_response::Event::Message {
                peer,
                message: request_response::Message::Response { response, .. },
                ..
            } => {
                if response.success {
                    debug!(peer = %peer, "Content stream request acknowledged");
                } else {
                    warn!(peer = %peer, "Content stream request failed");
                }
            }

            request_response::Event::OutboundFailure { peer, error, .. } => {
                warn!(peer = %peer, error = %error, "Content outbound failure");
            }

            request_response::Event::InboundFailure { peer, error, .. } => {
                warn!(peer = %peer, error = %error, "Content inbound failure");
            }

            _ => {}
        }
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
                let msg = crate::transport::ContentStreamMessage::ShardTransfer {
                    content_hash,
                    shard_index,
                    shard_data,
                };
                self.swarm.behaviour_mut().content.send_request(&peer_id, msg);
                debug!(peer = %peer_id, "Sent shard transfer via /valence/content/1.0.0");
            }
            TransportCommand::SendStorageProof { peer_id, proof } => {
                let msg = crate::transport::ContentStreamMessage::StorageProof {
                    proof_hash: proof.proof_hash,
                };
                self.swarm.behaviour_mut().content.send_request(&peer_id, msg);
                debug!(peer = %peer_id, "Sent storage proof via /valence/content/1.0.0");
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
            uptime_seconds: self.start_time.elapsed().as_secs(),
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

    // ── Auth handshake with VDF tests ──

    #[tokio::test]
    async fn auth_response_includes_vdf_proof() {
        let identity = NodeIdentity::generate();
        let config = test_config();
        let (mut swarm, _, _) = ValenceSwarm::new(identity.clone(), config).unwrap();

        // Set VDF proof
        let proof = valence_crypto::vdf::compute(&identity.public_key_bytes(), 10);
        let vdf_json = serde_json::json!({
            "output": hex::encode(&proof.output),
            "input_data": hex::encode(&proof.input_data),
            "difficulty": proof.difficulty,
            "computed_at": proof.computed_at,
            "checkpoints": proof.checkpoints.iter().map(|cp| serde_json::json!({
                "iteration": cp.iteration,
                "hash": hex::encode(&cp.hash),
            })).collect::<Vec<_>>(),
        });
        swarm.set_vdf_proof(vdf_json.clone());

        // Create a challenge and response
        let challenge = crate::gossip::AuthChallenge::new("test_initiator_key");
        let response = swarm.create_auth_response(&challenge);

        assert_eq!(response.vdf_proof, vdf_json);
        assert_eq!(response.public_key, identity.node_id());
    }

    #[tokio::test]
    async fn verify_and_authenticate_valid_peer() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();

        let config = test_config();
        let (mut alice_swarm, _, _) = ValenceSwarm::new(alice.clone(), config.clone()).unwrap();

        // Bob's VDF proof
        let bob_proof = valence_crypto::vdf::compute(&bob.public_key_bytes(), 10);
        let bob_vdf_json = serde_json::json!({
            "output": hex::encode(&bob_proof.output),
            "input_data": hex::encode(&bob_proof.input_data),
            "difficulty": bob_proof.difficulty,
            "computed_at": bob_proof.computed_at,
            "checkpoints": bob_proof.checkpoints.iter().map(|cp| serde_json::json!({
                "iteration": cp.iteration,
                "hash": hex::encode(&cp.hash),
            })).collect::<Vec<_>>(),
        });

        // Simulate: Alice sends challenge, Bob responds
        let challenge = auth::create_challenge(&alice);
        let bob_response = auth::create_response(&bob, &challenge, bob_vdf_json);

        // We need to insert a pending auth for a fake peer_id
        let bob_peer_id: PeerId = PeerId::random();
        alice_swarm.pending_auth.insert(bob_peer_id, (challenge, std::time::Instant::now()));

        let result = alice_swarm.verify_and_authenticate_peer(bob_peer_id, &bob_response);
        assert!(result.is_ok(), "Valid auth should succeed: {:?}", result);
        assert_eq!(result.unwrap(), bob.node_id());
        assert!(alice_swarm.authenticated_peers.contains(&bob_peer_id));
        assert!(!alice_swarm.pending_auth.contains_key(&bob_peer_id));
    }

    #[tokio::test]
    async fn verify_and_authenticate_rejects_missing_vdf() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();

        let config = test_config();
        let (mut alice_swarm, _, _) = ValenceSwarm::new(alice.clone(), config).unwrap();

        let challenge = auth::create_challenge(&alice);
        let bob_response = auth::create_response(&bob, &challenge, serde_json::json!({}));

        let bob_peer_id = PeerId::random();
        alice_swarm.pending_auth.insert(bob_peer_id, (challenge, std::time::Instant::now()));

        let result = alice_swarm.verify_and_authenticate_peer(bob_peer_id, &bob_response);
        assert!(result.is_err(), "Should reject missing VDF proof");
        assert!(!alice_swarm.authenticated_peers.contains(&bob_peer_id));
    }

    #[tokio::test]
    async fn verify_and_authenticate_rejects_wrong_key_vdf() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let charlie = NodeIdentity::generate();

        let config = test_config();
        let (mut alice_swarm, _, _) = ValenceSwarm::new(alice.clone(), config).unwrap();

        // VDF proof for charlie, not bob
        let wrong_proof = valence_crypto::vdf::compute(&charlie.public_key_bytes(), 10);
        let wrong_vdf_json = serde_json::json!({
            "output": hex::encode(&wrong_proof.output),
            "input_data": hex::encode(&wrong_proof.input_data),
            "difficulty": wrong_proof.difficulty,
            "computed_at": wrong_proof.computed_at,
            "checkpoints": wrong_proof.checkpoints.iter().map(|cp| serde_json::json!({
                "iteration": cp.iteration,
                "hash": hex::encode(&cp.hash),
            })).collect::<Vec<_>>(),
        });

        let challenge = auth::create_challenge(&alice);
        let bob_response = auth::create_response(&bob, &challenge, wrong_vdf_json);

        let bob_peer_id = PeerId::random();
        alice_swarm.pending_auth.insert(bob_peer_id, (challenge, std::time::Instant::now()));

        let result = alice_swarm.verify_and_authenticate_peer(bob_peer_id, &bob_response);
        assert!(result.is_err(), "Should reject VDF for wrong key");
        assert!(result.unwrap_err().contains("VDF input"));
    }

    #[tokio::test]
    async fn auth_handshake_full_flow_between_two_peers() {
        // F-2: Simulate the full auth flow: Alice challenges Bob, Bob responds, Alice verifies
        let alice_id = NodeIdentity::generate();
        let bob_id = NodeIdentity::generate();

        let (mut alice_swarm, _, _) = ValenceSwarm::new(alice_id.clone(), test_config()).unwrap();

        // Bob computes a valid VDF proof
        let bob_proof = valence_crypto::vdf::compute(&bob_id.public_key_bytes(), 10);
        let bob_vdf_json = serde_json::json!({
            "output": hex::encode(&bob_proof.output),
            "input_data": hex::encode(&bob_proof.input_data),
            "difficulty": bob_proof.difficulty,
            "computed_at": bob_proof.computed_at,
            "checkpoints": bob_proof.checkpoints.iter().map(|cp| serde_json::json!({
                "iteration": cp.iteration,
                "hash": hex::encode(&cp.hash),
            })).collect::<Vec<_>>(),
        });

        // Step 1: Alice creates a challenge (happens on ConnectionEstablished)
        let challenge = auth::create_challenge(&alice_id);
        let bob_peer_id = PeerId::random();
        alice_swarm.pending_auth.insert(bob_peer_id, (challenge.clone(), Instant::now()));

        // Step 2: Bob receives challenge and creates response (happens in handle_auth_event)
        let bob_response = auth::create_response(&bob_id, &challenge, bob_vdf_json);

        // Step 3: Alice verifies (happens in handle_auth_event on Response)
        let result = alice_swarm.verify_and_authenticate_peer(bob_peer_id, &bob_response);
        assert!(result.is_ok(), "Auth flow should succeed: {:?}", result);
        assert_eq!(result.unwrap(), bob_id.node_id());

        // Peer should now be authenticated and removed from pending
        assert!(alice_swarm.authenticated_peers.contains(&bob_peer_id));
        assert!(!alice_swarm.pending_auth.contains_key(&bob_peer_id));
        assert_eq!(alice_swarm.authenticated_peer_count(), 1);
        assert_eq!(alice_swarm.pending_peer_count(), 0);
    }

    #[tokio::test]
    async fn auth_timeout_disconnects_unauthenticated_peer() {
        // F-2: Peers that don't respond within AUTH_TIMEOUT are disconnected
        let alice_id = NodeIdentity::generate();
        let (mut alice_swarm, _, _) = ValenceSwarm::new(alice_id.clone(), test_config()).unwrap();

        let peer = PeerId::random();
        let challenge = auth::create_challenge(&alice_id);
        // Insert with a timestamp in the past (beyond AUTH_TIMEOUT)
        alice_swarm.pending_auth.insert(peer, (challenge, Instant::now() - auth::AUTH_TIMEOUT - Duration::from_secs(1)));

        // disconnect_unauthenticated_peers should remove this peer
        alice_swarm.disconnect_unauthenticated_peers();
        assert!(!alice_swarm.pending_auth.contains_key(&peer), "Timed-out peer should be removed from pending");
    }

    #[tokio::test]
    async fn pending_and_authenticated_peer_counts() {
        let identity = NodeIdentity::generate();
        let config = test_config();
        let (mut swarm, _, _) = ValenceSwarm::new(identity, config).unwrap();

        assert_eq!(swarm.authenticated_peer_count(), 0);
        assert_eq!(swarm.pending_peer_count(), 0);

        let peer = PeerId::random();
        let challenge = auth::create_challenge(&swarm.identity);
        swarm.pending_auth.insert(peer, (challenge, std::time::Instant::now()));
        assert_eq!(swarm.pending_peer_count(), 1);

        swarm.authenticate_peer(peer, "some_node_id".to_string());
        assert_eq!(swarm.authenticated_peer_count(), 1);
        assert_eq!(swarm.pending_peer_count(), 0);
    }
}
