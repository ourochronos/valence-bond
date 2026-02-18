//! libp2p Swarm event loop — composing GossipSub, mDNS, Identify, Kademlia per §3-§5.

use std::collections::HashSet;
use std::time::Duration;

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

use crate::gossip::{validate_and_dedup, GossipValidation, MessageStore, PeerAnnounce};
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
    announce_interval: tokio::time::Interval,
    prune_interval: tokio::time::Interval,
    config: TransportConfig,
}

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
            announce_interval,
            prune_interval,
            config,
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
                info!(peer = %peer_id, addr = %endpoint.get_remote_address(), "Connection established");
                // TODO: Initiate auth handshake (§3)
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
            vdf_proof: serde_json::json!({}), // TODO: Include actual VDF proof
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
    pub fn authenticate_peer(&mut self, peer_id: PeerId, node_id: String) {
        self.authenticated_peers.insert(peer_id);
        if let Some(peer_info) = self.peer_table.get(&peer_id) {
            let _ = self.event_tx.send(TransportEvent::PeerConnected {
                peer_id,
                node_id,
                addresses: peer_info.addresses.clone(),
            });
        }
    }
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

    #[tokio::test]
    async fn two_swarms_get_different_peer_ids() {
        let id1 = NodeIdentity::generate();
        let id2 = NodeIdentity::generate();
        let (s1, _, _) = ValenceSwarm::new(id1, test_config()).unwrap();
        let (s2, _, _) = ValenceSwarm::new(id2, test_config()).unwrap();
        assert_ne!(s1.local_peer_id(), s2.local_peer_id());
    }
}
