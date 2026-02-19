//! Valence Network v0 node — reference implementation.

mod api;

use valence_node::handler;
use valence_node::state;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::RwLock;
use tracing::info;

use valence_crypto::identity::NodeIdentity;
use valence_network::swarm::ValenceSwarm;
use valence_network::transport::TransportConfig;

use crate::api::{ApiConfig, ApiState};
use crate::state::{create_snapshot, restore_from_snapshot, NodeState, StatePersistence};

/// CLI arguments parsed via clap.
#[derive(Debug)]
enum Command {
    /// Initialize a new node identity.
    Init { data_dir: PathBuf },
    /// Run the node daemon.
    Run {
        data_dir: PathBuf,
        listen: String,
        bootstrap: Vec<String>,
        no_mdns: bool,
        api_port: u16,
    },
    /// Show node status.
    Status { data_dir: PathBuf },
}

fn parse_cli() -> Command {
    let mut args = std::env::args().skip(1).peekable();

    let subcommand = args.next().unwrap_or_else(|| {
        print_help();
        std::process::exit(0);
    });

    let mut data_dir = StatePersistence::default_dir();
    let mut listen = "/ip4/0.0.0.0/tcp/9090".to_string();
    let mut bootstrap = Vec::new();
    let mut no_mdns = false;
    let mut api_port = 9091u16;

    // Parse remaining flags
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--data-dir" | "-d" => {
                data_dir = PathBuf::from(args.next().expect("--data-dir requires a value"));
            }
            "--listen" | "-l" => {
                listen = args.next().expect("--listen requires a value");
            }
            "--bootstrap" | "-b" => {
                bootstrap.push(args.next().expect("--bootstrap requires a value"));
            }
            "--no-mdns" => no_mdns = true,
            "--api-port" => {
                api_port = args
                    .next()
                    .expect("--api-port requires a value")
                    .parse()
                    .expect("--api-port must be a number");
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown flag: {arg}");
                std::process::exit(1);
            }
        }
    }

    match subcommand.as_str() {
        "init" => Command::Init { data_dir },
        "run" => Command::Run {
            data_dir,
            listen,
            bootstrap,
            no_mdns,
            api_port,
        },
        "status" => Command::Status { data_dir },
        "--help" | "-h" | "help" => {
            print_help();
            std::process::exit(0);
        }
        _ => {
            eprintln!("Unknown command: {subcommand}");
            print_help();
            std::process::exit(1);
        }
    }
}

fn print_help() {
    eprintln!("Valence Network v0 Node");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  valence-node <COMMAND> [OPTIONS]");
    eprintln!();
    eprintln!("COMMANDS:");
    eprintln!("  init     Create a new node identity");
    eprintln!("  run      Start the node daemon");
    eprintln!("  status   Show node identity and status");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  -d, --data-dir <DIR>     Data directory (default: ~/.valence-node/)");
    eprintln!("  -l, --listen <ADDR>      Listen address (default: /ip4/0.0.0.0/tcp/9090)");
    eprintln!("  -b, --bootstrap <ADDR>   Bootstrap peer (repeatable)");
    eprintln!("  --no-mdns                Disable mDNS discovery");
    eprintln!("  --api-port <PORT>        Local API port (default: 9091)");
    eprintln!("  -h, --help               Show this help");
}

/// M-5: Drop root privileges after binding sockets.
/// Looks for VALENCE_USER env var or falls back to "nobody".
#[cfg(unix)]
fn drop_privileges_if_root() {
    unsafe {
        if libc::getuid() == 0 {
            let target_user = std::env::var("VALENCE_USER").unwrap_or_else(|_| "nobody".into());
            tracing::info!(user = %target_user, "Running as root, attempting to drop privileges");

            let c_user = std::ffi::CString::new(target_user.clone()).unwrap();
            let pw = libc::getpwnam(c_user.as_ptr());
            if pw.is_null() {
                tracing::warn!(user = %target_user, "User not found, cannot drop privileges");
                return;
            }

            let uid = (*pw).pw_uid;
            let gid = (*pw).pw_gid;

            if libc::setgid(gid) != 0 {
                tracing::warn!("Failed to setgid({})", gid);
                return;
            }
            if libc::setuid(uid) != 0 {
                tracing::warn!("Failed to setuid({})", uid);
                return;
            }

            tracing::info!(uid, gid, "Dropped privileges successfully");
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,valence=debug".into()),
        )
        .init();

    let command = parse_cli();

    match command {
        Command::Init { data_dir } => cmd_init(data_dir),
        Command::Run {
            data_dir,
            listen,
            bootstrap,
            no_mdns,
            api_port,
        } => cmd_run(data_dir, listen, bootstrap, no_mdns, api_port).await,
        Command::Status { data_dir } => cmd_status(data_dir),
    }
}

/// `valence-node init` — create identity and data directory.
fn cmd_init(data_dir: PathBuf) -> Result<()> {
    let persist = StatePersistence::new(data_dir)?;

    if persist.load_identity_seed()?.is_some() {
        eprintln!("Identity already exists at {}", persist.identity_path().display());
        eprintln!("Delete it first if you want to re-initialize.");
        std::process::exit(1);
    }

    let identity = NodeIdentity::generate();
    persist.save_identity_seed(&identity.signing_key().to_bytes())?;

    // Compute VDF proof over public key bytes (§10)
    info!("Computing VDF proof (this may take a moment)...");
    let vdf_proof = valence_crypto::vdf::compute_standard(&identity.public_key_bytes());
    persist.save_vdf_proof(&vdf_proof)?;

    println!("Node initialized.");
    println!("  Node ID: {}", identity.node_id());
    println!("  Data dir: {}", persist.identity_path().parent().unwrap().display());
    println!("  VDF proof: computed and saved");

    Ok(())
}

/// `valence-node status` — display node identity and state.
fn cmd_status(data_dir: PathBuf) -> Result<()> {
    let persist = StatePersistence::new(data_dir)?;

    let seed = persist
        .load_identity_seed()?
        .context("No identity found. Run `valence-node init` first.")?;

    let identity = NodeIdentity::from_seed(&seed);
    println!("Node ID: {}", identity.node_id());

    if let Some(snapshot) = persist.load()? {
        println!("Identities tracked: {}", snapshot.identities.len());
        println!("Proposals tracked: {}", snapshot.tracked_proposals.len());
        println!("Active withdrawals: {}", snapshot.withdrawals.len());
    } else {
        println!("No state snapshot found (fresh node).");
    }

    Ok(())
}

/// `valence-node run` — start the daemon.
async fn cmd_run(
    data_dir: PathBuf,
    listen: String,
    bootstrap: Vec<String>,
    no_mdns: bool,
    api_port: u16,
) -> Result<()> {
    let persist = StatePersistence::new(data_dir.clone())?;

    // Load or create identity
    let identity = if let Some(seed) = persist.load_identity_seed()? {
        let id = NodeIdentity::from_seed(&seed);
        info!(node_id = %id.node_id(), "Loaded identity from disk");
        id
    } else {
        let id = NodeIdentity::generate();
        persist.save_identity_seed(&id.signing_key().to_bytes())?;
        info!(node_id = %id.node_id(), "Generated and saved new identity");
        id
    };

    // Initialize protocol state
    let mut node_state = NodeState::new();

    // Restore from snapshot if available
    if let Some(snapshot) = persist.load()? {
        restore_from_snapshot(&mut node_state, &snapshot);
    }

    let node_state = Arc::new(RwLock::new(node_state));

    // Load VDF proof
    let vdf_proof_json = persist.load_vdf_proof()?
        .unwrap_or_else(|| {
            info!("No VDF proof found, computing one...");
            let proof = valence_crypto::vdf::compute_standard(&identity.public_key_bytes());
            if let Err(e) = persist.save_vdf_proof(&proof) {
                tracing::warn!(error = %e, "Failed to save computed VDF proof");
            }
            serde_json::json!({
                "output": hex::encode(&proof.output),
                "input_data": hex::encode(&proof.input_data),
                "difficulty": proof.difficulty,
                "computed_at": proof.computed_at,
                "checkpoints": proof.checkpoints.iter().map(|cp| serde_json::json!({
                    "iteration": cp.iteration,
                    "hash": hex::encode(&cp.hash),
                })).collect::<Vec<_>>(),
            })
        });
    info!("VDF proof loaded");

    // Build transport config
    let transport_config = TransportConfig {
        listen_addrs: vec![listen.parse().expect("Invalid listen address")],
        bootstrap_peers: bootstrap
            .iter()
            .map(|a| a.parse().expect("Invalid bootstrap address"))
            .collect(),
        enable_mdns: !no_mdns,
        ..Default::default()
    };

    // Create swarm
    let (mut swarm, cmd_tx, mut event_rx) =
        ValenceSwarm::new(identity.clone(), transport_config).context("Failed to create swarm")?;

    swarm.set_vdf_proof(vdf_proof_json);

    swarm.start_listening().context("Failed to start listening")?;

    // Start API server with bearer token authentication (C-4)
    let api_token = api::load_or_create_api_token(&data_dir)?;
    info!("API token loaded (use Authorization: Bearer <token>)");
    let api_config = ApiConfig {
        bind_addr: format!("127.0.0.1:{api_port}").parse().unwrap(),
    };
    let peer_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let api_state = Arc::new(ApiState {
        node_state: node_state.clone(),
        identity: identity.clone(),
        command_tx: cmd_tx.clone(),
        started_at: chrono::Utc::now(),
        api_token,
        peer_count: peer_count.clone(),
    });
    api::start_api_server(api_config, api_state).await?;

    // M-5: Drop privileges if running as root after binding sockets
    #[cfg(unix)]
    drop_privileges_if_root();

    info!("Valence node running. Press Ctrl+C to stop.");

    // L-7: Handle both SIGINT (Ctrl+C) and SIGTERM for graceful shutdown
    let shutdown = async {
        let ctrl_c = tokio::signal::ctrl_c();

        #[cfg(unix)]
        {
            let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to register SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => { info!("Received SIGINT"); }
                _ = sigterm.recv() => { info!("Received SIGTERM"); }
            }
        }

        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
            info!("Received SIGINT");
        }
    };
    tokio::pin!(shutdown);

    // Checkpoint interval
    let mut checkpoint_interval = tokio::time::interval(std::time::Duration::from_secs(300));

    // Rent cycle check interval (every hour)
    let mut rent_check_interval = tokio::time::interval(std::time::Duration::from_secs(3600));

    // Snapshot publishing interval (every 8 hours)
    let mut snapshot_publish_interval = tokio::time::interval(std::time::Duration::from_secs(8 * 3600));

    // Main event loop
    loop {
        tokio::select! {
            // Swarm event loop (handles network events internally)
            result = swarm.run() => {
                if let Err(e) = result {
                    tracing::error!(error = %e, "Swarm error");
                }
                break;
            }

            // Transport events (gossip messages dispatched to handlers)
            Some(event) = event_rx.recv() => {
                use valence_network::transport::TransportEvent;
                match event {
                    TransportEvent::GossipMessage { envelope, .. } => {
                        let now_ms = chrono::Utc::now().timestamp_millis();
                        let mut state = node_state.write().await;
                        handler::handle_gossip_message(&mut state, &envelope, now_ms);
                        if state.record_event() {
                            let snapshot = create_snapshot(&state);
                            if let Err(e) = persist.save(&snapshot) {
                                tracing::warn!(error = %e, "Failed to save checkpoint");
                            }
                            state.mark_checkpointed();
                        }
                    }
                    TransportEvent::PeerConnected { peer_id, node_id, .. } => {
                        info!(peer = %peer_id, node = %node_id, "Peer connected");
                        peer_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    TransportEvent::PeerDisconnected { peer_id } => {
                        info!(peer = %peer_id, "Peer disconnected");
                        peer_count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    TransportEvent::SyncResponse { messages, .. } => {
                        let now_ms = chrono::Utc::now().timestamp_millis();
                        let mut state = node_state.write().await;
                        let count = messages.len();
                        for envelope in &messages {
                            handler::handle_gossip_message(&mut state, envelope, now_ms);
                        }
                        tracing::debug!(count, "Processed sync response");
                    }
                    TransportEvent::ContentReceived { content_hash, shard_index, shard_data, .. } => {
                        let state = node_state.write().await;
                        if let Err(e) = state.shard_store.store_shard(&content_hash, shard_index, &shard_data) {
                            tracing::warn!(error = %e, content = %content_hash, shard = shard_index, "Failed to store shard");
                        } else {
                            tracing::info!(content = %content_hash, shard = shard_index, bytes = shard_data.len(), "Stored shard");
                        }
                    }
                    TransportEvent::StorageChallengeReceived { peer_id, challenge } => {
                        use sha2::{Digest, Sha256};
                        use valence_core::message::MessageType;
                        use valence_crypto::signing::sign_message;
                        
                        let state = node_state.read().await;
                        // Extract shard_index from shard_hash (format: "content_hash:shard_index")
                        let parts: Vec<&str> = challenge.shard_hash.split(':').collect();
                        if parts.len() == 2
                            && let Ok(shard_index) = parts[1].parse::<u32>() {
                                let content_hash = parts[0];
                                match state.shard_store.read_shard(content_hash, shard_index) {
                                    Ok(shard_data) => {
                                        // Compute proof: hash(nonce || shard_data)
                                        let mut hasher = Sha256::new();
                                        hasher.update(challenge.challenge_nonce.as_bytes());
                                        hasher.update(&shard_data);
                                        let proof_hash = format!("{:x}", hasher.finalize());
                                        
                                        // Publish ChallengeResult message
                                        let now_ms = chrono::Utc::now().timestamp_millis();
                                        let payload = serde_json::json!({
                                            "shard_hash": challenge.shard_hash,
                                            "proof_hash": proof_hash,
                                            "challenge_nonce": challenge.challenge_nonce,
                                        });
                                        let envelope = sign_message(&identity, MessageType::ChallengeResult, payload, now_ms);
                                        if let Ok(data) = serde_json::to_vec(&envelope) {
                                            let _ = cmd_tx.send(valence_network::transport::TransportCommand::Publish {
                                                topic: "/valence/proposals".into(),
                                                data,
                                            });
                                            tracing::debug!(peer = %peer_id, shard = %challenge.shard_hash, "Sent challenge proof");
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = %e, shard = %challenge.shard_hash, "Failed to read shard for challenge");
                                    }
                                }
                            }
                    }
                    TransportEvent::StorageProofReceived { peer_id, proof } => {
                        tracing::debug!(peer = %peer_id, proof = %proof.proof_hash, "Received storage proof");
                        // Verification happens in the ChallengeResult gossip handler
                    }
                    TransportEvent::ContentRequested { peer_id, content_hash, offset, length } => {
                        let state = node_state.read().await;
                        // For now, assume offset/length map to shard_index (simplified)
                        let shard_index = (offset / length) as u32;
                        let content_hash_clone = content_hash.clone();
                        match state.shard_store.read_shard(&content_hash, shard_index) {
                            Ok(shard_data) => {
                                let _ = cmd_tx.send(valence_network::transport::TransportCommand::SendShard {
                                    peer_id,
                                    content_hash: content_hash_clone.clone(),
                                    shard_index,
                                    shard_data,
                                });
                                tracing::debug!(peer = %peer_id, content = %content_hash_clone, shard = shard_index, "Sent shard");
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, peer = %peer_id, content = %content_hash, "Failed to read requested shard");
                            }
                        }
                    }
                }
            }

            // Periodic checkpoints
            _ = checkpoint_interval.tick() => {
                let state = node_state.read().await;
                let snapshot = create_snapshot(&state);
                if let Err(e) = persist.save(&snapshot) {
                    tracing::warn!(error = %e, "Failed to save periodic checkpoint");
                }
            }

            // Rent cycle automation (§6)
            _ = rent_check_interval.tick() => {
                let now_ms = chrono::Utc::now().timestamp_millis();
                let responses = {
                    let mut state = node_state.write().await;
                    handler::check_rent_cycle(&mut state, &identity, now_ms)
                };
                for resp in responses {
                    if let handler::HandlerResponse::Publish { topic, data } = resp
                        && let Err(e) = cmd_tx.send(valence_network::transport::TransportCommand::Publish { topic, data }) {
                            tracing::warn!(error = %e, "Failed to publish rent payment");
                        }
                }
            }

            // STATE_SNAPSHOT publishing (§5)
            _ = snapshot_publish_interval.tick() => {
                let now_ms = chrono::Utc::now().timestamp_millis();
                let responses = {
                    let mut state = node_state.write().await;
                    handler::check_snapshot_publishing(&mut state, &identity, now_ms)
                };
                for resp in responses {
                    if let handler::HandlerResponse::Publish { topic, data } = resp
                        && let Err(e) = cmd_tx.send(valence_network::transport::TransportCommand::Publish { topic, data }) {
                            tracing::warn!(error = %e, "Failed to publish state snapshot");
                        }
                }
            }

            // Graceful shutdown on SIGINT or SIGTERM (L-7)
            _ = &mut shutdown => {
                info!("Received shutdown signal, saving state...");
                let state = node_state.read().await;
                let snapshot = create_snapshot(&state);
                if let Err(e) = persist.save(&snapshot) {
                    tracing::warn!(error = %e, "Failed to save final checkpoint");
                }
                break;
            }
        }
    }

    info!("Valence node stopped.");
    Ok(())
}
