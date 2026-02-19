//! Local HTTP API for agent interaction with the node.
//!
//! Provides a lightweight REST API on localhost for agents to interact with
//! the Valence node. In v0 this is a stub layer — real implementations will
//! be fleshed out as the node matures.

use std::net::SocketAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use valence_core::message::MessageType;
use valence_crypto::identity::NodeIdentity;
use valence_crypto::signing::sign_message;
use valence_network::transport::TransportCommand;

use crate::state::NodeState;

/// M-9: Maximum API response body size (1 MiB).
const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// API server configuration.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Bind address for the HTTP server.
    pub bind_addr: SocketAddr,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:9091".parse().unwrap(),
        }
    }
}

/// Shared state accessible by API handlers.
pub struct ApiState {
    pub node_state: Arc<RwLock<NodeState>>,
    pub identity: NodeIdentity,
    pub command_tx: mpsc::UnboundedSender<TransportCommand>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Bearer token for API authentication (C-4).
    pub api_token: String,
    /// Current authenticated peer count.
    pub peer_count: Arc<std::sync::atomic::AtomicUsize>,
}

/// Generate a random API token (64 hex characters = 32 bytes of entropy).
pub fn generate_api_token() -> String {
    let bytes: [u8; 32] = rand::random();
    hex::encode(bytes)
}

/// Load or create the API token file at `<data_dir>/api.token`.
/// File is created with 0600 permissions.
pub fn load_or_create_api_token(data_dir: &std::path::Path) -> anyhow::Result<String> {
    let token_path = data_dir.join("api.token");
    if token_path.exists() {
        let token = std::fs::read_to_string(&token_path)
            .map_err(|e| anyhow::anyhow!("Failed to read API token: {e}"))?
            .trim()
            .to_string();
        if token.is_empty() {
            anyhow::bail!("API token file is empty");
        }
        return Ok(token);
    }

    let token = generate_api_token();
    std::fs::write(&token_path, &token)
        .map_err(|e| anyhow::anyhow!("Failed to write API token: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(token)
}

// ─── Request/Response types ──────────────────────────────────────────

/// GET /sync-status — Sync protocol status per §5.
#[derive(Debug, Serialize)]
pub struct SyncStatusResponse {
    pub sync_status: String,
    pub current_phase: Option<String>,
    pub completed_phases: Vec<String>,
    pub can_vote: bool,
    pub can_propose: bool,
    pub vote_weight_multiplier: u32,
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub node_id: String,
    pub uptime_seconds: i64,
    pub peer_count: usize,
    pub proposal_count: usize,
    pub identity_count: usize,
}

#[derive(Debug, Serialize)]
pub struct IdentityResponse {
    pub node_id: String,
    pub linked_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ProposeRequest {
    pub title: String,
    pub body: String,
    pub tier: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VoteRequest {
    pub proposal_id: String,
    pub stance: String,
}

#[derive(Debug, Deserialize)]
pub struct ShareRequest {
    pub content_hash: String,
    pub content_type: String,
    pub content_size: u64,
    pub filename: Option<String>,
    pub description: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReplicateRequest {
    pub content_hash: String,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

// ─── Handler stubs ───────────────────────────────────────────────────

/// GET /sync-status — Sync protocol status per §5.
pub async fn handle_sync_status(api_state: &ApiState) -> ApiResponse<SyncStatusResponse> {
    let state = api_state.node_state.read().await;
    let sm = &state.sync_manager;

    let current_phase = sm.current_phase.map(|p| format!("{:?}", p));
    let completed_phases: Vec<String> = sm.completed_phases.iter()
        .map(|p| format!("{:?}", p))
        .collect();

    ApiResponse::success(SyncStatusResponse {
        sync_status: sm.status.as_str().to_string(),
        current_phase,
        completed_phases,
        can_vote: sm.can_vote(),
        can_propose: sm.can_propose(),
        vote_weight_multiplier: sm.vote_weight_multiplier(),
    })
}

/// GET /status — Node status overview.
pub async fn handle_status(api_state: &ApiState) -> ApiResponse<StatusResponse> {
    let state = api_state.node_state.read().await;
    let uptime = chrono::Utc::now()
        .signed_duration_since(api_state.started_at)
        .num_seconds();

    ApiResponse::success(StatusResponse {
        node_id: api_state.identity.node_id().to_string(),
        uptime_seconds: uptime,
        peer_count: api_state.peer_count.load(std::sync::atomic::Ordering::Relaxed),
        proposal_count: state.proposals.len(),
        identity_count: state.identity_manager.identity_count(),
    })
}

/// GET /identity — Current node identity.
pub async fn handle_identity(api_state: &ApiState) -> ApiResponse<IdentityResponse> {
    let state = api_state.node_state.read().await;
    let node_id = api_state.identity.node_id().to_string();

    let linked_keys = state
        .identity_manager
        .identity_group(&node_id)
        .map(|group| group.into_iter().filter(|k| *k != node_id).collect())
        .unwrap_or_default();

    ApiResponse::success(IdentityResponse {
        node_id,
        linked_keys,
    })
}

/// POST /propose — Submit a proposal.
pub async fn handle_propose(
    api_state: &ApiState,
    request: ProposeRequest,
) -> ApiResponse<String> {
    let now_ms = chrono::Utc::now().timestamp_millis();

    let tier = request.tier.as_deref().unwrap_or("standard");
    let payload = serde_json::json!({
        "tier": tier,
        "title": request.title,
        "body": request.body,
        "voting_deadline_ms": now_ms + 7 * 24 * 3600 * 1000,
    });

    let envelope = sign_message(&api_state.identity, MessageType::Propose, payload, now_ms);
    let msg_id = envelope.id.clone();

    let topic = MessageType::Propose
        .gossipsub_topic()
        .unwrap_or("/valence/proposals");
    match serde_json::to_vec(&envelope) {
        Ok(data) => {
            let _ = api_state.command_tx.send(TransportCommand::Publish {
                topic: topic.to_string(),
                data,
            });
            ApiResponse::success(msg_id)
        }
        Err(e) => ApiResponse::error(format!("Serialization error: {e}")),
    }
}

/// POST /vote — Cast a vote on a proposal.
pub async fn handle_vote(api_state: &ApiState, request: VoteRequest) -> ApiResponse<String> {
    let now_ms = chrono::Utc::now().timestamp_millis();

    let payload = serde_json::json!({
        "proposal_id": request.proposal_id,
        "stance": request.stance,
    });

    let envelope = sign_message(&api_state.identity, MessageType::Vote, payload, now_ms);
    let msg_id = envelope.id.clone();

    let topic = MessageType::Vote
        .gossipsub_topic()
        .unwrap_or("/valence/votes");
    match serde_json::to_vec(&envelope) {
        Ok(data) => {
            let _ = api_state.command_tx.send(TransportCommand::Publish {
                topic: topic.to_string(),
                data,
            });
            ApiResponse::success(msg_id)
        }
        Err(e) => ApiResponse::error(format!("Serialization error: {e}")),
    }
}

/// POST /share — Announce content to the network.
pub async fn handle_share(api_state: &ApiState, request: ShareRequest) -> ApiResponse<String> {
    let now_ms = chrono::Utc::now().timestamp_millis();

    let payload = serde_json::json!({
        "entries": [{
            "content_hash": request.content_hash,
            "content_type": request.content_type,
            "content_size": request.content_size,
            "filename": request.filename,
            "description": request.description,
            "tags": request.tags,
        }]
    });

    let envelope = sign_message(&api_state.identity, MessageType::Share, payload, now_ms);
    let msg_id = envelope.id.clone();

    let topic = MessageType::Share
        .gossipsub_topic()
        .unwrap_or("/valence/peers");
    match serde_json::to_vec(&envelope) {
        Ok(data) => {
            let _ = api_state.command_tx.send(TransportCommand::Publish {
                topic: topic.to_string(),
                data,
            });
            ApiResponse::success(msg_id)
        }
        Err(e) => ApiResponse::error(format!("Serialization error: {e}")),
    }
}

/// GET /content/:hash — Look up content metadata.
pub async fn handle_content_lookup(
    api_state: &ApiState,
    content_hash: &str,
) -> ApiResponse<serde_json::Value> {
    let state = api_state.node_state.read().await;

    if let Some(transfer) = state.content_transfers.get(content_hash) {
        ApiResponse::success(serde_json::json!({
            "content_hash": content_hash,
            "uploader": transfer.uploader,
            "confirmed_shards": transfer.confirmed_count(),
            "pending_shards": transfer.pending_count(),
        }))
    } else {
        ApiResponse::error(format!("Content not found: {content_hash}"))
    }
}

/// POST /replicate — Request content replication.
pub async fn handle_replicate(
    api_state: &ApiState,
    request: ReplicateRequest,
) -> ApiResponse<String> {
    let now_ms = chrono::Utc::now().timestamp_millis();

    let payload = serde_json::json!({
        "content_hash": request.content_hash,
        "content_type": "application/octet-stream",
        "content_size": 0,
        "coding": "standard",
        "reputation_stake": 0.01,
        "tags": [],
    });

    let envelope = sign_message(
        &api_state.identity,
        MessageType::ReplicateRequest,
        payload,
        now_ms,
    );
    let msg_id = envelope.id.clone();

    let topic = MessageType::ReplicateRequest
        .gossipsub_topic()
        .unwrap_or("/valence/proposals");
    match serde_json::to_vec(&envelope) {
        Ok(data) => {
            let _ = api_state.command_tx.send(TransportCommand::Publish {
                topic: topic.to_string(),
                data,
            });
            ApiResponse::success(msg_id)
        }
        Err(e) => ApiResponse::error(format!("Serialization error: {e}")),
    }
}

// ─── Minimal HTTP server using raw tokio TCP ─────────────────────────
//
// A production node would use axum/warp/actix, but we keep dependencies
// minimal for v0. This is a stub that parses basic HTTP/1.1 requests.

/// Start the API server (spawns a background task).
pub async fn start_api_server(
    config: ApiConfig,
    api_state: Arc<ApiState>,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    info!(addr = %config.bind_addr, "API server listening");

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let state = api_state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, state).await {
                            debug!(addr = %addr, error = %e, "API connection error");
                        }
                    });
                }
                Err(e) => {
                    warn!(error = %e, "API accept error");
                }
            }
        }
    });

    Ok(())
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    api_state: Arc<ApiState>,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await?;
    let request_str = String::from_utf8_lossy(&buf[..n]);

    // Parse first line: METHOD PATH HTTP/1.1
    let first_line = request_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        let resp = http_response(400, "Bad Request");
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    // C-4: Verify bearer token authentication
    let authorized = request_str
        .lines()
        .find(|line| line.to_lowercase().starts_with("authorization:"))
        .and_then(|line| line.split_once(':'))
        .map(|(_, value)| value.trim())
        .and_then(|value| value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer ")))
        .map(|token| token.trim() == api_state.api_token)
        .unwrap_or(false);

    if !authorized {
        let resp = http_response(401, r#"{"ok":false,"error":"Unauthorized: missing or invalid Bearer token"}"#);
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    // Extract body (after blank line)
    let body = request_str
        .split("\r\n\r\n")
        .nth(1)
        .or_else(|| request_str.split("\n\n").nth(1))
        .unwrap_or("");

    let response_body = match (method, path) {
        ("GET", "/status") => {
            let resp = handle_status(&api_state).await;
            serde_json::to_string(&resp).unwrap_or_default()
        }
        ("GET", "/sync-status") => {
            let resp = handle_sync_status(&api_state).await;
            serde_json::to_string(&resp).unwrap_or_default()
        }
        ("GET", "/identity") => {
            let resp = handle_identity(&api_state).await;
            serde_json::to_string(&resp).unwrap_or_default()
        }
        ("POST", "/propose") => match serde_json::from_str::<ProposeRequest>(body) {
            Ok(req) => {
                let resp = handle_propose(&api_state, req).await;
                serde_json::to_string(&resp).unwrap_or_default()
            }
            Err(e) => {
                serde_json::to_string(&ApiResponse::<()>::error(format!("Bad request: {e}")))
                    .unwrap_or_default()
            }
        },
        ("POST", "/vote") => match serde_json::from_str::<VoteRequest>(body) {
            Ok(req) => {
                let resp = handle_vote(&api_state, req).await;
                serde_json::to_string(&resp).unwrap_or_default()
            }
            Err(e) => {
                serde_json::to_string(&ApiResponse::<()>::error(format!("Bad request: {e}")))
                    .unwrap_or_default()
            }
        },
        ("POST", "/share") => match serde_json::from_str::<ShareRequest>(body) {
            Ok(req) => {
                let resp = handle_share(&api_state, req).await;
                serde_json::to_string(&resp).unwrap_or_default()
            }
            Err(e) => {
                serde_json::to_string(&ApiResponse::<()>::error(format!("Bad request: {e}")))
                    .unwrap_or_default()
            }
        },
        ("POST", "/replicate") => match serde_json::from_str::<ReplicateRequest>(body) {
            Ok(req) => {
                let resp = handle_replicate(&api_state, req).await;
                serde_json::to_string(&resp).unwrap_or_default()
            }
            Err(e) => {
                serde_json::to_string(&ApiResponse::<()>::error(format!("Bad request: {e}")))
                    .unwrap_or_default()
            }
        },
        ("GET", p) if p.starts_with("/content/") => {
            let hash = &p["/content/".len()..];
            // M-2: Validate content hash is a 64-char hex string to prevent path traversal
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                let resp = http_response(400, r#"{"ok":false,"error":"Invalid content hash: must be 64 hex characters"}"#);
                stream.write_all(resp.as_bytes()).await?;
                return Ok(());
            }
            let resp = handle_content_lookup(&api_state, hash).await;
            serde_json::to_string(&resp).unwrap_or_default()
        }
        _ => {
            let resp = http_response(404, r#"{"ok":false,"error":"Not found"}"#);
            stream.write_all(resp.as_bytes()).await?;
            return Ok(());
        }
    };

    // M-9: Enforce maximum response size
    if response_body.len() > MAX_RESPONSE_SIZE {
        let truncated = serde_json::to_string(&ApiResponse::<()>::error("Response too large"))
            .unwrap_or_default();
        let resp = http_response(413, &truncated);
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    let resp = http_response(200, &response_body);
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

fn http_response(status: u16, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use valence_crypto::identity::NodeIdentity;

    fn make_api_state() -> Arc<ApiState> {
        let identity = NodeIdentity::generate();
        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();
        Arc::new(ApiState {
            node_state: Arc::new(RwLock::new(NodeState::new())),
            identity,
            command_tx: cmd_tx,
            started_at: chrono::Utc::now(),
            api_token: "test-token-12345".to_string(),
            peer_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    #[tokio::test]
    async fn status_returns_node_id() {
        let state = make_api_state();
        let resp = handle_status(&state).await;
        assert!(resp.ok);
        assert!(!resp.data.unwrap().node_id.is_empty());
    }

    #[tokio::test]
    async fn identity_returns_node_id() {
        let state = make_api_state();
        let resp = handle_identity(&state).await;
        assert!(resp.ok);
        assert!(!resp.data.unwrap().node_id.is_empty());
    }

    #[tokio::test]
    async fn propose_returns_message_id() {
        let state = make_api_state();
        let req = ProposeRequest {
            title: "Test".into(),
            body: "Body".into(),
            tier: None,
        };
        let resp = handle_propose(&state, req).await;
        assert!(resp.ok);
        assert!(!resp.data.unwrap().is_empty());
    }

    #[tokio::test]
    async fn vote_returns_message_id() {
        let state = make_api_state();
        let req = VoteRequest {
            proposal_id: "prop-1".into(),
            stance: "endorse".into(),
        };
        let resp = handle_vote(&state, req).await;
        assert!(resp.ok);
    }

    #[tokio::test]
    async fn content_lookup_not_found() {
        let state = make_api_state();
        let resp = handle_content_lookup(&state, "nonexistent").await;
        assert!(!resp.ok);
    }

    #[tokio::test]
    async fn api_auth_rejects_without_token() {
        // C-4: Test that the HTTP handler rejects unauthenticated requests
        let state = make_api_state();
        let _config = ApiConfig::default();

        // Start server on random port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = handle_connection(stream, state_clone).await;
            }
        });

        // Connect without auth header
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        use tokio::io::{AsyncWriteExt, AsyncReadExt};
        stream.write_all(b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("401"), "Should return 401 without token");
        assert!(response.contains("Unauthorized"));
    }

    #[tokio::test]
    async fn api_auth_accepts_valid_token() {
        let state = make_api_state();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = handle_connection(stream, state_clone).await;
            }
        });

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        use tokio::io::{AsyncWriteExt, AsyncReadExt};
        let req = format!(
            "GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
            "test-token-12345"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("200"), "Should return 200 with valid token");
    }

    #[tokio::test]
    async fn api_auth_rejects_wrong_token() {
        let state = make_api_state();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = handle_connection(stream, state_clone).await;
            }
        });

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        use tokio::io::{AsyncWriteExt, AsyncReadExt};
        stream.write_all(b"GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong-token\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("401"), "Should return 401 with wrong token");
    }

    #[test]
    fn api_token_generation_is_unique() {
        let t1 = generate_api_token();
        let t2 = generate_api_token();
        assert_ne!(t1, t2);
        assert_eq!(t1.len(), 64); // 32 bytes = 64 hex chars
    }

    // ── M-2: Content hash validation ──

    #[tokio::test]
    async fn content_hash_rejects_path_traversal() {
        // M-2: Hashes like ../../etc/passwd must be rejected
        let state = make_api_state();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = handle_connection(stream, state_clone).await;
            }
        });

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        use tokio::io::{AsyncWriteExt, AsyncReadExt};
        let req = format!(
            "GET /content/../../etc/passwd HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
            "test-token-12345"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("400"), "Path traversal should return 400, got: {response}");
    }

    #[tokio::test]
    async fn content_hash_rejects_non_hex() {
        let state = make_api_state();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = handle_connection(stream, state_clone).await;
            }
        });

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        use tokio::io::{AsyncWriteExt, AsyncReadExt};
        // 64 chars but not all hex
        let bad_hash = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let req = format!(
            "GET /content/{bad_hash} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
            "test-token-12345"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("400"), "Non-hex hash should return 400");
    }

    #[tokio::test]
    async fn content_hash_accepts_valid_hex() {
        let state = make_api_state();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = handle_connection(stream, state_clone).await;
            }
        });

        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await.unwrap();
        use tokio::io::{AsyncWriteExt, AsyncReadExt};
        let valid_hash = "a".repeat(64);
        let req = format!(
            "GET /content/{valid_hash} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
            "test-token-12345"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        // Should get 200 (even if content not found, it passes validation)
        assert!(response.contains("200"), "Valid hex hash should pass validation");
    }

    // ── M-9: Response size limit ──

    #[test]
    fn max_response_size_constant() {
        assert_eq!(MAX_RESPONSE_SIZE, 1024 * 1024);
    }

    #[tokio::test]
    async fn share_returns_message_id() {
        let state = make_api_state();
        let req = ShareRequest {
            content_hash: "a".repeat(64),
            content_type: "text/plain".into(),
            content_size: 1024,
            filename: None,
            description: None,
            tags: vec![],
        };
        let resp = handle_share(&state, req).await;
        assert!(resp.ok);
    }
}
