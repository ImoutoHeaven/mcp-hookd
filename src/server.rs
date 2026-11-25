//! Single-port HTTP facade: route isolation, MCP protocol branching, passthrough proxy,
//! `/v1/events` ingest endpoint, and graceful shutdown (spec §2, §4, §5).

use crate::auth::{AuthCheckOutcome, intersect_scopes};
use crate::config::Config;
use crate::engine::{
    CallerAuth, EngineError, HookdEngine, PassthroughResolution, SubscribeRequest,
    UnsubscribeRequest,
};
use crate::headers::{
    is_origin_allowed, strip_hop_by_hop_response_headers, validate_optional_event_routing_headers,
    validate_passthrough_path,
};
use crate::outbound::OutboundClient;
use crate::proxy_body::{ProxyBody, lease_bytes};
use crate::types::{
    ByteBudget, LATEST_LEGACY_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSIONS, LEGACY_SESSION_IDLE_SECS,
    MAX_INGEST_BODY_BYTES, MAX_LEGACY_SESSIONS, MAX_REQUEST_BODY_BYTES, MemoryPools,
    PROTOCOL_VERSION_MODERN, Profile, QuotaConfig, SecretString, constant_time_token_eq,
    random_base64url, unix_now,
};
use crate::upstream::UpstreamError;
use bytes::{BufMut, Bytes, BytesMut};
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body::Body;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);
const CONTROL_FALLBACK_MAX_BYTES: usize = 64 * 1024;

type RespBody = BoxBody<Bytes, io::Error>;

struct LegacySessionStore {
    sessions: HashMap<String, (u64, u64)>,
    seq: u64,
}

impl LegacySessionStore {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            seq: 0,
        }
    }

    fn next_seq(&mut self) -> u64 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    fn prune_expired(&mut self, now: u64) {
        self.sessions
            .retain(|_, (last_seen, _)| now.saturating_sub(*last_seen) < LEGACY_SESSION_IDLE_SECS);
    }

    fn issue(&mut self) -> Result<String, String> {
        let now = unix_now();
        self.prune_expired(now);
        if self.sessions.len() >= MAX_LEGACY_SESSIONS
            && let Some(oldest) = self
                .sessions
                .iter()
                .min_by_key(|(_, entry)| **entry)
                .map(|(k, _)| k.clone())
        {
            self.sessions.remove(&oldest);
        }
        let sid = format!("sess_{}", random_base64url(24)?);
        let seq = self.next_seq();
        self.sessions.insert(sid.clone(), (now, seq));
        Ok(sid)
    }

    fn touch(&mut self, sid: &str) -> bool {
        let now = unix_now();
        self.prune_expired(now);
        if self.sessions.contains_key(sid) {
            let seq = self.next_seq();
            if let Some(entry) = self.sessions.get_mut(sid) {
                *entry = (now, seq);
            }
            true
        } else {
            false
        }
    }

    fn remove(&mut self, sid: &str) -> bool {
        let now = unix_now();
        self.prune_expired(now);
        self.sessions.remove(sid).is_some()
    }
}

struct ServerState {
    engine: Arc<HookdEngine>,
    bound_addr: SocketAddr,
    legacy_sessions: Mutex<LegacySessionStore>,
}

pub struct RunningServer {
    bound_addr: SocketAddr,
    engine: Arc<HookdEngine>,
    cancel: CancellationToken,
    accept_task: JoinHandle<()>,
    conn_tracker: TaskTracker,
}

impl RunningServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    pub fn engine(&self) -> &Arc<HookdEngine> {
        &self.engine
    }

    /// Stop accepting new connections, and drain active HTTP connections and the engine
    /// concurrently within a single shared `drain_timeout_secs` window.
    pub async fn shutdown(self) -> Result<(), String> {
        self.cancel.cancel();
        let _ = self.accept_task.await;
        self.conn_tracker.close();
        let drain = Duration::from_secs(self.engine.quotas().drain_timeout_secs);
        let (_, engine_res) = tokio::join!(
            tokio::time::timeout(drain, self.conn_tracker.wait()),
            self.engine.shutdown(),
        );
        engine_res
    }
}

/// Bind `config.listen`, initialize `HookdEngine`, and start serving HTTP/1.1 requests.
pub async fn start_server(
    config: Config,
    quotas: QuotaConfig,
    outbound_override: Option<OutboundClient>,
) -> Result<RunningServer, String> {
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|e| format!("failed to bind {}: {e}", config.listen))?;
    let bound_addr = listener
        .local_addr()
        .map_err(|e| format!("failed to read bound address: {e}"))?;

    let pools = MemoryPools::from_quotas(&quotas);
    let engine = HookdEngine::new(config, quotas, pools, outbound_override).await?;

    let state = Arc::new(ServerState {
        engine: Arc::clone(&engine),
        bound_addr,
        legacy_sessions: Mutex::new(LegacySessionStore::new()),
    });

    let cancel = CancellationToken::new();
    let conn_tracker = TaskTracker::new();
    let accept_cancel = cancel.clone();
    let accept_tracker = conn_tracker.clone();

    let accept_task = tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = accept_cancel.cancelled() => break,
                res = listener.accept() => res,
            };
            let Ok((stream, _peer)) = accepted else {
                tokio::select! {
                    _ = accept_cancel.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                }
                continue;
            };
            let state = Arc::clone(&state);
            let conn_cancel = accept_cancel.clone();
            accept_tracker.spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    let state = Arc::clone(&state);
                    async move { Ok::<_, Infallible>(handle_request(state, req).await) }
                });
                let conn = http1::Builder::new().serve_connection(io, svc);
                tokio::pin!(conn);
                tokio::select! {
                    _ = conn.as_mut() => {}
                    _ = conn_cancel.cancelled() => {
                        conn.as_mut().graceful_shutdown();
                        let _ = conn.await;
                    }
                }
            });
        }
    });

    Ok(RunningServer {
        bound_addr,
        engine,
        cancel,
        accept_task,
        conn_tracker,
    })
}

/// Load config, run the foreground HTTP server, and drain cleanly on SIGINT/SIGTERM.
pub async fn run_serve(config_path: &Path) -> ExitCode {
    let config = match Config::load_from_path(config_path) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("mcp-hookd serve failed to load config: {err}");
            return ExitCode::FAILURE;
        }
    };
    let server = match start_server(config, QuotaConfig::default(), None).await {
        Ok(srv) => srv,
        Err(err) => {
            eprintln!("mcp-hookd serve failed to start: {err}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("mcp-hookd listening on http://{}", server.local_addr());

    wait_for_shutdown_signal().await;
    if let Err(err) = server.shutdown().await {
        eprintln!("mcp-hookd shutdown error: {err}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                if let Some(ref mut s) = sigterm {
                    s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn handle_request(state: Arc<ServerState>, req: Request<Incoming>) -> Response<RespBody> {
    let raw_path = req.uri().path().to_owned();
    let method = req.method().clone();

    // 1. Unauthenticated health probe.
    if raw_path == "/healthz" {
        return match method {
            Method::GET => json_response(StatusCode::OK, &json!({ "ok": true })),
            Method::HEAD => empty_response(StatusCode::OK),
            _ => method_not_allowed("GET, HEAD"),
        };
    }

    // 2. External producer ingest endpoint (only registered when `ingest` is configured).
    if raw_path == "/v1/events" {
        if state.engine.config().ingest.is_none() {
            return empty_response(StatusCode::NOT_FOUND);
        }
        return handle_ingest(state, req).await;
    }

    // 3. Primary MCP facade endpoint.
    if raw_path == state.engine.config().resource_path {
        return handle_mcp(state, req).await;
    }

    if raw_path == "/" {
        return empty_response(StatusCode::NOT_FOUND);
    }

    // 4. Configured passthrough prefixes (e.g. `/t/`).
    if let Some(up_cfg) = state.engine.config().upstream.as_ref()
        && !up_cfg.passthrough_prefixes.is_empty()
    {
        match validate_passthrough_path(&raw_path, &up_cfg.passthrough_prefixes) {
            Ok(true) => return handle_passthrough(state, req).await,
            Ok(false) => return empty_response(StatusCode::NOT_FOUND),
            Err(_) => return empty_response(StatusCode::BAD_REQUEST),
        }
    }

    empty_response(StatusCode::NOT_FOUND)
}

async fn handle_ingest(state: Arc<ServerState>, req: Request<Incoming>) -> Response<RespBody> {
    if req.method() != Method::POST {
        return method_not_allowed("POST");
    }
    let Some(ingest_cfg) = state.engine.config().ingest.as_ref() else {
        return empty_response(StatusCode::NOT_FOUND);
    };

    let Some(token_slot) = verify_bearer_token(req.headers(), &ingest_cfg.tokens) else {
        return unauthorized_response();
    };

    let body = match read_request_body_leased(
        req.into_body(),
        MAX_INGEST_BODY_BYTES,
        state.engine.pools(),
        false,
        false,
    )
    .await
    {
        Ok(res) => res,
        Err(BodyReadError::TooLarge) => {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &json!({ "ok": false, "error": "ingest body exceeds 256 KiB limit" }),
            );
        }
        Err(BodyReadError::Timeout) => {
            return json_response(
                StatusCode::REQUEST_TIMEOUT,
                &json!({ "ok": false, "error": "request body timed out" }),
            );
        }
        Err(BodyReadError::BudgetExhausted) => {
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({ "ok": false, "error": "server memory budget exhausted" }),
            );
        }
        Err(BodyReadError::Io(e)) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &json!({ "ok": false, "error": format!("failed to read body: {e}") }),
            );
        }
    };

    match state.engine.ingest_event(token_slot, &body) {
        Ok(res) => json_response(StatusCode::OK, &res),
        Err(err) => json_response(
            err.status_code(),
            &json!({ "ok": false, "error": err.to_string() }),
        ),
    }
}

async fn handle_passthrough(state: Arc<ServerState>, req: Request<Incoming>) -> Response<RespBody> {
    let method = req.method().clone();
    if !matches!(method, Method::GET | Method::HEAD | Method::PUT) {
        return method_not_allowed("GET, HEAD, PUT");
    }
    let Some(upstream) = state.engine.upstream_client() else {
        return empty_response(StatusCode::NOT_FOUND);
    };

    let pq = req
        .uri()
        .path_and_query()
        .map(|v| v.as_str().to_owned())
        .unwrap_or_else(|| req.uri().path().to_owned());
    if pq
        .bytes()
        .any(|b| b == b'\\' || b == 0 || b < 0x20 || b == 0x7f)
    {
        return empty_response(StatusCode::BAD_REQUEST);
    }

    let (parts, incoming) = req.into_parts();
    match upstream
        .forward_raw(
            method,
            Some(&pq),
            &parts.headers,
            ProxyBody::new(incoming, Arc::clone(&state.engine.pools().proxy)),
            false,
            None,
        )
        .await
    {
        Ok(resp) => relay_upstream_response(resp, Arc::clone(&state.engine.pools().proxy)),
        Err(UpstreamError::Timeout) => empty_response(StatusCode::GATEWAY_TIMEOUT),
        Err(_) => empty_response(StatusCode::BAD_GATEWAY),
    }
}

async fn handle_mcp(state: Arc<ServerState>, req: Request<Incoming>) -> Response<RespBody> {
    let cfg = state.engine.config();

    let Some(token_slot) = verify_bearer_token(req.headers(), &cfg.inbound_tokens) else {
        return unauthorized_response();
    };

    let origin = match single_header_str(req.headers(), header::ORIGIN.as_str()) {
        HeaderExtract::Missing => None,
        HeaderExtract::Single(val) => Some(val),
        HeaderExtract::DuplicateOrInvalid => return empty_response(StatusCode::FORBIDDEN),
    };
    if !is_origin_allowed(origin, state.bound_addr, &cfg.allowed_origins) {
        return empty_response(StatusCode::FORBIDDEN);
    }

    let caller = match extract_caller_auth(req.headers(), token_slot, cfg.auth_context.is_some()) {
        Ok(c) => c,
        Err(()) => return empty_response(StatusCode::INTERNAL_SERVER_ERROR),
    };

    match *req.method() {
        Method::GET => handle_mcp_get(state, req).await,
        Method::DELETE => handle_mcp_delete(state, req).await,
        Method::POST => handle_mcp_post(state, req, caller).await,
        _ => method_not_allowed("POST, GET, DELETE"),
    }
}

async fn handle_mcp_get(state: Arc<ServerState>, req: Request<Incoming>) -> Response<RespBody> {
    let Some(upstream) = state.engine.upstream_client() else {
        return method_not_allowed("POST, DELETE");
    };
    match upstream
        .forward_raw(
            Method::GET,
            None,
            req.headers(),
            Empty::<Bytes>::new(),
            true,
            None,
        )
        .await
    {
        Ok(resp) => relay_upstream_response(resp, Arc::clone(&state.engine.pools().proxy)),
        Err(UpstreamError::Timeout) => empty_response(StatusCode::GATEWAY_TIMEOUT),
        Err(_) => empty_response(StatusCode::BAD_GATEWAY),
    }
}

async fn handle_mcp_delete(state: Arc<ServerState>, req: Request<Incoming>) -> Response<RespBody> {
    let session_id = match single_header_str(req.headers(), "mcp-session-id") {
        HeaderExtract::Missing => None,
        HeaderExtract::Single(s) if !s.is_empty() => Some(s.to_owned()),
        _ => return empty_response(StatusCode::BAD_REQUEST),
    };

    let Some(sid) = session_id else {
        let is_modern = matches!(
            single_header_str(req.headers(), "mcp-protocol-version"),
            HeaderExtract::Single(v) if v == PROTOCOL_VERSION_MODERN
        );
        return if is_modern {
            method_not_allowed("POST, GET")
        } else {
            empty_response(StatusCode::BAD_REQUEST)
        };
    };

    if let Some(upstream) = state.engine.upstream_client() {
        return match upstream
            .forward_raw(
                Method::DELETE,
                None,
                req.headers(),
                Empty::<Bytes>::new(),
                true,
                None,
            )
            .await
        {
            Ok(resp) => relay_upstream_response(resp, Arc::clone(&state.engine.pools().proxy)),
            Err(UpstreamError::Timeout) => empty_response(StatusCode::GATEWAY_TIMEOUT),
            Err(_) => empty_response(StatusCode::BAD_GATEWAY),
        };
    }

    let removed = state
        .legacy_sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&sid);
    if removed {
        empty_response(StatusCode::ACCEPTED)
    } else {
        empty_response(StatusCode::NOT_FOUND)
    }
}

#[derive(Debug)]
enum ProtocolMode {
    LegacyHandshake,
    LegacySession {
        session_id: String,
        protocol_version: Option<String>,
    },
    Modern {
        version: String,
    },
}

struct RpcContext<'a> {
    req_headers: &'a HeaderMap,
    raw_body: Bytes,
    method: &'a str,
    req_id: Option<Value>,
    params: Option<&'a Value>,
}

async fn handle_mcp_post(
    state: Arc<ServerState>,
    req: Request<Incoming>,
    caller: CallerAuth,
) -> Response<RespBody> {
    if !is_json_content_type(req.headers()) {
        return empty_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    if !accepts_json_and_sse(req.headers()) {
        return empty_response(StatusCode::NOT_ACCEPTABLE);
    }

    let prefer_control = matches!(
        single_header_str(req.headers(), "mcp-method"),
        HeaderExtract::Single("events/unsubscribe")
    );
    let (parts, incoming) = req.into_parts();

    let raw_body = match read_request_body_leased(
        incoming,
        MAX_REQUEST_BODY_BYTES,
        state.engine.pools(),
        prefer_control,
        true,
    )
    .await
    {
        Ok(res) => res,
        Err(BodyReadError::TooLarge) => return empty_response(StatusCode::PAYLOAD_TOO_LARGE),
        Err(BodyReadError::Timeout) => return empty_response(StatusCode::REQUEST_TIMEOUT),
        Err(BodyReadError::BudgetExhausted) => {
            return empty_response(StatusCode::SERVICE_UNAVAILABLE);
        }
        Err(BodyReadError::Io(_)) => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                Value::Null,
                -32700,
                "Parse error",
                None,
            );
        }
    };

    let Ok(text) = std::str::from_utf8(&raw_body) else {
        return jsonrpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32700,
            "Parse error",
            None,
        );
    };
    let Ok(parsed) = serde_json::from_str::<Value>(text) else {
        return jsonrpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32700,
            "Parse error",
            None,
        );
    };

    let Some(obj) = parsed.as_object() else {
        return jsonrpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32600,
            "Invalid Request: top-level JSON must be an object",
            None,
        );
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return jsonrpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32600,
            "Invalid Request: missing or unsupported jsonrpc version",
            None,
        );
    }
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        return jsonrpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32600,
            "Invalid Request: missing string method",
            None,
        );
    };

    let req_id: Option<Value> = match obj.get("id") {
        None => None,
        Some(id_val) => {
            if is_valid_jsonrpc_id(id_val) {
                Some(id_val.clone())
            } else {
                return jsonrpc_error(
                    StatusCode::BAD_REQUEST,
                    Value::Null,
                    -32600,
                    "Invalid Request: id must be a non-null string or integer",
                    None,
                );
            }
        }
    };
    let err_id = req_id.clone().unwrap_or(Value::Null);
    let params = obj.get("params");

    let mode = match classify_protocol(&parts.headers, method, req_id.is_some(), params) {
        Ok(m) => m,
        Err((code, msg)) => {
            return jsonrpc_error(StatusCode::BAD_REQUEST, err_id, code, &msg, None);
        }
    };

    let ctx = RpcContext {
        req_headers: &parts.headers,
        raw_body,
        method,
        req_id,
        params,
    };

    match method {
        "initialize" => handle_initialize(state, ctx, mode).await,
        "server/discover" => handle_server_discover(state, ctx, mode).await,
        "events/list" | "events/poll" | "events/stream" | "events/subscribe"
        | "events/unsubscribe" => handle_events_method(state, ctx, mode, caller).await,
        _ => handle_other_method(state, ctx, mode).await,
    }
}

fn classify_protocol(
    headers: &HeaderMap,
    method: &str,
    is_request: bool,
    params: Option<&Value>,
) -> Result<ProtocolMode, (i64, String)> {
    let session_id = match single_header_str(headers, "mcp-session-id") {
        HeaderExtract::Missing => None,
        HeaderExtract::Single(s) if !s.is_empty() => Some(s.to_owned()),
        _ => return Err((-32600, "invalid or duplicate Mcp-Session-Id header".into())),
    };
    let proto_hdr = single_header_str(headers, "mcp-protocol-version");
    let method_hdr = single_header_str(headers, "mcp-method");

    // Branch 1: `initialize` request without session id -> legacy handshake negotiation.
    if session_id.is_none() && is_request && method == "initialize" {
        match proto_hdr {
            HeaderExtract::Missing => {}
            HeaderExtract::DuplicateOrInvalid => {
                return Err((
                    -32600,
                    "invalid or duplicate MCP-Protocol-Version header".into(),
                ));
            }
            HeaderExtract::Single(ver) => {
                let proposed = params
                    .and_then(Value::as_object)
                    .and_then(|p| p.get("protocolVersion"))
                    .and_then(Value::as_str);
                if proposed != Some(ver) {
                    return Err((
                        -32600,
                        "MCP-Protocol-Version header does not match params.protocolVersion".into(),
                    ));
                }
            }
        }
        match method_hdr {
            HeaderExtract::Missing => {}
            HeaderExtract::Single("initialize") => {}
            _ => {
                return Err((
                    -32020,
                    "Mcp-Method header must be single-valued 'initialize'".into(),
                ));
            }
        }
        return Ok(ProtocolMode::LegacyHandshake);
    }

    // Branch 2: request/notification carrying `Mcp-Session-Id` -> legacy session mode.
    if let Some(sid) = session_id {
        let protocol_version = match proto_hdr {
            HeaderExtract::Missing => None,
            HeaderExtract::DuplicateOrInvalid => {
                return Err((
                    -32600,
                    "invalid or duplicate MCP-Protocol-Version header".into(),
                ));
            }
            HeaderExtract::Single(ver) => {
                if ver >= PROTOCOL_VERSION_MODERN || !LEGACY_PROTOCOL_VERSIONS.contains(&ver) {
                    return Err((
                        -32600,
                        format!("unsupported legacy MCP-Protocol-Version '{ver}' with session"),
                    ));
                }
                Some(ver.to_owned())
            }
        };
        if let Some(meta_ver) = params
            .and_then(Value::as_object)
            .and_then(|p| p.get("_meta"))
            .and_then(Value::as_object)
            .and_then(|m| m.get("io.modelcontextprotocol/protocolVersion"))
            .and_then(Value::as_str)
            && meta_ver >= PROTOCOL_VERSION_MODERN
        {
            return Err((
                -32600,
                "modern protocolVersion in params._meta cannot be combined with Mcp-Session-Id"
                    .into(),
            ));
        }
        return Ok(ProtocolMode::LegacySession {
            session_id: sid,
            protocol_version,
        });
    }

    // Branch 3: modern stateless mode.
    let hdr_ver = match proto_hdr {
        HeaderExtract::Single(v) if !v.is_empty() => v,
        _ => {
            return Err((
                -32020,
                "missing or duplicate MCP-Protocol-Version header".into(),
            ));
        }
    };

    if is_request {
        let meta = params
            .and_then(Value::as_object)
            .and_then(|p| p.get("_meta"))
            .and_then(Value::as_object)
            .ok_or_else(|| (-32602, "missing params._meta object".to_string()))?;
        let meta_ver = meta
            .get("io.modelcontextprotocol/protocolVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    -32602,
                    "missing string io.modelcontextprotocol/protocolVersion in params._meta".into(),
                )
            })?;
        let has_caps = meta
            .get("io.modelcontextprotocol/clientCapabilities")
            .is_some_and(Value::is_object);
        if !has_caps {
            return Err((
                -32602,
                "missing object io.modelcontextprotocol/clientCapabilities in params._meta".into(),
            ));
        }
        if hdr_ver != meta_ver {
            return Err((
                -32020,
                "MCP-Protocol-Version header does not match params._meta protocolVersion".into(),
            ));
        }
        match method_hdr {
            HeaderExtract::Single(m) if m == method => {}
            _ => {
                return Err((
                    -32020,
                    "Mcp-Method header is missing, duplicate, or does not match method".into(),
                ));
            }
        }
    } else {
        if hdr_ver != PROTOCOL_VERSION_MODERN {
            return Err((
                -32022,
                format!("unsupported MCP-Protocol-Version '{hdr_ver}'"),
            ));
        }
        match method_hdr {
            HeaderExtract::Single(m) if m == method => {}
            _ => {
                return Err((
                    -32020,
                    "Mcp-Method header is missing, duplicate, or does not match method".into(),
                ));
            }
        }
    }

    Ok(ProtocolMode::Modern {
        version: hdr_ver.to_owned(),
    })
}

async fn handle_initialize(
    state: Arc<ServerState>,
    ctx: RpcContext<'_>,
    mode: ProtocolMode,
) -> Response<RespBody> {
    let Some(id) = ctx.req_id else {
        return jsonrpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32600,
            "initialize must be a JSON-RPC request with id",
            None,
        );
    };
    let profile = state.engine.config().profile;

    if let Some(upstream) = state.engine.upstream_client() {
        return match upstream
            .forward_handshake(ctx.req_headers, ctx.raw_body, profile, None)
            .await
        {
            Ok(hs) => {
                let mut builder = Response::builder().status(hs.status);
                if let Some(h) = builder.headers_mut() {
                    *h = hs.headers;
                }
                builder
                    .body(full_body(hs.body))
                    .unwrap_or_else(|_| empty_response(StatusCode::BAD_GATEWAY))
            }
            Err(UpstreamError::Timeout) => empty_response(StatusCode::GATEWAY_TIMEOUT),
            Err(_) => empty_response(StatusCode::BAD_GATEWAY),
        };
    }

    if matches!(mode, ProtocolMode::LegacySession { .. }) {
        return jsonrpc_error(
            StatusCode::BAD_REQUEST,
            id,
            -32600,
            "Invalid Request: initialize cannot be repeated on an active session",
            None,
        );
    }

    let proposed = ctx
        .params
        .and_then(Value::as_object)
        .and_then(|p| p.get("protocolVersion"))
        .and_then(Value::as_str);
    let negotiated = match proposed {
        Some(v) if LEGACY_PROTOCOL_VERSIONS.contains(&v) => v,
        _ => LATEST_LEGACY_PROTOCOL_VERSION,
    };

    let capabilities = match profile {
        Profile::Chatgpt => json!({ "events": {} }),
        Profile::Sep3415 => json!({}),
    };
    let payload = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": negotiated,
            "capabilities": capabilities,
            "serverInfo": {
                "name": "mcp-hookd",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    });

    let mut resp = json_response(StatusCode::OK, &payload);
    if profile == Profile::Chatgpt {
        let sid = match state
            .legacy_sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .issue()
        {
            Ok(s) => s,
            Err(_) => return empty_response(StatusCode::INTERNAL_SERVER_ERROR),
        };
        if let Ok(val) = HeaderValue::from_str(&sid) {
            resp.headers_mut()
                .insert(HeaderName::from_static("mcp-session-id"), val);
        }
    }
    resp
}

async fn handle_server_discover(
    state: Arc<ServerState>,
    ctx: RpcContext<'_>,
    mode: ProtocolMode,
) -> Response<RespBody> {
    let Some(id) = ctx.req_id else {
        return jsonrpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32600,
            "server/discover must be a JSON-RPC request with id",
            None,
        );
    };
    if matches!(mode, ProtocolMode::LegacySession { .. }) {
        return jsonrpc_error(
            StatusCode::BAD_REQUEST,
            id,
            -32600,
            "Invalid Request: server/discover cannot be called with Mcp-Session-Id",
            None,
        );
    }
    let profile = state.engine.config().profile;

    if let Some(upstream) = state.engine.upstream_client() {
        return match upstream
            .forward_handshake(ctx.req_headers, ctx.raw_body, profile, None)
            .await
        {
            Ok(hs) => {
                let mut builder = Response::builder().status(hs.status);
                if let Some(h) = builder.headers_mut() {
                    *h = hs.headers;
                }
                builder
                    .body(full_body(hs.body))
                    .unwrap_or_else(|_| empty_response(StatusCode::BAD_GATEWAY))
            }
            Err(UpstreamError::Timeout) => empty_response(StatusCode::GATEWAY_TIMEOUT),
            Err(_) => empty_response(StatusCode::BAD_GATEWAY),
        };
    }

    let mut caps = Map::new();
    caps.insert(
        "extensions".into(),
        json!({ "io.modelcontextprotocol/events": { "listChanged": false } }),
    );
    if profile == Profile::Chatgpt {
        caps.insert("events".into(), json!({}));
    }
    let cache_scope = if state.engine.config().auth_context.is_some() {
        "private"
    } else {
        "public"
    };

    let payload = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "resultType": "complete",
            "supportedVersions": [PROTOCOL_VERSION_MODERN],
            "capabilities": Value::Object(caps),
            "ttlMs": 60_000,
            "cacheScope": cache_scope,
            "_meta": {
                "io.modelcontextprotocol/serverInfo": {
                    "name": "mcp-hookd",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        }
    });
    json_response(StatusCode::OK, &payload)
}

async fn handle_events_method(
    state: Arc<ServerState>,
    ctx: RpcContext<'_>,
    mode: ProtocolMode,
    caller: CallerAuth,
) -> Response<RespBody> {
    let RpcContext {
        req_headers,
        raw_body,
        method,
        req_id,
        params,
    } = ctx;
    let profile = state.engine.config().profile;
    let Some(id) = req_id else {
        let status = if matches!(mode, ProtocolMode::LegacySession { .. }) {
            StatusCode::OK
        } else {
            StatusCode::BAD_REQUEST
        };
        return jsonrpc_error(
            status,
            Value::Null,
            -32600,
            "events/* must be a JSON-RPC request with id",
            None,
        );
    };

    let is_legacy = match &mode {
        ProtocolMode::LegacySession {
            session_id,
            protocol_version,
        } => {
            if profile == Profile::Sep3415 || matches!(method, "events/poll" | "events/stream") {
                return jsonrpc_error(StatusCode::OK, id, -32601, "Method not found", None);
            }
            if let Some(upstream) = state.engine.upstream_client() {
                match upstream
                    .ping_session(session_id, protocol_version.as_deref())
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => return empty_response(StatusCode::NOT_FOUND),
                    Err(_) => return empty_response(StatusCode::BAD_GATEWAY),
                }
            } else {
                let alive = state
                    .legacy_sessions
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .touch(session_id);
                if !alive {
                    return empty_response(StatusCode::NOT_FOUND);
                }
            }
            true
        }
        ProtocolMode::Modern { version } => {
            if version != PROTOCOL_VERSION_MODERN {
                return jsonrpc_error(
                    StatusCode::BAD_REQUEST,
                    id,
                    -32022,
                    &format!("Unsupported protocol version '{version}'"),
                    None,
                );
            }
            false
        }
        ProtocolMode::LegacyHandshake => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                id,
                -32600,
                "Invalid protocol state",
                None,
            );
        }
    };

    if matches!(
        method,
        "events/poll" | "events/stream" | "events/subscribe" | "events/unsubscribe"
    ) {
        let params_obj = match params.and_then(Value::as_object) {
            Some(o) => o,
            None => {
                return jsonrpc_error(
                    StatusCode::OK,
                    id,
                    -32602,
                    "params must be a JSON object",
                    None,
                );
            }
        };
        let Some(event_name) = params_obj.get("name").and_then(Value::as_str) else {
            return jsonrpc_error(
                StatusCode::OK,
                id,
                -32602,
                "params.name must be a string",
                None,
            );
        };
        let args_map = match params_obj.get("arguments") {
            None | Some(Value::Null) => None,
            Some(Value::Object(m)) => Some(m),
            Some(_) => {
                return jsonrpc_error(
                    StatusCode::OK,
                    id,
                    -32602,
                    "params.arguments must be an object",
                    None,
                );
            }
        };

        let disallowed = state
            .engine
            .config()
            .upstream
            .as_ref()
            .and_then(|u| u.expose_events.iter().find(|e| e.name == event_name))
            .map(|e| e.disallow_arguments.as_slice())
            .unwrap_or(&[]);

        if let Err(msg) =
            validate_optional_event_routing_headers(req_headers, event_name, args_map, disallowed)
        {
            return jsonrpc_error(StatusCode::BAD_REQUEST, id, -32020, &msg, None);
        }
    }

    match method {
        "events/list" => {
            let cursor = match params {
                None | Some(Value::Null) => None,
                Some(Value::Object(o)) => match o.get("cursor") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) => Some(s.as_str()),
                    Some(_) => {
                        return jsonrpc_error(
                            StatusCode::OK,
                            id,
                            -32602,
                            "params.cursor must be a string",
                            None,
                        );
                    }
                },
                Some(_) => {
                    return jsonrpc_error(
                        StatusCode::OK,
                        id,
                        -32602,
                        "params must be an object",
                        None,
                    );
                }
            };
            match state
                .engine
                .list_events(&caller, is_legacy, cursor, None)
                .await
            {
                Ok(res) => {
                    let mut val = serde_json::to_value(&res).unwrap_or_else(|_| json!({}));
                    attach_result_type(&mut val, !is_legacy);
                    jsonrpc_ok(id, val)
                }
                Err(err) => engine_error_response(id, profile, err),
            }
        }
        "events/poll" | "events/stream" => {
            if let CallerAuth::Delegated {
                auth_ref,
                header_scopes,
            } = &caller
                && let Some(auth_client) = state.engine.auth_client()
            {
                match auth_client.check_cached(auth_ref).await {
                    AuthCheckOutcome::Active(checked) => {
                        let effective = intersect_scopes(header_scopes, &checked.scopes);
                        if checked.resource != auth_client.expected_resource()
                            || checked.expires_at <= unix_now()
                            || effective.is_empty()
                        {
                            return engine_error_response(
                                id,
                                profile,
                                EngineError::Forbidden("delegated authorization rejected".into()),
                            );
                        }
                    }
                    AuthCheckOutcome::Inactive => {
                        return engine_error_response(
                            id,
                            profile,
                            EngineError::Forbidden("delegated authorization inactive".into()),
                        );
                    }
                    AuthCheckOutcome::TransientError(msg) => {
                        return engine_error_response(id, profile, EngineError::Internal(msg));
                    }
                }
            }
            let params_obj = params.and_then(Value::as_object).unwrap();
            let event_name = params_obj.get("name").and_then(Value::as_str).unwrap();
            let args_map = params_obj.get("arguments").and_then(Value::as_object);
            match state
                .engine
                .resolve_event_for_passthrough(event_name, args_map)
                .await
            {
                Ok(PassthroughResolution::NotFound) => jsonrpc_error(
                    StatusCode::OK,
                    id,
                    profile.not_found_code(),
                    &format!("event '{event_name}' not found"),
                    Some(json!({ "kind": "event" })),
                ),
                Ok(PassthroughResolution::IngestUnsupported) => jsonrpc_error(
                    StatusCode::OK,
                    id,
                    -32026,
                    &format!("event '{event_name}' only supports webhook delivery"),
                    None,
                ),
                Ok(PassthroughResolution::DisallowedArgument(arg)) => jsonrpc_error(
                    StatusCode::OK,
                    id,
                    -32602,
                    &format!("argument '{arg}' is disallowed for event '{event_name}'"),
                    None,
                ),
                Ok(PassthroughResolution::UpstreamAllowed) => {
                    let Some(upstream) = state.engine.upstream_client() else {
                        return jsonrpc_error(
                            StatusCode::OK,
                            id,
                            profile.not_found_code(),
                            &format!("event '{event_name}' not found"),
                            Some(json!({ "kind": "event" })),
                        );
                    };
                    match upstream
                        .forward_raw(
                            Method::POST,
                            None,
                            req_headers,
                            Full::new(raw_body),
                            true,
                            None,
                        )
                        .await
                    {
                        Ok(resp) => {
                            relay_upstream_response(resp, Arc::clone(&state.engine.pools().proxy))
                        }
                        Err(UpstreamError::Timeout) => empty_response(StatusCode::GATEWAY_TIMEOUT),
                        Err(_) => empty_response(StatusCode::BAD_GATEWAY),
                    }
                }
                Err(err) => engine_error_response(id, profile, err),
            }
        }
        "events/subscribe" => {
            let sub_req = match parse_subscribe_request(params.and_then(Value::as_object).unwrap())
            {
                Ok(r) => r,
                Err(msg) => return jsonrpc_error(StatusCode::OK, id, -32602, &msg, None),
            };
            match state.engine.subscribe(&caller, sub_req).await {
                Ok(res) => {
                    let mut val = serde_json::to_value(&res).unwrap_or_else(|_| json!({}));
                    attach_result_type(&mut val, !is_legacy);
                    jsonrpc_ok(id, val)
                }
                Err(err) => engine_error_response(id, profile, err),
            }
        }
        "events/unsubscribe" => {
            let unsub_req =
                match parse_unsubscribe_request(params.and_then(Value::as_object).unwrap()) {
                    Ok(r) => r,
                    Err(msg) => return jsonrpc_error(StatusCode::OK, id, -32602, &msg, None),
                };
            match state.engine.unsubscribe(&caller, unsub_req).await {
                Ok(()) => {
                    let mut val = json!({});
                    attach_result_type(&mut val, !is_legacy);
                    jsonrpc_ok(id, val)
                }
                Err(err) => engine_error_response(id, profile, err),
            }
        }
        _ => unreachable!(),
    }
}

async fn handle_other_method(
    state: Arc<ServerState>,
    ctx: RpcContext<'_>,
    mode: ProtocolMode,
) -> Response<RespBody> {
    let RpcContext {
        req_headers,
        raw_body,
        method,
        req_id,
        ..
    } = ctx;
    if let Some(upstream) = state.engine.upstream_client() {
        return match upstream
            .forward_raw(
                Method::POST,
                None,
                req_headers,
                Full::new(raw_body),
                true,
                None,
            )
            .await
        {
            Ok(resp) => relay_upstream_response(resp, Arc::clone(&state.engine.pools().proxy)),
            Err(UpstreamError::Timeout) => empty_response(StatusCode::GATEWAY_TIMEOUT),
            Err(_) => empty_response(StatusCode::BAD_GATEWAY),
        };
    }

    let is_legacy = match &mode {
        ProtocolMode::LegacySession { session_id, .. } => {
            let alive = state
                .legacy_sessions
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .touch(session_id);
            if !alive {
                return empty_response(StatusCode::NOT_FOUND);
            }
            true
        }
        ProtocolMode::Modern { version } => {
            if version != PROTOCOL_VERSION_MODERN {
                return jsonrpc_error(
                    StatusCode::BAD_REQUEST,
                    req_id.unwrap_or(Value::Null),
                    -32022,
                    &format!("Unsupported protocol version '{version}'"),
                    None,
                );
            }
            false
        }
        ProtocolMode::LegacyHandshake => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                req_id.unwrap_or(Value::Null),
                -32600,
                "Invalid protocol state",
                None,
            );
        }
    };

    if req_id.is_none() {
        return empty_response(StatusCode::ACCEPTED);
    }
    let id = req_id.unwrap();
    if method == "ping" {
        let mut val = json!({});
        attach_result_type(&mut val, !is_legacy);
        return jsonrpc_ok(id, val);
    }
    let status = if is_legacy {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    };
    jsonrpc_error(status, id, -32601, "Method not found", None)
}

fn parse_subscribe_request(params: &Map<String, Value>) -> Result<SubscribeRequest, String> {
    let event_name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "params.name must be a string".to_string())?
        .to_owned();
    let arguments = match params.get("arguments") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(_) => return Err("params.arguments must be an object".into()),
    };
    let delivery = params
        .get("delivery")
        .and_then(Value::as_object)
        .ok_or_else(|| "params.delivery must be an object".to_string())?;
    let delivery_mode = delivery
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| "params.delivery.mode must be a string".to_string())?
        .to_owned();
    let delivery_url = delivery
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| "params.delivery.url must be a string".to_string())?
        .to_owned();
    let delivery_secret = delivery
        .get("secret")
        .and_then(Value::as_str)
        .ok_or_else(|| "params.delivery.secret must be a string".to_string())?;

    let ttl_ms = match params.get("ttlMs") {
        None => None,
        Some(Value::Null) => Some(None),
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or_else(|| "params.ttlMs must be a non-negative integer or null".to_string())?;
            Some(Some(n))
        }
    };
    let cursor = match params.get("cursor") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err("params.cursor must be a string or null".into()),
    };
    let max_age_ms = match params.get("maxAgeMs") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or_else(|| "params.maxAgeMs must be a non-negative integer".to_string())?;
            Some(n)
        }
    };

    Ok(SubscribeRequest {
        event_name,
        arguments,
        delivery_mode,
        delivery_url,
        delivery_secret: SecretString::new(delivery_secret),
        ttl_ms,
        cursor,
        max_age_ms,
    })
}

fn parse_unsubscribe_request(params: &Map<String, Value>) -> Result<UnsubscribeRequest, String> {
    let event_name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "params.name must be a string".to_string())?
        .to_owned();
    let arguments = match params.get("arguments") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(_) => return Err("params.arguments must be an object".into()),
    };

    let (delivery_mode, delivery_url) = match params.get("delivery") {
        Some(Value::Object(delivery)) => {
            let mode = match delivery.get("mode") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) => Some(s.clone()),
                Some(_) => return Err("params.delivery.mode must be a string".into()),
            };
            let url = delivery
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| "params.delivery.url must be a string".to_string())?
                .to_owned();
            (mode, url)
        }
        None | Some(Value::Null) => {
            let url = params
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| "params.delivery.url must be provided".to_string())?
                .to_owned();
            (None, url)
        }
        Some(_) => return Err("params.delivery must be an object".into()),
    };

    Ok(UnsubscribeRequest {
        event_name,
        arguments,
        delivery_mode,
        delivery_url,
    })
}

enum HeaderExtract<'a> {
    Missing,
    Single(&'a str),
    DuplicateOrInvalid,
}

fn single_header_str<'a>(headers: &'a HeaderMap, name: &str) -> HeaderExtract<'a> {
    let mut iter = headers.get_all(name).iter();
    let Some(first) = iter.next() else {
        return HeaderExtract::Missing;
    };
    if iter.next().is_some() {
        return HeaderExtract::DuplicateOrInvalid;
    }
    match first.to_str() {
        Ok(s) => HeaderExtract::Single(s),
        Err(_) => HeaderExtract::DuplicateOrInvalid,
    }
}

fn verify_bearer_token(headers: &HeaderMap, tokens: &[SecretString]) -> Option<usize> {
    let raw = match single_header_str(headers, header::AUTHORIZATION.as_str()) {
        HeaderExtract::Single(s) => s,
        _ => return None,
    };
    let presented = raw.strip_prefix("Bearer ")?;
    if presented.is_empty() {
        return None;
    }
    let mut matched = None;
    for (idx, candidate) in tokens.iter().enumerate() {
        if constant_time_token_eq(presented.as_bytes(), candidate.expose().as_bytes())
            && matched.is_none()
        {
            matched = Some(idx);
        }
    }
    matched
}

fn extract_caller_auth(
    headers: &HeaderMap,
    token_slot: usize,
    delegated: bool,
) -> Result<CallerAuth, ()> {
    if !delegated {
        return Ok(CallerAuth::StaticSlot(token_slot));
    }
    let auth_ref = match single_header_str(headers, "x-authorization-ref") {
        HeaderExtract::Single(s) if !s.trim().is_empty() => s.to_owned(),
        _ => return Err(()),
    };
    let scope_raw = match single_header_str(headers, "x-authorization-scope") {
        HeaderExtract::Single(s) => s,
        _ => return Err(()),
    };
    let header_scopes = scope_raw
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect();
    Ok(CallerAuth::Delegated {
        auth_ref,
        header_scopes,
    })
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    let HeaderExtract::Single(raw) = single_header_str(headers, header::CONTENT_TYPE.as_str())
    else {
        return false;
    };
    raw.split(';')
        .next()
        .is_some_and(|main| main.trim().eq_ignore_ascii_case("application/json"))
}

fn accepts_json_and_sse(headers: &HeaderMap) -> bool {
    let mut has_json = false;
    let mut has_sse = false;
    for val in headers.get_all(header::ACCEPT) {
        let Ok(text) = val.to_str() else {
            continue;
        };
        for item in text.split(',') {
            let main = item.split(';').next().unwrap_or("").trim();
            if main.eq_ignore_ascii_case("application/json") {
                has_json = true;
            } else if main.eq_ignore_ascii_case("text/event-stream") {
                has_sse = true;
            }
        }
    }
    has_json && has_sse
}

fn is_valid_jsonrpc_id(val: &Value) -> bool {
    match val {
        Value::String(_) => true,
        Value::Number(n) => n.as_i64().is_some() || n.as_u64().is_some(),
        _ => false,
    }
}

enum BodyReadError {
    TooLarge,
    Timeout,
    BudgetExhausted,
    Io(String),
}

async fn read_request_body_leased<B>(
    mut body: B,
    limit: usize,
    pools: &MemoryPools,
    prefer_control: bool,
    allow_control_fallback: bool,
) -> Result<Bytes, BodyReadError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let mut lease = if prefer_control {
        pools
            .control
            .try_acquire(0)
            .ok_or(BodyReadError::BudgetExhausted)?
    } else {
        pools
            .proxy
            .try_acquire(0)
            .ok_or(BodyReadError::BudgetExhausted)?
    };
    let mut using_control = prefer_control;

    let read_fut = async {
        let mut out = BytesMut::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| BodyReadError::Io(e.to_string()))?;
            if let Ok(chunk) = frame.into_data() {
                let next_len = out.len() + chunk.len();
                if next_len > limit {
                    return Err(BodyReadError::TooLarge);
                }
                if using_control && !prefer_control && next_len > CONTROL_FALLBACK_MAX_BYTES {
                    return Err(BodyReadError::BudgetExhausted);
                }
                if !lease.grow(chunk.len()) {
                    // Fall back to the reserved control pool only for small MCP control requests.
                    if allow_control_fallback
                        && !using_control
                        && next_len <= CONTROL_FALLBACK_MAX_BYTES
                        && let Some(ctrl_lease) = pools.control.try_acquire(next_len)
                    {
                        lease = ctrl_lease;
                        using_control = true;
                    } else {
                        return Err(BodyReadError::BudgetExhausted);
                    }
                }
                out.put_slice(&chunk);
            }
        }
        Ok(lease_bytes(out.freeze(), lease))
    };

    tokio::time::timeout(BODY_READ_TIMEOUT, read_fut)
        .await
        .map_err(|_| BodyReadError::Timeout)?
}

fn relay_upstream_response(
    resp: Response<Incoming>,
    budget: Arc<ByteBudget>,
) -> Response<RespBody> {
    let (parts, body) = resp.into_parts();
    let headers = strip_hop_by_hop_response_headers(&parts.headers);
    let mut builder = Response::builder().status(parts.status);
    if let Some(h) = builder.headers_mut() {
        *h = headers;
    }
    let stream = ProxyBody::new(body, budget).boxed();
    builder
        .body(stream)
        .unwrap_or_else(|_| empty_response(StatusCode::BAD_GATEWAY))
}

fn attach_result_type(val: &mut Value, modern: bool) {
    if modern && let Some(obj) = val.as_object_mut() {
        obj.insert("resultType".into(), Value::String("complete".into()));
    }
}

fn engine_error_response(id: Value, profile: Profile, err: EngineError) -> Response<RespBody> {
    let code = err.to_jsonrpc_code(profile);
    let data = err.error_data();
    let msg = err.to_string();
    jsonrpc_error(StatusCode::OK, id, code, &msg, data)
}

fn jsonrpc_ok(id: Value, result: Value) -> Response<RespBody> {
    json_response(
        StatusCode::OK,
        &json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result
        }),
    )
}

fn jsonrpc_error(
    status: StatusCode,
    id: Value,
    code: i64,
    message: &str,
    data: Option<Value>,
) -> Response<RespBody> {
    let mut err_obj = Map::new();
    err_obj.insert("code".into(), json!(code));
    err_obj.insert("message".into(), Value::String(message.to_owned()));
    if let Some(d) = data {
        err_obj.insert("data".into(), d);
    }
    json_response(
        status,
        &json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": Value::Object(err_obj)
        }),
    )
}

fn json_response<T: serde::Serialize>(status: StatusCode, body: &T) -> Response<RespBody> {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, bytes.len())
        .body(full_body(Bytes::from(bytes)))
        .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

fn empty_response(status: StatusCode) -> Response<RespBody> {
    Response::builder()
        .status(status)
        .body(
            Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

fn unauthorized_response() -> Response<RespBody> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, "Bearer")
        .body(
            Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

fn method_not_allowed(allow: &'static str) -> Response<RespBody> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(header::ALLOW, allow)
        .body(
            Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap()
}

fn full_body(bytes: Bytes) -> RespBody {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body::Frame;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct Chunks(VecDeque<Bytes>);

    impl Body for Chunks {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            Poll::Ready(self.0.pop_front().map(|chunk| Ok(Frame::data(chunk))))
        }
    }

    #[tokio::test]
    async fn fallback_control_request_stays_small_across_body_chunks() {
        let pools = MemoryPools::from_quotas(&QuotaConfig {
            proxy_byte_budget: 0,
            ..Default::default()
        });
        let chunks = || {
            Chunks(
                [
                    Bytes::from(vec![0; 4096]),
                    Bytes::from(vec![0; CONTROL_FALLBACK_MAX_BYTES]),
                ]
                .into(),
            )
        };
        let result =
            read_request_body_leased(chunks(), MAX_REQUEST_BODY_BYTES, &pools, false, true).await;
        assert!(matches!(result, Err(BodyReadError::BudgetExhausted)));
        assert_eq!(pools.control.used(), 0);

        let body =
            read_request_body_leased(chunks(), MAX_REQUEST_BODY_BYTES, &pools, true, true).await;
        let body = match body {
            Ok(body) => body,
            Err(_) => panic!("explicit control request should use its full budget"),
        };
        assert_eq!(pools.control.used(), body.len());
        let retained = body.clone();
        drop(body);
        assert_eq!(pools.control.used(), retained.len());
        drop(retained);
        assert_eq!(pools.control.used(), 0);
    }
}
