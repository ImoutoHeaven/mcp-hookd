//! Single-port HTTP facade: route isolation, streaming MCP method dispatch, passthrough proxy,
//! `/v1/events` ingest endpoint, and graceful shutdown (spec §2, §4, §5).

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
use crate::proxy_body::{LeasedBuffer, PrefixedBody, ProxyBody};
use crate::types::{
    ByteBudget, LATEST_LEGACY_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSIONS, LEGACY_SESSION_IDLE_SECS,
    MAX_INGEST_BODY_BYTES, MAX_LEGACY_SESSIONS, MAX_REQUEST_BODY_BYTES, MemoryPools,
    PROTOCOL_VERSION_MODERN, Profile, QuotaConfig, SecretString, constant_time_token_eq,
    random_base64url, unix_now,
};
use crate::upstream::UpstreamError;
use bytes::Bytes;
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
const MAX_JSON_SCAN_NESTING: usize = 4096;

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
    force_cancel: CancellationToken,
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

    /// Stop new work, drain HTTP until the shared deadline, then persist the engine.
    pub async fn shutdown(self) -> Result<(), String> {
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(self.engine.quotas().drain_timeout_secs);
        self.engine.begin_shutdown();
        self.cancel.cancel();
        let _ = self.accept_task.await;
        self.conn_tracker.close();
        if tokio::time::timeout_at(deadline, self.conn_tracker.wait())
            .await
            .is_err()
        {
            self.force_cancel.cancel();
            self.conn_tracker.wait().await;
        }
        self.engine.shutdown_until(deadline).await
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
    let force_cancel = CancellationToken::new();
    let conn_tracker = TaskTracker::new();
    let accept_cancel = cancel.clone();
    let accept_force_cancel = force_cancel.clone();
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
            let conn_force_cancel = accept_force_cancel.clone();
            accept_tracker.spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    let state = Arc::clone(&state);
                    async move { Ok::<_, Infallible>(handle_request(state, req).await) }
                });
                let conn = http1::Builder::new().serve_connection(io, svc);
                tokio::pin!(conn);
                tokio::select! {
                    biased;
                    _ = conn_force_cancel.cancelled() => {}
                    _ = conn.as_mut() => {}
                    _ = conn_cancel.cancelled() => {
                        conn.as_mut().graceful_shutdown();
                        tokio::select! {
                            biased;
                            _ = conn_force_cancel.cancelled() => {}
                            _ = conn => {}
                        }
                    }
                }
            });
        }
    });

    Ok(RunningServer {
        bound_addr,
        engine,
        cancel,
        force_cancel,
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

    if raw_path == "/healthz" {
        return match method {
            Method::GET => json_response(StatusCode::OK, &json!({ "ok": true })),
            Method::HEAD => empty_response(StatusCode::OK),
            _ => method_not_allowed("GET, HEAD"),
        };
    }

    if raw_path == "/v1/events" {
        if state.engine.config().ingest.is_none() {
            return empty_response(StatusCode::NOT_FOUND);
        }
        return handle_ingest(state, req).await;
    }

    if raw_path == state.engine.config().resource_path {
        return handle_mcp(state, req).await;
    }

    if raw_path == "/" {
        return empty_response(StatusCode::NOT_FOUND);
    }

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

    match state.engine.ingest_event(token_slot, &body).await {
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
    let profile = cfg.profile;

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
        Err(()) => return empty_response(StatusCode::BAD_REQUEST),
    };

    match *req.method() {
        Method::GET => {
            if let Err(err) = state.engine.verify_caller(&caller, false).await {
                return auth_error_response(profile, None, err);
            }
            handle_mcp_get(state, req).await
        }
        Method::DELETE => {
            if let Err(err) = state.engine.verify_caller(&caller, false).await {
                return auth_error_response(profile, None, err);
            }
            handle_mcp_delete(state, req).await
        }
        Method::POST => handle_mcp_post(state, req, caller).await,
        _ => {
            if let Err(err) = state.engine.verify_caller(&caller, false).await {
                return auth_error_response(profile, None, err);
            }
            method_not_allowed("POST, GET, DELETE")
        }
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
    if let Some(upstream) = state.engine.upstream_client() {
        let (parts, incoming) = req.into_parts();
        return match upstream
            .forward_raw(
                Method::DELETE,
                None,
                &parts.headers,
                ProxyBody::new(incoming, Arc::clone(&state.engine.pools().proxy)),
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

fn is_intercepted_method(method: &str) -> bool {
    matches!(
        method,
        "initialize"
            | "server/discover"
            | "events/list"
            | "events/poll"
            | "events/stream"
            | "events/subscribe"
            | "events/unsubscribe"
    )
}

async fn forward_post_to_upstream<B>(
    state: &ServerState,
    headers: &HeaderMap,
    body: B,
) -> Response<RespBody>
where
    B: Body<Data = Bytes> + Send + Sync + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let Some(upstream) = state.engine.upstream_client() else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    match upstream
        .forward_raw(Method::POST, None, headers, body, true, None)
        .await
    {
        Ok(resp) => relay_upstream_response(resp, Arc::clone(&state.engine.pools().proxy)),
        Err(UpstreamError::Timeout) => empty_response(StatusCode::GATEWAY_TIMEOUT),
        Err(_) => empty_response(StatusCode::BAD_GATEWAY),
    }
}

async fn handle_mcp_post(
    state: Arc<ServerState>,
    req: Request<Incoming>,
    caller: CallerAuth,
) -> Response<RespBody> {
    let has_upstream = state.engine.upstream_client().is_some();
    let profile = state.engine.config().profile;
    let live_from_hdr = header_mentions_method(req.headers(), "events/subscribe");

    if has_non_identity_content_encoding(req.headers()) {
        if let Err(err) = state.engine.verify_caller(&caller, live_from_hdr).await {
            return auth_error_response(profile, None, err);
        }
        if !has_upstream || header_targets_intercepted_method(req.headers()) {
            return empty_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        let (parts, incoming) = req.into_parts();
        let body = ProxyBody::new(incoming, Arc::clone(&state.engine.pools().proxy));
        return forward_post_to_upstream(&state, &parts.headers, body).await;
    }

    if !is_json_content_type(req.headers()) {
        if let Err(err) = state.engine.verify_caller(&caller, live_from_hdr).await {
            return auth_error_response(profile, None, err);
        }
        if !has_upstream {
            return empty_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
        let (parts, incoming) = req.into_parts();
        let body = ProxyBody::new(incoming, Arc::clone(&state.engine.pools().proxy));
        return forward_post_to_upstream(&state, &parts.headers, body).await;
    }

    if !has_upstream {
        return handle_mcp_post_local_only(state, req, caller).await;
    }

    let prefer_control = matches!(
        single_header_str(req.headers(), "mcp-method"),
        HeaderExtract::Single("events/unsubscribe")
    );
    let (parts, incoming) = req.into_parts();

    let scanned = match scan_or_buffer_json_body(
        incoming,
        MAX_REQUEST_BODY_BYTES,
        state.engine.pools(),
        prefer_control,
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
            if let Err(err) = state.engine.verify_caller(&caller, live_from_hdr).await {
                return auth_error_response(profile, None, err);
            }
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                Value::Null,
                -32700,
                "Parse error",
                None,
            );
        }
    };

    match scanned {
        ScannedPostBody::PassthroughStream {
            prefix,
            rest,
            eof,
            captured_id,
        } => {
            if let Err(err) = state.engine.verify_caller(&caller, false).await {
                return auth_error_response(profile, captured_id, err);
            }
            if eof {
                forward_post_to_upstream(&state, &parts.headers, Full::new(prefix)).await
            } else {
                let body = PrefixedBody::new(
                    prefix,
                    ProxyBody::new(rest, Arc::clone(&state.engine.pools().proxy)),
                );
                forward_post_to_upstream(&state, &parts.headers, body).await
            }
        }
        ScannedPostBody::Malformed { captured_id } => {
            if let Err(err) = state.engine.verify_caller(&caller, live_from_hdr).await {
                return auth_error_response(profile, captured_id, err);
            }
            jsonrpc_error(
                StatusCode::BAD_REQUEST,
                Value::Null,
                -32700,
                "Parse error",
                None,
            )
        }
        ScannedPostBody::DuplicateMethod { captured_id } => {
            if let Err(err) = state.engine.verify_caller(&caller, true).await {
                return auth_error_response(profile, captured_id, err);
            }
            jsonrpc_error(
                StatusCode::BAD_REQUEST,
                Value::Null,
                -32600,
                "Invalid Request: duplicate method field",
                None,
            )
        }
        ScannedPostBody::Buffered(raw_body) => {
            handle_buffered_upstream_post(state, parts.headers, raw_body, caller).await
        }
    }
}

async fn handle_buffered_upstream_post(
    state: Arc<ServerState>,
    req_headers: HeaderMap,
    raw_body: Bytes,
    caller: CallerAuth,
) -> Response<RespBody> {
    let profile = state.engine.config().profile;
    let live_from_hdr = header_mentions_method(&req_headers, "events/subscribe");

    let Ok(text) = std::str::from_utf8(&raw_body) else {
        if let Err(err) = state.engine.verify_caller(&caller, live_from_hdr).await {
            return auth_error_response(profile, None, err);
        }
        return jsonrpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32700,
            "Parse error",
            None,
        );
    };
    let Ok(parsed) = serde_json::from_str::<Value>(text) else {
        if let Err(err) = state.engine.verify_caller(&caller, live_from_hdr).await {
            return auth_error_response(profile, None, err);
        }
        return jsonrpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32700,
            "Parse error",
            None,
        );
    };

    let Some(obj) = parsed.as_object() else {
        if let Err(err) = state.engine.verify_caller(&caller, false).await {
            return auth_error_response(profile, None, err);
        }
        return forward_post_to_upstream(&state, &req_headers, Full::new(raw_body)).await;
    };

    let method = match obj.get("method") {
        None => {
            let valid_id = obj.get("id").filter(|v| is_valid_jsonrpc_id(v)).cloned();
            if let Err(err) = state.engine.verify_caller(&caller, false).await {
                return auth_error_response(profile, valid_id, err);
            }
            return forward_post_to_upstream(&state, &req_headers, Full::new(raw_body)).await;
        }
        Some(Value::String(s)) => s.as_str(),
        Some(_) => {
            let valid_id = obj.get("id").filter(|v| is_valid_jsonrpc_id(v)).cloned();
            if let Err(err) = state.engine.verify_caller(&caller, live_from_hdr).await {
                return auth_error_response(profile, valid_id, err);
            }
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                Value::Null,
                -32600,
                "Invalid Request: method must be a string",
                None,
            );
        }
    };

    if !is_intercepted_method(method) {
        let valid_id = obj.get("id").filter(|v| is_valid_jsonrpc_id(v)).cloned();
        if let Err(err) = state.engine.verify_caller(&caller, false).await {
            return auth_error_response(profile, valid_id, err);
        }
        return forward_post_to_upstream(&state, &req_headers, Full::new(raw_body)).await;
    }

    let valid_id = obj.get("id").filter(|v| is_valid_jsonrpc_id(v)).cloned();
    let live = method == "events/subscribe";
    if let Err(err) = state.engine.verify_caller(&caller, live).await {
        return auth_error_response(profile, valid_id, err);
    }

    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return jsonrpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32600,
            "Invalid Request: missing or unsupported jsonrpc version",
            None,
        );
    }

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
    let params = obj.get("params");

    match method {
        "initialize" | "server/discover" => {
            if req_id.is_none() {
                return jsonrpc_error(
                    StatusCode::BAD_REQUEST,
                    Value::Null,
                    -32600,
                    &format!("{method} must be a JSON-RPC request with id"),
                    None,
                );
            }
            let Some(upstream) = state.engine.upstream_client() else {
                return empty_response(StatusCode::BAD_GATEWAY);
            };
            match upstream
                .forward_handshake(&req_headers, raw_body, profile, None)
                .await
            {
                Ok(hs) => {
                    let mut builder = Response::builder().status(hs.status);
                    if let Some(h) = builder.headers_mut() {
                        *h = hs.headers;
                    }
                    builder
                        .body(hs.body)
                        .unwrap_or_else(|_| empty_response(StatusCode::BAD_GATEWAY))
                }
                Err(UpstreamError::Timeout) => empty_response(StatusCode::GATEWAY_TIMEOUT),
                Err(_) => empty_response(StatusCode::BAD_GATEWAY),
            }
        }
        "events/poll" | "events/stream" => {
            let Some(id) = req_id else {
                return jsonrpc_error(
                    StatusCode::BAD_REQUEST,
                    Value::Null,
                    -32600,
                    "events/* must be a JSON-RPC request with id",
                    None,
                );
            };
            match single_header_str(&req_headers, "mcp-method") {
                HeaderExtract::Missing => {}
                HeaderExtract::Single(m) if m == method => {}
                _ => {
                    return jsonrpc_error(
                        StatusCode::BAD_REQUEST,
                        id,
                        -32020,
                        "Mcp-Method header is duplicate or does not match method",
                        None,
                    );
                }
            }
            handle_upstream_events_passthrough(&state, &req_headers, raw_body, id, params).await
        }
        "events/list" | "events/subscribe" | "events/unsubscribe" => {
            if !accepts_json_and_sse(&req_headers) {
                return empty_response(StatusCode::NOT_ACCEPTABLE);
            }
            let err_id = req_id.clone().unwrap_or(Value::Null);
            let mode = match classify_protocol(&req_headers, method, req_id.is_some(), params) {
                Ok(m) => m,
                Err((code, msg)) => {
                    return jsonrpc_error(StatusCode::BAD_REQUEST, err_id, code, &msg, None);
                }
            };
            let ctx = RpcContext {
                req_headers: &req_headers,
                raw_body,
                method,
                req_id,
                params,
            };
            handle_events_method(state, ctx, mode, caller).await
        }
        _ => unreachable!(),
    }
}

async fn validate_event_params_and_routing_headers<'a>(
    state: &ServerState,
    req_headers: &HeaderMap,
    id: &Value,
    params: Option<&'a Value>,
) -> Result<(&'a str, Option<&'a Map<String, Value>>), Response<RespBody>> {
    let profile = state.engine.config().profile;
    let Some(params_obj) = params.and_then(Value::as_object) else {
        return Err(jsonrpc_error(
            StatusCode::OK,
            id.clone(),
            -32602,
            "params must be a JSON object",
            None,
        ));
    };
    let Some(event_name) = params_obj.get("name").and_then(Value::as_str) else {
        return Err(jsonrpc_error(
            StatusCode::OK,
            id.clone(),
            -32602,
            "params.name must be a string",
            None,
        ));
    };
    let args_map = match params_obj.get("arguments") {
        None | Some(Value::Null) => None,
        Some(Value::Object(m)) => Some(m),
        Some(_) => {
            return Err(jsonrpc_error(
                StatusCode::OK,
                id.clone(),
                -32602,
                "params.arguments must be an object",
                None,
            ));
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

    let input_schema = if req_headers
        .keys()
        .any(|name| name.as_str().starts_with("mcp-param-"))
    {
        match state.engine.routing_input_schema(event_name).await {
            Ok(schema) => schema,
            Err(err) => return Err(engine_error_response(id.clone(), profile, err)),
        }
    } else {
        None
    };

    if let Err(msg) = validate_optional_event_routing_headers(
        req_headers,
        event_name,
        args_map,
        disallowed,
        input_schema.as_ref(),
    ) {
        return Err(jsonrpc_error(
            StatusCode::BAD_REQUEST,
            id.clone(),
            -32020,
            &msg,
            None,
        ));
    }

    Ok((event_name, args_map))
}

async fn handle_upstream_events_passthrough(
    state: &ServerState,
    req_headers: &HeaderMap,
    raw_body: Bytes,
    id: Value,
    params: Option<&Value>,
) -> Response<RespBody> {
    let profile = state.engine.config().profile;
    let (event_name, args_map) =
        match validate_event_params_and_routing_headers(state, req_headers, &id, params).await {
            Ok(pair) => pair,
            Err(resp) => return resp,
        };

    match state
        .engine
        .resolve_event_for_passthrough(event_name, args_map)
        .await
    {
        Ok(PassthroughResolution::IngestUnsupported) => jsonrpc_error(
            StatusCode::OK,
            id,
            profile.unsupported_code(),
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
            forward_post_to_upstream(state, req_headers, Full::new(raw_body)).await
        }
        Ok(PassthroughResolution::NotFound) => jsonrpc_error(
            StatusCode::OK,
            id,
            profile.not_found_code(),
            &format!("event '{event_name}' not found"),
            Some(json!({ "kind": "event" })),
        ),
        Err(err) => engine_error_response(id, profile, err),
    }
}

async fn handle_mcp_post_local_only(
    state: Arc<ServerState>,
    req: Request<Incoming>,
    caller: CallerAuth,
) -> Response<RespBody> {
    let profile = state.engine.config().profile;
    let live_from_hdr = header_mentions_method(req.headers(), "events/subscribe");

    if !accepts_json_and_sse(req.headers()) {
        if let Err(err) = state.engine.verify_caller(&caller, live_from_hdr).await {
            return auth_error_response(profile, None, err);
        }
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
            if let Err(err) = state.engine.verify_caller(&caller, live_from_hdr).await {
                return auth_error_response(profile, None, err);
            }
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
        if let Err(err) = state.engine.verify_caller(&caller, live_from_hdr).await {
            return auth_error_response(profile, None, err);
        }
        return jsonrpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32700,
            "Parse error",
            None,
        );
    };
    let Ok(parsed) = serde_json::from_str::<Value>(text) else {
        if let Err(err) = state.engine.verify_caller(&caller, live_from_hdr).await {
            return auth_error_response(profile, None, err);
        }
        return jsonrpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32700,
            "Parse error",
            None,
        );
    };

    let Some(obj) = parsed.as_object() else {
        if let Err(err) = state.engine.verify_caller(&caller, live_from_hdr).await {
            return auth_error_response(profile, None, err);
        }
        return jsonrpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32600,
            "Invalid Request: top-level JSON must be an object",
            None,
        );
    };

    let valid_id = obj.get("id").filter(|v| is_valid_jsonrpc_id(v)).cloned();
    let live = obj.get("method").and_then(Value::as_str) == Some("events/subscribe");
    if let Err(err) = state.engine.verify_caller(&caller, live).await {
        return auth_error_response(profile, valid_id, err);
    }

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

    if matches!(method, "events/subscribe" | "events/unsubscribe")
        && let Err(resp) =
            validate_event_params_and_routing_headers(&state, req_headers, &id, params).await
    {
        return resp;
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
            handle_upstream_events_passthrough(&state, req_headers, raw_body, id, params).await
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
    let RpcContext { method, req_id, .. } = ctx;
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

fn is_valid_oauth_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
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
    let mut header_scopes = Vec::new();
    for tok in scope_raw.split_whitespace() {
        if !is_valid_oauth_scope_token(tok) {
            return Err(());
        }
        header_scopes.push(tok.to_owned());
    }
    Ok(CallerAuth::Delegated {
        auth_ref,
        header_scopes,
    })
}

fn has_non_identity_content_encoding(headers: &HeaderMap) -> bool {
    let mut saw_any = false;
    for val in headers.get_all(header::CONTENT_ENCODING) {
        saw_any = true;
        let Ok(raw) = val.to_str() else {
            return true;
        };
        let mut saw_token = false;
        for tok in raw.split(',') {
            let trimmed = tok.trim();
            if trimmed.is_empty() {
                return true;
            }
            saw_token = true;
            if !trimmed.eq_ignore_ascii_case("identity") {
                return true;
            }
        }
        if !saw_token {
            return true;
        }
    }
    let _ = saw_any;
    false
}

fn header_mentions_method(headers: &HeaderMap, target: &str) -> bool {
    headers
        .get_all("mcp-method")
        .iter()
        .any(|v| v.to_str().ok().is_some_and(|s| s.trim() == target))
}

fn header_targets_intercepted_method(headers: &HeaderMap) -> bool {
    headers
        .get_all("mcp-method")
        .iter()
        .any(|v| v.to_str().map_or(true, |s| is_intercepted_method(s.trim())))
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

fn parse_qvalue_milli(raw: &str) -> Option<u16> {
    if let Some(frac) = raw.strip_prefix("0.") {
        if frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut val = 0u16;
        let mut scale = 100u16;
        for b in frac.bytes() {
            val += u16::from(b - b'0') * scale;
            scale /= 10;
        }
        Some(val)
    } else if raw == "0" {
        Some(0)
    } else if raw == "1" {
        Some(1000)
    } else if let Some(zeros) = raw.strip_prefix("1.") {
        (zeros.len() <= 3 && zeros.bytes().all(|b| b == b'0')).then_some(1000)
    } else {
        None
    }
}

fn accepts_media_type(headers: &HeaderMap, target_type: &str, target_sub: &str) -> bool {
    let mut best: Option<(u8, u16)> = None;
    for val in headers.get_all(header::ACCEPT) {
        let Ok(text) = val.to_str() else {
            return false;
        };
        for item in text.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let mut parts = item.split(';');
            let media = parts.next().unwrap_or("").trim();
            let Some((ty, sub)) = media.split_once('/') else {
                return false;
            };
            let ty = ty.trim();
            let sub = sub.trim();
            if ty.is_empty() || sub.is_empty() {
                return false;
            }

            let mut q_milli = 1000u16;
            for param in parts {
                let param = param.trim();
                if param.is_empty() {
                    continue;
                }
                if let Some((k, v)) = param.split_once('=')
                    && k.trim().eq_ignore_ascii_case("q")
                {
                    let Some(parsed_q) = parse_qvalue_milli(v.trim()) else {
                        return false;
                    };
                    q_milli = parsed_q;
                }
            }

            let specificity =
                if ty.eq_ignore_ascii_case(target_type) && sub.eq_ignore_ascii_case(target_sub) {
                    3u8
                } else if ty.eq_ignore_ascii_case(target_type) && sub == "*" {
                    2u8
                } else if ty == "*" && sub == "*" {
                    1u8
                } else {
                    continue;
                };

            best = Some(match best {
                None => (specificity, q_milli),
                Some((cur_spec, cur_q)) => {
                    if specificity > cur_spec {
                        (specificity, q_milli)
                    } else if specificity == cur_spec {
                        (cur_spec, cur_q.min(q_milli))
                    } else {
                        (cur_spec, cur_q)
                    }
                }
            });
        }
    }
    best.is_some_and(|(_, q)| q > 0)
}

fn accepts_json_and_sse(headers: &HeaderMap) -> bool {
    accepts_media_type(headers, "application", "json")
        && accepts_media_type(headers, "text", "event-stream")
}

fn is_valid_jsonrpc_id(val: &Value) -> bool {
    match val {
        Value::String(_) => true,
        Value::Number(n) => n.as_i64().is_some() || n.as_u64().is_some(),
        _ => false,
    }
}

#[derive(Clone, Copy)]
enum EscapeState {
    None,
    Backslash,
    Unicode {
        digits: u8,
        value: u16,
        high_surrogate: Option<u16>,
    },
    SurrogateBackslash(u16),
    SurrogateU(u16),
}

struct StringCollector {
    buf: Vec<u8>,
    cap: usize,
    overflowed: bool,
    escape: EscapeState,
}

impl StringCollector {
    fn new(cap: usize) -> Self {
        Self {
            buf: Vec::new(),
            cap,
            overflowed: false,
            escape: EscapeState::None,
        }
    }

    fn push_byte(&mut self, b: u8) {
        if self.overflowed {
            return;
        }
        if self.buf.len() < self.cap {
            self.buf.push(b);
        } else {
            self.overflowed = true;
        }
    }

    fn push_char(&mut self, ch: char) {
        if self.overflowed {
            return;
        }
        let mut tmp = [0u8; 4];
        let encoded = ch.encode_utf8(&mut tmp).as_bytes();
        if self.buf.len() + encoded.len() <= self.cap {
            self.buf.extend_from_slice(encoded);
        } else {
            self.overflowed = true;
        }
    }

    fn feed_byte(&mut self, b: u8) -> Result<bool, ()> {
        match self.escape {
            EscapeState::None => match b {
                b'"' => Ok(true),
                b'\\' => {
                    self.escape = EscapeState::Backslash;
                    Ok(false)
                }
                0x00..=0x1f => Err(()),
                _ => {
                    self.push_byte(b);
                    Ok(false)
                }
            },
            EscapeState::Backslash => {
                let decoded = match b {
                    b'"' => b'"',
                    b'\\' => b'\\',
                    b'/' => b'/',
                    b'b' => 0x08,
                    b'f' => 0x0c,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'u' => {
                        self.escape = EscapeState::Unicode {
                            digits: 0,
                            value: 0,
                            high_surrogate: None,
                        };
                        return Ok(false);
                    }
                    _ => return Err(()),
                };
                self.push_byte(decoded);
                self.escape = EscapeState::None;
                Ok(false)
            }
            EscapeState::Unicode {
                digits,
                value,
                high_surrogate,
            } => {
                let nibble = match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    b'A'..=b'F' => b - b'A' + 10,
                    _ => return Err(()),
                };
                let next_val = (value << 4) | u16::from(nibble);
                if digits + 1 < 4 {
                    self.escape = EscapeState::Unicode {
                        digits: digits + 1,
                        value: next_val,
                        high_surrogate,
                    };
                    return Ok(false);
                }
                if let Some(hi) = high_surrogate {
                    if !(0xdc00..=0xdfff).contains(&next_val) {
                        return Err(());
                    }
                    let cp =
                        0x10000 + ((u32::from(hi - 0xd800)) << 10) + u32::from(next_val - 0xdc00);
                    let ch = char::from_u32(cp).ok_or(())?;
                    self.push_char(ch);
                    self.escape = EscapeState::None;
                    Ok(false)
                } else if (0xd800..=0xdbff).contains(&next_val) {
                    self.escape = EscapeState::SurrogateBackslash(next_val);
                    Ok(false)
                } else if (0xdc00..=0xdfff).contains(&next_val) {
                    Err(())
                } else {
                    let ch = char::from_u32(u32::from(next_val)).ok_or(())?;
                    self.push_char(ch);
                    self.escape = EscapeState::None;
                    Ok(false)
                }
            }
            EscapeState::SurrogateBackslash(hi) => {
                if b == b'\\' {
                    self.escape = EscapeState::SurrogateU(hi);
                    Ok(false)
                } else {
                    Err(())
                }
            }
            EscapeState::SurrogateU(hi) => {
                if b == b'u' {
                    self.escape = EscapeState::Unicode {
                        digits: 0,
                        value: 0,
                        high_surrogate: Some(hi),
                    };
                    Ok(false)
                } else {
                    Err(())
                }
            }
        }
    }

    fn take_string(&mut self) -> Result<Option<String>, ()> {
        if self.overflowed {
            self.buf.clear();
            return Ok(None);
        }
        let bytes = std::mem::take(&mut self.buf);
        let text = String::from_utf8(bytes).map_err(|_| ())?;
        Ok(Some(text))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Depth1Key {
    Method,
    Id,
    Other,
}

enum LexState {
    Start,
    ObjExpectKeyOrEnd,
    ObjExpectKey,
    ReadingKey(StringCollector),
    ObjExpectColon(Depth1Key),
    ObjExpectValue(Depth1Key),
    ReadingMethod(StringCollector),
    ReadingStringId(StringCollector),
    ReadingNumberId(Vec<u8>),
    SkippingString(StringCollector),
    SkippingPrimitive,
    SkippingNested {
        stack: Vec<u8>,
        in_string: Option<StringCollector>,
    },
    ObjExpectCommaOrEnd,
    AfterRootObject,
    PassthroughRoot,
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanDecision {
    NeedMore,
    Passthrough,
    Intercepted,
    DuplicateMethod,
    Malformed,
}

/// Zero-AST depth-1 JSON lexical scanner for streaming MCP POST classification.
struct TopLevelJsonScanner {
    state: LexState,
    saw_method_key: bool,
    intercepted_method: bool,
    non_string_method: bool,
    duplicate_method: bool,
    passthrough_ready: bool,
    captured_id: Option<Value>,
}

impl TopLevelJsonScanner {
    fn new() -> Self {
        Self {
            state: LexState::Start,
            saw_method_key: false,
            intercepted_method: false,
            non_string_method: false,
            duplicate_method: false,
            passthrough_ready: false,
            captured_id: None,
        }
    }

    fn captured_id(&self) -> Option<Value> {
        self.captured_id.clone()
    }

    fn feed_chunk(&mut self, chunk: &[u8]) -> ScanDecision {
        let mut idx = 0usize;
        while idx < chunk.len() {
            let b = chunk[idx];
            idx += 1;
            self.step_byte(b);
            if matches!(self.state, LexState::Malformed) {
                return ScanDecision::Malformed;
            }
            if self.duplicate_method {
                return ScanDecision::DuplicateMethod;
            }
            if matches!(self.state, LexState::PassthroughRoot) {
                return ScanDecision::Passthrough;
            }
        }
        if self.passthrough_ready {
            ScanDecision::Passthrough
        } else if self.intercepted_method {
            ScanDecision::Intercepted
        } else {
            ScanDecision::NeedMore
        }
    }

    fn finish_eof(&mut self) -> ScanDecision {
        if let LexState::ReadingNumberId(buf) = &mut self.state {
            let bytes = std::mem::take(buf);
            self.finish_number_id(&bytes);
            self.state = LexState::Malformed;
            return ScanDecision::Malformed;
        }
        if self.duplicate_method {
            return ScanDecision::DuplicateMethod;
        }
        match self.state {
            LexState::PassthroughRoot => ScanDecision::Passthrough,
            LexState::AfterRootObject => {
                if self.passthrough_ready || !self.saw_method_key {
                    ScanDecision::Passthrough
                } else {
                    ScanDecision::Intercepted
                }
            }
            _ => ScanDecision::Malformed,
        }
    }

    fn finish_number_id(&mut self, bytes: &[u8]) {
        if self.captured_id.is_none()
            && bytes.len() <= 32
            && let Ok(s) = std::str::from_utf8(bytes)
            && let Ok(val) = serde_json::from_str::<Value>(s)
            && is_valid_jsonrpc_id(&val)
        {
            self.captured_id = Some(val);
        }
    }

    fn step_byte(&mut self, b: u8) {
        loop {
            match &mut self.state {
                LexState::Start => {
                    if is_json_ws(b) {
                        return;
                    }
                    match b {
                        b'[' => {
                            self.passthrough_ready = true;
                            self.state = LexState::PassthroughRoot;
                        }
                        b'{' => {
                            self.state = LexState::ObjExpectKeyOrEnd;
                        }
                        _ => {
                            self.state = LexState::Malformed;
                        }
                    }
                    return;
                }
                LexState::ObjExpectKeyOrEnd => {
                    if is_json_ws(b) {
                        return;
                    }
                    match b {
                        b'}' => {
                            if !self.saw_method_key {
                                self.passthrough_ready = true;
                            }
                            self.state = LexState::AfterRootObject;
                        }
                        b'"' => {
                            self.state = LexState::ReadingKey(StringCollector::new(32));
                        }
                        _ => {
                            self.state = LexState::Malformed;
                        }
                    }
                    return;
                }
                LexState::ObjExpectKey => {
                    if is_json_ws(b) {
                        return;
                    }
                    if b == b'"' {
                        self.state = LexState::ReadingKey(StringCollector::new(32));
                    } else {
                        self.state = LexState::Malformed;
                    }
                    return;
                }
                LexState::ReadingKey(collector) => {
                    match collector.feed_byte(b) {
                        Ok(false) => {}
                        Ok(true) => match collector.take_string() {
                            Ok(Some(k)) if k == "method" => {
                                if self.saw_method_key {
                                    self.duplicate_method = true;
                                }
                                self.saw_method_key = true;
                                self.state = LexState::ObjExpectColon(Depth1Key::Method);
                            }
                            Ok(Some(k)) if k == "id" => {
                                self.state = LexState::ObjExpectColon(Depth1Key::Id);
                            }
                            Ok(_) => {
                                self.state = LexState::ObjExpectColon(Depth1Key::Other);
                            }
                            Err(()) => {
                                self.state = LexState::Malformed;
                            }
                        },
                        Err(()) => {
                            self.state = LexState::Malformed;
                        }
                    }
                    return;
                }
                LexState::ObjExpectColon(key) => {
                    if is_json_ws(b) {
                        return;
                    }
                    let key = *key;
                    if b == b':' {
                        self.state = LexState::ObjExpectValue(key);
                    } else {
                        self.state = LexState::Malformed;
                    }
                    return;
                }
                LexState::ObjExpectValue(key) => {
                    if is_json_ws(b) {
                        return;
                    }
                    let key = *key;
                    match (key, b) {
                        (Depth1Key::Method, b'"') => {
                            self.state = LexState::ReadingMethod(StringCollector::new(64));
                        }
                        (Depth1Key::Method, _) => {
                            self.non_string_method = true;
                            self.enter_skip_value(b);
                        }
                        (Depth1Key::Id, b'"') if self.captured_id.is_none() => {
                            self.state = LexState::ReadingStringId(StringCollector::new(256));
                        }
                        (Depth1Key::Id, b'-' | b'0'..=b'9') if self.captured_id.is_none() => {
                            let mut num = Vec::with_capacity(16);
                            num.push(b);
                            self.state = LexState::ReadingNumberId(num);
                        }
                        (_, first) => {
                            self.enter_skip_value(first);
                        }
                    }
                    return;
                }
                LexState::ReadingMethod(collector) => {
                    match collector.feed_byte(b) {
                        Ok(false) => {}
                        Ok(true) => match collector.take_string() {
                            Ok(Some(m)) if is_intercepted_method(&m) => {
                                self.intercepted_method = true;
                                self.state = LexState::ObjExpectCommaOrEnd;
                            }
                            Ok(_) => {
                                self.passthrough_ready = true;
                                self.state = LexState::ObjExpectCommaOrEnd;
                            }
                            Err(()) => {
                                self.state = LexState::Malformed;
                            }
                        },
                        Err(()) => {
                            self.state = LexState::Malformed;
                        }
                    }
                    return;
                }
                LexState::ReadingStringId(collector) => {
                    match collector.feed_byte(b) {
                        Ok(false) => {}
                        Ok(true) => match collector.take_string() {
                            Ok(Some(id_str)) => {
                                self.captured_id = Some(Value::String(id_str));
                                self.state = LexState::ObjExpectCommaOrEnd;
                            }
                            Ok(None) => {
                                self.state = LexState::ObjExpectCommaOrEnd;
                            }
                            Err(()) => {
                                self.state = LexState::Malformed;
                            }
                        },
                        Err(()) => {
                            self.state = LexState::Malformed;
                        }
                    }
                    return;
                }
                LexState::ReadingNumberId(buf) => {
                    if matches!(b, b'0'..=b'9' | b'+' | b'-' | b'.' | b'e' | b'E') {
                        if buf.len() <= 32 {
                            buf.push(b);
                        }
                        return;
                    }
                    if is_json_ws(b) || b == b',' || b == b'}' {
                        let bytes = std::mem::take(buf);
                        self.finish_number_id(&bytes);
                        self.state = LexState::ObjExpectCommaOrEnd;
                        continue;
                    }
                    self.state = LexState::Malformed;
                    return;
                }
                LexState::SkippingString(collector) => {
                    match collector.feed_byte(b) {
                        Ok(false) => {}
                        Ok(true) => {
                            self.state = LexState::ObjExpectCommaOrEnd;
                        }
                        Err(()) => {
                            self.state = LexState::Malformed;
                        }
                    }
                    return;
                }
                LexState::SkippingPrimitive => {
                    if matches!(b, b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'+' | b'-' | b'.') {
                        return;
                    }
                    if is_json_ws(b) || b == b',' || b == b'}' {
                        self.state = LexState::ObjExpectCommaOrEnd;
                        continue;
                    }
                    self.state = LexState::Malformed;
                    return;
                }
                LexState::SkippingNested { stack, in_string } => {
                    if let Some(sc) = in_string {
                        match sc.feed_byte(b) {
                            Ok(false) => {}
                            Ok(true) => *in_string = None,
                            Err(()) => self.state = LexState::Malformed,
                        }
                        return;
                    }
                    match b {
                        b'"' => {
                            *in_string = Some(StringCollector::new(0));
                        }
                        b'{' => {
                            if stack.len() >= MAX_JSON_SCAN_NESTING {
                                self.state = LexState::Malformed;
                            } else {
                                stack.push(b'}');
                            }
                        }
                        b'[' => {
                            if stack.len() >= MAX_JSON_SCAN_NESTING {
                                self.state = LexState::Malformed;
                            } else {
                                stack.push(b']');
                            }
                        }
                        b'}' | b']' => {
                            if stack.pop() != Some(b) {
                                self.state = LexState::Malformed;
                            } else if stack.is_empty() {
                                self.state = LexState::ObjExpectCommaOrEnd;
                            }
                        }
                        _ => {}
                    }
                    return;
                }
                LexState::ObjExpectCommaOrEnd => {
                    if is_json_ws(b) {
                        return;
                    }
                    match b {
                        b',' => {
                            if self.passthrough_ready && self.captured_id.is_some() {
                                self.state = LexState::PassthroughRoot;
                            } else {
                                self.state = LexState::ObjExpectKey;
                            }
                        }
                        b'}' => {
                            if !self.saw_method_key {
                                self.passthrough_ready = true;
                            }
                            self.state = LexState::AfterRootObject;
                        }
                        _ => {
                            self.state = LexState::Malformed;
                        }
                    }
                    return;
                }
                LexState::AfterRootObject => {
                    if !is_json_ws(b) {
                        self.state = LexState::Malformed;
                    }
                    return;
                }
                LexState::PassthroughRoot | LexState::Malformed => return,
            }
        }
    }

    fn enter_skip_value(&mut self, first: u8) {
        match first {
            b'"' => {
                self.state = LexState::SkippingString(StringCollector::new(0));
            }
            b'{' => {
                self.state = LexState::SkippingNested {
                    stack: vec![b'}'],
                    in_string: None,
                };
            }
            b'[' => {
                self.state = LexState::SkippingNested {
                    stack: vec![b']'],
                    in_string: None,
                };
            }
            b't' | b'f' | b'n' | b'-' | b'0'..=b'9' => {
                self.state = LexState::SkippingPrimitive;
            }
            _ => {
                self.state = LexState::Malformed;
            }
        }
    }
}

fn is_json_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

enum ScannedPostBody<B> {
    PassthroughStream {
        prefix: Bytes,
        rest: B,
        eof: bool,
        captured_id: Option<Value>,
    },
    Buffered(Bytes),
    DuplicateMethod {
        captured_id: Option<Value>,
    },
    Malformed {
        captured_id: Option<Value>,
    },
}

#[derive(Debug)]
enum BodyReadError {
    TooLarge,
    Timeout,
    BudgetExhausted,
    Io(String),
}

fn append_leased_chunk(
    out: &mut LeasedBuffer,
    chunk: &[u8],
    limit: usize,
    pools: &MemoryPools,
    prefer_control: bool,
    allow_control_fallback: bool,
    using_control: &mut bool,
) -> Result<(), BodyReadError> {
    let next_len = out.len() + chunk.len();
    if next_len > limit {
        return Err(BodyReadError::TooLarge);
    }
    if *using_control && !prefer_control && next_len > CONTROL_FALLBACK_MAX_BYTES {
        return Err(BodyReadError::BudgetExhausted);
    }
    if !out
        .try_extend(chunk)
        .map_err(|err| BodyReadError::Io(err.to_string()))?
    {
        if allow_control_fallback
            && !*using_control
            && next_len <= CONTROL_FALLBACK_MAX_BYTES
            && let Some(ctrl_lease) = pools.control.try_acquire(next_len.max(out.capacity()))
        {
            out.replace_lease(ctrl_lease);
            *using_control = true;
            if !out
                .try_extend(chunk)
                .map_err(|err| BodyReadError::Io(err.to_string()))?
            {
                return Err(BodyReadError::BudgetExhausted);
            }
        } else {
            return Err(BodyReadError::BudgetExhausted);
        }
    }
    Ok(())
}

async fn scan_or_buffer_json_body<B>(
    mut body: B,
    limit: usize,
    pools: &MemoryPools,
    prefer_control: bool,
) -> Result<ScannedPostBody<B>, BodyReadError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let lease = if prefer_control {
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

    let scan_fut = async {
        let mut out = LeasedBuffer::new(lease);
        let mut scanner = TopLevelJsonScanner::new();

        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| BodyReadError::Io(e.to_string()))?;
            if let Ok(chunk) = frame.into_data() {
                if chunk.is_empty() {
                    continue;
                }
                append_leased_chunk(
                    &mut out,
                    &chunk,
                    limit,
                    pools,
                    prefer_control,
                    true,
                    &mut using_control,
                )?;

                match scanner.feed_chunk(&chunk) {
                    ScanDecision::Passthrough => {
                        let eof = body.is_end_stream();
                        return Ok(ScannedPostBody::PassthroughStream {
                            prefix: out.into_bytes(),
                            rest: body,
                            eof,
                            captured_id: scanner.captured_id(),
                        });
                    }
                    ScanDecision::DuplicateMethod => {
                        return Ok(ScannedPostBody::DuplicateMethod {
                            captured_id: scanner.captured_id(),
                        });
                    }
                    ScanDecision::Malformed => {
                        return Ok(ScannedPostBody::Malformed {
                            captured_id: scanner.captured_id(),
                        });
                    }
                    ScanDecision::NeedMore | ScanDecision::Intercepted => {}
                }
            }
        }

        match scanner.finish_eof() {
            ScanDecision::Passthrough => Ok(ScannedPostBody::PassthroughStream {
                prefix: out.into_bytes(),
                rest: body,
                eof: true,
                captured_id: scanner.captured_id(),
            }),
            ScanDecision::DuplicateMethod => Ok(ScannedPostBody::DuplicateMethod {
                captured_id: scanner.captured_id(),
            }),
            ScanDecision::Malformed => Ok(ScannedPostBody::Malformed {
                captured_id: scanner.captured_id(),
            }),
            ScanDecision::Intercepted | ScanDecision::NeedMore => {
                Ok(ScannedPostBody::Buffered(out.into_bytes()))
            }
        }
    };

    tokio::time::timeout(BODY_READ_TIMEOUT, scan_fut)
        .await
        .map_err(|_| BodyReadError::Timeout)?
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
    let lease = if prefer_control {
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
        let mut out = LeasedBuffer::new(lease);
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| BodyReadError::Io(e.to_string()))?;
            if let Ok(chunk) = frame.into_data() {
                append_leased_chunk(
                    &mut out,
                    &chunk,
                    limit,
                    pools,
                    prefer_control,
                    allow_control_fallback,
                    &mut using_control,
                )?;
            }
        }
        Ok(out.into_bytes())
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

fn auth_error_response(
    profile: Profile,
    req_id: Option<Value>,
    err: EngineError,
) -> Response<RespBody> {
    match err {
        EngineError::InvalidToken(msg) => {
            let www = HeaderValue::from_static(r#"Bearer error="invalid_token""#);
            match req_id {
                Some(id) => {
                    let mut resp = jsonrpc_error(
                        StatusCode::UNAUTHORIZED,
                        id,
                        profile.forbidden_code(),
                        &msg,
                        None,
                    );
                    resp.headers_mut().insert(header::WWW_AUTHENTICATE, www);
                    resp
                }
                None => {
                    let mut resp = empty_response(StatusCode::UNAUTHORIZED);
                    resp.headers_mut().insert(header::WWW_AUTHENTICATE, www);
                    resp
                }
            }
        }
        EngineError::InsufficientScope {
            required_scopes,
            message,
        } => {
            let www_text = if required_scopes.is_empty() {
                r#"Bearer error="insufficient_scope""#.to_owned()
            } else {
                format!(
                    r#"Bearer error="insufficient_scope", scope="{}""#,
                    required_scopes.join(" ")
                )
            };
            let www = HeaderValue::from_str(&www_text).unwrap_or_else(|_| {
                HeaderValue::from_static(r#"Bearer error="insufficient_scope""#)
            });
            match req_id {
                Some(id) => {
                    let mut resp = jsonrpc_error(
                        StatusCode::FORBIDDEN,
                        id,
                        profile.forbidden_code(),
                        &message,
                        None,
                    );
                    resp.headers_mut().insert(header::WWW_AUTHENTICATE, www);
                    resp
                }
                None => {
                    let mut resp = empty_response(StatusCode::FORBIDDEN);
                    resp.headers_mut().insert(header::WWW_AUTHENTICATE, www);
                    resp
                }
            }
        }
        EngineError::AuthUnavailable(msg) => match req_id {
            Some(id) => jsonrpc_error(StatusCode::SERVICE_UNAVAILABLE, id, -32603, &msg, None),
            None => empty_response(StatusCode::SERVICE_UNAVAILABLE),
        },
        other => match req_id {
            Some(id) => engine_error_response(id, profile, other),
            None => empty_response(StatusCode::INTERNAL_SERVER_ERROR),
        },
    }
}

fn engine_error_response(id: Value, profile: Profile, err: EngineError) -> Response<RespBody> {
    if matches!(
        err,
        EngineError::InvalidToken(_)
            | EngineError::InsufficientScope { .. }
            | EngineError::AuthUnavailable(_)
    ) {
        return auth_error_response(profile, Some(id), err);
    }
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

        fn is_end_stream(&self) -> bool {
            self.0.is_empty()
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

    #[test]
    fn accept_header_handles_wildcards_and_q_zero_exclusions() {
        let check = |raw: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::ACCEPT, raw.parse().unwrap());
            accepts_json_and_sse(&h)
        };
        assert!(check("application/json, text/event-stream"));
        assert!(check("*/*"));
        assert!(check("application/*, text/*"));
        assert!(check("application/json;q=0.5, text/event-stream;q=1.0"));
        assert!(check("*/*;q=0.1, application/json;q=0.8"));

        assert!(!check("application/json"));
        assert!(!check("text/event-stream"));
        assert!(!check("*/*, text/event-stream;q=0"));
        assert!(!check("*/*, application/*;q=0"));
        assert!(!check(
            "application/*, application/json;q=0.000, text/event-stream"
        ));
        assert!(!check(
            "application/json, application/json;q=0, text/event-stream"
        ));
        assert!(!check("*/*;q=0"));
    }

    #[test]
    fn depth1_scanner_classifies_across_arbitrary_byte_splits_and_unicode_escapes() {
        let escaped_intercept =
            br#"{"params":{"nested":{"method":"tools/call"},"pad":"xyz"},"\u006dethod":"events\u002fpoll","id":99}"#;
        for step in [1usize, 2, 3, 7, 19] {
            let mut s = TopLevelJsonScanner::new();
            let mut dec = ScanDecision::NeedMore;
            for chunk in escaped_intercept.chunks(step) {
                dec = s.feed_chunk(chunk);
            }
            if dec == ScanDecision::NeedMore {
                dec = s.finish_eof();
            }
            assert_eq!(dec, ScanDecision::Intercepted, "step {step}");
            assert_eq!(s.captured_id(), Some(json!(99)));
        }

        // JSON-RPC client response (no method) streams after root object closes.
        let client_resp = br#"{"jsonrpc":"2.0","id":"srv_1","result":{"sampling":"ok"}}"#;
        for step in [1usize, 5, 13] {
            let mut s = TopLevelJsonScanner::new();
            let mut dec = ScanDecision::NeedMore;
            for chunk in client_resp.chunks(step) {
                dec = s.feed_chunk(chunk);
                if dec == ScanDecision::Passthrough {
                    break;
                }
            }
            if dec == ScanDecision::NeedMore {
                dec = s.finish_eof();
            }
            assert_eq!(dec, ScanDecision::Passthrough, "step {step}");
            assert_eq!(s.captured_id(), Some(json!("srv_1")));
        }

        // Batch array stops on the opening '['.
        let mut batch = TopLevelJsonScanner::new();
        assert_eq!(batch.feed_chunk(b" [ {}"), ScanDecision::Passthrough);

        // Duplicate depth-1 method key is rejected.
        let dup = br#"{"jsonrpc":"2.0","id":1,"method":"events/list","method":"tools/call"}"#;
        let mut dup_s = TopLevelJsonScanner::new();
        assert_eq!(dup_s.feed_chunk(dup), ScanDecision::DuplicateMethod);
    }

    #[tokio::test]
    async fn streaming_scanner_stops_buffering_immediately_on_non_local_method() {
        let pools = MemoryPools::from_quotas(&QuotaConfig::default());
        let chunk1 = Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"blob":""#,
        );
        let chunk2 = Bytes::from(vec![b'x'; 256 * 1024]);
        let chunk3 = Bytes::from_static(br#""}}"#);
        let incoming = Chunks([chunk1.clone(), chunk2, chunk3].into());

        let res = scan_or_buffer_json_body(incoming, MAX_REQUEST_BODY_BYTES, &pools, false)
            .await
            .unwrap();
        match res {
            ScannedPostBody::PassthroughStream {
                prefix,
                mut rest,
                eof,
                captured_id,
            } => {
                assert!(!eof);
                assert_eq!(prefix, chunk1);
                assert_eq!(captured_id, Some(json!(7)));
                let rem1 = rest.frame().await.unwrap().unwrap().into_data().unwrap();
                assert_eq!(rem1.len(), 256 * 1024);
            }
            _ => panic!("expected early PassthroughStream"),
        }
    }
}
