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
use crate::proxy_body::{LeasedBuffer, PrefixedBody, ProxyBody, StreamValidator};
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
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

const MAX_CONCURRENT_CONNECTIONS: usize = 1024;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(60);
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);
const CONTROL_FALLBACK_MAX_BYTES: usize = 64 * 1024;
const MAX_JSON_SCAN_NESTING: usize = 4096;

#[derive(Clone, Copy)]
struct ListenerLimits {
    max_connections: usize,
    header_read_timeout: Duration,
    idle_keepalive_timeout: Duration,
    body_read_timeout: Duration,
    max_request_body_bytes: usize,
}

impl Default for ListenerLimits {
    fn default() -> Self {
        Self {
            max_connections: MAX_CONCURRENT_CONNECTIONS,
            header_read_timeout: HEADER_READ_TIMEOUT,
            idle_keepalive_timeout: IDLE_KEEPALIVE_TIMEOUT,
            body_read_timeout: BODY_READ_TIMEOUT,
            max_request_body_bytes: MAX_REQUEST_BODY_BYTES,
        }
    }
}

struct ConnActivity {
    in_flight: AtomicUsize,
    last_idle_ns: AtomicU64,
    idle_notify: Notify,
    epoch: Instant,
}

impl ConnActivity {
    fn new() -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
            last_idle_ns: AtomicU64::new(0),
            idle_notify: Notify::new(),
            epoch: Instant::now(),
        }
    }
}

struct ActiveReqGuard {
    activity: Arc<ConnActivity>,
}

impl Drop for ActiveReqGuard {
    fn drop(&mut self) {
        if self.activity.in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.activity
                .last_idle_ns
                .store(elapsed_ns(self.activity.epoch), Ordering::Release);
            self.activity.idle_notify.notify_waiters();
        }
    }
}

struct ActiveRespBody {
    inner: RespBody,
    guard: Option<ActiveReqGuard>,
}

impl Body for ActiveRespBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        if matches!(polled, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            this.guard = None;
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn elapsed_ns(epoch: Instant) -> u64 {
    u64::try_from(epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

async fn wait_for_conn_idle(activity: &ConnActivity, timeout: Duration) {
    let timeout_ns = u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX);
    loop {
        let notified = activity.idle_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if activity.in_flight.load(Ordering::Acquire) > 0 {
            notified.await;
            continue;
        }
        let last_idle = activity.last_idle_ns.load(Ordering::Acquire);
        let now = elapsed_ns(activity.epoch);
        let idle_for = now.saturating_sub(last_idle);
        if idle_for >= timeout_ns {
            if activity.in_flight.load(Ordering::Acquire) == 0
                && activity.last_idle_ns.load(Ordering::Acquire) == last_idle
            {
                return;
            }
            continue;
        }
        tokio::time::sleep(Duration::from_nanos(timeout_ns - idle_for)).await;
    }
}

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
    limits: ListenerLimits,
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
    start_server_with_limits(config, quotas, outbound_override, ListenerLimits::default()).await
}

async fn start_server_with_limits(
    config: Config,
    quotas: QuotaConfig,
    outbound_override: Option<OutboundClient>,
    limits: ListenerLimits,
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
        limits,
        legacy_sessions: Mutex::new(LegacySessionStore::new()),
    });

    let cancel = CancellationToken::new();
    let force_cancel = CancellationToken::new();
    let conn_tracker = TaskTracker::new();
    let conn_sem = Arc::new(Semaphore::new(limits.max_connections.max(1)));
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
            let Ok(permit) = Arc::clone(&conn_sem).try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let _ = stream.set_nodelay(true);
            let state = Arc::clone(&state);
            let conn_cancel = accept_cancel.clone();
            let conn_force_cancel = accept_force_cancel.clone();
            let activity = Arc::new(ConnActivity::new());
            let svc_activity = Arc::clone(&activity);

            accept_tracker.spawn(async move {
                let _permit = permit;
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    svc_activity.in_flight.fetch_add(1, Ordering::AcqRel);
                    let req_guard = ActiveReqGuard {
                        activity: Arc::clone(&svc_activity),
                    };
                    let state = Arc::clone(&state);
                    async move {
                        let resp = handle_request(state, req).await;
                        let wrapped = resp.map(|body| {
                            ActiveRespBody {
                                inner: body,
                                guard: Some(req_guard),
                            }
                            .boxed()
                        });
                        Ok::<_, Infallible>(wrapped)
                    }
                });
                let mut builder = http1::Builder::new();
                builder
                    .timer(TokioTimer::new())
                    .header_read_timeout(limits.header_read_timeout);
                let conn = builder.serve_connection(io, svc);
                let idle_expired = wait_for_conn_idle(&activity, limits.idle_keepalive_timeout);
                tokio::pin!(conn);
                tokio::pin!(idle_expired);
                tokio::select! {
                    biased;
                    _ = conn_force_cancel.cancelled() => {}
                    _ = conn.as_mut() => {}
                    _ = &mut idle_expired => {
                        conn.as_mut().graceful_shutdown();
                        tokio::select! {
                            biased;
                            _ = conn_force_cancel.cancelled() => {}
                            _ = tokio::time::timeout(limits.header_read_timeout, conn.as_mut()) => {}
                        }
                    }
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

fn request_origin_allowed(headers: &HeaderMap, state: &ServerState) -> bool {
    let origin = match single_header_str(headers, header::ORIGIN.as_str()) {
        HeaderExtract::Missing => None,
        HeaderExtract::Single(val) => Some(val),
        HeaderExtract::DuplicateOrInvalid => return false,
    };
    is_origin_allowed(
        origin,
        state.bound_addr,
        &state.engine.config().allowed_origins,
    )
}

async fn handle_passthrough(state: Arc<ServerState>, req: Request<Incoming>) -> Response<RespBody> {
    if !request_origin_allowed(req.headers(), &state) {
        return empty_response(StatusCode::FORBIDDEN);
    }
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

    if !request_origin_allowed(req.headers(), &state) {
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
        return empty_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
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
    let (mut parts, incoming) = req.into_parts();

    let scanned = match scan_or_buffer_json_body(
        incoming,
        state.limits.max_request_body_bytes,
        state.limits.body_read_timeout,
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
            scanner,
            captured_id,
        } => {
            if let Err(err) = state.engine.verify_caller(&caller, false).await {
                return auth_error_response(profile, captured_id, err);
            }
            match scanner {
                None => forward_post_to_upstream(&state, &parts.headers, Full::new(prefix)).await,
                Some(scanner) => {
                    // Force chunked framing so validate_eof runs before the upstream body completes.
                    parts.headers.remove(header::CONTENT_LENGTH);
                    let abort_slot: Arc<Mutex<Option<StreamAbortReason>>> =
                        Arc::new(Mutex::new(None));
                    let validator = PassthroughBodyValidator {
                        scanner,
                        abort_slot: Arc::clone(&abort_slot),
                    };
                    let body = PrefixedBody::new(
                        prefix,
                        ProxyBody::new(rest, Arc::clone(&state.engine.pools().proxy)),
                        Box::new(validator),
                        state.limits.max_request_body_bytes,
                        state.limits.body_read_timeout,
                    );
                    let Some(upstream) = state.engine.upstream_client() else {
                        return empty_response(StatusCode::NOT_FOUND);
                    };
                    let forward_res = upstream
                        .forward_raw(Method::POST, None, &parts.headers, body, true, None)
                        .await;
                    if let Some(reason) =
                        abort_slot.lock().unwrap_or_else(|p| p.into_inner()).take()
                    {
                        return stream_abort_response(reason);
                    }
                    match forward_res {
                        Ok(resp) => {
                            relay_upstream_response(resp, Arc::clone(&state.engine.pools().proxy))
                        }
                        Err(UpstreamError::Timeout) => empty_response(StatusCode::GATEWAY_TIMEOUT),
                        Err(_) => empty_response(StatusCode::BAD_GATEWAY),
                    }
                }
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
        ScannedPostBody::InvalidRequest {
            captured_id,
            message,
        } => {
            if let Err(err) = state.engine.verify_caller(&caller, true).await {
                return auth_error_response(profile, captured_id, err);
            }
            jsonrpc_error(
                StatusCode::BAD_REQUEST,
                captured_id.unwrap_or(Value::Null),
                -32600,
                message,
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
) -> Result<(&'a str, Option<&'a Map<String, Value>>), Box<Response<RespBody>>> {
    let profile = state.engine.config().profile;
    let Some(params_obj) = params.and_then(Value::as_object) else {
        return Err(Box::new(jsonrpc_error(
            StatusCode::OK,
            id.clone(),
            -32602,
            "params must be a JSON object",
            None,
        )));
    };
    let Some(event_name) = params_obj.get("name").and_then(Value::as_str) else {
        return Err(Box::new(jsonrpc_error(
            StatusCode::OK,
            id.clone(),
            -32602,
            "params.name must be a string",
            None,
        )));
    };
    let args_map = match params_obj.get("arguments") {
        None | Some(Value::Null) => None,
        Some(Value::Object(m)) => Some(m),
        Some(_) => {
            return Err(Box::new(jsonrpc_error(
                StatusCode::OK,
                id.clone(),
                -32602,
                "params.arguments must be an object",
                None,
            )));
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
            Err(err) => return Err(Box::new(engine_error_response(id.clone(), profile, err))),
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
        return Err(Box::new(jsonrpc_error(
            StatusCode::BAD_REQUEST,
            id.clone(),
            -32020,
            &msg,
            None,
        )));
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
            Err(resp) => return *resp,
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

    let raw_body = match read_local_json_body_scanned(
        incoming,
        state.limits.max_request_body_bytes,
        state.limits.body_read_timeout,
        state.engine.pools(),
        prefer_control,
    )
    .await
    {
        Ok(LocalScannedBody::Buffered(res)) => res,
        Ok(LocalScannedBody::InvalidRequest {
            captured_id,
            message,
        }) => {
            if let Err(err) = state.engine.verify_caller(&caller, true).await {
                return auth_error_response(profile, captured_id, err);
            }
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                captured_id.unwrap_or(Value::Null),
                -32600,
                message,
                None,
            );
        }
        Ok(LocalScannedBody::Malformed { captured_id }) => {
            if let Err(err) = state.engine.verify_caller(&caller, live_from_hdr).await {
                return auth_error_response(profile, captured_id, err);
            }
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                Value::Null,
                -32700,
                "Parse error",
                None,
            );
        }
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
        return *resp;
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
    for val in headers.get_all(header::CONTENT_ENCODING) {
        let Ok(raw) = val.to_str() else {
            return true;
        };
        for tok in raw.split(',') {
            let trimmed = tok.trim();
            if trimmed.is_empty() {
                continue;
            }
            if !trimmed.eq_ignore_ascii_case("identity") {
                return true;
            }
        }
    }
    false
}

fn header_mentions_method(headers: &HeaderMap, target: &str) -> bool {
    headers
        .get_all("mcp-method")
        .iter()
        .any(|v| v.to_str().ok().is_some_and(|s| s.trim() == target))
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
    utf8_rem: u8,
    utf8_min: u8,
    utf8_max: u8,
}

impl StringCollector {
    fn new(cap: usize) -> Self {
        Self {
            buf: Vec::new(),
            cap,
            overflowed: false,
            escape: EscapeState::None,
            utf8_rem: 0,
            utf8_min: 0x80,
            utf8_max: 0xbf,
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
        if self.utf8_rem > 0 {
            if b < self.utf8_min || b > self.utf8_max {
                return Err(());
            }
            self.push_byte(b);
            self.utf8_min = 0x80;
            self.utf8_max = 0xbf;
            self.utf8_rem -= 1;
            return Ok(false);
        }
        match self.escape {
            EscapeState::None => match b {
                b'"' => Ok(true),
                b'\\' => {
                    self.escape = EscapeState::Backslash;
                    Ok(false)
                }
                0x00..=0x1f => Err(()),
                0x20..=0x7f => {
                    self.push_byte(b);
                    Ok(false)
                }
                0xc2..=0xdf => {
                    self.push_byte(b);
                    self.utf8_rem = 1;
                    self.utf8_min = 0x80;
                    self.utf8_max = 0xbf;
                    Ok(false)
                }
                0xe0 => {
                    self.push_byte(b);
                    self.utf8_rem = 2;
                    self.utf8_min = 0xa0;
                    self.utf8_max = 0xbf;
                    Ok(false)
                }
                0xe1..=0xec | 0xee..=0xef => {
                    self.push_byte(b);
                    self.utf8_rem = 2;
                    self.utf8_min = 0x80;
                    self.utf8_max = 0xbf;
                    Ok(false)
                }
                0xed => {
                    self.push_byte(b);
                    self.utf8_rem = 2;
                    self.utf8_min = 0x80;
                    self.utf8_max = 0x9f;
                    Ok(false)
                }
                0xf0 => {
                    self.push_byte(b);
                    self.utf8_rem = 3;
                    self.utf8_min = 0x90;
                    self.utf8_max = 0xbf;
                    Ok(false)
                }
                0xf1..=0xf3 => {
                    self.push_byte(b);
                    self.utf8_rem = 3;
                    self.utf8_min = 0x80;
                    self.utf8_max = 0xbf;
                    Ok(false)
                }
                0xf4 => {
                    self.push_byte(b);
                    self.utf8_rem = 3;
                    self.utf8_min = 0x80;
                    self.utf8_max = 0x8f;
                    Ok(false)
                }
                _ => Err(()),
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum SkipTarget {
    RootObj,
    BatchElem,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NestedContainer {
    Obj,
    Arr,
}

#[derive(Clone, Copy)]
enum NumState {
    Minus,
    Zero,
    Int,
    Dot,
    Frac,
    ExpSign,
    ExpDigitReq,
    Exp,
}

enum NumStep {
    Next(NumState),
    Done,
    Malformed,
}

fn is_value_delimiter(b: u8) -> bool {
    is_json_ws(b) || matches!(b, b',' | b'}' | b']')
}

fn is_json_value_start(b: u8) -> bool {
    matches!(
        b,
        b'{' | b'[' | b'"' | b't' | b'f' | b'n' | b'-' | b'0'..=b'9'
    )
}

fn initial_num_state(b: u8) -> Option<NumState> {
    match b {
        b'-' => Some(NumState::Minus),
        b'0' => Some(NumState::Zero),
        b'1'..=b'9' => Some(NumState::Int),
        _ => None,
    }
}

fn step_num(state: NumState, b: u8) -> NumStep {
    match state {
        NumState::Minus => match b {
            b'0' => NumStep::Next(NumState::Zero),
            b'1'..=b'9' => NumStep::Next(NumState::Int),
            _ => NumStep::Malformed,
        },
        NumState::Zero => match b {
            b'.' => NumStep::Next(NumState::Dot),
            b'e' | b'E' => NumStep::Next(NumState::ExpSign),
            _ if is_value_delimiter(b) => NumStep::Done,
            _ => NumStep::Malformed,
        },
        NumState::Int => match b {
            b'0'..=b'9' => NumStep::Next(NumState::Int),
            b'.' => NumStep::Next(NumState::Dot),
            b'e' | b'E' => NumStep::Next(NumState::ExpSign),
            _ if is_value_delimiter(b) => NumStep::Done,
            _ => NumStep::Malformed,
        },
        NumState::Dot => match b {
            b'0'..=b'9' => NumStep::Next(NumState::Frac),
            _ => NumStep::Malformed,
        },
        NumState::Frac => match b {
            b'0'..=b'9' => NumStep::Next(NumState::Frac),
            b'e' | b'E' => NumStep::Next(NumState::ExpSign),
            _ if is_value_delimiter(b) => NumStep::Done,
            _ => NumStep::Malformed,
        },
        NumState::ExpSign => match b {
            b'+' | b'-' => NumStep::Next(NumState::ExpDigitReq),
            b'0'..=b'9' => NumStep::Next(NumState::Exp),
            _ => NumStep::Malformed,
        },
        NumState::ExpDigitReq => match b {
            b'0'..=b'9' => NumStep::Next(NumState::Exp),
            _ => NumStep::Malformed,
        },
        NumState::Exp => match b {
            b'0'..=b'9' => NumStep::Next(NumState::Exp),
            _ if is_value_delimiter(b) => NumStep::Done,
            _ => NumStep::Malformed,
        },
    }
}

enum SkipSubState {
    ExpectValue,
    InString(StringCollector),
    InLiteral(&'static [u8], usize),
    InNumber(NumState),
    ObjKeyOrEnd,
    ObjKey,
    ObjKeyStr(StringCollector),
    ObjColon,
    ArrValOrEnd,
    AfterValue,
}

enum LexState {
    Start,
    RootObjKeyOrEnd,
    RootObjKey,
    RootObjReadingKey(StringCollector),
    RootObjColon(Depth1Key),
    RootObjValue(Depth1Key),
    RootObjReadingMethod(StringCollector),
    RootObjReadingStringId(StringCollector),
    RootObjReadingNumberId {
        num_state: NumState,
        buf: Vec<u8>,
    },
    RootObjCommaOrEnd,
    BatchElemOrEnd,
    BatchElemAfterComma,
    BatchElemKeyOrEnd,
    BatchElemKey,
    BatchElemReadingKey(StringCollector),
    BatchElemColon(bool),
    BatchElemValue(bool),
    BatchElemReadingMethod(StringCollector),
    BatchElemCommaOrEnd,
    BatchAfterElem,
    Skipping {
        target: SkipTarget,
        stack: Vec<NestedContainer>,
        sub: SkipSubState,
    },
    RootClosed,
    InvalidRequest(&'static str),
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanDecision {
    NeedMore,
    Passthrough,
    Intercepted,
    InvalidRequest(&'static str),
    Malformed,
}

/// Zero-AST streaming JSON lexical scanner for MCP POST classification and tail validation.
pub(crate) struct TopLevelJsonScanner {
    state: LexState,
    saw_method_key: bool,
    elem_saw_method: bool,
    intercepted_method: bool,
    passthrough_ready: bool,
    captured_id: Option<Value>,
}

impl TopLevelJsonScanner {
    fn new() -> Self {
        Self {
            state: LexState::Start,
            saw_method_key: false,
            elem_saw_method: false,
            intercepted_method: false,
            passthrough_ready: false,
            captured_id: None,
        }
    }

    fn captured_id(&self) -> Option<Value> {
        self.captured_id.clone()
    }

    fn feed_chunk(&mut self, chunk: &[u8]) -> ScanDecision {
        for &b in chunk {
            self.step_byte(b);
            match self.state {
                LexState::Malformed => return ScanDecision::Malformed,
                LexState::InvalidRequest(msg) => return ScanDecision::InvalidRequest(msg),
                _ => {}
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
        if let LexState::RootObjReadingNumberId { num_state, buf } = &mut self.state {
            if matches!(
                num_state,
                NumState::Zero | NumState::Int | NumState::Frac | NumState::Exp
            ) {
                let bytes = std::mem::take(buf);
                self.finish_number_id(&bytes);
            }
            self.state = LexState::Malformed;
            return ScanDecision::Malformed;
        }
        match self.state {
            LexState::InvalidRequest(msg) => ScanDecision::InvalidRequest(msg),
            LexState::RootClosed => {
                if self.passthrough_ready {
                    ScanDecision::Passthrough
                } else {
                    ScanDecision::Intercepted
                }
            }
            _ => {
                self.state = LexState::Malformed;
                ScanDecision::Malformed
            }
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
                        b'{' => self.state = LexState::RootObjKeyOrEnd,
                        b'[' => self.state = LexState::BatchElemOrEnd,
                        _ => self.state = LexState::Malformed,
                    }
                    return;
                }
                LexState::RootObjKeyOrEnd => {
                    if is_json_ws(b) {
                        return;
                    }
                    match b {
                        b'}' => {
                            if !self.saw_method_key {
                                self.passthrough_ready = true;
                            }
                            self.state = LexState::RootClosed;
                        }
                        b'"' => {
                            self.state = LexState::RootObjReadingKey(StringCollector::new(32));
                        }
                        _ => self.state = LexState::Malformed,
                    }
                    return;
                }
                LexState::RootObjKey => {
                    if is_json_ws(b) {
                        return;
                    }
                    if b == b'"' {
                        self.state = LexState::RootObjReadingKey(StringCollector::new(32));
                    } else {
                        self.state = LexState::Malformed;
                    }
                    return;
                }
                LexState::RootObjReadingKey(collector) => {
                    match collector.feed_byte(b) {
                        Ok(false) => {}
                        Ok(true) => match collector.take_string() {
                            Ok(Some(k)) if k == "method" => {
                                if self.saw_method_key {
                                    self.state = LexState::InvalidRequest(
                                        "Invalid Request: duplicate method field",
                                    );
                                } else {
                                    self.saw_method_key = true;
                                    self.state = LexState::RootObjColon(Depth1Key::Method);
                                }
                            }
                            Ok(Some(k)) if k == "id" => {
                                self.state = LexState::RootObjColon(Depth1Key::Id);
                            }
                            Ok(_) => {
                                self.state = LexState::RootObjColon(Depth1Key::Other);
                            }
                            Err(()) => self.state = LexState::Malformed,
                        },
                        Err(()) => self.state = LexState::Malformed,
                    }
                    return;
                }
                LexState::RootObjColon(key) => {
                    if is_json_ws(b) {
                        return;
                    }
                    let key = *key;
                    if b == b':' {
                        self.state = LexState::RootObjValue(key);
                    } else {
                        self.state = LexState::Malformed;
                    }
                    return;
                }
                LexState::RootObjValue(key) => {
                    if is_json_ws(b) {
                        return;
                    }
                    let key = *key;
                    match (key, b) {
                        (Depth1Key::Method, b'"') => {
                            self.state = LexState::RootObjReadingMethod(StringCollector::new(64));
                        }
                        (Depth1Key::Method, first) if is_json_value_start(first) => {
                            self.state = LexState::InvalidRequest(
                                "Invalid Request: method must be a string",
                            );
                        }
                        (Depth1Key::Method, _) => {
                            self.state = LexState::Malformed;
                        }
                        (Depth1Key::Id, b'"') if self.captured_id.is_none() => {
                            self.state =
                                LexState::RootObjReadingStringId(StringCollector::new(256));
                        }
                        (Depth1Key::Id, first)
                            if self.captured_id.is_none() && initial_num_state(first).is_some() =>
                        {
                            let mut buf = Vec::with_capacity(16);
                            buf.push(first);
                            self.state = LexState::RootObjReadingNumberId {
                                num_state: initial_num_state(first).unwrap(),
                                buf,
                            };
                        }
                        (_, first) => {
                            self.enter_skip_value(first, SkipTarget::RootObj);
                        }
                    }
                    return;
                }
                LexState::RootObjReadingMethod(collector) => {
                    match collector.feed_byte(b) {
                        Ok(false) => {}
                        Ok(true) => match collector.take_string() {
                            Ok(Some(m)) if is_intercepted_method(&m) => {
                                self.intercepted_method = true;
                                self.state = LexState::RootObjCommaOrEnd;
                            }
                            Ok(_) => {
                                self.passthrough_ready = true;
                                self.state = LexState::RootObjCommaOrEnd;
                            }
                            Err(()) => self.state = LexState::Malformed,
                        },
                        Err(()) => self.state = LexState::Malformed,
                    }
                    return;
                }
                LexState::RootObjReadingStringId(collector) => {
                    match collector.feed_byte(b) {
                        Ok(false) => {}
                        Ok(true) => match collector.take_string() {
                            Ok(Some(id_str)) => {
                                self.captured_id = Some(Value::String(id_str));
                                self.state = LexState::RootObjCommaOrEnd;
                            }
                            Ok(None) => {
                                self.state = LexState::RootObjCommaOrEnd;
                            }
                            Err(()) => self.state = LexState::Malformed,
                        },
                        Err(()) => self.state = LexState::Malformed,
                    }
                    return;
                }
                LexState::RootObjReadingNumberId { num_state, buf } => {
                    match step_num(*num_state, b) {
                        NumStep::Next(next) => {
                            *num_state = next;
                            if buf.len() <= 32 {
                                buf.push(b);
                            }
                            return;
                        }
                        NumStep::Done => {
                            let bytes = std::mem::take(buf);
                            self.finish_number_id(&bytes);
                            self.state = LexState::RootObjCommaOrEnd;
                            continue;
                        }
                        NumStep::Malformed => {
                            self.state = LexState::Malformed;
                            return;
                        }
                    }
                }
                LexState::RootObjCommaOrEnd => {
                    if is_json_ws(b) {
                        return;
                    }
                    match b {
                        b',' => self.state = LexState::RootObjKey,
                        b'}' => {
                            if !self.saw_method_key {
                                self.passthrough_ready = true;
                            }
                            self.state = LexState::RootClosed;
                        }
                        _ => self.state = LexState::Malformed,
                    }
                    return;
                }
                LexState::BatchElemOrEnd => {
                    if is_json_ws(b) {
                        return;
                    }
                    match b {
                        b']' => {
                            self.state = LexState::InvalidRequest(
                                "Invalid Request: batch array must not be empty",
                            );
                        }
                        b'{' => {
                            self.elem_saw_method = false;
                            self.state = LexState::BatchElemKeyOrEnd;
                        }
                        first if is_json_value_start(first) => {
                            self.state = LexState::InvalidRequest(
                                "Invalid Request: batch elements must be JSON objects",
                            );
                        }
                        _ => self.state = LexState::Malformed,
                    }
                    return;
                }
                LexState::BatchElemAfterComma => {
                    if is_json_ws(b) {
                        return;
                    }
                    match b {
                        b'{' => {
                            self.elem_saw_method = false;
                            self.state = LexState::BatchElemKeyOrEnd;
                        }
                        first if is_json_value_start(first) => {
                            self.state = LexState::InvalidRequest(
                                "Invalid Request: batch elements must be JSON objects",
                            );
                        }
                        _ => self.state = LexState::Malformed,
                    }
                    return;
                }
                LexState::BatchElemKeyOrEnd => {
                    if is_json_ws(b) {
                        return;
                    }
                    match b {
                        b'}' => {
                            if !self.elem_saw_method {
                                self.passthrough_ready = true;
                            }
                            self.state = LexState::BatchAfterElem;
                        }
                        b'"' => {
                            self.state = LexState::BatchElemReadingKey(StringCollector::new(32));
                        }
                        _ => self.state = LexState::Malformed,
                    }
                    return;
                }
                LexState::BatchElemKey => {
                    if is_json_ws(b) {
                        return;
                    }
                    if b == b'"' {
                        self.state = LexState::BatchElemReadingKey(StringCollector::new(32));
                    } else {
                        self.state = LexState::Malformed;
                    }
                    return;
                }
                LexState::BatchElemReadingKey(collector) => {
                    match collector.feed_byte(b) {
                        Ok(false) => {}
                        Ok(true) => match collector.take_string() {
                            Ok(Some(k)) if k == "method" => {
                                if self.elem_saw_method {
                                    self.state = LexState::InvalidRequest(
                                        "Invalid Request: duplicate method field in batch element",
                                    );
                                } else {
                                    self.elem_saw_method = true;
                                    self.state = LexState::BatchElemColon(true);
                                }
                            }
                            Ok(_) => {
                                self.state = LexState::BatchElemColon(false);
                            }
                            Err(()) => self.state = LexState::Malformed,
                        },
                        Err(()) => self.state = LexState::Malformed,
                    }
                    return;
                }
                LexState::BatchElemColon(is_method) => {
                    if is_json_ws(b) {
                        return;
                    }
                    let is_method = *is_method;
                    if b == b':' {
                        self.state = LexState::BatchElemValue(is_method);
                    } else {
                        self.state = LexState::Malformed;
                    }
                    return;
                }
                LexState::BatchElemValue(is_method) => {
                    if is_json_ws(b) {
                        return;
                    }
                    let is_method = *is_method;
                    match (is_method, b) {
                        (true, b'"') => {
                            self.state = LexState::BatchElemReadingMethod(StringCollector::new(64));
                        }
                        (true, first) if is_json_value_start(first) => {
                            self.state = LexState::InvalidRequest(
                                "Invalid Request: batch element method must be a string",
                            );
                        }
                        (true, _) => {
                            self.state = LexState::Malformed;
                        }
                        (false, first) => {
                            self.enter_skip_value(first, SkipTarget::BatchElem);
                        }
                    }
                    return;
                }
                LexState::BatchElemReadingMethod(collector) => {
                    match collector.feed_byte(b) {
                        Ok(false) => {}
                        Ok(true) => match collector.take_string() {
                            Ok(Some(m)) if is_intercepted_method(&m) => {
                                self.state = LexState::InvalidRequest(
                                    "Invalid Request: controlled MCP method cannot be batched",
                                );
                            }
                            Ok(_) => {
                                self.passthrough_ready = true;
                                self.state = LexState::BatchElemCommaOrEnd;
                            }
                            Err(()) => self.state = LexState::Malformed,
                        },
                        Err(()) => self.state = LexState::Malformed,
                    }
                    return;
                }
                LexState::BatchElemCommaOrEnd => {
                    if is_json_ws(b) {
                        return;
                    }
                    match b {
                        b',' => self.state = LexState::BatchElemKey,
                        b'}' => {
                            if !self.elem_saw_method {
                                self.passthrough_ready = true;
                            }
                            self.state = LexState::BatchAfterElem;
                        }
                        _ => self.state = LexState::Malformed,
                    }
                    return;
                }
                LexState::BatchAfterElem => {
                    if is_json_ws(b) {
                        return;
                    }
                    match b {
                        b',' => self.state = LexState::BatchElemAfterComma,
                        b']' => self.state = LexState::RootClosed,
                        _ => self.state = LexState::Malformed,
                    }
                    return;
                }
                LexState::Skipping { target, stack, sub } => match sub {
                    SkipSubState::ExpectValue => {
                        if is_json_ws(b) {
                            return;
                        }
                        match b {
                            b'"' => *sub = SkipSubState::InString(StringCollector::new(0)),
                            b't' => *sub = SkipSubState::InLiteral(b"rue", 0),
                            b'f' => *sub = SkipSubState::InLiteral(b"alse", 0),
                            b'n' => *sub = SkipSubState::InLiteral(b"ull", 0),
                            b'{' => {
                                if stack.len() >= MAX_JSON_SCAN_NESTING {
                                    self.state = LexState::Malformed;
                                } else {
                                    stack.push(NestedContainer::Obj);
                                    *sub = SkipSubState::ObjKeyOrEnd;
                                }
                            }
                            b'[' => {
                                if stack.len() >= MAX_JSON_SCAN_NESTING {
                                    self.state = LexState::Malformed;
                                } else {
                                    stack.push(NestedContainer::Arr);
                                    *sub = SkipSubState::ArrValOrEnd;
                                }
                            }
                            first => match initial_num_state(first) {
                                Some(ns) => *sub = SkipSubState::InNumber(ns),
                                None => self.state = LexState::Malformed,
                            },
                        }
                        return;
                    }
                    SkipSubState::InString(sc) => {
                        match sc.feed_byte(b) {
                            Ok(false) => {}
                            Ok(true) => {
                                if stack.is_empty() {
                                    let done_target = *target;
                                    self.finish_skip_target(done_target);
                                } else {
                                    *sub = SkipSubState::AfterValue;
                                }
                            }
                            Err(()) => self.state = LexState::Malformed,
                        }
                        return;
                    }
                    SkipSubState::InLiteral(expected, pos) => {
                        if b != expected[*pos] {
                            self.state = LexState::Malformed;
                            return;
                        }
                        *pos += 1;
                        if *pos == expected.len() {
                            if stack.is_empty() {
                                let done_target = *target;
                                self.finish_skip_target(done_target);
                            } else {
                                *sub = SkipSubState::AfterValue;
                            }
                        }
                        return;
                    }
                    SkipSubState::InNumber(ns) => match step_num(*ns, b) {
                        NumStep::Next(next) => {
                            *ns = next;
                            return;
                        }
                        NumStep::Done => {
                            if stack.is_empty() {
                                let done_target = *target;
                                self.finish_skip_target(done_target);
                                continue;
                            }
                            *sub = SkipSubState::AfterValue;
                            continue;
                        }
                        NumStep::Malformed => {
                            self.state = LexState::Malformed;
                            return;
                        }
                    },
                    SkipSubState::ObjKeyOrEnd => {
                        if is_json_ws(b) {
                            return;
                        }
                        match b {
                            b'}' => {
                                stack.pop();
                                if stack.is_empty() {
                                    let done_target = *target;
                                    self.finish_skip_target(done_target);
                                } else {
                                    *sub = SkipSubState::AfterValue;
                                }
                            }
                            b'"' => *sub = SkipSubState::ObjKeyStr(StringCollector::new(0)),
                            _ => self.state = LexState::Malformed,
                        }
                        return;
                    }
                    SkipSubState::ObjKey => {
                        if is_json_ws(b) {
                            return;
                        }
                        if b == b'"' {
                            *sub = SkipSubState::ObjKeyStr(StringCollector::new(0));
                        } else {
                            self.state = LexState::Malformed;
                        }
                        return;
                    }
                    SkipSubState::ObjKeyStr(sc) => {
                        match sc.feed_byte(b) {
                            Ok(false) => {}
                            Ok(true) => *sub = SkipSubState::ObjColon,
                            Err(()) => self.state = LexState::Malformed,
                        }
                        return;
                    }
                    SkipSubState::ObjColon => {
                        if is_json_ws(b) {
                            return;
                        }
                        if b == b':' {
                            *sub = SkipSubState::ExpectValue;
                        } else {
                            self.state = LexState::Malformed;
                        }
                        return;
                    }
                    SkipSubState::ArrValOrEnd => {
                        if is_json_ws(b) {
                            return;
                        }
                        if b == b']' {
                            stack.pop();
                            if stack.is_empty() {
                                let done_target = *target;
                                self.finish_skip_target(done_target);
                            } else {
                                *sub = SkipSubState::AfterValue;
                            }
                            return;
                        }
                        *sub = SkipSubState::ExpectValue;
                        continue;
                    }
                    SkipSubState::AfterValue => {
                        if is_json_ws(b) {
                            return;
                        }
                        match (stack.last().copied(), b) {
                            (Some(NestedContainer::Obj), b',') => {
                                *sub = SkipSubState::ObjKey;
                            }
                            (Some(NestedContainer::Obj), b'}') => {
                                stack.pop();
                                if stack.is_empty() {
                                    let done_target = *target;
                                    self.finish_skip_target(done_target);
                                }
                            }
                            (Some(NestedContainer::Arr), b',') => {
                                *sub = SkipSubState::ExpectValue;
                            }
                            (Some(NestedContainer::Arr), b']') => {
                                stack.pop();
                                if stack.is_empty() {
                                    let done_target = *target;
                                    self.finish_skip_target(done_target);
                                }
                            }
                            _ => self.state = LexState::Malformed,
                        }
                        return;
                    }
                },
                LexState::RootClosed => {
                    if !is_json_ws(b) {
                        self.state = LexState::Malformed;
                    }
                    return;
                }
                LexState::InvalidRequest(_) | LexState::Malformed => return,
            }
        }
    }

    fn finish_skip_target(&mut self, target: SkipTarget) {
        self.state = match target {
            SkipTarget::RootObj => LexState::RootObjCommaOrEnd,
            SkipTarget::BatchElem => LexState::BatchElemCommaOrEnd,
        };
    }

    fn enter_skip_value(&mut self, first: u8, target: SkipTarget) {
        let mut stack = Vec::new();
        let sub = match first {
            b'"' => SkipSubState::InString(StringCollector::new(0)),
            b't' => SkipSubState::InLiteral(b"rue", 0),
            b'f' => SkipSubState::InLiteral(b"alse", 0),
            b'n' => SkipSubState::InLiteral(b"ull", 0),
            b'{' => {
                stack.push(NestedContainer::Obj);
                SkipSubState::ObjKeyOrEnd
            }
            b'[' => {
                stack.push(NestedContainer::Arr);
                SkipSubState::ArrValOrEnd
            }
            other => match initial_num_state(other) {
                Some(ns) => SkipSubState::InNumber(ns),
                None => {
                    self.state = LexState::Malformed;
                    return;
                }
            },
        };
        self.state = LexState::Skipping { target, stack, sub };
    }
}

#[derive(Clone, Debug)]
enum StreamAbortReason {
    InvalidRequest {
        id: Option<Value>,
        message: &'static str,
    },
    ParseError,
    PayloadTooLarge,
    BodyTimeout,
    BudgetExhausted,
}

struct PassthroughBodyValidator {
    scanner: TopLevelJsonScanner,
    abort_slot: Arc<Mutex<Option<StreamAbortReason>>>,
}

impl PassthroughBodyValidator {
    fn record(&self, reason: StreamAbortReason) {
        let mut guard = self.abort_slot.lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_none() {
            *guard = Some(reason);
        }
    }
}

impl StreamValidator for PassthroughBodyValidator {
    fn validate_chunk(&mut self, chunk: &[u8]) -> io::Result<()> {
        match self.scanner.feed_chunk(chunk) {
            ScanDecision::Passthrough | ScanDecision::NeedMore => Ok(()),
            ScanDecision::Intercepted => {
                let message = "Invalid Request: controlled MCP method in passthrough stream";
                self.record(StreamAbortReason::InvalidRequest {
                    id: self.scanner.captured_id(),
                    message,
                });
                Err(io::Error::new(io::ErrorKind::InvalidData, message))
            }
            ScanDecision::InvalidRequest(message) => {
                self.record(StreamAbortReason::InvalidRequest {
                    id: self.scanner.captured_id(),
                    message,
                });
                Err(io::Error::new(io::ErrorKind::InvalidData, message))
            }
            ScanDecision::Malformed => {
                self.record(StreamAbortReason::ParseError);
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed JSON in passthrough stream",
                ))
            }
        }
    }

    fn validate_eof(&mut self) -> io::Result<()> {
        match self.scanner.finish_eof() {
            ScanDecision::Passthrough => Ok(()),
            ScanDecision::InvalidRequest(message) => {
                self.record(StreamAbortReason::InvalidRequest {
                    id: self.scanner.captured_id(),
                    message,
                });
                Err(io::Error::new(io::ErrorKind::InvalidData, message))
            }
            ScanDecision::Malformed | ScanDecision::NeedMore | ScanDecision::Intercepted => {
                self.record(StreamAbortReason::ParseError);
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated or invalid JSON at passthrough EOF",
                ))
            }
        }
    }

    fn on_too_large(&mut self) {
        self.record(StreamAbortReason::PayloadTooLarge);
    }

    fn on_timeout(&mut self) {
        self.record(StreamAbortReason::BodyTimeout);
    }

    fn on_read_error(&mut self, err: &io::Error) {
        if err.kind() == io::ErrorKind::OutOfMemory {
            self.record(StreamAbortReason::BudgetExhausted);
        } else {
            self.record(StreamAbortReason::ParseError);
        }
    }
}

fn stream_abort_response(reason: StreamAbortReason) -> Response<RespBody> {
    match reason {
        StreamAbortReason::InvalidRequest { id, message } => jsonrpc_error(
            StatusCode::BAD_REQUEST,
            id.unwrap_or(Value::Null),
            -32600,
            message,
            None,
        ),
        StreamAbortReason::ParseError => jsonrpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32700,
            "Parse error",
            None,
        ),
        StreamAbortReason::PayloadTooLarge => empty_response(StatusCode::PAYLOAD_TOO_LARGE),
        StreamAbortReason::BodyTimeout => empty_response(StatusCode::REQUEST_TIMEOUT),
        StreamAbortReason::BudgetExhausted => empty_response(StatusCode::SERVICE_UNAVAILABLE),
    }
}

#[cfg(test)]
impl StreamValidator for TopLevelJsonScanner {
    fn validate_chunk(&mut self, chunk: &[u8]) -> io::Result<()> {
        match self.feed_chunk(chunk) {
            ScanDecision::Passthrough | ScanDecision::NeedMore => Ok(()),
            ScanDecision::Intercepted => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected controlled method in passthrough stream",
            )),
            ScanDecision::InvalidRequest(msg) => {
                Err(io::Error::new(io::ErrorKind::InvalidData, msg))
            }
            ScanDecision::Malformed => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed JSON in passthrough stream",
            )),
        }
    }

    fn validate_eof(&mut self) -> io::Result<()> {
        match self.finish_eof() {
            ScanDecision::Passthrough => Ok(()),
            ScanDecision::InvalidRequest(msg) => {
                Err(io::Error::new(io::ErrorKind::InvalidData, msg))
            }
            ScanDecision::Malformed | ScanDecision::NeedMore | ScanDecision::Intercepted => {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated or invalid JSON at passthrough EOF",
                ))
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
        scanner: Option<TopLevelJsonScanner>,
        captured_id: Option<Value>,
    },
    Buffered(Bytes),
    InvalidRequest {
        captured_id: Option<Value>,
        message: &'static str,
    },
    Malformed {
        captured_id: Option<Value>,
    },
}

enum LocalScannedBody {
    Buffered(Bytes),
    InvalidRequest {
        captured_id: Option<Value>,
        message: &'static str,
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
    frame_timeout: Duration,
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
    let mut out = LeasedBuffer::new(lease);
    let mut scanner = TopLevelJsonScanner::new();

    loop {
        let next_frame = tokio::time::timeout(frame_timeout, body.frame())
            .await
            .map_err(|_| BodyReadError::Timeout)?;
        let Some(frame) = next_frame else {
            break;
        };
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
                    let captured_id = scanner.captured_id();
                    if body.is_end_stream() {
                        return match scanner.finish_eof() {
                            ScanDecision::Passthrough => Ok(ScannedPostBody::PassthroughStream {
                                prefix: out.into_bytes(),
                                rest: body,
                                scanner: None,
                                captured_id,
                            }),
                            ScanDecision::InvalidRequest(message) => {
                                Ok(ScannedPostBody::InvalidRequest {
                                    captured_id: scanner.captured_id(),
                                    message,
                                })
                            }
                            ScanDecision::Malformed => Ok(ScannedPostBody::Malformed {
                                captured_id: scanner.captured_id(),
                            }),
                            ScanDecision::Intercepted | ScanDecision::NeedMore => {
                                Ok(ScannedPostBody::Buffered(out.into_bytes()))
                            }
                        };
                    }
                    return Ok(ScannedPostBody::PassthroughStream {
                        prefix: out.into_bytes(),
                        rest: body,
                        scanner: Some(scanner),
                        captured_id,
                    });
                }
                ScanDecision::InvalidRequest(message) => {
                    return Ok(ScannedPostBody::InvalidRequest {
                        captured_id: scanner.captured_id(),
                        message,
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
            scanner: None,
            captured_id: scanner.captured_id(),
        }),
        ScanDecision::InvalidRequest(message) => Ok(ScannedPostBody::InvalidRequest {
            captured_id: scanner.captured_id(),
            message,
        }),
        ScanDecision::Malformed => Ok(ScannedPostBody::Malformed {
            captured_id: scanner.captured_id(),
        }),
        ScanDecision::Intercepted | ScanDecision::NeedMore => {
            Ok(ScannedPostBody::Buffered(out.into_bytes()))
        }
    }
}

async fn read_local_json_body_scanned<B>(
    mut body: B,
    limit: usize,
    frame_timeout: Duration,
    pools: &MemoryPools,
    prefer_control: bool,
) -> Result<LocalScannedBody, BodyReadError>
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
    let mut out = LeasedBuffer::new(lease);
    let mut scanner = TopLevelJsonScanner::new();

    loop {
        let next_frame = tokio::time::timeout(frame_timeout, body.frame())
            .await
            .map_err(|_| BodyReadError::Timeout)?;
        let Some(frame) = next_frame else {
            break;
        };
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
                ScanDecision::InvalidRequest(message) => {
                    return Ok(LocalScannedBody::InvalidRequest {
                        captured_id: scanner.captured_id(),
                        message,
                    });
                }
                ScanDecision::Malformed => {
                    return Ok(LocalScannedBody::Malformed {
                        captured_id: scanner.captured_id(),
                    });
                }
                ScanDecision::NeedMore | ScanDecision::Passthrough | ScanDecision::Intercepted => {}
            }
        }
    }

    match scanner.finish_eof() {
        ScanDecision::InvalidRequest(message) => Ok(LocalScannedBody::InvalidRequest {
            captured_id: scanner.captured_id(),
            message,
        }),
        ScanDecision::Malformed => Ok(LocalScannedBody::Malformed {
            captured_id: scanner.captured_id(),
        }),
        ScanDecision::Passthrough | ScanDecision::Intercepted | ScanDecision::NeedMore => {
            Ok(LocalScannedBody::Buffered(out.into_bytes()))
        }
    }
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

    const _: () = {
        assert!(std::mem::size_of::<Box<Response<RespBody>>>() < 128);
        assert!(std::mem::size_of::<BodyReadError>() < 128);
        assert!(std::mem::size_of::<EngineError>() < 128);
        assert!(std::mem::size_of::<UpstreamError>() < 128);
        assert!(std::mem::size_of::<crate::engine::IngestError>() < 128);
        assert!(std::mem::size_of::<crate::outbound::VerifyError>() < 128);
        assert!(std::mem::size_of::<crate::outbound::OutboundConnectError>() < 128);
    };
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

        // Valid non-controlled batch streams after the first element is verified.
        let valid_batch =
            br#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":"r1","result":{}}]"#;
        for step in [1usize, 3, 11] {
            let mut s = TopLevelJsonScanner::new();
            let mut dec = ScanDecision::NeedMore;
            for chunk in valid_batch.chunks(step) {
                dec = s.feed_chunk(chunk);
            }
            assert_eq!(dec, ScanDecision::Passthrough, "batch step {step}");
            assert_eq!(s.finish_eof(), ScanDecision::Passthrough);
        }

        // Duplicate depth-1 method key is rejected regardless of order.
        for dup in [
            &br#"{"jsonrpc":"2.0","id":1,"method":"events/list","method":"tools/call"}"#[..],
            &br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{},"method":"events/poll"}"#[..],
        ] {
            let mut dup_s = TopLevelJsonScanner::new();
            assert!(matches!(
                dup_s.feed_chunk(dup),
                ScanDecision::InvalidRequest(_)
            ));
        }
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

        let res = scan_or_buffer_json_body(
            incoming,
            MAX_REQUEST_BODY_BYTES,
            BODY_READ_TIMEOUT,
            &pools,
            false,
        )
        .await
        .unwrap();
        match res {
            ScannedPostBody::PassthroughStream {
                prefix,
                rest,
                scanner: Some(scanner),
                captured_id,
            } => {
                assert_eq!(prefix, chunk1);
                assert_eq!(captured_id, Some(json!(7)));
                let mut stream = PrefixedBody::new(
                    prefix,
                    ProxyBody::new(rest, Arc::clone(&pools.proxy)),
                    Box::new(scanner),
                    MAX_REQUEST_BODY_BYTES,
                    BODY_READ_TIMEOUT,
                );
                let _ = stream.frame().await.unwrap().unwrap();
                let rem1 = stream.frame().await.unwrap().unwrap().into_data().unwrap();
                assert_eq!(rem1.len(), 256 * 1024);
                let rem2 = stream.frame().await.unwrap().unwrap().into_data().unwrap();
                assert_eq!(&rem2[..], br#""}}"#);
                assert!(stream.frame().await.is_none());
            }
            _ => panic!("expected early PassthroughStream with live validator"),
        }
    }

    #[tokio::test]
    async fn scanner_rejects_non_string_method_duplicate_tail_and_invalid_batches() {
        let pools = MemoryPools::from_quotas(&QuotaConfig::default());

        // 1. Non-string method fails immediately on chunk 1 without reading oversized chunk 2.
        for bad_first in [
            &br#"{"jsonrpc":"2.0","id":42,"method":123,"pad":""#[..],
            &br#"{"jsonrpc":"2.0","id":"req_a","method":true,"pad":""#[..],
            &br#"{"jsonrpc":"2.0","method":null,"pad":""#[..],
            &br#"{"jsonrpc":"2.0","id":9,"method":{},"pad":""#[..],
            &br#"{"jsonrpc":"2.0","id":9,"method":[],"pad":""#[..],
        ] {
            let incoming = Chunks(
                [
                    Bytes::copy_from_slice(bad_first),
                    Bytes::from(vec![b'x'; MAX_REQUEST_BODY_BYTES + 1024]),
                ]
                .into(),
            );
            let res = scan_or_buffer_json_body(
                incoming,
                MAX_REQUEST_BODY_BYTES,
                BODY_READ_TIMEOUT,
                &pools,
                false,
            )
            .await
            .unwrap();
            assert!(matches!(res, ScannedPostBody::InvalidRequest { .. }));
            if bad_first.windows(7).any(|w| w == br#""id":42"#)
                && let ScannedPostBody::InvalidRequest { captured_id, .. } = res
            {
                assert_eq!(captured_id, Some(json!(42)));
            }
        }

        // 2. Cross-chunk second method or trailing garbage aborts PrefixedBody before yielding bad frame.
        for bad_tail in [
            &br#""},"method":"events/poll"}"#[..],
            &br#""}} garbage"#[..],
        ] {
            let c1 = Bytes::from_static(
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"x":""#,
            );
            let c2 = Bytes::copy_from_slice(bad_tail);
            let res = scan_or_buffer_json_body(
                Chunks([c1.clone(), c2].into()),
                MAX_REQUEST_BODY_BYTES,
                BODY_READ_TIMEOUT,
                &pools,
                false,
            )
            .await
            .unwrap();
            let ScannedPostBody::PassthroughStream {
                prefix,
                rest,
                scanner: Some(scanner),
                ..
            } = res
            else {
                panic!("expected PassthroughStream");
            };
            let mut body = PrefixedBody::new(
                prefix,
                ProxyBody::new(rest, Arc::clone(&pools.proxy)),
                Box::new(scanner),
                MAX_REQUEST_BODY_BYTES,
                BODY_READ_TIMEOUT,
            );
            assert_eq!(
                body.frame().await.unwrap().unwrap().into_data().unwrap(),
                c1
            );
            assert!(body.frame().await.unwrap().is_err());
        }

        // 3. Batch rejections: empty, non-object, non-string/duplicate method, and all 7 controlled methods.
        for bad_batch in [
            "[]".to_owned(),
            "[1]".to_owned(),
            r#"["str"]"#.to_owned(),
            "[true]".to_owned(),
            "[null]".to_owned(),
            "[[]]".to_owned(),
            r#"[{"jsonrpc":"2.0","id":1,"method":99}]"#.to_owned(),
            r#"[{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}]"#.to_owned(),
            r#"[{"jsonrpc":"2.0","id":1,"method":"initialize"}]"#.to_owned(),
            r#"[{"jsonrpc":"2.0","id":1,"method":"server/discover"}]"#.to_owned(),
            r#"[{"jsonrpc":"2.0","id":1,"method":"events/list"}]"#.to_owned(),
            r#"[{"jsonrpc":"2.0","id":1,"method":"events/subscribe"}]"#.to_owned(),
            r#"[{"jsonrpc":"2.0","id":1,"method":"events/unsubscribe"}]"#.to_owned(),
            r#"[{"jsonrpc":"2.0","id":1,"method":"events/poll"}]"#.to_owned(),
            r#"[{"jsonrpc":"2.0","id":1,"method":"events/stream"}]"#.to_owned(),
            r#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"events/poll"}]"#.to_owned(),
        ] {
            for step in [1usize, 4, 64] {
                let mut s = TopLevelJsonScanner::new();
                let mut dec = ScanDecision::NeedMore;
                for ch in bad_batch.as_bytes().chunks(step) {
                    dec = s.feed_chunk(ch);
                    if matches!(dec, ScanDecision::InvalidRequest(_) | ScanDecision::Malformed) {
                        break;
                    }
                }
                if !matches!(dec, ScanDecision::InvalidRequest(_)) {
                    dec = s.finish_eof();
                }
                assert!(
                    matches!(dec, ScanDecision::InvalidRequest(_)),
                    "expected InvalidRequest for {bad_batch} at step {step}, got {dec:?}"
                );
            }
        }

        // 4. Cross-chunk batch where element 2 smuggles a controlled method aborts PrefixedBody.
        let bc1 = Bytes::from_static(br#"[{"jsonrpc":"2.0","id":1,"method":"ping"},"#);
        let bc2 = Bytes::from_static(br#"{"jsonrpc":"2.0","id":2,"method":"events/poll"}]"#);
        let res = scan_or_buffer_json_body(
            Chunks([bc1.clone(), bc2].into()),
            MAX_REQUEST_BODY_BYTES,
            BODY_READ_TIMEOUT,
            &pools,
            false,
        )
        .await
        .unwrap();
        let ScannedPostBody::PassthroughStream {
            prefix,
            rest,
            scanner: Some(scanner),
            ..
        } = res
        else {
            panic!("expected streaming batch");
        };
        let mut body = PrefixedBody::new(
            prefix,
            ProxyBody::new(rest, Arc::clone(&pools.proxy)),
            Box::new(scanner),
            MAX_REQUEST_BODY_BYTES,
            BODY_READ_TIMEOUT,
        );
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            bc1
        );
        assert!(body.frame().await.unwrap().is_err());
    }

    #[tokio::test]
    async fn listener_enforces_connection_cap_header_timeout_and_idle_reap_without_killing_sse() {
        use crate::config::UpstreamConfig;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        // Mock upstream that streams an open SSE response lasting > 2x idle_keepalive_timeout.
        let up_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up_listener.local_addr().unwrap();
        let up_task = tokio::spawn(async move {
            while let Ok((stream, _)) = up_listener.accept().await {
                tokio::spawn(async move {
                    let svc = service_fn(|req: Request<Incoming>| async move {
                        if req.method() == Method::GET && req.uri().path() == "/mcp" {
                            let (tx, rx) =
                                tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
                            tokio::spawn(async move {
                                let _ = tx
                                    .send(Ok(Frame::data(Bytes::from_static(b": first\n\n"))))
                                    .await;
                                tokio::time::sleep(Duration::from_millis(450)).await;
                                let _ = tx
                                    .send(Ok(Frame::data(Bytes::from_static(b"data: done\n\n"))))
                                    .await;
                            });
                            struct ChanBody(
                                tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, Infallible>>,
                            );
                            impl Body for ChanBody {
                                type Data = Bytes;
                                type Error = Infallible;
                                fn poll_frame(
                                    mut self: Pin<&mut Self>,
                                    cx: &mut Context<'_>,
                                ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>>
                                {
                                    self.0.poll_recv(cx)
                                }
                            }
                            let resp = Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_TYPE, "text/event-stream")
                                .body(ChanBody(rx).boxed())
                                .unwrap();
                            return Ok::<_, Infallible>(resp);
                        }
                        if req.method() == Method::POST
                            && req.uri().path() == "/mcp"
                            && req.into_body().collect().await.is_err()
                        {
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::BAD_REQUEST)
                                    .body(Empty::<Bytes>::new().boxed())
                                    .unwrap(),
                            );
                        }
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Empty::<Bytes>::new().boxed())
                                .unwrap(),
                        )
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        let dir = tempfile::TempDir::new().unwrap();
        let cfg = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            resource_path: "/mcp".into(),
            state_path: dir.path().join("state.json"),
            profile: Profile::Sep3415,
            inbound_tokens: vec![SecretString::new("inbound-secret-tok-1")],
            allowed_origins: Vec::new(),
            max_ttl_secs: 3600,
            auth_context: None,
            upstream: Some(UpstreamConfig {
                url: url::Url::parse(&format!("http://{up_addr}/mcp")).unwrap(),
                bearer_token: None,
                passthrough_prefixes: Vec::new(),
                request_timeout_secs: 10,
                expose_events: Vec::new(),
            }),
            ingest: None,
        };
        let srv = start_server_with_limits(
            cfg,
            QuotaConfig::default(),
            None,
            ListenerLimits {
                max_connections: 2,
                header_read_timeout: Duration::from_millis(120),
                idle_keepalive_timeout: Duration::from_millis(180),
                body_read_timeout: Duration::from_millis(150),
                max_request_body_bytes: 2048,
            },
        )
        .await
        .unwrap();
        let addr = srv.local_addr();

        // 1. Long-lived GET /mcp SSE stream (450ms) survives well past idle_keepalive_timeout (180ms).
        let mut sse_conn = TcpStream::connect(addr).await.unwrap();
        sse_conn
            .write_all(
                b"GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer inbound-secret-tok-1\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();

        // 2. Simultaneously occupy slot #2 with a Slowloris partial-header connection, and verify slot #3 is dropped.
        let mut slow_conn = TcpStream::connect(addr).await.unwrap();
        slow_conn
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let mut overflow_conn = TcpStream::connect(addr).await.unwrap();
        let mut probe = [0u8; 16];
        let n_overflow =
            tokio::time::timeout(Duration::from_millis(150), overflow_conn.read(&mut probe))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            n_overflow, 0,
            "expected 3rd connection past max_connections=2 to close immediately"
        );

        // Slowloris connection must be closed by header_read_timeout (~120ms).
        let n_slow = tokio::time::timeout(Duration::from_millis(300), slow_conn.read(&mut probe))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            n_slow, 0,
            "expected Slowloris connection to be closed by header_read_timeout"
        );

        // Meanwhile SSE stream on slot #1 must still complete with "data: done".
        let mut sse_bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), sse_conn.read_to_end(&mut sse_bytes))
            .await
            .unwrap()
            .unwrap();
        let sse_str = String::from_utf8_lossy(&sse_bytes);
        assert!(
            sse_str.contains("200 OK"),
            "unexpected SSE response: {sse_str}"
        );
        assert!(
            sse_str.contains("data: done"),
            "SSE stream was prematurely terminated: {sse_str}"
        );

        // 3. Idle Keep-Alive connection is gracefully closed after idle_keepalive_timeout (~180ms).
        let mut ka_conn = TcpStream::connect(addr).await.unwrap();
        ka_conn
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut ka_buf = [0u8; 512];
        let n_ka = ka_conn.read(&mut ka_buf).await.unwrap();
        assert!(String::from_utf8_lossy(&ka_buf[..n_ka]).contains("200 OK"));
        let n_eof = tokio::time::timeout(Duration::from_millis(450), ka_conn.read(&mut probe))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n_eof, 0, "expected idle keep-alive connection to be reaped");

        // 4. Cross-chunk cutover aborts restore exact HTTP statuses (400 -32600, 413, and 408) instead of 502.
        let send_split_chunked = |chunk1: &[u8], pause_ms: u64, chunk2: Option<&[u8]>| {
            let chunk1 = chunk1.to_vec();
            let chunk2 = chunk2.map(|b| b.to_vec());
            async move {
                let mut conn = TcpStream::connect(addr).await.unwrap();
                let _ = conn.set_nodelay(true);
                conn.write_all(
                    b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer inbound-secret-tok-1\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
                let h1 = format!("{:x}\r\n", chunk1.len());
                conn.write_all(h1.as_bytes()).await.unwrap();
                conn.write_all(&chunk1).await.unwrap();
                conn.write_all(b"\r\n").await.unwrap();
                conn.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(pause_ms)).await;
                if let Some(c2) = chunk2 {
                    let h2 = format!("{:x}\r\n", c2.len());
                    let _ = conn.write_all(h2.as_bytes()).await;
                    let _ = conn.write_all(&c2).await;
                    let _ = conn.write_all(b"\r\n0\r\n\r\n").await;
                    let _ = conn.flush().await;
                }
                let mut raw_resp = Vec::new();
                conn.read_to_end(&mut raw_resp).await.unwrap();
                String::from_utf8_lossy(&raw_resp).into_owned()
            }
        };

        // 4a. Second TCP chunk injects duplicate method -> 400 Bad Request with JSON-RPC -32600 and id=55.
        let resp_dup = send_split_chunked(
            br#"{"jsonrpc":"2.0","id":55,"method":"tools/call","params":{"x":"ok""#,
            30,
            Some(br#"},"method":"events/poll"}"#),
        )
        .await;
        assert!(
            resp_dup.starts_with("HTTP/1.1 400 Bad Request"),
            "expected 400 on split duplicate method, got: {resp_dup}"
        );
        let body_dup = resp_dup.split("\r\n\r\n").nth(1).unwrap();
        let json_dup: Value = serde_json::from_str(body_dup).unwrap();
        assert_eq!(json_dup["id"], 55);
        assert_eq!(json_dup["error"]["code"], -32600);

        // 4b. Second TCP chunk exceeds max_request_body_bytes (2048) -> 413 Payload Too Large.
        let big_second = format!("{}\"}}", "a".repeat(2500));
        let resp_413 = send_split_chunked(
            br#"{"jsonrpc":"2.0","id":56,"method":"tools/call","params":{"x":""#,
            30,
            Some(big_second.as_bytes()),
        )
        .await;
        assert!(
            resp_413.starts_with("HTTP/1.1 413 Payload Too Large"),
            "expected 413 on split oversized body, got: {resp_413}"
        );

        // 4c. Stalling past body_read_timeout (150ms) after first chunk -> 408 Request Timeout.
        let resp_408 = send_split_chunked(
            br#"{"jsonrpc":"2.0","id":57,"method":"tools/call","params":{"x":""#,
            260,
            None,
        )
        .await;
        assert!(
            resp_408.starts_with("HTTP/1.1 408 Request Timeout"),
            "expected 408 on split inter-frame timeout, got: {resp_408}"
        );

        srv.shutdown().await.unwrap();
        up_task.abort();
    }
}
