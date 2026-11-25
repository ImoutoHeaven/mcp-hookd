//! Upstream HTTP MCP client: raw streaming proxy, handshake capability injection,
//! session ping keepalive, and 2026-07-28 events/list, events/poll, and events/stream.

use crate::config::UpstreamConfig;
use crate::headers::{
    build_event_routing_headers, build_upstream_headers, strip_hop_by_hop_response_headers,
    url_authority,
};
use crate::types::{
    MAX_HANDSHAKE_BODY_BYTES, MAX_PING_BODY_BYTES, PROTOCOL_VERSION_MODERN, Profile, SecretString,
    random_hex,
};
use bytes::{BufMut, Bytes, BytesMut};
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body::Body;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use url::Url;

const PING_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CATALOG_PAGES: usize = 128;
const MAX_CONTROL_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_SSE_FRAME_BYTES: usize = 1024 * 1024;

type ReqBody = BoxBody<Bytes, io::Error>;

#[derive(Debug)]
pub enum UpstreamError {
    Http(String),
    Timeout,
    BodyTooLarge {
        limit: usize,
    },
    InvalidResponse(String),
    JsonRpc {
        code: i64,
        message: String,
        data: Option<Value>,
    },
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(msg) => write!(f, "upstream HTTP error: {msg}"),
            Self::Timeout => write!(f, "upstream request timed out"),
            Self::BodyTooLarge { limit } => {
                write!(f, "upstream response exceeded {limit} byte limit")
            }
            Self::InvalidResponse(msg) => write!(f, "invalid upstream response: {msg}"),
            Self::JsonRpc { code, message, .. } => {
                write!(f, "upstream JSON-RPC error {code}: {message}")
            }
        }
    }
}

impl std::error::Error for UpstreamError {}

#[derive(Clone, Debug)]
pub struct HandshakeResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamEventDescriptor {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub delivery: Vec<String>,
    #[serde(default)]
    pub input_schema: Value,
    #[serde(default)]
    pub payload_schema: Value,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamPolledEvent {
    pub event_id: String,
    pub name: String,
    pub timestamp: String,
    pub data: Value,
}

fn default_next_poll_ms() -> u64 {
    5000
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamPollResponse {
    pub events: Vec<UpstreamPolledEvent>,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default = "default_next_poll_ms")]
    pub next_poll_ms: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum UpstreamStreamFrame {
    Active {
        cursor: Option<String>,
        truncated: bool,
        heartbeat_ms: Option<u64>,
    },
    Heartbeat {
        cursor: Option<String>,
    },
    Event {
        event_id: String,
        name: String,
        timestamp: String,
        data: Value,
        cursor: Option<String>,
    },
    Error {
        code: Option<i64>,
        message: String,
        data: Option<Value>,
    },
    Terminated {
        code: Option<i64>,
        message: String,
        data: Option<Value>,
    },
}

pub struct UpstreamEventStream {
    body: Incoming,
    buf: BytesMut,
    eof: bool,
    at_start: bool,
}

impl UpstreamEventStream {
    fn new(body: Incoming) -> Self {
        Self {
            body,
            buf: BytesMut::new(),
            eof: false,
            at_start: true,
        }
    }

    /// Read the next structured `notifications/events/*` frame, returning `Ok(None)` on clean EOF.
    pub async fn next_frame(&mut self) -> Result<Option<UpstreamStreamFrame>, UpstreamError> {
        loop {
            while let Some(raw_frame) = take_sse_frame(&mut self.buf) {
                if let Some(data) =
                    extract_sse_data(&raw_frame, std::mem::replace(&mut self.at_start, false))
                {
                    if data.trim().is_empty() {
                        continue;
                    }
                    let msg: Value = serde_json::from_str(&data).map_err(|e| {
                        UpstreamError::InvalidResponse(format!("invalid SSE JSON frame: {e}"))
                    })?;
                    if let Some(frame) = classify_stream_message(&msg)? {
                        return Ok(Some(frame));
                    }
                    // A JSON-RPC `result` frame marks clean stream completion.
                    if msg.get("result").is_some() {
                        return Ok(None);
                    }
                }
            }

            if self.eof {
                return Ok(None);
            }

            match self.body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(chunk) = frame.into_data() {
                        if self.buf.len() + chunk.len() > MAX_SSE_FRAME_BYTES {
                            return Err(UpstreamError::BodyTooLarge {
                                limit: MAX_SSE_FRAME_BYTES,
                            });
                        }
                        self.buf.put_slice(&chunk);
                    }
                }
                Some(Err(e)) => return Err(UpstreamError::Http(e.to_string())),
                None => {
                    self.eof = true;
                    if !self.buf.is_empty() {
                        // Flush any trailing frame not terminated by a blank line.
                        self.buf.put_slice(b"\n\n");
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct UpstreamClient {
    client: Client<HttpsConnector<HttpConnector>, ReqBody>,
    url: Url,
    origin_base: String,
    bearer_token: Option<SecretString>,
    default_timeout: Duration,
    req_counter: Arc<AtomicU64>,
}

impl UpstreamClient {
    pub fn new(config: &UpstreamConfig) -> Result<Self, String> {
        let authority = url_authority(&config.url)?;
        let origin_base = format!("{}://{authority}", config.url.scheme());

        let mut root_store = rustls::RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = root_store.add(cert);
        }
        let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("failed to configure TLS versions: {e}"))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .wrap_connector(http);

        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .build(https);

        Ok(Self {
            client,
            url: config.url.clone(),
            origin_base,
            bearer_token: config.bearer_token.clone(),
            default_timeout: Duration::from_secs(config.request_timeout_secs),
            req_counter: Arc::new(AtomicU64::new(1)),
        })
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    fn next_id(&self, prefix: &str) -> String {
        let seq = self.req_counter.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}_{seq}")
    }

    fn target_uri(&self, path_and_query: Option<&str>) -> Result<Uri, UpstreamError> {
        let raw = match path_and_query {
            Some(pq) => format!("{}{pq}", self.origin_base),
            None => self.url.as_str().to_owned(),
        };
        raw.parse::<Uri>()
            .map_err(|e| UpstreamError::Http(format!("invalid target URI: {e}")))
    }

    /// Stream an HTTP request with sanitized headers and raw body bytes to upstream.
    pub async fn forward_raw<B>(
        &self,
        method: Method,
        path_and_query: Option<&str>,
        inbound_headers: &HeaderMap,
        body: B,
        inject_auth: bool,
        timeout: Option<Duration>,
    ) -> Result<Response<Incoming>, UpstreamError>
    where
        B: Body<Data = Bytes> + Send + Sync + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let uri = self.target_uri(path_and_query)?;
        let headers = build_upstream_headers(
            inbound_headers,
            &self.url,
            self.bearer_token.as_ref(),
            inject_auth,
        )
        .map_err(UpstreamError::Http)?;

        let boxed = body.map_err(|e| io::Error::other(e.into())).boxed();
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(h) = req.headers_mut() {
            *h = headers;
        }
        let req = req
            .body(boxed)
            .map_err(|e| UpstreamError::Http(format!("failed to build request: {e}")))?;

        let dur = timeout.unwrap_or(self.default_timeout);
        tokio::time::timeout(dur, self.client.request(req))
            .await
            .map_err(|_| UpstreamError::Timeout)?
            .map_err(|e| UpstreamError::Http(e.to_string()))
    }

    /// Forward `initialize` or `server/discover`, injecting Events capabilities per spec §4.2.
    pub async fn forward_handshake(
        &self,
        inbound_headers: &HeaderMap,
        body: Bytes,
        profile: Profile,
        timeout: Option<Duration>,
    ) -> Result<HandshakeResponse, UpstreamError> {
        let dur = timeout.unwrap_or(self.default_timeout);
        let deadline = tokio::time::Instant::now() + dur;
        let request: Value = serde_json::from_slice(&body)
            .map_err(|e| UpstreamError::Http(format!("invalid handshake request: {e}")))?;
        let request_id = request
            .get("id")
            .ok_or_else(|| UpstreamError::Http("handshake request is missing id".into()))?;

        let resp = self
            .forward_raw(
                Method::POST,
                None,
                inbound_headers,
                Full::new(body),
                true,
                Some(dur),
            )
            .await?;

        let status = resp.status();
        let mut headers = strip_hop_by_hop_response_headers(resp.headers());
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let content_type = media_type(&headers);
        let transformed = if status.is_success()
            && content_type.as_deref() == Some("text/event-stream")
        {
            read_sse_handshake(resp.into_body(), request_id, profile, remaining).await?
        } else {
            let raw_body =
                read_body_bounded(resp.into_body(), MAX_HANDSHAKE_BODY_BYTES, remaining).await?;
            if status.is_success() && content_type.as_deref() == Some("application/json") {
                rewrite_json_handshake(&raw_body, profile)?
            } else {
                raw_body
            }
        };

        headers.remove(header::CONTENT_LENGTH);
        if let Ok(len_val) = HeaderValue::from_str(&transformed.len().to_string()) {
            headers.insert(header::CONTENT_LENGTH, len_val);
        }

        Ok(HandshakeResponse {
            status,
            headers,
            body: transformed,
        })
    }

    /// Verify and keep alive a legacy upstream session using a CSPRNG random ping ID (5s timeout, 4 KiB cap).
    pub async fn ping_session(
        &self,
        session_id: &str,
        protocol_version: Option<&str>,
    ) -> Result<bool, UpstreamError> {
        let rand_hex = random_hex(16).map_err(UpstreamError::Http)?;
        let ping_id = format!("hookd_ping_{rand_hex}");
        let payload = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": ping_id,
            "method": "ping"
        }))
        .map_err(|e| UpstreamError::Http(e.to_string()))?;

        let mut inbound = HeaderMap::new();
        inbound.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        inbound.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        inbound.insert(
            HeaderName::from_static("mcp-session-id"),
            HeaderValue::from_str(session_id)
                .map_err(|e| UpstreamError::Http(format!("invalid session_id header: {e}")))?,
        );
        if let Some(ver) = protocol_version {
            inbound.insert(
                HeaderName::from_static("mcp-protocol-version"),
                HeaderValue::from_str(ver).map_err(|e| {
                    UpstreamError::Http(format!("invalid protocol_version header: {e}"))
                })?,
            );
        }

        let deadline = tokio::time::Instant::now() + PING_TIMEOUT;
        let resp = self
            .forward_raw(
                Method::POST,
                None,
                &inbound,
                Full::new(Bytes::from(payload)),
                true,
                Some(PING_TIMEOUT),
            )
            .await?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if resp.status() != StatusCode::OK {
            return Err(UpstreamError::InvalidResponse(format!(
                "upstream ping returned HTTP {}",
                resp.status()
            )));
        }

        let is_sse = media_type(resp.headers()).as_deref() == Some("text/event-stream");
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let msg = if is_sse {
            read_first_sse_json_bounded(resp.into_body(), MAX_PING_BODY_BYTES, remaining).await?
        } else {
            let bytes = read_body_bounded(resp.into_body(), MAX_PING_BODY_BYTES, remaining).await?;
            serde_json::from_slice::<Value>(&bytes).map_err(|e| {
                UpstreamError::InvalidResponse(format!("invalid ping JSON response: {e}"))
            })?
        };

        if msg.get("error").is_some() {
            return Err(parse_jsonrpc_error(&msg));
        }
        if msg.get("result").is_none() {
            return Err(UpstreamError::InvalidResponse(
                "upstream ping response missing 'result'".into(),
            ));
        }
        if msg.get("id").and_then(Value::as_str) != Some(ping_id.as_str()) {
            return Err(UpstreamError::InvalidResponse(
                "upstream ping response id missing or mismatch".into(),
            ));
        }
        Ok(true)
    }

    /// Fetch the full upstream `events/list` catalog across all pages using 2026-07-28 headers.
    pub async fn list_events_all_pages(
        &self,
        allow_method_not_found: bool,
    ) -> Result<Vec<UpstreamEventDescriptor>, UpstreamError> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = HashSet::new();

        for _ in 0..MAX_CATALOG_PAGES {
            let mut params = Map::new();
            params.insert("_meta".into(), modern_client_meta());
            if let Some(ref c) = cursor {
                params.insert("cursor".into(), Value::String(c.clone()));
            }

            let resp = match self
                .call_modern_jsonrpc("events/list", Value::Object(params), &[])
                .await
            {
                Ok(v) => v,
                Err(UpstreamError::JsonRpc { code: -32601, .. }) if allow_method_not_found => {
                    return Ok(Vec::new());
                }
                Err(e) => return Err(e),
            };

            let result = resp.get("result").ok_or_else(|| {
                UpstreamError::InvalidResponse("events/list response missing 'result'".into())
            })?;
            let page_events: Vec<UpstreamEventDescriptor> = result
                .get("events")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .map_err(|e| {
                    UpstreamError::InvalidResponse(format!("invalid events/list items: {e}"))
                })?
                .unwrap_or_default();
            all.extend(page_events);

            match result.get("nextCursor").and_then(Value::as_str) {
                Some(next) if !next.is_empty() => {
                    if !seen_cursors.insert(next.to_owned()) {
                        return Err(UpstreamError::InvalidResponse(
                            "events/list returned duplicate nextCursor".into(),
                        ));
                    }
                    cursor = Some(next.to_owned());
                }
                _ => return Ok(all),
            }
        }

        Err(UpstreamError::InvalidResponse(
            "events/list exceeded maximum page count".into(),
        ))
    }

    /// Call upstream `events/poll` with 2026-07-28 headers, `Mcp-Name`, `Mcp-Param-*`, and `params._meta`.
    pub async fn poll_events(
        &self,
        name: &str,
        arguments: Option<&Map<String, Value>>,
        cursor: Option<&str>,
        max_age_ms: Option<u64>,
        max_events: Option<usize>,
    ) -> Result<UpstreamPollResponse, UpstreamError> {
        let mut params = Map::new();
        params.insert("_meta".into(), modern_client_meta());
        params.insert("name".into(), Value::String(name.to_owned()));
        if let Some(args) = arguments
            && !args.is_empty()
        {
            params.insert("arguments".into(), Value::Object(args.clone()));
        }
        if let Some(c) = cursor {
            params.insert("cursor".into(), Value::String(c.to_owned()));
        }
        if let Some(ms) = max_age_ms {
            params.insert("maxAgeMs".into(), json!(ms));
        }
        if let Some(max) = max_events {
            params.insert("maxEvents".into(), json!(max));
        }

        let routing = build_event_routing_headers(name, arguments).map_err(UpstreamError::Http)?;
        let resp = self
            .call_modern_jsonrpc("events/poll", Value::Object(params), &routing)
            .await?;

        let result = resp.get("result").cloned().ok_or_else(|| {
            UpstreamError::InvalidResponse("events/poll response missing 'result'".into())
        })?;
        serde_json::from_value(result)
            .map_err(|e| UpstreamError::InvalidResponse(format!("invalid events/poll result: {e}")))
    }

    /// Open an upstream `events/stream` SSE subscription with 2026-07-28 headers and routing headers.
    pub async fn open_event_stream(
        &self,
        name: &str,
        arguments: Option<&Map<String, Value>>,
        cursor: Option<&str>,
        max_age_ms: Option<u64>,
        heartbeat_ms: Option<u64>,
    ) -> Result<UpstreamEventStream, UpstreamError> {
        let mut params = Map::new();
        params.insert("_meta".into(), modern_client_meta());
        params.insert("name".into(), Value::String(name.to_owned()));
        if let Some(args) = arguments
            && !args.is_empty()
        {
            params.insert("arguments".into(), Value::Object(args.clone()));
        }
        if let Some(c) = cursor {
            params.insert("cursor".into(), Value::String(c.to_owned()));
        }
        if let Some(ms) = max_age_ms {
            params.insert("maxAgeMs".into(), json!(ms));
        }
        if let Some(hb) = heartbeat_ms {
            params.insert("heartbeatMs".into(), json!(hb));
        }

        let routing = build_event_routing_headers(name, arguments).map_err(UpstreamError::Http)?;
        let inbound = build_modern_request_headers("events/stream", &routing)?;
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": self.next_id("hookd_stream"),
            "method": "events/stream",
            "params": Value::Object(params),
        }))
        .map_err(|e| UpstreamError::Http(e.to_string()))?;

        let resp = self
            .forward_raw(
                Method::POST,
                None,
                &inbound,
                Full::new(Bytes::from(body)),
                true,
                Some(self.default_timeout),
            )
            .await?;

        let status = resp.status();
        let ct = media_type(resp.headers());
        if status.is_success() && ct.as_deref() == Some("text/event-stream") {
            return Ok(UpstreamEventStream::new(resp.into_body()));
        }

        let raw = read_body_bounded(
            resp.into_body(),
            MAX_CONTROL_RESPONSE_BYTES,
            Duration::from_secs(10),
        )
        .await?;
        if let Ok(msg) = serde_json::from_slice::<Value>(&raw)
            && msg.get("error").is_some()
        {
            return Err(parse_jsonrpc_error(&msg));
        }
        Err(UpstreamError::InvalidResponse(format!(
            "events/stream returned HTTP {status} with content-type {ct:?}"
        )))
    }

    async fn call_modern_jsonrpc(
        &self,
        method: &str,
        params: Value,
        extra_headers: &[(HeaderName, HeaderValue)],
    ) -> Result<Value, UpstreamError> {
        let inbound = build_modern_request_headers(method, extra_headers)?;
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": self.next_id("hookd_rpc"),
            "method": method,
            "params": params,
        }))
        .map_err(|e| UpstreamError::Http(e.to_string()))?;

        let deadline = tokio::time::Instant::now() + self.default_timeout;
        let resp = self
            .forward_raw(
                Method::POST,
                None,
                &inbound,
                Full::new(Bytes::from(body)),
                true,
                Some(self.default_timeout),
            )
            .await?;

        let status = resp.status();
        let ct = media_type(resp.headers());
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());

        let msg = if ct.as_deref() == Some("text/event-stream") {
            read_first_sse_json_bounded(resp.into_body(), MAX_CONTROL_RESPONSE_BYTES, remaining)
                .await?
        } else {
            let bytes =
                read_body_bounded(resp.into_body(), MAX_CONTROL_RESPONSE_BYTES, remaining).await?;
            match serde_json::from_slice::<Value>(&bytes) {
                Ok(v) => v,
                Err(_) if !status.is_success() => {
                    return Err(UpstreamError::InvalidResponse(format!(
                        "{method} returned HTTP {status}"
                    )));
                }
                Err(e) => {
                    return Err(UpstreamError::InvalidResponse(format!(
                        "{method} returned invalid JSON: {e}"
                    )));
                }
            }
        };

        if msg.get("error").is_some() {
            return Err(parse_jsonrpc_error(&msg));
        }
        if !status.is_success() {
            return Err(UpstreamError::InvalidResponse(format!(
                "{method} returned HTTP {status} without JSON-RPC error"
            )));
        }
        Ok(msg)
    }
}

fn build_modern_request_headers(
    method: &str,
    extra: &[(HeaderName, HeaderValue)],
) -> Result<HeaderMap, UpstreamError> {
    let mut headers = HeaderMap::with_capacity(4 + extra.len());
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("application/json, text/event-stream"),
    );
    headers.insert(
        HeaderName::from_static("mcp-protocol-version"),
        HeaderValue::from_static(PROTOCOL_VERSION_MODERN),
    );
    headers.insert(
        HeaderName::from_static("mcp-method"),
        HeaderValue::from_str(method)
            .map_err(|e| UpstreamError::Http(format!("invalid Mcp-Method header: {e}")))?,
    );
    for (k, v) in extra {
        headers.append(k.clone(), v.clone());
    }
    Ok(headers)
}

fn modern_client_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION_MODERN,
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {
                "io.modelcontextprotocol/events": {}
            }
        },
        "io.modelcontextprotocol/clientInfo": {
            "name": "mcp-hookd",
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}

fn media_type(headers: &HeaderMap) -> Option<String> {
    let ct = headers.get(header::CONTENT_TYPE)?.to_str().ok()?;
    let main = ct.split(';').next()?.trim();
    if main.is_empty() {
        None
    } else {
        Some(main.to_ascii_lowercase())
    }
}

fn parse_jsonrpc_error(msg: &Value) -> UpstreamError {
    let Some(err) = msg.get("error").and_then(Value::as_object) else {
        return UpstreamError::InvalidResponse("malformed JSON-RPC error object".into());
    };
    let code = err.get("code").and_then(Value::as_i64).unwrap_or(-32603);
    let message = err
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("upstream error")
        .to_owned();
    let data = err.get("data").cloned();
    UpstreamError::JsonRpc {
        code,
        message,
        data,
    }
}

/// Inject Events capabilities into a `initialize` or `server/discover` JSON-RPC response per §4.2.
pub fn inject_handshake_capabilities(payload: &mut Value, profile: Profile) -> bool {
    let Some(result) = payload.get_mut("result").and_then(Value::as_object_mut) else {
        return false;
    };

    let is_modern = result.contains_key("supportedVersions")
        || result.get("protocolVersion").and_then(Value::as_str) == Some(PROTOCOL_VERSION_MODERN);

    if !is_modern && profile == Profile::Sep3415 {
        return false;
    }

    let caps = result
        .entry("capabilities")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(caps_obj) = caps.as_object_mut() else {
        return false;
    };

    if is_modern {
        let extensions = caps_obj
            .entry("extensions")
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(ext_obj) = extensions.as_object_mut() {
            ext_obj.insert(
                "io.modelcontextprotocol/events".into(),
                json!({ "listChanged": false }),
            );
        }
        if profile == Profile::Chatgpt {
            caps_obj
                .entry("events")
                .or_insert_with(|| Value::Object(Map::new()));
        }
        true
    } else {
        caps_obj
            .entry("events")
            .or_insert_with(|| Value::Object(Map::new()));
        true
    }
}

fn rewrite_json_handshake(raw: &Bytes, profile: Profile) -> Result<Bytes, UpstreamError> {
    let mut val: Value = serde_json::from_slice(raw)
        .map_err(|e| UpstreamError::InvalidResponse(format!("invalid handshake JSON body: {e}")))?;
    if inject_handshake_capabilities(&mut val, profile) {
        let encoded =
            serde_json::to_vec(&val).map_err(|e| UpstreamError::InvalidResponse(e.to_string()))?;
        Ok(Bytes::from(encoded))
    } else {
        Ok(raw.clone())
    }
}

async fn read_sse_handshake(
    mut body: Incoming,
    request_id: &Value,
    profile: Profile,
    timeout: Duration,
) -> Result<Bytes, UpstreamError> {
    tokio::time::timeout(timeout, async {
        let mut buf = BytesMut::new();
        let mut out = String::new();
        let mut total_read = 0usize;
        let mut at_start = true;
        let mut eof = false;
        loop {
            while let Some(frame) = take_sse_frame(&mut buf) {
                let first = std::mem::replace(&mut at_start, false);
                let response = extract_sse_data(&frame, first)
                    .filter(|data| !data.trim().is_empty())
                    .and_then(|data| serde_json::from_str::<Value>(&data).ok())
                    .filter(|msg| {
                        msg.get("id") == Some(request_id)
                            && (msg.get("result").is_some() || msg.get("error").is_some())
                    });
                if let Some(mut response) = response {
                    if inject_handshake_capabilities(&mut response, profile) {
                        let encoded = serde_json::to_string(&response)
                            .map_err(|e| UpstreamError::InvalidResponse(e.to_string()))?;
                        write_sse_frame_with_data(&mut out, &frame, &encoded, first);
                    } else {
                        out.push_str(&frame);
                    }
                    return Ok(Bytes::from(out));
                }
                out.push_str(&frame);
            }
            if eof {
                return Err(UpstreamError::InvalidResponse(
                    "handshake SSE ended without the requested response".into(),
                ));
            }
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(chunk) = frame.into_data() {
                        total_read += chunk.len();
                        if total_read > MAX_HANDSHAKE_BODY_BYTES {
                            return Err(UpstreamError::BodyTooLarge {
                                limit: MAX_HANDSHAKE_BODY_BYTES,
                            });
                        }
                        buf.put_slice(&chunk);
                    }
                }
                Some(Err(e)) => return Err(UpstreamError::Http(e.to_string())),
                None => {
                    eof = true;
                    if !buf.is_empty() {
                        buf.put_slice(b"\n\n");
                    }
                }
            }
        }
    })
    .await
    .map_err(|_| UpstreamError::Timeout)?
}

fn sse_lines(text: &str) -> impl Iterator<Item = (&str, &str)> {
    let mut rest = text;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let end = rest.find(['\r', '\n']).unwrap_or(rest.len());
        let mut next = end;
        if next < rest.len() {
            next += 1;
            if rest.as_bytes()[end] == b'\r' && rest.as_bytes().get(next) == Some(&b'\n') {
                next += 1;
            }
        }
        let line = (&rest[..end], &rest[end..next]);
        rest = &rest[next..];
        Some(line)
    })
}

fn write_sse_frame_with_data(out: &mut String, frame: &str, new_data: &str, at_start: bool) {
    let mut wrote_data = false;
    for (index, (line, ending)) in sse_lines(frame).enumerate() {
        let clean = if at_start && index == 0 {
            line.strip_prefix('\u{feff}').unwrap_or(line)
        } else {
            line
        };
        if clean.starts_with("data:") || clean == "data" {
            if !wrote_data {
                if clean.len() != line.len() {
                    out.push('\u{feff}');
                }
                out.push_str("data: ");
                out.push_str(new_data);
                out.push_str(ending);
                wrote_data = true;
            }
        } else {
            out.push_str(line);
            out.push_str(ending);
        }
    }
}

fn take_sse_frame(buf: &mut BytesMut) -> Option<String> {
    let mut line_start = 0;
    let mut index = 0;
    while index < buf.len() {
        if matches!(buf[index], b'\r' | b'\n') {
            let mut next = index + 1;
            if buf[index] == b'\r' && buf.get(next) == Some(&b'\n') {
                next += 1;
            }
            if index == line_start {
                return Some(String::from_utf8_lossy(&buf.split_to(next)).into_owned());
            }
            line_start = next;
            index = next;
        } else {
            index += 1;
        }
    }
    None
}

fn extract_sse_data(frame: &str, at_start: bool) -> Option<String> {
    let frame = if at_start {
        frame.strip_prefix('\u{feff}').unwrap_or(frame)
    } else {
        frame
    };
    let mut data_lines = Vec::new();
    for (line, _) in sse_lines(frame) {
        if let Some(rest) = line.strip_prefix("data:") {
            data_lines.push(rest.strip_prefix(' ').unwrap_or(rest));
        } else if line == "data" {
            data_lines.push("");
        }
    }
    if data_lines.is_empty() {
        None
    } else {
        Some(data_lines.join("\n"))
    }
}

fn classify_stream_message(msg: &Value) -> Result<Option<UpstreamStreamFrame>, UpstreamError> {
    if msg.get("error").is_some() {
        return Err(parse_jsonrpc_error(msg));
    }
    let Some(method) = msg.get("method").and_then(Value::as_str) else {
        return Ok(None);
    };
    let params = msg.get("params");
    match method {
        "notifications/events/active" => Ok(Some(UpstreamStreamFrame::Active {
            cursor: params
                .and_then(|p| p.get("cursor"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            truncated: params
                .and_then(|p| p.get("truncated"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
            heartbeat_ms: params
                .and_then(|p| p.get("heartbeatMs"))
                .and_then(Value::as_u64),
        })),
        "notifications/events/heartbeat" => Ok(Some(UpstreamStreamFrame::Heartbeat {
            cursor: params
                .and_then(|p| p.get("cursor"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
        })),
        "notifications/events/event" => {
            let obj = params.and_then(Value::as_object).ok_or_else(|| {
                UpstreamError::InvalidResponse("notifications/events/event missing params".into())
            })?;
            let event_id = obj
                .get("eventId")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    UpstreamError::InvalidResponse("event frame missing 'eventId'".into())
                })?
                .to_owned();
            let name = obj
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| UpstreamError::InvalidResponse("event frame missing 'name'".into()))?
                .to_owned();
            let timestamp = obj
                .get("timestamp")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let data = obj.get("data").cloned().unwrap_or(Value::Null);
            let cursor = obj
                .get("cursor")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            Ok(Some(UpstreamStreamFrame::Event {
                event_id,
                name,
                timestamp,
                data,
                cursor,
            }))
        }
        "notifications/events/error" => {
            let (code, message, data) = extract_error_fields(params);
            Ok(Some(UpstreamStreamFrame::Error {
                code,
                message,
                data,
            }))
        }
        "notifications/events/terminated" => {
            let (code, message, data) = extract_error_fields(params);
            Ok(Some(UpstreamStreamFrame::Terminated {
                code,
                message,
                data,
            }))
        }
        _ => Ok(None),
    }
}

fn extract_error_fields(params: Option<&Value>) -> (Option<i64>, String, Option<Value>) {
    let err = params.and_then(|p| p.get("error")).or(params);
    let code = err.and_then(|e| e.get("code")).and_then(Value::as_i64);
    let message = err
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("upstream stream error")
        .to_owned();
    let data = err.and_then(|e| e.get("data")).cloned();
    (code, message, data)
}

async fn read_body_bounded(
    mut body: Incoming,
    limit: usize,
    timeout: Duration,
) -> Result<Bytes, UpstreamError> {
    tokio::time::timeout(timeout, async {
        let mut out = BytesMut::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| UpstreamError::Http(e.to_string()))?;
            if let Ok(chunk) = frame.into_data() {
                if out.len() + chunk.len() > limit {
                    return Err(UpstreamError::BodyTooLarge { limit });
                }
                out.put_slice(&chunk);
            }
        }
        Ok(out.freeze())
    })
    .await
    .map_err(|_| UpstreamError::Timeout)?
}

async fn read_first_sse_json_bounded(
    mut body: Incoming,
    limit: usize,
    timeout: Duration,
) -> Result<Value, UpstreamError> {
    tokio::time::timeout(timeout, async {
        let mut buf = BytesMut::new();
        let mut total_read = 0usize;
        let mut eof = false;
        let mut at_start = true;
        loop {
            while let Some(raw_frame) = take_sse_frame(&mut buf) {
                if let Some(data) =
                    extract_sse_data(&raw_frame, std::mem::replace(&mut at_start, false))
                    && !data.trim().is_empty()
                {
                    let msg: Value = serde_json::from_str(&data).map_err(|e| {
                        UpstreamError::InvalidResponse(format!("invalid SSE JSON: {e}"))
                    })?;
                    if msg.get("result").is_some() || msg.get("error").is_some() {
                        return Ok(msg);
                    }
                }
            }
            if eof {
                return Err(UpstreamError::InvalidResponse(
                    "SSE stream ended without a JSON-RPC response frame".into(),
                ));
            }
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(chunk) = frame.into_data() {
                        total_read += chunk.len();
                        if total_read > limit {
                            return Err(UpstreamError::BodyTooLarge { limit });
                        }
                        buf.put_slice(&chunk);
                    }
                }
                Some(Err(e)) => return Err(UpstreamError::Http(e.to_string())),
                None => {
                    eof = true;
                    if !buf.is_empty() {
                        buf.put_slice(b"\n\n");
                    }
                }
            }
        }
    })
    .await
    .map_err(|_| UpstreamError::Timeout)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    async fn spawn_mock_server<F, Fut, B>(handler: F) -> (Url, tokio::task::JoinHandle<()>)
    where
        F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Response<B>> + Send + 'static,
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| {
                        let handler = Arc::clone(&handler);
                        async move { Ok::<_, Infallible>(handler(req).await) }
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });
        let url = Url::parse(&format!("http://{addr}/mcp")).unwrap();
        (url, handle)
    }

    fn make_client(url: Url, token: Option<&str>) -> UpstreamClient {
        let cfg = UpstreamConfig {
            url,
            bearer_token: token.map(SecretString::new),
            passthrough_prefixes: vec!["/t/".into()],
            request_timeout_secs: 10,
            expose_events: vec![],
        };
        UpstreamClient::new(&cfg).unwrap()
    }

    struct OpenSseBody(std::collections::VecDeque<Bytes>);

    impl Body for OpenSseBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Infallible>>> {
            match self.0.pop_front() {
                Some(chunk) => std::task::Poll::Ready(Some(Ok(http_body::Frame::data(chunk)))),
                None => std::task::Poll::Pending,
            }
        }
    }

    #[test]
    fn sse_frames_accept_split_bom_and_mixed_line_endings() {
        let raw = "\u{feff}data: first\r\rdata: second\r\ndata: line\n\r\n";
        for split in 0..=raw.len() {
            let mut buf = BytesMut::new();
            let mut at_start = true;
            let mut data = Vec::new();
            for chunk in [&raw.as_bytes()[..split], &raw.as_bytes()[split..]] {
                buf.extend_from_slice(chunk);
                while let Some(frame) = take_sse_frame(&mut buf) {
                    if let Some(value) =
                        extract_sse_data(&frame, std::mem::replace(&mut at_start, false))
                    {
                        data.push(value);
                    }
                }
            }
            assert_eq!(data, ["first", "second\nline"], "split at {split}");
        }
    }

    #[tokio::test]
    async fn handshake_finishes_at_matching_response_on_open_sse() {
        let (url, _srv) = spawn_mock_server(|_req| async {
            Response::builder()
                .header(header::CONTENT_TYPE, "text/event-stream")
                .header("mcp-session-id", "open-session")
                .body(OpenSseBody(
                    [
                        Bytes::from_static(b"\xef"),
                        Bytes::from_static(b"\xbb\xbf: priming\r\rdata:\r\n\r"),
                        Bytes::from_static(b"\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\r\r"),
                        Bytes::from_static(b"id: answer\r\nevent: message\rdata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{}}}\r\r"),
                    ]
                    .into(),
                ))
                .unwrap()
        })
        .await;
        let response = make_client(url, None)
            .forward_handshake(
                &HeaderMap::new(),
                Bytes::from_static(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}"),
                Profile::Chatgpt,
                Some(Duration::from_secs(1)),
            )
            .await
            .unwrap();
        let text = std::str::from_utf8(&response.body).unwrap();
        assert!(text.starts_with("\u{feff}: priming\r\rdata:\r\n\r\n"));
        assert!(text.contains("id: answer\r\nevent: message\r"));
        assert!(text.contains("\"id\":2,\"result\":{}"));
        assert!(text.contains("\"events\":{}"));
        assert_eq!(response.headers["mcp-session-id"], "open-session");
    }

    #[tokio::test]
    async fn forward_handshake_injects_capabilities_into_sse_with_priming_and_preserves_session() {
        let (url, _srv) = spawn_mock_server(|_req| async {
            let sse = concat!(
                ": priming comment\n\n",
                "id: 1\ndata:\n\n",
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{\"tools\":{}}}}\n\n"
            );
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .header("mcp-session-id", "sess-abc-123")
                .body(Full::new(Bytes::from(sse)))
                .unwrap()
        })
        .await;

        let client = make_client(url, Some("up-tok"));
        let mut inbound = HeaderMap::new();
        inbound.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        inbound.insert(
            header::ACCEPT,
            "application/json, text/event-stream".parse().unwrap(),
        );
        let req_body = Bytes::from(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#);

        // ChatGPT profile injects `"events": {}` on legacy initialize.
        let resp = client
            .forward_handshake(&inbound, req_body.clone(), Profile::Chatgpt, None)
            .await
            .unwrap();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.headers.get("mcp-session-id").unwrap(), "sess-abc-123");
        let text = std::str::from_utf8(&resp.body).unwrap();
        assert!(text.starts_with(": priming comment\n\nid: 1\ndata:\n\n"));
        assert!(text.contains(r#""events":{}"#));

        // SEP-3415 profile does NOT inject Events capability on legacy initialize.
        let resp_sep = client
            .forward_handshake(&inbound, req_body, Profile::Sep3415, None)
            .await
            .unwrap();
        let text_sep = std::str::from_utf8(&resp_sep.body).unwrap();
        assert!(!text_sep.contains(r#""events""#));
    }

    #[tokio::test]
    async fn forward_handshake_injects_modern_discover_capabilities_per_profile() {
        let (url, _srv) = spawn_mock_server(|_req| async {
            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "supportedVersions": ["2026-07-28"],
                    "capabilities": {}
                }
            });
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
                .unwrap()
        })
        .await;

        let client = make_client(url, None);
        let inbound = HeaderMap::new();
        let req_body = Bytes::from(r#"{"jsonrpc":"2.0","id":1,"method":"server/discover"}"#);

        let sep = client
            .forward_handshake(&inbound, req_body.clone(), Profile::Sep3415, None)
            .await
            .unwrap();
        let sep_json: Value = serde_json::from_slice(&sep.body).unwrap();
        assert_eq!(
            sep_json["result"]["capabilities"]["extensions"]["io.modelcontextprotocol/events"]["listChanged"],
            false
        );
        assert!(sep_json["result"]["capabilities"].get("events").is_none());

        let gpt = client
            .forward_handshake(&inbound, req_body, Profile::Chatgpt, None)
            .await
            .unwrap();
        let gpt_json: Value = serde_json::from_slice(&gpt.body).unwrap();
        assert_eq!(
            gpt_json["result"]["capabilities"]["extensions"]["io.modelcontextprotocol/events"]["listChanged"],
            false
        );
        assert_eq!(gpt_json["result"]["capabilities"]["events"], json!({}));
    }

    #[tokio::test]
    async fn ping_session_uses_unique_random_id_and_handles_404_and_200() {
        let seen_ids: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_clone = Arc::clone(&seen_ids);

        let (url, _srv) = spawn_mock_server(move |req| {
            let seen_clone = Arc::clone(&seen_clone);
            async move {
                let sid = req
                    .headers()
                    .get("mcp-session-id")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                let val: Value = serde_json::from_slice(&bytes).unwrap();
                let id = val["id"].as_str().unwrap().to_owned();
                seen_clone.lock().unwrap().push(id.clone());

                if sid == "expired" {
                    return Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Full::new(Bytes::new()))
                        .unwrap();
                }
                if sid == "broken" {
                    return Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Full::new(Bytes::new()))
                        .unwrap();
                }
                let sse = format!(
                    ": keepalive\n\ndata: {}\n\n",
                    json!({"jsonrpc": "2.0", "id": id, "result": {}})
                );
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(Full::new(Bytes::from(sse)))
                    .unwrap()
            }
        })
        .await;

        let client = make_client(url, Some("tok"));
        assert!(
            client
                .ping_session("live-1", Some("2025-11-25"))
                .await
                .unwrap()
        );
        assert!(client.ping_session("live-1", None).await.unwrap());
        assert!(!client.ping_session("expired", None).await.unwrap());
        assert!(client.ping_session("broken", None).await.is_err());

        let ids = seen_ids.lock().unwrap();
        assert_eq!(ids.len(), 4);
        for id in ids.iter() {
            assert!(id.starts_with("hookd_ping_"));
            assert_eq!(id.len(), "hookd_ping_".len() + 32);
        }
        assert_ne!(ids[0], ids[1]);
    }

    #[tokio::test]
    async fn list_poll_and_stream_send_modern_headers_and_parse_structured_responses() {
        let (url, _srv) = spawn_mock_server(|req| async move {
            assert_eq!(
                req.headers().get("mcp-protocol-version").unwrap(),
                PROTOCOL_VERSION_MODERN
            );
            let method = req
                .headers()
                .get("mcp-method")
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let mcp_name = req
                .headers()
                .get("mcp-name")
                .and_then(|v| v.to_str().ok())
                .map(ToOwned::to_owned);
            let mcp_param_repo = req
                .headers()
                .get("mcp-param-repo")
                .and_then(|v| v.to_str().ok())
                .map(ToOwned::to_owned);
            let bytes = req.into_body().collect().await.unwrap().to_bytes();
            let val: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                val["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
                PROTOCOL_VERSION_MODERN
            );

            match method.as_str() {
                "events/list" => {
                    let cursor = val["params"].get("cursor").and_then(Value::as_str);
                    let resp_body = if cursor.is_none() {
                        json!({
                            "jsonrpc": "2.0",
                            "id": val["id"],
                            "result": {
                                "events": [{"name": "a.ev", "description": "A", "delivery": ["push"], "inputSchema": {}, "payloadSchema": {}}],
                                "nextCursor": "p2"
                            }
                        })
                    } else {
                        json!({
                            "jsonrpc": "2.0",
                            "id": val["id"],
                            "result": {
                                "events": [{"name": "b.ev", "description": "B", "delivery": ["poll"], "inputSchema": {}, "payloadSchema": {}}]
                            }
                        })
                    };
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from(serde_json::to_vec(&resp_body).unwrap())))
                        .unwrap()
                }
                "events/poll" => {
                    assert_eq!(mcp_name.as_deref(), Some("a.ev"));
                    assert_eq!(mcp_param_repo.as_deref(), Some("org/repo"));
                    let resp_body = json!({
                        "jsonrpc": "2.0",
                        "id": val["id"],
                        "result": {
                            "events": [{"eventId": "e1", "name": "a.ev", "timestamp": "2026-11-25T00:00:00Z", "data": {"ok": true}}],
                            "cursor": "c1",
                            "truncated": false,
                            "hasMore": false,
                            "nextPollMs": 2000
                        }
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from(serde_json::to_vec(&resp_body).unwrap())))
                        .unwrap()
                }
                "events/stream" => {
                    assert_eq!(mcp_name.as_deref(), Some("a.ev"));
                    let sse = concat!(
                        ": comment\n\n",
                        "data:\n\n",
                        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/events/active\",\"params\":{\"cursor\":\"c0\",\"truncated\":false,\"heartbeatMs\":5000}}\n\n",
                        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/events/heartbeat\",\"params\":{\"cursor\":\"c0\"}}\n\n",
                        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/events/event\",\"params\":{\"eventId\":\"e2\",\"name\":\"a.ev\",\"timestamp\":\"2026-11-25T00:00:01Z\",\"data\":{\"x\":1},\"cursor\":\"c2\"}}\n\n",
                        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/events/error\",\"params\":{\"error\":{\"code\":-32000,\"message\":\"transient\"}}}\n\n",
                        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/events/terminated\",\"params\":{\"error\":{\"code\":-32025,\"message\":\"closed\"}}}\n\n"
                    );
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/event-stream")
                        .body(Full::new(Bytes::from(sse)))
                        .unwrap()
                }
                _ => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            }
        })
        .await;

        let client = make_client(url, None);
        let list = client.list_events_all_pages(false).await.unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "a.ev");
        assert_eq!(list[1].name, "b.ev");

        let args = json!({"repo": "org/repo"}).as_object().unwrap().clone();
        let polled = client
            .poll_events("a.ev", Some(&args), None, None, Some(10))
            .await
            .unwrap();
        assert_eq!(polled.events.len(), 1);
        assert_eq!(polled.cursor.as_deref(), Some("c1"));
        assert_eq!(polled.next_poll_ms, 2000);

        let mut stream = client
            .open_event_stream("a.ev", Some(&args), None, None, Some(5000))
            .await
            .unwrap();
        assert!(matches!(
            stream.next_frame().await.unwrap(),
            Some(UpstreamStreamFrame::Active { cursor: Some(c), truncated: false, heartbeat_ms: Some(5000) }) if c == "c0"
        ));
        assert!(matches!(
            stream.next_frame().await.unwrap(),
            Some(UpstreamStreamFrame::Heartbeat { cursor: Some(c) }) if c == "c0"
        ));
        assert!(matches!(
            stream.next_frame().await.unwrap(),
            Some(UpstreamStreamFrame::Event { event_id, cursor: Some(c), .. }) if event_id == "e2" && c == "c2"
        ));
        assert!(matches!(
            stream.next_frame().await.unwrap(),
            Some(UpstreamStreamFrame::Error {
                code: Some(-32000),
                ..
            })
        ));
        assert!(matches!(
            stream.next_frame().await.unwrap(),
            Some(UpstreamStreamFrame::Terminated {
                code: Some(-32025),
                ..
            })
        ));
        assert_eq!(stream.next_frame().await.unwrap(), None);
    }

    #[tokio::test]
    async fn list_events_handles_method_not_found_when_allowed() {
        let (url, _srv) = spawn_mock_server(|_req| async {
            let body = json!({
                "jsonrpc": "2.0",
                "id": "1",
                "error": {"code": -32601, "message": "Method not found"}
            });
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
                .unwrap()
        })
        .await;

        let client = make_client(url, None);
        assert!(client.list_events_all_pages(true).await.unwrap().is_empty());
        assert!(matches!(
            client.list_events_all_pages(false).await,
            Err(UpstreamError::JsonRpc { code: -32601, .. })
        ));
    }

    #[tokio::test]
    async fn forward_raw_passthrough_streams_bytes_without_injecting_auth() {
        let (url, _srv) = spawn_mock_server(|req| async move {
            assert_eq!(req.uri().path_and_query().unwrap().as_str(), "/t/abc?dl=1");
            assert!(req.headers().get(header::AUTHORIZATION).is_none());
            assert!(req.headers().get("x-authorization-ref").is_none());
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Full::new(Bytes::from_static(b"raw-payload-bytes")))
                .unwrap()
        })
        .await;

        let client = make_client(url, Some("secret-upstream-token"));
        let mut inbound = HeaderMap::new();
        inbound.insert(header::AUTHORIZATION, "Bearer inbound-tok".parse().unwrap());
        inbound.insert("x-authorization-ref", "aref_123".parse().unwrap());

        let resp = client
            .forward_raw(
                Method::GET,
                Some("/t/abc?dl=1"),
                &inbound,
                Full::new(Bytes::new()),
                false,
                None,
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"raw-payload-bytes");
    }

    #[tokio::test]
    async fn ping_session_rejects_missing_or_numeric_id_and_notification_only_sse_eof() {
        let (url, _srv) = spawn_mock_server(|req| async move {
            let sid = req
                .headers()
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            match sid.as_str() {
                "missing-id" => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(r#"{"jsonrpc":"2.0","result":{}}"#)))
                    .unwrap(),
                "numeric-id" => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(
                        r#"{"jsonrpc":"2.0","id":123,"result":{}}"#,
                    )))
                    .unwrap(),
                "notif-eof" => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    // Unterminated trailing notification frame without `\n\n` and no response frame.
                    .body(Full::new(Bytes::from(
                        r#"data: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}"#,
                    )))
                    .unwrap(),
                _ => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            }
        })
        .await;

        let client = make_client(url, None);
        assert!(matches!(
            client.ping_session("missing-id", None).await,
            Err(UpstreamError::InvalidResponse(_))
        ));
        assert!(matches!(
            client.ping_session("numeric-id", None).await,
            Err(UpstreamError::InvalidResponse(_))
        ));
        assert!(matches!(
            client.ping_session("notif-eof", None).await,
            Err(UpstreamError::InvalidResponse(_))
        ));
    }
}
