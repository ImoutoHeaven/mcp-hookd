//! End-to-end acceptance tests covering spec §8 items 1-4 over loopback mocks.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use bytes::Bytes;
use http::header::{self, HeaderMap};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use mcp_hookd::config::{
    AuthContextConfig, Config, ExposeEventConfig, IngestConfig, IngestEventConfig, UpstreamConfig,
};
use mcp_hookd::emit::{EmitOptions, OnInvalid, run_emit_with_io};
use mcp_hookd::outbound::{DnsResolver, OutboundClient, SafeHttpsConnector};
use mcp_hookd::schema::build_filter_input_schema;
use mcp_hookd::server::{RunningServer, start_server};
use mcp_hookd::types::{
    PROTOCOL_VERSION_MODERN, Profile, QuotaConfig, SecretString, sign_webhook_v1, unix_now,
};
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::convert::Infallible;
use std::io::Cursor;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::TlsAcceptor;
use url::Url;

type HttpClient = Client<HttpConnector, Full<Bytes>>;

fn http_client() -> HttpClient {
    Client::builder(TokioExecutor::new()).build(HttpConnector::new())
}

fn test_whsec(byte: u8) -> String {
    format!("whsec_{}", BASE64_STD.encode([byte; 32]))
}

fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION_MODERN,
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": { "io.modelcontextprotocol/events": {} }
        }
    })
}

async fn send_http(
    client: &HttpClient,
    method: Method,
    url: &str,
    headers: &[(&str, &str)],
    body: Bytes,
) -> (StatusCode, HeaderMap, Bytes) {
    let mut builder = Request::builder().method(method).uri(url);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Full::new(body)).unwrap();
    let resp = client.request(req).await.unwrap();
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, resp_headers, bytes)
}

async fn mcp_post_modern(
    client: &HttpClient,
    base_url: &str,
    token: &str,
    method: &str,
    id: i64,
    mut params: Value,
    extra_headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Value) {
    if let Some(obj) = params.as_object_mut() {
        obj.entry("_meta").or_insert_with(modern_meta);
    }
    let payload = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params
    });
    let auth = format!("Bearer {token}");
    let mut headers = vec![
        ("authorization", auth.as_str()),
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
        ("mcp-protocol-version", PROTOCOL_VERSION_MODERN),
        ("mcp-method", method),
    ];
    headers.extend_from_slice(extra_headers);
    let (status, resp_headers, bytes) = send_http(
        client,
        Method::POST,
        &format!("{base_url}/mcp"),
        &headers,
        Bytes::from(serde_json::to_vec(&payload).unwrap()),
    )
    .await;
    let val = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, resp_headers, val)
}

#[derive(Clone, Debug)]
struct CapturedCallback {
    headers: HeaderMap,
    body: Bytes,
}

struct MockTlsCallbackServer {
    addr: SocketAddr,
    roots: RootCertStore,
    requests: Arc<AsyncMutex<Vec<CapturedCallback>>>,
    _task: tokio::task::JoinHandle<()>,
}

impl MockTlsCallbackServer {
    async fn start<F>(responder: F) -> Self
    where
        F: Fn(&HeaderMap, &Bytes) -> (StatusCode, Vec<u8>) + Send + Sync + 'static,
    {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der: CertificateDer<'static> = ck.cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

        let mut roots = RootCertStore::empty();
        roots.add(cert_der.clone()).unwrap();

        let server_cfg =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AsyncMutex::new(Vec::new()));
        let reqs_bg = Arc::clone(&requests);
        let responder = Arc::new(responder);

        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let reqs_conn = Arc::clone(&reqs_bg);
                let responder_conn = Arc::clone(&responder);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let io = TokioIo::new(tls);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let reqs_req = Arc::clone(&reqs_conn);
                        let responder_req = Arc::clone(&responder_conn);
                        async move {
                            let headers = req.headers().clone();
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            reqs_req.lock().await.push(CapturedCallback {
                                headers: headers.clone(),
                                body: body.clone(),
                            });
                            let (status, resp_body) = (responder_req)(&headers, &body);
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(status)
                                    .header(header::CONTENT_TYPE, "application/json")
                                    .body(Full::new(Bytes::from(resp_body)))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });

        Self {
            addr,
            roots,
            requests,
            _task: task,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("https://localhost:{}{path}", self.addr.port())
    }

    fn outbound_client(&self) -> OutboundClient {
        let port = self.addr.port();
        let resolver: DnsResolver = Arc::new(move |_host, _port| {
            let target = SocketAddr::from(([127, 0, 0, 1], port));
            Box::pin(async move { Ok(vec![target]) })
        });
        let connector =
            SafeHttpsConnector::with_roots_and_resolver(self.roots.clone(), true, resolver)
                .unwrap();
        OutboundClient::from_connector(connector, true, Duration::from_secs(60))
    }
}

fn standard_challenge_responder(_headers: &HeaderMap, body: &Bytes) -> (StatusCode, Vec<u8>) {
    if let Ok(v) = serde_json::from_slice::<Value>(body)
        && v.get("type").and_then(Value::as_str) == Some("verification")
        && let Some(ch) = v.get("challenge").and_then(Value::as_str)
    {
        return (
            StatusCode::OK,
            serde_json::to_vec(&json!({ "challenge": ch })).unwrap(),
        );
    }
    (StatusCode::OK, br#"{"ok":true}"#.to_vec())
}

async fn spawn_http_mock<F, Fut>(handler: F) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<Full<Bytes>>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
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
    (addr, task)
}

fn ci_ingest_event() -> IngestEventConfig {
    let payload_schema = json!({
        "type": "object",
        "properties": {
            "repo": { "type": "string" },
            "pr": { "type": "integer" }
        },
        "required": ["repo"],
        "additionalProperties": false
    });
    let filter_fields = vec!["repo".to_string(), "pr".to_string()];
    let input_schema = build_filter_input_schema(&payload_schema, &filter_fields).unwrap();
    IngestEventConfig {
        name: "ci.build_failed".to_string(),
        description: "Fired when CI fails.".to_string(),
        filter_fields,
        payload_schema,
        input_schema,
    }
}

fn base_config(
    state_path: PathBuf,
    profile: Profile,
    upstream: Option<UpstreamConfig>,
    ingest: Option<IngestConfig>,
    auth_context: Option<AuthContextConfig>,
) -> Config {
    Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        resource_path: "/mcp".to_string(),
        state_path,
        profile,
        inbound_tokens: vec![SecretString::new("inbound-tok-1")],
        allowed_origins: vec!["https://allowed.example.com".to_string()],
        max_ttl_secs: 3600,
        auth_context,
        upstream,
        ingest,
    }
}

async fn wait_until<F, Fut>(timeout: Duration, mut pred: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if pred().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("condition not met within {timeout:?}");
}

#[tokio::test]
async fn acceptance_1_protocol_facade_passthrough_origin_and_emit_stream() {
    let seen_pings: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_pings_bg = Arc::clone(&seen_pings);

    let (up_addr, _up_task) = spawn_http_mock(move |req| {
        let seen_pings = Arc::clone(&seen_pings_bg);
        async move {
            let path = req.uri().path().to_owned();
            let method = req.method().clone();
            let auth = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(ToOwned::to_owned);

            if path.starts_with("/t/") {
                // Passthrough must never receive upstream bearer_token.
                assert!(auth.is_none(), "passthrough leaked Authorization header");
                let body = req.into_body().collect().await.unwrap().to_bytes();
                return match method {
                    Method::HEAD => Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_LENGTH, "11")
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                    Method::PUT => Response::builder()
                        .status(StatusCode::CREATED)
                        .body(Full::new(body))
                        .unwrap(),
                    _ => Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from_static(b"hello-world")))
                        .unwrap(),
                };
            }

            assert_eq!(auth.as_deref(), Some("Bearer upstream-secret"));
            let body = req.into_body().collect().await.unwrap().to_bytes();
            let msg: Value = serde_json::from_slice(&body).unwrap();
            let rpc_method = msg["method"].as_str().unwrap_or("");
            match rpc_method {
                "initialize" => {
                    let sse = concat!(
                        ": priming comment\n\n",
                        "id: 1\ndata:\n\n",
                        "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{\"tools\":{}}}}\n\n"
                    );
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/event-stream")
                        .header("mcp-session-id", "up-sess-1")
                        .body(Full::new(Bytes::from(sse)))
                        .unwrap()
                }
                "ping" => {
                    let id = msg["id"].as_str().unwrap().to_owned();
                    seen_pings.lock().unwrap().push(id.clone());
                    let resp = json!({"jsonrpc": "2.0", "id": id, "result": {}});
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from(serde_json::to_vec(&resp).unwrap())))
                        .unwrap()
                }
                "tools/call" => {
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    let resp = json!({"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text", "text": "done"}]}});
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from(serde_json::to_vec(&resp).unwrap())))
                        .unwrap()
                }
                "events/list" => {
                    let resp = json!({
                        "jsonrpc": "2.0",
                        "id": msg["id"],
                        "result": {
                            "resultType": "complete",
                            "events": [{
                                "name": "task.exited",
                                "description": "Task exited",
                                "delivery": ["push", "poll"],
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "taskId": { "type": "string" },
                                        "scope": { "type": "string", "x-mcp-header": "scope" }
                                    },
                                    "required": ["scope"]
                                },
                                "payloadSchema": { "type": "object" }
                            }]
                        }
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from(serde_json::to_vec(&resp).unwrap())))
                        .unwrap()
                }
                "events/poll" => {
                    let resp = json!({
                        "jsonrpc": "2.0",
                        "id": msg["id"],
                        "result": {
                            "resultType": "complete",
                            "events": [],
                            "cursor": "c1",
                            "truncated": false,
                            "hasMore": false,
                            "nextPollMs": 2000
                        }
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from(serde_json::to_vec(&resp).unwrap())))
                        .unwrap()
                }
                _ => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            }
        }
    })
    .await;

    let cb = MockTlsCallbackServer::start(standard_challenge_responder).await;
    let dir = TempDir::new().unwrap();
    let cfg = base_config(
        dir.path().join("subscriptions.json"),
        Profile::Chatgpt,
        Some(UpstreamConfig {
            url: Url::parse(&format!("http://{up_addr}/mcp")).unwrap(),
            bearer_token: Some(SecretString::new("upstream-secret")),
            passthrough_prefixes: vec!["/t/".to_string()],
            request_timeout_secs: 10,
            expose_events: vec![ExposeEventConfig {
                name: "task.exited".to_string(),
                disallow_arguments: vec!["scope".to_string()],
            }],
        }),
        Some(IngestConfig {
            tokens: vec![SecretString::new("producer-tok-1")],
            events: vec![ci_ingest_event()],
        }),
        None,
    );
    let quotas = QuotaConfig {
        allow_loopback_callbacks: true,
        ..Default::default()
    };
    let server: RunningServer = start_server(cfg, quotas, Some(cb.outbound_client()))
        .await
        .unwrap();
    let base_url = format!("http://{}", server.local_addr());
    let client = http_client();

    // 1. /healthz GET & HEAD
    let (st, _, body) = send_http(
        &client,
        Method::GET,
        &format!("{base_url}/healthz"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"ok": true})
    );
    let (st, _, body) = send_http(
        &client,
        Method::HEAD,
        &format!("{base_url}/healthz"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.is_empty());

    // 2. Auth + Origin + reverse-proxy Host checks
    let (st, _, _) = send_http(
        &client,
        Method::POST,
        &format!("{base_url}/mcp"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, _, _) = send_http(
        &client,
        Method::POST,
        &format!("{base_url}/mcp"),
        &[
            ("authorization", "Bearer inbound-tok-1"),
            ("origin", "https://evil.example"),
        ],
        Bytes::new(),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // 3. /t/ GET, HEAD, PUT passthrough + %2e%2e traversal blocked + POST 405
    let (st, _, body) = send_http(
        &client,
        Method::GET,
        &format!("{base_url}/t/item1"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(&body[..], b"hello-world");
    let (st, _, _) = send_http(
        &client,
        Method::HEAD,
        &format!("{base_url}/t/item1"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, body) = send_http(
        &client,
        Method::PUT,
        &format!("{base_url}/t/upload"),
        &[],
        Bytes::from_static(b"put-data"),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(&body[..], b"put-data");
    let (st, _, _) = send_http(
        &client,
        Method::POST,
        &format!("{base_url}/t/item1"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
    let (st, _, _) = send_http(
        &client,
        Method::GET,
        &format!("{base_url}/t/%2e%2e/mcp"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // 4. SSE priming initialize proposing 2026-07-28 (downgrade negotiation) + Origin whitelist + reverse-proxy Host
    let init_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": { "protocolVersion": "2026-07-28", "capabilities": {} }
    });
    let (st, hdrs, body) = send_http(
        &client,
        Method::POST,
        &format!("{base_url}/mcp"),
        &[
            ("authorization", "Bearer inbound-tok-1"),
            ("origin", "https://allowed.example.com"),
            ("host", "public-proxy.example.com"),
            ("content-type", "application/json; charset=utf-8"),
            ("accept", "application/json, text/event-stream"),
        ],
        Bytes::from(serde_json::to_vec(&init_body).unwrap()),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get("mcp-session-id").unwrap(), "up-sess-1");
    let sse_text = std::str::from_utf8(&body).unwrap();
    assert!(sse_text.starts_with(": priming comment\n\nid: 1\ndata:\n\n"));
    assert!(sse_text.contains(r#""events":{}"#));

    // 5. Concurrent slow tools/call + legacy events/list triggering random ping keepalive
    let slow_call_body = Bytes::from(
        serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "slow"}})).unwrap(),
    );
    let legacy_list_body = Bytes::from(
        serde_json::to_vec(
            &json!({"jsonrpc": "2.0", "id": 11, "method": "events/list", "params": {}}),
        )
        .unwrap(),
    );
    let legacy_headers = [
        ("authorization", "Bearer inbound-tok-1"),
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
        ("mcp-session-id", "up-sess-1"),
        ("mcp-protocol-version", "2025-11-25"),
    ];
    let mcp_url = format!("{base_url}/mcp");
    let (tool_res, list_res) = tokio::join!(
        send_http(
            &client,
            Method::POST,
            &mcp_url,
            &legacy_headers,
            slow_call_body
        ),
        send_http(
            &client,
            Method::POST,
            &mcp_url,
            &legacy_headers,
            legacy_list_body
        ),
    );
    assert_eq!(tool_res.0, StatusCode::OK);
    assert_eq!(list_res.0, StatusCode::OK);
    let list_json: Value = serde_json::from_slice(&list_res.2).unwrap();
    assert!(list_json["result"].get("resultType").is_none());
    let events = list_json["result"]["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    let task_ev = events.iter().find(|e| e["name"] == "task.exited").unwrap();
    assert_eq!(task_ev["delivery"], json!(["webhook"]));
    assert!(task_ev["inputSchema"]["properties"].get("scope").is_none());
    let pings = seen_pings.lock().unwrap().clone();
    assert_eq!(pings.len(), 1);
    assert!(pings[0].starts_with("hookd_ping_"));

    // 6. Modern 2026-07-28 symmetry + optional Mcp-Name mismatch + disallow_arguments on events/poll
    let (st, _, bad_meta) = send_http(
        &client,
        Method::POST,
        &format!("{base_url}/mcp"),
        &[
            ("authorization", "Bearer inbound-tok-1"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("mcp-protocol-version", PROTOCOL_VERSION_MODERN),
            ("mcp-method", "events/list"),
        ],
        Bytes::from(r#"{"jsonrpc":"2.0","id":2,"method":"events/list","params":{}}"#),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_slice::<Value>(&bad_meta).unwrap()["error"]["code"],
        -32602
    );

    let (st, _, bad_name) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "events/poll",
        3,
        json!({"name": "task.exited"}),
        &[("mcp-name", "wrong.event")],
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(bad_name["error"]["code"], -32020);

    let (st, _, disallowed) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "events/poll",
        4,
        json!({"name": "task.exited", "arguments": {"scope": "all"}}),
        &[],
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(disallowed["error"]["code"], -32602);

    let (st, _, allowed_poll) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "events/poll",
        5,
        json!({"name": "task.exited", "arguments": {"taskId": "t1"}}),
        &[],
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(allowed_poll["result"]["cursor"], "c1");

    // 7. POST /v1/events rejects inbound_tokens, accepts producer token + emit --stream delivers webhook
    let (st, _, _) = send_http(
        &client,
        Method::POST,
        &format!("{base_url}/v1/events"),
        &[("authorization", "Bearer inbound-tok-1")],
        Bytes::from_static(b"{}"),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    let secret = test_whsec(0x11);
    let (st, _, sub_resp) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "events/subscribe",
        6,
        json!({
            "name": "ci.build_failed",
            "arguments": {"repo": "org/app"},
            "delivery": {
                "mode": "webhook",
                "url": cb.url("/hook"),
                "secret": secret
            }
        }),
        &[],
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(sub_resp["result"]["resultType"], "complete");

    let ndjson = "{\"name\":\"ci.build_failed\",\"eventId\":\"emit-1\",\"data\":{\"repo\":\"org/app\",\"pr\":7},\"cursor\":\"ignored\"}\n";
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run_emit_with_io(
        EmitOptions {
            url: format!("{base_url}/v1/events"),
            name: None,
            stream: true,
            on_invalid: OnInvalid::Fail,
            token: Some(SecretString::new("producer-tok-1")),
        },
        Cursor::new(ndjson.as_bytes()),
        &mut stdout,
        &mut stderr,
    )
    .await;
    assert_eq!(exit, std::process::ExitCode::SUCCESS);
    let ack: Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(ack["ok"], true);
    assert_eq!(ack["eventId"], "emit-1");

    wait_until(Duration::from_secs(3), || async {
        cb.requests.lock().await.iter().any(|r| {
            serde_json::from_slice::<Value>(&r.body)
                .ok()
                .and_then(|v| {
                    v.get("eventId")
                        .and_then(Value::as_str)
                        .map(|s| s == "emit-1")
                })
                .unwrap_or(false)
        })
    })
    .await;

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn acceptance_2_delegated_auth_isolation_narrow_scope_revocation_and_startup_reverify() {
    type GrantMap = HashMap<String, (bool, Vec<String>, u64)>;
    let grants: Arc<Mutex<GrantMap>> = Arc::new(Mutex::new(HashMap::new()));
    let exp = unix_now() + 3600;
    {
        let mut g = grants.lock().unwrap();
        g.insert(
            "aref_alice".into(),
            (true, vec!["events:read".into(), "events:write".into()], exp),
        );
        g.insert("aref_bob".into(), (true, vec!["events:read".into()], exp));
    }
    let grants_bg = Arc::clone(&grants);

    let (auth_addr, _auth_task) = spawn_http_mock(move |req| {
        let grants = Arc::clone(&grants_bg);
        async move {
            let body = req.into_body().collect().await.unwrap().to_bytes();
            let val: Value = serde_json::from_slice(&body).unwrap();
            let aref = val["ref"].as_str().unwrap_or("");
            let resp = match grants.lock().unwrap().get(aref) {
                Some((true, scopes, expires_at)) => json!({
                    "active": true,
                    "principal": aref,
                    "resource": "https://mcp.example.com/mcp",
                    "scopes": scopes,
                    "expiresAt": expires_at
                }),
                _ => json!({ "active": false }),
            };
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(serde_json::to_vec(&resp).unwrap())))
                .unwrap()
        }
    })
    .await;

    let (up_addr, _up_task) = spawn_http_mock(|req| async move {
        // Forged X-Authorization-* must be stripped before reaching upstream.
        assert!(req.headers().get("x-authorization-ref").is_none());
        assert!(req.headers().get("x-authorization-scope").is_none());
        let body = req.into_body().collect().await.unwrap().to_bytes();
        let msg: Value = serde_json::from_slice(&body).unwrap();
        let resp = json!({"jsonrpc": "2.0", "id": msg["id"], "result": {"ok": true}});
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(serde_json::to_vec(&resp).unwrap())))
            .unwrap()
    })
    .await;

    let cb = MockTlsCallbackServer::start(standard_challenge_responder).await;
    let dir = TempDir::new().unwrap();
    let state_path = dir.path().join("subscriptions.json");

    let make_cfg = |reverify_secs: u64| {
        base_config(
            state_path.clone(),
            Profile::Sep3415,
            Some(UpstreamConfig {
                url: Url::parse(&format!("http://{up_addr}/mcp")).unwrap(),
                bearer_token: None,
                passthrough_prefixes: vec![],
                request_timeout_secs: 10,
                expose_events: vec![],
            }),
            Some(IngestConfig {
                tokens: vec![SecretString::new("prod-tok")],
                events: vec![ci_ingest_event()],
            }),
            Some(AuthContextConfig {
                check_url: Url::parse(&format!("http://{auth_addr}/authorization/check")).unwrap(),
                check_token: SecretString::new("0123456789abcdef"),
                expected_resource: "https://mcp.example.com/mcp".to_string(),
                reverify_secs,
            }),
        )
    };

    let quotas = QuotaConfig {
        allow_loopback_callbacks: true,
        ..Default::default()
    };
    let server = start_server(make_cfg(1), quotas.clone(), Some(cb.outbound_client()))
        .await
        .unwrap();
    let base_url = format!("http://{}", server.local_addr());
    let client = http_client();

    // 1. Missing X-Authorization-Ref returns HTTP 500
    let (st, _, _) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "events/list",
        1,
        json!({}),
        &[],
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);

    // 2. Upstream tools/call strips X-Authorization-* headers
    let (st, _, _) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "tools/call",
        2,
        json!({"name": "echo"}),
        &[
            ("x-authorization-ref", "aref_alice"),
            ("x-authorization-scope", "events:read"),
        ],
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // 3. Alice and Bob share the same inbound token slot but get isolated subscriptions
    let secret = test_whsec(0x22);
    let sub_params = json!({
        "name": "ci.build_failed",
        "delivery": { "mode": "webhook", "url": cb.url("/hook"), "secret": secret }
    });
    let (st_a, _, res_a) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "events/subscribe",
        3,
        sub_params.clone(),
        &[
            ("x-authorization-ref", "aref_alice"),
            ("x-authorization-scope", "events:read events:write"),
        ],
    )
    .await;
    let (st_b, _, res_b) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "events/subscribe",
        4,
        sub_params.clone(),
        &[
            ("x-authorization-ref", "aref_bob"),
            ("x-authorization-scope", "events:read"),
        ],
    )
    .await;
    assert_eq!(st_a, StatusCode::OK);
    assert_eq!(st_b, StatusCode::OK);
    assert_ne!(res_a["result"]["id"], res_b["result"]["id"]);
    assert_eq!(server.engine().active_subscription_count(), 2);

    // 4. Refreshing Alice with narrowed scope returns HTTP 200 + JSON-RPC Forbidden (-32024)
    let (st_narrow, _, res_narrow) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "events/subscribe",
        5,
        sub_params,
        &[
            ("x-authorization-ref", "aref_alice"),
            ("x-authorization-scope", "events:read"),
        ],
    )
    .await;
    assert_eq!(st_narrow, StatusCode::OK);
    assert_eq!(res_narrow["error"]["code"], -32024);

    // 5. Revoking Bob destroys Bob's subscription within reverify_secs and sends terminated
    grants.lock().unwrap().get_mut("aref_bob").unwrap().0 = false;
    wait_until(Duration::from_secs(7), || async {
        server.engine().active_subscription_count() == 1
    })
    .await;
    wait_until(Duration::from_secs(2), || async {
        cb.requests.lock().await.iter().any(|r| {
            serde_json::from_slice::<Value>(&r.body)
                .ok()
                .and_then(|v| {
                    v.get("type")
                        .and_then(Value::as_str)
                        .map(|s| s == "terminated")
                })
                .unwrap_or(false)
                && r.headers.get("x-mcp-subscription-id").is_some()
        })
    })
    .await;

    server.shutdown().await.unwrap();

    // 6. Revoke Alice while stopped, then restart -> startup reverify gate purges Alice
    grants.lock().unwrap().get_mut("aref_alice").unwrap().0 = false;
    let restarted = start_server(make_cfg(1), quotas, Some(cb.outbound_client()))
        .await
        .unwrap();
    assert_eq!(restarted.engine().active_subscription_count(), 0);
    restarted.shutdown().await.unwrap();
}

#[tokio::test]
async fn acceptance_3_secure_callbacks_verification_redirect_dual_secret_and_410() {
    let event_count = Arc::new(AtomicUsize::new(0));
    let event_count_bg = Arc::clone(&event_count);

    let cb = MockTlsCallbackServer::start(move |headers, body| {
        if headers.get("x-mcp-subscription-id").is_none() {
            return (StatusCode::BAD_REQUEST, b"{}".to_vec());
        }
        if let Ok(v) = serde_json::from_slice::<Value>(body)
            && v.get("type").and_then(Value::as_str) == Some("verification")
            && let Some(ch) = v.get("challenge").and_then(Value::as_str)
        {
            return (
                StatusCode::OK,
                serde_json::to_vec(&json!({ "challenge": ch })).unwrap(),
            );
        }
        // First business event gets 410 Gone (single-message fast drop); subsequent get 200 OK.
        let n = event_count_bg.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            (StatusCode::GONE, b"{}".to_vec())
        } else {
            (StatusCode::OK, br#"{"ok":true}"#.to_vec())
        }
    })
    .await;

    let redir_cb =
        MockTlsCallbackServer::start(|_headers, _body| (StatusCode::FOUND, b"".to_vec())).await;

    let dir = TempDir::new().unwrap();
    let cfg = base_config(
        dir.path().join("subscriptions.json"),
        Profile::Sep3415,
        None,
        Some(IngestConfig {
            tokens: vec![SecretString::new("prod-tok")],
            events: vec![ci_ingest_event()],
        }),
        None,
    );
    let quotas = QuotaConfig {
        allow_loopback_callbacks: true,
        ..Default::default()
    };
    let server = start_server(cfg, quotas, Some(cb.outbound_client()))
        .await
        .unwrap();
    let base_url = format!("http://{}", server.local_addr());
    let client = http_client();

    // 1. Non-https URL and bad whsec_ rejected
    let (_, _, bad_url) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "events/subscribe",
        1,
        json!({
            "name": "ci.build_failed",
            "delivery": { "mode": "webhook", "url": "http://example.com/hook", "secret": test_whsec(1) }
        }),
        &[],
    )
    .await;
    assert_eq!(bad_url["error"]["code"], -32602);

    let (_, _, bad_secret) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "events/subscribe",
        2,
        json!({
            "name": "ci.build_failed",
            "delivery": { "mode": "webhook", "url": cb.url("/hook"), "secret": "whsec_short" }
        }),
        &[],
    )
    .await;
    assert_eq!(bad_secret["error"]["code"], -32602);

    // 2. 302 redirect callback fails verification with CallbackEndpointError (-32027)
    let dir2 = TempDir::new().unwrap();
    let cfg2 = base_config(
        dir2.path().join("s2.json"),
        Profile::Sep3415,
        None,
        Some(IngestConfig {
            tokens: vec![SecretString::new("prod-tok")],
            events: vec![ci_ingest_event()],
        }),
        None,
    );
    let q2 = QuotaConfig {
        allow_loopback_callbacks: true,
        ..Default::default()
    };
    let redir_srv = start_server(cfg2, q2, Some(redir_cb.outbound_client()))
        .await
        .unwrap();
    let (_, _, redir_err) = mcp_post_modern(
        &client,
        &format!("http://{}", redir_srv.local_addr()),
        "inbound-tok-1",
        "events/subscribe",
        3,
        json!({
            "name": "ci.build_failed",
            "delivery": { "mode": "webhook", "url": redir_cb.url("/redir"), "secret": test_whsec(2) }
        }),
        &[],
    )
    .await;
    assert_eq!(redir_err["error"]["code"], -32027);
    redir_srv.shutdown().await.unwrap();

    // 3. Initial subscribe + secret rotation triggers second verification & dual-secret signatures
    let secret1 = test_whsec(0x31);
    let secret2 = test_whsec(0x32);
    let (_, _, sub1) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "events/subscribe",
        4,
        json!({
            "name": "ci.build_failed",
            "delivery": { "mode": "webhook", "url": cb.url("/hook"), "secret": secret1 }
        }),
        &[],
    )
    .await;
    let sub_id = sub1["result"]["id"].as_str().unwrap().to_owned();

    let (_, _, sub2) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "events/subscribe",
        5,
        json!({
            "name": "ci.build_failed",
            "delivery": { "mode": "webhook", "url": cb.url("/hook"), "secret": secret2 }
        }),
        &[],
    )
    .await;
    assert_eq!(sub2["result"]["id"], sub_id);

    // Two distinct verification challenges must have been sent with X-MCP-Subscription-Id.
    let verifications = cb
        .requests
        .lock()
        .await
        .iter()
        .filter(|r| {
            serde_json::from_slice::<Value>(&r.body)
                .ok()
                .and_then(|v| {
                    v.get("type")
                        .and_then(Value::as_str)
                        .map(|s| s == "verification")
                })
                .unwrap_or(false)
        })
        .count();
    assert_eq!(verifications, 2);

    // 4. Send two events: first gets 410 Gone (dropped without suspending), second gets 200 OK with dual signatures
    for eid in ["ev-410", "ev-200"] {
        let (st, _, _) = send_http(
            &client,
            Method::POST,
            &format!("{base_url}/v1/events"),
            &[
                ("authorization", "Bearer prod-tok"),
                ("content-type", "application/json"),
            ],
            Bytes::from(
                serde_json::to_vec(&json!({
                    "name": "ci.build_failed",
                    "eventId": eid,
                    "timestamp": "2026-11-25T00:00:00Z",
                    "data": { "repo": "org/app" }
                }))
                .unwrap(),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
    }

    wait_until(Duration::from_secs(3), || async {
        cb.requests.lock().await.iter().any(|r| {
            serde_json::from_slice::<Value>(&r.body)
                .ok()
                .and_then(|v| {
                    v.get("eventId")
                        .and_then(Value::as_str)
                        .map(|s| s == "ev-200")
                })
                .unwrap_or(false)
        })
    })
    .await;

    let captured = cb
        .requests
        .lock()
        .await
        .iter()
        .find(|r| {
            serde_json::from_slice::<Value>(&r.body)
                .ok()
                .and_then(|v| {
                    v.get("eventId")
                        .and_then(Value::as_str)
                        .map(|s| s == "ev-200")
                })
                .unwrap_or(false)
        })
        .unwrap()
        .clone();
    assert_eq!(
        captured
            .headers
            .get("x-mcp-subscription-id")
            .unwrap()
            .to_str()
            .unwrap(),
        sub_id
    );
    let wh_id = captured
        .headers
        .get("webhook-id")
        .unwrap()
        .to_str()
        .unwrap();
    let wh_ts: u64 = captured
        .headers
        .get("webhook-timestamp")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let sig_hdr = captured
        .headers
        .get("webhook-signature")
        .unwrap()
        .to_str()
        .unwrap();
    let sig1 = sign_webhook_v1(&secret1, wh_id, wh_ts, &captured.body).unwrap();
    let sig2 = sign_webhook_v1(&secret2, wh_id, wh_ts, &captured.body).unwrap();
    assert!(sig_hdr.contains(&sig1));
    assert!(sig_hdr.contains(&sig2));

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn acceptance_4_poll_fallback_slow_consumer_drop_and_budget_isolation() {
    let poll_calls = Arc::new(AtomicUsize::new(0));
    let poll_calls_bg = Arc::clone(&poll_calls);

    let (up_addr, _up_task) = spawn_http_mock(move |req| {
        let poll_calls = Arc::clone(&poll_calls_bg);
        async move {
            let body = req.into_body().collect().await.unwrap().to_bytes();
            let msg: Value = serde_json::from_slice(&body).unwrap();
            match msg["method"].as_str().unwrap_or("") {
                "events/list" => {
                    let resp = json!({
                        "jsonrpc": "2.0",
                        "id": msg["id"],
                        "result": {
                            "resultType": "complete",
                            "events": [{
                                "name": "task.exited",
                                "description": "Task exited",
                                "delivery": ["push", "poll"],
                                "inputSchema": {
                                    "type": "object",
                                    "properties": { "tag": { "type": "string" } }
                                },
                                "payloadSchema": { "type": "object" }
                            }]
                        }
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from(serde_json::to_vec(&resp).unwrap())))
                        .unwrap()
                }
                "events/stream" => {
                    // Hold stream open with active notice.
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    let sse = "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/events/active\",\"params\":{\"cursor\":\"c0\",\"truncated\":false,\"heartbeatMs\":5000}}\n\n";
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/event-stream")
                        .body(Full::new(Bytes::from(sse)))
                        .unwrap()
                }
                "events/poll" => {
                    poll_calls.fetch_add(1, Ordering::SeqCst);
                    let resp = json!({
                        "jsonrpc": "2.0",
                        "id": msg["id"],
                        "result": {
                            "resultType": "complete",
                            "events": [],
                            "cursor": "c0",
                            "truncated": false,
                            "hasMore": false,
                            "nextPollMs": 100
                        }
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from(serde_json::to_vec(&resp).unwrap())))
                        .unwrap()
                }
                "tools/call" => {
                    let resp = json!({"jsonrpc": "2.0", "id": msg["id"], "result": {"ok": true}});
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from(serde_json::to_vec(&resp).unwrap())))
                        .unwrap()
                }
                _ => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            }
        }
    })
    .await;

    // Callback server: `/slow` stalls on business events (via 503 retry), `/fast` returns 200 immediately.
    let cb = MockTlsCallbackServer::start(|_headers, body| {
        if let Ok(v) = serde_json::from_slice::<Value>(body)
            && v.get("type").and_then(Value::as_str) == Some("verification")
            && let Some(ch) = v.get("challenge").and_then(Value::as_str)
        {
            return (
                StatusCode::OK,
                serde_json::to_vec(&json!({ "challenge": ch })).unwrap(),
            );
        }
        (StatusCode::OK, br#"{"ok":true}"#.to_vec())
    })
    .await;

    let dir = TempDir::new().unwrap();
    let cfg = base_config(
        dir.path().join("subscriptions.json"),
        Profile::Sep3415,
        Some(UpstreamConfig {
            url: Url::parse(&format!("http://{up_addr}/mcp")).unwrap(),
            bearer_token: None,
            passthrough_prefixes: vec![],
            request_timeout_secs: 10,
            expose_events: vec![ExposeEventConfig {
                name: "task.exited".to_string(),
                disallow_arguments: vec![],
            }],
        }),
        Some(IngestConfig {
            tokens: vec![SecretString::new("prod-tok")],
            events: vec![ci_ingest_event()],
        }),
        None,
    );

    let quotas = QuotaConfig {
        allow_loopback_callbacks: true,
        max_upstream_streams: 1,
        max_outbox_per_sub: 2,
        ..Default::default()
    };
    let server = start_server(cfg, quotas, Some(cb.outbound_client()))
        .await
        .unwrap();
    let base_url = format!("http://{}", server.local_addr());
    let client = http_client();

    // 1. Register 2 upstream bridged subscriptions with max_upstream_streams=1 -> 2nd falls back to poll
    for tag in ["s1", "s2"] {
        let (st, _, _) = mcp_post_modern(
            &client,
            &base_url,
            "inbound-tok-1",
            "events/subscribe",
            1,
            json!({
                "name": "task.exited",
                "arguments": { "tag": tag },
                "delivery": { "mode": "webhook", "url": cb.url("/hook"), "secret": test_whsec(0x41) }
            }),
            &[],
        )
        .await;
        assert_eq!(st, StatusCode::OK);
    }
    wait_until(Duration::from_secs(3), || async {
        poll_calls.load(Ordering::SeqCst) >= 1
    })
    .await;

    // 2. Exhaust OUTBOX_BYTE_BUDGET directly and verify tools/call & events/unsubscribe still succeed
    let sub_url = cb.url("/ingest");
    let (st, _, _) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "events/subscribe",
        2,
        json!({
            "name": "ci.build_failed",
            "delivery": { "mode": "webhook", "url": sub_url, "secret": test_whsec(0x42) }
        }),
        &[],
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Acquire entire outbox byte budget to simulate severe outbox pressure.
    let outbox_limit = server.engine().pools().outbox.limit();
    let _full_outbox = server
        .engine()
        .pools()
        .outbox
        .try_acquire(outbox_limit)
        .unwrap();

    // Ingest returns 503 when outbox budget is exhausted.
    let (st_ingest, _, _) = send_http(
        &client,
        Method::POST,
        &format!("{base_url}/v1/events"),
        &[
            ("authorization", "Bearer prod-tok"),
            ("content-type", "application/json"),
        ],
        Bytes::from(
            serde_json::to_vec(&json!({
                "name": "ci.build_failed",
                "eventId": "budget-full-1",
                "timestamp": "2026-11-25T00:00:00Z",
                "data": { "repo": "org/app" }
            }))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(st_ingest, StatusCode::SERVICE_UNAVAILABLE);

    // Meanwhile tools/call and events/unsubscribe still succeed!
    let (st_tool, _, tool_val) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "tools/call",
        3,
        json!({ "name": "ping_tool" }),
        &[],
    )
    .await;
    assert_eq!(st_tool, StatusCode::OK);
    assert_eq!(tool_val["result"]["ok"], true);

    let (st_unsub, _, unsub_val) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "events/unsubscribe",
        4,
        json!({
            "name": "ci.build_failed",
            "delivery": { "mode": "webhook", "url": sub_url }
        }),
        &[],
    )
    .await;
    assert_eq!(st_unsub, StatusCode::OK);
    assert_eq!(unsub_val["result"]["resultType"], "complete");

    drop(_full_outbox);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn acceptance_5_burst_dropped_slow_without_suspending_or_blocking_healthy_sub() {
    let cb = MockTlsCallbackServer::start(|_headers, body| {
        if let Ok(v) = serde_json::from_slice::<Value>(body)
            && v.get("type").and_then(Value::as_str) == Some("verification")
            && let Some(ch) = v.get("challenge").and_then(Value::as_str)
        {
            return (
                StatusCode::OK,
                serde_json::to_vec(&json!({ "challenge": ch })).unwrap(),
            );
        }
        // Return 500 for `/slow` so its single in-flight retry backs off and its outbox fills up;
        // `/fast` returns 200 immediately (distinguished by subscription ID or event routing below).
        (StatusCode::OK, br#"{"ok":true}"#.to_vec())
    })
    .await;

    let slow_cb = MockTlsCallbackServer::start(|_headers, body| {
        if let Ok(v) = serde_json::from_slice::<Value>(body)
            && v.get("type").and_then(Value::as_str) == Some("verification")
            && let Some(ch) = v.get("challenge").and_then(Value::as_str)
        {
            return (
                StatusCode::OK,
                serde_json::to_vec(&json!({ "challenge": ch })).unwrap(),
            );
        }
        (StatusCode::SERVICE_UNAVAILABLE, b"{}".to_vec())
    })
    .await;

    // Combine both TLS root certs and route `slow.localhost` -> slow_cb, `fast.localhost` -> cb.
    let mut roots = RootCertStore::empty();
    for cert in cb.roots.roots.clone() {
        roots.roots.push(cert);
    }
    for cert in slow_cb.roots.roots.clone() {
        roots.roots.push(cert);
    }
    let fast_port = cb.addr.port();
    let slow_port = slow_cb.addr.port();
    let resolver: DnsResolver = Arc::new(move |_host, port| {
        let target = SocketAddr::from(([127, 0, 0, 1], port));
        Box::pin(async move { Ok(vec![target]) })
    });
    let connector = SafeHttpsConnector::with_roots_and_resolver(roots, true, resolver).unwrap();
    let outbound = OutboundClient::from_connector(connector, true, Duration::from_secs(60));

    let dir = TempDir::new().unwrap();
    let cfg = base_config(
        dir.path().join("subscriptions.json"),
        Profile::Sep3415,
        None,
        Some(IngestConfig {
            tokens: vec![SecretString::new("prod-tok")],
            events: vec![ci_ingest_event()],
        }),
        None,
    );
    let quotas = QuotaConfig {
        allow_loopback_callbacks: true,
        max_outbox_per_sub: 2,
        retry_base_ms: 500,
        ..Default::default()
    };
    let server = start_server(cfg, quotas, Some(outbound)).await.unwrap();
    let base_url = format!("http://{}", server.local_addr());
    let client = http_client();

    let fast_url = format!("https://localhost:{fast_port}/fast");
    let slow_url = format!("https://localhost:{slow_port}/slow");

    for (id, url) in [(1, &fast_url), (2, &slow_url)] {
        let (st, _, _) = mcp_post_modern(
            &client,
            &base_url,
            "inbound-tok-1",
            "events/subscribe",
            id,
            json!({
                "name": "ci.build_failed",
                "delivery": { "mode": "webhook", "url": url, "secret": test_whsec(0x55) }
            }),
            &[],
        )
        .await;
        assert_eq!(st, StatusCode::OK);
    }

    // Burst 6 events (> max_outbox_per_sub=2): slow subscriber drops excess without suspending,
    // while healthy fast subscriber receives all 6 events.
    let mut total_dropped_slow = 0u64;
    for i in 0..6 {
        let (st, _, body) = send_http(
            &client,
            Method::POST,
            &format!("{base_url}/v1/events"),
            &[
                ("authorization", "Bearer prod-tok"),
                ("content-type", "application/json"),
            ],
            Bytes::from(
                serde_json::to_vec(&json!({
                    "name": "ci.build_failed",
                    "eventId": format!("burst-{i}"),
                    "timestamp": "2026-11-25T00:00:00Z",
                    "data": { "repo": "org/app" }
                }))
                .unwrap(),
            ),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let val: Value = serde_json::from_slice(&body).unwrap();
        total_dropped_slow += val["droppedSlow"].as_u64().unwrap_or(0);
    }
    assert!(
        total_dropped_slow > 0,
        "expected slow subscriber to tail-drop excess burst events"
    );

    wait_until(Duration::from_secs(3), || async {
        cb.requests
            .lock()
            .await
            .iter()
            .filter(|r| {
                serde_json::from_slice::<Value>(&r.body)
                    .ok()
                    .and_then(|v| {
                        v.get("eventId")
                            .and_then(Value::as_str)
                            .map(|s| s.starts_with("burst-"))
                    })
                    .unwrap_or(false)
            })
            .count()
            == 6
    })
    .await;

    // Refreshing the slow subscription confirms it remained active (not suspended).
    let (st, _, refresh) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "events/subscribe",
        3,
        json!({
            "name": "ci.build_failed",
            "delivery": { "mode": "webhook", "url": slow_url, "secret": test_whsec(0x55) }
        }),
        &[],
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(refresh["result"]["deliveryStatus"]["active"], true);

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn acceptance_6_no_upstream_discover_wire_shape_session_guards_and_root_404() {
    let dir = TempDir::new().unwrap();
    let cfg = base_config(
        dir.path().join("subscriptions.json"),
        Profile::Chatgpt,
        None,
        Some(IngestConfig {
            tokens: vec![SecretString::new("prod-tok")],
            events: vec![ci_ingest_event()],
        }),
        None,
    );
    let server = start_server(cfg, QuotaConfig::default(), None)
        .await
        .unwrap();
    let base_url = format!("http://{}", server.local_addr());
    let client = http_client();

    // 1. No-upstream `server/discover` aligns with rmcp 3.9.0 wire shape.
    let (st, _, disc) = mcp_post_modern(
        &client,
        &base_url,
        "inbound-tok-1",
        "server/discover",
        1,
        json!({}),
        &[],
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(disc["result"]["resultType"], "complete");
    assert_eq!(disc["result"]["ttlMs"], 60_000);
    assert_eq!(disc["result"]["cacheScope"], "public");
    assert!(disc["result"].get("serverInfo").is_none());
    assert_eq!(
        disc["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "mcp-hookd"
    );
    assert_eq!(
        disc["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["version"],
        env!("CARGO_PKG_VERSION")
    );

    // 2. Initialize issues a legacy session; repeating initialize or calling server/discover on it returns 400 + -32600.
    let init_payload = Bytes::from(
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": { "protocolVersion": "2025-11-25", "capabilities": {} }
        }))
        .unwrap(),
    );
    let (st_init, hdrs_init, _) = send_http(
        &client,
        Method::POST,
        &format!("{base_url}/mcp"),
        &[
            ("authorization", "Bearer inbound-tok-1"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
        ],
        init_payload.clone(),
    )
    .await;
    assert_eq!(st_init, StatusCode::OK);
    let sid = hdrs_init
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    let (st_dup_init, _, dup_init_body) = send_http(
        &client,
        Method::POST,
        &format!("{base_url}/mcp"),
        &[
            ("authorization", "Bearer inbound-tok-1"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("mcp-session-id", &sid),
            ("mcp-protocol-version", "2025-11-25"),
        ],
        init_payload,
    )
    .await;
    assert_eq!(st_dup_init, StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_slice::<Value>(&dup_init_body).unwrap()["error"]["code"],
        -32600
    );

    let (st_sess_disc, _, sess_disc_body) = send_http(
        &client,
        Method::POST,
        &format!("{base_url}/mcp"),
        &[
            ("authorization", "Bearer inbound-tok-1"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("mcp-session-id", &sid),
            ("mcp-protocol-version", "2025-11-25"),
        ],
        Bytes::from(r#"{"jsonrpc":"2.0","id":3,"method":"server/discover","params":{}}"#),
    )
    .await;
    assert_eq!(st_sess_disc, StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_slice::<Value>(&sess_disc_body).unwrap()["error"]["code"],
        -32600
    );

    // 3. Duplicate Content-Type header returns 415; root path `/` returns 404.
    let (st_dup_ct, _, _) = send_http(
        &client,
        Method::POST,
        &format!("{base_url}/mcp"),
        &[
            ("authorization", "Bearer inbound-tok-1"),
            ("content-type", "application/json"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
        ],
        Bytes::from(r#"{"jsonrpc":"2.0","id":4,"method":"ping"}"#),
    )
    .await;
    assert_eq!(st_dup_ct, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let (st_root, _, _) = send_http(
        &client,
        Method::GET,
        &format!("{base_url}/"),
        &[],
        Bytes::new(),
    )
    .await;
    assert_eq!(st_root, StatusCode::NOT_FOUND);

    server.shutdown().await.unwrap();

    // 4. With auth_context enabled, no-upstream `server/discover` reports `cacheScope: "private"`.
    let dir2 = TempDir::new().unwrap();
    let cfg_priv = base_config(
        dir2.path().join("subscriptions.json"),
        Profile::Sep3415,
        None,
        Some(IngestConfig {
            tokens: vec![SecretString::new("prod-tok")],
            events: vec![ci_ingest_event()],
        }),
        Some(AuthContextConfig {
            check_url: Url::parse("http://127.0.0.1:1/authorization/check").unwrap(),
            check_token: SecretString::new("0123456789abcdef"),
            expected_resource: "https://mcp.example.com/mcp".to_string(),
            reverify_secs: 15,
        }),
    );
    let srv_priv = start_server(cfg_priv, QuotaConfig::default(), None)
        .await
        .unwrap();
    let (st_priv, _, disc_priv) = mcp_post_modern(
        &client,
        &format!("http://{}", srv_priv.local_addr()),
        "inbound-tok-1",
        "server/discover",
        5,
        json!({}),
        &[
            ("x-authorization-ref", "aref_1"),
            ("x-authorization-scope", "events:read"),
        ],
    )
    .await;
    assert_eq!(st_priv, StatusCode::OK);
    assert_eq!(disc_priv["result"]["cacheScope"], "private");
    srv_priv.shutdown().await.unwrap();
}

#[tokio::test]
async fn passthrough_response_obeys_proxy_byte_budget() {
    let (up_addr, _up_task) = spawn_http_mock(|_req| async {
        Response::new(Full::new(Bytes::from_static(
            b"this response exceeds the small test budget",
        )))
    })
    .await;
    let dir = TempDir::new().unwrap();
    let cfg = base_config(
        dir.path().join("subscriptions.json"),
        Profile::Sep3415,
        Some(UpstreamConfig {
            url: Url::parse(&format!("http://{up_addr}/mcp")).unwrap(),
            bearer_token: None,
            passthrough_prefixes: vec!["/t/".into()],
            request_timeout_secs: 10,
            expose_events: vec![],
        }),
        None,
        None,
    );
    let server = start_server(
        cfg,
        QuotaConfig {
            proxy_byte_budget: 16,
            ..Default::default()
        },
        None,
    )
    .await
    .unwrap();
    let req = Request::builder()
        .uri(format!("http://{}/t/file", server.local_addr()))
        .body(Full::new(Bytes::new()))
        .unwrap();
    if let Ok(response) = http_client().request(req).await {
        assert!(response.into_body().collect().await.is_err());
    }
    assert_eq!(server.engine().pools().proxy.used(), 0);
    server.shutdown().await.unwrap();
}
