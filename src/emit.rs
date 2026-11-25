//! `mcp-hookd emit` CLI implementation (spec §6.5).

use crate::types::{SecretString, normalize_emit_event_id, random_hex, utc_rfc3339_now};
use bytes::Bytes;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderValue, Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::ExitCode;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use url::Url;

pub const DEFAULT_INGEST_URL: &str = "http://127.0.0.1:8081/v1/events";
pub const MAX_EMIT_INPUT_BYTES: usize = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum OnInvalid {
    Fail,
    Drop,
}

#[derive(Clone, Debug)]
pub struct EmitOptions {
    pub url: String,
    pub name: Option<String>,
    pub stream: bool,
    pub on_invalid: OnInvalid,
    pub token: Option<SecretString>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OutgoingEvent {
    event_id: String,
    name: String,
    timestamp: String,
    data: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IngestOkBody {
    #[serde(default)]
    event_id: Option<String>,
    #[serde(default)]
    deduplicated: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StreamAck<'a> {
    ok: bool,
    event_id: &'a str,
    deduplicated: bool,
}

#[derive(Debug, Serialize)]
struct StreamDropped {
    ok: bool,
    dropped: bool,
}

#[derive(Debug, Serialize)]
struct StreamFail<'a> {
    ok: bool,
    error: &'a str,
}

enum SendOutcome {
    Ok {
        event_id: String,
        deduplicated: bool,
    },
    InvalidPayload(String),
    Fatal(String),
}

enum EmitClient {
    Http(Client<HttpConnector, Full<Bytes>>),
    Https(Client<HttpsConnector<HttpConnector>, Full<Bytes>>),
}

impl EmitClient {
    fn request(&self, req: Request<Full<Bytes>>) -> hyper_util::client::legacy::ResponseFuture {
        match self {
            Self::Http(c) => c.request(req),
            Self::Https(c) => c.request(req),
        }
    }
}

enum BoundedLine {
    Eof,
    Line(Vec<u8>),
    TooLong,
}

/// Run `mcp-hookd emit` using process stdio and `HOOKD_PRODUCER_TOKEN` when `options.token` is unset.
pub async fn run_emit(mut options: EmitOptions) -> ExitCode {
    if options.token.is_none()
        && let Ok(val) = std::env::var("HOOKD_PRODUCER_TOKEN")
    {
        options.token = Some(SecretString::new(val));
    }
    let stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let stdout = tokio::io::stdout();
    let stderr = tokio::io::stderr();
    run_emit_with_io(options, stdin, stdout, stderr).await
}

/// Run `mcp-hookd emit` with injected async streams for testing.
pub async fn run_emit_with_io<R, W, E>(
    options: EmitOptions,
    mut reader: R,
    mut stdout: W,
    mut stderr: E,
) -> ExitCode
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let Some(token) = options.token.as_ref().filter(|t| !t.is_empty()) else {
        let _ = write_err(
            &mut stderr,
            "mcp-hookd emit: HOOKD_PRODUCER_TOKEN is missing or empty",
        )
        .await;
        return ExitCode::FAILURE;
    };

    let auth_header = match HeaderValue::from_str(&format!("Bearer {}", token.expose())) {
        Ok(h) => h,
        Err(_) => {
            let _ = write_err(
                &mut stderr,
                "mcp-hookd emit: HOOKD_PRODUCER_TOKEN contains invalid HTTP header characters",
            )
            .await;
            return ExitCode::FAILURE;
        }
    };

    if let Some(ref name) = options.name
        && name.is_empty()
    {
        let _ = write_err(&mut stderr, "mcp-hookd emit: --name cannot be empty").await;
        return ExitCode::FAILURE;
    }

    let (uri, is_https) = match parse_ingest_uri(&options.url) {
        Ok(u) => u,
        Err(msg) => {
            let _ = write_err(&mut stderr, &format!("mcp-hookd emit: {msg}")).await;
            return ExitCode::FAILURE;
        }
    };

    let client = match build_http_client(is_https) {
        Ok(c) => c,
        Err(msg) => {
            let _ = write_err(&mut stderr, &format!("mcp-hookd emit: {msg}")).await;
            return ExitCode::FAILURE;
        }
    };

    if options.stream {
        run_stream_mode(
            &client,
            &uri,
            &auth_header,
            &options,
            &mut reader,
            &mut stdout,
            &mut stderr,
        )
        .await
    } else {
        run_single_mode(
            &client,
            &uri,
            &auth_header,
            &options,
            &mut reader,
            &mut stderr,
        )
        .await
    }
}

async fn run_single_mode<R, E>(
    client: &EmitClient,
    uri: &Uri,
    auth_header: &HeaderValue,
    options: &EmitOptions,
    reader: &mut R,
    stderr: &mut E,
) -> ExitCode
where
    R: AsyncBufRead + Unpin,
    E: AsyncWrite + Unpin,
{
    let mut raw_bytes = Vec::new();
    if let Err(err) = reader
        .take((MAX_EMIT_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut raw_bytes)
        .await
    {
        let _ = write_err(
            stderr,
            &format!("mcp-hookd emit: failed to read stdin: {err}"),
        )
        .await;
        return ExitCode::FAILURE;
    }

    if raw_bytes.len() > MAX_EMIT_INPUT_BYTES {
        let _ = write_err(
            stderr,
            &format!("mcp-hookd emit: input exceeds {MAX_EMIT_INPUT_BYTES} byte limit"),
        )
        .await;
        return if options.on_invalid == OnInvalid::Drop {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    let raw = match String::from_utf8(raw_bytes) {
        Ok(s) => s,
        Err(err) => {
            let _ = write_err(
                stderr,
                &format!("mcp-hookd emit: input is not valid UTF-8: {err}"),
            )
            .await;
            return if options.on_invalid == OnInvalid::Drop {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
    };

    let event = match build_outgoing_event(&raw, options.name.as_deref()) {
        Ok(ev) => ev,
        Err(msg) => {
            let _ = write_err(stderr, &format!("mcp-hookd emit: {msg}")).await;
            return if options.on_invalid == OnInvalid::Drop {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
    };

    match send_event(client, uri, auth_header, &event).await {
        SendOutcome::Ok { .. } => ExitCode::SUCCESS,
        SendOutcome::InvalidPayload(msg) => {
            let _ = write_err(stderr, &format!("mcp-hookd emit: {msg}")).await;
            if options.on_invalid == OnInvalid::Drop {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        SendOutcome::Fatal(msg) => {
            let _ = write_err(stderr, &format!("mcp-hookd emit: {msg}")).await;
            ExitCode::FAILURE
        }
    }
}

async fn run_stream_mode<R, W, E>(
    client: &EmitClient,
    uri: &Uri,
    auth_header: &HeaderValue,
    options: &EmitOptions,
    reader: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> ExitCode
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    loop {
        let line_bytes = match read_bounded_line(reader, MAX_EMIT_INPUT_BYTES).await {
            Ok(BoundedLine::Eof) => return ExitCode::SUCCESS,
            Ok(BoundedLine::TooLong) => {
                let msg = format!("input line exceeds {MAX_EMIT_INPUT_BYTES} byte limit");
                if handle_stream_invalid(options.on_invalid, &msg, stdout, stderr)
                    .await
                    .is_err()
                {
                    return ExitCode::FAILURE;
                }
                continue;
            }
            Ok(BoundedLine::Line(bytes)) => bytes,
            Err(err) => {
                let _ = write_err(
                    stderr,
                    &format!("mcp-hookd emit: failed to read stdin: {err}"),
                )
                .await;
                return ExitCode::FAILURE;
            }
        };

        let line = match String::from_utf8(line_bytes) {
            Ok(s) => s,
            Err(err) => {
                let msg = format!("input line is not valid UTF-8: {err}");
                if handle_stream_invalid(options.on_invalid, &msg, stdout, stderr)
                    .await
                    .is_err()
                {
                    return ExitCode::FAILURE;
                }
                continue;
            }
        };

        let trimmed = line.trim_end_matches('\r');
        if trimmed.trim().is_empty() {
            continue;
        }

        let event = match build_outgoing_event(trimmed, options.name.as_deref()) {
            Ok(ev) => ev,
            Err(msg) => {
                if handle_stream_invalid(options.on_invalid, &msg, stdout, stderr)
                    .await
                    .is_err()
                {
                    return ExitCode::FAILURE;
                }
                continue;
            }
        };

        match send_event(client, uri, auth_header, &event).await {
            SendOutcome::Ok {
                event_id,
                deduplicated,
            } => {
                let ack = StreamAck {
                    ok: true,
                    event_id: &event_id,
                    deduplicated,
                };
                if write_json_line(stdout, &ack).await.is_err() {
                    let _ = write_err(stderr, "mcp-hookd emit: failed to write stdout").await;
                    return ExitCode::FAILURE;
                }
            }
            SendOutcome::InvalidPayload(msg) => {
                if handle_stream_invalid(options.on_invalid, &msg, stdout, stderr)
                    .await
                    .is_err()
                {
                    return ExitCode::FAILURE;
                }
            }
            SendOutcome::Fatal(msg) => {
                // Never emit ok:true on auth/rate-limit/server/network errors so upstream keeps its cursor.
                let _ = write_err(stderr, &format!("mcp-hookd emit: {msg}")).await;
                return ExitCode::FAILURE;
            }
        }
    }
}

/// Read up to `limit` bytes until `\n` or EOF; if a line exceeds `limit`, discard the rest of it.
async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> std::io::Result<BoundedLine> {
    let mut out = Vec::new();
    let mut oversized = false;
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            return if oversized {
                Ok(BoundedLine::TooLong)
            } else if out.is_empty() {
                Ok(BoundedLine::Eof)
            } else {
                Ok(BoundedLine::Line(out))
            };
        }

        if let Some(nl_pos) = buf.iter().position(|&b| b == b'\n') {
            if !oversized {
                if out.len().saturating_add(nl_pos) > limit {
                    oversized = true;
                    out.clear();
                } else {
                    out.extend_from_slice(&buf[..nl_pos]);
                }
            }
            reader.consume(nl_pos + 1);
            return Ok(if oversized {
                BoundedLine::TooLong
            } else {
                BoundedLine::Line(out)
            });
        }

        let len = buf.len();
        if !oversized {
            if out.len().saturating_add(len) > limit {
                oversized = true;
                out.clear();
            } else {
                out.extend_from_slice(buf);
            }
        }
        reader.consume(len);
    }
}

async fn handle_stream_invalid<W, E>(
    on_invalid: OnInvalid,
    msg: &str,
    stdout: &mut W,
    stderr: &mut E,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    match on_invalid {
        OnInvalid::Fail => {
            let resp = StreamFail {
                ok: false,
                error: msg,
            };
            write_json_line(stdout, &resp).await
        }
        OnInvalid::Drop => {
            let _ = write_err(
                stderr,
                &format!("mcp-hookd emit: dropping invalid event: {msg}"),
            )
            .await;
            let resp = StreamDropped {
                ok: true,
                dropped: true,
            };
            write_json_line(stdout, &resp).await
        }
    }
}

fn parse_ingest_uri(raw: &str) -> Result<(Uri, bool), String> {
    let parsed = Url::parse(raw).map_err(|e| format!("invalid --url '{raw}': {e}"))?;
    let is_https = match parsed.scheme() {
        "http" if parsed.has_host() => false,
        "https" if parsed.has_host() => true,
        _ => return Err(format!("--url must be an http:// or https:// URL: '{raw}'")),
    };
    let uri = parsed
        .as_str()
        .parse::<Uri>()
        .map_err(|e| format!("invalid --url URI '{raw}': {e}"))?;
    Ok((uri, is_https))
}

fn build_http_client(is_https: bool) -> Result<EmitClient, String> {
    if !is_https {
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(POOL_IDLE_TIMEOUT)
            .build_http();
        return Ok(EmitClient::Http(client));
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|e| format!("failed to load native TLS roots: {e}"))?
        .https_only()
        .enable_http1()
        .build();
    Ok(EmitClient::Https(
        Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(POOL_IDLE_TIMEOUT)
            .build(https),
    ))
}

fn build_outgoing_event(raw: &str, name_override: Option<&str>) -> Result<OutgoingEvent, String> {
    let value: Value = serde_json::from_str(raw).map_err(|e| format!("invalid JSON: {e}"))?;
    let Value::Object(mut map) = value else {
        return Err("event input must be a JSON object".into());
    };

    let name = match name_override {
        Some(n) => n.to_owned(),
        None => map
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "missing or invalid 'name' field".to_string())?
            .to_owned(),
    };

    let event_id = match map.get("eventId") {
        None | Some(Value::Null) => format!("evt_{}", random_hex(16)?),
        Some(Value::String(raw_id)) if !raw_id.is_empty() => normalize_emit_event_id(&name, raw_id),
        Some(Value::String(_)) => return Err("'eventId' field cannot be empty".into()),
        Some(_) => return Err("'eventId' field must be a string".into()),
    };

    let timestamp = match map.get("timestamp") {
        None | Some(Value::Null) => utc_rfc3339_now(),
        Some(Value::String(ts)) if !ts.is_empty() => ts.clone(),
        Some(_) => return Err("'timestamp' field must be a non-empty string".into()),
    };

    let Some(data) = map.remove("data") else {
        return Err("missing required 'data' field".into());
    };

    // Extra top-level fields (cursor, truncated, _meta, etc.) are intentionally dropped here.
    Ok(OutgoingEvent {
        event_id,
        name,
        timestamp,
        data,
    })
}

async fn send_event(
    client: &EmitClient,
    uri: &Uri,
    auth_header: &HeaderValue,
    event: &OutgoingEvent,
) -> SendOutcome {
    let payload = match serde_json::to_vec(event) {
        Ok(b) => b,
        Err(e) => return SendOutcome::InvalidPayload(format!("failed to serialize event: {e}")),
    };

    let req = match Request::builder()
        .method(Method::POST)
        .uri(uri.clone())
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .header(AUTHORIZATION, auth_header.clone())
        .body(Full::new(Bytes::from(payload)))
    {
        Ok(r) => r,
        Err(e) => return SendOutcome::Fatal(format!("failed to build HTTP request: {e}")),
    };

    let resp = match tokio::time::timeout(REQUEST_TIMEOUT, client.request(req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return SendOutcome::Fatal(format!("HTTP request failed: {e}")),
        Err(_) => return SendOutcome::Fatal("HTTP request timed out".into()),
    };

    let status = resp.status();
    let body_bytes = match tokio::time::timeout(
        REQUEST_TIMEOUT,
        Limited::new(resp.into_body(), MAX_RESPONSE_BODY_BYTES).collect(),
    )
    .await
    {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(e)) => {
            return SendOutcome::Fatal(format!(
                "failed to read response body (HTTP {}): {e}",
                status.as_u16()
            ));
        }
        Err(_) => {
            return SendOutcome::Fatal(format!(
                "timed out reading response body (HTTP {})",
                status.as_u16()
            ));
        }
    };

    if status == StatusCode::OK {
        let parsed = serde_json::from_slice::<IngestOkBody>(&body_bytes).ok();
        let event_id = parsed
            .as_ref()
            .and_then(|p| p.event_id.clone())
            .unwrap_or_else(|| event.event_id.clone());
        let deduplicated = parsed.as_ref().is_some_and(|p| p.deduplicated);
        return SendOutcome::Ok {
            event_id,
            deduplicated,
        };
    }

    let detail = summarize_error_body(&body_bytes);
    let msg = if detail.is_empty() {
        format!("server returned HTTP {}", status.as_u16())
    } else {
        format!("server returned HTTP {}: {detail}", status.as_u16())
    };

    if matches!(
        status,
        StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE | StatusCode::UNPROCESSABLE_ENTITY
    ) {
        SendOutcome::InvalidPayload(msg)
    } else {
        SendOutcome::Fatal(msg)
    }
}

fn summarize_error_body(body: &[u8]) -> String {
    if body.is_empty() {
        return String::new();
    }
    if let Ok(val) = serde_json::from_slice::<Value>(body)
        && let Some(err_str) = val.get("error").and_then(Value::as_str)
    {
        return err_str.to_owned();
    }
    let text = String::from_utf8_lossy(body);
    let trimmed = text.trim();
    if trimmed.len() > 256 {
        trimmed.chars().take(256).collect()
    } else {
        trimmed.to_owned()
    }
}

async fn write_json_line<W, T>(writer: &mut W, value: &T) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut line = serde_json::to_vec(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push(b'\n');
    writer.write_all(&line).await?;
    writer.flush().await
}

async fn write_err<E>(stderr: &mut E, msg: &str) -> std::io::Result<()>
where
    E: AsyncWrite + Unpin,
{
    stderr.write_all(msg.as_bytes()).await?;
    stderr.write_all(b"\n").await?;
    stderr.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::is_valid_event_id;
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use serde_json::json;
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[test]
    fn ingest_uri_normalizes_unicode_hosts_and_paths() {
        let (uri, is_https) = parse_ingest_uri("https://bücher.example/通知?q=你好").unwrap();
        assert!(is_https);
        assert_eq!(uri.host(), Some("xn--bcher-kva.example"));
        assert_eq!(
            uri.path_and_query().unwrap().as_str(),
            "/%E9%80%9A%E7%9F%A5?q=%E4%BD%A0%E5%A5%BD"
        );
    }

    #[derive(Clone, Debug)]
    struct RecordedRequest {
        auth: Option<String>,
        content_type: Option<String>,
        body: Value,
    }

    struct MockServer {
        url: String,
        recorded: Arc<Mutex<Vec<RecordedRequest>>>,
        connections: Arc<AtomicUsize>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn spawn_mock_server(responses: Vec<(StatusCode, String)>) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let queue = Arc::new(Mutex::new(VecDeque::from(responses)));
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));

        let queue_bg = Arc::clone(&queue);
        let recorded_bg = Arc::clone(&recorded);
        let connections_bg = Arc::clone(&connections);

        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                connections_bg.fetch_add(1, Ordering::SeqCst);
                let queue_conn = Arc::clone(&queue_bg);
                let recorded_conn = Arc::clone(&recorded_bg);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let queue_req = Arc::clone(&queue_conn);
                        let recorded_req = Arc::clone(&recorded_conn);
                        async move {
                            let auth = req
                                .headers()
                                .get(AUTHORIZATION)
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned);
                            let content_type = req
                                .headers()
                                .get(CONTENT_TYPE)
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned);
                            let raw = req.into_body().collect().await.unwrap().to_bytes();
                            let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
                            recorded_req.lock().unwrap().push(RecordedRequest {
                                auth,
                                content_type,
                                body: body.clone(),
                            });

                            let (status, resp_body) =
                                queue_req.lock().unwrap().pop_front().unwrap_or_else(|| {
                                    let eid = body
                                        .get("eventId")
                                        .and_then(Value::as_str)
                                        .unwrap_or("evt_default");
                                    (
                                        StatusCode::OK,
                                        json!({
                                            "ok": true,
                                            "eventId": eid,
                                            "deduplicated": false
                                        })
                                        .to_string(),
                                    )
                                });

                            let resp = hyper::Response::builder()
                                .status(status)
                                .header(CONTENT_TYPE, "application/json")
                                .body(Full::new(Bytes::from(resp_body)))
                                .unwrap();
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    let _ = http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });

        MockServer {
            url: format!("http://{addr}/v1/events"),
            recorded,
            connections,
            handle,
        }
    }

    fn base_options(url: String, stream: bool, on_invalid: OnInvalid) -> EmitOptions {
        EmitOptions {
            url,
            name: None,
            stream,
            on_invalid,
            token: Some(SecretString::new("prod_secret_token")),
        }
    }

    #[tokio::test]
    async fn single_shot_sends_minimal_payload_and_ignores_extra_fields() {
        let server = spawn_mock_server(vec![]).await;
        let input = json!({
            "name": "ci.build_failed",
            "data": {"repo": "mcp-hookd", "pr": 7},
            "cursor": "cur_123",
            "truncated": true,
            "_meta": {"source": "mcpcli"}
        })
        .to_string();

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_emit_with_io(
            base_options(server.url.clone(), false, OnInvalid::Fail),
            Cursor::new(input.into_bytes()),
            &mut stdout,
            &mut stderr,
        )
        .await;

        assert_eq!(code, ExitCode::SUCCESS);
        assert!(stderr.is_empty());

        let reqs = server.recorded.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].auth.as_deref(), Some("Bearer prod_secret_token"));
        assert_eq!(reqs[0].content_type.as_deref(), Some("application/json"));

        let obj = reqs[0].body.as_object().unwrap();
        assert_eq!(obj.len(), 4);
        assert_eq!(obj.get("name").unwrap(), "ci.build_failed");
        assert_eq!(
            obj.get("data").unwrap(),
            &json!({"repo": "mcp-hookd", "pr": 7})
        );
        assert!(!obj.contains_key("cursor"));
        assert!(!obj.contains_key("truncated"));
        assert!(!obj.contains_key("_meta"));

        let event_id = obj.get("eventId").unwrap().as_str().unwrap();
        assert!(event_id.starts_with("evt_"));
        assert_eq!(event_id.len(), 36);
        assert!(is_valid_event_id(event_id));

        let ts = obj.get("timestamp").unwrap().as_str().unwrap();
        assert!(ts.ends_with('Z') && ts.contains('T'));
    }

    #[tokio::test]
    async fn name_override_and_invalid_event_id_are_normalized_deterministically() {
        let server = spawn_mock_server(vec![]).await;
        let input = json!({
            "name": "original.event",
            "eventId": "boot:42/weird.id",
            "timestamp": "2026-11-25T10:00:00Z",
            "data": {"ok": true}
        })
        .to_string();

        let mut opts = base_options(server.url.clone(), false, OnInvalid::Fail);
        opts.name = Some("override.event".into());

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_emit_with_io(
            opts,
            Cursor::new(input.into_bytes()),
            &mut stdout,
            &mut stderr,
        )
        .await;

        assert_eq!(code, ExitCode::SUCCESS);
        let reqs = server.recorded.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].body["name"], "override.event");
        assert_eq!(
            reqs[0].body["eventId"],
            normalize_emit_event_id("override.event", "boot:42/weird.id")
        );
        assert_eq!(reqs[0].body["timestamp"], "2026-11-25T10:00:00Z");
    }

    #[tokio::test]
    async fn single_shot_on_invalid_drop_skips_local_and_400_413_422_errors() {
        for bad_input in ["not-json", r#"{"name":"x"}"#] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let code_fail = run_emit_with_io(
                base_options(
                    "http://127.0.0.1:9/v1/events".into(),
                    false,
                    OnInvalid::Fail,
                ),
                Cursor::new(bad_input.as_bytes()),
                &mut stdout,
                &mut stderr,
            )
            .await;
            assert_eq!(code_fail, ExitCode::FAILURE);
            assert!(!stderr.is_empty());

            stderr.clear();
            let code_drop = run_emit_with_io(
                base_options(
                    "http://127.0.0.1:9/v1/events".into(),
                    false,
                    OnInvalid::Drop,
                ),
                Cursor::new(bad_input.as_bytes()),
                &mut stdout,
                &mut stderr,
            )
            .await;
            assert_eq!(code_drop, ExitCode::SUCCESS);
            assert!(!stderr.is_empty());
        }

        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::PAYLOAD_TOO_LARGE,
            StatusCode::UNPROCESSABLE_ENTITY,
        ] {
            let server = spawn_mock_server(vec![
                (status, r#"{"error":"schema mismatch"}"#.into()),
                (status, r#"{"error":"schema mismatch"}"#.into()),
            ])
            .await;
            let payload = r#"{"name":"ev","data":{}}"#;

            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let code_fail = run_emit_with_io(
                base_options(server.url.clone(), false, OnInvalid::Fail),
                Cursor::new(payload.as_bytes()),
                &mut stdout,
                &mut stderr,
            )
            .await;
            assert_eq!(code_fail, ExitCode::FAILURE);
            assert!(!stderr.is_empty());

            stderr.clear();
            let code_drop = run_emit_with_io(
                base_options(server.url.clone(), false, OnInvalid::Drop),
                Cursor::new(payload.as_bytes()),
                &mut stdout,
                &mut stderr,
            )
            .await;
            assert_eq!(code_drop, ExitCode::SUCCESS);
            assert!(!stderr.is_empty());
        }
    }

    #[tokio::test]
    async fn single_shot_fatal_statuses_always_exit_nonzero_even_with_drop() {
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::CONFLICT,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            let server = spawn_mock_server(vec![(status, r#"{"error":"fatal"}"#.into())]).await;
            let payload = r#"{"name":"ev","data":{}}"#;
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();

            let code = run_emit_with_io(
                base_options(server.url.clone(), false, OnInvalid::Drop),
                Cursor::new(payload.as_bytes()),
                &mut stdout,
                &mut stderr,
            )
            .await;

            assert_eq!(code, ExitCode::FAILURE, "status {status} must fail");
            assert!(!stderr.is_empty());
        }
    }

    #[tokio::test]
    async fn stream_mode_reuses_keep_alive_skips_blank_lines_and_handles_crlf() {
        let server = spawn_mock_server(vec![
            (
                StatusCode::OK,
                r#"{"ok":true,"eventId":"id_1","deduplicated":false}"#.into(),
            ),
            (
                StatusCode::OK,
                r#"{"ok":true,"eventId":"id_2","deduplicated":true}"#.into(),
            ),
        ])
        .await;

        let input = concat!(
            "\n",
            "   \r\n",
            r#"{"name":"ev","eventId":"id_1","data":{"n":1},"cursor":"c1","truncated":false,"_meta":{}}"#,
            "\r\n",
            "\t\n",
            r#"{"name":"ev","eventId":"id_2","data":{"n":2}}"#,
            "\n"
        );

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_emit_with_io(
            base_options(server.url.clone(), true, OnInvalid::Fail),
            Cursor::new(input.as_bytes()),
            &mut stdout,
            &mut stderr,
        )
        .await;

        assert_eq!(code, ExitCode::SUCCESS);
        assert!(stderr.is_empty());
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);

        let out_str = String::from_utf8(stdout).unwrap();
        let lines: Vec<Value> = out_str
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(
            lines,
            vec![
                json!({"ok": true, "eventId": "id_1", "deduplicated": false}),
                json!({"ok": true, "eventId": "id_2", "deduplicated": true}),
            ]
        );
    }

    #[tokio::test]
    async fn stream_mode_handles_invalid_events_under_fail_and_drop() {
        let input = concat!(
            "not-json\n",
            r#"{"name":"ev","eventId":"bad_400","data":{}}"#,
            "\n",
            r#"{"name":"ev","eventId":"bad_413","data":{}}"#,
            "\n",
            r#"{"name":"ev","eventId":"bad_422","data":{}}"#,
            "\n",
            r#"{"name":"ev","eventId":"good_1","data":{"ok":1}}"#,
            "\n",
        );

        let responses = || {
            vec![
                (StatusCode::BAD_REQUEST, r#"{"error":"bad"}"#.into()),
                (StatusCode::PAYLOAD_TOO_LARGE, r#"{"error":"big"}"#.into()),
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    r#"{"error":"unprocessable"}"#.into(),
                ),
                (
                    StatusCode::OK,
                    r#"{"ok":true,"eventId":"good_1","deduplicated":false}"#.into(),
                ),
            ]
        };

        // Fail mode
        let server_fail = spawn_mock_server(responses()).await;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_emit_with_io(
            base_options(server_fail.url.clone(), true, OnInvalid::Fail),
            Cursor::new(input.as_bytes()),
            &mut stdout,
            &mut stderr,
        )
        .await;
        assert_eq!(code, ExitCode::SUCCESS);
        let lines: Vec<Value> = String::from_utf8(stdout)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 5);
        for item in &lines[..4] {
            assert_eq!(item["ok"], false);
            assert!(item["error"].as_str().is_some_and(|s| !s.is_empty()));
        }
        assert_eq!(
            lines[4],
            json!({"ok": true, "eventId": "good_1", "deduplicated": false})
        );

        // Drop mode
        let server_drop = spawn_mock_server(responses()).await;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_emit_with_io(
            base_options(server_drop.url.clone(), true, OnInvalid::Drop),
            Cursor::new(input.as_bytes()),
            &mut stdout,
            &mut stderr,
        )
        .await;
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(!stderr.is_empty());
        let lines: Vec<Value> = String::from_utf8(stdout)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 5);
        for item in &lines[..4] {
            assert_eq!(*item, json!({"ok": true, "dropped": true}));
        }
        assert_eq!(
            lines[4],
            json!({"ok": true, "eventId": "good_1", "deduplicated": false})
        );
    }

    #[tokio::test]
    async fn stream_mode_fatal_errors_never_emit_ok_true_and_exit_nonzero() {
        let input = concat!(
            r#"{"name":"ev","eventId":"ok_first","data":{}}"#,
            "\n",
            r#"{"name":"ev","eventId":"hits_fatal","data":{}}"#,
            "\n",
            r#"{"name":"ev","eventId":"must_not_run","data":{}}"#,
            "\n",
        );

        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            for mode in [OnInvalid::Fail, OnInvalid::Drop] {
                let server = spawn_mock_server(vec![
                    (
                        StatusCode::OK,
                        r#"{"ok":true,"eventId":"ok_first","deduplicated":false}"#.into(),
                    ),
                    (status, r#"{"error":"blocked"}"#.into()),
                ])
                .await;

                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                let code = run_emit_with_io(
                    base_options(server.url.clone(), true, mode),
                    Cursor::new(input.as_bytes()),
                    &mut stdout,
                    &mut stderr,
                )
                .await;

                assert_eq!(code, ExitCode::FAILURE);
                assert!(!stderr.is_empty());

                let out_str = String::from_utf8(stdout).unwrap();
                let lines: Vec<Value> = out_str
                    .lines()
                    .map(|l| serde_json::from_str(l).unwrap())
                    .collect();
                // Only the first 200 line is acknowledged; the fatal line must never emit ok:true.
                assert_eq!(
                    lines,
                    vec![json!({"ok": true, "eventId": "ok_first", "deduplicated": false})]
                );
                assert_eq!(server.recorded.lock().unwrap().len(), 2);
            }
        }
    }

    #[tokio::test]
    async fn missing_or_empty_token_exits_nonzero() {
        for token in [None, Some(SecretString::new(""))] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let code = run_emit_with_io(
                EmitOptions {
                    url: "http://127.0.0.1:9/v1/events".into(),
                    name: None,
                    stream: false,
                    on_invalid: OnInvalid::Drop,
                    token,
                },
                Cursor::new(b"{}"),
                &mut stdout,
                &mut stderr,
            )
            .await;

            assert_eq!(code, ExitCode::FAILURE);
            assert!(stdout.is_empty());
            assert!(
                String::from_utf8(stderr)
                    .unwrap()
                    .contains("HOOKD_PRODUCER_TOKEN")
            );
        }
    }

    #[tokio::test]
    async fn single_shot_oversized_input_respects_on_invalid() {
        let server = spawn_mock_server(vec![]).await;
        let big_pad = "a".repeat(MAX_EMIT_INPUT_BYTES + 16);
        let input = format!(r#"{{"name":"ev","data":"{big_pad}"}}"#);

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code_fail = run_emit_with_io(
            base_options(server.url.clone(), false, OnInvalid::Fail),
            Cursor::new(input.as_bytes()),
            &mut stdout,
            &mut stderr,
        )
        .await;
        assert_eq!(code_fail, ExitCode::FAILURE);
        assert!(!stderr.is_empty());

        stderr.clear();
        let code_drop = run_emit_with_io(
            base_options(server.url.clone(), false, OnInvalid::Drop),
            Cursor::new(input.as_bytes()),
            &mut stdout,
            &mut stderr,
        )
        .await;
        assert_eq!(code_drop, ExitCode::SUCCESS);
        assert!(!stderr.is_empty());
        assert!(server.recorded.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn stream_mode_oversized_line_drains_and_continues() {
        let big_pad = "x".repeat(MAX_EMIT_INPUT_BYTES + 64);
        let input = format!(
            "{{\"name\":\"ev\",\"data\":\"{big_pad}\"}}\n{{\"name\":\"ev\",\"eventId\":\"after_big\",\"data\":{{\"ok\":true}}}}\n"
        );

        // Fail mode
        let server_fail = spawn_mock_server(vec![(
            StatusCode::OK,
            r#"{"ok":true,"eventId":"after_big","deduplicated":false}"#.into(),
        )])
        .await;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_emit_with_io(
            base_options(server_fail.url.clone(), true, OnInvalid::Fail),
            Cursor::new(input.as_bytes()),
            &mut stdout,
            &mut stderr,
        )
        .await;
        assert_eq!(code, ExitCode::SUCCESS);
        let lines: Vec<Value> = String::from_utf8(stdout)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["ok"], false);
        assert!(lines[0]["error"].as_str().unwrap().contains("byte limit"));
        assert_eq!(
            lines[1],
            json!({"ok": true, "eventId": "after_big", "deduplicated": false})
        );
        assert_eq!(server_fail.recorded.lock().unwrap().len(), 1);

        // Drop mode
        let server_drop = spawn_mock_server(vec![(
            StatusCode::OK,
            r#"{"ok":true,"eventId":"after_big","deduplicated":false}"#.into(),
        )])
        .await;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_emit_with_io(
            base_options(server_drop.url.clone(), true, OnInvalid::Drop),
            Cursor::new(input.as_bytes()),
            &mut stdout,
            &mut stderr,
        )
        .await;
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(!stderr.is_empty());
        let lines: Vec<Value> = String::from_utf8(stdout)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(
            lines,
            vec![
                json!({"ok": true, "dropped": true}),
                json!({"ok": true, "eventId": "after_big", "deduplicated": false}),
            ]
        );
        assert_eq!(server_drop.recorded.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn empty_string_event_id_is_rejected_as_invalid() {
        let server = spawn_mock_server(vec![]).await;
        let payload = r#"{"name":"ev","eventId":"","data":{"k":1}}"#;

        // Single-shot fail & drop
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code_fail = run_emit_with_io(
            base_options(server.url.clone(), false, OnInvalid::Fail),
            Cursor::new(payload.as_bytes()),
            &mut stdout,
            &mut stderr,
        )
        .await;
        assert_eq!(code_fail, ExitCode::FAILURE);
        assert!(
            String::from_utf8(stderr.clone())
                .unwrap()
                .contains("eventId")
        );

        stderr.clear();
        let code_drop = run_emit_with_io(
            base_options(server.url.clone(), false, OnInvalid::Drop),
            Cursor::new(payload.as_bytes()),
            &mut stdout,
            &mut stderr,
        )
        .await;
        assert_eq!(code_drop, ExitCode::SUCCESS);
        assert!(!stderr.is_empty());

        // Stream fail & drop
        let stream_input = format!("{payload}\n");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code_s_fail = run_emit_with_io(
            base_options(server.url.clone(), true, OnInvalid::Fail),
            Cursor::new(stream_input.as_bytes()),
            &mut stdout,
            &mut stderr,
        )
        .await;
        assert_eq!(code_s_fail, ExitCode::SUCCESS);
        let line: Value = serde_json::from_str(String::from_utf8(stdout).unwrap().trim()).unwrap();
        assert_eq!(line["ok"], false);
        assert!(line["error"].as_str().unwrap().contains("eventId"));

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code_s_drop = run_emit_with_io(
            base_options(server.url.clone(), true, OnInvalid::Drop),
            Cursor::new(stream_input.as_bytes()),
            &mut stdout,
            &mut stderr,
        )
        .await;
        assert_eq!(code_s_drop, ExitCode::SUCCESS);
        assert!(!stderr.is_empty());
        let line: Value = serde_json::from_str(String::from_utf8(stdout).unwrap().trim()).unwrap();
        assert_eq!(line, json!({"ok": true, "dropped": true}));

        assert!(server.recorded.lock().unwrap().is_empty());
    }
}
