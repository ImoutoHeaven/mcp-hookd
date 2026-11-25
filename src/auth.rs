//! Delegated authorization re-verification client, cache, single-flight coalescing, and scope/TTL helpers.

use crate::config::AuthContextConfig;
use crate::types::{DEFAULT_TTL_SECS, MIN_TTL_SECS, SecretString, unix_now};
use bytes::Bytes;
use http::{HeaderValue, Method, Request, Uri, header};
use http_body::Body;
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, Once, Weak};
use std::time::{Duration, Instant};

pub const AUTH_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_AUTH_CHECK_RESP_BYTES: usize = 4 * 1024;
const MAX_CACHE_ENTRIES: usize = 4096;
const LOCK_MAP_PRUNE_THRESHOLD: usize = 256;

static INSTALL_CRYPTO_PROVIDER: Once = Once::new();

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedAuth {
    pub principal: String,
    pub resource: String,
    pub scopes: Vec<String>,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthCheckOutcome {
    Active(CheckedAuth),
    Inactive,
    TransientError(String),
}

#[derive(Clone, Debug)]
enum CachedOutcome {
    Active(CheckedAuth),
    Inactive,
}

#[derive(Clone, Debug)]
struct CacheEntry {
    outcome: CachedOutcome,
    checked_at: Instant,
}

#[derive(Serialize)]
struct CheckRequest<'a> {
    #[serde(rename = "ref")]
    auth_ref: &'a str,
}

#[derive(Deserialize)]
struct RawCheckResponse {
    active: bool,
    #[serde(default)]
    principal: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default, rename = "expiresAt")]
    expires_at: Option<u64>,
}

#[derive(Clone)]
enum AuthHttpClient {
    Http(Client<HttpConnector, Full<Bytes>>),
    Https(Client<HttpsConnector<HttpConnector>, Full<Bytes>>),
}

impl AuthHttpClient {
    async fn request(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Result<http::Response<hyper::body::Incoming>, hyper_util::client::legacy::Error> {
        match self {
            Self::Http(client) => client.request(req).await,
            Self::Https(client) => client.request(req).await,
        }
    }
}

/// Client for gateway `POST /authorization/check` with per-`auth_ref` TTL cache and single-flight locks.
#[derive(Clone)]
pub struct AuthContextClient {
    check_uri: Uri,
    check_token: SecretString,
    expected_resource: String,
    reverify_interval: Duration,
    timeout: Duration,
    http: AuthHttpClient,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    locks: Arc<Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>>,
}

impl AuthContextClient {
    pub fn new(config: &AuthContextConfig) -> Result<Self, String> {
        Self::with_timeout(config, AUTH_CHECK_TIMEOUT)
    }

    pub fn with_timeout(config: &AuthContextConfig, timeout: Duration) -> Result<Self, String> {
        let check_uri: Uri = config
            .check_url
            .as_str()
            .parse()
            .map_err(|e| format!("invalid auth_context.check_url URI: {e}"))?;

        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_secs(15));

        let http = if config.check_url.scheme() == "https" {
            INSTALL_CRYPTO_PROVIDER.call_once(|| {
                let _ = rustls::crypto::ring::default_provider().install_default();
            });
            let https = hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .map_err(|e| format!("cannot load native TLS root certificates: {e}"))?
                .https_only()
                .enable_http1()
                .build();
            AuthHttpClient::Https(builder.build(https))
        } else {
            AuthHttpClient::Http(builder.build(HttpConnector::new()))
        };

        Ok(Self {
            check_uri,
            check_token: config.check_token.clone(),
            expected_resource: config.expected_resource.clone(),
            reverify_interval: Duration::from_secs(config.reverify_secs),
            timeout,
            http,
            cache: Arc::new(Mutex::new(HashMap::new())),
            locks: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn expected_resource(&self) -> &str {
        &self.expected_resource
    }

    pub fn reverify_interval(&self) -> Duration {
        self.reverify_interval
    }

    /// Always contact `check_url` (used for subscribe/refresh and startup re-verification).
    pub async fn check_live(&self, auth_ref: &str) -> AuthCheckOutcome {
        let lock = self.ref_lock(auth_ref);
        let _guard = lock.lock().await;
        let outcome = self.fetch_live(auth_ref).await;
        self.store_cache(auth_ref, &outcome);
        outcome
    }

    /// Return a fresh cached result within `reverify_secs`, coalescing concurrent misses per `auth_ref`.
    pub async fn check_cached(&self, auth_ref: &str) -> AuthCheckOutcome {
        if let Some(hit) = self.lookup_cache(auth_ref) {
            return hit;
        }
        let lock = self.ref_lock(auth_ref);
        let _guard = lock.lock().await;
        if let Some(hit) = self.lookup_cache(auth_ref) {
            return hit;
        }
        let outcome = self.fetch_live(auth_ref).await;
        self.store_cache(auth_ref, &outcome);
        outcome
    }

    fn ref_lock(&self, auth_ref: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.locks.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = map.get(auth_ref).and_then(Weak::upgrade) {
            return existing;
        }
        if map.len() >= LOCK_MAP_PRUNE_THRESHOLD {
            map.retain(|_, weak| weak.strong_count() > 0);
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        map.insert(auth_ref.to_owned(), Arc::downgrade(&lock));
        lock
    }

    fn lookup_cache(&self, auth_ref: &str) -> Option<AuthCheckOutcome> {
        let now_instant = Instant::now();
        let entry = {
            let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            cache.get(auth_ref).cloned()
        }?;
        if now_instant.saturating_duration_since(entry.checked_at) >= self.reverify_interval {
            return None;
        }
        match entry.outcome {
            CachedOutcome::Inactive => Some(AuthCheckOutcome::Inactive),
            CachedOutcome::Active(auth) => {
                if auth.expires_at <= unix_now() {
                    Some(AuthCheckOutcome::Inactive)
                } else {
                    Some(AuthCheckOutcome::Active(auth))
                }
            }
        }
    }

    fn store_cache(&self, auth_ref: &str, outcome: &AuthCheckOutcome) {
        let cached = match outcome {
            AuthCheckOutcome::Active(auth) => CachedOutcome::Active(auth.clone()),
            AuthCheckOutcome::Inactive => CachedOutcome::Inactive,
            AuthCheckOutcome::TransientError(_) => return,
        };
        let now = Instant::now();
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if cache.len() >= MAX_CACHE_ENTRIES && !cache.contains_key(auth_ref) {
            let ttl = self.reverify_interval;
            cache.retain(|_, v| now.saturating_duration_since(v.checked_at) < ttl);
            if cache.len() >= MAX_CACHE_ENTRIES
                && let Some(oldest_key) = cache
                    .iter()
                    .min_by_key(|(_, v)| v.checked_at)
                    .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            }
        }
        cache.insert(
            auth_ref.to_owned(),
            CacheEntry {
                outcome: cached,
                checked_at: now,
            },
        );
    }

    async fn fetch_live(&self, auth_ref: &str) -> AuthCheckOutcome {
        let body_bytes = match serde_json::to_vec(&CheckRequest { auth_ref }) {
            Ok(b) => Bytes::from(b),
            Err(e) => {
                return AuthCheckOutcome::TransientError(format!(
                    "cannot serialize auth check request: {e}"
                ));
            }
        };

        let auth_header =
            match HeaderValue::from_str(&format!("Bearer {}", self.check_token.expose())) {
                Ok(v) => v,
                Err(_) => {
                    return AuthCheckOutcome::TransientError(
                        "invalid authorization header value".into(),
                    );
                }
            };

        let req = match Request::builder()
            .method(Method::POST)
            .uri(self.check_uri.clone())
            .header(header::AUTHORIZATION, auth_header)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .body(Full::new(body_bytes))
        {
            Ok(r) => r,
            Err(e) => {
                return AuthCheckOutcome::TransientError(format!(
                    "cannot build auth check request: {e}"
                ));
            }
        };

        let work = async {
            let resp = self
                .http
                .request(req)
                .await
                .map_err(|e| format!("auth check request failed: {e}"))?;
            let status = resp.status();
            if !status.is_success() {
                return Err(format!("auth check returned HTTP {}", status.as_u16()));
            }
            let body = read_bounded_body(resp.into_body(), MAX_AUTH_CHECK_RESP_BYTES).await?;
            Ok(body)
        };

        let body = match tokio::time::timeout(self.timeout, work).await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(err)) => return AuthCheckOutcome::TransientError(err),
            Err(_) => return AuthCheckOutcome::TransientError("auth check timed out".into()),
        };

        let parsed: RawCheckResponse = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                return AuthCheckOutcome::TransientError(format!(
                    "invalid auth check JSON response: {e}"
                ));
            }
        };

        if !parsed.active {
            return AuthCheckOutcome::Inactive;
        }

        let (Some(principal), Some(resource), Some(scopes), Some(expires_at)) = (
            parsed.principal,
            parsed.resource,
            parsed.scopes,
            parsed.expires_at,
        ) else {
            return AuthCheckOutcome::TransientError(
                "active auth check response missing required fields".into(),
            );
        };

        if principal.is_empty() {
            return AuthCheckOutcome::TransientError(
                "active auth check response has empty principal".into(),
            );
        }

        if resource != self.expected_resource || expires_at <= unix_now() {
            return AuthCheckOutcome::Inactive;
        }

        AuthCheckOutcome::Active(CheckedAuth {
            principal,
            resource,
            scopes,
            expires_at,
        })
    }
}

async fn read_bounded_body<B>(mut body: B, limit: usize) -> Result<Vec<u8>, String>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    if body.size_hint().lower() > limit as u64 {
        return Err(format!("auth check response exceeds {limit} byte limit"));
    }
    let mut out = Vec::new();
    while let Some(frame_res) = body.frame().await {
        let frame = frame_res.map_err(|e| format!("cannot read auth check response: {e}"))?;
        if let Ok(data) = frame.into_data() {
            if out.len().saturating_add(data.len()) > limit {
                return Err(format!("auth check response exceeds {limit} byte limit"));
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

/// Deduplicated intersection of request header scopes and gateway-verified scopes.
pub fn intersect_scopes(header_scopes: &[String], check_scopes: &[String]) -> Vec<String> {
    let allowed: HashSet<&str> = check_scopes.iter().map(String::as_str).collect();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for scope in header_scopes {
        if allowed.contains(scope.as_str()) && seen.insert(scope.as_str()) {
            out.push(scope.clone());
        }
    }
    out
}

/// True when every scope in `granted` is present in `effective`.
pub fn scopes_subset(granted: &[String], effective: &[String]) -> bool {
    let eff: HashSet<&str> = effective.iter().map(String::as_str).collect();
    granted.iter().all(|s| eff.contains(s.as_str()))
}

/// Compute `refresh_before` per spec §5:
/// - `ttl_ms = None` (omitted) uses `DEFAULT_TTL_SECS`
/// - `ttl_ms = Some(None)` (explicit JSON `null`) uses `max_ttl_secs`
/// - `ttl_ms = Some(Some(ms))` uses `ms / 1000`
///
/// The result is clamped to `[MIN_TTL_SECS, max_ttl_secs]`, then capped at `expires_at` when present.
pub fn compute_refresh_before(
    now: u64,
    ttl_ms: Option<Option<u64>>,
    max_ttl_secs: u64,
    expires_at: Option<u64>,
) -> u64 {
    let raw_secs = match ttl_ms {
        None => DEFAULT_TTL_SECS,
        Some(None) => max_ttl_secs,
        Some(Some(ms)) => ms / 1000,
    };
    let upper = max_ttl_secs.max(MIN_TTL_SECS);
    let desired_secs = raw_secs.clamp(MIN_TTL_SECS, upper);
    let candidate = now.saturating_add(desired_secs);
    match expires_at {
        Some(exp) => candidate.min(exp),
        None => candidate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Response, StatusCode};
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use url::Url;

    #[test]
    fn scope_intersection_and_subset() {
        let header = vec!["a".into(), "b".into(), "a".into(), "c".into()];
        let check = vec!["c".into(), "a".into(), "d".into()];
        assert_eq!(intersect_scopes(&header, &check), vec!["a", "c"]);
        assert!(intersect_scopes(&[], &check).is_empty());

        assert!(scopes_subset(&["a".into(), "c".into()], &check));
        assert!(!scopes_subset(&["a".into(), "b".into()], &check));
        assert!(scopes_subset(&[], &[]));
    }

    #[test]
    fn compute_refresh_before_clamping_boundaries() {
        let now = 1_700_000_000u64;
        // Omitted ttlMs -> DEFAULT_TTL_SECS (1800).
        assert_eq!(
            compute_refresh_before(now, None, 3600, None),
            now + DEFAULT_TTL_SECS
        );
        // Omitted ttlMs clamped down when max_ttl_secs < DEFAULT_TTL_SECS.
        assert_eq!(compute_refresh_before(now, None, 600, None), now + 600);
        // Explicit null -> max_ttl_secs.
        assert_eq!(
            compute_refresh_before(now, Some(None), 3600, None),
            now + 3600
        );
        // Below MIN_TTL_SECS clamped up to MIN_TTL_SECS (60).
        assert_eq!(
            compute_refresh_before(now, Some(Some(5_000)), 3600, None),
            now + MIN_TTL_SECS
        );
        // Above max_ttl_secs clamped down to max_ttl_secs.
        assert_eq!(
            compute_refresh_before(now, Some(Some(9_999_000)), 3600, None),
            now + 3600
        );
        // Capped by expiresAt even when 0 < expiresAt - now < MIN_TTL_SECS.
        assert_eq!(
            compute_refresh_before(now, Some(Some(10_000)), 3600, Some(now + 20)),
            now + 20
        );
        assert_eq!(
            compute_refresh_before(now, Some(None), 3600, Some(now + 500)),
            now + 500
        );
    }

    async fn spawn_mock_check_server<F, Fut>(handler: F) -> Url
    where
        F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Response<Full<Bytes>>> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        tokio::spawn(async move {
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
        Url::parse(&format!("http://{addr}/authorization/check")).unwrap()
    }

    fn make_config(check_url: Url, reverify_secs: u64) -> AuthContextConfig {
        AuthContextConfig {
            check_url,
            check_token: SecretString::new("0123456789abcdef_check_token"),
            expected_resource: "https://mcp.example.com/mcp".into(),
            reverify_secs,
        }
    }

    #[tokio::test]
    async fn check_cached_single_flight_and_cache_reuse() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = Arc::clone(&hits);
        let url = spawn_mock_check_server(move |req| {
            let hits_srv = Arc::clone(&hits_srv);
            async move {
                assert_eq!(req.method(), Method::POST);
                assert_eq!(
                    req.headers().get(header::AUTHORIZATION).unwrap(),
                    "Bearer 0123456789abcdef_check_token"
                );
                let body = req.into_body().collect().await.unwrap().to_bytes();
                let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(parsed["ref"], "aref_1");

                hits_srv.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(60)).await;
                let exp = unix_now() + 3600;
                let resp_json = serde_json::json!({
                    "active": true,
                    "principal": "aref_1",
                    "resource": "https://mcp.example.com/mcp",
                    "scopes": ["events:read", "tools:call"],
                    "expiresAt": exp
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from(resp_json.to_string())))
                    .unwrap()
            }
        })
        .await;

        let client = AuthContextClient::new(&make_config(url, 15)).unwrap();

        // Launch 8 concurrent check_cached calls for the same auth_ref -> single-flight coalesces into 1 HTTP request.
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let c = client.clone();
            tasks.push(tokio::spawn(async move { c.check_cached("aref_1").await }));
        }
        for t in tasks {
            match t.await.unwrap() {
                AuthCheckOutcome::Active(a) => {
                    assert_eq!(a.principal, "aref_1");
                    assert_eq!(a.scopes, vec!["events:read", "tools:call"]);
                }
                other => panic!("expected Active, got {other:?}"),
            }
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // Subsequent check_cached within reverify_secs hits cache without another HTTP call.
        assert!(matches!(
            client.check_cached("aref_1").await,
            AuthCheckOutcome::Active(_)
        ));
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // check_live always hits the server.
        assert!(matches!(
            client.check_live("aref_1").await,
            AuthCheckOutcome::Active(_)
        ));
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn inactive_on_revoked_wrong_resource_or_expired() {
        let url = spawn_mock_check_server(move |req| async move {
            let body = req.into_body().collect().await.unwrap().to_bytes();
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let resp_json = match parsed["ref"].as_str().unwrap() {
                "revoked" => serde_json::json!({"active": false}),
                "wrong_res" => serde_json::json!({
                    "active": true,
                    "principal": "p",
                    "resource": "https://other.example.com/mcp",
                    "scopes": ["s"],
                    "expiresAt": unix_now() + 3600
                }),
                "expired" => serde_json::json!({
                    "active": true,
                    "principal": "p",
                    "resource": "https://mcp.example.com/mcp",
                    "scopes": ["s"],
                    "expiresAt": unix_now()
                }),
                _ => serde_json::json!({"active": false}),
            };
            Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from(resp_json.to_string())))
                .unwrap()
        })
        .await;

        let client = AuthContextClient::new(&make_config(url, 15)).unwrap();
        assert_eq!(
            client.check_live("revoked").await,
            AuthCheckOutcome::Inactive
        );
        assert_eq!(
            client.check_live("wrong_res").await,
            AuthCheckOutcome::Inactive
        );
        assert_eq!(
            client.check_live("expired").await,
            AuthCheckOutcome::Inactive
        );
    }

    #[tokio::test]
    async fn transient_error_on_timeout_5xx_and_oversized_response_not_cached() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = Arc::clone(&hits);
        let url = spawn_mock_check_server(move |req| {
            let hits_srv = Arc::clone(&hits_srv);
            async move {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
                hits_srv.fetch_add(1, Ordering::SeqCst);
                match parsed["ref"].as_str().unwrap() {
                    "slow" => {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from(r#"{"active":false}"#)))
                            .unwrap()
                    }
                    "err500" => Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Full::new(Bytes::from("boom")))
                        .unwrap(),
                    "huge" => {
                        let big = "a".repeat(MAX_AUTH_CHECK_RESP_BYTES + 128);
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from(big)))
                            .unwrap()
                    }
                    _ => Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from(r#"{"active":false}"#)))
                        .unwrap(),
                }
            }
        })
        .await;

        let client =
            AuthContextClient::with_timeout(&make_config(url, 15), Duration::from_millis(100))
                .unwrap();

        assert!(matches!(
            client.check_cached("slow").await,
            AuthCheckOutcome::TransientError(_)
        ));
        assert!(matches!(
            client.check_cached("err500").await,
            AuthCheckOutcome::TransientError(_)
        ));
        // Transient errors must not be cached, so calling again hits the server again.
        assert!(matches!(
            client.check_cached("err500").await,
            AuthCheckOutcome::TransientError(_)
        ));
        assert!(matches!(
            client.check_cached("huge").await,
            AuthCheckOutcome::TransientError(_)
        ));
        assert_eq!(hits.load(Ordering::SeqCst), 4);
    }
}
