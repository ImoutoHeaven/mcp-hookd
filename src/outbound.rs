//! Anti-DNS-rebinding HTTPS connector and Standard Webhooks delivery client (spec §6.2 & §6.4).

use crate::types::{
    CallbackErrorReason, MAX_DELIVERY_RESP_BYTES, MAX_VERIFY_RESP_BYTES, QuotaConfig, SecretString,
    constant_time_bytes_eq, random_hex, sign_webhook_v1, unix_now,
};
use bytes::Bytes;
use http::{HeaderValue, Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{
    CaptureConnection, Connected, Connection, capture_connection,
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tower_service::Service;
use url::{Host, Url};

pub const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);
pub const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);
pub const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

const VERIFY_IP_RATE_WINDOW: Duration = Duration::from_secs(60);
const VERIFY_IP_RATE_LIMIT: usize = 20;
const MAX_VERIFY_IP_ENTRIES: usize = 4096;

pub type DnsFuture = Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>>;
pub type DnsResolver = Arc<dyn Fn(&str, u16) -> DnsFuture + Send + Sync>;

#[cfg(test)]
pub type TcpDialFuture = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>;
#[cfg(test)]
pub type TcpDialer = Arc<dyn Fn(SocketAddr) -> TcpDialFuture + Send + Sync>;

/// Result of a synchronous callback verification challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifyError {
    Callback(CallbackErrorReason),
    RateLimited(String),
}

/// Result of a single webhook delivery attempt (spec §6.4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryOutcome {
    Success,
    PermanentDrop(CallbackErrorReason),
    Transient(CallbackErrorReason),
}

/// Returns true only for globally routable unicast IPs per IANA registries.
/// IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are unwrapped and checked as IPv4.
pub fn is_public_unicast_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_unicast_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public_unicast_v4(v4),
            None => is_public_unicast_v6(v6),
        },
    }
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.is_loopback(),
            None => v6.is_loopback(),
        },
    }
}

fn is_allowed_ip(ip: IpAddr, allow_loopback: bool) -> bool {
    is_public_unicast_ip(ip) || (allow_loopback && is_loopback_ip(ip))
}

fn is_public_unicast_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    let blocked = o[0] == 0 // 0.0.0.0/8
        || o[0] == 10 // 10.0.0.0/8
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
        || o[0] == 127 // 127.0.0.0/8
        || (o[0] == 169 && o[1] == 254) // 169.254.0.0/16 link-local & cloud metadata
        || (o[0] == 172 && (o[1] & 0xf0) == 16) // 172.16.0.0/12
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF protocol assignments
        || (o[0] == 192 && o[1] == 0 && o[2] == 2) // 192.0.2.0/24 TEST-NET-1
        || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 192.88.99.0/24 6to4 relay anycast
        || (o[0] == 192 && o[1] == 168) // 192.168.0.0/16
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking
        || (o[0] == 198 && o[1] == 51 && o[2] == 100) // 198.51.100.0/24 TEST-NET-2
        || (o[0] == 203 && o[1] == 0 && o[2] == 113) // 203.0.113.0/24 TEST-NET-3
        || o[0] >= 224; // 224.0.0.0/4 multicast & 240.0.0.0/4 reserved/broadcast
    !blocked
}

fn is_public_unicast_v6(v6: Ipv6Addr) -> bool {
    let s = v6.segments();
    // Only 2000::/3 is allocated for global unicast.
    if (s[0] & 0xe000) != 0x2000 {
        return false;
    }
    match s[0] {
        0x2001 => {
            let blocked = s[1] == 0x0000 // 2001::/32 Teredo
                || (s[1] == 0x0002 && s[2] == 0x0000) // 2001:2::/48 benchmarking
                || s[1] == 0x0003 // 2001:3::/32 AMT
                || (s[1] == 0x0004 && s[2] == 0x0112) // 2001:4:112::/48 AS112-v6
                || (s[1] & 0xfff0) == 0x0010 // 2001:10::/28 ORCHID
                || (s[1] & 0xfff0) == 0x0020 // 2001:20::/28 ORCHIDv2
                || (s[1] & 0xfff0) == 0x0030 // 2001:30::/28 DRIP
                || s[1] == 0x0db8; // 2001:db8::/32 documentation
            !blocked
        }
        0x2002 => false,                               // 2002::/16 6to4
        0x2620 => !(s[1] == 0x004f && s[2] == 0x8000), // 2620:4f:8000::/48 Direct Delegation AS112
        0x3fff => (s[1] & 0xf000) != 0x0000,           // 3fff::/20 documentation
        _ => true,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum IpVerifyPrefix {
    V4([u8; 4]),
    V6([u16; 4]),
}

fn ip_verify_prefix(ip: IpAddr) -> IpVerifyPrefix {
    match ip {
        IpAddr::V4(v4) => IpVerifyPrefix::V4(v4.octets()),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpVerifyPrefix::V4(v4.octets()),
            None => {
                let s = v6.segments();
                IpVerifyPrefix::V6([s[0], s[1], s[2], s[3]])
            }
        },
    }
}

struct IpRateBucket {
    window_start: Instant,
    count: usize,
}

#[derive(Default)]
struct IpVerifyLimiter {
    buckets: HashMap<IpVerifyPrefix, IpRateBucket>,
}

impl IpVerifyLimiter {
    fn check_and_record(&mut self, prefix: IpVerifyPrefix) -> Result<(), &'static str> {
        let now = Instant::now();
        self.buckets
            .retain(|_, b| now.saturating_duration_since(b.window_start) < VERIFY_IP_RATE_WINDOW);
        if !self.buckets.contains_key(&prefix) && self.buckets.len() >= MAX_VERIFY_IP_ENTRIES {
            return Err("callback target IP verification rate table is full");
        }
        let entry = self.buckets.entry(prefix).or_insert(IpRateBucket {
            window_start: now,
            count: 0,
        });
        if entry.count >= VERIFY_IP_RATE_LIMIT {
            return Err("callback target IP verification rate limit exceeded");
        }
        entry.count += 1;
        Ok(())
    }
}

/// Validate a webhook callback URL per spec §6.2 & §6.4.
pub fn validate_callback_url(raw: &str, allow_loopback: bool) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|e| format!("invalid callback URL: {e}"))?;
    if url.scheme() != "https" {
        return Err("callback URL must use https://".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("callback URL must not contain userinfo".into());
    }
    if url.fragment().is_some() {
        return Err("callback URL must not contain a fragment".into());
    }
    let host = url
        .host()
        .ok_or_else(|| "callback URL must contain a host".to_string())?;
    match host {
        Host::Ipv4(v4) if !is_allowed_ip(IpAddr::V4(v4), allow_loopback) => {
            return Err("callback URL points to a non-public IP address".into());
        }
        Host::Ipv6(v6) if !is_allowed_ip(IpAddr::V6(v6), allow_loopback) => {
            return Err("callback URL points to a non-public IP address".into());
        }
        Host::Domain("") => {
            return Err("callback URL host must not be empty".into());
        }
        _ => {}
    }
    Ok(url)
}

tokio::task_local! {
    static VERIFY_DIALED: Arc<AtomicBool>;
}

#[derive(Clone, Copy, Debug)]
struct ConnMeta {
    created_at: Instant,
    peer_ip: IpAddr,
}

#[derive(Debug)]
pub enum OutboundConnectError {
    InvalidUri(&'static str),
    Dns(io::Error),
    DnsEmpty,
    DisallowedIp(IpAddr),
    RateLimited(&'static str),
    Tcp(io::Error),
    Tls(io::Error),
}

impl fmt::Display for OutboundConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUri(msg) => write!(f, "invalid outbound URI: {msg}"),
            Self::Dns(e) => write!(f, "DNS resolution failed: {e}"),
            Self::DnsEmpty => f.write_str("DNS returned no addresses"),
            Self::DisallowedIp(ip) => write!(f, "resolved IP {ip} is not allowed"),
            Self::RateLimited(msg) => f.write_str(msg),
            Self::Tcp(e) => write!(f, "TCP connect failed: {e}"),
            Self::Tls(e) => write!(f, "TLS handshake failed: {e}"),
        }
    }
}

impl Error for OutboundConnectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Dns(e) | Self::Tcp(e) | Self::Tls(e) => Some(e),
            _ => None,
        }
    }
}

/// TLS stream wrapper carrying TCP connection creation time for pool lifetime poisoning.
pub struct SafeHttpsStream {
    inner: TokioIo<TlsStream<TcpStream>>,
    created_at: Instant,
    peer_ip: IpAddr,
}

impl Connection for SafeHttpsStream {
    fn connected(&self) -> Connected {
        Connected::new().extra(ConnMeta {
            created_at: self.created_at,
            peer_ip: self.peer_ip,
        })
    }
}

impl Read for SafeHttpsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl Write for SafeHttpsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
}

fn default_dns_resolver() -> DnsResolver {
    Arc::new(|host: &str, port: u16| {
        let host = host.to_owned();
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host.as_str(), port)).await?;
            Ok(addrs.collect())
        })
    })
}

fn build_tls_config(roots: RootCertStore) -> Result<Arc<ClientConfig>, String> {
    let mut cfg =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS protocol config error: {e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    // Force HTTP/1.1 ALPN so servers never negotiate HTTP/2.
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

fn load_native_root_store() -> Result<RootCertStore, String> {
    let result = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(result.certs);
    if added == 0 {
        let detail = result
            .errors
            .into_iter()
            .next()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no certificates found".into());
        return Err(format!("failed to load native root certificates: {detail}"));
    }
    Ok(roots)
}

/// HTTPS connector that resolves DNS on every new connection, rejects any non-public IP,
/// connects directly to the validated IP, and verifies TLS SNI/certs against the original host.
#[derive(Clone)]
pub struct SafeHttpsConnector {
    tls_config: Arc<ClientConfig>,
    allow_loopback: bool,
    resolver: DnsResolver,
    #[cfg(test)]
    dialer: Option<TcpDialer>,
    verify_ip_limiter: Option<Arc<Mutex<IpVerifyLimiter>>>,
}

impl SafeHttpsConnector {
    pub fn new(allow_loopback: bool) -> Result<Self, String> {
        let roots = load_native_root_store()?;
        Self::with_roots_and_resolver(roots, allow_loopback, default_dns_resolver())
    }

    pub fn with_roots_and_resolver(
        roots: RootCertStore,
        allow_loopback: bool,
        resolver: DnsResolver,
    ) -> Result<Self, String> {
        let tls_config = build_tls_config(roots)?;
        Ok(Self {
            tls_config,
            allow_loopback,
            resolver,
            #[cfg(test)]
            dialer: None,
            verify_ip_limiter: None,
        })
    }

    #[cfg(test)]
    pub fn with_dialer(mut self, dialer: TcpDialer) -> Self {
        self.dialer = Some(dialer);
        self
    }

    fn with_verify_ip_limiter(mut self, limiter: Arc<Mutex<IpVerifyLimiter>>) -> Self {
        self.verify_ip_limiter = Some(limiter);
        self
    }
}

impl Service<Uri> for SafeHttpsConnector {
    type Response = SafeHttpsStream;
    type Error = OutboundConnectError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let tls_config = Arc::clone(&self.tls_config);
        let allow_loopback = self.allow_loopback;
        let resolver = Arc::clone(&self.resolver);
        #[cfg(test)]
        let dialer = self.dialer.clone();
        let verify_ip_limiter = self.verify_ip_limiter.clone();

        Box::pin(async move {
            if dst.scheme_str() != Some("https") {
                return Err(OutboundConnectError::InvalidUri("scheme must be https"));
            }
            let raw_host = dst
                .host()
                .ok_or(OutboundConnectError::InvalidUri("missing host"))?;
            let host = raw_host
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(raw_host);
            let port = dst.port_u16().unwrap_or(443);

            let addrs = (resolver)(host, port)
                .await
                .map_err(OutboundConnectError::Dns)?;
            if addrs.is_empty() {
                return Err(OutboundConnectError::DnsEmpty);
            }
            // Reject the entire dial if any returned A/AAAA record is non-public.
            for addr in &addrs {
                if !is_allowed_ip(addr.ip(), allow_loopback) {
                    return Err(OutboundConnectError::DisallowedIp(addr.ip()));
                }
            }

            let verify_dialed = VERIFY_DIALED.try_with(Arc::clone).ok();
            let mut checked_prefixes = Vec::new();
            let mut last_err = None;
            let mut connected_tcp = None;
            for addr in addrs {
                if let (Some(limiter), Some(dialed)) = (&verify_ip_limiter, &verify_dialed) {
                    let prefix = ip_verify_prefix(addr.ip());
                    if !checked_prefixes.contains(&prefix) {
                        limiter
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .check_and_record(prefix)
                            .map_err(OutboundConnectError::RateLimited)?;
                        checked_prefixes.push(prefix);
                    }
                    dialed.store(true, Ordering::Release);
                }
                #[cfg(test)]
                let connect_res = match &dialer {
                    Some(d) => (d)(addr).await,
                    None => TcpStream::connect(addr).await,
                };
                #[cfg(not(test))]
                let connect_res = TcpStream::connect(addr).await;

                match connect_res {
                    Ok(stream) => {
                        let _ = stream.set_nodelay(true);
                        connected_tcp = Some((stream, addr.ip()));
                        break;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            let (tcp, peer_ip) = match connected_tcp {
                Some(pair) => pair,
                None => {
                    return Err(OutboundConnectError::Tcp(last_err.unwrap_or_else(|| {
                        io::Error::new(io::ErrorKind::NotConnected, "no reachable address")
                    })));
                }
            };
            let created_at = Instant::now();

            let server_name = ServerName::try_from(host.to_owned())
                .map_err(|_| OutboundConnectError::InvalidUri("invalid TLS server name"))?;
            let tls_stream = TlsConnector::from(tls_config)
                .connect(server_name, tcp)
                .await
                .map_err(OutboundConnectError::Tls)?;

            Ok(SafeHttpsStream {
                inner: TokioIo::new(tls_stream),
                created_at,
                peer_ip,
            })
        })
    }
}

/// Outbound Standard Webhooks client with anti-DNS-rebinding connection lifetime caps.
#[derive(Clone)]
pub struct OutboundClient {
    client: Client<SafeHttpsConnector, Full<Bytes>>,
    verify_ip_limiter: Arc<Mutex<IpVerifyLimiter>>,
    allow_loopback: bool,
    conn_max_lifetime: Duration,
}

impl OutboundClient {
    pub fn from_quotas(quotas: &QuotaConfig) -> Result<Self, String> {
        let connector = SafeHttpsConnector::new(quotas.allow_loopback_callbacks)?;
        Ok(Self::from_connector(
            connector,
            quotas.allow_loopback_callbacks,
            Duration::from_secs(quotas.conn_max_lifetime_secs),
        ))
    }

    pub fn from_connector(
        connector: SafeHttpsConnector,
        allow_loopback: bool,
        conn_max_lifetime: Duration,
    ) -> Self {
        let verify_ip_limiter = Arc::new(Mutex::new(IpVerifyLimiter::default()));
        let shared_connector = connector.with_verify_ip_limiter(Arc::clone(&verify_ip_limiter));
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(POOL_IDLE_TIMEOUT)
            .build(shared_connector);
        Self {
            client,
            verify_ip_limiter,
            allow_loopback,
            conn_max_lifetime,
        }
    }

    /// Perform synchronous callback endpoint verification challenge (spec §6.2).
    pub async fn verify_callback(
        &self,
        url: &str,
        subscription_id: &str,
        secret: &SecretString,
    ) -> Result<(), VerifyError> {
        let url = validate_callback_url(url, self.allow_loopback)
            .map_err(|_| VerifyError::Callback(CallbackErrorReason::ConnectionRefused))?;

        let challenge = random_hex(24)
            .map_err(|_| VerifyError::Callback(CallbackErrorReason::ChallengeFailed))?;
        let webhook_id = format!(
            "msg_verification_{}",
            random_hex(16)
                .map_err(|_| VerifyError::Callback(CallbackErrorReason::ChallengeFailed))?
        );
        let body = serde_json::to_vec(&VerificationRequest {
            kind: "verification",
            challenge: &challenge,
        })
        .map_err(|_| VerifyError::Callback(CallbackErrorReason::ChallengeFailed))?;

        let timestamp = unix_now();
        let signature = sign_webhook_v1(secret.expose(), &webhook_id, timestamp, &body)
            .map_err(|_| VerifyError::Callback(CallbackErrorReason::ChallengeFailed))?;

        let req = build_signed_request(
            &url,
            subscription_id,
            &webhook_id,
            timestamp,
            &signature,
            Bytes::from(body),
        )
        .map_err(|_| VerifyError::Callback(CallbackErrorReason::ConnectionRefused))?;

        let dialed = Arc::new(AtomicBool::new(false));
        let (status, resp_bytes, peer_ip, captured) = VERIFY_DIALED
            .scope(
                Arc::clone(&dialed),
                self.send_with_bounded_body(req, VERIFY_TIMEOUT, MAX_VERIFY_RESP_BYTES, true),
            )
            .await?;
        if !dialed.load(Ordering::Acquire)
            && let Some(ip) = peer_ip
            && let Err(msg) = self
                .verify_ip_limiter
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .check_and_record(ip_verify_prefix(ip))
        {
            if let Some(conn) = captured.connection_metadata().as_ref() {
                conn.poison();
            }
            return Err(VerifyError::RateLimited(msg.to_owned()));
        }

        if status.is_success() {
            let parsed: VerificationResponse = serde_json::from_slice(&resp_bytes)
                .map_err(|_| VerifyError::Callback(CallbackErrorReason::ChallengeFailed))?;
            if constant_time_bytes_eq(parsed.challenge.as_bytes(), challenge.as_bytes()) {
                Ok(())
            } else {
                Err(VerifyError::Callback(CallbackErrorReason::ChallengeFailed))
            }
        } else if status.is_client_error() {
            Err(VerifyError::Callback(CallbackErrorReason::Http4xx))
        } else if status.is_server_error() {
            Err(VerifyError::Callback(CallbackErrorReason::Http5xx))
        } else {
            Err(VerifyError::Callback(CallbackErrorReason::ChallengeFailed))
        }
    }

    /// Deliver a signed webhook event or control envelope (spec §6.4).
    pub async fn post_webhook(
        &self,
        url: &str,
        subscription_id: &str,
        webhook_id: &str,
        raw_body: &[u8],
        secret: &SecretString,
        prev_secret_if_active: Option<&SecretString>,
    ) -> DeliveryOutcome {
        let url = match validate_callback_url(url, self.allow_loopback) {
            Ok(url) => url,
            Err(_) => return DeliveryOutcome::Transient(CallbackErrorReason::ConnectionRefused),
        };

        let timestamp = unix_now();
        let sig_new = match sign_webhook_v1(secret.expose(), webhook_id, timestamp, raw_body) {
            Ok(s) => s,
            Err(_) => return DeliveryOutcome::Transient(CallbackErrorReason::ConnectionRefused),
        };
        let signature = match prev_secret_if_active {
            Some(prev) => match sign_webhook_v1(prev.expose(), webhook_id, timestamp, raw_body) {
                Ok(sig_old) => format!("{sig_old} {sig_new}"),
                Err(_) => {
                    return DeliveryOutcome::Transient(CallbackErrorReason::ConnectionRefused);
                }
            },
            None => sig_new,
        };

        let req = match build_signed_request(
            &url,
            subscription_id,
            webhook_id,
            timestamp,
            &signature,
            Bytes::copy_from_slice(raw_body),
        ) {
            Ok(r) => r,
            Err(_) => return DeliveryOutcome::Transient(CallbackErrorReason::ConnectionRefused),
        };

        match self
            .send_with_bounded_body(req, DELIVERY_TIMEOUT, MAX_DELIVERY_RESP_BYTES, false)
            .await
        {
            Ok((status, _, _, _)) => classify_delivery_status(status),
            Err(VerifyError::Callback(reason)) => DeliveryOutcome::Transient(reason),
            Err(VerifyError::RateLimited(_)) => {
                DeliveryOutcome::Transient(CallbackErrorReason::ConnectionRefused)
            }
        }
    }

    async fn send_with_bounded_body(
        &self,
        mut req: Request<Full<Bytes>>,
        timeout_dur: Duration,
        max_resp_bytes: usize,
        collect_body: bool,
    ) -> Result<(StatusCode, Vec<u8>, Option<IpAddr>, CaptureConnection), VerifyError> {
        let captured = capture_connection(&mut req);
        let fut = async {
            let res = self
                .client
                .request(req)
                .await
                .map_err(|e| classify_client_error(&e))?;
            let status = res.status();
            let meta = res.extensions().get::<ConnMeta>().copied();
            let created_at = meta.map(|m| m.created_at);
            let peer_ip = meta.map(|m| m.peer_ip);
            let poison_if_expired = || {
                if let Some(t0) = created_at
                    && t0.elapsed() >= self.conn_max_lifetime
                    && let Some(conn) = captured.connection_metadata().as_ref()
                {
                    conn.poison();
                }
            };
            // Check before draining the body so EOF cannot return an expired connection to the pool first.
            poison_if_expired();

            let mut body = res.into_body();
            let mut collected = Vec::new();
            let mut total = 0usize;
            let mut exceeded = false;

            while let Some(frame_res) = body.frame().await {
                let frame = frame_res.map_err(|e| classify_client_error(&e))?;
                if let Some(chunk) = frame.data_ref() {
                    total = total.saturating_add(chunk.len());
                    if total > max_resp_bytes {
                        exceeded = true;
                        break;
                    }
                    if collect_body {
                        collected.extend_from_slice(chunk);
                    }
                }
            }

            // Re-check after draining the body in case conn_max_lifetime elapsed mid-response.
            poison_if_expired();

            if exceeded && collect_body {
                return Err(VerifyError::Callback(CallbackErrorReason::ChallengeFailed));
            }
            Ok((status, collected, peer_ip))
        };

        match tokio::time::timeout(timeout_dur, fut).await {
            Ok(Ok((status, collected, peer_ip))) => Ok((status, collected, peer_ip, captured)),
            Ok(Err(err)) => Err(err),
            Err(_) => {
                if let Some(conn) = captured.connection_metadata().as_ref() {
                    conn.poison();
                }
                Err(VerifyError::Callback(CallbackErrorReason::Timeout))
            }
        }
    }
}

#[derive(Serialize)]
struct VerificationRequest<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    challenge: &'a str,
}

#[derive(Deserialize)]
struct VerificationResponse {
    challenge: String,
}

fn build_signed_request(
    url: &Url,
    subscription_id: &str,
    webhook_id: &str,
    timestamp: u64,
    signature: &str,
    body: Bytes,
) -> Result<Request<Full<Bytes>>, String> {
    let uri: Uri = url
        .as_str()
        .parse()
        .map_err(|e| format!("invalid URI: {e}"))?;
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )
        .header(
            "webhook-id",
            HeaderValue::from_str(webhook_id).map_err(|e| format!("invalid webhook-id: {e}"))?,
        )
        .header(
            "webhook-timestamp",
            HeaderValue::from_str(&timestamp.to_string())
                .map_err(|e| format!("invalid webhook-timestamp: {e}"))?,
        )
        .header(
            "webhook-signature",
            HeaderValue::from_str(signature)
                .map_err(|e| format!("invalid webhook-signature: {e}"))?,
        )
        .header(
            "X-MCP-Subscription-Id",
            HeaderValue::from_str(subscription_id)
                .map_err(|e| format!("invalid X-MCP-Subscription-Id: {e}"))?,
        );
    builder = builder.version(http::Version::HTTP_11);
    builder
        .body(Full::new(body))
        .map_err(|e| format!("failed to build request: {e}"))
}

fn classify_delivery_status(status: StatusCode) -> DeliveryOutcome {
    if status.is_success() {
        DeliveryOutcome::Success
    } else if matches!(status.as_u16(), 400 | 410 | 413 | 422) {
        DeliveryOutcome::PermanentDrop(CallbackErrorReason::Http4xx)
    } else if status.is_server_error() {
        DeliveryOutcome::Transient(CallbackErrorReason::Http5xx)
    } else {
        // 3xx redirects and retryable 4xx (401/403/404/408/429) are transient.
        DeliveryOutcome::Transient(CallbackErrorReason::Http4xx)
    }
}

fn classify_client_error(err: &(dyn Error + 'static)) -> VerifyError {
    let mut cur: Option<&(dyn Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(ce) = e.downcast_ref::<OutboundConnectError>() {
            return match ce {
                OutboundConnectError::Tls(_) => {
                    VerifyError::Callback(CallbackErrorReason::TlsError)
                }
                OutboundConnectError::RateLimited(msg) => {
                    VerifyError::RateLimited((*msg).to_owned())
                }
                _ => VerifyError::Callback(CallbackErrorReason::ConnectionRefused),
            };
        }
        if e.downcast_ref::<rustls::Error>().is_some() {
            return VerifyError::Callback(CallbackErrorReason::TlsError);
        }
        cur = e.source();
    }
    VerifyError::Callback(CallbackErrorReason::ConnectionRefused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STD;
    use hyper::Response;
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use rustls::ServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::atomic::AtomicUsize;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;
    use tokio_rustls::TlsAcceptor;

    fn test_secret(byte: u8) -> SecretString {
        SecretString::new(format!("whsec_{}", BASE64_STD.encode([byte; 32])))
    }

    struct CapturedRequest {
        headers: http::HeaderMap,
        body: Bytes,
    }

    struct TestTlsServer {
        addr: SocketAddr,
        roots: RootCertStore,
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl Drop for TestTlsServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn spawn_tls_server<F>(san: &str, responder: F) -> TestTlsServer
    where
        F: Fn(http::HeaderMap, Bytes) -> (StatusCode, Vec<u8>) + Send + Sync + 'static,
    {
        let ck = rcgen::generate_simple_self_signed(vec![san.to_owned()]).unwrap();
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
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_bg = Arc::clone(&requests);
        let responder = Arc::new(responder);

        let handle = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let requests_conn = Arc::clone(&requests_bg);
                let responder_conn = Arc::clone(&responder);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let io = TokioIo::new(tls);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let requests_req = Arc::clone(&requests_conn);
                        let responder_req = Arc::clone(&responder_conn);
                        async move {
                            let headers = req.headers().clone();
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            requests_req.lock().await.push(CapturedRequest {
                                headers: headers.clone(),
                                body: body.clone(),
                            });
                            let (status, resp_body) = (responder_req)(headers, body);
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(status)
                                    .header(http::header::CONTENT_TYPE, "application/json")
                                    .body(Full::new(Bytes::from(resp_body)))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });

        TestTlsServer {
            addr,
            roots,
            requests,
            handle,
        }
    }

    #[test]
    fn ip_classification_rejects_all_iana_non_global_and_allows_public() {
        let blocked = [
            "0.0.0.0",
            "0.255.255.255",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "127.1.2.3",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.254",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:100.64.0.1",
            "::ffff:169.254.169.254",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "64:ff9b::1.1.1.1",
            "100::1",
            "2001::1",
            "2001:db8::1",
            "2001:2::1",
            "2001:3::1",
            "2001:3:ffff::1",
            "2001:4:112::1",
            "2001:4:112:ffff::1",
            "2001:10::1",
            "2001:20::1",
            "2001:30::1",
            "2001:3f:ffff::1",
            "2002:c000:0201::1",
            "2620:4f:8000::1",
            "2620:4f:8000:ffff::1",
            "3fff::1",
            "3fff:0fff::1",
            "4000::1",
        ];
        for s in blocked {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_public_unicast_ip(ip), "expected {s} to be rejected");
        }

        let allowed = [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
            "::ffff:1.1.1.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "2001:4:113::1",
            "2001:40::1",
            "2620:4f:8001::1",
            "3fff:1000::1",
        ];
        for s in allowed {
            let ip: IpAddr = s.parse().unwrap();
            assert!(is_public_unicast_ip(ip), "expected {s} to be allowed");
        }
    }

    #[test]
    fn signed_request_uses_normalized_unicode_url() {
        let parsed = validate_callback_url("https://bücher.example/通知?q=你好", false).unwrap();
        let request = build_signed_request(
            &parsed,
            "sub_example",
            "msg_example",
            123,
            "v1,signature",
            Bytes::new(),
        )
        .unwrap();
        assert_eq!(request.uri().host(), Some("xn--bcher-kva.example"));
        assert_eq!(
            request.uri().path_and_query().unwrap().as_str(),
            "/%E9%80%9A%E7%9F%A5?q=%E4%BD%A0%E5%A5%BD"
        );
    }

    #[test]
    fn callback_url_validation_rules() {
        assert!(validate_callback_url("http://example.com/hook", false).is_err());
        assert!(validate_callback_url("https://user:pass@example.com/hook", false).is_err());
        assert!(validate_callback_url("https://example.com/hook#frag", false).is_err());
        assert!(validate_callback_url("https://127.0.0.1/hook", false).is_err());
        assert!(validate_callback_url("https://[::ffff:127.0.0.1]/hook", false).is_err());
        assert!(validate_callback_url("https://100.64.0.1/hook", false).is_err());

        assert!(validate_callback_url("https://127.0.0.1/hook", true).is_ok());
        assert!(validate_callback_url("https://1.1.1.1/hook", false).is_ok());
        assert!(validate_callback_url("https://hooks.example.com/cb?k=v", false).is_ok());
    }

    #[tokio::test]
    async fn mixed_public_and_private_dns_records_are_rejected_before_dial() {
        let resolver: DnsResolver = Arc::new(|_host, port| {
            Box::pin(async move {
                Ok(vec![
                    SocketAddr::new("1.1.1.1".parse().unwrap(), port),
                    SocketAddr::new("10.0.0.1".parse().unwrap(), port),
                ])
            })
        });
        let connector =
            SafeHttpsConnector::with_roots_and_resolver(RootCertStore::empty(), false, resolver)
                .unwrap();
        let client = OutboundClient::from_connector(connector, false, Duration::from_secs(60));
        let outcome = client
            .post_webhook(
                "https://mixed.example.test/hook",
                "sub_0123",
                "msg_1",
                b"{}",
                &test_secret(1),
                None,
            )
            .await;
        assert_eq!(
            outcome,
            DeliveryOutcome::Transient(CallbackErrorReason::ConnectionRefused)
        );
    }

    #[tokio::test]
    async fn verify_callback_checks_signature_headers_and_challenge() {
        let server = spawn_tls_server("hook.example.test", |_headers, body| {
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["type"], "verification");
            let ch = v["challenge"].as_str().unwrap();
            (
                StatusCode::OK,
                serde_json::to_vec(&serde_json::json!({ "challenge": ch })).unwrap(),
            )
        })
        .await;

        let addr = server.addr;
        let resolver: DnsResolver = Arc::new(move |_, _| Box::pin(async move { Ok(vec![addr]) }));
        let connector =
            SafeHttpsConnector::with_roots_and_resolver(server.roots.clone(), true, resolver)
                .unwrap();
        let client = OutboundClient::from_connector(connector, true, Duration::from_secs(60));
        let secret = test_secret(42);
        let url = format!("https://hook.example.test:{}/cb", addr.port());

        client
            .verify_callback(&url, "sub_abcdef", &secret)
            .await
            .unwrap();

        let reqs = server.requests.lock().await;
        assert_eq!(reqs.len(), 1);
        let r = &reqs[0];
        assert_eq!(r.headers["content-type"], "application/json");
        assert_eq!(r.headers["x-mcp-subscription-id"], "sub_abcdef");
        let wid = r.headers["webhook-id"].to_str().unwrap();
        assert!(wid.starts_with("msg_verification_"));
        let ts: u64 = r.headers["webhook-timestamp"]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let expected_sig = sign_webhook_v1(secret.expose(), wid, ts, &r.body).unwrap();
        assert_eq!(
            r.headers["webhook-signature"].to_str().unwrap(),
            expected_sig
        );
    }

    #[tokio::test]
    async fn verify_callback_rejects_wrong_challenge_and_oversized_response() {
        let server = spawn_tls_server("hook.example.test", |headers, _| {
            if headers["x-mcp-subscription-id"] == "sub_big" {
                (StatusCode::OK, vec![b'a'; MAX_VERIFY_RESP_BYTES + 128])
            } else {
                (StatusCode::OK, br#"{"challenge":"wrong-nonce"}"#.to_vec())
            }
        })
        .await;

        let addr = server.addr;
        let resolver: DnsResolver = Arc::new(move |_, _| Box::pin(async move { Ok(vec![addr]) }));
        let connector =
            SafeHttpsConnector::with_roots_and_resolver(server.roots.clone(), true, resolver)
                .unwrap();
        let client = OutboundClient::from_connector(connector, true, Duration::from_secs(60));
        let url = format!("https://hook.example.test:{}/cb", addr.port());

        assert_eq!(
            client
                .verify_callback(&url, "sub_wrong", &test_secret(1))
                .await,
            Err(VerifyError::Callback(CallbackErrorReason::ChallengeFailed))
        );
        assert_eq!(
            client
                .verify_callback(&url, "sub_big", &test_secret(1))
                .await,
            Err(VerifyError::Callback(CallbackErrorReason::ChallengeFailed))
        );
    }

    #[tokio::test]
    async fn post_webhook_dual_secret_and_status_classification() {
        let server = spawn_tls_server("hook.example.test", |headers, _| {
            let status = match headers["webhook-id"].to_str().unwrap() {
                "msg_ok" => StatusCode::NO_CONTENT,
                "msg_302" => StatusCode::FOUND,
                "msg_400" => StatusCode::BAD_REQUEST,
                "msg_410" => StatusCode::GONE,
                "msg_413" => StatusCode::PAYLOAD_TOO_LARGE,
                "msg_422" => StatusCode::UNPROCESSABLE_ENTITY,
                "msg_429" => StatusCode::TOO_MANY_REQUESTS,
                "msg_500" => StatusCode::INTERNAL_SERVER_ERROR,
                _ => StatusCode::OK,
            };
            (status, Vec::new())
        })
        .await;

        let addr = server.addr;
        let resolver: DnsResolver = Arc::new(move |_, _| Box::pin(async move { Ok(vec![addr]) }));
        let connector =
            SafeHttpsConnector::with_roots_and_resolver(server.roots.clone(), true, resolver)
                .unwrap();
        let client = OutboundClient::from_connector(connector, true, Duration::from_secs(60));
        let url = format!("https://hook.example.test:{}/cb", addr.port());
        let old_secret = test_secret(11);
        let new_secret = test_secret(22);
        let payload = br#"{"eventId":"evt_1","name":"demo","data":{}}"#;

        assert_eq!(
            client
                .post_webhook(
                    &url,
                    "sub_1",
                    "msg_ok",
                    payload,
                    &new_secret,
                    Some(&old_secret),
                )
                .await,
            DeliveryOutcome::Success
        );

        // Verify dual-secret header order: v1,<sig_old> v1,<sig_new>.
        {
            let reqs = server.requests.lock().await;
            let r = &reqs[0];
            let ts: u64 = r.headers["webhook-timestamp"]
                .to_str()
                .unwrap()
                .parse()
                .unwrap();
            let sig_old = sign_webhook_v1(old_secret.expose(), "msg_ok", ts, payload).unwrap();
            let sig_new = sign_webhook_v1(new_secret.expose(), "msg_ok", ts, payload).unwrap();
            assert_eq!(
                r.headers["webhook-signature"].to_str().unwrap(),
                format!("{sig_old} {sig_new}")
            );
        }

        assert_eq!(
            client
                .post_webhook(&url, "sub_1", "msg_302", payload, &new_secret, None)
                .await,
            DeliveryOutcome::Transient(CallbackErrorReason::Http4xx)
        );
        for id in ["msg_400", "msg_410", "msg_413", "msg_422"] {
            assert_eq!(
                client
                    .post_webhook(&url, "sub_1", id, payload, &new_secret, None)
                    .await,
                DeliveryOutcome::PermanentDrop(CallbackErrorReason::Http4xx),
                "expected permanent drop for {id}"
            );
        }
        assert_eq!(
            client
                .post_webhook(&url, "sub_1", "msg_429", payload, &new_secret, None)
                .await,
            DeliveryOutcome::Transient(CallbackErrorReason::Http4xx)
        );
        assert_eq!(
            client
                .post_webhook(&url, "sub_1", "msg_500", payload, &new_secret, None)
                .await,
            DeliveryOutcome::Transient(CallbackErrorReason::Http5xx)
        );
    }

    #[tokio::test]
    async fn untrusted_tls_certificate_maps_to_tls_error() {
        let server =
            spawn_tls_server("hook.example.test", |_, _| (StatusCode::OK, Vec::new())).await;
        let addr = server.addr;
        let resolver: DnsResolver = Arc::new(move |_, _| Box::pin(async move { Ok(vec![addr]) }));
        // Empty root store forces TLS verification failure.
        let connector =
            SafeHttpsConnector::with_roots_and_resolver(RootCertStore::empty(), true, resolver)
                .unwrap();
        let client = OutboundClient::from_connector(connector, true, Duration::from_secs(60));
        let url = format!("https://hook.example.test:{}/cb", addr.port());

        assert_eq!(
            client
                .verify_callback(&url, "sub_tls", &test_secret(9))
                .await,
            Err(VerifyError::Callback(CallbackErrorReason::TlsError))
        );
    }

    #[tokio::test]
    async fn verify_callback_rate_limits_resolved_ipv4_and_ipv6_subnets() {
        let server = spawn_tls_server("hook.example.test", |_headers, body| {
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let ch = v["challenge"].as_str().unwrap();
            (
                StatusCode::OK,
                serde_json::to_vec(&serde_json::json!({ "challenge": ch })).unwrap(),
            )
        })
        .await;
        let addr = server.addr;
        let dns_calls = Arc::new(AtomicUsize::new(0));
        let dns_calls_bg = Arc::clone(&dns_calls);
        let resolver: DnsResolver = Arc::new(move |_, _| {
            dns_calls_bg.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(vec![addr]) })
        });
        let connector =
            SafeHttpsConnector::with_roots_and_resolver(server.roots.clone(), true, resolver)
                .unwrap();
        let client = OutboundClient::from_connector(connector, true, Duration::from_secs(60));
        let url = format!("https://hook.example.test:{}/cb", addr.port());
        let secret = test_secret(5);

        // First call dials via SafeHttpsConnector; remaining 19 reuse the Keep-Alive pool socket
        // and charge ConnMeta.peer_ip via !dialed without double-counting the initial dial.
        for i in 0..VERIFY_IP_RATE_LIMIT {
            client
                .verify_callback(&url, &format!("sub_{i}"), &secret)
                .await
                .unwrap();
        }
        assert_eq!(dns_calls.load(Ordering::SeqCst), 1);

        assert!(matches!(
            client.verify_callback(&url, "sub_overflow", &secret).await,
            Err(VerifyError::RateLimited(_))
        ));
        let reqs_after_first_overflow = server.requests.lock().await.len();
        assert_eq!(reqs_after_first_overflow, VERIFY_IP_RATE_LIMIT + 1);

        // Pooled connection was poisoned on rate-limit overflow; subsequent call blocks pre-connect.
        assert!(matches!(
            client
                .verify_callback(&url, "sub_overflow_2", &secret)
                .await,
            Err(VerifyError::RateLimited(_))
        ));
        assert_eq!(dns_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            server.requests.lock().await.len(),
            reqs_after_first_overflow
        );

        // Different interface IDs in the same IPv6 /64 share one bucket.
        let mut limiter = IpVerifyLimiter::default();
        for host_id in 0..VERIFY_IP_RATE_LIMIT {
            let ip: IpAddr = format!("2606:4700:4700:1111::{host_id:x}").parse().unwrap();
            limiter.check_and_record(ip_verify_prefix(ip)).unwrap();
        }
        let same_subnet: IpAddr = "2606:4700:4700:1111::ffff".parse().unwrap();
        assert!(
            limiter
                .check_and_record(ip_verify_prefix(same_subnet))
                .is_err()
        );
        let other_subnet: IpAddr = "2606:4700:4700:1112::1".parse().unwrap();
        assert!(
            limiter
                .check_and_record(ip_verify_prefix(other_subnet))
                .is_ok()
        );
    }

    #[tokio::test]
    async fn verify_callback_rate_limits_multi_record_fallback_and_dns_rebinding() {
        let echo_challenge = |_headers: http::HeaderMap, body: Bytes| {
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let ch = v["challenge"].as_str().unwrap();
            (
                StatusCode::OK,
                serde_json::to_vec(&serde_json::json!({ "challenge": ch })).unwrap(),
            )
        };
        let victim = spawn_tls_server("*.evil.test", echo_challenge).await;
        let real_victim_addr = victim.addr;
        let virt_victim_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10)),
            real_victim_addr.port(),
        );

        // 1. Multi-A fallback: [unreachable_distinct_ip, victim_ip] must charge victim_ip on fallback.
        let resolver_fallback: DnsResolver = Arc::new(move |host, _port| {
            let idx: u8 = host
                .strip_prefix('h')
                .and_then(|s| s.strip_suffix(".evil.test"))
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let unreachable = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 1, idx.saturating_add(1))),
                9,
            );
            Box::pin(async move { Ok(vec![unreachable, virt_victim_addr]) })
        });
        let dialer_fallback: TcpDialer = Arc::new(move |target| {
            Box::pin(async move {
                if target == virt_victim_addr {
                    TcpStream::connect(real_victim_addr).await
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "simulated unreachable address",
                    ))
                }
            })
        });
        let connector = SafeHttpsConnector::with_roots_and_resolver(
            victim.roots.clone(),
            true,
            resolver_fallback,
        )
        .unwrap()
        .with_dialer(dialer_fallback);
        let client = OutboundClient::from_connector(connector, true, Duration::from_secs(60));
        let secret = test_secret(7);

        for i in 0..VERIFY_IP_RATE_LIMIT {
            let url = format!("https://h{i}.evil.test:{}/cb", real_victim_addr.port());
            client
                .verify_callback(&url, &format!("sub_fb_{i}"), &secret)
                .await
                .unwrap();
        }
        assert_eq!(victim.requests.lock().await.len(), VERIFY_IP_RATE_LIMIT);

        let overflow_url = format!(
            "https://h{VERIFY_IP_RATE_LIMIT}.evil.test:{}/cb",
            real_victim_addr.port()
        );
        assert!(matches!(
            client
                .verify_callback(&overflow_url, "sub_fb_overflow", &secret)
                .await,
            Err(VerifyError::RateLimited(_))
        ));
        assert_eq!(victim.requests.lock().await.len(), VERIFY_IP_RATE_LIMIT);

        // 2. DNS rebinding: rebind.evil.test switches from virtual 127.0.0.2 to saturated 127.0.0.3
        // while all real listeners stay bound on portable 127.0.0.1:0.
        let srv_old_and_rebound = spawn_tls_server("*.evil.test", echo_challenge).await;
        let real_srv_addr = srv_old_and_rebound.addr;
        let virt_old = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            real_srv_addr.port(),
        );
        let virt_saturated = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)),
            real_srv_addr.port(),
        );

        let rebind_step = Arc::new(AtomicUsize::new(0));
        let rebind_step_bg = Arc::clone(&rebind_step);
        let resolver_rebind: DnsResolver = Arc::new(move |host, _port| {
            let is_rebind = host == "rebind.evil.test";
            let step = rebind_step_bg.load(Ordering::SeqCst);
            Box::pin(async move {
                if is_rebind && step == 0 {
                    Ok(vec![virt_old])
                } else {
                    Ok(vec![virt_saturated])
                }
            })
        });
        let dialer_rebind: TcpDialer =
            Arc::new(move |_target| Box::pin(TcpStream::connect(real_srv_addr)));

        let connector2 = SafeHttpsConnector::with_roots_and_resolver(
            srv_old_and_rebound.roots.clone(),
            true,
            resolver_rebind,
        )
        .unwrap()
        .with_dialer(dialer_rebind);
        // Zero conn_max_lifetime forces fresh DNS dial on each call instead of reusing pooled socket.
        let client2 = OutboundClient::from_connector(connector2, true, Duration::ZERO);

        client2
            .verify_callback("https://rebind.evil.test/cb", "sub_rb_0", &secret)
            .await
            .unwrap();
        for i in 0..VERIFY_IP_RATE_LIMIT {
            client2
                .verify_callback("https://saturate.evil.test/cb", &format!("s_{i}"), &secret)
                .await
                .unwrap();
        }
        let before_rebind = srv_old_and_rebound.requests.lock().await.len();
        rebind_step.store(1, Ordering::SeqCst);
        assert!(matches!(
            client2
                .verify_callback("https://rebind.evil.test/cb", "sub_rb_rebound", &secret)
                .await,
            Err(VerifyError::RateLimited(_))
        ));
        assert_eq!(
            srv_old_and_rebound.requests.lock().await.len(),
            before_rebind
        );
    }

    #[tokio::test]
    async fn conn_max_lifetime_poisons_pooled_conn_and_blocks_rebound_private_ip() {
        let server =
            spawn_tls_server("rebind.example.test", |_, _| (StatusCode::OK, Vec::new())).await;
        let addr = server.addr;
        let dns_calls = Arc::new(AtomicUsize::new(0));
        let dns_calls_bg = Arc::clone(&dns_calls);

        let resolver: DnsResolver = Arc::new(move |_, port| {
            let n = dns_calls_bg.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if n == 0 {
                    Ok(vec![addr])
                } else {
                    // Simulate DNS rebinding to a private RFC1918 IP on the second lookup.
                    Ok(vec![SocketAddr::new("10.0.0.42".parse().unwrap(), port)])
                }
            })
        });

        let connector =
            SafeHttpsConnector::with_roots_and_resolver(server.roots.clone(), true, resolver)
                .unwrap();
        let client = OutboundClient::from_connector(connector, true, Duration::from_millis(250));
        let url = format!("https://rebind.example.test:{}/cb", addr.port());
        let secret = test_secret(3);

        // Request 1 establishes the pooled connection (DNS lookup #1).
        assert_eq!(
            client
                .post_webhook(&url, "sub_r", "msg_1", b"{}", &secret, None)
                .await,
            DeliveryOutcome::Success
        );
        assert_eq!(dns_calls.load(Ordering::SeqCst), 1);

        // Request 2 within conn_max_lifetime reuses the pooled connection without re-resolving DNS.
        assert_eq!(
            client
                .post_webhook(&url, "sub_r", "msg_2", b"{}", &secret, None)
                .await,
            DeliveryOutcome::Success
        );
        assert_eq!(dns_calls.load(Ordering::SeqCst), 1);

        // Wait past conn_max_lifetime; request 3 reuses the pooled connection and poisons it.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            client
                .post_webhook(&url, "sub_r", "msg_3", b"{}", &secret, None)
                .await,
            DeliveryOutcome::Success
        );
        assert_eq!(dns_calls.load(Ordering::SeqCst), 1);

        // Request 4 must re-resolve DNS (lookup #2) and reject the rebound private IP.
        assert_eq!(
            client
                .post_webhook(&url, "sub_r", "msg_4", b"{}", &secret, None)
                .await,
            DeliveryOutcome::Transient(CallbackErrorReason::ConnectionRefused)
        );
        assert_eq!(dns_calls.load(Ordering::SeqCst), 2);
    }
}
