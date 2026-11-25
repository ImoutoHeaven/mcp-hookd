//! Shared protocol types, quotas, memory budgets, crypto primitives, and canonical JSON.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD as BASE64_URL};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const DEFAULT_TTL_SECS: u64 = 1800;
pub const MIN_TTL_SECS: u64 = 60;
pub const MAX_TTL_SECS_DEFAULT: u64 = 3600;
pub const MAX_TTL_SECS_UPPER: u64 = 86_400;

pub const MAX_SUBSCRIPTIONS: usize = 256;
pub const MAX_PER_PRINCIPAL: usize = 64;
pub const MAX_OUTBOX_PER_SUB: usize = 64;
pub const MAX_IN_FLIGHT_PER_SUB: usize = 1;
pub const MAX_GLOBAL_DELIVERIES: usize = 64;
pub const MAX_UPSTREAM_STREAMS: usize = 16;
pub const MAX_DEDUP_ENTRIES: usize = 16_384;
pub const DEDUP_RETENTION_SECS: u64 = 3600;
pub const MAX_VERIFIED_ENDPOINTS: usize = 1024;
pub const VERIFIED_RETENTION_SECS: u64 = 3600;
pub const DUAL_SECRET_WINDOW_SECS: u64 = 300;
pub const MAX_LEGACY_SESSIONS: usize = 1024;
pub const LEGACY_SESSION_IDLE_SECS: u64 = 3600;

pub const OUTBOX_BYTE_BUDGET: usize = 64 * 1024 * 1024;
pub const PROXY_BYTE_BUDGET: usize = 64 * 1024 * 1024;
pub const CONTROL_BYTE_BUDGET: usize = 8 * 1024 * 1024;
pub const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_INGEST_BODY_BYTES: usize = 256 * 1024;
pub const MAX_WEBHOOK_PAYLOAD_BYTES: usize = 256 * 1024;
pub const MAX_HANDSHAKE_BODY_BYTES: usize = 1024 * 1024;
pub const MAX_PING_BODY_BYTES: usize = 4 * 1024;
pub const MAX_VERIFY_RESP_BYTES: usize = 16 * 1024;
pub const MAX_DELIVERY_RESP_BYTES: usize = 4 * 1024;
pub const CONN_MAX_LIFETIME_SECS: u64 = 60;
pub const DRAIN_TIMEOUT_SECS: u64 = 10;

pub const PROTOCOL_VERSION_MODERN: &str = "2026-07-28";
pub const LEGACY_PROTOCOL_VERSIONS: &[&str] =
    &["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];
pub const LATEST_LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";

static MONOTONIC_UNIX_FLOOR: AtomicU64 = AtomicU64::new(0);

pub fn unix_now() -> u64 {
    let raw = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    MONOTONIC_UNIX_FLOOR
        .fetch_max(raw, Ordering::Relaxed)
        .max(raw)
}

/// Format the current UTC wall-clock time as an RFC 3339 timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn utc_rfc3339_now() -> String {
    format_utc_rfc3339(unix_now())
}

/// Format a Unix timestamp in seconds as UTC RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn format_utc_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    // Howard Hinnant's civil-from-days algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Zeroizing secret string whose Debug/Display output is always redacted.
#[derive(Clone, PartialEq, Eq, Hash, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Serialize for SecretString {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(SecretString)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Sep3415,
    Chatgpt,
}

impl Profile {
    pub fn forbidden_code(self) -> i64 {
        match self {
            Self::Sep3415 => -32024,
            Self::Chatgpt => -32012,
        }
    }

    pub fn callback_error_code(self) -> i64 {
        match self {
            Self::Sep3415 => -32027,
            Self::Chatgpt => -32015,
        }
    }

    pub fn not_found_code(self) -> i64 {
        match self {
            Self::Sep3415 => -32023,
            Self::Chatgpt => -32602,
        }
    }

    pub fn resource_exhausted_code(self) -> i64 {
        match self {
            Self::Sep3415 => -32025,
            Self::Chatgpt => -32602,
        }
    }

    pub fn unsupported_code(self) -> i64 {
        match self {
            Self::Sep3415 => -32026,
            Self::Chatgpt => -32602,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackErrorReason {
    ChallengeFailed,
    Timeout,
    ConnectionRefused,
    TlsError,
    Http4xx,
    Http5xx,
}

impl CallbackErrorReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChallengeFailed => "challenge_failed",
            Self::Timeout => "timeout",
            Self::ConnectionRefused => "connection_refused",
            Self::TlsError => "tls_error",
            Self::Http4xx => "http_4xx",
            Self::Http5xx => "http_5xx",
        }
    }
}

/// Configurable internal quotas; production uses defaults, tests may inject smaller limits.
#[derive(Clone, Debug)]
pub struct QuotaConfig {
    pub max_subscriptions: usize,
    pub max_per_principal: usize,
    pub max_outbox_per_sub: usize,
    pub max_global_deliveries: usize,
    pub max_upstream_streams: usize,
    pub max_dedup_entries: usize,
    pub dedup_retention_secs: u64,
    pub max_verified_endpoints: usize,
    pub verified_retention_secs: u64,
    pub outbox_byte_budget: usize,
    pub proxy_byte_budget: usize,
    pub control_byte_budget: usize,
    pub dual_secret_window_secs: u64,
    pub conn_max_lifetime_secs: u64,
    pub drain_timeout_secs: u64,
    pub retry_base_ms: u64,
    pub suspend_failure_count: u32,
    pub suspend_min_duration_secs: u64,
    pub allow_loopback_callbacks: bool,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            max_subscriptions: MAX_SUBSCRIPTIONS,
            max_per_principal: MAX_PER_PRINCIPAL,
            max_outbox_per_sub: MAX_OUTBOX_PER_SUB,
            max_global_deliveries: MAX_GLOBAL_DELIVERIES,
            max_upstream_streams: MAX_UPSTREAM_STREAMS,
            max_dedup_entries: MAX_DEDUP_ENTRIES,
            dedup_retention_secs: DEDUP_RETENTION_SECS,
            max_verified_endpoints: MAX_VERIFIED_ENDPOINTS,
            verified_retention_secs: VERIFIED_RETENTION_SECS,
            outbox_byte_budget: OUTBOX_BYTE_BUDGET,
            proxy_byte_budget: PROXY_BYTE_BUDGET,
            control_byte_budget: CONTROL_BYTE_BUDGET,
            dual_secret_window_secs: DUAL_SECRET_WINDOW_SECS,
            conn_max_lifetime_secs: CONN_MAX_LIFETIME_SECS,
            drain_timeout_secs: DRAIN_TIMEOUT_SECS,
            retry_base_ms: 1000,
            suspend_failure_count: 12,
            suspend_min_duration_secs: 180,
            allow_loopback_callbacks: false,
        }
    }
}

/// Atomic byte-budget pool for isolating outbox, proxy, and control memory.
#[derive(Debug)]
pub struct ByteBudget {
    limit: usize,
    used: AtomicUsize,
}

#[derive(Debug)]
pub struct ByteLease {
    budget: Arc<ByteBudget>,
    bytes: usize,
}

impl ByteBudget {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
        })
    }

    pub fn try_acquire(self: &Arc<Self>, bytes: usize) -> Option<ByteLease> {
        if bytes == 0 {
            return Some(ByteLease {
                budget: Arc::clone(self),
                bytes: 0,
            });
        }
        let mut cur = self.used.load(Ordering::Acquire);
        loop {
            let next = cur.checked_add(bytes)?;
            if next > self.limit {
                return None;
            }
            match self
                .used
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    return Some(ByteLease {
                        budget: Arc::clone(self),
                        bytes,
                    });
                }
                Err(actual) => cur = actual,
            }
        }
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    pub fn limit(&self) -> usize {
        self.limit
    }
}

impl ByteLease {
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn grow(&mut self, additional: usize) -> bool {
        if additional == 0 {
            return true;
        }
        let mut cur = self.budget.used.load(Ordering::Acquire);
        loop {
            let Some(next) = cur.checked_add(additional) else {
                return false;
            };
            if next > self.budget.limit {
                return false;
            }
            match self.budget.used.compare_exchange_weak(
                cur,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.bytes += additional;
                    return true;
                }
                Err(actual) => cur = actual,
            }
        }
    }
}

impl Drop for ByteLease {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }
}

/// Three isolated memory pools per spec §3.
#[derive(Clone, Debug)]
pub struct MemoryPools {
    pub outbox: Arc<ByteBudget>,
    pub proxy: Arc<ByteBudget>,
    pub control: Arc<ByteBudget>,
}

impl MemoryPools {
    pub fn from_quotas(quotas: &QuotaConfig) -> Self {
        Self {
            outbox: ByteBudget::new(quotas.outbox_byte_budget),
            proxy: ByteBudget::new(quotas.proxy_byte_budget),
            control: ByteBudget::new(quotas.control_byte_budget),
        }
    }
}

/// Composite key uniquely identifying a webhook subscription.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionKey {
    pub principal: String,
    pub url: String,
    pub event_name: String,
    pub canonical_arguments: String,
}

impl SubscriptionKey {
    pub fn new(
        principal: impl Into<String>,
        url: impl Into<String>,
        event_name: impl Into<String>,
        arguments: &Map<String, Value>,
    ) -> Result<Self, String> {
        let arguments = Value::Object(arguments.clone());
        require_exact_jcs_integers(&arguments)?;
        let canonical_arguments = canonical_json(&arguments)?;
        Ok(Self {
            principal: principal.into(),
            url: url.into(),
            event_name: event_name.into(),
            canonical_arguments,
        })
    }

    pub fn subscription_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.principal.as_bytes());
        hasher.update([0]);
        hasher.update(self.url.as_bytes());
        hasher.update([0]);
        hasher.update(self.event_name.as_bytes());
        hasher.update([0]);
        hasher.update(self.canonical_arguments.as_bytes());
        let digest = hasher.finalize();
        format!("sub_{}", hex_encode(&digest[..16]))
    }
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&sha256_bytes(data))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Constant-time equality over SHA-256 digests of two byte slices.
pub fn constant_time_token_eq(a: &[u8], b: &[u8]) -> bool {
    let da = sha256_bytes(a);
    let db = sha256_bytes(b);
    bool::from(da.ct_eq(&db))
}

/// Constant-time equality for equal-length or arbitrary byte slices.
pub fn constant_time_bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

/// RFC 2104 HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = sha256_bytes(key);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut o_key_pad = [0x5cu8; BLOCK_SIZE];
    let mut i_key_pad = [0x36u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        o_key_pad[i] ^= key_block[i];
        i_key_pad[i] ^= key_block[i];
    }
    key_block.zeroize();

    let mut inner = Sha256::new();
    inner.update(i_key_pad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(o_key_pad);
    outer.update(inner_hash);
    let out: [u8; 32] = outer.finalize().into();
    o_key_pad.zeroize();
    i_key_pad.zeroize();
    out
}

/// Generate `n` random bytes using the OS CSPRNG.
pub fn random_bytes(n: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).map_err(|e| format!("CSPRNG failure: {e}"))?;
    Ok(buf)
}

pub fn random_hex(num_bytes: usize) -> Result<String, String> {
    Ok(hex_encode(&random_bytes(num_bytes)?))
}

pub fn random_base64url(num_bytes: usize) -> Result<String, String> {
    Ok(BASE64_URL.encode(random_bytes(num_bytes)?))
}

/// Validate a `whsec_<base64>` secret and return the decoded raw key bytes (24..=64 bytes).
pub fn decode_whsec(secret: &str) -> Result<Vec<u8>, String> {
    let Some(b64) = secret.strip_prefix("whsec_") else {
        return Err("delivery.secret must start with 'whsec_'".into());
    };
    let decoded = BASE64_STD.decode(b64).map_err(|_| {
        "delivery.secret must contain valid standard base64 after 'whsec_'".to_string()
    })?;
    if !(24..=64).contains(&decoded.len()) {
        return Err(format!(
            "delivery.secret decoded length must be 24..=64 bytes, got {}",
            decoded.len()
        ));
    }
    Ok(decoded)
}

/// Sign a Standard Webhooks message (`HMAC-SHA256(key, "{webhook_id}.{timestamp}.{raw_body}")`).
pub fn sign_webhook_v1(
    secret: &str,
    webhook_id: &str,
    timestamp: u64,
    raw_body: &[u8],
) -> Result<String, String> {
    let mut key = decode_whsec(secret)?;
    let mut input = Vec::with_capacity(webhook_id.len() + 24 + raw_body.len());
    input.extend_from_slice(webhook_id.as_bytes());
    input.push(b'.');
    input.extend_from_slice(timestamp.to_string().as_bytes());
    input.push(b'.');
    input.extend_from_slice(raw_body);
    let mac = hmac_sha256(&key, &input);
    key.zeroize();
    Ok(format!("v1,{}", BASE64_STD.encode(mac)))
}

/// Validate an `eventId` against `^[A-Za-z0-9_-]{1,128}$`.
pub fn is_valid_event_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Deterministic eventId normalization for `emit` when raw_id violates `^[A-Za-z0-9_-]{1,128}$`.
pub fn normalize_emit_event_id(event_name: &str, raw_id: &str) -> String {
    if is_valid_event_id(raw_id) {
        return raw_id.to_owned();
    }
    let mut hasher = Sha256::new();
    hasher.update(event_name.as_bytes());
    hasher.update([0]);
    hasher.update(raw_id.as_bytes());
    let digest = hasher.finalize();
    format!("evt_{}", hex_encode(&digest[..12]))
}

/// RFC 8785 (JCS) canonical JSON serialization for deterministic subscription keys.
pub fn canonical_json(value: &Value) -> Result<String, String> {
    serde_json_canonicalizer::to_string(value)
        .map_err(|error| format!("cannot canonicalize subscription arguments: {error}"))
}

fn require_exact_jcs_integers(value: &Value) -> Result<(), String> {
    match value {
        Value::Number(number) => {
            // JCS uses binary64; reject integer rounding before it can merge subscription keys.
            let exact = if let Some(value) = number.as_i64() {
                (value as f64) as i128 == i128::from(value)
            } else if let Some(value) = number.as_u64() {
                (value as f64) as u128 == u128::from(value)
            } else {
                true
            };
            if !exact {
                return Err(
                    "subscription argument integer is not exactly representable as IEEE 754 binary64; use a string"
                        .into(),
                );
            }
        }
        Value::Array(values) => {
            for value in values {
                require_exact_jcs_integers(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                require_exact_jcs_integers(value)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hmac_sha256_matches_rfc4231_case2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex_encode(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn canonical_json_uses_ecmascript_number_formatting() {
        let value: Value = serde_json::from_str(
            "[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001,1e18,1e-6]",
        )
        .unwrap();
        assert_eq!(
            canonical_json(&value).unwrap(),
            "[333333333.3333333,1e+30,4.5,0.002,1e-27,1000000000000000000,0.000001]"
        );
        let key = |value| {
            SubscriptionKey::new(
                "principal",
                "https://example.com/hook",
                "build",
                &Map::from_iter([("n".into(), value)]),
            )
        };
        assert_eq!(
            key(json!(1_000_000_000_000_000_000u64)).unwrap(),
            key(json!(1e18)).unwrap()
        );
        assert_eq!(
            key(json!(9_223_372_036_854_775_808u64))
                .unwrap()
                .canonical_arguments,
            r#"{"n":9223372036854776000}"#
        );
        for value in [
            json!(9_007_199_254_740_992u64),
            json!(9_223_372_036_854_775_808u64),
            json!(-9_223_372_036_854_775_808i64),
            json!(18_446_744_073_709_549_568u64),
        ] {
            assert!(key(value).is_ok());
        }
        for value in [
            json!(9_007_199_254_740_993u64),
            json!(u64::MAX),
            json!(i64::MAX),
            json!({"nested": [i64::MIN + 1]}),
        ] {
            assert!(key(value).is_err());
        }
    }

    #[test]
    fn canonical_json_sorts_keys_by_utf16_and_normalizes_numbers() {
        let v = json!({"b": 1, "a": [true, null, "x"], "c": -0.0});
        assert_eq!(
            canonical_json(&v).unwrap(),
            r#"{"a":[true,null,"x"],"b":1,"c":0}"#
        );
        assert_eq!(
            canonical_json(&json!({"\u{e000}": 1, "\u{1f600}": 2})).unwrap(),
            "{\"\u{1f600}\":2,\"\u{e000}\":1}"
        );
    }

    #[test]
    fn whsec_validation_enforces_prefix_and_length() {
        let valid = format!("whsec_{}", BASE64_STD.encode([7u8; 32]));
        assert_eq!(decode_whsec(&valid).unwrap().len(), 32);
        let short = format!("whsec_{}", BASE64_STD.encode([7u8; 16]));
        assert!(decode_whsec(&short).is_err());
        let long = format!("whsec_{}", BASE64_STD.encode([7u8; 65]));
        assert!(decode_whsec(&long).is_err());
        assert!(decode_whsec("bad_prefix").is_err());
    }

    #[test]
    fn normalize_emit_event_id_preserves_valid_and_hashes_invalid() {
        assert_eq!(normalize_emit_event_id("e", "abc_123-Z"), "abc_123-Z");
        let n1 = normalize_emit_event_id("task.exited", "boot:42");
        let n2 = normalize_emit_event_id("other.event", "boot:42");
        assert!(n1.starts_with("evt_"));
        assert!(is_valid_event_id(&n1));
        assert_ne!(n1, n2);
    }

    #[test]
    fn byte_budget_enforces_limit_and_releases_on_drop() {
        let budget = ByteBudget::new(100);
        let mut lease = budget.try_acquire(60).unwrap();
        assert!(budget.try_acquire(50).is_none());
        assert!(lease.grow(40));
        assert!(!lease.grow(1));
        drop(lease);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn format_utc_rfc3339_epoch_and_known_date() {
        assert_eq!(format_utc_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }
}
