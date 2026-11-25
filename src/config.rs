//! Configuration loading, `${VAR}` whole-string expansion, and startup validation.

use crate::schema::build_filter_input_schema;
use crate::types::{MAX_TTL_SECS_DEFAULT, MAX_TTL_SECS_UPPER, MIN_TTL_SECS, Profile, SecretString};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use url::Url;

pub const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;
pub const DEFAULT_RESOURCE_PATH: &str = "/mcp";
pub const DEFAULT_REVERIFY_SECS: u64 = 15;
pub const MIN_REVERIFY_SECS: u64 = 5;
pub const MAX_REVERIFY_SECS: u64 = 300;
pub const DEFAULT_UPSTREAM_TIMEOUT_SECS: u64 = 300;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: String,
    #[serde(default = "default_resource_path")]
    resource_path: String,
    state_path: String,
    profile: Profile,
    inbound_tokens: Vec<String>,
    #[serde(default)]
    allowed_origins: Vec<String>,
    #[serde(default = "default_max_ttl_secs")]
    max_ttl_secs: u64,
    #[serde(default)]
    auth_context: Option<RawAuthContextConfig>,
    #[serde(default)]
    upstream: Option<RawUpstreamConfig>,
    #[serde(default)]
    ingest: Option<RawIngestConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuthContextConfig {
    check_url: String,
    check_token: String,
    expected_resource: String,
    #[serde(default = "default_reverify_secs")]
    reverify_secs: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUpstreamConfig {
    url: String,
    #[serde(default)]
    bearer_token: Option<String>,
    #[serde(default)]
    passthrough_prefixes: Vec<String>,
    #[serde(default = "default_upstream_timeout_secs")]
    request_timeout_secs: u64,
    #[serde(default)]
    expose_events: Vec<RawExposeEventConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExposeEventConfig {
    name: String,
    #[serde(default)]
    disallow_arguments: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIngestConfig {
    tokens: Vec<String>,
    events: Vec<RawIngestEventConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIngestEventConfig {
    name: String,
    description: String,
    #[serde(default)]
    filter_fields: Vec<String>,
    payload_schema: Value,
}

fn default_resource_path() -> String {
    DEFAULT_RESOURCE_PATH.to_owned()
}

fn default_max_ttl_secs() -> u64 {
    MAX_TTL_SECS_DEFAULT
}

fn default_reverify_secs() -> u64 {
    DEFAULT_REVERIFY_SECS
}

fn default_upstream_timeout_secs() -> u64 {
    DEFAULT_UPSTREAM_TIMEOUT_SECS
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub resource_path: String,
    pub state_path: PathBuf,
    pub profile: Profile,
    pub inbound_tokens: Vec<SecretString>,
    pub allowed_origins: Vec<String>,
    pub max_ttl_secs: u64,
    pub auth_context: Option<AuthContextConfig>,
    pub upstream: Option<UpstreamConfig>,
    pub ingest: Option<IngestConfig>,
}

#[derive(Clone, Debug)]
pub struct AuthContextConfig {
    pub check_url: Url,
    pub check_token: SecretString,
    pub expected_resource: String,
    pub reverify_secs: u64,
}

#[derive(Clone, Debug)]
pub struct UpstreamConfig {
    pub url: Url,
    pub bearer_token: Option<SecretString>,
    pub passthrough_prefixes: Vec<String>,
    pub request_timeout_secs: u64,
    pub expose_events: Vec<ExposeEventConfig>,
}

#[derive(Clone, Debug)]
pub struct ExposeEventConfig {
    pub name: String,
    pub disallow_arguments: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct IngestConfig {
    pub tokens: Vec<SecretString>,
    pub events: Vec<IngestEventConfig>,
}

#[derive(Clone, Debug)]
pub struct IngestEventConfig {
    pub name: String,
    pub description: String,
    pub filter_fields: Vec<String>,
    pub payload_schema: Value,
    pub input_schema: Value,
}

impl Config {
    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        Self::load_from_path_with_env(path, |k| std::env::var(k).ok())
    }

    pub fn load_from_path_with_env<F>(path: &Path, env_lookup: F) -> Result<Self, String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let file =
            File::open(path).map_err(|e| format!("cannot open config {}: {e}", path.display()))?;
        let mut buf = Vec::new();
        file.take(MAX_CONFIG_FILE_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
        if buf.len() as u64 > MAX_CONFIG_FILE_BYTES {
            return Err(format!(
                "config {} exceeds {} byte limit",
                path.display(),
                MAX_CONFIG_FILE_BYTES
            ));
        }
        let text = String::from_utf8(buf)
            .map_err(|e| format!("config {} is not valid UTF-8: {e}", path.display()))?;
        Self::parse_json_with_env(&text, env_lookup)
    }

    pub fn parse_json_with_env<F>(json_text: &str, env_lookup: F) -> Result<Self, String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let raw: RawConfig =
            serde_json::from_str(json_text).map_err(|e| format!("invalid config JSON: {e}"))?;
        validate_raw_config(raw, &env_lookup)
    }
}

fn expand_env_string<F>(field: &str, raw: &str, env_lookup: &F) -> Result<String, String>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(inner) = raw.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        if inner.is_empty()
            || !inner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(format!(
                "{field}: invalid environment variable placeholder '{raw}'"
            ));
        }
        let val = env_lookup(inner)
            .ok_or_else(|| format!("{field}: environment variable '{inner}' is not set"))?;
        if val.is_empty() {
            return Err(format!("{field}: environment variable '{inner}' is empty"));
        }
        return Ok(val);
    }
    if raw.contains("${") {
        return Err(format!(
            "{field}: partial '${{VAR}}' interpolation is not allowed; use the entire string"
        ));
    }
    Ok(raw.to_owned())
}

fn validate_visible_ascii_token(field: &str, token: &str, min_len: usize) -> Result<(), String> {
    if token.len() < min_len {
        return Err(format!(
            "{field}: token must be at least {min_len} visible ASCII characters"
        ));
    }
    if !token.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(format!(
            "{field}: token must contain only visible ASCII characters (0x21..=0x7e)"
        ));
    }
    Ok(())
}

fn validate_raw_config<F>(raw: RawConfig, env_lookup: &F) -> Result<Config, String>
where
    F: Fn(&str) -> Option<String>,
{
    let listen_str = expand_env_string("listen", &raw.listen, env_lookup)?;
    let listen: SocketAddr = listen_str
        .parse()
        .map_err(|e| format!("listen: invalid socket address '{listen_str}': {e}"))?;

    let resource_path = expand_env_string("resource_path", &raw.resource_path, env_lookup)?;
    if !resource_path.starts_with('/') || resource_path == "/" || resource_path.contains('?') {
        return Err("resource_path: must start with '/', not be '/', and contain no query".into());
    }
    if resource_path == "/healthz" || resource_path == "/v1/events" {
        return Err(format!(
            "resource_path: '{resource_path}' collides with reserved route"
        ));
    }

    let state_path_str = expand_env_string("state_path", &raw.state_path, env_lookup)?;
    if state_path_str.is_empty() {
        return Err("state_path: must not be empty".into());
    }
    let state_path = PathBuf::from(state_path_str);

    if !(MIN_TTL_SECS..=MAX_TTL_SECS_UPPER).contains(&raw.max_ttl_secs) {
        return Err(format!(
            "max_ttl_secs: must be in {MIN_TTL_SECS}..={MAX_TTL_SECS_UPPER}, got {}",
            raw.max_ttl_secs
        ));
    }

    if raw.inbound_tokens.is_empty() {
        return Err("inbound_tokens: must contain at least one token".into());
    }
    let mut inbound_tokens = Vec::with_capacity(raw.inbound_tokens.len());
    for (i, tok) in raw.inbound_tokens.iter().enumerate() {
        let field = format!("inbound_tokens[{i}]");
        let expanded = expand_env_string(&field, tok, env_lookup)?;
        validate_visible_ascii_token(&field, &expanded, 1)?;
        inbound_tokens.push(SecretString::new(expanded));
    }

    let mut allowed_origins = Vec::with_capacity(raw.allowed_origins.len());
    for (i, origin) in raw.allowed_origins.iter().enumerate() {
        let field = format!("allowed_origins[{i}]");
        let expanded = expand_env_string(&field, origin, env_lookup)?;
        let parsed =
            Url::parse(&expanded).map_err(|e| format!("{field}: invalid origin URL: {e}"))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(format!(
                "{field}: origin must be scheme://host[:port] with no path, query, or fragment"
            ));
        }
        allowed_origins.push(expanded.trim_end_matches('/').to_owned());
    }

    let auth_context = match raw.auth_context {
        Some(ac) => {
            if !(MIN_REVERIFY_SECS..=MAX_REVERIFY_SECS).contains(&ac.reverify_secs) {
                return Err(format!(
                    "auth_context.reverify_secs: must be in {MIN_REVERIFY_SECS}..={MAX_REVERIFY_SECS}"
                ));
            }
            let url_str = expand_env_string("auth_context.check_url", &ac.check_url, env_lookup)?;
            let check_url = Url::parse(&url_str)
                .map_err(|e| format!("auth_context.check_url: invalid URL: {e}"))?;
            validate_check_url(&check_url)?;

            let check_token_str =
                expand_env_string("auth_context.check_token", &ac.check_token, env_lookup)?;
            validate_visible_ascii_token("auth_context.check_token", &check_token_str, 16)?;

            let expected_resource = expand_env_string(
                "auth_context.expected_resource",
                &ac.expected_resource,
                env_lookup,
            )?;
            if expected_resource.is_empty() {
                return Err("auth_context.expected_resource: must not be empty".into());
            }

            Some(AuthContextConfig {
                check_url,
                check_token: SecretString::new(check_token_str),
                expected_resource,
                reverify_secs: ac.reverify_secs,
            })
        }
        None => None,
    };

    if raw.upstream.is_none() && raw.ingest.is_none() {
        return Err("at least one of 'upstream' or 'ingest' must be configured".into());
    }

    let mut upstream_event_names = HashSet::new();
    let upstream = match raw.upstream {
        Some(up) => {
            let url_str = expand_env_string("upstream.url", &up.url, env_lookup)?;
            let url =
                Url::parse(&url_str).map_err(|e| format!("upstream.url: invalid URL: {e}"))?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err("upstream.url: must be a valid http:// or https:// URL".into());
            }
            let bearer_token = match up.bearer_token {
                Some(tok) => {
                    let expanded = expand_env_string("upstream.bearer_token", &tok, env_lookup)?;
                    validate_visible_ascii_token("upstream.bearer_token", &expanded, 1)?;
                    Some(SecretString::new(expanded))
                }
                None => None,
            };
            if up.request_timeout_secs == 0 {
                return Err("upstream.request_timeout_secs: must be >= 1".into());
            }
            let mut passthrough_prefixes = Vec::with_capacity(up.passthrough_prefixes.len());
            for (i, pref) in up.passthrough_prefixes.iter().enumerate() {
                let field = format!("upstream.passthrough_prefixes[{i}]");
                let expanded = expand_env_string(&field, pref, env_lookup)?;
                if !expanded.starts_with('/') || !expanded.ends_with('/') || expanded == "/" {
                    return Err(format!(
                        "{field}: passthrough prefix must start and end with '/' and not be '/'"
                    ));
                }
                if resource_path.starts_with(&expanded) || expanded.starts_with(&resource_path) {
                    return Err(format!(
                        "{field}: prefix '{expanded}' collides with resource_path '{resource_path}'"
                    ));
                }
                passthrough_prefixes.push(expanded);
            }
            let mut expose_events = Vec::with_capacity(up.expose_events.len());
            for (i, ev) in up.expose_events.into_iter().enumerate() {
                if ev.name.is_empty() {
                    return Err(format!(
                        "upstream.expose_events[{i}].name: must not be empty"
                    ));
                }
                if !upstream_event_names.insert(ev.name.clone()) {
                    return Err(format!(
                        "upstream.expose_events: duplicate event name '{}'",
                        ev.name
                    ));
                }
                expose_events.push(ExposeEventConfig {
                    name: ev.name,
                    disallow_arguments: ev.disallow_arguments,
                });
            }
            Some(UpstreamConfig {
                url,
                bearer_token,
                passthrough_prefixes,
                request_timeout_secs: up.request_timeout_secs,
                expose_events,
            })
        }
        None => None,
    };

    let ingest = match raw.ingest {
        Some(ing) => {
            if ing.tokens.is_empty() {
                return Err("ingest.tokens: must contain at least one token".into());
            }
            let mut tokens = Vec::with_capacity(ing.tokens.len());
            for (i, tok) in ing.tokens.iter().enumerate() {
                let field = format!("ingest.tokens[{i}]");
                let expanded = expand_env_string(&field, tok, env_lookup)?;
                validate_visible_ascii_token(&field, &expanded, 1)?;
                tokens.push(SecretString::new(expanded));
            }
            if ing.events.is_empty() {
                return Err("ingest.events: must declare at least one event".into());
            }
            let mut ingest_names = HashSet::new();
            let mut events = Vec::with_capacity(ing.events.len());
            for (i, ev) in ing.events.into_iter().enumerate() {
                if ev.name.is_empty() {
                    return Err(format!("ingest.events[{i}].name: must not be empty"));
                }
                if !ingest_names.insert(ev.name.clone()) {
                    return Err(format!("ingest.events: duplicate event name '{}'", ev.name));
                }
                if upstream_event_names.contains(&ev.name) {
                    return Err(format!(
                        "event name '{}' is declared in both upstream.expose_events and ingest.events",
                        ev.name
                    ));
                }
                let desc_chars = ev.description.chars().count();
                if !(1..=400).contains(&desc_chars) {
                    return Err(format!(
                        "ingest.events[{i}].description: length must be 1..=400 Unicode characters, got {desc_chars}"
                    ));
                }
                let input_schema = build_filter_input_schema(&ev.payload_schema, &ev.filter_fields)
                    .map_err(|e| format!("ingest.events[{i}] ('{}'): {e}", ev.name))?;
                events.push(IngestEventConfig {
                    name: ev.name,
                    description: ev.description,
                    filter_fields: ev.filter_fields,
                    payload_schema: ev.payload_schema,
                    input_schema,
                });
            }
            Some(IngestConfig { tokens, events })
        }
        None => None,
    };

    Ok(Config {
        listen,
        resource_path,
        state_path,
        profile: raw.profile,
        inbound_tokens,
        allowed_origins,
        max_ttl_secs: raw.max_ttl_secs,
        auth_context,
        upstream,
        ingest,
    })
}

fn validate_check_url(url: &Url) -> Result<(), String> {
    if url.username() != "" || url.password().is_some() || url.fragment().is_some() {
        return Err("auth_context.check_url: must not contain userinfo or fragment".into());
    }
    match url.scheme() {
        "https" => {
            if url.host_str().is_none() {
                return Err("auth_context.check_url: missing host".into());
            }
            Ok(())
        }
        "http" => {
            let Some(host) = url.host() else {
                return Err("auth_context.check_url: missing host".into());
            };
            let is_literal_loopback = match host {
                url::Host::Ipv4(v4) => IpAddr::V4(v4).is_loopback(),
                url::Host::Ipv6(v6) => IpAddr::V6(v6).is_loopback(),
                url::Host::Domain(_) => false,
            };
            if !is_literal_loopback {
                return Err(
                    "auth_context.check_url: plain http:// is only allowed for literal loopback IPs (127.0.0.0/8 or [::1])".into(),
                );
            }
            Ok(())
        }
        other => Err(format!(
            "auth_context.check_url: unsupported scheme '{other}' (expected https or loopback http)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ingest_config() -> &'static str {
        r#"{
            "listen": "127.0.0.1:8081",
            "state_path": "/tmp/subscriptions.json",
            "profile": "chatgpt",
            "inbound_tokens": ["${INBOUND}"],
            "ingest": {
                "tokens": ["${PROD}"],
                "events": [{
                    "name": "ci.build_failed",
                    "description": "Fired when CI fails.",
                    "filter_fields": ["repo", "pr"],
                    "payload_schema": {
                        "type": "object",
                        "properties": {
                            "repo": {"type": "string"},
                            "pr": {"type": "integer"}
                        },
                        "required": ["repo"],
                        "additionalProperties": false
                    }
                }]
            }
        }"#
    }

    #[test]
    fn parses_valid_config_and_expands_env() {
        let cfg = Config::parse_json_with_env(sample_ingest_config(), |k| match k {
            "INBOUND" => Some("secret_inbound_token".into()),
            "PROD" => Some("secret_producer_token".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(cfg.profile, Profile::Chatgpt);
        assert_eq!(cfg.resource_path, "/mcp");
        assert_eq!(cfg.max_ttl_secs, 3600);
        assert_eq!(cfg.ingest.as_ref().unwrap().events.len(), 1);
    }

    #[test]
    fn rejects_partial_env_interpolation_and_plaintext_non_loopback_check_url() {
        let partial = sample_ingest_config().replace("${INBOUND}", "prefix-${INBOUND}");
        assert!(Config::parse_json_with_env(&partial, |_| Some("x".into())).is_err());

        let bad_check = r#"{
            "listen": "127.0.0.1:8081",
            "state_path": "/tmp/s.json",
            "profile": "sep3415",
            "inbound_tokens": ["tok1"],
            "auth_context": {
                "check_url": "http://localhost:8083/authorization/check",
                "check_token": "0123456789abcdef",
                "expected_resource": "https://mcp.example.com/mcp"
            },
            "upstream": {
                "url": "http://127.0.0.1:8765/mcp"
            }
        }"#;
        assert!(Config::parse_json_with_env(bad_check, |_| None).is_err());

        let good_check = bad_check.replace("http://localhost:8083", "http://127.0.0.1:8083");
        assert!(Config::parse_json_with_env(&good_check, |_| None).is_ok());
    }

    #[test]
    fn rejects_duplicate_event_names_across_upstream_and_ingest() {
        let dup = r#"{
            "listen": "127.0.0.1:8081",
            "state_path": "/tmp/s.json",
            "profile": "sep3415",
            "inbound_tokens": ["tok1"],
            "upstream": {
                "url": "http://127.0.0.1:8765/mcp",
                "expose_events": [{"name": "dup.ev"}]
            },
            "ingest": {
                "tokens": ["ptok"],
                "events": [{
                    "name": "dup.ev",
                    "description": "dup",
                    "payload_schema": {"type": "object"}
                }]
            }
        }"#;
        assert!(Config::parse_json_with_env(dup, |_| None).is_err());
    }
}
