//! Inbound header sanitization, passthrough path checks, Origin checks, and MCP routing headers.

use crate::types::SecretString;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use url::Url;

const MAX_PERCENT_DECODE_ROUNDS: usize = 8;
const BASE64_HEADER_PREFIX: &str = "=?base64?";
const BASE64_HEADER_SUFFIX: &str = "?=";

const STANDARD_HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// Extract the `host[:port]` authority string from an HTTP(S) URL.
pub fn url_authority(url: &Url) -> Result<String, String> {
    let host = url
        .host_str()
        .ok_or_else(|| "upstream URL is missing host".to_string())?;
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

fn collect_connection_nominated(headers: &HeaderMap) -> HashSet<String> {
    let mut nominated = HashSet::new();
    for val in headers.get_all(header::CONNECTION) {
        if let Ok(text) = val.to_str() {
            for token in text.split(',') {
                let name = token.trim();
                if !name.is_empty() {
                    nominated.insert(name.to_ascii_lowercase());
                }
            }
        }
    }
    nominated
}

fn is_hop_by_hop(lower_name: &str, connection_nominated: &HashSet<String>) -> bool {
    STANDARD_HOP_BY_HOP.contains(&lower_name) || connection_nominated.contains(lower_name)
}

/// Sanitize inbound headers for forwarding to `upstream_url` per spec §4.1.
pub fn build_upstream_headers(
    inbound: &HeaderMap,
    upstream_url: &Url,
    bearer_token: Option<&SecretString>,
    inject_auth: bool,
) -> Result<HeaderMap, String> {
    let nominated = collect_connection_nominated(inbound);
    let mut out = HeaderMap::with_capacity(inbound.len() + 3);
    let mut has_forwarded_proto = false;

    for (name, value) in inbound {
        let lower = name.as_str();
        if is_hop_by_hop(lower, &nominated)
            || matches!(lower, "authorization" | "cookie" | "origin" | "host")
            || lower.starts_with("x-authorization-")
        {
            continue;
        }
        if lower == "x-forwarded-proto" {
            has_forwarded_proto = true;
        }
        out.append(name.clone(), value.clone());
    }

    if !has_forwarded_proto {
        let proto = HeaderValue::from_str(upstream_url.scheme())
            .map_err(|e| format!("invalid upstream scheme for X-Forwarded-Proto: {e}"))?;
        out.insert(HeaderName::from_static("x-forwarded-proto"), proto);
    }

    let authority = url_authority(upstream_url)?;
    let host_val =
        HeaderValue::from_str(&authority).map_err(|e| format!("invalid Host authority: {e}"))?;
    out.insert(header::HOST, host_val);

    if inject_auth && let Some(token) = bearer_token {
        let auth_val = HeaderValue::from_str(&format!("Bearer {}", token.expose()))
            .map_err(|e| format!("invalid upstream bearer token header: {e}"))?;
        out.insert(header::AUTHORIZATION, auth_val);
    }

    Ok(out)
}

/// Strip hop-by-hop headers (including Connection-nominated names) from an upstream response.
pub fn strip_hop_by_hop_response_headers(inbound: &HeaderMap) -> HeaderMap {
    let nominated = collect_connection_nominated(inbound);
    let mut out = HeaderMap::with_capacity(inbound.len());
    for (name, value) in inbound {
        if !is_hop_by_hop(name.as_str(), &nominated) {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

/// Normalize and validate a candidate passthrough path (up to 8 percent-decode rounds)
/// and report whether it matches any configured `prefixes`.
pub fn validate_passthrough_path(raw_path: &str, prefixes: &[String]) -> Result<bool, String> {
    if prefixes.is_empty() {
        return Ok(false);
    }
    if raw_path.is_empty() || !raw_path.starts_with('/') {
        return Err("path must start with '/'".into());
    }
    if raw_path.contains('\\')
        || raw_path.contains('\0')
        || raw_path.contains('#')
        || raw_path.chars().any(char::is_control)
    {
        return Err("path contains forbidden characters".into());
    }

    let path = raw_path.split('?').next().unwrap_or(raw_path);
    let raw_bytes = path.as_bytes();
    if has_malformed_percent(raw_bytes) {
        return Err("path contains malformed percent-encoding".into());
    }
    check_safe_path_bytes(raw_bytes)?;

    let mut current = raw_bytes.to_vec();
    let mut settled = false;
    for _ in 0..MAX_PERCENT_DECODE_ROUNDS {
        let (next, changed) = decode_percent_pairs(&current);
        if changed {
            check_safe_path_bytes(&next)?;
            current = next;
        } else {
            settled = true;
            break;
        }
    }
    if !settled && has_decodable_percent(&current) {
        return Err("path exceeds maximum percent-decoding depth".into());
    }

    let matched = prefixes.iter().any(|prefix| {
        let pb = prefix.as_bytes();
        raw_bytes.starts_with(pb) && current.starts_with(pb)
    });
    Ok(matched)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn has_malformed_percent(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || hex_nibble(bytes[i + 1]).is_none()
                || hex_nibble(bytes[i + 2]).is_none()
            {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

fn has_decodable_percent(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'%'
            && hex_nibble(bytes[i + 1]).is_some()
            && hex_nibble(bytes[i + 2]).is_some()
        {
            return true;
        }
        i += 1;
    }
    false
}

fn decode_percent_pairs(bytes: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            changed = true;
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    (out, changed)
}

fn check_safe_path_bytes(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes[0] != b'/' {
        return Err("path must start with '/'".into());
    }
    if bytes
        .iter()
        .any(|&b| b == 0 || b == b'\\' || b == b';' || b < 0x20 || b == 0x7f)
    {
        return Err("path contains forbidden byte (NUL, control, backslash, or ';')".into());
    }
    if bytes.len() == 1 {
        return Err("path must not be root '/'".into());
    }
    for seg in bytes[1..].split(|&b| b == b'/') {
        if seg.is_empty() {
            return Err("path contains empty segment".into());
        }
        if seg == b"." || seg == b".." {
            return Err("path contains dot traversal segment".into());
        }
    }
    Ok(())
}

/// Check whether an inbound `Origin` header is allowed per spec §2.
pub fn is_origin_allowed(
    origin_header: Option<&str>,
    bound_addr: SocketAddr,
    allowed_origins: &[String],
) -> bool {
    let Some(raw) = origin_header else {
        return true;
    };
    let Some(parsed) = parse_origin_tuple(raw) else {
        return false;
    };

    let bound_port = bound_addr.port();
    if parsed.0 == "http" && parsed.2 == bound_port {
        let bound_host = match bound_addr.ip() {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        };
        if parsed.1 == "127.0.0.1"
            || parsed.1 == "localhost"
            || parsed.1 == "[::1]"
            || parsed.1 == bound_host
        {
            return true;
        }
    }

    allowed_origins
        .iter()
        .filter_map(|entry| parse_origin_tuple(entry))
        .any(|allowed| allowed == parsed)
}

fn parse_origin_tuple(raw: &str) -> Option<(String, String, u16)> {
    if raw.ends_with('/') {
        return None;
    }
    let url = Url::parse(raw).ok()?;
    let scheme = url.scheme();
    if !matches!(scheme, "http" | "https") {
        return None;
    }
    if url.username() != ""
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    let port = url.port_or_known_default()?;
    Some((scheme.to_owned(), host, port))
}

/// Decode an `Mcp-Name` or `Mcp-Param-*` header value, supporting `=?base64?...?=`.
pub fn decode_mcp_header_value(raw: &str) -> Option<String> {
    if let Some(rest) = raw.strip_prefix(BASE64_HEADER_PREFIX) {
        let encoded = rest.strip_suffix(BASE64_HEADER_SUFFIX)?;
        let bytes = BASE64_STD.decode(encoded).ok()?;
        return String::from_utf8(bytes).ok();
    }
    Some(raw.to_owned())
}

/// Encode an `Mcp-Name` or `Mcp-Param-*` header value using `=?base64?...?=` when required.
pub fn encode_mcp_header_value(value: &str) -> String {
    if requires_base64(value) {
        format!(
            "{BASE64_HEADER_PREFIX}{}{BASE64_HEADER_SUFFIX}",
            BASE64_STD.encode(value.as_bytes())
        )
    } else {
        value.to_owned()
    }
}

fn requires_base64(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let bytes = value.as_bytes();
    if matches!(bytes.first(), Some(b' ' | b'\t')) || matches!(bytes.last(), Some(b' ' | b'\t')) {
        return true;
    }
    if value
        .chars()
        .any(|c| (c as u32) < 0x20 || (c as u32) > 0x7E)
    {
        return true;
    }
    value.starts_with(BASE64_HEADER_PREFIX)
}

fn is_http_tchar(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~'
        )
}

struct HeaderBinding<'a> {
    name: &'a str,
    path: Vec<&'a str>,
}

fn header_bindings(schema: Option<&Value>) -> Result<Vec<HeaderBinding<'_>>, String> {
    fn visit<'a>(
        schema: &'a Value,
        path: &mut Vec<&'a str>,
        out: &mut Vec<HeaderBinding<'a>>,
        seen: &mut HashSet<String>,
    ) -> Result<(), String> {
        let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
            return Ok(());
        };
        for (name, property) in properties {
            path.push(name);
            if let Some(annotation) = property.get("x-mcp-header") {
                let Some(header) = annotation.as_str() else {
                    return Err("x-mcp-header must be a string".into());
                };
                if header.is_empty() || !header.chars().all(is_http_tchar) {
                    return Err(format!("invalid x-mcp-header name {header:?}"));
                }
                if !seen.insert(header.to_ascii_lowercase()) {
                    return Err(format!("duplicate x-mcp-header name {header:?}"));
                }
                if !matches!(
                    property.get("type").and_then(Value::as_str),
                    Some("string" | "integer" | "boolean")
                ) {
                    return Err(format!(
                        "x-mcp-header {header:?} requires a scalar property"
                    ));
                }
                out.push(HeaderBinding {
                    name: header,
                    path: path.clone(),
                });
            }
            visit(property, path, out, seen)?;
            path.pop();
        }
        Ok(())
    }

    let mut out = Vec::new();
    if let Some(schema) = schema {
        visit(schema, &mut Vec::new(), &mut out, &mut HashSet::new())?;
    }
    Ok(out)
}

fn argument_at<'a>(arguments: Option<&'a Map<String, Value>>, path: &[&str]) -> Option<&'a Value> {
    let (first, rest) = path.split_first()?;
    rest.iter()
        .try_fold(arguments?.get(*first)?, |value, key| value.get(*key))
}

/// Build routing headers from schema annotations and unannotated scalar arguments.
pub fn build_event_routing_headers(
    event_name: &str,
    arguments: Option<&Map<String, Value>>,
    input_schema: &Value,
) -> Result<Vec<(HeaderName, HeaderValue)>, String> {
    let mut out = Vec::new();
    let encoded_name = encode_mcp_header_value(event_name);
    let name_val = HeaderValue::from_str(&encoded_name)
        .map_err(|e| format!("invalid Mcp-Name header value: {e}"))?;
    out.push((HeaderName::from_static("mcp-name"), name_val));

    let bindings = header_bindings(Some(input_schema))?;
    let mut push = |name: &str, value: &Value| -> Result<(), String> {
        let Some(scalar_text) = scalar_to_header_string(value) else {
            return Ok(());
        };
        let header_name = HeaderName::from_bytes(format!("mcp-param-{name}").as_bytes())
            .map_err(|e| format!("invalid Mcp-Param header name '{name}': {e}"))?;
        let header_val = HeaderValue::from_str(&encode_mcp_header_value(&scalar_text))
            .map_err(|e| format!("invalid Mcp-Param header value for '{name}': {e}"))?;
        out.push((header_name, header_val));
        Ok(())
    };

    for binding in &bindings {
        if let Some(value) = argument_at(arguments, &binding.path) {
            push(binding.name, value)?;
        }
    }
    if let Some(args) = arguments {
        for (key, value) in args {
            if key.is_empty()
                || !key.chars().all(is_http_tchar)
                || bindings.iter().any(|binding| {
                    binding.name.eq_ignore_ascii_case(key)
                        || (binding.path.len() == 1 && binding.path[0] == key)
                })
                || args
                    .keys()
                    .any(|other| other != key && other.eq_ignore_ascii_case(key))
            {
                continue;
            }
            push(key, value)?;
        }
    }

    Ok(out)
}

fn as_exact_i128(val: &Value) -> Option<i128> {
    let n = val.as_number()?;
    if let Some(i) = n.as_i64() {
        return Some(i128::from(i));
    }
    if let Some(u) = n.as_u64() {
        return Some(i128::from(u));
    }
    let f = n.as_f64()?;
    // Restrict float-to-int conversion to exact IEEE-754 integer range (|f| <= 2^53).
    if f.is_finite() && f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_992.0 {
        Some(f as i128)
    } else {
        None
    }
}

fn scalar_to_header_string(val: &Value) -> Option<String> {
    match val {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(if *b { "true" } else { "false" }.to_owned()),
        Value::Number(n) => {
            if let Some(i) = as_exact_i128(val) {
                Some(i.to_string())
            } else {
                Some(n.to_string())
            }
        }
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

/// Validate optional `Mcp-Name` and `Mcp-Param-*` headers on `events/*` requests per spec §4.1.
pub fn validate_optional_event_routing_headers(
    headers: &HeaderMap,
    event_name: &str,
    arguments: Option<&Map<String, Value>>,
    disallowed_args: &[String],
    input_schema: Option<&Value>,
) -> Result<(), String> {
    let mut name_values = headers.get_all("mcp-name").iter();
    if let Some(first) = name_values.next() {
        if name_values.next().is_some() {
            return Err("duplicate Mcp-Name header".into());
        }
        let raw = first
            .to_str()
            .map_err(|_| "Mcp-Name header is not valid ASCII".to_string())?;
        let decoded = decode_mcp_header_value(raw)
            .ok_or_else(|| "Mcp-Name header has invalid base64 encoding".to_string())?;
        if decoded != event_name {
            return Err(format!(
                "Mcp-Name header ({decoded:?}) does not match params.name ({event_name:?})"
            ));
        }
    }

    let bindings = header_bindings(input_schema)?;
    let mut seen_params = HashSet::new();
    for (name, value) in headers {
        let Some(param_key) = name.as_str().strip_prefix("mcp-param-") else {
            continue;
        };
        if param_key.is_empty() {
            return Err("empty Mcp-Param- header name".into());
        }
        if !seen_params.insert(param_key) {
            return Err(format!("duplicate Mcp-Param-{param_key} header"));
        }
        let raw = value
            .to_str()
            .map_err(|_| format!("Mcp-Param-{param_key} header is not valid ASCII"))?;
        let decoded = decode_mcp_header_value(raw)
            .ok_or_else(|| format!("Mcp-Param-{param_key} header has invalid base64 encoding"))?;

        let binding = bindings
            .iter()
            .find(|binding| binding.name.eq_ignore_ascii_case(param_key));
        let target = binding.map_or(param_key, |binding| binding.path[0]);
        if disallowed_args
            .iter()
            .any(|disallowed| disallowed.eq_ignore_ascii_case(target))
        {
            return Err(format!(
                "Mcp-Param-{param_key} targets a disallowed argument"
            ));
        }
        let arg_val = if let Some(binding) = binding {
            argument_at(arguments, &binding.path).ok_or_else(|| {
                format!("Mcp-Param-{param_key} present but missing from params.arguments")
            })?
        } else {
            lookup_argument(arguments, param_key)?
        };
        if !header_matches_scalar(&decoded, arg_val) {
            return Err(format!(
                "Mcp-Param-{param_key} header ({decoded:?}) does not match params.arguments"
            ));
        }
    }

    Ok(())
}

fn lookup_argument<'a>(
    arguments: Option<&'a Map<String, Value>>,
    param_key: &str,
) -> Result<&'a Value, String> {
    let args = arguments
        .ok_or_else(|| format!("Mcp-Param-{param_key} present but params.arguments is missing"))?;
    let val = if let Some(exact) = args.get(param_key) {
        exact
    } else {
        let mut matches = args
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(param_key));
        let Some((_, first)) = matches.next() else {
            return Err(format!(
                "Mcp-Param-{param_key} present but missing from params.arguments"
            ));
        };
        if matches.next().is_some() {
            return Err(format!(
                "Mcp-Param-{param_key} ambiguously matches multiple argument keys"
            ));
        }
        first
    };
    if val.is_null() {
        return Err(format!(
            "Mcp-Param-{param_key} present but argument value is null"
        ));
    }
    Ok(val)
}

fn exact_header_integer(text: &str) -> Option<i128> {
    let negative = text.starts_with('-');
    let unsigned = text.strip_prefix('-').unwrap_or(text);
    let (mantissa, exponent) = match unsigned.find(['e', 'E']) {
        Some(index) => (&unsigned[..index], Some(&unsigned[index + 1..])),
        None => (unsigned, None),
    };
    let Some(end) = mantissa
        .bytes()
        .rposition(|byte| matches!(byte, b'1'..=b'9'))
        .map(|index| index + 1)
    else {
        return Some(0);
    };
    let fraction = mantissa
        .find('.')
        .map_or(0, |index| mantissa.len() - index - 1);
    let trailing = mantissa[end..].bytes().filter(u8::is_ascii_digit).count();
    let exponent = exponent
        .map_or(Some(0), |value| value.parse::<i64>().ok())?
        .checked_sub(i64::try_from(fraction).ok()?)?
        .checked_add(i64::try_from(trailing).ok()?)?;
    let mut coefficient = 0_i128;
    for digit in mantissa[..end].bytes().filter(u8::is_ascii_digit) {
        coefficient = coefficient
            .checked_mul(10)?
            .checked_add(i128::from(digit - b'0'))?;
    }
    let integer = coefficient.checked_mul(10_i128.checked_pow(u32::try_from(exponent).ok()?)?)?;
    if negative {
        integer.checked_neg()
    } else {
        Some(integer)
    }
}

fn header_matches_scalar(decoded: &str, arg_val: &Value) -> bool {
    match arg_val {
        Value::String(s) => decoded == s,
        Value::Bool(b) => decoded == if *b { "true" } else { "false" },
        Value::Number(n) => {
            if decoded != decoded.trim() {
                return false;
            }
            let Ok(hdr_val) = serde_json::from_str::<Value>(decoded) else {
                return false;
            };
            let Some(hdr_num) = hdr_val.as_number() else {
                return false;
            };
            if let Some(integer) = as_exact_i128(arg_val) {
                return exact_header_integer(decoded) == Some(integer);
            }
            if as_exact_i128(&hdr_val).is_some() {
                return exact_header_integer(&n.to_string())
                    .is_some_and(|integer| exact_header_integer(decoded) == Some(integer));
            }
            match (n.as_f64(), hdr_num.as_f64()) {
                (Some(a), Some(b)) => a.is_finite() && b.is_finite() && a == b,
                _ => false,
            }
        }
        Value::Null | Value::Array(_) | Value::Object(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_upstream_headers_strips_hop_by_hop_auth_and_custom_connection_headers() {
        let mut inbound = HeaderMap::new();
        inbound.insert(
            header::ACCEPT,
            "application/json, text/event-stream".parse().unwrap(),
        );
        inbound.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        inbound.insert(
            header::AUTHORIZATION,
            "Bearer inbound-secret".parse().unwrap(),
        );
        inbound.insert(header::COOKIE, "sid=123".parse().unwrap());
        inbound.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        inbound.insert(header::HOST, "public.example.com".parse().unwrap());
        inbound.insert(
            header::CONNECTION,
            "keep-alive, X-Custom-Hop, X-Another".parse().unwrap(),
        );
        inbound.insert("x-custom-hop", "drop-me".parse().unwrap());
        inbound.insert("x-another", "drop-me-too".parse().unwrap());
        inbound.insert("keep-alive", "timeout=5".parse().unwrap());
        inbound.insert("transfer-encoding", "chunked".parse().unwrap());
        inbound.insert("x-authorization-ref", "aref_forged".parse().unwrap());
        inbound.insert("x-authorization-scope", "admin".parse().unwrap());
        inbound.insert("mcp-session-id", "sess-1".parse().unwrap());
        inbound.insert("mcp-protocol-version", "2026-07-28".parse().unwrap());
        inbound.insert("mcp-method", "events/poll".parse().unwrap());
        inbound.insert("mcp-name", "task.exited".parse().unwrap());
        inbound.insert("mcp-param-repo", "org/app".parse().unwrap());
        inbound.insert("last-event-id", "evt-9".parse().unwrap());

        let upstream = Url::parse("http://127.0.0.1:8765/mcp").unwrap();
        let token = SecretString::new("upstream-token");

        let out = build_upstream_headers(&inbound, &upstream, Some(&token), true).unwrap();
        assert_eq!(out.get(header::HOST).unwrap(), "127.0.0.1:8765");
        assert_eq!(
            out.get(header::AUTHORIZATION).unwrap(),
            "Bearer upstream-token"
        );
        assert_eq!(out.get("x-forwarded-proto").unwrap(), "http");
        assert_eq!(out.get("mcp-session-id").unwrap(), "sess-1");
        assert_eq!(out.get("mcp-protocol-version").unwrap(), "2026-07-28");
        assert_eq!(out.get("mcp-method").unwrap(), "events/poll");
        assert_eq!(out.get("mcp-name").unwrap(), "task.exited");
        assert_eq!(out.get("mcp-param-repo").unwrap(), "org/app");
        assert_eq!(out.get("last-event-id").unwrap(), "evt-9");

        for stripped in [
            "cookie",
            "origin",
            "connection",
            "keep-alive",
            "transfer-encoding",
            "x-custom-hop",
            "x-another",
            "x-authorization-ref",
            "x-authorization-scope",
        ] {
            assert!(out.get(stripped).is_none(), "{stripped} should be stripped");
        }

        // Passthrough mode (`inject_auth = false`) must never inject upstream bearer token.
        let out_no_auth = build_upstream_headers(&inbound, &upstream, Some(&token), false).unwrap();
        assert!(out_no_auth.get(header::AUTHORIZATION).is_none());

        // Existing X-Forwarded-Proto is preserved.
        let mut with_proto = HeaderMap::new();
        with_proto.insert("x-forwarded-proto", "https".parse().unwrap());
        let out_proto = build_upstream_headers(&with_proto, &upstream, None, true).unwrap();
        assert_eq!(out_proto.get("x-forwarded-proto").unwrap(), "https");
    }

    #[test]
    fn validate_passthrough_path_blocks_traversal_and_multi_round_encoding() {
        let prefixes = vec!["/t/".to_string()];

        assert_eq!(validate_passthrough_path("/t/file123", &prefixes), Ok(true));
        assert_eq!(
            validate_passthrough_path("/t/dir/file.bin", &prefixes),
            Ok(true)
        );
        assert_eq!(validate_passthrough_path("/mcp", &prefixes), Ok(false));

        // Traversal, empty segments, backslash, semicolon, NUL, control chars.
        assert!(validate_passthrough_path("/t/%2e%2e/mcp", &prefixes).is_err());
        assert!(validate_passthrough_path("/t/./file", &prefixes).is_err());
        assert!(validate_passthrough_path("/t//file", &prefixes).is_err());
        assert!(validate_passthrough_path("/t/", &prefixes).is_err());
        assert!(validate_passthrough_path("/t/a\\b", &prefixes).is_err());
        assert!(validate_passthrough_path("/t/a%5cb", &prefixes).is_err());
        assert!(validate_passthrough_path("/t/a;v=1/b", &prefixes).is_err());
        assert!(validate_passthrough_path("/t/a%3bv=1", &prefixes).is_err());
        assert!(validate_passthrough_path("/t/a%00b", &prefixes).is_err());
        assert!(validate_passthrough_path("/t/a%0ab", &prefixes).is_err());
        assert!(validate_passthrough_path("/t/%2", &prefixes).is_err());

        // 8-round encoded `..`: `%25` repeated 7 times before `2e` -> 8 rounds decodes to `..`.
        let mut encoded = "..".to_string();
        for _ in 0..8 {
            let mut next = String::new();
            for b in encoded.bytes() {
                next.push_str(&format!("%{b:02x}"));
            }
            encoded = next;
        }
        assert!(validate_passthrough_path(&format!("/t/{encoded}/mcp"), &prefixes).is_err());

        // 9-round encoded harmless char exceeds 8-round cap and is rejected.
        let mut deep = "a".to_string();
        for _ in 0..9 {
            deep = deep.replace('%', "%25");
            if deep == "a" {
                deep = "%61".to_string();
            }
        }
        assert!(validate_passthrough_path(&format!("/t/{deep}"), &prefixes).is_err());
    }

    #[test]
    fn is_origin_allowed_handles_loopback_bound_addr_and_whitelist() {
        let bound: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let allow = vec!["https://app.example.com".to_string()];

        assert!(is_origin_allowed(None, bound, &allow));
        assert!(is_origin_allowed(
            Some("http://127.0.0.1:8081"),
            bound,
            &allow
        ));
        assert!(is_origin_allowed(
            Some("http://localhost:8081"),
            bound,
            &allow
        ));
        assert!(is_origin_allowed(Some("http://[::1]:8081"), bound, &allow));
        assert!(is_origin_allowed(
            Some("https://app.example.com"),
            bound,
            &allow
        ));
        assert!(is_origin_allowed(
            Some("HTTPS://APP.EXAMPLE.COM"),
            bound,
            &allow
        ));

        assert!(!is_origin_allowed(
            Some("http://127.0.0.1:9999"),
            bound,
            &allow
        ));
        assert!(!is_origin_allowed(
            Some("https://127.0.0.1:8081"),
            bound,
            &allow
        ));
        assert!(!is_origin_allowed(
            Some("https://evil.example.com"),
            bound,
            &allow
        ));
        assert!(!is_origin_allowed(
            Some("https://app.example.com/"),
            bound,
            &allow
        ));
        assert!(!is_origin_allowed(Some("null"), bound, &allow));

        let non_loopback: SocketAddr = "10.0.0.5:8081".parse().unwrap();
        assert!(is_origin_allowed(
            Some("http://10.0.0.5:8081"),
            non_loopback,
            &[]
        ));
    }

    #[test]
    fn optional_event_routing_headers_decode_base64_and_compare_integers() {
        let args = json!({"repo": "org/测试", "pr": 42, "draft": false, "empty": null});
        let args_map = args.as_object().unwrap();

        // Missing headers are allowed.
        let empty = HeaderMap::new();
        assert!(
            validate_optional_event_routing_headers(&empty, "ci.build", Some(args_map), &[], None)
                .is_ok()
        );

        // Matching encoded headers (base64 non-ASCII + integer numeric equality).
        let mut hdrs = HeaderMap::new();
        hdrs.insert(
            "mcp-name",
            encode_mcp_header_value("ci.build").parse().unwrap(),
        );
        hdrs.insert(
            "mcp-param-repo",
            encode_mcp_header_value("org/测试").parse().unwrap(),
        );
        hdrs.insert("mcp-param-pr", "42.0".parse().unwrap());
        hdrs.insert("mcp-param-draft", "false".parse().unwrap());
        assert!(
            validate_optional_event_routing_headers(&hdrs, "ci.build", Some(args_map), &[], None)
                .is_ok()
        );

        // Disallowed argument is rejected.
        assert!(
            validate_optional_event_routing_headers(
                &hdrs,
                "ci.build",
                Some(args_map),
                &["repo".to_string()],
                None
            )
            .is_err()
        );

        // Null argument or missing argument is rejected.
        let mut null_hdr = HeaderMap::new();
        null_hdr.insert("mcp-param-empty", "null".parse().unwrap());
        assert!(
            validate_optional_event_routing_headers(
                &null_hdr,
                "ci.build",
                Some(args_map),
                &[],
                None
            )
            .is_err()
        );

        let mut missing_hdr = HeaderMap::new();
        missing_hdr.insert("mcp-param-unknown", "1".parse().unwrap());
        assert!(
            validate_optional_event_routing_headers(
                &missing_hdr,
                "ci.build",
                Some(args_map),
                &[],
                None
            )
            .is_err()
        );

        // Duplicate Mcp-Name is rejected.
        let mut dup = HeaderMap::new();
        dup.append("mcp-name", "ci.build".parse().unwrap());
        dup.append("mcp-name", "ci.build".parse().unwrap());
        assert!(
            validate_optional_event_routing_headers(&dup, "ci.build", Some(args_map), &[], None)
                .is_err()
        );

        // Round-trip encode helper.
        let built = build_event_routing_headers("ci.build", Some(args_map), &json!({})).unwrap();
        let mut built_map = HeaderMap::new();
        for (k, v) in built {
            built_map.append(k, v);
        }
        assert!(built_map.get("mcp-param-empty").is_none());
        assert!(
            validate_optional_event_routing_headers(
                &built_map,
                "ci.build",
                Some(args_map),
                &[],
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn annotated_aliases_and_nested_properties_round_trip() {
        let schema = json!({
            "type": "object",
            "properties": {
                "repo": {"type": "string", "x-mcp-header": "Workspace"},
                "nested": {"type": "object", "properties": {
                    "count": {"type": "integer", "x-mcp-header": "Count"}
                }},
                "scope": {"type": "string", "x-mcp-header": "Access"}
            }
        });
        let args = json!({
            "repo": "org/app",
            "nested": {"count": 7},
            "scope": "all",
            "plain": true
        });
        let built: HeaderMap = build_event_routing_headers("changes", args.as_object(), &schema)
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(built["mcp-param-workspace"], "org/app");
        assert_eq!(built["mcp-param-count"], "7");
        assert_eq!(built["mcp-param-plain"], "true");
        assert!(!built.contains_key("mcp-param-repo"));
        assert!(
            validate_optional_event_routing_headers(
                &built,
                "changes",
                args.as_object(),
                &[],
                Some(&schema),
            )
            .is_ok()
        );
        assert!(
            validate_optional_event_routing_headers(
                &built,
                "changes",
                args.as_object(),
                &["scope".into()],
                Some(&schema),
            )
            .is_err()
        );
        assert!(
            validate_optional_event_routing_headers(
                &built,
                "changes",
                args.as_object(),
                &["nested".into()],
                Some(&schema),
            )
            .is_err()
        );
        let wrong = json!({"repo": "other/app", "nested": {"count": 7}, "scope": "all"});
        assert!(
            validate_optional_event_routing_headers(
                &built,
                "changes",
                wrong.as_object(),
                &[],
                Some(&schema),
            )
            .is_err()
        );
    }

    #[test]
    fn integer_headers_compare_decimal_and_exponent_spellings_without_rounding() {
        let big = json!(1_000_000_000_000_000_000_u64);
        for header in ["1e18", "1000000000000000000.0", "10000000000000000000e-1"] {
            assert!(header_matches_scalar(header, &big), "{header}");
        }
        for header in ["1000000000000000001.0", "1.000000000000000001e18", "1e17"] {
            assert!(!header_matches_scalar(header, &big), "{header}");
        }
        assert!(header_matches_scalar(
            "-9.223372036854775808e18",
            &json!(i64::MIN),
        ));
        assert!(header_matches_scalar(
            "18446744073709551615.0",
            &json!(u64::MAX),
        ));
        assert!(!header_matches_scalar(
            "18446744073709551614.0",
            &json!(u64::MAX),
        ));
        assert!(header_matches_scalar("-0.000e+200", &json!(0)));
        assert!(!header_matches_scalar("1e-1", &json!(0)));
        assert!(!header_matches_scalar("1e39", &json!(0)));
    }

    #[test]
    fn exponent_bodies_accept_exact_integer_headers_and_keep_float_round_trips() {
        let body = json!(1e18_f64);
        assert!(header_matches_scalar("1000000000000000000", &body));
        assert!(!header_matches_scalar("1000000000000000001", &body));
        for body in [
            json!(1e18_f64),
            json!(9.223372036854776e18_f64),
            json!(1e38_f64),
        ] {
            assert!(header_matches_scalar(&body.to_string(), &body));
        }
        assert!(!header_matches_scalar("2", &json!(1.5)));
    }

    #[test]
    fn base64_prefix_round_trips_and_numeric_headers_reject_loose_formats_and_u64_collisions() {
        // Unclosed `=?base64?foo` must be base64-wrapped on encode so decode round-trips cleanly.
        let unclosed = "=?base64?foo";
        let encoded = encode_mcp_header_value(unclosed);
        assert_ne!(encoded, unclosed);
        assert_eq!(decode_mcp_header_value(&encoded).as_deref(), Some(unclosed));

        let args = json!({
            "pr": 42,
            "big": u64::MAX,
            "ratio": 1.5
        });
        let args_map = args.as_object().unwrap();

        // Reject `+42`, leading-zero `042`, and leading/trailing whitespace.
        for bad in ["+42", "042", " 42", "42 ", "\t42"] {
            let mut h = HeaderMap::new();
            h.insert(
                "mcp-param-pr",
                encode_mcp_header_value(bad).parse().unwrap(),
            );
            assert!(
                validate_optional_event_routing_headers(&h, "ci.build", Some(args_map), &[], None)
                    .is_err(),
                "expected {bad:?} to be rejected"
            );
        }

        // Exact u64::MAX matches itself, but distinct u64::MAX - 1 (same f64) is rejected.
        let mut ok_big = HeaderMap::new();
        ok_big.insert("mcp-param-big", u64::MAX.to_string().parse().unwrap());
        assert!(
            validate_optional_event_routing_headers(&ok_big, "ci.build", Some(args_map), &[], None)
                .is_ok()
        );

        let mut collision_big = HeaderMap::new();
        collision_big.insert("mcp-param-big", (u64::MAX - 1).to_string().parse().unwrap());
        assert!(
            validate_optional_event_routing_headers(
                &collision_big,
                "ci.build",
                Some(args_map),
                &[],
                None
            )
            .is_err()
        );

        // Whitespace-padded float is also rejected.
        let mut padded_float = HeaderMap::new();
        padded_float.insert(
            "mcp-param-ratio",
            encode_mcp_header_value(" 1.5 ").parse().unwrap(),
        );
        assert!(
            validate_optional_event_routing_headers(
                &padded_float,
                "ci.build",
                Some(args_map),
                &[],
                None
            )
            .is_err()
        );
    }
}
