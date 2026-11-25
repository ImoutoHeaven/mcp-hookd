# mcp-hookd Architecture and Protocol Design

`mcp-hookd` terminates MCP Events webhook subscriptions (`events/subscribe`, `events/unsubscribe`), merges event catalogs (`events/list`), validates and fans out locally ingested events (`POST /v1/events`), and delivers signed Standard Webhooks over HTTPS while remaining transparent to standard Streamable HTTP MCP traffic when fronting an upstream server.

## 1. Deployment Topologies and Route Boundaries

`mcp-hookd` supports three deployment shapes:

1. Gateway-chained upstream bridge: `MCP Client -> oauth2-mcp-gateway -> mcp-hookd -> Standard HTTP MCP Server`, optionally combined with local event producers posting to `POST /v1/events`.
2. Reverse-proxy-fronted upstream bridge: `MCP Client -> TLS Reverse Proxy -> mcp-hookd -> Standard HTTP MCP Server` authenticated with static `inbound_tokens`.
3. Standalone webhook ingest daemon: `MCP Client -> Gateway or Reverse Proxy -> mcp-hookd` with `ingest` configured and `upstream` omitted.

All inbound HTTP traffic arrives on `listen` and dispatches across four disjoint route boundaries:

| Route | Active When | Authentication | Responsibility |
| :--- | :--- | :--- | :--- |
| `<resource_path>` (default `/mcp`) | Always | `Origin` check + `inbound_tokens` + optional `auth_context` | MCP Streamable HTTP endpoint (`POST`, `GET`, `DELETE`); handles webhook subscriptions, capability injection, policy checks on `events/poll\|stream`, and streaming passthrough to `upstream`. |
| `POST /v1/events` | `ingest` configured (`404` otherwise) | `ingest.tokens` (`Authorization: Bearer`) | Accepts a single `application/json` event object up to `256 KiB` (NDJSON line-splitting is performed client-side by `mcp-hookd emit --stream`), validates against precompiled `payload_schema`, deduplicates `(token_slot, name, eventId)`, and enqueues matching webhook deliveries. |
| `<passthrough_prefixes>` | `upstream` configured | `Origin` check (capability URL; no `inbound_tokens` required) | Raw HTTP (`GET`, `HEAD`, `PUT`) passthrough to the `upstream.url` origin (for example `/t/` capability file transfer routes) after path normalization; strips inbound `Authorization` and never injects `upstream.bearer_token`. |
| `GET /healthz` | Always | None | Liveness probe returning `200 OK` with `{"ok":true}`. |

### Origin Validation, Path Normalization, and Header Sanitization

Requests on `<resource_path>` and `<passthrough_prefixes>` that include an `Origin` header must match either an entry in `allowed_origins` (`scheme://host[:port]` with no path, query, or fragment) or a local `http` origin on the bound port (`http://127.0.0.1:<port>`, `http://localhost:<port>`, `http://[::1]:<port>`, or `http://<bound_ip>:<port>`). Disallowed, duplicate, or malformed `Origin` headers are rejected with `403 Forbidden` before body reads or upstream forwarding.

Each entry in `upstream.passthrough_prefixes` must start and end with `/` (`len >= 3`), contain no `..`, `\`, `?`, `#`, `%`, `//`, whitespace, or control characters, and share no prefix overlap with `<resource_path>`, reserved routes (`/healthz`, `/healthz/`, `/v1/`, `/v1/events`), or the `upstream.url` path. Candidate passthrough paths undergo up to `8` rounds of percent-decoding; `mcp-hookd` rejects paths containing `\`, `;`, NUL, control characters, malformed `%` sequences, empty segments (`//`), dot segments (`.` or `..`), or decodable `%` sequences remaining after round `8` with `400 Bad Request`, and requires both the raw path and fully decoded path to match the configured prefix.

Before forwarding any request to `upstream`, `mcp-hookd` strips:

- RFC 9110 hop-by-hop headers (`connection`, `keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`, `trailers`, `transfer-encoding`, `upgrade`) plus every header name nominated inside inbound `Connection` headers;
- `authorization`, `cookie`, `origin`, and `host`;
- All `x-authorization-*` delegation headers;
- Inbound proxy and client-IP headers (`forwarded`, `x-forwarded-*`, `x-real-ip`, `cf-connecting-ip`, and `true-client-ip`) to prevent client spoofing of proxy metadata.

`mcp-hookd` then sets `Host` to the `upstream.url` authority, sets `X-Forwarded-Proto` from the `upstream.url` scheme, and injects `Authorization: Bearer <upstream.bearer_token>` only on `<resource_path>` upstream calls (never on `passthrough_prefixes`). Hop-by-hop headers are also stripped from upstream responses before relay.

## 2. Orthogonal Passthrough and On-Demand Protocol Validation

When `upstream` is configured, the upstream MCP server is the sole validation authority for `Content-Type`, `Accept`, session lifecycle (`Mcp-Session-Id`), protocol version negotiation (`MCP-Protocol-Version`), and non-local JSON-RPC methods. `mcp-hookd` avoids imposing SDK-specific framing rules on traffic it does not terminate, while unconditionally rejecting compressed (`Content-Encoding` other than `identity`) `POST <resource_path>` requests so encoded bodies cannot obscure controlled MCP methods.

### Method and Verb Routing on `<resource_path>`

- `GET <resource_path>` and `DELETE <resource_path>`: With `upstream` configured, requests stream directly to `upstream` after `Origin`, hop Bearer auth, `auth_context` verification, and header sanitization, preserving `Mcp-Session-Id`, `MCP-Protocol-Version`, and `Last-Event-ID`. Without `upstream`, `GET` returns `405 Method Not Allowed` and `DELETE` terminates local legacy sessions (`202 Accepted` if active, `404 Not Found` if unknown, `405 Method Not Allowed` for stateless `2026-07-28` without a session, or `400 Bad Request` when `Mcp-Session-Id` is missing or malformed).
- `POST <resource_path>`: Requests carrying a non-empty `Content-Encoding` other than `identity` (case-insensitive) immediately return `415 Unsupported Media Type` regardless of `upstream` or `Mcp-Method`. Non-`application/json` `Content-Type` bodies stream directly to `upstream` (`415` when standalone). JSON request chunks are bounded by `MAX_REQUEST_BODY_BYTES` (`16 MiB` total across prefix and streamed frames, `413 Payload Too Large` when exceeded) and `BODY_READ_TIMEOUT` (`30s` inter-frame read bound, `408 Request Timeout` when exceeded) under `PROXY_BYTE_BUDGET` (`64 MiB` total pool), and are inspected by a zero-AST streaming JSON lexical scanner.

### Zero-AST Streaming JSON Lexical Scanner

The scanner validates RFC 8259 JSON tokens and UTF-8 strings over raw bytes without allocating a `serde_json::Value` tree. Every incoming chunk is scanned to its end (with no early short-circuit after the first `"method"`), and when a request transitions to streaming `PrefixedBody` passthrough before root JSON EOF, the scanner moves into `PrefixedBody` to validate every subsequent frame and final EOF closure:

- On root JSON objects `{...}`, a non-string depth-1 `"method"` or a duplicate depth-1 `"method"` immediately returns `400 Bad Request` with JSON-RPC `-32600` (echoing any valid `id` already captured, or `null`) without buffering the rest of a `16 MiB` payload; if a second depth-1 `"method"`, syntax error, or trailing non-whitespace token appears in a later streamed frame, `PrefixedBody` aborts the outbound stream before yielding that frame and maps the client response directly to `400 Bad Request` (`-32600` or `-32700`).
- On root JSON batch arrays `[...]`, the scanner inspects every depth-2 element object across single-buffer and multi-chunk `PrefixedBody` streams: empty batches `[]`, non-object elements, elements with non-string or duplicate `"method"`, or any element whose `"method"` matches one of the seven controlled methods (`initialize`, `server/discover`, `events/list`, `events/subscribe`, `events/unsubscribe`, `events/poll`, `events/stream`) are rejected with `400 Bad Request` and JSON-RPC `-32600`.

Once the current chunk finishes scanning cleanly, `mcp-hookd` splices the validated prefix ahead of the remaining `hyper::body::Incoming` stream (`PrefixedBody`) and forwards the request to `upstream` whenever any of the following holds:

1. `Content-Type` is anything other than `application/json` (with `identity` or omitted `Content-Encoding`);
2. The top-level JSON value is a non-empty `[...]` batch of objects containing only non-controlled methods (for example `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`) or client `Response`/`Error` objects;
3. The top-level JSON object is a client-to-server JSON-RPC `Response` or `Error` without `"method"` (for example client replies to upstream `sampling/createMessage`, `elicitation/create`, `roots/list`, or `ping` requests);
4. The top-level `"method"` is a valid string outside the seven locally inspected methods listed below.

| Method Group | Methods | Validation and Handling Contract |
| :--- | :--- | :--- |
| Locally terminated | `events/list`, `events/subscribe`, `events/unsubscribe` | Full JSON-RPC 2.0 request validation (`jsonrpc: "2.0"`, non-null string or exact integer `id`, object `params`), `Content-Type` / `Accept` checks, and protocol version / session validation (`2026-07-28` stateless vs `2024-11-05`..`2025-11-25` session-bound). `events/list` merges cached upstream `expose_events` (`30s` TTL) with local `ingest.events` (`100` descriptors per page). |
| Policy-filtered passthrough | `events/poll`, `events/stream` | Rejects `ingest.events` names with profile `Unsupported` error (`ingest` events support `"webhook"` only), enforces `upstream.expose_events[*].disallow_arguments`, and checks optional `Mcp-Name` and `Mcp-Param-*` headers against `params`. Event names absent from the 30-second catalog cache forward directly to `upstream` so the upstream server decides unknown events. |
| Handshake capability injection | `initialize`, `server/discover` | Forwards handshake to `upstream` and on modern handshakes injects `capabilities.extensions["io.modelcontextprotocol/events"] = {"listChanged": false}` (plus `capabilities.events = {}` under `chatgpt`; on legacy `< 2026-07-28` handshakes `chatgpt` injects `capabilities.events = {}`). Without `upstream`, handles handshakes locally (`MAX_LEGACY_SESSIONS = 1024`, `3600s` idle TTL). |
| Transparent passthrough | All other methods (`tools/*`, `resources/*`, `prompts/*`, `ping`, custom methods), batches, client `Response`/`Error` | Zero local JSON-RPC, header, or session validation; buffered prefix + unread `Incoming` body stream straight to `upstream`. Without `upstream`, `ping` succeeds locally, notifications return `202 Accepted`, and unknown methods return `-32601`. |

### Streaming Handshake Rewrite (`HandshakeSseBody`)

When `upstream` answers `initialize` or `server/discover` with `application/json`, `mcp-hookd` reads up to `MAX_HANDSHAKE_BODY_BYTES` (`1 MiB`), injects `capabilities.extensions["io.modelcontextprotocol/events"] = {"listChanged": false}` (and `capabilities.events = {}` under `chatgpt`), and updates the response body. When `upstream` answers with `text/event-stream`, `mcp-hookd` strips any fixed `Content-Length` header and wraps the upstream stream in `HandshakeSseBody`. `HandshakeSseBody` implements `http_body::Body` as a streaming state machine: it buffers SSE frames only up to `MAX_HANDSHAKE_BODY_BYTES` until locating the JSON-RPC response frame whose `id` matches the handshake request, rewrites that single `data:` payload in place, and then forwards every subsequent SSE notification or server-to-client request frame verbatim until upstream EOF.

### Optional Event Routing Headers (`Mcp-Name` and `Mcp-Param-*`)

On `events/poll`, `events/stream`, `events/subscribe`, and `events/unsubscribe`, clients may attach `Mcp-Name` and `Mcp-Param-<key>` headers for HTTP-layer routing:

- Values containing control characters, non-ASCII UTF-8, leading/trailing spaces or tabs, or a literal `=?base64?` prefix use RFC 2047-style `=?base64?<standard-base64>?=` encoding.
- Properties annotated with `"x-mcp-header": "<Alias>"` in `inputSchema` bind `Mcp-Param-<Alias>` (case-insensitively) to that scalar property path (`string`, `integer`, or `boolean`).
- Invalid or duplicate `Mcp-Name` headers, invalid or duplicate `Mcp-Param-*` headers, headers targeting `disallow_arguments`, headers referencing missing, `null`, or unmapped non-scalar arguments, and scalar mismatches against `params` return HTTP `400 Bad Request` with JSON-RPC error `-32020`.
- Numeric header values are compared using exact `i128` integer arithmetic across decimal and scientific-notation spellings (rejecting leading `+`, leading zeros, whitespace padding, and `u64` values that collide only after `f64` rounding).

## 3. Delegated Authorization and HTTP Status Semantics

`mcp-hookd` separates hop-to-hop service authentication from end-user OAuth delegation so downstream HTTP status codes compose cleanly with `oauth2-mcp-gateway` and standard RFC 6750 / RFC 9728 MCP clients.

### Hop Authentication (`inbound_tokens`)

Every request to `<resource_path>` must carry a single `Authorization: Bearer <token>` header matching an entry in `inbound_tokens` under constant-time comparison (`subtle::ConstantTimeEq`). Capability URL routes under `<passthrough_prefixes>` do not require `inbound_tokens`; they enforce browser `Origin` validation, strip any inbound `Authorization` header, and never inject `upstream.bearer_token`. Every static token configured in `inbound_tokens[*]`, `auth_context.check_token`, `upstream.bearer_token`, and `ingest.tokens[*]` must be at least `16` visible ASCII characters (`0x21..=0x7E`). When `auth_context` is omitted, the authenticated caller principal is `token:<slot_index>`.

### Delegated Subject Authorization (`auth_context`)

Enabling `auth_context` requires `listen` to be a literal loopback IP (`127.0.0.0/8` or `[::1]`), preventing untrusted network peers from spoofing `X-Authorization-*` headers directly. Plain `http://` in `auth_context.check_url` is likewise restricted to literal loopback IPs.

At the `<resource_path>` entry for every HTTP method (`GET`, `POST`, `DELETE`), `mcp-hookd` extracts `X-Authorization-Ref` (`1..=256` visible ASCII bytes) and `X-Authorization-Scope` (space-delimited RFC 6749 scope tokens) and verifies the grant against `POST <auth_context.check_url>` (`Authorization: Bearer <check_token>`, request body `{"ref":"<auth_ref>"}`, `5s` timeout, `4 KiB` response cap). Concurrent checks for the same `auth_ref` coalesce behind a per-ref single-flight lock, and definitive outcomes cache for `reverify_secs` (`default 15s`, range `5..=300s`, capped at `4096` entries).

Effective caller scopes equal `header_scopes ∩ checked.scopes`. Subscription TTLs clamp `refresh_before` to `min(now + effective_ttl, checked.expires_at)`.

| Condition at `<resource_path>` | HTTP Status | `WWW-Authenticate` Header | `oauth2-mcp-gateway` Handling (`auth_context` Enabled) |
| :--- | :--- | :--- | :--- |
| Missing, malformed, or mismatched hop `Authorization` (`inbound_tokens`) | `401 Unauthorized` | `Bearer` | Treated as hop misconfiguration; rewritten to `502 Bad Gateway`. |
| Missing, duplicate, or invalid `X-Authorization-Ref` or `X-Authorization-Scope` | `400 Bad Request` | Omitted | Relayed as `400 Bad Request`. |
| `check_url` timeout, network error, HTTP `5xx`, or invalid check payload | `503 Service Unavailable` | Omitted | Relayed as `503 Service Unavailable`. |
| Grant `active: false`, `expiresAt <= now`, or `resource != expected_resource` | `401 Unauthorized` | `Bearer error="invalid_token"` | Status and JSON body preserved; gateway synthesizes public `WWW-Authenticate` with its own `resource_metadata` URL. |
| Empty `header_scopes ∩ checked.scopes`, or subscription refresh narrowing previously `granted_scopes` | `403 Forbidden` | `Bearer error="insufficient_scope"` (plus required `scope="..."` on narrowed refresh) | Status and JSON body preserved; gateway synthesizes public `WWW-Authenticate` with `error="insufficient_scope"` and public `resource_metadata`. |

### Continuous Re-Verification, Startup Gating, and Instance-Exact Revocation

`mcp-hookd` re-verifies `auth_ref` before outbound webhook deliveries and on periodic sweeps (`reverify_secs`). If a grant becomes inactive, changes `resource`, or narrows scopes below the subscription's persisted `granted_scopes`, `mcp-hookd` revokes only the exact `SubRuntime` instance that failed verification (`Arc::ptr_eq`), clears its outbox, cancels its upstream stream/poll tasks, and marks state dirty. Under the `sep3415` profile, it then acquires the subscription's `key_lock` and global delivery permit, confirms no replacement subscription has been registered under the same `SubscriptionKey`, and posts `{"type":"terminated","reason":"authorization_revoked"}`. Serializing termination on `key_lock` prevents an older revocation task from delivering `terminated` after a rapid re-subscribe to the same key.

On startup with `auth_context` enabled, persisted subscriptions carrying an `auth_ref` remain gated (no upstream consumption or outbound webhook delivery) until `run_startup_auth_recovery` confirms their grants against `check_url`, retrying transient check failures with exponential backoff and revoking grants confirmed inactive.

## 4. `sep3415` and `chatgpt` Profile Mapping

A single `mcp-hookd` instance runs under either `"profile": "sep3415"` or `"profile": "chatgpt"`. Both profiles use identical `SubscriptionKey` derivation: `principal \0 url \0 event_name \0 RFC8785_JCS(arguments)` hashed with SHA-256 to form `sub_<32-lowercase-hex>`. Exact JSON integers are required for JCS canonicalization. On protocol version `2026-07-28`, JSON-RPC `result` objects include `_meta` framing per modern Streamable HTTP conventions; legacy sessions (`2024-11-05`..`2025-11-25`) omit modern result type annotations.

| Behavior Dimension | `sep3415` Profile | `chatgpt` Profile |
| :--- | :--- | :--- |
| `NotFound` JSON-RPC error | `-32023`, `data: {"kind": "event" \| "subscription"}` | `-32602`, `data: {"kind": "event" \| "subscription"}` |
| `Forbidden` JSON-RPC error | `-32024` | `-32012` |
| `ResourceExhausted` JSON-RPC error | `-32025` | `-32602` |
| `Unsupported` JSON-RPC error | `-32026` | `-32602` |
| `CallbackEndpoint` JSON-RPC error | `-32027`, `data: {"reason": "<reason>"}` | `-32015`, `data: {"reason": "<reason>"}` |
| `events/unsubscribe` when subscription is absent | Returns `-32023` (`{"kind":"subscription"}`) | Idempotent success (`result: {}`) |
| Outbound event `webhook-id` header | Fresh `msg_<24-char-base64url>` per queued envelope | Event `eventId` verbatim (upstream events with non-token `eventId` are skipped via `Checkpoint`) |
| Upstream cursor gap (`truncated: true`) | Delivers signed `{"type":"gap","cursor":"<cursor>"}` webhook with transient retries before advancing `safe_cursor` | Suppresses `gap` webhook; sets `pending_truncated_for_refresh = true` so the next `events/subscribe` refresh returns `"truncated": true` |
| Delegated grant revocation | Sends best-effort signed `{"type":"terminated","reason":"authorization_revoked"}` under `key_lock` | Drops subscription silently without `terminated` webhook |

`CallbackErrorReason` values in `error.data.reason` and `deliveryStatus.lastError` are `"challenge_failed"`, `"timeout"`, `"connection_refused"`, `"tls_error"`, `"http_4xx"`, and `"http_5xx"`.

### Outbound Event Envelope and SEP-3415 Ingest Contract

Outbound event webhooks carry a canonical JSON envelope (`<= 256 KiB`):

```json
{
  "type": "event",
  "eventId": "evt_01J...",
  "name": "ci.build_failed",
  "timestamp": "2026-11-25T18:00:00Z",
  "data": { "repo": "org/service" },
  "cursor": "cur_42"
}
```

`cursor` is `null` for `ingest` events and carries the upstream watermark string (or `null`) for `upstream` events. `POST /v1/events` accepts a single `application/json` event object (`mcp-hookd emit --stream` splits NDJSON lines on the client before posting each object). Both `POST /v1/events` and `mcp-hookd emit` restrict top-level JSON keys to SEP-3415 `EventOccurrence` fields (`eventId`, `name`, optional RFC 3339 `timestamp`, `data`) plus optional ignored stream-wrapper keys (`cursor`, `_meta`), require `eventId` to match `[A-Za-z0-9_-]{1,128}`, and deduplicate by `(token_slot, name, eventId)`. Control-plane or unknown top-level keys such as `truncated` or `upstreamEventId` are rejected immediately with HTTP `400` / validation error.

## 5. Standard Webhooks Signing, Secret Rotation, and Callback Verification

### Standard Webhooks `v1` Signing and Dual-Secret Window

Subscription requests supply `params.delivery.secret` formatted as `whsec_<standard-base64>`, decoding to `32..=64` raw key bytes. Secrets live in `SecretString`, which zeroes backing memory on drop (`zeroize`) and formats as `[REDACTED]` in `Debug` and `Display`.

Every outbound `POST` (verification, `event`, `gap`, and `terminated`) uses HTTP/1.1 (`ALPN: http/1.1`) and includes:

- `Content-Type: application/json`
- `webhook-id: <id>`
- `webhook-timestamp: <unix_epoch_seconds>`
- `webhook-signature: v1,<base64(HMAC-SHA256(key, "{webhook-id}.{webhook-timestamp}.{raw_body}"))>`
- `X-MCP-Subscription-Id: sub_<32-hex>`

When a subscriber refreshes an existing subscription with a rotated `whsec_` secret, `mcp-hookd` moves the previous secret into `prev_secret` with `prev_secret_until = unix_now() + 300` (`DUAL_SECRET_WINDOW_SECS = 300`). Throughout that 300-second window, outbound requests emit space-separated dual signatures (`webhook-signature: v1,<old_sig> v1,<new_sig>`) so receivers can roll over keys without dropping in-flight deliveries.

### Callback Verification Challenge and Fail-Closed Rate Limiting

Before activating a new endpoint or unsuspending a `suspended` subscription, `mcp-hookd` performs a synchronous challenge:

1. Sends a signed `POST` to `delivery.url` with `webhook-id: msg_verification_<32-hex>` and body `{"type":"verification","challenge":"<48-hex>"}` (`VERIFY_TIMEOUT = 5s`, response body capped at `MAX_VERIFY_RESP_BYTES = 16 KiB`).
2. Requires a `2xx` JSON response `{"challenge":"..."}` whose `challenge` string matches in constant time.
3. Records `(principal, url, sha256_hex(secret))` in the verified-endpoint cache (`VERIFIED_RETENTION_SECS = 3600`, `MAX_VERIFIED_ENDPOINTS = 1024`, persisted in `subscriptions.json`) so subsequent refreshes or sibling event subscriptions sharing the same `(principal, url, secret)` skip redundant round-trips. Refreshing a `suspended` subscription bypasses this cache and forces a live challenge.

To prevent `events/subscribe` from being abused as a reflection or port-scanning amplifier, callback verification enforces a fail-closed three-dimensional sliding-window rate limiter over `VERIFY_RATE_WINDOW = 60s`:

- Dimension 1 checks `(principal, callback_host)` (`VERIFY_RATE_LIMIT = 20 / 60s`) before DNS resolution or TCP dial;
- Dimension 2 checks the caller's aggregate principal budget across all callback hosts (`VERIFY_PRINCIPAL_RATE_LIMIT = 60 / 60s`) before DNS resolution or TCP dial;
- Dimension 3 checks the target address prefix (`VERIFY_IP_RATE_LIMIT = 20 / 60s`), keyed by IPv4 `/32` (unwrapping `::ffff:a.b.c.d`) or IPv6 `/64` prefix so rotating hostnames or interface identifiers within one IPv6 `/64` subnet share a single target budget, enforced before every `TcpStream::connect` dial in `SafeHttpsConnector` (including multi-record fallback dials) and against `ConnMeta.peer_ip` when reusing an idle keep-alive connection;
- Active rate-limit tables are each bounded by a hard cap of `4096` unexpired entries (`MAX_VERIFY_RATE_ENTRIES = 4096`, `MAX_VERIFY_IP_ENTRIES = 4096`); if `4096` unexpired buckets are occupied after pruning expired windows, new bucket allocations fail closed with `ResourceExhausted` rather than evicting tracked callers.

## 6. Anti-DNS-Rebinding Outbound Connector (`SafeHttpsConnector`)

Callback URLs must use `https://` with a non-empty host, no userinfo, and no `#fragment`. `SafeHttpsConnector` hardens every outbound webhook connection against SSRF and DNS rebinding:

1. Fresh resolution per dial: Every new TCP connection resolves `(host, port)` via DNS and rejects the entire connection attempt (`DisallowedIp`) if **any** returned `A` or `AAAA` address falls outside globally routable unicast space. Mixed public/private round-robin DNS records are rejected outright.
2. IP-pinned dial with hostname-pinned TLS: `TcpStream` connects directly to the validated `SocketAddr`, while `tokio-rustls` (`ring` provider + OS native root certificates via `rustls-native-certs`) verifies TLS SNI and server certificates against the original hostname.
3. Zero redirect following: `3xx` responses are never followed; verification rejects them with `ChallengeFailed` and event delivery treats them as transient `Http4xx` errors.
4. Connection lifetime poisoning (`CONN_MAX_LIFETIME_SECS = 60`, `POOL_IDLE_TIMEOUT = 15s`): Each `SafeHttpsStream` records `created_at = Instant::now()` at TCP connect. `OutboundClient` inspects elapsed connection age both before and after reading the response body (and on request timeout) and calls `conn.poison()` on the hyper pool handle once `60s` has elapsed, forcing periodic DNS re-resolution and IP re-validation.

### Blocked IANA Non-Global Address Ranges

IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are unwrapped and checked against the IPv4 rules first. Loopback callbacks remain blocked unless internal test quotas explicitly opt in.

| Family | Blocked Ranges and Gate Rule | Purpose / RFC |
| :--- | :--- | :--- |
| IPv4 | `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4` (including `255.255.255.255/32`) | "This" network, RFC 1918 private, RFC 6598 CGNAT, loopback, link-local / cloud metadata, IETF assignments, TEST-NET-1/2/3, 6to4 relay anycast, benchmarking, multicast, reserved/broadcast. |
| IPv6 outer gate | Anything outside `2000::/3` (`(seg0 & 0xe000) != 0x2000`) | Blocks `::/128`, `::1/128` loopback, `64:ff9b::/96` & `64:ff9b:1::/48` NAT64, `100::/64` discard, `fc00::/7` ULA, `fe80::/10` link-local, and `ff00::/8` multicast. |
| IPv6 inner exclusions | `2001::/32` (Teredo), `2001:2::/48` (BMWG benchmarking), `2001:3::/32` (AMT), `2001:4:112::/48` (AS112-v6), `2001:10::/28` (ORCHID), `2001:20::/28` (ORCHIDv2), `2001:30::/28` (Drone Remote ID / DETS), `2001:db8::/32` (documentation), `2002::/16` (6to4), `2620:4f:8000::/48` (Direct Delegation AS112), `3fff::/20` (RFC 9637 documentation) | Blocks all non-globally-reachable special-purpose allocations inside `2000::/3`. |

## 7. Offline Precompiled JSON Schema Validation

`mcp-hookd` compiles `jsonschema` without `resolve-http`, `resolve-file`, `resolve-async`, or `tls-ring` features and supplies a custom offline `Retrieve` implementation that rejects every external `$ref` URI (`http://`, `https://`, `file://`, or custom schemes). Untrusted upstream `inputSchema` documents cannot trigger outbound SSRF or local file reads.

Schema compilation is amortized off the request hot path:

- For `ingest.events[*]`, startup (`Config::load_from_path`) validates `payload_schema` against its bundled Draft 4 / 6 / 7 / 2019-09 / 2020-12 meta-schema, derives the flat object `input_schema` from scalar `filter_fields` (`string`, `integer`, `boolean`), and precompiles both `Validator` instances once.
- For `upstream.expose_events[*]`, `Validator` instances for upstream `inputSchema` descriptors are precompiled whenever the 30-second catalog cache refreshes rather than recompiled on every `events/subscribe` call.

## 8. Ordered Watermark, Retry/Suspend Lifecycle, and Atomic Persistence

### Per-Subscription Outbox and `safe_cursor` State Machine

Each subscription runs a single serialized delivery loop (`MAX_IN_FLIGHT_PER_SUB = 1`) fed by a bounded FIFO outbox (`MAX_OUTBOX_PER_SUB = 64`) and throttled globally by `MAX_GLOBAL_DELIVERIES = 64`:

- Upstream consumption prefers `events/stream` (`MAX_UPSTREAM_STREAMS = 16`) and falls back to `events/poll`, seeding initial historical batches gracefully when `cursor` is `None` and `maxAgeMs` is supplied so neither returned events nor replay cursors are lost.
- `safe_cursor` is the persisted recovery watermark. It advances strictly in order only after an item completes:
  - `2xx` response: item pops and `safe_cursor` advances to `advance_cursor` (when present);
  - Permanent `4xx` (`400`, `410`, `413`, `422`): item drops permanently without stalling subsequent events and `safe_cursor` advances;
  - Oversized upstream envelopes (`> 256 KiB`) or invalid `chatgpt` event IDs enqueue lightweight `Checkpoint` items so `safe_cursor` advances once all preceding deliveries finish;
  - Transient failures (`5xx`, `3xx`, `401`, `403`, `404`, `408`, `429`, timeouts, TCP/TLS errors) on both `Event` and `Gap` (`sep3415`) items back off exponentially (`retry_base_ms * 2^min(attempt, 5)` plus `0..=25%` random jitter, up to `MAX_TRANSIENT_RETRIES = 6` per cycle) with the item kept at the head of the outbox.
- Suspension: If consecutive transient failures reach `suspend_failure_count = 12` and span at least `suspend_min_duration_secs = 180s`, the subscription sets `suspended = true`, records `last_error`, cancels upstream consumption, and persists state. For `Ingest` subscriptions (which have no upstream replay cursor), entering `suspended` immediately clears `outbox` so held `ByteLease` allocations return to `OUTBOX_BYTE_BUDGET` (`64 MiB`) instead of pinning memory until TTL expiry. Refreshing via `events/subscribe` re-verifies the callback URL, clears `suspended`, and returns the prior state in `deliveryStatus: { "active": false, "lastError": "<reason>" }`.

### Atomic State Persistence and Graceful Shutdown

`StateStore` persists `PersistedState` (`version: 1`, `subscriptions`, `verified_endpoints`) to `state_path` with a `25ms` group-commit debounce (`DEFAULT_GROUP_COMMIT_DEBOUNCE`):

- Both startup reads and runtime writes enforce `MAX_STATE_FILE_BYTES = 16 MiB`. A snapshot exceeding `16 MiB` fails the save and leaves the previously committed `state_path` intact; startup rejects oversized, symlinked, or multi-hardlinked state files and requires owner-only permissions (`0600` file and non-world/group-writable parent on Unix, owner-only DACL via `SetFileSecurity` / `CreateFileW` security attributes on Windows).
- Saves write to a sibling random temporary file created with `0600` / owner-only permissions, flush via `File::sync_all()`, atomically `rename` over `state_path`, and `sync_all()` the parent directory on Unix. Stale sibling temp files from prior crashes are cleaned on open.
- On `SIGINT` / `SIGTERM` (or Ctrl+C on Windows), `mcp-hookd` stops accepting new subscriptions, cancels upstream streams and background loops, flushes dirty state, and waits up to `DRAIN_TIMEOUT_SECS = 10s` for in-flight deliveries to settle.

## 9. Memory, Concurrency, Size, and Timing Quotas

Memory across data planes is partitioned into three atomic `ByteBudget` pools (`outbox`, `proxy`, `control`) so traffic spikes in one plane cannot starve another.

| Constant / Parameter | Value | Scope and Enforcement |
| :--- | :--- | :--- |
| `OUTBOX_BYTE_BUDGET` | `64 MiB` | Global queued webhook envelope byte budget across all subscriptions. |
| `PROXY_BYTE_BUDGET` | `64 MiB` | Global request/response streaming buffer budget for `<resource_path>` and passthrough proxying. |
| `CONTROL_BYTE_BUDGET` | `8 MiB` | Control-plane memory pool for catalog/handshake/ingest bookkeeping. |
| `MAX_CONFIG_FILE_BYTES` | `1 MiB` | Maximum `hookd.json` file size. |
| `MAX_STATE_FILE_BYTES` | `16 MiB` | Maximum `subscriptions.json` size on startup load and atomic save. |
| `MAX_REQUEST_BODY_BYTES` | `16 MiB` | Maximum inbound `POST <resource_path>` JSON request body size across buffered inspection and streaming `PrefixedBody` passthrough. |
| `MAX_HANDSHAKE_BODY_BYTES` | `1 MiB` | Maximum upstream `initialize` / `server/discover` body buffered before capability rewrite. |
| `MAX_INGEST_BODY_BYTES` | `256 KiB` | Maximum `POST /v1/events` single-event JSON request body. |
| `MAX_WEBHOOK_PAYLOAD_BYTES` | `256 KiB` | Maximum outbound serialized webhook JSON envelope. |
| `MAX_EMIT_INPUT_BYTES` | `1 MiB` | Maximum single JSON input read by `mcp-hookd emit`. |
| `MAX_VERIFY_RESP_BYTES` | `16 KiB` | Maximum callback verification response body read. |
| `MAX_DELIVERY_RESP_BYTES` | `4 KiB` | Maximum webhook delivery response body drained. |
| `MAX_AUTH_CHECK_RESP_BYTES` | `4 KiB` | Maximum `POST /authorization/check` response body read. |
| `MAX_PING_BODY_BYTES` | `4 KiB` | Maximum upstream ping/probe body read. |
| `MAX_SUBSCRIPTIONS` | `256` | Global active + suspended webhook subscription cap. |
| `MAX_PER_PRINCIPAL` | `64` | Maximum subscriptions owned by a single `principal`. |
| `MAX_OUTBOX_PER_SUB` | `64` | Maximum queued envelopes per subscription outbox. |
| `MAX_IN_FLIGHT_PER_SUB` | `1` | Strictly serialized in-flight HTTP delivery per subscription. |
| `MAX_GLOBAL_DELIVERIES` | `64` | Global concurrent outbound webhook HTTP requests (`Semaphore`). |
| `MAX_UPSTREAM_STREAMS` | `16` | Global concurrent upstream `events/stream` SSE consumers. |
| `MAX_DEDUP_ENTRIES` | `16,384` | Maximum `(token_slot, name, eventId)` ingest deduplication entries (`DEDUP_RETENTION_SECS = 3600`). |
| `MAX_VERIFIED_ENDPOINTS` | `1,024` | Maximum cached `(principal, url, secret_sha256)` entries (`VERIFIED_RETENTION_SECS = 3600`). |
| `MAX_LEGACY_SESSIONS` | `1,024` | Maximum standalone legacy MCP sessions (`LEGACY_SESSION_IDLE_SECS = 3600`). |
| `AUTH_CHECK_CACHE_CAP` | `4,096` | Maximum cached `auth_ref` check entries (`reverify_secs` default `15s`, range `5..=300s`). |
| `VERIFY_RATE_LIMIT` / `VERIFY_PRINCIPAL_RATE_LIMIT` | `20 / 60s`, `60 / 60s` (`4,096` max buckets) | Per-`(principal, host)` (`20 / 60s`), per-`principal` (`60 / 60s`), and per-target IPv4 `/32` or IPv6 `/64` prefix (`20 / 60s`) challenge rate limits; fails closed at `4,096` active buckets per table. |
| `DEFAULT_TTL_SECS` / Bounds | `1800s` (`60s..=86400s`) | Default subscription TTL when `ttlMs` is omitted; `max_ttl_secs` defaults to `3600s`. |
| `DUAL_SECRET_WINDOW_SECS` | `300s` | Dual `webhook-signature` grace window after secret rotation. |
| `CATALOG_CACHE_TTL` | `30s` | Upstream `events/list` descriptor and precompiled schema cache TTL. |
| `CONN_MAX_LIFETIME_SECS` | `60s` | Outbound TLS connection lifetime before pool poisoning forces fresh DNS + IP validation. |
| `VERIFY_TIMEOUT` / `DELIVERY_TIMEOUT` | `5s` / `10s` | Outbound verification challenge timeout and event delivery timeout. |
| `AUTH_CHECK_TIMEOUT` / `DEFAULT_UPSTREAM_TIMEOUT_SECS` | `5s` / `300s` | Gateway `/authorization/check` timeout and default upstream MCP request timeout. |
| `MAX_TRANSIENT_RETRIES` / Backoff | `6` (`1000ms * 2^min(n,5)` + `0..=25%` jitter) | Transient retry schedule before re-queuing; `12` failures across `>= 180s` suspends the subscription. |
| `DEFAULT_GROUP_COMMIT_DEBOUNCE` / `DRAIN_TIMEOUT_SECS` | `25ms` / `10s` | State persistence group-commit window and graceful shutdown delivery drain bound. |
