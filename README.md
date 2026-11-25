# mcp-hookd

`mcp-hookd` is a single-binary daemon for Model Context Protocol (MCP) Events webhook subscriptions, callback challenge verification, external event ingest, and signed outbound HTTPS delivery. It runs either standalone in front of local event producers or inline between `oauth2-mcp-gateway` (or a reverse proxy) and any standard Streamable HTTP MCP server.

```text
MCP Client -> oauth2-mcp-gateway / Reverse Proxy -> mcp-hookd (/mcp, /healthz)
                                                       |-> Standard HTTP MCP Server (upstream + passthrough_prefixes)
                                                       |-> Outbound HTTPS Webhooks (Standard Webhooks v1)
Local Producers / mcp-hookd emit --------------------> mcp-hookd (POST /v1/events)
```

When `upstream` is configured, `mcp-hookd` streams non-local MCP methods, responses, and batches straight through without local protocol re-validation, injects webhook event capabilities during MCP handshakes, and bridges exposed upstream events to verified HTTPS callbacks (`sep3415` or `chatgpt` profile). When `ingest` is configured, local services or `mcp-hookd emit` post single `application/json` event objects to `POST /v1/events` (`mcp-hookd emit --stream` splits NDJSON lines client-side) for offline schema validation, scalar filtering, `(token_slot, name, eventId)` deduplication, and ordered webhook delivery.

See [docs/design.md](docs/design.md) for the full architecture, wire contracts, security controls, and runtime quotas.

## Build and Test

Requires Rust 1.92 or newer and Python 3 for the test runner:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
python3 scripts/ci/run-tests.py
```

## CLI Quick Reference

| Command | Purpose |
| :--- | :--- |
| `mcp-hookd serve [-c <path>]` | Run the HTTP listener, upstream bridge, and webhook delivery workers in the foreground (`--config <path>` long form also accepted; default `hookd.json`). |
| `mcp-hookd check [-c <path>]` | Expand `"${VAR}"` placeholders, validate configuration and schemas, and exit (`--config <path>` long form also accepted; default `hookd.json`). |
| `mcp-hookd emit [--url <url>] [--name <event>] [--stream] [--on-invalid fail\|drop]` | Read a single JSON event (or newline-delimited JSON split client-side with `--stream`) from stdin and post each event object as `application/json` to `POST /v1/events` (`eventId` matching `[A-Za-z0-9_-]{1,128}`). |

Environment variables recognized by the CLI:

| Variable | Used By | Behavior |
| :--- | :--- | :--- |
| `HOOKD_CONFIG` | `serve`, `check` | Default configuration file path when `-c` / `--config` is omitted. |
| `HOOKD_INGEST_URL` | `emit` | Default ingest endpoint URL when `--url` is omitted (`http://127.0.0.1:8081/v1/events`). |
| `HOOKD_PRODUCER_TOKEN` | `emit` | Required Bearer token sent to `POST /v1/events` (must match an entry in `ingest.tokens`). |

## Minimal Configuration

Configuration files are strict UTF-8 JSON (up to `1 MiB`, no duplicate keys or unknown fields). Any string value equal to `"${VAR}"` expands once from the process environment at startup; partial string interpolation such as `"prefix-${VAR}"` is rejected. Configure `upstream`, `ingest`, or both.

```json
{
  "listen": "127.0.0.1:8081",
  "state_path": "./subscriptions.json",
  "profile": "sep3415",
  "inbound_tokens": ["${HOOKD_INBOUND_TOKEN}"],
  "ingest": {
    "tokens": ["${HOOKD_INGEST_TOKEN}"],
    "events": [
      {
        "name": "ci.build_failed",
        "description": "Fired when a CI build fails.",
        "filter_fields": ["repo"],
        "payload_schema": {
          "type": "object",
          "properties": {
            "repo": { "type": "string" }
          },
          "required": ["repo"],
          "additionalProperties": false
        }
      }
    ]
  }
}
```

Validate configuration, start the daemon, and emit a test event:

```bash
export HOOKD_INBOUND_TOKEN='inbound-hop-secret-0123456789'
export HOOKD_INGEST_TOKEN='ingest-prod-secret-0123456789'

mcp-hookd check -c hookd.json
mcp-hookd serve -c hookd.json &

HOOKD_PRODUCER_TOKEN="$HOOKD_INGEST_TOKEN" \
  mcp-hookd emit --name ci.build_failed <<< '{"data":{"repo":"org/service"}}'
```

## Core Configuration Reference

| Field | Required | Default | Rules and Security Constraints |
| :--- | :--- | :--- | :--- |
| `listen` | Yes | None | Bind socket address (`ip:port`). Must be a literal loopback IP (`127.0.0.0/8` or `[::1]`) whenever `auth_context` is configured. |
| `resource_path` | No | `"/mcp"` | MCP endpoint path starting with `/`; cannot be `/`, `/healthz`, or `/v1/events`. |
| `state_path` | Yes | None | Atomic JSON state file path (`16 MiB` read/write limit, `0600` mode on Unix, owner-only DACL on Windows). |
| `profile` | Yes | None | `"sep3415"` or `"chatgpt"`; selects JSON-RPC error codes, gap handling, and `webhook-id` derivation. |
| `inbound_tokens` | Yes | None | Non-empty list of hop Bearer tokens for `<resource_path>` and `passthrough_prefixes`; each token requires `>= 16` visible ASCII bytes (`0x21..=0x7E`). |
| `allowed_origins` | No | `[]` | Additional `scheme://host[:port]` origins allowed on `<resource_path>` alongside local `http` loopback/bound-port origins. |
| `max_ttl_secs` | No | `3600` | Maximum subscription TTL in seconds (`60..=86400`; default requested TTL when omitted is `1800`). |
| `auth_context` | No | Omitted | Delegated OAuth verification (`check_url`, `check_token` `>= 16` visible ASCII, `expected_resource`, `reverify_secs` in `5..=300` defaulting to `15`). Plain `http://` in `check_url` requires a literal loopback IP. |
| `upstream` | Conditional | Omitted | Upstream HTTP MCP target (`url`, optional `bearer_token` `>= 16` visible ASCII, `passthrough_prefixes`, `request_timeout_secs` default `300`, `expose_events` with `name` and `disallow_arguments`). |
| `ingest` | Conditional | Omitted | Local producer ingest (`tokens` `>= 16` visible ASCII, `events` with unique `name`, `description` `1..=400` chars, scalar `filter_fields`, and offline `payload_schema`). |

## Further Documentation

- Architecture, passthrough scanner, delegated auth status semantics, outbound SSRF protections, and quota tables: [docs/design.md](docs/design.md)
- Release workflow and binary verification: [RELEASING.md](RELEASING.md)
- License and third-party notices: [LICENSE](LICENSE) and [NOTICE](NOTICE)
