# mcp-hookd

`mcp-hookd` is a single-binary webhook subscription, verification, ingest, and delivery daemon for Model Context Protocol (MCP) Events. It sits between remote MCP clients (usually behind a reverse proxy or OAuth gateway) and either an upstream Streamable HTTP MCP server, local event producers, or both.

When an upstream server is configured, `mcp-hookd` proxies normal MCP traffic and exposes selected upstream events over signed HTTPS webhooks (`sep3415` or `chatgpt` profile). When `ingest` is configured, local services or scripts push JSON events to `POST /v1/events`, which `mcp-hookd` validates, filters, and delivers to active webhook subscribers.

## Topology

```text
MCP Client -> Reverse Proxy / OAuth Gateway -> mcp-hookd (/mcp, /healthz)
                                                 |-> Upstream MCP Server (optional, + passthrough_prefixes)
                                                 |-> Outbound HTTPS Webhooks (signed, verified)
Local Producers / mcp-hookd emit --------------> mcp-hookd (POST /v1/events)
```

Subscriptions persist in a local JSON state file (`state_path`) protected with `0600` permissions on Unix. When `auth_context` is enabled, `mcp-hookd` periodically rechecks delegated OAuth grants against the gateway's loopback check endpoint and drops revoked subscriptions.

## Commands

Requires Rust 1.92 or newer.

- `mcp-hookd check [--config hookd.json]` validates the configuration file and exits.
- `mcp-hookd serve [--config hookd.json]` runs the HTTP facade and webhook delivery daemon in the foreground.
- `mcp-hookd emit [--url URL] [--name EVENT] [--stream] [--on-invalid fail|drop]` reads one JSON object (or NDJSON with `--stream`) from stdin and posts it to `POST /v1/events`.

`HOOKD_CONFIG` sets the default config path when `--config` is omitted. `HOOKD_INGEST_URL` sets the default target URL for `emit` (default `http://127.0.0.1:8081/v1/events`), and `HOOKD_PRODUCER_TOKEN` supplies the required bearer token for `emit`.

## Minimal configuration

String values equal to `"${VAR}"` expand from the environment at startup. Partial interpolation is rejected. Configure at least one of `upstream` or `ingest`.

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

Validate before starting:

```bash
export HOOKD_INBOUND_TOKEN='replace-with-inbound-token'
export HOOKD_INGEST_TOKEN='replace-with-ingest-token'

mcp-hookd check --config hookd.json
mcp-hookd serve --config hookd.json
```

## Build and test

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
python3 scripts/ci/run-tests.py
```

## License

Apache-2.0. See [LICENSE](LICENSE).
