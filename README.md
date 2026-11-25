# mcp-hookd

Webhook subscription, verification, ingest, and delivery daemon for MCP Events.

## Commands

- `mcp-hookd check [--config hookd.json]` — validate configuration.
- `mcp-hookd serve [--config hookd.json]` — run the HTTP facade and webhook delivery daemon.
- `mcp-hookd emit [--url URL] [--name EVENT] [--stream] [--on-invalid fail|drop]` — emit events to `POST /v1/events`.
