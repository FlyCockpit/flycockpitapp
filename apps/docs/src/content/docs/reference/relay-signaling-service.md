---
title: Relay Signaling Service
---

Flycockpit remote control uses a dedicated WebSocket relay service in `apps/relay`. Daemons connect outbound to `/ws/daemon`, browser/native clients connect to `/ws/client`, and user-level notification sockets connect to `/ws/user`.

The relay verifies short-lived ES256 JWTs against the control plane JWKS endpoint at `/api/relay/jwks.json`. It never needs `BETTER_AUTH_SECRET`, model provider keys, or user credentials. Server deployments that run the relay on a separate origin should set `COCKPIT_RELAY_URL` to the public WebSocket base, for example `wss://relay.example.com/ws`.

Security posture for v1:

- TLS per hop; end-to-end frame encryption is not implemented yet.
- Frame bodies are routed in memory only and are not logged or persisted.
- Logs contain connection metadata, frame counts, and byte counts.
- Client principals and grants are stamped by the relay from verified token claims; clients cannot supply their own identity.
- Redis-backed presence is used when `REDIS_URL` is configured. Without Redis, presence is in-memory and single-relay only.

Key relay env vars:

- `BETTER_AUTH_URL` or `RELAY_TOKEN_ISSUER`: issuer expected in relay JWTs.
- `RELAY_JWKS_URL`: optional override for the control-plane JWKS URL; defaults to `<issuer>/api/relay/jwks.json`.
- `RELAY_PORT`: HTTP/WebSocket listen port, default `3010`.
- `REDIS_URL`: optional presence directory and forced-disconnect pub/sub backend.
- `RELAY_MAX_FRAME_BYTES`, `RELAY_MAX_CHANNELS_PER_CLIENT`, `RELAY_CLIENT_RATE_LIMIT_PER_SECOND`: runtime abuse limits.

Manual smoke test after deployment:

1. Confirm `GET /healthz` on the relay returns `{ "ok": true }`.
2. Confirm `GET /api/relay/jwks.json` on the server returns a JWKS with one public EC signing key.
3. Mint a connector token through `instances.mintConnectorToken`; its `relayUrl` should point at the relay service.
4. Connect a daemon to `/ws/daemon`, then a client to `/ws/client`, and verify frames relay with `principal.userId` stamped server-side.
