---
title: Relay Signaling Service
---

Flycockpit remote control uses a dedicated WebSocket relay service in `apps/relay`. Daemons connect outbound to `/ws/daemon`, browser/native clients connect to `/ws/client`, and user-level notification sockets connect to `/ws/user`.

The relay verifies short-lived ES256 JWTs against the control plane JWKS endpoint at `/api/relay/jwks.json`. It never needs `BETTER_AUTH_SECRET`, model provider keys, or user credentials. Server deployments that run the relay on a separate origin should set `COCKPIT_RELAY_ID` and the relay process `RELAY_ID` to the same stable value, set `COCKPIT_RELAY_URL` to the public WebSocket base such as `wss://relay.example.com/ws`, and set the same `RELAY_CONTROL_SECRET` on the server and relay.

Security posture for v1:

- TLS per hop; end-to-end frame encryption is not implemented yet.
- Frame bodies are routed in memory only and are not logged or persisted.
- Logs contain connection metadata, frame counts, and byte counts.
- Client principals and grants are stamped by the relay from verified token claims; clients cannot supply their own identity.
- Redis-backed presence is used when `REDIS_URL` is configured. Without Redis, presence is in-memory and single-relay only.

Conforming relay implementations must accept this env surface:

- `BETTER_AUTH_URL` or `RELAY_TOKEN_ISSUER`: issuer expected in relay JWTs.
- `RELAY_ID`: stable relay identity used as the JWT audience. It must match the server's `COCKPIT_RELAY_ID` for the relay URL it returns.
- `RELAY_JWKS_URL`: optional override for the control-plane JWKS URL; defaults to `<issuer>/api/relay/jwks.json`.
- `RELAY_PORT`: HTTP/WebSocket listen port, default `3010`.
- `RELAY_CONTROL_SECRET`: shared bearer secret used for relay-to-server ingest and server-to-relay control messages.
- `RELAY_CONTROL_INGEST_URL`: server endpoint for daemon attention events and user presence, usually `<server-origin>/api/relay/control-ingest`.
- `REDIS_URL`: optional presence directory and forced-disconnect pub/sub backend.
- `RELAY_HEARTBEAT_MS`, `RELAY_LEASE_TTL_MS`, `RELAY_MAX_FRAME_BYTES`, `RELAY_MAX_CHANNELS_PER_CLIENT`, `RELAY_MAX_CONNECTIONS_PER_INSTANCE`, `RELAY_CLIENT_RATE_LIMIT_PER_SECOND`, `RELAY_SHUTDOWN_GRACE_MS`: runtime timing and abuse limits.

Conforming relays expose these HTTP endpoints:

- `GET /healthz` returns JSON with `{ "ok": true, "relayId": "<relay-id>" }` once the process is ready to accept WebSockets.
- `GET /metrics` returns JSON with `relayId`, `daemons`, `clients`, `users`, `frames`, and `bytes` counters.
- `POST /control` requires `Authorization: Bearer <RELAY_CONTROL_SECRET>`, accepts a `relayControlMessageSchema` JSON body, returns `{ "ok": true }` on success, `401` for a bad bearer token, `400` for invalid JSON or invalid control messages, and `404` when control is disabled.

Conforming relays use these close and upgrade behaviors:

- Invalid signatures, wrong issuer, and wrong `aud` are refused during HTTP upgrade with `401 Unauthorized`; no WebSocket is established.
- `4401` closes a WebSocket after upgrade when the token type is valid but not allowed on that route.
- `4404` closes a client when no daemon is online for its instance.
- `4409` closes a daemon when a newer daemon replaces it for the same instance.
- `4429` closes a client that exceeds `RELAY_CLIENT_RATE_LIMIT_PER_SECOND` or instance connection limits.
- `4400` closes malformed JSON or schema-invalid relay frames.
- `4410` closes daemons, clients, or users disconnected by `/control`.
- `1009` is used for frames larger than `RELAY_MAX_FRAME_BYTES`.

These log prefixes are stable conformance signals and must not include frame bodies:

- `[relay] listening`
- `[relay] daemon connected` and `[relay] daemon disconnected`
- `[relay] client connected` and `[relay] client disconnected`
- `[relay] user connected` and `[relay] user disconnected`
- `[relay] control frame dropped`
- `[relay] control ingest failed` and `[relay] user presence ingest failed`

Manual smoke test after deployment:

1. Confirm `GET /healthz` on the relay returns `{ "ok": true }`.
2. Confirm `GET /api/relay/jwks.json` on the server returns a JWKS with one public EC signing key.
3. Mint a connector token through `instances.mintConnectorToken`; its `relayUrl` should point at the relay service.
4. Connect a daemon to `/ws/daemon`, then a client to `/ws/client`, and verify frames relay with `principal.userId` stamped server-side.
