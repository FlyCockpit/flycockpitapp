---
title: Relay Signaling Service
---

Flycockpit remote control uses the Rust WebSocket relay binary `flycockpit-relay` from `apps/relay-rs`. Daemons connect outbound to `/ws/daemon`, browser/native clients connect to `/ws/client`, and user-level notification sockets connect to `/ws/user`. The TypeScript relay app remains only as the conformance suite until it is retired.

The relay verifies short-lived ES256 JWTs against the control plane JWKS endpoint at `/api/relay/jwks.json`. It never needs `BETTER_AUTH_SECRET`, model provider keys, or user credentials. Server deployments that run one relay on a separate origin should set `COCKPIT_RELAY_ID` and the relay process `RELAY_ID` to the same stable value, set `COCKPIT_RELAY_URL` to the public WebSocket base such as `wss://relay.example.com/ws`, and set the same `RELAY_CONTROL_SECRET` on the server and relay. Enterprise fleet deployments keep that shared control secret for server-to-relay `/control` posts, but relay discovery and client routing come from the fleet registration and heartbeat endpoints instead of `COCKPIT_RELAY_URL`.

Security posture for v1:

- TLS per hop; end-to-end frame encryption is not implemented yet.
- Frame bodies are routed in memory only and are not logged or persisted.
- Logs contain connection metadata, frame counts, and byte counts.
- Client principals and grants are stamped by the relay from verified token claims; clients cannot supply their own identity.
- Redis-backed presence is used when `REDIS_URL` is configured. Without Redis, presence is in-memory and single-relay only.

The Rust relay uses `jsonwebtoken` for local ES256 verification after fetching the JWKS with `reqwest`; the crate does not provide remote JWKS caching itself, so the relay owns bounded caching and refetch-on-unknown-`kid` behavior. Redis support uses the `redis` crate because it covers the small command/pub-sub surface needed here without introducing a second async runtime or a higher-level client abstraction.

Conforming relay implementations must accept this env surface:

- `BETTER_AUTH_URL` or `RELAY_TOKEN_ISSUER`: issuer expected in relay JWTs.
- `RELAY_ID`: stable relay identity used as the JWT audience. It must match the server's `COCKPIT_RELAY_ID` for the relay URL it returns.
- `RELAY_JWKS_URL`: optional override for the control-plane JWKS URL; defaults to `<issuer>/api/relay/jwks.json`.
- `RELAY_PORT`: HTTP/WebSocket listen port, default `3010`.
- `RELAY_MODE`: `embedded` (default), `shared-secret`, or `fleet`. `embedded` binds loopback only and is for a supervised self-host child process. `shared-secret` is for a network-reachable standalone relay authenticated with `RELAY_CONTROL_SECRET`. `fleet` is for certificate-backed public or enterprise relay nodes.
- `RELAY_BIND_ADDR`: optional bind interface. `embedded` defaults to `127.0.0.1`; `shared-secret` defaults to `0.0.0.0`.
- `RELAY_CONTROL_SECRET`: shared bearer secret used for relay-to-server ingest and server-to-relay control messages. It is required for `shared-secret` mode.
- `RELAY_CONTROL_INGEST_URL`: server endpoint for daemon attention events and user presence, usually `<server-origin>/api/relay/control-ingest`.
- `REDIS_URL`: optional presence directory and forced-disconnect pub/sub backend.
- `RELAY_CERTIFICATE_PATH`, `RELAY_PRIVATE_KEY_PATH`: required in `fleet` mode. The relay reads its certificate and private key from these paths; the private key is never logged or sent to the control plane.
- `RELAY_HEARTBEAT_MS`, `RELAY_LEASE_TTL_MS`, `RELAY_MAX_FRAME_BYTES`, `RELAY_MAX_CHANNELS_PER_CLIENT`, `RELAY_MAX_CONNECTIONS_PER_INSTANCE`, `RELAY_CLIENT_RATE_LIMIT_PER_SECOND`, `RELAY_SHUTDOWN_GRACE_MS`: runtime timing and abuse limits.

Enterprise fleet control planes additionally accept this server env surface:

- `RELAY_CA_PUBLIC_KEYS`: JSON array of `{ "kid": string, "publicKey": string }` CA public keys used to verify relay certificates. Multiple keys are supported for rotation.
- `RELAY_REVOKED_IDS`: optional comma-separated relay ids rejected during registration even if their certificates are otherwise valid.

Enterprise fleet relays register and report health through these server endpoints:

- `POST /api/relay/register` accepts `{ certificate, challengeSignature, nonce, timestamp }`. The certificate payload attests `relayId`, `subdomain`, `region`, `relayPublicKey`, `notBefore`, and `notAfter`; the challenge proves possession of the relay private key. Success returns an opaque 30-minute session token. Authentication failures return identical `401` responses.
- `POST /api/relay/heartbeat` requires `Authorization: Bearer <fleet-session-token>` and accepts `{ relayId, accepting, connections, leaseDeltas, userDeltas }`, or a full reconcile with `leases` and `users`. Heartbeats refresh 45-second relay, instance, and user leases.
- `instances.listRelayCandidates({ instanceId, instanceToken })` returns one fresh accepting relay per region. On `DEPLOYMENT_PROFILE=oss`, it returns the configured single relay with `region: null` and never loads the enterprise fleet registry.

Conforming relays expose these HTTP endpoints:

- `GET /healthz` returns JSON with `{ "ok": true, "relayId": "<relay-id>" }` once the process is ready to accept WebSockets.
- `GET /metrics` returns JSON with `relayId`, `daemons`, `clients`, `users`, `frames`, and `bytes` counters.
- `POST /control` requires `Authorization: Bearer <RELAY_CONTROL_SECRET>`, accepts a `relayControlMessageSchema` JSON body, returns `{ "ok": true }` on success, `401` for a bad bearer token, `400` for invalid JSON or invalid control messages, and `404` when control is disabled.

Conforming relays use these close and upgrade behaviors:

- Invalid signatures, wrong issuer, and wrong `aud` are refused during HTTP upgrade with `401 Unauthorized`; no WebSocket is established.
- `4401` closes a WebSocket after upgrade when the token type is valid but not allowed on that route.
- `4404` closes a client when no daemon is online for its instance.
- `4409` closes a daemon when a newer daemon replaces it for the same instance.
- `4429` closes a client that exceeds `RELAY_CLIENT_RATE_LIMIT_PER_SECOND`, instance connection limits, or the bounded outbound buffer/backpressure limits.
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
3. In OSS, call `instances.listRelayCandidates` and confirm it returns the configured relay with `region: null`; in enterprise fleet mode, confirm it returns one candidate per healthy region.
4. Mint a connector token through `instances.mintConnectorToken` with the selected `relayId`; its `relayUrl` should point at the selected relay service.
5. Connect a daemon to `/ws/daemon`, then a client to `/ws/client`, and verify frames relay with `principal.userId` stamped server-side.
