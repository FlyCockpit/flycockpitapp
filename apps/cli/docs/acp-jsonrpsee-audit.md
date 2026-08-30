# jsonrpsee audit for ACP v1 stdio dispatch

Audited crate: `jsonrpsee` **0.24.11** (exact pin).
License: MIT.
Workspace consumer: `apps/cli` (`cockpit-cli`), feature `server-core` only
(`default-features = false`). Cockpit owns the ACP-prescribed LF stdio codec;
jsonrpsee is not the framing owner and is not given an HTTP, WebSocket, or
TCP listener.

This document records the evidence required before the pin. The eight items
below are the audit surface from the transport-selection prompt.

## 1. Exact version

| Field | Value |
| --- | --- |
| Crate | `jsonrpsee` |
| Exact version | `0.24.11` |
| crates.io published | 2026-05-27 |
| Pin | `jsonrpsee = { version = "=0.24.11", default-features = false, features = ["server-core"] }` in `apps/cli/Cargo.toml`, locked in the workspace `Cargo.lock` |
| Companion types crate | `jsonrpsee-types` 0.24.11 (direct pin plus `server-core` graph) |
| Why this line | 0.24.11 is the newest published jsonrpsee crate as of this audit (the 0.26.0 line last published 2025-08-11). `server-core` exposes `RpcModule` / `Params` / standard JSON-RPC error objects without enabling jsonrpsee's HTTP or WebSocket server transports. |

## 2. License

MIT, as declared on crates.io and in the crate source header
(`jsonrpsee-types` 0.24.11 `params.rs` copyright Parity Technologies (UK)
Ltd.). Compatible with this repository's Apache-2.0 CLI crate.

## 3. Maintenance evidence

- Owned by Parity Technologies (`github:paritytech:core-devs`,
  `parity-crate-owner`).
- Successor to Parity's `jsonrpc` crate; used by polkadot-sdk, subxt, Forest,
  zkSync, and other production JSON-RPC stacks.
- 0.24.x still received a crates.io release on 2026-05-27 (`0.24.11`) after
  the 0.25/0.26 trains, so the audited line is not a frozen abandoned tag.
- Public changelog documents `Box<RawValue>` / raw-params work (`unify usage
  of JSON via Box<RawValue>`, `#1545`) and `RpcModule::raw_json_request`.

## 4. Rust 1.95 compatibility

There is no workspace `rust-toolchain.toml`. Every Cargo workspace member
that declares an MSRV uses `rust-version = "1.95"` (including `cockpit-cli`).
That package field is the concrete toolchain target for this audit: **Rust
1.95**. jsonrpsee 0.24.11 declares MSRV **1.74.0**, which is below 1.95.
jsonrpsee 0.25/0.26 declare MSRV 1.85.0, also below 1.95, but they are not
the line pinned here.

Owner follow-up: if a `rust-toolchain.toml` is added later, re-check this
section against that pin. No version-gating for older ACP/jsonrpsee protocol
editions is introduced.

## 5. Exact raw-request / parameter API

Inbound ACP `session/new` and `session/load` must keep lossless `params`
bytes until Cockpit's private DTO is built. jsonrpsee 0.24.11 provides that
seam without decoding to a map:

- `jsonrpsee::types::Request` carries `params` as raw JSON (the 0.24 line
  stores parameter text, not a deserialized `serde_json::Map`).
- `jsonrpsee::types::Params<'a>` wraps `Option<Cow<'a, str>>` of the raw
  params JSON.
- `Params::new(Option<&'a str>)` builds params from retained bytes.
- `Params::as_str() -> Option<&str>` returns the underlying JSON text
  without serde deserialization.
- `Params::len_bytes()` is the UTF-8 byte length of that text.
- `Params::parse::<T>()` is explicit and opt-in; handlers are not forced to
  call it.
- `RpcModule::register_method` callbacks receive `Params<'_>` as the first
  argument, so `session/new` / `session/load` can take `params.as_str()` and
  hand the slice to the owned DTO builder.
- `Methods::raw_json_request(&str, buf_size)` dispatches an already-framed
  JSON-RPC object by raw string.

Deterministic build-time check in `apps/cli/src/acp/dispatch.rs`:

```rust
fn jsonrpsee_raw_params_as_str<'a, 'p>(
    params: &'a jsonrpsee::types::Params<'p>,
) -> Option<&'a str> {
    params.as_str()
}

const JSONRPSEE_RAW_PARAMS_API: for<'a, 'p> fn(&'a jsonrpsee::types::Params<'p>) -> Option<&'a str> =
    jsonrpsee_raw_params_as_str;
```

If a future jsonrpsee upgrade removes `Params::as_str`, this crate fails to
compile. That is the prompt's stop-and-re-decide hatch: do not substitute
another library and do not decode the lossy generated `mcpServers` type.

Cockpit still does **not** use jsonrpsee to parse the inbound frame. The
owned raw parser rejects duplicate member names first; jsonrpsee only sees
frames that already passed that gate.

## 6. Method dispatch and malformed-request behavior

`RpcModule` / `Methods` (feature `server-core`) is the dispatch table:

- `register_method` / `register_async_method` bind JSON-RPC method names to
  callbacks.
- Unknown methods yield JSON-RPC `-32601` (`Method not found`).
- `Params::parse` failures yield `-32602` (`Invalid params`) via
  `ErrorObject`.
- `jsonrpsee::types::error::ErrorCode` supplies ParseError (`-32700`),
  InvalidRequest (`-32600`), MethodNotFound (`-32601`), InvalidParams
  (`-32602`), InternalError (`-32603`).
- `jsonrpsee::prepare_error` extracts an `Id` from a sufficiently complete
  malformed request, matching the ACP rule that a malformed frame produces a
  bounded JSON-RPC error when an unambiguous request id is available, and
  otherwise produces no routed response.

Cockpit applies those codes after the owned codec and duplicate-member
parser. jsonrpsee is not asked to interpret batch arrays, `Content-Length`
headers, or non-object frames; those are rejected before dispatch.

## 7. Bidirectional request / notification support

jsonrpsee's server is request/response-oriented. An ACP agent must also
*originate* JSON-RPC traffic on the same stdio pair:

- agent → client request: `session/request_permission`
- agent → client notification: `$/cancel_request`
- client → agent response: routed by the permission registry's pending id

`server-core` does not provide a stdio peer that can emit those
client-directed requests. Subscriptions (`register_subscription`) are a
server-push notification channel, not a general pending-id request
registry, and they assume jsonrpsee-owned transports.

**Minimal interoperable extension (owned by Cockpit, required):**

1. The owned LF writer serializes every outbound JSON value, including
   agent-originated requests and `$/cancel_request` notifications.
2. The outbound permission registry is the pending-id table for
   `session/request_permission` (capacity, charge, state machine, first-wins
   races). It is not a jsonrpsee client.
3. Inbound responses are classified by the owned envelope parser and looked
   up in that registry *before* jsonrpsee method routing.
4. jsonrpsee `RpcModule` handles only **inbound** client → agent requests
   and notifications (`initialize`, `session/list`, `session/new`,
   `session/load`, `session/cancel`, …). `cockpit acp` composes its ingress
   with the socket-daemon Code-root routes; default/test callers without that
   owner still fail closed. `initialize` advertises Code-root session loading
   and listing, while prompt and forwarded-MCP admission stay on the same
   daemon-owned bridge boundary. Unsupported session notifications close the
   peer rather than being treated as successful cancellation.

This extension is the documented bidirectional gap, not a silent substitute
for jsonrpsee. Unstable elicitation (`elicitation/create`,
`elicitation.form`, `elicitation/complete`) is neither advertised nor
registered.

## 8. JSON-RPC ids, cancellation, and errors; compatibility with the owned LF codec

- **Ids.** jsonrpsee `Id` is `Null | Number(u64) | Str`. Cockpit's outbound
  permission ids are monotonic connection-scoped unsigned-decimal *strings*
  (`"1"`, `"2"`, …), which `Id::Str` carries losslessly. Inbound client ids
  may be number or string; they are preserved on responses we emit.
- **Cancellation.** ACP `$/cancel_request` is a JSON-RPC notification, not a
  jsonrpsee subscription unsubscribe. Daemon terminality queues that
  notification through the owned writer before registry release. Client
  `session/cancel` remains unavailable until it has an owner; a notification
  for it therefore closes the peer without a daemon mutation or fabricated
  success response.
- **Errors.** Standard JSON-RPC error objects (`code`, `message`, optional
  `data`) with `"jsonrpc":"2.0"`. Capacity refusal uses the closed local
  error `outbound_request_capacity_exhausted` and never emits a partial
  outbound request.
- **Framing.** jsonrpsee 0.24.11 transports are HTTP, WebSocket, WASM, and
  an abstract async client. None of those is LF-delimited ACP stdio. Feature
  `server-core` compiles the dispatch table without those listeners.
  Cockpit's codec reads one UTF-8 JSON value per physical LF, rejects EOF
  fragments, embedded physical line breaks, over-limit frames, invalid
  UTF-8, batches, and `Content-Length` input, and writes exactly one `\n`
  after each stdout JSON value. CR is neither stripped nor a delimiter.
  jsonrpsee never sees a byte stream.

## Outcome

jsonrpsee **0.24.11** satisfies raw-param dispatch (`Params::as_str`) and
standard inbound JSON-RPC error/result handling. It does **not** own stdio
framing and does **not** originate agent → client requests; those stay in
the Cockpit codec and permission registry. The pin is accepted. The
ACP-prescribed codec remains Cockpit-owned regardless.

Pinned official ACP v1 schema crate (types only, not a runtime):
`agent-client-protocol-schema = { version = "=1.7.0", default-features = false }`.
Unstable features (`unstable_protocol_v2`, `unstable_mcp_over_acp`) are not
enabled. Schema types are a consistency check after the lossless DTO is
built.
