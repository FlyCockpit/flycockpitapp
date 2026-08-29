---
title: ComfyUI Setup
description: Configurable ComfyUI workflow adapter, routes, cancellation branches, and ownership boundary.
---

The ComfyUI adapter (`comfyui`) connects to a user-configured ComfyUI server
using registered API-format workflows with typed bindings. This page documents
the exact route profile, cancellation contract, and the ownership boundary.

## Ownership boundary

ComfyUI is **not** bundled, installed, launched, upgraded, or administered by
Cockpit. `http://127.0.0.1:8188` is only a suggestion relative to the daemon
host. The origin, port, path prefix, auth, TLS, and location are explicit
configuration. External executable installation (FFmpeg, FFprobe, Bubblewrap,
and similar) remains owned by the
[runtime prerequisites](../../reference/runtime-prerequisites/) page and is
linked, not duplicated here.

## Routes

| Route | Path | Method | Use |
| --- | --- | --- | --- |
| Submit | `/prompt` | `POST` | Submit a workflow with a unique `client_id` |
| Events | `/ws` | `GET` | WebSocket events (when supported) |
| History | `/history/{prompt_id}` | `GET` | Bounded polling fallback |
| Artifact | `/view` | `GET` | Retrieve declared output-node artifacts |
| Queue | `/queue` | `POST` | Delete queued work |
| Job cancel | `/api/jobs/{job_id}/cancel` | `POST` | Job-scoped cancellation |

Server paths (filenames, subfolders, types) from ComfyUI responses are
**remote identifiers** — validated against traversal, absolute paths, and shell
metacharacters. They are never treated as local filesystem paths or exposed as
download routes.

## Workflow binding

The adapter clones a registered API-format workflow graph and binds only
declared semantic fields to exact node/input locations. Agents can supply typed
canonical values:

| Value type | JSON |
| --- | --- |
| Integer | `i64` |
| Decimal (milli) | `i64` |
| Text | bounded string |
| Image reference | Not supported for ComfyUI in v1 |

Agents **cannot** supply URLs, workflow JSON, node IDs, filenames, subfolders,
raw provider fields, or graph patches. A binding value's type must match the
declared `WorkflowValueType`. ComfyUI reference-image jobs fail closed before
any provider request: the supported route profile has no discovered,
ownership-safe remote delete operation, so Cockpit does not upload reference
media that it cannot clean up durably.

## Output retrieval

Only declared output-node artifacts are retrieved, through bounded `GET /view`
requests. Output bytes are canonically detected and validated; SVG passes the
closed sanitizer before retention.

## Cancellation

Cancellation follows an **exact capability union**. The adapter selects the
strongest available capability in priority order:

### 1. Job-scoped cancel (`job_scoped_cancel`)

When the configured or discovered profile provides an exact job binding, the
adapter sends idempotent `POST /api/jobs/{job_id}/cancel` with
`{ "cancelled": bool }`. This targets the exact job and is always preferred
when available.

### 2. Queued prompt delete (`queued_prompt_delete`)

When the work is still queued (not yet executing), the adapter sends
`POST /queue` with `{ "delete": [prompt_id] }`. This deletes the exact queued
prompt without affecting other work.

### 3. Exclusive-server interrupt (`exclusive_server_interrupt`)

`POST /interrupt` without an ID is **process-global** — it interrupts all work
on the server. It is **forbidden** unless:

- `exclusive_server: true` is explicitly configured on the endpoint, **and**
- Cockpit proves it owns the only executing work on the server.

If either condition is not met, this capability is not selected.

### 4. Unsupported (`unsupported`)

When no provider cancellation is available, the adapter records local
`cancellation_requested`, stops polling, and quarantines any later result as
`late_quarantined`. Late output is never silently published.

## What is never recommended

- No-ID `POST /interrupt` on a shared server.
- Treating `/upload/image` as an operational Cockpit route. It is deliberately
  not used in v1 because remote cleanup cannot be proved.
- Clearing a queue or history as file cleanup.
- Treating server paths as local filesystem paths.
- Exposing ComfyUI server URLs as remote download routes.

## Setup

Configure an endpoint with `adapter: comfyui`, the ComfyUI origin, optional
path prefix, and `route_profile_version: 1`. Set `exclusive_server: true` only
if the server is truly exclusive to this Cockpit instance.

```json
{
  "id": "comfyui-local",
  "adapter": "comfyui",
  "origin": "http://127.0.0.1:8188",
  "location": "local",
  "allow_insecure_transport": true,
  "enabled": true,
  "route_profile_version": 1,
  "exclusive_server": false
}
```

The example uses the suggested loopback origin. No live secret is required.
