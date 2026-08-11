---
title: Image Generation Overview
description: The four-adapter image generation system, its target model, authorization, and operational contract.
---

Cockpit's image generation system lets an agent produce images through one of
four provider adapters. Every generation passes through one immutable preflight
plan that binds destinations, references, dimensions, spend, and output
authority before any paid byte leaves the process. This page is the canonical
overview; provider-specific setup, security, jobs, remote access, and
troubleshooting each have their own page linked below.

## Endpoint versus target

An **endpoint** is the configured connection to a provider API: origin, path
prefix, credential, headers, transport class, and route profile version. A
**target** is the resolved, health-checked, capability-fresh destination the
agent actually dispatches to. An endpoint that fails health, has stale
capabilities, or is disabled is not a selectable target.

The agent tool `list_image_generation_targets` returns only currently selectable
targets. Discovery never grants generation authority — it only lists what is
available.

## Default target

There is no implicit default target. A generation request must name at least
one target by its endpoint id. If no target is named, the request fails closed
before dispatch.

## Multi-target fanout

A single `generate_image` call may fan out to multiple targets, subject to
authorization limits:

| Bound | Value |
| --- | --- |
| Maximum targets per request | 16 |
| Maximum samples per target | 64 |
| Maximum total outputs | 256 |
| Maximum image dimension | 16,384 px |
| Maximum references | 64 |
| Maximum typed parameters | 64 |
| Maximum prompt bytes | 8,192 |

Fanout, total outputs, and known cost are each checked against the matching
grant tuple. A grant that does not cover the requested fanout, total outputs,
or cost blocks the request.

## Capability freshness

Each target carries a capability snapshot with a provenance of `live`, `cache`,
or `stale`. The capability dispatch TTL is 15 minutes; the display-stale TTL is
24 hours. A stale capability is shown but cannot be selected for dispatch — the
agent must refresh before a paid request. A target whose capabilities cannot be
refreshed is marked incompatible.

## Dimensions: exact, nearest, provider-default

Dimensions are resolved per target according to the provider's contract:

- **Exact pixels** — canonical `WxH` where each dimension is a nonzero decimal.
  Authorized only when the provider advertises that exact size.
- **Nearest tier** — a documented tier token (for example `512`, `1K`, `2K`,
  `4K` on OpenRouter) that maps to a resolution. Authorized only when the tier
  appears in every possible endpoint's resolution enum.
- **Provider-default** — the field is omitted and the provider chooses. On
  Gemini, `image_size` is provider-default for `gemini-2.5-flash-image`.

An aspect ratio combined with explicit pixels must be exact-rational
consistent: `width * denominator == height * numerator`, proved by cross
multiplication. An `auto` aspect with explicit pixels is rejected.

## Sample and total limits

The per-target sample count (`samples`) is planning intent, not a provider
guarantee. The total outputs across all targets must not exceed 256. Each
adapter enforces its own per-request output limit (for example, OpenAI allows
1–10 outputs per request; OpenRouter allows 1–10).

## References

Input references are typed attachments — either an `attachment_id` or a
daemon-local `local_path` — never raw URLs or provider JSON. A local path
first passes normal read-path authorization and is normalized once into a typed
attachment. Reference egress to a destination without a matching grant raises
risk and blocks under Yolo.

## Immutable preflight plan and digest

Before any dispatch, the planner emits a closed DTO that resolves every target
and output slot. Its canonical bytes are the authorization, queue, spend, and
provider-dispatch binding. No dispatcher may reinterpret caller input. The plan
projection and its SHA-256 digest are displayed for approval; the projection is
review-only and cannot edit the plan.

## Resource and spend reservation

Paid generation cannot dispatch until request, session, and project spend
policies are each explicitly finite or Unlimited, and a finite project budget
has an explicit epoch policy. The spend ledger reserves every finite scope
before the external journal moves to `dispatching`. See
[Security and Budgets](../security-and-budgets/).

## Stable job and slot states

Every generation creates a durable job with one or more slots. The canonical
state machines are:

### Job states

| State | Meaning |
| --- | --- |
| `queued` | Plan accepted, awaiting dispatch |
| `dispatching` | External journal durably dispatching |
| `submission_unknown` | Handoff ambiguous — provider may or may not have accepted |
| `running` | Provider accepted, generating |
| `cancellation_requested` | Cancellation requested, not yet terminal |
| `downloading` | Fetching bounded output bytes |
| `completed_after_cancel` | Provider completed after cancellation was requested |
| `partially_failed` | Some slots failed, some succeeded |
| `completed` | All slots published |
| `failed` | All slots failed |
| `cancelled` | All slots cancelled |

### Slot states

| State | Meaning |
| --- | --- |
| `queued` | Awaiting dispatch |
| `dispatching` | Dispatching to provider |
| `submission_unknown` | Handoff ambiguous |
| `running` | Provider generating |
| `cancellation_requested` | Cancellation requested |
| `downloading` | Fetching output |
| `validating` | Validating output bytes and media type |
| `ready_to_publish` | Validated, ready to publish |
| `published` | Published as a retained artifact |
| `completed_after_cancel` | Completed after cancellation was requested |
| `late_quarantined` | Late output quarantined pending publish/discard |
| `failed` | Slot failed |
| `cancelled` | Slot cancelled |
| `discarded` | Late result explicitly discarded |

See [Jobs and Artifacts](../jobs-and-artifacts/) for the full transition
diagrams and late-output handling.

## Partial failure

A job may end `partially_failed` when some slots publish and others fail. Each
slot's terminal state is independent. The job terminal event records published,
failed, cancelled, and late counts.

## Cancellation: request versus terminal

Cancellation is a **request**, not an immediate terminal state. The agent tool
`cancel_image_generation_job` records `cancellation_requested` on the job and
each non-terminal slot. The provider may still complete the work, producing
`completed_after_cancel`. Only when the provider confirms cancellation (or the
slot fails) does the slot reach a terminal `cancelled` or `failed` state.

Late output after cancellation is quarantined as `late_quarantined`, never
silently published. See the [ComfyUI page](../comfyui/) for the exact
cancellation capability union and the [Jobs page](../jobs-and-artifacts/) for
late publish/discard.

## Late quarantine, publish, discard

When output arrives after `cancellation_requested` or after the slot has
already reached a terminal state, it is quarantined as `late_quarantined`. A
quarantined artifact may then be:

- **Published** — promoted to a retained artifact after re-authorization.
- **Discarded** — explicitly discarded with an audit record.

Late publication is never automatic. Each transition is durable and audited.

## Retained artifact versus host-published copy

A **retained artifact** is the Cockpit-managed copy stored under Cockpit's
artifact authority with a checksum, byte length, and stable identity. A
**host-published copy** is a copy the provider or ComfyUI server may retain on
its own storage. Cockpit never treats a provider URL or ComfyUI server path as
a download route. The retained artifact is the canonical copy; the
host-published copy is out of Cockpit's control.

## Authenticated remote download

Remote download of artifact metadata, thumbnails, and bytes requires exact
authorized session/project access. Download handles are opaque and
authenticated; provider URLs, ComfyUI paths, and daemon paths are never exposed
as remote routes. See [Remote Client](../remote-client/).

## Provider pages

- [OpenAI Images](../openai/)
- [OpenRouter Images](../openrouter/)
- [Gemini Images](../gemini/)
- [ComfyUI](../comfyui/)
