---
title: Jobs and Artifacts
description: Durable job and slot state machines, late quarantine, publish/discard, and artifact copies.
---

Every image generation creates a durable job with one or more slots. Jobs and
artifacts are immutable after preflight — changing any binding requires a new
plan, health check, and authorization. This page documents the canonical state
machines and artifact handling.

## Job state machine

```
queued → dispatching → submission_unknown → running → downloading → validating → ready_to_publish → published
                   ↓                         ↓                                        ↓
              failed                   cancellation_requested              failed
                   ↓                         ↓
              cancelled              completed_after_cancel
                                             ↓
                                       late_quarantined
                                             ↓
                                    publish / discard
```

| Job state | Meaning |
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

A job ends `partially_failed` when some slots publish and others fail. The job
terminal event records published, failed, cancelled, and late counts.

## Slot state machine

| Slot state | Meaning |
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

## Attempt states

Each slot may have multiple attempts. Attempt states include `accepted`,
`submission_unknown`, `reconciling`, `running`, `downloading`,
`cancellation_requested`, `completed_after_cancel`, and
`failed_after_acceptance`. An attempt that times out or resets after handoff
becomes `submission_unknown` and is reconciled — it is never blindly retried.

## Late quarantine

When output arrives after `cancellation_requested` or after the slot has reached
a terminal state, it is quarantined as `late_quarantined`. Late output is
**never** silently published. A quarantined artifact may then be:

- **Published** — promoted to a retained artifact after re-authorization. The
  late publication moves through `copy_committed` → `published`.
- **Discarded** — explicitly discarded with an audit record. The late
  publication moves to `aborted`.

Each transition is durable and audited. The late publication state machine:

```
late_quarantined → copy_committed → published
                ↘ aborted (discarded)
```

## Immutable identity

Changing any of the following requires a new health check, preflight, and
authorization:

- endpoint origin
- credential
- workflow
- routing
- location class
- capability
- budget
- reference
- output authority

The immutable plan's canonical bytes are the binding. No dispatcher may
reinterpret caller input after the plan is sealed.

## Artifact copies

Three copies must be kept distinct:

| Copy | Owner | Canonical? |
| --- | --- | --- |
| Retained artifact | Cockpit | Yes — checksum, byte length, stable identity |
| Host-published copy | Provider or ComfyUI server | No — out of Cockpit's control |
| Device copy | Remote client cache | No — derived from authenticated download |

Cockpit never treats a provider URL, ComfyUI server path, or daemon path as a
download route. The retained artifact is the canonical copy.

## Artifact components

Each artifact has one or more components with a kind, state, checksum
(SHA-256), byte length, and relative storage key. Component states include
`retained`, `late_quarantined`, `cleanup_pending`, and `security_blocked`. A
`security_blocked` component never reaches a published or downloadable state.

## Partial failure

A job may end `partially_failed` when some slots publish and others fail. Each
slot's terminal state is independent — a failed slot does not retract a
published slot. The job terminal event records the exact counts.
