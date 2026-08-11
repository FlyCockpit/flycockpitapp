---
title: Troubleshooting
description: Stable reason to safe check mapping for image generation, without unsafe workarounds or secret disclosure.
---

Each entry maps a stable failure reason to safe checks. No remedy advises
clearing a queue/history as file cleanup, disabling TLS/SSRF checks, using a
global interrupt on a shared server, retrying `submission_unknown`, or
downloading provider URLs directly.

## Unconfigured budget

**Reason:** A spend scope is `Unconfigured` or the project epoch is missing.

**Safe checks:**

- Open **Settings → Image Spend** and set each scope to an explicit finite or
  Unlimited value.
- If the project scope is finite, set an explicit epoch policy (calendar month
  or rolling).
- UI suggestions (USD 1/10/100, project-month) are display aids only — they are
  not defaults and do not participate in authorization.

## Stale capability

**Reason:** The target's capability snapshot is older than the dispatch TTL
(15 minutes).

**Safe checks:**

- Refresh the target's capabilities from **Settings → Image Generation** or by
  re-running `list_image_generation_targets`.
- A stale target is shown but cannot be selected for dispatch.
- If refresh fails, the target is marked incompatible — check the provider
  endpoint and credential.

## DNS or location transition

**Reason:** The endpoint origin no longer resolves or the location class
changed.

**Safe checks:**

- Verify the endpoint origin is still reachable from the daemon host.
- A `local` endpoint must resolve to loopback; a `public_cloud` endpoint must
  not.
- Changing the origin, location class, or path prefix requires a new health
  check and preflight — the immutable identity changes.

## TLS or auth failure

**Reason:** The TLS handshake failed or the credential was rejected.

**Safe checks:**

- Verify the endpoint origin uses `https` for any non-loopback location.
- `allow_insecure_transport` is rejected for `https` origins and is only valid
  for `local` loopback.
- Do not disable TLS or SSRF checks. Rotate the credential instead.

## Credential rotation

**Reason:** The credential reference no longer resolves or the provider
rejected it.

**Safe checks:**

- Update the credential at its source (not in a docs example).
- A credential identity change requires a new health check and preflight — the
  immutable identity changes.
- Credential data is never logged or included in journal metadata.

## Incompatible model or workflow

**Reason:** The selected model is not in the catalog or the workflow binding is
invalid.

**Safe checks:**

- Verify the model name is an exact checked-in catalog entry. Unknown, alias,
  preview, and `latest` names are rejected.
- For ComfyUI, verify the registered workflow graph and typed bindings match
  the declared `WorkflowValueType`.
- A catalog or workflow change requires a fresh review and preflight.

## Missing Comfy nodes

**Reason:** The ComfyUI server does not have the nodes the registered workflow
requires.

**Safe checks:**

- Install the missing nodes on the ComfyUI server (Cockpit does not administer
  ComfyUI).
- The adapter reports `workflow_invalid` when the graph cannot be bound.
- Server paths from ComfyUI responses are remote identifiers — do not treat
  them as local paths.

## Busy queue

**Reason:** The provider or ComfyUI server is busy and cannot accept new work.

**Safe checks:**

- Wait for the queue to drain, or reduce the fanout/sample count.
- For ComfyUI, a busy queue is not a reason to use `POST /interrupt` — that is
  process-global and forbidden on a shared server.
- Do not clear the queue or history as file cleanup.

## Ambiguous submission

**Reason:** The handoff returned `submission_unknown` — the provider may or may
not have accepted.

**Safe checks:**

- Do **not** retry. Retrying risks a paid duplicate.
- The adapter reconciles the submission; the slot moves to `running`,
  `failed`, or `late_quarantined` based on provider evidence.
- If reconciliation is unavailable, the slot remains `submission_unknown` until
  evidence arrives.

## Unknown cost

**Reason:** The plan maximum is unknown and a spend scope is finite.

**Safe checks:**

- Set request, session, and project spend all to `Unlimited` if you accept
  unknown cost.
- Or choose a provider/endpoint combination with a known finite maximum.
- A token-priced prompt line without a proven finite token maximum makes the
  maximum unknown.

## Reservation exhaustion

**Reason:** A finite spend scope would be exceeded by this request.

**Safe checks:**

- Reduce the fanout, sample count, or choose a less expensive endpoint.
- Increase the finite scope limit (requires explicit policy review).
- The spend ledger reserves every finite scope before dispatch — no partial
  reservation is committed.

## Grant or session revoke

**Reason:** The reference egress grant or session authorization was revoked.

**Safe checks:**

- Re-authorize the session for the project.
- Reference egress grants are `once`, `session`, or machine-local `project`
  only — there is no global grant.
- A project grant still requires current session authorization and per-use
  audit.

## Output path reauthorization

**Reason:** The output directory authority changed.

**Safe checks:**

- Re-authorize the output directory in the plan.
- Changing output authority requires a new preflight and authorization.
- The output authority is part of the immutable plan identity.

## Cancellation unsupported

**Reason:** The provider has no cancellation capability.

**Safe checks:**

- The adapter records local `cancellation_requested` and stops polling.
- Any later output is quarantined as `late_quarantined` — it is never silently
  published.
- For ComfyUI, the `unsupported` branch applies when no job binding, no queued
  prompt, and no exclusive-server ownership is proven.

## Late quarantine

**Reason:** Output arrived after cancellation or after a terminal state.

**Safe checks:**

- Review the quarantined artifact and choose **publish** or **discard**.
- Publishing requires re-authorization; discarding records an audit entry.
- Late output is never automatically published.

## Cleaned artifact

**Reason:** The retained artifact was cleaned up.

**Safe checks:**

- The retained artifact is gone; a device copy (if cached) is no longer backed
  by Cockpit.
- Re-generate if the image is still needed.
- Cleanup is a normal lifecycle operation, not an error.

## Remote 404

**Reason:** A remote client requested an artifact it is not authorized for, or
the artifact no longer exists.

**Safe checks:**

- Verify the session and project still have access to the artifact.
- An opaque authenticated handle that does not match returns 404 — the existence
  of an artifact is not leaked to an unauthorized client.
- Provider URLs, ComfyUI paths, and daemon paths are never remote routes.

## Checksum, decode, or SVG validation failure

**Reason:** Output bytes failed canonical detection, base64 decode, or SVG
sanitization.

**Safe checks:**

- The artifact is marked `security_blocked` and never reaches a published or
  downloadable state.
- Do not bypass validation. Re-generate with a different model or parameters.
- A present `media_type` that conflicts with canonical detection is rejected —
  do not trust a declared MIME over sniffed bytes.
