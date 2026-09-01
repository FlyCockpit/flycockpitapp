# Verification profiles, recipes, and modes

Cockpit can optionally verify `write` / `edit` (and granted `plan_write` /
`plan_edit`) calls before they execute. The layer is **opt-in**: shipped
agent configs stay `action: off`. When a rule matches `verify`, Cockpit
generates alternative implementations, adjudicates, and either gates the
original call or applies a revised variant.

This page covers the local CLI/TUI path only. Audit/settings UI is out of
scope here.

## Modes

| Mode | Default | Behavior |
| --- | --- | --- |
| `gate` | yes | Approve → dispatch the original unchanged. Block → do not execute; the tool result is `verification blocked this edit: <feedback>; revise and re-emit`. |
| `revise` | | Apply the selected candidate by re-entering ordinary write/edit dispatch (locks, identity-write, sandbox, stale-content, skill validation all still run). `wire_output` gets a disclosure suffix with the original→applied unified diff. |

`off` remains a first-match rule action and writes no ledger rows.

Adjudicator failure never hangs the turn. `onAdjudicationFailure` is
`dispatch_original` (default) or `refuse`.

## Recipes

Two recipes assemble generator context.

### `inherit`

The author's live history slice, a framing prompt, and the proposed diff.
**Cache economics:** inherit reuses the provider cache only when the
generator runs the **same slot** as the author with the author's **full
tool-definition schemas** (a restricted toolset breaks the Anthropic
prefix at the tools block) and, on OpenAI-compat paths, the author's
`prompt_cache_key` (session id). Inherit generators receive those schemas
with execution disabled at the verification layer. Cross-slot generators
should use `cleanRoom`.

### `cleanRoom`

Stable-parts-first so the prefix caches across verifications:

1. The persisted session goal (objective and non-empty context)
2. Instructions file (target-anchored, trust-gated — see below)
3. Optional files the instructions link
4. Up to N curated investigation results from the session tool-call log
   (**not** the lock read-tracker), preferring results relevant to the target
   before falling back to recency
5. The proposed diff (`write` diffs against the current file, empty for
   new files)

The curated investigation section keeps an output's provenance header (for
example path, query, and range) and its output, but never includes the raw
tool-call invocation JSON.

`includeLinkedFiles` defaults to `false`; `lastNReads` defaults to `5`.
`toolCategories` defaults to `[reads, exploration]`: `reads` selects `read`,
and `exploration` selects `code`, `graph`, `search`, `grep`, and `glob`.
`toolAllowlist` defaults to `[]` and additionally selects the exact tool names
it contains. Results selected by either mechanism share the same N-result
window.

For example, this recipe keeps up to four target-relevant exploration results
or `context_pack` results:

```yaml
recipe:
  cleanRoom:
    includeLinkedFiles: true
    lastNReads: 4
    toolCategories: [exploration]
    toolAllowlist: [context_pack]
```

#### Instructions-file selection (target-anchored)

Walk up from the **target file's directory** (the `path` arg), matching
`agent_guidance_files` (default `["AGENTS.md"]`), stopping at that file's
repo/worktree root — not the session cwd. Editing `repos/foo/src/x.rs` in
a multi-repo workspace therefore uses `repos/foo/AGENTS.md`. Fall back to
the session-level guidance file when the target's tree has none.

A nested repo's instructions file is used only when that repo root's
`workspace_trust` is `trust`. `ignore-config` and `untrusted`/unset skip
it and fall back to the session-level file.

#### Linked-file resolution

Markdown links resolve against three bases, first existing file wins:

1. The instructions file's own directory (standard markdown)
2. The repo root containing the instructions file (also serves
   GitHub-style `/docs/x.md` links)
3. The workspace root

Missing links are dropped. Canonicalized resolutions must be regular
files under the workspace root (symlink escapes rejected). Deduped by
canonical path. Caps: 8 files / 256 KiB total; over-cap or resolution
errors fail open to omission.

## Custody

Trust custody is one-directional. Only a generator on the author's slot can
use `inherit` and receive the author's live history. Every foreign-slot
generator — including one configured with `inherit` — is projected through the
default `cleanRoom` recipe instead: it receives the session goal, selected
instructions/files, curated tool outputs with provenance, and the proposed
change, but no author transcript or raw tool-call invocations. Configuration
validation warns when an `inherit` generator targets an untrusted slot.

The trusted adjudicator still receives the full context. Candidates containing
the redaction placeholder are marked `invalid` and are never selectable.

Generator and adjudicator inferences are journaled through the normal
inference-journal barrier. Candidate bodies never enter the tool-call
audit path; the ledger stores only `RedactedVerificationJson`
(classification + digest, ≤16 KiB).

## Builtin profiles

Profiles are presets, not a registry. Explicit fields win over the
profile defaults.

### `self-check`

```yaml
verification:
  rules:
    - selector:
        allOf: [{ toolClass: artifact_write }]
      action: verify
      adjudicatorSlot: primary
      profile: self-check
```

Expands to: one `inherit` generator on the author's `primary` slot, `mode:
gate`.

### `clean-room`

```yaml
verification:
  rules:
    - selector:
        allOf: [{ toolClass: artifact_write }]
      action: verify
      adjudicatorSlot: primary
      profile: clean-room
```

Expands to: one `cleanRoom` generator on the adjudicator slot, `mode: gate`.

### `panel`

```yaml
verification:
  rules:
    - selector:
        allOf: [{ toolClass: artifact_write }]
      action: verify
      adjudicatorSlot: primary
      maxCandidates: 3
      profile: panel
```

Expands to: N (default `resolved_max_candidates`) mixed generators
(inherit + clean-room), `mode: revise`.

## Rule fields

| Field | Default | Introduced |
| --- | --- | --- |
| `selector` | required | Stage 1 |
| `action` (`off` \| `verify`) | required | Stage 1 |
| `maxCandidates` | 5 | Stage 1 |
| `maxTotalTokens` | host ceiling | Stage 1 |
| `maxEstimatedCostMicrousd` | host ceiling | Stage 1 |
| `maxCollectionMillis` | host ceiling | Stage 1 |
| `adjudicatorSlot` | required for `verify` | Stage 1 |
| `onBudgetExceeded` (`refuse` \| `dispatch_original`) | `dispatch_original` | Stage 1 |
| `mode` (`gate` \| `revise`) | `gate` | Stage 3 |
| `generators` | empty (adjudicator-only) | Stage 3 |
| `generators[].slot` | required | Stage 3 |
| `generators[].recipe` | `inherit` | Stage 3 |
| `generators[].maxTurns` | 1 (max 4) | Stage 3 / Stage 7 |
| `profile` | none | Stage 3 |
| `onAdjudicationFailure` | `dispatch_original` | Stage 3 / Stage 5 |

`verify` with empty `generators` is valid: cheapest form, adjudicator-only
review of the original.
