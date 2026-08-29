---
title: Agent definition packages and multi-model slots
description: Directory-form agent packages, nearest-project resolution, and load-bearing model slots.
---

Single-file agent defs (`agents/<name>.md`) remain fully valid. A directory package is opt-in.

## Package layout

```text
agents/<name>/
  agent.md                 # root definition (required)
  subagents/<child>.md     # private subagents (optional)
  mcp.json                 # agent-scope MCP registry (same schema as layer files)
  <slot>.md                # per-slot prompt overrides (optional)
```

Package identity is whole-tree: the digest covers the sorted relative paths and contents of every file. A single-file def's digest is still the canonical `to_markdown()` bytes, so existing installations do not flip to `rebind_required`.

Private subagents are visible only through the parent's `allowedChildren`. They never appear in agent pickers or `GetAgentInventory`. `mode: primary` under `subagents/` is a validation error. A private name that collides with a global agent wins inside its parent (with a load warning).

## Delegation

- `"self"` in `allowedChildren` is explicit self-invocation and counts against `maxDescendantDepth` / `maxConcurrentChildren`.
- `defaultChild: <name>` is used when a parent delegates without naming an agent; otherwise today's default resolution applies.

## Multi-model slots

A model slot may list multiple allowed models with exactly one default:

```yaml
modelSlots:
  primary:
    purpose: Conversational coding
    minContextTokens: 8
    requiredCapabilities: [text_generation]
    locality: any
    allowDefaultFallback: false
    models:
      - providerId: anthropic
        modelId: claude-opus-4
        default: true
      - providerId: openai
        modelId: gpt-5
```

Empty `models` keeps today's any-compatible binding. Durable defaults and bindings are keyed `(provider_id, model_id)` — never `choice_id`.

## Selection semantics

- A fresh session with an installed vNext agent runs the primary-slot **default**. Resume keeps the session's persisted model.
- The session model picker shows the slot's allowed models first (default marked), then other compatible installed models. Picking outside the set is a derived-def path with a lint, never silent widening.
- Subagents run their slot default unless the parent names one of the child slot's **allowed** models. Naming anything else is a structured refusal.
- Adjudicator and question-resolver slots stay on the slot default and ignore session-scoped model overrides.

## Resolution order

Agent discovery is **nearest-project-wins**, matching `mcp.json` layering. A home def no longer silently shadows a workspace file. A shadowed lower-precedence def emits a load warning. Configured `agent_dirs` layers extend rather than replace.
