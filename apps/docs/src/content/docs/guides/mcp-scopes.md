---
title: MCP scopes, credential profiles, and device flow
description: Global, workspace, and agent MCP servers; named credential profiles; RFC 8628 device-flow auth; and when config changes take effect.
---

MCP servers can be defined at three scopes. Bindings — which servers an agent gets, and with which credential profile — live on the agent definition.

## Scopes and precedence

| Scope | Location |
| --- | --- |
| Global | `~/.config/cockpit/mcp.json` and `~/.cockpit/mcp.json` |
| Workspace | `.cockpit/mcp.json` (trust-gated, as today) |
| Agent | `mcp.json` inside an agent package (`agents/<name>/mcp.json`) |

Same-named servers resolve **workspace > agent > global**. Shadowing is never silent: the effective catalog keeps a `shadowed_by` marker for the UI. The builtin `cockpit` server cannot be defined, shadowed, or unbound at any scope.

`cockpit mcp add --scope global|workspace|agent[=<name>]` chooses the write target. `global` and `workspace` are a single `SaveMcpConfig` CAS; `agent` is a single `MutateAgent` / editor-lease CAS. An open editor lease (8h, non-renewable) is a structured "agent is being edited" refusal.

## Credential profiles

A server may declare named `profiles` in addition to the flat `auth` block. Existing configs keep an implicit `default` profile and round-trip byte-for-byte. An agent binding is `{server, profile}`. Vault keys are `mcp:<server>:<profile>` (the historical `mcp:<server>` key remains the default-profile alias). `$secret:name` references in MCP headers resolve through the credential store.

Agent-bound servers use agent-dimensioned approval grant keys, so a grant for agent A does not satisfy agent B. Scope-level servers keep the historical `server/tool` keys. Pre-release grant invalidation is acceptable. Child catalogs keep scope-level servers and intersect agent-bound servers with the parent-reachable set.

## Device flow (RFC 8628)

When `auth.kind` is `oauth` and `device_authorization_endpoint` is set, Cockpit runs RFC 8628 device flow instead of a loopback redirect. The TUI shows the verification URI and the user code with a "confirm this code" caption. Display strings are validated before they are shown or opened. Tokens land in the ownership-guarded vault under the profile-aware key.

## Staleness

MCP config changes (new/edited servers at global or workspace scope) take effect on the next tool call. Agent-binding changes apply when the agent is next rebuilt. Mutation responses that change a live binding say which sessions see the change when.

## Approvals

CLI connection-approval details live in `apps/cli/docs/mcp-approvals.md`. Agent-bound grant keys are a new dimension; existing `server/tool` grants still apply to scope-level servers.
