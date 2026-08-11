---
title: OpenRouter Images Setup
description: Exact OpenRouter direct Image API routes, discovery, routing, references, and output bounds.
---

The OpenRouter Images adapter (`openrouter_images`) connects to the configured
OpenRouter origin using the **direct Image API**. This page documents the exact
initial contract. Provider documentation was last verified 2026-08-04; link it
rather than copying unstable prose.

## Routes

| Route | Method | Use |
| --- | --- | --- |
| `/api/v1/images` | `POST` | Submit a generation request |
| `/api/v1/images/models` | `GET` | Discover available image models |
| `/api/v1/images/models/{author}/{slug}/endpoints` | `GET` | Discover endpoints for a model |

There is no `/images/generations` route, no server tool, no Responses/Chat
route, no orchestrator, and no generic routing JSON. The OpenRouter Image API
is a direct submission API with typed discovery and provider routing.

## Attribution headers

Every discovery, submission, and same-origin follow-up uses the attribution
header merge contract:

| Header | Default |
| --- | --- |
| `HTTP-Referer` | `https://flycockpit.dev` |
| `X-OpenRouter-Title` | `FlyCockpit` |

A non-empty configured value is preserved; an empty configured value is
removed; a missing header gets the canonical default.

## Redirects

Automatic redirects are disabled for all authenticated OpenRouter Image API
requests. Every 3xx is a stable failure — credentials and attribution cannot
cross origins.

## Model IDs

A model ID is exactly two nonempty path segments: `{author}/{slug}`. The
endpoint link for a model is exactly
`/api/v1/images/models/{author}/{slug}/endpoints`. Absolute URLs,
protocol-relative URLs, userinfo/query/fragment, dot/traversal, and encoded
separator components are rejected.

## Routing policy

The closed routing policy supports:

| Field | Effect |
| --- | --- |
| `only` | Retain only endpoints whose non-null tag is named |
| `ignore` | Remove all endpoints in each named tag group |
| `order` | Preserve relative priority of named tag groups without excluding others |
| `sort` | Scalar sort: `price`, `throughput`, or `latency` (object forms rejected) |
| `allow_fallbacks` | With `true`, every eligible endpoint is selectable |

`deny_unknown_fields` rejects arbitrary `provider.options`, unknown routing
keys, and provider passthrough. Duplicate entries within each list,
contradictory `only`/`ignore`, unknown names, and an empty eligible set are all
errors.

## References

Input references are typed as `{ type: "image_url", image_url: { url: <data URL> } }`.
Cockpit never accepts or emits an agent-supplied remote URL. Each reference is
built from an already-authorized typed attachment and encoded as a `data:` URL.

| Bound | Value |
| --- | --- |
| Maximum references per request | Limited by endpoint `input_references.max_count` |
| Maximum bytes per reference | 16 MiB (or endpoint cap, whichever is tighter) |
| Maximum aggregate reference bytes | 64 MiB (or endpoint cap, whichever is tighter) |

An absent or unparseable endpoint reference limit makes references unavailable —
the request fails closed.

## Output bounds

| Bound | Value |
| --- | --- |
| Output count (`n`) | 1–10, also limited by endpoint `n.max` |
| Output encoding | base64 (`data[].b64_json`) |
| Maximum output base64 bytes | 32 MiB |

There is no remote-output URL branch. Output bytes are canonically detected by
magic bytes; a present `media_type` must match detection. SVG outputs pass the
closed SVG sanitizer before retention.

## Dimensions

| Form | Example | Authorization |
| --- | --- | --- |
| Tier token | `512`, `1K`, `2K`, `4K` | Must appear in every possible endpoint's `resolution` enum |
| Explicit pixels | `1024x1024` | Must appear in a `size` descriptor across every endpoint |

Explicit pixels plus `resolution` always fails. An aspect ratio with explicit
pixels must be exact-rational consistent. `auto` aspect with explicit pixels is
rejected.

## Pricing and spend

Each endpoint carries its own pricing record with billable lines: `prompt`,
`image_request`, `image_output`, and `image_megapixel`. Cost is parsed from the
JSON number's lexical decimal form with checked arithmetic — no binary floating
point. The conservative plan maximum is the greatest known endpoint maximum. If
any possible endpoint's maximum is unknown, finite-budget authorization blocks.

A token-priced `prompt` line without a proven finite token maximum makes the
maximum unknown. Variants without a selected variant name in the request make
the maximum unknown.

## Setup

Configure an endpoint with `adapter: openrouter_images`, the OpenRouter origin,
a credential reference, and `route_profile_version: 1`.

```json
{
  "id": "openrouter-primary",
  "adapter": "openrouter_images",
  "origin": "https://openrouter.ai",
  "credential_ref": "openrouter_api_key",
  "location": "public_cloud",
  "enabled": true,
  "route_profile_version": 1
}
```

The example uses a placeholder credential reference and a normalized origin.
No live secret is required.
