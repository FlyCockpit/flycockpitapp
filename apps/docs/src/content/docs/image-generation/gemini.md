---
title: Gemini Images Setup
description: Exact Gemini Interactions API route, four-model catalog, response format, and output parsing.
---

The Gemini Images adapter (`gemini_images`) connects to the configured Gemini
origin using the raw Interactions API. This page documents the exact initial
contract. Provider documentation was last verified 2026-08-04; link it rather
than copying unstable prose.

## Route

| Route | Method | Credential header |
| --- | --- | --- |
| `/v1beta/interactions` | `POST` | `x-goog-api-key` |

There is no SDK convenience field (`.output_image`, `.output_text`), no legacy
`generateContent` / `generation_config.image_config` / `response_modalities`,
and no OpenAI-compatible facade. The REST DTOs model the raw Interactions API
union directly.

## Model catalog

The checked-in catalog (verified 2026-08-04) contains exactly four models:

| Model | Aspect ratios | Image sizes | Formats | Max references |
| --- | --- | --- | --- | --- |
| `gemini-3.1-flash-lite-image` | 1:1, 3:4, 4:3 | small, medium | PNG, JPEG | 1 |
| `gemini-3.1-flash-image` | 1:1, 3:4, 4:3, 9:16, 16:9 | small, medium, large | PNG, JPEG | 4 |
| `gemini-3-pro-image` | 1:1, 3:4, 4:3, 9:16, 16:9 | small, medium, large | PNG, JPEG, WebP | 4 |
| `gemini-2.5-flash-image` | 1:1, 3:4, 4:3 | small, medium | PNG, JPEG | 1 |

Any other model, alias, preview, `latest` name, or future image model is
unavailable until a freshly reviewed catalog update. Model name matching is
exact and case-sensitive.

## Control policies

Each control is either `explicit` (set to a catalog-supported value) or
`provider_default` (omitted; the provider chooses):

| Model | `aspect_ratio` | `image_size` | `mime_type` |
| --- | --- | --- | --- |
| `gemini-3.1-flash-lite-image` | explicit | explicit | explicit |
| `gemini-3.1-flash-image` | explicit | explicit | explicit |
| `gemini-3-pro-image` | explicit | explicit | explicit |
| `gemini-2.5-flash-image` | explicit | provider-default | explicit |

For `gemini-2.5-flash-image`, `image_size` is omitted from the request and the
provider chooses the default.

## Response format

The top-level `response_format` carries the image `mime_type`. Output is parsed
from the raw `steps[]` `model_output` `content[]` image fields — no SDK
`output_image` convenience accessor. Reference bytes are local typed attachments
encoded inline after aggregate limits; remote reference URIs are not sent in
the initial adapter.

## Bounds

| Bound | Value |
| --- | --- |
| Maximum inline image bytes | 20 MiB |
| Maximum reference images | 4 (or per-model catalog cap) |

The requested sample count is planning intent, not a provider guarantee.

## Setup

Configure an endpoint with `adapter: gemini_images`, the Gemini origin, a
credential reference, and `route_profile_version: 1`.

```json
{
  "id": "gemini-primary",
  "adapter": "gemini_images",
  "origin": "https://generativelanguage.googleapis.com",
  "credential_ref": "gemini_api_key",
  "location": "public_cloud",
  "enabled": true,
  "route_profile_version": 1
}
```

The example uses a placeholder credential reference and a normalized origin.
No live secret is required.
