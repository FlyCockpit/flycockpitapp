---
title: OpenAI Images Setup
description: Exact OpenAI Images API routes, model catalog, reference and output bounds, and legacy exclusion.
---

The OpenAI Images adapter (`openai_images`) connects to the configured OpenAI
origin using the direct Images API. This page documents the exact initial
contract. Provider documentation was last verified 2026-08-04; link it rather
than copying unstable prose.

## Routes

| Route | Method | Use |
| --- | --- | --- |
| `/v1/images/generations` | `POST` | Prompt-only plans (no references) |
| `/v1/images/edits` | `POST` (multipart) | Plans with one or more typed image references |

There is no Responses, Chat, or DALL-E architecture. Only `data[].b64_json` is
parsed into bounded bytes; there is no URL-output branch.

## Model catalog

The checked-in catalog (revision 1, verified 2026-08-04) contains exactly these
models:

| Model identity | Wire name |
| --- | --- |
| GPT Image 2 | `gpt-image-2` |
| GPT Image 2 dated snapshot | `gpt-image-2-2026-04-21` |
| GPT Image 1.5 | `gpt-image-1.5` |
| GPT Image 1 Mini | `gpt-image-1-mini` |

### Legacy exclusion

`gpt-image-1` is **deliberately excluded**. Official OpenAI guidance classifies
it as legacy compatibility only, and pre-release Cockpit carries no legacy
compatibility role. It never appears as a selectable model or in setup guidance.
A request naming `gpt-image-1` fails preflight with an unknown-model error.

Unknown or newly observed model values are unavailable — they are not guessed
or mapped to a similar model. A catalog update requires a fresh review and a
revision bump.

## Prompt and output bounds

| Bound | Value |
| --- | --- |
| Maximum prompt length | 32,000 Unicode scalar values |
| Maximum prompt UTF-8 bytes | 128,000 bytes |
| Output count (`n`) | 1–10, must equal the immutable planned slot count |
| Output encoding | base64 GPT Image output (`data[].b64_json`) |

## References (edits route)

Plans with one or more authorized typed image references use the multipart
`POST /v1/images/edits` route. Reference limits:

| Bound | Value |
| --- | --- |
| Maximum references per request | 16 |
| Multipart parts | Bounded typed media values with deterministic order and provider field names |

References are typed attachments (`attachment_id` or daemon-local `local_path`),
normalized once into bounded media. Raw URLs and provider JSON are rejected at
the schema layer.

## Typed controls

The catalog stores quality, background, output format, compression, and
moderation as typed descriptors. All four catalog entries support `auto`,
`low`, `medium`, and `high` quality. Transparent background requires PNG or
WebP and is rejected for both `gpt-image-2` identities. Unknown values fail
preflight.

## Submission safety

Automatic submission retry is forbidden unless transport evidence proves no
request byte was accepted. A timeout or reset after handoff becomes
`submission_unknown` — the provider may or may not have processed the request.
Credential data and raw reference bytes are absent from logs, journal metadata,
and errors.

## Setup

Configure an endpoint with `adapter: openai_images`, the OpenAI origin, a
credential reference, and `route_profile_version: 1`. The origin is normalized:
no userinfo, query, fragment, or non-root path. `allow_insecure_transport` is
rejected for `https` origins. See [Security and Budgets](../security-and-budgets/)
for credential and spend requirements.

```json
{
  "id": "openai-primary",
  "adapter": "openai_images",
  "origin": "https://api.openai.com",
  "credential_ref": "openai_api_key",
  "location": "public_cloud",
  "enabled": true,
  "route_profile_version": 1
}
```

The example uses a placeholder credential reference and a normalized origin.
No live secret is required.
