# Provider Setup

Cockpit separates two kinds of sign-in:

- `cockpit provider ...` manages model providers such as OpenAI, Anthropic, OpenRouter, GitHub Copilot, and OpenAI-compatible endpoints.
- `cockpit account ...` signs in to Flycockpit account services for sync and relay features.

## Add A Provider

Use the TUI first-run flow or run:

```sh
cockpit provider add
cockpit provider add openai
```

The provider wizard asks for a template, a provider id, credentials, and a default model. API-key templates can store either a pasted key in the private credential store or a reference such as `$OPENAI_API_KEY` in provider config. OAuth templates open a browser/device-code flow and store refreshable tokens in the private credential store.

Useful commands:

```sh
cockpit provider list
cockpit provider usage
cockpit provider logout codex-oauth
cockpit fetch-models
cockpit provider-catalog-status
cockpit models
```

## In The TUI

`/model` only chooses an already configured model for the current session. Choose **Use for this session** for a session-only switch, or **Use and make default** to persist that active model for future sessions. It never changes provider/model configuration.

`/setup model` is the sole model-configuration flow. It starts with a choice to configure the confirmed session model or choose a different provider and one of that provider’s models. Choosing a current model does not switch the live session, and making a model the default remains an explicit configuration choice.

## Templates

- OpenAI-compatible: generic `/v1` endpoints with `Authorization: Bearer ...`.
- OpenAI Platform API: API key from `https://platform.openai.com/api-keys`; defaults to `$OPENAI_API_KEY`.
- Codex OAuth: browser/device-code login for ChatGPT Plus/Pro quota; no API key.
- Grok xAI API: API key from the xAI console; defaults to `$XAI_API_KEY`.
- Grok SuperGrok: shown as disabled pending xAI authorization. Follow the petition/learn-more link in the picker; the official binary does not include its browser OAuth flow.
- z.ai, MiniMax, OpenCode Zen, OpenRouter, DeepSeek, Anthropic, Xiaomi MiMo, and Nous Research: API-key templates with provider-specific default environment variable names and headers.
- Nous Research (`nous-research`): Chat Completions at `https://inference-api.nousresearch.com/v1` with `NOUS_API_KEY` / `Authorization: Bearer $NOUS_API_KEY`. There is no published `/models` endpoint — add models with `cockpit provider add nous-research` or `/setup model`. Failed credential checks report a sanitized status and the portal docs link (`https://portal.nousresearch.com/api-docs`), never a raw provider response body or key material. Automatic x402 payment and non-chat Nous services are not supported.
- Baseten Model APIs (`baseten`): Chat Completions at `https://inference.baseten.co/v1` with `BASETEN_API_KEY` / `Authorization: Bearer $BASETEN_API_KEY`. Live catalog via `cockpit fetch-models baseten` (`GET /v1/models`). Input capabilities (vision/audio) stay model-dependent and conservatively Unknown until mapped; custom Baseten deployments use a separate custom/OpenAI-compatible provider entry, not this template.
- GitHub Copilot: OAuth-backed provider setup.

## Anthropic-Compatible Endpoints

For a third-party endpoint that implements Anthropic's Messages wire (for
example, a proxy or aggregator rather than `api.anthropic.com`), add a custom
provider and choose **anthropic** in the wizard's wire picker. Enter the
endpoint's `/v1` base URL and the auth shape it documents:

- `x-api-key: $PROVIDER_API_KEY`
- `Authorization: Bearer $PROVIDER_API_KEY`

Bearer-authenticated endpoints receive `Authorization` only; Cockpit removes
the native client's required internal `x-api-key` header before the request is
sent. Keep `anthropic-version` as a normal provider header when the endpoint
requires it (the first-party Anthropic template uses `2023-06-01`).

Custom Anthropic-wire providers default to the portable Messages API. They do
not send `cache_control` blocks or `anthropic-beta` headers unless the gateway
explicitly supports those Anthropic extensions. Opt in per provider only after
confirming support:

```json
{
  "anthropic": {
    "prompt_caching": true,
    "betas": true
  }
}
```

`prompt_caching` enables prompt-cache blocks. `betas` permits the extended
cache-TTL and computer-use beta headers; without it, a one-hour cache setting
uses the compatible five-minute cache form. Third-party endpoints must support
the Messages request and streaming response formats; third-party Anthropic
OAuth or subscription login is not supported.

## Third-Party OpenAI Responses Endpoints

For a third-party endpoint that implements OpenAI's `/v1/responses` wire, add
a custom provider and choose **responses** in the wizard's wire picker. Enter
the endpoint's `/v1` base URL and configure the provider's documented Bearer
authentication, for example `Authorization: Bearer $PROVIDER_API_KEY`.

This is the generic OpenAI Responses path, not Codex OAuth: Cockpit sends the
Bearer credential only and never sends `chatgpt-account-id`, `originator`, or
the Codex `OpenAI-Beta` header. Responses requests are stateless: Cockpit sends
the complete conversation in `input`, always uses `store: false`, and never
sends `previous_response_id`, `background`, or server-side tools. Providers
that support it also receive the configured reasoning-effort control.

## Credentials

Provider config stores non-secret policy and references in layered `.cockpit/` config. Raw pasted secrets and OAuth tokens live in Cockpit's private credential store, not in project files. A project can name a provider or model, but workspace trust controls whether project config is loaded at all.

Environment-variable references are kept as references. For example, `Bearer $OPENAI_API_KEY` means Cockpit reads `OPENAI_API_KEY` from the process environment when it needs to call the provider.

## Custom Grok subscription authentication

The official binary does not ship a SuperGrok browser-login implementation pending xAI authorization. If you independently have a permitted way to obtain a subscription bearer token, configure it as a global user-layer custom OpenAI-compatible provider at your own risk. Do not put `auth_command` in project configuration: Cockpit intentionally ignores it there.

For example, this global provider entry calls a user-owned helper that prints a fresh credential JSON object. The helper is not supplied by FlyCockpit and must not print anything except JSON on stdout:

```json
{
  "url": "https://api.x.ai/v1",
  "auth": "command",
  "auth_command": ["/Users/you/bin/grok-subscription-token"],
  "wire_api": "completions",
  "models": [{ "id": "grok-4" }]
}
```

`/Users/you/bin/grok-subscription-token` must return:

```json
{"token":"your-current-bearer-token","expires_at":1767225600,"headers":null}
```

`expires_at` is a Unix timestamp and may be `null` when the helper should run for each new Cockpit process. The command can use `$VAR` or `$secret:name` references in its argv. It runs only from your global user provider layer, so review it as carefully as any other executable authentication helper. This path uses the normal OpenAI-compatible transport and has no built-in SuperGrok OAuth code.

## Test Key

The setup wizard can test credentials before saving. A failed test reports a sanitized status/classification and the template's documentation link (never a raw response body or key material) and leaves the wizard open so you can edit the key, header, endpoint, or model. Skipping the test stores the configuration without making a network call.

## Trust And Redaction

Workspace trust controls whether project `.cockpit/` config and project approvals are honored. Model trust is the capture/write setting: trusted models may participate in host-mediated capture, while untrusted models may not. Every inference request receives redacted, reference-only sealed values; missing trust resolves to untrusted.

Trusted is for a host-selected capture-capable endpoint. It never authorizes raw secret or environment-value delivery: model use of a sealed value always goes through an explicit grant and `use_sealed_value`. Trust is only ever set explicitly: neither model locality nor agent-definition posture implies it.

Agent definitions own harness steering, capabilities, prompts, and context policy. Harness mode never changes provider eligibility, data custody, or redaction. Provider/model trust remains an independent data-custody setting. Locality is descriptive and never implies trust — `local`, `remote`, and `private_remote` say where a provider runs, not what it may hold.

Exports and client display stay redacted regardless of trust. Sealed literals are scrubbed before every model or harness completion request; model use is reference-only. Redaction is a safety boundary, but it is not a substitute for choosing providers and trust settings deliberately.

## External Harness Custody

External harnesses (claude, codex, opencode, copilot, goose, grok, and any custom harness configured under `harnesses` in `/settings → Harnesses`) are OS processes, not trusted inference providers. They are **untrusted by default**. An explicit per-harness `trust` field can opt into host-mediated capture only; it never opts into raw prompt delivery and is never inferred from the harness's model name, locality, command, or agent-definition posture.

- **Untrusted harness** (the default): receives a redacted, reference-only rendering of the prompt. Sensitive environment, credential-store, and sealed values are redacted before every harness prompt regardless of its selected model string, location, or agent-definition posture. Disabling discretionary redaction (`redact.enabled = false`) does not disable this mandatory sensitive baseline.
- **Trusted harness** (explicit opt-in via `trust: "trusted"`): may participate in host-mediated capture, but receives the same redacted, reference-only prompt. Invocation records, child output, process records, histories, diagnostics, and `/export debug` receive only generic-redacted representations before write.

No harness, trusted or untrusted, receives Cockpit-provided secret environment values. The former `auth_env_vars` configuration field is retired and rejected: a harness must authenticate independently without a Cockpit-provided secret. Non-secret session-overlay entries may remain available to the subprocess.

Harness trust is a separate policy from configured provider/model `ModelTrust` and from agent-definition posture. Both trust settings control host-mediated capture eligibility, never raw inference egress. Agent-definition posture is a separate harness-steering concern and never alters harness subprocess custody.
