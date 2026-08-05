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
- Grok SuperGrok: browser login for SuperGrok; no API key.
- z.ai, MiniMax, OpenCode Zen, OpenRouter, DeepSeek, Anthropic, Xiaomi MiMo, and Nous Research: API-key templates with provider-specific default environment variable names and headers.
- Nous Research (`nous-research`): Chat Completions at `https://inference-api.nousresearch.com/v1` with `NOUS_API_KEY` / `Authorization: Bearer $NOUS_API_KEY`. There is no published `/models` endpoint — add models with `cockpit provider add nous-research` or `/setup model`. Failed credential checks report a sanitized status and the portal docs link (`https://portal.nousresearch.com/api-docs`), never a raw provider response body or key material. Automatic x402 payment and non-chat Nous services are not supported.
- Baseten Model APIs (`baseten`): Chat Completions at `https://inference.baseten.co/v1` with `BASETEN_API_KEY` / `Authorization: Bearer $BASETEN_API_KEY`. Live catalog via `cockpit fetch-models baseten` (`GET /v1/models`). Input capabilities (vision/audio) stay model-dependent and conservatively Unknown until mapped; custom Baseten deployments use a separate custom/OpenAI-compatible provider entry, not this template.
- GitHub Copilot: OAuth-backed provider setup.

## Credentials

Provider config stores non-secret policy and references in layered `.cockpit/` config. Raw pasted secrets and OAuth tokens live in Cockpit's private credential store, not in project files. A project can name a provider or model, but workspace trust controls whether project config is loaded at all.

Environment-variable references are kept as references. For example, `Bearer $OPENAI_API_KEY` means Cockpit reads `OPENAI_API_KEY` from the process environment when it needs to call the provider.

## Test Key

The setup wizard can test credentials before saving. A failed test reports a sanitized status/classification and the template's documentation link (never a raw response body or key material) and leaves the wizard open so you can edit the key, header, endpoint, or model. Skipping the test stores the configuration without making a network call.

## Trust And Redaction

Workspace trust controls whether project `.cockpit/` config and project approvals are honored. Model trust is the sole model trust posture: trusted models disable outbound redaction, while untrusted models keep it enabled. Trusted models are intended for self-hosted providers; trusting an external provider is permitted and is the user's decision.

Secrets are scrubbed through Cockpit's redaction table before they leave the machine for model requests, exports, sync, or client display boundaries. Redaction is a safety boundary, but it is not a substitute for choosing providers and trust settings deliberately.
