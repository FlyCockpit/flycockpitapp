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

## Templates

- OpenAI-compatible: generic `/v1` endpoints with `Authorization: Bearer ...`.
- OpenAI Platform API: API key from `https://platform.openai.com/api-keys`; defaults to `$OPENAI_API_KEY`.
- Codex OAuth: browser/device-code login for ChatGPT Plus/Pro quota; no API key.
- Grok xAI API: API key from the xAI console; defaults to `$XAI_API_KEY`.
- Grok SuperGrok: browser login for SuperGrok; no API key.
- z.ai, MiniMax, OpenCode Zen, OpenRouter, DeepSeek, Anthropic, and Xiaomi MiMo: API-key templates with provider-specific default environment variable names and headers.
- GitHub Copilot: OAuth-backed provider setup.

## Credentials

Provider config stores non-secret policy and references in layered `.cockpit/` config. Raw pasted secrets and OAuth tokens live in Cockpit's private credential store, not in project files. A project can name a provider or model, but workspace trust controls whether project config is loaded at all.

Environment-variable references are kept as references. For example, `Bearer $OPENAI_API_KEY` means Cockpit reads `OPENAI_API_KEY` from the process environment when it needs to call the provider.

## Test Key

The setup wizard can test credentials before saving. A failed test reports the provider response and leaves the wizard open so you can edit the key, header, endpoint, or model. Skipping the test stores the configuration without making a network call.

## Trust And Redaction

Workspace trust controls whether project `.cockpit/` config and project approvals are honored. Model trust controls whether a model may receive exact prompts and tool results. Untrusted models keep outbound redaction enabled.

Secrets are scrubbed through Cockpit's redaction table before they leave the machine for model requests, exports, sync, or client display boundaries. Redaction is a safety boundary, but it is not a substitute for choosing providers and trust settings deliberately.
