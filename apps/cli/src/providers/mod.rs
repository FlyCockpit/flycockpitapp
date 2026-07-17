#![allow(dead_code)]
//! Built-in provider templates.
//!
//! The Add-Provider wizard offers these as prefill choices, in addition
//! to the catch-all `openai-compatible` template. Adapted from
//! `mixer-rs/src/providers/{glm,minimax,opencode}.rs` — the URLs,
//! display names, and auth shape match what mixer ships with.
//!
//! These are *templates*, not provider implementations: a user that
//! picks `z.ai` ends up with a regular [`crate::config::providers::ProviderEntry`]
//! whose URL and headers are pre-populated. No special code path runs at
//! request time.

pub(crate) mod auth_check;
pub(crate) mod http_retry;
pub mod models_fetch;
pub(crate) mod registry;
pub mod usage;

pub(crate) use registry::ProviderRegistry;

use std::env;

use crate::config::providers::{AuthKind, HeaderSpec, ThinkingMode, WireApi};
use serde_json::{Value, json};

/// One picker entry in the Add Provider wizard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderTemplate {
    /// Stable id used as the config-map key.
    pub id: &'static str,
    /// Human-readable label shown in the picker.
    pub display: &'static str,
    /// Pre-filled base URL.
    pub url: &'static str,
    /// Auth model — drives wizard prompts (env-var name, OAuth flow, etc.).
    pub auth: AuthKind,
    /// Suggested env-var name for API-key providers. Used to seed the
    /// Authorization header value with `Bearer $NAME`.
    pub default_env_var: Option<&'static str>,
    /// Ordered env-var names to prefer when they are already set in the
    /// current process. The config still stores a `$NAME` reference, never
    /// the secret value.
    pub env_var_candidates: &'static [&'static str],
    /// Headers to write into config. `value` may contain `$VAR`
    /// references; the wizard auto-fills `$default_env_var` if present.
    pub default_headers: &'static [(&'static str, &'static str)],
    /// Whether the upstream exposes a `/models` endpoint we can hit.
    pub supports_models_endpoint: bool,
    /// One-liner shown under the URL field — typically a link to the
    /// vendor's API-key page.
    pub hint: Option<&'static str>,
    /// If `true`, the template's `id` may be used as the default when
    /// adding. The OpenAI-compatible template is `false` because the
    /// user is expected to add several of them (one per vendor) and
    /// they must each have distinct ids.
    pub use_id_as_default: bool,
    /// Provider-level wire endpoint default for newly materialized entries.
    pub default_wire_api: WireApi,
    /// API-key entry metadata for the key-first setup wizard.
    pub api_key: Option<ApiKeyTemplate>,
    /// User-visible setup/doctor credential check for this template.
    pub auth_check: AuthCheckKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiKeyTemplate {
    pub header_name: &'static str,
    pub value_template: &'static str,
    pub format_hint: &'static str,
    pub console_url: &'static str,
}

impl ApiKeyTemplate {
    pub fn value_for_key(&self, key: &str) -> String {
        self.value_template.replace("{key}", key.trim())
    }

    pub fn value_for_env_var(&self, env_var: &str) -> String {
        self.value_template
            .replace("{key}", &format!("${}", env_var.trim()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthCheckKind {
    ModelsEndpoint,
    ChatCompletions {
        path: &'static str,
        model: &'static str,
        docs_url: &'static str,
    },
}

/// The catalog the wizard cycles through. `openai-compatible` is first
/// (per the user spec) so it's the default landing entry in the picker.
pub const TEMPLATES: &[ProviderTemplate] = &[
    ProviderTemplate {
        id: "openai-compatible",
        display: "OpenAI-compatible",
        url: "",
        auth: AuthKind::ApiKey,
        default_env_var: None,
        env_var_candidates: &[],
        default_headers: &[("Authorization", "Bearer $API_KEY")],
        supports_models_endpoint: true,
        hint: Some(
            "Generic OpenAI-compatible endpoint. You can add as many of these as you want; each one needs a unique id.",
        ),
        use_id_as_default: false,
        default_wire_api: WireApi::Auto,
        api_key: Some(ApiKeyTemplate {
            header_name: "Authorization",
            value_template: "Bearer {key}",
            format_hint: "OpenAI-compatible API key",
            console_url: "https://platform.openai.com/api-keys",
        }),
        auth_check: AuthCheckKind::ModelsEndpoint,
    },
    ProviderTemplate {
        id: "openai",
        display: "OpenAI Platform API",
        url: "https://api.openai.com/v1",
        auth: AuthKind::ApiKey,
        default_env_var: Some("OPENAI_API_KEY"),
        env_var_candidates: &["OPENAI_API_KEY", "OPENAI_TOKEN", "OPENAI_API_TOKEN"],
        default_headers: &[("Authorization", "Bearer $OPENAI_API_KEY")],
        supports_models_endpoint: true,
        hint: Some(
            "Generate a key at https://platform.openai.com/api-keys. GPT-5-family models use the Responses API.",
        ),
        use_id_as_default: true,
        default_wire_api: WireApi::Auto,
        api_key: Some(ApiKeyTemplate {
            header_name: "Authorization",
            value_template: "Bearer {key}",
            format_hint: "starts with sk-",
            console_url: "https://platform.openai.com/api-keys",
        }),
        auth_check: AuthCheckKind::ModelsEndpoint,
    },
    ProviderTemplate {
        id: "codex-oauth",
        display: "Codex (ChatGPT Plus/Pro)",
        url: "https://chatgpt.com/backend-api/codex",
        auth: AuthKind::OAuth,
        default_env_var: None,
        env_var_candidates: &[],
        default_headers: &[],
        supports_models_endpoint: true,
        hint: Some(
            "Subscription login via device code at auth.openai.com/codex/device; no OPENAI_API_KEY. Uses ChatGPT Plus/Pro quota.",
        ),
        use_id_as_default: true,
        default_wire_api: WireApi::Responses,
        api_key: None,
        auth_check: AuthCheckKind::ModelsEndpoint,
    },
    ProviderTemplate {
        id: "grok",
        display: "Grok (xAI API)",
        url: "https://api.x.ai/v1",
        auth: AuthKind::ApiKey,
        default_env_var: Some("XAI_API_KEY"),
        env_var_candidates: &["XAI_API_KEY", "GROK_API_KEY", "XAI_TOKEN", "GROK_TOKEN"],
        default_headers: &[("Authorization", "Bearer $XAI_API_KEY")],
        supports_models_endpoint: true,
        hint: Some(
            "Generate a key at https://console.x.ai/team/default/api-keys. Uses the Responses API.",
        ),
        use_id_as_default: true,
        default_wire_api: WireApi::Responses,
        api_key: Some(ApiKeyTemplate {
            header_name: "Authorization",
            value_template: "Bearer {key}",
            format_hint: "starts with xai- or a provider-issued xAI key",
            console_url: "https://console.x.ai/team/default/api-keys",
        }),
        auth_check: AuthCheckKind::ModelsEndpoint,
    },
    ProviderTemplate {
        id: "grok-oauth",
        display: "Grok (SuperGrok)",
        url: "https://api.x.ai/v1",
        auth: AuthKind::OAuth,
        default_env_var: None,
        env_var_candidates: &[],
        default_headers: &[],
        supports_models_endpoint: true,
        hint: Some(
            "Standalone SuperGrok browser login at accounts.x.ai; no XAI_API_KEY required. X Premium+ does not include xAI API access; HTTP 403/tier denial means use Grok (xAI API).",
        ),
        use_id_as_default: true,
        default_wire_api: WireApi::Responses,
        api_key: None,
        auth_check: AuthCheckKind::ModelsEndpoint,
    },
    ProviderTemplate {
        id: "z-ai",
        display: "z.ai (GLM)",
        url: "https://api.z.ai/api/paas/v4",
        auth: AuthKind::ApiKey,
        default_env_var: Some("Z_AI_API_KEY"),
        env_var_candidates: &["Z_AI_API_KEY", "ZAI_API_KEY", "Z_AI_TOKEN", "ZAI_TOKEN"],
        default_headers: &[("Authorization", "Bearer $Z_AI_API_KEY")],
        supports_models_endpoint: false,
        hint: Some("Generate a key at https://z.ai/manage-apikey/apikey-list"),
        use_id_as_default: true,
        default_wire_api: WireApi::Auto,
        api_key: Some(ApiKeyTemplate {
            header_name: "Authorization",
            value_template: "Bearer {key}",
            format_hint: "Z.AI API key or JWT token",
            console_url: "https://z.ai/manage-apikey/apikey-list",
        }),
        // Z.AI documents API-key auth via `Authorization: Bearer` and
        // `POST /chat/completions` as the authenticated HTTP API path:
        // https://docs.z.ai/api-reference/llm/chat-completion
        auth_check: AuthCheckKind::ChatCompletions {
            path: "/chat/completions",
            model: "glm-5.1",
            docs_url: "https://docs.z.ai/api-reference/llm/chat-completion",
        },
    },
    ProviderTemplate {
        id: "minimax",
        display: "MiniMax",
        url: "https://api.minimax.io/v1",
        auth: AuthKind::ApiKey,
        default_env_var: Some("MINIMAX_API_KEY"),
        env_var_candidates: &["MINIMAX_API_KEY", "MINIMAX_TOKEN", "MINIMAX_KEY"],
        default_headers: &[("Authorization", "Bearer $MINIMAX_API_KEY")],
        supports_models_endpoint: true,
        hint: Some("Generate a key at https://platform.minimaxi.com/"),
        use_id_as_default: true,
        default_wire_api: WireApi::Auto,
        api_key: Some(ApiKeyTemplate {
            header_name: "Authorization",
            value_template: "Bearer {key}",
            format_hint: "MiniMax API key",
            console_url: "https://platform.minimaxi.com/",
        }),
        auth_check: AuthCheckKind::ModelsEndpoint,
    },
    ProviderTemplate {
        id: "opencode-zen",
        display: "OpenCode Zen",
        url: "https://opencode.ai/zen/v1",
        auth: AuthKind::ApiKey,
        default_env_var: Some("OPENCODE_ZEN_TOKEN"),
        env_var_candidates: &[
            "OPENCODE_ZEN_TOKEN",
            "OPENCODE_ZEN_API_KEY",
            "OPENCODE_TOKEN",
        ],
        default_headers: &[("Authorization", "Bearer $OPENCODE_ZEN_TOKEN")],
        supports_models_endpoint: true,
        hint: Some("Generate a token at https://opencode.ai/zen"),
        use_id_as_default: true,
        default_wire_api: WireApi::Auto,
        api_key: Some(ApiKeyTemplate {
            header_name: "Authorization",
            value_template: "Bearer {key}",
            format_hint: "OpenCode Zen token",
            console_url: "https://opencode.ai/zen",
        }),
        auth_check: AuthCheckKind::ModelsEndpoint,
    },
    ProviderTemplate {
        id: "copilot",
        display: "GitHub Copilot",
        url: "https://api.githubcopilot.com",
        auth: AuthKind::ApiKey,
        default_env_var: Some("COPILOT_GITHUB_TOKEN"),
        env_var_candidates: &["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"],
        default_headers: &[("Authorization", "Bearer $COPILOT_GITHUB_TOKEN")],
        supports_models_endpoint: true,
        hint: Some(
            "Auth uses GitHub's documented tokens. Set COPILOT_GITHUB_TOKEN, GH_TOKEN, or GITHUB_TOKEN to a GitHub OAuth/App/fine-grained token with Copilot access (a token from the `copilot` CLI works). COPILOT_API_URL overrides the base URL.",
        ),
        use_id_as_default: true,
        default_wire_api: WireApi::Auto,
        api_key: Some(ApiKeyTemplate {
            header_name: "Authorization",
            value_template: "Bearer {key}",
            format_hint: "GitHub token with Copilot access",
            console_url: "https://github.com/settings/tokens",
        }),
        auth_check: AuthCheckKind::ModelsEndpoint,
    },
    ProviderTemplate {
        id: "openrouter",
        display: "OpenRouter",
        url: "https://openrouter.ai/api/v1",
        auth: AuthKind::ApiKey,
        default_env_var: Some("OPENROUTER_API_KEY"),
        env_var_candidates: &["OPENROUTER_API_KEY", "OPENROUTER_TOKEN"],
        default_headers: &[("Authorization", "Bearer $OPENROUTER_API_KEY")],
        supports_models_endpoint: true,
        hint: Some("Generate a key at https://openrouter.ai/keys"),
        use_id_as_default: true,
        default_wire_api: WireApi::Auto,
        api_key: Some(ApiKeyTemplate {
            header_name: "Authorization",
            value_template: "Bearer {key}",
            format_hint: "starts with sk-or-",
            console_url: "https://openrouter.ai/keys",
        }),
        auth_check: AuthCheckKind::ModelsEndpoint,
    },
    ProviderTemplate {
        id: "deepseek",
        display: "DeepSeek",
        url: "https://api.deepseek.com/v1",
        auth: AuthKind::ApiKey,
        default_env_var: Some("DEEPSEEK_API_KEY"),
        env_var_candidates: &["DEEPSEEK_API_KEY", "DEEPSEEK_TOKEN"],
        default_headers: &[("Authorization", "Bearer $DEEPSEEK_API_KEY")],
        supports_models_endpoint: true,
        hint: Some("Generate a key at https://platform.deepseek.com/api_keys"),
        use_id_as_default: true,
        default_wire_api: WireApi::Auto,
        api_key: Some(ApiKeyTemplate {
            header_name: "Authorization",
            value_template: "Bearer {key}",
            format_hint: "starts with sk-",
            console_url: "https://platform.deepseek.com/api_keys",
        }),
        auth_check: AuthCheckKind::ModelsEndpoint,
    },
    ProviderTemplate {
        id: "anthropic",
        display: "Anthropic (Claude API)",
        url: "https://api.anthropic.com/v1",
        auth: AuthKind::ApiKey,
        default_env_var: Some("ANTHROPIC_API_KEY"),
        env_var_candidates: &["ANTHROPIC_API_KEY", "ANTHROPIC_TOKEN"],
        default_headers: &[
            ("x-api-key", "$ANTHROPIC_API_KEY"),
            ("anthropic-version", "2023-06-01"),
        ],
        supports_models_endpoint: true,
        hint: Some(
            "Sanctioned API-key path. Generate a key at https://console.anthropic.com/settings/keys. Anthropic Pro/Max OAuth passthrough is intentionally not offered (see GOALS §20).",
        ),
        use_id_as_default: true,
        default_wire_api: WireApi::Auto,
        api_key: Some(ApiKeyTemplate {
            header_name: "x-api-key",
            value_template: "{key}",
            format_hint: "starts with sk-ant-",
            console_url: "https://console.anthropic.com/settings/keys",
        }),
        auth_check: AuthCheckKind::ModelsEndpoint,
    },
    ProviderTemplate {
        id: "xiaomi-mimo",
        display: "Xiaomi MiMo",
        url: "https://api.xiaomimimo.com/v1",
        auth: AuthKind::ApiKey,
        default_env_var: Some("MIMO_API_KEY"),
        env_var_candidates: &[
            "MIMO_API_KEY",
            "MIMO_TOKEN",
            "XIAOMI_MIMO_API_KEY",
            "XIAOMI_MIMO_TOKEN",
        ],
        default_headers: &[("Authorization", "Bearer $MIMO_API_KEY")],
        supports_models_endpoint: true,
        hint: Some(
            "Xiaomi MiMo open platform. Generate a key at https://api.xiaomimimo.com/. Flagship is MiMo-V2.5-Pro (1M context); MiMo-V2-Flash is the cheap-fast tier.",
        ),
        use_id_as_default: true,
        default_wire_api: WireApi::Auto,
        api_key: Some(ApiKeyTemplate {
            header_name: "Authorization",
            value_template: "Bearer {key}",
            format_hint: "Xiaomi MiMo API key",
            console_url: "https://api.xiaomimimo.com/",
        }),
        auth_check: AuthCheckKind::ModelsEndpoint,
    },
];

pub fn template_by_id(id: &str) -> Option<&'static ProviderTemplate> {
    TEMPLATES.iter().find(|t| t.id == id)
}

/// Built-in `ThinkingMode` → extra-request-body fragment for a provider
/// id — the bottom tier of the three-tier resolution in
/// [`crate::config::providers::ProvidersConfig::resolve_thinking_params`]
/// (implementation note). This is the *only* place a
/// provider id is mapped to a vendor reasoning-control shape; the request
/// builder never branches on a provider string. A provider with no
/// built-in mapping (or a mode with no entry) returns `None`, so existing
/// providers send no extra body keys and stay byte-for-byte unchanged.
///
/// DeepSeek (`deepseek`): "Off disables, every level enables." `Off`
/// explicitly sends the disabled form (not omission) so a default-on
/// endpoint is forced off; each thinking level enables and sets
/// `reasoning_effort` to the matching tier.
pub fn builtin_thinking_params(provider: &str, mode: ThinkingMode) -> Option<Value> {
    match provider {
        "deepseek" => Some(match mode {
            ThinkingMode::Off => json!({ "thinking": { "type": "disabled" } }),
            ThinkingMode::Low => {
                json!({ "thinking": { "type": "enabled" }, "reasoning_effort": "low" })
            }
            ThinkingMode::Medium => {
                json!({ "thinking": { "type": "enabled" }, "reasoning_effort": "medium" })
            }
            ThinkingMode::High => {
                json!({ "thinking": { "type": "enabled" }, "reasoning_effort": "high" })
            }
        }),
        _ => None,
    }
}

/// Materialize the template's default headers into an owned `Vec`.
pub fn default_headers_for(template: &ProviderTemplate) -> Vec<HeaderSpec> {
    default_headers_for_with_env(template, env_var_is_nonempty)
}

pub fn headers_for_pasted_key(template: &ProviderTemplate, key: &str) -> Vec<HeaderSpec> {
    let Some(api_key) = template.api_key else {
        return default_headers_for(template);
    };
    headers_with_key_value(template, api_key.value_for_key(key))
}

pub fn headers_for_env_var(template: &ProviderTemplate, env_var: &str) -> Vec<HeaderSpec> {
    let Some(api_key) = template.api_key else {
        return default_headers_for(template);
    };
    headers_with_key_value(template, api_key.value_for_env_var(env_var))
}

fn headers_with_key_value(template: &ProviderTemplate, key_value: String) -> Vec<HeaderSpec> {
    let Some(api_key) = template.api_key else {
        return default_headers_for(template);
    };
    let mut replaced = false;
    let mut headers = template
        .default_headers
        .iter()
        .map(|(name, value)| {
            let is_key = name.eq_ignore_ascii_case(api_key.header_name);
            if is_key {
                replaced = true;
            }
            HeaderSpec {
                name: (*name).to_string(),
                value: if is_key {
                    key_value.clone()
                } else {
                    (*value).to_string()
                },
            }
        })
        .collect::<Vec<_>>();
    if !replaced {
        headers.insert(
            0,
            HeaderSpec {
                name: api_key.header_name.to_string(),
                value: key_value,
            },
        );
    }
    headers
}

fn default_headers_for_with_env(
    template: &ProviderTemplate,
    is_nonempty_env: impl Fn(&str) -> bool,
) -> Vec<HeaderSpec> {
    let selected_env = selected_env_var(template, is_nonempty_env);
    template
        .default_headers
        .iter()
        .map(|(n, v)| HeaderSpec {
            name: (*n).to_string(),
            value: header_value_with_env(template.default_env_var, selected_env, v),
        })
        .collect()
}

fn selected_env_var(
    template: &ProviderTemplate,
    is_nonempty_env: impl Fn(&str) -> bool,
) -> Option<&'static str> {
    let default = template.default_env_var?;
    template
        .env_var_candidates
        .iter()
        .copied()
        .find(|name| is_nonempty_env(name))
        .or(Some(default))
}

fn env_var_is_nonempty(name: &str) -> bool {
    env::var_os(name).is_some_and(|value| !value.to_string_lossy().is_empty())
}

fn header_value_with_env(
    default_env_var: Option<&str>,
    selected_env_var: Option<&str>,
    value: &str,
) -> String {
    match (default_env_var, selected_env_var) {
        (Some(default), Some(selected)) if default != selected => {
            value.replace(&format!("${default}"), &format!("${selected}"))
        }
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_compatible_is_first() {
        assert_eq!(TEMPLATES[0].id, "openai-compatible");
    }

    #[test]
    fn every_template_has_a_display_label() {
        for t in TEMPLATES {
            assert!(!t.display.is_empty(), "template {} missing display", t.id);
        }
    }

    #[test]
    fn api_key_templates_declare_key_and_auth_check() {
        for template in TEMPLATES
            .iter()
            .filter(|template| matches!(template.auth, AuthKind::ApiKey))
        {
            let api_key = template
                .api_key
                .as_ref()
                .unwrap_or_else(|| panic!("{} missing API-key metadata", template.id));
            assert!(
                !api_key.header_name.is_empty(),
                "{} missing key header",
                template.id
            );
            assert!(
                api_key.value_template.contains("{key}"),
                "{} key template must include {{key}}",
                template.id
            );
            assert!(
                !api_key.format_hint.is_empty(),
                "{} missing key format hint",
                template.id
            );
            assert!(
                api_key.console_url.starts_with("https://"),
                "{} missing console URL",
                template.id
            );
            if !template.supports_models_endpoint {
                assert!(
                    matches!(template.auth_check, AuthCheckKind::ChatCompletions { .. }),
                    "{} without /models must declare explicit auth_check",
                    template.id
                );
            }
        }
    }

    #[test]
    fn lookup_by_id() {
        assert!(template_by_id("openai").is_some());
        assert!(template_by_id("codex-oauth").is_some());
        assert!(template_by_id("grok").is_some());
        assert!(template_by_id("grok-oauth").is_some());
        assert!(template_by_id("z-ai").is_some());
        assert!(template_by_id("minimax").is_some());
        assert!(template_by_id("openrouter").is_some());
        assert!(template_by_id("deepseek").is_some());
        assert!(template_by_id("anthropic").is_some());
        assert!(template_by_id("nope").is_none());

        let mimo = template_by_id("xiaomi-mimo").expect("xiaomi-mimo template");
        assert_eq!(mimo.url, "https://api.xiaomimimo.com/v1");
        assert_eq!(mimo.default_env_var, Some("MIMO_API_KEY"));
        assert_eq!(
            mimo.default_headers,
            &[("Authorization", "Bearer $MIMO_API_KEY")]
        );
    }

    #[test]
    fn openai_templates_are_ordered_and_configured() {
        let openai_idx = TEMPLATES.iter().position(|t| t.id == "openai").unwrap();
        let codex_idx = TEMPLATES
            .iter()
            .position(|t| t.id == "codex-oauth")
            .unwrap();
        assert!(openai_idx < codex_idx);

        let openai = template_by_id("openai").expect("openai template");
        assert_eq!(openai.url, "https://api.openai.com/v1");
        assert_eq!(openai.auth, AuthKind::ApiKey);
        assert_eq!(openai.default_env_var, Some("OPENAI_API_KEY"));
        assert_eq!(
            openai.env_var_candidates,
            &["OPENAI_API_KEY", "OPENAI_TOKEN", "OPENAI_API_TOKEN"]
        );
        assert_eq!(
            openai.default_headers,
            &[("Authorization", "Bearer $OPENAI_API_KEY")]
        );
        assert_eq!(openai.default_wire_api, WireApi::Auto);

        let codex = template_by_id("codex-oauth").expect("codex-oauth template");
        assert_eq!(codex.url, "https://chatgpt.com/backend-api/codex");
        assert_eq!(codex.auth, AuthKind::OAuth);
        assert!(codex.default_headers.is_empty());
        assert!(codex.env_var_candidates.is_empty());
        assert_eq!(codex.default_wire_api, WireApi::Responses);
    }

    #[test]
    fn grok_templates_are_ordered_and_configured() {
        let grok_idx = TEMPLATES.iter().position(|t| t.id == "grok").unwrap();
        let oauth_idx = TEMPLATES.iter().position(|t| t.id == "grok-oauth").unwrap();
        assert!(grok_idx < oauth_idx);

        let grok = template_by_id("grok").expect("grok template");
        assert_eq!(grok.url, "https://api.x.ai/v1");
        assert_eq!(grok.auth, AuthKind::ApiKey);
        assert_eq!(grok.default_env_var, Some("XAI_API_KEY"));
        assert_eq!(
            grok.env_var_candidates,
            &["XAI_API_KEY", "GROK_API_KEY", "XAI_TOKEN", "GROK_TOKEN"]
        );
        assert_eq!(grok.default_wire_api, WireApi::Responses);

        let oauth = template_by_id("grok-oauth").expect("grok-oauth template");
        assert_eq!(oauth.url, "https://api.x.ai/v1");
        assert_eq!(oauth.auth, AuthKind::OAuth);
        assert!(oauth.default_headers.is_empty());
        assert!(oauth.env_var_candidates.is_empty());
        assert_eq!(oauth.default_wire_api, WireApi::Responses);
    }

    #[test]
    fn default_headers_materialize() {
        let t = template_by_id("opencode-zen").unwrap();
        let h = default_headers_for_with_env(t, |_| false);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].name, "Authorization");
        assert_eq!(h[0].value, "Bearer $OPENCODE_ZEN_TOKEN");
    }

    #[test]
    fn default_headers_prefer_first_nonempty_provider_candidate() {
        let t = template_by_id("minimax").unwrap();
        let h = default_headers_for_with_env(t, |name| name == "MINIMAX_TOKEN");

        assert_eq!(h[0].name, "Authorization");
        assert_eq!(h[0].value, "Bearer $MINIMAX_TOKEN");
    }

    #[test]
    fn grok_default_headers_autodetect_api_key_candidates() {
        let t = template_by_id("grok").unwrap();
        let h = default_headers_for_with_env(t, |name| name == "GROK_API_KEY");

        assert_eq!(h[0].name, "Authorization");
        assert_eq!(h[0].value, "Bearer $GROK_API_KEY");
    }

    #[test]
    fn openai_default_headers_autodetect_api_key_candidates() {
        let t = template_by_id("openai").unwrap();

        let default = default_headers_for_with_env(t, |name| name == "OPENAI_API_KEY");
        assert_eq!(default[0].value, "Bearer $OPENAI_API_KEY");

        let token = default_headers_for_with_env(t, |name| name == "OPENAI_TOKEN");
        assert_eq!(token[0].value, "Bearer $OPENAI_TOKEN");

        let priority = default_headers_for_with_env(t, |name| {
            matches!(name, "OPENAI_API_KEY" | "OPENAI_TOKEN")
        });
        assert_eq!(priority[0].value, "Bearer $OPENAI_API_KEY");
    }

    #[test]
    fn default_headers_use_deterministic_candidate_priority() {
        let t = template_by_id("minimax").unwrap();
        let h = default_headers_for_with_env(t, |name| {
            matches!(name, "MINIMAX_API_KEY" | "MINIMAX_TOKEN")
        });

        assert_eq!(h[0].value, "Bearer $MINIMAX_API_KEY");
    }

    #[test]
    fn default_headers_fall_back_to_template_default_when_no_candidate_set() {
        let t = template_by_id("minimax").unwrap();
        let h = default_headers_for_with_env(t, |_| false);

        assert_eq!(h[0].value, "Bearer $MINIMAX_API_KEY");
    }

    #[test]
    fn default_headers_preserve_anthropic_header_shape_with_detected_var() {
        let t = template_by_id("anthropic").unwrap();
        let h = default_headers_for_with_env(t, |name| name == "ANTHROPIC_TOKEN");

        assert_eq!(h[0].name, "x-api-key");
        assert_eq!(h[0].value, "$ANTHROPIC_TOKEN");
        assert_eq!(h[1].name, "anthropic-version");
        assert_eq!(h[1].value, "2023-06-01");
    }

    #[test]
    fn openai_compatible_keeps_generic_header_without_guessing_env() {
        let t = template_by_id("openai-compatible").unwrap();
        let h = default_headers_for_with_env(t, |name| name == "OPENAI_API_KEY");

        assert_eq!(h[0].value, "Bearer $API_KEY");
    }

    #[test]
    fn default_headers_never_materialize_literal_env_values() {
        let t = template_by_id("minimax").unwrap();
        let h = default_headers_for_with_env(t, |name| name == "MINIMAX_TOKEN");

        assert!(h[0].value.contains("$MINIMAX_TOKEN"));
        assert!(!h[0].value.contains("secret-token-value"));
    }
}
