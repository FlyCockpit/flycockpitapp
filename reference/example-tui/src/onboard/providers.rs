//! Built-in provider catalog for the first-run form.
//!
//! Ids, display names, and hints follow `cockpit_core::providers::TEMPLATES`
//! so this picker stays a fair sketch of what Cockpit can add. Order puts
//! the subscription logins first — the same onboarding preference the
//! product wizard uses.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    ApiKey,
    OAuth,
}

impl Kind {
    pub(super) fn label(self) -> &'static str {
        match self {
            Kind::ApiKey => "API key",
            Kind::OAuth => "OAuth",
        }
    }
}

/// How the provider's credential is presented on the wire, so the verify step
/// knows which auth header to send when it probes `/models`. Mirrors the
/// header shapes `cockpit_core::providers` materializes for each template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AuthStyle {
    /// `Authorization: Bearer <key>` — the OpenAI-compatible default.
    Bearer,
    /// `x-api-key: <key>` plus a pinned `anthropic-version` header.
    Anthropic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Provider {
    pub id: &'static str,
    pub display: &'static str,
    pub kind: Kind,
    pub hint: &'static str,
    /// API root the verify step hits as `{base_url}/models`. Empty for
    /// `openai-compatible`, where the user supplies it during auth.
    pub base_url: &'static str,
    /// Environment variable Cockpit reads a key from by default, if any. The
    /// API-key screen offers to use it when it is set in the environment.
    pub env_var: Option<&'static str>,
    /// Wire auth header shape used when probing `/models`.
    pub auth_style: AuthStyle,
    /// Whether the provider publishes a `/models` endpoint. When false the
    /// verify step skips the probe instead of showing a spurious 404.
    pub supports_models: bool,
    /// Human-facing OAuth URL shown during the login step (device-code page
    /// for Codex, authorize page for Grok). Empty for API-key providers.
    pub oauth_url: &'static str,
}

impl Provider {
    /// Base URL to probe, or `None` when it must still be supplied (the
    /// `openai-compatible` case).
    pub(super) fn known_base_url(self) -> Option<&'static str> {
        (!self.base_url.is_empty()).then_some(self.base_url)
    }
}

impl Provider {
    pub(super) fn matches(self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let q = query.to_lowercase();
        self.id.to_lowercase().contains(&q)
            || self.display.to_lowercase().contains(&q)
            || self.kind.label().to_lowercase().contains(&q)
            || self.hint.to_lowercase().contains(&q)
    }
}

/// Onboarding order: subscription logins, then the rest of the wizard catalog.
pub(super) const PROVIDERS: &[Provider] = &[
    Provider {
        id: "codex-oauth",
        display: "Codex (ChatGPT Plus/Pro)",
        kind: Kind::OAuth,
        hint: "Subscription login via device code at auth.openai.com/codex/device; no OPENAI_API_KEY. Uses ChatGPT Plus/Pro quota.",
        base_url: "https://chatgpt.com/backend-api/codex",
        env_var: None,
        auth_style: AuthStyle::Bearer,
        supports_models: true,
        oauth_url: "https://auth.openai.com/codex/device",
    },
    Provider {
        id: "grok-oauth",
        display: "Grok (SuperGrok)",
        kind: Kind::OAuth,
        hint: "Standalone SuperGrok browser login at accounts.x.ai; no XAI_API_KEY required. X Premium+ does not include xAI API access.",
        base_url: "https://api.x.ai/v1",
        env_var: None,
        auth_style: AuthStyle::Bearer,
        supports_models: true,
        oauth_url: "https://accounts.x.ai",
    },
    Provider {
        id: "copilot",
        display: "GitHub Copilot",
        kind: Kind::ApiKey,
        hint: "Auth uses GitHub's documented tokens. Set COPILOT_GITHUB_TOKEN, GH_TOKEN, or GITHUB_TOKEN to a GitHub OAuth/App/fine-grained token with Copilot access.",
        base_url: "https://api.githubcopilot.com",
        env_var: Some("COPILOT_GITHUB_TOKEN"),
        auth_style: AuthStyle::Bearer,
        supports_models: true,
        oauth_url: "",
    },
    Provider {
        id: "openai-compatible",
        display: "OpenAI-compatible",
        kind: Kind::ApiKey,
        hint: "Generic OpenAI-compatible endpoint. You can add as many of these as you want; each one needs a unique id.",
        base_url: "",
        env_var: None,
        auth_style: AuthStyle::Bearer,
        supports_models: true,
        oauth_url: "",
    },
    Provider {
        id: "openai",
        display: "OpenAI Platform API",
        kind: Kind::ApiKey,
        hint: "Generate a key at https://platform.openai.com/api-keys. GPT-5-family models use the Responses API.",
        base_url: "https://api.openai.com/v1",
        env_var: Some("OPENAI_API_KEY"),
        auth_style: AuthStyle::Bearer,
        supports_models: true,
        oauth_url: "",
    },
    Provider {
        id: "grok",
        display: "Grok (xAI API)",
        kind: Kind::ApiKey,
        hint: "Generate a key at https://console.x.ai/team/default/api-keys. Uses the Responses API.",
        base_url: "https://api.x.ai/v1",
        env_var: Some("XAI_API_KEY"),
        auth_style: AuthStyle::Bearer,
        supports_models: true,
        oauth_url: "",
    },
    Provider {
        id: "crofai",
        display: "CrofAI",
        kind: Kind::ApiKey,
        hint: "OpenAI Chat Completions and Responses on /v1 with reasoning_effort. Generate a key at https://crof.ai/settings.",
        base_url: "https://ai.nahcrof.com/v2",
        env_var: Some("CROFAI_API_KEY"),
        auth_style: AuthStyle::Bearer,
        supports_models: true,
        oauth_url: "",
    },
    Provider {
        id: "z-ai",
        display: "z.ai (GLM)",
        kind: Kind::ApiKey,
        hint: "Generate a key at https://z.ai/manage-apikey/apikey-list",
        base_url: "https://api.z.ai/api/paas/v4",
        env_var: Some("Z_AI_API_KEY"),
        auth_style: AuthStyle::Bearer,
        supports_models: false,
        oauth_url: "",
    },
    Provider {
        id: "nous-research",
        display: "Nous Research",
        kind: Kind::ApiKey,
        hint: "Generate a key at https://portal.nousresearch.com/api-docs. Chat Completions only; no published /models endpoint.",
        base_url: "https://inference-api.nousresearch.com/v1",
        env_var: Some("NOUS_API_KEY"),
        auth_style: AuthStyle::Bearer,
        supports_models: false,
        oauth_url: "",
    },
    Provider {
        id: "baseten",
        display: "Baseten Model APIs",
        kind: Kind::ApiKey,
        hint: "Generate an API key at https://app.baseten.co/settings/api_keys.",
        base_url: "https://inference.baseten.co/v1",
        env_var: Some("BASETEN_API_KEY"),
        auth_style: AuthStyle::Bearer,
        supports_models: true,
        oauth_url: "",
    },
    Provider {
        id: "minimax",
        display: "MiniMax",
        kind: Kind::ApiKey,
        hint: "Generate a key at https://platform.minimaxi.com/",
        base_url: "https://api.minimaxi.com/v1",
        env_var: Some("MINIMAX_API_KEY"),
        auth_style: AuthStyle::Bearer,
        supports_models: true,
        oauth_url: "",
    },
    Provider {
        id: "opencode-zen",
        display: "OpenCode Zen",
        kind: Kind::ApiKey,
        hint: "Generate a token at https://opencode.ai/zen",
        base_url: "https://opencode.ai/zen/v1",
        env_var: Some("OPENCODE_API_KEY"),
        auth_style: AuthStyle::Bearer,
        supports_models: true,
        oauth_url: "",
    },
    Provider {
        id: "openrouter",
        display: "OpenRouter",
        kind: Kind::ApiKey,
        hint: "Generate a key at https://openrouter.ai/keys. The /models list is public, so verification works even before you paste a key.",
        base_url: "https://openrouter.ai/api/v1",
        env_var: Some("OPENROUTER_API_KEY"),
        auth_style: AuthStyle::Bearer,
        supports_models: true,
        oauth_url: "",
    },
    Provider {
        id: "deepseek",
        display: "DeepSeek",
        kind: Kind::ApiKey,
        hint: "Generate a key at https://platform.deepseek.com/api_keys",
        base_url: "https://api.deepseek.com/v1",
        env_var: Some("DEEPSEEK_API_KEY"),
        auth_style: AuthStyle::Bearer,
        supports_models: true,
        oauth_url: "",
    },
    Provider {
        id: "anthropic",
        display: "Anthropic (Claude API)",
        kind: Kind::ApiKey,
        hint: "Generate an API key at https://console.anthropic.com/settings/keys. Browser subscription login is not available for this provider.",
        base_url: "https://api.anthropic.com/v1",
        env_var: Some("ANTHROPIC_API_KEY"),
        auth_style: AuthStyle::Anthropic,
        supports_models: true,
        oauth_url: "",
    },
    Provider {
        id: "xiaomi-mimo",
        display: "Xiaomi MiMo",
        kind: Kind::ApiKey,
        hint: "Xiaomi MiMo open platform. Generate a key at https://api.xiaomimimo.com/. Flagship is MiMo-V2.5-Pro.",
        base_url: "https://api.xiaomimimo.com/v1",
        env_var: Some("MIMO_API_KEY"),
        auth_style: AuthStyle::Bearer,
        supports_models: true,
        oauth_url: "",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_covers_the_cockpit_wizard_ids() {
        let ids: Vec<_> = PROVIDERS.iter().map(|p| p.id).collect();
        for id in [
            "openai-compatible",
            "openai",
            "codex-oauth",
            "grok",
            "grok-oauth",
            "crofai",
            "z-ai",
            "nous-research",
            "baseten",
            "minimax",
            "opencode-zen",
            "copilot",
            "openrouter",
            "deepseek",
            "anthropic",
            "xiaomi-mimo",
        ] {
            assert!(ids.contains(&id), "missing provider {id}");
        }
        assert_eq!(ids.len(), 16);
    }

    #[test]
    fn subscription_logins_lead_the_list() {
        assert_eq!(PROVIDERS[0].id, "codex-oauth");
        assert_eq!(PROVIDERS[1].id, "grok-oauth");
        assert_eq!(PROVIDERS[2].id, "copilot");
    }

    #[test]
    fn filter_matches_id_display_kind_and_hint() {
        let grok: Vec<_> = PROVIDERS
            .iter()
            .copied()
            .filter(|p| p.matches("grok"))
            .map(|p| p.id)
            .collect();
        assert_eq!(grok, ["grok-oauth", "grok"]);
        assert!(
            PROVIDERS
                .iter()
                .any(|p| p.matches("OAuth") && p.id == "codex-oauth")
        );
        assert!(
            PROVIDERS
                .iter()
                .any(|p| p.matches("openrouter.ai") && p.id == "openrouter")
        );
        assert!(
            Provider {
                id: "x",
                display: "Y",
                kind: Kind::ApiKey,
                hint: "z",
                base_url: "https://example.test/v1",
                env_var: None,
                auth_style: AuthStyle::Bearer,
                supports_models: true,
                oauth_url: "",
            }
            .matches("")
        );
    }

    #[test]
    fn oauth_providers_carry_a_login_url_and_others_do_not() {
        for provider in PROVIDERS {
            match provider.kind {
                Kind::OAuth => assert!(
                    !provider.oauth_url.is_empty(),
                    "{} is OAuth but has no login URL",
                    provider.id
                ),
                Kind::ApiKey => assert!(
                    provider.oauth_url.is_empty(),
                    "{} is an API-key provider but carries an OAuth URL",
                    provider.id
                ),
            }
        }
    }

    #[test]
    fn only_openai_compatible_defers_its_base_url() {
        for provider in PROVIDERS {
            if provider.id == "openai-compatible" {
                assert!(provider.known_base_url().is_none());
            } else {
                assert!(
                    provider.known_base_url().is_some(),
                    "{} should ship a base URL",
                    provider.id
                );
            }
        }
    }

    #[test]
    fn providers_without_a_models_endpoint_are_flagged() {
        let no_models: Vec<_> = PROVIDERS
            .iter()
            .filter(|p| !p.supports_models)
            .map(|p| p.id)
            .collect();
        assert_eq!(no_models, ["z-ai", "nous-research"]);
    }
}
