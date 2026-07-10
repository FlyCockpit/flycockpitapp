use std::sync::Arc;

use anyhow::{Result, anyhow};
use reqwest::Url;

use crate::config::providers::{AuthKind, ModelEntry, ProviderEntry, ProviderModelCatalog};
use crate::providers::models_fetch::{self, ResolvedRequest};
use crate::providers::usage::probes::{
    CodexOAuthUsageProbe, GrokOAuthUsageProbe, ProviderUsageProbe,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderCredentialKind {
    CodexOAuth,
    XaiOAuth,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderRequestKind {
    Template,
    Copilot,
}

pub(crate) enum OAuthCredential {
    Bearer(String),
    Codex(crate::auth::codex_oauth::StoredTokens),
}

impl OAuthCredential {
    pub(crate) fn access_token(&self) -> &str {
        match self {
            OAuthCredential::Bearer(token) => token,
            OAuthCredential::Codex(tokens) => &tokens.access_token,
        }
    }
}

/// Provider-specific behavior for request resolution, model listing, and optional usage.
///
/// Adding a new OAuth/special provider is intentionally limited to one implementation of
/// this trait plus one registration in [`ProviderRegistry::standard`]. Plain
/// OpenAI-compatible API-key providers remain template data only and are served by the
/// registry's fallback [`TemplateProvider`].
pub(crate) trait Provider: Send + Sync {
    fn id(&self) -> &'static str;

    fn matches(&self, provider_id: &str, entry: &ProviderEntry) -> bool;

    fn request_kind(&self) -> ProviderRequestKind {
        ProviderRequestKind::Template
    }

    fn credential_kind(&self) -> Option<ProviderCredentialKind> {
        None
    }

    fn sync_auth_error(&self) -> Option<&'static str> {
        None
    }

    fn request(
        &self,
        provider_id: &str,
        entry: &ProviderEntry,
        oauth_credential: Option<OAuthCredential>,
        lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Result<ResolvedRequest> {
        models_fetch::resolve_provider_request_inner(
            provider_id,
            entry,
            oauth_credential,
            self.request_kind(),
            lookup,
        )
    }

    fn model_list_request(
        &self,
        _provider_id: &str,
        _entry: &ProviderEntry,
        resolved: &ResolvedRequest,
        _oauth_credential: Option<OAuthCredential>,
        _lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Result<ResolvedRequest> {
        Ok(resolved.clone())
    }

    fn models_url(&self, _entry: &ProviderEntry, base_url: &str) -> String {
        format!("{}/models", base_url.trim_end_matches('/'))
    }

    fn fallback_models(&self) -> Vec<ModelEntry> {
        Vec::new()
    }

    fn fallback_catalog(&self) -> ProviderModelCatalog {
        ProviderModelCatalog::Live
    }

    fn usage_probe(&self) -> Option<&dyn ProviderUsageProbe> {
        None
    }
}

pub(crate) struct TemplateProvider;

impl Provider for TemplateProvider {
    fn id(&self) -> &'static str {
        "template"
    }

    fn matches(&self, _provider_id: &str, _entry: &ProviderEntry) -> bool {
        true
    }
}

pub(crate) struct CodexProvider {
    usage: CodexOAuthUsageProbe,
}

impl Default for CodexProvider {
    fn default() -> Self {
        Self {
            usage: CodexOAuthUsageProbe,
        }
    }
}

impl Provider for CodexProvider {
    fn id(&self) -> &'static str {
        crate::auth::codex_oauth::CREDENTIAL_KEY
    }

    fn matches(&self, provider_id: &str, entry: &ProviderEntry) -> bool {
        provider_id.eq_ignore_ascii_case(crate::auth::codex_oauth::CREDENTIAL_KEY)
            || entry.credential_ref.as_deref() == Some(crate::auth::codex_oauth::CREDENTIAL_KEY)
            || (matches!(entry.auth, Some(AuthKind::OAuth))
                && entry
                    .url
                    .trim_end_matches('/')
                    .eq_ignore_ascii_case(crate::auth::codex_oauth::DEFAULT_BASE_URL))
    }

    fn credential_kind(&self) -> Option<ProviderCredentialKind> {
        Some(ProviderCredentialKind::CodexOAuth)
    }

    fn sync_auth_error(&self) -> Option<&'static str> {
        Some("Codex subscription auth required — set up OAuth in /settings → Providers.")
    }

    fn model_list_request(
        &self,
        provider_id: &str,
        entry: &ProviderEntry,
        _resolved: &ResolvedRequest,
        oauth_credential: Option<OAuthCredential>,
        lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Result<ResolvedRequest> {
        let Some(OAuthCredential::Codex(tokens)) = oauth_credential else {
            return Err(anyhow!(
                "Codex subscription auth required — set up OAuth in /settings → Providers."
            ));
        };
        models_fetch::resolve_codex_model_list_request(provider_id, entry, tokens, lookup)
    }

    fn models_url(&self, _entry: &ProviderEntry, base_url: &str) -> String {
        let base = base_url.trim_end_matches('/');
        let mut url = Url::parse(&format!("{base}/models"))
            .expect("resolved provider base URL must parse as URL");
        url.query_pairs_mut().append_pair(
            "client_version",
            models_fetch::codex_model_list_client_version(),
        );
        url.to_string()
    }

    fn fallback_models(&self) -> Vec<ModelEntry> {
        ["gpt-5.5", "gpt-5.4", "gpt-5.4-mini"]
            .into_iter()
            .map(|id| ModelEntry {
                id: id.to_string(),
                ..ModelEntry::default()
            })
            .collect()
    }

    fn fallback_catalog(&self) -> ProviderModelCatalog {
        ProviderModelCatalog::CodexFallback
    }

    fn usage_probe(&self) -> Option<&dyn ProviderUsageProbe> {
        Some(&self.usage)
    }
}

pub(crate) struct GrokProvider {
    usage: GrokOAuthUsageProbe,
}

impl Default for GrokProvider {
    fn default() -> Self {
        Self {
            usage: GrokOAuthUsageProbe,
        }
    }
}

impl Provider for GrokProvider {
    fn id(&self) -> &'static str {
        crate::auth::xai_oauth::CREDENTIAL_KEY
    }

    fn matches(&self, provider_id: &str, entry: &ProviderEntry) -> bool {
        provider_id.eq_ignore_ascii_case(crate::auth::xai_oauth::CREDENTIAL_KEY)
            || entry.credential_ref.as_deref() == Some(crate::auth::xai_oauth::CREDENTIAL_KEY)
            || (matches!(entry.auth, Some(AuthKind::OAuth)) && entry.url.contains("api.x.ai"))
    }

    fn credential_kind(&self) -> Option<ProviderCredentialKind> {
        Some(ProviderCredentialKind::XaiOAuth)
    }

    fn sync_auth_error(&self) -> Option<&'static str> {
        Some("Grok subscription auth required — set up OAuth in /settings → Providers.")
    }

    fn usage_probe(&self) -> Option<&dyn ProviderUsageProbe> {
        Some(&self.usage)
    }
}

pub(crate) struct CopilotProvider;

impl Provider for CopilotProvider {
    fn id(&self) -> &'static str {
        "copilot"
    }

    fn matches(&self, provider_id: &str, entry: &ProviderEntry) -> bool {
        provider_id.eq_ignore_ascii_case("copilot")
            || entry.credential_ref.as_deref() == Some("copilot")
            || entry.url.contains("githubcopilot.com")
    }

    fn request_kind(&self) -> ProviderRequestKind {
        ProviderRequestKind::Copilot
    }
}

#[derive(Clone)]
pub(crate) struct ProviderRegistry {
    special: Arc<Vec<Arc<dyn Provider>>>,
    template: Arc<TemplateProvider>,
}

impl ProviderRegistry {
    pub(crate) fn new(special: Vec<Arc<dyn Provider>>) -> Self {
        Self {
            special: Arc::new(special),
            template: Arc::new(TemplateProvider),
        }
    }

    pub(crate) fn standard() -> Self {
        Self::new(vec![
            Arc::new(CodexProvider::default()),
            Arc::new(GrokProvider::default()),
            Arc::new(CopilotProvider),
        ])
    }

    pub(crate) fn provider_for(&self, provider_id: &str, entry: &ProviderEntry) -> &dyn Provider {
        let mut matches = self
            .special
            .iter()
            .filter(|provider| provider.matches(provider_id, entry));
        let first = matches.next();
        debug_assert!(
            matches.next().is_none(),
            "multiple special providers matched `{provider_id}`"
        );
        first
            .map(|provider| provider.as_ref())
            .unwrap_or(self.template.as_ref())
    }

    pub(crate) fn special_match_ids(
        &self,
        provider_id: &str,
        entry: &ProviderEntry,
    ) -> Vec<&'static str> {
        self.special
            .iter()
            .filter(|provider| provider.matches(provider_id, entry))
            .map(|provider| provider.id())
            .collect()
    }
}
