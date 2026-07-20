use std::collections::HashSet;
use std::future::Future;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use reqwest::header::{self, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::config::extended::{WebConfig, WebProvider};
use crate::engine::tool::{
    TOOL_PRESENTATION_FULL_CHARS, TOOL_PRESENTATION_SUMMARY_CHARS, Tool, ToolCtx, ToolOutput,
    ToolPresentation, bounded_preview, invalid_input, readable_args, single_line_preview,
    string_field,
};
use crate::tools::common::{OUTPUT_BYTE_CAP, truncate_head_tail};
use crate::tools::custom::{CustomBashTool, ToolTemplateProvenance, WEBFETCH, WEBSEARCH};

const FIRECRAWL_API_KEY_ENV: &str = "FIRECRAWL_API_KEY";
const FIRECRAWL_API_URL_ENV: &str = "FIRECRAWL_API_URL";
const TINYFISH_API_KEY_ENV: &str = "TINYFISH_API_KEY";
const FIRECRAWL_PROVIDER_ID: &str = "firecrawl";
const TINYFISH_PROVIDER_ID: &str = "tinyfish";
const DEFAULT_FIRECRAWL_API_URL: &str = "https://api.firecrawl.dev";
const TINYFISH_SEARCH_URL: &str = "https://api.search.tinyfish.ai";
const TINYFISH_FETCH_URL: &str = "https://api.fetch.tinyfish.ai";
const NATIVE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RATE_LIMIT_RETRY_AFTER: Duration = Duration::from_secs(10);
const DEFAULT_SEARCH_LIMIT: usize = 5;
const MAX_SEARCH_LIMIT: usize = 10;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FetchedPage {
    pub markdown: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebToolErrorKind {
    RateLimited { retry_after: Option<Duration> },
    QuotaExhausted,
    AuthFailed,
    General,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum WebProviderRuntime {
    Firecrawl,
    Tinyfish,
}

impl WebProviderRuntime {
    fn label(self) -> &'static str {
        match self {
            Self::Firecrawl => "Firecrawl",
            Self::Tinyfish => "TinyFish",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WebToolError {
    pub kind: WebToolErrorKind,
    pub provider: WebProviderRuntime,
    pub with_api_key: bool,
    message: String,
}

impl WebToolError {
    fn general(
        provider: WebProviderRuntime,
        with_api_key: bool,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind: WebToolErrorKind::General,
            provider,
            with_api_key,
            message: message.into(),
        }
    }

    fn to_tool_text(&self, tool: &str) -> String {
        let access = if self.with_api_key {
            "with a configured API key"
        } else {
            "without an API key"
        };
        let key_hint = match (self.provider, self.with_api_key) {
            (WebProviderRuntime::Firecrawl, false) => {
                "Set FIRECRAWL_API_KEY to raise limits for the built-in web tools."
            }
            (WebProviderRuntime::Firecrawl, true) => {
                "Check FIRECRAWL_API_KEY, the stored Firecrawl key, or the account quota."
            }
            (WebProviderRuntime::Tinyfish, false) => {
                "Set TINYFISH_API_KEY to use TinyFish directly."
            }
            (WebProviderRuntime::Tinyfish, true) => {
                "Check TINYFISH_API_KEY, the stored TinyFish key, or the account quota."
            }
        };
        let class = match self.kind {
            WebToolErrorKind::RateLimited { retry_after } => match retry_after {
                Some(delay) => format!("rate limited; retry after {}s", delay.as_secs()),
                None => "rate limited".to_string(),
            },
            WebToolErrorKind::QuotaExhausted => "quota exhausted".to_string(),
            WebToolErrorKind::AuthFailed => "authentication failed".to_string(),
            WebToolErrorKind::General => "request failed".to_string(),
        };
        let detail = if self.message.trim().is_empty() {
            String::new()
        } else {
            format!("\nDetail: {}", self.message.trim())
        };
        format!(
            "{tool} failed: {class} while using {} {access}. {key_hint}{detail}",
            self.provider.label()
        )
    }
}

struct ApiKey(String);

impl ApiKey {
    fn new(raw: String) -> Option<Self> {
        let trimmed = raw.trim();
        (!trimmed.is_empty()).then(|| Self(trimmed.to_string()))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl Clone for ApiKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey(REDACTED)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectedBackendKind {
    Firecrawl,
    Tinyfish,
    Custom,
}

#[derive(Clone)]
pub(crate) struct SelectedBackend {
    kind: SelectedBackendKind,
    api_key: Option<ApiKey>,
    firecrawl_base_url: Option<String>,
    fallback_from_tinyfish: bool,
}

impl SelectedBackend {
    #[cfg(test)]
    fn kind(&self) -> SelectedBackendKind {
        self.kind
    }

    pub(crate) fn has_api_key(&self) -> bool {
        self.api_key.is_some()
    }

    #[cfg(test)]
    fn api_key_for_test(&self) -> Option<&str> {
        self.api_key.as_ref().map(ApiKey::expose)
    }

    #[cfg(test)]
    fn fallback_from_tinyfish(&self) -> bool {
        self.fallback_from_tinyfish
    }
}

#[allow(dead_code)]
#[async_trait]
pub(crate) trait WebProviderClient: Send + Sync {
    async fn search(
        &self,
        query: &str,
        limit: usize,
        ctx: &ToolCtx,
    ) -> std::result::Result<Vec<SearchResult>, WebToolError>;
    async fn fetch(
        &self,
        url: &str,
        ctx: &ToolCtx,
    ) -> std::result::Result<FetchedPage, WebToolError>;
}

pub(crate) struct WebSearchTool;
pub(crate) struct WebFetchTool;

#[async_trait]
impl Tool for WebSearchTool {
    fn name(&self) -> &str {
        WEBSEARCH
    }

    fn description(&self) -> &str {
        "Search the web for current information."
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Search the web for current information; use webfetch separately for page content."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Search query." },
                "limit": { "type": "integer", "description": "Maximum results." }
            },
            "required": ["query"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Non-empty search query; do not put URLs here when you need page content." },
                "limit": { "type": "integer", "description": "Optional result count; values are clamped to 1 through 10." }
            },
            "required": ["query"]
        }))
    }

    fn presentation(&self, args: &Value) -> ToolPresentation {
        let query = string_field(args, "query").unwrap_or_else(|| readable_args(args).1);
        ToolPresentation::with_parts(
            None,
            self.name(),
            single_line_preview(&query, TOOL_PRESENTATION_SUMMARY_CHARS),
            bounded_preview(&query, TOOL_PRESENTATION_FULL_CHARS),
        )
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let query = required_non_empty_string(&args, "query")?;
        let limit = search_limit(args.get("limit"));
        let cfg = crate::config::extended::load_for_cwd(&ctx.cwd);
        let selected = select_backend(&cfg.web, ctx);
        let out = match selected.kind {
            SelectedBackendKind::Custom => {
                return Err(invalid_input(
                    "websearch native tool cannot run custom backend directly",
                ));
            }
            SelectedBackendKind::Firecrawl => search_firecrawl(&selected, query, limit, ctx).await,
            SelectedBackendKind::Tinyfish => {
                search_tinyfish_or_fallback(&selected, query, limit, ctx).await
            }
        };
        Ok(match out {
            Ok(results) => capped_text(render_search_results(&results)),
            Err(err) => {
                if maybe_capture_web_key(ctx, &err, WEBSEARCH).await? {
                    let cfg = crate::config::extended::load_for_cwd(&ctx.cwd);
                    let selected = select_backend(&cfg.web, ctx);
                    let retry = match selected.kind {
                        SelectedBackendKind::Firecrawl => {
                            search_firecrawl(&selected, query, limit, ctx).await
                        }
                        SelectedBackendKind::Tinyfish => {
                            search_tinyfish_or_fallback(&selected, query, limit, ctx).await
                        }
                        SelectedBackendKind::Custom => Err(err.clone()),
                    };
                    match retry {
                        Ok(results) => capped_text(render_search_results(&results)),
                        Err(retry_err) => ToolOutput::text(retry_err.to_tool_text(WEBSEARCH)),
                    }
                } else {
                    ToolOutput::text(err.to_tool_text(WEBSEARCH))
                }
            }
        })
    }
}

#[async_trait]
impl Tool for WebFetchTool {
    fn name(&self) -> &str {
        WEBFETCH
    }

    fn description(&self) -> &str {
        "Fetch a web page as markdown."
    }

    fn defensive_description(&self) -> Option<String> {
        Some("Fetch an http or https URL and return the page as markdown.".to_string())
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "url": { "type": "string", "description": "URL to fetch." }
            },
            "required": ["url"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "url": { "type": "string", "description": "HTTP or HTTPS URL whose markdown page content should be fetched." }
            },
            "required": ["url"]
        }))
    }

    fn presentation(&self, args: &Value) -> ToolPresentation {
        string_field(args, "url")
            .map(|url| ToolPresentation::with_parts(None, self.name(), url.clone(), url))
            .unwrap_or_else(|| {
                let (summary, full_input) = readable_args(args);
                ToolPresentation::with_parts(None, self.name(), summary, full_input)
            })
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let url = required_non_empty_string(&args, "url")?;
        validate_http_url(url)?;
        let cfg = crate::config::extended::load_for_cwd(&ctx.cwd);
        let selected = select_backend(&cfg.web, ctx);
        let out = match selected.kind {
            SelectedBackendKind::Custom => {
                return Err(invalid_input(
                    "webfetch native tool cannot run custom backend directly",
                ));
            }
            SelectedBackendKind::Firecrawl => fetch_firecrawl(&selected, url, ctx).await,
            SelectedBackendKind::Tinyfish => fetch_tinyfish_or_fallback(&selected, url, ctx).await,
        };
        Ok(match out {
            Ok(page) => capped_text(page.markdown),
            Err(err) => {
                if maybe_capture_web_key(ctx, &err, WEBFETCH).await? {
                    let cfg = crate::config::extended::load_for_cwd(&ctx.cwd);
                    let selected = select_backend(&cfg.web, ctx);
                    let retry = match selected.kind {
                        SelectedBackendKind::Firecrawl => {
                            fetch_firecrawl(&selected, url, ctx).await
                        }
                        SelectedBackendKind::Tinyfish => {
                            fetch_tinyfish_or_fallback(&selected, url, ctx).await
                        }
                        SelectedBackendKind::Custom => Err(err.clone()),
                    };
                    match retry {
                        Ok(page) => capped_text(page.markdown),
                        Err(retry_err) => ToolOutput::text(retry_err.to_tool_text(WEBFETCH)),
                    }
                } else {
                    ToolOutput::text(err.to_tool_text(WEBFETCH))
                }
            }
        })
    }
}

pub(crate) fn materialize_web_tool(
    name: &str,
    cwd: &std::path::Path,
) -> Result<std::sync::Arc<dyn Tool>> {
    let cfg = crate::config::extended::load_for_cwd(cwd);
    if cfg.web.provider == WebProvider::Custom {
        let command = match name {
            WEBFETCH => cfg.web.custom.fetch_command.as_deref(),
            WEBSEARCH => cfg.web.custom.search_command.as_deref(),
            other => return Err(anyhow::anyhow!("unknown web tool `{other}`")),
        }
        .map(str::trim)
        .filter(|command| !command.is_empty())
        .ok_or_else(|| anyhow::anyhow!("custom web tool `{name}` has no configured command"))?;
        let tpl = crate::config::extended::ToolCommandTemplate {
            enabled: true,
            command: command.to_string(),
            description: None,
        };
        return Ok(std::sync::Arc::new(
            CustomBashTool::from_template_with_provenance(
                name,
                &tpl,
                ToolTemplateProvenance::Configured {
                    source: format!(
                        "web.custom command in effective config for {}",
                        cwd.display()
                    ),
                },
            ),
        ));
    }
    match name {
        WEBSEARCH => Ok(std::sync::Arc::new(WebSearchTool)),
        WEBFETCH => Ok(std::sync::Arc::new(WebFetchTool)),
        other => Err(anyhow::anyhow!("unknown web tool `{other}`")),
    }
}

pub(crate) fn is_custom_web_provider(cwd: &std::path::Path) -> bool {
    crate::config::extended::load_for_cwd(cwd).web.provider == WebProvider::Custom
}

pub(crate) fn web_tool_requires_gate(name: &str, cwd: &std::path::Path) -> bool {
    match name {
        WEBFETCH => true,
        WEBSEARCH => is_custom_web_provider(cwd),
        _ => false,
    }
}

fn required_non_empty_string<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    let value = args
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid_input(format!("`{key}` is required and non-empty")))?;
    Ok(value)
}

fn validate_http_url(raw: &str) -> Result<()> {
    let parsed =
        reqwest::Url::parse(raw).map_err(|_| invalid_input("`url` must be a valid URL"))?;
    match parsed.scheme() {
        "http" | "https" => Ok(()),
        _ => Err(invalid_input("`url` must use http or https")),
    }
}

pub(crate) fn search_limit(value: Option<&Value>) -> usize {
    value
        .and_then(Value::as_i64)
        .unwrap_or(DEFAULT_SEARCH_LIMIT as i64)
        .clamp(1, MAX_SEARCH_LIMIT as i64) as usize
}

pub(crate) fn render_search_results(results: &[SearchResult]) -> String {
    if results.is_empty() {
        return "No results found.".to_string();
    }
    let mut out = String::new();
    for (idx, result) in results.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(&format!(
            "{}. {}\n{}\n{}\n",
            idx + 1,
            result.title.trim(),
            result.url.trim(),
            result.snippet.trim()
        ));
    }
    out
}

fn capped_text(text: String) -> ToolOutput {
    if text.len() > OUTPUT_BYTE_CAP {
        ToolOutput::truncated_text(truncate_head_tail(&text, OUTPUT_BYTE_CAP))
    } else {
        ToolOutput::text(text)
    }
}

fn select_backend(web: &WebConfig, ctx: &ToolCtx) -> SelectedBackend {
    select_backend_with(web, |name| lookup_env(ctx, name), credential_api_key)
}

pub(crate) fn select_backend_with<E, S>(web: &WebConfig, env: E, store: S) -> SelectedBackend
where
    E: Fn(&str) -> Option<String>,
    S: Fn(&str) -> Option<String>,
{
    match web.provider {
        WebProvider::Firecrawl => SelectedBackend {
            kind: SelectedBackendKind::Firecrawl,
            api_key: resolve_key_with(FIRECRAWL_API_KEY_ENV, FIRECRAWL_PROVIDER_ID, &env, &store),
            firecrawl_base_url: resolve_firecrawl_base_url_with(web, &env),
            fallback_from_tinyfish: false,
        },
        WebProvider::Tinyfish => {
            let tiny_key =
                resolve_key_with(TINYFISH_API_KEY_ENV, TINYFISH_PROVIDER_ID, &env, &store);
            if tiny_key.is_some() {
                SelectedBackend {
                    kind: SelectedBackendKind::Tinyfish,
                    api_key: tiny_key,
                    firecrawl_base_url: None,
                    fallback_from_tinyfish: false,
                }
            } else {
                SelectedBackend {
                    kind: SelectedBackendKind::Firecrawl,
                    api_key: resolve_key_with(
                        FIRECRAWL_API_KEY_ENV,
                        FIRECRAWL_PROVIDER_ID,
                        &env,
                        &store,
                    ),
                    firecrawl_base_url: resolve_firecrawl_base_url_with(web, &env),
                    fallback_from_tinyfish: true,
                }
            }
        }
        WebProvider::Custom => SelectedBackend {
            kind: SelectedBackendKind::Custom,
            api_key: None,
            firecrawl_base_url: None,
            fallback_from_tinyfish: false,
        },
    }
}

fn resolve_key_with<E, S>(env_name: &str, provider_id: &str, env: &E, store: &S) -> Option<ApiKey>
where
    E: Fn(&str) -> Option<String>,
    S: Fn(&str) -> Option<String>,
{
    env(env_name)
        .and_then(ApiKey::new)
        .or_else(|| store(provider_id).and_then(ApiKey::new))
}

pub(crate) fn resolve_firecrawl_base_url_with<E>(web: &WebConfig, env: &E) -> Option<String>
where
    E: Fn(&str) -> Option<String>,
{
    env(FIRECRAWL_API_URL_ENV)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            web.firecrawl_base_url
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
}

fn lookup_env(ctx: &ToolCtx, name: &str) -> Option<String> {
    if let Ok(overlay) = ctx.env_overlay.read()
        && let Some(value) = overlay.get(name)
        && !value.trim().is_empty()
    {
        return Some(value.clone());
    }
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn credential_api_key(provider_id: &str) -> Option<String> {
    crate::credentials::CredentialStore::open_default()
        .ok()
        .and_then(|store| store.api_key(provider_id))
}

fn web_key_suppression_set() -> &'static Mutex<HashSet<(Uuid, WebProviderRuntime)>> {
    static SUPPRESSED: OnceLock<Mutex<HashSet<(Uuid, WebProviderRuntime)>>> = OnceLock::new();
    SUPPRESSED.get_or_init(|| Mutex::new(HashSet::new()))
}

fn provider_id(provider: WebProviderRuntime) -> &'static str {
    match provider {
        WebProviderRuntime::Firecrawl => FIRECRAWL_PROVIDER_ID,
        WebProviderRuntime::Tinyfish => TINYFISH_PROVIDER_ID,
    }
}

fn provider_key_env(provider: WebProviderRuntime) -> &'static str {
    match provider {
        WebProviderRuntime::Firecrawl => FIRECRAWL_API_KEY_ENV,
        WebProviderRuntime::Tinyfish => TINYFISH_API_KEY_ENV,
    }
}

fn provider_url(provider: WebProviderRuntime) -> &'static str {
    match provider {
        WebProviderRuntime::Firecrawl => "https://www.firecrawl.dev",
        WebProviderRuntime::Tinyfish => "https://agent.tinyfish.ai",
    }
}

fn provider_key_resolvable(ctx: &ToolCtx, provider: WebProviderRuntime) -> bool {
    lookup_env(ctx, provider_key_env(provider))
        .and_then(ApiKey::new)
        .is_some()
        || credential_api_key(provider_id(provider))
            .and_then(ApiKey::new)
            .is_some()
}

fn web_error_qualifies_for_key_prompt(err: &WebToolError) -> bool {
    match err.kind {
        WebToolErrorKind::RateLimited { .. } | WebToolErrorKind::QuotaExhausted => {
            !err.with_api_key
        }
        WebToolErrorKind::AuthFailed => true,
        WebToolErrorKind::General => false,
    }
}

fn web_key_prompt_should_raise(ctx: &ToolCtx, err: &WebToolError) -> bool {
    if !web_error_qualifies_for_key_prompt(err) || !ctx.interrupts.is_interactive_attached() {
        return false;
    }
    let mut guard = match web_key_suppression_set().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let key = (ctx.session.id, err.provider);
    if guard.contains(&key) {
        if provider_key_resolvable(ctx, err.provider) {
            guard.remove(&key);
        } else {
            return false;
        }
    }
    true
}

fn suppress_web_key_prompt(ctx: &ToolCtx, provider: WebProviderRuntime) {
    let mut guard = match web_key_suppression_set().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.insert((ctx.session.id, provider));
}

async fn maybe_capture_web_key(ctx: &ToolCtx, err: &WebToolError, tool: &str) -> Result<bool> {
    if !web_key_prompt_should_raise(ctx, err) {
        return Ok(false);
    }
    let env_name = provider_key_env(err.provider);
    let url = provider_url(err.provider);
    let failure = match err.kind {
        WebToolErrorKind::RateLimited { .. } | WebToolErrorKind::QuotaExhausted => {
            format!(
                "{} free-tier limit reached while running {tool}.",
                err.provider.label()
            )
        }
        WebToolErrorKind::AuthFailed => {
            format!(
                "{} rejected the configured API key while running {tool}.",
                err.provider.label()
            )
        }
        WebToolErrorKind::General => return Ok(false),
    };
    let prompt = format!(
        "{failure}\nPaste a {} API key to save it and retry once. Set {env_name} for the durable env-var path; env vars override stored keys. Provider site: {url}",
        err.provider.label()
    );
    let set = crate::daemon::proto::InterruptQuestionSet {
        questions: vec![crate::daemon::proto::InterruptQuestion::Freetext {
            prompt,
            masked: true,
        }],
    };
    let response = crate::engine::interrupt::raise_and_wait(
        &ctx.session.db,
        &ctx.interrupts,
        ctx.session.id,
        &ctx.agent_id,
        "Web tool API key required",
        set,
        "web key prompt",
    )
    .await
    .into_response()?;
    if ctx.cancel.is_cancelled() {
        return Ok(false);
    }
    let Some(key) = crate::engine::interrupt::freetext_of(&response)
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
    else {
        suppress_web_key_prompt(ctx, err.provider);
        return Ok(false);
    };
    let saved = crate::credentials::CredentialStore::open_default()
        .and_then(|store| {
            store.save_record_merged(
                provider_id(err.provider),
                serde_json::json!({ "api_key": key }),
            )
        })
        .is_ok();
    if saved {
        Ok(true)
    } else {
        suppress_web_key_prompt(ctx, err.provider);
        Ok(false)
    }
}

async fn search_tinyfish_or_fallback(
    selected: &SelectedBackend,
    query: &str,
    limit: usize,
    ctx: &ToolCtx,
) -> std::result::Result<Vec<SearchResult>, WebToolError> {
    if selected.fallback_from_tinyfish {
        emit_tinyfish_fallback_warning(ctx);
        return search_firecrawl(selected, query, limit, ctx).await;
    }
    search_tinyfish(selected, query, limit, ctx).await
}

async fn fetch_tinyfish_or_fallback(
    selected: &SelectedBackend,
    url: &str,
    ctx: &ToolCtx,
) -> std::result::Result<FetchedPage, WebToolError> {
    if selected.fallback_from_tinyfish {
        emit_tinyfish_fallback_warning(ctx);
        return fetch_firecrawl(selected, url, ctx).await;
    }
    fetch_tinyfish(selected, url, ctx).await
}

pub(crate) fn emit_tinyfish_fallback_warning(ctx: &ToolCtx) -> bool {
    static WARNED: OnceLock<Mutex<HashSet<Uuid>>> = OnceLock::new();
    let warned = WARNED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = match warned.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if !guard.insert(ctx.session.id) {
        return false;
    }
    if let Some(events) = &ctx.events {
        let _ = events.try_send(crate::engine::agent::TurnEvent::Notice {
            text: "TinyFish web provider selected but TINYFISH_API_KEY is not configured; using Firecrawl keyless for this session.".to_string(),
        });
    }
    true
}

async fn search_firecrawl(
    selected: &SelectedBackend,
    query: &str,
    limit: usize,
    ctx: &ToolCtx,
) -> std::result::Result<Vec<SearchResult>, WebToolError> {
    let client = firecrawl_client(selected)?;
    let options = firecrawl::SearchOptions {
        limit: Some(limit as u32),
        sources: Some(vec![firecrawl::SearchSource::Web]),
        scrape_options: None,
        ..Default::default()
    };
    let response = firecrawl_with_retry(ctx, selected.has_api_key(), || {
        client.search(query, options.clone())
    })
    .await?;
    Ok(map_firecrawl_search(response)
        .into_iter()
        .take(limit)
        .collect())
}

async fn fetch_firecrawl(
    selected: &SelectedBackend,
    url: &str,
    ctx: &ToolCtx,
) -> std::result::Result<FetchedPage, WebToolError> {
    let client = firecrawl_client(selected)?;
    let options = firecrawl::ScrapeOptions {
        formats: Some(vec![firecrawl::Format::Markdown]),
        only_main_content: Some(true),
        timeout: Some(NATIVE_TIMEOUT.as_millis() as u32),
        ..Default::default()
    };
    let document = firecrawl_with_retry(ctx, selected.has_api_key(), || {
        client.scrape(url, options.clone())
    })
    .await?;
    let markdown = document.markdown.unwrap_or_default();
    if markdown.trim().is_empty() {
        return Err(WebToolError::general(
            WebProviderRuntime::Firecrawl,
            selected.has_api_key(),
            "provider returned no markdown content",
        ));
    }
    Ok(FetchedPage { markdown })
}

fn firecrawl_client(
    selected: &SelectedBackend,
) -> std::result::Result<firecrawl::Client, WebToolError> {
    let base = selected
        .firecrawl_base_url
        .as_deref()
        .unwrap_or(DEFAULT_FIRECRAWL_API_URL);
    firecrawl::Client::new_selfhosted(base, selected.api_key.as_ref().map(ApiKey::expose)).map_err(
        |e| {
            WebToolError::general(
                WebProviderRuntime::Firecrawl,
                selected.has_api_key(),
                e.to_string(),
            )
        },
    )
}

async fn firecrawl_with_retry<T, F, Fut>(
    ctx: &ToolCtx,
    with_api_key: bool,
    request: F,
) -> std::result::Result<T, WebToolError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = std::result::Result<T, firecrawl::FirecrawlError>>,
{
    let mut attempted_retry = false;
    loop {
        let result =
            timeout_or_cancel(ctx, WebProviderRuntime::Firecrawl, with_api_key, request()).await;
        match result {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(error)) => {
                let err = classify_firecrawl_error(error, with_api_key);
                if !attempted_retry
                    && let WebToolErrorKind::RateLimited {
                        retry_after: Some(delay),
                    } = err.kind
                    && delay <= MAX_RATE_LIMIT_RETRY_AFTER
                {
                    attempted_retry = true;
                    sleep_or_cancel(ctx, WebProviderRuntime::Firecrawl, with_api_key, delay)
                        .await?;
                    continue;
                }
                return Err(err);
            }
            Err(err) => return Err(err),
        }
    }
}

fn map_firecrawl_search(response: firecrawl::SearchResponse) -> Vec<SearchResult> {
    response
        .data
        .web
        .unwrap_or_default()
        .into_iter()
        .filter_map(|item| match item {
            firecrawl::SearchResultOrDocument::WebResult(result) => Some(SearchResult {
                title: result.title.unwrap_or_else(|| result.url.clone()),
                url: result.url,
                snippet: result.description.unwrap_or_default(),
            }),
            firecrawl::SearchResultOrDocument::Document(document) => {
                let meta = document.metadata?;
                let url = meta.source_url.or(meta.og_url)?;
                Some(SearchResult {
                    title: meta.title.or(meta.og_title).unwrap_or_else(|| url.clone()),
                    url,
                    snippet: meta.description.or(meta.og_description).unwrap_or_default(),
                })
            }
        })
        .collect()
}

fn classify_firecrawl_error(error: firecrawl::FirecrawlError, with_api_key: bool) -> WebToolError {
    match error {
        firecrawl::FirecrawlError::HttpRequestFailed(_, status, message) => classify_status_code(
            WebProviderRuntime::Firecrawl,
            status,
            None,
            with_api_key,
            message,
        ),
        firecrawl::FirecrawlError::HttpError(_, error) => WebToolError::general(
            WebProviderRuntime::Firecrawl,
            with_api_key,
            error.to_string(),
        ),
        firecrawl::FirecrawlError::APIError(_, api_error) => {
            // The Firecrawl SDK parses JSON error bodies into APIError without
            // preserving the HTTP status or Retry-After header. Keep the SDK as
            // the official client path, then classify the known Firecrawl API
            // messages here until the SDK exposes status/header metadata.
            classify_error_message(WebProviderRuntime::Firecrawl, with_api_key, api_error.error)
        }
        other => WebToolError::general(
            WebProviderRuntime::Firecrawl,
            with_api_key,
            other.to_string(),
        ),
    }
}

async fn search_tinyfish(
    selected: &SelectedBackend,
    query: &str,
    limit: usize,
    ctx: &ToolCtx,
) -> std::result::Result<Vec<SearchResult>, WebToolError> {
    let key = selected.api_key.as_ref().ok_or_else(|| {
        WebToolError::general(
            WebProviderRuntime::Tinyfish,
            false,
            "missing TinyFish API key",
        )
    })?;
    let client = native_http_client(WebProviderRuntime::Tinyfish, true)?;
    let response: TinyFishSearchResponse =
        send_tinyfish_json(ctx, WebProviderRuntime::Tinyfish, true, || {
            let url = format!(
                "{}?query={}",
                TINYFISH_SEARCH_URL,
                urlencoding::encode(query)
            );
            let mut request = client.get(url);
            request = request.header("X-API-Key", tinyfish_header_value(key)?);
            Ok(request)
        })
        .await?;
    Ok(response.into_results(limit))
}

async fn fetch_tinyfish(
    selected: &SelectedBackend,
    url: &str,
    ctx: &ToolCtx,
) -> std::result::Result<FetchedPage, WebToolError> {
    let key = selected.api_key.as_ref().ok_or_else(|| {
        WebToolError::general(
            WebProviderRuntime::Tinyfish,
            false,
            "missing TinyFish API key",
        )
    })?;
    let client = native_http_client(WebProviderRuntime::Tinyfish, true)?;
    let response: TinyFishFetchResponse =
        send_tinyfish_json(ctx, WebProviderRuntime::Tinyfish, true, || {
            let mut request = client.post(TINYFISH_FETCH_URL).json(&serde_json::json!({
                "urls": [url],
                "format": "markdown"
            }));
            request = request.header("X-API-Key", tinyfish_header_value(key)?);
            Ok(request)
        })
        .await?;
    response.into_page(url)
}

fn native_http_client(
    provider: WebProviderRuntime,
    with_api_key: bool,
) -> std::result::Result<reqwest::Client, WebToolError> {
    reqwest::Client::builder()
        .timeout(NATIVE_TIMEOUT)
        .build()
        .map_err(|e| WebToolError::general(provider, with_api_key, e.to_string()))
}

fn tinyfish_header_value(key: &ApiKey) -> std::result::Result<HeaderValue, WebToolError> {
    HeaderValue::from_str(key.expose()).map_err(|_| {
        WebToolError::general(
            WebProviderRuntime::Tinyfish,
            true,
            "TINYFISH_API_KEY contains characters that cannot be sent as an HTTP header",
        )
    })
}

async fn send_tinyfish_json<T, F>(
    ctx: &ToolCtx,
    provider: WebProviderRuntime,
    with_api_key: bool,
    build_request: F,
) -> std::result::Result<T, WebToolError>
where
    T: for<'de> Deserialize<'de>,
    F: Fn() -> std::result::Result<reqwest::RequestBuilder, WebToolError>,
{
    let mut attempted_retry = false;
    loop {
        let request = build_request()?;
        let response = timeout_or_cancel(ctx, provider, with_api_key, request.send()).await??;
        let status = response.status();
        let headers = response.headers().clone();
        if status.is_success() {
            return timeout_or_cancel(ctx, provider, with_api_key, response.json::<T>())
                .await?
                .map_err(|e| {
                    WebToolError::general(
                        provider,
                        with_api_key,
                        format!("invalid JSON response: {e}"),
                    )
                });
        }
        let body = timeout_or_cancel(ctx, provider, with_api_key, response.text())
            .await?
            .unwrap_or_default();
        let err = classify_http_status(provider, status, &headers, with_api_key, body);
        if !attempted_retry
            && let WebToolErrorKind::RateLimited {
                retry_after: Some(delay),
            } = err.kind
            && delay <= MAX_RATE_LIMIT_RETRY_AFTER
        {
            attempted_retry = true;
            sleep_or_cancel(ctx, provider, with_api_key, delay).await?;
            continue;
        }
        return Err(err);
    }
}

impl From<reqwest::Error> for WebToolError {
    fn from(error: reqwest::Error) -> Self {
        WebToolError::general(WebProviderRuntime::Tinyfish, true, error.to_string())
    }
}

async fn timeout_or_cancel<T, F>(
    ctx: &ToolCtx,
    provider: WebProviderRuntime,
    with_api_key: bool,
    fut: F,
) -> std::result::Result<T, WebToolError>
where
    F: Future<Output = T>,
{
    tokio::select! {
        _ = ctx.cancel.cancelled() => Err(WebToolError::general(provider, with_api_key, "tool call cancelled")),
        result = tokio::time::timeout(NATIVE_TIMEOUT, fut) => result.map_err(|_| WebToolError::general(provider, with_api_key, "request timed out after 30s")),
    }
}

async fn sleep_or_cancel(
    ctx: &ToolCtx,
    provider: WebProviderRuntime,
    with_api_key: bool,
    delay: Duration,
) -> std::result::Result<(), WebToolError> {
    tokio::select! {
        _ = ctx.cancel.cancelled() => Err(WebToolError::general(provider, with_api_key, "tool call cancelled")),
        _ = tokio::time::sleep(delay) => Ok(()),
    }
}

pub(crate) fn classify_http_status(
    provider: WebProviderRuntime,
    status: reqwest::StatusCode,
    headers: &HeaderMap,
    with_api_key: bool,
    body: String,
) -> WebToolError {
    classify_status_code(
        provider,
        status.as_u16(),
        headers
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(crate::engine::retry::parse_retry_after),
        with_api_key,
        body,
    )
}

fn classify_status_code(
    provider: WebProviderRuntime,
    status: u16,
    retry_after: Option<Duration>,
    with_api_key: bool,
    body: String,
) -> WebToolError {
    let kind = match status {
        429 => WebToolErrorKind::RateLimited { retry_after },
        402 => WebToolErrorKind::QuotaExhausted,
        401 | 403 => WebToolErrorKind::AuthFailed,
        _ => return classify_error_message(provider, with_api_key, body),
    };
    WebToolError {
        kind,
        provider,
        with_api_key,
        message: body,
    }
}

fn classify_error_message(
    provider: WebProviderRuntime,
    with_api_key: bool,
    message: String,
) -> WebToolError {
    let lower = message.to_lowercase();
    let kind = if lower.contains("rate limit") || lower.contains("too many requests") {
        WebToolErrorKind::RateLimited { retry_after: None }
    } else if lower.contains("insufficient credits")
        || lower.contains("quota")
        || lower.contains("payment required")
    {
        WebToolErrorKind::QuotaExhausted
    } else if lower.contains("unauthorized")
        || lower.contains("forbidden")
        || lower.contains("invalid api key")
        || lower.contains("authentication")
    {
        WebToolErrorKind::AuthFailed
    } else {
        WebToolErrorKind::General
    };
    WebToolError {
        kind,
        provider,
        with_api_key,
        message,
    }
}

#[derive(Debug, Deserialize)]
struct TinyFishSearchResponse {
    #[allow(dead_code)]
    query: Option<String>,
    results: Vec<TinyFishSearchResult>,
    #[allow(dead_code)]
    total_results: Option<u64>,
    #[allow(dead_code)]
    page: Option<u64>,
}

impl TinyFishSearchResponse {
    fn into_results(self, limit: usize) -> Vec<SearchResult> {
        self.results
            .into_iter()
            .take(limit)
            .map(|result| SearchResult {
                title: result.title,
                url: result.url,
                snippet: result.snippet,
            })
            .collect()
    }
}

#[derive(Debug, Deserialize)]
struct TinyFishSearchResult {
    #[allow(dead_code)]
    position: Option<u64>,
    #[allow(dead_code)]
    site_name: Option<String>,
    title: String,
    snippet: String,
    url: String,
}

#[derive(Debug, Deserialize)]
struct TinyFishFetchResponse {
    results: Vec<TinyFishFetchResult>,
    #[serde(default)]
    errors: Vec<TinyFishFetchError>,
}

impl TinyFishFetchResponse {
    fn into_page(self, requested_url: &str) -> std::result::Result<FetchedPage, WebToolError> {
        if let Some(error) = self
            .errors
            .into_iter()
            .find(|error| error.url.as_deref() == Some(requested_url) || error.url.is_none())
        {
            return Err(WebToolError::general(
                WebProviderRuntime::Tinyfish,
                true,
                format!("{}: {}", requested_url, error.message()),
            ));
        }
        let Some(result) = self.results.into_iter().find(|result| {
            result.url == requested_url || result.final_url.as_deref() == Some(requested_url)
        }) else {
            return Err(WebToolError::general(
                WebProviderRuntime::Tinyfish,
                true,
                format!("{requested_url}: no fetched content returned"),
            ));
        };
        let markdown = match result.text {
            Value::String(text) => text,
            other => other.to_string(),
        };
        Ok(FetchedPage { markdown })
    }
}

#[derive(Debug, Deserialize)]
struct TinyFishFetchResult {
    url: String,
    final_url: Option<String>,
    text: Value,
}

#[derive(Debug, Deserialize)]
struct TinyFishFetchError {
    url: Option<String>,
    error: Option<String>,
    message: Option<String>,
    code: Option<String>,
}

impl TinyFishFetchError {
    fn message(&self) -> String {
        self.message
            .as_deref()
            .or(self.error.as_deref())
            .or(self.code.as_deref())
            .unwrap_or("fetch failed")
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::agent::TurnEvent;

    #[test]
    fn backend_selection_defaults_to_firecrawl_and_routes_explicit_values() {
        let absent = WebConfig::default();
        assert_eq!(
            select_backend_with(&absent, |_| None, |_| None).kind(),
            SelectedBackendKind::Firecrawl
        );

        let tiny = WebConfig {
            provider: WebProvider::Tinyfish,
            firecrawl_base_url: None,
            custom: Default::default(),
        };
        let selected = select_backend_with(
            &tiny,
            |name| (name == TINYFISH_API_KEY_ENV).then(|| "tiny-env".to_string()),
            |_| None,
        );
        assert_eq!(selected.kind(), SelectedBackendKind::Tinyfish);
        assert_eq!(selected.api_key_for_test(), Some("tiny-env"));

        let custom = WebConfig {
            provider: WebProvider::Custom,
            firecrawl_base_url: None,
            custom: Default::default(),
        };
        assert_eq!(
            select_backend_with(&custom, |_| None, |_| None).kind(),
            SelectedBackendKind::Custom
        );
    }

    #[test]
    fn key_resolution_prefers_env_over_store_and_allows_none() {
        let key = resolve_key_with(
            FIRECRAWL_API_KEY_ENV,
            FIRECRAWL_PROVIDER_ID,
            &|name| (name == FIRECRAWL_API_KEY_ENV).then(|| "env-key".to_string()),
            &|provider| (provider == FIRECRAWL_PROVIDER_ID).then(|| "store-key".to_string()),
        );
        assert_eq!(key.as_ref().map(ApiKey::expose), Some("env-key"));

        let key = resolve_key_with(
            TINYFISH_API_KEY_ENV,
            TINYFISH_PROVIDER_ID,
            &|_| None,
            &|provider| (provider == TINYFISH_PROVIDER_ID).then(|| "store-key".to_string()),
        );
        assert_eq!(key.as_ref().map(ApiKey::expose), Some("store-key"));

        let missing = resolve_key_with(
            FIRECRAWL_API_KEY_ENV,
            FIRECRAWL_PROVIDER_ID,
            &|_| None,
            &|_| None,
        );
        assert!(missing.is_none());
    }

    #[test]
    fn web_key_popup_trigger_rules_match_prompt_contract() {
        let keyless_rate = WebToolError {
            kind: WebToolErrorKind::RateLimited { retry_after: None },
            provider: WebProviderRuntime::Firecrawl,
            with_api_key: false,
            message: String::new(),
        };
        assert!(web_error_qualifies_for_key_prompt(&keyless_rate));

        let keyed_quota = WebToolError {
            kind: WebToolErrorKind::QuotaExhausted,
            provider: WebProviderRuntime::Firecrawl,
            with_api_key: true,
            message: String::new(),
        };
        assert!(!web_error_qualifies_for_key_prompt(&keyed_quota));

        let auth = WebToolError {
            kind: WebToolErrorKind::AuthFailed,
            provider: WebProviderRuntime::Tinyfish,
            with_api_key: true,
            message: String::new(),
        };
        assert!(web_error_qualifies_for_key_prompt(&auth));

        let general = WebToolError {
            kind: WebToolErrorKind::General,
            provider: WebProviderRuntime::Firecrawl,
            with_api_key: false,
            message: String::new(),
        };
        assert!(!web_error_qualifies_for_key_prompt(&general));
    }

    #[test]
    fn firecrawl_base_url_prefers_env_over_config() {
        let cfg = WebConfig {
            provider: WebProvider::Firecrawl,
            firecrawl_base_url: Some("https://config.example".to_string()),
            custom: Default::default(),
        };
        assert_eq!(
            resolve_firecrawl_base_url_with(&cfg, &|name| {
                (name == FIRECRAWL_API_URL_ENV).then(|| "https://env.example".to_string())
            })
            .as_deref(),
            Some("https://env.example")
        );
        assert_eq!(
            resolve_firecrawl_base_url_with(&cfg, &|_| None).as_deref(),
            Some("https://config.example")
        );
    }

    #[test]
    fn status_classification_sets_kind_retry_after_and_key_flag() {
        let mut headers = HeaderMap::new();
        headers.insert(header::RETRY_AFTER, HeaderValue::from_static("7"));
        let err = classify_http_status(
            WebProviderRuntime::Tinyfish,
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            &headers,
            true,
            "slow down".to_string(),
        );
        assert_eq!(
            err.kind,
            WebToolErrorKind::RateLimited {
                retry_after: Some(Duration::from_secs(7))
            }
        );
        assert!(err.with_api_key);

        let err = classify_http_status(
            WebProviderRuntime::Firecrawl,
            reqwest::StatusCode::PAYMENT_REQUIRED,
            &HeaderMap::new(),
            false,
            "insufficient credits".to_string(),
        );
        assert_eq!(err.kind, WebToolErrorKind::QuotaExhausted);
        assert!(!err.with_api_key);

        let err = classify_http_status(
            WebProviderRuntime::Tinyfish,
            reqwest::StatusCode::FORBIDDEN,
            &HeaderMap::new(),
            true,
            "forbidden".to_string(),
        );
        assert_eq!(err.kind, WebToolErrorKind::AuthFailed);
    }

    #[test]
    fn tinyfish_search_fixture_parses_and_truncates() {
        let fixture = r#"{
            "query": "web automation tools",
            "results": [
                {"position":1,"site_name":"tinyfish.ai","title":"TinyFish","snippet":"Automate any website","url":"https://tinyfish.ai"},
                {"position":2,"site_name":"github.com","title":"Tools","snippet":"A curated list","url":"https://github.com/example/tools"}
            ],
            "total_results": 10,
            "page": 0
        }"#;
        let parsed: TinyFishSearchResponse = serde_json::from_str(fixture).unwrap();
        let results = parsed.into_results(1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "TinyFish");
        assert_eq!(results[0].url, "https://tinyfish.ai");
    }

    #[test]
    fn tinyfish_fetch_fixture_parses_content_and_failed_url() {
        let fixture = r##"{
            "results": [{
                "url": "https://www.tinyfish.ai/",
                "final_url": "https://www.tinyfish.ai/",
                "title": "TinyFish",
                "description": "TinyFish provides enterprise infrastructure.",
                "language": "en",
                "format": "markdown",
                "text": "# TinyFish\n\nEnterprise infrastructure"
            }],
            "errors": []
        }"##;
        let parsed: TinyFishFetchResponse = serde_json::from_str(fixture).unwrap();
        let page = parsed.into_page("https://www.tinyfish.ai/").unwrap();
        assert!(page.markdown.contains("# TinyFish"));

        let failed = r#"{
            "results": [],
            "errors": [{"url":"https://bad.example","code":"timeout","message":"timed out"}]
        }"#;
        let parsed: TinyFishFetchResponse = serde_json::from_str(failed).unwrap();
        let err = parsed.into_page("https://bad.example").unwrap_err();
        assert!(err.message.contains("https://bad.example"));
        assert!(err.message.contains("timed out"));
    }

    #[test]
    fn websearch_rendering_defaults_and_clamps_limit() {
        assert_eq!(search_limit(None), 5);
        assert_eq!(search_limit(Some(&serde_json::json!(99))), 10);
        assert_eq!(search_limit(Some(&serde_json::json!(0))), 1);
        let rendered = render_search_results(&[
            SearchResult {
                title: "One".to_string(),
                url: "https://one.example".to_string(),
                snippet: "First".to_string(),
            },
            SearchResult {
                title: "Two".to_string(),
                url: "https://two.example".to_string(),
                snippet: "Second".to_string(),
            },
        ]);
        assert!(rendered.contains("1. One\nhttps://one.example\nFirst"));
        assert!(rendered.contains("2. Two\nhttps://two.example\nSecond"));
    }

    #[tokio::test]
    async fn tinyfish_missing_key_falls_back_and_warns_once_per_session() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut ctx, _db) = crate::tools::common::test_ctx_with_db(tmp.path());
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        ctx.events = Some(tx);

        let cfg = WebConfig {
            provider: WebProvider::Tinyfish,
            firecrawl_base_url: None,
            custom: Default::default(),
        };
        let selected = select_backend_with(&cfg, |_| None, |_| None);
        assert_eq!(selected.kind(), SelectedBackendKind::Firecrawl);
        assert!(selected.fallback_from_tinyfish());
        assert!(!selected.has_api_key());

        assert!(emit_tinyfish_fallback_warning(&ctx));
        assert!(!emit_tinyfish_fallback_warning(&ctx));
        let first = rx.recv().await.unwrap();
        assert!(matches!(first, TurnEvent::Notice { text } if text.contains(TINYFISH_API_KEY_ENV)));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn native_schemas_are_backend_neutral() {
        let tool = WebSearchTool;
        let desc = tool.description().to_lowercase();
        assert!(!desc.contains("firecrawl"));
        assert!(!desc.contains("tinyfish"));
        assert!(!desc.contains("curl"));
        assert_eq!(
            tool.parameters()["properties"]["query"]["description"],
            "Search query."
        );

        let tool = WebFetchTool;
        let desc = tool.description().to_lowercase();
        assert!(!desc.contains("firecrawl"));
        assert!(!desc.contains("tinyfish"));
        assert!(!desc.contains("curl"));
        assert_eq!(
            tool.parameters()["properties"]["url"]["description"],
            "URL to fetch."
        );
    }
}
