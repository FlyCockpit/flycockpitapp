use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use crate::config::providers::{ProviderEntry, ProvidersConfig, ResolvedEmbeddingModel};
use crate::engine::model::{Model, OutboundGuard};
use crate::providers::models_fetch;
use crate::redact::RedactionTable;

// Finite embedding batches can legitimately exceed the directory/error budget.
const MAX_EMBEDDING_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const EMBEDDING_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

#[async_trait]
pub trait Embedder: Send + Sync {
    async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>>;

    /// Durable identity of the model whose vector space this embedder returns.
    /// Knowledge sidecars use it to reject vectors from a different model even
    /// when the two models happen to share a dimension.
    fn identity(&self) -> String;
}

#[derive(Clone)]
pub struct OpenAiCompatEmbedder {
    client: reqwest::Client,
    base_url: String,
    headers: Vec<models_fetch::ResolvedHeader>,
    model: String,
    expected_dimensions: Option<u32>,
    guard: Arc<Mutex<OutboundGuard>>,
    command_refresh: Option<Arc<CommandRefresh>>,
}

/// Runtime state for a long-lived command-authenticated embedding client.
/// The request that sends a credential owns its generation, so both must move
/// together after every refresh rather than retaining construction-time data.
struct CommandRefresh {
    provider_id: String,
    /// Live config authority. A rejection-triggered refresh may not execute
    /// the argv from the construction-time provider entry after reload.
    config: crate::daemon::session_worker::SessionConfigHandle,
    configured_generation: u64,
    store: crate::credentials::CredentialStore,
    request: Mutex<models_fetch::ResolvedRequest>,
}

impl CommandRefresh {
    /// Resolve the command entry authorized by the current provider snapshot.
    /// A removed command fails closed; a replacement is the only executable
    /// this long-lived client may run.
    fn current_entry(&self) -> Result<ProviderEntry> {
        let snapshot = self.config.snapshot();
        if snapshot.generation != self.configured_generation {
            tracing::debug!(
                provider_id = %self.provider_id,
                configured_generation = self.configured_generation,
                current_generation = snapshot.generation,
                "embedding auth-command refresh re-authorized against reloaded provider config"
            );
        }
        snapshot
            .providers
            .providers
            .get(&self.provider_id)
            .filter(|entry| entry.auth_command.is_some() || entry.oauth.is_some())
            .cloned()
            .with_context(|| {
                format!(
                    "provider `{}` no longer has global dynamic authentication authorized for embedding refresh",
                    self.provider_id
                )
            })
    }
}

impl OpenAiCompatEmbedder {
    /// Build an OpenAI-compatible embeddings client.
    ///
    /// Embeddings are computed over the post-redaction text. If the input
    /// carries a secret, the provider receives and embeds the configured
    /// placeholder instead of the original secret-bearing string.
    #[allow(dead_code)]
    pub(crate) async fn for_resolved_model(
        providers: &ProvidersConfig,
        resolved: &ResolvedEmbeddingModel,
        session_redact: Arc<RedactionTable>,
    ) -> Result<Self> {
        let entry = providers
            .providers
            .get(&resolved.provider)
            .with_context(|| format!("unknown embedding provider `{}`", resolved.provider))?;
        Self::for_provider_entry_with_store(
            providers,
            &resolved.provider,
            entry,
            &resolved.model,
            resolved.embedding_dimensions,
            session_redact,
            None,
            None,
        )
        .await
    }

    pub(crate) async fn for_resolved_model_with_store(
        providers: &ProvidersConfig,
        resolved: &ResolvedEmbeddingModel,
        session_redact: Arc<RedactionTable>,
        store: crate::credentials::CredentialStore,
        config: &crate::daemon::session_worker::SessionConfigHandle,
    ) -> Result<Self> {
        let entry = providers
            .providers
            .get(&resolved.provider)
            .with_context(|| format!("unknown embedding provider `{}`", resolved.provider))?;
        Self::for_provider_entry_with_store(
            providers,
            &resolved.provider,
            entry,
            &resolved.model,
            resolved.embedding_dimensions,
            session_redact,
            Some(store),
            Some(config),
        )
        .await
    }

    #[allow(dead_code)]
    pub(crate) async fn for_provider_entry(
        providers: &ProvidersConfig,
        provider_id: &str,
        entry: &ProviderEntry,
        model: &str,
        expected_dimensions: Option<u32>,
        session_redact: Arc<RedactionTable>,
    ) -> Result<Self> {
        Self::for_provider_entry_with_store(
            providers,
            provider_id,
            entry,
            model,
            expected_dimensions,
            session_redact,
            None,
            None,
        )
        .await
    }

    pub(crate) async fn for_provider_entry_with_store(
        providers: &ProvidersConfig,
        provider_id: &str,
        entry: &ProviderEntry,
        model: &str,
        expected_dimensions: Option<u32>,
        session_redact: Arc<RedactionTable>,
        store: Option<crate::credentials::CredentialStore>,
        config: Option<&crate::daemon::session_worker::SessionConfigHandle>,
    ) -> Result<Self> {
        let request = match store.clone() {
            Some(store) => {
                models_fetch::resolve_provider_request_async_with_store(
                    provider_id,
                    entry,
                    store,
                    |name| std::env::var(name).ok(),
                )
                .await?
            }
            None => models_fetch::resolve_provider_request_async(provider_id, entry).await?,
        };
        // The embedding send boundary uses the same enforced table as every
        // other model egress. Trust never releases sealed literals.
        let effective_redact = Model::effective_redact_table_for_configured(
            providers,
            provider_id,
            model,
            session_redact,
        );
        let guard = OutboundGuard::new(effective_redact);
        let command_request = request.clone();
        Ok(
            Self::from_resolved_request(request, model.to_string(), expected_dimensions, guard)?
                .with_command_refresh(
                    store
                        .zip(config)
                        .filter(|_| entry.auth_command.is_some() || entry.oauth.is_some())
                        .map(|(store, config)| {
                            Arc::new(CommandRefresh {
                                provider_id: provider_id.to_string(),
                                config: config.live(),
                                configured_generation: providers.resolution_generation,
                                store,
                                request: Mutex::new(command_request),
                            })
                        }),
                ),
        )
    }

    #[allow(dead_code)]
    pub(crate) fn from_resolved_request(
        request: models_fetch::ResolvedRequest,
        model: String,
        expected_dimensions: Option<u32>,
        guard: OutboundGuard,
    ) -> Result<Self> {
        Ok(Self {
            client: crate::providers::provider_http::build_with_timeout(EMBEDDING_REQUEST_TIMEOUT)
                .context("building embedding HTTP client")?,
            base_url: request.base_url,
            headers: request.headers,
            model,
            expected_dimensions,
            guard: Arc::new(Mutex::new(guard)),
            command_refresh: None,
        })
    }

    fn with_command_refresh(mut self, command_refresh: Option<Arc<CommandRefresh>>) -> Self {
        self.command_refresh = command_refresh;
        self
    }

    fn request<'a>(
        &self,
        body: &EmbeddingsRequest<'a>,
        base_url: &str,
        headers: &[models_fetch::ResolvedHeader],
    ) -> reqwest::RequestBuilder {
        let mut req = self
            .client
            .post(format!("{}/embeddings", base_url.trim_end_matches('/')))
            .json(body);
        let effective_ua = headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("user-agent"))
            .map(|header| header.value.clone())
            .unwrap_or_else(|| crate::user_agent::user_agent().to_owned());
        req = req.header(reqwest::header::USER_AGENT, effective_ua);
        for header in headers {
            if !header.name.eq_ignore_ascii_case("user-agent") {
                req = req.header(&header.name, &header.value);
            }
        }
        req
    }

    fn current_request(&self) -> (String, Vec<models_fetch::ResolvedHeader>, Option<u64>) {
        self.command_refresh
            .as_ref()
            .map(|refresh| {
                let request = refresh
                    .request
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                (
                    request.base_url.clone(),
                    request.headers.clone(),
                    request.command_credential_generation(),
                )
            })
            .unwrap_or_else(|| (self.base_url.clone(), self.headers.clone(), None))
    }

    fn guard(&self) -> OutboundGuard {
        self.guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

#[async_trait]
impl Embedder for OpenAiCompatEmbedder {
    async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        tokio::time::timeout(EMBEDDING_REQUEST_TIMEOUT, self.embed_with_deadline(texts))
            .await
            .context("embedding request deadline exceeded")?
    }

    fn identity(&self) -> String {
        format!("openai-compatible:{}:{}", self.base_url, self.model)
    }
}

impl OpenAiCompatEmbedder {
    async fn embed_with_deadline(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        let redacted = self.guard().scrub_many(texts);
        let redacted_refs: Vec<&str> = redacted.iter().map(String::as_str).collect();
        let body = EmbeddingsRequest {
            model: &self.model,
            input: &redacted_refs,
        };
        let (base_url, headers, request_generation) = self.current_request();
        let mut diagnostic_headers = headers.clone();
        let response = self
            .request(&body, &base_url, &headers)
            .send()
            .await
            .context("sending embeddings request")?;
        let refreshed = if matches!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
        ) {
            self.command_refresh.as_ref()
        } else {
            None
        };
        let response = if let Some(refresh) = refreshed {
            drop(response);
            let request = models_fetch::refresh_provider_request_async_with_store_authorized(
                &refresh.provider_id,
                refresh.store.clone(),
                |name| std::env::var(name).ok(),
                request_generation,
                || refresh.current_entry(),
            )
            .await?;
            // The store now contains the refreshed command result. Update
            // both request provenance and diagnostic redaction before the
            // retry can send or surface a provider body.
            let guard = self
                .guard()
                .with_current_provider_auth_command_values(&refresh.store)?;
            *self
                .guard
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = guard;
            *refresh
                .request
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = request.clone();
            diagnostic_headers.extend(request.headers.iter().cloned());
            self.request(&body, &request.base_url, &request.headers)
                .send()
                .await
                .context("retrying embeddings request after credential refresh")?
        } else {
            response
        };
        let status = response.status();
        let limit = if status.is_success() {
            MAX_EMBEDDING_RESPONSE_BYTES
        } else {
            crate::providers::models_fetch::MAX_PROVIDER_RESPONSE_BYTES
        };
        let text =
            crate::providers::provider_http::read_body_with_limit(response, "embeddings", limit)
                .await
                .with_context(|| format!("reading embeddings response ({status})"))?;
        let diagnostic = || self.guard().provider_diagnostic(&text, &diagnostic_headers);
        if !status.is_success() {
            anyhow::bail!(
                "embeddings request returned {status}: {}",
                snippet(&diagnostic())
            );
        }
        let parsed: EmbeddingsResponse = serde_json::from_str(&text).map_err(|error| {
            // Serde's Unexpected::Str prints decoded provider data. Never retain
            // that raw error as an anyhow cause, even behind a scrubbed context.
            anyhow!(
                "parsing embeddings response at line {}, column {}: {}",
                error.line(),
                error.column(),
                snippet(&diagnostic())
            )
        })?;
        let validate = || -> Result<Vec<Vec<f32>>> {
            if parsed.data.len() != texts.len() {
                anyhow::bail!(
                    "embeddings response count mismatch: requested {}, got {}",
                    texts.len(),
                    parsed.data.len()
                );
            }

            let mut by_index: Vec<Option<Vec<f32>>> = vec![None; texts.len()];
            for item in parsed.data {
                if item.index >= texts.len() {
                    anyhow::bail!("embeddings response index {} out of range", item.index);
                }
                if let Some(expected) = self.expected_dimensions
                    && item.embedding.len() != expected as usize
                {
                    anyhow::bail!(
                        "embedding dimension mismatch: expected {}, got {}",
                        expected,
                        item.embedding.len()
                    );
                }
                if by_index[item.index].replace(item.embedding).is_some() {
                    anyhow::bail!("duplicate embedding response index {}", item.index);
                }
            }
            by_index
                .into_iter()
                .enumerate()
                .map(|(index, embedding)| {
                    embedding.ok_or_else(|| anyhow!("missing embedding response index {index}"))
                })
                .collect()
        };
        validate().map_err(|error| {
            anyhow!(
                self.guard()
                    .provider_diagnostic(&error.to_string(), &diagnostic_headers)
            )
        })
    }
}

#[derive(Serialize)]
struct EmbeddingsRequest<'a> {
    model: &'a str,
    input: &'a [&'a str],
}

#[derive(Deserialize)]
struct EmbeddingsResponse {
    data: Vec<EmbeddingItem>,
}

#[derive(Deserialize)]
struct EmbeddingItem {
    index: usize,
    embedding: Vec<f32>,
}

fn snippet(body: &str) -> String {
    const MAX: usize = 500;
    let compact = body.replace(['\n', '\r'], " ");
    if compact.len() > MAX {
        let mut end = MAX;
        while !compact.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &compact[..end])
    } else {
        compact
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    #[cfg(unix)]
    use std::sync::RwLock;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const SECRET: &str = "sk-embed-secret-token-abc123";
    const PLACEHOLDER: &str = "[embed-redacted]";

    #[derive(Debug, Clone)]
    struct CapturedEmbeddingRequest {
        head: String,
        body: String,
    }

    async fn capture_embedding_server_with_response_status(
        response_body: &'static str,
        status: &'static str,
        location: Option<&'static str>,
    ) -> (
        String,
        tokio::sync::oneshot::Receiver<CapturedEmbeddingRequest>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0_u8; 1024];
            loop {
                let n = socket.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if let Some(header_end) = find_header_end(&buf) {
                    let headers = String::from_utf8_lossy(&buf[..header_end]);
                    let content_len = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .or_else(|| {
                            headers
                                .lines()
                                .find_map(|line| line.strip_prefix("Content-Length:"))
                        })
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let body_start = header_end + 4;
                    if buf.len() >= body_start + content_len {
                        let body =
                            String::from_utf8(buf[body_start..body_start + content_len].to_vec())
                                .unwrap();
                        let _ = tx.send(CapturedEmbeddingRequest {
                            head: headers.into_owned(),
                            body,
                        });
                        break;
                    }
                }
            }
            let mut response = format!("HTTP/1.1 {status}\r\n");
            if let Some(location) = location {
                response.push_str(&format!("Location: {location}\r\n"));
            }
            response.push_str(&format!(
                "content-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            ));
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        (format!("http://{addr}/v1"), rx)
    }

    async fn capture_embedding_server_with_response(
        response_body: &'static str,
    ) -> (
        String,
        tokio::sync::oneshot::Receiver<CapturedEmbeddingRequest>,
    ) {
        capture_embedding_server_with_response_status(response_body, "200 OK", None).await
    }

    async fn capture_embedding_server() -> (
        String,
        tokio::sync::oneshot::Receiver<CapturedEmbeddingRequest>,
    ) {
        capture_embedding_server_with_response(
            r#"{"data":[{"index":0,"embedding":[1.0,2.0,3.0]},{"index":1,"embedding":[4.0,5.0,6.0]}]}"#,
        )
        .await
    }

    fn user_agent_values(head: &str) -> Vec<String> {
        head.lines()
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("user-agent") {
                    Some(value.trim().to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    fn find_header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n")
    }

    fn secret_table() -> Arc<RedactionTable> {
        let cfg = crate::config::extended::RedactConfig {
            enabled: true,
            scan_environment: false,
            scan_dotenv: false,
            scan_ssh_keys: false,
            min_secret_length: 8,
            placeholder: PLACEHOLDER.to_string(),
            denylist: vec![SECRET.to_string()],
            ..crate::config::extended::RedactConfig::default()
        };
        Arc::new(
            RedactionTable::build_with_env_and_secrets(
                &cfg,
                std::path::Path::new("."),
                &std::collections::HashMap::new(),
                std::iter::empty(),
            )
            .unwrap(),
        )
    }

    fn guard(_trusted: bool) -> OutboundGuard {
        OutboundGuard::new(secret_table())
    }

    fn embedder(base_url: String, guard: OutboundGuard) -> OpenAiCompatEmbedder {
        OpenAiCompatEmbedder::from_resolved_request(
            models_fetch::ResolvedRequest {
                base_url,
                headers: vec![models_fetch::ResolvedHeader {
                    name: "Authorization".into(),
                    value: "Bearer test-token".into(),
                }],
                is_codex_credential: false,
            },
            "text-embedding-3-small".into(),
            Some(3),
            guard,
        )
        .unwrap()
    }

    /// AC4, embeddings send boundary. The embedding path is a potentially
    /// sensitive caller — it ships user text to a provider — so it may not
    /// uses the enforced table regardless of configured trust. This pins the
    /// production constructor [`OpenAiCompatEmbedder::for_provider_entry`].
    #[tokio::test]
    async fn embedding_send_boundary_routes_custody_before_the_wire() {
        use crate::config::providers::{ModelEntry, ModelTrust, ProviderEntry, ProvidersConfig};

        for trust in [ModelTrust::Trusted, ModelTrust::Untrusted] {
            let (base_url, capture_rx) = capture_embedding_server_with_response(
                r#"{"data":[{"index":0,"embedding":[1.0,2.0,3.0]}]}"#,
            )
            .await;
            let entry = ProviderEntry {
                url: base_url,
                trust: Some(trust),
                models: vec![ModelEntry {
                    id: "text-embedding-3-small".into(),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            };
            let mut providers = ProvidersConfig::default();
            providers.providers.insert("p".into(), entry.clone());

            let embedder = OpenAiCompatEmbedder::for_provider_entry(
                &providers,
                "p",
                &entry,
                "text-embedding-3-small",
                Some(3),
                secret_table(),
            )
            .await
            .unwrap();
            let _ = embedder
                .embed(&[&format!("index this {SECRET} please")])
                .await
                .unwrap();

            let captured = capture_rx.await.unwrap();
            assert!(
                !captured.body.contains(SECRET),
                "{trust:?}: an embedding endpoint must never receive the secret: {}",
                captured.body
            );
            assert!(
                captured.body.contains(PLACEHOLDER),
                "{trust:?}: the redacted rendering must have reached the wire: {}",
                captured.body
            );
        }
    }

    #[tokio::test]
    async fn embedder_openai_compat_wire() {
        let (base_url, capture_rx) = capture_embedding_server().await;
        let embedder = embedder(base_url, guard(false));

        let vectors = embedder.embed(&["alpha", "beta"]).await.unwrap();

        assert_eq!(vectors, vec![vec![1.0, 2.0, 3.0], vec![4.0, 5.0, 6.0]]);
        let captured = capture_rx.await.unwrap();
        let body: serde_json::Value = serde_json::from_str(&captured.body).unwrap();
        assert_eq!(body["model"], "text-embedding-3-small");
        assert_eq!(body["input"], serde_json::json!(["alpha", "beta"]));
        let uas = user_agent_values(&captured.head);
        assert_eq!(
            uas,
            vec![crate::user_agent::user_agent().to_string()],
            "exactly one canonical User-Agent expected; head=\n{}",
            captured.head
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn embedding_refresh_does_not_run_a_command_revoked_while_waiting() {
        use crate::config::providers::{AuthKind, ModelEntry, ProviderEntry, ProvidersConfig};
        use crate::daemon::session_worker::{SessionConfigHandle, SessionConfigSnapshot};

        const PROVIDER_ID: &str = "embedding-refresh-revoked-while-waiting";
        let temp = tempfile::tempdir().unwrap();
        let executions = temp.path().join("auth-command-executions");
        let (base_url, request_rx) = capture_embedding_server_with_response_status(
            r#"{"error":"expired"}"#,
            "401 Unauthorized",
            None,
        )
        .await;
        let entry = ProviderEntry {
            url: base_url,
            auth: Some(AuthKind::Command),
            auth_command: Some(vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf 'executed\\n' >> \"$1\"; printf '%s' '{\"token\":\"test-token\",\"expires_at\":null}'"
                    .into(),
                "auth-command".into(),
                executions.to_string_lossy().into_owned(),
            ]),
            models: vec![ModelEntry {
                id: "text-embedding-3-small".into(),
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        };
        let mut providers = ProvidersConfig::default();
        providers
            .providers
            .insert(PROVIDER_ID.into(), entry.clone());
        let config = SessionConfigHandle::new(Arc::new(RwLock::new(SessionConfigSnapshot::new(
            1,
            providers.clone(),
            crate::config::extended::ExtendedConfig::default(),
        ))));
        let store = crate::credentials::CredentialStore::open(temp.path().join("credentials.json"))
            .unwrap();
        let embedder = OpenAiCompatEmbedder::for_provider_entry_with_store(
            &providers,
            PROVIDER_ID,
            &entry,
            "text-embedding-3-small",
            Some(3),
            secret_table(),
            Some(store),
            Some(&config),
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read_to_string(&executions).unwrap(), "executed\n");

        // Occupy the same production refresh guard so the rejected embedding
        // request is queued when its provider config is reloaded.
        let (guard_entered_tx, guard_entered_rx) = tokio::sync::oneshot::channel();
        let (release_guard_tx, release_guard_rx) = tokio::sync::oneshot::channel();
        let guard = tokio::spawn(async move {
            crate::auth::refresh_guard::serialized_refresh(PROVIDER_ID, || async move {
                let _ = guard_entered_tx.send(());
                let _ = release_guard_rx.await;
            })
            .await;
        });
        guard_entered_rx.await.unwrap();

        let embedding = tokio::spawn(async move { embedder.embed(&["queued refresh"]).await });
        let _request = request_rx.await.unwrap();

        let mut revoked_providers = providers;
        revoked_providers.providers.remove(PROVIDER_ID);
        config.set_full_config_snapshot_for_tests(SessionConfigSnapshot::new(
            2,
            revoked_providers,
            crate::config::extended::ExtendedConfig::default(),
        ));
        let _ = release_guard_tx.send(());
        guard.await.unwrap();

        let error = embedding.await.unwrap().unwrap_err();
        assert!(
            error.to_string().contains(
                "no longer has global dynamic authentication authorized for embedding refresh"
            ),
            "unexpected refresh error: {error}"
        );
        assert_eq!(
            std::fs::read_to_string(&executions).unwrap(),
            "executed\n",
            "the production embedding retry must not spawn the revoked command"
        );
    }

    #[tokio::test]
    async fn embedding_user_agent_configured_override_wins() {
        let (base_url, capture_rx) = capture_embedding_server_with_response(
            r#"{"data":[{"index":0,"embedding":[1.0,2.0,3.0]}]}"#,
        )
        .await;
        let embedder = OpenAiCompatEmbedder::from_resolved_request(
            models_fetch::ResolvedRequest {
                base_url: base_url.clone(),
                headers: vec![
                    models_fetch::ResolvedHeader {
                        name: "Authorization".into(),
                        value: "Bearer test-token".into(),
                    },
                    models_fetch::ResolvedHeader {
                        name: "User-Agent".into(),
                        value: "first-ua/1".into(),
                    },
                    models_fetch::ResolvedHeader {
                        name: "user-agent".into(),
                        value: "second-ua/2".into(),
                    },
                ],
                is_codex_credential: false,
            },
            "text-embedding-3-small".into(),
            Some(3),
            guard(false),
        )
        .unwrap();

        let _ = embedder.embed(&["alpha"]).await.unwrap();
        let captured = capture_rx.await.unwrap();
        let uas = user_agent_values(&captured.head);
        assert_eq!(
            uas,
            vec!["first-ua/1".to_string()],
            "User-Agent before user-agent: first resolved wins; head=\n{}",
            captured.head
        );
        assert_ne!(uas[0], crate::user_agent::user_agent());
    }

    #[tokio::test]
    async fn embedding_user_agent_single_configured_header() {
        let (base_url, capture_rx) = capture_embedding_server_with_response(
            r#"{"data":[{"index":0,"embedding":[1.0,2.0,3.0]}]}"#,
        )
        .await;
        let embedder = OpenAiCompatEmbedder::from_resolved_request(
            models_fetch::ResolvedRequest {
                base_url,
                headers: vec![
                    models_fetch::ResolvedHeader {
                        name: "Authorization".into(),
                        value: "Bearer test-token".into(),
                    },
                    models_fetch::ResolvedHeader {
                        name: "user-agent".into(),
                        value: "configured-ua/1".into(),
                    },
                ],
                is_codex_credential: false,
            },
            "text-embedding-3-small".into(),
            Some(3),
            guard(false),
        )
        .unwrap();

        let _ = embedder.embed(&["alpha"]).await.unwrap();
        let captured = capture_rx.await.unwrap();
        let uas = user_agent_values(&captured.head);
        assert_eq!(uas, vec!["configured-ua/1".to_string()]);
    }

    #[test]
    fn embedder_requires_redaction_table() {
        let guard = guard(false);
        let embedder = OpenAiCompatEmbedder::from_resolved_request(
            models_fetch::ResolvedRequest {
                base_url: "http://127.0.0.1:1/v1".into(),
                headers: vec![],
                is_codex_credential: false,
            },
            "text-embedding-3-small".into(),
            Some(3),
            guard,
        )
        .unwrap();

        let guard = embedder
            .guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _: &OutboundGuard = &guard;
    }

    #[tokio::test]
    async fn embed_redacts_before_send() {
        let (base_url, capture_rx) = capture_embedding_server_with_response(
            r#"{"data":[{"index":0,"embedding":[1.0,2.0,3.0]}]}"#,
        )
        .await;
        let embedder = embedder(base_url, guard(false));
        let input = format!("alpha {SECRET} omega");

        let _ = embedder.embed(&[input.as_str()]).await.unwrap();

        let raw = capture_rx.await.unwrap().body;
        assert!(raw.contains(PLACEHOLDER), "redacted body: {raw}");
        assert!(!raw.contains(SECRET), "secret leaked in body: {raw}");
    }

    #[tokio::test]
    async fn embed_redacts_every_batch_element() {
        let (base_url, capture_rx) = capture_embedding_server().await;
        let embedder = embedder(base_url, guard(false));
        let later = format!("beta {SECRET}");

        let _ = embedder.embed(&["alpha", later.as_str()]).await.unwrap();

        let body: serde_json::Value =
            serde_json::from_str(&capture_rx.await.unwrap().body).unwrap();
        assert_eq!(body["input"][0], "alpha");
        assert_eq!(body["input"][1], format!("beta {PLACEHOLDER}"));
    }

    #[tokio::test]
    async fn embed_trusted_provider_redacts() {
        let (base_url, capture_rx) = capture_embedding_server_with_response(
            r#"{"data":[{"index":0,"embedding":[1.0,2.0,3.0]}]}"#,
        )
        .await;
        let embedder = embedder(base_url, guard(true));
        let input = format!("trusted {SECRET}");

        let _ = embedder.embed(&[input.as_str()]).await.unwrap();

        let raw = capture_rx.await.unwrap().body;
        assert!(
            !raw.contains(SECRET),
            "trusted provider must not see sealed text: {raw}"
        );
        assert!(
            raw.contains(PLACEHOLDER),
            "trusted provider must receive the redacted rendering: {raw}"
        );
    }

    #[tokio::test]
    async fn embed_empty_batch_is_safe() {
        let (base_url, capture_rx) = capture_embedding_server_with_response(r#"{"data":[]}"#).await;
        let embedder = embedder(base_url, guard(false));

        let vectors = embedder.embed(&[]).await.unwrap();

        assert!(vectors.is_empty());
        let body: serde_json::Value =
            serde_json::from_str(&capture_rx.await.unwrap().body).unwrap();
        assert_eq!(body["input"], serde_json::json!([]));
    }

    #[test]
    fn outbound_guard_shared_by_dispatch_and_embedder() {
        let embedder = OpenAiCompatEmbedder::from_resolved_request(
            models_fetch::ResolvedRequest {
                base_url: "http://127.0.0.1:1/v1".into(),
                headers: vec![],
                is_codex_credential: false,
            },
            "text-embedding-3-small".into(),
            Some(3),
            guard(false),
        )
        .unwrap();

        let guard = embedder
            .guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _: &OutboundGuard = &guard;
    }

    #[tokio::test]
    async fn embedding_client_rejects_redirect_without_replaying_credentials() {
        let (base_url, capture_rx) = capture_embedding_server_with_response_status(
            r#"{"error":"moved"}"#,
            "302 Found",
            Some("http://credential-leak.invalid/v1/embeddings"),
        )
        .await;
        let embedder = OpenAiCompatEmbedder::from_resolved_request(
            models_fetch::ResolvedRequest {
                base_url,
                headers: vec![models_fetch::ResolvedHeader {
                    name: "x-api-key".into(),
                    value: "leaked-secret".into(),
                }],
                is_codex_credential: false,
            },
            "text-embedding-3-small".into(),
            Some(3),
            guard(false),
        )
        .unwrap();
        let err = embedder.embed(&["alpha"]).await.unwrap_err();
        assert!(err.to_string().contains("302"), "{err}");
        let captured = capture_rx.await.unwrap();
        assert!(
            captured
                .head
                .to_ascii_lowercase()
                .contains("x-api-key: leaked-secret"),
            "{}",
            captured.head
        );
    }
    #[tokio::test]
    async fn embedding_parse_success_validation_scrubs_actual_numeric_credentials() {
        const CREDENTIAL: &str = "65432109";
        let (url, capture) = capture_embedding_server_with_response(
            r#"{"data":[{"index":65432109,"embedding":[1,2,3]}]}"#,
        )
        .await;
        let embedder = OpenAiCompatEmbedder::from_resolved_request(
            models_fetch::ResolvedRequest {
                base_url: url,
                headers: vec![models_fetch::ResolvedHeader {
                    name: "x-api-key".into(),
                    value: CREDENTIAL.into(),
                }],
                is_codex_credential: false,
            },
            "m".into(),
            Some(3),
            OutboundGuard::new(Arc::new(RedactionTable::empty())),
        )
        .unwrap();
        let error = format!("{:#}", embedder.embed(&["test"]).await.unwrap_err());
        let request = capture.await.unwrap();
        assert!(
            request.head.lines().any(|line| line
                .split_once(':')
                .is_some_and(|(name, value)| name.eq_ignore_ascii_case("x-api-key")
                    && value.trim() == CREDENTIAL)),
            "actual private credential must reach the provider"
        );
        assert!(
            !error.contains(CREDENTIAL),
            "numeric credential escaped a post-parse validation error: {error}"
        );
        assert!(
            error.contains("out of range"),
            "useful validation diagnostic lost: {error}"
        );
    }
}

#[cfg(test)]
mod response_budget_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_embedder(url: String) -> OpenAiCompatEmbedder {
        OpenAiCompatEmbedder::from_resolved_request(
            models_fetch::ResolvedRequest {
                base_url: url,
                headers: vec![],
                is_codex_credential: false,
            },
            "m".into(),
            None,
            OutboundGuard::new(Arc::new(RedactionTable::empty())),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn embedding_bodies_bound_declared_chunked_exact_and_large_vectors() {
        for success in [false, true] {
            let limit = if success {
                MAX_EMBEDDING_RESPONSE_BYTES
            } else {
                crate::providers::models_fetch::MAX_PROVIDER_RESPONSE_BYTES
            };
            for chunked in [false, true] {
                for overflow in [false, true] {
                    let prefix = if success {
                        r#"{"data":[{"index":0,"embedding":[1,2,3]}]}"#
                    } else {
                        "useful embedding diagnostic"
                    };
                    let body = format!(
                        "{prefix}{}",
                        " ".repeat(limit + usize::from(overflow) - prefix.len())
                    );
                    let (url, server) = crate::providers::provider_http::serve_test_bodies(vec![(
                        if success { 200 } else { 400 },
                        body,
                        chunked,
                    )])
                    .await;
                    let result = test_embedder(url).embed(&["a"]).await;
                    if success && !overflow {
                        assert_eq!(result.unwrap(), vec![vec![1.0, 2.0, 3.0]]);
                    } else {
                        let shown = format!("{:#}", result.unwrap_err());
                        if overflow {
                            assert!(shown.contains("byte limit"), "{shown}");
                        } else {
                            assert!(
                                shown.contains("400")
                                    && shown.contains("useful embedding diagnostic"),
                                "{shown}"
                            );
                        }
                        assert!(
                            !shown.contains("Unauthorized"),
                            "body overflow is not an auth failure: {shown}"
                        );
                    }
                    server.await.unwrap();
                }
            }
        }
        let count = 900_000;
        let body = format!(
            r#"{{"data":[{{"index":0,"embedding":[{}0]}}]}}"#,
            "0.123456789,".repeat(count)
        );
        assert!(body.len() > crate::providers::models_fetch::MAX_PROVIDER_RESPONSE_BYTES);
        let (url, server) =
            crate::providers::provider_http::serve_test_bodies(vec![(200, body, true)]).await;
        let vectors = test_embedder(url)
            .embed(&["large finite vector"])
            .await
            .unwrap();
        assert_eq!(vectors[0].len(), count + 1);
        assert_eq!(vectors[0][count], 0.0);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn embedding_pending_success_and_error_deadline_and_drop_release_body() {
        for status in [200, 400] {
            for deadline in [false, true] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let url = format!("http://{}", listener.local_addr().unwrap());
                let retained = Arc::new(test_embedder(url));
                let sending = retained.clone();
                let task = tokio::spawn(async move { sending.embed(&["a"]).await });
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0; 8192];
                let mut received = Vec::new();
                while !received.windows(4).any(|v| v == b"\r\n\r\n") {
                    let n = socket.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    received.extend_from_slice(&buf[..n]);
                }
                socket.write_all(format!("HTTP/1.1 {status} OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n1\r\nx\r\n").as_bytes()).await.unwrap();
                for _ in 0..20 {
                    tokio::task::yield_now().await;
                }
                assert!(!task.is_finished(), "body must be pending");
                if deadline {
                    tokio::time::pause();
                    tokio::time::advance(
                        EMBEDDING_REQUEST_TIMEOUT + std::time::Duration::from_secs(1),
                    )
                    .await;
                    let error = format!(
                        "{:#}",
                        tokio::time::timeout(std::time::Duration::from_secs(1), task)
                            .await
                            .expect("embedding transport must own a finite deadline")
                            .unwrap()
                            .unwrap_err()
                    );
                    assert!(
                        error.contains("deadline") || error.contains("timed out"),
                        "{error}"
                    );
                    tokio::time::resume();
                } else {
                    task.abort();
                    assert!(task.await.unwrap_err().is_cancelled());
                }
                tokio::time::timeout(std::time::Duration::from_secs(3), async {
                    while socket.read(&mut buf).await.unwrap_or(0) != 0 {}
                })
                .await
                .expect("body future drop releases TCP connection");
                assert_eq!(
                    Arc::strong_count(&retained),
                    1,
                    "the configured client remains alive after the consumed body is dropped"
                );
                let next_client = retained.clone();
                let next =
                    tokio::spawn(async move { next_client.embed(&["after cancellation"]).await });
                tokio::time::timeout(std::time::Duration::from_secs(5),async {
                    let (mut next_socket,_) = listener.accept().await.unwrap();
                    assert!(next_socket.read(&mut buf).await.unwrap()>0);
                    let body=r#"{"data":[{"index":0,"embedding":[1,2,3]}]}"#;
                    next_socket.write_all(format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
                    assert_eq!(next.await.unwrap().unwrap(),vec![vec![1.0,2.0,3.0]]);
                }).await.expect("retained client handles the next normal embedding after body cancellation/deadline");
            }
        }
    }
}

#[cfg(all(test, unix))]
mod retry_response_budget_tests {
    use super::*;

    #[tokio::test]
    async fn embedding_credential_retry_uses_same_body_budget_and_preserves_vectors() {
        use crate::config::providers::{AuthKind, ModelEntry};
        use crate::daemon::session_worker::{SessionConfigHandle, SessionConfigSnapshot};
        for status in [200, 400] {
            for overflow in [false, true] {
                let temp = tempfile::tempdir().unwrap();
                let body = if overflow {
                    "x".repeat(if status == 200 {
                        MAX_EMBEDDING_RESPONSE_BYTES + 1
                    } else {
                        crate::providers::models_fetch::MAX_PROVIDER_RESPONSE_BYTES + 1
                    })
                } else if status == 200 {
                    r#"{"data":[{"index":0,"embedding":[1,2,3]}]}"#.into()
                } else {
                    "useful retry diagnostic".into()
                };
                let (url, server) = crate::providers::provider_http::serve_test_bodies(vec![
                    (401, "expired".into(), true),
                    (status, body, true),
                ])
                .await;
                let id = format!("embedding-retry-{status}-{overflow}");
                let entry = ProviderEntry {
                    url,
                    auth: Some(AuthKind::Command),
                    auth_command: Some(vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        "printf '%s' '{\"token\":\"test-retry-token\",\"expires_at\":null}'".into(),
                    ]),
                    models: vec![ModelEntry {
                        id: "m".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                };
                let mut providers = ProvidersConfig::default();
                providers.providers.insert(id.clone(), entry.clone());
                let config = SessionConfigHandle::new(Arc::new(std::sync::RwLock::new(
                    SessionConfigSnapshot::new(1, providers.clone(), Default::default()),
                )));
                let store =
                    crate::credentials::CredentialStore::open(temp.path().join("credentials.json"))
                        .unwrap();
                let embedder = OpenAiCompatEmbedder::for_provider_entry_with_store(
                    &providers,
                    &id,
                    &entry,
                    "m",
                    Some(3),
                    Arc::new(RedactionTable::empty()),
                    Some(store),
                    Some(&config),
                )
                .await
                .unwrap();
                let result = embedder.embed(&["retry"]).await;
                if status == 200 && !overflow {
                    assert_eq!(result.unwrap(), vec![vec![1.0, 2.0, 3.0]]);
                } else {
                    let error = format!("{:#}", result.unwrap_err());
                    if overflow {
                        assert!(error.contains("byte limit"), "{error}");
                    } else {
                        assert!(
                            error.contains("400") && error.contains("useful retry diagnostic"),
                            "{error}"
                        );
                    }
                }
                server.await.unwrap();
            }
        }
    }
}

#[cfg(test)]
mod parse_diagnostic_tests {
    use super::*;

    #[tokio::test]
    async fn embedding_parse_error_chain_scrubs_decoded_header_and_session_values() {
        for credential in [
            r#"known/header-key/+private\fragment-0042"#,
            r#"known/header-key/+private"fragment-0042"#,
        ] {
            let session_secret = r#"known/session-key/+private"fragment-0042"#;
            let body=serde_json::json!({"data":[{"index":0,"embedding":[credential]}],"detail":{"useful":"useful vector diagnostic","local":session_secret}}).to_string();
            let (url, server) =
                crate::providers::provider_http::serve_test_bodies(vec![(200, body, true)]).await;
            let guard = OutboundGuard::new(Arc::new(
                RedactionTable::empty()
                    .with_forced_literal(session_secret.into(), "session discovery".into())
                    .unwrap(),
            ));
            let embedder = OpenAiCompatEmbedder::from_resolved_request(
                models_fetch::ResolvedRequest {
                    base_url: url,
                    headers: vec![models_fetch::ResolvedHeader {
                        name: "x-api-key".into(),
                        value: credential.into(),
                    }],
                    is_codex_credential: false,
                },
                "m".into(),
                Some(3),
                guard,
            )
            .unwrap();
            let error = format!("{:#}", embedder.embed(&["test"]).await.unwrap_err());
            assert!(
                !error.contains("known/header-key")
                    && !error.contains("known/session-key")
                    && !error.contains("fragment-0042"),
                "credential escaped error chain: {error}"
            );
            assert!(
                error.contains("useful vector diagnostic") && error.contains("line 1"),
                "useful parse diagnostic lost: {error}"
            );
            server.await.unwrap();
        }
    }
}
