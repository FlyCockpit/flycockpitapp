use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use crate::config::providers::{ProviderEntry, ProvidersConfig, ResolvedEmbeddingModel};
use crate::engine::model::{Model, OutboundGuard};
use crate::providers::models_fetch;
use crate::redact::RedactionTable;

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
            .filter(|entry| entry.auth_command.is_some())
            .cloned()
            .with_context(|| {
                format!(
                    "provider `{}` no longer has a global auth_command authorized for embedding refresh",
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
        // AC4: the embedding send boundary is a potentially sensitive caller.
        // Its custody class is host-owned (the *configured* embedding model
        // fixes it, no caller may ask for `Trusted`), but it still may not
        // decide raw-vs-redacted by reading a trust flag: it routes custody
        // through the typed request API and takes the raw table only from the
        // grant that route mints. An unroutable target falls closed.
        let effective_redact = Model::effective_redact_table_for_configured(
            providers,
            provider_id,
            model,
            session_redact,
        );
        let guard = OutboundGuard::new(effective_redact);
        let command_request = request.clone();
        Ok(
            Self::from_resolved_request(request, model.to_string(), expected_dimensions, guard)
                .with_command_refresh(
                    store
                        .zip(config)
                        .filter(|_| entry.auth_command.is_some())
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
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: request.base_url,
            headers: request.headers,
            model,
            expected_dimensions,
            guard: Arc::new(Mutex::new(guard)),
            command_refresh: None,
        }
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
        let redacted = self.guard().scrub_many(texts);
        let redacted_refs: Vec<&str> = redacted.iter().map(String::as_str).collect();
        let body = EmbeddingsRequest {
            model: &self.model,
            input: &redacted_refs,
        };
        let (base_url, headers, request_generation) = self.current_request();
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
            let entry = refresh.current_entry()?;
            let request = models_fetch::refresh_provider_request_async_with_store(
                &refresh.provider_id,
                &entry,
                refresh.store.clone(),
                |name| std::env::var(name).ok(),
                request_generation,
            )
            .await?;
            if let Some(request) = request {
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
                self.request(&body, &request.base_url, &request.headers)
                    .send()
                    .await
                    .context("retrying embeddings request after credential refresh")?
            } else {
                response
            }
        } else {
            response
        };
        let status = response.status();
        let text = response
            .text()
            .await
            .context("reading embeddings response")?;
        let diagnostic = self.guard().scrub(&text);
        if !status.is_success() {
            anyhow::bail!(
                "embeddings request returned {status}: {}",
                snippet(&diagnostic)
            );
        }
        let parsed: EmbeddingsResponse = serde_json::from_str(&text)
            .with_context(|| format!("parsing embeddings response: {}", snippet(&diagnostic)))?;
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
    }

    fn identity(&self) -> String {
        format!("openai-compatible:{}:{}", self.base_url, self.model)
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
        format!("{}…", &compact[..MAX])
    } else {
        compact
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const SECRET: &str = "sk-embed-secret-token-abc123";
    const PLACEHOLDER: &str = "[embed-redacted]";

    #[derive(Debug, Clone)]
    struct CapturedEmbeddingRequest {
        head: String,
        body: String,
    }

    async fn capture_embedding_server_with_response(
        response_body: &'static str,
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
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        (format!("http://{addr}/v1"), rx)
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

    fn guard(trusted: bool) -> OutboundGuard {
        let redact = if trusted {
            Arc::new(RedactionTable::empty())
        } else {
            secret_table()
        };
        OutboundGuard::new(redact)
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
    }

    /// AC4, embeddings send boundary. The embedding path is a potentially
    /// sensitive caller — it ships user text to a provider — so it may not
    /// pick raw-vs-redacted by reading a trust flag. It routes custody through
    /// the typed request API and takes the raw table only from the grant that
    /// route mints.
    ///
    /// Custody here is host-owned: the *configured* embedding model fixes the
    /// class and no caller may ask for `Trusted`. What this pins is the
    /// outcome on the wire, built through the production constructor
    /// [`OpenAiCompatEmbedder::for_provider_entry`]: an untrusted (cloud)
    /// endpoint receives the placeholder, a trusted (self-hosted / no-log)
    /// endpoint receives the value — and neither changes with harness posture.
    #[tokio::test]
    async fn embedding_send_boundary_routes_custody_before_the_wire() {
        use crate::config::providers::{ModelEntry, ModelTrust, ProviderEntry, ProvidersConfig};

        for (trust, raw_expected) in [(ModelTrust::Trusted, true), (ModelTrust::Untrusted, false)] {
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
            if raw_expected {
                assert!(
                    captured.body.contains(SECRET),
                    "{trust:?}: a trusted embedding endpoint keeps raw custody: {}",
                    captured.body
                );
            } else {
                assert!(
                    !captured.body.contains(SECRET),
                    "{trust:?}: an untrusted embedding endpoint must never receive the secret: {}",
                    captured.body
                );
                assert!(
                    captured.body.contains(PLACEHOLDER),
                    "{trust:?}: the redacted rendering must have reached the wire: {}",
                    captured.body
                );
            }
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
        );

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
        );

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
        );

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
    async fn embed_trusted_provider_skips_redaction() {
        let (base_url, capture_rx) = capture_embedding_server_with_response(
            r#"{"data":[{"index":0,"embedding":[1.0,2.0,3.0]}]}"#,
        )
        .await;
        let embedder = embedder(base_url, guard(true));
        let input = format!("trusted {SECRET}");

        let _ = embedder.embed(&[input.as_str()]).await.unwrap();

        let raw = capture_rx.await.unwrap().body;
        assert!(
            raw.contains(SECRET),
            "trusted provider should see original text: {raw}"
        );
        assert!(
            !raw.contains(PLACEHOLDER),
            "trusted provider should skip redaction: {raw}"
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
        );

        let guard = embedder
            .guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _: &OutboundGuard = &guard;
    }
}
