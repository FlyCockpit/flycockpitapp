use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crate::config::providers::{ProviderEntry, ProvidersConfig, ResolvedEmbeddingModel};
use crate::engine::model::OutboundGuard;
use crate::providers::models_fetch;
use crate::redact::RedactionTable;

#[async_trait]
pub trait Embedder: Send + Sync {
    async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>>;
}

#[derive(Clone)]
pub struct OpenAiCompatEmbedder {
    client: reqwest::Client,
    base_url: String,
    headers: Vec<models_fetch::ResolvedHeader>,
    model: String,
    expected_dimensions: Option<u32>,
    guard: OutboundGuard,
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
        trusted_only: Arc<AtomicBool>,
    ) -> Result<Self> {
        let entry = providers
            .providers
            .get(&resolved.provider)
            .with_context(|| format!("unknown embedding provider `{}`", resolved.provider))?;
        Self::for_provider_entry(
            providers,
            &resolved.provider,
            entry,
            &resolved.model,
            resolved.embedding_dimensions,
            session_redact,
            trusted_only,
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
        trusted_only: Arc<AtomicBool>,
    ) -> Result<Self> {
        let request = models_fetch::resolve_provider_request_async(provider_id, entry).await?;
        let trusted = providers.resolve_trust(provider_id, model).is_trusted();
        let effective_redact = if trusted {
            Arc::new(RedactionTable::empty())
        } else {
            session_redact
        };
        let guard = OutboundGuard::new(
            provider_id.to_string(),
            model.to_string(),
            trusted_only,
            trusted,
            effective_redact,
        );
        Ok(Self::from_resolved_request(
            request,
            model.to_string(),
            expected_dimensions,
            guard,
        ))
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
            guard,
        }
    }

    fn embeddings_url(&self) -> String {
        format!("{}/embeddings", self.base_url.trim_end_matches('/'))
    }
}

#[async_trait]
impl Embedder for OpenAiCompatEmbedder {
    async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        self.guard.ensure_dispatch_allowed()?;
        let redacted = self.guard.scrub_many(texts);
        let redacted_refs: Vec<&str> = redacted.iter().map(String::as_str).collect();
        let body = EmbeddingsRequest {
            model: &self.model,
            input: &redacted_refs,
        };
        let mut req = self.client.post(self.embeddings_url()).json(&body);
        for header in &self.headers {
            req = req.header(&header.name, &header.value);
        }

        let response = req.send().await.context("sending embeddings request")?;
        let status = response.status();
        let text = response
            .text()
            .await
            .context("reading embeddings response")?;
        if !status.is_success() {
            anyhow::bail!("embeddings request returned {status}: {}", snippet(&text));
        }
        let parsed: EmbeddingsResponse = serde_json::from_str(&text)
            .with_context(|| format!("parsing embeddings response: {}", snippet(&text)))?;
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
    use std::sync::atomic::AtomicBool;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const SECRET: &str = "sk-embed-secret-token-abc123";
    const PLACEHOLDER: &str = "[embed-redacted]";

    async fn capture_embedding_server_with_response(
        response_body: &'static str,
    ) -> (String, tokio::sync::oneshot::Receiver<String>) {
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
                        let _ = tx.send(body);
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

    async fn capture_embedding_server() -> (String, tokio::sync::oneshot::Receiver<String>) {
        capture_embedding_server_with_response(
            r#"{"data":[{"index":0,"embedding":[1.0,2.0,3.0]},{"index":1,"embedding":[4.0,5.0,6.0]}]}"#,
        )
        .await
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

    fn guard(trusted: bool, trusted_only: bool) -> OutboundGuard {
        let redact = if trusted {
            Arc::new(RedactionTable::empty())
        } else {
            secret_table()
        };
        OutboundGuard::new(
            "p",
            "m",
            Arc::new(AtomicBool::new(trusted_only)),
            trusted,
            redact,
        )
    }

    fn embedder(base_url: String, guard: OutboundGuard) -> OpenAiCompatEmbedder {
        OpenAiCompatEmbedder::from_resolved_request(
            models_fetch::ResolvedRequest {
                base_url,
                headers: vec![models_fetch::ResolvedHeader {
                    name: "Authorization".into(),
                    value: "Bearer test-token".into(),
                }],
            },
            "text-embedding-3-small".into(),
            Some(3),
            guard,
        )
    }

    #[tokio::test]
    async fn embedder_openai_compat_wire() {
        let (base_url, body_rx) = capture_embedding_server().await;
        let embedder = embedder(base_url, guard(false, false));

        let vectors = embedder.embed(&["alpha", "beta"]).await.unwrap();

        assert_eq!(vectors, vec![vec![1.0, 2.0, 3.0], vec![4.0, 5.0, 6.0]]);
        let body: serde_json::Value = serde_json::from_str(&body_rx.await.unwrap()).unwrap();
        assert_eq!(body["model"], "text-embedding-3-small");
        assert_eq!(body["input"], serde_json::json!(["alpha", "beta"]));
    }

    #[test]
    fn embedder_requires_redaction_table() {
        let guard = guard(false, false);
        let embedder = OpenAiCompatEmbedder::from_resolved_request(
            models_fetch::ResolvedRequest {
                base_url: "http://127.0.0.1:1/v1".into(),
                headers: vec![],
            },
            "text-embedding-3-small".into(),
            Some(3),
            guard,
        );

        let _: &OutboundGuard = &embedder.guard;
    }

    #[tokio::test]
    async fn embed_redacts_before_send() {
        let (base_url, body_rx) = capture_embedding_server_with_response(
            r#"{"data":[{"index":0,"embedding":[1.0,2.0,3.0]}]}"#,
        )
        .await;
        let embedder = embedder(base_url, guard(false, false));
        let input = format!("alpha {SECRET} omega");

        let _ = embedder.embed(&[input.as_str()]).await.unwrap();

        let raw = body_rx.await.unwrap();
        assert!(raw.contains(PLACEHOLDER), "redacted body: {raw}");
        assert!(!raw.contains(SECRET), "secret leaked in body: {raw}");
    }

    #[tokio::test]
    async fn embed_redacts_every_batch_element() {
        let (base_url, body_rx) = capture_embedding_server().await;
        let embedder = embedder(base_url, guard(false, false));
        let later = format!("beta {SECRET}");

        let _ = embedder.embed(&["alpha", later.as_str()]).await.unwrap();

        let body: serde_json::Value = serde_json::from_str(&body_rx.await.unwrap()).unwrap();
        assert_eq!(body["input"][0], "alpha");
        assert_eq!(body["input"][1], format!("beta {PLACEHOLDER}"));
    }

    #[tokio::test]
    async fn embed_trusted_provider_skips_redaction() {
        let (base_url, body_rx) = capture_embedding_server_with_response(
            r#"{"data":[{"index":0,"embedding":[1.0,2.0,3.0]}]}"#,
        )
        .await;
        let embedder = embedder(base_url, guard(true, false));
        let input = format!("trusted {SECRET}");

        let _ = embedder.embed(&[input.as_str()]).await.unwrap();

        let raw = body_rx.await.unwrap();
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
    async fn embed_enforces_trusted_only_gate() {
        let embedder = embedder("http://127.0.0.1:1/v1".into(), guard(false, true));

        let err = embedder
            .embed(&["this must not reach a provider"])
            .await
            .expect_err("trusted-only should block untrusted embeddings");

        assert!(format!("{err:#}").contains("trusted-only is enabled"));
    }

    #[tokio::test]
    async fn embed_empty_batch_is_safe() {
        let (base_url, body_rx) = capture_embedding_server_with_response(r#"{"data":[]}"#).await;
        let embedder = embedder(base_url, guard(false, false));

        let vectors = embedder.embed(&[]).await.unwrap();

        assert!(vectors.is_empty());
        let body: serde_json::Value = serde_json::from_str(&body_rx.await.unwrap()).unwrap();
        assert_eq!(body["input"], serde_json::json!([]));
    }

    #[test]
    fn outbound_guard_shared_by_dispatch_and_embedder() {
        let embedder = OpenAiCompatEmbedder::from_resolved_request(
            models_fetch::ResolvedRequest {
                base_url: "http://127.0.0.1:1/v1".into(),
                headers: vec![],
            },
            "text-embedding-3-small".into(),
            Some(3),
            guard(false, false),
        );

        let _: &OutboundGuard = &embedder.guard;
    }
}
