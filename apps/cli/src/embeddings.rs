use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::config::providers::{ProviderEntry, ProvidersConfig, ResolvedEmbeddingModel};
use crate::providers::models_fetch;

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
}

impl OpenAiCompatEmbedder {
    pub async fn for_resolved_model(
        providers: &ProvidersConfig,
        resolved: &ResolvedEmbeddingModel,
    ) -> Result<Self> {
        let entry = providers
            .providers
            .get(&resolved.provider)
            .with_context(|| format!("unknown embedding provider `{}`", resolved.provider))?;
        Self::for_provider_entry(
            &resolved.provider,
            entry,
            &resolved.model,
            resolved.embedding_dimensions,
        )
        .await
    }

    pub async fn for_provider_entry(
        provider_id: &str,
        entry: &ProviderEntry,
        model: &str,
        expected_dimensions: Option<u32>,
    ) -> Result<Self> {
        let request = models_fetch::resolve_provider_request_async(provider_id, entry).await?;
        Ok(Self::from_resolved_request(
            request,
            model.to_string(),
            expected_dimensions,
        ))
    }

    pub fn from_resolved_request(
        request: models_fetch::ResolvedRequest,
        model: String,
        expected_dimensions: Option<u32>,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: request.base_url,
            headers: request.headers,
            model,
            expected_dimensions,
        }
    }

    fn embeddings_url(&self) -> String {
        format!("{}/embeddings", self.base_url.trim_end_matches('/'))
    }
}

#[async_trait]
impl Embedder for OpenAiCompatEmbedder {
    async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        let body = EmbeddingsRequest {
            model: &self.model,
            input: texts,
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn capture_embedding_server() -> (String, tokio::sync::oneshot::Receiver<String>) {
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
            let body = r#"{"data":[{"index":0,"embedding":[1.0,2.0,3.0]},{"index":1,"embedding":[4.0,5.0,6.0]}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        (format!("http://{addr}/v1"), rx)
    }

    fn find_header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n")
    }

    #[tokio::test]
    async fn embedder_openai_compat_wire() {
        let (base_url, body_rx) = capture_embedding_server().await;
        let embedder = OpenAiCompatEmbedder::from_resolved_request(
            models_fetch::ResolvedRequest {
                base_url,
                headers: vec![models_fetch::ResolvedHeader {
                    name: "Authorization".into(),
                    value: "Bearer test-token".into(),
                }],
            },
            "text-embedding-3-small".into(),
            Some(3),
        );

        let vectors = embedder.embed(&["alpha", "beta"]).await.unwrap();

        assert_eq!(vectors, vec![vec![1.0, 2.0, 3.0], vec![4.0, 5.0, 6.0]]);
        let body: serde_json::Value = serde_json::from_str(&body_rx.await.unwrap()).unwrap();
        assert_eq!(body["model"], "text-embedding-3-small");
        assert_eq!(body["input"], serde_json::json!(["alpha", "beta"]));
    }
}
