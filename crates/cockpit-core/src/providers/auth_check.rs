//! Reusable provider credential checks for setup and diagnostics.

use std::time::Duration;

use anyhow::Context;
use reqwest::StatusCode;
use serde_json::json;

use crate::config::providers::{ModelEntry, ProviderEntry, ProviderModelCatalog};
use crate::providers::models_fetch::{self, FetchOutcome, ResolvedHeader};
use crate::providers::{AuthCheckKind, ProviderTemplate};

#[derive(Debug)]
pub enum AuthCheckSuccess {
    Models {
        models: Vec<ModelEntry>,
        catalog: ProviderModelCatalog,
    },
    Checked,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthCheckError {
    #[error("{0}")]
    CredentialsRejected(String),
    #[error("{0}")]
    Network(String),
    #[error("{0}")]
    Other(String),
}

pub async fn check_provider_auth(
    provider_id: &str,
    entry: &ProviderEntry,
    template: &ProviderTemplate,
    timeout: Duration,
) -> Result<AuthCheckSuccess, AuthCheckError> {
    let resolved = models_fetch::resolve_provider_request_async(provider_id, entry)
        .await
        .map_err(|error| AuthCheckError::Other(error.to_string()))?;
    match template.auth_check {
        AuthCheckKind::ModelsEndpoint => {
            let outcome =
                models_fetch::fetch_models_for_provider(provider_id, entry, &resolved, timeout)
                    .await
                    .map_err(classify_error)?;
            match outcome {
                FetchOutcome::Models { models, catalog }
                | FetchOutcome::FallbackAvailable {
                    models, catalog, ..
                } => Ok(AuthCheckSuccess::Models { models, catalog }),
                FetchOutcome::Unsupported => Ok(AuthCheckSuccess::Checked),
            }
        }
        AuthCheckKind::ChatCompletions { path, model, .. } => {
            post_chat_completion_probe(&resolved.base_url, &resolved.headers, path, model, timeout)
                .await
        }
    }
}

async fn post_chat_completion_probe(
    base_url: &str,
    headers: &[ResolvedHeader],
    path: &str,
    model: &str,
    timeout: Duration,
) -> Result<AuthCheckSuccess, AuthCheckError> {
    let url = format!(
        "{}{}",
        base_url.trim_end_matches('/'),
        if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        }
    );
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|error| AuthCheckError::Other(error.to_string()))?;
    let user_agent = headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("user-agent"))
        .map(|header| header.value.clone())
        .unwrap_or_else(|| crate::user_agent::user_agent().to_string());
    let mut request = client
        .post(&url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::USER_AGENT, user_agent)
        .json(&json!({
            "model": model,
            "messages": [{ "role": "user", "content": "ping" }],
            "max_tokens": 1,
            "stream": false
        }));
    for header in headers {
        if header.name.eq_ignore_ascii_case("user-agent") {
            continue;
        }
        request = request.header(&header.name, &header.value);
    }
    let response = request
        .send()
        .await
        .with_context(|| format!("POST {url}"))
        .map_err(classify_error)?;
    let status = response.status();
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return Err(AuthCheckError::CredentialsRejected(format!(
            "{url} returned {status} — credentials rejected. Verify the API key, OAuth login, and headers."
        )));
    }
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(AuthCheckError::Other(format!(
            "{url} returned {status}: {}",
            response_body_snippet(&body)
        )));
    }
    Ok(AuthCheckSuccess::Checked)
}

fn classify_error(error: anyhow::Error) -> AuthCheckError {
    let message = error.to_string();
    if message.contains("returned 401") || message.contains("returned 403") {
        return AuthCheckError::CredentialsRejected(message);
    }
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<reqwest::Error>()
            .is_some_and(|reqwest| reqwest.is_connect() || reqwest.is_timeout())
    }) {
        return AuthCheckError::Network(message);
    }
    AuthCheckError::Other(message)
}

fn response_body_snippet(body: &str) -> String {
    const MAX: usize = 256;
    let mut snippet = body.chars().take(MAX).collect::<String>();
    if body.chars().count() > MAX {
        snippet.push_str("...");
    }
    format!("body_bytes={} body_prefix={snippet:?}", body.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::{AuthKind, HeaderSpec, ProviderEntry, WireApi};

    async fn one_shot_server(status: StatusCode, body: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut buf = vec![0; 4096];
            let _ = stream.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("OK"),
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });
        format!("http://{addr}/v1")
    }

    fn test_entry(base_url: String) -> ProviderEntry {
        ProviderEntry {
            url: base_url,
            headers: vec![HeaderSpec {
                name: "Authorization".into(),
                value: "Bearer sk-test".into(),
            }],
            ..ProviderEntry::default()
        }
    }

    fn z_ai_template() -> ProviderTemplate {
        ProviderTemplate {
            id: "z-ai",
            display: "z.ai",
            url: "https://api.z.ai/api/paas/v4",
            auth: AuthKind::ApiKey,
            default_env_var: Some("Z_AI_API_KEY"),
            env_var_candidates: &[],
            default_headers: &[("Authorization", "Bearer $Z_AI_API_KEY")],
            supports_models_endpoint: false,
            hint: None,
            use_id_as_default: true,
            default_wire_api: WireApi::Auto,
            api_key: Some(crate::providers::ApiKeyTemplate {
                header_name: "Authorization",
                value_template: "Bearer {key}",
                format_hint: "Z.AI key",
                console_url: "https://z.ai/manage-apikey/apikey-list",
            }),
            auth_check: AuthCheckKind::ChatCompletions {
                path: "/chat/completions",
                model: "glm-5.1",
                docs_url: "https://docs.z.ai/api-reference/llm/chat-completion",
            },
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_key_models_success() {
        let base = one_shot_server(StatusCode::OK, r#"{"data":[{"id":"gpt-test"}]}"#).await;
        let entry = test_entry(base);
        let template = crate::providers::template_by_id("openai").expect("openai template");

        let result = check_provider_auth("openai", &entry, template, Duration::from_secs(2)).await;

        let AuthCheckSuccess::Models { models, .. } = result.expect("auth check succeeds") else {
            panic!("models endpoint should return models");
        };
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].id, "gpt-test");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_key_models_rejected() {
        let base = one_shot_server(StatusCode::UNAUTHORIZED, r#"{"error":"bad key"}"#).await;
        let entry = test_entry(base);
        let template = crate::providers::template_by_id("openai").expect("openai template");

        let error = check_provider_auth("openai", &entry, template, Duration::from_secs(2))
            .await
            .unwrap_err();

        assert!(matches!(error, AuthCheckError::CredentialsRejected(_)));
        assert!(error.to_string().contains("credentials rejected"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_key_auth_check_no_models_endpoint() {
        let base = one_shot_server(
            StatusCode::OK,
            r#"{"choices":[{"message":{"content":"ok"}}]}"#,
        )
        .await;
        let entry = test_entry(base);

        let result =
            check_provider_auth("z-ai", &entry, &z_ai_template(), Duration::from_secs(2)).await;

        assert!(matches!(result, Ok(AuthCheckSuccess::Checked)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_key_network_error_distinct() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind unused port");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        let entry = test_entry(format!("http://{addr}/v1"));

        let error =
            check_provider_auth("z-ai", &entry, &z_ai_template(), Duration::from_millis(200))
                .await
                .unwrap_err();

        assert!(matches!(error, AuthCheckError::Network(_)), "{error:?}");
    }
}
