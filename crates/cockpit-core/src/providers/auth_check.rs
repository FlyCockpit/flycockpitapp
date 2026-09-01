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
    FallbackAvailable {
        models: Vec<ModelEntry>,
        catalog: ProviderModelCatalog,
        reason: String,
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
    check_provider_auth_with_store(provider_id, entry, template, timeout, None).await
}

pub async fn check_provider_auth_with_store(
    provider_id: &str,
    entry: &ProviderEntry,
    template: &ProviderTemplate,
    timeout: Duration,
    store: Option<crate::credentials::CredentialStore>,
) -> Result<AuthCheckSuccess, AuthCheckError> {
    let fetch_store = store.clone();
    let resolved = match store {
        Some(store) => {
            models_fetch::resolve_provider_request_async_with_store(
                provider_id,
                entry,
                store,
                |name| std::env::var(name).ok(),
            )
            .await
        }
        None => models_fetch::resolve_provider_request_async(provider_id, entry).await,
    }
    .map_err(|error| AuthCheckError::Other(error.to_string()))?;
    match template.auth_check {
        AuthCheckKind::ModelsEndpoint => {
            let outcome = models_fetch::fetch_models_for_provider_with_store(
                provider_id,
                entry,
                &resolved,
                timeout,
                fetch_store,
                |name| std::env::var(name).ok(),
            )
            .await
            .map_err(classify_error)?;
            match outcome {
                FetchOutcome::Models { models, catalog } => {
                    Ok(AuthCheckSuccess::Models { models, catalog })
                }
                FetchOutcome::FallbackAvailable {
                    models,
                    catalog,
                    reason,
                } => Ok(AuthCheckSuccess::FallbackAvailable {
                    models,
                    catalog,
                    reason,
                }),
                FetchOutcome::Unsupported => Err(AuthCheckError::Other(
                    "credential validation endpoint is unsupported; no authenticated response was received"
                        .to_string(),
                )),
            }
        }
        AuthCheckKind::ChatCompletions {
            path,
            model,
            docs_url,
        } => {
            let outcome = post_chat_completion_probe(
                &resolved.base_url,
                &resolved.headers,
                path,
                model,
                docs_url,
                timeout,
            )
            .await;
            if matches!(&outcome, Err(AuthCheckError::CredentialsRejected(_)))
                && let Some(store) = fetch_store
            {
                let refreshed = models_fetch::refresh_provider_request_async_with_store(
                    provider_id,
                    entry,
                    store,
                    |name| std::env::var(name).ok(),
                    resolved.command_credential_generation(),
                )
                .await
                .map_err(|error| AuthCheckError::Other(error.to_string()))?;
                if let Some(refreshed) = refreshed {
                    return post_chat_completion_probe(
                        &refreshed.base_url,
                        &refreshed.headers,
                        path,
                        model,
                        docs_url,
                        timeout,
                    )
                    .await;
                }
            }
            outcome
        }
    }
}

async fn post_chat_completion_probe(
    base_url: &str,
    headers: &[ResolvedHeader],
    path: &str,
    model: &str,
    docs_url: &str,
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
        .map_err(|error| classify_chat_error(error, docs_url))?;
    let status = response.status();
    // Drain body without surfacing it — ChatCompletions failures are status +
    // docs_url only (never raw body or key material).
    let _ = response.text().await;
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return Err(AuthCheckError::CredentialsRejected(format!(
            "credentials rejected ({status}). See {docs_url}"
        )));
    }
    if !status.is_success() {
        return Err(AuthCheckError::Other(format!(
            "chat completions check returned {status}. See {docs_url}"
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

fn classify_chat_error(error: anyhow::Error, docs_url: &str) -> AuthCheckError {
    match classify_error(error) {
        AuthCheckError::CredentialsRejected(message) => {
            AuthCheckError::CredentialsRejected(format!("{message}. See {docs_url}"))
        }
        AuthCheckError::Network(message) => {
            AuthCheckError::Network(format!("{message}. See {docs_url}"))
        }
        AuthCheckError::Other(message) => {
            AuthCheckError::Other(format!("{message}. See {docs_url}"))
        }
    }
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
            usage_probe: None,
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
    async fn test_key_models_unsupported_is_not_credential_proof() {
        let base = one_shot_server(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#).await;
        let entry = test_entry(base);
        let template = crate::providers::template_by_id("openai").expect("openai template");

        let error = check_provider_auth("openai", &entry, template, Duration::from_secs(2))
            .await
            .unwrap_err();

        assert!(matches!(error, AuthCheckError::Other(_)));
        assert!(error.to_string().contains("no authenticated response"));
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

    fn chat_templates() -> Vec<&'static ProviderTemplate> {
        crate::providers::TEMPLATES
            .iter()
            .filter(|t| matches!(t.auth_check, AuthCheckKind::ChatCompletions { .. }))
            .collect()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chat_auth_check_failures_are_redacted_and_template_documented() {
        let _env = crate::test_env::lock_async().await;
        const LEAK: &str = "sk-leaked-body-secret";
        const LEAK_BODY: &str = r#"{"error":"sk-leaked-body-secret"}"#;
        for template in chat_templates() {
            let AuthCheckKind::ChatCompletions {
                path,
                model,
                docs_url,
            } = template.auth_check
            else {
                unreachable!();
            };
            assert!(docs_url.starts_with("https://"), "{} docs", template.id);

            // Credentials rejected
            let base = one_shot_server(StatusCode::UNAUTHORIZED, LEAK_BODY).await;
            let entry = test_entry(base);
            let err = check_provider_auth(template.id, &entry, template, Duration::from_secs(2))
                .await
                .unwrap_err();
            let msg = err.to_string();
            assert!(
                matches!(err, AuthCheckError::CredentialsRejected(_)),
                "{}: {err:?}",
                template.id
            );
            assert!(
                msg.contains(docs_url),
                "{} missing docs: {msg}",
                template.id
            );
            assert!(!msg.contains(LEAK), "{} leaked body: {msg}", template.id);
            assert!(
                !msg.contains("Bearer sk-test"),
                "{} leaked key: {msg}",
                template.id
            );

            // Non-success HTTP
            let base = one_shot_server(StatusCode::INTERNAL_SERVER_ERROR, LEAK_BODY).await;
            let entry = test_entry(base);
            let err = check_provider_auth(template.id, &entry, template, Duration::from_secs(2))
                .await
                .unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains(docs_url),
                "{} missing docs: {msg}",
                template.id
            );
            assert!(!msg.contains(LEAK), "{} leaked body: {msg}", template.id);

            // Transport
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().unwrap();
            drop(listener);
            let entry = test_entry(format!("http://{addr}/v1"));
            let err =
                check_provider_auth(template.id, &entry, template, Duration::from_millis(150))
                    .await
                    .unwrap_err();
            assert!(
                matches!(err, AuthCheckError::Network(_)),
                "{} transport: {err:?}",
                template.id
            );
            let tmsg = err.to_string();
            assert!(
                tmsg.contains(docs_url),
                "{} transport missing docs: {tmsg}",
                template.id
            );

            if template.id == "nous-research" {
                assert_eq!(path, "/chat/completions");
                assert_eq!(model, "Hermes-4.3-36B");
                assert_eq!(docs_url, "https://portal.nousresearch.com/api-docs");
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nous_chat_probe_posts_bounded_completions_request() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let _ = tx.send(req);
            let body = r#"{"choices":[{"message":{"content":"ok"}}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });

        let template = crate::providers::template_by_id("nous-research").expect("template");
        let entry = test_entry(format!("http://{addr}/v1"));
        let result =
            check_provider_auth("nous-research", &entry, template, Duration::from_secs(2)).await;
        assert!(matches!(result, Ok(AuthCheckSuccess::Checked)));
        let req = rx.await.expect("request captured");
        assert!(req.starts_with("POST "), "{req}");
        assert!(req.contains("/v1/chat/completions") || req.contains(" /chat/completions"));
        assert!(req.to_ascii_lowercase().contains("authorization: bearer"));
        assert!(req.contains("Hermes-4.3-36B"));
        assert!(req.contains("\"max_tokens\":1") || req.contains("\"max_tokens\": 1"));
        assert!(req.contains("\"stream\":false") || req.contains("\"stream\": false"));
    }
}
