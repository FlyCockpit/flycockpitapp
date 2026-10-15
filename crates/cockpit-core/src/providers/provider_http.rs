//! Shared reqwest policy for provider HTTP calls that attach credentials.
//!
//! Outbound provider clients must not follow redirects or trust ambient proxy
//! configuration while carrying `Authorization` or `x-api-key` headers.

use std::time::Duration;

use anyhow::{Context, Result};

/// Base builder for credentialed provider HTTP: no ambient proxy trust and no
/// redirects. Credential headers must not leave the validated endpoint origin.
pub(crate) fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
}

pub(crate) fn build() -> Result<reqwest::Client> {
    client_builder()
        .build()
        .context("building credentialed provider HTTP client")
}

pub(crate) fn build_with_timeout(timeout: Duration) -> Result<reqwest::Client> {
    client_builder()
        .timeout(timeout)
        .build()
        .context("building credentialed provider HTTP client")
}

/// Charge decoded bytes on every consuming provider path, irrespective of
/// status, transfer encoding, or retry. Status-only callers drop the response.
pub(crate) async fn read_body_limited(response: reqwest::Response, name: &str) -> Result<String> {
    read_body_with_limit(
        response,
        name,
        super::models_fetch::MAX_PROVIDER_RESPONSE_BYTES,
    )
    .await
}

pub(crate) async fn read_body_with_limit(
    mut response: reqwest::Response,
    name: &str,
    limit: usize,
) -> Result<String> {
    if response
        .content_length()
        .is_some_and(|bytes| bytes > limit as u64)
    {
        anyhow::bail!("{name} response body exceeded {limit} byte limit");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("reading provider response body")?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            anyhow::bail!("{name} response body exceeded {limit} byte limit");
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).with_context(|| format!("{name} response body was not valid UTF-8"))
}

tokio::task_local! {
    static DIAGNOSTIC_CREDENTIALS: crate::redact::RedactionTable;
}

/// The daemon supplies its complete owner credential table. Lower transport
/// APIs add the actual outbound literals (including refreshed credentials).
/// FuturesUnordered is polled within this task scope; no child task carries
/// untrusted diagnostics beyond it.
pub(crate) async fn diagnostic_scope<F: std::future::Future>(
    table: crate::redact::RedactionTable,
    work: F,
) -> F::Output {
    DIAGNOSTIC_CREDENTIALS.scope(table.enforced(), work).await
}

/// Config owns the grammar for public protocol metadata. Such literals are
/// not credentials (e.g. MIME types or anthropic-version dates).
pub(crate) fn public_header_literal(name: &str, value: &str) -> bool {
    !value.contains('$')
        && crate::config::providers::is_safe_provider_header_reference(
            &name.to_ascii_lowercase(),
            value,
        )
}

pub(crate) fn authorization_payload(value: &str) -> Option<&str> {
    let (scheme, payload) = value.trim().split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer")
        || scheme.eq_ignore_ascii_case("basic")
        || scheme.eq_ignore_ascii_case("token"))
    .then_some(payload.trim())
    .filter(|payload| !payload.is_empty())
}

/// Include actual outbound credentials before any provider-controlled field is
/// transformed. Directory diagnostics and every inference client constructor
/// use this same boundary, including authorization payloads and private headers.
pub(crate) fn with_diagnostic_credentials(
    mut table: crate::redact::RedactionTable,
    headers: &[super::models_fetch::ResolvedHeader],
) -> Result<crate::redact::RedactionTable> {
    for header in headers {
        if public_header_literal(&header.name, &header.value) {
            continue;
        }
        // Native clients normalize surrounding HTTP whitespace on credential
        // fields such as x-api-key/account-id. Cover both actual forms.
        for value in std::iter::once(header.value.as_str())
            .chain((header.value.trim() != header.value).then_some(header.value.trim()))
            .chain(authorization_payload(&header.value))
        {
            if value.is_empty() {
                continue;
            }
            if value.len() < crate::redact::MIN_REDACTION_ENTRY_LENGTH {
                anyhow::bail!(
                    "provider request credential is below the safe diagnostic coverage length"
                );
            }
            table = table
                .with_forced_literal(
                    value.to_string(),
                    "$secret:provider request credential".into(),
                )
                .map_err(|_| anyhow::anyhow!("provider request credential coverage unavailable"))?;
        }
    }
    Ok(table)
}

fn scrub_diagnostic_value(value: &mut serde_json::Value, table: &crate::redact::RedactionTable) {
    match value {
        serde_json::Value::String(text) => {
            if let Ok(mut inner) = serde_json::from_str::<serde_json::Value>(text)
                && (inner.is_object() || inner.is_array())
            {
                scrub_diagnostic_value(&mut inner, table);
                *text = serde_json::to_string(&inner)
                    .unwrap_or_else(|_| "[provider diagnostic omitted]".into());
            } else {
                *text = table.scrub(text);
            }
        }
        serde_json::Value::Array(items) => items
            .iter_mut()
            .for_each(|v| scrub_diagnostic_value(v, table)),
        serde_json::Value::Object(fields) => {
            let prior = std::mem::take(fields);
            for (key, mut value) in prior {
                scrub_diagnostic_value(&mut value, table);
                fields.insert(table.scrub(&key), value);
            }
        }
        _ => {}
    }
}

/// Scrub decoded successful usage values before compact JSON can escape literals.
pub(crate) fn diagnostic_value(
    value: &mut serde_json::Value,
    headers: &[super::models_fetch::ResolvedHeader],
) -> Result<()> {
    let table = DIAGNOSTIC_CREDENTIALS
        .try_with(Clone::clone)
        .unwrap_or_else(|_| crate::redact::RedactionTable::empty());
    let table = with_diagnostic_credentials(table, headers)?;
    scrub_diagnostic_value(value, &table);
    Ok(())
}

/// Scrub complete decoded fields before callers slice, escape, persist or log
/// provider diagnostics. The table includes every outbound header literal and
/// its authorization payload, including dynamically resolved credentials.
/// Failure to construct the table omits the diagnostic rather than releasing it.
pub(crate) fn diagnostic_body(
    raw: &str,
    headers: &[super::models_fetch::ResolvedHeader],
) -> String {
    let table = DIAGNOSTIC_CREDENTIALS
        .try_with(Clone::clone)
        .unwrap_or_else(|_| crate::redact::RedactionTable::empty());
    diagnostic_body_with_table(raw, headers, table)
}

pub(crate) fn diagnostic_body_with_table(
    raw: &str,
    headers: &[super::models_fetch::ResolvedHeader],
    table: crate::redact::RedactionTable,
) -> String {
    let Ok(table) = with_diagnostic_credentials(table.enforced(), headers) else {
        return "[provider diagnostic omitted]".into();
    };
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(raw) {
        scrub_diagnostic_value(&mut value, &table);
        // A nested encoded envelope (e.g. metadata.raw) is scrubbed again after
        // decoding by the inference projection; discovery never exposes it.
        serde_json::to_string(&value).unwrap_or_else(|_| "[provider diagnostic omitted]".into())
    } else if raw.trim_start().starts_with(['{', '[']) {
        // Malformed JSON has no safely decoded fields. Its escaped literals
        // may not match complete registered credentials, so omit its body.
        "[malformed provider JSON diagnostic omitted]".into()
    } else {
        table.scrub(raw)
    }
}

/// Real finite HTTP bodies for provider transport regressions. Early client
/// rejection may close the socket while the fixture is writing its body.
#[cfg(test)]
pub(crate) async fn serve_test_bodies(
    responses: Vec<(u16, String, bool)>,
) -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        for (status, body, chunked) in responses {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 16384];
            let read = socket.read(&mut request).await.unwrap();
            assert!(read > 0);
            let framing = if chunked {
                "transfer-encoding: chunked".into()
            } else {
                format!("content-length: {}", body.len())
            };
            let headers = format!(
                "HTTP/1.1 {status} Test\r\n{framing}\r\ncontent-type: application/json\r\nretry-after: 0\r\nconnection: close\r\n\r\n"
            );
            if socket.write_all(headers.as_bytes()).await.is_err() {
                continue;
            }
            if chunked {
                for chunk in body.as_bytes().chunks(16384) {
                    if socket
                        .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                        .await
                        .is_err()
                        || socket.write_all(chunk).await.is_err()
                        || socket.write_all(b"\r\n").await.is_err()
                    {
                        break;
                    }
                }
                let _ = socket.write_all(b"0\r\n\r\n").await;
            } else {
                let _ = socket.write_all(body.as_bytes()).await;
            }
        }
    });
    (format!("http://{address}/v1"), task)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn decoded_body_limit_accepts_boundary_and_rejects_declared_and_chunked_overflow() {
        let limit = super::super::models_fetch::MAX_PROVIDER_RESPONSE_BYTES;
        for chunked in [false, true] {
            for size in [limit, limit + 1] {
                let (url, server) = serve_test_bodies(vec![(400, "x".repeat(size), chunked)]).await;
                let response = build_with_timeout(Duration::from_secs(5))
                    .unwrap()
                    .get(url)
                    .send()
                    .await
                    .unwrap();
                let result = read_body_limited(response, "fixture").await;
                if size == limit {
                    assert_eq!(result.unwrap().len(), limit);
                } else {
                    assert!(
                        result
                            .unwrap_err()
                            .to_string()
                            .contains("exceeded 8388608 byte limit")
                    );
                }
                server.await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn decoded_body_limit_times_out_a_slow_body() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let read = socket.read(&mut request).await.unwrap();
            assert!(read > 0);
            socket
                .write_all(b"HTTP/1.1 400 Test\r\ntransfer-encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });
        let response = build_with_timeout(Duration::from_millis(150))
            .unwrap()
            .get(format!("http://{address}"))
            .send()
            .await
            .unwrap();
        let error = read_body_limited(response, "slow").await.unwrap_err();
        assert!(format!("{error:#}").contains("timed out"), "{error:#}");
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn cancelling_decoded_body_read_releases_the_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (started, ready) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let read = socket.read(&mut request).await.unwrap();
            assert!(read > 0);
            socket
                .write_all(b"HTTP/1.1 400 Test\r\ntransfer-encoding: chunked\r\n\r\n1\r\nx\r\n")
                .await
                .unwrap();
            started.send(()).unwrap();
            let mut remaining = [0; 1];
            let eof = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut remaining))
                .await
                .unwrap();
            assert!(
                matches!(eof, Ok(0)) || eof.is_err(),
                "cancelled reader retained its body connection"
            );
        });
        let reader = tokio::spawn(async move {
            let response = build_with_timeout(Duration::from_secs(5))
                .unwrap()
                .get(format!("http://{address}"))
                .send()
                .await
                .unwrap();
            read_body_limited(response, "cancelled").await
        });
        ready.await.unwrap();
        reader.abort();
        assert!(reader.await.unwrap_err().is_cancelled());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn credential_scrub_preserves_public_protocol_literals_and_model_ids() {
        use super::super::models_fetch::{FetchOutcome, ResolvedHeader};
        let headers = vec![
            ResolvedHeader {
                name: "Content-Type".into(),
                value: "application/json".into(),
            },
            ResolvedHeader {
                name: "anthropic-version".into(),
                value: "2023-06-01".into(),
            },
            ResolvedHeader {
                name: "Authorization".into(),
                value: "Bearer known/session-key/+fragment-0042".into(),
            },
        ];
        let body = diagnostic_body(
            "application/json version 2023-06-01 denied known/session-key/+fragment-0042",
            &headers,
        );
        assert!(
            body.contains("application/json version 2023-06-01"),
            "{body}"
        );
        assert!(!body.contains("known/session"), "{body}");
        let (url, server) = serve_test_bodies(vec![(
            200,
            r#"{"data":[{"id":"model-2023-06-01"}]}"#.into(),
            true,
        )])
        .await;
        let outcome =
            super::super::models_fetch::fetch_models(&url, &headers, Duration::from_secs(5))
                .await
                .unwrap();
        let FetchOutcome::Models { models, .. } = outcome else {
            panic!("catalog");
        };
        assert_eq!(models[0].id, "model-2023-06-01");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn credential_scrub_covers_all_supported_authorization_schemes() {
        const SECRET: &str = "known/session-key/+fragment-0042";
        for scheme in ["Bearer", "Basic", "Token", "tOkEn"] {
            let headers = vec![super::super::models_fetch::ResolvedHeader {
                name: "Authorization".into(),
                value: format!("{scheme} {SECRET}"),
            }];
            let body = format!("useful diagnostic {}{SECRET}", "word ".repeat(44));
            let (url, server) = serve_test_bodies(vec![(400, body, true)]).await;
            let error =
                super::super::models_fetch::fetch_models(&url, &headers, Duration::from_secs(5))
                    .await
                    .unwrap_err();
            let shown = error.to_string();
            assert!(!shown.contains("known/session"), "{scheme}: {shown}");
            assert!(shown.contains("useful diagnostic"), "{shown}");
            server.await.unwrap();
        }
    }

    static PROXY_ENV_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            // SAFETY: serialized by `PROXY_ENV_TEST_LOCK` for the test lifetime.
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => {
                    // SAFETY: serialized by `PROXY_ENV_TEST_LOCK` for the test lifetime.
                    unsafe { std::env::set_var(self.key, value) };
                }
                None => {
                    // SAFETY: serialized by `PROXY_ENV_TEST_LOCK` for the test lifetime.
                    unsafe { std::env::remove_var(self.key) };
                }
            }
        }
    }

    fn strip_test_modules(src: &str) -> String {
        let mut out = String::new();
        let mut i = 0;
        let bytes = src.as_bytes();
        while i < src.len() {
            if let Some(rel) = src[i..].find("#[cfg(test)]") {
                out.push_str(&src[i..i + rel]);
                let after = i + rel + "#[cfg(test)]".len();
                if let Some(mod_rel) = src[after..].find('{') {
                    let mut depth = 0;
                    let mut j = after + mod_rel;
                    while j < src.len() {
                        match bytes[j] {
                            b'{' => depth += 1,
                            b'}' => {
                                depth -= 1;
                                if depth == 0 {
                                    j += 1;
                                    break;
                                }
                            }
                            _ => {}
                        }
                        j += 1;
                    }
                    i = j;
                } else {
                    i = after;
                }
                continue;
            }
            out.push_str(&src[i..]);
            break;
        }
        out
    }

    fn collect_rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                let name = path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("");
                if name == "tests" {
                    continue;
                }
                collect_rs_files(&path, out);
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                let name = path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("");
                if !name.contains("ratchet") {
                    out.push(path);
                }
            }
        }
    }

    #[test]
    fn production_reqwest_client_construction_uses_shared_provider_policy() {
        const ALLOWLIST: &[&str] = &[
            "providers/provider_http.rs",
            // TinyFish web tool; issue #295 scopes the five provider clients.
            "tools/web.rs",
            // Public metadata fetches with no attached credentials.
            "packages/resolve.rs",
            "daemon/agent_catalog.rs",
            "daemon/connector.rs",
            // MCP transport uses a custom same-origin redirect policy.
            "mcp/transport/timeout.rs",
            // Inline no_proxy + Policy::none() duplicates kept until a later sweep.
            "media_https.rs",
            "mcp/network.rs",
            "image_generation_runtime.rs",
            "image_generation/http_transport.rs",
            "sealed/action_admin/executor.rs",
        ];
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs_files(&root, &mut files);
        let mut violations = Vec::new();
        for path in files {
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let source = strip_test_modules(&std::fs::read_to_string(&path).unwrap());
            let has_naked = source.contains("reqwest::Client::new()")
                || source.contains("reqwest::Client::builder()");
            if !has_naked {
                continue;
            }
            if ALLOWLIST.contains(&rel.as_str()) {
                continue;
            }
            violations.push(rel);
        }
        assert!(
            violations.is_empty(),
            "credentialed provider HTTP must use provider_http::client_builder(); \
             add provider_http or document an allow-list exemption:\n{}",
            violations.join("\n")
        );
    }

    #[tokio::test]
    async fn credentialed_provider_http_ignores_ambient_proxy() {
        let _lock = PROXY_ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind proxy listener");
        let proxy_addr = proxy_listener.local_addr().expect("proxy local addr");
        let proxy_hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let proxy_hits_task = proxy_hits.clone();
        let proxy_server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = proxy_listener.accept().await.expect("proxy accept");
                proxy_hits_task.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut buf = [0_u8; 4096];
                let _ = socket.read(&mut buf).await;
            }
        });

        let origin_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind origin listener");
        let origin_addr = origin_listener.local_addr().expect("origin local addr");
        let origin_server = tokio::spawn(async move {
            let (mut socket, _) = origin_listener.accept().await.expect("origin accept");
            let mut buf = [0_u8; 4096];
            let read = socket.read(&mut buf).await.expect("read origin request");
            let request = String::from_utf8_lossy(&buf[..read]).into_owned();
            let response = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: application/json\r\n",
                "Content-Length: 2\r\n",
                "Connection: close\r\n\r\n",
                "{}"
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write origin response");
            request
        });

        let _proxy_env = EnvVarGuard::set("HTTP_PROXY", &format!("http://{proxy_addr}"));
        let _https_proxy_env = EnvVarGuard::set("HTTPS_PROXY", &format!("http://{proxy_addr}"));

        let client = build_with_timeout(Duration::from_secs(2)).expect("build client");
        let url = format!("http://{origin_addr}/v1/models");
        let response = client
            .get(&url)
            .header("x-api-key", "leaked-secret")
            .send()
            .await
            .expect("send request");
        assert_eq!(response.status(), reqwest::StatusCode::OK);

        let captured = origin_server.await.expect("origin server task");
        assert!(
            captured
                .to_ascii_lowercase()
                .contains("x-api-key: leaked-secret"),
            "{captured}"
        );
        assert_eq!(
            proxy_hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "ambient proxy must not receive credentialed provider traffic"
        );
        proxy_server.abort();
    }

    #[tokio::test]
    async fn credentialed_provider_http_rejects_cross_origin_redirect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redirect test server");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept request");
            let mut buf = [0_u8; 4096];
            let read = socket.read(&mut buf).await.expect("read request");
            let request = String::from_utf8_lossy(&buf[..read]).into_owned();
            let response = concat!(
                "HTTP/1.1 302 Found\r\n",
                "Location: http://credential-leak.invalid/secret\r\n",
                "Content-Length: 0\r\n",
                "Connection: close\r\n\r\n"
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write redirect");
            request
        });

        let client = build_with_timeout(Duration::from_secs(2)).expect("build client");
        let url = format!("http://{addr}/v1/models");
        let response = client
            .get(&url)
            .header("x-api-key", "leaked-secret")
            .send()
            .await
            .expect("send request");
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);

        let captured = server.await.expect("server task");
        assert!(
            captured
                .to_ascii_lowercase()
                .contains("x-api-key: leaked-secret"),
            "{captured}"
        );
    }
}

#[cfg(test)]
mod credential_floor_tests {
    use super::*;

    #[test]
    fn credential_coverage_below_matcher_floor_fails_closed() {
        let headers = vec![super::super::models_fetch::ResolvedHeader {
            name: "x-api-key".into(),
            value: "abc".into(),
        }];
        assert!(
            with_diagnostic_credentials(crate::redact::RedactionTable::empty(), &headers).is_err()
        );
        assert_eq!(
            diagnostic_body("abc reflected", &headers),
            "[provider diagnostic omitted]"
        );
    }
}
