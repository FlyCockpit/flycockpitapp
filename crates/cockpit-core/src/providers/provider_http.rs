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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
