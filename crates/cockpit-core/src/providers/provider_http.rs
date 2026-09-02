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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
