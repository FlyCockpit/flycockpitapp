use std::error::Error as _;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::Url;

const MAX_REDIRECTS: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpTimeouts {
    pub connect: Duration,
    pub request: Duration,
}

impl McpTimeouts {
    pub fn from_secs(connect_timeout_secs: u64, timeout_secs: u64) -> Self {
        Self {
            connect: Duration::from_secs(connect_timeout_secs),
            request: Duration::from_secs(timeout_secs),
        }
    }
}

pub fn client(timeouts: McpTimeouts, endpoint: &str) -> Result<reqwest::Client> {
    let endpoint = validate_remote_endpoint(endpoint)?;
    let redirect_origin = endpoint.clone();
    reqwest::Client::builder()
        .connect_timeout(timeouts.connect)
        .timeout(timeouts.request)
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            let target = attempt.url().clone();
            if attempt.previous().len() >= MAX_REDIRECTS {
                return attempt.error(std::io::Error::other(format!(
                    "MCP redirect chain exceeded {MAX_REDIRECTS} redirects before {target}"
                )));
            }
            if !same_origin(&redirect_origin, &target) {
                return attempt.error(std::io::Error::other(format!(
                    "refusing MCP redirect to different origin or scheme: {target}"
                )));
            }
            attempt.follow()
        }))
        .build()
        .context("building MCP HTTP client")
}

pub(crate) fn validate_remote_endpoint(endpoint: &str) -> Result<Url> {
    let url = Url::parse(endpoint).with_context(|| format!("invalid MCP endpoint `{endpoint}`"))?;
    match url.scheme() {
        "https" => Ok(url),
        "http" if is_loopback(&url) => Ok(url),
        "http" => bail!(
            "refusing plaintext MCP endpoint `{url}`; use HTTPS (HTTP is allowed only for localhost, 127.0.0.1, or [::1])"
        ),
        scheme => bail!("unsupported MCP endpoint scheme `{scheme}` for `{url}`; use HTTPS"),
    }
}

fn is_loopback(url: &Url) -> bool {
    matches!(
        url.host_str(),
        Some("localhost") | Some("127.0.0.1") | Some("::1") | Some("[::1]")
    )
}

pub(crate) fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

pub fn timeout_error(label: &str, error: reqwest::Error) -> anyhow::Error {
    if error.is_timeout() {
        anyhow::anyhow!("{label} timed out")
    } else {
        anyhow::anyhow!(
            "{label}: {}",
            error
                .source()
                .map(ToString::to_string)
                .unwrap_or_else(|| error.to_string())
        )
    }
}

pub async fn with_request_timeout<T, F>(label: &str, timeouts: McpTimeouts, fut: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    match tokio::time::timeout(timeouts.request, fut).await {
        Ok(result) => result,
        Err(_) => bail!("{label} timed out"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_remote_endpoint_is_refused() {
        let err = validate_remote_endpoint("http://example.com/mcp").unwrap_err();
        assert!(format!("{err:?}").contains("HTTPS"));
    }

    #[test]
    fn loopback_plaintext_is_permitted() {
        for endpoint in [
            "http://127.0.0.1/mcp",
            "http://[::1]/mcp",
            "http://localhost/mcp",
        ] {
            assert!(validate_remote_endpoint(endpoint).is_ok(), "{endpoint}");
        }
    }

    #[test]
    fn port_change_is_cross_origin() {
        let base = Url::parse("https://example.com:443/mcp").unwrap();
        let redirected = Url::parse("https://example.com:8443/mcp").unwrap();
        assert!(!same_origin(&base, &redirected));
    }

    #[test]
    fn scheme_downgrade_is_cross_origin() {
        let base = Url::parse("https://example.com/mcp").unwrap();
        let redirected = Url::parse("http://example.com/mcp").unwrap();
        assert!(!same_origin(&base, &redirected));
    }
}

#[cfg(test)]
mod redirect_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn read_request(socket: &mut tokio::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buf = [0_u8; 1024];
        loop {
            let count = socket.read(&mut buf).await.unwrap();
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&buf[..count]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }

    async fn redirect_once(location: String) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut socket).await;
            socket
                .write_all(
                    format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
        });
        (endpoint, server)
    }

    #[tokio::test]
    async fn cross_origin_redirect_is_refused() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = format!("http://{}/stolen", target.local_addr().unwrap());
        let (endpoint, source) = redirect_once(destination.clone()).await;
        let err = client(McpTimeouts::from_secs(1, 1), &endpoint)
            .unwrap()
            .post(&endpoint)
            .header("Authorization", "Bearer secret")
            .send()
            .await
            .unwrap_err();
        source.await.unwrap();
        assert!(format!("{err:?}").contains(&destination), "{err:?}");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn scheme_downgrade_redirect_is_refused() {
        let (endpoint, source) = redirect_once("https://127.0.0.1:8443/mcp".to_string()).await;
        let err = client(McpTimeouts::from_secs(1, 1), &endpoint)
            .unwrap()
            .get(&endpoint)
            .send()
            .await
            .unwrap_err();
        source.await.unwrap();
        assert!(
            format!("{err:?}").contains("https://127.0.0.1:8443/mcp"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn port_change_is_cross_origin() {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = format!("http://{}/other", target.local_addr().unwrap());
        let (endpoint, source) = redirect_once(destination.clone()).await;
        let err = client(McpTimeouts::from_secs(1, 1), &endpoint)
            .unwrap()
            .get(&endpoint)
            .send()
            .await
            .unwrap_err();
        source.await.unwrap();
        assert!(format!("{err:?}").contains(&destination), "{err:?}");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn same_origin_redirect_is_followed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
        let destination = format!("{endpoint}/next");
        let server = tokio::spawn(async move {
            for response in [
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: {destination}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                ),
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string(),
            ] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let _ = read_request(&mut socket).await;
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let response = client(McpTimeouts::from_secs(1, 1), &endpoint)
            .unwrap()
            .get(&endpoint)
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn redirect_chain_is_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
        let redirect = endpoint.clone();
        let server = tokio::spawn(async move {
            for _ in 0..MAX_REDIRECTS {
                let (mut socket, _) = listener.accept().await.unwrap();
                let _ = read_request(&mut socket).await;
                socket
                    .write_all(
                        format!("HTTP/1.1 302 Found\r\nLocation: {redirect}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });
        let err = client(McpTimeouts::from_secs(1, 1), &endpoint)
            .unwrap()
            .get(&endpoint)
            .send()
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("exceeded"), "{err:?}");
        server.await.unwrap();
    }
}
