use std::fmt;
use std::pin::Pin;
use std::time::Duration;

use futures::StreamExt;
use rig::providers::{anthropic, chatgpt, openai};

use super::wire::{normalize_openai_usage_aliases_bytes, take_normalized_sse_lines};

const PROVIDER_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// `openai::Client` is rig's *Responses API* client (POSTs `/responses`).
// Every OpenAI-compatible provider in `src/providers/mod.rs` (z.ai,
// MiniMax, OpenCode Zen, generic openai-compatible, Ollama) speaks the
// *Chat Completions* API — `/chat/completions`. We have to construct
// the `CompletionsClient` variant instead, or every non-OpenAI-proper
// endpoint 404s on the wrong path.
pub(super) type OpenAiCompatClient = openai::CompletionsClient<UsageAliasHttpClient>;
pub(super) type ChatGptResponsesModel = chatgpt::ResponsesCompletionModel<UsageAliasHttpClient>;
pub(super) type AnthropicCompletionModel =
    anthropic::completion::CompletionModel<UsageAliasHttpClient>;

#[derive(Clone)]
pub struct UsageAliasHttpClient {
    client: reqwest::Client,
    extra_headers: Vec<(String, String)>,
}

impl Default for UsageAliasHttpClient {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl fmt::Debug for UsageAliasHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UsageAliasHttpClient")
            .field("extra_headers", &self.extra_headers.len())
            .finish()
    }
}

impl UsageAliasHttpClient {
    pub(super) fn new(extra_headers: Vec<(String, String)>) -> Self {
        let extra_headers = with_canonical_user_agent(extra_headers);
        let client = reqwest::Client::builder()
            .connect_timeout(PROVIDER_CONNECT_TIMEOUT)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            extra_headers,
        }
    }
}

fn with_canonical_user_agent(mut headers: Vec<(String, String)>) -> Vec<(String, String)> {
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(reqwest::header::USER_AGENT.as_str()))
    {
        headers.push((
            reqwest::header::USER_AGENT.as_str().to_string(),
            crate::user_agent::user_agent().to_string(),
        ));
    }
    headers
}

fn apply_extra_headers<T>(
    req: rig::http_client::Request<T>,
    headers: &[(String, String)],
) -> rig::http_client::Request<T> {
    let (mut parts, body) = req.into_parts();
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) {
            parts.headers.insert(name, value);
        }
    }
    rig::http_client::Request::from_parts(parts, body)
}

impl rig::http_client::HttpClientExt for UsageAliasHttpClient {
    fn send<T, U>(
        &self,
        req: rig::http_client::Request<T>,
    ) -> impl std::future::Future<
        Output = rig::http_client::Result<
            rig::http_client::Response<rig::http_client::LazyBody<U>>,
        >,
    > + Send
    + 'static
    where
        T: Into<bytes::Bytes>,
        T: Send,
        U: From<bytes::Bytes>,
        U: Send + 'static,
    {
        let client = self.client.clone();
        let req = apply_extra_headers(req, &self.extra_headers);
        let (parts, body) = req.into_parts();
        let req = rig::http_client::Request::from_parts(parts, body.into());
        async move {
            let response = client.send::<bytes::Bytes, bytes::Bytes>(req).await?;
            let (parts, body) = response.into_parts();
            let body: rig::http_client::LazyBody<U> = Box::pin(async move {
                let bytes = body.await?;
                Ok(U::from(normalize_openai_usage_aliases_bytes(bytes)))
            });
            Ok(rig::http_client::Response::from_parts(parts, body))
        }
    }

    fn send_multipart<U>(
        &self,
        req: rig::http_client::Request<rig::http_client::MultipartForm>,
    ) -> impl std::future::Future<
        Output = rig::http_client::Result<
            rig::http_client::Response<rig::http_client::LazyBody<U>>,
        >,
    > + Send
    + 'static
    where
        U: From<bytes::Bytes>,
        U: Send + 'static,
    {
        self.client
            .send_multipart(apply_extra_headers(req, &self.extra_headers))
    }

    fn send_streaming<T>(
        &self,
        req: rig::http_client::Request<T>,
    ) -> impl std::future::Future<
        Output = rig::http_client::Result<rig::http_client::StreamingResponse>,
    > + Send
    where
        T: Into<bytes::Bytes> + Send,
    {
        let client = self.client.clone();
        let req = apply_extra_headers(req, &self.extra_headers);
        let (parts, body) = req.into_parts();
        let req = rig::http_client::Request::from_parts(parts, body.into());
        async move {
            let response = client.send_streaming(req).await?;
            let (parts, body) = response.into_parts();
            let stream: Pin<
                Box<
                    dyn rig::wasm_compat::WasmCompatSendStream<
                            InnerItem = rig::http_client::Result<bytes::Bytes>,
                        >,
                >,
            > = Box::pin(futures::stream::unfold(
                (body, Vec::<u8>::new()),
                |(mut body, mut pending)| async move {
                    loop {
                        let normalized = take_normalized_sse_lines(&mut pending, false);
                        if !normalized.is_empty() {
                            return Some((Ok(normalized), (body, pending)));
                        }
                        match body.next().await {
                            Some(Ok(bytes)) => pending.extend_from_slice(&bytes),
                            Some(Err(e)) => return Some((Err(e), (body, pending))),
                            None => {
                                let normalized = take_normalized_sse_lines(&mut pending, true);
                                return (!normalized.is_empty())
                                    .then_some((Ok(normalized), (body, pending)));
                            }
                        }
                    }
                },
            ));
            Ok(rig::http_client::Response::from_parts(parts, stream))
        }
    }
}
