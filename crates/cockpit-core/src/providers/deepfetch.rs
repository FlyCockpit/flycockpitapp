//! User-confirmed live model probes for endpoint and context-window metadata.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use reqwest::StatusCode;
use serde_json::json;

use crate::config::providers::{
    CapabilitySource, ModelEntry, ProvidersConfig, WireApi, is_anthropic_native_base_url,
};
use crate::providers::models_fetch::{ResolvedHeader, ResolvedRequest};

#[cfg(test)]
use crate::config::providers::ProviderEntry;

pub(crate) const CONTEXT_PROBE_MAX_TOKENS: u32 = 100_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeepfetchMode {
    Interactive,
    AssumeYes,
    NonInteractive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeepfetchScope {
    pub provider: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeepfetchPlan {
    pub providers: usize,
    pub models: usize,
    pub endpoint_requests: usize,
    pub context_requests: usize,
}

impl DeepfetchPlan {
    pub fn total_requests(&self) -> usize {
        self.endpoint_requests + self.context_requests
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeepfetchTarget {
    pub provider_id: String,
    pub model_id: String,
    pub explicit_wire_api: WireApi,
    pub inherited_wire_api: WireApi,
    pub direct_model_scope: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeEndpoint {
    Completions,
    Responses,
}

impl ProbeEndpoint {
    pub(crate) fn wire_api(self) -> WireApi {
        match self {
            Self::Completions => WireApi::Completions,
            Self::Responses => WireApi::Responses,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointProbeRequest {
    pub provider_id: String,
    pub model_id: String,
    pub endpoint: ProbeEndpoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextProbeRequest {
    pub provider_id: String,
    pub model_id: String,
    pub endpoint: ProbeEndpoint,
    pub max_tokens: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeHttpError {
    pub status: u16,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeRawOutcome {
    Works,
    HttpError(ProbeHttpError),
    Transport(String),
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointProbeOutcome {
    Works,
    Incompatible,
    Entitlement,
    RateLimited,
    Inconclusive(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextProbeOutcome {
    Oversize { context_tokens: u32 },
    Entitlement,
    RateLimited,
    Inconclusive(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeepfetchApplyReport {
    Applied {
        endpoint: WireApi,
        pinned_wire_api: Option<WireApi>,
        context_tokens: Option<u32>,
        endpoint_note: EndpointSelectionNote,
    },
    BothEndpointsWork {
        endpoint: WireApi,
        context_tokens: Option<u32>,
    },
    ExplicitPinPreserved {
        existing: WireApi,
        probed: WireApi,
    },
    Entitlement {
        endpoint: Option<WireApi>,
    },
    RateLimited {
        endpoint: Option<WireApi>,
    },
    Inconclusive {
        endpoint: Option<WireApi>,
        reason: String,
    },
    SkippedNoEndpointChoice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointSelectionNote {
    Explicit,
    Pinned,
    AutoDetectedAfterBothWorked,
}

pub trait DeepfetchProbeClient {
    fn probe_endpoint<'a>(
        &'a mut self,
        request: EndpointProbeRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ProbeRawOutcome>> + Send + 'a>>;

    fn probe_context<'a>(
        &'a mut self,
        request: ContextProbeRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ProbeRawOutcome>> + Send + 'a>>;
}

pub struct HttpDeepfetchProbeClient {
    resolved: BTreeMap<String, ResolvedRequest>,
    timeout: Duration,
}

impl HttpDeepfetchProbeClient {
    pub fn new(resolved: BTreeMap<String, ResolvedRequest>, timeout: Duration) -> Self {
        Self { resolved, timeout }
    }
}

impl DeepfetchProbeClient for HttpDeepfetchProbeClient {
    fn probe_endpoint<'a>(
        &'a mut self,
        request: EndpointProbeRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ProbeRawOutcome>> + Send + 'a>> {
        Box::pin(async move {
            let resolved = self
                .resolved
                .get(&request.provider_id)
                .ok_or_else(|| anyhow!("provider `{}` was not resolved", request.provider_id))?;
            send_probe(
                &resolved.base_url,
                &resolved.headers,
                request.endpoint,
                &request.model_id,
                1,
                self.timeout,
            )
            .await
        })
    }

    fn probe_context<'a>(
        &'a mut self,
        request: ContextProbeRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ProbeRawOutcome>> + Send + 'a>> {
        Box::pin(async move {
            let resolved = self
                .resolved
                .get(&request.provider_id)
                .ok_or_else(|| anyhow!("provider `{}` was not resolved", request.provider_id))?;
            send_probe(
                &resolved.base_url,
                &resolved.headers,
                request.endpoint,
                &request.model_id,
                request.max_tokens,
                self.timeout,
            )
            .await
        })
    }
}

async fn send_probe(
    base_url: &str,
    headers: &[ResolvedHeader],
    endpoint: ProbeEndpoint,
    model_id: &str,
    max_tokens: u32,
    timeout: Duration,
) -> Result<ProbeRawOutcome> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .context("building deepfetch HTTP client")?;
    let url = match endpoint {
        ProbeEndpoint::Completions => {
            format!("{}/chat/completions", base_url.trim_end_matches('/'))
        }
        ProbeEndpoint::Responses => format!("{}/responses", base_url.trim_end_matches('/')),
    };
    let body = probe_request_body(endpoint, model_id, max_tokens);
    let mut request = client.post(url).json(&body);
    for header in headers {
        request = request.header(&header.name, &header.value);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => return Ok(ProbeRawOutcome::Transport(error.to_string())),
    };
    let status = response.status();
    if status.is_success() {
        return Ok(ProbeRawOutcome::Works);
    }
    if status == StatusCode::TOO_MANY_REQUESTS
        && let Some(delay) = retry_after_delay(response.headers())
    {
        tokio::time::sleep(delay).await;
        return send_probe_once(base_url, headers, endpoint, model_id, max_tokens, timeout).await;
    }
    probe_http_error(response).await
}

async fn send_probe_once(
    base_url: &str,
    headers: &[ResolvedHeader],
    endpoint: ProbeEndpoint,
    model_id: &str,
    max_tokens: u32,
    timeout: Duration,
) -> Result<ProbeRawOutcome> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .context("building deepfetch HTTP client")?;
    let url = match endpoint {
        ProbeEndpoint::Completions => {
            format!("{}/chat/completions", base_url.trim_end_matches('/'))
        }
        ProbeEndpoint::Responses => format!("{}/responses", base_url.trim_end_matches('/')),
    };
    let body = probe_request_body(endpoint, model_id, max_tokens);
    let mut request = client.post(url).json(&body);
    for header in headers {
        request = request.header(&header.name, &header.value);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => return Ok(ProbeRawOutcome::Transport(error.to_string())),
    };
    if response.status().is_success() {
        return Ok(ProbeRawOutcome::Works);
    }
    probe_http_error(response).await
}

async fn probe_http_error(response: reqwest::Response) -> Result<ProbeRawOutcome> {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Ok(ProbeRawOutcome::HttpError(ProbeHttpError {
        status: status.as_u16(),
        body,
    }))
}

fn retry_after_delay(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn probe_request_body(
    endpoint: ProbeEndpoint,
    model_id: &str,
    max_tokens: u32,
) -> serde_json::Value {
    match endpoint {
        ProbeEndpoint::Completions => json!({
            "model": model_id,
            "messages": [{ "role": "user", "content": "hi" }],
            "max_tokens": max_tokens,
            "stream": false
        }),
        ProbeEndpoint::Responses => json!({
            "model": model_id,
            "input": "hi",
            "max_output_tokens": max_tokens,
            "stream": false
        }),
    }
}

pub(crate) fn classify_endpoint_probe(raw: ProbeRawOutcome) -> EndpointProbeOutcome {
    match raw {
        ProbeRawOutcome::Works => EndpointProbeOutcome::Works,
        ProbeRawOutcome::Cancelled => EndpointProbeOutcome::Inconclusive("cancelled".into()),
        ProbeRawOutcome::Transport(error) => EndpointProbeOutcome::Inconclusive(error),
        ProbeRawOutcome::HttpError(error) => match StatusCode::from_u16(error.status) {
            Ok(StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) => {
                EndpointProbeOutcome::Entitlement
            }
            Ok(StatusCode::TOO_MANY_REQUESTS) => EndpointProbeOutcome::RateLimited,
            Ok(StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED) => {
                EndpointProbeOutcome::Incompatible
            }
            _ if crate::engine::model::rig_boundary::is_endpoint_mismatch_error_text(
                &error.body,
            ) =>
            {
                EndpointProbeOutcome::Incompatible
            }
            _ => EndpointProbeOutcome::Inconclusive(error.body),
        },
    }
}

pub(crate) fn classify_context_probe(raw: ProbeRawOutcome) -> ContextProbeOutcome {
    match raw {
        ProbeRawOutcome::Works => ContextProbeOutcome::Inconclusive(
            "oversize context probe unexpectedly succeeded".into(),
        ),
        ProbeRawOutcome::Cancelled => ContextProbeOutcome::Inconclusive("cancelled".into()),
        ProbeRawOutcome::Transport(error) => ContextProbeOutcome::Inconclusive(error),
        ProbeRawOutcome::HttpError(error) => match StatusCode::from_u16(error.status) {
            Ok(StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) => {
                ContextProbeOutcome::Entitlement
            }
            Ok(StatusCode::TOO_MANY_REQUESTS) => ContextProbeOutcome::RateLimited,
            _ => parse_context_limit(&error.body)
                .map(|context_tokens| ContextProbeOutcome::Oversize { context_tokens })
                .unwrap_or_else(|| ContextProbeOutcome::Inconclusive(error.body)),
        },
    }
}

pub(crate) fn choose_probed_wire_api(
    completions: EndpointProbeOutcome,
    responses: EndpointProbeOutcome,
) -> Option<WireApi> {
    match (completions, responses) {
        (EndpointProbeOutcome::Works, EndpointProbeOutcome::Incompatible) => {
            Some(WireApi::Completions)
        }
        (EndpointProbeOutcome::Incompatible, EndpointProbeOutcome::Works) => {
            Some(WireApi::Responses)
        }
        _ => None,
    }
}

pub(crate) fn apply_probed_wire_api(
    model: &mut ModelEntry,
    explicit_wire_api: WireApi,
    probed: WireApi,
) -> DeepfetchApplyReport {
    if !explicit_wire_api.is_auto() && explicit_wire_api != probed {
        return DeepfetchApplyReport::ExplicitPinPreserved {
            existing: explicit_wire_api,
            probed,
        };
    }
    model.wire_api = probed;
    DeepfetchApplyReport::Applied {
        endpoint: probed,
        pinned_wire_api: Some(probed),
        context_tokens: None,
        endpoint_note: EndpointSelectionNote::Pinned,
    }
}

pub(crate) fn apply_probed_context(model: &mut ModelEntry, context_tokens: u32) {
    model.capabilities.context_tokens = Some(context_tokens);
    model.capabilities.context_tokens_source = Some(CapabilitySource::Probed);
}

pub fn collect_deepfetch_targets(
    cfg: &ProvidersConfig,
    scope: &DeepfetchScope,
) -> Result<Vec<DeepfetchTarget>> {
    let mut targets = Vec::new();
    for (provider_id, entry) in &cfg.providers {
        if scope
            .provider
            .as_ref()
            .is_some_and(|selected| selected != provider_id)
        {
            continue;
        }
        if is_anthropic_native_base_url(&entry.url) {
            continue;
        }
        if provider_id == "codex-oauth" {
            continue;
        }
        for model in &entry.models {
            if scope
                .model
                .as_ref()
                .is_some_and(|selected| selected != &model.id)
            {
                continue;
            }
            if model
                .capability_overrides
                .embeddings
                .or(model.capabilities.embeddings)
                .or(model.embeddings)
                .unwrap_or(false)
            {
                continue;
            }
            targets.push(DeepfetchTarget {
                provider_id: provider_id.clone(),
                model_id: model.id.clone(),
                explicit_wire_api: model.wire_api,
                inherited_wire_api: entry.wire_api,
                direct_model_scope: scope.provider.is_some() && scope.model.is_some(),
            });
        }
    }
    if let Some(provider_id) = &scope.provider
        && !cfg.providers.contains_key(provider_id)
    {
        anyhow::bail!("no provider with id `{provider_id}` in effective config");
    }
    Ok(targets)
}

pub fn plan_deepfetch(targets: &[DeepfetchTarget]) -> DeepfetchPlan {
    let providers = targets
        .iter()
        .map(|target| target.provider_id.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let endpoint_requests = targets
        .iter()
        .filter(|target| target.explicit_wire_api.is_auto())
        .count()
        * 2;
    let context_requests = targets.len();
    DeepfetchPlan {
        providers,
        models: targets.len(),
        endpoint_requests,
        context_requests,
    }
}

pub fn deepfetch_confirmation_message(plan: &DeepfetchPlan) -> String {
    format!(
        "Deep fetch will send up to {} live probe request(s) across {} provider(s) and {} model(s). These calls use your provider credentials and may cost money. Continue? [y/N] ",
        plan.total_requests(),
        plan.providers,
        plan.models
    )
}

pub fn should_run_deepfetch(
    mode: DeepfetchMode,
    confirmed: bool,
    is_terminal: bool,
) -> Result<bool> {
    match mode {
        DeepfetchMode::AssumeYes => Ok(true),
        DeepfetchMode::Interactive if is_terminal => Ok(confirmed),
        DeepfetchMode::Interactive | DeepfetchMode::NonInteractive => {
            anyhow::bail!("deep fetch requires an interactive confirmation or --yes")
        }
    }
}

pub async fn probe_target<C: DeepfetchProbeClient>(
    client: &mut C,
    cfg: &mut ProvidersConfig,
    target: &DeepfetchTarget,
) -> Result<DeepfetchApplyReport> {
    let mut pinned_wire_api = None;
    let mut endpoint_note = EndpointSelectionNote::Explicit;
    let endpoint = if target.explicit_wire_api.is_auto() || target.direct_model_scope {
        let completions = classify_endpoint_probe(
            client
                .probe_endpoint(EndpointProbeRequest {
                    provider_id: target.provider_id.clone(),
                    model_id: target.model_id.clone(),
                    endpoint: ProbeEndpoint::Completions,
                })
                .await?,
        );
        let responses = classify_endpoint_probe(
            client
                .probe_endpoint(EndpointProbeRequest {
                    provider_id: target.provider_id.clone(),
                    model_id: target.model_id.clone(),
                    endpoint: ProbeEndpoint::Responses,
                })
                .await?,
        );
        if let Some(probed) = choose_probed_wire_api(completions.clone(), responses.clone()) {
            if target.explicit_wire_api.is_auto() {
                let model = cfg
                    .providers
                    .get_mut(&target.provider_id)
                    .and_then(|entry| entry.models.iter_mut().find(|m| m.id == target.model_id))
                    .ok_or_else(|| anyhow!("model disappeared during deepfetch"))?;
                match apply_probed_wire_api(model, target.explicit_wire_api, probed) {
                    DeepfetchApplyReport::Applied { .. } => {
                        pinned_wire_api = Some(probed);
                        endpoint_note = EndpointSelectionNote::Pinned;
                        probed
                    }
                    report => return Ok(report),
                }
            } else if target.explicit_wire_api != probed {
                let model = cfg
                    .providers
                    .get_mut(&target.provider_id)
                    .and_then(|entry| entry.models.iter_mut().find(|m| m.id == target.model_id))
                    .ok_or_else(|| anyhow!("model disappeared during deepfetch"))?;
                return Ok(apply_probed_wire_api(
                    model,
                    target.explicit_wire_api,
                    probed,
                ));
            } else {
                target.explicit_wire_api
            }
        } else {
            match (&completions, &responses) {
                (EndpointProbeOutcome::Works, EndpointProbeOutcome::Works) => {
                    endpoint_note = EndpointSelectionNote::AutoDetectedAfterBothWorked;
                    if target.inherited_wire_api.is_auto() {
                        WireApi::detect_for_provider(&target.provider_id, &target.model_id)
                    } else {
                        target.inherited_wire_api
                    }
                }
                (EndpointProbeOutcome::Entitlement, _) | (_, EndpointProbeOutcome::Entitlement) => {
                    return Ok(DeepfetchApplyReport::Entitlement { endpoint: None });
                }
                (EndpointProbeOutcome::RateLimited, _) | (_, EndpointProbeOutcome::RateLimited) => {
                    return Ok(DeepfetchApplyReport::RateLimited { endpoint: None });
                }
                _ if !target.explicit_wire_api.is_auto() => target.explicit_wire_api,
                _ => {
                    return Ok(DeepfetchApplyReport::Inconclusive {
                        endpoint: None,
                        reason: format!("completions={completions:?}, responses={responses:?}"),
                    });
                }
            }
        }
    } else {
        target.explicit_wire_api
    };

    let raw = client
        .probe_context(ContextProbeRequest {
            provider_id: target.provider_id.clone(),
            model_id: target.model_id.clone(),
            endpoint: match endpoint {
                WireApi::Completions => ProbeEndpoint::Completions,
                WireApi::Responses => ProbeEndpoint::Responses,
                WireApi::Auto => return Ok(DeepfetchApplyReport::SkippedNoEndpointChoice),
            },
            max_tokens: CONTEXT_PROBE_MAX_TOKENS,
        })
        .await?;
    let context_tokens = match classify_context_probe(raw) {
        ContextProbeOutcome::Oversize { context_tokens } => {
            let model = cfg
                .providers
                .get_mut(&target.provider_id)
                .and_then(|entry| entry.models.iter_mut().find(|m| m.id == target.model_id))
                .ok_or_else(|| anyhow!("model disappeared during deepfetch"))?;
            apply_probed_context(model, context_tokens);
            Some(context_tokens)
        }
        ContextProbeOutcome::Entitlement => {
            return Ok(DeepfetchApplyReport::Entitlement {
                endpoint: Some(endpoint),
            });
        }
        ContextProbeOutcome::RateLimited => {
            return Ok(DeepfetchApplyReport::RateLimited {
                endpoint: Some(endpoint),
            });
        }
        ContextProbeOutcome::Inconclusive(reason) => {
            return Ok(DeepfetchApplyReport::Inconclusive {
                endpoint: Some(endpoint),
                reason,
            });
        }
    };

    if endpoint_note == EndpointSelectionNote::AutoDetectedAfterBothWorked {
        Ok(DeepfetchApplyReport::BothEndpointsWork {
            endpoint,
            context_tokens,
        })
    } else {
        Ok(DeepfetchApplyReport::Applied {
            endpoint,
            pinned_wire_api,
            context_tokens,
            endpoint_note,
        })
    }
}

pub(crate) fn parse_context_limit(message: &str) -> Option<u32> {
    let lower = message.to_ascii_lowercase();
    if !(lower.contains("context") || lower.contains("token")) {
        return None;
    }
    let mut numbers = Vec::new();
    let mut current = String::new();
    for ch in lower.chars() {
        if ch.is_ascii_digit() || (ch == ',' && !current.is_empty()) {
            current.push(ch);
        } else if !current.is_empty() {
            if let Ok(value) = current.replace(',', "").parse::<u32>() {
                numbers.push(value);
            }
            current.clear();
        }
    }
    if !current.is_empty()
        && let Ok(value) = current.replace(',', "").parse::<u32>()
    {
        numbers.push(value);
    }
    numbers
        .into_iter()
        .filter(|value| *value > 0 && *value < CONTEXT_PROBE_MAX_TOKENS)
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingClient {
        endpoint: Vec<ProbeRawOutcome>,
        context: Vec<ProbeRawOutcome>,
        endpoint_calls: Vec<EndpointProbeRequest>,
        context_calls: Vec<ContextProbeRequest>,
    }

    impl RecordingClient {
        fn new(endpoint: Vec<ProbeRawOutcome>, context: Vec<ProbeRawOutcome>) -> Self {
            Self {
                endpoint,
                context,
                endpoint_calls: Vec::new(),
                context_calls: Vec::new(),
            }
        }
    }

    impl DeepfetchProbeClient for RecordingClient {
        fn probe_endpoint<'a>(
            &'a mut self,
            request: EndpointProbeRequest,
        ) -> Pin<Box<dyn Future<Output = Result<ProbeRawOutcome>> + Send + 'a>> {
            self.endpoint_calls.push(request);
            Box::pin(async move {
                Ok(if self.endpoint.is_empty() {
                    ProbeRawOutcome::Works
                } else {
                    self.endpoint.remove(0)
                })
            })
        }

        fn probe_context<'a>(
            &'a mut self,
            request: ContextProbeRequest,
        ) -> Pin<Box<dyn Future<Output = Result<ProbeRawOutcome>> + Send + 'a>> {
            self.context_calls.push(request);
            Box::pin(async move {
                Ok(if self.context.is_empty() {
                    ProbeRawOutcome::Works
                } else {
                    self.context.remove(0)
                })
            })
        }
    }

    #[test]
    fn endpoint_probe_pins_only_on_conclusive_mismatch() {
        assert_eq!(
            choose_probed_wire_api(
                EndpointProbeOutcome::Incompatible,
                EndpointProbeOutcome::Works
            ),
            Some(WireApi::Responses)
        );
        assert_eq!(
            choose_probed_wire_api(
                EndpointProbeOutcome::Works,
                EndpointProbeOutcome::Incompatible
            ),
            Some(WireApi::Completions)
        );
        assert_eq!(
            choose_probed_wire_api(
                EndpointProbeOutcome::Works,
                EndpointProbeOutcome::Inconclusive("timeout".into())
            ),
            None
        );
        assert_eq!(
            choose_probed_wire_api(
                EndpointProbeOutcome::Incompatible,
                EndpointProbeOutcome::Incompatible
            ),
            None
        );
        assert_eq!(
            classify_endpoint_probe(ProbeRawOutcome::HttpError(ProbeHttpError {
                status: 404,
                body: String::new(),
            })),
            EndpointProbeOutcome::Incompatible
        );
        assert_eq!(
            classify_endpoint_probe(ProbeRawOutcome::HttpError(ProbeHttpError {
                status: 405,
                body: String::new(),
            })),
            EndpointProbeOutcome::Incompatible
        );
        assert_eq!(
            classify_endpoint_probe(ProbeRawOutcome::HttpError(ProbeHttpError {
                status: 400,
                body: crate::engine::model::rig_boundary::UNSUPPORTED_API_CODE.into(),
            })),
            EndpointProbeOutcome::Incompatible
        );
        assert_eq!(
            classify_endpoint_probe(ProbeRawOutcome::Transport("timeout".into())),
            EndpointProbeOutcome::Inconclusive("timeout".into())
        );
        assert_eq!(
            classify_endpoint_probe(ProbeRawOutcome::HttpError(ProbeHttpError {
                status: 429,
                body: "slow down".into(),
            })),
            EndpointProbeOutcome::RateLimited
        );
        assert_eq!(
            classify_endpoint_probe(ProbeRawOutcome::HttpError(ProbeHttpError {
                status: 403,
                body: "forbidden".into(),
            })),
            EndpointProbeOutcome::Entitlement
        );
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "2".parse().unwrap());
        assert_eq!(retry_after_delay(&headers), Some(Duration::from_secs(2)));
    }

    #[test]
    fn both_endpoints_work_pins_nothing() {
        assert_eq!(
            choose_probed_wire_api(EndpointProbeOutcome::Works, EndpointProbeOutcome::Works),
            None
        );
    }

    #[test]
    fn entitlement_failure_never_records_unsupported() {
        let outcome = classify_endpoint_probe(ProbeRawOutcome::HttpError(ProbeHttpError {
            status: 403,
            body: "forbidden".into(),
        }));
        assert_eq!(outcome, EndpointProbeOutcome::Entitlement);
        assert_eq!(
            choose_probed_wire_api(outcome, EndpointProbeOutcome::Works),
            None
        );
    }

    #[test]
    fn context_probe_declares_oversize_and_parses_limit() {
        let completions_body = probe_request_body(
            ProbeEndpoint::Completions,
            "gpt-5-mini",
            CONTEXT_PROBE_MAX_TOKENS,
        );
        assert_eq!(
            completions_body["messages"],
            serde_json::json!([{ "role": "user", "content": "hi" }])
        );
        assert_eq!(
            completions_body["max_tokens"],
            serde_json::json!(CONTEXT_PROBE_MAX_TOKENS)
        );
        let responses_body = probe_request_body(
            ProbeEndpoint::Responses,
            "gpt-5-mini",
            CONTEXT_PROBE_MAX_TOKENS,
        );
        assert_eq!(responses_body["input"], serde_json::json!("hi"));
        assert_eq!(
            responses_body["max_output_tokens"],
            serde_json::json!(CONTEXT_PROBE_MAX_TOKENS)
        );

        for (body, expected) in [
            (
                "This model's maximum context length is 128000 tokens. However, you requested 100000000 tokens.",
                128000,
            ),
            (
                "This model supports at most 64,000 context tokens. Requested tokens: 100000000.",
                64000,
            ),
            (
                "prompt + completion exceeds model context window of 1,048,576 tokens",
                1_048_576,
            ),
        ] {
            let outcome = classify_context_probe(ProbeRawOutcome::HttpError(ProbeHttpError {
                status: 400,
                body: body.into(),
            }));
            assert_eq!(
                outcome,
                ContextProbeOutcome::Oversize {
                    context_tokens: expected
                }
            );
        }
    }

    #[test]
    fn context_probe_unparseable_leaves_context_unknown() {
        let outcome = classify_context_probe(ProbeRawOutcome::HttpError(ProbeHttpError {
            status: 400,
            body: "bad request".into(),
        }));
        assert!(matches!(outcome, ContextProbeOutcome::Inconclusive(_)));
    }

    #[test]
    fn deepfetch_confirm_reports_accurate_counts() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "p1".into(),
            ProviderEntry {
                models: vec![
                    ModelEntry {
                        id: "a".into(),
                        ..ModelEntry::default()
                    },
                    ModelEntry {
                        id: "b".into(),
                        wire_api: WireApi::Responses,
                        ..ModelEntry::default()
                    },
                ],
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "p2".into(),
            ProviderEntry {
                models: vec![ModelEntry {
                    id: "c".into(),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );

        let all = collect_deepfetch_targets(
            &cfg,
            &DeepfetchScope {
                provider: None,
                model: None,
            },
        )
        .unwrap();
        let plan = plan_deepfetch(&all);
        assert_eq!(plan.providers, 2);
        assert_eq!(plan.models, 3);
        assert_eq!(plan.endpoint_requests, 4);
        assert_eq!(plan.context_requests, 3);
        let message = deepfetch_confirmation_message(&plan);
        assert!(message.contains("7 live probe request"));
        assert!(message.contains("2 provider"));
        assert!(message.contains("3 model"));
        assert!(message.contains("may cost money"));

        let one_provider = collect_deepfetch_targets(
            &cfg,
            &DeepfetchScope {
                provider: Some("p1".into()),
                model: None,
            },
        )
        .unwrap();
        let plan = plan_deepfetch(&one_provider);
        assert_eq!(
            (plan.providers, plan.models, plan.total_requests()),
            (1, 2, 4)
        );

        let one_model = collect_deepfetch_targets(
            &cfg,
            &DeepfetchScope {
                provider: Some("p1".into()),
                model: Some("b".into()),
            },
        )
        .unwrap();
        let plan = plan_deepfetch(&one_model);
        assert_eq!(
            (plan.providers, plan.models, plan.total_requests()),
            (1, 1, 1)
        );
    }

    #[test]
    fn deepfetch_non_interactive_refuses_to_probe() {
        assert!(should_run_deepfetch(DeepfetchMode::NonInteractive, false, false).is_err());
        assert!(should_run_deepfetch(DeepfetchMode::Interactive, false, false).is_err());
        assert!(should_run_deepfetch(DeepfetchMode::AssumeYes, false, false).unwrap());
    }

    #[tokio::test]
    async fn deepfetch_sends_nothing_without_confirmation() {
        let mut client = RecordingClient::new(vec![ProbeRawOutcome::Works], Vec::new());
        let run = should_run_deepfetch(DeepfetchMode::Interactive, false, true).unwrap();
        if run {
            let mut cfg = ProvidersConfig::default();
            let target = DeepfetchTarget {
                provider_id: "p".into(),
                model_id: "m".into(),
                explicit_wire_api: WireApi::Auto,
                inherited_wire_api: WireApi::Auto,
                direct_model_scope: false,
            };
            let _ = probe_target(&mut client, &mut cfg, &target).await;
        }
        assert!(client.endpoint_calls.is_empty());
        assert!(client.context_calls.is_empty());
    }

    #[tokio::test]
    async fn deepfetch_skips_models_without_endpoint_choice() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "anthropic".into(),
            ProviderEntry {
                url: "https://api.anthropic.com/v1".into(),
                models: vec![ModelEntry {
                    id: "claude-opus-4".into(),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "codex-oauth".into(),
            ProviderEntry {
                models: vec![ModelEntry {
                    id: "gpt-5.5".into(),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "openai".into(),
            ProviderEntry {
                models: vec![
                    ModelEntry {
                        id: "text-embedding-3-large".into(),
                        embeddings: Some(true),
                        ..ModelEntry::default()
                    },
                    ModelEntry {
                        id: "gpt-5-mini".into(),
                        ..ModelEntry::default()
                    },
                ],
                ..ProviderEntry::default()
            },
        );
        let targets = collect_deepfetch_targets(
            &cfg,
            &DeepfetchScope {
                provider: None,
                model: None,
            },
        )
        .unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].provider_id, "openai");
        assert_eq!(targets[0].model_id, "gpt-5-mini");

        let mut client = RecordingClient::new(
            vec![
                ProbeRawOutcome::Transport("timeout".into()),
                ProbeRawOutcome::Transport("timeout".into()),
            ],
            vec![ProbeRawOutcome::HttpError(ProbeHttpError {
                status: 400,
                body: "maximum context length is 128000 tokens".into(),
            })],
        );
        let target = DeepfetchTarget {
            provider_id: "openai".into(),
            model_id: "gpt-5-mini".into(),
            explicit_wire_api: WireApi::Auto,
            inherited_wire_api: WireApi::Auto,
            direct_model_scope: false,
        };
        let report = probe_target(&mut client, &mut cfg, &target).await.unwrap();
        assert!(matches!(report, DeepfetchApplyReport::Inconclusive { .. }));
        assert!(client.context_calls.is_empty());
    }

    #[tokio::test]
    async fn deepfetch_both_endpoints_work_still_context_probes_without_pin() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "openai".into(),
            ProviderEntry {
                models: vec![ModelEntry {
                    id: "gpt-5-mini".into(),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        let mut client = RecordingClient::new(
            vec![ProbeRawOutcome::Works, ProbeRawOutcome::Works],
            vec![ProbeRawOutcome::HttpError(ProbeHttpError {
                status: 400,
                body: "maximum context length is 128000 tokens".into(),
            })],
        );
        let target = DeepfetchTarget {
            provider_id: "openai".into(),
            model_id: "gpt-5-mini".into(),
            explicit_wire_api: WireApi::Auto,
            inherited_wire_api: WireApi::Auto,
            direct_model_scope: false,
        };
        let report = probe_target(&mut client, &mut cfg, &target).await.unwrap();
        assert_eq!(
            report,
            DeepfetchApplyReport::BothEndpointsWork {
                endpoint: WireApi::Responses,
                context_tokens: Some(128000)
            }
        );
        let model = &cfg.providers["openai"].models[0];
        assert_eq!(model.wire_api, WireApi::Auto);
        assert_eq!(model.capabilities.context_tokens, Some(128000));
        assert_eq!(client.context_calls.len(), 1);
    }

    #[tokio::test]
    async fn deepfetch_provider_wire_default_still_endpoint_probes_and_can_pin_model() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "acme".into(),
            ProviderEntry {
                wire_api: WireApi::Completions,
                models: vec![ModelEntry {
                    id: "m".into(),
                    wire_api: WireApi::Auto,
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        let targets = collect_deepfetch_targets(
            &cfg,
            &DeepfetchScope {
                provider: Some("acme".into()),
                model: None,
            },
        )
        .unwrap();
        let plan = plan_deepfetch(&targets);
        assert_eq!(plan.endpoint_requests, 2);
        assert_eq!(plan.context_requests, 1);

        let mut client = RecordingClient::new(
            vec![
                ProbeRawOutcome::HttpError(ProbeHttpError {
                    status: 404,
                    body: String::new(),
                }),
                ProbeRawOutcome::Works,
            ],
            vec![ProbeRawOutcome::HttpError(ProbeHttpError {
                status: 400,
                body: "maximum context length is 128000 tokens".into(),
            })],
        );
        let report = probe_target(&mut client, &mut cfg, &targets[0])
            .await
            .unwrap();
        assert_eq!(
            report,
            DeepfetchApplyReport::Applied {
                endpoint: WireApi::Responses,
                pinned_wire_api: Some(WireApi::Responses),
                context_tokens: Some(128000),
                endpoint_note: EndpointSelectionNote::Pinned,
            }
        );
        let model = &cfg.providers["acme"].models[0];
        assert_eq!(model.wire_api, WireApi::Responses);
    }

    #[test]
    fn deepfetch_never_overwrites_explicit_pin() {
        let mut model = ModelEntry {
            id: "m".into(),
            wire_api: WireApi::Completions,
            ..ModelEntry::default()
        };
        let report = apply_probed_wire_api(&mut model, WireApi::Completions, WireApi::Responses);
        assert_eq!(
            report,
            DeepfetchApplyReport::ExplicitPinPreserved {
                existing: WireApi::Completions,
                probed: WireApi::Responses
            }
        );
        assert_eq!(model.wire_api, WireApi::Completions);
    }

    #[tokio::test]
    async fn deepfetch_direct_scope_reports_explicit_pin_contradiction() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "p".into(),
            ProviderEntry {
                models: vec![ModelEntry {
                    id: "m".into(),
                    wire_api: WireApi::Completions,
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        let mut client = RecordingClient::new(
            vec![
                ProbeRawOutcome::HttpError(ProbeHttpError {
                    status: 404,
                    body: String::new(),
                }),
                ProbeRawOutcome::Works,
            ],
            Vec::new(),
        );
        let target = DeepfetchTarget {
            provider_id: "p".into(),
            model_id: "m".into(),
            explicit_wire_api: WireApi::Completions,
            inherited_wire_api: WireApi::Auto,
            direct_model_scope: true,
        };
        let report = probe_target(&mut client, &mut cfg, &target).await.unwrap();
        assert_eq!(
            report,
            DeepfetchApplyReport::ExplicitPinPreserved {
                existing: WireApi::Completions,
                probed: WireApi::Responses
            }
        );
        assert_eq!(cfg.providers["p"].models[0].wire_api, WireApi::Completions);
        assert!(client.context_calls.is_empty());
    }

    #[tokio::test]
    async fn deepfetch_cancellation_preserves_completed_results() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "p".into(),
            ProviderEntry {
                models: vec![
                    ModelEntry {
                        id: "completed".into(),
                        wire_api: WireApi::Responses,
                        ..ModelEntry::default()
                    },
                    ModelEntry {
                        id: "cancelled".into(),
                        wire_api: WireApi::Responses,
                        ..ModelEntry::default()
                    },
                ],
                ..ProviderEntry::default()
            },
        );
        let mut client = RecordingClient::new(
            Vec::new(),
            vec![ProbeRawOutcome::HttpError(ProbeHttpError {
                status: 400,
                body: "maximum context length is 64000 tokens".into(),
            })],
        );
        let target = DeepfetchTarget {
            provider_id: "p".into(),
            model_id: "completed".into(),
            explicit_wire_api: WireApi::Responses,
            inherited_wire_api: WireApi::Auto,
            direct_model_scope: false,
        };
        let report = probe_target(&mut client, &mut cfg, &target).await.unwrap();
        assert_eq!(
            report,
            DeepfetchApplyReport::Applied {
                endpoint: WireApi::Responses,
                pinned_wire_api: None,
                context_tokens: Some(64000),
                endpoint_note: EndpointSelectionNote::Explicit,
            }
        );
        let completed = &cfg.providers["p"].models[0];
        assert_eq!(completed.capabilities.context_tokens, Some(64000));
        assert_eq!(
            completed.capabilities.context_tokens_source,
            Some(CapabilitySource::Probed)
        );

        let mut client = RecordingClient::new(Vec::new(), vec![ProbeRawOutcome::Cancelled]);
        let target = DeepfetchTarget {
            provider_id: "p".into(),
            model_id: "cancelled".into(),
            explicit_wire_api: WireApi::Responses,
            inherited_wire_api: WireApi::Auto,
            direct_model_scope: false,
        };
        let report = probe_target(&mut client, &mut cfg, &target).await.unwrap();
        assert!(matches!(report, DeepfetchApplyReport::Inconclusive { .. }));
        let completed = &cfg.providers["p"].models[0];
        assert_eq!(completed.capabilities.context_tokens, Some(64000));
        let cancelled = &cfg.providers["p"].models[1];
        assert_eq!(cancelled.capabilities.context_tokens, None);
    }
}
