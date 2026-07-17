use super::*;

static ENDPOINT_PROBES: OnceLock<Mutex<HashMap<EndpointProbeKey, EndpointProbeState>>> =
    OnceLock::new();
pub(super) const ENDPOINT_PROBE_TTL: Duration = Duration::from_secs(15 * 60);
pub(super) const ENDPOINT_PROBE_MAX_ENTRIES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct EndpointProbeKey {
    provider: String,
    model: String,
    base_url: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct EndpointProbeState {
    completions: EndpointObservation,
    responses: EndpointObservation,
    completions_observed_at: Option<Instant>,
    responses_observed_at: Option<Instant>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum EndpointObservation {
    #[default]
    Unknown,
    Works,
    Incompatible,
    TransientFailed,
}

pub(super) fn endpoint_probes() -> &'static Mutex<HashMap<EndpointProbeKey, EndpointProbeState>> {
    ENDPOINT_PROBES.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn normalize_probe_base_url(base_url: &str) -> String {
    base_url.trim().trim_end_matches('/').to_string()
}

pub(super) fn probe_key(provider: &str, model: &str, base_url: &str) -> EndpointProbeKey {
    EndpointProbeKey {
        provider: provider.to_string(),
        model: model.to_string(),
        base_url: normalize_probe_base_url(base_url),
    }
}

pub(super) fn prune_endpoint_probes(
    probes: &mut HashMap<EndpointProbeKey, EndpointProbeState>,
    now: Instant,
) {
    probes.retain(|_, state| {
        state.observed_at().is_some_and(|observed_at| {
            now.saturating_duration_since(observed_at) <= ENDPOINT_PROBE_TTL
        })
    });
    while probes.len() > ENDPOINT_PROBE_MAX_ENTRIES {
        let Some(oldest_key) = probes
            .iter()
            .min_by_key(|(_, state)| state.observed_at())
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        probes.remove(&oldest_key);
    }
}

pub(super) fn learned_working_endpoint(
    provider: &str,
    model: &str,
    base_url: &str,
) -> Option<crate::config::providers::WireApi> {
    let mut probes = endpoint_probes()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    prune_endpoint_probes(&mut probes, Instant::now());
    let state = probes.get(&probe_key(provider, model, base_url))?;
    state.most_recent_working_endpoint()
}

pub(super) fn endpoint_observation(
    provider: &str,
    model: &str,
    base_url: &str,
    endpoint: crate::config::providers::WireApi,
) -> EndpointObservation {
    let mut probes = endpoint_probes()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    prune_endpoint_probes(&mut probes, Instant::now());
    let Some(state) = probes.get(&probe_key(provider, model, base_url)) else {
        return EndpointObservation::Unknown;
    };
    match endpoint {
        crate::config::providers::WireApi::Completions => state.completions,
        crate::config::providers::WireApi::Responses => state.responses,
        crate::config::providers::WireApi::Auto => EndpointObservation::Unknown,
    }
}

pub(super) fn record_endpoint_observation(
    provider: &str,
    model: &str,
    base_url: &str,
    endpoint: crate::config::providers::WireApi,
    observation: EndpointObservation,
) {
    record_endpoint_observation_at(
        provider,
        model,
        base_url,
        endpoint,
        observation,
        Instant::now(),
    );
}

pub(super) fn record_endpoint_observation_at(
    provider: &str,
    model: &str,
    base_url: &str,
    endpoint: crate::config::providers::WireApi,
    observation: EndpointObservation,
    now: Instant,
) {
    let mut probes = endpoint_probes()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    prune_endpoint_probes(&mut probes, now);
    let state = probes
        .entry(probe_key(provider, model, base_url))
        .or_default();
    match endpoint {
        crate::config::providers::WireApi::Completions => {
            state.completions = observation;
            state.completions_observed_at = Some(now);
        }
        crate::config::providers::WireApi::Responses => {
            state.responses = observation;
            state.responses_observed_at = Some(now);
        }
        crate::config::providers::WireApi::Auto => {}
    }
    prune_endpoint_probes(&mut probes, now);
}

impl EndpointProbeState {
    fn observed_at(&self) -> Option<Instant> {
        self.completions_observed_at.max(self.responses_observed_at)
    }

    fn most_recent_working_endpoint(&self) -> Option<crate::config::providers::WireApi> {
        let completions = if self.completions == EndpointObservation::Works {
            self.completions_observed_at
                .map(|at| (crate::config::providers::WireApi::Completions, at))
        } else {
            None
        };
        let responses = if self.responses == EndpointObservation::Works {
            self.responses_observed_at
                .map(|at| (crate::config::providers::WireApi::Responses, at))
        } else {
            None
        };
        match (completions, responses) {
            (Some((endpoint, _)), None) | (None, Some((endpoint, _))) => Some(endpoint),
            (
                Some((completions_endpoint, completions_at)),
                Some((responses_endpoint, responses_at)),
            ) => {
                if responses_at > completions_at {
                    Some(responses_endpoint)
                } else {
                    Some(completions_endpoint)
                }
            }
            (None, None) => None,
        }
    }
}

pub(super) fn normalize_openai_usage_aliases_bytes(bytes: bytes::Bytes) -> bytes::Bytes {
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return bytes;
    };
    if text.contains("\ndata: ") || text.starts_with("data: ") {
        return bytes::Bytes::from(normalize_sse_usage_aliases(text));
    }
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(text) else {
        return bytes;
    };
    normalize_usage_aliases_in_value(&mut value);
    serde_json::to_vec(&value).map_or(bytes, bytes::Bytes::from)
}

pub(super) fn normalize_sse_usage_aliases(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        push_normalized_sse_line(&mut out, line);
    }
    out
}

pub(super) fn take_normalized_sse_lines(pending: &mut Vec<u8>, final_chunk: bool) -> bytes::Bytes {
    let mut out = Vec::new();
    while let Some(newline) = pending.iter().position(|b| *b == b'\n') {
        let mut line = pending.drain(..=newline).collect::<Vec<_>>();
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        push_normalized_sse_line_bytes(&mut out, &line);
    }
    if final_chunk && !pending.is_empty() {
        let line = std::mem::take(pending);
        push_normalized_sse_line_bytes(&mut out, &line);
    }
    bytes::Bytes::from(out)
}

pub(super) fn push_normalized_sse_line_bytes(out: &mut Vec<u8>, line: &[u8]) {
    let Ok(line) = std::str::from_utf8(line) else {
        out.extend_from_slice(line);
        out.push(b'\n');
        return;
    };
    let mut normalized = String::new();
    push_normalized_sse_line(&mut normalized, line);
    out.extend_from_slice(normalized.as_bytes());
}

pub(super) fn push_normalized_sse_line(out: &mut String, line: &str) {
    let Some(data) = line.strip_prefix("data: ") else {
        out.push_str(line);
        out.push('\n');
        return;
    };
    if data.trim() == "[DONE]" {
        out.push_str(line);
        out.push('\n');
        return;
    }
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(data) else {
        out.push_str(line);
        out.push('\n');
        return;
    };
    normalize_usage_aliases_in_value(&mut value);
    out.push_str("data: ");
    out.push_str(&serde_json::to_string(&value).unwrap_or_else(|_| data.to_string()));
    out.push('\n');
}

pub(super) fn normalize_usage_aliases_in_value(value: &mut serde_json::Value) {
    let Some(usage) = value
        .get_mut("usage")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    if !usage.contains_key("prompt_tokens")
        && let Some(input) = usage.get("input_tokens").cloned()
    {
        usage.insert("prompt_tokens".to_string(), input);
    }
    if !usage.contains_key("completion_tokens")
        && let Some(output) = usage.get("output_tokens").cloned()
    {
        usage.insert("completion_tokens".to_string(), output);
    }
    if !usage.contains_key("total_tokens") {
        if let Some(total) = usage_u64_object(usage, "input_tokens")
            .zip(usage_u64_object(usage, "output_tokens"))
            .map(|(input, output)| input.saturating_add(output))
        {
            usage.insert("total_tokens".to_string(), serde_json::Value::from(total));
        } else if let Some(total) = usage_u64_object(usage, "prompt_tokens")
            .zip(usage_u64_object(usage, "completion_tokens"))
            .map(|(input, output)| input.saturating_add(output))
        {
            usage.insert("total_tokens".to_string(), serde_json::Value::from(total));
        }
    }
}

pub(super) fn usage_u64_object(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<u64> {
    map.get(key).and_then(|v| match v {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => s.parse::<u64>().ok(),
        _ => None,
    })
}

#[derive(Clone)]
pub struct EndpointRecoveryContext {
    pub approve: Arc<dyn Fn(EndpointRecoveryPrompt) -> BoxFuture<'static, bool> + Send + Sync>,
}

#[derive(Debug, Clone)]
pub struct EndpointRecoveryPrompt {
    pub provider: String,
    pub model: String,
    pub attempted: crate::config::providers::WireApi,
    pub alternate: crate::config::providers::WireApi,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub(super) struct ResponsesToolIdentityRecord {
    pub(super) cockpit_call_id: String,
    pub(super) provider_item_id: String,
    pub(super) provider_call_id: String,
    pub(super) provider_call_id_source: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponsesToolIdentityFailureKind {
    OrphanAssistantCall,
    OrphanToolResult,
    MismatchedPair,
}

impl ResponsesToolIdentityFailureKind {
    fn as_str(self) -> &'static str {
        match self {
            ResponsesToolIdentityFailureKind::OrphanAssistantCall => "orphan_assistant_call",
            ResponsesToolIdentityFailureKind::OrphanToolResult => "orphan_tool_result",
            ResponsesToolIdentityFailureKind::MismatchedPair => "mismatched_pair",
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error(
    "Responses tool-call identity repair required: {kind} for `{call_id}` before provider replay"
)]
pub(super) struct ResponsesToolIdentityError {
    pub(super) kind: &'static str,
    pub(super) call_id: String,
}

#[derive(Debug, Clone)]
struct OpenResponsesCall {
    id: String,
    call_id: String,
    source: &'static str,
    covered: bool,
}

pub(super) fn normalize_responses_tool_call_identity(
    history: &mut [Message],
    prompt: &mut Message,
) -> Result<Vec<ResponsesToolIdentityRecord>> {
    let mut records = Vec::new();
    let mut open: Vec<OpenResponsesCall> = Vec::new();
    for msg in history.iter_mut() {
        normalize_responses_message(msg, &mut open, &mut records)?;
    }
    normalize_responses_message(prompt, &mut open, &mut records)?;
    ensure_responses_open_calls_covered(&open)?;
    Ok(records)
}

fn normalize_responses_message(
    msg: &mut Message,
    open: &mut Vec<OpenResponsesCall>,
    records: &mut Vec<ResponsesToolIdentityRecord>,
) -> Result<()> {
    match msg {
        Message::Assistant { content, .. } => {
            ensure_responses_open_calls_covered(open)?;
            open.clear();
            for part in content.iter_mut() {
                if let AssistantContent::ToolCall(tc) = part {
                    let (call_id, source) = match tc.call_id.clone() {
                        Some(call_id) => (call_id, "provider"),
                        None => {
                            let call_id = tc.id.clone();
                            tc.call_id = Some(call_id.clone());
                            (call_id, "normalized_from_assistant_id")
                        }
                    };
                    records.push(ResponsesToolIdentityRecord {
                        cockpit_call_id: tc.id.clone(),
                        provider_item_id: tc.id.clone(),
                        provider_call_id: call_id.clone(),
                        provider_call_id_source: source,
                    });
                    open.push(OpenResponsesCall {
                        id: tc.id.clone(),
                        call_id,
                        source,
                        covered: false,
                    });
                }
            }
        }
        Message::User { content } => {
            let mut saw_result = false;
            for part in content.iter_mut() {
                if let UserContent::ToolResult(tr) = part {
                    saw_result = true;
                    let Some(open_call) = open.iter_mut().find(|call| call.id == tr.id) else {
                        return Err(responses_identity_error(
                            ResponsesToolIdentityFailureKind::OrphanToolResult,
                            tr.id.clone(),
                        ));
                    };
                    match tr.call_id.as_deref() {
                        Some(call_id) if call_id != open_call.call_id => {
                            return Err(responses_identity_error(
                                ResponsesToolIdentityFailureKind::MismatchedPair,
                                tr.id.clone(),
                            ));
                        }
                        Some(_) => {}
                        None => {
                            tr.call_id = Some(open_call.call_id.clone());
                        }
                    }
                    records.push(ResponsesToolIdentityRecord {
                        cockpit_call_id: tr.id.clone(),
                        provider_item_id: tr.id.clone(),
                        provider_call_id: tr
                            .call_id
                            .clone()
                            .unwrap_or_else(|| open_call.call_id.clone()),
                        provider_call_id_source: open_call.source,
                    });
                    open_call.covered = true;
                }
            }
            if !saw_result {
                ensure_responses_open_calls_covered(open)?;
                open.clear();
            }
        }
        Message::System { .. } => {
            ensure_responses_open_calls_covered(open)?;
            open.clear();
        }
    }
    Ok(())
}

fn ensure_responses_open_calls_covered(open: &[OpenResponsesCall]) -> Result<()> {
    if let Some(call) = open.iter().find(|call| !call.covered) {
        return Err(responses_identity_error(
            ResponsesToolIdentityFailureKind::OrphanAssistantCall,
            call.id.clone(),
        ));
    }
    Ok(())
}

fn responses_identity_error(
    kind: ResponsesToolIdentityFailureKind,
    call_id: String,
) -> anyhow::Error {
    anyhow::Error::new(ResponsesToolIdentityError {
        kind: kind.as_str(),
        call_id,
    })
}
