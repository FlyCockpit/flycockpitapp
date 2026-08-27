//! jsonrpsee inbound method dispatch for the ACP v1 peer.
//!
//! Cockpit's parser gates each frame and retains raw `params`; the admitted
//! request is then routed through jsonrpsee's raw-request dispatch API.

use std::sync::{Arc, Mutex};

use jsonrpsee::RpcModule;
use jsonrpsee_types::{ErrorObjectOwned, Params};

use super::AcpTransportCounters;
use super::bridge::BridgeFacade;
use super::classify::InboundRequest;
use super::dto::{SessionAdmissionDto, decode_session_load, decode_session_new, initialize_result};
use super::raw_json::parse_frame;

/// If this fails to type-check, return the transport-selection prompt.
const JSONRPSEE_RAW_PARAMS_API: fn(&Params<'_>) -> Option<&str> = Params::as_str;

const INBOUND_METHODS: &[&str] = &[
    "initialize",
    "session/new",
    "session/load",
    "session/cancel",
    "session/prompt",
];

#[derive(Debug, Default)]
pub struct DispatchContext {
    counters: Mutex<AcpTransportCounters>,
    cancelled_sessions: Mutex<Vec<String>>,
    raw_params: Option<String>,
}

pub fn build_rpc_module() -> RpcModule<DispatchContext> {
    build_rpc_module_from_arc(Arc::new(DispatchContext::default()))
}

fn build_rpc_module_from_arc(context: Arc<DispatchContext>) -> RpcModule<DispatchContext> {
    let mut module = RpcModule::from_arc(context);
    module
        .register_method("initialize", |params, _, _| {
            let _ = JSONRPSEE_RAW_PARAMS_API(&params);
            Ok::<_, ErrorObjectOwned>(initialize_result())
        })
        .expect("initialize is unique");
    module
        .register_method("session/new", |params, context, _| {
            let raw = required_raw_params(&params, context)?;
            let parsed = parse_frame(&raw).map_err(|err| invalid_params(err.to_string()))?;
            let mut counters = context.counters.lock().expect("dispatch counters");
            let dto = decode_session_new(&raw, &parsed.root, &mut counters)
                .map_err(|err| invalid_params(err.to_string()))?;
            let receipt = BridgeFacade.admit(&SessionAdmissionDto::New(dto), &mut counters);
            Ok(serde_json::json!({
                "sessionId": format!("acp-session-{}", receipt.server_count)
            }))
        })
        .expect("session/new is unique");
    module
        .register_method("session/load", |params, context, _| {
            let raw = required_raw_params(&params, context)?;
            let parsed = parse_frame(&raw).map_err(|err| invalid_params(err.to_string()))?;
            let mut counters = context.counters.lock().expect("dispatch counters");
            let dto = decode_session_load(&raw, &parsed.root, &mut counters)
                .map_err(|err| invalid_params(err.to_string()))?;
            BridgeFacade.admit(&SessionAdmissionDto::Load(dto), &mut counters);
            Ok(serde_json::json!({}))
        })
        .expect("session/load is unique");
    module
        .register_method("session/cancel", |params, context, _| {
            let raw = required_raw_params(&params, context)?;
            let value: serde_json::Value =
                serde_json::from_str(&raw).map_err(|err| invalid_params(err.to_string()))?;
            let session_id = value
                .get("sessionId")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| invalid_params("missing sessionId"))?;
            context
                .cancelled_sessions
                .lock()
                .expect("cancelled sessions")
                .push(session_id.to_string());
            Ok(serde_json::Value::Null)
        })
        .expect("session/cancel is unique");
    module
        .register_method("session/prompt", |params, _, _| {
            let _ = JSONRPSEE_RAW_PARAMS_API(&params);
            Ok::<_, ErrorObjectOwned>(serde_json::json!({ "stopReason": "end_turn" }))
        })
        .expect("session/prompt is unique");
    module
}

fn required_raw_params(
    params: &Params<'_>,
    context: &DispatchContext,
) -> Result<String, ErrorObjectOwned> {
    context
        .raw_params
        .clone()
        .or_else(|| JSONRPSEE_RAW_PARAMS_API(params).map(str::to_string))
        .ok_or_else(|| invalid_params("params required"))
}

fn invalid_params(message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32602, message.into(), None::<()>)
}

pub fn registered_method_names() -> Vec<&'static str> {
    INBOUND_METHODS.to_vec()
}

pub fn elicitation_is_rejected(method: &str) -> bool {
    matches!(
        method,
        "elicitation/create" | "elicitation/complete" | "elicitation.form"
    )
}

pub enum DispatchResult {
    Response(String),
    NotificationHandled,
    NoResponse,
}

pub fn dispatch_request(
    request: &InboundRequest,
    _bridge: &BridgeFacade,
    counters: &mut AcpTransportCounters,
    cancelled: &mut Vec<String>,
) -> DispatchResult {
    let context = Arc::new(DispatchContext {
        raw_params: request.raw_params.clone(),
        ..DispatchContext::default()
    });
    let module = build_rpc_module_from_arc(Arc::clone(&context));
    let response = futures::executor::block_on(module.raw_json_request(&request.raw, 1));
    let Ok((response, _notifications)) = response else {
        return DispatchResult::NoResponse;
    };
    let dispatch_counters = context.counters.lock().expect("dispatch counters").clone();
    counters.daemon_mutations += dispatch_counters.daemon_mutations;
    counters.bridge_conversions += dispatch_counters.bridge_conversions;
    counters.catalog_mutations += dispatch_counters.catalog_mutations;
    counters.dto_produced += dispatch_counters.dto_produced;
    counters.schema_decode_attempts += dispatch_counters.schema_decode_attempts;
    cancelled.extend(
        context
            .cancelled_sessions
            .lock()
            .expect("cancelled sessions")
            .drain(..),
    );
    DispatchResult::Response(response)
}

pub fn dispatch_notification(
    method: &str,
    raw: &str,
    cancelled: &mut Vec<String>,
) -> DispatchResult {
    if method == "$/cancel_request" {
        return DispatchResult::NotificationHandled;
    }
    let Ok(parsed) = parse_frame(raw) else {
        return DispatchResult::NoResponse;
    };
    let raw_params = parsed.root.member("params").map(|node| node.raw(raw));
    let routed = match raw_params {
        Some(params) => format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":{},\"params\":{params}}}",
            serde_json::to_string(method).expect("method is a JSON string")
        ),
        None => format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":{}}}",
            serde_json::to_string(method).expect("method is a JSON string")
        ),
    };
    let context = Arc::new(DispatchContext {
        raw_params: raw_params.map(str::to_string),
        ..DispatchContext::default()
    });
    let module = build_rpc_module_from_arc(Arc::clone(&context));
    let response = futures::executor::block_on(module.raw_json_request(&routed, 1));
    if response.is_err() {
        return DispatchResult::NoResponse;
    }
    cancelled.extend(
        context
            .cancelled_sessions
            .lock()
            .expect("cancelled sessions")
            .drain(..),
    );
    DispatchResult::NotificationHandled
}
