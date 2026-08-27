//! jsonrpsee inbound method dispatch for the ACP v1 peer.
//!
//! Raw `params` bytes are retained via `jsonrpsee_types::Params::as_str`.
//! Unstable elicitation methods are not registered.

use jsonrpsee::RpcModule;
use jsonrpsee_types::Params;

use super::AcpTransportCounters;
use super::bridge::BridgeFacade;
use super::classify::InboundRequest;
use super::dto::{
    SessionAdmissionDto, decode_session_load, decode_session_new, initialize_result,
    raw_kind_is_object,
};
use super::envelope::{invalid_params, method_not_found, success_response};
use super::raw_json::JsonRpcId;

/// If this fails to type-check, return the transport-selection prompt.
const JSONRPSEE_RAW_PARAMS_API: fn(&Params<'_>) -> Option<&str> = Params::as_str;

const INBOUND_METHODS: &[&str] = &[
    "initialize",
    "session/new",
    "session/load",
    "session/cancel",
    "session/prompt",
];

pub fn build_rpc_module() -> RpcModule<()> {
    let mut module = RpcModule::new(());
    module
        .register_method("initialize", |params, _, _| {
            let _ = JSONRPSEE_RAW_PARAMS_API(&params);
            initialize_result()
        })
        .expect("initialize is unique");
    module
        .register_method("session/new", |params, _, _| {
            let _ = JSONRPSEE_RAW_PARAMS_API(&params);
            serde_json::json!({ "sessionId": "deferred" })
        })
        .expect("session/new is unique");
    module
        .register_method("session/load", |params, _, _| {
            let _ = JSONRPSEE_RAW_PARAMS_API(&params);
            serde_json::json!({})
        })
        .expect("session/load is unique");
    module
        .register_method("session/cancel", |params, _, _| {
            let _ = JSONRPSEE_RAW_PARAMS_API(&params);
            serde_json::Value::Null
        })
        .expect("session/cancel is unique");
    module
        .register_method("session/prompt", |params, _, _| {
            let _ = JSONRPSEE_RAW_PARAMS_API(&params);
            serde_json::json!({ "stopReason": "end_turn" })
        })
        .expect("session/prompt is unique");
    module
}

pub fn registered_method_names() -> Vec<&'static str> {
    INBOUND_METHODS.to_vec()
}

pub fn method_is_registered(method: &str) -> bool {
    INBOUND_METHODS.contains(&method)
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
    bridge: &BridgeFacade,
    counters: &mut AcpTransportCounters,
    cancelled: &mut Vec<String>,
) -> DispatchResult {
    let params = Params::new(request.raw_params.as_deref());
    let raw = JSONRPSEE_RAW_PARAMS_API(&params);
    if elicitation_is_rejected(&request.method) || !method_is_registered(&request.method) {
        return DispatchResult::Response(method_not_found(&request.id));
    }
    match request.method.as_str() {
        "initialize" => {
            DispatchResult::Response(success_response(&request.id, initialize_result()))
        }
        "session/new" => dispatch_session_new(request, raw, bridge, counters),
        "session/load" => dispatch_session_load(request, raw, bridge, counters),
        "session/prompt" => DispatchResult::Response(success_response(
            &request.id,
            serde_json::json!({ "stopReason": "end_turn" }),
        )),
        "session/cancel" => {
            if let Some(session_id) = request
                .params
                .as_ref()
                .and_then(|node| node.member("sessionId"))
                .and_then(|node| node.as_str())
            {
                cancelled.push(session_id.to_string());
            }
            DispatchResult::Response(success_response(&request.id, serde_json::Value::Null))
        }
        _ => DispatchResult::Response(method_not_found(&request.id)),
    }
}

pub fn dispatch_notification(
    method: &str,
    raw_params: Option<&str>,
    params_node: Option<&super::raw_json::RawNode>,
    cancelled: &mut Vec<String>,
) -> DispatchResult {
    let params = Params::new(raw_params);
    let _ = JSONRPSEE_RAW_PARAMS_API(&params);
    match method {
        "session/cancel" => {
            if let Some(session_id) = params_node
                .and_then(|node| node.member("sessionId"))
                .and_then(|node| node.as_str())
            {
                cancelled.push(session_id.to_string());
            }
            DispatchResult::NotificationHandled
        }
        "$/cancel_request" => DispatchResult::NotificationHandled,
        _ => DispatchResult::NoResponse,
    }
}

fn dispatch_session_new(
    request: &InboundRequest,
    raw: Option<&str>,
    bridge: &BridgeFacade,
    counters: &mut AcpTransportCounters,
) -> DispatchResult {
    let Some(raw) = raw else {
        return DispatchResult::Response(invalid_params(&request.id, "params required"));
    };
    let Some(node) = request.params.as_ref() else {
        return DispatchResult::Response(invalid_params(&request.id, "params required"));
    };
    if !raw_kind_is_object(node) {
        return DispatchResult::Response(invalid_params(&request.id, "params must be an object"));
    }
    match decode_session_new(raw, node, counters) {
        Ok(dto) => {
            let receipt = bridge.admit(&SessionAdmissionDto::New(dto), counters);
            DispatchResult::Response(success_response(
                &request.id,
                serde_json::json!({
                    "sessionId": format!("acp-session-{}", receipt.server_count)
                }),
            ))
        }
        Err(err) => DispatchResult::Response(invalid_params(&request.id, &err.to_string())),
    }
}

fn dispatch_session_load(
    request: &InboundRequest,
    raw: Option<&str>,
    bridge: &BridgeFacade,
    counters: &mut AcpTransportCounters,
) -> DispatchResult {
    let Some(raw) = raw else {
        return DispatchResult::Response(invalid_params(&request.id, "params required"));
    };
    let Some(node) = request.params.as_ref() else {
        return DispatchResult::Response(invalid_params(&request.id, "params required"));
    };
    match decode_session_load(raw, node, counters) {
        Ok(dto) => {
            let _receipt = bridge.admit(&SessionAdmissionDto::Load(dto), counters);
            DispatchResult::Response(success_response(&request.id, serde_json::json!({})))
        }
        Err(err) => DispatchResult::Response(invalid_params(&request.id, &err.to_string())),
    }
}

pub fn request_id_json(id: &JsonRpcId) -> String {
    id.to_json()
}
