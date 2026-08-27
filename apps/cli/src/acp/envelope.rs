//! JSON-RPC 2.0 envelope helpers for the ACP stdio peer.
//!
//! This module owns request/response/notification serialization. It has no
//! MCP connection, tool execution, or proto-ingress conversion path.

use super::classify::JSON_RPC_VERSION;
use super::raw_json::JsonRpcId;
use jsonrpsee_types::error::{
    INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE, INVALID_REQUEST_CODE, METHOD_NOT_FOUND_CODE,
    PARSE_ERROR_CODE,
};
use serde_json::{Value, json};

pub fn success_response(id: &JsonRpcId, result: Value) -> String {
    json!({
        "jsonrpc": JSON_RPC_VERSION,
        "id": id_value(id),
        "result": result,
    })
    .to_string()
}

pub fn error_response(id: Option<&JsonRpcId>, code: i32, message: &str) -> Option<String> {
    let id = id.filter(|id| !matches!(id, JsonRpcId::Null))?;
    Some(
        json!({
            "jsonrpc": JSON_RPC_VERSION,
            "id": id_value(id),
            "error": { "code": code, "message": message },
        })
        .to_string(),
    )
}

pub fn parse_error(id: Option<&JsonRpcId>) -> Option<String> {
    error_response(id, PARSE_ERROR_CODE, "Parse error")
}

pub fn invalid_request(id: Option<&JsonRpcId>) -> Option<String> {
    error_response(id, INVALID_REQUEST_CODE, "Invalid Request")
}

pub fn method_not_found(id: &JsonRpcId) -> String {
    error_response(Some(id), METHOD_NOT_FOUND_CODE, "Method not found")
        .expect("request id is present")
}

pub fn invalid_params(id: &JsonRpcId, message: &str) -> String {
    error_response(Some(id), INVALID_PARAMS_CODE, message).expect("request id is present")
}

pub fn internal_error(id: &JsonRpcId, message: &str) -> String {
    error_response(Some(id), INTERNAL_ERROR_CODE, message).expect("request id is present")
}

pub fn notification(method: &str, params: Value) -> String {
    json!({
        "jsonrpc": JSON_RPC_VERSION,
        "method": method,
        "params": params,
    })
    .to_string()
}

pub fn request(id: &str, method: &str, params: Value) -> String {
    json!({
        "jsonrpc": JSON_RPC_VERSION,
        "id": id,
        "method": method,
        "params": params,
    })
    .to_string()
}

pub fn cancel_request_notification(request_id: &str) -> String {
    notification("$/cancel_request", json!({ "requestId": request_id }))
}

fn id_value(id: &JsonRpcId) -> Value {
    match id {
        JsonRpcId::Null => Value::Null,
        JsonRpcId::Number(n) => {
            if let Ok(as_u64) = n.parse::<u64>() {
                Value::from(as_u64)
            } else {
                Value::from(n.clone())
            }
        }
        JsonRpcId::String(s) => Value::from(s.clone()),
    }
}

pub fn assert_jsonrpc_2_0(frame: &str) -> bool {
    frame.contains("\"jsonrpc\":\"2.0\"")
}
