//! Classify an inbound ACP line without losing raw `params` bytes.

use super::raw_json::{
    JsonRpcId, ParsedFrame, RawJsonError, RawJsonErrorKind, RawNode, parse_frame,
};

pub const JSON_RPC_VERSION: &str = "2.0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassifyError {
    DuplicateMember {
        path: String,
        name: String,
        request_id: Option<JsonRpcId>,
    },
    InvalidJson {
        request_id: Option<JsonRpcId>,
    },
    InvalidJsonrpc {
        request_id: Option<JsonRpcId>,
    },
    MissingMethod {
        request_id: Option<JsonRpcId>,
    },
    BothRequestAndResponse {
        request_id: Option<JsonRpcId>,
    },
}

impl ClassifyError {
    pub fn request_id(&self) -> Option<&JsonRpcId> {
        match self {
            Self::DuplicateMember { request_id, .. }
            | Self::InvalidJson { request_id }
            | Self::InvalidJsonrpc { request_id }
            | Self::MissingMethod { request_id }
            | Self::BothRequestAndResponse { request_id } => request_id.as_ref(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundMessage {
    Request(InboundRequest),
    Notification(InboundNotification),
    Response(InboundResponse),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundRequest {
    pub id: JsonRpcId,
    pub method: String,
    pub raw_params: Option<String>,
    pub params: Option<RawNode>,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundNotification {
    pub method: String,
    pub raw_params: Option<String>,
    pub params: Option<RawNode>,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundResponse {
    pub id: JsonRpcId,
    pub result: Option<RawNode>,
    pub error: Option<RawNode>,
    pub raw: String,
}

pub fn classify(frame: &str) -> Result<InboundMessage, ClassifyError> {
    let parsed = match parse_frame(frame) {
        Ok(parsed) => parsed,
        Err(RawJsonError {
            kind,
            unambiguous_request_id,
        }) => {
            return Err(match kind {
                RawJsonErrorKind::DuplicateMember { path, name } => {
                    ClassifyError::DuplicateMember {
                        path,
                        name,
                        request_id: unambiguous_request_id,
                    }
                }
                _ => ClassifyError::InvalidJson {
                    request_id: unambiguous_request_id,
                },
            });
        }
    };
    classify_parsed(frame, parsed)
}

fn classify_parsed(frame: &str, parsed: ParsedFrame) -> Result<InboundMessage, ClassifyError> {
    if parsed.root.as_object().is_none() {
        return Err(ClassifyError::InvalidJson { request_id: None });
    }

    let jsonrpc = parsed.root.member("jsonrpc");
    let jsonrpc_ok = matches!(jsonrpc.and_then(RawNode::as_str), Some(JSON_RPC_VERSION));
    if parsed.root.member_count("jsonrpc") != 1 || !jsonrpc_ok {
        return Err(ClassifyError::InvalidJsonrpc {
            request_id: parsed.unambiguous_request_id,
        });
    }

    let has_method = parsed.root.member("method").is_some();
    let has_result = parsed.root.member("result").is_some();
    let has_error = parsed.root.member("error").is_some();
    let id_node = parsed.root.member("id");

    if has_method && (has_result || has_error) {
        return Err(ClassifyError::BothRequestAndResponse {
            request_id: parsed.unambiguous_request_id,
        });
    }

    let params = parsed.root.member("params").cloned();
    let raw_params = params.as_ref().map(|node| node.raw(frame).to_string());

    if has_method {
        let method = parsed
            .root
            .member("method")
            .and_then(RawNode::as_str)
            .ok_or_else(|| ClassifyError::MissingMethod {
                request_id: parsed.unambiguous_request_id.clone(),
            })?
            .to_string();
        match id_node {
            Some(_) => {
                let id = parsed
                    .unambiguous_request_id
                    .ok_or(ClassifyError::InvalidJsonrpc { request_id: None })?;
                if !jsonrpsee_supports_id(&id) {
                    return Err(ClassifyError::InvalidJsonrpc {
                        request_id: Some(id),
                    });
                }
                Ok(InboundMessage::Request(InboundRequest {
                    id,
                    method,
                    raw_params,
                    params,
                    raw: frame.to_string(),
                }))
            }
            None => Ok(InboundMessage::Notification(InboundNotification {
                method,
                raw_params,
                params,
                raw: frame.to_string(),
            })),
        }
    } else if has_result ^ has_error {
        let id = parsed
            .unambiguous_request_id
            .ok_or(ClassifyError::InvalidJsonrpc { request_id: None })?;
        Ok(InboundMessage::Response(InboundResponse {
            id,
            result: parsed.root.member("result").cloned(),
            error: parsed.root.member("error").cloned(),
            raw: frame.to_string(),
        }))
    } else if has_result && has_error {
        Err(ClassifyError::BothRequestAndResponse {
            request_id: parsed.unambiguous_request_id,
        })
    } else {
        Err(ClassifyError::MissingMethod {
            request_id: parsed.unambiguous_request_id,
        })
    }
}

fn jsonrpsee_supports_id(id: &JsonRpcId) -> bool {
    match id {
        JsonRpcId::Number(number) => number.parse::<u64>().is_ok(),
        JsonRpcId::Null | JsonRpcId::String(_) => true,
    }
}
