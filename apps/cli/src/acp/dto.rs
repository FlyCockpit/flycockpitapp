//! Lossless structural DTOs for `session/new` and `session/load`.
//!
//! Built from the owned raw parser before any official ACP schema decode.
//! Shape, declared byte, and count validation happen here. A failure produces
//! no partial DTO.

use super::AcpTransportCounters;
use super::codec::ACP_FORWARDED_MCP_VECTOR_MAX_BYTES_V1;
use super::raw_json::{RawKind, RawNode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DtoError {
    ParamsNotObject,
    MissingField(&'static str),
    FieldType(&'static str),
    McpVectorOverLimit { bytes: usize },
    MixedOrUnknownTransport,
    SchemaInconsistent,
}

impl std::fmt::Display for DtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParamsNotObject => f.write_str("params must be an object"),
            Self::MissingField(name) => write!(f, "missing field {name}"),
            Self::FieldType(name) => write!(f, "invalid type for field {name}"),
            Self::McpVectorOverLimit { bytes } => {
                write!(
                    f,
                    "mcpServers exceeds {ACP_FORWARDED_MCP_VECTOR_MAX_BYTES_V1} bytes ({bytes})"
                )
            }
            Self::MixedOrUnknownTransport => {
                f.write_str("malformed or mixed mcpServers transport vector")
            }
            Self::SchemaInconsistent => {
                f.write_str("ACP schema consistency check failed after lossless DTO validation")
            }
        }
    }
}

impl std::error::Error for DtoError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAdmissionDto {
    New(SessionNewDto),
    Load(SessionLoadDto),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionNewDto {
    pub cwd: String,
    pub mcp_servers: Vec<McpServerDto>,
    pub additional_directories: Vec<String>,
    pub raw_params: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLoadDto {
    pub cwd: String,
    pub session_id: String,
    pub mcp_servers: Vec<McpServerDto>,
    pub additional_directories: Vec<String>,
    pub raw_params: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpServerDto {
    Stdio {
        name: String,
        command: String,
        args: Vec<String>,
        env: Vec<NameValueDto>,
    },
    Http {
        name: String,
        url: String,
        headers: Vec<NameValueDto>,
    },
    Sse {
        name: String,
        url: String,
        headers: Vec<NameValueDto>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameValueDto {
    pub name: String,
    pub value: String,
}

pub fn decode_session_new(
    raw_params: &str,
    params: &RawNode,
    counters: &mut AcpTransportCounters,
) -> Result<SessionNewDto, DtoError> {
    let dto = decode_new_lossless(raw_params, params)?;
    counters.schema_decode_attempts += 1;
    consistency_check_new(raw_params)?;
    counters.dto_produced += 1;
    Ok(dto)
}

pub fn decode_session_load(
    raw_params: &str,
    params: &RawNode,
    counters: &mut AcpTransportCounters,
) -> Result<SessionLoadDto, DtoError> {
    let dto = decode_load_lossless(raw_params, params)?;
    counters.schema_decode_attempts += 1;
    consistency_check_load(raw_params)?;
    counters.dto_produced += 1;
    Ok(dto)
}

fn decode_new_lossless(raw_params: &str, params: &RawNode) -> Result<SessionNewDto, DtoError> {
    let members = params.as_object().ok_or(DtoError::ParamsNotObject)?;
    let _ = members;
    let cwd = required_string(params, "cwd")?;
    let mcp_servers = decode_mcp_servers(raw_params, params)?;
    let additional_directories = optional_string_array(params, "additionalDirectories")?;
    Ok(SessionNewDto {
        cwd,
        mcp_servers,
        additional_directories,
        raw_params: raw_params.to_string(),
    })
}

fn decode_load_lossless(raw_params: &str, params: &RawNode) -> Result<SessionLoadDto, DtoError> {
    let cwd = required_string(params, "cwd")?;
    let session_id = required_string(params, "sessionId")?;
    let mcp_servers = decode_mcp_servers(raw_params, params)?;
    let additional_directories = optional_string_array(params, "additionalDirectories")?;
    Ok(SessionLoadDto {
        cwd,
        session_id,
        mcp_servers,
        additional_directories,
        raw_params: raw_params.to_string(),
    })
}

fn decode_mcp_servers(_raw_params: &str, params: &RawNode) -> Result<Vec<McpServerDto>, DtoError> {
    let node = params
        .member("mcpServers")
        .ok_or(DtoError::MissingField("mcpServers"))?;
    let bytes = node.end - node.start;
    if bytes > ACP_FORWARDED_MCP_VECTOR_MAX_BYTES_V1 {
        return Err(DtoError::McpVectorOverLimit { bytes });
    }
    let items = node.as_array().ok_or(DtoError::FieldType("mcpServers"))?;
    let mut servers = Vec::with_capacity(items.len());
    for item in items {
        servers.push(decode_one_server(item)?);
    }
    Ok(servers)
}

fn decode_one_server(node: &RawNode) -> Result<McpServerDto, DtoError> {
    if node.as_object().is_none() {
        return Err(DtoError::FieldType("mcpServers[]"));
    }
    let name = required_string(node, "name")?;
    let type_name = match node.member("type") {
        Some(discriminator) => Some(
            discriminator
                .as_str()
                .ok_or(DtoError::MixedOrUnknownTransport)?,
        ),
        None => None,
    };
    match type_name {
        None | Some("stdio") if !has_any_member(node, &["url", "headers"]) => {
            Ok(McpServerDto::Stdio {
                name,
                command: required_string(node, "command")?,
                args: optional_string_array(node, "args")?,
                env: optional_pairs(node, "env")?,
            })
        }
        Some("http") if !has_any_member(node, &["command", "args", "env"]) => {
            Ok(McpServerDto::Http {
                name,
                url: required_string(node, "url")?,
                headers: optional_pairs(node, "headers")?,
            })
        }
        Some("sse") if !has_any_member(node, &["command", "args", "env"]) => {
            Ok(McpServerDto::Sse {
                name,
                url: required_string(node, "url")?,
                headers: optional_pairs(node, "headers")?,
            })
        }
        Some(_) => Err(DtoError::MixedOrUnknownTransport),
        _ => Err(DtoError::MixedOrUnknownTransport),
    }
}

fn has_any_member(node: &RawNode, names: &[&str]) -> bool {
    names.iter().any(|name| node.member(name).is_some())
}

fn required_string(node: &RawNode, name: &'static str) -> Result<String, DtoError> {
    node.member(name)
        .and_then(RawNode::as_str)
        .map(str::to_string)
        .ok_or(DtoError::MissingField(name))
}

fn optional_string_array(node: &RawNode, name: &'static str) -> Result<Vec<String>, DtoError> {
    let Some(value) = node.member(name) else {
        return Ok(Vec::new());
    };
    let items = value.as_array().ok_or(DtoError::FieldType(name))?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(item.as_str().ok_or(DtoError::FieldType(name))?.to_string());
    }
    Ok(out)
}

fn optional_pairs(node: &RawNode, name: &'static str) -> Result<Vec<NameValueDto>, DtoError> {
    let Some(value) = node.member(name) else {
        return Ok(Vec::new());
    };
    let items = value.as_array().ok_or(DtoError::FieldType(name))?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if item.as_object().is_none() {
            return Err(DtoError::FieldType(name));
        }
        out.push(NameValueDto {
            name: required_string(item, "name")?,
            value: required_string(item, "value")?,
        });
    }
    Ok(out)
}

fn consistency_check_new(raw_params: &str) -> Result<(), DtoError> {
    serde_json::from_str::<agent_client_protocol_schema::v1::NewSessionRequest>(raw_params)
        .map(|_| ())
        .map_err(|_| DtoError::SchemaInconsistent)
}

fn consistency_check_load(raw_params: &str) -> Result<(), DtoError> {
    serde_json::from_str::<agent_client_protocol_schema::v1::LoadSessionRequest>(raw_params)
        .map(|_| ())
        .map_err(|_| DtoError::SchemaInconsistent)
}

impl SessionAdmissionDto {
    pub fn mcp_servers(&self) -> &[McpServerDto] {
        match self {
            Self::New(dto) => &dto.mcp_servers,
            Self::Load(dto) => &dto.mcp_servers,
        }
    }
}

pub fn initialize_result() -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": 1,
        "agentCapabilities": {
            "loadSession": true,
            "promptCapabilities": {
                "image": false,
                "audio": false,
                "embeddedContext": false
            },
            "mcpCapabilities": {
                "http": true,
                "sse": true
            },
            "sessionCapabilities": {}
        },
        "agentInfo": {
            "name": "cockpit",
            "title": "Cockpit",
            "version": "0.1.0"
        },
        "authMethods": []
    })
}

/// Touch `RawKind` so admission keeps the lossless node, not a map.
pub fn raw_kind_is_object(node: &RawNode) -> bool {
    matches!(node.kind, RawKind::Object(_))
}
