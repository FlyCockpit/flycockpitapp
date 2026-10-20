//! Lossless structural DTOs for `session/new` and `session/load`.
//!
//! Built from the owned raw parser before any official ACP schema decode.
//! Shape, declared byte, and count validation happen here. A failure produces
//! no partial DTO.

use super::AcpTransportCounters;
use super::codec::ACP_FORWARDED_MCP_VECTOR_MAX_BYTES_V1;
use super::raw_json::RawNode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DtoError {
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
pub(crate) enum SessionAdmissionDto {
    New(SessionNewDto),
    Load(SessionLoadDto),
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SessionNewDto {
    pub cwd: String,
    pub mcp_servers: Vec<McpServerDto>,
    pub additional_directories: Vec<String>,
    pub raw_params: String,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SessionLoadDto {
    pub cwd: String,
    pub session_id: String,
    pub mcp_servers: Vec<McpServerDto>,
    pub additional_directories: Vec<String>,
    pub raw_params: String,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum McpServerDto {
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

// The raw admission JSON carries the editor's MCP env/header values verbatim:
// diagnostics get its length only.
impl std::fmt::Debug for SessionNewDto {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionNewDto")
            .field("cwd", &self.cwd)
            .field("mcp_servers", &self.mcp_servers)
            .field("additional_directories", &self.additional_directories)
            .field("raw_params_len", &self.raw_params.len())
            .finish()
    }
}

impl std::fmt::Debug for SessionLoadDto {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionLoadDto")
            .field("cwd", &self.cwd)
            .field("session_id", &self.session_id)
            .field("mcp_servers", &self.mcp_servers)
            .field("additional_directories", &self.additional_directories)
            .field("raw_params_len", &self.raw_params.len())
            .finish()
    }
}

// Stdio argv can carry `--token=…` and URLs can carry userinfo or query
// tokens: argument counts and redacted URLs only.
impl std::fmt::Debug for McpServerDto {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdio {
                name,
                command,
                args,
                env,
            } => formatter
                .debug_struct("Stdio")
                .field("name", name)
                .field("command", command)
                .field("argument_count", &args.len())
                .field("env", env)
                .finish(),
            Self::Http { name, url, headers } | Self::Sse { name, url, headers } => formatter
                .debug_struct(if matches!(self, Self::Http { .. }) {
                    "Http"
                } else {
                    "Sse"
                })
                .field("name", name)
                .field(
                    "url",
                    &cockpit_config::config::value_free::redacted_url(url),
                )
                .field("headers", headers)
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct NameValueDto {
    pub name: String,
    pub value: String,
}

// Env and header values carry credentials: diagnostics get the name only.
impl std::fmt::Debug for NameValueDto {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NameValueDto")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

pub(crate) fn decode_session_new(
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

pub(crate) fn decode_session_load(
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
    #[cfg(test)]
    pub(crate) fn mcp_servers(&self) -> &[McpServerDto] {
        match self {
            Self::New(dto) => &dto.mcp_servers,
            Self::Load(dto) => &dto.mcp_servers,
        }
    }
}

pub(crate) fn initialize_result() -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": 1,
        "agentCapabilities": {
            "loadSession": true,
            "sessionCapabilities": { "list": {} }
        },
        "agentInfo": {
            "name": "cockpit",
            "title": "Cockpit",
            "version": "0.1.0"
        },
        "authMethods": []
    })
}

#[cfg(test)]
mod debug_hygiene_tests {
    use super::*;

    /// Secrets I1 class sweep: ACP-supplied MCP env / header values never
    /// reach `{:?}` output of the DTOs.
    #[test]
    fn mcp_server_dto_debug_never_prints_env_or_secret_values() {
        const SENTINEL: &str = "dtoDebugSentinel2c7f";
        let server = McpServerDto::Stdio {
            name: "demo".to_string(),
            command: "/usr/bin/server".to_string(),
            args: vec![],
            env: vec![NameValueDto {
                name: "API_TOKEN".to_string(),
                value: SENTINEL.to_string(),
            }],
        };
        for rendered in [format!("{server:?}"), format!("{server:#?}")] {
            assert!(!rendered.contains(SENTINEL), "{rendered}");
            assert!(rendered.contains("API_TOKEN"), "{rendered}");
        }
    }
}

#[cfg(test)]
mod raw_params_debug_tests {
    use super::*;

    /// Secrets r2 C1: the raw ACP admission JSON (which carries the editor's
    /// MCP env/header values verbatim) and stdio argv never print.
    #[test]
    fn admission_dto_debug_hides_raw_params_and_argv() {
        let secret = ["NovelDebug515", "Secret78529"].concat();
        let dto = SessionNewDto {
            cwd: "/workspace".into(),
            mcp_servers: vec![McpServerDto::Stdio {
                name: "demo".into(),
                command: "/usr/bin/server".into(),
                args: vec![format!("--token={secret}")],
                env: vec![],
            }],
            additional_directories: vec![],
            raw_params: format!(r#"{{"env":[{{"name":"API_KEY","value":"{secret}"}}]}}"#),
        };
        let rendered = format!("{dto:?}");
        assert!(!rendered.contains(&secret), "{rendered}");
        assert!(rendered.contains("raw_params_len"), "{rendered}");
    }
}
