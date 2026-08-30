//! Bridge facade: the only CLI production converter from the private DTO to
//! `cockpit_proto::AcpForwardedMcpIngressV1`.
//!
//! This module does not connect MCP servers, execute tools, or call catalog
//! `Install*` / `Release*` lifecycle APIs.

use cockpit_proto::{
    AcpForwardedMcpDeclarationV1, AcpForwardedMcpIngressV1, AcpForwardedMcpTransportV1,
    AcpNameValuePairV1, OpaqueAsciiId128V1,
};
use sha2::{Digest, Sha256};

use super::AcpTransportCounters;
use super::dto::{McpServerDto, NameValueDto, SessionAdmissionDto, SessionLoadDto, SessionNewDto};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionAdmissionReceipt {
    pub method: SessionAdmissionMethod,
    pub server_count: usize,
    pub ingress: AcpForwardedMcpIngressV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionAdmissionMethod {
    New,
    Load,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BridgeError(String);

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BridgeError {}

#[derive(Debug, Default)]
pub(crate) struct BridgeFacade;

impl BridgeFacade {
    pub(crate) fn admit(
        &self,
        dto: &SessionAdmissionDto,
        counters: &mut AcpTransportCounters,
    ) -> Result<SessionAdmissionReceipt, BridgeError> {
        let ingress = self.to_ingress(dto)?;
        counters.bridge_conversions += 1;
        Ok(SessionAdmissionReceipt {
            method: match dto {
                SessionAdmissionDto::New(_) => SessionAdmissionMethod::New,
                SessionAdmissionDto::Load(_) => SessionAdmissionMethod::Load,
            },
            server_count: dto.mcp_servers().len(),
            ingress,
        })
    }

    pub(crate) fn to_ingress(
        &self,
        dto: &SessionAdmissionDto,
    ) -> Result<AcpForwardedMcpIngressV1, BridgeError> {
        let ingress = match dto {
            SessionAdmissionDto::New(new) => self.from_new(new),
            SessionAdmissionDto::Load(load) => self.from_load(load),
        };
        ingress.validate().map_err(BridgeError)?;
        Ok(ingress)
    }

    fn from_new(&self, dto: &SessionNewDto) -> AcpForwardedMcpIngressV1 {
        AcpForwardedMcpIngressV1 {
            version: 1,
            declarations: dto.mcp_servers.iter().map(declaration_from_dto).collect(),
            client_provenance_id: opaque_digest("new", &dto.cwd),
            ingress_request_id: opaque_digest("request", &dto.raw_params),
        }
    }

    fn from_load(&self, dto: &SessionLoadDto) -> AcpForwardedMcpIngressV1 {
        AcpForwardedMcpIngressV1 {
            version: 1,
            declarations: dto.mcp_servers.iter().map(declaration_from_dto).collect(),
            client_provenance_id: opaque_digest("load", &dto.session_id),
            ingress_request_id: opaque_digest("request", &dto.raw_params),
        }
    }
}

fn opaque_digest(domain: &str, value: &str) -> OpaqueAsciiId128V1 {
    let digest = Sha256::digest([domain.as_bytes(), b"\0", value.as_bytes()].concat());
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    OpaqueAsciiId128V1::new(format!("{domain}-{digest}"))
        .expect("SHA-256 based ACP identity is bounded printable ASCII")
}

fn declaration_from_dto(server: &McpServerDto) -> AcpForwardedMcpDeclarationV1 {
    match server {
        McpServerDto::Stdio {
            name,
            command,
            args,
            env,
        } => AcpForwardedMcpDeclarationV1 {
            name: name.clone(),
            transport: AcpForwardedMcpTransportV1::Stdio {
                command: command.clone(),
                args: args.clone(),
                env: pairs(env),
            },
        },
        McpServerDto::Http { name, url, headers } => AcpForwardedMcpDeclarationV1 {
            name: name.clone(),
            transport: AcpForwardedMcpTransportV1::Http {
                url: url.clone(),
                headers: pairs(headers),
            },
        },
        McpServerDto::Sse { name, url, headers } => AcpForwardedMcpDeclarationV1 {
            name: name.clone(),
            transport: AcpForwardedMcpTransportV1::Sse {
                url: url.clone(),
                headers: pairs(headers),
            },
        },
    }
}

fn pairs(pairs: &[NameValueDto]) -> Vec<AcpNameValuePairV1> {
    pairs
        .iter()
        .map(|pair| AcpNameValuePairV1 {
            name: pair.name.clone(),
            value: pair.value.clone(),
        })
        .collect()
}
