//! Bridge facade: the only CLI production converter from the private DTO to
//! `cockpit_proto::AcpForwardedMcpIngressV1`.
//!
//! This module does not connect MCP servers, execute tools, or call catalog
//! `Install*` / `Release*` lifecycle APIs.

use cockpit_proto::{
    AcpForwardedMcpDeclarationV1, AcpForwardedMcpIngressV1, AcpForwardedMcpProvenanceV1,
    AcpForwardedMcpTransportV1, AcpNameValuePairV1, AcpSessionAdmissionMethodV1,
};

use super::AcpTransportCounters;
use super::dto::{McpServerDto, NameValueDto, SessionAdmissionDto, SessionLoadDto, SessionNewDto};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionAdmissionReceipt {
    pub method: AcpSessionAdmissionMethodV1,
    pub server_count: usize,
    pub ingress: AcpForwardedMcpIngressV1,
}

#[derive(Debug, Default)]
pub(crate) struct BridgeFacade;

impl BridgeFacade {
    pub(crate) fn admit(
        &self,
        dto: &SessionAdmissionDto,
        counters: &mut AcpTransportCounters,
    ) -> SessionAdmissionReceipt {
        let ingress = self.to_ingress(dto);
        counters.bridge_conversions += 1;
        SessionAdmissionReceipt {
            method: match dto {
                SessionAdmissionDto::New(_) => AcpSessionAdmissionMethodV1::SessionNew,
                SessionAdmissionDto::Load(_) => AcpSessionAdmissionMethodV1::SessionLoad,
            },
            server_count: dto.mcp_servers().len(),
            ingress,
        }
    }

    pub(crate) fn to_ingress(&self, dto: &SessionAdmissionDto) -> AcpForwardedMcpIngressV1 {
        match dto {
            SessionAdmissionDto::New(new) => self.from_new(new),
            SessionAdmissionDto::Load(load) => self.from_load(load),
        }
    }

    fn from_new(&self, dto: &SessionNewDto) -> AcpForwardedMcpIngressV1 {
        AcpForwardedMcpIngressV1 {
            declarations: dto.mcp_servers.iter().map(declaration_from_dto).collect(),
            provenance: AcpForwardedMcpProvenanceV1 {
                method: AcpSessionAdmissionMethodV1::SessionNew,
                session_id: None,
            },
        }
    }

    fn from_load(&self, dto: &SessionLoadDto) -> AcpForwardedMcpIngressV1 {
        AcpForwardedMcpIngressV1 {
            declarations: dto.mcp_servers.iter().map(declaration_from_dto).collect(),
            provenance: AcpForwardedMcpProvenanceV1 {
                method: AcpSessionAdmissionMethodV1::SessionLoad,
                session_id: Some(dto.session_id.clone()),
            },
        }
    }
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
