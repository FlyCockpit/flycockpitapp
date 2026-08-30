//! Internal ACP Code-root/catalog composition boundary.
//!
//! Public routes compose the existing base create/attach/close operation with
//! this service's memory-only validation, binding, publication, and release.
//! No serialized install/release handle exists.

use cockpit_proto as proto;

pub(crate) trait AcpCatalogCompositionServiceV1: Send + Sync {
    fn validate_ingress(
        &self,
        cwd: &std::path::Path,
        ingress: &proto::AcpForwardedMcpIngressV1,
    ) -> Result<(), proto::ErrorPayload>;

    fn bind_catalog(
        &self,
        root_id: uuid::Uuid,
        attachment: &proto::CodeRootAttachmentCapabilityV1,
        cwd: &std::path::Path,
        ingress: &proto::AcpForwardedMcpIngressV1,
        slot: std::sync::Arc<crate::mcp::forwarded::ForwardedCatalogSlot>,
    ) -> Result<(), proto::ErrorPayload>;

    fn release_catalog(
        &self,
        root_id: uuid::Uuid,
        attachment: &proto::CodeRootAttachmentCapabilityV1,
    );
}

#[derive(Default)]
pub(crate) struct DaemonAcpCatalogCompositionV1 {
    registry: crate::mcp::forwarded::AcpForwardedMcpRegistryV1,
}

impl DaemonAcpCatalogCompositionV1 {
    fn persistent_names(cwd: &std::path::Path) -> Vec<String> {
        crate::mcp::resolver::EffectiveCatalogResolver::for_cwd(cwd)
            .catalog()
            .server_names()
            .map(str::to_string)
            .collect()
    }

    fn semantic_error(error: anyhow::Error) -> proto::ErrorPayload {
        proto::ErrorPayload {
            code: proto::ErrorCode::InvalidIngress,
            message: error
                .chain()
                .next()
                .map(ToString::to_string)
                .unwrap_or_else(|| "acp_mcp_invalid_declaration".to_string()),
        }
    }
}

impl AcpCatalogCompositionServiceV1 for DaemonAcpCatalogCompositionV1 {
    fn validate_ingress(
        &self,
        cwd: &std::path::Path,
        ingress: &proto::AcpForwardedMcpIngressV1,
    ) -> Result<(), proto::ErrorPayload> {
        self.registry
            .validate(ingress, Self::persistent_names(cwd))
            .map_err(Self::semantic_error)
    }

    fn bind_catalog(
        &self,
        root_id: uuid::Uuid,
        attachment: &proto::CodeRootAttachmentCapabilityV1,
        cwd: &std::path::Path,
        ingress: &proto::AcpForwardedMcpIngressV1,
        slot: std::sync::Arc<crate::mcp::forwarded::ForwardedCatalogSlot>,
    ) -> Result<(), proto::ErrorPayload> {
        self.registry
            .bind(
                root_id,
                attachment,
                ingress,
                Self::persistent_names(cwd),
                slot,
            )
            .map(|_| ())
            .map_err(Self::semantic_error)
    }

    fn release_catalog(
        &self,
        root_id: uuid::Uuid,
        attachment: &proto::CodeRootAttachmentCapabilityV1,
    ) {
        self.registry.release_attachment(root_id, attachment);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn service_publishes_and_releases_only_the_bound_attachment() {
        let service = DaemonAcpCatalogCompositionV1::default();
        let temp = tempfile::tempdir().unwrap();
        let ingress = proto::AcpForwardedMcpIngressV1 {
            version: 1,
            declarations: vec![proto::AcpForwardedMcpDeclarationV1 {
                name: "docs".to_string(),
                transport: proto::AcpForwardedMcpTransportV1::Http {
                    url: "https://example.com/mcp".to_string(),
                    headers: vec![],
                },
            }],
            client_provenance_id: proto::OpaqueAsciiId128V1::new("editor").unwrap(),
            ingress_request_id: proto::OpaqueAsciiId128V1::new("request").unwrap(),
        };
        let root = uuid::Uuid::new_v4();
        let attachment =
            proto::CodeRootAttachmentCapabilityV1::new_opaque("attachment").unwrap();
        let slot = Arc::new(crate::mcp::forwarded::ForwardedCatalogSlot::default());

        service.validate_ingress(temp.path(), &ingress).unwrap();
        service
            .bind_catalog(
                root,
                &attachment,
                temp.path(),
                &ingress,
                slot.clone(),
            )
            .unwrap();
        let epoch = slot.active().expect("published epoch");
        assert_eq!(epoch.root_id(), root);

        service.release_catalog(root, &attachment);
        assert!(slot.active().is_none());
        assert!(epoch.is_released());
    }
}
