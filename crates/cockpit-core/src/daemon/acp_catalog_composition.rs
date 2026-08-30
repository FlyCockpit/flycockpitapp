//! Internal ACP Code-root/catalog composition boundary.
//!
//! The public daemon routes call only this service. Implementations must use
//! the existing Code-root create/attach/close seams exactly once and make the
//! base operation plus forwarded-catalog binding all-or-nothing. There is no
//! public install/release RPC and no serialized binding handle.
//!
//! The implementation owns the boot-local idempotency record for the complete
//! composition fingerprint, including authenticated principal and the
//! server-read capture generation on attach. Identical concurrent requests
//! coalesce; conflicting request-id reuse must fail before calling either the
//! base seam or catalog machinery. Close derives its target only from the
//! capability and delegates to `CloseCodeRootAttachmentV1` exactly once.

use async_trait::async_trait;
use cockpit_proto as proto;

use crate::daemon::principal::ClientPrincipal;

#[async_trait]
pub(crate) trait AcpCatalogCompositionServiceV1: Send + Sync {
    async fn create_code_root(
        &self,
        principal: &ClientPrincipal,
        request: proto::CreateCodeRootWithAcpIngressV1Request,
    ) -> Result<proto::CreateCodeRootWithAcpIngressV1Result, proto::ErrorPayload>;

    async fn attach_existing_code_root(
        &self,
        principal: &ClientPrincipal,
        request: proto::AttachExistingCodeRootWithAcpIngressV1Request,
    ) -> Result<proto::AttachExistingCodeRootWithAcpIngressV1Result, proto::ErrorPayload>;

    async fn close_code_root_attachment(
        &self,
        principal: &ClientPrincipal,
        request: proto::CloseAcpCodeRootAttachmentV1Request,
    ) -> Result<proto::CloseAcpCodeRootAttachmentV1Result, proto::ErrorPayload>;
}
