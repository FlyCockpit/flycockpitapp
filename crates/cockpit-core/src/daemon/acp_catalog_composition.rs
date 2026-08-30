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

pub(crate) async fn create_route(
    service: &dyn AcpCatalogCompositionServiceV1,
    principal: &ClientPrincipal,
    request: proto::CreateCodeRootWithAcpIngressV1Request,
) -> Result<proto::CreateCodeRootWithAcpIngressV1Result, proto::ErrorPayload> {
    service.create_code_root(principal, request).await
}

pub(crate) async fn attach_route(
    service: &dyn AcpCatalogCompositionServiceV1,
    principal: &ClientPrincipal,
    request: proto::AttachExistingCodeRootWithAcpIngressV1Request,
) -> Result<proto::AttachExistingCodeRootWithAcpIngressV1Result, proto::ErrorPayload> {
    service.attach_existing_code_root(principal, request).await
}

pub(crate) async fn close_route(
    service: &dyn AcpCatalogCompositionServiceV1,
    principal: &ClientPrincipal,
    request: proto::CloseAcpCodeRootAttachmentV1Request,
) -> Result<proto::CloseAcpCodeRootAttachmentV1Result, proto::ErrorPayload> {
    service.close_code_root_attachment(principal, request).await
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Default)]
    struct RecordingComposition {
        creates: AtomicUsize,
        attaches: AtomicUsize,
        closes: AtomicUsize,
        create_requests: Mutex<
            Vec<(
                ClientPrincipal,
                proto::CreateCodeRootWithAcpIngressV1Request,
            )>,
        >,
        attach_requests: Mutex<
            Vec<(
                ClientPrincipal,
                proto::AttachExistingCodeRootWithAcpIngressV1Request,
            )>,
        >,
        close_requests: Mutex<Vec<(ClientPrincipal, proto::CloseAcpCodeRootAttachmentV1Request)>>,
    }

    fn observed() -> proto::ErrorPayload {
        proto::ErrorPayload {
            code: proto::ErrorCode::Unavailable,
            message: "observed".to_string(),
        }
    }

    #[async_trait]
    impl AcpCatalogCompositionServiceV1 for RecordingComposition {
        async fn create_code_root(
            &self,
            principal: &ClientPrincipal,
            request: proto::CreateCodeRootWithAcpIngressV1Request,
        ) -> Result<proto::CreateCodeRootWithAcpIngressV1Result, proto::ErrorPayload> {
            self.creates.fetch_add(1, Ordering::Relaxed);
            self.create_requests
                .lock()
                .unwrap()
                .push((principal.clone(), request));
            Err(observed())
        }

        async fn attach_existing_code_root(
            &self,
            principal: &ClientPrincipal,
            request: proto::AttachExistingCodeRootWithAcpIngressV1Request,
        ) -> Result<proto::AttachExistingCodeRootWithAcpIngressV1Result, proto::ErrorPayload>
        {
            self.attaches.fetch_add(1, Ordering::Relaxed);
            self.attach_requests
                .lock()
                .unwrap()
                .push((principal.clone(), request));
            Err(observed())
        }

        async fn close_code_root_attachment(
            &self,
            principal: &ClientPrincipal,
            request: proto::CloseAcpCodeRootAttachmentV1Request,
        ) -> Result<proto::CloseAcpCodeRootAttachmentV1Result, proto::ErrorPayload> {
            self.closes.fetch_add(1, Ordering::Relaxed);
            self.close_requests
                .lock()
                .unwrap()
                .push((principal.clone(), request));
            Err(observed())
        }
    }

    fn ingress() -> proto::AcpForwardedMcpIngressV1 {
        proto::AcpForwardedMcpIngressV1 {
            version: 1,
            declarations: vec![],
            client_provenance_id: proto::OpaqueAsciiId128V1::new("editor").unwrap(),
            ingress_request_id: proto::OpaqueAsciiId128V1::new("ingress").unwrap(),
        }
    }

    fn options() -> proto::CodeRootAttachOptionsV1 {
        proto::CodeRootAttachOptionsV1 {
            initial_model: None,
            model_override: None,
            no_sandbox: false,
            interactive: false,
            client_protocol_version: proto::PROTOCOL_VERSION,
            env_snapshot: None,
            env_policy: proto::EnvDriftPolicy::Daemon,
        }
    }

    #[tokio::test]
    async fn composed_routes_forward_the_exact_closed_contract_to_the_internal_service_once() {
        let service = RecordingComposition::default();
        let principal = ClientPrincipal::Owner;
        let create = proto::CreateCodeRootWithAcpIngressV1Request {
            base: proto::CreateCodeRootV1Request {
                workspace_selector: proto::CodeRootWorkspaceSelectorV1 {
                    path: "/workspace".to_string(),
                },
                logical_client_id: proto::OpaqueAsciiId128V1::new("editor").unwrap(),
                client_request_id: proto::OpaqueAsciiId128V1::new("create").unwrap(),
                options: options(),
            },
            ingress: ingress(),
        };
        assert!(
            create_route(&service, &principal, create.clone())
                .await
                .is_err()
        );

        let root_id = proto::CodeRootIdV1(uuid::Uuid::new_v4());
        let attach = proto::AttachExistingCodeRootWithAcpIngressV1Request {
            base: proto::AttachExistingCodeRootV1Request {
                root_id,
                capture_generation: root_id.capture_generation(),
                logical_client_id: proto::OpaqueAsciiId128V1::new("editor").unwrap(),
                client_request_id: proto::OpaqueAsciiId128V1::new("attach").unwrap(),
                replay_cursor: None,
                since_seq: None,
                options: options(),
            },
            ingress: ingress(),
        };
        assert!(
            attach_route(&service, &principal, attach.clone())
                .await
                .is_err()
        );

        let close = proto::CloseAcpCodeRootAttachmentV1Request {
            attachment_capability: proto::CodeRootAttachmentCapabilityV1::new_opaque("capability")
                .unwrap(),
            client_request_id: proto::OpaqueAsciiId128V1::new("close").unwrap(),
        };
        assert!(
            close_route(&service, &principal, close.clone())
                .await
                .is_err()
        );

        assert_eq!(service.creates.load(Ordering::Relaxed), 1);
        assert_eq!(service.attaches.load(Ordering::Relaxed), 1);
        assert_eq!(service.closes.load(Ordering::Relaxed), 1);
        assert_eq!(
            service.create_requests.lock().unwrap().as_slice(),
            &[(principal.clone(), create)]
        );
        assert_eq!(
            service.attach_requests.lock().unwrap().as_slice(),
            &[(principal.clone(), attach)]
        );
        assert_eq!(
            service.close_requests.lock().unwrap().as_slice(),
            &[(principal, close)]
        );
    }
}
