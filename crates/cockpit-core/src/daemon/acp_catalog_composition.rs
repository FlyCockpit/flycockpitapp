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

/// Whether a staged attachment is a new attach or an exact idempotent replay.
///
/// The distinction is intentionally supplied by the composition service,
/// which owns its complete idempotency record.  Dispatch uses it only after
/// validating the returned attachment: a new attachment always takes the
/// normal attach path, while an exact replay may retain an already matching
/// local attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcpCatalogAttachmentDispositionV1 {
    New,
    Replayed,
}

/// The service-facing, side-effect-free half of a connection attachment.
///
/// Staging records the one attachment that the service intends to return; it
/// never mutates the connection.  The route wrapper validates this staged
/// value against the successful result and commits it only then.  Therefore a
/// service error, cancellation, duplicate stage, or mismatched result cannot
/// leave a connection-local attachment installed.
#[async_trait]
pub(crate) trait AcpCatalogConnectionAttachmentV1: Send {
    async fn stage_code_root_attachment(
        &mut self,
        attachment: &proto::CodeRootAttachmentV1,
        disposition: AcpCatalogAttachmentDispositionV1,
    ) -> Result<(), proto::ErrorPayload>;
}

/// Dispatch-owned commit half of a staged connection attachment.
///
/// This is deliberately not exposed to composition services.  It retains the
/// mutable client state until the service has produced a successful result
/// whose capability exactly matches the staged value.
#[async_trait]
pub(crate) trait AcpCatalogConnectionAttachmentCommitV1: Send {
    async fn commit_code_root_attachment(
        &mut self,
        attachment: &proto::CodeRootAttachmentV1,
        options: &proto::CodeRootAttachOptionsV1,
        since_seq: Option<i64>,
        disposition: AcpCatalogAttachmentDispositionV1,
    ) -> Result<(), proto::ErrorPayload>;
}

/// An owned create composition that rolls its base/catalog work back when it
/// is dropped before [`Self::commit`].
///
/// Implementations must make `commit` infallible: it is called only after the
/// connection attachment has committed, and is the irreversible publication
/// point for the composed service work.
pub(crate) trait AcpCatalogCreateTransactionV1: Send {
    fn result(&self) -> &proto::CreateCodeRootWithAcpIngressV1Result;
    fn commit(self: Box<Self>) -> proto::CreateCodeRootWithAcpIngressV1Result;
}

/// An owned existing-root composition with the same rollback-on-drop rule as
/// [`AcpCatalogCreateTransactionV1`].
pub(crate) trait AcpCatalogAttachTransactionV1: Send {
    fn result(&self) -> &proto::AttachExistingCodeRootWithAcpIngressV1Result;
    fn commit(self: Box<Self>) -> proto::AttachExistingCodeRootWithAcpIngressV1Result;
}

struct PendingConnectionAttachment<'a> {
    connection: &'a mut dyn AcpCatalogConnectionAttachmentCommitV1,
    staged: Option<(
        proto::CodeRootAttachmentV1,
        AcpCatalogAttachmentDispositionV1,
    )>,
    stage_violation: bool,
}

impl<'a> PendingConnectionAttachment<'a> {
    fn new(connection: &'a mut dyn AcpCatalogConnectionAttachmentCommitV1) -> Self {
        Self {
            connection,
            staged: None,
            stage_violation: false,
        }
    }

    async fn commit(
        self,
        returned: &proto::CodeRootAttachmentV1,
        options: &proto::CodeRootAttachOptionsV1,
        since_seq: Option<i64>,
    ) -> Result<(), proto::ErrorPayload> {
        if self.stage_violation {
            return Err(proto::ErrorPayload {
                code: proto::ErrorCode::Conflict,
                message: "ACP composition attempted an invalid client-attachment stage".to_string(),
            });
        }
        let Some((staged, disposition)) = self.staged else {
            return Err(proto::ErrorPayload {
                code: proto::ErrorCode::Internal,
                message: "ACP composition returned success without staging a client attachment"
                    .to_string(),
            });
        };
        if staged != *returned {
            return Err(proto::ErrorPayload {
                code: proto::ErrorCode::Conflict,
                message:
                    "ACP composition staged an attachment different from its returned capability"
                        .to_string(),
            });
        }
        self.connection
            .commit_code_root_attachment(returned, options, since_seq, disposition)
            .await
    }
}

#[async_trait]
impl AcpCatalogConnectionAttachmentV1 for PendingConnectionAttachment<'_> {
    async fn stage_code_root_attachment(
        &mut self,
        attachment: &proto::CodeRootAttachmentV1,
        disposition: AcpCatalogAttachmentDispositionV1,
    ) -> Result<(), proto::ErrorPayload> {
        if self.staged.is_some() {
            self.stage_violation = true;
            return Err(proto::ErrorPayload {
                code: proto::ErrorCode::Conflict,
                message: "ACP composition attempted to stage more than one client attachment"
                    .to_string(),
            });
        }
        self.staged = Some((attachment.clone(), disposition));
        Ok(())
    }
}

#[async_trait]
pub(crate) trait AcpCatalogCompositionServiceV1: Send + Sync {
    /// Stage base create/catalog work and the one pending connection
    /// attachment. The returned transaction rolls its staged service work back
    /// unless dispatch later consumes it through `commit`.
    async fn create_code_root(
        &self,
        principal: &ClientPrincipal,
        request: proto::CreateCodeRootWithAcpIngressV1Request,
        connection: &mut dyn AcpCatalogConnectionAttachmentV1,
    ) -> Result<Box<dyn AcpCatalogCreateTransactionV1>, proto::ErrorPayload>;

    /// Stage base attach/catalog work and the one pending connection
    /// attachment. The returned transaction rolls its staged service work back
    /// unless dispatch later consumes it through `commit`.
    async fn attach_existing_code_root(
        &self,
        principal: &ClientPrincipal,
        request: proto::AttachExistingCodeRootWithAcpIngressV1Request,
        connection: &mut dyn AcpCatalogConnectionAttachmentV1,
    ) -> Result<Box<dyn AcpCatalogAttachTransactionV1>, proto::ErrorPayload>;

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
    connection: &mut dyn AcpCatalogConnectionAttachmentCommitV1,
) -> Result<proto::CreateCodeRootWithAcpIngressV1Result, proto::ErrorPayload> {
    let options = request.base.options.clone();
    let mut pending = PendingConnectionAttachment::new(connection);
    let transaction = service
        .create_code_root(principal, request, &mut pending)
        .await?;
    pending
        .commit(&transaction.result().base.attachment, &options, None)
        .await?;
    Ok(transaction.commit())
}

pub(crate) async fn attach_route(
    service: &dyn AcpCatalogCompositionServiceV1,
    principal: &ClientPrincipal,
    request: proto::AttachExistingCodeRootWithAcpIngressV1Request,
    connection: &mut dyn AcpCatalogConnectionAttachmentCommitV1,
) -> Result<proto::AttachExistingCodeRootWithAcpIngressV1Result, proto::ErrorPayload> {
    let options = request.base.options.clone();
    let since_seq = request.base.since_seq;
    let mut pending = PendingConnectionAttachment::new(connection);
    let transaction = service
        .attach_existing_code_root(principal, request, &mut pending)
        .await?;
    pending
        .commit(&transaction.result().base.attachment, &options, since_seq)
        .await?;
    Ok(transaction.commit())
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

    #[derive(Default)]
    struct RecordingConnectionAttachment {
        commits: AtomicUsize,
        committed: Mutex<
            Vec<(
                proto::CodeRootAttachmentV1,
                proto::CodeRootAttachOptionsV1,
                Option<i64>,
                AcpCatalogAttachmentDispositionV1,
            )>,
        >,
    }

    struct SuccessfulCreateComposition {
        result: proto::CreateCodeRootWithAcpIngressV1Result,
        creates: AtomicUsize,
    }

    struct SuccessfulCreateTransaction {
        result: proto::CreateCodeRootWithAcpIngressV1Result,
    }

    impl AcpCatalogCreateTransactionV1 for SuccessfulCreateTransaction {
        fn result(&self) -> &proto::CreateCodeRootWithAcpIngressV1Result {
            &self.result
        }

        fn commit(self: Box<Self>) -> proto::CreateCodeRootWithAcpIngressV1Result {
            self.result
        }
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
            _connection: &mut dyn AcpCatalogConnectionAttachmentV1,
        ) -> Result<Box<dyn AcpCatalogCreateTransactionV1>, proto::ErrorPayload> {
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
            _connection: &mut dyn AcpCatalogConnectionAttachmentV1,
        ) -> Result<Box<dyn AcpCatalogAttachTransactionV1>, proto::ErrorPayload> {
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

    #[async_trait]
    impl AcpCatalogCompositionServiceV1 for SuccessfulCreateComposition {
        async fn create_code_root(
            &self,
            _principal: &ClientPrincipal,
            _request: proto::CreateCodeRootWithAcpIngressV1Request,
            connection: &mut dyn AcpCatalogConnectionAttachmentV1,
        ) -> Result<Box<dyn AcpCatalogCreateTransactionV1>, proto::ErrorPayload> {
            self.creates.fetch_add(1, Ordering::Relaxed);
            connection
                .stage_code_root_attachment(
                    &self.result.base.attachment,
                    AcpCatalogAttachmentDispositionV1::New,
                )
                .await?;
            Ok(Box::new(SuccessfulCreateTransaction {
                result: self.result.clone(),
            }))
        }

        async fn attach_existing_code_root(
            &self,
            _principal: &ClientPrincipal,
            _request: proto::AttachExistingCodeRootWithAcpIngressV1Request,
            _connection: &mut dyn AcpCatalogConnectionAttachmentV1,
        ) -> Result<Box<dyn AcpCatalogAttachTransactionV1>, proto::ErrorPayload> {
            Err(observed())
        }

        async fn close_code_root_attachment(
            &self,
            _principal: &ClientPrincipal,
            _request: proto::CloseAcpCodeRootAttachmentV1Request,
        ) -> Result<proto::CloseAcpCodeRootAttachmentV1Result, proto::ErrorPayload> {
            Err(observed())
        }
    }

    #[async_trait]
    impl AcpCatalogConnectionAttachmentCommitV1 for RecordingConnectionAttachment {
        async fn commit_code_root_attachment(
            &mut self,
            attachment: &proto::CodeRootAttachmentV1,
            options: &proto::CodeRootAttachOptionsV1,
            since_seq: Option<i64>,
            disposition: AcpCatalogAttachmentDispositionV1,
        ) -> Result<(), proto::ErrorPayload> {
            self.commits.fetch_add(1, Ordering::Relaxed);
            self.committed.lock().unwrap().push((
                attachment.clone(),
                options.clone(),
                since_seq,
                disposition,
            ));
            Ok(())
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

    fn successful_create_result(
        attachment: proto::CodeRootAttachmentV1,
    ) -> proto::CreateCodeRootWithAcpIngressV1Result {
        let root_id = attachment.root_id.0;
        let base = serde_json::from_value(serde_json::json!({
            "attachment": attachment,
            "root": {
                "root_id": root_id,
                "workspace_path": "/workspace",
                "title": null,
                "short_id": "root",
                "project_id": "project",
                "active_agent": "agent",
                "active_agent_path": ["agent"],
                "history": [],
                "daemon_version": "test",
                "compatible": true,
                "attention": []
            }
        }))
        .expect("minimal Code-root result");
        proto::CreateCodeRootWithAcpIngressV1Result { base }
    }

    #[tokio::test]
    async fn composed_routes_forward_the_exact_closed_contract_to_the_internal_service_once() {
        let service = RecordingComposition::default();
        let mut connection = RecordingConnectionAttachment::default();
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
            create_route(&service, &principal, create.clone(), &mut connection)
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
            attach_route(&service, &principal, attach.clone(), &mut connection)
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
        assert_eq!(connection.commits.load(Ordering::Relaxed), 0);
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

    #[tokio::test]
    async fn successful_composition_establishes_the_connection_before_returning() {
        let root_id = proto::CodeRootIdV1(uuid::Uuid::new_v4());
        let attachment = proto::CodeRootAttachmentV1 {
            root_id,
            attachment_capability: proto::CodeRootAttachmentCapabilityV1::new_opaque("capability")
                .unwrap(),
            capture_generation: root_id.capture_generation(),
            replay_cursor: proto::CodeRootReplayCursorV1::from_daemon_random(uuid::Uuid::new_v4()),
        };
        let service = SuccessfulCreateComposition {
            result: successful_create_result(attachment.clone()),
            creates: AtomicUsize::new(0),
        };
        let mut connection = RecordingConnectionAttachment::default();
        let request = proto::CreateCodeRootWithAcpIngressV1Request {
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

        let principal = ClientPrincipal::Owner;
        let expected_options = request.base.options.clone();
        let result = create_route(&service, &principal, request, &mut connection)
            .await
            .expect("successful composition");

        assert_eq!(service.creates.load(Ordering::Relaxed), 1);
        assert_eq!(connection.commits.load(Ordering::Relaxed), 1);
        assert_eq!(
            connection.committed.lock().unwrap().as_slice(),
            &[(
                attachment.clone(),
                expected_options,
                None,
                AcpCatalogAttachmentDispositionV1::New,
            )]
        );
        assert_eq!(result.base.attachment.root_id, attachment.root_id);
        assert_eq!(
            result.base.attachment.attachment_capability,
            attachment.attachment_capability
        );
    }
}
