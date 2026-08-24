use super::attachments::*;
use super::authz::*;
use super::run_invocation::{principal_digest, wall_ms_now};
use super::sessions::*;
#[cfg(feature = "remote")]
use super::sessions_remote::{self, RemoteSessionLedger};
use super::*;

use crate::db::protected_leak_records::ProtectedLeakRecordRef;
use sha2::Sha256;
// The named-secret ownership guard primitives were factored into the shared
// `crate::secret_ownership` funnel so policy import, `cockpit mcp add`,
// credential refresh, and owner-scoped resolution reuse the SAME model. Re-export
// them here (`pub(crate)`) so this module's existing call sites and the
// `daemon::server::tests` `use super::dispatch::*` glob keep resolving them.
pub(crate) use crate::secret_ownership::{
    NamedSecretClaimConflict, ensure_static_named_reference_owned_on_conn,
    guard_mcp_reference_ownership_on_conn, reject_conflicting_named_ownership_on_conn,
};
use rusqlite::OptionalExtension;

// Keep the local dispatch AST free of remote operation types and helpers while
// sharing the mutation body with the opt-in remote profile. In the local
// expansion the operation token is deliberately consumed but never emitted.
#[cfg(feature = "remote")]
macro_rules! finish_nonrepeatable_response {
    ($operation:ident, $ctx:expr, $kind:literal, $response:expr) => {{
        match $operation {
            Some(operation) => commit_remote_nonrepeatable(operation, $ctx, $kind, $response).await,
            None => Ok($response),
        }
    }};
}

#[cfg(feature = "remote")]
macro_rules! finish_provider_mutation_future {
    ($operation:ident, $ctx:expr, $kind:literal, $mutation:expr) => {{
        match $operation {
            Some(operation) => {
                finish_remote_provider_mutation(operation, $ctx, $kind, $mutation).await
            }
            None => $mutation.await,
        }
    }};
}

#[cfg(not(feature = "remote"))]
macro_rules! finish_provider_mutation_future {
    ($operation:ident, $ctx:expr, $kind:literal, $mutation:expr) => {{
        let _ = $ctx;
        $mutation.await
    }};
}

#[cfg(not(feature = "remote"))]
macro_rules! finish_nonrepeatable_response {
    ($operation:ident, $ctx:expr, $kind:literal, $response:expr) => {{
        let _ = $ctx;
        Ok($response)
    }};
}

static WORKSPACE_TRUST_RPC_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static SECRET_OWNER_RPC_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// Credential clear must never wait indefinitely on a best-effort remote
/// instance revoke. Local vault ownership is cleared independently below.
#[cfg(feature = "remote")]
const FLYCOCKPIT_REVOKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// Serialize daemon-side provider/config read-modify-write operations. The
/// ConfigDoc writer also takes the shared cross-process lock, so this closes
/// races between clients in one daemon while the file lock covers peers.
/// Serialize every provider/MCP config publication, reference scan, and
/// cleanup. They share the named-secret vault namespace.
static CONFIG_PUBLICATION_RPC_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct McpOAuthPending {
    project_root: String,
    server: String,
    flow: crate::mcp::auth::McpOAuthFlow,
}

#[derive(Clone)]
enum ProviderOAuthFlow {
    /// A flow that has not started its one-time provider exchange.
    Ready(ProviderOAuthReady),
    /// A flow is never left in this state in the map: claiming it removes the
    /// Ready value before network I/O. The variant documents the state machine
    /// and makes accidental re-insertion of an in-flight flow conspicuous.
    #[allow(dead_code)]
    Completing,
}

#[derive(Clone)]
enum ProviderOAuthReady {
    Grok(crate::auth::xai_oauth::ManualLogin),
    Codex(crate::auth::codex_oauth::DeviceLogin),
}

const OAUTH_FLOW_TTL: Duration = Duration::from_secs(10 * 60);
const OAUTH_FLOW_GLOBAL_CAPACITY: usize = 64;
const OAUTH_FLOW_OWNER_CAPACITY: usize = 8;

struct StoredProviderOAuthFlow {
    owner: String,
    created_at: Instant,
    flow: ProviderOAuthFlow,
}

struct StoredMcpOAuthFlow {
    owner: String,
    created_at: Instant,
    flow: McpOAuthPending,
}

/// Daemon-owned OAuth state. Keeping this on the context prevents one daemon
/// instance or test from observing another's PKCE/device state, while the
/// bounded TTL/capacity prevents abandoned flows from growing without limit.
pub(crate) struct OAuthFlowStore {
    provider: tokio::sync::Mutex<std::collections::HashMap<String, StoredProviderOAuthFlow>>,
    mcp: tokio::sync::Mutex<std::collections::HashMap<String, StoredMcpOAuthFlow>>,
}

impl OAuthFlowStore {
    pub(crate) fn new() -> Self {
        Self {
            provider: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            mcp: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn purge_provider(flows: &mut std::collections::HashMap<String, StoredProviderOAuthFlow>) {
        let now = Instant::now();
        flows.retain(|_, flow| now.duration_since(flow.created_at) <= OAUTH_FLOW_TTL);
    }

    fn purge_mcp(flows: &mut std::collections::HashMap<String, StoredMcpOAuthFlow>) {
        let now = Instant::now();
        flows.retain(|_, flow| now.duration_since(flow.created_at) <= OAUTH_FLOW_TTL);
    }

    fn evict_oldest_provider(
        flows: &mut std::collections::HashMap<String, StoredProviderOAuthFlow>,
        owner: &str,
    ) {
        if let Some(id) = flows
            .iter()
            .filter(|(_, flow)| flow.owner == owner)
            .min_by_key(|(_, flow)| flow.created_at)
            .map(|(id, _)| id.clone())
        {
            flows.remove(&id);
        }
    }

    fn evict_oldest_mcp(
        flows: &mut std::collections::HashMap<String, StoredMcpOAuthFlow>,
        owner: &str,
    ) {
        if let Some(id) = flows
            .iter()
            .filter(|(_, flow)| flow.owner == owner)
            .min_by_key(|(_, flow)| flow.created_at)
            .map(|(id, _)| id.clone())
        {
            flows.remove(&id);
        }
    }

    async fn insert_provider(&self, id: String, owner: String, flow: ProviderOAuthFlow) {
        let mut flows = self.provider.lock().await;
        Self::purge_provider(&mut flows);
        if flows.values().filter(|flow| flow.owner == owner).count() >= OAUTH_FLOW_OWNER_CAPACITY {
            Self::evict_oldest_provider(&mut flows, &owner);
        }
        if flows.len() >= OAUTH_FLOW_GLOBAL_CAPACITY
            && let Some(id) = flows
                .iter()
                .min_by_key(|(_, flow)| flow.created_at)
                .map(|(id, _)| id.clone())
        {
            flows.remove(&id);
        }
        flows.insert(
            id,
            StoredProviderOAuthFlow {
                owner,
                created_at: Instant::now(),
                flow,
            },
        );
    }

    async fn take_provider(&self, id: &str, owner: &str) -> Option<ProviderOAuthFlow> {
        let mut flows = self.provider.lock().await;
        Self::purge_provider(&mut flows);
        (flows.get(id).is_some_and(|flow| flow.owner == owner))
            .then(|| flows.remove(id).expect("flow checked above").flow)
    }

    async fn restore_provider(&self, id: String, owner: String, flow: ProviderOAuthFlow) {
        self.insert_provider(id, owner, flow).await;
    }

    async fn remove_provider(&self, id: &str, owner: &str) -> bool {
        let mut flows = self.provider.lock().await;
        Self::purge_provider(&mut flows);
        flows.get(id).is_some_and(|flow| flow.owner == owner) && flows.remove(id).is_some()
    }

    async fn insert_mcp(&self, id: String, owner: String, flow: McpOAuthPending) {
        let mut flows = self.mcp.lock().await;
        Self::purge_mcp(&mut flows);
        if flows.values().filter(|flow| flow.owner == owner).count() >= OAUTH_FLOW_OWNER_CAPACITY {
            Self::evict_oldest_mcp(&mut flows, &owner);
        }
        if flows.len() >= OAUTH_FLOW_GLOBAL_CAPACITY
            && let Some(id) = flows
                .iter()
                .min_by_key(|(_, flow)| flow.created_at)
                .map(|(id, _)| id.clone())
        {
            flows.remove(&id);
        }
        flows.insert(
            id,
            StoredMcpOAuthFlow {
                owner,
                created_at: Instant::now(),
                flow,
            },
        );
    }

    async fn take_mcp(&self, id: &str, owner: &str) -> Option<McpOAuthPending> {
        let mut flows = self.mcp.lock().await;
        Self::purge_mcp(&mut flows);
        (flows.get(id).is_some_and(|flow| flow.owner == owner))
            .then(|| flows.remove(id).expect("flow checked above").flow)
    }

    async fn remove_mcp(&self, id: &str, owner: &str) -> bool {
        let mut flows = self.mcp.lock().await;
        Self::purge_mcp(&mut flows);
        flows.get(id).is_some_and(|flow| flow.owner == owner) && flows.remove(id).is_some()
    }
}

fn oauth_owner(state: &MutableClientState) -> String {
    state
        .principal
        .tag()
        .unwrap_or_else(|| "local-owner".to_string())
}

/// Authentic "this request may perform LOCAL-HOST actions" signal for handlers
/// that would otherwise open a host browser, bind a host loopback listener, or
/// adopt the host's ambient environment secrets.
///
/// Both inputs are assigned by the daemon, never by the caller:
/// - `state.principal` is set at connection authentication from the transport
///   (a local unix-domain socket yields `ClientPrincipal::Owner`; a relay /
///   attempt-grant connection yields `ClientPrincipal::Remote` via the daemon's
///   verified constructors). A caller cannot present itself as `Owner`.
/// - `remote_operation` is produced only by `admit_remote_operation` from a
///   daemon-verified device actor binding; a genuine local owner always yields
///   `None` (admission short-circuits on `is_owner()`), and it cannot be forged.
///
/// Requiring BOTH (`is_owner()` AND no remote-operation context) can only make
/// the gate MORE restrictive, so it never downgrades a remote caller to local;
/// it additionally treats a remote-operation ledger dispatch as remote even when
/// the ledger path is exercised with an owner principal.
fn is_local_owner_action(
    state: &MutableClientState,
    #[cfg(feature = "remote")] remote_operation: Option<&super::RemoteOperationContext>,
) -> bool {
    state.principal.is_owner() && {
        #[cfg(feature = "remote")]
        {
            remote_operation.is_none()
        }
        #[cfg(not(feature = "remote"))]
        {
            true
        }
    }
}

/// Concurrent-lane analogue of [`is_local_owner_action`] over a shared snapshot.
/// Same semantics: a genuine local owner is the owner principal AND no
/// remote-operation ledger dispatch. A remoted owner (an owner principal
/// carrying a remote-operation context) is NOT a local-owner action, so it is
/// refused the raw `--include-sensitive` export exactly like any other remote.
#[cfg(feature = "remote")]
fn is_local_owner_action_shared(
    shared: &SharedClientState,
    remote_operation: Option<&super::RemoteOperationContext>,
) -> bool {
    shared.principal.is_owner() && remote_operation.is_none()
}

#[cfg(test)]
mod oauth_store_tests {
    use super::*;

    #[tokio::test]
    async fn provider_store_is_owner_scoped_and_bounded_per_owner() {
        let store = OAuthFlowStore::new();
        for index in 0..=OAUTH_FLOW_OWNER_CAPACITY {
            store
                .insert_provider(
                    format!("flow-{index}"),
                    "owner-a".to_string(),
                    ProviderOAuthFlow::Completing,
                )
                .await;
        }

        assert!(store.take_provider("flow-0", "owner-a").await.is_none());
        assert!(store.take_provider("flow-1", "owner-b").await.is_none());
        assert!(store.take_provider("flow-8", "owner-a").await.is_some());
    }
}

#[derive(Debug)]
struct PinMutationRejected(String);

impl std::fmt::Display for PinMutationRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for PinMutationRejected {}

#[derive(Debug)]
struct GoalMutationRejected(String);
impl std::fmt::Display for GoalMutationRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for GoalMutationRejected {}

fn app_flag_db_key(key: proto::AppFlagKey) -> &'static str {
    match key {
        proto::AppFlagKey::DaemonAutostartNotice => "daemon-autostart",
    }
}

fn workspace_trust_mode_to_db(
    mode: proto::WorkspaceTrustMode,
) -> crate::db::workspace_trust::WorkspaceTrustMode {
    match mode {
        proto::WorkspaceTrustMode::Trust => crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        proto::WorkspaceTrustMode::IgnoreConfig => {
            crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig
        }
        proto::WorkspaceTrustMode::Untrusted => {
            crate::db::workspace_trust::WorkspaceTrustMode::Untrusted
        }
    }
}

fn workspace_trust_mode_from_db(
    mode: crate::db::workspace_trust::WorkspaceTrustMode,
) -> proto::WorkspaceTrustMode {
    match mode {
        crate::db::workspace_trust::WorkspaceTrustMode::Trust => proto::WorkspaceTrustMode::Trust,
        crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig => {
            proto::WorkspaceTrustMode::IgnoreConfig
        }
        crate::db::workspace_trust::WorkspaceTrustMode::Untrusted => {
            proto::WorkspaceTrustMode::Untrusted
        }
    }
}

#[cfg(feature = "remote")]
fn org_disclosure_to_proto(
    value: crate::db::org_sync::OrgSyncDisclosure,
) -> proto::OrgSyncDisclosure {
    proto::OrgSyncDisclosure {
        org_id: value.org_id,
        cursor_seq: value.cursor_seq,
        last_synced_at_ms: value.last_synced_at_ms,
    }
}

#[cfg(feature = "remote")]
fn connector_disclosure_to_proto(
    value: crate::db::connector::ConnectorDisclosure,
) -> proto::ConnectorDisclosure {
    proto::ConnectorDisclosure {
        enabled: value.enabled,
        status: value.status,
        relay_url: value.relay_url,
        relay_id: value.relay_id,
        relay_region: value.relay_region,
        last_error: value.last_error,
    }
}

fn invalid_terminal_ingress() -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::InvalidIngress,
        message: "invalid terminal ingress".to_string(),
    }
}

fn require_terminal_binding(
    state: &MutableClientState,
    terminal_id: Uuid,
    binding: proto::terminal::TerminalBinding,
) -> std::result::Result<(), ErrorPayload> {
    if state.terminal_views.get(&terminal_id) == Some(&binding) {
        Ok(())
    } else {
        Err(invalid_terminal_ingress())
    }
}

/// Build the only durable ingress representation for a text-only source that
/// crosses the artifact threshold. This happens before legacy queue admission
/// and, critically, before an over-8MiB source can create a receipt/lease.
/// Text-only submissions at or below this size retain the ordinary inline
/// representation. Above it, the only admissible representation is the
/// FCM2-backed source-artifact path.
const INLINE_USER_TEXT_BYTES: usize = 64 * 1024;

pub(super) struct OversizedTextArtifactAdmissionRequest<'a> {
    pub session_id: Uuid,
    pub client_submission_id: Uuid,
    pub expected_model_state_generation: Option<u64>,
    pub expected_model: Option<&'a cockpit_config::config::providers::ActiveModelRef>,
    pub text: &'a str,
    pub display_text: Option<&'a str>,
    pub tag_expansions: &'a [proto::TagExpansionMeta],
    pub forced_skill: Option<&'a str>,
    #[cfg(feature = "remote")]
    pub remote_operation: Option<&'a super::RemoteOperationContext>,
}

pub(super) fn oversized_text_artifact_admission(
    ctx: &DaemonContext,
    handle: &crate::daemon::session_worker::SessionWorkerHandle,
    principal: &ClientPrincipal,
    request: OversizedTextArtifactAdmissionRequest<'_>,
) -> std::result::Result<
    Option<crate::daemon::session_worker::OversizedTextArtifactAdmission>,
    ErrorPayload,
> {
    let OversizedTextArtifactAdmissionRequest {
        session_id,
        client_submission_id,
        expected_model_state_generation,
        expected_model,
        text,
        display_text,
        tag_expansions,
        forced_skill,
        #[cfg(feature = "remote")]
        remote_operation,
    } = request;
    if text.len() <= INLINE_USER_TEXT_BYTES {
        return Ok(None);
    }
    if text.len() > crate::proto_crate::send_user_message_v2::MAX_MESSAGE_TEXT_BYTES {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "message text exceeds the 8 MiB FCM2 limit".to_owned(),
        });
    }

    let model_fence = match (expected_model_state_generation, expected_model) {
        (None, None) => None,
        (Some(generation), Some(model)) => Some((generation, model.clone())),
        _ => {
            return Err(ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "expected model fence must include both generation and model".to_owned(),
            });
        }
    };
    let canonical_project_digest = Sha256::digest(
        format!(
            "flycockpit-project-v1\\0{}\\0{}",
            handle.project_id(),
            handle.project_root.display()
        )
        .as_bytes(),
    )
    .into();
    // An omitted fence deliberately has a fixed canonical identity: it must
    // replay across active-model changes.  Conversely, an explicit fence is
    // part of the accepted request identity, so it must be represented in
    // FCM2 rather than only in the worker-side acceptance check.
    let (model_config_generation, canonical_model_digest) = match &model_fence {
        None => (
            0,
            Sha256::digest(b"flycockpit-fcm2-v2-model-digest\0").into(),
        ),
        Some((generation, model)) => {
            let model_json = serde_json::to_vec(model).map_err(internal)?;
            let mut digest_input = b"flycockpit-fcm2-v2-model-digest\0".to_vec();
            digest_input.extend_from_slice(&model_json);
            (*generation, Sha256::digest(digest_input).into())
        }
    };
    let canonical = crate::proto_crate::send_user_message_v2::CanonicalSendUserMessageV2 {
        session_id,
        canonical_project_digest,
        model_config_generation,
        canonical_model_digest,
        request: crate::proto_crate::send_user_message_v2::SendUserMessageV2 {
            client_submission_id,
            text: text.to_owned(),
            display_text: display_text.map(str::to_owned),
            tag_expansions: tag_expansions
                .iter()
                .map(
                    |tag| crate::proto_crate::send_user_message_v2::MessageTagExpansion {
                        tool: tag.tool.clone(),
                        path: tag.path.clone(),
                        detail: tag.detail.clone(),
                        ok: tag.ok,
                    },
                )
                .collect(),
            forced_skill: forced_skill.map(str::to_owned),
            attachments: Vec::new(),
        },
    };
    let canonical_message = canonical.encode().map_err(|_| ErrorPayload {
        code: ErrorCode::BadRequest,
        message: "message is not a valid bounded FCM2 submission".to_owned(),
    })?;
    #[cfg(feature = "remote")]
    let (operation_id, actor, request_hash) = match remote_operation {
        Some(operation) => {
            if operation.operation_id == client_submission_id {
                return Err(ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: "remote operation and client submission identities must differ"
                        .to_owned(),
                });
            }
            let fcor = crate::proto_crate::remote_operation_fcor::encode_fcor_v1(
                "send_user_message",
                &[],
                &canonical_message,
            )
            .map_err(internal)?;
            (
                operation.operation_id,
                crate::db::db::message_attachments::MessageActor::ExternalPrincipal {
                    id: *operation.authenticated_device_id.as_bytes(),
                    generation: operation.authenticated_device_generation,
                },
                remote_request_hash(ctx, &fcor),
            )
        }
        None if principal.is_owner() => {
            let operation_id = Uuid::new_v5(
                &session_id,
                format!("typed-session-artifacts-v1:{client_submission_id}").as_bytes(),
            );
            (
                operation_id,
                crate::db::db::message_attachments::MessageActor::LocalOwner,
                Sha256::digest(&canonical_message).into(),
            )
        }
        None => {
            return Err(ErrorPayload {
                code: ErrorCode::Authorization,
                message: "oversized remote user messages require an authenticated operation actor"
                    .to_owned(),
            });
        }
    };
    #[cfg(not(feature = "remote"))]
    let (operation_id, actor, request_hash) = if principal.is_owner() {
        let operation_id = Uuid::new_v5(
            &session_id,
            format!("typed-session-artifacts-v1:{client_submission_id}").as_bytes(),
        );
        (
            operation_id,
            crate::db::db::message_attachments::MessageActor::LocalOwner,
            Sha256::digest(&canonical_message).into(),
        )
    } else {
        return Err(ErrorPayload {
            code: ErrorCode::Authorization,
            message: "oversized user messages require the local owner".to_owned(),
        });
    };
    Ok(Some(
        crate::daemon::session_worker::OversizedTextArtifactAdmission {
            operation_id: *operation_id.as_bytes(),
            actor,
            request_hash,
            message_request_digest: canonical.message_request_digest().map_err(internal)?,
            attachment_set_digest: canonical.attachment_set_digest().map_err(internal)?,
            canonical_message,
            model_fence,
            run_invocation: None,
        },
    ))
}

#[cfg(test)]
pub(super) async fn handle_request(
    request: Request,
    state: &mut MutableClientState,
    ctx: &Arc<DaemonContext>,
) -> std::result::Result<Response, ErrorPayload> {
    let mut effects = ClientRequestEffects::default();
    let shared = state.shared_snapshot();
    let result = handle_serialized_request(request, state, &shared, ctx, &mut effects).await;
    if effects.shutdown_after_response {
        request_shutdown(ctx);
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn handle_send_user_message(
    state: &mut MutableClientState,
    ctx: &Arc<DaemonContext>,
    client_submission_id: Uuid,
    expected_model_state_generation: Option<u64>,
    expected_model: Option<cockpit_config::config::providers::ActiveModelRef>,
    text: String,
    display_text: Option<String>,
    tag_expansions: Vec<proto::TagExpansionMeta>,
    image_refs: Vec<proto::ImageAttachmentRef>,
    forced_skill: Option<String>,
    run_invocation_options: Option<proto::RunInvocationOptions>,
    #[cfg(feature = "remote")] remote_operation: Option<&super::RemoteOperationContext>,
) -> std::result::Result<Response, ErrorPayload> {
    if ctx.shutdown.is_draining() {
        return Err(ErrorPayload {
            code: ErrorCode::Shutdown,
            message: "daemon is shutting down; not accepting new messages".into(),
        });
    }
    // This is the transport-normalized FCM2 text domain, not only the
    // artifact threshold. Check it before any receipt, run-invocation, media,
    // or remote-operation side effect so an image-backed/direct request cannot
    // bypass the 8 MiB source or display-text limit.
    if text.len() > crate::proto_crate::send_user_message_v2::MAX_MESSAGE_TEXT_BYTES {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "message text exceeds the 8 MiB FCM2 limit".to_owned(),
        });
    }
    if display_text.as_ref().is_some_and(|value| {
        value.len() > crate::proto_crate::send_user_message_v2::MAX_MESSAGE_TEXT_BYTES
    }) {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "message display text exceeds the 8 MiB FCM2 limit".to_owned(),
        });
    }
    // The FCM2 source-artifact composition is deliberately text-only.  Do not
    // let a media/file submission fall through to the legacy queue with a
    // source that resume and archive import are required to treat as an
    // artifact-backed event: that would create a durable event which can no
    // longer be rehydrated or imported.  Reject before attachment probing,
    // receipt/run-invocation acceptance, scheduler activity, or any provider
    // handoff.  Media/file submissions at the inline boundary retain their
    // existing typed attachment route unchanged.
    if !image_refs.is_empty() && text.len() > INLINE_USER_TEXT_BYTES {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "media/file submissions cannot carry text over the 64 KiB artifact threshold"
                .to_owned(),
        });
    }
    let session_id = require_attached(state)?.handle.session_id;
    let handle = require_attached(state)?.handle.clone();
    let origin_principal = state.principal.tag();
    // A text-only oversized source switches to FCM2 before any receipt or
    // queue side effect. In particular the codec rejects 8MiB+1 before the
    // worker can create a receipt triple or reservation.
    let mut artifact_admission = if image_refs.is_empty() {
        oversized_text_artifact_admission(
            ctx,
            &handle,
            &state.principal,
            OversizedTextArtifactAdmissionRequest {
                session_id,
                client_submission_id,
                expected_model_state_generation,
                expected_model: expected_model.as_ref(),
                text: &text,
                display_text: display_text.as_deref(),
                tag_expansions: &tag_expansions,
                forced_skill: forced_skill.as_deref(),
                #[cfg(feature = "remote")]
                remote_operation,
            },
        )?
    } else {
        None
    };
    // Legacy-sized/media messages retain their existing admission behavior.
    // Oversized FCM2 messages record activity only after the worker has
    // durably accepted both the receipt triple and source reservation.
    if artifact_admission.is_none()
        && let Some(scheduler) = &ctx.scheduler
    {
        scheduler.record_user_activity().await;
    }
    let mut wire_fingerprint = user_message_wire_fingerprint(
        &text,
        display_text.as_deref(),
        &tag_expansions,
        &image_refs,
        forced_skill.as_deref(),
    );
    if let (Some(generation), Some(model)) =
        (expected_model_state_generation, expected_model.as_ref())
    {
        let model_json = serde_json::to_string(model).map_err(internal)?;
        wire_fingerprint.push_str(&format!("|model:{generation}:{model_json}"));
    }
    // Include immutable run options in the fingerprint so option drift
    // conflicts. Inline/media retains its historical barrier; oversized FCM2
    // carries the immutable values to the worker, which creates it atomically
    // with phase one and binds it to the exact source reservation.
    if let Some(options) = &run_invocation_options {
        let opts_digest = run_invocation::options_digest(options);
        wire_fingerprint = format!("{wire_fingerprint}|run:{opts_digest}");
        if let Some(admission) = artifact_admission.as_mut() {
            admission.run_invocation = Some(
                crate::daemon::session_worker::OversizedRunInvocationAdmission {
                    origin_principal_digest: principal_digest(&state.principal),
                    options_json: run_invocation::options_json(options)?,
                    options_digest: opts_digest.clone(),
                    content_digest: run_invocation::content_digest(&wire_fingerprint, &opts_digest),
                    max_turns: options.max_turns,
                    timeout_ms: options.timeout_ms,
                },
            );
        } else {
            let _accepted = run_invocation::accept_run_if_marked(
                ctx,
                &state.principal,
                session_id,
                client_submission_id,
                &wire_fingerprint,
                options,
                run_invocation::wall_ms_now(),
            )
            .await?;
        }
    }
    // Oversized text owns its remote/local identity exclusively through the
    // FCM2 receipt composition above. Do not also enter the legacy remote
    // queue ledger: that would create a second accept path after phase one.
    // Media and inline text retain their existing legacy ledger until their
    // own transport representation is migrated.
    #[cfg(feature = "remote")]
    let remote_queue_operation = if artifact_admission.is_some() {
        None
    } else {
        match remote_operation {
            Some(operation) => {
                let mut params = proto::remote_operation_fcor::CanonicalParamsV1::new();
                params.push_uuid(session_id);
                params.push_uuid(client_submission_id);
                params.push_string(&wire_fingerprint).map_err(internal)?;
                let canonical = proto::remote_operation_fcor::encode_fcor_v1(
                    "send_user_message",
                    &[],
                    &params.into_bytes(),
                )
                .map_err(internal)?;
                Some(crate::daemon::session_worker::RemoteQueueOperation {
                    logical_attachment_id: operation.logical_attachment_id.to_string(),
                    operation_id: operation.operation_id.to_string(),
                    authenticated_device_id: operation.authenticated_device_id.to_string(),
                    authenticated_device_generation: operation.authenticated_device_generation,
                    request_hash: remote_request_hash(ctx, &canonical),
                })
            }
            None => None,
        }
    };
    let mut requires_content_check = false;
    if !image_refs.is_empty() {
        let (probe_tx, probe_rx) = tokio::sync::oneshot::channel();
        handle
            .send_work(SessionWork::ProbeUserMessage {
                client_submission_id,
                wire_fingerprint: wire_fingerprint.clone(),
                origin_principal: origin_principal.clone(),
                respond_to: probe_tx,
            })
            .await
            .map_err(internal)?;
        match probe_rx.await.map_err(internal)?? {
            UserMessageProbeResult::Duplicate { item, queue } => {
                // An image-backed exact-duplicate short-circuits BEFORE the worker
                // accept path (to avoid re-claiming already-consumed image refs),
                // so for an authenticated remote send we must still resolve its
                // operation identity through the SAME transactional ledger the
                // worker uses — record a fresh operation, replay an already
                // committed one, or reject an operation/actor conflict — so no
                // remote send returns accepted without a ledger operation row.
                #[cfg(feature = "remote")]
                if let Some(operation) = &remote_queue_operation {
                    match crate::daemon::session_worker::reserve_remote_send_operation(
                        &ctx.db, operation,
                    )
                    .await
                    {
                        crate::daemon::session_worker::RemoteSendDecision::Accepted
                        | crate::daemon::session_worker::RemoteSendDecision::Replayed => {}
                        crate::daemon::session_worker::RemoteSendDecision::Rejected(error) => {
                            return Err(error);
                        }
                    }
                }
                // Run-marker acceptance already happened above (main's position:
                // before the worker dispatch), so this duplicate path matches
                // main and adds no marker step of its own.
                return Ok(Response::UserMessageQueued { item, queue });
            }
            UserMessageProbeResult::Conflict => {
                return Err(ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: format!(
                        "client_submission_id {client_submission_id} was already used by a different principal"
                    ),
                });
            }
            UserMessageProbeResult::Unknown => {}
            UserMessageProbeResult::ContentCheckRequired => requires_content_check = true,
        }
    }
    let images = match claim_message_image_refs_admitted(
        ctx,
        state,
        session_id,
        client_submission_id,
        &image_refs,
    )
    .await
    {
        Ok(images) => images,
        Err(_) if requires_content_check => {
            return Err(ErrorPayload {
                code: ErrorCode::BadRequest,
                message: format!(
                    "client_submission_id {client_submission_id} was already used for a different payload"
                ),
            });
        }
        Err(error) => return Err(error),
    };
    let (respond_to, response_rx) = tokio::sync::oneshot::channel();
    let mut submission = crate::engine::message::UserSubmission {
        origin: crate::engine::message::SubmissionOrigin::ExternalRoot,
        expected_model_state_generation,
        expected_model,
        kind: crate::engine::message::UserSubmissionKind::User,
        text,
        display_text,
        tag_expansions,
        images,
        forced_skill,
        origin_principal: origin_principal.clone(),
        job_id: None,
        preflight_cleaned: None,
        queue_item_ids: Vec::new(),
        client_submissions: Vec::new(),
        queue_target: None,
        pending_terminal_disposition: None,
        run_invocation_id: run_invocation_options
            .as_ref()
            .map(|_| client_submission_id),
    };
    let fingerprint = submission.client_fingerprint();
    submission
        .client_submissions
        .push(crate::engine::message::ClientSubmissionReceipt {
            id: client_submission_id,
            fingerprint,
            wire_fingerprint,
            origin_principal,
        });
    handle
        .send_work(SessionWork::UserMessage {
            submission: Box::new(submission),
            #[cfg(feature = "remote")]
            remote_operation: remote_queue_operation,
            artifact_admission: artifact_admission.clone().map(Box::new),
            respond_to,
        })
        .await
        .map_err(internal)?;
    let actor_result = response_rx.await.map_err(internal)?;
    let (item, queue) = match actor_result {
        Ok(result) => result,
        Err(error) => {
            match ctx
                .media_ledger
                .return_downstream_ownership(&client_submission_id.to_string())
                .await
            {
                Ok(_) => release_message_image_refs(state, client_submission_id, &image_refs),
                Err(cleanup_error) => {
                    // Keep refs in the consumed/quarantined map. Re-exposing
                    // them while durable ownership still names the rejected
                    // invocation would permit two owners for one reservation.
                    tracing::warn!(%cleanup_error,invocation=%client_submission_id,"rejected user submission could not return media ownership; refs remain quarantined");
                }
            }
            return Err(error);
        }
    };
    // Oversized activity is advanced by the driver only after phase-two
    // materialization. The dispatch path must not create an accepted-turn
    // side effect merely because phase one reserved a lease.
    Ok(Response::UserMessageQueued { item, queue })
}

/// Bind opaque user-message transfer staging to the attached session and the
/// daemon-authenticated client identity. Upload chunks and their later
/// `SendUserMessageBulk` consumer use distinct request operation UUIDs, so the
/// stable authenticated attachment/device binding (plus principal) is the
/// operation identity that can safely span the whole transfer.
fn bulk_user_message_transfer_owner_impl(
    principal: &ClientPrincipal,
    session_id: Uuid,
    #[cfg(feature = "remote")] remote_operation: Option<&super::RemoteOperationContext>,
) -> std::result::Result<crate::daemon::bulk_staging::BulkTransferOwner, ErrorPayload> {
    let mut identity = Vec::with_capacity(128);
    identity.extend_from_slice(b"principal:");
    identity.extend_from_slice(
        principal
            .tag()
            .unwrap_or_else(|| "local-owner".to_owned())
            .as_bytes(),
    );
    #[cfg(feature = "remote")]
    if let Some(operation) = remote_operation {
        identity.extend_from_slice(b"\0remote-actor:");
        identity.extend_from_slice(operation.logical_attachment_id.as_bytes());
        identity.extend_from_slice(operation.authenticated_device_id.as_bytes());
        identity.extend_from_slice(&operation.authenticated_device_generation.to_be_bytes());
        return Ok(
            crate::daemon::bulk_staging::BulkTransferOwner::for_attached_identity(
                session_id, &identity,
            ),
        );
    }
    if principal.is_owner() {
        identity.extend_from_slice(b"\0local-owner");
    } else {
        return Err(ErrorPayload {
            code: ErrorCode::Authorization,
            message: "bulk user-message transfers require an authenticated operation actor"
                .to_owned(),
        });
    }
    Ok(
        crate::daemon::bulk_staging::BulkTransferOwner::for_attached_identity(
            session_id, &identity,
        ),
    )
}

pub(super) fn bulk_user_message_transfer_owner_local(
    principal: &ClientPrincipal,
    session_id: Uuid,
) -> std::result::Result<crate::daemon::bulk_staging::BulkTransferOwner, ErrorPayload> {
    bulk_user_message_transfer_owner_impl(principal, session_id)
}

#[cfg(feature = "remote")]
pub(super) fn bulk_user_message_transfer_owner(
    principal: &ClientPrincipal,
    session_id: Uuid,
    remote_operation: Option<&super::RemoteOperationContext>,
) -> std::result::Result<crate::daemon::bulk_staging::BulkTransferOwner, ErrorPayload> {
    bulk_user_message_transfer_owner_impl(principal, session_id, remote_operation)
}

/// The durable FCM2 replay gate parallel to [`bulk_user_message_transfer_owner`].
/// A consumed/expired reference may only be reconstructed for the same stored
/// message actor, never merely because another client knows its transfer id and
/// client submission id.
fn bulk_user_message_replay_actor_impl(
    principal: &ClientPrincipal,
    #[cfg(feature = "remote")] remote_operation: Option<&super::RemoteOperationContext>,
) -> std::result::Result<crate::db::message_attachments::MessageActor, ErrorPayload> {
    #[cfg(feature = "remote")]
    if let Some(operation) = remote_operation {
        return Ok(
            crate::db::message_attachments::MessageActor::ExternalPrincipal {
                id: *operation.authenticated_device_id.as_bytes(),
                generation: operation.authenticated_device_generation,
            },
        );
    }
    if principal.is_owner() {
        Ok(crate::db::message_attachments::MessageActor::LocalOwner)
    } else {
        Err(ErrorPayload {
            code: ErrorCode::Authorization,
            message: "bulk user-message transfers require an authenticated operation actor"
                .to_owned(),
        })
    }
}

pub(super) fn bulk_user_message_replay_actor_local(
    principal: &ClientPrincipal,
) -> std::result::Result<crate::db::message_attachments::MessageActor, ErrorPayload> {
    bulk_user_message_replay_actor_impl(principal)
}

#[cfg(feature = "remote")]
pub(super) fn bulk_user_message_replay_actor(
    principal: &ClientPrincipal,
    remote_operation: Option<&super::RemoteOperationContext>,
) -> std::result::Result<crate::db::message_attachments::MessageActor, ErrorPayload> {
    bulk_user_message_replay_actor_impl(principal, remote_operation)
}

pub(super) fn unavailable_bulk_user_message_transfer() -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::BadRequest,
        message: "bulk user-message transfer is unavailable".to_owned(),
    }
}

pub(super) struct BulkUserMessagePayloadRequest<'a> {
    pub session_id: Uuid,
    pub owner: &'a crate::daemon::bulk_staging::BulkTransferOwner,
    pub replay_actor: crate::db::message_attachments::MessageActor,
    pub client_submission_id: Uuid,
    pub transfer: &'a cockpit_proto::bulk_transfer::BulkTransferRef,
    pub display_text: &'a Option<String>,
    pub display_transfer: &'a Option<cockpit_proto::bulk_transfer::BulkTransferRef>,
    pub tag_expansions: &'a [proto::TagExpansionMeta],
    pub forced_skill: &'a Option<String>,
}

/// Resolve the bounded remote bulk references into the exact FCM2 text pair.
/// A completed message consumes its source and optional display form atomically.
/// If its ephemeral staging entries have already been consumed/expired, only an
/// already-durable canonical FCM2 row may satisfy a replay; a missing transfer
/// never becomes a new inline submission.
pub(super) async fn resolve_bulk_user_message_payload(
    ctx: &Arc<DaemonContext>,
    request: BulkUserMessagePayloadRequest<'_>,
) -> std::result::Result<(String, Option<String>), ErrorPayload> {
    use cockpit_proto::bulk_transfer::BulkMimeClass as RemoteBulkMimeClass;

    let BulkUserMessagePayloadRequest {
        session_id,
        owner,
        replay_actor,
        client_submission_id,
        transfer,
        display_text,
        display_transfer,
        tag_expansions,
        forced_skill,
    } = request;

    let is_opaque_text_transfer = |reference: &cockpit_proto::bulk_transfer::BulkTransferRef,
                                   minimum_length: u64| {
        reference.mime_class == RemoteBulkMimeClass::Opaque
            && (minimum_length
                ..=crate::proto_crate::send_user_message_v2::MAX_MESSAGE_TEXT_BYTES as u64)
                .contains(&reference.total_length_value())
    };
    let source_minimum_length = if display_transfer.is_some() {
        1
    } else {
        65_537
    };
    if !is_opaque_text_transfer(transfer, source_minimum_length) {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "bulk user message must be an opaque 64KiB..8MiB transfer".to_owned(),
        });
    }
    if display_text
        .as_ref()
        .is_some_and(|value| value.len() > 64 * 1024)
    {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "bulk user message display text over 64KiB must use a transfer".to_owned(),
        });
    }
    if let Some(display_transfer) = display_transfer {
        if display_text.is_some() {
            return Err(ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "bulk user message display text must be inline or a transfer, not both"
                    .to_owned(),
            });
        }
        if !is_opaque_text_transfer(display_transfer, 1) {
            return Err(ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "bulk user message display transfer must be an opaque 1B..8MiB transfer"
                    .to_owned(),
            });
        }
        if display_transfer.transfer_id == transfer.transfer_id {
            return Err(ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "bulk user message text and display transfers must be distinct".to_owned(),
            });
        }
    }

    let staged_bodies = match display_transfer {
        Some(display_transfer) => {
            crate::daemon::bulk_staging::take_all_owned(&[transfer, display_transfer], owner)
        }
        None => crate::daemon::bulk_staging::take_all_owned(&[transfer], owner),
    };
    match staged_bodies {
        Ok(mut bodies) => {
            let source = String::from_utf8(bodies.remove(0)).map_err(|_| ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "bulk user-message body must be valid UTF-8".to_owned(),
            })?;
            let display = match display_transfer {
                Some(_) => Some(
                    String::from_utf8(bodies.remove(0)).map_err(|_| ErrorPayload {
                        code: ErrorCode::BadRequest,
                        message: "bulk user-message display body must be valid UTF-8".to_owned(),
                    })?,
                ),
                None => display_text.clone(),
            };
            Ok((source, display))
        }
        Err(crate::daemon::bulk_staging::BulkStagingError::UnknownTransfer) => {
            let canonical = ctx
                .db
                .text_artifact_submission_canonical_message_for_actor(
                    session_id,
                    *client_submission_id.as_bytes(),
                    replay_actor,
                )
                .await
                .map_err(internal)?
                .ok_or_else(unavailable_bulk_user_message_transfer)?;
            let canonical =
                crate::proto_crate::send_user_message_v2::CanonicalSendUserMessageV2::decode(
                    &canonical,
                )
                .map_err(|_| ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: "durable bulk user-message replay is malformed".to_owned(),
                })?;
            let source = canonical.request.text;
            let canonical_display_text = canonical.request.display_text;
            let source_digest: [u8; 32] = Sha256::digest(source.as_bytes()).into();
            let display_matches = match display_transfer {
                None => canonical_display_text == *display_text,
                Some(reference) => canonical_display_text.as_ref().is_some_and(|display| {
                    let digest: [u8; 32] = Sha256::digest(display.as_bytes()).into();
                    display.len() as u64 == reference.total_length_value()
                        && digest == reference.sha256
                }),
            };
            if canonical.session_id != session_id
                || canonical.request.client_submission_id != client_submission_id
                || source.len() as u64 != transfer.total_length_value()
                || source_digest != transfer.sha256
                || !display_matches
                || canonical.request.forced_skill != *forced_skill
                || canonical.request.tag_expansions.len() != tag_expansions.len()
                || !canonical
                    .request
                    .tag_expansions
                    .iter()
                    .zip(tag_expansions)
                    .all(|(stored, supplied)| {
                        stored.tool == supplied.tool
                            && stored.path == supplied.path
                            && stored.detail == supplied.detail
                            && stored.ok == supplied.ok
                    })
            {
                return Err(ErrorPayload {
                    code: ErrorCode::IdempotencyConflict,
                    message: "bulk user-message replay does not match its durable FCM2 identity"
                        .to_owned(),
                });
            }
            Ok((source, canonical_display_text))
        }
        // Ownership mismatch deliberately does not fall through to durable
        // replay. Doing so would turn a consumed reference into a cross-client
        // canonical-body oracle.
        Err(crate::daemon::bulk_staging::BulkStagingError::OwnerMismatch) => {
            Err(unavailable_bulk_user_message_transfer())
        }
        Err(error) => Err(staging_error(error)),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_send_user_message_bulk(
    state: &mut MutableClientState,
    ctx: &Arc<DaemonContext>,
    client_submission_id: Uuid,
    expected_model_state_generation: Option<u64>,
    expected_model: Option<cockpit_config::config::providers::ActiveModelRef>,
    transfer: cockpit_proto::bulk_transfer::BulkTransferRef,
    display_text: Option<String>,
    display_transfer: Option<cockpit_proto::bulk_transfer::BulkTransferRef>,
    tag_expansions: Vec<proto::TagExpansionMeta>,
    forced_skill: Option<String>,
    run_invocation_options: Option<proto::RunInvocationOptions>,
    #[cfg(feature = "remote")] remote_operation: Option<&super::RemoteOperationContext>,
) -> std::result::Result<Response, ErrorPayload> {
    let session_id = require_attached(state)?.handle.session_id;
    #[cfg(feature = "remote")]
    let owner = bulk_user_message_transfer_owner(&state.principal, session_id, remote_operation)?;
    #[cfg(not(feature = "remote"))]
    let owner = bulk_user_message_transfer_owner_local(&state.principal, session_id)?;
    #[cfg(feature = "remote")]
    let replay_actor = bulk_user_message_replay_actor(&state.principal, remote_operation)?;
    #[cfg(not(feature = "remote"))]
    let replay_actor = bulk_user_message_replay_actor_local(&state.principal)?;
    let (text, display_text) = resolve_bulk_user_message_payload(
        ctx,
        BulkUserMessagePayloadRequest {
            session_id,
            owner: &owner,
            replay_actor,
            client_submission_id,
            transfer: &transfer,
            display_text: &display_text,
            display_transfer: &display_transfer,
            tag_expansions: &tag_expansions,
            forced_skill: &forced_skill,
        },
    )
    .await?;
    handle_send_user_message(
        state,
        ctx,
        client_submission_id,
        expected_model_state_generation,
        expected_model,
        text,
        display_text,
        tag_expansions,
        Vec::new(),
        forced_skill,
        run_invocation_options,
        #[cfg(feature = "remote")]
        remote_operation,
    )
    .await
}

pub(super) async fn handle_serialized_request(
    request: Request,
    state: &mut MutableClientState,
    shared: &Arc<SharedClientState>,
    ctx: &Arc<DaemonContext>,
    effects: &mut ClientRequestEffects,
) -> std::result::Result<Response, ErrorPayload> {
    Box::pin(handle_serialized_request_impl(
        request, state, shared, ctx, effects,
    ))
    .await
}

#[cfg(feature = "remote")]
async fn begin_remote_nonrepeatable(
    request: &Request,
    authorized: &AuthorizedRequestContext,
    operation: &super::RemoteOperationContext,
    ctx: &DaemonContext,
) -> std::result::Result<Option<Response>, ErrorPayload> {
    let params = request
        .canonical_remote_operation_params_v1()
        .map_err(internal)?;
    let canonical = authorized.encode_fcor(request, &params)?;
    let request_hash = remote_request_hash(ctx, &canonical);
    let attachment = operation.logical_attachment_id.to_string();
    let operation_id = operation.operation_id.to_string();
    let device = operation.authenticated_device_id.to_string();
    match ctx.db.begin_nonrepeatable_remote_operation(
        crate::db::remote_attachment_operations::ReserveRemoteOperation {
            logical_attachment_id: &attachment, operation_id: &operation_id,
            authenticated_device_id: &device,
            authenticated_device_generation: operation.authenticated_device_generation,
            operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::NonrepeatableMutation,
            request_hash, now_ms: chrono::Utc::now().timestamp_millis(),
        },
    ).await.map_err(internal)? {
        crate::db::remote_attachment_operations::BeginNonrepeatableRemoteOperationOutcome::Dispatch { .. } => Ok(None),
        crate::db::remote_attachment_operations::BeginNonrepeatableRemoteOperationOutcome::Replay(bytes) =>
            serde_json::from_slice(&bytes).map(Some).map_err(internal),
        crate::db::remote_attachment_operations::BeginNonrepeatableRemoteOperationOutcome::OutcomeUnknown(_) =>
            Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation outcome is unknown; it will not be retried".into() }),
        crate::db::remote_attachment_operations::BeginNonrepeatableRemoteOperationOutcome::OperationConflict
        | crate::db::remote_attachment_operations::BeginNonrepeatableRemoteOperationOutcome::OperationActorConflict =>
            Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation conflict".into() }),
        crate::db::remote_attachment_operations::BeginNonrepeatableRemoteOperationOutcome::AttachmentLedgerCapacity =>
            Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation capacity reached".into() }),
    }
}

/// Derive the identity persisted in a remote-operation ledger from the
/// daemon-held vault key. FCOR is canonical and authenticated, but its plain
/// SHA-256 is intentionally not suitable for ledger rows because it would let
/// anyone who can read a row test guesses for secret-bearing requests.
#[cfg(feature = "remote")]
pub(super) fn remote_request_hash(ctx: &DaemonContext, canonical: &[u8]) -> [u8; 32] {
    ctx.secret_vault
        .keyed_request_identity(b"flycockpit-remote-operation-v1\0", canonical)
}

/// Authoritative wiring declaration (production, colocated with the dispatch
/// handlers): the `transactional_mutation` request tags that a remote actor can
/// be ADMITTED for (i.e. NOT `owner_only`, whose remote non-owner callers the
/// authorization layer denies before dispatch) and that therefore MUST carry a
/// real daemon transactional remote-operation ledger site — either an inline
/// `execute_transactional_remote_operation` arm, the shared
/// `commit_session_remote_mutation` helper, or the FCM2
/// `message_operation_receipts` composition used by text-only message sends.
///
/// Adding a new remotely-admissible `transactional_mutation` command REQUIRES
/// adding it here AND wiring its ledger site;
/// `transactional_mutation_inventory_has_ledger_site` asserts this set EXACTLY
/// equals the remotely-admissible `transactional_mutation` rows enumerated from
/// the `command!` classification table (a new tag missing here — or a stale tag
/// listed here — fails the gate).
#[cfg(all(any(unix, test), feature = "remote"))]
pub(super) const REMOTELY_LEDGERED_TRANSACTIONAL_TAGS: &[&str] = &[
    "send_user_message",
    "send_user_message_bulk",
    "cancel_run_invocation",
    "remove_queued_user_message",
    "remove_newest_queued_user_message",
    "remove_editable_queued_user_messages",
    "resume_paused_work",
    "cancel_paused_work",
    "create_goal",
    "set_goal_status",
    "clear_goal",
    "pin_message",
    "unpin_message",
    "toggle_pinned_message",
    "archive_session",
    "unarchive_session",
    "fork_session",
    "discard_session",
    "btw_create",
    "btw_end",
    "rename_session",
    "record_session_note",
    "delete_session",
];

/// Production consumer of [`REMOTELY_LEDGERED_TRANSACTIONAL_TAGS`]: checks that
/// the registry stays in EXACT sync with the classification table's
/// remotely-admissible (non-`owner_only`) `transactional_mutation` rows. Called
/// once from `run_accept_loop`, but the equality is a `debug_assert_eq!` — it is
/// compiled OUT of release builds, so this enforces consistency only in
/// DEBUG/CI builds (a new or removed transactional tag without a matching
/// registry entry fails there); it does NOT trip a release daemon. The set
/// computation still references the registry in every profile so the const is
/// never dead code.
#[cfg(all(any(unix, test), feature = "remote"))]
pub(super) fn debug_assert_ledger_site_registry_consistent() {
    macro_rules! transactional_registry_rows {
        (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
            let mut rows = Vec::new();
            $($(#[$row_attr])* rows.push(($tag, stringify!($authz), stringify!($remote_class)));)+
            rows
        }};
    }
    let rows: Vec<(&str, &str, &str)> = proto::command!(transactional_registry_rows);
    let remotely_admissible: std::collections::BTreeSet<&str> = rows
        .iter()
        .filter(|(_, authz, class)| *class == "transactional_mutation" && *authz != "owner_only")
        .map(|(tag, _, _)| *tag)
        .collect();
    let registered: std::collections::BTreeSet<&str> = REMOTELY_LEDGERED_TRANSACTIONAL_TAGS
        .iter()
        .copied()
        .collect();
    debug_assert_eq!(
        registered, remotely_admissible,
        "REMOTELY_LEDGERED_TRANSACTIONAL_TAGS drifted from the classification table's \
         remotely-admissible transactional_mutation rows"
    );
}

/// Build the transactional-ledger identity for a session mutation admitted as
/// an authenticated remote operation: FCOR-encode the request at the
/// authorization boundary (resolved resources + canonical params), key-hash it,
/// and bind it to the admitted operation identity. Used by the session-mutation
/// dispatch arms (`fork_session`/`discard_session`/`btw_create`/`btw_end`/
/// `delete_session`) so the durable mutation and its exactly-once replay record
/// commit together on the daemon.
#[cfg(feature = "remote")]
fn build_remote_session_ledger(
    ctx: &DaemonContext,
    authorized_request: &AuthorizedRequestContext,
    request: &Request,
    operation: &super::RemoteOperationContext,
) -> std::result::Result<RemoteSessionLedger, ErrorPayload> {
    let canonical_params = request
        .canonical_remote_operation_params_v1()
        .map_err(internal)?;
    let canonical = authorized_request.encode_fcor(request, &canonical_params)?;
    let request_hash = remote_request_hash(ctx, &canonical);
    Ok(RemoteSessionLedger::new(operation, request_hash))
}

#[cfg(feature = "remote")]
async fn commit_remote_nonrepeatable(
    operation: &super::RemoteOperationContext,
    ctx: &DaemonContext,
    kind: &str,
    response: Response,
) -> std::result::Result<Response, ErrorPayload> {
    let attachment = operation.logical_attachment_id.to_string();
    let operation_id = operation.operation_id.to_string();
    let bytes = serde_json::to_vec(&response).map_err(internal)?;
    let delivery = Uuid::now_v7().to_string();
    match ctx
        .db
        .commit_remote_attachment_operation(
            crate::db::remote_attachment_operations::CommitRemoteOperation {
                logical_attachment_id: &attachment,
                operation_id: &operation_id,
                safe_response: &bytes,
                outbox_delivery_id: &delivery,
                outbox_kind: kind,
                outbox_payload: &bytes,
                now_ms: chrono::Utc::now().timestamp_millis(),
            },
        )
        .await
        .map_err(internal)?
    {
        crate::db::remote_attachment_operations::CommitRemoteOperationOutcome::Committed {
            ..
        } => Ok(response),
        _ => {
            ctx.db
                .mark_nonrepeatable_remote_operation_outcome_unknown(
                    &attachment,
                    &operation_id,
                    br#"{"outcome":"unknown"}"#,
                    chrono::Utc::now().timestamp_millis(),
                )
                .await
                .map_err(internal)?;
            Err(ErrorPayload {
                code: ErrorCode::Conflict,
                message: "remote operation outcome is unknown; it will not be retried".into(),
            })
        }
    }
}

/// Finish a provider configuration mutation that was admitted as a remote
/// nonrepeatable operation.
///
/// Provider layers live on the filesystem, so their write cannot share the
/// SQLite transaction that commits the remote replay record.  In particular,
/// a write error may be reported after an atomic replacement has reached the
/// filesystem.  Close the reserved operation as unknown in that case: a
/// retry must never run the mutation again and turn an indeterminate write
/// into a second provider-layer change.
#[cfg(feature = "remote")]
pub(super) async fn finish_remote_provider_mutation<F>(
    operation: &super::RemoteOperationContext,
    ctx: &DaemonContext,
    kind: &str,
    mutation: F,
) -> std::result::Result<Response, ErrorPayload>
where
    F: std::future::Future<Output = std::result::Result<Response, ErrorPayload>>,
{
    match mutation.await {
        Ok(response) => commit_remote_nonrepeatable(operation, ctx, kind, response).await,
        Err(error) => {
            let attachment = operation.logical_attachment_id.to_string();
            let operation_id = operation.operation_id.to_string();
            ctx.db
                .mark_nonrepeatable_remote_operation_outcome_unknown(
                    &attachment,
                    &operation_id,
                    br#"{"outcome":"unknown"}"#,
                    chrono::Utc::now().timestamp_millis(),
                )
                .await
                .map_err(internal)?;
            Err(error)
        }
    }
}

/// Apply an owner-vault mutation and commit its remote replay/outbox outcome
/// in one SQLite transaction.  A remote reservation is intentionally created
/// before dispatch, but must never be terminally recorded *after* a separate
/// vault transaction: a process loss between those writes would make the
/// mutation durable while leaving an indeterminate replay record.
// The argument list threads a durable vault mutation, its remote-ledger
// context, and the response together so the whole thing commits atomically;
// bundling them into a params struct would only obscure that hot security path
// for a purely cosmetic lint, so allow the count here.
#[cfg(feature = "remote")]
#[allow(clippy::too_many_arguments)]
async fn mutate_owner_vault_item_with_remote_ledger(
    ctx: &DaemonContext,
    operation: &super::RemoteOperationContext,
    kind: cockpit_db::secret_vault::SecretVaultKind,
    item_id: &str,
    plaintext: Option<&[u8]>,
    outbox_kind: &'static str,
    response: Response,
    disable_org_sync_for: Option<&str>,
) -> std::result::Result<Response, ErrorPayload> {
    let attachment = operation.logical_attachment_id.to_string();
    let operation_id = operation.operation_id.to_string();
    let item_id = item_id.to_owned();
    let plaintext = plaintext.map(ToOwned::to_owned);
    let bytes = serde_json::to_vec(&response).map_err(internal)?;
    let delivery = Uuid::now_v7().to_string();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let vault = ctx.secret_vault.clone();
    let transaction_attachment = attachment.clone();
    let transaction_operation_id = operation_id.clone();
    let disable_org_sync_for = disable_org_sync_for.map(ToOwned::to_owned);
    let committed = ctx
        .db
        .transaction(move |conn| {
            match plaintext.as_deref() {
                Some(value) => vault
                    .put_item_on_conn(conn, kind, &item_id, value)
                    .map_err(|error| anyhow::anyhow!(error))?,
                None => vault
                    .delete_item_on_conn(conn, kind, &item_id)
                    .map_err(|error| anyhow::anyhow!(error))?,
            }
            if let Some(server_url) = disable_org_sync_for.as_deref() {
                cockpit_db::Db::mark_org_sync_disabled_on_conn(conn, server_url, now_ms)?;
            }
            match crate::db::Db::commit_remote_attachment_operation_on_conn(
                conn,
                cockpit_db::remote_attachment_operations::CommitRemoteOperation {
                    logical_attachment_id: &transaction_attachment,
                    operation_id: &transaction_operation_id,
                    safe_response: &bytes,
                    outbox_delivery_id: &delivery,
                    outbox_kind,
                    outbox_payload: &bytes,
                    now_ms,
                },
            )? {
                cockpit_db::remote_attachment_operations::CommitRemoteOperationOutcome::Committed { .. } => Ok(()),
                outcome => anyhow::bail!("remote owner-secret ledger commit failed: {outcome:?}"),
            }
        })
        .await;
    if let Err(error) = committed {
        // The durable mutation transaction rolled back.  Preserve the
        // nonrepeatable safety rule: the reserved operation is not retried
        // after an indeterminate writer failure.
        ctx.db
            .mark_nonrepeatable_remote_operation_outcome_unknown(
                &attachment,
                &operation_id,
                br#"{\"outcome\":\"unknown\"}"#,
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            .map_err(internal)?;
        return Err(ErrorPayload {
            code: ErrorCode::Conflict,
            message: format!(
                "remote operation outcome is unknown; it will not be retried ({error})"
            ),
        });
    }
    // The committed response is now authoritative. Returning a normal error
    // here would make the caller retry while replay returns that response, so
    // publication failure instead poisons and force-shuts the daemon before
    // it can serve another request with a stale redaction table.
    if let Err(error) = ctx.publish_owner_redaction_table() {
        ctx.poison_redaction_publication(&error);
    }
    Ok(response)
}

#[cfg(feature = "remote")]
enum RemoteAdapterBegin {
    Dispatch { generation: u64 },
    Replay(Response),
}

#[cfg(feature = "remote")]
fn remote_adapter_incarnation_id() -> Uuid {
    static ID: std::sync::OnceLock<Uuid> = std::sync::OnceLock::new();
    *ID.get_or_init(Uuid::now_v7)
}

#[cfg(feature = "remote")]
async fn begin_remote_idempotent_adapter(
    request: &Request,
    authorized: &AuthorizedRequestContext,
    operation: &super::RemoteOperationContext,
    ctx: &DaemonContext,
) -> std::result::Result<RemoteAdapterBegin, ErrorPayload> {
    let params = request
        .canonical_remote_operation_params_v1()
        .map_err(internal)?;
    let canonical = authorized.encode_fcor(request, &params)?;
    let request_hash = remote_request_hash(ctx, &canonical);
    let attachment = operation.logical_attachment_id.to_string();
    let operation_id = operation.operation_id.to_string();
    let device = operation.authenticated_device_id.to_string();
    match ctx.db.begin_idempotent_adapter_remote_operation(
        crate::db::remote_attachment_operations::ReserveRemoteOperation {
            logical_attachment_id: &attachment,
            operation_id: &operation_id,
            authenticated_device_id: &device,
            authenticated_device_generation: operation.authenticated_device_generation,
            operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::IdempotentAdapterMutation,
            request_hash,
            now_ms: chrono::Utc::now().timestamp_millis(),
        }, remote_adapter_incarnation_id(), 30_000,
    ).await.map_err(internal)? {
        crate::db::remote_attachment_operations::BeginIdempotentAdapterRemoteOperationOutcome::Dispatch { dispatch_generation, .. } => Ok(RemoteAdapterBegin::Dispatch { generation: dispatch_generation }),
        crate::db::remote_attachment_operations::BeginIdempotentAdapterRemoteOperationOutcome::Replay(bytes) =>
            serde_json::from_slice(&bytes).map(RemoteAdapterBegin::Replay).map_err(internal),
        crate::db::remote_attachment_operations::BeginIdempotentAdapterRemoteOperationOutcome::OperationConflict
        | crate::db::remote_attachment_operations::BeginIdempotentAdapterRemoteOperationOutcome::OperationActorConflict =>
            Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation conflict".into() }),
        crate::db::remote_attachment_operations::BeginIdempotentAdapterRemoteOperationOutcome::ExistingIndeterminate =>
            Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation has an indeterminate persisted outcome; it will not be retried".into() }),
        crate::db::remote_attachment_operations::BeginIdempotentAdapterRemoteOperationOutcome::AttachmentLedgerCapacity =>
            Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation capacity reached".into() }),
    }
}

#[cfg(feature = "remote")]
async fn commit_remote_idempotent_adapter(
    operation: &super::RemoteOperationContext,
    ctx: &DaemonContext,
    kind: &str,
    expected_dispatch_generation: u64,
    response: Response,
) -> std::result::Result<Response, ErrorPayload> {
    let attachment = operation.logical_attachment_id.to_string();
    let operation_id = operation.operation_id.to_string();
    let bytes = serde_json::to_vec(&response).map_err(internal)?;
    let delivery = Uuid::now_v7().to_string();
    match ctx
        .db
        .commit_idempotent_adapter_remote_operation(
            crate::db::remote_attachment_operations::CommitRemoteOperation {
                logical_attachment_id: &attachment,
                operation_id: &operation_id,
                safe_response: &bytes,
                outbox_delivery_id: &delivery,
                outbox_kind: kind,
                outbox_payload: &bytes,
                now_ms: chrono::Utc::now().timestamp_millis(),
            },
            remote_adapter_incarnation_id(),
            expected_dispatch_generation,
        )
        .await
        .map_err(internal)?
    {
        crate::db::remote_attachment_operations::CommitRemoteOperationOutcome::Committed {
            ..
        } => Ok(response),
        _ => Err(ErrorPayload {
            code: ErrorCode::Conflict,
            message: "remote adapter result could not be committed; reconciliation is required"
                .into(),
        }),
    }
}

#[cfg(all(feature = "remote", any(target_os = "linux", target_os = "macos")))]
fn db_filesystem_identity(
    value: crate::external_journal::HeldEntryIdentity,
) -> crate::db::remote_attachment_operations::RemoteFilesystemIdentityV1 {
    crate::db::remote_attachment_operations::RemoteFilesystemIdentityV1 {
        filesystem_id: value.filesystem_id,
        object_id: value.object_id,
        kind: value.kind,
        len: value.len,
        mode: value.mode,
        owner_id: value.owner_id,
        link_count: value.link_count,
    }
}

#[cfg(all(feature = "remote", any(target_os = "linux", target_os = "macos")))]
async fn cleanup_remote_rename_artifacts(
    _ctx: &DaemonContext,
    journal: &crate::external_journal::ExternalJournal,
    _attachment: &str,
    _operation_id: &str,
) {
    let _ = journal.drain_remote_rename_artifact_cleanup().await;
}

#[cfg(all(feature = "remote", any(target_os = "linux", target_os = "macos")))]
async fn close_remote_rename_effect_unknown(
    ctx: &DaemonContext,
    journal: &crate::external_journal::ExternalJournal,
    attachment: &str,
    operation_id: &str,
    dispatch_generation: u64,
    message: &'static str,
) -> std::result::Result<Response, ErrorPayload> {
    ctx.db
        .record_remote_rename_effect_unknown(
            attachment,
            operation_id,
            dispatch_generation,
            b"{\"outcome\":\"unknown\"}",
            chrono::Utc::now().timestamp_millis(),
        )
        .await
        .map_err(internal)?;
    cleanup_remote_rename_artifacts(ctx, journal, attachment, operation_id).await;
    Err(ErrorPayload {
        code: ErrorCode::Conflict,
        message: message.into(),
    })
}

#[cfg(all(feature = "remote", any(target_os = "linux", target_os = "macos")))]
pub(crate) async fn execute_remote_staged_rename(
    request: &Request,
    authorized: &AuthorizedRequestContext,
    operation: &super::RemoteOperationContext,
    ctx: &DaemonContext,
) -> std::result::Result<Response, ErrorPayload> {
    execute_remote_staged_rename_with_hook(request, authorized, operation, ctx, |_| Ok(())).await
}

#[cfg(all(feature = "remote", any(target_os = "linux", target_os = "macos")))]
pub(super) async fn execute_remote_staged_rename_with_hook(
    request: &Request,
    authorized: &AuthorizedRequestContext,
    operation: &super::RemoteOperationContext,
    ctx: &DaemonContext,
    mut after_barrier: impl FnMut(&'static str) -> std::result::Result<(), ErrorPayload>,
) -> std::result::Result<Response, ErrorPayload> {
    use crate::db::remote_attachment_operations::{
        CommitRemoteOperation, CommitRemoteOperationOutcome, PrepareRemoteRenameOutcome,
        RemoteOperationClass, ReserveRemoteOperation,
    };
    use crate::external_journal::{DirGuard, HeldRenameEffect, RemoteRenameArtifactV1};

    let journal = ctx.external_journal.as_ref().ok_or_else(|| ErrorPayload {
        code: ErrorCode::Unavailable,
        message: "remote staged rename recovery authority is unavailable".into(),
    })?;
    journal
        .ensure_dispatch_allowed()
        .await
        .map_err(|error| ErrorPayload {
            code: ErrorCode::Unavailable,
            message: format!("remote staged rename recovery authority blocked dispatch: {error}"),
        })?;
    let paths: Vec<std::path::PathBuf> = authorized
        .fcor_resources
        .iter()
        .filter(|resource| {
            resource.kind == proto::remote_operation_fcor::RemoteOperationResourceKind::FilePath
        })
        .map(|resource| {
            std::str::from_utf8(&resource.value)
                .map(std::path::PathBuf::from)
                .map_err(internal)
        })
        .collect::<std::result::Result<_, _>>()?;
    let [source_path, target_path] = paths.as_slice() else {
        return Err(internal(anyhow::anyhow!(
            "rename requires exact source and target resources"
        )));
    };
    let source_parent_path = source_path
        .parent()
        .ok_or_else(|| internal(anyhow::anyhow!("rename source has no parent")))?;
    let target_parent_path = target_path
        .parent()
        .ok_or_else(|| internal(anyhow::anyhow!("rename target has no parent")))?;
    let source_name = source_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| internal(anyhow::anyhow!("rename source name is invalid")))?
        .to_owned();
    let target_name = target_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| internal(anyhow::anyhow!("rename target name is invalid")))?
        .to_owned();
    let source_parent = DirGuard::open_root(source_parent_path, false).map_err(internal)?;
    let target_parent = DirGuard::open_root(target_parent_path, false).map_err(internal)?;
    source_parent
        .require_same_filesystem(&target_parent)
        .map_err(internal)?;

    let params = request
        .canonical_remote_operation_params_v1()
        .map_err(internal)?;
    let canonical = authorized.encode_fcor(request, &params)?;
    let request_hash = remote_request_hash(ctx, &canonical);
    let attachment = operation.logical_attachment_id.to_string();
    let operation_id = operation.operation_id.to_string();
    let device = operation.authenticated_device_id.to_string();
    let source_observed = source_parent.open_entry_identity(&source_name).ok();
    if source_observed.is_some() {
        target_parent
            .require_entry_absent(&target_name)
            .map_err(|_| ErrorPayload {
                code: ErrorCode::Conflict,
                message: "remote rename target already exists".into(),
            })?;
    }
    let source_parent_identity =
        db_filesystem_identity(source_parent.held_identity().map_err(internal)?);
    let target_parent_identity =
        db_filesystem_identity(target_parent.held_identity().map_err(internal)?);
    let outcome = ctx
        .db
        .prepare_remote_rename_operation(
            ReserveRemoteOperation {
                logical_attachment_id: &attachment,
                operation_id: &operation_id,
                authenticated_device_id: &device,
                authenticated_device_generation: operation.authenticated_device_generation,
                operation_class: RemoteOperationClass::IdempotentAdapterMutation,
                request_hash,
                now_ms: chrono::Utc::now().timestamp_millis(),
            },
            source_observed.map(db_filesystem_identity),
            Some(source_parent_identity),
            Some(target_parent_identity),
        )
        .await
        .map_err(internal)?;
    let evidence = match outcome {
        PrepareRemoteRenameOutcome::Prepared(value)
        | PrepareRemoteRenameOutcome::Reconcile(value) => value,
        PrepareRemoteRenameOutcome::Replay(bytes) => {
            cleanup_remote_rename_artifacts(ctx, journal, &attachment, &operation_id).await;
            return serde_json::from_slice(&bytes).map_err(internal);
        }
        PrepareRemoteRenameOutcome::OutcomeUnknown(_) => {
            cleanup_remote_rename_artifacts(ctx, journal, &attachment, &operation_id).await;
            return Err(ErrorPayload {
                code: ErrorCode::Conflict,
                message: "remote rename outcome is unknown and will not be redispatched".into(),
            });
        }
        PrepareRemoteRenameOutcome::OperationConflict
        | PrepareRemoteRenameOutcome::OperationActorConflict => {
            return Err(ErrorPayload {
                code: ErrorCode::Conflict,
                message: "remote operation conflict".into(),
            });
        }
        PrepareRemoteRenameOutcome::AttachmentLedgerCapacity => {
            return Err(ErrorPayload {
                code: ErrorCode::Conflict,
                message: "remote operation capacity reached".into(),
            });
        }
    };
    if evidence.state != "applied"
        && (evidence.source_parent_identity != source_parent_identity
            || evidence.target_parent_identity != target_parent_identity)
    {
        ctx.db
            .record_remote_rename_effect_unknown(
                &attachment,
                &operation_id,
                evidence.dispatch_generation,
                b"{\"outcome\":\"unknown\"}",
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            .map_err(internal)?;
        cleanup_remote_rename_artifacts(ctx, journal, &attachment, &operation_id).await;
        return Err(ErrorPayload {
            code: ErrorCode::Conflict,
            message: "rename authority changed during recovery".into(),
        });
    }
    let artifact_id = Uuid::parse_str(&evidence.artifact_id).map_err(internal)?;
    let artifact = RemoteRenameArtifactV1 {
        logical_attachment_id: operation.logical_attachment_id,
        operation_id: operation.operation_id,
        dispatch_generation: evidence.dispatch_generation,
        source_identity: evidence.source_identity,
        source_parent_identity: evidence.source_parent_identity,
        target_parent_identity: evidence.target_parent_identity,
        source_name: source_name.clone(),
        target_name: target_name.clone(),
    };
    match journal.read_remote_rename_artifact(artifact_id, evidence.dispatch_generation) {
        Ok(stored) if stored == artifact => {}
        Ok(_) => {
            ctx.db
                .record_remote_rename_effect_unknown(
                    &attachment,
                    &operation_id,
                    evidence.dispatch_generation,
                    b"{\"outcome\":\"unknown\"}",
                    chrono::Utc::now().timestamp_millis(),
                )
                .await
                .map_err(internal)?;
            cleanup_remote_rename_artifacts(ctx, journal, &attachment, &operation_id).await;
            return Err(ErrorPayload {
                code: ErrorCode::Conflict,
                message: "rename artifact binding mismatch; outcome is unknown".into(),
            });
        }
        Err(crate::external_journal::ExternalJournalError::CapsuleMissing(_)) => {
            if let Err(error) = journal.write_remote_rename_artifact(artifact_id, &artifact) {
                ctx.db
                    .record_remote_rename_effect_unknown(
                        &attachment,
                        &operation_id,
                        evidence.dispatch_generation,
                        b"{\"outcome\":\"unknown\"}",
                        chrono::Utc::now().timestamp_millis(),
                    )
                    .await
                    .map_err(internal)?;
                cleanup_remote_rename_artifacts(ctx, journal, &attachment, &operation_id).await;
                return Err(internal(error));
            }
        }
        Err(error) => {
            ctx.db
                .record_remote_rename_effect_unknown(
                    &attachment,
                    &operation_id,
                    evidence.dispatch_generation,
                    b"{\"outcome\":\"unknown\"}",
                    chrono::Utc::now().timestamp_millis(),
                )
                .await
                .map_err(internal)?;
            cleanup_remote_rename_artifacts(ctx, journal, &attachment, &operation_id).await;
            return Err(internal(error));
        }
    }
    after_barrier("artifact_durable")?;
    if evidence.state == "prepared" {
        if source_observed.map(db_filesystem_identity) != Some(evidence.source_identity) {
            ctx.db
                .record_remote_rename_effect_unknown(
                    &attachment,
                    &operation_id,
                    evidence.dispatch_generation,
                    b"{\"outcome\":\"unknown\"}",
                    chrono::Utc::now().timestamp_millis(),
                )
                .await
                .map_err(internal)?;
            cleanup_remote_rename_artifacts(ctx, journal, &attachment, &operation_id).await;
            return Err(ErrorPayload {
                code: ErrorCode::Conflict,
                message: "rename source changed after reservation; outcome is closed as unknown"
                    .into(),
            });
        }
        if target_parent.require_entry_absent(&target_name).is_err() {
            return close_remote_rename_effect_unknown(
                ctx,
                journal,
                &attachment,
                &operation_id,
                evidence.dispatch_generation,
                "rename target appeared after artifact durability; outcome is closed as unknown",
            )
            .await;
        }
        if !ctx
            .db
            .advance_remote_rename_operation(
                &attachment,
                &operation_id,
                evidence.dispatch_generation,
                "prepared",
                "artifact_synced",
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            .map_err(internal)?
        {
            return Err(internal(anyhow::anyhow!(
                "rename artifact barrier generation lost"
            )));
        }
        after_barrier("artifact_journal_synced")?;
    }
    let mut state = if evidence.state == "prepared" {
        "artifact_synced"
    } else {
        evidence.state.as_str()
    };
    if state == "artifact_synced" {
        match (
            source_parent.open_entry_identity(&source_name),
            target_parent.open_entry_identity(&target_name),
        ) {
            (Ok(source), Err(_)) if db_filesystem_identity(source) == evidence.source_identity => {
                if target_parent.require_entry_absent(&target_name).is_err() {
                    return close_remote_rename_effect_unknown(
                        ctx,
                        journal,
                        &attachment,
                        &operation_id,
                        evidence.dispatch_generation,
                        "rename target appeared before dispatch; outcome is closed as unknown",
                    )
                    .await;
                }
                let rename_effect = match source_parent.rename_entry_noreplace_atomic(
                    &source_name,
                    &target_parent,
                    &target_name,
                    source,
                ) {
                    Ok(effect) => effect,
                    Err(crate::external_journal::ExternalJournalError::QuarantineNameTaken(_)) => {
                        ctx.db
                            .record_remote_rename_effect_unknown(
                                &attachment,
                                &operation_id,
                                evidence.dispatch_generation,
                                b"{\"outcome\":\"unknown\"}",
                                chrono::Utc::now().timestamp_millis(),
                            )
                            .await
                            .map_err(internal)?;
                        cleanup_remote_rename_artifacts(ctx, journal, &attachment, &operation_id)
                            .await;
                        return Err(ErrorPayload { code: ErrorCode::Conflict, message: "rename target appeared during dispatch; outcome is closed as unknown".into() });
                    }
                    Err(error) => return Err(internal(error)),
                };
                match rename_effect {
                    HeldRenameEffect::Applied(_) => {}
                    HeldRenameEffect::AppliedIdentityMismatch { observed, .. } => {
                        ctx.db
                            .record_remote_rename_applied_mismatch(
                                &attachment,
                                &operation_id,
                                evidence.dispatch_generation,
                                db_filesystem_identity(observed),
                                b"{\"outcome\":\"unknown\"}",
                                chrono::Utc::now().timestamp_millis(),
                            )
                            .await
                            .map_err(internal)?;
                        cleanup_remote_rename_artifacts(ctx, journal, &attachment, &operation_id)
                            .await;
                        return Err(ErrorPayload {
                            code: ErrorCode::Conflict,
                            message:
                                "rename applied an unexpected source identity; outcome is unknown"
                                    .into(),
                        });
                    }
                }
                after_barrier("rename_effect")?;
            }
            (Err(_), Ok(target)) if db_filesystem_identity(target) == evidence.source_identity => {}
            _ => {
                ctx.db
                    .record_remote_rename_effect_unknown(
                        &attachment,
                        &operation_id,
                        evidence.dispatch_generation,
                        b"{\"outcome\":\"unknown\"}",
                        chrono::Utc::now().timestamp_millis(),
                    )
                    .await
                    .map_err(internal)?;
                cleanup_remote_rename_artifacts(ctx, journal, &attachment, &operation_id).await;
                return Err(ErrorPayload {
                    code: ErrorCode::Conflict,
                    message: "rename filesystem evidence is ambiguous; outcome is unknown".into(),
                });
            }
        }
        ctx.db
            .advance_remote_rename_operation(
                &attachment,
                &operation_id,
                evidence.dispatch_generation,
                "artifact_synced",
                "renamed",
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            .map_err(internal)?;
        state = "renamed";
    }
    if state == "renamed" {
        source_parent.sync().map_err(internal)?;
        after_barrier("source_parent_fsync")?;
        ctx.db
            .advance_remote_rename_operation(
                &attachment,
                &operation_id,
                evidence.dispatch_generation,
                "renamed",
                "source_parent_synced",
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            .map_err(internal)?;
        state = "source_parent_synced";
    }
    if state == "source_parent_synced" {
        target_parent.sync().map_err(internal)?;
        after_barrier("target_parent_fsync")?;
        ctx.db
            .advance_remote_rename_operation(
                &attachment,
                &operation_id,
                evidence.dispatch_generation,
                "source_parent_synced",
                "target_parent_synced",
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            .map_err(internal)?;
        state = "target_parent_synced";
    }
    if state == "target_parent_synced" {
        ctx.db
            .advance_remote_rename_operation(
                &attachment,
                &operation_id,
                evidence.dispatch_generation,
                "target_parent_synced",
                "applied",
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            .map_err(internal)?;
        after_barrier("applied_journal")?;
    }
    let response = Response::Ack;
    let bytes = serde_json::to_vec(&response).map_err(internal)?;
    let delivery = Uuid::now_v7().to_string();
    match ctx
        .db
        .commit_remote_rename_operation(
            CommitRemoteOperation {
                logical_attachment_id: &attachment,
                operation_id: &operation_id,
                safe_response: &bytes,
                outbox_delivery_id: &delivery,
                outbox_kind: "fs_rename",
                outbox_payload: &bytes,
                now_ms: chrono::Utc::now().timestamp_millis(),
            },
            evidence.dispatch_generation,
        )
        .await
        .map_err(internal)?
    {
        CommitRemoteOperationOutcome::Committed { .. } => {
            after_barrier("ledger_committed")?;
            cleanup_remote_rename_artifacts(ctx, journal, &attachment, &operation_id).await;
            Ok(response)
        }
        _ => Err(ErrorPayload {
            code: ErrorCode::Conflict,
            message: "remote rename result could not be committed".into(),
        }),
    }
}

/// LOCAL owner image-generation control-plane READ dispatch, shared by the
/// serialized and concurrent surfaces. These commands are declared
/// `owner_only` + `local_only` + `concurrent`, so at runtime they route to the
/// concurrent surface; the arm is duplicated on the (exhaustive) serialized
/// surface for match completeness. Every reply is a redacted safe projection
/// assembled through the single `cockpit_proto::image_control` funnel.
async fn dispatch_image_control_read(
    ctx: &Arc<DaemonContext>,
    request: Request,
) -> std::result::Result<Response, ErrorPayload> {
    // Every image-control read carries the project root. Resolve it once, then
    // load the image-generation registry through the SAME trust-gated daemon
    // config contract every other owner config read uses
    // (`resolve_workspace_trust_policy_from_db` + `load_effective_for_daemon`):
    // untrusted project layers are filtered out and remote `image_generation`
    // is stripped before it can be projected. `project_root` is only a config
    // cwd here, never authority — the RPC is already `owner_only`-gated.
    let project_root = match &request {
        Request::ImageEndpointList { project_root, .. }
        | Request::ImageEndpointGet { project_root, .. }
        | Request::ImageTargetList { project_root, .. }
        | Request::ImageTargetGet { project_root, .. }
        | Request::ImageWorkflowList { project_root, .. }
        | Request::ImageWorkflowGet { project_root, .. } => project_root.clone(),
        other => {
            return Err(internal(format!(
                "dispatch_image_control_read called with non-image-control request `{}`",
                principal::request_kind(other)
            )));
        }
    };
    if project_root.trim().is_empty() {
        return Err(bad_request("project_root must not be empty"));
    }
    let cwd = std::path::PathBuf::from(&project_root);
    let trust_policy = crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &cwd)
        .await
        .map_err(internal)?;
    let (_, extended) = ctx
        .config_source
        .load_effective_for_daemon(&cwd, &trust_policy)
        .map_err(internal)?;
    let cfg = &extended.image_generation;
    let generation = inventory::current_config_generation().to_string();
    let daemon_instance_id = inventory::daemon_instance_id().to_string();
    match request {
        Request::ImageEndpointList { limit, cursor, .. } => image_control_reads::endpoint_list(
            cfg,
            &generation,
            daemon_instance_id,
            project_root,
            limit,
            cursor.as_deref(),
        )
        .map(Response::ImageControlRead),
        Request::ImageEndpointGet { endpoint_id, .. } => image_control_reads::endpoint_get(
            cfg,
            &generation,
            daemon_instance_id,
            project_root,
            &endpoint_id,
        )
        .map(Response::ImageControlRead),
        Request::ImageTargetList { limit, cursor, .. } => image_control_reads::target_list(
            cfg,
            &generation,
            daemon_instance_id,
            project_root,
            limit,
            cursor.as_deref(),
        )
        .map(Response::ImageControlRead),
        Request::ImageTargetGet { target_id, .. } => image_control_reads::target_get(
            cfg,
            &generation,
            daemon_instance_id,
            project_root,
            &target_id,
        )
        .map(Response::ImageControlRead),
        Request::ImageWorkflowList { limit, cursor, .. } => image_control_reads::workflow_list(
            cfg,
            &generation,
            daemon_instance_id,
            project_root,
            limit,
            cursor.as_deref(),
        )
        .map(Response::ImageControlRead),
        Request::ImageWorkflowGet { workflow_id, .. } => image_control_reads::workflow_get(
            cfg,
            &generation,
            daemon_instance_id,
            project_root,
            &workflow_id,
        )
        .map(Response::ImageControlRead),
        // The project_root pre-match already rejected any non-image-control
        // variant, so this arm is unreachable.
        other => Err(internal(format!(
            "dispatch_image_control_read called with non-image-control request `{}`",
            principal::request_kind(&other)
        ))),
    }
}

async fn handle_serialized_request_impl(
    request: Request,
    state: &mut MutableClientState,
    shared: &Arc<SharedClientState>,
    ctx: &Arc<DaemonContext>,
    effects: &mut ClientRequestEffects,
    #[cfg(feature = "remote")] remote_operation: Option<&super::RemoteOperationContext>,
) -> std::result::Result<Response, ErrorPayload> {
    if ctx.redaction_publication_is_poisoned() {
        return Err(ErrorPayload {
            code: ErrorCode::Internal,
            message: "daemon is shutting down after a redaction publication failure".into(),
        });
    }
    #[cfg(feature = "remote")]
    if let Some(operation) = remote_operation {
        tracing::debug!(
            request_id = %operation.request_id,
            operation_id = %operation.operation_id,
            logical_attachment_id = %operation.logical_attachment_id,
            authenticated_device_id = %operation.authenticated_device_id,
            authenticated_device_generation = operation.authenticated_device_generation,
            "dispatching admitted remote operation"
        );
    }
    validate_request_semantics(&request)?;
    debug_assert_eq!(shared.principal, state.principal);
    let pruned = prune_expired_attachments(state);
    for receipt in pruned.cancelled {
        ctx.media_ledger
            .request_cancellation(
                &receipt.reservation_id,
                receipt.version,
                chrono::Utc::now()
                    .timestamp_millis()
                    .try_into()
                    .unwrap_or(0),
            )
            .await
            .map_err(internal)?;
    }
    for receipt in pruned.destroyed {
        ctx.media_ledger
            .destroy_local_artifacts(
                &receipt.reservation_id,
                receipt.version,
                &format!("attachment-ttl-destroyed:{}", receipt.reservation_id),
                chrono::Utc::now()
                    .timestamp_millis()
                    .try_into()
                    .unwrap_or(0),
            )
            .await
            .map_err(internal)?;
    }
    #[cfg(feature = "remote")]
    let request_kind = principal::request_kind(&request);
    #[cfg(feature = "remote")]
    let audit_session_id = request_session_id(&request, state);
    #[cfg(feature = "remote")]
    let audit_path = request_audit_path(&request);
    #[cfg(feature = "remote")]
    let audit_remote = !state.principal.is_owner() && is_remote_mutating_request(&request);
    #[cfg(feature = "remote")]
    let authorized_request = match authorize_request_context(&request, state, ctx).await {
        Ok(authorized) => authorized,
        Err(error) => {
            if audit_remote {
                audit_remote_request(
                    ctx,
                    &state.principal,
                    request_kind,
                    audit_session_id,
                    audit_path.as_deref(),
                    "denied",
                )
                .await;
            }
            // `SetDefaultModel` is terminal-by-event: a bare authorization error
            // would leave a remote/shared client waiting for a correlated result
            // that never arrives. Emit the typed rejection instead — no scope
            // label, no path, no configuration content, and no mutation.
            if let Request::SetDefaultModel {
                default_update_id, ..
            } = &request
                && let Some(att) = state.attached.as_ref()
            {
                att.handle.broadcast_default_model_update_result(
                *default_update_id,
                proto::DefaultModelStandaloneOutcome::Rejected {
                    user_message: "Changing the default model for new sessions requires the                                    local owner of this workspace."
                        .to_string(),
                    diagnostic_code: "effective_default_local_owner_only".to_string(),
                },
            );
            }
            return Err(error);
        }
    };
    #[cfg(not(feature = "remote"))]
    if let Err(error) = authorize_request_context(&request, state, ctx).await {
        return Err(error);
    }
    #[cfg(feature = "remote")]
    if audit_remote {
        audit_remote_request(
            ctx,
            &state.principal,
            request_kind,
            audit_session_id,
            audit_path.as_deref(),
            "allowed",
        )
        .await;
    }
    match request {
        Request::Attach {
            session_id,
            since_seq,
            project_root,
            initial_model,
            no_sandbox,
            interactive,
            model_override,
            client_protocol_version,
            env_snapshot,
            env_policy,
        } => {
            let principal = state.principal.clone();
            attach(
                state,
                ctx,
                session_id,
                since_seq,
                project_root,
                initial_model,
                no_sandbox,
                interactive,
                model_override,
                client_protocol_version,
                env_snapshot,
                env_policy,
                &principal,
                effects,
            )
            .await
        }

        Request::SubagentTranscript {
            session_id,
            task_call_id,
            label,
        } => {
            let db = ctx.db.clone();
            let task_call_id_for_read = task_call_id.clone();
            let label_for_read = label.clone();
            let mut history = db
                .read(move |conn| {
                    crate::engine::rehydrate::subagent_history_snapshot_conn(
                        conn,
                        session_id,
                        &task_call_id_for_read,
                        &label_for_read,
                    )
                })
                .await
                .map_err(internal)?;
            if !state.principal.is_owner() {
                let redact = if let Some(handle) = ctx.registry.live_handle(session_id) {
                    handle.redaction_table()
                } else {
                    let session = crate::session::Session::resume(
                        ctx.db.clone(),
                        session_id,
                        ctx.redaction_key_resolver().map_err(internal)?,
                        ctx.secret_vault.clone(),
                    )
                    .map_err(internal)?
                    .ok_or_else(|| ErrorPayload {
                        code: ErrorCode::UnknownSession,
                        message: format!("unknown session {session_id}"),
                    })?;
                    std::sync::Arc::new(
                        session
                            .persisted_redaction_table()
                            .map_err(internal)?
                            .ok_or_else(|| ErrorPayload {
                                code: ErrorCode::Authorization,
                                message: "session transcript redaction data is unavailable"
                                    .to_string(),
                            })?,
                    )
                };
                history = scrub_history_for_principal(&state.principal, history, &redact);
            }
            Ok(Response::SubagentTranscript {
                session_id,
                task_call_id,
                label,
                history,
            })
        }

        Request::SendUserMessage {
            expected_model_state_generation,
            expected_model,
            client_submission_id,
            text,
            display_text,
            tag_expansions,
            image_refs,
            forced_skill,
            run_invocation_options,
        } => {
            Box::pin(handle_send_user_message(
                state,
                ctx,
                client_submission_id,
                expected_model_state_generation,
                expected_model,
                text,
                display_text,
                tag_expansions,
                image_refs,
                forced_skill,
                run_invocation_options,
                #[cfg(feature = "remote")]
                remote_operation,
            ))
            .await
        }

        Request::SendUserMessageBulk {
            expected_model_state_generation,
            expected_model,
            client_submission_id,
            transfer,
            display_text,
            display_transfer,
            tag_expansions,
            forced_skill,
            run_invocation_options,
        } => {
            Box::pin(handle_send_user_message_bulk(
                state,
                ctx,
                client_submission_id,
                expected_model_state_generation,
                expected_model,
                transfer,
                display_text,
                display_transfer,
                tag_expansions,
                forced_skill,
                run_invocation_options,
                #[cfg(feature = "remote")]
                remote_operation,
            ))
            .await
        }

        Request::GetRunInvocationStatus {
            client_submission_id,
        } => {
            run_invocation::handle_get_run_invocation_status(state, ctx, client_submission_id).await
        }

        Request::CancelRunInvocation {
            client_submission_id,
        } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let canonical_request = Request::CancelRunInvocation {
                    client_submission_id,
                };
                let params = canonical_request
                    .canonical_remote_operation_params_v1()
                    .map_err(internal)?;
                let canonical = authorized_request.encode_fcor(&canonical_request, &params)?;
                let request_hash = remote_request_hash(ctx, &canonical);
                let logical_attachment_id = operation.logical_attachment_id.to_string();
                let operation_id = operation.operation_id.to_string();
                let device_id = operation.authenticated_device_id.to_string();
                let digest = principal_digest(&state.principal);
                let is_owner = state.principal.is_owner();
                let now = wall_ms_now();
                let outcome = ctx.db.execute_transactional_remote_operation(
                    crate::db::remote_attachment_operations::ReserveRemoteOperation {
                        logical_attachment_id: &logical_attachment_id, operation_id: &operation_id,
                        authenticated_device_id: &device_id, authenticated_device_generation: operation.authenticated_device_generation,
                        operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::TransactionalMutation,
                        request_hash, now_ms: now,
                    },
                    move |conn| {
                        let lookup = crate::db::Db::lookup_or_tombstone_run_invocation_conn(
                            conn, client_submission_id, &digest, now, is_owner,
                        )?;
                        let row = match lookup {
                            crate::db::run_invocations::LookupRunInvocationOutcome::Found(row) => *row,
                            crate::db::run_invocations::LookupRunInvocationOutcome::LookupBusy => anyhow::bail!("invocation lookup busy"),
                            crate::db::run_invocations::LookupRunInvocationOutcome::NotFoundInstalledTombstone
                            | crate::db::run_invocations::LookupRunInvocationOutcome::NotFoundExistingTombstone => {
                                let receipt = proto::RunInvocationCancelResultV1 {
                                    schema_version: proto::RunInvocationCancelResultV1::SCHEMA_VERSION,
                                    client_submission_id,
                                    outcome: proto::RunInvocationCancelOutcome::NotFound,
                                    state: proto::RunInvocationLifecycleState::NotFound,
                                    state_version: 0,
                                };
                                let bytes = serde_json::to_vec(&receipt)?;
                                return Ok(crate::db::remote_attachment_operations::TransactionalRemoteMutation {
                                    value: (receipt, None), safe_response: bytes.clone(),
                                    outbox_kind: "cancel_run_invocation".into(), outbox_payload: bytes,
                                });
                            }
                        };
                        let updated = if row.cancel_result.is_some() {
                            row
                        } else {
                            let (state_name, result) = if row.terminal_at_wall_ms.is_some() {
                                (row.state.as_str(), "already_terminal")
                            } else {
                                ("cancellation_requested", "cancellation_requested")
                            };
                            crate::db::Db::update_run_invocation_state_conn(
                                conn, client_submission_id, row.state_version, state_name,
                                row.remaining_ms, Some(true), Some(result), now,
                            )?.ok_or_else(|| anyhow::anyhow!("invocation not found"))?
                        };
                        let result = match updated.cancel_result.as_deref() {
                            Some("cancellation_requested") => proto::RunInvocationCancelOutcome::CancellationRequested,
                            Some("already_cancelled") => proto::RunInvocationCancelOutcome::AlreadyCancelled,
                            Some("already_terminal") => proto::RunInvocationCancelOutcome::AlreadyTerminal,
                            _ => anyhow::bail!("invalid cancellation result"),
                        };
                        let receipt = proto::RunInvocationCancelResultV1 {
                            schema_version: proto::RunInvocationCancelResultV1::SCHEMA_VERSION,
                            client_submission_id, outcome: result,
                            state: run_invocation::parse_lifecycle_state(&updated.state)
                                .map_err(|error| anyhow::anyhow!(error.message))?,
                            state_version: updated.state_version,
                        };
                        let bytes = serde_json::to_vec(&receipt)?;
                        Ok(crate::db::remote_attachment_operations::TransactionalRemoteMutation {
                            value: (receipt, Some(updated.session_id)), safe_response: bytes.clone(),
                            outbox_kind: "cancel_run_invocation".into(), outbox_payload: bytes,
                        })
                    },
                ).await.map_err(internal)?;
                let (result, session_id, applied) = match outcome {
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied((result, session_id)) => (result, session_id, true),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(bytes) => {
                        let result: proto::RunInvocationCancelResultV1 = serde_json::from_slice(&bytes).map_err(internal)?;
                        (result, None, false)
                    }
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationConflict
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationActorConflict
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::ExistingIndeterminate => return Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation conflict".into() }),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity => return Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation capacity reached".into() }),
                };
                if applied
                    && result.outcome == proto::RunInvocationCancelOutcome::CancellationRequested
                    && let Some(session_id) = session_id
                    && let Some(handle) = ctx.registry.live_handle(session_id)
                {
                    let _ = handle.send_work(SessionWork::Cancel).await;
                }
                Ok(Response::RunInvocationCancelResult { result })
            } else {
                run_invocation::handle_cancel_run_invocation(state, ctx, client_submission_id).await
            }
            #[cfg(not(feature = "remote"))]
            {
                run_invocation::handle_cancel_run_invocation(state, ctx, client_submission_id).await
            }
        }

        Request::SteerDelegation {
            session_id,
            task_call_id,
            label,
            message,
        } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::SteerDelegation {
                    session_id,
                    task_call_id: task_call_id.clone(),
                    label: label.clone(),
                    message: message.clone(),
                };
                if let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
                {
                    return Ok(response);
                }
            }
            let Some(handle) = ctx.registry.live_handle(session_id) else {
                let response = Response::DelegationSteer {
                    result: proto::DelegationSteerResult::not_steerable(
                        task_call_id,
                        Some(label),
                        "session is not live".to_string(),
                    ),
                };
                #[cfg(feature = "remote")]
                return match remote_operation {
                    Some(operation) => {
                        commit_remote_nonrepeatable(operation, ctx, "steer_delegation", response)
                            .await
                    }
                    None => Ok(response),
                };
                #[cfg(not(feature = "remote"))]
                return Ok(response);
            };
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            handle
                .send_work(SessionWork::SteerDelegation {
                    task_call_id,
                    label,
                    message,
                    origin_principal: state.principal.steer_origin(),
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let result = response_rx.await.map_err(internal)?;
            let response = Response::DelegationSteer { result };
            #[cfg(feature = "remote")]
            {
                match remote_operation {
                    Some(operation) => {
                        commit_remote_nonrepeatable(operation, ctx, "steer_delegation", response)
                            .await
                    }
                    None => Ok(response),
                }
            }
            #[cfg(not(feature = "remote"))]
            {
                Ok(response)
            }
        }

        Request::BeginAttachmentUpload {
            mime,
            byte_len,
            sha256,
            purpose,
        } => {
            begin_attachment_upload_admitted(ctx, state, mime, byte_len as usize, sha256, purpose)
                .await
        }

        Request::UploadAttachmentChunk {
            upload_id,
            offset,
            data_base64,
        } => upload_attachment_chunk(state, upload_id, offset as usize, data_base64),

        Request::FinishAttachmentUpload { upload_id } => {
            finish_attachment_upload_admitted(ctx, state, upload_id).await
        }

        Request::CancelAttachmentUpload { upload_id } => {
            if let Some(upload) = state.pending_uploads.remove(&upload_id) {
                release_uploads(&state.upload_accounting, [upload_id]);
                if let Some(receipt) = upload.media_reservation {
                    ctx.media_ledger
                        .request_cancellation(
                            &receipt.reservation_id,
                            receipt.version,
                            chrono::Utc::now()
                                .timestamp_millis()
                                .try_into()
                                .unwrap_or(0),
                        )
                        .await
                        .map_err(internal)?;
                }
            }
            Ok(Response::Ack)
        }

        Request::RemoveQueuedUserMessage { queue_item_id } => {
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            let remote_queue_operation = if let Some(operation) = remote_operation {
                let request = Request::RemoveQueuedUserMessage { queue_item_id };
                let params = request
                    .canonical_remote_operation_params_v1()
                    .map_err(internal)?;
                let canonical = authorized_request.encode_fcor(&request, &params)?;
                Some(crate::daemon::session_worker::RemoteQueueOperation {
                    logical_attachment_id: operation.logical_attachment_id.to_string(),
                    operation_id: operation.operation_id.to_string(),
                    authenticated_device_id: operation.authenticated_device_id.to_string(),
                    authenticated_device_generation: operation.authenticated_device_generation,
                    request_hash: remote_request_hash(ctx, &canonical),
                })
            } else {
                None
            };
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::RemoveQueuedUserMessage {
                    queue_item_id,
                    #[cfg(feature = "remote")]
                    remote_operation: remote_queue_operation,
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let result = response_rx.await.map_err(internal)??;
            Ok(Response::RemoveQueuedUserMessageResult {
                applied: result.applied,
                reason: result.reason,
                removed_item: result.removed_item,
                queue: result.queue,
            })
        }
        Request::RemoveNewestQueuedUserMessage { target_id } => {
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            let remote_queue_operation = if let Some(operation) = remote_operation {
                if target_id.is_none() {
                    return Err(ErrorPayload {
                        code: ErrorCode::BadRequest,
                        message: "remote editable queue removal requires an explicit target_id"
                            .into(),
                    });
                }
                let request = Request::RemoveNewestQueuedUserMessage {
                    target_id: target_id.clone(),
                };
                let params = request
                    .canonical_remote_operation_params_v1()
                    .map_err(internal)?;
                let canonical = authorized_request.encode_fcor(&request, &params)?;
                Some(crate::daemon::session_worker::RemoteQueueOperation {
                    logical_attachment_id: operation.logical_attachment_id.to_string(),
                    operation_id: operation.operation_id.to_string(),
                    authenticated_device_id: operation.authenticated_device_id.to_string(),
                    authenticated_device_generation: operation.authenticated_device_generation,
                    request_hash: remote_request_hash(ctx, &canonical),
                })
            } else {
                None
            };
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::RemoveNewestQueuedUserMessage {
                    target_id,
                    #[cfg(feature = "remote")]
                    remote_operation: remote_queue_operation,
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let result = response_rx.await.map_err(internal)??;
            Ok(Response::RemoveQueuedUserMessageResult {
                applied: result.applied,
                reason: result.reason,
                removed_item: result.removed_item,
                queue: result.queue,
            })
        }
        Request::RemoveEditableQueuedUserMessages { target_id } => {
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            let remote_queue_operation = if let Some(operation) = remote_operation {
                let request = Request::RemoveEditableQueuedUserMessages {
                    target_id: target_id.clone(),
                };
                let params = request
                    .canonical_remote_operation_params_v1()
                    .map_err(internal)?;
                let canonical = authorized_request.encode_fcor(&request, &params)?;
                Some(crate::daemon::session_worker::RemoteQueueOperation {
                    logical_attachment_id: operation.logical_attachment_id.to_string(),
                    operation_id: operation.operation_id.to_string(),
                    authenticated_device_id: operation.authenticated_device_id.to_string(),
                    authenticated_device_generation: operation.authenticated_device_generation,
                    request_hash: remote_request_hash(ctx, &canonical),
                })
            } else {
                None
            };
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::RemoveEditableQueuedUserMessages {
                    target_id,
                    #[cfg(feature = "remote")]
                    remote_operation: remote_queue_operation,
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let result = response_rx.await.map_err(internal)??;
            Ok(Response::RemoveQueuedUserMessagesResult {
                applied: result.applied,
                reason: result.reason,
                removed_items: result.removed_items,
                queue: result.queue,
            })
        }

        Request::ResumePausedWork { session_id } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::ResumePausedWork { session_id };
                let canonical_params = request
                    .canonical_remote_operation_params_v1()
                    .map_err(internal)?;
                let canonical = authorized_request.encode_fcor(&request, &canonical_params)?;
                let request_hash = remote_request_hash(ctx, &canonical);
                let logical_attachment_id = operation.logical_attachment_id.to_string();
                let operation_id = operation.operation_id.to_string();
                let device_id = operation.authenticated_device_id.to_string();
                let outcome = ctx.db.execute_transactional_remote_operation(
                    crate::db::remote_attachment_operations::ReserveRemoteOperation {
                        logical_attachment_id: &logical_attachment_id,
                        operation_id: &operation_id,
                        authenticated_device_id: &device_id,
                        authenticated_device_generation: operation.authenticated_device_generation,
                        operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::TransactionalMutation,
                        request_hash,
                        now_ms: chrono::Utc::now().timestamp_millis(),
                    },
                    move |conn| {
                        let changed = crate::db::Db::resolve_paused_session_work_conn(
                            conn, session_id, crate::db::paused_work::PausedWorkStatus::Resumed,
                            chrono::Utc::now().timestamp(),
                        )?;
                        let response = Response::Ack;
                        let safe_response = serde_json::to_vec(&response)?;
                        Ok(crate::db::remote_attachment_operations::TransactionalRemoteMutation {
                            value: (response, changed), safe_response: safe_response.clone(),
                            outbox_kind: "resume_paused_work".into(), outbox_payload: safe_response,
                        })
                    },
                ).await.map_err(internal)?;
                return match outcome {
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied((response, changed)) => {
                        if changed && let Some(att) = state.attached.as_ref().filter(|att| att.handle.session_id == session_id) {
                            att.handle.broadcast_notice("paused work resumed; pending approvals will use the normal prompt flow".to_string());
                        }
                        Ok(response)
                    }
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(bytes) => serde_json::from_slice(&bytes).map_err(internal),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationActorConflict
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::ExistingIndeterminate => Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation conflict".into() }),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity => Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation capacity reached".into() }),
                };
            }
            let changed = ctx
                .db
                .mark_paused_session_work_resumed(session_id)
                .await
                .map_err(internal)?;
            if changed
                && let Some(att) = state.attached.as_ref()
                && att.handle.session_id == session_id
            {
                att.handle.broadcast_notice(
                    "paused work resumed; pending approvals will use the normal prompt flow"
                        .to_string(),
                );
            }
            Ok(Response::Ack)
        }

        Request::CancelPausedWork { session_id } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::CancelPausedWork { session_id };
                let canonical_params = request
                    .canonical_remote_operation_params_v1()
                    .map_err(internal)?;
                let canonical = authorized_request.encode_fcor(&request, &canonical_params)?;
                let request_hash = remote_request_hash(ctx, &canonical);
                let logical_attachment_id = operation.logical_attachment_id.to_string();
                let operation_id = operation.operation_id.to_string();
                let device_id = operation.authenticated_device_id.to_string();
                let outcome = ctx.db.execute_transactional_remote_operation(
                    crate::db::remote_attachment_operations::ReserveRemoteOperation {
                        logical_attachment_id: &logical_attachment_id, operation_id: &operation_id,
                        authenticated_device_id: &device_id, authenticated_device_generation: operation.authenticated_device_generation,
                        operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::TransactionalMutation,
                        request_hash, now_ms: chrono::Utc::now().timestamp_millis(),
                    },
                    move |conn| {
                        let changed = crate::db::Db::resolve_paused_session_work_conn(
                            conn, session_id, crate::db::paused_work::PausedWorkStatus::Cancelled,
                            chrono::Utc::now().timestamp(),
                        )?;
                        let response = Response::Ack;
                        let bytes = serde_json::to_vec(&response)?;
                        let effect = serde_json::to_vec(&crate::daemon::remote_outbox_worker::RemoteSessionEffectV1 { schema_version: 1, session_id })?;
                        Ok(crate::db::remote_attachment_operations::TransactionalRemoteMutation {
                            value: (response, changed), safe_response: bytes.clone(),
                            outbox_kind: "cancel_paused_work".into(), outbox_payload: effect,
                        })
                    },
                ).await.map_err(internal)?;
                return match outcome {
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied((response, changed)) => {
                        if changed {
                            if let Err(error) = ctx.registry.locks().suspend_session(session_id).await {
                                tracing::warn!(%error, %session_id, "releasing cancelled paused work locks failed");
                            }
                            if let Some(att) = state.attached.as_ref().filter(|att| att.handle.session_id == session_id) {
                                att.handle.broadcast_notice("paused work cancelled; the session is waiting for new input".to_string());
                            }
                        }
                        Ok(response)
                    }
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(bytes) => serde_json::from_slice(&bytes).map_err(internal),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationActorConflict
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::ExistingIndeterminate => Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation conflict".into() }),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity => Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation capacity reached".into() }),
                };
            }
            let changed = ctx
                .db
                .cancel_paused_session_work(session_id)
                .await
                .map_err(internal)?;
            if changed {
                if let Err(e) = ctx.registry.locks().suspend_session(session_id).await {
                    tracing::warn!(error = %e, %session_id, "releasing cancelled paused work locks failed");
                }
                if let Some(att) = state.attached.as_ref()
                    && att.handle.session_id == session_id
                {
                    att.handle.broadcast_notice(
                        "paused work cancelled; the session is waiting for new input".to_string(),
                    );
                }
            }
            Ok(Response::Ack)
        }

        Request::RepairResume { session_id } => {
            let att = require_attached(state)?;
            if att.handle.session_id != session_id {
                return Err(ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: "repair_resume session_id does not match the attached session".into(),
                });
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::RepairResume { session_id };
                if let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
                {
                    return Ok(response);
                }
            }
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::RepairResume { respond_to })
                .await
                .map_err(internal)?;
            match response_rx.await.map_err(internal)? {
                Ok(()) => finish_nonrepeatable_response!(
                    remote_operation,
                    ctx,
                    "repair_resume",
                    Response::Ack
                ),
                Err(message) => Err(ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message,
                }),
            }
        }

        Request::CreateGoal {
            session_id,
            objective,
            token_budget,
        } => {
            let session = ctx
                .db
                .get_session(session_id)
                .await
                .map_err(internal)?
                .ok_or_else(|| ErrorPayload {
                    code: ErrorCode::UnknownSession,
                    message: format!("unknown session {session_id}"),
                })?;
            let (_, extended) = ctx
                .config_source
                .load(std::path::Path::new(&session.project_root))
                .map_err(internal)?;
            let session_override = session
                .goal_settings_override_json
                .as_deref()
                .map(crate::agents::parse_goal_settings_override_json)
                .transpose()
                .map_err(|error| ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: error.to_string(),
                })?;
            let policy = crate::agents::effective_goal_supervision_for_agent(
                std::path::Path::new(&session.project_root),
                &session.active_agent,
                session_override.as_ref(),
                extended.goal_supervision,
            );
            if !policy.enabled {
                return Err(ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: "goal supervision is disabled by operator configuration".to_string(),
                });
            }
            policy.validate().map_err(|error| ErrorPayload {
                code: ErrorCode::BadRequest,
                message: error.to_string(),
            })?;
            let budget = token_budget.unwrap_or(policy.default_token_budget);
            if budget <= 0 {
                return Err(ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: "goal budget must be positive".to_string(),
                });
            }
            let policy_json = serde_json::to_string(&policy).map_err(internal)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::CreateGoal {
                    session_id,
                    objective: objective.clone(),
                    token_budget,
                };
                let params = request
                    .canonical_remote_operation_params_v1()
                    .map_err(internal)?;
                let canonical = authorized_request.encode_fcor(&request, &params)?;
                let request_hash = remote_request_hash(ctx, &canonical);
                let logical_attachment_id = operation.logical_attachment_id.to_string();
                let operation_id = operation.operation_id.to_string();
                let device_id = operation.authenticated_device_id.to_string();
                let project_id = session.project_id.clone();
                let goal_id = Uuid::new_v4();
                let now = chrono::Utc::now().timestamp();
                let outcome = ctx.db.execute_transactional_remote_operation(
                    crate::db::remote_attachment_operations::ReserveRemoteOperation {
                        logical_attachment_id: &logical_attachment_id, operation_id: &operation_id,
                        authenticated_device_id: &device_id, authenticated_device_generation: operation.authenticated_device_generation,
                        operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::TransactionalMutation,
                        request_hash, now_ms: chrono::Utc::now().timestamp_millis(),
                    },
                    move |conn| {
                        let goal = crate::db::Db::create_session_goal_with_policy_conn(conn, session_id, goal_id, now, &project_id, &objective, None, budget, &policy_json)
                            .map_err(|error| GoalMutationRejected(error.to_string()))?;
                        let receipt = proto::RemoteGoalOutcomeV1 { schema_version: 1, session_id, goal_id: goal.id, attempt_generation: goal.attempt_generation, disposition: goal.disposition };
                        let safe_response = serde_json::to_vec(&receipt)?;
                        Ok(crate::db::remote_attachment_operations::TransactionalRemoteMutation { value: receipt, safe_response: safe_response.clone(), outbox_kind: "create_goal".into(), outbox_payload: safe_response })
                    },
                ).await.map_err(|error| {
                    if let Some(rejected) = error.downcast_ref::<GoalMutationRejected>() { bad_request(rejected.to_string()) } else { internal(error) }
                })?;
                let receipt = match outcome {
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied(receipt) => receipt,
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(bytes) => serde_json::from_slice(&bytes).map_err(internal)?,
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationActorConflict
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::ExistingIndeterminate => return Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation conflict".into() }),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity => return Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation capacity reached".into() }),
                };
                if receipt.schema_version != 1
                    || receipt.session_id != session_id
                    || receipt.disposition != proto::GoalDisposition::Running
                {
                    return Err(internal(anyhow::anyhow!(
                        "invalid remote create-goal receipt"
                    )));
                }
                if let Some(attached) = state
                    .attached
                    .as_ref()
                    .filter(|attached| attached.handle.session().id == session_id)
                {
                    attached
                        .handle
                        .send_work(SessionWork::WakeGoal)
                        .await
                        .map_err(internal)?;
                }
                return Ok(Response::RemoteGoalOutcome { outcome: receipt });
            }
            ctx.db
                .create_session_goal_with_policy(
                    session_id,
                    &session.project_id,
                    &objective,
                    None,
                    Some(budget),
                    &policy_json,
                )
                .await
                .map_err(|error| ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: error.to_string(),
                })?;
            let goal = ctx
                .db
                .current_session_goal(session_id, false)
                .await
                .map_err(internal)?
                .ok_or_else(|| ErrorPayload {
                    code: ErrorCode::Internal,
                    message: "created goal disappeared".to_string(),
                })?;
            if let Some(attached) = state
                .attached
                .as_ref()
                .filter(|attached| attached.handle.session().id == session_id)
            {
                attached
                    .handle
                    .send_work(SessionWork::WakeGoal)
                    .await
                    .map_err(internal)?;
            }
            Ok(Response::GoalUpdated {
                goal: goal_to_proto(goal),
            })
        }

        Request::GoalStatus { session_id } => {
            ctx.db
                .refresh_session_goal_usage(session_id)
                .await
                .map_err(internal)?;
            let goal = ctx
                .db
                .current_session_goal(session_id, false)
                .await
                .map_err(internal)?
                .map(goal_to_proto);
            Ok(Response::GoalStatus { goal })
        }

        Request::SetGoalStatus { session_id, status } => {
            if status == proto::GoalDisposition::Running {
                let session = ctx
                    .db
                    .get_session(session_id)
                    .await
                    .map_err(internal)?
                    .ok_or_else(|| ErrorPayload {
                        code: ErrorCode::UnknownSession,
                        message: format!("unknown session {session_id}"),
                    })?;
                let (_, extended) = ctx
                    .config_source
                    .load(std::path::Path::new(&session.project_root))
                    .map_err(internal)?;
                if !extended.goal_supervision.enabled {
                    return Err(ErrorPayload {
                        code: ErrorCode::BadRequest,
                        message: "goal supervision is disabled by operator configuration"
                            .to_string(),
                    });
                }
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::SetGoalStatus { session_id, status };
                let params = request
                    .canonical_remote_operation_params_v1()
                    .map_err(internal)?;
                let canonical = authorized_request.encode_fcor(&request, &params)?;
                let request_hash = remote_request_hash(ctx, &canonical);
                let logical_attachment_id = operation.logical_attachment_id.to_string();
                let operation_id = operation.operation_id.to_string();
                let device_id = operation.authenticated_device_id.to_string();
                let outcome = ctx.db.execute_transactional_remote_operation(
                    crate::db::remote_attachment_operations::ReserveRemoteOperation {
                        logical_attachment_id: &logical_attachment_id, operation_id: &operation_id,
                        authenticated_device_id: &device_id, authenticated_device_generation: operation.authenticated_device_generation,
                        operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::TransactionalMutation,
                        request_hash, now_ms: chrono::Utc::now().timestamp_millis(),
                    },
                    move |conn| {
                        let goal = crate::db::Db::set_session_goal_status_conn(conn, session_id, status)
                            .map_err(|error| GoalMutationRejected(error.to_string()))?;
                        let receipt = proto::RemoteGoalOutcomeV1 { schema_version: 1, session_id, goal_id: goal.id, attempt_generation: goal.attempt_generation, disposition: goal.disposition };
                        let safe_response = serde_json::to_vec(&receipt)?;
                        Ok(crate::db::remote_attachment_operations::TransactionalRemoteMutation { value: receipt, safe_response: safe_response.clone(), outbox_kind: "set_goal_status".into(), outbox_payload: safe_response })
                    },
                ).await.map_err(|error| {
                    if let Some(rejected) = error.downcast_ref::<GoalMutationRejected>() { bad_request(rejected.to_string()) } else { internal(error) }
                })?;
                let receipt = match outcome {
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied(receipt) => receipt,
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(bytes) => serde_json::from_slice(&bytes).map_err(internal)?,
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationActorConflict
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::ExistingIndeterminate => return Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation conflict".into() }),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity => return Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation capacity reached".into() }),
                };
                if receipt.schema_version != 1
                    || receipt.session_id != session_id
                    || receipt.disposition != status
                {
                    return Err(internal(anyhow::anyhow!(
                        "invalid remote goal replay receipt"
                    )));
                }
                if status == proto::GoalDisposition::Running
                    && let Some(attached) = state
                        .attached
                        .as_ref()
                        .filter(|attached| attached.handle.session().id == session_id)
                {
                    attached
                        .handle
                        .send_work(SessionWork::WakeGoal)
                        .await
                        .map_err(internal)?;
                }
                return Ok(Response::RemoteGoalOutcome { outcome: receipt });
            }
            let goal = ctx
                .db
                .set_session_goal_status(session_id, status)
                .await
                .map_err(|error| ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: error.to_string(),
                })?;
            if status == proto::GoalDisposition::Running
                && let Some(attached) = state
                    .attached
                    .as_ref()
                    .filter(|attached| attached.handle.session().id == session_id)
            {
                attached
                    .handle
                    .send_work(SessionWork::WakeGoal)
                    .await
                    .map_err(internal)?;
            }
            Ok(Response::GoalUpdated {
                goal: goal_to_proto(goal),
            })
        }

        Request::ClearGoal { session_id } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::ClearGoal { session_id };
                let canonical_params = request
                    .canonical_remote_operation_params_v1()
                    .map_err(internal)?;
                let canonical = authorized_request.encode_fcor(&request, &canonical_params)?;
                let request_hash = remote_request_hash(ctx, &canonical);
                let logical_attachment_id = operation.logical_attachment_id.to_string();
                let operation_id = operation.operation_id.to_string();
                let device_id = operation.authenticated_device_id.to_string();
                let outcome = ctx
                    .db
                    .execute_transactional_remote_operation(
                        crate::db::remote_attachment_operations::ReserveRemoteOperation {
                            logical_attachment_id: &logical_attachment_id,
                            operation_id: &operation_id,
                            authenticated_device_id: &device_id,
                            authenticated_device_generation: operation
                                .authenticated_device_generation,
                            operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::TransactionalMutation,
                            request_hash,
                            now_ms: chrono::Utc::now().timestamp_millis(),
                        },
                        move |conn| {
                            let cleared = crate::db::Db::clear_session_goal_conn(conn, session_id)?;
                            let response = Response::GoalCleared { cleared };
                            let safe_response = serde_json::to_vec(&response)?;
                            let effect = serde_json::to_vec(&crate::daemon::remote_outbox_worker::RemoteSessionEffectV1 { schema_version: 1, session_id })?;
                            Ok(crate::db::remote_attachment_operations::TransactionalRemoteMutation {
                                value: response,
                                safe_response: safe_response.clone(),
                                outbox_kind: "clear_goal".into(),
                                outbox_payload: effect,
                            })
                        },
                    )
                    .await
                    .map_err(internal)?;
                return match outcome {
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied(response) => {
                        // WakeGoal is a level-triggered reconciliation nudge: the driver
                        // reloads the authoritative goal row and is safe to wake more than
                        // once. Deliver it for Applied and Replay so a response retry closes
                        // a crash/send-failure window after the durable commit.
                        if matches!(response, Response::GoalCleared { cleared: true })
                            && let Some(attached) = state.attached.as_ref().filter(|attached| attached.handle.session().id == session_id)
                        {
                            attached.handle.send_work(SessionWork::WakeGoal).await.map_err(internal)?;
                        }
                        Ok(response)
                    }
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(bytes) => {
                        let response: Response = serde_json::from_slice(&bytes).map_err(internal)?;
                        if matches!(response, Response::GoalCleared { cleared: true })
                            && let Some(attached) = state.attached.as_ref().filter(|attached| attached.handle.session().id == session_id)
                        {
                            attached.handle.send_work(SessionWork::WakeGoal).await.map_err(internal)?;
                        }
                        Ok(response)
                    }
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationActorConflict
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::ExistingIndeterminate => Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation conflict".into() }),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity => Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation capacity reached".into() }),
                };
            }
            let cleared = ctx
                .db
                .clear_session_goal(session_id)
                .await
                .map_err(internal)?;
            if cleared
                && let Some(attached) = state
                    .attached
                    .as_ref()
                    .filter(|attached| attached.handle.session().id == session_id)
            {
                attached
                    .handle
                    .send_work(SessionWork::WakeGoal)
                    .await
                    .map_err(internal)?;
            }
            Ok(Response::GoalCleared { cleared })
        }

        Request::PinMessage { session_id, seq } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::PinMessage { session_id, seq };
                let canonical_params = request
                    .canonical_remote_operation_params_v1()
                    .map_err(internal)?;
                let canonical = authorized_request.encode_fcor(&request, &canonical_params)?;
                let request_hash = remote_request_hash(ctx, &canonical);
                let logical_attachment_id = operation.logical_attachment_id.to_string();
                let operation_id = operation.operation_id.to_string();
                let device_id = operation.authenticated_device_id.to_string();
                let outcome = ctx.db.execute_transactional_remote_operation(
                    crate::db::remote_attachment_operations::ReserveRemoteOperation {
                        logical_attachment_id: &logical_attachment_id,
                        operation_id: &operation_id,
                        authenticated_device_id: &device_id,
                        authenticated_device_generation: operation.authenticated_device_generation,
                        operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::TransactionalMutation,
                        request_hash,
                        now_ms: chrono::Utc::now().timestamp_millis(),
                    },
                    move |conn| {
                        let changed = crate::db::Db::pin_message_conn(conn, session_id, seq, chrono::Utc::now().timestamp_millis())
                            .map_err(|error| PinMutationRejected(error.to_string()))?;
                        let response = Response::PinChanged { changed };
                        let safe_response = serde_json::to_vec(&response)?;
                        Ok(crate::db::remote_attachment_operations::TransactionalRemoteMutation { value: response, safe_response: safe_response.clone(), outbox_kind: "pin_message".into(), outbox_payload: safe_response })
                    },
                ).await.map_err(|error| {
                    if let Some(rejected) = error.downcast_ref::<PinMutationRejected>() {
                        bad_request(rejected.to_string())
                    } else {
                        internal(error)
                    }
                })?;
                return match outcome {
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied(response) => Ok(response),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(bytes) => serde_json::from_slice(&bytes).map_err(internal),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationActorConflict
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::ExistingIndeterminate => Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation conflict".into() }),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity => Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation capacity reached".into() }),
                };
            }
            ctx.db
                .pin_message(session_id, seq)
                .await
                .map(|changed| Response::PinChanged { changed })
                .map_err(|error| bad_request(error.to_string()))
        }
        Request::UnpinMessage { session_id, seq } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::UnpinMessage { session_id, seq };
                let canonical_params = request
                    .canonical_remote_operation_params_v1()
                    .map_err(internal)?;
                let canonical = authorized_request.encode_fcor(&request, &canonical_params)?;
                let request_hash = remote_request_hash(ctx, &canonical);
                let logical_attachment_id = operation.logical_attachment_id.to_string();
                let operation_id = operation.operation_id.to_string();
                let device_id = operation.authenticated_device_id.to_string();
                let outcome = ctx.db.execute_transactional_remote_operation(
                    crate::db::remote_attachment_operations::ReserveRemoteOperation {
                        logical_attachment_id: &logical_attachment_id,
                        operation_id: &operation_id,
                        authenticated_device_id: &device_id,
                        authenticated_device_generation: operation.authenticated_device_generation,
                        operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::TransactionalMutation,
                        request_hash,
                        now_ms: chrono::Utc::now().timestamp_millis(),
                    },
                    move |conn| {
                        let changed = crate::db::Db::unpin_message_conn(conn, session_id, seq)?;
                        let response = Response::PinChanged { changed };
                        let safe_response = serde_json::to_vec(&response)?;
                        Ok(crate::db::remote_attachment_operations::TransactionalRemoteMutation {
                            value: response, safe_response: safe_response.clone(),
                            outbox_kind: "unpin_message".into(), outbox_payload: safe_response,
                        })
                    },
                ).await.map_err(internal)?;
                return match outcome {
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied(response) => Ok(response),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(bytes) => serde_json::from_slice(&bytes).map_err(internal),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationActorConflict
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::ExistingIndeterminate => Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation conflict".into() }),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity => Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation capacity reached".into() }),
                };
            }
            ctx.db
                .unpin_message(session_id, seq)
                .await
                .map(|changed| Response::PinChanged { changed })
                .map_err(|error| bad_request(error.to_string()))
        }
        Request::TogglePinnedMessage { session_id, seq } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::TogglePinnedMessage { session_id, seq };
                let canonical_params = request
                    .canonical_remote_operation_params_v1()
                    .map_err(internal)?;
                let canonical = authorized_request.encode_fcor(&request, &canonical_params)?;
                let request_hash = remote_request_hash(ctx, &canonical);
                let logical_attachment_id = operation.logical_attachment_id.to_string();
                let operation_id = operation.operation_id.to_string();
                let device_id = operation.authenticated_device_id.to_string();
                let outcome = ctx.db.execute_transactional_remote_operation(
                    crate::db::remote_attachment_operations::ReserveRemoteOperation {
                        logical_attachment_id: &logical_attachment_id,
                        operation_id: &operation_id,
                        authenticated_device_id: &device_id,
                        authenticated_device_generation: operation.authenticated_device_generation,
                        operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::TransactionalMutation,
                        request_hash,
                        now_ms: chrono::Utc::now().timestamp_millis(),
                    },
                    move |conn| {
                        let pinned = crate::db::Db::toggle_pin_conn(conn, session_id, seq, chrono::Utc::now().timestamp_millis())
                            .map_err(|error| PinMutationRejected(error.to_string()))?;
                        let response = Response::PinToggled { pinned };
                        let safe_response = serde_json::to_vec(&response)?;
                        Ok(crate::db::remote_attachment_operations::TransactionalRemoteMutation { value: response, safe_response: safe_response.clone(), outbox_kind: "toggle_pinned_message".into(), outbox_payload: safe_response })
                    },
                ).await.map_err(|error| {
                    if let Some(rejected) = error.downcast_ref::<PinMutationRejected>() { bad_request(rejected.to_string()) } else { internal(error) }
                })?;
                return match outcome {
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied(response) => Ok(response),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(bytes) => serde_json::from_slice(&bytes).map_err(internal),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationActorConflict
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::ExistingIndeterminate => Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation conflict".into() }),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity => Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation capacity reached".into() }),
                };
            }
            ctx.db
                .toggle_pin(session_id, seq)
                .await
                .map(|pinned| Response::PinToggled { pinned })
                .map_err(|error| bad_request(error.to_string()))
        }
        Request::CountPinnedMessages { session_id } => ctx
            .db
            .count_pins(session_id)
            .await
            .map(|count| Response::PinCount { count })
            .map_err(internal),
        Request::ListPinnedMessageSeqs { session_id } => ctx
            .db
            .list_pin_seqs(session_id)
            .await
            .map(|seqs| Response::PinSeqs { seqs })
            .map_err(internal),
        Request::ListPinnedMessagesWithText { session_id } => ctx
            .db
            .list_pins_with_text(session_id)
            .await
            .map(|pins| Response::PinsWithText {
                pins: pins.into_iter().map(pinned_message_to_proto).collect(),
            })
            .map_err(internal),
        Request::PinnedMessageState { session_id } => {
            let count = ctx.db.count_pins(session_id).await.map_err(internal)?;
            let seqs = ctx.db.list_pin_seqs(session_id).await.map_err(internal)?;
            Ok(Response::PinState {
                state: proto::PinState { count, seqs },
            })
        }
        // ---- v10-only owner-remoted sealed-owner sensitive channel ------
        // Non-owner callers are rejected by the central owner-only authorizer
        // before reaching these arms. The live directory / capability-table
        // backing (RwLock registry, persistence) is installed by the
        // `sealed-owner-persistence-and-executor` sibling; until then every arm
        // that would touch durable state or a literal fails CLOSED here — no
        // literal, no capability minted, no unjournaled persist.
        Request::BeginSealedOwnerOperation {
            disposition,
            record_id,
            name,
            description,
            scope_kind,
            scope_key,
        } => {
            let owner = crate::sealed::action::OwnerAuthority::for_owner_request();
            // Validate the closed disposition + per-disposition field presence
            // (a distinct, content-free rejection) before touching the backing.
            // Never echoes a literal — begin is secret-free.
            validate_sealed_begin_shape(
                &disposition,
                record_id.as_deref(),
                name.as_deref(),
                description.as_deref(),
                scope_kind.as_deref(),
                scope_key.as_deref(),
            )
            .map_err(|error| bad_request(error.to_string()))?;
            let input = build_begin_sensitive_input(
                &disposition,
                record_id,
                name,
                description,
                scope_kind,
                scope_key,
            )
            .map_err(|error| bad_request(error.to_string()))?;
            let directory = sealed_value_directory(ctx);
            let now_ms = chrono::Utc::now().timestamp_millis();
            // `begin` loads/binds the record under owner authority for non-create
            // dispositions; a missing/foreign row or a name collision is a
            // content-free client error (no capability is minted).
            let result = crate::sealed::owner::BeginSensitiveOwnerOperation::begin(
                owner, &directory, input, now_ms,
            )
            .await
            .map_err(|error| bad_request(error.to_string()))?;
            let capability_id = result.capability.capability_id().to_string();
            let expires_at_ms = result.expires_at_ms;
            // Bind the capability to the connection that minted it. Apply/Cancel
            // from any other connection is rejected fail-closed (AC8). If the
            // in-memory table is already full of still-valid capabilities, fail
            // closed rather than grow it without bound: the just-minted
            // capability is dropped (never stored), so it can never be applied.
            let minting_session = state.terminal_context.client_instance_id;
            let stored = ctx.sealed_owner_capabilities.lock().unwrap().insert(
                result.capability,
                minting_session,
                now_ms,
            );
            if !stored {
                return Err(bad_request(
                    "too many outstanding sealed-owner operations; complete or cancel some first"
                        .to_string(),
                ));
            }
            Ok(Response::SealedOwnerOperationBegun {
                capability_id,
                expires_at_ms,
            })
        }
        Request::ApplySealedOwnerOperation {
            capability_id,
            literal,
        } => {
            let owner = crate::sealed::action::OwnerAuthority::for_owner_request();
            let capability_uuid = match uuid::Uuid::parse_str(capability_id.trim()) {
                Ok(id) => id,
                Err(_) => {
                    // Drop the literal (zeroized on drop) before returning.
                    drop(literal);
                    return Err(bad_request(
                        "capability id must be a valid uuid".to_string(),
                    ));
                }
            };
            // Look up (clone) the stored capability. The single-use flag is an
            // `Arc<AtomicBool>`, so consuming the clone consumes the stored
            // capability. An unknown/expired/consumed id fails closed.
            let stored = ctx
                .sealed_owner_capabilities
                .lock()
                .unwrap()
                .get(capability_uuid);
            let Some(stored) = stored else {
                drop(literal);
                return Err(bad_request(
                    "unknown, expired, or already-used sealed-owner capability".to_string(),
                ));
            };
            // AC8: the applying connection must be the minting connection. A
            // cross-session apply is rejected WITHOUT spending the capability, so
            // the legitimate minting session can still apply it.
            if stored.minting_session != state.terminal_context.client_instance_id {
                drop(literal);
                return Err(bad_request(
                    "sealed-owner capability was minted in a different session".to_string(),
                ));
            }
            let directory = sealed_value_directory(ctx);
            let now_ms = chrono::Utc::now().timestamp_millis();
            let frame_kind = stored.capability.operation().disposition.frame_kind();
            let outcome = match frame_kind {
                crate::sealed::owner::SensitiveFrameKind::Write => {
                    let Some(literal) = literal else {
                        return Err(bad_request(
                            "a write/replace/rotate apply requires a literal".to_string(),
                        ));
                    };
                    crate::sealed::owner::SensitiveOwnerFrame::for_write(
                        &stored.capability,
                        literal.into_zeroizing(),
                    )
                    .apply(owner, &directory, now_ms)
                    .await
                }
                crate::sealed::owner::SensitiveFrameKind::Recover => {
                    if literal.is_some() {
                        return Err(bad_request(
                            "a recover apply must not carry a literal".to_string(),
                        ));
                    }
                    crate::sealed::owner::SensitiveOwnerFrame::for_recover(
                        &stored.capability,
                        stored.minting_session.to_string(),
                    )
                    .apply(owner, &directory, now_ms)
                    .await
                }
            };
            // The capability is spent whether the operation succeeded or failed
            // (the compare-and-swap fired inside `apply`), so drop the table
            // entry. A recover whose audit commit failed returns `Err` here — no
            // literal is ever placed on the response (fail closed, AC2).
            ctx.sealed_owner_capabilities
                .lock()
                .unwrap()
                .remove(capability_uuid);
            let outcome = outcome.map_err(|error| bad_request(error.to_string()))?;
            match outcome {
                crate::sealed::owner::SensitiveFrameOutcome::Contained { .. } => {
                    Ok(Response::SealedOwnerOperationApplied {
                        revealed_literal: None,
                    })
                }
                crate::sealed::owner::SensitiveFrameOutcome::Revealed { literal } => {
                    // Move the resolved plaintext straight into the zeroizing wire
                    // type; no intermediate non-zeroizing `String` copy.
                    Ok(Response::SealedOwnerOperationApplied {
                        revealed_literal: Some(proto::SensitiveWireLiteral::from_zeroizing(
                            literal,
                        )),
                    })
                }
            }
        }
        Request::CancelSealedOwnerOperation { capability_id } => {
            let _owner = crate::sealed::action::OwnerAuthority::for_owner_request();
            let capability_uuid = uuid::Uuid::parse_str(capability_id.trim())
                .map_err(|_| bad_request("capability id must be a valid uuid".to_string()))?;
            let stored = ctx
                .sealed_owner_capabilities
                .lock()
                .unwrap()
                .get(capability_uuid);
            let Some(stored) = stored else {
                // Unknown/expired/already-spent: cancel is idempotent and safe.
                return Ok(Response::SealedOwnerOperationCancelled { spent: false });
            };
            // Only the minting connection may cancel its capability (fail closed).
            if stored.minting_session != state.terminal_context.client_instance_id {
                return Err(bad_request(
                    "sealed-owner capability was minted in a different session".to_string(),
                ));
            }
            // Spend through the same compare-and-swap as apply; `true` only if
            // this call consumed it (not a replay/double-cancel).
            let spent = stored.capability.cancel();
            ctx.sealed_owner_capabilities
                .lock()
                .unwrap()
                .remove(capability_uuid);
            Ok(Response::SealedOwnerOperationCancelled { spent })
        }
        Request::SealedOwnerInventory {
            scope_kind,
            scope_key,
        } => {
            let owner = crate::sealed::action::OwnerAuthority::for_owner_request();
            // An optional scope filter narrows the inventory; absent, it is
            // machine-wide. A malformed filter is a content-free client error.
            let scope = match scope_kind {
                Some(kind) => Some(
                    build_sealed_scope_ref(Some(kind), scope_key)
                        .map_err(|error| bad_request(error.to_string()))?,
                ),
                None => None,
            };
            let directory = sealed_value_directory(ctx);
            let rows = directory
                .inventory_records(owner, scope.as_ref())
                .await
                .map_err(internal)?;
            let items = rows
                .into_iter()
                .map(sealed_record_row_to_inventory_item)
                .collect();
            // The funnel clamps the row count to the bounded wire ceiling.
            Ok(Response::sealed_owner_inventory(items))
        }
        Request::EditSealedOwnerDescription {
            record_id,
            description,
        } => {
            let _owner = crate::sealed::action::OwnerAuthority::for_owner_request();
            if record_id.trim().is_empty() {
                return Err(bad_request("record id must not be empty".to_string()));
            }
            let description = crate::sealed::identity::SealedDescription::parse(&description)
                .map_err(|error| bad_request(error.to_string()))?;
            let now_ms = chrono::Utc::now().timestamp_millis();
            // Metadata-only update; the literal, name, scope, and version are
            // untouched. An unknown/deleted record is a content-free client error.
            let edited = ctx
                .db
                .set_sealed_value_description(
                    record_id.clone(),
                    description.as_str().to_string(),
                    now_ms,
                )
                .await
                .map_err(internal)?;
            if !edited {
                return Err(bad_request(
                    "sealed value record does not exist".to_string(),
                ));
            }
            Ok(Response::SealedOwnerDescriptionEdited { record_id })
        }
        Request::ListSealedActions => {
            let owner = crate::sealed::action::OwnerAuthority::for_owner_request();
            let actions = sealed_action_directory(ctx)
                .list(owner)
                .await
                .map_err(internal)?
                .into_iter()
                .map(sealed_action_summary_to_wire)
                .collect();
            Ok(Response::sealed_actions(actions))
        }
        Request::CreateSealedAction {
            kind_id,
            project_id,
            description,
            origin_id,
            projection_id,
        } => {
            let owner = crate::sealed::action::OwnerAuthority::for_owner_request();
            // Resolve the three closed-lookup ids to a compiled action kind and
            // parse the safe fields FIRST. An unknown id / unsafe field is
            // rejected here, before any persist.
            let kind = resolve_sealed_action_kind(&kind_id, &origin_id, &projection_id)
                .map_err(|error| bad_request(error.to_string()))?;
            let description = crate::sealed::identity::SealedDescription::parse(&description)
                .map_err(|error| bad_request(error.to_string()))?;
            if project_id.trim().is_empty() {
                return Err(bad_request("project id must not be empty".to_string()));
            }
            let project_key = crate::sealed::identity::SealedProjectKey::from_canonical(project_id);
            let now_ms = chrono::Utc::now().timestamp_millis();
            let summary = sealed_action_directory(ctx)
                .create(
                    owner,
                    crate::sealed::action_admin::CreateSealedAction {
                        kind,
                        description,
                        project_key,
                    },
                    now_ms,
                )
                .await
                .map_err(internal)?;
            Ok(Response::SealedActionCreated {
                action_id: summary.action_id,
                revision: summary.revision,
            })
        }
        Request::ReviseSealedActionDescription {
            action_id,
            description,
        } => {
            let owner = crate::sealed::action::OwnerAuthority::for_owner_request();
            if action_id.trim().is_empty() {
                return Err(bad_request("action id must not be empty".to_string()));
            }
            let description = crate::sealed::identity::SealedDescription::parse(&description)
                .map_err(|error| bad_request(error.to_string()))?;
            let now_ms = chrono::Utc::now().timestamp_millis();
            let summary = sealed_action_directory(ctx)
                .revise(
                    owner,
                    crate::sealed::action_admin::ReviseSealedAction::Description {
                        action_id,
                        description,
                    },
                    now_ms,
                )
                .await
                .map_err(|error| bad_request(error.to_string()))?;
            Ok(Response::SealedActionRevised {
                action_id: summary.action_id,
                revision: summary.revision,
            })
        }
        Request::ReviseSealedActionEnabled { action_id, enabled } => {
            let owner = crate::sealed::action::OwnerAuthority::for_owner_request();
            if action_id.trim().is_empty() {
                return Err(bad_request("action id must not be empty".to_string()));
            }
            let now_ms = chrono::Utc::now().timestamp_millis();
            let summary = sealed_action_directory(ctx)
                .revise(
                    owner,
                    crate::sealed::action_admin::ReviseSealedAction::Enabled { action_id, enabled },
                    now_ms,
                )
                .await
                .map_err(|error| bad_request(error.to_string()))?;
            Ok(Response::SealedActionRevised {
                action_id: summary.action_id,
                revision: summary.revision,
            })
        }
        Request::RetireSealedAction { action_id, confirm } => {
            let owner = crate::sealed::action::OwnerAuthority::for_owner_request();
            if action_id != confirm {
                return Err(bad_request(
                    "retire confirmation must exactly match the action id".to_string(),
                ));
            }
            let now_ms = chrono::Utc::now().timestamp_millis();
            let retired = sealed_action_directory(ctx)
                .retire(owner, &action_id, now_ms)
                .await
                .map_err(internal)?;
            Ok(Response::SealedActionRetired { action_id, retired })
        }

        Request::ListProjectNotes { project_root } => ctx
            .db
            .list_project_notes(&project_root)
            .await
            .map(|notes| Response::ProjectNotes {
                notes: notes.into_iter().map(project_note_to_proto).collect(),
            })
            .map_err(internal),
        Request::CreateProjectNote { project_root, name } => ctx
            .db
            .create_project_note(&project_root, &name)
            .await
            .map(|note| Response::ProjectNoteCreated {
                note: project_note_to_proto(note),
            })
            .map_err(|error| bad_request(error.to_string())),
        Request::SetProjectNoteContent {
            project_root,
            id,
            content,
        } => {
            ensure_project_note_member(&ctx.db, &project_root, id).await?;
            ctx.db
                .set_project_note_content(id, &content)
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }
        Request::RenameProjectNote {
            project_root,
            id,
            name,
        } => {
            ensure_project_note_member(&ctx.db, &project_root, id).await?;
            ctx.db
                .rename_project_note(id, &name)
                .await
                .map(|name| Response::ProjectNoteRenamed { name })
                .map_err(|error| bad_request(error.to_string()))
        }
        Request::DeleteProjectNote { project_root, id } => {
            ensure_project_note_member(&ctx.db, &project_root, id).await?;
            ctx.db.delete_project_note(id).await.map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetWorkspaceTrust {
            project_root,
            mode,
            expected_config_generation,
        } => {
            let _guard = WORKSPACE_TRUST_RPC_LOCK.lock().await;
            let current = inventory::current_config_generation();
            if current != expected_config_generation {
                return Err(ErrorPayload {
                    code: ErrorCode::Conflict,
                    message: format!(
                        "workspace trust config generation is {current}, expected {expected_config_generation}"
                    ),
                });
            }
            ctx.db
                .set_workspace_trust(
                    PathBuf::from(&project_root).as_path(),
                    workspace_trust_mode_to_db(mode),
                )
                .await
                .map_err(internal)?;
            let config_generation = inventory::compare_and_bump_config_generation(current)
                .ok_or_else(|| ErrorPayload {
                    code: ErrorCode::Conflict,
                    message: "workspace trust config generation changed concurrently".into(),
                })?;
            Ok(Response::WorkspaceTrustSet { config_generation })
        }
        Request::GetWorkspaceTrust { project_root } => {
            let _guard = WORKSPACE_TRUST_RPC_LOCK.lock().await;
            let decision = ctx
                .db
                .workspace_trust_by_root(PathBuf::from(&project_root).as_path())
                .await
                .map_err(internal)?;
            Ok(Response::WorkspaceTrust {
                mode: decision.map(|decision| workspace_trust_mode_from_db(decision.mode)),
                config_generation: inventory::current_config_generation(),
            })
        }
        Request::GetStartupDisclosures { project_root: _ } => {
            #[cfg(not(feature = "remote"))]
            return Ok(Response::StartupDisclosures {
                org_sync: None,
                connector: None,
                config_generation: inventory::current_config_generation(),
            });
            #[cfg(feature = "remote")]
            let (org_sync, connector) =
                if let Some(credential) = ctx.load_flycockpit_credential().map_err(internal)? {
                    let org = ctx
                        .db
                        .org_sync_disclosure_for_server(&credential.server_url)
                        .await
                        .map_err(internal)?
                        .map(org_disclosure_to_proto);
                    let connector = ctx
                        .db
                        .connector_disclosure(&credential.server_url, &credential.instance_id)
                        .await
                        .map_err(internal)?
                        .map(connector_disclosure_to_proto);
                    (org, connector)
                } else {
                    (None, None)
                };
            #[cfg(feature = "remote")]
            return Ok(Response::StartupDisclosures {
                org_sync,
                connector,
                config_generation: inventory::current_config_generation(),
            });
        }
        Request::GetAppFlag { key } => {
            let db_key = app_flag_db_key(key);
            let version = ctx
                .db
                .read(move |conn| crate::db::Db::app_flag_version_conn(conn, db_key))
                .await
                .map_err(internal)?;
            Ok(Response::AppFlag {
                key,
                seen: version > 0,
                version,
            })
        }
        Request::MarkAppFlagSeen {
            key,
            expected_version,
        } => {
            // `mark_app_flag_seen` is classified `local_only`: app flags are
            // daemon-local UI acknowledgements, NOT a remoted owner mutation, so
            // the request never reserves a transactional remote-operation ledger
            // row. `admit_remote_operation` already denies a remote non-owner
            // (the `local_only` class resolves to no remote class) and returns
            // `None` for the owner, so any `remote_operation` identity is inert
            // here by construction — persist locally only. See
            // `mark_app_flag_seen_is_local_only_and_does_not_call_remote_ledger`.
            let db_key = app_flag_db_key(key);
            let outcome = ctx
                .db
                .write(move |conn| {
                    crate::db::Db::mark_app_flag_seen_versioned_conn(conn, db_key, expected_version)
                })
                .await
                .map_err(internal)?;
            let Some((version, changed)) = outcome else {
                return Err(ErrorPayload {
                    code: ErrorCode::Conflict,
                    message: "app flag version changed; refresh before retrying".into(),
                });
            };
            Ok(Response::AppFlagSeen {
                key,
                version,
                changed,
            })
        }
        Request::ResolveAssistantSession {
            assistant_id,
            project_root,
            mode: proto::AssistantSessionResolutionMode::MostRecentOrCreate,
        } => {
            let assistant_for_db = assistant_id.clone();
            let project_root_for_db = project_root.clone();
            let (session, created) = ctx
                .db
                .write(move |conn| {
                    let assistant = crate::db::Db::get_assistant_conn(conn, &assistant_for_db)?
                        .ok_or_else(|| {
                            anyhow::anyhow!("assistant `{assistant_for_db}` not found")
                        })?;
                    crate::assistants::load_from_row(&assistant)?;
                    let (row, created) =
                        match crate::db::Db::most_recent_session_for_assistant_conn(
                            conn,
                            &assistant_for_db,
                        )? {
                            Some(row) => (row, false),
                            None => {
                                let project_id =
                                    crate::session::project_id_for(Path::new(&project_root_for_db));
                                let row = crate::db::Db::build_new_assistant_session_row_conn(
                                    conn,
                                    &project_id,
                                    &project_root_for_db,
                                    &assistant_for_db,
                                    &assistant_for_db,
                                )?;
                                (crate::db::Db::insert_session_row_conn(conn, &row)?, true)
                            }
                        };
                    let summary = crate::db::Db::list_session_summaries_conn(
                        conn,
                        Some(&row.project_id),
                        None,
                        100,
                    )?
                    .into_iter()
                    .find(|summary| summary.session_id == row.session_id)
                    .ok_or_else(|| anyhow::anyhow!("resolved assistant session is unavailable"))?;
                    Ok((summary, created))
                })
                .await
                .map_err(|error| bad_request(error.to_string()))?;
            Ok(Response::AssistantSessionResolved { session, created })
        }

        Request::ListAssistants => {
            let assistants = ctx
                .db
                .list_assistants()
                .await
                .map_err(internal)?
                .into_iter()
                .map(assistant_to_proto_with_definition)
                .collect();
            Ok(Response::Assistants { assistants })
        }
        Request::UpsertAssistant {
            name,
            description,
            prompt,
        } => {
            #[cfg(feature = "remote")]
            let request = Request::UpsertAssistant {
                name: name.clone(),
                description: description.clone(),
                prompt: prompt.clone(),
            };
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept persistent assistant writes",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let home_dir = crate::assistants::default_home_dir(&name)
                .map_err(|error| bad_request(error.to_string()))?;
            let row = crate::assistants::create_assistant(
                &ctx.db,
                crate::assistants::CreateAssistantSpec {
                    name,
                    description,
                    prompt,
                    home_dir,
                },
            )
                .await
                .map_err(|error| bad_request(error.to_string()))?;
            let response = Response::AssistantUpserted {
                assistant: assistant_to_proto(row),
            };
            finish_nonrepeatable_response!(remote_operation, ctx, "upsert_assistant", response)
        }
        Request::SaveAssistantDefinition {
            name,
            markdown,
            expected_revision,
        } => {
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept persistent assistant writes",
                ));
            }
            crate::assistants::validate_assistant_name(&name)
                .map_err(|error| bad_request(error.to_string()))?;
            if markdown.len() > proto::MAX_AGENT_MARKDOWN_BYTES {
                return Err(bad_request("assistant markdown exceeds maximum length"));
            }
            let row = ctx
                .db
                .get_assistant(&name)
                .await
                .map_err(internal)?
                .ok_or_else(|| bad_request(format!("assistant `{name}` was not found")))?;
            let updated =
                crate::assistants::save_definition_cas(&ctx.db, row, markdown, &expected_revision)
                    .await
                    .map_err(|error| ErrorPayload {
                        code: ErrorCode::Conflict,
                        message: format!("assistant definition save rejected: {error:#}"),
                    })?;
            Ok(Response::AssistantDefinitionSaved {
                assistant: assistant_to_proto_with_definition(updated),
            })
        }

        Request::AddPackage {
            project_root,
            identifier,
            git,
            branch,
            local_path,
            deep,
        } => {
            #[cfg(feature = "remote")]
            let request = Request::AddPackage {
                project_root: project_root.clone(),
                identifier: identifier.clone(),
                git: git.clone(),
                branch: branch.clone(),
                local_path: local_path.clone(),
                deep,
            };
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept package registry writes",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let cwd = PathBuf::from(&project_root);
            let shallow = !deep;
            let row = if let Some(url) = git.as_deref() {
                crate::packages::add_git(
                    &ctx.db,
                    &cwd,
                    &identifier,
                    url,
                    branch.as_deref(),
                    shallow,
                )
                .await
                .map_err(|error| bad_request(error.to_string()))?
            } else if let Some(path) = local_path.as_deref() {
                crate::packages::add_local(&ctx.db, &identifier, std::path::Path::new(path))
                    .await
                    .map_err(|error| bad_request(error.to_string()))?
            } else {
                return Err(bad_request(
                    "add_package needs either a git url or a local path",
                ));
            };
            let response = Response::PackageAdded {
                package_json: serde_json::to_string(&package_row_json(&row)).map_err(internal)?,
            };
            finish_nonrepeatable_response!(remote_operation, ctx, "add_package", response)
        }

        Request::ImportPackage {
            project_root,
            dir,
            package,
            id,
            as_path,
        } => {
            #[cfg(feature = "remote")]
            let request = Request::ImportPackage {
                project_root: project_root.clone(),
                dir: dir.clone(),
                package: package.clone(),
                id: id.clone(),
                as_path,
            };
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept package registry writes",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let cwd = PathBuf::from(&project_root);
            let summary = if let Some(dir) = dir.as_deref() {
                crate::packages::import_package_directory(
                    &ctx.db,
                    &cwd,
                    std::path::Path::new(dir),
                    as_path,
                )
                .await
                .map_err(|error| bad_request(error.to_string()))?
            } else if let Some(package_dir) = package.as_deref() {
                crate::packages::import_package(
                    &ctx.db,
                    &cwd,
                    std::path::Path::new(package_dir),
                    id.as_deref(),
                    as_path,
                )
                .await
                .map_err(|error| bad_request(error.to_string()))?
            } else {
                return Err(bad_request(
                    "import_package needs either a directory or a single package path",
                ));
            };
            let response = Response::PackageImported {
                summary_json: serde_json::to_string(&package_import_summary_json(&summary))
                    .map_err(internal)?,
            };
            finish_nonrepeatable_response!(remote_operation, ctx, "import_package", response)
        }

        Request::PrunePackages {
            project_root,
            days,
            dry_run,
        } => {
            #[cfg(feature = "remote")]
            let request = Request::PrunePackages {
                project_root: project_root.clone(),
                days,
                dry_run,
            };
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept package registry writes",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let cwd = PathBuf::from(&project_root);
            let report = crate::packages::prune_package_clones(
                &ctx.db,
                &cwd,
                &crate::packages::PackagePruneOptions { days, dry_run },
            )
            .await
            .map_err(|error| bad_request(error.to_string()))?;
            let response = Response::PackagesPruned {
                report_json: serde_json::to_string(&package_prune_report_json(&report))
                    .map_err(internal)?,
            };
            finish_nonrepeatable_response!(remote_operation, ctx, "prune_packages", response)
        }

        Request::ImportKclPackages { project_root } => {
            #[cfg(feature = "remote")]
            let request = Request::ImportKclPackages {
                project_root: project_root.clone(),
            };
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept package registry writes",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let cwd = PathBuf::from(&project_root);
            let result = crate::packages::import_from_kcl(&ctx.db, &cwd)
                .await
                .map_err(|error| bad_request(error.to_string()))?;
            let value = match result {
                crate::packages::KclImport::Imported(count) => serde_json::json!({
                    "imported": count,
                }),
                crate::packages::KclImport::NoKclDb(path) => serde_json::json!({
                    "no_kcl_db": path.display().to_string(),
                }),
            };
            let response = Response::KclPackagesImported {
                result_json: serde_json::to_string(&value).map_err(internal)?,
            };
            finish_nonrepeatable_response!(remote_operation, ctx, "import_kcl_packages", response)
        }

        Request::PurgeEndedSessions { before } => {
            #[cfg(feature = "remote")]
            let request = Request::PurgeEndedSessions { before };
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept persistent session purges",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let session_ids = ctx
                .db
                .read(move |conn| {
                    let mut statement = conn.prepare(
                        "SELECT session_id FROM sessions WHERE ended_at IS NOT NULL AND ended_at < ?1",
                    )?;
                    statement
                        .query_map([before], |row| row.get::<_, String>(0))?
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(Into::into)
                })
                .await
                .map_err(internal)?;
            let mut purged = 0u32;
            for id in &session_ids {
                if let Ok(session_id) = Uuid::parse_str(id) {
                    ctx.db.delete_session(session_id).await.map_err(internal)?;
                    purged = purged.saturating_add(1);
                }
            }
            let response = Response::EndedSessionsPurged {
                purged,
                session_ids_json: serde_json::to_string(&session_ids).map_err(internal)?,
            };
            finish_nonrepeatable_response!(remote_operation, ctx, "purge_ended_sessions", response)
        }

        Request::DeleteAssistant { name } => {
            #[cfg(feature = "remote")]
            let request = Request::DeleteAssistant { name: name.clone() };
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept persistent assistant writes",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let deleted = crate::assistants::delete_registration(&ctx.db, &name)
                .await
                .map_err(internal)?;
            let response = Response::AssistantDeleted { deleted };
            finish_nonrepeatable_response!(remote_operation, ctx, "delete_assistant", response)
        }

        Request::RepairMediaReservation {
            scope,
            id,
            expected_block_generation,
            repair_plan_digest,
            idempotency_key,
        } => {
            #[cfg(feature = "remote")]
            let request = Request::RepairMediaReservation {
                scope: scope.clone(),
                id: id.clone(),
                expected_block_generation,
                repair_plan_digest: repair_plan_digest.clone(),
                idempotency_key: idempotency_key.clone(),
            };
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept media reservation repairs",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let outcome = ctx
                .media_ledger
                .repair_accounting(
                    crate::media_reservation::AccountingRepairRequest {
                        attempt_id: Uuid::new_v4().to_string(),
                        scope_kind: scope,
                        scope_id: id,
                        expected_block_generation,
                        repair_plan_digest,
                        idempotency_key,
                        wall_ms: chrono::Utc::now()
                            .timestamp_millis()
                            .try_into()
                            .unwrap_or(0),
                    },
                    &state.principal,
                )
                .await
                .map_err(|error| bad_request(error.to_string()))?;
            let response = Response::MediaReservationRepaired {
                outcome: outcome.code().to_string(),
            };
            finish_nonrepeatable_response!(
                remote_operation,
                ctx,
                "repair_media_reservation",
                response
            )
        }

        // The following owner-remoted reads are `read_only`/concurrent and are
        // dispatched on the concurrent path; the serialized match is also
        // exhaustive over `Request`, so they delegate to the shared helpers.
        Request::ListPackages => list_packages_response(ctx).await,
        #[cfg(feature = "remote")]
        Request::GetConnectorState => get_connector_state_response(ctx).await,
        #[cfg(feature = "remote")]
        Request::GetOrgSyncStatus => get_org_sync_status_response(ctx).await,
        Request::ListFailedToolCalls {
            since_epoch,
            tool,
            model,
            project_id,
            include_recovered,
            limit,
        } => {
            list_failed_tool_calls_response(
                ctx,
                since_epoch,
                tool,
                model,
                project_id,
                include_recovered,
                limit,
            )
            .await
        }
        Request::GetSessionCompactions { session_id } => {
            get_session_compactions_response(ctx, session_id).await
        }
        Request::GetAssistant { name } => get_assistant_response(ctx, name).await,
        Request::DiagnoseMediaReservation { scope, id } => {
            diagnose_media_reservation_response(ctx, scope, id).await
        }
        Request::GetDoctorSnapshot {
            project_root,
            no_sandbox,
            offline,
        } => {
            get_doctor_snapshot_response(
                Some(ctx.db.clone()),
                ctx.secret_vault.clone(),
                project_root,
                no_sandbox,
                offline,
            )
            .await
        }
        // Owner-remoted, read-only, serialized: the docs pipeline creates a
        // `"docs"` session and runs a full turn, so it is not a snapshot-correct
        // concurrent read. Runs on this per-client serialized executor.
        Request::DocsAsk {
            question,
            package,
            project_root,
        } => docs_ask_response(ctx, question, package, project_root).await,

        Request::AgentInstallationBegin(request) => {
            let service = ctx.agent_installation_service().map_err(internal)?;
            Ok(Response::AgentInstallation(
                service
                    .begin(request, chrono::Utc::now().timestamp_millis())
                    .await,
            ))
        }
        Request::AgentInstallationSubmitChoice(request) => {
            let service = ctx.agent_installation_service().map_err(internal)?;
            Ok(Response::AgentInstallation(
                service
                    .submit_choice(request, chrono::Utc::now().timestamp_millis())
                    .await,
            ))
        }
        Request::AgentInstallationList(request) => {
            let service = ctx.agent_installation_service().map_err(internal)?;
            Ok(Response::AgentInstallation(service.list(request).await))
        }
        Request::AgentInstallationInspect(request) => {
            let service = ctx.agent_installation_service().map_err(internal)?;
            Ok(Response::AgentInstallation(service.inspect(request).await))
        }

        Request::CreateAssistantSession {
            name,
            project_root,
            initial_model,
            no_sandbox,
            env_snapshot,
        } => {
            let env_snapshot = env_snapshot.map(EnvSnapshot::from_wire).unwrap_or_else(|| {
                ctx.env_baseline
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone()
            });
            let handle = ctx
                .registry
                .create_assistant_session(
                    &name,
                    PathBuf::from(project_root),
                    initial_model,
                    no_sandbox,
                    env_snapshot,
                )
                .await
                .map_err(|error| {
                    if error
                        .downcast_ref::<crate::config::extended::InvalidResponseMetricsTokenizer>()
                        .is_some()
                    {
                        daemon_config_error(error)
                    } else {
                        ErrorPayload {
                            code: ErrorCode::BadRequest,
                            message: error.to_string(),
                        }
                    }
                })?;
            Ok(Response::AssistantSessionCreated {
                session: proto::AssistantSessionCreated {
                    session_id: handle.session_id,
                    short_id: handle.short_id(),
                    project_root: handle.project_root.display().to_string(),
                    project_id: handle.project_id(),
                    assistant_name: name,
                    active_agent: handle.active_agent_name,
                },
            })
        }

        Request::AutoTitle { session_id } => auto_title_request(ctx, session_id).await,

        Request::ExportSessionData {
            session_id,
            kind,
            include_generated_artifacts,
            include_sensitive,
        } => {
            let local_owner_action = is_local_owner_action(
                state,
                #[cfg(feature = "remote")]
                remote_operation,
            );
            export_session_data(
                ctx,
                session_id,
                kind,
                include_generated_artifacts,
                include_sensitive,
                local_owner_action,
            )
            .await
        }
        Request::ReadRedactedExportChunk {
            transfer_id,
            chunk_index,
        } => read_redacted_export_chunk(&transfer_id, chunk_index).await,
        #[cfg(feature = "remote")]
        Request::OperationStatus { operation_id } => {
            let ClientPrincipal::Remote(remote) = &shared.principal else {
                return Err(ErrorPayload {
                    code: ErrorCode::Authorization,
                    message: "operation status requires an authenticated remote actor".into(),
                });
            };
            let Some(actor) = remote.actor_binding.as_ref() else {
                return Err(ErrorPayload {
                    code: ErrorCode::Authorization,
                    message: "legacy actorless transport cannot query operation status".into(),
                });
            };
            let row = ctx
                .db
                .remote_operation_status(
                    &actor.logical_attachment_id.to_string(),
                    &operation_id.to_string(),
                )
                .await
                .map_err(internal)?;
            let status = if let Some(row) = row {
                let state = match row.state.as_str() {
                    "reserved" => proto::RemoteOperationStateV1::Reserved,
                    "committed" => proto::RemoteOperationStateV1::Committed,
                    "rejected" => proto::RemoteOperationStateV1::Rejected,
                    "outcome_unknown" => proto::RemoteOperationStateV1::OutcomeUnknown,
                    _ => return Err(internal(anyhow::anyhow!("invalid remote operation state"))),
                };
                Some(proto::RemoteOperationStatusV1 {
                    schema_version: 1,
                    operation_id,
                    state,
                    operation_seq: proto::remote_protocol_id::CanonicalU64DecimalStringV1::from_u64(
                        row.operation_seq,
                    ),
                    safe_response: row.safe_response,
                    event_high_water_mark: row
                        .event_high_water_mark
                        .map(proto::remote_protocol_id::CanonicalU64DecimalStringV1::from_u64),
                })
            } else {
                None
            };
            Ok(Response::RemoteOperationStatus { status })
        }

        Request::ImportSessionArchive { transfer } => import_session_archive(ctx, &transfer).await,
        Request::WriteBulkTransferChunk {
            transfer,
            chunk_index,
            data_base64,
        } => {
            let owner =
                if transfer.mime_class == cockpit_proto::bulk_transfer::BulkMimeClass::Opaque {
                    let session_id = require_attached(state)?.handle.session_id;
                    #[cfg(feature = "remote")]
                    {
                        Some(bulk_user_message_transfer_owner(
                            &state.principal,
                            session_id,
                            remote_operation,
                        )?)
                    }
                    #[cfg(not(feature = "remote"))]
                    {
                        Some(bulk_user_message_transfer_owner_local(
                            &state.principal,
                            session_id,
                        )?)
                    }
                } else {
                    None
                };
            write_bulk_transfer_chunk(&transfer, chunk_index, &data_base64, owner.as_ref()).await
        }
        Request::ReadBulkTransferChunk {
            transfer_id,
            chunk_index,
        } => read_bulk_transfer_chunk(&transfer_id, chunk_index).await,

        Request::Curator {
            project_root,
            action,
        } => curator_request(ctx, PathBuf::from(project_root), action).await,

        Request::CancelTurn => {
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::CancelTurn;
                let params = request
                    .canonical_remote_operation_params_v1()
                    .map_err(internal)?;
                let canonical = authorized_request.encode_fcor(&request, &params)?;
                let request_hash = remote_request_hash(ctx, &canonical);
                let logical_attachment_id = operation.logical_attachment_id.to_string();
                let operation_id = operation.operation_id.to_string();
                let device_id = operation.authenticated_device_id.to_string();
                let now = chrono::Utc::now().timestamp_millis();
                let begin = ctx.db.begin_nonrepeatable_remote_operation(
                    crate::db::remote_attachment_operations::ReserveRemoteOperation {
                        logical_attachment_id: &logical_attachment_id, operation_id: &operation_id,
                        authenticated_device_id: &device_id,
                        authenticated_device_generation: operation.authenticated_device_generation,
                        operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::NonrepeatableMutation,
                        request_hash, now_ms: now,
                    },
                ).await.map_err(internal)?;
                match begin {
                    crate::db::remote_attachment_operations::BeginNonrepeatableRemoteOperationOutcome::Replay(bytes) =>
                        return serde_json::from_slice(&bytes).map_err(internal),
                    crate::db::remote_attachment_operations::BeginNonrepeatableRemoteOperationOutcome::OutcomeUnknown(_) =>
                        return Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation outcome is unknown; it will not be retried".into() }),
                    crate::db::remote_attachment_operations::BeginNonrepeatableRemoteOperationOutcome::OperationConflict
                    | crate::db::remote_attachment_operations::BeginNonrepeatableRemoteOperationOutcome::OperationActorConflict =>
                        return Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation conflict".into() }),
                    crate::db::remote_attachment_operations::BeginNonrepeatableRemoteOperationOutcome::AttachmentLedgerCapacity =>
                        return Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation capacity reached".into() }),
                    crate::db::remote_attachment_operations::BeginNonrepeatableRemoteOperationOutcome::Dispatch { .. } => {}
                }
                if let Err(error) = att.handle.send_work(SessionWork::Cancel).await {
                    let unknown = serde_json::to_vec(&serde_json::json!({"outcome":"unknown"}))
                        .map_err(internal)?;
                    ctx.db
                        .mark_nonrepeatable_remote_operation_outcome_unknown(
                            &logical_attachment_id,
                            &operation_id,
                            &unknown,
                            chrono::Utc::now().timestamp_millis(),
                        )
                        .await
                        .map_err(internal)?;
                    return Err(internal(error));
                }
                let response = Response::Ack;
                let bytes = serde_json::to_vec(&response).map_err(internal)?;
                let delivery_id = Uuid::now_v7().to_string();
                match ctx.db.commit_remote_attachment_operation(
                    crate::db::remote_attachment_operations::CommitRemoteOperation {
                        logical_attachment_id: &logical_attachment_id, operation_id: &operation_id,
                        safe_response: &bytes, outbox_delivery_id: &delivery_id,
                        outbox_kind: "cancel_turn", outbox_payload: &bytes,
                        now_ms: chrono::Utc::now().timestamp_millis(),
                    },
                ).await.map_err(internal)? {
                    crate::db::remote_attachment_operations::CommitRemoteOperationOutcome::Committed { .. } => return Ok(response),
                    _ => {
                        let unknown = br#"{"outcome":"unknown"}"#;
                        ctx.db.mark_nonrepeatable_remote_operation_outcome_unknown(
                            &logical_attachment_id, &operation_id, unknown,
                            chrono::Utc::now().timestamp_millis(),
                        ).await.map_err(internal)?;
                        return Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation capacity reached after dispatch; outcome is unknown".into() });
                    }
                }
            }
            att.handle
                .send_work(SessionWork::Cancel)
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::FsList {
            project_root,
            path,
            show_hidden,
        } => {
            crate::daemon::fs_api::fs_list(
                ctx.clone(),
                state.principal.clone(),
                project_root,
                path,
                show_hidden,
            )
            .await
        }

        Request::FsStat { project_root, path } => {
            crate::daemon::fs_api::fs_stat(ctx.clone(), state.principal.clone(), project_root, path)
                .await
        }

        Request::FsRead {
            project_root,
            path,
            base64,
        } => {
            crate::daemon::fs_api::fs_read(
                ctx.clone(),
                state.principal.clone(),
                project_root,
                path,
                base64,
            )
            .await
        }

        Request::FsWrite {
            project_root,
            path,
            content,
            base_hash,
        } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::FsWrite {
                    project_root: project_root.clone(),
                    path: path.clone(),
                    content: content.clone(),
                    base_hash: base_hash.clone(),
                };
                let generation = match begin_remote_idempotent_adapter(
                    &request,
                    &authorized_request,
                    operation,
                    ctx,
                )
                .await?
                {
                    RemoteAdapterBegin::Replay(response) => return Ok(response),
                    RemoteAdapterBegin::Dispatch { generation } => generation,
                };
                let response = crate::daemon::fs_api::fs_write_staged_remote(
                    ctx.clone(),
                    project_root,
                    path,
                    content,
                    base_hash,
                    operation.operation_id.to_string(),
                )
                .await?;
                return commit_remote_idempotent_adapter(
                    operation, ctx, "fs_write", generation, response,
                )
                .await;
            }
            crate::daemon::fs_api::fs_write(ctx.clone(), project_root, path, content, base_hash)
                .await
        }

        Request::GetAgentInventory { project_root } => {
            crate::daemon::agent_management::inventory(ctx, project_root).await
        }

        Request::GetAgentEditSnapshot { project_root, name } => {
            crate::daemon::agent_management::edit_snapshot(ctx, project_root, name).await
        }

        Request::MutateAgent {
            project_root,
            mutation,
            expected_revision,
        } => {
            crate::daemon::agent_management::mutate(ctx, project_root, mutation, expected_revision)
                .await
        }

        Request::BeginAgentEditorLease {
            project_root,
            name,
            expected_revision,
        } => {
            crate::daemon::agent_management::begin_editor_lease(
                ctx,
                project_root,
                name,
                expected_revision,
                agent_editor_lease_owner(state),
            )
            .await
        }

        Request::CompleteAgentEditorLease {
            project_root,
            lease_id,
            markdown,
        } => {
            crate::daemon::agent_management::complete_editor_lease(
                ctx,
                project_root,
                lease_id,
                markdown,
                agent_editor_lease_owner(state),
            )
            .await
        }

        Request::GetExtendedConfigSnapshot { project_root } => {
            crate::daemon::fs_api::get_extended_config_snapshot(ctx, project_root).await
        }

        Request::ApplyExtendedConfigPatch {
            project_root,
            layer_id,
            patch,
            expected_revision,
        } => {
            let response = crate::daemon::fs_api::apply_extended_config_patch(
                ctx,
                project_root,
                layer_id,
                patch,
                expected_revision,
            )
            .await?;
            if let Err(error) = ctx.refresh_redaction_table() {
                ctx.poison_redaction_publication(&error);
                return Err(internal(error));
            }
            Ok(response)
        }

        Request::SaveExtendedConfig {
            project_root,
            path,
            content,
            base_hash,
        } => {
            #[cfg(feature = "remote")]
            let request = Request::SaveExtendedConfig {
                project_root: project_root.clone(),
                path: path.clone(),
                content: content.clone(),
                base_hash: base_hash.clone(),
            };
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            // A durable config write. It touches the filesystem, so it cannot
            // share the SQLite transaction that commits the remote replay
            // record; `finish_remote_provider_mutation` closes the reserved
            // operation as unknown on any error (an atomic replacement may have
            // reached disk) so a retry never rewrites the config a second time.
            let mutation = async {
                let response = crate::daemon::fs_api::save_extended_config(
                    project_root,
                    path,
                    content,
                    base_hash,
                )
                .await?;
                // The saved config can change `redact.denylist`. The committed
                // global redaction table is otherwise rebuilt only when the
                // vault inventory generation advances (see `broadcast_global`),
                // so a config-only denylist change would leave the next global
                // broadcast scrubbing against a STALE table and disclose a newly
                // denylisted secret. Rebuild the table now — mirroring how
                // owner-vault mutations publish theirs — so every subsequent
                // broadcast uses the fresh denylist. This runs once per (rare)
                // config mutation, never per broadcast, so it does not
                // reintroduce the per-event fork/scan storm. A rebuild failure
                // must not be swallowed: retaining the stale table could
                // disclose the secret, so poison the daemon.
                if let Err(error) = ctx.refresh_redaction_table() {
                    ctx.poison_redaction_publication(&error);
                    return Err(internal(error));
                }
                Ok(response)
            };
            finish_provider_mutation_future!(
                remote_operation,
                ctx,
                "save_extended_config",
                mutation
            )
        }

        Request::ExportPolicy { project_root } => {
            let bundle_json = tokio::task::spawn_blocking(move || {
                crate::policy::export(std::path::Path::new(&project_root))
            })
            .await
            .map_err(internal)?
            .map_err(internal)?;
            Ok(Response::PolicyExported { bundle_json })
        }

        Request::ImportPolicy {
            project_root,
            bundle_json,
            replace,
        } => {
            #[cfg(feature = "remote")]
            let request = Request::ImportPolicy {
                project_root: project_root.clone(),
                bundle_json: bundle_json.clone(),
                replace,
            };
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            // Import stages any literal credentials into the vault (never into
            // config) inside `crate::policy::import`; the vault handle is passed
            // through unchanged on the remote path so the vault-only custody
            // guarantee holds identically for a remote owner.
            let import_vault = ctx.secret_vault.clone();
            let mutation = async move {
                let (target, provider_count) = tokio::task::spawn_blocking(move || {
                    crate::policy::import(
                        std::path::Path::new(&project_root),
                        &bundle_json,
                        replace,
                        Some(import_vault),
                    )
                })
                .await
                .map_err(internal)?
                .map_err(internal)?;
                Ok(Response::PolicyImported {
                    target: target.display().to_string(),
                    provider_count,
                })
            };
            finish_provider_mutation_future!(remote_operation, ctx, "import_policy", mutation)
        }

        Request::GetImageSpendPolicy { project_key } => {
            let current = ctx
                .db
                .current_image_spend_policy(project_key)
                .await
                .map_err(internal)?;
            Ok(Response::ImageSpendPolicy {
                settings: current.as_ref().map(|policy| policy.settings.clone()),
                policy_version: current.map(|policy| policy.policy_version),
            })
        }

        // LOCAL owner image-control reads are `concurrent`, so they normally
        // route to the concurrent surface; this arm keeps the exhaustive
        // serialized match complete and shares the one redacting handler.
        Request::ImageEndpointList { .. }
        | Request::ImageEndpointGet { .. }
        | Request::ImageTargetList { .. }
        | Request::ImageTargetGet { .. }
        | Request::ImageWorkflowList { .. }
        | Request::ImageWorkflowGet { .. } => dispatch_image_control_read(ctx, request).await,

        // LOCAL owner image-config MUTATIONS (owner_only + local_only +
        // serialized). No remote operation is ever reserved for a local_only
        // request, so these run the load → validate(`ImageGenerationConfig::new`)
        // → generation-CAS → write → `config_changed` sequence directly.
        Request::ImageEndpointCreate { .. }
        | Request::ImageEndpointUpdate { .. }
        | Request::ImageEndpointDelete { .. }
        | Request::ImageTargetCreate { .. }
        | Request::ImageTargetUpdate { .. }
        | Request::ImageTargetDelete { .. }
        | Request::ImageTargetSetDefault { .. }
        | Request::ImageWorkflowUpload { .. }
        | Request::ImageWorkflowBind { .. }
        | Request::ImageWorkflowDelete { .. } => {
            image_control_mutations::dispatch_image_control_mutation(ctx, request).await
        }

        Request::SaveImageSpendPolicy {
            project_key,
            settings_json,
            expected_policy_version,
        } => {
            #[cfg(feature = "remote")]
            let request = Request::SaveImageSpendPolicy {
                project_key: project_key.clone(),
                settings_json: settings_json.clone(),
                expected_policy_version,
            };
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let mutation = async {
                let settings =
                    serde_json::from_str(&settings_json).map_err(|error| ErrorPayload {
                        code: ErrorCode::BadRequest,
                        message: format!("invalid image spend settings: {error}"),
                    })?;
                let saved = cockpit_config::config::image_spend::activate_saved_policy(
                    &ctx.db,
                    project_key,
                    settings,
                    expected_policy_version,
                    chrono::Utc::now().timestamp_millis(),
                )
                .await
                .map_err(internal)?;
                Ok(Response::ImageSpendPolicySaved {
                    policy_version: saved.policy_version,
                })
            };
            finish_provider_mutation_future!(
                remote_operation,
                ctx,
                "save_image_spend_policy",
                mutation
            )
        }

        Request::FsCreateDir { project_root, path } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::FsCreateDir {
                    project_root: project_root.clone(),
                    path: path.clone(),
                };
                let generation = match begin_remote_idempotent_adapter(
                    &request,
                    &authorized_request,
                    operation,
                    ctx,
                )
                .await?
                {
                    RemoteAdapterBegin::Replay(response) => return Ok(response),
                    RemoteAdapterBegin::Dispatch { generation } => generation,
                };
                let response =
                    crate::daemon::fs_api::fs_create_dir_reconciled_remote(project_root, path)
                        .await?;
                return commit_remote_idempotent_adapter(
                    operation,
                    ctx,
                    "fs_create_dir",
                    generation,
                    response,
                )
                .await;
            }
            crate::daemon::fs_api::fs_create_dir(project_root, path).await
        }

        Request::FsRename {
            project_root,
            from_path,
            to_path,
        } => {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                if ctx.external_journal.is_some() {
                    let request = Request::FsRename {
                        project_root,
                        from_path,
                        to_path,
                    };
                    return execute_remote_staged_rename(
                        &request,
                        &authorized_request,
                        operation,
                        ctx,
                    )
                    .await;
                }
                return Err(ErrorPayload {
                    code: ErrorCode::Unavailable,
                    message: if cfg!(any(target_os = "linux", target_os = "macos")) {
                        "remote staged rename is unavailable until held-handle recovery is initialized"
                            .into()
                    } else {
                        "remote staged rename is unavailable on this platform; held-handle security is deferred"
                            .into()
                    },
                });
            }
            crate::daemon::fs_api::fs_rename(ctx.clone(), project_root, from_path, to_path).await
        }

        Request::FsDelete { project_root, path } => {
            crate::daemon::fs_api::fs_delete(ctx.clone(), project_root, path).await
        }

        Request::GitStatus { project_root } => {
            crate::daemon::fs_api::git_status(project_root).await
        }

        Request::GitDiffFile { project_root, path } => {
            crate::daemon::fs_api::git_diff_file(project_root, path).await
        }

        Request::OpenTerminal { cwd, cols, rows } => {
            let session_id = state
                .attached
                .as_ref()
                .map_or(Uuid::nil(), |attached| attached.handle.session_id);
            let response = state.terminal_host.open(
                state.terminal_context.clone(),
                session_id,
                cwd,
                cols,
                rows,
            )?;
            if let Response::TerminalOpened {
                terminal_id,
                binding,
                ..
            } = &response
            {
                state.terminal_views.insert(*terminal_id, *binding);
                Ok(response)
            } else {
                Ok(response)
            }
        }

        Request::AttachTerminal {
            terminal_id,
            cols,
            rows,
        } => {
            let session_id = state
                .attached
                .as_ref()
                .map_or(Uuid::nil(), |attached| attached.handle.session_id);
            let response = state.terminal_host.attach(
                state.terminal_context.clone(),
                session_id,
                terminal_id,
                cols,
                rows,
            )?;
            if let Response::TerminalOpened { binding, .. } = &response {
                state.terminal_views.insert(terminal_id, *binding);
            }
            Ok(response)
        }

        Request::TerminalInput { terminal_id, bytes } => {
            let binding = *state
                .terminal_views
                .get(&terminal_id)
                .ok_or_else(invalid_terminal_ingress)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::TerminalInput {
                    terminal_id,
                    bytes: bytes.clone(),
                };
                if let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
                {
                    return Ok(response);
                }
                let response = state.terminal_host.input(terminal_id, binding, bytes)?;
                return commit_remote_nonrepeatable(operation, ctx, "terminal_input", response)
                    .await;
            }
            state.terminal_host.input(terminal_id, binding, bytes)
        }

        Request::TerminalResize {
            terminal_id,
            cols,
            rows,
        } => {
            let binding = *state
                .terminal_views
                .get(&terminal_id)
                .ok_or_else(invalid_terminal_ingress)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::TerminalResize {
                    terminal_id,
                    cols,
                    rows,
                };
                if let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
                {
                    return Ok(response);
                }
                let response = state
                    .terminal_host
                    .resize(terminal_id, binding, cols, rows)?;
                return commit_remote_nonrepeatable(operation, ctx, "terminal_resize", response)
                    .await;
            }
            state.terminal_host.resize(terminal_id, binding, cols, rows)
        }

        Request::CloseTerminal { terminal_id } => {
            let binding = state
                .terminal_views
                .remove(&terminal_id)
                .ok_or_else(invalid_terminal_ingress)?;
            state.terminal_host.close(terminal_id, binding)
        }

        Request::TerminalIngressBegin {
            terminal_id,
            binding,
            metadata,
        } => {
            require_terminal_binding(state, terminal_id, binding)?;
            state
                .terminal_host
                .ingress_begin(terminal_id, binding, metadata)
        }
        Request::TerminalIngressChunk {
            terminal_id,
            binding,
            operation_id,
            offset,
            data_base64,
        } => {
            require_terminal_binding(state, terminal_id, binding)?;
            if data_base64.len() > 66_000 {
                return Err(invalid_terminal_ingress());
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data_base64)
                .map_err(|_| invalid_terminal_ingress())?;
            state
                .terminal_host
                .ingress_chunk(terminal_id, binding, operation_id, offset, bytes)
        }
        Request::TerminalIngressFinish {
            terminal_id,
            binding,
            operation_id,
        } => {
            require_terminal_binding(state, terminal_id, binding)?;
            state
                .terminal_host
                .ingress_finish(terminal_id, binding, operation_id)
        }
        Request::TerminalIngressStatus {
            terminal_id,
            binding,
            operation_id,
        } => {
            require_terminal_binding(state, terminal_id, binding)?;
            state
                .terminal_host
                .ingress_status(terminal_id, binding, operation_id)
        }

        Request::LspControl {
            project_root,
            server_id,
            action,
        } => {
            let att = require_attached(state)?;
            let cwd = Path::new(&project_root);
            let trust_policy = attached_trust_policy(ctx, att).await?;
            let (_, config) = ctx
                .config_source()
                .load_with_trust(cwd, &trust_policy)
                .map_err(internal)?;
            let message = ctx
                .registry
                .lsp_manager()
                .control(cwd, &server_id, action, &config)
                .await;
            att.handle.broadcast_notice(message.clone());
            Ok(Response::LspControlResult { message })
        }

        Request::ResolveInterrupt {
            interrupt_id,
            response,
        } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::ResolveInterrupt {
                    interrupt_id,
                    response,
                })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::ListSessions {
            project_id,
            parent_session_id,
            assistant_id,
        } => {
            list_sessions(
                ctx,
                &state.principal,
                project_id,
                parent_session_id,
                assistant_id,
            )
            .await
        }

        Request::ReadSessionMessages {
            session_id,
            before_seq,
            limit,
        } => {
            let db = ctx.db.clone();
            let (messages, has_more) = db
                .read(move |conn| {
                    crate::db::Db::read_session_messages_conn(conn, session_id, before_seq, limit)
                })
                .await
                .map_err(internal)?;
            Ok(Response::SessionMessages {
                session_id,
                messages,
                has_more,
            })
        }

        Request::ReadClientSubmissionReceipt {
            session_id,
            client_submission_id,
        } => {
            let durable = ctx
                .db
                .client_submission_receipt(session_id, client_submission_id)
                .await
                .map_err(internal)?;
            let status = if let Some(receipt) = durable {
                proto::ClientSubmissionReceiptStatus::Accepted {
                    seq: receipt.seq,
                    wire_fingerprint: receipt.wire_fingerprint,
                }
            } else if let Some(receipt) = ctx
                .db
                .client_submission_terminal_receipt(session_id, client_submission_id)
                .await
                .map_err(internal)?
            {
                proto::ClientSubmissionReceiptStatus::Terminal {
                    disposition: receipt.disposition.as_str().to_string(),
                    wire_fingerprint: receipt.wire_fingerprint,
                }
            } else {
                proto::ClientSubmissionReceiptStatus::Pending
            };
            Ok(Response::ClientSubmissionReceipt {
                session_id,
                client_submission_id,
                status,
            })
        }

        Request::ReadHistoryPage {
            session_id,
            before_seq,
            limit,
        } => {
            let db = ctx.db.clone();
            let config_source = ctx.config_source.clone();
            let page = db
                .read(move |conn| {
                    read_history_page_conn(conn, session_id, before_seq, limit, &config_source)
                })
                .await
                .map_err(internal)?;
            Ok(Response::HistoryPage {
                session_id,
                entries: page.entries,
                has_more: page.has_more,
                oldest_seq: page.oldest_seq,
            })
        }

        Request::ReadSubagentHistoryPage {
            session_id,
            task_call_id,
            label,
            before_seq,
            limit,
        } => {
            let db = ctx.db.clone();
            let query_task_call_id = task_call_id.clone();
            let query_label = label.clone();
            let page = db
                .read(move |conn| {
                    read_subagent_history_page_conn(
                        conn,
                        session_id,
                        &query_task_call_id,
                        &query_label,
                        before_seq,
                        limit,
                    )
                })
                .await
                .map_err(internal)?;
            Ok(Response::SubagentHistoryPage {
                session_id,
                task_call_id,
                label,
                entries: page.entries,
                has_more: page.has_more,
                oldest_seq: page.oldest_seq,
            })
        }

        Request::SessionLiveStatus { session_ids } => {
            let mut visible_ids = Vec::new();
            for id in session_ids {
                if state.principal.is_owner() {
                    visible_ids.push(id);
                    continue;
                }
                match ctx.db.get_session(id).await {
                    Ok(Some(row))
                        if session_access_for_row(&state.principal, &row)
                            != SessionAccess::None =>
                    {
                        visible_ids.push(id);
                    }
                    Ok(_) => {}
                    Err(e) => return Err(internal(e)),
                }
            }
            let mut statuses = Vec::new();
            for id in visible_ids {
                let Some((has_active_schedules, processing, _tool_running)) =
                    ctx.registry.live_status(id)
                else {
                    continue;
                };
                // v10-only: include the session's canonical project root so a
                // `cockpit run --session <id>` client can validate it matches
                // --cwd/--project before attaching. The field is `None` for v9
                // negotiated connections (the version gate strips it).
                let project_root = ctx
                    .db
                    .get_session(id)
                    .await
                    .ok()
                    .flatten()
                    .map(|row| row.project_root);
                statuses.push(proto::LiveStatus {
                    session_id: id,
                    has_active_schedules,
                    processing,
                    project_root,
                });
            }
            Ok(Response::SessionLiveStatus { statuses })
        }

        Request::ArchiveSession {
            session_id,
            cascade,
        } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::ArchiveSession {
                    session_id,
                    cascade,
                };
                let ledger =
                    build_remote_session_ledger(ctx, &authorized_request, &request, operation)?;
                return sessions_remote::archive_session(ctx, session_id, cascade, &ledger).await;
            }
            archive_session(ctx, session_id, cascade).await
        }

        Request::UnarchiveSession { session_id } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::UnarchiveSession { session_id };
                let ledger =
                    build_remote_session_ledger(ctx, &authorized_request, &request, operation)?;
                return sessions_remote::unarchive_session(ctx, session_id, &ledger).await;
            }
            unarchive_session(ctx, session_id).await
        }

        Request::ForkSession {
            parent_session_id,
            fork_point_turn_id,
            ephemeral,
        } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let ledger = build_remote_session_ledger(
                    ctx,
                    &authorized_request,
                    &Request::ForkSession {
                        parent_session_id,
                        fork_point_turn_id: fork_point_turn_id.clone(),
                        ephemeral,
                    },
                    operation,
                )?;
                return sessions_remote::fork_session(
                    ctx,
                    &state.principal,
                    parent_session_id,
                    fork_point_turn_id,
                    ephemeral,
                    &ledger,
                )
                .await;
            }
            fork_session(
                ctx,
                &state.principal,
                parent_session_id,
                fork_point_turn_id,
                ephemeral,
            )
            .await
        }

        Request::DiscardSession { session_id } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let ledger = build_remote_session_ledger(
                    ctx,
                    &authorized_request,
                    &Request::DiscardSession { session_id },
                    operation,
                )?;
                return sessions_remote::discard_session(state, ctx, session_id, &ledger).await;
            }
            discard_session(state, ctx, session_id).await
        }

        Request::CreateBtwFork {
            parent_session_id,
            tangent,
        } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let ledger = build_remote_session_ledger(
                    ctx,
                    &authorized_request,
                    &Request::CreateBtwFork {
                        parent_session_id,
                        tangent,
                    },
                    operation,
                )?;
                return sessions_remote::create_btw_fork(
                    ctx,
                    &state.principal,
                    parent_session_id,
                    tangent,
                    &ledger,
                )
                .await;
            }
            create_btw_fork(ctx, &state.principal, parent_session_id, tangent).await
        }

        Request::EndBtwFork { parent_session_id } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let ledger = build_remote_session_ledger(
                    ctx,
                    &authorized_request,
                    &Request::EndBtwFork { parent_session_id },
                    operation,
                )?;
                return sessions_remote::end_btw_fork(ctx, parent_session_id, &ledger).await;
            }
            end_btw_fork(ctx, parent_session_id).await
        }

        Request::RenameSession { session_id, title } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::RenameSession {
                    session_id,
                    title: title.clone(),
                };
                let ledger =
                    build_remote_session_ledger(ctx, &authorized_request, &request, operation)?;
                return sessions_remote::rename_session(ctx, session_id, title, &ledger).await;
            }
            rename_session(ctx, session_id, &title).await
        }

        Request::ShareSession { session_id, shared } => {
            ctx.db
                .set_session_shared_with_collaborators(session_id, shared)
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::RecordSessionNote { session_id, text } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::RecordSessionNote {
                    session_id,
                    text: text.clone(),
                };
                let ledger =
                    build_remote_session_ledger(ctx, &authorized_request, &request, operation)?;
                return sessions_remote::record_session_note(ctx, session_id, text, &ledger).await;
            }
            record_session_note(ctx, session_id, &text).await
        }

        Request::DeleteSession { session_id } => {
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let ledger = build_remote_session_ledger(
                    ctx,
                    &authorized_request,
                    &Request::DeleteSession { session_id },
                    operation,
                )?;
                return sessions_remote::delete_session(
                    ctx,
                    session_id,
                    state.negotiated_protocol_version(),
                    &ledger,
                )
                .await;
            }
            delete_session(ctx, session_id, state.negotiated_protocol_version()).await
        }

        Request::GetInventoryBundle {
            project_root,
            session_id,
            selected_agent,
        } => get_inventory_bundle(ctx, state, project_root, session_id, selected_agent).await,
        Request::ResourceSnapshot => Ok(Response::ResourceSnapshot {
            snapshot: resource_scheduler_snapshot(ctx),
        }),
        Request::PromoteResource {
            request_id,
            session_id,
        } => promote_resource_request(ctx, &request_id, session_id).await,

        Request::CreateScheduledJob { job } => {
            let scheduler = require_scheduler(ctx)?;
            let job = scheduler.create_job(job).await.map_err(internal)?;
            Ok(Response::ScheduledJob { job })
        }
        Request::ListScheduledJobs { owner } => {
            let scheduler = require_scheduler(ctx)?;
            let jobs = scheduler
                .list_jobs(owner.as_deref())
                .await
                .map_err(internal)?;
            Ok(Response::ScheduledJobs { jobs })
        }
        Request::DeleteScheduledJob { id } => {
            let scheduler = require_scheduler(ctx)?;
            let deleted = scheduler.delete_job(&id).await.map_err(internal)?;
            Ok(Response::ScheduledJobDeleted { id, deleted })
        }
        Request::SetScheduledJobEnabled { id, enabled } => {
            let scheduler = require_scheduler(ctx)?;
            let job = scheduler
                .set_enabled(&id, enabled)
                .await
                .map_err(internal)?
                .ok_or_else(|| ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: format!("scheduled job `{id}` not found"),
                })?;
            Ok(Response::ScheduledJob { job })
        }
        Request::RunScheduledJob { id } => {
            let scheduler = require_scheduler(ctx)?;
            scheduler.run_now(&id).await.map_err(internal)?;
            Ok(Response::ScheduledJobRunQueued { id })
        }

        Request::SetModelFavorite {
            provider,
            model,
            favorite,
        } => {
            let att = require_attached(state)?;
            let snapshot = att.handle.config_snapshot();
            let provider_entry = snapshot
                .providers
                .providers
                .get(&provider)
                .ok_or_else(|| bad_request(format!("provider {provider} not in config")))?;
            if !provider_entry.models.iter().any(|entry| entry.id == model) {
                return Err(bad_request(format!(
                    "model {model} not in provider {provider}"
                )));
            }
            let trust_policy = attached_trust_policy(ctx, att).await?;
            let path = crate::config::trust::with_workspace_trust_policy(trust_policy, || {
                ctx.config_source()
                    .config_write_target_for_provider(&att.handle.project_root, &provider)
            })
            .ok_or_else(|| bad_request("no cockpit config found"))?;
            // Trust selects the concrete provider layer above. The blocking
            // mutation uses only that path (it does not rediscover layers),
            // so no task-local trust state is needed inside this thread.
            tokio::task::spawn_blocking(move || {
                let mut doc = crate::config::providers::ConfigDoc::load(&path)?;
                doc.write_model_favorite(&provider, &model, favorite)
            })
            .await
            .map_err(internal)?
            .map_err(internal)?;
            crate::daemon::config_refresh::refresh_session_config(
                &ctx.db,
                ctx.config_source(),
                &att.handle,
                None,
            )
            .await
            .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetDefaultModel {
            default_update_id,
            provider,
            model,
            reasoning_effort,
            thinking_mode,
            prompt_cache_retention,
            clear,
        } => {
            let att = require_attached(state)?;
            let trust_policy = attached_trust_policy(ctx, att).await?;
            let cwd = att.handle.project_root.clone();
            let session_id = att.handle.session_id;
            // Project root and trust come solely from the authenticated
            // attachment; a caller can never name a filesystem target.
            let requested = if clear {
                None
            } else {
                Some(crate::config::providers::ActiveModelRef {
                    provider: provider.unwrap_or_default(),
                    model: model.unwrap_or_default(),
                    reasoning_effort: reasoning_effort
                        .map(|value| crate::config::providers::ActiveReasoningEffort { value }),
                    thinking_mode,
                    prompt_cache_retention,
                })
            };
            let result = tokio::task::spawn_blocking(move || {
                let write = || {
                    crate::config::providers::mutate_effective_default(
                        &cwd,
                        requested.as_ref(),
                        crate::config::providers::ActiveModelWriteMode::Replace,
                        None,
                        None,
                        Some(
                            crate::config::providers::TransactionCorrelation::DefaultUpdate {
                                default_update_id,
                                session_id,
                            },
                        ),
                    )
                };
                crate::config::trust::with_workspace_trust_policy(trust_policy, write)
            })
            .await
            .map_err(internal)?;
            let outcome = match result {
                Ok(result) => {
                    // The write is verified; the snapshot refresh is a
                    // best-effort follow-up. A refresh failure must never
                    // replace the correlated terminal result with a bare
                    // transport error — the client would wait forever.
                    if let Err(error) = crate::daemon::config_refresh::refresh_session_config(
                        &ctx.db,
                        ctx.config_source(),
                        &att.handle,
                        None,
                    )
                    .await
                    {
                        tracing::warn!(
                            %error,
                            "default model verified but the config snapshot refresh failed"
                        );
                    }
                    proto::DefaultModelStandaloneOutcome::Applied {
                        selection: result.selection,
                        generation: result.generation,
                        scope_label: result.scope_label,
                        unchanged: result.unchanged,
                    }
                }
                // A transaction still pending recovery is not terminal: the
                // recovery pass that converges the journal emits the one
                // correlated result. Ack the request and emit nothing here.
                Err(error) if error.recovery_pending => {
                    tracing::warn!(
                        diagnostic_code = error.diagnostic_code,
                        "default model update is pending recovery; no terminal result emitted"
                    );
                    return Ok(Response::Ack);
                }
                Err(error) => proto::DefaultModelStandaloneOutcome::Rejected {
                    user_message: error.user_message,
                    diagnostic_code: error.diagnostic_code.to_string(),
                },
            };
            att.handle
                .broadcast_default_model_update_result(default_update_id, outcome);
            Ok(Response::Ack)
        }

        Request::SetActiveModel {
            selection_id,
            provider,
            model,
            persist_as_default,
            trigger,
            reasoning_effort,
            thinking_mode,
            prompt_cache_retention,
        } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetActiveModel {
                    selection_id,
                    selection_deadline: std::time::Instant::now()
                        + std::time::Duration::from_secs(60),
                    provider,
                    model,
                    persist_as_default,
                    trigger: active_model_trigger_from_proto(trigger),
                    reasoning_effort,
                    thinking_mode,
                    prompt_cache_retention,
                })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetAgent { name } => {
            let att = require_attached(state)?;
            validate_set_agent(ctx, att, &name)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let session_id = att.handle.session_id;
                let request = Request::SetAgent { name: name.clone() };
                let params = request
                    .canonical_remote_operation_params_v1()
                    .map_err(internal)?;
                let canonical = authorized_request.encode_fcor(&request, &params)?;
                let request_hash = remote_request_hash(ctx, &canonical);
                let attachment = operation.logical_attachment_id.to_string();
                let operation_id = operation.operation_id.to_string();
                let device = operation.authenticated_device_id.to_string();
                let desired = name.clone();
                let outcome = ctx.db.execute_idempotent_adapter_remote_operation(
                    crate::db::remote_attachment_operations::ReserveRemoteOperation {
                        logical_attachment_id: &attachment, operation_id: &operation_id,
                        authenticated_device_id: &device,
                        authenticated_device_generation: operation.authenticated_device_generation,
                        operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::IdempotentAdapterMutation,
                        request_hash, now_ms: chrono::Utc::now().timestamp_millis(),
                    },
                    move |conn| {
                        crate::db::Db::set_session_agent_conn(conn, session_id, &desired)?;
                        let response = Response::Ack;
                        let bytes = serde_json::to_vec(&response)?;
                        Ok(crate::db::remote_attachment_operations::TransactionalRemoteMutation {
                            value: response, safe_response: bytes.clone(),
                            outbox_kind: "set_agent".into(), outbox_payload: bytes,
                        })
                    },
                ).await.map_err(internal)?;
                let response = match outcome {
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied(response) => response,
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(bytes) => serde_json::from_slice(&bytes).map_err(internal)?,
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationConflict
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationActorConflict
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::ExistingIndeterminate => return Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation conflict".into() }),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity => return Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation capacity reached".into() }),
                };
                // Idempotent live convergence. If the process dies here, the
                // durable session row is authoritative on resume/recovery.
                att.handle
                    .send_work(SessionWork::SetAgent { name })
                    .await
                    .map_err(internal)?;
                return Ok(response);
            }
            att.handle
                .send_work(SessionWork::SetAgent { name })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetLlmMode { mode } => {
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) = begin_remote_nonrepeatable(
                    &Request::SetLlmMode { mode },
                    &authorized_request,
                    operation,
                    ctx,
                )
                .await?
            {
                return Ok(response);
            }
            att.handle
                .send_work(SessionWork::SetLlmMode { mode })
                .await
                .map_err(internal)?;
            finish_nonrepeatable_response!(remote_operation, ctx, "set_llm_mode", Response::Ack)
        }

        Request::SetSessionLlmMode { mode } => {
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let session_id = att.handle.session_id;
                let request = Request::SetSessionLlmMode { mode };
                let params = request
                    .canonical_remote_operation_params_v1()
                    .map_err(internal)?;
                let canonical = authorized_request.encode_fcor(&request, &params)?;
                let request_hash = remote_request_hash(ctx, &canonical);
                let attachment = operation.logical_attachment_id.to_string();
                let operation_id = operation.operation_id.to_string();
                let device = operation.authenticated_device_id.to_string();
                let mode_label = mode.as_str().to_string();
                let outcome = ctx.db.execute_idempotent_adapter_remote_operation(
                    crate::db::remote_attachment_operations::ReserveRemoteOperation {
                        logical_attachment_id: &attachment, operation_id: &operation_id,
                        authenticated_device_id: &device,
                        authenticated_device_generation: operation.authenticated_device_generation,
                        operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::IdempotentAdapterMutation,
                        request_hash, now_ms: chrono::Utc::now().timestamp_millis(),
                    },
                    move |conn| {
                        crate::db::Db::set_session_llm_mode_conn(conn, session_id, &mode_label)?;
                        let response = Response::Ack;
                        let bytes = serde_json::to_vec(&response)?;
                        Ok(crate::db::remote_attachment_operations::TransactionalRemoteMutation {
                            value: response, safe_response: bytes.clone(),
                            outbox_kind: "set_session_llm_mode".into(), outbox_payload: bytes,
                        })
                    },
                ).await.map_err(internal)?;
                let response = match outcome {
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied(response) => response,
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(bytes) => serde_json::from_slice(&bytes).map_err(internal)?,
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationConflict
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationActorConflict
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::ExistingIndeterminate => return Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation conflict".into() }),
                    crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity
                    | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity => return Err(ErrorPayload { code: ErrorCode::Conflict, message: "remote operation capacity reached".into() }),
                };
                att.handle
                    .send_work(SessionWork::SetSessionLlmMode { mode })
                    .await
                    .map_err(internal)?;
                return Ok(response);
            }
            att.handle
                .send_work(SessionWork::SetSessionLlmMode { mode })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetToolSurfaceOverride {
            override_json,
            persist_session,
            prune_after_switch,
            monty_nudge,
        } => {
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::SetToolSurfaceOverride {
                    override_json: override_json.clone(),
                    persist_session,
                    prune_after_switch,
                    monty_nudge: monty_nudge.clone(),
                };
                if let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
                {
                    return Ok(response);
                }
            }
            serde_json::from_str::<crate::agents::ToolSurfaceSelection>(&override_json)
                .map_err(|error| bad_request(format!("invalid tool surface override: {error}")))?;
            att.handle
                .send_work(SessionWork::SetToolSurfaceOverride {
                    override_json,
                    persist_session,
                    prune_after_switch,
                    monty_nudge,
                })
                .await
                .map_err(internal)?;
            finish_nonrepeatable_response!(
                remote_operation,
                ctx,
                "set_tool_surface_override",
                Response::Ack
            )
        }

        Request::SetGoalSettingsOverride {
            override_json,
            persist_session,
        } => {
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::SetGoalSettingsOverride {
                    override_json: override_json.clone(),
                    persist_session,
                };
                if let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
                {
                    return Ok(response);
                }
            }
            if let Some(raw) = override_json.as_deref() {
                crate::agents::parse_goal_settings_override_json(raw).map_err(|error| {
                    bad_request(format!("invalid goal settings override: {error}"))
                })?;
            }
            att.handle
                .send_work(SessionWork::SetGoalSettingsOverride {
                    override_json,
                    persist_session,
                })
                .await
                .map_err(internal)?;
            finish_nonrepeatable_response!(
                remote_operation,
                ctx,
                "set_goal_settings_override",
                Response::Ack
            )
        }

        Request::SetApprovalMode { mode } => {
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) = begin_remote_nonrepeatable(
                    &Request::SetApprovalMode { mode },
                    &authorized_request,
                    operation,
                    ctx,
                )
                .await?
            {
                return Ok(response);
            }
            let mode = att.handle.set_approval_mode(mode);
            let response = Response::ApprovalModeState { mode };
            finish_nonrepeatable_response!(remote_operation, ctx, "set_approval_mode", response)
        }

        Request::SetDelegationRecursion {
            enabled,
            default_depth,
        } => {
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) = begin_remote_nonrepeatable(
                    &Request::SetDelegationRecursion {
                        enabled,
                        default_depth,
                    },
                    &authorized_request,
                    operation,
                    ctx,
                )
                .await?
            {
                return Ok(response);
            }
            att.handle
                .send_work(SessionWork::SetDelegationRecursion {
                    enabled,
                    default_depth,
                })
                .await
                .map_err(internal)?;
            let response = Response::DelegationRecursionState {
                enabled,
                default_depth,
            };
            finish_nonrepeatable_response!(
                remote_operation,
                ctx,
                "set_delegation_recursion",
                response
            )
        }

        Request::SetCaffeinate { mode } => set_caffeinate(state, ctx, mode),

        Request::CancelSchedule { job_id } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::CancelSchedule { job_id })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetSandbox {
            mode,
            container_network_enabled,
        } => {
            // Flip the session's sandbox mode directly (it's a shared
            // atomic) and reply with the resulting state. The handle also
            // broadcasts a `SandboxState` event so every attached client
            // stays in sync.
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::SetSandbox {
                    mode,
                    container_network_enabled,
                };
                if let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
                {
                    return Ok(response);
                }
            }
            let caps = current_host_capability_snapshot(ctx);
            let applied = att
                .handle
                .set_sandbox(mode, container_network_enabled, &caps)
                .map_err(|error| match error {
                    crate::daemon::session_worker::SetSandboxError::CapabilityMissing(missing) => {
                        sandbox_capability_missing(missing)
                    }
                    crate::daemon::session_worker::SetSandboxError::Persist(message) => {
                        internal(message)
                    }
                })?;
            let response = Response::SandboxState {
                mode: applied.effective,
                enabled: applied.effective.enabled(),
                container_network_enabled: att.handle.container_network_enabled(),
                container_availability: crate::container::availability_snapshot(),
                persisted_intent: Some(applied.persisted_intent),
            };
            finish_nonrepeatable_response!(remote_operation, ctx, "set_sandbox", response)
        }

        Request::SetSandboxEscalation { enabled } => {
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) = begin_remote_nonrepeatable(
                    &Request::SetSandboxEscalation { enabled },
                    &authorized_request,
                    operation,
                    ctx,
                )
                .await?
            {
                return Ok(response);
            }
            let enabled = att.handle.set_sandbox_escalation(enabled);
            let response = Response::SandboxEscalationState { enabled };
            finish_nonrepeatable_response!(
                remote_operation,
                ctx,
                "set_sandbox_escalation",
                response
            )
        }

        Request::SetPreflight { enabled } => {
            // `/preflight`: route to the worker, which sets the session-only
            // override on the driver (precedence over config), and broadcasts
            // the resulting state (→ toast + mirror). Session-only — no
            // config-file write.
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) = begin_remote_nonrepeatable(
                    &Request::SetPreflight { enabled },
                    &authorized_request,
                    operation,
                    ctx,
                )
                .await?
            {
                return Ok(response);
            }
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::SetPreflight {
                    enabled,
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let response = Response::PreflightState {
                enabled: response_rx
                    .await
                    .map_err(internal)?
                    .map_err(|error| internal(anyhow::anyhow!(error)))?,
            };
            finish_nonrepeatable_response!(remote_operation, ctx, "set_preflight", response)
        }

        Request::SetLongcache { enabled } => {
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) = begin_remote_nonrepeatable(
                    &Request::SetLongcache { enabled },
                    &authorized_request,
                    operation,
                    ctx,
                )
                .await?
            {
                return Ok(response);
            }
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::SetLongcache {
                    enabled,
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let response = Response::LongcacheState {
                enabled: response_rx
                    .await
                    .map_err(internal)?
                    .map_err(|error| internal(anyhow::anyhow!(error)))?,
            };
            finish_nonrepeatable_response!(remote_operation, ctx, "set_longcache", response)
        }

        Request::SetRedaction {
            scan_environment,
            scan_dotenv,
            scan_ssh_keys,
        } => {
            // `/toggle-redaction`: route to the worker, which mutates the
            // session's effective `RedactConfig` in memory, rebuilds the
            // redaction table for subsequent outbound prompts, and
            // broadcasts the resulting state (→ toast). Session-only — no
            // config-file write. `scrub()` stays non-bypassable.
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::SetRedaction {
                    scan_environment,
                    scan_dotenv,
                    scan_ssh_keys,
                };
                if let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
                {
                    return Ok(response);
                }
            }
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::SetRedaction {
                    scan_environment,
                    scan_dotenv,
                    scan_ssh_keys,
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let (scan_environment, scan_dotenv, scan_ssh_keys) = response_rx
                .await
                .map_err(internal)?
                .map_err(|error| internal(anyhow::anyhow!(error)))?;
            let response = Response::RedactionState {
                scan_environment,
                scan_dotenv,
                scan_ssh_keys,
            };
            finish_nonrepeatable_response!(remote_operation, ctx, "set_redaction", response)
        }

        Request::SetTandemModels { models } => {
            // `/model-comparison`: route to the worker, which builds a
            // completion model for each selected `(provider, model)`, replaces
            // the driver's in-memory tandem set, and broadcasts the resulting
            // state (+ token-burn warning) via `Event::TandemState`.
            // Session-only — no config-file write.
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::SetTandemModels {
                    models: models.clone(),
                };
                if let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
                {
                    return Ok(response);
                }
            }
            att.handle
                .send_work(SessionWork::SetTandemModels { models })
                .await
                .map_err(internal)?;
            finish_nonrepeatable_response!(
                remote_operation,
                ctx,
                "set_tandem_models",
                Response::Ack
            )
        }

        Request::Prune => {
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&Request::Prune, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            att.handle
                .send_work(SessionWork::Prune)
                .await
                .map_err(internal)?;
            finish_nonrepeatable_response!(remote_operation, ctx, "prune", Response::Ack)
        }

        Request::Compact => {
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) = begin_remote_nonrepeatable(
                    &Request::Compact,
                    &authorized_request,
                    operation,
                    ctx,
                )
                .await?
            {
                return Ok(response);
            }
            att.handle
                .send_work(SessionWork::Compact)
                .await
                .map_err(internal)?;
            finish_nonrepeatable_response!(remote_operation, ctx, "compact", Response::Ack)
        }

        Request::Pin { text } => {
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::Pin { text: text.clone() };
                if let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
                {
                    return Ok(response);
                }
            }
            att.handle
                .send_work(SessionWork::Pin { text })
                .await
                .map_err(internal)?;
            finish_nonrepeatable_response!(remote_operation, ctx, "pin", Response::Ack)
        }

        #[cfg(feature = "remote")]
        Request::StoreFlycockpitCredential { credential, force } => {
            let request = Request::StoreFlycockpitCredential {
                credential: credential.clone(),
                force,
            };
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept Flycockpit credential writes",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let _credential_lock = SECRET_OWNER_RPC_LOCK.lock().await;
            if !force && let Some(existing) = ctx.load_flycockpit_credential().map_err(internal)? {
                let response = Response::FlycockpitAlreadyLoggedIn {
                    email: existing.account.email,
                    server_url: existing.server_url,
                };
                return match remote_operation {
                    Some(operation) => {
                        commit_remote_nonrepeatable(
                            operation,
                            ctx,
                            "store_flycockpit_credential",
                            response,
                        )
                        .await
                    }
                    None => Ok(response),
                };
            }
            credential.validate().map_err(internal)?;
            let credential_bytes = serde_json::to_vec(&credential).map_err(internal)?;
            let response = Response::FlycockpitStored;
            let result = match remote_operation {
                Some(operation) => {
                    mutate_owner_vault_item_with_remote_ledger(
                        ctx,
                        operation,
                        cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
                        crate::auth::flycockpit::CREDENTIAL_KEY,
                        Some(&credential_bytes),
                        "store_flycockpit_credential",
                        response,
                        None,
                    )
                    .await
                }
                None => ctx
                    .mutate_owner_vault_item(
                        cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
                        crate::auth::flycockpit::CREDENTIAL_KEY,
                        Some(&credential_bytes),
                    )
                    .map(|()| response)
                    .map_err(internal),
            };
            if result.is_ok() {
                // Mirror the legacy `store_credential_in_store` path: keep the
                // instance token redactable after a successful store. This is
                // a no-op in production (redaction reads the vault directly);
                // it restores the hermetic test seam the owner-RPC store path
                // otherwise bypasses.
                crate::auth::flycockpit::register_credential_for_redaction(&credential);
                ctx.wake_connector();
            }
            result
        }

        #[cfg(feature = "remote")]
        Request::ClearFlycockpitCredential => {
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept Flycockpit credential writes",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) = begin_remote_nonrepeatable(
                    &Request::ClearFlycockpitCredential,
                    &authorized_request,
                    operation,
                    ctx,
                )
                .await?
            {
                return Ok(response);
            }
            let credential = {
                let _credential_lock = SECRET_OWNER_RPC_LOCK.lock().await;
                ctx.load_flycockpit_credential().map_err(internal)?
            };
            let Some(credential) = credential else {
                let response = Response::FlycockpitNotLoggedIn;
                return match remote_operation {
                    Some(operation) => {
                        commit_remote_nonrepeatable(
                            operation,
                            ctx,
                            "clear_flycockpit_credential",
                            response,
                        )
                        .await
                    }
                    None => Ok(response),
                };
            };
            if let Ok(client) =
                crate::auth::flycockpit::FlycockpitClient::new(&credential.server_url)
            {
                match tokio::time::timeout(
                    FLYCOCKPIT_REVOKE_TIMEOUT,
                    client.revoke_instance(&credential),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => tracing::warn!(
                        error = %error,
                        "FlyCockpit credential clear: best-effort instance revoke failed"
                    ),
                    Err(_) => tracing::warn!(
                        timeout_ms = FLYCOCKPIT_REVOKE_TIMEOUT.as_millis(),
                        "FlyCockpit credential clear: best-effort instance revoke timed out"
                    ),
                }
            }
            // The network revoke deliberately runs without the owner-secret
            // lock. A replacement may be stored while it is in flight; never
            // let this clear remove that newer credential.
            let _credential_lock = SECRET_OWNER_RPC_LOCK.lock().await;
            let current = ctx.load_flycockpit_credential().map_err(internal)?;
            if current.as_ref() != Some(&credential) {
                let response = match current {
                    Some(current) => Response::FlycockpitAlreadyLoggedIn {
                        email: current.account.email,
                        server_url: current.server_url,
                    },
                    None => Response::FlycockpitNotLoggedIn,
                };
                return match remote_operation {
                    Some(operation) => {
                        commit_remote_nonrepeatable(
                            operation,
                            ctx,
                            "clear_flycockpit_credential",
                            response,
                        )
                        .await
                    }
                    None => Ok(response),
                };
            }
            let response = Response::FlycockpitCleared {
                server_url: credential.server_url.clone(),
            };
            let result = match remote_operation {
                Some(operation) => {
                    mutate_owner_vault_item_with_remote_ledger(
                        ctx,
                        operation,
                        cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
                        crate::auth::flycockpit::CREDENTIAL_KEY,
                        None,
                        "clear_flycockpit_credential",
                        response,
                        Some(&credential.server_url),
                    )
                    .await
                }
                None => ctx
                    .mutate_owner_vault_item_with_org_sync_disabled(
                        cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
                        crate::auth::flycockpit::CREDENTIAL_KEY,
                        &credential.server_url,
                    )
                    .await
                    .map(|()| response)
                    .map_err(internal),
            };
            if result.is_ok() {
                // Mirror the legacy `clear_credential_in_store` path so a
                // cleared credential stops being redactable in the hermetic
                // test seam (no-op in production).
                crate::auth::flycockpit::clear_credential_redaction_registration();
                ctx.wake_connector();
            }
            result
        }

        #[cfg(feature = "remote")]
        Request::SetFlycockpitConnectorEnabled { enabled } => {
            let request = Request::SetFlycockpitConnectorEnabled { enabled };
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept FlyCockpit connector settings",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let Some(credential) = ctx.load_flycockpit_credential().map_err(internal)? else {
                return Err(bad_request("not logged in to FlyCockpit"));
            };
            ctx.db
                .set_connector_enabled(&credential.server_url, &credential.instance_id, enabled)
                .await
                .map_err(internal)?;
            ctx.wake_connector();
            let response = Response::Ack;
            match remote_operation {
                Some(operation) => {
                    commit_remote_nonrepeatable(
                        operation,
                        ctx,
                        "set_flycockpit_connector_enabled",
                        response,
                    )
                    .await
                }
                None => Ok(response),
            }
        }

        #[cfg(feature = "remote")]
        Request::SyncFlycockpitOrgPolicy => {
            let request = Request::SyncFlycockpitOrgPolicy;
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept FlyCockpit org policy sync",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let outcome = crate::daemon::org_sync::sync_current_credential_once(ctx)
                .await
                .map_err(internal)?;
            let outcome = match outcome {
                crate::daemon::org_sync::OrgSyncOnceOutcome::NoCredential => {
                    proto::FlycockpitOrgSyncOutcome::NoCredential
                }
                crate::daemon::org_sync::OrgSyncOnceOutcome::Disabled => {
                    proto::FlycockpitOrgSyncOutcome::Disabled
                }
                crate::daemon::org_sync::OrgSyncOnceOutcome::EnrollmentRequired { org_id } => {
                    proto::FlycockpitOrgSyncOutcome::EnrollmentRequired { org_id }
                }
                crate::daemon::org_sync::OrgSyncOnceOutcome::Idle => {
                    proto::FlycockpitOrgSyncOutcome::Idle
                }
                crate::daemon::org_sync::OrgSyncOnceOutcome::Filtered { cursor_seq } => {
                    proto::FlycockpitOrgSyncOutcome::Filtered { cursor_seq }
                }
                crate::daemon::org_sync::OrgSyncOnceOutcome::Uploaded { events, cursor_seq } => {
                    proto::FlycockpitOrgSyncOutcome::Uploaded { events, cursor_seq }
                }
                crate::daemon::org_sync::OrgSyncOnceOutcome::Revoked => {
                    proto::FlycockpitOrgSyncOutcome::Revoked
                }
            };
            let response = Response::FlycockpitOrgSync { outcome };
            match remote_operation {
                Some(operation) => {
                    commit_remote_nonrepeatable(
                        operation,
                        ctx,
                        "sync_flycockpit_org_policy",
                        response,
                    )
                    .await
                }
                None => Ok(response),
            }
        }

        #[cfg(feature = "remote")]
        Request::EnrollFlycockpitOrgSync { org_id } => {
            let request = Request::EnrollFlycockpitOrgSync {
                org_id: org_id.clone(),
            };
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept FlyCockpit org sync enrollment",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let Some(credential) = ctx.load_flycockpit_credential().map_err(internal)? else {
                return Err(bad_request("not logged in to FlyCockpit"));
            };
            ctx.db
                .set_org_sync_enrolled(&credential.server_url, &org_id)
                .await
                .map_err(internal)?;
            let response = Response::Ack;
            match remote_operation {
                Some(operation) => {
                    commit_remote_nonrepeatable(
                        operation,
                        ctx,
                        "enroll_flycockpit_org_sync",
                        response,
                    )
                    .await
                }
                None => Ok(response),
            }
        }

        Request::ListSecretInventory { cursor, limit } => {
            let _lock = SECRET_OWNER_RPC_LOCK.lock().await;
            ctx.list_secret_inventory(cursor.as_deref(), limit)
        }

        Request::PutNamedSecret { name, value } => {
            #[cfg(feature = "remote")]
            let request = Request::PutNamedSecret {
                name: name.clone(),
                value: value.clone(),
            };
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept persistent named-secret writes",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let _lock = SECRET_OWNER_RPC_LOCK.lock().await;
            reject_owned_named_secret(ctx, &name).await?;
            #[cfg(feature = "remote")]
            {
                match remote_operation {
                    Some(operation) => {
                        mutate_owner_vault_item_with_remote_ledger(
                            ctx,
                            operation,
                            cockpit_db::secret_vault::SecretVaultKind::NamedSecret,
                            &name,
                            Some(value.as_bytes()),
                            "put_named_secret",
                            Response::Ack,
                            None,
                        )
                        .await
                    }
                    None => {
                        ctx.mutate_owner_vault_item(
                            cockpit_db::secret_vault::SecretVaultKind::NamedSecret,
                            &name,
                            Some(value.as_bytes()),
                        )
                        .map_err(internal)?;
                        Ok(Response::Ack)
                    }
                }
            }
            #[cfg(not(feature = "remote"))]
            {
                ctx.mutate_owner_vault_item(
                    cockpit_db::secret_vault::SecretVaultKind::NamedSecret,
                    &name,
                    Some(value.as_bytes()),
                )
                .map_err(internal)?;
                Ok(Response::Ack)
            }
        }

        Request::PutSubscriptionAck { provider_id } => {
            #[cfg(feature = "remote")]
            let request = Request::PutSubscriptionAck {
                provider_id: provider_id.clone(),
            };
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept persistent subscription acknowledgement writes",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let _lock = SECRET_OWNER_RPC_LOCK.lock().await;
            let item_id = format!("{}{}", crate::auth::subscription_ack::PREFIX, provider_id);
            let payload = serde_json::to_vec(&serde_json::Value::Bool(true)).map_err(internal)?;
            #[cfg(feature = "remote")]
            {
                match remote_operation {
                    Some(operation) => {
                        mutate_owner_vault_item_with_remote_ledger(
                            ctx,
                            operation,
                            cockpit_db::secret_vault::SecretVaultKind::SubscriptionAck,
                            &item_id,
                            Some(&payload),
                            "put_subscription_ack",
                            Response::Ack,
                            None,
                        )
                        .await
                    }
                    None => {
                        ctx.mutate_owner_vault_item(
                            cockpit_db::secret_vault::SecretVaultKind::SubscriptionAck,
                            &item_id,
                            Some(&payload),
                        )
                        .map_err(internal)?;
                        Ok(Response::Ack)
                    }
                }
            }
            #[cfg(not(feature = "remote"))]
            {
                ctx.mutate_owner_vault_item(
                    cockpit_db::secret_vault::SecretVaultKind::SubscriptionAck,
                    &item_id,
                    Some(&payload),
                )
                .map_err(internal)?;
                Ok(Response::Ack)
            }
        }

        Request::DeleteNamedSecret { name } => {
            #[cfg(feature = "remote")]
            let request = Request::DeleteNamedSecret { name: name.clone() };
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept persistent named-secret writes",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let _lock = SECRET_OWNER_RPC_LOCK.lock().await;
            reject_owned_named_secret(ctx, &name).await?;
            #[cfg(feature = "remote")]
            {
                match remote_operation {
                    Some(operation) => {
                        mutate_owner_vault_item_with_remote_ledger(
                            ctx,
                            operation,
                            cockpit_db::secret_vault::SecretVaultKind::NamedSecret,
                            &name,
                            None,
                            "delete_named_secret",
                            Response::Ack,
                            None,
                        )
                        .await
                    }
                    None => {
                        ctx.mutate_owner_vault_item(
                            cockpit_db::secret_vault::SecretVaultKind::NamedSecret,
                            &name,
                            None,
                        )
                        .map_err(internal)?;
                        Ok(Response::Ack)
                    }
                }
            }
            #[cfg(not(feature = "remote"))]
            {
                ctx.mutate_owner_vault_item(
                    cockpit_db::secret_vault::SecretVaultKind::NamedSecret,
                    &name,
                    None,
                )
                .map_err(internal)?;
                Ok(Response::Ack)
            }
        }

        Request::PutProviderCredential {
            provider_id,
            record,
        } => {
            #[cfg(feature = "remote")]
            let request = Request::PutProviderCredential {
                provider_id: provider_id.clone(),
                record: record.clone(),
            };
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept persistent provider credential writes",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let record_value: serde_json::Value = serde_json::from_str(&record).map_err(|_| {
                // Malformed caller-supplied JSON is a client error, not an
                // internal fault. Keep the message field-only so a partially
                // parsed record cannot leak secret bytes through the error.
                bad_request("provider credential record is not valid JSON")
            })?;
            let record_bytes = serde_json::to_vec(&record_value).map_err(internal)?;
            let _lock = SECRET_OWNER_RPC_LOCK.lock().await;
            #[cfg(feature = "remote")]
            {
                match remote_operation {
                    Some(operation) => {
                        mutate_owner_vault_item_with_remote_ledger(
                            ctx,
                            operation,
                            cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
                            &provider_id,
                            Some(&record_bytes),
                            "put_provider_credential",
                            Response::Ack,
                            None,
                        )
                        .await
                    }
                    None => {
                        ctx.mutate_owner_vault_item(
                            cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
                            &provider_id,
                            Some(&record_bytes),
                        )
                        .map_err(internal)?;
                        Ok(Response::Ack)
                    }
                }
            }
            #[cfg(not(feature = "remote"))]
            {
                ctx.mutate_owner_vault_item(
                    cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
                    &provider_id,
                    Some(&record_bytes),
                )
                .map_err(internal)?;
                Ok(Response::Ack)
            }
        }

        Request::BeginProviderOAuth { provider_id } => {
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept persistent provider OAuth logins",
                ));
            }
            let flow_id = uuid::Uuid::new_v4().to_string();
            let owner = oauth_owner(state);
            let (flow, authorize_url, user_code) = match provider_id.as_str() {
                crate::auth::xai_oauth::CREDENTIAL_KEY => {
                    let login = crate::auth::xai_oauth::begin_manual_login()
                        .await
                        .map_err(internal)?;
                    let authorize_url = login.authorize_url.clone();
                    (
                        ProviderOAuthFlow::Ready(ProviderOAuthReady::Grok(login)),
                        authorize_url,
                        None,
                    )
                }
                crate::auth::codex_oauth::CREDENTIAL_KEY => {
                    let login = crate::auth::codex_oauth::begin_device_code_login()
                        .await
                        .map_err(internal)?;
                    let authorize_url = login.verification_uri.clone();
                    let user_code = Some(login.user_code.clone());
                    (
                        ProviderOAuthFlow::Ready(ProviderOAuthReady::Codex(login)),
                        authorize_url,
                        user_code,
                    )
                }
                _ => return Err(bad_request("unsupported provider OAuth flow")),
            };
            ctx.oauth_flows
                .insert_provider(flow_id.clone(), owner, flow)
                .await;
            Ok(Response::ProviderOAuthStarted {
                flow_id,
                authorize_url,
                user_code,
            })
        }

        Request::CompleteProviderOAuth { flow_id, input } => {
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept persistent provider OAuth logins",
                ));
            }
            #[cfg(feature = "remote")]
            let request = Request::CompleteProviderOAuth {
                flow_id: flow_id.clone(),
                input: input.clone(),
            };
            // The durable completion reserves a nonrepeatable remote operation
            // before the one-shot exchange so an authenticated remote owner can
            // retry it idempotently: a replay returns the cached safe response
            // (which carries no token) without re-running the exchange. The PKCE
            // verifier and the exchanged tokens stay server-side / in the vault
            // and never enter the ledger's safe response or any log.
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let mutation = async {
                // Atomically claim the one-shot flow before any provider network
                // exchange. A second concurrent completion therefore fails at
                // lookup instead of issuing another token set. Restore only when
                // validation or the pre-persistence exchange fails; once the
                // provider has exchanged the code, replay must remain rejected.
                let owner = oauth_owner(state);
                let flow = ctx
                    .oauth_flows
                    .take_provider(&flow_id, &owner)
                    .await
                    .ok_or_else(|| {
                        bad_request("provider OAuth flow is unknown or already completed")
                    })?;
                let ready = match flow {
                    ProviderOAuthFlow::Ready(ready) => ready,
                    ProviderOAuthFlow::Completing => {
                        return Err(bad_request("provider OAuth flow is already completing"));
                    }
                };
                let exchange_ready = ready.clone();
                let exchange = match exchange_ready {
                    ProviderOAuthReady::Grok(login) => {
                        let Some(callback) = input.as_deref() else {
                            ctx.oauth_flows
                                .restore_provider(
                                    flow_id,
                                    owner.clone(),
                                    ProviderOAuthFlow::Ready(ProviderOAuthReady::Grok(login)),
                                )
                                .await;
                            return Err(bad_request(
                                "Grok OAuth completion requires a callback URL or code",
                            ));
                        };
                        crate::auth::xai_oauth::complete_manual_login_unpersisted(login, callback)
                            .await
                            .map_err(internal)
                            .and_then(|tokens| {
                                serde_json::to_vec(&tokens)
                                    .map(|record| (crate::auth::xai_oauth::CREDENTIAL_KEY, record))
                                    .map_err(internal)
                            })
                    }
                    ProviderOAuthReady::Codex(login) => {
                        if input.is_some() {
                            ctx.oauth_flows
                                .restore_provider(
                                    flow_id,
                                    owner.clone(),
                                    ProviderOAuthFlow::Ready(ProviderOAuthReady::Codex(login)),
                                )
                                .await;
                            return Err(bad_request(
                                "Codex device OAuth does not accept callback input",
                            ));
                        }
                        crate::auth::codex_oauth::complete_device_code_login_unpersisted(login)
                            .await
                            .map_err(internal)
                            .and_then(|tokens| {
                                serde_json::to_vec(&tokens)
                                    .map(|record| {
                                        (crate::auth::codex_oauth::CREDENTIAL_KEY, record)
                                    })
                                    .map_err(internal)
                            })
                    }
                };
                let (provider_id, record) = match exchange {
                    Ok(value) => value,
                    Err(error) => {
                        ctx.oauth_flows
                            .restore_provider(
                                flow_id,
                                owner.clone(),
                                ProviderOAuthFlow::Ready(ready),
                            )
                            .await;
                        return Err(error);
                    }
                };
                let _lock = SECRET_OWNER_RPC_LOCK.lock().await;
                ctx.mutate_owner_vault_item(
                    cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
                    provider_id,
                    Some(&record),
                )
                .map_err(internal)?;
                // The token record is now durable; consuming the one-time flow
                // prevents a duplicate exchange after a successful completion.
                ctx.oauth_flows.remove_provider(&flow_id, &owner).await;
                Ok(Response::ProviderOAuthCompleted {
                    logged_in: true,
                    retry_after_seconds: None,
                })
            };
            finish_provider_mutation_future!(
                remote_operation,
                ctx,
                "complete_provider_oauth",
                mutation
            )
        }

        Request::BeginMcpOAuth {
            project_root,
            server,
        } => {
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept persistent MCP OAuth logins",
                ));
            }
            // Canonicalize once: the ownership pre-check here, the pending flow's
            // stored root, and the in-transaction guard at `CompleteMcpOAuth` must
            // all key on the same canonical workspace root as later resolution.
            let project_root = crate::secret_ownership::canonical_owner_root(&project_root);
            let cwd = std::path::PathBuf::from(&project_root);
            let trust_policy =
                crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &cwd)
                    .await
                    .map_err(workspace_trust_error)?;
            let paths = daemon_mcp_paths(ctx, &cwd, &trust_policy)?;
            let config = mcp_config_from_paths(&paths)?;
            let server_config = config
                .servers
                .get(&server)
                .ok_or_else(|| bad_request(format!("MCP server `{server}` is not configured")))?;
            if !matches!(server_config.auth, crate::mcp::config::Auth::Oauth(_)) {
                return Err(bad_request(format!(
                    "MCP server `{server}` is not configured for OAuth"
                )));
            }
            ensure_mcp_ownership_available(
                ctx,
                &project_root,
                [crate::mcp::auth::cred_key(&server)],
            )
            .await?;
            // Only a LOCAL owner may have the daemon open a host browser and
            // bind a host loopback listener for the callback. For a remote
            // caller the daemon returns the authorize URL only (no browser, no
            // listener); the remote client presents it and returns the callback
            // code over `CompleteMcpOAuth`. `is_local_owner_action` derives this
            // from daemon-assigned signals the caller cannot forge.
            let local_display = is_local_owner_action(
                state,
                #[cfg(feature = "remote")]
                remote_operation,
            );
            let (flow, authorize_url) =
                crate::mcp::auth::begin_oauth_flow(&server, server_config, local_display)
                    .await
                    .map_err(internal)?;
            let flow_id = uuid::Uuid::new_v4().to_string();
            ctx.oauth_flows
                .insert_mcp(
                    flow_id.clone(),
                    oauth_owner(state),
                    McpOAuthPending {
                        project_root,
                        server,
                        flow,
                    },
                )
                .await;
            Ok(Response::McpOAuthStarted {
                flow_id,
                authorize_url,
            })
        }

        Request::CompleteMcpOAuth { flow_id, input } => {
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept persistent MCP OAuth logins",
                ));
            }
            #[cfg(feature = "remote")]
            let request = Request::CompleteMcpOAuth {
                flow_id: flow_id.clone(),
                input: input.clone(),
            };
            // Durable MCP OAuth completion: reserve a nonrepeatable remote
            // operation before the one-shot exchange so a remote owner can retry
            // idempotently (a replay returns the cached, token-free safe
            // response). The exchanged tokens are staged into the vault inside
            // the BEGIN IMMEDIATE transaction below and never enter the ledger
            // safe response or any log.
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let mutation = async {
                let owner = oauth_owner(state);
                let pending = ctx
                    .oauth_flows
                    .take_mcp(&flow_id, &owner)
                    .await
                    .ok_or_else(|| bad_request("MCP OAuth flow is unknown or already completed"))?;
                // Once claimed, this flow is one-shot. A provider exchange may have
                // consumed its authorization code even if vault persistence fails,
                // so it must not be reinserted for a second exchange.
                let tokens = crate::mcp::auth::complete_oauth_flow(pending.flow, input.as_deref())
                    .await
                    .map_err(internal)?;
                let record = serde_json::to_vec(&tokens).map_err(internal)?;
                let _lock = SECRET_OWNER_RPC_LOCK.lock().await;
                let credential_key = crate::mcp::auth::cred_key(&pending.server);
                let owner_root = pending.project_root.clone();
                let vault = ctx.secret_vault.clone();
                ctx.db
                    .transaction(move |conn| {
                        // ATOMIC cross-kind admission for the flow-managed OAuth
                        // token key. The `ensure_mcp_ownership_available` check ran
                        // back at `StartMcpOAuth`; a provider (or another workspace)
                        // could have claimed `mcp:<server>` during the OAuth round
                        // trip. Re-check INSIDE this `BEGIN IMMEDIATE` transaction so
                        // the completion cannot overwrite a foreign-owned secret. A
                        // conflict fails closed (the token must be re-authorized)
                        // rather than clobbering another owner's live value.
                        reject_conflicting_named_ownership_on_conn(
                            conn,
                            &credential_key,
                            "mcp",
                            &owner_root,
                        )?;
                        vault
                            .mutate_item_on_conn(
                                conn,
                                cockpit_db::secret_vault::SecretVaultKind::NamedSecret,
                                &credential_key,
                                Some(&record),
                            )
                            .map_err(|error| anyhow::anyhow!(error))?;
                        conn.execute(
                            "INSERT OR IGNORE INTO secret_named_ownership
                         (item_id, owner_kind, project_root, created_at)
                         VALUES (?1, 'mcp', ?2, ?3)",
                            rusqlite::params![
                                credential_key,
                                owner_root,
                                chrono::Utc::now().timestamp_millis()
                            ],
                        )?;
                        Ok(())
                    })
                    .await
                    .map_err(map_named_secret_tx_error)?;
                if let Err(error) = ctx.publish_owner_redaction_table() {
                    // Vault + ownership are committed. The exchange is one-shot,
                    // so rollback could orphan the already-authorized token;
                    // poison and fail closed until the daemon is restarted.
                    ctx.poison_redaction_publication(&error);
                    return Err(internal(error));
                }
                Ok(Response::McpOAuthCompleted {
                    authenticated: true,
                })
            };
            finish_provider_mutation_future!(remote_operation, ctx, "complete_mcp_oauth", mutation)
        }

        Request::CancelMcpOAuth { flow_id } => {
            let owner = oauth_owner(state);
            let cancelled = ctx.oauth_flows.remove_mcp(&flow_id, &owner).await;
            Ok(Response::McpOAuthCancelled { cancelled })
        }

        Request::DeleteProviderCredential {
            provider_id,
            project_root,
        } => {
            #[cfg(feature = "remote")]
            let request = Request::DeleteProviderCredential {
                provider_id: provider_id.clone(),
                project_root: project_root.clone(),
            };
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept persistent provider credential writes",
                ));
            }
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let _config_lock = CONFIG_PUBLICATION_RPC_LOCK.lock().await;
            if let Some(root) = project_root.as_deref() {
                recover_provider_config_journals(ctx, root, Some(&provider_id)).await?;
            }
            let _lock = SECRET_OWNER_RPC_LOCK.lock().await;
            // A CLI identifies a configured provider, never a hidden vault
            // record name. Resolve that reference only inside the daemon so a
            // custom OAuth provider cannot delete an unrelated record. The
            // direct (`project_root: None`) path is the owner-settings mirror
            // of `PutProviderCredential`: the owner supplies the raw vault
            // record id and receives a plain `Ack`.
            let (credential_record_id, response) = if let Some(project_root) =
                project_root.as_deref()
            {
                let (_, _, config) = daemon_provider_config(ctx, project_root).await?;
                let provider = config.providers.get(&provider_id).ok_or_else(|| {
                    bad_request(format!("provider `{provider_id}` is not configured"))
                })?;
                if provider.auth != Some(crate::config::providers::AuthKind::OAuth) {
                    return Err(bad_request(
                        "provider credential logout is only available for OAuth providers",
                    ));
                }
                let credential_record_id = provider.credential_ref.clone().ok_or_else(|| {
                    bad_request(format!("provider `{provider_id}` has no credential_ref"))
                })?;
                let credential_present = ctx
                    .secret_vault
                    .get_item(
                        cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
                        &credential_record_id,
                    )
                    .is_ok();
                (
                    credential_record_id,
                    Response::ProviderCredentialDeleted {
                        found: credential_present,
                        deleted: credential_present,
                    },
                )
            } else {
                (provider_id.clone(), Response::Ack)
            };
            #[cfg(feature = "remote")]
            {
                match remote_operation {
                    Some(operation) => {
                        mutate_owner_vault_item_with_remote_ledger(
                            ctx,
                            operation,
                            cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
                            &credential_record_id,
                            None,
                            "delete_provider_credential",
                            response,
                            None,
                        )
                        .await
                    }
                    None => {
                        ctx.mutate_owner_vault_item(
                            cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
                            &credential_record_id,
                            None,
                        )
                        .map_err(internal)?;
                        Ok(response)
                    }
                }
            }
            #[cfg(not(feature = "remote"))]
            {
                ctx.mutate_owner_vault_item(
                    cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
                    &credential_record_id,
                    None,
                )
                .map_err(internal)?;
                Ok(response)
            }
        }

        #[cfg(feature = "remote")]
        Request::GetFlycockpitAccount => ctx
            .flycockpit_account_view()
            .map(|account| Response::FlycockpitAccount { account })
            .map_err(internal),

        Request::GetProviderCatalogSnapshot {
            project_root,
            provider_id,
        } => provider_catalog_snapshot(ctx, &project_root, provider_id.as_deref()).await,

        Request::FetchProviderModels {
            project_root,
            provider_id,
            model_id,
            deep,
            on_unlisted,
            allow_fallback,
        } => {
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept provider model fetches that persist config",
                ));
            }
            #[cfg(feature = "remote")]
            let request = Request::FetchProviderModels {
                project_root: project_root.clone(),
                provider_id: provider_id.clone(),
                model_id: model_id.clone(),
                deep,
                on_unlisted,
                allow_fallback,
            };
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let mutation = provider_models_fetch(
                ctx,
                &project_root,
                provider_id.as_deref(),
                model_id.as_deref(),
                deep,
                on_unlisted,
                allow_fallback,
                provider_env_snapshot(ctx, state),
            );
            finish_provider_mutation_future!(
                remote_operation,
                ctx,
                "fetch_provider_models",
                mutation
            )
        }

        Request::GetProviderUsageSnapshot {
            project_root,
            provider_id,
        } => {
            provider_usage_snapshot(
                ctx,
                &project_root,
                provider_id.as_deref(),
                provider_env_snapshot(ctx, state),
            )
            .await
        }

        Request::UpsertProviderConfig {
            project_root,
            provider_id,
            entry,
        } => {
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept provider config writes",
                ));
            }
            #[cfg(feature = "remote")]
            let request = Request::UpsertProviderConfig {
                project_root: project_root.clone(),
                provider_id: provider_id.clone(),
                entry: entry.clone(),
            };
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let mutation = provider_config_upsert(ctx, &project_root, &provider_id, entry);
            finish_provider_mutation_future!(
                remote_operation,
                ctx,
                "upsert_provider_config",
                mutation
            )
        }

        Request::SaveProviderConfig {
            project_root,
            provider_id,
            entry,
            header_secrets,
        } => {
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept provider config writes",
                ));
            }
            #[cfg(feature = "remote")]
            let request = Request::SaveProviderConfig {
                project_root: project_root.clone(),
                provider_id: provider_id.clone(),
                entry: entry.clone(),
                header_secrets: header_secrets.clone(),
            };
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let mutation =
                provider_config_save(ctx, &project_root, &provider_id, entry, header_secrets);
            let result = finish_provider_mutation_future!(
                remote_operation,
                ctx,
                "save_provider_config",
                mutation
            );
            // Invalidate + re-resolve the command secrets this provider
            // references AFTER the save completes and its config-publication lock
            // is released (so a slow, up-to-30s subprocess never blocks other
            // config-publication RPCs; inc1's generation fencing keeps a stale
            // in-flight result from being injected). The reference set is read
            // from the EFFECTIVE post-save entry — NOT the caller's request entry,
            // whose masked `********` headers hide a preserved `$secret:cmd` that
            // `provider_config_save` restores internally — and scoped to THIS
            // provider (a sibling's reference is never re-executed by an unrelated
            // save). A referencing update re-execs exactly once more; an
            // unreferenced update execs zero times
            // (`provider_update_invalidation_reexecutes_once`).
            //
            // NOTE: a provider header can only statically reference a `$secret:`
            // name backed by a `NamedSecret` vault row (the atomic
            // `ensure_static_named_reference_owned_on_conn` check). A COMMAND-kind
            // secret has no such row, so a provider that references a command
            // secret is not saveable until inc4 extends that validation and the
            // put-command-spec RPC. This re-resolution is therefore correct and
            // forward-compatible; the resolution semantics themselves are covered
            // now by the registry-level `provider_update_invalidation_reexecutes_once`.
            if result.is_ok()
                && let Ok((_, _, effective)) = daemon_provider_config(ctx, &project_root).await
                && let Some(saved_entry) = effective.providers.get(&provider_id)
            {
                let saved_command_refs: std::collections::BTreeSet<String> = saved_entry
                    .headers
                    .iter()
                    .flat_map(|header| crate::envref::referenced_names(&header.value))
                    .filter_map(|name| name.strip_prefix("secret:").map(str::to_string))
                    .collect();
                ctx.registry
                    .resolve_provider_command_secrets(&project_root, &saved_command_refs, true)
                    .await;
            }
            result
        }

        Request::SetupCopilotAuth {
            project_root,
            provider_id,
        } => {
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept Copilot auth setup",
                ));
            }
            #[cfg(feature = "remote")]
            let request = Request::SetupCopilotAuth {
                project_root: project_root.clone(),
                provider_id: provider_id.clone(),
            };
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            // A local unix-socket owner (`ClientPrincipal::Owner`, no
            // remote-operation ledger context) may adopt the host's ambient
            // GitHub token; any remote caller is failed closed inside
            // `setup_copilot_auth`. `is_local_owner` is derived only from
            // daemon-assigned signals — see `is_local_owner_action`.
            let is_local_owner = is_local_owner_action(
                state,
                #[cfg(feature = "remote")]
                remote_operation,
            );
            let operation_result = setup_copilot_auth(
                ctx,
                &project_root,
                &provider_id,
                provider_env_snapshot(ctx, state),
                is_local_owner,
            )
            .await;
            let operation_result = operation_result.map(|_| Response::Ack);
            finish_provider_mutation_future!(remote_operation, ctx, "setup_copilot_auth", async {
                operation_result
            })
        }

        Request::ApplySetupWizard {
            project_root,
            wizard_id,
            answers_json,
        } => {
            #[cfg(feature = "remote")]
            let request = Request::ApplySetupWizard {
                project_root: project_root.clone(),
                wizard_id: wizard_id.clone(),
                answers_json: answers_json.clone(),
            };
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let mutation = async {
                let result = crate::wizard::apply_setup_wizard_answers_authoritative(
                    std::path::Path::new(&project_root),
                    &wizard_id,
                    &answers_json,
                )
                .await
                .map_err(internal)?;
                Ok(Response::SetupWizardApplied {
                    changed: result.0,
                    model_file_written: result.1,
                    default_scope: result.2,
                })
            };
            finish_provider_mutation_future!(remote_operation, ctx, "apply_setup_wizard", mutation)
        }

        Request::SaveMcpConfig {
            project_root,
            config_json,
            secret_values_json,
            cleanup_names_json,
        } => {
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept MCP config writes",
                ));
            }
            #[cfg(feature = "remote")]
            let request = Request::SaveMcpConfig {
                project_root: project_root.clone(),
                config_json: config_json.clone(),
                secret_values_json: secret_values_json.clone(),
                cleanup_names_json: cleanup_names_json.clone(),
            };
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let operation_result = save_mcp_config(
                ctx,
                &project_root,
                &config_json,
                &secret_values_json,
                &cleanup_names_json,
            );
            finish_provider_mutation_future!(
                remote_operation,
                ctx,
                "save_mcp_config",
                operation_result
            )
        }

        Request::DeleteProviderConfig {
            project_root,
            provider_id,
            delete_stored_secrets,
        } => {
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept provider config writes",
                ));
            }
            #[cfg(feature = "remote")]
            let request = Request::DeleteProviderConfig {
                project_root: project_root.clone(),
                provider_id: provider_id.clone(),
                delete_stored_secrets,
            };
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let mutation =
                provider_config_delete(ctx, &project_root, &provider_id, delete_stored_secrets);
            finish_provider_mutation_future!(
                remote_operation,
                ctx,
                "delete_provider_config",
                mutation
            )
        }

        Request::SetProviderLayerMetadata {
            project_root,
            category_defaults_json,
            on_unlisted_models_fetch,
        } => {
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept provider metadata writes",
                ));
            }
            #[cfg(feature = "remote")]
            let request = Request::SetProviderLayerMetadata {
                project_root: project_root.clone(),
                category_defaults_json: category_defaults_json.clone(),
                on_unlisted_models_fetch,
            };
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
            {
                return Ok(response);
            }
            let mutation = provider_layer_metadata_set(
                ctx,
                &project_root,
                category_defaults_json,
                on_unlisted_models_fetch,
            );
            finish_provider_mutation_future!(
                remote_operation,
                ctx,
                "set_provider_layer_metadata",
                mutation
            )
        }

        Request::DaemonStatus => Ok(Response::DaemonStatus {
            pid: std::process::id(),
            uptime_secs: ctx.started_at.elapsed().as_secs(),
            active_sessions: ctx.registry.active_session_ids().len() as u32,
            socket_path: ctx.paths.socket.display().to_string(),
            daemon_version: proto::DAEMON_VERSION.to_string(),
            protocol_version: proto::PROTOCOL_VERSION,
            paused_sessions: ctx
                .db
                .paused_session_work_all()
                .await
                .map_err(internal)?
                .len() as u32,
            database_path: ctx
                .db
                .path()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<in-memory>".to_string()),
            schema_version: ctx.db.schema_version().await.map_err(internal)?,
        }),

        Request::RefreshEnv { vars } => {
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation {
                let request = Request::RefreshEnv { vars: vars.clone() };
                if let Some(response) =
                    begin_remote_nonrepeatable(&request, &authorized_request, operation, ctx)
                        .await?
                {
                    return Ok(response);
                }
            }
            att.handle.set_env_overlay(vars);
            finish_nonrepeatable_response!(remote_operation, ctx, "refresh_env", Response::Ack)
        }

        Request::RefreshConfig => {
            let att = require_attached(state)?;
            #[cfg(feature = "remote")]
            if let Some(operation) = remote_operation
                && let Some(response) = begin_remote_nonrepeatable(
                    &Request::RefreshConfig,
                    &authorized_request,
                    operation,
                    ctx,
                )
                .await?
            {
                return Ok(response);
            }
            let refreshed = crate::daemon::config_refresh::refresh_session_config_explicit(
                &ctx.db,
                ctx.config_source(),
                &att.handle,
            )
            .await
            .map_err(explicit_config_refresh_error)?;
            let response = Response::ConfigRefreshed {
                applied_generation: refreshed.applied_generation,
                changed: refreshed.changed,
            };
            finish_nonrepeatable_response!(remote_operation, ctx, "refresh_config", response)
        }

        Request::RecordUsage {
            kind,
            key,
            project_id,
        } => {
            if key.trim().is_empty() {
                return Err(bad_request("usage key cannot be empty"));
            }
            // Global tally — no attached session required.
            ctx.db
                .record_usage(
                    kind.as_str(),
                    &key,
                    project_id.as_deref(),
                    chrono::Utc::now().timestamp(),
                )
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::GetUsageCounts { project_id } => {
            let since = chrono::Utc::now().timestamp() - crate::db::usage_events::USAGE_WINDOW_SECS;
            let models = ctx
                .db
                .usage_counts("model", None, since)
                .await
                .map_err(internal)?;
            let slash = ctx
                .db
                .usage_counts("slash", None, since)
                .await
                .map_err(internal)?;
            // Tags are per-project; with no project there's nothing to
            // scope to, so the map is empty rather than a global mash-up.
            let tags = match project_id.as_deref() {
                Some(pid) => ctx
                    .db
                    .usage_counts("tag", Some(pid), since)
                    .await
                    .map_err(internal)?,
                None => std::collections::HashMap::new(),
            };
            Ok(Response::UsageCounts {
                models,
                slash,
                tags,
            })
        }

        Request::StatsRollup {
            project_id,
            range,
            by_role,
        } => stats_rollup(ctx, project_id, range, by_role).await,

        Request::GuidanceEstimate {
            project_root,
            provider,
            model,
        } => {
            // Resolve the single guidance file the engine would load and
            // estimate, with the calibrated tokenizer for the active model
            // (cl100k fallback when uncalibrated), two figures: the
            // guidance-file body (the `… in <file>` label) and the full
            // composed system prompt (the fresh-context baseline the
            // running estimate folds in). No session exists yet at the
            // fresh-chat indicator, so the system prompt omits the
            // `Session:` line — matching what the engine then sends.
            let cwd = Path::new(&project_root);
            let (strategy, scale) = ctx
                .db
                .resolve_tokenizer(
                    provider.as_deref().unwrap_or(""),
                    model.as_deref().unwrap_or(""),
                )
                .await;
            let strategy = crate::tokens::calibration_strategy_from_persisted(strategy.as_str());
            let system_prompt = crate::engine::builtin::default_chat_system_prompt(cwd, "");
            let system_tokens = crate::tokens::scaled_estimate(&system_prompt, strategy, scale);
            let model_instruction_tokens = provider
                .as_deref()
                .zip(model.as_deref())
                .and_then(|(provider, model)| {
                    let (cfg, _) = ctx.config_source().load(cwd).ok()?;
                    cfg.resolve_model_system_prompt(provider, model)
                        .map(|prompt| crate::tokens::scaled_estimate(prompt, strategy, scale))
                })
                .unwrap_or(0);
            match crate::engine::builtin::load_agent_guidance(cwd) {
                Some((path, body)) => {
                    let tokens = crate::tokens::scaled_estimate(&body, strategy, scale);
                    let file = path.file_name().map(|n| n.to_string_lossy().into_owned());
                    Ok(Response::GuidanceEstimate {
                        file,
                        tokens,
                        system_tokens,
                        model_instruction_tokens,
                    })
                }
                None => Ok(Response::GuidanceEstimate {
                    file: None,
                    tokens: 0,
                    system_tokens,
                    model_instruction_tokens,
                }),
            }
        }

        Request::StopDaemon { grace_secs } => {
            tracing::info!(?grace_secs, "StopDaemon requested via client");
            if let Some(secs) = grace_secs {
                ctx.set_shutdown_grace_override(std::time::Duration::from_secs(secs));
            }
            effects.shutdown_after_response = true;
            Ok(Response::Ack)
        }
        Request::GetHostCapabilities => get_host_capabilities(ctx),
        Request::RefreshHostCapabilities => refresh_host_capabilities_request(ctx).await,
        Request::MigrateKekPlacement { dest } => migrate_kek_placement_request(ctx, dest).await,
        Request::RestartIfIdle => {
            tracing::info!("RestartIfIdle requested via client");
            let _decision = crate::sync::lock_or_recover(&ctx.restart_decision);
            if ctx.shutdown.is_draining() {
                return Ok(Response::RestartDecision {
                    will_restart: false,
                    reason: Some("already shutting down".to_string()),
                });
            }
            if ctx.registry.any_agent_running() {
                return Ok(Response::RestartDecision {
                    will_restart: false,
                    reason: Some("a session is busy".to_string()),
                });
            }
            request_shutdown(ctx);
            Ok(Response::RestartDecision {
                will_restart: true,
                reason: None,
            })
        }
        Request::RecoverSecurityBlockedMedia(request) => {
            use sha2::{Digest as _, Sha256};
            let expected_owner = super::run_invocation::principal_digest(&state.principal);
            if request.owner_principal_digest != expected_owner {
                return Err(authorization_error(
                    "media recovery owner binding is invalid",
                ));
            }
            let recovery = ctx
                .media_storage_recovery
                .as_ref()
                .ok_or_else(|| ErrorPayload {
                    code: ErrorCode::Internal,
                    message: "media storage authority is unavailable".into(),
                })?;
            let att = require_attached(state).map_err(|_| ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "media_attachment_unavailable".into(),
            })?;
            let project_text = att
                .handle
                .project_root
                .to_str()
                .ok_or_else(|| ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: "media_attachment_unavailable".into(),
                })?;
            let project_digest = crate::intel::hex_lower(&Sha256::digest(project_text.as_bytes()));
            let receipt = recovery
                .recover(
                    request,
                    att.handle.session_id,
                    project_digest,
                    None,
                    chrono::Utc::now().timestamp_millis(),
                )
                .await
                .map_err(|error| {
                    if error
                        .to_string()
                        .contains("security-blocked media attachment unavailable")
                    {
                        ErrorPayload {
                            code: ErrorCode::BadRequest,
                            message: "media_attachment_unavailable".into(),
                        }
                    } else {
                        internal(error)
                    }
                })?;
            Ok(Response::MediaOwnerRecovery(receipt))
        }
        Request::RegisterLocalPathMedia(request) => {
            use sha2::{Digest as _, Sha256};
            let unavailable = || ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "media_attachment_unavailable".into(),
            };
            let attached = require_attached(state).map_err(|_| unavailable())?;
            let owner = super::run_invocation::principal_digest(&state.principal);
            let project_text = attached
                .handle
                .project_root
                .to_str()
                .ok_or_else(unavailable)?;
            let project_digest = crate::intel::hex_lower(&Sha256::digest(project_text.as_bytes()));
            if request.owner_principal_digest != owner
                || request.session_id != attached.handle.session_id
                || request.canonical_project_digest != project_digest
            {
                return Err(unavailable());
            }
            let recovery = ctx
                .media_storage_recovery
                .as_ref()
                .ok_or_else(|| ErrorPayload {
                    code: ErrorCode::Internal,
                    message: "media storage authority is unavailable".into(),
                })?;
            let (_, extended) = ctx
                .config_source
                .load_effective_for_daemon(
                    &attached.handle.project_root,
                    &attached.handle.trust_policy,
                )
                .map_err(internal)?;
            let receipt = recovery
                .register_local_path(
                    request,
                    &attached.handle.project_root,
                    &extended.media_resources,
                    ctx.media_ledger.clock_now_ms(),
                    chrono::Utc::now().timestamp_millis(),
                )
                .await
                .map_err(|error| {
                    let text = error.to_string();
                    if text.contains("media_attachment_unavailable") {
                        unavailable()
                    } else if text.contains("idempotency_conflict") {
                        ErrorPayload {
                            code: ErrorCode::Conflict,
                            message: "idempotency_conflict".into(),
                        }
                    } else {
                        internal(error)
                    }
                })?;
            Ok(Response::LocalPathMediaRegistration(receipt))
        }
        Request::RetainHttpsMedia(request) => {
            use sha2::{Digest as _, Sha256};
            let unavailable = || ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "media_attachment_unavailable".into(),
            };
            let attached = require_attached(state).map_err(|_| unavailable())?;
            let owner = super::run_invocation::principal_digest(&state.principal);
            let project_text = attached
                .handle
                .project_root
                .to_str()
                .ok_or_else(unavailable)?;
            let project_digest = crate::intel::hex_lower(&Sha256::digest(project_text.as_bytes()));
            if request.schema_version != 1
                || request.kind != "retainHttpsMedia"
                || request.owner_principal_digest != owner
                || request.session_id != attached.handle.session_id
                || request.canonical_project_digest != project_digest
            {
                return Err(unavailable());
            }
            let recovery = ctx
                .media_storage_recovery
                .as_ref()
                .ok_or_else(unavailable)?;
            let (_, extended) = ctx
                .config_source
                .load_effective_for_daemon(
                    &attached.handle.project_root,
                    &attached.handle.trust_policy,
                )
                .map_err(internal)?;
            let receipt = recovery
                .retain_https_media(
                    request,
                    &extended.media_resources,
                    ctx.media_ledger.clock_now_ms(),
                    chrono::Utc::now().timestamp_millis(),
                )
                .await
                .map_err(|error| {
                    if error.to_string().contains("idempotency_conflict") {
                        ErrorPayload {
                            code: ErrorCode::Conflict,
                            message: "idempotency_conflict".into(),
                        }
                    } else {
                        internal(error)
                    }
                })?;
            recovery
                .process_retained_https_jobs(chrono::Utc::now().timestamp_millis())
                .await
                .map_err(internal)?;
            Ok(Response::RetainedHttpsMedia(receipt))
        }
        Request::GetMediaAttachmentStatus(request) => {
            use sha2::{Digest as _, Sha256};
            let unavailable = || ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "media_attachment_unavailable".into(),
            };
            authorize_session_row_reader(&state.principal, ctx, request.session_id)
                .await
                .map_err(|_| unavailable())?;
            let attached = require_attached(state).map_err(|_| unavailable())?;
            let project_text = attached
                .handle
                .project_root
                .to_str()
                .ok_or_else(unavailable)?;
            let project_digest = crate::intel::hex_lower(&Sha256::digest(project_text.as_bytes()));
            if request.session_id != attached.handle.session_id
                || request.canonical_project_digest != project_digest
            {
                return Err(unavailable());
            }
            let status = ctx
                .db
                .read(move |conn| {
                    cockpit_db::Db::media_attachment_status_for_owner_conn(conn, &request)
                })
                .await
                .map_err(internal)?
                .ok_or_else(unavailable)?;
            Ok(Response::MediaAttachmentStatus(status))
        }
        Request::GetMediaAttachmentPreview(request) => {
            use cockpit_db::media_attachments::{
                GetMediaAttachmentStatusV1, MediaAttachmentPreviewV1,
                MediaAttachmentStatusDetailV1, MediaComponentLeaseKind,
            };
            use sha2::{Digest as _, Sha256};
            let unavailable = || ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "media_attachment_unavailable".into(),
            };
            if request.schema_version != 1
                || request.kind != "getMediaAttachmentPreview"
                || request.attachment_version == 0
                || request.availability_generation == 0
                || request.preview_generation == 0
            {
                return Err(unavailable());
            }
            authorize_session_row_reader(&state.principal, ctx, request.session_id)
                .await
                .map_err(|_| unavailable())?;
            let attached = require_attached(state).map_err(|_| unavailable())?;
            let project_text = attached
                .handle
                .project_root
                .to_str()
                .ok_or_else(unavailable)?;
            let project_digest = crate::intel::hex_lower(&Sha256::digest(project_text.as_bytes()));
            if request.session_id != attached.handle.session_id
                || request.canonical_project_digest != project_digest
                || request.preview_checksum.len() != 64
                || request
                    .preview_checksum
                    .bytes()
                    .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
            {
                return Err(unavailable());
            }
            let status_request = GetMediaAttachmentStatusV1 {
                schema_version: 1,
                kind: "getMediaAttachmentStatus".into(),
                session_id: request.session_id,
                canonical_project_digest: request.canonical_project_digest.clone(),
                attachment_id: request.attachment_id,
            };
            let (status, capability) = ctx
                .db
                .read(move |conn| {
                    let status = cockpit_db::Db::media_attachment_status_for_owner_conn(
                        conn,
                        &status_request,
                    )?
                    .context("media_attachment_unavailable")?;
                    let record = cockpit_db::Db::media_attachment_for_owner_conn(
                        conn,
                        status_request.attachment_id,
                        status_request.session_id,
                        &status_request.canonical_project_digest,
                    )?
                    .context("media_attachment_unavailable")?;
                    Ok((status, record.captured_capability_generation))
                })
                .await
                .map_err(|_| unavailable())?;
            let MediaAttachmentStatusDetailV1::Ready {
                preview: Some(preview),
                ..
            } = status.detail
            else {
                return Err(unavailable());
            };
            if status.attachment_version != request.attachment_version
                || status.availability_generation != request.availability_generation
                || preview.generation != request.preview_generation
                || preview.checksum != request.preview_checksum
                || preview.byte_length > 524_288
            {
                return Err(unavailable());
            }
            let storage = ctx
                .media_storage_recovery
                .as_ref()
                .ok_or_else(unavailable)?;
            let now = chrono::Utc::now().timestamp_millis();
            let lease = storage
                .acquire_component_lease(crate::media_storage::AcquireComponentLeaseInput {
                    lease_id: Uuid::now_v7(),
                    attachment_id: request.attachment_id,
                    attachment_version: request.attachment_version,
                    availability_generation: request.availability_generation,
                    capability_generation: capability,
                    kind: MediaComponentLeaseKind::Preview,
                    now_unix_ms: now,
                })
                .await
                .map_err(|_| unavailable())?;
            let body = lease.read_verified(now).await.map_err(|_| unavailable())?;
            if body.len() as u64 != preview.byte_length || !body.starts_with(b"\x89PNG\r\n\x1a\n") {
                return Err(unavailable());
            }
            Ok(Response::MediaAttachmentPreview(MediaAttachmentPreviewV1 {
                schema_version: 1,
                kind: "mediaAttachmentPreview".into(),
                content_type: "image/png".into(),
                cache_control: "no-store, private".into(),
                x_content_type_options: "nosniff".into(),
                content_length: body.len() as u64,
                body,
            }))
        }
        Request::BeginMediaUpload(request) => {
            use cockpit_db::media_attachments::{
                LocalMediaActorRoleV1, LocalMediaMutationPayloadV1,
            };
            use sha2::{Digest as _, Sha256};
            let unavailable = || ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "media_attachment_unavailable".into(),
            };
            let LocalMediaMutationPayloadV1::Begin {
                session_id,
                canonical_project_digest,
                ..
            } = &request.payload
            else {
                return Err(bad_request("media upload action mismatch"));
            };
            let access = ctx
                .db
                .get_session(*session_id)
                .await
                .map_err(internal)?
                .map(|row| session_access_for_row(&state.principal, &row))
                .ok_or_else(unavailable)?;
            let expected_role = match access {
                SessionAccess::Owner => LocalMediaActorRoleV1::Owner,
                SessionAccess::Writer => LocalMediaActorRoleV1::Writer,
                _ => return Err(unavailable()),
            };
            let attached = require_attached(state).map_err(|_| unavailable())?;
            let project_text = attached
                .handle
                .project_root
                .to_str()
                .ok_or_else(unavailable)?;
            let project_digest = crate::intel::hex_lower(&Sha256::digest(project_text.as_bytes()));
            if *session_id != attached.handle.session_id
                || *canonical_project_digest != project_digest
                || request.actor_role != expected_role
                || request.actor_principal_digest
                    != super::run_invocation::principal_digest(&state.principal)
            {
                return Err(unavailable());
            }
            let (_, extended) = ctx
                .config_source
                .load_effective_for_daemon(
                    &attached.handle.project_root,
                    &attached.handle.trust_policy,
                )
                .map_err(internal)?;
            let recovery = ctx
                .media_storage_recovery
                .as_ref()
                .ok_or_else(|| internal("media storage authority is unavailable"))?;
            let receipt = recovery
                .begin_media_upload(
                    request,
                    &extended.media_resources,
                    ctx.media_ledger.clock_now_ms(),
                    chrono::Utc::now().timestamp_millis(),
                )
                .await
                .map_err(|error| {
                    let text = error.to_string();
                    if text.contains("conflict") {
                        ErrorPayload {
                            code: ErrorCode::Conflict,
                            message: text,
                        }
                    } else {
                        internal(error)
                    }
                })?;
            Ok(Response::LocalMediaMutation(receipt))
        }
        Request::AppendMediaUploadChunk(request) => {
            use cockpit_db::media_attachments::{
                LocalMediaActorRoleV1, LocalMediaMutationPayloadV1,
            };
            use sha2::{Digest as _, Sha256};
            let unavailable = || ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "media_attachment_unavailable".into(),
            };
            let LocalMediaMutationPayloadV1::Append {
                session_id,
                canonical_project_digest,
                ..
            } = &request.mutation.payload
            else {
                return Err(bad_request("media upload action mismatch"));
            };
            let access = ctx
                .db
                .get_session(*session_id)
                .await
                .map_err(internal)?
                .map(|row| session_access_for_row(&state.principal, &row))
                .ok_or_else(unavailable)?;
            let role = match access {
                SessionAccess::Owner => LocalMediaActorRoleV1::Owner,
                SessionAccess::Writer => LocalMediaActorRoleV1::Writer,
                _ => return Err(unavailable()),
            };
            let attached = require_attached(state).map_err(|_| unavailable())?;
            let text = attached
                .handle
                .project_root
                .to_str()
                .ok_or_else(unavailable)?;
            let digest = crate::intel::hex_lower(&Sha256::digest(text.as_bytes()));
            if *session_id != attached.handle.session_id
                || *canonical_project_digest != digest
                || request.mutation.actor_role != role
                || request.mutation.actor_principal_digest
                    != super::run_invocation::principal_digest(&state.principal)
            {
                return Err(unavailable());
            }
            let recovery = ctx
                .media_storage_recovery
                .as_ref()
                .ok_or_else(|| internal("media storage authority is unavailable"))?;
            let receipt = recovery
                .append_media_upload_chunk(request, chrono::Utc::now().timestamp_millis())
                .await
                .map_err(|error| {
                    let text = error.to_string();
                    if text.contains("conflict") {
                        ErrorPayload {
                            code: ErrorCode::Conflict,
                            message: text,
                        }
                    } else {
                        internal(error)
                    }
                })?;
            Ok(Response::LocalMediaMutation(receipt))
        }
        Request::CancelMediaUpload(request) => {
            use cockpit_db::media_attachments::{
                LocalMediaActorRoleV1, LocalMediaMutationPayloadV1,
            };
            use sha2::{Digest as _, Sha256};
            let unavailable = || ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "media_attachment_unavailable".into(),
            };
            let LocalMediaMutationPayloadV1::Cancel {
                session_id,
                canonical_project_digest,
                ..
            } = &request.payload
            else {
                return Err(bad_request("media upload action mismatch"));
            };
            let access = ctx
                .db
                .get_session(*session_id)
                .await
                .map_err(internal)?
                .map(|row| session_access_for_row(&state.principal, &row))
                .ok_or_else(unavailable)?;
            let role = match access {
                SessionAccess::Owner => LocalMediaActorRoleV1::Owner,
                SessionAccess::Writer => LocalMediaActorRoleV1::Writer,
                _ => return Err(unavailable()),
            };
            let attached = require_attached(state).map_err(|_| unavailable())?;
            let text = attached
                .handle
                .project_root
                .to_str()
                .ok_or_else(unavailable)?;
            let digest = crate::intel::hex_lower(&Sha256::digest(text.as_bytes()));
            if *session_id != attached.handle.session_id
                || *canonical_project_digest != digest
                || request.actor_role != role
                || request.actor_principal_digest
                    != super::run_invocation::principal_digest(&state.principal)
            {
                return Err(unavailable());
            }
            let recovery = ctx
                .media_storage_recovery
                .as_ref()
                .ok_or_else(|| internal("media storage authority is unavailable"))?;
            let receipt = recovery
                .cancel_media_upload(request, chrono::Utc::now().timestamp_millis())
                .await
                .map_err(|error| {
                    let text = error.to_string();
                    if text.contains("conflict") {
                        ErrorPayload {
                            code: ErrorCode::Conflict,
                            message: text,
                        }
                    } else {
                        internal(error)
                    }
                })?;
            Ok(Response::LocalMediaMutation(receipt))
        }
        Request::DiscardUnreferencedMediaAttachment(request) => {
            use cockpit_db::media_attachments::{
                LocalMediaActorRoleV1, LocalMediaMutationPayloadV1,
            };
            use sha2::{Digest as _, Sha256};
            let unavailable = || ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "media_attachment_unavailable".into(),
            };
            let LocalMediaMutationPayloadV1::Discard {
                session_id,
                canonical_project_digest,
                ..
            } = &request.payload
            else {
                return Err(bad_request("media discard action mismatch"));
            };
            let access = ctx
                .db
                .get_session(*session_id)
                .await
                .map_err(internal)?
                .map(|row| session_access_for_row(&state.principal, &row))
                .ok_or_else(unavailable)?;
            let role = match access {
                SessionAccess::Owner => LocalMediaActorRoleV1::Owner,
                SessionAccess::Writer => LocalMediaActorRoleV1::Writer,
                _ => return Err(unavailable()),
            };
            let attached = require_attached(state).map_err(|_| unavailable())?;
            let project = attached
                .handle
                .project_root
                .to_str()
                .ok_or_else(unavailable)?;
            let digest = crate::intel::hex_lower(&Sha256::digest(project.as_bytes()));
            if *session_id != attached.handle.session_id
                || *canonical_project_digest != digest
                || request.actor_role != role
                || request.actor_principal_digest
                    != super::run_invocation::principal_digest(&state.principal)
            {
                return Err(unavailable());
            }
            let storage = ctx
                .media_storage_recovery
                .as_ref()
                .ok_or_else(|| internal("media storage authority is unavailable"))?;
            let receipt = storage
                .discard_media_attachment(request, chrono::Utc::now().timestamp_millis())
                .await
                .map_err(|error| {
                    let text = error.to_string();
                    if text.contains("conflict") {
                        ErrorPayload {
                            code: ErrorCode::Conflict,
                            message: text,
                        }
                    } else if text.contains("media_attachment_unavailable") {
                        unavailable()
                    } else {
                        internal(error)
                    }
                })?;
            if receipt.outcome
                == cockpit_db::media_attachments::LocalMediaMutationOutcomeV1::Applied
            {
                storage
                    .reconcile_media_cleanup_intents(chrono::Utc::now().timestamp_millis())
                    .await
                    .map_err(internal)?;
            }
            Ok(Response::LocalMediaMutation(receipt))
        }
        Request::GetMediaUploadStatus(request) => {
            use sha2::{Digest as _, Sha256};
            let unavailable = || ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "media_attachment_unavailable".into(),
            };
            authorize_session_row_reader(&state.principal, ctx, request.session_id)
                .await
                .map_err(|_| unavailable())?;
            let attached = require_attached(state).map_err(|_| unavailable())?;
            let text = attached
                .handle
                .project_root
                .to_str()
                .ok_or_else(unavailable)?;
            let digest = crate::intel::hex_lower(&Sha256::digest(text.as_bytes()));
            if request.session_id != attached.handle.session_id
                || request.canonical_project_digest != digest
            {
                return Err(unavailable());
            }
            let status = ctx
                .db
                .read(move |conn| {
                    cockpit_db::Db::media_upload_status_for_owner_conn(conn, &request)
                })
                .await
                .map_err(|error| {
                    if error.to_string().contains("media_attachment_unavailable") {
                        unavailable()
                    } else {
                        internal(error)
                    }
                })?
                .ok_or_else(unavailable)?;
            Ok(Response::MediaUploadStatus(status))
        }
        Request::FinalizeMediaUpload(request) => {
            use cockpit_db::media_attachments::{
                LocalMediaActorRoleV1, LocalMediaMutationPayloadV1,
            };
            use sha2::{Digest as _, Sha256};
            let unavailable = || ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "media_attachment_unavailable".into(),
            };
            let LocalMediaMutationPayloadV1::Finalize {
                session_id,
                canonical_project_digest,
                ..
            } = &request.payload
            else {
                return Err(bad_request("media upload action mismatch"));
            };
            let access = ctx
                .db
                .get_session(*session_id)
                .await
                .map_err(internal)?
                .map(|row| session_access_for_row(&state.principal, &row))
                .ok_or_else(unavailable)?;
            let role = match access {
                SessionAccess::Owner => LocalMediaActorRoleV1::Owner,
                SessionAccess::Writer => LocalMediaActorRoleV1::Writer,
                _ => return Err(unavailable()),
            };
            let attached = require_attached(state).map_err(|_| unavailable())?;
            let text = attached
                .handle
                .project_root
                .to_str()
                .ok_or_else(unavailable)?;
            let digest = crate::intel::hex_lower(&Sha256::digest(text.as_bytes()));
            if *session_id != attached.handle.session_id
                || *canonical_project_digest != digest
                || request.actor_role != role
                || request.actor_principal_digest
                    != super::run_invocation::principal_digest(&state.principal)
            {
                return Err(unavailable());
            }
            let recovery = ctx
                .media_storage_recovery
                .as_ref()
                .ok_or_else(|| internal("media storage authority is unavailable"))?;
            let receipt = recovery
                .finalize_media_upload(request, chrono::Utc::now().timestamp_millis())
                .await
                .map_err(|error| {
                    let text = error.to_string();
                    if text.contains("conflict") {
                        ErrorPayload {
                            code: ErrorCode::Conflict,
                            message: text,
                        }
                    } else {
                        internal(error)
                    }
                })?;
            Ok(Response::LocalMediaMutation(receipt))
        }
        Request::ListLeakReports {
            cursor,
            limit,
            project_root,
            session_id,
            rotation,
        } => list_leak_reports(ctx, cursor, limit, project_root, session_id, rotation).await,
        Request::BeginLeakReveal { report_id } => {
            begin_leak_reveal(ctx, &state.principal, report_id).await
        }
        Request::MarkLeakRotated {
            report_id,
            rotation,
        } => mark_leak_rotated(ctx, report_id, rotation).await,
        Request::DeleteLeakReport { report_id } => delete_leak_report(ctx, report_id).await,
        Request::Unknown => Err(proto::unsupported_request_error(
            proto::PROTOCOL_VERSION,
            None,
        )),
    }
}

fn agent_editor_lease_owner(state: &MutableClientState) -> String {
    let session = state
        .attached
        .as_ref()
        .map(|attached| attached.handle.session_id.to_string())
        .unwrap_or_else(|| "detached".into());
    format!(
        "{}:{}:{}:{session}",
        principal_digest(&state.principal),
        state.terminal_context.client_instance_id,
        state.terminal_context.connection_epoch,
    )
}

#[cfg(feature = "remote")]
pub(super) async fn handle_serialized_request_with_remote_operation(
    request: Request,
    state: &mut MutableClientState,
    shared: &Arc<SharedClientState>,
    ctx: &Arc<DaemonContext>,
    effects: &mut ClientRequestEffects,
    remote_operation: Option<&super::RemoteOperationContext>,
) -> std::result::Result<Response, ErrorPayload> {
    Box::pin(handle_serialized_request_impl(
        request,
        state,
        shared,
        ctx,
        effects,
        remote_operation,
    ))
    .await
}

// ---- `/leaks` dispatch helpers ---------------------------------------------
//
// These handlers back the `/leaks` page. List rows never carry plaintext; the
// list cursor is MAC'd per daemon boot (see `crate::leaks`). Reveal is NOT an
// ordinary request here: after `implement-leak-reveal` the ordinary protocol
// cannot express a revealed secret at all — the plaintext travels only on the
// sensitive local endpoint (in-process handoff or the Unix peer-authenticated
// reveal socket) via `crate::daemon::leak_reveal`. `BeginLeakReveal` is a
// secret-free owner RPC that mints the single-use capability into the daemon
// context's reveal slot.

/// Convert a [`ProtectedLeakRecordRef`] into a proto [`LeakReportMetadata`]
/// with the derived closed rotation plan. Carries no plaintext, ciphertext,
/// prefix, length, or fingerprint.
fn leak_ref_to_proto(r: &ProtectedLeakRecordRef) -> proto::LeakReportMetadata {
    let rotation_plan =
        crate::leaks::LeakRotationPlan::derive(r.source, r.category, r.connector_id.as_deref());
    proto::LeakReportMetadata {
        report_id: r.report_id.clone(),
        session_id: Uuid::parse_str(&r.session_id).unwrap_or_else(|_| Uuid::nil()),
        source: r.source.as_str().to_owned(),
        category: r.category.as_str().to_owned(),
        provider_id: r.provider_id.clone(),
        model_id: r.model_id.clone(),
        generation: r.generation,
        connector_id: r.connector_id.clone(),
        status: r.status.as_str().to_owned(),
        rotation: r.rotation.as_str().to_owned(),
        rotation_plan: Some(proto::LeakRotationPlan::from(rotation_plan)),
        seen_count: r.seen_count,
        first_reported_ms: r.first_reported_ms,
        last_reported_ms: r.last_reported_ms,
        contained_at_ms: r.contained_at_ms,
    }
}

/// Map a [`crate::leaks::LeakRotationPlan`] to the proto enum.
impl From<crate::leaks::LeakRotationPlan> for proto::LeakRotationPlan {
    fn from(plan: crate::leaks::LeakRotationPlan) -> Self {
        match plan {
            crate::leaks::LeakRotationPlan::RevokeConnectorCredential => {
                Self::RevokeConnectorCredential
            }
            crate::leaks::LeakRotationPlan::RotateNamedSecret => Self::RotateNamedSecret,
            crate::leaks::LeakRotationPlan::InvalidateSession => Self::InvalidateSession,
            crate::leaks::LeakRotationPlan::OwnerReviewRequired => Self::OwnerReviewRequired,
        }
    }
}

/// Map the proto rotation-state filter to the db rotation enum.
fn leak_rotation_filter(
    rotation: Option<proto::LeakRotationState>,
) -> Option<crate::db::protected_leak_records::LeakRotation> {
    rotation.map(|r| match r {
        proto::LeakRotationState::None => crate::db::protected_leak_records::LeakRotation::None,
        proto::LeakRotationState::PendingUser => {
            crate::db::protected_leak_records::LeakRotation::PendingUser
        }
        proto::LeakRotationState::Rotated => {
            crate::db::protected_leak_records::LeakRotation::Rotated
        }
        proto::LeakRotationState::NotApplicable => {
            crate::db::protected_leak_records::LeakRotation::NotApplicable
        }
    })
}

/// Map a leak list error to the ordinary proto payload. `InvalidCursor` /
/// `InvalidLimit` are `BadRequest`; `NotFound` is the indistinguishable
/// `unauthorized`; everything else is `Internal` (secret-free).
fn leak_list_error(e: crate::leaks::LeakListError) -> ErrorPayload {
    match e {
        crate::leaks::LeakListError::InvalidCursor => ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "invalid_cursor".to_string(),
        },
        crate::leaks::LeakListError::InvalidLimit => ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "limit must be in 1..=100".to_string(),
        },
        crate::leaks::LeakListError::NotFound => ErrorPayload {
            code: ErrorCode::Authorization,
            message: "unauthorized".to_string(),
        },
        crate::leaks::LeakListError::Internal => internal("leak store unavailable"),
    }
}

/// Dispatch `ListLeakReports`: machine-wide Owner list of safe metadata,
/// newest-first, with a MAC'd snapshot cursor, honored `project_root` /
/// session / rotation filters, and a correct `has_more`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn list_leak_reports(
    ctx: &Arc<DaemonContext>,
    cursor: Option<String>,
    limit: Option<u32>,
    project_root: Option<String>,
    session_id: Option<Uuid>,
    rotation: Option<proto::LeakRotationState>,
) -> std::result::Result<Response, ErrorPayload> {
    let limit = limit.unwrap_or(50) as i64;
    let filters = crate::db::protected_leak_records::LeakListFilters {
        session_filter: session_id.map(|s| s.to_string()),
        project_root,
        rotation: leak_rotation_filter(rotation),
    };
    let page = crate::leaks::list_leak_reports(
        &ctx.db,
        &ctx.leak_cursor_key,
        filters,
        limit,
        cursor.as_deref(),
    )
    .await
    .map_err(leak_list_error)?;
    let reports: Vec<proto::LeakReportMetadata> = page.refs.iter().map(leak_ref_to_proto).collect();
    Ok(Response::LeakReports {
        page: proto::LeakReportsPage {
            reports,
            next_cursor: page.next_cursor,
            has_more: page.has_more,
        },
    })
}

/// Dispatch `BeginLeakReveal`: after owner + record checks, mint 32 raw random
/// token bytes into the daemon context's single reveal slot (replacing —
/// invalidating — any outstanding capability) and return the lowercase-hex
/// encoding. Secret-free: no plaintext rides this response. Unknown/deleted
/// reports return the one indistinguishable `unauthorized` payload.
pub(super) async fn begin_leak_reveal(
    ctx: &Arc<DaemonContext>,
    principal: &ClientPrincipal,
    report_id: String,
) -> std::result::Result<Response, ErrorPayload> {
    if !principal.is_owner() {
        return Err(authorization_error("leak reveal requires local owner"));
    }
    let unauthorized = || ErrorPayload {
        code: ErrorCode::Authorization,
        message: "unauthorized".to_string(),
    };
    // Resolve/validate the record BEFORE minting the capability (no lifecycle
    // side effect for an unknown/deleted report).
    let record = ctx
        .db
        .protected_leak_record_get(&report_id)
        .await
        .map_err(internal)?
        .ok_or_else(unauthorized)?;
    if record.status == crate::db::protected_leak_records::LeakRecordStatus::Deleted {
        return Err(unauthorized());
    }
    let (token, hex) = crate::leaks::mint_reveal_token();
    let expires_at_ms =
        chrono::Utc::now().timestamp_millis() + crate::leaks::LEAK_REVEAL_CAPABILITY_TTL_MS;
    ctx.leak_reveal_state
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .mint(token, report_id.clone(), expires_at_ms);
    Ok(Response::LeakRevealCapability {
        capability: proto::LeakRevealCapability {
            capability: hex,
            report_id,
            expires_at_ms,
        },
    })
}

/// Dispatch `MarkLeakRotated`: update the rotation disposition of a leak
/// record. Metadata-only and reversible.
async fn mark_leak_rotated(
    ctx: &Arc<DaemonContext>,
    report_id: String,
    rotation: proto::LeakRotationDisposition,
) -> std::result::Result<Response, ErrorPayload> {
    let (action, db_rotation) = match rotation {
        proto::LeakRotationDisposition::Accept => (
            crate::leaks::LeakRotationAction::Accept,
            crate::db::protected_leak_records::LeakRotation::PendingUser,
        ),
        proto::LeakRotationDisposition::Dismiss => (
            crate::leaks::LeakRotationAction::Dismiss,
            crate::db::protected_leak_records::LeakRotation::NotApplicable,
        ),
        proto::LeakRotationDisposition::Rotated => (
            crate::leaks::LeakRotationAction::MarkRotated,
            crate::db::protected_leak_records::LeakRotation::Rotated,
        ),
    };
    crate::leaks::update_rotation(&ctx.db, &report_id, action)
        .await
        .map_err(leak_list_error)?;
    Ok(Response::LeakRotationUpdated {
        report_id,
        rotation: db_rotation.as_str().to_owned(),
    })
}

/// Dispatch `DeleteLeakReport`: delete the protected plaintext/ciphertext
/// while retaining safe historical report metadata and mandatory redaction.
/// A missing report returns the same indistinguishable `unauthorized` payload
/// as reveal; deleting an already-deleted report is idempotent success. No
/// error path (including `Internal`) contains a reference count.
pub(super) async fn delete_leak_report(
    ctx: &Arc<DaemonContext>,
    report_id: String,
) -> std::result::Result<Response, ErrorPayload> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    crate::leaks::delete_protected_value(&ctx.db, &report_id, now_ms)
        .await
        .map_err(leak_list_error)?;
    Ok(Response::LeakReportDeleted { report_id })
}

async fn handle_concurrent_request_impl(
    request: Request,
    shared: Arc<SharedClientState>,
    ctx: Arc<DaemonContext>,
    #[cfg(feature = "remote")] remote_operation: Option<super::RemoteOperationContext>,
) -> std::result::Result<Response, ErrorPayload> {
    #[cfg(feature = "remote")]
    if let Some(operation) = &remote_operation {
        tracing::debug!(
            request_id = %operation.request_id,
            operation_id = %operation.operation_id,
            logical_attachment_id = %operation.logical_attachment_id,
            authenticated_device_id = %operation.authenticated_device_id,
            authenticated_device_generation = operation.authenticated_device_generation,
            "dispatching admitted concurrent remote operation"
        );
    }
    validate_request_semantics(&request)?;
    let request_kind = principal::request_kind(&request);
    #[cfg(feature = "remote")]
    let audit_path = request_audit_path(&request);
    #[cfg(feature = "remote")]
    let audit_remote = !shared.principal.is_owner() && is_remote_mutating_request(&request);
    if let Err(error) = authorize_request_shared(&request, &shared, &ctx).await {
        #[cfg(feature = "remote")]
        if audit_remote {
            audit_remote_request(
                &ctx,
                &shared.principal,
                request_kind,
                None,
                audit_path.as_deref(),
                "denied",
            )
            .await;
        }
        return Err(error);
    }
    #[cfg(feature = "remote")]
    if audit_remote {
        audit_remote_request(
            &ctx,
            &shared.principal,
            request_kind,
            None,
            audit_path.as_deref(),
            "allowed",
        )
        .await;
    }
    #[cfg(test)]
    apply_concurrent_request_test_hook(&request).await;
    match request {
        Request::AgentInstallationList(request) => {
            let service = ctx.agent_installation_service().map_err(internal)?;
            Ok(Response::AgentInstallation(service.list(request).await))
        }
        Request::AgentInstallationInspect(request) => {
            let service = ctx.agent_installation_service().map_err(internal)?;
            Ok(Response::AgentInstallation(service.inspect(request).await))
        }
        Request::SubagentTranscript {
            session_id,
            task_call_id,
            label,
        } => {
            let db = ctx.db.clone();
            let task_call_id_for_read = task_call_id.clone();
            let label_for_read = label.clone();
            let mut history = db
                .read(move |conn| {
                    crate::engine::rehydrate::subagent_history_snapshot_conn(
                        conn,
                        session_id,
                        &task_call_id_for_read,
                        &label_for_read,
                    )
                })
                .await
                .map_err(internal)?;
            if !shared.principal.is_owner() {
                let redact = if let Some(handle) = ctx.registry.live_handle(session_id) {
                    handle.redaction_table()
                } else {
                    let session = crate::session::Session::resume(
                        ctx.db.clone(),
                        session_id,
                        ctx.redaction_key_resolver().map_err(internal)?,
                        ctx.secret_vault.clone(),
                    )
                    .map_err(internal)?
                    .ok_or_else(|| ErrorPayload {
                        code: ErrorCode::UnknownSession,
                        message: format!("unknown session {session_id}"),
                    })?;
                    std::sync::Arc::new(
                        session
                            .persisted_redaction_table()
                            .map_err(internal)?
                            .ok_or_else(|| ErrorPayload {
                                code: ErrorCode::Authorization,
                                message: "session transcript redaction data is unavailable"
                                    .to_string(),
                            })?,
                    )
                };
                history = scrub_history_for_principal(&shared.principal, history, &redact);
            }
            Ok(Response::SubagentTranscript {
                session_id,
                task_call_id,
                label,
                history,
            })
        }
        Request::ListAssistants => {
            let assistants = ctx
                .db
                .list_assistants()
                .await
                .map_err(internal)?
                .into_iter()
                .map(assistant_to_proto_with_definition)
                .collect();
            Ok(Response::Assistants { assistants })
        }
        Request::CountPinnedMessages { session_id } => ctx
            .db
            .count_pins(session_id)
            .await
            .map(|count| Response::PinCount { count })
            .map_err(internal),
        Request::ListPinnedMessageSeqs { session_id } => ctx
            .db
            .list_pin_seqs(session_id)
            .await
            .map(|seqs| Response::PinSeqs { seqs })
            .map_err(internal),
        Request::ListPinnedMessagesWithText { session_id } => ctx
            .db
            .list_pins_with_text(session_id)
            .await
            .map(|pins| Response::PinsWithText {
                pins: pins.into_iter().map(pinned_message_to_proto).collect(),
            })
            .map_err(internal),
        Request::PinnedMessageState { session_id } => {
            let count = ctx.db.count_pins(session_id).await.map_err(internal)?;
            let seqs = ctx.db.list_pin_seqs(session_id).await.map_err(internal)?;
            Ok(Response::PinState {
                state: proto::PinState { count, seqs },
            })
        }
        // v10-only owner-remoted sealed-owner reads (concurrent). Non-owner is
        // rejected by the central authorizer; the live directory backing is
        // installed by the persistence sibling, so these fail closed here.
        Request::SealedOwnerInventory {
            scope_kind,
            scope_key,
        } => {
            let owner = crate::sealed::action::OwnerAuthority::for_owner_request();
            // An optional scope filter narrows the inventory; absent, it is
            // machine-wide. A malformed filter is a content-free client error.
            let scope = match scope_kind {
                Some(kind) => Some(
                    build_sealed_scope_ref(Some(kind), scope_key)
                        .map_err(|error| bad_request(error.to_string()))?,
                ),
                None => None,
            };
            let directory = sealed_value_directory(&ctx);
            let rows = directory
                .inventory_records(owner, scope.as_ref())
                .await
                .map_err(internal)?;
            let items = rows
                .into_iter()
                .map(sealed_record_row_to_inventory_item)
                .collect();
            // The funnel clamps the row count to the bounded wire ceiling.
            Ok(Response::sealed_owner_inventory(items))
        }
        Request::ListSealedActions => {
            let owner = crate::sealed::action::OwnerAuthority::for_owner_request();
            let actions = sealed_action_directory(&ctx)
                .list(owner)
                .await
                .map_err(internal)?
                .into_iter()
                .map(sealed_action_summary_to_wire)
                .collect();
            Ok(Response::sealed_actions(actions))
        }
        Request::ExportSessionData {
            session_id,
            kind,
            include_generated_artifacts,
            include_sensitive,
        } => {
            #[cfg(feature = "remote")]
            let local_owner_action =
                is_local_owner_action_shared(&shared, remote_operation.as_ref());
            #[cfg(not(feature = "remote"))]
            let local_owner_action = shared.principal.is_owner();
            export_session_data(
                &ctx,
                session_id,
                kind,
                include_generated_artifacts,
                include_sensitive,
                local_owner_action,
            )
            .await
        }

        Request::ImportSessionArchive { transfer } => import_session_archive(&ctx, &transfer).await,
        Request::WriteBulkTransferChunk {
            transfer,
            chunk_index,
            data_base64,
        } => {
            let owner =
                if transfer.mime_class == cockpit_proto::bulk_transfer::BulkMimeClass::Opaque {
                    let session_id = shared
                        .attached
                        .as_ref()
                        .map(SharedAttachedSession::session_id)
                        .ok_or_else(|| ErrorPayload {
                            code: ErrorCode::NotAttached,
                            message: "request requires an attached session".to_owned(),
                        })?;
                    #[cfg(feature = "remote")]
                    {
                        Some(bulk_user_message_transfer_owner(
                            &shared.principal,
                            session_id,
                            remote_operation.as_ref(),
                        )?)
                    }
                    #[cfg(not(feature = "remote"))]
                    {
                        Some(bulk_user_message_transfer_owner_local(
                            &shared.principal,
                            session_id,
                        )?)
                    }
                } else {
                    None
                };
            write_bulk_transfer_chunk(&transfer, chunk_index, &data_base64, owner.as_ref()).await
        }
        Request::ReadBulkTransferChunk {
            transfer_id,
            chunk_index,
        } => read_bulk_transfer_chunk(&transfer_id, chunk_index).await,
        Request::ReadRedactedExportChunk {
            transfer_id,
            chunk_index,
        } => read_redacted_export_chunk(&transfer_id, chunk_index).await,
        Request::FsList {
            project_root,
            path,
            show_hidden,
        } => {
            crate::daemon::fs_api::fs_list(
                ctx.clone(),
                shared.principal.clone(),
                project_root,
                path,
                show_hidden,
            )
            .await
        }
        Request::FsStat { project_root, path } => {
            crate::daemon::fs_api::fs_stat(
                ctx.clone(),
                shared.principal.clone(),
                project_root,
                path,
            )
            .await
        }
        Request::FsRead {
            project_root,
            path,
            base64,
        } => {
            crate::daemon::fs_api::fs_read(
                ctx.clone(),
                shared.principal.clone(),
                project_root,
                path,
                base64,
            )
            .await
        }
        Request::GitStatus { project_root } => {
            crate::daemon::fs_api::git_status(project_root).await
        }
        Request::GitDiffFile { project_root, path } => {
            crate::daemon::fs_api::git_diff_file(project_root, path).await
        }
        Request::ListSessions {
            project_id,
            parent_session_id,
            assistant_id,
        } => {
            list_sessions(
                &ctx,
                &shared.principal,
                project_id,
                parent_session_id,
                assistant_id,
            )
            .await
        }
        Request::ReadSessionMessages {
            session_id,
            before_seq,
            limit,
        } => {
            let db = ctx.db.clone();
            let (messages, has_more) = db
                .read(move |conn| {
                    crate::db::Db::read_session_messages_conn(conn, session_id, before_seq, limit)
                })
                .await
                .map_err(internal)?;
            Ok(Response::SessionMessages {
                session_id,
                messages,
                has_more,
            })
        }
        Request::ReadClientSubmissionReceipt {
            session_id,
            client_submission_id,
        } => {
            let durable = ctx
                .db
                .client_submission_receipt(session_id, client_submission_id)
                .await
                .map_err(internal)?;
            let status = if let Some(receipt) = durable {
                proto::ClientSubmissionReceiptStatus::Accepted {
                    seq: receipt.seq,
                    wire_fingerprint: receipt.wire_fingerprint,
                }
            } else if let Some(receipt) = ctx
                .db
                .client_submission_terminal_receipt(session_id, client_submission_id)
                .await
                .map_err(internal)?
            {
                proto::ClientSubmissionReceiptStatus::Terminal {
                    disposition: receipt.disposition.as_str().to_string(),
                    wire_fingerprint: receipt.wire_fingerprint,
                }
            } else {
                proto::ClientSubmissionReceiptStatus::Pending
            };
            Ok(Response::ClientSubmissionReceipt {
                session_id,
                client_submission_id,
                status,
            })
        }
        Request::ReadHistoryPage {
            session_id,
            before_seq,
            limit,
        } => {
            let db = ctx.db.clone();
            let config_source = ctx.config_source.clone();
            let page = db
                .read(move |conn| {
                    read_history_page_conn(conn, session_id, before_seq, limit, &config_source)
                })
                .await
                .map_err(internal)?;
            Ok(Response::HistoryPage {
                session_id,
                entries: page.entries,
                has_more: page.has_more,
                oldest_seq: page.oldest_seq,
            })
        }
        Request::ReadSubagentHistoryPage {
            session_id,
            task_call_id,
            label,
            before_seq,
            limit,
        } => {
            let db = ctx.db.clone();
            let query_task_call_id = task_call_id.clone();
            let query_label = label.clone();
            let page = db
                .read(move |conn| {
                    read_subagent_history_page_conn(
                        conn,
                        session_id,
                        &query_task_call_id,
                        &query_label,
                        before_seq,
                        limit,
                    )
                })
                .await
                .map_err(internal)?;
            Ok(Response::SubagentHistoryPage {
                session_id,
                task_call_id,
                label,
                entries: page.entries,
                has_more: page.has_more,
                oldest_seq: page.oldest_seq,
            })
        }
        Request::SessionLiveStatus { session_ids } => {
            let mut visible_ids = Vec::new();
            for id in session_ids {
                if shared.principal.is_owner() {
                    visible_ids.push(id);
                    continue;
                }
                match ctx.db.get_session(id).await {
                    Ok(Some(row))
                        if session_access_for_row(&shared.principal, &row)
                            != SessionAccess::None =>
                    {
                        visible_ids.push(id);
                    }
                    Ok(_) => {}
                    Err(e) => return Err(internal(e)),
                }
            }
            let mut statuses = Vec::new();
            for id in visible_ids {
                let Some((has_active_schedules, processing, _tool_running)) =
                    ctx.registry.live_status(id)
                else {
                    continue;
                };
                // v10-only: include the session's canonical project root so a
                // `cockpit run --session <id>` client can validate it matches
                // --cwd/--project before attaching. The field is `None` for v9
                // negotiated connections (the version gate strips it).
                let project_root = ctx
                    .db
                    .get_session(id)
                    .await
                    .ok()
                    .flatten()
                    .map(|row| row.project_root);
                statuses.push(proto::LiveStatus {
                    session_id: id,
                    has_active_schedules,
                    processing,
                    project_root,
                });
            }
            Ok(Response::SessionLiveStatus { statuses })
        }
        Request::GetInventoryBundle {
            project_root,
            session_id,
            selected_agent,
        } => {
            get_inventory_bundle_shared(&ctx, &shared, project_root, session_id, selected_agent)
                .await
        }
        Request::ResourceSnapshot => Ok(Response::ResourceSnapshot {
            snapshot: resource_scheduler_snapshot(&ctx),
        }),
        Request::ListScheduledJobs { owner } => {
            let scheduler = require_scheduler(&ctx)?;
            let jobs = scheduler
                .list_jobs(owner.as_deref())
                .await
                .map_err(internal)?;
            Ok(Response::ScheduledJobs { jobs })
        }
        Request::DaemonStatus => Ok(Response::DaemonStatus {
            pid: std::process::id(),
            uptime_secs: ctx.started_at.elapsed().as_secs(),
            active_sessions: ctx.registry.active_session_ids().len() as u32,
            socket_path: ctx.paths.socket.display().to_string(),
            daemon_version: proto::DAEMON_VERSION.to_string(),
            protocol_version: proto::PROTOCOL_VERSION,
            paused_sessions: ctx
                .db
                .paused_session_work_all()
                .await
                .map_err(internal)?
                .len() as u32,
            database_path: ctx
                .db
                .path()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<in-memory>".to_string()),
            schema_version: ctx.db.schema_version().await.map_err(internal)?,
        }),
        Request::GetHostCapabilities => get_host_capabilities(&ctx),
        Request::ListLeakReports {
            cursor,
            limit,
            project_root,
            session_id,
            rotation,
        } => list_leak_reports(&ctx, cursor, limit, project_root, session_id, rotation).await,
        Request::TerminalIngressStatus {
            terminal_id,
            binding,
            operation_id,
        } => {
            if shared.terminal_views.get(&terminal_id) != Some(&binding) {
                return Err(invalid_terminal_ingress());
            }
            shared
                .terminal_host
                .ingress_status(terminal_id, binding, operation_id)
        }
        Request::GetUsageCounts { project_id } => {
            let since = chrono::Utc::now().timestamp() - crate::db::usage_events::USAGE_WINDOW_SECS;
            let models = ctx
                .db
                .usage_counts("model", None, since)
                .await
                .map_err(internal)?;
            let slash = ctx
                .db
                .usage_counts("slash", None, since)
                .await
                .map_err(internal)?;
            let tags = match project_id.as_deref() {
                Some(pid) => ctx
                    .db
                    .usage_counts("tag", Some(pid), since)
                    .await
                    .map_err(internal)?,
                None => std::collections::HashMap::new(),
            };
            Ok(Response::UsageCounts {
                models,
                slash,
                tags,
            })
        }
        Request::GetRunInvocationStatus {
            client_submission_id,
        } => {
            run_invocation::handle_get_run_invocation_status_shared(
                &shared,
                &ctx,
                client_submission_id,
            )
            .await
        }
        Request::StatsRollup {
            project_id,
            range,
            by_role,
        } => stats_rollup(&ctx, project_id, range, by_role).await,
        Request::GuidanceEstimate {
            project_root,
            provider,
            model,
        } => guidance_estimate(&ctx, project_root, provider, model).await,
        // Owner-only concurrent policy reads. Their ordering is declared
        // `concurrent` in the command table (and asserted by
        // `request_ordering_concurrent_set_is_exactly_the_enumerated_reads`), so
        // they are routed here rather than to the serialized dispatch; implement
        // them on this concurrent path so an owner export/read does not fall
        // through to the "not marked concurrent" arm below.
        Request::ExportPolicy { project_root } => {
            let bundle_json = tokio::task::spawn_blocking(move || {
                crate::policy::export(std::path::Path::new(&project_root))
            })
            .await
            .map_err(internal)?
            .map_err(internal)?;
            Ok(Response::PolicyExported { bundle_json })
        }
        Request::GetAgentInventory { project_root } => {
            crate::daemon::agent_management::inventory(&ctx, project_root).await
        }
        Request::GetAgentEditSnapshot { project_root, name } => {
            crate::daemon::agent_management::edit_snapshot(&ctx, project_root, name).await
        }
        Request::GetExtendedConfigSnapshot { project_root } => {
            crate::daemon::fs_api::get_extended_config_snapshot(&ctx, project_root).await
        }
        Request::GetImageSpendPolicy { project_key } => {
            let current = ctx
                .db
                .current_image_spend_policy(project_key)
                .await
                .map_err(internal)?;
            Ok(Response::ImageSpendPolicy {
                settings: current.as_ref().map(|policy| policy.settings.clone()),
                policy_version: current.map(|policy| policy.policy_version),
            })
        }
        // LOCAL owner image-generation control-plane reads (declared
        // `concurrent`). Redacted safe projections only.
        Request::ImageEndpointList { .. }
        | Request::ImageEndpointGet { .. }
        | Request::ImageTargetList { .. }
        | Request::ImageTargetGet { .. }
        | Request::ImageWorkflowList { .. }
        | Request::ImageWorkflowGet { .. } => dispatch_image_control_read(&ctx, request).await,
        // Owner-only catalog read. It resolves only from `ctx` (config source +
        // vault) and takes its own config-publication lock, so it needs no
        // per-connection session state and is safe to run concurrently. Its
        // sibling `GetProviderUsageSnapshot` stays serialized because it needs
        // the attached session's env overlay snapshot, which is not carried on
        // the concurrent (shared) path.
        Request::GetProviderCatalogSnapshot {
            project_root,
            provider_id,
        } => provider_catalog_snapshot(&ctx, &project_root, provider_id.as_deref()).await,
        Request::ListPackages => list_packages_response(&ctx).await,
        #[cfg(feature = "remote")]
        Request::GetConnectorState => get_connector_state_response(&ctx).await,
        #[cfg(feature = "remote")]
        Request::GetOrgSyncStatus => get_org_sync_status_response(&ctx).await,
        Request::ListFailedToolCalls {
            since_epoch,
            tool,
            model,
            project_id,
            include_recovered,
            limit,
        } => {
            list_failed_tool_calls_response(
                &ctx,
                since_epoch,
                tool,
                model,
                project_id,
                include_recovered,
                limit,
            )
            .await
        }
        Request::GetSessionCompactions { session_id } => {
            get_session_compactions_response(&ctx, session_id).await
        }
        Request::GetAssistant { name } => get_assistant_response(&ctx, name).await,
        Request::DiagnoseMediaReservation { scope, id } => {
            diagnose_media_reservation_response(&ctx, scope, id).await
        }
        Request::GetDoctorSnapshot {
            project_root,
            no_sandbox,
            offline,
        } => {
            get_doctor_snapshot_response(
                Some(ctx.db.clone()),
                ctx.secret_vault.clone(),
                project_root,
                no_sandbox,
                offline,
            )
            .await
        }
        _ => Err(ErrorPayload {
            code: ErrorCode::Internal,
            message: format!("request `{request_kind}` is not marked concurrent"),
        }),
    }
}

/// Local-profile concurrent dispatch entry point. Remote operation identity is
/// not part of the caller-facing contract.
pub(super) async fn handle_concurrent_request(
    request: Request,
    shared: Arc<SharedClientState>,
    ctx: Arc<DaemonContext>,
) -> std::result::Result<Response, ErrorPayload> {
    handle_concurrent_request_impl(request, shared, ctx).await
}

#[cfg(feature = "remote")]
pub(super) async fn handle_concurrent_request_with_remote_operation(
    request: Request,
    shared: Arc<SharedClientState>,
    ctx: Arc<DaemonContext>,
    remote_operation: Option<super::RemoteOperationContext>,
) -> std::result::Result<Response, ErrorPayload> {
    handle_concurrent_request_impl(request, shared, ctx, remote_operation).await
}

fn current_host_capability_snapshot(ctx: &DaemonContext) -> cockpit_proto::HostCapabilitySnapshot {
    ctx.host_capabilities
        .current()
        .map(|snapshot| (*snapshot).clone())
        .unwrap_or_else(crate::daemon::session_worker::unpublished_host_capability_snapshot)
}

fn sandbox_capability_missing(
    missing: crate::daemon::session_worker::SandboxCapabilityMissing,
) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::SandboxCapabilityMissing,
        message: missing.to_string(),
    }
}

fn get_host_capabilities(ctx: &DaemonContext) -> std::result::Result<Response, ErrorPayload> {
    let snapshot = ctx
        .host_capabilities
        .current()
        .ok_or_else(|| ErrorPayload {
            code: ErrorCode::Internal,
            message: "host capability snapshot has not been published".to_string(),
        })?;
    Ok(Response::HostCapabilities {
        snapshot: (*snapshot).clone(),
    })
}

async fn migrate_kek_placement_request(
    ctx: &Arc<DaemonContext>,
    dest: cockpit_proto::SecretStorePlacement,
) -> std::result::Result<Response, ErrorPayload> {
    if dest == cockpit_proto::SecretStorePlacement::Unavailable {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "cannot migrate the wrap-key vault to an unavailable placement".into(),
        });
    }
    let probe = match ctx.host_capabilities.current().and_then(|snapshot| {
        snapshot
            .feature(crate::host_capabilities::FEATURE_SECRET_STORE_KEYRING)
            .cloned()
    }) {
        Some(row) => crate::secure_key::KeyringProbeResult {
            state: row.state,
            reason: row.reason,
            fix_command: row.fix_command,
            remedy_text: row.remedy_text,
        },
        None => crate::secure_key::probe_platform_keyring(),
    };
    let db = ctx.db.clone();
    let snapshot = tokio::task::spawn_blocking(move || {
        crate::secure_key::migrate_installation_kek(
            &db,
            dest,
            &probe,
            crate::secure_key::SecretStoreInjected::default(),
        )
    })
    .await
    .map_err(|e| ErrorPayload {
        code: ErrorCode::Internal,
        message: format!("kek migrate task failed: {e}"),
    })?
    .map_err(|e| ErrorPayload {
        code: ErrorCode::Internal,
        message: e.to_string(),
    })?;
    let (host_snapshot, published) =
        crate::host_capabilities::refresh_host_capabilities_with_secret_store(
            &ctx.host_capabilities,
            &ctx.host_capability_probes,
            snapshot,
        )
        .await
        .map_err(internal)?;
    if published {
        ctx.broadcast_global(proto::Event::HostCapabilitiesChanged {
            snapshot: host_snapshot.clone(),
        });
    }
    Ok(Response::HostCapabilities {
        snapshot: host_snapshot,
    })
}

async fn refresh_host_capabilities_request(
    ctx: &Arc<DaemonContext>,
) -> std::result::Result<Response, ErrorPayload> {
    let (snapshot, published) = crate::host_capabilities::refresh_host_capabilities(
        &ctx.host_capabilities,
        &ctx.host_capability_probes,
    )
    .await
    .map_err(internal)?;
    if published {
        ctx.broadcast_global(proto::Event::HostCapabilitiesChanged {
            snapshot: snapshot.clone(),
        });
    }
    Ok(Response::HostCapabilities { snapshot })
}

fn validate_request_semantics(request: &Request) -> std::result::Result<(), ErrorPayload> {
    request
        .validate_semantics()
        .map_err(|message| ErrorPayload {
            code: ErrorCode::BadRequest,
            message: format!("invalid {} request: {message}", request.wire_tag()),
        })?;
    let owner_secret_error = match request {
        Request::PutNamedSecret { name, .. } | Request::DeleteNamedSecret { name } => {
            if name.trim().is_empty() {
                Some("secret name must not be empty")
            } else if name.contains('\0') {
                Some("secret name contains NUL")
            } else {
                None
            }
        }
        Request::PutProviderCredential {
            provider_id,
            record,
        } => {
            if provider_id.trim().is_empty() {
                Some("provider id must not be empty")
            } else if provider_id.contains('\0') {
                Some("provider id contains NUL")
            } else if provider_id == crate::auth::flycockpit::CREDENTIAL_KEY
                || provider_id.starts_with(crate::auth::subscription_ack::PREFIX)
            {
                Some("provider id is reserved")
            } else if serde_json::from_str::<serde_json::Value>(record).is_err() {
                Some("provider credential record must be valid JSON")
            } else {
                None
            }
        }
        Request::DeleteProviderCredential { provider_id, .. } => {
            if provider_id.trim().is_empty() {
                Some("provider id must not be empty")
            } else if provider_id.contains('\0') {
                Some("provider id contains NUL")
            } else if provider_id == crate::auth::flycockpit::CREDENTIAL_KEY
                || provider_id.starts_with(crate::auth::subscription_ack::PREFIX)
            {
                Some("provider id is reserved")
            } else {
                None
            }
        }
        _ => None,
    };
    if let Some(message) = owner_secret_error {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: format!("invalid {} request: {message}", request.wire_tag()),
        });
    }
    Ok(())
}

/// Load a provider configuration through the daemon's one injected,
/// trust-aware resolver.  Settings and CLI callers deliberately never get a
/// chance to resolve a credential-bearing config on their own.
async fn daemon_provider_config(
    ctx: &DaemonContext,
    project_root: &str,
) -> std::result::Result<
    (
        std::path::PathBuf,
        crate::config::trust::WorkspaceTrustPolicy,
        crate::config::providers::ProvidersConfig,
    ),
    ErrorPayload,
> {
    let cwd = std::path::PathBuf::from(project_root);
    if project_root.trim().is_empty() {
        return Err(bad_request("project_root must not be empty"));
    }
    let trust_policy = crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &cwd)
        .await
        .map_err(internal)?;
    let (config, _) = ctx
        .config_source()
        .load_effective_for_daemon(&cwd, &trust_policy)
        .map_err(daemon_config_error)?;
    Ok((cwd, trust_policy, config))
}

/// Use the attached session's authenticated RefreshEnv overlay when one is
/// available. Detached owner RPCs fall back to the daemon-owned baseline. In
/// neither case do provider operations consult the daemon process's stale
/// startup environment directly.
pub(super) fn provider_env_snapshot(
    ctx: &DaemonContext,
    state: &MutableClientState,
) -> std::collections::HashMap<String, String> {
    state
        .attached
        .as_ref()
        .map(|attached| attached.handle.env_overlay_snapshot())
        .unwrap_or_else(|| {
            ctx.env_baseline
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .vars()
                .clone()
        })
}

async fn provider_catalog_snapshot(
    ctx: &DaemonContext,
    project_root: &str,
    provider_id: Option<&str>,
) -> std::result::Result<Response, ErrorPayload> {
    let _config_lock = CONFIG_PUBLICATION_RPC_LOCK.lock().await;
    recover_provider_config_journals(ctx, project_root, None).await?;
    let (cwd, trust_policy, mut config) = daemon_provider_config(ctx, project_root).await?;
    if let Some(provider_id) = provider_id {
        let Some(entry) = config.providers.remove(provider_id) else {
            return Err(bad_request(format!(
                "provider `{provider_id}` is not configured"
            )));
        };
        config.providers.clear();
        config.providers.insert(provider_id.to_string(), entry);
    }
    let mut view = crate::secret_ref::redact_provider_view(&config);
    view.mcp_config_json = Some(redacted_mcp_config_json(ctx, &cwd, &trust_policy)?);
    view.extended_config_json = Some(redacted_extended_config_json(ctx, &cwd, &trust_policy)?);
    bounded_provider_response(Response::ProviderCatalogSnapshot { config: view })
}

fn redacted_extended_config_json(
    ctx: &DaemonContext,
    cwd: &std::path::Path,
    trust_policy: &crate::config::trust::WorkspaceTrustPolicy,
) -> std::result::Result<String, ErrorPayload> {
    // Owner projection: resolve the extended config through the daemon's
    // trust-aware config source rather than a direct disk primitive, so the
    // session-config boundary ratchet holds and trust gating matches the
    // provider snapshot resolved alongside it.
    let (_, mut extended) = ctx
        .config_source()
        .load_with_trust(cwd, trust_policy)
        .map_err(daemon_config_error)?;
    extended.redact.denylist = extended
        .redact
        .denylist
        .iter()
        .map(|_| "[redacted]".to_string())
        .collect();
    extended.image_generation = extended.image_generation.redacted_for_snapshot();
    serde_json::to_string(&extended).map_err(internal)
}

/// Project the layered MCP config for settings clients without returning any
/// credential-bearing literal. The daemon still reads/parses the config at
/// this owner boundary; the TUI receives only this sanitized projection.
fn redacted_mcp_config_json(
    ctx: &DaemonContext,
    cwd: &std::path::Path,
    trust_policy: &crate::config::trust::WorkspaceTrustPolicy,
) -> std::result::Result<String, ErrorPayload> {
    let paths = daemon_mcp_paths(ctx, cwd, trust_policy)?;
    let mut config = mcp_config_from_paths(&paths)?;
    for server in config.servers.values_mut() {
        server.endpoint = server
            .endpoint
            .as_deref()
            .map(cockpit_proto::redact_url_for_owner_view);
        server.env = server
            .env
            .iter()
            .map(|(name, value)| {
                (
                    name.clone(),
                    if value.trim_start().starts_with('$') {
                        value.clone()
                    } else {
                        "[redacted]".to_string()
                    },
                )
            })
            .collect();
        match &mut server.auth {
            crate::mcp::config::Auth::Header(header) => {
                if !header.value.trim_start().starts_with('$') {
                    header.value = "[redacted]".to_string();
                }
            }
            crate::mcp::config::Auth::Env(env) => {
                env.vars = env
                    .vars
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.clone(),
                            if value.trim_start().starts_with('$') {
                                value.clone()
                            } else {
                                "[redacted]".to_string()
                            },
                        )
                    })
                    .collect();
            }
            crate::mcp::config::Auth::Oauth(oauth) => {
                oauth.authorize_url = oauth
                    .authorize_url
                    .as_deref()
                    .map(cockpit_proto::redact_url_for_owner_view);
                oauth.token_url = oauth
                    .token_url
                    .as_deref()
                    .map(cockpit_proto::redact_url_for_owner_view);
            }
            crate::mcp::config::Auth::None => {}
        }
    }
    serde_json::to_string(&config).map_err(internal)
}

// Model fetch is parameterized by provider/model selectors plus the fetch-mode
// flags and the resolved env; bundling them into a struct buys nothing but
// churn for a cosmetic lint, so allow the count.
#[allow(clippy::too_many_arguments)]
async fn provider_models_fetch(
    ctx: &DaemonContext,
    project_root: &str,
    provider_id: Option<&str>,
    model_id: Option<&str>,
    deep: bool,
    on_unlisted: Option<crate::config::providers::OnUnlistedModelsFetch>,
    allow_fallback: bool,
    env: std::collections::HashMap<String, String>,
) -> std::result::Result<Response, ErrorPayload> {
    let _config_rpc_lock = CONFIG_PUBLICATION_RPC_LOCK.lock().await;
    // Finish an older save/delete intent before deciding whether this request
    // owns a layer entry.  A crash after the file replacement must not turn a
    // later delete into an early no-op that forgets its vault cleanup.
    recover_provider_config_journals(ctx, project_root, provider_id).await?;
    let (cwd, trust_policy, mut config) = daemon_provider_config(ctx, project_root).await?;
    // An all-provider probe is one user-visible operation.  Keep its original
    // catalog until every selected provider has yielded a durable-safe result:
    // persisting the early successes after a later failure would make a retry
    // repeat paid probes against a partially updated catalog.
    let original_config = config.clone();
    let provider_ids = match provider_id {
        Some(provider_id) => {
            if !config.providers.contains_key(provider_id) {
                return Err(bad_request(format!(
                    "provider `{provider_id}` is not configured"
                )));
            }
            vec![provider_id.to_string()]
        }
        None => config.providers.keys().cloned().collect::<Vec<_>>(),
    };
    if provider_ids.is_empty() {
        return bounded_provider_response(Response::ProviderModelsFetched {
            results: Vec::new(),
            config: crate::secret_ref::redact_provider_view(&config),
        });
    }
    // Owner-scoped resolution: model-fetch requests may only resolve `$secret:`
    // names owned by (provider, this project root). This daemon boundary can
    // scan every other known config, so it proves sole-ownership before
    // backfilling an unclaimed legacy name (gap 4). If the scan itself fails (a
    // broken/removed foreign workspace config, or a DB fault), sole-ownership is
    // UNPROVABLE: fall back to no-backfill (owned names still resolve; an
    // unclaimed legacy name fails closed) rather than failing the whole request.
    let canonical_root = crate::secret_ownership::canonical_owner_root(project_root);
    let foreign_refs = foreign_provider_named_references(ctx, &canonical_root)
        .await
        .ok();
    let store = crate::credentials::CredentialStore::from_vault_owner_scoped(
        ctx.secret_vault.clone(),
        crate::secret_ownership::OWNER_KIND_PROVIDER,
        &canonical_root,
        &crate::secret_ref::provider_named_secret_references(&config),
        foreign_refs.as_ref(),
    )
    .map_err(internal)?;
    let selected_policy = on_unlisted
        .or(config.on_unlisted_models_fetch)
        .unwrap_or(crate::config::providers::OnUnlistedModelsFetch::Keep);
    let mut changed_provider_ids = std::collections::BTreeSet::new();
    let results = if deep {
        let (results, completed_provider_ids) =
            daemon_deep_provider_fetch(&mut config, &provider_ids, model_id, store.clone(), &env)
                .await?;
        // A failed provider may have completed an earlier target before its
        // later probe failed. Do not expose or persist that ambiguous partial
        // mutation; retain the original provider snapshot and account only
        // for providers whose complete target set finished successfully.
        for result in &results {
            if matches!(
                &result.outcome,
                crate::daemon::proto::ProviderModelFetchOutcome::Error { .. }
            ) && let Some(original) = original_config.providers.get(&result.provider_id)
            {
                config
                    .providers
                    .insert(result.provider_id.clone(), original.clone());
            }
        }
        changed_provider_ids.extend(completed_provider_ids);
        results
    } else {
        let mut results = Vec::with_capacity(provider_ids.len());
        for provider_id in provider_ids {
            let entry = config
                .providers
                .get(&provider_id)
                .expect("selected provider")
                .clone();
            let resolved =
                crate::providers::models_fetch::resolve_provider_request_async_with_store(
                    &provider_id,
                    &entry,
                    store.clone(),
                    |name| env.get(name).cloned(),
                )
                .await
                .map_err(internal)?;
            let fetched = crate::providers::models_fetch::fetch_models_for_provider_with_store(
                &provider_id,
                &entry,
                &resolved,
                std::time::Duration::from_secs(15),
                Some(store.clone()),
            )
            .await;
            let outcome = match fetched {
                Ok(crate::providers::models_fetch::FetchOutcome::Models { models, catalog }) => {
                    let mut updated = entry.clone();
                    let unlisted = entry
                        .models
                        .iter()
                        .filter(|old| !models.iter().any(|fetched| fetched.id == old.id))
                        .collect::<Vec<_>>();
                    // Ask is an explicit decision point. Do not persist a
                    // fetched list while silently dropping local entries;
                    // the client must retry with Keep or Remove.
                    if selected_policy == crate::config::providers::OnUnlistedModelsFetch::Ask
                        && !unlisted.is_empty()
                    {
                        results.push(crate::daemon::proto::ProviderModelFetchResult {
                            provider_id,
                            outcome: crate::daemon::proto::ProviderModelFetchOutcome::UnlistedModelsPreview {
                                unlisted_count: u32::try_from(unlisted.len()).unwrap_or(u32::MAX),
                            },
                        });
                        continue;
                    }
                    let merge_policy = match selected_policy {
                        crate::config::providers::OnUnlistedModelsFetch::Remove => {
                            crate::config::providers::ModelMergePolicy::RemoveUnlisted
                        }
                        crate::config::providers::OnUnlistedModelsFetch::Ask
                        | crate::config::providers::OnUnlistedModelsFetch::Keep => {
                            crate::config::providers::ModelMergePolicy::KeepUnlisted
                        }
                    };
                    updated.models = crate::config::providers::merge_fetched_models_with_policy(
                        updated.effective_template(&provider_id),
                        &entry.models,
                        models.clone(),
                        merge_policy,
                    );
                    updated.models_fetched_at = Some(chrono::Utc::now());
                    updated.model_catalog = catalog;
                    config.providers.insert(provider_id.clone(), updated);
                    changed_provider_ids.insert(provider_id.clone());
                    crate::daemon::proto::ProviderModelFetchOutcome::Models { models, catalog }
                }
                Ok(crate::providers::models_fetch::FetchOutcome::FallbackAvailable {
                    models,
                    catalog,
                    reason,
                }) => {
                    let reason = crate::config::providers::redact_model_fetch_reason(reason);
                    if allow_fallback {
                        let mut updated = entry.clone();
                        let merge_policy = match selected_policy {
                            crate::config::providers::OnUnlistedModelsFetch::Remove => {
                                crate::config::providers::ModelMergePolicy::RemoveUnlisted
                            }
                            crate::config::providers::OnUnlistedModelsFetch::Ask
                            | crate::config::providers::OnUnlistedModelsFetch::Keep => {
                                crate::config::providers::ModelMergePolicy::KeepUnlisted
                            }
                        };
                        updated.models = crate::config::providers::merge_fetched_models_with_policy(
                            updated.effective_template(&provider_id),
                            &entry.models,
                            models.clone(),
                            merge_policy,
                        );
                        updated.models_fetched_at = Some(chrono::Utc::now());
                        updated.model_catalog = catalog;
                        updated.mark_model_fetch_fallback(reason.clone());
                        config.providers.insert(provider_id.clone(), updated);
                        changed_provider_ids.insert(provider_id.clone());
                    } else {
                        // Preserve the live catalog and persist only the
                        // failure marker. A later --allow-fallback retry can
                        // safely activate the returned fallback catalog.
                        let mut updated = entry.clone();
                        updated.mark_model_fetch_failed_kept_existing(reason.clone());
                        config.providers.insert(provider_id.clone(), updated);
                        changed_provider_ids.insert(provider_id.clone());
                    }
                    crate::daemon::proto::ProviderModelFetchOutcome::FallbackAvailable {
                        models,
                        catalog,
                        reason,
                    }
                }
                Ok(crate::providers::models_fetch::FetchOutcome::Unsupported) => {
                    crate::daemon::proto::ProviderModelFetchOutcome::Unsupported
                }
                Err(error) => crate::daemon::proto::ProviderModelFetchOutcome::Error {
                    message: crate::config::providers::redact_model_fetch_reason(error.to_string()),
                },
            };
            results.push(crate::daemon::proto::ProviderModelFetchResult {
                provider_id,
                outcome,
            });
        }
        results
    };
    let aggregate_fetch_failed = provider_id.is_none()
        && results.iter().any(|result| {
            matches!(
                &result.outcome,
                crate::daemon::proto::ProviderModelFetchOutcome::Error { .. }
            )
        });
    if aggregate_fetch_failed && !deep {
        config = original_config;
        changed_provider_ids.clear();
    }
    if let Some(on_unlisted) = on_unlisted {
        // Keep the aggregate operation all-or-nothing at the config boundary.
        // A caller can make the policy update explicitly rather than coupling
        // it to a failed multi-provider network probe.
        if !aggregate_fetch_failed {
            config.on_unlisted_models_fetch = Some(on_unlisted);
        }
    }
    // Build and bound the exact response before any persistence. Otherwise a
    // large fetched catalog could become durable while the caller receives an
    // error and therefore cannot distinguish a safe retry from a replay.
    let response = Response::ProviderModelsFetched {
        results,
        config: crate::secret_ref::redact_provider_view(&config),
    };
    let response =
        bounded_provider_response(scrub_provider_response(response, &config, &store, &env)?)?;
    for provider_id in changed_provider_ids {
        let entry = config
            .providers
            .get(&provider_id)
            .expect("changed provider remains configured")
            .clone();
        persist_daemon_provider(&cwd, &trust_policy, ctx, &provider_id, entry)?;
    }
    if let Some(on_unlisted) = on_unlisted.filter(|_| !aggregate_fetch_failed) {
        persist_provider_layer_metadata(
            &cwd,
            &trust_policy,
            ctx,
            config.category_defaults.clone(),
            on_unlisted,
        )?;
    }
    Ok(response)
}

async fn daemon_deep_provider_fetch(
    config: &mut crate::config::providers::ProvidersConfig,
    provider_ids: &[String],
    model_id: Option<&str>,
    store: crate::credentials::CredentialStore,
    env: &std::collections::HashMap<String, String>,
) -> std::result::Result<
    (
        Vec<crate::daemon::proto::ProviderModelFetchResult>,
        std::collections::BTreeSet<String>,
    ),
    ErrorPayload,
> {
    use crate::providers::deepfetch::{
        DeepfetchScope, HttpDeepfetchProbeClient, collect_deepfetch_targets, probe_target,
    };
    let scope = DeepfetchScope {
        provider: (provider_ids.len() == 1).then(|| provider_ids[0].clone()),
        model: model_id.map(str::to_string),
    };
    let targets = collect_deepfetch_targets(config, &scope).map_err(internal)?;
    let mut resolved = std::collections::BTreeMap::new();
    let mut failures = std::collections::BTreeMap::new();
    for target in &targets {
        if resolved.contains_key(&target.provider_id) {
            continue;
        }
        let entry = config
            .providers
            .get(&target.provider_id)
            .expect("deepfetch target provider");
        let request = crate::providers::models_fetch::resolve_provider_request_async_with_store(
            &target.provider_id,
            entry,
            store.clone(),
            |name| env.get(name).cloned(),
        )
        .await;
        match request {
            Ok(request) => {
                resolved.insert(target.provider_id.clone(), request);
            }
            Err(error) => {
                failures.insert(
                    target.provider_id.clone(),
                    crate::config::providers::redact_model_fetch_reason(error.to_string()),
                );
            }
        }
    }
    let mut client = HttpDeepfetchProbeClient::new(resolved, std::time::Duration::from_secs(20));
    for target in &targets {
        if failures.contains_key(&target.provider_id) {
            continue;
        }
        if let Err(error) = probe_target(&mut client, config, target).await {
            failures.insert(
                target.provider_id.clone(),
                crate::config::providers::redact_model_fetch_reason(error.to_string()),
            );
        }
    }
    // Persistence happens only after the caller has a bounded complete
    // response; see `provider_models_fetch`.
    let completed = provider_ids
        .iter()
        .filter(|provider_id| !failures.contains_key(*provider_id))
        .filter(|provider_id| {
            targets
                .iter()
                .any(|target| &target.provider_id == *provider_id)
        })
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    Ok((
        provider_ids
            .iter()
            .filter_map(|provider_id| {
                config.providers.get(provider_id).map(|entry| {
                    let outcome = failures.get(provider_id).map_or_else(
                        || crate::daemon::proto::ProviderModelFetchOutcome::Models {
                            models: entry.models.clone(),
                            catalog: entry.model_catalog,
                        },
                        |message| crate::daemon::proto::ProviderModelFetchOutcome::Error {
                            message: message.clone(),
                        },
                    );
                    crate::daemon::proto::ProviderModelFetchResult {
                        provider_id: provider_id.clone(),
                        outcome,
                    }
                })
            })
            .collect(),
        completed,
    ))
}

async fn provider_usage_snapshot(
    ctx: &DaemonContext,
    project_root: &str,
    provider_id: Option<&str>,
    env: std::collections::HashMap<String, String>,
) -> std::result::Result<Response, ErrorPayload> {
    let _config_lock = CONFIG_PUBLICATION_RPC_LOCK.lock().await;
    recover_provider_config_journals(ctx, project_root, None).await?;
    let (_, _, config) = daemon_provider_config(ctx, project_root).await?;
    // Owner-scoped resolution: usage probes may only resolve `$secret:` names
    // owned by (provider, this project root). This daemon boundary scans every
    // other known config to prove sole-ownership before backfilling (gap 4). A
    // scan failure makes sole-ownership unprovable, so fall back to no-backfill
    // (owned names still resolve) rather than failing the whole request.
    let canonical_root = crate::secret_ownership::canonical_owner_root(project_root);
    let foreign_refs = foreign_provider_named_references(ctx, &canonical_root)
        .await
        .ok();
    let store = crate::credentials::CredentialStore::from_vault_owner_scoped(
        ctx.secret_vault.clone(),
        crate::secret_ownership::OWNER_KIND_PROVIDER,
        &canonical_root,
        &crate::secret_ref::provider_named_secret_references(&config),
        foreign_refs.as_ref(),
    )
    .map_err(internal)?;
    let rows = crate::providers::usage::probes::fetch_all_provider_usage_with_store(
        &config,
        provider_id,
        Some(store.clone()),
        env.clone(),
    )
    .await
    .map_err(internal)?;
    bounded_provider_response(Response::ProviderUsageSnapshot {
        snapshots: rows
            .into_iter()
            .map(|row| provider_usage_view(row, &store, &config, &env))
            .collect(),
    })
}

/// Provider catalog, discovery, and usage responses all travel on the
/// interactive RPC lane.  Reject an oversized complete response before it is
/// handed to the transport: sending a prefix (or relying on a later transport
/// failure) would make the client observe ambiguous partial state.
pub(super) fn bounded_provider_response(
    response: Response,
) -> std::result::Result<Response, ErrorPayload> {
    let encoded = serde_json::to_vec(&response).map_err(internal)?;
    if encoded.len() > proto::MAX_INTERACTIVE_RPC_PAYLOAD_BYTES {
        return Err(bad_request(
            "provider response exceeds the interactive payload limit; narrow the provider or model selection",
        ));
    }
    Ok(response)
}

fn validate_unique_provider_header_names(
    headers: &[crate::config::providers::HeaderSpec],
) -> std::result::Result<(), ErrorPayload> {
    let mut names = std::collections::BTreeSet::new();
    for header in headers {
        let normalized = header.name.trim().to_ascii_lowercase();
        if !names.insert(normalized) {
            return Err(bad_request(
                "provider header names must be unique (case-insensitive)",
            ));
        }
    }
    Ok(())
}

fn provider_usage_view(
    row: crate::providers::usage::ProviderUsageSnapshot,
    store: &crate::credentials::CredentialStore,
    config: &crate::config::providers::ProvidersConfig,
    env: &std::collections::HashMap<String, String>,
) -> crate::daemon::proto::ProviderUsageSnapshotView {
    use crate::daemon::proto::{ProviderUsageAvailabilityView as Wire, ProviderUsageWindowView};
    use crate::providers::usage::UsageAvailability;
    let availability = match row.availability {
        UsageAvailability::Fetched {
            source,
            plan,
            windows,
            details,
        } => Wire::Fetched {
            source: source.to_string(),
            plan: plan.map(|value| redact_provider_response_text(&value, store, config, env)),
            windows: windows
                .into_iter()
                .enumerate()
                .map(|(index, window)| ProviderUsageWindowView {
                    label: format!("window {}", index + 1),
                    used_percent: window.used_percent,
                    reset_at: window.reset_at,
                    detail: window
                        .detail
                        .map(|value| redact_provider_response_text(&value, store, config, env)),
                })
                .collect(),
            details: details
                .into_iter()
                .map(|value| redact_provider_response_text(&value, store, config, env))
                .collect(),
        },
        UsageAvailability::Unsupported { reason } => Wire::Unsupported {
            reason: redact_provider_response_text(reason, store, config, env),
        },
        UsageAvailability::Unavailable {
            reason,
            hint_url: _hint_url,
        } => Wire::Unavailable {
            reason: redact_provider_response_text(&reason, store, config, env),
            hint_url: None,
        },
        UsageAvailability::Error { message } => Wire::Error {
            message: redact_provider_response_text(&message, store, config, env),
        },
    };
    crate::daemon::proto::ProviderUsageSnapshotView {
        provider_id: redact_provider_response_text(&row.provider_id, store, config, env),
        display_name: redact_provider_response_text(&row.display_name, store, config, env),
        fetched_at: row.fetched_at,
        availability,
    }
}

fn redact_provider_response_text(
    text: &str,
    store: &crate::credentials::CredentialStore,
    config: &crate::config::providers::ProvidersConfig,
    env: &std::collections::HashMap<String, String>,
) -> String {
    redact_provider_response_text_with_values(
        text,
        provider_response_secret_values(store, config, env),
    )
}

pub(super) fn redact_provider_response_text_with_values(
    text: &str,
    secret_values: impl IntoIterator<Item = String>,
) -> String {
    let mut value = text.to_string();
    for secret in secret_values {
        if !secret.is_empty() {
            value = value.replace(&secret, "[redacted]");
        }
    }
    crate::config::providers::redact_model_fetch_reason(value)
}

/// Provider APIs can reflect credentials in error, quota, and even catalog
/// fields. Header-backed environment values therefore join vault values in
/// the daemon's response scrubber.
fn provider_response_secret_values(
    store: &crate::credentials::CredentialStore,
    config: &crate::config::providers::ProvidersConfig,
    env: &std::collections::HashMap<String, String>,
) -> std::collections::BTreeSet<String> {
    let mut values = store
        .named_secret_entries()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .chain(store.provider_credential_entries())
        .chain(store.provider_credential_leaf_entries())
        .map(|(_, value)| value)
        .filter(|value| !value.is_empty())
        .collect::<std::collections::BTreeSet<_>>();
    values.extend(configured_provider_env_values(config, |name| {
        env.get(name).cloned()
    }));
    values
}

pub(super) fn configured_provider_env_values<F>(
    config: &crate::config::providers::ProvidersConfig,
    lookup: F,
) -> std::collections::BTreeSet<String>
where
    F: Fn(&str) -> Option<String>,
{
    config
        .providers
        .values()
        .flat_map(|entry| &entry.headers)
        .flat_map(|header| crate::envref::referenced_names(&header.value))
        .filter(|name| !name.starts_with("secret:"))
        .filter_map(|name| lookup(&name))
        .filter(|value| !value.is_empty())
        .collect()
}

/// Fetch results contain upstream-owned strings such as model labels and
/// diagnostics. Traverse their typed wire representation as a final barrier
/// so a reflected environment credential cannot reach a client.
pub(super) fn scrub_provider_response(
    response: Response,
    config: &crate::config::providers::ProvidersConfig,
    store: &crate::credentials::CredentialStore,
    env: &std::collections::HashMap<String, String>,
) -> std::result::Result<Response, ErrorPayload> {
    fn scrub_value(value: &mut serde_json::Value, secret_values: &[String]) {
        match value {
            serde_json::Value::String(text) => {
                *text =
                    redact_provider_response_text_with_values(text, secret_values.iter().cloned());
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    scrub_value(item, secret_values);
                }
            }
            serde_json::Value::Object(fields) => {
                for value in fields.values_mut() {
                    scrub_value(value, secret_values);
                }
            }
            _ => {}
        }
    }

    let secret_values = provider_response_secret_values(store, config, env)
        .into_iter()
        .collect::<Vec<_>>();
    let mut value = serde_json::to_value(response).map_err(internal)?;
    scrub_value(&mut value, &secret_values);
    serde_json::from_value(value).map_err(internal)
}

async fn provider_config_upsert(
    ctx: &DaemonContext,
    project_root: &str,
    provider_id: &str,
    mut entry: crate::config::providers::ProviderEntry,
) -> std::result::Result<Response, ErrorPayload> {
    if provider_id.trim().is_empty() {
        return Err(bad_request("provider_id must not be empty"));
    }
    // Upsert is also used by redacted settings projections. A missing
    // credential_ref means “unchanged” in that projection, never removal.
    if entry.credential_ref.is_none() {
        let (_, _, current) = daemon_provider_config(ctx, project_root).await?;
        if let Some(existing) = current.providers.get(provider_id) {
            entry.credential_ref = existing.credential_ref.clone();
        }
    }
    let header_secrets = vec![None; entry.headers.len()];
    provider_config_save(ctx, project_root, provider_id, entry, header_secrets).await
}

/// Configure Copilot without exposing its credential to a client.  The daemon
/// is the only component allowed to inspect its environment and the only
/// component that stages the resulting secret through `provider_config_save`.
async fn setup_copilot_auth(
    ctx: &DaemonContext,
    project_root: &str,
    provider_id: &str,
    env: std::collections::HashMap<String, String>,
    is_local_owner: bool,
) -> std::result::Result<(), ErrorPayload> {
    // Adopting the daemon HOST's ambient GitHub token (`COPILOT_GITHUB_TOKEN` /
    // `GH_TOKEN` / `GITHUB_TOKEN`) and injecting it into a caller-selected
    // provider's `Authorization` header is a local-host action: the chosen
    // provider's base URL is caller-controllable, so a REMOTE owner could steer
    // the host's ambient token to an attacker endpoint (the token would then
    // leave the host on every later request to that provider). Gate the ambient
    // adoption on the authentic local-owner signal and fail closed for a remote
    // caller BEFORE the token is ever read — a remote owner must authenticate
    // the provider through the explicit OAuth flow instead.
    if !is_local_owner {
        return Err(bad_request(
            "adopting the daemon host's ambient GitHub token is local-only; a remote owner must authenticate the provider through the explicit OAuth flow",
        ));
    }
    let token = ["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"]
        .into_iter()
        .find_map(|name| env.get(name).filter(|value| !value.trim().is_empty()))
        .cloned()
        .ok_or_else(|| {
            bad_request(
                "Copilot authentication is unavailable in the daemon environment; set COPILOT_GITHUB_TOKEN, GH_TOKEN, or GITHUB_TOKEN for the daemon",
            )
        })?;
    let (_, _, config) = daemon_provider_config(ctx, project_root).await?;
    let mut entry = config
        .providers
        .get(provider_id)
        .cloned()
        .ok_or_else(|| bad_request(format!("provider `{provider_id}` is not configured")))?;
    let auth_index = entry
        .headers
        .iter()
        .position(|header| header.name.eq_ignore_ascii_case("authorization"));
    let mut header_secrets = vec![None; entry.headers.len()];
    let index = if let Some(index) = auth_index {
        index
    } else {
        entry.headers.push(crate::config::providers::HeaderSpec {
            name: "Authorization".into(),
            value: "$secret:copilot".into(),
        });
        header_secrets.push(None);
        entry.headers.len() - 1
    };
    header_secrets[index] = Some(token);
    provider_config_save(ctx, project_root, provider_id, entry, header_secrets).await?;
    Ok(())
}

#[derive(serde::Deserialize)]
struct ProviderConfigJournal {
    journal_id: String,
    provider_id: String,
    action: String,
    entry_json: Option<String>,
    cleanup_named_json: String,
    cleanup_credential_json: String,
}

fn provider_owned_secret_references(
    entry: &crate::config::providers::ProviderEntry,
) -> (
    std::collections::BTreeSet<String>,
    std::collections::BTreeSet<String>,
) {
    let named = entry
        .headers
        .iter()
        .flat_map(|header| crate::envref::referenced_names(&header.value))
        .filter_map(|name| name.strip_prefix("secret:").map(str::to_string))
        .collect();
    let credentials = entry.credential_ref.iter().cloned().collect();
    (named, credentials)
}

/// Upsert is a reference-only provider write. A caller may not introduce an
/// arbitrary `$secret:` name unless the daemon already has a durable provider
/// claim for it (staged provider saves create that claim transactionally).
/// This prevents a config-only write from acquiring an untracked vault row
/// that later delete/recovery paths cannot safely account for.
async fn ensure_provider_named_references_claimed(
    ctx: &DaemonContext,
    project_root: &str,
    entry: &crate::config::providers::ProviderEntry,
) -> std::result::Result<(), ErrorPayload> {
    let (names, _) = provider_owned_secret_references(entry);
    if names.is_empty() {
        return Ok(());
    }
    let root = project_root.to_owned();
    let names = names.into_iter().collect::<Vec<_>>();
    for name in names {
        if ctx
            .secret_vault
            .get_item(
                cockpit_db::secret_vault::SecretVaultKind::NamedSecret,
                &name,
            )
            .is_err()
        {
            return Err(bad_request(format!(
                "provider secret reference `{name}` is not a daemon-owned staged secret"
            )));
        }
        let name_for_query = name.clone();
        let root_for_query = root.clone();
        let claimed = ctx
            .db
            .read(move |conn| {
                let claimed = conn.query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM secret_named_ownership
                         WHERE item_id = ?1 AND owner_kind = 'provider' AND project_root = ?2
                     )",
                    rusqlite::params![name_for_query, root_for_query],
                    |row| row.get::<_, bool>(0),
                )?;
                Ok(claimed)
            })
            .await
            .map_err(internal)?;
        if !claimed {
            return Err(bad_request(format!(
                "provider secret reference `{name}` has no durable provider claim"
            )));
        }
    }
    Ok(())
}

async fn ensure_provider_credential_reference_available(
    ctx: &DaemonContext,
    entry: &crate::config::providers::ProviderEntry,
) -> std::result::Result<(), ErrorPayload> {
    if let Some(reference) = entry.credential_ref.as_deref()
        && ctx
            .secret_vault
            .get_item(
                cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
                reference,
            )
            .is_err()
    {
        return Err(bad_request(format!(
            "provider credential reference `{reference}` is not present in the daemon vault"
        )));
    }
    Ok(())
}

/// Only names minted by a provider-save operation are safe for automatic
/// cleanup. The vault is shared by all workspaces, while journal rows are
/// scoped to one workspace; a journal cannot prove that a user-chosen name
/// is unowned elsewhere without a global ownership index. Provider saves use
/// `provider-{slug}-{journal UUID}-{index}`.
fn is_operation_owned_secret_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("provider-") else {
        return false;
    };
    let parts = rest.split('-').collect::<Vec<_>>();
    parts
        .windows(5)
        .any(|window| Uuid::parse_str(&window.join("-")).is_ok())
}

#[cfg(test)]
mod operation_owned_secret_tests {
    use super::{
        is_operation_owned_secret_name, mcp_secret_references,
        validate_unique_provider_header_names,
    };

    #[test]
    fn only_provider_journal_names_are_eligible_for_automatic_cleanup() {
        assert!(is_operation_owned_secret_name(
            "provider-openai-018f0f2e-6c3b-7b42-ae1a-8e2b8a6f4d11-0"
        ));
        assert!(!is_operation_owned_secret_name("mcp:server:header"));
        assert!(!is_operation_owned_secret_name(
            "provider-openai-user-token"
        ));
        assert!(!is_operation_owned_secret_name("mcp:server"));
        assert!(!is_operation_owned_secret_name("user-chosen-token"));
    }

    #[test]
    fn provider_header_names_are_unique_case_insensitively() {
        let unique = vec![
            crate::config::providers::HeaderSpec {
                name: "Authorization".into(),
                value: "$secret:one".into(),
            },
            crate::config::providers::HeaderSpec {
                name: "X-Trace".into(),
                value: "$secret:two".into(),
            },
        ];
        assert!(validate_unique_provider_header_names(&unique).is_ok());

        let duplicate = vec![
            crate::config::providers::HeaderSpec {
                name: "Authorization".into(),
                value: "********".into(),
            },
            crate::config::providers::HeaderSpec {
                name: "authorization".into(),
                value: "********".into(),
            },
        ];
        let error = validate_unique_provider_header_names(&duplicate).unwrap_err();
        assert_eq!(error.code, cockpit_proto::ErrorCode::BadRequest);
        assert!(error.message.contains("case-insensitive"));
    }

    #[test]
    fn mcp_oauth_servers_protect_their_named_token_reference() {
        let server: crate::mcp::config::ServerConfig = serde_json::from_value(serde_json::json!({
            "transport": "streamable",
            "auth": { "kind": "oauth" }
        }))
        .expect("valid MCP OAuth server");
        let refs = mcp_secret_references("example", &server);
        assert!(refs.contains(&crate::mcp::auth::cred_key("example")));
    }
}

pub(super) async fn recover_provider_config_journals(
    ctx: &DaemonContext,
    project_root: &str,
    provider_id: Option<&str>,
) -> std::result::Result<(), ErrorPayload> {
    let project_root = project_root.to_string();
    let provider_id = provider_id.map(str::to_string);
    let project_root_query = project_root.clone();
    let journals = ctx
        .db
        .read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT journal_id, provider_id, action, entry_json, cleanup_named_json, cleanup_credential_json
                 FROM provider_config_journals WHERE project_root = ?1 AND (?2 IS NULL OR provider_id = ?2)
                 ORDER BY created_at, journal_id",
            )?;
            statement
                .query_map(rusqlite::params![project_root_query, provider_id], |row| {
                    Ok(ProviderConfigJournal {
                        journal_id: row.get(0)?,
                        provider_id: row.get(1)?,
                        action: row.get(2)?,
                        entry_json: row.get(3)?,
                        cleanup_named_json: row.get(4)?,
                        cleanup_credential_json: row.get(5)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Into::into)
        })
        .await
        .map_err(internal)?;
    for journal in journals {
        let (cwd, trust_policy, _) = daemon_provider_config(ctx, project_root.as_str()).await?;
        match journal.action.as_str() {
            "save" => {
                let entry: crate::config::providers::ProviderEntry =
                    serde_json::from_str(journal.entry_json.as_deref().ok_or_else(|| {
                        bad_request("provider save journal is missing its reference-only entry")
                    })?)
                    .map_err(internal)?;
                // Recovery re-applies a journaled entry, but a journaled entry
                // is NOT trusted to still be valid at replay time — it must run
                // the SAME validation funnel as the create path
                // (`provider_config_save`). Between journaling and recovery a
                // referenced credential record or named secret can be logged
                // out / deleted (dead reference), and the URL/header invariants
                // must still hold. On any validation failure we FAIL CLOSED:
                // the `?` aborts before the journal-deletion below, so the
                // journal is RETAINED for a later attempt rather than
                // republishing config that points at a dead reference.
                validate_daemon_provider_url(&entry.url)?;
                validate_unique_provider_header_names(&entry.headers)?;
                ensure_provider_named_references_claimed(ctx, project_root.as_str(), &entry)
                    .await?;
                ensure_provider_credential_reference_available(ctx, &entry).await?;
                persist_daemon_provider(&cwd, &trust_policy, ctx, &journal.provider_id, entry)?;
            }
            "delete" => {
                let path = crate::config::trust::with_workspace_trust_policy(trust_policy, || {
                    ctx.config_source()
                        .config_write_target_for_provider(&cwd, &journal.provider_id)
                })
                .ok_or_else(|| bad_request("no cockpit config found"))?;
                let mut doc = crate::config::providers::ConfigDoc::load(&path).map_err(internal)?;
                let mut layer = doc.providers();
                if layer.providers.remove(&journal.provider_id).is_some() {
                    doc.write(&layer).map_err(internal)?;
                }
            }
            _ => return Err(bad_request("provider config journal has an invalid action")),
        }
        let (_, _, effective) = daemon_provider_config(ctx, project_root.as_str()).await?;
        let mut named: std::collections::BTreeSet<String> =
            serde_json::from_str(&journal.cleanup_named_json).map_err(internal)?;
        let mut credentials: std::collections::BTreeSet<String> =
            serde_json::from_str(&journal.cleanup_credential_json).map_err(internal)?;
        for provider in effective.providers.values() {
            let (used_named, used_credentials) = provider_owned_secret_references(provider);
            for name in used_named {
                named.remove(&name);
            }
            for reference in used_credentials {
                credentials.remove(&reference);
            }
        }
        // MCP and provider entries share the named-secret namespace. A
        // provider journal must not delete a name still live in MCP config.
        for name in mcp_global_live_secret_references(ctx, project_root.as_str()).await? {
            named.remove(&name);
        }
        let live_credentials =
            provider_global_live_credential_references(ctx, project_root.as_str()).await?;
        let _secret_lock = SECRET_OWNER_RPC_LOCK.lock().await;
        for name in named {
            if !is_operation_owned_secret_name(&name) {
                continue;
            }
            if !release_named_secret_ownership(ctx, &name, "provider", &project_root).await? {
                retire_named_secret_ownership(ctx, &name, "provider", &project_root).await?;
                continue;
            }
            delete_owned_named_secret(ctx, &name, "provider", &project_root).await?;
        }
        for reference in credentials {
            let sole_claim =
                release_credential_ownership(ctx, &reference, &journal.provider_id, &project_root)
                    .await?;
            retire_credential_ownership(ctx, &reference, &journal.provider_id, &project_root)
                .await?;
            if !live_credentials.contains(&reference) && sole_claim.is_none_or(|sole| sole) {
                ctx.mutate_owner_vault_item(
                    cockpit_db::secret_vault::SecretVaultKind::CredentialRecord,
                    &reference,
                    None,
                )
                .map_err(internal)?;
            }
        }
        let journal_id = journal.journal_id;
        ctx.db
            .write(move |conn| {
                conn.execute(
                    "DELETE FROM provider_config_journals WHERE journal_id = ?1",
                    rusqlite::params![journal_id],
                )?;
                Ok(())
            })
            .await
            .map_err(internal)?;
    }
    Ok(())
}

#[cfg(any(unix, test))]
pub(super) async fn recover_all_provider_config_journals(
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let roots: Vec<String> = ctx
        .db
        .read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT project_root FROM provider_config_journals
                 UNION SELECT project_root FROM secret_named_ownership
                 UNION SELECT project_root FROM secret_credential_ownership
                 ORDER BY project_root",
            )?;
            stmt.query_map([], |row| row.get(0))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Into::into)
        })
        .await
        .map_err(internal)?;
    for root in roots {
        recover_provider_config_journals(ctx, &root, None).await?;
    }
    Ok(())
}

/// Compensate a staged provider save in one SQLite transaction.  The vault
/// rows and their recovery journal are one durable unit: if any deletion or
/// the journal retirement fails, SQLite rolls back every deletion and leaves
/// the journal available for recovery on the next daemon start.
async fn compensate_provider_config_save(
    ctx: &DaemonContext,
    journal_id: &str,
    staged_named: &[String],
    credential_ref: Option<&str>,
) -> std::result::Result<(), ErrorPayload> {
    let journal_id = journal_id.to_owned();
    let staged_named = staged_named.to_vec();
    let credential_ref = credential_ref.map(str::to_owned);
    let vault = ctx.secret_vault.clone();
    ctx.db
        .transaction(move |conn| {
            for name in &staged_named {
                vault
                    .delete_item_on_conn(
                        conn,
                        cockpit_db::secret_vault::SecretVaultKind::NamedSecret,
                        name,
                    )
                    .map_err(|error| anyhow::anyhow!(error))?;
                conn.execute(
                    "DELETE FROM secret_named_ownership
                     WHERE item_id = ?1 AND owner_kind = 'provider'
                       AND project_root = (SELECT project_root FROM provider_config_journals WHERE journal_id = ?2)
                       AND created_at >= (SELECT created_at FROM provider_config_journals WHERE journal_id = ?2)",
                    rusqlite::params![name, journal_id],
                )?;
            }
            if let Some(reference) = credential_ref {
                conn.execute(
                    "DELETE FROM secret_credential_ownership
                     WHERE item_id = ?1
                       AND provider_id = (SELECT provider_id FROM provider_config_journals WHERE journal_id = ?2)
                       AND project_root = (SELECT project_root FROM provider_config_journals WHERE journal_id = ?2)
                       AND created_at >= (SELECT created_at FROM provider_config_journals WHERE journal_id = ?2)",
                    rusqlite::params![reference, journal_id],
                )?;
            }
            conn.execute(
                "DELETE FROM provider_config_journals WHERE journal_id = ?1",
                rusqlite::params![journal_id],
            )?;
            Ok(())
        })
        .await
        .map_err(internal)
}

async fn provider_config_save(
    ctx: &DaemonContext,
    project_root: &str,
    provider_id: &str,
    mut entry: crate::config::providers::ProviderEntry,
    mut header_secrets: Vec<Option<String>>,
) -> std::result::Result<Response, ErrorPayload> {
    let _config_rpc_lock = CONFIG_PUBLICATION_RPC_LOCK.lock().await;
    // Canonicalize the workspace root once, at this daemon boundary, so every
    // ownership claim, journal, recovery, and owner-scoped read below keys on the
    // same symlink-resolved form the authz layer and resolution paths use — a
    // symlink/trailing-slash spelling can't split the claim from resolution.
    let project_root_canon = crate::secret_ownership::canonical_owner_root(project_root);
    let project_root = project_root_canon.as_str();
    // Defense in depth: typed in-process callers must not be able to bypass
    // the protocol ingress validator and journal a credential-bearing URL.
    validate_daemon_provider_url(&entry.url)?;
    validate_unique_provider_header_names(&entry.headers)?;
    recover_provider_config_journals(ctx, project_root, Some(provider_id)).await?;
    if header_secrets.len() != entry.headers.len() {
        return Err(bad_request(
            "provider header secret count does not match headers",
        ));
    }
    let (_, _, config) = daemon_provider_config(ctx, project_root).await?;
    let old_references = config
        .providers
        .get(provider_id)
        .map(provider_owned_secret_references)
        .unwrap_or_default();
    // Validate only references present in the caller's projection. Header
    // secrets staged below intentionally receive new daemon-owned names that
    // do not exist until the journal/vault transaction commits.
    ensure_provider_named_references_claimed(ctx, project_root, &entry).await?;
    // Settings receives only redacted header values after a successful save.
    // Treat its non-secret marker as an instruction to retain the daemon's
    // existing value; otherwise every subsequent save would either rotate or
    // fail validation despite no user edit.
    if let Some(old_entry) = config.providers.get(provider_id) {
        validate_unique_provider_header_names(&old_entry.headers)?;
        for (index, header) in entry.headers.iter_mut().enumerate() {
            if header.value.trim() == "********"
                && let Some(old_header) = old_entry
                    .headers
                    .iter()
                    .find(|candidate| candidate.name.eq_ignore_ascii_case(&header.name))
            {
                header.value.clone_from(&old_header.value);
            }
            // A redacted snapshot intentionally omits legacy literal values.
            // If the marker restored the daemon's old literal, stage that
            // value here so migration remains daemon-owned and atomic.
            if header_secrets[index].is_none()
                && !header.value.trim().is_empty()
                && !crate::config::providers::is_safe_provider_header_reference(
                    &header.name.to_ascii_lowercase(),
                    &header.value,
                )
            {
                header_secrets[index] = Some(header.value.clone());
            }
        }
    }
    let journal_id = Uuid::now_v7().to_string();
    let provider_slug = provider_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(48)
        .collect::<String>();
    let mut staged = Vec::new();
    for (index, (header, secret)) in entry.headers.iter_mut().zip(header_secrets).enumerate() {
        if let Some(secret) = secret {
            if secret.is_empty() {
                return Err(bad_request("provider header secret must not be empty"));
            }
            let name = format!("provider-{}-{}-{index}", provider_slug, journal_id);
            header.value = format!("$secret:{name}");
            staged.push((name, secret));
        } else if !header.value.is_empty()
            && !crate::config::providers::is_safe_provider_header_reference(
                &header.name.to_ascii_lowercase(),
                &header.value,
            )
        {
            return Err(bad_request(
                "provider header values must use a reference or be staged as secrets",
            ));
        }
    }
    let entry_json = serde_json::to_string(&entry).map_err(internal)?;
    let named_json = serde_json::to_string(&old_references.0).map_err(internal)?;
    let credentials_json = serde_json::to_string(&old_references.1).map_err(internal)?;
    ensure_provider_credential_reference_available(ctx, &entry).await?;
    // Existing static `$secret:` header references that are NOT freshly staged
    // in this save must be re-verified atomically with the publish below,
    // symmetric with the MCP writer. `ensure_provider_named_references_claimed`
    // validated them in a pre-transaction read, but a cross-process actor could
    // rotate the claim (e.g. an MCP save claiming the same shared name) between
    // that read and this commit; without an in-transaction re-check a provider
    // save could stomp / consume an mcp-owned name in the same racy way.
    let staged_name_set = staged
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let static_named_refs = provider_owned_secret_references(&entry)
        .0
        .into_iter()
        .filter(|name| !staged_name_set.contains(name))
        .collect::<std::collections::BTreeSet<_>>();
    let project_root_owned = project_root.to_string();
    let provider_id_owned = provider_id.to_string();
    let journal_id_owned = journal_id.clone();
    let vault = ctx.secret_vault.clone();
    let staged_for_tx = staged.clone();
    let credential_ref_for_tx = entry.credential_ref.clone();
    let static_named_refs_for_tx = static_named_refs.clone();
    ctx.db.transaction(move |conn| {
        // Atomic backstop for the non-staged static header references: each must
        // still be owned by this exact provider/root with a live vault row,
        // verified on THIS connection under the writer lock (fails closed on a
        // conflict, rolling the whole save back).
        for reference in &static_named_refs_for_tx {
            ensure_static_named_reference_owned_on_conn(
                conn,
                &vault,
                reference,
                "provider",
                &project_root_owned,
            )?;
        }
        for (name, secret) in &staged_for_tx {
            // ATOMIC cross-kind admission, symmetric with the MCP writer:
            // re-check ownership INSIDE the same `BEGIN IMMEDIATE` transaction
            // that writes the vault value and inserts the provider claim. These
            // are freshly minted per-save names, but an atomic guard here (not
            // just `INSERT OR IGNORE`) fails closed rather than silently
            // coexisting should any name ever collide with a foreign owner.
            reject_conflicting_named_ownership_on_conn(conn, name, "provider", &project_root_owned)?;
            vault.put_item_on_conn(conn, cockpit_db::secret_vault::SecretVaultKind::NamedSecret, name, secret.as_bytes())?;
            conn.execute(
                "INSERT OR IGNORE INTO secret_named_ownership
                 (item_id, owner_kind, project_root, created_at)
                 VALUES (?1, 'provider', ?2, ?3)",
                rusqlite::params![name, project_root_owned, chrono::Utc::now().timestamp_millis()],
            )?;
        }
        if let Some(reference) = credential_ref_for_tx {
            conn.execute(
                "INSERT OR IGNORE INTO secret_credential_ownership
                 (item_id, provider_id, project_root, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    reference,
                    provider_id_owned.clone(),
                    project_root_owned.clone(),
                    chrono::Utc::now().timestamp_millis()
                ],
            )?;
        }
        conn.execute(
            "INSERT INTO provider_config_journals (journal_id, project_root, provider_id, action, entry_json, cleanup_named_json, cleanup_credential_json, created_at)
             VALUES (?1, ?2, ?3, 'save', ?4, ?5, ?6, ?7)",
            rusqlite::params![journal_id_owned, project_root_owned, provider_id_owned, entry_json, named_json, credentials_json, chrono::Utc::now().timestamp_millis()],
        )?;
        Ok(())
    }).await.map_err(map_named_secret_tx_error)?;
    // The staged writes above intentionally bypass `mutate_owner_vault_item`
    // so they can share one SQLite transaction with the recovery journal. Do
    // not acknowledge (or persist the config) until the live redaction table
    // includes those newly-created values. A publication failure is a
    // fail-closed operation: compensate the staged rows and retire the
    // journal, then poison the daemon if compensation itself cannot complete.
    if let Err(publication_error) = ctx.publish_owner_redaction_table() {
        let staged_names = staged
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        let rollback_error = compensate_provider_config_save(
            ctx,
            &journal_id,
            &staged_names,
            entry.credential_ref.as_deref(),
        )
        .await
        .err()
        .map(|error| anyhow::anyhow!(error.message));
        let error = if let Some(rollback_error) = rollback_error {
            anyhow::anyhow!(
                "provider secret redaction publication failed: {publication_error}; compensation failed: {rollback_error}"
            )
        } else {
            publication_error
        };
        ctx.poison_redaction_publication(&error);
        return Err(internal(error));
    }
    recover_provider_config_journals(ctx, project_root, Some(provider_id)).await?;
    let (_, _, final_config) = daemon_provider_config(ctx, project_root).await?;
    Ok(Response::ProviderConfigUpserted {
        config: crate::secret_ref::redact_provider_view(&final_config),
    })
}

/// Save the complete MCP layer through the daemon. The client supplies only
/// a reference-bearing JSON projection plus staged named-secret values; the
/// daemon owns vault staging, config publication, redaction publication, and
/// cleanup of refs made stale by delete/rename edits.
async fn save_mcp_config(
    ctx: &DaemonContext,
    project_root: &str,
    config_json: &str,
    secret_values_json: &str,
    _cleanup_names_json: &str,
) -> std::result::Result<Response, ErrorPayload> {
    let _lock = CONFIG_PUBLICATION_RPC_LOCK.lock().await;
    // Canonicalize the workspace root once at this daemon boundary so every
    // ownership claim/guard/journal below (and later resolution) keys on the
    // same symlink-resolved form. The CLI (`cockpit mcp add`) sends a raw cwd;
    // canonicalizing here is what makes that raw wire spelling consistent.
    let project_root_canon = crate::secret_ownership::canonical_owner_root(project_root);
    let project_root = project_root_canon.as_str();
    recover_mcp_config_journals(ctx, project_root).await?;
    let mut config: crate::mcp::config::McpConfig =
        crate::mcp::config::McpConfig::parse(config_json).map_err(internal)?;
    let secret_values: std::collections::BTreeMap<String, String> =
        serde_json::from_str(secret_values_json)
            .map_err(|error| bad_request(format!("invalid MCP secret values: {error}")))?;
    for (name, value) in &secret_values {
        if name.is_empty() || name.len() > cockpit_proto::MAX_OWNER_SECRET_NAME_BYTES {
            return Err(bad_request("MCP secret name exceeds maximum length"));
        }
        if value.is_empty() || value.len() > cockpit_proto::MAX_OWNER_SECRET_VALUE_BYTES {
            return Err(bad_request("MCP secret value exceeds maximum length"));
        }
    }
    // The owner RPC is the final custody boundary.  Do not rely on the TUI's
    // editor to turn credential-bearing MCP fields into references: callers
    // can invoke this production path directly.  Normalize values supplied
    // alongside a staged secret, and reject every other literal before either
    // the vault transaction or config publication starts.
    validate_and_normalize_mcp_credentials(&mut config, &secret_values)?;
    let cwd = std::path::PathBuf::from(project_root);
    let trust_policy = crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &cwd)
        .await
        .map_err(workspace_trust_error)?;
    let mcp_paths = daemon_mcp_paths(ctx, &cwd, &trust_policy)?;
    let target = mcp_paths.last().cloned().or_else(|| {
        crate::config::trust::with_workspace_trust_policy(trust_policy.clone(), || {
            cockpit_config::config::dirs::most_specific_config_write_target(&cwd)
                .map(|path| path.with_file_name(cockpit_config::config::dirs::MCP_FILE))
        })
    });
    let target =
        target.ok_or_else(|| bad_request("no Cockpit config layer is available for MCP save"))?;
    let path = target
        .parent()
        .ok_or_else(|| bad_request("MCP config target has no parent"))?
        .join(cockpit_config::config::dirs::MCP_FILE);
    // Cleanup authority comes from the daemon's prior on-disk layer, never
    // from a caller-supplied list of arbitrary vault names. A malformed prior
    // layer is a hard failure: treating it as empty could delete credentials
    // still needed by that layer.
    let prior_config = match std::fs::read_to_string(&path) {
        Ok(raw) => crate::mcp::config::McpConfig::parse(&raw).map_err(internal)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::mcp::config::McpConfig::default()
        }
        Err(error) => return Err(internal(error)),
    };
    let prior_references = prior_config
        .servers
        .iter()
        .flat_map(|(server_name, server)| mcp_secret_references(server_name, server))
        .collect::<std::collections::BTreeSet<_>>();
    let journal_id = Uuid::now_v7().to_string();
    let cleanup_json = serde_json::to_string(&prior_references).map_err(internal)?;
    let config_json_owned = serde_json::to_string(&config).map_err(internal)?;
    let staged_values = secret_values.into_iter().collect::<Vec<_>>();
    let staged_names = staged_values
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<std::collections::BTreeSet<_>>();
    // Validate EVERY named-secret reference in the submitted config — not just
    // the staged entries — before any vault mutation. Otherwise an owner could
    // point an MCP server's `credential_ref` at an existing provider-owned (or
    // foreign-workspace) `$secret:` with an empty staged map and silently make
    // the MCP server consume that secret (a cross-kind boundary bypass).
    ensure_mcp_references_claimable(ctx, project_root, &config, &staged_names).await?;
    // Derive the FULL normalized reference set once, so the in-transaction guard
    // re-checks EVERY reference (not just the staged ones) atomically with the
    // config publish below. `all_refs` covers staged names, existing static
    // `credential_ref`s, and flow-managed OAuth keys (`mcp:<server>`);
    // `static_nonstaged_refs` is the subset that must already be owned by this
    // mcp/root with a live vault row (OAuth keys stay permissive-when-absent and
    // are therefore excluded).
    let mut all_refs = std::collections::BTreeSet::new();
    let mut oauth_keys = std::collections::BTreeSet::new();
    for (server_name, server) in &config.servers {
        if matches!(server.auth, crate::mcp::config::Auth::Oauth(_)) {
            oauth_keys.insert(crate::mcp::auth::cred_key(server_name));
        }
        for reference in mcp_secret_references(server_name, server) {
            all_refs.insert(reference);
        }
    }
    let static_nonstaged_refs = all_refs
        .iter()
        .filter(|reference| !oauth_keys.contains(*reference) && !staged_names.contains(*reference))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let staged_for_tx = staged_values.clone();
    let staged_mutations = ctx
        .db
        .transaction({
            let vault = ctx.secret_vault.clone();
            let journal_id = journal_id.clone();
            let project_root = project_root.to_string();
            let config_path = path.to_string_lossy().into_owned();
            let config_json = config_json_owned.clone();
            let cleanup_json = cleanup_json.clone();
            let all_refs = all_refs.clone();
            let static_nonstaged_refs = static_nonstaged_refs.clone();
            move |conn| {
                conn.execute(
                    "INSERT INTO mcp_config_journals
                     (journal_id, project_root, config_path, config_json, cleanup_names_json, phase, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'staged', ?6)",
                    rusqlite::params![
                        journal_id,
                        project_root,
                        config_path,
                        config_json,
                        cleanup_json,
                        chrono::Utc::now().timestamp_millis(),
                    ],
                )?;
                // ATOMIC full-reference admission: re-check EVERY normalized
                // reference (staged, existing static, and flow-managed OAuth
                // keys) inside this `BEGIN IMMEDIATE` transaction, not only in
                // the pre-transaction read. This closes the cross-process TOCTOU
                // where another workspace/provider claims a non-staged or OAuth
                // name after the precheck but before this publish. A conflict
                // rolls the whole transaction back (no journal, no vault write,
                // no claim). OAuth keys that are absent stay permissive so
                // configure-then-authenticate still works.
                guard_mcp_reference_ownership_on_conn(
                    conn,
                    &vault,
                    &all_refs,
                    &static_nonstaged_refs,
                    &project_root,
                )?;
                let mut mutations = std::collections::BTreeMap::new();
                for (name, value) in &staged_for_tx {
                    // ATOMIC cross-kind admission: re-check ownership INSIDE the
                    // transaction that mutates the vault and inserts the claim,
                    // not only in the earlier `ensure_mcp_references_claimable`
                    // read. `BEGIN IMMEDIATE` holds the writer lock across this
                    // whole closure, so a provider in another daemon process
                    // cannot claim the name between the check and the write. A
                    // conflict fails closed: no vault mutation, no claim insert,
                    // and the enclosing transaction rolls back. Do NOT rely on
                    // `INSERT OR IGNORE` to let cross-kind claims silently
                    // coexist.
                    reject_conflicting_named_ownership_on_conn(
                        conn,
                        name,
                        "mcp",
                        &project_root,
                    )?;
                    let mutation = vault.mutate_item_on_conn(
                        conn,
                        cockpit_db::secret_vault::SecretVaultKind::NamedSecret,
                        name,
                        Some(value.as_bytes()),
                    )?;
                    mutations.insert(name.clone(), mutation);
                    conn.execute(
                        "INSERT OR IGNORE INTO secret_named_ownership
                         (item_id, owner_kind, project_root, created_at)
                         VALUES (?1, 'mcp', ?2, ?3)",
                        rusqlite::params![
                            name,
                            project_root,
                            chrono::Utc::now().timestamp_millis()
                        ],
                    )?;
                }
                Ok(mutations)
            }
        })
        .await
        .map_err(map_named_secret_tx_error)?;
    if let Err(error) = ctx.publish_owner_redaction_table() {
        compensate_mcp_staged_and_retire(ctx, &journal_id, &staged_mutations).await?;
        ctx.poison_redaction_publication(&error);
        return Err(internal(error));
    }
    if let Err(error) = config.write_private(&path) {
        let error = anyhow::anyhow!(error);
        ctx.poison_redaction_publication(&error);
        // The atomic write may have succeeded before reporting an error. Keep
        // the journal and staged claims for recovery rather than deleting a
        // vault value that the file may now reference.
        return Err(internal(error));
    }
    if let Err(error) = ctx
        .db
        .write({
            let journal_id = journal_id.clone();
            move |conn| {
                conn.execute(
                    "UPDATE mcp_config_journals SET phase = 'published' WHERE journal_id = ?1",
                    rusqlite::params![journal_id],
                )?;
                Ok(())
            }
        })
        .await
    {
        let error = anyhow::anyhow!(error);
        ctx.poison_redaction_publication(&error);
        return Err(internal(error));
    }
    let referenced = mcp_global_live_secret_references(ctx, project_root).await?;
    let cleanup_names = prior_references
        .difference(&referenced)
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let _secret_lock = SECRET_OWNER_RPC_LOCK.lock().await;
    for name in cleanup_names {
        if !release_named_secret_ownership(ctx, &name, "mcp", project_root).await? {
            retire_named_secret_ownership(ctx, &name, "mcp", project_root).await?;
            continue;
        }
        delete_owned_named_secret(ctx, &name, "mcp", project_root).await?;
    }
    delete_mcp_journal(ctx, &journal_id).await?;
    let credential_count = config
        .servers
        .iter()
        .flat_map(|(name, server)| mcp_secret_references(name, server))
        .count();
    Ok(Response::McpConfigSaved {
        credential_count: u32::try_from(credential_count).unwrap_or(u32::MAX),
    })
}

async fn delete_mcp_journal(
    ctx: &DaemonContext,
    journal_id: &str,
) -> std::result::Result<(), ErrorPayload> {
    let journal_id = journal_id.to_owned();
    ctx.db
        .write(move |conn| {
            conn.execute(
                "DELETE FROM mcp_config_journals WHERE journal_id = ?1",
                rusqlite::params![journal_id],
            )?;
            Ok(())
        })
        .await
        .map_err(internal)
}

fn mcp_live_secret_references(
    project_root: &str,
) -> std::result::Result<std::collections::BTreeSet<String>, ErrorPayload> {
    let mut merged = crate::mcp::config::McpConfig::default();
    for path in
        cockpit_config::config::dirs::mcp_file_paths_for_load(std::path::Path::new(project_root))
    {
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(internal(error)),
        };
        let layer = crate::mcp::config::McpConfig::parse(&raw).map_err(internal)?;
        for (name, server) in layer.servers {
            merged.servers.insert(name, server);
        }
    }
    Ok(merged
        .servers
        .iter()
        .flat_map(|(server_name, server)| mcp_secret_references(server_name, server))
        .collect())
}

fn daemon_mcp_paths(
    ctx: &DaemonContext,
    cwd: &std::path::Path,
    policy: &crate::config::trust::WorkspaceTrustPolicy,
) -> std::result::Result<Vec<std::path::PathBuf>, ErrorPayload> {
    let config_files = crate::config::trust::with_workspace_trust_policy(policy.clone(), || {
        ctx.config_source().watch_paths(cwd).config_files
    });
    Ok(config_files
        .into_iter()
        .filter_map(|path| {
            path.parent()
                .map(|parent| parent.join(cockpit_config::config::dirs::MCP_FILE))
        })
        .collect())
}

fn mcp_config_from_paths(
    paths: &[std::path::PathBuf],
) -> std::result::Result<crate::mcp::config::McpConfig, ErrorPayload> {
    let mut merged = crate::mcp::config::McpConfig::default();
    for path in paths {
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(internal(error)),
        };
        let layer = crate::mcp::config::McpConfig::parse(&raw).map_err(internal)?;
        for (name, server) in layer.servers {
            merged.servers.insert(name, server);
        }
    }
    Ok(merged)
}

fn mcp_and_provider_live_secret_references(
    ctx: &DaemonContext,
    project_root: &str,
) -> std::result::Result<std::collections::BTreeSet<String>, ErrorPayload> {
    let mut references = mcp_live_secret_references(project_root)?;
    // Provider entries share the named-secret vault namespace with MCP. Use
    // the daemon config source's effective layered resolver so a provider in
    // any live config layer protects a name from MCP cleanup (and the
    // session-config boundary ratchet holds).
    let (providers, _) = ctx
        .config_source()
        .load(std::path::Path::new(project_root))
        .map_err(daemon_config_error)?;
    for provider in providers.providers.values() {
        let (named, _) = provider_owned_secret_references(provider);
        references.extend(named);
    }
    Ok(references)
}

fn provider_credential_references_for_root(
    ctx: &DaemonContext,
    project_root: &str,
) -> std::result::Result<std::collections::BTreeSet<String>, ErrorPayload> {
    let (providers, _) = ctx
        .config_source()
        .load(std::path::Path::new(project_root))
        .map_err(daemon_config_error)?;
    Ok(providers
        .providers
        .values()
        .filter_map(|provider| provider.credential_ref.clone())
        .collect())
}

/// Named-secret references made by provider configs under every durably-known
/// workspace root OTHER than `current_root` (which must already be the canonical
/// owner root).
///
/// Owner-scoped provider resolution uses this to prove SOLE ownership before
/// lazily backfilling an unclaimed legacy `$secret:` name (gap 4): a name in
/// this set is referenced by a different workspace, so it is ambiguous and must
/// never be auto-claimed. Roots come from the same durable tables the cleanup
/// scanners use; per-root config loading is `config_source().load`.
async fn foreign_provider_named_references(
    ctx: &DaemonContext,
    current_root: &str,
) -> std::result::Result<std::collections::BTreeSet<String>, ErrorPayload> {
    let current_root = current_root.to_owned();
    let roots: std::collections::BTreeSet<String> = ctx
        .db
        .read(|conn| {
            let mut roots = std::collections::BTreeSet::new();
            for sql in [
                "SELECT project_root FROM provider_config_journals",
                "SELECT project_root FROM secret_named_ownership",
            ] {
                let mut statement = conn.prepare(sql)?;
                for root in statement.query_map([], |row| row.get::<_, String>(0))? {
                    roots.insert(root?);
                }
            }
            Ok(roots)
        })
        .await
        .map_err(internal)?;
    let mut references = std::collections::BTreeSet::new();
    for root in roots {
        // Compare against the canonical current root; only OTHER workspaces
        // contribute foreign references.
        if crate::secret_ownership::canonical_owner_root(&root) == current_root {
            continue;
        }
        let (providers, _) = ctx
            .config_source()
            .load(std::path::Path::new(&root))
            .map_err(daemon_config_error)?;
        for provider in providers.providers.values() {
            let (named, _) = provider_owned_secret_references(provider);
            references.extend(named);
        }
    }
    Ok(references)
}

/// Credential records use a separate vault kind from named header secrets.
/// Their cleanup must therefore be based on every durable provider config
/// reference, not on the generated names used for staged header values.
async fn provider_global_live_credential_references(
    ctx: &DaemonContext,
    current_root: &str,
) -> std::result::Result<std::collections::BTreeSet<String>, ErrorPayload> {
    let current_root = current_root.to_owned();
    let mut roots: std::collections::BTreeSet<String> = ctx
        .db
        .read(|conn| {
            let mut roots = std::collections::BTreeSet::new();
            for sql in [
                "SELECT project_root FROM provider_config_journals",
                "SELECT project_root FROM secret_credential_ownership",
            ] {
                let mut statement = conn.prepare(sql)?;
                for root in statement.query_map([], |row| row.get::<_, String>(0))? {
                    roots.insert(root?);
                }
            }
            Ok(roots)
        })
        .await
        .map_err(internal)?;
    roots.insert(current_root);
    let mut references = std::collections::BTreeSet::new();
    for root in roots {
        references.extend(provider_credential_references_for_root(ctx, &root)?);
    }
    Ok(references)
}

/// Build the live named-secret inventory across every workspace that has
/// durable configuration activity recorded by this daemon. MCP OAuth and
/// staged names are daemon-generated but the vault is shared, so checking
/// only the current project can delete a token still referenced elsewhere.
/// The current root is always included, even before its journal is retired.
async fn mcp_global_live_secret_references(
    ctx: &DaemonContext,
    current_root: &str,
) -> std::result::Result<std::collections::BTreeSet<String>, ErrorPayload> {
    let current_root = current_root.to_owned();
    let mut roots: std::collections::BTreeSet<String> = ctx
        .db
        .read(|conn| {
            let mut roots = std::collections::BTreeSet::new();
            for sql in [
                "SELECT project_root FROM mcp_config_journals",
                "SELECT project_root FROM provider_config_journals",
                "SELECT project_root FROM secret_named_ownership",
            ] {
                let mut statement = conn.prepare(sql)?;
                for root in statement.query_map([], |row| row.get::<_, String>(0))? {
                    roots.insert(root?);
                }
            }
            Ok(roots)
        })
        .await
        .map_err(internal)?;
    roots.insert(current_root);
    let mut references = std::collections::BTreeSet::new();
    for root in roots {
        references.extend(mcp_and_provider_live_secret_references(ctx, &root)?);
    }
    Ok(references)
}

/// Report whether this workspace is the sole durable owner. The claim is
/// retired only after the vault deletion succeeds.
async fn release_named_secret_ownership(
    ctx: &DaemonContext,
    item_id: &str,
    owner_kind: &str,
    project_root: &str,
) -> std::result::Result<bool, ErrorPayload> {
    let item_id = item_id.to_owned();
    let owner_kind = owner_kind.to_owned();
    let project_root = project_root.to_owned();
    ctx.db
        .transaction(move |conn| {
            let owned: i64 = conn.query_row(
                "SELECT COUNT(*) FROM secret_named_ownership
                 WHERE item_id = ?1 AND owner_kind = ?2 AND project_root = ?3",
                rusqlite::params![item_id, owner_kind, project_root],
                |row| row.get(0),
            )?;
            if owned == 0 {
                return Ok(false);
            }
            let remaining: i64 = conn.query_row(
                "SELECT COUNT(*) FROM secret_named_ownership WHERE item_id = ?1",
                rusqlite::params![item_id],
                |row| row.get(0),
            )?;
            // The caller's own claim is included in the count.
            Ok(remaining == 1)
        })
        .await
        .map_err(internal)
}

async fn release_credential_ownership(
    ctx: &DaemonContext,
    item_id: &str,
    provider_id: &str,
    project_root: &str,
) -> std::result::Result<Option<bool>, ErrorPayload> {
    let item_id = item_id.to_owned();
    let provider_id = provider_id.to_owned();
    let project_root = project_root.to_owned();
    ctx.db
        .transaction(move |conn| {
            let owned: i64 = conn.query_row(
                "SELECT COUNT(*) FROM secret_credential_ownership
                 WHERE item_id = ?1 AND provider_id = ?2 AND project_root = ?3",
                rusqlite::params![item_id, provider_id, project_root],
                |row| row.get(0),
            )?;
            if owned == 0 {
                return Ok(None);
            }
            let remaining: i64 = conn.query_row(
                "SELECT COUNT(*) FROM secret_credential_ownership WHERE item_id = ?1",
                rusqlite::params![item_id],
                |row| row.get(0),
            )?;
            Ok(Some(remaining == 1))
        })
        .await
        .map_err(internal)
}

async fn retire_credential_ownership(
    ctx: &DaemonContext,
    item_id: &str,
    provider_id: &str,
    project_root: &str,
) -> std::result::Result<(), ErrorPayload> {
    let item_id = item_id.to_owned();
    let provider_id = provider_id.to_owned();
    let project_root = project_root.to_owned();
    ctx.db
        .write(move |conn| {
            conn.execute(
                "DELETE FROM secret_credential_ownership
                 WHERE item_id = ?1 AND provider_id = ?2 AND project_root = ?3",
                rusqlite::params![item_id, provider_id, project_root],
            )?;
            Ok(())
        })
        .await
        .map_err(internal)
}

async fn ensure_mcp_ownership_available(
    ctx: &DaemonContext,
    project_root: &str,
    names: impl IntoIterator<Item = String>,
) -> std::result::Result<(), ErrorPayload> {
    let root = project_root.to_owned();
    let names = names.into_iter().collect::<Vec<_>>();
    ctx.db
        .read(move |conn| {
            for name in names {
                // Reject ANY existing claim that does not belong to this exact
                // MCP owner (same `mcp` kind AND same project root). This
                // covers cross-kind claims (for example a `provider`-owned
                // `$secret:` name) as well as `mcp` claims held by another
                // workspace, so an MCP save can never overwrite a vault value a
                // provider or another root still authenticates with. Re-saving
                // the same MCP owner/root remains permitted (idempotent).
                let conflict: Option<(String, String)> = conn
                    .query_row(
                        "SELECT owner_kind, project_root FROM secret_named_ownership
                         WHERE item_id = ?1
                           AND NOT (owner_kind = 'mcp' AND project_root = ?2)
                         LIMIT 1",
                        rusqlite::params![name, root],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                if conflict.is_some() {
                    return Err(rusqlite::Error::InvalidQuery.into());
                }
            }
            Ok(())
        })
        .await
        .map_err(|error| {
            bad_request(format!(
                "MCP credential name is already claimed by a provider or another workspace: {error}"
            ))
        })
}

/// Map an error returned from a vault-mutation transaction: a
/// [`NamedSecretClaimConflict`] becomes a `BadRequest` (fail-closed ownership
/// rejection), everything else an `internal` fault.
fn map_named_secret_tx_error(error: anyhow::Error) -> ErrorPayload {
    match error.downcast::<NamedSecretClaimConflict>() {
        Ok(conflict) => bad_request(conflict.to_string()),
        Err(error) => internal(error),
    }
}

/// Validate that every named-secret reference in a normalized MCP config is
/// legitimately available to this MCP owner BEFORE any vault mutation. This is
/// the MCP analog of `ensure_provider_named_references_claimed`: a config-only
/// write must not make an MCP server consume a vault value it does not own.
///
/// References are derived from the whole normalized config, not just the staged
/// map, and split into:
///   * staging-managed references (header/env `credential_ref`s): a reference
///     staged in THIS transaction is allowed (the transaction creates the `mcp`
///     claim), and any other reference must already be claimed `owner_kind='mcp'`
///     at THIS project root AND have a live vault item. This rejects an MCP save
///     that references an existing provider-owned (or foreign-workspace)
///     `$secret:` name with an empty staged map.
///   * OAuth token keys (`mcp:<server>`), which are flow-managed and persisted
///     later by `CompleteMcpOAuth`: only checked for cross-kind/foreign-workspace
///     conflicts, never required to already exist.
///
/// Every reference (including OAuth keys and freshly staged names) is also run
/// through the cross-kind conflict check so a name currently claimed by a
/// provider or another workspace can never be adopted here.
async fn ensure_mcp_references_claimable(
    ctx: &DaemonContext,
    project_root: &str,
    config: &crate::mcp::config::McpConfig,
    staged_names: &std::collections::BTreeSet<String>,
) -> std::result::Result<(), ErrorPayload> {
    let mut staging_refs = std::collections::BTreeSet::new();
    let mut all_refs = std::collections::BTreeSet::new();
    for (server_name, server) in &config.servers {
        let oauth_key = matches!(server.auth, crate::mcp::config::Auth::Oauth(_))
            .then(|| crate::mcp::auth::cred_key(server_name));
        for reference in mcp_secret_references(server_name, server) {
            if Some(&reference) != oauth_key.as_ref() {
                staging_refs.insert(reference.clone());
            }
            all_refs.insert(reference);
        }
    }

    // Cross-kind / foreign-workspace conflict check for every reference,
    // including flow-managed OAuth keys and freshly staged names. A brand-new
    // staged name has no prior claim and passes; a provider- or foreign-root
    // claim is rejected here.
    ensure_mcp_ownership_available(ctx, project_root, all_refs).await?;

    // Every non-staged staging-managed reference must already be owned by this
    // MCP at this root and have a live vault item.
    let root = project_root.to_owned();
    for reference in &staging_refs {
        if staged_names.contains(reference) {
            continue;
        }
        if ctx
            .secret_vault
            .get_item(
                cockpit_db::secret_vault::SecretVaultKind::NamedSecret,
                reference,
            )
            .is_err()
        {
            return Err(bad_request(format!(
                "MCP credential reference `{reference}` is not a daemon-owned staged secret"
            )));
        }
        let reference_for_query = reference.clone();
        let root_for_query = root.clone();
        let claimed = ctx
            .db
            .read(move |conn| {
                let claimed = conn.query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM secret_named_ownership
                         WHERE item_id = ?1 AND owner_kind = 'mcp' AND project_root = ?2
                     )",
                    rusqlite::params![reference_for_query, root_for_query],
                    |row| row.get::<_, bool>(0),
                )?;
                Ok(claimed)
            })
            .await
            .map_err(internal)?;
        if !claimed {
            return Err(bad_request(format!(
                "MCP credential reference `{reference}` has no durable MCP claim at this workspace"
            )));
        }
    }
    Ok(())
}

async fn reject_owned_named_secret(
    ctx: &DaemonContext,
    item_id: &str,
) -> std::result::Result<(), ErrorPayload> {
    let item_id = item_id.to_owned();
    let claimed = ctx
        .db
        .read(move |conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM secret_named_ownership WHERE item_id = ?1",
                rusqlite::params![item_id],
                |row| row.get(0),
            )?;
            Ok(count != 0)
        })
        .await
        .map_err(internal)?;
    if claimed {
        return Err(bad_request(
            "named secret is daemon-owned by a provider or MCP workspace",
        ));
    }
    Ok(())
}

async fn retire_named_secret_ownership(
    ctx: &DaemonContext,
    item_id: &str,
    owner_kind: &str,
    project_root: &str,
) -> std::result::Result<(), ErrorPayload> {
    let item_id = item_id.to_owned();
    let owner_kind = owner_kind.to_owned();
    let project_root = project_root.to_owned();
    ctx.db
        .write(move |conn| {
            conn.execute(
                "DELETE FROM secret_named_ownership
                 WHERE item_id = ?1 AND owner_kind = ?2 AND project_root = ?3",
                rusqlite::params![item_id, owner_kind, project_root],
            )?;
            Ok(())
        })
        .await
        .map_err(internal)
}

async fn delete_owned_named_secret(
    ctx: &DaemonContext,
    item_id: &str,
    owner_kind: &str,
    project_root: &str,
) -> std::result::Result<(), ErrorPayload> {
    let item_id = item_id.to_owned();
    let owner_kind = owner_kind.to_owned();
    let project_root = project_root.to_owned();
    let vault = ctx.secret_vault.clone();
    ctx.db
        .transaction(move |conn| {
            vault
                .mutate_item_on_conn(
                    conn,
                    cockpit_db::secret_vault::SecretVaultKind::NamedSecret,
                    &item_id,
                    None,
                )
                .map_err(|error| anyhow::anyhow!(error))?;
            conn.execute(
                "DELETE FROM secret_named_ownership
                 WHERE item_id = ?1 AND owner_kind = ?2 AND project_root = ?3",
                rusqlite::params![item_id, owner_kind, project_root],
            )?;
            Ok(())
        })
        .await
        .map_err(internal)?;
    if let Err(error) = ctx.publish_owner_redaction_table() {
        ctx.poison_redaction_publication(&error);
        return Err(internal(error));
    }
    Ok(())
}

/// Complete MCP vault/file journals left by a crashed daemon. The config is
/// reference-only, so replaying publication is idempotent; cleanup is gated
/// by a fresh cross-layer reference inventory.
pub(super) async fn recover_mcp_config_journals(
    ctx: &DaemonContext,
    project_root: &str,
) -> std::result::Result<(), ErrorPayload> {
    let root = project_root.to_owned();
    let journals: Vec<(String, String, String, String)> = ctx
        .db
        .read(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT journal_id, config_path, config_json, cleanup_names_json
                 FROM mcp_config_journals WHERE project_root = ?1
                 ORDER BY created_at, journal_id",
            )?;
            stmt.query_map(rusqlite::params![root], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
        })
        .await
        .map_err(internal)?;
    for (journal_id, path, config_json, cleanup_json) in journals {
        let config = crate::mcp::config::McpConfig::parse(&config_json).map_err(internal)?;
        config
            .write_private(std::path::Path::new(&path))
            .map_err(internal)?;
        let cleanup: std::collections::BTreeSet<String> =
            serde_json::from_str(&cleanup_json).map_err(internal)?;
        let live = mcp_global_live_secret_references(ctx, project_root).await?;
        let _secret_lock = SECRET_OWNER_RPC_LOCK.lock().await;
        for name in cleanup.difference(&live) {
            if !release_named_secret_ownership(ctx, name, "mcp", project_root).await? {
                retire_named_secret_ownership(ctx, name, "mcp", project_root).await?;
                continue;
            }
            delete_owned_named_secret(ctx, name, "mcp", project_root).await?;
        }
        delete_mcp_journal(ctx, &journal_id).await?;
    }
    Ok(())
}

#[cfg(any(unix, test))]
pub(super) async fn recover_all_mcp_config_journals(
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let roots: Vec<String> = ctx
        .db
        .read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT project_root FROM mcp_config_journals
                 UNION SELECT project_root FROM secret_named_ownership
                 ORDER BY project_root",
            )?;
            stmt.query_map([], |row| row.get(0))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Into::into)
        })
        .await
        .map_err(internal)?;
    for root in roots {
        recover_mcp_config_journals(ctx, &root).await?;
    }
    Ok(())
}

/// Validate the reference-only MCP wire projection and normalize a newly
/// entered literal into the corresponding credential reference.  This runs
/// before any vault transaction or filesystem write.
fn validate_and_normalize_mcp_credentials(
    config: &mut crate::mcp::config::McpConfig,
    staged: &std::collections::BTreeMap<String, String>,
) -> std::result::Result<(), ErrorPayload> {
    let mut consumed = std::collections::BTreeSet::new();

    for (server_name, server) in &mut config.servers {
        normalize_mcp_env_map(
            server_name,
            &mut server.env,
            &mut server.env_credential_refs,
            crate::mcp::auth::base_env_cred_key,
            staged,
            &mut consumed,
            "server env",
        )?;

        match &mut server.auth {
            crate::mcp::config::Auth::Header(header) => {
                if let Some(reference) = &header.credential_ref {
                    validate_mcp_secret_ref(reference)?;
                    if staged.contains_key(reference) {
                        consumed.insert(reference.clone());
                    }
                    if !header.value.trim().is_empty() && !is_mcp_env_reference(&header.value) {
                        let value = staged.get(reference).ok_or_else(|| {
                            bad_request(format!(
                                "MCP server `{server_name}` header must use a staged secret or reference"
                            ))
                        })?;
                        if value != header.value.trim() {
                            return Err(bad_request(format!(
                                "MCP server `{server_name}` header literal does not match its staged secret"
                            )));
                        }
                        header.value.clear();
                    } else if !header.value.trim().is_empty() {
                        return Err(bad_request(format!(
                            "MCP server `{server_name}` header cannot combine an environment reference with a credential reference"
                        )));
                    }
                } else if !header.value.trim().is_empty() && !is_mcp_env_reference(&header.value) {
                    let reference = crate::mcp::auth::header_cred_key(server_name);
                    let value = staged.get(&reference).ok_or_else(|| {
                        bad_request(format!(
                            "MCP server `{server_name}` header value must be a reference or staged secret"
                        ))
                    })?;
                    if value != header.value.trim() {
                        return Err(bad_request(format!(
                            "MCP server `{server_name}` header literal does not match its staged secret"
                        )));
                    }
                    header.value.clear();
                    header.credential_ref = Some(reference.clone());
                    consumed.insert(reference);
                }
            }
            crate::mcp::config::Auth::Env(env) => {
                normalize_mcp_env_map(
                    server_name,
                    &mut env.vars,
                    &mut env.credential_refs,
                    crate::mcp::auth::auth_env_cred_key,
                    staged,
                    &mut consumed,
                    "auth env",
                )?;
            }
            crate::mcp::config::Auth::Oauth(_) | crate::mcp::config::Auth::None => {}
        }

        for reference in server.env_credential_refs.values() {
            validate_mcp_secret_ref(reference)?;
            if staged.contains_key(reference) {
                consumed.insert(reference.clone());
            }
        }
        if let crate::mcp::config::Auth::Env(env) = &server.auth {
            for reference in env.credential_refs.values() {
                validate_mcp_secret_ref(reference)?;
                if staged.contains_key(reference) {
                    consumed.insert(reference.clone());
                }
            }
        }
    }

    if let Some(unused) = staged.keys().find(|name| !consumed.contains(*name)) {
        return Err(bad_request(format!(
            "MCP staged secret `{unused}` is not referenced by the configuration"
        )));
    }
    Ok(())
}

fn normalize_mcp_env_map(
    server_name: &str,
    values: &mut std::collections::BTreeMap<String, String>,
    refs: &mut std::collections::BTreeMap<String, String>,
    key_fn: fn(&str, &str) -> String,
    staged: &std::collections::BTreeMap<String, String>,
    consumed: &mut std::collections::BTreeSet<String>,
    field: &str,
) -> std::result::Result<(), ErrorPayload> {
    for reference in refs.values() {
        validate_mcp_secret_ref(reference)?;
        if staged.contains_key(reference) {
            consumed.insert(reference.clone());
        }
    }

    let mut remove = Vec::new();
    for (name, value) in values.iter() {
        let value = value.trim();
        if value.is_empty() || is_mcp_env_reference(value) {
            continue;
        }
        let reference = refs
            .get(name)
            .cloned()
            .unwrap_or_else(|| key_fn(server_name, name));
        validate_mcp_secret_ref(&reference)?;
        let staged_value = staged.get(&reference).ok_or_else(|| {
            bad_request(format!(
                "MCP server `{server_name}` {field} `{name}` must use a reference or staged secret"
            ))
        })?;
        if staged_value != value {
            return Err(bad_request(format!(
                "MCP server `{server_name}` {field} `{name}` literal does not match its staged secret"
            )));
        }
        refs.insert(name.clone(), reference.clone());
        consumed.insert(reference);
        remove.push(name.clone());
    }
    for name in remove {
        values.remove(&name);
    }
    Ok(())
}

fn validate_mcp_secret_ref(reference: &str) -> std::result::Result<(), ErrorPayload> {
    if reference.is_empty()
        || reference.len() > cockpit_proto::MAX_OWNER_SECRET_NAME_BYTES
        || reference.contains('\0')
    {
        return Err(bad_request("MCP credential reference is invalid"));
    }
    Ok(())
}

fn is_mcp_env_reference(value: &str) -> bool {
    value.trim().starts_with('$')
}

/// Restore staged MCP rows and retire their journal under one SQLite writer
/// transaction. Raw row/revision comparison keeps a concurrent newer write
/// intact; a failed compensation leaves the journal for recovery.
async fn compensate_mcp_staged_and_retire(
    ctx: &DaemonContext,
    journal_id: &str,
    mutations: &std::collections::BTreeMap<String, crate::secure_key::SecretVaultMutation>,
) -> std::result::Result<(), ErrorPayload> {
    let journal_id = journal_id.to_owned();
    let mutations = mutations.clone();
    ctx.db
        .transaction(move |conn| {
            let kind = cockpit_db::secret_vault::SecretVaultKind::NamedSecret;
            for (name, mutation) in &mutations {
                let current = cockpit_db::secret_vault::load_item_conn(conn, kind, name)?;
                let revision: u64 = conn
                    .query_row(
                        "SELECT revision FROM secret_vault_item_revisions WHERE kind = ?1 AND item_id = ?2",
                        rusqlite::params![kind.as_str(), name],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?
                    .unwrap_or(0)
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid vault item revision"))?;
                if revision != mutation.after.generation || current != mutation.after.row {
                    continue;
                }
                let next_revision = revision
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("vault item revision overflow"))?;
                match &mutation.prior.row {
                    Some(row) => {
                        conn.execute(
                            "INSERT INTO secret_vault_items
                             (kind, item_id, key_version, nonce, ciphertext, created_at, updated_at, revision)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                             ON CONFLICT(kind, item_id) DO UPDATE SET
                               key_version = excluded.key_version, nonce = excluded.nonce,
                               ciphertext = excluded.ciphertext, created_at = excluded.created_at,
                               updated_at = excluded.updated_at, revision = excluded.revision",
                            rusqlite::params![
                                row.kind.as_str(), row.item_id, row.key_version, row.nonce,
                                row.ciphertext, row.created_at, row.updated_at,
                                i64::try_from(next_revision).map_err(|_| anyhow::anyhow!("vault item revision overflow"))?
                            ],
                        )?;
                    }
                    None => {
                        conn.execute(
                            "DELETE FROM secret_vault_items WHERE kind = ?1 AND item_id = ?2",
                            rusqlite::params![kind.as_str(), name],
                        )?;
                    }
                }
                conn.execute(
                    "INSERT INTO secret_vault_item_revisions (kind, item_id, revision)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(kind, item_id) DO UPDATE SET revision = excluded.revision",
                    rusqlite::params![
                        kind.as_str(),
                        name,
                        i64::try_from(next_revision)
                            .map_err(|_| anyhow::anyhow!("vault item revision overflow"))?
                    ],
                )?;
                // An overwrite may reuse an existing claim. Compensation may
                // retire only claims created by this staging operation.
                if mutation.prior.row.is_none() {
                    conn.execute(
                        "DELETE FROM secret_named_ownership
                         WHERE item_id = ?1 AND owner_kind = 'mcp'
                           AND project_root = (SELECT project_root FROM mcp_config_journals WHERE journal_id = ?2)",
                        rusqlite::params![name, journal_id],
                    )?;
                }
            }
            conn.execute(
                "DELETE FROM mcp_config_journals WHERE journal_id = ?1",
                rusqlite::params![journal_id],
            )?;
            Ok(())
        })
        .await
        .map_err(internal)
}

fn mcp_secret_references(
    server_name: &str,
    server: &crate::mcp::config::ServerConfig,
) -> std::collections::BTreeSet<String> {
    let mut refs: std::collections::BTreeSet<String> =
        server.env_credential_refs.values().cloned().collect();
    match &server.auth {
        crate::mcp::config::Auth::Header(header) => {
            if let Some(name) = &header.credential_ref {
                refs.insert(name.clone());
            }
        }
        crate::mcp::config::Auth::Env(env) => {
            refs.extend(env.credential_refs.values().cloned());
        }
        crate::mcp::config::Auth::Oauth(_) => {
            refs.insert(crate::mcp::auth::cred_key(server_name));
        }
        crate::mcp::config::Auth::None => {}
    }
    refs
}

fn validate_daemon_provider_url(url: &str) -> std::result::Result<(), ErrorPayload> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| bad_request("provider URL must be an absolute URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(bad_request("provider URL must use HTTP or HTTPS"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(bad_request("provider URL must not include credentials"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(bad_request(
            "provider URL must not include a query string or fragment",
        ));
    }
    Ok(())
}

fn persist_daemon_provider(
    cwd: &std::path::Path,
    trust_policy: &crate::config::trust::WorkspaceTrustPolicy,
    ctx: &DaemonContext,
    provider_id: &str,
    entry: crate::config::providers::ProviderEntry,
) -> std::result::Result<(), ErrorPayload> {
    let path = crate::config::trust::with_workspace_trust_policy(trust_policy.clone(), || {
        ctx.config_source()
            .config_write_target_for_provider(cwd, provider_id)
    })
    .ok_or_else(|| bad_request("no cockpit config found"))?;
    let mut doc = crate::config::providers::ConfigDoc::load(&path).map_err(internal)?;
    let mut layer = doc.providers();
    layer.providers.insert(provider_id.to_string(), entry);
    doc.write(&layer).map_err(internal)
}

async fn provider_config_delete(
    ctx: &DaemonContext,
    project_root: &str,
    provider_id: &str,
    delete_stored_secrets: bool,
) -> std::result::Result<Response, ErrorPayload> {
    let _config_rpc_lock = CONFIG_PUBLICATION_RPC_LOCK.lock().await;
    // Converge a matching prior intent before deciding that the provider is
    // absent; otherwise a crash between journal/file publication can turn a
    // requested no-op into a skipped cleanup.
    recover_provider_config_journals(ctx, project_root, Some(provider_id)).await?;
    let (cwd, trust_policy, config) = daemon_provider_config(ctx, project_root).await?;
    let path = crate::config::trust::with_workspace_trust_policy(trust_policy, || {
        ctx.config_source()
            .config_write_target_for_provider(&cwd, provider_id)
    })
    .ok_or_else(|| bad_request("no cockpit config found"))?;
    let doc = crate::config::providers::ConfigDoc::load(&path).map_err(internal)?;
    let layer = doc.providers();
    // Only a provider actually owned by this layer can be deleted here.  In
    // particular, a project request must not clean credentials for a provider
    // inherited from a lower layer merely because this layer has no override.
    let Some(removed_provider) = layer.providers.get(provider_id).cloned() else {
        return Ok(Response::ProviderConfigUpserted {
            config: crate::secret_ref::redact_provider_view(&config),
        });
    };
    let cleanup = if delete_stored_secrets {
        provider_owned_secret_references(&removed_provider)
    } else {
        Default::default()
    };
    let journal_id = Uuid::now_v7().to_string();
    let project_root_owned = project_root.to_string();
    let provider_id_owned = provider_id.to_string();
    let named_json = serde_json::to_string(&cleanup.0).map_err(internal)?;
    let credentials_json = serde_json::to_string(&cleanup.1).map_err(internal)?;
    ctx.db.write(move |conn| {
        conn.execute(
            "INSERT INTO provider_config_journals (journal_id, project_root, provider_id, action, entry_json, cleanup_named_json, cleanup_credential_json, created_at)
             VALUES (?1, ?2, ?3, 'delete', NULL, ?4, ?5, ?6)",
            rusqlite::params![journal_id, project_root_owned, provider_id_owned, named_json, credentials_json, chrono::Utc::now().timestamp_millis()],
        )?;
        Ok(())
    }).await.map_err(internal)?;
    recover_provider_config_journals(ctx, project_root, Some(provider_id)).await?;
    let (_, _, config) = daemon_provider_config(ctx, project_root).await?;
    Ok(Response::ProviderConfigUpserted {
        config: crate::secret_ref::redact_provider_view(&config),
    })
}

async fn provider_layer_metadata_set(
    ctx: &DaemonContext,
    project_root: &str,
    category_defaults_json: String,
    on_unlisted_models_fetch: crate::config::providers::OnUnlistedModelsFetch,
) -> std::result::Result<Response, ErrorPayload> {
    let _config_rpc_lock = CONFIG_PUBLICATION_RPC_LOCK.lock().await;
    let category_defaults: std::collections::BTreeMap<
        String,
        crate::config::providers::ProviderModelRef,
    > = serde_json::from_str(&category_defaults_json)
        .map_err(|error| bad_request(format!("invalid category defaults: {error}")))?;
    let (cwd, trust_policy, mut config) = daemon_provider_config(ctx, project_root).await?;
    persist_provider_layer_metadata(
        &cwd,
        &trust_policy,
        ctx,
        category_defaults.clone(),
        on_unlisted_models_fetch,
    )?;
    config.category_defaults = category_defaults;
    config.on_unlisted_models_fetch = Some(on_unlisted_models_fetch);
    Ok(Response::ProviderConfigUpserted {
        config: crate::secret_ref::redact_provider_view(&config),
    })
}

fn persist_provider_layer_metadata(
    cwd: &std::path::Path,
    trust_policy: &crate::config::trust::WorkspaceTrustPolicy,
    ctx: &DaemonContext,
    category_defaults: std::collections::BTreeMap<
        String,
        crate::config::providers::ProviderModelRef,
    >,
    on_unlisted_models_fetch: crate::config::providers::OnUnlistedModelsFetch,
) -> std::result::Result<(), ErrorPayload> {
    let path = crate::config::trust::with_workspace_trust_policy(trust_policy.clone(), || {
        ctx.config_source()
            .config_write_target_for_provider(cwd, "default")
    })
    .ok_or_else(|| bad_request("no cockpit config found"))?;
    let mut doc = crate::config::providers::ConfigDoc::load(&path).map_err(internal)?;
    let mut layer = doc.providers();
    layer.category_defaults = category_defaults;
    layer.on_unlisted_models_fetch = Some(on_unlisted_models_fetch);
    doc.write(&layer).map_err(internal)
}

pub(super) async fn attached_trust_policy(
    ctx: &DaemonContext,
    att: &AttachedSession,
) -> std::result::Result<crate::config::trust::WorkspaceTrustPolicy, ErrorPayload> {
    crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &att.handle.project_root)
        .await
        .map_err(internal)
}

pub(super) async fn get_inventory_bundle(
    ctx: &DaemonContext,
    state: &MutableClientState,
    project_root: String,
    session_id: Uuid,
    selected_agent: String,
) -> std::result::Result<Response, ErrorPayload> {
    let att = require_attached(state)?;
    if att.handle.session_id != session_id {
        return Err(ErrorPayload {
            code: ErrorCode::UnknownSession,
            message: format!("session `{session_id}` is not the attached session"),
        });
    }
    // Inventory is always projected for the attached session project; the
    // client-supplied project_root must match (canonical) or be rejected.
    let attached_root = att.handle.project_root.clone();
    if Path::new(&project_root) != attached_root.as_path()
        && canonicalize_opt(Path::new(&project_root)) != canonicalize_opt(&attached_root)
    {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: format!(
                "project_root `{project_root}` does not match attached session project `{}`",
                attached_root.display()
            ),
        });
    }

    let trust_policy = attached_trust_policy(ctx, att).await?;
    let cwd = attached_root.as_path();
    // One immutable snapshot: the session worker's last-good config is
    // authoritative. Disk is consulted only when the held snapshot has never
    // been populated (generation 0 and empty providers).
    let held = att.handle.config_snapshot();
    let (providers, skills_config, config_generation) =
        if held.generation > 0 || !held.providers.providers.is_empty() {
            (
                held.providers.clone(),
                held.extended.skills.clone(),
                held.generation,
            )
        } else {
            match ctx
                .config_source()
                .load_effective_for_daemon(cwd, &trust_policy)
            {
                Ok((providers, extended)) => (providers, extended.skills, 0),
                Err(err) => {
                    return Err(daemon_config_error(err));
                }
            }
        };

    // Session generation is the attached worker config epoch (attach identity).
    let session_generation = held.generation.max(config_generation);
    let inventory_generation = super::inventory::current_inventory_generation();
    let ownable_agents =
        crate::config::trust::with_workspace_trust_policy(trust_policy.clone(), || {
            crate::agents::chat_ownable_primaries(cwd)
        });

    let snapshot = super::inventory::InventorySourceSnapshot {
        project_root: cwd.to_path_buf(),
        session_id,
        selected_agent,
        session_generation,
        config_generation,
        inventory_generation,
        trust_policy,
        providers,
        skills_config,
        ownable_agents,
    };
    super::inventory::project_inventory_bundle(&snapshot)
}

fn canonicalize_opt(path: &Path) -> Option<std::path::PathBuf> {
    path.canonicalize().ok()
}

pub(super) fn require_shared_attached(
    shared: &SharedClientState,
) -> std::result::Result<&SharedAttachedSession, ErrorPayload> {
    shared.attached.as_ref().ok_or_else(|| ErrorPayload {
        code: ErrorCode::NotAttached,
        message: "client has not attached to a session".into(),
    })
}

pub(super) fn daemon_config_error(error: anyhow::Error) -> ErrorPayload {
    if let Some(invalid) =
        error.downcast_ref::<crate::config::extended::InvalidResponseMetricsTokenizer>()
    {
        tracing::warn!(diagnostic = %invalid.diagnostic(), "daemon config rejected invalid response tokenizer");
        ErrorPayload {
            code: ErrorCode::InvalidResponseMetricsTokenizer,
            message: "configuration value is invalid".into(),
        }
    } else {
        ErrorPayload {
            code: ErrorCode::InvalidConfig,
            message: format!("invalid config: {error:#}"),
        }
    }
}

pub(super) fn explicit_config_refresh_error(
    error: crate::daemon::config_refresh::ExplicitConfigRefreshError,
) -> ErrorPayload {
    ErrorPayload {
        code: match &error {
            crate::daemon::config_refresh::ExplicitConfigRefreshError::InvalidResponseMetricsTokenizer => ErrorCode::InvalidResponseMetricsTokenizer,
            crate::daemon::config_refresh::ExplicitConfigRefreshError::InvalidConfig(_) => ErrorCode::InvalidConfig,
            crate::daemon::config_refresh::ExplicitConfigRefreshError::Internal => ErrorCode::Internal,
        },
        message: match &error {
            crate::daemon::config_refresh::ExplicitConfigRefreshError::Internal => "config refresh failed",
            crate::daemon::config_refresh::ExplicitConfigRefreshError::InvalidResponseMetricsTokenizer => "configuration value is invalid",
            crate::daemon::config_refresh::ExplicitConfigRefreshError::InvalidConfig(detail) => return ErrorPayload {
                code: ErrorCode::InvalidConfig,
                message: format!("invalid config: {detail}"),
            },
        }.into(),
    }
}

pub(super) async fn attached_trust_policy_shared(
    ctx: &DaemonContext,
    att: &SharedAttachedSession,
) -> std::result::Result<crate::config::trust::WorkspaceTrustPolicy, ErrorPayload> {
    crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &att.project_root)
        .await
        .map_err(internal)
}

pub(super) async fn get_inventory_bundle_shared(
    ctx: &DaemonContext,
    shared: &SharedClientState,
    project_root: String,
    session_id: Uuid,
    selected_agent: String,
) -> std::result::Result<Response, ErrorPayload> {
    let att = require_shared_attached(shared)?;
    if att.session_id != session_id {
        return Err(ErrorPayload {
            code: ErrorCode::UnknownSession,
            message: format!("session `{session_id}` is not the attached session"),
        });
    }
    if Path::new(&project_root) != att.project_root.as_path()
        && canonicalize_opt(Path::new(&project_root)) != canonicalize_opt(&att.project_root)
    {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: format!(
                "project_root `{project_root}` does not match attached session project `{}`",
                att.project_root.display()
            ),
        });
    }

    let trust_policy = attached_trust_policy_shared(ctx, att).await?;
    let cwd = att.project_root.as_path();
    let (providers, extended) = ctx
        .config_source()
        .load_effective_for_daemon(cwd, &trust_policy)
        .map_err(daemon_config_error)?;

    // Shared concurrent path has no live config handle; use inventory gen only.
    let config_generation = super::inventory::current_inventory_generation();
    let session_generation = config_generation;
    let inventory_generation = config_generation;
    let ownable_agents =
        crate::config::trust::with_workspace_trust_policy(trust_policy.clone(), || {
            crate::agents::chat_ownable_primaries(cwd)
        });

    let snapshot = super::inventory::InventorySourceSnapshot {
        project_root: cwd.to_path_buf(),
        session_id,
        selected_agent,
        session_generation,
        config_generation,
        inventory_generation,
        trust_policy,
        providers,
        skills_config: extended.skills,
        ownable_agents,
    };
    super::inventory::project_inventory_bundle(&snapshot)
}

pub(super) async fn guidance_estimate(
    ctx: &DaemonContext,
    project_root: String,
    provider: Option<String>,
    model: Option<String>,
) -> std::result::Result<Response, ErrorPayload> {
    let cwd = Path::new(&project_root);
    let (strategy, scale) = ctx
        .db
        .resolve_tokenizer(
            provider.as_deref().unwrap_or(""),
            model.as_deref().unwrap_or(""),
        )
        .await;
    let strategy = crate::tokens::calibration_strategy_from_persisted(strategy.as_str());
    let system_prompt = crate::engine::builtin::default_chat_system_prompt(cwd, "");
    let system_tokens = crate::tokens::scaled_estimate(&system_prompt, strategy, scale);
    let model_instruction_tokens = provider
        .as_deref()
        .zip(model.as_deref())
        .and_then(|(provider, model)| {
            let (cfg, _) = ctx.config_source().load(cwd).ok()?;
            cfg.resolve_model_system_prompt(provider, model)
                .map(|prompt| crate::tokens::scaled_estimate(prompt, strategy, scale))
        })
        .unwrap_or(0);
    match crate::engine::builtin::load_agent_guidance(cwd) {
        Some((path, body)) => {
            let tokens = crate::tokens::scaled_estimate(&body, strategy, scale);
            let file = path.file_name().map(|n| n.to_string_lossy().into_owned());
            Ok(Response::GuidanceEstimate {
                file,
                tokens,
                system_tokens,
                model_instruction_tokens,
            })
        }
        None => Ok(Response::GuidanceEstimate {
            file: None,
            tokens: 0,
            system_tokens,
            model_instruction_tokens,
        }),
    }
}

#[allow(dead_code)] // retained for non-inventory agent summary projections
pub(super) fn agent_mode_summary(mode: crate::agents::AgentMode) -> &'static str {
    match mode {
        crate::agents::AgentMode::All => "all",
        crate::agents::AgentMode::Primary => "primary",
        crate::agents::AgentMode::Subagent => "subagent",
    }
}

// ---- shutdown -------------------------------------------------------------

/// The single entry point every stop trigger (SIGINT/SIGTERM, explicit
/// `StopDaemon`, the ephemeral last-client/owner-exit teardown) routes
/// through (`daemon-graceful-drain-shutdown.md`).
///
/// First call begins the drain: it broadcasts the `DaemonDraining { forced:
/// false }` notice (TUIs show "finishing in-flight work, shutting down…"
/// and start refusing new input) and flips the central gate so the
/// inference-dispatch chokepoint refuses new provider requests. A *second*
/// call while already draining **shortens** to an immediate force-exit —
/// it promotes the gate to `Forced` and broadcasts `DaemonDraining { forced:
/// true }`. Both transitions are monotonic/idempotent, so a redundant
/// trigger never starts a second drain, resets the deadline, or deadlocks.
pub fn request_shutdown(ctx: &Arc<DaemonContext>) {
    if ctx.shutdown.begin_drain() {
        tracing::info!("daemon: graceful drain begun");
        ctx.broadcast_global(proto::Event::DaemonDraining { forced: false });
    } else if !ctx.shutdown.is_forced() {
        // Already draining and a second trigger arrived: shorten to force.
        ctx.shutdown.force();
        tracing::warn!("daemon: second stop request during drain; forcing exit");
        ctx.broadcast_global(proto::Event::DaemonDraining { forced: true });
    }
}

// ---- helpers --------------------------------------------------------------

/// Apply a `/caffeinate` request: resolve the display-awake scope from
/// config, drive the daemon-held [`CaffeineController`], broadcast the
/// resulting state to **all** clients, and (for `until-idle`) arm the
/// daemon's auto-off watcher. The OS assertion lives in this process so it
/// survives the requesting client's exit.
pub(super) fn set_caffeinate(
    state: &MutableClientState,
    ctx: &Arc<DaemonContext>,
    mode: crate::daemon::caffeinate::CaffeinateMode,
) -> std::result::Result<Response, ErrorPayload> {
    use crate::daemon::caffeinate::InhibitScope;

    // Display-awake is a config setting; resolve it from the attached
    // session's project root when available, else the daemon's cwd.
    let attached_policy = state
        .attached
        .as_ref()
        .map(|att| att.handle.trust_policy.clone());
    let cfg_root = state
        .attached
        .as_ref()
        .map(|att| att.handle.project_root.clone())
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let configs = match attached_policy {
        Some(policy) => ctx.config_source().load_with_trust(&cfg_root, &policy),
        None => ctx.config_source().load(&cfg_root),
    };
    let scope: InhibitScope = match configs {
        Ok((_, extended)) => extended.tui.sleep_scope().into(),
        // Config read failure must not block caffeination: fall back to
        // the safe default (system-only, display free to sleep).
        Err(_) => InhibitScope {
            keep_display_on: false,
        },
    };

    match ctx.caffeinate.apply(mode, scope) {
        Ok(applied) => {
            // Broadcast to every client so the ☕ glyph stays in sync.
            ctx.broadcast_global(proto::Event::CaffeinateState {
                active: applied.state.active,
                lid_close_guaranteed: applied.lid_close_guaranteed,
                message: None,
            });
            // Arm the daemon-owned until-idle watcher: it polls "is any
            // agent running?" and auto-offs once none are.
            if applied.state.until_idle {
                spawn_until_idle_watcher(ctx.clone());
            }
            Ok(Response::CaffeinateState {
                active: applied.state.active,
                lid_close_guaranteed: applied.lid_close_guaranteed,
                message: applied.message,
            })
        }
        // Missing-mechanism / acquire failure: report it so the TUI shows
        // an honest, actionable toast (never silent). Publish the unchanged
        // inactive state too: every connected client must converge even when
        // the OS cannot acquire an inhibitor.
        Err(message) => {
            ctx.broadcast_global(proto::Event::CaffeinateState {
                active: false,
                lid_close_guaranteed: false,
                message: None,
            });
            Ok(Response::CaffeinateState {
                active: false,
                lid_close_guaranteed: false,
                message,
            })
        }
    }
}

fn read_history_page_conn(
    conn: &rusqlite::Connection,
    session_id: Uuid,
    before_seq: Option<i64>,
    limit: u32,
    config_source: &crate::daemon::config_source::ConfigSource,
) -> anyhow::Result<crate::engine::rehydrate::HistoryPage> {
    let extended_cfg = crate::db::Db::get_session_conn(conn, session_id)?
        .and_then(|row| {
            config_source
                .load(std::path::Path::new(&row.project_root))
                .ok()
                .map(|(_, extended)| extended)
        })
        .unwrap_or_default();
    let root_agent = crate::daemon::session_worker::resolve_root_agent_conn(
        conn,
        session_id,
        &extended_cfg,
        extended_cfg.llm_mode,
    );
    crate::engine::rehydrate::history_page_before_conn(
        conn,
        session_id,
        &root_agent,
        before_seq,
        limit,
    )
}

fn read_subagent_history_page_conn(
    conn: &rusqlite::Connection,
    session_id: Uuid,
    task_call_id: &str,
    label: &str,
    before_seq: Option<i64>,
    limit: u32,
) -> anyhow::Result<crate::engine::rehydrate::HistoryPage> {
    crate::engine::rehydrate::subagent_history_page_before_conn(
        conn,
        session_id,
        task_call_id,
        label,
        before_seq,
        limit,
    )
}

/// Poll interval for the until-idle auto-off watcher. Short enough that
/// the machine doesn't stay awake long after the last agent finishes,
/// long enough to be negligible overhead.
pub(super) const UNTIL_IDLE_POLL: std::time::Duration = std::time::Duration::from_secs(5);

/// Spawn the daemon's `until-idle` auto-off watcher. The daemon owns the
/// session workers / `ScheduleAuthority`, so it is the authority for "is an
/// agent running anywhere?". The watcher polls that and, once no agent is
/// running, releases the assertion and broadcasts the off-state to all
/// clients. It exits if the mode is no longer until-idle (a later
/// `on`/`off`/`toggle` superseded it) so a fresh `until-idle` can re-arm
/// without stacking watchers racing each other.
pub(super) fn spawn_until_idle_watcher(ctx: Arc<DaemonContext>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(UNTIL_IDLE_POLL).await;
            // Superseded (explicit on/off, or already auto-offed): stop.
            if !ctx.caffeinate.is_until_idle() {
                return;
            }
            let running = ctx.registry.any_agent_running();
            if let Some(applied) = ctx.caffeinate.idle_check(running) {
                ctx.broadcast_global(proto::Event::CaffeinateState {
                    active: applied.state.active,
                    lid_close_guaranteed: applied.lid_close_guaranteed,
                    message: None,
                });
                return;
            }
        }
    });
}

/// Poll interval for the idle-lock sweeper. Short relative to
/// [`crate::locks::LOCK_IDLE_TIMEOUT`] (5 min) so a reclaimable lock is
/// freed within a few seconds of crossing the threshold, but coarse enough
/// to be negligible overhead.
pub(super) const LOCK_SWEEP_POLL: std::time::Duration = std::time::Duration::from_secs(10);

/// Spawn the daemon's idle-lock sweeper
/// (implementation note). On each tick it asks the
/// single lock authority to reclaim any lock whose holder has been idle
/// past [`crate::locks::LOCK_IDLE_TIMEOUT`] — releasing it, invalidating the
/// §3c read-record, persisting the release, and waking blocked `read`
/// waiters so they proceed. Modeled on [`spawn_until_idle_watcher`]; runs
/// for the daemon's lifetime and exits when the daemon drains.
pub(crate) fn spawn_lock_sweeper(ctx: Arc<DaemonContext>) {
    let locks = ctx.registry.locks();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(LOCK_SWEEP_POLL).await;
            if ctx.shutdown.is_draining() {
                return;
            }
            let now = chrono::Utc::now().timestamp();
            match locks.sweep_expired(now).await {
                Ok(reclaimed) if !reclaimed.is_empty() => {
                    tracing::info!(count = reclaimed.len(), "swept idle-expired locks");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "idle-lock sweep failed"),
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn attach(
    state: &mut MutableClientState,
    ctx: &DaemonContext,
    session_id: Option<Uuid>,
    since_seq: Option<i64>,
    project_root: Option<String>,
    initial_model: Option<crate::config::providers::ActiveModelRef>,
    no_sandbox: bool,
    interactive: bool,
    model_override: Option<crate::config::providers::ActiveModelRef>,
    client_protocol_version: u32,
    env_snapshot: Option<EnvSnapshotWire>,
    env_policy: EnvDriftPolicy,
    principal: &ClientPrincipal,
    effects: &mut ClientRequestEffects,
) -> std::result::Result<Response, ErrorPayload> {
    // The client's `--no-sandbox` only governs sessions it *creates*
    // (sandboxing part 2). On resume of an existing session id the session
    // keeps its own runtime state, so the flag is ignored there.
    let client_no_sandbox = no_sandbox && session_id.is_none();
    // The plan-level model override (`cockpit run --model`) governs only
    // sessions this attach *creates*; on resume the worker is already
    // running, so the flag is ignored (mirrors `--no-sandbox`).
    let model_override = model_override.filter(|_| session_id.is_none());
    let project_root = project_root.map(PathBuf::from);

    let cfg_root = match (session_id, &project_root) {
        (Some(id), _) => match ctx.db.get_session(id).await {
            Ok(Some(row)) => Some(PathBuf::from(row.project_root)),
            Ok(None) => {
                return Err(ErrorPayload {
                    code: ErrorCode::UnknownSession,
                    message: format!("unknown session {id}"),
                });
            }
            Err(e) => return Err(internal(e)),
        },
        (None, Some(root)) => Some(root.clone()),
        (None, None) => {
            return Err(ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "attach requires session_id or project_root".into(),
            });
        }
    };

    let cfg_root = cfg_root.expect("resolved above");
    // Terminal results for transactions this attach converged. Delivered
    // through the worker below, once a handle exists to stamp the generation.
    let recovered_default_transactions;
    // Resolution barrier: finish any pending effective-default transaction —
    // including its guarded session half — before this attach can serve a
    // session or default snapshot. Failing closed here is deliberate: a
    // journal that cannot be converged means the durable default and the
    // session model may disagree, which is exactly what attach must not show.
    {
        let trust_policy =
            crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &cfg_root)
                .await
                .ok();
        recovered_default_transactions =
            crate::daemon::effective_default_recovery::recover_effective_default_journals(
                &ctx.db,
                &cfg_root,
                trust_policy,
            )
            .await
            .map_err(|error| {
            tracing::error!(%error, "effective-default journal recovery failed during attach");
            ErrorPayload {
                code: ErrorCode::InvalidConfig,
                    message:
                        "a pending default-model update could not be recovered; run `cockpit doctor` \
                         to inspect the pending journal for this configuration layer"
                            .to_string(),
                }
            })?;
    }
    let remote_readonly_attach = !principal.is_owner()
        && !principal.can_agent_write_project(&cfg_root.to_string_lossy())
        && principal.can_agent_read_project(&cfg_root.to_string_lossy());
    let client_no_sandbox = client_no_sandbox && !remote_readonly_attach;
    // Cross-process freshness invariant: no trust or session lookup may be
    // cached across requests without an invalidation path. The registry makes
    // the atomic live-vs-start decision: a live worker keeps its snapshotted
    // policy, while every newly-created/resumed worker reads through SQLite
    // after winning its start claim. Thus a trust flip affects the next worker
    // creation and never retroactively mutates a running session.
    // An environment snapshot is process-authority input: it influences
    // provider credential expansion, subprocess PATH lookup, and redaction.
    // Remote principals may attach to sessions but never supply that ambient
    // authority. Authorization rejects the global UpdateDaemon mutation; this
    // dispatch boundary also ignores every non-owner snapshot/policy so a
    // future authz regression cannot inject values into a cold worker.
    let (client_snapshot, env_policy) = if principal.is_owner() {
        (env_snapshot.map(EnvSnapshot::from_wire), env_policy)
    } else {
        (None, EnvDriftPolicy::Daemon)
    };
    let (session_env, env_baseline_meta, env_session_meta, env_drift, env_policy_applied) =
        select_session_env(ctx, client_snapshot, env_policy)?;

    let handle = ctx
        .registry
        .attach(
            session_id,
            project_root,
            initial_model,
            client_no_sandbox,
            model_override.as_ref(),
            session_env,
        )
        .await
        .map_err(workspace_trust_error)?;
    // Attach-only projections use the policy snapshot of the handle that the
    // registry actually returned. This is safe for both branches: live
    // workers retain their original policy, while newly-started workers have
    // already performed the post-claim DB read-through.
    // The worker exists now, so any transaction this attach converged can be
    // delivered as a correlated terminal result stamped with the driver's own
    // generation.
    crate::daemon::effective_default_recovery::deliver_recovered_terminals(
        ctx,
        recovered_default_transactions,
    )
    .await;
    let config_snapshot = handle.config_snapshot();
    let extended_cfg = config_snapshot.extended.clone();

    if session_id.is_none()
        && let Some(tag) = principal.tag()
    {
        handle
            .set_created_by_principal(Some(tag))
            .map_err(internal)?;
    }
    // A per-run daemon can disappear as soon as its client exits. Make the
    // session row durable before returning its id so another daemon process
    // can always find it through the normal DB-backed resume path.
    if session_id.is_none() && ctx.paths.ephemeral {
        handle.persist_if_needed().map_err(internal)?;
    }
    if remote_readonly_attach {
        let caps = current_host_capability_snapshot(ctx);
        let _ = handle.set_sandbox(
            Some(crate::tools::sandbox_mode::SandboxMode::Sandbox),
            None,
            &caps,
        );
        handle.set_approval_mode(crate::config::extended::ApprovalMode::Manual);
    }

    // Replace any prior attachment. Register this client with the worker's
    // interactive-client counter when it can answer interrupts (the loop
    // guard reads that count for headless detection). Building the guard
    // before the old `state.attached` is replaced means a re-attach by the
    // same client transiently holds two guards, never zero — the count
    // can't briefly read headless mid-swap.
    let mut event_rx = handle.subscribe();
    let interactive_guard = if interactive {
        Some(handle.register_interactive_client())
    } else {
        None
    };
    let session_id = handle.session_id;

    // Read/unread marker (GOALS §17f): the session just became active for
    // this client, so everything the agent produced up to now is "seen."
    // Best-effort — a marker write failure must not block the attach.
    if let Err(e) = handle.mark_viewed() {
        tracing::warn!(error = %e, %session_id, "mark_session_viewed failed");
    }

    let foreground = handle.foreground_snapshot();
    let project_root = handle.project_root.to_string_lossy().into_owned();
    let active_agent = foreground
        .active_agent_path
        .last()
        .cloned()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| handle.active_agent_name.clone());
    // Source identity from the live session, not a DB read: a freshly
    // created session is deferred-persistence (session-id-display-and-lazy-
    // persist) and has no `sessions` row yet, so `get_session` would miss.
    let project_id = handle.project_id();
    let short_id = handle.short_id();
    let active_model_state = handle.authoritative_active_model_state().map(|mut state| {
        state.generation = 0;
        state
    });

    drain_client_attachment_ownership(state, ctx, "reattach").await?;
    state.upload_limits = extended_cfg.daemon.uploads.into();
    state.attached = Some(AttachedSession {
        handle,
        _interactive_guard: interactive_guard,
    });

    // Hydrate the queue and gitignore read-allowlist for this client. The
    // just-subscribed `event_rx` receives both full-list replacements, so a
    // late-opened or reconnecting TUI — and any second concurrent client —
    // learns state established before it attached, not only later mutations.
    // Queue replay intentionally includes an empty snapshot; gitignore replay
    // sends only the allow-set.
    if let Some(att) = state.attached.as_ref() {
        att.handle
            .broadcast_queue_snapshot()
            .await
            .map_err(internal)?;
        att.handle.broadcast_gitignore_allow();
        att.handle.broadcast_active_interrupt().await;
        att.handle.broadcast_sandbox_state();
        att.handle.broadcast_sandbox_escalation();
        att.handle.broadcast_sandbox_unavailable_or_probe();
        att.handle.broadcast_config_snapshot();
    }

    // Full chronological history snapshot (user messages + assistant turns +
    // tool calls) for the attached session, so a resuming TUI repopulates the
    // whole prior transcript (implementation note). Run the
    // scan-shaped attach reads on one blocking DB worker and one mutex
    // acquisition, while preserving the single history projection source.
    let db = ctx.db.clone();
    let extended_cfg_for_attach = extended_cfg.clone();
    let active_subagent_for_attach = foreground.active_subagent.clone();
    let (mut history, paused_work, replay_max_seq): (
        Vec<proto::HistoryEntry>,
        Vec<proto::PausedWorkSummary>,
        Option<i64>,
    ) = db
        .read(move |conn| {
            let root_agent = crate::daemon::session_worker::resolve_root_agent_conn(
                conn,
                session_id,
                &extended_cfg_for_attach,
                extended_cfg_for_attach.llm_mode,
            );
            let (history, replay_max_seq) = if let Some(since_seq) = since_seq {
                let replay_max_seq =
                    crate::db::Db::list_session_events_since_conn(conn, session_id, since_seq)
                        .ok()
                        .and_then(|rows| rows.into_iter().map(|row| row.seq).max());
                let history =
                    crate::engine::rehydrate::history_snapshot_since_with_active_subagent_conn(
                        conn,
                        session_id,
                        &root_agent,
                        active_subagent_for_attach.as_ref(),
                        since_seq,
                    )
                    .unwrap_or_else(|e| {
                        tracing::warn!(error = %e, %session_id, since_seq, "building attach replay snapshot failed; sending empty replay");
                        Vec::new()
                    });
                (history, replay_max_seq)
            } else {
                let history = crate::engine::rehydrate::history_snapshot_with_active_subagent_conn(
                    conn,
                    session_id,
                    &root_agent,
                    active_subagent_for_attach.as_ref(),
                )
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, %session_id, "building attach history snapshot failed; sending empty history");
                    Vec::new()
                });
                (history, None)
            };
            let paused_work = crate::db::Db::paused_session_work_conn(conn, session_id)?
                .into_iter()
                .map(paused_work_to_proto)
                .collect();
            Ok((history, paused_work, replay_max_seq))
        })
        .await
        .map_err(internal)?;
    if !paused_work.is_empty()
        && let Some(att) = state.attached.as_ref()
    {
        att.handle.broadcast_notice(
            "paused work is waiting for resume or cancel after daemon restart".to_string(),
        );
    }

    loop {
        match event_rx.try_recv() {
            Ok(envelope) => state.pending_replay.push(envelope.event),
            Err(broadcast::error::TryRecvError::Empty) => break,
            Err(broadcast::error::TryRecvError::Lagged(n)) => {
                tracing::warn!(missed = n, "attach hydration event replay lagged");
                break;
            }
            Err(broadcast::error::TryRecvError::Closed) => break,
        }
    }
    effects.session_event_rx = Some(event_rx);

    history = if let Some(att) = state.attached.as_ref() {
        let redact = att.handle.redaction_table();
        scrub_history_for_principal(&state.principal, history, &redact)
    } else {
        history
    };
    if let Some(max_seq) = replay_max_seq {
        if !history.is_empty() {
            state.pending_replay.push(proto::Event::HistoryReplay {
                session_id,
                entries: history,
                max_seq,
            });
        }
        history = Vec::new();
    }
    let btw_fork = ctx
        .db
        .live_btw_fork_info(session_id)
        .await
        .map_err(internal)?
        .map(btw_info_to_proto);

    Ok(Response::Attached {
        session_id,
        short_id,
        project_root,
        project_id,
        active_agent,
        active_agent_path: foreground.active_agent_path,
        foreground_target: Some(foreground.foreground_target),
        active_subagent: foreground.active_subagent,
        active_model_state,
        history,
        paused_work,
        repair_required: state
            .attached
            .as_ref()
            .and_then(|att| att.handle.repair_required())
            .map(Box::new),
        daemon_version: proto::DAEMON_VERSION.to_string(),
        compatible: proto::is_protocol_compatible(client_protocol_version),
        env_baseline: Some(env_baseline_meta),
        env_session: Some(env_session_meta),
        env_drift: env_drift.map(Box::new),
        env_policy_applied,
        btw_fork,
    })
}

pub(super) fn select_session_env(
    ctx: &DaemonContext,
    client_snapshot: Option<EnvSnapshot>,
    policy: EnvDriftPolicy,
) -> std::result::Result<
    (
        EnvSnapshot,
        EnvSnapshotMeta,
        EnvSnapshotMeta,
        Option<EnvDiffSummary>,
        EnvDriftPolicy,
    ),
    ErrorPayload,
> {
    let Some(client_snapshot) = client_snapshot else {
        let baseline = ctx
            .env_baseline
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let meta = baseline.meta();
        return Ok((baseline, meta.clone(), meta, None, EnvDriftPolicy::Daemon));
    };

    let baseline = ctx
        .env_baseline
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let drift = diff_summary(&baseline, &client_snapshot).filter(EnvDiffSummary::meaningful);
    if matches!(policy, EnvDriftPolicy::ErrorOnDrift) && drift.is_some() {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "client environment differs from daemon baseline".to_string(),
        });
    }

    let chosen = match policy {
        EnvDriftPolicy::Daemon | EnvDriftPolicy::ErrorOnDrift => baseline.clone(),
        EnvDriftPolicy::Client => client_snapshot.clone(),
        EnvDriftPolicy::UpdateDaemon => {
            {
                let mut guard = ctx
                    .env_baseline
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                *guard = client_snapshot.clone();
            }
            client_snapshot.clone()
        }
    };
    let baseline_meta = if matches!(policy, EnvDriftPolicy::UpdateDaemon) {
        client_snapshot.meta()
    } else {
        baseline.meta()
    };
    let session_meta = chosen.meta();
    if matches!(policy, EnvDriftPolicy::Daemon)
        && let Some(diff) = drift.clone()
    {
        ctx.broadcast_global(proto::Event::EnvDriftWarning {
            baseline: baseline.meta(),
            candidate: client_snapshot.meta(),
            diff,
            policy,
        });
    }
    Ok((chosen, baseline_meta, session_meta, drift, policy))
}

pub(super) fn active_model_trigger_from_proto(
    trigger: proto::ActiveModelSwitchTrigger,
) -> crate::session::ModelSwitchTrigger {
    match trigger {
        proto::ActiveModelSwitchTrigger::Picker => crate::session::ModelSwitchTrigger::Picker,
        proto::ActiveModelSwitchTrigger::Quick => crate::session::ModelSwitchTrigger::Quick,
        proto::ActiveModelSwitchTrigger::Cycle => crate::session::ModelSwitchTrigger::Cycle,
        proto::ActiveModelSwitchTrigger::Daemon => crate::session::ModelSwitchTrigger::Daemon,
    }
}

pub(super) fn goal_to_proto(goal: crate::db::session_goals::SessionGoal) -> proto::GoalSummary {
    proto::GoalSummary {
        id: goal.id,
        session_id: goal.session_id,
        project_id: goal.project_id,
        objective: goal.objective,
        context: goal.context,
        disposition: goal.disposition,
        phase: goal.phase,
        resume_phase: goal.resume_phase,
        pause_reason: goal.pause_reason,
        contract_available: goal.contract.is_some(),
        latest_gap_or_blocker: goal
            .unresolved_gaps
            .first()
            .cloned()
            .or(goal.blocker_key.clone()),
        verification_attempts: goal.verification_rounds,
        max_verification_attempts: serde_json::from_str::<serde_json::Value>(
            &goal.resolved_policy_json,
        )
        .ok()
        .and_then(|value| {
            value
                .get("maxVerificationAttempts")
                .and_then(serde_json::Value::as_u64)
        })
        .unwrap_or(4),
        attempt_generation: goal.attempt_generation,
        token_budget: goal.token_budget,
        tokens_used: goal.tokens_used,
        remaining_tokens: goal.token_budget.saturating_sub(goal.tokens_used),
        elapsed_active_ms: goal.elapsed_active_ms,
        lifecycle_history: goal.lifecycle_history,
        blocked_attempts: goal.blocked_attempts,
        last_read_at: goal.last_read_at,
        created_at: goal.created_at,
        updated_at: goal.updated_at,
    }
}

pub(super) fn assistant_to_proto(
    row: crate::db::assistants::AssistantRow,
) -> proto::AssistantSummary {
    proto::AssistantSummary {
        name: row.name,
        created_at: row.created_at,
        home_dir: row.home_dir,
        config_json: row.config_json,
        content_hash: row.content_hash,
        definition_markdown: None,
        definition_revision: None,
        definition_diagnostic: None,
    }
}

fn assistant_to_proto_with_definition(
    row: crate::db::assistants::AssistantRow,
) -> proto::AssistantSummary {
    let mut summary = assistant_to_proto(row);
    let path = crate::assistants::assistant_definition_path(Path::new(&summary.home_dir));
    match cockpit_config::config::read_config_file_nofollow(&path) {
        Ok(Some(bytes)) => match String::from_utf8(bytes) {
            Ok(markdown) => {
                match crate::agents::parse_daemon_local_markdown(&markdown, &summary.name) {
                    Ok(_) => {
                        summary.definition_revision = Some(crate::assistants::definition_revision(
                            &crate::db::assistants::AssistantRow {
                                name: summary.name.clone(),
                                created_at: summary.created_at,
                                home_dir: summary.home_dir.clone(),
                                config_json: summary.config_json.clone(),
                                content_hash: summary.content_hash.clone(),
                            },
                            &markdown,
                        ));
                        summary.definition_markdown = Some(markdown);
                    }
                    Err(error) => summary.definition_diagnostic = Some(error.to_string()),
                }
            }
            Err(_) => summary.definition_diagnostic = Some("definition is not valid UTF-8".into()),
        },
        Ok(None) => summary.definition_diagnostic = Some("definition is missing".into()),
        Err(error) => summary.definition_diagnostic = Some(error.to_string()),
    }
    summary
}

/// Non-secret JSON projection of a registered package row for the
/// owner-remoted `list_packages` / `add_package` responses.
fn package_row_json(row: &crate::db::packages::PackageRow) -> serde_json::Value {
    serde_json::json!({
        "id": row.id,
        "identifier": row.identifier,
        "display_name": row.display_name,
        "source_type": row.source_type.as_str(),
        "source_url": row.source_url,
        "source_branch": row.source_branch,
        "path": row.path,
        "shallow": row.shallow,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    })
}

/// Non-secret JSON projection of the FlyCockpit connector state.
#[cfg(feature = "remote")]
fn connector_state_json(state: &crate::db::connector::ConnectorState) -> serde_json::Value {
    serde_json::json!({
        "server_url": state.server_url,
        "instance_id": state.instance_id,
        "enabled": state.enabled,
        "status": state.status,
        "relay_url": state.relay_url,
        "relay_id": state.relay_id,
        "relay_region": state.relay_region,
        "last_connected_at_ms": state.last_connected_at_ms,
        "last_error": state.last_error,
    })
}

/// Non-secret JSON projection of one org-policy sync state row.
#[cfg(feature = "remote")]
fn org_sync_state_json(state: &crate::db::org_sync::OrgSyncState) -> serde_json::Value {
    serde_json::json!({
        "server_url": state.server_url,
        "org_id": state.org_id,
        "cursor_seq": state.cursor_seq,
        "policy_version": state.policy_version,
        "enabled": state.enabled,
        "last_synced_at_ms": state.last_synced_at_ms,
        "last_error": state.last_error,
        "updated_at_ms": state.updated_at_ms,
    })
}

/// Non-secret JSON projection of one remote-audit upload cursor row.
#[cfg(feature = "remote")]
fn audit_upload_state_json(
    state: &crate::db::remote_audit_upload::RemoteAuditUploadState,
) -> serde_json::Value {
    serde_json::json!({
        "server_url": state.server_url,
        "instance_id": state.instance_id,
        "cursor_audit_id": state.cursor_audit_id,
        "last_uploaded_at_ms": state.last_uploaded_at_ms,
        "last_error": state.last_error,
        "updated_at_ms": state.updated_at_ms,
    })
}

/// JSON projection of one failed/recovered tool-call row. Mirrors the shape
/// `cockpit debug failed-calls --json` renders. Carries tool inputs/outputs
/// (never vault secrets).
fn failed_tool_call_json(row: &crate::db::tool_calls::ToolCallEvent) -> serde_json::Value {
    let (kind, stage) = row.recovery.raw_db_fields();
    serde_json::json!({
        "event_id": row.event_id,
        "session_id": row.session_id,
        "timestamp": row.timestamp,
        "model": row.model,
        "provider": row.provider,
        "project_id": row.project_id,
        "agent": row.agent,
        "tool": row.tool,
        "path": row.path,
        "hard_fail": row.hard_fail,
        "shape_fingerprint": row.shape_fingerprint,
        "recovery_kind": kind,
        "recovery_stage": stage,
        // `recovery_kind`/`recovery_stage` above carry the raw persisted values,
        // which are byte-identical for a recognized kind and one this binary
        // does not recognize (a newer/renamed/downgraded build). This explicit
        // flag lets a consumer tell them apart: `true` iff the row decoded to
        // `Recovery::Unknown`.
        "recovery_unknown": row.recovery.is_unknown(),
        "original_input": row.original_input_json,
        "wire_input": row.wire_input_json,
        "output": row.output,
        "truncated": row.truncated,
        "duration_ms": row.duration_ms,
    })
}

/// JSON projection of one `session_compacted` event; carries the complete
/// event payload (no secret bytes).
fn session_compaction_json(event: &crate::db::session_log::SessionEventRow) -> serde_json::Value {
    serde_json::json!({
        "seq": event.seq,
        "ts_ms": event.ts_ms,
        "data": event.data,
    })
}

/// JSON projection of a package import summary.
fn package_import_summary_json(
    summary: &crate::packages::PackageImportSummary,
) -> serde_json::Value {
    serde_json::json!({
        "imported": summary.imported,
        "deduped": summary.deduped,
        "skipped": summary.skipped,
        "failed": summary.failed(),
        "warnings": summary.warnings,
        "failures": summary
            .failures
            .iter()
            .map(|failure| serde_json::json!({
                "path": failure.path.display().to_string(),
                "reason": failure.reason,
            }))
            .collect::<Vec<_>>(),
    })
}

// ---- Owner-remoted CLI-surface reads -------------------------------------
// These `read_only` requests route to the concurrent path, but the serialized
// match is also exhaustive over `Request`, so both dispatch sites call these
// shared helpers.

async fn list_packages_response(
    ctx: &Arc<DaemonContext>,
) -> std::result::Result<Response, ErrorPayload> {
    let packages = ctx.db.list_packages().await.map_err(internal)?;
    let rows: Vec<serde_json::Value> = packages.iter().map(package_row_json).collect();
    Ok(Response::Packages {
        packages_json: serde_json::to_string(&rows).map_err(internal)?,
    })
}

#[cfg(feature = "remote")]
async fn get_connector_state_response(
    ctx: &Arc<DaemonContext>,
) -> std::result::Result<Response, ErrorPayload> {
    let value = match ctx.load_flycockpit_credential().map_err(internal)? {
        Some(credential) => match ctx
            .db
            .connector_state(&credential.server_url, &credential.instance_id)
            .await
            .map_err(internal)?
        {
            Some(state) => connector_state_json(&state),
            None => serde_json::Value::Null,
        },
        None => serde_json::Value::Null,
    };
    Ok(Response::ConnectorState {
        connector_json: serde_json::to_string(&value).map_err(internal)?,
    })
}

#[cfg(feature = "remote")]
async fn get_org_sync_status_response(
    ctx: &Arc<DaemonContext>,
) -> std::result::Result<Response, ErrorPayload> {
    let org_states = ctx.db.list_org_sync_states().await.map_err(internal)?;
    let audit_states = ctx
        .db
        .list_remote_audit_upload_states()
        .await
        .map_err(internal)?;
    let org: Vec<serde_json::Value> = org_states.iter().map(org_sync_state_json).collect();
    let audit: Vec<serde_json::Value> = audit_states.iter().map(audit_upload_state_json).collect();
    Ok(Response::OrgSyncStatus {
        org_states_json: serde_json::to_string(&org).map_err(internal)?,
        audit_states_json: serde_json::to_string(&audit).map_err(internal)?,
    })
}

async fn list_failed_tool_calls_response(
    ctx: &Arc<DaemonContext>,
    since_epoch: i64,
    tool: Option<String>,
    model: Option<String>,
    project_id: Option<String>,
    include_recovered: bool,
    limit: u32,
) -> std::result::Result<Response, ErrorPayload> {
    let rows = ctx
        .db
        .list_failed_tool_calls(crate::db::tool_calls::FailedCallsFilter {
            since_epoch,
            tool,
            model,
            project_id,
            include_recovered,
            limit: limit as usize,
        })
        .await
        .map_err(internal)?;
    let calls: Vec<serde_json::Value> = rows.iter().map(failed_tool_call_json).collect();
    Ok(Response::FailedToolCalls {
        calls_json: serde_json::to_string(&calls).map_err(internal)?,
    })
}

async fn get_session_compactions_response(
    ctx: &Arc<DaemonContext>,
    session_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    let events = ctx
        .db
        .read(move |conn| {
            crate::db::Db::get_session_conn(conn, session_id)?
                .ok_or_else(|| anyhow::anyhow!("session {session_id} not found"))?;
            Ok(crate::db::Db::list_session_events_conn(conn, session_id)?
                .into_iter()
                .filter(|event| event.kind == "session_compacted")
                .collect::<Vec<_>>())
        })
        .await
        .map_err(|error| bad_request(error.to_string()))?;
    let compactions: Vec<serde_json::Value> = events.iter().map(session_compaction_json).collect();
    Ok(Response::SessionCompactions {
        session_id,
        compactions_json: serde_json::to_string(&compactions).map_err(internal)?,
    })
}

async fn get_assistant_response(
    ctx: &Arc<DaemonContext>,
    name: String,
) -> std::result::Result<Response, ErrorPayload> {
    let row = ctx.db.get_assistant(&name).await.map_err(internal)?;
    Ok(Response::Assistant {
        assistant: row.map(assistant_to_proto),
    })
}

async fn diagnose_media_reservation_response(
    ctx: &Arc<DaemonContext>,
    scope: String,
    id: String,
) -> std::result::Result<Response, ErrorPayload> {
    let diagnosis = ctx
        .media_ledger
        .diagnose_accounting(&scope, &id)
        .await
        .map_err(|error| bad_request(error.to_string()))?;
    Ok(Response::MediaReservationDiagnosis {
        diagnosis_json: serde_json::to_string(&diagnosis).map_err(internal)?,
    })
}

async fn get_doctor_snapshot_response(
    db: Option<crate::db::Db>,
    vault: Arc<crate::secure_key::SecretVault>,
    project_root: Option<String>,
    no_sandbox: bool,
    offline: bool,
) -> std::result::Result<Response, ErrorPayload> {
    // `cli_snapshot` assembles a `!Send` future (it holds provider/config state
    // across `.await`). Drive it to completion on a dedicated current-thread
    // runtime inside `spawn_blocking` so it never crosses the concurrent
    // dispatch task's `Send` boundary. Only the rendered `String` and the
    // failure flag (both `Send`) leave the closure. The daemon injects its own
    // already-open `Db` (a cheap Arc-backed shared handle) so the snapshot never
    // opens a second DB. The vault-backed secret lookup lets the credential
    // check resolve `$secret:<name>` references after the literal-header
    // migration has rewritten provider config files.
    let (rendered, has_failures) = tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        let path = project_root.map(PathBuf::from);
        let store = crate::credentials::CredentialStore::from_vault(vault)
            .map_err(|error| error.to_string())?;
        let secret_lookup = |name: &str| store.named_secret(name).map(str::to_string);
        let snapshot = runtime
            .block_on(crate::diagnostics::cli_snapshot(
                path.as_deref(),
                no_sandbox,
                offline,
                db.as_ref(),
                Some(&secret_lookup),
            ))
            .map_err(|error| error.to_string())?;
        Ok::<(String, bool), String>((crate::diagnostics::render(&snapshot), snapshot.has_failures))
    })
    .await
    .map_err(internal)?
    .map_err(bad_request)?;
    Ok(Response::DoctorSnapshot {
        rendered,
        has_failures,
    })
}

/// Structured `{package, question}` brief consumed by the docs pipeline's
/// `parse_input`. Mirrors the JSON the former in-process `cockpit ask` built.
fn build_docs_ask_brief(package: Option<&str>, question: &str) -> String {
    serde_json::json!({
        "package": package.unwrap_or_default(),
        "question": question,
    })
    .to_string()
}

/// Owner-remoted `DocsAsk`: create a `"docs"`-agent session and run the
/// existing read-only package-question pipeline entirely inside the daemon,
/// returning the rendered answer. No standalone `SecureKeyActor` and no
/// CLI-opened `Db`: the vault, redaction-key resolver, config source, and env
/// baseline all come from the daemon context.
///
/// Trust + config resolution happen on this async task (Send DB reads); the
/// pipeline itself holds `!Send` provider/engine state across awaits, so it is
/// driven to completion on a dedicated current-thread runtime inside
/// `spawn_blocking` (mirroring `get_doctor_snapshot_response`). Only the
/// rendered answer `String` (Send) leaves the closure.
async fn docs_ask_response(
    ctx: &Arc<DaemonContext>,
    question: String,
    package: Option<String>,
    project_root: Option<String>,
) -> std::result::Result<Response, ErrorPayload> {
    let cwd = project_root
        .map(PathBuf::from)
        .unwrap_or_else(|| ctx.canonical_cwd.clone());
    let trust_policy = crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &cwd)
        .await
        .map_err(internal)?;
    let (providers, extended) = ctx
        .config_source()
        .load_effective_for_daemon(&cwd, &trust_policy)
        .map_err(daemon_config_error)?;

    let env_snapshot = ctx
        .env_baseline
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let resolver = ctx.redaction_key_resolver().map_err(internal)?;
    let vault = ctx.secret_vault.clone();
    let db = ctx.db.clone();

    // Async, owner-scoped pre-resolution BEFORE spawn_blocking: command
    // resolution is async subprocess work and cannot run on the sync docs build
    // inside spawn_blocking. Resolve into the daemon cache here (owner-scoped by
    // (provider, cwd)); the docs session then injects the cached outputs at its
    // sync redaction/model build via the installed cache.
    let command_secret_cache = ctx.registry.command_secret_cache();
    let docs_command_refs = crate::secret_ref::provider_named_secret_references(&providers);
    ctx.registry
        .resolve_provider_command_secrets(&cwd.display().to_string(), &docs_command_refs, false)
        .await;

    let answer = tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        runtime.block_on(run_docs_ask_pipeline(
            db,
            cwd,
            providers,
            extended,
            env_snapshot,
            resolver,
            vault,
            command_secret_cache,
            package,
            question,
        ))
    })
    .await
    .map_err(internal)?
    .map_err(bad_request)?;

    Ok(Response::DocsAnswer { answer })
}

/// Assemble the throwaway `"docs"` session + spawn args and run the two-stage
/// docs pipeline, returning its model-authored report. Runs on a dedicated
/// current-thread runtime (see `docs_ask_response`).
#[allow(clippy::too_many_arguments)]
async fn run_docs_ask_pipeline(
    db: crate::db::Db,
    cwd: PathBuf,
    providers: crate::config::providers::ProvidersConfig,
    extended: crate::config::extended::ExtendedConfig,
    env_snapshot: EnvSnapshot,
    resolver: Arc<dyn crate::redact::protected_redaction_history::RedactionKeyResolver>,
    vault: Arc<crate::secure_key::SecretVault>,
    command_secret_cache: Arc<crate::secret_command::CommandSecretCache>,
    package: Option<String>,
    question: String,
) -> std::result::Result<String, String> {
    let session = crate::session::Session::create(db.clone(), cwd.clone(), "docs", resolver, vault)
        .map_err(|error| format!("creating docs ask session: {error:#}"))?;
    // Install the daemon command-secret cache so this session's sync redaction
    // and model builds inject the (already pre-resolved) command outputs.
    session.set_command_secret_cache(Some(command_secret_cache));
    // The docs session is created outside the session worker, so it has no
    // attached daemon recovery journal; take the audited opt-out from the
    // inference journal barrier (its inference stays on the primary-row audit
    // path). This is one of the two enumerated `UnjournaledInferenceReason`
    // callers.
    session.allow_unjournaled_inference(crate::session::UnjournaledInferenceReason::DocsAsk);
    session.set_sandbox_enabled(true);
    session.set_approval_mode(extended.default_approval_mode);
    session.set_shell_compression(extended.shell_compression);
    if let Some(active) = providers.active_model.as_ref() {
        session
            .set_active_model_ref(active.clone())
            .map_err(|error| format!("recording active model for docs ask session: {error:#}"))?;
    }

    let store = session
        .provider_credential_store(&providers)
        .map_err(|error| format!("opening owner-scoped credential store: {error:#}"))?;
    let redact = Arc::new(
        crate::redact::RedactionTable::build_with_env_and_credential_store(
            &extended.redact,
            &cwd,
            env_snapshot.vars(),
            &store,
        )
        .map_err(|error| format!("building redaction table: {error:#}"))?,
    );
    let model = Arc::new(
        crate::engine::model::Model::from_config_with_store(
            &providers,
            redact.clone(),
            |name| env_snapshot.vars().get(name).cloned(),
            store.clone(),
        )
        .map_err(|error| format!("resolving active model: {error:#}"))?,
    );
    let reasoning_params = model.resolve_reasoning_params(&providers);
    let endpoint_recovery_reasoning_params = model.endpoint_recovery_reasoning_params(&providers);
    let config = crate::daemon::session_worker::SessionConfigHandle::detached(
        crate::daemon::session_worker::SessionConfigSnapshot::new(
            0,
            providers.clone(),
            extended.clone(),
        ),
    );
    let session = Arc::new(session);
    let spawn_args = crate::engine::builtin::SpawnArgs {
        model,
        params: crate::engine::model::ModelParams {
            additional_params: reasoning_params,
            endpoint_recovery_additional_params: endpoint_recovery_reasoning_params,
            prompt_cache_key: Some(session.id.to_string()),
            ..crate::engine::model::ModelParams::default()
        },
        env_overlay: Arc::new(std::sync::RwLock::new(Default::default())),
        cwd: cwd.clone(),
        config: config.clone(),
        session_short_id: session.short_id.clone(),
        assistant_identity_prefix: None,
        model_system_prompt_snapshot: session.model_system_prompt_snapshot(),
        interactive: false,
        llm_mode: extended.llm_mode,
        model_override: None,
        delegation_model: None,
        delegated: true,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        vnext_grant: None,
        vnext_host_policy: None,
        vnext_local_installation_resolver:
            crate::agents::LocalInstallationResolver::no_installations(),
        parent_vnext_grant: None,
        swarm_depth: 0,
        swarm_max_depth: crate::config::extended::DEFAULT_RECURSIVE_SPAWN_MAX_DEPTH,
        granted_tools: Vec::new(),
        lock_identity: None,
        write_scope: None,
        credential_store: Some(store),
    };
    let locks = Arc::new(
        crate::locks::LockManager::from_db(db)
            .await
            .map_err(|error| format!("loading lock state: {error:#}"))?,
    );
    let brief = build_docs_ask_brief(package.as_deref(), &question);
    let outcome = crate::engine::docs_pipeline::run(
        &brief,
        &spawn_args,
        session,
        locks,
        redact,
        config,
        None,
        Arc::new(crate::engine::interrupt::InterruptHub::detached()),
        tokio_util::sync::CancellationToken::new(),
        None,
        None,
        None,
    )
    .await
    .map_err(|error| format!("{error:#}"))?;
    Ok(outcome.report)
}

/// JSON projection of a package prune report.
fn package_prune_report_json(report: &crate::packages::PackagePruneReport) -> serde_json::Value {
    serde_json::json!({
        "deleted": report
            .deleted
            .iter()
            .map(|entry| serde_json::json!({
                "path": entry.path.display().to_string(),
                "bytes": entry.bytes,
            }))
            .collect::<Vec<_>>(),
        "bytes_reclaimed": report.bytes_reclaimed(),
        "skipped_groups": report.skipped_groups,
        "missing_dirs": report.missing_dirs,
        "failures": report
            .failures
            .iter()
            .map(|failure| serde_json::json!({
                "path": failure.path.display().to_string(),
                "reason": failure.reason,
            }))
            .collect::<Vec<_>>(),
    })
}

fn pinned_message_to_proto(row: crate::db::pins::PinnedMessage) -> proto::PinnedMessage {
    proto::PinnedMessage {
        seq: row.seq,
        is_assistant: row.is_assistant,
        text: row.text,
    }
}

fn project_note_to_proto(row: crate::db::project_notes::ProjectNote) -> proto::ProjectNote {
    proto::ProjectNote {
        id: row.id,
        project_root: row.project_root,
        name: row.name,
        content: row.content,
    }
}

/// Parse the closed sealed-owner scope kind. Rejects anything outside the fixed
/// `session|project|global` set.
fn parse_sealed_owner_scope_kind(
    raw: &str,
) -> anyhow::Result<crate::db::sealed_scope::SealedScopeKind> {
    match raw {
        "session" => Ok(crate::db::sealed_scope::SealedScopeKind::Session),
        "project" => Ok(crate::db::sealed_scope::SealedScopeKind::Project),
        "global" => Ok(crate::db::sealed_scope::SealedScopeKind::Global),
        other => {
            anyhow::bail!("scope kind must be `session`, `project`, or `global`, got `{other}`")
        }
    }
}

/// Validate the closed `BeginSealedOwnerOperation` disposition and its
/// per-disposition field presence. Create requires name + description +
/// scope_kind + scope_key and no record id; replace/rotate/recover require a
/// record id and none of the create fields. This is the content-free pre-persist
/// shape gate; it never touches a literal.
fn validate_sealed_begin_shape(
    disposition: &str,
    record_id: Option<&str>,
    name: Option<&str>,
    description: Option<&str>,
    scope_kind: Option<&str>,
    scope_key: Option<&str>,
) -> anyhow::Result<()> {
    match disposition {
        "create" => {
            if record_id.is_some() {
                anyhow::bail!("create begin must not carry a record id");
            }
            let name = name.context("create begin requires a name")?;
            crate::sealed::identity::SealedName::canonical(name)?;
            let description = description.context("create begin requires a description")?;
            crate::sealed::identity::SealedDescription::parse(description)?;
            let scope_kind = scope_kind.context("create begin requires a scope kind")?;
            parse_sealed_owner_scope_kind(scope_kind)?;
            // `scope_key` is required for session/project; global uses an empty
            // key. Presence (possibly empty) is required so the wire is explicit.
            scope_key.context("create begin requires a scope key field")?;
        }
        "replace" | "rotate" | "recover" => {
            let record_id = record_id.context("this disposition requires a record id")?;
            crate::sealed::identity::SealedRecordId::parse(record_id)?;
            if name.is_some()
                || description.is_some()
                || scope_kind.is_some()
                || scope_key.is_some()
            {
                anyhow::bail!("replace/rotate/recover begin must carry only a record id");
            }
        }
        other => anyhow::bail!(
            "disposition must be `create`, `replace`, `rotate`, or `recover`, got `{other}`"
        ),
    }
    Ok(())
}

/// Build the production sealed-value directory from daemon-held state.
///
/// The daemon's wrap-key vault backs the compartment (the same vault that stores
/// session-sealed and compartment-scope literals), and the protected
/// redaction-history key resolver, when the native secure-key actor has
/// attached, is installed so session-scope create/rotate journal their adoption.
/// Cheap to build per request: it clones the `Db` handle and the vault `Arc`.
fn sealed_value_directory(ctx: &DaemonContext) -> crate::sealed::store::SealedValueDirectory {
    let compartment =
        crate::sealed::compartment::SealedCompartment::from_vault(ctx.secret_vault.clone());
    let mut directory =
        crate::sealed::store::SealedValueDirectory::new(ctx.db.clone(), compartment);
    if let Some(resolver) = ctx.redaction_key_resolver.clone() {
        directory = directory.with_redaction_resolver(resolver);
    }
    directory
}

/// Build the SQLite-backed sealed-action directory over the daemon database.
/// Action instances are durable, so this holds only a cheap `Db` handle clone.
fn sealed_action_directory(
    ctx: &DaemonContext,
) -> crate::sealed::action_admin::SealedActionDirectory {
    crate::sealed::action_admin::SealedActionDirectory::new(ctx.db.clone())
}

/// Project a safe action-instance summary into its wire form.
fn sealed_action_summary_to_wire(
    summary: crate::sealed::action_admin::SealedActionInstanceSummary,
) -> proto::SealedActionSummaryWire {
    proto::SealedActionSummaryWire {
        action_id: summary.action_id,
        revision: summary.revision,
        enabled: summary.enabled,
        description: summary.description,
        project_key: summary.project_key,
    }
}

/// Reconstruct a typed [`SealedScopeRef`] from the wire scope kind + key. Session
/// scope requires a parseable session id; global ignores the key; project takes
/// the canonical key verbatim.
fn build_sealed_scope_ref(
    scope_kind: Option<String>,
    scope_key: Option<String>,
) -> anyhow::Result<crate::sealed::identity::SealedScopeRef> {
    use crate::sealed::identity::{SealedProjectKey, SealedScopeRef};
    let kind =
        parse_sealed_owner_scope_kind(scope_kind.as_deref().context("a scope kind is required")?)?;
    let key = scope_key.unwrap_or_default();
    match kind {
        crate::db::sealed_scope::SealedScopeKind::Session => Ok(SealedScopeRef::Session(
            uuid::Uuid::parse_str(&key).context("session scope key must be a session id")?,
        )),
        crate::db::sealed_scope::SealedScopeKind::Project => Ok(SealedScopeRef::Project(
            SealedProjectKey::from_canonical(key),
        )),
        crate::db::sealed_scope::SealedScopeKind::Global => Ok(SealedScopeRef::Global),
    }
}

/// Build the typed [`BeginSensitiveInput`] from the already-shape-validated wire
/// fields. Shape validation ([`validate_sealed_begin_shape`]) has run, so the
/// per-disposition fields are present; this only reparses them into the typed
/// domain values the library `begin` consumes.
fn build_begin_sensitive_input(
    disposition: &str,
    record_id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    scope_kind: Option<String>,
    scope_key: Option<String>,
) -> anyhow::Result<crate::sealed::owner::BeginSensitiveInput> {
    use crate::sealed::identity::{SealedDescription, SealedName, SealedRecordId};
    use crate::sealed::owner::BeginSensitiveInput;
    match disposition {
        "create" => {
            let name = SealedName::canonical(&name.context("create begin requires a name")?)?;
            let description = SealedDescription::parse(
                &description.context("create begin requires a description")?,
            )?;
            let scope = build_sealed_scope_ref(scope_kind, scope_key)?;
            Ok(BeginSensitiveInput::Create {
                scope,
                name,
                description,
            })
        }
        "replace" => Ok(BeginSensitiveInput::Replace {
            record_id: SealedRecordId::parse(&record_id.context("replace requires a record id")?)?,
        }),
        "rotate" => Ok(BeginSensitiveInput::Rotate {
            record_id: SealedRecordId::parse(&record_id.context("rotate requires a record id")?)?,
        }),
        "recover" => Ok(BeginSensitiveInput::Recover {
            record_id: SealedRecordId::parse(&record_id.context("recover requires a record id")?)?,
        }),
        other => anyhow::bail!("unknown sealed-owner disposition `{other}`"),
    }
}

/// Project a persisted sealed-value record row into a safe wire inventory item.
/// Carries no literal — only the owner-safe metadata the record row holds.
fn sealed_record_row_to_inventory_item(
    row: crate::db::sealed_scope::SealedValueRecordRow,
) -> proto::SealedOwnerInventoryItem {
    let scope_kind = match row.scope {
        crate::db::sealed_scope::SealedScopeKind::Session => proto::SealedOwnerScopeKind::Session,
        crate::db::sealed_scope::SealedScopeKind::Project => proto::SealedOwnerScopeKind::Project,
        crate::db::sealed_scope::SealedScopeKind::Global => proto::SealedOwnerScopeKind::Global,
    };
    proto::SealedOwnerInventoryItem {
        record_id: row.record_id,
        name: row.name,
        description: row.description,
        scope_kind,
        scope_key: row.scope_key,
        active_version: u32::try_from(row.active_version).unwrap_or(0),
        created_at_ms: row.created_at_ms,
    }
}

/// The closed server-side catalog that resolves the three `CreateSealedAction`
/// ids to a compiled [`SealedActionKind`].
///
/// The ids are closed lookups, never free-form payloads: `kind_id` selects a
/// builtin kind template (a fixed origin allowlist, credential placement, path
/// template, and parameter specs — all host-owned, never on the wire),
/// `origin_id` indexes into that template's allowlist, and `projection_id`
/// selects the fixed projection. Any unknown id is rejected here, before any
/// persist. The builtin catalog is intentionally small; the persistence sibling
/// installs the durable action directory that these snapshots are written to.
fn resolve_sealed_action_kind(
    kind_id: &str,
    origin_id: &str,
    projection_id: &str,
) -> anyhow::Result<crate::sealed::action_admin::SealedActionKind> {
    use crate::sealed::action_admin::{
        HttpsCredentialPlacement, HttpsOriginAllowlist, SealedActionKind, SealedProjectionId,
    };

    // Closed builtin kind templates. Each entry is a fixed, host-owned template;
    // the wire never supplies an origin URL, header, or path.
    struct KindTemplate {
        origins: &'static [&'static str],
        header_name: &'static str,
        path_template: &'static str,
    }
    // `origin_id` selects one origin from the template's allowlist by index.
    let template = match kind_id {
        "https.notify" => KindTemplate {
            origins: &[
                "https://api.deploy.example.com",
                "https://api.deploy-staging.example.com",
            ],
            header_name: "X-Deploy-Key",
            path_template: "/v1/notify",
        },
        other => anyhow::bail!("unknown sealed action kind id: `{other}`"),
    };

    let index: usize = origin_id
        .parse()
        .map_err(|_| anyhow::anyhow!("origin id must be a non-negative index"))?;
    if index >= template.origins.len() {
        anyhow::bail!("origin id `{origin_id}` is out of range for kind `{kind_id}`");
    }
    // The compiled kind carries the SELECTED origin only.
    let origins = HttpsOriginAllowlist::from_raw(&[template.origins[index]])?;
    let projection = SealedProjectionId::parse(projection_id)?;
    Ok(SealedActionKind::Https {
        origins,
        credential_placement: HttpsCredentialPlacement::Header {
            header_name: template.header_name.to_string(),
        },
        path_template: template.path_template.to_string(),
        projection,
        parameters: std::collections::BTreeMap::new(),
    })
}

async fn ensure_project_note_member(
    db: &crate::db::Db,
    project_root: &str,
    id: uuid::Uuid,
) -> std::result::Result<(), ErrorPayload> {
    let found = db
        .list_project_notes(project_root)
        .await
        .map_err(internal)?
        .into_iter()
        .any(|note| note.id == id);
    if found {
        Ok(())
    } else {
        Err(bad_request(format!(
            "project note `{id}` does not belong to project root `{project_root}`"
        )))
    }
}

pub(super) fn stats_range_from_proto(range: proto::StatsRange) -> crate::db::stats::StatsRange {
    match range {
        proto::StatsRange::Last7Days => crate::db::stats::StatsRange::Last7Days,
        proto::StatsRange::AllTime => crate::db::stats::StatsRange::AllTime,
    }
}

pub(super) async fn stats_rollup(
    ctx: &Arc<DaemonContext>,
    project_id: Option<String>,
    range: proto::StatsRange,
    by_role: bool,
) -> std::result::Result<Response, ErrorPayload> {
    let scope = project_id
        .map(crate::db::stats::StatsScope::Project)
        .unwrap_or(crate::db::stats::StatsScope::All);
    let range = stats_range_from_proto(range);
    let prices = crate::db::stats::PriceTable::load_default();
    let now = chrono::Utc::now().timestamp();
    let rollup = ctx
        .db
        .read(move |conn| crate::db::stats::rollup(conn, &scope, range, &prices, by_role, now))
        .await
        .map_err(internal)?;
    Ok(Response::StatsRollup { rollup })
}

fn staging_error(error: crate::daemon::bulk_staging::BulkStagingError) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::BadRequest,
        message: format!("bulk transfer rejected: {error}"),
    }
}

/// Accept one pushed chunk of a bulk transfer into daemon-side staging.
pub(super) async fn write_bulk_transfer_chunk(
    transfer: &cockpit_proto::bulk_transfer::BulkTransferRef,
    chunk_index: u32,
    data_base64: &str,
    owner: Option<&crate::daemon::bulk_staging::BulkTransferOwner>,
) -> std::result::Result<Response, ErrorPayload> {
    if data_base64.len() > cockpit_proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "bulk transfer chunk exceeds the advertised chunk bound".to_string(),
        });
    }
    let chunk = base64::engine::general_purpose::STANDARD
        .decode(data_base64)
        .map_err(|error| ErrorPayload {
            code: ErrorCode::BadRequest,
            message: format!("invalid bulk transfer chunk encoding: {error}"),
        })?;
    let accepted = match transfer.mime_class {
        cockpit_proto::bulk_transfer::BulkMimeClass::Opaque => {
            let owner = owner.ok_or_else(unavailable_bulk_user_message_transfer)?;
            crate::daemon::bulk_staging::write_chunk_owned(transfer, owner, chunk_index, &chunk)
                .map_err(|error| match error {
                    crate::daemon::bulk_staging::BulkStagingError::OwnerMismatch => {
                        unavailable_bulk_user_message_transfer()
                    }
                    other => staging_error(other),
                })?
        }
        _ => crate::daemon::bulk_staging::write_chunk(transfer, chunk_index, &chunk)
            .map_err(staging_error)?,
    };
    Ok(Response::BulkTransferChunkAccepted {
        next_chunk_index: accepted.next_chunk_index,
        received_bytes: cockpit_proto::wire_scalar::CanonicalU64DecimalStringV1::from_u64(
            accepted.received_bytes,
        ),
        complete: accepted.complete,
        // Advertise the deadline so the peer is never surprised by expiry.
        idle_timeout_ms: crate::daemon::bulk_staging::STAGED_TRANSFER_TTL_MS as u32,
    })
}

/// Serve one chunk of an owner-local raw export.
///
/// This generic export reader must never become a second consumer for opaque
/// user-message staging: an opaque transfer id is only a locator and carries
/// no session/actor proof on this request shape. User-message bodies are
/// consumed exclusively by the owned `SendUserMessageBulk` path.
pub(super) async fn read_bulk_transfer_chunk(
    transfer_id: &cockpit_proto::bulk_transfer::BulkTransferId,
    chunk_index: u32,
) -> std::result::Result<Response, ErrorPayload> {
    let (chunk, last) = crate::daemon::bulk_staging::read_chunk_of_kind(
        *transfer_id.as_bytes(),
        chunk_index,
        cockpit_proto::bulk_transfer::BulkMimeClass::Export,
    )
    .map_err(staging_error)?;
    Ok(Response::BulkTransferChunk {
        chunk_index,
        data_base64: base64::engine::general_purpose::STANDARD.encode(&chunk),
        last,
    })
}

pub(super) async fn import_session_archive(
    ctx: &Arc<DaemonContext>,
    transfer: &cockpit_proto::bulk_transfer::BulkTransferRef,
) -> std::result::Result<Response, ErrorPayload> {
    // The archive bytes were staged by prior WriteBulkTransferChunk calls; the
    // staging layer verified their length and SHA-256 before releasing them.
    let bytes = crate::daemon::bulk_staging::take(transfer).map_err(staging_error)?;
    let archive =
        crate::session::import::read_archive_bytes(&bytes).map_err(|error| ErrorPayload {
            code: ErrorCode::BadRequest,
            message: format!("invalid session import archive: {error:#}"),
        })?;
    let result = crate::session::import::import_archive(&ctx.db, archive)
        .await
        .map_err(internal)?;
    Ok(Response::ImportSessionArchive {
        imported: result.imported,
        redacted: result.redacted,
    })
}

/// Stage exported bytes for bulk pull and return their bounded reference.
///
/// The `mime_class` is the transfer's identity: a REDACTED export is staged as
/// [`RemoteBulkMimeClass::RedactedExport`] (served by the owner-remoted
/// type-bound reader), a RAW export as [`RemoteBulkMimeClass::Export`] (served
/// only by the owner-local generic reader). Passing the wrong class would let a
/// raw archive be pulled by the remoted reader, so the class is chosen at the
/// single assemble funnel below, never by the caller streaming it back.
fn stage_export_bytes(
    bytes: &[u8],
    mime_class: cockpit_proto::bulk_transfer::BulkMimeClass,
) -> std::result::Result<cockpit_proto::bulk_transfer::BulkTransferRef, ErrorPayload> {
    use rand::RngExt as _;
    let mut transfer_id = [0u8; 16];
    rand::rng().fill(&mut transfer_id[..]);
    // A random 128-bit id is never all-zero in practice; force it if it is.
    if transfer_id.iter().all(|b| *b == 0) {
        transfer_id[0] = 1;
    }
    crate::daemon::bulk_staging::stage(bytes, mime_class, transfer_id).map_err(staging_error)
}

/// Serve one chunk of a REDACTED export transfer to an owner-remoted caller.
///
/// The type-bound reader admits a transfer ONLY when its staged kind is
/// [`RemoteBulkMimeClass::RedactedExport`]; a raw `Export` id (or any other bulk
/// kind, or an unknown/non-export transfer) is refused by
/// [`crate::daemon::bulk_staging::read_chunk_of_kind`] with no bytes returned.
/// This is what keeps the raw archive owner-local while a redacted export is
/// downloadable over the wire.
pub(super) async fn read_redacted_export_chunk(
    transfer_id: &cockpit_proto::bulk_transfer::BulkTransferId,
    chunk_index: u32,
) -> std::result::Result<Response, ErrorPayload> {
    let (chunk, last) = crate::daemon::bulk_staging::read_chunk_of_kind(
        *transfer_id.as_bytes(),
        chunk_index,
        cockpit_proto::bulk_transfer::BulkMimeClass::RedactedExport,
    )
    .map_err(staging_error)?;
    Ok(Response::BulkTransferChunk {
        chunk_index,
        data_base64: base64::engine::general_purpose::STANDARD.encode(&chunk),
        last,
    })
}

pub(super) async fn export_session_data(
    ctx: &Arc<DaemonContext>,
    session_id: Uuid,
    kind: proto::ExportSessionKind,
    include_generated_artifacts: bool,
    include_sensitive: bool,
    local_owner_action: bool,
) -> std::result::Result<Response, ErrorPayload> {
    use cockpit_proto::bulk_transfer::BulkMimeClass as RemoteBulkMimeClass;
    // AC1: the raw, unredacted export is owner-LOCAL only. A remoted caller (a
    // remote-operation ledger dispatch, or any non-owner principal) is refused
    // BEFORE any archive is assembled or staged, so the only remoted success
    // path is the redacted one. This is the single dispatch funnel that decides
    // raw-vs-redacted; a future caller cannot reach the raw assembler without
    // passing this gate.
    if include_sensitive && !local_owner_action {
        return Err(ErrorPayload {
            code: ErrorCode::Authorization,
            message: "raw `--include-sensitive` export is owner-local only; a remoted \
                      caller cannot request the unredacted archive"
                .to_string(),
        });
    }
    let db = ctx.db.clone();
    let target = db
        .get_session(session_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ErrorPayload {
            code: ErrorCode::UnknownSession,
            message: format!("unknown session {session_id}"),
        })?;
    // A redacted export rides the type-bound RedactedExport class (owner-remoted
    // reader); the raw archive rides the plain Export class (owner-local generic
    // reader only).
    let mime_class = if include_sensitive {
        RemoteBulkMimeClass::Export
    } else {
        RemoteBulkMimeClass::RedactedExport
    };
    let data = match kind {
        proto::ExportSessionKind::TranscriptJson => {
            let bytes = if include_sensitive {
                // Raw local transcript: the unredacted message bodies verbatim.
                // No redaction and no history fold, so the multi-read is benign
                // (the raw archive shows everything regardless).
                let mut messages = Vec::new();
                let mut before_seq = None;
                loop {
                    let (mut page, has_more) = db
                        .read_session_messages(session_id, before_seq, u32::MAX)
                        .await
                        .map_err(internal)?;
                    if page.is_empty() {
                        break;
                    }
                    before_seq = page.first().map(|message| message.seq);
                    messages.append(&mut page);
                    if !has_more {
                        break;
                    }
                }
                messages.sort_by_key(|message| message.seq);
                serde_json::to_vec_pretty(&messages).map_err(internal)?
            } else {
                // Redacted transcript: the message reads, the protected-history
                // fold, and the scrub all run inside ONE read snapshot, so the
                // transcribed message set and the folded-literal set come from
                // the SAME snapshot — no discover-then-assemble TOCTOU. Fails
                // closed on any resolver/integrity error (no partial artifact).
                let resolver = ctx.redaction_key_resolver().map_err(internal)?;
                // Feed the live daemon environment baseline into the export
                // redaction table so an env-derived secret that surfaces in a
                // transcript member is scrubbed even when it was never
                // independently persisted or journaled (defense-in-depth: the
                // same env source the live session redaction path uses).
                let env = ctx
                    .env_baseline
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .vars()
                    .clone();
                crate::session::export::build_redacted_transcript_json_bytes(
                    &db,
                    &target,
                    &ctx.secret_vault,
                    resolver,
                    env,
                )
                .await
                .map_err(internal)?
            };
            let transfer = stage_export_bytes(&bytes, mime_class)?;
            proto::ExportSessionData {
                session_id,
                kind,
                filename_extension: "json".to_string(),
                mime: "application/json".to_string(),
                transfer,
                session_count: Some(1),
                redacted: !include_sensitive,
            }
        }
        proto::ExportSessionKind::DebugBundle => {
            let bundle = if include_sensitive {
                crate::session::export::build_bundle_zip_bytes_raw_local(
                    &db,
                    &target,
                    include_generated_artifacts,
                )
                .await
                .map_err(internal)?
            } else {
                // The debug bundle folds protected-history literals IN the same
                // read snapshot that discovers and assembles the bundle (the
                // resolver is warmed then threaded into the assembly), so a fork
                // or `/compact` successor committed concurrently can never be
                // assembled without its journal literals folded — closing the
                // discover-then-assemble TOCTOU. Fails closed on any
                // resolver/integrity error.
                let resolver = ctx.redaction_key_resolver().map_err(internal)?;
                // Feed the live daemon environment baseline into the export
                // redaction table (see the transcript branch): an env-derived
                // secret embedded in a config/approval/artifact member is
                // scrubbed even when it was never persisted or journaled.
                let env = ctx
                    .env_baseline
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .vars()
                    .clone();
                crate::session::export::build_bundle_zip_bytes(
                    &db,
                    &target,
                    include_generated_artifacts,
                    &ctx.secret_vault,
                    resolver,
                    env,
                )
                .await
                .map_err(internal)?
            };
            let transfer = stage_export_bytes(&bundle.bytes, mime_class)?;
            proto::ExportSessionData {
                session_id,
                kind,
                filename_extension: "zip".to_string(),
                mime: "application/zip".to_string(),
                transfer,
                session_count: Some(bundle.summary.session_count),
                redacted: !include_sensitive,
            }
        }
    };
    Ok(Response::ExportSessionData { data })
}

pub(super) async fn auto_title_request(
    ctx: &Arc<DaemonContext>,
    session_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    let live = ctx.registry.live_handle(session_id);
    let session = if let Some(handle) = live.as_ref() {
        handle.session()
    } else {
        let session = std::sync::Arc::new(
            crate::session::Session::resume(
                ctx.db.clone(),
                session_id,
                ctx.redaction_key_resolver().map_err(internal)?,
                ctx.secret_vault.clone(),
            )
            .map_err(internal)?
            .ok_or_else(|| ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {session_id}"),
            })?,
        );
        // Resumed outside the session worker: install the daemon command-secret
        // cache so this title model's store funnel injects resolved command
        // outputs (the live branch already carries the cache on its session).
        session.set_command_secret_cache(Some(ctx.registry.command_secret_cache()));
        session
    };

    if session.title().is_some() {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "session already has a title".to_string(),
        });
    }

    let trust_policy = crate::config::trust::resolve_workspace_trust_policy_from_db(
        &ctx.db,
        &session.project_root,
    )
    .await
    .map_err(workspace_trust_error)?;
    let (providers, extended) = ctx
        .config_source()
        .load_with_trust(&session.project_root, &trust_policy)
        .map_err(workspace_trust_error)?;
    let redact = if let Some(handle) = live {
        handle.redaction_table()
    } else {
        let table = match session.persisted_redaction_table().map_err(internal)? {
            Some(table) => table,
            None => crate::redact::RedactionTable::build(&extended.redact, &session.project_root)
                .map_err(internal)?,
        };
        std::sync::Arc::new(table)
    };

    let title = crate::auto_title::generate_session_title_slug_once(
        &session,
        extended,
        providers,
        redact,
        String::new(),
        crate::session::TitleAction::Explicit,
    )
    .await
    .map_err(|error| {
        crate::engine::model::log_utility_model_failure("auto_title", &error);
        ErrorPayload {
            code: ErrorCode::BadRequest,
            // Rig's provider-response display includes provider-owned body and
            // request-id details. Keep those out of this RPC error channel.
            message: crate::engine::model::safe_inference_error_detail(&error)
                .map_or_else(|| error.to_string(), |safe| safe.marker_string()),
        }
    })?
    .ok_or_else(|| ErrorPayload {
        code: ErrorCode::BadRequest,
        message: "utility model returned no usable title".to_string(),
    })?;

    if !session
        .set_explicit_auto_title_if_untitled(&title)
        .map_err(internal)?
    {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "session already has a title".to_string(),
        });
    }

    Ok(Response::AutoTitle { session_id, title })
}

pub(super) async fn curator_request(
    ctx: &Arc<DaemonContext>,
    project_root: PathBuf,
    action: proto::CuratorAction,
) -> std::result::Result<Response, ErrorPayload> {
    let trust_policy =
        crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &project_root)
            .await
            .map_err(workspace_trust_error)?;
    let (_, extended) = ctx
        .config_source()
        .load_with_trust(&project_root, &trust_policy)
        .map_err(workspace_trust_error)?;
    let db = ctx.db.clone();
    let run_cron_refs = if matches!(action, proto::CuratorAction::Run { .. }) {
        Some(
            crate::skills::curator::cron_referenced_skills(&db)
                .await
                .map_err(|error| ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: error.to_string(),
                })?,
        )
    } else {
        None
    };
    let result = crate::config::trust::scope_workspace_trust_policy(trust_policy, async move {
        let curator = crate::skills::curator::SkillCurator::new(db, project_root, extended.skills);
        let result: Result<proto::CuratorResult> = match action {
            proto::CuratorAction::Status => Ok(proto::CuratorResult::Status {
                status: curator_status_to_proto(curator.status().await?),
            }),
            proto::CuratorAction::Run {
                dry_run,
                consolidate,
            } => Ok(proto::CuratorResult::Run {
                report: curator_run_report_to_proto(
                    curator
                        .run_with_cron_refs(
                            crate::skills::curator::CuratorRunOptions {
                                dry_run,
                                consolidate,
                            },
                            run_cron_refs.context("scheduler skill references not loaded")?,
                        )
                        .await?,
                ),
            }),
            proto::CuratorAction::Pin { name } => {
                curator.pin(&name, true).await?;
                Ok(proto::CuratorResult::Pinned { name, pinned: true })
            }
            proto::CuratorAction::Unpin { name } => {
                curator.pin(&name, false).await?;
                Ok(proto::CuratorResult::Pinned {
                    name,
                    pinned: false,
                })
            }
            proto::CuratorAction::Restore { name } => {
                curator.restore(&name).await?;
                Ok(proto::CuratorResult::Restored { name })
            }
            proto::CuratorAction::Rollback { list, id } => {
                if list {
                    Ok(proto::CuratorResult::Snapshots {
                        snapshots: curator
                            .snapshots()
                            .await?
                            .into_iter()
                            .map(curator_snapshot_to_proto)
                            .collect(),
                    })
                } else {
                    Ok(proto::CuratorResult::RolledBack {
                        snapshot: curator_snapshot_to_proto(curator.rollback(id.as_deref()).await?),
                    })
                }
            }
        };
        result
    })
    .await
    .map_err(|error| ErrorPayload {
        code: ErrorCode::BadRequest,
        message: error.to_string(),
    })?;
    Ok(Response::Curator { result })
}

pub(super) fn curator_status_to_proto(
    status: crate::skills::curator::CuratorStatus,
) -> proto::CuratorStatus {
    proto::CuratorStatus {
        skills: status
            .skills
            .into_iter()
            .map(curator_skill_to_proto)
            .collect(),
        snapshots: status
            .snapshots
            .into_iter()
            .map(curator_snapshot_to_proto)
            .collect(),
    }
}

pub(super) fn curator_skill_to_proto(
    skill: crate::skills::curator::CuratorSkillStatus,
) -> proto::CuratorSkillStatus {
    proto::CuratorSkillStatus {
        name: skill.name,
        state: skill.state,
        created_by: skill.created_by,
        use_count: skill.use_count,
        view_count: skill.view_count,
        pinned: skill.pinned,
        source_path: skill.source_path,
        archive_path: skill.archive_path,
    }
}

pub(super) fn curator_snapshot_to_proto(
    snapshot: crate::skills::curator::CuratorSnapshotStatus,
) -> proto::CuratorSnapshotStatus {
    proto::CuratorSnapshotStatus {
        id: snapshot.id,
        path: snapshot.path,
        reason: snapshot.reason,
        created_at: snapshot.created_at,
    }
}

pub(super) fn curator_run_report_to_proto(
    report: crate::skills::curator::CuratorRunReport,
) -> proto::CuratorRunReport {
    proto::CuratorRunReport {
        dry_run: report.dry_run,
        scanned: report.scanned,
        stale: report.stale,
        archived: report.archived,
        reactivated: report.reactivated,
        skipped: report.skipped,
        snapshot_id: report.snapshot_id,
        consolidation: report.consolidation,
    }
}

pub(super) fn paused_work_to_proto(
    row: crate::db::paused_work::PausedWorkRow,
) -> proto::PausedWorkSummary {
    proto::PausedWorkSummary {
        session_id: row.session_id,
        active_agent: row.active_agent,
        project_root: row.project_root,
        reason: row.reason,
        pending_tool_count: row.pending_tool_count,
        daemon_version: row.daemon_version,
        client_version: row.client_version,
        updated_at: row.updated_at,
    }
}
