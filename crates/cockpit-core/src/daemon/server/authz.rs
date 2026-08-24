use super::sessions::*;
use super::*;

#[cfg(feature = "remote")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AuthorizedFcorResource {
    pub(super) kind: proto::remote_operation_fcor::RemoteOperationResourceKind,
    pub(super) value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizedRequestContext {
    #[cfg(feature = "remote")]
    pub(super) fcor_resources: Vec<AuthorizedFcorResource>,
}

#[cfg(feature = "remote")]
impl AuthorizedRequestContext {
    /// Build the canonical operation bytes from resources resolved at the
    /// authorization boundary. Callers must supply the request-specific
    /// canonical parameter encoding; schema text or transport JSON are not
    /// valid substitutes.
    pub(super) fn encode_fcor(
        &self,
        request: &Request,
        canonical_params: &[u8],
    ) -> std::result::Result<Vec<u8>, ErrorPayload> {
        let resources: Vec<_> = self
            .fcor_resources
            .iter()
            .map(
                |resource| proto::remote_operation_fcor::RemoteOperationResource {
                    kind: resource.kind,
                    value: resource.value.as_slice(),
                },
            )
            .collect();
        proto::remote_operation_fcor::encode_fcor_v1(
            request.wire_tag(),
            &resources,
            canonical_params,
        )
        .map_err(|error| ErrorPayload {
            code: ErrorCode::BadRequest,
            message: format!("request cannot be canonically encoded: {error}"),
        })
    }
}

#[cfg(feature = "remote")]
fn canonical_project_root_bytes(
    path: &std::path::Path,
) -> std::result::Result<Vec<u8>, ErrorPayload> {
    let text = path.to_str().ok_or_else(|| ErrorPayload {
        code: ErrorCode::BadRequest,
        message: "canonical project root is not valid UTF-8".into(),
    })?;
    Ok(text.as_bytes().to_vec())
}

#[cfg(feature = "remote")]
fn push_fcor_resource(
    resources: &mut Vec<AuthorizedFcorResource>,
    kind: proto::remote_operation_fcor::RemoteOperationResourceKind,
    value: Vec<u8>,
) {
    resources.push(AuthorizedFcorResource { kind, value });
}

#[cfg(feature = "remote")]
trait SessionFcorResource {
    fn push_to(&self, resources: &mut Vec<AuthorizedFcorResource>);
}
#[cfg(feature = "remote")]
impl SessionFcorResource for Uuid {
    fn push_to(&self, resources: &mut Vec<AuthorizedFcorResource>) {
        push_fcor_resource(
            resources,
            proto::remote_operation_fcor::RemoteOperationResourceKind::SessionUuid,
            self.as_bytes().to_vec(),
        );
    }
}
#[cfg(feature = "remote")]
impl SessionFcorResource for Option<Uuid> {
    fn push_to(&self, resources: &mut Vec<AuthorizedFcorResource>) {
        if let Some(value) = self {
            value.push_to(resources);
        }
    }
}

#[cfg(feature = "remote")]
trait OptionalFcorText {
    fn optional_text(&self) -> Option<&str>;
}
#[cfg(feature = "remote")]
impl OptionalFcorText for String {
    fn optional_text(&self) -> Option<&str> {
        Some(self)
    }
}
#[cfg(feature = "remote")]
impl OptionalFcorText for Option<String> {
    fn optional_text(&self) -> Option<&str> {
        self.as_deref()
    }
}

#[cfg(feature = "remote")]
macro_rules! resolve_fcor_role {
    ($resources:ident, $cwd:ident, $name:ident => param) => {
        let _ = $name;
    };
    ($resources:ident, $cwd:ident, $name:ident => scheduled) => {{
        use proto::remote_operation_fcor::RemoteOperationResourceKind as Kind;
        push_fcor_resource(
            &mut $resources,
            Kind::SchedulerId,
            $name.id.as_bytes().to_vec(),
        );
        if let proto::ScheduledJobPayload::RunPrompt { project_root, .. } = &$name.payload {
            let canonical = crate::daemon::fs_api::canonical_project_root(project_root)?;
            push_fcor_resource(
                &mut $resources,
                Kind::ProjectRoot,
                canonical_project_root_bytes(&canonical)?,
            );
        }
    }};
    ($resources:ident, $cwd:ident, $name:ident => session) => {
        $name.push_to(&mut $resources);
    };
    ($resources:ident, $cwd:ident, $name:ident => project_root_effective) => {{
        let raw = $name
            .as_deref()
            .unwrap_or_else(|| $cwd.to_str().unwrap_or(""));
        let canonical = crate::daemon::fs_api::canonical_project_root(raw)?;
        push_fcor_resource(
            &mut $resources,
            proto::remote_operation_fcor::RemoteOperationResourceKind::ProjectRoot,
            canonical_project_root_bytes(&canonical)?,
        );
    }};
    ($resources:ident, $cwd:ident, $name:ident => project_root) => {{
        // `$name` is either a `&String` (mandatory root) or a `&Option<String>`
        // (optional filter); `optional_text` yields `Some(&str)` for the former
        // always and for the latter only when present, so a mandatory root still
        // derives its resource unconditionally.
        if let Some(raw) = $name.optional_text() {
            let canonical = crate::daemon::fs_api::canonical_project_root(raw)?;
            push_fcor_resource(
                &mut $resources,
                proto::remote_operation_fcor::RemoteOperationResourceKind::ProjectRoot,
                canonical_project_root_bytes(&canonical)?,
            );
        }
    }};
    ($resources:ident, $cwd:ident, $name:ident => project) => {
        if let Some(value) = $name {
            push_fcor_resource(
                &mut $resources,
                proto::remote_operation_fcor::RemoteOperationResourceKind::ProjectId,
                value.as_bytes().to_vec(),
            );
        }
    };
    ($resources:ident, $cwd:ident, $name:ident => file_existing($root:ident)) => {{
        let canonical = crate::daemon::fs_api::resolve_authorized_canonical_path(
            $root,
            $name,
            crate::daemon::fs_api::AuthorizedCanonicalPathMode::Existing,
        )?;
        push_fcor_resource(
            &mut $resources,
            proto::remote_operation_fcor::RemoteOperationResourceKind::FilePath,
            canonical_project_root_bytes(&canonical)?,
        );
    }};
    ($resources:ident, $cwd:ident, $name:ident => file_write_target($root:ident)) => {{
        let canonical = crate::daemon::fs_api::resolve_authorized_canonical_path(
            $root,
            $name,
            crate::daemon::fs_api::AuthorizedCanonicalPathMode::WriteTarget,
        )?;
        push_fcor_resource(
            &mut $resources,
            proto::remote_operation_fcor::RemoteOperationResourceKind::FilePath,
            canonical_project_root_bytes(&canonical)?,
        );
    }};
    ($resources:ident, $cwd:ident, $name:ident => rename_source($root:ident)) => {{
        let canonical = crate::daemon::fs_api::resolve_authorized_canonical_path(
            $root,
            $name,
            crate::daemon::fs_api::AuthorizedCanonicalPathMode::RenameSource,
        )?;
        push_fcor_resource(
            &mut $resources,
            proto::remote_operation_fcor::RemoteOperationResourceKind::FilePath,
            canonical_project_root_bytes(&canonical)?,
        );
    }};
    ($resources:ident, $cwd:ident, $name:ident => terminal) => {
        push_fcor_resource(
            &mut $resources,
            proto::remote_operation_fcor::RemoteOperationResourceKind::TerminalUuid,
            $name.as_bytes().to_vec(),
        );
    };
    ($resources:ident, $cwd:ident, $name:ident => upload) => {
        push_fcor_resource(
            &mut $resources,
            proto::remote_operation_fcor::RemoteOperationResourceKind::UploadUuid,
            $name.as_bytes().to_vec(),
        );
    };
    ($resources:ident, $cwd:ident, $name:ident => interrupt) => {
        push_fcor_resource(
            &mut $resources,
            proto::remote_operation_fcor::RemoteOperationResourceKind::InterruptUuid,
            $name.as_bytes().to_vec(),
        );
    };
    ($resources:ident, $cwd:ident, $name:ident => queue) => {
        push_fcor_resource(
            &mut $resources,
            proto::remote_operation_fcor::RemoteOperationResourceKind::QueueUuid,
            $name.as_bytes().to_vec(),
        );
    };
    ($resources:ident, $cwd:ident, $name:ident => legacy_message) => {
        let _ = $name;
    };
    ($resources:ident, $cwd:ident, $name:ident => provider_model_right($left:ident)) => {
        let _ = ($name, $left);
    };
    ($resources:ident, $cwd:ident, $name:ident => provider_model_left($model:ident)) => {{
        if let (Some(provider), Some(model)) = ($name.optional_text(), $model.optional_text()) {
            let value =
                proto::remote_operation_fcor::encode_provider_model_resource_v1(provider, model)
                    .map_err(|error| ErrorPayload {
                        code: ErrorCode::BadRequest,
                        message: error.to_string(),
                    })?;
            push_fcor_resource(
                &mut $resources,
                proto::remote_operation_fcor::RemoteOperationResourceKind::ProviderModel,
                value,
            );
        }
    }};
}

#[cfg(feature = "remote")]
macro_rules! command_resolve_fcor_resources {
    (($request:ident, $cwd:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request { $($(#[$row_attr])* $pattern => {
            let mut resources = Vec::new();
            let _: &mut Vec<AuthorizedFcorResource> = &mut resources;
            let _ = $cwd;
            $(resolve_fcor_role!(resources, $cwd, $fcor_field => $fcor_role $(($($fcor_role_arg),*))?);)*
            Ok(resources)
        },)+ }
    }};
}

/// Resolve path-bearing FCOR resources only after request authorization.
/// Raw client path text never leaves this boundary.
#[cfg(feature = "remote")]
fn resolve_authorized_fcor_resources(
    request: &Request,
    daemon_cwd: &std::path::Path,
) -> std::result::Result<Vec<AuthorizedFcorResource>, ErrorPayload> {
    proto::command!(command_resolve_fcor_resources, request, daemon_cwd)
}

pub(super) async fn authorize_request_context(
    request: &Request,
    state: &MutableClientState,
    ctx: &DaemonContext,
) -> std::result::Result<AuthorizedRequestContext, ErrorPayload> {
    authorize_request(request, state, ctx).await?;
    #[cfg(all(test, feature = "remote"))]
    ctx.fcor_resolver_calls
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Ok(AuthorizedRequestContext {
        #[cfg(feature = "remote")]
        fcor_resources: resolve_authorized_fcor_resources(request, &ctx.canonical_cwd)?,
    })
}

pub(super) fn session_access_for_row(
    principal: &ClientPrincipal,
    row: &crate::db::sessions::SessionRow,
) -> SessionAccess {
    if principal.is_owner() {
        return SessionAccess::Owner;
    }
    let project_root = row.project_root.as_str();
    let created_by_this_principal = principal
        .tag()
        .as_deref()
        .is_some_and(|tag| row.created_by_principal.as_deref() == Some(tag));
    let scoped_to_session = created_by_this_principal || row.shared_with_collaborators;
    if !scoped_to_session {
        return SessionAccess::None;
    }
    if principal.can_agent_write_project(project_root) {
        SessionAccess::Writer
    } else if principal.can_agent_read_project(project_root) {
        SessionAccess::Readonly
    } else {
        SessionAccess::None
    }
}

pub(super) fn session_access_for_summary(
    principal: &ClientPrincipal,
    summary: &proto::SessionSummary,
) -> SessionAccess {
    if principal.is_owner() {
        return SessionAccess::Owner;
    }
    let created_by_this_principal = principal
        .tag()
        .as_deref()
        .is_some_and(|tag| summary.created_by_principal.as_deref() == Some(tag));
    let scoped_to_session = created_by_this_principal || summary.shared_with_collaborators;
    if !scoped_to_session {
        return SessionAccess::None;
    }
    if principal.can_agent_write_project(&summary.project_root) {
        SessionAccess::Writer
    } else if principal.can_agent_read_project(&summary.project_root) {
        SessionAccess::Readonly
    } else {
        SessionAccess::None
    }
}

pub(super) async fn attached_session_access(
    principal: &ClientPrincipal,
    state: &MutableClientState,
    ctx: &DaemonContext,
) -> std::result::Result<SessionAccess, ErrorPayload> {
    if principal.is_owner() {
        return Ok(SessionAccess::Owner);
    }
    let att = require_attached(state)?;
    match ctx.db.get_session(att.handle.session_id).await {
        Ok(Some(row)) => Ok(session_access_for_row(principal, &row)),
        Ok(None) => {
            let project_root = att.handle.project_root.to_string_lossy();
            if principal.can_agent_write_project(&project_root) {
                Ok(SessionAccess::Writer)
            } else if principal.can_agent_read_project(&project_root) {
                Ok(SessionAccess::Readonly)
            } else {
                Ok(SessionAccess::None)
            }
        }
        Err(e) => Err(internal(e)),
    }
}

pub(super) async fn require_remote_session_writer(
    principal: &ClientPrincipal,
    state: &MutableClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    match attached_session_access(principal, state, ctx).await? {
        SessionAccess::Owner | SessionAccess::Writer => Ok(()),
        SessionAccess::Readonly => Err(read_only_error(
            "remote principal has read-only access to this session",
        )),
        SessionAccess::None => Err(authorization_error(
            "remote principal cannot access this session",
        )),
    }
}

pub(super) async fn authorize_set_active_model(
    request: &Request,
    state: &MutableClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let Request::SetActiveModel {
        persist_as_default, ..
    } = request
    else {
        unreachable!("authorize_set_active_model called for non-SetActiveModel request");
    };
    if *persist_as_default {
        return Err(authorization_error(
            "saving the default model requires the local owner",
        ));
    }
    require_remote_session_writer(&state.principal, state, ctx).await
}

pub(super) async fn require_remote_shared_session_writer(
    principal: &ClientPrincipal,
    shared: &SharedClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    if principal.is_owner() {
        return Ok(());
    }
    let Some(att) = shared.attached.as_ref() else {
        return Err(ErrorPayload {
            code: ErrorCode::NotAttached,
            message: "client has not attached to a session".into(),
        });
    };
    match ctx.db.get_session(att.session_id()).await {
        Ok(Some(row)) => match session_access_for_row(principal, &row) {
            SessionAccess::Owner | SessionAccess::Writer => Ok(()),
            SessionAccess::Readonly => Err(read_only_error(
                "remote principal has read-only access to this session",
            )),
            SessionAccess::None => Err(authorization_error(
                "remote principal cannot access this session",
            )),
        },
        Ok(None) => {
            let project_root = att.project_root.to_string_lossy();
            if principal.can_agent_write_project(&project_root) {
                Ok(())
            } else if principal.can_agent_read_project(&project_root) {
                Err(read_only_error(
                    "remote principal has read-only access to this session",
                ))
            } else {
                Err(authorization_error(
                    "remote principal cannot access this session",
                ))
            }
        }
        Err(e) => Err(internal(e)),
    }
}

pub(super) async fn require_remote_target_session_writer(
    principal: &ClientPrincipal,
    ctx: &DaemonContext,
    session_id: Uuid,
) -> std::result::Result<(), ErrorPayload> {
    match ctx.db.get_session(session_id).await {
        Ok(Some(row)) => match session_access_for_row(principal, &row) {
            SessionAccess::Owner | SessionAccess::Writer => Ok(()),
            SessionAccess::Readonly => Err(read_only_error(
                "remote principal has read-only access to this session",
            )),
            SessionAccess::None => Err(authorization_error(
                "remote principal cannot access this session",
            )),
        },
        Ok(None) => Err(ErrorPayload {
            code: ErrorCode::UnknownSession,
            message: format!("unknown session {session_id}"),
        }),
        Err(e) => Err(internal(e)),
    }
}

macro_rules! command_session_id_value {
    ($state:expr, none) => {
        None
    };
    ($state:expr, attached) => {
        $state.attached.as_ref().map(|att| att.handle.session_id)
    };
    ($state:expr, field($field:ident)) => {
        Some(*$field)
    };
    ($state:expr, option_field($field:ident)) => {
        *$field
    };
}

macro_rules! command_request_session_id_match {
    (($request:ident, $state:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request {
            $($(#[$row_attr])* $pattern => command_session_id_value!($state, $session $(($session_arg))?),)+
        }
    }};
}

#[allow(unused_variables)]
pub(super) fn request_session_id(request: &Request, state: &MutableClientState) -> Option<Uuid> {
    proto::command!(command_request_session_id_match, request, state)
}

macro_rules! command_audit_path_value {
    (none) => {
        None
    };
    (path($path:ident)) => {
        Some($path.clone())
    };
    (rename($from_path:ident, $to_path:ident)) => {
        Some(format!("{} -> {}", $from_path, $to_path))
    };
}

macro_rules! command_request_audit_path_match {
    (($request:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request {
            $($(#[$row_attr])* $pattern => command_audit_path_value!($audit_path $(($($audit_arg),+))?),)+
        }
    }};
}

#[allow(unused_variables)]
pub(super) fn request_audit_path(request: &Request) -> Option<String> {
    proto::command!(command_request_audit_path_match, request)
}

macro_rules! command_is_remote_mutating_match {
    (($request:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request {
            $($(#[$row_attr])* $pattern => $mutating,)+
        }
    }};
}

#[allow(unused_variables)]
pub(super) fn is_remote_mutating_request(request: &Request) -> bool {
    proto::command!(command_is_remote_mutating_match, request)
}

#[cfg(feature = "remote")]
pub(super) async fn audit_remote_request(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    kind: &str,
    session_id: Option<Uuid>,
    path: Option<&str>,
    verdict: &str,
) {
    let Some(tag) = principal.tag() else {
        return;
    };
    let result = match path {
        Some(path) => {
            ctx.db
                .insert_remote_audit_with_path(&tag, kind, session_id, verdict, Some(path))
                .await
        }
        None => {
            ctx.db
                .insert_remote_audit(&tag, kind, session_id, verdict)
                .await
        }
    };
    if let Err(e) = result {
        tracing::warn!(error = %e, principal = %tag, request_kind = kind, "remote request audit write failed");
    }
}

pub(super) async fn authorize_attach(
    request: &Request,
    state: &MutableClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let principal = &state.principal;
    let Request::Attach {
        session_id,
        project_root,
        env_policy,
        ..
    } = request
    else {
        unreachable!("authorize_attach called for non-Attach request");
    };

    if matches!(
        env_policy,
        crate::env_snapshot::EnvDriftPolicy::UpdateDaemon
    ) {
        return Err(authorization_error(
            "updating the daemon environment baseline requires the local owner",
        ));
    }

    if let Some(session_id) = session_id {
        match ctx.db.get_session(*session_id).await {
            Ok(Some(row)) => match session_access_for_row(principal, &row) {
                SessionAccess::Writer => Ok(()),
                SessionAccess::Readonly => {
                    let has_durable_model =
                        persisted_row_has_active_model(&row).map_err(internal)?;
                    if has_durable_model {
                        Ok(())
                    } else {
                        Err(read_only_error(
                            "recovering a session model requires write access to the session",
                        ))
                    }
                }
                SessionAccess::Owner => Ok(()),
                SessionAccess::None => Err(authorization_error(
                    "remote principal cannot access this session",
                )),
            },
            Ok(None) => Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {session_id}"),
            }),
            Err(e) => Err(internal(e)),
        }
    } else if let Some(project_root) = project_root {
        if principal.can_agent_read_project(project_root) {
            Ok(())
        } else {
            Err(authorization_error(
                "remote principal cannot create sessions for this project",
            ))
        }
    } else {
        Ok(())
    }
}

/// Mirror session hydration's accepted durable model representation without
/// constructing a worker. The structured selection is authoritative and must
/// agree with its indexed projections. A genuinely model-less row would make
/// worker startup recover and persist a model, which a read-only attach must
/// never trigger; projection-only or malformed structured state is corruption.
fn persisted_row_has_active_model(row: &crate::db::sessions::SessionRow) -> Result<bool> {
    match row.model_selection_json.as_deref() {
        Some(raw) => {
            let selection = serde_json::from_str::<crate::config::providers::ActiveModelRef>(raw)
                .context(
                "decoding persisted session model selection during attach authorization",
            )?;
            if row.provider.as_deref() != Some(selection.provider.as_str())
                || row.model.as_deref() != Some(selection.model.as_str())
            {
                anyhow::bail!(
                    "persisted session model projections disagree with model_selection_json"
                );
            }
            Ok(true)
        }
        None => {
            anyhow::ensure!(
                row.provider.is_none() && row.model.is_none(),
                "persisted session model projections require model_selection_json"
            );
            Ok(false)
        }
    }
}

pub(super) async fn authorize_subagent_transcript(
    request: &Request,
    state: &MutableClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let principal = &state.principal;
    let Request::SubagentTranscript { session_id, .. } = request else {
        unreachable!("authorize_subagent_transcript called for non-SubagentTranscript request");
    };

    match ctx.db.get_session(*session_id).await {
        Ok(Some(row)) => match session_access_for_row(principal, &row) {
            SessionAccess::Writer | SessionAccess::Readonly | SessionAccess::Owner => Ok(()),
            SessionAccess::None => Err(authorization_error(
                "remote principal cannot access this session",
            )),
        },
        Ok(None) => Err(ErrorPayload {
            code: ErrorCode::UnknownSession,
            message: format!("unknown session {session_id}"),
        }),
        Err(e) => Err(internal(e)),
    }
}

pub(super) async fn authorize_read_session_messages(
    request: &Request,
    state: &MutableClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let session_id = match request {
        Request::ReadSessionMessages { session_id, .. }
        | Request::ReadClientSubmissionReceipt { session_id, .. } => session_id,
        _ => unreachable!("session receipt reader called for an unrelated request"),
    };

    authorize_session_reader_by_id(&state.principal, ctx, *session_id).await
}

pub(super) async fn authorize_read_history_page(
    request: &Request,
    state: &MutableClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let Request::ReadHistoryPage { session_id, .. } = request else {
        unreachable!("authorize_read_history_page called for non-ReadHistoryPage request");
    };

    authorize_session_reader_by_id(&state.principal, ctx, *session_id).await
}

pub(super) async fn authorize_read_subagent_history_page(
    request: &Request,
    state: &MutableClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let Request::ReadSubagentHistoryPage { session_id, .. } = request else {
        unreachable!(
            "authorize_read_subagent_history_page called for non-ReadSubagentHistoryPage request"
        );
    };

    authorize_session_reader_by_id(&state.principal, ctx, *session_id).await
}

async fn authorize_session_reader_by_id(
    principal: &ClientPrincipal,
    ctx: &DaemonContext,
    session_id: Uuid,
) -> std::result::Result<(), ErrorPayload> {
    match ctx.db.get_session(session_id).await {
        Ok(Some(row)) => match session_access_for_row(principal, &row) {
            SessionAccess::Writer | SessionAccess::Readonly | SessionAccess::Owner => Ok(()),
            SessionAccess::None => Err(authorization_error(
                "remote principal cannot access this session",
            )),
        },
        Ok(None) => Err(ErrorPayload {
            code: ErrorCode::UnknownSession,
            message: format!("unknown session {session_id}"),
        }),
        Err(e) => Err(internal(e)),
    }
}

pub(super) async fn authorize_begin_attachment_upload(
    request: &Request,
    state: &MutableClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let principal = &state.principal;
    let Request::BeginAttachmentUpload { purpose, .. } = request else {
        unreachable!(
            "authorize_begin_attachment_upload called for non-BeginAttachmentUpload request"
        );
    };

    let _ = purpose;
    require_remote_session_writer(principal, state, ctx).await
}

pub(super) async fn authorize_attachment_upload_step(
    request: &Request,
    state: &MutableClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let principal = &state.principal;
    let upload_id = match request {
        Request::UploadAttachmentChunk { upload_id, .. }
        | Request::FinishAttachmentUpload { upload_id }
        | Request::CancelAttachmentUpload { upload_id } => upload_id,
        _ => unreachable!("authorize_attachment_upload_step called for non-upload-step request"),
    };

    let _ = upload_id;
    require_remote_session_writer(principal, state, ctx).await
}

pub(super) async fn authorize_steer_delegation(
    request: &Request,
    state: &MutableClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let Request::SteerDelegation { session_id, .. } = request else {
        unreachable!("authorize_steer_delegation called for non-SteerDelegation request");
    };
    require_remote_target_session_writer(&state.principal, ctx, *session_id).await
}

pub(super) async fn authorize_lsp_control(
    request: &Request,
    state: &MutableClientState,
    _ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let principal = &state.principal;
    let Request::LspControl { project_root, .. } = request else {
        unreachable!("authorize_lsp_control called for non-LspControl request");
    };
    if principal.has_terminal() && principal.can_agent_read_project(project_root) {
        Ok(())
    } else {
        Err(authorization_error(
            "remote principal cannot control project language servers",
        ))
    }
}

pub(super) async fn authorize_shared_custom(
    request: &Request,
    shared: &SharedClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let principal = &shared.principal;
    match request {
        Request::Attach {
            session_id,
            project_root,
            env_policy,
            ..
        } => {
            if matches!(
                env_policy,
                crate::env_snapshot::EnvDriftPolicy::UpdateDaemon
            ) {
                return Err(authorization_error(
                    "updating the daemon environment baseline requires the local owner",
                ));
            }
            if let Some(session_id) = session_id {
                match ctx.db.get_session(*session_id).await {
                    Ok(Some(row)) => match session_access_for_row(principal, &row) {
                        SessionAccess::Writer | SessionAccess::Readonly | SessionAccess::Owner => {
                            Ok(())
                        }
                        SessionAccess::None => Err(authorization_error(
                            "remote principal cannot access this session",
                        )),
                    },
                    Ok(None) => Err(ErrorPayload {
                        code: ErrorCode::UnknownSession,
                        message: format!("unknown session {session_id}"),
                    }),
                    Err(e) => Err(internal(e)),
                }
            } else if let Some(project_root) = project_root {
                if principal.can_agent_read_project(project_root) {
                    Ok(())
                } else {
                    Err(authorization_error(
                        "remote principal cannot create sessions for this project",
                    ))
                }
            } else {
                Ok(())
            }
        }
        Request::SubagentTranscript { session_id, .. }
        | Request::ReadSessionMessages { session_id, .. }
        | Request::ReadClientSubmissionReceipt { session_id, .. }
        | Request::ReadHistoryPage { session_id, .. }
        | Request::ReadSubagentHistoryPage { session_id, .. } => {
            match ctx.db.get_session(*session_id).await {
                Ok(Some(row)) => match session_access_for_row(principal, &row) {
                    SessionAccess::Writer | SessionAccess::Readonly | SessionAccess::Owner => {
                        Ok(())
                    }
                    SessionAccess::None => Err(authorization_error(
                        "remote principal cannot access this session",
                    )),
                },
                Ok(None) => Err(ErrorPayload {
                    code: ErrorCode::UnknownSession,
                    message: format!("unknown session {session_id}"),
                }),
                Err(e) => Err(internal(e)),
            }
        }
        Request::BeginAttachmentUpload { .. } => {
            require_remote_shared_session_writer(principal, shared, ctx).await
        }
        Request::UploadAttachmentChunk { .. }
        | Request::FinishAttachmentUpload { .. }
        | Request::CancelAttachmentUpload { .. } => {
            require_remote_shared_session_writer(principal, shared, ctx).await
        }
        Request::SteerDelegation { session_id, .. } => {
            require_remote_target_session_writer(principal, ctx, *session_id).await
        }
        Request::LspControl { project_root, .. } => {
            if principal.has_terminal() && principal.can_agent_read_project(project_root) {
                Ok(())
            } else {
                Err(authorization_error(
                    "remote principal cannot control project language servers",
                ))
            }
        }
        Request::SetActiveModel {
            persist_as_default, ..
        } => {
            if *persist_as_default {
                Err(authorization_error(
                    "saving the default model requires the local owner",
                ))
            } else {
                require_remote_shared_session_writer(principal, shared, ctx).await
            }
        }
        _ => unreachable!("authorize_shared_custom called for non-custom command"),
    }
}

pub(super) async fn authorize_session_row_writer(
    principal: &ClientPrincipal,
    ctx: &DaemonContext,
    session_id: Uuid,
) -> std::result::Result<(), ErrorPayload> {
    match ctx.db.get_session(session_id).await {
        Ok(Some(row)) => match session_access_for_row(principal, &row) {
            SessionAccess::Writer | SessionAccess::Owner => Ok(()),
            SessionAccess::Readonly => Err(read_only_error(
                "remote principal has read-only access to this session",
            )),
            SessionAccess::None => Err(authorization_error(
                "remote principal cannot access this session",
            )),
        },
        Ok(None) => Err(ErrorPayload {
            code: ErrorCode::UnknownSession,
            message: format!("unknown session {session_id}"),
        }),
        Err(e) => Err(internal(e)),
    }
}

pub(super) async fn authorize_session_row_reader(
    principal: &ClientPrincipal,
    ctx: &DaemonContext,
    session_id: Uuid,
) -> std::result::Result<(), ErrorPayload> {
    match ctx.db.get_session(session_id).await {
        Ok(Some(row)) => match session_access_for_row(principal, &row) {
            SessionAccess::Writer | SessionAccess::Readonly | SessionAccess::Owner => Ok(()),
            SessionAccess::None => Err(authorization_error(
                "remote principal cannot access this session",
            )),
        },
        Ok(None) => Err(ErrorPayload {
            code: ErrorCode::UnknownSession,
            message: format!("unknown session {session_id}"),
        }),
        Err(e) => Err(internal(e)),
    }
}

// ---------------------------------------------------------------------------
// Attempt-grant ceiling authorization
// ---------------------------------------------------------------------------
//
// A `RemoteAuthorization::AttemptGrant` principal is authorized *exclusively*
// against its verified permission ceiling — never through the legacy
// `PrincipalScope` helpers, which fail closed for attempt grants and must never
// widen a grant. The mapping from the generated request-authorization category
// (the exhaustive `read_only_without_project | attachment_capability |
// project_capability` table proven by `remote_attempt_request_authz_table_exhaustive`)
// onto a ceiling capability query is:
//
//   authz tag          | request category           | ceiling requirement
//   -------------------|----------------------------|----------------------------------
//   public_read        | read_only_without_project  | allow (admission is the gate)
//   owner_only         | read_only_without_project  | deny (requires the local owner)
//   session_writer     | attachment_capability*     | project SessionWrite(8) on the
//                      |                            |   attached session's resolved root
//   session_row_writer | attachment_capability*     | project SessionWrite(8) on the
//                      |                            |   target session's resolved root
//   session_row_reader | attachment_capability*     | project SessionRead(7) on the
//                      |                            |   target session's resolved root
//   project_files      | project_capability         | project FilesystemWrite(4) when the
//                      |                            |   row is mutating, else FilesystemRead(3),
//                      |                            |   on the resolved project root
//   project_read       | project_capability         | project FilesystemRead(3) on the
//                      |                            |   resolved project root
//   terminal           | attachment_capability      | attachment AttachmentManageChildren(2)
//   custom             | project_capability         | deny (per-handler mapping owned by the
//                      |                            |   transport-wiring follow-ups)
//
// * The AC-mandated refinement: `session_writer` / `session_row_*` are enforced
//   as *project* capabilities on the resolver-resolved session root, not as a
//   coarse attachment capability. Every project-capability query resolves the
//   canonical root through the deny-closed `RemoteProjectResolver` on
//   `DaemonContext`; a resolver miss is a hard authorization failure, never a
//   best-effort id. Any authz tag not mapped above (and every `custom` handler)
//   fails closed. A read-only ceiling therefore denies every write category.

#[cfg(feature = "remote")]
use cockpit_proto::capability_ceiling::{
    RemoteAttachmentCapabilityV1, RemoteProjectCapabilityV1,
};

/// Resolve a raw project-root string to its 16-byte control-plane project id
/// through the injected deny-closed resolver. A canonicalization failure or a
/// resolver miss is a hard authorization failure (fail closed).
#[cfg(feature = "remote")]
fn attempt_grant_resolve_project_id(
    ctx: &DaemonContext,
    raw_root: &str,
) -> std::result::Result<[u8; 16], ErrorPayload> {
    let canonical = crate::daemon::fs_api::canonical_project_root(raw_root)?;
    ctx.remote_project_resolver
        .resolve_project_id(&canonical)
        .ok_or_else(|| {
            authorization_error("attempt-grant principal has no capability for this project")
        })
}

/// Require a project capability on the resolver-resolved control-plane project
/// id for `raw_root`. Deny-closed on resolver miss or absent capability.
#[cfg(feature = "remote")]
fn attempt_grant_require_project_capability(
    auth: &crate::daemon::principal::AttemptGrantAuthorization,
    ctx: &DaemonContext,
    raw_root: &str,
    capability: RemoteProjectCapabilityV1,
) -> std::result::Result<(), ErrorPayload> {
    let project_id = attempt_grant_resolve_project_id(ctx, raw_root)?;
    if auth.ceiling.project_has_capability(&project_id, capability) {
        Ok(())
    } else {
        Err(authorization_error(
            "attempt-grant ceiling does not grant this project capability",
        ))
    }
}

/// Require an attachment capability in the verified ceiling. Deny-closed on
/// absence.
#[cfg(feature = "remote")]
fn attempt_grant_require_attachment_capability(
    auth: &crate::daemon::principal::AttemptGrantAuthorization,
    capability: RemoteAttachmentCapabilityV1,
) -> std::result::Result<(), ErrorPayload> {
    if auth.ceiling.has_attachment_capability(capability) {
        Ok(())
    } else {
        Err(authorization_error(
            "attempt-grant ceiling does not grant this attachment capability",
        ))
    }
}

/// Require a project capability on the *attached* session's resolved project
/// root. Not attached → fail closed; resolver miss / absent capability → deny.
#[cfg(feature = "remote")]
async fn attempt_grant_require_attached_session_capability(
    auth: &crate::daemon::principal::AttemptGrantAuthorization,
    state: &MutableClientState,
    ctx: &DaemonContext,
    capability: RemoteProjectCapabilityV1,
) -> std::result::Result<(), ErrorPayload> {
    let att = require_attached(state)?;
    let raw_root = match ctx.db.get_session(att.handle.session_id).await {
        Ok(Some(row)) => row.project_root,
        // Fail closed if the attached session row is gone: never authorize against
        // the stale cached attachment root (a deleted session must not remain
        // writable via a lingering attachment).
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {}", att.handle.session_id),
            });
        }
        Err(e) => return Err(internal(e)),
    };
    attempt_grant_require_project_capability(auth, ctx, &raw_root, capability)
}

/// Shared-snapshot variant of [`attempt_grant_require_attached_session_capability`].
#[cfg(feature = "remote")]
async fn attempt_grant_require_shared_session_capability(
    auth: &crate::daemon::principal::AttemptGrantAuthorization,
    shared: &SharedClientState,
    ctx: &DaemonContext,
    capability: RemoteProjectCapabilityV1,
) -> std::result::Result<(), ErrorPayload> {
    let Some(att) = shared.attached.as_ref() else {
        return Err(ErrorPayload {
            code: ErrorCode::NotAttached,
            message: "client has not attached to a session".into(),
        });
    };
    let raw_root = match ctx.db.get_session(att.session_id()).await {
        Ok(Some(row)) => row.project_root,
        // Fail closed on a deleted attached session (see the mutable variant).
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {}", att.session_id()),
            });
        }
        Err(e) => return Err(internal(e)),
    };
    attempt_grant_require_project_capability(auth, ctx, &raw_root, capability)
}

/// Require a project capability on a specific target session's resolved project
/// root. Unknown session → typed error; resolver miss / absent capability → deny.
#[cfg(feature = "remote")]
async fn attempt_grant_require_session_row_capability(
    auth: &crate::daemon::principal::AttemptGrantAuthorization,
    ctx: &DaemonContext,
    session_id: Uuid,
    capability: RemoteProjectCapabilityV1,
) -> std::result::Result<(), ErrorPayload> {
    match ctx.db.get_session(session_id).await {
        Ok(Some(row)) => {
            attempt_grant_require_project_capability(auth, ctx, &row.project_root, capability)
        }
        Ok(None) => Err(ErrorPayload {
            code: ErrorCode::UnknownSession,
            message: format!("unknown session {session_id}"),
        }),
        Err(e) => Err(internal(e)),
    }
}

/// Map one command-table row's authz tag onto a verified-ceiling capability
/// query for a `MutableClientState` (serialized executor path). Every unmapped
/// tag and every `custom` handler fails closed.
#[cfg(feature = "remote")]
macro_rules! command_authorize_attempt_grant_value {
    ($auth:expr, $state:expr, $ctx:expr, $request:expr, $mutating:literal, owner_only) => {
        Err(authorization_error("request requires the local owner"))
    };
    ($auth:expr, $state:expr, $ctx:expr, $request:expr, $mutating:literal, public_read) => {
        // Read-only public commands are allowed (admission is the gate); a
        // *mutating* public_read command (e.g. cancelling an invocation) has no
        // project/session scope to check against a ceiling capability, so an
        // attempt-grant principal is denied it — fail closed, never let a
        // scopeless mutation bypass the ceiling.
        if $mutating {
            Err(authorization_error(
                "attempt-grant principal cannot perform this mutating request",
            ))
        } else {
            Ok(())
        }
    };
    ($auth:expr, $state:expr, $ctx:expr, $request:expr, $mutating:literal, session_writer) => {
        attempt_grant_require_attached_session_capability(
            $auth,
            $state,
            $ctx,
            RemoteProjectCapabilityV1::SessionWrite,
        )
        .await
    };
    ($auth:expr, $state:expr, $ctx:expr, $request:expr, $mutating:literal, terminal) => {
        attempt_grant_require_attachment_capability(
            $auth,
            RemoteAttachmentCapabilityV1::AttachmentManageChildren,
        )
    };
    ($auth:expr, $state:expr, $ctx:expr, $request:expr, $mutating:literal, project_files($project_root:ident)) => {
        attempt_grant_require_project_capability(
            $auth,
            $ctx,
            $project_root,
            if $mutating {
                RemoteProjectCapabilityV1::FilesystemWrite
            } else {
                RemoteProjectCapabilityV1::FilesystemRead
            },
        )
    };
    ($auth:expr, $state:expr, $ctx:expr, $request:expr, $mutating:literal, project_read($project_root:ident)) => {
        attempt_grant_require_project_capability(
            $auth,
            $ctx,
            $project_root,
            RemoteProjectCapabilityV1::FilesystemRead,
        )
    };
    ($auth:expr, $state:expr, $ctx:expr, $request:expr, $mutating:literal, session_row_writer($session_id:ident)) => {
        attempt_grant_require_session_row_capability(
            $auth,
            $ctx,
            *$session_id,
            RemoteProjectCapabilityV1::SessionWrite,
        )
        .await
    };
    ($auth:expr, $state:expr, $ctx:expr, $request:expr, $mutating:literal, session_row_reader($session_id:ident)) => {
        attempt_grant_require_session_row_capability(
            $auth,
            $ctx,
            *$session_id,
            RemoteProjectCapabilityV1::SessionRead,
        )
        .await
    };
    ($auth:expr, $state:expr, $ctx:expr, $request:expr, $mutating:literal, custom($handler:ident)) => {
        Err(authorization_error(
            "attempt-grant principal cannot perform this request",
        ))
    };
}

/// Shared-snapshot analogue of [`command_authorize_attempt_grant_value`].
#[cfg(feature = "remote")]
macro_rules! command_authorize_attempt_grant_shared_value {
    ($auth:expr, $shared:expr, $ctx:expr, $request:expr, $mutating:literal, owner_only) => {
        Err(authorization_error("request requires the local owner"))
    };
    ($auth:expr, $shared:expr, $ctx:expr, $request:expr, $mutating:literal, public_read) => {
        // Mirror the mutable path: mutating public_read is denied for attempt
        // grants (scopeless mutation must not bypass the ceiling).
        if $mutating {
            Err(authorization_error(
                "attempt-grant principal cannot perform this mutating request",
            ))
        } else {
            Ok(())
        }
    };
    ($auth:expr, $shared:expr, $ctx:expr, $request:expr, $mutating:literal, session_writer) => {
        attempt_grant_require_shared_session_capability(
            $auth,
            $shared,
            $ctx,
            RemoteProjectCapabilityV1::SessionWrite,
        )
        .await
    };
    ($auth:expr, $shared:expr, $ctx:expr, $request:expr, $mutating:literal, terminal) => {
        attempt_grant_require_attachment_capability(
            $auth,
            RemoteAttachmentCapabilityV1::AttachmentManageChildren,
        )
    };
    ($auth:expr, $shared:expr, $ctx:expr, $request:expr, $mutating:literal, project_files($project_root:ident)) => {
        attempt_grant_require_project_capability(
            $auth,
            $ctx,
            $project_root,
            if $mutating {
                RemoteProjectCapabilityV1::FilesystemWrite
            } else {
                RemoteProjectCapabilityV1::FilesystemRead
            },
        )
    };
    ($auth:expr, $shared:expr, $ctx:expr, $request:expr, $mutating:literal, project_read($project_root:ident)) => {
        attempt_grant_require_project_capability(
            $auth,
            $ctx,
            $project_root,
            RemoteProjectCapabilityV1::FilesystemRead,
        )
    };
    ($auth:expr, $shared:expr, $ctx:expr, $request:expr, $mutating:literal, session_row_writer($session_id:ident)) => {
        attempt_grant_require_session_row_capability(
            $auth,
            $ctx,
            *$session_id,
            RemoteProjectCapabilityV1::SessionWrite,
        )
        .await
    };
    ($auth:expr, $shared:expr, $ctx:expr, $request:expr, $mutating:literal, session_row_reader($session_id:ident)) => {
        attempt_grant_require_session_row_capability(
            $auth,
            $ctx,
            *$session_id,
            RemoteProjectCapabilityV1::SessionRead,
        )
        .await
    };
    ($auth:expr, $shared:expr, $ctx:expr, $request:expr, $mutating:literal, custom($handler:ident)) => {
        Err(authorization_error(
            "attempt-grant principal cannot perform this request",
        ))
    };
}

macro_rules! command_authorize_value {
    ($principal:expr, $state:expr, $ctx:expr, $request:expr, owner_only) => {
        Err(authorization_error("request requires the local owner"))
    };
    ($principal:expr, $state:expr, $ctx:expr, $request:expr, public_read) => {
        Ok(())
    };
    ($principal:expr, $state:expr, $ctx:expr, $request:expr, session_writer) => {
        require_remote_session_writer($principal, $state, $ctx).await
    };
    ($principal:expr, $state:expr, $ctx:expr, $request:expr, terminal) => {{
        if $principal.has_terminal() {
            Ok(())
        } else {
            Err(authorization_error(
                "remote principal cannot access terminals",
            ))
        }
    }};
    ($principal:expr, $state:expr, $ctx:expr, $request:expr, project_files($project_root:ident)) => {{
        if $principal.has_project_files($project_root) {
            Ok(())
        } else {
            Err(authorization_error(
                "remote principal cannot access project files for this project",
            ))
        }
    }};
    ($principal:expr, $state:expr, $ctx:expr, $request:expr, project_read($project_root:ident)) => {{
        if $principal.can_agent_read_project($project_root)
            || $principal.has_project_files($project_root)
        {
            Ok(())
        } else {
            Err(authorization_error(
                "remote principal cannot read this project",
            ))
        }
    }};
    ($principal:expr, $state:expr, $ctx:expr, $request:expr, session_row_writer($session_id:ident)) => {
        authorize_session_row_writer($principal, $ctx, *$session_id).await
    };
    ($principal:expr, $state:expr, $ctx:expr, $request:expr, session_row_reader($session_id:ident)) => {
        authorize_session_row_reader($principal, $ctx, *$session_id).await
    };
    ($principal:expr, $state:expr, $ctx:expr, $request:expr, custom($handler:ident)) => {
        $handler($request, $state, $ctx).await
    };
}

macro_rules! command_authorize_request_match {
    (($request:ident, $state:ident, $ctx:ident, $principal:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request {
            $($(#[$row_attr])* $pattern => command_authorize_value!($principal, $state, $ctx, $request, $authz $(($authz_arg))?),)+
        }
    }};
}

#[cfg(feature = "remote")]
macro_rules! command_authorize_attempt_grant_request_match {
    (($request:ident, $state:ident, $ctx:ident, $auth:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request {
            $($(#[$row_attr])* $pattern => command_authorize_attempt_grant_value!($auth, $state, $ctx, $request, $mutating, $authz $(($authz_arg))?),)+
        }
    }};
}

#[allow(unused_variables)]
pub(super) async fn authorize_request(
    request: &Request,
    state: &MutableClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let principal = &state.principal;
    if principal.is_owner() {
        return Ok(());
    }

    // An attempt-grant principal is authorized only against its verified
    // ceiling — never through the legacy `PrincipalScope` helpers. Fail-closed
    // on any unmapped category or resolver miss.
    #[cfg(feature = "remote")]
    if let Some(auth) = principal.attempt_grant_authorization() {
        return proto::command!(
            command_authorize_attempt_grant_request_match,
            request,
            state,
            ctx,
            auth
        );
    }

    proto::command!(
        command_authorize_request_match,
        request,
        state,
        ctx,
        principal
    )
}

macro_rules! command_authorize_shared_value {
    ($principal:expr, $shared:expr, $ctx:expr, $request:expr, owner_only) => {
        Err(authorization_error("request requires the local owner"))
    };
    ($principal:expr, $shared:expr, $ctx:expr, $request:expr, public_read) => {
        Ok(())
    };
    ($principal:expr, $shared:expr, $ctx:expr, $request:expr, session_writer) => {
        require_remote_shared_session_writer($principal, $shared, $ctx).await
    };
    ($principal:expr, $shared:expr, $ctx:expr, $request:expr, terminal) => {{
        if $principal.has_terminal() {
            Ok(())
        } else {
            Err(authorization_error(
                "remote principal cannot access terminals",
            ))
        }
    }};
    ($principal:expr, $shared:expr, $ctx:expr, $request:expr, project_files($project_root:ident)) => {{
        if $principal.has_project_files($project_root) {
            Ok(())
        } else {
            Err(authorization_error(
                "remote principal cannot access project files for this project",
            ))
        }
    }};
    ($principal:expr, $shared:expr, $ctx:expr, $request:expr, project_read($project_root:ident)) => {{
        if $principal.can_agent_read_project($project_root)
            || $principal.has_project_files($project_root)
        {
            Ok(())
        } else {
            Err(authorization_error(
                "remote principal cannot read this project",
            ))
        }
    }};
    ($principal:expr, $shared:expr, $ctx:expr, $request:expr, session_row_writer($session_id:ident)) => {
        authorize_session_row_writer($principal, $ctx, *$session_id).await
    };
    ($principal:expr, $shared:expr, $ctx:expr, $request:expr, session_row_reader($session_id:ident)) => {
        authorize_session_row_reader($principal, $ctx, *$session_id).await
    };
    ($principal:expr, $shared:expr, $ctx:expr, $request:expr, custom($handler:ident)) => {
        authorize_shared_custom($request, $shared, $ctx).await
    };
}

macro_rules! command_authorize_shared_request_match {
    (($request:ident, $shared:ident, $ctx:ident, $principal:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request {
            $($(#[$row_attr])* $pattern => command_authorize_shared_value!($principal, $shared, $ctx, $request, $authz $(($authz_arg))?),)+
        }
    }};
}

#[cfg(feature = "remote")]
macro_rules! command_authorize_attempt_grant_shared_request_match {
    (($request:ident, $shared:ident, $ctx:ident, $auth:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request {
            $($(#[$row_attr])* $pattern => command_authorize_attempt_grant_shared_value!($auth, $shared, $ctx, $request, $mutating, $authz $(($authz_arg))?),)+
        }
    }};
}

#[allow(unused_variables)]
pub(super) async fn authorize_request_shared(
    request: &Request,
    shared: &SharedClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let principal = &shared.principal;
    if principal.is_owner() {
        return Ok(());
    }

    // Attempt-grant principals: ceiling-only enforcement on the shared path too.
    #[cfg(feature = "remote")]
    if let Some(auth) = principal.attempt_grant_authorization() {
        return proto::command!(
            command_authorize_attempt_grant_shared_request_match,
            request,
            shared,
            ctx,
            auth
        );
    }

    proto::command!(
        command_authorize_shared_request_match,
        request,
        shared,
        ctx,
        principal
    )
}

#[cfg(test)]
mod remote_attempt_authz_tests {
    use super::*;

    /// Classify each authz tag into one of the three remote-attempt
    /// request-authorization categories:
    /// - `read_only_without_project`: requests that don't require a
    ///   project-scoped capability (public_read, owner_only, session-scoped).
    /// - `attachment_capability`: requests that require an attachment-wide
    ///   capability (terminal, session_writer, session_row_*).
    /// - `project_capability`: requests that require a project-scoped
    ///   capability (project_files, project_read, custom with project_root).
    macro_rules! remote_attempt_authz_class {
        (owner_only) => {
            "read_only_without_project"
        };
        (public_read) => {
            "read_only_without_project"
        };
        (terminal) => {
            "attachment_capability"
        };
        (session_writer) => {
            "attachment_capability"
        };
        (session_row_writer) => {
            "attachment_capability"
        };
        (session_row_reader) => {
            "attachment_capability"
        };
        (project_files) => {
            "project_capability"
        };
        (project_read) => {
            "project_capability"
        };
        (custom) => {
            "project_capability"
        };
    }

    macro_rules! remote_attempt_authz_rows {
        (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
            let mut rows = Vec::new();
            $($(#[$row_attr])* rows.push(($kind, remote_attempt_authz_class!($authz)));)+
            rows
        }};
    }

    macro_rules! remote_attempt_authz_row_count {
        (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
            let mut count = 0usize;
            $($(#[$row_attr])* { let _ = stringify!($pattern); count += 1; })+
            count
        }};
    }

    #[cfg(feature = "remote")]
    #[test]
    fn remote_attempt_request_authz_table_exhaustive() {
        let rows = proto::command!(remote_attempt_authz_rows);
        let row_count = proto::command!(remote_attempt_authz_row_count);

        // Every request kind is assigned to exactly one category.
        assert_eq!(rows.len(), row_count);
        assert!(
            rows.len() > 80,
            "command table should enumerate all Request rows"
        );

        // Every assigned category is one of the three valid values.
        let valid_categories = [
            "read_only_without_project",
            "attachment_capability",
            "project_capability",
        ];
        for (kind, category) in &rows {
            assert!(
                valid_categories.contains(category),
                "request {kind} has invalid authz category {category}"
            );
        }

        // No request kind is missing (no wildcard arm).
        let kinds: std::collections::BTreeSet<&str> = rows.iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds.len(), rows.len(), "duplicate request kinds in table");

        // All three categories have at least one request.
        let categories: std::collections::BTreeSet<&str> = rows.iter().map(|(_, c)| *c).collect();
        for expected in &valid_categories {
            assert!(
                categories.contains(expected),
                "category {expected} has zero requests"
            );
        }

        // Spot-check: read-only requests are classified as read_only_without_project.
        let read_only_kinds = [
            "daemon_status",
            "get_run_invocation_status",
            "operation_status",
        ];
        for kind in &read_only_kinds {
            let (_, category) = rows
                .iter()
                .find(|(k, _)| k == kind)
                .unwrap_or_else(|| panic!("missing request kind {kind}"));
            assert_eq!(
                *category, "read_only_without_project",
                "{kind} should be read_only_without_project"
            );
        }

        // Spot-check: project-scoped requests are classified as project_capability.
        let project_kinds = ["fs_list", "fs_read", "fs_stat"];
        for kind in &project_kinds {
            let (_, category) = rows
                .iter()
                .find(|(k, _)| k == kind)
                .unwrap_or_else(|| panic!("missing request kind {kind}"));
            assert_eq!(
                *category, "project_capability",
                "{kind} should be project_capability"
            );
        }

        // Spot-check: attachment-scoped requests are classified as attachment_capability.
        let attachment_kinds = ["send_user_message", "cancel_turn"];
        for kind in &attachment_kinds {
            let (_, category) = rows
                .iter()
                .find(|(k, _)| k == kind)
                .unwrap_or_else(|| panic!("missing request kind {kind}"));
            assert_eq!(
                *category, "attachment_capability",
                "{kind} should be attachment_capability"
            );
        }
    }
}
