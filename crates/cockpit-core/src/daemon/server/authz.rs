use super::sessions::*;
use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AuthorizedFcorResource {
    pub(super) kind: proto::remote_operation_fcor::RemoteOperationResourceKind,
    pub(super) value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AuthorizedRequestContext {
    pub(super) fcor_resources: Vec<AuthorizedFcorResource>,
}

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

fn canonical_project_root_bytes(
    path: &std::path::Path,
) -> std::result::Result<Vec<u8>, ErrorPayload> {
    let text = path.to_str().ok_or_else(|| ErrorPayload {
        code: ErrorCode::BadRequest,
        message: "canonical project root is not valid UTF-8".into(),
    })?;
    Ok(text.as_bytes().to_vec())
}

fn push_fcor_resource(
    resources: &mut Vec<AuthorizedFcorResource>,
    kind: proto::remote_operation_fcor::RemoteOperationResourceKind,
    value: Vec<u8>,
) {
    resources.push(AuthorizedFcorResource { kind, value });
}

macro_rules! resolve_fcor_role {
    ($resources:ident, $cwd:ident, $name:ident: $ty:ty => param) => {};
    ($resources:ident, $cwd:ident, $name:ident: ScheduledJobCreate => scheduled) => {{
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
    ($resources:ident, $cwd:ident, $name:ident: Option<Uuid> => session) => {
        if let Some(value) = $name {
            push_fcor_resource(
                &mut $resources,
                proto::remote_operation_fcor::RemoteOperationResourceKind::SessionUuid,
                value.as_bytes().to_vec(),
            );
        }
    };
    ($resources:ident, $cwd:ident, $name:ident: Uuid => session) => {
        push_fcor_resource(
            &mut $resources,
            proto::remote_operation_fcor::RemoteOperationResourceKind::SessionUuid,
            $name.as_bytes().to_vec(),
        );
    };
    ($resources:ident, $cwd:ident, $name:ident: Option<String> => project_root_effective) => {{
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
    ($resources:ident, $cwd:ident, $name:ident: String => project_root) => {{
        let canonical = crate::daemon::fs_api::canonical_project_root($name)?;
        push_fcor_resource(
            &mut $resources,
            proto::remote_operation_fcor::RemoteOperationResourceKind::ProjectRoot,
            canonical_project_root_bytes(&canonical)?,
        );
    }};
    ($resources:ident, $cwd:ident, $name:ident: Option<String> => project) => {
        if let Some(value) = $name {
            push_fcor_resource(
                &mut $resources,
                proto::remote_operation_fcor::RemoteOperationResourceKind::ProjectId,
                value.as_bytes().to_vec(),
            );
        }
    };
    ($resources:ident, $cwd:ident, $name:ident: String => file_existing($root:ident)) => {{
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
    ($resources:ident, $cwd:ident, $name:ident: String => file_write_target($root:ident)) => {{
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
    ($resources:ident, $cwd:ident, $name:ident: Uuid => terminal) => {
        push_fcor_resource(
            &mut $resources,
            proto::remote_operation_fcor::RemoteOperationResourceKind::TerminalUuid,
            $name.as_bytes().to_vec(),
        );
    };
    ($resources:ident, $cwd:ident, $name:ident: Uuid => upload) => {
        push_fcor_resource(
            &mut $resources,
            proto::remote_operation_fcor::RemoteOperationResourceKind::UploadUuid,
            $name.as_bytes().to_vec(),
        );
    };
    ($resources:ident, $cwd:ident, $name:ident: Uuid => interrupt) => {
        push_fcor_resource(
            &mut $resources,
            proto::remote_operation_fcor::RemoteOperationResourceKind::InterruptUuid,
            $name.as_bytes().to_vec(),
        );
    };
    ($resources:ident, $cwd:ident, $name:ident: Uuid => queue) => {
        push_fcor_resource(
            &mut $resources,
            proto::remote_operation_fcor::RemoteOperationResourceKind::QueueUuid,
            $name.as_bytes().to_vec(),
        );
    };
    ($resources:ident, $cwd:ident, $name:ident: $ty:ty => legacy_message) => {
        let _ = $name;
    };
    ($resources:ident, $cwd:ident, $name:ident: $ty:ty => provider_model_right($left:ident)) => {};
    ($resources:ident, $cwd:ident, $name:ident: String => provider_model_left($model:ident)) => {{
        let value = proto::remote_operation_fcor::encode_provider_model_resource_v1($name, $model)
            .map_err(|error| ErrorPayload {
                code: ErrorCode::BadRequest,
                message: error.to_string(),
            })?;
        push_fcor_resource(
            &mut $resources,
            proto::remote_operation_fcor::RemoteOperationResourceKind::ProviderModel,
            value,
        );
    }};
    ($resources:ident, $cwd:ident, $name:ident: Option<String> => provider_model_left($model:ident)) => {{
        if let (Some(provider), Some(model)) = ($name.as_deref(), $model.as_deref()) {
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

macro_rules! command_resolve_fcor_resources {
    (($request:ident, $cwd:ident) [$(($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request { $($pattern => { let mut resources = Vec::new(); $(resolve_fcor_role!(resources, $cwd, $fcor_field: $fcor_type => $fcor_role $(($($fcor_role_arg),*))?);)* Ok(resources) },)+ }
    }};
}

/// Resolve path-bearing FCOR resources only after request authorization.
/// Raw client path text never leaves this boundary.
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
    #[cfg(test)]
    ctx.fcor_resolver_calls
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Ok(AuthorizedRequestContext {
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
    (($request:ident, $state:ident) [$(($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request {
            $($pattern => command_session_id_value!($state, $session $(($session_arg))?),)+
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
    (($request:ident) [$(($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request {
            $($pattern => command_audit_path_value!($audit_path $(($($audit_arg),+))?),)+
        }
    }};
}

#[allow(unused_variables)]
pub(super) fn request_audit_path(request: &Request) -> Option<String> {
    proto::command!(command_request_audit_path_match, request)
}

macro_rules! command_is_remote_mutating_match {
    (($request:ident) [$(($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request {
            $($pattern => $mutating,)+
        }
    }};
}

#[allow(unused_variables)]
pub(super) fn is_remote_mutating_request(request: &Request) -> bool {
    proto::command!(command_is_remote_mutating_match, request)
}

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

    if matches!(purpose, proto::AttachmentPurpose::TerminalPasteImage { .. }) {
        if principal.has_terminal() {
            Ok(())
        } else {
            Err(authorization_error(
                "remote principal cannot paste into terminals",
            ))
        }
    } else {
        require_remote_session_writer(principal, state, ctx).await
    }
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

    if state.pending_uploads.get(upload_id).is_some_and(|upload| {
        matches!(
            upload.purpose,
            proto::AttachmentPurpose::TerminalPasteImage { .. }
        )
    }) {
        if principal.has_terminal() {
            Ok(())
        } else {
            Err(authorization_error(
                "remote principal cannot paste into terminals",
            ))
        }
    } else {
        require_remote_session_writer(principal, state, ctx).await
    }
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
        Request::BeginAttachmentUpload { purpose, .. } => {
            if matches!(purpose, proto::AttachmentPurpose::TerminalPasteImage { .. }) {
                if principal.has_terminal() {
                    Ok(())
                } else {
                    Err(authorization_error(
                        "remote principal cannot paste into terminals",
                    ))
                }
            } else {
                require_remote_shared_session_writer(principal, shared, ctx).await
            }
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
    (($request:ident, $state:ident, $ctx:ident, $principal:ident) [$(($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request {
            $($pattern => command_authorize_value!($principal, $state, $ctx, $request, $authz $(($authz_arg))?),)+
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
    (($request:ident, $shared:ident, $ctx:ident, $principal:ident) [$(($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request {
            $($pattern => command_authorize_shared_value!($principal, $shared, $ctx, $request, $authz $(($authz_arg))?),)+
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

    proto::command!(
        command_authorize_shared_request_match,
        request,
        shared,
        ctx,
        principal
    )
}
