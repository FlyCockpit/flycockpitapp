use super::sessions::*;
use super::*;

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

pub(super) fn attached_session_access(
    principal: &ClientPrincipal,
    state: &ClientState,
    ctx: &DaemonContext,
) -> std::result::Result<SessionAccess, ErrorPayload> {
    if principal.is_owner() {
        return Ok(SessionAccess::Owner);
    }
    let att = require_attached(state)?;
    match ctx.db.get_session(att.handle.session_id) {
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

pub(super) fn require_remote_session_writer(
    principal: &ClientPrincipal,
    state: &ClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    match attached_session_access(principal, state, ctx)? {
        SessionAccess::Owner | SessionAccess::Writer => Ok(()),
        SessionAccess::Readonly => Err(read_only_error(
            "remote principal has read-only access to this session",
        )),
        SessionAccess::None => Err(authorization_error(
            "remote principal cannot access this session",
        )),
    }
}

pub(super) fn require_remote_target_session_writer(
    principal: &ClientPrincipal,
    ctx: &DaemonContext,
    session_id: Uuid,
) -> std::result::Result<(), ErrorPayload> {
    match ctx.db.get_session(session_id) {
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
    (($request:ident, $state:ident) [$(($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $audit_path:ident $(($($audit_arg:ident),+))?);)+]) => {{
        match $request {
            $($pattern => command_session_id_value!($state, $session $(($session_arg))?),)+
        }
    }};
}

#[allow(unused_variables)]
pub(super) fn request_session_id(request: &Request, state: &ClientState) -> Option<Uuid> {
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
    (($request:ident) [$(($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $audit_path:ident $(($($audit_arg:ident),+))?);)+]) => {{
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
    (($request:ident) [$(($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $audit_path:ident $(($($audit_arg:ident),+))?);)+]) => {{
        match $request {
            $($pattern => $mutating,)+
        }
    }};
}

#[allow(unused_variables)]
pub(super) fn is_remote_mutating_request(request: &Request) -> bool {
    proto::command!(command_is_remote_mutating_match, request)
}

pub(super) fn audit_remote_request(
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
        }
        None => ctx.db.insert_remote_audit(&tag, kind, session_id, verdict),
    };
    if let Err(e) = result {
        tracing::warn!(error = %e, principal = %tag, request_kind = kind, "remote request audit write failed");
    }
}

pub(super) fn authorize_attach(
    request: &Request,
    state: &ClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let principal = &state.principal;
    let Request::Attach {
        session_id,
        project_root,
        ..
    } = request
    else {
        unreachable!("authorize_attach called for non-Attach request");
    };

    if let Some(session_id) = session_id {
        match ctx.db.get_session(*session_id) {
            Ok(Some(row)) => match session_access_for_row(principal, &row) {
                SessionAccess::Writer | SessionAccess::Readonly => Ok(()),
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

pub(super) fn authorize_subagent_transcript(
    request: &Request,
    state: &ClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let principal = &state.principal;
    let Request::SubagentTranscript { session_id, .. } = request else {
        unreachable!("authorize_subagent_transcript called for non-SubagentTranscript request");
    };

    match ctx.db.get_session(*session_id) {
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

pub(super) fn authorize_read_session_messages(
    request: &Request,
    state: &ClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let principal = &state.principal;
    let Request::ReadSessionMessages { session_id, .. } = request else {
        unreachable!("authorize_read_session_messages called for non-ReadSessionMessages request");
    };

    match ctx.db.get_session(*session_id) {
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

pub(super) fn authorize_begin_attachment_upload(
    request: &Request,
    state: &ClientState,
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
        require_remote_session_writer(principal, state, ctx)
    }
}

pub(super) fn authorize_attachment_upload_step(
    request: &Request,
    state: &ClientState,
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
        require_remote_session_writer(principal, state, ctx)
    }
}

pub(super) fn authorize_steer_delegation(
    request: &Request,
    state: &ClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let Request::SteerDelegation { session_id, .. } = request else {
        unreachable!("authorize_steer_delegation called for non-SteerDelegation request");
    };
    require_remote_target_session_writer(&state.principal, ctx, *session_id)
}

pub(super) fn authorize_lsp_control(
    request: &Request,
    state: &ClientState,
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

pub(super) fn authorize_session_row_writer(
    principal: &ClientPrincipal,
    ctx: &DaemonContext,
    session_id: Uuid,
) -> std::result::Result<(), ErrorPayload> {
    match ctx.db.get_session(session_id) {
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

pub(super) fn authorize_session_row_reader(
    principal: &ClientPrincipal,
    ctx: &DaemonContext,
    session_id: Uuid,
) -> std::result::Result<(), ErrorPayload> {
    match ctx.db.get_session(session_id) {
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
        require_remote_session_writer($principal, $state, $ctx)
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
        authorize_session_row_writer($principal, $ctx, *$session_id)
    };
    ($principal:expr, $state:expr, $ctx:expr, $request:expr, session_row_reader($session_id:ident)) => {
        authorize_session_row_reader($principal, $ctx, *$session_id)
    };
    ($principal:expr, $state:expr, $ctx:expr, $request:expr, custom($handler:ident)) => {
        $handler($request, $state, $ctx)
    };
}

macro_rules! command_authorize_request_match {
    (($request:ident, $state:ident, $ctx:ident, $principal:ident) [$(($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $audit_path:ident $(($($audit_arg:ident),+))?);)+]) => {{
        match $request {
            $($pattern => command_authorize_value!($principal, $state, $ctx, $request, $authz $(($authz_arg))?),)+
        }
    }};
}

#[allow(unused_variables)]
pub(super) fn authorize_request(
    request: &Request,
    state: &ClientState,
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
