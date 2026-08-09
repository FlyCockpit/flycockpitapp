//! Exhaustive application-message → lane classification.
//!
//! Every request, response, and event variant on the protocol-v6 wire has
//! exactly one row here. The table is generated from the `request_variants!`,
//! `response_variants!`, and `event_variants!` macros in `src/request.rs`,
//! `src/response.rs`, and `src/event.rs`, so a new variant that is not
//! classified fails `remote_transport_classification_is_exhaustive` rather
//! than silently defaulting to a lane.
//!
//! Two properties matter more than the individual assignments:
//!
//! 1. **The lane is a function of the message class alone.** There is no lane
//!    or priority input anywhere in this module, so a peer cannot select,
//!    promote, or hint a lane. [`RemoteMessageClass::lane`] is total.
//! 2. **Classification never grants authorization.** A row says where bytes
//!    travel, never what the sender may do.
//!
//! DO NOT EDIT BY HAND — regenerate alongside the wire enums.

use crate::remote_transport::lane::{
    RemoteLane, RemoteTransportError, RemoteTransportReason, RemoteTransportResult,
};

/// Which wire enum a row belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RemoteMessageKind {
    Request,
    Response,
    Event,
}

impl RemoteMessageKind {
    pub const ALL: [RemoteMessageKind; 3] = [
        RemoteMessageKind::Request,
        RemoteMessageKind::Response,
        RemoteMessageKind::Event,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteMessageKind::Request => "request",
            RemoteMessageKind::Response => "response",
            RemoteMessageKind::Event => "event",
        }
    }
}

impl serde::Serialize for RemoteMessageKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// The closed set of message classes, grouped by the lane each one rides.
///
/// The control classes `AuthCompletion`, `CapabilityVersion`, and
/// `LeaseRevocation` carry no protocol-v6 application variant today: they are
/// the transport-level control messages owned by the sibling handshake and
/// resume prompts. They are listed because the lane's permitted class set is
/// part of this contract, and because a future control message must land in an
/// already-named class rather than inventing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RemoteMessageClass {
    // --- control lane ---
    AuthCompletion,
    CapabilityVersion,
    LeaseRevocation,
    Liveness,
    Cancel,
    ResumeWindow,
    // --- interactive lane ---
    BoundedRequestResponse,
    BoundedEvent,
    TerminalIo,
    Approval,
    ModelDelta,
    // --- bulk lane ---
    BulkChunk,
}

impl RemoteMessageClass {
    pub const ALL: [RemoteMessageClass; 12] = [
        RemoteMessageClass::AuthCompletion,
        RemoteMessageClass::CapabilityVersion,
        RemoteMessageClass::LeaseRevocation,
        RemoteMessageClass::Liveness,
        RemoteMessageClass::Cancel,
        RemoteMessageClass::ResumeWindow,
        RemoteMessageClass::BoundedRequestResponse,
        RemoteMessageClass::BoundedEvent,
        RemoteMessageClass::TerminalIo,
        RemoteMessageClass::Approval,
        RemoteMessageClass::ModelDelta,
        RemoteMessageClass::BulkChunk,
    ];

    /// Total: every class has exactly one lane, and nothing else influences it.
    pub const fn lane(self) -> RemoteLane {
        match self {
            RemoteMessageClass::AuthCompletion
            | RemoteMessageClass::CapabilityVersion
            | RemoteMessageClass::LeaseRevocation
            | RemoteMessageClass::Liveness
            | RemoteMessageClass::Cancel
            | RemoteMessageClass::ResumeWindow => RemoteLane::Control,
            RemoteMessageClass::BoundedRequestResponse
            | RemoteMessageClass::BoundedEvent
            | RemoteMessageClass::TerminalIo
            | RemoteMessageClass::Approval
            | RemoteMessageClass::ModelDelta => RemoteLane::Interactive,
            RemoteMessageClass::BulkChunk => RemoteLane::Bulk,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteMessageClass::AuthCompletion => "auth_completion",
            RemoteMessageClass::CapabilityVersion => "capability_version",
            RemoteMessageClass::LeaseRevocation => "lease_revocation",
            RemoteMessageClass::Liveness => "liveness",
            RemoteMessageClass::Cancel => "cancel",
            RemoteMessageClass::ResumeWindow => "resume_window",
            RemoteMessageClass::BoundedRequestResponse => "bounded_request_response",
            RemoteMessageClass::BoundedEvent => "bounded_event",
            RemoteMessageClass::TerminalIo => "terminal_io",
            RemoteMessageClass::Approval => "approval",
            RemoteMessageClass::ModelDelta => "model_delta",
            RemoteMessageClass::BulkChunk => "bulk_chunk",
        }
    }

    pub fn from_str_exact(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == value)
    }
}

impl serde::Serialize for RemoteMessageClass {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// How a variant's payload is kept under the lane cap.
///
/// Every row carries one of these. `Bounded` means the encoded message is small
/// by construction; the other four are the dispositions of the >512 KiB
/// inventory. Nothing is allowed to be "unbounded inline".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RemoteInlinePayloadBound {
    /// Structurally small: scalars, ids, enums, fixed-shape rows.
    Bounded,
    /// The producer pages the collection; each page stays under the cap.
    Paged,
    /// The producer truncates at a named cap before the message is built.
    TruncatedByCap,
    /// Naturally delta-streamed; each message is one bounded chunk.
    StreamChunked,
    /// Large content travels as a typed bulk transfer reference on the bulk
    /// lane; the application message carries only the reference.
    BulkReference,
}

impl RemoteInlinePayloadBound {
    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteInlinePayloadBound::Bounded => "bounded",
            RemoteInlinePayloadBound::Paged => "paged",
            RemoteInlinePayloadBound::TruncatedByCap => "truncated_by_cap",
            RemoteInlinePayloadBound::StreamChunked => "stream_chunked",
            RemoteInlinePayloadBound::BulkReference => "bulk_reference",
        }
    }

    /// True when the variant needed a migration away from unbounded inline
    /// bytes. Every member of the >512 KiB inventory answers true.
    pub const fn requires_migration(self) -> bool {
        !matches!(self, RemoteInlinePayloadBound::Bounded)
    }
}

impl serde::Serialize for RemoteInlinePayloadBound {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// One classification row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct RemoteMessageClassification {
    pub tag: &'static str,
    pub class: RemoteMessageClass,
    pub inline_payload_bound: RemoteInlinePayloadBound,
}

impl RemoteMessageClassification {
    /// The lane is derived, never stored: there is no second source of truth.
    pub const fn lane(&self) -> RemoteLane {
        self.class.lane()
    }
}

const fn row(
    tag: &'static str,
    class: RemoteMessageClass,
    inline_payload_bound: RemoteInlinePayloadBound,
) -> RemoteMessageClassification {
    RemoteMessageClassification {
        tag,
        class,
        inline_payload_bound,
    }
}

/// The tag the wire enums use for their `#[serde(other)]` catch-all. It is
/// deliberately absent from every table: an unknown message has no lane.
pub const UNKNOWN_MESSAGE_TAG: &str = "__unknown";

/// Every `Request` variant.
pub const REQUEST_CLASSIFICATION: &[RemoteMessageClassification] = &[
    row(
        "attach",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "subagent_transcript",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "send_user_message",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "get_run_invocation_status",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "cancel_run_invocation",
        RemoteMessageClass::Cancel,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "steer_delegation",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "begin_attachment_upload",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "upload_attachment_chunk",
        RemoteMessageClass::BulkChunk,
        RemoteInlinePayloadBound::BulkReference,
    ),
    row(
        "finish_attachment_upload",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "cancel_attachment_upload",
        RemoteMessageClass::Cancel,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "remove_queued_user_message",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "remove_newest_queued_user_message",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "remove_editable_queued_user_messages",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "resume_paused_work",
        RemoteMessageClass::ResumeWindow,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "cancel_paused_work",
        RemoteMessageClass::Cancel,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "repair_resume",
        RemoteMessageClass::ResumeWindow,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "goal_status",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_goal_status",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "clear_goal",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "pin_message",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "unpin_message",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "toggle_pinned_message",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "count_pinned_messages",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "list_pinned_message_seqs",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "list_pinned_messages_with_text",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "pinned_message_state",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "list_sealed_values",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "delete_sealed_value",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "list_project_notes",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "create_project_note",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_project_note_content",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "rename_project_note",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "delete_project_note",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "list_assistants",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "upsert_assistant",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "create_assistant_session",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "auto_title",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "export_session_data",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "import_session_archive",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::BulkReference,
    ),
    row(
        "write_bulk_transfer_chunk",
        RemoteMessageClass::BulkChunk,
        RemoteInlinePayloadBound::BulkReference,
    ),
    row(
        "read_bulk_transfer_chunk",
        RemoteMessageClass::BulkChunk,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "curator",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "cancel_turn",
        RemoteMessageClass::Cancel,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "fs_list",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "fs_stat",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "fs_read",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "fs_write",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "fs_create_dir",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "fs_rename",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "fs_delete",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "git_status",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "git_diff_file",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "open_terminal",
        RemoteMessageClass::TerminalIo,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "attach_terminal",
        RemoteMessageClass::TerminalIo,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "terminal_input",
        RemoteMessageClass::TerminalIo,
        RemoteInlinePayloadBound::StreamChunked,
    ),
    row(
        "terminal_resize",
        RemoteMessageClass::TerminalIo,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "close_terminal",
        RemoteMessageClass::TerminalIo,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "lsp_control",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "resolve_interrupt",
        RemoteMessageClass::Approval,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "list_sessions",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "read_session_messages",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "read_client_submission_receipt",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "read_history_page",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "read_subagent_history_page",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "session_live_status",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "archive_session",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "unarchive_session",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "fork_session",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "discard_session",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "create_btw_fork",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "end_btw_fork",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "rename_session",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "share_session",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "record_session_note",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "delete_session",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "get_inventory_bundle",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "resource_snapshot",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "promote_resource",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "create_scheduled_job",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "list_scheduled_jobs",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "delete_scheduled_job",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_scheduled_job_enabled",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "run_scheduled_job",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_model_favorite",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_default_model",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_active_model",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_agent",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_llm_mode",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_session_llm_mode",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_tool_surface_override",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "set_goal_settings_override",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "set_approval_mode",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_delegation_recursion",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_sandbox",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_sandbox_escalation",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_preflight",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_longcache",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_redaction",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_tandem_models",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "set_caffeinate",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "cancel_schedule",
        RemoteMessageClass::Cancel,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "prune",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "compact",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "pin",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "store_flycockpit_credential",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "clear_flycockpit_credential",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "daemon_status",
        RemoteMessageClass::Liveness,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "refresh_env",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "refresh_config",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "record_usage",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "get_usage_counts",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "stats_rollup",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "guidance_estimate",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "stop_daemon",
        RemoteMessageClass::Liveness,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "restart_if_idle",
        RemoteMessageClass::Liveness,
        RemoteInlinePayloadBound::Bounded,
    ),
];

/// Every `Response` variant.
pub const RESPONSE_CLASSIFICATION: &[RemoteMessageClassification] = &[
    row(
        "ack",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "config_refreshed",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "restart_decision",
        RemoteMessageClass::Liveness,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "user_message_queued",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "delegation_steer",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "attachment_upload_started",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "attachment_chunk_accepted",
        RemoteMessageClass::BulkChunk,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "attachment_uploaded",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "terminal_paste_image",
        RemoteMessageClass::TerminalIo,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "remove_queued_user_message_result",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "remove_queued_user_messages_result",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "attached",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "subagent_transcript",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "sessions",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "session_messages",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "client_submission_receipt",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "history_page",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "subagent_history_page",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "note_recorded",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "goal_status",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "goal_updated",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "goal_cleared",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "pin_changed",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "pin_toggled",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "pin_count",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "pin_seqs",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "pins_with_text",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "pin_state",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "sealed_values",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "project_notes",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "project_note_created",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "project_note_renamed",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "assistants",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "assistant_upserted",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "assistant_session_created",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "auto_title",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "export_session_data",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::BulkReference,
    ),
    row(
        "import_session_archive",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "bulk_transfer_chunk_accepted",
        RemoteMessageClass::BulkChunk,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "bulk_transfer_chunk",
        RemoteMessageClass::BulkChunk,
        RemoteInlinePayloadBound::BulkReference,
    ),
    row(
        "curator",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "session_live_status",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "forked",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "btw_fork",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "inventory_bundle",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "resource_snapshot",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "promote_resource_result",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "scheduled_job",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "scheduled_jobs",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "scheduled_job_deleted",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "scheduled_job_run_queued",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "fs_list",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "fs_stat",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "fs_read",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "fs_write",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "git_status",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "git_diff_file",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "terminal_opened",
        RemoteMessageClass::TerminalIo,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "lsp_control_result",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "daemon_status",
        RemoteMessageClass::Liveness,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "usage_counts",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "stats_rollup",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "guidance_estimate",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "sandbox_state",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "sandbox_escalation_state",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "redaction_state",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "preflight_state",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "longcache_state",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "approval_mode_state",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "delegation_recursion_state",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "caffeinate_state",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "paused_work",
        RemoteMessageClass::ResumeWindow,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "run_invocation_status",
        RemoteMessageClass::BoundedRequestResponse,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "run_invocation_cancel_result",
        RemoteMessageClass::Cancel,
        RemoteInlinePayloadBound::Bounded,
    ),
];

/// Every `Event` variant.
pub const EVENT_CLASSIFICATION: &[RemoteMessageClassification] = &[
    row(
        "env_drift_warning",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "config_snapshot",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "queue_updated",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "foreground_input_target",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "active_model_state",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "model_selection_result",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "default_model_update_result",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "thinking_started",
        RemoteMessageClass::ModelDelta,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "reconnecting",
        RemoteMessageClass::Liveness,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "inference_warning",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "assistant_text_delta",
        RemoteMessageClass::ModelDelta,
        RemoteInlinePayloadBound::StreamChunked,
    ),
    row(
        "reasoning_delta",
        RemoteMessageClass::ModelDelta,
        RemoteInlinePayloadBound::StreamChunked,
    ),
    row(
        "assistant_text",
        RemoteMessageClass::ModelDelta,
        RemoteInlinePayloadBound::StreamChunked,
    ),
    row(
        "user_message_recorded",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "queued_user_messages_folded",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "session_persist_failed",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "session_driver_failed",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "preflight_started",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "user_messages_terminated",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "user_message_retracted",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "notice",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "lsp_notice",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "event_stream_lagged",
        RemoteMessageClass::Liveness,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "skill_auto_injected",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "tool_start",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "tool_progress",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::StreamChunked,
    ),
    row(
        "tool_end",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "resource_wait",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "resource_start",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "resource_clear",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "tool_error",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "inference_failed",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "inference_succeeded",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "backup_used",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "subagent_spawned",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "subagent_routing",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "subagent_report",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "nested_turn",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "usage",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "interrupt_raised",
        RemoteMessageClass::Approval,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "interrupt_queue_changed",
        RemoteMessageClass::Approval,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "interrupt_resolved",
        RemoteMessageClass::Approval,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "history_replay",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "agent_idle",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "goal_verification_progress",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "primary_swapped",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "llm_mode_changed",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "session_ended",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "schedule_started",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "schedule_progress",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "schedule_note",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "schedule_completed",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "context_projection",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "pruned",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "compact_ready",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "sandbox_state",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "sandbox_escalation_state",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "sandbox_unavailable",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "command_capability_unavailable",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "redaction_state",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "preflight_state",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "longcache_state",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "approval_mode_state",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "delegation_recursion_state",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "tandem_state",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "gitignore_allow",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Paged,
    ),
    row(
        "caffeinate_state",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "connector_status",
        RemoteMessageClass::BoundedEvent,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "terminal_output",
        RemoteMessageClass::TerminalIo,
        RemoteInlinePayloadBound::StreamChunked,
    ),
    row(
        "terminal_clipboard",
        RemoteMessageClass::TerminalIo,
        RemoteInlinePayloadBound::TruncatedByCap,
    ),
    row(
        "terminal_viewers",
        RemoteMessageClass::TerminalIo,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "terminal_closed",
        RemoteMessageClass::TerminalIo,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "osc52_protocol_violation",
        RemoteMessageClass::TerminalIo,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "daemon_draining",
        RemoteMessageClass::Liveness,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "paused_work_available",
        RemoteMessageClass::ResumeWindow,
        RemoteInlinePayloadBound::Bounded,
    ),
    row(
        "waiting_for_lock",
        RemoteMessageClass::Liveness,
        RemoteInlinePayloadBound::Bounded,
    ),
];

/// The committed inventory of variants whose pre-migration encoded payload
/// could exceed 512 KiB. Re-walked from `src/{request,response,event}.rs` at
/// implementation-time HEAD; it is test input, not a TODO.
pub const OVERSIZED_MESSAGE_INVENTORY: &[(RemoteMessageKind, &str)] = &[
    (RemoteMessageKind::Request, "attach"),
    (RemoteMessageKind::Request, "send_user_message"),
    (RemoteMessageKind::Request, "steer_delegation"),
    (RemoteMessageKind::Request, "upload_attachment_chunk"),
    (RemoteMessageKind::Request, "set_project_note_content"),
    (RemoteMessageKind::Request, "upsert_assistant"),
    (RemoteMessageKind::Request, "create_assistant_session"),
    (RemoteMessageKind::Request, "import_session_archive"),
    (RemoteMessageKind::Request, "write_bulk_transfer_chunk"),
    (RemoteMessageKind::Request, "fs_write"),
    (RemoteMessageKind::Request, "terminal_input"),
    (RemoteMessageKind::Request, "resolve_interrupt"),
    (RemoteMessageKind::Request, "session_live_status"),
    (RemoteMessageKind::Request, "record_session_note"),
    (RemoteMessageKind::Request, "create_scheduled_job"),
    (RemoteMessageKind::Request, "set_tool_surface_override"),
    (RemoteMessageKind::Request, "set_goal_settings_override"),
    (RemoteMessageKind::Request, "pin"),
    (RemoteMessageKind::Request, "refresh_env"),
    (RemoteMessageKind::Response, "user_message_queued"),
    (
        RemoteMessageKind::Response,
        "remove_queued_user_message_result",
    ),
    (
        RemoteMessageKind::Response,
        "remove_queued_user_messages_result",
    ),
    (RemoteMessageKind::Response, "attached"),
    (RemoteMessageKind::Response, "subagent_transcript"),
    (RemoteMessageKind::Response, "sessions"),
    (RemoteMessageKind::Response, "session_messages"),
    (RemoteMessageKind::Response, "history_page"),
    (RemoteMessageKind::Response, "subagent_history_page"),
    (RemoteMessageKind::Response, "pins_with_text"),
    (RemoteMessageKind::Response, "project_notes"),
    (RemoteMessageKind::Response, "project_note_created"),
    (RemoteMessageKind::Response, "assistants"),
    (RemoteMessageKind::Response, "assistant_upserted"),
    (RemoteMessageKind::Response, "export_session_data"),
    (RemoteMessageKind::Response, "bulk_transfer_chunk"),
    (RemoteMessageKind::Response, "curator"),
    (RemoteMessageKind::Response, "inventory_bundle"),
    (RemoteMessageKind::Response, "resource_snapshot"),
    (RemoteMessageKind::Response, "promote_resource_result"),
    (RemoteMessageKind::Response, "scheduled_job"),
    (RemoteMessageKind::Response, "scheduled_jobs"),
    (RemoteMessageKind::Response, "git_status"),
    (RemoteMessageKind::Response, "usage_counts"),
    (RemoteMessageKind::Event, "env_drift_warning"),
    (RemoteMessageKind::Event, "config_snapshot"),
    (RemoteMessageKind::Event, "queue_updated"),
    (RemoteMessageKind::Event, "assistant_text_delta"),
    (RemoteMessageKind::Event, "reasoning_delta"),
    (RemoteMessageKind::Event, "assistant_text"),
    (RemoteMessageKind::Event, "user_message_recorded"),
    (RemoteMessageKind::Event, "queued_user_messages_folded"),
    (RemoteMessageKind::Event, "tool_start"),
    (RemoteMessageKind::Event, "tool_progress"),
    (RemoteMessageKind::Event, "tool_end"),
    (RemoteMessageKind::Event, "tool_error"),
    (RemoteMessageKind::Event, "subagent_spawned"),
    (RemoteMessageKind::Event, "subagent_report"),
    (RemoteMessageKind::Event, "nested_turn"),
    (RemoteMessageKind::Event, "interrupt_raised"),
    (RemoteMessageKind::Event, "history_replay"),
    (RemoteMessageKind::Event, "schedule_note"),
    (RemoteMessageKind::Event, "pruned"),
    (RemoteMessageKind::Event, "compact_ready"),
    (RemoteMessageKind::Event, "gitignore_allow"),
    (RemoteMessageKind::Event, "terminal_output"),
    (RemoteMessageKind::Event, "terminal_clipboard"),
];

fn lookup(
    table: &'static [RemoteMessageClassification],
    tag: &str,
) -> RemoteTransportResult<&'static RemoteMessageClassification> {
    table
        .iter()
        .find(|row| row.tag == tag)
        .ok_or_else(|| RemoteTransportError::new(RemoteTransportReason::UnclassifiedMessage))
}

/// Classify a request tag. Unknown tags fail; they do not get a default lane.
pub fn classify_request_tag(
    tag: &str,
) -> RemoteTransportResult<&'static RemoteMessageClassification> {
    lookup(REQUEST_CLASSIFICATION, tag)
}

/// Classify a response tag.
pub fn classify_response_tag(
    tag: &str,
) -> RemoteTransportResult<&'static RemoteMessageClassification> {
    lookup(RESPONSE_CLASSIFICATION, tag)
}

/// Classify an event tag.
pub fn classify_event_tag(
    tag: &str,
) -> RemoteTransportResult<&'static RemoteMessageClassification> {
    lookup(EVENT_CLASSIFICATION, tag)
}

/// Table for a kind.
pub const fn table_for(kind: RemoteMessageKind) -> &'static [RemoteMessageClassification] {
    match kind {
        RemoteMessageKind::Request => REQUEST_CLASSIFICATION,
        RemoteMessageKind::Response => RESPONSE_CLASSIFICATION,
        RemoteMessageKind::Event => EVENT_CLASSIFICATION,
    }
}

/// Classify by kind and tag.
pub fn classify(
    kind: RemoteMessageKind,
    tag: &str,
) -> RemoteTransportResult<&'static RemoteMessageClassification> {
    lookup(table_for(kind), tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_transport::lane::MAX_LOGICAL_PAYLOAD_BYTES;
    use std::collections::BTreeSet;

    /// Expand a `*_variants!` macro into the set of wire tags it declares.
    macro_rules! collect_tags {
        (($($ctx:ident),*) [$(($pattern:pat, $tag:expr);)+]) => {{
            vec![$($tag),+]
        }};
    }

    fn request_tags() -> Vec<&'static str> {
        crate::request_variants!(collect_tags)
    }

    fn response_tags() -> Vec<&'static str> {
        crate::response_variants!(collect_tags)
    }

    fn event_tags() -> Vec<&'static str> {
        crate::event_variants!(collect_tags)
    }

    #[test]
    fn remote_transport_classification_is_exhaustive() {
        let sources: [(
            RemoteMessageKind,
            Vec<&'static str>,
            &[RemoteMessageClassification],
        ); 3] = [
            (
                RemoteMessageKind::Request,
                request_tags(),
                REQUEST_CLASSIFICATION,
            ),
            (
                RemoteMessageKind::Response,
                response_tags(),
                RESPONSE_CLASSIFICATION,
            ),
            (RemoteMessageKind::Event, event_tags(), EVENT_CLASSIFICATION),
        ];

        for (kind, wire_tags, table) in sources {
            let wire: BTreeSet<&str> = wire_tags
                .iter()
                .copied()
                .filter(|tag| *tag != UNKNOWN_MESSAGE_TAG)
                .collect();
            let classified: BTreeSet<&str> = table.iter().map(|row| row.tag).collect();

            // Both directions: no unclassified variant, no stale row.
            let unclassified: Vec<&str> = wire.difference(&classified).copied().collect();
            assert!(
                unclassified.is_empty(),
                "{} variants are on the wire but unclassified: {unclassified:?}",
                kind.as_str()
            );
            let stale: Vec<&str> = classified.difference(&wire).copied().collect();
            assert!(
                stale.is_empty(),
                "{} rows classify variants that no longer exist: {stale:?}",
                kind.as_str()
            );
            assert_eq!(table.len(), wire.len());
            assert_eq!(table.len(), classified.len(), "duplicate rows present");

            // The catch-all has no lane: an unknown kind fails classification.
            assert_eq!(
                classify(kind, UNKNOWN_MESSAGE_TAG).unwrap_err().reason,
                RemoteTransportReason::UnclassifiedMessage
            );
            for invented in ["definitely_not_a_real_variant", "", "Attach"] {
                assert_eq!(
                    classify(kind, invented).unwrap_err().reason,
                    RemoteTransportReason::UnclassifiedMessage,
                    "{invented} must not classify"
                );
            }

            // Every row resolves, and the lane is derived from the class alone.
            for row in table {
                let found = classify(kind, row.tag).unwrap();
                assert_eq!(found, row);
                assert_eq!(found.lane(), found.class.lane());
            }
        }

        // Exact table sizes, so a silent shrink is caught.
        assert_eq!(REQUEST_CLASSIFICATION.len(), 115);
        assert_eq!(RESPONSE_CLASSIFICATION.len(), 73);
        assert_eq!(EVENT_CLASSIFICATION.len(), 76);
    }

    #[test]
    fn remote_transport_classification_forbids_client_lane_selection() {
        // The only inputs to a lane decision are kind and tag. There is no
        // priority, lane, or hint parameter anywhere in this module's API, so
        // a peer has nothing to promote itself with.
        for class in RemoteMessageClass::ALL {
            let lane = class.lane();
            // Calling it repeatedly cannot change the answer.
            assert_eq!(class.lane(), lane);
            match lane {
                RemoteLane::Control => assert!(matches!(
                    class,
                    RemoteMessageClass::AuthCompletion
                        | RemoteMessageClass::CapabilityVersion
                        | RemoteMessageClass::LeaseRevocation
                        | RemoteMessageClass::Liveness
                        | RemoteMessageClass::Cancel
                        | RemoteMessageClass::ResumeWindow
                )),
                RemoteLane::Interactive => assert!(matches!(
                    class,
                    RemoteMessageClass::BoundedRequestResponse
                        | RemoteMessageClass::BoundedEvent
                        | RemoteMessageClass::TerminalIo
                        | RemoteMessageClass::Approval
                        | RemoteMessageClass::ModelDelta
                )),
                RemoteLane::Bulk => assert_eq!(class, RemoteMessageClass::BulkChunk),
            }
        }

        // Only the bulk transfer class may ride the bulk lane: no application
        // request can promote itself onto it.
        for kind in RemoteMessageKind::ALL {
            for row in table_for(kind) {
                if row.lane() == RemoteLane::Bulk {
                    assert_eq!(row.class, RemoteMessageClass::BulkChunk, "{}", row.tag);
                }
            }
        }

        // Classification carries no authorization signal whatsoever.
        let attach = classify_request_tag("attach").unwrap();
        let stop = classify_request_tag("stop_daemon").unwrap();
        assert_ne!(attach.lane(), stop.lane());
    }

    #[test]
    fn remote_message_classification_has_no_unbounded_inline_payload() {
        // The committed >512 KiB inventory is non-trivial and every member has
        // an explicit disposition other than `Bounded`.
        assert!(!OVERSIZED_MESSAGE_INVENTORY.is_empty());
        assert_eq!(OVERSIZED_MESSAGE_INVENTORY.len(), 66);

        for (kind, tag) in OVERSIZED_MESSAGE_INVENTORY {
            let row = classify(*kind, tag).unwrap_or_else(|_| {
                panic!("inventory entry {}/{tag} must classify", kind.as_str())
            });
            assert!(
                row.inline_payload_bound.requires_migration(),
                "{}/{tag} can exceed 512 KiB but is marked Bounded",
                kind.as_str()
            );
        }

        // Conversely, every non-`Bounded` row is in the inventory: the two
        // lists are the same set, so neither can drift.
        let inventory: BTreeSet<(RemoteMessageKind, &str)> = OVERSIZED_MESSAGE_INVENTORY
            .iter()
            .map(|(k, t)| (*k, *t))
            .collect();
        let mut migrated = BTreeSet::new();
        for kind in RemoteMessageKind::ALL {
            for row in table_for(kind) {
                if row.inline_payload_bound.requires_migration() {
                    migrated.insert((kind, row.tag));
                }
            }
        }
        assert_eq!(inventory, migrated);

        // The two structurally unbounded blob paths are the ones that had to
        // move to typed bulk transfers, and they did.
        assert_eq!(
            classify_request_tag("import_session_archive")
                .unwrap()
                .inline_payload_bound,
            RemoteInlinePayloadBound::BulkReference
        );
        assert_eq!(
            classify_response_tag("export_session_data")
                .unwrap()
                .inline_payload_bound,
            RemoteInlinePayloadBound::BulkReference
        );
        assert_eq!(
            classify_request_tag("upload_attachment_chunk")
                .unwrap()
                .inline_payload_bound,
            RemoteInlinePayloadBound::BulkReference
        );
        // Attachment chunks ride the bulk lane, not the interactive one.
        assert_eq!(
            classify_request_tag("upload_attachment_chunk")
                .unwrap()
                .lane(),
            RemoteLane::Bulk
        );
        // The advertised attachment chunk size fits a bulk logical payload.
        // Both sides are constants, so this holds at compile time.
        const { assert!(crate::MAX_ATTACHMENT_CHUNK_BASE64_BYTES < MAX_LOGICAL_PAYLOAD_BYTES) };

        // Nothing on the control lane may carry a migrated payload: the lane
        // that must never starve stays structurally tiny.
        for kind in RemoteMessageKind::ALL {
            for row in table_for(kind) {
                if row.lane() == RemoteLane::Control {
                    assert_eq!(
                        row.inline_payload_bound,
                        RemoteInlinePayloadBound::Bounded,
                        "control row {} must be structurally bounded",
                        row.tag
                    );
                }
            }
        }
    }

    #[test]
    fn remote_transport_classification_terminal_file_image_archive_coverage() {
        // Exhaustive terminal / file / image / archive classification, called
        // out by criterion 11.
        let terminal_requests = [
            "open_terminal",
            "attach_terminal",
            "terminal_input",
            "terminal_resize",
            "close_terminal",
        ];
        for tag in terminal_requests {
            let row = classify_request_tag(tag).unwrap();
            assert_eq!(row.class, RemoteMessageClass::TerminalIo, "{tag}");
            assert_eq!(row.lane(), RemoteLane::Interactive, "{tag}");
        }
        let terminal_events = [
            "terminal_output",
            "terminal_clipboard",
            "terminal_viewers",
            "terminal_closed",
            "osc52_protocol_violation",
        ];
        for tag in terminal_events {
            let row = classify_event_tag(tag).unwrap();
            assert_eq!(row.class, RemoteMessageClass::TerminalIo, "{tag}");
        }
        // Terminal bytes never starve control: they are interactive, and a
        // burst above the cap must be split by the producer.
        assert_eq!(
            classify_event_tag("terminal_output")
                .unwrap()
                .inline_payload_bound,
            RemoteInlinePayloadBound::StreamChunked
        );

        // File paths carry content but are capped daemon-side.
        for tag in ["fs_read", "fs_write", "fs_list", "fs_stat"] {
            assert_eq!(
                classify_request_tag(tag).unwrap().lane(),
                RemoteLane::Interactive
            );
        }
        assert_eq!(
            classify_request_tag("fs_write")
                .unwrap()
                .inline_payload_bound,
            RemoteInlinePayloadBound::TruncatedByCap
        );

        // Image / attachment upload: begin and finish are bounded control-shape
        // requests on the interactive lane; only the chunk rides bulk.
        for tag in ["begin_attachment_upload", "finish_attachment_upload"] {
            let row = classify_request_tag(tag).unwrap();
            assert_eq!(row.lane(), RemoteLane::Interactive, "{tag}");
            assert_eq!(row.inline_payload_bound, RemoteInlinePayloadBound::Bounded);
        }
        assert_eq!(
            classify_request_tag("cancel_attachment_upload")
                .unwrap()
                .lane(),
            RemoteLane::Control,
            "cancelling an upload must not queue behind the upload itself"
        );

        // Archive import/export both carry references, never bytes.
        assert_eq!(
            classify_request_tag("import_session_archive")
                .unwrap()
                .lane(),
            RemoteLane::Interactive
        );
        assert_eq!(
            classify_response_tag("export_session_data").unwrap().lane(),
            RemoteLane::Interactive
        );
    }
}
