//! `/settings → Agents` page (implementation note).
//!
//! A full management surface over the bundled cast
//! (`Build`/`builder`/`explore`/`Plan`) and any user-authored
//! custom agents. Each row shows the agent name, its builtin/custom
//! (+ overridden) status, and its **effective model** (the frontmatter
//! `model:` in canonical `provider/model` slash form, or the session
//! default). The docs pipeline is deliberately absent: it is a fixed
//! two-stage internal pipeline, never a user-editable [`cockpit_core::agents::AgentDef`].
//!
//! Actions:
//!   - `enter` — open the structured tool surface editor for the highlighted
//!     agent.
//!   - `e` — **raw edit** a daemon-returned definition snapshot. Workspace
//!     agents may use `$EDITOR` through a daemon editor lease and host-owned
//!     private staging file seeded once before launch; completion reads that
//!     leaf through its retained directory handle and sends only the edited
//!     bytes to the daemon. Assistant definitions use the in-TUI editor and
//!     their typed revisioned RPC. The TUI never writes either authoritative file.
//!   - `d` — **delete** a custom agent (arm→confirm via [`ResetButton`]).
//!     Built-ins can never be deleted.
//!   - `r` — **reset** the highlighted *overridden* built-in to its
//!     embedded default (arm→confirm), deleting just that one override.
//!   - `R` — **reset all** built-in overrides (the existing confirm flow).
//!
//! The page refreshes daemon-returned snapshots on entry and after each
//! edit/eject/delete/reset so the overridden/custom markers, revisions, and
//! effective model stay accurate. It never discovers authoritative files.

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::tui::theme::MUTED_COLOR_INDEX;
use crate::tui::tool_surface_picker::{
    ToolSurfaceDraft, ToolSurfaceEditOutcome, ToolSurfacePicker, ToolSurfaceRender,
    tool_surface_lines,
};
use cockpit_core::agents::AgentDef;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AgentKind {
    Builtin { overridden: bool },
    Custom,
}

use super::agent_editor::{AgentEditor, EditorOutcome};
use super::reset::{ResetButton, ResetOutcome};
use super::shell::{
    PointerOperationGate, PointerOperationId, SettingsScrollRegionId, push_wrapped_text,
    selected_line_from_marker,
};
use super::{Nav, SettingsCx, SettingsPage};
#[cfg(test)]
use super::{Page, SettingsDialog, TestPageMut, TestPageRef};

/// `/settings → Agents` state.
pub(super) struct AgentsPage {
    pub(super) cursor: usize,
    /// True while the "reset all built-in agents" confirmation is shown.
    pub(super) confirm_reset: bool,
    /// Arm→confirm guard for deleting the highlighted **custom** agent.
    pub(super) delete: ResetButton,
    /// Arm→confirm guard for resetting the highlighted **overridden
    /// built-in** to its embedded default.
    pub(super) reset_one: ResetButton,
    pub(super) status: Option<String>,
    /// One row per discovered agent (built-ins first, then custom).
    pub(super) rows: Vec<AgentRow>,
    /// In-TUI editor, present while the user is editing an agent file
    /// without `$EDITOR` (vim or plain — see editor-precedence ladder).
    pub(super) editing: Option<AgentEditor>,
    pub(super) detail: Option<AgentDetail>,
    /// Set when the user chose to edit and `$EDITOR` is available: the
    /// event loop drains this (the page can't suspend the TUI itself),
    /// runs `$EDITOR`, then calls back to re-read + re-parse.
    pub(super) pending_external_edit: Option<AgentExternalEdit>,
    /// Pointer/keyboard confirmation shown before the raw editor hands the
    /// current buffer to `$EDITOR`.  Keeping this separate from the live
    /// operation means repeated presses cannot submit an effect early.
    pub(super) external_edit_confirmation: Option<super::pointer_actions::AgentId>,
    external_edit_ops: PointerOperationGate,
    editor_body: Cell<Option<Rect>>,
    load_generation: uuid::Uuid,
    inventory_revision: Option<String>,
    canonical_project_root: Option<String>,
    /// Generation of the coherent inventory+assistant pair currently shown.
    authority_config_generation: Option<u64>,
    expected_inventory_after_commit: Option<String>,
    agent_rows: Vec<AgentRow>,
    assistant_rows: Vec<AgentRow>,
    inventory_load_error: Option<String>,
    assistant_load_error: Option<String>,
    staged_inventory: Option<StagedInventoryLoad>,
    staged_assistants: Option<StagedAssistantLoad>,
    pending_daemon: HashMap<uuid::Uuid, PendingAgentOperation>,
    /// Exact completion request retained after transport or response
    /// ambiguity. The page cannot close until the daemon replays a matching
    /// terminal receipt.
    uncertain_agent_operation: Option<Box<PendingAgentOperation>>,
}

struct StagedInventoryLoad {
    generation: uuid::Uuid,
    rows: Vec<AgentRow>,
    inventory_revision: String,
    canonical_project_root: String,
    config_generation: u64,
}

struct StagedAssistantLoad {
    generation: uuid::Uuid,
    rows: Vec<AgentRow>,
    config_generation: u64,
}

enum PendingAgentOperation {
    Inventory {
        generation: uuid::Uuid,
    },
    Assistants {
        generation: uuid::Uuid,
    },
    Snapshot {
        cwd: PathBuf,
        name: String,
        rendered_identity: super::pointer_actions::AgentId,
        authority_revision: String,
        purpose: SnapshotPurpose,
    },
    Mutation {
        client_operation_id: String,
        mutation_intent_hash: String,
        cwd: PathBuf,
        mutation: cockpit_core::daemon::proto::AgentMutation,
        expected_revision: Option<String>,
        purpose: MutationPurpose,
        querying: bool,
    },
    AssistantSave {
        client_operation_id: String,
        mutation_intent_hash: String,
        cwd: PathBuf,
        canonical_project_root: String,
        name: String,
        markdown: String,
        expected_revision: String,
        expected_config_generation: u64,
        purpose: SavePurpose,
        querying: bool,
    },
    AssistantDelete {
        client_operation_id: String,
        mutation_intent_hash: String,
        cwd: PathBuf,
        canonical_project_root: String,
        name: String,
        expected_registration_revision: String,
        expected_config_generation: u64,
        querying: bool,
    },
    BeginLease {
        client_operation_id: String,
        cwd: PathBuf,
        name: String,
        expected_revision: String,
        authority_id: super::pointer_actions::AgentId,
        draft: AgentEditor,
    },
    PrepareStaging {
        cwd: PathBuf,
        name: String,
        lease_id: String,
        consumed_revision: String,
        authority_id: super::pointer_actions::AgentId,
        staging_id: uuid::Uuid,
        draft: AgentEditor,
    },
    ReadStaging {
        pointer_operation_id: PointerOperationId,
        lease_id: String,
        consumed_revision: String,
        staging_id: uuid::Uuid,
        outcome: super::pointer_actions::ExternalEditOutcome,
        detail: Option<String>,
    },
    CompleteLease {
        client_operation_id: String,
        cwd: PathBuf,
        name: String,
        lease_id: String,
        consumed_revision: String,
        markdown: Option<String>,
        draft: Option<AgentEditor>,
        detail: Option<String>,
        outcome: super::pointer_actions::ExternalEditOutcome,
        querying: bool,
    },
}

#[derive(Clone, Copy)]
enum SnapshotPurpose {
    Edit { external: bool },
    OpenDetail,
    DeleteCustom,
    ResetBuiltin,
}

enum MutationPurpose {
    SaveEditor {
        markdown: String,
    },
    SaveDetail {
        markdown: String,
        cleanup_notice: Option<String>,
    },
    EjectForEdit {
        external: bool,
    },
    DeleteCustom,
    ResetBuiltin,
    ResetAll,
}

#[derive(Clone, Copy)]
enum SavePurpose {
    Editor,
    Detail,
}

pub(super) struct AgentExternalEdit {
    pub(super) id: PointerOperationId,
    pub(super) agent: super::pointer_actions::AgentId,
    /// Host-owned staging file. The authoritative agent path never leaves the
    /// daemon; completion returns the edited bytes under this lease.
    // Declared before TempDir so Windows closes the retained directory handle
    // before TempDir attempts recursive removal.
    staging_dir_handle: std::fs::File,
    staging_dir: tempfile::TempDir,
    staging_path: PathBuf,
    lease_id: String,
    consumed_revision: String,
    staging_id: uuid::Uuid,
    /// Raw draft retained until the effect reaches a terminal outcome. A
    /// failed/cancelled operation restores this exact editor for retry.
    draft: Option<AgentEditor>,
    servicing: bool,
}

/// Injected host-effect submission. The settings reducer only constructs this
/// value; the App owns the optional buffer write, terminal suspension/editor
/// launch, and completion callback.
pub(crate) struct AgentExternalEditEffect {
    pub(crate) operation_id: PointerOperationId,
    pub(crate) path: PathBuf,
}

pub(crate) struct AgentExternalEditStaging {
    // Drop order is security/lifecycle relevant on Windows.
    directory_handle: std::fs::File,
    directory: tempfile::TempDir,
    path: PathBuf,
}

impl AgentExternalEditStaging {
    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub(crate) fn retained_directory(&self) -> Result<std::fs::File, String> {
        self.directory_handle
            .try_clone()
            .map_err(|error| format!("failed to retain external-edit staging directory: {error}"))
    }

    pub(crate) fn leaf(&self) -> Option<std::ffi::OsString> {
        (self.path.parent() == Some(self.directory.path()))
            .then(|| self.path.file_name().map(std::ffi::OsStr::to_os_string))
            .flatten()
    }
}

fn agent_external_edit_staging() -> Result<AgentExternalEditStaging, String> {
    let directory = tempfile::Builder::new()
        .prefix("cockpit-agent-edit-")
        .tempdir()
        .map_err(|error| format!("failed to create private external-edit directory: {error}"))?;
    cockpit_core::private_fs::ensure_private_dir(directory.path())
        .map_err(|error| format!("failed to secure external-edit directory: {error:#}"))?;
    let path = directory.path().join("assistant.md");
    let directory_handle = cockpit_config::config::open_config_directory_nofollow(directory.path())
        .map_err(|error| format!("failed to retain external-edit directory: {error:#}"))?;
    Ok(AgentExternalEditStaging {
        directory_handle,
        directory,
        path,
    })
}

pub(crate) fn prepare_agent_external_edit_staging(
    text: &str,
) -> Result<AgentExternalEditStaging, String> {
    let staging = agent_external_edit_staging()?;
    seed_agent_external_edit_staging(&staging, text)?;
    Ok(staging)
}

fn seed_agent_external_edit_staging(
    staging: &AgentExternalEditStaging,
    text: &str,
) -> Result<(), String> {
    cockpit_config::config::write_config_bytes_atomic(&staging.path, text.as_bytes())
        .map_err(|error| format!("failed to seed external-edit recovery draft: {error:#}"))
}

pub(crate) fn read_agent_external_edit_staging(
    directory_handle: &std::fs::File,
    leaf: &std::ffi::OsStr,
) -> Result<String, String> {
    let bytes = cockpit_config::config::read_config_leaf_from_retained_directory(
        directory_handle,
        leaf,
        cockpit_core::daemon::proto::MAX_AGENT_MARKDOWN_BYTES,
    )
    .map_err(|error| format!("failed to read retained editor staging file: {error:#}"))?;
    String::from_utf8(bytes).map_err(|_| "external editor produced non-UTF-8 content".into())
}

/// A flattened, render-ready view of one [`AgentListing`]. We snapshot the
/// fields the page needs so the page state doesn't borrow the (non-`Clone`,
/// error-carrying) listing.
#[derive(Clone)]
pub(super) struct AgentRow {
    pub(super) name: String,
    pub(super) kind: AgentKind,
    /// `Ok(description)` when the agent parsed cleanly; `Err(error)`
    /// rendered distinctly when its file is malformed.
    pub(super) detail: Result<String, String>,
    /// Effective model display string: the frontmatter `model:` (canonical
    /// `provider/model` slash form), or `None` when the agent inherits the
    /// session's active model.
    pub(super) model: Option<String>,
    source: AgentRowSource,
}

#[derive(Clone)]
enum AgentRowSource {
    Agent {
        source_identity: String,
        revision: String,
    },
    Assistant {
        markdown: String,
        revision: String,
        registration_revision: String,
    },
    AssistantUnavailable {
        registration_revision: String,
    },
}

fn row_agent_id(name: &str, source: &AgentRowSource) -> super::pointer_actions::AgentId {
    match source {
        AgentRowSource::Agent {
            source_identity,
            revision,
        } => super::pointer_actions::AgentId::workspace_occurrence(name, source_identity, revision),
        AgentRowSource::Assistant {
            registration_revision,
            ..
        }
        | AgentRowSource::AssistantUnavailable {
            registration_revision,
        } => super::pointer_actions::AgentId::assistant_occurrence(name, registration_revision),
    }
}

pub(super) struct AgentDetail {
    name: String,
    original_text: String,
    revision: Option<String>,
    def: AgentDef,
    draft: Box<ToolSurfaceDraft>,
    picker: ToolSurfacePicker,
    status: Option<String>,
    row_errors: BTreeMap<String, String>,
    source: AgentRowSource,
}

impl AgentsPage {
    fn has_authoritative_pair(&self) -> bool {
        self.canonical_project_root.is_some()
            && self.authority_config_generation.is_some()
            && self.inventory_load_error.is_none()
            && self.assistant_load_error.is_none()
            && self.staged_inventory.is_none()
            && self.staged_assistants.is_none()
            && !self.pending_daemon.values().any(|pending| {
                matches!(
                    pending,
                    PendingAgentOperation::Inventory { .. }
                        | PendingAgentOperation::Assistants { .. }
                )
            })
    }

    pub(super) fn has_unsettled_external_edit(&self) -> bool {
        self.pending_external_edit.is_some()
            || self.uncertain_agent_operation.is_some()
            || self.pending_daemon.values().any(|pending| {
                matches!(
                    pending,
                    PendingAgentOperation::BeginLease { .. }
                        | PendingAgentOperation::PrepareStaging { .. }
                        | PendingAgentOperation::ReadStaging { .. }
                        | PendingAgentOperation::CompleteLease { .. }
                        | PendingAgentOperation::Mutation { .. }
                        | PendingAgentOperation::AssistantSave { .. }
                        | PendingAgentOperation::AssistantDelete { .. }
                )
            })
    }

    /// Build the page by discovering agents at `cwd`.
    pub(super) fn new(_cwd: &std::path::Path) -> Self {
        Self {
            cursor: 0,
            confirm_reset: false,
            delete: ResetButton::default(),
            reset_one: ResetButton::default(),
            status: Some("loading daemon-owned agent inventory…".into()),
            rows: Vec::new(),
            editing: None,
            detail: None,
            pending_external_edit: None,
            external_edit_confirmation: None,
            external_edit_ops: PointerOperationGate::default(),
            editor_body: Cell::new(None),
            load_generation: uuid::Uuid::new_v4(),
            inventory_revision: None,
            canonical_project_root: None,
            authority_config_generation: None,
            expected_inventory_after_commit: None,
            agent_rows: Vec::new(),
            assistant_rows: Vec::new(),
            inventory_load_error: None,
            assistant_load_error: None,
            staged_inventory: None,
            staged_assistants: None,
            pending_daemon: HashMap::new(),
            uncertain_agent_operation: None,
        }
    }

    fn retry_uncertain_agent_operation(&mut self, cx: &mut SettingsCx) {
        let Some(pending) = self.uncertain_agent_operation.take() else {
            return;
        };
        match *pending {
            PendingAgentOperation::BeginLease {
                client_operation_id,
                cwd,
                name,
                expected_revision,
                authority_id,
                draft,
            } => {
                self.stage(
                    cx,
                    super::SettingsEffectTarget {
                        surface: "agents.editor-lease-begin",
                        owner: format!("{}::{name}", cwd.display()),
                        revision: Some(expected_revision.clone()),
                    },
                    cockpit_core::daemon::proto::Request::BeginAgentEditorLease {
                        client_operation_id: client_operation_id.clone(),
                        project_root: cwd.to_string_lossy().into_owned(),
                        name: name.clone(),
                        expected_revision: expected_revision.clone(),
                    },
                    PendingAgentOperation::BeginLease {
                        client_operation_id,
                        cwd,
                        name,
                        expected_revision,
                        authority_id,
                        draft,
                    },
                );
                self.status = Some("retrying editor lease acquisition…".into());
            }
            PendingAgentOperation::CompleteLease {
                client_operation_id,
                cwd,
                name,
                lease_id,
                consumed_revision,
                markdown,
                draft,
                detail,
                outcome,
                querying: _,
            } => {
                self.stage(
                    cx,
                    super::SettingsEffectTarget {
                        surface: "agents.editor-lease-complete",
                        owner: format!("{}::{lease_id}", cwd.display()),
                        revision: Some(consumed_revision.clone()),
                    },
                    cockpit_core::daemon::proto::Request::GetAgentEditorLeaseSettlement {
                        client_operation_id: client_operation_id.clone(),
                        project_root: cwd.to_string_lossy().into_owned(),
                        lease_id: lease_id.clone(),
                    },
                    PendingAgentOperation::CompleteLease {
                        client_operation_id,
                        cwd,
                        name,
                        lease_id,
                        consumed_revision,
                        markdown,
                        draft,
                        detail,
                        outcome,
                        querying: true,
                    },
                );
                self.status = Some("retrying editor lease settlement…".into());
            }
            PendingAgentOperation::Mutation {
                client_operation_id,
                mutation_intent_hash,
                cwd,
                mutation,
                expected_revision,
                purpose,
                querying,
            } => {
                let project_root = cwd.to_string_lossy().into_owned();
                let request = if querying {
                    cockpit_core::daemon::proto::Request::MutateAgent {
                        client_operation_id: client_operation_id.clone(),
                        mutation_intent_hash: mutation_intent_hash.clone(),
                        project_root,
                        mutation: mutation.clone(),
                        expected_revision: expected_revision.clone(),
                    }
                } else {
                    cockpit_core::daemon::proto::Request::GetLocalOperationSettlement {
                        client_operation_id: client_operation_id.clone(),
                    }
                };
                self.stage(
                    cx,
                    super::SettingsEffectTarget {
                        surface: "agents.mutation",
                        owner: format!("{}::{}", cwd.display(), agent_mutation_owner(&mutation)),
                        revision: expected_revision.clone(),
                    },
                    request,
                    PendingAgentOperation::Mutation {
                        client_operation_id,
                        mutation_intent_hash,
                        cwd,
                        mutation,
                        expected_revision,
                        purpose,
                        querying: !querying,
                    },
                );
                self.status = Some(if querying {
                    "retrying the exact durable agent mutation…".into()
                } else {
                    "querying durable agent mutation settlement…".into()
                });
            }
            PendingAgentOperation::AssistantSave {
                client_operation_id,
                mutation_intent_hash,
                cwd,
                canonical_project_root,
                name,
                markdown,
                expected_revision,
                expected_config_generation,
                purpose,
                querying,
            } => {
                let project_root = cwd.to_string_lossy().into_owned();
                let request = if querying {
                    cockpit_core::daemon::proto::Request::SaveAssistantDefinition {
                        client_operation_id: client_operation_id.clone(),
                        mutation_intent_hash: mutation_intent_hash.clone(),
                        project_root,
                        name: name.clone(),
                        markdown: markdown.clone(),
                        expected_revision: expected_revision.clone(),
                        expected_config_generation,
                    }
                } else {
                    cockpit_core::daemon::proto::Request::GetLocalOperationSettlement {
                        client_operation_id: client_operation_id.clone(),
                    }
                };
                self.stage(
                    cx,
                    super::SettingsEffectTarget {
                        surface: "agents.assistant-save",
                        owner: name.clone(),
                        revision: Some(expected_revision.clone()),
                    },
                    request,
                    PendingAgentOperation::AssistantSave {
                        client_operation_id,
                        mutation_intent_hash,
                        cwd,
                        canonical_project_root,
                        name,
                        markdown,
                        expected_revision,
                        expected_config_generation,
                        purpose,
                        querying: !querying,
                    },
                );
                self.status = Some("reconciling assistant save settlement…".into());
            }
            PendingAgentOperation::AssistantDelete {
                client_operation_id,
                mutation_intent_hash,
                cwd,
                canonical_project_root,
                name,
                expected_registration_revision,
                expected_config_generation,
                querying,
            } => {
                let project_root = cwd.to_string_lossy().into_owned();
                let request = if querying {
                    cockpit_core::daemon::proto::Request::DeleteAssistant {
                        client_operation_id: client_operation_id.clone(),
                        mutation_intent_hash: mutation_intent_hash.clone(),
                        project_root,
                        name: name.clone(),
                        expected_revision: expected_registration_revision.clone(),
                        expected_config_generation,
                    }
                } else {
                    cockpit_core::daemon::proto::Request::GetLocalOperationSettlement {
                        client_operation_id: client_operation_id.clone(),
                    }
                };
                self.stage(
                    cx,
                    super::SettingsEffectTarget {
                        surface: "agents.assistant-delete",
                        owner: name.clone(),
                        revision: Some(expected_registration_revision.clone()),
                    },
                    request,
                    PendingAgentOperation::AssistantDelete {
                        client_operation_id,
                        mutation_intent_hash,
                        cwd,
                        canonical_project_root,
                        name,
                        expected_registration_revision,
                        expected_config_generation,
                        querying: !querying,
                    },
                );
                self.status = Some("reconciling assistant delete settlement…".into());
            }
            _ => unreachable!("only durable agent operations are retained for settlement"),
        }
    }

    pub(super) fn queue_load(&mut self, cx: &mut SettingsCx) {
        let cwd = cx.agents_cwd();
        let generation = uuid::Uuid::new_v4();
        self.load_generation = generation;
        self.inventory_load_error = None;
        self.assistant_load_error = None;
        self.staged_inventory = None;
        self.staged_assistants = None;
        self.status = Some("loading daemon-owned agent inventory…".into());
        let project_root = cwd.to_string_lossy().into_owned();
        let inventory = cx.enqueue_daemon_effect(
            super::SettingsEffectTarget {
                surface: "agents.inventory",
                owner: project_root.clone(),
                revision: Some(generation.to_string()),
            },
            cockpit_core::daemon::proto::Request::GetAgentInventory {
                project_root: project_root.clone(),
            },
        );
        self.pending_daemon
            .insert(inventory, PendingAgentOperation::Inventory { generation });
        let assistants = cx.enqueue_daemon_effect(
            super::SettingsEffectTarget {
                surface: "agents.assistants",
                owner: project_root,
                revision: Some(generation.to_string()),
            },
            cockpit_core::daemon::proto::Request::ListAssistants,
        );
        self.pending_daemon
            .insert(assistants, PendingAgentOperation::Assistants { generation });
    }

    fn rebuild_rows(&mut self) {
        self.rows = self.agent_rows.clone();
        self.rows.extend(self.assistant_rows.clone());
        self.cursor = self.cursor.min(self.rows.len().saturating_sub(1));
    }

    fn publish_paired_load(&mut self, generation: uuid::Uuid) {
        let (Some(inventory), Some(assistants)) = (
            self.staged_inventory.as_ref(),
            self.staged_assistants.as_ref(),
        ) else {
            return;
        };
        if inventory.generation != generation
            || assistants.generation != generation
            || inventory.config_generation != assistants.config_generation
        {
            self.inventory_load_error = Some(
                "inventory and assistants were read from different configuration generations"
                    .into(),
            );
            self.assistant_load_error = Some(
                "inventory and assistants were read from different configuration generations"
                    .into(),
            );
            self.staged_inventory = None;
            self.staged_assistants = None;
            return;
        }
        let inventory = self
            .staged_inventory
            .take()
            .expect("paired inventory staged");
        let assistants = self
            .staged_assistants
            .take()
            .expect("paired assistants staged");
        if let Some(expected) = self.expected_inventory_after_commit.take()
            && inventory.inventory_revision != expected
        {
            self.inventory_load_error =
                Some("inventory: committed refresh did not match its receipt".into());
            return;
        }
        self.agent_rows = inventory.rows;
        self.assistant_rows = assistants.rows;
        self.inventory_revision = Some(inventory.inventory_revision);
        self.canonical_project_root = Some(inventory.canonical_project_root);
        self.authority_config_generation = Some(inventory.config_generation);
        self.rebuild_rows();
    }

    fn refresh_paired_load_status(&mut self, generation: uuid::Uuid) {
        if generation != self.load_generation {
            return;
        }
        let waiting = self.pending_daemon.values().any(|pending| {
            matches!(pending,
                PendingAgentOperation::Inventory { generation: active }
                | PendingAgentOperation::Assistants { generation: active }
                if *active == generation)
        });
        let errors = [
            self.inventory_load_error.as_deref(),
            self.assistant_load_error.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        self.status = if !errors.is_empty() {
            Some(format!("Agents Unavailable — {}; Retry", errors.join("; ")))
        } else if waiting {
            Some("loading daemon-owned agent inventory…".into())
        } else {
            None
        };
    }

    pub(super) fn apply_daemon_completion(
        &mut self,
        cx: &mut SettingsCx,
        completion: super::SettingsDaemonEffectCompletion,
    ) {
        let Some(pending) = self.pending_daemon.remove(&completion.operation_id) else {
            return;
        };
        let cwd = cx.agents_cwd();
        let project_root = cwd.to_string_lossy();
        let target_matches = match &pending {
            PendingAgentOperation::Inventory { generation } => {
                completion.target.surface == "agents.inventory"
                    && completion.target.owner == project_root
                    && completion.target.revision.as_deref()
                        == Some(generation.to_string().as_str())
            }
            PendingAgentOperation::Assistants { generation } => {
                completion.target.surface == "agents.assistants"
                    && completion.target.owner == project_root
                    && completion.target.revision.as_deref()
                        == Some(generation.to_string().as_str())
            }
            PendingAgentOperation::Snapshot {
                cwd,
                name,
                authority_revision,
                ..
            } => {
                completion.target.surface == "agents.snapshot"
                    && completion.target.owner == format!("{}::{name}", cwd.display())
                    && completion.target.revision.as_deref() == Some(authority_revision)
            }
            PendingAgentOperation::Mutation {
                cwd,
                mutation,
                expected_revision,
                ..
            } => {
                completion.target.surface == "agents.mutation"
                    && completion.target.owner
                        == format!("{}::{}", cwd.display(), agent_mutation_owner(mutation))
                    && completion.target.revision == *expected_revision
            }
            PendingAgentOperation::AssistantSave {
                name,
                expected_revision,
                ..
            } => {
                completion.target.surface == "agents.assistant-save"
                    && completion.target.owner == *name
                    && completion.target.revision.as_deref() == Some(expected_revision)
            }
            PendingAgentOperation::AssistantDelete {
                name,
                expected_registration_revision,
                ..
            } => {
                completion.target.surface == "agents.assistant-delete"
                    && completion.target.owner == *name
                    && completion.target.revision.as_deref() == Some(expected_registration_revision)
            }
            PendingAgentOperation::BeginLease {
                client_operation_id: _,
                cwd,
                name,
                expected_revision,
                ..
            } => {
                completion.target.surface == "agents.editor-lease-begin"
                    && completion.target.owner == format!("{}::{name}", cwd.display())
                    && completion.target.revision.as_deref() == Some(expected_revision)
            }
            PendingAgentOperation::CompleteLease {
                cwd,
                lease_id,
                consumed_revision,
                ..
            } => {
                completion.target.surface == "agents.editor-lease-complete"
                    && completion.target.owner == format!("{}::{lease_id}", cwd.display())
                    && completion.target.revision.as_deref() == Some(consumed_revision)
            }
            PendingAgentOperation::PrepareStaging { .. }
            | PendingAgentOperation::ReadStaging { .. } => false,
        };
        if !target_matches {
            match pending {
                durable @ (PendingAgentOperation::Mutation { .. }
                | PendingAgentOperation::AssistantSave { .. }
                | PendingAgentOperation::AssistantDelete { .. }
                | PendingAgentOperation::BeginLease { .. }
                | PendingAgentOperation::CompleteLease { .. }) => {
                    self.uncertain_agent_operation = Some(Box::new(durable));
                    self.status = Some(
                        "durable agent completion target was malformed; press Enter to reconcile"
                            .into(),
                    );
                }
                PendingAgentOperation::Inventory { generation } => {
                    if generation == self.load_generation {
                        self.inventory_load_error =
                            Some("inventory completion target was malformed".into());
                        self.staged_inventory = None;
                        self.staged_assistants = None;
                        self.refresh_paired_load_status(generation);
                    }
                }
                PendingAgentOperation::Assistants { generation } => {
                    if generation == self.load_generation {
                        self.assistant_load_error =
                            Some("assistant completion target was malformed".into());
                        self.staged_inventory = None;
                        self.staged_assistants = None;
                        self.refresh_paired_load_status(generation);
                    }
                }
                PendingAgentOperation::Snapshot { .. }
                | PendingAgentOperation::PrepareStaging { .. }
                | PendingAgentOperation::ReadStaging { .. } => {
                    self.status = Some(
                        "stale or malformed read-only agent completion was discarded; retry the view"
                            .into(),
                    );
                }
            }
            return;
        }
        match pending {
            PendingAgentOperation::Inventory { generation } => {
                if generation != self.load_generation {
                    return;
                }
                match completion
                    .response
                    .and_then(|response| inventory_rows_from_response(&cwd, response))
                {
                    Ok((rows, inventory_revision, canonical_project_root, config_generation)) => {
                        self.inventory_load_error = None;
                        self.staged_inventory = Some(StagedInventoryLoad {
                            generation,
                            rows,
                            inventory_revision,
                            canonical_project_root,
                            config_generation,
                        });
                        self.publish_paired_load(generation);
                    }
                    Err(error) => {
                        self.inventory_load_error = Some(format!("inventory: {error}"));
                        self.staged_inventory = None;
                        self.staged_assistants = None;
                    }
                }
                self.refresh_paired_load_status(generation);
            }
            PendingAgentOperation::Assistants { generation } => {
                if generation != self.load_generation {
                    return;
                }
                match completion.response.and_then(assistant_rows_from_response) {
                    Ok((rows, config_generation)) => {
                        self.assistant_load_error = None;
                        self.staged_assistants = Some(StagedAssistantLoad {
                            generation,
                            rows,
                            config_generation,
                        });
                        self.publish_paired_load(generation);
                    }
                    Err(error) => {
                        self.assistant_load_error = Some(format!("assistants: {error}"));
                        self.staged_inventory = None;
                        self.staged_assistants = None;
                    }
                }
                self.refresh_paired_load_status(generation);
            }
            other => self.apply_operation_completion(cx, other, completion.response),
        }
    }

    pub(super) fn apply_blocking_completion(
        &mut self,
        cx: &mut SettingsCx,
        completion: super::SettingsBlockingEffectCompletion,
    ) {
        let Some(pending) = self.pending_daemon.remove(&completion.operation_id) else {
            return;
        };
        match pending {
            PendingAgentOperation::PrepareStaging {
                cwd,
                name,
                lease_id,
                consumed_revision,
                authority_id,
                staging_id,
                draft,
            } => {
                let expected = super::SettingsEffectTarget {
                    surface: "agents.editor-staging-prepare",
                    owner: format!("{}::{lease_id}", cwd.display()),
                    revision: Some(format!("{consumed_revision}::{staging_id}")),
                };
                if completion.target != expected {
                    self.settle_unserviced_editor_lease(
                        cx,
                        cwd,
                        name,
                        lease_id,
                        consumed_revision,
                        draft,
                        "external-editor staging receipt identity mismatch".into(),
                    );
                    return;
                }
                let staging = completion.outcome.and_then(|outcome| match outcome {
                    super::SettingsBlockingOutcome::AgentEditorPrepared {
                        staging_id: returned,
                        staging,
                    } if returned == staging_id => Ok(staging),
                    other => Err(format!(
                        "unexpected external-editor staging result: {other:?}"
                    )),
                });
                match staging {
                    Ok(staging)
                        if staging.path.parent() == Some(staging.directory.path())
                            && staging.path.file_name().is_some() =>
                    {
                        let id = self.external_edit_ops.begin();
                        self.pending_external_edit = Some(AgentExternalEdit {
                            id,
                            agent: authority_id,
                            staging_path: staging.path,
                            staging_dir: staging.directory,
                            staging_dir_handle: staging.directory_handle,
                            lease_id,
                            consumed_revision,
                            staging_id,
                            draft: Some(draft),
                            servicing: false,
                        });
                        self.status = Some("opening $EDITOR…".into());
                    }
                    Ok(_) => self.settle_unserviced_editor_lease(
                        cx,
                        cwd,
                        name,
                        lease_id,
                        consumed_revision,
                        draft,
                        "external-editor staging escaped its private directory".into(),
                    ),
                    Err(error) => self.settle_unserviced_editor_lease(
                        cx,
                        cwd,
                        name,
                        lease_id,
                        consumed_revision,
                        draft,
                        error,
                    ),
                }
            }
            PendingAgentOperation::ReadStaging {
                pointer_operation_id,
                lease_id,
                consumed_revision,
                staging_id,
                outcome,
                detail,
            } => {
                let expected = super::SettingsEffectTarget {
                    surface: "agents.editor-staging-read",
                    owner: lease_id.clone(),
                    revision: Some(format!("{consumed_revision}::{staging_id}")),
                };
                let read = if completion.target == expected {
                    completion.outcome.and_then(|outcome| match outcome {
                        super::SettingsBlockingOutcome::AgentEditorRead {
                            staging_id: returned,
                            text,
                        } if returned == staging_id => Ok(text),
                        other => Err(format!("unexpected external-editor read result: {other:?}")),
                    })
                } else {
                    Err("external-editor read receipt identity mismatch".into())
                };
                self.settle_external_edit_after_read(
                    cx,
                    pointer_operation_id,
                    lease_id,
                    consumed_revision,
                    staging_id,
                    outcome,
                    detail,
                    read,
                );
            }
            durable @ (PendingAgentOperation::Mutation { .. }
            | PendingAgentOperation::AssistantSave { .. }
            | PendingAgentOperation::AssistantDelete { .. }
            | PendingAgentOperation::BeginLease { .. }
            | PendingAgentOperation::CompleteLease { .. }) => {
                self.uncertain_agent_operation = Some(Box::new(durable));
                self.status = Some(
                    "durable agent operation received an invalid host completion; press Enter to reconcile"
                        .into(),
                );
            }
            PendingAgentOperation::Inventory { generation } => {
                if generation == self.load_generation {
                    self.inventory_load_error =
                        Some("inventory: invalid host completion channel".into());
                    self.staged_inventory = None;
                    self.staged_assistants = None;
                    self.refresh_paired_load_status(generation);
                }
            }
            PendingAgentOperation::Assistants { generation } => {
                if generation == self.load_generation {
                    self.assistant_load_error =
                        Some("assistants: invalid host completion channel".into());
                    self.staged_inventory = None;
                    self.staged_assistants = None;
                    self.refresh_paired_load_status(generation);
                }
            }
            PendingAgentOperation::Snapshot { .. } => {
                self.status = Some(
                    "read-only agent snapshot received an invalid host completion and was discarded"
                        .into(),
                );
            }
        }
    }

    fn stage(
        &mut self,
        cx: &mut SettingsCx,
        target: super::SettingsEffectTarget,
        request: cockpit_core::daemon::proto::Request,
        pending: PendingAgentOperation,
    ) {
        if self.pending_daemon.values().any(|existing| {
            !matches!(
                existing,
                PendingAgentOperation::Inventory { .. } | PendingAgentOperation::Assistants { .. }
            )
        }) {
            self.status = Some("an agent operation is already pending".into());
            return;
        }
        let operation_id = cx.enqueue_daemon_effect(target, request);
        self.pending_daemon.insert(operation_id, pending);
    }

    fn apply_operation_completion(
        &mut self,
        cx: &mut SettingsCx,
        pending: PendingAgentOperation,
        response: Result<cockpit_core::daemon::proto::Response, String>,
    ) {
        match pending {
            PendingAgentOperation::Snapshot {
                cwd,
                name,
                rendered_identity,
                authority_revision: _,
                purpose,
            } => {
                let snapshot = response.and_then(|response| match response {
                    cockpit_core::daemon::proto::Response::AgentEditSnapshot(snapshot) => {
                        validate_agent_snapshot(&snapshot, &cwd, &name, None)?;
                        Ok(snapshot)
                    }
                    other => Err(format!("unexpected agent snapshot response: {other:?}")),
                });
                let snapshot = match snapshot {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        self.status = Some(format!("agent operation failed: {error}"));
                        return;
                    }
                };
                let refreshed_identity = super::pointer_actions::AgentId::workspace_occurrence(
                    &name,
                    &snapshot.source_identity,
                    &snapshot.revision,
                );
                if refreshed_identity != rendered_identity {
                    self.status = Some("agent source changed since the action was rendered".into());
                    return;
                }
                match purpose {
                    SnapshotPurpose::Edit { external } if !snapshot.editable => {
                        let mutation = cockpit_core::daemon::proto::AgentMutation::EjectBuiltin {
                            name: name.clone(),
                        };
                        let expected_revision = snapshot.revision.clone();
                        let project_root = cwd.to_string_lossy().into_owned();
                        let client_operation_id = uuid::Uuid::new_v4().to_string();
                        let mutation_intent_hash = cockpit_proto::agent_mutation_intent_hash(
                            &project_root,
                            &mutation,
                            Some(&expected_revision),
                        );
                        self.stage(
                            cx,
                            super::SettingsEffectTarget {
                                surface: "agents.mutation",
                                owner: format!(
                                    "{}::{}",
                                    cwd.display(),
                                    agent_mutation_owner(&mutation)
                                ),
                                revision: Some(expected_revision.clone()),
                            },
                            cockpit_core::daemon::proto::Request::MutateAgent {
                                client_operation_id: client_operation_id.clone(),
                                mutation_intent_hash: mutation_intent_hash.clone(),
                                project_root,
                                mutation: mutation.clone(),
                                expected_revision: Some(expected_revision.clone()),
                            },
                            PendingAgentOperation::Mutation {
                                client_operation_id,
                                mutation_intent_hash,
                                cwd,
                                mutation,
                                expected_revision: Some(expected_revision),
                                purpose: MutationPurpose::EjectForEdit { external },
                                querying: false,
                            },
                        );
                    }
                    SnapshotPurpose::Edit { external } => {
                        self.open_workspace_editor(cx, cwd, snapshot, external)
                    }
                    SnapshotPurpose::OpenDetail => self.open_detail_from_snapshot(snapshot),
                    SnapshotPurpose::DeleteCustom => {
                        let mutation = cockpit_core::daemon::proto::AgentMutation::DeleteCustom {
                            name: name.clone(),
                        };
                        self.stage_mutation(
                            cx,
                            cwd,
                            mutation,
                            snapshot.revision,
                            MutationPurpose::DeleteCustom,
                        );
                    }
                    SnapshotPurpose::ResetBuiltin => {
                        let mutation = cockpit_core::daemon::proto::AgentMutation::ResetBuiltin {
                            name: name.clone(),
                        };
                        self.stage_mutation(
                            cx,
                            cwd,
                            mutation,
                            snapshot.revision,
                            MutationPurpose::ResetBuiltin,
                        );
                    }
                }
            }
            PendingAgentOperation::Mutation {
                client_operation_id,
                mutation_intent_hash,
                cwd,
                mutation,
                expected_revision,
                expected_config_generation,
                purpose,
                querying,
            } => {
                let response = match response {
                    Ok(response) => response,
                    Err(error) => {
                        self.uncertain_agent_operation =
                            Some(Box::new(PendingAgentOperation::Mutation {
                                client_operation_id,
                                mutation_intent_hash,
                                cwd,
                                mutation,
                                expected_revision,
                                purpose,
                                querying,
                            }));
                        self.status = Some(format!(
                            "agent mutation outcome is unknown ({error}); press Enter to reconcile"
                        ));
                        return;
                    }
                };
                let result = match bind_agent_mutation_settlement(
                    response,
                    &client_operation_id,
                    &mutation_intent_hash,
                ) {
                    Ok(AgentMutationSettlement::Committed(result)) => {
                        if let Err(error) = validate_agent_mutation_result(
                            &result,
                            &client_operation_id,
                            &mutation_intent_hash,
                            &cwd,
                            &mutation,
                            expected_revision.as_deref(),
                            None,
                        ) {
                            self.uncertain_agent_operation =
                                Some(Box::new(PendingAgentOperation::Mutation {
                                    client_operation_id,
                                    mutation_intent_hash,
                                    cwd,
                                    mutation,
                                    expected_revision,
                                    purpose,
                                    querying,
                                }));
                            self.status = Some(format!(
                                "agent mutation returned a malformed receipt ({error}); press Enter to reconcile"
                            ));
                            return;
                        }
                        result
                    }
                    Ok(AgentMutationSettlement::Pending) => {
                        self.uncertain_agent_operation =
                            Some(Box::new(PendingAgentOperation::Mutation {
                                client_operation_id,
                                mutation_intent_hash,
                                cwd,
                                mutation,
                                expected_revision,
                                purpose,
                                querying: false,
                            }));
                        self.status = Some(
                            "agent mutation is still pending; press Enter to query again".into(),
                        );
                        return;
                    }
                    Ok(AgentMutationSettlement::Rejected(error)) => {
                        self.status = Some(format!(
                            "agent mutation {} was rejected: {error}",
                            if querying { "settlement" } else { "request" }
                        ));
                        return;
                    }
                    Err(error) => {
                        self.uncertain_agent_operation =
                            Some(Box::new(PendingAgentOperation::Mutation {
                                client_operation_id,
                                mutation_intent_hash,
                                cwd,
                                mutation,
                                expected_revision,
                                purpose,
                                querying,
                            }));
                        self.status = Some(format!(
                            "agent mutation returned an unbound settlement ({error}); press Enter to reconcile"
                        ));
                        return;
                    }
                };
                if let cockpit_core::daemon::proto::AgentMutationOutcome::CommittedRefreshNeeded {
                    warning,
                } = &result.outcome
                {
                    match &purpose {
                        MutationPurpose::SaveEditor { .. } => self.editing = None,
                        MutationPurpose::SaveDetail { markdown, .. } => {
                            if let Some(detail) = self.detail.as_mut() {
                                detail.revision = Some(result.result_revision.clone());
                                detail.original_text = markdown.clone();
                            }
                        }
                        MutationPurpose::ResetAll => {
                            self.expected_inventory_after_commit =
                                result.inventory_revision.clone();
                        }
                        _ => {}
                    }
                    self.status = Some(format!(
                        "agent mutation committed but refresh is required: {warning}"
                    ));
                    self.queue_load(cx);
                    return;
                }
                match purpose {
                    MutationPurpose::EjectForEdit { external } => match result.snapshot {
                        Some(snapshot) => self.open_workspace_editor(cx, cwd, snapshot, external),
                        None => self.status = Some("daemon omitted ejected agent snapshot".into()),
                    },
                    MutationPurpose::SaveEditor { markdown } => match result.snapshot {
                        Some(snapshot) => {
                            let id = super::pointer_actions::AgentId::workspace_occurrence(
                                &snapshot.name,
                                &snapshot.source_identity,
                                &snapshot.revision,
                            );
                            self.editing = None;
                            self.status = Some(format!("saved `{}`", snapshot.name));
                            self.queue_load(cx);
                            self.restore_cursor_after_load(&id);
                            let _ = markdown;
                        }
                        None => self.status = Some("daemon omitted saved agent identity".into()),
                    },
                    MutationPurpose::SaveDetail {
                        markdown,
                        cleanup_notice,
                    } => {
                        let Some(snapshot) = result.snapshot else {
                            self.status = Some("daemon omitted saved agent identity".into());
                            return;
                        };
                        if let Some(detail) = self.detail.as_mut() {
                            detail.revision = Some(snapshot.revision.clone());
                            detail.source = AgentRowSource::Agent {
                                source_identity: snapshot.source_identity,
                                revision: snapshot.revision,
                            };
                            detail.original_text = markdown;
                            detail.status = Some(match cleanup_notice {
                                Some(notice) => format!("saved `{}`; {notice}", detail.name),
                                None => format!("saved `{}`", detail.name),
                            });
                        }
                        self.queue_load(cx);
                    }
                    MutationPurpose::DeleteCustom => {
                        self.status = Some("deleted custom agent".into());
                        self.queue_load(cx);
                    }
                    MutationPurpose::ResetBuiltin => {
                        self.status = Some("reset built-in agent to default".into());
                        self.queue_load(cx);
                    }
                    MutationPurpose::ResetAll => {
                        self.expected_inventory_after_commit = result.inventory_revision.clone();
                        self.status = Some(match result.outcome {
                            cockpit_core::daemon::proto::AgentMutationOutcome::Reconciled => {
                                "reset all built-in agent overrides".into()
                            }
                            cockpit_core::daemon::proto::AgentMutationOutcome::CommittedRefreshNeeded { warning } => warning,
                        });
                        self.queue_load(cx);
                    }
                }
            }
            PendingAgentOperation::AssistantSave {
                client_operation_id,
                mutation_intent_hash,
                cwd,
                canonical_project_root,
                name,
                markdown,
                expected_revision,
                expected_config_generation,
                purpose,
                querying,
            } => {
                let pending_for_retry = || PendingAgentOperation::AssistantSave {
                    client_operation_id: client_operation_id.clone(),
                    mutation_intent_hash: mutation_intent_hash.clone(),
                    cwd: cwd.clone(),
                    canonical_project_root: canonical_project_root.clone(),
                    name: name.clone(),
                    markdown: markdown.clone(),
                    expected_revision: expected_revision.clone(),
                    expected_config_generation,
                    purpose,
                    querying,
                };
                let response = match response {
                    Ok(response) => response,
                    Err(error) => {
                        self.uncertain_agent_operation = Some(Box::new(pending_for_retry()));
                        self.status = Some(format!(
                            "assistant save outcome is unknown ({error}); press Enter to reconcile"
                        ));
                        return;
                    }
                };
                let response = match bind_assistant_mutation_settlement(
                    response,
                    &client_operation_id,
                    &mutation_intent_hash,
                    "save_assistant_definition",
                ) {
                    Ok(AssistantMutationSettlement::Committed(response)) => response,
                    Ok(AssistantMutationSettlement::Pending) => {
                        self.uncertain_agent_operation = Some(Box::new(pending_for_retry()));
                        self.status =
                            Some("assistant save remains pending; press Enter to reconcile".into());
                        return;
                    }
                    Ok(AssistantMutationSettlement::Rejected(error)) => {
                        self.status = Some(format!("assistant save was rejected: {error}"));
                        return;
                    }
                    Err(error) => {
                        self.uncertain_agent_operation = Some(Box::new(pending_for_retry()));
                        self.status = Some(format!(
                            "assistant save receipt is unbound ({error}); press Enter to reconcile"
                        ));
                        return;
                    }
                };
                let requested_root = cwd.to_string_lossy();
                let saved = match response {
                    cockpit_core::daemon::proto::Response::AssistantDefinitionSaved {
                        client_operation_id: returned_operation_id,
                        mutation_intent_hash: returned_intent,
                        project_root,
                        requested_project_root,
                        name: returned_name,
                        assistant,
                        consumed_revision,
                        result_revision,
                        consumed_config_generation,
                        result_config_generation,
                        outcome,
                    } if returned_operation_id == client_operation_id
                        && returned_intent == mutation_intent_hash
                        && requested_project_root == requested_root.as_ref()
                        && canonical_project_root == project_root
                        && returned_name == name
                        && consumed_revision == expected_revision
                        && consumed_config_generation == expected_config_generation
                        && (matches!(
                            outcome,
                            cockpit_core::daemon::proto::AgentMutationOutcome::Reconciled
                        ) || result_config_generation > consumed_config_generation) =>
                    {
                        if let Some(assistant) = assistant {
                                coherent_assistant_save_revision(
                                    &assistant,
                                    &name,
                                    &markdown,
                                    &consumed_revision,
                                    &expected_revision,
                                )
                                .and_then(|revision| {
                                    if revision != result_revision {
                                        Err("assistant result revision is unbound".into())
                                    } else {
                                        Ok((Some(assistant), revision, outcome))
                                    }
                                })
                            } else if matches!(
                                &outcome,
                                cockpit_core::daemon::proto::AgentMutationOutcome::CommittedRefreshNeeded { .. }
                            ) {
                                Ok((None, result_revision, outcome))
                            } else {
                                Err("assistant save omitted its reconciled snapshot".into())
                            }
                    }
                    other => Err(format!("unexpected assistant save response: {other:?}")),
                };
                match saved {
                    Ok((assistant, revision, outcome)) => {
                        match purpose {
                            SavePurpose::Editor => self.editing = None,
                            SavePurpose::Detail => {
                                if let Some(detail) = self.detail.as_mut() {
                                    detail.revision = Some(revision.clone());
                                    if let Some(assistant) = assistant {
                                        detail.source = AgentRowSource::Assistant {
                                            markdown: markdown.clone(),
                                            revision,
                                            registration_revision: assistant.registration_revision,
                                        };
                                    }
                                    detail.original_text = markdown;
                                    detail.status = Some(format!("saved `{name}`"));
                                }
                            }
                        }
                        self.status = Some(match outcome {
                            cockpit_core::daemon::proto::AgentMutationOutcome::Reconciled => {
                                format!("saved assistant `{name}`")
                            }
                            cockpit_core::daemon::proto::AgentMutationOutcome::CommittedRefreshNeeded { warning } => warning,
                        });
                        self.queue_load(cx);
                    }
                    Err(error) => {
                        self.uncertain_agent_operation = Some(Box::new(pending_for_retry()));
                        self.status = Some(format!(
                            "assistant save receipt is malformed ({error}); press Enter to reconcile"
                        ));
                    }
                }
            }
            PendingAgentOperation::AssistantDelete {
                client_operation_id,
                mutation_intent_hash,
                cwd,
                canonical_project_root,
                name,
                expected_registration_revision,
                expected_config_generation,
                querying,
            } => {
                let retain_unknown = |this: &mut Self, message: String| {
                    this.uncertain_agent_operation =
                        Some(Box::new(PendingAgentOperation::AssistantDelete {
                            client_operation_id: client_operation_id.clone(),
                            mutation_intent_hash: mutation_intent_hash.clone(),
                            cwd: cwd.clone(),
                            canonical_project_root: canonical_project_root.clone(),
                            name: name.clone(),
                            expected_registration_revision: expected_registration_revision.clone(),
                            expected_config_generation,
                            querying,
                        }));
                    this.status = Some(message);
                };
                let response = match response {
                    Ok(response) => response,
                    Err(error) => {
                        retain_unknown(
                            self,
                            format!(
                                "assistant delete outcome is unknown ({error}); press Enter to reconcile"
                            ),
                        );
                        return;
                    }
                };
                let response = match bind_assistant_mutation_settlement(
                    response,
                    &client_operation_id,
                    &mutation_intent_hash,
                    "delete_assistant",
                ) {
                    Ok(AssistantMutationSettlement::Committed(response)) => response,
                    Ok(AssistantMutationSettlement::Pending) => {
                        retain_unknown(
                            self,
                            "assistant delete remains pending; press Enter to reconcile".into(),
                        );
                        return;
                    }
                    Ok(AssistantMutationSettlement::Rejected(error)) => {
                        self.status = Some(format!("assistant delete was rejected: {error}"));
                        return;
                    }
                    Err(error) => {
                        retain_unknown(
                            self,
                            format!(
                                "assistant delete receipt is unbound ({error}); press Enter to reconcile"
                            ),
                        );
                        return;
                    }
                };
                match response {
                    cockpit_core::daemon::proto::Response::AssistantDeleted {
                        client_operation_id: returned_operation_id,
                        mutation_intent_hash: returned_intent,
                        project_root,
                        requested_project_root,
                        name: deleted_name,
                        consumed_revision,
                        result_revision,
                        consumed_config_generation,
                        result_config_generation,
                        outcome,
                    } if returned_operation_id == client_operation_id
                        && returned_intent == mutation_intent_hash
                        && requested_project_root == cwd.to_string_lossy().as_ref()
                        && canonical_project_root == project_root
                        && deleted_name == name
                        && consumed_revision == expected_registration_revision
                        && !result_revision.trim().is_empty()
                        && consumed_config_generation == expected_config_generation
                        && (matches!(
                            outcome,
                            cockpit_core::daemon::proto::AgentMutationOutcome::Reconciled
                        ) || result_config_generation > consumed_config_generation) =>
                    {
                        self.status = Some(format!(
                            "unregistered assistant `{name}`; its home was retained"
                        ));
                        self.queue_load(cx);
                    }
                    other => retain_unknown(
                        self,
                        format!(
                            "assistant delete receipt is malformed ({other:?}); press Enter to reconcile"
                        ),
                    ),
                }
            }
            PendingAgentOperation::BeginLease {
                client_operation_id,
                cwd,
                name,
                expected_revision,
                authority_id,
                draft,
            } => self.apply_begin_lease(
                cx,
                client_operation_id,
                cwd,
                name,
                expected_revision,
                authority_id,
                draft,
                response,
            ),
            PendingAgentOperation::CompleteLease {
                client_operation_id,
                cwd,
                name,
                lease_id,
                consumed_revision,
                markdown,
                mut draft,
                detail,
                outcome,
                querying,
            } => self.apply_complete_lease(
                cx,
                client_operation_id,
                cwd,
                name,
                lease_id,
                consumed_revision,
                markdown,
                &mut draft,
                detail,
                outcome,
                querying,
                response,
            ),
            PendingAgentOperation::Inventory { .. } | PendingAgentOperation::Assistants { .. } => {}
        }
    }

    fn restore_cursor_after_load(&mut self, _id: &super::pointer_actions::AgentId) {
        // The subsequent inventory carries stable identities; selection is
        // clamped until that exact generation arrives. It is never rebound to
        // a row from an older generation.
    }

    fn open_detail_from_snapshot(
        &mut self,
        snapshot: cockpit_core::daemon::proto::AgentEditSnapshot,
    ) {
        let name = snapshot.name.clone();
        let original_text = snapshot.markdown.clone();
        let def = match cockpit_core::agents::parse_agent(
            &original_text,
            &name,
            PathBuf::from("<daemon-agent-snapshot>"),
        ) {
            Ok(def) if def.vnext.is_none() => def,
            Ok(_) => {
                self.status = Some(format!(
                    "structured tool editing is unavailable for `{name}`: schemaVersion 2 tool authority is host-owned"
                ));
                return;
            }
            Err(error) => {
                self.status = Some(format!(
                    "structured editor unavailable for `{name}`: {error}"
                ));
                return;
            }
        };
        let draft = ToolSurfaceDraft::from_def(&def);
        self.detail = Some(AgentDetail {
            name: name.clone(),
            path: PathBuf::from("<daemon-agent-snapshot>"),
            original_text,
            revision: Some(snapshot.revision.clone()),
            def,
            draft: Box::new(draft),
            picker: ToolSurfacePicker::default(),
            status: None,
            row_errors: BTreeMap::new(),
            source: AgentRowSource::Agent {
                source_identity: snapshot.source_identity,
                revision: snapshot.revision,
            },
        });
        self.status = None;
    }

    fn stage_mutation(
        &mut self,
        cx: &mut SettingsCx,
        cwd: PathBuf,
        mutation: cockpit_core::daemon::proto::AgentMutation,
        expected_revision: String,
        purpose: MutationPurpose,
    ) {
        let project_root = cwd.to_string_lossy().into_owned();
        let client_operation_id = uuid::Uuid::new_v4().to_string();
        let mutation_intent_hash = cockpit_proto::agent_mutation_intent_hash(
            &project_root,
            &mutation,
            Some(&expected_revision),
        );
        self.stage(
            cx,
            super::SettingsEffectTarget {
                surface: "agents.mutation",
                owner: format!("{}::{}", cwd.display(), agent_mutation_owner(&mutation)),
                revision: Some(expected_revision.clone()),
            },
            cockpit_core::daemon::proto::Request::MutateAgent {
                client_operation_id: client_operation_id.clone(),
                mutation_intent_hash: mutation_intent_hash.clone(),
                project_root,
                mutation: mutation.clone(),
                expected_revision: Some(expected_revision.clone()),
            },
            PendingAgentOperation::Mutation {
                client_operation_id,
                mutation_intent_hash,
                cwd,
                mutation,
                expected_revision: Some(expected_revision),
                purpose,
                querying: false,
            },
        );
    }

    fn open_workspace_editor(
        &mut self,
        cx: &mut SettingsCx,
        cwd: PathBuf,
        snapshot: cockpit_core::daemon::proto::AgentEditSnapshot,
        external: bool,
    ) {
        let name = snapshot.name.clone();
        let path = cwd.join(".cockpit/agents").join(format!("{name}.md"));
        let authority_id = super::pointer_actions::AgentId::workspace_occurrence(
            &name,
            &snapshot.source_identity,
            &snapshot.revision,
        );
        let draft = AgentEditor::new(
            name.clone(),
            path,
            &snapshot.markdown,
            cx.extended.tui.vim_mode.vim_enabled(),
            Some(snapshot.revision.clone()),
        )
        .with_authority_id(authority_id.clone());
        if external && std::env::var_os("EDITOR").is_some() {
            let expected_revision = snapshot.revision.clone();
            let client_operation_id = uuid::Uuid::new_v4().to_string();
            self.stage(
                cx,
                super::SettingsEffectTarget {
                    surface: "agents.editor-lease-begin",
                    owner: format!("{}::{name}", cwd.display()),
                    revision: Some(expected_revision.clone()),
                },
                cockpit_core::daemon::proto::Request::BeginAgentEditorLease {
                    client_operation_id: client_operation_id.clone(),
                    project_root: cwd.to_string_lossy().into_owned(),
                    name: name.clone(),
                    expected_revision: expected_revision.clone(),
                },
                PendingAgentOperation::BeginLease {
                    client_operation_id,
                    cwd,
                    name,
                    expected_revision,
                    authority_id,
                    draft,
                },
            );
            self.status = Some("requesting external editor lease…".into());
        } else {
            self.editing = Some(draft);
            self.status = None;
        }
    }

    fn apply_begin_lease(
        &mut self,
        cx: &mut SettingsCx,
        client_operation_id: String,
        cwd: PathBuf,
        name: String,
        expected_revision: String,
        authority_id: super::pointer_actions::AgentId,
        draft: AgentEditor,
        response: Result<cockpit_core::daemon::proto::Response, String>,
    ) {
        let lease = match response {
            Ok(cockpit_core::daemon::proto::Response::AgentEditorLeaseBegun(lease)) => lease,
            Ok(other) => {
                self.uncertain_agent_operation =
                    Some(Box::new(PendingAgentOperation::BeginLease {
                        client_operation_id,
                        cwd,
                        name,
                        expected_revision,
                        authority_id,
                        draft,
                    }));
                self.status = Some(format!(
                    "editor lease acquisition is unknown after an unexpected response: {other:?}; press Enter to query/retry"
                ));
                return;
            }
            Err(error) => {
                // The generic protocol error is not proof that the daemon did
                // not insert the lease. Preserve the exact operation and
                // replay it until a typed lease receipt arrives.
                self.uncertain_agent_operation =
                    Some(Box::new(PendingAgentOperation::BeginLease {
                        client_operation_id,
                        cwd,
                        name,
                        expected_revision,
                        authority_id,
                        draft,
                    }));
                self.status = Some(format!(
                    "editor lease acquisition is unknown: {error}; press Enter to query/retry"
                ));
                return;
            }
        };
        if lease.client_operation_id != client_operation_id
            || uuid::Uuid::parse_str(&lease.lease_id).is_err()
        {
            self.uncertain_agent_operation = Some(Box::new(PendingAgentOperation::BeginLease {
                client_operation_id,
                cwd,
                name,
                expected_revision,
                authority_id,
                draft,
            }));
            self.status = Some(
                "editor lease acquisition is unknown after a malformed lease receipt; press Enter to query/retry"
                    .into(),
            );
            return;
        }
        let validation =
            validate_agent_snapshot(&lease.snapshot, &cwd, &name, None).and_then(|()| {
                if lease.snapshot.revision != expected_revision
                    || !lease.snapshot.editable
                    || lease.snapshot.source_layer
                        != cockpit_core::daemon::proto::AgentSourceLayer::Workspace
                {
                    Err("daemon editor lease did not match the requested workspace revision".into())
                } else {
                    Ok(())
                }
            });
        if let Err(error) = validation {
            // The lease ID itself is authoritative even when the accompanying
            // snapshot is malformed or stale. Always settle that server-side
            // capability before falling back to the in-TUI recovery draft.
            self.settle_unserviced_editor_lease(
                cx,
                cwd,
                name,
                lease.lease_id,
                expected_revision,
                draft,
                format!("daemon editor lease snapshot was rejected: {error}"),
            );
            return;
        }
        let staging_id = uuid::Uuid::new_v4();
        let target = super::SettingsEffectTarget {
            surface: "agents.editor-staging-prepare",
            owner: format!("{}::{}", cwd.display(), lease.lease_id),
            revision: Some(format!("{}::{staging_id}", lease.snapshot.revision)),
        };
        let operation_id = cx.enqueue_blocking_work(
            target,
            super::SettingsBlockingEffectWork::PrepareAgentEditor {
                staging_id,
                seed: draft.text().to_string(),
            },
        );
        self.pending_daemon.insert(
            operation_id,
            PendingAgentOperation::PrepareStaging {
                cwd,
                name,
                lease_id: lease.lease_id,
                consumed_revision: lease.snapshot.revision,
                authority_id,
                staging_id,
                draft,
            },
        );
        self.status = Some("preparing private external-editor staging…".into());
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_unserviced_editor_lease(
        &mut self,
        cx: &mut SettingsCx,
        cwd: PathBuf,
        name: String,
        lease_id: String,
        consumed_revision: String,
        draft: AgentEditor,
        detail: String,
    ) {
        let client_operation_id = uuid::Uuid::new_v4().to_string();
        self.stage(
            cx,
            super::SettingsEffectTarget {
                surface: "agents.editor-lease-complete",
                owner: format!("{}::{lease_id}", cwd.display()),
                revision: Some(consumed_revision.clone()),
            },
            cockpit_core::daemon::proto::Request::CompleteAgentEditorLease {
                client_operation_id: client_operation_id.clone(),
                project_root: cwd.to_string_lossy().into_owned(),
                lease_id: lease_id.clone(),
                markdown: None,
            },
            PendingAgentOperation::CompleteLease {
                client_operation_id,
                cwd,
                name,
                lease_id,
                consumed_revision,
                markdown: None,
                draft: Some(draft),
                detail: Some(detail),
                outcome: super::pointer_actions::ExternalEditOutcome::Failed,
                querying: false,
            },
        );
        self.status = Some("external editor setup failed; cancelling daemon lease…".into());
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_complete_lease(
        &mut self,
        cx: &mut SettingsCx,
        client_operation_id: String,
        cwd: PathBuf,
        name: String,
        lease_id: String,
        consumed_revision: String,
        markdown: Option<String>,
        draft: &mut Option<AgentEditor>,
        detail: Option<String>,
        outcome: super::pointer_actions::ExternalEditOutcome,
        querying: bool,
        response: Result<cockpit_core::daemon::proto::Response, String>,
    ) {
        self.uncertain_agent_operation = None;
        let expected_saved = matches!(outcome, super::pointer_actions::ExternalEditOutcome::Saved);
        let receipt = match response {
            Ok(cockpit_core::daemon::proto::Response::AgentEditorLeaseCompleted(receipt))
                if cockpit_proto::validate_agent_editor_completion(
                    &receipt,
                    &client_operation_id,
                    cwd.to_string_lossy().as_ref(),
                    &name,
                    &lease_id,
                    &consumed_revision,
                )
                .is_ok() =>
            {
                receipt
            }
            other => {
                if let Some(markdown) = markdown.as_deref()
                    && let Some(editor) = draft.as_mut()
                {
                    editor.replace_with_recovery_text(markdown);
                }
                self.uncertain_agent_operation =
                    Some(Box::new(PendingAgentOperation::CompleteLease {
                        client_operation_id,
                        cwd,
                        name,
                        lease_id,
                        consumed_revision,
                        markdown,
                        draft: draft.take(),
                        detail,
                        outcome,
                        querying,
                    }));
                self.status = Some(format!(
                    "editor lease settlement is unknown after {other:?}; press Enter to query/retry"
                ));
                return;
            }
        };
        match receipt.status {
            cockpit_core::daemon::proto::AgentEditorSettlementStatus::NotStarted if querying => {
                self.stage(
                    cx,
                    super::SettingsEffectTarget {
                        surface: "agents.editor-lease-complete",
                        owner: format!("{}::{lease_id}", cwd.display()),
                        revision: Some(consumed_revision.clone()),
                    },
                    cockpit_core::daemon::proto::Request::CompleteAgentEditorLease {
                        client_operation_id: client_operation_id.clone(),
                        project_root: cwd.to_string_lossy().into_owned(),
                        lease_id: lease_id.clone(),
                        markdown: markdown.clone(),
                    },
                    PendingAgentOperation::CompleteLease {
                        client_operation_id,
                        cwd,
                        name,
                        lease_id,
                        consumed_revision,
                        markdown,
                        draft: draft.take(),
                        detail,
                        outcome,
                        querying: false,
                    },
                );
                self.status = Some("retrying exact editor lease settlement…".into());
            }
            cockpit_core::daemon::proto::AgentEditorSettlementStatus::Pending
            | cockpit_core::daemon::proto::AgentEditorSettlementStatus::NotStarted => {
                self.uncertain_agent_operation =
                    Some(Box::new(PendingAgentOperation::CompleteLease {
                        client_operation_id,
                        cwd,
                        name,
                        lease_id,
                        consumed_revision,
                        markdown,
                        draft: draft.take(),
                        detail,
                        outcome,
                        querying: true,
                    }));
                self.status = Some(
                    "editor lease settlement is still pending; press Enter to query again".into(),
                );
            }
            cockpit_core::daemon::proto::AgentEditorSettlementStatus::Rejected { error } => {
                if let Some(markdown) = markdown.as_deref()
                    && let Some(editor) = draft.as_mut()
                {
                    editor.replace_with_recovery_text(markdown);
                }
                self.editing = draft.take();
                self.status = Some(format!(
                    "daemon authoritatively rejected editor settlement: {}",
                    error.message
                ));
            }
            cockpit_core::daemon::proto::AgentEditorSettlementStatus::Cancelled
                if !expected_saved =>
            {
                self.editing = draft.take();
                self.status = Some(detail.unwrap_or_else(|| match outcome {
                    super::pointer_actions::ExternalEditOutcome::Cancelled => {
                        "external edit cancelled".into()
                    }
                    _ => "external edit failed".into(),
                }));
            }
            cockpit_core::daemon::proto::AgentEditorSettlementStatus::Saved {
                result_revision,
                outcome: commit_outcome,
            } if expected_saved && cockpit_proto::is_opaque_authority_token(&result_revision) => {
                self.status = Some(match (detail, commit_outcome) {
                    (Some(detail), _) => format!("saved `{name}`; {detail}"),
                    (
                        None,
                        cockpit_core::daemon::proto::AgentMutationOutcome::CommittedRefreshNeeded {
                            warning,
                        },
                    ) => format!("saved `{name}`; {warning}"),
                    _ => format!("saved `{name}`"),
                });
                self.queue_load(cx);
            }
            other => {
                self.uncertain_agent_operation =
                    Some(Box::new(PendingAgentOperation::CompleteLease {
                        client_operation_id,
                        cwd,
                        name,
                        lease_id,
                        consumed_revision,
                        markdown,
                        draft: draft.take(),
                        detail,
                        outcome,
                        querying: true,
                    }));
                self.status = Some(format!(
                    "daemon returned a mismatched editor settlement status {other:?}; press Enter to query again"
                ));
            }
        }
    }

    /// Help line for the footer, varying with the page sub-state.
    pub(super) fn help_text(&self) -> &'static str {
        if self.editing.is_some() {
            // The in-TUI editor draws its own hint; this is the footer.
            return if self
                .editing
                .as_ref()
                .is_some_and(AgentEditor::is_assistant_definition)
            {
                "editing assistant — ctrl+s: save  esc: cancel"
            } else {
                "editing agent — ctrl+s: save  e: $EDITOR  esc: cancel"
            };
        }
        if self.detail.is_some() {
            return "↑/↓  space: grant  t: tier  ctrl+s: save  e: raw editor  esc: list";
        }
        if self.confirm_reset {
            return "y: confirm reset-all  n/esc: cancel";
        }
        match self.rows.get(self.cursor) {
            Some(AgentRow {
                source: AgentRowSource::Assistant { .. },
                ..
            }) => {
                "↑/↓  enter: tools  e: edit definition  d: unregister (×2)  R: reset all  esc/h: back  q: close"
            }
            Some(AgentRow {
                source:
                    AgentRowSource::AssistantUnavailable {
                        registration_revision,
                    },
                ..
            }) if !registration_revision.is_empty() => {
                "↑/↓  enter: diagnostic  d: unregister (×2)  R: reset all  esc/h: back  q: close"
            }
            Some(AgentRow {
                source: AgentRowSource::AssistantUnavailable { .. },
                ..
            }) => "↑/↓  enter: diagnostic  R: reset all  esc/h: back  q: close",
            Some(AgentRow {
                kind: AgentKind::Custom,
                ..
            }) => {
                "↑/↓  enter: tools  e: raw edit  d: delete (×2)  R: reset all  esc/h: back  q: close"
            }
            Some(AgentRow {
                kind: AgentKind::Builtin { overridden: true },
                ..
            }) => {
                "↑/↓  enter: tools  e: raw edit  r: reset (×2)  R: reset all  esc/h: back  q: close"
            }
            _ => "↑/↓  enter: tools  e: raw edit  R: reset all  esc/h: back  q: close",
        }
    }

    /// Disarm both per-agent confirm guards. Called on any navigation /
    /// cancel so a stale "press again" can never fire on a different row.
    fn disarm_guards(&mut self) {
        self.delete.disarm();
        self.reset_one.disarm();
    }

    pub(super) fn take_external_edit_request(&mut self) -> Option<AgentExternalEditEffect> {
        let pending = self.pending_external_edit.as_mut()?;
        if pending.servicing {
            return None;
        }
        pending.servicing = true;
        Some(AgentExternalEditEffect {
            operation_id: pending.id,
            path: pending.staging_path.clone(),
        })
    }

    /// Re-read the edited file from disk, re-parse it, and refresh the row.
    /// A parse error is surfaced inline (keeping the user on the page); the
    /// `editor_error` from a failed external process is reported as-is.
    pub(super) fn finish_external_edit(
        &mut self,
        cx: &mut SettingsCx,
        id: PointerOperationId,
        outcome: super::pointer_actions::ExternalEditOutcome,
        detail: Option<String>,
    ) {
        let Some(agent) = self
            .pending_external_edit
            .as_ref()
            .filter(|pending| pending.id == id)
            .map(|pending| pending.agent.clone())
        else {
            return;
        };
        self.reduce_external_edit_result(
            cx,
            id,
            super::pointer_actions::AgentsAction::ExternalEditResult(agent, outcome),
            detail,
        );
    }

    fn reduce_external_edit_result(
        &mut self,
        cx: &mut SettingsCx,
        id: PointerOperationId,
        action: super::pointer_actions::AgentsAction,
        detail: Option<String>,
    ) {
        let super::pointer_actions::AgentsAction::ExternalEditResult(agent, outcome) = action
        else {
            return;
        };
        let Some(agent) = self
            .pending_external_edit
            .as_ref()
            .filter(|request| request.id == id && request.agent == agent)
            .map(|request| request.agent.clone())
        else {
            return;
        };
        let Some(pending) = self.pending_external_edit.as_ref() else {
            return;
        };
        let leaf = match pending.staging_path.file_name() {
            Some(leaf) if pending.staging_path.parent() == Some(pending.staging_dir.path()) => {
                leaf.to_os_string()
            }
            _ => {
                self.queue_failed_external_edit_read(
                    cx,
                    id,
                    outcome,
                    detail,
                    "external-edit staging path escaped its private directory".into(),
                );
                return;
            }
        };
        let directory_handle = match pending.staging_dir_handle.try_clone() {
            Ok(handle) => handle,
            Err(error) => {
                self.queue_failed_external_edit_read(
                    cx,
                    id,
                    outcome,
                    detail,
                    format!("failed to retain external-edit staging directory: {error}"),
                );
                return;
            }
        };
        let target = super::SettingsEffectTarget {
            surface: "agents.editor-staging-read",
            owner: pending.lease_id.clone(),
            revision: Some(format!(
                "{}::{}",
                pending.consumed_revision, pending.staging_id
            )),
        };
        let operation_id = cx.enqueue_blocking_work(
            target,
            super::SettingsBlockingEffectWork::ReadAgentEditor {
                staging_id: pending.staging_id,
                directory_handle,
                leaf,
            },
        );
        self.pending_daemon.insert(
            operation_id,
            PendingAgentOperation::ReadStaging {
                pointer_operation_id: id,
                lease_id: pending.lease_id.clone(),
                consumed_revision: pending.consumed_revision.clone(),
                staging_id: pending.staging_id,
                outcome,
                detail,
            },
        );
        self.status = Some("reading private external-editor staging…".into());
    }

    fn queue_failed_external_edit_read(
        &mut self,
        cx: &mut SettingsCx,
        id: PointerOperationId,
        _outcome: super::pointer_actions::ExternalEditOutcome,
        detail: Option<String>,
        error: String,
    ) {
        let Some(pending) = self.pending_external_edit.as_ref() else {
            return;
        };
        let lease_id = pending.lease_id.clone();
        let consumed_revision = pending.consumed_revision.clone();
        let staging_id = pending.staging_id;
        self.settle_external_edit_after_read(
            cx,
            id,
            lease_id,
            consumed_revision,
            staging_id,
            super::pointer_actions::ExternalEditOutcome::Failed,
            detail,
            Err(error),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_external_edit_after_read(
        &mut self,
        cx: &mut SettingsCx,
        id: PointerOperationId,
        lease_id: String,
        consumed_revision: String,
        staging_id: uuid::Uuid,
        outcome: super::pointer_actions::ExternalEditOutcome,
        detail: Option<String>,
        read: Result<String, String>,
    ) {
        let matches = self.pending_external_edit.as_ref().is_some_and(|pending| {
            pending.id == id
                && pending.lease_id == lease_id
                && pending.consumed_revision == consumed_revision
                && pending.staging_id == staging_id
        });
        if !matches || !self.external_edit_ops.complete(id) {
            return;
        }
        let Some(mut pending) = self.pending_external_edit.take() else {
            return;
        };
        let (settled_outcome, settled_detail, markdown) = match (outcome, read) {
            (super::pointer_actions::ExternalEditOutcome::Saved, Ok(text)) => {
                (outcome, detail, Some(text))
            }
            (non_saved, Ok(recovery)) => {
                if let Some(editor) = pending.draft.as_mut() {
                    editor.replace_with_recovery_text(&recovery);
                }
                (non_saved, detail, None)
            }
            (_, Err(error)) => (
                super::pointer_actions::ExternalEditOutcome::Failed,
                Some(match detail {
                    Some(detail) => format!("{detail}; {error}"),
                    None => error,
                }),
                None,
            ),
        };
        let cwd = cx.agents_cwd();
        let client_operation_id = uuid::Uuid::new_v4().to_string();
        self.stage(
            cx,
            super::SettingsEffectTarget {
                surface: "agents.editor-lease-complete",
                owner: format!("{}::{lease_id}", cwd.display()),
                revision: Some(consumed_revision.clone()),
            },
            cockpit_core::daemon::proto::Request::CompleteAgentEditorLease {
                client_operation_id: client_operation_id.clone(),
                project_root: cwd.to_string_lossy().into_owned(),
                lease_id: lease_id.clone(),
                markdown: markdown.clone(),
            },
            PendingAgentOperation::CompleteLease {
                client_operation_id,
                cwd,
                name: pending.agent.name().to_string(),
                lease_id,
                consumed_revision,
                markdown,
                draft: pending.draft.take(),
                detail: settled_detail,
                outcome: settled_outcome,
                querying: false,
            },
        );
        self.status = Some("settling external editor lease…".into());
    }
}

fn agent_mutation_owner(mutation: &cockpit_core::daemon::proto::AgentMutation) -> &str {
    match mutation {
        cockpit_core::daemon::proto::AgentMutation::EjectBuiltin { name }
        | cockpit_core::daemon::proto::AgentMutation::SaveDefinition { name, .. }
        | cockpit_core::daemon::proto::AgentMutation::CreateDefinition { name, .. }
        | cockpit_core::daemon::proto::AgentMutation::DeleteCustom { name }
        | cockpit_core::daemon::proto::AgentMutation::ResetBuiltin { name }
        | cockpit_core::daemon::proto::AgentMutation::SaveGoalSupervision { name, .. } => name,
        cockpit_core::daemon::proto::AgentMutation::ResetAllBuiltins => "reset-all",
    }
}

/// Build the per-row view models for `cwd`, including the effective model.
fn inventory_rows_from_response(
    cwd: &std::path::Path,
    response: cockpit_core::daemon::proto::Response,
) -> Result<(Vec<AgentRow>, String, String, u64), String> {
    let cockpit_core::daemon::proto::Response::AgentInventory {
        entries,
        inventory_revision,
        project_root,
        requested_project_root,
        config_generation,
    } = response
    else {
        return Err(format!("unexpected agent inventory response: {response:?}"));
    };
    if requested_project_root != cwd.to_string_lossy()
        || project_root.trim().is_empty()
        || project_root.contains('\0')
        || project_root.len() > cockpit_proto::MAX_ASSISTANT_HOME_BYTES
        || !std::path::Path::new(&project_root).is_absolute()
        || !valid_agent_inventory(cwd, &entries, &inventory_revision)
    {
        return Err("daemon returned an invalid agent inventory receipt".into());
    }
    let rows = entries
        .into_iter()
        .map(|entry| AgentRow {
            name: entry.name,
            kind: match entry.kind {
                cockpit_core::daemon::proto::AgentEntryKind::Builtin => AgentKind::Builtin {
                    overridden: entry.overridden,
                },
                cockpit_core::daemon::proto::AgentEntryKind::Custom => AgentKind::Custom,
            },
            detail: if entry.valid {
                Ok(entry.description.unwrap_or_default())
            } else {
                Err(entry.diagnostic.unwrap_or_else(|| "invalid agent".into()))
            },
            model: normalize_model(entry.model),
            source: AgentRowSource::Agent {
                source_identity: entry.source_identity,
                revision: entry.revision,
            },
        })
        .collect();
    Ok((rows, inventory_revision, project_root, config_generation))
}

fn valid_agent_inventory(
    _cwd: &std::path::Path,
    entries: &[cockpit_core::daemon::proto::AgentInventoryEntry],
    revision: &str,
) -> bool {
    let mut names = std::collections::HashSet::new();
    cockpit_proto::is_opaque_authority_token(revision)
        && entries.iter().all(|entry| {
            let builtin = cockpit_core::agents::is_builtin_agent(&entry.name);
            !entry.name.is_empty()
                && entry.name.len() <= cockpit_core::daemon::proto::MAX_AGENT_NAME_BYTES
                && names.insert(entry.name.as_str())
                && [
                    entry.description.as_deref(),
                    entry.model.as_deref(),
                    entry.diagnostic.as_deref(),
                ]
                .into_iter()
                .flatten()
                .all(|value| value.len() <= cockpit_proto::MAX_AGENT_METADATA_BYTES)
                && (entry.kind == cockpit_core::daemon::proto::AgentEntryKind::Builtin) == builtin
                && (!entry.overridden || builtin)
                && cockpit_proto::is_opaque_authority_token(&entry.source_identity)
                && cockpit_proto::is_opaque_authority_token(&entry.revision)
                && cockpit_proto::is_opaque_authority_token(&entry.projection_digest)
                && if entry.valid {
                    entry.diagnostic.is_none() && entry.description.is_some()
                } else {
                    entry.description.is_none()
                        && entry.model.is_none()
                        && entry
                            .diagnostic
                            .as_deref()
                            .is_some_and(|diagnostic| !diagnostic.trim().is_empty())
                }
        })
}

fn assistant_rows_from_response(
    response: cockpit_core::daemon::proto::Response,
) -> Result<(Vec<AgentRow>, u64), String> {
    let cockpit_core::daemon::proto::Response::Assistants {
        assistants,
        config_generation,
    } = response
    else {
        return Err(format!("unexpected assistants response: {response:?}"));
    };
    let mut names = std::collections::HashSet::new();
    let mut rows = Vec::with_capacity(assistants.len());
    for row in assistants {
        if !names.insert(row.name.clone()) {
            return Err(format!(
                "daemon returned duplicate assistant name `{}`",
                row.name
            ));
        }
        let summary_validation = cockpit_proto::validate_assistant_summary(&row);
        let source = match (row.definition_markdown, row.definition_revision) {
            (Some(markdown), Some(revision))
                if !revision.is_empty()
                    && row.definition_diagnostic.is_none()
                    && summary_validation.is_ok() =>
            {
                AgentRowSource::Assistant {
                    markdown,
                    revision,
                    registration_revision: row.registration_revision.clone(),
                }
            }
            (None, None)
                if row.definition_diagnostic.is_some()
                    && !row.registration_revision.is_empty()
                    && summary_validation.is_ok() =>
            {
                AgentRowSource::AssistantUnavailable {
                    registration_revision: row.registration_revision.clone(),
                }
            }
            _ => AgentRowSource::AssistantUnavailable {
                // A malformed presentation must never carry deletion
                // authority into a UI row. It remains visible only as a
                // diagnostic projection and cannot authorize a mutation.
                registration_revision: String::new(),
            },
        };
        let definition = match &source {
            AgentRowSource::Assistant { markdown, .. } => {
                cockpit_core::agents::parse_daemon_local_markdown(markdown, &row.name)
                    .map_err(|error| error.to_string())
            }
            AgentRowSource::AssistantUnavailable { .. } => Err(summary_validation
                .err()
                .map(str::to_string)
                .or(row.definition_diagnostic.clone())
                .unwrap_or_else(|| {
                    "daemon returned an incoherent assistant definition snapshot".into()
                })),
            AgentRowSource::Agent { .. } => unreachable!(),
        };
        let (detail, model) = match definition {
            Ok(def) => (Ok(def.description), normalize_model(def.model)),
            Err(error) => (Err(error), None),
        };
        rows.push(AgentRow {
            name: row.name,
            kind: AgentKind::Custom,
            detail,
            model,
            source,
        });
    }
    Ok((rows, config_generation))
}

fn coherent_assistant_save_revision(
    assistant: &cockpit_core::daemon::proto::AssistantSummary,
    expected_name: &str,
    expected_markdown: &str,
    consumed_revision: &str,
    expected_consumed_revision: &str,
) -> Result<String, String> {
    cockpit_proto::validate_assistant_summary(assistant).map_err(str::to_string)?;
    if assistant.name != expected_name || consumed_revision != expected_consumed_revision {
        return Err("daemon returned a misrouted assistant save snapshot".into());
    }
    match (
        assistant.definition_markdown.as_ref(),
        assistant.definition_revision.as_ref(),
        assistant.definition_diagnostic.as_ref(),
    ) {
        (Some(markdown), Some(revision), None)
            if markdown == expected_markdown && !revision.is_empty() =>
        {
            Ok(revision.clone())
        }
        _ => Err("daemon returned an incoherent assistant save snapshot".into()),
    }
}

pub(crate) fn validate_agent_snapshot(
    snapshot: &cockpit_core::daemon::proto::AgentEditSnapshot,
    cwd: &std::path::Path,
    expected_name: &str,
    expected_markdown: Option<&str>,
) -> Result<(), String> {
    cockpit_proto::validate_agent_source_identity(snapshot, cwd.to_string_lossy().as_ref())
        .map_err(str::to_string)?;
    if snapshot.name != expected_name
        || snapshot.name.is_empty()
        || snapshot.name.len() > cockpit_core::daemon::proto::MAX_AGENT_NAME_BYTES
        || snapshot.revision.is_empty()
        || snapshot.source_identity.is_empty()
        || snapshot.markdown.len() > cockpit_core::daemon::proto::MAX_AGENT_MARKDOWN_BYTES
        || snapshot.canonical_preview.len() > cockpit_core::daemon::proto::MAX_AGENT_MARKDOWN_BYTES
    {
        return Err("daemon returned a misrouted or revisionless agent snapshot".into());
    }
    if expected_markdown.is_some_and(|markdown| snapshot.markdown != markdown) {
        return Err("daemon returned an agent snapshot with unexpected content".into());
    }
    let workspace =
        snapshot.source_layer == cockpit_core::daemon::proto::AgentSourceLayer::Workspace;
    let embedded = snapshot.source_layer == cockpit_core::daemon::proto::AgentSourceLayer::Embedded;
    if snapshot.editable != workspace
        || snapshot.overridden != !embedded
        || (snapshot.kind == cockpit_core::daemon::proto::AgentEntryKind::Custom && embedded)
    {
        return Err("daemon returned incoherent agent source metadata".into());
    }
    if let Some(goal) = &snapshot.goal_supervision_json {
        serde_json::from_str::<serde_json::Value>(goal)
            .map_err(|_| "daemon returned invalid goal supervision JSON".to_string())?;
    }
    Ok(())
}

pub(crate) fn validate_agent_mutation_result(
    result: &cockpit_core::daemon::proto::AgentMutationResult,
    client_operation_id: &str,
    mutation_intent_hash: &str,
    cwd: &std::path::Path,
    mutation: &cockpit_core::daemon::proto::AgentMutation,
    prior_revision: Option<&str>,
    completed_lease_id: Option<&str>,
) -> Result<(), String> {
    use cockpit_core::daemon::proto::{
        AgentEntryKind as K, AgentMutation as M, AgentSourceLayer as L,
    };
    cockpit_proto::validate_agent_mutation_envelope(
        result,
        client_operation_id,
        mutation_intent_hash,
        cwd.to_string_lossy().as_ref(),
        cockpit_proto::agent_mutation_name(mutation),
        prior_revision,
        completed_lease_id,
        matches!(mutation, M::ResetAllBuiltins),
    )
    .map_err(str::to_string)?;
    if matches!(
        result.outcome,
        cockpit_core::daemon::proto::AgentMutationOutcome::CommittedRefreshNeeded { .. }
    ) {
        if let Some(snapshot) = &result.snapshot {
            let name = cockpit_proto::agent_mutation_name(mutation)
                .ok_or("inventory mutation returned a single-agent snapshot")?;
            validate_agent_snapshot(snapshot, cwd, name, None)?;
        }
        return Ok(());
    }
    let coherent_count = result.affected == u32::from(result.changed);
    let require_snapshot = |name: &str, markdown: Option<&str>| {
        let snapshot = result
            .snapshot
            .as_ref()
            .ok_or_else(|| "daemon omitted the mutation target snapshot".to_string())?;
        validate_agent_snapshot(snapshot, cwd, name, markdown)?;
        if let Some(prior) = prior_revision
            && result.changed != (snapshot.revision != prior)
        {
            return Err(
                "daemon mutation change flag disagrees with its exact revision transition"
                    .to_string(),
            );
        }
        Ok(snapshot)
    };
    match mutation {
        M::EjectBuiltin { name } => {
            if !coherent_count || !result.changed || result.affected != 1 {
                return Err("incoherent eject mutation count".into());
            }
            let s = require_snapshot(name, None)?;
            if s.kind != K::Builtin
                || !s.overridden
                || !s.editable
                || s.source_layer != L::Workspace
            {
                return Err("daemon returned incoherent ejected-agent ownership".into());
            }
        }
        M::SaveDefinition { name, markdown } => {
            if !coherent_count {
                return Err("incoherent save mutation count".into());
            }
            let s = require_snapshot(name, Some(markdown))?;
            if !s.editable || s.source_layer != L::Workspace {
                return Err("daemon returned saved content from a non-workspace source".into());
            }
        }
        M::CreateDefinition { name, markdown } => {
            if !result.changed || result.affected != 1 {
                return Err("agent creation was not a single committed change".into());
            }
            let s = require_snapshot(name, Some(markdown))?;
            if s.kind != K::Custom || !s.editable || s.source_layer != L::Workspace {
                return Err("daemon returned incoherent created-agent ownership".into());
            }
        }
        M::DeleteCustom { .. } => {
            if !result.changed || result.affected != 1 || result.snapshot.is_some() {
                return Err("daemon returned an incoherent custom-agent deletion result".into());
            }
        }
        M::ResetBuiltin { name } => {
            if !result.changed || result.affected != 1 {
                return Err("built-in reset was not a single committed change".into());
            }
            let s = require_snapshot(name, None)?;
            if s.kind != K::Builtin || s.overridden || s.editable || s.source_layer != L::Embedded {
                return Err("daemon returned incoherent reset built-in ownership".into());
            }
        }
        M::ResetAllBuiltins => {
            if result.snapshot.is_some()
                || result.changed != (result.affected != 0)
                || result.affected as usize > cockpit_core::agents::BUILTIN_AGENT_NAMES.len()
            {
                return Err("daemon returned an incoherent reset-all result".into());
            }
            if result
                .inventory_revision
                .as_deref()
                .is_none_or(str::is_empty)
            {
                return Err("daemon omitted the reset-all inventory revision".into());
            }
            if let cockpit_core::daemon::proto::AgentMutationOutcome::CommittedRefreshNeeded {
                warning,
            } = &result.outcome
                && warning.trim().is_empty()
            {
                return Err("daemon omitted the committed reset refresh warning".into());
            }
        }
        M::SaveGoalSupervision { name, .. } => {
            if !coherent_count {
                return Err("incoherent goal-settings mutation count".into());
            }
            let s = require_snapshot(name, None)?;
            if result.changed && (!s.editable || s.source_layer != L::Workspace) {
                return Err(
                    "changed goal settings were not published to the workspace layer".into(),
                );
            }
            if !s.supports_goal_supervision {
                return Err("daemon returned goal settings for an unsupported agent".into());
            }
            let M::SaveGoalSupervision { patch, .. } = mutation else {
                unreachable!()
            };
            let value: serde_json::Value = s
                .goal_supervision_json
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|_| "daemon returned invalid goal supervision JSON")?
                .unwrap_or_else(|| serde_json::json!({}));
            let object = value
                .as_object()
                .ok_or("goal supervision must be an object")?;
            let exact_optional = |key: &str, expected: &Option<Option<serde_json::Value>>| {
                expected.as_ref().is_none_or(|expected| match expected {
                    Some(expected) => object.get(key) == Some(expected),
                    None => !object.contains_key(key),
                })
            };
            if !exact_optional(
                "coldSkepticCount",
                &patch
                    .cold_skeptic_count
                    .map(|value| value.map(serde_json::Value::from)),
            ) || !exact_optional(
                "coldSkepticModel",
                &patch
                    .cold_skeptic_model
                    .clone()
                    .map(|value| value.map(serde_json::Value::from)),
            ) || !exact_optional(
                "maxVerificationAttempts",
                &patch
                    .max_verification_attempts
                    .map(|value| value.map(serde_json::Value::from)),
            ) {
                return Err(
                    "daemon goal-settings result does not match the requested patch".into(),
                );
            }
        }
    }
    Ok(())
}

pub(crate) enum AgentMutationSettlement {
    Committed(cockpit_core::daemon::proto::AgentMutationResult),
    Pending,
    Rejected(String),
}

enum AssistantMutationSettlement {
    Committed(cockpit_core::daemon::proto::Response),
    Pending,
    Rejected(String),
}

fn bind_assistant_mutation_settlement(
    response: cockpit_core::daemon::proto::Response,
    client_operation_id: &str,
    mutation_intent_hash: &str,
    operation_kind: &str,
) -> Result<AssistantMutationSettlement, String> {
    use cockpit_core::daemon::proto::Response;
    let receipt_matches = |response: &Response| match (operation_kind, response) {
        (
            "save_assistant_definition",
            Response::AssistantDefinitionSaved {
                client_operation_id: returned,
                mutation_intent_hash: returned_intent,
                ..
            },
        )
        | (
            "delete_assistant",
            Response::AssistantDeleted {
                client_operation_id: returned,
                mutation_intent_hash: returned_intent,
                ..
            },
        ) => returned == client_operation_id && returned_intent == mutation_intent_hash,
        _ => false,
    };
    if receipt_matches(&response) {
        return Ok(AssistantMutationSettlement::Committed(response));
    }
    match response {
        Response::LocalOperationSettlement {
            client_operation_id: returned,
            operation_kind: returned_kind,
            request_hash,
            pending,
            response,
            terminal_error,
            terminal_cancelled,
        } => {
            if returned != client_operation_id
                || returned_kind != operation_kind
                || !cockpit_proto::is_opaque_authority_token(&request_hash)
            {
                return Err("daemon returned an unbound assistant settlement".into());
            }
            let terminal_shapes = usize::from(pending)
                + usize::from(response.is_some())
                + usize::from(terminal_error.is_some())
                + usize::from(terminal_cancelled);
            if terminal_shapes != 1 {
                return Err("assistant settlement carried a contradictory terminal shape".into());
            }
            if pending {
                return Ok(AssistantMutationSettlement::Pending);
            }
            if terminal_cancelled {
                return Ok(AssistantMutationSettlement::Rejected(
                    "assistant mutation was durably cancelled".into(),
                ));
            }
            if let Some(error) = terminal_error {
                if error.message.trim().is_empty()
                    || error.message.len() > cockpit_proto::MAX_AGENT_METADATA_BYTES
                {
                    return Err("assistant settlement carried an invalid terminal error".into());
                }
                return Ok(AssistantMutationSettlement::Rejected(error.message));
            }
            let response = response.ok_or_else(|| {
                "assistant settlement omitted its exact terminal receipt".to_string()
            })?;
            if !receipt_matches(&response) {
                return Err("assistant settlement carried an unbound terminal receipt".into());
            }
            Ok(AssistantMutationSettlement::Committed(*response))
        }
        other => Err(format!("unexpected assistant mutation response: {other:?}")),
    }
}

/// Bind a direct or replayed response to one exact owner-generated agent
/// mutation. A transport error is handled by the caller by querying the local
/// operation ledger with the same operation id.
pub(crate) fn bind_agent_mutation_settlement(
    response: cockpit_core::daemon::proto::Response,
    client_operation_id: &str,
    mutation_intent_hash: &str,
) -> Result<AgentMutationSettlement, String> {
    use cockpit_core::daemon::proto::Response;
    match response {
        Response::AgentMutated(result) => {
            if result.client_operation_id != client_operation_id
                || result.mutation_intent_hash != mutation_intent_hash
            {
                return Err("daemon returned an unbound agent mutation receipt".into());
            }
            Ok(AgentMutationSettlement::Committed(result))
        }
        Response::LocalOperationSettlement {
            client_operation_id: returned_operation_id,
            operation_kind,
            request_hash,
            pending,
            response,
            terminal_error,
            terminal_cancelled,
        } => {
            if returned_operation_id != client_operation_id
                || operation_kind != "mutate_agent"
                || !cockpit_proto::is_opaque_authority_token(&request_hash)
            {
                return Err("daemon returned an unbound agent mutation settlement".into());
            }
            if pending {
                if response.is_some() || terminal_error.is_some() || terminal_cancelled {
                    return Err(
                        "pending agent mutation settlement carried a terminal result".into(),
                    );
                }
                return Ok(AgentMutationSettlement::Pending);
            }
            if terminal_cancelled {
                if response.is_some() || terminal_error.is_none() {
                    return Err("agent mutation cancellation was malformed".into());
                }
                return Ok(AgentMutationSettlement::Rejected(
                    "agent mutation was durably cancelled".into(),
                ));
            }
            if let Some(error) = terminal_error {
                if response.is_some() {
                    return Err("agent mutation rejection also carried a response".into());
                }
                if error.message.trim().is_empty() {
                    return Err("agent mutation rejection omitted its error".into());
                }
                return Ok(AgentMutationSettlement::Rejected(error.message));
            }
            if response.is_none() {
                return Err("agent mutation settlement was not exactly terminal".into());
            }
            match *response.expect("terminal response counted above") {
                Response::AgentMutated(result)
                    if result.client_operation_id == client_operation_id
                        && result.mutation_intent_hash == mutation_intent_hash =>
                {
                    Ok(AgentMutationSettlement::Committed(result))
                }
                _ => Err("agent mutation settlement carried an unbound terminal receipt".into()),
            }
        }
        other => Err(format!("unexpected agent mutation response: {other:?}")),
    }
}

/// Present the effective-model display value in canonical `provider/model`
/// slash form. A frontmatter `model:` is already authored in that form
/// (the live convention); we trim and drop blanks so an empty field reads
/// as "inherits the session model".
fn normalize_model(model: Option<String>) -> Option<String> {
    model
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty())
}

impl AgentDetail {
    fn toggle_selected_tool(&mut self) {
        if let ToolSurfaceEditOutcome::Ungranted(tool) =
            self.draft.toggle_selected_tool(&self.picker, false)
            && self.def.tool_descriptions.remove(&tool).is_some()
        {
            self.status = Some(format!("removed custom description for `{tool}`"));
        }
        if let Some(tool) = self.picker.selected_tool() {
            self.row_errors.remove(tool);
        }
    }

    fn cycle_selected_tier(&mut self) {
        self.draft.cycle_selected_tier(&self.picker);
        if let Some(tool) = self.picker.selected_tool() {
            self.row_errors.remove(tool);
        }
    }
}

impl SettingsCx {
    /// The cwd agents are discovered against: the picker's cwd when the
    /// dialog was opened from one, else the directory holding the config
    /// being edited, else the process cwd. Agents resolve through the
    /// layered-config walk rooted here.
    pub(super) fn agents_cwd(&self) -> PathBuf {
        if let Some(cwd) = &self.picker_cwd {
            return cwd.clone();
        }
        // `config_path` is `<dir>/.cockpit/config.json` or similar; walk
        // up past the `.cockpit/` segment to a plausible project cwd.
        self.config_path
            .parent()
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."))
    }

    /// The config directory eject writes into: the directory holding the
    /// `config.json` this settings dialog is editing (the `.cockpit/`
    /// layer the user selected in the picker).
    fn handle_agents_page_key(&mut self, key: KeyEvent, p: &mut AgentsPage) -> Nav {
        if p.uncertain_agent_operation.is_some() {
            if key.code == KeyCode::Enter {
                p.retry_uncertain_agent_operation(self);
            } else {
                p.status = Some(
                    "agent operation settlement is unresolved; press Enter to query/retry".into(),
                );
            }
            return Nav::Stay;
        }
        // ── In-TUI editor (vim or plain) ────────────────────────────
        if p.external_edit_confirmation.is_some() {
            match key.code {
                KeyCode::Enter => self.submit_agent_external_edit(p),
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                    p.external_edit_confirmation = None;
                    p.status = Some("external edit cancelled".into());
                }
                _ => {}
            }
            return Nav::Stay;
        }
        if let Some(editor) = p.editing.as_mut() {
            match editor.handle_key(key) {
                EditorOutcome::Stay => {}
                EditorOutcome::Save => {
                    let revision = editor.revision.clone();
                    let text = editor.text().to_string();
                    // Ensure a single trailing newline like a real editor.
                    let text = format!("{}\n", text.trim_end_matches('\n'));
                    let name = editor.name.clone();
                    let assistant_definition = editor.is_assistant_definition();
                    match revision {
                        Some(revision) if assistant_definition => {
                            if !p.has_authoritative_pair() {
                                p.status = Some(
                                    "assistant save requires a coherent daemon inventory refresh"
                                        .into(),
                                );
                                return Nav::Stay;
                            }
                            let canonical_project_root = p
                                .canonical_project_root
                                .clone()
                                .expect("authoritative pair has a canonical root");
                            let expected_config_generation = p
                                .authority_config_generation
                                .expect("authoritative pair has a configuration generation");
                            let cwd = self.agents_cwd();
                            let project_root = cwd.to_string_lossy().into_owned();
                            let client_operation_id = uuid::Uuid::new_v4().to_string();
                            let mutation_intent_hash =
                                cockpit_proto::assistant_mutation_intent_hash(
                                    &project_root,
                                    "save",
                                    &name,
                                    &revision,
                                    Some(&text),
                                );
                            p.stage(
                                self,
                                super::SettingsEffectTarget {
                                    surface: "agents.assistant-save",
                                    owner: name.clone(),
                                    revision: Some(revision.clone()),
                                },
                                cockpit_core::daemon::proto::Request::SaveAssistantDefinition {
                                    client_operation_id: client_operation_id.clone(),
                                    mutation_intent_hash: mutation_intent_hash.clone(),
                                    project_root,
                                    name: name.clone(),
                                    markdown: text.clone(),
                                    expected_revision: revision.clone(),
                                    expected_config_generation,
                                },
                                PendingAgentOperation::AssistantSave {
                                    client_operation_id,
                                    mutation_intent_hash,
                                    cwd,
                                    canonical_project_root,
                                    name,
                                    markdown: text,
                                    expected_revision: revision,
                                    expected_config_generation,
                                    purpose: SavePurpose::Editor,
                                    querying: false,
                                },
                            );
                        }
                        Some(revision) => {
                            let cwd = self.agents_cwd();
                            let mutation =
                                cockpit_core::daemon::proto::AgentMutation::SaveDefinition {
                                    name,
                                    markdown: text.clone(),
                                };
                            p.stage_mutation(
                                self,
                                cwd,
                                mutation,
                                revision,
                                MutationPurpose::SaveEditor { markdown: text },
                            );
                        }
                        None => p.status = Some(
                            "agent definition has no daemon-owned revision; reload before saving"
                                .to_string(),
                        ),
                    }
                    p.status
                        .get_or_insert_with(|| "saving agent definition…".into());
                }
                EditorOutcome::ExternalEdit => {
                    if editor.is_assistant_definition() {
                        p.status = Some(
                            "external editing is unavailable for assistant definitions; use the in-TUI editor"
                                .into(),
                        );
                    } else if std::env::var_os("EDITOR").is_none() {
                        p.status = Some("No $EDITOR environment variable".into());
                    } else {
                        p.external_edit_confirmation = Some(editor.authority_id.clone());
                        p.status = Some(format!("Open agent {} in $EDITOR?", editor.name));
                    }
                }
                EditorOutcome::Cancel => {
                    p.editing = None;
                    p.status = Some("edit cancelled".into());
                }
            }
            return Nav::Stay;
        }

        if p.detail.is_some() {
            return self.handle_agent_detail_key(key, p);
        }

        // ── Reset-all confirmation ──────────────────────────────────
        if p.confirm_reset {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    p.confirm_reset = false;
                    let cwd = self.agents_cwd();
                    // Reset-all authority is the exact inventory generation
                    // currently rendered. Refresh first if either half of the
                    // inventory load is still outstanding.
                    if p.pending_daemon.values().any(|pending| {
                        matches!(
                            pending,
                            PendingAgentOperation::Inventory { .. }
                                | PendingAgentOperation::Assistants { .. }
                        )
                    }) {
                        p.status = Some("agent inventory is still loading".into());
                    } else if let Some(revision) = p.inventory_revision.clone() {
                        p.stage_mutation(
                            self,
                            cwd,
                            cockpit_core::daemon::proto::AgentMutation::ResetAllBuiltins,
                            revision,
                            MutationPurpose::ResetAll,
                        );
                        p.status = Some("resetting all built-in overrides…".into());
                    } else {
                        p.queue_load(self);
                        p.status = Some(
                            "refreshing reset-all authority; confirm again when loaded".into(),
                        );
                    }
                }
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                    p.confirm_reset = false;
                    p.status = Some("reset cancelled".into());
                }
                _ => {}
            }
            return Nav::Stay;
        }

        let len = p.rows.len();
        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => {
                return Nav::Back;
            }
            KeyCode::Up | KeyCode::Char('k') if len > 0 => {
                p.disarm_guards();
                p.cursor = crate::tui::nav::wrap_prev(p.cursor, len);
                p.status = None;
            }
            KeyCode::Down | KeyCode::Char('j') if len > 0 => {
                p.disarm_guards();
                p.cursor = crate::tui::nav::wrap_next(p.cursor, len);
                p.status = None;
            }
            KeyCode::Char('R') => {
                p.disarm_guards();
                p.confirm_reset = true;
                p.status = None;
            }
            KeyCode::Char('d') => self.delete_selected(p),
            KeyCode::Char('r') => self.reset_one_selected(p),
            KeyCode::Char('e') => {
                p.disarm_guards();
                self.edit_selected(p);
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                p.disarm_guards();
                self.open_detail_selected(p);
            }
            _ => {}
        }
        Nav::Stay
    }

    /// Submit the confirmed raw-editor handoff exactly once. The event loop
    /// drains this request as an injected effect and returns the same id.
    fn submit_agent_external_edit(&mut self, p: &mut AgentsPage) {
        let Some(expected) = p.external_edit_confirmation.take() else {
            return;
        };
        let Some(editor) = p.editing.as_ref() else {
            return;
        };
        if editor.is_assistant_definition() {
            p.status = Some(
                "external editing is unavailable for assistant definitions; use the in-TUI editor"
                    .into(),
            );
            return;
        }
        if expected != editor.authority_id.clone() || p.pending_external_edit.is_some() {
            return;
        }
        let Some(revision) = editor.revision.clone() else {
            p.status = Some("external editing is unavailable for assistant definitions".into());
            return;
        };
        let cwd = self.agents_cwd();
        let name = editor.name.clone();
        let draft = p.editing.take().expect("editor checked above");
        let client_operation_id = uuid::Uuid::new_v4().to_string();
        p.stage(
            self,
            super::SettingsEffectTarget {
                surface: "agents.editor-lease-begin",
                owner: format!("{}::{name}", cwd.display()),
                revision: Some(revision.clone()),
            },
            cockpit_core::daemon::proto::Request::BeginAgentEditorLease {
                client_operation_id: client_operation_id.clone(),
                project_root: cwd.to_string_lossy().into_owned(),
                name: name.clone(),
                expected_revision: revision.clone(),
            },
            PendingAgentOperation::BeginLease {
                client_operation_id,
                cwd,
                name,
                expected_revision: revision,
                authority_id: expected,
                draft,
            },
        );
        p.status = Some("requesting external editor lease…".into());
    }

    fn handle_agent_detail_key(&mut self, key: KeyEvent, p: &mut AgentsPage) -> Nav {
        let Some(detail) = p.detail.as_mut() else {
            return Nav::Stay;
        };
        let len = cockpit_core::agents::tool_surface_catalog().len();
        match key.code {
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => {
                p.status = detail.status.clone();
                p.detail = None;
            }
            KeyCode::Up | KeyCode::Char('k') if len > 0 => {
                detail.picker.move_prev();
            }
            KeyCode::Down | KeyCode::Char('j') if len > 0 => {
                detail.picker.move_next();
            }
            KeyCode::Char(' ') => {
                detail.toggle_selected_tool();
            }
            KeyCode::Char('t') => {
                detail.cycle_selected_tier();
            }
            KeyCode::Char('s')
                if key
                    .modifiers
                    .contains(crossterm::event::KeyModifiers::CONTROL) =>
            {
                self.save_agent_detail(p);
            }
            KeyCode::Char('e') => {
                let name = detail.name.clone();
                let text = detail.original_text.clone();
                let revision = detail.revision.clone();
                let assistant_definition =
                    matches!(&detail.source, AgentRowSource::Assistant { .. });
                p.detail = None;
                let vim = self.extended.tui.vim_mode.vim_enabled();
                p.editing = match (assistant_definition, revision) {
                    (true, Some(revision)) => {
                        Some(AgentEditor::new_assistant(name, &text, vim, revision))
                    }
                    (false, revision) => Some(AgentEditor::new(name, &text, vim, revision)),
                    (true, None) => {
                        p.status = Some("raw edit failed: missing assistant revision".into());
                        None
                    }
                };
            }
            _ => {}
        }
        Nav::Stay
    }

    fn open_detail_selected(&mut self, p: &mut AgentsPage) {
        let Some(row) = p.rows.get(p.cursor) else {
            return;
        };
        if let Err(error) = &row.detail {
            p.status = Some(
                if matches!(&row.source, AgentRowSource::AssistantUnavailable { .. }) {
                    match &row.source {
                        AgentRowSource::AssistantUnavailable {
                            registration_revision,
                        } if !registration_revision.is_empty() => format!(
                            "assistant `{}` is unavailable and cannot be edited; it can still be unregistered with d: {error}",
                            row.name
                        ),
                        _ => format!(
                            "assistant `{}` is unavailable and cannot be edited or unregistered because its registry revision is missing: {error}",
                            row.name
                        ),
                    }
                } else {
                    format!(
                        "`{}` has a parse error; use the raw editor to repair it: {error}",
                        row.name
                    )
                },
            );
            return;
        }
        let name = row.name.clone();
        let source = row.source.clone();
        let cwd = self.agents_cwd();
        let (path, original_text, revision) = match &source {
            AgentRowSource::Agent { revision, .. } => {
                let rendered_identity = row_agent_id(&name, &source);
                p.stage(
                    self,
                    super::SettingsEffectTarget {
                        surface: "agents.snapshot",
                        owner: format!("{}::{name}", cwd.display()),
                        revision: Some(revision.clone()),
                    },
                    cockpit_core::daemon::proto::Request::GetAgentEditSnapshot {
                        project_root: cwd.to_string_lossy().into_owned(),
                        name: name.clone(),
                    },
                    PendingAgentOperation::Snapshot {
                        cwd,
                        name,
                        rendered_identity,
                        authority_revision: revision.clone(),
                        purpose: SnapshotPurpose::OpenDetail,
                    },
                );
                p.status = Some("loading agent definition…".into());
                return;
            }
            AgentRowSource::Assistant {
                markdown, revision, ..
            } => (markdown.clone(), Some(revision.clone())),
            AgentRowSource::AssistantUnavailable { .. } => {
                p.status = Some("assistant definition is unavailable; run cockpit doctor".into());
                return;
            }
        };
        let load_result = match &source {
            AgentRowSource::Agent { .. } => unreachable!("workspace agent staged above"),
            AgentRowSource::Assistant { .. } => {
                cockpit_core::agents::parse_daemon_local_markdown(&original_text, &name)
            }
            AgentRowSource::AssistantUnavailable { .. } => unreachable!("handled above"),
        };
        let def = match load_result {
            Ok(def) => def,
            Err(e) => {
                p.status = Some(format!("structured editor unavailable for `{name}`: {e}"));
                return;
            }
        };
        if def.vnext.is_some() {
            p.status = Some(format!(
                "structured tool editing is unavailable for `{name}`: schemaVersion 2 tool authority is host-owned; edit only declarative definition fields in the raw editor"
            ));
            return;
        }
        let selected_id = row_agent_id(&name, &source);
        if let Some(idx) = p
            .rows
            .iter()
            .position(|row| row_agent_id(&row.name, &row.source) == selected_id)
        {
            p.cursor = idx;
        }
        let draft = ToolSurfaceDraft::from_def(&def);
        p.detail = Some(AgentDetail {
            name,
            original_text,
            revision,
            def,
            draft: Box::new(draft),
            picker: ToolSurfacePicker::default(),
            status: None,
            row_errors: BTreeMap::new(),
            source,
        });
        p.status = None;
    }

    fn save_agent_detail(&mut self, p: &mut AgentsPage) {
        let Some(detail) = p.detail.as_mut() else {
            return;
        };
        detail.row_errors.clear();
        if detail.revision.is_none() {
            detail.status = Some("save failed: missing daemon-owned revision".into());
            return;
        }
        detail.draft.write_to_def(&mut detail.def);
        let cleanup_notice = detail
            .status
            .clone()
            .filter(|status| status.starts_with("removed custom description"));
        let markdown = match detail.def.to_markdown() {
            Ok(markdown) => markdown,
            Err(e) => {
                detail.status = Some(format!("serialize failed: {e}"));
                return;
            }
        };
        let name = detail.name.clone();
        let source = detail.source.clone();
        if let AgentRowSource::Assistant { .. } = &source {
            if !p.has_authoritative_pair() {
                p.status =
                    Some("assistant save requires a coherent daemon inventory refresh".into());
                return;
            }
            let canonical_project_root = p
                .canonical_project_root
                .clone()
                .expect("authoritative pair has a canonical root");
            let expected_config_generation = p
                .authority_config_generation
                .expect("authoritative pair has a configuration generation");
            let Some(expected_revision) = detail.revision.clone() else {
                detail.status = Some("save failed: missing assistant revision".into());
                return;
            };
            let cwd = self.agents_cwd();
            let project_root = cwd.to_string_lossy().into_owned();
            let client_operation_id = uuid::Uuid::new_v4().to_string();
            let mutation_intent_hash = cockpit_proto::assistant_mutation_intent_hash(
                &project_root,
                "save",
                &name,
                &expected_revision,
                Some(&markdown),
            );
            p.stage(
                self,
                super::SettingsEffectTarget {
                    surface: "agents.assistant-save",
                    owner: name.clone(),
                    revision: Some(expected_revision.clone()),
                },
                cockpit_core::daemon::proto::Request::SaveAssistantDefinition {
                    client_operation_id: client_operation_id.clone(),
                    mutation_intent_hash: mutation_intent_hash.clone(),
                    project_root,
                    name: name.clone(),
                    markdown: markdown.clone(),
                    expected_revision: expected_revision.clone(),
                    expected_config_generation,
                },
                PendingAgentOperation::AssistantSave {
                    client_operation_id,
                    mutation_intent_hash,
                    cwd,
                    canonical_project_root,
                    name,
                    markdown,
                    expected_revision,
                    expected_config_generation,
                    purpose: SavePurpose::Detail,
                    querying: false,
                },
            );
        } else if let Some(revision) = detail.revision.clone() {
            let cwd = self.agents_cwd();
            let mutation = cockpit_core::daemon::proto::AgentMutation::SaveDefinition {
                name,
                markdown: markdown.clone(),
            };
            p.stage_mutation(
                self,
                cwd,
                mutation,
                revision,
                MutationPurpose::SaveDetail {
                    markdown,
                    cleanup_notice,
                },
            );
        } else {
            detail.status = Some("save failed: missing daemon agent revision".into());
            return;
        }
        if let Some(detail) = p.detail.as_mut() {
            detail.status = Some("saving agent definition…".into());
        }
    }

    /// Begin editing the highlighted agent. A non-overridden built-in is
    /// auto-ejected first so there's always a concrete on-disk file. The
    /// editor is then chosen by precedence: `$EDITOR` (external — deferred
    /// to the event loop) → in-TUI vim (vim mode on) → in-TUI plain.
    fn edit_selected(&mut self, p: &mut AgentsPage) {
        let Some(row) = p.rows.get(p.cursor) else {
            return;
        };
        let name = row.name.clone();
        match &row.source {
            AgentRowSource::Assistant {
                markdown, revision, ..
            } => {
                let authority_id = row_agent_id(&name, &row.source);
                p.editing = Some(
                    AgentEditor::new_assistant(
                        name,
                        markdown,
                        self.extended.tui.vim_mode.vim_enabled(),
                        revision.clone(),
                    )
                    .with_authority_id(authority_id),
                );
                p.status = None;
                return;
            }
            AgentRowSource::AssistantUnavailable { .. } => {
                p.status = Some(
                    "assistant definition is unavailable; editing requires a valid daemon revision"
                        .into(),
                );
                return;
            }
            AgentRowSource::Agent { .. } => {}
        }
        let cwd = self.agents_cwd();
        let AgentRowSource::Agent { revision, .. } = &row.source else {
            unreachable!("assistant handled above")
        };
        let revision = revision.clone();
        let rendered_identity = row_agent_id(&name, &row.source);
        p.stage(
            self,
            super::SettingsEffectTarget {
                surface: "agents.snapshot",
                owner: format!("{}::{name}", cwd.display()),
                revision: Some(revision.clone()),
            },
            cockpit_core::daemon::proto::Request::GetAgentEditSnapshot {
                project_root: cwd.to_string_lossy().into_owned(),
                name: name.clone(),
            },
            PendingAgentOperation::Snapshot {
                cwd,
                name,
                rendered_identity,
                authority_revision: revision,
                purpose: SnapshotPurpose::Edit {
                    external: std::env::var_os("EDITOR").is_some(),
                },
            },
        );
        p.status = Some("loading agent definition…".into());
    }

    /// Pointer raw-edit always enters the in-TUI raw editor first so the
    /// separately named `$EDITOR` control can enforce its confirmation.
    fn edit_selected_in_tui(&mut self, p: &mut AgentsPage) {
        let Some(row) = p.rows.get(p.cursor) else {
            return;
        };
        let name = row.name.clone();
        match &row.source {
            AgentRowSource::Assistant {
                markdown, revision, ..
            } => {
                let authority_id = row_agent_id(&name, &row.source);
                p.editing = Some(
                    AgentEditor::new_assistant(
                        name,
                        markdown,
                        self.extended.tui.vim_mode.vim_enabled(),
                        revision.clone(),
                    )
                    .with_authority_id(authority_id),
                );
                p.status = None;
                return;
            }
            AgentRowSource::AssistantUnavailable { .. } => {
                p.status = Some(
                    "assistant definition is unavailable; editing requires a valid daemon revision"
                        .into(),
                );
                return;
            }
            AgentRowSource::Agent { .. } => {}
        }
        let cwd = self.agents_cwd();
        let AgentRowSource::Agent { revision, .. } = &row.source else {
            unreachable!("assistant handled above")
        };
        let revision = revision.clone();
        let rendered_identity = row_agent_id(&name, &row.source);
        p.stage(
            self,
            super::SettingsEffectTarget {
                surface: "agents.snapshot",
                owner: format!("{}::{name}", cwd.display()),
                revision: Some(revision.clone()),
            },
            cockpit_core::daemon::proto::Request::GetAgentEditSnapshot {
                project_root: cwd.to_string_lossy().into_owned(),
                name: name.clone(),
            },
            PendingAgentOperation::Snapshot {
                cwd,
                name,
                rendered_identity,
                authority_revision: revision,
                purpose: SnapshotPurpose::Edit { external: false },
            },
        );
        p.status = Some("loading agent definition…".into());
    }

    /// Delete the highlighted **custom** agent (arm→confirm). Built-ins are
    /// never deletable — for an overridden one the destructive action is
    /// per-agent reset (`r`), and a pristine built-in offers neither.
    fn delete_selected(&mut self, p: &mut AgentsPage) {
        p.reset_one.disarm();
        let Some(row) = p.rows.get(p.cursor) else {
            return;
        };
        if !matches!(row.kind, AgentKind::Custom) {
            p.status = Some("built-in agents cannot be deleted (use r/R to reset)".into());
            return;
        }
        let name = row.name.clone();
        if p.delete.activate() == ResetOutcome::Armed {
            p.status = Some(format!("delete `{name}`? press d again to confirm"));
            return;
        }
        let cwd = self.agents_cwd();
        match &row.source {
            AgentRowSource::Assistant {
                registration_revision,
                ..
            }
            | AgentRowSource::AssistantUnavailable {
                registration_revision,
            } if registration_revision.is_empty() => {
                p.status = Some(
                    "assistant cannot be unregistered because its registry revision is missing"
                        .into(),
                );
            }
            AgentRowSource::Assistant {
                registration_revision,
                ..
            }
            | AgentRowSource::AssistantUnavailable {
                registration_revision,
            } => {
                if !p.has_authoritative_pair() {
                    p.status = Some(
                        "assistant delete requires a coherent daemon inventory refresh".into(),
                    );
                    return;
                }
                let canonical_project_root = p
                    .canonical_project_root
                    .clone()
                    .expect("authoritative pair has a canonical root");
                let expected_config_generation = p
                    .authority_config_generation
                    .expect("authoritative pair has a configuration generation");
                let project_root = cwd.to_string_lossy().into_owned();
                let client_operation_id = uuid::Uuid::new_v4().to_string();
                let mutation_intent_hash = cockpit_proto::assistant_mutation_intent_hash(
                    &project_root,
                    "delete",
                    &name,
                    registration_revision,
                    None,
                );
                p.stage(
                    self,
                    super::SettingsEffectTarget {
                        surface: "agents.assistant-delete",
                        owner: name.clone(),
                        revision: Some(registration_revision.clone()),
                    },
                    cockpit_core::daemon::proto::Request::DeleteAssistant {
                        client_operation_id: client_operation_id.clone(),
                        mutation_intent_hash: mutation_intent_hash.clone(),
                        project_root,
                        name: name.clone(),
                        expected_revision: registration_revision.clone(),
                        expected_config_generation,
                    },
                    PendingAgentOperation::AssistantDelete {
                        client_operation_id,
                        mutation_intent_hash,
                        cwd,
                        canonical_project_root,
                        name,
                        expected_registration_revision: registration_revision.clone(),
                        expected_config_generation,
                        querying: false,
                    },
                );
            }
            AgentRowSource::Agent { revision, .. } => {
                let rendered_identity = row_agent_id(&name, &row.source);
                let revision = revision.clone();
                p.stage(
                    self,
                    super::SettingsEffectTarget {
                        surface: "agents.snapshot",
                        owner: format!("{}::{name}", cwd.display()),
                        revision: Some(revision.clone()),
                    },
                    cockpit_core::daemon::proto::Request::GetAgentEditSnapshot {
                        project_root: cwd.to_string_lossy().into_owned(),
                        name: name.clone(),
                    },
                    PendingAgentOperation::Snapshot {
                        cwd,
                        name,
                        rendered_identity,
                        authority_revision: revision,
                        purpose: SnapshotPurpose::DeleteCustom,
                    },
                );
            }
        }
        p.status.get_or_insert_with(|| "deleting agent…".into());
    }

    /// Reset the highlighted **overridden built-in** to its embedded
    /// default (arm→confirm), deleting just that one override file. A
    /// custom agent or pristine built-in offers nothing here.
    fn reset_one_selected(&mut self, p: &mut AgentsPage) {
        p.delete.disarm();
        let Some(row) = p.rows.get(p.cursor) else {
            return;
        };
        let AgentKind::Builtin { overridden: true } = row.kind else {
            p.status = Some("only an overridden built-in can be reset".into());
            return;
        };
        let name = row.name.clone();
        if p.reset_one.activate() == ResetOutcome::Armed {
            p.status = Some(format!(
                "reset `{name}` to default? press r again to confirm"
            ));
            return;
        }
        let cwd = self.agents_cwd();
        let rendered_identity = row_agent_id(&name, &row.source);
        let AgentRowSource::Agent { revision, .. } = &row.source else {
            p.status = Some("assistant rows cannot be reset as built-ins".into());
            return;
        };
        let revision = revision.clone();
        p.stage(
            self,
            super::SettingsEffectTarget {
                surface: "agents.snapshot",
                owner: format!("{}::{name}", cwd.display()),
                revision: Some(revision.clone()),
            },
            cockpit_core::daemon::proto::Request::GetAgentEditSnapshot {
                project_root: cwd.to_string_lossy().into_owned(),
                name: name.clone(),
            },
            PendingAgentOperation::Snapshot {
                cwd,
                name,
                rendered_identity,
                authority_revision: revision,
                purpose: SnapshotPurpose::ResetBuiltin,
            },
        );
        p.status = Some("resetting built-in agent…".into());
    }

    pub(super) fn render_agents_page(&self, frame: &mut Frame, area: Rect, p: &AgentsPage) {
        p.editor_body.set(None);
        // The in-TUI editor takes the whole page area when open.
        if let Some(editor) = &p.editing {
            editor.render(frame, area);
            let action_y = area.bottom().saturating_sub(1);
            let agent = editor.authority_id.clone();
            let confirming = p.external_edit_confirmation.as_ref() == Some(&agent);
            if !confirming && area.width > 4 && area.height > 3 {
                let editor_body = Rect::new(
                    area.x.saturating_add(2),
                    area.y.saturating_add(1),
                    area.width.saturating_sub(4),
                    area.height.saturating_sub(3),
                );
                p.editor_body.set(Some(editor_body));
                self.pointer_surface
                    .register(super::shell::SettingsPointerTarget {
                        rect: editor_body,
                        action: super::shell::SettingsPointerAction::Page(
                            super::pointer_actions::SettingsPointerAction::Agents(
                                super::pointer_actions::AgentsAction::EditText(agent.clone()),
                            ),
                        ),
                        enabled: true,
                        disabled_reason: None,
                    });
            }
            let assistant_editor = editor.is_assistant_definition();
            let actions = if confirming && !assistant_editor {
                vec![
                    (
                        super::pointer_actions::AgentsAction::ExternalEditBegin(agent.clone()),
                        0,
                        17,
                    ),
                    (
                        super::pointer_actions::AgentsAction::Cancel(agent.clone()),
                        19,
                        8,
                    ),
                ]
            } else if assistant_editor {
                vec![
                    (
                        super::pointer_actions::AgentsAction::Save(agent.clone()),
                        0,
                        6u16,
                    ),
                    (
                        super::pointer_actions::AgentsAction::Cancel(agent.clone()),
                        8u16,
                        8u16,
                    ),
                ]
            } else {
                vec![
                    (
                        super::pointer_actions::AgentsAction::Save(agent.clone()),
                        0,
                        6u16,
                    ),
                    (
                        super::pointer_actions::AgentsAction::Cancel(agent.clone()),
                        8u16,
                        8u16,
                    ),
                    (
                        super::pointer_actions::AgentsAction::ExternalEditBegin(agent.clone()),
                        18u16,
                        17u16,
                    ),
                ]
            };
            for (action, x, width) in actions {
                if x.saturating_add(width) > area.width {
                    continue;
                }
                self.pointer_surface
                    .register(super::shell::SettingsPointerTarget {
                        rect: Rect::new(area.x + x, action_y, width, 1),
                        action: super::shell::SettingsPointerAction::Page(
                            super::pointer_actions::SettingsPointerAction::Agents(action),
                        ),
                        enabled: true,
                        disabled_reason: None,
                    });
            }
            frame.render_widget(
                if confirming && !assistant_editor {
                    Line::from("[Open in $EDITOR]  [Cancel]")
                } else if assistant_editor {
                    Line::from("[Save]  [Cancel]")
                } else {
                    Line::from("[Save]  [Cancel]  [Open in $EDITOR]")
                },
                Rect::new(area.x, action_y, area.width, 1),
            );
            return;
        }
        if let Some(detail) = &p.detail {
            let action_y = area.bottom().saturating_sub(1);
            let detail_area = Rect::new(area.x, area.y, area.width, area.height.saturating_sub(1));
            self.render_agent_detail(frame, detail_area, detail);
            let agent = row_agent_id(&detail.name, &detail.source);
            for (action, x, width) in [
                (
                    super::pointer_actions::AgentsAction::OpenRawEditor(agent.clone()),
                    0,
                    15,
                ),
                (
                    super::pointer_actions::AgentsAction::Save(agent.clone()),
                    17,
                    6,
                ),
            ] {
                self.pointer_surface
                    .register(super::shell::SettingsPointerTarget {
                        rect: Rect::new(
                            area.x + x,
                            action_y,
                            width.min(area.width.saturating_sub(x)),
                            1,
                        ),
                        action: super::shell::SettingsPointerAction::Page(
                            super::pointer_actions::SettingsPointerAction::Agents(action),
                        ),
                        enabled: x < area.width,
                        disabled_reason: (x >= area.width).then_some("control is clipped"),
                    });
            }
            frame.render_widget(
                Line::from("[Edit raw file]  [Save]"),
                Rect::new(area.x, action_y, area.width, 1),
            );
            return;
        }

        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let yellow = Style::default().fg(Color::Yellow);
        let red = Style::default().fg(Color::Red);
        let cyan = Style::default().fg(Color::Cyan);

        let mut lines: Vec<Line<'static>> = vec![
            Line::from(Span::styled(
                "Agents".to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::default(),
        ];
        let mut controls = vec![None; lines.len()];
        push_wrapped_text(
            &mut lines,
            area.width,
            "Enter opens a structured tool editor; e edits a daemon snapshot. \
             Workspace agents can use $EDITOR through a private, securely seeded leased staging file; its edited bytes are committed by the daemon. Assistants use the in-TUI editor. Editing a built-in ejects its default first. The model is \
             the `model:` frontmatter field (provider/model). Delete uses the source-specific daemon authority; reset reverts an overridden built-in.",
            muted,
        );
        controls.resize(lines.len(), None);
        lines.push(Line::default());
        controls.push(None);

        let mut selected_action_line = None;
        for (i, row) in p.rows.iter().enumerate() {
            let on_cursor = i == p.cursor;
            let marker = if on_cursor { "▸ " } else { "  " };
            let name_style = if on_cursor {
                yellow.add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let tag = match row.kind {
                AgentKind::Builtin { overridden: true } => " (built-in, overridden)",
                AgentKind::Builtin { overridden: false } => " (built-in)",
                AgentKind::Custom
                    if matches!(
                        &row.source,
                        AgentRowSource::Assistant { .. }
                            | AgentRowSource::AssistantUnavailable { .. }
                    ) =>
                {
                    " (assistant)"
                }
                AgentKind::Custom => " (custom)",
            };
            let model_label = match &row.model {
                Some(m) => m.clone(),
                None => "session default".to_string(),
            };
            let mut spans = vec![
                Span::raw(marker),
                Span::styled(row.name.clone(), name_style),
                Span::styled(tag.to_string(), muted),
                Span::raw("  "),
                Span::styled(format!("model: {model_label}"), cyan),
            ];
            if let Err(e) = &row.detail {
                spans.push(Span::styled(format!("  ⚠ {e}"), red));
            }
            lines.push(Line::from(spans));
            let id = row_agent_id(&row.name, &row.source);
            let open = super::pointer_actions::SettingsPointerAction::Agents(
                super::pointer_actions::AgentsAction::Open(id.clone()),
            );
            controls.push(Some((open.clone(), true, None)));
            if let Ok(desc) = &row.detail {
                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(desc.clone(), muted),
                ]));
                controls.push(Some((open, true, None)));
            }
            if on_cursor && !p.confirm_reset && !p.delete.is_pending() && !p.reset_one.is_pending()
            {
                lines.push(Line::from("[Open]"));
                controls.push(Some((
                    super::pointer_actions::SettingsPointerAction::Agents(
                        super::pointer_actions::AgentsAction::Open(id.clone()),
                    ),
                    true,
                    None,
                )));
                if !matches!(&row.source, AgentRowSource::AssistantUnavailable { .. }) {
                    let label = if matches!(&row.source, AgentRowSource::Assistant { .. }) {
                        "[Edit definition]"
                    } else {
                        "[Edit raw file]"
                    };
                    lines.push(Line::from(label));
                    controls.push(Some((
                        super::pointer_actions::SettingsPointerAction::Agents(
                            super::pointer_actions::AgentsAction::Edit(id.clone()),
                        ),
                        true,
                        None,
                    )));
                    selected_action_line = Some(lines.len() - 1);
                }
                let row_action = match (&row.source, &row.kind) {
                    (AgentRowSource::Assistant { .. }, _) => Some((
                        "[Unregister]",
                        super::pointer_actions::AgentsAction::Delete(id.clone()),
                    )),
                    (
                        AgentRowSource::AssistantUnavailable {
                            registration_revision,
                        },
                        _,
                    ) if !registration_revision.is_empty() => Some((
                        "[Unregister]",
                        super::pointer_actions::AgentsAction::Delete(id.clone()),
                    )),
                    (AgentRowSource::AssistantUnavailable { .. }, _) => None,
                    (AgentRowSource::Agent { .. }, AgentKind::Custom) => Some((
                        "[Delete]",
                        super::pointer_actions::AgentsAction::Delete(id.clone()),
                    )),
                    (AgentRowSource::Agent { .. }, AgentKind::Builtin { overridden: true }) => {
                        Some(("[Reset]", super::pointer_actions::AgentsAction::Reset(id)))
                    }
                    (AgentRowSource::Agent { .. }, AgentKind::Builtin { overridden: false }) => {
                        None
                    }
                };
                if let Some((label, action)) = row_action {
                    lines.push(Line::from(label));
                    controls.push(Some((
                        super::pointer_actions::SettingsPointerAction::Agents(action),
                        true,
                        None,
                    )));
                }
                lines.push(Line::from("[Reset all]"));
                controls.push(Some((
                    super::pointer_actions::SettingsPointerAction::Agents(
                        super::pointer_actions::AgentsAction::ResetAll,
                    ),
                    true,
                    None,
                )));
            }
        }

        if p.confirm_reset {
            lines.push(Line::default());
            controls.push(None);
            lines.push(Line::from(Span::styled(
                "Reset ALL built-in agents to default? This deletes their \
                 on-disk overrides (custom agents are kept).  y: confirm  n: cancel"
                    .to_string(),
                red.add_modifier(Modifier::BOLD),
            )));
            controls.push(None);
            lines.push(Line::from("[Reset]"));
            controls.push(Some((
                super::pointer_actions::SettingsPointerAction::Agents(
                    super::pointer_actions::AgentsAction::ResetAll,
                ),
                true,
                None,
            )));
            selected_action_line = Some(lines.len() - 1);
            lines.push(Line::from("[Cancel]"));
            controls.push(Some((
                super::pointer_actions::SettingsPointerAction::Agents(
                    super::pointer_actions::AgentsAction::Cancel(
                        super::pointer_actions::AgentId::reset_all(),
                    ),
                ),
                true,
                None,
            )));
        } else if p.delete.is_pending() || p.reset_one.is_pending() {
            let verb = if p.delete.is_pending() {
                "Delete"
            } else {
                "Reset"
            };
            let selected_row = p.rows.get(p.cursor);
            let name = selected_row.map_or("agent", |row| row.name.as_str());
            lines.push(Line::default());
            controls.push(None);
            lines.push(Line::from(format!("{verb} {name}?")));
            controls.push(None);
            lines.push(Line::from(format!("[{verb}]")));
            let id = selected_row.map_or_else(
                || super::pointer_actions::AgentId::workspace(name),
                |row| row_agent_id(&row.name, &row.source),
            );
            let action = if p.delete.is_pending() {
                super::pointer_actions::AgentsAction::Delete(id.clone())
            } else {
                super::pointer_actions::AgentsAction::Reset(id.clone())
            };
            controls.push(Some((
                super::pointer_actions::SettingsPointerAction::Agents(action),
                true,
                None,
            )));
            selected_action_line = Some(lines.len() - 1);
            lines.push(Line::from("[Cancel]"));
            controls.push(Some((
                super::pointer_actions::SettingsPointerAction::Agents(
                    super::pointer_actions::AgentsAction::Cancel(id),
                ),
                true,
                None,
            )));
        }

        if let Some(status) = &p.status {
            lines.push(Line::default());
            controls.push(None);
            lines.push(Line::from(Span::styled(status.clone(), yellow)));
            controls.push(None);
        }

        let selected_line = selected_action_line.or_else(|| selected_line_from_marker(&lines));
        self.scroll_states.render_control_lines(
            frame,
            area,
            "agents",
            (lines, selected_line),
            controls,
            (&self.pointer_surface, SettingsScrollRegionId("agents:list")).into(),
        );
    }

    fn render_agent_detail(&self, frame: &mut Frame, area: Rect, detail: &AgentDetail) {
        let (lines, selected_line, semantic_rows) = tool_surface_lines(
            &detail.picker,
            &detail.draft,
            ToolSurfaceRender {
                title: &detail.name,
                subtitle: "tool surface",
                status: detail.status.as_deref(),
                row_errors: &detail.row_errors,
                block_safety_ungrant: false,
            },
        );
        self.scroll_states.render_bound_lines(
            frame,
            area,
            "agent-detail",
            (lines, selected_line),
            semantic_rows
                .iter()
                .filter(|(_, _, enabled)| *enabled)
                .map(|(line, index, _)| {
                    (
                        *line,
                        super::pointer_actions::SettingsPointerAction::Agents(
                            super::pointer_actions::AgentsAction::ToggleTool(
                                row_agent_id(&detail.name, &detail.source),
                                super::pointer_actions::AgentToolId(
                                    cockpit_core::agents::tool_surface_catalog()[*index]
                                        .name
                                        .into(),
                                ),
                            ),
                        ),
                    )
                }),
            (
                &self.pointer_surface,
                SettingsScrollRegionId("agents:detail"),
            )
                .into(),
        );
        let offset = self.scroll_states.offset_for("agent-detail");
        let tier_width = area.width.min(12);
        for (line, index, enabled) in semantic_rows {
            let Some(screen_row) = line.checked_sub(offset) else {
                continue;
            };
            if !enabled || screen_row >= usize::from(area.height) || tier_width == 0 {
                continue;
            }
            let tool = cockpit_core::agents::tool_surface_catalog()[index].name;
            self.pointer_surface
                .register(super::shell::SettingsPointerTarget {
                    rect: Rect::new(
                        area.right().saturating_sub(tier_width),
                        area.y.saturating_add(screen_row as u16),
                        tier_width,
                        1,
                    ),
                    action: super::shell::SettingsPointerAction::Page(
                        super::pointer_actions::SettingsPointerAction::Agents(
                            super::pointer_actions::AgentsAction::CycleTier(
                                row_agent_id(&detail.name, &detail.source),
                                super::pointer_actions::AgentToolId(tool.into()),
                            ),
                        ),
                    ),
                    enabled: true,
                    disabled_reason: None,
                });
        }
    }
}

impl SettingsPage for AgentsPage {
    fn pointer_surface_kind(&self) -> super::SettingsPointerSurfaceKind {
        super::SettingsPointerSurfaceKind::Agents
    }

    fn pointer_surface_token(&self) -> u64 {
        if self.editing.is_some() {
            402
        } else if self.detail.is_some() {
            401
        } else {
            400
        }
    }

    fn resolve_header_back(&self) -> super::SettingsLocalBack {
        if self.editing.is_some() || self.detail.is_some() {
            super::SettingsLocalBack::LocalBack
        } else {
            super::SettingsLocalBack::NoLocalBack
        }
    }

    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        cx.handle_agents_page_key(key, self)
    }

    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        cx.render_agents_page(frame, area, self);
    }

    fn handle_pointer_control(
        &mut self,
        cx: &mut SettingsCx,
        action: super::pointer_actions::SettingsPointerAction,
    ) -> Nav {
        let super::pointer_actions::SettingsPointerAction::Agents(action) = action else {
            return Nav::Stay;
        };
        if self.editing.is_some() {
            let expected_editor = self
                .editing
                .as_ref()
                .map(|editor| editor.authority_id.clone());
            let action_editor = match &action {
                super::pointer_actions::AgentsAction::EditText(id)
                | super::pointer_actions::AgentsAction::Save(id)
                | super::pointer_actions::AgentsAction::Cancel(id)
                | super::pointer_actions::AgentsAction::ExternalEditBegin(id) => Some(id),
                _ => None,
            };
            if action_editor.is_some_and(|id| Some(id) != expected_editor.as_ref()) {
                return Nav::Stay;
            }
            if let Some(confirming) = self.external_edit_confirmation.as_ref()
                && !matches!(
                    &action,
                    super::pointer_actions::AgentsAction::ExternalEditBegin(agent)
                        if agent == confirming
                )
                && !matches!(&action, super::pointer_actions::AgentsAction::Cancel(agent) if agent == confirming)
            {
                self.external_edit_confirmation = None;
                self.status = Some("external edit cancelled".into());
                return Nav::Stay;
            }
            return match action {
                super::pointer_actions::AgentsAction::EditText(_) => Nav::Stay,
                super::pointer_actions::AgentsAction::Save(_) => cx.handle_agents_page_key(
                    KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
                    self,
                ),
                super::pointer_actions::AgentsAction::Cancel(_) => {
                    cx.handle_agents_page_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), self)
                }
                super::pointer_actions::AgentsAction::ExternalEditBegin(ref agent)
                    if self
                        .editing
                        .as_ref()
                        .is_some_and(|editor| editor.name == agent.name()) =>
                {
                    if self.external_edit_confirmation.as_ref() == Some(agent) {
                        cx.handle_agents_page_key(
                            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                            self,
                        )
                    } else if std::env::var_os("EDITOR").is_none() {
                        self.status = Some("No $EDITOR environment variable".into());
                        Nav::Stay
                    } else {
                        self.external_edit_confirmation = Some(agent.clone());
                        self.status = Some(format!("Open agent {} in $EDITOR?", agent.name()));
                        Nav::Stay
                    }
                }
                _ => Nav::Stay,
            };
        }
        if let Some(detail) = self.detail.as_ref() {
            let expected = row_agent_id(&detail.name, &detail.source);
            let detail_id = match &action {
                super::pointer_actions::AgentsAction::OpenRawEditor(id)
                | super::pointer_actions::AgentsAction::Save(id)
                | super::pointer_actions::AgentsAction::Cancel(id)
                | super::pointer_actions::AgentsAction::ToggleTool(id, _)
                | super::pointer_actions::AgentsAction::CycleTier(id, _) => Some(id),
                _ => None,
            };
            if detail_id.is_some_and(|id| *id != expected) {
                return Nav::Stay;
            }
        }
        if self.detail.is_some()
            && matches!(
                &action,
                super::pointer_actions::AgentsAction::OpenRawEditor(_)
            )
        {
            return cx.handle_agents_page_key(
                KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE),
                self,
            );
        }
        if self.detail.is_some() && matches!(&action, super::pointer_actions::AgentsAction::Save(_))
        {
            return cx.handle_agents_page_key(
                KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
                self,
            );
        }
        if let Some(detail) = self.detail.as_mut() {
            let (row, key) = match action {
                super::pointer_actions::AgentsAction::ToggleTool(_, row) => {
                    (row, KeyCode::Char(' '))
                }
                super::pointer_actions::AgentsAction::CycleTier(_, row) => {
                    (row, KeyCode::Char('t'))
                }
                _ => return Nav::Stay,
            };
            let Some(index) = cockpit_core::agents::tool_surface_catalog()
                .iter()
                .position(|tool| tool.name == row.0)
            else {
                return Nav::Stay;
            };
            if index >= cockpit_core::agents::tool_surface_catalog().len() {
                return Nav::Stay;
            }
            detail.picker.set_cursor(index);
            return cx.handle_agents_page_key(KeyEvent::new(key, KeyModifiers::NONE), self);
        }
        let row_identity = match &action {
            super::pointer_actions::AgentsAction::Open(id)
            | super::pointer_actions::AgentsAction::Edit(id)
            | super::pointer_actions::AgentsAction::Delete(id)
            | super::pointer_actions::AgentsAction::Reset(id) => Some(id),
            _ => None,
        };
        if let Some(id) = row_identity {
            let Some(index) = self
                .rows
                .iter()
                .position(|row| row_agent_id(&row.name, &row.source) == *id)
            else {
                return Nav::Stay;
            };
            // A pending destructive action is valid only for the row that
            // still owns it; a different stable target starts fresh.
            if index != self.cursor {
                self.disarm_guards();
            }
            self.cursor = index;
        }
        if self.confirm_reset
            && matches!(action, super::pointer_actions::AgentsAction::Cancel(ref id)
                if *id != super::pointer_actions::AgentId::reset_all())
        {
            return Nav::Stay;
        }
        match &action {
            super::pointer_actions::AgentsAction::ResetAll if self.confirm_reset => {
                return cx.handle_agents_page_key(
                    KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                    self,
                );
            }
            super::pointer_actions::AgentsAction::Cancel(id)
                if self.confirm_reset && *id == super::pointer_actions::AgentId::reset_all() =>
            {
                self.confirm_reset = false;
                self.status = Some("reset cancelled".into());
                return Nav::Stay;
            }
            super::pointer_actions::AgentsAction::Delete(_) if self.delete.is_pending() => {
                return cx.handle_agents_page_key(
                    KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
                    self,
                );
            }
            super::pointer_actions::AgentsAction::Reset(_) if self.reset_one.is_pending() => {
                return cx.handle_agents_page_key(
                    KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
                    self,
                );
            }
            super::pointer_actions::AgentsAction::Open(_) => {
                return cx.handle_agents_page_key(
                    KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                    self,
                );
            }
            super::pointer_actions::AgentsAction::Cancel(_) => {
                self.disarm_guards();
                self.status = Some("action cancelled".into());
                return Nav::Stay;
            }
            super::pointer_actions::AgentsAction::Edit(_) => {
                cx.edit_selected_in_tui(self);
                return Nav::Stay;
            }
            super::pointer_actions::AgentsAction::Delete(_) => {
                return cx.handle_agents_page_key(
                    KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
                    self,
                );
            }
            super::pointer_actions::AgentsAction::Reset(_) => {
                return cx.handle_agents_page_key(
                    KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
                    self,
                );
            }
            super::pointer_actions::AgentsAction::ResetAll => {
                return cx.handle_agents_page_key(
                    KeyEvent::new(KeyCode::Char('R'), KeyModifiers::NONE),
                    self,
                );
            }
            _ => {}
        }
        Nav::Stay
    }

    fn handle_pointer_scroll(
        &mut self,
        _cx: &mut SettingsCx,
        region: SettingsScrollRegionId,
        delta: isize,
    ) -> Nav {
        if region == SettingsScrollRegionId("agents:list")
            && self.detail.is_none()
            && self.editing.is_none()
        {
            self.disarm_guards();
            self.cursor = self
                .cursor
                .saturating_add_signed(delta)
                .min(self.rows.len().saturating_sub(1));
        } else if region == SettingsScrollRegionId("agents:detail")
            && let Some(detail) = self.detail.as_mut()
        {
            let last = cockpit_core::agents::tool_surface_catalog()
                .len()
                .saturating_sub(1);
            let cursor = detail
                .picker
                .cursor()
                .saturating_add_signed(delta)
                .min(last);
            detail.picker.set_cursor(cursor);
        }
        Nav::Stay
    }

    fn handle_pointer_control_at(
        &mut self,
        cx: &mut SettingsCx,
        action: super::pointer_actions::SettingsPointerAction,
        column: u16,
        row: u16,
    ) -> Nav {
        if matches!(
            &action,
            super::pointer_actions::SettingsPointerAction::Agents(
                super::pointer_actions::AgentsAction::EditText(_)
            )
        ) && self.external_edit_confirmation.take().is_some()
        {
            self.status = Some("external edit cancelled".into());
            return Nav::Stay;
        }
        if matches!(
            &action,
            super::pointer_actions::SettingsPointerAction::Agents(
                super::pointer_actions::AgentsAction::EditText(_)
            )
        ) && let Some(editor) = self.editing.as_mut()
            && let Some(body) = self.editor_body.get()
        {
            editor.set_cursor_from_visible_cell(
                usize::from(row.saturating_sub(body.y)),
                usize::from(column.saturating_sub(body.x)),
            );
            return Nav::Stay;
        }
        self.handle_pointer_control(cx, action)
    }

    fn cancel_pointer_transients(&mut self) {
        self.confirm_reset = false;
        self.disarm_guards();
        self.external_edit_confirmation = None;
        // Geometry invalidation cancels only pointer-owned confirmations. An
        // editor effect owns a daemon lease, recovery draft and correlation
        // ID; it must survive resize/redraw and settle through its explicit
        // completion callback.
    }

    fn title(&self, cx: &SettingsCx) -> String {
        format!(
            "{} › Agents",
            cockpit_core::welcome::display_path(&cx.config_path)
        )
    }

    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        self.help_text()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "Agents"
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    use std::fs;
    use tempfile::TempDir;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    struct TrustedAgentsDialog {
        dialog: SettingsDialog,
        trust: cockpit_config::trust::ThreadWorkspaceTrustGuard,
    }

    impl std::ops::Deref for TrustedAgentsDialog {
        type Target = SettingsDialog;

        fn deref(&self) -> &Self::Target {
            &self.dialog
        }
    }

    impl std::ops::DerefMut for TrustedAgentsDialog {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.dialog
        }
    }

    impl TrustedAgentsDialog {
        fn into_parts(
            self,
        ) -> (
            SettingsDialog,
            cockpit_config::trust::ThreadWorkspaceTrustGuard,
        ) {
            (self.dialog, self.trust)
        }
    }

    /// A settings dialog whose `config.json` lives in `<tmp>/.cockpit/`
    /// and whose picker cwd is `<tmp>`, on the Agents page. The trust guard
    /// remains live for the whole test so refreshes exercise the same trusted
    /// project policy as the production TUI.
    fn agents_dialog(tmp: &TempDir) -> TrustedAgentsDialog {
        let cockpit = tmp.path().join(".cockpit");
        fs::create_dir_all(&cockpit).unwrap();
        let config_path = cockpit.join("config.json");
        fs::write(&config_path, "{}").unwrap();
        super::super::disk_daemon_fake::register_settings_layer_target(&config_path);
        let trust = cockpit_config::trust::enter_workspace_trust_policy(
            crate::tui::app::trusted_workspace_policy_for_tests(tmp.path()),
        );
        let mut d = SettingsDialog::open_from_picker(config_path, tmp.path().to_path_buf());
        d.set_test_page(Page::Agents(AgentsPage::new(tmp.path())));
        TrustedAgentsDialog { dialog: d, trust }
    }

    fn page(d: &SettingsDialog) -> &AgentsPage {
        match d.test_page() {
            TestPageRef::Agents(p) => p,
            _ => panic!("expected Agents page"),
        }
    }

    fn page_mut(d: &mut SettingsDialog) -> &mut AgentsPage {
        match d.test_page_mut() {
            TestPageMut::Agents(p) => p,
            _ => panic!("expected Agents page"),
        }
    }

    /// Move the cursor onto the row whose agent name is `name`.
    fn focus(d: &mut SettingsDialog, name: &str) {
        let idx = page(d).rows.iter().position(|r| r.name == name).unwrap();
        page_mut(d).cursor = idx;
    }

    /// The occurrence-bound identity the page renders for `name`. Row pointer
    /// targets carry the daemon's exact source identity and revision, so a
    /// fixture must read it from the live rows rather than name it.
    fn row_id(d: &SettingsDialog, name: &str) -> super::super::pointer_actions::AgentId {
        let row = page(d).rows.iter().find(|row| row.name == name).unwrap();
        row_agent_id(&row.name, &row.source)
    }

    struct EditorEnv {
        _guard: cockpit_test_support::TestEnvGuard,
    }
    impl EditorEnv {
        /// Take the lock and set `$EDITOR` to `value` (or unset it for `None`).
        fn with(value: Option<&str>) -> Self {
            let guard = cockpit_test_support::TestEnvGuard::blocking_lock();
            match value {
                Some(v) => guard.set_var("EDITOR", v),
                None => guard.remove_var("EDITOR"),
            }
            EditorEnv { _guard: guard }
        }
        fn unset() -> Self {
            Self::with(None)
        }
    }

    fn vnext_workspace_agent(name: &str, description: &str, body: &str) -> String {
        format!(
            "---\ndescription: {description}\nschemaVersion: 2\nagentId: authored/{name}\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: Execute the assigned coding task\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n---\n{body}\n"
        )
    }

    #[test]
    fn lists_builtins() {
        let tmp = TempDir::new().unwrap();
        let d = agents_dialog(&tmp);
        let names: Vec<&str> = page(&d).rows.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"Build"));
        assert!(names.contains(&"builder"));
        assert!(names.contains(&"explore"));
        // The docs pipeline is never listed.
        assert!(!names.iter().any(|n| n.starts_with("docs")));
    }

    #[test]
    fn rows_show_effective_model() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(
            agents_dir.join("with-model.md"),
            vnext_workspace_agent("with-model", "m", "body"),
        )
        .unwrap();
        fs::write(
            agents_dir.join("no-model.md"),
            vnext_workspace_agent("no-model", "n", "body"),
        )
        .unwrap();
        let d = agents_dialog(&tmp);
        let with = page(&d)
            .rows
            .iter()
            .find(|r| r.name == "with-model")
            .unwrap();
        assert_eq!(
            with.model, None,
            "v2 model advice is not a binding selector"
        );
        let without = page(&d).rows.iter().find(|r| r.name == "no-model").unwrap();
        assert_eq!(
            without.model, None,
            "v2 definitions defer model selection to the host"
        );
    }

    #[test]
    fn agents_page_enter_opens_tool_surface_detail_with_tier_state() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(
            agents_dir.join("mine.md"),
            vnext_workspace_agent("mine", "mine", "body"),
        )
        .unwrap();
        let mut d = agents_dialog(&tmp);
        focus(&mut d, "mine");
        d.handle_key(press(KeyCode::Enter));
        assert!(page(&d).detail.is_none());
        assert!(
            page(&d)
                .status
                .as_deref()
                .unwrap_or("")
                .contains("tool authority is host-owned")
        );
    }

    #[test]
    fn agents_page_rejects_legacy_tool_grants_before_structured_editing() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        let path = agents_dir.join("mine.md");
        fs::write(&path, "---\ndescription: mine\ntools: [read]\n---\nbody\n").unwrap();
        let err = cockpit_core::agents::load_workspace_named_from_file(&path, "mine")
            .expect_err("v2 rejects manifest tool authority");
        assert!(format!("{err}").contains("schemaVersion: 2"));
    }

    #[test]
    fn agents_page_rejects_legacy_structural_and_write_tool_authority() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(
            agents_dir.join("mine.md"),
            "---\ndescription: mine\ntools: [read, question, write]\n---\nbody\n",
        )
        .unwrap();
        let err = cockpit_core::agents::load_workspace_named_from_file(
            &agents_dir.join("mine.md"),
            "mine",
        )
        .expect_err("v2 rejects manifest tool authority");
        assert!(format!("{err}").contains("schemaVersion: 2"));
    }

    #[test]
    fn agents_page_rejects_legacy_fork_and_tool_authority() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        let path = agents_dir.join("mine.md");
        let original = "---\ndescription: mine\nmode: subagent\ntools: [read]\n---\nbody\n";
        fs::write(&path, original).unwrap();
        let err = cockpit_core::agents::load_workspace_named_from_file(&path, "mine")
            .expect_err("v2 rejects legacy fork and tool authority");
        assert!(format!("{err}").contains("schemaVersion: 2"));
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn agents_page_legacy_tool_fixture_is_not_a_structured_editor_candidate() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        let path = agents_dir.join("mine.md");
        fs::write(&path, "---\ndescription: mine\ntools: [read]\n---\nbody\n").unwrap();
        assert!(cockpit_core::agents::load_workspace_named_from_file(&path, "mine").is_err());
    }

    #[test]
    fn agents_page_rejects_legacy_tool_descriptions() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        let path = agents_dir.join("mine.md");
        fs::write(
            &path,
            "---\ndescription: mine\ntools: [read, search, mcp]\ntoolTiers:\n  search: discoverable\ntool_descriptions:\n  search:\n    normal: custom search\n---\nbody\n",
        )
        .unwrap();
        assert!(cockpit_core::agents::load_workspace_named_from_file(&path, "mine").is_err());
    }

    #[test]
    fn agents_page_parse_error_cannot_open_structured_detail() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(agents_dir.join("broken.md"), "no frontmatter\n").unwrap();
        let mut d = agents_dialog(&tmp);
        focus(&mut d, "broken");
        assert!(page(&d).rows[page(&d).cursor].detail.is_err());
        d.handle_key(press(KeyCode::Enter));
        assert!(page(&d).detail.is_none());
        assert!(
            page(&d)
                .status
                .as_deref()
                .unwrap_or("")
                .contains("raw editor")
        );
    }

    #[test]
    fn agents_page_assistant_wizard_omits_host_owned_tool_authority() {
        let descriptor = cockpit_core::assistants::descriptor();
        assert!(descriptor.steps.iter().all(|step| step.id != "tools"
            && !matches!(step.kind, cockpit_core::wizard::StepKind::ToolSurface)));
    }

    #[test]
    fn agents_page_assistant_wizard_rejects_legacy_tool_surface_answer() {
        let mut run =
            cockpit_core::wizard::WizardRun::new(cockpit_core::assistants::descriptor()).unwrap();
        let result = run.submit(cockpit_core::wizard::WizardAnswer::ToolSurface(
            cockpit_core::agents::ToolSurfaceSelection {
                tools: vec!["grep".to_string()],
                tool_tiers: Default::default(),
            },
        ));
        assert!(result.is_err());
        assert!(run.error().is_some());
    }

    #[test]
    fn agents_page_assistant_wizard_v2_spec_persists_identity_and_prompt_only() {
        let mut run =
            cockpit_core::wizard::WizardRun::new(cockpit_core::assistants::descriptor()).unwrap();
        run.submit(cockpit_core::wizard::WizardAnswer::Text(
            "Assistant".to_string(),
        ))
        .unwrap();
        run.submit(cockpit_core::wizard::WizardAnswer::Text(
            "Help.".to_string(),
        ))
        .unwrap();
        let spec = cockpit_core::assistants::spec_from_wizard(
            "helper-bot",
            std::path::PathBuf::from("/tmp/helper-bot"),
            &run,
        )
        .unwrap();
        assert_eq!(spec.name, "helper-bot");
        assert_eq!(spec.description, "Assistant");
        assert_eq!(spec.prompt, "Help.");
        assert_eq!(spec.home_dir, std::path::PathBuf::from("/tmp/helper-bot"));
    }

    #[test]
    fn edit_without_editor_opens_in_tui_and_auto_ejects_builtin() {
        let _g = EditorEnv::unset();
        let tmp = TempDir::new().unwrap();
        let mut d = agents_dialog(&tmp);
        focus(&mut d, "builder");
        // `e` starts the in-TUI raw editor; the built-in is ejected first.
        d.handle_key(press(KeyCode::Char('e')));
        assert!(page(&d).editing.is_some(), "in-TUI editor should be open");
        let ejected = tmp.path().join(".cockpit/agents/builder.md");
        assert!(ejected.exists(), "editing a pristine built-in ejects it");
        let builder = page(&d).rows.iter().find(|r| r.name == "builder").unwrap();
        assert!(matches!(
            builder.kind,
            AgentKind::Builtin { overridden: true }
        ));
    }

    #[test]
    fn in_tui_edit_save_writes_to_disk_and_reparses() {
        let _g = EditorEnv::unset();
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(
            agents_dir.join("mine.md"),
            vnext_workspace_agent("mine", "orig", "body"),
        )
        .unwrap();
        // Vim mode off → the in-TUI editor types chars directly.
        let mut d = agents_dialog(&tmp);
        d.extended.tui.vim_mode = cockpit_config::extended::VimModeSetting::Disabled;
        focus(&mut d, "mine");
        d.handle_key(press(KeyCode::Char('e')));
        assert!(page(&d).editing.is_some());
        // Move to the end of the buffer (past the frontmatter + body) and
        // append a marker to the body, keeping the frontmatter valid, then
        // save.
        for _ in 0..16 {
            d.handle_key(press(KeyCode::Down));
        }
        d.handle_key(press(KeyCode::End));
        d.handle_key(press(KeyCode::Char('Z')));
        d.handle_key(ctrl_s());
        assert!(page(&d).editing.is_none(), "save closes the editor");
        assert!(
            page(&d).status.as_deref().unwrap_or("").contains("saved"),
            "valid save reports saved, got {:?}",
            page(&d).status
        );
        let on_disk = fs::read_to_string(agents_dir.join("mine.md")).unwrap();
        assert!(
            on_disk.contains('Z') && on_disk.contains("description: orig"),
            "the edit was written to disk and frontmatter survived: {on_disk:?}"
        );
    }

    #[test]
    fn in_tui_edit_save_invalid_is_refused_and_keeps_the_draft() {
        let _g = EditorEnv::unset();
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        let original = vnext_workspace_agent("mine", "orig", "body");
        fs::write(agents_dir.join("mine.md"), &original).unwrap();
        let mut d = agents_dialog(&tmp);
        d.extended.tui.vim_mode = cockpit_config::extended::VimModeSetting::Disabled;
        focus(&mut d, "mine");
        d.handle_key(press(KeyCode::Char('e')));
        // Type a body-only document (no frontmatter) so the save fails
        // `parse_agent`. We replace by typing after deleting the original via
        // repeated forward-delete, then save: the daemon refuses the definition
        // instead of publishing a broken agent.
        for _ in 0..64 {
            d.handle_key(press(KeyCode::Delete));
        }
        for ch in "no frontmatter".chars() {
            d.handle_key(press(KeyCode::Char(ch)));
        }
        d.handle_key(ctrl_s());
        assert!(
            page(&d).editing.is_some(),
            "a refused save keeps the editor open for repair"
        );
        assert!(
            page(&d)
                .status
                .as_deref()
                .unwrap_or("")
                .contains("invalid agent definition"),
            "invalid content is refused with the daemon's diagnostic, got {:?}",
            page(&d).status
        );
        assert_eq!(
            fs::read_to_string(agents_dir.join("mine.md")).unwrap(),
            original,
            "a refused save never reaches the authoritative file"
        );
    }

    #[test]
    fn delete_requires_two_presses_and_only_for_custom() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(
            agents_dir.join("scratch.md"),
            vnext_workspace_agent("scratch", "s", "b"),
        )
        .unwrap();
        let mut d = agents_dialog(&tmp);
        // Built-in: delete is refused.
        focus(&mut d, "Build");
        d.handle_key(press(KeyCode::Char('d')));
        assert!(tmp.path().join(".cockpit/agents").exists());
        assert!(
            page(&d)
                .status
                .as_deref()
                .unwrap_or("")
                .contains("cannot be deleted"),
            "built-in delete is refused"
        );
        // Custom: first `d` arms, second deletes.
        focus(&mut d, "scratch");
        d.handle_key(press(KeyCode::Char('d')));
        assert!(
            agents_dir.join("scratch.md").exists(),
            "single d must not delete"
        );
        d.handle_key(press(KeyCode::Char('d')));
        assert!(
            !agents_dir.join("scratch.md").exists(),
            "double d deletes the custom agent"
        );
    }

    #[test]
    fn delete_disarms_on_navigation() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(
            agents_dir.join("a-scratch.md"),
            "---\ndescription: s\n---\nb\n",
        )
        .unwrap();
        let mut d = agents_dialog(&tmp);
        focus(&mut d, "a-scratch");
        d.handle_key(press(KeyCode::Char('d')));
        // Navigate away — must disarm.
        d.handle_key(press(KeyCode::Up));
        d.handle_key(press(KeyCode::Down));
        focus(&mut d, "a-scratch");
        d.handle_key(press(KeyCode::Char('d')));
        assert!(
            agents_dir.join("a-scratch.md").exists(),
            "navigation between the two d presses must re-arm, not delete"
        );
    }

    #[test]
    fn per_agent_reset_reverts_overridden_builtin_only() {
        let tmp = TempDir::new().unwrap();
        let mut d = agents_dialog(&tmp);
        // Eject Build via the edit path (with $EDITOR unset → in-TUI), then
        // cancel the editor so we just have the override on disk.
        {
            let _g = EditorEnv::unset();
            focus(&mut d, "Build");
            d.handle_key(press(KeyCode::Char('e')));
            d.handle_key(press(KeyCode::Esc)); // cancel editor
        }
        let build_md = tmp.path().join(".cockpit/agents/Build.md");
        assert!(build_md.exists(), "Build was ejected");
        // Now Build is overridden — per-agent reset removes just that file.
        focus(&mut d, "Build");
        d.handle_key(press(KeyCode::Char('r'))); // arm
        assert!(build_md.exists(), "single r must not reset");
        d.handle_key(press(KeyCode::Char('r'))); // confirm
        assert!(
            !build_md.exists(),
            "double r resets the overridden built-in"
        );

        // A pristine built-in offers no reset.
        focus(&mut d, "builder");
        d.handle_key(press(KeyCode::Char('r')));
        assert!(
            page(&d)
                .status
                .as_deref()
                .unwrap_or("")
                .contains("overridden"),
            "pristine built-in r is refused"
        );
    }

    #[test]
    fn external_editor_request_is_drained_when_editor_set() {
        // With $EDITOR set, editing defers to the event loop: a pending
        // external-edit path is recorded and drainable.
        let _g = EditorEnv::with(Some("true"));
        let tmp = TempDir::new().unwrap();
        let (dialog, _trust) = agents_dialog(&tmp).into_parts();
        let mut outer = super::super::Dialog::Settings(Box::new(dialog));
        // Focus + edit `builder` (auto-ejects, then requests $EDITOR).
        if let super::super::Dialog::Settings(s) = &mut outer {
            focus(s, "builder");
        }
        outer.handle_key(press(KeyCode::Char('e')));
        let drained = outer.take_pending_agent_edit();
        assert!(
            drained.is_some(),
            "an external-edit request should be pending"
        );
        assert!(
            tmp.path().join(".cockpit/agents/builder.md").exists(),
            "the built-in was ejected before handing off to $EDITOR"
        );
        // Second drain is empty (taken).
        assert!(outer.take_pending_agent_edit().is_none());
        // A matching completion is accepted once; a duplicate is inert.
        let effect = drained.unwrap();
        let operation_id = effect.operation_id;
        assert!(!fs::read_to_string(&effect.path).unwrap().is_empty());
        outer.finish_agent_edit(
            operation_id,
            super::super::pointer_actions::ExternalEditOutcome::Saved,
            None,
        );
        outer.finish_agent_edit(
            operation_id,
            super::super::pointer_actions::ExternalEditOutcome::Failed,
            Some("late duplicate".into()),
        );
        if let super::super::Dialog::Settings(s) = &mut outer {
            assert_ne!(page(s).status.as_deref(), Some("late duplicate"));
        }
    }

    pub(crate) fn run_pointer_external_edit_exactly_once_regression() {
        external_editor_request_is_drained_when_editor_set();

        let _g = EditorEnv::with(Some("true"));
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(
            agents_dir.join("pointer-agent.md"),
            vnext_workspace_agent("pointer-agent", "pointer fixture", "body"),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                agents_dir.join("pointer-agent.md"),
                fs::Permissions::from_mode(0o640),
            )
            .unwrap();
        }
        let mut dialog = agents_dialog(&tmp);
        focus(&mut dialog, "pointer-agent");
        // The pointer Edit action opens the in-TUI raw editor directly
        // (edit_selected_in_tui), bypassing the v2 detail-page guard.
        let edit_action = super::super::pointer_actions::SettingsPointerAction::Agents(
            super::super::pointer_actions::AgentsAction::Edit(row_id(&dialog, "pointer-agent")),
        );
        click_agent_action(&mut dialog, &edit_action);
        assert!(
            page(&dialog).editing.is_some(),
            "pointer Edit opens raw editor"
        );

        let original = fs::read_to_string(agents_dir.join("pointer-agent.md")).unwrap();
        let _ = super::super::tests::render_settings_rows(&dialog, 90, 28);
        let edit_text = dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .find(|target| {
                matches!(
                    target.action,
                    super::super::shell::SettingsPointerAction::Page(
                        super::super::pointer_actions::SettingsPointerAction::Agents(
                            super::super::pointer_actions::AgentsAction::EditText(_)
                        )
                    )
                )
            })
            .cloned()
            .expect("raw editor publishes text body");
        dialog.handle_pointer(super::super::tests::settings_mouse(
            crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            edit_text.rect.x,
            edit_text.rect.y + 3,
        ));
        dialog.handle_pointer(super::super::tests::settings_mouse(
            crossterm::event::MouseEventKind::Up(crossterm::event::MouseButton::Left),
            edit_text.rect.x,
            edit_text.rect.y + 3,
        ));
        page_mut(&mut dialog)
            .editing
            .as_mut()
            .expect("raw editor remains open after pointer placement")
            .paste("X");
        assert!(
            page(&dialog)
                .editing
                .as_ref()
                .unwrap()
                .text()
                .contains("\nXbody"),
            "click row is relative to retained editor-body origin"
        );

        let agent = super::super::pointer_actions::AgentId::workspace("pointer-agent");
        let action = super::super::pointer_actions::SettingsPointerAction::Agents(
            super::super::pointer_actions::AgentsAction::ExternalEditBegin(agent.clone()),
        );
        let _ = super::super::tests::render_settings_rows(&dialog, 90, 28);
        let begin = dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .find(|target| {
                target.action == super::super::shell::SettingsPointerAction::Page(action.clone())
            })
            .cloned()
            .expect("raw editor publishes Open in $EDITOR");
        dialog.handle_pointer(super::super::tests::settings_mouse(
            crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            begin.rect.x,
            begin.rect.y,
        ));
        dialog.handle_pointer(super::super::tests::settings_mouse(
            crossterm::event::MouseEventKind::Up(crossterm::event::MouseButton::Left),
            begin.rect.x,
            begin.rect.y,
        ));
        assert_eq!(
            page(&dialog).external_edit_confirmation.as_ref(),
            Some(&agent),
            "first activation only opens the named confirmation"
        );
        assert!(page(&dialog).pending_external_edit.is_none());
        assert_eq!(
            fs::read_to_string(agents_dir.join("pointer-agent.md")).unwrap(),
            original,
            "opening confirmation performs no eager file mutation"
        );
        let _ = super::super::tests::render_settings_rows(&dialog, 90, 28);
        assert!(
            !dialog
                .pointer_surface
                .targets
                .borrow()
                .iter()
                .any(|target| {
                    matches!(
                        target.action,
                        super::super::shell::SettingsPointerAction::Page(
                            super::super::pointer_actions::SettingsPointerAction::Agents(
                                super::super::pointer_actions::AgentsAction::EditText(_)
                            )
                        )
                    )
                }),
            "confirmation suppresses the editor text target"
        );
        let confirm = dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .find(|target| {
                target.action == super::super::shell::SettingsPointerAction::Page(action.clone())
            })
            .cloned()
            .expect("confirmation publishes named Open in $EDITOR");
        dialog.handle_pointer(super::super::tests::settings_mouse(
            crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            confirm.rect.x,
            confirm.rect.y,
        ));
        dialog.handle_pointer(super::super::tests::settings_mouse(
            crossterm::event::MouseEventKind::Up(crossterm::event::MouseButton::Left),
            confirm.rect.x,
            confirm.rect.y,
        ));
        let operation = page(&dialog)
            .pending_external_edit
            .as_ref()
            .expect("confirmed activation submits effect")
            .id;
        assert_eq!(
            page(&dialog)
                .pending_external_edit
                .as_ref()
                .map(|pending| pending.id),
            Some(operation),
            "release preserves the one correlated operation"
        );
        assert_eq!(
            fs::read_to_string(agents_dir.join("pointer-agent.md")).unwrap(),
            original,
            "submitting the injected effect still performs no reducer-side write"
        );
        assert_eq!(page(&dialog).external_edit_ops.pending(), Some(operation));

        let request = page_mut(&mut dialog)
            .take_external_edit_request()
            .expect("effect request drains once");
        assert_eq!(request.operation_id, operation);
        assert_eq!(
            fs::read_to_string(&request.path).unwrap(),
            vnext_workspace_agent("pointer-agent", "pointer fixture", "Xbody")
        );
        assert!(page_mut(&mut dialog).take_external_edit_request().is_none());
        let cwd = dialog.cx.agents_cwd();
        page_mut(&mut dialog).reduce_external_edit_result(
            &cwd,
            operation,
            super::super::pointer_actions::AgentsAction::ExternalEditResult(
                super::super::pointer_actions::AgentId::workspace("replacement-agent"),
                super::super::pointer_actions::ExternalEditOutcome::Saved,
            ),
            None,
        );
        assert!(
            page(&dialog).pending_external_edit.is_some(),
            "stale stable identity is inert"
        );
        dialog.finish_agent_external_edit(
            PointerOperationId(operation.0 + 1),
            super::super::pointer_actions::ExternalEditOutcome::Saved,
            None,
        );
        assert!(
            page(&dialog).pending_external_edit.is_some(),
            "stale completion is inert"
        );
        let saved_result = super::super::pointer_actions::SettingsPointerAction::Agents(
            super::super::pointer_actions::AgentsAction::ExternalEditResult(
                agent.clone(),
                super::super::pointer_actions::ExternalEditOutcome::Saved,
            ),
        );
        super::super::pointer_acceptance_tests::record_source_action(&saved_result);
        dialog.finish_agent_external_edit(
            operation,
            super::super::pointer_actions::ExternalEditOutcome::Saved,
            None,
        );
        super::super::pointer_acceptance_tests::record_dispatched_action(&saved_result);
        assert!(
            fs::read_to_string(agents_dir.join("pointer-agent.md"))
                .unwrap()
                .contains("\nXbody"),
            "Saved atomically commits the staged edit"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(agents_dir.join("pointer-agent.md"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600,
                "the committed definition is published owner-only, never widened by the editor"
            );
        }
        let status = page(&dialog).status.clone();
        dialog.finish_agent_external_edit(
            operation,
            super::super::pointer_actions::ExternalEditOutcome::Failed,
            Some("duplicate".into()),
        );
        assert_eq!(
            page(&dialog).status,
            status,
            "duplicate completion is inert"
        );

        for outcome in [
            super::super::pointer_actions::ExternalEditOutcome::Cancelled,
            super::super::pointer_actions::ExternalEditOutcome::Failed,
        ] {
            let mut retry = agents_dialog(&tmp);
            focus(&mut retry, "pointer-agent");
            let edit_action = super::super::pointer_actions::SettingsPointerAction::Agents(
                super::super::pointer_actions::AgentsAction::Edit(row_id(&retry, "pointer-agent")),
            );
            click_agent_action(&mut retry, &edit_action);
            page_mut(&mut retry)
                .editing
                .as_mut()
                .expect("pointer Edit opens the in-TUI raw editor")
                .paste("RETAINED");
            let action = super::super::pointer_actions::SettingsPointerAction::Agents(
                super::super::pointer_actions::AgentsAction::ExternalEditBegin(agent.clone()),
            );
            {
                let page = &mut retry.dialog.page;
                let cx = &mut retry.dialog.cx;
                page.handle_pointer_control(cx, action.clone());
                page.handle_pointer_control(cx, action);
            }
            let effect = page_mut(&mut retry)
                .take_external_edit_request()
                .expect("terminal outcome effect");
            let operation = effect.operation_id;
            fs::write(&effect.path, "externally changed staging").unwrap();
            let result_action = super::super::pointer_actions::SettingsPointerAction::Agents(
                super::super::pointer_actions::AgentsAction::ExternalEditResult(
                    agent.clone(),
                    outcome,
                ),
            );
            super::super::pointer_acceptance_tests::record_source_action(&result_action);
            retry.finish_agent_external_edit(operation, outcome, None);
            super::super::pointer_acceptance_tests::record_dispatched_action(&result_action);
            assert!(page(&retry).pending_external_edit.is_none());
            // Cancelling restores the exact pre-handoff draft; a failed editor
            // run keeps whatever bytes the external editor left behind.
            let retained = if matches!(
                outcome,
                super::super::pointer_actions::ExternalEditOutcome::Cancelled
            ) {
                "RETAINED"
            } else {
                "externally changed staging"
            };
            assert!(
                page(&retry)
                    .editing
                    .as_ref()
                    .is_some_and(|editor| editor.text().contains(retained)),
                "{outcome:?} restores the retryable draft"
            );
            assert!(page(&retry).external_edit_ops.pending().is_none());
            assert!(
                !fs::read_to_string(agents_dir.join("pointer-agent.md"))
                    .unwrap()
                    .contains("RETAINED"),
                "{outcome:?} never mutates the real agent path"
            );
        }

        let replacement_cases: &[bool] = if cfg!(unix) { &[false, true] } else { &[false] };
        for &replacement in replacement_cases {
            let target = agents_dir.join("pointer-agent.md");
            fs::write(
                &target,
                vnext_workspace_agent("pointer-agent", "pointer fixture", "Xbody"),
            )
            .unwrap();
            let mut conflict = agents_dialog(&tmp);
            focus(&mut conflict, "pointer-agent");
            let edit_action = super::super::pointer_actions::SettingsPointerAction::Agents(
                super::super::pointer_actions::AgentsAction::Edit(row_id(
                    &conflict,
                    "pointer-agent",
                )),
            );
            click_agent_action(&mut conflict, &edit_action);
            let action = super::super::pointer_actions::SettingsPointerAction::Agents(
                super::super::pointer_actions::AgentsAction::ExternalEditBegin(agent.clone()),
            );
            {
                let page = &mut conflict.dialog.page;
                let cx = &mut conflict.dialog.cx;
                page.handle_pointer_control(cx, action.clone());
                page.handle_pointer_control(cx, action);
            }
            let effect = page_mut(&mut conflict)
                .take_external_edit_request()
                .expect("regular-file conflict effect");
            // A well-formed staged definition, so only the revision conflict
            // can refuse the commit.
            fs::write(
                &effect.path,
                vnext_workspace_agent("pointer-agent", "pointer fixture", "Zbody"),
            )
            .unwrap();
            let concurrent =
                vnext_workspace_agent("pointer-agent", "pointer fixture", "Ybody").into_bytes();
            if replacement {
                let replacement_path = agents_dir.join("replacement.md");
                fs::write(&replacement_path, &concurrent).unwrap();
                fs::rename(replacement_path, &target).unwrap();
            } else {
                fs::write(&target, &concurrent).unwrap();
            }
            conflict.finish_agent_external_edit(
                effect.operation_id,
                super::super::pointer_actions::ExternalEditOutcome::Saved,
                None,
            );
            assert_eq!(
                fs::read(&target).unwrap(),
                concurrent,
                "{} conflict keeps the concurrent file",
                if replacement { "identity" } else { "content" }
            );
            assert!(page(&conflict).editing.is_some(), "conflict restores draft");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let target = agents_dir.join("pointer-agent.md");
            let before = fs::read(&target).unwrap();
            let mut chmod_race = agents_dialog(&tmp);
            focus(&mut chmod_race, "pointer-agent");
            let edit_action = super::super::pointer_actions::SettingsPointerAction::Agents(
                super::super::pointer_actions::AgentsAction::Edit(row_id(
                    &chmod_race,
                    "pointer-agent",
                )),
            );
            click_agent_action(&mut chmod_race, &edit_action);
            let action = super::super::pointer_actions::SettingsPointerAction::Agents(
                super::super::pointer_actions::AgentsAction::ExternalEditBegin(agent.clone()),
            );
            {
                let page = &mut chmod_race.dialog.page;
                let cx = &mut chmod_race.dialog.cx;
                page.handle_pointer_control(cx, action.clone());
                page.handle_pointer_control(cx, action);
            }
            let effect = page_mut(&mut chmod_race)
                .take_external_edit_request()
                .expect("chmod-race effect");
            fs::write(&effect.path, "staged replacement").unwrap();
            // The suite may run under a process umask changed by another
            // regression, and the identity-replacement case above creates a
            // fresh inode. Choose a mode relative to the live target so the
            // concurrent chmod is always a real metadata change.
            let original_mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            let concurrent_mode = if original_mode == 0o600 { 0o640 } else { 0o600 };
            fs::set_permissions(&target, fs::Permissions::from_mode(concurrent_mode)).unwrap();
            chmod_race.finish_agent_external_edit(
                effect.operation_id,
                super::super::pointer_actions::ExternalEditOutcome::Saved,
                None,
            );
            assert_eq!(
                fs::read(&target).unwrap(),
                before,
                "a refused commit keeps bytes"
            );
            assert_eq!(
                fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                concurrent_mode,
                "the host never restores stale permissions after a concurrent chmod"
            );
            assert!(
                page(&chmod_race).editing.is_some(),
                "draft restored on a refused commit"
            );
            assert!(
                page(&chmod_race).status.as_deref().is_some_and(
                    |status| status.contains("failed to atomically commit external edit")
                ),
                "a refused commit is reported, got {:?}",
                page(&chmod_race).status
            );
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let mut swapped = agents_dialog(&tmp);
            focus(&mut swapped, "pointer-agent");
            let edit_action = super::super::pointer_actions::SettingsPointerAction::Agents(
                super::super::pointer_actions::AgentsAction::Edit(row_id(
                    &swapped,
                    "pointer-agent",
                )),
            );
            click_agent_action(&mut swapped, &edit_action);
            let action = super::super::pointer_actions::SettingsPointerAction::Agents(
                super::super::pointer_actions::AgentsAction::ExternalEditBegin(agent.clone()),
            );
            {
                let page = &mut swapped.dialog.page;
                let cx = &mut swapped.dialog.cx;
                page.handle_pointer_control(cx, action.clone());
                page.handle_pointer_control(cx, action);
            }
            let effect = page_mut(&mut swapped)
                .take_external_edit_request()
                .expect("symlink-swap effect");
            // A well-formed staged definition, so only the swapped source can
            // refuse the commit.
            fs::write(
                &effect.path,
                vnext_workspace_agent("pointer-agent", "pointer fixture", "Zbody"),
            )
            .unwrap();
            let target = agents_dir.join("pointer-agent.md");
            let victim = tmp.path().join("symlink-victim.md");
            fs::write(&victim, "victim stays unchanged").unwrap();
            fs::remove_file(&target).unwrap();
            symlink(&victim, &target).unwrap();
            swapped.finish_agent_external_edit(
                effect.operation_id,
                super::super::pointer_actions::ExternalEditOutcome::Saved,
                None,
            );
            assert_eq!(
                fs::read_to_string(&victim).unwrap(),
                "victim stays unchanged"
            );
            assert!(page(&swapped).editing.is_some(), "draft restored on swap");
            assert!(
                page(&swapped).status.as_deref().is_some_and(
                    |status| status.contains("failed to atomically commit external edit")
                ),
                "a swapped source refuses the commit, got {:?}",
                page(&swapped).status
            );
        }
    }

    pub(crate) fn run_pointer_raw_editor_terminal_actions_regression() {
        let _g = EditorEnv::with(Some("true"));
        for terminal in ["save", "cancel"] {
            let tmp = TempDir::new().unwrap();
            let agents_dir = tmp.path().join(".cockpit/agents");
            fs::create_dir_all(&agents_dir).unwrap();
            fs::write(
                agents_dir.join("pointer-agent.md"),
                vnext_workspace_agent("pointer-agent", "pointer fixture", "body"),
            )
            .unwrap();
            let mut dialog = agents_dialog(&tmp);
            focus(&mut dialog, "pointer-agent");
            // The pointer Edit action opens the in-TUI raw editor directly
            // (edit_selected_in_tui), bypassing the v2 detail-page guard.
            let edit_action = super::super::pointer_actions::SettingsPointerAction::Agents(
                super::super::pointer_actions::AgentsAction::Edit(row_id(&dialog, "pointer-agent")),
            );
            click_agent_action(&mut dialog, &edit_action);
            // The draft has to stay a publishable definition: the daemon
            // refuses anything that does not parse, so the terminal action
            // under test would never be reached.
            page_mut(&mut dialog)
                .editing
                .as_mut()
                .expect("raw editor opens")
                .replace_with_recovery_text(&vnext_workspace_agent(
                    "pointer-agent",
                    "pointer fixture",
                    "changed-by-pointer",
                ));
            let agent = super::super::pointer_actions::AgentId::workspace("pointer-agent");
            let action = super::super::pointer_actions::SettingsPointerAction::Agents(
                if terminal == "save" {
                    super::super::pointer_actions::AgentsAction::Save(agent)
                } else {
                    super::super::pointer_actions::AgentsAction::Cancel(agent)
                },
            );
            let target = {
                let _ = super::super::tests::render_settings_rows(&dialog, 90, 28);
                dialog
                    .pointer_surface
                    .targets
                    .borrow()
                    .iter()
                    .find(|target| {
                        target.enabled
                            && target.action
                                == super::super::shell::SettingsPointerAction::Page(action.clone())
                    })
                    .cloned()
                    .expect("raw agent editor publishes its named terminal action")
            };
            dialog.handle_pointer(super::super::tests::settings_mouse(
                crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
                target.rect.x,
                target.rect.y,
            ));
            dialog.handle_pointer(super::super::tests::settings_mouse(
                crossterm::event::MouseEventKind::Up(crossterm::event::MouseButton::Left),
                target.rect.x,
                target.rect.y,
            ));
            assert!(
                page(&dialog).editing.is_none(),
                "{terminal} closes the raw editor through its real reducer"
            );
            let persisted = fs::read_to_string(agents_dir.join("pointer-agent.md")).unwrap();
            if terminal == "save" {
                assert!(
                    persisted.contains("changed-by-pointer"),
                    "Save persists the raw editor draft"
                );
            } else {
                assert_eq!(
                    persisted,
                    vnext_workspace_agent("pointer-agent", "pointer fixture", "body"),
                    "Cancel discards the raw editor draft"
                );
            }
        }
    }

    fn populated_pointer_agents_dialog(tmp: &TempDir) -> TrustedAgentsDialog {
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(
            agents_dir.join("pointer-agent.md"),
            vnext_workspace_agent("pointer-agent", "pointer fixture", "body"),
        )
        .unwrap();
        agents_dialog(tmp)
    }

    fn click_agent_action(
        dialog: &mut SettingsDialog,
        action: &super::super::pointer_actions::SettingsPointerAction,
    ) {
        let target = {
            let _ = super::super::tests::render_settings_rows(dialog, 90, 28);
            dialog
                .pointer_surface
                .targets
                .borrow()
                .iter()
                .find(|target| {
                    target.enabled
                        && target.action
                            == super::super::shell::SettingsPointerAction::Page(action.clone())
                })
                .cloned()
                .expect("stable agent action rerenders from its fresh selected source")
        };
        for kind in [
            crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            crossterm::event::MouseEventKind::Up(crossterm::event::MouseButton::Left),
        ] {
            dialog.handle_pointer(super::super::tests::settings_mouse(
                kind,
                target.rect.x,
                target.rect.y,
            ));
        }
    }

    fn overridden_pointer_agent_dialog(tmp: &TempDir, name: &str) -> TrustedAgentsDialog {
        let _editor = EditorEnv::unset();
        let mut dialog = populated_pointer_agents_dialog(tmp);
        focus(&mut dialog, name);
        dialog.handle_key(press(KeyCode::Char('e')));
        dialog.handle_key(press(KeyCode::Esc));
        if let TestPageMut::Agents(page) = dialog.test_page_mut() {
            *page = AgentsPage::new(tmp.path());
        }
        focus(&mut dialog, name);
        assert!(
            tmp.path()
                .join(format!(".cockpit/agents/{name}.md"))
                .exists()
        );
        dialog
    }

    pub(crate) fn run_pointer_agent_open_regression() {
        let source_tmp = TempDir::new().unwrap();
        let source = populated_pointer_agents_dialog(&source_tmp);
        // A row identity is bound to its exact daemon-returned source, so each
        // fixture workspace mints its own; only the names carry over.
        let names = page(&source)
            .rows
            .iter()
            .map(|row| row.name.clone())
            .collect::<Vec<_>>();
        assert!(!names.is_empty(), "populated Agents source has rows");

        for name in &names {
            let tmp = TempDir::new().unwrap();
            let mut dialog = populated_pointer_agents_dialog(&tmp);
            focus(&mut dialog, name);
            let agent = row_id(&dialog, name);
            let action = super::super::pointer_actions::SettingsPointerAction::Agents(
                super::super::pointer_actions::AgentsAction::Open(agent.clone()),
            );
            click_agent_action(&mut dialog, &action);
            // All agents are schemaVersion 2; the structured tool editor is
            // intentionally unavailable. Open still reaches the reducer and
            // sets the status message instead of opening the detail.
            assert!(
                page(&dialog).detail.is_none(),
                "v2 Open does not open the structured editor for {agent:?}"
            );
            assert!(
                page(&dialog)
                    .status
                    .as_ref()
                    .is_some_and(|s| s.contains("unavailable")),
                "v2 Open sets the unavailable status for {agent:?}"
            );
        }

        for name in &names {
            let tmp = TempDir::new().unwrap();
            let mut dialog = populated_pointer_agents_dialog(&tmp);
            focus(&mut dialog, name);
            let agent = row_id(&dialog, name);
            let action = super::super::pointer_actions::SettingsPointerAction::Agents(
                super::super::pointer_actions::AgentsAction::Edit(agent.clone()),
            );
            click_agent_action(&mut dialog, &action);
            assert!(
                page(&dialog)
                    .editing
                    .as_ref()
                    .is_some_and(|editor| editor.name == agent.name()),
                "Edit reaches the real raw-editor transition for {agent:?}"
            );
        }

        let tmp = TempDir::new().unwrap();
        let mut dialog = populated_pointer_agents_dialog(&tmp);
        focus(&mut dialog, "pointer-agent");
        let custom = row_id(&dialog, "pointer-agent");
        let delete = super::super::pointer_actions::SettingsPointerAction::Agents(
            super::super::pointer_actions::AgentsAction::Delete(custom.clone()),
        );
        click_agent_action(&mut dialog, &delete);
        assert!(page(&dialog).delete.is_pending());
        assert!(tmp.path().join(".cockpit/agents/pointer-agent.md").exists());
        click_agent_action(&mut dialog, &delete);
        assert!(!tmp.path().join(".cockpit/agents/pointer-agent.md").exists());

        let tmp = TempDir::new().unwrap();
        let mut dialog = populated_pointer_agents_dialog(&tmp);
        let reset_all = super::super::pointer_actions::SettingsPointerAction::Agents(
            super::super::pointer_actions::AgentsAction::ResetAll,
        );
        click_agent_action(&mut dialog, &reset_all);
        assert!(page(&dialog).confirm_reset);
        click_agent_action(&mut dialog, &reset_all);
        assert!(!page(&dialog).confirm_reset);

        let tmp = TempDir::new().unwrap();
        let mut dialog = populated_pointer_agents_dialog(&tmp);
        click_agent_action(&mut dialog, &reset_all);
        assert!(page(&dialog).confirm_reset);
        let cancel = super::super::pointer_actions::SettingsPointerAction::Agents(
            super::super::pointer_actions::AgentsAction::Cancel(
                super::super::pointer_actions::AgentId::reset_all(),
            ),
        );
        click_agent_action(&mut dialog, &cancel);
        assert!(!page(&dialog).confirm_reset);
        assert!(
            tmp.path().join(".cockpit/agents/pointer-agent.md").exists(),
            "cancelling ResetAll preserves configured agents"
        );

        let tmp = TempDir::new().unwrap();
        let mut dialog = overridden_pointer_agent_dialog(&tmp, "Build");
        let builtin = row_id(&dialog, "Build");
        let reset = super::super::pointer_actions::SettingsPointerAction::Agents(
            super::super::pointer_actions::AgentsAction::Reset(builtin.clone()),
        );
        let cancel = super::super::pointer_actions::SettingsPointerAction::Agents(
            super::super::pointer_actions::AgentsAction::Cancel(builtin),
        );
        click_agent_action(&mut dialog, &reset);
        assert!(page(&dialog).reset_one.is_pending());
        assert!(tmp.path().join(".cockpit/agents/Build.md").exists());
        click_agent_action(&mut dialog, &cancel);
        assert!(!page(&dialog).reset_one.is_pending());
        assert!(
            tmp.path().join(".cockpit/agents/Build.md").exists(),
            "cancelling one-agent reset preserves its override"
        );

        let tmp = TempDir::new().unwrap();
        let mut dialog = overridden_pointer_agent_dialog(&tmp, "Build");
        let builtin = row_id(&dialog, "Build");
        let reset = super::super::pointer_actions::SettingsPointerAction::Agents(
            super::super::pointer_actions::AgentsAction::Reset(builtin),
        );
        click_agent_action(&mut dialog, &reset);
        assert!(page(&dialog).reset_one.is_pending());
        click_agent_action(&mut dialog, &reset);
        assert!(!page(&dialog).reset_one.is_pending());
        assert!(
            !tmp.path().join(".cockpit/agents/Build.md").exists(),
            "the matching second Reset removes exactly the stable override"
        );

        // The structured tool surface editor (ToggleTool / CycleTier /
        // Save / OpenRawEditor) is intentionally unavailable for
        // schemaVersion 2 agents: tool authority is host-owned.  These
        // pointer interactions were exercised when the detail page opened
        // for v1 agents; v2 agents redirect to the raw editor instead.
    }

    #[test]
    fn external_editor_staging_is_a_private_regular_file() {
        let staging = agent_external_edit_staging().expect("create isolated staging file");
        seed_agent_external_edit_staging(&staging, "draft").unwrap();
        let directory = fs::symlink_metadata(staging.directory.path()).unwrap();
        assert!(directory.is_dir());
        assert!(!directory.file_type().is_symlink());
        let metadata = fs::symlink_metadata(&staging.path).unwrap();
        assert!(metadata.is_file());
        assert!(!metadata.file_type().is_symlink());
    }

    #[test]
    fn reset_all_confirm_removes_overrides() {
        let _g = EditorEnv::unset();
        let tmp = TempDir::new().unwrap();
        let mut d = agents_dialog(&tmp);
        // Eject one built-in (via edit, then cancel) and add a custom agent.
        focus(&mut d, "Build");
        d.handle_key(press(KeyCode::Char('e'))); // open in-TUI editor (ejects)
        d.handle_key(press(KeyCode::Esc)); // cancel editor
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::write(
            agents_dir.join("my-reviewer.md"),
            vnext_workspace_agent("my-reviewer", "r", "b"),
        )
        .unwrap();
        // Refresh the page so it sees the custom agent.
        if let TestPageMut::Agents(p) = d.test_page_mut() {
            *p = AgentsPage::new(tmp.path());
        }
        // `R` then `y` resets.
        d.handle_key(press(KeyCode::Char('R')));
        assert!(page(&d).confirm_reset);
        d.handle_key(press(KeyCode::Char('y')));
        assert!(!page(&d).confirm_reset);
        assert!(
            !agents_dir.join("Build.md").exists(),
            "built-in override removed"
        );
        assert!(
            agents_dir.join("my-reviewer.md").exists(),
            "custom agent kept"
        );
    }

    /// A Ctrl+S key, used by the save test.
    fn ctrl_s() -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char('s'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }
}
