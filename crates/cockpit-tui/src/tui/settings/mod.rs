#![allow(dead_code)]
#![allow(private_interfaces)]
//! `/settings` dialog state machine + rendering.
//!
//! Lifecycle:
//!   - `Dialog::None`            no overlay; viewport renders normally
//!   - `Dialog::PickConfig`      choose an existing config to edit
//!   - `Dialog::CreateConfig`    no config yet — pick a location to scaffold
//!   - `Dialog::Settings`        navigate the settings tree
//!
//! The Settings page tree (root has 16 nodes; see `root_nodes()`):
//!
//! ```text
//! Root
//!  ├── Default model for new sessions
//!  ├── Providers
//!  │    ├── List ──── Add Provider wizard ─── (template -> URL -> Auth -> save)
//!  │    │           └── Edit Provider page
//!  │    └── FetchAll dialog (triggered by /fetch-models)
//!  ├── Dependencies (read-only health)
//!  ├── Agents
//!  ├── Interface          ┐
//!  ├── Behavior           │ category pages
//!  ├── Privacy & Safety   │ (descriptor list + optional picker)
//!  ├── Translation        │
//!  ├── Profile            ┘
//!  ├── Image spend budgets
//!  ├── Generation
//!  ├── Tools
//!  ├── Harnesses
//!  ├── Skills
//!  ├── MCP
//!  └── LSP
//! ```
//!
//! Async fetches (the `/models` endpoint after Save, or via the Edit
//! page's `r`=refetch action) use [`FetchHandle`] — a shared cell the
//! background task writes into and the event loop reads on each tick.

mod agent_editor;
pub(crate) mod agents_page;
mod auth;
mod category;
mod dependencies_page;
mod descriptor;
mod grab;
mod harnesses_page;
mod image_generation;
mod image_spend;
mod lsp_page;
mod mcp_page;
mod multimodal_capability_editor;
#[cfg(test)]
mod pointer_acceptance_tests;
#[cfg(test)]
mod pointer_action_fixtures;
#[allow(dead_code)] // The registry is consumed incrementally by page fixture matrices.
pub(crate) mod pointer_actions;
mod providers;
mod reset;
pub(crate) mod secret_display;
mod settings_editor;
pub(crate) mod shell;
mod skills_page;
mod string_list;
mod tools_page;
mod ui_page;

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::tui::textfield::TextField;
use crate::tui::theme::MUTED_COLOR_INDEX;
use cockpit_config::dirs::{
    CONFIG_FILE, ConfigDir, ConfigDirKind, config_write_target_for_provider, creatable_config_dirs,
    cwd_scoped_creatable_dirs, discover_config_dirs,
};
use cockpit_config::extended::ExtendedConfig;
use cockpit_config::providers::{OnUnlistedModelsFetch, ProviderEntry, ProvidersConfig};

/// Settings-side operations that need provider secrets must use the persistent
/// daemon.  Keeping this tiny helper here makes accidental local vault opens
/// in settings code both unnecessary and easy for the boundary ratchet to
/// reject.
pub(crate) async fn settings_daemon_client()
-> anyhow::Result<cockpit_core::daemon::client::DaemonClient> {
    Ok(cockpit_core::daemon::client::ensure_persistent_daemon()
        .await?
        .client)
}

fn local_receipt_request_hash<T: serde::Serialize>(request: &T) -> Result<String, String> {
    use sha2::{Digest as _, Sha256};

    let encoded =
        zeroize::Zeroizing::new(serde_json::to_vec(request).map_err(|error| error.to_string())?);
    Ok(Sha256::digest(encoded.as_slice())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn hex_lower_for_authority(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn canonical_project_root(project_root: &std::path::Path) -> String {
    // Launch/session project roots are daemon-resolved before entering the
    // settings surface. Preserve that authority identity without performing
    // filesystem discovery in the synchronous reducer.
    project_root.to_string_lossy().to_string()
}

/// A daemon request emitted by a synchronous settings reducer. The target is
/// explicit authority context rather than display text, allowing the
/// completion reducer to reject stale results before interpreting the body.
#[derive(Debug)]
pub(crate) struct SettingsDaemonEffectRequest {
    pub(crate) dialog_id: uuid::Uuid,
    pub(crate) operation_id: uuid::Uuid,
    pub(crate) target: SettingsEffectTarget,
    pub(crate) work: SettingsDaemonEffectWork,
}

pub(crate) struct SettingsBlockingEffectRequest {
    pub(crate) dialog_id: uuid::Uuid,
    pub(crate) operation_id: uuid::Uuid,
    pub(crate) target: SettingsEffectTarget,
    pub(crate) work: SettingsBlockingEffectWork,
}

pub(crate) enum SettingsBlockingEffectWork {
    PrepareAgentEditor {
        staging_id: uuid::Uuid,
        seed: String,
    },
    ReadAgentEditor {
        staging_id: uuid::Uuid,
        directory_handle: std::fs::File,
        leaf: std::ffi::OsString,
    },
    PrepareCategoryEditor {
        staging_id: uuid::Uuid,
        seed: String,
    },
    ReadCategoryEditor {
        staging_id: uuid::Uuid,
        directory_handle: std::fs::File,
        leaf: std::ffi::OsString,
    },
}

impl std::fmt::Debug for SettingsBlockingEffectWork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrepareAgentEditor { staging_id, .. } => f
                .debug_struct("PrepareAgentEditor")
                .field("staging_id", staging_id)
                .field("seed", &"[DRAFT]")
                .finish(),
            Self::ReadAgentEditor {
                staging_id, leaf, ..
            } => f
                .debug_struct("ReadAgentEditor")
                .field("staging_id", staging_id)
                .field("leaf", leaf)
                .finish(),
            Self::PrepareCategoryEditor { staging_id, .. } => f
                .debug_struct("PrepareCategoryEditor")
                .field("staging_id", staging_id)
                .field("seed", &"[DRAFT]")
                .finish(),
            Self::ReadCategoryEditor {
                staging_id, leaf, ..
            } => f
                .debug_struct("ReadCategoryEditor")
                .field("staging_id", staging_id)
                .field("leaf", leaf)
                .finish(),
        }
    }
}

pub(crate) enum SettingsBlockingOutcome {
    AgentEditorPrepared {
        staging_id: uuid::Uuid,
        staging: agents_page::AgentExternalEditStaging,
    },
    AgentEditorRead {
        staging_id: uuid::Uuid,
        text: String,
    },
    CategoryEditorPrepared {
        staging_id: uuid::Uuid,
        staging: agents_page::AgentExternalEditStaging,
    },
    CategoryEditorRead {
        staging_id: uuid::Uuid,
        text: String,
    },
}

impl std::fmt::Debug for SettingsBlockingOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AgentEditorPrepared { staging_id, .. } => f
                .debug_struct("AgentEditorPrepared")
                .field("staging_id", staging_id)
                .field("staging", &"[PRIVATE STAGING]")
                .finish(),
            Self::AgentEditorRead { staging_id, text } => f
                .debug_struct("AgentEditorRead")
                .field("staging_id", staging_id)
                .field("bytes", &text.len())
                .finish(),
            Self::CategoryEditorPrepared { staging_id, .. } => f
                .debug_struct("CategoryEditorPrepared")
                .field("staging_id", staging_id)
                .field("staging", &"[PRIVATE STAGING]")
                .finish(),
            Self::CategoryEditorRead { staging_id, text } => f
                .debug_struct("CategoryEditorRead")
                .field("staging_id", staging_id)
                .field("bytes", &text.len())
                .finish(),
        }
    }
}

pub(crate) fn execute_settings_blocking_work(
    work: SettingsBlockingEffectWork,
) -> Result<SettingsBlockingOutcome, String> {
    match work {
        SettingsBlockingEffectWork::PrepareAgentEditor { staging_id, seed } => {
            let staging = agents_page::prepare_agent_external_edit_staging(&seed)?;
            Ok(SettingsBlockingOutcome::AgentEditorPrepared {
                staging_id,
                staging,
            })
        }
        SettingsBlockingEffectWork::ReadAgentEditor {
            staging_id,
            directory_handle,
            leaf,
        } => Ok(SettingsBlockingOutcome::AgentEditorRead {
            staging_id,
            text: agents_page::read_agent_external_edit_staging(&directory_handle, &leaf)?,
        }),
        SettingsBlockingEffectWork::PrepareCategoryEditor { staging_id, seed } => {
            let staging = agents_page::prepare_agent_external_edit_staging(&seed)?;
            Ok(SettingsBlockingOutcome::CategoryEditorPrepared {
                staging_id,
                staging,
            })
        }
        SettingsBlockingEffectWork::ReadCategoryEditor {
            staging_id,
            directory_handle,
            leaf,
        } => Ok(SettingsBlockingOutcome::CategoryEditorRead {
            staging_id,
            text: agents_page::read_agent_external_edit_staging(&directory_handle, &leaf)?,
        }),
    }
}

pub(crate) enum SettingsDaemonEffectWork {
    Request(Request),
    SettlementQuery(Request),
    ProviderCredentialPut {
        client_operation_id: String,
        provider_id: String,
        record: SecretPayload,
    },
    McpOAuthComplete {
        client_operation_id: String,
        flow_id: String,
        input: SecretPayload,
    },
    McpConfigSave {
        client_operation_id: String,
        project_root: String,
        config_json: String,
        secret_values_json: SecretPayload,
        cleanup_names_json: String,
    },
    ProviderMutation(ProviderMutationPlan),
    TypedDocumentEdit(TypedDocumentEditPlan),
}

pub(crate) struct SecretPayload(zeroize::Zeroizing<String>);

impl SecretPayload {
    pub(crate) fn new(value: String) -> Self {
        Self(zeroize::Zeroizing::new(value))
    }

    fn take(mut self) -> String {
        std::mem::take(&mut *self.0)
    }
}

impl std::fmt::Debug for SecretPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretPayload([REDACTED])")
    }
}

impl std::fmt::Debug for SettingsDaemonEffectWork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request(_) => f.write_str("Request([REDACTED BODY])"),
            Self::SettlementQuery(_) => f.write_str("SettlementQuery([REDACTED BODY])"),
            Self::ProviderCredentialPut { provider_id, .. } => f
                .debug_struct("ProviderCredentialPut")
                .field("provider_id", provider_id)
                .field("record", &"[REDACTED]")
                .finish(),
            Self::McpOAuthComplete { flow_id, .. } => f
                .debug_struct("McpOAuthComplete")
                .field("flow_id", flow_id)
                .field("input", &"[REDACTED]")
                .finish(),
            Self::McpConfigSave { project_root, .. } => f
                .debug_struct("McpConfigSave")
                .field("project_root", project_root)
                .field("secret_values_json", &"[REDACTED]")
                .finish(),
            Self::ProviderMutation(_) => f.write_str("ProviderMutation([REDACTED SECRETS])"),
            Self::TypedDocumentEdit(_) => f.write_str("TypedDocumentEdit([REDACTED PATCH])"),
        }
    }
}

pub(crate) struct ProviderMutationPlan {
    snapshot_session_id: String,
    layer_id: String,
    expected_revision: String,
    client_operation_id: String,
    saves: Vec<ProviderSavePlan>,
    deletes: Vec<(String, bool)>,
    metadata: Option<(
        BTreeMap<String, cockpit_config::config::providers::ProviderModelRef>,
        OnUnlistedModelsFetch,
    )>,
}

pub(crate) struct ProviderSavePlan {
    provider_id: String,
    entry: ProviderEntry,
    header_secrets: Vec<Option<zeroize::Zeroizing<String>>>,
}

impl std::fmt::Debug for ProviderMutationPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderMutationPlan")
            .field("snapshot_session_id", &self.snapshot_session_id)
            .field("layer_id", &self.layer_id)
            .field("expected_revision", &self.expected_revision)
            .field("client_operation_id", &self.client_operation_id)
            .field("save_count", &self.saves.len())
            .field("deletes", &self.deletes)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl std::fmt::Debug for ProviderSavePlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderSavePlan")
            .field("provider_id", &self.provider_id)
            .field("entry", &"[REDACTED HEADERS]")
            .field("header_secret_count", &self.header_secrets.len())
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct TypedDocumentEditPlan {
    project_root: String,
    requested_path: String,
    patch: serde_json::Value,
    snapshot_session_id: String,
}

#[derive(Debug)]
pub(crate) struct SettingsDaemonWorkOutcome {
    pub(crate) response: Result<Response, String>,
    pub(crate) committed_refresh_needed: Option<CommittedRefreshNeeded>,
}

#[derive(Debug, Clone)]
pub(crate) struct CommittedRefreshNeeded {
    pub(crate) result_revision: String,
    pub(crate) config_generation: u64,
    pub(crate) warning: String,
}

pub(crate) async fn execute_settings_daemon_work(
    work: SettingsDaemonEffectWork,
) -> Result<SettingsDaemonWorkOutcome, String> {
    let client = settings_daemon_client()
        .await
        .map_err(|error| error.to_string())?;
    match work {
        SettingsDaemonEffectWork::Request(request) => Ok(SettingsDaemonWorkOutcome {
            response: client
                .request(request)
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string()),
            committed_refresh_needed: None,
        }),
        SettingsDaemonEffectWork::SettlementQuery(request) => {
            let response =
                tokio::time::timeout(std::time::Duration::from_secs(15), client.request(request))
                    .await
                    .map_err(|_| "local operation settlement query timed out".to_string())?
                    .map_err(|error| error.to_string())?
                    .map_err(|error| error.to_string());
            Ok(SettingsDaemonWorkOutcome {
                response,
                committed_refresh_needed: None,
            })
        }
        SettingsDaemonEffectWork::ProviderCredentialPut {
            client_operation_id,
            provider_id,
            record,
        } => Ok(SettingsDaemonWorkOutcome {
            response: client
                .request(Request::PutProviderCredential {
                    client_operation_id,
                    provider_id,
                    record: cockpit_proto::SensitiveWirePayload::new(record.take()),
                })
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string()),
            committed_refresh_needed: None,
        }),
        SettingsDaemonEffectWork::McpOAuthComplete {
            client_operation_id,
            flow_id,
            input,
        } => Ok(SettingsDaemonWorkOutcome {
            response: client
                .request(Request::CompleteMcpOAuth {
                    client_operation_id,
                    flow_id,
                    input: Some(cockpit_proto::SensitiveWirePayload::new(input.take())),
                })
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string()),
            committed_refresh_needed: None,
        }),
        SettingsDaemonEffectWork::McpConfigSave {
            client_operation_id,
            project_root,
            config_json,
            secret_values_json,
            cleanup_names_json,
        } => Ok(SettingsDaemonWorkOutcome {
            response: client
                .request(Request::SaveMcpConfig {
                    client_operation_id,
                    project_root,
                    config_json,
                    secret_values_json: cockpit_proto::SensitiveWirePayload::new(
                        secret_values_json.take(),
                    ),
                    cleanup_names_json,
                })
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string()),
            committed_refresh_needed: None,
        }),
        SettingsDaemonEffectWork::ProviderMutation(plan) => {
            let mutation = cockpit_proto::ProviderMutationBatch {
                upserts: plan
                    .saves
                    .into_iter()
                    .map(|save| cockpit_proto::ProviderMutationUpsert {
                        provider_id: save.provider_id,
                        entry: save.entry,
                        header_secrets: save
                            .header_secrets
                            .into_iter()
                            .map(|secret| {
                                secret.map(|mut value| {
                                    cockpit_proto::ProviderSecretValue::new(std::mem::take(
                                        &mut *value,
                                    ))
                                })
                            })
                            .collect(),
                    })
                    .collect(),
                deletes: plan
                    .deletes
                    .into_iter()
                    .map(|(provider_id, delete_stored_secrets)| {
                        cockpit_proto::ProviderMutationDelete {
                            provider_id,
                            delete_stored_secrets,
                        }
                    })
                    .collect(),
                metadata: plan
                    .metadata
                    .map(|(category_defaults, on_unlisted_models_fetch)| {
                        cockpit_proto::ProviderLayerMetadataPatch {
                            category_defaults,
                            on_unlisted_models_fetch,
                        }
                    }),
            };
            let response = client
                .request(Request::ApplyProviderMutation {
                    snapshot_session_id: plan.snapshot_session_id,
                    layer_id: plan.layer_id,
                    expected_revision: plan.expected_revision,
                    client_operation_id: plan.client_operation_id,
                    mutation,
                })
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())?;
            Ok(SettingsDaemonWorkOutcome {
                response: Ok(response),
                committed_refresh_needed: None,
            })
        }
        SettingsDaemonEffectWork::TypedDocumentEdit(plan) => {
            let snapshot = client
                .request(Request::GetExtendedConfigSnapshot {
                    project_root: plan.project_root.clone(),
                    snapshot_session_id: plan.snapshot_session_id.clone(),
                })
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())?;
            let Response::ExtendedConfigSnapshot { layers, .. } = snapshot else {
                return Err(format!(
                    "unexpected typed-edit snapshot response: {snapshot:?}"
                ));
            };
            let layer = layers
                .into_iter()
                .find(|layer| layer.display_path == plan.requested_path)
                .ok_or_else(|| {
                    "typed settings target is not a daemon-discovered layer".to_string()
                })?;
            let mut document =
                serde_json::to_value(&layer.config).map_err(|error| error.to_string())?;
            apply_json_merge_patch_local(&mut document, plan.patch);
            let desired: ExtendedConfig = serde_json::from_value(document)
                .map_err(|error| format!("invalid typed settings edit: {error}"))?;
            let base = serde_json::to_value(&layer.config).map_err(|error| error.to_string())?;
            let desired_value =
                serde_json::to_value(&desired).map_err(|error| error.to_string())?;
            let operations = changed_extended_paths(&base, &desired_value)?;
            let expected_layer_id = layer.layer_id.clone();
            let expected_layer_kind = layer.kind;
            let expected_revision = layer.revision.clone();
            let response = client
                .request(Request::ApplyExtendedConfigPatch {
                    project_root: plan.project_root.clone(),
                    layer_id: expected_layer_id.clone(),
                    patch: cockpit_core::daemon::proto::ExtendedConfigPatch {
                        operations,
                        materialize: true,
                        denylist: Vec::new(),
                        redacted_mutations: Vec::new(),
                    },
                    expected_revision: expected_revision.clone(),
                    snapshot_session_id: plan.snapshot_session_id.clone(),
                })
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())?;
            let (result_revision, result_generation) = match response {
                Response::ExtendedConfigSaved {
                    hash,
                    layer_id,
                    layer,
                    consumed_revision,
                    result_revision,
                    status: cockpit_core::daemon::proto::ConfigCommitStatus::Committed,
                    config_generation,
                    ..
                } if layer_id == expected_layer_id
                    && layer == expected_layer_kind
                    && consumed_revision == expected_revision
                    && hash == result_revision
                    && cockpit_proto::is_opaque_authority_token(&result_revision) =>
                {
                    (result_revision, config_generation)
                }
                other => return Err(format!("unexpected typed-edit commit response: {other:?}")),
            };
            let refreshed = client
                .request(Request::GetExtendedConfigSnapshot {
                    project_root: plan.project_root,
                    snapshot_session_id: plan.snapshot_session_id,
                })
                .await
                .map_err(|error| error.to_string())
                .and_then(|response| response.map_err(|error| error.to_string()));
            match &refreshed {
                Ok(Response::ExtendedConfigSnapshot { layers, .. })
                    if layers.iter().any(|layer| {
                        layer.display_path == plan.requested_path
                            && layer.layer_id == expected_layer_id
                            && layer.revision == result_revision
                    }) =>
                {
                    Ok(SettingsDaemonWorkOutcome {
                        response: refreshed,
                        committed_refresh_needed: None,
                    })
                }
                _ => Ok(SettingsDaemonWorkOutcome {
                    response: Err(
                        "typed settings edit committed, but authoritative refresh did not reconcile"
                            .into(),
                    ),
                    committed_refresh_needed: Some(CommittedRefreshNeeded {
                        result_revision,
                        config_generation: result_generation,
                        warning: "settings committed, but the authoritative refresh did not reconcile; reload before editing again".into(),
                    }),
                }),
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SettingsEffectTarget {
    pub(crate) surface: &'static str,
    pub(crate) owner: String,
    pub(crate) revision: Option<String>,
}

#[derive(Debug)]
pub(crate) struct SettingsDaemonEffectCompletion {
    pub(crate) dialog_id: uuid::Uuid,
    pub(crate) operation_id: uuid::Uuid,
    pub(crate) target: SettingsEffectTarget,
    pub(crate) response: Result<Response, String>,
    pub(crate) committed_refresh_needed: Option<CommittedRefreshNeeded>,
}

#[derive(Debug)]
pub(crate) struct SettingsBlockingEffectCompletion {
    pub(crate) dialog_id: uuid::Uuid,
    pub(crate) operation_id: uuid::Uuid,
    pub(crate) target: SettingsEffectTarget,
    pub(crate) outcome: Result<SettingsBlockingOutcome, String>,
}

#[derive(Debug, Clone)]
pub(crate) struct SettingsBlockingEffectMetadata {
    pub(crate) dialog_id: uuid::Uuid,
    pub(crate) operation_id: uuid::Uuid,
    pub(crate) target: SettingsEffectTarget,
}

/// Run a short daemon RPC from an input reducer. Production reducers execute
/// beneath the application's multi-thread Tokio runtime. Unit reducers are
/// intentionally synchronous, so give those tests the same daemon boundary
/// instead of panicking before the request can be exercised.
#[cfg(test)]
fn run_settings_daemon<T>(
    future: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if matches!(
            handle.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        ) {
            return tokio::task::block_in_place(|| handle.block_on(future));
        }
        return Err("settings daemon RPC requires a multi-thread application runtime".to_string());
    }
    #[cfg(test)]
    {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?
            .block_on(future)
    }
    #[cfg(not(test))]
    Err("settings daemon RPC requires the application runtime".to_string())
}

/// Injectable transport boundary for settings daemon effects.  Both the real
/// client and tests feed responses through the same snapshot/patch/receipt
/// validation below; a test double may replace only transport, never config
/// loading or persistence.
#[cfg(test)]
trait SettingsDaemonEffect: Send + Sync {
    fn request(&self, request: Request) -> Result<Response, String>;
}

#[cfg(test)]
struct ProductionSettingsDaemonEffect;

#[cfg(test)]
impl SettingsDaemonEffect for ProductionSettingsDaemonEffect {
    fn request(&self, request: Request) -> Result<Response, String> {
        run_settings_daemon(async move {
            let client = settings_daemon_client()
                .await
                .map_err(|error| error.to_string())?;
            client
                .request(request)
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())
        })
    }
}

#[cfg(test)]
thread_local! {
    static TEST_SETTINGS_DAEMON_EFFECT: std::cell::RefCell<Option<Arc<dyn SettingsDaemonEffect>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn settings_daemon_request(request: Request) -> Result<Response, String> {
    #[cfg(test)]
    if let Some(effect) = TEST_SETTINGS_DAEMON_EFFECT.with(|slot| slot.borrow().clone()) {
        return effect.request(request);
    }
    ProductionSettingsDaemonEffect.request(request)
}

#[cfg(test)]
fn with_settings_daemon_effect<T>(
    effect: Arc<dyn SettingsDaemonEffect>,
    operation: impl FnOnce() -> T,
) -> T {
    struct Reset(Option<Arc<dyn SettingsDaemonEffect>>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_SETTINGS_DAEMON_EFFECT.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let previous = TEST_SETTINGS_DAEMON_EFFECT.with(|slot| slot.replace(Some(effect)));
    let _reset = Reset(previous);
    operation()
}

fn config_layer_request(
    _path: &std::path::Path,
    project_root: Option<&std::path::Path>,
) -> Result<String, String> {
    let cwd = std::env::current_dir().ok();
    let request_root = project_root.or(cwd.as_deref());
    request_root
        .map(|root| root.display().to_string())
        .ok_or_else(|| "settings request has no workspace root".to_string())
}

fn settings_snapshot_session_id() -> &'static str {
    static ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ID.get_or_init(|| uuid::Uuid::new_v4().to_string())
}

const DENYLIST_EXISTING_DRAFT_PREFIX: &str = "__cockpit_existing_denylist_occurrence_v1:";

enum DenylistDraftEntry<'a> {
    Existing(&'a str),
    New(&'a str),
}

fn denylist_draft_entry(value: &str) -> Result<DenylistDraftEntry<'_>, String> {
    match value.strip_prefix(DENYLIST_EXISTING_DRAFT_PREFIX) {
        Some("") => Err("denylist draft contains an empty occurrence token".into()),
        Some(entry_id) => Ok(DenylistDraftEntry::Existing(entry_id)),
        None => Ok(DenylistDraftEntry::New(value)),
    }
}

fn existing_denylist_draft(entry_id: &str) -> String {
    format!("{DENYLIST_EXISTING_DRAFT_PREFIX}{entry_id}")
}

#[cfg(test)]
fn extended_config_layer_snapshot(
    path: &std::path::Path,
    project_root: Option<&std::path::Path>,
) -> Result<(ExtendedConfig, serde_json::Value, String), String> {
    let project_root = config_layer_request(path, project_root)?;
    let requested_path = path.display().to_string();
    match settings_daemon_request(Request::GetExtendedConfigSnapshot {
        project_root,
        snapshot_session_id: settings_snapshot_session_id().to_owned(),
    })? {
        Response::ExtendedConfigSnapshot {
            layers,
            config_generation,
        } => {
            let layer = layers
                .into_iter()
                .find(|layer| layer.display_path == requested_path)
                .ok_or_else(|| "settings target is not a daemon-discovered layer".to_string())?;
            decode_extended_layer(layer, config_generation)
        }
        other => Err(format!("unexpected settings snapshot response: {other:?}")),
    }
}

fn decode_extended_layer(
    layer: cockpit_core::daemon::proto::ExtendedConfigLayerSnapshot,
    config_generation: u64,
) -> Result<(ExtendedConfig, serde_json::Value, String), String> {
    let layer_uuid = uuid::Uuid::parse_str(&layer.layer_id)
        .map_err(|_| "settings layer capability is malformed".to_string())?;
    if layer_uuid.to_string() != layer.layer_id
        || !cockpit_proto::is_opaque_authority_token(&layer.revision)
    {
        return Err("settings layer authority tokens are malformed".into());
    }
    let mut denylist_ids = std::collections::HashSet::new();
    if layer.denylist.iter().any(|entry| {
        !cockpit_proto::is_opaque_authority_token(&entry.entry_id)
            || entry.display_mask != cockpit_proto::REDACTED_DENYLIST_MASK
            || !denylist_ids.insert(entry.entry_id.as_str())
    }) {
        return Err("settings denylist snapshot contains invalid occurrence tokens".into());
    }
    let mut config = *layer.config;
    let denylist = layer.denylist;
    let revision = layer.revision;
    let authored_paths = layer.authored_paths;
    config.redact.denylist = denylist
        .iter()
        .map(|entry| existing_denylist_draft(&entry.entry_id))
        .collect();
    let mut value = serde_json::to_value(&config).map_err(|error| error.to_string())?;
    value
        .as_object_mut()
        .expect("ExtendedConfig serializes as object")
        .insert(
            "__cockpit_denylist_entries".into(),
            serde_json::to_value(denylist).map_err(|error| error.to_string())?,
        );
    value
        .as_object_mut()
        .expect("ExtendedConfig serializes as object")
        .insert(
            "__cockpit_settings_authored_paths".into(),
            serde_json::to_value(authored_paths).map_err(|error| error.to_string())?,
        );
    value
        .as_object_mut()
        .expect("ExtendedConfig serializes as object")
        .insert(
            "__cockpit_settings_layer_kind".into(),
            serde_json::to_value(layer.kind).map_err(|error| error.to_string())?,
        );
    value
        .as_object_mut()
        .expect("ExtendedConfig serializes as object")
        .insert(
            "__cockpit_settings_generation".into(),
            serde_json::Value::Number(config_generation.into()),
        );
    value
        .as_object_mut()
        .expect("ExtendedConfig serializes as object")
        .insert(
            "__cockpit_settings_layer_id".into(),
            serde_json::Value::String(layer.layer_id),
        );
    Ok((config, value, revision))
}

#[derive(Debug, Clone)]
pub(super) enum SettingsPatchOutcome {
    Reconciled {
        layer: cockpit_core::daemon::proto::ExtendedConfigLayerSnapshot,
        config_generation: u64,
    },
    CommittedRefreshNeeded {
        result_revision: String,
        config_generation: u64,
        warning: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SettingsSaveOutcome {
    Saved,
    Queued,
    CommittedRefreshNeeded(String),
}

enum PendingSettingsOperation {
    ExtendedLoad {
        requested_path: String,
        project_root: String,
        snapshot_session_id: String,
    },
    ExtendedSave {
        requested_path: String,
        project_root: String,
        snapshot_session_id: String,
        layer_id: String,
        expected_layer: cockpit_core::daemon::proto::CockpitConfigLayer,
        expected_revision: String,
        expected_generation: u64,
        operations: Vec<cockpit_core::daemon::proto::ExtendedConfigPathMutation>,
        denylist_plan: Vec<cockpit_core::daemon::proto::DesiredDenylistEntry>,
    },
    ExtendedRefresh {
        target: SettingsEffectTarget,
        requested_path: String,
        expected_layer: cockpit_core::daemon::proto::CockpitConfigLayer,
        result_revision: String,
        result_generation: u64,
        operations: Vec<cockpit_core::daemon::proto::ExtendedConfigPathMutation>,
        committed_denylist: Vec<cockpit_core::daemon::proto::CommittedDenylistEntry>,
        warning: Option<String>,
    },
    ProviderCatalog {
        project_root: String,
        provider_id: Option<String>,
        snapshot_session_id: String,
        navigation: Option<ProviderNavigation>,
    },
    ProjectShadowSnapshot {
        target: SettingsEffectTarget,
        prompt: category::ShadowedGlobalPrompt,
    },
    ProviderMutation {
        target: SettingsEffectTarget,
        client_operation_id: String,
        snapshot_session_id: String,
        layer_id: String,
        expected_revision: String,
        expected_generation: u64,
        staged_default: Option<cockpit_config::config::providers::ActiveModelRef>,
        notice: Option<String>,
    },
    Followup {
        label: &'static str,
        target: SettingsEffectTarget,
    },
    SimpleMutation {
        target: SettingsEffectTarget,
        action: SettingsMutationAction,
    },
    SettlementQuery {
        target: SettingsEffectTarget,
        client_operation_id: String,
        original: Box<PendingSettingsOperation>,
    },
    SettlementUnknown {
        target: SettingsEffectTarget,
        client_operation_id: String,
        original: Box<PendingSettingsOperation>,
    },
    TypedDocumentEdit {
        target: SettingsEffectTarget,
        requested_path: String,
        action: TypedDocumentEditAction,
    },
    CategoryExternalPrepare {
        target: SettingsEffectTarget,
        pointer_operation_id: shell::PointerOperationId,
        staging_id: uuid::Uuid,
    },
    CategoryExternalRead {
        target: SettingsEffectTarget,
        pointer_operation_id: shell::PointerOperationId,
        staging_id: uuid::Uuid,
        outcome: pointer_actions::ExternalEditOutcome,
        detail: Option<String>,
    },
}

impl PendingSettingsOperation {
    fn target(&self) -> SettingsEffectTarget {
        match self {
            Self::ExtendedLoad {
                requested_path,
                snapshot_session_id,
                ..
            } => SettingsEffectTarget {
                surface: "settings.extended-load",
                owner: requested_path.clone(),
                revision: Some(snapshot_session_id.clone()),
            },
            Self::ExtendedSave {
                layer_id,
                expected_revision,
                ..
            } => SettingsEffectTarget {
                surface: "settings.extended-save",
                owner: layer_id.clone(),
                revision: Some(expected_revision.clone()),
            },
            Self::ExtendedRefresh { target, .. }
            | Self::ProjectShadowSnapshot { target, .. }
            | Self::ProviderMutation { target, .. }
            | Self::Followup { target, .. }
            | Self::SimpleMutation { target, .. }
            | Self::SettlementQuery { target, .. }
            | Self::SettlementUnknown { target, .. }
            | Self::TypedDocumentEdit { target, .. }
            | Self::CategoryExternalPrepare { target, .. }
            | Self::CategoryExternalRead { target, .. } => target.clone(),
            Self::ProviderCatalog {
                project_root,
                provider_id,
                snapshot_session_id,
                ..
            } => SettingsEffectTarget {
                surface: "settings.provider-catalog",
                owner: format!(
                    "{}::{}",
                    project_root,
                    provider_id.as_deref().unwrap_or("*")
                ),
                revision: Some(snapshot_session_id.clone()),
            },
        }
    }

    fn target_matches(&self, actual: &SettingsEffectTarget) -> bool {
        self.target() == *actual
    }
}

#[derive(Clone)]
enum ProviderNavigation {
    Edit {
        provider_id: String,
        oauth_expired: bool,
    },
    Models {
        provider_id: String,
    },
}

enum ProviderMutationNavigation {
    List { status: String },
    Edit { provider_id: String, status: String },
}

enum TypedDocumentEditAction {
    Scaffold,
    RemoveProjectShadow(category::ShadowedGlobalPrompt),
}

#[derive(Clone)]
enum SettingsMutationAction {
    McpSave {
        config: cockpit_core::mcp::config::McpConfig,
        client_operation_id: String,
        project_root: String,
        expected_owner_root: String,
        expected_config_path: String,
        expected_consumed_revision: String,
        expected_result_revision: String,
    },
    McpOAuthBegin {
        server: String,
        client_operation_id: String,
        expected_request_hash: String,
    },
    McpOAuthComplete {
        server: String,
        flow_id: String,
        client_operation_id: String,
        expected_request_hash: String,
    },
    McpOAuthCancel {
        server: String,
        flow_id: String,
        client_operation_id: String,
        expected_request_hash: String,
    },
    ProviderCredentialDelete {
        provider_id: String,
        client_operation_id: String,
        project_root: String,
    },
    ProviderCredentialPut {
        provider_id: String,
        client_operation_id: String,
    },
    WebCredentialPut {
        provider_id: String,
        client_operation_id: String,
    },
    CopilotSetup {
        provider_id: String,
        client_operation_id: String,
        project_root: String,
    },
}

impl SettingsMutationAction {
    fn settlement_id(&self) -> Option<&str> {
        match self {
            Self::McpSave {
                client_operation_id,
                ..
            }
            | Self::McpOAuthBegin {
                client_operation_id,
                ..
            }
            | Self::McpOAuthComplete {
                client_operation_id,
                ..
            }
            | Self::McpOAuthCancel {
                client_operation_id,
                ..
            }
            | Self::ProviderCredentialDelete {
                client_operation_id,
                ..
            }
            | Self::ProviderCredentialPut {
                client_operation_id,
                ..
            }
            | Self::WebCredentialPut {
                client_operation_id,
                ..
            }
            | Self::CopilotSetup {
                client_operation_id,
                ..
            } => Some(client_operation_id),
            _ => None,
        }
    }

    fn matches_durable_receipt(&self, response: &Response) -> bool {
        match (self, response) {
            (
                Self::McpOAuthBegin {
                    client_operation_id,
                    expected_request_hash,
                    ..
                },
                Response::McpOAuthStarted {
                    client_operation_id: returned_id,
                    request_hash,
                    ..
                },
            ) => returned_id == client_operation_id && request_hash == expected_request_hash,
            (
                Self::McpOAuthComplete {
                    client_operation_id,
                    flow_id,
                    expected_request_hash,
                    ..
                },
                Response::McpOAuthCompleted {
                    client_operation_id: returned_id,
                    request_hash,
                    flow_id: returned_flow,
                    ..
                },
            ) => {
                returned_id == client_operation_id
                    && request_hash == expected_request_hash
                    && returned_flow == flow_id
            }
            (
                Self::McpOAuthCancel {
                    client_operation_id,
                    flow_id,
                    expected_request_hash,
                    ..
                },
                Response::McpOAuthCancelled {
                    client_operation_id: returned_id,
                    request_hash,
                    flow_id: Some(returned_flow),
                    ..
                },
            ) => {
                returned_id == client_operation_id
                    && request_hash == expected_request_hash
                    && returned_flow == flow_id
            }
            (
                Self::McpSave {
                    client_operation_id,
                    project_root,
                    expected_owner_root,
                    expected_config_path,
                    expected_consumed_revision,
                    expected_result_revision,
                    ..
                },
                Response::McpConfigCommitted {
                    client_operation_id: returned_id,
                    request_hash,
                    project_root: returned_root,
                    owner_root,
                    config_path,
                    consumed_revision,
                    result_revision,
                    config_generation,
                    ..
                },
            ) => {
                returned_id == client_operation_id
                    && returned_root == project_root
                    && owner_root == expected_owner_root
                    && config_path == expected_config_path
                    && consumed_revision == expected_consumed_revision
                    && result_revision == expected_result_revision
                    && cockpit_proto::is_opaque_authority_token(request_hash)
                    && *config_generation > 0
            }
            (
                Self::ProviderCredentialDelete {
                    provider_id,
                    client_operation_id,
                    project_root,
                },
                Response::ProviderCredentialCommitted {
                    client_operation_id: returned_id,
                    provider_id: returned_provider,
                    project_root: Some(returned_root),
                    owner_root: Some(owner_root),
                    owner_scope,
                    stored: false,
                    changed,
                    consumed_vault_generation,
                    result_vault_generation,
                    config_generation,
                    ..
                },
            ) => {
                returned_id == client_operation_id
                    && returned_provider == provider_id
                    && returned_root == project_root
                    && owner_root == project_root
                    && owner_scope == &format!("project:{owner_root}")
                    && *config_generation > 0
                    && valid_vault_freshness(
                        *consumed_vault_generation,
                        *result_vault_generation,
                        *changed,
                    )
            }
            (
                Self::ProviderCredentialPut {
                    provider_id,
                    client_operation_id,
                }
                | Self::WebCredentialPut {
                    provider_id,
                    client_operation_id,
                },
                Response::ProviderCredentialCommitted {
                    client_operation_id: returned_id,
                    provider_id: returned_provider,
                    project_root: None,
                    owner_root: None,
                    owner_scope,
                    stored: true,
                    changed,
                    consumed_vault_generation,
                    result_vault_generation,
                    config_generation,
                    ..
                },
            ) => {
                returned_id == client_operation_id
                    && returned_provider == provider_id
                    && owner_scope == "global"
                    && *config_generation > 0
                    && valid_vault_freshness(
                        *consumed_vault_generation,
                        *result_vault_generation,
                        *changed,
                    )
            }
            (
                Self::CopilotSetup {
                    provider_id,
                    client_operation_id,
                    project_root,
                },
                Response::CopilotAuthCommitted {
                    client_operation_id: returned_id,
                    provider_id: returned_provider,
                    project_root: returned_root,
                    owner_root,
                    owner_scope,
                    consumed_vault_generation,
                    result_vault_generation,
                    config_generation,
                    ..
                },
            ) => {
                returned_id == client_operation_id
                    && returned_provider == provider_id
                    && returned_root == project_root
                    && owner_root == project_root
                    && owner_scope == &format!("project:{owner_root}")
                    && *config_generation > 0
                    && *result_vault_generation > *consumed_vault_generation
                    && *result_vault_generation > 0
            }
            _ => false,
        }
    }
}

fn valid_vault_freshness(consumed: u64, result: u64, changed: bool) -> bool {
    result > 0
        && if changed {
            result > consumed
        } else {
            result == consumed
        }
}

enum CompletedProviderAuthMutation {
    Logout {
        provider_id: String,
        result: Result<bool, String>,
    },
    Copilot {
        provider_id: String,
        result: Result<bool, String>,
    },
}

enum PendingMcpOAuth {
    Started {
        server: String,
        begin_client_operation_id: String,
        flow_id: String,
        authorize_url: String,
    },
    Completed {
        server: String,
        flow_id: String,
    },
    Cancelled {
        server: String,
        flow_id: String,
    },
}

#[cfg(test)]
fn apply_settings_patch_via_daemon(
    path: &std::path::Path,
    project_root: Option<&std::path::Path>,
    base: &serde_json::Value,
    desired: &ExtendedConfig,
    revision: &str,
) -> Result<SettingsPatchOutcome, String> {
    let desired_value = serde_json::to_value(desired).map_err(|error| error.to_string())?;
    let operations = changed_extended_paths(base, &desired_value)?;
    let denylist = denylist_mutations(base, &desired.redact.denylist)?;
    let denylist_receipt_plan = denylist.clone();
    let patch = cockpit_core::daemon::proto::ExtendedConfigPatch {
        operations: operations.clone(),
        materialize: false,
        denylist,
        redacted_mutations: Vec::new(),
    };
    let project_root = config_layer_request(path, project_root)?;
    let layer_id = base
        .get("__cockpit_settings_layer_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "settings snapshot omitted its layer capability".to_string())?
        .to_owned();
    let expected_revision = revision.to_string();
    let expected_layer = serde_json::from_value(
        base.get("__cockpit_settings_layer_kind")
            .cloned()
            .ok_or_else(|| "settings snapshot omitted its layer kind".to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let expected_generation = base
        .get("__cockpit_settings_generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "settings snapshot omitted its config generation".to_string())?;
    let requested_path = path.display().to_string();
    let response = settings_daemon_request(Request::ApplyExtendedConfigPatch {
        project_root: project_root.clone(),
        layer_id: layer_id.clone(),
        patch,
        expected_revision: expected_revision.clone(),
        snapshot_session_id: settings_snapshot_session_id().to_owned(),
    });
    let (result_revision, result_generation, committed_denylist, warning) = match response {
        Ok(Response::ExtendedConfigSaved {
            hash,
            config_generation,
            layer_id: returned_layer_id,
            layer,
            consumed_revision,
            result_revision,
            status: cockpit_core::daemon::proto::ConfigCommitStatus::Committed,
            publication,
            denylist: committed_denylist,
        }) if returned_layer_id == layer_id
            && layer == expected_layer
            && consumed_revision == expected_revision
            && hash == result_revision
            && cockpit_proto::is_opaque_authority_token(&result_revision)
            && validate_committed_denylist(&denylist_receipt_plan, &committed_denylist).is_ok()
            && (config_generation == expected_generation
                || config_generation == expected_generation.saturating_add(1)) =>
        {
            let warning = (publication
                == cockpit_core::daemon::proto::ConfigPublicationStatus::Degraded)
                .then(|| "settings committed, but redaction publication is degraded; restart the daemon before continuing".to_string());
            (
                result_revision,
                config_generation,
                committed_denylist,
                warning,
            )
        }
        Ok(other) => Err(format!("unexpected settings patch response: {other:?}")),
        Err(error) => Err(error.to_string()),
    }?;
    let refresh = settings_daemon_request(Request::GetExtendedConfigSnapshot {
        project_root,
        snapshot_session_id: settings_snapshot_session_id().to_owned(),
    });
    match refresh {
        Ok(Response::ExtendedConfigSnapshot {
            layers,
            config_generation,
        }) if warning.is_none()
            && config_generation == result_generation =>
        {
            let layer = layers.into_iter().find(|layer| {
                layer.display_path == requested_path
                    && layer.kind == expected_layer
                    && layer.revision == result_revision
                    && same_denylist_occurrences(&layer.denylist, &committed_denylist)
                    && validate_settings_operations(
                        &operations,
                        &serde_json::to_value(&layer.config).unwrap_or(serde_json::Value::Null),
                        &layer.authored_paths,
                    ).is_ok()
            });
            match layer {
                Some(layer) => Ok(SettingsPatchOutcome::Reconciled { layer, config_generation }),
                None => Ok(SettingsPatchOutcome::CommittedRefreshNeeded {
                    result_revision,
                    config_generation: result_generation,
                    warning: "settings committed, but the authoritative refresh did not contain the exact committed layer; reload before editing again".into(),
                }),
            }
        }
        other => Ok(SettingsPatchOutcome::CommittedRefreshNeeded {
            result_revision,
            config_generation: result_generation,
            warning: warning.unwrap_or_else(|| format!(
                "settings committed at generation {result_generation}, but the authoritative refresh did not reconcile ({other:?}); reload before editing again"
            )),
        }),
    }
}

#[cfg(test)]
pub(super) fn apply_typed_settings_document_edit(
    path: &std::path::Path,
    project_root: Option<&std::path::Path>,
    patch: serde_json::Value,
) -> Result<SettingsPatchOutcome, String> {
    let (_, mut document, revision) = extended_config_layer_snapshot(path, project_root)?;
    let authority_base = document.clone();
    apply_json_merge_patch_local(&mut document, patch);
    let desired: ExtendedConfig = serde_json::from_value(document)
        .map_err(|error| format!("invalid typed settings edit: {error}"))?;
    let desired_value = serde_json::to_value(&desired).map_err(|error| error.to_string())?;
    // Derive authority operations from the actual RFC 7396 result. In
    // particular an empty object is a no-op when the authored value is
    // already an object; it is never serialized as a destructive Set({}).
    let operations = changed_extended_paths(&authority_base, &desired_value)?;
    let denylist = denylist_mutations(&authority_base, &desired.redact.denylist)?;
    let denylist_receipt_plan = denylist.clone();
    let patch = cockpit_core::daemon::proto::ExtendedConfigPatch {
        operations: operations.clone(),
        materialize: true,
        denylist,
        redacted_mutations: Vec::new(),
    };
    let project_root = config_layer_request(path, project_root)?;
    let layer_id = authority_base
        .get("__cockpit_settings_layer_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "settings snapshot omitted its layer capability".to_string())?
        .to_owned();
    let expected_layer = serde_json::from_value(
        authority_base
            .get("__cockpit_settings_layer_kind")
            .cloned()
            .ok_or_else(|| "settings snapshot omitted its layer kind".to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let expected_generation = authority_base
        .get("__cockpit_settings_generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "settings snapshot omitted its config generation".to_string())?;
    let requested_path = path.display().to_string();
    let response = settings_daemon_request(Request::ApplyExtendedConfigPatch {
        project_root: project_root.clone(),
        layer_id: layer_id.clone(),
        patch,
        expected_revision: revision.clone(),
        snapshot_session_id: settings_snapshot_session_id().to_owned(),
    });
    let (result_revision, result_generation, committed_denylist, warning) = match response {
        Ok(Response::ExtendedConfigSaved {
            hash,
            config_generation,
            layer_id: returned_layer_id,
            layer,
            consumed_revision,
            result_revision,
            status: cockpit_core::daemon::proto::ConfigCommitStatus::Committed,
            publication,
            denylist: committed_denylist,
        }) if returned_layer_id == layer_id
            && layer == expected_layer
            && consumed_revision == revision
            && hash == result_revision
            && cockpit_proto::is_opaque_authority_token(&result_revision)
            && validate_committed_denylist(&denylist_receipt_plan, &committed_denylist).is_ok()
            && (config_generation == expected_generation
                || config_generation == expected_generation.saturating_add(1)) =>
        {
            let warning = (publication
                == cockpit_core::daemon::proto::ConfigPublicationStatus::Degraded)
                .then(|| "settings committed, but redaction publication is degraded; restart the daemon before continuing".to_string());
            (
                result_revision,
                config_generation,
                committed_denylist,
                warning,
            )
        }
        Ok(other) => Err(format!("unexpected settings edit response: {other:?}")),
        Err(error) => Err(error.to_string()),
    }?;
    let refresh = settings_daemon_request(Request::GetExtendedConfigSnapshot {
        project_root,
        snapshot_session_id: settings_snapshot_session_id().to_owned(),
    });
    match refresh {
        Ok(Response::ExtendedConfigSnapshot {
            layers,
            config_generation,
        }) if warning.is_none()
            && config_generation == result_generation => {
            let layer = layers.into_iter().find(|layer| {
                layer.display_path == requested_path
                    && layer.kind == expected_layer
                    && layer.revision == result_revision
                    && same_denylist_occurrences(&layer.denylist, &committed_denylist)
                    && validate_settings_operations(
                        &operations,
                        &serde_json::to_value(&layer.config).unwrap_or(serde_json::Value::Null),
                        &layer.authored_paths,
                    )
                    .is_ok()
            });
            match layer {
                Some(layer) => Ok(SettingsPatchOutcome::Reconciled { layer, config_generation }),
                None => Ok(SettingsPatchOutcome::CommittedRefreshNeeded {
                    result_revision,
                    config_generation: result_generation,
                    warning: "settings committed, but the authoritative refresh did not contain the exact committed layer; reload before editing again".into(),
                }),
            }
        }
        other => Ok(SettingsPatchOutcome::CommittedRefreshNeeded {
            result_revision,
            config_generation: result_generation,
            warning: warning.unwrap_or_else(|| format!(
                "settings committed at generation {result_generation}, but the authoritative refresh did not reconcile ({other:?}); reload before editing again"
            )),
        }),
    }
}

fn apply_json_merge_patch_local(target: &mut serde_json::Value, patch: serde_json::Value) {
    let serde_json::Value::Object(patch) = patch else {
        *target = patch;
        return;
    };
    if !target.is_object() {
        *target = serde_json::json!({});
    }
    let target = target.as_object_mut().expect("normalized object");
    for (key, value) in patch {
        if value.is_null() {
            target.remove(&key);
        } else {
            apply_json_merge_patch_local(target.entry(key).or_default(), value);
        }
    }
}

fn changed_extended_paths(
    base: &serde_json::Value,
    desired: &serde_json::Value,
) -> Result<Vec<cockpit_core::daemon::proto::ExtendedConfigPathMutation>, String> {
    use cockpit_core::daemon::proto::{ExtendedConfigField, ExtendedConfigPathMutation as M};
    let base = base
        .as_object()
        .ok_or_else(|| "settings base is not an object".to_string())?;
    let desired = desired
        .as_object()
        .ok_or_else(|| "settings candidate is not an object".to_string())?;
    fn diff(
        base: Option<&serde_json::Value>,
        desired: Option<&serde_json::Value>,
        path: &mut Vec<String>,
        out: &mut Vec<M>,
    ) {
        if base == desired {
            return;
        }
        match (base, desired) {
            (_, None) => out.push(M::Unset { path: path.clone() }),
            (Some(serde_json::Value::Object(left)), Some(serde_json::Value::Object(right))) => {
                let mut keys = left.keys().chain(right.keys()).cloned().collect::<Vec<_>>();
                keys.sort();
                keys.dedup();
                for key in keys {
                    if path.len() == 1 && path[0] == "redact" && key == "denylist" {
                        continue;
                    }
                    path.push(key.clone());
                    diff(left.get(&key), right.get(&key), path, out);
                    path.pop();
                }
            }
            (_, Some(value)) => out.push(M::Set {
                path: path.clone(),
                value: value.clone(),
            }),
        }
    }
    let mut operations = Vec::new();
    let mut keys = base
        .keys()
        .chain(desired.keys())
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    for key in keys {
        let Some(field) = ExtendedConfigField::from_json_key(&key) else {
            continue;
        };
        if field == ExtendedConfigField::ImageGeneration {
            continue;
        }
        let mut path = vec![key.clone()];
        diff(
            base.get(&key),
            desired.get(&key),
            &mut path,
            &mut operations,
        );
    }
    Ok(operations)
}

fn validate_settings_operations(
    operations: &[cockpit_core::daemon::proto::ExtendedConfigPathMutation],
    snapshot: &serde_json::Value,
    authored_paths: &[Vec<String>],
) -> Result<(), String> {
    fn at_path<'a>(value: &'a serde_json::Value, path: &[String]) -> Option<&'a serde_json::Value> {
        path.iter()
            .try_fold(value, |value, key| value.as_object()?.get(key))
    }
    fn coherent(expected: &serde_json::Value, actual: &serde_json::Value) -> bool {
        match (expected, actual) {
            (serde_json::Value::String(expected), serde_json::Value::String(actual))
                if expected.contains("__cockpit_redacted_setting_v1_") =>
            {
                actual.contains("__cockpit_redacted_setting_v1_")
            }
            (serde_json::Value::Array(expected), serde_json::Value::Array(actual)) => {
                expected.len() == actual.len()
                    && expected.iter().zip(actual).all(|(a, b)| coherent(a, b))
            }
            (serde_json::Value::Object(expected), serde_json::Value::Object(actual)) => expected
                .iter()
                .all(|(key, value)| actual.get(key).is_some_and(|other| coherent(value, other))),
            _ => expected == actual,
        }
    }
    for operation in operations {
        match operation {
            cockpit_core::daemon::proto::ExtendedConfigPathMutation::Set { path, value } => {
                if !authored_paths
                    .iter()
                    .any(|authored| authored == path || authored.starts_with(path))
                    || !at_path(snapshot, path).is_some_and(|actual| coherent(value, actual))
                {
                    return Err(
                        "authoritative settings snapshot did not preserve an exact Set".into(),
                    );
                }
            }
            cockpit_core::daemon::proto::ExtendedConfigPathMutation::Unset { path } => {
                if authored_paths
                    .iter()
                    .any(|authored| authored == path || authored.starts_with(path))
                {
                    return Err(
                        "authoritative settings snapshot still authors an Unset path".into(),
                    );
                }
            }
        }
    }
    Ok(())
}

fn denylist_mutations(
    base: &serde_json::Value,
    desired: &[String],
) -> Result<Vec<cockpit_core::daemon::proto::DesiredDenylistEntry>, String> {
    use cockpit_core::daemon::proto::{DesiredDenylistEntry as D, RedactedDenylistEntry};
    let entries: Vec<RedactedDenylistEntry> = serde_json::from_value(
        base.get("__cockpit_denylist_entries")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([])),
    )
    .map_err(|error| error.to_string())?;
    let by_id = entries
        .iter()
        .map(|entry| (entry.entry_id.as_str(), entry))
        .collect::<std::collections::HashMap<_, _>>();
    let mut used = std::collections::HashSet::new();
    let mut target = Vec::new();
    for value in desired {
        match denylist_draft_entry(value)? {
            DenylistDraftEntry::Existing(entry_id) => {
                if !cockpit_proto::is_opaque_authority_token(entry_id)
                    || !by_id.contains_key(entry_id)
                    || !used.insert(entry_id)
                {
                    return Err("denylist draft contains a missing or duplicated occurrence".into());
                }
                target.push(D::Existing {
                    entry_id: entry_id.to_owned(),
                });
            }
            DenylistDraftEntry::New(value) => {
                if value == cockpit_proto::REDACTED_DENYLIST_MASK {
                    return Err(
                        "denylist display masks are reserved and cannot be literal values".into(),
                    );
                }
                target.push(D::New {
                    client_nonce: uuid::Uuid::new_v4().to_string(),
                    literal: value.to_owned(),
                });
            }
        }
    }
    Ok(target)
}

fn validate_committed_denylist(
    planned: &[cockpit_core::daemon::proto::DesiredDenylistEntry],
    committed: &[cockpit_core::daemon::proto::CommittedDenylistEntry],
) -> Result<(), String> {
    if planned.len() != committed.len() {
        return Err("denylist receipt has the wrong length".into());
    }
    let mut ids = std::collections::HashSet::new();
    for (planned, committed) in planned.iter().zip(committed) {
        if !cockpit_proto::is_opaque_authority_token(&committed.entry_id)
            || committed.display_mask != cockpit_proto::REDACTED_DENYLIST_MASK
            || !ids.insert(committed.entry_id.as_str())
        {
            return Err(
                "denylist receipt contains an invalid or duplicated occurrence token".into(),
            );
        }
        match planned {
            cockpit_core::daemon::proto::DesiredDenylistEntry::Existing { entry_id }
                if committed.client_nonce.is_none()
                    && committed.consumed_entry_id.as_ref() == Some(entry_id) => {}
            cockpit_core::daemon::proto::DesiredDenylistEntry::New {
                client_nonce,
                literal: _,
            } if committed.client_nonce.as_ref() == Some(client_nonce)
                && committed.consumed_entry_id.is_none()
                && uuid::Uuid::parse_str(client_nonce)
                    .is_ok_and(|nonce| nonce.to_string() == *client_nonce) => {}
            _ => {
                return Err("denylist receipt reordered or replaced an existing occurrence".into());
            }
        }
    }
    Ok(())
}

fn same_denylist_occurrences(
    authoritative: &[cockpit_core::daemon::proto::RedactedDenylistEntry],
    receipt: &[cockpit_core::daemon::proto::CommittedDenylistEntry],
) -> bool {
    authoritative.len() == receipt.len()
        && authoritative.iter().zip(receipt).all(|(left, right)| {
            left.entry_id == right.entry_id
                && left.display_mask == right.display_mask
                && right.display_mask == cockpit_proto::REDACTED_DENYLIST_MASK
        })
}

/// Search the complete metadata-only secret inventory.  Inventory pages are
/// keyset-paginated; callers must not treat the first page as the whole
/// answer, and a concurrent mutation requires restarting the traversal.
pub(crate) async fn secret_inventory_contains(
    client: &cockpit_core::daemon::client::DaemonClient,
    name: &str,
    kind: Option<cockpit_core::daemon::proto::SecretInventoryKind>,
) -> Result<bool, String> {
    let mut cursor = None;
    let mut restarts = 0;
    loop {
        let response = match client
            .request(cockpit_core::daemon::proto::Request::ListSecretInventory {
                cursor: cursor.clone(),
                limit: Some(cockpit_core::daemon::proto::MAX_OWNER_INVENTORY_PAGE_ENTRIES as u16),
            })
            .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(error))
                if error.code == cockpit_core::daemon::proto::ErrorCode::Conflict
                    && restarts < 2 =>
            {
                restarts += 1;
                cursor = None;
                continue;
            }
            Err(error) => return Err(error.to_string()),
            Ok(Err(error)) => return Err(error.to_string()),
        };
        let cockpit_core::daemon::proto::Response::SecretInventory {
            entries,
            next_cursor,
        } = response
        else {
            return Err("daemon returned an unexpected secret inventory response".into());
        };
        if entries
            .iter()
            .any(|entry| entry.name == name && kind.as_ref().is_none_or(|kind| &entry.kind == kind))
        {
            return Ok(true);
        }
        let Some(next_cursor) = next_cursor else {
            return Ok(false);
        };
        cursor = Some(next_cursor);
    }
}
use cockpit_core::daemon::proto::{Request, Response};
use cockpit_core::providers::models_fetch::FetchOutcome;
use shell::{
    SettingsHeaderAction, SettingsPointerAction, SettingsPointerSurface, SettingsScrollStates,
    marker, muted_style, selected_or_field,
};

/// Height (in rows) the dialog wants when active.
pub const DIALOG_HEIGHT: u16 = 20;

pub enum Dialog {
    None,
    WorkspaceTrust {
        root: cockpit_config::trust::TrustRoot,
        cursor: usize,
        chosen: Option<cockpit_config::WorkspaceTrustMode>,
    },
    PickConfig {
        dirs: Vec<ConfigDir>,
        cursor: usize,
        /// Held so the `a` affordance can scaffold a new scoped config
        /// in the right place.
        cwd: PathBuf,
        /// Transient error/status (e.g. scaffold-failure message).
        status: Option<String>,
    },
    CreateConfig {
        choices: Vec<ConfigDir>,
        cursor: usize,
        /// Held so the resulting settings dialog can offer "back to
        /// picker" — once a config has been scaffolded, reopening the
        /// picker yields a non-empty list.
        cwd: PathBuf,
        /// Transient scaffold error/status.
        status: Option<String>,
    },
    /// "Add a config scoped to the current directory" sub-dialog
    /// reached by pressing `a` on the picker. Offers a `.cockpit/` in
    /// the cwd (shareable with a team) or a hashed-cwd dir under the
    /// cockpit data dir (machine-local).
    CreateScopedConfig {
        choices: Vec<ConfigDir>,
        cursor: usize,
        cwd: PathBuf,
    },
    WizardMenu {
        wizards: Vec<cockpit_core::wizard::WizardDescriptor>,
        cursor: usize,
        cwd: PathBuf,
    },
    /// Entry point for `/setup model`. Only a confirmed session model may
    /// seed configuration; a pending selection is never treated as confirmed.
    ModelSetupChoice {
        cwd: PathBuf,
        confirmed: Option<(String, String)>,
        pending: Option<(String, String)>,
        cursor: usize,
    },
    SetupWizard(Box<SetupWizardDialog>),
    FirstRunComplete {
        summary: String,
    },
    /// Boxed because [`SettingsDialog`] dwarfs the other variants
    /// (~1.1KB vs <100 bytes), which would otherwise bloat every
    /// [`Dialog`] on the stack.
    Settings(Box<SettingsDialog>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub(crate) enum SettingsPointerOutcome {
    Consumed,
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum SettingsPointerSurfaceKind {
    Root,
    DefaultModel,
    Agents,
    Tools,
    Harnesses,
    Providers,
    Category,
    Instructions,
    RedactPatterns,
    StringList,
    Skills,
    Mcp,
    Lsp,
    Dependencies,
    GenerationList,
    EndpointEditor,
    TargetEditor,
    WorkflowEditor,
    BudgetEditor,
    GrantList,
    JobList,
    JobDetail,
    LateResultAction,
}

impl SettingsPointerSurfaceKind {
    pub(super) const ALL: [Self; 23] = [
        Self::Root,
        Self::DefaultModel,
        Self::Agents,
        Self::Tools,
        Self::Harnesses,
        Self::Providers,
        Self::Category,
        Self::Instructions,
        Self::RedactPatterns,
        Self::StringList,
        Self::Skills,
        Self::Mcp,
        Self::Lsp,
        Self::Dependencies,
        Self::GenerationList,
        Self::EndpointEditor,
        Self::TargetEditor,
        Self::WorkflowEditor,
        Self::BudgetEditor,
        Self::GrantList,
        Self::JobList,
        Self::JobDetail,
        Self::LateResultAction,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SettingsLocalBack {
    NoLocalBack,
    LocalBack,
}

pub struct SetupWizardDialog {
    run: cockpit_core::wizard::WizardRun,
    cursor: usize,
    text: TextField,
    multi: std::collections::BTreeSet<String>,
    multi_touched: bool,
    tool_surface: cockpit_core::agents::ToolSurfaceSelection,
    tool_surface_touched: bool,
    cwd: PathBuf,
    status: Option<String>,
}

pub struct SettingsDialog {
    pub(super) page: PageBox,
    /// Live parent pages for drill-down navigation. Popping restores the
    /// exact boxed page object, including cursor and scroll state.
    stack: Vec<PageBox>,
    cx: SettingsCx,
}

fn setup_wizard_dialog(
    cwd: &std::path::Path,
    descriptor: cockpit_core::wizard::WizardDescriptor,
    status: Option<String>,
) -> Result<Dialog, String> {
    let run = cockpit_core::wizard::WizardRun::new(descriptor).map_err(|e| e.to_string())?;
    let mut cursor = 0;
    let mut text = TextField::new("");
    let mut multi = std::collections::BTreeSet::new();
    let mut multi_touched = false;
    let mut tool_surface = cockpit_core::agents::ToolSurfaceSelection::default();
    let mut tool_surface_touched = false;
    sync_setup_wizard_inputs(
        &run,
        SetupWizardInputs {
            cursor: &mut cursor,
            text: &mut text,
            multi: &mut multi,
            multi_touched: &mut multi_touched,
            tool_surface: &mut tool_surface,
            tool_surface_touched: &mut tool_surface_touched,
        },
    );
    Ok(Dialog::SetupWizard(Box::new(SetupWizardDialog {
        run,
        cursor,
        text,
        multi,
        multi_touched,
        tool_surface,
        tool_surface_touched,
        cwd: cwd.to_path_buf(),
        status,
    })))
}

impl Deref for SettingsDialog {
    type Target = SettingsCx;

    fn deref(&self) -> &Self::Target {
        &self.cx
    }
}

impl DerefMut for SettingsDialog {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.cx
    }
}

pub(super) type PageBox = Box<dyn SettingsPage>;

pub(super) struct RootPage {
    cursor: usize,
}

/// Stateful `/settings` page behavior.
///
/// Adding a page should require one localized implementation:
///
/// 1. Define the page state type.
/// 2. Implement [`SettingsPage`] for that type.
/// 3. Construct a boxed page at the navigation site that opens it.
///
/// Page code uses [`SettingsCx`] for shared configuration, persistence,
/// pending requests, and scroll state; it returns [`Nav`] instead of touching
/// the navigation stack directly. The outer [`SettingsDialog`] stores the
/// current page and stack as boxed trait objects, so pushing and popping
/// preserves the live concrete page state without adding central render,
/// title, help, or key-dispatch arms.
#[allow(private_interfaces)]
pub(super) trait SettingsPage: Any {
    fn pointer_surface_kind(&self) -> SettingsPointerSurfaceKind;
    fn pointer_surface_token(&self) -> u64 {
        self.pointer_surface_kind() as u64
    }
    /// Declare whether Back first cancels/leaves page-local state. The
    /// dialog only pops its navigation stack for `NoLocalBack`.
    fn resolve_header_back(&self) -> SettingsLocalBack {
        SettingsLocalBack::NoLocalBack
    }
    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav;
    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect);
    fn render_with_links(
        &self,
        cx: &SettingsCx,
        frame: &mut Frame,
        area: Rect,
        _links: &mut crate::tui::links::LinkRegistry,
    ) {
        self.render(cx, frame, area);
    }
    fn title(&self, cx: &SettingsCx) -> String;
    fn help_text(&self, cx: &SettingsCx) -> &'static str;
    /// Resolve a semantic control registered by this page. Implementations
    /// must validate the stable identity against current state before
    /// mutating; stale targets therefore become inert after reloads.
    fn handle_pointer_control(
        &mut self,
        _cx: &mut SettingsCx,
        _action: pointer_actions::SettingsPointerAction,
    ) -> Nav {
        Nav::Stay
    }
    fn handle_pointer_control_at(
        &mut self,
        cx: &mut SettingsCx,
        action: pointer_actions::SettingsPointerAction,
        _column: u16,
        _row: u16,
    ) -> Nav {
        self.handle_pointer_control(cx, action)
    }
    /// Move only the independently scrollable region under the pointer.
    /// `delta` is measured in selectable controls and is already normalized
    /// to the settings wheel step (three per notch).
    fn handle_pointer_scroll(
        &mut self,
        cx: &mut SettingsCx,
        _region: shell::SettingsScrollRegionId,
        delta: isize,
    ) -> Nav {
        let key = if delta < 0 {
            KeyCode::Up
        } else {
            KeyCode::Down
        };
        for _ in 0..delta.unsigned_abs() {
            let nav = self.handle_key(cx, KeyEvent::new(key, KeyModifiers::NONE));
            if !matches!(nav, Nav::Stay) {
                return nav;
            }
        }
        Nav::Stay
    }
    /// Invalidate pointer-only confirmations/effects whose hit geometry or
    /// identity is no longer trustworthy after a terminal resize.
    fn cancel_pointer_transients(&mut self) {}
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    #[cfg(test)]
    fn test_name(&self) -> &'static str;
}

impl std::fmt::Debug for dyn SettingsPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(test)]
        {
            f.write_str(self.test_name())
        }
        #[cfg(not(test))]
        {
            f.write_str("SettingsPage")
        }
    }
}

impl dyn SettingsPage {
    fn downcast_ref<T: SettingsPage>(&self) -> Option<&T> {
        self.as_any().downcast_ref::<T>()
    }

    fn downcast_mut<T: SettingsPage>(&mut self) -> Option<&mut T> {
        self.as_any_mut().downcast_mut::<T>()
    }
}

#[cfg(test)]
#[allow(clippy::large_enum_variant)]
enum Page {
    Root { cursor: usize },
    Agents(AgentsPage),
    Tools(ToolsPage),
    Harnesses(HarnessesPage),
    Providers(ProvidersPage),
    Category(Box<CategoryPage>),
    Instructions(InstructionsPage),
    RedactPatterns(RedactPatternsPage),
    StringList(Box<StringListPage>),
    Skills(SkillsPage),
    Mcp(McpPage),
    Lsp(LspPage),
}

#[cfg(test)]
fn boxed_page(page: Page) -> PageBox {
    match page {
        Page::Root { cursor } => root_page(cursor),
        Page::Agents(page) => agents_page(page),
        Page::Tools(page) => tools_page(page),
        Page::Harnesses(page) => harnesses_page(page),
        Page::Providers(page) => providers_page(page),
        Page::Category(page) => category_page(*page),
        Page::Instructions(page) => instructions_page(page),
        Page::RedactPatterns(page) => redact_patterns_page(page),
        Page::StringList(page) => string_list_page(*page),
        Page::Skills(page) => skills_page(page),
        Page::Mcp(page) => mcp_page(page),
        Page::Lsp(page) => lsp_page(page),
    }
}

#[allow(private_interfaces)]
#[cfg(test)]
pub(crate) enum TestPageRef<'a> {
    Root { cursor: usize },
    DefaultModel(&'a DefaultModelPage),
    Agents(&'a AgentsPage),
    Tools(&'a ToolsPage),
    Harnesses(&'a HarnessesPage),
    Providers(&'a ProvidersPage),
    Category(&'a CategoryPage),
    ImageSpend(&'a image_spend::ImageSpendPage),
    Instructions(&'a InstructionsPage),
    RedactPatterns(&'a RedactPatternsPage),
    StringList(&'a StringListPage),
    Skills(&'a SkillsPage),
    Mcp(&'a McpPage),
    Lsp(&'a LspPage),
    GenerationList(&'a image_generation::GenerationListPage),
    EndpointEditor(&'a image_generation::EndpointEditorPage),
    TargetEditor(&'a image_generation::TargetEditorPage),
    WorkflowEditor(&'a image_generation::WorkflowEditorPage),
    BudgetEditor(&'a image_generation::BudgetEditorPage),
    GrantList(&'a image_generation::GrantListPage),
    JobList(&'a image_generation::JobListPage),
    JobDetail(&'a image_generation::JobDetailPage),
    LateResultAction(&'a image_generation::LateResultActionPage),
}

#[cfg(test)]
enum TestPageMut<'a> {
    Root { cursor: &'a mut usize },
    Agents(&'a mut AgentsPage),
    Tools(&'a mut ToolsPage),
    Harnesses(&'a mut HarnessesPage),
    Providers(&'a mut ProvidersPage),
    Category(&'a mut CategoryPage),
    ImageSpend(&'a mut image_spend::ImageSpendPage),
    Instructions(&'a mut InstructionsPage),
    RedactPatterns(&'a mut RedactPatternsPage),
    StringList(&'a mut StringListPage),
    Skills(&'a mut SkillsPage),
    Mcp(&'a mut McpPage),
    Lsp(&'a mut LspPage),
    GenerationList(&'a mut image_generation::GenerationListPage),
    EndpointEditor(&'a mut image_generation::EndpointEditorPage),
    TargetEditor(&'a mut image_generation::TargetEditorPage),
    WorkflowEditor(&'a mut image_generation::WorkflowEditorPage),
    BudgetEditor(&'a mut image_generation::BudgetEditorPage),
    GrantList(&'a mut image_generation::GrantListPage),
    JobList(&'a mut image_generation::JobListPage),
    JobDetail(&'a mut image_generation::JobDetailPage),
    LateResultAction(&'a mut image_generation::LateResultActionPage),
}

#[cfg(test)]
impl std::fmt::Debug for TestPageRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root { cursor } => write!(f, "Root({cursor})"),
            Self::DefaultModel(_) => f.write_str("DefaultModel"),
            Self::Agents(_) => f.write_str("Agents"),
            Self::Tools(_) => f.write_str("Tools"),
            Self::Harnesses(_) => f.write_str("Harnesses"),
            Self::Providers(_) => f.write_str("Providers"),
            Self::Category(_) => f.write_str("Category"),
            Self::ImageSpend(_) => f.write_str("ImageSpend"),
            Self::Instructions(_) => f.write_str("Instructions"),
            Self::RedactPatterns(_) => f.write_str("RedactPatterns"),
            Self::StringList(_) => f.write_str("StringList"),
            Self::Skills(_) => f.write_str("Skills"),
            Self::Mcp(_) => f.write_str("Mcp"),
            Self::Lsp(_) => f.write_str("Lsp"),
            Self::GenerationList(_) => f.write_str("GenerationList"),
            Self::EndpointEditor(_) => f.write_str("EndpointEditor"),
            Self::TargetEditor(_) => f.write_str("TargetEditor"),
            Self::WorkflowEditor(_) => f.write_str("WorkflowEditor"),
            Self::BudgetEditor(_) => f.write_str("BudgetEditor"),
            Self::GrantList(_) => f.write_str("GrantList"),
            Self::JobList(_) => f.write_str("JobList"),
            Self::JobDetail(_) => f.write_str("JobDetail"),
            Self::LateResultAction(_) => f.write_str("LateResultAction"),
        }
    }
}

#[cfg(test)]
impl std::fmt::Debug for TestPageMut<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root { cursor } => write!(f, "Root({})", **cursor),
            Self::Agents(_) => f.write_str("Agents"),
            Self::Tools(_) => f.write_str("Tools"),
            Self::Harnesses(_) => f.write_str("Harnesses"),
            Self::Providers(_) => f.write_str("Providers"),
            Self::Category(_) => f.write_str("Category"),
            Self::ImageSpend(_) => f.write_str("ImageSpend"),
            Self::Instructions(_) => f.write_str("Instructions"),
            Self::RedactPatterns(_) => f.write_str("RedactPatterns"),
            Self::StringList(_) => f.write_str("StringList"),
            Self::Skills(_) => f.write_str("Skills"),
            Self::Mcp(_) => f.write_str("Mcp"),
            Self::Lsp(_) => f.write_str("Lsp"),
            Self::GenerationList(_) => f.write_str("GenerationList"),
            Self::EndpointEditor(_) => f.write_str("EndpointEditor"),
            Self::TargetEditor(_) => f.write_str("TargetEditor"),
            Self::WorkflowEditor(_) => f.write_str("WorkflowEditor"),
            Self::BudgetEditor(_) => f.write_str("BudgetEditor"),
            Self::GrantList(_) => f.write_str("GrantList"),
            Self::JobList(_) => f.write_str("JobList"),
            Self::JobDetail(_) => f.write_str("JobDetail"),
            Self::LateResultAction(_) => f.write_str("LateResultAction"),
        }
    }
}

pub struct SettingsCx {
    dialog_id: uuid::Uuid,
    daemon_effects: VecDeque<SettingsDaemonEffectRequest>,
    blocking_effects: VecDeque<SettingsBlockingEffectRequest>,
    pending_settings: BTreeMap<uuid::Uuid, PendingSettingsOperation>,
    pending_mcp_oauth: Option<PendingMcpOAuth>,
    pending_mcp_navigation: Option<(String, bool)>,
    completed_mcp_navigation: Option<(String, bool, Result<(), String>)>,
    completed_web_credential: Option<(String, Result<(), String>)>,
    completed_provider_auth: Option<CompletedProviderAuthMutation>,
    pending_provider_add: Option<(String, ProviderEntry, bool)>,
    completed_provider_add: Option<Result<(String, ProviderEntry, bool), String>>,
    completed_provider_mutation: Option<Result<(), String>>,
    pending_provider_mutation_navigation: Option<ProviderMutationNavigation>,
    completed_provider_mutation_navigation: Option<ProviderMutationNavigation>,
    completed_shadow_removal: Option<category::ShadowedGlobalPrompt>,
    pending_shadow_prompt: Option<category::ShadowedGlobalPrompt>,
    completed_provider_navigation: Option<(ProviderNavigation, ProvidersConfig)>,
    after_extended_commit: Vec<(SettingsEffectTarget, Request, &'static str)>,
    pub config_path: PathBuf,
    /// Path to the cockpit-only config keys. Same `config.json` as
    /// [`config_path`](Self::config_path) (GOALS §2a) — the provider/model
    /// keys and the former-`ExtendedConfig` keys share one file. Loaded
    /// lazily when the UI / Tools pages open; saved on each edit there.
    pub(super) extended_path: PathBuf,
    scroll_states: SettingsScrollStates,
    pointer_surface: SettingsPointerSurface,
    /// Cached config state; reloaded on entry into the Providers list
    /// and after each successful save.
    pub(super) config: ProvidersConfig,
    /// Daemon-redacted snapshot loaded when the dialog opened or last saved.
    /// Every secret placeholder is a unique, location-bound occurrence under
    /// the opaque revisioned capability. The daemon rejects moved, duplicated,
    /// altered, or unselected removals before merging selected typed fields
    /// into the authoritative raw document.
    original_config: ProvidersConfig,
    provider_edit_authority: Option<ProviderEditAuthority>,
    latest_provider_snapshot_session_id: Option<String>,
    /// Cached secret-free cockpit-only settings projection. Read by the UI and
    /// Tools pages; mutations are committed only by the daemon.
    pub(super) extended: ExtendedConfig,
    /// Safe daemon snapshot used to calculate a minimal typed set/unset patch;
    /// serde-omitted optional/default fields are cleared only when named in
    /// the explicit unset list.
    extended_base: serde_json::Value,
    /// Opaque revision of the raw authoritative layer corresponding to
    /// `extended_base`.
    extended_revision: Option<String>,
    /// Malformed known extended-config fields reported by the daemon during
    /// the most recent authoritative load.
    pub(super) extended_warnings: Vec<String>,
    /// Daemon-redacted MCP snapshot. MCP config is never read from disk by
    /// the TUI; saves replace this cache only after the owner RPC succeeds.
    pub(super) mcp_config: cockpit_core::mcp::config::McpConfig,
    /// The cwd this dialog was opened against. Held so Root's `h`/←
    /// can reopen the picker without losing context. `None` when the
    /// settings dialog was opened from a flow that has no picker to
    /// return to.
    pub(super) picker_cwd: Option<PathBuf>,
    /// Active launch/session project root for side effects that must operate on
    /// a project while this dialog may be editing a home/global config file.
    pub(super) active_project_root: Option<PathBuf>,
    /// Per-session launch policy (`false` for `--no-sandbox`) used by
    /// dependency applicability. This is runtime state, never persisted.
    pub(super) sandbox_enabled: bool,
    /// Set by Root's back action to ask the outer [`Dialog`] to
    /// re-open the picker on the next `true` return from `handle_key`.
    pub(super) back_to_picker: bool,
    /// PATH-presence resolver for harness-preset seeding: returns whether a
    /// harness `command` is installed (found on `PATH`). Defaults to the
    /// real [`cockpit_core::harness::preflight::which_on_path`]; tests inject a
    /// stub so seeding doesn't depend on the CI machine's installed tools.
    pub(super) command_installed: fn(&str) -> bool,
    pub(super) env_lookup: fn(&str) -> Option<String>,
    pub(super) credential_store_path: Option<PathBuf>,
    pub(super) mcp_cache_dir: Option<PathBuf>,
    /// Disclosure produced when a provider save moved literal header values
    /// into the credential store. Consumed by the provider page's status line.
    pub(super) last_secret_notice: Option<String>,
    /// Metadata-only secret-presence cache used by settings renderers.  A
    /// frame must never wait for the daemon socket; cache misses are filled in
    /// the background and render as an unknown/checking state meanwhile.
    secret_inventory_cache: Arc<Mutex<BTreeMap<String, bool>>>,
    secret_inventory_pending: Arc<Mutex<BTreeSet<String>>>,
    pending_daemon_request: Option<Request>,
    pending_oauth_action: Option<OAuthFlowRequest>,
    /// Close settings and open the model picker for default-only mutation.
    pub(super) pending_default_model_picker: bool,
    /// Correlation id of a staged `SetDefaultModel`, so the app can match the
    /// terminal `DefaultModelUpdateResult` to this exact operation.
    pub(super) pending_default_model_update_id: Option<uuid::Uuid>,
    /// Last known host-capability snapshot. Tests inject; production copies
    /// from the App after Settings opens.
    pub(super) host_capabilities: cockpit_proto::HostCapabilitySnapshot,
    /// Next refresh results, consumed in order. Empty means "refresh left
    /// the snapshot unchanged."
    pub(super) capability_refresh_queue: Vec<cockpit_proto::HostCapabilitySnapshot>,
    pub(super) capability_refresh_calls: usize,
    pub(super) capability_refresh_in_flight: bool,
    pub(super) daemon_attached: bool,
    pub(super) pending_refresh_host_capabilities: bool,
    #[allow(clippy::type_complexity)]
    pub(super) secret_store_migrate: Option<
        std::sync::Arc<
            dyn Fn(
                    cockpit_proto::SecretStorePlacement,
                ) -> Result<cockpit_proto::SecretStoreSnapshot, String>
                + Send
                + Sync,
        >,
    >,
    pub(super) secret_store_migrate_calls: usize,
    pub(super) dependency_refresh_calls: usize,
    pub(super) dependency_refresh: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

#[derive(Clone)]
struct ProviderEditAuthority {
    snapshot_session_id: String,
    layer_id: String,
    base_revision: String,
    config_generation: u64,
}

impl SettingsCx {
    fn authority_operation_pending(&self) -> bool {
        !self.pending_settings.is_empty()
            || !self.daemon_effects.is_empty()
            || !self.blocking_effects.is_empty()
    }

    fn enqueue_daemon_effect(
        &mut self,
        target: SettingsEffectTarget,
        request: Request,
    ) -> uuid::Uuid {
        let operation_id = uuid::Uuid::new_v4();
        self.daemon_effects.push_back(SettingsDaemonEffectRequest {
            dialog_id: self.dialog_id,
            operation_id,
            target,
            work: SettingsDaemonEffectWork::Request(request),
        });
        operation_id
    }

    fn enqueue_settlement_effect(
        &mut self,
        target: SettingsEffectTarget,
        request: Request,
    ) -> uuid::Uuid {
        let operation_id = uuid::Uuid::new_v4();
        self.daemon_effects.push_back(SettingsDaemonEffectRequest {
            dialog_id: self.dialog_id,
            operation_id,
            target,
            work: SettingsDaemonEffectWork::SettlementQuery(request),
        });
        operation_id
    }

    fn queue_settlement_query(
        &mut self,
        client_operation_id: String,
        original: PendingSettingsOperation,
    ) {
        let target = SettingsEffectTarget {
            surface: "settings.settlement-query",
            owner: client_operation_id.clone(),
            revision: Some(client_operation_id.clone()),
        };
        let operation_id = self.enqueue_settlement_effect(
            target.clone(),
            Request::GetLocalOperationSettlement {
                client_operation_id: client_operation_id.clone(),
            },
        );
        self.pending_settings.insert(
            operation_id,
            PendingSettingsOperation::SettlementQuery {
                target,
                client_operation_id,
                original: Box::new(original),
            },
        );
        self.extended_warnings =
            vec!["operation settlement is unknown; querying the daemon receipt…".into()];
    }

    fn retry_unknown_settlement(&mut self) {
        let unknown_id = self.pending_settings.iter().find_map(|(id, pending)| {
            matches!(pending, PendingSettingsOperation::SettlementUnknown { .. }).then_some(*id)
        });
        let Some(unknown_id) = unknown_id else {
            return;
        };
        let Some(PendingSettingsOperation::SettlementUnknown {
            client_operation_id,
            original,
            ..
        }) = self.pending_settings.remove(&unknown_id)
        else {
            return;
        };
        self.queue_settlement_query(client_operation_id, *original);
    }

    fn enqueue_daemon_work(
        &mut self,
        target: SettingsEffectTarget,
        work: SettingsDaemonEffectWork,
    ) -> uuid::Uuid {
        let operation_id = uuid::Uuid::new_v4();
        self.daemon_effects.push_back(SettingsDaemonEffectRequest {
            dialog_id: self.dialog_id,
            operation_id,
            target,
            work,
        });
        operation_id
    }

    fn take_daemon_effect(&mut self) -> Option<SettingsDaemonEffectRequest> {
        self.daemon_effects.pop_front()
    }

    fn enqueue_blocking_work(
        &mut self,
        target: SettingsEffectTarget,
        work: SettingsBlockingEffectWork,
    ) -> uuid::Uuid {
        let operation_id = uuid::Uuid::new_v4();
        self.blocking_effects
            .push_back(SettingsBlockingEffectRequest {
                dialog_id: self.dialog_id,
                operation_id,
                target,
                work,
            });
        operation_id
    }

    fn take_blocking_effect(&mut self) -> Option<SettingsBlockingEffectRequest> {
        self.blocking_effects.pop_front()
    }

    fn queue_simple_mutation(
        &mut self,
        target: SettingsEffectTarget,
        request: Request,
        action: SettingsMutationAction,
    ) -> uuid::Uuid {
        let operation_id = self.enqueue_daemon_effect(target.clone(), request);
        self.pending_settings.insert(
            operation_id,
            PendingSettingsOperation::SimpleMutation { target, action },
        );
        operation_id
    }

    fn queue_simple_secret_mutation(
        &mut self,
        target: SettingsEffectTarget,
        work: SettingsDaemonEffectWork,
        action: SettingsMutationAction,
    ) -> uuid::Uuid {
        let operation_id = self.enqueue_daemon_work(target.clone(), work);
        self.pending_settings.insert(
            operation_id,
            PendingSettingsOperation::SimpleMutation { target, action },
        );
        operation_id
    }

    fn queue_typed_document_edit(
        &mut self,
        path: PathBuf,
        project_root: PathBuf,
        patch: serde_json::Value,
        action: TypedDocumentEditAction,
    ) {
        let requested_path = path.display().to_string();
        let snapshot_session_id = settings_snapshot_session_id().to_owned();
        let target = SettingsEffectTarget {
            surface: "settings.typed-document-edit",
            owner: requested_path.clone(),
            revision: Some(snapshot_session_id.clone()),
        };
        let operation_id = self.enqueue_daemon_work(
            target.clone(),
            SettingsDaemonEffectWork::TypedDocumentEdit(TypedDocumentEditPlan {
                project_root: project_root.display().to_string(),
                requested_path: requested_path.clone(),
                patch,
                snapshot_session_id,
            }),
        );
        self.pending_settings.insert(
            operation_id,
            PendingSettingsOperation::TypedDocumentEdit {
                target,
                requested_path,
                action,
            },
        );
    }

    fn queue_project_shadow_snapshot(&mut self, prompt: category::ShadowedGlobalPrompt) {
        let Some(project_root) = self.active_project_root.clone() else {
            return;
        };
        let snapshot_session_id = settings_snapshot_session_id().to_owned();
        let target = SettingsEffectTarget {
            surface: "settings.project-shadow-snapshot",
            owner: prompt.project_config.display().to_string(),
            revision: Some(snapshot_session_id.clone()),
        };
        let operation_id = self.enqueue_daemon_effect(
            target.clone(),
            Request::GetExtendedConfigSnapshot {
                project_root: project_root.display().to_string(),
                snapshot_session_id,
            },
        );
        self.pending_settings.insert(
            operation_id,
            PendingSettingsOperation::ProjectShadowSnapshot { target, prompt },
        );
    }

    fn queue_extended_load(&mut self) {
        let project_context = self
            .active_project_root
            .as_deref()
            .or(self.picker_cwd.as_deref());
        let Ok(project_root) = config_layer_request(&self.extended_path, project_context) else {
            self.extended_warnings = vec!["settings request has no workspace root".into()];
            return;
        };
        let requested_path = self.extended_path.display().to_string();
        let snapshot_session_id = settings_snapshot_session_id().to_owned();
        let target = SettingsEffectTarget {
            surface: "settings.extended-load",
            owner: requested_path.clone(),
            revision: Some(snapshot_session_id.clone()),
        };
        let request = Request::GetExtendedConfigSnapshot {
            project_root: project_root.clone(),
            snapshot_session_id: snapshot_session_id.clone(),
        };
        let operation_id = self.enqueue_daemon_effect(target, request);
        self.pending_settings.insert(
            operation_id,
            PendingSettingsOperation::ExtendedLoad {
                requested_path,
                project_root,
                snapshot_session_id,
            },
        );
        self.extended_revision = None;
        self.extended_warnings = vec!["loading daemon-owned settings…".into()];
    }

    fn queue_provider_catalog(&mut self, provider_id: Option<String>) {
        self.queue_provider_catalog_for(provider_id, None);
    }

    fn queue_provider_catalog_for(
        &mut self,
        provider_id: Option<String>,
        navigation: Option<ProviderNavigation>,
    ) {
        let project_root = self
            .active_project_root
            .clone()
            .or_else(|| self.picker_cwd.clone())
            .or_else(|| config_cwd(&self.config_path))
            .unwrap_or_else(|| PathBuf::from("."))
            .display()
            .to_string();
        let owner = format!(
            "{}::{}",
            project_root,
            provider_id.as_deref().unwrap_or("*")
        );
        let snapshot_session_id = uuid::Uuid::new_v4().to_string();
        self.latest_provider_snapshot_session_id = Some(snapshot_session_id.clone());
        let operation_id = self.enqueue_daemon_effect(
            SettingsEffectTarget {
                surface: "settings.provider-catalog",
                owner,
                revision: Some(snapshot_session_id.clone()),
            },
            Request::GetProviderCatalogSnapshot {
                project_root: project_root.clone(),
                provider_id: provider_id.clone(),
                snapshot_session_id: snapshot_session_id.clone(),
            },
        );
        self.pending_settings.insert(
            operation_id,
            PendingSettingsOperation::ProviderCatalog {
                project_root,
                provider_id,
                snapshot_session_id,
                navigation,
            },
        );
    }

    fn queue_extended_save(&mut self) -> Result<SettingsSaveOutcome, String> {
        if self.pending_settings.values().any(|pending| {
            matches!(
                pending,
                PendingSettingsOperation::ExtendedSave { .. }
                    | PendingSettingsOperation::ExtendedRefresh { .. }
            )
        }) {
            return Err("a settings save is already pending".into());
        }
        let expected_revision = self
            .extended_revision
            .clone()
            .ok_or_else(|| "settings snapshot has no revision; reload before saving".to_string())?;
        let desired_value =
            serde_json::to_value(&self.extended).map_err(|error| error.to_string())?;
        let operations = changed_extended_paths(&self.extended_base, &desired_value)?;
        let denylist = denylist_mutations(&self.extended_base, &self.extended.redact.denylist)?;
        let project_root = config_layer_request(
            &self.extended_path,
            self.active_project_root
                .as_deref()
                .or(self.picker_cwd.as_deref()),
        )?;
        let layer_id = self
            .extended_base
            .get("__cockpit_settings_layer_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "settings snapshot omitted its layer capability".to_string())?
            .to_owned();
        let expected_layer = serde_json::from_value(
            self.extended_base
                .get("__cockpit_settings_layer_kind")
                .cloned()
                .ok_or_else(|| "settings snapshot omitted its layer kind".to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let expected_generation = self
            .extended_base
            .get("__cockpit_settings_generation")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| "settings snapshot omitted its config generation".to_string())?;
        let requested_path = self.extended_path.display().to_string();
        let snapshot_session_id = settings_snapshot_session_id().to_owned();
        let request = Request::ApplyExtendedConfigPatch {
            project_root: project_root.clone(),
            layer_id: layer_id.clone(),
            patch: cockpit_core::daemon::proto::ExtendedConfigPatch {
                operations: operations.clone(),
                materialize: false,
                denylist: denylist.clone(),
                redacted_mutations: Vec::new(),
            },
            expected_revision: expected_revision.clone(),
            snapshot_session_id: snapshot_session_id.clone(),
        };
        let operation_id = self.enqueue_daemon_effect(
            SettingsEffectTarget {
                surface: "settings.extended-save",
                owner: layer_id.clone(),
                revision: Some(expected_revision.clone()),
            },
            request,
        );
        self.pending_settings.insert(
            operation_id,
            PendingSettingsOperation::ExtendedSave {
                requested_path,
                project_root,
                snapshot_session_id,
                layer_id,
                expected_layer,
                expected_revision,
                expected_generation,
                operations,
                denylist_plan: denylist,
            },
        );
        Ok(SettingsSaveOutcome::Queued)
    }

    fn queue_after_extended_commit(
        &mut self,
        label: &'static str,
        target: SettingsEffectTarget,
        request: Request,
    ) {
        self.after_extended_commit.push((target, request, label));
    }

    fn apply_general_completion(
        &mut self,
        completion: SettingsDaemonEffectCompletion,
    ) -> Result<(), SettingsDaemonEffectCompletion> {
        let Some(pending) = self.pending_settings.remove(&completion.operation_id) else {
            return Err(completion);
        };
        if !pending.target_matches(&completion.target) {
            self.extended_warnings = vec![format!(
                "ignored mismatched settings receipt for operation {}",
                completion.operation_id
            )];
            self.pending_settings
                .insert(completion.operation_id, pending);
            return Ok(());
        }
        match pending {
            PendingSettingsOperation::ExtendedLoad {
                requested_path,
                project_root: _,
                snapshot_session_id,
            } => {
                if completion.target
                    != (SettingsEffectTarget {
                        surface: "settings.extended-load",
                        owner: requested_path.clone(),
                        revision: Some(snapshot_session_id),
                    })
                {
                    return Ok(());
                }
                match completion.response {
                    Ok(Response::ExtendedConfigSnapshot {
                        layers,
                        config_generation,
                    }) => match layers
                        .into_iter()
                        .find(|layer| layer.display_path == requested_path)
                        .ok_or_else(|| {
                            "settings target is not a daemon-discovered layer".to_string()
                        })
                        .and_then(|layer| decode_extended_layer(layer, config_generation))
                    {
                        Ok((extended, base, revision)) => {
                            self.extended = extended;
                            self.extended_base = base;
                            self.extended_revision = Some(revision);
                            self.extended_warnings.clear();
                        }
                        Err(error) => self.extended_warnings = vec![error],
                    },
                    Ok(other) => {
                        self.extended_warnings =
                            vec![format!("unexpected settings snapshot response: {other:?}")]
                    }
                    Err(error) => self.extended_warnings = vec![format!("load failed: {error}")],
                }
            }
            PendingSettingsOperation::ProviderMutation {
                target,
                client_operation_id,
                snapshot_session_id,
                layer_id,
                expected_revision,
                expected_generation,
                staged_default,
                notice,
            } => {
                if completion.target != target {
                    return Ok(());
                }
                let settlement_pending = PendingSettingsOperation::ProviderMutation {
                    target: target.clone(),
                    client_operation_id: client_operation_id.clone(),
                    snapshot_session_id: snapshot_session_id.clone(),
                    layer_id: layer_id.clone(),
                    expected_revision: expected_revision.clone(),
                    expected_generation,
                    staged_default: staged_default.clone(),
                    notice: notice.clone(),
                };
                match completion.response {
                    Ok(Response::ProviderMutationCommitted {
                        client_operation_id: returned_operation_id,
                        snapshot_session_id: returned_session_id,
                        layer_id: returned_layer_id,
                        consumed_revision,
                        result_revision,
                        config_generation,
                        config,
                        status: cockpit_proto::ConfigCommitStatus::Committed,
                        publication,
                    }) if returned_operation_id == client_operation_id
                        && returned_session_id == snapshot_session_id
                        && returned_layer_id == layer_id
                        && consumed_revision == expected_revision
                        && config_generation == expected_generation.saturating_add(1)
                        && self.latest_provider_snapshot_session_id.as_deref()
                            == Some(returned_session_id.as_str()) =>
                    {
                        let mut authoritative = providers_config_from_view(&config);
                        authoritative.set_resolution_generation(config_generation);
                        authoritative.active_model = staged_default;
                        self.config = authoritative.clone();
                        self.original_config = authoritative;
                        self.provider_edit_authority = Some(ProviderEditAuthority {
                            snapshot_session_id: returned_session_id,
                            layer_id: returned_layer_id,
                            base_revision: result_revision,
                            config_generation,
                        });
                        self.last_secret_notice = notice;
                        self.extended_warnings = vec![if publication
                            == cockpit_proto::ConfigPublicationStatus::Published
                        {
                            "provider settings committed".into()
                        } else {
                            "provider settings committed, but publication is degraded; reload before editing again".into()
                        }];
                        self.completed_provider_mutation = Some(Ok(()));
                        self.completed_provider_mutation_navigation =
                            self.pending_provider_mutation_navigation.take();
                        if let Some(pending) = self.pending_provider_add.take() {
                            self.completed_provider_add = Some(Ok(pending));
                        }
                    }
                    Ok(other) => {
                        tracing::warn!(response = ?other, "provider mutation returned an unbound receipt; resolving durable settlement");
                        self.queue_settlement_query(client_operation_id, settlement_pending);
                    }
                    Err(error) => {
                        tracing::warn!(%error, "provider mutation transport/daemon outcome is ambiguous; resolving durable settlement");
                        self.queue_settlement_query(client_operation_id, settlement_pending);
                    }
                }
            }
            PendingSettingsOperation::ProjectShadowSnapshot { target, prompt } => {
                if completion.target != target {
                    return Ok(());
                }
                if let Ok(Response::ExtendedConfigSnapshot { layers, .. }) = completion.response
                    && let Some(layer) = layers.into_iter().find(|layer| {
                        layer.display_path == prompt.project_config.display().to_string()
                    })
                    && layer.authored_paths.iter().any(|authored| {
                        authored
                            .iter()
                            .map(String::as_str)
                            .eq(prompt.path.iter().copied())
                    })
                {
                    self.pending_shadow_prompt = Some(prompt);
                }
            }
            PendingSettingsOperation::ProviderCatalog {
                project_root,
                provider_id,
                snapshot_session_id,
                navigation,
            } => {
                let expected = SettingsEffectTarget {
                    surface: "settings.provider-catalog",
                    owner: format!(
                        "{}::{}",
                        project_root,
                        provider_id.as_deref().unwrap_or("*")
                    ),
                    revision: Some(snapshot_session_id.clone()),
                };
                if completion.target != expected {
                    return Ok(());
                }
                match completion.response {
                    Ok(Response::ProviderCatalogSnapshot {
                        config,
                        snapshot_session_id: returned_session_id,
                        layer_id,
                        base_revision,
                        config_generation,
                    }) if returned_session_id == snapshot_session_id
                        && self.latest_provider_snapshot_session_id.as_deref()
                            == Some(returned_session_id.as_str()) =>
                    {
                        let mut parsed = providers_config_from_view(&config);
                        parsed.set_resolution_generation(config_generation);
                        self.config = parsed.clone();
                        self.original_config = parsed;
                        self.provider_edit_authority = Some(ProviderEditAuthority {
                            snapshot_session_id,
                            layer_id,
                            base_revision,
                            config_generation,
                        });
                        if let Some(navigation) = navigation {
                            self.completed_provider_navigation =
                                Some((navigation, self.config.clone()));
                        }
                        if let Some(raw) = config.mcp_config_json
                            && let Ok(mcp) = cockpit_core::mcp::config::McpConfig::parse(&raw)
                        {
                            self.mcp_config = mcp;
                        }
                    }
                    Ok(other) => {
                        tracing::warn!(response = ?other, "unexpected async provider catalog response")
                    }
                    Err(error) => tracing::warn!(%error, "async provider catalog load failed"),
                }
            }
            PendingSettingsOperation::ExtendedSave {
                requested_path,
                project_root,
                snapshot_session_id,
                layer_id,
                expected_layer,
                expected_revision,
                expected_generation,
                operations,
                denylist_plan,
            } => {
                let expected_target = SettingsEffectTarget {
                    surface: "settings.extended-save",
                    owner: layer_id.clone(),
                    revision: Some(expected_revision.clone()),
                };
                if completion.target != expected_target {
                    return Ok(());
                }
                let receipt = match completion.response {
                    Ok(Response::ExtendedConfigSaved {
                        hash,
                        config_generation,
                        layer_id: returned_layer_id,
                        layer,
                        consumed_revision,
                        result_revision,
                        status: cockpit_core::daemon::proto::ConfigCommitStatus::Committed,
                        publication,
                        denylist,
                    }) if returned_layer_id == layer_id
                        && layer == expected_layer
                        && consumed_revision == expected_revision
                        && hash == result_revision
                        && cockpit_proto::is_opaque_authority_token(&result_revision)
                        && validate_committed_denylist(&denylist_plan, &denylist).is_ok()
                        && (config_generation == expected_generation
                            || config_generation == expected_generation.saturating_add(1)) =>
                    {
                        let warning = (publication
                            == cockpit_core::daemon::proto::ConfigPublicationStatus::Degraded)
                            .then(|| "settings committed, but redaction publication is degraded; restart the daemon before continuing".to_string());
                        Ok((result_revision, config_generation, denylist, warning))
                    }
                    Ok(other) => Err(format!("unexpected settings patch response: {other:?}")),
                    Err(error) => Err(error),
                };
                let (result_revision, result_generation, committed_denylist, warning) =
                    match receipt {
                        Ok(receipt) => receipt,
                        Err(error) => {
                            self.extended_warnings = vec![format!("save failed: {error}")];
                            return Ok(());
                        }
                    };
                // Once the commit receipt is valid, local cancellation or a
                // refresh failure cannot turn it into a reported rejection.
                self.extended_revision = None;
                for (target, request, label) in std::mem::take(&mut self.after_extended_commit) {
                    let followup_id = self.enqueue_daemon_effect(target.clone(), request);
                    self.pending_settings.insert(
                        followup_id,
                        PendingSettingsOperation::Followup { label, target },
                    );
                }
                let refresh_target = SettingsEffectTarget {
                    surface: "settings.extended-refresh",
                    owner: layer_id,
                    revision: Some(result_revision.clone()),
                };
                let operation_id = self.enqueue_daemon_effect(
                    refresh_target.clone(),
                    Request::GetExtendedConfigSnapshot {
                        project_root,
                        snapshot_session_id,
                    },
                );
                self.pending_settings.insert(
                    operation_id,
                    PendingSettingsOperation::ExtendedRefresh {
                        target: refresh_target,
                        requested_path,
                        expected_layer,
                        result_revision,
                        result_generation,
                        operations,
                        committed_denylist,
                        warning,
                    },
                );
                self.extended_warnings = vec!["settings committed; reconciling…".into()];
            }
            PendingSettingsOperation::ExtendedRefresh {
                target: _,
                requested_path,
                expected_layer,
                result_revision,
                result_generation,
                operations,
                committed_denylist,
                warning,
            } => {
                if completion.target.surface != "settings.extended-refresh"
                    || completion.target.revision.as_deref() != Some(result_revision.as_str())
                {
                    return Ok(());
                }
                let reconciled = match completion.response {
                    Ok(Response::ExtendedConfigSnapshot {
                        layers,
                        config_generation,
                    }) if warning.is_none() && config_generation == result_generation => layers
                        .into_iter()
                        .find(|layer| {
                            layer.display_path == requested_path
                                && layer.kind == expected_layer
                                && layer.revision == result_revision
                                && same_denylist_occurrences(&layer.denylist, &committed_denylist)
                                && validate_settings_operations(
                                    &operations,
                                    &serde_json::to_value(&layer.config)
                                        .unwrap_or(serde_json::Value::Null),
                                    &layer.authored_paths,
                                )
                                .is_ok()
                        })
                        .map(|layer| (layer, config_generation)),
                    _ => None,
                };
                match reconciled {
                    Some((layer, generation)) => match decode_extended_layer(layer, generation) {
                        Ok((extended, base, revision)) => {
                            self.extended = extended;
                            self.extended_base = base;
                            self.extended_revision = Some(revision);
                            self.extended_warnings.clear();
                        }
                        Err(error) => self.extended_warnings = vec![format!(
                            "settings committed, but authoritative refresh was invalid: {error}"
                        )],
                    },
                    None => self.extended_warnings = vec![warning.unwrap_or_else(|| {
                        format!(
                            "settings committed at generation {result_generation}, but refresh did not reconcile; reload before editing again"
                        )
                    })],
                }
            }
            PendingSettingsOperation::Followup { label, target } => {
                if completion.target != target {
                    return Ok(());
                }
                if let Err(error) = completion.response {
                    self.extended_warnings
                        .push(format!("{label} failed after settings committed: {error}"));
                }
            }
            PendingSettingsOperation::SimpleMutation { target, action } => {
                if completion.target != target {
                    return Ok(());
                }
                if let Some(client_operation_id) = action.settlement_id().map(str::to_owned)
                    && completion
                        .response
                        .as_ref()
                        .map_or(true, |response| !action.matches_durable_receipt(response))
                {
                    self.queue_settlement_query(
                        client_operation_id,
                        PendingSettingsOperation::SimpleMutation { target, action },
                    );
                    return Ok(());
                }
                let result = match (action, completion.response) {
                    (
                        SettingsMutationAction::McpSave {
                            config,
                            client_operation_id,
                            project_root,
                            expected_owner_root,
                            expected_config_path,
                            expected_consumed_revision,
                            expected_result_revision,
                        },
                        Ok(Response::McpConfigCommitted {
                            client_operation_id: returned_operation_id,
                            request_hash,
                            project_root: returned_root,
                            owner_root,
                            config_path,
                            consumed_revision,
                            result_revision,
                            config_generation,
                            ..
                        }),
                    ) if returned_operation_id == client_operation_id
                        && returned_root == project_root
                        && owner_root == expected_owner_root
                        && config_path == expected_config_path
                        && consumed_revision == expected_consumed_revision
                        && result_revision == expected_result_revision
                        && cockpit_proto::is_opaque_authority_token(&request_hash)
                        && config_generation > 0 =>
                    {
                        self.mcp_config = config;
                        self.invalidate_secret_inventory();
                        if let Some((name, edited)) = self.pending_mcp_navigation.take() {
                            self.completed_mcp_navigation = Some((name, edited, Ok(())));
                        }
                        Ok("MCP settings committed".to_string())
                    }
                    (
                        SettingsMutationAction::McpOAuthBegin {
                            server,
                            client_operation_id,
                            expected_request_hash,
                        },
                        Ok(Response::McpOAuthStarted {
                            client_operation_id: returned_operation_id,
                            request_hash,
                            flow_id,
                            authorize_url,
                            ..
                        }),
                    ) if returned_operation_id == client_operation_id
                        && request_hash == expected_request_hash =>
                    {
                        self.pending_mcp_oauth = Some(PendingMcpOAuth::Started {
                            server,
                            begin_client_operation_id: client_operation_id,
                            flow_id,
                            authorize_url,
                        });
                        Ok("MCP OAuth started; open the authorization URL".to_string())
                    }
                    (
                        SettingsMutationAction::McpOAuthComplete {
                            server,
                            flow_id,
                            client_operation_id,
                            expected_request_hash,
                        },
                        Ok(Response::McpOAuthCompleted {
                            client_operation_id: returned_operation_id,
                            request_hash,
                            flow_id: returned_flow_id,
                            authenticated: true,
                            ..
                        }),
                    ) if returned_operation_id == client_operation_id
                        && request_hash == expected_request_hash
                        && returned_flow_id == flow_id =>
                    {
                        self.invalidate_secret_inventory();
                        self.pending_mcp_oauth =
                            Some(PendingMcpOAuth::Completed { server, flow_id });
                        Ok("MCP OAuth authenticated".to_string())
                    }
                    (
                        SettingsMutationAction::McpOAuthCancel {
                            server,
                            flow_id,
                            client_operation_id,
                            expected_request_hash,
                        },
                        Ok(Response::McpOAuthCancelled {
                            client_operation_id: returned_operation_id,
                            request_hash,
                            flow_id: Some(returned_flow_id),
                            cancelled: true,
                            ..
                        }),
                    ) => {
                        if returned_operation_id != client_operation_id
                            || request_hash != expected_request_hash
                            || returned_flow_id != flow_id
                        {
                            return Ok(());
                        }
                        self.pending_mcp_oauth =
                            Some(PendingMcpOAuth::Cancelled { server, flow_id });
                        Ok("MCP OAuth cancelled".to_string())
                    }
                    (
                        SettingsMutationAction::ProviderCredentialDelete {
                            provider_id,
                            client_operation_id,
                            project_root,
                        },
                        Ok(Response::ProviderCredentialCommitted {
                            client_operation_id: returned_operation_id,
                            provider_id: returned_provider_id,
                            project_root: Some(returned_root),
                            owner_root: Some(owner_root),
                            owner_scope,
                            stored: false,
                            changed,
                            consumed_vault_generation,
                            result_vault_generation,
                            config_generation,
                            ..
                        }),
                    ) if returned_operation_id == client_operation_id
                        && returned_provider_id == provider_id
                        && returned_root == project_root
                        && owner_root == project_root
                        && owner_scope == format!("project:{owner_root}")
                        && config_generation > 0
                        && valid_vault_freshness(
                            consumed_vault_generation,
                            result_vault_generation,
                            changed,
                        ) =>
                    {
                        self.invalidate_secret_inventory_entry(&provider_id, None);
                        self.completed_provider_auth =
                            Some(CompletedProviderAuthMutation::Logout {
                                provider_id: provider_id.clone(),
                                result: Ok(()),
                            });
                        Ok(format!("signed out of {provider_id}"))
                    }
                    (
                        SettingsMutationAction::ProviderCredentialPut {
                            provider_id,
                            client_operation_id,
                        },
                        Ok(Response::ProviderCredentialCommitted {
                            client_operation_id: returned_operation_id,
                            provider_id: returned_provider_id,
                            project_root: None,
                            owner_root: None,
                            owner_scope,
                            stored: true,
                            changed,
                            consumed_vault_generation,
                            result_vault_generation,
                            config_generation,
                            ..
                        }),
                    ) if returned_operation_id == client_operation_id
                        && returned_provider_id == provider_id
                        && owner_scope == "global"
                        && config_generation > 0
                        && valid_vault_freshness(
                            consumed_vault_generation,
                            result_vault_generation,
                            changed,
                        ) =>
                    {
                        self.invalidate_secret_inventory_entry(
                            &provider_id,
                            Some(
                                cockpit_core::daemon::proto::SecretInventoryKind::CredentialRecord,
                            ),
                        );
                        Ok(format!("stored credential for {provider_id}"))
                    }
                    (
                        SettingsMutationAction::WebCredentialPut {
                            provider_id,
                            client_operation_id,
                        },
                        Ok(Response::ProviderCredentialCommitted {
                            client_operation_id: returned_operation_id,
                            provider_id: returned_provider_id,
                            project_root: None,
                            owner_root: None,
                            owner_scope,
                            stored: true,
                            changed,
                            consumed_vault_generation,
                            result_vault_generation,
                            config_generation,
                            ..
                        }),
                    ) if returned_operation_id == client_operation_id
                        && returned_provider_id == provider_id
                        && owner_scope == "global"
                        && config_generation > 0
                        && valid_vault_freshness(
                            consumed_vault_generation,
                            result_vault_generation,
                            changed,
                        ) =>
                    {
                        self.invalidate_secret_inventory_entry(
                            &provider_id,
                            Some(
                                cockpit_core::daemon::proto::SecretInventoryKind::CredentialRecord,
                            ),
                        );
                        self.completed_web_credential = Some((provider_id.clone(), Ok(())));
                        Ok(format!("stored credential for {provider_id}"))
                    }
                    (SettingsMutationAction::WebCredentialPut { provider_id, .. }, Ok(other)) => {
                        let error = format!("unexpected web credential response: {other:?}");
                        self.completed_web_credential = Some((provider_id, Err(error.clone())));
                        Err(error)
                    }
                    (SettingsMutationAction::WebCredentialPut { provider_id, .. }, Err(error)) => {
                        self.completed_web_credential = Some((provider_id, Err(error.clone())));
                        Err(error)
                    }
                    (
                        SettingsMutationAction::CopilotSetup {
                            provider_id,
                            client_operation_id,
                            project_root,
                        },
                        Ok(Response::CopilotAuthCommitted {
                            client_operation_id: returned_operation_id,
                            project_root: returned_root,
                            owner_root,
                            owner_scope,
                            provider_id: returned_provider_id,
                            consumed_vault_generation,
                            result_vault_generation,
                            config_generation,
                            ..
                        }),
                    ) if returned_operation_id == client_operation_id
                        && returned_provider_id == provider_id
                        && returned_root == project_root
                        && owner_root == project_root
                        && owner_scope == format!("project:{owner_root}")
                        && config_generation > 0
                        && result_vault_generation > consumed_vault_generation
                        && result_vault_generation > 0 =>
                    {
                        self.invalidate_secret_inventory_entry(&provider_id, None);
                        self.completed_provider_auth =
                            Some(CompletedProviderAuthMutation::Copilot {
                                provider_id,
                                result: Ok(()),
                            });
                        Ok("Copilot token configured in the daemon vault".to_string())
                    }
                    (
                        SettingsMutationAction::ProviderCredentialDelete { provider_id, .. },
                        result,
                    ) => {
                        let error = match result {
                            Ok(other) => format!("unexpected provider logout response: {other:?}"),
                            Err(error) => error,
                        };
                        self.completed_provider_auth =
                            Some(CompletedProviderAuthMutation::Logout {
                                provider_id,
                                result: Err(error.clone()),
                            });
                        Err(error)
                    }
                    (SettingsMutationAction::CopilotSetup { provider_id, .. }, result) => {
                        let error = match result {
                            Ok(other) => format!("unexpected Copilot setup response: {other:?}"),
                            Err(error) => error,
                        };
                        self.completed_provider_auth =
                            Some(CompletedProviderAuthMutation::Copilot {
                                provider_id,
                                result: Err(error.clone()),
                            });
                        Err(error)
                    }
                    (SettingsMutationAction::McpSave { .. }, Ok(other)) => {
                        let error = format!("unexpected MCP settings response: {other:?}");
                        if let Some((name, edited)) = self.pending_mcp_navigation.take() {
                            self.completed_mcp_navigation =
                                Some((name, edited, Err(error.clone())));
                        }
                        Err(error)
                    }
                    (SettingsMutationAction::McpSave { .. }, Err(error)) => {
                        if let Some((name, edited)) = self.pending_mcp_navigation.take() {
                            self.completed_mcp_navigation =
                                Some((name, edited, Err(error.clone())));
                        }
                        Err(error)
                    }
                    (_, Ok(other)) => {
                        Err(format!("unexpected settings mutation response: {other:?}"))
                    }
                    (_, Err(error)) => Err(error),
                };
                self.extended_warnings = vec![match result {
                    Ok(status) => status,
                    Err(error) => format!("settings operation failed: {error}"),
                }];
            }
            PendingSettingsOperation::SettlementQuery {
                target,
                client_operation_id,
                original,
            } => {
                if completion.target != target {
                    return Ok(());
                }
                match completion.response {
                    Ok(Response::LocalOperationSettlement {
                        client_operation_id: returned_id,
                        pending: false,
                        response: Some(response),
                    }) if returned_id == client_operation_id => {
                        let original = *original;
                        let original_target = original.target();
                        self.pending_settings
                            .insert(completion.operation_id, original);
                        return self.apply_general_completion(SettingsDaemonEffectCompletion {
                            dialog_id: completion.dialog_id,
                            operation_id: completion.operation_id,
                            target: original_target,
                            response: Ok(*response),
                            committed_refresh_needed: None,
                        });
                    }
                    Ok(Response::LocalOperationSettlement {
                        client_operation_id: returned_id,
                        pending: true,
                        response: None,
                    }) if returned_id == client_operation_id => {
                        self.pending_settings.insert(
                            completion.operation_id,
                            PendingSettingsOperation::SettlementUnknown {
                                target,
                                client_operation_id,
                                original,
                            },
                        );
                        self.extended_warnings = vec![
                            "operation remains unsettled; press any key to query the durable receipt again"
                                .into(),
                        ];
                    }
                    Ok(other) => {
                        tracing::warn!(response = ?other, "ignored unbound local settlement query response");
                        self.pending_settings.insert(
                            completion.operation_id,
                            PendingSettingsOperation::SettlementUnknown {
                                target,
                                client_operation_id,
                                original,
                            },
                        );
                        self.extended_warnings = vec![
                            "settlement receipt was unbound; press any key to query again".into(),
                        ];
                    }
                    Err(error) => {
                        tracing::warn!(%error, "local settlement query failed; retaining unknown state");
                        self.pending_settings.insert(
                            completion.operation_id,
                            PendingSettingsOperation::SettlementUnknown {
                                target,
                                client_operation_id,
                                original,
                            },
                        );
                        self.extended_warnings = vec![
                            "settlement query failed; press any key to retry without leaving this screen"
                                .into(),
                        ];
                    }
                }
            }
            PendingSettingsOperation::SettlementUnknown { .. } => {
                // No daemon effect is associated with this retained state.
                // `retry_unknown_settlement` replaces it before enqueueing the
                // next owner-scoped query.
                return Err(completion);
            }
            PendingSettingsOperation::TypedDocumentEdit {
                target,
                requested_path,
                action,
            } => {
                if completion.target != target {
                    return Ok(());
                }
                if let Some(committed) = completion.committed_refresh_needed {
                    self.extended_revision = None;
                    self.extended_warnings = vec![format!(
                        "{} (committed revision {}, generation {}); reload before editing again",
                        committed.warning, committed.result_revision, committed.config_generation
                    )];
                    return Ok(());
                }
                match completion.response {
                    Ok(Response::ExtendedConfigSnapshot {
                        layers,
                        config_generation,
                    }) => {
                        let reconciled = layers
                            .iter()
                            .find(|layer| layer.display_path == requested_path)
                            .cloned();
                        match (action, reconciled) {
                            (TypedDocumentEditAction::Scaffold, Some(layer)) => {
                                match decode_extended_layer(layer, config_generation) {
                                    Ok((extended, base, revision)) => {
                                        self.extended = extended;
                                        self.extended_base = base;
                                        self.extended_revision = Some(revision);
                                        self.extended_warnings =
                                            vec!["settings layer created".into()];
                                    }
                                    Err(error) => {
                                        self.extended_warnings = vec![format!(
                                            "settings committed, but refresh was invalid: {error}"
                                        )]
                                    }
                                }
                            }
                            (
                                TypedDocumentEditAction::RemoveProjectShadow(prompt),
                                Some(project_layer),
                            ) => {
                                let project_authored =
                                    project_layer.authored_paths.iter().any(|authored| {
                                        authored
                                            .iter()
                                            .map(String::as_str)
                                            .eq(prompt.path.iter().copied())
                                    });
                                let source = layers.iter().find(|layer| {
                                    layer.display_path == prompt.source_config.display().to_string()
                                });
                                let source_matches = source.is_some_and(|layer| {
                                    let value = serde_json::to_value(&layer.config).ok();
                                    let effective = value.as_ref().and_then(|document| {
                                        prompt.path.iter().try_fold(document, |value, segment| {
                                            value.get(*segment)
                                        })
                                    });
                                    !project_authored
                                        && layer.authored_paths.iter().any(|authored| {
                                            authored
                                                .iter()
                                                .map(String::as_str)
                                                .eq(prompt.path.iter().copied())
                                        })
                                        && effective == Some(&prompt.expected_effective_value)
                                });
                                if source_matches {
                                    self.completed_shadow_removal = Some(prompt);
                                    self.extended_warnings =
                                        vec!["project override removed".into()];
                                } else {
                                    self.extended_revision = None;
                                    self.extended_warnings = vec![
                                        "project override commit returned an unreconciled effective value; reload before editing again".into(),
                                    ];
                                }
                            }
                            (_, None) => {
                                self.extended_warnings = vec![
                                    "settings committed, but refreshed layer was absent".into(),
                                ]
                            }
                        }
                    }
                    Ok(other) => {
                        self.extended_warnings =
                            vec![format!("unexpected typed settings response: {other:?}")]
                    }
                    Err(error) => {
                        self.extended_warnings =
                            vec![format!("typed settings edit failed: {error}")]
                    }
                }
            }
            PendingSettingsOperation::CategoryExternalPrepare { .. }
            | PendingSettingsOperation::CategoryExternalRead { .. } => {
                self.extended_warnings =
                    vec!["category editor work completed on the wrong effect channel".into()];
            }
        }
        Ok(())
    }
    /// Return a cached metadata-only inventory answer and arrange a background
    /// refresh on a cache miss.  This is deliberately safe to call from a
    /// renderer: it never waits on the daemon or opens a local secret store.
    pub(super) fn cached_secret_inventory_contains(
        &self,
        name: &str,
        kind: Option<cockpit_core::daemon::proto::SecretInventoryKind>,
    ) -> Option<bool> {
        let key = format!("{kind:?}:{name}");
        if let Ok(cache) = self.secret_inventory_cache.lock()
            && let Some(value) = cache.get(&key)
        {
            return Some(*value);
        }
        self.refresh_secret_inventory_entry(name.to_string(), kind);
        None
    }

    pub(super) fn refresh_secret_inventory_entry(
        &self,
        name: String,
        kind: Option<cockpit_core::daemon::proto::SecretInventoryKind>,
    ) {
        // Synchronous unit-render tests intentionally have no Tokio runtime;
        // leave their cache miss as "checking" rather than panicking.
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let key = format!("{kind:?}:{name}");
        let Ok(mut pending) = self.secret_inventory_pending.lock() else {
            return;
        };
        if !pending.insert(key.clone()) {
            return;
        }
        let cache = Arc::clone(&self.secret_inventory_cache);
        let pending = Arc::clone(&self.secret_inventory_pending);
        tokio::spawn(async move {
            let present = match settings_daemon_client().await {
                Ok(client) => secret_inventory_contains(&client, &name, kind).await,
                Err(error) => Err(error.to_string()),
            };
            if let Ok(present) = present
                && let Ok(mut cache) = cache.lock()
            {
                cache.insert(key.clone(), present);
            }
            if let Ok(mut pending) = pending.lock() {
                pending.remove(&key);
            }
        });
    }

    pub(super) fn invalidate_secret_inventory_entry(
        &self,
        name: &str,
        kind: Option<cockpit_core::daemon::proto::SecretInventoryKind>,
    ) {
        let key = format!("{kind:?}:{name}");
        if let Ok(mut cache) = self.secret_inventory_cache.lock() {
            cache.remove(&key);
        }
    }

    pub(super) fn invalidate_secret_inventory(&self) {
        if let Ok(mut cache) = self.secret_inventory_cache.lock() {
            cache.clear();
        }
    }

    pub(super) fn refresh_host_capabilities(&mut self) -> cockpit_proto::HostCapabilitySnapshot {
        if self.capability_refresh_in_flight {
            return self.host_capabilities.clone();
        }
        self.capability_refresh_in_flight = true;
        self.capability_refresh_calls = self.capability_refresh_calls.saturating_add(1);
        if self.daemon_attached {
            self.pending_refresh_host_capabilities = true;
            self.pending_daemon_request = Some(Request::RefreshHostCapabilities);
        }
        if let Some(next) = self.capability_refresh_queue.pop() {
            self.host_capabilities = next;
        }
        self.capability_refresh_in_flight = false;
        self.host_capabilities.clone()
    }

    pub(super) fn apply_host_capabilities(
        &mut self,
        snapshot: cockpit_proto::HostCapabilitySnapshot,
        daemon_attached: bool,
    ) {
        self.host_capabilities = snapshot;
        self.daemon_attached = daemon_attached;
    }
}

fn root_page(cursor: usize) -> PageBox {
    Box::new(RootPage { cursor })
}

fn default_model_page(page: DefaultModelPage) -> PageBox {
    Box::new(page)
}

/// `/settings` -> **Default model for new sessions**.
///
/// Shows the currently effective default (or an explicit unset state) and its
/// safe scope label, opens the same provider-scoped model picker `/model`
/// uses, and can clear the context default. Every mutation goes through the
/// daemon's one authoritative effective-default operation; this page never
/// writes `active_model` and never changes a running session.
pub(super) struct DefaultModelPage {
    pub(super) status: Option<String>,
    /// Resolved once when the page opens, alongside the *effective* default
    /// below — both are layered resolutions and must not run per frame.
    pub(super) scope_label: String,
    /// The default a new session would actually resolve, i.e. the merge of
    /// every applicable layer. `cx.config` is only the single layer this
    /// dialog edits, so showing it here would misreport the default whenever
    /// a higher-precedence layer overrides it (AC9).
    pub(super) effective_default: Option<cockpit_config::providers::ActiveModelRef>,
}

impl SettingsPage for DefaultModelPage {
    fn pointer_surface_kind(&self) -> SettingsPointerSurfaceKind {
        SettingsPointerSurfaceKind::DefaultModel
    }

    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        match key.code {
            KeyCode::Esc
            | KeyCode::Char('q')
            | KeyCode::Left
            | KeyCode::Char('h')
            | KeyCode::Backspace => Nav::Back,
            KeyCode::Enter | KeyCode::Char('c') => {
                cx.pending_default_model_picker = true;
                Nav::Close
            }
            // Clearing is a daemon-verified operation: it succeeds only when
            // the reloaded effective configuration still resolves to a
            // deterministic inherited default or an explicit no-default state.
            KeyCode::Char('x') => {
                if self.effective_default.is_none() {
                    self.status =
                        Some("No default is set in this configuration context.".to_string());
                    return Nav::Stay;
                }
                let default_update_id = uuid::Uuid::new_v4();
                // Correlate the terminal event with this exact operation so
                // the confirmation names the resulting effective state.
                cx.pending_default_model_update_id = Some(default_update_id);
                cx.pending_daemon_request = Some(Request::SetDefaultModel {
                    default_update_id,
                    provider: None,
                    model: None,
                    reasoning_effort: None,
                    thinking_mode: None,
                    prompt_cache_retention: None,
                    clear: true,
                });
                self.status = Some(
                    "Clearing the default for new sessions… the result names the resulting effective state."
                        .to_string(),
                );
                Nav::Stay
            }
            _ => Nav::Stay,
        }
    }

    fn handle_pointer_control(
        &mut self,
        cx: &mut SettingsCx,
        action: pointer_actions::SettingsPointerAction,
    ) -> Nav {
        match action {
            pointer_actions::SettingsPointerAction::DefaultModel(
                pointer_actions::DefaultModelAction::Choose,
            ) => self.handle_key(cx, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            pointer_actions::SettingsPointerAction::DefaultModel(
                pointer_actions::DefaultModelAction::Clear,
            ) if self.effective_default.is_some() => {
                self.handle_key(cx, KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE))
            }
            _ => Nav::Stay,
        }
    }

    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        // Both values are resolved when the page opens: each is a layered
        // resolution and must not run per frame.
        let default = self.effective_default.as_ref();
        let scope = &self.scope_label;
        let mut lines = vec![Line::from("Default model for new sessions"), Line::from("")];
        match default {
            Some(active) => {
                lines.push(Line::from(format!(
                    "Effective default: {}/{}",
                    active.provider, active.model
                )));
                if let Some(effort) = active.reasoning_effort.as_ref() {
                    lines.push(Line::from(format!("  reasoning: {}", effort.value)));
                }
            }
            None => lines.push(Line::from(
                "Effective default: (unset — a new session resolves its model at creation)",
            )),
        }
        lines.push(Line::from(format!("Scope: {scope}")));
        lines.push(Line::from(""));
        let choose_line = lines.len();
        lines.push(Line::default());
        let clear_line = lines.len();
        lines.push(Line::default());
        lines.push(Line::from("Applies to newly created sessions only."));
        lines.push(Line::from(
            "Reopening an existing session keeps its own saved model.",
        ));
        if let Some(status) = &self.status {
            lines.push(Line::from(""));
            lines.push(Line::from(status.clone()));
        }
        let para = Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: false });
        frame.render_widget(para, area);
        for (line, action, enabled, label) in [
            (
                choose_line,
                pointer_actions::SettingsPointerAction::DefaultModel(
                    pointer_actions::DefaultModelAction::Choose,
                ),
                true,
                "Choose default model",
            ),
            (
                clear_line,
                pointer_actions::SettingsPointerAction::DefaultModel(
                    pointer_actions::DefaultModelAction::Clear,
                ),
                self.effective_default.is_some(),
                "Clear default for this scope",
            ),
        ] {
            cx.pointer_surface.paint_page_button(
                frame,
                area.x,
                area.y.saturating_add(line as u16),
                area.width,
                action,
                label,
                enabled,
                false,
            );
        }
    }

    fn title(&self, _cx: &SettingsCx) -> String {
        "Default model for new sessions".into()
    }

    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        "enter: change default  x: clear  esc/h: back"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "DefaultModel"
    }
}

fn agents_page(page: AgentsPage) -> PageBox {
    Box::new(page)
}

fn tools_page(page: ToolsPage) -> PageBox {
    Box::new(page)
}

fn harnesses_page(page: HarnessesPage) -> PageBox {
    Box::new(page)
}

fn providers_page(page: ProvidersPage) -> PageBox {
    Box::new(page)
}

fn category_page(page: CategoryPage) -> PageBox {
    Box::new(page)
}

fn instructions_page(page: InstructionsPage) -> PageBox {
    Box::new(page)
}

fn redact_patterns_page(page: RedactPatternsPage) -> PageBox {
    Box::new(page)
}

fn string_list_page(page: StringListPage) -> PageBox {
    Box::new(page)
}

fn skills_page(page: SkillsPage) -> PageBox {
    Box::new(page)
}

fn mcp_page(page: McpPage) -> PageBox {
    Box::new(page)
}

fn lsp_page(page: LspPage) -> PageBox {
    Box::new(page)
}

use agents_page::AgentsPage;
use category::{Category, CategoryPage};
#[cfg(test)]
use cockpit_core::daemon::proto::LspControlAction;
use harnesses_page::HarnessesPage;
use lsp_page::LspPage;
#[cfg(test)]
use lsp_page::{
    LSP_NAV_ROWS, LSP_SERVER_ROW_START, LspEdit, LspRow, PROJECT_CONTEXT_UNAVAILABLE,
    ProjectContext, lsp_rows, lsp_selected_line_for_cursor, project_context_for_config, row_index,
};
use mcp_page::McpPage;
pub(crate) use mcp_page::row_color as mcp_row_color;
use providers::{AddState, EditState, ModelEditor, ProvidersPage};
pub(crate) use providers::{
    OAuthBeginResult, OAuthFlowOp, OAuthFlowRequest, OAuthProvider, OAuthPublicBegin,
};
use reset::ResetButton;
use skills_page::SkillsPage;
use string_list::StringListPage;
use tools_page::ToolsPage;

use ui_page::{InstructionsPage, RedactPatternsPage};

fn oauth_credential_inventory_name(provider: OAuthProvider) -> &'static str {
    match provider {
        OAuthProvider::Grok => cockpit_core::auth::xai_oauth::CREDENTIAL_KEY,
        OAuthProvider::Codex => cockpit_core::auth::codex_oauth::CREDENTIAL_KEY,
    }
}

fn oauth_acknowledgement_inventory_name(provider: OAuthProvider) -> String {
    let provider = match provider {
        OAuthProvider::Grok => cockpit_core::auth::subscription_ack::GROK_OAUTH_PROVIDER,
        OAuthProvider::Codex => cockpit_core::auth::subscription_ack::CODEX_OAUTH_PROVIDER,
    };
    format!(
        "{}{}",
        cockpit_core::auth::subscription_ack::PREFIX,
        provider
    )
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct RowDeleteConfirm {
    pending: Option<usize>,
}

impl RowDeleteConfirm {
    pub(super) fn arm_or_confirm(&mut self, row: usize) -> bool {
        if self.pending == Some(row) {
            self.pending = None;
            true
        } else {
            self.pending = Some(row);
            false
        }
    }

    pub(super) fn disarm(&mut self) {
        self.pending = None;
    }

    pub(super) fn is_pending_for(&self, row: usize) -> bool {
        self.pending == Some(row)
    }
}

/// Navigation intent returned by a settings page. Page handlers return boxed
/// pages to keep the outer dialog as the only owner of stack mutation.
pub(super) enum Nav {
    /// Stay on the current page; sub-state mutations have already been
    /// applied to the borrowed `&mut SubState`.
    Stay,
    /// Navigate without preserving the current page.
    Replace(PageBox),
    /// Push the current page and navigate to another page.
    Push(PageBox),
    /// Pop one page from the navigation stack.
    Back,
    /// Close the whole dialog.
    Close,
}

// ── Dialog top-level ─────────────────────────────────────────────────────

impl Dialog {
    pub(crate) fn handle_settings_pointer(
        &mut self,
        mouse: MouseEvent,
    ) -> Option<SettingsPointerOutcome> {
        let Dialog::Settings(settings) = self else {
            return None;
        };
        // App-level z-order may route Settings before chat affordances only
        // after the dialog has actually rendered a pointer surface. A newly
        // constructed, not-yet-rendered dialog has no geometry to own and
        // must not swallow suggestion/selection events underneath it.
        settings.pointer_surface.area.get()?;
        Some(settings.handle_pointer(mouse))
    }

    pub(crate) fn clear_settings_pointer_hover(&self) {
        if let Dialog::Settings(settings) = self {
            *settings.pointer_surface.hover.borrow_mut() = None;
        }
    }
    pub(crate) fn cancel_settings_pointer_transients(&mut self) {
        if let Dialog::Settings(settings) = self {
            *settings.pointer_surface.hover.borrow_mut() = None;
            settings.pointer_surface.header_hover.set(None);
            *settings.pointer_surface.pressed.borrow_mut() = None;
            settings.page.cancel_pointer_transients();
        }
    }

    /// Current Behavior → response metrics tokenizer from an open settings
    /// dialog, used by App to arm confirmation on close.
    pub(crate) fn response_metrics_tokenizer(&self) -> Option<cockpit_tokenizer::TiktokenEncoding> {
        match self {
            Dialog::Settings(settings) => Some(settings.extended.response_metrics_tokenizer),
            _ => None,
        }
    }
    pub fn is_active(&self) -> bool {
        !matches!(self, Dialog::None)
    }

    pub fn is_workspace_trust(&self) -> bool {
        matches!(self, Dialog::WorkspaceTrust { .. })
    }

    pub(crate) fn set_runtime_sandbox_enabled(&mut self, enabled: bool) {
        if let Dialog::Settings(settings) = self {
            settings.cx.sandbox_enabled = enabled;
        }
    }

    #[cfg(test)]
    pub(crate) fn test_page_name(&self) -> Option<&'static str> {
        match self {
            Dialog::Settings(settings) => Some(settings.page.test_name()),
            Dialog::WorkspaceTrust { .. } => Some("workspace_trust"),
            Dialog::WizardMenu { .. } => Some("wizard_menu"),
            Dialog::SetupWizard(wizard) => Some(wizard.run.descriptor().id),
            Dialog::FirstRunComplete { .. } => Some("first_run_complete"),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_provider_surface(&self) -> Option<&'static str> {
        let Dialog::Settings(settings) = self else {
            return None;
        };
        let page = settings.page.as_any().downcast_ref::<ProvidersPage>()?;
        Some(match page {
            ProvidersPage::OAuthSetup { .. } => "oauth",
            ProvidersPage::Edit(_) => "edit",
            _ => "other",
        })
    }

    #[cfg(test)]
    pub(crate) fn test_provider_is_add(&self) -> bool {
        let Dialog::Settings(settings) = self else {
            return false;
        };
        matches!(
            settings.page.as_any().downcast_ref::<ProvidersPage>(),
            Some(ProvidersPage::Add(_))
        )
    }

    #[cfg(test)]
    pub(crate) fn test_provider_add_status(&self) -> Option<&str> {
        let Dialog::Settings(settings) = self else {
            return None;
        };
        let page = settings.page.as_any().downcast_ref::<ProvidersPage>()?;
        let ProvidersPage::Add(add) = page else {
            return None;
        };
        add.error.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn test_mark_provider_add_done(&mut self, provider_id: &str) {
        let Dialog::Settings(settings) = self else {
            panic!("expected settings dialog");
        };
        let page = settings
            .page
            .downcast_mut::<ProvidersPage>()
            .expect("expected providers page");
        let ProvidersPage::Add(add) = page else {
            panic!("expected provider add page");
        };
        add.saved_provider_id = Some(provider_id.to_string());
        add.run
            .return_to("done")
            .expect("provider done step exists");
    }

    #[cfg(test)]
    pub(crate) fn test_mark_setup_complete(&mut self, step_id: &str) {
        let Dialog::SetupWizard(wizard) = self else {
            panic!("expected setup wizard");
        };
        wizard
            .run
            .return_to(step_id)
            .expect("setup completion step exists");
        wizard
            .run
            .submit(cockpit_core::wizard::WizardAnswer::Acknowledged)
            .expect("setup completion step accepts acknowledgement");
    }

    #[cfg(test)]
    pub(crate) fn test_setup_answer(
        &self,
        step_id: &str,
    ) -> Option<cockpit_core::wizard::WizardAnswer> {
        let Dialog::SetupWizard(wizard) = self else {
            return None;
        };
        wizard.run.answer(step_id).cloned()
    }

    #[cfg(test)]
    pub(crate) fn test_setup_prefill(&self) -> Option<cockpit_core::wizard::WizardAnswer> {
        let Dialog::SetupWizard(wizard) = self else {
            return None;
        };
        wizard.run.prefill()
    }

    pub fn open(cwd: &std::path::Path) -> Self {
        let dirs = discover_config_dirs(cwd);
        if dirs.is_empty() {
            Dialog::CreateConfig {
                choices: creatable_config_dirs(),
                cursor: 0,
                cwd: cwd.to_path_buf(),
                status: None,
            }
        } else {
            Dialog::PickConfig {
                dirs,
                cursor: 0,
                cwd: cwd.to_path_buf(),
                status: None,
            }
        }
    }

    pub fn open_workspace_trust(root: cockpit_config::trust::TrustRoot) -> Self {
        Dialog::WorkspaceTrust {
            root,
            cursor: 0,
            chosen: None,
        }
    }

    pub fn take_workspace_trust_choice(
        &mut self,
    ) -> Option<(
        cockpit_config::trust::TrustRoot,
        cockpit_config::WorkspaceTrustMode,
    )> {
        let Dialog::WorkspaceTrust { root, chosen, .. } = self else {
            return None;
        };
        chosen.take().map(|mode| (root.clone(), mode))
    }

    /// Open directly into the MCP page (`/mcp settings`, GOALS §18a).
    pub fn open_mcp(cwd: &std::path::Path) -> Self {
        let mut d = Self::open(cwd);
        if let Dialog::PickConfig { dirs, .. } = &d
            && let Some(dir) = dirs.first()
        {
            let path = dir.path.join(CONFIG_FILE);
            d = Dialog::Settings(Box::new(SettingsDialog::open_from_picker(
                path,
                cwd.to_path_buf(),
            )));
            if let Dialog::Settings(s) = &mut d {
                s.enter_mcp();
            }
        }
        d
    }

    /// Open the settings dialog directly on the **active** model's
    /// model-settings sub-dialog (implementation note,
    /// `/model-settings`). When no model is active — or the active
    /// provider/model can't be found in config — open to the providers list
    /// with an inline status explaining there's nothing selected.
    pub fn open_model_settings(cwd: &std::path::Path) -> Self {
        let mut d = Self::open(cwd);
        if let Dialog::PickConfig { dirs, .. } = &d
            && let Some(dir) = dirs.first()
        {
            let path = dir.path.join(CONFIG_FILE);
            let mut s = SettingsDialog::open_from_picker(path, cwd.to_path_buf());
            s.enter_model_settings();
            d = Dialog::Settings(Box::new(s));
        }
        d
    }

    /// Open the settings dialog directly on the gitignore read-allowlist
    /// editor for the **current project** (`/gitignore-allow`,
    /// implementation note). The target config is the
    /// nearest project `.cockpit/config.json` (the deepest ancestor with a
    /// `.cockpit/` layer), scaffolded at `cwd` when none exists, so the editor
    /// writes the project layer. When `glob` is non-empty it is quick-added
    /// (and persisted) before the editor opens.
    pub fn open_gitignore_allow(cwd: &std::path::Path, glob: Option<&str>) -> Self {
        let path = nearest_project_config_path(cwd);
        let mut s = SettingsDialog::open_from_picker(path, cwd.to_path_buf());
        if let Some(g) = glob.filter(|g| !g.trim().is_empty()) {
            s.quick_add_gitignore_allow(g);
        }
        s.enter_gitignore_allow();
        Dialog::Settings(Box::new(s))
    }

    /// True when the first discovered config layer has zero provider files
    /// configured. Used by the TUI's
    /// first-run flow to auto-route into the Add wizard after the
    /// daemon prompt resolves.
    #[cfg(test)]
    pub fn has_no_providers(cwd: &std::path::Path) -> bool {
        daemon_provider_snapshot(cwd, None).is_none_or(|config| config.providers.is_empty())
    }

    /// Open the Add-Provider wizard directly, skipping the Providers
    /// list. Used when the user has no providers configured at TUI
    /// launch.
    pub fn open_providers_add(cwd: &std::path::Path) -> Self {
        Self::open_providers_add_with_status(cwd, None)
    }

    pub fn open_providers_add_with_status(cwd: &std::path::Path, status: Option<String>) -> Self {
        // The provider wizard is the first-run destination, not the generic
        // config-location picker. Opening (or cancelling) it must not create
        // a config layer. The daemon creates the selected target atomically
        // when the user first saves a provider.
        let path = match discover_config_dirs(cwd).first() {
            Some(dir) => Ok(dir.path.join(CONFIG_FILE)),
            None => creatable_config_dirs()
                .first()
                .ok_or_else(|| std::io::Error::other("no Cockpit config directory is available"))
                .map(|dir| dir.path.join(CONFIG_FILE)),
        };

        match path {
            Ok(path) => {
                let mut s = SettingsDialog::open_from_picker(path, cwd.to_path_buf());
                let mut add = AddState::new();
                add.error = status;
                s.page = providers_page(ProvidersPage::Add(add));
                Dialog::Settings(Box::new(s))
            }
            Err(error) => Dialog::CreateConfig {
                choices: creatable_config_dirs(),
                cursor: 0,
                cwd: cwd.to_path_buf(),
                status: Some(format!(
                    "could not select an initial Cockpit config: {error}"
                )),
            },
        }
    }

    pub fn open_setup(cwd: &std::path::Path) -> Self {
        Dialog::WizardMenu {
            wizards: cockpit_core::wizard::registry(),
            cursor: 0,
            cwd: cwd.to_path_buf(),
        }
    }

    pub fn open_setup_wizard(cwd: &std::path::Path, wizard_id: &str) -> Result<Self, String> {
        match wizard_id {
            cockpit_core::wizard::PROVIDER_WIZARD_ID => Ok(Self::open_providers_add(cwd)),
            cockpit_core::wizard::SECURITY_WIZARD_ID | cockpit_core::wizard::MODEL_WIZARD_ID => {
                let descriptor = cockpit_core::wizard::descriptor_for_cwd(wizard_id, cwd)
                    .ok_or_else(|| format!("unknown setup wizard `{wizard_id}`"))?;
                setup_wizard_dialog(cwd, descriptor, None)
            }
            other => Err(format!("unknown setup wizard `{other}`")),
        }
    }

    pub fn open_model_setup_preselected(
        cwd: &std::path::Path,
        provider_id: &str,
        model_id: &str,
        status: Option<String>,
    ) -> Result<Self, String> {
        let descriptor =
            cockpit_core::wizard::model_descriptor_for_cwd(cwd, Some((provider_id, model_id)));
        setup_wizard_dialog(cwd, descriptor, status)
    }

    pub fn open_model_setup_choice(
        cwd: &std::path::Path,
        confirmed: Option<(String, String)>,
        pending: Option<(String, String)>,
    ) -> Self {
        Self::ModelSetupChoice {
            cwd: cwd.to_path_buf(),
            confirmed,
            pending,
            cursor: 0,
        }
    }

    pub fn open_first_run_complete(summary: String) -> Self {
        Dialog::FirstRunComplete { summary }
    }

    pub fn take_completed_provider_id(&mut self) -> Option<String> {
        let Dialog::Settings(settings) = self else {
            return None;
        };
        let page = settings.page.downcast_mut::<ProvidersPage>()?;
        let ProvidersPage::Add(add) = page else {
            return None;
        };
        if add.run.is_complete() || add.is_step("done") {
            return add.saved_provider_id.clone();
        }
        None
    }

    pub fn setup_wizard_is_complete(&self, wizard_id: &str) -> bool {
        matches!(
            self,
            Dialog::SetupWizard(wizard)
                if wizard.run.descriptor().id == wizard_id && wizard.run.is_complete()
        )
    }

    /// Open directly on one configured provider. OAuth-expired failures for a
    /// known OAuth template land in its login flow; custom/template-less
    /// providers land on the ordinary edit page.
    pub fn open_provider_settings(
        cwd: &std::path::Path,
        provider_id: &str,
        oauth_expired: bool,
    ) -> Self {
        let Some(path) = config_write_target_for_provider(cwd, provider_id) else {
            return Self::open(cwd);
        };
        let mut settings = SettingsDialog::open_from_picker(path, cwd.to_path_buf());
        settings.page = providers_page(ProvidersPage::List {
            cursor: 0,
            status: Some(format!("loading `{provider_id}` from the daemon…")),
            delete_pending: false,
        });
        settings.cx.queue_provider_catalog_for(
            Some(provider_id.to_string()),
            Some(ProviderNavigation::Edit {
                provider_id: provider_id.to_string(),
                oauth_expired,
            }),
        );
        Dialog::Settings(Box::new(settings))
    }

    /// Open the existing provider-model editor directly for one configured provider.
    /// This is the canonical add-model surface used by scoped model recovery.
    pub fn open_provider_models(cwd: &std::path::Path, provider_id: &str) -> Self {
        let Some(path) = config_write_target_for_provider(cwd, provider_id) else {
            return Self::open(cwd);
        };
        let mut settings = SettingsDialog::open_from_picker(path, cwd.to_path_buf());
        settings.page = providers_page(ProvidersPage::List {
            cursor: 0,
            status: Some(format!("loading models for `{provider_id}`…")),
            delete_pending: false,
        });
        settings.cx.queue_provider_catalog_for(
            Some(provider_id.to_string()),
            Some(ProviderNavigation::Models {
                provider_id: provider_id.to_string(),
            }),
        );
        Dialog::Settings(Box::new(settings))
    }

    /// Re-open the picker after scaffolding a new scoped config, so the
    /// fresh row shows up and lands as the cursor target.
    fn reopen_picker(cwd: &std::path::Path, status: Option<String>) -> Self {
        let dirs = discover_config_dirs(cwd);
        if dirs.is_empty() {
            Dialog::CreateConfig {
                choices: creatable_config_dirs(),
                cursor: 0,
                cwd: cwd.to_path_buf(),
                status,
            }
        } else {
            Dialog::PickConfig {
                dirs,
                cursor: 0,
                cwd: cwd.to_path_buf(),
                status,
            }
        }
    }

    /// Drain the UI page's pending `mouse` toggle, if any. Returns
    /// `Some(new_value)` exactly once per user toggle so the App can
    /// push/pop crossterm's `EnableMouseCapture` to match. None when
    /// the dialog isn't on the UI page or the user hasn't touched the
    /// setting since the last drain.
    pub fn take_pending_mouse_capture(&mut self) -> Option<bool> {
        let Dialog::Settings(s) = self else {
            return None;
        };
        s.page
            .downcast_mut::<CategoryPage>()
            .and_then(|p| p.pending_mouse_capture.take())
    }

    /// Drain a pending external-editor (`$EDITOR`) request from the Agents
    /// page, if any. Returns the on-disk agent file the event loop should
    /// open `$EDITOR` against; the loop owns the terminal suspend/restore
    /// (the page handler can't), then calls [`Self::finish_agent_edit`] to
    /// re-read + re-parse the file. `None` unless the user just chose to
    /// edit an agent and `$EDITOR` is set.
    pub(crate) fn take_pending_agent_edit(
        &mut self,
    ) -> Option<agents_page::AgentExternalEditEffect> {
        let Dialog::Settings(s) = self else {
            return None;
        };
        s.page
            .downcast_mut::<AgentsPage>()
            .and_then(AgentsPage::take_external_edit_request)
    }

    /// Apply the result of an external-editor session the event loop ran on
    /// behalf of the Agents page: re-read the file from disk, re-parse it,
    /// surface any parse error inline, and refresh the row markers/model.
    /// The host reports a typed Saved/Cancelled/Failed terminal outcome;
    /// only Saved may atomically replace the real agent path.
    pub(crate) fn finish_agent_edit(
        &mut self,
        operation_id: shell::PointerOperationId,
        outcome: pointer_actions::ExternalEditOutcome,
        detail: Option<String>,
    ) {
        let Dialog::Settings(s) = self else {
            return;
        };
        s.finish_agent_external_edit(operation_id, outcome, detail);
    }

    /// Drain a pending category setting `$EDITOR` request. The category page
    /// retains the temp path until [`Self::finish_category_setting_edit`] reads
    /// it back and drops it.
    pub(crate) fn take_pending_category_setting_edit(
        &mut self,
    ) -> Option<(shell::PointerOperationId, PathBuf)> {
        let Dialog::Settings(s) = self else {
            return None;
        };
        s.take_pending_category_external_edit()
    }

    /// Apply the result of a category-setting `$EDITOR` round trip.
    pub(crate) fn finish_category_setting_edit(
        &mut self,
        operation_id: shell::PointerOperationId,
        outcome: pointer_actions::ExternalEditOutcome,
        detail: Option<String>,
    ) {
        let Dialog::Settings(s) = self else {
            return;
        };
        s.finish_category_external_edit(operation_id, outcome, detail);
    }

    /// Called by the event loop each tick so async fetches can apply
    /// their results.
    pub fn tick(&mut self) {
        if let Dialog::Settings(s) = self {
            s.tick();
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match self {
            Dialog::None => false,
            Dialog::FirstRunComplete { .. } => {
                matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q'))
            }
            Dialog::WorkspaceTrust { cursor, chosen, .. } => {
                match workspace_trust_key_action(key, cursor) {
                    WorkspaceTrustAction::Stay => false,
                    WorkspaceTrustAction::Choose(mode) => {
                        *chosen = Some(mode);
                        true
                    }
                }
            }
            Dialog::PickConfig {
                dirs,
                cursor,
                cwd,
                status,
            } => {
                // `a` opens the "add a scoped config" sub-dialog.
                // Anything else clears the transient status and falls
                // through to the standard list nav.
                if matches!(key.code, KeyCode::Char('a')) {
                    *self = Dialog::CreateScopedConfig {
                        choices: cwd_scoped_creatable_dirs(cwd),
                        cursor: 0,
                        cwd: cwd.clone(),
                    };
                    return false;
                }
                *status = None;
                match list_key_action(key, cursor, dirs.len()) {
                    ListAction::Stay => false,
                    ListAction::Close => true,
                    ListAction::Select(idx) => {
                        let chosen = dirs[idx].path.join(CONFIG_FILE);
                        let cwd = cwd.clone();
                        *self = Dialog::Settings(Box::new(SettingsDialog::open_from_picker(
                            chosen, cwd,
                        )));
                        false
                    }
                }
            }
            Dialog::CreateConfig {
                choices,
                cursor,
                cwd,
                status,
            } => match list_key_action(key, cursor, choices.len()) {
                ListAction::Stay => {
                    *status = None;
                    false
                }
                ListAction::Close => true,
                ListAction::Select(idx) => {
                    let settings =
                        SettingsDialog::open_for_scaffold(choices[idx].path.clone(), cwd.clone());
                    *self = Dialog::Settings(Box::new(settings));
                    false
                }
            },
            Dialog::CreateScopedConfig {
                choices,
                cursor,
                cwd,
            } => match list_key_action(key, cursor, choices.len()) {
                // Cancel → back to the picker.
                ListAction::Close => {
                    *self = Dialog::reopen_picker(cwd, None);
                    false
                }
                ListAction::Stay => false,
                ListAction::Select(idx) => {
                    let target = &choices[idx];
                    let settings =
                        SettingsDialog::open_for_scaffold(target.path.clone(), cwd.clone());
                    *self = Dialog::Settings(Box::new(settings));
                    false
                }
            },
            Dialog::WizardMenu {
                wizards,
                cursor,
                cwd,
            } => match list_key_action(key, cursor, wizards.len()) {
                ListAction::Stay => false,
                ListAction::Close => true,
                ListAction::Select(idx) => {
                    let wizard_id = wizards[idx].id;
                    match Self::open_setup_wizard(cwd, wizard_id) {
                        Ok(dialog) => *self = dialog,
                        Err(_) => *self = Dialog::open(cwd),
                    }
                    false
                }
            },
            Dialog::ModelSetupChoice {
                cwd,
                confirmed,
                cursor,
                ..
            } => {
                let choices = if confirmed.is_some() { 2 } else { 1 };
                match list_key_action(key, cursor, choices) {
                    ListAction::Stay => false,
                    ListAction::Close => true,
                    ListAction::Select(index) => {
                        let next = if confirmed.is_some() && index == 0 {
                            let (provider, model) = confirmed
                                .as_ref()
                                .expect("confirmed choice must have a pair");
                            Self::open_model_setup_preselected(cwd, provider, model, None)
                        } else {
                            Self::open_setup_wizard(cwd, cockpit_core::wizard::MODEL_WIZARD_ID)
                        };
                        if let Ok(next) = next {
                            *self = next;
                        }
                        false
                    }
                }
            }
            Dialog::SetupWizard(wizard) => handle_setup_wizard_key(wizard, key),
            Dialog::Settings(s) => {
                let close = s.handle_key(key);
                if close
                    && s.back_to_picker
                    && let Some(cwd) = s.picker_cwd.clone()
                {
                    *self = Dialog::reopen_picker(&cwd, None);
                    return false;
                }
                close
            }
        }
    }

    /// Insert pasted text into the focused text field. Only the settings
    /// pages own text fields; the config pickers are pure list nav, so a
    /// paste there is dropped.
    pub fn paste(&mut self, text: &str) {
        if let Dialog::Settings(s) = self {
            s.paste(text);
        }
    }

    pub fn take_daemon_request(&mut self) -> Option<Request> {
        match self {
            Dialog::Settings(s) => s.pending_daemon_request.take(),
            _ => None,
        }
    }

    pub(crate) fn take_settings_daemon_effect(&mut self) -> Option<SettingsDaemonEffectRequest> {
        match self {
            Dialog::Settings(settings) => settings.cx.take_daemon_effect(),
            _ => None,
        }
    }

    pub(crate) fn take_settings_blocking_effect(
        &mut self,
    ) -> Option<SettingsBlockingEffectRequest> {
        match self {
            Dialog::Settings(settings) => settings.cx.take_blocking_effect(),
            _ => None,
        }
    }

    pub(crate) fn apply_settings_daemon_completion(
        &mut self,
        completion: SettingsDaemonEffectCompletion,
    ) {
        let Dialog::Settings(settings) = self else {
            return;
        };
        if completion.dialog_id != settings.cx.dialog_id {
            return;
        }
        settings.apply_daemon_completion(completion);
    }

    pub(crate) fn apply_settings_blocking_completion(
        &mut self,
        completion: SettingsBlockingEffectCompletion,
    ) {
        let Dialog::Settings(settings) = self else {
            return;
        };
        if completion.dialog_id != settings.cx.dialog_id {
            return;
        }
        settings.apply_blocking_completion(completion);
    }

    pub fn apply_host_capabilities(
        &mut self,
        snapshot: cockpit_proto::HostCapabilitySnapshot,
        daemon_attached: bool,
    ) {
        if let Dialog::Settings(s) = self {
            s.apply_host_capabilities(snapshot, daemon_attached);
        }
    }

    /// Correlation id of the default-model request most recently staged by
    /// this dialog, taken alongside the request itself.
    pub fn take_pending_default_model_update_id(&mut self) -> Option<uuid::Uuid> {
        match self {
            Dialog::Settings(s) => s.pending_default_model_update_id.take(),
            _ => None,
        }
    }

    pub fn take_pending_default_model_picker(&mut self) -> bool {
        match self {
            Dialog::Settings(s) => {
                let pending = s.pending_default_model_picker;
                s.pending_default_model_picker = false;
                pending
            }
            _ => false,
        }
    }

    pub(crate) fn take_oauth_action(&mut self) -> Option<OAuthFlowRequest> {
        match self {
            Dialog::Settings(s) => s.pending_oauth_action.take(),
            _ => None,
        }
    }

    pub(crate) fn oauth_provider(&self) -> Option<OAuthProvider> {
        match self {
            Dialog::Settings(settings) => settings.oauth_flow_provider(),
            _ => None,
        }
    }

    pub(crate) fn apply_oauth_begin(
        &mut self,
        provider: OAuthProvider,
        client_flow_id: pointer_actions::OAuthFlowId,
        operation_id: shell::PointerOperationId,
        result: OAuthBeginResult,
    ) {
        if let Dialog::Settings(s) = self {
            s.apply_oauth_begin(provider, client_flow_id, operation_id, result);
        }
    }

    pub(crate) fn apply_oauth_complete(
        &mut self,
        provider: OAuthProvider,
        client_flow_id: pointer_actions::OAuthFlowId,
        operation_id: shell::PointerOperationId,
        result: Result<bool, String>,
    ) {
        if let Dialog::Settings(s) = self {
            s.apply_oauth_complete(provider, client_flow_id, operation_id, result);
        }
    }

    pub(crate) fn apply_oauth_present(
        &mut self,
        provider: OAuthProvider,
        client_flow_id: pointer_actions::OAuthFlowId,
        operation_id: shell::PointerOperationId,
        result: Result<providers::OAuthPresentationResult, String>,
    ) {
        if let Dialog::Settings(s) = self {
            s.apply_oauth_present(provider, client_flow_id, operation_id, result);
        }
    }

    pub(crate) fn apply_oauth_cancel(
        &mut self,
        provider: OAuthProvider,
        client_flow_id: pointer_actions::OAuthFlowId,
        operation_id: shell::PointerOperationId,
        result: Result<(), String>,
    ) {
        if let Dialog::Settings(s) = self {
            s.apply_oauth_cancel(provider, client_flow_id, operation_id, result);
        }
    }

    pub(crate) fn apply_oauth_settlement_unknown(
        &mut self,
        provider: OAuthProvider,
        client_flow_id: pointer_actions::OAuthFlowId,
        operation_id: shell::PointerOperationId,
        error: String,
    ) {
        if let Some(s) = self.state.as_mut()
            && let Some(s) = s.downcast_mut::<SettingsDialog>()
        {
            s.apply_oauth_settlement_unknown(provider, client_flow_id, operation_id, error);
        }
    }

    pub(crate) fn apply_oauth_acknowledgement(
        &mut self,
        provider: OAuthProvider,
        client_flow_id: pointer_actions::OAuthFlowId,
        operation_id: shell::PointerOperationId,
        result: Result<(), String>,
    ) {
        if let Dialog::Settings(s) = self {
            s.apply_oauth_acknowledgement_correlated(
                provider,
                client_flow_id,
                operation_id,
                result,
            );
        }
    }

    pub fn render(
        &self,
        frame: &mut Frame,
        area: Rect,
        links: &mut crate::tui::links::LinkRegistry,
    ) {
        match self {
            Dialog::None => {}
            Dialog::WorkspaceTrust { root, cursor, .. } => {
                render_workspace_trust(frame, area, root, *cursor)
            }
            Dialog::PickConfig {
                dirs,
                cursor,
                status,
                ..
            } => render_picker(
                frame,
                area,
                "pick a config to edit",
                dirs,
                *cursor,
                status.as_deref(),
                "↑/↓  enter: select  a: add scoped  esc: close",
            ),
            Dialog::CreateConfig {
                choices,
                cursor,
                status,
                ..
            } => render_picker(
                frame,
                area,
                "no config found, create one?",
                choices,
                *cursor,
                status.as_deref(),
                "↑/↓  enter: select  esc: cancel",
            ),
            Dialog::CreateScopedConfig {
                choices, cursor, ..
            } => render_picker(
                frame,
                area,
                "where should the new config live?",
                choices,
                *cursor,
                None,
                "↑/↓  enter: select  esc: back to picker",
            ),
            Dialog::WizardMenu {
                wizards, cursor, ..
            } => render_wizard_menu(frame, area, wizards, *cursor),
            Dialog::ModelSetupChoice {
                confirmed,
                pending,
                cursor,
                ..
            } => render_model_setup_choice(
                frame,
                area,
                confirmed.as_ref(),
                pending.as_ref(),
                *cursor,
            ),
            Dialog::SetupWizard(wizard) => render_setup_wizard(frame, area, wizard),
            Dialog::FirstRunComplete { summary } => render_first_run_complete(frame, area, summary),
            Dialog::Settings(s) => s.render(frame, area, links),
        }
    }
}

// ── SettingsDialog ───────────────────────────────────────────────────────

fn settings_action_from_button_id(
    id: crate::tui::button::ButtonId,
) -> Option<SettingsPointerAction> {
    match id {
        crate::tui::button::ButtonId::SettingsHeader(action) => {
            Some(SettingsPointerAction::Header(action))
        }
        crate::tui::button::ButtonId::Settings(action) => Some(SettingsPointerAction::Page(action)),
        _ => None,
    }
}

fn dispatch_from_settings_action(
    action: SettingsPointerAction,
) -> crate::tui::button::ButtonDispatch {
    match action {
        SettingsPointerAction::Header(action) => {
            crate::tui::button::ButtonDispatch::SettingsHeader(action)
        }
        SettingsPointerAction::Page(action) => crate::tui::button::ButtonDispatch::Settings(action),
    }
}

impl SettingsDialog {
    fn authority_operation_pending(&self) -> bool {
        self.cx.authority_operation_pending()
            || self
                .page
                .downcast_ref::<AgentsPage>()
                .is_some_and(AgentsPage::has_unsettled_external_edit)
            || self
                .page
                .downcast_ref::<ProvidersPage>()
                .is_some_and(ProvidersPage::has_unsettled_authority_operation)
    }

    fn apply_daemon_completion(&mut self, completion: SettingsDaemonEffectCompletion) {
        let completion = match self.cx.apply_general_completion(completion) {
            Ok(()) => {
                if let Some((navigation, config)) = self.cx.completed_provider_navigation.take() {
                    let requested_provider_id = match &navigation {
                        ProviderNavigation::Edit { provider_id, .. }
                        | ProviderNavigation::Models { provider_id } => provider_id.clone(),
                    };
                    if let Some(entry) = config.providers.get(&requested_provider_id).cloned() {
                        let parent = EditState::new(requested_provider_id.clone(), entry.clone());
                        self.page = match navigation {
                            ProviderNavigation::Edit {
                                provider_id,
                                oauth_expired,
                            } => {
                                let oauth_provider = oauth_expired
                                    .then(|| match entry.effective_template(&provider_id) {
                                        Some(
                                            cockpit_core::auth::codex_oauth::CREDENTIAL_KEY
                                            | "codex",
                                        ) => Some(OAuthProvider::Codex),
                                        Some(
                                            cockpit_core::auth::xai_oauth::CREDENTIAL_KEY | "grok",
                                        ) => Some(OAuthProvider::Grok),
                                        _ => None,
                                    })
                                    .flatten();
                                if let Some(provider) = oauth_provider {
                                    providers_page(ProvidersPage::OAuthSetup {
                                        state: Box::new(providers::OAuthFlowState::new(provider)),
                                        parent: Box::new(parent),
                                    })
                                } else {
                                    providers_page(ProvidersPage::Edit(parent))
                                }
                            }
                            ProviderNavigation::Models { provider_id } => {
                                providers_page(ProvidersPage::Models {
                                    editor: Box::new(ModelEditor::new(
                                        entry.effective_template(&provider_id).map(str::to_owned),
                                        entry.models.clone(),
                                    )),
                                    parent: Box::new(parent),
                                })
                            }
                        };
                    } else {
                        self.page = providers_page(ProvidersPage::List {
                            cursor: 0,
                            status: Some(format!(
                                "provider `{requested_provider_id}` is no longer configured"
                            )),
                            delete_pending: false,
                        });
                    }
                }
                if let Some(prompt) = self.cx.pending_shadow_prompt.take()
                    && let Some(page) = self.page.downcast_mut::<CategoryPage>()
                {
                    page.status = Some(format!(
                        "saved; project config overrides {} here. Remove that project value? y/n",
                        prompt.setting.descriptor().label
                    ));
                    page.shadowed_global = Some(prompt);
                }
                if let Some(prompt) = self.cx.completed_shadow_removal.take()
                    && let Some(page) = self.page.downcast_mut::<CategoryPage>()
                {
                    page.status = Some(format!(
                        "saved; removed project override for {}",
                        prompt.setting.descriptor().label
                    ));
                }
                if let Some(McpPage::List(state)) = self.page.downcast_mut::<McpPage>() {
                    self.cx.adopt_pending_mcp_oauth(state);
                }
                if let Some((provider_id, result)) = self.cx.completed_web_credential.take()
                    && let Some(page) = self.page.downcast_mut::<ToolsPage>()
                    && matches!(
                        page.editing,
                        Some(tools_page::ToolField::WebKey(provider))
                            if tools_page::web_key_provider_id(provider) == provider_id
                    )
                {
                    match result {
                        Ok(()) => {
                            page.status = Some(format!("{provider_id} key saved to credentials."));
                            page.buf = TextField::default();
                            page.editing = None;
                        }
                        Err(error) => {
                            page.status = Some(format!("Save failed: {error}"));
                        }
                    }
                }
                if let Some((name, edited, result)) = self.cx.completed_mcp_navigation.take() {
                    match result {
                        Ok(()) => {
                            self.page = mcp_page(McpPage::List(mcp_page::ListState {
                                cursor: 0,
                                status: Some(if edited {
                                    format!("saved `{name}`")
                                } else {
                                    format!("added `{name}`")
                                }),
                                delete_pending: false,
                                oauth: None,
                            }));
                        }
                        Err(error) => {
                            if let Some(McpPage::Add(state)) = self.page.downcast_mut::<McpPage>() {
                                state.status = Some(format!("save failed: {error}"));
                            }
                        }
                    }
                }
                if let Some(completion) = self.cx.completed_provider_auth.take()
                    && let Some(page) = self.page.downcast_mut::<ProvidersPage>()
                {
                    match (completion, page) {
                        (
                            CompletedProviderAuthMutation::Logout {
                                provider_id,
                                result,
                            },
                            ProvidersPage::Edit(state),
                        ) => {
                            state.status = Some(match result {
                                Ok(()) => format!("signed out of {provider_id}"),
                                Err(error) => format!("sign out failed: {error}"),
                            });
                        }
                        (
                            CompletedProviderAuthMutation::Copilot {
                                provider_id,
                                result,
                            },
                            ProvidersPage::CopilotSetup { state, .. },
                        ) => state.apply_daemon_result(provider_id, result),
                        _ => {}
                    }
                }
                if let Some(completion) = self.cx.completed_provider_add.take()
                    && let Some(ProvidersPage::Add(state)) =
                        self.page.downcast_mut::<ProvidersPage>()
                {
                    self.cx.adopt_provider_add_completion(state, completion);
                }
                if let Some(result) = self.cx.completed_provider_mutation.take()
                    && self.cx.completed_provider_add.is_none()
                    && let Some(page) = self.page.downcast_mut::<ProvidersPage>()
                {
                    let status = match result {
                        Ok(()) => "provider settings committed".to_string(),
                        Err(error) => format!("provider save failed: {error}"),
                    };
                    match page {
                        ProvidersPage::List { status: slot, .. } => *slot = Some(status),
                        ProvidersPage::Edit(state) => state.status = Some(status),
                        _ => {}
                    }
                }
                if let Some(navigation) = self.cx.completed_provider_mutation_navigation.take() {
                    self.page = match navigation {
                        ProviderMutationNavigation::List { status } => {
                            providers_page(ProvidersPage::List {
                                cursor: initial_list_cursor(&self.cx.config),
                                status: Some(status),
                                delete_pending: false,
                            })
                        }
                        ProviderMutationNavigation::Edit {
                            provider_id,
                            status,
                        } => {
                            let entry = self
                                .cx
                                .config
                                .providers
                                .get(&provider_id)
                                .cloned()
                                .unwrap_or_default();
                            let mut edit = EditState::new(provider_id, entry);
                            edit.status = Some(status);
                            providers_page(ProvidersPage::Edit(edit))
                        }
                    };
                }
                return;
            }
            Err(completion) => completion,
        };
        if let Some(page) = self.page.downcast_mut::<AgentsPage>() {
            page.apply_daemon_completion(&mut self.cx, completion);
        }
    }

    fn apply_blocking_completion(&mut self, completion: SettingsBlockingEffectCompletion) {
        let category_operation = matches!(
            self.cx.pending_settings.get(&completion.operation_id),
            Some(
                PendingSettingsOperation::CategoryExternalPrepare { .. }
                    | PendingSettingsOperation::CategoryExternalRead { .. }
            )
        );
        if category_operation && let Some(page) = self.page.downcast_mut::<CategoryPage>() {
            self.cx.apply_category_blocking_completion(page, completion);
            return;
        }
        if let Some(page) = self.page.downcast_mut::<AgentsPage>() {
            page.apply_blocking_completion(&mut self.cx, completion);
        }
    }
    #[cfg(test)]
    pub(crate) fn pointer_test_target_rects(&self) -> Vec<Rect> {
        self.cx
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .map(|target| target.rect)
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn pointer_test_hover_is_none(&self) -> bool {
        self.cx.pointer_surface.hover.borrow().is_none()
    }

    #[cfg(test)]
    pub(crate) fn pointer_test_button_targets(&self) -> Vec<crate::tui::button::RegisteredButton> {
        self.cx.pointer_surface.buttons.borrow().targets().to_vec()
    }

    #[cfg(test)]
    pub(crate) fn pointer_test_row_targets(&self) -> Vec<crate::tui::button::RowTarget> {
        self.cx.pointer_surface.rows.borrow().targets().to_vec()
    }

    #[cfg(test)]
    pub(crate) fn test_enter_root_node(&mut self, title: &str) {
        tests::enter_root_node(self, title);
    }

    #[cfg(test)]
    fn set_test_page(&mut self, page: Page) {
        self.page = boxed_page(page);
    }

    #[cfg(test)]
    pub(crate) fn test_page(&self) -> TestPageRef<'_> {
        if let Some(p) = self.page.downcast_ref::<RootPage>() {
            return TestPageRef::Root { cursor: p.cursor };
        }
        if let Some(p) = self.page.downcast_ref::<DefaultModelPage>() {
            return TestPageRef::DefaultModel(p);
        }
        if let Some(p) = self.page.downcast_ref::<AgentsPage>() {
            return TestPageRef::Agents(p);
        }
        if let Some(p) = self.page.downcast_ref::<ToolsPage>() {
            return TestPageRef::Tools(p);
        }
        if let Some(p) = self.page.downcast_ref::<HarnessesPage>() {
            return TestPageRef::Harnesses(p);
        }
        if let Some(p) = self.page.downcast_ref::<ProvidersPage>() {
            return TestPageRef::Providers(p);
        }
        if let Some(p) = self.page.downcast_ref::<CategoryPage>() {
            return TestPageRef::Category(p);
        }
        if let Some(p) = self.page.downcast_ref::<image_spend::ImageSpendPage>() {
            return TestPageRef::ImageSpend(p);
        }
        if let Some(p) = self.page.downcast_ref::<InstructionsPage>() {
            return TestPageRef::Instructions(p);
        }
        if let Some(p) = self.page.downcast_ref::<RedactPatternsPage>() {
            return TestPageRef::RedactPatterns(p);
        }
        if let Some(p) = self.page.downcast_ref::<StringListPage>() {
            return TestPageRef::StringList(p);
        }
        if let Some(p) = self.page.downcast_ref::<SkillsPage>() {
            return TestPageRef::Skills(p);
        }
        if let Some(p) = self.page.downcast_ref::<McpPage>() {
            return TestPageRef::Mcp(p);
        }
        if let Some(p) = self.page.downcast_ref::<LspPage>() {
            return TestPageRef::Lsp(p);
        }
        if let Some(p) = self
            .page
            .downcast_ref::<image_generation::GenerationListPage>()
        {
            return TestPageRef::GenerationList(p);
        }
        if let Some(p) = self
            .page
            .downcast_ref::<image_generation::EndpointEditorPage>()
        {
            return TestPageRef::EndpointEditor(p);
        }
        if let Some(p) = self
            .page
            .downcast_ref::<image_generation::TargetEditorPage>()
        {
            return TestPageRef::TargetEditor(p);
        }
        if let Some(p) = self
            .page
            .downcast_ref::<image_generation::WorkflowEditorPage>()
        {
            return TestPageRef::WorkflowEditor(p);
        }
        if let Some(p) = self
            .page
            .downcast_ref::<image_generation::BudgetEditorPage>()
        {
            return TestPageRef::BudgetEditor(p);
        }
        if let Some(p) = self.page.downcast_ref::<image_generation::GrantListPage>() {
            return TestPageRef::GrantList(p);
        }
        if let Some(p) = self.page.downcast_ref::<image_generation::JobListPage>() {
            return TestPageRef::JobList(p);
        }
        if let Some(p) = self.page.downcast_ref::<image_generation::JobDetailPage>() {
            return TestPageRef::JobDetail(p);
        }
        if let Some(p) = self
            .page
            .downcast_ref::<image_generation::LateResultActionPage>()
        {
            return TestPageRef::LateResultAction(p);
        }
        unreachable!("unknown settings page")
    }

    #[cfg(test)]
    fn test_page_mut(&mut self) -> TestPageMut<'_> {
        if self.page.as_any().is::<RootPage>() {
            let p = self.page.downcast_mut::<RootPage>().unwrap();
            return TestPageMut::Root {
                cursor: &mut p.cursor,
            };
        }
        if self.page.as_any().is::<AgentsPage>() {
            return TestPageMut::Agents(self.page.downcast_mut::<AgentsPage>().unwrap());
        }
        if self.page.as_any().is::<ToolsPage>() {
            return TestPageMut::Tools(self.page.downcast_mut::<ToolsPage>().unwrap());
        }
        if self.page.as_any().is::<HarnessesPage>() {
            return TestPageMut::Harnesses(self.page.downcast_mut::<HarnessesPage>().unwrap());
        }
        if self.page.as_any().is::<ProvidersPage>() {
            return TestPageMut::Providers(self.page.downcast_mut::<ProvidersPage>().unwrap());
        }
        if self.page.as_any().is::<CategoryPage>() {
            return TestPageMut::Category(self.page.downcast_mut::<CategoryPage>().unwrap());
        }
        if self.page.as_any().is::<image_spend::ImageSpendPage>() {
            return TestPageMut::ImageSpend(
                self.page
                    .downcast_mut::<image_spend::ImageSpendPage>()
                    .unwrap(),
            );
        }
        if self.page.as_any().is::<InstructionsPage>() {
            return TestPageMut::Instructions(
                self.page.downcast_mut::<InstructionsPage>().unwrap(),
            );
        }
        if self.page.as_any().is::<RedactPatternsPage>() {
            return TestPageMut::RedactPatterns(
                self.page.downcast_mut::<RedactPatternsPage>().unwrap(),
            );
        }
        if self.page.as_any().is::<StringListPage>() {
            return TestPageMut::StringList(self.page.downcast_mut::<StringListPage>().unwrap());
        }
        if self.page.as_any().is::<SkillsPage>() {
            return TestPageMut::Skills(self.page.downcast_mut::<SkillsPage>().unwrap());
        }
        if self.page.as_any().is::<McpPage>() {
            return TestPageMut::Mcp(self.page.downcast_mut::<McpPage>().unwrap());
        }
        if self.page.as_any().is::<LspPage>() {
            return TestPageMut::Lsp(self.page.downcast_mut::<LspPage>().unwrap());
        }
        if self
            .page
            .as_any()
            .is::<image_generation::GenerationListPage>()
        {
            return TestPageMut::GenerationList(
                self.page
                    .downcast_mut::<image_generation::GenerationListPage>()
                    .unwrap(),
            );
        }
        if self
            .page
            .as_any()
            .is::<image_generation::EndpointEditorPage>()
        {
            return TestPageMut::EndpointEditor(
                self.page
                    .downcast_mut::<image_generation::EndpointEditorPage>()
                    .unwrap(),
            );
        }
        if self
            .page
            .as_any()
            .is::<image_generation::TargetEditorPage>()
        {
            return TestPageMut::TargetEditor(
                self.page
                    .downcast_mut::<image_generation::TargetEditorPage>()
                    .unwrap(),
            );
        }
        if self
            .page
            .as_any()
            .is::<image_generation::WorkflowEditorPage>()
        {
            return TestPageMut::WorkflowEditor(
                self.page
                    .downcast_mut::<image_generation::WorkflowEditorPage>()
                    .unwrap(),
            );
        }
        if self
            .page
            .as_any()
            .is::<image_generation::BudgetEditorPage>()
        {
            return TestPageMut::BudgetEditor(
                self.page
                    .downcast_mut::<image_generation::BudgetEditorPage>()
                    .unwrap(),
            );
        }
        if self.page.as_any().is::<image_generation::GrantListPage>() {
            return TestPageMut::GrantList(
                self.page
                    .downcast_mut::<image_generation::GrantListPage>()
                    .unwrap(),
            );
        }
        if self.page.as_any().is::<image_generation::JobListPage>() {
            return TestPageMut::JobList(
                self.page
                    .downcast_mut::<image_generation::JobListPage>()
                    .unwrap(),
            );
        }
        if self.page.as_any().is::<image_generation::JobDetailPage>() {
            return TestPageMut::JobDetail(
                self.page
                    .downcast_mut::<image_generation::JobDetailPage>()
                    .unwrap(),
            );
        }
        if self
            .page
            .as_any()
            .is::<image_generation::LateResultActionPage>()
        {
            return TestPageMut::LateResultAction(
                self.page
                    .downcast_mut::<image_generation::LateResultActionPage>()
                    .unwrap(),
            );
        }
        unreachable!("unknown settings page")
    }
}

impl SettingsDialog {
    pub fn open(config_path: PathBuf) -> Self {
        let mut settings = Self::open_with_config(config_path, ProvidersConfig::default());
        settings.cx.queue_provider_catalog(None);
        settings.cx.queue_extended_load();
        settings
    }

    /// Construct settings from an already-authoritative provider snapshot.
    /// Direct provider entry points use this so legacy literal headers are
    /// never loaded into TUI state before the daemon redacts/migrates them.
    fn open_with_config(config_path: PathBuf, config: ProvidersConfig) -> Self {
        // The cockpit-only keys live in the same `config.json` as the
        // layer-wide provider metadata (GOALS §2a).
        let extended_path = config_path.clone();
        let extended = ExtendedConfig::default();
        let extended_base = serde_json::to_value(&extended).unwrap_or_default();
        let extended_revision = None;
        let extended_warnings = vec!["loading daemon-owned settings…".into()];
        // Fresh install (no config at this location yet): seed the
        // skills scan-dir list with the defaults so they show as ordinary
        // editable rows. Materialization-only — an existing config whose
        // `scan_dirs` is absent/empty stays empty (clean break).
        let mcp_config = cockpit_core::mcp::config::McpConfig::default();
        Self {
            page: root_page(0),
            stack: Vec::new(),
            cx: SettingsCx {
                dialog_id: uuid::Uuid::new_v4(),
                daemon_effects: VecDeque::new(),
                blocking_effects: VecDeque::new(),
                pending_settings: BTreeMap::new(),
                pending_mcp_oauth: None,
                pending_mcp_navigation: None,
                completed_mcp_navigation: None,
                completed_web_credential: None,
                completed_provider_auth: None,
                pending_provider_add: None,
                completed_provider_add: None,
                completed_provider_mutation: None,
                pending_provider_mutation_navigation: None,
                completed_provider_mutation_navigation: None,
                completed_shadow_removal: None,
                pending_shadow_prompt: None,
                completed_provider_navigation: None,
                after_extended_commit: Vec::new(),
                config_path,
                extended_path,
                scroll_states: SettingsScrollStates::default(),
                pointer_surface: SettingsPointerSurface::default(),
                original_config: config.clone(),
                config,
                provider_edit_authority: None,
                latest_provider_snapshot_session_id: None,
                extended,
                extended_base,
                extended_revision,
                extended_warnings,
                mcp_config,
                picker_cwd: None,
                active_project_root: None,
                sandbox_enabled: true,
                back_to_picker: false,
                command_installed: |cmd| {
                    cockpit_core::harness::preflight::which_on_path(cmd).is_some()
                },
                env_lookup: |name| std::env::var(name).ok().filter(|v| !v.trim().is_empty()),
                credential_store_path: None,
                mcp_cache_dir: None,
                last_secret_notice: None,
                secret_inventory_cache: Arc::new(Mutex::new(BTreeMap::new())),
                secret_inventory_pending: Arc::new(Mutex::new(BTreeSet::new())),
                pending_daemon_request: None,
                pending_oauth_action: None,
                pending_default_model_picker: false,
                pending_default_model_update_id: None,
                host_capabilities: crate::tui::capability_gate::empty_capability_snapshot(),
                capability_refresh_queue: Vec::new(),
                capability_refresh_calls: 0,
                capability_refresh_in_flight: false,
                daemon_attached: false,
                pending_refresh_host_capabilities: false,
                secret_store_migrate: None,
                secret_store_migrate_calls: 0,
                dependency_refresh_calls: 0,
                dependency_refresh: None,
            },
        }
    }

    fn open_for_scaffold(directory: PathBuf, cwd: PathBuf) -> Self {
        let config_path = directory.join(CONFIG_FILE);
        let mut settings = Self::open_with_config(config_path.clone(), ProvidersConfig::default());
        settings.picker_cwd = Some(cwd.clone());
        settings.active_project_root = Some(cwd.clone());
        settings.cx.queue_provider_catalog(None);
        settings.cx.queue_typed_document_edit(
            config_path,
            cwd,
            serde_json::json!({ "agents": {}, "tools": {} }),
            TypedDocumentEditAction::Scaffold,
        );
        settings.cx.extended_warnings = vec!["creating settings layer…".into()];
        settings
    }

    /// Same as [`Self::open`] but records the cwd of the picker that
    /// opened this dialog so Root's back keybind can reopen it.
    pub fn open_from_picker(config_path: PathBuf, cwd: PathBuf) -> Self {
        let mut s = Self::open_with_config(config_path, ProvidersConfig::default());
        s.picker_cwd = Some(cwd.clone());
        s.active_project_root = Some(cwd);
        s.cx.queue_provider_catalog(None);
        s.cx.queue_extended_load();
        // `open_with_config` already loaded the exact selected layer together
        // with its opaque revision. Do not replace it with the layered
        // effective projection here: doing so would materialize inherited
        // values into this layer and detach `extended_base` from the revision.
        s
    }

    /// Reload the authoritative extended-config snapshot after saving.
    fn reload_extended(&mut self) {
        self.cx.queue_extended_load();
    }

    /// Persist the cached extended-config through daemon authority.
    pub(super) fn save_extended(&mut self) -> Result<SettingsSaveOutcome, String> {
        self.cx.queue_extended_save()
    }

    #[cfg(test)]
    pub(super) fn category_value_for_test(&self, id: category::SettingId) -> String {
        self.category_value(id)
    }

    #[cfg(test)]
    pub(super) fn enter_dependencies_for_test(&mut self) {
        let cwd = self
            .picker_cwd
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        self.page = dependencies_page::page_after_first_paint(cwd, self.sandbox_enabled);
    }

    fn enter_providers(&mut self) {
        self.page = providers_page(ProvidersPage::List {
            cursor: providers::initial_list_cursor(&self.config),
            status: None,
            delete_pending: false,
        });
    }

    /// Enter a reorganized category page, reloading the cached
    /// extended-config first so the rows reflect on-disk state.
    fn enter_category(&mut self, category: Category) {
        self.reload_extended();
        self.page = category_page(CategoryPage::new(category));
    }

    /// Navigate to the active model's model-settings sub-dialog
    /// (implementation note). Falls back to the providers
    /// list with an inline status when no model is active or the active
    /// (provider, model) can't be found.
    fn enter_model_settings(&mut self) {
        self.page = providers_page(providers::active_model_settings_page(&self.config));
    }

    fn save_config(&mut self) -> Result<(), String> {
        self.cx.save_config()
    }

    fn delete_provider_and_stored_secrets(
        &mut self,
        provider_id: &str,
        delete_stored_secrets: bool,
    ) -> Result<usize, String> {
        self.cx
            .delete_provider_and_stored_secrets(provider_id, delete_stored_secrets)
    }

    fn tick(&mut self) {
        if let Some(page) = self.page.downcast_mut::<image_spend::ImageSpendPage>() {
            page.poll();
        }
        if let Some(page) = self
            .page
            .downcast_mut::<dependencies_page::DependenciesPage>()
        {
            page.tick();
        }
        let pending = self
            .page
            .downcast_mut::<ProvidersPage>()
            .and_then(|page| match page {
                ProvidersPage::Add(s) => s.fetch.clone(),
                ProvidersPage::Edit(s) => s.fetch.clone(),
                ProvidersPage::Headers { parent, .. } => parent.fetch.clone(),
                ProvidersPage::Models { parent, .. } => parent.fetch.clone(),
                ProvidersPage::ModelSettings { parent, .. } => parent.fetch.clone(),
                ProvidersPage::ProviderSettings { parent, .. } => parent.fetch.clone(),
                _ => None,
            });
        if let Some(handle) = pending
            && let Some(result) = handle.take()
        {
            self.apply_fetch_result(&handle.provider_id, result);
        }

        self.drain_fetch_all();
        self.drain_deep_fetch();
        self.refresh_oauth_inventory_state();
        if let Some(page) = self.page.downcast_mut::<ProvidersPage>() {
            match page {
                ProvidersPage::OAuthSetup { state, .. } if state.pending || state.polling => {
                    state.spinner_tick = state.spinner_tick.wrapping_add(1);
                }
                ProvidersPage::DeepFetch { state, .. } => state.advance_spinner(),
                ProvidersPage::Add(state)
                    if state
                        .oauth_auth
                        .as_ref()
                        .is_some_and(|oauth| oauth.pending || oauth.polling) =>
                {
                    let oauth = state.oauth_auth.as_mut().expect("guarded OAuth state");
                    oauth.spinner_tick = oauth.spinner_tick.wrapping_add(1);
                }
                _ => {}
            }
        }
    }

    fn apply_oauth_begin(
        &mut self,
        provider: OAuthProvider,
        client_flow_id: pointer_actions::OAuthFlowId,
        operation_id: shell::PointerOperationId,
        result: OAuthBeginResult,
    ) {
        let Some(state) = self.oauth_flow_state_mut(provider) else {
            return;
        };
        if !state.accepts_result(client_flow_id, operation_id) {
            return;
        }
        self.pending_oauth_action = state.apply_begin_deferred(result);
    }

    fn apply_oauth_complete(
        &mut self,
        provider: OAuthProvider,
        client_flow_id: pointer_actions::OAuthFlowId,
        operation_id: shell::PointerOperationId,
        result: Result<bool, String>,
    ) {
        let Some(state) = self.oauth_flow_state_mut(provider) else {
            return;
        };
        if !state.accepts_result(client_flow_id, operation_id) {
            return;
        }
        if matches!(result, Ok(true)) {
            self.invalidate_secret_inventory_entry(oauth_credential_inventory_name(provider), None);
        }
        let Some(state) = self.oauth_flow_state_mut(provider) else {
            return;
        };
        state.apply_complete(result);
    }

    fn apply_oauth_present(
        &mut self,
        provider: OAuthProvider,
        client_flow_id: pointer_actions::OAuthFlowId,
        operation_id: shell::PointerOperationId,
        result: Result<providers::OAuthPresentationResult, String>,
    ) {
        let Some(state) = self.oauth_flow_state_mut(provider) else {
            return;
        };
        if !state.accepts_result(client_flow_id, operation_id) {
            return;
        }
        self.pending_oauth_action = state.apply_present(result);
    }

    fn apply_oauth_cancel(
        &mut self,
        provider: OAuthProvider,
        client_flow_id: pointer_actions::OAuthFlowId,
        operation_id: shell::PointerOperationId,
        result: Result<(), String>,
    ) {
        let Some(state) = self.oauth_flow_state_mut(provider) else {
            return;
        };
        if state.accepts_result(client_flow_id, operation_id) {
            state.apply_cancel(result);
        }
    }

    fn apply_oauth_settlement_unknown(
        &mut self,
        provider: OAuthProvider,
        client_flow_id: pointer_actions::OAuthFlowId,
        operation_id: shell::PointerOperationId,
        error: String,
    ) {
        let Some(state) = self.oauth_flow_state_mut(provider) else {
            return;
        };
        if state.accepts_result(client_flow_id, operation_id) {
            state.apply_settlement_unknown(error);
        }
    }

    fn apply_oauth_acknowledgement_correlated(
        &mut self,
        provider: OAuthProvider,
        client_flow_id: pointer_actions::OAuthFlowId,
        operation_id: shell::PointerOperationId,
        result: Result<(), String>,
    ) {
        let Some(state) = self.oauth_flow_state_mut(provider) else {
            return;
        };
        if !state.accepts_result(client_flow_id, operation_id) {
            return;
        }
        if result.is_ok() {
            self.invalidate_secret_inventory_entry(
                &oauth_acknowledgement_inventory_name(provider),
                None,
            );
        }
        if let Some(state) = self.oauth_flow_state_mut(provider) {
            state.apply_acknowledgement(result);
        }
    }

    #[cfg(test)]
    fn apply_oauth_acknowledgement(&mut self, result: Result<(), String>) {
        if let Some(state) = self.oauth_flow_state_mut_for_any_provider() {
            state.apply_acknowledgement(result);
        }
    }

    fn refresh_oauth_inventory_state(&mut self) {
        let Some(provider) = self.oauth_flow_provider() else {
            return;
        };
        let logged_in =
            self.cached_secret_inventory_contains(oauth_credential_inventory_name(provider), None);
        let acknowledged = self.cached_secret_inventory_contains(
            &oauth_acknowledgement_inventory_name(provider),
            None,
        );
        if let Some(state) = self.oauth_flow_state_mut(provider) {
            state.refresh_inventory_state(logged_in, acknowledged);
        }
    }

    fn oauth_flow_provider(&self) -> Option<OAuthProvider> {
        let page = self.page.downcast_ref::<ProvidersPage>()?;
        match page {
            ProvidersPage::OAuthSetup { state, .. } => Some(state.provider),
            ProvidersPage::Add(add) => add.oauth_auth.as_ref().map(|state| state.provider),
            _ => None,
        }
    }

    fn oauth_flow_state_mut_for_any_provider(&mut self) -> Option<&mut providers::OAuthFlowState> {
        let page = self.page.downcast_mut::<ProvidersPage>()?;
        match page {
            ProvidersPage::OAuthSetup { state, .. } => Some(state),
            ProvidersPage::Add(add) => add.oauth_auth.as_deref_mut(),
            _ => None,
        }
    }

    fn oauth_flow_state_mut(
        &mut self,
        provider: OAuthProvider,
    ) -> Option<&mut providers::OAuthFlowState> {
        let page = self.page.downcast_mut::<ProvidersPage>()?;
        match page {
            ProvidersPage::OAuthSetup { state, .. } if state.provider == provider => Some(state),
            ProvidersPage::Add(add)
                if add
                    .oauth_auth
                    .as_ref()
                    .is_some_and(|state| state.provider == provider) =>
            {
                add.oauth_auth.as_deref_mut()
            }
            _ => None,
        }
    }

    /// True while a header or model add/edit popup or its browsing list
    /// is on screen — those editors own `Tab`/`Shift+Tab` themselves (the
    /// popup switches between fields; the browse list treats Tab as ↓), so
    /// the field-nav rewrite in [`Self::handle_key`] must leave them alone.
    fn in_header_editor(&self) -> bool {
        let Some(page) = self.page.downcast_ref::<ProvidersPage>() else {
            return false;
        };
        match page {
            ProvidersPage::Headers { .. } | ProvidersPage::Models { .. } => true,
            ProvidersPage::Add(s) => s.is_step("headers"),
            _ => false,
        }
    }

    /// True while a category page is inline-editing the packages-dir field —
    /// there Tab accepts a directory suggestion, so the field-nav Tab→Down
    /// rewrite in [`Self::handle_key`] must leave Tab alone.
    fn in_pkg_dir_autosuggest(&self) -> bool {
        self.page
            .downcast_ref::<CategoryPage>()
            .is_some_and(|p| p.is_path_editing())
    }

    /// Insert pasted text into the page's focused text field, mirroring the
    /// focus logic of each page's key handler so the paste lands in the same
    /// buffer a typed char would. Pages with no open field (or no field at
    /// all) drop the paste.
    fn paste(&mut self, text: &str) {
        let cwd = self.agents_cwd();
        if let Some(p) = self.page.downcast_mut::<ProvidersPage>() {
            if p.paste_oauth(text) {
                return;
            }
            if let Some(field) = p.active_text_field() {
                field.paste(text);
            }
        } else if let Some(p) = self.page.downcast_mut::<AgentsPage>() {
            if let Some(editor) = p.editing.as_mut() {
                editor.paste(text);
            }
        } else if let Some(p) = self.page.downcast_mut::<ToolsPage>() {
            if p.editing.is_some() {
                p.buf.paste(text);
            }
        } else if let Some(p) = self.page.downcast_mut::<HarnessesPage>() {
            match p {
                harnesses_page::HarnessesPage::List(s) => {
                    if let Some(buf) = s.adding.as_mut() {
                        buf.paste(text);
                    }
                }
                harnesses_page::HarnessesPage::Edit(s) => {
                    if let Some(buf) = s.editing.as_mut() {
                        buf.paste(text);
                    }
                }
            }
        } else if let Some(p) = self.page.downcast_mut::<CategoryPage>() {
            if let Some(editor) = p.path_editor.as_mut() {
                editor.paste(text, &cwd);
            } else if let Some(editor) = p.text_editor.as_mut() {
                editor.paste(text);
            } else if let Some(picker) = p.utility_picker.as_mut() {
                if let Some(field) = picker.active_text_field() {
                    field.paste(text);
                }
            } else if p.editing.is_some() {
                p.buf.paste(text);
            }
        } else if let Some(p) = self.page.downcast_mut::<InstructionsPage>() {
            if let Some(g) = p.grabbed.as_mut() {
                g.buf.paste(text);
            }
        } else if let Some(p) = self.page.downcast_mut::<RedactPatternsPage>() {
            if let Some(g) = p.grabbed.as_mut() {
                g.buf.paste(text);
            }
        } else if let Some(p) = self.page.downcast_mut::<StringListPage>() {
            if let Some(g) = p.grabbed.as_mut() {
                g.buf.paste(text);
            }
        } else if let Some(p) = self.page.downcast_mut::<SkillsPage>() {
            if let Some(g) = p.grabbed.as_mut() {
                g.buf.paste(text);
            }
        } else if let Some(p) = self.page.downcast_mut::<McpPage>() {
            if let mcp_page::McpPage::Add(s) = p {
                mcp_page::paste_into_add_state(s, text);
            }
        } else if let Some(p) = self.page.downcast_mut::<LspPage>()
            && p.editing.is_some()
        {
            p.buf.paste(text);
        }
    }

    fn apply_nav(&mut self, nav: Nav) -> bool {
        match nav {
            Nav::Stay => false,
            Nav::Replace(new) => {
                self.page = new;
                false
            }
            Nav::Push(new) => {
                let current = std::mem::replace(&mut self.page, new);
                self.stack.push(current);
                false
            }
            Nav::Back => {
                self.page = self.stack.pop().unwrap_or_else(|| root_page(0));
                false
            }
            Nav::Close => true,
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        self.cx.retry_unknown_settlement();
        if self.authority_operation_pending() {
            // OAuth is the sole authority operation with an interactive
            // terminal settlement control. Route only plain Escape to the
            // owning flow reducer so it can mint a correlated cancellation;
            // every other key remains blocked by this outer dialog gate.
            let oauth_cancel = matches!(key.code, KeyCode::Esc)
                && key.modifiers.is_empty()
                && self
                    .page
                    .downcast_ref::<ProvidersPage>()
                    .is_some_and(ProvidersPage::has_unsettled_oauth_operation);
            if oauth_cancel {
                let nav = self.page.handle_key(&mut self.cx, key);
                return self.apply_nav(nav);
            }
            self.cx.extended_warnings = vec![
                "Waiting for the daemon to settle this settings operation; navigation is disabled."
                    .into(),
            ];
            return false;
        }
        // Tab / Shift+Tab move between fields like ↓/↑ across settings
        // screens. Editors that own Tab themselves opt out through page state.
        let key = if self.in_header_editor() || self.in_pkg_dir_autosuggest() {
            key
        } else {
            match key.code {
                KeyCode::Tab => KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
                KeyCode::BackTab => KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
                _ => key,
            }
        };
        let nav = self.page.handle_key(&mut self.cx, key);
        self.apply_nav(nav)
    }

    fn handle_pointer(&mut self, mouse: MouseEvent) -> SettingsPointerOutcome {
        if self.authority_operation_pending() && !matches!(mouse.kind, MouseEventKind::Moved) {
            self.cx.extended_warnings = vec![
                "Waiting for the daemon to settle this settings operation; controls are disabled."
                    .into(),
            ];
            return SettingsPointerOutcome::Consumed;
        }
        let Some(area) = self.pointer_surface.area.get() else {
            return SettingsPointerOutcome::Consumed;
        };
        if mouse.column < area.x
            || mouse.column >= area.right()
            || mouse.row < area.y
            || mouse.row >= area.bottom()
        {
            if matches!(mouse.kind, MouseEventKind::Moved) {
                *self.pointer_surface.hover.borrow_mut() = None;
                self.pointer_surface.header_hover.set(None);
            }
            return SettingsPointerOutcome::Consumed;
        }
        match mouse.kind {
            MouseEventKind::Moved => {
                let button_outcome = self
                    .pointer_surface
                    .buttons
                    .borrow_mut()
                    .handle_mouse(mouse);
                let action = match button_outcome {
                    Some(_) => self
                        .pointer_surface
                        .buttons
                        .borrow()
                        .hover()
                        .cloned()
                        .and_then(settings_action_from_button_id),
                    None => self
                        .pointer_surface
                        .hit(mouse.column, mouse.row)
                        .filter(|target| target.enabled)
                        .map(|target| target.action),
                };
                *self.pointer_surface.hover.borrow_mut() = match &action {
                    Some(SettingsPointerAction::Page(action)) => Some(action.clone()),
                    _ => None,
                };
                self.pointer_surface.header_hover.set(match action {
                    Some(SettingsPointerAction::Header(action)) => Some(action),
                    _ => None,
                });
            }
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
                *self.pointer_surface.hover.borrow_mut() = None;
                self.pointer_surface.header_hover.set(None);
                self.pointer_surface
                    .buttons
                    .borrow_mut()
                    .clear_hover_and_pressed();
                if let Some(region) = self
                    .pointer_surface
                    .scroll_region_at(mouse.column, mouse.row)
                {
                    let delta = if matches!(mouse.kind, MouseEventKind::ScrollUp) {
                        -3
                    } else {
                        3
                    };
                    let nav = self.page.handle_pointer_scroll(&mut self.cx, region, delta);
                    let _ = self.apply_nav(nav);
                }
            }
            MouseEventKind::Down(MouseButton::Left) | MouseEventKind::Up(MouseButton::Left) => {
                let button_outcome = self
                    .pointer_surface
                    .buttons
                    .borrow_mut()
                    .handle_mouse(mouse);
                if let Some(outcome) = button_outcome {
                    match outcome {
                        crate::tui::button::ButtonPointerOutcome::Activated(dispatch) => {
                            *self.pointer_surface.pressed.borrow_mut() = None;
                            return self.dispatch_button(dispatch, mouse.column, mouse.row);
                        }
                        crate::tui::button::ButtonPointerOutcome::Pressed(id) => {
                            if let Some(action) = settings_action_from_button_id(id) {
                                *self.pointer_surface.pressed.borrow_mut() = Some(action);
                            }
                            return SettingsPointerOutcome::Consumed;
                        }
                        crate::tui::button::ButtonPointerOutcome::Cancelled
                        | crate::tui::button::ButtonPointerOutcome::Consumed
                        | crate::tui::button::ButtonPointerOutcome::HoverChanged => {}
                    }
                }
                if matches!(mouse.kind, MouseEventKind::Up(MouseButton::Left)) {
                    let pressed = self.pointer_surface.pressed.borrow_mut().take();
                    if let Some(action) = pressed {
                        let is_button = matches!(action, SettingsPointerAction::Header(_))
                            || matches!(&action, SettingsPointerAction::Page(page) if page.is_button());
                        let still_over = self
                            .pointer_surface
                            .hit(mouse.column, mouse.row)
                            .is_some_and(|target| target.enabled && target.action == action);
                        if is_button && still_over {
                            return self.dispatch_button(
                                dispatch_from_settings_action(action),
                                mouse.column,
                                mouse.row,
                            );
                        }
                    }
                    return SettingsPointerOutcome::Consumed;
                }
                let Some(target) = self.pointer_surface.hit(mouse.column, mouse.row) else {
                    return SettingsPointerOutcome::Consumed;
                };
                if !target.enabled {
                    return SettingsPointerOutcome::Consumed;
                }
                let is_button_target = matches!(target.action, SettingsPointerAction::Header(_))
                    || matches!(&target.action, SettingsPointerAction::Page(action) if action.is_button());
                if is_button_target {
                    *self.pointer_surface.pressed.borrow_mut() = Some(target.action);
                    return SettingsPointerOutcome::Consumed;
                }
                if self
                    .pointer_surface
                    .pressed
                    .borrow_mut()
                    .replace(target.action.clone())
                    .is_some()
                {
                    return SettingsPointerOutcome::Consumed;
                }
                if let SettingsPointerAction::Page(action) = target.action {
                    let nav = self.page.handle_pointer_control_at(
                        &mut self.cx,
                        action.clone(),
                        mouse.column,
                        mouse.row,
                    );
                    let close = self.apply_nav(nav);
                    #[cfg(test)]
                    pointer_acceptance_tests::record_dispatched_action(&action);
                    if close {
                        return SettingsPointerOutcome::Close;
                    }
                }
            }
            _ => {}
        }
        SettingsPointerOutcome::Consumed
    }

    fn dispatch_button(
        &mut self,
        dispatch: crate::tui::button::ButtonDispatch,
        column: u16,
        row: u16,
    ) -> SettingsPointerOutcome {
        if self.authority_operation_pending() {
            self.cx.extended_warnings = vec![
                "Waiting for the daemon to settle this settings operation; controls are disabled."
                    .into(),
            ];
            return SettingsPointerOutcome::Consumed;
        }
        match dispatch {
            crate::tui::button::ButtonDispatch::SettingsHeader(SettingsHeaderAction::Close) => {
                SettingsPointerOutcome::Close
            }
            crate::tui::button::ButtonDispatch::SettingsHeader(
                SettingsHeaderAction::BackToConfigPicker,
            ) => {
                self.back_to_picker = true;
                SettingsPointerOutcome::Close
            }
            crate::tui::button::ButtonDispatch::SettingsHeader(SettingsHeaderAction::Back) => {
                let nav = match self.page.resolve_header_back() {
                    SettingsLocalBack::LocalBack => self.page.handle_key(
                        &mut self.cx,
                        KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
                    ),
                    SettingsLocalBack::NoLocalBack => Nav::Back,
                };
                let _ = self.apply_nav(nav);
                SettingsPointerOutcome::Consumed
            }
            crate::tui::button::ButtonDispatch::Settings(action) => {
                let nav =
                    self.page
                        .handle_pointer_control_at(&mut self.cx, action.clone(), column, row);
                let close = self.apply_nav(nav);
                #[cfg(test)]
                pointer_acceptance_tests::record_dispatched_action(&action);
                if close {
                    SettingsPointerOutcome::Close
                } else {
                    SettingsPointerOutcome::Consumed
                }
            }
            _ => SettingsPointerOutcome::Consumed,
        }
    }

    fn enter_mcp(&mut self) {
        self.page = mcp_page(mcp_page::McpPage::List(mcp_page::ListState {
            cursor: 0,
            status: None,
            delete_pending: false,
            oauth: None,
        }));
    }

    fn enter_gitignore_allow(&mut self) {
        self.cx.reload_extended();
        self.page = string_list_page(StringListPage::gitignore_allow());
    }

    fn take_pending_category_external_edit(
        &mut self,
    ) -> Option<(shell::PointerOperationId, PathBuf)> {
        #[cfg(test)]
        self.drive_category_blocking_effects_for_test();
        self.page.downcast_mut::<CategoryPage>().and_then(|p| {
            let pending = p.pending_external_edit.as_mut()?;
            let id = pending.operation_id;
            pending.service_path().map(|path| (id, path))
        })
    }

    fn finish_category_external_edit(
        &mut self,
        operation_id: shell::PointerOperationId,
        outcome: pointer_actions::ExternalEditOutcome,
        detail: Option<String>,
    ) {
        let Some(p) = self.page.downcast_mut::<CategoryPage>() else {
            return;
        };
        self.cx
            .finish_category_page_external_edit(p, operation_id, outcome, detail);
        #[cfg(test)]
        self.drive_category_blocking_effects_for_test();
    }

    #[cfg(test)]
    fn drive_category_blocking_effects_for_test(&mut self) {
        while let Some(effect) = self.cx.take_blocking_effect() {
            let completion = SettingsBlockingEffectCompletion {
                dialog_id: effect.dialog_id,
                operation_id: effect.operation_id,
                target: effect.target,
                outcome: execute_settings_blocking_work(effect.work),
            };
            self.apply_blocking_completion(completion);
        }
    }

    fn finish_agent_external_edit(
        &mut self,
        operation_id: shell::PointerOperationId,
        outcome: pointer_actions::ExternalEditOutcome,
        detail: Option<String>,
    ) {
        let Some(page) = self.page.downcast_mut::<AgentsPage>() else {
            return;
        };
        page.finish_external_edit(&mut self.cx, operation_id, outcome, detail);
    }

    // ── Rendering ────────────────────────────────────────────────────────

    pub(crate) fn render(
        &self,
        frame: &mut Frame,
        area: Rect,
        links: &mut crate::tui::links::LinkRegistry,
    ) {
        let surface_token = self.page.pointer_surface_token();
        #[cfg(test)]
        pointer_acceptance_tests::record_rendered_surface(self.page.pointer_surface_kind());
        self.pointer_surface
            .enabled
            .set(self.extended.tui.mouse_capture);
        if !self.extended.tui.mouse_capture {
            *self.pointer_surface.hover.borrow_mut() = None;
        }
        self.pointer_surface.clear_for_page(area, surface_token);
        let title = self.title();
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" Settings — {title} "));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let layout = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(inner);
        let close_rect = self.pointer_surface.paint_header_button(
            frame,
            layout[0].x,
            layout[0].y,
            layout[0].width,
            SettingsHeaderAction::Close,
            "Close settings",
        );
        let root = self.page.as_any().is::<RootPage>();
        if !root || !self.stack.is_empty() {
            let x = close_rect
                .map(|rect| rect.right().saturating_add(2))
                .unwrap_or(layout[0].x.saturating_add(18));
            let max_width = layout[0].right().saturating_sub(x);
            self.pointer_surface.paint_header_button(
                frame,
                x,
                layout[0].y,
                max_width,
                SettingsHeaderAction::Back,
                "Back",
            );
        } else if self.picker_cwd.is_some() {
            let x = close_rect
                .map(|rect| rect.right().saturating_add(2))
                .unwrap_or(layout[0].x.saturating_add(18));
            let max_width = layout[0].right().saturating_sub(x);
            self.pointer_surface.paint_header_button(
                frame,
                x,
                layout[0].y,
                max_width,
                SettingsHeaderAction::BackToConfigPicker,
                "Back to config picker",
            );
        }
        self.page
            .render_with_links(&self.cx, frame, layout[1], links);
        #[cfg(test)]
        for target in self.pointer_surface.targets.borrow().iter() {
            if let SettingsPointerAction::Page(action) = &target.action {
                pointer_acceptance_tests::record_rendered_action(action, target.enabled);
            }
        }
        self.pointer_surface.buttons.borrow_mut().end_frame();
        if let Some(cursor) = shell::park_cursor_from_markers(frame, layout[1]) {
            frame.set_cursor_position(cursor);
        }
        let help = if self.pointer_surface.enabled.get() {
            format!("{}  click: activate  wheel: scroll", self.help_text())
        } else {
            self.help_text().to_string()
        };
        frame.render_widget(help_line(&help), layout[2]);
    }

    fn title(&self) -> String {
        self.page.title(&self.cx)
    }

    fn help_text(&self) -> &'static str {
        self.page.help_text(&self.cx)
    }
}

impl SettingsPage for RootPage {
    fn pointer_surface_kind(&self) -> SettingsPointerSurfaceKind {
        SettingsPointerSurfaceKind::Root
    }

    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        let children = root_nodes();
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return Nav::Close,
            KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace if cx.picker_cwd.is_some() => {
                cx.back_to_picker = true;
                return Nav::Close;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.cursor = crate::tui::nav::wrap_prev(self.cursor, children.len());
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.cursor = crate::tui::nav::wrap_next(self.cursor, children.len());
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                let chosen = children.get(self.cursor).map(|n| n.title).unwrap_or("");
                let next = match chosen {
                    DEFAULT_MODEL_TITLE => Some(default_model_page(DefaultModelPage {
                        status: None,
                        scope_label: cx.effective_default_scope_label(),
                        effective_default: cx.effective_default_model(),
                    })),
                    PROVIDERS_TITLE => Some(providers_page(ProvidersPage::List {
                        cursor: providers::initial_list_cursor(&cx.config),
                        status: None,
                        delete_pending: false,
                    })),
                    "Dependencies" => {
                        Some(dependencies_page::page(cx.agents_cwd(), cx.sandbox_enabled))
                    }
                    "Agents" => {
                        let mut page = AgentsPage::new(&cx.agents_cwd());
                        page.queue_load(cx);
                        Some(agents_page(page))
                    }
                    "Interface" => {
                        cx.reload_extended();
                        Some(category_page(CategoryPage::new(Category::Interface)))
                    }
                    "Behavior" => {
                        cx.reload_extended();
                        Some(category_page(CategoryPage::new(Category::Behavior)))
                    }
                    "Image spend budgets" => Some(image_spend::page(
                        cx.active_project_root
                            .as_ref()
                            .unwrap_or(&cx.extended_path)
                            .to_string_lossy()
                            .into_owned(),
                    )),
                    "Generation" => Some(image_generation::generation_list_page(
                        image_generation::GenerationPrincipal::local_owner(),
                    )),
                    "Privacy & Safety" => {
                        cx.reload_extended();
                        Some(category_page(CategoryPage::new(Category::Privacy)))
                    }
                    "Translation" => {
                        cx.reload_extended();
                        Some(category_page(CategoryPage::new(Category::Translation)))
                    }
                    "Profile" => {
                        cx.reload_extended();
                        Some(category_page(CategoryPage::new(Category::Profile)))
                    }
                    "Tools" => {
                        cx.reload_extended();
                        Some(tools_page(ToolsPage {
                            cursor: 0,
                            editing: None,
                            buf: TextField::default(),
                            status: None,
                            reset: ResetButton::default(),
                            delete_pending: None,
                        }))
                    }
                    "Harnesses" => {
                        cx.reload_extended();
                        let status = cx.extended_warnings.first().cloned();
                        Some(harnesses_page(harnesses_page::HarnessesPage::List(
                            harnesses_page::ListState {
                                cursor: 0,
                                status,
                                delete_pending: false,
                                reset: ResetButton::default(),
                                adding: None,
                            },
                        )))
                    }
                    "Skills" => {
                        cx.reload_extended();
                        Some(skills_page(skills_page::SkillsPage {
                            cursor: 0,
                            grabbed: None,
                            status: None,
                            reset: ResetButton::default(),
                            pointer_delete_pending: None,
                        }))
                    }
                    "MCP" => Some(mcp_page(mcp_page::McpPage::List(mcp_page::ListState {
                        cursor: 0,
                        status: None,
                        delete_pending: false,
                        oauth: None,
                    }))),
                    "LSP" => {
                        cx.reload_extended();
                        Some(lsp_page(LspPage {
                            cursor: 0,
                            editing: None,
                            buf: TextField::default(),
                            status: None,
                            reset: ResetButton::default(),
                        }))
                    }
                    _ => None,
                };
                if let Some(next) = next {
                    return Nav::Push(next);
                }
            }
            _ => {}
        }
        Nav::Stay
    }

    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        render_root(frame, area, self.cursor, cx);
    }

    fn handle_pointer_control(
        &mut self,
        cx: &mut SettingsCx,
        action: pointer_actions::SettingsPointerAction,
    ) -> Nav {
        let pointer_actions::SettingsPointerAction::Root(pointer_actions::RootAction::Open(id)) =
            action
        else {
            return Nav::Stay;
        };
        let Some(index) = root_nodes().iter().position(|node| node.id == id) else {
            return Nav::Stay;
        };
        self.cursor = index;
        self.handle_key(cx, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
    }

    fn handle_pointer_scroll(
        &mut self,
        _cx: &mut SettingsCx,
        region: shell::SettingsScrollRegionId,
        delta: isize,
    ) -> Nav {
        if region != shell::SettingsScrollRegionId("root") {
            return Nav::Stay;
        }
        let last = root_nodes().len().saturating_sub(1);
        self.cursor = self.cursor.saturating_add_signed(delta).min(last);
        Nav::Stay
    }

    fn title(&self, cx: &SettingsCx) -> String {
        cockpit_core::welcome::display_path(&cx.config_path)
    }

    fn help_text(&self, cx: &SettingsCx) -> &'static str {
        if cx.picker_cwd.is_some() {
            "↑/↓/Tab/Shift+Tab  enter: open  h: back to picker  esc/q: close"
        } else {
            "↑/↓/Tab/Shift+Tab  enter: open  esc/q: close"
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "Root"
    }
}

// ── Helpers / freestanding renderers ─────────────────────────────────────

/// The Providers & Provider Models menu node title (also the dispatch key).
pub(super) const PROVIDERS_TITLE: &str = "Providers & Provider Models";
pub(super) const DEFAULT_MODEL_TITLE: &str = "Default model for new sessions";

/// The reorganized top-level menu (implementation note).
/// `Default model for new sessions` leads, then the locked scheme in order;
/// MCP/LSP are kept as extra nodes so integration settings stay reachable
/// from the menu.
fn root_nodes() -> [NavNode; 16] {
    [
        NavNode {
            id: pointer_actions::RootNodeId::DefaultModel,
            title: pointer_actions::RootNodeId::DefaultModel.title(),
            description: "Default model for newly created sessions in the current configuration context. Does not change the model of an already-running session.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Providers,
            title: pointer_actions::RootNodeId::Providers.title(),
            description: "Provider setup and request controls: endpoints, headers, model lists, default model, context/cache, fallback, wire API, and per-provider/per-model inline-<think> extraction overrides.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Dependencies,
            title: "Dependencies",
            description: "Read-only dependency health grouped by safety, selected features, optional integrations, and accelerators.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Agents,
            title: "Agents",
            description: "Manage agent definitions, presets, and per-agent overrides.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Interface,
            title: "Interface",
            description: "Display & input only: vim mode, thinking display for stored reasoning, markdown rendering, mouse, diff style, banner, chrome toggles, emojis, and exit scrollback.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Behavior,
            title: "Behavior",
            description: "Session & agent behavior: default agent, llm mode, approval mode, plan isolation, prediction, shell compression, the utility model, instructions files, and (Advanced) tuning + plan-execution knobs.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::ImageSpend,
            title: "Image spend budgets",
            description: "Explicit request, session, and project image-generation budgets and project window. Suggestions do not authorize dispatch until reviewed and saved.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Generation,
            title: "Generation",
            description: "Image-generation endpoints, targets, workflows, budget, destination grants, and job management. Visibility follows the control-plane authorization matrix.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Privacy,
            title: "Privacy & Safety",
            description: "Redaction (master switch + every source), the prompt-injection guard, and the remote-config opt-in. Advanced holds the redaction internals.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Translation,
            title: "Translation",
            description: "Round-trip utility-model translation: your language and the model's language.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Tools,
            title: "Tools",
            description: "Tool inventory and configuration: web providers, builtin tools, user-defined command tools, and MCP catalogs.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Harnesses,
            title: "Harnesses",
            description: "External coding harnesses (claude, codex, opencode, grok, …) Build/Plan can delegate to via harness_invoke.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Skills,
            title: "Skills",
            description: "Skill scan directories and the auto-! command toggle (Claude vs Codex mode).",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Profile,
            title: "Profile",
            description: "Your display name, shown on the startup banner.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Mcp,
            title: "MCP",
            description: "Model Context Protocol servers: transport, auth, and enabled state.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Lsp,
            title: "LSP",
            description: "Language servers, diagnostics surfacing, semantic navigation, and install behavior.",
        },
    ]
}

struct NavNode {
    id: pointer_actions::RootNodeId,
    title: &'static str,
    description: &'static str,
}

pub(super) trait SaveStatusValue {
    fn status(self) -> String;
}

impl SaveStatusValue for () {
    fn status(self) -> String {
        "saved".into()
    }
}

impl SaveStatusValue for SettingsSaveOutcome {
    fn status(self) -> String {
        match self {
            SettingsSaveOutcome::Saved => "saved".into(),
            SettingsSaveOutcome::Queued => "saving…".into(),
            SettingsSaveOutcome::CommittedRefreshNeeded(warning) => {
                format!("committed; refresh needed: {warning}")
            }
        }
    }
}

pub(super) fn save_status<T: SaveStatusValue>(r: Result<T, String>) -> Option<String> {
    match r {
        Ok(value) => Some(value.status()),
        Err(e) => Some(format!("save failed: {e}")),
    }
}

/// A bottom-of-list `[label]` save-button row. The glyphs are a placeholder;
/// `render_control_lines` paints the exact `[label]` cells through
/// `ButtonRegistry` so the hit rect is the painted label, not the list row.
pub(super) fn save_button_line(label: &str, selected: bool) -> Line<'static> {
    let text = label.trim_start_matches('[').trim_end_matches(']');
    let spec = crate::tui::button::ButtonSpec::new(
        crate::tui::button::ButtonId::Settings(pointer_actions::SettingsPointerAction::Mcp(
            pointer_actions::McpAction::Save,
        )),
        text,
        crate::tui::button::ButtonDispatch::Settings(pointer_actions::SettingsPointerAction::Mcp(
            pointer_actions::McpAction::Save,
        )),
    )
    .focused(selected);
    Line::from(Span::styled(
        crate::tui::button::bracketed_label(text),
        crate::tui::button::button_style(&spec, false, false),
    ))
}

fn render_root(frame: &mut Frame, area: Rect, cursor: usize, cx: &SettingsCx) {
    let children = root_nodes();
    let cursor = cursor.min(children.len().saturating_sub(1));
    let rows = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(1),
        Constraint::Length(3),
    ])
    .split(area);

    let list_lines: Vec<Line<'static>> = children
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let selected = i == cursor;
            Line::from(vec![
                Span::raw(marker(selected)),
                Span::styled(node.title.to_string(), selected_or_field(selected)),
            ])
        })
        .collect();
    let controls = children
        .iter()
        .map(|node| {
            Some((
                pointer_actions::SettingsPointerAction::Root(pointer_actions::RootAction::Open(
                    node.id,
                )),
                true,
                None,
            ))
        })
        .collect();
    cx.scroll_states.render_control_lines(
        frame,
        rows[0],
        "root",
        (list_lines, Some(cursor)),
        controls,
        (&cx.pointer_surface, shell::SettingsScrollRegionId("root")).into(),
    );

    let desc = children[cursor].description;
    frame.render_widget(
        Paragraph::new(desc.to_string())
            .wrap(Wrap { trim: false })
            .style(muted_style()),
        rows[2],
    );
}

impl SettingsCx {
    /// Safe, non-secret label for the layer that governs the effective
    /// default in this dialog's configuration context. Never a filesystem
    /// path.
    /// The default a newly created session would resolve in this dialog's
    /// configuration context — the layered merge, not the single edited layer.
    pub(super) fn effective_default_model(
        &self,
    ) -> Option<cockpit_config::providers::ActiveModelRef> {
        // This is the dialog's daemon-synchronised provider snapshot.  Do
        // not load an effective layer here: that client-side helper may run
        // recovery/migration work and is not the authority for settings.
        self.config.active_model.clone()
    }

    pub(super) fn effective_default_scope_label(&self) -> String {
        let cwd = self
            .active_project_root
            .clone()
            .or_else(|| self.picker_cwd.clone());
        match cwd
            .as_deref()
            .map(cockpit_config::providers::resolve_effective_default_write_target)
        {
            Some(Ok(target)) => target.scope_label(),
            _ => "current configuration context".to_string(),
        }
    }

    /// Stage the one authoritative default-model request when a Settings edit
    /// changed the layer-wide `active_model`.
    ///
    /// `/settings` never writes `active_model` to a `config.json`: the daemon
    /// owns target-layer selection, locking, the journal, and reload
    /// verification, and it changes no running session.
    fn stage_default_model_change(&mut self) -> bool {
        if self.config.active_model == self.original_config.active_model {
            return false;
        }
        let default_update_id = uuid::Uuid::new_v4();
        let request = match self.config.active_model.clone() {
            Some(active) => Request::SetDefaultModel {
                default_update_id,
                provider: Some(active.provider),
                model: Some(active.model),
                reasoning_effort: active.reasoning_effort.map(|effort| effort.value),
                thinking_mode: active.thinking_mode,
                prompt_cache_retention: active.prompt_cache_retention,
                clear: false,
            },
            None => Request::SetDefaultModel {
                default_update_id,
                provider: None,
                model: None,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
                clear: true,
            },
        };
        self.pending_default_model_update_id = Some(default_update_id);
        self.pending_daemon_request = Some(request);
        true
    }

    fn reload_extended(&mut self) {
        self.queue_extended_load();
    }

    pub(super) fn save_extended(&mut self) -> Result<SettingsSaveOutcome, String> {
        self.queue_extended_save()
    }

    fn protect_provider_literal_headers(
        &self,
        providers: &mut std::collections::BTreeMap<String, ProviderEntry>,
    ) -> Result<Option<cockpit_core::secret_ref::SecretRefNotice>, String> {
        // The SaveProviderConfig RPC owns materialization and collision-safe
        // names. Settings must retain plaintext only long enough to include it
        // in that one daemon request; it never writes a separate vault record.
        let count = providers
            .values()
            .flat_map(|entry| &entry.headers)
            .filter(|header| {
                let value = header.value.trim();
                !value.is_empty()
                    && !value.starts_with('$')
                    && !cockpit_config::config::providers::is_safe_provider_header_reference(
                        &header.name.to_ascii_lowercase(),
                        value,
                    )
                    && !secret_display::is_mask_value(value)
            })
            .count();
        if count == 0 {
            return Ok(None);
        }
        Ok(Some(cockpit_core::secret_ref::SecretRefNotice {
            migrated: count,
            store_path: PathBuf::from("daemon vault"),
        }))
    }

    /// Provider configuration is daemon-owned for the same reason as the
    /// adjacent credentials: the daemon has the trust-aware write target and
    /// can refresh its authoritative snapshot atomically with the mutation.
    fn upsert_provider_config_via_daemon(
        &mut self,
        config: &mut ProvidersConfig,
        notice: Option<String>,
    ) -> Result<(), String> {
        if self
            .pending_settings
            .values()
            .any(|pending| matches!(pending, PendingSettingsOperation::ProviderMutation { .. }))
        {
            return Err("a provider settings save is already pending".into());
        }
        let authority = self.provider_edit_authority.clone().ok_or_else(|| {
            "provider snapshot has no edit capability; reload before saving".to_string()
        })?;
        // `config` is the dialog's effective view in some launch paths. Send
        // only the user's edit intent: unchanged inherited providers must not
        // be re-upserted into the defining layer and shadow the global entry.
        let saves = config
            .providers
            .iter_mut()
            .filter_map(|(provider_id, entry)| {
                let changed =
                self.original_config
                    .providers
                    .get(provider_id)
                    .is_none_or(|original| !provider_entries_equal(original, entry));
                if !changed {
                    return None;
                }
                let header_secrets = entry
                    .headers
                    .iter_mut()
                    .map(|header| {
                        let value = header.value.trim();
                        let is_secret = !value.is_empty()
                            && !value.starts_with('$')
                            && !cockpit_config::config::providers::is_safe_provider_header_reference(
                                &header.name.to_ascii_lowercase(),
                                value,
                            )
                            && !secret_display::is_mask_value(value);
                        is_secret.then(|| {
                            zeroize::Zeroizing::new(std::mem::take(&mut header.value))
                        })
                    })
                    .collect::<Vec<_>>();
                Some(ProviderSavePlan {
                    provider_id: provider_id.clone(),
                    // Every staged plaintext was moved, not cloned, before
                    // this reference-only projection was cloned.
                    entry: entry.clone(),
                    header_secrets,
                })
            })
            .collect::<Vec<_>>();
        let deletes = self
            .original_config
            .providers
            .keys()
            .filter(|provider_id| !config.providers.contains_key(*provider_id))
            .map(|provider_id| (provider_id.clone(), false))
            .collect::<Vec<_>>();
        let category_defaults = config.category_defaults.clone();
        let on_unlisted_models_fetch = config
            .on_unlisted_models_fetch
            .unwrap_or(OnUnlistedModelsFetch::Keep);
        let metadata_changed = config.category_defaults != self.original_config.category_defaults
            || config.on_unlisted_models_fetch != self.original_config.on_unlisted_models_fetch;
        if saves.is_empty() && deletes.is_empty() && !metadata_changed {
            return Ok(());
        }
        let client_operation_id = uuid::Uuid::new_v4().to_string();
        let target = SettingsEffectTarget {
            surface: "settings.provider-mutation",
            owner: authority.layer_id.clone(),
            revision: Some(authority.base_revision.clone()),
        };
        let plan = ProviderMutationPlan {
            snapshot_session_id: authority.snapshot_session_id.clone(),
            layer_id: authority.layer_id.clone(),
            expected_revision: authority.base_revision.clone(),
            client_operation_id: client_operation_id.clone(),
            saves,
            deletes,
            metadata: metadata_changed.then_some((category_defaults, on_unlisted_models_fetch)),
        };
        let operation_id = self.enqueue_daemon_work(
            target.clone(),
            SettingsDaemonEffectWork::ProviderMutation(plan),
        );
        self.pending_settings.insert(
            operation_id,
            PendingSettingsOperation::ProviderMutation {
                target,
                client_operation_id,
                snapshot_session_id: authority.snapshot_session_id,
                layer_id: authority.layer_id,
                expected_revision: authority.base_revision,
                expected_generation: authority.config_generation,
                staged_default: self.original_config.active_model.clone(),
                notice,
            },
        );
        self.extended_warnings = vec!["saving provider settings…".into()];
        Ok(())
    }

    fn delete_provider_config_via_daemon(
        &mut self,
        provider_id: String,
        delete_stored_secrets: bool,
    ) -> Result<(), String> {
        if self
            .pending_settings
            .values()
            .any(|pending| matches!(pending, PendingSettingsOperation::ProviderMutation { .. }))
        {
            return Err("a provider settings save is already pending".into());
        }
        let authority = self.provider_edit_authority.clone().ok_or_else(|| {
            "provider snapshot has no edit capability; reload before deleting".to_string()
        })?;
        let client_operation_id = uuid::Uuid::new_v4().to_string();
        let target = SettingsEffectTarget {
            surface: "settings.provider-delete",
            owner: authority.layer_id.clone(),
            revision: Some(authority.base_revision.clone()),
        };
        let operation_id = self.enqueue_daemon_work(
            target.clone(),
            SettingsDaemonEffectWork::ProviderMutation(ProviderMutationPlan {
                snapshot_session_id: authority.snapshot_session_id.clone(),
                layer_id: authority.layer_id.clone(),
                expected_revision: authority.base_revision.clone(),
                client_operation_id: client_operation_id.clone(),
                saves: Vec::new(),
                deletes: vec![(provider_id, delete_stored_secrets)],
                metadata: None,
            }),
        );
        self.pending_settings.insert(
            operation_id,
            PendingSettingsOperation::ProviderMutation {
                target,
                client_operation_id,
                snapshot_session_id: authority.snapshot_session_id,
                layer_id: authority.layer_id,
                expected_revision: authority.base_revision,
                expected_generation: authority.config_generation,
                staged_default: self.original_config.active_model.clone(),
                notice: None,
            },
        );
        Ok(())
    }

    fn save_config(&mut self) -> Result<(), String> {
        let mut merged = self.config.clone();
        let notice = self.protect_provider_literal_headers(&mut merged.providers)?;
        // The layer-wide default is never part of this file write; it goes to
        // the daemon's authoritative effective-default operation, and the
        // dialog only shows the new value once that verified result arrives.
        self.stage_default_model_change();
        let result = self
            .upsert_provider_config_via_daemon(&mut merged, notice.map(|notice| notice.render()));
        // Once queued, leave no second plaintext owner in the live dialog.
        for entry in self.config.providers.values_mut() {
            for header in &mut entry.headers {
                let value = header.value.trim();
                if !value.is_empty()
                    && !value.starts_with('$')
                    && !secret_display::is_mask_value(value)
                    && !cockpit_config::config::providers::is_safe_provider_header_reference(
                        &header.name.to_ascii_lowercase(),
                        value,
                    )
                {
                    header.value = "********".into();
                }
            }
        }
        result
    }

    fn delete_provider_and_stored_secrets(
        &mut self,
        provider_id: &str,
        delete_stored_secrets: bool,
    ) -> Result<usize, String> {
        self.delete_provider_config_via_daemon(provider_id.to_string(), delete_stored_secrets)?;
        Ok(0)
    }
}

fn merge_dialog_provider_config(
    disk: &mut ProvidersConfig,
    original: &ProvidersConfig,
    current: &ProvidersConfig,
) {
    // `active_model` is deliberately not merged here. It is layer-wide default
    // policy owned by the daemon's one effective-default mutation, so Settings
    // stages a `SetDefaultModel` request instead of writing the file directly.
    if current.category_defaults != original.category_defaults {
        disk.category_defaults = current.category_defaults.clone();
    }
    if current.on_unlisted_models_fetch != original.on_unlisted_models_fetch {
        disk.on_unlisted_models_fetch = current.on_unlisted_models_fetch;
    }

    for provider_id in original.providers.keys() {
        if !current.providers.contains_key(provider_id) {
            disk.providers.remove(provider_id);
        }
    }
    for (provider_id, entry) in &current.providers {
        let original_entry = original.providers.get(provider_id);
        if original_entry.is_none_or(|old| !provider_entries_equal(old, entry)) {
            disk.providers.insert(provider_id.clone(), entry.clone());
        }
    }
}

fn providers_config_from_view(
    view: &cockpit_core::daemon::proto::ProviderConfigView,
) -> ProvidersConfig {
    ProvidersConfig {
        providers: view
            .providers
            .iter()
            .map(|(provider_id, entry_view)| {
                let mut entry = entry_view.entry.clone();
                // Keep only a non-secret editor marker. The daemon accepts
                // this marker as "preserve the existing value" on a later
                // save, so the literal never remains in TUI state.
                entry.headers = entry_view
                    .headers
                    .iter()
                    .map(|header| cockpit_config::config::providers::HeaderSpec {
                        name: header.name.clone(),
                        value: secret_display::MASKED_VALUE.to_string(),
                    })
                    .collect();
                (provider_id.clone(), entry)
            })
            .collect(),
        category_defaults: view.category_defaults.clone(),
        on_unlisted_models_fetch: view.on_unlisted_models_fetch,
        active_model: view.active_model.clone(),
        resolution_generation: 0,
    }
}

#[cfg(test)]
fn daemon_provider_snapshot(
    cwd: &std::path::Path,
    provider_id: Option<&str>,
) -> Option<ProvidersConfig> {
    let project_root = cwd.display().to_string();
    let provider_id = provider_id.map(str::to_string);
    daemon_provider_view_snapshot_inner(project_root, provider_id)
        .map(|config| providers_config_from_view(&config))
}

#[cfg(test)]
fn daemon_provider_view_snapshot(
    cwd: &std::path::Path,
    provider_id: Option<&str>,
) -> Option<cockpit_core::daemon::proto::ProviderConfigView> {
    let project_root = cwd.display().to_string();
    let provider_id = provider_id.map(str::to_string);
    daemon_provider_view_snapshot_inner(project_root, provider_id)
}

#[cfg(test)]
fn daemon_provider_view_snapshot_inner(
    project_root: String,
    provider_id: Option<String>,
) -> Option<cockpit_core::daemon::proto::ProviderConfigView> {
    match settings_daemon_request(Request::GetProviderCatalogSnapshot {
        project_root,
        provider_id,
        snapshot_session_id: uuid::Uuid::new_v4().to_string(),
    }) {
        Ok(Response::ProviderCatalogSnapshot { config, .. }) => Some(config),
        Ok(other) => {
            tracing::warn!(response = ?other, "unexpected daemon provider snapshot response");
            None
        }
        Err(error) => {
            tracing::warn!(%error, "daemon provider snapshot failed");
            None
        }
    }
}

fn config_cwd(path: &std::path::Path) -> Option<std::path::PathBuf> {
    path.parent()
        .and_then(std::path::Path::parent)
        .or_else(|| path.parent())
        .map(std::path::Path::to_path_buf)
}

fn provider_entries_equal(left: &ProviderEntry, right: &ProviderEntry) -> bool {
    match (serde_json::to_value(left), serde_json::to_value(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn handle_setup_wizard_key(wizard: &mut SetupWizardDialog, key: KeyEvent) -> bool {
    let SetupWizardDialog {
        run,
        cursor,
        text,
        multi,
        multi_touched,
        tool_surface,
        tool_surface_touched,
        cwd,
        status,
    } = wizard;
    macro_rules! submit_answer {
        ($answer:expr $(,)?) => {
            let answer = $answer;
            submit_setup_wizard_answer(
                SetupWizardSubmit {
                    run,
                    inputs: SetupWizardInputs {
                        cursor,
                        text,
                        multi,
                        multi_touched,
                        tool_surface,
                        tool_surface_touched,
                    },
                    status,
                },
                answer,
            );
        };
    }
    if run.is_complete() {
        return matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q'));
    }
    let Some(step) = run.current_step().cloned() else {
        return false;
    };
    match step.kind {
        cockpit_core::wizard::StepKind::Select { .. } => {
            let options = run.select_options();
            match list_key_action(key, cursor, options.len()) {
                ListAction::Close => return true,
                ListAction::Stay => {}
                ListAction::Select(index) => {
                    submit_answer!(cockpit_core::wizard::WizardAnswer::Select(
                        options[index].id.to_string()
                    ),);
                }
            }
        }
        cockpit_core::wizard::StepKind::Confirm => match key.code {
            KeyCode::Esc => return true,
            KeyCode::Enter => {
                let answer = run
                    .prefill()
                    .unwrap_or(cockpit_core::wizard::WizardAnswer::Confirm(false));
                submit_answer!(answer);
            }
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                submit_answer!(cockpit_core::wizard::WizardAnswer::Confirm(true));
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                submit_answer!(cockpit_core::wizard::WizardAnswer::Confirm(false));
            }
            _ => {}
        },
        cockpit_core::wizard::StepKind::Text => match key.code {
            KeyCode::Esc => return true,
            KeyCode::Enter => {
                submit_answer!(cockpit_core::wizard::WizardAnswer::Text(
                    text.text().to_string()
                ),);
            }
            _ => {
                text.handle_key(key);
            }
        },
        cockpit_core::wizard::StepKind::Info => match key.code {
            KeyCode::Esc => return true,
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                submit_answer!(cockpit_core::wizard::WizardAnswer::Acknowledged);
            }
            _ => {}
        },
        cockpit_core::wizard::StepKind::Action { .. } => {
            if step.id == "security-save" {
                match cockpit_core::wizard::apply_security_answers(cwd, run) {
                    Ok(Some(path)) => *status = Some(format!("Saved {}", path.display())),
                    Ok(None) => *status = Some("Security settings unchanged.".to_string()),
                    Err(error) => {
                        *status = Some(error.to_string());
                        return false;
                    }
                }
            } else if step.id == "model-save" {
                match cockpit_core::wizard::apply_model_answers(cwd, run) {
                    Ok(outcome) if outcome.changed_nothing() => {
                        *status = Some("No model-setting changes were needed.".to_string())
                    }
                    Ok(outcome) => {
                        let mut parts = Vec::new();
                        if let Some(path) = outcome.model_file.as_ref() {
                            parts.push(format!("Saved model settings to {}.", path.display()));
                        }
                        // Layer-wide default policy names a safe scope label,
                        // never a filesystem path.
                        if let Some(scope) = outcome.default_scope.as_ref() {
                            parts.push(format!(
                                "Set the default model for new sessions ({scope}); running sessions are unchanged."
                            ));
                        }
                        *status = Some(parts.join(" "));
                    }
                    Err(error) => {
                        *status = Some(format!("Could not save model settings: {error}"));
                        return false;
                    }
                }
            }
            submit_answer!(cockpit_core::wizard::WizardAnswer::Acknowledged);
        }
        cockpit_core::wizard::StepKind::MultiToggle { options } => match key.code {
            KeyCode::Esc => return true,
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                *cursor = crate::tui::nav::wrap_prev(*cursor, options.len());
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                *cursor = crate::tui::nav::wrap_next(*cursor, options.len());
            }
            KeyCode::Char(' ') if *cursor < options.len() => {
                if !*multi_touched {
                    multi.clear();
                    if let Some(cockpit_core::wizard::WizardAnswer::MultiToggle(values)) =
                        run.prefill()
                    {
                        multi.extend(values);
                    }
                    *multi_touched = true;
                }
                let id = options[*cursor].id.to_string();
                if !multi.remove(&id) {
                    multi.insert(id);
                }
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                let answer = if !*multi_touched
                    && let Some(cockpit_core::wizard::WizardAnswer::MultiToggle(values)) =
                        run.prefill()
                {
                    cockpit_core::wizard::WizardAnswer::MultiToggle(values)
                } else {
                    cockpit_core::wizard::WizardAnswer::MultiToggle(multi.iter().cloned().collect())
                };
                submit_answer!(answer);
            }
            _ => {}
        },
        cockpit_core::wizard::StepKind::ToolSurface => match key.code {
            KeyCode::Esc => return true,
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                *cursor = crate::tui::nav::wrap_prev(
                    *cursor,
                    cockpit_core::agents::tool_surface_catalog().len(),
                );
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                *cursor = crate::tui::nav::wrap_next(
                    *cursor,
                    cockpit_core::agents::tool_surface_catalog().len(),
                );
            }
            KeyCode::Char(' ') => {
                touch_tool_surface(run, tool_surface, tool_surface_touched);
                if let Some(tool) = cockpit_core::agents::tool_surface_catalog().get(*cursor) {
                    if tool_surface
                        .tools
                        .iter()
                        .any(|existing| existing == tool.name)
                    {
                        tool_surface.tools.retain(|existing| existing != tool.name);
                    } else {
                        tool_surface.tools.push(tool.name.to_string());
                        tool_surface.tools.sort();
                    }
                    if !tool_surface
                        .tools
                        .iter()
                        .any(|existing| existing == tool.name)
                    {
                        tool_surface.tool_tiers.remove(tool.name);
                    }
                }
            }
            KeyCode::Char('t') => {
                touch_tool_surface(run, tool_surface, tool_surface_touched);
                if let Some(tool) = cockpit_core::agents::tool_surface_catalog().get(*cursor) {
                    if !tool_surface
                        .tools
                        .iter()
                        .any(|existing| existing == tool.name)
                    {
                        tool_surface.tools.push(tool.name.to_string());
                        tool_surface.tools.sort();
                    }
                    let current = tool_surface
                        .tool_tiers
                        .get(tool.name)
                        .copied()
                        .unwrap_or(cockpit_core::agents::ToolTier::Enabled);
                    let tiers = cockpit_core::agents::legal_tool_tiers(tool.name);
                    let index = tiers.iter().position(|tier| *tier == current).unwrap_or(0);
                    let next = tiers[(index + 1) % tiers.len()];
                    if next == cockpit_core::agents::ToolTier::Enabled {
                        tool_surface.tool_tiers.remove(tool.name);
                    } else {
                        tool_surface.tool_tiers.insert(tool.name.to_string(), next);
                    }
                }
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                touch_tool_surface(run, tool_surface, tool_surface_touched);
                submit_answer!(cockpit_core::wizard::WizardAnswer::ToolSurface(
                    tool_surface.clone()
                ),);
            }
            _ => {}
        },
        cockpit_core::wizard::StepKind::Secret => {}
    }
    false
}

struct SetupWizardInputs<'a> {
    cursor: &'a mut usize,
    text: &'a mut TextField,
    multi: &'a mut std::collections::BTreeSet<String>,
    multi_touched: &'a mut bool,
    tool_surface: &'a mut cockpit_core::agents::ToolSurfaceSelection,
    tool_surface_touched: &'a mut bool,
}

struct SetupWizardSubmit<'a> {
    run: &'a mut cockpit_core::wizard::WizardRun,
    inputs: SetupWizardInputs<'a>,
    status: &'a mut Option<String>,
}

fn submit_setup_wizard_answer(
    state: SetupWizardSubmit<'_>,
    answer: cockpit_core::wizard::WizardAnswer,
) {
    let SetupWizardSubmit {
        run,
        inputs,
        status,
    } = state;
    match run.submit(answer) {
        Ok(()) => sync_setup_wizard_inputs(run, inputs),
        Err(error) => *status = Some(error),
    }
}

fn sync_setup_wizard_inputs(run: &cockpit_core::wizard::WizardRun, inputs: SetupWizardInputs<'_>) {
    let SetupWizardInputs {
        cursor,
        text,
        multi,
        multi_touched,
        tool_surface,
        tool_surface_touched,
    } = inputs;
    *cursor = setup_wizard_cursor_for_current_prefill(run);
    multi.clear();
    *multi_touched = false;
    *tool_surface = cockpit_core::agents::ToolSurfaceSelection::default();
    *tool_surface_touched = false;
    let Some(step) = run.current_step() else {
        return;
    };
    match step.kind {
        cockpit_core::wizard::StepKind::Text => {
            let value = match run.prefill() {
                Some(cockpit_core::wizard::WizardAnswer::Text(value)) => value,
                _ => String::new(),
            };
            text.set(value);
        }
        cockpit_core::wizard::StepKind::MultiToggle { .. } => {
            if let Some(cockpit_core::wizard::WizardAnswer::MultiToggle(values)) = run.prefill() {
                multi.extend(values);
            }
        }
        cockpit_core::wizard::StepKind::ToolSurface => {
            if let Some(cockpit_core::wizard::WizardAnswer::ToolSurface(value)) = run.prefill() {
                *tool_surface = value;
            }
        }
        _ => {}
    }
}

fn setup_wizard_cursor_for_current_prefill(run: &cockpit_core::wizard::WizardRun) -> usize {
    let Some(step) = run.current_step() else {
        return 0;
    };
    let cockpit_core::wizard::StepKind::Select { .. } = &step.kind else {
        return 0;
    };
    let Some(cockpit_core::wizard::WizardAnswer::Select(value)) = run.prefill() else {
        return 0;
    };
    run.select_options()
        .iter()
        .position(|option| option.id == value)
        .unwrap_or(0)
}

fn touch_tool_surface(
    run: &cockpit_core::wizard::WizardRun,
    tool_surface: &mut cockpit_core::agents::ToolSurfaceSelection,
    touched: &mut bool,
) {
    if *touched {
        return;
    }
    if let Some(cockpit_core::wizard::WizardAnswer::ToolSurface(value)) = run.prefill() {
        *tool_surface = value;
    }
    *touched = true;
}

enum WorkspaceTrustAction {
    Stay,
    Choose(cockpit_config::WorkspaceTrustMode),
}

fn workspace_trust_key_action(key: KeyEvent, cursor: &mut usize) -> WorkspaceTrustAction {
    use cockpit_config::WorkspaceTrustMode;
    const LEN: usize = 3;
    match key.code {
        KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
            *cursor = crate::tui::nav::wrap_prev(*cursor, LEN);
            WorkspaceTrustAction::Stay
        }
        KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
            *cursor = crate::tui::nav::wrap_next(*cursor, LEN);
            WorkspaceTrustAction::Stay
        }
        KeyCode::Char('1') => WorkspaceTrustAction::Choose(WorkspaceTrustMode::Trust),
        KeyCode::Char('2') => WorkspaceTrustAction::Choose(WorkspaceTrustMode::IgnoreConfig),
        KeyCode::Char('3') | KeyCode::Esc => {
            WorkspaceTrustAction::Choose(WorkspaceTrustMode::Untrusted)
        }
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
            WorkspaceTrustAction::Choose(match *cursor {
                0 => WorkspaceTrustMode::Trust,
                1 => WorkspaceTrustMode::IgnoreConfig,
                _ => WorkspaceTrustMode::Untrusted,
            })
        }
        _ => WorkspaceTrustAction::Stay,
    }
}

enum ListAction {
    Stay,
    Close,
    Select(usize),
}

fn list_key_action(key: KeyEvent, cursor: &mut usize, len: usize) -> ListAction {
    match key.code {
        KeyCode::Esc => ListAction::Close,
        KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
            *cursor = crate::tui::nav::wrap_prev(*cursor, len);
            ListAction::Stay
        }
        KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
            *cursor = crate::tui::nav::wrap_next(*cursor, len);
            ListAction::Stay
        }
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') if *cursor < len => {
            ListAction::Select(*cursor)
        }
        _ => ListAction::Stay,
    }
}

fn render_workspace_trust(
    frame: &mut Frame,
    area: Rect,
    root: &cockpit_config::trust::TrustRoot,
    cursor: usize,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Workspace trust ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let selected = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let options = [
        (
            "trust",
            "open and honor project .cockpit config",
            cockpit_config::WorkspaceTrustMode::Trust,
        ),
        (
            "ignore-config",
            "open but ignore project .cockpit config and approvals",
            cockpit_config::WorkspaceTrustMode::IgnoreConfig,
        ),
        (
            "untrusted",
            "refuse to open",
            cockpit_config::WorkspaceTrustMode::Untrusted,
        ),
    ];
    let mut lines = vec![
        Line::from(Span::styled(
            "Cockpit has not seen this workspace before:",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::raw(format!("  {}", root.root.display()))),
        Line::default(),
        Line::from(Span::styled("Choose workspace trust:", muted)),
    ];
    for (index, (label, description, _)) in options.iter().enumerate() {
        let marker = if index == cursor { "▸ " } else { "  " };
        let style = if index == cursor {
            selected
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::raw(marker),
            Span::styled(format!("{}. {label}", index + 1), style),
            Span::raw(" - "),
            Span::styled((*description).to_string(), muted),
        ]));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), layout[0]);
    frame.render_widget(help_line("↑/↓  enter: choose  esc: untrusted"), layout[1]);
}

fn render_picker(
    frame: &mut Frame,
    area: Rect,
    subtitle: &str,
    entries: &[ConfigDir],
    cursor: usize,
    status: Option<&str>,
    help: &str,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Settings — {subtitle} "));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);

    let mut lines: Vec<Line<'static>> = Vec::new();
    if entries.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (no candidates)",
            Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
        )));
    } else {
        let path_w = entries
            .iter()
            .map(|e| cockpit_core::welcome::display_path(&e.path).chars().count())
            .max()
            .unwrap_or(0);
        for (i, entry) in entries.iter().enumerate() {
            let marker = if i == cursor { "▸ " } else { "  " };
            let path_str = cockpit_core::welcome::display_path(&entry.path);
            let kind_str = kind_label(&entry.kind);
            let mut spans: Vec<Span<'static>> = Vec::new();
            spans.push(Span::raw(marker));
            spans.push(Span::styled(
                pad_right(&path_str, path_w),
                if i == cursor {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            ));
            spans.push(Span::raw("   "));
            spans.push(Span::styled(
                kind_str.to_string(),
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            ));
            lines.push(Line::from(spans));
        }
    }
    if let Some(msg) = status {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            msg.to_string(),
            Style::default().fg(Color::Yellow),
        )));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), layout[0]);
    frame.render_widget(help_line(help), layout[1]);
}

fn render_wizard_menu(
    frame: &mut Frame,
    area: Rect,
    wizards: &[cockpit_core::wizard::WizardDescriptor],
    cursor: usize,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Setup — choose a wizard ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let selected = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let mut lines: Vec<Line<'static>> = Vec::new();
    if wizards.is_empty() {
        lines.push(Line::from(Span::styled("  (no wizards registered)", muted)));
    } else {
        for (index, wizard) in wizards.iter().enumerate() {
            let marker = if index == cursor { "▸ " } else { "  " };
            let style = if index == cursor {
                selected
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(vec![
                Span::raw(marker),
                Span::styled(wizard.id.to_string(), style),
                Span::raw("  "),
                Span::styled(wizard.description.to_string(), muted),
            ]));
        }
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), layout[0]);
    frame.render_widget(help_line("↑/↓  enter: select  esc: close"), layout[1]);
}

fn render_model_setup_choice(
    frame: &mut Frame,
    area: Rect,
    confirmed: Option<&(String, String)>,
    pending: Option<&(String, String)>,
    cursor: usize,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Setup — model ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let selected = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let mut lines: Vec<Line<'static>> = vec![
        Line::from(Span::styled(
            "Configure which model?",
            Style::default().fg(Color::White),
        )),
        Line::default(),
    ];
    if let Some((provider, model)) = confirmed {
        for (index, (label, description)) in [
            (
                format!("Use the currently selected model: {provider}/{model}"),
                "Configure this exact pair; it does not change the live session model.".to_string(),
            ),
            (
                "Choose a different model".to_string(),
                "Choose a provider, then one of that provider’s models.".to_string(),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let marker = if index == cursor { "▸ " } else { "  " };
            let style = if index == cursor {
                selected
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(vec![
                Span::raw(marker),
                Span::styled(label, style),
                Span::raw("  "),
                Span::styled(description, muted),
            ]));
        }
    } else {
        if let Some((provider, model)) = pending {
            lines.push(Line::from(Span::styled(
                format!("{provider}/{model} is still being selected. Wait for confirmation or choose a different model."),
                muted,
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "No model is confirmed for this session; choose a provider and model to configure.",
                muted,
            )));
        }
        lines.push(Line::default());
        let style = if cursor == 0 {
            selected
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::raw(if cursor == 0 { "▸ " } else { "  " }),
            Span::styled("Choose a different model", style),
            Span::raw("  "),
            Span::styled(
                "Choose a provider, then one of that provider’s models.",
                muted,
            ),
        ]));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), layout[0]);
    frame.render_widget(help_line("↑/↓  enter: select  esc: close"), layout[1]);
}

fn render_setup_wizard(frame: &mut Frame, area: Rect, wizard: &SetupWizardDialog) {
    let SetupWizardDialog {
        run,
        cursor,
        text,
        multi,
        multi_touched,
        tool_surface,
        tool_surface_touched,
        status,
        ..
    } = wizard;
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Setup — {} ", run.descriptor().title));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let selected = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(Span::styled(
        run.descriptor().description.to_string(),
        muted,
    )));
    lines.push(Line::default());

    if run.is_complete() {
        let complete = match run.descriptor().id {
            cockpit_core::wizard::MODEL_WIZARD_ID => "Model setup complete.",
            "security" => "Security setup complete.",
            _ => "Setup complete.",
        };
        lines.push(Line::from(complete));
    } else if let Some(step) = run.current_step() {
        lines.push(Line::from(Span::styled(
            step.prompt.to_string(),
            Style::default().fg(Color::White),
        )));
        let help = run.help();
        if !help.is_empty() {
            lines.push(Line::from(Span::styled(help.into_owned(), muted)));
        }
        lines.push(Line::default());
        match &step.kind {
            cockpit_core::wizard::StepKind::Select { .. } => {
                let options = run.select_options();
                for (index, option) in options.iter().enumerate() {
                    let marker = if index == *cursor { "▸ " } else { "  " };
                    let style = if index == *cursor {
                        selected
                    } else {
                        Style::default().fg(Color::White)
                    };
                    lines.push(Line::from(vec![
                        Span::raw(marker),
                        Span::styled(option.label.to_string(), style),
                        Span::raw("  "),
                        Span::styled(option.description.to_string(), muted),
                    ]));
                }
            }
            cockpit_core::wizard::StepKind::Confirm => {
                let current = match run.prefill() {
                    Some(cockpit_core::wizard::WizardAnswer::Confirm(true)) => "yes",
                    _ => "no",
                };
                lines.push(Line::from(format!("Current/default: {current}")));
            }
            cockpit_core::wizard::StepKind::Text => {
                lines.push(Line::from(format!("Value: {}", text.text())));
            }
            cockpit_core::wizard::StepKind::Info => {
                lines.push(Line::from("Press Enter to continue."));
            }
            cockpit_core::wizard::StepKind::Action { progress } => {
                lines.push(Line::from(*progress));
            }
            cockpit_core::wizard::StepKind::MultiToggle { options } => {
                let prefill_values = if *multi_touched {
                    None
                } else {
                    match run.prefill() {
                        Some(cockpit_core::wizard::WizardAnswer::MultiToggle(values)) => {
                            Some(values)
                        }
                        _ => None,
                    }
                };
                for (index, option) in options.iter().enumerate() {
                    let marker = if index == *cursor { "▸ " } else { "  " };
                    let checked = prefill_values
                        .as_ref()
                        .map(|values| values.iter().any(|value| value == option.id.as_ref()))
                        .unwrap_or_else(|| multi.contains(option.id.as_ref()));
                    let check = if checked { "[x]" } else { "[ ]" };
                    let style = if index == *cursor {
                        selected
                    } else {
                        Style::default().fg(Color::White)
                    };
                    lines.push(Line::from(vec![
                        Span::raw(marker),
                        Span::styled(check.to_string(), style),
                        Span::raw(" "),
                        Span::styled(option.label.to_string(), style),
                        Span::raw("  "),
                        Span::styled(option.description.to_string(), muted),
                    ]));
                }
            }
            cockpit_core::wizard::StepKind::ToolSurface => {
                let surface = if *tool_surface_touched {
                    tool_surface.clone()
                } else {
                    match run.prefill() {
                        Some(cockpit_core::wizard::WizardAnswer::ToolSurface(value)) => value,
                        _ => cockpit_core::agents::ToolSurfaceSelection::default(),
                    }
                };
                let mut last_family = "";
                for (index, item) in cockpit_core::agents::tool_surface_catalog()
                    .into_iter()
                    .enumerate()
                {
                    if item.family != last_family {
                        if !last_family.is_empty() {
                            lines.push(Line::default());
                        }
                        lines.push(Line::from(Span::styled(item.family.to_string(), muted)));
                        last_family = item.family;
                    }
                    let marker = if index == *cursor { "▸ " } else { "  " };
                    let checked = surface.tools.iter().any(|tool| tool == item.name);
                    let tier = if checked {
                        surface
                            .tool_tiers
                            .get(item.name)
                            .copied()
                            .unwrap_or(cockpit_core::agents::ToolTier::Enabled)
                            .label()
                    } else {
                        "-"
                    };
                    let style = if index == *cursor {
                        selected
                    } else {
                        Style::default().fg(Color::White)
                    };
                    lines.push(Line::from(vec![
                        Span::raw(marker),
                        Span::styled(if checked { "[x]" } else { "[ ]" }.to_string(), style),
                        Span::raw(" "),
                        Span::styled(item.name.to_string(), style),
                        Span::raw("  "),
                        Span::styled(format!("tier: {tier}"), muted),
                    ]));
                }
            }
            cockpit_core::wizard::StepKind::Secret => {
                lines.push(Line::from("Unsupported setup step."));
            }
        }
    }
    if let Some(status) = status.as_deref() {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(status.to_string(), muted)));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), layout[0]);
    frame.render_widget(
        help_line("↑/↓  space: toggle  t: tier  enter: select/continue  y/n: confirm  esc: close"),
        layout[1],
    );
}

fn render_first_run_complete(frame: &mut Frame, area: Rect, summary: &str) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Setup complete ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let lines = vec![
        Line::from("Cockpit is ready."),
        Line::from(summary.to_string()),
        Line::default(),
        Line::from("Next: run /setup security to choose project trust and approval defaults."),
        Line::from("Use /help any time to see available commands."),
        Line::default(),
        Line::from(Span::styled("Press Enter to start.", muted)),
    ];
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn help_line(text: &str) -> Paragraph<'static> {
    Paragraph::new(Line::from(Span::styled(
        text.to_string(),
        Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
    )))
}

/// The `config.json` path of the **nearest project** `.cockpit/` layer for
/// `cwd` (the deepest ancestor with a project layer), scaffolding
/// `cwd/.cockpit/config.json` when none exists. Used by `/gitignore-allow` so
/// the read-allowlist always lands in the project layer
/// (implementation note).
fn nearest_project_config_path(cwd: &std::path::Path) -> PathBuf {
    if let Some(dir) = discover_config_dirs(cwd)
        .into_iter()
        .rfind(|d| d.kind == ConfigDirKind::Project)
    {
        return dir.path.join(cockpit_config::dirs::CONFIG_FILE);
    }
    let project = cwd.join(".cockpit");
    project.join(cockpit_config::dirs::CONFIG_FILE)
}

fn kind_label(kind: &ConfigDirKind) -> &'static str {
    match kind {
        ConfigDirKind::HomeXdg => "(home / XDG)",
        ConfigDirKind::HomeDot => "(home / dotfile)",
        ConfigDirKind::MachineLocal => "(machine-local, scoped to cwd)",
        ConfigDirKind::Project => "(project — shareable with team)",
    }
}

fn pad_right(s: &str, target: usize) -> String {
    let len = s.chars().count();
    if len >= target {
        s.to_string()
    } else {
        let mut out = s.to_string();
        for _ in len..target {
            out.push(' ');
        }
        out
    }
}

// ── Public API for slash-command-triggered flows ─────────────────────────

/// Start a /fetch-models workflow against the currently-loaded config.
/// The caller wires this in from the slash command handler.
#[allow(dead_code)]
pub fn fetch_all_unlisted_dialog(
    config: &ProvidersConfig,
    finished: Vec<(String, Result<FetchOutcome, String>)>,
    store_default_decision: Option<OnUnlistedModelsFetch>,
) -> (Vec<(String, String)>, bool) {
    // Build the unlisted (config-model not present in remote-list) set.
    let mut unlisted: Vec<(String, String)> = Vec::new();
    for (pid, outcome) in &finished {
        if let Ok(FetchOutcome::Models { models: remote, .. }) = outcome
            && let Some(entry) = config.providers.get(pid)
        {
            for m in &entry.models {
                // Manual entries are intentionally absent from upstream —
                // they're retained by the merge, not "drifted out".
                if !m.manual && !remote.iter().any(|r| r.id == m.id) {
                    unlisted.push((pid.clone(), m.id.clone()));
                }
            }
        }
    }
    let needs_prompt = !unlisted.is_empty()
        && matches!(
            store_default_decision,
            Some(OnUnlistedModelsFetch::Ask) | None
        );
    (unlisted, needs_prompt)
}

#[cfg(test)]
pub(super) mod tests;
