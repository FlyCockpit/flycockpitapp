//! Driver-side native computer-use dispatch wiring.
//!
//! [`handle_native_computer_items`] is the concrete free function that the
//! real multi-turn / tool-result path in [`super`] invokes after a provider
//! completion, and that tests bind to directly (AC5). It replaces today's
//! silent drop of every model-emitted `computer_call` / native `tool_use`
//! item.
//!
//! # Contract
//!
//! - If no opened coordinator / no `native_computer` config is present, the
//!   function returns an empty vec — no items are expected because the tool
//!   was not advertised. The turn must not crash (edge case in the prompt).
//! - Otherwise, extract raw provider computer items, execute each on the
//!   opened coordinator via [`NativeComputerLiveLoop`], and return
//!   continuations for injection into the next provider request assembly.
//!
//! Extraction uses the provider's raw Responses / Anthropic content arrays
//! — not Rig `AssistantContent::ToolCall` JSON reinterpretation. Generic
//! Rig function-tool dispatch refuses reserved native computer tool names
//! via [`crate::computer::is_reserved_native_computer_tool_name`].

use crate::computer::ComputerToolContract;
use crate::computer::coordinator::{ComputerActionCoordinator, NativeComputerContinuation};
use crate::computer::live_loop::NativeComputerLiveLoop;
use crate::computer::{ComputerError, DisplayTarget};
use crate::engine::agent::Agent;
use crate::session::Session;
use futures::future::BoxFuture;
use std::sync::Arc;

pub(crate) fn computer_backend_open_remediation(
    target: DisplayTarget,
    error: &ComputerError,
) -> &'static str {
    match error {
        ComputerError::MissingTool { .. } => {
            #[cfg(target_os = "linux")]
            {
                "Install the missing host tools listed above on this Linux host"
            }
            #[cfg(target_os = "macos")]
            {
                "Install the missing host tools listed above on this Mac"
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                "Install the missing host tools listed above on this host"
            }
        }
        ComputerError::UnsupportedPlatform { .. } => match target {
            DisplayTarget::Virtual => {
                "The isolated virtual display is supported on Linux only; use a Linux host or explicitly opt into real-desktop control with a machine grant"
            }
            DisplayTarget::RealDesktop => {
                "Real desktop control is unavailable on this platform or session; set `computer_target` to `virtual` for the isolated display or use a supported desktop session"
            }
        },
        ComputerError::RealDesktopGrantMissing => {
            "Real desktop control requires a stored machine-local grant for this host"
        }
        ComputerError::CommandFailed { .. } => match target {
            DisplayTarget::Virtual => {
                "Resolve the host setup error above (Cockpit data directory permissions, capture workspace, or virtual display startup)"
            }
            DisplayTarget::RealDesktop => {
                "Resolve the host setup error above (Cockpit data directory permissions, input-state journal, or display session)"
            }
        },
        ComputerError::InvalidCoordinates(_) => {
            "The computer backend reported invalid coordinates during setup; see the error above"
        }
        ComputerError::Refused(_) => "The computer backend refused to open; see the error above",
        ComputerError::Cancelled => "The computer backend open was cancelled; retry the session",
    }
}

/// Open a selected delegation's native-computer capability before its first
/// advertised request. This is shared by foreground and noninteractive
/// delegation loops so neither can advertise geometry before the coordinator
/// owns the backend.
pub(crate) async fn open_native_computer_for_delegation(
    agent: &mut Agent,
    session: &Arc<Session>,
    approver: Option<Arc<crate::approval::Approver>>,
    delegation_id: String,
) -> anyhow::Result<Option<ComputerActionCoordinator>> {
    let Some(candidate) = agent.params.native_computer.clone() else {
        return Ok(None);
    };
    if !agent
        .model
        .supports_native_computer_contract(candidate.contract)
    {
        if candidate.require_backend {
            anyhow::bail!(
                "Computer primary model no longer supports its native computer_use contract"
            );
        }
        return Ok(None);
    }
    let Some(approver) = approver else {
        agent.params.native_computer = None;
        if candidate.require_backend {
            anyhow::bail!("Computer primary requires the session approval service");
        }
        return Ok(None);
    };
    let grant_store = if candidate.target == crate::computer::DisplayTarget::RealDesktop {
        Some(crate::computer::RealDesktopGrantStore::for_cockpit_data_dir()?)
    } else {
        None
    };
    let backend_result = crate::computer::coordinator::construct_platform_backend(
        candidate.target,
        grant_store.as_ref(),
    );
    let backend = match backend_result {
        Ok(backend) => backend,
        Err(error) => {
            tracing::warn!(error = %error, "native computer backend open failed");
            agent.params.native_computer = None;
            if candidate.require_backend {
                let remediation = computer_backend_open_remediation(candidate.target, &error);
                anyhow::bail!(
                    "Computer primary could not open its {} backend: {error}. {remediation}",
                    match candidate.target {
                        crate::computer::DisplayTarget::Virtual => "virtual-display",
                        crate::computer::DisplayTarget::RealDesktop => "real-desktop",
                    }
                );
            }
            return Ok(None);
        }
    };
    let owner_instance = crate::computer::coordinator::OwnerInstance(u64::from(std::process::id()));
    let (target_adapter, host_arbiter) = match candidate.target {
        crate::computer::DisplayTarget::Virtual => {
            let display_id = *uuid::Uuid::new_v4().as_bytes();
            let adapter = {
                #[cfg(target_os = "linux")]
                {
                    match backend.x11_display_name() {
                        Some(display) => {
                            crate::computer::coordinator::VirtualTargetEvidenceAdapter::with_x11_display(
                                display_id,
                                display.to_string(),
                            )
                        }
                        None => crate::computer::coordinator::VirtualTargetEvidenceAdapter::new(
                            display_id,
                        ),
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    crate::computer::coordinator::VirtualTargetEvidenceAdapter::new(display_id)
                }
            };
            (
                Box::new(adapter) as Box<dyn crate::computer::target::TargetEvidenceAdapter>,
                None,
            )
        }
        crate::computer::DisplayTarget::RealDesktop => {
            #[cfg(target_os = "linux")]
            {
                let display = backend.real_x11_display().ok_or_else(|| {
                    anyhow::anyhow!("real desktop backend did not expose an X11 display")
                })?;
                let adapter = crate::computer::platform::X11TargetEvidenceAdapter::new(display)
                    .map_err(|reason| {
                        anyhow::anyhow!("real desktop target evidence unavailable: {reason:?}")
                    })?;
                let file_lock = crate::computer::coordinator::FileAdvisoryLock::new()
                    .map_err(|error| anyhow::anyhow!("host input arbiter unavailable: {error}"))?;
                (
                    Box::new(adapter) as Box<dyn crate::computer::target::TargetEvidenceAdapter>,
                    Some(Arc::new(std::sync::Mutex::new(
                        crate::computer::coordinator::HostInputArbiter::new(
                            Box::new(file_lock),
                            owner_instance,
                        ),
                    ))),
                )
            }
            #[cfg(target_os = "windows")]
            {
                let adapter = crate::computer::platform::WindowsTargetEvidenceAdapter::new()
                    .map_err(|reason| {
                        anyhow::anyhow!("real desktop target evidence unavailable: {reason:?}")
                    })?;
                let file_lock = crate::computer::coordinator::FileAdvisoryLock::new()
                    .map_err(|error| anyhow::anyhow!("host input arbiter unavailable: {error}"))?;
                (
                    Box::new(adapter) as Box<dyn crate::computer::target::TargetEvidenceAdapter>,
                    Some(Arc::new(std::sync::Mutex::new(
                        crate::computer::coordinator::HostInputArbiter::new(
                            Box::new(file_lock),
                            owner_instance,
                        ),
                    ))),
                )
            }
            #[cfg(target_os = "macos")]
            {
                let adapter = crate::computer::platform::MacOsTargetEvidenceAdapter::new()
                    .map_err(|reason| {
                        anyhow::anyhow!("real desktop target evidence unavailable: {reason:?}")
                    })?;
                let file_lock = crate::computer::coordinator::FileAdvisoryLock::new()
                    .map_err(|error| anyhow::anyhow!("host input arbiter unavailable: {error}"))?;
                (
                    Box::new(adapter) as Box<dyn crate::computer::target::TargetEvidenceAdapter>,
                    Some(Arc::new(std::sync::Mutex::new(
                        crate::computer::coordinator::HostInputArbiter::new(
                            Box::new(file_lock),
                            owner_instance,
                        ),
                    ))),
                )
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
            {
                unreachable!("unsupported real desktop construction fails closed")
            }
        }
    };
    let handoff_journal = session.external_journal().map(|journal| {
        Arc::new(crate::computer::coordinator::ExternalJournalHandoff::new(
            journal,
            crate::external_journal::projection::SafeToken::for_session(session.id),
        )) as Arc<dyn crate::computer::coordinator::HandoffJournal>
    });
    let params = crate::computer::coordinator::CoordinatorParams {
        session_id: session.id.hyphenated().to_string(),
        delegation_id: crate::computer::coordinator::DelegationId(delegation_id),
        tier: if candidate.target == crate::computer::DisplayTarget::RealDesktop
            || candidate.approval_required
        {
            crate::computer::coordinator::ComputerApprovalTier::Ask
        } else {
            crate::computer::coordinator::ComputerApprovalTier::Yolo
        },
        owner_instance,
        authorizer: Arc::new(
            crate::computer::authorizer::ApproverComputerAuthorizer::new(approver),
        ),
        host_arbiter,
        target_adapter: Some(target_adapter),
        provider_id: crate::computer::coordinator::ProviderId(
            agent.model.provider_id().to_string(),
        ),
        model_id: crate::computer::coordinator::ModelId(agent.model.model_id_ref().to_string()),
        outcome_store: Some(Arc::new(
            crate::computer::outcome_store::SqliteOutcomeStore::new(session.db.clone()),
        )),
        handoff_journal,
        audit_chain: None, // TODO(#374): wire daemon `ComputerAuditChain` for production re-proof receipts.
    };
    match ComputerActionCoordinator::open(backend, params).await {
        Ok(coordinator) => {
            // Keep capability metadata only. Opened geometry is request-scoped:
            // the live-loop overlay copies it onto a turn-local agent so
            // compact / shrink / warm-resolver clones of long-lived params
            // cannot re-advertise the tool.
            agent.params.native_computer = Some(crate::computer::NativeComputerToolConfig {
                geometry: None,
                ..candidate
            });
            Ok(Some(coordinator))
        }
        Err(error) => {
            tracing::warn!(error = %error, "native computer coordinator open failed");
            agent.params.native_computer = None;
            if candidate.require_backend {
                anyhow::bail!("Computer primary could not open its action coordinator: {error}");
            }
            Ok(None)
        }
    }
}

/// Reconcile the live coordinator with the agent's *current* wire and policy
/// boundary at every turn boundary. Endpoint fallback can change an OpenAI
/// model from Responses to Chat Completions after a coordinator was opened;
/// a live rebuild can also change its target, backend requirement, or approval
/// policy. Retaining a coordinator across either change would make the next
/// request invalid or bypass the rebuilt policy. Both foreground and
/// noninteractive loops use this one lifecycle rule.
pub(crate) async fn reconcile_native_computer_for_delegation(
    agent: &mut Agent,
    session: &Arc<Session>,
    approver: Option<Arc<crate::approval::Approver>>,
    delegation_id: String,
    coordinator: &mut Option<ComputerActionCoordinator>,
    contract: &mut Option<ComputerToolContract>,
    coordinator_config: &mut Option<crate::computer::NativeComputerCoordinatorConfig>,
    pending_continuations: &mut Vec<serde_json::Value>,
    sticky_ask_denial: &mut Option<String>,
) -> anyhow::Result<()> {
    let session = Arc::clone(session);
    reconcile_native_computer_for_delegation_with_opener(
        agent,
        coordinator,
        contract,
        coordinator_config,
        pending_continuations,
        sticky_ask_denial,
        &mut move |agent| {
            let session = Arc::clone(&session);
            let approver = approver.clone();
            let delegation_id = delegation_id.clone();
            Box::pin(async move {
                open_native_computer_for_delegation(agent, &session, approver, delegation_id).await
            })
        },
    )
    .await
}

/// Reconcile the live coordinator through the supplied opener.
///
/// Keeping the lifecycle transition separate from concrete backend construction
/// lets its regression tests prove that every policy-boundary change closes,
/// clears, and reopens the coordinator without depending on host desktop
/// tooling. Production always supplies [`open_native_computer_for_delegation`]
/// through [`reconcile_native_computer_for_delegation`].
async fn reconcile_native_computer_for_delegation_with_opener(
    agent: &mut Agent,
    coordinator: &mut Option<ComputerActionCoordinator>,
    contract: &mut Option<ComputerToolContract>,
    coordinator_config: &mut Option<crate::computer::NativeComputerCoordinatorConfig>,
    pending_continuations: &mut Vec<serde_json::Value>,
    sticky_ask_denial: &mut Option<String>,
    opener: &mut impl for<'a> FnMut(
        &'a mut Agent,
    )
        -> BoxFuture<'a, anyhow::Result<Option<ComputerActionCoordinator>>>,
) -> anyhow::Result<()> {
    let current_config = agent
        .params
        .native_computer
        .as_ref()
        .map(crate::computer::NativeComputerToolConfig::coordinator_config);
    let retained_is_compatible = matches!(
        (
            coordinator.as_ref(),
            *contract,
            *coordinator_config,
            current_config,
        ),
        (Some(_), Some(contract), Some(opened_config), Some(current_config))
            if contract == opened_config.contract
                && agent.model.supports_native_computer_contract(contract)
                && opened_config == current_config
    );
    if retained_is_compatible {
        return Ok(());
    }

    // Ask denial is a delegation-lifetime fact. Capture it into the driver
    // slot before `take`/`close`/`Drop` so a failed or deferred replacement
    // still inherits it when a later reconciliation opens a successor.
    // Installed leases and pending waits die with `close` (fail-closed: the
    // next action re-prompts unless this sticky denial forbids it).
    if let Some(reason) = coordinator
        .as_ref()
        .and_then(ComputerActionCoordinator::terminal_denial)
    {
        *sticky_ask_denial = Some(reason.to_string());
    }

    if let Some(mut previous) = coordinator.take() {
        *contract = None;
        *coordinator_config = None;
        pending_continuations.clear();
        if let Some(candidate) = agent.params.native_computer.as_mut() {
            // Geometry describes a live, contract-specific coordinator. Keep
            // only the capability metadata until a compatible backend reopens.
            candidate.geometry = None;
        }
        if let Err(error) = previous.close().await {
            // The incompatible coordinator is never retained after an endpoint
            // fallback. Its backend has already been removed from scheduling;
            // report a best-effort resource-release failure without reviving
            // a capability whose wire contract no longer matches.
            tracing::warn!(error = %error, "closing incompatible native computer coordinator failed");
        }
    } else if contract.take().is_some() || coordinator_config.take().is_some() {
        // Preserve the same invariant even if a prior open failed halfway
        // through a driver-frame update: no contract/geometry/continuation is
        // retained without its matching coordinator.
        pending_continuations.clear();
        if let Some(candidate) = agent.params.native_computer.as_mut() {
            candidate.geometry = None;
        }
    }

    let Some(candidate) = agent.params.native_computer.as_ref() else {
        return Ok(());
    };
    if !agent
        .model
        .supports_native_computer_contract(candidate.contract)
    {
        if candidate.require_backend {
            anyhow::bail!(
                "Computer primary model does not support its required native computer_use contract"
            );
        }
        return Ok(());
    }

    let opened = opener(agent).await?;
    if let Some(mut opened) = opened {
        if let Some(reason) = sticky_ask_denial.clone() {
            opened.inherit_terminal_denial(reason);
        }
        let opened_config = agent
            .params
            .native_computer
            .as_ref()
            .map(crate::computer::NativeComputerToolConfig::coordinator_config)
            .ok_or_else(|| {
                anyhow::anyhow!("native computer coordinator opened without configuration")
            })?;
        *contract = Some(opened_config.contract);
        *coordinator_config = Some(opened_config);
        *coordinator = Some(opened);
    }
    Ok(())
}

/// Overlay opened backend geometry onto a request-local agent clone.
///
/// Long-lived agent params keep `geometry: None` after a successful
/// open. Only the coordinator-backed live-loop turn receives this overlay,
/// so compact / shrink / warm-resolver completions that clone the frame
/// agent cannot declare native `computer` / `computer_call` on the wire.
pub(crate) fn with_live_loop_native_computer_geometry(
    mut agent: Agent,
    coordinator: Option<&ComputerActionCoordinator>,
) -> Agent {
    let Some(coordinator) = coordinator else {
        return agent;
    };
    if let Some(config) = agent.params.native_computer.as_mut() {
        config.geometry = Some(coordinator.geometry().clone());
    }
    agent
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuidanceProposalCandidate {
    pub rules: Vec<crate::computer::guidance::ComputerGuidanceRuleV1>,
    pub rationale: Option<String>,
}

/// Extract the single closed typed proposal item allowed beside native
/// computer calls. All scope and identity fields are deliberately absent.
pub fn extract_guidance_proposal_candidate(
    raw_output: &[serde_json::Value],
) -> anyhow::Result<Option<GuidanceProposalCandidate>> {
    let mut candidate = None;
    for item in raw_output {
        if item.get("type").and_then(serde_json::Value::as_str)
            != Some("computer_guidance_proposal")
        {
            continue;
        }
        if candidate.is_some() {
            anyhow::bail!("multiple computer guidance proposals in one response");
        }
        let object = item
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("guidance proposal must be an object"))?;
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "type" | "rules" | "rationale"))
        {
            anyhow::bail!("computer guidance proposal contains an unknown field");
        }
        let values = object
            .get("rules")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("guidance proposal rules must be an array"))?;
        let rules = values
            .iter()
            .map(|value| {
                let bytes = value
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("guidance rule must be a three-byte array"))?;
                if bytes.len() != 3 {
                    anyhow::bail!("guidance rule must contain exactly three bytes");
                }
                let mut encoded = [0_u8; 3];
                for (target, value) in encoded.iter_mut().zip(bytes) {
                    *target = value
                        .as_u64()
                        .filter(|value| *value <= u8::MAX as u64)
                        .ok_or_else(|| anyhow::anyhow!("guidance rule bytes must be u8 values"))?
                        as u8;
                }
                crate::computer::guidance::ComputerGuidanceRuleV1::decode(&encoded)
                    .map_err(Into::into)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let rationale = match object.get("rationale") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("guidance rationale must be text"))?
                    .to_owned(),
            ),
        };
        candidate = Some(GuidanceProposalCandidate { rules, rationale });
    }
    Ok(candidate)
}

/// Route the provider's identity-free proposal item through the daemon-owned
/// lifecycle. The returned stable, content-free status belongs in ordinary
/// history; it must never be represented as a provider tool result because the
/// proposal item has no provider-issued call id.
pub(crate) async fn retain_guidance_proposal_candidate(
    raw_output: &[serde_json::Value],
    service: Option<
        &std::sync::Arc<
            tokio::sync::Mutex<crate::computer::guidance::service::GuidanceProposalService>,
        >,
    >,
    snapshot: Option<crate::computer::guidance::service::GuidanceCreateSnapshot>,
    session_id: [u8; 16],
    delegation_id: &str,
) -> Option<&'static str> {
    let candidate = match extract_guidance_proposal_candidate(raw_output) {
        Ok(Some(candidate)) => candidate,
        Ok(None) => return None,
        Err(error) => {
            tracing::warn!(%error, "invalid computer guidance proposal denied");
            return Some("proposal_invalid");
        }
    };
    let result = async {
        let service =
            service.ok_or_else(|| anyhow::anyhow!("guidance proposal service unavailable"))?;
        let snapshot = snapshot
            .ok_or_else(|| anyhow::anyhow!("guidance proposal config snapshot unavailable"))?;
        let delegation_id = uuid::Uuid::parse_str(delegation_id)
            .map_err(|_| anyhow::anyhow!("computer delegation lacks a UUID authority binding"))?;
        service
            .lock()
            .await
            .create_proposal(
                snapshot,
                session_id,
                *delegation_id.as_bytes(),
                *uuid::Uuid::new_v4().as_bytes(),
                candidate.rules,
                candidate.rationale,
                chrono::Utc::now().timestamp_millis(),
            )
            .await
            .map_err(anyhow::Error::from)
    }
    .await;
    match result {
        Ok(()) => Some("proposal_created"),
        Err(error) => {
            tracing::warn!(%error, "computer guidance proposal denied");
            Some(
                error
                    .downcast_ref::<crate::computer::guidance::service::CreateProposalError>()
                    .map_or("proposal_unavailable", |error| error.wire_reason()),
            )
        }
    }
}

/// Expire pending proposals for the computer-delegation UUID create stored
/// (`coordinator.delegation_id` = hyphenated `agent_instance_id`).
pub(crate) async fn invalidate_guidance_for_delegation(
    service: Option<
        &std::sync::Arc<
            tokio::sync::Mutex<crate::computer::guidance::service::GuidanceProposalService>,
        >,
    >,
    delegation_id: uuid::Uuid,
) {
    let Some(service) = service else {
        return;
    };
    let now = chrono::Utc::now().timestamp_millis();
    if let Err(error) = service
        .lock()
        .await
        .invalidate(
            |scope| scope.delegation_id == *delegation_id.as_bytes(),
            now,
        )
        .await
    {
        tracing::warn!(%error, %delegation_id, "guidance delegation invalidation deferred");
    }
}

/// Abort-safe invalidation for a noninteractive executor: Drop (including
/// `JoinHandle::abort`) still presents the same UUID create stored.
pub(crate) struct GuidanceDelegationDropGuard {
    service: Option<
        std::sync::Arc<
            tokio::sync::Mutex<crate::computer::guidance::service::GuidanceProposalService>,
        >,
    >,
    delegation_id: uuid::Uuid,
}

impl GuidanceDelegationDropGuard {
    pub(crate) fn new(
        service: Option<
            std::sync::Arc<
                tokio::sync::Mutex<crate::computer::guidance::service::GuidanceProposalService>,
            >,
        >,
        delegation_id: uuid::Uuid,
    ) -> Self {
        Self {
            service,
            delegation_id,
        }
    }
}

impl Drop for GuidanceDelegationDropGuard {
    fn drop(&mut self) {
        let Some(service) = self.service.take() else {
            return;
        };
        let delegation_id = self.delegation_id;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                invalidate_guidance_for_delegation(Some(&service), delegation_id).await;
            });
        }
    }
}

/// Handle native computer items from a provider completion.
///
/// This is the named production driver registration function (AC5). Both the
/// real `run_user_input` / tool-result path and tests invoke this same
/// symbol.
///
/// - If `coordinator` is `None` (no opened coordinator / tool not
///   advertised), returns an empty vec — no items are expected.
/// - Otherwise, extracts raw provider computer items using `contract`,
///   executes each on the coordinator, and returns continuations for
///   injection into the next provider request.
///
/// The continuations carry transient screenshots (from the live frame)
/// only in the wire payload; the coordinator journals only sanitized
/// `CoordinatedOutcome` values (AC6).
pub async fn handle_native_computer_items(
    coordinator: Option<&mut ComputerActionCoordinator>,
    contract: ComputerToolContract,
    raw_output: &[serde_json::Value],
) -> Vec<NativeComputerContinuation> {
    let Some(coordinator) = coordinator else {
        // No opened coordinator — tool was not advertised. No items are
        // expected; return empty without crashing the turn.
        return Vec::new();
    };
    let mut live_loop = NativeComputerLiveLoop::new(coordinator, contract);
    live_loop.handle_native_computer_items(raw_output).await
}

/// Build the short-lived provider wire items after executing retained raw
/// provider actions. Both provider-native action and result are retained only
/// for the one following request.
pub(crate) async fn handle_retained_native_computer_items(
    coordinator: &mut ComputerActionCoordinator,
    contract: ComputerToolContract,
    raw_items: Vec<serde_json::Value>,
    session: &Arc<Session>,
    approver: Option<&Arc<crate::approval::Approver>>,
) -> Vec<serde_json::Value> {
    if raw_items.is_empty() {
        return Vec::new();
    }
    let accounting = match crate::assistants::identity::check_identity_opaque_session_effect(
        session,
        approver,
        "delegated native computer actions",
    )
    .await
    {
        Ok(accounting) => crate::assistants::identity::IdentityAccountingGuard::new(accounting),
        Err(error) => {
            tracing::warn!(%error, "delegated native computer actions denied by assistant identity policy");
            return Vec::new();
        }
    };
    let continuations = handle_native_computer_items(Some(coordinator), contract, &raw_items).await;
    if let Err(error) = accounting.publish().await {
        tracing::error!(%error, "delegated native computer identity accounting failed");
        return Vec::new();
    }
    if continuations.is_empty() {
        return Vec::new();
    }
    let mut wire = raw_items
        .into_iter()
        .filter(|item| {
            item.get("call_id")
                .or_else(|| item.get("id"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|id| !id.is_empty())
        })
        .collect::<Vec<_>>();
    wire.extend(into_wire_items(continuations));
    wire
}

/// Consume transient continuations into the exact provider-native items that
/// may live only until the immediately-following HTTP request is assembled.
pub fn into_wire_items(continuations: Vec<NativeComputerContinuation>) -> Vec<serde_json::Value> {
    continuations
        .into_iter()
        .filter_map(|continuation| match continuation {
            NativeComputerContinuation::OpenAi { call_id, transient } => transient.map_or_else(
                || {
                    Some(serde_json::json!({
                        "type": "computer_call_output",
                        "call_id": call_id,
                        "output": { "type": "text", "text": "screenshot unavailable" }
                    }))
                },
                |transient| Some(transient.with_wire(Clone::clone).0),
            ),
            NativeComputerContinuation::Anthropic {
                tool_use_id,
                transient,
                ..
            } => transient.map_or_else(
                || {
                    Some(serde_json::json!({
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": [{"type": "text", "text": "screenshot unavailable"}]
                    }))
                },
                |transient| Some(transient.with_wire(Clone::clone).0),
            ),
            NativeComputerContinuation::Unsupported { wire_payload, .. } => wire_payload,
            NativeComputerContinuation::TextOnly {
                call_id,
                text,
                provider,
            } => match provider {
                crate::computer::coordinator::NativeProvider::OpenAi => Some(serde_json::json!({
                    "type": "computer_call_output",
                    "call_id": call_id,
                    "output": { "type": "text", "text": text }
                })),
                _ => Some(serde_json::json!({
                    "type": "tool_result",
                    "tool_use_id": call_id,
                    "content": [{"type": "text", "text": text}]
                })),
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::computer::coordinator::{
        ComputerApprovalTier, ComputerAuthorizer, CoordinatedOutcome, CoordinatorParams,
        DelegationId, FakeComputerAuthorizer, ModelId, NativeComputerContinuation, OwnerInstance,
        ProviderId,
    };
    use crate::computer::target::{
        EvidenceSource, FakeTargetEvidenceAdapter, FieldEvidence, OpaqueWindowId,
        sample_virtual_evidence,
    };
    use crate::computer::{
        ComputerActionOutcome, ComputerBackend, ComputerToolContract, DisplayGeometry,
        DisplayTarget, LogicalSize, NativeComputerCoordinatorConfig, NativeComputerToolConfig,
        NormalizedComputerAction, NormalizedComputerEffect, OpenAiComputerAction, PixelSize,
        ScaleFactor,
    };
    use async_trait::async_trait;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn computer_backend_open_remediation_is_error_kind_aware() {
        let missing_tool = ComputerError::MissingTool {
            tool: "Xvfb".to_string(),
            install_hint: "the `xvfb` package".to_string(),
        };
        let virtual_missing_hint =
            computer_backend_open_remediation(DisplayTarget::Virtual, &missing_tool);
        assert!(virtual_missing_hint.contains("Install the missing host tools"));
        assert!(!virtual_missing_hint.contains("computer_target"));
        #[cfg(target_os = "linux")]
        assert!(virtual_missing_hint.contains("Linux host"));
        #[cfg(target_os = "macos")]
        assert!(virtual_missing_hint.contains("this Mac"));
        #[cfg(target_os = "macos")]
        assert!(!virtual_missing_hint.contains("Linux"));

        let real_desktop_missing_tool = ComputerError::MissingTool {
            tool: "xdotool".to_string(),
            install_hint: "the `xdotool` package".to_string(),
        };
        let real_desktop_missing_hint = computer_backend_open_remediation(
            DisplayTarget::RealDesktop,
            &real_desktop_missing_tool,
        );
        assert!(real_desktop_missing_hint.contains("Install the missing host tools"));
        assert!(!real_desktop_missing_hint.contains("machine grant"));
        #[cfg(target_os = "linux")]
        assert!(real_desktop_missing_hint.contains("Linux host"));
        #[cfg(target_os = "macos")]
        {
            let screencapture_missing = ComputerError::MissingTool {
                tool: "/usr/sbin/screencapture".to_string(),
                install_hint: "the system macOS screencapture utility".to_string(),
            };
            let mac_hint = computer_backend_open_remediation(
                DisplayTarget::RealDesktop,
                &screencapture_missing,
            );
            assert!(mac_hint.contains("this Mac"));
            assert!(!mac_hint.contains("Linux"));
        }

        let command_failed = ComputerError::CommandFailed {
            program: "Xvfb".to_string(),
            detail: "Permission denied".to_string(),
        };
        let virtual_command_hint =
            computer_backend_open_remediation(DisplayTarget::Virtual, &command_failed);
        assert!(virtual_command_hint.contains("Resolve the host setup error"));
        assert!(!virtual_command_hint.contains("Xvfb"));
        assert!(!virtual_command_hint.contains("Install"));

        let unsupported = ComputerError::UnsupportedPlatform {
            platform: "linux".to_string(),
        };
        assert!(
            computer_backend_open_remediation(DisplayTarget::Virtual, &unsupported)
                .contains("Linux only")
        );
        assert!(
            computer_backend_open_remediation(
                DisplayTarget::RealDesktop,
                &ComputerError::RealDesktopGrantMissing
            )
            .contains("machine-local grant")
        );
        assert!(
            computer_backend_open_remediation(DisplayTarget::RealDesktop, &unsupported)
                .contains("computer_target")
        );
    }

    /// A fake backend that yields a successful capture frame.
    struct CapturingFakeBackend {
        geometry: DisplayGeometry,
    }

    impl CapturingFakeBackend {
        fn new() -> Self {
            Self {
                geometry: DisplayGeometry {
                    physical: PixelSize {
                        width: 1024,
                        height: 768,
                    },
                    logical: LogicalSize {
                        width: 1024.0,
                        height: 768.0,
                    },
                    scale_factor: ScaleFactor(1.0),
                },
            }
        }
    }

    #[async_trait]
    impl ComputerBackend for CapturingFakeBackend {
        fn backend_kind(&self) -> crate::computer::target::BackendKind {
            crate::computer::target::BackendKind::VirtualDisplay
        }
        async fn geometry(&mut self) -> Result<DisplayGeometry, crate::computer::ComputerError> {
            Ok(self.geometry.clone())
        }

        async fn execute_normalized_one(
            &mut self,
            action: &NormalizedComputerAction,
        ) -> Result<ComputerActionOutcome, crate::computer::ComputerError> {
            if matches!(action.effect(), NormalizedComputerEffect::CaptureFull) {
                Ok(ComputerActionOutcome::Captured(
                    crate::computer::CaptureFrame {
                        png: vec![0x89, 0x50, 0x4e, 0x47],
                        geometry: self.geometry.clone(),
                        region: None,
                        native_zoom: None,
                    },
                ))
            } else {
                Ok(ComputerActionOutcome::Completed)
            }
        }

        fn release_all(&mut self) -> Result<(), crate::computer::ComputerError> {
            Ok(())
        }
    }

    /// Records coordinator closure by counting `release_all`, which is the
    /// concrete backend-lifetime release performed by `close`.
    struct ReleaseCountingFakeBackend {
        inner: CapturingFakeBackend,
        releases: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ComputerBackend for ReleaseCountingFakeBackend {
        fn backend_kind(&self) -> crate::computer::target::BackendKind {
            self.inner.backend_kind()
        }

        async fn geometry(&mut self) -> Result<DisplayGeometry, crate::computer::ComputerError> {
            self.inner.geometry().await
        }

        async fn execute_normalized_one(
            &mut self,
            action: &NormalizedComputerAction,
        ) -> Result<ComputerActionOutcome, crate::computer::ComputerError> {
            self.inner.execute_normalized_one(action).await
        }

        fn release_all(&mut self) -> Result<(), crate::computer::ComputerError> {
            self.releases.fetch_add(1, Ordering::SeqCst);
            self.inner.release_all()
        }
    }

    fn virtual_window_evidence() -> crate::computer::target::TargetIdentityEvidence {
        let mut evidence = sample_virtual_evidence([0xAA; 16], 1);
        evidence.focus_generation = 1;
        evidence.focused_window_id = FieldEvidence::available(
            OpaqueWindowId::from_bytes([0x11; 16]),
            EvidenceSource::InjectedTest,
        );
        evidence
    }

    fn yolo_params(authorizer: Arc<dyn ComputerAuthorizer>) -> CoordinatorParams {
        CoordinatorParams {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            tier: ComputerApprovalTier::Yolo,
            owner_instance: OwnerInstance(1),
            authorizer,
            host_arbiter: None,
            target_adapter: Some(Box::new(FakeTargetEvidenceAdapter::new(
                virtual_window_evidence(),
            ))),
            provider_id: ProviderId("openai".to_string()),
            model_id: ModelId("gpt-4o".to_string()),
            outcome_store: None,
            handoff_journal: None,
            audit_chain: None,
        }
    }

    async fn make_coordinator() -> ComputerActionCoordinator {
        let authorizer: Arc<dyn ComputerAuthorizer> =
            Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = Box::new(CapturingFakeBackend::new());
        ComputerActionCoordinator::open(backend, yolo_params(authorizer))
            .await
            .expect("coordinator open")
    }

    async fn make_release_counting_coordinator(
        releases: Arc<AtomicUsize>,
    ) -> ComputerActionCoordinator {
        let authorizer: Arc<dyn ComputerAuthorizer> =
            Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = Box::new(ReleaseCountingFakeBackend {
            inner: CapturingFakeBackend::new(),
            releases,
        });
        ComputerActionCoordinator::open(backend, yolo_params(authorizer))
            .await
            .expect("coordinator open")
    }

    fn open_release_counting_coordinator<'a>(
        _agent: &'a mut Agent,
        opens: Arc<AtomicUsize>,
        releases: Arc<AtomicUsize>,
    ) -> BoxFuture<'a, anyhow::Result<Option<ComputerActionCoordinator>>> {
        Box::pin(async move {
            opens.fetch_add(1, Ordering::SeqCst);
            Ok(Some(make_release_counting_coordinator(releases).await))
        })
    }

    async fn make_ask_test_coordinator(
        authorizer: Arc<FakeComputerAuthorizer>,
    ) -> ComputerActionCoordinator {
        let mut evidence = crate::computer::target::sample_virtual_evidence([0xAA; 16], 1);
        evidence.focus_generation = 1;
        let params = CoordinatorParams {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            tier: ComputerApprovalTier::Ask,
            owner_instance: OwnerInstance(1),
            authorizer,
            host_arbiter: None,
            target_adapter: Some(Box::new(
                crate::computer::target::FakeTargetEvidenceAdapter::new(evidence),
            )),
            provider_id: ProviderId("openai".to_string()),
            model_id: ModelId("gpt-4o".to_string()),
            outcome_store: None,
            handoff_journal: None,
            audit_chain: None,
        };
        ComputerActionCoordinator::open(Box::new(CapturingFakeBackend::new()), params)
            .await
            .expect("ask coordinator open")
    }

    fn panicking_opener<'a>(
        _agent: &'a mut Agent,
    ) -> BoxFuture<'a, anyhow::Result<Option<ComputerActionCoordinator>>> {
        Box::pin(async {
            panic!("opener must not run when replacement is deferred before backend construction")
        })
    }

    fn none_opener<'a>(
        _agent: &'a mut Agent,
    ) -> BoxFuture<'a, anyhow::Result<Option<ComputerActionCoordinator>>> {
        Box::pin(async { Ok(None) })
    }

    fn error_opener<'a>(
        _agent: &'a mut Agent,
    ) -> BoxFuture<'a, anyhow::Result<Option<ComputerActionCoordinator>>> {
        Box::pin(async { anyhow::bail!("backend unavailable") })
    }

    fn open_ask_test_coordinator<'a>(
        _agent: &'a mut Agent,
        authorizer: Arc<FakeComputerAuthorizer>,
        opens: Arc<AtomicUsize>,
    ) -> BoxFuture<'a, anyhow::Result<Option<ComputerActionCoordinator>>> {
        Box::pin(async move {
            opens.fetch_add(1, Ordering::SeqCst);
            Ok(Some(make_ask_test_coordinator(authorizer).await))
        })
    }

    /// AC5: call the named production driver registration function. Fixture
    /// raw provider output → extract → fake coordinator → continuation
    /// injection.
    #[tokio::test]
    async fn computer_live_rig_seam_openai() {
        let mut coordinator = make_coordinator().await;
        let output = vec![serde_json::json!({
            "type": "computer_call",
            "call_id": "call-1",
            "action": {"type": "move", "x": 4.0, "y": 5.0}
        })];

        let continuations = handle_native_computer_items(
            Some(&mut coordinator),
            ComputerToolContract::OpenAiResponses,
            &output,
        )
        .await;
        assert_eq!(continuations.len(), 1);
        assert!(matches!(
            &continuations[0],
            NativeComputerContinuation::OpenAi { .. }
        ));
    }

    /// AC5: no coordinator (tool not advertised) → empty vec, no crash.
    #[tokio::test]
    async fn computer_live_rig_seam_no_coordinator() {
        let output = vec![serde_json::json!({
            "type": "computer_call",
            "call_id": "call-1",
            "action": {"type": "move", "x": 4.0, "y": 5.0}
        })];

        let continuations =
            handle_native_computer_items(None, ComputerToolContract::OpenAiResponses, &output)
                .await;
        assert!(continuations.is_empty());
    }

    /// AC5: Anthropic variant through the driver seam.
    #[tokio::test]
    async fn computer_live_rig_seam_anthropic() {
        let mut coordinator = make_coordinator().await;
        let content = vec![serde_json::json!({
            "type": "tool_use",
            "id": "toolu-1",
            "name": "computer",
            "input": {
                "action": "screenshot"
            }
        })];

        let continuations = handle_native_computer_items(
            Some(&mut coordinator),
            ComputerToolContract::Anthropic20251124,
            &content,
        )
        .await;
        assert_eq!(continuations.len(), 1);
        assert!(matches!(
            &continuations[0],
            NativeComputerContinuation::Anthropic { .. }
        ));
    }

    /// AC6: success path builds transient with live frame pixels only in
    /// the wire payload; the coordinator outcome is sanitized-only.
    #[tokio::test]
    async fn computer_live_continuation_has_transient_pixels() {
        let mut coordinator = make_coordinator().await;
        let output = vec![serde_json::json!({
            "type": "computer_call",
            "call_id": "call-1",
            "action": {"type": "move", "x": 4.0, "y": 5.0}
        })];

        // Execute through the driver seam.
        let continuations = handle_native_computer_items(
            Some(&mut coordinator),
            ComputerToolContract::OpenAiResponses,
            &output,
        )
        .await;
        assert_eq!(continuations.len(), 1);

        // With a successful capture, the continuation must carry a transient.
        match &continuations[0] {
            NativeComputerContinuation::OpenAi { transient, .. } => {
                assert!(
                    transient.is_some(),
                    "transient must be Some when live frame is present (AC6)"
                );
            }
            other => panic!("expected OpenAi continuation with transient, got {other:?}"),
        }

        // The live frame was consumed and dropped — take_last_live_frame
        // returns None.
        assert!(
            coordinator.take_last_live_frame().is_none(),
            "live frame must be consumed after continuation assembly"
        );
    }

    #[test]
    fn computer_live_unaddressed_unsupported_output_is_omitted() {
        let wire = into_wire_items(vec![NativeComputerContinuation::Unsupported {
            provider: crate::computer::coordinator::NativeProvider::Anthropic20251124,
            wire_payload: None,
        }]);
        assert!(wire.is_empty());
    }

    #[tokio::test]
    async fn computer_live_unaddressable_call_produces_empty_wire() {
        let mut coordinator = make_coordinator().await;
        let raw_items = vec![serde_json::json!({
            "type": "computer_call",
            "action": {"type": "screenshot"}
        })];
        let wire = into_wire_items(
            handle_native_computer_items(
                Some(&mut coordinator),
                ComputerToolContract::OpenAiResponses,
                &raw_items,
            )
            .await,
        );
        assert!(
            wire.is_empty(),
            "a computer_call with no call_id cannot produce a continuation payload"
        );
    }

    #[tokio::test]
    async fn computer_live_fail_closed_no_advertise_without_coordinator() {
        use crate::engine::agent::Agent;
        use crate::engine::model::{Model, ModelParams};
        use crate::redact::RedactionTable;
        use crate::session::Session;

        let mut cfg = crate::config::providers::ProvidersConfig::default();
        cfg.providers.insert(
            "local".to_string(),
            crate::config::providers::ProviderEntry {
                url: "http://127.0.0.1:9/v1".to_string(),
                wire_api: crate::config::providers::WireApi::Responses,
                ..crate::config::providers::ProviderEntry::default()
            },
        );
        let model = Arc::new(
            Model::for_provider_with_env(
                &cfg,
                "local",
                "test-model",
                Arc::new(RedactionTable::empty()),
                |_| None,
            )
            .expect("test model builds without network"),
        );
        let geometry = DisplayGeometry {
            physical: PixelSize {
                width: 1280,
                height: 720,
            },
            logical: LogicalSize {
                width: 1280.0,
                height: 720.0,
            },
            scale_factor: ScaleFactor(1.0),
        };
        let mut agent = Agent {
            name: "Build".to_string(),
            system: "system".to_string(),
            role_prompt: "system".to_string(),
            tools: crate::engine::tool::ToolBox::new(),
            model,
            params: ModelParams {
                native_computer: Some(crate::computer::NativeComputerToolConfig {
                    contract: ComputerToolContract::OpenAiResponses,
                    target: crate::computer::DisplayTarget::Virtual,
                    require_backend: false,
                    geometry: Some(geometry),
                    approval_required: false,
                }),
                ..ModelParams::default()
            },
            scan_tool_results: false,
            tool_steering: crate::agents::ToolSteering::Terse,
            posture: crate::agents::PostureResolution::standard(),
            context_policy: None,
            lock_identity: "Build".to_string(),
            write_scope: None,
            workspace_lease: None,
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            vnext_grant: None,
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            definition: None,
            assistant_identity_prefix: None,
            mcp_resolver: crate::mcp::resolver::EffectiveCatalogResolver::empty(),
        };
        let tmp = tempfile::tempdir().expect("session root");
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Arc::new(
            Session::create_for_test(
                db,
                tmp.path().to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        let opened =
            open_native_computer_for_delegation(&mut agent, &session, None, "delegation-1".into())
                .await;
        assert!(opened.unwrap().is_none());
        assert!(
            agent.params.native_computer.is_none(),
            "failed open must leave native_computer: None so the tool is not advertised"
        );
    }

    /// A live coordinator is reusable only under the exact policy boundary it
    /// opened with. Each case changes one field at a time and drives the real
    /// reconciliation transition: close the stale backend, clear its wire
    /// continuations, then open a replacement under the new configuration.
    #[tokio::test]
    async fn reconcile_reopens_for_each_native_computer_policy_boundary_change() {
        let initial = NativeComputerToolConfig {
            contract: ComputerToolContract::OpenAiResponses,
            target: DisplayTarget::Virtual,
            require_backend: false,
            geometry: None,
            approval_required: false,
        };
        let cases = [
            (
                "target",
                NativeComputerToolConfig {
                    target: DisplayTarget::RealDesktop,
                    ..initial.clone()
                },
            ),
            (
                "backend requirement",
                NativeComputerToolConfig {
                    require_backend: true,
                    ..initial.clone()
                },
            ),
            (
                "approval policy",
                NativeComputerToolConfig {
                    approval_required: true,
                    ..initial.clone()
                },
            ),
        ];

        for (case, changed) in cases {
            let mut agent = test_agent_with_native_geometry(None);
            agent.params.native_computer = Some(changed.clone());
            let original_releases = Arc::new(AtomicUsize::new(0));
            let reopened_releases = Arc::new(AtomicUsize::new(0));
            let mut coordinator =
                Some(make_release_counting_coordinator(Arc::clone(&original_releases)).await);
            let mut contract = Some(initial.contract);
            let mut coordinator_config = Some(initial.coordinator_config());
            let mut pending_continuations = vec![serde_json::json!({
                "type": "computer_call_output",
                "call_id": "stale-call"
            })];
            let mut sticky_ask_denial = None;
            let opens = Arc::new(AtomicUsize::new(0));
            let mut opener: Box<
                dyn for<'a> FnMut(
                    &'a mut Agent,
                ) -> BoxFuture<
                    'a,
                    anyhow::Result<Option<ComputerActionCoordinator>>,
                >,
            > = {
                let opens = Arc::clone(&opens);
                let reopened_releases = Arc::clone(&reopened_releases);
                Box::new(move |agent| {
                    open_release_counting_coordinator(
                        agent,
                        Arc::clone(&opens),
                        Arc::clone(&reopened_releases),
                    )
                })
            };

            reconcile_native_computer_for_delegation_with_opener(
                &mut agent,
                &mut coordinator,
                &mut contract,
                &mut coordinator_config,
                &mut pending_continuations,
                &mut sticky_ask_denial,
                &mut opener,
            )
            .await
            .expect("a changed policy boundary must reconcile");

            assert_eq!(
                original_releases.load(Ordering::SeqCst),
                1,
                "{case} change must close the stale coordinator"
            );
            assert!(
                pending_continuations.is_empty(),
                "{case} change must clear stale wire continuations"
            );
            assert_eq!(
                opens.load(Ordering::SeqCst),
                1,
                "{case} change must open a replacement coordinator"
            );
            assert!(
                coordinator.is_some(),
                "{case} change must retain the replacement"
            );
            assert_eq!(contract, Some(changed.contract));
            assert_eq!(
                coordinator_config,
                Some(NativeComputerCoordinatorConfig {
                    contract: changed.contract,
                    target: changed.target,
                    require_backend: changed.require_backend,
                    approval_required: changed.approval_required,
                }),
                "{case} change must record its replacement boundary"
            );

            coordinator
                .as_mut()
                .expect("replacement coordinator")
                .close()
                .await
                .expect("replacement coordinator closes");
            assert_eq!(reopened_releases.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn reconcile_inherits_terminal_ask_denial_onto_replacement() {
        let initial = NativeComputerToolConfig {
            contract: ComputerToolContract::OpenAiResponses,
            target: DisplayTarget::Virtual,
            require_backend: false,
            geometry: None,
            approval_required: false,
        };
        let mut agent = test_agent_with_native_geometry(None);
        agent.params.native_computer = Some(NativeComputerToolConfig {
            approval_required: true,
            ..initial.clone()
        });
        let original_releases = Arc::new(AtomicUsize::new(0));
        let reopened_releases = Arc::new(AtomicUsize::new(0));
        let mut coordinator =
            Some(make_release_counting_coordinator(Arc::clone(&original_releases)).await);
        coordinator
            .as_mut()
            .expect("original coordinator")
            .inherit_terminal_denial("policy blocks".to_string());
        let mut contract = Some(initial.contract);
        let mut coordinator_config = Some(initial.coordinator_config());
        let mut pending_continuations = Vec::new();
        let mut sticky_ask_denial = None;
        let opens = Arc::new(AtomicUsize::new(0));
        let mut opener: Box<
            dyn for<'a> FnMut(
                &'a mut Agent,
            )
                -> BoxFuture<'a, anyhow::Result<Option<ComputerActionCoordinator>>>,
        > = Box::new({
            let opens = Arc::clone(&opens);
            let reopened_releases = Arc::clone(&reopened_releases);
            move |agent| {
                open_release_counting_coordinator(
                    agent,
                    Arc::clone(&opens),
                    Arc::clone(&reopened_releases),
                )
            }
        });

        reconcile_native_computer_for_delegation_with_opener(
            &mut agent,
            &mut coordinator,
            &mut contract,
            &mut coordinator_config,
            &mut pending_continuations,
            &mut sticky_ask_denial,
            &mut opener,
        )
        .await
        .expect("denied coordinator still reconciles");
        assert_eq!(
            sticky_ask_denial.as_deref(),
            Some("policy blocks"),
            "driver slot must retain sticky Ask denial after a successful replacement"
        );

        let replacement = coordinator.as_ref().expect("replacement coordinator");
        assert_eq!(
            replacement.terminal_denial(),
            Some("policy blocks"),
            "replacement must inherit the sticky Ask denial"
        );
        assert_eq!(opens.load(Ordering::SeqCst), 1);
        coordinator
            .as_mut()
            .expect("replacement coordinator")
            .close()
            .await
            .expect("replacement coordinator closes");
    }

    /// Sticky Ask denial outlives a particular coordinator instance. Each
    /// case drives the production reconcile opener path, closes a denied
    /// coordinator, then returns without an immediate successor — the
    /// missing-config, unsupported-optional, opener-`None`, and opener-error
    /// exits cited in the review finding. A later reconciliation must still
    /// inherit the denial onto the replacement and refuse to re-prompt.
    #[tokio::test]
    async fn reconcile_preserves_terminal_ask_denial_across_failed_replacement() {
        #[derive(Clone, Copy, Debug)]
        enum ReplacementGap {
            MissingConfig,
            UnsupportedOptionalBackend,
            OpenerReturnsNone,
            OpenerError,
        }

        let screenshot = [OpenAiComputerAction::Screenshot];
        for gap in [
            ReplacementGap::MissingConfig,
            ReplacementGap::UnsupportedOptionalBackend,
            ReplacementGap::OpenerReturnsNone,
            ReplacementGap::OpenerError,
        ] {
            let initial = NativeComputerToolConfig {
                contract: ComputerToolContract::OpenAiResponses,
                target: DisplayTarget::Virtual,
                require_backend: false,
                geometry: None,
                approval_required: false,
            };
            let mut agent = test_agent_with_native_geometry(None);
            agent.params.native_computer = Some(NativeComputerToolConfig {
                approval_required: true,
                ..initial.clone()
            });
            let deny = Arc::new(FakeComputerAuthorizer::always_deny("policy blocks"));
            let mut coordinator = Some(make_ask_test_coordinator(Arc::clone(&deny)).await);
            assert!(
                matches!(
                    coordinator
                        .as_mut()
                        .expect("original coordinator")
                        .execute_openai_call("call-deny", &screenshot)
                        .await,
                    CoordinatedOutcome::Denied { .. }
                ),
                "{gap:?}: original Ask path must record a human denial"
            );
            let mut contract = Some(initial.contract);
            let mut coordinator_config = Some(initial.coordinator_config());
            let mut pending_continuations = Vec::new();
            let mut sticky_ask_denial = None;

            match gap {
                ReplacementGap::MissingConfig => {
                    agent.params.native_computer = None;
                    let mut opener = panicking_opener;
                    reconcile_native_computer_for_delegation_with_opener(
                        &mut agent,
                        &mut coordinator,
                        &mut contract,
                        &mut coordinator_config,
                        &mut pending_continuations,
                        &mut sticky_ask_denial,
                        &mut opener,
                    )
                    .await
                    .expect("missing config defers replacement");
                }
                ReplacementGap::UnsupportedOptionalBackend => {
                    agent.params.native_computer = Some(NativeComputerToolConfig {
                        contract: ComputerToolContract::Anthropic20251124,
                        approval_required: true,
                        ..initial.clone()
                    });
                    let mut opener = panicking_opener;
                    reconcile_native_computer_for_delegation_with_opener(
                        &mut agent,
                        &mut coordinator,
                        &mut contract,
                        &mut coordinator_config,
                        &mut pending_continuations,
                        &mut sticky_ask_denial,
                        &mut opener,
                    )
                    .await
                    .expect("unsupported optional backend defers replacement");
                }
                ReplacementGap::OpenerReturnsNone => {
                    let mut opener = none_opener;
                    reconcile_native_computer_for_delegation_with_opener(
                        &mut agent,
                        &mut coordinator,
                        &mut contract,
                        &mut coordinator_config,
                        &mut pending_continuations,
                        &mut sticky_ask_denial,
                        &mut opener,
                    )
                    .await
                    .expect("opener returning None defers replacement");
                }
                ReplacementGap::OpenerError => {
                    let mut opener = error_opener;
                    reconcile_native_computer_for_delegation_with_opener(
                        &mut agent,
                        &mut coordinator,
                        &mut contract,
                        &mut coordinator_config,
                        &mut pending_continuations,
                        &mut sticky_ask_denial,
                        &mut opener,
                    )
                    .await
                    .expect_err("opener error must surface");
                }
            }

            assert!(
                coordinator.is_none(),
                "{gap:?}: denied coordinator must be gone after the replacement gap"
            );
            assert_eq!(
                sticky_ask_denial.as_deref(),
                Some("policy blocks"),
                "{gap:?}: driver slot must retain sticky Ask denial across the replacement gap"
            );

            agent.params.native_computer = Some(NativeComputerToolConfig {
                approval_required: true,
                ..initial.clone()
            });
            let allow = Arc::new(FakeComputerAuthorizer::always_allow());
            let opens = Arc::new(AtomicUsize::new(0));
            let mut opener: Box<
                dyn for<'a> FnMut(
                    &'a mut Agent,
                ) -> BoxFuture<
                    'a,
                    anyhow::Result<Option<ComputerActionCoordinator>>,
                >,
            > = Box::new({
                let allow = Arc::clone(&allow);
                let opens = Arc::clone(&opens);
                move |agent| {
                    open_ask_test_coordinator(agent, Arc::clone(&allow), Arc::clone(&opens))
                }
            });
            reconcile_native_computer_for_delegation_with_opener(
                &mut agent,
                &mut coordinator,
                &mut contract,
                &mut coordinator_config,
                &mut pending_continuations,
                &mut sticky_ask_denial,
                &mut opener,
            )
            .await
            .expect("later reconciliation opens a successor");

            let replacement = coordinator.as_mut().expect("successor coordinator");
            assert_eq!(
                replacement.terminal_denial(),
                Some("policy blocks"),
                "{gap:?}: successor must inherit the sticky Ask denial"
            );
            assert!(
                matches!(
                    replacement
                        .execute_openai_call("call-after-gap", &screenshot)
                        .await,
                    CoordinatedOutcome::Denied { .. }
                ),
                "{gap:?}: successor must refuse dispatch after inherited denial"
            );
            assert_eq!(
                allow.call_count(),
                0,
                "{gap:?}: inherited denial must not re-prompt"
            );
            assert_eq!(opens.load(Ordering::SeqCst), 1);
            replacement.close().await.expect("successor closes");
        }
    }

    fn test_agent_with_native_geometry(
        geometry: Option<DisplayGeometry>,
    ) -> crate::engine::agent::Agent {
        use crate::engine::agent::Agent;
        use crate::engine::model::{Model, ModelParams};
        use crate::redact::RedactionTable;
        let mut cfg = crate::config::providers::ProvidersConfig::default();
        cfg.providers.insert(
            "local".to_string(),
            crate::config::providers::ProviderEntry {
                url: "http://127.0.0.1:9/v1".to_string(),
                wire_api: crate::config::providers::WireApi::Responses,
                ..crate::config::providers::ProviderEntry::default()
            },
        );
        let model = Arc::new(
            Model::for_provider_with_env(
                &cfg,
                "local",
                "test-model",
                Arc::new(RedactionTable::empty()),
                |_| None,
            )
            .expect("test model builds without network"),
        );
        Agent {
            name: "Build".to_string(),
            system: "system".to_string(),
            role_prompt: "system".to_string(),
            tools: crate::engine::tool::ToolBox::new(),
            model,
            params: crate::engine::model::ModelParams {
                native_computer: Some(crate::computer::NativeComputerToolConfig {
                    contract: ComputerToolContract::OpenAiResponses,
                    target: crate::computer::DisplayTarget::Virtual,
                    require_backend: false,
                    geometry,
                    approval_required: false,
                }),
                ..ModelParams::default()
            },
            scan_tool_results: false,
            tool_steering: crate::agents::ToolSteering::Terse,
            posture: crate::agents::PostureResolution::standard(),
            context_policy: None,
            lock_identity: "Build".to_string(),
            write_scope: None,
            workspace_lease: None,
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            vnext_grant: None,
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            definition: None,
            assistant_identity_prefix: None,
            mcp_resolver: crate::mcp::resolver::EffectiveCatalogResolver::empty(),
        }
    }

    #[tokio::test]
    async fn computer_live_loop_overlay_copies_geometry_without_mutating_source() {
        let coordinator = make_coordinator().await;
        let agent = test_agent_with_native_geometry(None);
        assert!(
            agent
                .params
                .native_computer
                .as_ref()
                .is_some_and(|config| config.geometry.is_none())
        );
        let overlaid = with_live_loop_native_computer_geometry(agent.clone(), Some(&coordinator));
        assert_eq!(
            overlaid
                .params
                .native_computer
                .as_ref()
                .and_then(|config| config.geometry.as_ref()),
            Some(coordinator.geometry()),
            "live-loop overlay is the only path that copies opened geometry onto request params"
        );
        assert!(
            agent
                .params
                .native_computer
                .as_ref()
                .is_some_and(|config| config.geometry.is_none()),
            "the long-lived agent must keep geometry unset so compact/shrink/resolver clones do not advertise"
        );
        let without_coordinator = with_live_loop_native_computer_geometry(agent, None);
        assert!(
            without_coordinator
                .params
                .native_computer
                .as_ref()
                .is_some_and(|config| config.geometry.is_none())
        );
    }
}
