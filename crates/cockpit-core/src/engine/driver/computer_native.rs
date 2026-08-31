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
use crate::engine::agent::Agent;
use crate::session::Session;
use futures::future::BoxFuture;
use std::sync::Arc;

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
    let backend = match crate::computer::VirtualDisplayBackend::construct(
        candidate.target,
        grant_store.as_ref(),
    ) {
        Ok(backend) => backend,
        Err(error) => {
            tracing::warn!(error = %error, "native computer backend open failed");
            agent.params.native_computer = None;
            if candidate.require_backend {
                anyhow::bail!(
                    "Computer primary could not open its {} backend: {error}. Set `computer_target` to `virtual` to use the isolated display instead",
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
        crate::computer::DisplayTarget::Virtual => (
            Box::new(
                crate::computer::coordinator::VirtualTargetEvidenceAdapter::new(
                    *uuid::Uuid::new_v4().as_bytes(),
                ),
            ) as Box<dyn crate::computer::target::TargetEvidenceAdapter>,
            None,
        ),
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
            #[cfg(not(target_os = "linux"))]
            {
                unreachable!("non-Linux real desktop construction fails closed")
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
    };
    match ComputerActionCoordinator::open(Box::new(backend), params).await {
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
) -> anyhow::Result<()> {
    let session = Arc::clone(session);
    reconcile_native_computer_for_delegation_with_opener(
        agent,
        coordinator,
        contract,
        coordinator_config,
        pending_continuations,
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
    if let Some(opened) = opened {
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
) -> Vec<serde_json::Value> {
    let continuations = handle_native_computer_items(Some(coordinator), contract, &raw_items).await;
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
        ComputerApprovalTier, ComputerAuthorizer, CoordinatorParams, DelegationId,
        FakeComputerAuthorizer, ModelId, NativeComputerContinuation, OwnerInstance, ProviderId,
    };
    use crate::computer::{
        ComputerAction, ComputerActionOutcome, ComputerBackend, ComputerBatchReport,
        ComputerToolContract, DisplayGeometry, DisplayTarget, LogicalSize,
        NativeComputerCoordinatorConfig, NativeComputerToolConfig, PixelSize, ScaleFactor,
    };
    use async_trait::async_trait;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

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

        async fn execute(&mut self, _actions: &[ComputerAction]) -> ComputerBatchReport {
            ComputerBatchReport {
                completed: Vec::new(),
                failure: None,
            }
        }

        async fn execute_one(
            &mut self,
            action: &ComputerAction,
        ) -> Result<ComputerActionOutcome, crate::computer::ComputerError> {
            if matches!(action, ComputerAction::CaptureFull) {
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

        async fn execute(&mut self, actions: &[ComputerAction]) -> ComputerBatchReport {
            self.inner.execute(actions).await
        }

        async fn execute_one(
            &mut self,
            action: &ComputerAction,
        ) -> Result<ComputerActionOutcome, crate::computer::ComputerError> {
            self.inner.execute_one(action).await
        }

        fn release_all(&mut self) -> Result<(), crate::computer::ComputerError> {
            self.releases.fetch_add(1, Ordering::SeqCst);
            self.inner.release_all()
        }
    }

    async fn make_coordinator() -> ComputerActionCoordinator {
        let authorizer: Arc<dyn ComputerAuthorizer> =
            Arc::new(FakeComputerAuthorizer::always_allow());
        let backend = Box::new(CapturingFakeBackend::new());
        let params = CoordinatorParams {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            tier: ComputerApprovalTier::Yolo,
            owner_instance: OwnerInstance(1),
            authorizer,
            host_arbiter: None,
            target_adapter: None,
            provider_id: ProviderId("openai".to_string()),
            model_id: ModelId("gpt-4o".to_string()),
            outcome_store: None,
            handoff_journal: None,
        };
        ComputerActionCoordinator::open(backend, params)
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
        let params = CoordinatorParams {
            session_id: "session-1".to_string(),
            delegation_id: DelegationId("delegation-1".to_string()),
            tier: ComputerApprovalTier::Yolo,
            owner_instance: OwnerInstance(1),
            authorizer,
            host_arbiter: None,
            target_adapter: None,
            provider_id: ProviderId("openai".to_string()),
            model_id: ModelId("gpt-4o".to_string()),
            outcome_store: None,
            handoff_journal: None,
        };
        ComputerActionCoordinator::open(backend, params)
            .await
            .expect("coordinator open")
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
        let wire = handle_retained_native_computer_items(
            &mut coordinator,
            ComputerToolContract::OpenAiResponses,
            raw_items,
        )
        .await;
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
            let opens = Arc::new(AtomicUsize::new(0));
            let mut opener = {
                let opens = Arc::clone(&opens);
                let reopened_releases = Arc::clone(&reopened_releases);
                move |_agent: &mut Agent| -> BoxFuture<'static, anyhow::Result<Option<ComputerActionCoordinator>>> {
                    let opens = Arc::clone(&opens);
                    let reopened_releases = Arc::clone(&reopened_releases);
                    Box::pin(async move {
                        opens.fetch_add(1, Ordering::SeqCst);
                        Ok(Some(
                            make_release_counting_coordinator(reopened_releases).await,
                        ))
                    })
                }
            };

            reconcile_native_computer_for_delegation_with_opener(
                &mut agent,
                &mut coordinator,
                &mut contract,
                &mut coordinator_config,
                &mut pending_continuations,
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
