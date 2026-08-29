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
) -> Option<ComputerActionCoordinator> {
    let candidate = agent.params.native_computer.clone()?;
    if !agent
        .model
        .supports_native_computer_contract(candidate.contract)
    {
        return None;
    }
    let Some(approver) = approver else {
        agent.params.native_computer = None;
        return None;
    };
    let backend = match crate::computer::VirtualDisplayBackend::construct(
        crate::computer::DisplayTarget::Virtual,
        None,
    ) {
        Ok(backend) => backend,
        Err(error) => {
            tracing::warn!(error = %error, "native computer backend open failed");
            agent.params.native_computer = None;
            return None;
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
        tier: if candidate.approval_required {
            crate::computer::coordinator::ComputerApprovalTier::Ask
        } else {
            crate::computer::coordinator::ComputerApprovalTier::Yolo
        },
        owner_instance: crate::computer::coordinator::OwnerInstance(1),
        authorizer: Arc::new(
            crate::computer::authorizer::ApproverComputerAuthorizer::new(approver),
        ),
        host_arbiter: None,
        target_adapter: Some(Box::new(
            crate::computer::coordinator::VirtualTargetEvidenceAdapter::new(
                *uuid::Uuid::new_v4().as_bytes(),
            ),
        )),
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
            Some(coordinator)
        }
        Err(error) => {
            tracing::warn!(error = %error, "native computer coordinator open failed");
            agent.params.native_computer = None;
            None
        }
    }
}

/// Reconcile the live coordinator with the model's *current* wire support at
/// every turn boundary. Endpoint fallback can change an OpenAI model from
/// Responses to Chat Completions after a coordinator was opened; retaining
/// Responses-only continuations across that change would make the next wire
/// request invalid. Both foreground and noninteractive loops use this one
/// lifecycle rule.
pub(crate) async fn reconcile_native_computer_for_delegation(
    agent: &mut Agent,
    session: &Arc<Session>,
    approver: Option<Arc<crate::approval::Approver>>,
    delegation_id: String,
    coordinator: &mut Option<ComputerActionCoordinator>,
    contract: &mut Option<ComputerToolContract>,
    pending_continuations: &mut Vec<serde_json::Value>,
) {
    let retained_is_compatible = coordinator.is_some()
        && contract.is_some_and(|contract| agent.model.supports_native_computer_contract(contract));
    if retained_is_compatible {
        return;
    }

    if let Some(mut previous) = coordinator.take() {
        *contract = None;
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
    } else if contract.take().is_some() {
        // Preserve the same invariant even if a prior open failed halfway
        // through a driver-frame update: no contract/geometry/continuation is
        // retained without its matching coordinator.
        pending_continuations.clear();
        if let Some(candidate) = agent.params.native_computer.as_mut() {
            candidate.geometry = None;
        }
    }

    let Some(candidate) = agent.params.native_computer.as_ref() else {
        return;
    };
    if !agent
        .model
        .supports_native_computer_contract(candidate.contract)
    {
        return;
    }

    let opened = open_native_computer_for_delegation(agent, session, approver, delegation_id).await;
    if let Some(opened) = opened {
        *contract = agent
            .params
            .native_computer
            .as_ref()
            .map(|config| config.contract);
        *coordinator = Some(opened);
    }
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
        ComputerToolContract, DisplayGeometry, LogicalSize, PixelSize, ScaleFactor,
    };
    use async_trait::async_trait;
    use std::sync::Arc;

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

        async fn release_all(&mut self) -> Result<(), crate::computer::ComputerError> {
            Ok(())
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
        assert!(opened.is_none());
        assert!(
            agent.params.native_computer.is_none(),
            "failed open must leave native_computer: None so the tool is not advertised"
        );
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
