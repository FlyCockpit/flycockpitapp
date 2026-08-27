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
        async fn geometry(&self) -> Result<DisplayGeometry, crate::computer::ComputerError> {
            Ok(self.geometry.clone())
        }

        async fn execute(&self, _actions: &[ComputerAction]) -> ComputerBatchReport {
            ComputerBatchReport {
                completed: Vec::new(),
                failure: None,
            }
        }

        async fn execute_one(
            &self,
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

        async fn release_all(&self) -> Result<(), crate::computer::ComputerError> {
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
            "actions": [
                {"type": "move", "x": 4.0, "y": 5.0}
            ]
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
            "actions": [
                {"type": "move", "x": 4.0, "y": 5.0}
            ]
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
            "actions": [
                {"type": "move", "x": 4.0, "y": 5.0}
            ]
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
}
