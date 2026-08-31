//! Provider-native computer-use live loop.
//!
//! [`NativeComputerLiveLoop`] is the single public orchestrator that extracts
//! raw provider `computer_call` / native `tool_use` items from a provider
//! completion, executes each on the opened [`ComputerActionCoordinator`],
//! builds continuations with live frames, and returns injection payloads for
//! the next provider request.
//!
//! Extraction uses the provider's raw Responses / Anthropic content arrays —
//! not Rig `AssistantContent::ToolCall` JSON reinterpretation. Generic Rig
//! function-tool dispatch must never re-parse native computer JSON; the
//! reserved-name refusal in [`super::is_reserved_native_computer_tool_name`]
//! is the guard at the generic dispatch chokepoint.
//!
//! The driver's real tool-result / multi-turn path calls
//! [`NativeComputerLiveLoop::handle_native_computer_items`] (or the free
//! function [`handle_native_computer_items`] in `engine/driver`), replacing
//! today's silent drop of every model-emitted computer action.

use super::ComputerToolContract;
use super::coordinator::{
    ComputerActionCoordinator, NativeComputerCall, NativeComputerContinuation,
    NativeResponseExtractor,
};

/// The single public live-loop orchestrator for provider-native computer use.
///
/// One instance is held per opened coordinator (per computer-capable
/// delegation). It is constructed after the coordinator successfully opens
/// (open-before-advertise) and lives for the coordinator's lifetime.
pub struct NativeComputerLiveLoop<'a> {
    coordinator: &'a mut ComputerActionCoordinator,
    contract: ComputerToolContract,
}

impl<'a> NativeComputerLiveLoop<'a> {
    /// Bind a live loop to an opened coordinator and tool contract.
    pub fn new(
        coordinator: &'a mut ComputerActionCoordinator,
        contract: ComputerToolContract,
    ) -> Self {
        Self {
            coordinator,
            contract,
        }
    }

    /// Extract OpenAI Responses `computer_call` items from a response payload.
    ///
    /// The `output` parameter is the raw `output` array from an OpenAI
    /// Responses API response. Each item with `"type": "computer_call"` is
    /// parsed with the canonical OpenAI parser.
    pub fn extract_openai(output: &[serde_json::Value]) -> Vec<NativeComputerCall> {
        NativeResponseExtractor::extract_openai(output)
    }

    /// Extract Anthropic native `tool_use` items named `computer` from a
    /// response payload.
    ///
    /// The `content` parameter is the raw `content` array from an Anthropic
    /// Messages API response. The `contract` selects the versioned action DTO
    /// parser.
    pub fn extract_anthropic(
        content: &[serde_json::Value],
        contract: ComputerToolContract,
    ) -> Vec<NativeComputerCall> {
        NativeResponseExtractor::extract_anthropic(content, contract)
    }

    /// Extract native computer items from a provider completion using the
    /// contract bound to this live loop. For OpenAI Responses, pass the raw
    /// `output` array; for Anthropic, pass the raw `content` array.
    pub fn extract(&self, raw: &[serde_json::Value]) -> Vec<NativeComputerCall> {
        match self.contract {
            ComputerToolContract::OpenAiResponses => Self::extract_openai(raw),
            ComputerToolContract::Anthropic20251124 | ComputerToolContract::Anthropic20250124 => {
                Self::extract_anthropic(raw, self.contract)
            }
        }
    }

    /// Execute each extracted call on the opened coordinator; build
    /// continuations with live frames; return injection payloads for the
    /// next provider request.
    ///
    /// Each call is executed in provider order. The coordinator's
    /// [`ComputerActionCoordinator::execute_native_call`] returns
    /// [`super::coordinator::ExecuteArtifacts`] carrying the sanitized outcome (journalable) and
    /// the live frame (for transient continuation assembly only). The live
    /// frame is consumed by [`NativeResponseExtractor::build_continuation`]
    /// and dropped immediately after.
    pub async fn handle_extracted(
        &mut self,
        calls: Vec<NativeComputerCall>,
    ) -> Vec<NativeComputerContinuation> {
        let mut continuations = Vec::with_capacity(calls.len());
        for call in calls {
            let artifacts = self.coordinator.execute_native_call(&call).await;
            let continuation = NativeResponseExtractor::build_continuation(
                &call,
                &artifacts.outcome,
                artifacts.live_frame.as_ref(),
            );
            // The live frame (if any) is dropped here — it was consumed by
            // build_continuation and must not persist beyond this point.
            continuations.push(continuation);
        }
        continuations
    }

    /// One-shot convenience: extract from raw provider output and execute in
    /// a single call. This is the method the driver registration function
    /// invokes.
    pub async fn handle_native_computer_items(
        &mut self,
        raw: &[serde_json::Value],
    ) -> Vec<NativeComputerContinuation> {
        let calls = self.extract(raw);
        if calls.is_empty() {
            return Vec::new();
        }
        self.handle_extracted(calls).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::computer::coordinator::{
        ComputerActionCoordinator, ComputerApprovalTier, ComputerAuthorizer, CoordinatorParams,
        DelegationId, FakeComputerAuthorizer, ModelId, OwnerInstance, ProviderId,
    };
    use crate::computer::{
        ComputerAction, ComputerActionOutcome, ComputerBackend, ComputerBatchReport,
        DisplayGeometry, LogicalSize, PixelSize, ScaleFactor,
    };
    use async_trait::async_trait;
    use std::sync::Arc;

    /// A fake backend that yields a successful capture frame.
    struct CapturingFakeBackend {
        geometry: DisplayGeometry,
        execute_count: std::sync::atomic::AtomicUsize,
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
                execute_count: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn execute_count(&self) -> usize {
            self.execute_count.load(std::sync::atomic::Ordering::SeqCst)
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
            self.execute_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ComputerBatchReport {
                completed: Vec::new(),
                failure: None,
                release_failure: None,
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

    /// Extraction of OpenAI `computer_call` items from raw output.
    #[test]
    fn computer_live_extract_openai_from_raw_output() {
        let output = vec![serde_json::json!({
            "type": "computer_call",
            "call_id": "call-1",
            "action": {"type": "move", "x": 4.0, "y": 5.0}
        })];
        let calls = NativeComputerLiveLoop::extract_openai(&output);
        assert_eq!(calls.len(), 1);
        assert!(matches!(calls[0], NativeComputerCall::OpenAi { .. }));
    }

    /// Extraction of Anthropic `tool_use` items from raw content.
    #[test]
    fn computer_live_extract_anthropic_from_raw_content() {
        let content = vec![serde_json::json!({
            "type": "tool_use",
            "id": "toolu-1",
            "name": "computer",
            "input": {
                "action": "screenshot"
            }
        })];
        let calls = NativeComputerLiveLoop::extract_anthropic(
            &content,
            ComputerToolContract::Anthropic20251124,
        );
        assert_eq!(calls.len(), 1);
        assert!(matches!(
            calls[0],
            NativeComputerCall::Anthropic20251124 { .. }
        ));
    }

    /// Handle extracted calls: execute on coordinator, build continuation with
    /// transient pixels from the live frame (AC6).
    #[tokio::test]
    async fn computer_live_handle_extracted_openai_transient_pixels() {
        let mut coordinator = make_coordinator().await;
        let mut live_loop =
            NativeComputerLiveLoop::new(&mut coordinator, ComputerToolContract::OpenAiResponses);

        let output = vec![serde_json::json!({
            "type": "computer_call",
            "call_id": "call-1",
            "action": {"type": "move", "x": 4.0, "y": 5.0}
        })];
        let calls = NativeComputerLiveLoop::extract_openai(&output);
        let continuations = live_loop.handle_extracted(calls).await;

        assert_eq!(continuations.len(), 1);
        // With a successful capture (live frame present), the continuation
        // carries a transient screenshot — not TextOnly.
        match &continuations[0] {
            NativeComputerContinuation::OpenAi { transient, .. } => {
                assert!(
                    transient.is_some(),
                    "transient must be Some when live frame is present"
                );
            }
            other => panic!("expected OpenAi continuation, got {other:?}"),
        }
    }

    /// Handle extracted calls: empty input yields empty continuations.
    #[tokio::test]
    async fn computer_live_handle_empty_items() {
        let mut coordinator = make_coordinator().await;
        let mut live_loop =
            NativeComputerLiveLoop::new(&mut coordinator, ComputerToolContract::OpenAiResponses);

        let continuations = live_loop.handle_native_computer_items(&[]).await;
        assert!(continuations.is_empty());
    }

    /// One-shot: extract + handle in a single call (AC5 — the named
    /// production driver registration function invokes this same symbol).
    #[tokio::test]
    async fn computer_live_handle_native_computer_items_openai() {
        let mut coordinator = make_coordinator().await;
        let mut live_loop =
            NativeComputerLiveLoop::new(&mut coordinator, ComputerToolContract::OpenAiResponses);

        let output = vec![serde_json::json!({
            "type": "computer_call",
            "call_id": "call-1",
            "action": {"type": "move", "x": 4.0, "y": 5.0}
        })];
        let continuations = live_loop.handle_native_computer_items(&output).await;
        assert_eq!(continuations.len(), 1);
        assert!(matches!(
            &continuations[0],
            NativeComputerContinuation::OpenAi { .. }
        ));
    }

    /// Unsupported variant produces a typed Unsupported continuation, no
    /// backend input (AC20).
    #[tokio::test]
    async fn computer_live_unsupported_variant_no_backend_input() {
        let mut coordinator = make_coordinator().await;
        let mut live_loop =
            NativeComputerLiveLoop::new(&mut coordinator, ComputerToolContract::OpenAiResponses);

        // Malformed computer_call — missing actions array, parse fails.
        let output = vec![serde_json::json!({
            "type": "computer_call",
            "call_id": "call-1"
        })];
        let continuations = live_loop.handle_native_computer_items(&output).await;
        assert_eq!(continuations.len(), 1);
        assert!(matches!(
            &continuations[0],
            NativeComputerContinuation::Unsupported { .. }
        ));
    }
}
