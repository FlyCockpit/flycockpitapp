//! End-to-end tests for the trusted-child acquisition coordinator (leak-report
//! AC6 `auto_yolo_trusted_acquisition_matrix`, sub-increment 2c-3b).
//!
//! Every test drives the REAL [`run_trusted_child_acquisition`] entry point with
//! a live [`ScriptedProvider`] behind the selected trusted child (never a mock
//! dispatch), a real in-memory [`Session`], and the real 2c-2
//! [`TrustedChildCaptureRegistry`]. Assertions target the live session store
//! (vault, `sealed_values` row, persisted redaction table, AND the durable
//! session event log), so a fail-closed path is proven by the total ABSENCE of
//! the planted value, and a leak would be proven by its presence.
//!
//! The child dispatch is a non-persisting utility completion, so the CORE
//! regression guard ([`assert_no_leak_in_session_events`]) asserts the child's
//! raw output never reaches a durable session event — the leak the earlier
//! turn-runner-based dispatch caused. It holds on every path, including a
//! successful `Sealed` capture.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use cockpit_test_support::provider::{ScriptedProvider, Turn};

use super::*;
use crate::config::extended::{ApprovalMode, ExtendedConfig, LlmMode};
use crate::config::providers::{
    ActiveModelRef, CapabilityStatus, ModelAvailability, ModelCapabilities, ModelEntry,
    ModelLocation, ModelTrust, ProviderEntry, ProvidersConfig, WireApi,
};
use crate::engine::model::Model;
use crate::redact::RedactionTable;
use crate::sealed::OwnerAuthority;
use crate::session::Session;

const RECORD_ID: &str = "rec-coord-1";
const VALUE_ID: &str = "captured_secret";
const REASON: &str = "trusted-child acquisition";
const ORIGIN: &str = "trusted_child";
const GENERATION: i64 = 11;
const VERSION: i64 = 2;
const TOOL_CALL: &str = "toolcall-coord";
const NOW_MS: i64 = 2_000_000;

/// A real captured credential the coordinator is expected to seal. `>= 12` chars
/// so the sealed-value validator admits it (2c-2 / `MIN_SEALED_VALUE_LENGTH`).
const REAL_SECRET: &str = "sk-acquired-by-trusted-child-7c4e9a2f";

/// A distinct token planted in the child's RAW output OUTSIDE the whitelisted
/// claim fields. It must never surface anywhere: not in the returned outcome,
/// the vault, the sealed row, the redaction table, or any durable session event.
const PLANT: &str = "PLANT-LEAK-TOKEN-b91d0e6a-must-never-escape";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A scripted provider that answers ONE non-streaming chat-completion with
/// `claim` as the assistant message content. The acquisition child dispatch is a
/// utility `text_completion` (a non-streaming `.send()`, not the streaming turn
/// runner), so the provider must return a verbatim JSON body (`Turn::RawJson`),
/// not an SSE stream (`Turn::Text`). The child provider is pinned to the
/// `Completions` wire (see `providers_with_child`), so this chat-completion shape
/// is the one dispatched.
async fn scripted(claim: &str) -> ScriptedProvider {
    let body = serde_json::json!({
        "id": "chatcmpl-acq",
        "object": "chat.completion",
        "created": 1,
        "model": "local",
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": claim },
            "finish_reason": "stop"
        }],
        "usage": { "prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2 }
    });
    ScriptedProvider::builder()
        .turn(Turn::RawJson(body))
        .start()
        .await
}

/// Providers carrying a single trusted `reasoning` child at `location` behind
/// `child_url`, plus an untrusted `reasoning` alternative so the forced-`Trusted`
/// scan must CHOOSE the trusted child rather than being handed the only
/// candidate. A separate dummy provider backs the session/active model.
fn providers_with_child(child_url: &str, location: Option<ModelLocation>) -> ProvidersConfig {
    let mut providers = BTreeMap::new();
    providers.insert(
        "localhost".to_string(),
        ProviderEntry {
            url: child_url.to_string(),
            models: vec![
                ModelEntry {
                    id: "trusted-reasoning".into(),
                    subagent_invokable: Some(true),
                    trust: Some(ModelTrust::Trusted),
                    quality_rank: Some(1_000),
                    location,
                    capabilities: ModelCapabilities {
                        reasoning: CapabilityStatus::Supported,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ModelEntry {
                    id: "untrusted-reasoning".into(),
                    subagent_invokable: Some(true),
                    trust: Some(ModelTrust::Untrusted),
                    availability: ModelAvailability {
                        categories: vec!["reasoning".to_string()],
                        ..Default::default()
                    },
                    capabilities: ModelCapabilities {
                        reasoning: CapabilityStatus::Supported,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ],
            // Pin the child to the Completions wire so the utility completion
            // dispatches a chat-completion the scripted `Turn::RawJson` answers
            // (deterministic — no probe/detection).
            wire_api: WireApi::Completions,
            ..ProviderEntry::default()
        },
    );
    providers.insert(
        "session-prov".to_string(),
        ProviderEntry {
            url: "http://localhost:1/v1".into(),
            ..ProviderEntry::default()
        },
    );
    ProvidersConfig {
        providers,
        active_model: Some(ActiveModelRef {
            provider: "session-prov".into(),
            model: "session".into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        }),
        ..ProvidersConfig::default()
    }
}

fn session_model(cfg: &ProvidersConfig) -> Arc<Model> {
    Arc::new(Model::from_config(cfg, Arc::new(RedactionTable::empty())).unwrap())
}

fn extended() -> ExtendedConfig {
    ExtendedConfig {
        llm_mode: LlmMode::Normal,
        agent_chooses_subagent_model: true,
        ..ExtendedConfig::default()
    }
}

fn new_session() -> Arc<Session> {
    let db = crate::db::Db::open_in_memory().unwrap();
    // No external journal is installed: the acquisition dispatch is a
    // non-persisting utility completion (not the turn runner), and the sealed
    // install path persists the redaction-table union directly — mirroring the
    // 2c-2 `set_sealed_value` tests, which seal on a bare `create_for_test`
    // session with no journal.
    Arc::new(
        Session::create_for_test(
            db,
            PathBuf::from("/repo"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap(),
    )
}

/// Build a request bound to `providers`/`session_model`, with a fixed brief.
fn request<'a>(
    caller_mode: ApprovalMode,
    providers: &'a ProvidersConfig,
    session_model: &'a Arc<Model>,
    extended: &'a ExtendedConfig,
) -> AcquisitionRequest<'a> {
    AcquisitionRequest {
        caller_mode,
        category: "reasoning",
        agent_name: "deepthink",
        extended,
        providers,
        session_model,
        store: None,
        record_id: RECORD_ID,
        value_id: VALUE_ID,
        reason: REASON,
        origin: ORIGIN,
        generation: GENERATION,
        version: VERSION,
        source_tool_call_id: TOOL_CALL,
        now_ms: NOW_MS,
        child_brief: "Acquire the deploy credential.".to_string(),
    }
}

async fn sealed_row_exists(session: &Session) -> bool {
    session
        .sealed_value_exists(OwnerAuthority::for_test("owner"), VALUE_ID)
        .await
        .unwrap()
}

fn vault_holds(session: &Session) -> Option<Vec<u8>> {
    let vault = crate::secure_key::vault_for_db(&session.db).unwrap();
    let item_id = crate::secure_key::session_sealed_item_id(&session.id.to_string(), VALUE_ID, 1);
    vault
        .get_item(
            cockpit_db::secret_vault::SecretVaultKind::SessionSealedValue,
            &item_id,
        )
        .ok()
        .map(|item| item.as_slice().to_vec())
}

/// The CORE 2c-3b regression guard: the child's raw output must never reach a
/// durable session event. The earlier turn-runner-based dispatch persisted the
/// child's raw assistant text+reasoning to the session event log before
/// classification; the non-persisting utility completion cannot. Holds on EVERY
/// path, including a successful `Sealed` capture (the secret goes to the vault +
/// redaction table, never a plaintext event).
async fn assert_no_leak_in_session_events(session: &Session) {
    let events = session.db.list_session_events(session.id).await.unwrap();
    for ev in &events {
        let blob = ev.data.to_string();
        assert!(
            !blob.contains(REAL_SECRET),
            "the captured secret leaked into a '{}' session event",
            ev.kind
        );
        assert!(
            !blob.contains(PLANT),
            "a planted token leaked into a '{}' session event",
            ev.kind
        );
    }
}

/// Assert nothing was stored: no sealed row, no vault item, the persisted
/// redaction table (if any) scrubs neither the real secret nor the plant, and
/// no session event carries child-derived plaintext.
async fn assert_no_store(session: &Session) {
    assert!(
        !sealed_row_exists(session).await,
        "no sealed_values row may exist on a fail-closed path"
    );
    assert!(
        vault_holds(session).is_none(),
        "no vault item may hold a captured literal on a fail-closed path"
    );
    if let Some(table) = session.persisted_redaction_table().unwrap() {
        assert_eq!(table.scrub(REAL_SECRET), REAL_SECRET);
        assert_eq!(table.scrub(PLANT), PLANT);
    }
    assert_no_leak_in_session_events(session).await;
}

// ---------------------------------------------------------------------------
// Eligibility
// ---------------------------------------------------------------------------

/// Manual (and any ineligible posture) performs ZERO side effects: the trusted
/// child is never selected or dispatched (the scripted provider is never hit),
/// and no capture record is minted.
#[tokio::test]
async fn manual_caller_never_selects_or_dispatches() {
    let provider = scripted(&format!("{{\"captured_secret\":\"{REAL_SECRET}\"}}")).await;
    let providers = providers_with_child(&provider.base_url(), Some(ModelLocation::Local));
    let sm = session_model(&providers);
    let ext = extended();
    let session = new_session();
    let registry = TrustedChildCaptureRegistry::new();
    let redaction = Arc::new(RedactionTable::empty());

    let outcome = run_trusted_child_acquisition(
        request(ApprovalMode::Manual, &providers, &sm, &ext),
        &registry,
        session.clone(),
        redaction,
    )
    .await;

    assert_eq!(outcome, AcquisitionOutcome::Failed);
    // The child was never dispatched: the scripted provider received no request.
    assert!(
        provider.captured().is_empty(),
        "Manual must not dispatch the child"
    );
    // No pending record was minted, so nothing is in flight and nothing stored.
    assert!(!registry.has_in_flight(&session.id.to_string(), NOW_MS));
    assert_no_store(&session).await;
}

// ---------------------------------------------------------------------------
// Selection gate (2c-1)
// ---------------------------------------------------------------------------

/// A non-`Local` trusted child fails closed at selection: `Failed`, no dispatch,
/// and the pending record minted before selection is cancelled.
#[tokio::test]
async fn non_local_trusted_child_fails_closed_and_cancels_pending() {
    let provider = scripted(&format!("{{\"captured_secret\":\"{REAL_SECRET}\"}}")).await;
    // Remote location: 2c-1 refuses to mint a grant, so the coordinator must not
    // dispatch.
    let providers = providers_with_child(&provider.base_url(), Some(ModelLocation::Remote));
    let sm = session_model(&providers);
    let ext = extended();
    let session = new_session();
    let registry = TrustedChildCaptureRegistry::new();
    let redaction = Arc::new(RedactionTable::empty());

    let outcome = run_trusted_child_acquisition(
        request(ApprovalMode::Auto, &providers, &sm, &ext),
        &registry,
        session.clone(),
        redaction,
    )
    .await;

    assert_eq!(outcome, AcquisitionOutcome::Failed);
    assert!(
        provider.captured().is_empty(),
        "a non-Local trusted child must not be dispatched"
    );
    // The pending record minted before selection was cancelled on the Err path.
    assert!(
        !registry.has_in_flight(&session.id.to_string(), NOW_MS),
        "the orphaned pending record must be cancelled"
    );
    assert_no_store(&session).await;
}

// ---------------------------------------------------------------------------
// Classification: RequiresUser
// ---------------------------------------------------------------------------

/// A valid `RequiresUser` claim is returned as the human-surfacing signal, the
/// pending record is RETAINED, and a secret planted in the child's discarded
/// output never reaches the returned prompt, the redaction table, any store, or
/// a session event. Runs under both eligible postures and every LLM mode.
#[tokio::test]
async fn valid_requires_user_is_returned_pending_retained_no_leak() {
    for mode in [ApprovalMode::Auto, ApprovalMode::Yolo] {
        for llm in [LlmMode::Defensive, LlmMode::Normal, LlmMode::Frontier] {
            // The whitelisted `prompt` is a clean single-line question; the
            // planted token rides in a NON-whitelisted sibling field the
            // coordinator never reads.
            let claim = format!(
                "{{\"requires_user\":{{\"reason\":\"missing_credential\",\"prompt\":\"which vault should I unlock?\"}},\"leaked\":\"{PLANT}\"}}"
            );
            let provider = scripted(&claim).await;
            let providers = providers_with_child(&provider.base_url(), Some(ModelLocation::Local));
            let sm = session_model(&providers);
            let ext = ExtendedConfig {
                llm_mode: llm,
                agent_chooses_subagent_model: true,
                ..ExtendedConfig::default()
            };
            let session = new_session();
            let registry = TrustedChildCaptureRegistry::new();
            let redaction = Arc::new(RedactionTable::empty());

            // Precondition (L7): the child's raw output really carries the plant.
            assert!(claim.contains(PLANT));

            let outcome = run_trusted_child_acquisition(
                request(mode, &providers, &sm, &ext),
                &registry,
                session.clone(),
                redaction,
            )
            .await;

            match &outcome {
                AcquisitionOutcome::RequiresUser(ru) => {
                    assert_eq!(ru.reason().as_str(), "missing_credential");
                    assert_eq!(ru.prompt(), "which vault should I unlock?");
                    assert!(!ru.prompt().contains(PLANT));
                }
                other => panic!("{mode:?}/{llm:?}: expected RequiresUser, got {other:?}"),
            }
            // The child WAS dispatched (eligible posture, Local trusted child).
            assert_eq!(provider.captured().len(), 1, "exactly one child turn ran");
            // Pending is RETAINED so the human's answer can complete the capture.
            assert!(
                registry.has_in_flight(&session.id.to_string(), NOW_MS),
                "pending must be retained on RequiresUser"
            );
            // Discard: the plant never reaches the returned outcome or any store.
            assert!(!format!("{outcome:?}").contains(PLANT));
            assert_no_store(&session).await;
        }
    }
}

/// Each invalid `RequiresUser` claim (unknown reason, over-length prompt, control
/// character) collapses to `Failed` and DELETES the pending record.
#[tokio::test]
async fn invalid_requires_user_fails_and_deletes_pending() {
    let long_prompt = "a".repeat(241);
    let cases = [
        // Unknown reason.
        "{\"requires_user\":{\"reason\":\"totally_unknown\",\"prompt\":\"which vault?\"}}"
            .to_string(),
        // Control character (newline) in the prompt.
        "{\"requires_user\":{\"reason\":\"missing_credential\",\"prompt\":\"line one\\nline two\"}}"
            .to_string(),
        // Over-length prompt (241 scalars).
        format!(
            "{{\"requires_user\":{{\"reason\":\"owner_knowledge\",\"prompt\":\"{long_prompt}\"}}}}"
        ),
    ];

    for claim in cases {
        let provider = scripted(&claim).await;
        let providers = providers_with_child(&provider.base_url(), Some(ModelLocation::Local));
        let sm = session_model(&providers);
        let ext = extended();
        let session = new_session();
        let registry = TrustedChildCaptureRegistry::new();
        let redaction = Arc::new(RedactionTable::empty());

        let outcome = run_trusted_child_acquisition(
            request(ApprovalMode::Auto, &providers, &sm, &ext),
            &registry,
            session.clone(),
            redaction,
        )
        .await;

        assert_eq!(
            outcome,
            AcquisitionOutcome::Failed,
            "invalid RequiresUser must fail closed: {claim}"
        );
        assert!(
            !registry.has_in_flight(&session.id.to_string(), NOW_MS),
            "the pending record must be deleted on an invalid RequiresUser: {claim}"
        );
        assert_no_store(&session).await;
    }
}

// ---------------------------------------------------------------------------
// Classification: captured secret
// ---------------------------------------------------------------------------

/// A captured-secret claim with the exact host-minted authority seals the value
/// in-process: the sealed row exists, the vault holds EXACTLY the literal, the
/// live redaction table now scrubs it, and the record is consumed single-use. A
/// token planted alongside the literal (in a non-whitelisted field) is never
/// sealed, logged, installed into the redaction table, or written to a session
/// event — and neither is the sealed secret itself.
#[tokio::test]
async fn captured_secret_seals_in_process_and_discards_surrounding_output() {
    // The real literal is in the whitelisted field; the plant rides in a
    // sibling the coordinator never reads.
    let claim = format!("{{\"captured_secret\":\"{REAL_SECRET}\",\"notes\":\"{PLANT}\"}}");
    let provider = scripted(&claim).await;
    let providers = providers_with_child(&provider.base_url(), Some(ModelLocation::Local));
    let sm = session_model(&providers);
    let ext = extended();
    let session = new_session();
    let registry = TrustedChildCaptureRegistry::new();
    let redaction = Arc::new(RedactionTable::empty());

    // Precondition (L7): a fresh table scrubs neither value, so the post-capture
    // scrub is a real signal, and the plant is really present in the raw output.
    assert_eq!(redaction.scrub(REAL_SECRET), REAL_SECRET);
    assert!(claim.contains(PLANT));

    let outcome = run_trusted_child_acquisition(
        request(ApprovalMode::Auto, &providers, &sm, &ext),
        &registry,
        session.clone(),
        redaction,
    )
    .await;

    assert_eq!(outcome, AcquisitionOutcome::Sealed);

    // In-process transfer landed: sealed row + vault item holding EXACTLY the
    // literal (not the raw JSON, not the plant).
    assert!(sealed_row_exists(&session).await);
    let stored = vault_holds(&session).expect("the vault holds the sealed literal");
    assert_eq!(stored.as_slice(), REAL_SECRET.as_bytes());

    // The live redaction table now scrubs the real secret but NOT the plant — a
    // coordinator that sealed the whole raw output would have installed the
    // plant here.
    let installed = session.persisted_redaction_table().unwrap().unwrap();
    assert!(!installed.scrub(REAL_SECRET).contains(REAL_SECRET));
    assert_eq!(
        installed.scrub(PLANT),
        PLANT,
        "the plant must never be installed in the redaction table"
    );

    // Single-use: the record was consumed.
    assert!(!registry.has_in_flight(&session.id.to_string(), NOW_MS));
    // The plant never surfaces in the returned outcome.
    assert!(!format!("{outcome:?}").contains(PLANT));
    // CORE GUARD: neither the sealed secret nor the plant reached a durable
    // session event on the SUCCESS path (the turn-runner leak this increment
    // exists to prevent).
    assert_no_leak_in_session_events(&session).await;
}

/// A captured-secret claim the 2c-2 verify path DENIES (here: a literal the
/// sealed-value validator rejects for being too short — the coordinator always
/// presents the exact minted authority, so a wrong authority cannot arise from
/// child input; that IS the security property) maps to `Failed`, stores nothing,
/// and frees the slot.
#[tokio::test]
async fn captured_secret_denied_by_registry_yields_failed_and_stores_nothing() {
    // A too-short literal fails the sealed-value validator inside 2c-2's
    // `set_sealed_value`, so verify_and_capture returns `Denied`.
    let claim = "{\"captured_secret\":\"short\"}".to_string();
    let provider = scripted(&claim).await;
    let providers = providers_with_child(&provider.base_url(), Some(ModelLocation::Local));
    let sm = session_model(&providers);
    let ext = extended();
    let session = new_session();
    let registry = TrustedChildCaptureRegistry::new();
    let redaction = Arc::new(RedactionTable::empty());

    let outcome = run_trusted_child_acquisition(
        request(ApprovalMode::Auto, &providers, &sm, &ext),
        &registry,
        session.clone(),
        redaction,
    )
    .await;

    assert_eq!(outcome, AcquisitionOutcome::Failed);
    assert!(
        !registry.has_in_flight(&session.id.to_string(), NOW_MS),
        "a denied capture must free the in-flight slot"
    );
    assert_no_store(&session).await;
}

/// A child that returns unclassifiable output (non-JSON prose carrying a planted
/// token) fails closed, deletes the pending record, and never leaks the token.
#[tokio::test]
async fn unclassifiable_child_output_fails_closed_no_leak() {
    let claim = format!("I could not do it. Here is a secret anyway: {PLANT}");
    let provider = scripted(&claim).await;
    let providers = providers_with_child(&provider.base_url(), Some(ModelLocation::Local));
    let sm = session_model(&providers);
    let ext = extended();
    let session = new_session();
    let registry = TrustedChildCaptureRegistry::new();
    let redaction = Arc::new(RedactionTable::empty());

    assert!(claim.contains(PLANT));

    let outcome = run_trusted_child_acquisition(
        request(ApprovalMode::Auto, &providers, &sm, &ext),
        &registry,
        session.clone(),
        redaction,
    )
    .await;

    assert_eq!(outcome, AcquisitionOutcome::Failed);
    assert!(!registry.has_in_flight(&session.id.to_string(), NOW_MS));
    assert!(!format!("{outcome:?}").contains(PLANT));
    assert_no_store(&session).await;
}

// ---------------------------------------------------------------------------
// Rate limit (2c-2 begin_capture)
// ---------------------------------------------------------------------------

/// A second concurrent acquisition for the same session is refused by 2c-2's
/// one-in-flight-per-session rate limit: the coordinator fails closed WITHOUT
/// dispatching a child, and the pre-existing in-flight record is undisturbed.
#[tokio::test]
async fn second_concurrent_acquisition_is_refused_without_dispatch() {
    let provider = scripted(&format!("{{\"captured_secret\":\"{REAL_SECRET}\"}}")).await;
    let providers = providers_with_child(&provider.base_url(), Some(ModelLocation::Local));
    let sm = session_model(&providers);
    let ext = extended();
    let session = new_session();
    let registry = TrustedChildCaptureRegistry::new();
    let redaction = Arc::new(RedactionTable::empty());

    // Pre-seed the single in-flight slot with an unrelated live acquisition.
    let _first = registry
        .begin_capture(
            &session,
            "rec-other",
            "other_slot",
            REASON,
            ORIGIN,
            GENERATION,
            VERSION,
            "toolcall-other",
            NOW_MS,
        )
        .expect("first acquisition is admitted");

    let outcome = run_trusted_child_acquisition(
        request(ApprovalMode::Auto, &providers, &sm, &ext),
        &registry,
        session.clone(),
        redaction,
    )
    .await;

    assert_eq!(outcome, AcquisitionOutcome::Failed);
    // No child was dispatched — the refusal happened before selection.
    assert!(
        provider.captured().is_empty(),
        "a rate-limited acquisition must not dispatch a child"
    );
    // The pre-existing in-flight record is undisturbed.
    assert!(registry.has_in_flight(&session.id.to_string(), NOW_MS));
    assert_no_store(&session).await;
}
