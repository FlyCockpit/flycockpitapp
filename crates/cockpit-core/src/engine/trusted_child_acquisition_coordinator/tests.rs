use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use super::*;
use crate::config::extended::{ApprovalMode, ExtendedConfig};
use crate::config::providers::{
    ActiveModelRef, ModelAvailability, ModelEntry, ModelLocation, ModelTrust, ProviderEntry,
    ProvidersConfig, WireApi,
};
use crate::engine::builtin::{DelegationRecursionContext, SpawnArgs};
use crate::engine::model::{Model, ModelParams};
use crate::redact::RedactionTable;
use crate::session::Session;
use cockpit_test_support::provider::{ScriptedProvider, Turn, WireDialect};

const RECORD_ID: &str = "3f2e1d0c-9b8a-4c7d-8e6f-5a4b3c2d1e0f";
const VALUE_NAME: &str = "acquired_deploy_token";
const ACQUISITION_ID: &str = "4d2e1c0b-8a7f-4e6d-9c5b-3a2f1e0d9c8b";
const SOURCE_TOOL_CALL_ID: &str = "run-acquisition-command";
const NOW_MS: i64 = 2_000_000;
const SECRET: &str = "sk-acquired-by-trusted-child-7c4e9a2f";

fn trusted_local_providers(url: String) -> ProvidersConfig {
    let mut providers = BTreeMap::new();
    providers.insert(
        "trusted-local".to_owned(),
        ProviderEntry {
            url,
            wire_api: WireApi::Completions,
            models: vec![ModelEntry {
                id: "trusted-acquisition".to_owned(),
                subagent_invokable: Some(true),
                trust: Some(ModelTrust::Trusted),
                location: Some(ModelLocation::Local),
                availability: ModelAvailability {
                    categories: vec!["trusted-child-acquisition".to_owned()],
                    ..ModelAvailability::default()
                },
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );
    ProvidersConfig {
        providers,
        active_model: Some(ActiveModelRef {
            provider: "trusted-local".to_owned(),
            model: "trusted-acquisition".to_owned(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        }),
        ..ProvidersConfig::default()
    }
}

fn acquisition_spawn_args(
    session: &Session,
    model: Arc<Model>,
    config: crate::daemon::session_worker::SessionConfigHandle,
) -> SpawnArgs {
    SpawnArgs {
        compiled_guidance: Vec::new(),
        guidance_compiler: None,
        model,
        params: ModelParams::default(),
        env_overlay: Arc::new(std::sync::RwLock::new(HashMap::new())),
        cwd: session.project_root.clone(),
        config,
        session_short_id: session.short_id(),
        workspace_scratch_dir: session.workspace_scratch_dir(),
        assistant_identity_prefix: None,
        model_system_prompt_snapshot: session.model_system_prompt_snapshot(),
        knowledge_base_system_prefix: session.knowledge_base_system_prompt(),
        interactive: false,
        mcp_parent_reachable: None,
        mcp_root_catalog: crate::mcp::resolver::EffectiveCatalogResolver::empty().root_catalog(),
        model_override: None,
        delegation_model: None,
        delegated: true,
        delegation_recursion: DelegationRecursionContext::default(),
        vnext_grant: None,
        vnext_host_policy: None,
        vnext_local_installation_resolver:
            crate::agents::LocalInstallationResolver::no_installations(),
        parent_vnext_grant: None,
        parent_posture: None,
        swarm_depth: 0,
        swarm_max_depth: crate::config::extended::DEFAULT_RECURSIVE_SPAWN_MAX_DEPTH,
        granted_tools: Vec::new(),
        lock_identity: None,
        write_scope: None,
        dream_read_scope: session.dream_read_scope(),
        workspace_lease: None,
        credential_store: None,
        media_availability: crate::tool_media_authority::MediaToolAvailability::unavailable(),
    }
}

fn interrupt_hub(
    session: &Session,
    redaction: Arc<RedactionTable>,
) -> Arc<crate::engine::interrupt::InterruptHub> {
    let (events, _receiver) = tokio::sync::broadcast::channel(16);
    Arc::new(crate::engine::interrupt::InterruptHub::new(
        events,
        Arc::new(std::sync::RwLock::new(redaction)),
        Arc::new(std::sync::atomic::AtomicUsize::new(1)),
        session.db.clone(),
        session.id,
    ))
}

/// Drives the live noninteractive child loop, real bash dispatch, production
/// quarantine, source-reference capture, and atomic sealed-value write. This
/// is deliberately not a unit test of the registry or quarantine helper: a
/// secret here would hit child/provider history and durable events if either
/// dispatch interception or coordinator ordering regressed.
#[test]
fn command_output_is_quarantined_before_child_history_and_sealed_by_reference() {
    crate::test_env::run_async_with_large_stack(|| async {
        let _env = crate::test_env::lock_async().await;
        let workspace = tempfile::tempdir().expect("create acquisition workspace");
        let provider = ScriptedProvider::builder()
            .dialect(WireDialect::ChatCompletions)
            .turn(Turn::ToolCall {
                id: SOURCE_TOOL_CALL_ID.to_owned(),
                name: "run_acquisition_command".to_owned(),
                arguments: serde_json::json!({}),
            })
            .turn(Turn::ToolCall {
                id: "capture-terminal".to_owned(),
                name: "capture_sealed_value".to_owned(),
                arguments: serde_json::json!({
                    "source_tool_call_id": SOURCE_TOOL_CALL_ID,
                }),
            })
            .turn(Turn::Text("acquisition complete".to_owned()))
            .start()
            .await;
        let providers = trusted_local_providers(provider.base_url());
        let redaction = Arc::new(RedactionTable::empty());
        let session_model = Arc::new(
            Model::from_config(&providers, redaction.clone())
                .expect("trusted local model is configured"),
        );
        let extended = ExtendedConfig::default();
        let config = crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                1,
                providers.clone(),
                extended.clone(),
            ),
        );
        let session = Arc::new(
            Session::create_for_test(
                crate::db::Db::open_in_memory().expect("open test database"),
                workspace.path().to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .expect("create test session"),
        );

        let outcome = run_trusted_child_acquisition(
            AcquisitionRequest {
                caller_mode: ApprovalMode::Yolo,
                category: "trusted-child-acquisition",
                delegating_agent_name: "Build",
                extended: &extended,
                providers: &providers,
                session_model: &session_model,
                store: None,
                acquisition_id: ACQUISITION_ID,
                record_id: RECORD_ID,
                value_name: VALUE_NAME,
                description: "Deploy credential acquired by trusted child",
                generation: 1,
                value_version: 1,
                now_ms: NOW_MS,
                command: format!("printf %s {SECRET}"),
                allowed_sealed_record_ids: BTreeSet::new(),
            },
            AcquisitionExecutionContext {
                spawn_args: acquisition_spawn_args(&session, session_model.clone(), config.clone()),
                session: session.clone(),
                locks: Arc::new(crate::locks::LockManager::in_memory(session.db.clone())),
                redaction: redaction.clone(),
                config,
                guidance_compiler: None,
                interrupts: interrupt_hub(&session, redaction.clone()),
                cancel: tokio_util::sync::CancellationToken::new(),
                approver: None,
                resource_scheduler: None,
                local_installations: crate::agents::LocalInstallationResolver::no_installations(),
            },
            &TrustedChildCaptureRegistry::new(),
        )
        .await;

        assert_eq!(outcome, AcquisitionOutcome::Sealed);
        assert!(
            !format!("{outcome:?}").contains(SECRET),
            "the parent-facing result is closed and cannot expose the value"
        );

        // The child saw only the production-time placeholder. The final
        // provider request contains the tool result it would otherwise retain
        // as child history, so this catches a quarantine-after-history bug.
        let requests = provider.captured();
        assert_eq!(
            requests.len(),
            3,
            "the scripted child completed its live loop"
        );
        for request in requests {
            let body = request.body.to_string();
            assert!(
                !body.contains(SECRET),
                "quarantined output reached the trusted child's provider history: {body}"
            );
        }

        // The only durable literal location is the sealed vault item. The
        // destination record, owner-visible audit, and redaction union prove
        // that the real create-only capture path completed atomically.
        let vault = crate::secure_key::vault_for_db(&session.db).expect("open session vault");
        let item_id =
            crate::secure_key::session_sealed_item_id(&session.id.to_string(), VALUE_NAME, 1);
        let stored = vault
            .get_item(
                cockpit_db::secret_vault::SecretVaultKind::SessionSealedValue,
                &item_id,
            )
            .expect("captured value is sealed in the vault");
        assert_eq!(stored.as_slice(), SECRET.as_bytes());
        let record = session
            .db
            .sealed_value_record(RECORD_ID.to_owned())
            .await
            .expect("read sealed record")
            .expect("agent-acquired record exists");
        assert_eq!(record.name, VALUE_NAME);
        assert_eq!(record.owner_principal, "agent-acquired");
        assert_eq!(record.active_version, 1);
        let audit = session
            .db
            .list_sealed_value_acquisition_audit(Some(session.id.to_string()), 10)
            .await
            .expect("read acquisition audit");
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].outcome, "sealed");
        assert_eq!(
            audit[0].source_tool_call_id.as_deref(),
            Some(SOURCE_TOOL_CALL_ID)
        );
        let persisted_redaction = session
            .persisted_redaction_table()
            .expect("read persisted redaction table")
            .expect("captured literal installs a redaction union");
        assert!(!persisted_redaction.scrub(SECRET).contains(SECRET));

        // Session events are the durable child transcript boundary. The vault
        // above is deliberately the sole allowed literal store; neither raw
        // command output nor its provider-facing history may be persisted.
        let events = session
            .db
            .list_session_events(session.id)
            .await
            .expect("read durable session events");
        for event in events {
            assert!(
                !event.data.to_string().contains(SECRET),
                "quarantined output leaked into durable '{}' event",
                event.kind
            );
        }
    });
}

#[test]
fn acquisition_definition_requests_but_does_not_self_grant_capture() {
    let definition = crate::agents::embedded_internal_default(ACQUISITION_AGENT).unwrap();
    assert!(
        definition
            .vnext
            .as_ref()
            .unwrap()
            .capabilities
            .contains(&crate::agents::AgentCapability::SealedAcquisitionCapture)
    );
    assert!(
        !crate::agents::PostureResolution::from_def(&definition)
            .grants()
            .contains(&crate::agents::AgentCapability::SealedAcquisitionCapture),
        "definition request must not become runtime authority"
    );
    assert_eq!(definition.tools.as_ref().unwrap().len(), 6);
}

#[tokio::test]
async fn acquisition_approval_posture_is_narrowed_without_mutating_session() {
    for (parent, expected) in [
        (ApprovalMode::Yolo, ApprovalMode::Yolo),
        (ApprovalMode::Auto, ApprovalMode::Manual),
        (ApprovalMode::Manual, ApprovalMode::Manual),
    ] {
        let runtime = AcquisitionRuntime::new(BTreeSet::new(), parent);
        let actual = with_acquisition_runtime(runtime, async {
            crate::tools::trusted_child_acquisition::effective_approval_mode(parent)
        })
        .await;
        assert_eq!(actual, expected);
    }
}

#[test]
fn steering_is_bounded_and_never_requests_the_value() {
    assert!((1..=2).contains(&MAX_TERMINAL_NUDGES));
    assert!(TERMINAL_NUDGE.contains("exactly one terminal move"));
    assert!(!TERMINAL_NUDGE.contains("tell me the value"));
}
