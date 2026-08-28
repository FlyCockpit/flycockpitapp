use super::shell::PointerOperationId;
use super::*;
use cockpit_config::extended::ExtendedConfigDoc;

#[test]
fn settings_input_pages_do_not_wait_on_daemon_rpcs() {
    for (name, source) in [
        ("providers", include_str!("providers/mod.rs")),
        ("mcp", include_str!("mcp_page.rs")),
        ("tools", include_str!("tools_page.rs")),
        ("category", include_str!("category.rs")),
    ] {
        assert!(
            !source.contains("block_in_place")
                && !source.contains("Handle::current().block_on")
                && !source.contains("settings_daemon_request("),
            "{name} settings input path contains a synchronous daemon wait"
        );
    }
}

#[test]
fn agent_editor_staging_is_dispatched_only_through_a_blocking_action() {
    let agents = include_str!("agents_page.rs");
    let app = include_str!("../app/async_actions.rs");
    let begin = agents
        .split("fn apply_begin_lease")
        .nth(1)
        .and_then(|source| source.split("fn settle_unserviced_editor_lease").next())
        .expect("agent lease reducer source");
    let completion = agents
        .split("fn reduce_external_edit_result")
        .nth(1)
        .and_then(|source| source.split("fn queue_failed_external_edit_read").next())
        .expect("agent external-edit completion source");
    assert!(begin.contains("SettingsBlockingEffectWork::PrepareAgentEditor"));
    assert!(!begin.contains("agent_external_edit_staging()"));
    assert!(completion.contains("SettingsBlockingEffectWork::ReadAgentEditor"));
    assert!(!completion.contains("read_config_leaf_from_retained_directory"));
    assert!(app.contains("start_blocking("));
    assert!(app.contains("settings.blocking-effect"));
}

#[test]
fn category_editor_staging_is_dispatched_only_through_blocking_actions() {
    let category = include_str!("category.rs");
    assert!(category.contains("PrepareCategoryEditor"));
    assert!(category.contains("ReadCategoryEditor"));
    assert!(!category.contains("std::fs::read_to_string(pending"));
    assert!(!category.contains("tempfile::Builder::new()"));
}

#[test]
fn settings_blocking_timeout_retains_operation_metadata() {
    let app = include_str!("../app/async_actions.rs");
    let state = include_str!("../app/mod.rs");
    assert!(app.contains("settings_blocking_actions.insert"));
    assert!(app.contains("outcome: Err(error)"));
    assert!(state.contains("SettingsBlockingEffectMetadata"));
}

#[test]
fn queued_secret_payloads_have_redacted_debug_and_single_owners() {
    let sentinel = "provider-header-secret-sentinel";
    let payload = SecretPayload::new(sentinel.to_string());
    assert!(!format!("{payload:?}").contains(sentinel));

    let save = ProviderSavePlan {
        provider_id: "example".into(),
        entry: ProviderEntry::default(),
        header_secrets: vec![Some(zeroize::Zeroizing::new(sentinel.to_string()))],
    };
    let plan = ProviderMutationPlan {
        snapshot_session_id: "snapshot".into(),
        layer_id: "layer".into(),
        owner_root: "/project".into(),
        mutation_intent_hash: "00".repeat(32),
        expected_revision: "revision".into(),
        client_operation_id: "operation".into(),
        saves: vec![save],
        deletes: Vec::new(),
        metadata: None,
    };
    assert!(!format!("{plan:?}").contains(sentinel));

    let settings = include_str!("mod.rs");
    let mcp = include_str!("mcp_page.rs");
    assert!(settings.contains("Vec<Option<zeroize::Zeroizing<String>>>"));
    assert!(mcp.contains("SecretPayload::new(secret_values_json)"));
}

#[test]
fn provider_settings_use_one_exact_atomic_receipt_and_no_legacy_sequence() {
    let settings = include_str!("mod.rs");
    let executor = settings
        .split("SettingsDaemonEffectWork::ProviderMutation(plan) =>")
        .nth(1)
        .and_then(|tail| {
            tail.split("SettingsDaemonEffectWork::TypedDocumentEdit")
                .next()
        })
        .expect("provider mutation executor");
    assert_eq!(executor.matches(".request(").count(), 1);
    assert!(executor.contains("Request::ApplyProviderMutation"));
    assert!(!executor.contains("Request::SaveProviderConfig"));
    assert!(!executor.contains("Request::DeleteProviderConfig"));
    assert!(!executor.contains("Request::SetProviderLayerMetadata"));

    let completion = settings
        .split("Ok(Response::ProviderMutationCommitted")
        .nth(1)
        .expect("provider committed receipt handling");
    for exact_field in [
        "returned_operation_id == client_operation_id",
        "returned_session_id == snapshot_session_id",
        "returned_layer_id == layer_id",
        "consumed_revision == expected_revision",
        "config_generation == expected_generation.saturating_add(1)",
    ] {
        assert!(completion.contains(exact_field), "missing {exact_field}");
    }
    assert!(completion.contains("ConfigPublicationStatus::Published"));
}

#[test]
fn settings_cannot_close_or_accept_a_stale_session_completion_while_pending() {
    let tmp = TempDir::new().unwrap();
    let mut settings = fresh_dialog(&tmp);
    let target = SettingsEffectTarget {
        surface: "settings.test-pending",
        owner: "owner".into(),
        revision: Some("revision".into()),
    };
    let operation_id = settings.cx.queue_simple_mutation(
        target.clone(),
        Request::ListAssistants,
        SettingsMutationAction::ProviderCredentialDelete {
            provider_id: "example".into(),
            client_operation_id: "test-operation".into(),
            project_root: "/workspace".into(),
            expected_request_hash: "00".repeat(32),
        },
    );
    assert!(!settings.handle_key(press(KeyCode::Char('q'))));
    assert!(settings.cx.pending_settings.contains_key(&operation_id));

    let current_dialog_id = settings.cx.dialog_id;
    let mut dialog = Dialog::Settings(Box::new(settings));
    dialog.apply_settings_daemon_completion(SettingsDaemonEffectCompletion {
        dialog_id: uuid::Uuid::new_v4(),
        operation_id,
        target,
        response: Ok(Response::Ack),
        authoritative_rejection: false,
        committed_refresh_needed: None,
    });
    let Dialog::Settings(settings) = &dialog else {
        unreachable!();
    };
    assert_eq!(settings.cx.dialog_id, current_dialog_id);
    assert!(settings.cx.pending_settings.contains_key(&operation_id));
    assert!(settings.cx.completed_provider_auth.is_none());
}

#[test]
fn authority_success_is_receipt_driven_and_committed_refresh_is_explicit() {
    let source = include_str!("mod.rs");
    let providers = include_str!("providers/mod.rs");
    let fetch = include_str!("providers/fetch.rs");
    assert!(source.contains("if self.authority_operation_pending()"));
    assert!(source.contains("completed_mcp_navigation"));
    assert!(source.contains("adopt_pending_mcp_oauth"));
    assert!(source.contains("committed_refresh_needed"));
    assert!(source.contains("settings committed at generation"));
    assert!(source.contains("pending_provider_mutation_navigation.take()"));
    assert!(source.contains("completed_provider_mutation_navigation"));
    assert!(providers.contains("has_unsettled_authority_operation"));
    assert!(providers.contains("Self::FetchAll(state) => state.is_fetching()"));
    assert!(providers.contains("ProviderMutationNavigation::Edit"));
    assert!(fetch.contains("ProviderMutationNavigation::List"));
    assert!(fetch.contains("return Nav::Stay"));
    let mcp = include_str!("mcp_page.rs");
    assert!(mcp.contains("Result<super::SettingsSaveOutcome, String>"));
    assert!(mcp.contains("Ok(super::SettingsSaveOutcome::Queued)"));
}

#[test]
fn path_suggestion_filesystem_reads_are_blocking_worker_only() {
    let reducer = include_str!("category.rs");
    let settings = include_str!("mod.rs");
    let worker = settings
        .split("pub(crate) fn execute_settings_blocking_work")
        .nth(1)
        .and_then(|source| {
            source
                .split("pub(crate) enum SettingsDaemonEffectWork")
                .next()
        })
        .expect("settings blocking worker inventory");

    assert!(!reducer.contains("suggest_paths("));
    assert!(!reducer.contains("std::fs::read_dir"));
    assert!(worker.contains("dir_suggest::suggest_paths"));
    assert!(settings.contains("\"settings.path-suggest\""));
    assert!(settings.contains("editor_generation"));
    assert!(settings.contains("draft_generation"));
}

#[test]
fn oauth_acknowledgement_keeps_explicit_authority_until_typed_settlement() {
    let flow = include_str!("providers/oauth_flow.rs");
    let providers = include_str!("providers/mod.rs");
    let app = include_str!("../app/async_actions.rs");
    let dialog = include_str!("mod.rs");

    assert!(flow.contains("acknowledgement_authority_pending: bool"));
    assert!(flow.contains("self.acknowledgement_authority_pending = true"));
    assert!(flow.contains("apply_acknowledgement_settlement_unknown"));
    assert!(flow.contains("self.acknowledgement_authority_pending = false"));
    assert!(providers.contains("has_unsettled_oauth_acknowledgement"));
    assert!(dialog.contains("oauth_ack_retry"));
    assert!(app.contains("Ok(Ok(Err(_))) | Ok(Err(_)) | Err(_)"));
    assert!(!app.contains("daemon rejected acknowledgement: {error}"));
}

#[test]
fn external_editor_generic_errors_never_release_daemon_authority() {
    let agents = include_str!("agents_page.rs");
    let begin = agents
        .split("fn apply_begin_lease")
        .nth(1)
        .and_then(|source| source.split("fn settle_unserviced_editor_lease").next())
        .expect("editor begin reducer");
    let completion = agents
        .split("fn apply_complete_lease")
        .nth(1)
        .and_then(|source| source.split("/// Help line for the footer").next())
        .expect("editor completion reducer");

    assert!(begin.contains("PendingAgentOperation::BeginLease"));
    assert!(!begin.contains("if authoritative_rejection"));
    assert!(completion.contains("validate_agent_editor_completion"));
    assert!(completion.contains("PendingAgentOperation::CompleteLease"));
    assert!(completion.contains("AgentEditorSettlementStatus::Pending"));
    assert!(completion.contains("AgentEditorSettlementStatus::Rejected"));
    assert!(completion.contains("AgentEditorSettlementStatus::Cancelled"));
    assert!(completion.contains("AgentEditorSettlementStatus::Saved"));
    assert!(!completion.contains("if authoritative_rejection"));
}

#[test]
fn provider_auth_completions_carry_unit_success_results() {
    let settings = include_str!("mod.rs");
    let auth_completion = settings
        .split("enum CompletedProviderAuthMutation")
        .nth(1)
        .and_then(|source| source.split("enum PendingMcpOAuth").next())
        .expect("provider auth completion enum");
    assert_eq!(
        auth_completion
            .matches("result: Result<(), String>")
            .count(),
        2
    );
    assert!(!auth_completion.contains("Result<bool, String>"));
}

#[test]
fn empty_object_merge_patch_is_derived_as_noop_for_existing_object() {
    let mut authored = serde_json::json!({
        "tui": { "mouse": true },
        "redact": { "scan_environment": true }
    });
    let before = authored.clone();
    apply_json_merge_patch_local(&mut authored, serde_json::json!({ "tui": {} }));
    assert_eq!(authored, before);
    let operations = changed_extended_paths(&before, &authored).expect("typed diff");
    assert!(operations.is_empty());
}
use cockpit_config::providers::{ModelEntry, ProviderEntry};
use cockpit_test_support::TestEnvGuard;
use providers::{FetchAllState, valid_url};
use ratatui::Terminal;
use ratatui::backend::{Backend, TestBackend};
use std::collections::BTreeMap;

struct QueuedSettingsDaemon {
    responses: Mutex<std::collections::VecDeque<Result<Response, String>>>,
    requests: Mutex<Vec<Request>>,
}

impl SettingsDaemonEffect for QueuedSettingsDaemon {
    fn request(&self, request: Request) -> Result<Response, String> {
        self.requests.lock().unwrap().push(request);
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("queued settings daemon response")
    }
}

fn settings_layer_base(
    config: &ExtendedConfig,
    layer_id: &str,
    generation: u64,
) -> serde_json::Value {
    let mut base = serde_json::to_value(config).unwrap();
    let object = base.as_object_mut().unwrap();
    object.insert(
        "__cockpit_settings_layer_id".into(),
        serde_json::Value::String(layer_id.into()),
    );
    object.insert(
        "__cockpit_settings_layer_kind".into(),
        serde_json::to_value(cockpit_proto::CockpitConfigLayer::Project).unwrap(),
    );
    object.insert(
        "__cockpit_settings_generation".into(),
        serde_json::Value::Number(generation.into()),
    );
    object.insert("__cockpit_denylist_entries".into(), serde_json::json!([]));
    base
}

#[test]
fn injected_settings_transport_uses_production_receipt_and_reconciliation_path() {
    let path = std::path::PathBuf::from("/workspace/.cockpit/config.json");
    let config = ExtendedConfig::default();
    let layer_id = "layer-capability";
    let base = settings_layer_base(&config, layer_id, 7);
    let effect = Arc::new(QueuedSettingsDaemon {
        responses: Mutex::new(std::collections::VecDeque::from([
            Ok(Response::ExtendedConfigSaved {
                client_operation_id: "fixture-operation".into(),
                request_hash: "aa".repeat(32),
                mutation_intent_hash: "bb".repeat(32),
                hash: "a3f1c2d4e5b6978081726354453627189a0b1c2d3e4f5a6b7c8d9e0f10213243".into(),
                config_generation: 8,
                layer_id: layer_id.into(),
                layer: cockpit_proto::CockpitConfigLayer::Project,
                consumed_revision: "revision-1".into(),
                result_revision: "a3f1c2d4e5b6978081726354453627189a0b1c2d3e4f5a6b7c8d9e0f10213243"
                    .into(),
                status: cockpit_proto::ConfigCommitStatus::Committed,
                publication: cockpit_proto::ConfigPublicationStatus::Published,
                denylist: Vec::new(),
            }),
            Ok(Response::ExtendedConfigSnapshot {
                layers: vec![cockpit_proto::ExtendedConfigLayerSnapshot {
                    layer_id: layer_id.into(),
                    kind: cockpit_proto::CockpitConfigLayer::Project,
                    display_path: path.display().to_string(),
                    config: Box::new(config.clone()),
                    denylist: Vec::new(),
                    revision: "a3f1c2d4e5b6978081726354453627189a0b1c2d3e4f5a6b7c8d9e0f10213243"
                        .into(),
                    authored_paths: Vec::new(),
                }],
                config_generation: 8,
            }),
        ])),
        requests: Mutex::new(Vec::new()),
    });

    with_settings_daemon_effect(effect.clone(), || {
        apply_settings_patch_via_daemon(
            &path,
            Some(std::path::Path::new("/workspace")),
            &base,
            &config,
            "revision-1",
        )
        .unwrap();
    });
    let requests = effect.requests.lock().unwrap();
    assert!(matches!(
        requests[0],
        Request::ApplyExtendedConfigPatch { .. }
    ));
    assert!(matches!(
        requests[1],
        Request::GetExtendedConfigSnapshot { .. }
    ));
}

#[test]
fn injected_settings_transport_rejects_wrong_consumed_revision() {
    let config = ExtendedConfig::default();
    let effect = Arc::new(QueuedSettingsDaemon {
        responses: Mutex::new(std::collections::VecDeque::from([Ok(
            Response::ExtendedConfigSaved {
                client_operation_id: "fixture-operation".into(),
                request_hash: "aa".repeat(32),
                mutation_intent_hash: "bb".repeat(32),
                hash: "a3f1c2d4e5b6978081726354453627189a0b1c2d3e4f5a6b7c8d9e0f10213243".into(),
                config_generation: 8,
                layer_id: "layer-capability".into(),
                layer: cockpit_proto::CockpitConfigLayer::Project,
                consumed_revision: "wrong-revision".into(),
                result_revision: "a3f1c2d4e5b6978081726354453627189a0b1c2d3e4f5a6b7c8d9e0f10213243"
                    .into(),
                status: cockpit_proto::ConfigCommitStatus::Committed,
                publication: cockpit_proto::ConfigPublicationStatus::Published,
                denylist: Vec::new(),
            },
        )])),
        requests: Mutex::new(Vec::new()),
    });
    let error = with_settings_daemon_effect(effect, || {
        apply_settings_patch_via_daemon(
            std::path::Path::new("/workspace/.cockpit/config.json"),
            Some(std::path::Path::new("/workspace")),
            &settings_layer_base(&config, "layer-capability", 7),
            &config,
            "revision-1",
        )
        .unwrap_err()
    });
    assert!(error.contains("unexpected settings patch response"));
}

#[test]
fn settings_config_mutations_stay_daemon_owned() {
    let source = include_str!("mod.rs");
    // Every settings config mutation funnels through the daemon's revisioned
    // typed merge-patch RPC.
    assert!(
        source.contains("Request::ApplyExtendedConfigPatch"),
        "settings must issue the daemon-owned config-patch RPC"
    );
    assert!(
        source.contains("apply_settings_patch_via_daemon"),
        "settings writes must route through the revisioned patch helper"
    );
    assert!(!source.contains("Request::SaveExtendedConfig"));
    assert!(!source.contains("base_hash = None"));
    // The retired local-save helper must be gone entirely.
    assert!(!source.contains("remove_raw_path_and_save"));
    for forbidden in [
        "ExtendedConfigDoc",
        "doc.write(&self.extended)",
        "scaffold_config_dir(",
        "remove_raw_path_and_save",
    ] {
        assert!(
            !source.contains(forbidden),
            "settings tests must not retain local authority substitute `{forbidden}`"
        );
    }
    assert!(source.contains("trait SettingsDaemonEffect"));
    assert!(source.contains("with_settings_daemon_effect"));
    assert!(source.contains("settings_daemon_request(Request::ApplyExtendedConfigPatch"));
}

#[test]
fn denylist_draft_occurrences_do_not_infer_identity_from_equal_masks() {
    let entries = vec![
        cockpit_proto::RedactedDenylistEntry {
            entry_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            display_mask: cockpit_proto::REDACTED_DENYLIST_MASK.into(),
        },
        cockpit_proto::RedactedDenylistEntry {
            entry_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            display_mask: cockpit_proto::REDACTED_DENYLIST_MASK.into(),
        },
    ];
    let mut base = serde_json::json!({});
    base.as_object_mut().unwrap().insert(
        "__cockpit_denylist_entries".into(),
        serde_json::to_value(entries).unwrap(),
    );
    let desired = vec![
        super::existing_denylist_draft(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        super::existing_denylist_draft(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
    ];
    let planned = super::denylist_mutations(&base, &desired).unwrap();
    assert!(matches!(
        &planned[0],
        cockpit_proto::DesiredDenylistEntry::Existing { entry_id }
            if entry_id == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ));
    assert!(matches!(
        &planned[1],
        cockpit_proto::DesiredDenylistEntry::Existing { entry_id }
            if entry_id == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ));
}

#[test]
fn typed_mask_text_is_new_and_cannot_alias_an_existing_occurrence() {
    let mut base = serde_json::json!({});
    base.as_object_mut().unwrap().insert(
        "__cockpit_denylist_entries".into(),
        serde_json::json!([{"entry_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","display_mask":"••••"}]),
    );
    let error = super::denylist_mutations(&base, &["••••".into()]).unwrap_err();
    assert!(error.contains("display masks are reserved"));
}

#[test]
fn denylist_commit_receipt_binds_consumed_and_created_occurrences_exactly() {
    let existing = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let result_existing = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let result_new = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let nonce = "11111111-1111-4111-8111-111111111111";
    let planned = vec![
        cockpit_proto::DesiredDenylistEntry::Existing {
            entry_id: existing.into(),
        },
        cockpit_proto::DesiredDenylistEntry::New {
            client_nonce: nonce.into(),
            literal: cockpit_proto::SensitiveWireLiteral::new("secret".into()),
        },
    ];
    let committed = vec![
        cockpit_proto::CommittedDenylistEntry {
            entry_id: result_existing.into(),
            consumed_entry_id: Some(existing.into()),
            client_nonce: None,
            display_mask: cockpit_proto::REDACTED_DENYLIST_MASK.into(),
        },
        cockpit_proto::CommittedDenylistEntry {
            entry_id: result_new.into(),
            consumed_entry_id: None,
            client_nonce: Some(nonce.into()),
            display_mask: cockpit_proto::REDACTED_DENYLIST_MASK.into(),
        },
    ];
    super::validate_committed_denylist(&planned, &committed).unwrap();

    let mut forged = committed;
    forged[0].consumed_entry_id = Some(result_existing.into());
    assert!(super::validate_committed_denylist(&planned, &forged).is_err());
}

fn entry(id_models: &[&str]) -> ProviderEntry {
    ProviderEntry {
        url: "https://x.example/v1".into(),
        models: id_models
            .iter()
            .map(|id| ModelEntry {
                id: (*id).into(),
                name: None,
                thinking_modes: vec![],
                inputs: None,
                context_length: None,
                favorite: false,
                manual: false,
                trust: None,
                location: None,
                quality_rank: None,
                cost_rank: None,
                subagent_invokable: None,
                can_delegate: None,
                computer_use: None,
                allow_computer_guidance_proposals: None,
                default_thinking_mode: None,
                embeddings: None,
                embedding_dimensions: None,
                availability: Default::default(),
                cache: None,
                shrink: None,
                context: None,
                auto_prune: None,
                timeout: None,
                backup: None,
                inline_think: None,
                hint_tool_call_corrections: None,
                text_embedded_recovery: None,
                thinking_params: Default::default(),
                system_prompt: None,
                wire_api: Default::default(),
                wire_api_provenance: Default::default(),
                extra: Default::default(),
                capabilities: Default::default(),
                capability_overrides: Default::default(),
                provider_metadata: Default::default(),
            })
            .collect(),
        ..ProviderEntry::default()
    }
}

#[test]
fn valid_url_accepts_http_and_https() {
    assert!(valid_url("https://x.example"));
    assert!(valid_url("http://localhost:1234"));
    assert!(!valid_url("foo.example"));
    assert!(!valid_url(""));
}

#[test]
fn list_key_action_wraps_at_both_ends() {
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }
    let mut cursor = 0usize;
    let len = 3usize;
    // Up from the first row wraps to the last.
    list_key_action(k(KeyCode::Up), &mut cursor, len);
    assert_eq!(cursor, 2);
    // Down from the last row wraps to the first.
    list_key_action(k(KeyCode::Down), &mut cursor, len);
    assert_eq!(cursor, 0);
    // `j`/`k` navigate identically on this non-typing list.
    list_key_action(k(KeyCode::Char('k')), &mut cursor, len);
    assert_eq!(cursor, 2);
    list_key_action(k(KeyCode::Char('j')), &mut cursor, len);
    assert_eq!(cursor, 0);
    // A single-item list stays put.
    let mut one = 0usize;
    list_key_action(k(KeyCode::Up), &mut one, 1);
    assert_eq!(one, 0);
    list_key_action(k(KeyCode::Down), &mut one, 1);
    assert_eq!(one, 0);
}

#[test]
fn fetch_all_unlisted_picks_only_drifted_ids() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers
        .insert("p1".into(), entry(&["m1", "m2", "stale"]));
    let remote_outcome = FetchOutcome::Models {
        models: vec![
            ModelEntry {
                id: "m1".into(),
                name: None,
                thinking_modes: vec![],
                inputs: None,
                context_length: None,
                favorite: false,
                manual: false,
                trust: None,
                location: None,
                quality_rank: None,
                cost_rank: None,
                subagent_invokable: None,
                can_delegate: None,
                computer_use: None,
                allow_computer_guidance_proposals: None,
                default_thinking_mode: None,
                embeddings: None,
                embedding_dimensions: None,
                availability: Default::default(),
                cache: None,
                shrink: None,
                context: None,
                auto_prune: None,
                timeout: None,
                backup: None,
                inline_think: None,
                hint_tool_call_corrections: None,
                text_embedded_recovery: None,
                thinking_params: Default::default(),
                system_prompt: None,
                wire_api: Default::default(),
                wire_api_provenance: Default::default(),
                extra: Default::default(),
                capabilities: Default::default(),
                capability_overrides: Default::default(),
                provider_metadata: Default::default(),
            },
            ModelEntry {
                id: "m2".into(),
                name: None,
                thinking_modes: vec![],
                inputs: None,
                context_length: None,
                favorite: false,
                manual: false,
                trust: None,
                location: None,
                quality_rank: None,
                cost_rank: None,
                subagent_invokable: None,
                can_delegate: None,
                computer_use: None,
                allow_computer_guidance_proposals: None,
                default_thinking_mode: None,
                embeddings: None,
                embedding_dimensions: None,
                availability: Default::default(),
                cache: None,
                shrink: None,
                context: None,
                auto_prune: None,
                timeout: None,
                backup: None,
                inline_think: None,
                hint_tool_call_corrections: None,
                text_embedded_recovery: None,
                thinking_params: Default::default(),
                system_prompt: None,
                wire_api: Default::default(),
                wire_api_provenance: Default::default(),
                extra: Default::default(),
                capabilities: Default::default(),
                capability_overrides: Default::default(),
                provider_metadata: Default::default(),
            },
        ],
        catalog: cockpit_config::providers::ProviderModelCatalog::Live,
    };
    let (unlisted, prompt) =
        fetch_all_unlisted_dialog(&cfg, vec![("p1".into(), Ok(remote_outcome))], None);
    assert_eq!(unlisted, vec![("p1".to_string(), "stale".to_string())]);
    assert!(prompt);
}

#[test]
fn fetch_all_unlisted_skips_prompt_when_user_has_chosen() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert("p1".into(), entry(&["stale"]));
    let remote_outcome = FetchOutcome::Models {
        models: vec![],
        catalog: cockpit_config::providers::ProviderModelCatalog::Live,
    };
    let (_unlisted, prompt) = fetch_all_unlisted_dialog(
        &cfg,
        vec![("p1".into(), Ok(remote_outcome))],
        Some(OnUnlistedModelsFetch::Remove),
    );
    assert!(!prompt);
}

// ── Regression: navigation must survive the swap-back ──────────────

use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
use tempfile::TempDir;

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn ctrl(ch: char) -> KeyEvent {
    KeyEvent {
        code: KeyCode::Char(ch),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

struct EditorEnv {
    _guard: cockpit_test_support::TestEnvGuard,
}

impl EditorEnv {
    fn with(value: Option<&str>) -> Self {
        let guard = cockpit_test_support::TestEnvGuard::blocking_lock();
        match value {
            Some(v) => guard.set_var("EDITOR", v),
            None => guard.remove_var("EDITOR"),
        }
        Self { _guard: guard }
    }

    fn unset() -> Self {
        Self::with(None)
    }
}

/// Open a dialog on a fixture config that lives outside every layer the daemon
/// discovers.
///
/// Two arrangements make such a path usable. Registering it as a settings layer
/// lets the extended-config snapshot and patch RPCs resolve it, and the provider
/// snapshot is handed in from that same file the way the production provider
/// entry points hand in an already-authoritative one — the layered provider
/// catalog cannot see a config in a bare temporary directory.
pub(super) fn open_fixture_dialog(path: &std::path::Path) -> SettingsDialog {
    super::disk_daemon_fake::register_settings_layer_target(path);
    let config = cockpit_config::providers::ConfigDoc::load(path)
        .map(|document| document.providers())
        .unwrap_or_default();
    SettingsDialog::open_with_config(path.to_path_buf(), config)
}

pub(super) fn fresh_dialog(tmp: &TempDir) -> SettingsDialog {
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut dialog = open_fixture_dialog(&path);
    // The MCP inventory reaches the dialog as the daemon's projection of
    // `McpConfig::discover`, which would read this developer box's real
    // `~/.config/cockpit/mcp.json`. Clear it so every fresh dialog starts from
    // an empty, hermetic MCP inventory; tests that need servers seed
    // `dialog.mcp_config` explicitly (mirroring the daemon snapshot the
    // production TUI receives).
    dialog.mcp_config = cockpit_core::mcp::config::McpConfig::default();
    dialog
}

/// The denylist as literals.
///
/// A committed save replaces every denylist row with the daemon's opaque
/// occurrence draft, so resolve those positionally against the layer the save
/// wrote; rows the user has typed but not yet committed are already literals.
fn resolved_denylist(dialog: &SettingsDialog) -> Vec<String> {
    let persisted = ExtendedConfigDoc::load(&dialog.extended_path)
        .map(|document| document.config().redact.denylist)
        .unwrap_or_default();
    dialog
        .extended
        .redact
        .denylist
        .iter()
        .enumerate()
        .map(|(index, value)| {
            if value.starts_with(super::DENYLIST_EXISTING_DRAFT_PREFIX) {
                persisted.get(index).cloned().unwrap_or_default()
            } else {
                value.clone()
            }
        })
        .collect()
}

fn write_provider_file(config_path: &std::path::Path, provider_id: &str, json: &str) {
    let path =
        cockpit_config::providers::provider_file_path_for_config(config_path, provider_id).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, json).unwrap();
}

fn on_add_page(d: &SettingsDialog) -> bool {
    matches!(d.test_page(), TestPageRef::Providers(ProvidersPage::Add(_)))
}

fn on_list_page(d: &SettingsDialog) -> bool {
    matches!(
        d.test_page(),
        TestPageRef::Providers(ProvidersPage::List { .. })
    )
}

fn on_root_page(d: &SettingsDialog) -> bool {
    matches!(d.test_page(), TestPageRef::Root { .. })
}

#[cfg(unix)]
#[test]
fn save_extended_repairs_private_config_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let _env = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let config_dir = tmp.path().join("home/.cockpit");
    std::fs::create_dir(&config_dir).unwrap();
    let config_path = config_dir.join("config.json");
    std::fs::write(&config_path, "{}").unwrap();
    let mut d = SettingsDialog::open(config_path);
    std::fs::set_permissions(&d.extended_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    d.extended.redact.denylist = vec!["secret-value".to_string()];
    d.save_extended().unwrap();

    let file_mode = std::fs::metadata(&d.extended_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let dir_mode = std::fs::metadata(&config_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o600);
    assert_eq!(dir_mode, 0o700);
}

#[cfg(unix)]
#[test]
fn save_extended_preserves_explicit_shared_parent_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let env = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let shared_parent = tmp.path().join("shared");
    std::fs::create_dir(&shared_parent).unwrap();
    std::fs::set_permissions(&shared_parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config_path = shared_parent.join("cockpit.json");
    std::fs::write(&config_path, "{}").unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    env.set_cockpit_config(&config_path);

    let mut dialog = SettingsDialog::open(config_path.clone());
    dialog.extended.redact.denylist = vec!["secret-value".to_string()];
    dialog.save_extended().unwrap();

    let file_mode = std::fs::metadata(config_path).unwrap().permissions().mode() & 0o777;
    let dir_mode = std::fs::metadata(shared_parent)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(file_mode, 0o600);
    assert_eq!(dir_mode, 0o755);
}

#[test]
fn pressing_a_from_providers_list_enters_add_wizard() {
    // Reproduces the "dialog freezes on a" bug — the original
    // implementation swapped the page out, then the inner handler
    // wrote `self.page = Add(...)` into the placeholder slot, and
    // the outer's unconditional swap-back discarded that write.
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.enter_providers();
    assert!(on_list_page(&d));
    let close = d.handle_key(press(KeyCode::Char('a')));
    assert!(!close);
    assert!(
        on_add_page(&d),
        "after pressing `a` the dialog should be on the Add wizard, not stuck on List"
    );
}

#[test]
fn pressing_esc_in_add_wizard_returns_to_list() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.enter_providers();
    d.handle_key(press(KeyCode::Char('a')));
    assert!(on_add_page(&d));
    d.handle_key(press(KeyCode::Esc));
    assert!(on_list_page(&d), "Esc from Add should return to List");
}

#[test]
fn pressing_left_from_providers_list_returns_to_root() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.enter_providers();
    d.handle_key(press(KeyCode::Left));
    assert!(on_root_page(&d), "Left from Providers should land on Root");
}

#[test]
fn oauth_add_step_help_collapses_after_login() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    let mut codex =
        providers::OAuthFlowState::new_with_acknowledgement_for_test(OAuthProvider::Codex);
    codex.logged_in = true;
    let mut add = providers::AddState::new();
    add.enter_oauth_for_test(codex);
    d.set_test_page(Page::Providers(ProvidersPage::Add(add)));
    assert_eq!(d.help_text(), "enter: acknowledge  esc: back");

    let mut grok =
        providers::OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    grok.logged_in = false;
    let mut add = providers::AddState::new();
    add.enter_oauth_for_test(grok);
    d.set_test_page(Page::Providers(ProvidersPage::Add(add)));
    assert_eq!(
        d.help_text(),
        "↑/↓/Tab/Shift+Tab  enter: choose  s: skip/continue  esc: back"
    );
}

#[test]
fn paste_routes_to_add_grok_oauth_manual_input() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    let mut grok =
        providers::OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    grok.paste_focused = true;
    grok.set_browser_session_for_test("https://x.ai/oauth/authorize?state=abc");
    let mut add = providers::AddState::new();
    add.enter_oauth_for_test(grok);
    d.set_test_page(Page::Providers(ProvidersPage::Add(add)));

    d.paste("http://127.0.0.1/callback?code=abc123&state=s\nignored");

    let TestPageRef::Providers(ProvidersPage::Add(add)) = d.test_page() else {
        panic!("expected Add provider page");
    };
    let grok = add.oauth_auth.as_ref().expect("expected OAuth add step");
    assert_eq!(
        grok.manual_input.text(),
        "http://127.0.0.1/callback?code=abc123&state=s"
    );
}

#[test]
fn paste_routes_to_standalone_grok_oauth_manual_input() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    let mut grok =
        providers::OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    grok.paste_focused = true;
    grok.set_browser_session_for_test("https://x.ai/oauth/authorize?state=abc");
    d.set_test_page(Page::Providers(ProvidersPage::OAuthSetup {
        state: Box::new(grok),
        parent: Box::new(providers::EditState::new(
            "grok-oauth".to_string(),
            Default::default(),
        )),
    }));

    d.paste("manual-code");

    let TestPageRef::Providers(ProvidersPage::OAuthSetup { state, .. }) = d.test_page() else {
        panic!("expected standalone Grok OAuth page");
    };
    assert_eq!(state.manual_input.text(), "manual-code");
}

#[test]
fn grok_and_codex_oauth_render_register_link_regions() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);

    let mut grok =
        providers::OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    grok.set_browser_session_for_test("https://x.ai/oauth/authorize?state=abc");
    d.set_test_page(Page::Providers(ProvidersPage::OAuthSetup {
        state: Box::new(grok),
        parent: Box::new(providers::EditState::new(
            "grok-oauth".to_string(),
            Default::default(),
        )),
    }));
    let links = render_settings_links(&d, 96, 24);
    assert_eq!(links.regions().len(), 1);
    assert_eq!(
        links.regions()[0].url,
        "https://x.ai/oauth/authorize?state=abc"
    );
    assert_eq!(links.regions()[0].rect.height, 1);
    assert_eq!(links.regions()[0].label, "open xai.com authorization page");
    let mut grok_confirming =
        providers::OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    grok_confirming.set_browser_session_for_test("https://x.ai/oauth/authorize?state=abc");
    grok_confirming.apply_complete(Ok(true));
    d.set_test_page(Page::Providers(ProvidersPage::OAuthSetup {
        state: Box::new(grok_confirming),
        parent: Box::new(providers::EditState::new(
            "grok-oauth".to_string(),
            Default::default(),
        )),
    }));
    let links = render_settings_links(&d, 96, 24);
    assert_eq!(links.regions().len(), 0);

    let mut codex =
        providers::OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
    codex.set_device_login_for_test(cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
        "https://microsoft.com/devicelogin",
        "ABCD-EFGH",
    ));
    d.set_test_page(Page::Providers(ProvidersPage::OAuthSetup {
        state: Box::new(codex),
        parent: Box::new(providers::EditState::new(
            "codex-oauth".to_string(),
            Default::default(),
        )),
    }));
    let links = render_settings_links(&d, 96, 24);
    assert_eq!(links.regions().len(), 1);
    assert_eq!(links.regions()[0].url, "https://microsoft.com/devicelogin");
    assert_eq!(links.regions()[0].rect.height, 1);
    assert_eq!(
        links.regions()[0].label,
        "https://microsoft.com/devicelogin"
    );

    let mut codex_confirming =
        providers::OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
    codex_confirming.set_device_login_for_test(
        cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
            "https://microsoft.com/devicelogin",
            "ABCD-EFGH",
        ),
    );
    codex_confirming.apply_complete(Ok(true));
    d.set_test_page(Page::Providers(ProvidersPage::OAuthSetup {
        state: Box::new(codex_confirming),
        parent: Box::new(providers::EditState::new(
            "codex-oauth".to_string(),
            Default::default(),
        )),
    }));
    let links = render_settings_links(&d, 96, 24);
    assert_eq!(links.regions().len(), 0);
}

// ── Category-page tests (reorganized /settings) ────────────────────

use category::{Category, SettingId};

/// Open a category page on `d` with the cursor on `id`'s row.
pub(super) fn open_category_on(d: &mut SettingsDialog, category: Category, id: SettingId) {
    d.enter_category(category);
    if let TestPageMut::Category(p) = d.test_page_mut() {
        p.cursor = p
            .cursor_of(id)
            .unwrap_or_else(|| panic!("setting {id:?} not on {category:?}"));
    } else {
        panic!("not on a category page");
    }
}

#[test]
fn category_commit_text_contract_keeps_invalid_edit_open() {
    use super::descriptor::SettingStore;
    use category::CategorySettingStore;

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    let mut page = category::CategoryPage::new(Category::Interface);
    let mut store = CategorySettingStore {
        dialog: &mut d,
        page: &mut page,
    };

    let err = store
        .commit_text(SettingId::ExitTailLines, "bad")
        .expect_err("invalid numeric text is rejected");
    assert_eq!(err, "must be a whole number (-1, 0, or a line count)");

    store
        .commit_text(SettingId::ExitTailLines, "7")
        .expect("valid numeric text commits");
    assert_eq!(
        store.value(SettingId::ExitTailLines),
        "7 (lines of tail dumped to scrollback on exit; 0 none, -1 all)"
    );
}

fn category_cursor(d: &SettingsDialog) -> Option<usize> {
    match d.test_page() {
        TestPageRef::Category(p) => Some(p.cursor),
        _ => None,
    }
}

fn line_text(line: &Line<'static>) -> String {
    line.spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect()
}

pub(super) fn render_settings_rows(d: &SettingsDialog, width: u16, height: u16) -> Vec<String> {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("terminal");
    let mut links = crate::tui::links::LinkRegistry::default();
    terminal
        .draw(|frame| d.render(frame, Rect::new(0, 0, width, height), &mut links))
        .expect("draw");
    terminal
        .backend()
        .buffer()
        .content()
        .chunks(usize::from(width))
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect()
}

fn render_dialog_rows(d: &Dialog, width: u16, height: u16) -> Vec<String> {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("terminal");
    let mut links = crate::tui::links::LinkRegistry::default();
    terminal
        .draw(|frame| d.render(frame, Rect::new(0, 0, width, height), &mut links))
        .expect("draw");
    terminal
        .backend()
        .buffer()
        .content()
        .chunks(usize::from(width))
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect()
}

fn render_settings_links(
    d: &SettingsDialog,
    width: u16,
    height: u16,
) -> crate::tui::links::LinkRegistry {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("terminal");
    let mut links = crate::tui::links::LinkRegistry::default();
    terminal
        .draw(|frame| d.render(frame, Rect::new(0, 0, width, height), &mut links))
        .expect("draw");
    links
}

fn rendered_char(row: &str, x: u16) -> char {
    row.chars().nth(usize::from(x)).unwrap_or(' ')
}

pub(super) fn settings_mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

/// Render height for pointer-acceptance tools-page fixtures.
///
/// The tools page renders the whole built-in inventory (45 tools across 14
/// families) plus the web/user/MCP sections and the bottom contextual detail
/// controls (`[Enable/disable]`, `[Delete]`, `[Reset field]`). The inventory
/// is NOT 59 rows: `wrap_chunks` breaks each summary at the ~78-column value
/// width, and 10 long summaries (the Media + Image-Generation families —
/// `read_image`, `inspect_audio`, `extract_audio`, `extract_video_clip`,
/// `list_image_generation_targets`, `generate_image`,
/// `get_image_generation_job`, `cancel_image_generation_job`, plus `graph`
/// and `use_sealed_value`) wrap to two rows, so the built-in section alone is
/// 69 rows. Counting the section headers, web/user/MCP rows, the reset row and
/// the bottom detail controls, the tallest fixture (a user tool selected, so
/// the contextual `[Enable/disable]`/`[Delete]` pair sits last) is ~93 rows
/// with its deepest control at row index ~90. The settings dialog gives the
/// page a list body of `render_height - 4` rows (2 block borders + a header
/// row + a footer row), so any height short of ~95 scrolls those bottom
/// detail controls off-screen and `render_control_lines` never registers them
/// — which is exactly why 90 (body 86) still failed the exhaustiveness
/// assertions. Render these fixtures tall enough that every page fits on
/// screen (offset stays 0) and every control target is registered.
const POINTER_TOOLS_FIXTURE_HEIGHT: u16 = 120;

/// Real rendered/reducer regressions reused by the named pointer acceptance
/// suites. Keeping these here lets them share the same concrete page fixtures
/// as the keyboard contract instead of rebuilding synthetic registries.
pub(super) fn run_pointer_dialog_regression_matrix() {
    render_all_non_provider_pointer_surface_variants();
    pointer_standalone_root_actions_dispatch_from_fresh_sources();
    pointer_default_model_actions_dispatch_from_fresh_sources();
    pointer_lsp_save_actions_dispatch_from_fresh_sources();
    pointer_skills_action_family_dispatches_from_fresh_sources();
    pointer_mcp_action_family_dispatches_from_fresh_sources();
    pointer_tool_credential_family_dispatches_from_fresh_sources();
    pointer_tool_custom_command_family_dispatches_from_fresh_sources();
    pointer_user_tool_action_family_dispatches_from_fresh_sources();
    pointer_tool_field_reset_family_dispatches_from_fresh_sources();
    pointer_read_only_tool_sources_render_disabled();
    pointer_harness_list_actions_dispatch_from_fresh_sources();
    pointer_harness_field_actions_dispatch_from_fresh_sources();
    pointer_harness_editor_lifecycle_dispatches_from_fresh_sources();
    pointer_instruction_list_actions_dispatch_from_fresh_sources();
    pointer_redact_pattern_rows_dispatch_from_fresh_sources();
    pointer_string_list_action_families_dispatch_from_fresh_sources();
    pointer_generation_action_family_dispatches_from_fresh_sources();
    root_settings_pointer_uses_rendered_semantic_targets_and_clamped_wheel();
    category_short_viewport_keeps_bottom_reset_row_visible();
    nav_stack_restores_behavior_cursor_and_scroll_from_instructions();
    nav_stack_restores_privacy_and_string_list_parents();
    root_children_restore_their_own_root_cursor();
    instructions_enter_grabs_existing_row_then_arrow_swaps();
    string_list_keyboard_delete_remains_immediate();
    tools_reset_arms_then_clears_custom_web_commands_and_drops_custom_tools();
    tools_reset_pending_cancelled_by_navigation();
    lsp_reset_r_once_arms_without_wiping();
    lsp_reset_r_twice_restores_defaults();
    lsp_reset_pending_cancelled_by_navigation();
    category_reset_pending_cancelled_by_navigation();
}

fn dialog_with_generation_page(tmp: &TempDir, page: PageBox) -> SettingsDialog {
    let mut dialog = fresh_dialog(tmp);
    dialog.extended.tui.mouse_capture = true;
    dialog.page = page;
    dialog
}

fn generation_pointer_job_reducer() -> image_generation::JobReducer {
    let mut reducer = image_generation::JobReducer::new("d".into(), "p".into(), "s".into());
    reducer.jobs.push(image_generation::JobCard {
        job_id: "j1".into(),
        version: 1,
        state: image_generation::ImageJobState::Running,
        slots: Vec::new(),
        quarantined_late_result_count: 1,
        stale: false,
    });
    reducer
}

fn pointer_generation_action_family_dispatches_from_fresh_sources() {
    use pointer_actions::SettingsPointerAction;

    let builders: [fn(&TempDir) -> SettingsDialog; 10] = [
        |tmp| {
            dialog_with_generation_page(
                tmp,
                image_generation::generation_list_page(
                    image_generation::GenerationPrincipal::local_owner(),
                ),
            )
        },
        |tmp| {
            dialog_with_generation_page(
                tmp,
                Box::new(image_generation::EndpointEditorPage {
                    cursor: 0,
                    principal: image_generation::GenerationPrincipal::local_owner(),
                    endpoint_id: Some("e1".into()),
                    viewport: image_generation::GenerationViewportMode::Full,
                }),
            )
        },
        |tmp| {
            dialog_with_generation_page(
                tmp,
                Box::new(image_generation::TargetEditorPage {
                    cursor: 0,
                    principal: image_generation::GenerationPrincipal::local_owner(),
                    target_id: Some("t1".into()),
                    viewport: image_generation::GenerationViewportMode::Full,
                }),
            )
        },
        |tmp| {
            dialog_with_generation_page(
                tmp,
                Box::new(image_generation::WorkflowEditorPage {
                    cursor: 0,
                    principal: image_generation::GenerationPrincipal::local_owner(),
                    workflow_id: Some("w1".into()),
                    viewport: image_generation::GenerationViewportMode::Full,
                }),
            )
        },
        |tmp| {
            dialog_with_generation_page(
                tmp,
                image_generation::budget_editor_page(
                    image_generation::GenerationPrincipal::local_owner(),
                ),
            )
        },
        |tmp| {
            dialog_with_generation_page(
                tmp,
                Box::new(image_generation::GrantListPage {
                    cursor: 0,
                    principal: image_generation::GenerationPrincipal::local_owner(),
                    grants: vec![image_generation::DestinationGrantRow {
                        grant_id: "g1".into(),
                        generation: "1".into(),
                        project_id: "p".into(),
                        destination_identity_digest: "deadbeef".into(),
                        state: image_generation::GrantState::Active,
                        expiry: None,
                    }],
                    confirm: Some((
                        pointer_actions::GenerationAction::RevokeGrant(
                            pointer_actions::LateResultId("g1".into()),
                        ),
                        pointer_actions::ConfirmationChoice::Confirm,
                    )),
                    viewport: image_generation::GenerationViewportMode::Full,
                }),
            )
        },
        |tmp| {
            dialog_with_generation_page(
                tmp,
                Box::new(image_generation::JobDetailPage {
                    cursor: 0,
                    principal: image_generation::GenerationPrincipal::local_owner(),
                    job_id: "j1".into(),
                    reducer: generation_pointer_job_reducer(),
                    confirm: Some((
                        pointer_actions::GenerationAction::CancelJob(pointer_actions::ImageJobId(
                            "j1".into(),
                        )),
                        pointer_actions::ConfirmationChoice::Confirm,
                    )),
                    viewport: image_generation::GenerationViewportMode::Full,
                }),
            )
        },
        |tmp| {
            dialog_with_generation_page(
                tmp,
                Box::new(image_generation::LateResultActionPage {
                    cursor: 0,
                    principal: image_generation::GenerationPrincipal::local_owner(),
                    late_result_id: "r1".into(),
                    action: image_generation::LateResultAction::Publish,
                    confirm: None,
                    viewport: image_generation::GenerationViewportMode::Full,
                }),
            )
        },
        |tmp| {
            dialog_with_generation_page(
                tmp,
                Box::new(image_generation::LateResultActionPage {
                    cursor: 0,
                    principal: image_generation::GenerationPrincipal::local_owner(),
                    late_result_id: "r1".into(),
                    action: image_generation::LateResultAction::Discard,
                    confirm: None,
                    viewport: image_generation::GenerationViewportMode::Full,
                }),
            )
        },
        |tmp| {
            dialog_with_generation_page(
                tmp,
                Box::new(image_generation::GrantListPage {
                    cursor: 0,
                    principal: image_generation::GenerationPrincipal::local_owner(),
                    grants: vec![image_generation::DestinationGrantRow {
                        grant_id: "g1".into(),
                        generation: "1".into(),
                        project_id: "p".into(),
                        destination_identity_digest: "deadbeef".into(),
                        state: image_generation::GrantState::Active,
                        expiry: None,
                    }],
                    confirm: None,
                    viewport: image_generation::GenerationViewportMode::Full,
                }),
            )
        },
    ];

    for build in builders {
        let tmp = TempDir::new().unwrap();
        let source = build(&tmp);
        let _ = render_settings_rows(&source, 100, 40);
        let actions = source
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .filter_map(|target| match (&target.action, target.enabled) {
                (
                    shell::SettingsPointerAction::Page(
                        action @ SettingsPointerAction::Generation(_),
                    ),
                    true,
                ) => Some(action.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            !actions.is_empty(),
            "generation fixture must publish enabled actions"
        );
        for action in actions {
            let tmp = TempDir::new().unwrap();
            let mut dialog = build(&tmp);
            click_settings_action(&mut dialog, &action);
        }
    }
}

fn pointer_string_list_action_families_dispatch_from_fresh_sources() {
    use pointer_actions::{ListAction, ListKind, ListRowId, SettingsPointerAction};
    use string_list::{StringListKind, StringListPage};

    fn fixture(tmp: &TempDir, kind: StringListKind) -> SettingsDialog {
        let mut dialog = fresh_dialog(tmp);
        match kind {
            StringListKind::AgentDirs => {
                dialog.extended.agent_dirs = vec!["alpha".into(), "beta".into()]
            }
            StringListKind::ExtraDotenvPaths => {
                dialog.extended.redact.extra_dotenv_paths = vec!["alpha".into(), "beta".into()]
            }
            StringListKind::RedactDenylist => {
                dialog.extended.redact.denylist = vec!["alpha".into(), "beta".into()]
            }
            StringListKind::RedactAllowlist => {
                dialog.extended.redact.allowlist = vec!["ALPHA".into(), "BETA".into()]
            }
            StringListKind::GitignoreAllow => {
                dialog.extended.gitignore_allow = vec!["alpha/**".into(), "beta/**".into()]
            }
        }
        let page = match kind {
            StringListKind::AgentDirs => StringListPage::agent_dirs(),
            StringListKind::ExtraDotenvPaths => StringListPage::extra_dotenv_paths(),
            StringListKind::RedactDenylist => StringListPage::redact_denylist(),
            StringListKind::RedactAllowlist => StringListPage::redact_allowlist(),
            StringListKind::GitignoreAllow => StringListPage::gitignore_allow(),
        };
        dialog.set_test_page(Page::StringList(Box::new(page)));
        dialog
    }

    fn values(dialog: &SettingsDialog, kind: StringListKind) -> Vec<String> {
        match kind {
            StringListKind::AgentDirs => dialog
                .extended
                .agent_dirs
                .iter()
                .map(|value| value.display().to_string())
                .collect(),
            StringListKind::ExtraDotenvPaths => dialog
                .extended
                .redact
                .extra_dotenv_paths
                .iter()
                .map(|value| value.display().to_string())
                .collect(),
            StringListKind::RedactDenylist => resolved_denylist(dialog),
            StringListKind::RedactAllowlist => dialog.extended.redact.allowlist.clone(),
            StringListKind::GitignoreAllow => dialog.extended.gitignore_allow.clone(),
        }
    }

    fn persisted_values(dialog: &SettingsDialog, kind: StringListKind) -> Vec<String> {
        let config = ExtendedConfigDoc::load(&dialog.extended_path)
            .expect("persisted string-list config")
            .config();
        match kind {
            StringListKind::AgentDirs => config
                .agent_dirs
                .iter()
                .map(|value| value.display().to_string())
                .collect(),
            StringListKind::ExtraDotenvPaths => config
                .redact
                .extra_dotenv_paths
                .iter()
                .map(|value| value.display().to_string())
                .collect(),
            StringListKind::RedactDenylist => config.redact.denylist,
            StringListKind::RedactAllowlist => config.redact.allowlist,
            StringListKind::GitignoreAllow => config.gitignore_allow,
        }
    }

    let kinds = [
        StringListKind::AgentDirs,
        StringListKind::ExtraDotenvPaths,
        StringListKind::RedactDenylist,
        StringListKind::RedactAllowlist,
        StringListKind::GitignoreAllow,
    ];
    for kind in kinds {
        let source_tmp = TempDir::new().unwrap();
        let source = fixture(&source_tmp, kind);
        let _ = render_settings_rows(&source, 100, 40);
        assert!(matches!(
            source.test_page(),
            TestPageRef::StringList(page) if page.kind == kind
        ));
        let actions = source
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .filter_map(|target| match (&target.action, target.enabled) {
                (
                    shell::SettingsPointerAction::Page(action @ SettingsPointerAction::List(_)),
                    true,
                ) => Some(action.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, SettingsPointerAction::List(ListAction::Add)))
        );
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(action, SettingsPointerAction::List(ListAction::Edit(_))))
                .count(),
            2
        );
        assert_eq!(
            actions
                .iter()
                .filter(|action| matches!(
                    action,
                    SettingsPointerAction::List(ListAction::Delete(_))
                ))
                .count(),
            2,
            "each concrete list publishes both stable delete identities"
        );
        let expected_ids = values(&source, kind)
            .into_iter()
            .enumerate()
            .map(|(index, value)| ListRowId {
                kind: ListKind::String(kind),
                index,
                value,
            })
            .collect::<std::collections::HashSet<_>>();
        for ids in [
            actions
                .iter()
                .filter_map(|action| match action {
                    SettingsPointerAction::List(ListAction::Edit(id)) => Some(id.clone()),
                    _ => None,
                })
                .collect::<std::collections::HashSet<_>>(),
            actions
                .iter()
                .filter_map(|action| match action {
                    SettingsPointerAction::List(ListAction::Delete(id)) => Some(id.clone()),
                    _ => None,
                })
                .collect::<std::collections::HashSet<_>>(),
        ] {
            assert_eq!(
                ids, expected_ids,
                "row payloads preserve exact source identity"
            );
        }

        let mut harvested = actions
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        let mut dispatched = harvested.clone();
        for action in actions {
            let tmp = TempDir::new().unwrap();
            let mut dialog = fixture(&tmp, kind);
            let before = values(&dialog, kind);
            let disk_before = std::fs::read(&dialog.extended_path).ok();
            click_settings_action(&mut dialog, &action);
            match &action {
                SettingsPointerAction::List(ListAction::Delete(id)) => {
                    dialog.handle_key(press(KeyCode::Char('d')));
                    let after = values(&dialog, kind);
                    assert_eq!(after.len(), 1);
                    assert!(!after.contains(&id.value));
                    assert_eq!(after[0], before[1usize.saturating_sub(id.index)]);
                    assert_eq!(persisted_values(&dialog, kind), after);
                    assert_ne!(std::fs::read(&dialog.extended_path).ok(), disk_before);
                }
                SettingsPointerAction::List(ListAction::Add) => {
                    type_chars(&mut dialog, "gamma");
                    click_settings_action(
                        &mut dialog,
                        &SettingsPointerAction::List(ListAction::Save),
                    );
                    let mut expected = before.clone();
                    expected.push("gamma".into());
                    assert_eq!(values(&dialog, kind), expected);
                    assert_eq!(persisted_values(&dialog, kind), expected);
                    assert_ne!(std::fs::read(&dialog.extended_path).ok(), disk_before);
                }
                SettingsPointerAction::List(ListAction::Edit(id)) => {
                    assert!(matches!(
                        dialog.test_page(),
                        TestPageRef::StringList(page) if page.grabbed.is_some()
                    ));
                    type_chars(&mut dialog, "discarded");
                    click_settings_action(
                        &mut dialog,
                        &SettingsPointerAction::List(ListAction::Cancel),
                    );
                    assert_eq!(values(&dialog, kind), before);
                    assert_eq!(std::fs::read(&dialog.extended_path).ok(), disk_before);

                    let save_tmp = TempDir::new().unwrap();
                    let mut save_dialog = fixture(&save_tmp, kind);
                    let save_before = values(&save_dialog, kind);
                    let save_disk_before = std::fs::read(&save_dialog.extended_path).ok();
                    click_settings_action(&mut save_dialog, &action);
                    type_chars(&mut save_dialog, "updated");
                    click_settings_action(
                        &mut save_dialog,
                        &SettingsPointerAction::List(ListAction::Save),
                    );
                    let after = values(&save_dialog, kind);
                    let mut expected = save_before.clone();
                    expected[id.index] = if kind == StringListKind::RedactDenylist {
                        "updated".into()
                    } else {
                        format!("{}updated", save_before[id.index])
                    };
                    assert_eq!(after, expected);
                    assert_eq!(persisted_values(&save_dialog, kind), expected);
                    assert_ne!(
                        std::fs::read(&save_dialog.extended_path).ok(),
                        save_disk_before
                    );
                }
                _ => {}
            }
        }
        dispatched.extend([
            SettingsPointerAction::List(ListAction::Save),
            SettingsPointerAction::List(ListAction::Cancel),
        ]);

        let initial_tmp = TempDir::new().unwrap();
        let initial = values(&fixture(&initial_tmp, kind), kind);
        let row_id = |index: usize| ListRowId {
            kind: ListKind::String(kind),
            index,
            value: initial[index].clone(),
        };
        let move_cases = [
            (
                SettingsPointerAction::List(ListAction::Edit(row_id(0))),
                SettingsPointerAction::List(ListAction::MoveDown(row_id(0))),
                false,
            ),
            (
                SettingsPointerAction::List(ListAction::Edit(row_id(1))),
                SettingsPointerAction::List(ListAction::MoveUp(row_id(1))),
                false,
            ),
            (
                SettingsPointerAction::List(ListAction::Add),
                SettingsPointerAction::List(ListAction::MoveUp(ListRowId {
                    kind: ListKind::String(kind),
                    index: 2,
                    value: String::new(),
                })),
                true,
            ),
        ];
        for (begin, movement, added) in move_cases {
            let source_tmp = TempDir::new().unwrap();
            let mut source = fixture(&source_tmp, kind);
            click_settings_action(&mut source, &begin);
            let _ = render_settings_rows(&source, 100, 40);
            harvested.extend(
                source
                    .pointer_surface
                    .targets
                    .borrow()
                    .iter()
                    .filter_map(|target| match (&target.action, target.enabled) {
                        (
                            shell::SettingsPointerAction::Page(
                                action @ SettingsPointerAction::List(_),
                            ),
                            true,
                        ) => Some(action.clone()),
                        _ => None,
                    }),
            );
            assert!(
                source
                    .pointer_surface
                    .targets
                    .borrow()
                    .iter()
                    .any(|target| {
                        target.enabled
                            && target.action == shell::SettingsPointerAction::Page(movement.clone())
                    })
            );

            let tmp = TempDir::new().unwrap();
            let mut dialog = fixture(&tmp, kind);
            let disk_before = std::fs::read(&dialog.extended_path).ok();
            click_settings_action(&mut dialog, &begin);
            click_settings_action(&mut dialog, &movement);
            dispatched.insert(movement.clone());
            if added {
                type_chars(&mut dialog, "gamma");
            }
            let expected = if added {
                vec![initial[0].clone(), "gamma".into(), initial[1].clone()]
            } else {
                vec![initial[1].clone(), initial[0].clone()]
            };
            dialog.handle_key(press(KeyCode::Enter));
            assert_eq!(values(&dialog, kind), expected);
            assert_eq!(persisted_values(&dialog, kind), expected);
            assert_ne!(std::fs::read(&dialog.extended_path).ok(), disk_before);
        }
        assert_eq!(
            harvested, dispatched,
            "every enabled identity from each closed list source state is replayed"
        );
    }
}

fn pointer_tool_credential_family_dispatches_from_fresh_sources() {
    use pointer_actions::{CredentialKind, SettingsPointerAction, ToolsAction};
    for credential in CredentialKind::ALL {
        let tmp = TempDir::new().unwrap();
        let mut dialog = standalone_pointer_dialog(&tmp, "Tools");
        enter_root_node(&mut dialog, "Tools");
        dialog.extended.web.provider = match credential {
            CredentialKind::Firecrawl => cockpit_config::extended::WebProvider::Firecrawl,
            CredentialKind::TinyFish => cockpit_config::extended::WebProvider::Tinyfish,
        };
        let action = SettingsPointerAction::Tools(ToolsAction::EditCredential(credential));
        click_settings_action(&mut dialog, &action);
        let expected = match credential {
            CredentialKind::Firecrawl => tools_page::WebKeyProvider::Firecrawl,
            CredentialKind::TinyFish => tools_page::WebKeyProvider::TinyFish,
        };
        assert!(matches!(
            dialog.test_page(),
            TestPageRef::Tools(page)
                if page.editing == Some(tools_page::ToolField::WebKey(expected))
        ));
    }
}

fn pointer_tool_custom_command_family_dispatches_from_fresh_sources() {
    use pointer_actions::{SettingsPointerAction, ToolsAction};
    for (action, expected) in [
        (
            ToolsAction::EditWebFetchCommand,
            tools_page::ToolField::WebFetchCommand,
        ),
        (
            ToolsAction::EditWebSearchCommand,
            tools_page::ToolField::WebSearchCommand,
        ),
    ] {
        let source_tmp = TempDir::new().unwrap();
        let mut source = standalone_pointer_dialog(&source_tmp, "Tools");
        enter_root_node(&mut source, "Tools");
        source.extended.web.provider = cockpit_config::extended::WebProvider::Custom;
        let _ = render_settings_rows(&source, 100, 80);
        let expected_action = SettingsPointerAction::Tools(action.clone());
        assert!(source.pointer_surface.targets.borrow().iter().any(|target| {
            target.enabled
                && matches!(
                    &target.action,
                    shell::SettingsPointerAction::Page(rendered) if rendered == &expected_action
                )
        }));

        let dispatch_tmp = TempDir::new().unwrap();
        let mut dialog = standalone_pointer_dialog(&dispatch_tmp, "Tools");
        enter_root_node(&mut dialog, "Tools");
        dialog.extended.web.provider = cockpit_config::extended::WebProvider::Custom;
        click_settings_action(&mut dialog, &expected_action);
        assert!(matches!(
            dialog.test_page(),
            TestPageRef::Tools(page) if page.editing.as_ref() == Some(&expected)
        ));
    }
}

fn pointer_user_tool_action_family_dispatches_from_fresh_sources() {
    use cockpit_config::extended::ToolCommandTemplate;
    use pointer_actions::{SettingsPointerAction, ToolsAction, UserToolId};

    fn dialog_with_user_tool(tmp: &TempDir) -> SettingsDialog {
        let mut dialog = standalone_pointer_dialog(tmp, "Tools");
        enter_root_node(&mut dialog, "Tools");
        dialog.extended.tools.insert(
            "pointer-tool".into(),
            ToolCommandTemplate {
                enabled: true,
                command: "printf pointer".into(),
                description: Some("pointer acceptance fixture".into()),
            },
        );
        set_tools_cursor_to_label(&mut dialog, "pointer-tool");
        dialog
    }

    let id = UserToolId("pointer-tool".into());
    let actions = [
        ToolsAction::EditUserToolCommand(id.clone()),
        ToolsAction::ToggleUserTool(id.clone()),
        ToolsAction::DeleteUserTool(id.clone()),
    ];
    let source_tmp = TempDir::new().unwrap();
    let source = dialog_with_user_tool(&source_tmp);
    let _ = render_settings_rows(&source, 100, POINTER_TOOLS_FIXTURE_HEIGHT);
    for action in &actions {
        let expected = SettingsPointerAction::Tools(action.clone());
        assert!(
            source
                .pointer_surface
                .targets
                .borrow()
                .iter()
                .any(|target| {
                    target.enabled
                        && matches!(
                            &target.action,
                            shell::SettingsPointerAction::Page(rendered) if rendered == &expected
                        )
                })
        );
    }

    for action in actions {
        let dispatch_tmp = TempDir::new().unwrap();
        let mut dialog = dialog_with_user_tool(&dispatch_tmp);
        click_settings_action(&mut dialog, &SettingsPointerAction::Tools(action.clone()));
        match action {
            ToolsAction::EditUserToolCommand(_) => assert!(matches!(
                dialog.test_page(),
                TestPageRef::Tools(page)
                    if page.editing
                        == Some(tools_page::ToolField::UserToolCommand("pointer-tool".into()))
            )),
            ToolsAction::ToggleUserTool(_) => assert!(
                !dialog
                    .extended
                    .tools
                    .get("pointer-tool")
                    .expect("pointer tool remains present")
                    .enabled
            ),
            ToolsAction::DeleteUserTool(_) => assert!(matches!(
                dialog.test_page(),
                TestPageRef::Tools(page) if page.delete_pending.as_deref() == Some("pointer-tool")
            )),
            _ => unreachable!("sealed user-tool action family"),
        }
    }
}

fn pointer_tool_field_reset_family_dispatches_from_fresh_sources() {
    use pointer_actions::{SettingsPointerAction, ToolFieldId, ToolsAction};

    fn dialog_for_field(tmp: &TempDir, field: ToolFieldId) -> SettingsDialog {
        let mut dialog = standalone_pointer_dialog(tmp, "Tools");
        enter_root_node(&mut dialog, "Tools");
        dialog.extended.web.firecrawl_base_url = Some("https://pointer.invalid".into());
        dialog.extended.web.custom.fetch_command = Some("pointer-fetch {url}".into());
        dialog.extended.web.custom.search_command = Some("pointer-search {query}".into());
        let label = match field {
            ToolFieldId::FirecrawlBaseUrl => "base url",
            ToolFieldId::WebFetchCommand => {
                dialog.extended.web.provider = cockpit_config::extended::WebProvider::Custom;
                "webfetch"
            }
            ToolFieldId::WebSearchCommand => {
                dialog.extended.web.provider = cockpit_config::extended::WebProvider::Custom;
                "websearch"
            }
        };
        set_tools_cursor_to_label(&mut dialog, label);
        dialog
    }

    for field in [
        ToolFieldId::FirecrawlBaseUrl,
        ToolFieldId::WebFetchCommand,
        ToolFieldId::WebSearchCommand,
    ] {
        let action = SettingsPointerAction::Tools(ToolsAction::ResetToolField(field));
        let source_tmp = TempDir::new().unwrap();
        let source = dialog_for_field(&source_tmp, field);
        let _ = render_settings_rows(&source, 100, POINTER_TOOLS_FIXTURE_HEIGHT);
        assert!(
            source
                .pointer_surface
                .targets
                .borrow()
                .iter()
                .any(|target| {
                    target.enabled
                        && matches!(
                            &target.action,
                            shell::SettingsPointerAction::Page(rendered) if rendered == &action
                        )
                })
        );

        let dispatch_tmp = TempDir::new().unwrap();
        let mut dialog = dialog_for_field(&dispatch_tmp, field);
        click_settings_action(&mut dialog, &action);
        match field {
            ToolFieldId::FirecrawlBaseUrl => {
                assert_eq!(dialog.extended.web.firecrawl_base_url, None);
                assert_eq!(
                    dialog.extended.web.custom.fetch_command.as_deref(),
                    Some("pointer-fetch {url}")
                );
                assert_eq!(
                    dialog.extended.web.custom.search_command.as_deref(),
                    Some("pointer-search {query}")
                );
            }
            ToolFieldId::WebFetchCommand => {
                assert_eq!(dialog.extended.web.custom.fetch_command, None);
                assert_eq!(
                    dialog.extended.web.custom.search_command.as_deref(),
                    Some("pointer-search {query}")
                );
                assert_eq!(
                    dialog.extended.web.firecrawl_base_url.as_deref(),
                    Some("https://pointer.invalid")
                );
            }
            ToolFieldId::WebSearchCommand => {
                assert_eq!(dialog.extended.web.custom.search_command, None);
                assert_eq!(
                    dialog.extended.web.custom.fetch_command.as_deref(),
                    Some("pointer-fetch {url}")
                );
                assert_eq!(
                    dialog.extended.web.firecrawl_base_url.as_deref(),
                    Some("https://pointer.invalid")
                );
            }
        }
    }
}

fn pointer_read_only_tool_sources_render_disabled() {
    use pointer_actions::{SettingsPointerAction, ToolsAction};

    let tmp = TempDir::new().unwrap();
    let mut dialog = fresh_dialog(&tmp);
    enter_tools_from_root(&mut dialog);
    set_tools_cursor_to_label(&mut dialog, "read");
    let _ = render_settings_rows(&dialog, 100, 18);
    assert!(
        dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .any(|target| {
                !target.enabled
                    && matches!(
                        &target.action,
                        shell::SettingsPointerAction::Page(SettingsPointerAction::Tools(
                            ToolsAction::ReadOnlyBuiltin(id)
                        )) if id.0 == "read"
                    )
            })
    );

    let raw = r#"{"servers":{"docs":{"transport":"streamable","endpoint":"https://example.test/mcp","enabled":true}}}"#;
    let cfg = cockpit_core::mcp::config::McpConfig::parse(raw).unwrap();
    let server = cfg.servers.get("docs").unwrap();
    let cache_dir = tmp.path().join("mcp-cache");
    cockpit_core::mcp::cache::save_in(
        &cache_dir,
        &cockpit_core::mcp::cache::cache_key("docs", server),
        &[cockpit_core::mcp::protocol::ToolDescriptor {
            name: "lookup".into(),
            description: "Find docs".into(),
            input_schema: serde_json::json!({}),
        }],
    )
    .unwrap();
    dialog.mcp_cache_dir = Some(cache_dir);
    // The tools page renders the daemon-owned MCP snapshot cached on the
    // dialog, not a disk file. Seed it directly so the "docs" server's cached
    // tool inventory renders as a read-only row.
    dialog.mcp_config = cfg;
    set_tools_cursor_to_label(&mut dialog, "docs/lookup");
    let _ = render_settings_rows(&dialog, 100, 18);
    assert!(
        dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .any(|target| {
                !target.enabled
                    && matches!(
                        &target.action,
                        shell::SettingsPointerAction::Page(SettingsPointerAction::Tools(
                            ToolsAction::ReadOnlyMcpTool(server, tool)
                        )) if server.0 == "docs" && tool.0 == "lookup"
                    )
            })
    );
}

fn redact_patterns_pointer_fixture(tmp: &TempDir) -> SettingsDialog {
    let mut dialog = fresh_dialog(tmp);
    dialog.page = Box::new(RedactPatternsPage::new());
    dialog
}

fn pointer_redact_pattern_rows_dispatch_from_fresh_sources() {
    use pointer_actions::{ListAction, SettingsPointerAction};

    let source_tmp = TempDir::new().unwrap();
    let source = redact_patterns_pointer_fixture(&source_tmp);
    let expected_values = source.extended.redact.dotenv_patterns.clone();
    assert_eq!(expected_values, [".env", ".env.local"]);
    let _ = render_settings_rows(&source, 100, 40);
    let actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::List(
                        ListAction::Edit(_) | ListAction::Delete(_),
                    ),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(actions.len(), expected_values.len() * 2);

    for action in actions {
        let tmp = TempDir::new().unwrap();
        let mut dialog = redact_patterns_pointer_fixture(&tmp);
        match &action {
            SettingsPointerAction::List(ListAction::Edit(_)) => {
                click_settings_action(&mut dialog, &action);
                assert!(matches!(
                    dialog.test_page(),
                    TestPageRef::RedactPatterns(page) if page.grabbed.is_some()
                ));
                let _ = render_settings_rows(&dialog, 100, 40);
                let grabbed_actions = dialog
                    .pointer_surface
                    .targets
                    .borrow()
                    .iter()
                    .filter_map(|target| match (&target.action, target.enabled) {
                        (
                            shell::SettingsPointerAction::Page(
                                action @ SettingsPointerAction::List(
                                    ListAction::MoveUp(_)
                                    | ListAction::MoveDown(_)
                                    | ListAction::Save
                                    | ListAction::Cancel,
                                ),
                            ),
                            true,
                        ) => Some(action.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                assert_eq!(grabbed_actions.len(), 3);
                for grabbed_action in grabbed_actions {
                    let nested_tmp = TempDir::new().unwrap();
                    let mut nested = redact_patterns_pointer_fixture(&nested_tmp);
                    click_settings_action(&mut nested, &action);
                    click_settings_action(&mut nested, &grabbed_action);
                    match grabbed_action {
                        SettingsPointerAction::List(
                            ListAction::MoveUp(_) | ListAction::MoveDown(_),
                        ) => assert_ne!(
                            nested.extended.redact.dotenv_patterns, expected_values,
                            "enabled move changes row order"
                        ),
                        SettingsPointerAction::List(ListAction::Save | ListAction::Cancel) => {
                            assert!(matches!(
                                nested.test_page(),
                                TestPageRef::RedactPatterns(page) if page.grabbed.is_none()
                            ));
                            assert_eq!(nested.extended.redact.dotenv_patterns, expected_values);
                        }
                        _ => unreachable!(),
                    }
                }
            }
            SettingsPointerAction::List(ListAction::Delete(_)) => {
                click_settings_action(&mut dialog, &action);
                assert_eq!(dialog.extended.redact.dotenv_patterns, expected_values);
                assert!(matches!(
                    dialog.test_page(),
                    TestPageRef::RedactPatterns(page) if page.delete.is_pending_for(page.cursor)
                ));
                click_settings_action(&mut dialog, &action);
                assert_eq!(dialog.extended.redact.dotenv_patterns.len(), 1);
            }
            _ => unreachable!(),
        }
    }
}

fn pointer_standalone_root_actions_dispatch_from_fresh_sources() {
    use pointer_actions::{LspAction, McpAction, SettingsPointerAction, SkillsAction, ToolsAction};

    for title in ["Tools", "Skills", "MCP", "LSP"] {
        let source_tmp = TempDir::new().unwrap();
        let mut source = standalone_pointer_dialog(&source_tmp, title);
        enter_root_node(&mut source, title);
        // Render tall enough that the whole page fits (offset stays 0). The Tools
        // page's tail rows (`AddUserTool`/`Reset`/`McpJump`) sit below an 80-row
        // viewport now that the image-generation tool family grew the page, so a
        // short render scrolls them off and they never appear as enabled targets
        // to dispatch — the same invariant `click_settings_action` pins.
        let _ = render_settings_rows(&source, 100, POINTER_TOOLS_FIXTURE_HEIGHT);
        let actions = source
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .filter_map(|target| match (&target.action, target.enabled, title) {
                (
                    shell::SettingsPointerAction::Page(action @ SettingsPointerAction::Tools(_)),
                    true,
                    "Tools",
                )
                | (
                    shell::SettingsPointerAction::Page(action @ SettingsPointerAction::Skills(_)),
                    true,
                    "Skills",
                )
                | (
                    shell::SettingsPointerAction::Page(action @ SettingsPointerAction::Mcp(_)),
                    true,
                    "MCP",
                )
                | (
                    shell::SettingsPointerAction::Page(action @ SettingsPointerAction::Lsp(_)),
                    true,
                    "LSP",
                ) => Some(action.clone()),
                _ => None,
            })
            .collect::<std::collections::HashSet<_>>();
        assert!(
            !actions.is_empty(),
            "{title} source renders enabled actions"
        );

        for action in actions {
            let tmp = TempDir::new().unwrap();
            let mut dialog = standalone_pointer_dialog(&tmp, title);
            enter_root_node(&mut dialog, title);
            let before = serde_json::to_value(&dialog.extended).unwrap();
            let token_before = dialog.page.pointer_surface_token();
            click_settings_action(&mut dialog, &action);
            let config_changed = serde_json::to_value(&dialog.extended).unwrap() != before;
            let token_changed = dialog.page.pointer_surface_token() != token_before;
            let semantic_outcome = match (&action, dialog.test_page()) {
                (SettingsPointerAction::Tools(ToolsAction::CycleWebProvider), _) => config_changed,
                (
                    SettingsPointerAction::Tools(
                        ToolsAction::EditFirecrawlBaseUrl
                        | ToolsAction::EditCredential(_)
                        | ToolsAction::EditWebFetchCommand
                        | ToolsAction::EditWebSearchCommand
                        | ToolsAction::AddUserTool,
                    ),
                    TestPageRef::Tools(page),
                ) => page.editing.is_some(),
                (SettingsPointerAction::Tools(ToolsAction::Reset), TestPageRef::Tools(page)) => {
                    page.reset.is_pending()
                }
                (SettingsPointerAction::Tools(ToolsAction::McpJump), _) => token_changed,
                (
                    SettingsPointerAction::Skills(
                        SkillsAction::ToggleAutoBangCommands | SkillsAction::ToggleAncestorWalk,
                    ),
                    _,
                ) => config_changed,
                (
                    SettingsPointerAction::Skills(SkillsAction::AddScanDirectory),
                    TestPageRef::Skills(page),
                ) => page.grabbed.is_some(),
                (SettingsPointerAction::Skills(SkillsAction::Reset), TestPageRef::Skills(page)) => {
                    page.reset.is_pending()
                }
                (SettingsPointerAction::Mcp(McpAction::Add), _) => token_changed,
                (
                    SettingsPointerAction::Lsp(
                        LspAction::ToggleEnabled
                        | LspAction::CycleAutoInstall
                        | LspAction::ToggleDiagnostics,
                    ),
                    _,
                ) => config_changed,
                (SettingsPointerAction::Lsp(LspAction::Edit(_)), TestPageRef::Lsp(page)) => {
                    page.editing.is_some()
                }
                (SettingsPointerAction::Lsp(LspAction::Reset), TestPageRef::Lsp(page)) => {
                    page.reset.is_pending()
                }
                (
                    SettingsPointerAction::Lsp(
                        LspAction::Check(_)
                        | LspAction::Install(_)
                        | LspAction::Uninstall(_)
                        | LspAction::Restart(_),
                    ),
                    _,
                ) => dialog.pending_daemon_request.is_some(),
                _ => panic!("unclassified fresh standalone action {action:?}"),
            };
            assert!(semantic_outcome, "{action:?} produced no semantic outcome");
            // This matrix is the sole dispatch site for the standalone root
            // action buttons (e.g. Tools `AddUserTool`/`Reset`/`McpJump`); record
            // them so the exhaustiveness gate counts them as operable-and-dispatched
            // rather than flagging them as rendered-but-never-dispatched.
            super::pointer_acceptance_tests::record_dispatched_action(&action);
        }
    }
}

fn pointer_default_model_actions_dispatch_from_fresh_sources() {
    use pointer_actions::{DefaultModelAction, SettingsPointerAction};

    fn selected() -> cockpit_config::providers::ActiveModelRef {
        cockpit_config::providers::ActiveModelRef {
            provider: "vendor".into(),
            model: "m1".into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        }
    }

    fn fixture(tmp: &TempDir) -> SettingsDialog {
        let mut dialog = fresh_dialog(tmp);
        let selected = selected();
        dialog.config.active_model = Some(selected.clone());
        dialog.original_config.active_model = Some(selected);
        enter_root_node(&mut dialog, DEFAULT_MODEL_TITLE);
        dialog
    }

    let source_tmp = TempDir::new().unwrap();
    let source = fixture(&source_tmp);
    let rendered = render_settings_rows(&source, 100, 24).join("\n");
    assert!(
        rendered.contains("Effective default: vendor/m1"),
        "fixture renders its exact effective selection: {rendered}"
    );
    let actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                shell::SettingsPointerAction::Page(action @ SettingsPointerAction::DefaultModel(_)),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        actions,
        [
            SettingsPointerAction::DefaultModel(DefaultModelAction::Choose),
            SettingsPointerAction::DefaultModel(DefaultModelAction::Clear),
        ]
        .into_iter()
        .collect(),
        "configured default-model page exposes its complete action family"
    );

    let unset_tmp = TempDir::new().unwrap();
    let mut unset = fresh_dialog(&unset_tmp);
    enter_root_node(&mut unset, DEFAULT_MODEL_TITLE);
    let _ = render_settings_rows(&unset, 100, 24);
    let clear_targets = unset
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter(|target| {
            target.action
                == shell::SettingsPointerAction::Page(SettingsPointerAction::DefaultModel(
                    DefaultModelAction::Clear,
                ))
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(clear_targets.len(), 1, "unset default has one Clear source");
    assert!(
        !clear_targets[0].enabled,
        "unset default renders Clear disabled"
    );

    for action in actions {
        let tmp = TempDir::new().unwrap();
        let mut dialog = fixture(&tmp);
        let persisted_before = std::fs::read(tmp.path().join("config.json")).unwrap();
        let _ = render_settings_rows(&dialog, 100, 24);
        let targets = dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .filter(|target| {
                target.enabled
                    && target.action == shell::SettingsPointerAction::Page(action.clone())
            })
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            targets.len(),
            1,
            "default-model action has one exact source"
        );
        let target = &targets[0];
        let down = dialog.handle_pointer(settings_mouse(
            MouseEventKind::Down(MouseButton::Left),
            target.rect.x,
            target.rect.y,
        ));
        assert_eq!(down, SettingsPointerOutcome::Consumed);
        let up = dialog.handle_pointer(settings_mouse(
            MouseEventKind::Up(MouseButton::Left),
            target.rect.x,
            target.rect.y,
        ));
        match action {
            SettingsPointerAction::DefaultModel(DefaultModelAction::Choose) => {
                assert_eq!(up, SettingsPointerOutcome::Close);
                assert!(dialog.pending_default_model_picker);
                assert!(dialog.pending_daemon_request.is_none());
            }
            SettingsPointerAction::DefaultModel(DefaultModelAction::Clear) => {
                assert_eq!(up, SettingsPointerOutcome::Consumed);
                let staged = dialog.pending_default_model_update_id;
                assert!(matches!(
                    dialog.pending_daemon_request.as_ref(),
                    Some(Request::SetDefaultModel {
                        default_update_id,
                        provider: None,
                        model: None,
                        clear: true,
                        ..
                    }) if Some(*default_update_id) == staged
                ));
                assert!(matches!(
                    dialog.test_page(),
                    TestPageRef::DefaultModel(page)
                        if page.effective_default.as_ref() == Some(&selected())
                            && page.status.as_deref().is_some_and(|status| {
                            status.starts_with("Clearing the default for new sessions")
                        })
                ));
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            dialog.test_page(),
            TestPageRef::DefaultModel(page)
                if page.effective_default.as_ref() == Some(&selected())
        ));
        assert_eq!(
            dialog.handle_pointer(settings_mouse(
                MouseEventKind::Up(MouseButton::Left),
                target.rect.x,
                target.rect.y,
            )),
            SettingsPointerOutcome::Consumed
        );
        assert_eq!(
            dialog.config.active_model.as_ref(),
            Some(&selected()),
            "pointer action does not claim daemon persistence before completion"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("config.json")).unwrap(),
            persisted_before,
            "default-model actions leave persistence to the selected workflow"
        );
    }
}

fn pointer_lsp_save_actions_dispatch_from_fresh_sources() {
    use pointer_actions::{LspAction, LspEdit as PointerLspEdit, SettingsPointerAction};

    let edits = [
        PointerLspEdit::OtherFilesLimit,
        PointerLspEdit::PerFileLimit,
        PointerLspEdit::DebounceMs,
        PointerLspEdit::DocumentTimeoutMs,
        PointerLspEdit::WorkspaceTimeoutMs,
    ];
    for (index, edit) in edits.into_iter().enumerate() {
        let tmp = TempDir::new().unwrap();
        let mut dialog = standalone_pointer_dialog(&tmp, "LSP");
        enter_root_node(&mut dialog, "LSP");
        click_settings_action(
            &mut dialog,
            &SettingsPointerAction::Lsp(LspAction::Edit(edit)),
        );
        let value = 700 + index as u64;
        let TestPageMut::Lsp(page) = dialog.test_page_mut() else {
            panic!("LSP edit action must preserve its page")
        };
        page.buf.set(value.to_string());

        let _ = render_settings_rows(&dialog, 100, 80);
        let actions = dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .filter_map(|target| match (&target.action, target.enabled) {
                (
                    shell::SettingsPointerAction::Page(
                        action @ SettingsPointerAction::Lsp(LspAction::SaveEdit(rendered)),
                    ),
                    true,
                ) if *rendered == edit => Some(action.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(actions.len(), 1, "each LSP edit owns one exact save source");
        click_settings_action(&mut dialog, &actions[0]);

        let diagnostics = &dialog.extended.lsp.diagnostics;
        let saved = match edit {
            PointerLspEdit::OtherFilesLimit => diagnostics.other_files_limit as u64,
            PointerLspEdit::PerFileLimit => diagnostics.per_file_limit as u64,
            PointerLspEdit::DebounceMs => diagnostics.debounce_ms,
            PointerLspEdit::DocumentTimeoutMs => diagnostics.document_timeout_ms,
            PointerLspEdit::WorkspaceTimeoutMs => diagnostics.workspace_timeout_ms,
        };
        assert_eq!(saved, value, "LSP save applies its source field exactly");
        assert!(matches!(
            dialog.test_page(),
            TestPageRef::Lsp(page) if page.editing.is_none() && page.status.as_deref() == Some("saved")
        ));

        let cancel_tmp = TempDir::new().unwrap();
        let mut cancel_dialog = standalone_pointer_dialog(&cancel_tmp, "LSP");
        enter_root_node(&mut cancel_dialog, "LSP");
        let config_before = serde_json::to_value(&cancel_dialog.extended).unwrap();
        click_settings_action(
            &mut cancel_dialog,
            &SettingsPointerAction::Lsp(LspAction::Edit(edit)),
        );
        let TestPageMut::Lsp(page) = cancel_dialog.test_page_mut() else {
            panic!("LSP cancel fixture must enter its editor")
        };
        page.buf.set("999999");
        let _ = render_settings_rows(&cancel_dialog, 100, 80);
        let cancel_actions = cancel_dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .filter_map(|target| match (&target.action, target.enabled) {
                (
                    shell::SettingsPointerAction::Page(
                        action @ SettingsPointerAction::Lsp(LspAction::CancelEdit(rendered)),
                    ),
                    true,
                ) if *rendered == edit => Some(action.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            cancel_actions.len(),
            1,
            "each LSP edit owns one exact cancel source"
        );
        click_settings_action(&mut cancel_dialog, &cancel_actions[0]);
        assert_eq!(
            serde_json::to_value(&cancel_dialog.extended).unwrap(),
            config_before,
            "LSP cancel does not persist its draft"
        );
        assert!(matches!(
            cancel_dialog.test_page(),
            TestPageRef::Lsp(page)
                if page.editing.is_none() && page.buf.text().is_empty() && page.status.is_none()
        ));
    }
}

fn pointer_skills_action_family_dispatches_from_fresh_sources() {
    use cockpit_config::extended::{ExtendedConfigDoc, SkillsConfig};
    use pointer_actions::{ConfirmationChoice, SettingsPointerAction, SkillsAction};

    fn fixture(tmp: &TempDir) -> SettingsDialog {
        let mut dialog = fresh_dialog(tmp);
        enter_root_node(&mut dialog, "Skills");
        dialog.extended.skills.scan_dirs = vec!["alpha/skills".into(), "beta/skills".into()];
        dialog.extended.skills.auto_bang_commands = false;
        dialog.extended.skills.ancestor_walk = false;
        dialog
            .save_extended()
            .expect("persist Skills fixture baseline");
        dialog
    }

    fn persisted(dialog: &SettingsDialog) -> SkillsConfig {
        ExtendedConfigDoc::load(&dialog.extended_path)
            .expect("reload pointer-written Skills config")
            .config()
            .skills
    }

    fn snapshot(skills: &SkillsConfig) -> serde_json::Value {
        serde_json::to_value(skills).expect("serialize Skills assertion snapshot")
    }

    let source_tmp = TempDir::new().unwrap();
    let source = fixture(&source_tmp);
    let _ = render_settings_rows(&source, 100, 80);
    let actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                shell::SettingsPointerAction::Page(action @ SettingsPointerAction::Skills(_)),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<std::collections::HashSet<_>>();

    assert_eq!(
        actions.len(),
        8,
        "two rows publish edit and delete controls"
    );
    for action in actions {
        let tmp = TempDir::new().unwrap();
        let mut dialog = fixture(&tmp);
        let before = dialog.extended.skills.clone();
        click_settings_action(&mut dialog, &action);
        match action {
            SettingsPointerAction::Skills(SkillsAction::ToggleAutoBangCommands) => {
                assert!(dialog.extended.skills.auto_bang_commands);
                assert!(persisted(&dialog).auto_bang_commands);
            }
            SettingsPointerAction::Skills(SkillsAction::ToggleAncestorWalk) => {
                assert!(dialog.extended.skills.ancestor_walk);
                assert!(persisted(&dialog).ancestor_walk);
            }
            SettingsPointerAction::Skills(SkillsAction::AddScanDirectory) => {
                assert!(
                    matches!(dialog.test_page(), TestPageRef::Skills(page) if page.grabbed.is_some())
                );
                dialog.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
                assert_eq!(snapshot(&dialog.extended.skills), snapshot(&before));
                assert_eq!(snapshot(&persisted(&dialog)), snapshot(&before));

                let nested_tmp = TempDir::new().unwrap();
                let mut nested = fixture(&nested_tmp);
                click_settings_action(&mut nested, &action);
                for ch in "gamma/skills".chars() {
                    nested.handle_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
                }
                nested.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
                let mut expected = before.clone();
                expected.scan_dirs.push("gamma/skills".into());
                assert_eq!(snapshot(&nested.extended.skills), snapshot(&expected));
                assert_eq!(snapshot(&persisted(&nested)), snapshot(&expected));
            }
            SettingsPointerAction::Skills(SkillsAction::EditScanDirectory(ref id)) => {
                assert!(
                    matches!(dialog.test_page(), TestPageRef::Skills(page) if page.grabbed.is_some())
                );
                dialog.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
                dialog.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
                assert_eq!(
                    snapshot(&dialog.extended.skills),
                    snapshot(&before),
                    "cancel rolls back {id:?}"
                );
                assert_eq!(snapshot(&persisted(&dialog)), snapshot(&before));

                let nested_tmp = TempDir::new().unwrap();
                let mut nested = fixture(&nested_tmp);
                click_settings_action(&mut nested, &action);
                nested.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
                nested.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
                let mut expected = before.clone();
                let edited = expected
                    .scan_dirs
                    .iter_mut()
                    .find(|path| path.as_str() == id.0)
                    .expect("edited source row remains addressable");
                edited.push('x');
                assert_eq!(snapshot(&nested.extended.skills), snapshot(&expected));
                assert_eq!(snapshot(&persisted(&nested)), snapshot(&expected));
            }
            SettingsPointerAction::Skills(SkillsAction::DeleteScanDirectory(ref id)) => {
                assert_eq!(
                    snapshot(&dialog.extended.skills),
                    snapshot(&before),
                    "delete first arms {id:?}"
                );
                let _ = render_settings_rows(&dialog, 100, 80);
                let confirmations = dialog
                    .pointer_surface
                    .targets
                    .borrow()
                    .iter()
                    .filter_map(|target| match (&target.action, target.enabled) {
                        (
                            shell::SettingsPointerAction::Page(
                                action @ SettingsPointerAction::Skills(
                                    SkillsAction::ConfirmDeleteScanDirectory(confirm_id, _),
                                ),
                            ),
                            true,
                        ) if confirm_id == id => Some(action.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                assert_eq!(confirmations.len(), 2);
                for confirmation in confirmations {
                    let nested_tmp = TempDir::new().unwrap();
                    let mut nested = fixture(&nested_tmp);
                    click_settings_action(&mut nested, &action);
                    click_settings_action(&mut nested, &confirmation);
                    match confirmation {
                        SettingsPointerAction::Skills(
                            SkillsAction::ConfirmDeleteScanDirectory(
                                _,
                                ConfirmationChoice::Confirm,
                            ),
                        ) => {
                            assert!(!nested.extended.skills.scan_dirs.contains(&id.0));
                            assert_eq!(
                                snapshot(&persisted(&nested)),
                                snapshot(&nested.extended.skills)
                            );
                        }
                        SettingsPointerAction::Skills(
                            SkillsAction::ConfirmDeleteScanDirectory(_, ConfirmationChoice::Cancel),
                        ) => {
                            assert_eq!(snapshot(&nested.extended.skills), snapshot(&before));
                            assert_eq!(snapshot(&persisted(&nested)), snapshot(&before));
                        }
                        _ => unreachable!(),
                    }
                }
            }
            SettingsPointerAction::Skills(SkillsAction::Reset) => {
                assert!(
                    matches!(dialog.test_page(), TestPageRef::Skills(page) if page.reset.is_pending())
                );
                assert_eq!(snapshot(&dialog.extended.skills), snapshot(&before));
                click_settings_action(&mut dialog, &action);
                let expected = SkillsConfig::seeded_default();
                assert_eq!(snapshot(&dialog.extended.skills), snapshot(&expected));
                assert_eq!(snapshot(&persisted(&dialog)), snapshot(&expected));
            }
            SettingsPointerAction::Skills(SkillsAction::ConfirmDeleteScanDirectory(_, _)) => {
                unreachable!("confirmation controls are only rendered after delete")
            }
            _ => unreachable!(),
        }
    }
}

fn pointer_mcp_action_family_dispatches_from_fresh_sources() {
    use pointer_actions::{McpAction, SettingsPointerAction};

    const MCP: &str = r#"{
      "servers": {
        "docs": {
          "transport": "streamable",
          "endpoint": "https://example.test/mcp",
          "auth": { "kind": "oauth" },
          "enabled": true
        }
      }
    }"#;

    // MCP list edits (toggle/delete/save) enqueue typed owner RPC effects and
    // fail closed on an untrusted workspace. Promote an isolated in-process
    // daemon and trust one shared project root so the helper can service each
    // queued effect and feed its correlated receipt back through the reducer.
    // The environment is isolated so the owner write never touches this box.
    let _env = cockpit_test_support::TestEnvGuard::isolated_cockpit_home();
    let _daemon = cockpit_core::daemon::enable_in_process_auto_promote_with_production_config();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("mcp pointer daemon runtime");
    let trust_tmp = TempDir::new().unwrap();
    let trusted_root = trust_tmp.path().to_path_buf();
    // Give the trusted root a concrete config layer and pin the daemon's write
    // target to it, so the owner-remoted MCP save has a layer to publish into
    // (an empty directory yields "no Cockpit config layer is available").
    let trusted_config = trusted_root.join("config.json");
    std::fs::write(&trusted_config, "{}").unwrap();
    _env.set_cockpit_config(&trusted_config);
    seed_workspace_trust(&trusted_root);

    let fixture = |tmp: &TempDir| -> SettingsDialog {
        let mut dialog = fresh_dialog(tmp);
        // The MCP list renders the daemon-owned snapshot cached on the dialog
        // (never a disk file). Seed it directly with the "docs" server so the
        // populated-row control set renders and its owner-remoted edits persist.
        dialog.mcp_config = cockpit_core::mcp::config::McpConfig::parse(MCP).unwrap();
        // Owner-remoted MCP saves fail closed unless the project root is
        // trusted; pin every fixture to the one trusted root seeded above.
        dialog.active_project_root = Some(trusted_root.clone());
        enter_root_node(&mut dialog, "MCP");
        dialog
    };
    let run_click = |dialog: &mut SettingsDialog, action: &SettingsPointerAction| {
        runtime.block_on(async { click_settings_action(dialog, action) });
    };

    fn config(dialog: &SettingsDialog) -> cockpit_core::mcp::config::McpConfig {
        dialog.load_mcp()
    }

    fn snapshot(config: &cockpit_core::mcp::config::McpConfig) -> serde_json::Value {
        serde_json::to_value(config).expect("serialize canonical MCP assertion snapshot")
    }

    fn rendered_actions(
        dialog: &SettingsDialog,
    ) -> std::collections::HashSet<SettingsPointerAction> {
        let _ = render_settings_rows(dialog, 120, 100);
        dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .filter_map(|target| match (&target.action, target.enabled) {
                (
                    shell::SettingsPointerAction::Page(action @ SettingsPointerAction::Mcp(_)),
                    true,
                ) => Some(action.clone()),
                _ => None,
            })
            .collect()
    }

    let source_tmp = TempDir::new().unwrap();
    let source = fixture(&source_tmp);
    let list_actions = rendered_actions(&source);
    let docs = pointer_actions::McpServerId("docs".into());
    assert_eq!(
        list_actions,
        [
            SettingsPointerAction::Mcp(McpAction::Open(docs.clone())),
            SettingsPointerAction::Mcp(McpAction::Add),
            SettingsPointerAction::Mcp(McpAction::ToggleEnabled(docs.clone())),
            SettingsPointerAction::Mcp(McpAction::Authenticate(docs.clone())),
            SettingsPointerAction::Mcp(McpAction::Delete(docs)),
        ]
        .into_iter()
        .collect(),
        "populated OAuth row publishes its exact initial control set"
    );

    for action in list_actions {
        let tmp = TempDir::new().unwrap();
        let mut dialog = fixture(&tmp);
        let before = config(&dialog);
        run_click(&mut dialog, &action);
        if matches!(
            &action,
            SettingsPointerAction::Mcp(McpAction::Authenticate(_))
        ) {
            assert_eq!(
                snapshot(&config(&dialog)),
                snapshot(&before),
                "authentication does not rewrite mcp.json"
            );
            assert!(
                matches!(dialog.test_page(), TestPageRef::Mcp(McpPage::List(state)) if state.status.is_some())
            );
        }
        match action {
            SettingsPointerAction::Mcp(McpAction::Open(_)) => {
                assert!(
                    matches!(dialog.test_page(), TestPageRef::Mcp(McpPage::Add(state)) if state.original_name.as_deref() == Some("docs"))
                );
                assert_eq!(snapshot(&config(&dialog)), snapshot(&before));
            }
            SettingsPointerAction::Mcp(McpAction::Add) => {
                assert!(
                    matches!(dialog.test_page(), TestPageRef::Mcp(McpPage::Add(state)) if state.original_name.is_none())
                );
                assert_eq!(snapshot(&config(&dialog)), snapshot(&before));
            }
            SettingsPointerAction::Mcp(McpAction::ToggleEnabled(_)) => {
                assert!(!config(&dialog).servers["docs"].enabled);
            }
            SettingsPointerAction::Mcp(McpAction::Authenticate(_)) => {}
            SettingsPointerAction::Mcp(McpAction::Delete(_)) => {
                assert_eq!(
                    snapshot(&config(&dialog)),
                    snapshot(&before),
                    "first delete only arms confirmation"
                );
                let confirmations = rendered_actions(&dialog);
                assert!(confirmations.contains(&SettingsPointerAction::Mcp(McpAction::Cancel)));
                assert!(confirmations.contains(&action));

                let cancel_tmp = TempDir::new().unwrap();
                let mut cancel = fixture(&cancel_tmp);
                run_click(&mut cancel, &action);
                run_click(&mut cancel, &SettingsPointerAction::Mcp(McpAction::Cancel));
                assert_eq!(snapshot(&config(&cancel)), snapshot(&before));

                run_click(&mut dialog, &action);
                assert!(config(&dialog).servers.is_empty());
            }
            SettingsPointerAction::Mcp(McpAction::Cancel) => unreachable!(),
            _ => unreachable!(),
        }
    }

    let editor_source_tmp = TempDir::new().unwrap();
    let mut editor_source = fixture(&editor_source_tmp);
    run_click(
        &mut editor_source,
        &SettingsPointerAction::Mcp(McpAction::Open(pointer_actions::McpServerId("docs".into()))),
    );
    let editor_actions = rendered_actions(&editor_source);
    assert_eq!(
        editor_actions.len(),
        19,
        "editor publishes every typed field and save"
    );

    for action in editor_actions {
        let tmp = TempDir::new().unwrap();
        let mut dialog = fixture(&tmp);
        let open = SettingsPointerAction::Mcp(McpAction::Open(pointer_actions::McpServerId(
            "docs".into(),
        )));
        run_click(&mut dialog, &open);
        let before = config(&dialog);
        let saved_enabled_from_editor = match dialog.test_page() {
            TestPageRef::Mcp(McpPage::Add(state)) => {
                if state.auth == mcp_page::AuthKind::Oauth
                    && (state.oauth_authorize_url.text().trim().is_empty()
                        || state.oauth_token_url.text().trim().is_empty())
                {
                    false
                } else {
                    state.enabled
                }
            }
            other => panic!("MCP open did not produce an editor source: {other:?}"),
        };
        run_click(&mut dialog, &action);
        match action {
            SettingsPointerAction::Mcp(McpAction::ToggleEditorEnabled) => {
                assert!(
                    matches!(dialog.test_page(), TestPageRef::Mcp(McpPage::Add(state)) if !state.enabled)
                );
                assert_eq!(snapshot(&config(&dialog)), snapshot(&before));
            }
            SettingsPointerAction::Mcp(McpAction::CycleTransport) => {
                assert!(
                    matches!(dialog.test_page(), TestPageRef::Mcp(McpPage::Add(state)) if state.transport == cockpit_core::mcp::config::Transport::Stdio)
                );
                assert_eq!(snapshot(&config(&dialog)), snapshot(&before));
            }
            SettingsPointerAction::Mcp(McpAction::CycleAuth) => {
                assert!(
                    matches!(dialog.test_page(), TestPageRef::Mcp(McpPage::Add(state)) if state.auth == mcp_page::AuthKind::None)
                );
                assert_eq!(snapshot(&config(&dialog)), snapshot(&before));
            }
            SettingsPointerAction::Mcp(McpAction::Save) => {
                assert!(matches!(
                    dialog.test_page(),
                    TestPageRef::Mcp(McpPage::List(_))
                ));
                let mut expected = before.clone();
                expected
                    .servers
                    .get_mut("docs")
                    .expect("editor source server remains in expected config")
                    .enabled = saved_enabled_from_editor;
                assert_eq!(snapshot(&config(&dialog)), snapshot(&expected));
            }
            SettingsPointerAction::Mcp(
                McpAction::EditName
                | McpAction::EditEndpoint
                | McpAction::EditCommand
                | McpAction::EditArgs
                | McpAction::EditBaseEnv
                | McpAction::EditHeaderName
                | McpAction::EditHeaderValue
                | McpAction::EditAuthEnv
                | McpAction::EditOauthAuthorizeUrl
                | McpAction::EditOauthTokenUrl
                | McpAction::EditOauthClientId
                | McpAction::EditOauthScopes
                | McpAction::EditCacheTtl
                | McpAction::EditConnectTimeout
                | McpAction::EditRequestTimeout,
            ) => {
                assert!(matches!(
                    dialog.test_page(),
                    TestPageRef::Mcp(McpPage::Add(_))
                ));
                assert_eq!(
                    snapshot(&config(&dialog)),
                    snapshot(&before),
                    "field focus does not persist edits"
                );
            }
            _ => unreachable!(),
        }
    }
}

fn standalone_pointer_dialog(tmp: &TempDir, title: &str) -> SettingsDialog {
    if title == "LSP" {
        let active = tmp.path().join("active-project");
        std::fs::create_dir_all(&active).unwrap();
        let path = tmp.path().join("config.json");
        super::disk_daemon_fake::register_settings_layer_target(&path);
        SettingsDialog::open_from_picker(path, active)
    } else {
        fresh_dialog(tmp)
    }
}

fn harness_list_pointer_fixture(tmp: &TempDir) -> SettingsDialog {
    let mut dialog = fresh_dialog(tmp);
    dialog.command_installed = |_| true;
    enter_harnesses_from_root(&mut dialog);
    dialog.extended.tui.mouse_capture = true;
    dialog
}

fn populated_harness_list_pointer_fixture(tmp: &TempDir) -> SettingsDialog {
    let mut dialog = fresh_dialog(tmp);
    dialog.command_installed = |_| true;
    enter_harnesses_from_root(&mut dialog);
    dialog.extended.tui.mouse_capture = true;
    let mut presets = cockpit_config::extended::builtin_harness_presets().into_iter();
    let (_, alpha) = presets.next().expect("first populated harness fixture");
    let (_, beta) = presets.next().expect("second populated harness fixture");
    dialog
        .extended
        .harnesses
        .insert("custom".into(), alpha.clone());
    dialog.extended.harnesses.insert("alpha".into(), alpha);
    dialog.extended.harnesses.insert("beta".into(), beta);
    let TestPageMut::Harnesses(HarnessesPage::List(state)) = dialog.test_page_mut() else {
        panic!("populated Harnesses fixture did not enter its list page");
    };
    state.cursor = 0;
    assert_eq!(dialog.extended.harnesses.len(), 3);
    dialog
}

fn click_settings_action(
    dialog: &mut SettingsDialog,
    action: &pointer_actions::SettingsPointerAction,
) {
    if let pointer_actions::SettingsPointerAction::Harnesses(
        pointer_actions::HarnessesAction::Open(id) | pointer_actions::HarnessesAction::Delete(id),
    ) = action
    {
        let mut names = dialog
            .extended
            .harnesses
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        names.sort();
        let index = names
            .iter()
            .position(|name| name == &id.0)
            .unwrap_or_else(|| panic!("harness action names a missing source row: {}", id.0));
        let TestPageMut::Harnesses(HarnessesPage::List(state)) = dialog.test_page_mut() else {
            panic!("harness row action requires a list source: {action:?}");
        };
        state.cursor = index;
    }
    // Dispatch fixtures include the Tools page, whose tallest variant (a user
    // tool selected, so the contextual detail controls sit last) is ~93 rows
    // with its deepest control near row index 90. A short viewport scrolls
    // those bottom controls off-screen and `render_control_lines` never
    // registers them, so their pointer targets never appear and the lookup
    // below panics. Render every dispatch source tall enough that the whole
    // page fits (offset stays 0) — the same invariant the source-harvest
    // fixtures already pin with `POINTER_TOOLS_FIXTURE_HEIGHT`.
    let _ = render_settings_rows(dialog, 100, POINTER_TOOLS_FIXTURE_HEIGHT);
    let target = dialog
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find(|target| {
            target.enabled && target.action == shell::SettingsPointerAction::Page(action.clone())
        })
        .cloned()
        .expect("source action must render on fresh harness fixture");
    for kind in [
        MouseEventKind::Down(MouseButton::Left),
        MouseEventKind::Up(MouseButton::Left),
    ] {
        dialog.handle_pointer(settings_mouse(kind, target.rect.x, target.rect.y));
    }
}

fn pointer_harness_list_actions_dispatch_from_fresh_sources() {
    use pointer_actions::{HarnessesAction, SettingsPointerAction};

    let source_tmp = TempDir::new().unwrap();
    let source = harness_list_pointer_fixture(&source_tmp);
    let _ = render_settings_rows(&source, 100, 40);
    let actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                shell::SettingsPointerAction::Page(action @ SettingsPointerAction::Harnesses(_)),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(actions.len(), 3, "empty Harnesses list has three actions");

    for action in actions {
        let SettingsPointerAction::Harnesses(harness_action) = &action else {
            unreachable!();
        };
        let tmp = TempDir::new().unwrap();
        let mut dialog = harness_list_pointer_fixture(&tmp);
        match harness_action {
            HarnessesAction::Add => {
                click_settings_action(&mut dialog, &action);
                assert!(matches!(
                    dialog.test_page(),
                    TestPageRef::Harnesses(HarnessesPage::List(state))
                        if state.adding.is_some()
                ));
            }
            HarnessesAction::SeedInstalledPresets => {
                click_settings_action(&mut dialog, &action);
                assert!(!dialog.extended.harnesses.is_empty());
                assert!(matches!(
                    dialog.test_page(),
                    TestPageRef::Harnesses(HarnessesPage::List(state))
                        if state.status.as_deref() == Some("saved")
                ));
            }
            HarnessesAction::ResetAndSeedPresets => {
                let (_, custom) = cockpit_config::extended::builtin_harness_presets()
                    .into_iter()
                    .next()
                    .expect("harness reset fixture");
                dialog.extended.harnesses.insert("custom".into(), custom);
                click_settings_action(&mut dialog, &action);
                assert!(dialog.extended.harnesses.contains_key("custom"));
                assert!(matches!(
                    dialog.test_page(),
                    TestPageRef::Harnesses(HarnessesPage::List(state)) if state.reset.is_pending()
                ));
                click_settings_action(&mut dialog, &action);
                assert!(!dialog.extended.harnesses.contains_key("custom"));
                assert!(!dialog.extended.harnesses.is_empty());
            }
            HarnessesAction::Open(_)
            | HarnessesAction::Delete(_)
            | HarnessesAction::EditField(_)
            | HarnessesAction::Save
            | HarnessesAction::Cancel => {
                panic!("empty Harnesses list rendered unexpected action {harness_action:?}")
            }
        }
    }

    let populated_tmp = TempDir::new().unwrap();
    let populated = populated_harness_list_pointer_fixture(&populated_tmp);
    let _ = render_settings_rows(&populated, 100, 40);
    let populated_actions = populated
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Harnesses(
                        HarnessesAction::Open(_) | HarnessesAction::Delete(_),
                    ),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<std::collections::HashSet<_>>();
    assert!(
        populated_actions.contains(&SettingsPointerAction::Harnesses(HarnessesAction::Open(
            pointer_actions::HarnessId("alpha".into()),
        )))
    );
    assert!(
        populated_actions.contains(&SettingsPointerAction::Harnesses(HarnessesAction::Delete(
            pointer_actions::HarnessId("alpha".into()),
        )))
    );
    for action in &populated_actions {
        let SettingsPointerAction::Harnesses(
            HarnessesAction::Open(id) | HarnessesAction::Delete(id),
        ) = action
        else {
            unreachable!("populated source filter admitted a non-row action");
        };
        assert!(
            populated.extended.harnesses.contains_key(&id.0),
            "rendered Harnesses identity must name a live config entry: {}",
            id.0
        );
    }
    for action in populated_actions {
        match &action {
            SettingsPointerAction::Harnesses(HarnessesAction::Open(id)) => {
                let tmp = TempDir::new().unwrap();
                let mut dialog = populated_harness_list_pointer_fixture(&tmp);
                click_settings_action(&mut dialog, &action);
                assert!(matches!(
                    dialog.test_page(),
                    TestPageRef::Harnesses(HarnessesPage::Edit(state)) if state.name == id.0
                ));
            }
            SettingsPointerAction::Harnesses(HarnessesAction::Delete(id)) => {
                // First press only arms; the explicit Cancel target clears it.
                let tmp = TempDir::new().unwrap();
                let mut dialog = populated_harness_list_pointer_fixture(&tmp);
                click_settings_action(&mut dialog, &action);
                assert!(dialog.extended.harnesses.contains_key(&id.0));
                assert!(matches!(
                    dialog.test_page(),
                    TestPageRef::Harnesses(HarnessesPage::List(state)) if state.delete_pending
                ));
                click_settings_action(
                    &mut dialog,
                    &SettingsPointerAction::Harnesses(HarnessesAction::Cancel),
                );
                assert!(matches!(
                    dialog.test_page(),
                    TestPageRef::Harnesses(HarnessesPage::List(state))
                        if !state.delete_pending
                            && state.status.as_deref() == Some("delete cancelled")
                ));

                // A second press on the same stable row identity applies.
                let tmp = TempDir::new().unwrap();
                let mut dialog = populated_harness_list_pointer_fixture(&tmp);
                click_settings_action(&mut dialog, &action);
                click_settings_action(&mut dialog, &action);
                assert!(!dialog.extended.harnesses.contains_key(&id.0));
                assert_eq!(dialog.extended.harnesses.len(), 2);

                // A target captured before its row disappears must be inert.
                let tmp = TempDir::new().unwrap();
                let mut dialog = populated_harness_list_pointer_fixture(&tmp);
                let _ = render_settings_rows(&dialog, 100, 40);
                let stale = dialog
                    .pointer_surface
                    .targets
                    .borrow()
                    .iter()
                    .find(|target| {
                        target.enabled
                            && target.action == shell::SettingsPointerAction::Page(action.clone())
                    })
                    .cloned()
                    .expect("populated delete target");
                dialog.extended.harnesses.remove(&id.0);
                for kind in [
                    MouseEventKind::Down(MouseButton::Left),
                    MouseEventKind::Up(MouseButton::Left),
                ] {
                    dialog.handle_pointer(settings_mouse(kind, stale.rect.x, stale.rect.y));
                }
                assert_eq!(dialog.extended.harnesses.len(), 2);
                assert!(matches!(
                    dialog.test_page(),
                    TestPageRef::Harnesses(HarnessesPage::List(state))
                        if !state.delete_pending
                ));
            }
            SettingsPointerAction::Harnesses(
                HarnessesAction::Add
                | HarnessesAction::SeedInstalledPresets
                | HarnessesAction::ResetAndSeedPresets
                | HarnessesAction::EditField(_)
                | HarnessesAction::Save
                | HarnessesAction::Cancel,
            )
            | SettingsPointerAction::Root(_)
            | SettingsPointerAction::Category(_)
            | SettingsPointerAction::Agents(_)
            | SettingsPointerAction::Tools(_)
            | SettingsPointerAction::Skills(_)
            | SettingsPointerAction::Mcp(_)
            | SettingsPointerAction::Providers(_)
            | SettingsPointerAction::Lsp(_)
            | SettingsPointerAction::List(_)
            | SettingsPointerAction::UtilityModel(_)
            | SettingsPointerAction::DefaultModel(_)
            | SettingsPointerAction::Generation(_) => {
                panic!("populated Harnesses fixture harvested unexpected action {action:?}")
            }
        }
    }

    // Delete is published only for the selected row. Independently select
    // and dispatch every real source identity, including rows clipped from
    // the smaller inventory render above.
    for name in ["alpha", "beta", "custom"] {
        let delete = SettingsPointerAction::Harnesses(HarnessesAction::Delete(
            pointer_actions::HarnessId(name.into()),
        ));
        let tmp = TempDir::new().unwrap();
        let mut dialog = populated_harness_list_pointer_fixture(&tmp);
        click_settings_action(&mut dialog, &delete);
        assert!(dialog.extended.harnesses.contains_key(name));
        assert!(matches!(
            dialog.test_page(),
            TestPageRef::Harnesses(HarnessesPage::List(state)) if state.delete_pending
        ));
    }
}

fn pointer_harness_field_actions_dispatch_from_fresh_sources() {
    use pointer_actions::{HarnessField, HarnessId, HarnessesAction, SettingsPointerAction};

    fn detail_dialog(tmp: &TempDir) -> SettingsDialog {
        let mut dialog = populated_harness_list_pointer_fixture(tmp);
        click_settings_action(
            &mut dialog,
            &SettingsPointerAction::Harnesses(HarnessesAction::Open(HarnessId("custom".into()))),
        );
        assert!(matches!(
            dialog.test_page(),
            TestPageRef::Harnesses(HarnessesPage::Edit(state)) if state.name == "custom"
        ));
        dialog
    }

    let source_tmp = TempDir::new().unwrap();
    let source = detail_dialog(&source_tmp);
    let _ = render_settings_rows(&source, 100, 80);
    for field in HarnessField::ALL {
        let action = SettingsPointerAction::Harnesses(HarnessesAction::EditField(field));
        assert!(
            source
                .pointer_surface
                .targets
                .borrow()
                .iter()
                .any(|target| {
                    target.enabled
                        && matches!(
                            &target.action,
                            shell::SettingsPointerAction::Page(rendered) if rendered == &action
                        )
                })
        );

        let dispatch_tmp = TempDir::new().unwrap();
        let mut dialog = detail_dialog(&dispatch_tmp);
        let before = dialog
            .extended
            .harnesses
            .get("custom")
            .expect("custom harness source")
            .clone();
        let before_json = serde_json::to_value(&before).expect("serialize harness source");
        click_settings_action(&mut dialog, &action);
        let TestPageRef::Harnesses(HarnessesPage::Edit(state)) = dialog.test_page() else {
            panic!("field dispatch preserves harness detail");
        };
        let after = dialog
            .extended
            .harnesses
            .get("custom")
            .expect("custom harness remains present");
        match field {
            HarnessField::PromptInput => {
                assert!(state.editing.is_none());
                assert_ne!(after.prompt_input, before.prompt_input);
            }
            HarnessField::ArgvOverflow => {
                assert!(state.editing.is_none());
                assert_ne!(after.argv_overflow, before.argv_overflow);
            }
            HarnessField::SupportsJson => {
                assert!(state.editing.is_none());
                assert_eq!(after.supports_json_output, !before.supports_json_output);
            }
            HarnessField::SupportsAgentFile => {
                assert!(state.editing.is_none());
                assert_eq!(after.supports_agent_file, !before.supports_agent_file);
            }
            HarnessField::AlwaysAllow => {
                assert!(state.editing.is_none());
                assert_eq!(after.always_allow, !before.always_allow);
            }
            HarnessField::Trust => {
                // The harness `trust` custody row (`HarnessConfig.trust:
                // HarnessTrust`) is a cycled enum (Untrusted↔Trusted), not a
                // text editor, so activating it flips trust in place rather
                // than opening an edit buffer.
                assert!(state.editing.is_none());
                assert_ne!(after.trust, before.trust);
            }
            HarnessField::Command
            | HarnessField::Args
            | HarnessField::ModelArgs
            | HarnessField::DefaultModel
            | HarnessField::Models
            | HarnessField::ModelListArgs
            | HarnessField::JsonOutputArgs
            | HarnessField::AgentFileArgs
            | HarnessField::AgentFileEnv
            | HarnessField::AuthProbeArgs
            | HarnessField::Timeout => {
                assert!(state.editing.is_some());
                assert_eq!(
                    serde_json::to_value(after).expect("serialize harness after editor open"),
                    before_json,
                    "opening a field editor does not commit"
                );
            }
        }
    }
}

fn pointer_harness_editor_lifecycle_dispatches_from_fresh_sources() {
    use pointer_actions::{HarnessField, HarnessId, HarnessesAction, SettingsPointerAction};

    fn command_editor(tmp: &TempDir) -> SettingsDialog {
        let mut dialog = populated_harness_list_pointer_fixture(tmp);
        click_settings_action(
            &mut dialog,
            &SettingsPointerAction::Harnesses(HarnessesAction::Open(HarnessId("custom".into()))),
        );
        click_settings_action(
            &mut dialog,
            &SettingsPointerAction::Harnesses(HarnessesAction::EditField(HarnessField::Command)),
        );
        assert!(matches!(
            dialog.test_page(),
            TestPageRef::Harnesses(HarnessesPage::Edit(state)) if state.editing.is_some()
        ));
        dialog
    }

    let source_tmp = TempDir::new().unwrap();
    let source = command_editor(&source_tmp);
    let _ = render_settings_rows(&source, 100, 80);
    for action in [HarnessesAction::Save, HarnessesAction::Cancel] {
        let expected = SettingsPointerAction::Harnesses(action);
        assert!(
            source
                .pointer_surface
                .targets
                .borrow()
                .iter()
                .any(|target| {
                    target.enabled
                        && matches!(
                            &target.action,
                            shell::SettingsPointerAction::Page(rendered) if rendered == &expected
                        )
                })
        );
    }

    let save_tmp = TempDir::new().unwrap();
    let mut save_dialog = command_editor(&save_tmp);
    let original = save_dialog.extended.harnesses["custom"].command.clone();
    let TestPageMut::Harnesses(HarnessesPage::Edit(state)) = save_dialog.test_page_mut() else {
        panic!("command editor remains open");
    };
    state.editing = Some(crate::tui::textfield::TextField::new("pointer-command"));
    click_settings_action(
        &mut save_dialog,
        &SettingsPointerAction::Harnesses(HarnessesAction::Save),
    );
    assert_ne!(original, "pointer-command");
    assert_eq!(
        save_dialog.extended.harnesses["custom"].command,
        "pointer-command"
    );
    assert!(matches!(
        save_dialog.test_page(),
        TestPageRef::Harnesses(HarnessesPage::Edit(state)) if state.editing.is_none()
    ));
    let persisted = ExtendedConfigDoc::load(&save_dialog.extended_path)
        .expect("saved harness config")
        .config();
    assert_eq!(persisted.harnesses["custom"].command, "pointer-command");

    let cancel_tmp = TempDir::new().unwrap();
    let mut cancel_dialog = command_editor(&cancel_tmp);
    let original = cancel_dialog.extended.harnesses["custom"].command.clone();
    let disk_before = std::fs::read(&cancel_dialog.extended_path).ok();
    let TestPageMut::Harnesses(HarnessesPage::Edit(state)) = cancel_dialog.test_page_mut() else {
        panic!("command editor remains open");
    };
    state.editing = Some(crate::tui::textfield::TextField::new("discarded-command"));
    click_settings_action(
        &mut cancel_dialog,
        &SettingsPointerAction::Harnesses(HarnessesAction::Cancel),
    );
    assert_eq!(cancel_dialog.extended.harnesses["custom"].command, original);
    assert!(matches!(
        cancel_dialog.test_page(),
        TestPageRef::Harnesses(HarnessesPage::Edit(state)) if state.editing.is_none()
    ));
    assert_eq!(
        std::fs::read(&cancel_dialog.extended_path).ok(),
        disk_before,
        "Cancel must not persist the edited buffer"
    );
}

/// Render the concrete nested states whose discriminants form the strict
/// pointer-surface inventory. Mouse capture is disabled for this inventory
/// pass: enabled controls are exercised by the reducer matrices below, while
/// this pass proves that every state variant itself remains constructible and
/// renderable through production navigation.
fn render_all_non_provider_pointer_surface_variants() {
    // Render each standalone root child explicitly. Surface coverage must be
    // owned by this acceptance run, never inherited accidentally from some
    // earlier test that happened to execute on the same thread-local worker.
    for (title, expected_surface) in [
        ("Dependencies", SettingsPointerSurfaceKind::Dependencies),
        ("Tools", SettingsPointerSurfaceKind::Tools),
        ("Skills", SettingsPointerSurfaceKind::Skills),
        ("MCP", SettingsPointerSurfaceKind::Mcp),
        ("LSP", SettingsPointerSurfaceKind::Lsp),
        ("Generation", SettingsPointerSurfaceKind::GenerationList),
    ] {
        let tmp = TempDir::new().unwrap();
        let mut d = standalone_pointer_dialog(&tmp, title);
        enter_root_node(&mut d, title);
        let _ = render_settings_rows(&d, 100, 40);
        let actual_surface = d.page.pointer_surface_kind();
        assert_eq!(
            actual_surface, expected_surface,
            "rendered {title} source page"
        );
        // Keep the acceptance recorder tied to the verified source page in
        // addition to the production render hook. This makes the fixture
        // deterministic under the parallel libtest harness instead of
        // relying on a render-hook thread-local surviving the draw closure.
        super::pointer_acceptance_tests::record_rendered_surface(actual_surface);
        if title == "Generation" {
            for node in [
                pointer_actions::GenerationNodeId::Endpoints,
                pointer_actions::GenerationNodeId::Targets,
                pointer_actions::GenerationNodeId::Workflows,
                pointer_actions::GenerationNodeId::Budget,
                pointer_actions::GenerationNodeId::Grants,
                pointer_actions::GenerationNodeId::Jobs,
            ] {
                let tmp = TempDir::new().unwrap();
                let mut generation = standalone_pointer_dialog(&tmp, title);
                enter_root_node(&mut generation, title);
                click_settings_action(
                    &mut generation,
                    &pointer_actions::SettingsPointerAction::Generation(
                        pointer_actions::GenerationAction::OpenNode(node),
                    ),
                );
            }
        }
    }

    for (page, expected_surface) in [
        (
            instructions_page(InstructionsPage::new()),
            SettingsPointerSurfaceKind::Instructions,
        ),
        (
            Box::new(RedactPatternsPage::new()) as PageBox,
            SettingsPointerSurfaceKind::RedactPatterns,
        ),
        (
            image_generation::generation_list_page(
                image_generation::GenerationPrincipal::local_owner(),
            ),
            SettingsPointerSurfaceKind::GenerationList,
        ),
        (
            image_generation::endpoint_editor_page(
                image_generation::GenerationPrincipal::local_owner(),
            ),
            SettingsPointerSurfaceKind::EndpointEditor,
        ),
        (
            image_generation::target_editor_page(
                image_generation::GenerationPrincipal::local_owner(),
            ),
            SettingsPointerSurfaceKind::TargetEditor,
        ),
        (
            image_generation::workflow_editor_page(
                image_generation::GenerationPrincipal::local_owner(),
            ),
            SettingsPointerSurfaceKind::WorkflowEditor,
        ),
        (
            image_generation::budget_editor_page(
                image_generation::GenerationPrincipal::local_owner(),
            ),
            SettingsPointerSurfaceKind::BudgetEditor,
        ),
        (
            image_generation::grant_list_page(image_generation::GenerationPrincipal::local_owner()),
            SettingsPointerSurfaceKind::GrantList,
        ),
        (
            image_generation::job_list_page(image_generation::GenerationPrincipal::local_owner()),
            SettingsPointerSurfaceKind::JobList,
        ),
        (
            Box::new(image_generation::JobDetailPage {
                cursor: 0,
                principal: image_generation::GenerationPrincipal::local_owner(),
                job_id: "j".into(),
                reducer: image_generation::JobReducer::new(
                    String::new(),
                    String::new(),
                    String::new(),
                ),
                confirm: None,
                viewport: image_generation::GenerationViewportMode::Full,
            }) as PageBox,
            SettingsPointerSurfaceKind::JobDetail,
        ),
        (
            Box::new(image_generation::LateResultActionPage {
                cursor: 0,
                principal: image_generation::GenerationPrincipal::local_owner(),
                late_result_id: "r1".into(),
                action: image_generation::LateResultAction::Publish,
                confirm: None,
                viewport: image_generation::GenerationViewportMode::Full,
            }) as PageBox,
            SettingsPointerSurfaceKind::LateResultAction,
        ),
    ] {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.page = page;
        let _ = render_settings_rows(&d, 100, 40);
        let actual_surface = d.page.pointer_surface_kind();
        assert_eq!(actual_surface, expected_surface);
        super::pointer_acceptance_tests::record_rendered_surface(actual_surface);
    }

    // Harnesses: list, add-name editor, harness editor, field editor.
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_harnesses_from_root(&mut d);
    d.extended.tui.mouse_capture = false;
    let _ = render_settings_rows(&d, 100, 40);
    d.handle_key(press(KeyCode::Char('a')));
    let _ = render_settings_rows(&d, 100, 40);

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_harnesses_from_root(&mut d);
    d.extended.tui.mouse_capture = false;
    let (_, harness) = cockpit_config::extended::builtin_harness_presets()
        .into_iter()
        .next()
        .expect("built-in harness fixture");
    d.extended.harnesses.insert("fixture".into(), harness);
    let TestPageMut::Harnesses(HarnessesPage::List(state)) = d.test_page_mut() else {
        panic!("Harnesses edit surface fixture did not enter list");
    };
    state.cursor = 0;
    d.handle_key(press(KeyCode::Enter));
    let _ = render_settings_rows(&d, 100, 40);
    d.handle_key(press(KeyCode::Enter));
    let _ = render_settings_rows(&d, 100, 40);

    // Agents: list, structured detail, and the in-TUI source editor.
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.extended.tui.mouse_capture = false;
    enter_root_node(&mut d, "Agents");
    let _ = render_settings_rows(&d, 100, 40);
    d.handle_key(press(KeyCode::Enter));
    let _ = render_settings_rows(&d, 100, 40);

    let _editor = EditorEnv::unset();
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.extended.tui.mouse_capture = false;
    enter_root_node(&mut d, "Agents");
    d.handle_key(press(KeyCode::Char('e')));
    let _ = render_settings_rows(&d, 100, 40);

    // Every StringListKind in both browse and grab/edit modes.
    let constructors: [fn() -> StringListPage; 5] = [
        StringListPage::agent_dirs,
        StringListPage::extra_dotenv_paths,
        StringListPage::redact_denylist,
        StringListPage::redact_allowlist,
        StringListPage::gitignore_allow,
    ];
    for construct in constructors {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.extended.tui.mouse_capture = false;
        d.set_test_page(Page::StringList(Box::new(construct())));
        let _ = render_settings_rows(&d, 100, 40);
        d.handle_key(press(KeyCode::Enter));
        let _ = render_settings_rows(&d, 100, 40);
        let actual_surface = d.page.pointer_surface_kind();
        assert_eq!(actual_surface, SettingsPointerSurfaceKind::StringList);
        super::pointer_acceptance_tests::record_rendered_surface(actual_surface);
    }

    // Category base, inline, path, full-text, external, picker-list, and
    // picker-custom modes. The fixture constructor uses the same production
    // editor/picker types as normal descriptor activation.
    for mode in category::CategoryPointerFixtureMode::ALL {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.extended.tui.mouse_capture = false;
        d.set_test_page(Page::Category(Box::new(
            category::CategoryPage::pointer_surface_fixture(mode, tmp.path()),
        )));
        let rows = render_settings_rows(&d, 100, 40);
        let rendered = rows.join("\n");
        let _ = rendered;
    }

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.extended.tui.mouse_capture = false;
    enter_root_node(&mut d, "Default model for new sessions");
    let rendered = render_settings_rows(&d, 100, 40).join("\n");
    assert!(
        rendered.contains("[Choose default model]"),
        "capture-off still paints enabled idle buttons: {rendered}"
    );
    assert!(
        rendered.contains("[Clear default for this scope]"),
        "capture-off still paints enabled idle buttons: {rendered}"
    );
    assert!(
        d.pointer_surface.buttons.borrow().targets().is_empty(),
        "capture-off registers no pointer targets"
    );
    assert!(d.pointer_surface.hover.borrow().is_none());
}

pub(super) fn run_pointer_text_layout_matrix() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    let entry = entry(&[]);
    let mut editor = settings_editor::SettingsEditor::for_provider("p", &entry);
    let field = settings_editor::ProviderSettingId::AutoCompactPct;
    editor.cursor = editor
        .fields()
        .iter()
        .position(|candidate| *candidate == field)
        .unwrap();
    editor.editing = Some(field);
    editor.buf = TextField::new("12345");
    d.set_test_page(Page::Providers(ProvidersPage::ProviderSettings {
        editor,
        parent: Box::new(providers::EditState::new("p".into(), entry)),
    }));
    for (width, height) in [(100, 30), (48, 18)] {
        let _ = render_settings_rows(&d, width, height);
        let target = d
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .find(|target| {
                matches!(
                    target.action,
                    shell::SettingsPointerAction::Page(
                        pointer_actions::SettingsPointerAction::Providers(
                            pointer_actions::ProvidersAction::RowEditor(
                                pointer_actions::ProviderRowEditorAction::SettingEdit(_)
                            )
                        )
                    )
                )
            })
            .cloned()
            .expect("numeric field target");
        let x = target.rect.right().saturating_sub(2);
        assert_eq!(
            d.handle_pointer(settings_mouse(
                MouseEventKind::Down(MouseButton::Left),
                x,
                target.rect.y
            )),
            SettingsPointerOutcome::Consumed
        );
        let TestPageRef::Providers(ProvidersPage::ProviderSettings { editor, .. }) = d.test_page()
        else {
            panic!("provider settings");
        };
        assert!(editor.buf.text().is_char_boundary(editor.buf.cursor()));
        assert_eq!(
            editor.buf.text(),
            "12345",
            "click does not commit or mutate"
        );
    }

    for value in ["ascii", "a界b", "e\u{301}x"] {
        let mut field = TextField::new(value);
        for column in 0..=12 {
            field.set_cursor_display_col(column);
            assert!(field.text().is_char_boundary(field.cursor()));
        }
    }
}

pub(super) fn run_pointer_picker_suggestion_matrix() {
    for expected in ["anthropic:opus", "", "custom-provider:model"] {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_models(&tmp);
        open_utility_picker(&mut d);
        let _ = render_settings_rows(&d, 90, 24);
        let wanted = if expected.is_empty() {
            pointer_actions::SettingsPointerAction::UtilityModel(
                pointer_actions::UtilityModelAction::Clear,
            )
        } else if expected.starts_with("custom-") {
            pointer_actions::SettingsPointerAction::UtilityModel(
                pointer_actions::UtilityModelAction::OpenCustom,
            )
        } else {
            pointer_actions::SettingsPointerAction::Category(
                pointer_actions::CategoryAction::PickerSelect(
                    SettingId::UtilityModel,
                    pointer_actions::PickerOptionId(expected.into()),
                ),
            )
        };
        let target = d
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .find(|target| target.action == shell::SettingsPointerAction::Page(wanted.clone()))
            .cloned()
            .expect("rendered picker target");
        d.handle_pointer(settings_mouse(
            MouseEventKind::Down(MouseButton::Left),
            target.rect.x,
            target.rect.y,
        ));
        d.handle_pointer(settings_mouse(
            MouseEventKind::Up(MouseButton::Left),
            target.rect.x,
            target.rect.y,
        ));
        if expected.starts_with("custom-") {
            type_chars(&mut d, expected);
            let _ = render_settings_rows(&d, 48, 18);
            let save = d
                .pointer_surface
                .targets
                .borrow()
                .iter()
                .find(|target| {
                    target.action
                        == shell::SettingsPointerAction::Page(
                            pointer_actions::SettingsPointerAction::UtilityModel(
                                pointer_actions::UtilityModelAction::CommitCustom,
                            ),
                        )
                })
                .cloned()
                .expect("custom save target");
            d.handle_pointer(settings_mouse(
                MouseEventKind::Down(MouseButton::Left),
                save.rect.x,
                save.rect.y,
            ));
            d.handle_pointer(settings_mouse(
                MouseEventKind::Up(MouseButton::Left),
                save.rect.x,
                save.rect.y,
            ));
        }
        assert_eq!(d.extended.utility_model.as_deref().unwrap_or(""), expected);
    }

    // Dispatch every concrete model identity published by the live picker,
    // not just one representative entry. The acceptance inventory compares
    // exact source payloads so a newly rendered model cannot hide behind the
    // shared `Select` discriminant.
    let source_tmp = TempDir::new().unwrap();
    let mut source = dialog_with_models(&source_tmp);
    open_utility_picker(&mut source);
    let _ = render_settings_rows(&source, 90, 24);
    let select_actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                shell::SettingsPointerAction::Page(
                    action @ pointer_actions::SettingsPointerAction::Category(
                        pointer_actions::CategoryAction::PickerSelect(_, _),
                    ),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(!select_actions.is_empty());
    for action in select_actions {
        let tmp = TempDir::new().unwrap();
        let mut dialog = dialog_with_models(&tmp);
        open_utility_picker(&mut dialog);
        click_settings_action(&mut dialog, &action);
        let pointer_actions::SettingsPointerAction::Category(
            pointer_actions::CategoryAction::PickerSelect(_, id),
        ) = action
        else {
            unreachable!();
        };
        assert_eq!(
            dialog.extended.utility_model.as_deref(),
            Some(id.0.as_str())
        );
    }

    let utility_select_actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                shell::SettingsPointerAction::Page(
                    action @ pointer_actions::SettingsPointerAction::UtilityModel(
                        pointer_actions::UtilityModelAction::Select(_),
                    ),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(!utility_select_actions.is_empty());
    for action in utility_select_actions {
        let tmp = TempDir::new().unwrap();
        let mut dialog = dialog_with_models(&tmp);
        open_utility_picker(&mut dialog);
        click_settings_action(&mut dialog, &action);
        let pointer_actions::SettingsPointerAction::UtilityModel(
            pointer_actions::UtilityModelAction::Select(id),
        ) = action
        else {
            unreachable!();
        };
        assert_eq!(
            dialog.extended.utility_model.as_deref(),
            Some(id.0.as_str())
        );
        assert!(matches!(
            dialog.test_page(),
            TestPageRef::Category(page) if page.utility_picker.is_none()
        ));
    }

    let back_tmp = TempDir::new().unwrap();
    let mut back = dialog_with_models(&back_tmp);
    open_utility_picker(&mut back);
    let config_before = serde_json::to_value(&back.extended).unwrap();
    let persisted_before = std::fs::read(back_tmp.path().join("config.json")).unwrap();
    let _ = render_settings_rows(&back, 90, 24);
    let back_actions = back
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                shell::SettingsPointerAction::Page(
                    action @ pointer_actions::SettingsPointerAction::UtilityModel(
                        pointer_actions::UtilityModelAction::Back,
                    ),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(back_actions.len(), 1, "utility picker owns one Back source");
    let target = back
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find(|target| {
            target.enabled
                && target.action == shell::SettingsPointerAction::Page(back_actions[0].clone())
        })
        .cloned()
        .expect("fresh utility picker renders its exact Back target");
    assert_eq!(
        back.handle_pointer(settings_mouse(
            MouseEventKind::Down(MouseButton::Left),
            target.rect.x,
            target.rect.y,
        )),
        SettingsPointerOutcome::Consumed
    );
    assert_eq!(
        back.handle_pointer(settings_mouse(
            MouseEventKind::Up(MouseButton::Left),
            target.rect.x,
            target.rect.y,
        )),
        SettingsPointerOutcome::Consumed
    );
    assert!(matches!(
        back.test_page(),
        TestPageRef::Category(page)
            if page.category == Category::Behavior
                && page.utility_picker.is_none()
                && page.utility_picker_target.is_none()
                && page.editing.is_none()
    ));
    assert_eq!(
        back.handle_pointer(settings_mouse(
            MouseEventKind::Up(MouseButton::Left),
            target.rect.x,
            target.rect.y,
        )),
        SettingsPointerOutcome::Consumed
    );
    assert_eq!(serde_json::to_value(&back.extended).unwrap(), config_before);
    assert_eq!(
        std::fs::read(back_tmp.path().join("config.json")).unwrap(),
        persisted_before,
        "Utility Back does not write configuration"
    );
    assert!(matches!(
        back.test_page(),
        TestPageRef::Category(page)
            if page.category == Category::Behavior
                && page.utility_picker.is_none()
                && page.utility_picker_target.is_none()
                && page.editing.is_none()
    ));

    let tmp = TempDir::new().unwrap();
    let mut source = dialog_with_models(&tmp);
    open_utility_picker(&mut source);
    click_settings_action(
        &mut source,
        &pointer_actions::SettingsPointerAction::UtilityModel(
            pointer_actions::UtilityModelAction::OpenCustom,
        ),
    );
    let _ = render_settings_rows(&source, 90, 24);
    let custom_actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                shell::SettingsPointerAction::Page(
                    action @ pointer_actions::SettingsPointerAction::UtilityModel(
                        pointer_actions::UtilityModelAction::EditCustom
                        | pointer_actions::UtilityModelAction::CommitCustom
                        | pointer_actions::UtilityModelAction::CancelCustom,
                    ),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(custom_actions.len(), 3);
    for action in custom_actions {
        let mut dialog = dialog_with_models(&tmp);
        open_utility_picker(&mut dialog);
        click_settings_action(
            &mut dialog,
            &pointer_actions::SettingsPointerAction::UtilityModel(
                pointer_actions::UtilityModelAction::OpenCustom,
            ),
        );
        if matches!(
            action,
            pointer_actions::SettingsPointerAction::UtilityModel(
                pointer_actions::UtilityModelAction::CommitCustom
            )
        ) {
            type_chars(&mut dialog, "custom-provider:model");
        }
        click_settings_action(&mut dialog, &action);
        match action {
            pointer_actions::SettingsPointerAction::UtilityModel(
                pointer_actions::UtilityModelAction::EditCustom,
            ) => assert!(matches!(
                dialog.test_page(),
                TestPageRef::Category(page) if page.utility_picker.is_some()
            )),
            pointer_actions::SettingsPointerAction::UtilityModel(
                pointer_actions::UtilityModelAction::CommitCustom,
            ) => assert_eq!(
                dialog.extended.utility_model.as_deref(),
                Some("custom-provider:model")
            ),
            pointer_actions::SettingsPointerAction::UtilityModel(
                pointer_actions::UtilityModelAction::CancelCustom,
            ) => {
                assert!(matches!(
                    dialog.test_page(),
                    TestPageRef::Category(page)
                        if page.utility_picker.as_ref().is_some_and(|picker| matches!(
                            &picker.mode,
                            super::ui_page::PickerMode::List { .. }
                        ))
                ));
                assert!(dialog.extended.utility_model.is_none());

                let mut keyboard = dialog_with_models(&tmp);
                open_utility_picker(&mut keyboard);
                click_settings_action(
                    &mut keyboard,
                    &pointer_actions::SettingsPointerAction::UtilityModel(
                        pointer_actions::UtilityModelAction::OpenCustom,
                    ),
                );
                keyboard.handle_key(press(KeyCode::Esc));
                assert!(matches!(
                    keyboard.test_page(),
                    TestPageRef::Category(page)
                        if page.utility_picker.as_ref().is_some_and(|picker| matches!(
                            &picker.mode,
                            super::ui_page::PickerMode::List { .. }
                        ))
                ));
                assert!(keyboard.extended.utility_model.is_none());
            }
            _ => unreachable!(),
        }
    }

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    std::fs::write(tmp.path().join("Dockerfile"), "FROM scratch").unwrap();
    open_category_on(&mut d, Category::Privacy, SettingId::SandboxDockerfile);
    d.handle_key(press(KeyCode::Enter));
    if let TestPageMut::Category(page) = d.test_page_mut() {
        page.path_editor
            .as_mut()
            .unwrap()
            .set_text_for_test("Dock".into(), tmp.path());
    }
    let before = d.extended.sandbox.dockerfile.clone();
    let _ = render_settings_rows(&d, 72, 20);
    let target = d
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find(|target| {
            matches!(
                target.action,
                shell::SettingsPointerAction::Page(
                    pointer_actions::SettingsPointerAction::Category(
                        pointer_actions::CategoryAction::SuggestionSelect(_, _)
                    )
                )
            )
        })
        .cloned()
        .expect("directory suggestion target");
    d.handle_pointer(settings_mouse(
        MouseEventKind::Down(MouseButton::Left),
        target.rect.x,
        target.rect.y,
    ));
    assert_ne!(
        d.extended.sandbox.dockerfile, before,
        "suggestion click follows Enter commit path"
    );
}

fn instructions_pointer_fixture(tmp: &TempDir) -> SettingsDialog {
    let mut dialog = fresh_dialog(tmp);
    dialog.extended.agent_guidance_files = vec!["AGENTS.md".into(), "GUIDE.md".into()];
    dialog.page = super::instructions_page(super::ui_page::InstructionsPage::new());
    dialog
}

fn pointer_instruction_list_actions_dispatch_from_fresh_sources() {
    use pointer_actions::{ListAction, SettingsPointerAction};
    let tmp = TempDir::new().unwrap();
    let source = instructions_pointer_fixture(&tmp);
    let _ = render_settings_rows(&source, 100, 40);
    let actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::List(
                        ListAction::Add | ListAction::Edit(_) | ListAction::Delete(_),
                    ),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, SettingsPointerAction::List(ListAction::Add)))
    );
    for action in actions {
        let mut dialog = instructions_pointer_fixture(&tmp);
        click_settings_action(&mut dialog, &action);
        match action {
            SettingsPointerAction::List(ListAction::Add | ListAction::Edit(_)) => {
                assert!(matches!(
                    dialog.test_page(),
                    TestPageRef::Instructions(page) if page.grabbed.is_some()
                ))
            }
            SettingsPointerAction::List(ListAction::Delete(row)) => assert!(matches!(
                dialog.test_page(),
                TestPageRef::Instructions(page) if page.delete.is_pending_for(row.index)
            )),
            _ => unreachable!(),
        }
    }
}

pub(super) fn run_pointer_header_back_matrix() {
    for title in [
        PROVIDERS_TITLE,
        "Agents",
        "Interface",
        "Behavior",
        "Privacy & Safety",
        "Translation",
        "Profile",
        "Tools",
        "Harnesses",
        "Skills",
        "MCP",
        "LSP",
    ] {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        enter_root_node(&mut d, title);
        let _ = render_settings_rows(&d, 92, 20);
        let back = d
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .find(|target| {
                target.action
                    == shell::SettingsPointerAction::Header(shell::SettingsHeaderAction::Back)
            })
            .cloned()
            .expect("child Back target");
        d.handle_pointer(settings_mouse(
            MouseEventKind::Down(MouseButton::Left),
            back.rect.x,
            back.rect.y,
        ));
        d.handle_pointer(settings_mouse(
            MouseEventKind::Up(MouseButton::Left),
            back.rect.x,
            back.rect.y,
        ));
        assert!(
            matches!(d.test_page(), TestPageRef::Root { cursor } if cursor == root_index(title))
        );
    }

    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_one_provider(&tmp);
    d.handle_key(press(KeyCode::Enter));
    let _ = render_settings_rows(&d, 92, 20);
    let back = d
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find(|target| {
            target.action == shell::SettingsPointerAction::Header(shell::SettingsHeaderAction::Back)
        })
        .cloned()
        .unwrap();
    d.handle_pointer(settings_mouse(
        MouseEventKind::Down(MouseButton::Left),
        back.rect.x,
        back.rect.y,
    ));
    d.handle_pointer(settings_mouse(
        MouseEventKind::Up(MouseButton::Left),
        back.rect.x,
        back.rect.y,
    ));
    assert!(matches!(
        d.test_page(),
        TestPageRef::Providers(ProvidersPage::List { .. })
    ));

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.cx.picker_cwd = Some(tmp.path().to_path_buf());
    let _ = render_settings_rows(&d, 48, 10);
    let picker = d
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find(|target| {
            target.action
                == shell::SettingsPointerAction::Header(
                    shell::SettingsHeaderAction::BackToConfigPicker,
                )
        })
        .cloned()
        .expect("picker return target");
    assert_eq!(
        d.handle_pointer(settings_mouse(
            MouseEventKind::Down(MouseButton::Left),
            picker.rect.x,
            picker.rect.y
        )),
        SettingsPointerOutcome::Consumed
    );
    assert_eq!(
        d.handle_pointer(settings_mouse(
            MouseEventKind::Up(MouseButton::Left),
            picker.rect.x,
            picker.rect.y
        )),
        SettingsPointerOutcome::Close
    );
    assert!(d.back_to_picker);
}

#[test]
fn root_settings_pointer_uses_rendered_semantic_targets_and_clamped_wheel() {
    let tmp = TempDir::new().unwrap();
    let mut dialog = fresh_dialog(&tmp);
    let _ = render_settings_rows(&dialog, 80, 12);

    let first = dialog
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find(|target| {
            matches!(
                target.action,
                shell::SettingsPointerAction::Page(pointer_actions::SettingsPointerAction::Root(_))
            )
        })
        .cloned()
        .expect("root's first semantic target");
    assert_eq!(
        dialog.handle_pointer(settings_mouse(
            MouseEventKind::ScrollDown,
            first.rect.x,
            first.rect.y,
        )),
        SettingsPointerOutcome::Consumed
    );
    assert!(matches!(
        dialog.test_page(),
        TestPageRef::Root { cursor: 3 }
    ));
    for _ in 0..10 {
        let _ = dialog.handle_pointer(settings_mouse(
            MouseEventKind::ScrollUp,
            first.rect.x,
            first.rect.y,
        ));
    }
    assert!(matches!(
        dialog.test_page(),
        TestPageRef::Root { cursor: 0 }
    ));

    let _ = dialog.handle_pointer(settings_mouse(
        MouseEventKind::Down(MouseButton::Left),
        first.rect.x,
        first.rect.y,
    ));
    assert_eq!(
        dialog.page.pointer_surface_kind(),
        SettingsPointerSurfaceKind::DefaultModel
    );

    // Dispatch every identity published by the real root source, not merely
    // the first row. Each action gets a fresh dialog because navigation
    // replaces the root page.
    let source_tmp = TempDir::new().unwrap();
    let source = fresh_dialog(&source_tmp);
    let _ = render_settings_rows(&source, 100, 40);
    let actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                shell::SettingsPointerAction::Page(
                    action @ pointer_actions::SettingsPointerAction::Root(_),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(actions.len(), pointer_actions::RootNodeId::ALL.len());
    for action in actions {
        let tmp = TempDir::new().unwrap();
        let mut fresh = fresh_dialog(&tmp);
        click_settings_action(&mut fresh, &action);
        assert_ne!(
            fresh.page.pointer_surface_kind(),
            SettingsPointerSurfaceKind::Root,
            "root action did not navigate: {action:?}"
        );
    }
}

#[derive(Default)]
struct ProbePage {
    handled: bool,
}

impl SettingsPage for ProbePage {
    fn pointer_surface_kind(&self) -> super::SettingsPointerSurfaceKind {
        super::SettingsPointerSurfaceKind::Root
    }

    fn handle_key(&mut self, _cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        match key.code {
            KeyCode::Esc => Nav::Back,
            KeyCode::Char('x') => {
                self.handled = true;
                Nav::Stay
            }
            _ => Nav::Stay,
        }
    }

    fn render(&self, _cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        frame.render_widget(Paragraph::new("probe page"), area);
    }

    fn title(&self, cx: &SettingsCx) -> String {
        format!(
            "{} › Probe",
            cockpit_core::welcome::display_path(&cx.config_path)
        )
    }

    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        "probe help"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    fn test_name(&self) -> &'static str {
        "Probe"
    }
}

#[test]
fn boxed_settings_page_can_be_pushed_driven_rendered_and_popped() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);

    assert!(!d.apply_nav(Nav::Push(Box::new(ProbePage::default()))));
    assert_eq!(
        d.title(),
        format!(
            "{} › Probe",
            cockpit_core::welcome::display_path(&d.config_path)
        )
    );
    assert_eq!(d.help_text(), "probe help");

    d.handle_key(press(KeyCode::Char('x')));
    assert!(
        d.page
            .downcast_ref::<ProbePage>()
            .is_some_and(|page| page.handled),
        "probe page should handle keys through SettingsPage"
    );

    // The dialog reserves one row each for its header and help strip. Include
    // one body row inside the border so the boxed page can render content.
    let rows = render_settings_rows(&d, 40, 5).join("\n");
    assert!(rows.contains("probe page"), "rendered rows were {rows:?}");

    d.handle_key(press(KeyCode::Esc));
    assert!(matches!(d.test_page(), TestPageRef::Root { cursor: 0 }));
}

fn settings_body_area(width: u16, height: u16) -> Rect {
    Rect::new(1, 1, width.saturating_sub(2), height.saturating_sub(3))
}

#[test]
fn provider_settings_numeric_edit_render_places_caret_at_textfield_cursor() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    let entry = entry(&[]);
    let mut editor = settings_editor::SettingsEditor::for_provider("p", &entry);
    let field = settings_editor::ProviderSettingId::AutoCompactPct;
    editor.cursor = editor
        .fields()
        .iter()
        .position(|candidate| *candidate == field)
        .expect("auto compact field");
    editor.editing = Some(field);
    editor.buf = TextField::new("1234");
    editor.buf.handle_key(press(KeyCode::Home));
    editor.buf.handle_key(press(KeyCode::Right));
    editor.buf.handle_key(press(KeyCode::Right));
    d.set_test_page(Page::Providers(ProvidersPage::ProviderSettings {
        editor,
        parent: Box::new(providers::EditState::new("p".to_string(), entry)),
    }));

    let rows = render_settings_rows(&d, 100, 30).join("\n");

    assert!(rows.contains("12 34"), "{rows}");
}

#[test]
fn category_short_viewport_keeps_bottom_reset_row_visible() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.enter_category(Category::Behavior);
    if let TestPageMut::Category(p) = d.test_page_mut() {
        p.cursor = p.cursor_of_reset().expect("reset row");
    }
    let rendered = render_settings_rows(&d, 92, 12).join("\n");
    assert!(
        rendered.contains("reset behavior settings"),
        "selected reset row should be visible:\n{rendered}"
    );
    assert!(
        rendered.contains("↑"),
        "window should disclose hidden rows above:\n{rendered}"
    );
}

#[test]
fn category_wrapped_values_continue_under_value_column() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.enter_category(Category::Behavior);
    if let TestPageMut::Category(p) = d.test_page_mut() {
        p.cursor = p.cursor_of(SettingId::ApprovalMode).expect("approval mode");
    }
    let rendered = render_settings_rows(&d, 62, 30).join("\n");
    let continuation = rendered
        .lines()
        .find(|line| line.contains("leave the sandbox"))
        .unwrap_or_else(|| panic!("expected wrapped approval-mode value:\n{rendered}"));
    assert!(
        continuation.starts_with("│     "),
        "continuation should stay in the value column, not column 0:\n{rendered}"
    );
    assert!(
        !continuation.starts_with("│manual") && !continuation.starts_with("│default"),
        "continuation must not restart at the far left:\n{rendered}"
    );
}

#[test]
fn category_two_column_render_reserves_blank_gutter() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.enter_category(Category::Interface);

    let width = 92;
    let height = 16;
    let rendered = render_settings_rows(&d, width, height);
    let shell::TextColumnLayout::Two { left, right } =
        shell::settings_text_columns(settings_body_area(width, height))
    else {
        panic!("expected representative width to use two columns");
    };

    assert_eq!(
        right.x,
        left.x + left.width + shell::TEXT_COLUMN_GUTTER_WIDTH
    );
    for y in left.y..left.y + left.height {
        let row = &rendered[usize::from(y)];
        for x in left.x + left.width..right.x {
            assert_eq!(
                rendered_char(row, x),
                ' ',
                "expected blank gutter at x={x}, y={y}:\n{}",
                rendered.join("\n")
            );
        }
    }
}

#[test]
fn category_narrow_render_stacks_help_below_settings() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.enter_category(Category::Interface);

    let width = 48;
    let height = 18;
    let rendered = render_settings_rows(&d, width, height);
    let shell::TextColumnLayout::Stacked { top, bottom } =
        shell::settings_text_columns(settings_body_area(width, height))
    else {
        panic!("expected narrow width to use stacked layout");
    };

    assert!(bottom.y > top.y + top.height);
    let help_region =
        rendered[usize::from(bottom.y)..usize::from(bottom.y + bottom.height)].join("\n");
    assert!(
        help_region.contains("How the terminal UI"),
        "help pane should remain visible below the settings list:\n{}",
        rendered.join("\n")
    );
}

#[test]
fn lsp_server_row_windows_into_short_viewport() {
    let tmp = TempDir::new().unwrap();
    let cockpit_dir = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&cockpit_dir).unwrap();
    let mut d = SettingsDialog::open(cockpit_dir.join("config.json"));
    d.set_test_page(Page::Lsp(LspPage {
        cursor: LSP_SERVER_ROW_START,
        editing: None,
        buf: TextField::default(),
        status: None,
        reset: ResetButton::default(),
    }));
    let rendered = render_settings_rows(&d, 110, 10).join("\n");
    assert!(
        rendered.contains("cockpit-installed") || rendered.contains("project actions"),
        "selected LSP action/server row should be visible:\n{rendered}"
    );
    assert!(
        rendered.contains("↑"),
        "LSP viewport should show hidden rows:\n{rendered}"
    );
}

#[test]
fn shared_single_line_field_and_text_area_render_caret_and_hint() {
    let mut lines = Vec::new();
    shell::push_text_field_at_cursor(&mut lines, 24, "name", "alpha", "alpha".len(), true, None);
    let rendered = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
    assert!(rendered.contains("name: alpha\u{E000}"));

    let area = shell::text_area_lines(
        "editing agent".to_string(),
        "insert".to_string(),
        "ctrl+s: save  enter: newline  esc: cancel",
        "one\ntwo",
        (1, 1),
    );
    let rendered = area.iter().map(line_text).collect::<Vec<_>>().join("\n");
    assert!(rendered.contains("ctrl+s: save  enter: newline  esc: cancel"));
    assert!(rendered.contains("t\u{E000}wo"));
}

#[test]
fn representative_footer_hints_match_tab_and_back_close_behavior() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    assert!(d.help_text().contains("Tab/Shift+Tab"));
    d.enter_category(Category::Interface);
    let help = d.help_text();
    assert!(help.contains("Tab/Shift+Tab"), "{help}");
    assert!(help.contains("esc/h: back"), "{help}");
    assert!(help.contains("q: close"), "{help}");
    if let TestPageMut::Category(p) = d.test_page_mut() {
        p.editing = Some(SettingId::Name);
    }
    assert!(
        !d.help_text().contains("Tab/Shift+Tab"),
        "text editing contexts should not advertise Tab navigation"
    );
}

#[test]
fn behavior_command_resource_profile_rows_edit_and_persist() {
    use cockpit_config::extended::ExtendedConfigDoc;

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);

    open_category_on(&mut d, Category::Behavior, SettingId::CommandProfileRust);
    d.handle_key(press(KeyCode::Enter));
    assert!(
        !d.extended
            .command_resource_profiles
            .profile_enabled("rust_toolchain")
    );
    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert!(!reloaded.command_resource_profiles.enabled["rust_toolchain"]);

    open_category_on(
        &mut d,
        Category::Behavior,
        SettingId::CommandProfileWrappers,
    );
    d.handle_key(press(KeyCode::Enter));
    if let TestPageMut::Category(p) = d.test_page_mut() {
        p.text_editor
            .as_mut()
            .expect("wrappers editor")
            .set_text_for_test(
                r#"{"just ci":["rust_toolchain","node_package_manager"]}"#.to_string(),
            );
    }
    d.handle_key(ctrl('s'));
    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert_eq!(
        reloaded.command_resource_profiles.wrappers["just ci"],
        vec![
            "rust_toolchain".to_string(),
            "node_package_manager".to_string()
        ]
    );

    open_category_on(
        &mut d,
        Category::Behavior,
        SettingId::CommandProfileCustomProfiles,
    );
    d.handle_key(press(KeyCode::Enter));
    if let TestPageMut::Category(p) = d.test_page_mut() {
        p.text_editor
                .as_mut()
                .expect("profiles editor")
                .set_text_for_test(
                    r#"{"terraform_toolchain":{"commands":["terraform"],"roots":[{"kind":"terraform_plugin_cache","path":".terraform","withinCwd":true}]}}"#.to_string(),
                );
    }
    d.handle_key(ctrl('s'));
    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    let profile = &reloaded.command_resource_profiles.profiles["terraform_toolchain"];
    assert_eq!(profile.commands, vec!["terraform".to_string()]);
    assert_eq!(profile.roots[0].kind, "terraform_plugin_cache");
    assert!(profile.roots[0].within_cwd);
}

#[test]
fn behavior_default_agent_row_cycles_and_persists() {
    use cockpit_config::extended::{DefaultPrimaryAgent, ExtendedConfigDoc};
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    assert_eq!(d.extended.default_primary_agent, DefaultPrimaryAgent::Build);
    open_category_on(&mut d, Category::Behavior, SettingId::DefaultPrimaryAgent);
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.default_primary_agent, DefaultPrimaryAgent::Plan);
    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert_eq!(reloaded.default_primary_agent, DefaultPrimaryAgent::Plan);
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.default_primary_agent, DefaultPrimaryAgent::Build);
}

#[test]
fn roster_trim_behavior_settings_has_no_experimental_row_and_cycles_build_plan() {
    use cockpit_config::extended::DefaultPrimaryAgent;
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);

    open_category_on(&mut d, Category::Behavior, SettingId::DefaultPrimaryAgent);
    let rendered = render_settings_rows(&d, 100, 30).join("\n");
    assert!(
        !rendered.contains("experimental mode"),
        "experimental mode row must be removed"
    );
    d.extended.default_primary_agent = DefaultPrimaryAgent::Plan;
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.default_primary_agent, DefaultPrimaryAgent::Build);
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.default_primary_agent, DefaultPrimaryAgent::Plan);
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.default_primary_agent, DefaultPrimaryAgent::Build);
}

#[test]
fn category_ctrl_g_focused_prose_setting_round_trips_and_commits() {
    use cockpit_config::extended::ExtendedConfigDoc;

    let _env = EditorEnv::with(Some("true"));
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    open_category_on(&mut d, Category::Behavior, SettingId::CompactPrompt);
    d.handle_key(ctrl('g'));
    let (operation_id, path) = d
        .take_pending_category_external_edit()
        .expect("category external edit should be pending");
    assert!(d.take_pending_category_external_edit().is_none());
    std::fs::write(&path, "external compact prompt\n").unwrap();
    d.finish_category_external_edit(
        operation_id,
        pointer_actions::ExternalEditOutcome::Saved,
        None,
    );

    assert_eq!(
        d.extended.compact_prompt.as_deref(),
        Some("external compact prompt")
    );
    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert_eq!(
        reloaded.compact_prompt.as_deref(),
        Some("external compact prompt")
    );
}

#[test]
fn category_ctrl_g_ignores_numeric_settings_and_reports_missing_editor() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);

    let _env = EditorEnv::with(Some("true"));
    open_category_on(&mut d, Category::Behavior, SettingId::ScheduleMaxConcurrent);
    d.handle_key(ctrl('g'));
    assert!(d.take_pending_category_external_edit().is_none());

    drop(_env);
    let _env = EditorEnv::unset();
    open_category_on(&mut d, Category::Behavior, SettingId::CompactPrompt);
    d.handle_key(ctrl('g'));
    assert!(d.take_pending_category_external_edit().is_none());
    match d.test_page() {
        TestPageRef::Category(p) => {
            assert_eq!(p.status.as_deref(), Some("No $EDITOR environment variable"))
        }
        _ => panic!("not on category page"),
    }
}

#[test]
fn mcp_add_form_renders_cursor_at_textfield_position() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.set_test_page(Page::Mcp(McpPage::Add(Box::new(mcp_page::AddState {
        original_name: None,
        name: TextField::new("abcd"),
        endpoint: TextField::default(),
        command: TextField::default(),
        args: TextField::default(),
        base_env: TextField::default(),
        stored_base_env_refs: BTreeMap::new(),
        transport: cockpit_core::mcp::config::Transport::Streamable,
        auth: mcp_page::AuthKind::None,
        header_name: TextField::default(),
        header_value: TextField::default(),
        stored_header_credential_ref: None,
        auth_env: TextField::default(),
        stored_auth_env_refs: BTreeMap::new(),
        oauth_authorize_url: TextField::default(),
        oauth_token_url: TextField::default(),
        oauth_client_id: TextField::default(),
        oauth_scopes: TextField::default(),
        enabled: true,
        cache_ttl_secs: TextField::new("3600"),
        connect_timeout_secs: TextField::default(),
        request_timeout_secs: TextField::default(),
        cursor: 0,
        status: None,
    }))));
    d.handle_key(press(KeyCode::Home));
    d.handle_key(press(KeyCode::Right));
    d.handle_key(press(KeyCode::Right));
    d.handle_key(press(KeyCode::Char('X')));

    let width = 96;
    let height = 24;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("terminal");
    let mut links = crate::tui::links::LinkRegistry::default();
    terminal
        .draw(|frame| d.render(frame, Rect::new(0, 0, width, height), &mut links))
        .expect("draw");
    let rendered: Vec<String> = terminal
        .backend()
        .buffer()
        .content()
        .chunks(usize::from(width))
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect();
    let y = rendered
        .iter()
        .position(|row| row.contains("name: abX"))
        .expect("name row rendered") as u16;
    let row = &rendered[usize::from(y)];
    let value_start = row.find("name: ").expect("name label rendered") + "name: ".len();
    let value_end = row.find("cd").expect("tail rendered") + "cd".len();
    let cursor = terminal.backend_mut().get_cursor_position().unwrap();
    assert_eq!(cursor.y, y);
    assert!(
        usize::from(cursor.x) > value_start && usize::from(cursor.x) < value_end,
        "cursor should be inside the edited value, not pinned at the end: row={row:?}, cursor={cursor:?}"
    );
}

#[test]
fn behavior_packages_dir_text_edit_persists() {
    use cockpit_config::extended::ExtendedConfigDoc;
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    open_category_on(&mut d, Category::Behavior, SettingId::PackagesDir);
    d.handle_key(press(KeyCode::Enter)); // open path editor
    if let TestPageMut::Category(p) = d.test_page_mut() {
        p.path_editor
            .as_mut()
            .expect("packages path editor")
            .set_text_for_test("/tmp/pkgs".to_string(), tmp.path());
    }
    d.handle_key(press(KeyCode::Enter)); // commit
    assert_eq!(
        d.extended.packages_directory.as_deref(),
        Some(std::path::Path::new("/tmp/pkgs"))
    );
    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert_eq!(
        reloaded.packages_directory,
        Some(std::path::PathBuf::from("/tmp/pkgs"))
    );
}

#[test]
fn behavior_jobs_max_concurrent_rejects_zero() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    let before = d.extended.schedule.max_concurrent;
    open_category_on(&mut d, Category::Behavior, SettingId::ScheduleMaxConcurrent);
    d.handle_key(press(KeyCode::Enter)); // open edit (seeded with current)
    // Clear and type 0.
    for _ in 0..6 {
        d.handle_key(press(KeyCode::Backspace));
    }
    type_chars(&mut d, "0");
    d.handle_key(press(KeyCode::Enter)); // reject
    match d.test_page() {
        TestPageRef::Category(p) => {
            assert!(p.is_editing(), "stays open on invalid input");
            assert!(p.status.as_deref().unwrap_or("").contains(">="));
        }
        _ => panic!("not on category page"),
    }
    assert_eq!(
        d.extended.schedule.max_concurrent, before,
        "garbage not persisted"
    );
}

#[test]
fn privacy_sandbox_rows_cycle_edit_and_persist() {
    use cockpit_config::extended::ExtendedConfigDoc;
    use cockpit_proto::FeatureCapabilityState;
    use cockpit_proto::SandboxMode;

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.host_capabilities = crate::tui::capability_gate::snapshot_with_sandbox(
        FeatureCapabilityState::Available,
        FeatureCapabilityState::Missing,
    );
    d.extended.sandbox.default_mode = SandboxMode::Off;
    d.save_extended().unwrap();

    open_category_on(&mut d, Category::Privacy, SettingId::SandboxDefaultMode);
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.sandbox.default_mode, SandboxMode::Sandbox);

    let dockerfile = tmp.path().join("Dockerfile");
    std::fs::write(&dockerfile, "FROM scratch").unwrap();
    open_category_on(&mut d, Category::Privacy, SettingId::SandboxDockerfile);
    d.handle_key(press(KeyCode::Enter));
    if let TestPageMut::Category(p) = d.test_page_mut() {
        let editor = p.path_editor.as_mut().expect("dockerfile path editor");
        editor.set_text_for_test("Dock".to_string(), tmp.path());
        assert!(
            editor
                .suggest
                .entries
                .iter()
                .any(|entry| !entry.is_dir && entry.name == "Dockerfile"),
            "file suggestions should include Dockerfile"
        );
    }
    d.handle_key(press(KeyCode::Tab));
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(
        d.extended.sandbox.dockerfile.as_deref(),
        Some(std::path::Path::new("Dockerfile"))
    );

    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert_eq!(reloaded.sandbox.default_mode, SandboxMode::Sandbox);
    assert_eq!(
        reloaded.sandbox.dockerfile,
        Some(std::path::PathBuf::from("Dockerfile"))
    );
}

fn inject_missing_host_sandbox(d: &mut SettingsDialog, fix: &str) {
    d.host_capabilities = crate::tui::capability_gate::snapshot_with_sandbox_reasons(
        cockpit_proto::FeatureCapabilityState::Missing,
        cockpit_proto::FeatureCapabilityState::Available,
        "bwrap is not installed",
        Some(fix),
    );
}

fn inject_secret_store(
    d: &mut SettingsDialog,
    intent: cockpit_proto::SecretStoreIntent,
    placement: cockpit_proto::SecretStorePlacement,
    keyring: cockpit_proto::FeatureCapabilityState,
) {
    let mut store = crate::tui::capability_gate::unified_secret_store(intent, placement);
    if keyring != cockpit_proto::FeatureCapabilityState::Available {
        store.fail_closed_reason = Some("secret service unavailable".into());
        store.fix_command = Some("install gnome-keyring".into());
    }
    d.host_capabilities = crate::tui::capability_gate::with_secret_store(
        crate::tui::capability_gate::snapshot_with_sandbox(
            cockpit_proto::FeatureCapabilityState::Available,
            cockpit_proto::FeatureCapabilityState::Missing,
        ),
        store,
        keyring,
        if keyring == cockpit_proto::FeatureCapabilityState::Available {
            "platform keyring can hold a wrapping key"
        } else {
            "secret service unavailable"
        },
        (keyring != cockpit_proto::FeatureCapabilityState::Available)
            .then_some("install gnome-keyring"),
    );
}

#[test]
fn privacy_sandbox_on_blocked_when_host_cap_missing() {
    use cockpit_config::extended::ExtendedConfigDoc;
    use cockpit_proto::SandboxMode;

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    inject_missing_host_sandbox(&mut d, "sudo apt-get install bubblewrap");
    d.extended.sandbox.default_mode = SandboxMode::Off;
    d.save_extended().unwrap();

    open_category_on(&mut d, Category::Privacy, SettingId::SandboxDefaultMode);
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.sandbox.default_mode, SandboxMode::Off);
    match d.test_page() {
        TestPageRef::Category(p) => {
            let status = p.status.as_deref().unwrap_or("");
            assert!(
                status.contains("sudo apt-get install bubblewrap") || status.contains("bwrap"),
                "blocked on must show snapshot remedy, got {status:?}"
            );
        }
        _ => panic!("not on category page"),
    }
    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert_eq!(reloaded.sandbox.default_mode, SandboxMode::Off);
}

#[test]
fn sandbox_on_recheck_then_instruct() {
    use cockpit_config::extended::ExtendedConfigDoc;
    use cockpit_proto::SandboxMode;

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    inject_missing_host_sandbox(&mut d, "sudo apt-get install bubblewrap");
    d.extended.sandbox.default_mode = SandboxMode::Off;
    d.save_extended().unwrap();

    open_category_on(&mut d, Category::Privacy, SettingId::SandboxDefaultMode);
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.capability_refresh_calls, 1);
    assert_eq!(d.extended.sandbox.default_mode, SandboxMode::Off);
    match d.test_page() {
        TestPageRef::Category(p) => {
            let status = p.status.as_deref().unwrap_or("");
            assert!(
                status.contains("sudo apt-get install bubblewrap"),
                "{status:?}"
            );
        }
        _ => panic!("not on category page"),
    }

    d.capability_refresh_queue
        .push(crate::tui::capability_gate::snapshot_with_sandbox(
            cockpit_proto::FeatureCapabilityState::Available,
            cockpit_proto::FeatureCapabilityState::Missing,
        ));
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.sandbox.default_mode, SandboxMode::Sandbox);
    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert_eq!(reloaded.sandbox.default_mode, SandboxMode::Sandbox);
}

#[test]
fn secret_store_row_shows_intent_without_preparing_gate() {
    use cockpit_proto::{SecretStoreIntent, SecretStorePlacement};

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    inject_secret_store(
        &mut d,
        SecretStoreIntent::Database,
        SecretStorePlacement::Database,
        cockpit_proto::FeatureCapabilityState::Available,
    );
    open_category_on(&mut d, Category::Privacy, SettingId::SecretStore);
    assert_eq!(
        d.category_value_for_test(SettingId::SecretStore),
        crate::tui::capability_gate::SECRET_STORE_DATABASE_LABEL
    );
}

#[test]
fn secret_store_row_first_run_shows_keyring_when_available() {
    use cockpit_proto::{SecretStoreIntent, SecretStorePlacement};

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    inject_secret_store(
        &mut d,
        SecretStoreIntent::Keyring,
        SecretStorePlacement::Keyring,
        cockpit_proto::FeatureCapabilityState::Available,
    );
    open_category_on(&mut d, Category::Privacy, SettingId::SecretStore);
    assert_eq!(
        d.category_value_for_test(SettingId::SecretStore),
        crate::tui::capability_gate::SECRET_STORE_KEYRING_LABEL
    );
}

#[test]
fn secret_store_row_rejects_keyring_when_missing() {
    use cockpit_proto::{SecretStoreIntent, SecretStorePlacement};

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    inject_secret_store(
        &mut d,
        SecretStoreIntent::Database,
        SecretStorePlacement::Database,
        cockpit_proto::FeatureCapabilityState::Missing,
    );
    open_category_on(&mut d, Category::Privacy, SettingId::SecretStore);
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.secret_store_migrate_calls, 0);
    match d.test_page() {
        TestPageRef::Category(p) => {
            let status = p.status.as_deref().unwrap_or("");
            assert!(
                status.contains("install gnome-keyring") || status.contains("unavailable"),
                "{status:?}"
            );
        }
        _ => panic!("not on category page"),
    }
    assert_eq!(
        d.host_capabilities.secret_store.effective_placement,
        SecretStorePlacement::Database
    );
}

#[test]
fn secret_store_row_applies_keyring_after_recheck() {
    use cockpit_proto::{SecretStoreIntent, SecretStorePlacement};

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    inject_secret_store(
        &mut d,
        SecretStoreIntent::Database,
        SecretStorePlacement::Database,
        cockpit_proto::FeatureCapabilityState::Missing,
    );
    let mut available = d.host_capabilities.clone();
    if let Some(row) = available
        .features
        .iter_mut()
        .find(|row| row.id == cockpit_core::host_capabilities::FEATURE_SECRET_STORE_KEYRING)
    {
        row.state = cockpit_proto::FeatureCapabilityState::Available;
        row.reason = "platform keyring can hold a wrapping key".into();
        row.fix_command = None;
    }
    available.secret_store = crate::tui::capability_gate::unified_secret_store(
        SecretStoreIntent::Database,
        SecretStorePlacement::Database,
    );
    d.capability_refresh_queue.push(available);
    d.secret_store_migrate = Some(std::sync::Arc::new(|dest| {
        Ok(crate::tui::capability_gate::unified_secret_store(
            match dest {
                SecretStorePlacement::Keyring => SecretStoreIntent::Keyring,
                _ => SecretStoreIntent::Database,
            },
            dest,
        ))
    }));
    open_category_on(&mut d, Category::Privacy, SettingId::SecretStore);
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.secret_store_migrate_calls, 1);
    assert_eq!(
        d.host_capabilities.secret_store.effective_placement,
        SecretStorePlacement::Keyring
    );
}

#[test]
fn secret_store_row_does_not_write_layered_config() {
    use cockpit_config::extended::ExtendedConfigDoc;
    use cockpit_proto::{SecretStoreIntent, SecretStorePlacement};

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    inject_secret_store(
        &mut d,
        SecretStoreIntent::Database,
        SecretStorePlacement::Database,
        cockpit_proto::FeatureCapabilityState::Available,
    );
    d.secret_store_migrate = Some(std::sync::Arc::new(|dest| {
        Ok(crate::tui::capability_gate::unified_secret_store(
            SecretStoreIntent::Keyring,
            dest,
        ))
    }));
    open_category_on(&mut d, Category::Privacy, SettingId::SecretStore);
    d.handle_key(press(KeyCode::Enter));
    let raw = std::fs::read_to_string(&d.extended_path).unwrap();
    assert!(
        !raw.contains("secretStore") && !raw.contains("secret_store"),
        "settings must not write secretStore into layered config: {raw}"
    );
    let doc = ExtendedConfigDoc::load(&d.extended_path).unwrap();
    assert!(doc.raw_field("secretStore").is_none());
}

#[test]
fn secret_store_row_help_mentions_encrypted_sqlite_and_is_weaker() {
    use cockpit_proto::{SecretStoreIntent, SecretStorePlacement};

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    inject_secret_store(
        &mut d,
        SecretStoreIntent::Database,
        SecretStorePlacement::Database,
        cockpit_proto::FeatureCapabilityState::Available,
    );
    let help = crate::tui::capability_gate::secret_store_row_help(&d.host_capabilities);
    let lower = help.to_ascii_lowercase();
    assert!(help.contains("encrypted SQLite") || lower.contains("encrypted sqlite"));
    assert!(lower.contains("kek"));
    assert!(lower.contains("weaker"));
    assert!(!lower.contains("plaintext"));
}

#[test]
fn secret_store_available_keyring_rejects_database_placement() {
    use cockpit_core::secure_key::TestInjectedVault;
    use cockpit_proto::{FeatureCapabilityState, SecretStoreIntent, SecretStorePlacement};

    let tmp = TempDir::new().unwrap();
    let vault = TestInjectedVault::first_run_database(tmp.path());
    vault.promote_to_keyring();
    assert_eq!(vault.keyring_kek.len(), 1);
    assert_eq!(vault.file_kek.len(), 0);

    let mut d = fresh_dialog(&tmp);
    inject_secret_store(
        &mut d,
        SecretStoreIntent::Keyring,
        SecretStorePlacement::Keyring,
        FeatureCapabilityState::Available,
    );
    d.secret_store_migrate = Some(std::sync::Arc::new(move |_| {
        panic!("available keyring must not migrate dest=database");
    }));
    open_category_on(&mut d, Category::Privacy, SettingId::SecretStore);
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.secret_store_migrate_calls, 0);
    match d.test_page() {
        TestPageRef::Category(p) => {
            assert!(p.secret_store_confirm.is_none());
            let status = p.status.as_deref().unwrap_or("");
            assert!(
                status.contains("database") && status.contains("keyring"),
                "switcher must reject dest=database: {status:?}"
            );
        }
        _ => panic!("not on category page"),
    }
    assert_eq!(
        d.host_capabilities.secret_store.intent,
        SecretStoreIntent::Keyring
    );
    assert_eq!(
        d.host_capabilities.secret_store.effective_placement,
        SecretStorePlacement::Keyring
    );
    assert_eq!(vault.keyring_kek.len(), 1);
    assert_eq!(vault.file_kek.len(), 0);
}

#[test]
fn dependencies_page_refresh_after_first_paint() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let hook_calls = calls.clone();
    d.dependency_refresh = Some(std::sync::Arc::new(move || {
        hook_calls.fetch_add(1, Ordering::SeqCst);
    }));
    d.enter_dependencies_for_test();
    assert_eq!(d.dependency_refresh_calls, 0);
    d.handle_key(press(KeyCode::Char('r')));
    assert_eq!(d.dependency_refresh_calls, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    d.handle_key(press(KeyCode::Char('r')));
    assert_eq!(
        d.dependency_refresh_calls, 1,
        "in-flight refresh must not stack"
    );
}

#[test]
fn behavior_sandbox_escalation_toggles_persists_and_updates_daemon() {
    use cockpit_config::extended::ExtendedConfigDoc;

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    assert!(d.extended.sandbox_escalation_enabled);

    open_category_on(
        &mut d,
        Category::Behavior,
        SettingId::SandboxEscalationEnabled,
    );
    d.handle_key(press(KeyCode::Enter));
    assert!(!d.extended.sandbox_escalation_enabled);

    match d.pending_daemon_request.take() {
        Some(Request::SetSandboxEscalation { enabled }) => assert!(!enabled),
        other => panic!("expected sandbox escalation request, got {other:?}"),
    }

    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert!(!reloaded.sandbox_escalation_enabled);
}

#[test]
fn privacy_redaction_rows_toggle_and_persist() {
    use cockpit_config::extended::ExtendedConfigDoc;
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    assert!(d.extended.redact.scan_environment);
    assert!(d.extended.redact.scan_dotenv);
    open_category_on(&mut d, Category::Privacy, SettingId::RedactScanEnvironment);
    d.handle_key(press(KeyCode::Enter));
    assert!(!d.extended.redact.scan_environment);
    // The env-file row is the next one down.
    d.handle_key(press(KeyCode::Down));
    let want = match d.test_page() {
        TestPageRef::Category(p) => p.cursor_of(SettingId::RedactScanDotenv),
        _ => None,
    };
    assert_eq!(category_cursor(&d), want);
    d.handle_key(press(KeyCode::Enter));
    assert!(!d.extended.redact.scan_dotenv);
    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert!(!reloaded.redact.scan_environment);
    assert!(!reloaded.redact.scan_dotenv);
}

#[test]
fn privacy_redact_min_secret_length_rejects_non_numeric() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    let before = d.extended.redact.min_secret_length;
    open_category_on(&mut d, Category::Privacy, SettingId::RedactMinSecretLength);
    d.handle_key(press(KeyCode::Enter));
    for _ in 0..4 {
        d.handle_key(press(KeyCode::Backspace));
    }
    type_chars(&mut d, "abc");
    d.handle_key(press(KeyCode::Enter));
    match d.test_page() {
        TestPageRef::Category(p) => assert!(p.is_editing(), "stays open on bad input"),
        _ => panic!("not on category page"),
    }
    assert_eq!(d.extended.redact.min_secret_length, before);
}

#[test]
fn translation_languages_edit_and_persist() {
    use cockpit_config::extended::ExtendedConfigDoc;
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    open_category_on(
        &mut d,
        Category::Translation,
        SettingId::TranslationUserLanguage,
    );
    d.handle_key(press(KeyCode::Enter));
    type_chars(&mut d, "English");
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.translation.user_language, "English");
    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert_eq!(reloaded.translation.user_language, "English");
}

#[test]
fn profile_name_edit_and_persist() {
    use cockpit_config::extended::ExtendedConfigDoc;
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    open_category_on(&mut d, Category::Profile, SettingId::Name);
    d.handle_key(press(KeyCode::Enter));
    type_chars(&mut d, "Ada");
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.name.as_deref(), Some("Ada"));
    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert_eq!(reloaded.name.as_deref(), Some("Ada"));
}

#[test]
fn global_name_edit_prompts_to_remove_shadowing_project_value() {
    use cockpit_config::extended::ExtendedConfigDoc;
    let tmp = TempDir::new().unwrap();
    let global = tmp.path().join("home/.config/cockpit/config.json");
    let project = tmp.path().join("repo");
    let project_config = project.join(".cockpit/config.json");
    std::fs::create_dir_all(global.parent().unwrap()).unwrap();
    std::fs::create_dir_all(project_config.parent().unwrap()).unwrap();
    std::fs::write(&global, r#"{"name":"Global"}"#).unwrap();
    std::fs::write(
        &project_config,
        r#"{"name":"Project","tui":{"show_cwd":false}}"#,
    )
    .unwrap();
    // Neither layer sits under a root the daemon discovers from this test's
    // process cwd; register both so the global edit and the project-shadow
    // removal each resolve their own layer.
    super::disk_daemon_fake::register_settings_layer_target(&global);
    super::disk_daemon_fake::register_settings_layer_target(&project_config);

    let mut d = SettingsDialog::open_from_picker(global.clone(), project.clone());
    open_category_on(&mut d, Category::Profile, SettingId::Name);
    d.handle_key(press(KeyCode::Enter));
    for _ in 0..20 {
        d.handle_key(press(KeyCode::Backspace));
    }
    type_chars(&mut d, "Ada");
    d.handle_key(press(KeyCode::Enter));

    match d.test_page() {
        TestPageRef::Category(p) => {
            assert!(p.shadowed_global.is_some());
            assert!(
                p.status
                    .as_deref()
                    .unwrap_or("")
                    .contains("Remove that project value")
            );
        }
        _ => panic!("not on category page"),
    }

    d.handle_key(press(KeyCode::Char('y')));
    let global_cfg = ExtendedConfigDoc::load(&global).unwrap().config();
    let project_raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&project_config).unwrap()).unwrap();
    assert_eq!(global_cfg.name.as_deref(), Some("Ada"));
    assert!(project_raw.get("name").is_none());
    assert_eq!(project_raw["tui"]["show_cwd"], false);
}

pub(super) fn run_pointer_category_confirmation_and_effect_matrix() {
    use cockpit_config::extended::ExtendedConfigDoc;
    for (choice, removes) in [
        (pointer_actions::ConfirmationChoice::Confirm, true),
        (pointer_actions::ConfirmationChoice::Cancel, false),
    ] {
        let tmp = TempDir::new().unwrap();
        let global = tmp.path().join("home/.config/cockpit/config.json");
        let project = tmp.path().join("repo");
        let project_config = project.join(".cockpit/config.json");
        std::fs::create_dir_all(global.parent().unwrap()).unwrap();
        std::fs::create_dir_all(project_config.parent().unwrap()).unwrap();
        std::fs::write(&global, r#"{"name":"Global"}"#).unwrap();
        std::fs::write(&project_config, r#"{"name":"Project"}"#).unwrap();
        super::disk_daemon_fake::register_settings_layer_target(&global);
        super::disk_daemon_fake::register_settings_layer_target(&project_config);
        let mut dialog = SettingsDialog::open_from_picker(global, project);
        open_category_on(&mut dialog, Category::Profile, SettingId::Name);
        dialog.handle_key(press(KeyCode::Enter));
        type_chars(&mut dialog, " pointer");
        dialog.handle_key(press(KeyCode::Enter));
        let _ = render_settings_rows(&dialog, 80, 20);
        click_settings_action(
            &mut dialog,
            &pointer_actions::SettingsPointerAction::Category(
                pointer_actions::CategoryAction::Confirm(SettingId::Name, choice),
            ),
        );
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&project_config).unwrap()).unwrap();
        assert_eq!(raw.get("name").is_none(), removes);
        assert!(matches!(
            dialog.test_page(),
            TestPageRef::Category(page) if page.shadowed_global.is_none()
        ));
        let _ = ExtendedConfigDoc::load(&dialog.config_path).unwrap();
    }

    let guard = cockpit_test_support::TestEnvGuard::blocking_lock();
    guard.set_var("EDITOR", "true");
    let tmp = TempDir::new().unwrap();
    let mut dialog = fresh_dialog(&tmp);
    open_category_on(&mut dialog, Category::Profile, SettingId::Name);
    dialog.handle_key(press(KeyCode::Enter));
    let action = pointer_actions::SettingsPointerAction::Category(
        pointer_actions::CategoryAction::ExternalEditBegin(
            SettingId::Name,
            pointer_actions::CategoryExternalSource::Inline,
        ),
    );
    let _ = render_settings_rows(&dialog, 80, 20);
    click_settings_action(&mut dialog, &action);
    let (operation, _) = dialog
        .take_pending_category_external_edit()
        .expect("category effect drains once");
    assert!(dialog.take_pending_category_external_edit().is_none());
    dialog.finish_category_external_edit(
        PointerOperationId(operation.0 + 1),
        pointer_actions::ExternalEditOutcome::Saved,
        None,
    );
    assert!(matches!(
        dialog.test_page(),
        TestPageRef::Category(page) if page.pending_external_edit.is_some()
    ));
    let saved_action = pointer_actions::SettingsPointerAction::Category(
        pointer_actions::CategoryAction::ExternalEditResult(
            SettingId::Name,
            pointer_actions::ExternalEditOutcome::Saved,
        ),
    );
    super::pointer_acceptance_tests::record_source_action(&saved_action);
    dialog.finish_category_external_edit(
        operation,
        pointer_actions::ExternalEditOutcome::Saved,
        None,
    );
    super::pointer_acceptance_tests::record_dispatched_action(&saved_action);
    let status = match dialog.test_page() {
        TestPageRef::Category(page) => page.status.clone(),
        _ => unreachable!(),
    };
    dialog.finish_category_external_edit(
        operation,
        pointer_actions::ExternalEditOutcome::Failed,
        Some("duplicate".into()),
    );
    assert!(matches!(
        dialog.test_page(),
        TestPageRef::Category(page) if page.status == status
    ));

    for outcome in [
        pointer_actions::ExternalEditOutcome::Cancelled,
        pointer_actions::ExternalEditOutcome::Failed,
    ] {
        let tmp = TempDir::new().unwrap();
        let mut dialog = fresh_dialog(&tmp);
        open_category_on(&mut dialog, Category::Profile, SettingId::Name);
        dialog.handle_key(press(KeyCode::Enter));
        type_chars(&mut dialog, " retained-draft");
        let _ = render_settings_rows(&dialog, 80, 20);
        click_settings_action(
            &mut dialog,
            &pointer_actions::SettingsPointerAction::Category(
                pointer_actions::CategoryAction::ExternalEditBegin(
                    SettingId::Name,
                    pointer_actions::CategoryExternalSource::Inline,
                ),
            ),
        );
        let operation = dialog
            .take_pending_category_external_edit()
            .expect("category outcome effect")
            .0;
        let result_action = pointer_actions::SettingsPointerAction::Category(
            pointer_actions::CategoryAction::ExternalEditResult(SettingId::Name, outcome),
        );
        super::pointer_acceptance_tests::record_source_action(&result_action);
        dialog.finish_category_external_edit(operation, outcome, None);
        super::pointer_acceptance_tests::record_dispatched_action(&result_action);
        assert!(matches!(
            dialog.test_page(),
            TestPageRef::Category(page)
                if page.pending_external_edit.is_none()
                    && page.editing == Some(SettingId::Name)
                    && page.buf.text().contains("retained-draft")
        ));
    }
}

fn dialog_with_one_provider(tmp: &TempDir) -> SettingsDialog {
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    write_provider_file(&path, "vendor", r#"{"url":"https://x","headers":[]}"#);
    let mut d = open_fixture_dialog(&path);
    d.enter_providers();
    d
}

/// Environment + in-process daemon guard for settings tests whose mutations are
/// owner-remoted. The fixture must outlive the dialog: dropping it restores the
/// environment and tears the promoted daemon down.
struct SettingsDaemonFixture {
    _env: cockpit_test_support::TestEnvGuard,
    _daemon: cockpit_core::daemon::InProcessAutoPromoteGuard,
}

/// A one-provider dialog whose config writes and secret cleanups are
/// owner-remoted to an isolated in-process daemon (production layered config
/// source) rather than timing out on a real socket. The environment is
/// isolated, `COCKPIT_CONFIG` pins the daemon's write target to the dialog's
/// config file (so owner-remoted provider writes land where the dialog reads
/// them back), and the workspace is trusted — as a user trusts it once —
/// because owner-remoted config writes fail closed on an untrusted workspace.
fn daemon_dialog_with_one_provider(tmp: &TempDir) -> (SettingsDialog, SettingsDaemonFixture) {
    let root = tmp.path();
    let env = cockpit_test_support::TestEnvGuard::blocking_lock();
    for (var, sub) in [
        ("HOME", "home"),
        ("XDG_CONFIG_HOME", "xdg-config"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_STATE_HOME", "state"),
        ("XDG_RUNTIME_DIR", "runtime"),
    ] {
        let dir = root.join(sub);
        std::fs::create_dir_all(&dir).unwrap();
        env.set_var(var, &dir);
    }
    env.set_var("COCKPIT_TEST_NO_KEYRING", "1");

    let path = root.join("config.json");
    std::fs::write(&path, "{}").unwrap();
    env.set_cockpit_config(&path);
    write_provider_file(&path, "vendor", r#"{"url":"https://x","headers":[]}"#);

    let daemon = cockpit_core::daemon::enable_in_process_auto_promote_with_production_config();

    let mut d = SettingsDialog::open(path);
    d.active_project_root = Some(root.to_path_buf());
    d.enter_providers();

    seed_workspace_trust(root);

    (
        d,
        SettingsDaemonFixture {
            _env: env,
            _daemon: daemon,
        },
    )
}

/// Trust `root` in the promoted daemon so owner-remoted config writes are
/// accepted. Trust is DB-owned by the daemon (a local runtime-policy override
/// would not reach its authoritative check), so it must be set via RPC. The
/// transient runtime here only carries the request; the daemon context — and
/// thus the seeded trust — persists across the per-call runtimes the settings
/// reducers spin up.
fn seed_workspace_trust(root: &std::path::Path) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("settings trust seed runtime");
    runtime.block_on(async {
        let lifecycle = crate::tui::settings::test_lifecycle_client();
        let client = crate::tui::settings::settings_daemon_client(&lifecycle)
            .await
            .expect("settings daemon client for trust seed");
        let project_root = root.display().to_string();
        let expected_config_generation = match client
            .request(Request::GetWorkspaceTrust {
                project_root: project_root.clone(),
            })
            .await
            .expect("trust read transport")
            .expect("trust read response")
        {
            Response::WorkspaceTrust {
                config_generation, ..
            } => config_generation,
            other => panic!("unexpected trust read: {other:?}"),
        };
        match client
            .request(Request::SetWorkspaceTrust {
                project_root,
                mode: cockpit_proto::WorkspaceTrustMode::Trust,
                expected_config_generation,
            })
            .await
            .expect("trust set transport")
            .expect("trust set response")
        {
            Response::WorkspaceTrustSet { .. } => {}
            other => panic!("unexpected trust set: {other:?}"),
        }
    });
}

#[test]
fn save_config_preserves_untouched_provider_file_disk_edits() {
    let tmp = TempDir::new().unwrap();
    let (mut d, _fx) = daemon_dialog_with_one_provider(&tmp);
    write_provider_file(
        &d.config_path,
        "vendor",
        r#"{"url":"https://out-of-band","headers":[]}"#,
    );

    d.config.active_model = Some(cockpit_config::providers::ActiveModelRef {
        provider: "vendor".into(),
        model: "m1".into(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    });
    d.save_config().unwrap();

    let reloaded = cockpit_config::providers::ConfigDoc::load(&d.config_path)
        .unwrap()
        .providers();
    assert_eq!(reloaded.providers["vendor"].url, "https://out-of-band");
    assert_eq!(
        reloaded.active_model, None,
        "`/settings` must never write `active_model` directly; the daemon owns it"
    );
    let staged_id = d.pending_default_model_update_id;
    match d.pending_daemon_request.take() {
        Some(Request::SetDefaultModel {
            provider,
            model,
            clear,
            default_update_id,
            ..
        }) => {
            assert_eq!(provider.as_deref(), Some("vendor"));
            assert_eq!(model.as_deref(), Some("m1"));
            assert!(!clear);
            assert_eq!(staged_id, Some(default_update_id));
        }
        other => panic!("expected a staged SetDefaultModel request, got {other:?}"),
    }
}

#[test]
fn root_menu_exposes_the_default_model_row_first() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let d = open_fixture_dialog(&path);
    assert_eq!(root_nodes()[0].title, DEFAULT_MODEL_TITLE);
    assert!(matches!(d.test_page(), TestPageRef::Root { cursor: 0 }));
}

#[cfg(not(feature = "extended"))]
#[test]
fn root_menu_inventory_matches_the_default_profile() {
    let nodes = root_nodes();
    assert_eq!(nodes.len(), 15);
    assert_eq!(nodes[0].id, pointer_actions::RootNodeId::DefaultModel);
}

#[cfg(feature = "extended")]
#[test]
fn root_menu_inventory_adds_image_spend_in_extended_profile() {
    let nodes = root_nodes();
    assert_eq!(nodes.len(), 16);
    assert_eq!(nodes[0].id, pointer_actions::RootNodeId::DefaultModel);
    assert!(
        nodes
            .iter()
            .any(|node| node.id == pointer_actions::RootNodeId::ImageSpend)
    );
}

#[test]
fn default_model_row_shows_the_effective_default_and_opens_the_shared_picker() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut d = open_fixture_dialog(&path);
    d.config.active_model = Some(cockpit_config::providers::ActiveModelRef {
        provider: "vendor".into(),
        model: "m1".into(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    });

    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.page.test_name(), "DefaultModel");
    let text = render_settings_rows(&d, 100, 24).join("\n");
    assert!(text.contains("Effective default: vendor/m1"), "{text}");
    assert!(text.contains("Scope:"), "{text}");
    assert!(
        text.contains("newly created sessions only"),
        "the row must distinguish new sessions from reattachment: {text}"
    );

    // Enter opens the same provider-scoped picker `/model` uses.
    d.handle_key(press(KeyCode::Enter));
    assert!(d.pending_default_model_picker);
    assert!(
        d.pending_daemon_request.take().is_none(),
        "opening the picker must not mutate anything"
    );
}

#[test]
fn default_model_row_shows_an_explicit_unset_state() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut d = open_fixture_dialog(&path);

    d.handle_key(press(KeyCode::Enter));
    let text = render_settings_rows(&d, 100, 24).join("\n");
    assert!(text.contains("Effective default: (unset"), "{text}");
}

#[test]
fn clearing_the_default_from_settings_delegates_to_the_daemon_operation() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut d = open_fixture_dialog(&path);
    d.config.active_model = Some(cockpit_config::providers::ActiveModelRef {
        provider: "vendor".into(),
        model: "m1".into(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    });
    d.original_config.active_model = d.config.active_model.clone();

    d.handle_key(press(KeyCode::Enter));
    d.handle_key(press(KeyCode::Char('x')));

    let staged_id = d.pending_default_model_update_id;
    match d.pending_daemon_request.take() {
        Some(Request::SetDefaultModel {
            clear,
            default_update_id,
            provider,
            model,
            ..
        }) => {
            assert!(clear);
            assert_eq!(provider, None, "a clear carries no reference");
            assert_eq!(model, None);
            assert_eq!(
                staged_id,
                Some(default_update_id),
                "the clear must stage its correlation id so the terminal event matches"
            );
        }
        other => panic!("expected a staged clear request, got {other:?}"),
    }
    let reloaded = cockpit_config::providers::ConfigDoc::load(&d.config_path)
        .unwrap()
        .providers();
    assert_eq!(
        reloaded.active_model, None,
        "clearing must not be a local ConfigDoc mutation"
    );
}

#[test]
fn clearing_an_already_unset_default_stages_nothing() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut d = open_fixture_dialog(&path);

    d.handle_key(press(KeyCode::Enter));
    d.handle_key(press(KeyCode::Char('x')));

    assert!(d.pending_daemon_request.take().is_none());
    let text = render_settings_rows(&d, 100, 24).join("\n");
    assert!(text.contains("No default is set"), "{text}");
}

#[test]
fn pressing_d_once_arms_delete_and_keeps_provider() {
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_one_provider(&tmp);
    d.handle_key(press(KeyCode::Char('d')));
    assert!(
        d.config.providers.contains_key("vendor"),
        "single `d` press must not delete"
    );
    match d.test_page() {
        TestPageRef::Providers(ProvidersPage::List {
            delete_pending,
            status,
            ..
        }) => {
            assert!(delete_pending);
            assert!(
                status.as_deref().unwrap_or("").contains("press d again"),
                "expected confirm hint, got {status:?}"
            );
        }
        other => panic!("expected ProvidersPage::List, got {other:?}"),
    }
}

#[test]
fn pressing_d_twice_deletes_the_provider() {
    let tmp = TempDir::new().unwrap();
    let (mut d, _fx) = daemon_dialog_with_one_provider(&tmp);
    d.handle_key(press(KeyCode::Char('d')));
    d.handle_key(press(KeyCode::Char('d')));
    assert!(
        !d.config.providers.contains_key("vendor"),
        "double `d` press must delete"
    );
    // Persisted to disk.
    let reloaded = cockpit_config::providers::ConfigDoc::load(&d.config_path)
        .unwrap()
        .providers();
    assert!(!reloaded.providers.contains_key("vendor"));
}

#[test]
fn arrow_after_d_clears_delete_pending() {
    // Vim-style safety: moving the cursor should disarm a pending
    // delete so the second press doesn't nuke a different row.
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_one_provider(&tmp);
    // Arm the focused provider row, then move — the move must disarm it.
    d.handle_key(press(KeyCode::Char('d')));
    d.handle_key(press(KeyCode::Up));
    match d.test_page() {
        TestPageRef::Providers(ProvidersPage::List { delete_pending, .. }) => {
            assert!(!delete_pending, "arrow key should clear pending-delete");
        }
        other => panic!("expected List, got {other:?}"),
    }
}

// ── Providers save-UX (visible button + no-loss-on-exit) ───────────

/// Enter the Edit page for the single provider in `dialog_with_one_provider`.
fn enter_edit_first_provider(d: &mut SettingsDialog) {
    d.handle_key(press(KeyCode::Enter)); // open Edit
    assert!(
        matches!(
            d.test_page(),
            TestPageRef::Providers(ProvidersPage::Edit(_))
        ),
        "expected to be on the Edit page"
    );
}

fn disk_url(d: &SettingsDialog, id: &str) -> Option<String> {
    cockpit_config::providers::ConfigDoc::load(&d.config_path)
        .unwrap()
        .providers()
        .providers
        .get(id)
        .map(|e| e.url.clone())
}

/// The Edit page's `[save changes]` row commits the staged
/// entry to disk and stays on the page with a `saved` confirmation.
#[test]
fn edit_save_changes_row_commits_and_stays() {
    let tmp = TempDir::new().unwrap();
    let (mut d, _fx) = daemon_dialog_with_one_provider(&tmp);
    enter_edit_first_provider(&mut d);
    // Stage a URL edit, then move the cursor to the `[save changes]`
    // row and activate it.
    if let TestPageMut::Providers(ProvidersPage::Edit(s)) = d.test_page_mut() {
        s.entry.url = "https://new".to_string();
        s.cursor = crate::tui::settings::providers::edit_menu_actions(&s.provider_id, &s.entry)
            .iter()
            .position(|action| matches!(action, crate::tui::settings::providers::EditAction::Save))
            .expect("save row");
    } else {
        panic!("not on Edit page");
    }
    d.handle_key(press(KeyCode::Enter));
    // Still on the Edit page, with a `saved` status.
    match d.test_page() {
        TestPageRef::Providers(ProvidersPage::Edit(s)) => {
            assert_eq!(s.status.as_deref(), Some("saved"));
        }
        other => panic!("expected to stay on Edit, got {other:?}"),
    }
    assert_eq!(disk_url(&d, "vendor").as_deref(), Some("https://new"));
}

/// Single-line field edit (the Edit page URL row): Enter commits the
/// field straight to disk — no manual save step.
#[test]
fn edit_url_field_enter_commits_to_disk() {
    let tmp = TempDir::new().unwrap();
    let (mut d, _fx) = daemon_dialog_with_one_provider(&tmp);
    enter_edit_first_provider(&mut d);
    // Cursor 0 is the URL row; Enter opens the inline field pre-filled
    // with the current value. Clear it, type a new URL, Enter commits.
    d.handle_key(press(KeyCode::Enter));
    for _ in 0..40 {
        d.handle_key(press(KeyCode::Backspace));
    }
    type_chars(&mut d, "https://committed");
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(disk_url(&d, "vendor").as_deref(), Some("https://committed"));
}

/// Leaving the Edit page via Esc auto-commits a staged URL edit — no
/// silent data loss even without pressing save.
#[test]
fn edit_esc_persists_staged_url() {
    let tmp = TempDir::new().unwrap();
    let (mut d, _fx) = daemon_dialog_with_one_provider(&tmp);
    enter_edit_first_provider(&mut d);
    // Stage a URL edit directly on the EditState (no manual save).
    if let TestPageMut::Providers(ProvidersPage::Edit(s)) = d.test_page_mut() {
        s.entry.url = "https://staged".to_string();
    } else {
        panic!("not on Edit page");
    }
    // Esc back to the list must persist the staged edit to disk.
    d.handle_key(press(KeyCode::Esc));
    assert!(on_list_page(&d), "Esc returns to the provider list");
    assert_eq!(disk_url(&d, "vendor").as_deref(), Some("https://staged"));
}

/// The Headers sub-page `s` accelerator commits the provider entry —
/// including the in-flight header edits — directly to disk and stays.
#[test]
fn headers_save_accelerator_commits_and_stays() {
    let tmp = TempDir::new().unwrap();
    let (mut d, _fx) = daemon_dialog_with_one_provider(&tmp);
    enter_edit_first_provider(&mut d);
    // Open the Headers sub-page (Edit cursor 1 → Enter).
    if let TestPageMut::Providers(ProvidersPage::Edit(s)) = d.test_page_mut() {
        s.cursor = 1;
    } else {
        panic!("not on Edit page");
    }
    d.handle_key(press(KeyCode::Enter));
    assert!(matches!(
        d.test_page(),
        TestPageRef::Providers(ProvidersPage::Headers { .. })
    ));
    // Stage a header row directly on the editor, then press `s`.
    if let TestPageMut::Providers(ProvidersPage::Headers { editor, .. }) = d.test_page_mut() {
        editor.rows.push(cockpit_config::providers::HeaderSpec {
            name: "Authorization".into(),
            value: "Bearer x".into(),
        });
    } else {
        panic!("not on Headers page");
    }
    d.handle_key(press(KeyCode::Char('s')));
    // Stayed on the Headers page, committed to disk.
    assert!(
        matches!(
            d.test_page(),
            TestPageRef::Providers(ProvidersPage::Headers { .. })
        ),
        "`s` keeps us on the Headers sub-page"
    );
    let reloaded = cockpit_config::providers::ConfigDoc::load(&d.config_path)
        .unwrap()
        .providers();
    let entry = reloaded.providers.get("vendor").unwrap();
    assert_eq!(entry.headers.len(), 1);
    assert_eq!(entry.headers[0].name, "Authorization");
}

/// Leaving the Headers sub-page via Esc auto-commits the header edits —
/// no silent data loss.
#[test]
fn headers_esc_persists_edits() {
    let tmp = TempDir::new().unwrap();
    let (mut d, _fx) = daemon_dialog_with_one_provider(&tmp);
    enter_edit_first_provider(&mut d);
    if let TestPageMut::Providers(ProvidersPage::Edit(s)) = d.test_page_mut() {
        s.cursor = 1;
    } else {
        panic!("not on Edit page");
    }
    d.handle_key(press(KeyCode::Enter));
    if let TestPageMut::Providers(ProvidersPage::Headers { editor, .. }) = d.test_page_mut() {
        editor.rows.push(cockpit_config::providers::HeaderSpec {
            name: "X-Test".into(),
            value: "1".into(),
        });
    } else {
        panic!("not on Headers page");
    }
    // Esc back to Edit must persist.
    d.handle_key(press(KeyCode::Esc));
    assert!(matches!(
        d.test_page(),
        TestPageRef::Providers(ProvidersPage::Edit(_))
    ));
    let reloaded = cockpit_config::providers::ConfigDoc::load(&d.config_path)
        .unwrap()
        .providers();
    let entry = reloaded.providers.get("vendor").unwrap();
    assert_eq!(entry.headers.len(), 1, "header edit persisted on Esc");
    assert_eq!(entry.headers[0].name, "X-Test");
}

/// Leaving the Models sub-page via Esc auto-commits a staged model row.
#[test]
fn models_esc_persists_edits() {
    let tmp = TempDir::new().unwrap();
    let (mut d, _fx) = daemon_dialog_with_one_provider(&tmp);
    enter_edit_first_provider(&mut d);
    if let TestPageMut::Providers(ProvidersPage::Edit(s)) = d.test_page_mut() {
        s.cursor = 2; // Models row
    } else {
        panic!("not on Edit page");
    }
    d.handle_key(press(KeyCode::Enter));
    if let TestPageMut::Providers(ProvidersPage::Models { editor, .. }) = d.test_page_mut() {
        editor.rows.push(cockpit_config::providers::ModelEntry {
            id: "m-new".into(),
            name: None,
            thinking_modes: Vec::new(),
            inputs: None,
            context_length: None,
            favorite: false,
            manual: true,
            trust: None,
            location: None,
            quality_rank: None,
            cost_rank: None,
            subagent_invokable: None,
            can_delegate: None,
            computer_use: None,
            allow_computer_guidance_proposals: None,
            default_thinking_mode: None,
            embeddings: None,
            embedding_dimensions: None,
            availability: Default::default(),
            cache: None,
            shrink: None,
            context: None,
            auto_prune: None,
            timeout: None,
            backup: None,
            inline_think: None,
            hint_tool_call_corrections: None,
            text_embedded_recovery: None,
            thinking_params: Default::default(),
            system_prompt: None,
            wire_api: Default::default(),
            wire_api_provenance: Default::default(),
            extra: Default::default(),
            capabilities: Default::default(),
            capability_overrides: Default::default(),
            provider_metadata: Default::default(),
        });
    } else {
        panic!("not on Models page");
    }
    d.handle_key(press(KeyCode::Esc));
    let reloaded = cockpit_config::providers::ConfigDoc::load(&d.config_path)
        .unwrap()
        .providers();
    let entry = reloaded.providers.get("vendor").unwrap();
    assert_eq!(entry.models.len(), 1, "model edit persisted on Esc");
    assert_eq!(entry.models[0].id, "m-new");
}

fn on_fetch_all_page(d: &SettingsDialog) -> bool {
    matches!(
        d.test_page(),
        TestPageRef::Providers(ProvidersPage::FetchAll(_))
    )
}

#[test]
fn providers_list_initial_enter_edits_first_provider() {
    // Providers configured: initial focus is the first provider row,
    // not the `[refetch provider models]` button.
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_one_provider(&tmp);
    d.handle_key(press(KeyCode::Enter));
    assert!(
        matches!(
            d.test_page(),
            TestPageRef::Providers(ProvidersPage::Edit(_))
        ),
        "initial Enter should edit the first provider, got {:?}",
        d.page
    );
}

#[tokio::test]
async fn refetch_all_button_enters_fetch_all_with_providers() {
    // The visible `[refetch provider models]` button remains reachable by
    // moving to row 0 and pressing Enter.
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_one_provider(&tmp);
    d.handle_key(press(KeyCode::Up));
    d.handle_key(press(KeyCode::Enter));
    assert!(
        on_fetch_all_page(&d),
        "Enter on the refetch-all button should enter FetchAll, got {:?}",
        d.page
    );
    if let TestPageRef::Providers(ProvidersPage::FetchAll(s)) = d.test_page() {
        assert_eq!(
            s.in_flight.len() + s.finished.len(),
            1,
            "exactly one provider should be accounted for"
        );
    }
}

#[tokio::test]
async fn refetch_all_via_capital_r_enters_fetch_all() {
    // `R` triggers the same flow from any row on the list.
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_one_provider(&tmp);
    d.handle_key(press(KeyCode::Char('R')));
    assert!(
        on_fetch_all_page(&d),
        "`R` on the list should enter FetchAll, got {:?}",
        d.page
    );
}

#[test]
fn refetch_all_with_no_providers_is_a_noop_with_status() {
    // No providers: the button is reachable but activating it must
    // not error or navigate — just set a status on the List page.
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.enter_providers();
    assert!(d.config.providers.is_empty());
    d.handle_key(press(KeyCode::Enter));
    match d.test_page() {
        TestPageRef::Providers(ProvidersPage::List { status, .. }) => {
            assert_eq!(
                status.as_deref(),
                Some("no providers configured"),
                "expected the no-op status, got {status:?}"
            );
        }
        other => panic!("expected to stay on List, got {other:?}"),
    }
}

#[tokio::test]
async fn fetch_all_in_flight_ignores_keys_except_esc() {
    // While the per-provider fetches are running, a stray Enter must
    // not navigate away (which is how a second concurrent all-fetch
    // would otherwise be stacked). Only Esc cancels.
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_one_provider(&tmp);
    // Force a state with a live in-flight handle, independent of how
    // fast the spawned task completes (we never tick, so in_flight
    // stays populated).
    let state = ProvidersPage::FetchAll(FetchAllState::spawn(
        crate::tui::settings::test_lifecycle_client(),
        &d.config,
        tmp.path().display().to_string(),
    ));
    d.set_test_page(Page::Providers(state));
    if let TestPageRef::Providers(ProvidersPage::FetchAll(s)) = d.test_page() {
        assert!(s.is_fetching(), "expected an in-flight fetch");
    }
    // A non-Esc key is ignored — we stay on FetchAll.
    let closed = d.handle_key(press(KeyCode::Enter));
    assert!(!closed);
    assert!(
        on_fetch_all_page(&d),
        "Enter during an in-flight fetch must not navigate, got {:?}",
        d.page
    );
}

#[test]
fn has_no_providers_true_when_config_dir_empty() {
    // discover_config_dirs walks up from `cwd`, so a tempdir with
    // no `.cockpit/` or local config should fall back to the user's
    // config (which may or may not exist). The cleanest assertion
    // we can make portably is the symmetry: open_providers_add
    // produces a non-Settings dialog when has_no_providers reports
    // no config — i.e. the function doesn't panic and is honest
    // about what it found.
    let tmp = TempDir::new().unwrap();
    // Just exercising the codepath — the answer depends on the
    // host's $HOME, so we only assert it returns *some* bool.
    let _ = Dialog::has_no_providers(tmp.path());
}

#[test]
fn fresh_install_reaches_add_provider() {
    let tmp = TempDir::new().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());

    let dialog = Dialog::open_providers_add(tmp.path());

    assert!(dialog.test_provider_is_add());
    assert!(
        !tmp.path().join("home/.config/cockpit/config.json").exists(),
        "opening provider add must not scaffold a config before save"
    );
    assert!(!tmp.path().join(".cockpit").exists());
}

#[test]
fn mcp_oauth_ui_retains_public_url_and_accepts_manual_callback() {
    let mut callback = TextField::default();
    callback.set("http://127.0.0.1:43123/callback?code=opaque");
    let state = mcp_page::McpOAuthState {
        server: "docs".into(),
        begin_client_operation_id: "begin".into(),
        flow_id: "flow-id".into(),
        authorize_url: "https://auth.example.test/authorize".into(),
        callback,
        status: None,
    };
    assert_eq!(state.authorize_url, "https://auth.example.test/authorize");
    assert_eq!(
        state.callback.text(),
        "http://127.0.0.1:43123/callback?code=opaque"
    );
    assert_eq!(state.flow_id, "flow-id");
}

#[test]
fn open_providers_add_lands_on_add_page_when_config_exists() {
    let tmp = TempDir::new().unwrap();
    // Create a `.cockpit/config.json` so the dialog has a layer to
    // open without falling through to CreateConfig.
    let cockpit_dir = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&cockpit_dir).unwrap();
    std::fs::write(cockpit_dir.join("config.json"), "{}").unwrap();
    let d = Dialog::open_providers_add(tmp.path());
    let Dialog::Settings(s) = d else {
        panic!("expected Settings dialog");
    };
    assert!(
        matches!(s.test_page(), TestPageRef::Providers(ProvidersPage::Add(_))),
        "expected Add page, got {:?}",
        s.page
    );
}

#[test]
fn no_providers_auto_opens_wizard() {
    let tmp = TempDir::new().unwrap();
    let cockpit_dir = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&cockpit_dir).unwrap();
    std::fs::write(cockpit_dir.join("config.json"), "{}").unwrap();

    let d = Dialog::open_providers_add(tmp.path());
    let Dialog::Settings(s) = d else {
        panic!("expected Settings dialog");
    };
    assert!(matches!(
        s.test_page(),
        TestPageRef::Providers(ProvidersPage::Add(_))
    ));
}

#[test]
fn model_setup_choice_distinguishes_confirmed_and_pending_models() {
    let tmp = TempDir::new().unwrap();
    let confirmed = Dialog::open_model_setup_choice(
        tmp.path(),
        Some(("provider".to_string(), "model".to_string())),
        None,
    );
    let rendered = render_dialog_rows(&confirmed, 100, 12).join("\n");
    assert!(rendered.contains("Configure which model?"), "{rendered}");
    assert!(
        rendered.contains("Use the currently selected model: provider/model"),
        "{rendered}"
    );
    assert!(rendered.contains("Choose a different model"), "{rendered}");

    let pending = Dialog::open_model_setup_choice(
        tmp.path(),
        None,
        Some(("pending-provider".to_string(), "pending-model".to_string())),
    );
    let rendered = render_dialog_rows(&pending, 100, 12).join("\n");
    assert!(
        rendered.contains("pending-provider/pending-model is still being selected"),
        "{rendered}"
    );
    assert!(!rendered.contains("currently selected model"), "{rendered}");
}

#[test]
fn first_run_completion_copy_points_to_security_and_help() {
    let d = Dialog::open_first_run_complete(
        "Configured p/m as the default model for future sessions.".to_string(),
    );
    let rendered = render_dialog_rows(&d, 96, 12).join("\n");

    assert!(rendered.contains("/setup security"), "{rendered}");
    assert!(rendered.contains("/help"), "{rendered}");
}

#[test]
fn security_setup_wizard_tui_edits_redaction_number() {
    let tmp = TempDir::new().unwrap();
    let mut d = Dialog::open_setup_wizard(tmp.path(), cockpit_core::wizard::SECURITY_WIZARD_ID)
        .expect("security wizard opens");

    d.handle_key(press(KeyCode::Enter)); // sandbox default
    d.handle_key(press(KeyCode::Enter)); // approval default
    for _ in 0..8 {
        d.handle_key(press(KeyCode::Backspace));
    }
    d.handle_key(press(KeyCode::Char('1')));
    d.handle_key(press(KeyCode::Char('2')));
    d.handle_key(press(KeyCode::Enter));

    let Dialog::SetupWizard(wizard) = d else {
        panic!("expected setup wizard");
    };
    assert_eq!(
        wizard.run.answer("redaction"),
        Some(&cockpit_core::wizard::WizardAnswer::Text("12".to_string()))
    );
}

#[test]
fn model_wizard_tui_dialog_opens_descriptor() {
    let tmp = TempDir::new().unwrap();
    let cockpit_dir = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&cockpit_dir).unwrap();
    let config_path = cockpit_dir.join("config.json");
    let mut cfg = ProvidersConfig::default();
    let mut provider = ProviderEntry {
        url: "http://localhost:1/v1".to_string(),
        ..Default::default()
    };
    provider.models.push(ModelEntry {
        id: "m".to_string(),
        ..Default::default()
    });
    cfg.providers.insert("p".to_string(), provider);
    let mut doc = cockpit_config::providers::ConfigDoc::load(&config_path).unwrap();
    doc.write(&cfg).unwrap();

    let d = Dialog::open_setup_wizard(tmp.path(), cockpit_core::wizard::MODEL_WIZARD_ID)
        .expect("model wizard opens");
    let Dialog::SetupWizard(wizard) = d else {
        panic!("expected setup wizard");
    };
    assert_eq!(
        wizard.run.descriptor().id,
        cockpit_core::wizard::MODEL_WIZARD_ID
    );
    assert_eq!(wizard.run.current_step_id(), Some("provider"));
}

#[test]
fn model_wizard_tui_advances_through_multitoggle_steps() {
    let tmp = TempDir::new().unwrap();
    let mut cfg = ProvidersConfig::default();
    let mut provider = ProviderEntry {
        url: "http://localhost:1/v1".to_string(),
        subagent_invokable: Some(true),
        can_delegate: Some(true),
        ..Default::default()
    };
    provider.models.push(ModelEntry {
        id: "m".to_string(),
        capabilities: cockpit_config::providers::ModelCapabilities {
            image_input: cockpit_config::providers::CapabilityStatus::Supported,
            reasoning: cockpit_config::providers::CapabilityStatus::Supported,
            ..Default::default()
        },
        ..Default::default()
    });
    cfg.providers.insert("p".to_string(), provider);
    let run = cockpit_core::wizard::WizardRun::new(
        cockpit_core::wizard::model_descriptor_for_config(&cfg),
    )
    .expect("model wizard run");
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
    let mut d = Dialog::SetupWizard(Box::new(SetupWizardDialog {
        run,
        cursor,
        text,
        multi,
        multi_touched,
        tool_surface,
        tool_surface_touched,
        cwd: tmp.path().to_path_buf(),
        status: None,
    }));
    for expected in [
        "provider",
        "model",
        "class",
        "trust",
        "capabilities",
        "context-tokens",
        "max-output-tokens",
        "thinking",
        "subagent-flags",
        "default-model",
        "system-prompt-choice",
    ] {
        let Dialog::SetupWizard(wizard) = &d else {
            panic!("expected setup wizard");
        };
        assert_eq!(wizard.run.current_step_id(), Some(expected));
        d.handle_key(press(KeyCode::Enter));
    }

    let Dialog::SetupWizard(wizard) = d else {
        panic!("expected setup wizard");
    };
    assert_eq!(wizard.run.current_step_id(), Some("model-save"));
}

#[test]
fn lsp_server_rows_queue_daemon_actions() {
    let tmp = TempDir::new().unwrap();
    let cockpit_dir = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&cockpit_dir).unwrap();
    let mut d = SettingsDialog::open(cockpit_dir.join("config.json"));
    d.set_test_page(Page::Lsp(LspPage {
        cursor: LSP_SERVER_ROW_START,
        editing: None,
        buf: TextField::default(),
        status: None,
        reset: ResetButton::default(),
    }));

    d.handle_key(press(KeyCode::Enter));
    match d.pending_daemon_request.take() {
        Some(Request::LspControl {
            project_root,
            server_id,
            action,
        }) => {
            assert_eq!(project_root, tmp.path().display().to_string());
            assert_eq!(server_id, "rust-analyzer");
            assert_eq!(action, LspControlAction::Check);
        }
        other => panic!("expected LSP check request, got {other:?}"),
    }

    d.handle_key(press(KeyCode::Char('i')));
    match d.pending_daemon_request.take() {
        Some(Request::LspControl {
            server_id, action, ..
        }) => {
            assert_eq!(server_id, "rust-analyzer");
            assert_eq!(action, LspControlAction::Install);
        }
        other => panic!("expected LSP install request, got {other:?}"),
    }
}

fn lsp_snapshot(
    lsp: &cockpit_config::extended::LspConfig,
) -> (bool, String, bool, usize, usize, u64, u64, u64) {
    (
        lsp.enabled,
        lsp.auto_install.as_str().to_string(),
        lsp.diagnostics.enabled,
        lsp.diagnostics.other_files_limit,
        lsp.diagnostics.per_file_limit,
        lsp.diagnostics.debounce_ms,
        lsp.diagnostics.document_timeout_ms,
        lsp.diagnostics.workspace_timeout_ms,
    )
}

#[test]
fn lsp_reset_r_once_arms_without_wiping() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.set_test_page(Page::Lsp(LspPage {
        cursor: 0,
        editing: None,
        buf: TextField::default(),
        status: Some("old status".into()),
        reset: ResetButton::default(),
    }));
    d.extended.lsp.enabled = false;
    d.extended.lsp.diagnostics.other_files_limit = 17;
    let before = lsp_snapshot(&d.extended.lsp);

    d.handle_key(press(KeyCode::Char('r')));

    assert_eq!(
        lsp_snapshot(&d.extended.lsp),
        before,
        "first r must not reset"
    );
    match d.test_page() {
        TestPageRef::Lsp(p) => {
            assert!(p.reset.is_pending());
            assert!(p.status.is_none(), "arming clears stale status");
        }
        other => panic!("expected LSP page, got {other:?}"),
    }
}

#[test]
fn lsp_reset_r_twice_restores_defaults() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.set_test_page(Page::Lsp(LspPage {
        cursor: 0,
        editing: None,
        buf: TextField::default(),
        status: None,
        reset: ResetButton::default(),
    }));
    d.extended.lsp.enabled = false;
    d.extended.lsp.diagnostics.other_files_limit = 17;

    d.handle_key(press(KeyCode::Char('r')));
    d.handle_key(press(KeyCode::Char('r')));

    assert_eq!(
        lsp_snapshot(&d.extended.lsp),
        lsp_snapshot(&cockpit_config::extended::LspConfig::default())
    );
    match d.test_page() {
        TestPageRef::Lsp(p) => {
            assert!(!p.reset.is_pending());
            assert!(p.status.is_some(), "applying reports save status");
        }
        other => panic!("expected LSP page, got {other:?}"),
    }
}

#[test]
fn lsp_reset_pending_cancelled_by_navigation() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.set_test_page(Page::Lsp(LspPage {
        cursor: 0,
        editing: None,
        buf: TextField::default(),
        status: None,
        reset: ResetButton::default(),
    }));
    d.extended.lsp.enabled = false;
    let before = lsp_snapshot(&d.extended.lsp);

    d.handle_key(press(KeyCode::Char('r')));
    d.handle_key(press(KeyCode::Down));
    d.handle_key(press(KeyCode::Char('r')));

    assert_eq!(
        lsp_snapshot(&d.extended.lsp),
        before,
        "navigation disarms, so the next r arms again instead of applying"
    );
    match d.test_page() {
        TestPageRef::Lsp(p) => assert!(p.reset.is_pending()),
        other => panic!("expected LSP page, got {other:?}"),
    }
}

#[test]
fn lsp_reset_row_and_accelerator_share_confirm_state() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.set_test_page(Page::Lsp(LspPage {
        cursor: row_index(LspRow::Reset),
        editing: None,
        buf: TextField::default(),
        status: None,
        reset: ResetButton::default(),
    }));
    d.extended.lsp.enabled = false;

    d.handle_key(press(KeyCode::Enter));
    match d.test_page() {
        TestPageRef::Lsp(p) => assert!(p.reset.is_pending()),
        other => panic!("expected LSP page, got {other:?}"),
    }
    d.handle_key(press(KeyCode::Char('r')));
    assert_eq!(
        lsp_snapshot(&d.extended.lsp),
        lsp_snapshot(&cockpit_config::extended::LspConfig::default())
    );

    d.extended.lsp.enabled = false;
    d.handle_key(press(KeyCode::Char('r')));
    match d.test_page() {
        TestPageRef::Lsp(p) => assert!(p.reset.is_pending()),
        other => panic!("expected LSP page, got {other:?}"),
    }
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(
        lsp_snapshot(&d.extended.lsp),
        lsp_snapshot(&cockpit_config::extended::LspConfig::default())
    );
}

#[test]
fn lsp_selected_line_is_derived_from_row_data_not_marker_text() {
    assert_eq!(lsp_selected_line_for_cursor(row_index(LspRow::Enabled)), 0);
    assert_eq!(
        lsp_selected_line_for_cursor(row_index(LspRow::DebounceMs)),
        row_index(LspRow::DebounceMs) + 1
    );
    assert_eq!(
        lsp_selected_line_for_cursor(LSP_SERVER_ROW_START),
        LSP_SERVER_ROW_START + 1
    );
}

#[test]
fn lsp_edit_row_places_caret_at_textfield_cursor() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.set_test_page(Page::Lsp(LspPage {
        cursor: row_index(LspRow::DebounceMs),
        editing: Some(LspEdit::DebounceMs),
        buf: TextField::new("1234"),
        status: None,
        reset: ResetButton::default(),
    }));
    let TestPageMut::Lsp(p) = d.test_page_mut() else {
        panic!("expected LSP page")
    };
    p.buf.handle_key(press(KeyCode::Home));
    p.buf.handle_key(press(KeyCode::Right));
    p.buf.handle_key(press(KeyCode::Right));
    let TestPageRef::Lsp(p) = d.test_page() else {
        panic!("expected LSP page")
    };
    let (rows, selected_line) = lsp_rows(&d, p);

    assert_eq!(selected_line, row_index(LspRow::DebounceMs) + 1);
    assert!(line_text(&rows[selected_line]).contains("12\u{E000}34"));
}

#[test]
fn lsp_severity_is_muted_non_selectable_info_line() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.set_test_page(Page::Lsp(LspPage {
        cursor: 0,
        editing: None,
        buf: TextField::default(),
        status: None,
        reset: ResetButton::default(),
    }));

    let TestPageRef::Lsp(p) = d.test_page() else {
        panic!("expected LSP page");
    };
    let (rows, _) = lsp_rows(&d, p);
    let severity = rows
        .iter()
        .find(|line| line.to_string().contains("severity"))
        .expect("severity info line is rendered");
    assert!(severity.to_string().contains("error (errors only)"));
    assert!(
        severity
            .spans
            .iter()
            .any(|span| span.style.fg == Some(Color::Indexed(MUTED_COLOR_INDEX))),
        "severity info line is muted"
    );

    for _ in 0..(LSP_NAV_ROWS.len() * 2) {
        let TestPageRef::Lsp(p) = d.test_page() else {
            panic!("expected LSP page");
        };
        let selected = lsp_rows(&d, p)
            .0
            .into_iter()
            .find(|line| line.to_string().starts_with("▸ "))
            .expect("one selected row");
        assert!(
            !selected.to_string().contains("severity"),
            "severity line must never be selected"
        );
        d.handle_key(press(KeyCode::Down));
    }
}

#[test]
fn project_context_uses_project_config_root() {
    let tmp = TempDir::new().unwrap();
    let project = tmp.path().join("project");
    let config = project.join(".cockpit/config.json");

    assert_eq!(
        project_context_for_config(&config, None),
        ProjectContext::Available(project)
    );
}

#[test]
fn project_context_uses_active_root_for_global_config() {
    let tmp = TempDir::new().unwrap();
    let active = tmp.path().join("work");
    let global = tmp.path().join(".config/cockpit/config.json");

    assert_eq!(
        project_context_for_config(&global, Some(&active)),
        ProjectContext::Available(active)
    );
}

#[test]
fn project_context_global_config_without_active_root_is_unavailable() {
    let tmp = TempDir::new().unwrap();
    let global = tmp.path().join(".config/cockpit/config.json");

    assert_eq!(
        project_context_for_config(&global, None),
        ProjectContext::Unavailable
    );
}

#[test]
fn project_context_does_not_treat_config_parent_as_project_root() {
    let tmp = TempDir::new().unwrap();
    let config_parent = tmp.path().join(".config");
    let global = config_parent.join("cockpit/config.json");

    assert_ne!(
        project_context_for_config(&global, None),
        ProjectContext::Available(config_parent)
    );
}

#[test]
fn lsp_action_from_global_settings_uses_active_project_context() {
    let tmp = TempDir::new().unwrap();
    let active = tmp.path().join("active-project");
    let global = tmp.path().join(".config/cockpit/config.json");
    let mut d = SettingsDialog::open_from_picker(global, active.clone());
    d.set_test_page(Page::Lsp(LspPage {
        cursor: LSP_SERVER_ROW_START,
        editing: None,
        buf: TextField::default(),
        status: None,
        reset: ResetButton::default(),
    }));

    d.handle_key(press(KeyCode::Enter));

    match d.pending_daemon_request.take() {
        Some(Request::LspControl { project_root, .. }) => {
            assert_eq!(project_root, active.display().to_string());
        }
        other => panic!("expected LSP check request, got {other:?}"),
    }
}

#[test]
fn lsp_action_without_project_context_is_disabled() {
    let tmp = TempDir::new().unwrap();
    let global = tmp.path().join(".config/cockpit/config.json");
    let mut d = SettingsDialog::open(global);
    d.set_test_page(Page::Lsp(LspPage {
        cursor: LSP_SERVER_ROW_START,
        editing: None,
        buf: TextField::default(),
        status: None,
        reset: ResetButton::default(),
    }));

    d.handle_key(press(KeyCode::Enter));

    assert!(d.pending_daemon_request.is_none());
    let TestPageRef::Lsp(p) = d.test_page() else {
        panic!("expected LSP page");
    };
    assert_eq!(p.status.as_deref(), Some(PROJECT_CONTEXT_UNAVAILABLE));
}

impl std::fmt::Debug for Page {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Page::Root { cursor } => write!(f, "Root({cursor})"),
            Page::Agents(_) => f.write_str("Agents"),
            Page::Tools(_) => f.write_str("Tools"),
            Page::Harnesses(_) => f.write_str("Harnesses"),
            Page::Providers(_) => f.write_str("Providers"),
            Page::Category(p) => write!(f, "Category({:?})", p.category),
            Page::Instructions(_) => f.write_str("Instructions"),
            Page::RedactPatterns(_) => f.write_str("RedactPatterns"),
            Page::StringList(p) => write!(f, "StringList({:?})", p.kind),
            Page::Skills(_) => f.write_str("Skills"),
            Page::Mcp(_) => f.write_str("Mcp"),
            Page::Lsp(_) => f.write_str("Lsp"),
        }
    }
}

/// The root-menu index of a node by its title, so tests don't hardcode
/// the (locked but long) ordering.
fn root_index(title: &str) -> usize {
    root_nodes()
        .iter()
        .position(|n| n.title == title)
        .unwrap_or_else(|| panic!("no root node titled `{title}`"))
}

pub(super) fn enter_root_node(d: &mut SettingsDialog, title: &str) {
    d.set_test_page(Page::Root {
        cursor: root_index(title),
    });
    d.handle_key(press(KeyCode::Enter));
}

fn enter_tools_from_root(d: &mut SettingsDialog) {
    enter_root_node(d, "Tools");
}

fn enter_harnesses_from_root(d: &mut SettingsDialog) {
    enter_root_node(d, "Harnesses");
}

#[test]
fn harnesses_page_opens_and_seeds_presets() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    // Pretend every preset command is installed so the result doesn't
    // depend on what's on the CI machine's PATH.
    d.command_installed = |_| true;
    enter_harnesses_from_root(&mut d);
    assert!(
        matches!(d.test_page(), TestPageRef::Harnesses(_)),
        "expected Harnesses page, got {:?}",
        d.page
    );
    // Fresh: no harnesses configured.
    assert!(d.extended.harnesses.is_empty());
    // Navigate to the `[seed installed presets]` row: with 0 harnesses
    // it's at cursor 1 (after `[+ add harness]` at 0), then activate.
    d.handle_key(press(KeyCode::Down)); // -> [seed installed presets]
    d.handle_key(press(KeyCode::Enter));
    // The verified presets are now configured.
    for name in ["claude", "codex", "opencode", "copilot", "goose", "grok"] {
        assert!(
            d.extended.harnesses.contains_key(name),
            "missing seeded preset `{name}`"
        );
    }
}

#[test]
fn seeded_harnesses_reappear_after_settings_disk_round_trip() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();

    let mut d = open_fixture_dialog(&path);
    d.command_installed = |_| true;
    seed_via_keys(&mut d);
    assert_eq!(harness_status(&d).as_deref(), Some("saved"));

    let mut reopened = open_fixture_dialog(&path);
    enter_harnesses_from_root(&mut reopened);
    for name in ["claude", "codex", "opencode", "copilot", "goose", "grok"] {
        assert!(
            reopened.extended.harnesses.contains_key(name),
            "missing seeded preset `{name}` after reopening settings"
        );
    }
}

#[test]
fn harnesses_page_refuses_a_layer_whose_unrelated_field_is_malformed() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
                "harnesses": {
                    "codex": { "command": "codex", "args": ["exec"] }
                },
                "tui": "not an object"
            }"#,
    )
    .unwrap();

    let mut d = open_fixture_dialog(&path);
    enter_harnesses_from_root(&mut d);
    // The settings snapshot is all-or-nothing: a layer the typed schema cannot
    // parse is refused whole, so the page opens on defaults instead of
    // presenting a partially parsed document as editable state.
    assert!(d.extended.harnesses.is_empty());
    assert!(d.extended_revision.is_none());
    assert_eq!(harness_status(&d), None);
}

/// Move to the `[seed installed presets]` row and activate it. Assumes
/// the cursor starts at row 0; with `n` harnesses already configured,
/// the seed row is at `n + 1` (after the harness rows and `[+ add]`).
fn seed_via_keys(d: &mut SettingsDialog) {
    enter_harnesses_from_root(d);
    let n = d.extended.harnesses.len();
    for _ in 0..(n + 1) {
        d.handle_key(press(KeyCode::Down));
    }
    d.handle_key(press(KeyCode::Enter));
}

fn harness_status(d: &SettingsDialog) -> Option<String> {
    match d.test_page() {
        TestPageRef::Harnesses(HarnessesPage::List(s)) => s.status.clone(),
        _ => None,
    }
}

#[test]
fn seeds_only_installed_presets() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    // Only `codex` and `goose` are on PATH.
    d.command_installed = |cmd| matches!(cmd, "codex" | "goose");
    seed_via_keys(&mut d);
    for name in ["codex", "goose"] {
        assert!(
            d.extended.harnesses.contains_key(name),
            "missing installed preset `{name}`"
        );
    }
    for name in ["claude", "opencode", "copilot", "grok"] {
        assert!(
            !d.extended.harnesses.contains_key(name),
            "seeded uninstalled preset `{name}`"
        );
    }
    assert_eq!(harness_status(&d).as_deref(), Some("saved"));
}

#[test]
fn seeds_nothing_and_reports_when_none_installed() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.command_installed = |_| false;
    seed_via_keys(&mut d);
    assert!(
        d.extended.harnesses.is_empty(),
        "seeded a preset with nothing on PATH"
    );
    assert_eq!(
        harness_status(&d).as_deref(),
        Some("no known harnesses found on `PATH`")
    );
}

#[test]
fn reset_with_partial_install_drops_uninstalled() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    // Seed the full set first (everything installed).
    d.command_installed = |_| true;
    seed_via_keys(&mut d);
    for name in ["claude", "codex", "opencode", "copilot", "goose", "grok"] {
        assert!(d.extended.harnesses.contains_key(name));
    }
    // Now only `claude` is on PATH; reset clears all then re-seeds
    // only the installed presets.
    d.command_installed = |cmd| cmd == "claude";
    // Reset row sits two below the seed row; navigate from the current
    // List page. n harnesses + [+ add] + [seed] = reset at n + 2.
    let n = d.extended.harnesses.len();
    // Re-enter to reset cursor to a known position.
    enter_harnesses_from_root(&mut d);
    for _ in 0..(n + 2) {
        d.handle_key(press(KeyCode::Down));
    }
    // Reset is a two-step confirm.
    d.handle_key(press(KeyCode::Enter));
    d.handle_key(press(KeyCode::Enter));
    assert!(d.extended.harnesses.contains_key("claude"));
    for name in ["codex", "opencode", "copilot", "goose", "grok"] {
        assert!(
            !d.extended.harnesses.contains_key(name),
            "reset kept uninstalled preset `{name}`"
        );
    }
    assert_eq!(harness_status(&d).as_deref(), Some("saved"));
}

#[test]
fn seeding_never_clobbers_existing_entry() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    // A user-edited `claude` entry with a custom command that isn't on
    // PATH; seeding must not overwrite it even though we only seed
    // installed presets.
    let mut custom = cockpit_config::extended::builtin_harness_presets()
        .into_iter()
        .find(|(n, _)| n == "claude")
        .map(|(_, hc)| hc)
        .unwrap();
    custom.command = "my-claude-wrapper".to_string();
    d.extended.harnesses.insert("claude".to_string(), custom);
    // Persist so it survives the reload-from-disk when the page opens.
    d.save_extended().unwrap();
    d.command_installed = |_| true;
    seed_via_keys(&mut d);
    assert_eq!(
        d.extended.harnesses.get("claude").unwrap().command,
        "my-claude-wrapper",
        "seeding clobbered an existing entry"
    );
}

#[test]
fn harnesses_page_h_returns_to_root() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_harnesses_from_root(&mut d);
    d.handle_key(press(KeyCode::Char('h')));
    assert!(on_root_page(&d), "h from Harnesses should return to Root");
}

#[test]
fn pressing_h_in_category_returns_to_root() {
    // Regression for the swap-back bug: the page wrappers used to
    // clobber inner `self.page = Root` writes with the placeholder
    // swap-back, so `h` from those pages did nothing.
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_root_node(&mut d, "Interface");
    assert!(
        matches!(d.test_page(), TestPageRef::Category(_)),
        "expected Category, got {:?}",
        d.page
    );
    d.handle_key(press(KeyCode::Char('h')));
    assert!(
        on_root_page(&d),
        "h from a category should return to Root, got {:?}",
        d.page
    );
}

fn type_chars(d: &mut SettingsDialog, s: &str) {
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    for ch in s.chars() {
        d.handle_key(KeyEvent {
            code: KeyCode::Char(ch),
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        });
    }
}

/// Open the Behavior page on the utility-model row and open the picker.
pub(super) fn open_utility_picker(d: &mut SettingsDialog) {
    open_category_on(d, Category::Behavior, SettingId::UtilityModel);
    d.handle_key(press(KeyCode::Enter)); // open picker
}

fn utility_picker(d: &SettingsDialog) -> &ui_page::UtilityModelPicker {
    match d.test_page() {
        TestPageRef::Category(p) => p.utility_picker.as_ref().expect("picker open"),
        other => panic!("expected Category page, got {other:?}"),
    }
}

/// With no configured models, opening the field drops straight into
/// the free-text fallback (Custom mode), and a typed `provider:model-id`
/// is accepted + persisted.
#[test]
fn utility_picker_custom_render_places_caret_at_textfield_cursor() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    open_utility_picker(&mut d);
    type_chars(&mut d, "ab");
    d.handle_key(press(KeyCode::Left));

    let rows = render_settings_rows(&d, 80, 20).join("\n");

    assert!(rows.contains("› a b"), "{rows}");
}

#[test]
fn utility_picker_no_models_falls_back_to_free_text() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    open_utility_picker(&mut d);
    // No providers → no entries → Custom mode immediately.
    let picker = utility_picker(&d);
    assert!(picker.entries.is_empty(), "no models configured");
    assert!(
        matches!(picker.mode, ui_page::PickerMode::Custom { .. }),
        "empty list opens straight into free-text entry"
    );
    type_chars(&mut d, "anthropic:claude-haiku");
    d.handle_key(press(KeyCode::Enter)); // accept
    assert_eq!(
        d.extended.utility_model.as_deref(),
        Some("anthropic:claude-haiku")
    );
    // Picker closed, status reflects the save.
    match d.test_page() {
        TestPageRef::Category(p) => {
            assert!(p.utility_picker.is_none(), "picker closes on accept");
            assert_eq!(p.status.as_deref(), Some("saved"));
        }
        other => panic!("expected Category, got {other:?}"),
    }
    let reloaded = cockpit_config::extended::ExtendedConfigDoc::load(&d.extended_path)
        .unwrap()
        .config();
    assert_eq!(
        reloaded.utility_model.as_deref(),
        Some("anthropic:claude-haiku"),
        "free-text utility model must persist to disk"
    );
}

pub(super) fn dialog_with_models(tmp: &TempDir) -> SettingsDialog {
    let path = tmp.path().join("config.json");
    // Two providers, each with two models, in natural (stored) order.
    std::fs::write(&path, "{}").unwrap();
    write_provider_file(
        &path,
        "anthropic",
        r#"{"url":"https://a","headers":[],
                "models":[{"id":"opus"},{"id":"haiku","name":"Haiku"}]}"#,
    );
    write_provider_file(
        &path,
        "openai",
        r#"{"url":"https://o","headers":[],"models":[{"id":"gpt-5"}]}"#,
    );
    open_fixture_dialog(&path)
}

/// The picker builds a grouped list across all configured providers,
/// each as `provider:model-id`, in provider-then-natural order.
#[test]
fn utility_picker_builds_grouped_list() {
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_models(&tmp);
    open_utility_picker(&mut d);
    let picker = utility_picker(&d);
    let values: Vec<String> = picker.entries.iter().map(|e| e.value()).collect();
    // Providers iterate in BTreeMap order (anthropic, openai); each
    // provider's models keep their stored order. No ranking.
    assert_eq!(
        values,
        vec![
            "anthropic:opus".to_string(),
            "anthropic:haiku".to_string(),
            "openai:gpt-5".to_string(),
        ]
    );
    // With no current value, the cursor lands on the first model row
    // (past the [clear] + [custom] action rows), and the human name
    // is carried for display.
    assert!(matches!(
        picker.mode,
        ui_page::PickerMode::List { cursor: 2, .. }
    ));
    assert_eq!(
        picker.entries[1].display_name.as_deref(),
        Some("Haiku"),
        "human name is preserved for display"
    );
}

/// Selecting a model row sets + saves `provider:model-id`.
#[test]
fn utility_picker_select_sets_and_saves() {
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_models(&tmp);
    open_utility_picker(&mut d);
    // Cursor starts on the first model row (anthropic:opus); Enter picks it.
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.utility_model.as_deref(), Some("anthropic:opus"));
    match d.test_page() {
        TestPageRef::Category(p) => {
            assert!(p.utility_picker.is_none(), "picker closes on select")
        }
        other => panic!("expected Ui, got {other:?}"),
    }
    let reloaded = cockpit_config::extended::ExtendedConfigDoc::load(&d.extended_path)
        .unwrap()
        .config();
    assert_eq!(reloaded.utility_model.as_deref(), Some("anthropic:opus"));
}

/// The current value is pre-selected (highlighted) when the picker opens.
#[test]
fn utility_picker_preselects_current_value() {
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_models(&tmp);
    d.extended.utility_model = Some("openai:gpt-5".into());
    // Persist so entering the UI page (which reloads extended-config)
    // preserves the value.
    d.save_extended().unwrap();
    open_utility_picker(&mut d);
    let picker = utility_picker(&d);
    // openai:gpt-5 is entry index 2; +2 action rows = cursor 4.
    match &picker.mode {
        ui_page::PickerMode::List { cursor, .. } => assert_eq!(*cursor, 4),
        _ => panic!("expected List mode"),
    }
    assert_eq!(picker.current.as_deref(), Some("openai:gpt-5"));
}

/// Free-text fallback from a populated list: the `[custom…]` action
/// switches to typing, and an id absent from every provider is accepted.
#[test]
fn utility_picker_custom_accepts_unlisted_id() {
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_models(&tmp);
    open_utility_picker(&mut d);
    // Move up from the first model row to the [custom] action (row 1).
    d.handle_key(press(KeyCode::Up)); // → [custom]
    match &utility_picker(&d).mode {
        ui_page::PickerMode::List { cursor, .. } => assert_eq!(*cursor, 1),
        _ => panic!("expected List mode on the custom row"),
    }
    d.handle_key(press(KeyCode::Enter)); // → Custom mode
    assert!(matches!(
        utility_picker(&d).mode,
        ui_page::PickerMode::Custom { .. }
    ));
    type_chars(&mut d, "local:my-llama");
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.utility_model.as_deref(), Some("local:my-llama"));
}

/// Clearing: the `[clear]` action unsets the value back to `None`.
#[test]
fn utility_picker_clear_unsets_value() {
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_models(&tmp);
    d.extended.utility_model = Some("anthropic:opus".into());
    d.save_extended().unwrap();
    open_utility_picker(&mut d);
    // Move up to the [clear] action (row 0) and pick it.
    // From the preselected current (anthropic:opus = cursor 2), Up twice
    // lands on [clear] (0).
    d.handle_key(press(KeyCode::Up));
    d.handle_key(press(KeyCode::Up));
    match &utility_picker(&d).mode {
        ui_page::PickerMode::List { cursor, .. } => assert_eq!(*cursor, 0),
        _ => panic!("expected List mode on the clear row"),
    }
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.utility_model, None, "clear unsets the value");
    let reloaded = cockpit_config::extended::ExtendedConfigDoc::load(&d.extended_path)
        .unwrap()
        .config();
    assert_eq!(reloaded.utility_model, None);
}

/// A blank custom entry also clears the value (unset).
#[test]
fn utility_picker_blank_custom_clears() {
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_models(&tmp);
    d.extended.utility_model = Some("anthropic:opus".into());
    d.save_extended().unwrap();
    open_utility_picker(&mut d);
    d.handle_key(press(KeyCode::Up)); // → [custom]
    d.handle_key(press(KeyCode::Enter)); // → Custom (pre-filled with current)
    // Clear the pre-filled buffer, then accept empty.
    for _ in 0..40 {
        d.handle_key(press(KeyCode::Backspace));
    }
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.utility_model, None, "blank custom clears");
}

#[test]
fn pressing_h_in_tools_returns_to_root() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);
    assert!(matches!(d.test_page(), TestPageRef::Tools(_)));
    d.handle_key(press(KeyCode::Char('h')));
    assert!(
        on_root_page(&d),
        "h from Tools should return to Root, got {:?}",
        d.page
    );
}

#[test]
fn enter_on_instructions_row_opens_instructions_page() {
    // The `instructions files` row on the Behavior page drills into the
    // Instructions sub-page.
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    open_category_on(&mut d, Category::Behavior, SettingId::Instructions);
    d.handle_key(press(KeyCode::Enter));
    assert!(
        matches!(d.test_page(), TestPageRef::Instructions(_)),
        "expected Instructions page after Enter on the instructions row, got {:?}",
        d.page
    );
}

#[test]
fn nav_stack_restores_behavior_cursor_and_scroll_from_instructions() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_root_node(&mut d, "Behavior");
    let before_cursor = match d.test_page_mut() {
        TestPageMut::Category(p) => {
            p.cursor = p.cursor_of(SettingId::Instructions).unwrap();
            p.cursor
        }
        other => panic!("expected Behavior category, got {other:?}"),
    };

    let _ = render_settings_rows(&d, 80, 10);
    let before_offset = d.scroll_states.offset_for("category:Behavior");
    assert!(before_offset > 0, "test setup should scroll Behavior");

    d.handle_key(press(KeyCode::Enter));
    assert!(matches!(d.test_page(), TestPageRef::Instructions(_)));
    d.handle_key(press(KeyCode::Esc));

    match d.test_page() {
        TestPageRef::Category(p) => {
            assert_eq!(p.category, Category::Behavior);
            assert_eq!(p.cursor, before_cursor);
        }
        other => panic!("expected restored Behavior category, got {other:?}"),
    }
    assert_eq!(
        d.scroll_states.offset_for("category:Behavior"),
        before_offset,
        "category ListState offset should survive drill-in/back"
    );
}

#[test]
fn nav_stack_restores_privacy_and_string_list_parents() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_root_node(&mut d, "Privacy & Safety");
    let privacy_cursor = match d.test_page_mut() {
        TestPageMut::Category(p) => {
            p.cursor = p.cursor_of(SettingId::RedactPatterns).unwrap();
            p.cursor
        }
        other => panic!("expected Privacy category, got {other:?}"),
    };
    d.handle_key(press(KeyCode::Enter));
    assert!(matches!(d.test_page(), TestPageRef::RedactPatterns(_)));
    d.handle_key(press(KeyCode::Esc));
    match d.test_page() {
        TestPageRef::Category(p) => {
            assert_eq!(p.category, Category::Privacy);
            assert_eq!(p.cursor, privacy_cursor);
        }
        other => panic!("expected restored Privacy category, got {other:?}"),
    }

    enter_root_node(&mut d, "Behavior");
    let behavior_cursor = match d.test_page_mut() {
        TestPageMut::Category(p) => {
            p.cursor = p.cursor_of(SettingId::AgentDirs).unwrap();
            p.cursor
        }
        other => panic!("expected Behavior category, got {other:?}"),
    };
    d.handle_key(press(KeyCode::Enter));
    assert!(matches!(d.test_page(), TestPageRef::StringList(_)));
    d.handle_key(press(KeyCode::Esc));
    match d.test_page() {
        TestPageRef::Category(p) => {
            assert_eq!(p.category, Category::Behavior);
            assert_eq!(p.cursor, behavior_cursor);
        }
        other => panic!("expected restored Behavior category, got {other:?}"),
    }
}

#[test]
fn esc_from_depth_two_pops_only_one_level() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_root_node(&mut d, "Behavior");
    match d.test_page_mut() {
        TestPageMut::Category(p) => p.cursor = p.cursor_of(SettingId::Instructions).unwrap(),
        other => panic!("expected Behavior category, got {other:?}"),
    }
    d.handle_key(press(KeyCode::Enter));
    assert!(matches!(d.test_page(), TestPageRef::Instructions(_)));

    assert!(!d.handle_key(press(KeyCode::Esc)));
    assert!(
        matches!(d.test_page(), TestPageRef::Category(p) if p.category == Category::Behavior),
        "Esc from sub-page should restore Behavior, got {:?}",
        d.page
    );
}

#[test]
fn popped_parent_renders_updated_subpage_values() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.extended.agent_guidance_files.clear();
    enter_root_node(&mut d, "Behavior");
    match d.test_page_mut() {
        TestPageMut::Category(p) => p.cursor = p.cursor_of(SettingId::Instructions).unwrap(),
        other => panic!("expected Behavior category, got {other:?}"),
    }
    d.handle_key(press(KeyCode::Enter));
    d.handle_key(press(KeyCode::Char('a')));
    type_chars(&mut d, "STACK.md");
    d.handle_key(press(KeyCode::Enter));
    d.handle_key(press(KeyCode::Esc));

    assert!(
        d.extended
            .agent_guidance_files
            .iter()
            .any(|path| path == "STACK.md"),
        "restored category should see updated instructions config"
    );
    let rendered = render_settings_rows(&d, 100, 20).join("\n");
    assert!(
        rendered.contains("STACK") && rendered.contains(".md"),
        "restored category should render updated instructions value; got:\n{rendered}"
    );
}

#[test]
fn back_from_behavior_restores_root_cursor() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_root_node(&mut d, "Behavior");
    d.handle_key(press(KeyCode::Char('h')));
    match d.test_page() {
        TestPageRef::Root { cursor } => {
            assert_eq!(
                cursor,
                root_index("Behavior"),
                "cursor should be on the Behavior row after return"
            )
        }
        other => panic!("expected Root, got {other:?}"),
    }
}

#[test]
fn back_from_tools_restores_root_cursor() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);
    d.handle_key(press(KeyCode::Char('h')));
    match d.test_page() {
        TestPageRef::Root { cursor } => {
            assert_eq!(
                cursor,
                root_index("Tools"),
                "cursor should be on the Tools row after return"
            )
        }
        other => panic!("expected Root, got {other:?}"),
    }
}

#[test]
fn root_children_restore_their_own_root_cursor() {
    let root_children = [
        PROVIDERS_TITLE,
        "Agents",
        "Interface",
        "Behavior",
        "Privacy & Safety",
        "Translation",
        "Profile",
        "Tools",
        "Harnesses",
        "Skills",
        "MCP",
        "LSP",
    ];
    for title in root_children {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        enter_root_node(&mut d, title);
        assert!(
            !matches!(d.test_page(), TestPageRef::Root { .. }),
            "`{title}` should open a child page"
        );

        d.handle_key(press(KeyCode::Char('h')));

        match d.test_page() {
            TestPageRef::Root { cursor } => assert_eq!(
                cursor,
                root_index(title),
                "`{title}` should return to its own root row"
            ),
            other => panic!("expected `{title}` to return to Root, got {other:?}"),
        }
    }
}

#[test]
fn pressing_a_on_picker_opens_scoped_create_dialog() {
    // The new affordance: `a` on Dialog::PickConfig opens the
    // "where should this config live?" sub-dialog.
    // Isolate the home layers: discovery must see exactly this fixture, not
    // whatever concurrent test processes leave under the shared real $HOME.
    let _env = cockpit_test_support::TestEnvGuard::isolated_cockpit_home();
    let tmp = TempDir::new().unwrap();
    let cockpit_dir = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&cockpit_dir).unwrap();
    std::fs::write(cockpit_dir.join("config.json"), "{}").unwrap();
    let mut d = Dialog::open(tmp.path());
    assert!(matches!(d, Dialog::PickConfig { .. }));
    let close = d.handle_key(press(KeyCode::Char('a')));
    assert!(!close);
    assert!(
        matches!(d, Dialog::CreateScopedConfig { .. }),
        "after `a` the dialog should be on CreateScopedConfig"
    );
}

#[test]
fn esc_from_scoped_create_returns_to_picker() {
    // Hermetic home for the same reason as the sibling `a` test above.
    let _env = cockpit_test_support::TestEnvGuard::isolated_cockpit_home();
    let tmp = TempDir::new().unwrap();
    let cockpit_dir = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&cockpit_dir).unwrap();
    std::fs::write(cockpit_dir.join("config.json"), "{}").unwrap();
    let mut d = Dialog::open(tmp.path());
    d.handle_key(press(KeyCode::Char('a')));
    assert!(matches!(d, Dialog::CreateScopedConfig { .. }));
    d.handle_key(press(KeyCode::Esc));
    assert!(
        matches!(d, Dialog::PickConfig { .. }),
        "Esc from CreateScopedConfig should return to PickConfig"
    );
}

#[test]
fn create_config_scaffold_failure_stays_open_with_path_status() {
    let tmp = TempDir::new().unwrap();
    let blocked = tmp.path().join("not-a-dir");
    std::fs::write(&blocked, "file blocks directory creation").unwrap();
    let mut d = Dialog::CreateConfig {
        choices: vec![ConfigDir {
            kind: ConfigDirKind::Project,
            path: blocked.clone(),
        }],
        cursor: 0,
        cwd: tmp.path().to_path_buf(),
        status: None,
    };

    let close = d.handle_key(press(KeyCode::Enter));
    assert!(!close, "scaffold failure must not close the dialog");
    match d {
        Dialog::CreateConfig { status, .. } => {
            let status = status.expect("failure should set inline status");
            assert!(status.contains("failed to create"));
            assert!(status.contains(&blocked.display().to_string()));
        }
        _ => panic!("expected CreateConfig after failure"),
    }
}

#[test]
fn create_config_success_opens_settings_editor() {
    let tmp = TempDir::new().unwrap();
    let target = tmp.path().join(".cockpit");
    // Scaffolding materializes the layer through the daemon patch path, so the
    // target has to be a layer the daemon can resolve.
    super::disk_daemon_fake::register_settings_layer_target(&target.join("config.json"));
    let mut d = Dialog::CreateConfig {
        choices: vec![ConfigDir {
            kind: ConfigDirKind::Project,
            path: target.clone(),
        }],
        cursor: 0,
        cwd: tmp.path().to_path_buf(),
        status: Some("old error".into()),
    };

    let close = d.handle_key(press(KeyCode::Enter));
    assert!(!close);
    match d {
        Dialog::Settings(settings) => {
            assert_eq!(settings.config_path, target.join("config.json"))
        }
        _ => panic!("expected Settings after scaffold success"),
    }
}

#[test]
fn scoped_create_scaffold_failure_still_returns_to_picker_with_path_status() {
    let tmp = TempDir::new().unwrap();
    let existing = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&existing).unwrap();
    std::fs::write(existing.join("config.json"), "{}").unwrap();
    let blocked = tmp.path().join("not-a-dir");
    std::fs::write(&blocked, "file blocks directory creation").unwrap();
    let mut d = Dialog::CreateScopedConfig {
        choices: vec![ConfigDir {
            kind: ConfigDirKind::Project,
            path: blocked.clone(),
        }],
        cursor: 0,
        cwd: tmp.path().to_path_buf(),
    };

    let close = d.handle_key(press(KeyCode::Enter));
    assert!(!close);
    match d {
        Dialog::PickConfig { status, .. } => {
            let status = status.expect("failure should set picker status");
            assert!(status.contains("failed to create"));
            assert!(status.contains(&blocked.display().to_string()));
        }
        _ => panic!("expected PickConfig after scoped failure"),
    }
}

#[test]
fn h_from_settings_root_returns_to_picker() {
    // After picking a config, the user should be able to back out
    // of the settings root with h/← and land on the picker again.
    let tmp = TempDir::new().unwrap();
    let cockpit_dir = tmp.path().join(".cockpit");
    std::fs::create_dir_all(&cockpit_dir).unwrap();
    std::fs::write(cockpit_dir.join("config.json"), "{}").unwrap();
    let mut d = Dialog::open(tmp.path());
    // Step into the (only) config.
    d.handle_key(press(KeyCode::Enter));
    assert!(matches!(d, Dialog::Settings(_)));
    d.handle_key(press(KeyCode::Char('h')));
    assert!(
        matches!(d, Dialog::PickConfig { .. }),
        "h from Settings Root should reopen the picker"
    );
}

#[test]
fn settings_nested_esc_backs_out_but_q_closes() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    open_category_on(&mut d, Category::Behavior, SettingId::Instructions);
    assert!(matches!(d.test_page(), TestPageRef::Category(_)));
    assert!(!d.handle_key(press(KeyCode::Esc)));
    assert!(on_root_page(&d), "Esc from category returns to root");

    open_category_on(&mut d, Category::Behavior, SettingId::Instructions);
    assert!(d.handle_key(press(KeyCode::Char('q'))));
}

fn fresh_instructions_dialog(tmp: &TempDir) -> SettingsDialog {
    let mut d = fresh_dialog(tmp);
    open_category_on(&mut d, Category::Behavior, SettingId::Instructions);
    d.handle_key(press(KeyCode::Enter));
    assert!(matches!(d.test_page(), TestPageRef::Instructions(_)));
    d
}

#[test]
fn instructions_a_starts_grab_with_empty_buffer() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_instructions_dialog(&tmp);
    d.handle_key(press(KeyCode::Char('a')));
    match d.test_page() {
        TestPageRef::Instructions(p) => {
            let g = p.grabbed.as_ref().expect("expected grabbed state");
            assert!(g.buf.text().is_empty());
            assert!(g.original_name.is_none(), "new row has no original name");
            assert_eq!(p.cursor, d.extended.agent_guidance_files.len() - 1);
        }
        other => panic!("expected Instructions, got {other:?}"),
    }
}

#[test]
fn instructions_esc_on_freshly_added_row_removes_it() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_instructions_dialog(&tmp);
    let before = d.extended.agent_guidance_files.len();
    d.handle_key(press(KeyCode::Char('a')));
    d.handle_key(press(KeyCode::Esc));
    match d.test_page() {
        TestPageRef::Instructions(p) => {
            assert!(p.grabbed.is_none(), "esc should drop the grab");
            assert_eq!(
                d.extended.agent_guidance_files.len(),
                before,
                "esc on a freshly-added row should delete it"
            );
        }
        other => panic!("expected Instructions, got {other:?}"),
    }
}

#[test]
fn instructions_enter_grabs_existing_row_then_arrow_swaps() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_instructions_dialog(&tmp);
    // Seed two known rows.
    d.extended.agent_guidance_files = vec!["AGENTS.md".into(), "project guidance".into()];
    // Reset to row 0 and grab it.
    d.set_test_page(Page::Instructions(InstructionsPage {
        cursor: 0,
        grabbed: None,
        status: None,
        delete: RowDeleteConfirm::default(),
    }));
    d.handle_key(press(KeyCode::Enter));
    // Now grabbed at idx 0. Press ↓ to swap with row 1.
    d.handle_key(press(KeyCode::Down));
    assert_eq!(
        d.extended.agent_guidance_files,
        vec!["project guidance".to_string(), "AGENTS.md".to_string()]
    );
    // Drop with Enter → save.
    d.handle_key(press(KeyCode::Enter));
    match d.test_page() {
        TestPageRef::Instructions(p) => assert!(p.grabbed.is_none()),
        other => panic!("expected Instructions, got {other:?}"),
    }
}

#[test]
fn instructions_esc_after_swap_restores_original_order() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_instructions_dialog(&tmp);
    d.extended.agent_guidance_files = vec!["AGENTS.md".into(), "project guidance".into()];
    d.set_test_page(Page::Instructions(InstructionsPage {
        cursor: 0,
        grabbed: None,
        status: None,
        delete: RowDeleteConfirm::default(),
    }));
    d.handle_key(press(KeyCode::Enter));
    d.handle_key(press(KeyCode::Down));
    // Mid-grab the list is mutated. Esc must restore.
    d.handle_key(press(KeyCode::Esc));
    assert_eq!(
        d.extended.agent_guidance_files,
        vec!["AGENTS.md".to_string(), "project guidance".to_string()],
        "esc should restore original order"
    );
}

#[test]
fn instructions_typing_while_grabbed_edits_filename() {
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_instructions_dialog(&tmp);
    d.extended.agent_guidance_files = vec!["X".into()];
    d.set_test_page(Page::Instructions(InstructionsPage {
        cursor: 0,
        grabbed: None,
        status: None,
        delete: RowDeleteConfirm::default(),
    }));
    d.handle_key(press(KeyCode::Enter));
    for ch in "Y".chars() {
        d.handle_key(KeyEvent {
            code: KeyCode::Char(ch),
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        });
    }
    // Commit with Enter.
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.agent_guidance_files, vec!["XY".to_string()]);
}

#[test]
fn string_list_keyboard_delete_remains_immediate() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.extended.redact.denylist = vec!["secret-value".to_string(), "other-value".to_string()];
    d.save_extended().unwrap();
    d.set_test_page(Page::StringList(
        Box::new(StringListPage::redact_denylist()),
    ));

    d.handle_key(press(KeyCode::Char('d')));
    assert_eq!(resolved_denylist(&d), vec!["other-value".to_string()]);
    let on_disk = std::fs::read_to_string(&d.extended_path).unwrap();
    assert!(!on_disk.contains("secret-value"), "{on_disk}");
}

#[test]
fn redact_denylist_values_are_masked_in_summary_and_list_render() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.extended.redact.denylist = vec!["secret-value".to_string(), "other-value".to_string()];
    d.save_extended().unwrap();

    open_category_on(&mut d, Category::Privacy, SettingId::RedactDenylist);
    let rendered = render_settings_rows(&d, 100, 55).join("\n");
    assert!(rendered.contains("2 value(s) masked"), "{rendered}");
    assert!(!rendered.contains("secret-value"), "{rendered}");
    assert!(!rendered.contains("other-value"), "{rendered}");

    d.set_test_page(Page::StringList(
        Box::new(StringListPage::redact_denylist()),
    ));
    let rendered = render_settings_rows(&d, 100, 22).join("\n");
    assert!(
        rendered.contains(secret_display::MASKED_VALUE),
        "{rendered}"
    );
    assert!(!rendered.contains("secret-value"), "{rendered}");
    assert!(!rendered.contains("other-value"), "{rendered}");
}

#[test]
fn redact_denylist_existing_edit_is_replacement_only() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.extended.redact.denylist = vec!["secret-value".to_string()];
    d.save_extended().unwrap();
    d.set_test_page(Page::StringList(
        Box::new(StringListPage::redact_denylist()),
    ));

    d.handle_key(press(KeyCode::Enter));
    match d.test_page() {
        TestPageRef::StringList(p) => {
            let grabbed = p.grabbed.as_ref().expect("grabbed denylist row");
            assert_eq!(grabbed.buf.text(), "");
            // A committed row is addressed by its opaque occurrence, so the
            // literal is never carried back into the editor.
            let original = grabbed.original_name.as_deref().expect("existing row");
            assert!(original.starts_with(super::DENYLIST_EXISTING_DRAFT_PREFIX));
            assert!(!original.contains("secret-value"));
        }
        other => panic!("expected StringList, got {other:?}"),
    }
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(resolved_denylist(&d), vec!["secret-value".to_string()]);

    d.handle_key(press(KeyCode::Enter));
    for ch in "replacement".chars() {
        d.handle_key(press(KeyCode::Char(ch)));
    }
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(resolved_denylist(&d), vec!["replacement".to_string()]);
}

#[test]
fn enter_on_headers_row_navigates_to_headers_subpage() {
    // Provider Edit page → cursor on row 1 (Headers) → Enter
    // should land on the dedicated Headers sub-page, not open an
    // overlay on the Edit page.
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_one_provider(&tmp);
    d.handle_key(press(KeyCode::Enter)); // List → Edit(vendor)
    match d.test_page() {
        TestPageRef::Providers(ProvidersPage::Edit(_)) => {}
        other => panic!("expected Edit, got {other:?}"),
    }
    // Move to Headers row (idx 1).
    d.handle_key(press(KeyCode::Char('j')));
    d.handle_key(press(KeyCode::Enter));
    match d.test_page() {
        TestPageRef::Providers(ProvidersPage::Headers { parent, .. }) => {
            assert_eq!(parent.provider_id, "vendor");
        }
        other => panic!("expected Headers sub-page, got {other:?}"),
    }
}

#[test]
fn back_from_headers_returns_to_edit_with_updated_headers() {
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_one_provider(&tmp);
    d.handle_key(press(KeyCode::Enter)); // → Edit
    d.handle_key(press(KeyCode::Char('j'))); // cursor → row 1 (Headers)
    d.handle_key(press(KeyCode::Enter)); // → Headers sub-page
    // Add a header via the Browse-mode `a` action, which opens the
    // name/value popup focused on the name field.
    d.handle_key(press(KeyCode::Char('a')));
    // Type a name — a new header with an empty name is discarded on
    // save — then Enter commits and closes the popup.
    d.handle_key(press(KeyCode::Char('x')));
    d.handle_key(press(KeyCode::Enter));
    // `h` from Browse mode returns to the Edit page.
    d.handle_key(press(KeyCode::Char('h')));
    match d.test_page() {
        TestPageRef::Providers(ProvidersPage::Edit(s)) => {
            assert_eq!(s.provider_id, "vendor");
            assert_eq!(s.cursor, 1, "cursor returns to the Headers row");
            assert_eq!(
                s.entry.headers.len(),
                1,
                "headers added on the sub-page should be on the parent EditState"
            );
        }
        other => panic!("expected Edit after back, got {other:?}"),
    }
}

#[test]
fn cancel_add_leaves_no_header() {
    // Opening the add popup and pressing Esc must not leave a blank
    // row behind — the row is only committed on Enter.
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_one_provider(&tmp);
    d.handle_key(press(KeyCode::Enter)); // → Edit
    d.handle_key(press(KeyCode::Char('j'))); // cursor → Headers row
    d.handle_key(press(KeyCode::Enter)); // → Headers sub-page
    let before = match d.test_page() {
        TestPageRef::Providers(ProvidersPage::Headers { editor, .. }) => editor.rows().len(),
        other => panic!("expected Headers sub-page, got {other:?}"),
    };
    d.handle_key(press(KeyCode::Char('a'))); // open add popup
    d.handle_key(press(KeyCode::Char('x'))); // type a name
    d.handle_key(press(KeyCode::Esc)); // cancel — discards the add
    match d.test_page() {
        TestPageRef::Providers(ProvidersPage::Headers { editor, .. }) => {
            assert_eq!(editor.rows().len(), before, "cancelled add leaves no row");
            assert!(!editor.is_editing(), "popup is closed after cancel");
        }
        other => panic!("expected Headers sub-page, got {other:?}"),
    }
}

#[test]
fn popup_tab_routes_typing_to_value_field() {
    // In the add/edit popup, Tab switches focus from name to value
    // so subsequent keystrokes land in the value field.
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_one_provider(&tmp);
    d.handle_key(press(KeyCode::Enter)); // → Edit
    d.handle_key(press(KeyCode::Char('j'))); // cursor → Headers row
    d.handle_key(press(KeyCode::Enter)); // → Headers sub-page
    d.handle_key(press(KeyCode::Char('a'))); // open add popup (name focus)
    d.handle_key(press(KeyCode::Char('n'))); // → name buffer
    d.handle_key(press(KeyCode::Tab)); // focus → value
    d.handle_key(press(KeyCode::Char('v'))); // → value buffer
    d.handle_key(press(KeyCode::Enter)); // commit
    match d.test_page() {
        TestPageRef::Providers(ProvidersPage::Headers { editor, .. }) => {
            let row = editor.rows().last().expect("a header row was added");
            assert_eq!(row.name, "n");
            assert_eq!(row.value, "v");
        }
        other => panic!("expected Headers sub-page, got {other:?}"),
    }
}

#[test]
fn enter_on_models_row_navigates_to_models_subpage() {
    // Provider Edit page → cursor on row 2 (Models) → Enter lands on
    // the dedicated Models sub-page.
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_one_provider(&tmp);
    d.handle_key(press(KeyCode::Enter)); // List → Edit(vendor)
    d.handle_key(press(KeyCode::Char('j'))); // → row 1 (Headers)
    d.handle_key(press(KeyCode::Char('j'))); // → row 2 (Models)
    d.handle_key(press(KeyCode::Enter));
    match d.test_page() {
        TestPageRef::Providers(ProvidersPage::Models { parent, .. }) => {
            assert_eq!(parent.provider_id, "vendor");
        }
        other => panic!("expected Models sub-page, got {other:?}"),
    }
}

#[test]
fn add_manual_model_then_back_lands_on_edit_with_manual_entry() {
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_one_provider(&tmp);
    d.handle_key(press(KeyCode::Enter)); // → Edit
    d.handle_key(press(KeyCode::Char('j'))); // → Headers
    d.handle_key(press(KeyCode::Char('j'))); // → Models
    d.handle_key(press(KeyCode::Enter)); // → Models sub-page
    // Add a manual entry: `a` opens the popup focused on the id field.
    d.handle_key(press(KeyCode::Char('a')));
    for ch in "gpt-x".chars() {
        d.handle_key(press(KeyCode::Char(ch)));
    }
    d.handle_key(press(KeyCode::Enter)); // commit
    // Back to Edit.
    d.handle_key(press(KeyCode::Char('h')));
    match d.test_page() {
        TestPageRef::Providers(ProvidersPage::Edit(s)) => {
            assert_eq!(s.cursor, 2, "cursor returns to the Models row");
            assert_eq!(s.entry.models.len(), 1);
            assert_eq!(s.entry.models[0].id, "gpt-x");
            assert!(s.entry.models[0].manual, "added entry is flagged manual");
        }
        other => panic!("expected Edit after back, got {other:?}"),
    }
}

#[test]
fn add_model_empty_id_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_one_provider(&tmp);
    d.handle_key(press(KeyCode::Enter)); // → Edit
    d.handle_key(press(KeyCode::Char('j'))); // → Headers
    d.handle_key(press(KeyCode::Char('j'))); // → Models
    d.handle_key(press(KeyCode::Enter)); // → Models sub-page
    d.handle_key(press(KeyCode::Char('a'))); // open popup
    d.handle_key(press(KeyCode::Enter)); // commit with empty id
    match d.test_page() {
        TestPageRef::Providers(ProvidersPage::Models { editor, .. }) => {
            assert!(editor.is_editing(), "popup stays open on empty id");
            assert!(editor.rows().is_empty(), "no row added");
            assert!(editor.status.as_deref().unwrap_or("").contains("empty"));
        }
        other => panic!("expected Models sub-page, got {other:?}"),
    }
}

#[test]
fn add_model_duplicate_id_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_one_provider(&tmp);
    d.handle_key(press(KeyCode::Enter)); // → Edit
    d.handle_key(press(KeyCode::Char('j'))); // → Headers
    d.handle_key(press(KeyCode::Char('j'))); // → Models
    d.handle_key(press(KeyCode::Enter)); // → Models sub-page
    // Add `dup` once.
    d.handle_key(press(KeyCode::Char('a')));
    for ch in "dup".chars() {
        d.handle_key(press(KeyCode::Char(ch)));
    }
    d.handle_key(press(KeyCode::Enter));
    // Try to add `dup` again.
    d.handle_key(press(KeyCode::Char('a')));
    for ch in "dup".chars() {
        d.handle_key(press(KeyCode::Char(ch)));
    }
    d.handle_key(press(KeyCode::Enter));
    match d.test_page() {
        TestPageRef::Providers(ProvidersPage::Models { editor, .. }) => {
            assert!(editor.is_editing(), "popup stays open on duplicate id");
            assert_eq!(editor.rows().len(), 1, "no duplicate row added");
            assert!(
                editor
                    .status
                    .as_deref()
                    .unwrap_or("")
                    .contains("already exists")
            );
        }
        other => panic!("expected Models sub-page, got {other:?}"),
    }
}

#[test]
fn h_on_edit_page_returns_to_list() {
    // `h` on the Edit page is back-to-list — it must not open the
    // (now-removed) inline header editor.
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_one_provider(&tmp);
    d.handle_key(press(KeyCode::Enter)); // → Edit
    d.handle_key(press(KeyCode::Char('h')));
    match d.test_page() {
        TestPageRef::Providers(ProvidersPage::List { .. }) => {}
        other => panic!("expected List after `h`, got {other:?}"),
    }
}

#[test]
fn instructions_esc_after_rename_restores_original_name() {
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_instructions_dialog(&tmp);
    d.extended.agent_guidance_files = vec!["AGENTS.md".into()];
    d.set_test_page(Page::Instructions(InstructionsPage {
        cursor: 0,
        grabbed: None,
        status: None,
        delete: RowDeleteConfirm::default(),
    }));
    d.handle_key(press(KeyCode::Enter));
    // Type some junk.
    for ch in "ZZZ".chars() {
        d.handle_key(KeyEvent {
            code: KeyCode::Char(ch),
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        });
    }
    d.handle_key(press(KeyCode::Esc));
    assert_eq!(
        d.extended.agent_guidance_files,
        vec!["AGENTS.md".to_string()],
        "esc should restore the original filename"
    );
}

// ── Page-level "reset to defaults" buttons ─────────────────────────

/// Move the cursor to a row by issuing `n` Down keys from the top.
fn cursor_down(d: &mut SettingsDialog, n: usize) {
    for _ in 0..n {
        d.handle_key(press(KeyCode::Down));
    }
}

fn tools_page_lines(d: &SettingsDialog) -> Vec<String> {
    let p = match d.test_page() {
        TestPageRef::Tools(p) => p,
        other => panic!("expected Tools, got {other:?}"),
    };
    d.build_tools_page_lines(100, p)
        .iter()
        .map(line_text)
        .collect()
}

fn set_tools_cursor(d: &mut SettingsDialog, cursor: usize) {
    match d.test_page_mut() {
        TestPageMut::Tools(p) => p.cursor = cursor,
        other => panic!("expected Tools, got {other:?}"),
    }
}

fn selected_tools_line_for_cursor(d: &mut SettingsDialog, cursor: usize) -> Option<String> {
    set_tools_cursor(d, cursor);
    tools_page_lines(d)
        .into_iter()
        .find(|line| line.starts_with("▸ "))
}

fn tools_cursor_for_label(d: &mut SettingsDialog, label: &str) -> usize {
    for cursor in 0..200 {
        if let Some(line) = selected_tools_line_for_cursor(d, cursor)
            && line.contains(label)
        {
            return cursor;
        }
    }
    panic!("no Tools row containing `{label}`");
}

fn set_tools_cursor_to_label(d: &mut SettingsDialog, label: &str) {
    let cursor = tools_cursor_for_label(d, label);
    set_tools_cursor(d, cursor);
}

#[test]
fn tools_reset_arms_then_clears_custom_web_commands_and_drops_custom_tools() {
    use cockpit_config::extended::ToolCommandTemplate;
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);

    d.extended.web.custom.fetch_command = Some("fetch {url}".into());
    d.extended.web.custom.search_command = Some("search {query}".into());
    d.extended.web.provider = cockpit_config::extended::WebProvider::Custom;
    d.extended.web.firecrawl_base_url = Some("https://firecrawl.local".into());
    d.extended.tools.insert(
        "my_custom".into(),
        ToolCommandTemplate {
            enabled: true,
            command: "echo hi".into(),
            description: None,
        },
    );

    set_tools_cursor_to_label(&mut d, "[reset to defaults]");

    // First activation arms (no change yet).
    d.handle_key(press(KeyCode::Enter));
    match d.test_page() {
        TestPageRef::Tools(p) => assert!(p.reset.is_pending(), "first activation arms"),
        other => panic!("expected Tools, got {other:?}"),
    }
    assert_eq!(
        d.extended.web.custom.fetch_command.as_deref(),
        Some("fetch {url}"),
        "arming must not mutate config"
    );
    assert!(d.extended.tools.contains_key("my_custom"));

    // Second activation applies + saves.
    d.handle_key(press(KeyCode::Enter));
    match d.test_page() {
        TestPageRef::Tools(p) => assert!(!p.reset.is_pending(), "applying disarms"),
        other => panic!("expected Tools, got {other:?}"),
    }
    assert!(
        !d.extended.tools.contains_key("my_custom"),
        "custom tool removed"
    );
    assert_eq!(d.extended.web.custom.fetch_command, None);
    assert_eq!(d.extended.web.custom.search_command, None);
    assert_eq!(
        d.extended.web.provider,
        cockpit_config::extended::WebProvider::Firecrawl
    );
    assert_eq!(d.extended.web.firecrawl_base_url, None);
    assert!(
        tools_page_lines(&d)
            .iter()
            .any(|line| line.contains("read") && line.contains("sandbox boundary")),
        "builtin inventory remains rendered"
    );
    // Persisted to disk.
    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert!(!reloaded.tools.contains_key("my_custom"));
    assert_eq!(reloaded.web.custom.fetch_command, None);
    assert_eq!(reloaded.web.custom.search_command, None);
    assert_eq!(
        reloaded.web.provider,
        cockpit_config::extended::WebProvider::Firecrawl
    );
    assert_eq!(reloaded.web.firecrawl_base_url, None);
}

#[test]
fn tools_reset_pending_cancelled_by_navigation() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);
    set_tools_cursor_to_label(&mut d, "[reset to defaults]");
    d.handle_key(press(KeyCode::Enter)); // arm
    match d.test_page() {
        TestPageRef::Tools(p) => assert!(p.reset.is_pending()),
        other => panic!("expected Tools, got {other:?}"),
    }
    // Navigate away → disarm.
    d.handle_key(press(KeyCode::Up));
    match d.test_page() {
        TestPageRef::Tools(p) => assert!(!p.reset.is_pending(), "navigation disarms reset"),
        other => panic!("expected Tools, got {other:?}"),
    }
}

#[test]
fn tools_page_documents_custom_web_placeholders() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);
    let p = match d.test_page() {
        TestPageRef::Tools(p) => p,
        other => panic!("expected Tools, got {other:?}"),
    };
    let rendered = d
        .build_tools_page_lines(80, p)
        .into_iter()
        .flat_map(|line| line.spans.into_iter().map(|span| span.content.into_owned()))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(rendered.contains("Custom web commands must include {url}"));
    assert!(rendered.contains("{query}"));
}

#[test]
fn tools_page_wraps_long_values_under_value_column() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);
    d.extended.web.provider = cockpit_config::extended::WebProvider::Custom;
    d.extended.web.custom.fetch_command =
        Some("curl --header very-long-header --max-time 20 --retry 4 -- {url}".into());

    let p = match d.test_page() {
        TestPageRef::Tools(p) => p,
        other => panic!("expected Tools, got {other:?}"),
    };
    let rendered: Vec<String> = d
        .build_tools_page_lines(38, p)
        .into_iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
        })
        .collect();

    let command_row = rendered
        .iter()
        .position(|line| line.contains("webfetch"))
        .expect("command row rendered");
    assert!(
        rendered[command_row + 1].starts_with("                  "),
        "command continuation should align under value column: {:?}",
        rendered[command_row + 1]
    );
    assert!(
        !rendered[command_row + 1].starts_with("curl"),
        "command continuation must not restart at column 0"
    );
}

#[test]
fn tools_page_renders_inventory_sections_in_order() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);
    let rendered = tools_page_lines(&d);
    let web = rendered
        .iter()
        .position(|line| line == "Web tools")
        .unwrap();
    let builtin = rendered
        .iter()
        .position(|line| line == "Built-in tools")
        .unwrap();
    let user = rendered
        .iter()
        .position(|line| line == "User-defined tools")
        .unwrap();
    let mcp = rendered
        .iter()
        .position(|line| line == "MCP tools")
        .unwrap();
    assert!(web < builtin && builtin < user && user < mcp);
}

#[test]
fn tools_page_provider_choice_is_first_navigable_control() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);
    let selected = selected_tools_line_for_cursor(&mut d, 0).expect("selected row");
    assert!(selected.contains("provider"), "{selected}");
}

#[test]
fn tools_page_root_description_matches_inventory_scope() {
    let nodes = root_nodes();
    let tools = nodes
        .iter()
        .find(|node| node.title == "Tools")
        .expect("Tools root node");
    assert!(!tools.description.contains("Custom bash-command tools"));
    assert!(tools.description.contains("Tool inventory"));
}

#[test]
fn tools_page_provider_rows_are_inline_and_provider_specific() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);

    let rendered = tools_page_lines(&d);
    let builtin = rendered
        .iter()
        .position(|line| line == "Built-in tools")
        .unwrap();
    let firecrawl = rendered[..builtin].join("\n");
    assert!(firecrawl.contains("provider"));
    assert!(firecrawl.contains("base url"), "{firecrawl}");
    assert!(firecrawl.contains("api key"), "{firecrawl}");
    assert!(!firecrawl.contains("webfetch"), "{firecrawl}");

    d.extended.web.provider = cockpit_config::extended::WebProvider::Custom;
    let rendered = tools_page_lines(&d);
    let builtin = rendered
        .iter()
        .position(|line| line == "Built-in tools")
        .unwrap();
    let custom = rendered[..builtin].join("\n");
    assert!(custom.contains("webfetch"), "{custom}");
    assert!(custom.contains("websearch"), "{custom}");
    assert!(!custom.contains("api key"), "{custom}");
    assert!(!custom.contains("base url"), "{custom}");
}

#[test]
fn tools_page_custom_blank_webfetch_warns_not_registered() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);
    d.extended.web.provider = cockpit_config::extended::WebProvider::Custom;
    d.extended.web.custom.fetch_command = None;

    let blank = tools_page_lines(&d);
    let webfetch = blank
        .iter()
        .find(|line| line.contains("webfetch"))
        .expect("webfetch row");
    assert!(
        webfetch.contains("not registered - no command set"),
        "{webfetch}"
    );

    d.extended.web.custom.fetch_command = Some("fetch-cli {url}".into());
    let set = tools_page_lines(&d);
    let webfetch = set
        .iter()
        .find(|line| line.contains("webfetch"))
        .expect("webfetch row");
    assert!(!webfetch.contains("not registered"), "{webfetch}");
}

#[test]
fn tools_page_builtin_rows_are_read_only() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);
    set_tools_cursor_to_label(&mut d, "read");
    d.handle_key(press(KeyCode::Enter));
    match d.test_page() {
        TestPageRef::Tools(p) => {
            assert!(p.editing.is_none());
            assert_eq!(p.status.as_deref(), Some("read-only inventory row"));
        }
        other => panic!("expected Tools, got {other:?}"),
    }
}

#[test]
fn tools_page_add_and_remove_user_defined_tool_persists() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);

    set_tools_cursor_to_label(&mut d, "[+ add tool]");
    d.handle_key(press(KeyCode::Enter));
    d.paste("my_tool");
    d.handle_key(press(KeyCode::Enter));
    assert!(d.extended.tools.contains_key("my_tool"));
    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert!(reloaded.tools.contains_key("my_tool"));

    set_tools_cursor_to_label(&mut d, "my_tool");
    d.handle_key(press(KeyCode::Char('d')));
    assert!(d.extended.tools.contains_key("my_tool"));
    d.handle_key(press(KeyCode::Char('d')));
    assert!(!d.extended.tools.contains_key("my_tool"));
    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert!(!reloaded.tools.contains_key("my_tool"));
}

#[test]
fn tools_page_reserved_user_defined_tool_name_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);

    set_tools_cursor_to_label(&mut d, "[+ add tool]");
    d.handle_key(press(KeyCode::Enter));
    d.paste("webfetch");
    d.handle_key(press(KeyCode::Enter));

    assert!(!d.extended.tools.contains_key("webfetch"));
    match d.test_page() {
        TestPageRef::Tools(p) => {
            assert!(p.status.as_deref().unwrap_or_default().contains("webfetch"))
        }
        other => panic!("expected Tools, got {other:?}"),
    }
}

#[test]
fn tools_page_mcp_section_empty_and_cached_tools_jump_to_mcp() {
    let tmp = TempDir::new().unwrap();
    // The tools page's MCP view is the daemon's redacted MCP snapshot, taken
    // when the dialog opens. Isolate the environment and promote an in-process
    // daemon so that snapshot is empty here rather than reflecting a real
    // developer daemon's servers.
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let _daemon = cockpit_core::daemon::enable_in_process_auto_promote();
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);
    let empty = tools_page_lines(&d).join("\n");
    assert!(empty.contains("No MCP servers configured."), "{empty}");
    assert!(empty.contains("configure in MCP ->"), "{empty}");

    let raw = r#"{"servers":{"docs":{"transport":"streamable","endpoint":"https://example.test/mcp","enabled":true}}}"#;
    let cfg = cockpit_core::mcp::config::McpConfig::parse(raw).unwrap();
    let server = cfg.servers.get("docs").unwrap().clone();
    let cache_dir = tmp.path().join("mcp-cache");
    cockpit_core::mcp::cache::save_in(
        &cache_dir,
        &cockpit_core::mcp::cache::cache_key("docs", &server),
        &[cockpit_core::mcp::protocol::ToolDescriptor {
            name: "lookup".into(),
            description: "Find docs\nwith details".into(),
            input_schema: serde_json::json!({}),
        }],
    )
    .unwrap();
    // The MCP snapshot the tools page reads is the daemon's redacted view; seed
    // the dialog's snapshot with the configured "docs" server (as a fresh
    // daemon snapshot would deliver it) so the cached tool inventory renders.
    d.mcp_config = cfg;
    d.mcp_cache_dir = Some(cache_dir);

    let cached = tools_page_lines(&d).join("\n");
    assert!(cached.contains("docs/lookup"), "{cached}");
    assert!(cached.contains("Find docs"), "{cached}");

    set_tools_cursor_to_label(&mut d, "docs/lookup");
    d.handle_key(press(KeyCode::Enter));
    match d.test_page() {
        TestPageRef::Tools(p) => {
            assert!(p.editing.is_none());
            assert_eq!(p.status.as_deref(), Some("read-only inventory row"));
        }
        other => panic!("expected Tools, got {other:?}"),
    }

    set_tools_cursor_to_label(&mut d, "configure in MCP ->");
    d.handle_key(press(KeyCode::Enter));
    assert!(matches!(d.test_page(), TestPageRef::Mcp(_)));
}

fn tools_page_rendered(d: &SettingsDialog) -> String {
    let p = match d.test_page() {
        TestPageRef::Tools(p) => p,
        other => panic!("expected Tools, got {other:?}"),
    };
    d.build_tools_page_lines(80, p)
        .into_iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|s| s.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The web-tools API key is owner-remoted (`PutProviderCredential`): the field
/// masks the pasted value, the daemon persists it, and the settings client
/// never reads its bytes back. `save_web_api_key` blocks on the ambient
/// runtime, so this test runs under a multi-thread runtime with the promoted
/// in-process daemon; persistence is verified through the daemon's redacted
/// owner inventory (a local `credentials.json` is never written).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tools_page_web_key_entry_persists_and_renders_masked() {
    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolated_cockpit_home_async().await;
    let _daemon = cockpit_core::daemon::enable_in_process_auto_promote_with_production_config();
    // Boot the in-process daemon once, up front, so its canonical context is
    // registered before anything else touches it. Rendering the tools page
    // spawns background secret-inventory refresh tasks that also call
    // `settings_daemon_client()`; without priming, that spawn can race the
    // owner-remoted save's own boot and split-brain into two in-memory daemon
    // DBs (the save lands in one, the verification reads the other, empty).
    let lifecycle = crate::tui::settings::test_lifecycle_client();
    crate::tui::settings::settings_daemon_client(&lifecycle)
        .await
        .expect("prime in-process settings daemon");
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);

    set_tools_cursor_to_label(&mut d, "api key");
    d.handle_key(press(KeyCode::Enter)); // key field
    d.paste("fc-secret-value");

    let rendered = tools_page_rendered(&d);
    assert!(rendered.contains(secret_display::MASKED_VALUE));
    assert!(!rendered.contains("fc-secret-value"));

    d.handle_key(press(KeyCode::Enter)); // owner-remoted persist

    // Persistence is owner-remoted: the key must land in the daemon vault as a
    // redacted provider credential record — never a local credentials.json —
    // and the settings client never reads its bytes back. Verify through the
    // same redacted owner inventory the production read path consults.
    assert!(
        !tmp.path().join("credentials.json").exists(),
        "web-key save must persist through the owner vault, not credentials.json"
    );
    let lifecycle = crate::tui::settings::test_lifecycle_client();
    let client = crate::tui::settings::settings_daemon_client(&lifecycle)
        .await
        .expect("settings daemon client");
    let response = client
        .request(Request::ListSecretInventory {
            cursor: None,
            limit: Some(cockpit_proto::MAX_OWNER_INVENTORY_PAGE_ENTRIES as u16),
        })
        .await
        .expect("owner inventory transport")
        .expect("owner inventory response");
    let Response::SecretInventory { entries, .. } = response else {
        panic!("unexpected owner inventory response");
    };
    assert!(
        entries.iter().any(|entry| entry.name == "firecrawl"
            && entry.kind == cockpit_proto::SecretInventoryKind::CredentialRecord),
        "owner vault must hold the firecrawl web-key credential: {entries:?}"
    );
    let wire = serde_json::to_string(&entries).expect("inventory serializes");
    assert!(
        !wire.contains("fc-secret-value"),
        "owner inventory must not leak the web-key bytes"
    );

    // And the editor still never displays the raw bytes.
    let rendered = tools_page_rendered(&d);
    assert!(!rendered.contains("fc-secret-value"));
}

#[test]
fn tools_page_firecrawl_base_url_validates_and_round_trips() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);

    set_tools_cursor_to_label(&mut d, "base url");
    d.handle_key(press(KeyCode::Enter));
    d.paste("not-a-url");
    d.handle_key(press(KeyCode::Enter));
    assert!(matches!(d.test_page(), TestPageRef::Tools(p) if p.editing.is_some()));

    if let TestPageMut::Tools(p) = d.test_page_mut() {
        p.buf = crate::tui::textfield::TextField::new("https://firecrawl.local");
    }
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(
        d.extended.web.firecrawl_base_url.as_deref(),
        Some("https://firecrawl.local")
    );
}

#[test]
fn tools_page_custom_commands_edit_typed_fields() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);
    d.extended.web.provider = cockpit_config::extended::WebProvider::Custom;

    set_tools_cursor_to_label(&mut d, "webfetch");
    d.handle_key(press(KeyCode::Enter)); // fetch command
    d.paste("fetch-cli {url}");
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(
        d.extended.web.custom.fetch_command.as_deref(),
        Some("fetch-cli {url}")
    );

    set_tools_cursor_to_label(&mut d, "websearch");
    d.handle_key(press(KeyCode::Enter)); // search command
    d.paste("search-cli {query}");
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(
        d.extended.web.custom.search_command.as_deref(),
        Some("search-cli {query}")
    );
}

/// Move a category page's cursor onto its reset button row (the last
/// selectable row).
fn move_to_reset_row(d: &mut SettingsDialog) {
    let target = match d.test_page() {
        TestPageRef::Category(p) => p.cursor_of_reset().expect("category has a reset button"),
        _ => panic!("not on a category page"),
    };
    if let TestPageMut::Category(p) = d.test_page_mut() {
        p.cursor = target;
    }
}

#[test]
fn interface_reset_restores_display_toggles_but_preserves_other_fields() {
    use cockpit_config::extended::{ThinkingDisplay, TuiConfig, VimModeSetting};
    use std::path::PathBuf;
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_root_node(&mut d, "Interface");

    // Mutate display toggles away from their defaults.
    d.extended.tui.vim_mode = VimModeSetting::Disabled;
    d.extended.tui.thinking = ThinkingDisplay::Verbose;
    d.extended.tui.render_agent_markdown = false;
    d.extended.tui.render_user_markdown = true;
    d.extended.tui.mouse_capture = false;
    d.extended.tui.rich_text_copy = false;
    d.extended.tui.use_emojis = true;
    d.extended.tui.caffeinate_display_awake = true;
    // Set NON-display fields the Interface reset must preserve.
    d.extended.utility_model = Some("openai:gpt-tiny".into());
    d.extended.name = Some("Ada".into());
    d.extended.packages_directory = Some(PathBuf::from("/tmp/pkgs"));
    d.extended.agent_guidance_files = vec!["MINE.md".into()];

    move_to_reset_row(&mut d);
    d.handle_key(press(KeyCode::Enter)); // arm
    match d.test_page() {
        TestPageRef::Category(p) => assert!(p.reset.is_pending()),
        other => panic!("expected Category, got {other:?}"),
    }
    // Arming must not change anything.
    assert_eq!(d.extended.tui.vim_mode, VimModeSetting::Disabled);

    d.handle_key(press(KeyCode::Enter)); // apply
    match d.test_page() {
        TestPageRef::Category(p) => {
            assert!(!p.reset.is_pending(), "applying disarms");
            assert_eq!(
                p.pending_mouse_capture,
                Some(TuiConfig::default().mouse_capture),
                "reset signals the App to reconcile mouse capture"
            );
        }
        other => panic!("expected Category, got {other:?}"),
    }

    let def = TuiConfig::default();
    assert_eq!(d.extended.tui.vim_mode, def.vim_mode);
    assert_eq!(d.extended.tui.thinking, def.thinking);
    assert_eq!(
        d.extended.tui.render_agent_markdown,
        def.render_agent_markdown
    );
    assert_eq!(
        d.extended.tui.render_user_markdown,
        def.render_user_markdown
    );
    assert_eq!(d.extended.tui.mouse_capture, def.mouse_capture);
    assert_eq!(d.extended.tui.rich_text_copy, def.rich_text_copy);
    assert_eq!(d.extended.tui.use_emojis, def.use_emojis);
    assert_eq!(
        d.extended.tui.caffeinate_display_awake,
        def.caffeinate_display_awake
    );

    // Non-display fields preserved.
    assert_eq!(d.extended.utility_model.as_deref(), Some("openai:gpt-tiny"));
    assert_eq!(d.extended.name.as_deref(), Some("Ada"));
    assert_eq!(
        d.extended.packages_directory,
        Some(PathBuf::from("/tmp/pkgs"))
    );
    assert_eq!(d.extended.agent_guidance_files, vec!["MINE.md".to_string()]);

    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert_eq!(reloaded.tui.vim_mode, def.vim_mode);
    assert_eq!(reloaded.utility_model.as_deref(), Some("openai:gpt-tiny"));
    assert_eq!(reloaded.name.as_deref(), Some("Ada"));
}

#[test]
fn privacy_reset_restores_knobs_but_preserves_redaction_content() {
    use cockpit_config::extended::{ExtendedConfig, InjectionThreshold};
    use std::path::PathBuf;

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_root_node(&mut d, "Privacy & Safety");

    d.extended.redact.enabled = false;
    d.extended.redact.scan_environment = false;
    d.extended.redact.scan_dotenv = false;
    d.extended.redact.scan_ssh_keys = false;
    d.extended.redact.ssh_key_dir = Some(PathBuf::from("/tmp/custom-ssh"));
    d.extended.redact.min_secret_length = 42;
    d.extended.redact.placeholder = "MASKED".into();
    d.extended.prompt_injection_guard.threshold = InjectionThreshold::Low;
    d.extended.prompt_injection_guard.check_prompt = Some("custom check".into());
    d.extended.prompt_injection_guard.model = Some("openai:guard".into());
    d.extended.allow_remote_config = true;

    d.extended.redact.dotenv_patterns = vec![".env.secret".into(), "config/*.env".into()];
    d.extended.redact.extra_dotenv_paths =
        vec![PathBuf::from("/secure/app.env"), PathBuf::from("local.env")];
    d.extended.redact.denylist = vec!["must-redact".into(), "also-redact".into()];
    d.extended.redact.allowlist = vec!["SAFE_ENV".into(), "PUBLIC_TOKEN".into()];
    d.extended.gitignore_allow = vec!["fixtures/secrets.env".into(), "docs/*.md".into()];

    move_to_reset_row(&mut d);
    d.handle_key(press(KeyCode::Enter)); // arm
    d.handle_key(press(KeyCode::Enter)); // apply

    let def = ExtendedConfig::default();
    assert_eq!(d.extended.redact.enabled, def.redact.enabled);
    assert_eq!(
        d.extended.redact.scan_environment,
        def.redact.scan_environment
    );
    assert_eq!(d.extended.redact.scan_dotenv, def.redact.scan_dotenv);
    assert_eq!(d.extended.redact.scan_ssh_keys, def.redact.scan_ssh_keys);
    assert_eq!(d.extended.redact.ssh_key_dir, def.redact.ssh_key_dir);
    assert_eq!(
        d.extended.redact.min_secret_length,
        def.redact.min_secret_length
    );
    assert_eq!(d.extended.redact.placeholder, def.redact.placeholder);
    assert_eq!(
        d.extended.prompt_injection_guard.threshold,
        def.prompt_injection_guard.threshold
    );
    assert_eq!(d.extended.prompt_injection_guard.check_prompt, None);
    assert_eq!(d.extended.prompt_injection_guard.model, None);
    assert!(!d.extended.allow_remote_config);

    assert_eq!(
        d.extended.redact.dotenv_patterns,
        vec![".env.secret".to_string(), "config/*.env".to_string()]
    );
    assert_eq!(
        d.extended.redact.extra_dotenv_paths,
        vec![PathBuf::from("/secure/app.env"), PathBuf::from("local.env")]
    );
    assert_eq!(
        resolved_denylist(&d),
        vec!["must-redact".to_string(), "also-redact".to_string()]
    );
    assert_eq!(
        d.extended.redact.allowlist,
        vec!["SAFE_ENV".to_string(), "PUBLIC_TOKEN".to_string()]
    );
    assert_eq!(
        d.extended.gitignore_allow,
        vec!["fixtures/secrets.env".to_string(), "docs/*.md".to_string()]
    );

    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert_eq!(reloaded.redact.denylist, resolved_denylist(&d));
    assert_eq!(reloaded.redact.allowlist, d.extended.redact.allowlist);
    assert_eq!(reloaded.gitignore_allow, d.extended.gitignore_allow);
    assert!(!reloaded.allow_remote_config);
}

#[test]
fn category_reset_pending_cancelled_by_navigation() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    enter_root_node(&mut d, "Interface");
    move_to_reset_row(&mut d);
    d.handle_key(press(KeyCode::Enter)); // arm
    match d.test_page() {
        TestPageRef::Category(p) => assert!(p.reset.is_pending()),
        other => panic!("expected Category, got {other:?}"),
    }
    d.handle_key(press(KeyCode::Up)); // navigate away
    match d.test_page() {
        TestPageRef::Category(p) => assert!(!p.reset.is_pending(), "navigation disarms reset"),
        other => panic!("expected Category, got {other:?}"),
    }
}

#[test]
fn runtime_sandbox_policy_reaches_settings_dependency_context() {
    let tmp = TempDir::new().unwrap();
    let mut dialog = Dialog::Settings(Box::new(fresh_dialog(&tmp)));
    dialog.set_runtime_sandbox_enabled(false);
    let Dialog::Settings(settings) = dialog else {
        unreachable!()
    };
    assert!(!settings.cx.sandbox_enabled);
}

#[test]
fn durable_settings_mutations_retain_unknown_settlement_until_receipt() {
    let source = include_str!("mod.rs");
    assert!(source.contains("PendingSettingsOperation::SettlementQuery"));
    assert!(source.contains("Request::GetLocalOperationSettlement"));
    assert!(source.contains("SettingsDaemonEffectWork::SettlementQuery"));
    assert!(source.contains("local operation settlement query timed out"));
    assert!(source.contains("operation settlement is unknown"));
    assert!(source.contains("authority_operation_pending"));
    assert!(source.contains("pending_settlement_kind"));
    assert!(source.contains("valid_local_settlement_hash"));
    assert!(source.contains("operation was authoritatively rejected"));
    assert!(source.contains("operation was authoritatively cancelled"));
}

#[test]
fn oauth_and_project_receipts_are_bound_to_exact_authority_targets() {
    let source = include_str!("mod.rs");
    let mcp = include_str!("mcp_page.rs");
    let providers = include_str!("providers/mod.rs");

    assert!(source.contains("expected_request_hash"));
    assert!(source.contains("request_hash == expected_request_hash"));
    assert!(source.contains("owner_root == project_root"));
    assert!(mcp.contains("local_receipt_request_hash"));
    assert!(providers.contains("canonical_project_root"));
    assert!(source.contains("client_operation_id: client_operation_id.clone()"));
    assert!(source.contains("settings commit settlement is unknown"));
    assert!(source.contains("typed settings commit remains unsettled"));
    assert!(mcp.contains("expected_consumed_revision"));
    assert!(mcp.contains("expected_result_revision"));
    assert!(source.contains("sanitized_intent_hash"));
    assert!(source.contains("returned_intent_hash == mutation_intent_hash"));
    assert!(source.contains("mutation_intent_hash == expected_request_hash"));
    assert!(mcp.contains("expected_request_intent_hash"));
    assert!(source.contains("provider_view_matches_mutation"));
}
