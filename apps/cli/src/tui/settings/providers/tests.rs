use super::*;
use crate::config::providers::ProvidersConfig;
use crate::config::providers::{ConfigDoc, ProviderEntry};
use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
use std::collections::BTreeMap;

fn provider_with_models(models: Vec<ModelEntry>) -> ProviderEntry {
    ProviderEntry {
        url: "https://api.example.com/v1".to_string(),
        models,
        ..Default::default()
    }
}

fn model(id: &str, manual: bool) -> ModelEntry {
    ModelEntry {
        id: id.to_string(),
        manual,
        ..Default::default()
    }
}

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn dialog_with_config(config: ProvidersConfig) -> (tempfile::TempDir, SettingsDialog) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ConfigDoc::load(&path).unwrap();
    doc.write(&config).unwrap();
    let dialog = SettingsDialog::open(path);
    (tmp, dialog)
}

fn break_config_saving(dialog: &SettingsDialog) {
    if let Some(parent) = dialog.config_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&dialog.config_path, "[").unwrap();
}

fn load_provider(path: &std::path::Path, id: &str) -> ProviderEntry {
    ConfigDoc::load(path).unwrap().providers().providers[id].clone()
}

fn replaced_provider(nav: &Nav) -> &ProvidersPage {
    let Nav::Replace(page) = nav else {
        panic!("expected replace nav");
    };
    page.downcast_ref::<ProvidersPage>()
        .expect("expected providers page replacement")
}

fn one_provider_config(policy: Option<OnUnlistedModelsFetch>) -> ProvidersConfig {
    let mut providers = BTreeMap::new();
    providers.insert(
        "p".to_string(),
        provider_with_models(vec![model("stale", false), model("current", false)]),
    );
    ProvidersConfig {
        providers,
        on_unlisted_models_fetch: policy,
        ..Default::default()
    }
}

fn line_text(line: &Line<'static>) -> String {
    line.spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect()
}

fn rendered_text(lines: &[Line<'static>]) -> String {
    lines.iter().map(line_text).collect::<Vec<_>>().join("\n")
}

fn option_row_count(rendered: &str) -> usize {
    rendered.lines().filter(|line| line.contains('[')).count()
}

#[test]
fn single_fetch_error_is_redacted_in_status_and_saved_state() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert(
        "p".into(),
        provider_with_models(vec![model("existing", true)]),
    );
    let (_tmp, mut dialog) = dialog_with_config(cfg);
    let entry = dialog.config.providers["p"].clone();
    dialog.set_test_page(Page::Providers(ProvidersPage::Edit(EditState::new(
        "p".into(),
        entry,
    ))));

    let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";
    dialog.apply_fetch_result(
        "p",
        Err(format!("fetch failed with Authorization: Bearer {secret}")),
    );

    let status = match dialog.test_page() {
        TestPageRef::Providers(ProvidersPage::Edit(s)) => s.status.as_deref().unwrap_or(""),
        other => panic!("expected Edit page, got {other:?}"),
    };
    assert!(!status.contains(secret), "status leaked secret: {status}");
    let reason = dialog.config.providers["p"]
        .last_model_fetch
        .as_ref()
        .and_then(|status| status.reason.as_deref())
        .unwrap_or("");
    assert!(
        !reason.contains(secret),
        "saved reason leaked secret: {reason}"
    );
}

#[test]
fn grok_oauth_template_materializes_oauth_credential_ref() {
    let template = templates::template_by_id("grok-oauth").unwrap();
    let mut state = AddState::new();
    state.id_field.set("grok-oauth");
    state.url_field.set(template.url);

    let entry = provider_entry_from_add(&state, template, Vec::new());

    assert_eq!(entry.auth, Some(AuthKind::OAuth));
    assert_eq!(
        entry.credential_ref.as_deref(),
        Some(crate::auth::xai_oauth::CREDENTIAL_KEY)
    );
    assert!(entry.headers.is_empty());
    assert_eq!(entry.wire_api, WireApi::Responses);
}

#[test]
fn codex_oauth_template_materializes_oauth_credential_ref() {
    let template = templates::template_by_id("codex-oauth").unwrap();
    let mut state = AddState::new();
    state.id_field.set("codex-oauth");
    state.url_field.set(template.url);

    let entry = provider_entry_from_add(&state, template, Vec::new());

    assert_eq!(entry.auth, Some(AuthKind::OAuth));
    assert_eq!(
        entry.credential_ref.as_deref(),
        Some(crate::auth::codex_oauth::CREDENTIAL_KEY)
    );
    assert!(entry.headers.is_empty());
    assert_eq!(entry.wire_api, WireApi::Responses);
}

#[test]
fn header_display_masks_literal_authorization_secret() {
    let shown = display_header_value("Authorization", "Bearer sk-abcdef123456");
    assert_eq!(shown, "Bearer ...3456");
    assert!(!shown.contains("sk-abcdef123456"));
}

#[test]
fn header_display_keeps_env_only_authorization_visible() {
    assert_eq!(
        display_header_value("Authorization", "Bearer $OPENAI_API_KEY"),
        "Bearer $OPENAI_API_KEY"
    );
}

#[test]
fn header_display_masks_mixed_env_and_literal_material() {
    let shown = display_header_value("Authorization", "Bearer $OPENAI_API_KEY literal123456");
    assert_eq!(shown, "Bearer ...3456");
    assert!(!shown.contains("$OPENAI_API_KEY"));
    assert!(!shown.contains("literal123456"));
}

#[test]
fn header_display_masks_short_sensitive_header_literals() {
    let shown = display_header_value("X-API-Key", "short");
    assert_eq!(shown, "...hort");
}

#[test]
fn header_display_masks_common_sensitive_header_names() {
    let shown = display_header_value("OpenAI-Organization", "org-abcdef123456");
    assert_eq!(shown, "...3456");
    assert!(!shown.contains("org-abcdef123456"));
}

#[test]
fn header_editor_list_masks_values_but_keeps_env_refs_visible() {
    let editor = HeaderEditor::new(
        vec![
            HeaderSpec {
                name: "Authorization".to_string(),
                value: "Bearer sk-abcdef123456".to_string(),
            },
            HeaderSpec {
                name: "Authorization".to_string(),
                value: "Bearer $OPENAI_API_KEY".to_string(),
            },
        ],
        false,
    );
    let mut lines = Vec::new();
    render_header_editor(&mut lines, &editor);
    let rendered = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

    assert!(rendered.contains("Bearer ...3456"), "{rendered}");
    assert!(!rendered.contains("sk-abcdef123456"), "{rendered}");
    assert!(rendered.contains("Bearer $OPENAI_API_KEY"), "{rendered}");
}

#[test]
fn header_editor_list_keeps_secret_refs_visible() {
    let editor = HeaderEditor::new(
        vec![HeaderSpec {
            name: "Authorization".to_string(),
            value: "Bearer $secret:openai".to_string(),
        }],
        false,
    );
    let mut lines = Vec::new();
    render_header_editor(&mut lines, &editor);
    let rendered = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

    assert!(rendered.contains("Bearer $secret:openai"), "{rendered}");
}

#[test]
fn literal_key_entry_writes_secret_ref() {
    let (tmp, mut dialog) = dialog_with_config(one_provider_config(None));
    let store_path = tmp.path().join("state/cockpit/credentials.json");
    dialog.credential_store_path = Some(store_path.clone());
    dialog.config.providers.get_mut("p").unwrap().headers = vec![HeaderSpec {
        name: "Authorization".into(),
        value: "Bearer sk-provider-secret-abcdefghijklmnopqrstuvwxyz".into(),
    }];

    dialog.save_config().unwrap();

    let saved = load_provider(&tmp.path().join("config.json"), "p");
    assert_eq!(saved.headers[0].value, "$secret:p");
    let provider_raw = std::fs::read_to_string(tmp.path().join("providers/p.json")).unwrap();
    assert!(!provider_raw.contains("sk-provider-secret-abcdefghijklmnopqrstuvwxyz"));
    let store = crate::credentials::CredentialStore::open(store_path.clone()).unwrap();
    assert_eq!(
        store.named_secret("p"),
        Some("Bearer sk-provider-secret-abcdefghijklmnopqrstuvwxyz")
    );
    let notice = dialog.last_secret_notice.as_deref().unwrap();
    assert!(notice.contains(&store_path.display().to_string()));
    assert!(!notice.contains("sk-provider-secret-abcdefghijklmnopqrstuvwxyz"));
}

#[test]
fn header_delete_requires_second_press_on_same_row() {
    let mut editor = HeaderEditor::new(
        vec![
            HeaderSpec {
                name: "X-One".to_string(),
                value: "1".to_string(),
            },
            HeaderSpec {
                name: "X-Two".to_string(),
                value: "2".to_string(),
            },
        ],
        false,
    );

    assert!(matches!(
        editor.handle_key(press(KeyCode::Char('d'))),
        HeaderResult::Stay
    ));
    assert_eq!(editor.rows().len(), 2, "first press only arms");
    assert!(editor.delete.is_pending_for(0));
    assert!(editor.status.as_deref().unwrap_or("").contains("X-One"));

    editor.handle_key(press(KeyCode::Down));
    assert!(!editor.delete.is_pending_for(0), "navigation disarms");
    editor.handle_key(press(KeyCode::Char('d')));
    assert_eq!(editor.rows().len(), 2, "fresh first press on row 1 arms");
    assert!(editor.delete.is_pending_for(1));

    editor.handle_key(press(KeyCode::Char('d')));
    assert_eq!(editor.rows().len(), 1, "second press deletes row 1");
    assert_eq!(editor.rows()[0].name, "X-One");
}

/// A Copilot-shaped provider (detected by URL) gets the "Copilot auth"
/// row in its Edit menu; a generic provider does not. The action list
/// is the single source of truth render and key handling share, so
/// asserting on it covers both.
#[test]
fn edit_menu_copilot_auth_row_only_for_copilot_providers() {
    let copilot = ProviderEntry {
        url: "https://api.githubcopilot.com".to_string(),
        ..Default::default()
    };
    let actions = edit_menu_actions("my-copilot", &copilot);
    assert!(
        actions.contains(&EditAction::CopilotAuth),
        "Copilot-shaped provider must expose the Copilot-auth row"
    );

    let generic = ProviderEntry {
        url: "https://api.example.com/v1".to_string(),
        ..Default::default()
    };
    let generic_actions = edit_menu_actions("openai-compatible", &generic);
    assert!(
        !generic_actions.contains(&EditAction::CopilotAuth),
        "generic provider must not expose the Copilot-auth row"
    );
    // The conditional row is the only difference in menu length.
    assert_eq!(actions.len(), generic_actions.len() + 1);
}

#[test]
fn provider_settings_summary_surfaces_timeout_values() {
    let provider = ProviderEntry {
        url: "https://api.example.com/v1".to_string(),
        timeout: crate::config::providers::TimeoutConfig {
            ttft_secs: 240,
            idle_secs: 180,
        },
        backup: Some(crate::config::providers::BackupConfig {
            provider: "backup".to_string(),
            model: "model".to_string(),
        }),
        ..Default::default()
    };

    let summary = provider_settings_summary(&provider);

    assert!(summary.contains("ttft 240s"));
    assert!(summary.contains("idle 180s"));
    assert!(summary.contains("backup set"));
}

#[test]
fn model_editor_enter_hints_match_selected_row_actions() {
    let mut editor = ModelEditor::new(None, vec![model("fetched", false), model("manual", true)]);

    editor.cursor = 0;
    assert_eq!(editor.selected_enter_hint(), "enter: read-only settings");

    editor.cursor = 1;
    assert_eq!(editor.selected_enter_hint(), "enter: settings");

    editor.cursor = editor.add_row_idx();
    assert_eq!(editor.selected_enter_hint(), "enter: add model");

    editor.cursor = editor.save_idx();
    assert_eq!(editor.selected_enter_hint(), "enter: save changes");
}

#[test]
fn enter_on_fetched_and_manual_model_rows_opens_settings() {
    let mut editor = ModelEditor::new(None, vec![model("fetched", false), model("manual", true)]);

    editor.cursor = 0;
    assert!(matches!(
        editor.handle_key(press(KeyCode::Enter)),
        ModelResult::OpenSettings(0)
    ));

    editor.cursor = 1;
    assert!(matches!(
        editor.handle_key(press(KeyCode::Enter)),
        ModelResult::OpenSettings(1)
    ));
}

#[test]
fn enter_on_model_action_rows_matches_hints() {
    let mut editor = ModelEditor::new(None, vec![model("manual", true)]);

    editor.cursor = editor.add_row_idx();
    assert_eq!(editor.selected_enter_hint(), "enter: add model");
    assert!(matches!(
        editor.handle_key(press(KeyCode::Enter)),
        ModelResult::Stay
    ));
    assert!(editor.is_editing());

    editor.cancel_edit();
    editor.cursor = editor.save_idx();
    assert_eq!(editor.selected_enter_hint(), "enter: save changes");
    assert!(matches!(
        editor.handle_key(press(KeyCode::Enter)),
        ModelResult::Save
    ));
}

#[test]
fn model_delete_requires_second_press_on_same_row() {
    let mut editor = ModelEditor::new(None, vec![model("fetched", false), model("manual", true)]);

    editor.handle_key(press(KeyCode::Delete));
    assert_eq!(editor.rows().len(), 2, "first press only arms");
    assert!(editor.delete.is_pending_for(0));
    assert!(editor.status.as_deref().unwrap_or("").contains("fetched"));

    editor.handle_key(press(KeyCode::Down));
    assert!(!editor.delete.is_pending_for(0), "navigation disarms");
    editor.handle_key(press(KeyCode::Delete));
    assert_eq!(editor.rows().len(), 2, "fresh first press on row 1 arms");
    assert!(editor.delete.is_pending_for(1));

    editor.handle_key(press(KeyCode::Delete));
    assert_eq!(editor.rows().len(), 1, "second press deletes row 1");
    assert_eq!(editor.rows()[0].id, "fetched");
}

#[test]
fn fetch_all_prompt_remove_drops_only_non_manual_unlisted_models() {
    let mut providers = BTreeMap::new();
    providers.insert(
        "p".to_string(),
        provider_with_models(vec![
            model("stale", false),
            model("manual-only", true),
            model("current", false),
        ]),
    );
    let (_, mut dialog) = dialog_with_config(ProvidersConfig {
        providers,
        on_unlisted_models_fetch: Some(OnUnlistedModelsFetch::Ask),
        ..Default::default()
    });
    dialog.set_test_page(Page::Providers(ProvidersPage::FetchAll(FetchAllState {
        providers: vec!["p".to_string()],
        in_flight: Vec::new(),
        finished: vec![FetchedSummary {
            provider_id: "p".to_string(),
            outcome: Ok(FetchOutcome::Models {
                models: vec![model("current", false)],
                catalog: ProviderModelCatalog::Live,
            }),
        }],
        pre_fetch_models: [(
            "p".to_string(),
            vec![
                model("stale", false),
                model("manual-only", true),
                model("current", false),
            ],
        )]
        .into_iter()
        .collect(),
        policy_resolved: false,
        cursor: 1,
        dont_ask_again: false,
        unlisted: vec![("p".to_string(), "stale".to_string())],
    })));

    let nav = {
        let (cx, page) = (&mut dialog.cx, &mut dialog.page);
        let Some(ProvidersPage::FetchAll(state)) = page.downcast_mut::<ProvidersPage>() else {
            panic!("expected fetch-all page");
        };
        cx.handle_fetch_all_key(press(KeyCode::Enter), state)
    };
    assert!(matches!(
        replaced_provider(&nav),
        ProvidersPage::List { .. }
    ));

    let ids: Vec<&str> = dialog.config.providers["p"]
        .models
        .iter()
        .map(|m| m.id.as_str())
        .collect();
    assert_eq!(ids, vec!["current", "manual-only"]);
}

#[test]
fn fetch_all_stored_remove_applies_without_prompt() {
    let (_, mut dialog) =
        dialog_with_config(one_provider_config(Some(OnUnlistedModelsFetch::Remove)));
    dialog.set_test_page(Page::Providers(ProvidersPage::FetchAll(FetchAllState {
        providers: vec!["p".to_string()],
        in_flight: Vec::new(),
        finished: vec![FetchedSummary {
            provider_id: "p".to_string(),
            outcome: Ok(FetchOutcome::Models {
                models: vec![model("current", false)],
                catalog: ProviderModelCatalog::Live,
            }),
        }],
        pre_fetch_models: [(
            "p".to_string(),
            vec![model("stale", false), model("current", false)],
        )]
        .into_iter()
        .collect(),
        policy_resolved: false,
        cursor: 0,
        dont_ask_again: false,
        unlisted: Vec::new(),
    })));

    dialog.drain_fetch_all();

    let state = match dialog.test_page() {
        TestPageRef::Providers(ProvidersPage::FetchAll(s)) => s,
        _ => panic!("expected fetch-all page"),
    };
    assert!(state.unlisted.is_empty());
    let ids: Vec<&str> = dialog.config.providers["p"]
        .models
        .iter()
        .map(|m| m.id.as_str())
        .collect();
    assert_eq!(ids, vec!["current"]);
}

#[test]
fn fetch_all_stored_keep_applies_without_prompt() {
    let (_, mut dialog) =
        dialog_with_config(one_provider_config(Some(OnUnlistedModelsFetch::Keep)));
    dialog.set_test_page(Page::Providers(ProvidersPage::FetchAll(FetchAllState {
        providers: vec!["p".to_string()],
        in_flight: Vec::new(),
        finished: vec![FetchedSummary {
            provider_id: "p".to_string(),
            outcome: Ok(FetchOutcome::Models {
                models: vec![model("current", false)],
                catalog: ProviderModelCatalog::Live,
            }),
        }],
        pre_fetch_models: [(
            "p".to_string(),
            vec![model("stale", false), model("current", false)],
        )]
        .into_iter()
        .collect(),
        policy_resolved: false,
        cursor: 0,
        dont_ask_again: false,
        unlisted: Vec::new(),
    })));

    dialog.drain_fetch_all();

    let ids: Vec<&str> = dialog.config.providers["p"]
        .models
        .iter()
        .map(|m| m.id.as_str())
        .collect();
    assert_eq!(ids, vec!["current", "stale"]);
}

#[test]
fn per_provider_refetch_prompt_remove_returns_to_edit_page() {
    let (_tmp, mut dialog) = dialog_with_config(one_provider_config(None));
    dialog.set_test_page(Page::Providers(ProvidersPage::FetchOnePrompt(
        FetchOnePromptState {
            provider_id: "p".to_string(),
            remote: vec![model("current", false)],
            catalog: ProviderModelCatalog::Live,
            pre_fetch_models: vec![model("stale", false), model("current", false)],
            unlisted: vec!["stale".to_string()],
            cursor: 1,
            dont_ask_again: false,
        },
    )));

    let nav = {
        let (cx, page) = (&mut dialog.cx, &mut dialog.page);
        let Some(ProvidersPage::FetchOnePrompt(state)) = page.downcast_mut::<ProvidersPage>()
        else {
            panic!("expected per-provider prompt page");
        };
        cx.handle_fetch_one_prompt_key(press(KeyCode::Enter), state)
    };
    assert!(matches!(replaced_provider(&nav), ProvidersPage::Edit(_)));

    let ids: Vec<&str> = dialog.config.providers["p"]
        .models
        .iter()
        .map(|m| m.id.as_str())
        .collect();
    assert_eq!(ids, vec!["current"]);
}

#[test]
fn fetch_one_prompt_save_failure_surfaces() {
    let (_tmp, mut dialog) = dialog_with_config(one_provider_config(None));
    dialog.set_test_page(Page::Providers(ProvidersPage::FetchOnePrompt(
        FetchOnePromptState {
            provider_id: "p".to_string(),
            remote: vec![model("current", false)],
            catalog: ProviderModelCatalog::Live,
            pre_fetch_models: vec![model("stale", false), model("current", false)],
            unlisted: vec!["stale".to_string()],
            cursor: 0,
            dont_ask_again: false,
        },
    )));
    break_config_saving(&dialog);

    let nav = {
        let (cx, page) = (&mut dialog.cx, &mut dialog.page);
        let Some(ProvidersPage::FetchOnePrompt(state)) = page.downcast_mut::<ProvidersPage>()
        else {
            panic!("expected per-provider prompt page");
        };
        cx.handle_fetch_one_prompt_key(press(KeyCode::Enter), state)
    };

    match replaced_provider(&nav) {
        ProvidersPage::Edit(edit) => {
            assert!(
                edit.status
                    .as_deref()
                    .is_some_and(|s| s.starts_with("save failed:")),
                "status was {:?}",
                edit.status
            );
        }
        _ => panic!("expected edit replacement"),
    }
}

#[test]
fn fetch_all_save_failure_surfaces() {
    let (_tmp, mut dialog) = dialog_with_config(one_provider_config(None));
    dialog.set_test_page(Page::Providers(ProvidersPage::FetchAll(FetchAllState {
        providers: vec!["p".to_string()],
        in_flight: Vec::new(),
        finished: vec![FetchedSummary {
            provider_id: "p".to_string(),
            outcome: Ok(FetchOutcome::Models {
                models: vec![model("current", false)],
                catalog: ProviderModelCatalog::Live,
            }),
        }],
        pre_fetch_models: [(
            "p".to_string(),
            vec![model("stale", false), model("current", false)],
        )]
        .into_iter()
        .collect(),
        policy_resolved: false,
        cursor: 0,
        dont_ask_again: false,
        unlisted: vec![("p".to_string(), "stale".to_string())],
    })));
    break_config_saving(&dialog);

    let nav = {
        let (cx, page) = (&mut dialog.cx, &mut dialog.page);
        let Some(ProvidersPage::FetchAll(state)) = page.downcast_mut::<ProvidersPage>() else {
            panic!("expected fetch-all page");
        };
        cx.handle_fetch_all_key(press(KeyCode::Enter), state)
    };

    match replaced_provider(&nav) {
        ProvidersPage::List { status, .. } => {
            assert!(
                status
                    .as_deref()
                    .is_some_and(|s| s.starts_with("save failed:")),
                "status was {status:?}"
            );
        }
        _ => panic!("expected list replacement"),
    }
}

#[test]
fn render_field_row_places_caret_at_textfield_cursor() {
    let mut field = TextField::new("alpha");
    field.handle_key(press(KeyCode::Home));
    field.handle_key(press(KeyCode::Right));
    field.handle_key(press(KeyCode::Right));
    let mut lines = Vec::new();

    render_field_row(&mut lines, "Name", &field, true);

    assert_eq!(line_text(&lines[0]), "▸ Name: al\u{E000}pha");
}

#[test]
fn edit_delete_enter_requires_second_enter_to_confirm() {
    let (_, mut dialog) = dialog_with_config(one_provider_config(None));
    let entry = dialog.config.providers["p"].clone();
    let mut state = EditState::new("p".into(), entry.clone());
    state.cursor = edit_menu_actions("p", &entry)
        .iter()
        .position(|action| matches!(action, EditAction::Delete))
        .expect("delete row");
    dialog.set_test_page(Page::Providers(ProvidersPage::Edit(state)));

    dialog.handle_key(press(KeyCode::Enter));
    assert!(dialog.config.providers.contains_key("p"));
    let TestPageRef::Providers(ProvidersPage::Edit(state)) = dialog.test_page() else {
        panic!("expected edit page");
    };
    assert!(state.delete_pending);
    assert_eq!(
        state.status.as_deref(),
        Some("press Enter again to delete + stored secrets (default); n: keep secrets")
    );

    dialog.handle_key(press(KeyCode::Enter));

    assert!(!dialog.config.providers.contains_key("p"));
    assert!(matches!(
        dialog.test_page(),
        TestPageRef::Providers(ProvidersPage::List { .. })
    ));
}

#[test]
fn edit_delete_d_requires_second_d_to_confirm() {
    let (_, mut dialog) = dialog_with_config(one_provider_config(None));
    let entry = dialog.config.providers["p"].clone();
    dialog.set_test_page(Page::Providers(ProvidersPage::Edit(EditState::new(
        "p".into(),
        entry,
    ))));

    dialog.handle_key(press(KeyCode::Char('d')));
    assert!(dialog.config.providers.contains_key("p"));
    let TestPageRef::Providers(ProvidersPage::Edit(state)) = dialog.test_page() else {
        panic!("expected edit page");
    };
    assert!(state.delete_pending);
    assert_eq!(
        state.status.as_deref(),
        Some("press d again to delete + stored secrets (default); n: keep secrets")
    );

    dialog.handle_key(press(KeyCode::Char('d')));

    assert!(!dialog.config.providers.contains_key("p"));
    assert!(matches!(
        dialog.test_page(),
        TestPageRef::Providers(ProvidersPage::List { .. })
    ));
}

#[test]
fn provider_delete_removes_its_unshared_stored_secret() {
    let mut cfg = one_provider_config(None);
    cfg.providers.get_mut("p").unwrap().headers = vec![HeaderSpec {
        name: "Authorization".into(),
        value: "$secret:p".into(),
    }];
    let (tmp, mut dialog) = dialog_with_config(cfg);
    let store_path = tmp.path().join("credentials.json");
    dialog.credential_store_path = Some(store_path.clone());
    let mut store = crate::credentials::CredentialStore::open(store_path.clone()).unwrap();
    store.set_named_secret("p", "sk-provider-secret-value");
    store.save().unwrap();

    assert_eq!(
        dialog
            .delete_provider_and_stored_secrets("p", true)
            .unwrap(),
        1
    );
    assert!(!dialog.config.providers.contains_key("p"));
    assert!(
        crate::credentials::CredentialStore::open(store_path)
            .unwrap()
            .named_secret("p")
            .is_none()
    );
}

#[test]
fn provider_delete_preserves_a_shared_stored_secret() {
    let mut cfg = one_provider_config(None);
    cfg.providers.get_mut("p").unwrap().headers = vec![HeaderSpec {
        name: "Authorization".into(),
        value: "$secret:shared".into(),
    }];
    cfg.providers.insert(
        "other".into(),
        ProviderEntry {
            headers: vec![HeaderSpec {
                name: "Authorization".into(),
                value: "$secret:shared".into(),
            }],
            ..provider_with_models(vec![])
        },
    );
    let (tmp, mut dialog) = dialog_with_config(cfg);
    let store_path = tmp.path().join("credentials.json");
    dialog.credential_store_path = Some(store_path.clone());
    let mut store = crate::credentials::CredentialStore::open(store_path.clone()).unwrap();
    store.set_named_secret("shared", "sk-provider-secret-value");
    store.save().unwrap();

    assert_eq!(
        dialog
            .delete_provider_and_stored_secrets("p", true)
            .unwrap(),
        0
    );
    assert_eq!(
        crate::credentials::CredentialStore::open(store_path)
            .unwrap()
            .named_secret("shared"),
        Some("sk-provider-secret-value")
    );
}

#[test]
fn provider_delete_offer_can_keep_an_unshared_stored_secret() {
    let mut cfg = one_provider_config(None);
    cfg.providers.get_mut("p").unwrap().headers = vec![HeaderSpec {
        name: "Authorization".into(),
        value: "$secret:p".into(),
    }];
    let (tmp, mut dialog) = dialog_with_config(cfg);
    let store_path = tmp.path().join("credentials.json");
    dialog.credential_store_path = Some(store_path.clone());
    let mut store = crate::credentials::CredentialStore::open(store_path.clone()).unwrap();
    store.set_named_secret("p", "sk-provider-secret-value");
    store.save().unwrap();
    let entry = dialog.config.providers["p"].clone();
    dialog.set_test_page(Page::Providers(ProvidersPage::Edit(EditState::new(
        "p".into(),
        entry,
    ))));

    dialog.handle_key(press(KeyCode::Char('d')));
    dialog.handle_key(press(KeyCode::Char('n')));

    assert!(!dialog.config.providers.contains_key("p"));
    assert_eq!(
        crate::credentials::CredentialStore::open(store_path)
            .unwrap()
            .named_secret("p"),
        Some("sk-provider-secret-value")
    );
}

#[test]
fn favorite_toggle_status_is_unsaved() {
    let (_, mut dialog) = dialog_with_config(one_provider_config(None));
    let entry = dialog.config.providers["p"].clone();
    dialog.set_test_page(Page::Providers(ProvidersPage::Edit(EditState::new(
        "p".into(),
        entry,
    ))));

    dialog.handle_key(press(KeyCode::Char('f')));
    let TestPageRef::Providers(ProvidersPage::Edit(state)) = dialog.test_page() else {
        panic!("expected edit page");
    };
    assert_eq!(
        state.status.as_deref(),
        Some("favorite ✓ (unsaved — s to save)")
    );
    assert_eq!(state.entry.favorite, Some(true));
}

#[test]
fn q_commits_favorite_from_edit_page() {
    let (tmp, mut dialog) = dialog_with_config(one_provider_config(None));
    let entry = dialog.config.providers["p"].clone();
    dialog.set_test_page(Page::Providers(ProvidersPage::Edit(EditState::new(
        "p".into(),
        entry,
    ))));

    dialog.handle_key(press(KeyCode::Char('f')));
    assert!(dialog.handle_key(press(KeyCode::Char('q'))));

    assert_eq!(
        load_provider(&tmp.path().join("config.json"), "p").favorite,
        Some(true)
    );
}

#[test]
fn q_commit_failure_after_favorite_does_not_panic() {
    let (_tmp, mut dialog) = dialog_with_config(one_provider_config(None));
    let entry = dialog.config.providers["p"].clone();
    dialog.set_test_page(Page::Providers(ProvidersPage::Edit(EditState::new(
        "p".into(),
        entry,
    ))));
    dialog.handle_key(press(KeyCode::Char('f')));
    break_config_saving(&dialog);

    assert!(dialog.handle_key(press(KeyCode::Char('q'))));
}

#[test]
fn q_commits_headers_subpage() {
    let (tmp, mut dialog) = dialog_with_config(one_provider_config(None));
    let entry = dialog.config.providers["p"].clone();
    let parent = EditState::new("p".into(), entry);
    let editor = HeaderEditor::new(
        vec![HeaderSpec {
            name: "X-Test".into(),
            value: "one".into(),
        }],
        false,
    );
    dialog.set_test_page(Page::Providers(ProvidersPage::Headers {
        editor,
        parent: Box::new(parent),
    }));

    assert!(dialog.handle_key(press(KeyCode::Char('q'))));

    assert_eq!(
        load_provider(&tmp.path().join("config.json"), "p").headers,
        vec![HeaderSpec {
            name: "X-Test".into(),
            value: "one".into(),
        }]
    );
}

#[tokio::test]
async fn refetch_commits_staged_entry_first() {
    let (tmp, mut dialog) = dialog_with_config(one_provider_config(None));
    let entry = dialog.config.providers["p"].clone();
    dialog.set_test_page(Page::Providers(ProvidersPage::Edit(EditState::new(
        "p".into(),
        entry,
    ))));

    dialog.handle_key(press(KeyCode::Char('f')));
    dialog.handle_key(press(KeyCode::Char('r')));

    assert_eq!(
        load_provider(&tmp.path().join("config.json"), "p").favorite,
        Some(true)
    );
}

#[test]
fn refetch_result_preserves_staged_favorite() {
    let (_tmp, mut dialog) =
        dialog_with_config(one_provider_config(Some(OnUnlistedModelsFetch::Keep)));
    let entry = dialog.config.providers["p"].clone();
    let mut edit = EditState::new("p".into(), entry);
    edit.entry.favorite = Some(true);
    dialog.set_test_page(Page::Providers(ProvidersPage::Edit(edit)));

    dialog.apply_fetch_result(
        "p",
        Ok(FetchOutcome::Models {
            models: vec![model("new", false)],
            catalog: ProviderModelCatalog::Live,
        }),
    );

    let TestPageRef::Providers(ProvidersPage::Edit(state)) = dialog.test_page() else {
        panic!("expected edit page");
    };
    assert_eq!(state.entry.favorite, Some(true));
    assert_eq!(
        state
            .entry
            .models
            .iter()
            .map(|m| m.id.as_str())
            .collect::<Vec<_>>(),
        vec!["new", "stale", "current"]
    );
}

#[test]
fn refetch_result_marks_codex_fallback_catalog_active() {
    let (_tmp, mut dialog) =
        dialog_with_config(one_provider_config(Some(OnUnlistedModelsFetch::Keep)));
    let entry = dialog.config.providers["p"].clone();
    dialog.set_test_page(Page::Providers(ProvidersPage::Edit(EditState::new(
        "p".into(),
        entry,
    ))));

    dialog.apply_fetch_result(
        "p",
        Ok(FetchOutcome::Models {
            models: vec![model("gpt-5.5", false)],
            catalog: ProviderModelCatalog::CodexFallback,
        }),
    );

    let provider = &dialog.config.providers["p"];
    assert_eq!(provider.model_catalog, ProviderModelCatalog::CodexFallback);
    let TestPageRef::Providers(ProvidersPage::Edit(state)) = dialog.test_page() else {
        panic!("expected edit page");
    };
    assert_eq!(
        state.entry.model_catalog,
        ProviderModelCatalog::CodexFallback
    );
    assert!(
        state
            .status
            .as_deref()
            .is_some_and(|s| s.contains("fallback Codex catalog"))
    );
}

#[test]
fn refetch_result_with_fallback_available_opens_explicit_prompt() {
    let (_tmp, mut dialog) =
        dialog_with_config(one_provider_config(Some(OnUnlistedModelsFetch::Keep)));
    let entry = dialog.config.providers["p"].clone();
    dialog.set_test_page(Page::Providers(ProvidersPage::Edit(EditState::new(
        "p".into(),
        entry,
    ))));

    dialog.apply_fetch_result(
        "p",
        Ok(FetchOutcome::FallbackAvailable {
            models: vec![model("fallback", false)],
            catalog: ProviderModelCatalog::CodexFallback,
            reason:
                "GET /models returned 500. Bearer sk-test-token-abcdefghijklmnopqrstuvwxyz123456"
                    .into(),
        }),
    );

    let TestPageRef::Providers(ProvidersPage::FetchFallbackPrompt(state)) = dialog.test_page()
    else {
        panic!("expected fallback prompt");
    };
    assert_eq!(state.provider_id, "p");
    assert!(state.reason.contains("returned 500"));
    assert!(state.reason.contains("[redacted]"));
    assert!(!state.reason.contains("sk-test-token"));
    let provider = &dialog.config.providers["p"];
    assert_eq!(provider.model_catalog, ProviderModelCatalog::Live);
    assert_eq!(
        provider
            .models
            .iter()
            .map(|m| m.id.as_str())
            .collect::<Vec<_>>(),
        vec!["stale", "current"]
    );
}

#[test]
fn fetch_fallback_prompt_use_fallback_records_degraded_status() {
    let (_tmp, mut dialog) =
        dialog_with_config(one_provider_config(Some(OnUnlistedModelsFetch::Keep)));
    dialog.set_test_page(Page::Providers(ProvidersPage::FetchFallbackPrompt(
        FetchFallbackPromptState {
            provider_id: "p".to_string(),
            models: vec![model("fallback", false)],
            catalog: ProviderModelCatalog::CodexFallback,
            reason:
                "GET /models returned 500. Bearer sk-test-token-abcdefghijklmnopqrstuvwxyz123456"
                    .into(),
            cursor: 2,
        },
    )));

    let nav = {
        let (cx, page) = (&mut dialog.cx, &mut dialog.page);
        let Some(ProvidersPage::FetchFallbackPrompt(state)) = page.downcast_mut::<ProvidersPage>()
        else {
            panic!("expected fallback prompt");
        };
        cx.handle_fetch_fallback_prompt_key(press(KeyCode::Enter), state)
    };

    assert!(matches!(replaced_provider(&nav), ProvidersPage::Edit(_)));
    let provider = &dialog.config.providers["p"];
    assert_eq!(provider.model_catalog, ProviderModelCatalog::CodexFallback);
    assert_eq!(
        provider
            .models
            .iter()
            .map(|m| m.id.as_str())
            .collect::<Vec<_>>(),
        vec!["fallback", "stale", "current"]
    );
    let status = provider.last_model_fetch.as_ref().unwrap();
    assert_eq!(
        status.status,
        crate::config::providers::ModelFetchStatusKind::Fallback
    );
    assert_eq!(
        status.source,
        crate::config::providers::ModelFetchSource::Fallback
    );
    let reason = status.reason.as_ref().unwrap();
    assert!(reason.contains("returned 500"));
    assert!(reason.contains("[redacted]"));
    assert!(!reason.contains("sk-test-token"));
}

#[test]
fn refetch_summary_names_empty_codex_fallback_catalog() {
    let mut entry = ProviderEntry {
        models: vec![
            model("gpt-5.5", false),
            model("gpt-5.4", false),
            model("gpt-5.4-mini", false),
        ],
        model_catalog: ProviderModelCatalog::CodexFallback,
        ..ProviderEntry::default()
    };
    entry.mark_model_fetch_fallback(
        "https://chatgpt.com/backend-api/codex/models?client_version=0.0.0 returned an empty model list (status 200 OK)",
    );

    let summary = refetch_summary(&entry);

    assert!(summary.contains("fallback catalog active (3 model(s))"));
    assert!(summary.contains("live /models returned empty list"));
    assert!(summary.contains("using hardcoded fallback"));
}

#[test]
fn model_fetch_status_block_renders_redacted_status_details() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-06-19T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let entry = ProviderEntry {
        models: vec![model("gpt-5-mini", false)],
        models_fetched_at: Some(
            chrono::DateTime::parse_from_rfc3339("2026-06-19T11:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        ),
        last_model_fetch: Some(crate::config::providers::ModelFetchStatus {
            status: crate::config::providers::ModelFetchStatusKind::FailedKeptExisting,
            at: now,
            source: crate::config::providers::ModelFetchSource::Live,
            reason: Some(
                "GET /models returned 500 Authorization Bearer sk-test-token-abcdefghijklmnopqrstuvwxyz123456"
                    .to_string(),
            ),
        }),
        ..ProviderEntry::default()
    };
    let mut lines = Vec::new();

    render_model_fetch_status_block(&mut lines, &entry, now);
    let rendered = rendered_text(&lines);

    assert!(rendered.contains("Catalog status:"));
    assert!(rendered.contains("state:   Preserved"));
    assert!(rendered.contains("count:   1"));
    assert!(rendered.contains("fetched: 1 hour ago"));
    assert!(rendered.contains("[redacted]"));
    assert!(!rendered.contains("sk-test-token"));
}

#[test]
fn model_fetch_status_block_uses_never_and_dash_for_missing_fetch() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-06-19T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let entry = ProviderEntry::default();
    let mut lines = Vec::new();

    render_model_fetch_status_block(&mut lines, &entry, now);
    let rendered = rendered_text(&lines);

    assert!(rendered.contains("state:   Live"));
    assert!(rendered.contains("count:   0"));
    assert!(rendered.contains("fetched: never"));
    assert!(rendered.contains("reason:  —"));
}

#[test]
fn apply_fetch_result_save_failure_surfaces() {
    let (_tmp, mut dialog) =
        dialog_with_config(one_provider_config(Some(OnUnlistedModelsFetch::Keep)));
    let entry = dialog.config.providers["p"].clone();
    dialog.set_test_page(Page::Providers(ProvidersPage::Edit(EditState::new(
        "p".into(),
        entry,
    ))));
    break_config_saving(&dialog);

    dialog.apply_fetch_result(
        "p",
        Ok(FetchOutcome::Models {
            models: vec![model("new", false)],
            catalog: ProviderModelCatalog::Live,
        }),
    );

    let TestPageRef::Providers(ProvidersPage::Edit(state)) = dialog.test_page() else {
        panic!("expected edit page");
    };
    assert!(
        state
            .status
            .as_deref()
            .is_some_and(|s| s.starts_with("save failed:")),
        "status was {:?}",
        state.status
    );
}

#[test]
fn copy_oauth_url_reports_success_error_and_missing_url() {
    let mut status = None;
    let copied = crate::clipboard::CopyOutcome {
        osc52_written: true,
        local_clipboard_written: false,
    };
    copy_oauth_url_with(Some("https://example.test/oauth"), &mut status, |_| {
        Ok(copied)
    });
    assert_eq!(status, Some(Ok("copied OAuth URL".to_string())));

    copy_oauth_url_with(None, &mut status, |_| Ok(copied));
    assert_eq!(status, Some(Ok("no OAuth URL yet".to_string())));

    copy_oauth_url_with(Some("https://example.test/oauth"), &mut status, |_| {
        Err(crate::clipboard::CopyError::Backend("denied".to_string()))
    });
    assert_eq!(
        status,
        Some(Err("clipboard backend error: denied".to_string()))
    );
}

static OAUTH_EFFECTS_LOG: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
static OAUTH_EFFECTS_SSH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn reset_oauth_effects(ssh: bool) {
    OAUTH_EFFECTS_SSH.store(ssh, std::sync::atomic::Ordering::SeqCst);
    OAUTH_EFFECTS_LOG.lock().unwrap().clear();
}

fn oauth_effects_log() -> Vec<String> {
    OAUTH_EFFECTS_LOG.lock().unwrap().clone()
}

fn fake_copy(value: &str) -> Result<crate::clipboard::CopyOutcome, crate::clipboard::CopyError> {
    OAUTH_EFFECTS_LOG
        .lock()
        .unwrap()
        .push(format!("copy:{value}"));
    Ok(crate::clipboard::CopyOutcome {
        osc52_written: true,
        local_clipboard_written: false,
    })
}

fn fake_open(value: &str) -> anyhow::Result<()> {
    OAUTH_EFFECTS_LOG
        .lock()
        .unwrap()
        .push(format!("open:{value}"));
    Ok(())
}

fn fake_is_ssh() -> bool {
    OAUTH_EFFECTS_SSH.load(std::sync::atomic::Ordering::SeqCst)
}

fn fake_oauth_effects() -> OAuthEffects {
    OAuthEffects {
        copy: fake_copy,
        is_ssh: fake_is_ssh,
        open: fake_open,
    }
}

#[test]
fn codex_apply_begin_queues_poll_and_uses_injected_effects() {
    reset_oauth_effects(false);
    let login =
        crate::auth::codex_oauth::DeviceLogin::for_test("https://example.test/device", "CODE-123");
    let mut state = OAuthFlowState::new_with_effects(OAuthProvider::Codex, fake_oauth_effects());
    let action = state.apply_begin(
        OAuthBeginResult::Device(Ok(login.clone())),
        fake_oauth_effects(),
    );

    assert!(state.polling);
    assert!(matches!(
        action,
        Some(OAuthFlowRequest {
            provider: OAuthProvider::Codex,
            op: OAuthFlowOp::Poll(_),
        })
    ));
    assert_eq!(
        oauth_effects_log(),
        vec![
            "copy:CODE-123".to_string(),
            "open:https://example.test/device".to_string()
        ]
    );
}

#[test]
fn codex_copy_keys_are_ssh_aware() {
    let login =
        crate::auth::codex_oauth::DeviceLogin::for_test("https://example.test/device", "CODE-123");

    reset_oauth_effects(true);
    let mut ssh_state =
        OAuthFlowState::new_with_effects(OAuthProvider::Codex, fake_oauth_effects());
    ssh_state.set_device_login_for_test(login.clone());
    handle_oauth_flow_key_with(
        press(KeyCode::Char('c')),
        &mut ssh_state,
        fake_oauth_effects(),
    );
    handle_oauth_flow_key_with(
        press(KeyCode::Char('y')),
        &mut ssh_state,
        fake_oauth_effects(),
    );
    assert_eq!(
        oauth_effects_log(),
        vec![
            "copy:https://example.test/device".to_string(),
            "copy:CODE-123".to_string()
        ]
    );

    reset_oauth_effects(false);
    let mut local_state =
        OAuthFlowState::new_with_effects(OAuthProvider::Codex, fake_oauth_effects());
    local_state.set_device_login_for_test(login);
    handle_oauth_flow_key_with(
        press(KeyCode::Char('c')),
        &mut local_state,
        fake_oauth_effects(),
    );
    handle_oauth_flow_key_with(
        press(KeyCode::Char('y')),
        &mut local_state,
        fake_oauth_effects(),
    );
    assert_eq!(
        oauth_effects_log(),
        vec![
            "copy:CODE-123".to_string(),
            "open:https://example.test/device".to_string(),
            "copy:CODE-123".to_string()
        ]
    );
}

#[test]
fn add_grok_oauth_paste_focus_reports_active_text_field() {
    let mut state = AddState::new();
    state.step = AddStep::OAuthAuth(Box::new(OAuthFlowState::new(OAuthProvider::Grok)));
    let mut page = ProvidersPage::Add(state);

    assert!(page.active_text_field().is_none());

    let ProvidersPage::Add(add) = &mut page else {
        unreachable!();
    };
    let AddStep::OAuthAuth(grok) = &mut add.step else {
        unreachable!();
    };
    grok.paste_focused = true;

    let field = page
        .active_text_field()
        .expect("manual Grok OAuth input should own paste focus");
    field.paste("callback-code");

    let ProvidersPage::Add(add) = &page else {
        unreachable!();
    };
    let AddStep::OAuthAuth(grok) = &add.step else {
        unreachable!();
    };
    assert_eq!(grok.manual_input.text(), "callback-code");
}

#[test]
fn grok_paste_focus_char_c_inserts_instead_of_copying_url() {
    let mut state = OAuthFlowState::new(OAuthProvider::Grok);
    state.paste_focused = true;
    state.set_browser_session_for_test("https://example.test/oauth");

    let (_close, action) = handle_oauth_flow_key(press(KeyCode::Char('c')), &mut state);

    assert!(action.is_none());
    assert_eq!(state.manual_input.text(), "c");
    assert_ne!(state.status, Some(Ok("copied OAuth URL".to_string())));
}

#[test]
fn grok_paste_focus_char_by_char_callback_keeps_shortcut_letters() {
    let mut state = OAuthFlowState::new(OAuthProvider::Grok);
    state.paste_focused = true;
    let callback = "http://127.0.0.1:56121/callback?code=abc123&state=s";

    for ch in callback.chars() {
        handle_oauth_flow_key(press(KeyCode::Char(ch)), &mut state);
    }

    assert_eq!(state.manual_input.text(), callback);
}

#[test]
fn codex_oauth_logged_in_renders_single_continue_row() {
    let mut state = OAuthFlowState::new(OAuthProvider::Codex);
    state.logged_in = true;
    state.status = Some(Ok("Codex OAuth login complete".to_string()));
    let mut lines = Vec::new();

    render_oauth_body(&mut lines, OAuthFlowView::OAuth(&state));
    let rendered = rendered_text(&lines);

    assert!(rendered.contains("continue"), "{rendered}");
    assert_eq!(option_row_count(&rendered), 1, "{rendered}");
    assert!(!rendered.contains("log in"), "{rendered}");
    assert!(!rendered.contains("skip / continue"), "{rendered}");
    assert!(!rendered.contains("manual paste"), "{rendered}");
}

#[test]
fn codex_oauth_logged_out_renders_start_or_poll_menu() {
    let mut state = OAuthFlowState::new(OAuthProvider::Codex);
    state.logged_in = false;
    let mut lines = Vec::new();

    render_oauth_body(&mut lines, OAuthFlowView::OAuth(&state));
    let rendered = rendered_text(&lines);
    assert!(rendered.contains("log in"), "{rendered}");
    assert!(rendered.contains("skip / continue"), "{rendered}");

    state.set_device_login_for_test(crate::auth::codex_oauth::DeviceLogin::for_test(
        "https://example.test/device",
        "ABCD-EFGH",
    ));
    lines.clear();
    render_oauth_body(&mut lines, OAuthFlowView::OAuth(&state));
    let rendered = rendered_text(&lines);
    assert!(rendered.contains("poll for approval"), "{rendered}");
    assert!(rendered.contains("skip / continue"), "{rendered}");
    assert!(!rendered.contains("[continue]"), "{rendered}");
}

#[test]
fn grok_oauth_logged_in_renders_single_continue_row() {
    let mut state = OAuthFlowState::new(OAuthProvider::Grok);
    state.logged_in = true;
    state.status = Some(Ok("xAI OAuth login complete".to_string()));
    let mut lines = Vec::new();

    render_oauth_body(&mut lines, OAuthFlowView::OAuth(&state));
    let rendered = rendered_text(&lines);

    assert!(rendered.contains("continue"), "{rendered}");
    assert_eq!(option_row_count(&rendered), 1, "{rendered}");
    assert!(!rendered.contains("log in"), "{rendered}");
    assert!(!rendered.contains("manual paste"), "{rendered}");
    assert!(!rendered.contains("skip / continue"), "{rendered}");
}

#[test]
fn grok_oauth_logged_out_renders_full_menu() {
    let mut state = OAuthFlowState::new(OAuthProvider::Grok);
    state.logged_in = false;
    let mut lines = Vec::new();

    render_oauth_body(&mut lines, OAuthFlowView::OAuth(&state));
    let rendered = rendered_text(&lines);

    assert!(rendered.contains("log in"), "{rendered}");
    assert!(rendered.contains("manual paste"), "{rendered}");
    assert!(rendered.contains("skip / continue"), "{rendered}");
    assert_eq!(option_row_count(&rendered), 3, "{rendered}");
}

#[test]
fn logged_in_oauth_navigation_clamps_to_single_continue_row() {
    let mut codex = OAuthFlowState::new(OAuthProvider::Codex);
    codex.logged_in = true;
    codex.cursor = 99;
    handle_oauth_flow_key(press(KeyCode::Down), &mut codex);
    assert_eq!(codex.cursor, 0);

    let mut grok = OAuthFlowState::new(OAuthProvider::Grok);
    grok.logged_in = true;
    grok.cursor = 99;
    handle_oauth_flow_key(press(KeyCode::Up), &mut grok);
    assert_eq!(grok.cursor, 0);
}

#[test]
fn grok_oauth_logged_out_enter_still_begins_login() {
    let mut state = OAuthFlowState::new(OAuthProvider::Grok);
    state.logged_in = false;
    state.ssh = false;
    state.cursor = 0;
    let (_close, action) = handle_oauth_flow_key(press(KeyCode::Enter), &mut state);

    assert!(matches!(
        action,
        Some(OAuthFlowRequest {
            provider: OAuthProvider::Grok,
            op: OAuthFlowOp::Begin,
        })
    ));
    assert!(state.pending);
}

#[tokio::test]
async fn logged_in_oauth_enter_advances_add_wizard() {
    for template_id in ["codex-oauth", "grok-oauth"] {
        let template = templates::template_by_id(template_id).unwrap();
        let (_, mut dialog) = dialog_with_config(ProvidersConfig::default());
        let mut state = AddState::new();
        state.template = Some(template);
        state.id_field.set(template_id);
        state.url_field.set(template.url);
        state.step = match template_id {
            "codex-oauth" => {
                let mut oauth = OAuthFlowState::new(OAuthProvider::Codex);
                oauth.logged_in = true;
                oauth.cursor = 0;
                AddStep::OAuthAuth(Box::new(oauth))
            }
            "grok-oauth" => {
                let mut oauth = OAuthFlowState::new(OAuthProvider::Grok);
                oauth.logged_in = true;
                oauth.cursor = 0;
                AddStep::OAuthAuth(Box::new(oauth))
            }
            _ => unreachable!(),
        };

        dialog.handle_add_key(press(KeyCode::Enter), &mut state);

        assert!(
            !matches!(state.step, AddStep::OAuthAuth(_)),
            "{template_id} should advance past the OAuth confirmation step"
        );
    }
}

fn template_cursor(template_id: &str) -> usize {
    templates::TEMPLATES
        .iter()
        .position(|t| t.id == template_id)
        .unwrap()
}

/// Every template — including the frontier-defaults ones — now goes through
/// the editable-id step. The id is no longer locked, so a user can rename a
/// first-party connection (e.g. `anthropic-work`) and still add a second one.
#[test]
fn all_templates_offer_edit_id_step() {
    for t in templates::TEMPLATES {
        let (_tmp, mut dialog) = dialog_with_config(ProvidersConfig::default());
        let mut state = AddState::new();
        state.step = AddStep::PickTemplate {
            cursor: template_cursor(t.id),
        };

        dialog.handle_add_key(press(KeyCode::Enter), &mut state);

        assert!(
            matches!(state.step, AddStep::EditId),
            "{} should land on the EditId step",
            t.id
        );
        // The chosen template is committed and the id is pre-filled for
        // single-vendor templates.
        assert_eq!(state.template.map(|c| c.id), Some(t.id));
        let expected_id = if t.use_id_as_default { t.id } else { "" };
        assert_eq!(state.id_field.text(), expected_id, "{}", t.id);
        assert!(state.error.is_none(), "{}: {:?}", t.id, state.error);
    }
}

/// A second connection to a first-party vendor is allowed: the EditId step
/// rejects the exact-duplicate default id but accepts a renamed key, so the
/// user can keep e.g. separate work and personal Anthropic keys.
#[test]
fn second_first_party_connection_under_custom_id_works() {
    let mut providers = BTreeMap::new();
    providers.insert("anthropic".to_string(), provider_with_models(Vec::new()));
    let (_tmp, mut dialog) = dialog_with_config(ProvidersConfig {
        providers,
        ..Default::default()
    });
    let mut state = AddState::new();
    state.step = AddStep::PickTemplate {
        cursor: template_cursor("anthropic"),
    };

    // Pick the template — lands on EditId with the default `anthropic` id.
    dialog.handle_add_key(press(KeyCode::Enter), &mut state);
    assert!(matches!(state.step, AddStep::EditId));
    assert_eq!(state.id_field.text(), "anthropic");

    // The default id collides with the existing provider.
    dialog.handle_add_key(press(KeyCode::Enter), &mut state);
    assert!(
        matches!(state.step, AddStep::EditId),
        "collision keeps EditId"
    );
    assert!(
        state
            .error
            .as_deref()
            .unwrap_or("")
            .contains("already exists"),
        "{:?}",
        state.error
    );

    // Renaming to a unique key advances past EditId with no error.
    state.id_field.set("anthropic-work");
    dialog.handle_add_key(press(KeyCode::Enter), &mut state);
    assert!(
        matches!(state.step, AddStep::EditUrl),
        "unique renamed id advances the wizard"
    );
    assert!(state.error.is_none(), "{:?}", state.error);
}

/// The committed entry records the template identity (not the config-map
/// key), so a renamed first-party connection still resolves to its vendor
/// template and receives the frontier defaults.
#[test]
fn committed_entry_records_template_identity() {
    let anthropic = templates::template_by_id("anthropic").unwrap();
    let mut state = AddState::new();
    state.template = Some(anthropic);
    state.url_field.set(anthropic.url);

    let entry =
        provider_entry_from_add(&state, anthropic, templates::default_headers_for(anthropic));

    assert_eq!(entry.template.as_deref(), Some("anthropic"));
    // Even under a renamed config key the vendor identity is preserved.
    assert_eq!(
        entry.effective_template("anthropic-work"),
        Some("anthropic")
    );
}
