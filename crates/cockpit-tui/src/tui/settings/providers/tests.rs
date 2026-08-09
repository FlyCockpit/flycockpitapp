use super::oauth_flow::{OAuthBrowserBegin, OAuthOption, oauth_options};
use super::row_editor::RowListEditor;
use super::*;
use crate::tui::settings::pointer_actions::ProviderRowEditorAction;
use crate::tui::settings::settings_editor::ProviderSettingId;
use cockpit_config::providers::{AuthKind, ProvidersConfig};
use cockpit_config::providers::{ConfigDoc, ProviderEntry};
use cockpit_core::providers::deepfetch::{
    ContextProbeRequest, DeepfetchProbeClient, EndpointProbeRequest, ProbeRawOutcome,
};
use cockpit_core::wizard::ProviderWizardStep;
use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};
use serde_json::json;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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
    let mut dialog = SettingsDialog::open(path);
    // Provider-save tests must never touch the developer's real credential
    // store when literal-header protection runs as part of a save.
    dialog.credential_store_path = Some(tmp.path().join("credentials.json"));
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

fn oauth_provider_config(provider_id: &str, credential_ref: &str) -> ProvidersConfig {
    let mut providers = BTreeMap::new();
    providers.insert(
        provider_id.to_string(),
        ProviderEntry {
            url: "https://api.example.com/v1".to_string(),
            auth: Some(AuthKind::OAuth),
            credential_ref: Some(credential_ref.to_string()),
            ..Default::default()
        },
    );
    ProvidersConfig {
        providers,
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

fn oauth_body_text(state: &OAuthFlowState, host: OAuthHost) -> String {
    let mut lines = Vec::new();
    render_oauth_body(&mut lines, OAuthFlowView::OAuth(state), host);
    rendered_text(&lines)
}

fn oauth_option_rows(state: &OAuthFlowState, host: OAuthHost) -> usize {
    option_row_count(&oauth_body_text(state, host))
}

fn add_state_for_oauth(template_id: &str, oauth: OAuthFlowState) -> AddState {
    let template = templates::template_by_id(template_id).unwrap();
    let mut state = AddState::new();
    state.template = Some(template);
    state.id_field.set(template_id);
    state.url_field.set(template.url);
    state.enter_oauth_for_test(oauth);
    state
}

fn standalone_oauth_page(provider: OAuthProvider, state: OAuthFlowState) -> ProvidersPage {
    let id = match provider {
        OAuthProvider::Grok => "grok-oauth",
        OAuthProvider::Codex => "codex-oauth",
    };
    ProvidersPage::OAuthSetup {
        state: Box::new(state),
        parent: Box::new(EditState::new(id.to_string(), ProviderEntry::default())),
    }
}

fn render_provider_rows(d: &SettingsDialog, width: u16, height: u16) -> Vec<String> {
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

fn render_provider_links(
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

pub(crate) fn run_pointer_provider_regression_matrix() {
    // The aggregate exercises every provider surface, including reducers
    // that spawn refetch/OAuth work. Keep one reactor alive across the full
    // construction -> render -> dispatch matrix; narrower fixtures must not
    // accidentally drop the runtime before later nested traversals run.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("provider pointer matrix runtime");
    let _runtime_guard = runtime.enter();
    pointer_render_boundary_publishes_stable_provider_identity();
    pointer_delete_confirmation_is_rendered_and_reduced();
    pointer_edit_menu_mapping_is_exhaustive_over_source_actions();
    pointer_row_editor_actions_survive_reordering_by_identity();
    header_delete_requires_second_press_on_same_row();
    model_delete_requires_second_press_on_same_row();
    q_commits_headers_subpage();
    standalone_oauth_enter_on_continue_returns_to_edit();
    edit_delete_enter_requires_second_enter_to_confirm();
    provider_delete_removes_its_unshared_stored_secret();
    provider_delete_preserves_a_shared_stored_secret();
    provider_delete_offer_can_keep_an_unshared_stored_secret();
    every_visible_oauth_row_acts_on_enter();
    standalone_oauth_link_region_survives_scroll_and_clipping();
    copilot_setup_effect_accepts_only_its_live_operation_once();
    oauth_copy_completion_is_flow_scoped_and_exactly_once();
    pointer_provider_list_action_family_dispatches_from_fresh_sources();
    pointer_enabled_list_and_edit_actions_dispatch_through_dialog_impl();
    pointer_headers_surface_dispatches_every_enabled_control();
    pointer_reachable_nested_surfaces_render_and_dispatch();
    pointer_prompt_surfaces_render_and_dispatch();
    pointer_active_model_retention_renders_dispatches_and_persists();
    pointer_copilot_setup_sources_render_and_dispatch_from_fresh_state();
    pointer_grok_oauth_sources_render_and_dispatch_from_fresh_state();
    pointer_codex_oauth_sources_render_and_dispatch_from_fresh_state();
    pointer_add_oauth_skip_continue_sources_save_from_fresh_state();
    pointer_model_lifecycle_sources_dispatch_by_stable_identity();
    pointer_add_provider_id_field_renders_and_dispatches_from_fresh_state();
    pointer_add_url_field_renders_and_dispatches_from_fresh_state();
    pointer_add_headers_existing_row_renders_and_dispatches_from_fresh_state();
    pointer_add_auth_method_choices_render_and_dispatch_from_fresh_state();
    pointer_add_api_key_field_renders_and_dispatches_from_fresh_state();
    pointer_add_env_var_field_renders_and_dispatches_from_fresh_state();
    pointer_add_test_key_choices_render_and_dispatch_from_fresh_state();
    pointer_add_grok_login_renders_and_dispatches_from_fresh_state();
    pointer_add_codex_login_renders_and_dispatches_from_fresh_state();
    pointer_add_grok_continue_renders_and_dispatches_from_fresh_state();
    pointer_add_codex_continue_renders_and_dispatches_from_fresh_state();
    pointer_add_grok_acknowledge_renders_and_dispatches_from_fresh_state();
    pointer_add_codex_acknowledge_renders_and_dispatches_from_fresh_state();
    pointer_model_refresh_renders_and_dispatches_from_fresh_state();
    pointer_model_discard_renders_and_dispatches_from_fresh_state();
    pointer_model_retry_renders_and_dispatches_from_fresh_state();
    pointer_model_reload_renders_and_dispatches_from_fresh_state();
    pointer_model_reapply_renders_and_dispatches_from_fresh_state();
    pointer_model_rebind_renders_and_dispatches_from_fresh_state();
    pointer_model_dismiss_renders_and_dispatches_from_fresh_state();
}

#[test]
fn pointer_active_model_retention_renders_dispatches_and_persists() {
    use super::super::pointer_actions::{
        ProviderRowEditorAction, ProvidersAction, SettingsPointerAction,
    };
    use cockpit_config::providers::{ActiveModelRef, PromptCacheRetention};
    use cockpit_core::daemon::proto::Request;

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let mut config = one_provider_config(None);
        config.active_model = Some(ActiveModelRef {
            provider: "p".into(),
            model: "stale".into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: Some(PromptCacheRetention::Default),
        });
        let (tmp, mut dialog) = dialog_with_config(config.clone());
        dialog.page = super::super::providers_page(active_model_settings_page(&config));
        let Some(ProvidersPage::ModelSettings { editor, .. }) =
            dialog.page.downcast_mut::<ProvidersPage>()
        else {
            panic!("active model fixture must open model settings")
        };
        editor.cursor = editor
            .fields()
            .iter()
            .position(|field| *field == ProviderSettingId::PromptCacheRetention)
            .expect("active model exposes prompt-cache retention");
        (tmp, dialog)
    }

    let mut inventory = std::collections::HashSet::new();
    let entry = one_provider_config(None).providers["p"].clone();
    inventory.extend(
        SettingsEditor::for_provider("p", &entry)
            .fields()
            .iter()
            .copied(),
    );
    inventory.extend(
        SettingsEditor::for_model("p", &entry, "stale")
            .with_active_prompt_cache_retention(
                PromptCacheRetention::Default,
                cockpit_config::providers::CapabilityStatus::Supported,
            )
            .fields()
            .iter()
            .copied(),
    );
    let mut grok = entry.clone();
    grok.url = "https://api.x.ai/v1".into();
    inventory.extend(
        SettingsEditor::for_provider("grok", &grok)
            .fields()
            .iter()
            .copied(),
    );
    assert_eq!(
        inventory,
        super::super::settings_editor::ALL_PROVIDER_SETTING_IDS
            .iter()
            .copied()
            .collect(),
        "scope- and capability-specific sources cover the sealed setting inventory"
    );

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 20);
    let actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::RowEditor(
                        ProviderRowEditorAction::SettingEdit(
                            ProviderSettingId::PromptCacheRetention,
                        ),
                    )),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(actions.len(), 1, "active model owns one retention source");

    let (_tmp, mut fresh) = fixture();
    let _ = render_provider_rows(&fresh, 110, 20);
    let target = fresh
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find(|target| {
            target.enabled
                && target.action
                    == super::super::shell::SettingsPointerAction::Page(actions[0].clone())
        })
        .cloned()
        .expect("fresh active model renders exact retention identity");
    for kind in [
        crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
        crossterm::event::MouseEventKind::Up(crossterm::event::MouseButton::Left),
    ] {
        assert_eq!(
            fresh.handle_pointer(super::super::tests::settings_mouse(
                kind,
                target.rect.x,
                target.rect.y,
            )),
            super::super::SettingsPointerOutcome::Consumed
        );
    }
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::ModelSettings { editor, .. })
            if editor.active_prompt_cache_retention() == Some(PromptCacheRetention::Extended)
                && editor.value_str(ProviderSettingId::PromptCacheRetention).starts_with("extended")
    ));

    fresh.handle_key(press(KeyCode::Char('s')));
    assert_eq!(
        fresh
            .config
            .active_model
            .as_ref()
            .and_then(|active| active.prompt_cache_retention),
        Some(PromptCacheRetention::Extended)
    );
    let staged = fresh.pending_default_model_update_id;
    assert!(matches!(
        fresh.pending_daemon_request.as_ref(),
        Some(Request::SetDefaultModel {
            default_update_id,
            provider: Some(provider),
            model: Some(model),
            prompt_cache_retention: Some(retention),
            clear: false,
            ..
        }) if Some(*default_update_id) == staged
            && provider == "p"
            && model == "stale"
            && *retention == PromptCacheRetention::Extended
    ));
    let reloaded = cockpit_config::providers::ConfigDoc::load(&fresh.config_path)
        .unwrap()
        .providers();
    assert_eq!(
        reloaded
            .active_model
            .as_ref()
            .and_then(|active| active.prompt_cache_retention),
        Some(PromptCacheRetention::Default),
        "default persistence remains daemon-owned until verified completion"
    );
}

#[test]
fn pointer_model_dismiss_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{
        ModelLifecycleAction, ProvidersAction, SettingsPointerAction,
    };

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let config = one_provider_config(None);
        let (tmp, mut dialog) = dialog_with_config(config);
        let entry = dialog.config.providers["p"].clone();
        let model_id = entry.models[0].id.clone();
        let mut editor = SettingsEditor::for_model_with_generation("p", &entry, &model_id, 1);
        let refresh_id = editor
            .begin_multimodal_refresh()
            .expect("multimodal refresh begins");
        editor.complete_multimodal_refresh_failure(refresh_id, "fixture refresh failure");
        dialog.page = super::super::providers_page(ProvidersPage::ModelSettings {
            editor,
            models: Box::new(ModelEditor::new(None, entry.models.clone())),
            parent: Box::new(EditState::new("p".into(), entry)),
        });
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let action = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::ModelLifecycle(
                        ModelLifecycleAction::Dismiss(provider, model),
                    )),
                ),
                true,
            ) if provider.0 == "p" && model.0 == "stale" => Some(action.clone()),
            _ => None,
        })
        .expect("failed multimodal refresh renders identity-keyed Dismiss");
    assert_eq!(
        super::super::pointer_action_fixtures::key_for(&action),
        super::super::pointer_action_fixtures::ActionFixtureKey::Providers(
            super::super::pointer_action_fixtures::ProvidersFixture::ModelDismiss,
        )
    );

    let (_tmp, mut fresh) = fixture();
    click_rendered_provider_action(&mut fresh, &action);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::ModelSettings { editor, parent, .. })
            if parent.provider_id == "p"
                && editor.status.as_deref()
                    == Some("media capability refresh failure dismissed")
                && editor.multimodal().is_some_and(|multimodal| {
                    matches!(&multimodal.refresh,
                        super::super::multimodal_capability_editor::RefreshPhase::Idle)
                        && matches!(&multimodal.phase,
                            super::super::multimodal_capability_editor::EditorPhase::Clean { .. })
                        && !multimodal.available_actions().contains(&"Dismiss")
                        && !multimodal.available_actions().contains(&"Retry")
                })
    ));
}

#[test]
fn pointer_model_rebind_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{
        ModelLifecycleAction, ProvidersAction, SettingsPointerAction,
    };

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let mut config = one_provider_config(None);
        config.providers.get_mut("p").unwrap().models[0]
            .capability_overrides
            .image_input = Some(cockpit_config::providers::CapabilityStatus::Supported);
        let (tmp, mut dialog) = dialog_with_config(config);
        let entry = dialog.config.providers["p"].clone();
        let model_id = entry.models[0].id.clone();
        let mut editor = SettingsEditor::for_model_with_generation("p", &entry, &model_id, 1);
        editor.cursor = editor
            .fields()
            .iter()
            .position(|field| *field == ProviderSettingId::CapabilityImages)
            .expect("model settings has image capability row");
        editor.handle_key(press(KeyCode::Enter));

        let removed_models = ModelEditor::new(None, Vec::new());
        editor.sync_multimodal_lifecycle("p", &entry, &removed_models, 2);
        let rebound_models = ModelEditor::new(None, entry.models.clone());
        editor.sync_multimodal_lifecycle("p", &entry, &rebound_models, 2);

        dialog.page = super::super::providers_page(ProvidersPage::ModelSettings {
            editor,
            models: Box::new(rebound_models),
            parent: Box::new(EditState::new("p".into(), entry)),
        });
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let action = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::ModelLifecycle(
                        ModelLifecycleAction::Rebind(provider, model),
                    )),
                ),
                true,
            ) if provider.0 == "p" && model.0 == "stale" => Some(action.clone()),
            _ => None,
        })
        .expect("reappeared unavailable draft renders identity-keyed Rebind");
    assert_eq!(
        super::super::pointer_action_fixtures::key_for(&action),
        super::super::pointer_action_fixtures::ActionFixtureKey::Providers(
            super::super::pointer_action_fixtures::ProvidersFixture::ModelRebind,
        )
    );

    let (_tmp, mut fresh) = fixture();
    click_rendered_provider_action(&mut fresh, &action);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::ModelSettings { editor, models, parent })
            if parent.provider_id == "p"
                && models.rows().iter().any(|model| model.id == "stale")
                && editor.is_overridden(ProviderSettingId::CapabilityImages)
                && editor.value_str(ProviderSettingId::CapabilityImages).starts_with("Unsupported")
                && editor.status.as_deref() == Some("media capability draft rebound")
                && editor.multimodal().is_some_and(|multimodal| {
                    matches!(&multimodal.phase,
                        super::super::multimodal_capability_editor::EditorPhase::Dirty)
                        && multimodal.identity.provider_id == "p"
                        && multimodal.identity.model_id == "stale"
                        && !multimodal.available_actions().contains(&"Rebind")
                })
    ));
    assert_eq!(
        load_provider(&fresh.config_path, "p").models[0]
            .capability_overrides
            .image_input,
        Some(cockpit_config::providers::CapabilityStatus::Supported)
    );
}

#[test]
fn pointer_model_reapply_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{
        ModelLifecycleAction, ProvidersAction, SettingsPointerAction,
    };

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let mut config = one_provider_config(None);
        config.providers.get_mut("p").unwrap().models[0]
            .capability_overrides
            .image_input = Some(cockpit_config::providers::CapabilityStatus::Supported);
        let (tmp, mut dialog) = dialog_with_config(config);
        let entry = dialog.config.providers["p"].clone();
        let model_id = entry.models[0].id.clone();
        let mut editor = SettingsEditor::for_model_with_generation("p", &entry, &model_id, 1);
        editor.cursor = editor
            .fields()
            .iter()
            .position(|field| *field == ProviderSettingId::CapabilityImages)
            .expect("model settings has image capability row");
        editor.handle_key(press(KeyCode::Enter));
        let (save_id, provider_id, model_id, selection_generation, base_generation) = editor
            .begin_multimodal_save()
            .expect("dirty media draft begins save");
        editor.complete_multimodal_save_conflict(
            save_id,
            &provider_id,
            &model_id,
            selection_generation,
            base_generation,
            2,
            &entry,
        );
        dialog.page = super::super::providers_page(ProvidersPage::ModelSettings {
            editor,
            models: Box::new(ModelEditor::new(None, entry.models.clone())),
            parent: Box::new(EditState::new("p".into(), entry)),
        });
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let action = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::ModelLifecycle(
                        ModelLifecycleAction::Reapply(provider, model),
                    )),
                ),
                true,
            ) if provider.0 == "p" && model.0 == "stale" => Some(action.clone()),
            _ => None,
        })
        .expect("conflicted multimodal save renders identity-keyed Reapply");
    assert_eq!(
        super::super::pointer_action_fixtures::key_for(&action),
        super::super::pointer_action_fixtures::ActionFixtureKey::Providers(
            super::super::pointer_action_fixtures::ProvidersFixture::ModelReapply,
        )
    );

    let (_tmp, mut fresh) = fixture();
    click_rendered_provider_action(&mut fresh, &action);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::ModelSettings { editor, parent, .. })
            if parent.provider_id == "p"
                && editor.is_overridden(ProviderSettingId::CapabilityImages)
                && editor.value_str(ProviderSettingId::CapabilityImages).starts_with("Unsupported")
                && editor.status.as_deref() == Some("media capability draft reapplied")
                && editor.multimodal().is_some_and(|multimodal| {
                    matches!(&multimodal.phase,
                        super::super::multimodal_capability_editor::EditorPhase::Dirty)
                        && !multimodal.available_actions().contains(&"Reapply")
                })
    ));
    assert_eq!(
        load_provider(&fresh.config_path, "p").models[0]
            .capability_overrides
            .image_input,
        Some(cockpit_config::providers::CapabilityStatus::Supported)
    );
}

#[test]
fn pointer_model_reload_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{
        ModelLifecycleAction, ProvidersAction, SettingsPointerAction,
    };

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let mut config = one_provider_config(None);
        config.providers.get_mut("p").unwrap().models[0]
            .capability_overrides
            .image_input = Some(cockpit_config::providers::CapabilityStatus::Supported);
        let (tmp, mut dialog) = dialog_with_config(config);
        let entry = dialog.config.providers["p"].clone();
        let model_id = entry.models[0].id.clone();
        let mut editor = SettingsEditor::for_model_with_generation("p", &entry, &model_id, 1);
        editor.cursor = editor
            .fields()
            .iter()
            .position(|field| *field == ProviderSettingId::CapabilityImages)
            .expect("model settings has image capability row");
        editor.handle_key(press(KeyCode::Enter));
        let (save_id, provider_id, model_id, selection_generation, base_generation) = editor
            .begin_multimodal_save()
            .expect("dirty media draft begins save");
        editor.complete_multimodal_save_failure(
            save_id,
            &provider_id,
            &model_id,
            selection_generation,
            base_generation,
            "fixture save failure",
        );
        dialog.page = super::super::providers_page(ProvidersPage::ModelSettings {
            editor,
            models: Box::new(ModelEditor::new(None, entry.models.clone())),
            parent: Box::new(EditState::new("p".into(), entry)),
        });
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let action = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::ModelLifecycle(
                        ModelLifecycleAction::Reload(provider, model),
                    )),
                ),
                true,
            ) if provider.0 == "p" && model.0 == "stale" => Some(action.clone()),
            _ => None,
        })
        .expect("failed multimodal save renders identity-keyed Reload");
    assert_eq!(
        super::super::pointer_action_fixtures::key_for(&action),
        super::super::pointer_action_fixtures::ActionFixtureKey::Providers(
            super::super::pointer_action_fixtures::ProvidersFixture::ModelReload,
        )
    );

    let (_tmp, mut fresh) = fixture();
    click_rendered_provider_action(&mut fresh, &action);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::ModelSettings { editor, parent, .. })
            if parent.provider_id == "p"
                && editor.is_overridden(ProviderSettingId::CapabilityImages)
                && editor.value_str(ProviderSettingId::CapabilityImages).starts_with("Supported")
                && editor.status.as_deref() == Some("media capability draft reloaded")
                && editor.multimodal().is_some_and(|multimodal| {
                    matches!(&multimodal.phase,
                        super::super::multimodal_capability_editor::EditorPhase::Clean { .. })
                        && !multimodal.available_actions().contains(&"Reload")
                })
    ));
    assert_eq!(
        load_provider(&fresh.config_path, "p").models[0]
            .capability_overrides
            .image_input,
        Some(cockpit_config::providers::CapabilityStatus::Supported)
    );
}

#[test]
fn pointer_model_retry_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{
        ModelLifecycleAction, ProvidersAction, SettingsPointerAction,
    };

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let config = one_provider_config(None);
        let (tmp, mut dialog) = dialog_with_config(config);
        let entry = dialog.config.providers["p"].clone();
        let model_id = entry.models[0].id.clone();
        let mut editor = SettingsEditor::for_model_with_generation("p", &entry, &model_id, 1);
        let refresh_id = editor
            .begin_multimodal_refresh()
            .expect("multimodal refresh begins");
        editor.complete_multimodal_refresh_failure(refresh_id, "fixture refresh failure");
        dialog.page = super::super::providers_page(ProvidersPage::ModelSettings {
            editor,
            models: Box::new(ModelEditor::new(None, entry.models.clone())),
            parent: Box::new(EditState::new("p".into(), entry)),
        });
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let action = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::ModelLifecycle(
                        ModelLifecycleAction::Retry(provider, model),
                    )),
                ),
                true,
            ) if provider.0 == "p" && model.0 == "stale" => Some(action.clone()),
            _ => None,
        })
        .expect("failed multimodal refresh renders identity-keyed Retry");
    assert_eq!(
        super::super::pointer_action_fixtures::key_for(&action),
        super::super::pointer_action_fixtures::ActionFixtureKey::Providers(
            super::super::pointer_action_fixtures::ProvidersFixture::ModelRetry,
        )
    );

    let (_tmp, mut fresh) = fixture();
    click_rendered_provider_action(&mut fresh, &action);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::ModelSettings { editor, parent, .. })
            if parent.provider_id == "p"
                && editor.multimodal().is_some_and(|multimodal| {
                    matches!(&multimodal.refresh,
                        super::super::multimodal_capability_editor::RefreshPhase::Idle)
                        && !multimodal.available_actions().contains(&"Retry")
                })
                && editor.status.as_deref() == Some("media capabilities refreshed")
    ));
}

#[test]
fn pointer_model_discard_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{
        ModelLifecycleAction, ProvidersAction, SettingsPointerAction,
    };

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let config = one_provider_config(None);
        let (tmp, mut dialog) = dialog_with_config(config);
        let entry = dialog.config.providers["p"].clone();
        let model_id = entry.models[0].id.clone();
        let mut editor = SettingsEditor::for_model_with_generation("p", &entry, &model_id, 1);
        editor.cursor = editor
            .fields()
            .iter()
            .position(|field| *field == ProviderSettingId::CapabilityImages)
            .expect("model settings has image capability row");
        editor.handle_key(press(KeyCode::Enter));
        let (save_id, provider_id, model_id, selection_generation, base_generation) = editor
            .begin_multimodal_save()
            .expect("dirty media draft begins save");
        editor.complete_multimodal_save_failure(
            save_id,
            &provider_id,
            &model_id,
            selection_generation,
            base_generation,
            "fixture save failure",
        );
        dialog.page = super::super::providers_page(ProvidersPage::ModelSettings {
            editor,
            models: Box::new(ModelEditor::new(None, entry.models.clone())),
            parent: Box::new(EditState::new("p".into(), entry)),
        });
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let action = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::ModelLifecycle(
                        ModelLifecycleAction::Discard(provider, model),
                    )),
                ),
                true,
            ) if provider.0 == "p" && model.0 == "stale" => Some(action.clone()),
            _ => None,
        })
        .expect("failed multimodal save renders identity-keyed Discard");
    assert_eq!(
        super::super::pointer_action_fixtures::key_for(&action),
        super::super::pointer_action_fixtures::ActionFixtureKey::Providers(
            super::super::pointer_action_fixtures::ProvidersFixture::ModelDiscard,
        )
    );

    let (_tmp, mut fresh) = fixture();
    click_rendered_provider_action(&mut fresh, &action);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::ModelSettings { editor, parent, .. })
            if parent.provider_id == "p"
                && !editor.is_overridden(ProviderSettingId::CapabilityImages)
                && editor.status.as_deref() == Some("media capability draft discarded")
                && editor.multimodal().is_some_and(|multimodal| {
                    !multimodal.available_actions().contains(&"Discard")
                })
    ));
    assert_eq!(
        load_provider(&fresh.config_path, "p").models[0]
            .capability_overrides
            .image_input,
        None
    );
}

#[test]
fn pointer_model_refresh_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{
        ModelLifecycleAction, ProvidersAction, SettingsPointerAction,
    };

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let config = one_provider_config(None);
        let (tmp, mut dialog) = dialog_with_config(config);
        let entry = dialog.config.providers["p"].clone();
        let model_id = entry.models[0].id.clone();
        dialog.page = super::super::providers_page(ProvidersPage::ModelSettings {
            editor: SettingsEditor::for_model_with_generation("p", &entry, &model_id, 1),
            models: Box::new(ModelEditor::new(None, entry.models.clone())),
            parent: Box::new(EditState::new("p".into(), entry)),
        });
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let action = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::ModelLifecycle(
                        ModelLifecycleAction::Refresh(provider, model),
                    )),
                ),
                true,
            ) if provider.0 == "p" && model.0 == "stale" => Some(action.clone()),
            _ => None,
        })
        .expect("model settings renders identity-keyed media refresh");
    assert_eq!(
        super::super::pointer_action_fixtures::key_for(&action),
        super::super::pointer_action_fixtures::ActionFixtureKey::Providers(
            super::super::pointer_action_fixtures::ProvidersFixture::ModelRefresh,
        )
    );

    let (_tmp, mut fresh) = fixture();
    click_rendered_provider_action(&mut fresh, &action);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::ModelSettings { editor, parent, .. })
            if parent.provider_id == "p"
                && editor.multimodal().is_some_and(|multimodal| {
                    matches!(&multimodal.refresh,
                        super::super::multimodal_capability_editor::RefreshPhase::Idle)
                })
                && editor.status.as_deref() == Some("media capabilities refreshed")
    ));
}

fn pointer_provider_list_action_family_dispatches_from_fresh_sources() {
    use super::super::pointer_actions::{
        ProviderDeleteChoice, ProviderId, ProvidersAction, SettingsPointerAction,
    };

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let (tmp, mut dialog) = dialog_with_config(one_provider_config(None));
        dialog.page = super::super::providers_page(ProvidersPage::List {
            cursor: 1,
            status: None,
            delete_pending: false,
        });
        (tmp, dialog)
    }

    fn actions(dialog: &SettingsDialog) -> std::collections::HashSet<SettingsPointerAction> {
        let _ = render_provider_rows(dialog, 110, 60);
        dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .filter_map(|target| match (&target.action, target.enabled) {
                (
                    super::super::shell::SettingsPointerAction::Page(
                        action @ SettingsPointerAction::Providers(_),
                    ),
                    true,
                ) => Some(action.clone()),
                _ => None,
            })
            .collect()
    }

    let (_tmp, source) = fixture();
    let id = ProviderId("p".into());
    assert_eq!(
        actions(&source),
        [
            SettingsPointerAction::Providers(ProvidersAction::RefetchAll),
            SettingsPointerAction::Providers(ProvidersAction::Add),
            SettingsPointerAction::Providers(ProvidersAction::CycleUnlistedPolicy),
            SettingsPointerAction::Providers(ProvidersAction::Open(id.clone())),
            SettingsPointerAction::Providers(ProvidersAction::BeginDelete(id.clone())),
        ]
        .into_iter()
        .collect(),
        "provider list publishes its complete initial action family"
    );

    for action in actions(&source) {
        let (_tmp, mut dialog) = fixture();
        click_rendered_provider_action(&mut dialog, &action);
        match action {
            SettingsPointerAction::Providers(ProvidersAction::Add) => assert!(matches!(
                dialog.test_page(),
                TestPageRef::Providers(ProvidersPage::Add(_))
            )),
            SettingsPointerAction::Providers(ProvidersAction::Open(_)) => assert!(matches!(
                dialog.test_page(),
                TestPageRef::Providers(ProvidersPage::Edit(state)) if state.provider_id == "p"
            )),
            SettingsPointerAction::Providers(ProvidersAction::RefetchAll) => assert!(matches!(
                dialog.test_page(),
                TestPageRef::Providers(ProvidersPage::FetchAll(_))
            )),
            SettingsPointerAction::Providers(ProvidersAction::CycleUnlistedPolicy) => {
                assert_eq!(
                    dialog.config.on_unlisted_models_fetch,
                    Some(OnUnlistedModelsFetch::Keep)
                );
                assert_eq!(
                    ConfigDoc::load(&dialog.config_path)
                        .unwrap()
                        .providers()
                        .on_unlisted_models_fetch,
                    Some(OnUnlistedModelsFetch::Keep)
                );
            }
            SettingsPointerAction::Providers(ProvidersAction::BeginDelete(ref provider)) => {
                assert!(matches!(
                    dialog.test_page(),
                    TestPageRef::Providers(ProvidersPage::List {
                        delete_pending: true,
                        ..
                    })
                ));
                let choices = actions(&dialog);
                let expected_choices = [
                    ProviderDeleteChoice::RemoveSecrets,
                    ProviderDeleteChoice::KeepSecrets,
                    ProviderDeleteChoice::Cancel,
                ];
                for choice in expected_choices {
                    let delete = SettingsPointerAction::Providers(ProvidersAction::Delete(
                        provider.clone(),
                        choice,
                    ));
                    assert!(
                        choices.contains(&delete),
                        "missing delete choice {choice:?}"
                    );
                    let (_nested_tmp, mut nested) = fixture();
                    click_rendered_provider_action(&mut nested, &action);
                    click_rendered_provider_action(&mut nested, &delete);
                    if choice == ProviderDeleteChoice::Cancel {
                        assert!(nested.config.providers.contains_key("p"));
                        assert!(matches!(
                            nested.test_page(),
                            TestPageRef::Providers(ProvidersPage::List {
                                delete_pending: false,
                                ..
                            })
                        ));
                    } else {
                        assert!(!nested.config.providers.contains_key("p"));
                        assert!(
                            !ConfigDoc::load(&nested.config_path)
                                .unwrap()
                                .providers()
                                .providers
                                .contains_key("p")
                        );
                    }
                }
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Copy)]
enum PromptFixture {
    FetchAll,
    FetchOne,
    FetchFallback,
    Copilot,
}

fn prompt_fixture(kind: PromptFixture) -> (tempfile::TempDir, SettingsDialog) {
    let config = one_provider_config(Some(OnUnlistedModelsFetch::Ask));
    let (tmp, mut dialog) = dialog_with_config(config);
    let entry = dialog.config.providers["p"].clone();
    dialog.page = super::super::providers_page(match kind {
        PromptFixture::FetchAll => ProvidersPage::FetchAll(FetchAllState {
            providers: vec!["p".into()],
            in_flight: Vec::new(),
            finished: Vec::new(),
            pre_fetch_models: [("p".into(), entry.models.clone())].into_iter().collect(),
            policy_resolved: false,
            cursor: 0,
            dont_ask_again: false,
            unlisted: vec![("p".into(), "stale".into())],
        }),
        PromptFixture::FetchOne => ProvidersPage::FetchOnePrompt(FetchOnePromptState {
            provider_id: "p".into(),
            remote: vec![model("current", false)],
            catalog: ProviderModelCatalog::Live,
            pre_fetch_models: entry.models.clone(),
            unlisted: vec!["stale".into()],
            cursor: 0,
            dont_ask_again: false,
        }),
        PromptFixture::FetchFallback => {
            ProvidersPage::FetchFallbackPrompt(FetchFallbackPromptState {
                provider_id: "p".into(),
                models: vec![model("fallback", false)],
                catalog: ProviderModelCatalog::CodexFallback,
                reason: "live catalog unavailable".into(),
                cursor: 0,
            })
        }
        PromptFixture::Copilot => ProvidersPage::CopilotSetup {
            state: CopilotSetupState {
                shell: None,
                rc_path: None,
                already_configured: false,
                outcome: Some(Ok("fixture complete".into())),
                operation: super::super::shell::PointerOperationGate::default(),
            },
            parent: Box::new(EditState::new("p".into(), entry)),
        },
    });
    (tmp, dialog)
}

#[test]
fn pointer_prompt_surfaces_render_and_dispatch() {
    for kind in [
        PromptFixture::FetchAll,
        PromptFixture::FetchOne,
        PromptFixture::FetchFallback,
        PromptFixture::Copilot,
    ] {
        let (_tmp, source) = prompt_fixture(kind);
        let _ = render_provider_rows(&source, 110, 60);
        let actions = source
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .filter_map(|target| match (&target.action, target.enabled) {
                (
                    super::super::shell::SettingsPointerAction::Page(
                        action @ super::super::pointer_actions::SettingsPointerAction::Providers(_),
                    ),
                    true,
                ) => Some(action.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            !actions.is_empty(),
            "prompt fixture must render enabled controls"
        );
        for action in actions {
            let (_tmp, mut dialog) = prompt_fixture(kind);
            click_rendered_provider_action(&mut dialog, &action);
            if matches!(
                action,
                super::super::pointer_actions::SettingsPointerAction::Providers(
                    super::super::pointer_actions::ProvidersAction::FetchOneConfirm(
                        _,
                        super::super::pointer_actions::FetchOneChoice::Cancel,
                    ),
                )
            ) {
                assert!(matches!(
                    dialog.test_page(),
                    TestPageRef::Providers(ProvidersPage::List { status, .. })
                        if status.as_deref() == Some("refetch cancelled")
                ));
            }
        }
    }
}

fn replay_special_provider_edit_actions(
    provider_id: &str,
    fixture: impl Fn() -> (tempfile::TempDir, SettingsDialog),
) {
    use super::super::pointer_actions::{ProvidersAction, SettingsPointerAction};
    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (super::super::shell::SettingsPointerAction::Page(action), true) => {
                Some(action.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        !actions.is_empty(),
        "special provider edit source has controls"
    );
    for action in actions {
        let (_tmp, mut fresh) = fixture();
        let expected_deep_fetch = matches!(
            &action,
            SettingsPointerAction::Providers(ProvidersAction::DeepFetchConfirm(_))
        )
        .then(|| DeepFetchState::prepare(&fresh.config_path, provider_id).map(|_| ()));
        click_rendered_provider_action(&mut fresh, &action);
        let parent_matches = |candidate: &EditState| candidate.provider_id == provider_id;
        match action {
            SettingsPointerAction::Providers(ProvidersAction::EditField(_, EditField::Url)) => {
                assert!(
                    matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::Edit(state)) if parent_matches(state) && state.editing_field == Some(EditField::Url))
                );
            }
            SettingsPointerAction::Providers(ProvidersAction::EditHeaders(_)) => assert!(
                matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::Headers { parent, .. }) if parent_matches(parent))
            ),
            SettingsPointerAction::Providers(ProvidersAction::CopilotSetup(_)) => assert!(
                matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::CopilotSetup { parent, .. }) if parent_matches(parent))
            ),
            SettingsPointerAction::Providers(ProvidersAction::BeginOAuth(_, provider)) => assert!(
                matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::OAuthSetup { state, parent }) if state.provider == provider && parent_matches(parent))
            ),
            SettingsPointerAction::Providers(ProvidersAction::ManageModels(_)) => assert!(
                matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::Models { parent, .. }) if parent_matches(parent))
            ),
            SettingsPointerAction::Providers(ProvidersAction::ProviderSettings(_)) => assert!(
                matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::ProviderSettings { parent, .. }) if parent_matches(parent))
            ),
            SettingsPointerAction::Providers(ProvidersAction::Favorite(_)) => assert!(
                matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::Edit(state)) if parent_matches(state) && state.entry.favorite == Some(true))
            ),
            SettingsPointerAction::Providers(ProvidersAction::Refetch(_)) => assert!(
                matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::Edit(state)) if parent_matches(state) && state.fetch.is_some())
            ),
            SettingsPointerAction::Providers(ProvidersAction::DeepFetchConfirm(_)) => {
                match expected_deep_fetch.expect("deep-fetch expectation") {
                    Ok(()) => assert!(
                        matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::DeepFetch { parent, .. }) if parent_matches(parent))
                    ),
                    Err(expected) => assert!(
                        matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::Edit(state)) if parent_matches(state) && state.status.as_deref() == Some(expected.as_str()))
                    ),
                }
            }
            SettingsPointerAction::Providers(ProvidersAction::BeginDelete(_)) => assert!(
                matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::Edit(state)) if parent_matches(state) && state.delete_pending)
            ),
            SettingsPointerAction::Providers(ProvidersAction::SaveProvider(_)) => assert!(
                matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::Edit(state)) if parent_matches(state) && state.status.is_some())
            ),
            SettingsPointerAction::Providers(ProvidersAction::LocalBack) => assert!(matches!(
                fresh.test_page(),
                TestPageRef::Providers(ProvidersPage::List { .. })
            )),
            other => panic!("unexpected special-provider edit action: {other:?}"),
        }
    }
}

#[test]
fn pointer_copilot_setup_sources_render_and_dispatch_from_fresh_state() {
    use super::super::pointer_actions::{
        ConfirmationChoice, ProviderId, ProvidersAction, SettingsPointerAction,
    };

    fn copilot_edit_fixture() -> (tempfile::TempDir, SettingsDialog) {
        let mut config = one_provider_config(None);
        let entry = config.providers.remove("p").unwrap();
        config.providers.insert("copilot".into(), entry);
        let (tmp, mut dialog) = dialog_with_config(config);
        let entry = dialog.config.providers["copilot"].clone();
        dialog.page = super::super::providers_page(ProvidersPage::Edit(EditState::new(
            "copilot".into(),
            entry,
        )));
        let ProvidersPage::Edit(state) = dialog.page.downcast_mut::<ProvidersPage>().unwrap()
        else {
            unreachable!("edit fixture")
        };
        state.cursor = edit_menu_actions(&state.provider_id, &state.entry)
            .iter()
            .position(|action| *action == EditAction::CopilotAuth)
            .expect("Copilot provider exposes its auth setup source");
        (tmp, dialog)
    }

    fn setup_fixture(kind: u8) -> (tempfile::TempDir, SettingsDialog) {
        let (tmp, mut dialog) = copilot_edit_fixture();
        let entry = dialog.config.providers["copilot"].clone();
        let (shell, rc_path, already_configured, outcome) = match kind {
            0 => (
                Some(CopilotShell::Bash),
                Some(tmp.path().join("copilot-test.bashrc")),
                false,
                None,
            ),
            1 => (None, None, false, None),
            2 => (
                Some(CopilotShell::Bash),
                Some(tmp.path().join("unused")),
                true,
                None,
            ),
            3 => (None, None, false, Some(Ok("fixture complete".into()))),
            _ => unreachable!(),
        };
        dialog.page = super::super::providers_page(ProvidersPage::CopilotSetup {
            state: CopilotSetupState {
                shell,
                rc_path,
                already_configured,
                outcome,
                operation: super::super::shell::PointerOperationGate::default(),
            },
            parent: Box::new(EditState::new("copilot".into(), entry)),
        });
        (tmp, dialog)
    }

    fn rendered_actions(
        dialog: &SettingsDialog,
    ) -> std::collections::HashSet<SettingsPointerAction> {
        let _ = render_provider_rows(dialog, 110, 60);
        dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .filter_map(|target| match (&target.action, target.enabled) {
                (super::super::shell::SettingsPointerAction::Page(action), true) => {
                    Some(action.clone())
                }
                _ => None,
            })
            .collect()
    }

    replay_special_provider_edit_actions("copilot", copilot_edit_fixture);

    let expected = [
        (
            0,
            SettingsPointerAction::Providers(ProvidersAction::CopilotConfirm(
                ProviderId("copilot".into()),
                ConfirmationChoice::Cancel,
            )),
        ),
        (
            1,
            SettingsPointerAction::Providers(ProvidersAction::LocalBack),
        ),
        (
            2,
            SettingsPointerAction::Providers(ProvidersAction::LocalBack),
        ),
        (
            3,
            SettingsPointerAction::Providers(ProvidersAction::CopilotConfirm(
                ProviderId("copilot".into()),
                ConfirmationChoice::Confirm,
            )),
        ),
    ];
    for (kind, action) in expected {
        let (_tmp, mut fresh) = setup_fixture(kind);
        click_rendered_provider_action(&mut fresh, &action);
        assert!(matches!(
            fresh.test_page(),
            TestPageRef::Providers(ProvidersPage::Edit(state)) if state.provider_id == "copilot"
        ));
    }

    // The actionable source publishes both commands. Dispatch Cancel on a
    // separate fresh instance so it proves that cancellation performs no
    // setup work and preserves the parent edit state.
    let (_tmp, source) = setup_fixture(0);
    let rendered = rendered_actions(&source);
    assert!(rendered.contains(&SettingsPointerAction::Providers(
        ProvidersAction::CopilotConfirm(ProviderId("copilot".into()), ConfirmationChoice::Confirm,)
    )));
    assert!(rendered.contains(&SettingsPointerAction::Providers(
        ProvidersAction::CopilotConfirm(ProviderId("copilot".into()), ConfirmationChoice::Cancel,)
    )));
}

#[test]
fn pointer_grok_oauth_sources_render_and_dispatch_from_fresh_state() {
    use super::super::pointer_actions::{
        OAuthCopyKind, ProviderId, ProvidersAction, SettingsPointerAction,
    };

    let _guard = OAUTH_EFFECTS_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reset_oauth_effects(false);

    fn edit_fixture() -> (tempfile::TempDir, SettingsDialog) {
        let config = oauth_provider_config("grok-oauth", "oauth:test");
        let (tmp, mut dialog) = dialog_with_config(config);
        let entry = dialog.config.providers["grok-oauth"].clone();
        let mut state = EditState::new("grok-oauth".into(), entry);
        state.cursor = edit_menu_actions(&state.provider_id, &state.entry)
            .iter()
            .position(|action| *action == EditAction::OAuthAuth(OAuthProvider::Grok))
            .expect("Grok provider exposes its OAuth source");
        dialog.page = super::super::providers_page(ProvidersPage::Edit(state));
        (tmp, dialog)
    }

    fn oauth_fixture(kind: u8) -> (tempfile::TempDir, SettingsDialog) {
        let (tmp, mut dialog) =
            dialog_with_config(oauth_provider_config("grok-oauth", "oauth:test"));
        let mut state = OAuthFlowState::new_without_acknowledgement_with_effects_for_test(
            OAuthProvider::Grok,
            fake_oauth_effects(),
        );
        match kind {
            0 => {}
            1 => {
                state.set_browser_session_for_test("https://example.test/oauth");
                state.pending = true;
            }
            2 => state.logged_in = true,
            _ => unreachable!(),
        }
        dialog.page =
            super::super::providers_page(standalone_oauth_page(OAuthProvider::Grok, state));
        (tmp, dialog)
    }

    fn actions(dialog: &SettingsDialog) -> std::collections::HashSet<SettingsPointerAction> {
        let _ = render_provider_rows(dialog, 110, 60);
        dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .filter_map(|target| match (&target.action, target.enabled) {
                (super::super::shell::SettingsPointerAction::Page(action), true) => {
                    Some(action.clone())
                }
                _ => None,
            })
            .collect()
    }

    fn copy_visible_authorization_url(dialog: &mut SettingsDialog, expected_copies: usize) {
        let _ = render_provider_rows(dialog, 110, 60);
        let actions = dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .filter_map(|target| match (&target.action, target.enabled) {
                (
                    super::super::shell::SettingsPointerAction::Page(
                        action @ SettingsPointerAction::Providers(ProvidersAction::CopyOAuth(
                            _,
                            OAuthCopyKind::AuthorizationUrl,
                        )),
                    ),
                    true,
                ) => Some(action.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actions.len(),
            1,
            "each active Grok fixture must own exactly one authorization-copy source"
        );
        let action = actions.into_iter().next().unwrap();
        let flow_id = match action {
            SettingsPointerAction::Providers(ProvidersAction::CopyOAuth(flow_id, _)) => flow_id,
            _ => unreachable!(),
        };
        click_rendered_provider_action(
            dialog,
            &SettingsPointerAction::Providers(ProvidersAction::CopyOAuth(
                flow_id,
                OAuthCopyKind::AuthorizationUrl,
            )),
        );
        assert_eq!(
            oauth_effects_log(),
            vec!["copy:https://example.test/oauth".to_string(); expected_copies]
        );
        assert!(matches!(
            dialog.test_page(),
            TestPageRef::Providers(ProvidersPage::OAuthSetup { state, .. })
                if state.flow_id == flow_id
                    && state.status.as_ref().is_some_and(|status| status.as_deref() == Ok(
                        "copied OAuth URL (unverified — also reachable via the Open link above)"
                    ))
        ));
    }

    replay_special_provider_edit_actions("grok-oauth", edit_fixture);
    let begin = SettingsPointerAction::Providers(ProvidersAction::BeginOAuth(
        ProviderId("grok-oauth".into()),
        OAuthProvider::Grok,
    ));
    let (_tmp, source) = edit_fixture();
    assert!(actions(&source).contains(&begin));
    let (_tmp, mut fresh) = edit_fixture();
    click_rendered_provider_action(&mut fresh, &begin);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::OAuthSetup { state, parent })
            if state.provider == OAuthProvider::Grok && parent.provider_id == "grok-oauth"
    ));

    let initial = [OAuthOption::Login, OAuthOption::ManualPaste]
        .into_iter()
        .map(|option| {
            SettingsPointerAction::Providers(ProvidersAction::OAuthOption(
                ProviderId("grok-oauth".into()),
                option,
            ))
        })
        .collect::<std::collections::HashSet<_>>();
    let (_tmp, source) = oauth_fixture(0);
    assert_eq!(actions(&source), initial);
    for action in initial {
        let (_tmp, mut fresh) = oauth_fixture(0);
        click_rendered_provider_action(&mut fresh, &action);
        assert!(matches!(
            fresh.test_page(),
            TestPageRef::Providers(ProvidersPage::OAuthSetup { state, .. })
                if state.provider == OAuthProvider::Grok
                    && (state.pending || state.paste_focused)
        ));
    }

    let paste = SettingsPointerAction::Providers(ProvidersAction::OAuthOption(
        ProviderId("grok-oauth".into()),
        OAuthOption::ManualPaste,
    ));
    let (_tmp, mut fresh) = oauth_fixture(1);
    copy_visible_authorization_url(&mut fresh, 1);
    click_rendered_provider_action(&mut fresh, &paste);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::OAuthSetup { state, .. })
            if state.paste_focused
    ));

    let poll = SettingsPointerAction::Providers(ProvidersAction::OAuthOption(
        ProviderId("grok-oauth".into()),
        OAuthOption::Poll,
    ));
    let (_tmp, mut fresh) = oauth_fixture(1);
    copy_visible_authorization_url(&mut fresh, 2);
    click_rendered_provider_action(&mut fresh, &poll);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::OAuthSetup { state, .. })
            if state.pending
                && !state.paste_focused
                && state.status.as_ref().is_some_and(|status| {
                    status.as_ref().is_ok_and(|message| message.contains("Checking"))
                })
    ));

    let skip = SettingsPointerAction::Providers(ProvidersAction::OAuthOption(
        ProviderId("grok-oauth".into()),
        OAuthOption::SkipContinue,
    ));
    let (_tmp, mut fresh) = oauth_fixture(1);
    copy_visible_authorization_url(&mut fresh, 3);
    click_rendered_provider_action(&mut fresh, &skip);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::Edit(state))
            if state.provider_id == "grok-oauth"
    ));

    let (_tmp, mut acknowledge) =
        dialog_with_config(oauth_provider_config("grok-oauth", "oauth:test"));
    acknowledge.page = super::super::providers_page(standalone_oauth_page(
        OAuthProvider::Grok,
        OAuthFlowState::new_with_acknowledgement_for_test(OAuthProvider::Grok),
    ));
    let acknowledge_action = SettingsPointerAction::Providers(ProvidersAction::OAuthOption(
        ProviderId("grok-oauth".into()),
        OAuthOption::Acknowledge,
    ));
    click_rendered_provider_action(&mut acknowledge, &acknowledge_action);
    assert!(!actions(&acknowledge).contains(&acknowledge_action));

    let continue_action = SettingsPointerAction::Providers(ProvidersAction::OAuthOption(
        ProviderId("grok-oauth".into()),
        OAuthOption::Continue,
    ));
    let (_tmp, mut fresh) = oauth_fixture(2);
    click_rendered_provider_action(&mut fresh, &continue_action);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::Edit(state))
            if state.provider_id == "grok-oauth"
    ));
}

#[test]
fn pointer_codex_oauth_sources_render_and_dispatch_from_fresh_state() {
    use super::super::pointer_actions::{
        OAuthCopyKind, ProviderId, ProvidersAction, SettingsPointerAction,
    };

    let _guard = OAUTH_EFFECTS_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reset_oauth_effects(false);

    fn edit_fixture() -> (tempfile::TempDir, SettingsDialog) {
        let config = oauth_provider_config("codex-oauth", "oauth:test");
        let (tmp, mut dialog) = dialog_with_config(config);
        let entry = dialog.config.providers["codex-oauth"].clone();
        let mut state = EditState::new("codex-oauth".into(), entry);
        state.cursor = edit_menu_actions(&state.provider_id, &state.entry)
            .iter()
            .position(|action| *action == EditAction::OAuthAuth(OAuthProvider::Codex))
            .expect("Codex provider exposes its OAuth source");
        dialog.page = super::super::providers_page(ProvidersPage::Edit(state));
        (tmp, dialog)
    }

    fn oauth_fixture(kind: u8) -> (tempfile::TempDir, SettingsDialog) {
        let (tmp, mut dialog) =
            dialog_with_config(oauth_provider_config("codex-oauth", "oauth:test"));
        let mut state = OAuthFlowState::new_without_acknowledgement_with_effects_for_test(
            OAuthProvider::Codex,
            fake_oauth_effects(),
        );
        match kind {
            0 => {}
            1 => state.set_device_login_for_test(
                cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
                    "https://example.test/device",
                    "CODE-123",
                ),
            ),
            2 => state.logged_in = true,
            _ => unreachable!(),
        }
        dialog.page =
            super::super::providers_page(standalone_oauth_page(OAuthProvider::Codex, state));
        (tmp, dialog)
    }

    fn copy_visible_device_code(dialog: &mut SettingsDialog) {
        reset_oauth_effects(false);
        let _ = render_provider_rows(dialog, 110, 60);
        let actions = dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .filter_map(|target| match (&target.action, target.enabled) {
                (
                    super::super::shell::SettingsPointerAction::Page(
                        action @ SettingsPointerAction::Providers(ProvidersAction::CopyOAuth(
                            _,
                            OAuthCopyKind::DeviceCode,
                        )),
                    ),
                    true,
                ) => Some(action.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actions.len(),
            1,
            "each active Codex fixture must own exactly one device-code copy source"
        );
        let action = actions.into_iter().next().unwrap();
        let flow_id = match action {
            SettingsPointerAction::Providers(ProvidersAction::CopyOAuth(flow_id, _)) => flow_id,
            _ => unreachable!(),
        };
        click_rendered_provider_action(
            dialog,
            &SettingsPointerAction::Providers(ProvidersAction::CopyOAuth(
                flow_id,
                OAuthCopyKind::DeviceCode,
            )),
        );
        assert_eq!(
            oauth_effects_log(),
            vec![
                "copy:CODE-123".to_string(),
                "open:https://example.test/device".to_string(),
            ]
        );
        assert!(matches!(
            dialog.test_page(),
            TestPageRef::Providers(ProvidersPage::OAuthSetup { state, .. })
                if state.flow_id == flow_id
                    && state.status.as_ref().is_some_and(|status| status.as_deref() == Ok(
                        "copied device code (unverified — also reachable via the Open link above)"
                    ))
        ));
    }

    replay_special_provider_edit_actions("codex-oauth", edit_fixture);

    let begin = SettingsPointerAction::Providers(ProvidersAction::BeginOAuth(
        ProviderId("codex-oauth".into()),
        OAuthProvider::Codex,
    ));
    let (_tmp, mut fresh) = edit_fixture();
    click_rendered_provider_action(&mut fresh, &begin);
    assert!(
        matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::OAuthSetup { state, parent }) if state.provider == OAuthProvider::Codex && parent.provider_id == "codex-oauth")
    );

    for (kind, option) in [
        (0, OAuthOption::Login),
        (1, OAuthOption::Poll),
        (1, OAuthOption::SkipContinue),
        (2, OAuthOption::Continue),
    ] {
        let action = SettingsPointerAction::Providers(ProvidersAction::OAuthOption(
            ProviderId("codex-oauth".into()),
            option,
        ));
        let (_tmp, mut fresh) = oauth_fixture(kind);
        if kind == 1 {
            copy_visible_device_code(&mut fresh);
        }
        click_rendered_provider_action(&mut fresh, &action);
        match option {
            OAuthOption::Login => assert!(
                matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::OAuthSetup { state, .. }) if state.polling)
            ),
            OAuthOption::Poll => assert!(
                matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::OAuthSetup { state, .. }) if state.polling)
            ),
            OAuthOption::Continue | OAuthOption::SkipContinue => assert!(
                matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::Edit(state)) if state.provider_id == "codex-oauth")
            ),
            _ => unreachable!(),
        }
    }
}

#[test]
fn pointer_add_oauth_skip_continue_sources_save_from_fresh_state() {
    use super::super::pointer_actions::{ProvidersAction, SettingsPointerAction, WizardControlId};

    fn fixture(provider: OAuthProvider) -> (tempfile::TempDir, SettingsDialog) {
        let template_id = match provider {
            OAuthProvider::Grok => "grok-oauth",
            OAuthProvider::Codex => "codex-oauth",
        };
        let mut oauth = OAuthFlowState::new_without_acknowledgement_for_test(provider);
        match provider {
            OAuthProvider::Grok => {
                oauth.set_browser_session_for_test("https://example.test/oauth");
                oauth.pending = true;
            }
            OAuthProvider::Codex => oauth.set_device_login_for_test(
                cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
                    "https://example.test/device",
                    "CODE-123",
                ),
            ),
        }
        let (tmp, mut dialog) = dialog_with_config(ProvidersConfig::default());
        dialog.page = super::super::providers_page(ProvidersPage::Add(add_state_for_oauth(
            template_id,
            oauth,
        )));
        (tmp, dialog)
    }

    for provider in [OAuthProvider::Grok, OAuthProvider::Codex] {
        let template_id = match provider {
            OAuthProvider::Grok => "grok-oauth",
            OAuthProvider::Codex => "codex-oauth",
        };
        let (_tmp, source) = fixture(provider);
        let _ = render_provider_rows(&source, 110, 60);
        let actions = source
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .filter_map(|target| match (&target.action, target.enabled) {
                (
                    super::super::shell::SettingsPointerAction::Page(
                        action @ SettingsPointerAction::Providers(ProvidersAction::WizardControl(
                            _,
                            WizardControlId::OAuth(_),
                        )),
                    ),
                    true,
                ) => Some(action.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let expected_count = if provider == OAuthProvider::Grok {
            3
        } else {
            2
        };
        assert_eq!(actions.len(), expected_count, "pending Add OAuth controls");

        for action in actions {
            let option = match &action {
                SettingsPointerAction::Providers(ProvidersAction::WizardControl(
                    _,
                    WizardControlId::OAuth(option),
                )) => *option,
                _ => unreachable!(),
            };
            let (_tmp, mut fresh) = fixture(provider);
            click_rendered_provider_action(&mut fresh, &action);
            match (provider, option) {
                (OAuthProvider::Grok, OAuthOption::ManualPaste) => assert!(matches!(
                    fresh.test_page(),
                    TestPageRef::Providers(ProvidersPage::Add(state))
                        if state.oauth_auth.as_deref().is_some_and(|oauth| oauth.paste_focused)
                )),
                (OAuthProvider::Grok, OAuthOption::Poll) => assert!(matches!(
                    fresh.test_page(),
                    TestPageRef::Providers(ProvidersPage::Add(state))
                        if state.oauth_auth.as_deref().is_some_and(|oauth| {
                            oauth.pending
                                && !oauth.paste_focused
                                && oauth.status.as_ref().is_some_and(|status| {
                                    status.as_ref().is_ok_and(|message| message.contains("Checking"))
                                })
                        })
                )),
                (OAuthProvider::Codex, OAuthOption::Poll) => assert!(matches!(
                    fresh.test_page(),
                    TestPageRef::Providers(ProvidersPage::Add(state))
                        if state.oauth_auth.as_deref().is_some_and(|oauth| oauth.polling)
                )),
                (_, OAuthOption::SkipContinue) => {
                    assert!(fresh.config.providers.contains_key(template_id));
                    assert!(matches!(
                        fresh.test_page(),
                        TestPageRef::Providers(ProvidersPage::Add(state))
                            if state.saved_provider_id.as_deref() == Some(template_id)
                                && state.error.as_deref().is_some_and(|message| message.starts_with("saved."))
                    ));
                }
                other => panic!("unexpected pending Add OAuth control: {other:?}"),
            }
        }
    }
}

#[test]
fn pointer_model_lifecycle_sources_dispatch_by_stable_identity() {
    use super::super::pointer_actions::{ProvidersAction, SettingsPointerAction};

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let config = one_provider_config(None);
        let (tmp, mut dialog) = dialog_with_config(config);
        let mut entry = dialog.config.providers["p"].clone();
        entry.models = vec![model("stable-manual", true)];
        dialog.page = super::super::providers_page(ProvidersPage::Models {
            editor: Box::new(ModelEditor::new(None, entry.models.clone())),
            parent: Box::new(EditState::new("p".into(), entry)),
        });
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(
                        ProvidersAction::AddModel(_)
                        | ProvidersAction::RenameModel(_, _)
                        | ProvidersAction::DeleteModel(_, _)
                        | ProvidersAction::ModelSettings(_, _)
                        | ProvidersAction::RowEditor(
                            ProviderRowEditorAction::ModelOpen(_)
                            | ProviderRowEditorAction::ModelAdd
                            | ProviderRowEditorAction::ModelSave,
                        ),
                    ),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(actions.len(), 7, "complete model lifecycle is rendered");
    for action in actions {
        let (_tmp, mut fresh) = fixture();
        click_rendered_provider_action(&mut fresh, &action);
        match action {
            SettingsPointerAction::Providers(
                ProvidersAction::AddModel(_)
                | ProvidersAction::RenameModel(_, _)
                | ProvidersAction::RowEditor(ProviderRowEditorAction::ModelAdd),
            ) => assert!(matches!(
                fresh.test_page(),
                TestPageRef::Providers(ProvidersPage::Models { editor, .. })
                    if editor.is_editing()
            )),
            SettingsPointerAction::Providers(ProvidersAction::ModelSettings(_, ref model_id)) => {
                assert!(matches!(
                    fresh.test_page(),
                    TestPageRef::Providers(ProvidersPage::ModelSettings { models, parent, .. })
                        if parent.provider_id == "p"
                            && models.rows().iter().any(|row| row.id == model_id.0)
                ));
            }
            SettingsPointerAction::Providers(ProvidersAction::RowEditor(
                ProviderRowEditorAction::ModelOpen(ref model_id),
            )) => assert!(matches!(
                fresh.test_page(),
                TestPageRef::Providers(ProvidersPage::ModelSettings { models, parent, .. })
                    if parent.provider_id == "p"
                        && models.rows().iter().any(|row| row.id == model_id.0)
            )),
            SettingsPointerAction::Providers(ProvidersAction::RowEditor(
                ProviderRowEditorAction::ModelSave,
            )) => {
                assert!(matches!(
                    fresh.test_page(),
                    TestPageRef::Providers(ProvidersPage::Models { parent, .. })
                        if parent.status.as_deref().is_some_and(|status| status.starts_with("saved"))
                ));
                assert_eq!(
                    load_provider(&fresh.config_path, "p").models[0].id,
                    "stable-manual"
                );
            }
            SettingsPointerAction::Providers(ProvidersAction::DeleteModel(_, _)) => {
                assert!(
                    matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::Models { editor, .. }) if editor.rows().len() == 1)
                );
                click_rendered_provider_action(&mut fresh, &action);
                assert!(
                    matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::Models { editor, .. }) if editor.rows().is_empty())
                );
            }
            other => panic!("unexpected model lifecycle action: {other:?}"),
        }
    }
}

#[test]
fn pointer_add_provider_id_field_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{ProvidersAction, SettingsPointerAction, WizardControlId};

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let (tmp, mut dialog) = dialog_with_config(ProvidersConfig::default());
        let mut state = AddState::new();
        state.enter_template_for_test(template_cursor("anthropic"));
        dialog.handle_add_key(press(KeyCode::Enter), &mut state);
        assert!(state.is_step("id"));
        dialog.page = super::super::providers_page(ProvidersPage::Add(state));
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let action = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::WizardControl(
                        step,
                        WizardControlId::EditText,
                    )),
                ),
                true,
            ) if step.source_id() == "id" => Some(action.clone()),
            _ => None,
        })
        .expect("provider ID field publishes its wizard edit identity");
    let (_tmp, mut fresh) = fixture();
    click_rendered_provider_action(&mut fresh, &action);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::Add(state))
            if state.is_step("id") && state.id_field.text() == "anthropic"
    ));
}

#[test]
fn pointer_add_url_field_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{ProvidersAction, SettingsPointerAction, WizardControlId};

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let (tmp, mut dialog) = dialog_with_config(ProvidersConfig::default());
        let mut state = AddState::new();
        state.enter_template_for_test(template_cursor("anthropic"));
        dialog.handle_add_key(press(KeyCode::Enter), &mut state);
        dialog.handle_add_key(press(KeyCode::Enter), &mut state);
        assert!(state.is_step("url"));
        dialog.page = super::super::providers_page(ProvidersPage::Add(state));
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let action = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::WizardControl(
                        step,
                        WizardControlId::EditText,
                    )),
                ),
                true,
            ) if step.source_id() == "url" => Some(action.clone()),
            _ => None,
        })
        .expect("provider URL field publishes its wizard edit identity");
    let (_tmp, mut fresh) = fixture();
    click_rendered_provider_action(&mut fresh, &action);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::Add(state))
            if state.is_step("url") && !state.url_field.text().is_empty()
    ));
}

#[test]
fn pointer_add_headers_existing_row_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{ProvidersAction, SettingsPointerAction, WizardControlId};

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let (tmp, mut dialog) = dialog_with_config(ProvidersConfig::default());
        let template = templates::template_by_id("anthropic").unwrap();
        let mut state = AddState::new();
        state.template = Some(template);
        state.id_field.set(template.id);
        state.url_field.set(template.url);
        state.headers = Box::new(HeaderEditor::new(
            vec![HeaderSpec {
                name: "X-Stable".into(),
                value: "stable-value".into(),
            }],
            true,
        ));
        state.run.return_to("headers").unwrap();
        dialog.page = super::super::providers_page(ProvidersPage::Add(state));
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::WizardControl(
                        _,
                        control @ (WizardControlId::Header(_)
                        | WizardControlId::AddHeader
                        | WizardControlId::ContinueHeaders),
                    )),
                ),
                true,
            ) if matches!(control, WizardControlId::Header(name) if name.0 == "X-Stable")
                || matches!(
                    control,
                    WizardControlId::AddHeader | WizardControlId::ContinueHeaders
                ) =>
            {
                Some(action.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(actions.len(), 3, "Headers publishes row, Add, and Continue");
    for action in actions {
        let control = match &action {
            SettingsPointerAction::Providers(ProvidersAction::WizardControl(_, control)) => control,
            _ => unreachable!(),
        };
        let (_tmp, mut fresh) = fixture();
        click_rendered_provider_action(&mut fresh, &action);
        match control {
            WizardControlId::Header(_) | WizardControlId::AddHeader => assert!(matches!(
                fresh.test_page(),
                TestPageRef::Providers(ProvidersPage::Add(state))
                    if state.is_step("headers") && state.headers.is_editing()
            )),
            WizardControlId::ContinueHeaders => {
                assert!(fresh.config.providers.contains_key("anthropic"));
                assert!(matches!(
                    fresh.test_page(),
                    TestPageRef::Providers(ProvidersPage::Add(state))
                        if state.saved_provider_id.as_deref() == Some("anthropic")
                            && state.headers.rows().iter().any(|row| row.name == "X-Stable")
                ));
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn pointer_add_auth_method_choices_render_and_dispatch_from_fresh_state() {
    use super::super::pointer_actions::{
        ProvidersAction, SettingsPointerAction, WizardAuthMethod, WizardControlId,
    };

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let (tmp, mut dialog) = dialog_with_config(ProvidersConfig::default());
        let template = templates::template_by_id("anthropic").unwrap();
        let mut state = AddState::new();
        state.template = Some(template);
        state.id_field.set(template.id);
        state.url_field.set(template.url);
        state.run.return_to("auth-method").unwrap();
        dialog.page = super::super::providers_page(ProvidersPage::Add(state));
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::WizardControl(
                        _,
                        WizardControlId::AuthMethod(_),
                    )),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(actions.len(), 3, "all auth methods are rendered");
    for action in actions {
        let method = match &action {
            SettingsPointerAction::Providers(ProvidersAction::WizardControl(
                _,
                WizardControlId::AuthMethod(method),
            )) => *method,
            _ => unreachable!(),
        };
        let (_tmp, mut fresh) = fixture();
        click_rendered_provider_action(&mut fresh, &action);
        let expected_step = match method {
            WizardAuthMethod::PasteKey => "api-key",
            WizardAuthMethod::EnvVar => "env-var",
            WizardAuthMethod::AdvancedHeaders => "headers",
        };
        assert!(matches!(
            fresh.test_page(),
            TestPageRef::Providers(ProvidersPage::Add(state))
                if state.is_step(expected_step)
        ));
    }
}

#[test]
fn pointer_add_api_key_field_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{ProvidersAction, SettingsPointerAction, WizardControlId};

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let (tmp, mut dialog) = dialog_with_config(ProvidersConfig::default());
        let template = templates::template_by_id("anthropic").unwrap();
        let mut state = AddState::new();
        state.template = Some(template);
        state.id_field.set(template.id);
        state.url_field.set(template.url);
        state.run.return_to("auth-method").unwrap();
        dialog.handle_add_key(press(KeyCode::Enter), &mut state);
        assert!(state.is_step("api-key"));
        state.api_key_field.set("sk-stable-secret");
        dialog.page = super::super::providers_page(ProvidersPage::Add(state));
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let action = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::WizardControl(
                        step,
                        WizardControlId::EditText,
                    )),
                ),
                true,
            ) if step.source_id() == "api-key" => Some(action.clone()),
            _ => None,
        })
        .expect("API key field publishes its wizard edit identity");
    let (_tmp, mut fresh) = fixture();
    click_rendered_provider_action(&mut fresh, &action);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::Add(state))
            if state.is_step("api-key") && state.api_key_field.text() == "sk-stable-secret"
    ));
}

#[test]
fn pointer_add_env_var_field_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{ProvidersAction, SettingsPointerAction, WizardControlId};

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let (tmp, mut dialog) = dialog_with_config(ProvidersConfig::default());
        let template = templates::template_by_id("anthropic").unwrap();
        let mut state = AddState::new();
        state.template = Some(template);
        state.id_field.set(template.id);
        state.url_field.set(template.url);
        state.run.return_to("auth-method").unwrap();
        state.auth_method_cursor = 1;
        dialog.handle_add_key(press(KeyCode::Enter), &mut state);
        assert!(state.is_step("env-var"));
        state.env_var_field.set("ANTHROPIC_API_KEY_STABLE");
        dialog.page = super::super::providers_page(ProvidersPage::Add(state));
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let action = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::WizardControl(
                        step,
                        WizardControlId::EditText,
                    )),
                ),
                true,
            ) if step.source_id() == "env-var" => Some(action.clone()),
            _ => None,
        })
        .expect("environment variable field publishes its wizard edit identity");
    let (_tmp, mut fresh) = fixture();
    click_rendered_provider_action(&mut fresh, &action);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::Add(state))
            if state.is_step("env-var")
                && state.env_var_field.text() == "ANTHROPIC_API_KEY_STABLE"
    ));
}

#[test]
fn pointer_add_test_key_choices_render_and_dispatch_from_fresh_state() {
    use super::super::pointer_actions::{
        ProvidersAction, SettingsPointerAction, WizardControlId, WizardTestChoice,
    };

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let template = templates::template_by_id("anthropic").unwrap();
        let mut config = ProvidersConfig::default();
        config
            .providers
            .insert("anthropic".into(), ProviderEntry::default());
        let (tmp, mut dialog) = dialog_with_config(config);
        let mut state = AddState::new();
        state.template = Some(template);
        state.id_field.set(template.id);
        state.url_field.set(template.url);
        state.saved_provider_id = Some("anthropic".into());
        state.run.return_to("test-key-choice").unwrap();
        dialog.page = super::super::providers_page(ProvidersPage::Add(state));
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::WizardControl(
                        _,
                        WizardControlId::TestChoice(_),
                    )),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(actions.len(), 2, "both test-key choices are rendered");
    for action in actions {
        let choice = match &action {
            SettingsPointerAction::Providers(ProvidersAction::WizardControl(
                _,
                WizardControlId::TestChoice(choice),
            )) => *choice,
            _ => unreachable!(),
        };
        let (_tmp, mut fresh) = fixture();
        click_rendered_provider_action(&mut fresh, &action);
        match choice {
            WizardTestChoice::TestKey => assert!(matches!(
                fresh.test_page(),
                TestPageRef::Providers(ProvidersPage::Add(state))
                    if state.fetch.is_some()
                        && state.error.as_deref() == Some("Testing key via /models…")
                        && !state.is_step("test-key-choice")
            )),
            WizardTestChoice::SkipTest => assert!(matches!(
                fresh.test_page(),
                TestPageRef::Providers(ProvidersPage::Add(state))
                    if state.is_step("test-skipped")
                        && state.error.as_deref().is_some_and(|message| message.contains("unverified"))
            )),
        }
    }
}

#[test]
fn pointer_add_grok_login_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{ProvidersAction, SettingsPointerAction, WizardControlId};

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let (tmp, mut dialog) = dialog_with_config(ProvidersConfig::default());
        let oauth = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
        dialog.page = super::super::providers_page(ProvidersPage::Add(add_state_for_oauth(
            "grok-oauth",
            oauth,
        )));
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let login = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::WizardControl(
                        ProviderWizardStep::GrokOAuth,
                        WizardControlId::OAuth(OAuthOption::Login),
                    )),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .expect("logged-out Grok wizard renders Login");
    let (_tmp, mut fresh) = fixture();
    click_rendered_provider_action(&mut fresh, &login);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::Add(state))
            if state.oauth_auth.as_deref().is_some_and(|oauth| {
                oauth.pending
                    && !oauth.paste_focused
                    && oauth.status.as_ref().is_some_and(|status| {
                        status.as_ref().is_ok_and(|message| message.contains("Preparing"))
                    })
            })
    ));
}

#[test]
fn pointer_add_codex_login_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{ProvidersAction, SettingsPointerAction, WizardControlId};

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let (tmp, mut dialog) = dialog_with_config(ProvidersConfig::default());
        let mut oauth = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
        // This source represents the Login row regardless of credentials on
        // the machine running the exhaustive pointer matrix.
        oauth.logged_in = false;
        dialog.page = super::super::providers_page(ProvidersPage::Add(add_state_for_oauth(
            "codex-oauth",
            oauth,
        )));
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let login = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::WizardControl(
                        ProviderWizardStep::CodexOAuth,
                        WizardControlId::OAuth(OAuthOption::Login),
                    )),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .expect("logged-out Codex wizard renders Login");

    let (_tmp, mut fresh) = fixture();
    click_rendered_provider_action(&mut fresh, &login);
    assert!(matches!(
        fresh.pending_oauth_action.take(),
        Some(OAuthFlowRequest {
            provider: OAuthProvider::Codex,
            op: OAuthFlowOp::Begin,
        })
    ));
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::Add(state))
            if state.oauth_auth.as_deref().is_some_and(|oauth| {
                oauth.polling
                    && oauth.device_login().is_none()
                    && oauth.status.as_ref().is_some_and(|status| {
                        status.as_ref().is_ok_and(|message| {
                            message == "Requesting Codex device code..."
                        })
                    })
            })
    ));
}

#[test]
fn pointer_add_grok_continue_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{ProvidersAction, SettingsPointerAction, WizardControlId};

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let (tmp, mut dialog) = dialog_with_config(ProvidersConfig::default());
        let mut oauth = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
        oauth.logged_in = true;
        dialog.page = super::super::providers_page(ProvidersPage::Add(add_state_for_oauth(
            "grok-oauth",
            oauth,
        )));
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let action = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::WizardControl(
                        _,
                        WizardControlId::OAuth(OAuthOption::Continue),
                    )),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .expect("logged-in Grok wizard renders Continue");
    let (_tmp, mut fresh) = fixture();
    click_rendered_provider_action(&mut fresh, &action);
    assert!(fresh.config.providers.contains_key("grok-oauth"));
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::Add(state))
            if state.saved_provider_id.as_deref() == Some("grok-oauth")
                && state.error.as_deref().is_some_and(|message| message.starts_with("saved."))
    ));
}

#[test]
fn pointer_add_codex_continue_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{ProvidersAction, SettingsPointerAction, WizardControlId};

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let (tmp, mut dialog) = dialog_with_config(ProvidersConfig::default());
        let mut oauth = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
        oauth.logged_in = true;
        dialog.page = super::super::providers_page(ProvidersPage::Add(add_state_for_oauth(
            "codex-oauth",
            oauth,
        )));
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let action = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::WizardControl(
                        ProviderWizardStep::CodexOAuth,
                        WizardControlId::OAuth(OAuthOption::Continue),
                    )),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .expect("logged-in Codex wizard renders Continue");
    assert_eq!(
        super::super::pointer_action_fixtures::key_for(&action),
        super::super::pointer_action_fixtures::ActionFixtureKey::Providers(
            super::super::pointer_action_fixtures::ProvidersFixture::WizardCodexContinue,
        )
    );

    let (_tmp, mut fresh) = fixture();
    click_rendered_provider_action(&mut fresh, &action);
    assert!(fresh.config.providers.contains_key("codex-oauth"));
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::Add(state))
            if state.saved_provider_id.as_deref() == Some("codex-oauth")
                && state.error.as_deref().is_some_and(|message| message.starts_with("saved."))
    ));
    assert_eq!(
        load_provider(&fresh.config_path, "codex-oauth").auth,
        Some(AuthKind::OAuth)
    );
}

#[test]
fn pointer_add_grok_acknowledge_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{ProvidersAction, SettingsPointerAction, WizardControlId};

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let (tmp, mut dialog) = dialog_with_config(ProvidersConfig::default());
        let oauth = OAuthFlowState::new_with_acknowledgement_for_test(OAuthProvider::Grok);
        dialog.page = super::super::providers_page(ProvidersPage::Add(add_state_for_oauth(
            "grok-oauth",
            oauth,
        )));
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let action = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::WizardControl(
                        ProviderWizardStep::GrokOAuth,
                        WizardControlId::OAuth(OAuthOption::Acknowledge),
                    )),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .expect("Grok wizard renders acknowledgement gate");
    let (_tmp, mut fresh) = fixture();
    click_rendered_provider_action(&mut fresh, &action);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::Add(state))
            if state.is_step("grok-oauth")
                && state.oauth_auth.as_deref().is_some_and(|oauth| {
                    oauth.status.as_ref().is_some_and(|status| {
                        status.as_ref().is_ok_and(|message| message.contains("acknowledged"))
                    })
                })
    ));
    let _ = render_provider_rows(&fresh, 110, 60);
    assert!(
        !fresh.pointer_surface.targets.borrow().iter().any(|target| {
            target.enabled
                && target.action == super::super::shell::SettingsPointerAction::Page(action.clone())
        })
    );
}

#[test]
fn pointer_add_codex_acknowledge_renders_and_dispatches_from_fresh_state() {
    use super::super::pointer_actions::{ProvidersAction, SettingsPointerAction, WizardControlId};

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let (tmp, mut dialog) = dialog_with_config(ProvidersConfig::default());
        let oauth = OAuthFlowState::new_with_acknowledgement_for_test(OAuthProvider::Codex);
        dialog.page = super::super::providers_page(ProvidersPage::Add(add_state_for_oauth(
            "codex-oauth",
            oauth,
        )));
        (tmp, dialog)
    }

    let (_tmp, source) = fixture();
    let _ = render_provider_rows(&source, 110, 60);
    let action = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ SettingsPointerAction::Providers(ProvidersAction::WizardControl(
                        ProviderWizardStep::CodexOAuth,
                        WizardControlId::OAuth(OAuthOption::Acknowledge),
                    )),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .expect("Codex wizard renders acknowledgement gate");
    assert_eq!(
        super::super::pointer_action_fixtures::key_for(&action),
        super::super::pointer_action_fixtures::ActionFixtureKey::Providers(
            super::super::pointer_action_fixtures::ProvidersFixture::WizardCodexAcknowledge,
        )
    );

    let (_tmp, mut fresh) = fixture();
    click_rendered_provider_action(&mut fresh, &action);
    assert!(matches!(
        fresh.test_page(),
        TestPageRef::Providers(ProvidersPage::Add(state))
            if state.is_step("codex-oauth")
                && state.oauth_auth.as_deref().is_some_and(|oauth| {
                    oauth.status.as_ref().is_some_and(|status| {
                        status.as_ref().is_ok_and(|message| message.contains("acknowledged"))
                    })
                })
    ));
    let _ = render_provider_rows(&fresh, 110, 60);
    assert!(
        !fresh.pointer_surface.targets.borrow().iter().any(|target| {
            target.enabled
                && target.action == super::super::shell::SettingsPointerAction::Page(action.clone())
        })
    );
}

fn edit_fixture(config: ProvidersConfig) -> (tempfile::TempDir, SettingsDialog) {
    let (tmp, mut dialog) = dialog_with_config(config);
    let entry = dialog.config.providers["p"].clone();
    dialog.page =
        super::super::providers_page(ProvidersPage::Edit(EditState::new("p".into(), entry)));
    (tmp, dialog)
}

fn deep_fetch_fixture(config: ProvidersConfig) -> (tempfile::TempDir, SettingsDialog) {
    let (tmp, mut dialog) = dialog_with_config(config);
    let entry = dialog.config.providers["p"].clone();
    let state = DeepFetchState::prepare(&dialog.config_path, "p").expect("deep-fetch fixture");
    dialog.page = super::super::providers_page(ProvidersPage::DeepFetch {
        state,
        parent: Box::new(EditState::new("p".into(), entry)),
    });
    (tmp, dialog)
}

fn descend_provider(
    dialog: &mut SettingsDialog,
    requested: &'static str,
    matches: impl Fn(&super::super::pointer_actions::ProvidersAction) -> bool,
) {
    if let Some(ProvidersPage::Edit(state)) = dialog.page.downcast_mut::<ProvidersPage>()
        && let Some(index) = edit_menu_actions(&state.provider_id, &state.entry)
            .iter()
            .position(|source| {
                let super::super::pointer_actions::SettingsPointerAction::Providers(action) =
                    provider_edit_pointer_action(state, *source)
                else {
                    return false;
                };
                matches(&action)
            })
    {
        state.cursor = index;
    }
    let _ = render_provider_rows(dialog, 110, 60);
    let target = dialog.pointer_surface.targets.borrow().iter().find(|target| {
        matches!(&target.action, super::super::shell::SettingsPointerAction::Page(super::super::pointer_actions::SettingsPointerAction::Providers(action)) if target.enabled && matches(action))
    }).cloned().unwrap_or_else(|| panic!("nested provider source action `{requested}` was not rendered"));
    for kind in [
        crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
        crossterm::event::MouseEventKind::Up(crossterm::event::MouseButton::Left),
    ] {
        dialog.handle_pointer(super::super::tests::settings_mouse(
            kind,
            target.rect.x,
            target.rect.y,
        ));
    }
}

fn nested_provider_fixture(
    config: ProvidersConfig,
    path: usize,
) -> (tempfile::TempDir, SettingsDialog) {
    let (tmp, mut dialog) = edit_fixture(config);
    match path {
        0 => descend_provider(&mut dialog, "EditAction::Models", |action| {
            matches!(
                action,
                super::super::pointer_actions::ProvidersAction::ManageModels(_)
            )
        }),
        1 => descend_provider(&mut dialog, "EditAction::Settings", |action| {
            matches!(
                action,
                super::super::pointer_actions::ProvidersAction::ProviderSettings(_)
            )
        }),
        2 => {
            descend_provider(&mut dialog, "EditAction::Models", |action| {
                matches!(
                    action,
                    super::super::pointer_actions::ProvidersAction::ManageModels(_)
                )
            });
            descend_provider(&mut dialog, "ModelEditor::ModelOpen", |action| {
                matches!(
                    action,
                    super::super::pointer_actions::ProvidersAction::RowEditor(
                        ProviderRowEditorAction::ModelOpen(_)
                    )
                )
            });
        }
        _ => unreachable!("nested source path"),
    }
    (tmp, dialog)
}

#[test]
fn pointer_reachable_nested_surfaces_render_and_dispatch() {
    use super::super::pointer_actions::ProvidersAction;
    let config = one_provider_config(None);
    for path in [0, 1, 2, 3] {
        let (_tmp, dialog) = if path == 3 {
            let (tmp, mut dialog) = edit_fixture(config.clone());
            descend_provider(&mut dialog, "EditAction::DeepFetch", |action| {
                matches!(action, ProvidersAction::DeepFetchConfirm(_))
            });
            (tmp, dialog)
        } else {
            nested_provider_fixture(config.clone(), path)
        };
        let _ = render_provider_rows(&dialog, 110, 60);
        let actions = dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .filter_map(|target| match (&target.action, target.enabled) {
                (
                    super::super::shell::SettingsPointerAction::Page(
                        action @ super::super::pointer_actions::SettingsPointerAction::Providers(_),
                    ),
                    true,
                ) => Some(action.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        // Each nested source is real and rendered. Its actions are covered by
        // the dedicated editor matrices; this traversal makes the concrete
        // variant itself part of the strict surface inventory.
        assert!(
            !actions.is_empty(),
            "nested provider surface {path} has no enabled controls"
        );
        if path < 3 {
            for action in actions {
                let (_tmp, mut fresh) = nested_provider_fixture(config.clone(), path);
                click_rendered_provider_action(&mut fresh, &action);
                match &action {
                    super::super::pointer_actions::SettingsPointerAction::Providers(
                        ProvidersAction::RowEditor(ProviderRowEditorAction::ModelOpen(id)),
                    ) => assert!(matches!(
                        fresh.test_page(),
                        TestPageRef::Providers(ProvidersPage::ModelSettings { models, .. })
                            if models.rows().iter().any(|row| row.id == id.0)
                    )),
                    super::super::pointer_actions::SettingsPointerAction::Providers(
                        ProvidersAction::RowEditor(ProviderRowEditorAction::ModelAdd),
                    ) => assert!(matches!(
                        fresh.test_page(),
                        TestPageRef::Providers(ProvidersPage::Models { editor, .. })
                            if !editor.is_browsing()
                    )),
                    super::super::pointer_actions::SettingsPointerAction::Providers(
                        ProvidersAction::RowEditor(ProviderRowEditorAction::ModelSave),
                    ) => assert!(matches!(
                        fresh.test_page(),
                        TestPageRef::Providers(ProvidersPage::Models { .. })
                    )),
                    super::super::pointer_actions::SettingsPointerAction::Providers(
                        ProvidersAction::RowEditor(ProviderRowEditorAction::SettingSave),
                    ) => assert!(matches!(
                        fresh.test_page(),
                        TestPageRef::Providers(ProvidersPage::ProviderSettings { .. })
                            | TestPageRef::Providers(ProvidersPage::ModelSettings { .. })
                    )),
                    super::super::pointer_actions::SettingsPointerAction::Providers(
                        ProvidersAction::RowEditor(ProviderRowEditorAction::SettingEdit(_)),
                    ) => assert!(matches!(
                        fresh.test_page(),
                        TestPageRef::Providers(ProvidersPage::ProviderSettings { .. })
                            | TestPageRef::Providers(ProvidersPage::ModelSettings { .. })
                    )),
                    _ => {}
                }
            }
        } else {
            for action in actions {
                let super::super::pointer_actions::SettingsPointerAction::Providers(
                    ProvidersAction::DeepFetchChoice(_, choice),
                ) = &action
                else {
                    continue;
                };
                let choice = *choice;
                let (_tmp, mut fresh) = deep_fetch_fixture(config.clone());
                click_rendered_provider_action(&mut fresh, &action);
                match choice {
                    super::super::pointer_actions::DeepFetchChoice::Fetch => {
                        assert!(matches!(
                            fresh.test_page(),
                            TestPageRef::Providers(ProvidersPage::DeepFetch { state, .. })
                                if state.is_running()
                        ));
                    }
                    super::super::pointer_actions::DeepFetchChoice::Cancel => {
                        assert!(matches!(
                            fresh.test_page(),
                            TestPageRef::Providers(ProvidersPage::Edit(state))
                                if state.status.as_deref() == Some("deep fetch cancelled")
                        ));
                    }
                }
            }
        }
    }
}

fn headers_fixture(config: ProvidersConfig) -> (tempfile::TempDir, SettingsDialog) {
    let (tmp, mut dialog) = dialog_with_config(config);
    let entry = dialog.config.providers["p"].clone();
    dialog.page = super::super::providers_page(ProvidersPage::Headers {
        editor: HeaderEditor::new(
            vec![HeaderSpec {
                name: "X-Test".into(),
                value: "one".into(),
            }],
            false,
        ),
        parent: Box::new(EditState::new("p".into(), entry)),
    });
    (tmp, dialog)
}

#[test]
fn pointer_headers_surface_dispatches_every_enabled_control() {
    let config = one_provider_config(None);
    let (_tmp, source) = headers_fixture(config.clone());
    let _ = render_provider_rows(&source, 110, 60);
    let actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ super::super::pointer_actions::SettingsPointerAction::Providers(_),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(!actions.is_empty(), "Headers must render enabled controls");
    for action in actions {
        let (_tmp, mut dialog) = headers_fixture(config.clone());
        click_rendered_provider_action(&mut dialog, &action);
    }
}

fn click_rendered_provider_action(
    dialog: &mut SettingsDialog,
    action: &super::super::pointer_actions::SettingsPointerAction,
) {
    let _ = render_provider_rows(dialog, 110, 60);
    let target = dialog
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find(|target| {
            target.enabled
                && target.action == super::super::shell::SettingsPointerAction::Page(action.clone())
        })
        .cloned()
        .expect("source-derived provider action is rendered");
    for kind in [
        crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
        crossterm::event::MouseEventKind::Up(crossterm::event::MouseButton::Left),
    ] {
        dialog.handle_pointer(super::super::tests::settings_mouse(
            kind,
            target.rect.x,
            target.rect.y,
        ));
    }
}

#[test]
fn pointer_enabled_list_and_edit_actions_dispatch_through_dialog() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("provider pointer test runtime");
    let _runtime_guard = runtime.enter();
    pointer_enabled_list_and_edit_actions_dispatch_through_dialog_impl();
}

fn pointer_enabled_list_and_edit_actions_dispatch_through_dialog_impl() {
    // Several visible provider controls intentionally start async-backed
    // production effects (model refetch/OAuth). Keep this synchronous matrix
    // deterministic while still entering the real reducers: spawned work is
    // owned by the caller's runtime and cancelled when the fixture completes.
    let _guard = OAUTH_EFFECTS_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let config = one_provider_config(None);
    let provider_id = "p".to_string();
    let entry = config.providers[&provider_id].clone();

    for edit in [false, true] {
        let (_tmp, mut source) = dialog_with_config(config.clone());
        source.page = if edit {
            super::super::providers_page(ProvidersPage::Edit(EditState::new(
                provider_id.clone(),
                entry.clone(),
            )))
        } else {
            super::super::providers_page(ProvidersPage::List {
                cursor: 1,
                status: None,
                delete_pending: false,
            })
        };
        let _ = render_provider_rows(&source, 110, 60);
        let actions = source
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .filter_map(|target| match (&target.action, target.enabled) {
                (
                    super::super::shell::SettingsPointerAction::Page(
                        action @ super::super::pointer_actions::SettingsPointerAction::Providers(_),
                    ),
                    true,
                ) => Some(action.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(!actions.is_empty());
        for action in actions {
            let (_tmp, mut dialog) = dialog_with_config(config.clone());
            dialog.page = if edit {
                super::super::providers_page(ProvidersPage::Edit(EditState::new(
                    provider_id.clone(),
                    entry.clone(),
                )))
            } else {
                super::super::providers_page(ProvidersPage::List {
                    cursor: 1,
                    status: None,
                    delete_pending: false,
                })
            };
            click_rendered_provider_action(&mut dialog, &action);
        }
    }

    let (_tmp, mut add_source) = dialog_with_config(config.clone());
    add_source.page = super::super::providers_page(ProvidersPage::Add(AddState::new()));
    let _ = render_provider_rows(&add_source, 110, 60);
    let add_actions = add_source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ super::super::pointer_actions::SettingsPointerAction::Providers(_),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        !add_actions.is_empty(),
        "Add wizard must render enabled controls"
    );
    for action in add_actions {
        let (_tmp, mut dialog) = dialog_with_config(config.clone());
        dialog.page = super::super::providers_page(ProvidersPage::Add(AddState::new()));
        click_rendered_provider_action(&mut dialog, &action);
    }

    let oauth = oauth_provider_config("codex-oauth", "oauth:test");
    let (_tmp, mut source) = dialog_with_config(oauth.clone());
    source.page = super::super::providers_page(standalone_oauth_page(
        OAuthProvider::Codex,
        OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex),
    ));
    let _ = render_provider_rows(&source, 110, 60);
    let actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ super::super::pointer_actions::SettingsPointerAction::Providers(
                        super::super::pointer_actions::ProvidersAction::OAuthOption(_, _),
                    ),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        !actions.is_empty(),
        "OAuth source row must render its setup action"
    );
    for action in actions {
        let (_tmp, mut dialog) = dialog_with_config(oauth.clone());
        dialog.page = super::super::providers_page(standalone_oauth_page(
            OAuthProvider::Codex,
            OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex),
        ));
        click_rendered_provider_action(&mut dialog, &action);
    }

    // The Codex device-code state publishes Poll rather than Login. Exercise
    // that independently from the initial OAuth source above.
    let (_tmp, mut poll_source) = dialog_with_config(oauth.clone());
    reset_oauth_effects(false);
    let mut poll_state = OAuthFlowState::new_without_acknowledgement_with_effects_for_test(
        OAuthProvider::Codex,
        fake_oauth_effects(),
    );
    poll_state.set_device_login_for_test(cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
        "https://example.test/device",
        "CODE-123",
    ));
    poll_source.page =
        super::super::providers_page(standalone_oauth_page(OAuthProvider::Codex, poll_state));
    let poll = super::super::pointer_actions::SettingsPointerAction::Providers(
        super::super::pointer_actions::ProvidersAction::OAuthOption(
            super::super::pointer_actions::ProviderId("codex-oauth".into()),
            OAuthOption::Poll,
        ),
    );
    let _ = render_provider_rows(&poll_source, 110, 60);
    assert!(
        poll_source
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .any(|target| {
                target.enabled
                    && target.action
                        == super::super::shell::SettingsPointerAction::Page(poll.clone())
            })
    );
    let copy_actions = poll_source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ super::super::pointer_actions::SettingsPointerAction::Providers(
                        super::super::pointer_actions::ProvidersAction::CopyOAuth(
                            _,
                            super::super::pointer_actions::OAuthCopyKind::DeviceCode,
                        ),
                    ),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        copy_actions.len(),
        1,
        "the pending Codex source owns one device-code copy identity"
    );
    let copy = copy_actions.into_iter().next().unwrap();
    click_rendered_provider_action(&mut poll_source, &copy);
    assert_eq!(
        oauth_effects_log(),
        vec![
            "copy:CODE-123".to_string(),
            "open:https://example.test/device".to_string(),
        ]
    );
    assert!(matches!(
        poll_source.test_page(),
        TestPageRef::Providers(ProvidersPage::OAuthSetup { state, .. })
            if matches!(
                copy,
                super::super::pointer_actions::SettingsPointerAction::Providers(
                    super::super::pointer_actions::ProvidersAction::CopyOAuth(flow_id, _)
                ) if state.flow_id == flow_id
            )
                && state.status.as_ref().is_some_and(|status| status.as_deref() == Ok(
                    "copied device code (unverified — also reachable via the Open link above)"
                ))
    ));
    click_rendered_provider_action(&mut poll_source, &poll);
    assert!(matches!(
        poll_source.test_page(),
        TestPageRef::Providers(ProvidersPage::OAuthSetup { state, .. }) if state.polling
    ));
}

fn pointer_delete_choice_fixture() -> (tempfile::TempDir, SettingsDialog) {
    let mut cfg = one_provider_config(None);
    cfg.providers.get_mut("p").unwrap().headers = vec![HeaderSpec {
        name: "Authorization".into(),
        value: "$secret:p".into(),
    }];
    let (tmp, mut dialog) = dialog_with_config(cfg);
    let store_path = tmp.path().join("credentials.json");
    dialog.credential_store_path = Some(store_path.clone());
    let mut store = cockpit_core::credentials::CredentialStore::open(store_path).unwrap();
    store.set_named_secret("p", "sk-provider-secret-value");
    store.save().unwrap();
    let entry = dialog.config.providers["p"].clone();
    dialog.page =
        super::super::providers_page(ProvidersPage::Edit(EditState::new("p".into(), entry)));
    click_rendered_provider_action(
        &mut dialog,
        &super::super::pointer_actions::SettingsPointerAction::Providers(
            super::super::pointer_actions::ProvidersAction::BeginDelete(
                super::super::pointer_actions::ProviderId("p".into()),
            ),
        ),
    );
    (tmp, dialog)
}

#[test]
pub(crate) fn pointer_delete_confirmation_is_rendered_and_reduced() {
    let cfg = one_provider_config(None);
    let provider_id = cfg.providers.keys().next().unwrap().clone();
    let entry = cfg.providers[&provider_id].clone();
    let (_tmp, mut dialog) = dialog_with_config(cfg);
    dialog.page = super::super::providers_page(ProvidersPage::Edit(EditState::new(
        provider_id.clone(),
        entry,
    )));
    let _ = render_provider_rows(&dialog, 100, 40);
    let begin = dialog
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find(|target| {
            target.action
                == super::super::shell::SettingsPointerAction::Page(
                    super::super::pointer_actions::SettingsPointerAction::Providers(
                        super::super::pointer_actions::ProvidersAction::BeginDelete(
                            super::super::pointer_actions::ProviderId(provider_id.clone()),
                        ),
                    ),
                )
        })
        .cloned()
        .expect("rendered provider delete arm target");
    dialog.handle_pointer(super::super::tests::settings_mouse(
        crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
        begin.rect.x,
        begin.rect.y,
    ));
    dialog.handle_pointer(super::super::tests::settings_mouse(
        crossterm::event::MouseEventKind::Up(crossterm::event::MouseButton::Left),
        begin.rect.x,
        begin.rect.y,
    ));
    let _ = render_provider_rows(&dialog, 100, 40);
    let cancel = dialog
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find(|target| {
            matches!(
                &target.action,
                super::super::shell::SettingsPointerAction::Page(
                    super::super::pointer_actions::SettingsPointerAction::Providers(
                        super::super::pointer_actions::ProvidersAction::Delete(
                            _,
                            super::super::pointer_actions::ProviderDeleteChoice::Cancel
                        )
                    )
                )
            )
        })
        .cloned()
        .expect("rendered provider delete cancellation target");
    dialog.handle_pointer(super::super::tests::settings_mouse(
        crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
        cancel.rect.x,
        cancel.rect.y,
    ));
    assert!(matches!(
        dialog.test_page(),
        TestPageRef::Providers(ProvidersPage::Edit(state)) if !state.delete_pending
    ));

    let (_tmp, source) = pointer_delete_choice_fixture();
    let _ = render_provider_rows(&source, 100, 40);
    let choices = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                super::super::shell::SettingsPointerAction::Page(
                    action @ super::super::pointer_actions::SettingsPointerAction::Providers(
                        super::super::pointer_actions::ProvidersAction::Delete(_, _),
                    ),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        choices.len(),
        3,
        "unshared secret offers all delete choices"
    );
    for action in choices {
        let choice = match &action {
            super::super::pointer_actions::SettingsPointerAction::Providers(
                super::super::pointer_actions::ProvidersAction::Delete(_, choice),
            ) => *choice,
            _ => unreachable!(),
        };
        let (_tmp, mut fresh) = pointer_delete_choice_fixture();
        click_rendered_provider_action(&mut fresh, &action);
        match choice {
            super::super::pointer_actions::ProviderDeleteChoice::Cancel => assert!(
                fresh.config.providers.contains_key("p")
                    && matches!(fresh.test_page(), TestPageRef::Providers(ProvidersPage::Edit(state)) if !state.delete_pending)
            ),
            super::super::pointer_actions::ProviderDeleteChoice::RemoveSecrets
            | super::super::pointer_actions::ProviderDeleteChoice::KeepSecrets => {
                assert!(!fresh.config.providers.contains_key("p"))
            }
        }
    }
}

#[test]
fn pointer_render_boundary_publishes_stable_provider_identity() {
    use super::super::pointer_actions::{
        ProviderDeleteChoice, ProviderId, ProvidersAction, SettingsPointerAction,
    };

    fn fixture() -> (tempfile::TempDir, SettingsDialog) {
        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("stable-provider".into(), ProviderEntry::default());
        let (tmp, mut dialog) = dialog_with_config(cfg);
        dialog.page = super::super::providers_page(ProvidersPage::List {
            cursor: 1,
            status: None,
            delete_pending: false,
        });
        (tmp, dialog)
    }

    fn identity_actions(dialog: &SettingsDialog) -> Vec<SettingsPointerAction> {
        let _ = render_provider_rows(dialog, 90, 24);
        dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .filter_map(|target| match (&target.action, target.enabled) {
                (
                    super::super::shell::SettingsPointerAction::Page(
                        action @ SettingsPointerAction::Providers(
                            ProvidersAction::Open(_)
                            | ProvidersAction::BeginDelete(_)
                            | ProvidersAction::Delete(_, _),
                        ),
                    ),
                    true,
                ) => Some(action.clone()),
                _ => None,
            })
            .collect()
    }

    let (_tmp, source) = fixture();
    let id = ProviderId("stable-provider".into());
    let initial = identity_actions(&source);
    assert_eq!(
        initial
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>(),
        [
            SettingsPointerAction::Providers(ProvidersAction::Open(id.clone())),
            SettingsPointerAction::Providers(ProvidersAction::BeginDelete(id.clone())),
        ]
        .into_iter()
        .collect(),
        "stable provider row publishes every identity-bearing list action"
    );

    for action in initial {
        let (_fresh_tmp, mut dialog) = fixture();
        click_rendered_provider_action(&mut dialog, &action);
        match action {
            SettingsPointerAction::Providers(ProvidersAction::Open(_)) => assert!(matches!(
                dialog.test_page(),
                TestPageRef::Providers(ProvidersPage::Edit(state))
                    if state.provider_id == "stable-provider"
            )),
            action @ SettingsPointerAction::Providers(ProvidersAction::BeginDelete(_)) => {
                assert!(matches!(
                    dialog.test_page(),
                    TestPageRef::Providers(ProvidersPage::List {
                        delete_pending: true,
                        ..
                    })
                ));
                let nested = identity_actions(&dialog);
                for choice in [
                    ProviderDeleteChoice::RemoveSecrets,
                    ProviderDeleteChoice::KeepSecrets,
                    ProviderDeleteChoice::Cancel,
                ] {
                    let delete = SettingsPointerAction::Providers(ProvidersAction::Delete(
                        id.clone(),
                        choice,
                    ));
                    assert!(nested.contains(&delete));
                    let (_choice_tmp, mut choice_dialog) = fixture();
                    click_rendered_provider_action(&mut choice_dialog, &action);
                    click_rendered_provider_action(&mut choice_dialog, &delete);
                    assert_eq!(
                        choice_dialog
                            .config
                            .providers
                            .contains_key("stable-provider"),
                        choice == ProviderDeleteChoice::Cancel
                    );
                }
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn pointer_render_boundary_click_is_consumed() {
    let (_tmp, mut dialog) = {
        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("stable-provider".into(), ProviderEntry::default());
        let (tmp, mut dialog) = dialog_with_config(cfg);
        dialog.page = super::super::providers_page(ProvidersPage::List {
            cursor: 1,
            status: None,
            delete_pending: false,
        });
        (tmp, dialog)
    };
    let _ = render_provider_rows(&dialog, 90, 24);
    let target = dialog
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find(|target| {
            target.action
                == super::super::shell::SettingsPointerAction::Page(
                    super::super::pointer_actions::SettingsPointerAction::Providers(
                        super::super::pointer_actions::ProvidersAction::Open(
                            super::super::pointer_actions::ProviderId("stable-provider".into()),
                        ),
                    ),
                )
        })
        .cloned()
        .expect("provider row publishes its config-map identity");
    assert_eq!(
        dialog.handle_pointer(super::super::tests::settings_mouse(
            crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            target.rect.x,
            target.rect.y,
        )),
        super::super::SettingsPointerOutcome::Consumed
    );
    assert!(matches!(
        dialog.test_page(),
        TestPageRef::Providers(ProvidersPage::Edit(state))
            if state.provider_id == "stable-provider"
    ));
}

#[test]
fn pointer_edit_menu_mapping_is_exhaustive_over_source_actions() {
    let state = EditState::new("p".into(), ProviderEntry::default());
    for source in edit_menu_actions(&state.provider_id, &state.entry) {
        let action = provider_edit_pointer_action(&state, source);
        assert!(matches!(
            action,
            super::super::pointer_actions::SettingsPointerAction::Providers(_)
        ));
    }
    assert_eq!(
        provider_edit_pointer_action(&state, EditAction::Delete),
        super::super::pointer_actions::SettingsPointerAction::Providers(
            super::super::pointer_actions::ProvidersAction::BeginDelete(
                super::super::pointer_actions::ProviderId("p".into()),
            ),
        ),
        "the ordinary row can only arm deletion"
    );
}

#[test]
fn pointer_row_editor_actions_survive_reordering_by_identity() {
    let headers = HeaderEditor::new(
        vec![
            HeaderSpec {
                name: "X-First".into(),
                value: "one".into(),
            },
            HeaderSpec {
                name: "X-Second".into(),
                value: "two".into(),
            },
        ],
        false,
    );
    let action = provider_header_pointer_action(&headers, 1).expect("second header action");
    assert_eq!(
        action,
        super::super::pointer_actions::SettingsPointerAction::Providers(
            super::super::pointer_actions::ProvidersAction::RowEditor(
                super::super::pointer_actions::ProviderRowEditorAction::HeaderOpen(
                    super::super::pointer_actions::HeaderName("X-Second".into()),
                ),
            ),
        )
    );

    let models = ModelEditor::new(
        None,
        vec![model("first", true), model("stable-model", true)],
    );
    assert_eq!(
        provider_model_pointer_action(&models, 1).expect("second model action"),
        super::super::pointer_actions::SettingsPointerAction::Providers(
            super::super::pointer_actions::ProvidersAction::RowEditor(
                super::super::pointer_actions::ProviderRowEditorAction::ModelOpen(
                    super::super::pointer_actions::ModelId("stable-model".into()),
                ),
            ),
        )
    );
}

fn compact_text(s: &str) -> String {
    s.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn assert_rendered_contains_text(rendered: &str, expected: &str) {
    assert!(
        compact_text(rendered).contains(&compact_text(expected)),
        "expected `{expected}` in:\n{rendered}"
    );
}

struct RecordingDeepFetchClient {
    endpoint_calls: Vec<EndpointProbeRequest>,
    context_calls: Vec<ContextProbeRequest>,
    cancel_after_first_context: Option<Arc<AtomicBool>>,
    fail_context: bool,
}

impl RecordingDeepFetchClient {
    fn succeeds() -> Self {
        Self {
            endpoint_calls: Vec::new(),
            context_calls: Vec::new(),
            cancel_after_first_context: None,
            fail_context: false,
        }
    }
}

impl DeepfetchProbeClient for RecordingDeepFetchClient {
    fn probe_endpoint<'a>(
        &'a mut self,
        request: EndpointProbeRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<ProbeRawOutcome>> + Send + 'a>> {
        self.endpoint_calls.push(request);
        Box::pin(async { Ok(ProbeRawOutcome::Works) })
    }

    fn probe_context<'a>(
        &'a mut self,
        request: ContextProbeRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<ProbeRawOutcome>> + Send + 'a>> {
        self.context_calls.push(request);
        let cancel = self.cancel_after_first_context.take();
        let fail = self.fail_context;
        Box::pin(async move {
            if let Some(cancel) = cancel {
                cancel.store(true, Ordering::Release);
            }
            if fail {
                anyhow::bail!("test probe failure");
            }
            Ok(ProbeRawOutcome::Works)
        })
    }
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
        Some(cockpit_core::auth::xai_oauth::CREDENTIAL_KEY)
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
        Some(cockpit_core::auth::codex_oauth::CREDENTIAL_KEY)
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
    let store = cockpit_core::credentials::CredentialStore::open(store_path.clone()).unwrap();
    assert_eq!(
        store.named_secret("p"),
        Some("Bearer sk-provider-secret-abcdefghijklmnopqrstuvwxyz")
    );
    let notice = dialog.last_secret_notice.as_deref().unwrap();
    assert!(notice.contains(&store_path.display().to_string()));
    assert!(!notice.contains("sk-provider-secret-abcdefghijklmnopqrstuvwxyz"));
}

#[test]
fn github_token_applies_without_env_mutation() {
    let tmp = tempfile::tempdir().unwrap();
    let store_path = tmp.path().join("credentials.json");
    let env = cockpit_test_support::TestEnvGuard::blocking_lock();
    for name in ["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"] {
        env.remove_var(name);
    }

    store_copilot_token(Some(&store_path), "ghu_session_token".to_string()).unwrap();

    for name in ["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"] {
        assert!(std::env::var_os(name).is_none(), "{name} was mutated");
    }
    let store = cockpit_core::credentials::CredentialStore::open(store_path).unwrap();
    let entry = ProviderEntry {
        url: "https://api.githubcopilot.com".into(),
        ..ProviderEntry::default()
    };
    let resolved = cockpit_core::providers::models_fetch::resolve_provider_request_with_sources(
        "copilot",
        &entry,
        |_| None,
        |name| store.named_secret(name).map(str::to_owned),
    )
    .unwrap();
    let authorization = resolved
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("authorization"))
        .unwrap();
    assert_eq!(authorization.value, "Bearer ghu_session_token");
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
    assert!(
        generic_actions.contains(&EditAction::DeepFetch),
        "provider settings must expose the confirmation-gated deep-fetch action"
    );
    // The conditional row is the only difference in menu length.
    assert_eq!(actions.len(), generic_actions.len() + 1);
}

#[test]
fn deep_fetch_constructs_confirm_page_without_starting_probes() {
    let (_tmp, mut dialog) = dialog_with_config(one_provider_config(None));
    let entry = dialog.config.providers["p"].clone();
    let mut state = EditState::new("p".into(), entry.clone());
    state.cursor = edit_menu_actions("p", &entry)
        .iter()
        .position(|action| matches!(action, EditAction::DeepFetch))
        .expect("deep fetch row");
    dialog.set_test_page(Page::Providers(ProvidersPage::Edit(state)));

    dialog.handle_key(press(KeyCode::Enter));

    let TestPageRef::Providers(ProvidersPage::DeepFetch { state, .. }) = dialog.test_page() else {
        panic!("expected deep-fetch confirmation page");
    };
    assert!(state.is_confirming());
    assert_eq!(state.target_count(), 2);
    assert_eq!(state.completed_and_lines_for_test(), (0, Vec::new()));
}

#[test]
fn deep_fetch_cancel_from_confirm_returns_to_edit_without_probing() {
    let (tmp, mut dialog) = dialog_with_config(one_provider_config(None));
    let entry = dialog.config.providers["p"].clone();
    let state = DeepFetchState::prepare(&dialog.config_path, "p").unwrap();
    dialog.set_test_page(Page::Providers(ProvidersPage::DeepFetch {
        state,
        parent: Box::new(EditState::new("p".into(), entry)),
    }));

    dialog.handle_key(press(KeyCode::Down));
    dialog.handle_key(press(KeyCode::Enter));

    let TestPageRef::Providers(ProvidersPage::Edit(state)) = dialog.test_page() else {
        panic!("expected Edit page after cancellation");
    };
    assert_eq!(state.status.as_deref(), Some("deep fetch cancelled"));
    assert_eq!(
        load_provider(&tmp.path().join("config.json"), "p")
            .models
            .len(),
        2
    );
}

#[tokio::test]
async fn deep_fetch_plan_and_run_use_disk_entry_not_unsaved_edit() {
    let (tmp, mut dialog) = dialog_with_config(one_provider_config(None));
    let mut unsaved = dialog.config.providers["p"].clone();
    unsaved.models.push(model("unsaved", false));
    let mut edit = EditState::new("p".into(), unsaved);
    edit.cursor = edit_menu_actions("p", &edit.entry)
        .iter()
        .position(|action| matches!(action, EditAction::DeepFetch))
        .unwrap();
    dialog.set_test_page(Page::Providers(ProvidersPage::Edit(edit)));
    dialog.handle_key(press(KeyCode::Enter));

    let TestPageRef::Providers(ProvidersPage::DeepFetch { state, .. }) = dialog.test_page() else {
        panic!("expected deep-fetch confirmation page");
    };
    assert_eq!(state.target_count(), 2, "confirmation plan must use disk");
    assert_eq!(
        state.plan_total_requests(),
        6,
        "confirmation request count must use disk"
    );

    let state = DeepFetchState::prepare(&dialog.config_path, "p").unwrap();
    let mut disk = ConfigDoc::load(&dialog.config_path).unwrap().providers();
    let mut client = RecordingDeepFetchClient::succeeds();
    state
        .run_with_client_for_test(&dialog.config_path, &mut disk, &mut client)
        .await
        .unwrap();

    let saved = load_provider(&tmp.path().join("config.json"), "p");
    assert_eq!(saved.models.len(), 2);
    assert!(!saved.models.iter().any(|model| model.id == "unsaved"));
    assert!(!client.endpoint_calls.is_empty());
}

#[test]
fn deep_fetch_running_blocks_q_and_requests_cancel_on_escape() {
    let (_tmp, mut dialog) = dialog_with_config(one_provider_config(None));
    let entry = dialog.config.providers["p"].clone();
    let mut state = DeepFetchState::prepare(&dialog.config_path, "p").unwrap();
    state.set_running_for_test();
    dialog.set_test_page(Page::Providers(ProvidersPage::DeepFetch {
        state,
        parent: Box::new(EditState::new("p".into(), entry)),
    }));

    assert!(!dialog.handle_key(press(KeyCode::Char('q'))));
    let TestPageRef::Providers(ProvidersPage::DeepFetch { state, .. }) = dialog.test_page() else {
        panic!("q must not close the running deep-fetch page");
    };
    assert!(state.is_running());
    assert!(
        state
            .status
            .as_deref()
            .unwrap_or_default()
            .contains("probes are in flight")
    );

    dialog.handle_key(press(KeyCode::Esc));
    let TestPageRef::Providers(ProvidersPage::DeepFetch { state, .. }) = dialog.test_page() else {
        panic!("Esc must keep the page open until the in-flight probe completes");
    };
    assert!(state.cancellation_requested());
}

#[tokio::test]
async fn deep_fetch_cancellation_stops_between_models_and_keeps_lines() {
    let (_tmp, dialog) = dialog_with_config(one_provider_config(None));
    let state = DeepFetchState::prepare(&dialog.config_path, "p").unwrap();
    let mut disk = ConfigDoc::load(&dialog.config_path).unwrap().providers();
    let mut client = RecordingDeepFetchClient {
        cancel_after_first_context: Some(state.cancellation_handle_for_test()),
        ..RecordingDeepFetchClient::succeeds()
    };

    state
        .run_with_client_for_test(&dialog.config_path, &mut disk, &mut client)
        .await
        .unwrap();

    assert!(state.cancellation_requested());
    assert!(
        client
            .endpoint_calls
            .iter()
            .all(|call| call.model_id == "stale")
    );
    let (completed, lines) = state.completed_and_lines_for_test();
    assert_eq!(completed, 1);
    assert!(lines.iter().any(|line| line.contains("p:stale")));
}

#[test]
fn deep_fetch_done_renders_summary_and_returns_it_to_edit() {
    let (_tmp, mut dialog) = dialog_with_config(one_provider_config(None));
    let entry = dialog.config.providers["p"].clone();
    let mut state = DeepFetchState::prepare(&dialog.config_path, "p").unwrap();
    state.set_running_for_test();
    state.finish_for_test(
        Ok("deep fetch complete: test summary".into()),
        vec!["saved line".into()],
    );
    dialog.set_test_page(Page::Providers(ProvidersPage::DeepFetch {
        state,
        parent: Box::new(EditState::new("p".into(), entry)),
    }));
    dialog.tick();

    let rendered = render_provider_rows(&dialog, 100, 20).join("\n");
    assert_rendered_contains_text(&rendered, "deep fetch complete: test summary");
    assert_rendered_contains_text(&rendered, "saved line");
    dialog.handle_key(press(KeyCode::Enter));
    let TestPageRef::Providers(ProvidersPage::Edit(state)) = dialog.test_page() else {
        panic!("expected edit page after Done");
    };
    assert_eq!(
        state.status.as_deref(),
        Some("deep fetch complete: test summary")
    );
}

#[test]
fn deep_fetch_failure_reaches_done_and_retains_prior_lines() {
    let (_tmp, mut dialog) = dialog_with_config(one_provider_config(None));
    let entry = dialog.config.providers["p"].clone();
    let mut state = DeepFetchState::prepare(&dialog.config_path, "p").unwrap();
    state.set_running_for_test();
    state.finish_for_test(
        Err("deep fetch failed: test probe failure".into()),
        vec!["→ p:stale".into(), "  using responses".into()],
    );
    dialog.set_test_page(Page::Providers(ProvidersPage::DeepFetch {
        state,
        parent: Box::new(EditState::new("p".into(), entry)),
    }));
    dialog.tick();

    let TestPageRef::Providers(ProvidersPage::DeepFetch { state, .. }) = dialog.test_page() else {
        panic!("failed run must remain on Done page");
    };
    assert!(state.is_done());
    assert!(
        state
            .status
            .as_deref()
            .unwrap()
            .starts_with("deep fetch failed:")
    );
    assert_eq!(state.completed_and_lines_for_test().1.len(), 2);
}

#[test]
fn deep_fetch_running_help_has_no_q_and_page_has_no_text_field_or_missing_breadcrumb() {
    let (_tmp, dialog) = dialog_with_config(one_provider_config(None));
    let entry = dialog.config.providers["p"].clone();
    let mut state = DeepFetchState::prepare(&dialog.config_path, "p").unwrap();
    state.set_running_for_test();
    let mut page = ProvidersPage::DeepFetch {
        state,
        parent: Box::new(EditState::new("p".into(), entry)),
    };

    assert!(!page.help_text(&dialog.cx).contains("q:"));
    assert!(page.active_text_field().is_none());
    assert!(page.title(&dialog.cx).contains("p"));
}

#[test]
fn deep_fetch_success_refreshes_cached_and_parent_provider_entry() {
    let (tmp, mut dialog) = dialog_with_config(one_provider_config(None));
    let mut persisted = dialog.config.providers["p"].clone();
    persisted.models.push(model("persisted", false));
    let mut doc = ConfigDoc::load(&dialog.config_path).unwrap();
    doc.write_provider_models("p", &persisted.models, None, persisted.model_catalog, None)
        .unwrap();

    let mut state = DeepFetchState::prepare(&dialog.config_path, "p").unwrap();
    state.set_running_for_test();
    state.finish_for_test(Ok("deep fetch complete: refreshed".into()), Vec::new());
    let stale_parent = EditState::new("p".into(), dialog.config.providers["p"].clone());
    dialog.set_test_page(Page::Providers(ProvidersPage::DeepFetch {
        state,
        parent: Box::new(stale_parent),
    }));
    dialog.tick();

    assert!(
        dialog.config.providers["p"]
            .models
            .iter()
            .any(|model| model.id == "persisted")
    );
    let TestPageRef::Providers(ProvidersPage::DeepFetch { parent, .. }) = dialog.test_page() else {
        panic!("expected Done page");
    };
    assert!(
        parent
            .entry
            .models
            .iter()
            .any(|model| model.id == "persisted")
    );
    assert!(
        load_provider(&tmp.path().join("config.json"), "p")
            .models
            .iter()
            .any(|model| model.id == "persisted")
    );
}

#[test]
fn provider_settings_summary_surfaces_timeout_values() {
    let provider = ProviderEntry {
        url: "https://api.example.com/v1".to_string(),
        timeout: cockpit_config::providers::TimeoutConfig {
            ttft_secs: 240,
            idle_secs: 180,
        },
        backup: Some(cockpit_config::providers::BackupConfig {
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
    let mut store = cockpit_core::credentials::CredentialStore::open(store_path.clone()).unwrap();
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
        cockpit_core::credentials::CredentialStore::open(store_path)
            .unwrap()
            .named_secret("p")
            .is_none()
    );
}

#[test]
fn provider_delete_removes_grok_oauth_credential_record() {
    let (tmp, mut dialog) = dialog_with_config(oauth_provider_config(
        cockpit_core::auth::xai_oauth::CREDENTIAL_KEY,
        cockpit_core::auth::xai_oauth::CREDENTIAL_KEY,
    ));
    let store_path = tmp.path().join("credentials.json");
    dialog.credential_store_path = Some(store_path.clone());
    let mut store = cockpit_core::credentials::CredentialStore::open(store_path.clone()).unwrap();
    store.set(
        cockpit_core::auth::xai_oauth::CREDENTIAL_KEY,
        json!({"access_token":"grok","refresh_token":"refresh","expires_at":9_999_999_999i64}),
    );
    store.save().unwrap();

    assert_eq!(
        dialog
            .delete_provider_and_stored_secrets(cockpit_core::auth::xai_oauth::CREDENTIAL_KEY, true)
            .unwrap(),
        1
    );

    let store = cockpit_core::credentials::CredentialStore::open(store_path).unwrap();
    assert!(
        store
            .get(cockpit_core::auth::xai_oauth::CREDENTIAL_KEY)
            .is_none()
    );
}

#[test]
fn provider_delete_removes_codex_oauth_credential_record() {
    let (tmp, mut dialog) = dialog_with_config(oauth_provider_config(
        cockpit_core::auth::codex_oauth::CREDENTIAL_KEY,
        cockpit_core::auth::codex_oauth::CREDENTIAL_KEY,
    ));
    let store_path = tmp.path().join("credentials.json");
    dialog.credential_store_path = Some(store_path.clone());
    let mut store = cockpit_core::credentials::CredentialStore::open(store_path.clone()).unwrap();
    store.set(
        cockpit_core::auth::codex_oauth::CREDENTIAL_KEY,
        json!({"access_token":"codex","refresh_token":"refresh","expires_at":9_999_999_999i64}),
    );
    store.save().unwrap();

    assert_eq!(
        dialog
            .delete_provider_and_stored_secrets(
                cockpit_core::auth::codex_oauth::CREDENTIAL_KEY,
                true
            )
            .unwrap(),
        1
    );

    let store = cockpit_core::credentials::CredentialStore::open(store_path).unwrap();
    assert!(
        store
            .get(cockpit_core::auth::codex_oauth::CREDENTIAL_KEY)
            .is_none()
    );
}

#[test]
fn provider_delete_preserves_shared_oauth_credential_record() {
    let mut cfg = oauth_provider_config("grok-a", cockpit_core::auth::xai_oauth::CREDENTIAL_KEY);
    cfg.providers.insert(
        "grok-b".into(),
        ProviderEntry {
            url: "https://api.example.com/v1".to_string(),
            auth: Some(AuthKind::OAuth),
            credential_ref: Some(cockpit_core::auth::xai_oauth::CREDENTIAL_KEY.to_string()),
            ..Default::default()
        },
    );
    let (tmp, mut dialog) = dialog_with_config(cfg);
    let store_path = tmp.path().join("credentials.json");
    dialog.credential_store_path = Some(store_path.clone());
    let mut store = cockpit_core::credentials::CredentialStore::open(store_path.clone()).unwrap();
    store.set(
        cockpit_core::auth::xai_oauth::CREDENTIAL_KEY,
        json!({"access_token":"grok","refresh_token":"refresh","expires_at":9_999_999_999i64}),
    );
    store.save().unwrap();

    assert_eq!(
        dialog
            .delete_provider_and_stored_secrets("grok-a", true)
            .unwrap(),
        0
    );

    let store = cockpit_core::credentials::CredentialStore::open(store_path).unwrap();
    assert!(
        store
            .get(cockpit_core::auth::xai_oauth::CREDENTIAL_KEY)
            .is_some()
    );
}

#[test]
fn provider_delete_signs_out_oauth_even_when_named_secrets_are_kept() {
    let (tmp, mut dialog) = dialog_with_config(oauth_provider_config(
        cockpit_core::auth::xai_oauth::CREDENTIAL_KEY,
        cockpit_core::auth::xai_oauth::CREDENTIAL_KEY,
    ));
    let store_path = tmp.path().join("credentials.json");
    dialog.credential_store_path = Some(store_path.clone());
    let mut store = cockpit_core::credentials::CredentialStore::open(store_path.clone()).unwrap();
    store.set(
        cockpit_core::auth::xai_oauth::CREDENTIAL_KEY,
        json!({"access_token":"grok","refresh_token":"refresh","expires_at":9_999_999_999i64}),
    );
    store.save().unwrap();

    assert_eq!(
        dialog
            .delete_provider_and_stored_secrets(
                cockpit_core::auth::xai_oauth::CREDENTIAL_KEY,
                false
            )
            .unwrap(),
        1
    );

    let store = cockpit_core::credentials::CredentialStore::open(store_path).unwrap();
    assert!(
        store
            .get(cockpit_core::auth::xai_oauth::CREDENTIAL_KEY)
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
    let mut store = cockpit_core::credentials::CredentialStore::open(store_path.clone()).unwrap();
    store.set_named_secret("shared", "sk-provider-secret-value");
    store.save().unwrap();

    assert_eq!(
        dialog
            .delete_provider_and_stored_secrets("p", true)
            .unwrap(),
        0
    );
    assert_eq!(
        cockpit_core::credentials::CredentialStore::open(store_path)
            .unwrap()
            .named_secret("shared"),
        Some("sk-provider-secret-value")
    );
}

#[test]
fn provider_edit_oauth_sign_out_updates_login_state_and_row_status() {
    let (tmp, mut dialog) = dialog_with_config(oauth_provider_config(
        cockpit_core::auth::xai_oauth::CREDENTIAL_KEY,
        cockpit_core::auth::xai_oauth::CREDENTIAL_KEY,
    ));
    let store_path = tmp.path().join("credentials.json");
    dialog.credential_store_path = Some(store_path.clone());
    let mut store = cockpit_core::credentials::CredentialStore::open(store_path.clone()).unwrap();
    store.set(
        cockpit_core::auth::xai_oauth::CREDENTIAL_KEY,
        json!({"access_token":"grok","refresh_token":"refresh","expires_at":9_999_999_999i64}),
    );
    store.save().unwrap();
    let entry = dialog.config.providers[cockpit_core::auth::xai_oauth::CREDENTIAL_KEY].clone();
    let mut state = EditState::new(cockpit_core::auth::xai_oauth::CREDENTIAL_KEY.into(), entry);
    state.cursor = edit_menu_actions(cockpit_core::auth::xai_oauth::CREDENTIAL_KEY, &state.entry)
        .iter()
        .position(|action| *action == EditAction::OAuthAuth(OAuthProvider::Grok))
        .unwrap();
    dialog.set_test_page(Page::Providers(ProvidersPage::Edit(state)));

    assert!(cockpit_core::auth::xai_oauth::is_logged_in_at(Some(
        &store_path
    )));
    assert_eq!(
        dialog.provider_oauth_status_value(OAuthProvider::Grok),
        "logged in — Enter: Sign out"
    );

    dialog.handle_key(press(KeyCode::Enter));

    assert!(!cockpit_core::auth::xai_oauth::is_logged_in_at(Some(
        &store_path
    )));
    assert_eq!(
        dialog.provider_oauth_status_value(OAuthProvider::Grok),
        "not logged in — Enter: Sign in"
    );
    match dialog.test_page() {
        TestPageRef::Providers(ProvidersPage::Edit(state)) => {
            assert_eq!(
                state.status.as_deref(),
                Some("signed out of Grok subscription auth")
            );
        }
        other => panic!("expected Edit page, got {other:?}"),
    }
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
    let mut store = cockpit_core::credentials::CredentialStore::open(store_path.clone()).unwrap();
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
        cockpit_core::credentials::CredentialStore::open(store_path)
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
        cockpit_config::providers::ModelFetchStatusKind::Fallback
    );
    assert_eq!(
        status.source,
        cockpit_config::providers::ModelFetchSource::Fallback
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
        last_model_fetch: Some(cockpit_config::providers::ModelFetchStatus {
            status: cockpit_config::providers::ModelFetchStatusKind::FailedKeptExisting,
            at: now,
            source: cockpit_config::providers::ModelFetchSource::Live,
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
    // Confirmed, not Unverified: this exercises the plain "copied OAuth
    // URL" wording specifically. `copy_oauth_url_reports_unverified_delivery_distinctly`
    // (below) covers the Unverified case, which now has different wording
    // — see the follow-up finding on M5's toast-based sibling.
    let copied = crate::clipboard::DeliveryResult {
        attempts: vec![],
        requested_representation: crate::clipboard::Representation::Plain,
        delivered_representation: crate::clipboard::Representation::Plain,
        downgrade: None,
        confidence: crate::clipboard::Confidence::Confirmed,
    };
    copy_oauth_url_with(Some("https://example.test/oauth"), &mut status, |_| {
        Ok(copied.clone())
    });
    assert_eq!(status, Some(Ok("copied OAuth URL".to_string())));

    copy_oauth_url_with(None, &mut status, |_| Ok(copied.clone()));
    assert_eq!(status, Some(Ok("no OAuth URL yet".to_string())));

    copy_oauth_url_with(Some("https://example.test/oauth"), &mut status, |_| {
        Err(crate::clipboard::CopyError::Backend)
    });
    assert_eq!(status, Some(Err("clipboard backend error".to_string())));
}

/// The finding this proves against: `copy_oauth_url_with` used to report
/// "copied OAuth URL" for both Confirmed and Unverified deliveries —
/// exactly the class of gap `describe_delivered` exists to close for the
/// toast-based copy paths, just on a status-line path that has no
/// `ToastKind` of its own.
#[test]
fn copy_oauth_url_reports_unverified_delivery_distinctly() {
    let mut status = None;
    let unverified = crate::clipboard::DeliveryResult {
        attempts: vec![],
        requested_representation: crate::clipboard::Representation::Plain,
        delivered_representation: crate::clipboard::Representation::Plain,
        downgrade: None,
        confidence: crate::clipboard::Confidence::Unverified,
    };
    copy_oauth_url_with(Some("https://example.test/oauth"), &mut status, |_| {
        Ok(unverified.clone())
    });
    let message = status.unwrap().unwrap();
    assert_ne!(
        message, "copied OAuth URL",
        "an Unverified delivery must not read identically to a Confirmed one"
    );
    assert!(message.contains("copied OAuth URL"));
    assert!(message.to_lowercase().contains("unverified"));
}

static OAUTH_EFFECTS_LOG: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
static OAUTH_EFFECTS_SSH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static OAUTH_EFFECTS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static OAUTH_BOUND_ADDR: std::sync::Mutex<Option<std::net::SocketAddr>> =
    std::sync::Mutex::new(None);

fn reset_oauth_effects(ssh: bool) {
    OAUTH_EFFECTS_SSH.store(ssh, std::sync::atomic::Ordering::SeqCst);
    OAUTH_EFFECTS_LOG.lock().unwrap().clear();
    *OAUTH_BOUND_ADDR.lock().unwrap() = None;
}

fn oauth_effects_log() -> Vec<String> {
    OAUTH_EFFECTS_LOG.lock().unwrap().clone()
}

fn fake_copy(value: &str) -> Result<crate::clipboard::DeliveryResult, crate::clipboard::CopyError> {
    OAUTH_EFFECTS_LOG
        .lock()
        .unwrap()
        .push(format!("copy:{value}"));
    Ok(crate::clipboard::DeliveryResult {
        attempts: vec![],
        requested_representation: crate::clipboard::Representation::Plain,
        delivered_representation: crate::clipboard::Representation::Plain,
        downgrade: None,
        confidence: crate::clipboard::Confidence::Unverified,
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

fn fake_bind(port: u16) -> anyhow::Result<tokio::net::TcpListener> {
    OAUTH_EFFECTS_LOG.lock().unwrap().push("bind".to_string());
    let listener = cockpit_core::auth::xai_oauth::bind_callback_listener(port)?;
    *OAUTH_BOUND_ADDR.lock().unwrap() = Some(listener.local_addr()?);
    Ok(listener)
}

fn failing_bind(_port: u16) -> anyhow::Result<tokio::net::TcpListener> {
    OAUTH_EFFECTS_LOG.lock().unwrap().push("bind".to_string());
    anyhow::bail!("callback port busy")
}

fn connecting_open(value: &str) -> anyhow::Result<()> {
    OAUTH_EFFECTS_LOG
        .lock()
        .unwrap()
        .push(format!("open:{value}"));
    let addr = OAUTH_BOUND_ADDR
        .lock()
        .unwrap()
        .expect("listener must be bound before open");
    std::net::TcpStream::connect(addr)?;
    Ok(())
}

fn failing_open(value: &str) -> anyhow::Result<()> {
    OAUTH_EFFECTS_LOG
        .lock()
        .unwrap()
        .push(format!("open:{value}"));
    anyhow::bail!("browser unavailable")
}

fn fake_oauth_effects() -> OAuthEffects {
    OAuthEffects {
        copy: fake_copy,
        is_ssh: fake_is_ssh,
        open: fake_open,
        bind: fake_bind,
    }
}

#[tokio::test]
async fn oauth_grok_binds_before_opening_browser() {
    let _guard = OAUTH_EFFECTS_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reset_oauth_effects(false);
    let effects = OAuthEffects {
        open: connecting_open,
        ..fake_oauth_effects()
    };
    let login = cockpit_core::auth::xai_oauth::ManualLogin::for_test("https://example.test/oauth");

    let start = prepare_grok_browser_start(login, effects, 0);

    assert!(start.listener.is_some());
    assert_eq!(
        oauth_effects_log(),
        vec![
            "bind".to_string(),
            "open:https://example.test/oauth".to_string()
        ]
    );
}

#[tokio::test]
async fn oauth_grok_browser_open_failure_still_listens() {
    let _guard = OAUTH_EFFECTS_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reset_oauth_effects(false);
    let effects = OAuthEffects {
        open: failing_open,
        ..fake_oauth_effects()
    };
    let login = cockpit_core::auth::xai_oauth::ManualLogin::for_test("https://example.test/oauth");
    let start = prepare_grok_browser_start(login, effects, 0);
    assert!(start.listener.is_some());

    let mut state = OAuthFlowState::new_with_effects(OAuthProvider::Grok, effects);
    state.apply_begin(OAuthBeginResult::Browser(Ok(start.begin)), effects);
    assert!(state.pending);
    assert!(state.has_browser_session());
    let status = state.status.unwrap().unwrap();
    assert!(status.contains("Could not open browser"), "{status}");
    assert!(status.contains("Waiting for callback"), "{status}");
}

#[test]
fn oauth_grok_bind_failure_offers_manual_paste() {
    let _guard = OAUTH_EFFECTS_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reset_oauth_effects(false);
    let effects = OAuthEffects {
        bind: failing_bind,
        ..fake_oauth_effects()
    };
    let login = cockpit_core::auth::xai_oauth::ManualLogin::for_test("https://example.test/oauth");
    let start = prepare_grok_browser_start(login, effects, 0);
    assert!(start.listener.is_none());

    let mut state = OAuthFlowState::new_with_effects(OAuthProvider::Grok, effects);
    state.apply_begin(OAuthBeginResult::Browser(Ok(start.begin)), effects);
    assert!(!state.pending);
    assert!(!state.ssh);
    assert!(state.has_browser_session());
    assert!(state.paste_focused);
    let status = state.status.as_ref().unwrap().as_ref().unwrap();
    assert!(status.contains("callback port busy"), "{status}");
}

#[test]
fn oauth_grok_ssh_begin_binds_no_listener() {
    let _guard = OAUTH_EFFECTS_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reset_oauth_effects(true);
    let effects = fake_oauth_effects();
    let login = cockpit_core::auth::xai_oauth::ManualLogin::for_test("https://example.test/oauth");
    let start = prepare_grok_browser_start(login, effects, 0);
    assert!(start.listener.is_none());
    assert!(oauth_effects_log().is_empty());

    let mut state = OAuthFlowState::new_with_effects(OAuthProvider::Grok, effects);
    state.apply_begin(OAuthBeginResult::Browser(Ok(start.begin)), effects);
    assert!(!state.pending);
    assert!(state.ssh);
    assert!(state.has_browser_session());
    assert!(state.paste_focused);
    assert!(oauth_effects_log().is_empty());
}

#[test]
fn subscription_oauth_acknowledgement_blocks_login_until_chosen() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut state = OAuthFlowState::new(OAuthProvider::Codex);

    assert_eq!(state.option_count(OAuthHost::AddWizard), 1);
    assert_eq!(
        oauth_options(&state, OAuthHost::AddWizard),
        vec![OAuthOption::Acknowledge]
    );

    let outcome = handle_oauth_flow_key_with(
        press(KeyCode::Enter),
        &mut state,
        OAuthHost::AddWizard,
        fake_oauth_effects(),
    );
    assert_eq!(outcome.nav, OAuthNav::Stay);
    assert!(outcome.action.is_none());
    assert!(
        cockpit_core::auth::subscription_ack::acknowledged(
            cockpit_core::auth::subscription_ack::CODEX_OAUTH_PROVIDER
        )
        .unwrap()
    );
    assert_ne!(
        oauth_options(&state, OAuthHost::AddWizard),
        vec![OAuthOption::Acknowledge]
    );

    let grok = OAuthFlowState::new(OAuthProvider::Grok);
    assert_eq!(
        oauth_options(&grok, OAuthHost::AddWizard),
        vec![OAuthOption::Acknowledge]
    );

    let body = oauth_body_text(&state, OAuthHost::AddWizard);
    assert!(!body.contains("I acknowledge the risk"));
}

#[test]
fn oauth_grok_manual_paste_option_focuses_without_rebeginning_state() {
    let _guard = OAUTH_EFFECTS_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reset_oauth_effects(false);
    let effects = fake_oauth_effects();
    let mut state = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    state.set_browser_session_for_test("https://example.test/oauth");
    state.pending = false;
    state.cursor = 1;
    let before = state.browser_state_for_test().unwrap().to_string();

    let outcome = handle_oauth_flow_key_with(
        press(KeyCode::Enter),
        &mut state,
        OAuthHost::AddWizard,
        effects,
    );

    assert!(outcome.action.is_none());
    assert!(state.paste_focused);
    assert_eq!(state.browser_state_for_test(), Some(before.as_str()));
}

#[test]
fn oauth_grok_manual_paste_starts_session_then_focuses_input() {
    let mut state = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    state.logged_in = false;
    state.cursor = 1;

    let outcome = handle_oauth_flow_key(press(KeyCode::Enter), &mut state, OAuthHost::AddWizard);

    assert!(matches!(
        outcome.action,
        Some(OAuthFlowRequest {
            provider: OAuthProvider::Grok,
            op: OAuthFlowOp::Begin,
        })
    ));
    assert!(state.pending);
    assert!(!state.paste_focused);

    state.apply_begin(
        OAuthBeginResult::Browser(Ok(OAuthBrowserBegin::for_test(true, false))),
        fake_oauth_effects(),
    );

    assert!(state.has_browser_session());
    assert!(state.paste_focused);
}

#[test]
fn oauth_grok_manual_paste_preserves_existing_session_and_input() {
    let mut state = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    state.set_browser_session_for_test("https://example.test/oauth");
    state.manual_input.set("already pasted");
    state.cursor = 1;
    let before = state.browser_state_for_test().unwrap().to_string();

    let outcome = handle_oauth_flow_key(press(KeyCode::Enter), &mut state, OAuthHost::AddWizard);

    assert!(outcome.action.is_none());
    assert!(state.paste_focused);
    assert_eq!(state.browser_state_for_test(), Some(before.as_str()));
    assert_eq!(state.manual_input.text(), "already pasted");
}

#[test]
fn oauth_grok_login_after_failed_manual_begin_does_not_focus_paste() {
    let mut state = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    state.logged_in = false;
    state.cursor = 1;
    handle_oauth_flow_key(press(KeyCode::Enter), &mut state, OAuthHost::AddWizard);
    state.apply_begin(
        OAuthBeginResult::Browser(Err("begin failed".into())),
        fake_oauth_effects(),
    );

    state.cursor = 0;
    handle_oauth_flow_key(press(KeyCode::Enter), &mut state, OAuthHost::AddWizard);
    state.apply_begin(
        OAuthBeginResult::Browser(Ok(OAuthBrowserBegin::for_test(true, false))),
        fake_oauth_effects(),
    );

    assert!(state.has_browser_session());
    assert!(!state.paste_focused);
}

#[test]
fn oauth_grok_manual_paste_rendering_and_no_session_error_explain_recovery() {
    let mut focused = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    focused.set_browser_session_for_test("https://example.test/oauth");
    focused.paste_focused = true;
    let focused_body = oauth_body_text(&focused, OAuthHost::AddWizard);
    assert!(focused_body.contains("esc: options (c copies URL)"));
    assert!(!focused_body.contains("c copy URL"));

    focused.paste_focused = false;
    let menu_body = oauth_body_text(&focused, OAuthHost::AddWizard);
    assert!(menu_body.contains("c copy URL"));

    let mut without_session =
        OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    without_session.paste_focused = true;
    handle_oauth_flow_key(
        press(KeyCode::Enter),
        &mut without_session,
        OAuthHost::AddWizard,
    );
    let message = without_session.status.unwrap().unwrap_err();
    assert!(message.contains("start login or manual paste first"));
    assert_ne!(message, "manual OAuth session was not initialized");
}

#[test]
fn codex_apply_begin_queues_poll_and_uses_injected_effects() {
    let _guard = OAUTH_EFFECTS_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reset_oauth_effects(false);
    let login = cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
        "https://example.test/device",
        "CODE-123",
    );
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
    let _guard = OAUTH_EFFECTS_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let login = cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
        "https://example.test/device",
        "CODE-123",
    );

    reset_oauth_effects(true);
    let mut ssh_state =
        OAuthFlowState::new_with_effects(OAuthProvider::Codex, fake_oauth_effects());
    ssh_state.set_device_login_for_test(login.clone());
    handle_oauth_flow_key_with(
        press(KeyCode::Char('c')),
        &mut ssh_state,
        OAuthHost::AddWizard,
        fake_oauth_effects(),
    );
    handle_oauth_flow_key_with(
        press(KeyCode::Char('y')),
        &mut ssh_state,
        OAuthHost::AddWizard,
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
        OAuthHost::AddWizard,
        fake_oauth_effects(),
    );
    handle_oauth_flow_key_with(
        press(KeyCode::Char('y')),
        &mut local_state,
        OAuthHost::AddWizard,
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
    state.enter_oauth_for_test(OAuthFlowState::new_without_acknowledgement_for_test(
        OAuthProvider::Grok,
    ));
    let mut page = ProvidersPage::Add(state);

    assert!(page.active_text_field().is_none());

    let ProvidersPage::Add(add) = &mut page else {
        unreachable!();
    };
    let grok = add.oauth_auth.as_mut().expect("expected OAuth add step");
    grok.paste_focused = true;

    let field = page
        .active_text_field()
        .expect("manual Grok OAuth input should own paste focus");
    field.paste("callback-code");

    let ProvidersPage::Add(add) = &page else {
        unreachable!();
    };
    let grok = add.oauth_auth.as_ref().expect("expected OAuth add step");
    assert_eq!(grok.manual_input.text(), "callback-code");
}

#[test]
fn grok_paste_focus_char_c_inserts_instead_of_copying_url() {
    let mut state = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    state.paste_focused = true;
    state.set_browser_session_for_test("https://example.test/oauth");

    let outcome =
        handle_oauth_flow_key(press(KeyCode::Char('c')), &mut state, OAuthHost::AddWizard);

    assert!(outcome.action.is_none());
    assert_eq!(state.manual_input.text(), "c");
    assert_ne!(state.status, Some(Ok("copied OAuth URL".to_string())));
}

#[test]
fn grok_paste_focus_char_by_char_callback_keeps_shortcut_letters() {
    let mut state = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    state.paste_focused = true;
    let callback = "http://127.0.0.1:56121/callback?code=abc123&state=s";

    for ch in callback.chars() {
        handle_oauth_flow_key(press(KeyCode::Char(ch)), &mut state, OAuthHost::AddWizard);
    }

    assert_eq!(state.manual_input.text(), callback);
}

#[test]
fn codex_oauth_logged_in_renders_single_continue_row() {
    let mut state = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
    state.logged_in = true;
    state.status = Some(Ok("Codex OAuth login complete".to_string()));
    let mut lines = Vec::new();

    render_oauth_body(
        &mut lines,
        OAuthFlowView::OAuth(&state),
        OAuthHost::AddWizard,
    );
    let rendered = rendered_text(&lines);

    assert!(rendered.contains("continue"), "{rendered}");
    assert_eq!(option_row_count(&rendered), 1, "{rendered}");
    assert!(!rendered.contains("log in"), "{rendered}");
    assert!(!rendered.contains("skip / continue"), "{rendered}");
    assert!(!rendered.contains("manual paste"), "{rendered}");
}

#[test]
fn codex_oauth_logged_out_renders_start_or_poll_menu() {
    let mut state = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
    state.logged_in = false;
    let mut lines = Vec::new();

    render_oauth_body(
        &mut lines,
        OAuthFlowView::OAuth(&state),
        OAuthHost::AddWizard,
    );
    let rendered = rendered_text(&lines);
    assert!(rendered.contains("log in"), "{rendered}");
    assert!(rendered.contains("skip / continue"), "{rendered}");

    state.set_device_login_for_test(cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
        "https://example.test/device",
        "ABCD-EFGH",
    ));
    lines.clear();
    render_oauth_body(
        &mut lines,
        OAuthFlowView::OAuth(&state),
        OAuthHost::AddWizard,
    );
    let rendered = rendered_text(&lines);
    assert!(rendered.contains("poll for approval"), "{rendered}");
    assert!(rendered.contains("skip / continue"), "{rendered}");
    assert!(!rendered.contains("[continue]"), "{rendered}");
}

#[test]
fn grok_oauth_logged_in_renders_single_continue_row() {
    let mut state = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    state.logged_in = true;
    state.status = Some(Ok("xAI OAuth login complete".to_string()));
    let mut lines = Vec::new();

    render_oauth_body(
        &mut lines,
        OAuthFlowView::OAuth(&state),
        OAuthHost::AddWizard,
    );
    let rendered = rendered_text(&lines);

    assert!(rendered.contains("continue"), "{rendered}");
    assert_eq!(option_row_count(&rendered), 1, "{rendered}");
    assert!(!rendered.contains("log in"), "{rendered}");
    assert!(!rendered.contains("manual paste"), "{rendered}");
    assert!(!rendered.contains("skip / continue"), "{rendered}");
}

#[test]
fn grok_oauth_logged_out_renders_full_menu() {
    let mut state = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    state.logged_in = false;
    let mut lines = Vec::new();

    render_oauth_body(
        &mut lines,
        OAuthFlowView::OAuth(&state),
        OAuthHost::AddWizard,
    );
    let rendered = rendered_text(&lines);

    assert!(rendered.contains("log in"), "{rendered}");
    assert!(rendered.contains("manual paste"), "{rendered}");
    assert!(rendered.contains("skip / continue"), "{rendered}");
    assert_eq!(option_row_count(&rendered), 3, "{rendered}");
}

#[test]
fn logged_in_oauth_navigation_clamps_to_single_continue_row() {
    let mut codex = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
    codex.logged_in = true;
    codex.cursor = 99;
    handle_oauth_flow_key(press(KeyCode::Down), &mut codex, OAuthHost::AddWizard);
    assert_eq!(codex.cursor, 0);

    let mut grok = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    grok.logged_in = true;
    grok.cursor = 99;
    handle_oauth_flow_key(press(KeyCode::Up), &mut grok, OAuthHost::AddWizard);
    assert_eq!(grok.cursor, 0);
}

#[test]
fn oauth_grok_login_option_still_begins() {
    let mut state = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    state.logged_in = false;
    state.ssh = false;
    state.cursor = 0;
    let outcome = handle_oauth_flow_key(press(KeyCode::Enter), &mut state, OAuthHost::AddWizard);

    assert!(matches!(
        outcome.action,
        Some(OAuthFlowRequest {
            provider: OAuthProvider::Grok,
            op: OAuthFlowOp::Begin,
        })
    ));
    assert!(state.pending);
}

#[test]
fn standalone_oauth_enter_on_continue_returns_to_edit() {
    for provider in [OAuthProvider::Codex, OAuthProvider::Grok] {
        let (_, mut dialog) = dialog_with_config(ProvidersConfig::default());
        let mut state = OAuthFlowState::new_without_acknowledgement_for_test(provider);
        state.logged_in = true;
        state.cursor = 0;
        let mut page = standalone_oauth_page(provider, state);

        let nav = dialog.handle_providers_page_key(press(KeyCode::Enter), &mut page);

        let ProvidersPage::Edit(edit) = replaced_provider(&nav) else {
            panic!("expected OAuthSetup to return to Edit");
        };
        let expected_id = match provider {
            OAuthProvider::Codex => "codex-oauth",
            OAuthProvider::Grok => "grok-oauth",
        };
        assert_eq!(edit.provider_id, expected_id);
    }
}

#[test]
fn add_wizard_oauth_enter_saves_without_backing_out() {
    for (template_id, provider) in [
        ("codex-oauth", OAuthProvider::Codex),
        ("grok-oauth", OAuthProvider::Grok),
    ] {
        let (_, mut dialog) = dialog_with_config(ProvidersConfig::default());
        let mut oauth = OAuthFlowState::new_without_acknowledgement_for_test(provider);
        oauth.logged_in = true;
        oauth.cursor = 0;
        let mut state = add_state_for_oauth(template_id, oauth);

        dialog.handle_add_key(press(KeyCode::Enter), &mut state);

        assert!(
            dialog.config.providers.contains_key(template_id),
            "{template_id} should be saved"
        );
        assert_ne!(state.run.current_step_id(), Some("url"));
        assert!(
            state.oauth_auth.is_some(),
            "{template_id} OAuth state should not be cleared by back-out"
        );
    }
}

#[test]
fn standalone_oauth_body_exposes_skip_only_while_active() {
    for provider in [OAuthProvider::Codex, OAuthProvider::Grok] {
        let mut logged_out = OAuthFlowState::new_without_acknowledgement_for_test(provider);
        logged_out.logged_in = false;
        assert!(
            !oauth_body_text(&logged_out, OAuthHost::Standalone).contains("skip / continue"),
            "{provider:?} logged-out standalone body should hide skip"
        );

        let mut active = OAuthFlowState::new_without_acknowledgement_for_test(provider);
        match provider {
            OAuthProvider::Grok => {
                active.set_browser_session_for_test("https://example.test/oauth");
                active.pending = true;
            }
            OAuthProvider::Codex => {
                active.set_device_login_for_test(
                    cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
                        "https://example.test/device",
                        "CODE-123",
                    ),
                );
            }
        }
        assert!(
            oauth_body_text(&active, OAuthHost::Standalone).contains("skip / continue"),
            "{provider:?} active standalone body should expose skip"
        );

        let mut confirming = OAuthFlowState::new_without_acknowledgement_for_test(provider);
        confirming.logged_in = true;
        assert!(
            !oauth_body_text(&confirming, OAuthHost::Standalone).contains("skip / continue"),
            "{provider:?} confirming standalone body should hide skip"
        );
    }
}

#[test]
fn add_host_oauth_body_keeps_skip_continue_row() {
    let mut codex = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
    codex.logged_in = false;
    assert!(oauth_body_text(&codex, OAuthHost::AddWizard).contains("skip / continue"));
    codex.set_device_login_for_test(cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
        "https://example.test/device",
        "CODE-123",
    ));
    assert!(oauth_body_text(&codex, OAuthHost::AddWizard).contains("skip / continue"));

    let mut grok = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    grok.logged_in = false;
    assert!(oauth_body_text(&grok, OAuthHost::AddWizard).contains("skip / continue"));
    grok.set_browser_session_for_test("https://example.test/oauth");
    grok.pending = true;
    assert!(oauth_body_text(&grok, OAuthHost::AddWizard).contains("skip / continue"));
}

#[test]
fn oauth_option_count_matches_rendered_rows_per_host() {
    for host in [OAuthHost::Standalone, OAuthHost::AddWizard] {
        let mut grok_logged_out =
            OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
        grok_logged_out.logged_in = false;
        assert_eq!(
            grok_logged_out.option_count(host),
            oauth_option_rows(&grok_logged_out, host)
        );

        let mut grok_pending =
            OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
        grok_pending.set_browser_session_for_test("https://example.test/oauth");
        grok_pending.pending = true;
        assert_eq!(
            grok_pending.option_count(host),
            oauth_option_rows(&grok_pending, host)
        );

        let mut codex_logged_out =
            OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
        codex_logged_out.logged_in = false;
        assert_eq!(
            codex_logged_out.option_count(host),
            oauth_option_rows(&codex_logged_out, host)
        );

        let mut codex_device =
            OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
        codex_device.set_device_login_for_test(
            cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
                "https://example.test/device",
                "CODE-123",
            ),
        );
        assert_eq!(
            codex_device.option_count(host),
            oauth_option_rows(&codex_device, host)
        );

        let mut confirming =
            OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
        confirming.logged_in = true;
        assert_eq!(
            confirming.option_count(host),
            oauth_option_rows(&confirming, host)
        );
    }
}

#[derive(Debug, Clone, Copy)]
enum ExpectedEnter {
    Action,
    Confirm,
    PasteFocus,
}

fn assert_enter_effect(
    mut state: OAuthFlowState,
    host: OAuthHost,
    cursor: usize,
    expected: ExpectedEnter,
) {
    state.cursor = cursor;
    let outcome = handle_oauth_flow_key(press(KeyCode::Enter), &mut state, host);
    match expected {
        ExpectedEnter::Action => assert!(outcome.action.is_some(), "{host:?} cursor {cursor}"),
        ExpectedEnter::Confirm => {
            assert_eq!(outcome.nav, OAuthNav::Confirm, "{host:?} cursor {cursor}")
        }
        ExpectedEnter::PasteFocus => assert!(state.paste_focused, "{host:?} cursor {cursor}"),
    }
}

#[test]
fn every_visible_oauth_row_acts_on_enter() {
    for host in [OAuthHost::Standalone, OAuthHost::AddWizard] {
        assert_enter_effect(
            {
                let mut s =
                    OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
                s.logged_in = false;
                s
            },
            host,
            0,
            ExpectedEnter::Action,
        );
        assert_enter_effect(
            {
                let mut s =
                    OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
                s.logged_in = false;
                s
            },
            host,
            1,
            ExpectedEnter::Action,
        );
        if host == OAuthHost::AddWizard {
            assert_enter_effect(
                {
                    let mut s =
                        OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
                    s.logged_in = false;
                    s
                },
                host,
                2,
                ExpectedEnter::Confirm,
            );
        }

        let pending_grok = || {
            let mut state =
                OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
            state.set_browser_session_for_test("https://example.test/oauth");
            state.pending = true;
            state
        };
        let manual_index = oauth_options(&pending_grok(), host)
            .iter()
            .position(|option| *option == OAuthOption::ManualPaste)
            .expect("pending Grok renders manual paste");
        let poll_index = oauth_options(&pending_grok(), host)
            .iter()
            .position(|option| *option == OAuthOption::Poll)
            .expect("pending Grok renders poll");
        assert_enter_effect(pending_grok(), host, poll_index, ExpectedEnter::Action);
        assert_enter_effect(
            pending_grok(),
            host,
            manual_index,
            ExpectedEnter::PasteFocus,
        );
        let skip_index = oauth_options(&pending_grok(), host)
            .iter()
            .position(|option| *option == OAuthOption::SkipContinue)
            .expect("pending Grok renders skip / continue");
        assert_enter_effect(pending_grok(), host, skip_index, ExpectedEnter::Confirm);

        assert_enter_effect(
            {
                let mut s =
                    OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
                s.logged_in = false;
                s
            },
            host,
            0,
            ExpectedEnter::Action,
        );
        if host == OAuthHost::AddWizard {
            assert_enter_effect(
                {
                    let mut s =
                        OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
                    s.logged_in = false;
                    s
                },
                host,
                1,
                ExpectedEnter::Confirm,
            );
        }

        assert_enter_effect(
            {
                let mut s =
                    OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
                s.set_device_login_for_test(
                    cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
                        "https://example.test/device",
                        "CODE-123",
                    ),
                );
                s
            },
            host,
            0,
            ExpectedEnter::Action,
        );
        assert_enter_effect(
            {
                let mut s =
                    OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
                s.set_device_login_for_test(
                    cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
                        "https://example.test/device",
                        "CODE-123",
                    ),
                );
                s.polling = true;
                s
            },
            host,
            0,
            ExpectedEnter::Action,
        );
        if host == OAuthHost::AddWizard {
            assert_enter_effect(
                {
                    let mut s =
                        OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
                    s.set_device_login_for_test(
                        cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
                            "https://example.test/device",
                            "CODE-123",
                        ),
                    );
                    s
                },
                host,
                1,
                ExpectedEnter::Confirm,
            );
        }

        assert_enter_effect(
            {
                let mut s =
                    OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
                s.logged_in = true;
                s
            },
            host,
            0,
            ExpectedEnter::Confirm,
        );
    }
}

#[test]
fn codex_skip_row_saves_with_device_code_present() {
    let (_, mut dialog) = dialog_with_config(ProvidersConfig::default());
    let mut oauth = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
    oauth.set_device_login_for_test(cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
        "https://example.test/device",
        "CODE-123",
    ));
    oauth.cursor = 1;
    let mut state = add_state_for_oauth("codex-oauth", oauth);

    dialog.handle_add_key(press(KeyCode::Enter), &mut state);

    assert!(dialog.config.providers.contains_key("codex-oauth"));
    assert_ne!(state.run.current_step_id(), Some("url"));
    assert!(state.oauth_auth.is_some());
}

#[test]
fn grok_pending_skip_row_saves_at_rendered_index() {
    let (_, mut dialog) = dialog_with_config(ProvidersConfig::default());
    let mut oauth = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
    oauth.set_browser_session_for_test("https://example.test/oauth");
    oauth.pending = true;
    oauth.cursor = 1;
    let mut state = add_state_for_oauth("grok-oauth", oauth);

    dialog.handle_add_key(press(KeyCode::Enter), &mut state);

    assert!(dialog.config.providers.contains_key("grok-oauth"));
    assert_ne!(state.run.current_step_id(), Some("url"));
    assert!(state.oauth_auth.is_some());
}

fn codex_standalone_dialog() -> SettingsDialog {
    let (_tmp, mut dialog) = dialog_with_config(ProvidersConfig::default());
    let mut codex = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
    codex.set_device_login_for_test(cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
        "https://example.test/very/long/device/login/path/that/must/be/clipped",
        "ABCD-EFGH",
    ));
    codex.polling = true;
    codex.cursor = 0;
    dialog.set_test_page(Page::Providers(standalone_oauth_page(
        OAuthProvider::Codex,
        codex,
    )));
    dialog
}

#[test]
fn standalone_oauth_setup_scrolls_to_reveal_option_rows() {
    let dialog = codex_standalone_dialog();
    let rendered = render_provider_rows(&dialog, 80, 10).join("\n");

    assert!(rendered.contains("poll for approval"), "{rendered}");
}

#[test]
fn standalone_oauth_setup_renders_full_hints_at_80_columns() {
    let dialog = codex_standalone_dialog();
    let rendered = render_provider_rows(&dialog, 80, 18).join("\n");

    assert_rendered_contains_text(&rendered, "documented Codex agent login");
    assert_rendered_contains_text(&rendered, "refresh-token contention");
    assert_rendered_contains_text(&rendered, "different machine from this terminal");
}

#[test]
fn standalone_oauth_setup_renders_full_hints_at_120_columns() {
    let dialog = codex_standalone_dialog();
    let rendered = render_provider_rows(&dialog, 120, 18).join("\n");

    assert_rendered_contains_text(&rendered, "documented Codex agent login");
    assert_rendered_contains_text(&rendered, "refresh-token contention");
    assert_rendered_contains_text(&rendered, "different machine from this terminal");
}

#[test]
fn standalone_oauth_link_region_survives_scroll_and_clipping() {
    for width in [80, 120] {
        let dialog = codex_standalone_dialog();
        let links = render_provider_links(&dialog, width, 18);
        assert_eq!(links.regions().len(), 1, "{width}");
        let region = &links.regions()[0];
        assert_eq!(
            region.url,
            "https://example.test/very/long/device/login/path/that/must/be/clipped"
        );
        assert!(region.rect.x < width, "{region:?}");
        assert!(
            region.rect.x.saturating_add(region.rect.width) <= width,
            "{region:?}"
        );
    }

    let dialog = codex_standalone_dialog();
    let links = render_provider_links(&dialog, 80, 6);
    assert!(
        links.regions().is_empty(),
        "scrolled-out device URL should not register"
    );
}

#[test]
fn oauth_help_legend_matches_bindings_for_every_host_and_state() {
    for host in [OAuthHost::Standalone, OAuthHost::AddWizard] {
        for provider in [OAuthProvider::Codex, OAuthProvider::Grok] {
            let mut logged_out = OAuthFlowState::new_without_acknowledgement_for_test(provider);
            logged_out.logged_in = false;
            let legend = oauth_help_legend(host, &logged_out);
            assert!(!legend.contains("enter: continue"), "{host:?} {provider:?}");
            assert_eq!(
                legend.contains("s: skip/continue"),
                host == OAuthHost::AddWizard
            );
            assert!(legend.contains("esc: back"), "{legend}");

            let mut active = OAuthFlowState::new_without_acknowledgement_for_test(provider);
            match provider {
                OAuthProvider::Grok => {
                    active.set_browser_session_for_test("https://example.test/oauth");
                    active.pending = true;
                }
                OAuthProvider::Codex => {
                    active.set_device_login_for_test(
                        cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
                            "https://example.test/device",
                            "CODE-123",
                        ),
                    );
                    active.polling = true;
                }
            }
            let legend = oauth_help_legend(host, &active);
            assert!(legend.contains("esc: cancel login"), "{legend}");
            assert_eq!(
                legend.contains("s: skip/continue"),
                host == OAuthHost::AddWizard
            );
            assert!(legend.contains("c:"), "{legend}");
            assert_eq!(
                legend.contains("y:"),
                provider == OAuthProvider::Codex,
                "{legend}"
            );

            let mut confirming = OAuthFlowState::new_without_acknowledgement_for_test(provider);
            confirming.logged_in = true;
            let legend = oauth_help_legend(host, &confirming);
            assert!(legend.contains("enter: continue"), "{legend}");
            assert_eq!(
                legend.contains("s: skip/continue"),
                host == OAuthHost::AddWizard
            );

            if provider == OAuthProvider::Grok {
                let mut paste = OAuthFlowState::new_without_acknowledgement_for_test(provider);
                paste.paste_focused = true;
                let legend = oauth_help_legend(host, &paste);
                assert_eq!(legend, "type/paste code  enter: submit  esc: options");
            }
        }
    }
}

#[test]
fn logged_in_oauth_enter_advances_add_wizard() {
    for template_id in ["codex-oauth", "grok-oauth"] {
        let template = templates::template_by_id(template_id).unwrap();
        let (_, mut dialog) = dialog_with_config(ProvidersConfig::default());
        let mut state = AddState::new();
        state.template = Some(template);
        state.id_field.set(template_id);
        state.url_field.set(template.url);
        let oauth = match template_id {
            "codex-oauth" => {
                let mut oauth =
                    OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
                oauth.logged_in = true;
                oauth.cursor = 0;
                oauth
            }
            "grok-oauth" => {
                let mut oauth =
                    OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Grok);
                oauth.logged_in = true;
                oauth.cursor = 0;
                oauth
            }
            _ => unreachable!(),
        };
        state.enter_oauth_for_test(oauth);

        dialog.handle_add_key(press(KeyCode::Enter), &mut state);

        assert!(
            dialog.config.providers.contains_key(template_id),
            "{template_id} should be saved"
        );
        assert_ne!(state.run.current_step_id(), Some("url"));
        assert!(state.oauth_auth.is_some());
        assert!(
            !matches!(
                state.run.current_step_id(),
                Some("grok-oauth" | "codex-oauth")
            ),
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
        state.enter_template_for_test(template_cursor(t.id));

        dialog.handle_add_key(press(KeyCode::Enter), &mut state);

        assert!(
            state.is_step("id"),
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
    state.enter_template_for_test(template_cursor("anthropic"));

    // Pick the template — lands on EditId with the default `anthropic` id.
    dialog.handle_add_key(press(KeyCode::Enter), &mut state);
    assert!(state.is_step("id"));
    assert_eq!(state.id_field.text(), "anthropic");

    // The default id collides with the existing provider.
    dialog.handle_add_key(press(KeyCode::Enter), &mut state);
    assert!(state.is_step("id"), "collision keeps EditId");
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
        state.is_step("url"),
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

#[test]
pub(crate) fn copilot_setup_effect_accepts_only_its_live_operation_once() {
    struct Spy {
        calls: usize,
    }
    impl CopilotSetupEffect for Spy {
        fn apply(
            &mut self,
            _shell: CopilotShell,
            _rc_path: &std::path::Path,
            _credential_store_path: Option<&std::path::Path>,
        ) -> Result<String, String> {
            self.calls += 1;
            Ok("effect complete".into())
        }
    }

    let mut state = CopilotSetupState {
        shell: Some(CopilotShell::Bash),
        rc_path: Some(std::path::PathBuf::from("/not-touched-in-test")),
        already_configured: false,
        outcome: None,
        operation: super::super::shell::PointerOperationGate::default(),
    };
    let mut spy = Spy { calls: 0 };
    state.submit(None, &mut spy);
    assert_eq!(spy.calls, 1);
    assert_eq!(
        state.outcome.as_ref().unwrap().as_deref(),
        Ok("effect complete")
    );

    let stale = super::super::shell::PointerOperationId(99);
    state.complete(stale, Err("stale".into()));
    assert_eq!(
        state.outcome.as_ref().unwrap().as_deref(),
        Ok("effect complete")
    );
    state.submit(None, &mut spy);
    assert_eq!(spy.calls, 1, "a terminal result cannot be submitted twice");
}

#[test]
pub(crate) fn oauth_copy_completion_is_flow_scoped_and_exactly_once() {
    use super::super::pointer_actions::{OAuthCopyKind, ProvidersAction, SettingsPointerAction};

    let _guard = OAUTH_EFFECTS_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    reset_oauth_effects(false);
    let (tmp, mut dialog) = dialog_with_config(oauth_provider_config("grok-oauth", "oauth:test"));
    let mut visible = OAuthFlowState::new_without_acknowledgement_with_effects_for_test(
        OAuthProvider::Grok,
        fake_oauth_effects(),
    );
    visible.set_browser_session_for_test("https://example.test/oauth");
    let visible_flow_id = visible.flow_id;
    dialog.page = super::super::providers_page(standalone_oauth_page(OAuthProvider::Grok, visible));
    let _ = render_provider_rows(&dialog, 110, 60);
    let action = SettingsPointerAction::Providers(ProvidersAction::CopyOAuth(
        visible_flow_id,
        OAuthCopyKind::AuthorizationUrl,
    ));
    assert_eq!(
        super::super::pointer_action_fixtures::key_for(&action),
        super::super::pointer_action_fixtures::ActionFixtureKey::Providers(
            super::super::pointer_action_fixtures::ProvidersFixture::CopyAuthorizationUrl,
        )
    );
    click_rendered_provider_action(&mut dialog, &action);
    assert_eq!(
        oauth_effects_log(),
        vec!["copy:https://example.test/oauth".to_string()]
    );
    assert!(matches!(
        dialog.test_page(),
        TestPageRef::Providers(ProvidersPage::OAuthSetup { state, .. })
            if state.flow_id == visible_flow_id
                && state.status.as_ref().is_some_and(|status| {
                    status.as_ref().is_ok_and(|message| message.contains("copied OAuth URL"))
                })
    ));
    drop(tmp);

    reset_oauth_effects(false);
    let (tmp, mut dialog) = dialog_with_config(oauth_provider_config("codex-oauth", "oauth:test"));
    let mut visible = OAuthFlowState::new_without_acknowledgement_with_effects_for_test(
        OAuthProvider::Codex,
        fake_oauth_effects(),
    );
    visible.set_device_login_for_test(cockpit_core::auth::codex_oauth::DeviceLogin::for_test(
        "https://example.test/device",
        "CODE-123",
    ));
    let visible_flow_id = visible.flow_id;
    dialog.page =
        super::super::providers_page(standalone_oauth_page(OAuthProvider::Codex, visible));
    let action = SettingsPointerAction::Providers(ProvidersAction::CopyOAuth(
        visible_flow_id,
        OAuthCopyKind::DeviceCode,
    ));
    assert_eq!(
        super::super::pointer_action_fixtures::key_for(&action),
        super::super::pointer_action_fixtures::ActionFixtureKey::Providers(
            super::super::pointer_action_fixtures::ProvidersFixture::CopyDeviceCode,
        )
    );
    click_rendered_provider_action(&mut dialog, &action);
    assert_eq!(
        oauth_effects_log(),
        vec![
            "copy:CODE-123".to_string(),
            "open:https://example.test/device".to_string(),
        ]
    );
    assert!(matches!(
        dialog.test_page(),
        TestPageRef::Providers(ProvidersPage::OAuthSetup { state, .. })
            if state.flow_id == visible_flow_id
                && state.status.as_ref().is_some_and(|status| status.as_deref() == Ok(
                    "copied device code (unverified — also reachable via the Open link above)"
                ))
    ));
    drop(tmp);

    let mut state = OAuthFlowState::new_without_acknowledgement_for_test(OAuthProvider::Codex);
    let (flow_id, operation_id) = state.begin_copy_for_test();
    state.complete_copy(flow_id, operation_id, Ok("copied".into()));
    assert_eq!(state.status.as_ref().unwrap().as_deref(), Ok("copied"));

    state.complete_copy(flow_id, operation_id, Err("duplicate".into()));
    assert_eq!(state.status.as_ref().unwrap().as_deref(), Ok("copied"));

    let (live_flow, live_operation) = state.begin_copy_for_test();
    state.cancel_copy_effect();
    state.complete_copy(
        live_flow,
        live_operation,
        Err("cancelled late result".into()),
    );
    assert_eq!(state.status.as_ref().unwrap().as_deref(), Ok("copied"));

    let (live_flow, live_operation) = state.begin_copy_for_test();
    state.complete_copy(
        super::super::pointer_actions::OAuthFlowId(live_flow.0.saturating_add(1)),
        live_operation,
        Err("wrong flow".into()),
    );
    assert_eq!(state.status.as_ref().unwrap().as_deref(), Ok("copied"));
}
