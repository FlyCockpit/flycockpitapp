use super::*;
use cockpit_config::providers::{ModelEntry, ProviderEntry};
use providers::{FetchAllState, valid_url};
use ratatui::Terminal;
use ratatui::backend::{Backend, TestBackend};
use std::collections::BTreeMap;

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
                mode: None,
                inline_think: None,
                hint_tool_call_corrections: None,
                text_embedded_recovery: None,
                thinking_params: Default::default(),
                system_prompt: None,
                wire_api: Default::default(),
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
                mode: None,
                inline_think: None,
                hint_tool_call_corrections: None,
                text_embedded_recovery: None,
                thinking_params: Default::default(),
                system_prompt: None,
                wire_api: Default::default(),
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
                mode: None,
                inline_think: None,
                hint_tool_call_corrections: None,
                text_embedded_recovery: None,
                thinking_params: Default::default(),
                system_prompt: None,
                wire_api: Default::default(),
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

fn fresh_dialog(tmp: &TempDir) -> SettingsDialog {
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    SettingsDialog::open(path)
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
    let mut d = fresh_dialog(&tmp);
    std::fs::set_permissions(&d.extended_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

    d.extended.redact.denylist = vec!["secret-value".to_string()];
    d.save_extended().unwrap();

    let file_mode = std::fs::metadata(&d.extended_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let dir_mode = std::fs::metadata(tmp.path()).unwrap().permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o600);
    assert_eq!(dir_mode, 0o700);
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
    let mut codex = providers::OAuthFlowState::new(OAuthProvider::Codex);
    codex.logged_in = true;
    let mut add = providers::AddState::new();
    add.enter_oauth_for_test(codex);
    d.set_test_page(Page::Providers(ProvidersPage::Add(add)));
    assert_eq!(
        d.help_text(),
        "enter: continue  s: skip/continue  esc: back"
    );

    let mut grok = providers::OAuthFlowState::new(OAuthProvider::Grok);
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
    let mut grok = providers::OAuthFlowState::new(OAuthProvider::Grok);
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
    let mut grok = providers::OAuthFlowState::new(OAuthProvider::Grok);
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

    let mut grok = providers::OAuthFlowState::new(OAuthProvider::Grok);
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
    let mut grok_confirming = providers::OAuthFlowState::new(OAuthProvider::Grok);
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

    let mut codex = providers::OAuthFlowState::new(OAuthProvider::Codex);
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

    let mut codex_confirming = providers::OAuthFlowState::new(OAuthProvider::Codex);
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
fn open_category_on(d: &mut SettingsDialog, category: Category, id: SettingId) {
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

fn render_settings_rows(d: &SettingsDialog, width: u16, height: u16) -> Vec<String> {
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

#[derive(Default)]
struct ProbePage {
    handled: bool,
}

impl SettingsPage for ProbePage {
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

    let rows = render_settings_rows(&d, 40, 4).join("\n");
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
        p.cursor = p.cursor_of(SettingId::LlmMode).expect("llm mode");
    }
    let rendered = render_settings_rows(&d, 62, 18).join("\n");
    let continuation = rendered
        .lines()
        .find(|line| line.contains("default) uses"))
        .unwrap_or_else(|| panic!("expected wrapped llm-mode value:\n{rendered}"));
    assert!(
        continuation.starts_with("│     "),
        "continuation should stay in the value column, not column 0:\n{rendered}"
    );
    assert!(
        !continuation.starts_with("│defensive") && !continuation.starts_with("│default"),
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
fn behavior_llm_mode_row_toggles_and_persists() {
    use cockpit_config::extended::{ExtendedConfigDoc, LlmMode};
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    assert_eq!(d.extended.llm_mode, LlmMode::Defensive);
    open_category_on(&mut d, Category::Behavior, SettingId::LlmMode);
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.llm_mode, LlmMode::Normal);
    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert_eq!(reloaded.llm_mode, LlmMode::Normal);
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.llm_mode, LlmMode::Frontier);
    let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
    assert_eq!(reloaded.llm_mode, LlmMode::Frontier);
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.llm_mode, LlmMode::Defensive);
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
    let path = d
        .take_pending_category_external_edit()
        .expect("category external edit should be pending");
    assert!(d.take_pending_category_external_edit().is_none());
    std::fs::write(&path, "external compact prompt\n").unwrap();
    d.finish_category_external_edit(None);

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
    use cockpit_core::tools::sandbox_mode::SandboxMode;

    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
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
    let global = tmp.path().join(".config/cockpit/config.json");
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

fn dialog_with_one_provider(tmp: &TempDir) -> SettingsDialog {
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    write_provider_file(&path, "vendor", r#"{"url":"https://x","headers":[]}"#);
    let mut d = SettingsDialog::open(path);
    d.enter_providers();
    d
}

#[test]
fn save_config_preserves_untouched_provider_file_disk_edits() {
    let tmp = TempDir::new().unwrap();
    let mut d = dialog_with_one_provider(&tmp);
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
    });
    d.save_config().unwrap();

    let reloaded = cockpit_config::providers::ConfigDoc::load(&d.config_path)
        .unwrap()
        .providers();
    assert_eq!(reloaded.providers["vendor"].url, "https://out-of-band");
    assert_eq!(
        reloaded
            .active_model
            .as_ref()
            .map(|active| active.model.as_str()),
        Some("m1")
    );
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
    let mut d = dialog_with_one_provider(&tmp);
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
    let mut d = dialog_with_one_provider(&tmp);
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
    let mut d = dialog_with_one_provider(&tmp);
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
    let mut d = dialog_with_one_provider(&tmp);
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
    let mut d = dialog_with_one_provider(&tmp);
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
    let mut d = dialog_with_one_provider(&tmp);
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
    let mut d = dialog_with_one_provider(&tmp);
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
            mode: None,
            inline_think: None,
            hint_tool_call_corrections: None,
            text_embedded_recovery: None,
            thinking_params: Default::default(),
            system_prompt: None,
            wire_api: Default::default(),
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
    let state = ProvidersPage::FetchAll(FetchAllState::spawn(&d.config));
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
fn first_run_completion_copy_points_to_security_and_help() {
    let d = Dialog::open_first_run_complete();
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
    d.handle_key(press(KeyCode::Enter)); // trusted-only default
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
            images: Some(true),
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

fn enter_root_node(d: &mut SettingsDialog, title: &str) {
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

    let mut d = SettingsDialog::open(path.clone());
    d.command_installed = |_| true;
    seed_via_keys(&mut d);
    assert_eq!(harness_status(&d).as_deref(), Some("saved"));

    let mut reopened = SettingsDialog::open(path);
    enter_harnesses_from_root(&mut reopened);
    for name in ["claude", "codex", "opencode", "copilot", "goose", "grok"] {
        assert!(
            reopened.extended.harnesses.contains_key(name),
            "missing seeded preset `{name}` after reopening settings"
        );
    }
}

#[test]
fn harnesses_page_shows_rows_and_warning_when_unrelated_field_is_malformed() {
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

    let mut d = SettingsDialog::open(path);
    enter_harnesses_from_root(&mut d);
    assert!(d.extended.harnesses.contains_key("codex"));
    assert!(
        harness_status(&d)
            .as_deref()
            .is_some_and(|s| s.contains("ignored malformed `tui`")),
        "expected malformed-field warning, got {:?}",
        harness_status(&d)
    );
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
fn open_utility_picker(d: &mut SettingsDialog) {
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

fn dialog_with_models(tmp: &TempDir) -> SettingsDialog {
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
    SettingsDialog::open(path)
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
fn string_list_delete_requires_second_press_and_first_press_does_not_persist() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.extended.redact.denylist = vec!["secret-value".to_string(), "other-value".to_string()];
    d.save_extended().unwrap();
    d.set_test_page(Page::StringList(
        Box::new(StringListPage::redact_denylist()),
    ));

    d.handle_key(press(KeyCode::Char('d')));
    match d.test_page() {
        TestPageRef::StringList(p) => {
            assert_eq!(
                d.extended.redact.denylist,
                vec!["secret-value".to_string(), "other-value".to_string()],
                "first press only arms"
            );
            assert!(p.delete.is_pending_for(0));
            let status = p.status.as_deref().unwrap_or("");
            assert!(status.contains(secret_display::MASKED_VALUE));
            assert!(!status.contains("secret-value"));
        }
        other => panic!("expected StringList, got {other:?}"),
    }
    let on_disk = std::fs::read_to_string(&d.extended_path).unwrap();
    assert!(
        on_disk.contains("secret-value"),
        "single delete press must not persist removal:\n{on_disk}"
    );

    d.handle_key(press(KeyCode::Down));
    match d.test_page() {
        TestPageRef::StringList(p) => {
            assert!(!p.delete.is_pending_for(0), "navigation disarms");
        }
        other => panic!("expected StringList, got {other:?}"),
    }
    d.handle_key(press(KeyCode::Char('d')));
    assert_eq!(
        d.extended.redact.denylist.len(),
        2,
        "fresh first press on row 1 only arms"
    );
    d.handle_key(press(KeyCode::Char('d')));
    assert_eq!(d.extended.redact.denylist, vec!["secret-value".to_string()]);
    let on_disk = std::fs::read_to_string(&d.extended_path).unwrap();
    assert!(!on_disk.contains("other-value"), "{on_disk}");
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
            assert_eq!(grabbed.original_name.as_deref(), Some("secret-value"));
        }
        other => panic!("expected StringList, got {other:?}"),
    }
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.redact.denylist, vec!["secret-value".to_string()]);

    d.handle_key(press(KeyCode::Enter));
    for ch in "replacement".chars() {
        d.handle_key(press(KeyCode::Char(ch)));
    }
    d.handle_key(press(KeyCode::Enter));
    assert_eq!(d.extended.redact.denylist, vec!["replacement".to_string()]);
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
    let mut d = fresh_dialog(&tmp);
    enter_tools_from_root(&mut d);
    let empty = tools_page_lines(&d).join("\n");
    assert!(empty.contains("No MCP servers configured."), "{empty}");
    assert!(empty.contains("configure in MCP ->"), "{empty}");

    let raw = r#"{"servers":{"docs":{"transport":"streamable","endpoint":"https://example.test/mcp","enabled":true}}}"#;
    std::fs::write(tmp.path().join("mcp.json"), raw).unwrap();
    let cfg = cockpit_core::mcp::config::McpConfig::parse(raw).unwrap();
    let server = cfg.servers.get("docs").unwrap();
    let cache_dir = tmp.path().join("mcp-cache");
    cockpit_core::mcp::cache::save_in(
        &cache_dir,
        &cockpit_core::mcp::cache::cache_key("docs", server),
        &[cockpit_core::mcp::protocol::ToolDescriptor {
            name: "lookup".into(),
            description: "Find docs\nwith details".into(),
            input_schema: serde_json::json!({}),
        }],
    )
    .unwrap();
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

#[test]
fn tools_page_web_key_entry_persists_and_renders_masked() {
    let tmp = TempDir::new().unwrap();
    let mut d = fresh_dialog(&tmp);
    d.credential_store_path = Some(tmp.path().join("credentials.json"));
    enter_tools_from_root(&mut d);

    set_tools_cursor_to_label(&mut d, "api key");
    d.handle_key(press(KeyCode::Enter)); // key field
    d.paste("fc-secret-value");

    let p = match d.test_page() {
        TestPageRef::Tools(p) => p,
        other => panic!("expected Tools, got {other:?}"),
    };
    let rendered = d
        .build_tools_page_lines(80, p)
        .into_iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|s| s.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(rendered.contains(secret_display::MASKED_VALUE));
    assert!(!rendered.contains("fc-secret-value"));

    d.handle_key(press(KeyCode::Enter));
    let store =
        cockpit_core::credentials::CredentialStore::open(d.credential_store_path.clone().unwrap())
            .unwrap();
    assert_eq!(
        store.api_key("firecrawl").as_deref(),
        Some("fc-secret-value")
    );

    let p = match d.test_page() {
        TestPageRef::Tools(p) => p,
        other => panic!("expected Tools, got {other:?}"),
    };
    let rendered = d
        .build_tools_page_lines(80, p)
        .into_iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|s| s.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(rendered.contains(secret_display::MASKED_VALUE));
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
        d.extended.redact.denylist,
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
    assert_eq!(reloaded.redact.denylist, d.extended.redact.denylist);
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
