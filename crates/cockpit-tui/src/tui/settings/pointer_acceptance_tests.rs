use super::SettingsPointerSurfaceKind;
use super::pointer_actions::*;
use super::shell::{
    PointerOperationGate, PointerOperationId, SettingsHeaderAction,
    SettingsPointerAction as RenderAction, SettingsPointerSurface, SettingsPointerTarget,
};
use crossterm::event::MouseEventKind;
use ratatui::layout::Rect;
use tempfile::TempDir;

use super::tests::{fresh_dialog, render_settings_rows, settings_mouse};
use super::{SettingsPointerOutcome, TestPageRef};
use std::cell::RefCell;
use std::collections::HashSet;

thread_local! {
    static ACTION_COVERAGE: RefCell<(HashSet<String>, HashSet<String>)> = RefCell::default();
}

fn action_variant_key(action: &SettingsPointerAction) -> String {
    let debug = format!("{action:?}");
    let mut depth = 0;
    for (index, ch) in debug.char_indices() {
        match ch {
            '(' => {
                depth += 1;
                if depth == 2 {
                    return debug[..index].to_string();
                }
            }
            ')' if depth == 1 => return debug[..=index].to_string(),
            ')' => depth -= 1,
            _ => {}
        }
    }
    debug
}

pub(super) fn record_rendered_action(action: &SettingsPointerAction) {
    assert_source_action_family_is_exhaustive(action);
    ACTION_COVERAGE.with(|coverage| {
        coverage.borrow_mut().0.insert(action_variant_key(action));
    });
}

pub(super) fn record_dispatched_action(action: &SettingsPointerAction) {
    ACTION_COVERAGE.with(|coverage| {
        coverage.borrow_mut().1.insert(action_variant_key(action));
    });
}

fn click_target(dialog: &mut super::SettingsDialog, target: &SettingsPointerTarget) {
    for kind in [
        MouseEventKind::Down(crossterm::event::MouseButton::Left),
        MouseEventKind::Up(crossterm::event::MouseButton::Left),
    ] {
        dialog.handle_pointer(settings_mouse(kind, target.rect.x, target.rect.y));
    }
}

fn rendered_surface() -> SettingsPointerSurface {
    let surface = SettingsPointerSurface::default();
    surface.clear_for(Rect::new(10, 5, 30, 10));
    surface.register(SettingsPointerTarget {
        rect: Rect::new(12, 7, 8, 1),
        action: RenderAction::Page(SettingsPointerAction::Root(RootAction::Open(RootNodeId(
            "interface".into(),
        )))),
        enabled: true,
        disabled_reason: None,
    });
    surface.register(SettingsPointerTarget {
        rect: Rect::new(12, 8, 8, 1),
        action: RenderAction::Page(SettingsPointerAction::Tools(ToolsAction::ReadOnlyBuiltin(
            BuiltinToolId("read".into()),
        ))),
        enabled: false,
        disabled_reason: Some("read only"),
    });
    surface
}

fn assert_rendered_action_matrix(actions: &[SettingsPointerAction]) {
    let surface = SettingsPointerSurface::default();
    surface.clear_for(Rect::new(4, 3, 40, actions.len() as u16));
    for (index, action) in actions.iter().cloned().enumerate() {
        assert_source_action_family_is_exhaustive(&action);
        surface.register(SettingsPointerTarget {
            rect: Rect::new(4, 3 + index as u16, 40, 1),
            action: RenderAction::Page(action.clone()),
            enabled: true,
            disabled_reason: None,
        });
        assert_eq!(
            surface.hit(5, 3 + index as u16).map(|target| target.action),
            Some(RenderAction::Page(action))
        );
    }
    assert!(surface.hit(3, 3).is_none(), "left gutter is inert");
    assert!(
        surface.hit(44, 3).is_none(),
        "right clipped boundary is inert"
    );
}

#[test]
fn settings_pointer_contract_covers_all_current_pages() {
    super::tests::run_pointer_dialog_regression_matrix();
    let surfaces = [
        SettingsPointerSurfaceKind::Root,
        SettingsPointerSurfaceKind::DefaultModel,
        SettingsPointerSurfaceKind::Agents,
        SettingsPointerSurfaceKind::Tools,
        SettingsPointerSurfaceKind::Harnesses,
        SettingsPointerSurfaceKind::Providers,
        SettingsPointerSurfaceKind::Category,
        SettingsPointerSurfaceKind::Instructions,
        SettingsPointerSurfaceKind::RedactPatterns,
        SettingsPointerSurfaceKind::StringList,
        SettingsPointerSurfaceKind::Skills,
        SettingsPointerSurfaceKind::Mcp,
        SettingsPointerSurfaceKind::Lsp,
    ];
    assert_eq!(surfaces.len(), 13);
}

#[test]
fn settings_pointer_dispatch_preempts_chat() {
    crate::tui::app::settings_pointer_tests::run_settings_pointer_z_order_matrix();
    let surface = rendered_surface();
    assert_eq!(
        surface.hit(13, 7).unwrap().action,
        RenderAction::Page(SettingsPointerAction::Root(RootAction::Open(RootNodeId(
            "interface".into()
        ))))
    );
    let area = surface.area.get().unwrap();
    assert!(39 >= area.x && 39 < area.right() && 14 >= area.y && 14 < area.bottom());
    assert!(
        surface.hit(1, 1).is_none(),
        "outside settings cannot reach an underlying route"
    );
}

#[test]
fn settings_wheel_moves_focus_and_liststate_without_activation() {
    let tmp = TempDir::new().unwrap();
    let mut dialog = fresh_dialog(&tmp);
    let _ = render_settings_rows(&dialog, 80, 12);
    let target = dialog
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find(|target| {
            matches!(
                target.action,
                RenderAction::Page(SettingsPointerAction::Root(_))
            )
        })
        .cloned()
        .expect("rendered root target");
    assert_eq!(
        dialog.handle_pointer(settings_mouse(
            MouseEventKind::ScrollDown,
            target.rect.x,
            target.rect.y,
        )),
        SettingsPointerOutcome::Consumed
    );
    assert!(matches!(
        dialog.test_page(),
        TestPageRef::Root { cursor: 3 }
    ));
    for _ in 0..8 {
        let _ = dialog.handle_pointer(settings_mouse(
            MouseEventKind::ScrollUp,
            target.rect.x,
            target.rect.y,
        ));
    }
    assert!(matches!(
        dialog.test_page(),
        TestPageRef::Root { cursor: 0 }
    ));
}

#[test]
fn settings_pointer_clicks_visible_controls_only() {
    let tmp = TempDir::new().unwrap();
    let mut dialog = fresh_dialog(&tmp);
    let _ = render_settings_rows(&dialog, 80, 18);
    let target = dialog
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find(|target| {
            matches!(
                target.action,
                RenderAction::Page(SettingsPointerAction::Root(_))
            )
        })
        .cloned()
        .expect("rendered root target");
    assert_eq!(
        dialog.handle_pointer(settings_mouse(
            MouseEventKind::Down(crossterm::event::MouseButton::Left),
            target.rect.x,
            target.rect.y,
        )),
        SettingsPointerOutcome::Consumed
    );
    assert!(!matches!(dialog.test_page(), TestPageRef::Root { .. }));
    super::providers::tests::run_pointer_provider_regression_matrix();
}

#[test]
fn settings_text_click_places_grapheme_safe_caret() {
    super::tests::run_pointer_text_layout_matrix();
    let mut field = crate::tui::textfield::TextField::new("a界e\u{301}");
    field.set_cursor_display_col(2);
    assert!(field.cursor() <= field.text().len());
    assert!(field.text().is_char_boundary(field.cursor()));
}

#[test]
fn settings_pointer_picker_and_suggestion_actions_match_enter() {
    super::tests::run_pointer_picker_suggestion_matrix();
    assert_rendered_action_matrix(&[
        SettingsPointerAction::UtilityModel(UtilityModelAction::Select(UtilityModelId(
            "provider/model".into(),
        ))),
        SettingsPointerAction::UtilityModel(UtilityModelAction::Clear),
        SettingsPointerAction::UtilityModel(UtilityModelAction::OpenCustom),
        SettingsPointerAction::Category(CategoryAction::SuggestionSelect(
            SettingId(4),
            StableRowId("/workspace/src".into()),
        )),
    ]);
}

#[test]
fn settings_pointer_destructive_confirmations_remain_two_step() {
    let provider = ProviderId("fixture".into());
    let actions = [
        SettingsPointerAction::Providers(ProvidersAction::BeginDelete(provider.clone())),
        SettingsPointerAction::Providers(ProvidersAction::Delete(
            provider.clone(),
            ProviderDeleteChoice::RemoveSecrets,
        )),
        SettingsPointerAction::Providers(ProvidersAction::Delete(
            provider.clone(),
            ProviderDeleteChoice::KeepSecrets,
        )),
        SettingsPointerAction::Providers(ProvidersAction::Delete(
            provider,
            ProviderDeleteChoice::Cancel,
        )),
    ];
    assert_rendered_action_matrix(&actions);
    assert_ne!(actions[0], actions[1], "arming is never confirmation");
}

#[test]
fn settings_pointer_surface_registry_is_exhaustive() {
    settings_pointer_contract_covers_all_current_pages();
    super::providers::tests::run_pointer_provider_regression_matrix();
}

#[test]
fn settings_pointer_links_and_capture_transitions_are_safe() {
    use crossterm::event::MouseButton;
    use std::time::{Duration, Instant};
    let now = Instant::now();
    let mut gesture = crate::tui::links::LinkPointerGesture::default();
    assert_eq!(
        gesture.handle(
            MouseEventKind::Down(MouseButton::Left),
            2,
            3,
            Some("https://example.test"),
            1,
            now
        ),
        crate::tui::links::LinkGestureOutcome::Consumed
    );
    assert_eq!(
        gesture.handle(
            MouseEventKind::Up(MouseButton::Left),
            2,
            3,
            Some("https://example.test"),
            1,
            now + Duration::from_millis(500)
        ),
        crate::tui::links::LinkGestureOutcome::Activate("https://example.test".into())
    );
    assert_eq!(
        gesture.handle(
            MouseEventKind::Up(MouseButton::Left),
            2,
            3,
            Some("https://example.test"),
            1,
            now
        ),
        crate::tui::links::LinkGestureOutcome::Unhandled
    );
    let _ = gesture.handle(
        MouseEventKind::Down(MouseButton::Left),
        2,
        3,
        Some("https://example.test"),
        1,
        now,
    );
    gesture.cancel();
    assert_eq!(
        gesture.handle(
            MouseEventKind::Up(MouseButton::Left),
            2,
            3,
            Some("https://example.test"),
            1,
            now
        ),
        crate::tui::links::LinkGestureOutcome::Unhandled
    );
    super::providers::tests::run_pointer_provider_regression_matrix();
    let surface = rendered_surface();
    surface.enabled.set(false);
    surface.clear_for(Rect::new(0, 0, 1, 1));
    assert!(surface.hit(12, 7).is_none());
}

#[test]
fn settings_pointer_hover_and_help_are_truthful() {
    let surface = rendered_surface();
    let disabled = surface
        .hit(13, 8)
        .expect("disabled target remains discoverable");
    assert!(!disabled.enabled);
    assert_eq!(disabled.disabled_reason, Some("read only"));
    *surface.hover.borrow_mut() = Some(SettingsPointerAction::Root(RootAction::Open(RootNodeId(
        "interface".into(),
    ))));
    surface.clear_for_page(Rect::new(10, 5, 30, 10), 2);
    assert!(surface.hover.borrow().is_none());

    let tmp = TempDir::new().unwrap();
    let mut dialog = fresh_dialog(&tmp);
    let rows = render_settings_rows(&dialog, 80, 18);
    assert!(
        rows.iter()
            .any(|row| row.contains("click: activate") && row.contains("wheel: scroll"))
    );
    let target = dialog
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .find(|target| target.enabled && matches!(target.action, RenderAction::Page(_)))
        .cloned()
        .unwrap();
    dialog.handle_pointer(settings_mouse(
        MouseEventKind::Moved,
        target.rect.x,
        target.rect.y,
    ));
    assert!(dialog.pointer_surface.hover.borrow().is_some());
    let area = dialog.pointer_surface.area.get().unwrap();
    let blank = (area.y..area.bottom())
        .find_map(|row| {
            (area.x..area.right())
                .find(|column| dialog.pointer_surface.hit(*column, row).is_none())
                .map(|column| (column, row))
        })
        .expect("render includes inert title/gutter/blank geometry");
    dialog.handle_pointer(settings_mouse(MouseEventKind::Moved, blank.0, blank.1));
    assert!(
        dialog.pointer_surface.hover.borrow().is_none(),
        "blank move clears hover"
    );
    dialog.handle_pointer(settings_mouse(
        MouseEventKind::Moved,
        target.rect.x,
        target.rect.y,
    ));
    dialog.handle_pointer(settings_mouse(
        MouseEventKind::ScrollDown,
        target.rect.x,
        target.rect.y,
    ));
    assert!(
        dialog.pointer_surface.hover.borrow().is_none(),
        "wheel clears hover"
    );
    dialog.handle_pointer(settings_mouse(
        MouseEventKind::Moved,
        target.rect.x,
        target.rect.y,
    ));
    let _ = render_settings_rows(&dialog, 72, 16);
    assert!(
        dialog.pointer_surface.hover.borrow().is_none(),
        "resize clears hover"
    );
    dialog.extended.tui.mouse_capture = false;
    let _ = render_settings_rows(&dialog, 72, 16);
    assert!(
        dialog.pointer_surface.targets.borrow().is_empty(),
        "capture-off render has no pointer affordances"
    );
}

#[test]
fn settings_pointer_action_registry_is_exhaustive_and_operable() {
    ACTION_COVERAGE.with(|coverage| *coverage.borrow_mut() = Default::default());
    super::tests::run_pointer_dialog_regression_matrix();
    super::providers::tests::run_pointer_provider_regression_matrix();
    super::agents_page::tests::run_pointer_external_edit_exactly_once_regression();
    ACTION_COVERAGE.with(|coverage| {
        let coverage = coverage.borrow();
        let missing = coverage
            .0
            .difference(&coverage.1)
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "enabled rendered actions without reducer dispatch: {missing:?}"
        );
        assert!(
            !coverage.0.is_empty(),
            "real rendered matrix collected no actions"
        );
    });
}

/// No wildcard: adding a list action forces the rendered reducer fixtures to
/// classify it before acceptance compiles.
fn assert_source_list_action_is_covered(action: &ListAction) {
    match action {
        ListAction::Add
        | ListAction::Edit(_)
        | ListAction::Delete(_)
        | ListAction::MoveUp(_)
        | ListAction::MoveDown(_)
        | ListAction::Save
        | ListAction::Cancel => {}
    }
}

#[allow(clippy::too_many_lines)]
fn assert_source_action_family_is_exhaustive(action: &SettingsPointerAction) {
    match action {
        SettingsPointerAction::Root(action) => match action {
            RootAction::Open(_) => {}
        },
        SettingsPointerAction::Category(action) => match action {
            CategoryAction::DescriptorActivate(_)
            | CategoryAction::InlineEditBegin(_)
            | CategoryAction::InlineEditCommit(_)
            | CategoryAction::InlineEditCancel(_)
            | CategoryAction::PathEditBegin(_)
            | CategoryAction::PathEditCommit(_)
            | CategoryAction::PathEditCancel(_)
            | CategoryAction::SuggestionSelect(_, _)
            | CategoryAction::TextEditorSave(_)
            | CategoryAction::TextEditorCancel(_)
            | CategoryAction::PickerSelect(_, _)
            | CategoryAction::Confirm(_, _)
            | CategoryAction::Reset
            | CategoryAction::ExternalEditBegin(_, _)
            | CategoryAction::ExternalEditResult(_, _) => {}
        },
        SettingsPointerAction::Agents(action) => match action {
            AgentsAction::Open(_)
            | AgentsAction::Edit(_)
            | AgentsAction::Delete(_)
            | AgentsAction::Reset(_)
            | AgentsAction::ResetAll
            | AgentsAction::ToggleTool(_, _)
            | AgentsAction::CycleTier(_, _)
            | AgentsAction::Save(_)
            | AgentsAction::OpenRawEditor(_)
            | AgentsAction::EditText(_)
            | AgentsAction::Cancel(_)
            | AgentsAction::ExternalEditBegin(_)
            | AgentsAction::ExternalEditResult(_, _) => {}
        },
        SettingsPointerAction::Tools(action) => match action {
            ToolsAction::CycleWebProvider
            | ToolsAction::EditFirecrawlBaseUrl
            | ToolsAction::EditCredential(_)
            | ToolsAction::EditWebFetchCommand
            | ToolsAction::EditWebSearchCommand
            | ToolsAction::EditUserToolCommand(_)
            | ToolsAction::AddUserTool
            | ToolsAction::ToggleUserTool(_)
            | ToolsAction::ResetToolField(_)
            | ToolsAction::McpJump
            | ToolsAction::Reset
            | ToolsAction::DeleteUserTool(_)
            | ToolsAction::ReadOnlyBuiltin(_)
            | ToolsAction::ReadOnlyMcpTool(_, _) => {}
        },
        SettingsPointerAction::Harnesses(action) => match action {
            HarnessesAction::Open(_)
            | HarnessesAction::Add
            | HarnessesAction::Delete(_)
            | HarnessesAction::SeedInstalledPresets
            | HarnessesAction::ResetAndSeedPresets
            | HarnessesAction::EditField(_)
            | HarnessesAction::Save
            | HarnessesAction::Cancel => {}
        },
        SettingsPointerAction::Skills(action) => match action {
            SkillsAction::ToggleAutoBangCommands
            | SkillsAction::ToggleAncestorWalk
            | SkillsAction::AddScanDirectory
            | SkillsAction::EditScanDirectory(_)
            | SkillsAction::DeleteScanDirectory(_)
            | SkillsAction::ConfirmDeleteScanDirectory(_, _)
            | SkillsAction::Reset => {}
        },
        SettingsPointerAction::Mcp(action) => match action {
            McpAction::Open(_)
            | McpAction::Add
            | McpAction::ToggleEnabled(_)
            | McpAction::Authenticate(_)
            | McpAction::Delete(_)
            | McpAction::EditName
            | McpAction::ToggleEditorEnabled
            | McpAction::CycleTransport
            | McpAction::EditEndpoint
            | McpAction::EditCommand
            | McpAction::EditArgs
            | McpAction::EditBaseEnv
            | McpAction::CycleAuth
            | McpAction::EditHeaderName
            | McpAction::EditHeaderValue
            | McpAction::EditAuthEnv
            | McpAction::EditOauthAuthorizeUrl
            | McpAction::EditOauthTokenUrl
            | McpAction::EditOauthClientId
            | McpAction::EditOauthScopes
            | McpAction::EditCacheTtl
            | McpAction::EditConnectTimeout
            | McpAction::EditRequestTimeout
            | McpAction::Save
            | McpAction::Cancel => {}
        },
        SettingsPointerAction::Providers(action) => match action {
            ProvidersAction::Open(_)
            | ProvidersAction::Add
            | ProvidersAction::EditField(_, _)
            | ProvidersAction::EditHeaders(_)
            | ProvidersAction::CopilotSetup(_)
            | ProvidersAction::OAuthSetup(_, _)
            | ProvidersAction::ManageModels(_)
            | ProvidersAction::ProviderSettings(_)
            | ProvidersAction::Favorite(_)
            | ProvidersAction::Refetch(_)
            | ProvidersAction::RefetchAll
            | ProvidersAction::CycleUnlistedPolicy
            | ProvidersAction::DeepFetchConfirm(_, _)
            | ProvidersAction::BeginDelete(_)
            | ProvidersAction::Delete(_, _)
            | ProvidersAction::SaveProvider(_)
            | ProvidersAction::LocalBack
            | ProvidersAction::AddModel(_)
            | ProvidersAction::RenameModel(_, _)
            | ProvidersAction::DeleteModel(_, _)
            | ProvidersAction::ModelSettings(_, _)
            | ProvidersAction::FetchAllConfirm(_)
            | ProvidersAction::FetchOneConfirm(_, _)
            | ProvidersAction::FetchFallbackConfirm(_, _)
            | ProvidersAction::DeepFetchChoice(_, _)
            | ProvidersAction::WizardControl(_, _)
            | ProvidersAction::RowEditor(_)
            | ProvidersAction::ModelLifecycle(_)
            | ProvidersAction::CopyOAuth(_, _)
            | ProvidersAction::CopilotConfirm(_, _) => {}
        },
        SettingsPointerAction::Lsp(action) => match action {
            LspAction::ToggleEnabled
            | LspAction::CycleAutoInstall
            | LspAction::ToggleDiagnostics
            | LspAction::Edit(_)
            | LspAction::SaveEdit(_)
            | LspAction::CancelEdit(_)
            | LspAction::Reset
            | LspAction::Check(_)
            | LspAction::Install(_)
            | LspAction::Uninstall(_)
            | LspAction::Restart(_) => {}
        },
        SettingsPointerAction::List(action) => assert_source_list_action_is_covered(action),
        SettingsPointerAction::UtilityModel(action) => match action {
            UtilityModelAction::Select(_)
            | UtilityModelAction::Clear
            | UtilityModelAction::OpenCustom
            | UtilityModelAction::Back
            | UtilityModelAction::EditCustom
            | UtilityModelAction::CommitCustom
            | UtilityModelAction::CancelCustom => {}
        },
        SettingsPointerAction::DefaultModel(action) => match action {
            DefaultModelAction::Choose | DefaultModelAction::Clear => {}
        },
    }
}

#[test]
fn every_string_list_renders_and_reduces_stable_two_step_delete_targets() {
    use super::string_list::{StringListKind, StringListPage};

    for kind in [
        StringListKind::AgentDirs,
        StringListKind::ExtraDotenvPaths,
        StringListKind::RedactDenylist,
        StringListKind::RedactAllowlist,
        StringListKind::GitignoreAllow,
    ] {
        let tmp = TempDir::new().unwrap();
        let mut dialog = fresh_dialog(&tmp);
        match kind {
            StringListKind::AgentDirs => dialog.extended.agent_dirs.push("界🙂".into()),
            StringListKind::ExtraDotenvPaths => {
                dialog.extended.redact.extra_dotenv_paths.push("one".into())
            }
            StringListKind::RedactDenylist => dialog.extended.redact.denylist.push("one".into()),
            StringListKind::RedactAllowlist => dialog.extended.redact.allowlist.push("ONE".into()),
            StringListKind::GitignoreAllow => dialog.extended.gitignore_allow.push("one".into()),
        }
        dialog.page = super::string_list_page(match kind {
            StringListKind::AgentDirs => StringListPage::agent_dirs(),
            StringListKind::ExtraDotenvPaths => StringListPage::extra_dotenv_paths(),
            StringListKind::RedactDenylist => StringListPage::redact_denylist(),
            StringListKind::RedactAllowlist => StringListPage::redact_allowlist(),
            StringListKind::GitignoreAllow => StringListPage::gitignore_allow(),
        });

        let _ = render_settings_rows(&dialog, 90, 30);
        let delete = dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .find(|target| {
                matches!(
                    target.action,
                    RenderAction::Page(SettingsPointerAction::List(ListAction::Delete(_)))
                )
            })
            .cloned()
            .expect("visible trailing delete target");
        if let RenderAction::Page(SettingsPointerAction::List(action)) = &delete.action {
            assert_source_list_action_is_covered(action);
        }
        click_target(&mut dialog, &delete);
        assert_eq!(list_len(&dialog, kind), 1, "first click only arms {kind:?}");

        let rows = render_settings_rows(&dialog, 90, 30).join("\n");
        let name = if kind == StringListKind::RedactDenylist {
            "replacement #1"
        } else if kind == StringListKind::RedactAllowlist {
            "ONE"
        } else if kind == StringListKind::AgentDirs {
            "界🙂"
        } else {
            "one"
        };
        assert!(rows.contains(&format!("Delete {name}? [Delete] [Cancel]")));
        click_target(&mut dialog, &delete);
        assert_eq!(
            list_len(&dialog, kind),
            1,
            "replaying the pre-confirmation row coordinate is inert"
        );
        let cancel = dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .find(|target| {
                matches!(
                    target.action,
                    RenderAction::Page(SettingsPointerAction::List(ListAction::Cancel))
                )
            })
            .cloned()
            .expect("inline cancel target");
        click_target(&mut dialog, &cancel);
        assert_eq!(list_len(&dialog, kind), 1);

        let _ = render_settings_rows(&dialog, 90, 30);
        for _ in 0..2 {
            let target = dialog
                .pointer_surface
                .targets
                .borrow()
                .iter()
                .find(|target| {
                    matches!(
                        target.action,
                        RenderAction::Page(SettingsPointerAction::List(ListAction::Delete(_)))
                    )
                })
                .cloned()
                .expect("delete target remains rendered");
            click_target(&mut dialog, &target);
            let _ = render_settings_rows(&dialog, 90, 30);
        }
        assert_eq!(
            list_len(&dialog, kind),
            0,
            "confirmed deletion mutates {kind:?}"
        );

        // The action captured before deletion carries index + value identity
        // and must be inert once that row no longer exists.
        dialog.page.handle_pointer_control(
            &mut dialog.cx,
            match delete.action {
                RenderAction::Page(action) => action,
                _ => unreachable!(),
            },
        );
        assert_eq!(list_len(&dialog, kind), 0, "stale identity is rejected");
    }
}

fn list_len(dialog: &super::SettingsDialog, kind: super::string_list::StringListKind) -> usize {
    use super::string_list::StringListKind;
    match kind {
        StringListKind::AgentDirs => dialog.extended.agent_dirs.len(),
        StringListKind::ExtraDotenvPaths => dialog.extended.redact.extra_dotenv_paths.len(),
        StringListKind::RedactDenylist => dialog.extended.redact.denylist.len(),
        StringListKind::RedactAllowlist => dialog.extended.redact.allowlist.len(),
        StringListKind::GitignoreAllow => dialog.extended.gitignore_allow.len(),
    }
}

#[test]
fn instructions_and_redact_patterns_use_inline_confirmed_delete_reducers() {
    for redact in [false, true] {
        let tmp = TempDir::new().unwrap();
        let mut dialog = fresh_dialog(&tmp);
        if redact {
            dialog.extended.redact.dotenv_patterns.push("*.env".into());
            dialog.page = Box::new(super::ui_page::RedactPatternsPage::new());
        } else {
            dialog
                .extended
                .agent_guidance_files
                .push("AGENTS.md".into());
            dialog.page = Box::new(super::ui_page::InstructionsPage::new());
        }
        let len = |dialog: &super::SettingsDialog| {
            if redact {
                dialog.extended.redact.dotenv_patterns.len()
            } else {
                dialog.extended.agent_guidance_files.len()
            }
        };

        let _ = render_settings_rows(&dialog, 90, 30);
        let delete = dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .find(|target| {
                matches!(
                    target.action,
                    RenderAction::Page(SettingsPointerAction::List(ListAction::Delete(_)))
                )
            })
            .cloned()
            .expect("list page publishes trailing Delete");
        click_target(&mut dialog, &delete);
        assert_eq!(len(&dialog), 1);
        let _ = render_settings_rows(&dialog, 90, 30);
        click_target(&mut dialog, &delete);
        assert_eq!(len(&dialog), 1, "original delete-row coordinate is inert");
        let cancel = dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .find(|target| {
                matches!(
                    target.action,
                    RenderAction::Page(SettingsPointerAction::List(ListAction::Cancel))
                )
            })
            .cloned()
            .expect("inline cancellation is rendered");
        click_target(&mut dialog, &cancel);
        assert_eq!(len(&dialog), 1);

        let _ = render_settings_rows(&dialog, 90, 30);
        for expected in [1, 0] {
            let target = if expected == 1 {
                dialog
                    .pointer_surface
                    .targets
                    .borrow()
                    .iter()
                    .find(|target| {
                        matches!(
                            target.action,
                            RenderAction::Page(SettingsPointerAction::List(ListAction::Delete(_)))
                        )
                    })
                    .cloned()
                    .expect("delete target after cancellation")
            } else {
                let _ = render_settings_rows(&dialog, 90, 30);
                dialog
                    .pointer_surface
                    .targets
                    .borrow()
                    .iter()
                    .find(|target| {
                        matches!(
                            target.action,
                            RenderAction::Page(SettingsPointerAction::List(ListAction::Delete(_)))
                        )
                    })
                    .cloned()
                    .expect("confirmation target")
            };
            click_target(&mut dialog, &target);
            assert_eq!(len(&dialog), expected);
        }
        dialog.page.handle_pointer_control(
            &mut dialog.cx,
            match delete.action {
                RenderAction::Page(action) => action,
                _ => unreachable!(),
            },
        );
        assert_eq!(len(&dialog), 0, "stale delete identity stays inert");
    }
}

#[test]
fn settings_pointer_copilot_setup_is_explicit_and_exactly_once() {
    super::providers::tests::copilot_setup_effect_accepts_only_its_live_operation_once();
    let mut gate = PointerOperationGate::default();
    let id = gate.begin();
    assert_eq!(gate.pending(), Some(id));
    assert!(!gate.complete(PointerOperationId(id.0 + 1)));
    assert!(gate.complete(id));
    assert!(!gate.complete(id));
    let cancelled = gate.begin();
    gate.cancel();
    assert!(!gate.complete(cancelled));
}

#[test]
fn settings_pointer_provider_secret_choices_are_functional() {
    // The provider matrix renders the edit page, dispatches BeginDelete,
    // renders each resulting confirmation choice, and drives the real
    // credential-aware reducer for remove/keep/cancel.
    super::providers::tests::run_pointer_provider_regression_matrix();
}

#[test]
fn existing_settings_tests_retain_behavioral_assertions() {
    let settings_tests = include_str!("tests.rs");
    let provider_tests = include_str!("providers/tests.rs");
    for retained in [
        "fn category_short_viewport_keeps_bottom_reset_row_visible",
        "fn nav_stack_restores_behavior_cursor_and_scroll_from_instructions",
    ] {
        assert!(settings_tests.contains(retained), "missing {retained}");
    }
    assert!(
        provider_tests.contains("secret") && provider_tests.contains("delete"),
        "provider secret-deletion assertions must remain in the production suite"
    );
    assert!(
        provider_tests.contains("oauth") && provider_tests.contains("link"),
        "OAuth link/scroll assertions must remain in the production suite"
    );
}

#[test]
fn settings_pointer_header_navigation_is_complete() {
    super::tests::run_pointer_header_back_matrix();
    super::tests::run_pointer_dialog_regression_matrix();
    super::providers::tests::run_pointer_provider_regression_matrix();
    let tmp = TempDir::new().unwrap();
    let dialog = fresh_dialog(&tmp);
    let rows = render_settings_rows(&dialog, 80, 12);
    let targets = dialog.pointer_surface.targets.borrow();
    assert!(
        targets
            .iter()
            .any(|target| { target.action == RenderAction::Header(SettingsHeaderAction::Close) })
    );
    assert!(rows.iter().any(|row| row.contains("Close settings")));
    assert!(
        !targets
            .iter()
            .any(|target| { target.action == RenderAction::Header(SettingsHeaderAction::Back) }),
        "root without a parent has no Back target"
    );
}

#[test]
fn settings_pointer_oauth_copy_actions_are_effect_safe() {
    super::providers::tests::oauth_copy_completion_is_flow_scoped_and_exactly_once();
    let mut gate = PointerOperationGate::default();
    let live = gate.begin();
    assert!(!gate.complete(PointerOperationId(live.0 + 1)));
    assert!(gate.complete(live));
    assert!(!gate.complete(live), "duplicate completion is inert");
    let cancelled = gate.begin();
    gate.cancel();
    assert!(!gate.complete(cancelled));
    let replaced = gate.begin();
    let replacement = gate.begin();
    assert!(!gate.complete(replaced));
    assert!(gate.complete(replacement));
}
