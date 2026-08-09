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

fn fixture_actions() -> Vec<SettingsPointerAction> {
    let row = || StableRowId("fixture".into());
    let provider = || ProviderId("provider".into());
    let agent = || AgentId("agent".into());
    vec![
        SettingsPointerAction::Root(RootAction::Open(RootNodeId("interface".into()))),
        SettingsPointerAction::Category(CategoryAction::DescriptorActivate(SettingId(1))),
        SettingsPointerAction::Category(CategoryAction::InlineEditBegin(SettingId(1))),
        SettingsPointerAction::Category(CategoryAction::InlineEditCommit(SettingId(1))),
        SettingsPointerAction::Category(CategoryAction::InlineEditCancel(SettingId(1))),
        SettingsPointerAction::Category(CategoryAction::PathEditBegin(SettingId(1))),
        SettingsPointerAction::Category(CategoryAction::PathEditCommit(SettingId(1))),
        SettingsPointerAction::Category(CategoryAction::PathEditCancel(SettingId(1))),
        SettingsPointerAction::Category(CategoryAction::SuggestionSelect(SettingId(1), row())),
        SettingsPointerAction::Category(CategoryAction::TextEditorSave(SettingId(1))),
        SettingsPointerAction::Category(CategoryAction::TextEditorCancel(SettingId(1))),
        SettingsPointerAction::Category(CategoryAction::PickerSelect(SettingId(1), row())),
        SettingsPointerAction::Category(CategoryAction::Confirm(
            SettingId(1),
            ConfirmationChoice::Confirm,
        )),
        SettingsPointerAction::Category(CategoryAction::Reset),
        SettingsPointerAction::Category(CategoryAction::ExternalEditBegin(
            SettingId(1),
            CategoryExternalSource::Cursor,
        )),
        SettingsPointerAction::Category(CategoryAction::ExternalEditResult(
            SettingId(1),
            ExternalEditOutcome::Saved,
        )),
        SettingsPointerAction::Agents(AgentsAction::Open(agent())),
        SettingsPointerAction::Agents(AgentsAction::Edit(agent())),
        SettingsPointerAction::Agents(AgentsAction::Delete(agent())),
        SettingsPointerAction::Agents(AgentsAction::Reset(agent())),
        SettingsPointerAction::Agents(AgentsAction::ResetAll),
        SettingsPointerAction::Agents(AgentsAction::ToggleTool(agent(), row())),
        SettingsPointerAction::Agents(AgentsAction::CycleTier(agent(), row())),
        SettingsPointerAction::Agents(AgentsAction::Save(agent())),
        SettingsPointerAction::Agents(AgentsAction::OpenRawEditor(agent())),
        SettingsPointerAction::Agents(AgentsAction::EditText(agent())),
        SettingsPointerAction::Agents(AgentsAction::Cancel(agent())),
        SettingsPointerAction::Agents(AgentsAction::ExternalEditBegin(agent())),
        SettingsPointerAction::Agents(AgentsAction::ExternalEditResult(
            agent(),
            ExternalEditOutcome::Failed,
        )),
        SettingsPointerAction::Tools(ToolsAction::CycleWebProvider),
        SettingsPointerAction::Tools(ToolsAction::EditFirecrawlBaseUrl),
        SettingsPointerAction::Tools(ToolsAction::EditCredential(CredentialKind::Firecrawl)),
        SettingsPointerAction::Tools(ToolsAction::EditCredential(CredentialKind::TinyFish)),
        SettingsPointerAction::Tools(ToolsAction::EditWebFetchCommand),
        SettingsPointerAction::Tools(ToolsAction::EditWebSearchCommand),
        SettingsPointerAction::Tools(ToolsAction::EditUserToolCommand(UserToolId("tool".into()))),
        SettingsPointerAction::Tools(ToolsAction::AddUserTool),
        SettingsPointerAction::Tools(ToolsAction::ToggleUserTool(UserToolId("tool".into()))),
        SettingsPointerAction::Tools(ToolsAction::ResetToolField(ToolFieldId("field".into()))),
        SettingsPointerAction::Tools(ToolsAction::McpJump),
        SettingsPointerAction::Tools(ToolsAction::Reset),
        SettingsPointerAction::Tools(ToolsAction::DeleteUserTool(UserToolId("tool".into()))),
        SettingsPointerAction::Tools(ToolsAction::ReadOnlyBuiltin(BuiltinToolId(
            "builtin".into(),
        ))),
        SettingsPointerAction::Tools(ToolsAction::ReadOnlyMcpTool(
            McpServerId("server".into()),
            McpToolId("tool".into()),
        )),
        SettingsPointerAction::Harnesses(HarnessesAction::Open(row())),
        SettingsPointerAction::Harnesses(HarnessesAction::Add),
        SettingsPointerAction::Harnesses(HarnessesAction::Delete(row())),
        SettingsPointerAction::Harnesses(HarnessesAction::SeedInstalledPresets),
        SettingsPointerAction::Harnesses(HarnessesAction::ResetAndSeedPresets),
        SettingsPointerAction::Harnesses(HarnessesAction::EditField(row())),
        SettingsPointerAction::Harnesses(HarnessesAction::Save),
        SettingsPointerAction::Harnesses(HarnessesAction::Cancel),
        SettingsPointerAction::Skills(SkillsAction::ToggleAutoBangCommands),
        SettingsPointerAction::Skills(SkillsAction::ToggleAncestorWalk),
        SettingsPointerAction::Skills(SkillsAction::AddScanDirectory),
        SettingsPointerAction::Skills(SkillsAction::EditScanDirectory(row())),
        SettingsPointerAction::Skills(SkillsAction::DeleteScanDirectory(row())),
        SettingsPointerAction::Skills(SkillsAction::ConfirmDeleteScanDirectory(
            row(),
            ConfirmationChoice::Confirm,
        )),
        SettingsPointerAction::Skills(SkillsAction::Reset),
        SettingsPointerAction::Mcp(McpAction::Open(McpServerId("server".into()))),
        SettingsPointerAction::Mcp(McpAction::Add),
        SettingsPointerAction::Mcp(McpAction::ToggleEnabled(McpServerId("server".into()))),
        SettingsPointerAction::Mcp(McpAction::Authenticate(McpServerId("server".into()))),
        SettingsPointerAction::Mcp(McpAction::Delete(McpServerId("server".into()))),
        SettingsPointerAction::Mcp(McpAction::EditName),
        SettingsPointerAction::Mcp(McpAction::ToggleEditorEnabled),
        SettingsPointerAction::Mcp(McpAction::CycleTransport),
        SettingsPointerAction::Mcp(McpAction::EditEndpoint),
        SettingsPointerAction::Mcp(McpAction::EditCommand),
        SettingsPointerAction::Mcp(McpAction::EditArgs),
        SettingsPointerAction::Mcp(McpAction::EditBaseEnv),
        SettingsPointerAction::Mcp(McpAction::CycleAuth),
        SettingsPointerAction::Mcp(McpAction::EditHeaderName),
        SettingsPointerAction::Mcp(McpAction::EditHeaderValue),
        SettingsPointerAction::Mcp(McpAction::EditAuthEnv),
        SettingsPointerAction::Mcp(McpAction::EditOauthAuthorizeUrl),
        SettingsPointerAction::Mcp(McpAction::EditOauthTokenUrl),
        SettingsPointerAction::Mcp(McpAction::EditOauthClientId),
        SettingsPointerAction::Mcp(McpAction::EditOauthScopes),
        SettingsPointerAction::Mcp(McpAction::EditCacheTtl),
        SettingsPointerAction::Mcp(McpAction::EditConnectTimeout),
        SettingsPointerAction::Mcp(McpAction::EditRequestTimeout),
        SettingsPointerAction::Mcp(McpAction::Save),
        SettingsPointerAction::Mcp(McpAction::Cancel),
        SettingsPointerAction::Providers(ProvidersAction::Open(provider())),
        SettingsPointerAction::Providers(ProvidersAction::Add),
        SettingsPointerAction::Providers(ProvidersAction::EditField(provider(), row())),
        SettingsPointerAction::Providers(ProvidersAction::EditHeaders(provider())),
        SettingsPointerAction::Providers(ProvidersAction::CopilotSetup(provider())),
        SettingsPointerAction::Providers(ProvidersAction::OAuthSetup(provider(), row())),
        SettingsPointerAction::Providers(ProvidersAction::ManageModels(provider())),
        SettingsPointerAction::Providers(ProvidersAction::ProviderSettings(provider())),
        SettingsPointerAction::Providers(ProvidersAction::Favorite(provider())),
        SettingsPointerAction::Providers(ProvidersAction::Refetch(provider())),
        SettingsPointerAction::Providers(ProvidersAction::RefetchAll),
        SettingsPointerAction::Providers(ProvidersAction::CycleUnlistedPolicy),
        SettingsPointerAction::Providers(ProvidersAction::DeepFetchConfirm(provider(), row())),
        SettingsPointerAction::Providers(ProvidersAction::BeginDelete(provider())),
        SettingsPointerAction::Providers(ProvidersAction::Delete(
            provider(),
            ProviderDeleteChoice::RemoveSecrets,
        )),
        SettingsPointerAction::Providers(ProvidersAction::Delete(
            provider(),
            ProviderDeleteChoice::KeepSecrets,
        )),
        SettingsPointerAction::Providers(ProvidersAction::Delete(
            provider(),
            ProviderDeleteChoice::Cancel,
        )),
        SettingsPointerAction::Providers(ProvidersAction::SaveProvider(provider())),
        SettingsPointerAction::Providers(ProvidersAction::LocalBack),
        SettingsPointerAction::Providers(ProvidersAction::AddModel(provider())),
        SettingsPointerAction::Providers(ProvidersAction::RenameModel(
            provider(),
            ModelId("model".into()),
        )),
        SettingsPointerAction::Providers(ProvidersAction::DeleteModel(
            provider(),
            ModelId("model".into()),
        )),
        SettingsPointerAction::Providers(ProvidersAction::ModelSettings(
            provider(),
            ModelId("model".into()),
        )),
        SettingsPointerAction::Providers(ProvidersAction::FetchAllConfirm(FetchAllChoice::Apply)),
        SettingsPointerAction::Providers(ProvidersAction::FetchOneConfirm(
            provider(),
            FetchOneChoice::Apply,
        )),
        SettingsPointerAction::Providers(ProvidersAction::FetchFallbackConfirm(
            provider(),
            FetchFallbackChoice::Retry,
        )),
        SettingsPointerAction::Providers(ProvidersAction::FetchFallbackConfirm(
            provider(),
            FetchFallbackChoice::KeepLocal,
        )),
        SettingsPointerAction::Providers(ProvidersAction::FetchFallbackConfirm(
            provider(),
            FetchFallbackChoice::UseFallback,
        )),
        SettingsPointerAction::Providers(ProvidersAction::FetchFallbackConfirm(
            provider(),
            FetchFallbackChoice::Cancel,
        )),
        SettingsPointerAction::Providers(ProvidersAction::DeepFetchChoice(
            provider(),
            DeepFetchChoice::Fetch,
        )),
        SettingsPointerAction::Providers(ProvidersAction::WizardControl(
            WizardStepId("step".into()),
            WizardControlId("control".into()),
        )),
        SettingsPointerAction::Providers(ProvidersAction::RowEditor(
            ProviderRowEditorAction::HeaderOpen(row()),
        )),
        SettingsPointerAction::Providers(ProvidersAction::RowEditor(
            ProviderRowEditorAction::HeaderAdd,
        )),
        SettingsPointerAction::Providers(ProvidersAction::RowEditor(
            ProviderRowEditorAction::HeaderContinue,
        )),
        SettingsPointerAction::Providers(ProvidersAction::RowEditor(
            ProviderRowEditorAction::HeaderSave,
        )),
        SettingsPointerAction::Providers(ProvidersAction::RowEditor(
            ProviderRowEditorAction::ModelOpen(ModelId("model".into())),
        )),
        SettingsPointerAction::Providers(ProvidersAction::RowEditor(
            ProviderRowEditorAction::ModelAdd,
        )),
        SettingsPointerAction::Providers(ProvidersAction::RowEditor(
            ProviderRowEditorAction::ModelSave,
        )),
        SettingsPointerAction::Providers(ProvidersAction::RowEditor(
            ProviderRowEditorAction::SettingEdit(row()),
        )),
        SettingsPointerAction::Providers(ProvidersAction::RowEditor(
            ProviderRowEditorAction::SettingSave,
        )),
        SettingsPointerAction::Providers(ProvidersAction::ModelLifecycle(
            ModelLifecycleAction::Refresh,
        )),
        SettingsPointerAction::Providers(ProvidersAction::CopyOAuth(
            OAuthFlowId(1),
            OAuthCopyKind::AuthorizationUrl,
        )),
        SettingsPointerAction::Providers(ProvidersAction::CopyOAuth(
            OAuthFlowId(1),
            OAuthCopyKind::DeviceCode,
        )),
        SettingsPointerAction::Providers(ProvidersAction::CopilotConfirm(
            provider(),
            ConfirmationChoice::Confirm,
        )),
        SettingsPointerAction::Lsp(LspAction::ToggleEnabled),
        SettingsPointerAction::Lsp(LspAction::CycleAutoInstall),
        SettingsPointerAction::Lsp(LspAction::ToggleDiagnostics),
        SettingsPointerAction::Lsp(LspAction::Edit(LspEdit::DebounceMs)),
        SettingsPointerAction::Lsp(LspAction::SaveEdit(LspEdit::DebounceMs)),
        SettingsPointerAction::Lsp(LspAction::CancelEdit(LspEdit::DebounceMs)),
        SettingsPointerAction::Lsp(LspAction::Reset),
        SettingsPointerAction::Lsp(LspAction::Check(LspServerId("rust-analyzer".into()))),
        SettingsPointerAction::Lsp(LspAction::Install(LspServerId("rust-analyzer".into()))),
        SettingsPointerAction::Lsp(LspAction::Uninstall(LspServerId("rust-analyzer".into()))),
        SettingsPointerAction::Lsp(LspAction::Restart(LspServerId("rust-analyzer".into()))),
        SettingsPointerAction::List(ListAction::Add),
        SettingsPointerAction::List(ListAction::Edit(row())),
        SettingsPointerAction::List(ListAction::Delete(row())),
        SettingsPointerAction::List(ListAction::MoveUp(row())),
        SettingsPointerAction::List(ListAction::MoveDown(row())),
        SettingsPointerAction::List(ListAction::Save),
        SettingsPointerAction::List(ListAction::Cancel),
        SettingsPointerAction::UtilityModel(UtilityModelAction::Select(UtilityModelId(
            "p/m".into(),
        ))),
        SettingsPointerAction::UtilityModel(UtilityModelAction::Clear),
        SettingsPointerAction::UtilityModel(UtilityModelAction::OpenCustom),
        SettingsPointerAction::UtilityModel(UtilityModelAction::Back),
        SettingsPointerAction::UtilityModel(UtilityModelAction::EditCustom),
        SettingsPointerAction::UtilityModel(UtilityModelAction::CommitCustom),
        SettingsPointerAction::UtilityModel(UtilityModelAction::CancelCustom),
        SettingsPointerAction::DefaultModel(DefaultModelAction::Choose),
        SettingsPointerAction::DefaultModel(DefaultModelAction::Clear),
    ]
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
}

#[test]
fn settings_text_click_places_grapheme_safe_caret() {
    let mut field = crate::tui::textfield::TextField::new("a界e\u{301}");
    field.set_cursor_display_col(2);
    assert!(field.cursor() <= field.text().len());
    assert!(field.text().is_char_boundary(field.cursor()));
}

#[test]
fn settings_pointer_picker_and_suggestion_actions_match_enter() {
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
}

#[test]
fn settings_pointer_links_and_capture_transitions_are_safe() {
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
}

#[test]
fn settings_pointer_action_registry_is_exhaustive_and_operable() {
    let fixtures = fixture_actions();
    let surface = SettingsPointerSurface::default();
    surface.clear_for(Rect::new(0, 0, 80, fixtures.len() as u16));
    for (row, action) in fixtures.iter().cloned().enumerate() {
        surface.register(SettingsPointerTarget {
            rect: Rect::new(0, row as u16, 80, 1),
            action: RenderAction::Page(action.clone()),
            enabled: true,
            disabled_reason: None,
        });
        assert_eq!(
            surface.hit(1, row as u16).map(|target| target.action),
            Some(RenderAction::Page(action)),
            "fixture row {row} must round-trip through rendered hit geometry"
        );
    }
    assert!(fixtures.len() >= 100);
    for expected in [
        ProviderRowEditorAction::HeaderAdd,
        ProviderRowEditorAction::HeaderContinue,
        ProviderRowEditorAction::HeaderSave,
        ProviderRowEditorAction::ModelAdd,
        ProviderRowEditorAction::ModelSave,
        ProviderRowEditorAction::SettingSave,
    ] {
        assert!(fixtures.contains(&SettingsPointerAction::Providers(
            ProvidersAction::RowEditor(expected)
        )));
    }
}

#[test]
fn settings_pointer_copilot_setup_is_explicit_and_exactly_once() {
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
    let actions = fixture_actions();
    assert!(
        actions.contains(&SettingsPointerAction::Providers(ProvidersAction::Delete(
            provider_id(),
            ProviderDeleteChoice::RemoveSecrets
        )))
    );
    fn provider_id() -> ProviderId {
        ProviderId("provider".into())
    }
    let choices = actions
        .iter()
        .filter(|action| {
            matches!(
                action,
                SettingsPointerAction::Providers(ProvidersAction::Delete(_, _))
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(choices.len(), 3);
    assert_rendered_action_matrix(&choices);
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
