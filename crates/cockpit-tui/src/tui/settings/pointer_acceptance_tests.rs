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
    static ACTION_COVERAGE: RefCell<(
        HashSet<SettingsPointerAction>,
        HashSet<SettingsPointerAction>,
        HashSet<SettingsPointerAction>,
        HashSet<SettingsPointerSurfaceKind>,
    )> = RefCell::default();
    static FIXTURE_COVERAGE: RefCell<(
        HashSet<super::pointer_action_fixtures::ActionFixtureKey>,
        HashSet<super::pointer_action_fixtures::ActionFixtureKey>,
        HashSet<super::pointer_action_fixtures::ActionFixtureKey>,
    )> = RefCell::default();
    static PAYLOAD_COVERAGE: RefCell<(
        HashSet<super::pointer_action_fixtures::PayloadFixtureKey>,
        HashSet<super::pointer_action_fixtures::PayloadFixtureKey>,
    )> = RefCell::default();
    static WIZARD_SOURCE_COVERAGE: RefCell<HashSet<cockpit_core::wizard::ProviderWizardStep>> = RefCell::default();
}

pub(super) fn record_rendered_wizard_step(step: cockpit_core::wizard::ProviderWizardStep) {
    WIZARD_SOURCE_COVERAGE.with(|coverage| {
        coverage.borrow_mut().insert(step);
    });
}

pub(super) fn record_rendered_surface(surface: SettingsPointerSurfaceKind) {
    ACTION_COVERAGE.with(|coverage| {
        coverage.borrow_mut().3.insert(surface);
    });
}

pub(super) fn record_rendered_action(action: &SettingsPointerAction, enabled: bool) {
    assert_eq!(
        super::pointer_action_fixtures::key_for(action).expected()
            == super::pointer_action_fixtures::ExpectedReducerOutcome::Enabled,
        enabled,
        "typed source fixture disagrees with rendered reducer outcome"
    );
    ACTION_COVERAGE.with(|coverage| {
        let mut coverage = coverage.borrow_mut();
        if enabled {
            &mut coverage.0
        } else {
            &mut coverage.2
        }
        .insert(action.clone());
    });
    FIXTURE_COVERAGE.with(|coverage| {
        let key = super::pointer_action_fixtures::key_for(action);
        let mut coverage = coverage.borrow_mut();
        if enabled {
            &mut coverage.0
        } else {
            &mut coverage.1
        }
        .insert(key);
    });
    if enabled {
        PAYLOAD_COVERAGE.with(|coverage| {
            coverage
                .borrow_mut()
                .0
                .extend(super::pointer_action_fixtures::payload_keys_for(action));
        });
    }
}

pub(super) fn record_dispatched_action(action: &SettingsPointerAction) {
    ACTION_COVERAGE.with(|coverage| {
        coverage.borrow_mut().1.insert(action.clone());
    });
    FIXTURE_COVERAGE.with(|coverage| {
        coverage
            .borrow_mut()
            .2
            .insert(super::pointer_action_fixtures::key_for(action));
    });
    PAYLOAD_COVERAGE.with(|coverage| {
        coverage
            .borrow_mut()
            .1
            .extend(super::pointer_action_fixtures::payload_keys_for(action));
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
        action: RenderAction::Page(SettingsPointerAction::Root(RootAction::Open(
            RootNodeId::Interface,
        ))),
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
        RenderAction::Page(SettingsPointerAction::Root(RootAction::Open(
            RootNodeId::Interface
        )))
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
}

#[test]
fn settings_pointer_destructive_confirmations_remain_two_step() {
    super::providers::tests::pointer_delete_confirmation_is_rendered_and_reduced();
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
    *surface.hover.borrow_mut() = Some(SettingsPointerAction::Root(RootAction::Open(
        RootNodeId::Interface,
    )));
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
    let rows = render_settings_rows(&dialog, 72, 16);
    assert!(
        dialog.pointer_surface.targets.borrow().is_empty(),
        "capture-off render has no pointer affordances"
    );
    let rendered = rows.join("\n");
    assert!(!rendered.contains("[Close settings]"));
    assert!(!rendered.contains("[Back]"));
    assert!(!rendered.contains("[Back to config picker]"));
}

#[test]
fn settings_pointer_action_registry_is_exhaustive_and_operable() {
    ACTION_COVERAGE.with(|coverage| *coverage.borrow_mut() = Default::default());
    FIXTURE_COVERAGE.with(|coverage| *coverage.borrow_mut() = Default::default());
    PAYLOAD_COVERAGE.with(|coverage| *coverage.borrow_mut() = Default::default());
    WIZARD_SOURCE_COVERAGE.with(|coverage| coverage.borrow_mut().clear());
    super::tests::run_pointer_dialog_regression_matrix();
    super::providers::tests::run_pointer_provider_regression_matrix();
    super::agents_page::tests::run_pointer_external_edit_exactly_once_regression();
    dispatch_enabled_category_descriptor_actions();
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
        for surface in [
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
        ] {
            assert!(
                coverage.3.contains(&surface),
                "source settings surface {surface:?} was not rendered"
            );
        }
        assert!(
            !coverage.2.is_empty(),
            "disabled/read-only targets must be represented explicitly"
        );
        assert!(
            coverage.2.is_disjoint(&coverage.1),
            "disabled targets reached a reducer"
        );
        for expected in ["builtin", "mcp"] {
            assert!(
                coverage.2.iter().any(|action| match (expected, action) {
                    ("builtin", SettingsPointerAction::Tools(ToolsAction::ReadOnlyBuiltin(_))) =>
                        true,
                    ("mcp", SettingsPointerAction::Tools(ToolsAction::ReadOnlyMcpTool(_, _))) =>
                        true,
                    _ => false,
                }),
                "disabled/read-only {expected} source payload was not rendered"
            );
        }
    });
    FIXTURE_COVERAGE.with(|coverage| {
        use super::pointer_action_fixtures::ExpectedReducerOutcome;
        let coverage = coverage.borrow();
        for key in super::pointer_action_fixtures::all_keys() {
            match key.expected() {
                ExpectedReducerOutcome::Enabled => {
                    assert!(
                        coverage.0.contains(&key),
                        "enabled source fixture was not rendered: {key:?}"
                    );
                    assert!(
                        coverage.2.contains(&key),
                        "enabled source fixture did not reach reducer: {key:?}"
                    );
                }
                ExpectedReducerOutcome::Disabled => {
                    assert!(
                        coverage.1.contains(&key),
                        "disabled source fixture was not rendered: {key:?}"
                    );
                    assert!(
                        !coverage.2.contains(&key),
                        "disabled source fixture reached reducer: {key:?}"
                    );
                }
                ExpectedReducerOutcome::NoPointerControl => {
                    assert!(
                        !coverage.0.contains(&key) && !coverage.1.contains(&key),
                        "non-interactive source step published a pointer target: {key:?}"
                    );
                    assert!(
                        !coverage.2.contains(&key),
                        "non-interactive source step reached a pointer reducer: {key:?}"
                    );
                }
            }
        }
    });
    PAYLOAD_COVERAGE.with(|coverage| {
        let coverage = coverage.borrow();
        for key in super::pointer_action_fixtures::all_payload_keys() {
            if key.expects_pointer_control() {
                assert!(
                    coverage.0.contains(&key),
                    "source payload was not rendered: {key:?}"
                );
                assert!(
                    coverage.1.contains(&key),
                    "source payload did not reach reducer: {key:?}"
                );
            } else {
                assert!(
                    !coverage.0.contains(&key),
                    "non-interactive source payload rendered a pointer control: {key:?}"
                );
                assert!(
                    !coverage.1.contains(&key),
                    "non-interactive source payload reached pointer reducer: {key:?}"
                );
            }
        }
    });
    WIZARD_SOURCE_COVERAGE.with(|coverage| {
        let coverage = coverage.borrow();
        for step in cockpit_core::wizard::ProviderWizardStep::ALL {
            assert!(
                coverage.contains(&step),
                "provider wizard source step was not rendered: {step:?}"
            );
        }
    });
}

fn dispatch_enabled_category_descriptor_actions() {
    use super::category::Category;
    use super::category::SettingId;
    let tmp = TempDir::new().unwrap();
    let mut source = fresh_dialog(&tmp);
    super::tests::open_category_on(&mut source, Category::Interface, SettingId::Mouse);
    let _ = render_settings_rows(&source, 100, 50);
    let interface_actions = source
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .filter_map(|target| match (&target.action, target.enabled) {
            (
                RenderAction::Page(
                    action @ SettingsPointerAction::Category(
                        CategoryAction::DescriptorActivate(_) | CategoryAction::Reset,
                    ),
                ),
                true,
            ) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(!interface_actions.is_empty());
    for action in interface_actions {
        let tmp = TempDir::new().unwrap();
        let mut dialog = fresh_dialog(&tmp);
        super::tests::open_category_on(&mut dialog, Category::Interface, SettingId::Mouse);
        let _ = render_settings_rows(&dialog, 100, 50);
        let target = dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .find(|target| target.enabled && target.action == RenderAction::Page(action.clone()))
            .cloned()
            .expect("source interface descriptor action is rendered");
        click_target(&mut dialog, &target);
    }

    for (category, setting) in [
        (Category::Behavior, SettingId::Instructions),
        (Category::Behavior, SettingId::CompactPrompt),
        (Category::Behavior, SettingId::AgentDirs),
        (Category::Behavior, SettingId::PackagesDir),
        (Category::Behavior, SettingId::TimeInjectionInterval),
        (Category::Behavior, SettingId::AutoTitleModel),
        (Category::Behavior, SettingId::ScheduleAllowUnboundedLoops),
        (Category::Behavior, SettingId::DelegationMaxParallel),
        (Category::Behavior, SettingId::DeepthinkEnabled),
        (Category::Behavior, SettingId::TranslationModel),
        (Category::Behavior, SettingId::TextEmbeddedRecovery),
        (Category::Behavior, SettingId::Concurrency),
        (Category::Behavior, SettingId::LoopGuardThreshold),
        (Category::Behavior, SettingId::GoalVerificationSkepticCount),
        (Category::Behavior, SettingId::CheapCodeModel),
        (Category::Behavior, SettingId::GoalVerificationMaxRounds),
        (Category::Behavior, SettingId::CompactModel),
        (Category::Behavior, SettingId::ScheduleMaxConcurrent),
        (Category::Behavior, SettingId::PredictNextMessageModel),
        (Category::Behavior, SettingId::SmartCodeModel),
        (Category::Behavior, SettingId::ReasoningModel),
        (Category::Behavior, SettingId::GoalVerificationModel),
        (Category::Behavior, SettingId::DialogLockoutMs),
        (Category::Behavior, SettingId::AgentChoosesSubagentModel),
        (Category::Behavior, SettingId::GoalVerificationEnabled),
        (
            Category::Behavior,
            SettingId::HarnessReportSummarizationModel,
        ),
        (Category::Behavior, SettingId::SkillInjectionModel),
        (Category::Behavior, SettingId::MaxPrimaryRounds),
        (Category::Behavior, SettingId::UtilityModel),
    ] {
        let tmp = TempDir::new().unwrap();
        let mut dialog = fresh_dialog(&tmp);
        super::tests::open_category_on(&mut dialog, category, setting);
        let before = render_settings_rows(&dialog, 100, 50);
        let target = dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .find(|target| {
                target.enabled
                    && target.action
                        == RenderAction::Page(SettingsPointerAction::Category(
                            CategoryAction::DescriptorActivate(setting),
                        ))
            })
            .cloned()
            .expect("source category descriptor action is rendered");
        click_target(&mut dialog, &target);
        if matches!(
            setting,
            SettingId::Instructions
                | SettingId::CompactPrompt
                | SettingId::AgentDirs
                | SettingId::PackagesDir
                | SettingId::TimeInjectionInterval
        ) {
            assert!(
                !matches!(dialog.test_page(), TestPageRef::Category(page) if !page.is_editing()),
                "descriptor activation had no semantic outcome for {setting:?}"
            );
        }
        let after = render_settings_rows(&dialog, 100, 50);
        assert_ne!(
            before, after,
            "descriptor activation had no rendered outcome for {setting:?}"
        );
        match setting {
            SettingId::AutoTitleModel
            | SettingId::TranslationModel
            | SettingId::CheapCodeModel
            | SettingId::CompactModel
            | SettingId::PredictNextMessageModel
            | SettingId::SmartCodeModel
            | SettingId::ReasoningModel
            | SettingId::GoalVerificationModel
            | SettingId::HarnessReportSummarizationModel
            | SettingId::SkillInjectionModel
            | SettingId::UtilityModel => assert!(matches!(
                dialog.test_page(),
                TestPageRef::Category(page) if page.utility_picker.is_some()
            )),
            SettingId::DelegationMaxParallel
            | SettingId::LoopGuardThreshold
            | SettingId::GoalVerificationSkepticCount
            | SettingId::GoalVerificationMaxRounds
            | SettingId::ScheduleMaxConcurrent
            | SettingId::DialogLockoutMs
            | SettingId::MaxPrimaryRounds => assert!(matches!(
                dialog.test_page(),
                TestPageRef::Category(page) if page.is_editing()
            )),
            SettingId::ScheduleAllowUnboundedLoops
            | SettingId::DeepthinkEnabled
            | SettingId::TextEmbeddedRecovery
            | SettingId::Concurrency
            | SettingId::AgentChoosesSubagentModel
            | SettingId::GoalVerificationEnabled => assert!(matches!(
                dialog.test_page(),
                TestPageRef::Category(page) if !page.is_editing()
            )),
            SettingId::Instructions
            | SettingId::CompactPrompt
            | SettingId::AgentDirs
            | SettingId::PackagesDir
            | SettingId::TimeInjectionInterval => {}
            _ => unreachable!("unclassified Behavior descriptor fixture: {setting:?}"),
        }
    }
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
