use super::{App, Overlay};
use crate::tui::context_menu::ContextMenu;
use crate::tui::keys_overlay::{KeyContext, KeysOverlay};
use crate::tui::settings::{Dialog, TestPageRef};
use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{Terminal, backend::TestBackend, layout::Rect};

fn mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

fn render_settings(app: &mut App, width: u16, height: u16) {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("terminal");
    let Dialog::Settings(dialog) = &app.dialog else {
        panic!("settings dialog");
    };
    terminal
        .draw(|frame| {
            dialog.render(
                frame,
                Rect::new(0, 0, width, height),
                &mut app.link_registry,
            )
        })
        .expect("draw");
}

pub(crate) fn run_settings_pointer_z_order_matrix() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = Dialog::Settings(Box::new(crate::tui::settings::SettingsDialog::open(
        tmp.path().join("config.json"),
    )));
    app.mouse_capture = true;
    app.chat_area = Some(Rect::new(0, 0, 80, 24));
    app.chat_scroll_offset = 7;
    render_settings(&mut app, 80, 24);
    let Dialog::Settings(dialog) = &app.dialog else {
        unreachable!()
    };
    let target = dialog
        .pointer_test_target_rects()
        .into_iter()
        .max_by_key(|rect| rect.y)
        .expect("root target");

    app.sandbox_notice_copy_rect = Some(target);
    app.auth_failure_notice = Some(crate::tui::auth_failure::AuthFailureNotice {
        provider: "fixture".into(),
        model: "fixture".into(),
        kind: cockpit_proto::AuthFailureKind::ProviderNotConfigured,
    });
    app.auth_notice_switch_rect = Some(target);
    app.auth_notice_fix_rect = Some(target);
    app.handle_mouse(mouse(
        MouseEventKind::Down(MouseButton::Left),
        target.x,
        target.y,
    ));
    assert!(
        matches!(&app.dialog, Dialog::Settings(dialog) if !matches!(dialog.test_page(), TestPageRef::Root { .. })),
        "settings must preempt ordinary persistent-notice controls"
    );
    assert!(app.auth_failure_notice.is_some());

    app.dialog = Dialog::Settings(Box::new(crate::tui::settings::SettingsDialog::open(
        tmp.path().join("config.json"),
    )));
    render_settings(&mut app, 80, 24);

    app.keys_overlay = Some(KeysOverlay::open(KeyContext::Composer));
    app.handle_mouse(mouse(MouseEventKind::ScrollDown, target.x, target.y));
    assert!(
        matches!(&app.dialog, Dialog::Settings(dialog) if matches!(dialog.test_page(), TestPageRef::Root { cursor: 0 }))
    );
    assert_eq!(app.chat_scroll_offset, 7);
    app.keys_overlay = None;

    app.context_menu = Some(ContextMenu {
        preferred_origin: (target.x, target.y),
        clicked_chat_row: 0,
        cursor: 0,
        items: ContextMenu::build_items(false, false),
    });
    app.handle_mouse(mouse(
        MouseEventKind::Down(MouseButton::Middle),
        target.x,
        target.y,
    ));
    assert!(app.context_menu.is_none());
    assert!(
        matches!(&app.dialog, Dialog::Settings(dialog) if matches!(dialog.test_page(), TestPageRef::Root { cursor: 0 }))
    );

    render_settings(&mut app, 80, 24);
    app.handle_mouse(mouse(MouseEventKind::ScrollDown, target.x, target.y));
    assert!(
        matches!(&app.dialog, Dialog::Settings(dialog) if matches!(dialog.test_page(), TestPageRef::Root { cursor: 3 }))
    );
    assert_eq!(app.chat_scroll_offset, 7, "settings preempts chat wheel");

    app.handle_mouse(mouse(MouseEventKind::ScrollDown, 100, 100));
    assert!(
        matches!(&app.dialog, Dialog::Settings(dialog) if matches!(dialog.test_page(), TestPageRef::Root { cursor: 3 }))
    );
    assert_eq!(
        app.chat_scroll_offset, 7,
        "outside settings is inert while modal is open"
    );

    render_settings(&mut app, 80, 24);
    app.link_registry
        .register(target, "https://example.test", "fixture");
    app.handle_mouse(mouse(MouseEventKind::Moved, target.x, target.y));
    assert!(
        app.link_registry.hovered().is_some(),
        "link wins hover z-order"
    );
    let Dialog::Settings(dialog) = &app.dialog else {
        unreachable!()
    };
    assert!(dialog.pointer_test_hover_is_none());
}

#[test]
fn settings_pointer_z_order_matrix() {
    run_settings_pointer_z_order_matrix();
}

#[test]
fn settings_mouse_default_model_picker_matches_keyboard() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = Dialog::Settings(Box::new(crate::tui::settings::SettingsDialog::open(
        tmp.path().join("config.json"),
    )));
    app.mouse_capture = true;
    {
        let Dialog::Settings(dialog) = &mut app.dialog else {
            panic!("settings");
        };
        dialog.test_enter_root_node("Default model for new sessions");
    }
    render_settings(&mut app, 80, 24);
    let target = {
        let Dialog::Settings(dialog) = &app.dialog else {
            panic!("settings");
        };
        dialog
            .pointer_test_button_targets()
            .into_iter()
            .find(|target| {
                matches!(
                    target.dispatch,
                    crate::tui::button::ButtonDispatch::Settings(
                        crate::tui::settings::pointer_actions::SettingsPointerAction::DefaultModel(
                            crate::tui::settings::pointer_actions::DefaultModelAction::Choose
                        )
                    )
                )
            })
            .map(|target| target.rect)
            .expect("choose default model button")
    };
    app.handle_mouse(mouse(
        MouseEventKind::Down(MouseButton::Left),
        target.x,
        target.y,
    ));
    assert!(
        matches!(app.dialog, Dialog::Settings(_)),
        "choose default model must not close on Down"
    );
    app.handle_mouse(mouse(
        MouseEventKind::Up(MouseButton::Left),
        target.x,
        target.y,
    ));
    assert!(
        matches!(app.overlay, super::Overlay::ModelPicker(_)),
        "mouse Up must open the same default-model picker as keyboard"
    );
    assert!(
        app.default_model_picker_mode,
        "mouse close path must consume take_pending_default_model_picker"
    );
}

#[test]
fn tui_button_pointer_dispatch_matrix() {
    run_tui_button_pointer_dispatch_matrix();
}

pub(crate) fn run_tui_button_pointer_dispatch_matrix() {
    use crate::tui::button::{ButtonDispatch, ButtonId, OverlaySurface, RowControlId};
    use crate::tui::settings::Dialog as SettingsDialogKind;

    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut app = App::new(Some(tmp.path()), false);
    app.mouse_capture = true;

    app.dialog = SettingsDialogKind::Settings(Box::new(
        crate::tui::settings::SettingsDialog::open(tmp.path().join("config.json")),
    ));
    render_settings(&mut app, 80, 24);
    {
        let Dialog::Settings(dialog) = &app.dialog else {
            panic!("settings");
        };
        assert!(
            dialog
                .pointer_test_button_targets()
                .iter()
                .any(|target| matches!(target.id, ButtonId::SettingsHeader(_))),
            "settings header buttons register exact rects"
        );
        assert!(
            dialog
                .pointer_test_row_targets()
                .iter()
                .any(|target| matches!(target.id, RowControlId::Settings(_))),
            "settings root rows register full-row controls"
        );
    }

    app.dialog = SettingsDialogKind::None;
    app.daemon_prompt = None;
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).expect("terminal");
    let mut draw = |app: &mut App| {
        terminal.draw(|frame| app.render(frame)).expect("draw");
    };

    let overlay_cases: Vec<(OverlaySurface, Overlay)> = vec![
        (
            OverlaySurface::ModelPicker,
            Overlay::ModelPicker(
                crate::tui::model_picker::ModelPickerDialog::open_with_failures(
                    app.config_snapshot.providers.clone(),
                    None,
                    &Default::default(),
                    &Default::default(),
                    0,
                )
                .expect("model picker"),
            ),
        ),
        (
            OverlaySurface::Multireview,
            match crate::tui::multireview_dialog::MultireviewDialog::open(
                tmp.path(),
                &app.config_snapshot.extended,
                &[],
                &Default::default(),
            ) {
                Ok(dialog) => Overlay::Multireview(dialog),
                Err(_) => {
                    dispatch_overlay_surface(&mut app, OverlaySurface::Multireview);
                    Overlay::None
                }
            },
        ),
        (
            OverlaySurface::Stats,
            Overlay::Stats(crate::tui::stats_pane::StatsPane::open(None, tmp.path())),
        ),
        (
            OverlaySurface::Usage,
            Overlay::Usage(crate::tui::usage_pane::UsagePane::open(Vec::new())),
        ),
        (
            OverlaySurface::Sessions,
            Overlay::Sessions(crate::tui::sessions_pane::SessionsPane::open(
                None,
                tmp.path(),
                false,
                None,
                false,
            )),
        ),
        (
            OverlaySurface::Skills,
            Overlay::Skills(crate::tui::skills_pane::SkillsPane::loading(0)),
        ),
        (
            OverlaySurface::Permissions,
            Overlay::Permissions(crate::tui::permissions_pane::PermissionsPane::open(
                Some(tmp.path()),
            )),
        ),
        (
            OverlaySurface::Resources,
            Overlay::Resources(crate::tui::resources_pane::ResourcesPane::open()),
        ),
        (
            OverlaySurface::Quick,
            Overlay::Quick(crate::tui::quick_dialog::QuickDialog::open(
                crate::tui::quick_dialog::QuickCurrent {
                    llm_mode: app.llm_mode,
                    recursion_enabled: app.delegation_recursion_enabled,
                    recursion_depth: app.delegation_recursion_depth,
                    sandbox_mode: app.sandbox_mode,
                    container_network_enabled: app.container_network_enabled,
                    container_availability: app.container_availability.clone(),
                    host_capabilities: app.host_capabilities.clone(),
                    approval_mode: app.approval_mode,
                    active_model: None,
                    prompt_cache_retention: Default::default(),
                    prompt_cache_retention_status: Default::default(),
                },
                Vec::new(),
            )),
        ),
        (
            OverlaySurface::Context,
            Overlay::Context(crate::tui::context_pane::ContextPane::open(
                crate::tui::context_pane::ContextSnapshot::new(0, 0, 0, 0, 0, None),
            )),
        ),
        (
            OverlaySurface::Notes,
            Overlay::Notes(crate::tui::notes_pane::NotesPane::open(tmp.path(), false)),
        ),
        (
            OverlaySurface::Diff,
            Overlay::Diff(crate::tui::diff_pane::DiffPane::open(
                crate::tui::diff_pane::DiffSource::Worktree,
                tmp.path(),
                &[],
                app.diff_style,
            )),
        ),
        (
            OverlaySurface::Help,
            Overlay::Help(crate::tui::app::help_overlay::HelpOverlay::open()),
        ),
    ];
    let mut rendered_surfaces = Vec::new();
    for (surface, overlay) in overlay_cases {
        app.overlay = overlay;
        app.mouse_capture = true;
        draw(&mut app);
        rendered_surfaces.push(surface);
        app.mouse_capture = false;
        draw(&mut app);
        assert!(
            app.button_registry.targets().is_empty(),
            "{surface:?} capture-off publishes no ButtonRegistry pointer targets"
        );
        assert!(app.button_registry.hover().is_none());
        assert!(app.button_registry.pressed().is_none());
    }
    if let Ok(pane) = crate::tui::tools_pane::ToolsPane::open(tmp.path(), "Build", true) {
        app.overlay = Overlay::Tools(pane);
        app.mouse_capture = true;
        draw(&mut app);
        rendered_surfaces.push(OverlaySurface::Tools);
        app.mouse_capture = false;
        draw(&mut app);
        assert!(app.button_registry.targets().is_empty());
    } else {
        dispatch_overlay_surface(&mut app, OverlaySurface::Tools);
        rendered_surfaces.push(OverlaySurface::Tools);
    }
    if let Ok(pane) =
        crate::tui::goal_settings_pane::GoalSettingsPane::open(tmp.path(), "Build", true)
    {
        app.overlay = Overlay::GoalSettings(pane);
        app.mouse_capture = true;
        draw(&mut app);
        rendered_surfaces.push(OverlaySurface::GoalSettings);
        app.mouse_capture = false;
        draw(&mut app);
        assert!(app.button_registry.targets().is_empty());
    } else {
        dispatch_overlay_surface(&mut app, OverlaySurface::GoalSettings);
        rendered_surfaces.push(OverlaySurface::GoalSettings);
    }
    for required in [
        OverlaySurface::ModelPicker,
        OverlaySurface::Multireview,
        OverlaySurface::Stats,
        OverlaySurface::Usage,
        OverlaySurface::Sessions,
        OverlaySurface::Skills,
        OverlaySurface::Tools,
        OverlaySurface::GoalSettings,
        OverlaySurface::Permissions,
        OverlaySurface::Resources,
        OverlaySurface::Quick,
        OverlaySurface::Context,
        OverlaySurface::Notes,
        OverlaySurface::Diff,
        OverlaySurface::Help,
    ] {
        assert!(
            rendered_surfaces.contains(&required),
            "matrix must render or dispatch {required:?}"
        );
    }

    app.overlay = Overlay::None;
    let dialogs: Vec<(&str, Dialog)> = vec![
        (
            "WorkspaceTrust",
            Dialog::open_workspace_trust(cockpit_config::trust::TrustRoot {
                opened_path: tmp.path().to_path_buf(),
                root: tmp.path().to_path_buf(),
                kind: cockpit_config::trust::TrustRootKind::Directory,
            }),
        ),
        (
            "PickConfig",
            Dialog::PickConfig {
                dirs: vec![cockpit_config::dirs::ConfigDir {
                    kind: cockpit_config::dirs::ConfigDirKind::Project,
                    path: tmp.path().to_path_buf(),
                }],
                cursor: 0,
                cwd: tmp.path().to_path_buf(),
                status: None,
            },
        ),
        (
            "CreateConfig",
            Dialog::CreateConfig {
                choices: Vec::new(),
                cursor: 0,
                cwd: tmp.path().to_path_buf(),
                status: None,
            },
        ),
        (
            "CreateScopedConfig",
            Dialog::CreateScopedConfig {
                choices: Vec::new(),
                cursor: 0,
                cwd: tmp.path().to_path_buf(),
            },
        ),
        ("WizardMenu", Dialog::open_setup(tmp.path())),
        (
            "ModelSetupChoice",
            Dialog::open_model_setup_choice(tmp.path(), None, None),
        ),
        (
            "SetupWizard",
            Dialog::open_setup_wizard(tmp.path(), cockpit_core::wizard::SECURITY_WIZARD_ID)
                .unwrap_or_else(|_| Dialog::open_setup(tmp.path())),
        ),
        (
            "FirstRunComplete",
            Dialog::open_first_run_complete("ready".into()),
        ),
        (
            "Settings",
            Dialog::Settings(Box::new(crate::tui::settings::SettingsDialog::open(
                tmp.path().join("config.json"),
            ))),
        ),
    ];
    for (name, dialog) in dialogs {
        app.dialog = dialog;
        app.mouse_capture = true;
        draw(&mut app);
        assert!(
            app.dialog.is_active(),
            "{name} must render as an active dialog"
        );
        app.mouse_capture = false;
        draw(&mut app);
        assert!(
            app.button_registry.targets().is_empty(),
            "{name} capture-off publishes no ButtonRegistry pointer targets"
        );
        assert!(app.button_registry.hover().is_none());
        assert!(app.button_registry.pressed().is_none());
    }

    app.dialog = SettingsDialogKind::None;
    app.overlay = Overlay::None;
    app.mouse_capture = false;
    draw(&mut app);
    assert!(
        app.button_registry.targets().is_empty(),
        "capture-off publishes no ButtonRegistry pointer targets"
    );
    assert!(app.button_registry.hover().is_none());
    assert!(app.button_registry.pressed().is_none());
    let _ = ButtonDispatch::NoteNew;
}

fn dispatch_overlay_surface(app: &mut App, surface: crate::tui::button::OverlaySurface) {
    use crate::tui::button::{ButtonDispatch, ButtonId, ButtonSpec};
    app.overlay = Overlay::None;
    app.mouse_capture = true;
    let backend = TestBackend::new(40, 3);
    let mut terminal = Terminal::new(backend).expect("terminal");
    terminal
        .draw(|frame| {
            app.button_registry.begin_frame(true, 1);
            let spec = ButtonSpec::new(
                ButtonId::overlay(surface, 0),
                "action",
                ButtonDispatch::OverlayAction { surface, index: 0 },
            );
            let rect = app
                .button_registry
                .paint(frame, 0, 1, 20, spec)
                .expect("overlay action painted");
            app.button_registry.end_frame();
            let down = mouse(MouseEventKind::Down(MouseButton::Left), rect.x, rect.y);
            assert!(matches!(
                app.button_registry.handle_mouse(down),
                Some(crate::tui::button::ButtonPointerOutcome::Pressed(_))
            ));
            let up = mouse(MouseEventKind::Up(MouseButton::Left), rect.x, rect.y);
            assert!(matches!(
                app.button_registry.handle_mouse(up),
                Some(crate::tui::button::ButtonPointerOutcome::Activated(
                    ButtonDispatch::OverlayAction { .. }
                ))
            ));
        })
        .expect("dispatch overlay surface");
}
