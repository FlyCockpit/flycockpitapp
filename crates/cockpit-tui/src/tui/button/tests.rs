use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier};

use crate::tui::button::{
    ButtonDispatch, ButtonId, ButtonPointerOutcome, ButtonRegistry, ButtonSpec, ControlKind,
    InventoryMember, bracketed_label, button_inventory, clip_to_display_width, display_width,
    settings_pointer_control_kind,
};
use crate::tui::chrome::FooterControl;
use crate::tui::settings::pointer_actions::SettingsPointerAction;
use crate::tui::settings::shell::SettingsHeaderAction;
use crate::tui::theme::{
    BUTTON_DESTRUCTIVE_BG, BUTTON_DESTRUCTIVE_BG_ANSI, BUTTON_DESTRUCTIVE_FG, BUTTON_FOCUS_BG,
    BUTTON_FOCUS_BG_ANSI, BUTTON_FOCUS_FG, BUTTON_HOVER_BG, BUTTON_HOVER_BG_ANSI, BUTTON_HOVER_FG,
    BUTTON_PRESSED_BG, BUTTON_PRESSED_BG_ANSI, BUTTON_PRESSED_FG, button_hover_style,
};

fn mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

fn paint_sample(
    registry: &mut ButtonRegistry,
    spec: ButtonSpec,
    x: u16,
    max_width: u16,
) -> (Rect, String) {
    let backend = TestBackend::new(40, 3);
    let mut terminal = Terminal::new(backend).expect("terminal");
    let mut painted = None;
    terminal
        .draw(|frame| {
            painted = registry.paint(frame, x, 1, max_width, spec);
        })
        .expect("draw");
    let rect = painted.expect("button painted");
    let buf = terminal.backend().buffer();
    let mut text = String::new();
    for col in rect.x..rect.right() {
        text.push(buf[(col, rect.y)].symbol().chars().next().unwrap_or(' '));
    }
    (rect, text)
}

#[test]
fn button_primitive_exact_bounds() {
    let mut registry = ButtonRegistry::default();
    registry.begin_frame(true, 1);

    let ascii = ButtonSpec::new(
        ButtonId::SettingsHeader(SettingsHeaderAction::Close),
        "Close settings",
        ButtonDispatch::SettingsHeader(SettingsHeaderAction::Close),
    );
    let (rect, text) = paint_sample(&mut registry, ascii, 2, 40);
    assert_eq!(text, "[Close settings]");
    assert_eq!(rect, Rect::new(2, 1, display_width("[Close settings]"), 1));
    let hit = registry.hit(2, 1).expect("ascii hit");
    assert_eq!(hit.rect, rect);
    assert_eq!(
        hit.id,
        ButtonId::SettingsHeader(SettingsHeaderAction::Close)
    );
    assert!(registry.hit(1, 1).is_none());
    assert!(registry.hit(rect.right(), 1).is_none());

    registry.begin_frame(true, 1);
    let wide = ButtonSpec::new(ButtonId::NoteNew, "加 新", ButtonDispatch::NoteNew);
    let (rect, text) = paint_sample(&mut registry, wide, 0, 40);
    let compact: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
    assert!(compact.contains('加') && compact.contains('新'), "{text:?}");
    assert_eq!(rect.width, display_width("[加 新]"));
    assert_eq!(registry.hit(0, 1).map(|t| t.rect), Some(rect));

    registry.begin_frame(true, 1);
    let combining = ButtonSpec::new(
        ButtonId::Footer(FooterControl::Model),
        "e\u{301}",
        ButtonDispatch::Footer(FooterControl::Model),
    );
    let (rect, _) = paint_sample(&mut registry, combining, 0, 40);
    assert_eq!(rect.width, display_width("[e\u{301}]"));
    assert_eq!(registry.targets()[0].rect, rect);

    registry.begin_frame(true, 1);
    let clipped = ButtonSpec::new(
        ButtonId::SessionsConfirmArchive,
        "Archive",
        ButtonDispatch::SessionsConfirmArchive,
    );
    let (rect, text) = paint_sample(&mut registry, clipped, 0, 4);
    assert_eq!(text, "[Arc");
    assert_eq!(rect.width, 4);
    assert!(registry.hit(3, 1).is_some());
    assert!(registry.hit(4, 1).is_none());

    registry.begin_frame(true, 1);
    let disabled = ButtonSpec::new(
        ButtonId::PersistentNoticeCopy,
        "copy",
        ButtonDispatch::PersistentNoticeCopy,
    )
    .enabled(false);
    let (rect, text) = paint_sample(&mut registry, disabled, 0, 20);
    assert_eq!(text, "[copy]");
    assert!(!registry.hit(rect.x, rect.y).unwrap().enabled);

    registry.begin_frame(true, 1);
    let zero = ButtonSpec::new(
        ButtonId::ResourcePromote {
            request_id: uuid::Uuid::nil(),
        },
        "promote",
        ButtonDispatch::ResourcePromote {
            request_id: uuid::Uuid::nil(),
        },
    );
    let backend = TestBackend::new(40, 3);
    let mut terminal = Terminal::new(backend).expect("terminal");
    let mut painted = None;
    terminal
        .draw(|frame| {
            painted = registry.paint(frame, 0, 1, 0, zero);
        })
        .expect("draw");
    assert!(painted.is_none());
    assert!(registry.targets().is_empty());
    assert_eq!(clip_to_display_width(&bracketed_label("x"), 0), "");
}

#[test]
fn button_press_cancellation_matrix() {
    let mut registry = ButtonRegistry::default();
    registry.begin_frame(true, 1);
    let spec = ButtonSpec::new(
        ButtonId::SettingsHeader(SettingsHeaderAction::Close),
        "Close settings",
        ButtonDispatch::SettingsHeader(SettingsHeaderAction::Close),
    );
    let (rect, _) = paint_sample(&mut registry, spec.clone(), 0, 40);
    assert!(matches!(
        registry.handle_mouse(mouse(
            MouseEventKind::Down(MouseButton::Left),
            rect.x,
            rect.y
        )),
        Some(ButtonPointerOutcome::Pressed(_))
    ));
    assert!(registry.pressed().is_some());

    assert!(matches!(
        registry.handle_mouse(mouse(MouseEventKind::Moved, 30, 2)),
        Some(ButtonPointerOutcome::Cancelled | ButtonPointerOutcome::HoverChanged)
    ));
    assert!(registry.pressed().is_none());
    assert!(!matches!(
        registry.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 30, 2)),
        Some(ButtonPointerOutcome::Activated(_))
    ));

    registry.begin_frame(true, 1);
    let _ = paint_sample(&mut registry, spec.clone(), 0, 40);
    let _ = registry.handle_mouse(mouse(
        MouseEventKind::Down(MouseButton::Left),
        rect.x,
        rect.y,
    ));
    registry.begin_frame(true, 2);
    let _ = paint_sample(&mut registry, spec.clone(), 0, 40);
    registry.end_frame();
    assert!(registry.pressed().is_none());
    assert!(!matches!(
        registry.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), rect.x, rect.y)),
        Some(ButtonPointerOutcome::Activated(_))
    ));

    registry.begin_frame(true, 3);
    let _ = paint_sample(&mut registry, spec.clone(), 0, 40);
    let _ = registry.handle_mouse(mouse(
        MouseEventKind::Down(MouseButton::Left),
        rect.x,
        rect.y,
    ));
    registry.clear_hover_and_pressed();
    assert!(!matches!(
        registry.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), rect.x, rect.y)),
        Some(ButtonPointerOutcome::Activated(_))
    ));

    registry.begin_frame(true, 4);
    let disabled = spec.clone().enabled(false);
    let _ = paint_sample(&mut registry, disabled, 0, 40);
    assert!(matches!(
        registry.handle_mouse(mouse(
            MouseEventKind::Down(MouseButton::Left),
            rect.x,
            rect.y
        )),
        Some(ButtonPointerOutcome::Consumed)
    ));
    assert!(registry.pressed().is_none());

    registry.begin_frame(true, 5);
    let _ = paint_sample(&mut registry, spec.clone(), 0, 40);
    let _ = registry.handle_mouse(mouse(
        MouseEventKind::Down(MouseButton::Left),
        rect.x,
        rect.y,
    ));
    assert!(matches!(
        registry.handle_mouse(mouse(
            MouseEventKind::Down(MouseButton::Right),
            rect.x,
            rect.y
        )),
        Some(ButtonPointerOutcome::Cancelled)
    ));
    assert!(!matches!(
        registry.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), rect.x, rect.y)),
        Some(ButtonPointerOutcome::Activated(_))
    ));

    registry.begin_frame(true, 6);
    let _ = paint_sample(&mut registry, spec, 0, 40);
    assert!(matches!(
        registry.handle_mouse(mouse(
            MouseEventKind::Down(MouseButton::Left),
            rect.x,
            rect.y
        )),
        Some(ButtonPointerOutcome::Pressed(_))
    ));
    assert!(matches!(
        registry.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), rect.x, rect.y)),
        Some(ButtonPointerOutcome::Activated(_))
    ));
    assert!(matches!(
        registry.handle_mouse(mouse(
            MouseEventKind::Down(MouseButton::Left),
            rect.x,
            rect.y
        )),
        Some(ButtonPointerOutcome::Pressed(_))
    ));
    assert!(matches!(
        registry.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), rect.x, rect.y)),
        Some(ButtonPointerOutcome::Consumed)
    ));
}

#[test]
fn button_press_survives_same_id_redraw() {
    let mut registry = ButtonRegistry::default();
    registry.begin_frame(true, 1);
    let spec = ButtonSpec::new(
        ButtonId::Settings(SettingsPointerAction::DefaultModel(
            crate::tui::settings::pointer_actions::DefaultModelAction::Choose,
        )),
        "Choose default model",
        ButtonDispatch::Settings(SettingsPointerAction::DefaultModel(
            crate::tui::settings::pointer_actions::DefaultModelAction::Choose,
        )),
    );
    let (rect, _) = paint_sample(&mut registry, spec.clone(), 0, 40);
    assert!(matches!(
        registry.handle_mouse(mouse(
            MouseEventKind::Down(MouseButton::Left),
            rect.x,
            rect.y
        )),
        Some(ButtonPointerOutcome::Pressed(_))
    ));

    registry.begin_frame(true, 1);
    let _ = paint_sample(&mut registry, spec, 0, 40);
    registry.end_frame();
    assert!(
        registry.pressed().is_some(),
        "press identity is ButtonId and must survive a same-surface redraw"
    );
    assert!(matches!(
        registry.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), rect.x, rect.y)),
        Some(ButtonPointerOutcome::Activated(_))
    ));
}

#[test]
fn tui_button_inventory_is_complete() {
    let inventory = button_inventory();
    assert!(
        inventory.iter().any(|item| matches!(
            item.member,
            InventoryMember::Button(ButtonId::SettingsHeader(_))
        )),
        "settings header buttons must be inventoried"
    );
    assert!(inventory.iter().any(|item| item.surface == "footer"));
    assert!(inventory.iter().any(|item| item.surface == "transcript"));
    assert!(inventory.iter().any(|item| item.surface == "queue"));
    assert!(inventory.iter().any(|item| item.surface == "notice"));
    assert!(inventory.iter().any(|item| item.surface == "sessions"));
    assert!(inventory.iter().any(|item| item.surface == "model_picker"));
    assert!(inventory.iter().any(|item| item.surface == "multireview"));
    assert!(inventory.iter().any(|item| item.surface == "stats"));
    assert!(inventory.iter().any(|item| item.surface == "skills"));
    assert!(inventory.iter().any(|item| item.surface == "tools"));
    assert!(inventory.iter().any(|item| item.surface == "goal_settings"));
    assert!(inventory.iter().any(|item| item.surface == "permissions"));
    assert!(inventory.iter().any(|item| item.surface == "resources"));
    assert!(inventory.iter().any(|item| item.surface == "quick"));
    assert!(inventory.iter().any(|item| item.surface == "notes"));
    assert!(inventory.iter().any(|item| item.surface == "diff"));
    assert!(
        inventory
            .iter()
            .any(|item| item.surface == "workspace_trust")
    );
    assert!(inventory.iter().any(|item| item.surface == "pick_config"));
    assert!(inventory.iter().any(|item| item.surface == "create_config"));
    assert!(
        inventory
            .iter()
            .any(|item| item.surface == "create_scoped_config")
    );
    assert!(inventory.iter().any(|item| item.surface == "wizard_menu"));
    assert!(
        inventory
            .iter()
            .any(|item| item.surface == "model_setup_choice")
    );
    assert!(inventory.iter().any(|item| item.surface == "setup_wizard"));
    assert!(
        inventory
            .iter()
            .any(|item| item.surface == "first_run_complete")
    );
    assert!(inventory.iter().any(|item| item.surface == "question"));
    assert!(inventory.iter().any(|item| item.surface == "context_menu"));
    assert!(
        !inventory
            .iter()
            .any(|item| item.surface == "help" && item.kind == ControlKind::Button),
        "help is a read-only overlay"
    );

    let families: Vec<_> = inventory
        .iter()
        .filter_map(|item| match &item.member {
            InventoryMember::Button(id) => Some(super::inventory::button_id_family(id)),
            InventoryMember::RowControl(_) => None,
        })
        .collect();
    for family in [
        "settings_header",
        "footer",
        "transcript",
        "notice",
        "sessions",
        "resources",
        "notes",
        "queue",
    ] {
        assert!(families.contains(&family), "missing button family {family}");
    }

    assert_eq!(
        settings_pointer_control_kind(&SettingsPointerAction::DefaultModel(
            crate::tui::settings::pointer_actions::DefaultModelAction::Choose
        )),
        ControlKind::Button
    );
    assert_eq!(
        settings_pointer_control_kind(&SettingsPointerAction::Root(
            crate::tui::settings::pointer_actions::RootAction::Open(
                crate::tui::settings::pointer_actions::RootNodeId::Interface
            )
        )),
        ControlKind::RowControl
    );

    let src = collect_tui_source();
    let forbidden = scan_raw_interactive_brackets(&src);
    assert!(
        forbidden.is_empty(),
        "raw bracketed interactive actions must go through ButtonRegistry::paint: {forbidden:?}"
    );
}

#[test]
fn interaction_theme_contrast_matrix() {
    let pairs = [
        (BUTTON_HOVER_FG, BUTTON_HOVER_BG, BUTTON_HOVER_BG_ANSI),
        (BUTTON_FOCUS_FG, BUTTON_FOCUS_BG, BUTTON_FOCUS_BG_ANSI),
        (BUTTON_PRESSED_FG, BUTTON_PRESSED_BG, BUTTON_PRESSED_BG_ANSI),
        (
            BUTTON_DESTRUCTIVE_FG,
            BUTTON_DESTRUCTIVE_BG,
            BUTTON_DESTRUCTIVE_BG_ANSI,
        ),
    ];
    for (fg, bg, ansi) in pairs {
        assert!(
            contrast_ratio(fg, bg) >= 4.5,
            "contrast {fg:?} on {bg:?} is {}",
            contrast_ratio(fg, bg)
        );
        assert_ne!(ansi, Color::Reset);
        match ansi {
            Color::Indexed(_) | Color::Rgb(_, _, _) => {}
            other => panic!("ANSI fallback must be explicit, got {other:?}"),
        }
    }
    assert_ne!(BUTTON_HOVER_BG, BUTTON_FOCUS_BG);
    assert_ne!(BUTTON_HOVER_BG, BUTTON_PRESSED_BG);
    assert_ne!(BUTTON_FOCUS_BG, BUTTON_PRESSED_BG);

    let src = collect_tui_source();
    assert!(
        !src.contains("fg(Color::Black).bg(Color::White)"),
        "action text must not use hard black-on-white"
    );
    assert!(
        !src.contains(".fg(Color::Black).bg(ERROR_TEXT)"),
        "action text must not use black-on-error"
    );
}

#[test]
fn interaction_highlight_role_inventory_is_complete() {
    let roles = highlight_role_inventory();
    assert!(roles.iter().any(|role| role.contains("button hover")));
    assert!(roles.iter().any(|role| role.contains("link base")));
    assert!(roles.iter().any(|role| role.contains("text selection")));
    assert!(roles.iter().any(|role| role.contains("question.rs")));
    assert!(roles.iter().any(|role| role.contains("notes_pane.rs")));
    assert!(roles.iter().any(|role| role.contains("markdown")));
}

#[test]
fn links_and_selection_remain_semantic() {
    let link = crate::tui::links::base_link_style();
    assert_eq!(link.fg, Some(Color::Cyan));
    assert!(link.add_modifier.contains(Modifier::UNDERLINED));
    assert_ne!(link, button_hover_style());

    let hover = crate::tui::links::hovered_link_style();
    assert!(hover.add_modifier.contains(Modifier::UNDERLINED));
    assert_ne!(hover.bg, Some(BUTTON_HOVER_BG));

    let src = include_str!("../app/render.rs");
    assert!(
        src.contains("add_modifier(Modifier::REVERSED)"),
        "text selection must keep reverse-video"
    );
    assert!(
        !src.contains("button_hover_style()") || src.contains("Selection"),
        "selection path stays distinct from button hover"
    );
}

fn collect_tui_source() -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tui");
    let mut out = String::new();
    visit_rs(&root, &mut out);
    out
}

fn visit_rs(path: &std::path::Path, out: &mut String) {
    if path.is_dir() {
        for entry in std::fs::read_dir(path).expect("read dir") {
            visit_rs(&entry.expect("entry").path(), out);
        }
        return;
    }
    if path.extension().and_then(|e| e.to_str()) != Some("rs") {
        return;
    }
    let rel = path.to_string_lossy();
    if rel.contains("/button/") || rel.ends_with("tests.rs") || rel.contains("/tests/") {
        return;
    }
    out.push_str(&std::fs::read_to_string(path).expect("read"));
    out.push('\n');
}

fn scan_raw_interactive_brackets(src: &str) -> Vec<String> {
    let forbidden_labels = [
        "[Close settings]",
        "[Choose default model]",
        "[Clear default for this scope]",
        "[switch model]",
        "[fix provider]",
        "[ Archive ]",
    ];
    let mut hits = Vec::new();
    for (idx, line) in src.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("///") {
            continue;
        }
        if !(line.contains("Span::") || line.contains("Line::from")) {
            continue;
        }
        if line.contains("bracketed_label")
            || line.contains("paint_header_button")
            || line.contains("paint_page_button")
            || line.contains("button_idle_style")
            || line.contains("button_style")
        {
            continue;
        }
        if forbidden_labels.iter().any(|label| line.contains(label)) {
            hits.push(format!("{}: {trimmed}", idx + 1));
        }
    }
    hits
}

fn highlight_role_inventory() -> Vec<String> {
    let mut roles = vec![
        "button hover → BUTTON_HOVER_* via ButtonRegistry".into(),
        "button focus → BUTTON_FOCUS_* via ButtonRegistry".into(),
        "button pressed → BUTTON_PRESSED_* via ButtonRegistry".into(),
        "button destructive → BUTTON_DESTRUCTIVE_* via ButtonRegistry".into(),
        "row selection → row_selection_style / ROW_SELECTION_*".into(),
        "transcript affordance hover → TRANSCRIPT_HOVER_BG".into(),
        "link base → links::base_link_style cyan+underline".into(),
        "link hover → links::hovered_link_style".into(),
        "text selection → terminal reverse-video in app/render.rs".into(),
    ];
    roles.extend(scan_highlight_roles());
    roles
}

fn scan_highlight_roles() -> Vec<String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tui");
    let mut hits = Vec::new();
    visit_highlight_roles(&root, &root, &mut hits);
    hits
}

fn visit_highlight_roles(root: &std::path::Path, path: &std::path::Path, hits: &mut Vec<String>) {
    if path.is_dir() {
        for entry in std::fs::read_dir(path).expect("read dir") {
            visit_highlight_roles(root, &entry.expect("entry").path(), hits);
        }
        return;
    }
    if path.extension().and_then(|e| e.to_str()) != Some("rs") {
        return;
    }
    let rel = path.strip_prefix(root).unwrap_or(path);
    let rel = rel.to_string_lossy();
    if rel.starts_with("button/") || rel.ends_with("tests.rs") || rel.contains("/tests/") {
        return;
    }
    let src = std::fs::read_to_string(path).expect("read");
    for (idx, line) in src.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("///") {
            continue;
        }
        if trimmed.contains("assert!")
            || trimmed.contains("assert_eq")
            || trimmed.contains("assert_ne")
            || trimmed.contains(".contains(")
            || trimmed.contains("filter(")
        {
            continue;
        }
        let underlined = trimmed.contains("Modifier::UNDERLINED");
        let reversed = trimmed.contains("Modifier::REVERSED");
        let black_on_white =
            trimmed.contains("fg(Color::Black)") && trimmed.contains("Color::White");
        let black_on_error = trimmed.contains("fg(Color::Black)")
            && (trimmed.contains("ERROR_TEXT") || trimmed.contains("ERROR"));
        let black_on = trimmed.contains("fg(Color::Black)") && trimmed.contains(".bg(");
        if !(underlined || reversed || black_on_white || black_on_error || black_on) {
            continue;
        }
        let role = classify_highlight_role(&rel, trimmed);
        hits.push(format!("{rel}:{} → {role}", idx + 1));
    }
}

fn classify_highlight_role(rel: &str, line: &str) -> String {
    if rel.contains("links.rs") {
        return "link base/hover cyan+underline".into();
    }
    if rel.contains("markdown.rs") {
        return "markdown underline formatting exception".into();
    }
    if rel.contains("question.rs") {
        return "question.rs command-span underline → noninteractive emphasis".into();
    }
    if rel.contains("notes_pane.rs") && line.contains("UNDERLINED") {
        return "notes_pane.rs name-field underline → text-field caret exception".into();
    }
    if rel.contains("notes_pane.rs") {
        return "notes_pane.rs row selection token".into();
    }
    if rel.contains("chrome.rs") && line.contains("Color::Black") {
        return "chrome branch badge black-on-yellow → noninteractive status".into();
    }
    if rel.contains("history/") && line.contains("UNDERLINED") {
        return "history DIM|UNDERLINED metadata → static status exception".into();
    }
    if rel.contains("pins_overlay.rs") && line.contains("REVERSED") {
        return "pins overlay REVERSED row → row selection".into();
    }
    if rel.contains("leaks_pane.rs") && line.contains("REVERSED") {
        return "leaks pane REVERSED row → row selection".into();
    }
    if rel.contains("app/render.rs") && line.contains("REVERSED") {
        return "text selection / composer REVERSED".into();
    }
    if rel.contains("app/render.rs") && line.contains("Color::Black") {
        return "shell-mode badge noninteractive status".into();
    }
    if rel.contains("oauth_flow.rs") && line.contains("UNDERLINED") {
        return "oauth wizard noninteractive emphasis".into();
    }
    panic!("unclassified highlight role in {rel}: {line}");
}

fn contrast_ratio(fg: Color, bg: Color) -> f64 {
    let (fr, fg_, fb) = srgb(fg);
    let (br, bg_, bb) = srgb(bg);
    let l1 = luminance(fr, fg_, fb);
    let l2 = luminance(br, bg_, bb);
    let (hi, lo) = if l1 > l2 { (l1, l2) } else { (l2, l1) };
    (hi + 0.05) / (lo + 0.05)
}

fn srgb(color: Color) -> (u8, u8, u8) {
    match color {
        Color::Rgb(r, g, b) => (r, g, b),
        Color::White => (255, 255, 255),
        Color::Black => (0, 0, 0),
        other => panic!("expected explicit sRGB color, got {other:?}"),
    }
}

fn luminance(r: u8, g: u8, b: u8) -> f64 {
    fn chan(c: u8) -> f64 {
        let c = f64::from(c) / 255.0;
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    }
    0.2126 * chan(r) + 0.7152 * chan(g) + 0.0722 * chan(b)
}
