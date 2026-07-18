//! Which-key overlay — a Cockpit-native, context-aware key-discovery panel.
//!
//! Pressing the leader key (`Ctrl+K` — `Ctrl+X` is already the embedded-pane
//! force-close, so the nearest free binding is used) or running `/keys`
//! (`/keybindings`) opens a modal overlay that lists the keybindings live in
//! the *current* TUI context first, followed by the always-available global
//! bindings. It is purely informational: `Esc`, `q`, or the leader again
//! closes it, focus unchanged.
//!
//! Design notes (the four design rules this file honors):
//!  - **TUI-only.** The overlay is pure chrome: it never sends anything to the
//!    agent and never enters the transcript or any inference request.
//!  - **Modal precedence.** The overlay is never opened while an approval /
//!    question dialog is up, so a required agent decision is never obscured or
//!    bypassed. Startup prompts and informational panes can sit underneath it.
//!  - **Data-driven descriptors.** Each pane / context exposes a small
//!    `keybindings()` descriptor (a [`KeyGroup`]); this module's
//!    [`groups_for`] aggregates them in context-first order. No comment
//!    scraping, no prose duplication.
//!  - **Discovery only.** This is *not* a configurable keybinding/remapping
//!    system — the descriptors are static and informational.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::tui::pane::Pane;
use crate::tui::theme::MUTED_COLOR_INDEX;

/// The leader key shown in help text. `Ctrl+X` is taken (embedded-pane
/// force-close, `crate::tui::app::input`), so the which-key overlay uses
/// the nearest free chord, `Ctrl+K`.
pub const LEADER_HINT: &str = "Ctrl+K";

/// One discoverable keybinding row: the key glyph, the action label, and a
/// terse description. Static `&'static str` so the descriptors cost nothing
/// to build and can live in `const`s on each pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyBinding {
    /// The key (or chord) glyph shown in the left column, e.g. `↑/↓`, `q`.
    pub key: &'static str,
    /// The short action label shown in the middle column, e.g. `scroll`.
    pub action: &'static str,
    /// A terse one-clause description shown in the right column.
    pub desc: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogBindingId {
    Pick,
    ApprovalPick,
    Toggle,
    Move,
    Choose,
    SpaceToggle,
    EnterSelectConfirm,
    ConfirmAgain,
    Questions,
    PromptScroll,
    ChatScroll,
    Expand,
    Collapse,
    Cancel,
    TypeAnswer,
    Done,
    Submit,
    Back,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialogBinding {
    pub id: DialogBindingId,
    pub key: &'static str,
    pub action: &'static str,
    pub desc: &'static str,
    pub footer: &'static str,
    pub priority: u8,
    pub requires_keyboard_enhancement: bool,
    pub which_key: bool,
}

impl DialogBinding {
    pub fn key_binding(self) -> KeyBinding {
        KeyBinding {
            key: self.key,
            action: self.action,
            desc: self.desc,
        }
    }
}

/// A titled group of [`KeyBinding`]s for one context, e.g. `Sessions`,
/// `Composer`, `Global`. The overlay renders these in order, context-first.
#[derive(Debug, Clone, Copy)]
pub struct KeyGroup {
    /// The group heading, e.g. `Sessions`.
    pub title: &'static str,
    /// The rows in this group.
    pub bindings: &'static [KeyBinding],
}

#[derive(Debug, Clone)]
struct OwnedKeyGroup {
    title: &'static str,
    bindings: Vec<KeyBinding>,
}

impl From<KeyGroup> for OwnedKeyGroup {
    fn from(group: KeyGroup) -> Self {
        Self {
            title: group.title,
            bindings: group.bindings.to_vec(),
        }
    }
}

/// The active TUI context the overlay was opened in. Determines which group
/// is listed *first* (before [`GLOBAL`]). Resolved by the app from its modal
/// /pane state at the moment the leader fires (see
/// `crate::tui::app::App::key_context`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyContext {
    /// Main chat / composer — no modal or pane open.
    Composer,
    /// Slash-command menu is open in the composer.
    SlashMenu,
    /// `/model` picker.
    ModelPicker,
    /// Settings / config dialog.
    Settings,
    /// `/sessions` / `/resume` browser.
    Sessions,
    /// `/plans` browser.
    /// `/permissions` pane.
    Permissions,
    /// `/resources` pane.
    Resources,
    /// `/quick` session settings dialog.
    QuickSettings,
    /// `/scratchpad` (notes) pane.
    Scratchpad,
    /// `/diff` read-only diff browser.
    Diff,
    /// `/pins` review or `/pin` pick mode.
    Pins,
    /// Embedded `$EDITOR` / `lazygit` pane.
    EmbeddedPane,
    /// `/btw` side conversation pane.
    BtwPane,
    /// A `question`-tool answering dialog.
    QuestionDialog,
    /// An approval dialog (`y`/`n` style required decision).
    ApprovalDialog,
}

/// Global bindings — always live, listed after the context group.
const GLOBAL: KeyGroup = KeyGroup {
    title: "Global",
    bindings: &[
        KeyBinding {
            key: LEADER_HINT,
            action: "keys",
            desc: "open/close this which-key overlay (also /keys)",
        },
        KeyBinding {
            key: "Ctrl+C",
            action: "interrupt",
            desc: "stop the running agent; press twice to quit",
        },
        KeyBinding {
            key: "Ctrl+D",
            action: "quit",
            desc: "exit when idle; guarded while work is active",
        },
        KeyBinding {
            key: "/",
            action: "commands",
            desc: "open the slash-command menu",
        },
    ],
};

/// Composer / main-chat bindings.
const COMPOSER: KeyGroup = KeyGroup {
    title: "Composer",
    bindings: &[
        KeyBinding {
            key: "Enter",
            action: "send",
            desc: "submit the message",
        },
        KeyBinding {
            key: "Ctrl+J",
            action: "newline",
            desc: "insert a newline",
        },
        KeyBinding {
            key: "Ctrl+T",
            action: "thinking",
            desc: "toggle reasoning blocks",
        },
        KeyBinding {
            key: "Ctrl+Y",
            action: "copy pick",
            desc: "pick a message or code block to copy",
        },
        KeyBinding {
            key: "Shift+Tab",
            action: "cycle agent",
            desc: "switch the primary agent",
        },
        KeyBinding {
            key: "@",
            action: "file tag",
            desc: "tag a file into the message",
        },
        KeyBinding {
            key: "↑/↓",
            action: "history",
            desc: "recall previously sent messages",
        },
        KeyBinding {
            key: "PgUp/PgDn",
            action: "scroll",
            desc: "scroll the chat transcript; Shift+↑/↓ scrolls by line",
        },
        KeyBinding {
            key: "End",
            action: "live tail",
            desc: "jump to the newest messages",
        },
        KeyBinding {
            key: "Ctrl+N",
            action: "scratchpad",
            desc: "open the project scratchpad",
        },
        KeyBinding {
            key: "Ctrl+G",
            action: "$EDITOR",
            desc: "edit the composer text in $EDITOR",
        },
        KeyBinding {
            key: "Esc",
            action: "normal/cancel",
            desc: "vim Normal mode, or cancel a slash query",
        },
    ],
};

/// Slash-menu bindings (composer with a `/` query open).
const SLASH_MENU: KeyGroup = KeyGroup {
    title: "Slash menu",
    bindings: &[
        KeyBinding {
            key: "↑/↓",
            action: "move",
            desc: "highlight a command",
        },
        KeyBinding {
            key: "Tab",
            action: "complete",
            desc: "complete / cycle the highlighted command",
        },
        KeyBinding {
            key: "Enter",
            action: "run",
            desc: "run the highlighted command",
        },
        KeyBinding {
            key: "Esc",
            action: "cancel",
            desc: "close the menu",
        },
    ],
};

/// Embedded-pane (`$EDITOR` / `lazygit`) bindings.
const EMBEDDED_PANE: KeyGroup = KeyGroup {
    title: "Embedded pane",
    bindings: &[
        KeyBinding {
            key: "Ctrl+X",
            action: "close",
            desc: "force-close the embedded pane",
        },
        KeyBinding {
            key: "Ctrl+O",
            action: "focus",
            desc: "toggle focus between the pane and the composer",
        },
    ],
};

/// `/btw` side-pane bindings.
const BTW_PANE: KeyGroup = KeyGroup {
    title: "BTW pane",
    bindings: &[
        KeyBinding {
            key: "Ctrl+B",
            action: "focus",
            desc: "toggle focus between the btw pane and main composer",
        },
        KeyBinding {
            key: "F11",
            action: "zoom",
            desc: "toggle the btw pane full-screen",
        },
        KeyBinding {
            key: "Esc",
            action: "main focus",
            desc: "return to main composer when the side composer is idle",
        },
        KeyBinding {
            key: "Enter",
            action: "send",
            desc: "submit the side-pane message",
        },
    ],
};

pub const DIALOG_BINDINGS: &[DialogBinding] = &[
    DialogBinding {
        id: DialogBindingId::Pick,
        key: "1-9",
        action: "select",
        desc: "choose a numbered option",
        footer: "1-9: pick",
        priority: 20,
        requires_keyboard_enhancement: false,
        which_key: true,
    },
    DialogBinding {
        id: DialogBindingId::ApprovalPick,
        key: "1-9/Enter",
        action: "select",
        desc: "select an approval option",
        footer: "1-9/enter: select",
        priority: 20,
        requires_keyboard_enhancement: false,
        which_key: false,
    },
    DialogBinding {
        id: DialogBindingId::Toggle,
        key: "1-9/Enter",
        action: "toggle",
        desc: "toggle a multiselect option",
        footer: "1-9/enter: toggle",
        priority: 20,
        requires_keyboard_enhancement: false,
        which_key: false,
    },
    DialogBinding {
        key: "↑/↓ or j/k",
        id: DialogBindingId::Move,
        action: "move",
        desc: "highlight an option",
        footer: "↑/↓: move",
        priority: 35,
        requires_keyboard_enhancement: false,
        which_key: true,
    },
    DialogBinding {
        id: DialogBindingId::Choose,
        key: "Enter",
        action: "choose",
        desc: "choose the highlighted answer",
        footer: "enter: choose",
        priority: 5,
        requires_keyboard_enhancement: false,
        which_key: false,
    },
    DialogBinding {
        id: DialogBindingId::ConfirmAgain,
        key: "Enter",
        action: "confirm",
        desc: "confirm a selected approval choice",
        footer: "enter again: confirm",
        priority: 6,
        requires_keyboard_enhancement: false,
        which_key: false,
    },
    DialogBinding {
        id: DialogBindingId::Questions,
        key: "←/→ or h/l",
        action: "questions",
        desc: "move between question pages",
        footer: "←/→: questions",
        priority: 50,
        requires_keyboard_enhancement: false,
        which_key: true,
    },
    DialogBinding {
        id: DialogBindingId::SpaceToggle,
        key: "Space",
        action: "toggle/type",
        desc: "toggle selection or edit Other…",
        footer: "space: toggle/type",
        priority: 60,
        requires_keyboard_enhancement: false,
        which_key: true,
    },
    DialogBinding {
        id: DialogBindingId::EnterSelectConfirm,
        key: "Enter",
        action: "select/confirm",
        desc: "select, then confirm permission choices",
        footer: "enter: choose",
        priority: 5,
        requires_keyboard_enhancement: false,
        which_key: true,
    },
    DialogBinding {
        id: DialogBindingId::PromptScroll,
        key: "PgUp/PgDn",
        action: "prompt scroll",
        desc: "scroll dialog prompt content",
        footer: "pgup/pgdn: scroll",
        priority: 70,
        requires_keyboard_enhancement: false,
        which_key: true,
    },
    DialogBinding {
        id: DialogBindingId::ChatScroll,
        key: "Shift+PgUp/PgDn",
        action: "chat scroll",
        desc: "scroll the transcript behind the dialog",
        footer: "shift+pgup/pgdn: chat",
        priority: 80,
        requires_keyboard_enhancement: true,
        which_key: true,
    },
    DialogBinding {
        id: DialogBindingId::Expand,
        key: "Ctrl+E",
        action: "expand",
        desc: "expand or collapse the dialog",
        footer: "ctrl+e: expand",
        priority: 90,
        requires_keyboard_enhancement: false,
        which_key: true,
    },
    DialogBinding {
        id: DialogBindingId::Collapse,
        key: "Ctrl+E",
        action: "collapse",
        desc: "collapse the dialog",
        footer: "ctrl+e: collapse",
        priority: 90,
        requires_keyboard_enhancement: false,
        which_key: false,
    },
    DialogBinding {
        id: DialogBindingId::Cancel,
        key: "Esc",
        action: "cancel",
        desc: "cancel the dialog",
        footer: "esc: cancel",
        priority: 0,
        requires_keyboard_enhancement: false,
        which_key: true,
    },
    DialogBinding {
        id: DialogBindingId::TypeAnswer,
        key: "type",
        action: "answer",
        desc: "type a free-text answer",
        footer: "type your answer",
        priority: 10,
        requires_keyboard_enhancement: false,
        which_key: false,
    },
    DialogBinding {
        id: DialogBindingId::Done,
        key: "Enter",
        action: "done",
        desc: "finish editing",
        footer: "enter: done",
        priority: 5,
        requires_keyboard_enhancement: false,
        which_key: false,
    },
    DialogBinding {
        id: DialogBindingId::Submit,
        key: "Enter",
        action: "submit",
        desc: "submit all answers",
        footer: "enter: submit",
        priority: 5,
        requires_keyboard_enhancement: false,
        which_key: false,
    },
    DialogBinding {
        id: DialogBindingId::Back,
        key: "←/h",
        action: "back",
        desc: "return to the previous question",
        footer: "←/h: back",
        priority: 25,
        requires_keyboard_enhancement: false,
        which_key: false,
    },
];

pub fn dialog_binding(id: DialogBindingId) -> &'static DialogBinding {
    DIALOG_BINDINGS
        .iter()
        .find(|binding| binding.id == id)
        .expect("dialog binding id exists")
}

pub fn dialog_which_key_bindings(keyboard_enhancement_active: bool) -> Vec<KeyBinding> {
    DIALOG_BINDINGS
        .iter()
        .filter(|binding| binding.which_key)
        .filter(|binding| !binding.requires_keyboard_enhancement || keyboard_enhancement_active)
        .map(|binding| binding.key_binding())
        .collect()
}

pub fn dialog_footer_bindings(
    ids: &[DialogBindingId],
    keyboard_enhancement_active: bool,
) -> Vec<&'static DialogBinding> {
    ids.iter()
        .map(|id| dialog_binding(*id))
        .filter(|binding| !binding.requires_keyboard_enhancement || keyboard_enhancement_active)
        .collect()
}

/// Model-picker bindings.
const MODEL_PICKER: KeyGroup = KeyGroup {
    title: "Model picker",
    bindings: &[
        KeyBinding {
            key: "↑/↓",
            action: "move",
            desc: "highlight a model",
        },
        KeyBinding {
            key: "type",
            action: "filter",
            desc: "filter the model list",
        },
        KeyBinding {
            key: "Enter",
            action: "select",
            desc: "switch to the highlighted model",
        },
        KeyBinding {
            key: "Esc",
            action: "cancel",
            desc: "close without changing the model",
        },
    ],
};

/// Settings-dialog bindings.
const SETTINGS: KeyGroup = KeyGroup {
    title: "Settings",
    bindings: &[
        KeyBinding {
            key: "↑/↓",
            action: "move",
            desc: "navigate settings",
        },
        KeyBinding {
            key: "Enter",
            action: "edit",
            desc: "open/toggle the highlighted setting",
        },
        KeyBinding {
            key: "Tab",
            action: "section",
            desc: "switch between settings sections",
        },
        KeyBinding {
            key: "Esc",
            action: "close",
            desc: "back out / close settings",
        },
    ],
};

/// Pins (review + pick) bindings.
const PINS: KeyGroup = KeyGroup {
    title: "Pins",
    bindings: &[
        KeyBinding {
            key: "↑/↓ · j/k",
            action: "move",
            desc: "scan pins / move the pick arrow",
        },
        KeyBinding {
            key: "Enter",
            action: "pin",
            desc: "pin the selected message (pick mode)",
        },
        KeyBinding {
            key: "d · Space",
            action: "unpin",
            desc: "unpin the highlighted pin (review mode)",
        },
        KeyBinding {
            key: "Esc",
            action: "close",
            desc: "leave pins, refocus the composer",
        },
    ],
};

/// The ordered list of groups to show for `context`: the context group
/// first, then [`GLOBAL`]. Pane-owned groups come from each pane's
/// `keybindings()` descriptor so the source of truth lives next to the
/// handler (data-driven, no prose duplication).
#[cfg(test)]
pub fn groups_for(context: KeyContext) -> Vec<KeyGroup> {
    groups_for_owned(context, true)
        .into_iter()
        .map(|group| {
            let leaked: &'static [KeyBinding] = Box::leak(group.bindings.into_boxed_slice());
            KeyGroup {
                title: group.title,
                bindings: leaked,
            }
        })
        .collect()
}

fn groups_for_owned(context: KeyContext, keyboard_enhancement_active: bool) -> Vec<OwnedKeyGroup> {
    let first = match context {
        KeyContext::QuestionDialog | KeyContext::ApprovalDialog => OwnedKeyGroup {
            title: match context {
                KeyContext::QuestionDialog => "Question",
                _ => "Approval",
            },
            bindings: dialog_which_key_bindings(keyboard_enhancement_active),
        },
        KeyContext::Composer => COMPOSER.into(),
        KeyContext::SlashMenu => SLASH_MENU.into(),
        KeyContext::ModelPicker => MODEL_PICKER.into(),
        KeyContext::Settings => SETTINGS.into(),
        KeyContext::Sessions => crate::tui::sessions_pane::SessionsPane::keybindings().into(),
        KeyContext::Permissions => {
            crate::tui::permissions_pane::PermissionsPane::keybindings().into()
        }
        KeyContext::Resources => crate::tui::resources_pane::ResourcesPane::keybindings().into(),
        KeyContext::QuickSettings => crate::tui::quick_dialog::QuickDialog::keybindings().into(),
        KeyContext::Scratchpad => crate::tui::notes_pane::NotesPane::keybindings().into(),
        KeyContext::Diff => crate::tui::diff_pane::DiffPane::keybindings().into(),
        KeyContext::Pins => PINS.into(),
        KeyContext::EmbeddedPane => EMBEDDED_PANE.into(),
        KeyContext::BtwPane => BTW_PANE.into(),
    };
    vec![first, GLOBAL.into()]
}

/// The modal which-key overlay. Scrollable, informational, bottom-anchored
/// over the chat body (like the other read-only panes). Owns nothing but
/// its own scroll + the captured context groups.
pub struct KeysOverlay {
    /// The context the overlay was opened in (drives the title + ordering).
    context: KeyContext,
    /// The aggregated groups (context-first, then global), captured at open.
    groups: Vec<OwnedKeyGroup>,
    /// Vertical scroll offset (in rendered body rows).
    scroll: usize,
    /// Rendered body height at the last draw — drives scroll clamping.
    last_body_height: usize,
    /// Total rendered body rows at the last draw — drives scroll clamp.
    last_content_rows: usize,
}

impl KeysOverlay {
    /// Open the overlay for `context`, capturing its ordered groups.
    #[cfg(test)]
    pub fn open(context: KeyContext) -> Self {
        Self::open_with_keyboard_enhancement(context, true)
    }

    pub fn open_with_keyboard_enhancement(
        context: KeyContext,
        keyboard_enhancement_active: bool,
    ) -> Self {
        Self {
            context,
            groups: groups_for_owned(context, keyboard_enhancement_active),
            scroll: 0,
            last_body_height: 0,
            last_content_rows: 0,
        }
    }

    /// Handle a key. Returns `true` when the overlay should close.
    ///
    /// The overlay is informational: only scroll + dismiss keys are live
    /// here. Dispatching a listed continuation key into the underlying
    /// context is deliberately *not* done — reusing each pane's key path
    /// from here would mean re-opening the just-closed pane or duplicating
    /// dispatch logic, which the prompt says to avoid where reuse isn't
    /// clean. The leader-again / Esc / q close is the single contract.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return true,
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll = self.scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
                self.scroll = (self.scroll + 1).min(max_scroll);
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(self.last_body_height.max(1));
            }
            KeyCode::PageDown => {
                let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
                self.scroll = (self.scroll + self.last_body_height.max(1)).min(max_scroll);
            }
            KeyCode::Char('g') => self.scroll = 0,
            KeyCode::Char('G') => {
                self.scroll = self.last_content_rows.saturating_sub(self.last_body_height);
            }
            _ => {}
        }
        false
    }

    /// Scroll the body up by one row (mouse wheel).
    pub fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    /// Scroll the body down by one row (mouse wheel), clamped to the floor.
    pub fn scroll_down(&mut self) {
        let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
        self.scroll = (self.scroll + 1).min(max_scroll);
    }

    /// The context this overlay is showing (tests assert the overlay opened
    /// in the right context).
    #[cfg(test)]
    pub fn context(&self) -> KeyContext {
        self.context
    }

    /// Render the overlay into `area`. Bottom-anchored over the chat body so
    /// the fixed chrome (cwd + git branch + context + active agent) stays
    /// visible — never permanently covered. Scrolls when the rows exceed the
    /// available height.
    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        // A clear under the overlay so the chat doesn't bleed through, then a
        // titled, rounded box. Anchored to the bottom of the body, capped to
        // the body height so it can never cover the fixed chrome above.
        if area.width == 0 || area.height == 0 {
            self.last_body_height = 0;
            return;
        }
        let lines = self.body_lines();
        let want = (lines.len() as u16).saturating_add(3); // borders + help row
        let h = want.min(area.height);
        let y = area.y + area.height.saturating_sub(h);
        let rect = Rect::new(area.x, y, area.width, h);

        frame.render_widget(Clear, rect);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .title(Line::from(format!(" keybindings — {} ", self.title())));
        let inner = block.inner(rect);
        frame.render_widget(block, rect);

        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
        let body = layout[0];
        let help_area = layout[1];

        self.last_content_rows = lines.len();
        self.last_body_height = body.height as usize;
        let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
        }

        frame.render_widget(Paragraph::new(lines).scroll((self.scroll as u16, 0)), body);

        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!("Esc/q/{LEADER_HINT} close  ↑/↓ scroll  g/G top/bottom"),
                muted,
            ))),
            help_area,
        );
    }

    /// The title suffix naming the active context (the context group's
    /// heading). Derived from `self.context` so the box title always matches
    /// the leading group even if the descriptor list changes.
    fn title(&self) -> &'static str {
        match self.context {
            KeyContext::Composer => "Composer",
            KeyContext::SlashMenu => "Slash menu",
            KeyContext::ModelPicker => "Model picker",
            KeyContext::Settings => "Settings",
            KeyContext::Sessions => "Sessions",
            KeyContext::Permissions => "Permissions",
            KeyContext::Resources => "Resources",
            KeyContext::QuickSettings => "Quick settings",
            KeyContext::Scratchpad => "Scratchpad",
            KeyContext::Diff => "Diff",
            KeyContext::Pins => "Pins",
            KeyContext::EmbeddedPane => "Embedded pane",
            KeyContext::BtwPane => "BTW pane",
            KeyContext::QuestionDialog => "Question",
            KeyContext::ApprovalDialog => "Approval",
        }
    }

    /// Assemble every body row as owned [`Line`]s — a heading per group then
    /// its key/action/desc rows. Pure (reads only `self.groups`), so the
    /// listing is unit-testable without a terminal.
    fn body_lines(&self) -> Vec<Line<'static>> {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let key_style = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);
        let action_style = Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD);

        // Column width for the key glyph — widest key across all groups,
        // capped so a stray long chord can't blow out the layout.
        let key_w = self
            .groups
            .iter()
            .flat_map(|g| g.bindings.iter())
            .map(|b| b.key.chars().count())
            .max()
            .unwrap_or(0)
            .clamp(1, 14);

        let mut out: Vec<Line<'static>> = Vec::new();
        for (gi, group) in self.groups.iter().enumerate() {
            if gi > 0 {
                out.push(Line::default());
            }
            out.push(Line::from(Span::styled(
                group.title.to_string(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));
            for b in &group.bindings {
                let pad = key_w.saturating_sub(b.key.chars().count());
                out.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(b.key.to_string(), key_style),
                    Span::raw(" ".repeat(pad + 2)),
                    Span::styled(format!("{:<14}", b.action), action_style),
                    Span::raw(" "),
                    Span::styled(b.desc.to_string(), muted),
                ]));
            }
        }
        out
    }

    /// The plain-text rendering of the overlay body — used by snapshot tests
    /// to assert which context's keys appear and in what order.
    #[cfg(test)]
    pub fn snapshot(&self) -> String {
        self.body_lines()
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
            .trim_end()
            .to_string()
    }
}

impl Pane for KeysOverlay {
    type Outcome = bool;

    fn handle_key(&mut self, key: KeyEvent) -> Self::Outcome {
        KeysOverlay::handle_key(self, key)
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        KeysOverlay::render(self, frame, area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    #[test]
    fn composer_context_lists_composer_then_global() {
        let overlay = KeysOverlay::open(KeyContext::Composer);
        let text = overlay.snapshot();
        let composer_at = text.find("Composer").expect("Composer heading present");
        let global_at = text.find("Global").expect("Global heading present");
        assert!(
            composer_at < global_at,
            "context group precedes Global:\n{text}"
        );
        assert!(text.contains("Shift+Tab"));
        assert!(text.contains("send"));
        assert!(text.contains("PgUp/PgDn"));
        assert!(text.contains("scroll"));
        assert!(text.contains("End"));
        assert!(text.contains("live tail"));
    }

    #[test]
    fn sessions_context_lists_sessions_first() {
        let overlay = KeysOverlay::open(KeyContext::Sessions);
        let text = overlay.snapshot();
        let sessions_at = text.find("Sessions").expect("Sessions heading present");
        let global_at = text.find("Global").expect("Global heading present");
        assert!(
            sessions_at < global_at,
            "Sessions group precedes Global:\n{text}"
        );
    }

    #[test]
    fn approval_context_lists_approval_first_and_decision_keys() {
        let overlay = KeysOverlay::open(KeyContext::ApprovalDialog);
        let text = overlay.snapshot();
        let approval_at = text.find("Approval").expect("Approval heading present");
        let global_at = text.find("Global").expect("Global heading present");
        assert!(approval_at < global_at, "Approval precedes Global:\n{text}");
        assert!(
            text.contains("1-9"),
            "approval shows numbered selection keys"
        );
        assert_eq!(
            dialog_which_key_bindings(true),
            groups_for(KeyContext::QuestionDialog)[0].bindings
        );
        assert_eq!(
            groups_for(KeyContext::ApprovalDialog)[0].bindings,
            groups_for(KeyContext::QuestionDialog)[0].bindings
        );
    }

    #[test]
    fn dialog_shift_page_keys_are_protocol_gated() {
        let off = KeysOverlay::open_with_keyboard_enhancement(KeyContext::QuestionDialog, false)
            .snapshot();
        assert!(!off.contains("Shift+PgUp/PgDn"));

        let on = KeysOverlay::open_with_keyboard_enhancement(KeyContext::QuestionDialog, true)
            .snapshot();
        assert!(on.contains("Shift+PgUp/PgDn"));
    }

    #[test]
    fn question_context_lists_question_first() {
        let overlay = KeysOverlay::open(KeyContext::QuestionDialog);
        let text = overlay.snapshot();
        let q_at = text.find("Question").expect("Question heading present");
        let global_at = text.find("Global").expect("Global heading present");
        assert!(q_at < global_at, "Question precedes Global:\n{text}");
    }

    #[test]
    fn every_context_resolves_to_two_groups_first_is_context() {
        // Each context yields exactly the context group then Global, and the
        // global group is always last (so global keys are discoverable
        // everywhere).
        for ctx in [
            KeyContext::Composer,
            KeyContext::SlashMenu,
            KeyContext::ModelPicker,
            KeyContext::Settings,
            KeyContext::Sessions,
            KeyContext::Permissions,
            KeyContext::Resources,
            KeyContext::QuickSettings,
            KeyContext::Scratchpad,
            KeyContext::Pins,
            KeyContext::EmbeddedPane,
            KeyContext::QuestionDialog,
            KeyContext::ApprovalDialog,
        ] {
            let groups = groups_for(ctx);
            assert_eq!(groups.len(), 2, "{ctx:?} → context group + global");
            assert_eq!(groups[1].title, "Global", "{ctx:?} ends with Global");
            assert_ne!(groups[0].title, "Global", "{ctx:?} leads with its context");
        }
    }

    #[test]
    fn esc_q_close_overlay() {
        let mut overlay = KeysOverlay::open(KeyContext::Composer);
        assert!(overlay.handle_key(press(KeyCode::Esc)));
        let mut overlay = KeysOverlay::open(KeyContext::Composer);
        assert!(overlay.handle_key(press(KeyCode::Char('q'))));
    }

    #[test]
    fn scroll_clamps_to_content_on_a_short_body() {
        // Simulate a narrow/tall-constrained terminal where the rows exceed
        // the body height: Down advances, capped at content - height; g/G
        // jump to the ends.
        let mut overlay = KeysOverlay::open(KeyContext::Composer);
        overlay.last_content_rows = 30;
        overlay.last_body_height = 4;
        for _ in 0..50 {
            overlay.handle_key(press(KeyCode::Down));
        }
        assert_eq!(overlay.scroll, 26, "scroll caps at content - body height");
        overlay.handle_key(press(KeyCode::Char('g')));
        assert_eq!(overlay.scroll, 0, "g jumps to top");
        overlay.handle_key(press(KeyCode::Char('G')));
        assert_eq!(overlay.scroll, 26, "G jumps to bottom");

        // With a body taller than the content, the floor pins at zero.
        overlay.last_content_rows = 3;
        overlay.last_body_height = 100;
        overlay.scroll = 0;
        overlay.handle_key(press(KeyCode::Down));
        assert_eq!(overlay.scroll, 0, "can't scroll past the content floor");
    }

    #[test]
    fn open_captures_the_context() {
        let overlay = KeysOverlay::open(KeyContext::Sessions);
        assert_eq!(overlay.context(), KeyContext::Sessions);
        assert_eq!(overlay.title(), "Sessions");
    }

    // ---- render-path snapshot tests (real ratatui buffer) ------------------

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    /// Render `overlay` into a `body` sub-region of a `w`×`h` terminal and
    /// return the full frame as newline-joined rows of cell symbols. The
    /// region narrower than the full frame mirrors how the app renders the
    /// overlay into `rects.body` (chrome lives outside that rect).
    fn render_in_body(overlay: &mut KeysOverlay, w: u16, h: u16, body: Rect) -> String {
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| overlay.render(f, body)).unwrap();
        let buf = terminal.backend().buffer().clone();
        (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Render `overlay` into a full `w`×`h` body buffer (no surrounding chrome).
    fn render_to_string(overlay: &mut KeysOverlay, w: u16, h: u16) -> String {
        render_in_body(overlay, w, h, Rect::new(0, 0, w, h))
    }

    #[test]
    fn render_main_chat_shows_composer_then_global() {
        let mut overlay = KeysOverlay::open(KeyContext::Composer);
        let text = render_to_string(&mut overlay, 70, 24);
        assert!(
            text.contains("keybindings — Composer"),
            "titled box:\n{text}"
        );
        assert!(text.contains("Composer"));
        assert!(text.contains("Global"));
        assert!(text.contains("Shift+Tab"));
        assert!(text.contains(LEADER_HINT), "help row names the leader");
    }

    #[test]
    fn render_sessions_shows_sessions_context() {
        let mut overlay = KeysOverlay::open(KeyContext::Sessions);
        let text = render_to_string(&mut overlay, 70, 24);
        assert!(
            text.contains("keybindings — Sessions"),
            "titled box:\n{text}"
        );
        assert!(text.contains("resume"), "sessions action present");
    }

    #[test]
    fn render_approval_dialog_shows_decision_keys() {
        let mut overlay = KeysOverlay::open(KeyContext::ApprovalDialog);
        let text = render_to_string(&mut overlay, 70, 24);
        assert!(
            text.contains("keybindings — Approval"),
            "titled box:\n{text}"
        );
        assert!(text.contains("1-9"), "approval decision keys present");
    }

    #[test]
    fn render_tiny_body_stays_inside_area() {
        let mut overlay = KeysOverlay::open(KeyContext::Composer);
        let text = render_in_body(&mut overlay, 8, 3, Rect::new(2, 1, 3, 1));
        let rows: Vec<&str> = text.lines().collect();

        assert!(rows[0].trim().is_empty(), "above body changed:\n{text}");
        assert!(rows[2].trim().is_empty(), "below body changed:\n{text}");
        assert_eq!(overlay.last_body_height, 0);
    }

    #[test]
    fn render_never_covers_chrome_outside_the_body_and_scrolls() {
        // Mimic the app layout on a narrow/tall-constrained terminal: a 1-row
        // header at the top, a 1-row status line at the bottom, and the overlay
        // confined to the body region between them. The overlay renders into
        // the body only, so the chrome rows above/below stay untouched even
        // when the rows overflow the short body — proof it never permanently
        // covers fixed chrome.
        let w = 40;
        let h = 8;
        // Body is rows 1..=6 (header row 0, status row 7).
        let body = Rect::new(0, 1, w, 6);
        let mut overlay = KeysOverlay::open(KeyContext::Composer);
        let text = render_in_body(&mut overlay, w, h, body);
        let rows: Vec<&str> = text.lines().collect();
        assert!(
            rows[0].trim().is_empty(),
            "header row (above body) untouched:\n{text}"
        );
        assert!(
            rows[(h - 1) as usize].trim().is_empty(),
            "status row (below body) untouched:\n{text}"
        );
        assert!(text.contains("keybindings — Composer"), "box drawn in body");

        // The content overflows the short body, so it scrolls: scrolling down
        // changes the visible rows.
        overlay.scroll_down();
        overlay.scroll_down();
        let scrolled = render_in_body(&mut overlay, w, h, body);
        assert_ne!(text, scrolled, "scrolling changes the visible rows");
    }
}
