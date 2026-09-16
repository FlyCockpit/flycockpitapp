//! First-run secret-encryption step, shown *before* the provider picker.
//!
//! Cockpit encrypts every stored API key and sealed value under a wrapping
//! key (the KEK). Where that KEK lives is the one decision only the human can
//! make, so onboarding asks it up front. The three choices mirror
//! `cockpit_core::secure_key::FirstRunSecretStoreIntent`:
//!
//! | this screen        | flycockpitapp intent                    |
//! |--------------------|-----------------------------------------|
//! | Use the OS keyring | `FirstRunSecretStoreIntent::Keyring`    |
//! | Use a password     | `FirstRunSecretStoreIntent::FilePassphrase` (Argon2id KEK) |
//! | Don't encrypt      | *(no product analog — Cockpit always wraps)* |
//!
//! The keyring row is greyed out and unselectable when the platform keyring
//! cannot hold a wrapping key, matching `probe_platform_keyring`. "Use a
//! password" is the default: choosing it drops into a masked entry where the
//! password derives the KEK. In the product that password is held by the
//! daemon for the session; here we simply hand it back to the caller.

use std::io::Stdout;

use anyhow::Result;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Margin, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Padding, Paragraph, Wrap};

use super::chrome;

/// Warm instrument-panel palette, shared in spirit with [`super::form`].
const INK: Color = Color::Rgb(0xF4, 0xEF, 0xE6);
const FOG: Color = Color::Rgb(0x8A, 0x9B, 0xB0);
const BRASS: Color = Color::Rgb(0xE0, 0xB1, 0x56);
const NIGHT: Color = Color::Rgb(0x4A, 0x5A, 0x6A);
const PLACEHOLDER: Color = Color::Rgb(0x6A, 0x7A, 0x8A);
/// Disabled rows sink toward the background so they read as unavailable.
const DISABLED: Color = Color::Rgb(0x55, 0x62, 0x70);
const WARN: Color = Color::Rgb(0xD8, 0x8A, 0x5A);
const HOVER_BG: Color = Color::Rgb(0x2C, 0x38, 0x46);

const SELECTED_MARK: &str = "◉ ";
const UNSELECTED_MARK: &str = "○ ";
const MASK: char = '•';

/// The onboarding secret-encryption decision handed back to the caller.
///
/// `Password` carries the plaintext the user typed. A real daemon would keep
/// it in locked memory for the session and derive the KEK with Argon2id (see
/// `PassphraseKekStore`); this reference just returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Encryption {
    /// KEK stored as one item in the OS keyring.
    Keyring,
    /// KEK derived from a password kept by the daemon at startup.
    Password(String),
    /// Secrets stored in the clear. No product analog — always the weakest.
    None,
}

impl Encryption {
    /// One-line summary for the caller to echo after onboarding.
    pub fn summary(&self) -> String {
        match self {
            Encryption::Keyring => "OS keyring".to_string(),
            Encryption::Password(pw) => format!("password ({} chars)", pw.chars().count()),
            Encryption::None => "not encrypted".to_string(),
        }
    }
}

/// The three placements, in the order onboarding offers them.
const MODES: [Mode; 3] = [Mode::Keyring, Mode::Password, Mode::None];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Keyring,
    Password,
    None,
}

impl Mode {
    fn title(self) -> &'static str {
        match self {
            Mode::Keyring => "Use the OS keyring",
            Mode::Password => "Use a password",
            Mode::None => "Don't encrypt",
        }
    }

    /// Short line shown next to the title in the option row. `recommended`
    /// depends on host capabilities (see [`Wizard::recommended_mode`]).
    fn tagline(self, recommended: bool) -> &'static str {
        match self {
            _ if recommended => "recommended",
            Mode::Keyring => "hardware-backed, no prompt",
            Mode::Password => "works without a keyring",
            Mode::None => "not recommended",
        }
    }

    /// Longer copy for the detail pane below the list.
    fn detail(self) -> &'static str {
        match self {
            Mode::Keyring => {
                "Your wrapping key lives in the platform keyring (macOS Keychain, Windows Credential Manager, or a Linux Secret Service). Cockpit unlocks secrets without ever prompting you."
            }
            Mode::Password => {
                "You choose a password now. Cockpit derives the wrapping key from it with Argon2id and the daemon holds it for the session, so secrets stay encrypted at rest even without an OS keyring."
            }
            Mode::None => {
                "API keys and sealed values are written to disk in the clear. Anyone who can read the Cockpit data directory can read your secrets. Only sensible on a throwaway machine."
            }
        }
    }
}

/// Whether the platform keyring can hold a wrapping key.
///
/// Mirrors the daemon's `probe_platform_keyring`: on Linux a Secret Service
/// needs a session bus, elsewhere the native store is assumed present. Set
/// `EXCOC_NO_KEYRING` to demo the greyed-out row on any platform.
pub fn keyring_available() -> bool {
    if std::env::var_os("EXCOC_NO_KEYRING").is_some() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some()
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        true
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        false
    }
}

/// Run the secrets step. `resume` preselects a prior choice when the user
/// steps back into this screen from a later wizard step.
pub(super) fn run(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    resume: Option<Encryption>,
) -> Result<Option<Encryption>> {
    execute!(terminal.backend_mut(), EnableMouseCapture)?;
    let result = run_loop(terminal, resume);
    let _ = execute!(terminal.backend_mut(), DisableMouseCapture);
    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    resume: Option<Encryption>,
) -> Result<Option<Encryption>> {
    let mut wizard = Wizard::new_with(keyring_available(), resume);
    loop {
        terminal.draw(|frame| wizard.render(frame, frame.area()))?;
        match event::read()? {
            Event::Key(key) if key.is_press() || key.kind == KeyEventKind::Repeat => {
                match wizard.handle_key(key) {
                    Action::Continue => {}
                    Action::Quit => return Ok(None),
                    Action::Done(choice) => return Ok(Some(choice)),
                }
            }
            Event::Mouse(mouse) => match wizard.handle_mouse(mouse) {
                Action::Continue => {}
                Action::Quit => return Ok(None),
                Action::Done(choice) => return Ok(Some(choice)),
            },
            Event::Paste(text) => wizard.paste(&text),
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    Continue,
    Quit,
    Done(Encryption),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Choose,
    Password,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PwFocus {
    Password,
    Confirm,
}

/// A masked, single-line text field. A trimmed sibling of
/// [`super::form`]'s search field: no scrolling niceties, just enough to type
/// a password and move the caret.
#[derive(Default)]
struct PasswordField {
    buffer: String,
    /// Byte index into [`Self::buffer`]; always on a char boundary.
    cursor: usize,
}

impl PasswordField {
    fn text(&self) -> &str {
        &self.buffer
    }

    fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    fn len_chars(&self) -> usize {
        self.buffer.chars().count()
    }

    fn cursor_col(&self) -> usize {
        self.buffer[..self.cursor].chars().count()
    }

    fn insert(&mut self, ch: char) {
        self.buffer.insert(self.cursor, ch);
        self.cursor += ch.len_utf8();
    }

    fn paste(&mut self, text: &str) {
        let first_line = text.split(['\n', '\r']).next().unwrap_or("");
        if first_line.is_empty() {
            return;
        }
        self.buffer.insert_str(self.cursor, first_line);
        self.cursor += first_line.len();
    }

    fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let prev = self.buffer[..self.cursor]
            .char_indices()
            .next_back()
            .map(|(i, _)| i)
            .unwrap_or(0);
        self.buffer.drain(prev..self.cursor);
        self.cursor = prev;
    }

    fn delete(&mut self) {
        if self.cursor >= self.buffer.len() {
            return;
        }
        let len = self.buffer[self.cursor..]
            .chars()
            .next()
            .map(char::len_utf8)
            .unwrap_or(0);
        self.buffer.drain(self.cursor..self.cursor + len);
    }

    fn left(&mut self) {
        if let Some((i, _)) = self.buffer[..self.cursor].char_indices().next_back() {
            self.cursor = i;
        }
    }

    fn right(&mut self) {
        if let Some(ch) = self.buffer[self.cursor..].chars().next() {
            self.cursor += ch.len_utf8();
        }
    }

    fn home(&mut self) {
        self.cursor = 0;
    }

    fn end(&mut self) {
        self.cursor = self.buffer.len();
    }

    fn clear(&mut self) {
        self.buffer.clear();
        self.cursor = 0;
    }

    /// Replace the contents and park the caret at the end.
    fn set(&mut self, text: &str) {
        self.buffer = text.to_string();
        self.cursor = self.buffer.len();
    }

    /// Returns true when the edit changed the buffer (so callers can clear a
    /// stale error).
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.clear();
                true
            }
            KeyCode::Char(ch)
                if key.modifiers.intersects(
                    KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER,
                ) =>
            {
                let _ = ch;
                false
            }
            KeyCode::Char(ch) => {
                self.insert(ch);
                true
            }
            KeyCode::Backspace => {
                self.backspace();
                true
            }
            KeyCode::Delete => {
                self.delete();
                true
            }
            KeyCode::Left => {
                self.left();
                false
            }
            KeyCode::Right => {
                self.right();
                false
            }
            KeyCode::Home => {
                self.home();
                false
            }
            KeyCode::End => {
                self.end();
                false
            }
            _ => false,
        }
    }
}

struct Wizard {
    keyring_available: bool,
    phase: Phase,
    /// Index into [`MODES`].
    selected: usize,
    hover: Option<usize>,
    /// Option rows from the last draw, for hit-testing.
    option_rows: Vec<Rect>,
    password: PasswordField,
    confirm: PasswordField,
    focus: PwFocus,
    reveal: bool,
    error: Option<String>,
    /// Back button rect from the last draw (only on the password sub-step),
    /// and whether the pointer is over it.
    back_rect: Rect,
    back_hover: bool,
    actions: chrome::ActionBar,
    /// Password / confirm field rects, for click-to-focus on the password step.
    pw_rect: Rect,
    confirm_rect: Rect,
}

impl Wizard {
    fn new(keyring_available: bool) -> Self {
        let recommended = Self::recommended_mode(keyring_available);
        let mut wizard = Self {
            keyring_available,
            phase: Phase::Choose,
            // Start on the recommended row.
            selected: mode_index(recommended),
            hover: None,
            option_rows: Vec::new(),
            password: PasswordField::default(),
            confirm: PasswordField::default(),
            focus: PwFocus::Password,
            reveal: false,
            error: None,
            back_rect: Rect::default(),
            back_hover: false,
            actions: chrome::ActionBar::default(),
            pw_rect: Rect::default(),
            confirm_rect: Rect::default(),
        };
        // The recommended row is always selectable, but stay defensive.
        if !wizard.selectable(MODES[wizard.selected]) {
            wizard.move_by(1);
        }
        wizard
    }

    /// Build a wizard with a previous choice preselected, used when the user
    /// steps back into this screen. A prior password is preserved so returning
    /// forward does not force a retype; a keyring choice that is no longer
    /// available falls back to the current recommendation.
    fn new_with(keyring_available: bool, resume: Option<Encryption>) -> Self {
        let mut wizard = Self::new(keyring_available);
        match resume {
            Some(Encryption::Keyring) if keyring_available => {
                wizard.selected = mode_index(Mode::Keyring);
            }
            Some(Encryption::Keyring) | None => {}
            Some(Encryption::None) => wizard.selected = mode_index(Mode::None),
            Some(Encryption::Password(pw)) => {
                wizard.selected = mode_index(Mode::Password);
                wizard.password.set(&pw);
                wizard.confirm.set(&pw);
            }
        }
        wizard
    }

    /// The keyring is best when the platform can hold the wrapping key;
    /// otherwise a password keeps secrets encrypted at rest.
    fn recommended_mode(keyring_available: bool) -> Mode {
        if keyring_available {
            Mode::Keyring
        } else {
            Mode::Password
        }
    }

    fn is_recommended(&self, mode: Mode) -> bool {
        mode == Self::recommended_mode(self.keyring_available)
    }

    fn selectable(&self, mode: Mode) -> bool {
        match mode {
            Mode::Keyring => self.keyring_available,
            Mode::Password | Mode::None => true,
        }
    }

    fn selected_mode(&self) -> Mode {
        MODES[self.selected]
    }

    fn move_by(&mut self, delta: isize) {
        let n = MODES.len() as isize;
        let mut idx = self.selected as isize;
        for _ in 0..MODES.len() {
            idx = (idx + delta).rem_euclid(n);
            if self.selectable(MODES[idx as usize]) {
                self.selected = idx as usize;
                return;
            }
        }
    }

    fn paste(&mut self, text: &str) {
        if self.phase == Phase::Password {
            self.active_field().paste(text);
            self.error = None;
        }
    }

    fn active_field(&mut self) -> &mut PasswordField {
        match self.focus {
            PwFocus::Password => &mut self.password,
            PwFocus::Confirm => &mut self.confirm,
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> Action {
        let ctrl_c = key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'));
        if ctrl_c {
            return Action::Quit;
        }
        match self.phase {
            Phase::Choose => self.handle_choose_key(key),
            Phase::Password => self.handle_password_key(key),
        }
    }

    fn handle_choose_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Esc => Action::Quit,
            KeyCode::Up | KeyCode::BackTab => {
                self.move_by(-1);
                Action::Continue
            }
            KeyCode::Down | KeyCode::Tab => {
                self.move_by(1);
                Action::Continue
            }
            KeyCode::Char('k') => {
                self.move_by(-1);
                Action::Continue
            }
            KeyCode::Char('j') => {
                self.move_by(1);
                Action::Continue
            }
            KeyCode::Enter | KeyCode::Char(' ') => self.activate_selected(),
            _ => Action::Continue,
        }
    }

    fn activate_selected(&mut self) -> Action {
        match self.selected_mode() {
            Mode::Keyring if self.keyring_available => Action::Done(Encryption::Keyring),
            // A disabled keyring row does nothing.
            Mode::Keyring => Action::Continue,
            Mode::None => Action::Done(Encryption::None),
            Mode::Password => {
                self.phase = Phase::Password;
                self.focus = PwFocus::Password;
                self.error = None;
                Action::Continue
            }
        }
    }

    fn handle_password_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Esc => self.return_to_choose(),
            KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.reveal = !self.reveal;
                Action::Continue
            }
            KeyCode::Tab | KeyCode::Down => {
                self.focus = PwFocus::Confirm;
                Action::Continue
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.focus = PwFocus::Password;
                Action::Continue
            }
            KeyCode::Enter => self.submit_password(),
            _ => {
                if self.active_field().handle_key(key) {
                    self.error = None;
                }
                Action::Continue
            }
        }
    }

    /// Return from the password sub-step to the choice list, forgetting the
    /// half-typed password.
    fn return_to_choose(&mut self) -> Action {
        self.phase = Phase::Choose;
        self.password.clear();
        self.confirm.clear();
        self.reveal = false;
        self.error = None;
        self.back_hover = false;
        Action::Continue
    }

    fn submit_password(&mut self) -> Action {
        if self.password.is_empty() {
            self.error = Some("Enter a password.".to_string());
            self.focus = PwFocus::Password;
            return Action::Continue;
        }
        if self.password.text() != self.confirm.text() {
            self.error = Some("Passwords don't match.".to_string());
            self.focus = PwFocus::Confirm;
            return Action::Continue;
        }
        Action::Done(Encryption::Password(self.password.text().to_string()))
    }

    fn handle_mouse(&mut self, event: MouseEvent) -> Action {
        let pos = Position::new(event.column, event.row);
        if matches!(event.kind, MouseEventKind::Moved | MouseEventKind::Drag(_)) {
            self.actions.track(pos);
        }
        if self.phase == Phase::Password {
            self.back_hover = chrome::hit(self.back_rect, pos);
            if matches!(event.kind, MouseEventKind::Down(MouseButton::Left)) {
                if chrome::hit(self.back_rect, pos) {
                    return self.return_to_choose();
                }
                match self.actions.clicked(pos) {
                    // [ Reveal ] toggles masking; [ Save ] submits.
                    Some(0) => {
                        self.reveal = !self.reveal;
                        return Action::Continue;
                    }
                    Some(_) => return self.submit_password(),
                    None => {}
                }
                if chrome::hit(self.pw_rect, pos) {
                    self.focus = PwFocus::Password;
                } else if chrome::hit(self.confirm_rect, pos) {
                    self.focus = PwFocus::Confirm;
                }
            }
            return Action::Continue;
        }
        match event.kind {
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                self.hover = self.option_at(pos);
                Action::Continue
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if self.actions.clicked(pos).is_some() {
                    return self.activate_selected();
                }
                if let Some(index) = self.option_at(pos)
                    && self.selectable(MODES[index])
                {
                    if self.selected == index {
                        // A second click on the live row activates it.
                        return self.activate_selected();
                    }
                    self.selected = index;
                }
                Action::Continue
            }
            _ => Action::Continue,
        }
    }

    fn option_at(&self, pos: Position) -> Option<usize> {
        self.option_rows.iter().position(|row| row.contains(pos))
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        frame.render_widget(Clear, area);
        // The choice list is the first onboarding step, so it has no back
        // target; the password sub-step draws a back button to the list.
        self.back_rect =
            chrome::render_back_button(frame, area, self.phase == Phase::Password, self.back_hover);
        let col = column(area);
        match self.phase {
            Phase::Choose => self.render_choose(frame, col),
            Phase::Password => self.render_password(frame, col),
        }
    }

    fn render_choose(&mut self, frame: &mut Frame, area: Rect) {
        let layout = Layout::vertical([
            Constraint::Length(3), // header
            Constraint::Length(1), // spacer
            Constraint::Length(3), // options (one row each)
            Constraint::Length(1), // spacer
            Constraint::Min(4),    // detail
            Constraint::Length(1), // help
        ]);
        let [header, _, options, _, detail, help] = area.layout(&layout);

        render_header(
            frame,
            header,
            "Secure your secrets",
            "Choose how Cockpit protects your API keys and sealed values.",
        );
        self.render_options(frame, options);
        self.render_detail(frame, detail);
        render_help(
            frame,
            help,
            "↑↓ move   click choose   enter choose   esc quit",
        );
        self.actions
            .render(frame, help, &[chrome::Button::primary("Continue")]);
    }

    fn render_options(&mut self, frame: &mut Frame, area: Rect) {
        self.option_rows.clear();
        let rows = Layout::vertical([Constraint::Length(1); 3]).split(area);
        for (index, (&mode, &row)) in MODES.iter().zip(rows.iter()).enumerate() {
            self.option_rows.push(row);
            let enabled = self.selectable(mode);
            let selected = self.selected == index;
            let hovered = self.hover == Some(index) && enabled;
            let recommended = enabled && self.is_recommended(mode);
            frame.render_widget(
                option_line(mode, enabled, selected, hovered, recommended),
                row,
            );
        }
    }

    fn render_detail(&self, frame: &mut Frame, area: Rect) {
        let mode = self.selected_mode();
        let mut lines = vec![Line::from(Span::styled(
            mode.detail(),
            Style::new().fg(FOG),
        ))];

        match mode {
            Mode::Keyring if !self.keyring_available => {
                lines.push(Line::raw(""));
                lines.push(Line::from(Span::styled(
                    "Unavailable: no platform keyring is reachable on this host.",
                    Style::new().fg(WARN),
                )));
                lines.push(Line::from(Span::styled(
                    "Fix: install/unlock a Secret Service (Linux), Keychain (macOS), or Credential Manager (Windows).",
                    Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
                )));
            }
            Mode::None => {
                lines.push(Line::raw(""));
                lines.push(Line::from(Span::styled(
                    "Warning: secrets are stored unencrypted.",
                    Style::new().fg(WARN).add_modifier(Modifier::BOLD),
                )));
            }
            _ => {}
        }

        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn render_password(&mut self, frame: &mut Frame, area: Rect) {
        let layout = Layout::vertical([
            Constraint::Length(3), // header
            Constraint::Length(1), // spacer
            Constraint::Length(3), // password
            Constraint::Length(3), // confirm
            Constraint::Length(2), // error / hint
            Constraint::Min(0),    // filler
            Constraint::Length(1), // help
        ]);
        let [header, _, password, confirm, note, _, help] = area.layout(&layout);
        self.pw_rect = password;
        self.confirm_rect = confirm;

        render_header(
            frame,
            header,
            "Set an encryption password",
            "Cockpit derives your wrapping key from this password (Argon2id).",
        );

        let pw_cursor = self.render_field(
            frame,
            password,
            "Password",
            &self.password,
            self.focus == PwFocus::Password,
        );
        let confirm_cursor = self.render_field(
            frame,
            confirm,
            "Confirm",
            &self.confirm,
            self.focus == PwFocus::Confirm,
        );

        if let Some(error) = &self.error {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    error.clone(),
                    Style::new().fg(WARN).add_modifier(Modifier::BOLD),
                ))),
                note,
            );
        } else {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "This password isn't recoverable — losing it means re-adding every secret.",
                    Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
                )))
                .wrap(Wrap { trim: true }),
                note,
            );
        }

        render_help(
            frame,
            help,
            "type password   tab switch   ctrl-r reveal   enter save   esc back",
        );
        self.actions.render(
            frame,
            help,
            &[
                chrome::Button::secondary("Reveal"),
                chrome::Button::primary("Save"),
            ],
        );

        // Park the terminal cursor in the focused field.
        if let Some(pos) = match self.focus {
            PwFocus::Password => pw_cursor,
            PwFocus::Confirm => confirm_cursor,
        } {
            frame.set_cursor_position(pos);
        }
    }

    /// Draws one masked field and returns where the caret would sit, so the
    /// caller can place the real terminal cursor only for the focused field.
    fn render_field(
        &self,
        frame: &mut Frame,
        area: Rect,
        title: &str,
        field: &PasswordField,
        focused: bool,
    ) -> Option<Position> {
        let border = if focused { BRASS } else { NIGHT };
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(border))
            .title(Span::styled(format!(" {title} "), Style::new().fg(border)))
            .padding(Padding::horizontal(1));
        let inner = block.inner(area);
        frame.render_widget(&block, area);

        let count = field.len_chars();
        let mut spans = Vec::new();
        if field.is_empty() {
            spans.push(Span::styled(
                "enter a password",
                Style::new().fg(PLACEHOLDER).add_modifier(Modifier::ITALIC),
            ));
        } else if self.reveal {
            spans.push(Span::styled(field.text().to_string(), Style::new().fg(INK)));
        } else {
            spans.push(Span::styled(
                MASK.to_string().repeat(count),
                Style::new().fg(INK),
            ));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), inner);

        if !focused || inner.width == 0 || inner.height == 0 {
            return None;
        }
        let col = field
            .cursor_col()
            .min(usize::from(inner.width.saturating_sub(1)));
        Some(Position::new(inner.x + col as u16, inner.y))
    }
}

fn mode_index(mode: Mode) -> usize {
    MODES.iter().position(|m| *m == mode).unwrap_or(0)
}

fn option_line(
    mode: Mode,
    enabled: bool,
    selected: bool,
    hovered: bool,
    recommended: bool,
) -> Paragraph<'static> {
    let mark = if selected {
        SELECTED_MARK
    } else {
        UNSELECTED_MARK
    };
    let (mark_style, title_style, mut tag_style) = if !enabled {
        (
            Style::new().fg(DISABLED),
            Style::new().fg(DISABLED),
            Style::new().fg(DISABLED).add_modifier(Modifier::ITALIC),
        )
    } else if selected {
        (
            Style::new().fg(BRASS),
            Style::new().fg(BRASS).add_modifier(Modifier::BOLD),
            Style::new().fg(FOG),
        )
    } else {
        (
            Style::new().fg(FOG),
            Style::new().fg(INK),
            Style::new().fg(FOG),
        )
    };

    // Keep the "recommended" tag legible even when the row isn't selected.
    if recommended {
        tag_style = Style::new().fg(BRASS).add_modifier(Modifier::BOLD);
    }

    let tag = if !enabled {
        "unavailable".to_string()
    } else {
        mode.tagline(recommended).to_string()
    };

    let mut line = Line::from(vec![
        Span::styled(mark, mark_style),
        Span::styled(mode.title(), title_style),
        Span::styled("  —  ", Style::new().fg(NIGHT)),
        Span::styled(tag, tag_style),
    ]);
    if hovered {
        line = line.style(Style::new().bg(HOVER_BG));
    }
    Paragraph::new(line)
}

fn render_header(frame: &mut Frame, area: Rect, title: &str, subtitle: &str) {
    let rule = "─".repeat(28.min(usize::from(area.width)));
    let lines = vec![
        Line::from(Span::styled(
            title.to_string(),
            Style::new().fg(INK).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(subtitle.to_string(), Style::new().fg(FOG))),
        Line::from(Span::styled(rule, Style::new().fg(BRASS))),
    ];
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_help(frame: &mut Frame, area: Rect, text: &str) {
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            text.to_string(),
            Style::new().fg(FOG),
        ))),
        area,
    );
}

/// Centre a readable column, matching [`super::form`].
fn column(area: Rect) -> Rect {
    area.inner(Margin::new(2, 1))
        .centered(Constraint::Max(86), Constraint::Fill(1))
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::layout::Position;

    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    fn ctrl(ch: char) -> KeyEvent {
        let mut key = KeyEvent::from(KeyCode::Char(ch));
        key.modifiers = KeyModifiers::CONTROL;
        key
    }

    fn mouse(kind: MouseEventKind, pos: Position) -> MouseEvent {
        MouseEvent {
            kind,
            column: pos.x,
            row: pos.y,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn type_text(wizard: &mut Wizard, text: &str) {
        for ch in text.chars() {
            wizard.handle_key(key(KeyCode::Char(ch)));
        }
    }

    fn find(backend: &TestBackend, needle: &str) -> Position {
        let buf = backend.buffer();
        for y in 0..buf.area.height {
            let row: String = (0..buf.area.width)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect();
            if let Some(col) = row.find(needle) {
                return Position::new(col as u16, y);
            }
        }
        panic!("{needle:?} not found on screen");
    }

    fn draw(wizard: &mut Wizard, width: u16, height: u16) -> (TestBackend, Position, bool) {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| wizard.render(frame, frame.area()))
            .unwrap();
        let pos = terminal.get_cursor_position().unwrap();
        let visible = terminal.backend().cursor_visible();
        (terminal.backend().clone(), pos, visible)
    }

    fn screen(backend: &TestBackend) -> String {
        let buf = backend.buffer();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn keyring_is_default_and_recommended_when_available() {
        let wizard = Wizard::new(true);
        assert_eq!(wizard.selected_mode(), Mode::Keyring);
        assert!(wizard.is_recommended(Mode::Keyring));
        assert!(!wizard.is_recommended(Mode::Password));
    }

    #[test]
    fn password_is_default_and_recommended_when_keyring_unavailable() {
        let wizard = Wizard::new(false);
        assert_eq!(wizard.selected_mode(), Mode::Password);
        assert!(wizard.is_recommended(Mode::Password));
        assert!(!wizard.is_recommended(Mode::Keyring));
    }

    #[test]
    fn arrows_skip_the_disabled_keyring_row() {
        let mut wizard = Wizard::new(false);
        // Default lands on Password since keyring is unavailable.
        assert_eq!(wizard.selected_mode(), Mode::Password);
        wizard.handle_key(key(KeyCode::Up));
        assert_eq!(
            wizard.selected_mode(),
            Mode::None,
            "up from Password must skip the disabled keyring and wrap to None"
        );
        wizard.handle_key(key(KeyCode::Down));
        assert_eq!(wizard.selected_mode(), Mode::Password);
    }

    #[test]
    fn arrows_reach_the_keyring_row_when_available() {
        let mut wizard = Wizard::new(true);
        wizard.handle_key(key(KeyCode::Down));
        assert_eq!(wizard.selected_mode(), Mode::Password);
        wizard.handle_key(key(KeyCode::Up));
        assert_eq!(wizard.selected_mode(), Mode::Keyring);
    }

    #[test]
    fn choosing_keyring_returns_keyring() {
        let mut wizard = Wizard::new(true);
        // Keyring is the default when available.
        assert_eq!(wizard.selected_mode(), Mode::Keyring);
        assert_eq!(
            wizard.handle_key(key(KeyCode::Enter)),
            Action::Done(Encryption::Keyring)
        );
    }

    #[test]
    fn recommended_label_follows_keyring_availability() {
        let mut with = Wizard::new(true);
        let (backend, _, _) = draw(&mut with, 80, 24);
        let keyring_row = with.option_rows[0];
        let password_row = with.option_rows[1];
        let line = |backend: &TestBackend, row: Rect| {
            (row.x..row.right())
                .map(|x| backend.buffer()[(x, row.y)].symbol().to_string())
                .collect::<String>()
        };
        assert!(
            line(&backend, keyring_row).contains("recommended"),
            "keyring should be recommended when available"
        );
        assert!(!line(&backend, password_row).contains("recommended"));

        let mut without = Wizard::new(false);
        let (backend, _, _) = draw(&mut without, 80, 24);
        assert!(
            line(&backend, without.option_rows[1]).contains("recommended"),
            "password should be recommended when the keyring is unavailable"
        );
    }

    #[test]
    fn disabled_keyring_cannot_be_activated_by_enter() {
        // Even if selection somehow points at keyring while unavailable.
        let mut wizard = Wizard::new(false);
        wizard.selected = MODES.iter().position(|m| *m == Mode::Keyring).unwrap();
        assert_eq!(wizard.activate_selected(), Action::Continue);
    }

    #[test]
    fn choosing_dont_encrypt_returns_none() {
        let mut wizard = Wizard::new(true);
        wizard.handle_key(key(KeyCode::Down)); // keyring -> password
        wizard.handle_key(key(KeyCode::Down)); // password -> none
        assert_eq!(wizard.selected_mode(), Mode::None);
        assert_eq!(
            wizard.handle_key(key(KeyCode::Enter)),
            Action::Done(Encryption::None)
        );
    }

    #[test]
    fn password_flow_enters_masks_and_confirms() {
        // Keyring unavailable => password is the default row.
        let mut wizard = Wizard::new(false);
        assert_eq!(wizard.handle_key(key(KeyCode::Enter)), Action::Continue);
        assert_eq!(wizard.phase, Phase::Password);
        type_text(&mut wizard, "hunter2");
        // Empty confirm -> mismatch, not accepted.
        assert_eq!(wizard.handle_key(key(KeyCode::Enter)), Action::Continue);
        assert!(wizard.error.is_some());
        assert_eq!(wizard.focus, PwFocus::Confirm);
        type_text(&mut wizard, "hunter2");
        assert_eq!(
            wizard.handle_key(key(KeyCode::Enter)),
            Action::Done(Encryption::Password("hunter2".to_string()))
        );
    }

    #[test]
    fn empty_password_is_rejected() {
        let mut wizard = Wizard::new(false);
        wizard.handle_key(key(KeyCode::Enter));
        assert_eq!(wizard.handle_key(key(KeyCode::Enter)), Action::Continue);
        assert_eq!(wizard.error.as_deref(), Some("Enter a password."));
    }

    #[test]
    fn esc_from_password_returns_to_choice_and_clears() {
        let mut wizard = Wizard::new(false);
        wizard.handle_key(key(KeyCode::Enter));
        type_text(&mut wizard, "secret");
        wizard.handle_key(key(KeyCode::Esc));
        assert_eq!(wizard.phase, Phase::Choose);
        assert!(wizard.password.is_empty());
    }

    #[test]
    fn esc_from_choice_quits() {
        let mut wizard = Wizard::new(true);
        assert_eq!(wizard.handle_key(key(KeyCode::Esc)), Action::Quit);
    }

    #[test]
    fn ctrl_c_quits_from_either_phase() {
        let mut wizard = Wizard::new(false);
        assert_eq!(wizard.handle_key(ctrl('c')), Action::Quit);
        wizard.handle_key(key(KeyCode::Enter));
        assert_eq!(wizard.phase, Phase::Password);
        assert_eq!(wizard.handle_key(ctrl('c')), Action::Quit);
    }

    #[test]
    fn ctrl_r_toggles_reveal() {
        let mut wizard = Wizard::new(false);
        wizard.handle_key(key(KeyCode::Enter));
        assert!(!wizard.reveal);
        wizard.handle_key(ctrl('r'));
        assert!(wizard.reveal);
    }

    #[test]
    fn choose_screen_shows_all_three_options() {
        let mut wizard = Wizard::new(true);
        let (backend, _, _) = draw(&mut wizard, 80, 24);
        let text = screen(&backend);
        assert!(text.contains("Secure your secrets"), "{text}");
        assert!(text.contains("Use the OS keyring"), "{text}");
        assert!(text.contains("Use a password"), "{text}");
        assert!(text.contains("Don't encrypt"), "{text}");
    }

    #[test]
    fn unavailable_keyring_row_reads_as_unavailable() {
        let mut wizard = Wizard::new(false);
        let (backend, _, _) = draw(&mut wizard, 80, 24);
        let text = screen(&backend);
        assert!(text.contains("unavailable"), "{text}");
    }

    #[test]
    fn disabled_keyring_row_is_greyed() {
        let mut wizard = Wizard::new(false);
        let (backend, _, _) = draw(&mut wizard, 80, 24);
        let row = wizard.option_rows[0];
        let cell = &backend.buffer()[(row.x, row.y)];
        assert_eq!(cell.fg, DISABLED, "the keyring marker should be greyed");
    }

    #[test]
    fn password_screen_masks_and_places_cursor() {
        let mut wizard = Wizard::new(false);
        wizard.handle_key(key(KeyCode::Enter));
        type_text(&mut wizard, "abc");
        let (backend, pos, visible) = draw(&mut wizard, 80, 24);
        let text = screen(&backend);
        assert!(text.contains("Set an encryption password"), "{text}");
        assert!(text.contains("•••"), "masked password expected: {text}");
        assert!(
            !text.contains("abc"),
            "raw password must not render: {text}"
        );
        assert!(visible, "the caret must show in the focused field");
        assert!(
            pos.x > 0 && pos.y > 0,
            "caret should sit in the field: {pos:?}"
        );
    }

    #[test]
    fn reveal_shows_the_password_text() {
        let mut wizard = Wizard::new(false);
        wizard.handle_key(key(KeyCode::Enter));
        type_text(&mut wizard, "abc");
        wizard.handle_key(ctrl('r'));
        let (backend, _, _) = draw(&mut wizard, 80, 24);
        let text = screen(&backend);
        assert!(text.contains("abc"), "revealed password expected: {text}");
    }

    #[test]
    fn click_selects_then_activates_an_option() {
        let mut wizard = Wizard::new(true);
        let _ = draw(&mut wizard, 80, 24);
        let none_row = wizard.option_rows[2];
        let pos = Position::new(none_row.x, none_row.y);
        // First click selects.
        assert_eq!(
            wizard.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), pos)),
            Action::Continue
        );
        assert_eq!(wizard.selected_mode(), Mode::None);
        // Second click on the live row activates it.
        assert_eq!(
            wizard.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), pos)),
            Action::Done(Encryption::None)
        );
    }

    #[test]
    fn clicking_the_continue_button_activates_the_choice() {
        let mut wizard = Wizard::new(true);
        let (backend, _, _) = draw(&mut wizard, 80, 24);
        let pos = find(&backend, "[ Continue ]");
        assert_eq!(
            wizard.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), pos)),
            Action::Done(Encryption::Keyring)
        );
    }

    #[test]
    fn clicking_the_save_button_submits_the_password() {
        let mut wizard = Wizard::new(false);
        wizard.handle_key(key(KeyCode::Enter)); // into password phase
        type_text(&mut wizard, "hunter2");
        wizard.handle_key(key(KeyCode::Tab)); // to confirm
        type_text(&mut wizard, "hunter2");
        let (backend, _, _) = draw(&mut wizard, 80, 24);
        let pos = find(&backend, "[ Save ]");
        assert_eq!(
            wizard.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), pos)),
            Action::Done(Encryption::Password("hunter2".to_string()))
        );
    }

    #[test]
    fn clicking_a_password_field_focuses_it() {
        let mut wizard = Wizard::new(false);
        wizard.handle_key(key(KeyCode::Enter)); // password phase
        let (backend, _, _) = draw(&mut wizard, 80, 24);
        assert_eq!(wizard.focus, PwFocus::Password);
        let pos = find(&backend, "Confirm");
        wizard.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), pos));
        assert_eq!(wizard.focus, PwFocus::Confirm);
    }

    #[test]
    fn clicking_a_disabled_row_does_nothing() {
        let mut wizard = Wizard::new(false);
        let _ = draw(&mut wizard, 80, 24);
        let keyring_row = wizard.option_rows[0];
        let pos = Position::new(keyring_row.x, keyring_row.y);
        wizard.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), pos));
        assert_ne!(wizard.selected_mode(), Mode::Keyring);
    }

    #[test]
    fn password_phase_shows_a_back_button_and_click_returns() {
        let mut wizard = Wizard::new(false);
        wizard.handle_key(key(KeyCode::Enter));
        assert_eq!(wizard.phase, Phase::Password);
        let (backend, _, _) = draw(&mut wizard, 80, 24);
        let text = screen(&backend);
        assert!(text.contains("‹ Back"), "expected a back button: {text}");
        assert!(wizard.back_rect.width > 0);
        let pos = Position::new(wizard.back_rect.x, wizard.back_rect.y);
        wizard.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), pos));
        assert_eq!(wizard.phase, Phase::Choose);
    }

    #[test]
    fn choose_phase_has_no_back_button() {
        let mut wizard = Wizard::new(true);
        let (backend, _, _) = draw(&mut wizard, 80, 24);
        let text = screen(&backend);
        assert!(
            !text.contains("‹ Back"),
            "step 1 must not offer back: {text}"
        );
        assert_eq!(wizard.back_rect, Rect::default());
    }

    #[test]
    fn resume_preselects_the_prior_choice() {
        let none = Wizard::new_with(true, Some(Encryption::None));
        assert_eq!(none.selected_mode(), Mode::None);

        let pw = Wizard::new_with(true, Some(Encryption::Password("s3cret".to_string())));
        assert_eq!(pw.selected_mode(), Mode::Password);
        // Password is preserved so stepping forward again needs no retype.
        assert_eq!(pw.password.text(), "s3cret");
        assert_eq!(pw.confirm.text(), "s3cret");
    }

    #[test]
    fn resume_keyring_falls_back_when_now_unavailable() {
        let wizard = Wizard::new_with(false, Some(Encryption::Keyring));
        // Keyring is no longer selectable, so we land on the recommendation.
        assert_eq!(wizard.selected_mode(), Mode::Password);
    }

    #[test]
    fn summary_describes_each_choice() {
        assert_eq!(Encryption::Keyring.summary(), "OS keyring");
        assert_eq!(Encryption::None.summary(), "not encrypted");
        assert_eq!(
            Encryption::Password("abcd".to_string()).summary(),
            "password (4 chars)"
        );
    }
}
