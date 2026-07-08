//! Embedded-PTY pane for `/editor` and `/lazygit` (GOALS §1i/§1j,
//! plan T9).
//!
//! A [`PtyPane`] runs a child process in a pseudo-terminal and renders
//! its screen inside a ratatui rect — distinct from the suspend-the-
//! whole-TUI `$EDITOR` handoff (§1f / Ctrl+G, which edits the composer
//! text). The child's output is parsed by a background thread into a
//! [`vt100::Parser`] behind an `Arc<Mutex<_>>`; the render path locks
//! it and hands the screen to `tui_term`'s `PseudoTerminal` widget.
//!
//! Input is forwarded by encoding crossterm `KeyEvent`s /
//! `MouseEvent`s back into terminal byte sequences. The encoders cover
//! the common vim / lazygit surface; exotic sequences may not
//! round-trip (documented as best-effort in plan T9 risks).

use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use anyhow::{Context, Result, anyhow};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use ratatui::Frame;
use ratatui::layout::Rect;
use vt100::{MouseProtocolEncoding, MouseProtocolMode, Parser};

/// Which kind of process the pane is running. Only used for labels and
/// the auto-close message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneKind {
    Editor,
    Lazygit,
}

impl PaneKind {
    pub fn label(self) -> &'static str {
        match self {
            PaneKind::Editor => "editor",
            PaneKind::Lazygit => "lazygit",
        }
    }
}

/// A live child process running in a PTY, rendered into a ratatui rect.
pub struct PtyPane {
    parser: Arc<Mutex<Parser>>,
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn Child + Send + Sync>,
    /// Set by the reader thread when the PTY hits EOF (the child closed
    /// its end — i.e. it exited). The authoritative auto-close signal.
    reader_eof: Arc<AtomicBool>,
    rows: u16,
    cols: u16,
    /// Kept so the handle is owned for the pane's lifetime; the thread
    /// exits on its own when the master is dropped (EOF), so we never
    /// join it (joining could block on a wedged child).
    _reader: JoinHandle<()>,
}

impl PtyPane {
    /// Spawn `argv` in a new PTY sized `rows`×`cols` with `cwd` as the
    /// working directory. The child inherits the parent environment
    /// (portable-pty seeds the command env from the current process).
    pub fn spawn(
        kind: PaneKind,
        argv: &[String],
        cwd: &Path,
        rows: u16,
        cols: u16,
    ) -> Result<Self> {
        let prog = argv.first().ok_or_else(|| anyhow!("empty command"))?;
        let rows = rows.max(1);
        let cols = cols.max(1);

        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("open pty")?;

        let mut cmd = CommandBuilder::new(prog.as_str());
        for arg in &argv[1..] {
            cmd.arg(arg);
        }
        cmd.cwd(cwd);
        // Advertise a capable terminal so editors enable colors / keys.
        cmd.env("TERM", "xterm-256color");

        let child = pair.slave.spawn_command(cmd).context("spawn child")?;
        // Drop our handle on the slave so the kernel reports EOF on the
        // master once the child exits and closes its end.
        drop(pair.slave);

        let master = pair.master;
        let writer = master.take_writer().context("take pty writer")?;
        let mut reader = master.try_clone_reader().context("clone pty reader")?;

        let parser = Arc::new(Mutex::new(Parser::new(rows, cols, 0)));
        let reader_eof = Arc::new(AtomicBool::new(false));

        let thread = {
            let parser = Arc::clone(&parser);
            let reader_eof = Arc::clone(&reader_eof);
            std::thread::Builder::new()
                .name(format!("cockpit-pty-{}", kind.label()))
                .spawn(move || {
                    let mut buf = [0u8; 8192];
                    loop {
                        match reader.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                if let Ok(mut p) = parser.lock() {
                                    p.process(&buf[..n]);
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    reader_eof.store(true, Ordering::SeqCst);
                })
                .context("spawn pty reader thread")?
        };

        Ok(Self {
            parser,
            master,
            writer,
            child,
            reader_eof,
            rows,
            cols,
            _reader: thread,
        })
    }

    /// Resize the PTY to fit `rows`×`cols`. No-op when unchanged.
    /// `master.resize` raises SIGWINCH so the child reflows.
    pub fn resize(&mut self, rows: u16, cols: u16) {
        let rows = rows.max(1);
        let cols = cols.max(1);
        if rows == self.rows && cols == self.cols {
            return;
        }
        self.rows = rows;
        self.cols = cols;
        let _ = self.master.resize(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        });
        if let Ok(mut p) = self.parser.lock() {
            p.screen_mut().set_size(rows, cols);
        }
    }

    /// Write raw bytes to the child's stdin.
    pub fn write_input(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let _ = self.writer.write_all(bytes);
        let _ = self.writer.flush();
    }

    /// Forward a key press to the child, encoding it back into terminal
    /// bytes. DECCKM (application cursor keys) is honored for arrows.
    pub fn forward_key(&mut self, key: &KeyEvent) {
        let app_cursor = self
            .parser
            .lock()
            .map(|p| p.screen().application_cursor())
            .unwrap_or(false);
        if let Some(bytes) = key_to_bytes(key, app_cursor) {
            self.write_input(&bytes);
        }
    }

    /// Forward a terminal paste to the child, honoring bracketed paste
    /// mode when the parsed screen reports it.
    pub fn forward_paste(&mut self, text: &str) {
        let bracketed = self
            .parser
            .lock()
            .map(|p| p.screen().bracketed_paste())
            .unwrap_or(false);
        let bytes = paste_to_bytes(text, bracketed);
        self.write_input(&bytes);
    }

    /// Forward a mouse event to the child if it has requested mouse
    /// tracking. `area` is the pane's content rect (absolute coords).
    /// Returns true when the event was consumed (encoded + written).
    pub fn forward_mouse(&mut self, ev: &MouseEvent, area: Rect) -> bool {
        let bytes = {
            let Ok(p) = self.parser.lock() else {
                return false;
            };
            let screen = p.screen();
            mouse_to_bytes(
                ev,
                area,
                screen.mouse_protocol_mode(),
                screen.mouse_protocol_encoding(),
            )
        };
        match bytes {
            Some(b) => {
                self.write_input(&b);
                true
            }
            None => false,
        }
    }

    /// True once the child has exited (reader hit EOF or the process
    /// has been reaped/finished).
    pub fn has_exited(&mut self) -> bool {
        if self.reader_eof.load(Ordering::SeqCst) {
            return true;
        }
        matches!(self.child.try_wait(), Ok(Some(_)))
    }

    /// Reap an already-exited child (auto-close path). Non-blocking in
    /// practice since the child is already gone.
    pub fn reap(&mut self) {
        let _ = self.child.wait();
    }

    /// Force-terminate a still-running child and reap it (Ctrl+X). The
    /// reader thread ends on its own once `self` (and the master) drop.
    pub fn terminate(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Render the child's current screen into `area`. tui_term's own
    /// cursor is hidden — the App parks the real terminal cursor at
    /// [`cursor_in`](Self::cursor_in) when the pane is focused.
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        use tui_term::widget::{Cursor, PseudoTerminal};
        let Ok(parser) = self.parser.lock() else {
            return;
        };
        let screen = parser.screen();
        let mut cursor = Cursor::default();
        cursor.hide();
        let term = PseudoTerminal::new(screen).cursor(cursor);
        frame.render_widget(term, area);
    }

    /// Absolute terminal position of the child's cursor within `area`,
    /// or `None` when the child has hidden its cursor or it's offscreen.
    pub fn cursor_in(&self, area: Rect) -> Option<(u16, u16)> {
        let parser = self.parser.lock().ok()?;
        let screen = parser.screen();
        if screen.hide_cursor() {
            return None;
        }
        let (row, col) = screen.cursor_position();
        if col >= area.width || row >= area.height {
            return None;
        }
        Some((area.x + col, area.y + row))
    }

    #[cfg(test)]
    pub fn screen_contents_for_test(&self) -> String {
        self.parser
            .lock()
            .map(|p| p.screen().contents())
            .unwrap_or_default()
    }
}

/// Split an `$EDITOR`-style string into argv, honoring single/double
/// quotes (e.g. `code -w` → `["code", "-w"]`). Minimal — enough for the
/// editor-command case; not a full POSIX shell parser.
pub fn shell_split(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    let mut in_word = false;
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '\'' | '"' => {
                in_word = true;
                let quote = c;
                for q in chars.by_ref() {
                    if q == quote {
                        break;
                    }
                    cur.push(q);
                }
            }
            '\\' => {
                in_word = true;
                if let Some(next) = chars.next() {
                    cur.push(next);
                }
            }
            _ => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    out
}

/// Encode a crossterm key into the bytes a terminal would deliver to a
/// child. `app_cursor` selects SS3 (`ESC O`) vs CSI (`ESC [`) for the
/// arrow / Home / End keys (DECCKM).
pub fn key_to_bytes(key: &KeyEvent, app_cursor: bool) -> Option<Vec<u8>> {
    let m = key.modifiers;
    let ctrl = m.contains(KeyModifiers::CONTROL);
    let alt = m.contains(KeyModifiers::ALT);
    let mut out: Vec<u8> = Vec::new();

    match key.code {
        KeyCode::Char(c) => {
            if ctrl {
                let b = control_byte(c)?;
                if alt {
                    out.push(0x1b);
                }
                out.push(b);
            } else {
                if alt {
                    out.push(0x1b);
                }
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
        KeyCode::Enter => {
            if alt {
                out.push(0x1b);
            }
            out.push(b'\r');
        }
        KeyCode::Tab => out.push(b'\t'),
        KeyCode::BackTab => out.extend_from_slice(b"\x1b[Z"),
        KeyCode::Backspace => out.push(0x7f),
        KeyCode::Esc => out.push(0x1b),
        KeyCode::Delete => out.extend_from_slice(b"\x1b[3~"),
        KeyCode::Insert => out.extend_from_slice(b"\x1b[2~"),
        KeyCode::Home => push_cursor_seq(&mut out, app_cursor, b'H', m),
        KeyCode::End => push_cursor_seq(&mut out, app_cursor, b'F', m),
        KeyCode::PageUp => out.extend_from_slice(b"\x1b[5~"),
        KeyCode::PageDown => out.extend_from_slice(b"\x1b[6~"),
        KeyCode::Up => push_cursor_seq(&mut out, app_cursor, b'A', m),
        KeyCode::Down => push_cursor_seq(&mut out, app_cursor, b'B', m),
        KeyCode::Right => push_cursor_seq(&mut out, app_cursor, b'C', m),
        KeyCode::Left => push_cursor_seq(&mut out, app_cursor, b'D', m),
        KeyCode::F(n) => push_function_key(&mut out, n),
        _ => return None,
    }

    if out.is_empty() { None } else { Some(out) }
}

/// Encode a terminal paste payload for child stdin. Empty paste events
/// write nothing; non-empty bracketed paste is wrapped the way a real
/// terminal delivers it after DEC private mode ?2004 is enabled.
pub fn paste_to_bytes(text: &str, bracketed: bool) -> Vec<u8> {
    if text.is_empty() {
        return Vec::new();
    }
    if !bracketed {
        return text.as_bytes().to_vec();
    }
    let mut out = Vec::with_capacity(b"\x1b[200~".len() + text.len() + b"\x1b[201~".len());
    out.extend_from_slice(b"\x1b[200~");
    out.extend_from_slice(text.as_bytes());
    out.extend_from_slice(b"\x1b[201~");
    out
}

/// Map a printable char under Ctrl to its control byte. `None` for
/// combos with no canonical control code.
fn control_byte(c: char) -> Option<u8> {
    let lc = c.to_ascii_lowercase();
    match lc {
        'a'..='z' => Some((lc as u8 - b'a') + 1),
        ' ' | '@' => Some(0),
        '[' => Some(0x1b),
        '\\' => Some(0x1c),
        ']' => Some(0x1d),
        '^' => Some(0x1e),
        '_' | '/' => Some(0x1f),
        '?' => Some(0x7f),
        _ => None,
    }
}

/// CSI/SS3 modifier parameter: `1 + sum(shift=1, alt=2, ctrl=4)`.
fn modifier_param(m: KeyModifiers) -> u8 {
    1 + u8::from(m.contains(KeyModifiers::SHIFT))
        + (u8::from(m.contains(KeyModifiers::ALT)) * 2)
        + (u8::from(m.contains(KeyModifiers::CONTROL)) * 4)
}

/// Push an arrow / Home / End sequence. Unmodified uses SS3 (`ESC O`)
/// under application-cursor mode, else CSI (`ESC [`); modified always
/// uses the CSI `1;<mod><letter>` form.
fn push_cursor_seq(out: &mut Vec<u8>, app_cursor: bool, letter: u8, m: KeyModifiers) {
    let mp = modifier_param(m);
    if mp == 1 {
        out.push(0x1b);
        out.push(if app_cursor { b'O' } else { b'[' });
        out.push(letter);
    } else {
        out.extend_from_slice(b"\x1b[1;");
        out.extend_from_slice(mp.to_string().as_bytes());
        out.push(letter);
    }
}

fn push_function_key(out: &mut Vec<u8>, n: u8) {
    match n {
        1 => out.extend_from_slice(b"\x1bOP"),
        2 => out.extend_from_slice(b"\x1bOQ"),
        3 => out.extend_from_slice(b"\x1bOR"),
        4 => out.extend_from_slice(b"\x1bOS"),
        5 => out.extend_from_slice(b"\x1b[15~"),
        6 => out.extend_from_slice(b"\x1b[17~"),
        7 => out.extend_from_slice(b"\x1b[18~"),
        8 => out.extend_from_slice(b"\x1b[19~"),
        9 => out.extend_from_slice(b"\x1b[20~"),
        10 => out.extend_from_slice(b"\x1b[21~"),
        11 => out.extend_from_slice(b"\x1b[23~"),
        12 => out.extend_from_slice(b"\x1b[24~"),
        _ => {}
    }
}

/// Encode a mouse event for a child that requested tracking. Returns
/// `None` when the child's mode doesn't want this event (or it's
/// outside `area`). Supports SGR (1006) and the legacy X10 encoding.
fn mouse_to_bytes(
    ev: &MouseEvent,
    area: Rect,
    mode: MouseProtocolMode,
    encoding: MouseProtocolEncoding,
) -> Option<Vec<u8>> {
    if mode == MouseProtocolMode::None {
        return None;
    }
    if ev.column < area.x || ev.row < area.y {
        return None;
    }
    let rel_col = ev.column - area.x;
    let rel_row = ev.row - area.y;
    if rel_col >= area.width || rel_row >= area.height {
        return None;
    }

    // (button base code, is-release, kind of report)
    enum Need {
        Press,
        Release,
        Motion,
    }
    let (base, release, need) = match ev.kind {
        MouseEventKind::Down(b) => (button_base(b), false, Need::Press),
        MouseEventKind::Up(b) => (button_base(b), true, Need::Release),
        MouseEventKind::Drag(b) => (button_base(b) + 32, false, Need::Motion),
        MouseEventKind::ScrollUp => (64, false, Need::Press),
        MouseEventKind::ScrollDown => (65, false, Need::Press),
        MouseEventKind::ScrollLeft => (66, false, Need::Press),
        MouseEventKind::ScrollRight => (67, false, Need::Press),
        MouseEventKind::Moved => return None,
    };

    // Gate by what the child asked for.
    match need {
        Need::Motion => {
            if !matches!(
                mode,
                MouseProtocolMode::ButtonMotion | MouseProtocolMode::AnyMotion
            ) {
                return None;
            }
        }
        Need::Release => {
            if matches!(mode, MouseProtocolMode::Press) {
                return None;
            }
        }
        Need::Press => {}
    }

    let mods = ev.modifiers;
    let mod_bits = (u8::from(mods.contains(KeyModifiers::SHIFT)) * 4)
        + (u8::from(mods.contains(KeyModifiers::ALT)) * 8)
        + (u8::from(mods.contains(KeyModifiers::CONTROL)) * 16);
    let cb = base + mod_bits;
    // 1-based coordinates.
    let cx = rel_col as u32 + 1;
    let cy = rel_row as u32 + 1;

    let mut out = Vec::new();
    match encoding {
        MouseProtocolEncoding::Sgr => {
            out.extend_from_slice(b"\x1b[<");
            out.extend_from_slice(cb.to_string().as_bytes());
            out.push(b';');
            out.extend_from_slice(cx.to_string().as_bytes());
            out.push(b';');
            out.extend_from_slice(cy.to_string().as_bytes());
            out.push(if release { b'm' } else { b'M' });
        }
        _ => {
            // Legacy X10: ESC [ M  Cb+32  Cx+32  Cy+32 . Release uses
            // button code 3. Coordinates cap at 223 (255 - 32).
            let legacy_cb = if release { 3 + mod_bits } else { cb };
            out.extend_from_slice(b"\x1b[M");
            out.push(legacy_cb.saturating_add(32));
            out.push((cx.min(223) as u8).saturating_add(32));
            out.push((cy.min(223) as u8).saturating_add(32));
        }
    }
    Some(out)
}

fn button_base(b: MouseButton) -> u8 {
    match b {
        MouseButton::Left => 0,
        MouseButton::Middle => 1,
        MouseButton::Right => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_split_basic() {
        assert_eq!(shell_split("vim"), vec!["vim"]);
        assert_eq!(shell_split("code -w"), vec!["code", "-w"]);
        assert_eq!(
            shell_split("  nvim   -u  none "),
            vec!["nvim", "-u", "none"]
        );
    }

    #[test]
    fn shell_split_quotes() {
        assert_eq!(
            shell_split("\"/Applications/My Editor\" --wait"),
            vec!["/Applications/My Editor", "--wait"]
        );
        assert_eq!(shell_split("emacs '+5'"), vec!["emacs", "+5"]);
    }

    #[test]
    fn key_plain_char() {
        let k = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
        assert_eq!(key_to_bytes(&k, false), Some(vec![b'a']));
    }

    #[test]
    fn key_ctrl_c_is_etx() {
        let k = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(key_to_bytes(&k, false), Some(vec![0x03]));
    }

    #[test]
    fn key_enter_is_cr() {
        let k = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(key_to_bytes(&k, false), Some(vec![b'\r']));
    }

    #[test]
    fn key_arrow_decckm() {
        let up = KeyEvent::new(KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(key_to_bytes(&up, false), Some(b"\x1b[A".to_vec()));
        assert_eq!(key_to_bytes(&up, true), Some(b"\x1bOA".to_vec()));
    }

    #[test]
    fn key_modified_arrow() {
        let k = KeyEvent::new(KeyCode::Left, KeyModifiers::CONTROL);
        // mod param = 1 + 4 = 5
        assert_eq!(key_to_bytes(&k, false), Some(b"\x1b[1;5D".to_vec()));
    }

    #[test]
    fn paste_raw_preserves_newlines() {
        assert_eq!(paste_to_bytes("a\nb", false), b"a\nb".to_vec());
    }

    #[test]
    fn paste_bracketed_wraps_payload() {
        assert_eq!(
            paste_to_bytes("a\nb", true),
            b"\x1b[200~a\nb\x1b[201~".to_vec()
        );
    }

    #[test]
    fn paste_empty_writes_nothing() {
        assert!(paste_to_bytes("", false).is_empty());
        assert!(paste_to_bytes("", true).is_empty());
    }

    #[test]
    fn vt100_tracks_bracketed_paste_mode() {
        let mut parser = Parser::new(24, 80, 0);
        assert!(!parser.screen().bracketed_paste());
        parser.process(b"\x1b[?2004h");
        assert!(parser.screen().bracketed_paste());
        parser.process(b"\x1b[?1006h");
        assert!(parser.screen().bracketed_paste());
        parser.process(b"\x1b[?2004l");
        assert!(!parser.screen().bracketed_paste());
    }

    #[test]
    fn mouse_sgr_press() {
        let area = Rect::new(0, 0, 80, 24);
        let ev = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 4,
            row: 2,
            modifiers: KeyModifiers::NONE,
        };
        let b = mouse_to_bytes(
            &ev,
            area,
            MouseProtocolMode::PressRelease,
            MouseProtocolEncoding::Sgr,
        );
        assert_eq!(b, Some(b"\x1b[<0;5;3M".to_vec()));
    }

    #[cfg(unix)]
    #[test]
    fn pty_spawn_reads_child_output() {
        // End-to-end: spawn a real child in a PTY and confirm its output
        // lands on the vt100 screen via the reader thread.
        let argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            "printf COCKPIT_PTY_OK".to_string(),
        ];
        let cwd = std::env::temp_dir();
        let mut pane =
            PtyPane::spawn(PaneKind::Editor, &argv, &cwd, 24, 80).expect("spawn pty child");
        // Give the reader thread time to drain the child's output.
        for _ in 0..50 {
            if pane.has_exited() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        let contents = pane.parser.lock().unwrap().screen().contents();
        pane.reap();
        assert!(
            contents.contains("COCKPIT_PTY_OK"),
            "screen did not capture child output, got: {contents:?}"
        );
    }

    #[test]
    fn mouse_disabled_yields_none() {
        let area = Rect::new(0, 0, 80, 24);
        let ev = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 4,
            row: 2,
            modifiers: KeyModifiers::NONE,
        };
        assert_eq!(
            mouse_to_bytes(
                &ev,
                area,
                MouseProtocolMode::None,
                MouseProtocolEncoding::Sgr
            ),
            None
        );
    }
}
