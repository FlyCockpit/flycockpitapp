use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine as _;
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
#[cfg(test)]
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::daemon::proto::{self, ErrorCode, ErrorPayload, Response};
use crate::daemon::{EventSender, SharedRedactionTable, send_current_event};
#[cfg(test)]
use crate::redact::RedactionTable;

const REPLAY_BUFFER_BYTES: usize = 256 * 1024;
const OUTPUT_CHUNK_BYTES: usize = 32 * 1024;
const MAX_TERMINALS: usize = 4;
const TERMINAL_IDLE_TTL: Duration = Duration::from_secs(10 * 60);
const TERMINAL_INPUT_CAP: usize = 1024 * 1024;
const BRACKETED_PASTE_START: &[u8] = b"\x1b[200~";
const BRACKETED_PASTE_END: &[u8] = b"\x1b[201~";

#[derive(Debug, Clone)]
pub struct TerminalHost {
    inner: Arc<Mutex<TerminalHostInner>>,
    event_tx: EventSender,
    redaction: SharedRedactionTable,
    temp_root: PathBuf,
    idle_ttl: Duration,
}

#[derive(Debug, Default)]
struct TerminalHostInner {
    terminals: HashMap<Uuid, Arc<Mutex<TerminalState>>>,
}

struct TerminalState {
    id: Uuid,
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn Child + Send + Sync>,
    buffer: ReplayBuffer,
    filter: TerminalOutputFilter,
    viewer_count: usize,
    temp_dir: PathBuf,
    paste_counter: u64,
    closed: bool,
    last_detached: Option<Instant>,
}

impl std::fmt::Debug for TerminalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalState")
            .field("id", &self.id)
            .field("viewer_count", &self.viewer_count)
            .field("temp_dir", &self.temp_dir)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
struct ReplayBuffer {
    bytes: VecDeque<u8>,
    cap: usize,
}

impl ReplayBuffer {
    fn new(cap: usize) -> Self {
        Self {
            bytes: VecDeque::with_capacity(cap.min(8192)),
            cap,
        }
    }

    fn push(&mut self, data: &[u8]) {
        if data.len() >= self.cap {
            self.bytes.clear();
            self.bytes
                .extend(data[data.len() - self.cap..].iter().copied());
            return;
        }
        while self.bytes.len() + data.len() > self.cap {
            self.bytes.pop_front();
        }
        self.bytes.extend(data.iter().copied());
    }

    fn bytes(&self) -> Vec<u8> {
        self.bytes.iter().copied().collect()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.bytes.len()
    }
}

#[derive(Debug, Default)]
pub struct TerminalOutputFilter {
    pending: Vec<u8>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct FilteredTerminalOutput {
    pub passthrough: Vec<u8>,
    pub clipboards: Vec<String>,
}

impl TerminalOutputFilter {
    pub fn push(&mut self, bytes: &[u8]) -> FilteredTerminalOutput {
        let mut input = std::mem::take(&mut self.pending);
        input.extend_from_slice(bytes);
        let mut passthrough = Vec::with_capacity(input.len());
        let mut clipboards = Vec::new();
        let mut i = 0;
        while i < input.len() {
            if input[i] == 0x1b {
                if is_incomplete_known_escape_prefix(&input[i..]) {
                    break;
                }
                if input[i..].starts_with(b"\x1b]52;") {
                    match find_osc_terminator(&input, i + 5) {
                        Some((end, term_len)) => {
                            if let Some(text) = parse_osc52(&input[i + 5..end]) {
                                clipboards.push(text);
                            }
                            i = end + term_len;
                            continue;
                        }
                        None => break,
                    }
                }
                if input[i..].starts_with(b"\x1b[?") {
                    if let Some(end) = find_decrqm_response_end(&input, i) {
                        i = end;
                        continue;
                    }
                    if input.len() - i < 128 {
                        break;
                    }
                }
            }
            passthrough.push(input[i]);
            i += 1;
        }
        self.pending.extend_from_slice(&input[i..]);
        FilteredTerminalOutput {
            passthrough,
            clipboards,
        }
    }
}

fn is_incomplete_known_escape_prefix(bytes: &[u8]) -> bool {
    const PREFIXES: [&[u8]; 2] = [b"\x1b]52;", b"\x1b[?"];
    PREFIXES
        .iter()
        .any(|prefix| bytes.len() < prefix.len() && prefix.starts_with(bytes))
}

fn find_osc_terminator(input: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut i = start;
    while i < input.len() {
        if input[i] == 0x07 {
            return Some((i, 1));
        }
        if input[i] == 0x1b && input.get(i + 1) == Some(&b'\\') {
            return Some((i, 2));
        }
        i += 1;
    }
    None
}

fn parse_osc52(body: &[u8]) -> Option<String> {
    let semicolon = body.iter().position(|b| *b == b';')?;
    let payload = &body[semicolon + 1..];
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .ok()?;
    String::from_utf8(decoded).ok()
}

fn find_decrqm_response_end(input: &[u8], start: usize) -> Option<usize> {
    let max = input.len().min(start + 128);
    let mut i = start + 3;
    while i + 1 < max {
        if input[i] == b'$' && input[i + 1] == b'y' {
            return Some(i + 2);
        }
        i += 1;
    }
    None
}

impl TerminalHost {
    pub fn new(event_tx: EventSender, redaction: SharedRedactionTable, temp_root: PathBuf) -> Self {
        prepare_temp_root(&temp_root);
        Self {
            inner: Arc::new(Mutex::new(TerminalHostInner::default())),
            event_tx,
            redaction,
            temp_root,
            idle_ttl: TERMINAL_IDLE_TTL,
        }
    }

    #[cfg(test)]
    pub fn new_for_test(event_tx: EventSender, temp_root: PathBuf) -> Self {
        let redaction = Arc::new(std::sync::RwLock::new(Arc::new(RedactionTable::empty())));
        Self::new(event_tx, redaction, temp_root)
    }

    pub fn open(
        &self,
        cwd: Option<String>,
        cols: u16,
        rows: u16,
    ) -> std::result::Result<Response, ErrorPayload> {
        let cwd = resolve_cwd(cwd)?;
        {
            let inner = crate::sync::lock_or_recover(&self.inner);
            if inner.terminals.len() >= MAX_TERMINALS {
                return Err(bad_request(format!(
                    "too many active terminals: limit {MAX_TERMINALS}"
                )));
            }
        }
        let id = Uuid::new_v4();
        let terminal = spawn_terminal(
            id,
            &cwd,
            cols,
            rows,
            &self.temp_root,
            self.event_tx.clone(),
            self.redaction.clone(),
        )
        .map_err(internal)?;
        crate::sync::lock_or_recover(&self.inner)
            .terminals
            .insert(id, terminal);
        Ok(Response::TerminalOpened {
            terminal_id: id,
            viewer_count: 1,
            recording: false,
        })
    }

    pub fn attach(
        &self,
        terminal_id: Uuid,
        cols: u16,
        rows: u16,
    ) -> std::result::Result<Response, ErrorPayload> {
        let terminal = self.get_terminal(terminal_id)?;
        let (viewer_count, replay) = {
            let mut state = crate::sync::lock_or_recover(&terminal);
            if state.closed {
                return Err(unknown_terminal(terminal_id));
            }
            state.viewer_count = state.viewer_count.saturating_add(1);
            state.last_detached = None;
            resize_locked(&mut state, cols, rows);
            (state.viewer_count, state.buffer.bytes())
        };
        if !replay.is_empty() {
            self.emit_output_chunks(terminal_id, replay);
        }
        self.emit(proto::Event::TerminalViewers {
            terminal_id,
            count: viewer_count,
        });
        Ok(Response::TerminalOpened {
            terminal_id,
            viewer_count,
            recording: false,
        })
    }

    pub fn release_viewer(&self, terminal_id: Uuid) {
        let Ok(terminal) = self.get_terminal(terminal_id) else {
            return;
        };
        let count = {
            let mut state = crate::sync::lock_or_recover(&terminal);
            state.viewer_count = state.viewer_count.saturating_sub(1);
            if state.viewer_count == 0 {
                state.last_detached = Some(Instant::now());
            }
            state.viewer_count
        };
        self.emit(proto::Event::TerminalViewers { terminal_id, count });
    }

    pub fn input(
        &self,
        terminal_id: Uuid,
        bytes: Vec<u8>,
    ) -> std::result::Result<Response, ErrorPayload> {
        if bytes.len() > TERMINAL_INPUT_CAP {
            return Err(bad_request(format!(
                "terminal input is too large: {} bytes exceeds {TERMINAL_INPUT_CAP}",
                bytes.len()
            )));
        }
        let terminal = self.get_terminal(terminal_id)?;
        let mut state = crate::sync::lock_or_recover(&terminal);
        ensure_open(&state, terminal_id)?;
        state.writer.write_all(&bytes).map_err(internal)?;
        state.writer.flush().map_err(internal)?;
        Ok(Response::Ack)
    }

    pub fn resize(
        &self,
        terminal_id: Uuid,
        cols: u16,
        rows: u16,
    ) -> std::result::Result<Response, ErrorPayload> {
        let terminal = self.get_terminal(terminal_id)?;
        let mut state = crate::sync::lock_or_recover(&terminal);
        ensure_open(&state, terminal_id)?;
        resize_locked(&mut state, cols, rows);
        Ok(Response::Ack)
    }

    pub fn close(&self, terminal_id: Uuid) -> std::result::Result<Response, ErrorPayload> {
        let terminal = {
            let mut inner = crate::sync::lock_or_recover(&self.inner);
            inner
                .terminals
                .remove(&terminal_id)
                .ok_or_else(|| unknown_terminal(terminal_id))?
        };
        let temp_dir = {
            let mut state = crate::sync::lock_or_recover(&terminal);
            state.closed = true;
            let _ = state.child.kill();
            let _ = state.child.wait();
            state.temp_dir.clone()
        };
        let _ = std::fs::remove_dir_all(&temp_dir);
        self.emit(proto::Event::TerminalClosed {
            terminal_id,
            reason: "closed".to_string(),
            exit_code: None,
        });
        Ok(Response::Ack)
    }

    pub fn paste_image(
        &self,
        terminal_id: Uuid,
        bytes: &[u8],
    ) -> std::result::Result<Response, ErrorPayload> {
        let terminal = self.get_terminal(terminal_id)?;
        let path = {
            let mut state = crate::sync::lock_or_recover(&terminal);
            ensure_open(&state, terminal_id)?;
            std::fs::create_dir_all(&state.temp_dir).map_err(internal)?;
            set_private_dir_permissions(&state.temp_dir).map_err(internal)?;
            state.paste_counter += 1;
            let path = state
                .temp_dir
                .join(format!("paste-{}.png", state.paste_counter));
            std::fs::write(&path, bytes).map_err(internal)?;
            set_private_file_permissions(&path).map_err(internal)?;
            let path_text = path.to_string_lossy().into_owned();
            let paste = bracketed_paste_bytes(&path_text);
            state.writer.write_all(&paste).map_err(internal)?;
            state.writer.flush().map_err(internal)?;
            path_text
        };
        Ok(Response::TerminalPasteImage { terminal_id, path })
    }

    pub fn contains(&self, terminal_id: Uuid) -> bool {
        crate::sync::lock_or_recover(&self.inner)
            .terminals
            .contains_key(&terminal_id)
    }

    pub fn sweep_idle(&self, now: Instant) -> Vec<Uuid> {
        let ids: Vec<_> = {
            let inner = crate::sync::lock_or_recover(&self.inner);
            inner
                .terminals
                .iter()
                .filter_map(|(id, terminal)| {
                    let state = crate::sync::lock_or_recover(terminal);
                    (state.viewer_count == 0
                        && state
                            .last_detached
                            .is_some_and(|then| now.duration_since(then) >= self.idle_ttl))
                    .then_some(*id)
                })
                .collect()
        };
        for id in &ids {
            let _ = self.close(*id);
        }
        ids
    }

    fn get_terminal(
        &self,
        terminal_id: Uuid,
    ) -> std::result::Result<Arc<Mutex<TerminalState>>, ErrorPayload> {
        crate::sync::lock_or_recover(&self.inner)
            .terminals
            .get(&terminal_id)
            .cloned()
            .ok_or_else(|| unknown_terminal(terminal_id))
    }

    fn emit(&self, event: proto::Event) {
        send_current_event(&self.event_tx, &self.redaction, event);
    }

    fn emit_output_chunks(&self, terminal_id: Uuid, bytes: Vec<u8>) {
        for chunk in bytes.chunks(OUTPUT_CHUNK_BYTES) {
            self.emit(proto::Event::TerminalOutput {
                terminal_id,
                bytes: chunk.to_vec(),
            });
        }
    }
}

pub(crate) fn install_factory() {
    crate::daemon::terminal::install_default_host_factory(factory());
}

pub(crate) fn factory() -> crate::daemon::terminal::TerminalHostFactory {
    crate::daemon::terminal::TerminalHostFactory::new(|events, redaction, temp_root| {
        Arc::new(TerminalHost::new(events, redaction, temp_root))
    })
}

impl crate::daemon::terminal::TerminalHost for TerminalHost {
    fn open(
        &self,
        cwd: Option<String>,
        cols: u16,
        rows: u16,
    ) -> crate::daemon::terminal::TerminalResult {
        TerminalHost::open(self, cwd, cols, rows)
    }

    fn attach(
        &self,
        terminal_id: Uuid,
        cols: u16,
        rows: u16,
    ) -> crate::daemon::terminal::TerminalResult {
        TerminalHost::attach(self, terminal_id, cols, rows)
    }

    fn release_viewer(&self, terminal_id: Uuid) {
        TerminalHost::release_viewer(self, terminal_id);
    }

    fn input(&self, terminal_id: Uuid, bytes: Vec<u8>) -> crate::daemon::terminal::TerminalResult {
        TerminalHost::input(self, terminal_id, bytes)
    }

    fn resize(
        &self,
        terminal_id: Uuid,
        cols: u16,
        rows: u16,
    ) -> crate::daemon::terminal::TerminalResult {
        TerminalHost::resize(self, terminal_id, cols, rows)
    }

    fn close(&self, terminal_id: Uuid) -> crate::daemon::terminal::TerminalResult {
        TerminalHost::close(self, terminal_id)
    }

    fn paste_image(
        &self,
        terminal_id: Uuid,
        bytes: &[u8],
    ) -> crate::daemon::terminal::TerminalResult {
        TerminalHost::paste_image(self, terminal_id, bytes)
    }

    fn contains(&self, terminal_id: Uuid) -> bool {
        TerminalHost::contains(self, terminal_id)
    }

    fn sweep_idle(&self, now: Instant) -> Vec<Uuid> {
        TerminalHost::sweep_idle(self, now)
    }
}

fn spawn_terminal(
    id: Uuid,
    cwd: &Path,
    cols: u16,
    rows: u16,
    temp_root: &Path,
    event_tx: EventSender,
    redaction: SharedRedactionTable,
) -> Result<Arc<Mutex<TerminalState>>> {
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
        .context("open terminal pty")?;
    let shell = default_shell();
    let mut cmd = CommandBuilder::new(&shell);
    cmd.cwd(cwd);
    cmd.env("TERM", "xterm-256color");
    cmd.env("COCKPIT_REMOTE", "1");
    let child = pair
        .slave
        .spawn_command(cmd)
        .with_context(|| format!("spawn shell `{shell}`"))?;
    drop(pair.slave);

    let master = pair.master;
    let writer = master.take_writer().context("take terminal pty writer")?;
    let mut reader = master
        .try_clone_reader()
        .context("clone terminal pty reader")?;
    let temp_dir = temp_root.join(format!("term-{id}"));
    let state = Arc::new(Mutex::new(TerminalState {
        id,
        master,
        writer,
        child,
        buffer: ReplayBuffer::new(REPLAY_BUFFER_BYTES),
        filter: TerminalOutputFilter::default(),
        viewer_count: 1,
        temp_dir,
        paste_counter: 0,
        closed: false,
        last_detached: None,
    }));

    let reader_state = Arc::clone(&state);
    let reader_redaction = redaction.clone();
    std::thread::Builder::new()
        .name(format!("cockpit-remote-terminal-{id}"))
        .spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let filtered = {
                            let mut state = crate::sync::lock_or_recover(&reader_state);
                            let filtered = state.filter.push(&buf[..n]);
                            if !filtered.passthrough.is_empty() {
                                state.buffer.push(&filtered.passthrough);
                            }
                            filtered
                        };
                        for chunk in filtered.passthrough.chunks(OUTPUT_CHUNK_BYTES) {
                            send_current_event(
                                &event_tx,
                                &reader_redaction,
                                proto::Event::TerminalOutput {
                                    terminal_id: id,
                                    bytes: chunk.to_vec(),
                                },
                            );
                        }
                        for text in filtered.clipboards {
                            send_current_event(
                                &event_tx,
                                &reader_redaction,
                                proto::Event::TerminalClipboard {
                                    terminal_id: id,
                                    text,
                                },
                            );
                        }
                    }
                    Err(_) => break,
                }
            }
            let mut state = crate::sync::lock_or_recover(&reader_state);
            if !state.closed {
                state.closed = true;
                send_current_event(
                    &event_tx,
                    &reader_redaction,
                    proto::Event::TerminalClosed {
                        terminal_id: id,
                        reason: "exited".to_string(),
                        exit_code: None,
                    },
                );
            }
        })
        .context("spawn terminal pty reader thread")?;

    Ok(state)
}

fn resize_locked(state: &mut TerminalState, cols: u16, rows: u16) {
    let _ = state.master.resize(PtySize {
        rows: rows.max(1),
        cols: cols.max(1),
        pixel_width: 0,
        pixel_height: 0,
    });
}

fn resolve_cwd(cwd: Option<String>) -> std::result::Result<PathBuf, ErrorPayload> {
    let path = match cwd {
        Some(cwd) => PathBuf::from(cwd),
        None => dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")),
    };
    let canonical = std::fs::canonicalize(&path).map_err(|e| ErrorPayload {
        code: ErrorCode::RootMissing,
        message: format!("terminal cwd `{}` is unavailable: {e}", path.display()),
    })?;
    if !canonical.is_dir() {
        return Err(ErrorPayload {
            code: ErrorCode::RootMissing,
            message: format!("terminal cwd `{}` is not a directory", path.display()),
        });
    }
    Ok(canonical)
}

fn default_shell() -> String {
    #[cfg(windows)]
    {
        std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string())
    }
    #[cfg(not(windows))]
    {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
    }
}

fn ensure_open(state: &TerminalState, terminal_id: Uuid) -> std::result::Result<(), ErrorPayload> {
    if state.closed {
        Err(unknown_terminal(terminal_id))
    } else {
        Ok(())
    }
}

fn bracketed_paste_bytes(text: &str) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(BRACKETED_PASTE_START.len() + text.len() + BRACKETED_PASTE_END.len());
    out.extend_from_slice(BRACKETED_PASTE_START);
    out.extend_from_slice(text.as_bytes());
    out.extend_from_slice(BRACKETED_PASTE_END);
    out
}

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::BadRequest,
        message: message.into(),
    }
}

fn unknown_terminal(terminal_id: Uuid) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::BadRequest,
        message: format!("unknown terminal {terminal_id}"),
    }
}

fn internal<E: std::fmt::Display>(err: E) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Internal,
        message: format!("{err:#}"),
    }
}

fn prepare_temp_root(temp_root: &Path) {
    let _ = std::fs::remove_dir_all(temp_root);
    let _ = std::fs::create_dir_all(temp_root);
    let _ = set_private_dir_permissions(temp_root);
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osc52_is_extracted_and_stripped_across_chunks() {
        let mut filter = TerminalOutputFilter::default();
        let first = filter.push(b"before \x1b]52;c;");
        assert_eq!(first.passthrough, b"before ".to_vec());
        assert!(first.clipboards.is_empty());
        let second = filter.push(b"aGVsbG8=\x07 after");
        assert_eq!(second.passthrough, b" after".to_vec());
        assert_eq!(second.clipboards, vec!["hello".to_string()]);
    }

    #[test]
    fn decrqm_response_is_stripped() {
        let mut filter = TerminalOutputFilter::default();
        let out = filter.push(b"a\x1b[?2004;1$yb");
        assert_eq!(out.passthrough, b"ab".to_vec());
    }

    #[test]
    fn replay_buffer_drops_oldest_bytes() {
        let mut buffer = ReplayBuffer::new(5);
        buffer.push(b"abc");
        buffer.push(b"def");
        assert_eq!(buffer.len(), 5);
        assert_eq!(buffer.bytes(), b"bcdef".to_vec());
        buffer.push(b"1234567");
        assert_eq!(buffer.bytes(), b"34567".to_vec());
    }

    #[test]
    fn bracketed_paste_wraps_path() {
        assert_eq!(
            bracketed_paste_bytes("/tmp/img.png"),
            b"\x1b[200~/tmp/img.png\x1b[201~".to_vec()
        );
    }

    #[test]
    fn startup_sweeps_stale_temp_root() {
        let (tx, _rx) = broadcast::channel(16);
        let tmp = tempfile::tempdir().unwrap();
        let temp_root = tmp.path().join("terms");
        let stale_dir = temp_root.join("term-stale");
        std::fs::create_dir_all(&stale_dir).unwrap();
        std::fs::write(stale_dir.join("paste-1.png"), b"old").unwrap();

        let _host = TerminalHost::new_for_test(tx, temp_root.clone());

        assert!(temp_root.exists());
        assert!(!stale_dir.exists());
    }

    #[cfg(unix)]
    #[test]
    fn paste_image_writes_private_file_and_injects_path() {
        use std::os::unix::fs::PermissionsExt;
        let (tx, _rx) = broadcast::channel(16);
        let tmp = tempfile::tempdir().unwrap();
        let host = TerminalHost::new_for_test(tx, tmp.path().join("terms"));
        let Response::TerminalOpened { terminal_id, .. } = host
            .open(Some(tmp.path().to_string_lossy().into_owned()), 80, 24)
            .unwrap()
        else {
            panic!("expected terminal opened");
        };
        let bytes = b"not really png";
        let Response::TerminalPasteImage { path, .. } =
            host.paste_image(terminal_id, bytes).unwrap()
        else {
            panic!("expected paste image response");
        };
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = host.close(terminal_id);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn open_input_resize_close_round_trip() {
        let (tx, mut rx) = broadcast::channel(64);
        let tmp = tempfile::tempdir().unwrap();
        let host = TerminalHost::new_for_test(tx, tmp.path().join("terms"));
        let Response::TerminalOpened { terminal_id, .. } = host
            .open(Some(tmp.path().to_string_lossy().into_owned()), 80, 24)
            .unwrap()
        else {
            panic!("expected terminal opened");
        };

        host.input(terminal_id, b"printf COCKPIT_REMOTE_OK\n".to_vec())
            .unwrap();
        host.resize(terminal_id, 100, 30).unwrap();

        let mut seen = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            if let Ok(Ok(envelope)) =
                tokio::time::timeout(Duration::from_millis(250), rx.recv()).await
                && let proto::Event::TerminalOutput {
                    terminal_id: id,
                    bytes,
                } = envelope.event
                && id == terminal_id
            {
                seen.extend(bytes);
                if String::from_utf8_lossy(&seen).contains("COCKPIT_REMOTE_OK") {
                    break;
                }
            }
        }
        assert!(
            String::from_utf8_lossy(&seen).contains("COCKPIT_REMOTE_OK"),
            "did not see shell output; got {:?}",
            String::from_utf8_lossy(&seen)
        );

        host.close(terminal_id).unwrap();
    }

    #[test]
    fn idle_sweep_closes_detached_terminal() {
        let (tx, _rx) = broadcast::channel(16);
        let tmp = tempfile::tempdir().unwrap();
        let host = TerminalHost::new_for_test(tx, tmp.path().join("terms"));
        let id = Uuid::new_v4();
        let terminal = Arc::new(Mutex::new(TerminalState::new_test(
            id,
            tmp.path().join("term"),
        )));
        {
            let mut state = crate::sync::lock_or_recover(&terminal);
            state.viewer_count = 0;
            state.last_detached = Some(Instant::now() - TERMINAL_IDLE_TTL - Duration::from_secs(1));
        }
        crate::sync::lock_or_recover(&host.inner)
            .terminals
            .insert(id, terminal);
        let closed = host.sweep_idle(Instant::now());
        assert_eq!(closed, vec![id]);
        assert!(!host.contains(id));
    }

    impl TerminalState {
        fn new_test(id: Uuid, temp_dir: PathBuf) -> Self {
            let pty_system = native_pty_system();
            let pair = pty_system
                .openpty(PtySize {
                    rows: 1,
                    cols: 1,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .unwrap();
            let mut cmd = CommandBuilder::new(default_shell());
            #[cfg(unix)]
            {
                cmd.arg("-c");
                cmd.arg("sleep 60");
            }
            let child = pair.slave.spawn_command(cmd).unwrap();
            drop(pair.slave);
            let master = pair.master;
            let writer = master.take_writer().unwrap();
            Self {
                id,
                master,
                writer,
                child,
                buffer: ReplayBuffer::new(REPLAY_BUFFER_BYTES),
                filter: TerminalOutputFilter::default(),
                viewer_count: 1,
                temp_dir,
                paste_counter: 0,
                closed: false,
                last_detached: None,
            }
        }
    }
}
