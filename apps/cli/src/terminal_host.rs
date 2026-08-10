//! Daemon-side remote terminal host: PTY spawn, OSC 52 filtering, and
//! generation-bound session close.
//!
//! OSC 52 candidates are fail-closed: complete in-cap sequences are always
//! stripped from display bytes; only the exact host grammar emits a clipboard
//! event. Exceeding [`cockpit_proto::terminal::OSC52_MAX_SEQUENCE_BYTES`]
//! invokes the one terminal-generation close oracle immediately — there is
//! no discard/resync mode and no wall-clock timeout.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine as _;
use cockpit_proto::terminal::{
    OSC52_MAX_SEQUENCE_BYTES, TERMINAL_INGRESS_MAX_BYTES, TERMINAL_INGRESS_MAX_CHUNK_BYTES,
    TerminalBinding, TerminalImageType, TerminalIngressMetadata, TerminalIngressReceipt,
    TerminalIngressState,
};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use sha2::{Digest, Sha256};
#[cfg(test)]
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::daemon::proto::{self, ErrorCode, ErrorPayload, Response};
use crate::daemon::terminal::AuthenticatedTerminalContext;
use crate::daemon::{EventSender, SharedRedactionTable, send_current_event};
#[cfg(test)]
use crate::redact::RedactionTable;
#[cfg(test)]
use cockpit_core::process_containment::{ContainmentLease, EmptyOutcome, ProcessContainmentHandle};

const REPLAY_BUFFER_BYTES: usize = 256 * 1024;
const OUTPUT_CHUNK_BYTES: usize = 32 * 1024;
const MAX_TERMINALS: usize = 4;
const TERMINAL_IDLE_TTL: Duration = Duration::from_secs(10 * 60);
const TERMINAL_INPUT_CAP: usize = 1024 * 1024;
const TERMINAL_INPUT_QUEUE_CAP: usize = 64;
const BRACKETED_PASTE_START: &[u8] = b"\x1b[200~";
const BRACKETED_PASTE_END: &[u8] = b"\x1b[201~";
const INGRESS_JOURNAL_CAP: usize = 64;
const INGRESS_TTL: Duration = Duration::from_secs(10 * 60);
#[cfg(test)]
static NEXT_LOCAL_TERMINAL_CONNECTION_EPOCH: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct IngressOperation {
    metadata: TerminalIngressMetadata,
    binding: TerminalBinding,
    bytes: Vec<u8>,
    state: TerminalIngressState,
    input_sequence: Option<u64>,
    created_at: Instant,
    committed_at: Option<Instant>,
    path: Option<PathBuf>,
    verified_file: Option<cockpit_config::config::VerifiedTerminalIngressFile>,
    binding_dir: PathBuf,
    owner: AuthenticatedTerminalContext,
    session_id: Uuid,
}

#[derive(Debug, Clone)]
struct BindingRecord {
    epoch: u64,
    owner: AuthenticatedTerminalContext,
    session_id: Uuid,
}

/// Content-free terminal close outcome for one generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalCloseOutcome {
    /// Containment empty oracle returned same-generation ProvenEmpty and
    /// leader reap completed without durable recovery needs.
    Clean,
    /// Generation is irreversibly closed but containment was Unsupported,
    /// Uncertain, timed out, or absent — never reported clean or reopened.
    CloseBlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseTrigger {
    ClientClose,
    ProcessExited,
    Osc52Overflow,
}

impl CloseTrigger {
    fn reason(self, outcome: TerminalCloseOutcome) -> &'static str {
        match (self, outcome) {
            (Self::ClientClose, TerminalCloseOutcome::Clean) => "closed",
            (Self::ClientClose, TerminalCloseOutcome::CloseBlocked) => "closed_close_blocked",
            (Self::ProcessExited, TerminalCloseOutcome::Clean) => "exited",
            (Self::ProcessExited, TerminalCloseOutcome::CloseBlocked) => "exited_close_blocked",
            (Self::Osc52Overflow, TerminalCloseOutcome::Clean) => "osc52_protocol_violation",
            (Self::Osc52Overflow, TerminalCloseOutcome::CloseBlocked) => {
                "osc52_protocol_violation_close_blocked"
            }
        }
    }
}

/// Optional generation-bound containment binding. Tests inject a real
/// [`ContainmentLease`]; production open currently leaves this empty until
/// PTY placement is owned by the containment actor.
#[cfg(test)]
struct TerminalContainmentBinding {
    handle: ProcessContainmentHandle,
    lease: ContainmentLease,
    /// When set, await_empty is treated as this outcome instead of calling
    /// the actor (used for Uncertain/timeout race branches).
    force_empty_outcome: Option<EmptyOutcome>,
    /// Simulated await deadline expiry.
    force_timeout: bool,
}

#[derive(Clone)]
pub struct TerminalHost {
    inner: Arc<Mutex<TerminalHostInner>>,
    event_tx: EventSender,
    redaction: SharedRedactionTable,
    temp_root: PathBuf,
    idle_ttl: Duration,
    #[cfg(test)]
    #[allow(clippy::type_complexity)]
    ingress_barrier: Arc<Mutex<Option<Arc<dyn Fn(IngressMutationEdge, &Path) + Send + Sync>>>>,
}

impl std::fmt::Debug for TerminalHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TerminalHost")
            .field("temp_root", &self.temp_root)
            .field("idle_ttl", &self.idle_ttl)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IngressMutationEdge {
    BeforePublish,
    AfterPublish,
    AfterFinalVerification,
    BeforeReserve,
    AfterReserve,
}

#[derive(Debug, Default)]
struct TerminalHostInner {
    terminals: HashMap<Uuid, Arc<Mutex<TerminalState>>>,
}

struct TerminalState {
    id: Uuid,
    /// Exact terminal generation. Tombstoned generations never reopen.
    generation: u64,
    master: Option<Box<dyn MasterPty + Send>>,
    input_tx: Option<mpsc::SyncSender<Vec<u8>>>,
    input_cancel: Arc<AtomicBool>,
    input_thread: Option<std::thread::JoinHandle<()>>,
    child: Option<Box<dyn Child + Send + Sync>>,
    buffer: ReplayBuffer,
    filter: TerminalOutputFilter,
    viewer_count: usize,
    temp_dir: PathBuf,
    bindings: HashMap<Uuid, BindingRecord>,
    binding_dirs: HashMap<Uuid, PathBuf>,
    next_binding_epoch: u64,
    ingress: HashMap<Uuid, IngressOperation>,
    input_sequence: u64,
    /// Irreversible tombstone for this generation.
    closed: bool,
    /// Output forwarding cancelled after generation close begins.
    forwarding_cancelled: bool,
    /// Exactly one generation-close transition is recorded.
    close_transitions: u32,
    /// Exactly one content-free Osc52ProtocolViolation for overflow close.
    osc52_violation_emitted: bool,
    close_outcome: Option<TerminalCloseOutcome>,
    last_detached: Option<Instant>,
    #[cfg(test)]
    containment: Option<TerminalContainmentBinding>,
    /// Test double: when true, child.kill/wait are no-ops already done.
    #[cfg(test)]
    test_leader_reaped: bool,
}

impl std::fmt::Debug for TerminalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalState")
            .field("id", &self.id)
            .field("generation", &self.generation)
            .field("viewer_count", &self.viewer_count)
            .field("temp_dir", &self.temp_dir)
            .field("closed", &self.closed)
            .field("close_outcome", &self.close_outcome)
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

// ---- OSC 52 filter --------------------------------------------------------

#[derive(Debug, Default)]
pub struct TerminalOutputFilter {
    pending: Vec<u8>,
    /// True after overflow: no further candidate or suffix bytes are released.
    overflowed: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct FilteredTerminalOutput {
    pub passthrough: Vec<u8>,
    pub clipboards: Vec<String>,
    /// Candidate would require a 102401st byte — invoke generation close.
    pub overflow: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanMode {
    Normal,
    /// Buffer holds introducer; collecting decimal command digits until `;`
    /// or a decision that this is not OSC 52.
    OscCommand,
    /// Buffer holds introducer + `52;`; collecting payload until terminator.
    Osc52Payload {
        saw_esc: bool,
    },
}

impl TerminalOutputFilter {
    pub fn push(&mut self, bytes: &[u8]) -> FilteredTerminalOutput {
        if self.overflowed {
            return FilteredTerminalOutput {
                passthrough: Vec::new(),
                clipboards: Vec::new(),
                overflow: true,
            };
        }

        let mut input = std::mem::take(&mut self.pending);
        input.extend_from_slice(bytes);
        let mut passthrough = Vec::with_capacity(input.len());
        let mut clipboards = Vec::new();
        let mut i = 0;
        let mut mode = ScanMode::Normal;
        let mut candidate_start = 0usize;

        while i < input.len() {
            match mode {
                ScanMode::Normal => {
                    if input[i] == 0x1b {
                        // Incomplete known prefixes held for the next chunk.
                        if is_incomplete_known_escape_prefix(&input[i..]) {
                            break;
                        }
                        // 7-bit OSC introducer ESC ]
                        if input.get(i + 1) == Some(&b']') {
                            candidate_start = i;
                            mode = ScanMode::OscCommand;
                            i += 2;
                            continue;
                        }
                        // DECRQM private-mode query response strip.
                        if input[i..].starts_with(b"\x1b[?") {
                            if let Some(end) = find_decrqm_response_end(&input, i) {
                                i = end;
                                continue;
                            }
                            if input.len() - i < 128 {
                                break;
                            }
                        }
                        passthrough.push(input[i]);
                        i += 1;
                    } else if input[i] == 0x9d {
                        // Single-byte C1 OSC. UTF-8 `C2 9D` is ordinary data.
                        let prev = if i > 0 {
                            Some(input[i - 1])
                        } else {
                            passthrough.last().copied()
                        };
                        if prev == Some(0xc2) {
                            passthrough.push(input[i]);
                            i += 1;
                        } else {
                            candidate_start = i;
                            mode = ScanMode::OscCommand;
                            i += 1;
                        }
                    } else {
                        passthrough.push(input[i]);
                        i += 1;
                    }
                }
                ScanMode::OscCommand => {
                    // Collect command digits until we know it is / is not `52;`.
                    let cmd_start =
                        candidate_start + if input[candidate_start] == 0x1b { 2 } else { 1 };
                    // Need more bytes to decide?
                    if i >= input.len() {
                        break;
                    }
                    let b = input[i];
                    if b.is_ascii_digit() {
                        // Cap check while still collecting command.
                        let next_len = i - candidate_start + 1;
                        if next_len > OSC52_MAX_SEQUENCE_BYTES {
                            self.overflowed = true;
                            self.pending.clear();
                            return FilteredTerminalOutput {
                                passthrough,
                                clipboards,
                                overflow: true,
                            };
                        }
                        i += 1;
                        continue;
                    }
                    if b == b';' {
                        let digits = &input[cmd_start..i];
                        if digits == b"52" {
                            // Transition to payload collection (include `;`).
                            let next_len = i - candidate_start + 1;
                            if next_len > OSC52_MAX_SEQUENCE_BYTES {
                                self.overflowed = true;
                                self.pending.clear();
                                return FilteredTerminalOutput {
                                    passthrough,
                                    clipboards,
                                    overflow: true,
                                };
                            }
                            i += 1;
                            mode = ScanMode::Osc52Payload { saw_esc: false };
                            continue;
                        }
                        // Not OSC 52 — release introducer..current as plain.
                        passthrough.extend_from_slice(&input[candidate_start..=i]);
                        i += 1;
                        mode = ScanMode::Normal;
                        continue;
                    }
                    // Non-digit, non-semicolon before a valid OSC 52 command:
                    // release as non-OSC52 from introducer through this byte.
                    // Also handle early terminator forms as plain.
                    passthrough.extend_from_slice(&input[candidate_start..=i]);
                    i += 1;
                    mode = ScanMode::Normal;
                }
                ScanMode::Osc52Payload { saw_esc } => {
                    if saw_esc {
                        // Previous byte was ESC; only `\` completes ST.
                        if i >= input.len() {
                            break;
                        }
                        let b = input[i];
                        let next_len = i - candidate_start + 1;
                        if next_len > OSC52_MAX_SEQUENCE_BYTES {
                            self.overflowed = true;
                            self.pending.clear();
                            return FilteredTerminalOutput {
                                passthrough,
                                clipboards,
                                overflow: true,
                            };
                        }
                        if b == b'\\' {
                            // Complete 7-bit ST terminator. Strip always.
                            let end = i + 1;
                            let seq = &input[candidate_start..end];
                            if let Some(text) = parse_osc52_clipboard_event(seq) {
                                clipboards.push(text);
                            }
                            i = end;
                            mode = ScanMode::Normal;
                            continue;
                        }
                        // Malformed: ESC + non-\ remains inside candidate.
                        mode = ScanMode::Osc52Payload { saw_esc: false };
                        i += 1;
                        continue;
                    }

                    if i >= input.len() {
                        break;
                    }
                    let b = input[i];
                    let next_len = i - candidate_start + 1;
                    if next_len > OSC52_MAX_SEQUENCE_BYTES {
                        self.overflowed = true;
                        self.pending.clear();
                        return FilteredTerminalOutput {
                            passthrough,
                            clipboards,
                            overflow: true,
                        };
                    }

                    if b == 0x07 {
                        // BEL terminator.
                        let end = i + 1;
                        let seq = &input[candidate_start..end];
                        if let Some(text) = parse_osc52_clipboard_event(seq) {
                            clipboards.push(text);
                        }
                        i = end;
                        mode = ScanMode::Normal;
                        continue;
                    }
                    if b == 0x9c {
                        // C1 ST terminator. UTF-8 `C2 9C` is ordinary payload
                        // data, not a terminator.
                        let prev = if i > candidate_start {
                            Some(input[i - 1])
                        } else {
                            None
                        };
                        if prev != Some(0xc2) {
                            let end = i + 1;
                            let seq = &input[candidate_start..end];
                            if let Some(text) = parse_osc52_clipboard_event(seq) {
                                clipboards.push(text);
                            }
                            i = end;
                            mode = ScanMode::Normal;
                            continue;
                        }
                    }
                    if b == 0x1b {
                        // Possible start of 7-bit ST; need following byte.
                        if i + 1 >= input.len() {
                            // Hold ESC for next chunk.
                            mode = ScanMode::Osc52Payload { saw_esc: true };
                            i += 1;
                            break;
                        }
                        mode = ScanMode::Osc52Payload { saw_esc: true };
                        i += 1;
                        continue;
                    }
                    // Ordinary candidate byte (nested OSC never resyncs).
                    i += 1;
                }
            }
        }

        // Incomplete candidate / prefix held for next chunk (EOF handled by
        // `finish` / process-exit path which discards pending without event).
        match mode {
            ScanMode::Normal => {
                self.pending.extend_from_slice(&input[i..]);
            }
            ScanMode::OscCommand | ScanMode::Osc52Payload { .. } => {
                // Hold from candidate_start; any plain already emitted.
                self.pending.extend_from_slice(&input[candidate_start..]);
            }
        }

        FilteredTerminalOutput {
            passthrough,
            clipboards,
            overflow: false,
        }
    }

    /// Discard an incomplete in-cap candidate at EOF without a clipboard event.
    pub fn finish(&mut self) {
        self.pending.clear();
    }

    #[cfg(test)]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    #[cfg(test)]
    pub fn has_overflowed(&self) -> bool {
        self.overflowed
    }
}

fn is_incomplete_known_escape_prefix(bytes: &[u8]) -> bool {
    // Hold lone ESC and ESC-only prefixes of known multi-byte forms we parse.
    if bytes.is_empty() {
        return false;
    }
    if bytes[0] != 0x1b {
        return false;
    }
    if bytes.len() == 1 {
        return true;
    }
    // ESC ] … incomplete OSC that has not yet decided command.
    if bytes[1] == b']' {
        return false; // Handled by OscCommand mode (may still hold later).
    }
    // ESC [ ? … DECRQM
    if bytes[1] == b'[' {
        const PREFIX: &[u8] = b"\x1b[?";
        return bytes.len() < PREFIX.len() && PREFIX.starts_with(bytes);
    }
    false
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

/// Parse a complete OSC 52 sequence (including introducer + terminator).
/// Returns decoded UTF-8 clipboard text only for the exact host grammar.
fn parse_osc52_clipboard_event(seq: &[u8]) -> Option<String> {
    let body = osc52_body_after_introducer(seq)?;
    // body is `52;…` without terminator (terminator already excluded).
    if !body.starts_with(b"52;") {
        return None;
    }
    let rest = &body[3..];
    // Exact selector `c` then `;` then payload.
    // rest must be `c;<payload>` with nonempty payload.
    if rest.len() < 2 || rest[0] != b'c' || rest[1] != b';' {
        return None;
    }
    let payload = &rest[2..];
    if payload.is_empty() {
        return None;
    }
    // Payload must be nonempty ASCII canonical STANDARD base64.
    if !payload
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'=')
    {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .ok()?;
    if decoded.is_empty() {
        return None;
    }
    // Exact STANDARD re-encoding must match (canonical padding / pad bits).
    let reencoded = base64::engine::general_purpose::STANDARD.encode(&decoded);
    if reencoded.as_bytes() != payload {
        return None;
    }
    String::from_utf8(decoded).ok()
}

/// Strip introducer and terminator from a complete OSC sequence, returning
/// the interior starting at the command digits.
fn osc52_body_after_introducer(seq: &[u8]) -> Option<&[u8]> {
    if seq.len() < 4 {
        return None;
    }
    let (after_intro, term_len) = if seq[0] == 0x1b && seq.get(1) == Some(&b']') {
        (2usize, osc_terminator_len(seq)?)
    } else if seq[0] == 0x9d {
        (1usize, osc_terminator_len(seq)?)
    } else {
        return None;
    };
    if seq.len() < after_intro + term_len {
        return None;
    }
    Some(&seq[after_intro..seq.len() - term_len])
}

fn osc_terminator_len(seq: &[u8]) -> Option<usize> {
    if seq.last() == Some(&0x07) {
        return Some(1);
    }
    if seq.last() == Some(&0x9c) {
        return Some(1);
    }
    if seq.len() >= 2 && seq[seq.len() - 2] == 0x1b && seq[seq.len() - 1] == b'\\' {
        return Some(2);
    }
    None
}

// ---- Host -----------------------------------------------------------------

impl TerminalHost {
    pub fn new(event_tx: EventSender, redaction: SharedRedactionTable, temp_root: PathBuf) -> Self {
        prepare_temp_root(&temp_root);
        Self {
            inner: Arc::new(Mutex::new(TerminalHostInner::default())),
            event_tx,
            redaction,
            temp_root,
            idle_ttl: TERMINAL_IDLE_TTL,
            #[cfg(test)]
            ingress_barrier: Arc::new(Mutex::new(None)),
        }
    }

    #[cfg(test)]
    pub fn new_for_test(event_tx: EventSender, temp_root: PathBuf) -> Self {
        let redaction = Arc::new(std::sync::RwLock::new(Arc::new(RedactionTable::empty())));
        Self::new(event_tx, redaction, temp_root)
    }

    #[cfg(test)]
    pub fn open(
        &self,
        cwd: Option<String>,
        cols: u16,
        rows: u16,
    ) -> std::result::Result<Response, ErrorPayload> {
        self.open_with_context(test_local_terminal_context(), Uuid::nil(), cwd, cols, rows)
    }

    fn open_with_context(
        &self,
        context: AuthenticatedTerminalContext,
        session_id: Uuid,
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
            .insert(id, terminal.clone());
        let (binding, terminal_generation) = issue_binding(
            &mut crate::sync::lock_or_recover(&terminal),
            context,
            session_id,
        );
        Ok(Response::TerminalOpened {
            terminal_id: id,
            viewer_count: 1,
            recording: false,
            binding,
            terminal_generation,
        })
    }

    #[cfg(test)]
    pub fn attach(
        &self,
        terminal_id: Uuid,
        cols: u16,
        rows: u16,
    ) -> std::result::Result<Response, ErrorPayload> {
        self.attach_with_context(
            test_local_terminal_context(),
            Uuid::nil(),
            terminal_id,
            cols,
            rows,
        )
    }

    fn attach_with_context(
        &self,
        context: AuthenticatedTerminalContext,
        session_id: Uuid,
        terminal_id: Uuid,
        cols: u16,
        rows: u16,
    ) -> std::result::Result<Response, ErrorPayload> {
        let terminal = self.get_terminal(terminal_id)?;
        let (viewer_count, replay, binding, terminal_generation) = {
            let mut state = crate::sync::lock_or_recover(&terminal);
            if state.closed {
                return Err(unknown_terminal(terminal_id));
            }
            state.viewer_count = state.viewer_count.saturating_add(1);
            state.last_detached = None;
            resize_locked(&mut state, cols, rows);
            let (binding, generation) = issue_binding(&mut state, context, session_id);
            (
                state.viewer_count,
                state.buffer.bytes(),
                binding,
                generation,
            )
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
            binding,
            terminal_generation,
        })
    }

    pub fn release_viewer(&self, terminal_id: Uuid, binding: TerminalBinding) {
        let Ok(terminal) = self.get_terminal(terminal_id) else {
            return;
        };
        let count = {
            let mut state = crate::sync::lock_or_recover(&terminal);
            if !state
                .bindings
                .get(&binding.binding_id)
                .is_some_and(|record| record.epoch == binding.binding_epoch)
            {
                return;
            }
            state.bindings.remove(&binding.binding_id);
            state.viewer_count = state.viewer_count.saturating_sub(1);
            if state.viewer_count == 0 {
                state.last_detached = Some(Instant::now());
            }
            state.viewer_count
        };
        self.emit(proto::Event::TerminalViewers { terminal_id, count });
    }

    #[cfg(test)]
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
        let state = crate::sync::lock_or_recover(&terminal);
        ensure_open(&state, terminal_id)?;
        reserve_input_locked(&state, bytes).map_err(internal)?;
        Ok(Response::Ack)
    }

    fn input_bound(
        &self,
        terminal_id: Uuid,
        binding: TerminalBinding,
        bytes: Vec<u8>,
    ) -> std::result::Result<Response, ErrorPayload> {
        let terminal = self.get_terminal(terminal_id)?;
        let state = crate::sync::lock_or_recover(&terminal);
        authorize_binding(&state, binding)?;
        if bytes.len() > TERMINAL_INPUT_CAP {
            return Err(invalid_ingress());
        }
        reserve_input_locked(&state, bytes).map_err(|_| invalid_ingress())?;
        Ok(Response::Ack)
    }

    fn resize_bound(
        &self,
        terminal_id: Uuid,
        binding: TerminalBinding,
        cols: u16,
        rows: u16,
    ) -> std::result::Result<Response, ErrorPayload> {
        let terminal = self.get_terminal(terminal_id)?;
        let mut state = crate::sync::lock_or_recover(&terminal);
        authorize_binding(&state, binding)?;
        resize_locked(&mut state, cols, rows);
        Ok(Response::Ack)
    }

    fn close_bound(
        &self,
        terminal_id: Uuid,
        binding: TerminalBinding,
    ) -> std::result::Result<Response, ErrorPayload> {
        let terminal = self.get_terminal(terminal_id)?;
        authorize_binding(&crate::sync::lock_or_recover(&terminal), binding)?;
        self.close(terminal_id)
    }

    #[cfg(test)]
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
            let inner = crate::sync::lock_or_recover(&self.inner);
            // Keep the map entry until after close oracle so concurrent
            // overflow/exit races share one transition; remove after.
            inner
                .terminals
                .get(&terminal_id)
                .cloned()
                .ok_or_else(|| unknown_terminal(terminal_id))?
        };
        {
            let mut state = crate::sync::lock_or_recover(&terminal);
            let _ = close_generation_locked(
                &mut state,
                CloseTrigger::ClientClose,
                &self.event_tx,
                &self.redaction,
            );
        }
        crate::sync::lock_or_recover(&self.inner)
            .terminals
            .remove(&terminal_id);
        Ok(Response::Ack)
    }

    pub fn ingress_begin(
        &self,
        terminal_id: Uuid,
        binding: TerminalBinding,
        metadata: TerminalIngressMetadata,
    ) -> std::result::Result<Response, ErrorPayload> {
        let terminal = self.get_terminal(terminal_id)?;
        let mut state = crate::sync::lock_or_recover(&terminal);
        authorize_binding(&state, binding)?;
        sweep_ingress_locked(&mut state);
        if metadata.operation_id.get_version_num() != 4
            || !(1..=TERMINAL_INGRESS_MAX_BYTES).contains(&metadata.size)
            || !is_sha256_hex(&metadata.sha256)
        {
            return Err(invalid_ingress());
        }
        if let Some(operation) = state.ingress.get(&metadata.operation_id) {
            if operation.binding != binding
                && state.bindings.contains_key(&operation.binding.binding_id)
            {
                return Err(invalid_ingress());
            }
            if operation.metadata != metadata {
                return Err(ingress_conflict());
            }
            if operation.binding != binding {
                let new_owner = state
                    .bindings
                    .get(&binding.binding_id)
                    .cloned()
                    .ok_or_else(invalid_ingress)?;
                if new_owner.owner.principal_id != operation.owner.principal_id
                    || new_owner.owner.client_instance_id != operation.owner.client_instance_id
                    || new_owner.session_id != operation.session_id
                    || new_owner.owner.connection_epoch <= operation.owner.connection_epoch
                {
                    return Err(invalid_ingress());
                }
                let operation = state
                    .ingress
                    .get_mut(&metadata.operation_id)
                    .expect("operation exists");
                operation.binding = binding;
                operation.owner = new_owner.owner;
            }
            return Ok(ingress_response(
                state
                    .ingress
                    .get(&metadata.operation_id)
                    .expect("operation exists"),
            ));
        }
        if state.ingress.len() >= INGRESS_JOURNAL_CAP
            || state.ingress.values().any(|operation| {
                operation.state == TerminalIngressState::Prepared && operation.binding == binding
            })
        {
            return Err(invalid_ingress());
        }
        let binding_record = state
            .bindings
            .get(&binding.binding_id)
            .cloned()
            .ok_or_else(invalid_ingress)?;
        let binding_dir = state
            .binding_dirs
            .get(&binding.binding_id)
            .cloned()
            .ok_or_else(invalid_ingress)?;
        state.ingress.insert(
            metadata.operation_id,
            IngressOperation {
                metadata: metadata.clone(),
                binding,
                bytes: Vec::with_capacity(metadata.size as usize),
                state: TerminalIngressState::Prepared,
                input_sequence: None,
                created_at: Instant::now(),
                committed_at: None,
                path: None,
                verified_file: None,
                binding_dir,
                owner: binding_record.owner,
                session_id: binding_record.session_id,
            },
        );
        Ok(ingress_response(
            state.ingress.get(&metadata.operation_id).expect("inserted"),
        ))
    }

    pub fn ingress_chunk(
        &self,
        terminal_id: Uuid,
        binding: TerminalBinding,
        operation_id: Uuid,
        offset: u64,
        bytes: Vec<u8>,
    ) -> std::result::Result<Response, ErrorPayload> {
        if bytes.is_empty() || bytes.len() > TERMINAL_INGRESS_MAX_CHUNK_BYTES {
            return Err(invalid_ingress());
        }
        let terminal = self.get_terminal(terminal_id)?;
        let mut state = crate::sync::lock_or_recover(&terminal);
        authorize_binding(&state, binding)?;
        sweep_ingress_locked(&mut state);
        let operation = state
            .ingress
            .get_mut(&operation_id)
            .ok_or_else(invalid_ingress)?;
        if operation.binding != binding
            || operation.state != TerminalIngressState::Prepared
            || offset != operation.bytes.len() as u64
            || offset.saturating_add(bytes.len() as u64) > operation.metadata.size
        {
            return Err(invalid_ingress());
        }
        operation.bytes.extend_from_slice(&bytes);
        Ok(ingress_response(operation))
    }

    pub fn ingress_status(
        &self,
        terminal_id: Uuid,
        binding: TerminalBinding,
        operation_id: Uuid,
    ) -> std::result::Result<Response, ErrorPayload> {
        let terminal = self.get_terminal(terminal_id)?;
        let mut state = crate::sync::lock_or_recover(&terminal);
        authorize_binding(&state, binding)?;
        sweep_ingress_locked(&mut state);
        let operation = state
            .ingress
            .get(&operation_id)
            .ok_or_else(invalid_ingress)?;
        if operation.binding != binding {
            return Err(invalid_ingress());
        }
        Ok(ingress_response(operation))
    }

    pub fn ingress_finish(
        &self,
        terminal_id: Uuid,
        binding: TerminalBinding,
        operation_id: Uuid,
    ) -> std::result::Result<Response, ErrorPayload> {
        let terminal = self.get_terminal(terminal_id)?;
        let mut state = crate::sync::lock_or_recover(&terminal);
        authorize_binding(&state, binding)?;
        sweep_ingress_locked(&mut state);
        if let Some(operation) = state.ingress.get(&operation_id)
            && operation.binding == binding
            && operation.state == TerminalIngressState::Committed
        {
            return Ok(ingress_response(operation));
        }
        let (metadata, bytes) = {
            let operation = state
                .ingress
                .get(&operation_id)
                .ok_or_else(invalid_ingress)?;
            if operation.binding != binding
                || operation.bytes.len() as u64 != operation.metadata.size
            {
                return Err(invalid_ingress());
            }
            (operation.metadata.clone(), operation.bytes.clone())
        };
        validate_image(&metadata, &bytes)?;
        let binding_dir = state
            .ingress
            .get(&operation_id)
            .ok_or_else(invalid_ingress)?
            .binding_dir
            .clone();
        let name = format!("{}.{}", random_base32(), metadata.media_type.extension());
        let final_path = binding_dir.join(name);
        let path_text = final_path.to_str().ok_or_else(ingress_path_unavailable)?;
        validate_path_text(path_text)?;
        cockpit_config::config::ensure_terminal_ingress_private_dir(&binding_dir)
            .map_err(internal)?;
        #[cfg(test)]
        self.hit_ingress_barrier(IngressMutationEdge::BeforePublish, &final_path);
        let published_identity =
            cockpit_config::config::write_terminal_ingress_private_file(&final_path, &bytes)
                .map_err(internal)?;
        #[cfg(test)]
        self.hit_ingress_barrier(IngressMutationEdge::AfterPublish, &final_path);
        let (verified, verified_file) = match read_verified_final(&final_path, metadata.size) {
            Ok(verified) => verified,
            Err(error) => {
                remove_if_same_identity(&final_path, Some(published_identity));
                return Err(error);
            }
        };
        if let Err(error) = validate_image(&metadata, &verified) {
            drop(verified_file);
            return Err(error);
        }
        #[cfg(test)]
        self.hit_ingress_barrier(IngressMutationEdge::AfterFinalVerification, &final_path);
        if let Err(error) = authorize_binding(&state, binding) {
            drop(verified_file);
            return Err(error);
        }
        let frame = bracketed_paste_bytes(&shell_path_literal(path_text, host_shell_dialect())?);
        #[cfg(test)]
        self.hit_ingress_barrier(IngressMutationEdge::BeforeReserve, &final_path);
        if let Err(error) = reserve_input_locked(&state, frame) {
            drop(verified_file);
            return Err(internal(error));
        }
        state.input_sequence = state.input_sequence.saturating_add(1);
        let sequence = state.input_sequence;
        let operation = state
            .ingress
            .get_mut(&operation_id)
            .ok_or_else(invalid_ingress)?;
        operation.state = TerminalIngressState::Committed;
        operation.input_sequence = Some(sequence);
        operation.committed_at = Some(Instant::now());
        operation.path = Some(final_path);
        operation.verified_file = Some(verified_file);
        operation.bytes.clear();
        #[cfg(test)]
        self.hit_ingress_barrier(
            IngressMutationEdge::AfterReserve,
            operation.path.as_deref().expect("committed path"),
        );
        Ok(ingress_response(operation))
    }

    #[cfg(test)]
    fn hit_ingress_barrier(&self, edge: IngressMutationEdge, path: &Path) {
        let hook = crate::sync::lock_or_recover(&self.ingress_barrier).clone();
        if let Some(hook) = hook {
            hook(edge, path);
        }
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
                    let mut state = crate::sync::lock_or_recover(terminal);
                    sweep_ingress_locked(&mut state);
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

    /// Feed PTY output through the filter and generation-close path.
    /// Shared by the reader thread and overflow tests.
    fn handle_pty_bytes(
        terminal: &Arc<Mutex<TerminalState>>,
        event_tx: &EventSender,
        redaction: &SharedRedactionTable,
        bytes: &[u8],
    ) {
        let (filtered, terminal_id) = {
            let mut state = crate::sync::lock_or_recover(terminal);
            if state.closed || state.forwarding_cancelled {
                return;
            }
            let filtered = state.filter.push(bytes);
            // Plain bytes before an overflowing candidate remain deliverable.
            if !filtered.passthrough.is_empty() {
                state.buffer.push(&filtered.passthrough);
            }
            let id = state.id;
            if filtered.overflow {
                let passthrough = filtered.passthrough.clone();
                let clipboards = filtered.clipboards.clone();
                // Emit safe pre-overflow output first, then close. No candidate
                // or suffix bytes are present in passthrough on overflow.
                drop(state);
                for chunk in passthrough.chunks(OUTPUT_CHUNK_BYTES) {
                    send_current_event(
                        event_tx,
                        redaction,
                        proto::Event::TerminalOutput {
                            terminal_id: id,
                            bytes: chunk.to_vec(),
                        },
                    );
                }
                for text in clipboards {
                    send_current_event(
                        event_tx,
                        redaction,
                        proto::Event::TerminalClipboard {
                            terminal_id: id,
                            text,
                        },
                    );
                }
                let mut state = crate::sync::lock_or_recover(terminal);
                let _ = close_generation_locked(
                    &mut state,
                    CloseTrigger::Osc52Overflow,
                    event_tx,
                    redaction,
                );
                return;
            }
            (filtered, id)
        };
        for chunk in filtered.passthrough.chunks(OUTPUT_CHUNK_BYTES) {
            send_current_event(
                event_tx,
                redaction,
                proto::Event::TerminalOutput {
                    terminal_id,
                    bytes: chunk.to_vec(),
                },
            );
        }
        for text in filtered.clipboards {
            let still_open = {
                let state = crate::sync::lock_or_recover(terminal);
                !state.closed && !state.forwarding_cancelled
            };
            if !still_open {
                return;
            }
            send_current_event(
                event_tx,
                redaction,
                proto::Event::TerminalClipboard { terminal_id, text },
            );
        }
    }
}

/// One linearized terminal-generation close oracle.
///
/// Tombstones the exact generation, rejects new input/attachments, closes
/// PTY writer/reader/master handles, cancels output forwarding, terminates
/// the generation-bound containment lease when present, waits for the
/// same-generation ProvenEmpty oracle (or records CloseBlocked), reaps the
/// PTY leader, and emits at most one content-free Osc52ProtocolViolation
/// plus one TerminalClosed outcome. Idempotent under concurrent client
/// close / PTY EOF / leader exit / overflow.
fn close_generation_locked(
    state: &mut TerminalState,
    trigger: CloseTrigger,
    event_tx: &EventSender,
    redaction: &SharedRedactionTable,
) -> TerminalCloseOutcome {
    if state.closed {
        return state
            .close_outcome
            .unwrap_or(TerminalCloseOutcome::CloseBlocked);
    }

    // Tombstone first so concurrent paths observe closed.
    state.closed = true;
    state.forwarding_cancelled = true;
    state.close_transitions = state.close_transitions.saturating_add(1);
    state.filter.finish();

    // Close PTY writer/master handles (reader is cancelled via closed flag).
    state.input_cancel.store(true, Ordering::Release);
    state.input_tx.take();
    if let Some(input_thread) = state.input_thread.take() {
        let _ = input_thread.join();
    }
    state.master.take();

    // Containment terminate + same-generation empty oracle when a lease is
    // bound. Without a lease (production until PTY placement is actor-owned)
    // successful leader reap is Clean for ordinary close/exit; overflow still
    // emits the content-free violation. Injected Uncertain/Unsupported/timeout
    // bindings force CloseBlocked and never clean.
    #[cfg(test)]
    let outcome = {
        if let Some(binding) = state.containment.take() {
            run_containment_close(binding)
        } else {
            TerminalCloseOutcome::Clean
        }
    };
    #[cfg(not(test))]
    let outcome = TerminalCloseOutcome::Clean;

    // Reap PTY leader. Prefer try_wait after kill so a stuck wait cannot
    // block the close oracle indefinitely under test load.
    if let Some(mut child) = state.child.take() {
        let _ = child.kill();
        for _ in 0..50 {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
        let _ = child.wait();
    }
    #[cfg(test)]
    {
        state.test_leader_reaped = true;
    }

    // Only overflow emits Osc52ProtocolViolation, and only once.
    if matches!(trigger, CloseTrigger::Osc52Overflow) && !state.osc52_violation_emitted {
        state.osc52_violation_emitted = true;
        send_current_event(
            event_tx,
            redaction,
            proto::Event::Osc52ProtocolViolation {
                terminal_id: state.id,
                generation: state.generation,
            },
        );
    }

    state.close_outcome = Some(outcome);
    let reason = trigger.reason(outcome).to_string();
    send_current_event(
        event_tx,
        redaction,
        proto::Event::TerminalClosed {
            terminal_id: state.id,
            reason,
            exit_code: None,
        },
    );

    // Drop held verified handles first so each exact committed object is
    // scrubbed without a racy pathname unlink before directory teardown.
    state.ingress.clear();
    let _ = std::fs::remove_dir_all(&state.temp_dir);
    outcome
}

#[cfg(test)]
fn run_containment_close(binding: TerminalContainmentBinding) -> TerminalCloseOutcome {
    let TerminalContainmentBinding {
        handle,
        lease,
        force_empty_outcome,
        force_timeout,
    } = binding;
    let generation = lease.generation();

    if force_timeout {
        return TerminalCloseOutcome::CloseBlocked;
    }

    // Always run on a dedicated thread so this is safe both from the PTY
    // reader thread and from inside a tokio test runtime.
    let handle2 = handle.clone();
    let lease2 = lease.clone();
    let term = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("containment helper runtime");
        rt.block_on(handle2.terminate(lease2))
    })
    .join()
    .expect("containment terminate join");
    if term.is_err() {
        return TerminalCloseOutcome::CloseBlocked;
    }

    let empty = if let Some(forced) = force_empty_outcome {
        forced
    } else {
        match std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("containment helper runtime");
            rt.block_on(handle.await_empty(lease))
        })
        .join()
        .expect("containment await_empty join")
        {
            Ok(o) => o,
            Err(_) => return TerminalCloseOutcome::CloseBlocked,
        }
    };

    match empty {
        EmptyOutcome::ProvenEmpty { generation: g } if g == generation => {
            TerminalCloseOutcome::Clean
        }
        EmptyOutcome::ProvenEmpty { .. }
        | EmptyOutcome::Uncertain { .. }
        | EmptyOutcome::Unsupported { .. } => TerminalCloseOutcome::CloseBlocked,
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
        context: AuthenticatedTerminalContext,
        session_id: Uuid,
        cwd: Option<String>,
        cols: u16,
        rows: u16,
    ) -> crate::daemon::terminal::TerminalResult {
        TerminalHost::open_with_context(self, context, session_id, cwd, cols, rows)
    }

    fn attach(
        &self,
        context: AuthenticatedTerminalContext,
        session_id: Uuid,
        terminal_id: Uuid,
        cols: u16,
        rows: u16,
    ) -> crate::daemon::terminal::TerminalResult {
        TerminalHost::attach_with_context(self, context, session_id, terminal_id, cols, rows)
    }

    fn release_viewer(&self, terminal_id: Uuid, binding: TerminalBinding) {
        TerminalHost::release_viewer(self, terminal_id, binding);
    }

    fn input(
        &self,
        terminal_id: Uuid,
        binding: TerminalBinding,
        bytes: Vec<u8>,
    ) -> crate::daemon::terminal::TerminalResult {
        TerminalHost::input_bound(self, terminal_id, binding, bytes)
    }

    fn resize(
        &self,
        terminal_id: Uuid,
        binding: TerminalBinding,
        cols: u16,
        rows: u16,
    ) -> crate::daemon::terminal::TerminalResult {
        TerminalHost::resize_bound(self, terminal_id, binding, cols, rows)
    }

    fn close(
        &self,
        terminal_id: Uuid,
        binding: TerminalBinding,
    ) -> crate::daemon::terminal::TerminalResult {
        TerminalHost::close_bound(self, terminal_id, binding)
    }

    fn ingress_begin(
        &self,
        terminal_id: Uuid,
        binding: TerminalBinding,
        metadata: TerminalIngressMetadata,
    ) -> crate::daemon::terminal::TerminalResult {
        TerminalHost::ingress_begin(self, terminal_id, binding, metadata)
    }
    fn ingress_chunk(
        &self,
        terminal_id: Uuid,
        binding: TerminalBinding,
        operation_id: Uuid,
        offset: u64,
        bytes: Vec<u8>,
    ) -> crate::daemon::terminal::TerminalResult {
        TerminalHost::ingress_chunk(self, terminal_id, binding, operation_id, offset, bytes)
    }
    fn ingress_finish(
        &self,
        terminal_id: Uuid,
        binding: TerminalBinding,
        operation_id: Uuid,
    ) -> crate::daemon::terminal::TerminalResult {
        TerminalHost::ingress_finish(self, terminal_id, binding, operation_id)
    }
    fn ingress_status(
        &self,
        terminal_id: Uuid,
        binding: TerminalBinding,
        operation_id: Uuid,
    ) -> crate::daemon::terminal::TerminalResult {
        TerminalHost::ingress_status(self, terminal_id, binding, operation_id)
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
    let mut writer = master.take_writer().context("take terminal pty writer")?;
    let (input_tx, input_rx) = mpsc::sync_channel::<Vec<u8>>(TERMINAL_INPUT_QUEUE_CAP);
    let input_cancel = Arc::new(AtomicBool::new(false));
    let writer_cancel = Arc::clone(&input_cancel);
    let input_thread = std::thread::Builder::new()
        .name(format!("terminal-input-{id}"))
        .spawn(move || {
            while let Ok(frame) = input_rx.recv() {
                if writer_cancel.load(Ordering::Acquire) {
                    break;
                }
                if writer
                    .write_all(&frame)
                    .and_then(|()| writer.flush())
                    .is_err()
                {
                    break;
                }
            }
        })
        .context("spawn terminal input writer")?;
    let mut reader = master
        .try_clone_reader()
        .context("clone terminal pty reader")?;
    let temp_dir = temp_root.join(random_base32());
    let state = Arc::new(Mutex::new(TerminalState {
        id,
        generation: 1,
        master: Some(master),
        input_tx: Some(input_tx),
        input_cancel,
        input_thread: Some(input_thread),
        child: Some(child),
        buffer: ReplayBuffer::new(REPLAY_BUFFER_BYTES),
        filter: TerminalOutputFilter::default(),
        viewer_count: 1,
        temp_dir,
        bindings: HashMap::new(),
        binding_dirs: HashMap::new(),
        next_binding_epoch: 0,
        ingress: HashMap::new(),
        input_sequence: 0,
        closed: false,
        forwarding_cancelled: false,
        close_transitions: 0,
        osc52_violation_emitted: false,
        close_outcome: None,
        last_detached: None,
        #[cfg(test)]
        containment: None,
        #[cfg(test)]
        test_leader_reaped: false,
    }));

    let reader_state = Arc::clone(&state);
    let reader_redaction = redaction.clone();
    let reader_events = event_tx.clone();
    std::thread::Builder::new()
        .name(format!("cockpit-remote-terminal-{id}"))
        .spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        TerminalHost::handle_pty_bytes(
                            &reader_state,
                            &reader_events,
                            &reader_redaction,
                            &buf[..n],
                        );
                    }
                    Err(_) => break,
                }
            }
            let mut state = crate::sync::lock_or_recover(&reader_state);
            if !state.closed {
                let _ = close_generation_locked(
                    &mut state,
                    CloseTrigger::ProcessExited,
                    &reader_events,
                    &reader_redaction,
                );
            }
        })
        .context("spawn terminal pty reader thread")?;

    Ok(state)
}

fn resize_locked(state: &mut TerminalState, cols: u16, rows: u16) {
    if let Some(master) = state.master.as_ref() {
        let _ = master.resize(PtySize {
            rows: rows.max(1),
            cols: cols.max(1),
            pixel_width: 0,
            pixel_height: 0,
        });
    }
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

fn reserve_input_locked(state: &TerminalState, bytes: Vec<u8>) -> Result<()> {
    let sender = state
        .input_tx
        .as_ref()
        .context("terminal input queue is unavailable")?;
    sender
        .try_send(bytes)
        .map_err(|error| anyhow::anyhow!("terminal input queue rejected frame: {error}"))
}

fn bracketed_paste_bytes(text: &str) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(BRACKETED_PASTE_START.len() + text.len() + BRACKETED_PASTE_END.len());
    out.extend_from_slice(BRACKETED_PASTE_START);
    out.extend_from_slice(text.as_bytes());
    out.extend_from_slice(BRACKETED_PASTE_END);
    out
}

#[cfg(test)]
fn test_local_terminal_context() -> AuthenticatedTerminalContext {
    AuthenticatedTerminalContext {
        principal_id: "local-owner".to_string(),
        client_instance_id: Uuid::nil(),
        connection_epoch: NEXT_LOCAL_TERMINAL_CONNECTION_EPOCH.fetch_add(1, Ordering::Relaxed),
    }
}

fn issue_binding(
    state: &mut TerminalState,
    owner: AuthenticatedTerminalContext,
    session_id: Uuid,
) -> (TerminalBinding, u64) {
    state.next_binding_epoch = state.next_binding_epoch.saturating_add(1);
    let binding = TerminalBinding {
        binding_id: Uuid::new_v4(),
        binding_epoch: state.next_binding_epoch,
    };
    state.bindings.insert(
        binding.binding_id,
        BindingRecord {
            epoch: binding.binding_epoch,
            owner,
            session_id,
        },
    );
    let binding_dir = state.temp_dir.join(random_base32());
    state.binding_dirs.insert(binding.binding_id, binding_dir);
    (binding, state.generation)
}

fn authorize_binding(
    state: &TerminalState,
    binding: TerminalBinding,
) -> std::result::Result<(), ErrorPayload> {
    ensure_open(state, state.id).map_err(|_| invalid_ingress())?;
    if state
        .bindings
        .get(&binding.binding_id)
        .is_some_and(|record| record.epoch == binding.binding_epoch)
    {
        Ok(())
    } else {
        Err(invalid_ingress())
    }
}

fn invalid_ingress() -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::InvalidIngress,
        message: "invalid terminal ingress".to_string(),
    }
}
fn ingress_conflict() -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::IngressConflict,
        message: "terminal ingress metadata conflict".to_string(),
    }
}
fn ingress_path_unavailable() -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::IngressPathUnavailable,
        message: "terminal ingress path unavailable".to_string(),
    }
}

fn ingress_response(operation: &IngressOperation) -> Response {
    let expires_at_unix_ms = operation.committed_at.map(|committed_at| {
        let remaining = INGRESS_TTL.saturating_sub(committed_at.elapsed());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        (now + remaining).as_millis().min(u128::from(u64::MAX)) as u64
    });
    Response::TerminalIngress {
        receipt: TerminalIngressReceipt {
            operation_id: operation.metadata.operation_id,
            state: operation.state,
            next_offset: if operation.state == TerminalIngressState::Committed {
                operation.metadata.size
            } else {
                operation.bytes.len() as u64
            },
            input_sequence: operation.input_sequence,
            expires_at_unix_ms,
        },
    }
}

fn sweep_ingress_locked(state: &mut TerminalState) {
    let now = Instant::now();
    state.ingress.retain(|_, operation| {
        let horizon = operation.committed_at.unwrap_or(operation.created_at);
        let expired = now.duration_since(horizon) >= INGRESS_TTL;
        !expired
    });
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest.iter() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn validate_image(
    metadata: &TerminalIngressMetadata,
    bytes: &[u8],
) -> std::result::Result<(), ErrorPayload> {
    if bytes.len() as u64 != metadata.size || sha256_hex(bytes) != metadata.sha256 {
        return Err(invalid_ingress());
    }
    let magic = match metadata.media_type {
        TerminalImageType::Png => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        TerminalImageType::Jpeg => bytes.starts_with(&[0xff, 0xd8, 0xff]),
        TerminalImageType::Gif => bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
        TerminalImageType::Webp => {
            bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP"
        }
    };
    if magic {
        Ok(())
    } else {
        Err(invalid_ingress())
    }
}

fn validate_path_text(path: &str) -> std::result::Result<(), ErrorPayload> {
    if path
        .bytes()
        .any(|byte| matches!(byte, 0 | 7 | 10 | 13 | 27))
        || path.contains("\x1b[200~")
        || path.contains("\x1b[201~")
        || !Path::new(path).is_absolute()
    {
        Err(ingress_path_unavailable())
    } else {
        Ok(())
    }
}

fn posix_literal(path: &str) -> String {
    format!("'{}'", path.replace('\'', "'\\''"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IngressShellDialect {
    Posix,
    #[allow(dead_code)]
    PowerShell,
    #[allow(dead_code)]
    Cmd,
}

fn shell_path_literal(
    path: &str,
    dialect: IngressShellDialect,
) -> std::result::Result<String, ErrorPayload> {
    validate_path_text(path)?;
    match dialect {
        IngressShellDialect::Posix => Ok(posix_literal(path)),
        IngressShellDialect::PowerShell => Ok(format!("'{}'", path.replace('\'', "''"))),
        IngressShellDialect::Cmd => {
            if path
                .bytes()
                .any(|byte| matches!(byte, b'%' | b'!' | b'^' | b'&' | b'|' | b'<' | b'>'))
            {
                Err(ingress_path_unavailable())
            } else {
                Ok(format!("\"{}\"", path.replace('"', "\"\"")))
            }
        }
    }
}

fn host_shell_dialect() -> IngressShellDialect {
    #[cfg(windows)]
    {
        let shell = default_shell().to_ascii_lowercase();
        if shell.ends_with("powershell.exe") || shell.ends_with("pwsh.exe") {
            IngressShellDialect::PowerShell
        } else {
            IngressShellDialect::Cmd
        }
    }
    #[cfg(not(windows))]
    {
        IngressShellDialect::Posix
    }
}

fn random_base32() -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    // UUIDv4 fixes six bits. Hashing two independent draws and taking 128
    // output bits restores a full 128-bit opaque component without adding a
    // second randomness dependency.
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let digest = Sha256::new()
        .chain_update(first.as_bytes())
        .chain_update(second.as_bytes())
        .finalize();
    let bytes: [u8; 16] = digest[..16].try_into().expect("SHA-256 prefix length");
    let mut output = String::with_capacity(26);
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((accumulator >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(ALPHABET[((accumulator << (5 - bits)) & 31) as usize] as char);
    }
    output
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

#[cfg(test)]
#[cfg(unix)]
fn set_private_open_file_permissions(file: &std::fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
#[cfg(all(not(unix), not(windows)))]
fn set_private_open_file_permissions(_file: &std::fs::File) -> Result<()> {
    Ok(())
}

fn read_verified_final(
    path: &Path,
    expected_len: u64,
) -> std::result::Result<(Vec<u8>, cockpit_config::config::VerifiedTerminalIngressFile), ErrorPayload>
{
    let (bytes, identity) = cockpit_config::config::read_terminal_ingress_file_verified(path)
        .map_err(internal)?
        .ok_or_else(invalid_ingress)?;
    if bytes.len() as u64 != expected_len || identity.links != 1 {
        return Err(invalid_ingress());
    }
    let post = cockpit_config::config::hold_terminal_ingress_file_verified(path)
        .map_err(internal)?
        .ok_or_else(invalid_ingress)?;
    if post.identity != identity || post.bytes != bytes {
        return Err(invalid_ingress());
    }
    Ok((bytes, post))
}

fn remove_if_same_identity(
    path: &Path,
    expected: Option<cockpit_config::config::TerminalIngressFileIdentity>,
) {
    let Ok(Some((_, current))) = cockpit_config::config::read_terminal_ingress_file_verified(path)
    else {
        return;
    };
    if Some(current) != expected {
        return;
    }
    let _ = cockpit_config::config::remove_terminal_ingress_file_nofollow(path);
}

// ---- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use cockpit_core::process_containment::{
        FakeProvenAdapter, PlatformKind, ProcessContainmentActor,
    };
    use cockpit_db::Db;
    use std::sync::Arc as StdArc;

    // -- helpers -----------------------------------------------------------

    fn bel_seq(intro: &[u8], body_after_intro: &[u8]) -> Vec<u8> {
        let mut v = intro.to_vec();
        v.extend_from_slice(body_after_intro);
        v.push(0x07);
        v
    }

    fn st7_seq(intro: &[u8], body_after_intro: &[u8]) -> Vec<u8> {
        let mut v = intro.to_vec();
        v.extend_from_slice(body_after_intro);
        v.extend_from_slice(b"\x1b\\");
        v
    }

    fn stc1_seq(intro: &[u8], body_after_intro: &[u8]) -> Vec<u8> {
        let mut v = intro.to_vec();
        v.extend_from_slice(body_after_intro);
        v.push(0x9c);
        v
    }

    fn valid_body(text: &str) -> Vec<u8> {
        let mut body = b"52;c;".to_vec();
        body.extend_from_slice(STANDARD.encode(text.as_bytes()).as_bytes());
        body
    }

    fn push_all_splits(seq: &[u8]) -> Vec<FilteredTerminalOutput> {
        let mut outs = Vec::new();
        // Full push.
        let mut f = TerminalOutputFilter::default();
        outs.push(f.push(seq));
        // Every single-byte split.
        let mut f = TerminalOutputFilter::default();
        let mut last = FilteredTerminalOutput::default();
        for b in seq {
            last = f.push(&[*b]);
            if last.overflow {
                break;
            }
        }
        outs.push(last);
        // Split after first byte (covers ESC | second-byte boundary).
        if seq.len() >= 2 {
            let mut f = TerminalOutputFilter::default();
            let _ = f.push(&seq[..1]);
            outs.push(f.push(&seq[1..]));
        }
        outs
    }

    fn assert_valid_clipboard(seq: &[u8], expected: &str) {
        for out in push_all_splits(seq) {
            assert!(!out.overflow, "valid seq must not overflow");
            assert!(
                out.passthrough.is_empty()
                    || !String::from_utf8_lossy(&out.passthrough).contains("52;"),
                "OSC52 must be stripped: {:?}",
                out.passthrough
            );
            assert_eq!(out.clipboards, vec![expected.to_string()]);
        }
    }

    fn assert_stripped_no_clipboard(seq: &[u8]) {
        let mut f = TerminalOutputFilter::default();
        let out = f.push(seq);
        assert!(!out.overflow);
        assert!(out.clipboards.is_empty(), "no clipboard for {:?}", seq);
        // Sequence itself must not appear in passthrough.
        let pass = out.passthrough;
        assert!(
            !contains_subslice(&pass, seq),
            "complete OSC52 must be stripped"
        );
    }

    fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    // AC1: remove every resynchronize/recover-after-overflow expectation.
    // There are no such tests remaining; this test locks the new contract.
    #[test]
    fn osc52_tests_are_corrected_first() {
        // Overflow must not resync or forward a suffix after the cap.
        let mut f = TerminalOutputFilter::default();
        // Build a sequence that exceeds the cap mid-payload.
        let mut huge = b"\x1b]52;c;".to_vec();
        huge.extend(std::iter::repeat_n(b'A', OSC52_MAX_SEQUENCE_BYTES));
        let out = f.push(&huge);
        assert!(out.overflow);
        assert!(out.passthrough.is_empty());
        assert!(out.clipboards.is_empty());
        // Further bytes must not resync.
        let out2 = f.push(b"\x07SECRET_SUFFIX");
        assert!(out2.overflow);
        assert!(out2.passthrough.is_empty());
        assert!(out2.clipboards.is_empty());
        assert!(f.has_overflowed());
    }

    #[test]
    fn osc52_is_extracted_and_stripped_across_chunks() {
        let mut filter = TerminalOutputFilter::default();
        let first = filter.push(b"before \x1b]52;c;");
        assert_eq!(first.passthrough, b"before ".to_vec());
        assert!(first.clipboards.is_empty());
        let second = filter.push(b"aGVsbG8=\x07 after");
        assert_eq!(second.passthrough, b" after".to_vec());
        assert_eq!(second.clipboards, vec!["hello".to_string()]);
        assert!(!second.overflow);
    }

    #[test]
    fn osc52_exact_total_cap() {
        // Exactly 102400 with valid final terminator is accepted.
        // Cap+1 terminates via overflow.
        type TermFn = fn(&[u8], &[u8]) -> Vec<u8>;
        let intros: &[&[u8]] = &[b"\x1b]", &[0x9d]];
        let terms: &[(TermFn, &str)] = &[(bel_seq, "bel"), (st7_seq, "st7"), (stc1_seq, "stc1")];

        for intro in intros {
            for (term_fn, term_name) in terms {
                // Build payload so total length with intro+52;c;+payload+term = CAP.
                // body_prefix = 52;c;
                let body_prefix = b"52;c;";
                let term_probe = term_fn(intro, body_prefix);
                let overhead = term_probe.len(); // intro + 52;c; + term, payload empty
                assert!(
                    overhead < OSC52_MAX_SEQUENCE_BYTES,
                    "overhead {overhead} for {term_name}"
                );
                let payload_len = OSC52_MAX_SEQUENCE_BYTES - overhead;
                // Use 'A' payload (valid base64 alphabet); may not be valid
                // clipboard grammar — we only care about cap acceptance vs overflow.
                let mut body = body_prefix.to_vec();
                body.extend(std::iter::repeat_n(b'A', payload_len));
                let exact = term_fn(intro, &body);
                assert_eq!(
                    exact.len(),
                    OSC52_MAX_SEQUENCE_BYTES,
                    "exact len for intro={intro:?} term={term_name}"
                );

                // Exact cap: complete, no overflow (malformed clipboard OK).
                let mut f = TerminalOutputFilter::default();
                let out = f.push(&exact);
                assert!(
                    !out.overflow,
                    "exact cap must complete for {term_name}/{:?}",
                    intro
                );
                assert!(out.clipboards.is_empty() || out.clipboards.len() == 1);

                // Cap+1: first required byte at 102401 overflows. Feed all
                // in-cap bytes in one chunk, then the single overflowing byte
                // (and prove byte-boundary splits around the cap edge).
                let mut body_over = body_prefix.to_vec();
                body_over.extend(std::iter::repeat_n(b'A', payload_len + 1));
                let over = term_fn(intro, &body_over);
                assert!(over.len() > OSC52_MAX_SEQUENCE_BYTES);
                let mut f = TerminalOutputFilter::default();
                let head = &over[..OSC52_MAX_SEQUENCE_BYTES];
                let overflow_byte = &over[OSC52_MAX_SEQUENCE_BYTES..OSC52_MAX_SEQUENCE_BYTES + 1];
                let out_head = f.push(head);
                assert!(
                    !out_head.overflow,
                    "first {OSC52_MAX_SEQUENCE_BYTES} bytes stay in-cap"
                );
                let out_over = f.push(overflow_byte);
                assert!(
                    out_over.overflow,
                    "cap+1 must overflow for {term_name}/{:?}",
                    intro
                );
                assert!(out_over.passthrough.is_empty());
                assert!(out_over.clipboards.is_empty());
                // Also prove the overflow byte alone after a one-byte-shorter head.
                let mut f = TerminalOutputFilter::default();
                let _ = f.push(&over[..OSC52_MAX_SEQUENCE_BYTES - 1]);
                let mid = f.push(&over[OSC52_MAX_SEQUENCE_BYTES - 1..OSC52_MAX_SEQUENCE_BYTES]);
                assert!(!mid.overflow);
                let last = f.push(&over[OSC52_MAX_SEQUENCE_BYTES..OSC52_MAX_SEQUENCE_BYTES + 1]);
                assert!(last.overflow, "boundary split overflow for {term_name}");

                // Boundary split between ESC and its second byte for 7-bit intro.
                if intro == &b"\x1b]".as_ref() {
                    let mut f = TerminalOutputFilter::default();
                    let a = f.push(b"\x1b");
                    assert!(a.passthrough.is_empty());
                    let mut rest = b"]".to_vec();
                    rest.extend_from_slice(&body);
                    // Use BEL for the split test.
                    rest.push(0x07);
                    // Trim/extend to exact if needed — use `exact` after first ESC.
                    let mut f = TerminalOutputFilter::default();
                    let _ = f.push(b"\x1b");
                    let out = f.push(&exact[1..]);
                    assert!(!out.overflow, "ESC-split exact must complete");
                }
            }
        }
    }

    #[test]
    fn osc52_valid_malformed_and_plain_stream() {
        type TermFn = fn(&[u8], &[u8]) -> Vec<u8>;
        let intros: &[&[u8]] = &[b"\x1b]", &[0x9d]];
        let term_fns: &[TermFn] = &[bel_seq, st7_seq, stc1_seq];

        // All six introducer/terminator combos for valid selector c.
        for intro in intros {
            for term_fn in term_fns {
                let body = valid_body("hello");
                let seq = term_fn(intro, &body);
                assert_valid_clipboard(&seq, "hello");
            }
        }

        // Multibyte UTF-8.
        let snow = "雪";
        assert_valid_clipboard(&bel_seq(b"\x1b]", &valid_body(snow)), snow);

        // Canonical STANDARD with 0/1/2 padding bytes.
        // 3 bytes → 0 pad; 2 bytes → 1 pad (=); 1 byte → 2 pad (==).
        assert_valid_clipboard(&bel_seq(b"\x1b]", &valid_body("abc")), "abc"); // 3
        assert_valid_clipboard(&bel_seq(b"\x1b]", &valid_body("ab")), "ab"); // 2
        assert_valid_clipboard(&bel_seq(b"\x1b]", &valid_body("a")), "a"); // 1

        // Malformed: empty selector field / wrong / multi
        for bad in [
            b"52;;QUJD\x07" as &[u8],
            b"52;C;QUJD\x07",
            b"52;p;QUJD\x07",
            b"52;c0;QUJD\x07",
            b"52;c;p;QUJD\x07",
        ] {
            let mut seq = b"\x1b]".to_vec();
            seq.extend_from_slice(bad);
            assert_stripped_no_clipboard(&seq);
        }

        // Query
        let mut q = b"\x1b]52;c;?\x07".to_vec();
        assert_stripped_no_clipboard(&q);
        q = b"\x1b]52;c?\x07".to_vec();
        assert_stripped_no_clipboard(&q);

        // Empty payload
        assert_stripped_no_clipboard(b"\x1b]52;c;\x07");

        // URL-safe alphabet
        // '+' → '-' would be URL-safe; construct a payload that uses '-'.
        assert_stripped_no_clipboard(b"\x1b]52;c;abc-defg\x07");

        // Missing padding (unpadded)
        // "a" → "YQ=="; without padding:
        assert_stripped_no_clipboard(b"\x1b]52;c;YQ\x07");

        // Extra/misplaced padding
        assert_stripped_no_clipboard(b"\x1b]52;c;YQ===\x07");
        assert_stripped_no_clipboard(b"\x1b]52;c;=YQ=\x07");

        // Whitespace / control in payload
        assert_stripped_no_clipboard(b"\x1b]52;c;YQ ==\x07");
        assert_stripped_no_clipboard(b"\x1b]52;c;YQ\x00==\x07");

        // Invalid alphabet
        assert_stripped_no_clipboard(b"\x1b]52;c;!!!!\x07");

        // Non-UTF-8 decoded bytes: 0xff encodes as /w==
        let non_utf8 = STANDARD.encode([0xff]);
        let mut seq = b"\x1b]52;c;".to_vec();
        seq.extend_from_slice(non_utf8.as_bytes());
        seq.push(0x07);
        assert_stripped_no_clipboard(&seq);

        // Nonzero pad bits: decode may succeed but re-encode differs.
        // Classic: "YQ" padded wrong bits — use "YR==" which decodes to
        // something that re-encodes as "YQ==" under strict canonical check.
        assert_stripped_no_clipboard(b"\x1b]52;c;YR==\x07");

        // Non-52 OSC released as plain
        let mut f = TerminalOutputFilter::default();
        let out = f.push(b"x\x1b]0;title\x07y");
        assert_eq!(out.passthrough, b"x\x1b]0;title\x07y".to_vec());
        assert!(out.clipboards.is_empty());

        // Overlong / nondecimal command
        let mut f = TerminalOutputFilter::default();
        let out = f.push(b"\x1b]052;c;QUJD\x07");
        assert!(out.clipboards.is_empty());
        assert!(out.passthrough.windows(4).any(|w| w == b"052;"));

        // Lone / nonterminating ESC inside payload remains stripped until term.
        let mut f = TerminalOutputFilter::default();
        let out = f.push(b"\x1b]52;c;AA\x1bXBB\x07");
        assert!(out.clipboards.is_empty());
        assert!(out.passthrough.is_empty());

        // Raw C1 vs UTF-8 c2 9d / c2 9c as ordinary data.
        let mut f = TerminalOutputFilter::default();
        let out = f.push(b"a\xc2\x9db\xc2\x9cc");
        assert_eq!(out.passthrough, b"a\xc2\x9db\xc2\x9cc".to_vec());
        assert!(out.clipboards.is_empty());

        // Incomplete EOF discards without clipboard.
        let mut f = TerminalOutputFilter::default();
        let out = f.push(b"\x1b]52;c;YQ==");
        assert!(out.clipboards.is_empty());
        assert!(out.passthrough.is_empty());
        f.finish();
        assert_eq!(f.pending_len(), 0);

        // Nested candidates never resync count — second intro is data.
        let mut f = TerminalOutputFilter::default();
        let out = f.push(b"\x1b]52;c;\x1b]52;c;YQ==\x07");
        // Outer candidate terminated; payload invalid → strip, no event.
        assert!(out.clipboards.is_empty());

        // Multiple in-cap sequences.
        let mut f = TerminalOutputFilter::default();
        let mut stream = bel_seq(b"\x1b]", &valid_body("one"));
        stream.extend_from_slice(b" mid ");
        stream.extend(bel_seq(b"\x1b]", &valid_body("two")));
        let out = f.push(&stream);
        assert_eq!(out.clipboards, vec!["one".to_string(), "two".to_string()]);
        assert_eq!(out.passthrough, b" mid ".to_vec());

        // Byte-identical plain under chunking.
        let plain = b"hello\nworld\t\xc2\x80";
        for split in 0..=plain.len() {
            let mut f = TerminalOutputFilter::default();
            let mut got = f.push(&plain[..split]).passthrough;
            got.extend(f.push(&plain[split..]).passthrough);
            assert_eq!(got, plain.to_vec());
        }
    }

    #[test]
    fn osc52_diagnostics_content_free() {
        // Osc52ProtocolViolation carries only terminal_id + generation.
        let ev = proto::Event::Osc52ProtocolViolation {
            terminal_id: Uuid::nil(),
            generation: 1,
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(!json.contains("aGVsbG8"));
        assert!(!json.contains("hello"));
        assert!(!json.contains("payload"));
        assert!(json.contains("osc52_protocol_violation") || json.contains("generation"));
    }

    #[test]
    fn osc52_single_shared_contract() {
        // Compile-time import of the sole public constant.
        let _ = OSC52_MAX_SEQUENCE_BYTES;
        assert_eq!(OSC52_MAX_SEQUENCE_BYTES, 102_400);

        // Workspace inventory: exactly one declaration of the constant value.
        let roots = [
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../apps/cli"),
        ];
        let mut decls = Vec::new();
        let mut numeric_dupes = Vec::new();
        for root in roots {
            for entry in walkdir_rs(&root) {
                let Ok(content) = std::fs::read_to_string(&entry) else {
                    continue;
                };
                for (idx, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    // Skip the inventory probe itself and pure string literals.
                    if trimmed.contains("trimmed.contains")
                        || trimmed.contains("numeric_dupes")
                        || trimmed.contains("competing OSC52")
                    {
                        continue;
                    }
                    if trimmed.contains("OSC52_MAX_SEQUENCE_BYTES")
                        && (trimmed.starts_with("pub const ")
                            || trimmed.starts_with("const ")
                            || trimmed.starts_with("pub static ")
                            || trimmed.starts_with("static "))
                        && !trimmed.starts_with("//")
                    {
                        decls.push(format!("{}:{}", entry.display(), idx + 1));
                    }
                    // Reject local aliases / payload-only caps as declarations.
                    let is_decl = trimmed.starts_with("const ")
                        || trimmed.starts_with("pub const ")
                        || trimmed.starts_with("static ")
                        || trimmed.starts_with("pub static ");
                    if is_decl
                        && (trimmed.contains("OSC52_MAX_B64")
                            || trimmed.contains("OSC52_MAX_PAYLOAD")
                            || (trimmed.contains("OSC52_MAX")
                                && !trimmed.contains("OSC52_MAX_SEQUENCE_BYTES")))
                    {
                        numeric_dupes.push(format!("{}:{}: {trimmed}", entry.display(), idx + 1));
                    }
                }
            }
        }
        assert_eq!(
            decls.len(),
            1,
            "exactly one OSC52_MAX_SEQUENCE_BYTES declaration expected, found {decls:?}"
        );
        assert!(
            decls[0].contains("cockpit-proto"),
            "sole declaration must live in cockpit-proto, got {}",
            decls[0]
        );
        assert!(
            numeric_dupes.is_empty(),
            "competing OSC52 caps/aliases: {numeric_dupes:?}"
        );
    }

    fn walkdir_rs(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for ent in rd.flatten() {
                let p = ent.path();
                if p.is_dir() {
                    let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                    if name == "target" || name == ".git" {
                        continue;
                    }
                    stack.push(p);
                } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
                    out.push(p);
                }
            }
        }
        out
    }

    async fn seed_containment() -> (
        ProcessContainmentActor,
        ProcessContainmentHandle,
        FakeProvenAdapter,
        Uuid,
        ContainmentLease,
    ) {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("proj", "/tmp/term-osc52", "orchestrator-build")
            .await
            .unwrap()
            .session_id;
        let fake = FakeProvenAdapter::new(PlatformKind::Fake);
        let actor = ProcessContainmentActor::start(db, StdArc::new(fake.clone()));
        let handle = actor.handle();
        let lease = handle
            .create_and_spawn(
                session,
                format!("term-{session}"),
                PathBuf::from("/bin/true"),
                vec![],
                PathBuf::from("/tmp"),
                true,
            )
            .await
            .unwrap();
        (actor, handle, fake, session, lease)
    }

    fn install_test_terminal_with_containment(
        host: &TerminalHost,
        lease: ContainmentLease,
        handle: ProcessContainmentHandle,
        force_empty: Option<EmptyOutcome>,
        force_timeout: bool,
    ) -> Uuid {
        let id = Uuid::new_v4();
        let terminal = Arc::new(Mutex::new(TerminalState::new_test(
            id,
            host.temp_root.join(format!("term-{id}")),
        )));
        {
            let mut state = crate::sync::lock_or_recover(&terminal);
            state.containment = Some(TerminalContainmentBinding {
                handle,
                lease,
                force_empty_outcome: force_empty,
                force_timeout,
            });
        }
        crate::sync::lock_or_recover(&host.inner)
            .terminals
            .insert(id, terminal);
        id
    }

    #[tokio::test]
    async fn osc52_overflow_terminates_session() {
        let (tx, mut rx) = broadcast::channel(64);
        let tmp = tempfile::tempdir().unwrap();
        let host = TerminalHost::new_for_test(tx, tmp.path().join("terms"));
        let (_actor, handle, fake, _session, lease) = seed_containment().await;
        let lease_generation = lease.generation();
        let id = install_test_terminal_with_containment(&host, lease, handle, None, false);

        // Overflow via filter path on the installed terminal.
        // In-cap head then one overflow byte (avoids multi-100k rescans).
        let mut head = b"\x1b]52;c;".to_vec();
        let head_len = head.len();
        head.extend(std::iter::repeat_n(
            b'A',
            OSC52_MAX_SEQUENCE_BYTES.saturating_sub(head_len),
        ));
        assert_eq!(head.len(), OSC52_MAX_SEQUENCE_BYTES);
        let terminal = host.get_terminal(id).unwrap();
        TerminalHost::handle_pty_bytes(&terminal, &host.event_tx, &host.redaction, &head);
        TerminalHost::handle_pty_bytes(&terminal, &host.event_tx, &host.redaction, b"X");
        // Suffix after overflow must not forward.
        TerminalHost::handle_pty_bytes(&terminal, &host.event_tx, &host.redaction, b"\x07SECRET");

        {
            let state = crate::sync::lock_or_recover(&terminal);
            assert!(state.closed);
            assert!(state.forwarding_cancelled);
            assert_eq!(state.close_transitions, 1);
            assert!(state.osc52_violation_emitted);
            assert!(state.input_tx.is_none());
            assert!(state.master.is_none());
            assert!(state.child.is_none());
            assert!(state.test_leader_reaped);
            assert_eq!(state.generation, lease_generation);
            assert_eq!(state.close_outcome, Some(TerminalCloseOutcome::Clean));
        }
        // Input rejected.
        assert!(host.input(id, b"x".to_vec()).is_err());
        assert!(
            host.ingress_status(
                id,
                TerminalBinding {
                    binding_id: Uuid::new_v4(),
                    binding_epoch: 1
                },
                Uuid::new_v4(),
            )
            .is_err()
        );

        // Terminate was called on the fake adapter.
        assert!(!fake.terminate_log().is_empty());

        // Exactly one violation + one closed, content-free.
        let mut violations = 0;
        let mut closed = 0;
        let mut saw_secret = false;
        while let Ok(env) = rx.try_recv() {
            match env.event {
                proto::Event::Osc52ProtocolViolation {
                    terminal_id,
                    generation,
                } => {
                    assert_eq!(terminal_id, id);
                    assert_eq!(generation, lease_generation);
                    violations += 1;
                }
                proto::Event::TerminalClosed {
                    terminal_id,
                    reason,
                    ..
                } => {
                    assert_eq!(terminal_id, id);
                    assert!(reason.contains("osc52_protocol_violation"));
                    assert!(!reason.contains("SECRET"));
                    closed += 1;
                }
                proto::Event::TerminalOutput { bytes, .. }
                    if bytes.windows(6).any(|w| w == b"SECRET") =>
                {
                    saw_secret = true;
                }
                proto::Event::TerminalClipboard { text, .. } => {
                    assert!(!text.contains("SECRET"));
                }
                _ => {}
            }
        }
        assert_eq!(violations, 1);
        assert_eq!(closed, 1);
        assert!(!saw_secret);
        // Unsupported / Uncertain / timeout → close_blocked, never clean.
        // Reuse one actor; only the empty-outcome injection changes.
        for (force_empty, force_timeout, label) in [
            (
                Some(EmptyOutcome::Uncertain {
                    generation: 1,
                    reason: "forced".into(),
                }),
                false,
                "uncertain",
            ),
            (
                Some(EmptyOutcome::Unsupported {
                    reason: "unsupported".into(),
                }),
                false,
                "unsupported",
            ),
            (None, true, "timeout"),
        ] {
            let (_a, h, _f, _s, lease) = seed_containment().await;
            let lease_gen = lease.generation();
            let id =
                install_test_terminal_with_containment(&host, lease, h, force_empty, force_timeout);
            let terminal = host.get_terminal(id).unwrap();
            // Direct close-oracle path (skip multi-100k filter) with overflow trigger.
            {
                let mut state = crate::sync::lock_or_recover(&terminal);
                assert_eq!(state.generation, lease_gen);
                let outcome = close_generation_locked(
                    &mut state,
                    CloseTrigger::Osc52Overflow,
                    &host.event_tx,
                    &host.redaction,
                );
                assert_eq!(outcome, TerminalCloseOutcome::CloseBlocked, "{label}");
                assert_eq!(
                    state.close_outcome,
                    Some(TerminalCloseOutcome::CloseBlocked),
                    "{label}"
                );
                assert!(state.closed, "{label}");
            }
            assert!(host.input(id, b"x".to_vec()).is_err(), "{label}");
        }
    }

    #[tokio::test]
    async fn osc52_overflow_close_exit_races() {
        // Every ordering of client close, overflow, and process-exit must
        // produce exactly one generation-close transition and at most one
        // violation (only when overflow participates and wins the race).
        let orderings: &[&[CloseTrigger]] = &[
            &[CloseTrigger::Osc52Overflow, CloseTrigger::ClientClose],
            &[CloseTrigger::ClientClose, CloseTrigger::Osc52Overflow],
            &[CloseTrigger::ProcessExited, CloseTrigger::Osc52Overflow],
            &[CloseTrigger::Osc52Overflow, CloseTrigger::ProcessExited],
            &[CloseTrigger::ClientClose, CloseTrigger::ProcessExited],
            &[
                CloseTrigger::Osc52Overflow,
                CloseTrigger::ClientClose,
                CloseTrigger::ProcessExited,
            ],
            &[
                CloseTrigger::ClientClose,
                CloseTrigger::Osc52Overflow,
                CloseTrigger::ProcessExited,
            ],
        ];

        for order in orderings {
            let (tx, mut rx) = broadcast::channel(64);
            let tmp = tempfile::tempdir().unwrap();
            let host = TerminalHost::new_for_test(tx, tmp.path().join("terms"));
            let (_a, h, _f, _s, lease) = seed_containment().await;
            let id = install_test_terminal_with_containment(&host, lease, h, None, false);
            let terminal = host.get_terminal(id).unwrap();

            for trigger in *order {
                let mut state = crate::sync::lock_or_recover(&terminal);
                match trigger {
                    CloseTrigger::Osc52Overflow => {
                        drop(state);
                        let mut head = b"\x1b]52;c;".to_vec();
                        let head_len = head.len();
                        head.extend(std::iter::repeat_n(
                            b'A',
                            OSC52_MAX_SEQUENCE_BYTES.saturating_sub(head_len),
                        ));
                        TerminalHost::handle_pty_bytes(
                            &terminal,
                            &host.event_tx,
                            &host.redaction,
                            &head,
                        );
                        TerminalHost::handle_pty_bytes(
                            &terminal,
                            &host.event_tx,
                            &host.redaction,
                            b"X",
                        );
                    }
                    other => {
                        let _ = close_generation_locked(
                            &mut state,
                            *other,
                            &host.event_tx,
                            &host.redaction,
                        );
                    }
                }
            }

            let state = crate::sync::lock_or_recover(&terminal);
            assert_eq!(
                state.close_transitions, 1,
                "order {order:?} must have exactly one close transition"
            );
            assert!(state.closed);

            let mut violations = 0;
            let mut closed = 0;
            while let Ok(env) = rx.try_recv() {
                match env.event {
                    proto::Event::Osc52ProtocolViolation { .. } => violations += 1,
                    proto::Event::TerminalClosed { .. } => closed += 1,
                    _ => {}
                }
            }
            assert_eq!(closed, 1, "order {order:?}");
            let overflow_first = order
                .iter()
                .position(|t| matches!(t, CloseTrigger::Osc52Overflow))
                .map(|i| {
                    order.iter().take(i).all(|t| {
                        // Overflow "wins" only if no prior close.
                        !matches!(t, CloseTrigger::ClientClose | CloseTrigger::ProcessExited)
                    })
                })
                .unwrap_or(false);
            // Violation only if overflow was the first close trigger.
            let expected_violation = matches!(order[0], CloseTrigger::Osc52Overflow);
            assert_eq!(
                violations,
                if expected_violation { 1 } else { 0 },
                "order {order:?} overflow_first={overflow_first}"
            );
        }
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
    fn terminal_ingress_generation_and_cleanup() {
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
    fn terminal_ingress_tests_corrected_first() {
        use std::os::unix::fs::PermissionsExt;
        let (tx, _rx) = broadcast::channel(16);
        let tmp = tempfile::tempdir().unwrap();
        let host = TerminalHost::new_for_test(tx, tmp.path().join("terms"));
        let Response::TerminalOpened {
            terminal_id,
            binding,
            ..
        } = host
            .open(Some(tmp.path().to_string_lossy().into_owned()), 80, 24)
            .unwrap()
        else {
            panic!("expected terminal opened");
        };
        let bytes = b"\x89PNG\r\n\x1a\nvalidated";
        let operation_id = Uuid::new_v4();
        let metadata = TerminalIngressMetadata {
            operation_id,
            size: bytes.len() as u64,
            media_type: TerminalImageType::Png,
            sha256: sha256_hex(bytes),
        };
        host.ingress_begin(terminal_id, binding, metadata).unwrap();
        host.ingress_chunk(terminal_id, binding, operation_id, 0, bytes.to_vec())
            .unwrap();
        let Response::TerminalIngress { receipt } = host
            .ingress_finish(terminal_id, binding, operation_id)
            .unwrap()
        else {
            panic!("expected terminal ingress receipt");
        };
        assert_eq!(receipt.state, TerminalIngressState::Committed);
        let terminal = host.get_terminal(terminal_id).unwrap();
        let state = crate::sync::lock_or_recover(&terminal);
        let path = state.ingress[&operation_id].path.as_ref().unwrap().clone();
        drop(state);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = host.close(terminal_id);
    }

    #[cfg(unix)]
    #[test]
    fn terminal_ingress_general_agent_integration() {
        let (tx, _rx) = broadcast::channel(32);
        let tmp = tempfile::tempdir().unwrap();
        let host = TerminalHost::new_for_test(tx, tmp.path().join("terms"));
        let Response::TerminalOpened {
            terminal_id,
            binding,
            ..
        } = host
            .open(Some(tmp.path().to_string_lossy().into_owned()), 80, 24)
            .unwrap()
        else {
            panic!()
        };
        let fixtures: &[(TerminalImageType, &[u8])] = &[
            (TerminalImageType::Png, b"\x89PNG\r\n\x1a\nreal-png"),
            (TerminalImageType::Jpeg, b"\xff\xd8\xff\xe0real-jpeg"),
            (TerminalImageType::Gif, b"GIF89areal-gif"),
            (TerminalImageType::Webp, b"RIFF0000WEBPreal-webp"),
        ];
        for (index, (media_type, bytes)) in fixtures.iter().enumerate() {
            let operation_id = Uuid::new_v4();
            let metadata = TerminalIngressMetadata {
                operation_id,
                size: bytes.len() as u64,
                media_type: *media_type,
                sha256: sha256_hex(bytes),
            };
            host.ingress_begin(terminal_id, binding, metadata).unwrap();
            host.ingress_chunk(terminal_id, binding, operation_id, 0, bytes.to_vec())
                .unwrap();
            let Response::TerminalIngress { receipt } = host
                .ingress_finish(terminal_id, binding, operation_id)
                .unwrap()
            else {
                panic!()
            };
            assert_eq!(receipt.input_sequence, Some((index + 1) as u64));
            let terminal = host.get_terminal(terminal_id).unwrap();
            let path = crate::sync::lock_or_recover(&terminal).ingress[&operation_id]
                .path
                .as_ref()
                .unwrap()
                .clone();
            assert_eq!(std::fs::read(&path).unwrap(), *bytes);
            std::fs::write(&path, b"foreground mutation").unwrap();
            std::fs::remove_file(&path).unwrap();
            let Response::TerminalIngress { receipt: replay } = host
                .ingress_status(terminal_id, binding, operation_id)
                .unwrap()
            else {
                panic!()
            };
            assert_eq!(replay, receipt);
        }
        let _ = host.close(terminal_id);
    }

    #[test]
    fn terminal_ingress_path_literal() {
        let path = if cfg!(windows) {
            "C:\\private dir\\it's.png"
        } else {
            "/tmp/private dir/it's.png"
        };
        assert_eq!(
            shell_path_literal(path, IngressShellDialect::Posix).unwrap(),
            format!("'{}'", path.replace('\'', "'\\''"))
        );
        assert_eq!(
            shell_path_literal(path, IngressShellDialect::PowerShell).unwrap(),
            format!("'{}'", path.replace('\'', "''"))
        );
        assert_eq!(
            shell_path_literal(path, IngressShellDialect::Cmd).unwrap(),
            format!("\"{path}\"")
        );
        for dialect in [
            IngressShellDialect::Posix,
            IngressShellDialect::PowerShell,
            IngressShellDialect::Cmd,
        ] {
            let literal = shell_path_literal(path, dialect).unwrap();
            assert_eq!(
                cockpit_tui::tui::structured_paste::parse_private_image_path_literal(&literal),
                Some(PathBuf::from(path))
            );
        }
        for rejected in [
            "/tmp/a\nb",
            "/tmp/a\rb",
            "/tmp/a\x07b",
            "/tmp/a\x1bb",
            "/tmp/\x1b[200~x",
            "/tmp/\x1b[201~x",
        ] {
            assert!(shell_path_literal(rejected, IngressShellDialect::Posix).is_err());
            assert!(shell_path_literal(rejected, IngressShellDialect::PowerShell).is_err());
            assert!(shell_path_literal(rejected, IngressShellDialect::Cmd).is_err());
        }
        for byte in ['%', '!', '^', '&', '|', '<', '>'] {
            assert!(
                shell_path_literal(&format!("/tmp/a{byte}b"), IngressShellDialect::Cmd).is_err()
            );
        }
        let exact =
            bracketed_paste_bytes(&shell_path_literal(path, IngressShellDialect::Posix).unwrap());
        assert!(exact.starts_with(BRACKETED_PASTE_START));
        assert!(exact.ends_with(BRACKETED_PASTE_END));
        assert!(!exact.ends_with(b"\n"));
        assert!(!exact.ends_with(b"\r"));
    }

    #[test]
    fn terminal_ingress_operation_and_budget() {
        assert_eq!(random_base32().len(), 26);
        assert!(
            random_base32()
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
        );
        assert!(!is_sha256_hex(&"0".repeat(63)));
        assert!(is_sha256_hex(&"0".repeat(64)));
        assert_eq!(TERMINAL_INGRESS_MAX_CHUNK_BYTES, 48 * 1024);
        assert_eq!(TERMINAL_INGRESS_MAX_BYTES, 10 * 1024 * 1024);
        assert_eq!(INGRESS_JOURNAL_CAP, 64);
        assert_eq!(INGRESS_TTL, Duration::from_secs(10 * 60));
    }

    #[test]
    fn terminal_ingress_architecture_boundary() {
        let protocol = include_str!("../../../packages/relay-protocol/src/terminal.ts");
        let daemon_attachments =
            include_str!("../../../crates/cockpit-core/src/daemon/server/attachments.rs");
        for forbidden in [
            "TerminalPasteImage",
            "retained_media",
            "durable_media",
            "composer",
        ] {
            assert!(
                !protocol.contains(forbidden),
                "terminal relay imports forbidden {forbidden}"
            );
            assert!(
                !daemon_attachments.contains(forbidden),
                "terminal ingress couples to forbidden {forbidden}"
            );
        }
    }

    #[test]
    fn terminal_ingress_windows_no_reparse() {
        let source = include_str!("../../../crates/cockpit-config/src/config/files.rs");
        for required in [
            "NtCreateFile",
            "RootDirectory",
            "FILE_OPEN_REPARSE_POINT",
            "FILE_CREATE",
            "FILE_SHARE_DELETE",
        ] {
            assert!(
                source.contains(required),
                "missing hardened Windows primitive {required}"
            );
        }
        assert!(source.contains("commit_noreplace"));
    }

    #[test]
    fn terminal_ingress_validated_copy() {
        for (media_type, bytes) in [
            (TerminalImageType::Png, b"\x89PNG\r\n\x1a\n".as_slice()),
            (TerminalImageType::Jpeg, b"\xff\xd8\xff".as_slice()),
            (TerminalImageType::Gif, b"GIF89a".as_slice()),
            (TerminalImageType::Webp, b"RIFF0000WEBP".as_slice()),
        ] {
            let metadata = TerminalIngressMetadata {
                operation_id: Uuid::new_v4(),
                size: bytes.len() as u64,
                media_type,
                sha256: sha256_hex(bytes),
            };
            assert!(validate_image(&metadata, bytes).is_ok());
            let mut changed = bytes.to_vec();
            changed[0] ^= 1;
            assert!(validate_image(&metadata, &changed).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn terminal_ingress_unix_no_follow() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        std::fs::write(&target, b"secret").unwrap();
        let link = tmp.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(read_verified_final(&link, 6).is_err());
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(&target)
            .unwrap();
        set_private_open_file_permissions(&file).unwrap();
        let metadata = file.metadata().unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    }

    #[cfg(unix)]
    #[test]
    fn terminal_ingress_binding_ownership() {
        let (tx, _rx) = broadcast::channel(16);
        let tmp = tempfile::tempdir().unwrap();
        let host = TerminalHost::new_for_test(tx, tmp.path().join("terms"));
        let Response::TerminalOpened {
            terminal_id,
            binding: first,
            terminal_generation,
            ..
        } = host
            .open(Some(tmp.path().to_string_lossy().into_owned()), 80, 24)
            .unwrap()
        else {
            panic!()
        };
        let Response::TerminalOpened {
            binding: second,
            terminal_generation: attached_generation,
            ..
        } = host.attach(terminal_id, 80, 24).unwrap()
        else {
            panic!()
        };
        assert_ne!(first, second);
        assert_eq!(terminal_generation, attached_generation);
        let bytes = b"\x89PNG\r\n\x1a\n";
        let metadata = TerminalIngressMetadata {
            operation_id: Uuid::new_v4(),
            size: bytes.len() as u64,
            media_type: TerminalImageType::Png,
            sha256: sha256_hex(bytes),
        };
        host.release_viewer(terminal_id, second);
        assert!(
            host.ingress_begin(terminal_id, second, metadata.clone())
                .is_err()
        );
        let Response::TerminalOpened {
            binding: resumed, ..
        } = host.attach(terminal_id, 80, 24).unwrap()
        else {
            panic!()
        };
        host.ingress_begin(terminal_id, resumed, metadata.clone())
            .unwrap();
        let Response::TerminalOpened {
            binding: other_viewer,
            ..
        } = host.attach(terminal_id, 80, 24).unwrap()
        else {
            panic!()
        };
        assert!(
            host.ingress_begin(terminal_id, other_viewer, metadata.clone())
                .is_err()
        );
        host.release_viewer(terminal_id, resumed);
        let Response::TerminalOpened {
            binding: reauthenticated,
            ..
        } = host.attach(terminal_id, 80, 24).unwrap()
        else {
            panic!()
        };
        host.ingress_begin(terminal_id, reauthenticated, metadata)
            .unwrap();
        host.release_viewer(terminal_id, reauthenticated);
        let foreign_context = AuthenticatedTerminalContext {
            principal_id: "different-principal".into(),
            client_instance_id: Uuid::new_v4(),
            connection_epoch: u64::MAX,
        };
        let Response::TerminalOpened {
            binding: foreign, ..
        } = host
            .attach_with_context(foreign_context, Uuid::nil(), terminal_id, 80, 24)
            .unwrap()
        else {
            panic!()
        };
        let operation = host.get_terminal(terminal_id).unwrap();
        let original_metadata = crate::sync::lock_or_recover(&operation)
            .ingress
            .values()
            .next()
            .unwrap()
            .metadata
            .clone();
        assert!(
            host.ingress_begin(terminal_id, foreign, original_metadata)
                .is_err()
        );
        host.release_viewer(terminal_id, first);
        host.release_viewer(terminal_id, other_viewer);
        host.release_viewer(terminal_id, foreign);
        let _ = host.close(terminal_id);
    }

    #[cfg(unix)]
    #[test]
    fn terminal_ingress_commit_and_replay() {
        let (tx, _rx) = broadcast::channel(16);
        let tmp = tempfile::tempdir().unwrap();
        let host = TerminalHost::new_for_test(tx, tmp.path().join("terms"));
        let Response::TerminalOpened {
            terminal_id,
            binding,
            ..
        } = host
            .open(Some(tmp.path().to_string_lossy().into_owned()), 80, 24)
            .unwrap()
        else {
            panic!()
        };
        let bytes = b"GIF89a-frame";
        let operation_id = Uuid::new_v4();
        let metadata = TerminalIngressMetadata {
            operation_id,
            size: bytes.len() as u64,
            media_type: TerminalImageType::Gif,
            sha256: sha256_hex(bytes),
        };
        host.ingress_begin(terminal_id, binding, metadata.clone())
            .unwrap();
        assert!(
            host.ingress_chunk(terminal_id, binding, operation_id, 1, bytes.to_vec())
                .is_err()
        );
        host.ingress_chunk(terminal_id, binding, operation_id, 0, bytes.to_vec())
            .unwrap();
        let first = host
            .ingress_finish(terminal_id, binding, operation_id)
            .unwrap();
        let replay = host
            .ingress_finish(terminal_id, binding, operation_id)
            .unwrap();
        let (
            Response::TerminalIngress { receipt: first },
            Response::TerminalIngress { receipt: replay },
        ) = (first, replay)
        else {
            panic!()
        };
        assert_eq!(first, replay);
        assert_eq!(first.input_sequence, Some(1));
        let conflict = TerminalIngressMetadata {
            sha256: "0".repeat(64),
            ..metadata
        };
        assert_eq!(
            host.ingress_begin(terminal_id, binding, conflict)
                .unwrap_err()
                .code,
            ErrorCode::IngressConflict
        );
        let _ = host.close(terminal_id);
    }

    #[cfg(unix)]
    #[test]
    fn terminal_ingress_injected_mutation_barriers() {
        let (tx, _rx) = broadcast::channel(16);
        let tmp = tempfile::tempdir().unwrap();
        let host = TerminalHost::new_for_test(tx, tmp.path().join("terms"));
        let Response::TerminalOpened {
            terminal_id,
            binding,
            ..
        } = host
            .open(Some(tmp.path().to_string_lossy().into_owned()), 80, 24)
            .unwrap()
        else {
            panic!()
        };
        let bytes = b"GIF89a-barrier";
        let operation_id = Uuid::new_v4();
        let metadata = TerminalIngressMetadata {
            operation_id,
            size: bytes.len() as u64,
            media_type: TerminalImageType::Gif,
            sha256: sha256_hex(bytes),
        };
        host.ingress_begin(terminal_id, binding, metadata).unwrap();
        host.ingress_chunk(terminal_id, binding, operation_id, 0, bytes.to_vec())
            .unwrap();
        *crate::sync::lock_or_recover(&host.ingress_barrier) = Some(Arc::new(|edge, path| {
            if edge == IngressMutationEdge::AfterPublish {
                std::fs::write(path, b"mutated-before-verification").unwrap();
            }
        }));
        assert!(
            host.ingress_finish(terminal_id, binding, operation_id)
                .is_err()
        );
        assert_eq!(
            crate::sync::lock_or_recover(&host.get_terminal(terminal_id).unwrap()).input_sequence,
            0
        );

        *crate::sync::lock_or_recover(&host.ingress_barrier) = None;
        let second_id = Uuid::new_v4();
        let second = TerminalIngressMetadata {
            operation_id: second_id,
            size: bytes.len() as u64,
            media_type: TerminalImageType::Gif,
            sha256: sha256_hex(bytes),
        };
        // The failed Prepared operation still owns the binding budget. A fresh
        // authenticated binding gets an independent bounded operation.
        let Response::TerminalOpened {
            binding: second_binding,
            ..
        } = host.attach(terminal_id, 80, 24).unwrap()
        else {
            panic!()
        };
        host.ingress_begin(terminal_id, second_binding, second)
            .unwrap();
        host.ingress_chunk(terminal_id, second_binding, second_id, 0, bytes.to_vec())
            .unwrap();
        *crate::sync::lock_or_recover(&host.ingress_barrier) = Some(Arc::new(|edge, path| {
            if edge == IngressMutationEdge::AfterFinalVerification {
                std::fs::write(path, b"ordinary-postverify-mutation").unwrap();
            }
        }));
        let Response::TerminalIngress { receipt } = host
            .ingress_finish(terminal_id, second_binding, second_id)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(receipt.state, TerminalIngressState::Committed);
        assert_eq!(receipt.input_sequence, Some(1));
        *crate::sync::lock_or_recover(&host.ingress_barrier) = None;
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
        /// Lightweight generation state for close-oracle tests (no live PTY).
        fn new_test(id: Uuid, temp_dir: PathBuf) -> Self {
            Self {
                id,
                generation: 1,
                master: None,
                input_tx: None,
                input_cancel: Arc::new(AtomicBool::new(true)),
                input_thread: None,
                child: None,
                buffer: ReplayBuffer::new(REPLAY_BUFFER_BYTES),
                filter: TerminalOutputFilter::default(),
                viewer_count: 1,
                temp_dir,
                bindings: HashMap::new(),
                binding_dirs: HashMap::new(),
                next_binding_epoch: 0,
                ingress: HashMap::new(),
                input_sequence: 0,
                closed: false,
                forwarding_cancelled: false,
                close_transitions: 0,
                osc52_violation_emitted: false,
                close_outcome: None,
                last_detached: None,
                containment: None,
                test_leader_reaped: false,
            }
        }
    }
}
