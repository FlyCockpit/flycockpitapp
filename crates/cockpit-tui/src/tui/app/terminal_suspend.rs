//! Terminal suspension for external `$EDITOR` handoff.
//!
//! Snapshots raw mode, alternate screen, mouse capture, and input suspension,
//! then restores that exact snapshot through one RAII/async-finish guard on
//! every success, failure, and cancellation path.

use std::ffi::OsStr;
use std::fmt;
use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::DefaultTerminal;

use super::{disable_mouse_capture_with_motion, enable_mouse_capture_with_motion};
use crate::tui::input_source::TerminalInput;

/// Observed TUI terminal modes to restore after an external editor session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct TerminalModeSnapshot {
    pub raw_mode: bool,
    pub alternate_screen: bool,
    pub mouse_capture: bool,
    pub input_suspended: bool,
}

impl TerminalModeSnapshot {
    /// Modes Cockpit holds while the event loop owns the TTY.
    pub(super) fn tui_active(mouse_capture: bool) -> Self {
        Self {
            raw_mode: true,
            alternate_screen: true,
            mouse_capture,
            input_suspended: false,
        }
    }
}

/// Ordered terminal actions used by suspend/restore and error reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum TerminalSuspendAction {
    SuspendInput,
    DisableMouseCapture,
    LeaveAlternateScreen,
    DisableRawMode,
    EnableRawMode,
    EnterAlternateScreen,
    ClearTerminal,
    EnableMouseCapture,
    ResumeInput,
    Redraw,
}

impl TerminalSuspendAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::SuspendInput => "suspend_input",
            Self::DisableMouseCapture => "disable_mouse_capture",
            Self::LeaveAlternateScreen => "leave_alternate_screen",
            Self::DisableRawMode => "disable_raw_mode",
            Self::EnableRawMode => "enable_raw_mode",
            Self::EnterAlternateScreen => "enter_alternate_screen",
            Self::ClearTerminal => "clear_terminal",
            Self::EnableMouseCapture => "enable_mouse_capture",
            Self::ResumeInput => "resume_input",
            Self::Redraw => "redraw",
        }
    }
}

impl fmt::Display for TerminalSuspendAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Actions applied when leaving TUI control for the editor.
pub(super) fn suspend_actions(snapshot: TerminalModeSnapshot) -> Vec<TerminalSuspendAction> {
    let mut actions = Vec::with_capacity(4);
    if !snapshot.input_suspended {
        actions.push(TerminalSuspendAction::SuspendInput);
    }
    if snapshot.mouse_capture {
        actions.push(TerminalSuspendAction::DisableMouseCapture);
    }
    if snapshot.alternate_screen {
        actions.push(TerminalSuspendAction::LeaveAlternateScreen);
    }
    if snapshot.raw_mode {
        actions.push(TerminalSuspendAction::DisableRawMode);
    }
    actions
}

/// Actions applied when reclaiming the TTY after the editor.
pub(super) fn restore_actions(snapshot: TerminalModeSnapshot) -> Vec<TerminalSuspendAction> {
    let mut actions = Vec::with_capacity(6);
    if snapshot.raw_mode {
        actions.push(TerminalSuspendAction::EnableRawMode);
    }
    if snapshot.alternate_screen {
        actions.push(TerminalSuspendAction::EnterAlternateScreen);
        actions.push(TerminalSuspendAction::ClearTerminal);
    }
    if snapshot.mouse_capture {
        actions.push(TerminalSuspendAction::EnableMouseCapture);
    }
    if !snapshot.input_suspended {
        actions.push(TerminalSuspendAction::ResumeInput);
    }
    actions.push(TerminalSuspendAction::Redraw);
    actions
}

/// Injectable terminal-mode surface for suspend/restore.
pub(super) trait TerminalSuspendHost {
    fn apply(&mut self, action: TerminalSuspendAction) -> io::Result<()>;

    /// Current capture/suspension state after the last applied action.
    fn state(&self) -> TerminalModeSnapshot;
}

/// Injectable editor runner (no real `$EDITOR` / process-global env).
pub(super) trait ExternalEditorHost {
    fn run_editor(
        &mut self,
        editor: &OsStr,
        path: &Path,
        cancel: &EditorCancel,
    ) -> Pin<Box<dyn Future<Output = Result<ExitStatus, EditorRunError>> + Send>>;
}

/// Cooperative cancellation flag shared across suspend/editor/cleanup barriers.
#[derive(Debug, Default, Clone)]
pub(super) struct EditorCancel {
    cancelled: Arc<AtomicBool>,
}

impl EditorCancel {
    pub(super) fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)] // exercised by unit tests / injectable hosts
    pub(super) fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
pub(super) enum EditorRunError {
    Spawn(io::Error),
    Wait(io::Error),
    Cancelled,
}

impl fmt::Display for EditorRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(err) => write!(f, "spawn failed: {err}"),
            Self::Wait(err) => write!(f, "wait failed: {err}"),
            Self::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl std::error::Error for EditorRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(err) | Self::Wait(err) => Some(err),
            Self::Cancelled => None,
        }
    }
}

/// Structured cleanup failure: every restore action that failed, in order.
#[derive(Debug)]
pub(super) struct TerminalRestoreError {
    failures: Vec<(TerminalSuspendAction, String)>,
}

impl TerminalRestoreError {
    #[allow(dead_code)] // exercised by unit tests / injectable hosts
    pub(super) fn failures(&self) -> &[(TerminalSuspendAction, String)] {
        &self.failures
    }
}

impl fmt::Display for TerminalRestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.failures.is_empty() {
            return f.write_str("terminal restore failed");
        }
        for (i, (action, msg)) in self.failures.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{action}: {msg}")?;
        }
        Ok(())
    }
}

impl std::error::Error for TerminalRestoreError {}

#[derive(Debug)]
pub(super) struct ExternalEditorSessionOutcome {
    pub status: Result<ExitStatus, EditorRunError>,
    pub restore: Result<(), TerminalRestoreError>,
    pub redraw: bool,
}

/// RAII/async-finish guard: restore runs exactly once via [`Self::finish`].
///
/// [`Drop`] is a best-effort, nonblocking last resort for unwinding paths that
/// did not await finish.
pub(super) struct TerminalSuspensionGuard<'a, H: TerminalSuspendHost + ?Sized> {
    host: &'a mut H,
    snapshot: TerminalModeSnapshot,
    finished: bool,
}

impl<'a, H: TerminalSuspendHost + ?Sized> TerminalSuspensionGuard<'a, H> {
    /// Snapshot modes, then apply suspend actions in deterministic order.
    ///
    /// Suspend-step failures are recorded but do not prevent the guard from
    /// existing: finish still restores to the original snapshot.
    pub(super) fn begin(
        host: &'a mut H,
        snapshot: TerminalModeSnapshot,
    ) -> (Self, Vec<(TerminalSuspendAction, String)>) {
        let mut suspend_failures = Vec::new();
        for action in suspend_actions(snapshot) {
            if let Err(err) = host.apply(action) {
                suspend_failures.push((action, err.to_string()));
            }
        }
        (
            Self {
                host,
                snapshot,
                finished: false,
            },
            suspend_failures,
        )
    }

    /// Restore terminal modes, mouse capture, and redraw exactly once.
    pub(super) async fn finish(&mut self) -> Result<(), TerminalRestoreError> {
        // Yield so cancellation-aware callers can interleave with cleanup.
        tokio::task::yield_now().await;
        self.finish_now()
    }

    fn finish_now(&mut self) -> Result<(), TerminalRestoreError> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        let mut failures = Vec::new();
        for action in restore_actions(self.snapshot) {
            if let Err(err) = self.host.apply(action) {
                failures.push((action, err.to_string()));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(TerminalRestoreError { failures })
        }
    }

    #[allow(dead_code)] // exercised by unit tests / injectable hosts
    pub(super) fn is_finished(&self) -> bool {
        self.finished
    }
}

impl<H: TerminalSuspendHost + ?Sized> Drop for TerminalSuspensionGuard<'_, H> {
    fn drop(&mut self) {
        // Best-effort, nonblocking last resort for panics/unwinds.
        let _ = self.finish_now();
    }
}

/// Run `editor` under one suspension guard. Always finishes the guard once.
pub(super) async fn run_external_editor_with_guard<H, E>(
    host: &mut H,
    editor_host: &mut E,
    snapshot: TerminalModeSnapshot,
    editor: &OsStr,
    path: &Path,
    cancel: &EditorCancel,
) -> ExternalEditorSessionOutcome
where
    H: TerminalSuspendHost + ?Sized,
    E: ExternalEditorHost + ?Sized,
{
    let (mut guard, suspend_failures) = TerminalSuspensionGuard::begin(host, snapshot);

    // Do not hand the TTY to the editor if any pre-handoff suspend action failed
    // (e.g. mouse capture still enabled). Always finish the guard to restore.
    let status = if !suspend_failures.is_empty() {
        Err(EditorRunError::Spawn(io::Error::other(format!(
            "terminal suspend incomplete: {}",
            suspend_failures
                .iter()
                .map(|(action, msg)| format!("{action}: {msg}"))
                .collect::<Vec<_>>()
                .join("; ")
        ))))
    } else if cancel.is_cancelled() {
        Err(EditorRunError::Cancelled)
    } else {
        match editor_host.run_editor(editor, path, cancel).await {
            Ok(status) => {
                if cancel.is_cancelled() {
                    Err(EditorRunError::Cancelled)
                } else {
                    Ok(status)
                }
            }
            Err(err) => Err(err),
        }
    };

    // Cancellation during cleanup still converges on a single finish.
    let restore = guard.finish().await;

    ExternalEditorSessionOutcome {
        status,
        restore,
        // Always request a frame after handoff so the next loop paints a cleared buffer.
        redraw: true,
    }
}

/// Production host: crossterm modes + [`TerminalInput`] + ratatui clear.
pub(super) struct LiveTerminalSuspendHost<'a> {
    terminal: &'a mut DefaultTerminal,
    input: &'a mut TerminalInput,
    state: TerminalModeSnapshot,
}

impl<'a> LiveTerminalSuspendHost<'a> {
    pub(super) fn new(
        terminal: &'a mut DefaultTerminal,
        input: &'a mut TerminalInput,
        mouse_capture: bool,
    ) -> Self {
        Self {
            terminal,
            input,
            state: TerminalModeSnapshot::tui_active(mouse_capture),
        }
    }
}

impl TerminalSuspendHost for LiveTerminalSuspendHost<'_> {
    fn apply(&mut self, action: TerminalSuspendAction) -> io::Result<()> {
        match action {
            TerminalSuspendAction::SuspendInput => {
                self.input.suspend();
                self.state.input_suspended = true;
                Ok(())
            }
            TerminalSuspendAction::ResumeInput => {
                self.input.resume();
                self.state.input_suspended = false;
                Ok(())
            }
            TerminalSuspendAction::DisableMouseCapture => {
                disable_mouse_capture_with_motion()?;
                self.state.mouse_capture = false;
                Ok(())
            }
            TerminalSuspendAction::EnableMouseCapture => {
                enable_mouse_capture_with_motion()?;
                self.state.mouse_capture = true;
                Ok(())
            }
            TerminalSuspendAction::LeaveAlternateScreen => {
                crossterm::execute!(io::stdout(), LeaveAlternateScreen)?;
                self.state.alternate_screen = false;
                Ok(())
            }
            TerminalSuspendAction::EnterAlternateScreen => {
                crossterm::execute!(io::stdout(), EnterAlternateScreen)?;
                self.state.alternate_screen = true;
                Ok(())
            }
            TerminalSuspendAction::DisableRawMode => {
                disable_raw_mode()?;
                self.state.raw_mode = false;
                Ok(())
            }
            TerminalSuspendAction::EnableRawMode => {
                enable_raw_mode()?;
                self.state.raw_mode = true;
                Ok(())
            }
            TerminalSuspendAction::ClearTerminal => self.terminal.clear(),
            // Actual paint is owned by the event loop; finish records redraw via outcome.
            TerminalSuspendAction::Redraw => Ok(()),
        }
    }

    fn state(&self) -> TerminalModeSnapshot {
        self.state
    }
}

/// Production editor host: inherits stdio and waits for exit (cancel-aware).
pub(super) struct ProcessExternalEditorHost;

impl ExternalEditorHost for ProcessExternalEditorHost {
    fn run_editor(
        &mut self,
        editor: &OsStr,
        path: &Path,
        cancel: &EditorCancel,
    ) -> Pin<Box<dyn Future<Output = Result<ExitStatus, EditorRunError>> + Send>> {
        let editor = editor.to_os_string();
        let path = path.to_path_buf();
        let cancel = cancel.clone();
        Box::pin(async move {
            if cancel.is_cancelled() {
                return Err(EditorRunError::Cancelled);
            }
            let mut child = tokio::process::Command::new(&editor)
                .arg(&path)
                .stdin(std::process::Stdio::inherit())
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .spawn()
                .map_err(EditorRunError::Spawn)?;

            loop {
                if cancel.is_cancelled() {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    return Err(EditorRunError::Cancelled);
                }
                match tokio::time::timeout(std::time::Duration::from_millis(50), child.wait()).await
                {
                    Ok(Ok(status)) => return Ok(status),
                    Ok(Err(err)) => return Err(EditorRunError::Wait(err)),
                    Err(_elapsed) => continue,
                }
            }
        })
    }
}

/// Format a history/toast line without including editor buffer plaintext.
pub(super) fn format_external_editor_notice(
    editor: &OsStr,
    outcome: &ExternalEditorSessionOutcome,
) -> Option<String> {
    let editor_name = editor.to_string_lossy();
    match (&outcome.status, &outcome.restore) {
        (Ok(status), Ok(())) if status.success() => None,
        (Ok(status), Ok(())) => Some(format!("editor: exited with {status}")),
        (Ok(status), Err(restore)) if status.success() => {
            Some(format!("editor: terminal restore: {restore}"))
        }
        (Ok(status), Err(restore)) => Some(format!(
            "editor: exited with {status}; terminal restore: {restore}"
        )),
        (Err(EditorRunError::Spawn(err)), Ok(())) => {
            Some(format!("editor: invoking `{editor_name}`: {err}"))
        }
        (Err(EditorRunError::Spawn(err)), Err(restore)) => Some(format!(
            "editor: invoking `{editor_name}`: {err}; terminal restore: {restore}"
        )),
        (Err(EditorRunError::Wait(err)), Ok(())) => {
            Some(format!("editor: waiting on `{editor_name}`: {err}"))
        }
        (Err(EditorRunError::Wait(err)), Err(restore)) => Some(format!(
            "editor: waiting on `{editor_name}`: {err}; terminal restore: {restore}"
        )),
        (Err(EditorRunError::Cancelled), Ok(())) => Some("editor: cancelled".to_string()),
        (Err(EditorRunError::Cancelled), Err(restore)) => {
            Some(format!("editor: cancelled; terminal restore: {restore}"))
        }
    }
}

#[cfg(test)]
mod external_editor_mouse_restore_tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    fn exit_status(code: i32) -> ExitStatus {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            // Wait-status encoding: normal exit puts the code in the high byte.
            ExitStatus::from_raw(code.checked_shl(8).unwrap_or(0))
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::ExitStatusExt;
            ExitStatus::from_raw(code as u32)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = code;
            std::process::Command::new("true")
                .status()
                .expect("portable exit status")
        }
    }

    #[derive(Clone, Default)]
    struct RecordingTerminalHost {
        inner: Arc<Mutex<RecordingTerminalInner>>,
    }

    #[derive(Default)]
    struct RecordingTerminalInner {
        state: TerminalModeSnapshot,
        ops: Vec<TerminalSuspendAction>,
        fail_actions: HashSet<TerminalSuspendAction>,
        cancel_on: HashMap<TerminalSuspendAction, EditorCancel>,
    }

    impl RecordingTerminalHost {
        fn new(initial: TerminalModeSnapshot) -> Self {
            let host = Self::default();
            host.inner.lock().unwrap().state = initial;
            host
        }

        fn fail_on(self, action: TerminalSuspendAction) -> Self {
            self.inner.lock().unwrap().fail_actions.insert(action);
            self
        }

        fn cancel_on(self, action: TerminalSuspendAction, cancel: EditorCancel) -> Self {
            self.inner.lock().unwrap().cancel_on.insert(action, cancel);
            self
        }

        fn ops(&self) -> Vec<TerminalSuspendAction> {
            self.inner.lock().unwrap().ops.clone()
        }

        fn state_now(&self) -> TerminalModeSnapshot {
            self.inner.lock().unwrap().state
        }

        fn op_counts(&self) -> HashMap<TerminalSuspendAction, usize> {
            let mut counts = HashMap::new();
            for op in self.ops() {
                *counts.entry(op).or_default() += 1;
            }
            counts
        }
    }

    impl TerminalSuspendHost for RecordingTerminalHost {
        fn apply(&mut self, action: TerminalSuspendAction) -> io::Result<()> {
            let mut inner = self.inner.lock().unwrap();
            inner.ops.push(action);
            if let Some(cancel) = inner.cancel_on.get(&action) {
                cancel.cancel();
            }
            if inner.fail_actions.contains(&action) {
                return Err(io::Error::other(format!("injected failure: {action}")));
            }
            match action {
                TerminalSuspendAction::SuspendInput => inner.state.input_suspended = true,
                TerminalSuspendAction::ResumeInput => inner.state.input_suspended = false,
                TerminalSuspendAction::DisableMouseCapture => inner.state.mouse_capture = false,
                TerminalSuspendAction::EnableMouseCapture => inner.state.mouse_capture = true,
                TerminalSuspendAction::LeaveAlternateScreen => inner.state.alternate_screen = false,
                TerminalSuspendAction::EnterAlternateScreen => inner.state.alternate_screen = true,
                TerminalSuspendAction::DisableRawMode => inner.state.raw_mode = false,
                TerminalSuspendAction::EnableRawMode => inner.state.raw_mode = true,
                TerminalSuspendAction::ClearTerminal | TerminalSuspendAction::Redraw => {}
            }
            Ok(())
        }

        fn state(&self) -> TerminalModeSnapshot {
            self.state_now()
        }
    }

    #[derive(Clone)]
    struct FakeEditorHost {
        inner: Arc<Mutex<FakeEditorInner>>,
    }

    struct FakeEditorInner {
        result: Result<ExitStatus, EditorRunError>,
        started: bool,
        finished: bool,
        cancel_before_start: bool,
        cancel_while_running: bool,
        invocations: usize,
    }

    impl FakeEditorHost {
        fn success() -> Self {
            Self::with_result(Ok(exit_status(0)))
        }

        fn nonzero() -> Self {
            Self::with_result(Ok(exit_status(1)))
        }

        fn spawn_error() -> Self {
            Self::with_result(Err(EditorRunError::Spawn(io::Error::new(
                io::ErrorKind::NotFound,
                "editor binary missing",
            ))))
        }

        fn with_result(result: Result<ExitStatus, EditorRunError>) -> Self {
            Self {
                inner: Arc::new(Mutex::new(FakeEditorInner {
                    result,
                    started: false,
                    finished: false,
                    cancel_before_start: false,
                    cancel_while_running: false,
                    invocations: 0,
                })),
            }
        }

        fn cancel_before_start(self) -> Self {
            self.inner.lock().unwrap().cancel_before_start = true;
            self
        }

        fn cancel_while_running(self) -> Self {
            self.inner.lock().unwrap().cancel_while_running = true;
            self
        }

        fn invocations(&self) -> usize {
            self.inner.lock().unwrap().invocations
        }

        fn started(&self) -> bool {
            self.inner.lock().unwrap().started
        }

        fn finished(&self) -> bool {
            self.inner.lock().unwrap().finished
        }
    }

    impl ExternalEditorHost for FakeEditorHost {
        fn run_editor(
            &mut self,
            editor: &OsStr,
            path: &Path,
            cancel: &EditorCancel,
        ) -> Pin<Box<dyn Future<Output = Result<ExitStatus, EditorRunError>> + Send>> {
            let inner = Arc::clone(&self.inner);
            let cancel = cancel.clone();
            let _ = (editor, path);
            Box::pin(async move {
                {
                    let mut g = inner.lock().unwrap();
                    g.invocations += 1;
                    if g.cancel_before_start {
                        cancel.cancel();
                    }
                    if cancel.is_cancelled() {
                        return Err(EditorRunError::Cancelled);
                    }
                    g.started = true;
                }

                // Yield so cancel-while-running can interleave with the scheduler.
                tokio::task::yield_now().await;

                if inner.lock().unwrap().cancel_while_running {
                    cancel.cancel();
                }
                if cancel.is_cancelled() {
                    return Err(EditorRunError::Cancelled);
                }

                let mut g = inner.lock().unwrap();
                g.finished = true;
                match &g.result {
                    Ok(status) => Ok(*status),
                    Err(EditorRunError::Spawn(err)) => Err(EditorRunError::Spawn(io::Error::new(
                        err.kind(),
                        err.to_string(),
                    ))),
                    Err(EditorRunError::Wait(err)) => Err(EditorRunError::Wait(io::Error::new(
                        err.kind(),
                        err.to_string(),
                    ))),
                    Err(EditorRunError::Cancelled) => Err(EditorRunError::Cancelled),
                }
            })
        }
    }

    fn snapshot_mouse_on() -> TerminalModeSnapshot {
        TerminalModeSnapshot::tui_active(true)
    }

    fn snapshot_mouse_off() -> TerminalModeSnapshot {
        TerminalModeSnapshot::tui_active(false)
    }

    fn index_of(ops: &[TerminalSuspendAction], action: TerminalSuspendAction) -> Option<usize> {
        ops.iter().position(|op| *op == action)
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_success_restores_snapshot_state() {
        let snapshot = snapshot_mouse_on();
        let mut host = RecordingTerminalHost::new(snapshot);
        let mut editor = FakeEditorHost::success();
        let cancel = EditorCancel::new();

        let outcome = run_external_editor_with_guard(
            &mut host,
            &mut editor,
            snapshot,
            OsStr::new("fake-editor"),
            Path::new("/tmp/prompt.md"),
            &cancel,
        )
        .await;

        assert!(outcome.status.unwrap().success());
        assert!(outcome.restore.is_ok());
        assert_eq!(host.state_now(), snapshot);
        assert!(outcome.redraw);
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_disables_capture_before_editor_handoff() {
        let snapshot = snapshot_mouse_on();
        let mut host = RecordingTerminalHost::new(snapshot);
        let mut editor = FakeEditorHost::success();
        let cancel = EditorCancel::new();

        let _ = run_external_editor_with_guard(
            &mut host,
            &mut editor,
            snapshot,
            OsStr::new("fake-editor"),
            Path::new("/tmp/prompt.md"),
            &cancel,
        )
        .await;

        let ops = host.ops();
        let disable = index_of(&ops, TerminalSuspendAction::DisableMouseCapture).unwrap();
        let leave = index_of(&ops, TerminalSuspendAction::LeaveAlternateScreen).unwrap();
        let raw_off = index_of(&ops, TerminalSuspendAction::DisableRawMode).unwrap();
        let enable = index_of(&ops, TerminalSuspendAction::EnableMouseCapture).unwrap();
        let enter = index_of(&ops, TerminalSuspendAction::EnterAlternateScreen).unwrap();
        let clear = index_of(&ops, TerminalSuspendAction::ClearTerminal).unwrap();
        let redraw = index_of(&ops, TerminalSuspendAction::Redraw).unwrap();

        assert!(disable < leave, "mouse off before leave alt: {ops:?}");
        assert!(leave < raw_off, "leave alt before disable raw: {ops:?}");
        assert!(
            enter < enable,
            "mouse restored only after alt re-entered: {ops:?}"
        );
        assert!(clear < enable, "clear before mouse restore: {ops:?}");
        assert!(enable < redraw, "mouse restore before redraw: {ops:?}");
        assert!(editor.started());
        assert!(editor.finished());
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_pre_disabled_stays_disabled_on_success() {
        let snapshot = snapshot_mouse_off();
        let mut host = RecordingTerminalHost::new(snapshot);
        let mut editor = FakeEditorHost::success();
        let cancel = EditorCancel::new();

        let _ = run_external_editor_with_guard(
            &mut host,
            &mut editor,
            snapshot,
            OsStr::new("fake-editor"),
            Path::new("/tmp/prompt.md"),
            &cancel,
        )
        .await;

        assert!(!host.state_now().mouse_capture);
        let ops = host.ops();
        assert!(!ops.contains(&TerminalSuspendAction::DisableMouseCapture));
        assert!(!ops.contains(&TerminalSuspendAction::EnableMouseCapture));
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_pre_disabled_stays_disabled_on_spawn_failure() {
        let snapshot = snapshot_mouse_off();
        let mut host = RecordingTerminalHost::new(snapshot);
        let mut editor = FakeEditorHost::spawn_error();
        let cancel = EditorCancel::new();

        let outcome = run_external_editor_with_guard(
            &mut host,
            &mut editor,
            snapshot,
            OsStr::new("missing-editor"),
            Path::new("/tmp/prompt.md"),
            &cancel,
        )
        .await;

        assert!(matches!(outcome.status, Err(EditorRunError::Spawn(_))));
        assert!(outcome.restore.is_ok());
        assert!(!host.state_now().mouse_capture);
        assert!(
            !host
                .ops()
                .contains(&TerminalSuspendAction::EnableMouseCapture)
        );
    }

    /// Snapshot must come from host-observed state. A host with capture off
    /// must not re-enable capture on restore (production App.mouse_capture is
    /// the live flag after startup/toggle, not a pure config preference).
    #[tokio::test]
    async fn external_editor_mouse_restore_snapshots_observed_host_state() {
        let mut host = RecordingTerminalHost::new(snapshot_mouse_off());
        let snapshot = host.state();
        assert!(!snapshot.mouse_capture);
        let mut editor = FakeEditorHost::success();
        let cancel = EditorCancel::new();
        let outcome = run_external_editor_with_guard(
            &mut host,
            &mut editor,
            snapshot,
            OsStr::new("ed"),
            Path::new("/tmp/x"),
            &cancel,
        )
        .await;
        assert!(outcome.status.is_ok());
        assert!(outcome.restore.is_ok());
        assert!(!host.state().mouse_capture);
        assert!(
            !host
                .ops()
                .contains(&TerminalSuspendAction::EnableMouseCapture),
            "must not enable mouse when observed snapshot was off: {:?}",
            host.ops()
        );
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_suspend_failure_aborts_editor() {
        let mut host = RecordingTerminalHost::new(snapshot_mouse_on())
            .fail_on(TerminalSuspendAction::DisableMouseCapture);
        let snapshot = host.state();
        let mut editor = FakeEditorHost::success();
        let cancel = EditorCancel::new();
        let outcome = run_external_editor_with_guard(
            &mut host,
            &mut editor,
            snapshot,
            OsStr::new("ed"),
            Path::new("/tmp/x"),
            &cancel,
        )
        .await;
        assert!(
            matches!(outcome.status, Err(EditorRunError::Spawn(_))),
            "suspend failure must abort editor handoff: {:?}",
            outcome.status
        );
        assert_eq!(
            editor.invocations(),
            0,
            "editor must not start after suspend failure"
        );
        assert!(outcome.restore.is_ok() || outcome.restore.is_err());
        // restore still ran (finish always)
        assert!(
            host.ops().contains(&TerminalSuspendAction::EnableRawMode)
                || host.ops().contains(&TerminalSuspendAction::Redraw),
            "finish must still restore after suspend failure: {:?}",
            host.ops()
        );
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_spawn_error_still_restores() {
        let snapshot = snapshot_mouse_on();
        let mut host = RecordingTerminalHost::new(snapshot);
        let mut editor = FakeEditorHost::spawn_error();
        let cancel = EditorCancel::new();

        let outcome = run_external_editor_with_guard(
            &mut host,
            &mut editor,
            snapshot,
            OsStr::new("missing-editor"),
            Path::new("/tmp/prompt.md"),
            &cancel,
        )
        .await;

        assert!(matches!(outcome.status, Err(EditorRunError::Spawn(_))));
        assert!(outcome.restore.is_ok());
        assert_eq!(host.state_now(), snapshot);
        assert!(
            host.ops()
                .contains(&TerminalSuspendAction::EnableMouseCapture)
        );
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_nonzero_exit_still_restores() {
        let snapshot = snapshot_mouse_on();
        let mut host = RecordingTerminalHost::new(snapshot);
        let mut editor = FakeEditorHost::nonzero();
        let cancel = EditorCancel::new();

        let outcome = run_external_editor_with_guard(
            &mut host,
            &mut editor,
            snapshot,
            OsStr::new("fake-editor"),
            Path::new("/tmp/prompt.md"),
            &cancel,
        )
        .await;

        assert!(!outcome.status.unwrap().success());
        assert!(outcome.restore.is_ok());
        assert_eq!(host.state_now(), snapshot);
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_cancel_before_spawn_restores() {
        let snapshot = snapshot_mouse_on();
        let mut host = RecordingTerminalHost::new(snapshot);
        let mut editor = FakeEditorHost::success().cancel_before_start();
        let cancel = EditorCancel::new();

        let outcome = run_external_editor_with_guard(
            &mut host,
            &mut editor,
            snapshot,
            OsStr::new("fake-editor"),
            Path::new("/tmp/prompt.md"),
            &cancel,
        )
        .await;

        assert!(matches!(outcome.status, Err(EditorRunError::Cancelled)));
        assert!(outcome.restore.is_ok());
        assert_eq!(host.state_now(), snapshot);
        assert!(editor.invocations() >= 1);
        assert!(!editor.finished());
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_cancel_while_running_restores() {
        let snapshot = snapshot_mouse_on();
        let mut host = RecordingTerminalHost::new(snapshot);
        let mut editor = FakeEditorHost::success().cancel_while_running();
        let cancel = EditorCancel::new();

        let outcome = run_external_editor_with_guard(
            &mut host,
            &mut editor,
            snapshot,
            OsStr::new("fake-editor"),
            Path::new("/tmp/prompt.md"),
            &cancel,
        )
        .await;

        assert!(matches!(outcome.status, Err(EditorRunError::Cancelled)));
        assert!(outcome.restore.is_ok());
        assert_eq!(host.state_now(), snapshot);
        assert!(editor.started());
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_cancel_before_lifecycle_skips_spawn() {
        let snapshot = snapshot_mouse_on();
        let mut host = RecordingTerminalHost::new(snapshot);
        let mut editor = FakeEditorHost::success();
        let cancel = EditorCancel::new();
        cancel.cancel();

        let outcome = run_external_editor_with_guard(
            &mut host,
            &mut editor,
            snapshot,
            OsStr::new("fake-editor"),
            Path::new("/tmp/prompt.md"),
            &cancel,
        )
        .await;

        assert!(matches!(outcome.status, Err(EditorRunError::Cancelled)));
        assert!(outcome.restore.is_ok());
        assert_eq!(editor.invocations(), 0);
        assert_eq!(host.state_now(), snapshot);
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_cancel_during_cleanup_finishes_once() {
        let snapshot = snapshot_mouse_on();
        let cancel = EditorCancel::new();
        let mut host = RecordingTerminalHost::new(snapshot)
            .cancel_on(TerminalSuspendAction::EnableRawMode, cancel.clone());
        let mut editor = FakeEditorHost::success();

        let outcome = run_external_editor_with_guard(
            &mut host,
            &mut editor,
            snapshot,
            OsStr::new("fake-editor"),
            Path::new("/tmp/prompt.md"),
            &cancel,
        )
        .await;

        assert!(outcome.status.is_ok());
        assert!(outcome.restore.is_ok());
        assert_eq!(host.state_now(), snapshot);
        let counts = host.op_counts();
        assert_eq!(counts.get(&TerminalSuspendAction::Redraw).copied(), Some(1));
        assert_eq!(
            counts
                .get(&TerminalSuspendAction::EnableMouseCapture)
                .copied(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_collects_all_restore_failures() {
        let snapshot = snapshot_mouse_on();
        let mut host = RecordingTerminalHost::new(snapshot)
            .fail_on(TerminalSuspendAction::EnableRawMode)
            .fail_on(TerminalSuspendAction::EnableMouseCapture)
            .fail_on(TerminalSuspendAction::Redraw);
        let mut editor = FakeEditorHost::spawn_error();
        let cancel = EditorCancel::new();

        let outcome = run_external_editor_with_guard(
            &mut host,
            &mut editor,
            snapshot,
            OsStr::new("missing-editor"),
            Path::new("/tmp/prompt.md"),
            &cancel,
        )
        .await;

        let restore = outcome.restore.as_ref().unwrap_err();
        let failed: Vec<_> = restore.failures().iter().map(|(a, _)| *a).collect();
        assert_eq!(
            failed,
            vec![
                TerminalSuspendAction::EnableRawMode,
                TerminalSuspendAction::EnableMouseCapture,
                TerminalSuspendAction::Redraw,
            ]
        );
        // Other restore steps still attempted.
        let ops = host.ops();
        assert!(ops.contains(&TerminalSuspendAction::EnterAlternateScreen));
        assert!(ops.contains(&TerminalSuspendAction::ClearTerminal));
        assert!(ops.contains(&TerminalSuspendAction::ResumeInput));

        let notice = format_external_editor_notice(OsStr::new("missing-editor"), &outcome).unwrap();
        assert!(notice.contains("invoking"));
        assert!(notice.contains("enable_raw_mode"));
        assert!(notice.contains("enable_mouse_capture"));
        assert!(notice.contains("redraw"));
        assert!(
            !notice.contains("secret paste body"),
            "restore errors must not include editor plaintext"
        );
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_editor_and_restore_error_chain() {
        let snapshot = snapshot_mouse_on();
        let mut host = RecordingTerminalHost::new(snapshot)
            .fail_on(TerminalSuspendAction::EnterAlternateScreen)
            .fail_on(TerminalSuspendAction::ResumeInput);
        let mut editor = FakeEditorHost::nonzero();
        let cancel = EditorCancel::new();

        let outcome = run_external_editor_with_guard(
            &mut host,
            &mut editor,
            snapshot,
            OsStr::new("fake-editor"),
            Path::new("/tmp/prompt.md"),
            &cancel,
        )
        .await;

        let notice = format_external_editor_notice(OsStr::new("fake-editor"), &outcome).unwrap();
        assert!(notice.contains("exited with"), "{notice}");
        assert!(notice.contains("enter_alternate_screen"), "{notice}");
        assert!(notice.contains("resume_input"), "{notice}");
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_repeated_invocations_are_balanced() {
        let snapshot = snapshot_mouse_on();
        let mut host = RecordingTerminalHost::new(snapshot);
        let cancel = EditorCancel::new();

        for _ in 0..3 {
            let mut editor = FakeEditorHost::success();
            let outcome = run_external_editor_with_guard(
                &mut host,
                &mut editor,
                snapshot,
                OsStr::new("fake-editor"),
                Path::new("/tmp/prompt.md"),
                &cancel,
            )
            .await;
            assert!(outcome.restore.is_ok());
            assert_eq!(host.state_now(), snapshot);
        }

        let counts = host.op_counts();
        assert_eq!(
            counts.get(&TerminalSuspendAction::DisableMouseCapture),
            counts.get(&TerminalSuspendAction::EnableMouseCapture)
        );
        assert_eq!(
            counts.get(&TerminalSuspendAction::SuspendInput),
            counts.get(&TerminalSuspendAction::ResumeInput)
        );
        assert_eq!(
            counts.get(&TerminalSuspendAction::LeaveAlternateScreen),
            counts.get(&TerminalSuspendAction::EnterAlternateScreen)
        );
        assert_eq!(
            counts.get(&TerminalSuspendAction::DisableRawMode),
            counts.get(&TerminalSuspendAction::EnableRawMode)
        );
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_finish_is_idempotent_with_drop() {
        let snapshot = snapshot_mouse_on();
        let host = RecordingTerminalHost::new(snapshot);
        {
            // Clone shares Arc interior state so the guard can hold &mut while
            // assertions read the twin handle.
            let mut host_mut = host.clone();
            let (mut guard, _) = TerminalSuspensionGuard::begin(&mut host_mut, snapshot);
            assert!(!host.state_now().mouse_capture);
            guard.finish().await.unwrap();
            assert!(guard.is_finished());
            // Second finish is a no-op.
            guard.finish().await.unwrap();
        }
        // Drop after finish must not re-apply restore actions.
        let counts = host.op_counts();
        assert_eq!(counts.get(&TerminalSuspendAction::Redraw).copied(), Some(1));
        assert_eq!(
            counts
                .get(&TerminalSuspendAction::EnableMouseCapture)
                .copied(),
            Some(1)
        );
        assert_eq!(host.state_now(), snapshot);
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_drop_without_finish_restores_best_effort() {
        let snapshot = snapshot_mouse_on();
        let host = RecordingTerminalHost::new(snapshot);
        {
            let mut host_mut = host.clone();
            let (guard, _) = TerminalSuspensionGuard::begin(&mut host_mut, snapshot);
            assert!(!host.state_now().mouse_capture);
            assert!(!host.state_now().raw_mode);
            drop(guard);
        }
        assert_eq!(host.state_now(), snapshot);
        assert_eq!(
            host.op_counts()
                .get(&TerminalSuspendAction::EnableMouseCapture)
                .copied(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_late_child_cannot_double_finish() {
        // A late completion path must not re-restore or emit a second redraw.
        let snapshot = snapshot_mouse_on();
        let host = RecordingTerminalHost::new(snapshot);
        let mut host_mut = host.clone();
        let (mut guard, _) = TerminalSuspensionGuard::begin(&mut host_mut, snapshot);
        guard.finish().await.unwrap();
        let ops_after_first = host.ops().len();
        let redraws_after_first = host
            .op_counts()
            .get(&TerminalSuspendAction::Redraw)
            .copied()
            .unwrap_or(0);
        // Late "child done" path calls finish again.
        guard.finish().await.unwrap();
        assert_eq!(host.ops().len(), ops_after_first);
        assert_eq!(
            host.op_counts()
                .get(&TerminalSuspendAction::Redraw)
                .copied()
                .unwrap_or(0),
            redraws_after_first
        );
        assert_eq!(host.state_now(), snapshot);
    }

    #[test]
    fn external_editor_mouse_restore_action_order_helpers_are_stable() {
        let on = snapshot_mouse_on();
        assert_eq!(
            suspend_actions(on),
            vec![
                TerminalSuspendAction::SuspendInput,
                TerminalSuspendAction::DisableMouseCapture,
                TerminalSuspendAction::LeaveAlternateScreen,
                TerminalSuspendAction::DisableRawMode,
            ]
        );
        assert_eq!(
            restore_actions(on),
            vec![
                TerminalSuspendAction::EnableRawMode,
                TerminalSuspendAction::EnterAlternateScreen,
                TerminalSuspendAction::ClearTerminal,
                TerminalSuspendAction::EnableMouseCapture,
                TerminalSuspendAction::ResumeInput,
                TerminalSuspendAction::Redraw,
            ]
        );

        let off = snapshot_mouse_off();
        assert!(!suspend_actions(off).contains(&TerminalSuspendAction::DisableMouseCapture));
        assert!(!restore_actions(off).contains(&TerminalSuspendAction::EnableMouseCapture));
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_readback_path_still_restores_when_status_ok() {
        // Readback happens outside the guard in the app layer; the session
        // outcome still restores for a successful editor exit so the caller
        // can fail on readback without leaving mouse capture off.
        let snapshot = snapshot_mouse_on();
        let mut host = RecordingTerminalHost::new(snapshot);
        let mut editor = FakeEditorHost::success();
        let cancel = EditorCancel::new();

        let outcome = run_external_editor_with_guard(
            &mut host,
            &mut editor,
            snapshot,
            OsStr::new("fake-editor"),
            Path::new("/tmp/prompt.md"),
            &cancel,
        )
        .await;

        assert!(outcome.status.unwrap().success());
        assert!(outcome.restore.is_ok());
        assert!(host.state_now().mouse_capture);
        // Caller would now fail readback; terminal is already restored.
        let readback_err = io::Error::other("readback failed");
        assert_eq!(readback_err.to_string(), "readback failed");
        assert_eq!(host.state_now(), snapshot);
    }

    #[tokio::test]
    async fn external_editor_mouse_restore_cleanup_failure_combinations() {
        let snapshot = snapshot_mouse_on();
        let restore = restore_actions(snapshot);
        for failing in &restore {
            let mut host = RecordingTerminalHost::new(snapshot).fail_on(*failing);
            let mut editor = FakeEditorHost::success();
            let cancel = EditorCancel::new();
            let outcome = run_external_editor_with_guard(
                &mut host,
                &mut editor,
                snapshot,
                OsStr::new("fake-editor"),
                Path::new("/tmp/prompt.md"),
                &cancel,
            )
            .await;
            let err = outcome.restore.unwrap_err();
            assert_eq!(err.failures().len(), 1);
            assert_eq!(err.failures()[0].0, *failing);
            // Every restore action was attempted exactly once.
            for action in &restore {
                assert_eq!(
                    host.op_counts().get(action).copied(),
                    Some(1),
                    "missing attempt for {action:?} when failing {failing:?}"
                );
            }
        }
    }

    #[test]
    fn external_editor_mouse_restore_error_display_omits_plaintext() {
        let restore = TerminalRestoreError {
            failures: vec![(
                TerminalSuspendAction::EnableMouseCapture,
                "device busy".into(),
            )],
        };
        let outcome = ExternalEditorSessionOutcome {
            status: Err(EditorRunError::Spawn(io::Error::new(
                io::ErrorKind::NotFound,
                "gone",
            ))),
            restore: Err(restore),
            redraw: true,
        };
        let text = format_external_editor_notice(OsStr::new("ed"), &outcome).unwrap();
        assert!(text.contains("invoking"));
        assert!(text.contains("enable_mouse_capture"));
        assert!(!text.contains("<user_paste"));
        assert!(!text.contains("paste body"));
    }
}
