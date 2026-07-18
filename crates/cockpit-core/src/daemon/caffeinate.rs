//! `/caffeinate` — daemon-held sleep suppression (GOALS §1a chrome glyph).
//!
//! cockpit is daemon-first: agent work runs in the long-lived daemon, so
//! locking the screen or detaching the TUI never interrupts an agent —
//! only the OS suspending the machine does. `/caffeinate` suppresses that
//! suspend (idle sleep **and** lid-close), with the laptop-lid-close case
//! as the primary target, so a user can start agents, close the lid, and
//! return hours later to still-running agents.
//!
//! ## Why the assertion lives here
//!
//! A TUI client may exit while agents keep running, so the OS sleep
//! assertion cannot live in the client. It is held in the daemon process
//! (the one that must stay up). A `/caffeinate` from any client is a
//! request to the daemon; the daemon owns the on/off state, holds the
//! assertion, and broadcasts the resulting state to **every** connected
//! client (so the `☕` chrome glyph stays in sync on all of them).
//!
//! ## Platform reality (honest about lid-close)
//!
//! The OS assertion is provided by the `keepawake` crate
//! (`SetThreadExecutionState` on Windows, `IOPMAssertionCreateWithName`
//! on macOS, logind `idle`+`sleep` inhibitor locks on Linux). That covers
//! idle sleep everywhere, but lid-close is governed differently per OS:
//!
//! - **Linux** — logind's `LidSwitchIgnoreInhibited=yes` (the default)
//!   makes a plain `sleep` inhibitor *ignored* on lid close. The only
//!   userspace lever that logind always honors is a `handle-lid-switch`
//!   inhibitor lock, which keepawake does not take. So on Linux we add
//!   our own `handle-lid-switch:sleep` inhibitor (see [`linux`]); when
//!   logind is unreachable (headless / non-systemd) we say so.
//! - **macOS** — `PreventSystemSleep` does not override clamshell sleep
//!   on battery (the `caffeinate -s` limitation). We keep the machine
//!   awake on AC / external-display setups and say lid-close is not
//!   guaranteed on battery.
//! - **Windows** — `ES_SYSTEM_REQUIRED` does not override an explicit
//!   "sleep when I close the lid" power-plan setting. We say so and name
//!   the setting the user can change.
//!
//! When a platform cannot guarantee lid-close survival from userspace,
//! [`AcquireOutcome::lid_note`] carries an honest, actionable message; the
//! TUI surfaces it in the toast. When **no** inhibition mechanism is
//! available at all, [`SleepInhibitor::acquire`] returns `Err` with a
//! message naming what's missing — never a silent no-op.
//!
//! ## Threading
//!
//! The real assertion runs on a dedicated OS thread ([`OsInhibitor`]),
//! not a tokio task, because `SetThreadExecutionState` is *per-thread*
//! (the assertion clears if the holding thread exits) and because the
//! logind paths use blocking zbus. The controller talks to that thread
//! over channels. The mode state machine + the until-idle decision are
//! pure and tested without touching the OS via the [`SleepInhibitor`]
//! trait.

use std::sync::Mutex;
use std::sync::mpsc;
use std::thread::JoinHandle;

use crate::config::extended::SleepScope;

/// What the daemon should keep awake. Driven by the `display-awake` UI
/// setting (`ExtendedConfig.tui.caffeinate_display_awake`): system-idle
/// and lid-close are *always* suppressed while caffeinated; the display
/// is only kept on when the user opted in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InhibitScope {
    /// Also assert display-on (the user enabled display-awake).
    pub keep_display_on: bool,
}

impl From<SleepScope> for InhibitScope {
    fn from(s: SleepScope) -> Self {
        Self {
            keep_display_on: matches!(s, SleepScope::SystemAndDisplay),
        }
    }
}

pub use crate::daemon::proto::CaffeinateMode;

/// The two pieces of caffeination state: whether the assertion is held,
/// and whether it is in `until-idle` auto-off mode. A pure value so the
/// state machine is testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CaffeineState {
    /// The OS assertion is currently held.
    pub active: bool,
    /// `until-idle`: when active, auto-disable as soon as no agent runs.
    pub until_idle: bool,
}

/// What [`CaffeineState::next`] decided the new state should be, plus
/// whether the inhibitor must be (re)acquired or released to reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    pub state: CaffeineState,
    pub action: InhibitAction,
}

/// The side effect the [`Transition`] requires on the OS inhibitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InhibitAction {
    /// Acquire (or keep) the assertion. No-op on the inhibitor if already
    /// held — the controller only calls `acquire` when not already held.
    Acquire,
    /// Release the assertion.
    Release,
    /// State unchanged; no inhibitor call needed.
    None,
}

impl CaffeineState {
    /// Apply a mode request to the current state. Pure: returns the
    /// target state + the inhibitor action needed to reach it. The
    /// `until_idle` flag is set only while active in until-idle mode and
    /// is cleared whenever the assertion drops.
    pub fn next(self, mode: CaffeinateMode) -> Transition {
        let target = match mode {
            CaffeinateMode::Off => CaffeineState {
                active: false,
                until_idle: false,
            },
            CaffeinateMode::On => CaffeineState {
                active: true,
                until_idle: false,
            },
            CaffeinateMode::UntilIdle => CaffeineState {
                active: true,
                until_idle: true,
            },
            CaffeinateMode::Toggle => {
                if self.active {
                    CaffeineState {
                        active: false,
                        until_idle: false,
                    }
                } else {
                    CaffeineState {
                        active: true,
                        until_idle: false,
                    }
                }
            }
        };
        Transition {
            state: target,
            action: Self::action(self, target),
        }
    }

    /// The until-idle auto-off decision, decided by the daemon: when in
    /// until-idle mode and no agent is running, drop to off. Pure.
    /// `any_agent_running` is the daemon's view of its session workers /
    /// `ScheduleAuthority`. Returns `Some(Transition)` only when a change is
    /// warranted, so the caller can skip a no-op broadcast.
    pub fn idle_check(self, any_agent_running: bool) -> Option<Transition> {
        if self.active && self.until_idle && !any_agent_running {
            let target = CaffeineState {
                active: false,
                until_idle: false,
            };
            Some(Transition {
                state: target,
                action: Self::action(self, target),
            })
        } else {
            None
        }
    }

    fn action(from: CaffeineState, to: CaffeineState) -> InhibitAction {
        match (from.active, to.active) {
            (false, true) => InhibitAction::Acquire,
            (true, false) => InhibitAction::Release,
            // active→active stays held (scope changes re-acquire via the
            // controller, not here); inactive→inactive is a no-op.
            (true, true) | (false, false) => InhibitAction::None,
        }
    }
}

/// The result of asking the OS to inhibit sleep. Carries the honest
/// lid-close note (`None` when lid-close is fully covered on this
/// platform/config) so the TUI can word the toast truthfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquireOutcome {
    /// `true` when this platform/config can guarantee the machine survives
    /// a lid close from userspace. When `false`, [`Self::lid_note`] says
    /// why and (where possible) names the OS setting to change.
    pub lid_close_guaranteed: bool,
    /// Human-readable note appended to the on-toast when lid-close is not
    /// guaranteed; `None` when it is. Never implies coverage it lacks.
    pub lid_note: Option<String>,
}

/// Abstraction over the OS sleep assertion so the daemon's state logic is
/// testable without really inhibiting sleep (the real assertion is
/// platform/privilege-dependent). The real implementation is
/// [`OsInhibitor`]; tests use a fake.
pub trait SleepInhibitor: Send {
    /// Acquire (or re-acquire with a new scope) the assertion. Returns the
    /// honest lid-close outcome on success, or `Err(message)` when no
    /// inhibition mechanism is available — the message names what is
    /// missing / what to install or enable (never a silent failure).
    fn acquire(&mut self, scope: InhibitScope) -> Result<AcquireOutcome, String>;

    /// Release the assertion. Idempotent.
    fn release(&mut self);
}

// ---- Real, dedicated-thread-backed inhibitor --------------------------------

/// Command sent to the inhibitor worker thread.
enum InhibitCmd {
    Acquire {
        scope: InhibitScope,
        reply: mpsc::Sender<Result<AcquireOutcome, String>>,
    },
    Release,
    Shutdown,
}

/// Real OS sleep inhibitor. Owns a dedicated OS thread that holds the
/// assertion for its whole lifetime — required because
/// `SetThreadExecutionState` (Windows) is per-thread and because the
/// logind paths use blocking zbus. The controller drives it over a
/// channel; the held assertion is dropped (released) when the thread
/// processes `Release`/`Shutdown`.
pub struct OsInhibitor {
    tx: mpsc::Sender<InhibitCmd>,
    thread: Option<JoinHandle<()>>,
}

impl OsInhibitor {
    /// Spawn the worker thread. Cheap — the thread parks until commanded.
    pub fn spawn() -> Self {
        let (tx, rx) = mpsc::channel::<InhibitCmd>();
        let thread = std::thread::Builder::new()
            .name("cockpit-caffeinate".into())
            .spawn(move || inhibitor_thread(rx))
            .expect("spawning caffeinate inhibitor thread");
        Self {
            tx,
            thread: Some(thread),
        }
    }
}

impl SleepInhibitor for OsInhibitor {
    fn acquire(&mut self, scope: InhibitScope) -> Result<AcquireOutcome, String> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.tx
            .send(InhibitCmd::Acquire {
                scope,
                reply: reply_tx,
            })
            .map_err(|_| "caffeinate inhibitor thread is gone".to_string())?;
        reply_rx
            .recv()
            .map_err(|_| "caffeinate inhibitor thread dropped the reply".to_string())?
    }

    fn release(&mut self) {
        let _ = self.tx.send(InhibitCmd::Release);
    }
}

impl Drop for OsInhibitor {
    fn drop(&mut self) {
        let _ = self.tx.send(InhibitCmd::Shutdown);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The held OS assertion, kept alive on the worker thread. Dropping it
/// releases sleep suppression.
struct HeldAssertion {
    /// keepawake's idle+system-sleep assertion (and optionally display).
    /// Always present once acquired — a failed create makes `acquire`
    /// return `Err` before any `HeldAssertion` is built. Dropping it
    /// releases the keepawake locks.
    _keepawake: keepawake::KeepAwake,
    /// Linux-only `handle-lid-switch` inhibitor; `None` on other
    /// platforms or when logind couldn't grant it.
    #[cfg(target_os = "linux")]
    _lid: Option<linux::LidInhibitor>,
}

/// Worker-thread main loop. Holds at most one [`HeldAssertion`]; replacing
/// or releasing it drops the previous one (releasing the OS assertion).
fn inhibitor_thread(rx: mpsc::Receiver<InhibitCmd>) {
    let mut held: Option<HeldAssertion> = None;
    while let Ok(cmd) = rx.recv() {
        match cmd {
            InhibitCmd::Acquire { scope, reply } => {
                // Drop any prior assertion before acquiring the new scope
                // so we don't stack locks. `take` + explicit `drop`
                // releases the OS assertion now (rather than relying on the
                // reassignment below, which doesn't happen on the Err arm).
                drop(held.take());
                match acquire_os(scope) {
                    Ok((assertion, outcome)) => {
                        held = Some(assertion);
                        let _ = reply.send(Ok(outcome));
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                }
            }
            InhibitCmd::Release => {
                held = None;
            }
            InhibitCmd::Shutdown => {
                // Release explicitly before returning (the assignment form
                // would be flagged as never-read).
                drop(held.take());
                return;
            }
        }
    }
    // Sender dropped: release on the way out.
    drop(held);
}

/// Acquire the real OS assertion for `scope`. System-idle + sleep are
/// always requested; display only when `scope.keep_display_on`. Builds the
/// honest lid-close outcome per platform. Runs on the worker thread.
fn acquire_os(scope: InhibitScope) -> Result<(HeldAssertion, AcquireOutcome), String> {
    let keepawake = keepawake::Builder::default()
        .idle(true)
        .sleep(true)
        .display(scope.keep_display_on)
        .reason("cockpit /caffeinate: agents running")
        .app_name("cockpit")
        .app_reverse_domain("ai.cockpit.cockpit")
        .create()
        .map_err(|e| keepawake_unavailable_message(&e))?;

    #[cfg(target_os = "linux")]
    {
        // keepawake's `sleep` lock is ignored on lid close
        // (LidSwitchIgnoreInhibited=yes). Take the high-level
        // handle-lid-switch lock logind always honors.
        match linux::LidInhibitor::acquire() {
            Ok(lid) => {
                let outcome = AcquireOutcome {
                    lid_close_guaranteed: true,
                    lid_note: None,
                };
                Ok((
                    HeldAssertion {
                        _keepawake: keepawake,
                        _lid: Some(lid),
                    },
                    outcome,
                ))
            }
            Err(why) => {
                // Idle sleep is still suppressed via keepawake; only
                // lid-close can't be guaranteed. Honest note, no silent
                // failure.
                let outcome = AcquireOutcome {
                    lid_close_guaranteed: false,
                    lid_note: Some(why),
                };
                Ok((
                    HeldAssertion {
                        _keepawake: keepawake,
                        _lid: None,
                    },
                    outcome,
                ))
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        // PreventSystemSleep keeps the machine awake but does not
        // override clamshell sleep on battery (the `caffeinate -s`
        // limitation). On AC with an external display the machine stays
        // up; on battery a closed lid still suspends.
        let outcome = AcquireOutcome {
            lid_close_guaranteed: false,
            lid_note: Some(
                "lid-close suspend can't be guaranteed on macOS battery power (clamshell sleep); \
                 keep the machine on AC power to survive a closed lid"
                    .to_string(),
            ),
        };
        Ok((
            HeldAssertion {
                _keepawake: keepawake,
            },
            outcome,
        ))
    }

    #[cfg(target_os = "windows")]
    {
        // ES_SYSTEM_REQUIRED suppresses idle sleep but does not override
        // an explicit "sleep when I close the lid" lid-close power-plan
        // action. Name the setting the user can change.
        let outcome = AcquireOutcome {
            lid_close_guaranteed: false,
            lid_note: Some(
                "lid-close suspend can't be guaranteed on Windows; set Control Panel → Power \
                 Options → \"When I close the lid\" to \"Do nothing\" (while plugged in) to \
                 survive a closed lid"
                    .to_string(),
            ),
        };
        Ok((
            HeldAssertion {
                _keepawake: keepawake,
            },
            outcome,
        ))
    }

    // Any platform keepawake doesn't special-case: report idle-sleep
    // coverage honestly without claiming lid-close.
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let outcome = AcquireOutcome {
            lid_close_guaranteed: false,
            lid_note: Some(
                "lid-close suspend behavior is unknown on this platform; idle sleep is suppressed"
                    .to_string(),
            ),
        };
        Ok((
            HeldAssertion {
                _keepawake: keepawake,
            },
            outcome,
        ))
    }
}

/// Turn a keepawake create-error into an actionable "what's missing"
/// message — the missing-mechanism toast contract (never silent).
fn keepawake_unavailable_message(e: &keepawake::Error) -> String {
    #[cfg(target_os = "linux")]
    {
        format!(
            "no sleep-inhibition mechanism available: {e}. cockpit needs a logind/D-Bus session \
             (systemd) to suppress sleep; headless or non-systemd Linux has no userspace lever"
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        format!("no sleep-inhibition mechanism available: {e}")
    }
}

// ---- Daemon-held controller -------------------------------------------------

/// The applied result of a `SetCaffeinate` request: the resulting state
/// plus an honest, user-facing message for the confirmation toast. Mirrors
/// the `CaffeinateState` proto response/event payload.
#[derive(Debug, Clone)]
pub struct Applied {
    pub state: CaffeineState,
    /// `true` when the assertion is held *and* lid-close survival is
    /// guaranteed on this platform/config. `false` when off, or when the
    /// assertion is held but lid-close can't be guaranteed.
    pub lid_close_guaranteed: bool,
    /// User-facing confirmation text for the toast (token-economy §10).
    pub message: String,
}

/// Daemon-owned caffeination authority. Holds the OS sleep assertion (in
/// the daemon process, the long-lived one) and the on/off + until-idle
/// state behind one mutex. A `/caffeinate` from any client routes here;
/// the result broadcasts to every connected client (so the `☕` chrome
/// glyph stays in sync).
///
/// Generic over [`SleepInhibitor`] so tests can substitute a fake; the
/// daemon constructs it with [`CaffeineController::new`] (the real
/// [`OsInhibitor`]).
pub struct CaffeineController<I: SleepInhibitor = OsInhibitor> {
    state: Mutex<StateInner>,
    inhibitor: Mutex<I>,
}

struct StateInner {
    state: CaffeineState,
    generation: u64,
    /// Whether the currently-held assertion guarantees lid-close survival
    /// (carried so an `idle_check` / re-read can report state without a
    /// fresh acquire).
    lid_close_guaranteed: bool,
}

impl CaffeineController<OsInhibitor> {
    /// Construct the daemon's controller with the real OS inhibitor. The
    /// inhibitor's worker thread is spawned eagerly but parked until the
    /// first `/caffeinate on`.
    pub fn new() -> Self {
        Self::with_inhibitor(OsInhibitor::spawn())
    }
}

impl Default for CaffeineController<OsInhibitor> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I: SleepInhibitor> CaffeineController<I> {
    /// Construct with a specific inhibitor (the daemon uses the real one;
    /// tests pass a fake).
    pub fn with_inhibitor(inhibitor: I) -> Self {
        Self {
            state: Mutex::new(StateInner {
                state: CaffeineState::default(),
                generation: 0,
                lid_close_guaranteed: false,
            }),
            inhibitor: Mutex::new(inhibitor),
        }
    }

    /// Current on/off state (cheap snapshot for new clients on attach).
    pub fn snapshot(&self) -> CaffeineState {
        crate::sync::lock_or_recover(&self.state).state
    }

    /// Whether caffeination is currently in until-idle mode. The daemon's
    /// until-idle watcher polls this to know when to stop (a later
    /// `on`/`off`/`toggle` clears the flag, so the watcher must exit
    /// rather than auto-off a now-explicit `on`).
    pub fn is_until_idle(&self) -> bool {
        let s = crate::sync::lock_or_recover(&self.state).state;
        s.active && s.until_idle
    }

    /// Apply a `/caffeinate` mode request. Acquires/releases the OS
    /// assertion as the [`CaffeineState`] transition dictates, with the
    /// display kept on per `scope`. Returns the [`Applied`] result (the
    /// new state plus the honest toast message). On an acquire failure the
    /// state stays off and the error message is returned for the
    /// missing-mechanism toast.
    pub fn apply(&self, mode: CaffeinateMode, scope: InhibitScope) -> Result<Applied, String> {
        let (generation, t) = {
            let mut inner = crate::sync::lock_or_recover(&self.state);
            inner.generation = inner.generation.wrapping_add(1);
            let generation = inner.generation;
            let t = inner.state.next(mode);
            if t.action == InhibitAction::Release {
                inner.state = t.state;
                inner.lid_close_guaranteed = false;
            }
            (generation, t)
        };

        match t.action {
            InhibitAction::Acquire => {
                let mut inhibitor = crate::sync::lock_or_recover(&self.inhibitor);
                let outcome = inhibitor.acquire(scope);
                match outcome {
                    Ok(outcome) => {
                        let mut release_stale_assertion = false;
                        let applied = {
                            let mut inner = crate::sync::lock_or_recover(&self.state);
                            if inner.generation == generation {
                                inner.state = t.state;
                                inner.lid_close_guaranteed = outcome.lid_close_guaranteed;
                                Applied {
                                    state: inner.state,
                                    lid_close_guaranteed: outcome.lid_close_guaranteed,
                                    message: on_message(inner.state, &outcome),
                                }
                            } else {
                                release_stale_assertion = true;
                                current_applied(&inner)
                            }
                        };
                        if release_stale_assertion {
                            inhibitor.release();
                        }
                        Ok(applied)
                    }
                    Err(message) => {
                        let mut inner = crate::sync::lock_or_recover(&self.state);
                        if inner.generation == generation {
                            inner.state = CaffeineState::default();
                            inner.lid_close_guaranteed = false;
                            Err(message)
                        } else {
                            Ok(current_applied(&inner))
                        }
                    }
                }
            }
            InhibitAction::Release => {
                let should_release = {
                    let inner = crate::sync::lock_or_recover(&self.state);
                    inner.generation == generation
                };
                if should_release {
                    let mut inhibitor = crate::sync::lock_or_recover(&self.inhibitor);
                    let still_current = {
                        let inner = crate::sync::lock_or_recover(&self.state);
                        inner.generation == generation
                    };
                    if still_current {
                        inhibitor.release();
                    }
                }
                let inner = crate::sync::lock_or_recover(&self.state);
                if inner.generation == generation {
                    Ok(Applied {
                        state: inner.state,
                        lid_close_guaranteed: false,
                        message: "caffeinate off".to_string(),
                    })
                } else {
                    Ok(current_applied(&inner))
                }
            }
            InhibitAction::None => {
                // No state change (e.g. `on` while already on). Report the
                // current state without re-acquiring.
                let inner = crate::sync::lock_or_recover(&self.state);
                Ok(current_applied(&inner))
            }
        }
    }

    /// The daemon's until-idle auto-off decision: when in until-idle mode
    /// and no agent is running, release the assertion and drop to off.
    /// Returns `Some(Applied)` (an off result to broadcast) only when a
    /// transition actually happened, so the caller skips no-op broadcasts.
    pub fn idle_check(&self, any_agent_running: bool) -> Option<Applied> {
        let generation = {
            let mut inner = crate::sync::lock_or_recover(&self.state);
            let t = inner.state.idle_check(any_agent_running)?;
            inner.generation = inner.generation.wrapping_add(1);
            inner.state = t.state;
            inner.lid_close_guaranteed = false;
            inner.generation
        };
        let mut inhibitor = crate::sync::lock_or_recover(&self.inhibitor);
        let still_current = {
            let inner = crate::sync::lock_or_recover(&self.state);
            inner.generation == generation
        };
        if still_current {
            inhibitor.release();
        }
        let inner = crate::sync::lock_or_recover(&self.state);
        if inner.generation == generation {
            Some(Applied {
                state: inner.state,
                lid_close_guaranteed: false,
                message: "caffeinate off (no agents running)".to_string(),
            })
        } else {
            None
        }
    }
}

fn current_applied(inner: &StateInner) -> Applied {
    Applied {
        state: inner.state,
        lid_close_guaranteed: inner.lid_close_guaranteed,
        message: if inner.state.active {
            "caffeinate already on".to_string()
        } else {
            "caffeinate already off".to_string()
        },
    }
}

/// Honest confirmation text for an active assertion (token-economy §10).
/// When lid-close isn't guaranteed, the note is appended so the user knows
/// closing the lid may still suspend — never implies coverage it lacks.
fn on_message(state: CaffeineState, outcome: &AcquireOutcome) -> String {
    let base = if state.until_idle {
        "caffeinate on (until no agents running)"
    } else {
        "caffeinate on"
    };
    match (&outcome.lid_note, outcome.lid_close_guaranteed) {
        (Some(note), false) => format!("{base} — note: {note}"),
        _ => base.to_string(),
    }
}

#[cfg(target_os = "linux")]
pub mod linux {
    //! Linux `handle-lid-switch` inhibitor over logind via blocking zbus.
    //!
    //! keepawake takes `idle`+`sleep` logind locks, but logind's
    //! `LidSwitchIgnoreInhibited=yes` (the upstream default) makes those
    //! ignored when the lid closes. The only userspace lock logind
    //! *always* honors is the high-level `handle-lid-switch` inhibitor
    //! (`org.freedesktop.login1.Manager.Inhibit` with
    //! `what="handle-lid-switch"`, `mode="block"`). We hold the returned
    //! fd for the assertion's lifetime; dropping it releases the lock.

    use zbus::blocking::Connection;
    use zbus::zvariant::OwnedFd;

    #[zbus::proxy(
        interface = "org.freedesktop.login1.Manager",
        default_service = "org.freedesktop.login1",
        default_path = "/org/freedesktop/login1"
    )]
    trait Manager {
        fn inhibit(&self, what: &str, who: &str, why: &str, mode: &str) -> zbus::Result<OwnedFd>;
    }

    /// Holds the `handle-lid-switch` inhibitor fd. Dropping it closes the
    /// fd, releasing the lock.
    pub struct LidInhibitor {
        // Keep the connection alive alongside the fd: closing the bus
        // connection would invalidate the lock.
        _conn: Connection,
        _fd: OwnedFd,
    }

    impl LidInhibitor {
        /// Take a `handle-lid-switch:sleep` block lock from logind on the
        /// system bus. Returns `Err(reason)` (an honest, actionable
        /// message) when logind is unreachable — e.g. non-systemd or
        /// headless — so the caller can degrade to "lid-close not
        /// guaranteed" instead of failing silently.
        pub fn acquire() -> Result<Self, String> {
            let conn = Connection::system().map_err(|e| {
                format!(
                    "logind unreachable on the system D-Bus ({e}); lid-close suspend can't be \
                     inhibited without systemd-logind"
                )
            })?;
            let proxy = ManagerProxyBlocking::new(&conn)
                .map_err(|e| format!("logind Manager proxy failed ({e})"))?;
            // `handle-lid-switch` is the high-level inhibitor logind always
            // honors regardless of LidSwitchIgnoreInhibited; combine with
            // `sleep` so a manual suspend during the run is also blocked.
            let fd = proxy
                .inhibit(
                    "handle-lid-switch:sleep",
                    "cockpit",
                    "agents running (/caffeinate)",
                    "block",
                )
                .map_err(|e| {
                    format!(
                        "logind refused the lid-switch inhibitor ({e}); lid-close suspend can't \
                         be guaranteed"
                    )
                })?;
            Ok(Self {
                _conn: conn,
                _fd: fd,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    #[test]
    fn parses_mode_arguments() {
        assert_eq!(CaffeinateMode::parse(""), Ok(CaffeinateMode::Toggle));
        assert_eq!(CaffeinateMode::parse("  "), Ok(CaffeinateMode::Toggle));
        assert_eq!(CaffeinateMode::parse("toggle"), Ok(CaffeinateMode::Toggle));
        assert_eq!(CaffeinateMode::parse("on"), Ok(CaffeinateMode::On));
        assert_eq!(CaffeinateMode::parse("off"), Ok(CaffeinateMode::Off));
        assert_eq!(
            CaffeinateMode::parse("until-idle"),
            Ok(CaffeinateMode::UntilIdle)
        );
        assert_eq!(
            CaffeinateMode::parse("until_idle"),
            Ok(CaffeinateMode::UntilIdle)
        );
        assert_eq!(CaffeinateMode::parse("nope"), Err("nope".to_string()));
    }

    #[test]
    fn toggle_flips_active_and_clears_until_idle() {
        let off = CaffeineState::default();
        let on = off.next(CaffeinateMode::Toggle);
        assert_eq!(
            on.state,
            CaffeineState {
                active: true,
                until_idle: false
            }
        );
        assert_eq!(on.action, InhibitAction::Acquire);

        let back_off = on.state.next(CaffeinateMode::Toggle);
        assert!(!back_off.state.active);
        assert_eq!(back_off.action, InhibitAction::Release);

        // Toggling off an until-idle state still releases + clears the flag.
        let until = CaffeineState {
            active: true,
            until_idle: true,
        };
        let t = until.next(CaffeinateMode::Toggle);
        assert!(!t.state.active);
        assert!(!t.state.until_idle);
        assert_eq!(t.action, InhibitAction::Release);
    }

    #[test]
    fn explicit_on_off_until_idle_transitions() {
        let off = CaffeineState::default();

        let on = off.next(CaffeinateMode::On);
        assert!(on.state.active && !on.state.until_idle);
        assert_eq!(on.action, InhibitAction::Acquire);

        // on→on is a no-op on the inhibitor.
        let still_on = on.state.next(CaffeinateMode::On);
        assert_eq!(still_on.action, InhibitAction::None);

        let until = off.next(CaffeinateMode::UntilIdle);
        assert!(until.state.active && until.state.until_idle);
        assert_eq!(until.action, InhibitAction::Acquire);

        let off2 = until.state.next(CaffeinateMode::Off);
        assert!(!off2.state.active && !off2.state.until_idle);
        assert_eq!(off2.action, InhibitAction::Release);

        // off→off is a no-op.
        let still_off = off.next(CaffeinateMode::Off);
        assert_eq!(still_off.action, InhibitAction::None);
    }

    #[test]
    fn until_idle_auto_off_decided_by_agent_running_flag() {
        let until = CaffeineState {
            active: true,
            until_idle: true,
        };
        // Agent still running: no change.
        assert_eq!(until.idle_check(true), None);
        // No agent running: drop to off + release.
        let t = until.idle_check(false).expect("auto-off transition");
        assert!(!t.state.active && !t.state.until_idle);
        assert_eq!(t.action, InhibitAction::Release);

        // A plain `on` (not until-idle) never auto-offs, even when idle.
        let on = CaffeineState {
            active: true,
            until_idle: false,
        };
        assert_eq!(on.idle_check(false), None);

        // An off state never auto-offs.
        assert_eq!(CaffeineState::default().idle_check(false), None);
    }

    #[test]
    fn scope_maps_from_sleep_scope_setting() {
        assert!(!InhibitScope::from(SleepScope::SystemOnly).keep_display_on);
        assert!(InhibitScope::from(SleepScope::SystemAndDisplay).keep_display_on);
    }

    // ---- Controller-level test with a fake inhibitor ----------------------

    /// Records acquire/release calls so the controller's wiring is tested
    /// without touching the real OS assertion (platform/privilege-bound).
    struct FakeInhibitor {
        acquires: Vec<InhibitScope>,
        releases: usize,
        /// When set, `acquire` fails with this message (missing-mechanism
        /// path).
        fail_with: Option<String>,
        guaranteed: bool,
    }

    impl FakeInhibitor {
        fn new() -> Self {
            Self {
                acquires: Vec::new(),
                releases: 0,
                fail_with: None,
                guaranteed: true,
            }
        }
    }

    impl SleepInhibitor for FakeInhibitor {
        fn acquire(&mut self, scope: InhibitScope) -> Result<AcquireOutcome, String> {
            if let Some(msg) = &self.fail_with {
                return Err(msg.clone());
            }
            self.acquires.push(scope);
            Ok(AcquireOutcome {
                lid_close_guaranteed: self.guaranteed,
                lid_note: if self.guaranteed {
                    None
                } else {
                    Some("lid note".into())
                },
            })
        }

        fn release(&mut self) {
            self.releases += 1;
        }
    }

    struct AcquireStep {
        started: mpsc::Sender<()>,
        finish: mpsc::Receiver<Result<AcquireOutcome, String>>,
    }

    struct BlockingInhibitor {
        acquires: VecDeque<AcquireStep>,
        releases: Arc<AtomicUsize>,
    }

    impl BlockingInhibitor {
        fn new(acquires: Vec<AcquireStep>, releases: Arc<AtomicUsize>) -> Self {
            Self {
                acquires: acquires.into(),
                releases,
            }
        }
    }

    impl SleepInhibitor for BlockingInhibitor {
        fn acquire(&mut self, _scope: InhibitScope) -> Result<AcquireOutcome, String> {
            let step = self.acquires.pop_front().expect("unexpected acquire");
            step.started.send(()).unwrap();
            step.finish.recv().unwrap()
        }

        fn release(&mut self) {
            self.releases.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn acquire_step() -> (
        AcquireStep,
        mpsc::Receiver<()>,
        mpsc::Sender<Result<AcquireOutcome, String>>,
    ) {
        let (started_tx, started_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        (
            AcquireStep {
                started: started_tx,
                finish: finish_rx,
            },
            started_rx,
            finish_tx,
        )
    }

    fn acquire_success() -> Result<AcquireOutcome, String> {
        Ok(AcquireOutcome {
            lid_close_guaranteed: true,
            lid_note: None,
        })
    }

    const SYSTEM_ONLY: InhibitScope = InhibitScope {
        keep_display_on: false,
    };
    const WITH_DISPLAY: InhibitScope = InhibitScope {
        keep_display_on: true,
    };

    #[test]
    fn controller_acquires_on_until_idle_then_auto_releases_when_no_agent() {
        let c = CaffeineController::with_inhibitor(FakeInhibitor::new());
        let applied = c.apply(CaffeinateMode::UntilIdle, SYSTEM_ONLY).unwrap();
        assert!(applied.state.active && applied.state.until_idle);
        assert!(applied.lid_close_guaranteed);

        // Agent still running: daemon decides no auto-off.
        assert!(c.idle_check(true).is_none());
        assert!(c.snapshot().active);

        // No agent running: daemon decides auto-off + releases assertion.
        let off = c.idle_check(false).expect("auto-off");
        assert!(!off.state.active && !off.state.until_idle);
        assert!(off.message.contains("no agents running"));
        assert!(!c.snapshot().active);
    }

    #[test]
    fn controller_passes_display_scope_through_and_is_idempotent() {
        let c = CaffeineController::with_inhibitor(FakeInhibitor::new());
        c.apply(CaffeinateMode::On, WITH_DISPLAY).unwrap();
        // `on` while already on does not re-acquire (cache-safe no-op).
        let again = c.apply(CaffeinateMode::On, WITH_DISPLAY).unwrap();
        assert!(again.message.contains("already on"));
        // Drop into the inhibitor to confirm exactly one acquire with the
        // display scope.
        let inhibitor = crate::sync::lock_or_recover(&c.inhibitor);
        assert_eq!(inhibitor.acquires, vec![WITH_DISPLAY]);
    }

    #[test]
    fn controller_surfaces_missing_mechanism_error_and_stays_off() {
        let mut inhibitor = FakeInhibitor::new();
        inhibitor.fail_with = Some("no logind/D-Bus session".into());
        let c = CaffeineController::with_inhibitor(inhibitor);
        let err = c.apply(CaffeinateMode::On, SYSTEM_ONLY).unwrap_err();
        assert_eq!(err, "no logind/D-Bus session");
        // The state must stay off when the acquire failed (no silent
        // "on" with nothing actually inhibited).
        assert!(!c.snapshot().active);
    }

    #[test]
    fn controller_appends_honest_lid_note_when_not_guaranteed() {
        let mut inhibitor = FakeInhibitor::new();
        inhibitor.guaranteed = false;
        let c = CaffeineController::with_inhibitor(inhibitor);
        let applied = c.apply(CaffeinateMode::On, SYSTEM_ONLY).unwrap();
        assert!(applied.state.active);
        assert!(!applied.lid_close_guaranteed);
        // The toast must carry the honest lid-close note, never imply it
        // is covered.
        assert!(applied.message.contains("note:"));
        assert!(applied.message.contains("lid note"));
    }

    #[test]
    fn controller_toggle_then_off_releases() {
        let c = CaffeineController::with_inhibitor(FakeInhibitor::new());
        assert!(
            c.apply(CaffeinateMode::Toggle, SYSTEM_ONLY)
                .unwrap()
                .state
                .active
        );
        let off = c.apply(CaffeinateMode::Toggle, SYSTEM_ONLY).unwrap();
        assert!(!off.state.active);
        assert_eq!(off.message, "caffeinate off");
        let inhibitor = crate::sync::lock_or_recover(&c.inhibitor);
        assert_eq!(inhibitor.releases, 1);
    }

    #[test]
    fn snapshot_and_until_idle_do_not_wait_for_blocked_acquire() {
        let (step, started, finish) = acquire_step();
        let releases = Arc::new(AtomicUsize::new(0));
        let c = Arc::new(CaffeineController::with_inhibitor(BlockingInhibitor::new(
            vec![step],
            releases,
        )));
        let worker = {
            let c = Arc::clone(&c);
            std::thread::spawn(move || c.apply(CaffeinateMode::UntilIdle, SYSTEM_ONLY).unwrap())
        };
        started.recv().unwrap();

        assert_eq!(c.snapshot(), CaffeineState::default());
        assert!(!c.is_until_idle());

        finish.send(acquire_success()).unwrap();
        let applied = worker.join().unwrap();
        assert!(applied.state.active);
        assert!(applied.state.until_idle);
    }

    #[test]
    fn stale_acquire_after_off_releases_and_leaves_state_off() {
        let (step, started, finish) = acquire_step();
        let releases = Arc::new(AtomicUsize::new(0));
        let c = Arc::new(CaffeineController::with_inhibitor(BlockingInhibitor::new(
            vec![step],
            Arc::clone(&releases),
        )));
        let worker = {
            let c = Arc::clone(&c);
            std::thread::spawn(move || c.apply(CaffeinateMode::On, SYSTEM_ONLY).unwrap())
        };
        started.recv().unwrap();

        let off = c.apply(CaffeinateMode::Off, SYSTEM_ONLY).unwrap();
        assert!(!off.state.active);
        finish.send(acquire_success()).unwrap();
        let stale = worker.join().unwrap();

        assert!(!stale.state.active);
        assert!(!c.snapshot().active);
        assert_eq!(releases.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn newer_on_wins_after_stale_acquire_failure() {
        let (first_step, first_started, first_finish) = acquire_step();
        let (second_step, second_started, second_finish) = acquire_step();
        let releases = Arc::new(AtomicUsize::new(0));
        let c = Arc::new(CaffeineController::with_inhibitor(BlockingInhibitor::new(
            vec![first_step, second_step],
            releases,
        )));

        let stale_worker = {
            let c = Arc::clone(&c);
            std::thread::spawn(move || c.apply(CaffeinateMode::On, SYSTEM_ONLY))
        };
        first_started.recv().unwrap();

        let winning_worker = {
            let c = Arc::clone(&c);
            std::thread::spawn(move || c.apply(CaffeinateMode::On, SYSTEM_ONLY).unwrap())
        };
        while crate::sync::lock_or_recover(&c.state).generation < 2 {
            std::thread::yield_now();
        }
        first_finish.send(Err("missing inhibitor".into())).unwrap();
        second_started.recv().unwrap();
        second_finish.send(acquire_success()).unwrap();

        let stale = stale_worker.join().unwrap().unwrap();
        let winning = winning_worker.join().unwrap();
        assert!(!stale.state.active);
        assert!(winning.state.active);
        assert!(c.snapshot().active);
    }

    #[test]
    fn stale_idle_auto_off_cannot_clear_newer_explicit_on() {
        let c = CaffeineController::with_inhibitor(FakeInhibitor::new());
        c.apply(CaffeinateMode::UntilIdle, SYSTEM_ONLY).unwrap();
        let off = c.idle_check(false).expect("auto-off");
        assert!(!off.state.active);
        let on = c.apply(CaffeinateMode::On, SYSTEM_ONLY).unwrap();
        assert!(on.state.active);
        assert!(!on.state.until_idle);
        assert!(c.idle_check(false).is_none());
        assert!(c.snapshot().active);
    }
}
