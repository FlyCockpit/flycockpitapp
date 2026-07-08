//! Async-jobs subsystem — loop / timer / background (GOALS §22).
//!
//! Three async capabilities, one `schedule` meta-tool: recurring self-prompts
//! (`loop`), one-shot delayed prompts (`timer` = a `loop` with `limit=1`),
//! and background shell jobs (`background`). They run without blocking the
//! human; their results inject as a late-arriving turn at the next turn
//! boundary.
//!
//! ## Single authority
//!
//! **Main is the single async-job authority** — same shape as cockpit's
//! single-writer (`builder`) and single-lock-authority (daemon) rules. The
//! [`ScheduleAuthority`] lives on the driver (which the session worker owns).
//! Tool calls in the main context post a [`ScheduleCommand`] to the authority;
//! the authority owns the [`ScheduleRegistry`] and spawns the per-job tasks.
//! Spawned job tasks report progress / completion back over a single
//! [`tokio::sync::mpsc`] channel ([`ScheduleEvent`]) that the driver drains at
//! the **same** turn boundary as the user-input queue (see
//! [`crate::engine::driver`]). This preserves the fold semantics: an async
//! result is just another thing folded in at an inference boundary.
//!
//! ## Anti-runaway invariant
//!
//! Forks **cannot** spawn async work. A loop iteration running in an
//! ephemeral fork that calls `loop.start` / `background.start` does not
//! execute the job; instead the `note`/`schedule` tools in the fork record a
//! [`SpawnRequest`] that rides back to main with the fork's terminal
//! return. Main decides whether to honour it. This prevents
//! recursive/runaway loops.
//!
//! ## Scope (v1)
//!
//! - `background` is shell-only (a loop is already a background job).
//! - A configurable [`max_concurrent`](ScheduleAuthority::max_concurrent) cap
//!   guards against accidental fan-out.
//! - Jobs live for the **daemon/session lifetime**. Surviving a daemon
//!   restart is out of scope for v1 — the registry is in-memory only; a
//!   restart drops live jobs (they are not persisted).

pub mod authority;
mod background;
mod loop_runner;
pub mod schemas;
pub mod spec;
mod swarm;
pub mod tandem;

#[cfg(test)]
mod repair_tests;

pub use authority::{ScheduleAuthority, ScheduleCommand, ScheduleEvent};
pub use spec::{
    ScheduleAction, ScheduleKind, loop_start_message, parse_background_cancel,
    parse_background_start, parse_background_tail, parse_loop_cancel, parse_loop_start,
};
pub use tandem::{TandemDispatch, TandemSet, TandemTarget};

/// Default cap on concurrently-running async jobs per session. Generous
/// enough for "watch the deploy + run the test suite + a reminder timer"
/// but low enough that a confused model can't fan out into dozens of
/// background shells. Configurable via
/// `extended.schedule.max_concurrent` (see [`crate::config::extended`]).
pub const DEFAULT_MAX_CONCURRENT_SCHEDULES: usize = 8;

/// Token cap on a single async result injected into main context (loop
/// terminal result, timer fire, background completion). A `cargo build`
/// can dump huge output; this is the §10 budget for what reaches the
/// model, enforced via [`crate::intel::budget::BudgetedWriter`].
pub const ASYNC_RESULT_TOKEN_CAP: usize = 8_192;

/// Token cap on a `background.tail` response.
pub const TAIL_TOKEN_CAP: usize = 1_000;

/// Maximum number of lines a single `background.tail` request may ask for.
pub const BACKGROUND_TAIL_LINE_CAP: usize = 200;

/// Maximum bytes retained for one background stdout/stderr line before it is
/// truncated with an overflow note.
pub const BACKGROUND_LINE_BYTE_CAP: usize = 8 * 1024;

/// Maximum bytes retained in one background job's stdout/stderr ring.
pub const BACKGROUND_RING_BYTE_CAP: usize = 1024 * 1024;

/// Maximum accumulated messages retained by an ephemeral loop fork.
pub const FORK_HISTORY_MESSAGE_CAP: usize = 64;

/// Maximum approximate serialized bytes retained by an ephemeral loop fork.
pub const FORK_HISTORY_BYTE_CAP: usize = 256 * 1024;

/// Maximum tandem shadow requests dispatched per substantive turn.
pub const DEFAULT_TANDEM_DISPATCH_CAP: usize = 4;
