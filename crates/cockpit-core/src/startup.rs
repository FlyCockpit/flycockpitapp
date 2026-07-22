//! Cold-start timing instrumentation.
//!
//! A single, low-overhead mechanism for breaking down where launch time
//! goes — both the TUI client (`App::new` → first frame + daemon attach)
//! and the daemon (`server::boot` → ready to accept). Everything routes
//! through `tracing` at the dedicated `cockpit::startup` target, level
//! `info`. The default `EnvFilter` is `warn`, so these lines are silent
//! and effectively free in normal runs (a disabled `info!` is just a
//! level check). Enable a breakdown on demand with:
//!
//! ```text
//! COCKPIT_LOG=cockpit::startup=info cockpit
//! ```
//!
//! Daemon child phases land in the daemon's log file (it's spawned with
//! stdio nulled); inherit the env var into it to capture them. The TUI's
//! own phases, including launch-to-first-paint, print to its interactive
//! log file unless `--print-logs`.

use std::time::Instant;

/// `tracing` target every startup-timing line uses. Filter on this to
/// capture (only) the cold-start breakdown.
pub const TARGET: &str = "cockpit::startup";

/// Sequential phase timer. Each [`PhaseTimer::phase`] call logs the
/// elapsed time since the previous mark (or since construction for the
/// first), labelled with the phase name and the owning span name. The
/// emit is a single `tracing::info!` at [`TARGET`]; when that target is
/// disabled (the default) it compiles down to a level check, so there is
/// no always-on overhead and no stray output.
pub struct PhaseTimer {
    span: &'static str,
    start: Instant,
    last: Instant,
}

impl PhaseTimer {
    /// Start timing a named span (e.g. `"daemon::boot"`, `"App::new"`).
    pub fn start(span: &'static str) -> Self {
        let now = Instant::now();
        Self {
            span,
            start: now,
            last: now,
        }
    }

    /// Record the time spent in the phase that just finished. `name`
    /// labels the work between the previous mark and now.
    pub fn phase(&mut self, name: &str) {
        let now = Instant::now();
        let phase_ms = now.duration_since(self.last).as_secs_f64() * 1000.0;
        let total_ms = now.duration_since(self.start).as_secs_f64() * 1000.0;
        tracing::info!(
            target: TARGET,
            span = self.span,
            phase = name,
            phase_ms = format_args!("{phase_ms:.1}"),
            total_ms = format_args!("{total_ms:.1}"),
            "startup phase"
        );
        self.last = now;
    }

    /// Log a final total for the whole span.
    pub fn done(self) {
        let total_ms = self.start.elapsed().as_secs_f64() * 1000.0;
        tracing::info!(
            target: TARGET,
            span = self.span,
            total_ms = format_args!("{total_ms:.1}"),
            "startup complete"
        );
    }
}
