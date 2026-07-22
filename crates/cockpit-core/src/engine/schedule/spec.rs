//! `schedule` meta-tool action schemas + per-action arg parsing.
//!
//! The meta-tool's *outer* schema is fixed and minimal (`action` +
//! `args`) so the tools array stays byte-stable across a conversation
//! (no prompt-cache bust on capability growth). Per-action `args` are
//! validated here, leaning on the §12 repair layer for the loose outer
//! shape: the dispatcher repairs the outer object, then this module does
//! the real per-action validation.

use serde_json::Value;

use crate::engine::tool::invalid_input;

/// The enabled-mid-conversation branches of the `schedule` meta-tool. Parsed
/// from the `action` string; unknown actions are a model-fault invalid
/// input (priority #1 — fail loud, not silent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleAction {
    LoopStart,
    LoopCancel,
    BackgroundStart,
    BackgroundTail,
    BackgroundCancel,
    /// List active jobs (always available in main).
    List,
}

impl ScheduleAction {
    pub const ALL: [Self; 6] = [
        Self::LoopStart,
        Self::LoopCancel,
        Self::BackgroundStart,
        Self::BackgroundTail,
        Self::BackgroundCancel,
        Self::List,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ScheduleAction::LoopStart => "loop.start",
            ScheduleAction::LoopCancel => "loop.cancel",
            ScheduleAction::BackgroundStart => "background.start",
            ScheduleAction::BackgroundTail => "background.tail",
            ScheduleAction::BackgroundCancel => "background.cancel",
            ScheduleAction::List => "list",
        }
    }
}

/// Parse an `action` string into a [`ScheduleAction`]. Returns an
/// invalid-input error (model fault) for an unknown action.
pub fn parse_action(action: &str) -> anyhow::Result<ScheduleAction> {
    match action {
        "loop.start" => Ok(ScheduleAction::LoopStart),
        "loop.cancel" => Ok(ScheduleAction::LoopCancel),
        "background.start" => Ok(ScheduleAction::BackgroundStart),
        "background.tail" => Ok(ScheduleAction::BackgroundTail),
        "background.cancel" => Ok(ScheduleAction::BackgroundCancel),
        "list" => Ok(ScheduleAction::List),
        other => Err(invalid_input(format!(
            "unknown schedule action `{other}` (expected loop.start, loop.cancel, background.start, background.tail, background.cancel, or list)"
        ))),
    }
}

/// What a running job is. `Timer` is a `Loop` with `limit == 1`; the UI
/// renders it distinctly but the scheduler treats both the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleKind {
    Loop,
    Timer,
    Background,
    /// A recursive `Swarm` subagent (GOALS §24) running as a parallel
    /// background job under the global concurrency cap.
    Swarm,
}

impl ScheduleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ScheduleKind::Loop => "loop",
            ScheduleKind::Timer => "timer",
            ScheduleKind::Background => "background",
            ScheduleKind::Swarm => "swarm",
        }
    }
}

/// Validated `loop.start` arguments. `timer` is this with `limit = 1`.
#[derive(Debug, Clone)]
pub struct LoopStartArgs {
    /// Seconds between iterations.
    pub interval_secs: u64,
    /// The self-prompt delivered each iteration.
    pub prompt: String,
    /// Exponential backoff (double the delay each iteration up to a
    /// ceiling). Default false.
    pub backoff: bool,
    /// Max iterations. `None` = unlimited. Default 10. `Some(1)` = timer.
    pub limit: Option<u64>,
    /// `true` when `limit` was absent and [`DEFAULT_LOOP_LIMIT`] was
    /// applied (vs. the model passing an explicit value) — lets the
    /// success message surface the silently-applied default (priority #1,
    /// defensive against weak models).
    pub limit_defaulted: bool,
    /// Each iteration accumulates in the main context (default true) vs.
    /// an ephemeral fork (false).
    pub keep_in_context: bool,
    /// Only meaningful when `keep_in_context == false`: fresh fork per
    /// iteration (true) vs. accumulate-in-fork (false, default).
    pub independent: bool,
}

impl LoopStartArgs {
    /// `true` when this loop is a one-shot timer (`limit == 1`).
    pub fn is_timer(&self) -> bool {
        self.limit == Some(1)
    }

    pub fn kind(&self) -> ScheduleKind {
        if self.is_timer() {
            ScheduleKind::Timer
        } else {
            ScheduleKind::Loop
        }
    }
}

/// Build the `loop.start` success message the model sees. The
/// cancel-instruction hint is present in every case; the prefix varies by
/// how `limit` resolved so a weak model is never silently handed a
/// recurring or unbounded loop (priority #1):
/// - default applied (`limit` absent) → notes the default + how to override,
/// - explicit `N > 0` → unchanged from the base form,
/// - unbounded (`limit == 0` → `None`) → an explicit no-end warning.
pub fn loop_start_message(
    noun: &str,
    job_id: &str,
    limit: Option<u64>,
    limit_defaulted: bool,
) -> String {
    let cancel =
        format!("cancel with schedule(action=\"loop.cancel\", args={{\"job_id\":\"{job_id}\"}})");
    if limit.is_none() {
        format!("started {noun} `{job_id}` (unbounded — no end) — {cancel}")
    } else if limit_defaulted {
        format!(
            "started {noun} `{job_id}` (limit defaulted to {DEFAULT_LOOP_LIMIT} iterations — set limit=0 for unbounded, or specify a value) — {cancel}"
        )
    } else {
        format!("started {noun} `{job_id}` — {cancel}")
    }
}

/// Ceiling on the backoff delay so an exponential loop can't drift to
/// effectively-never. Five minutes is plenty for a poll loop.
pub const BACKOFF_CEILING_SECS: u64 = 300;

/// Minimum loop interval. A weak model emitting `interval: 0` would
/// otherwise busy-loop the provider; clamp to a sane floor.
pub const MIN_INTERVAL_SECS: u64 = 1;

/// Default loop iteration cap (GOALS §22).
pub const DEFAULT_LOOP_LIMIT: u64 = 10;

/// Maximum finite loop iteration cap. Longer-running loops must use
/// `limit: 0`, which routes through the interactive approval gate.
pub const MAX_LOOP_LIMIT: u64 = 100;

/// Parse + validate `loop.start` args. Accepts `interval` as either a
/// number of seconds or a string like `"30s"` / `"2m"` / `"1h"` —
/// defensive against weak models (priority #1). `limit: 0` means
/// unlimited.
pub fn parse_loop_start(args: &Value) -> anyhow::Result<LoopStartArgs> {
    let prompt = args
        .get("prompt")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| invalid_input("`prompt` is required and must be a non-empty string"))?
        .to_string();

    let interval_secs = match args.get("interval") {
        Some(Value::Number(n)) => n.as_u64().or_else(|| n.as_f64().map(|f| f as u64)),
        Some(Value::String(s)) => parse_duration_secs(s),
        _ => None,
    }
    .ok_or_else(|| {
        invalid_input("`interval` is required (seconds, or a string like \"30s\"/\"2m\"/\"1h\")")
    })?
    .max(MIN_INTERVAL_SECS);

    let backoff = args
        .get("backoff")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // limit: absent → default 10; 0 → unlimited; >0 → that cap.
    let mut limit_defaulted = false;
    let limit = match args.get("limit") {
        None | Some(Value::Null) => {
            limit_defaulted = true;
            Some(DEFAULT_LOOP_LIMIT)
        }
        Some(v) => match v.as_u64() {
            Some(0) => None,
            Some(n) if n > MAX_LOOP_LIMIT => {
                return Err(invalid_input(format!(
                    "`limit` {n} exceeds the maximum of {MAX_LOOP_LIMIT} iterations; for genuinely long-running work use `limit: 0` (unbounded), which requires the user's interactive approval, or split the work into a shorter loop"
                )));
            }
            Some(n) => Some(n),
            None => {
                return Err(invalid_input("`limit` must be a non-negative integer"));
            }
        },
    };

    let keep_in_context = args
        .get("keep_in_context")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let independent = args
        .get("independent")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    Ok(LoopStartArgs {
        interval_secs,
        prompt,
        backoff,
        limit,
        limit_defaulted,
        keep_in_context,
        independent,
    })
}

/// `loop.cancel` args — a job id.
#[derive(Debug, Clone)]
pub struct LoopCancelArgs {
    pub job_id: String,
}

pub fn parse_loop_cancel(args: &Value) -> anyhow::Result<LoopCancelArgs> {
    let job_id = args
        .get("job_id")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| invalid_input("`job_id` is required"))?
        .to_string();
    Ok(LoopCancelArgs { job_id })
}

/// `background.start` args — a shell command.
#[derive(Debug, Clone)]
pub struct BackgroundStartArgs {
    pub command: String,
    /// Optional working directory; defaults to the session cwd.
    pub cwd: Option<String>,
}

pub fn parse_background_start(args: &Value) -> anyhow::Result<BackgroundStartArgs> {
    let command = args
        .get("command")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| invalid_input("`command` is required"))?
        .to_string();
    let cwd = args.get("cwd").and_then(Value::as_str).map(str::to_string);
    Ok(BackgroundStartArgs { command, cwd })
}

/// `background.tail` args — a job id and an optional line count.
#[derive(Debug, Clone)]
pub struct BackgroundTailArgs {
    pub job_id: String,
    pub lines: usize,
}

/// Default number of trailing lines `background.tail` returns.
pub const DEFAULT_TAIL_LINES: usize = 40;

pub fn parse_background_tail(args: &Value) -> anyhow::Result<BackgroundTailArgs> {
    let job_id = args
        .get("job_id")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| invalid_input("`job_id` is required"))?
        .to_string();
    let lines = args
        .get("lines")
        .and_then(Value::as_u64)
        .map(|n| n as usize)
        .unwrap_or(DEFAULT_TAIL_LINES)
        .clamp(1, super::BACKGROUND_TAIL_LINE_CAP);
    Ok(BackgroundTailArgs { job_id, lines })
}

/// `background.cancel` args — a job id.
#[derive(Debug, Clone)]
pub struct BackgroundCancelArgs {
    pub job_id: String,
}

pub fn parse_background_cancel(args: &Value) -> anyhow::Result<BackgroundCancelArgs> {
    let job_id = args
        .get("job_id")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| invalid_input("`job_id` is required"))?
        .to_string();
    Ok(BackgroundCancelArgs { job_id })
}

/// A create-action a fork emitted that main must decide whether to honour
/// (anti-runaway: forks request, they do not spawn). Rides back to main
/// bundled with the fork's terminal return.
#[derive(Debug, Clone)]
pub enum SpawnRequest {
    Loop(LoopStartArgs),
    Background(BackgroundStartArgs),
}

impl SpawnRequest {
    /// One-line human description for the request chip surfaced to main.
    pub fn summary(&self) -> String {
        match self {
            SpawnRequest::Loop(a) => {
                let kind = if a.is_timer() { "timer" } else { "loop" };
                format!(
                    "{kind}(interval={}s, prompt={:?})",
                    a.interval_secs,
                    snippet(&a.prompt)
                )
            }
            SpawnRequest::Background(a) => {
                format!("background({:?})", snippet(&a.command))
            }
        }
    }
}

fn snippet(s: &str) -> String {
    let first = s.lines().next().unwrap_or("").trim();
    if first.chars().count() > 60 {
        let t: String = first.chars().take(60).collect();
        format!("{t}…")
    } else {
        first.to_string()
    }
}

/// Parse a duration string like `"30s"`, `"2m"`, `"1h"`, or a bare
/// number (seconds). Returns `None` on garbage.
pub fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    let split = s.len() - s.chars().next_back()?.len_utf8();
    let (num, unit) = s.split_at(split);
    let n: u64 = num.trim().parse().ok()?;
    match unit {
        "s" | "S" => Some(n),
        "m" | "M" => Some(n.saturating_mul(60)),
        "h" | "H" => Some(n.saturating_mul(3600)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_action_known_and_unknown() {
        assert_eq!(
            parse_action("loop.start").unwrap(),
            ScheduleAction::LoopStart
        );
        assert_eq!(parse_action("list").unwrap(), ScheduleAction::List);
        assert!(parse_action("loop.frobnicate").is_err());
    }

    #[test]
    fn loop_start_defaults() {
        let a = parse_loop_start(&json!({ "interval": 30, "prompt": "check it" })).unwrap();
        assert_eq!(a.interval_secs, 30);
        assert_eq!(a.limit, Some(DEFAULT_LOOP_LIMIT));
        assert!(a.keep_in_context);
        assert!(!a.independent);
        assert!(!a.backoff);
        assert!(!a.is_timer());
        assert_eq!(a.kind(), ScheduleKind::Loop);
    }

    #[test]
    fn loop_start_default_sets_limit_defaulted_flag() {
        let a = parse_loop_start(&json!({ "interval": 30, "prompt": "p" })).unwrap();
        assert!(a.limit_defaulted);
        // An explicit value (even one equal to the default) is not "defaulted".
        let b = parse_loop_start(&json!({ "interval": 30, "prompt": "p", "limit": 10 })).unwrap();
        assert!(!b.limit_defaulted);
        let c = parse_loop_start(&json!({ "interval": 30, "prompt": "p", "limit": 0 })).unwrap();
        assert!(!c.limit_defaulted);
    }

    #[test]
    fn loop_start_message_default_applied() {
        // limit absent → default-applied note + override hint, plus cancel.
        let a = parse_loop_start(&json!({ "interval": 30, "prompt": "p" })).unwrap();
        let m = loop_start_message("loop", "sched-x", a.limit, a.limit_defaulted);
        assert!(m.contains("defaulted to 10 iterations"), "got {m}");
        assert!(m.contains("set limit=0 for unbounded"), "got {m}");
        assert!(m.contains("loop.cancel"), "cancel hint present: {m}");
    }

    #[test]
    fn loop_start_message_explicit_positive_unchanged() {
        // explicit N > 0 → base form only (no default note, no unbounded warning).
        let a = parse_loop_start(&json!({ "interval": 30, "prompt": "p", "limit": 5 })).unwrap();
        let m = loop_start_message("loop", "sched-x", a.limit, a.limit_defaulted);
        assert_eq!(
            m,
            "started loop `sched-x` — cancel with schedule(action=\"loop.cancel\", args={\"job_id\":\"sched-x\"})"
        );
        assert!(!m.contains("defaulted"), "no default note: {m}");
        assert!(!m.contains("unbounded"), "no unbounded warning: {m}");
    }

    #[test]
    fn loop_start_message_unbounded_warns() {
        // limit=0 → unbounded warning + cancel, even though explicitly asked.
        let a = parse_loop_start(&json!({ "interval": 30, "prompt": "p", "limit": 0 })).unwrap();
        assert_eq!(a.limit, None);
        let m = loop_start_message("loop", "sched-x", a.limit, a.limit_defaulted);
        assert!(m.contains("unbounded"), "got {m}");
        assert!(m.contains("loop.cancel"), "cancel hint present: {m}");
        assert!(!m.contains("defaulted"), "no default note: {m}");
    }

    #[test]
    fn loop_start_limit_one_is_timer() {
        let a =
            parse_loop_start(&json!({ "interval": "5m", "prompt": "fire", "limit": 1 })).unwrap();
        assert!(a.is_timer());
        assert_eq!(a.kind(), ScheduleKind::Timer);
        assert_eq!(a.interval_secs, 300);
    }

    #[test]
    fn loop_start_limit_zero_is_unlimited() {
        let a = parse_loop_start(&json!({ "interval": 10, "prompt": "p", "limit": 0 })).unwrap();
        assert_eq!(a.limit, None);
    }

    #[test]
    fn schedule_loop_limit_rejects_above_ceiling() {
        let err = parse_loop_start(
            &json!({ "interval": 10, "prompt": "p", "limit": MAX_LOOP_LIMIT + 1 }),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains(&(MAX_LOOP_LIMIT + 1).to_string()), "{err}");
        assert!(err.contains(&MAX_LOOP_LIMIT.to_string()), "{err}");
    }

    #[test]
    fn schedule_loop_limit_error_names_unbounded_path() {
        let err = parse_loop_start(&json!({ "interval": 10, "prompt": "p", "limit": 1000 }))
            .unwrap_err()
            .to_string();

        assert!(err.contains("1000"), "{err}");
        assert!(err.contains("100"), "{err}");
        assert!(err.contains("limit: 0"), "{err}");
        assert!(err.contains("approval"), "{err}");
    }

    #[test]
    fn schedule_loop_limit_accepts_ceiling_exactly() {
        let a =
            parse_loop_start(&json!({ "interval": 10, "prompt": "p", "limit": MAX_LOOP_LIMIT }))
                .unwrap();

        assert_eq!(a.limit, Some(MAX_LOOP_LIMIT));
    }

    #[test]
    fn schedule_loop_limit_zero_still_means_unbounded() {
        let a = parse_loop_start(&json!({ "interval": 10, "prompt": "p", "limit": 0 })).unwrap();

        assert_eq!(a.limit, None);
        assert!(!a.limit_defaulted);
    }

    #[test]
    fn schedule_loop_limit_omitted_still_defaults() {
        let a = parse_loop_start(&json!({ "interval": 10, "prompt": "p" })).unwrap();

        assert_eq!(a.limit, Some(DEFAULT_LOOP_LIMIT));
        assert!(a.limit_defaulted);
    }

    #[test]
    fn loop_start_missing_prompt_errors() {
        assert!(parse_loop_start(&json!({ "interval": 10 })).is_err());
        assert!(parse_loop_start(&json!({ "interval": 10, "prompt": "  " })).is_err());
    }

    #[test]
    fn loop_start_missing_interval_errors() {
        assert!(parse_loop_start(&json!({ "prompt": "p" })).is_err());
    }

    #[test]
    fn interval_floor_clamps_zero() {
        let a = parse_loop_start(&json!({ "interval": 0, "prompt": "p" })).unwrap();
        assert_eq!(a.interval_secs, MIN_INTERVAL_SECS);
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(parse_duration_secs("30"), Some(30));
        assert_eq!(parse_duration_secs("30s"), Some(30));
        assert_eq!(parse_duration_secs("2m"), Some(120));
        assert_eq!(parse_duration_secs("1h"), Some(3600));
        assert_eq!(parse_duration_secs("nonsense"), None);
        assert_eq!(parse_duration_secs(""), None);
        // Multibyte trailing char must not panic on the split.
        assert_eq!(parse_duration_secs("30µ"), None);
    }

    #[test]
    fn background_start_requires_command() {
        assert!(parse_background_start(&json!({})).is_err());
        let a = parse_background_start(&json!({ "command": "cargo test" })).unwrap();
        assert_eq!(a.command, "cargo test");
        assert!(a.cwd.is_none());
    }

    #[test]
    fn background_tail_clamps_lines() {
        let a = parse_background_tail(&json!({ "job_id": "x", "lines": 99999 })).unwrap();
        assert_eq!(a.lines, super::super::BACKGROUND_TAIL_LINE_CAP);
        let b = parse_background_tail(&json!({ "job_id": "x" })).unwrap();
        assert_eq!(b.lines, DEFAULT_TAIL_LINES);
    }
}
