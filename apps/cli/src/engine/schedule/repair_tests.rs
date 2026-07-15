//! Per-action `schedule` sub-arg repair tests
//! (implementation note).
//!
//! These pin the §12 validate-then-repair contract for the `schedule`
//! meta-tool's per-action `args`, driven through the exact pipeline the
//! driver runs: look up the hidden per-action schema
//! ([`super::schemas::schema_for`]), run [`crate::engine::repair::repair`],
//! then hand the repaired `args` to the [`super::spec`] parser. The headline
//! case is the observed weak-model failure (session `ezhcf7`): a model that
//! emits stringified numerics (`limit:"1"`, `interval:"20000"`) must have
//! them coerced rather than looping on a value-vs-type error.

use serde_json::{Value, json};

use super::schemas::schema_for;
use super::spec::{
    ScheduleAction, parse_background_cancel, parse_background_start, parse_background_tail,
    parse_loop_cancel, parse_loop_start,
};
use crate::db::tool_calls::Recovery;
use crate::engine::repair::repair;

/// Run the production per-action repair pass: validate `args` against the
/// hidden schema for `action`, repair on failure, re-validate. Returns the
/// (possibly-repaired) `args` + the recovery the row would record.
fn repair_subargs(action: ScheduleAction, mut args: Value) -> (Value, Recovery) {
    let schema = schema_for(action);
    let recovery = repair(&mut args, &schema, "schedule").recovery;
    (args, recovery)
}

// ---- loop.start: every numeric field (interval, limit) -------------------

#[test]
fn loop_start_coerces_stringified_limit() {
    let (args, recovery) = repair_subargs(
        ScheduleAction::LoopStart,
        json!({ "interval": 30, "prompt": "p", "limit": "1" }),
    );
    // The string was coerced to a real integer.
    assert_eq!(args["limit"], json!(1));
    assert!(matches!(
        recovery,
        Recovery::ShapeRepair {
            stage: "parse_stringified_number",
            ..
        }
    ));
    // The spec parser now sees well-typed input: limit==1 → timer.
    let parsed = parse_loop_start(&args).unwrap();
    assert_eq!(parsed.limit, Some(1));
    assert!(parsed.is_timer());
}

#[test]
fn loop_start_stringified_limit_zero_is_unbounded() {
    // `"0"` coerces to the integer 0, which the parser reads as unbounded.
    let (args, recovery) = repair_subargs(
        ScheduleAction::LoopStart,
        json!({ "interval": 5, "prompt": "p", "limit": "0" }),
    );
    assert_eq!(args["limit"], json!(0));
    assert!(matches!(recovery, Recovery::ShapeRepair { .. }));
    let parsed = parse_loop_start(&args).unwrap();
    assert_eq!(parsed.limit, None, "limit 0 → unbounded");
    assert!(!parsed.limit_defaulted, "explicit 0 is not a default");
}

#[test]
fn loop_start_interval_string_digits_passes_through_to_parser() {
    // `interval` accepts integer OR string in the schema (the parser also
    // accepts `"30s"`-style durations), so a digit-string interval is a
    // *clean* member of the union — no coercion, and the parser reads it.
    let (args, recovery) = repair_subargs(
        ScheduleAction::LoopStart,
        json!({ "interval": "20000", "prompt": "echo hello", "limit": 1 }),
    );
    assert_eq!(recovery, Recovery::Clean, "string interval is schema-valid");
    let parsed = parse_loop_start(&args).unwrap();
    assert_eq!(parsed.interval_secs, 20000);
}

#[test]
fn loop_start_both_numeric_fields_stringified_end_to_end() {
    // The exact observed failure: interval AND limit both stringified. The
    // limit coerces (its schema is integer-only); the interval is a clean
    // union member. Both reach the parser well-typed and the loop builds.
    let (args, _recovery) = repair_subargs(
        ScheduleAction::LoopStart,
        json!({ "interval": "20000", "limit": "1", "prompt": "echo hello" }),
    );
    assert_eq!(args["limit"], json!(1));
    let parsed = parse_loop_start(&args).unwrap();
    assert_eq!(parsed.interval_secs, 20000);
    assert_eq!(parsed.limit, Some(1));
    assert!(parsed.is_timer());
    assert_eq!(parsed.prompt, "echo hello");
}

#[test]
fn loop_start_clean_numeric_input_is_untouched() {
    let original = json!({ "interval": 30, "prompt": "p", "limit": 5 });
    let (args, recovery) = repair_subargs(ScheduleAction::LoopStart, original.clone());
    assert_eq!(recovery, Recovery::Clean);
    assert_eq!(args, original, "clean input is never mutated");
}

#[test]
fn loop_start_non_numeric_limit_falls_through_to_parser_error() {
    // A genuinely non-numeric `limit` can't be coerced; the repair fails to
    // validate and the args fall through to the parser, which produces its
    // existing error wording (improving that wording is out of scope).
    let (args, recovery) = repair_subargs(
        ScheduleAction::LoopStart,
        json!({ "interval": 5, "prompt": "p", "limit": "lots" }),
    );
    // No coercion claimed credit.
    assert_eq!(recovery, Recovery::Clean);
    // The unchanged string reaches the parser, which rejects it with the
    // same wording it uses today.
    let err = parse_loop_start(&args).unwrap_err();
    assert!(
        format!("{err}").contains("`limit` must be a non-negative integer"),
        "got: {err}"
    );
}

// ---- background.tail: the `lines` numeric field --------------------------

#[test]
fn background_tail_coerces_stringified_lines() {
    let (args, recovery) = repair_subargs(
        ScheduleAction::BackgroundTail,
        json!({ "job_id": "x", "lines": "40" }),
    );
    assert_eq!(args["lines"], json!(40));
    assert!(matches!(
        recovery,
        Recovery::ShapeRepair {
            stage: "parse_stringified_number",
            ..
        }
    ));
    let parsed = parse_background_tail(&args).unwrap();
    assert_eq!(parsed.lines, 40);
}

#[test]
fn background_tail_clean_lines_untouched() {
    let original = json!({ "job_id": "x", "lines": 12 });
    let (args, recovery) = repair_subargs(ScheduleAction::BackgroundTail, original.clone());
    assert_eq!(recovery, Recovery::Clean);
    assert_eq!(args, original);
}

// ---- actions with no numeric fields: repair runs trivially ---------------

#[test]
fn loop_cancel_string_job_id_is_clean() {
    let (args, recovery) =
        repair_subargs(ScheduleAction::LoopCancel, json!({ "job_id": "job-abc" }));
    assert_eq!(recovery, Recovery::Clean);
    assert_eq!(parse_loop_cancel(&args).unwrap().job_id, "job-abc");
}

#[test]
fn background_start_string_fields_are_clean() {
    let (args, recovery) = repair_subargs(
        ScheduleAction::BackgroundStart,
        json!({ "command": "cargo test", "cwd": "/tmp" }),
    );
    assert_eq!(recovery, Recovery::Clean);
    let parsed = parse_background_start(&args).unwrap();
    assert_eq!(parsed.command, "cargo test");
    assert_eq!(parsed.cwd.as_deref(), Some("/tmp"));
}

#[test]
fn background_cancel_string_job_id_is_clean() {
    let (args, recovery) = repair_subargs(
        ScheduleAction::BackgroundCancel,
        json!({ "job_id": "job-z" }),
    );
    assert_eq!(recovery, Recovery::Clean);
    assert_eq!(parse_background_cancel(&args).unwrap().job_id, "job-z");
}

#[test]
fn list_empty_object_validates_trivially() {
    // The `list` schema is an empty closed object: an empty args object is
    // clean, and the validate+repair pass runs without complaint.
    let (args, recovery) = repair_subargs(ScheduleAction::List, json!({}));
    assert_eq!(recovery, Recovery::Clean);
    assert!(args.as_object().unwrap().is_empty());
}
