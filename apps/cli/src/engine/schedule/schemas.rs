//! Per-action JSON Schemas for the `schedule` meta-tool sub-args.
//!
//! These schemas are **hidden from the model** — the public `schedule` tool
//! schema stays `{action: string, args: object}` (byte-stable, no
//! prompt-cache bust on capability growth; token economy, §10). They exist
//! solely so the dispatcher can run the §12 validate-then-repair contract on
//! the per-action `args` object before handing it to the [`super::spec`]
//! parser — the same coercions (notably string→int) the top-level tool
//! dispatcher gets, applied to `schedule` sub-args (the §22 meta-tool's
//! "actions appear contextually" affordance is preserved).
//!
//! The schemas are deliberately *loose* where `spec.rs` is tolerant by
//! design: `interval` accepts a number **or** a duration string (`"30s"`),
//! and the schemas never re-impose required-field rules the parser doesn't —
//! the parser remains the single source of truth for cross-field invariants
//! (timer == `limit==1`, `limit==0` == unbounded, the interval floor). What
//! the schema buys is the disagreeing-path signal the repair catalog needs:
//! a `limit:"1"` is flagged as a type mismatch at `limit`, the
//! `parse_stringified_number` repair fires, and the parser then sees a real
//! integer instead of erroring on a string.

use serde_json::{Value, json};

use super::spec::ScheduleAction;

/// The hidden per-action schema for `action`'s sub-`args`. Used only for the
/// dispatcher's validate-then-repair pass; never advertised to the model.
///
/// `list` carries an empty-object schema (no args) so the validate+repair
/// pass still runs, just trivially.
pub fn schema_for(action: ScheduleAction) -> Value {
    match action {
        ScheduleAction::LoopStart => json!({
            "type": "object",
            "properties": {
                // Seconds, or a duration string like "30s"/"2m"/"1h" — the
                // parser accepts both, so the schema does too (a bare-number
                // emitter and a duration-string emitter are both clean here;
                // only a non-numeric, non-duration value disagrees).
                "interval": { "type": ["integer", "string"] },
                "prompt": { "type": "string" },
                "backoff": { "type": "boolean" },
                "limit": { "type": "integer", "minimum": 0 },
                "keep_in_context": { "type": "boolean" },
                "independent": { "type": "boolean" }
            }
        }),
        ScheduleAction::LoopCancel => json!({
            "type": "object",
            "properties": {
                "job_id": { "type": "string" }
            }
        }),
        ScheduleAction::BackgroundStart => json!({
            "type": "object",
            "properties": {
                "command": { "type": "string" },
                "cwd": { "type": "string" }
            }
        }),
        ScheduleAction::BackgroundTail => json!({
            "type": "object",
            "properties": {
                "job_id": { "type": "string" },
                "lines": { "type": "integer", "minimum": 1 }
            }
        }),
        ScheduleAction::BackgroundCancel => json!({
            "type": "object",
            "properties": {
                "job_id": { "type": "string" }
            }
        }),
        ScheduleAction::List => json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_action_has_a_compilable_object_schema() {
        for action in [
            ScheduleAction::LoopStart,
            ScheduleAction::LoopCancel,
            ScheduleAction::BackgroundStart,
            ScheduleAction::BackgroundTail,
            ScheduleAction::BackgroundCancel,
            ScheduleAction::List,
        ] {
            let schema = schema_for(action);
            assert_eq!(schema["type"], "object", "{} schema", action.as_str());
            // Every schema compiles (a malformed hand-authored schema is a
            // programming bug; this pins it at test time).
            jsonschema::validator_for(&schema)
                .unwrap_or_else(|e| panic!("{} schema failed to compile: {e}", action.as_str()));
        }
    }

    #[test]
    fn list_schema_rejects_extra_properties() {
        let schema = schema_for(ScheduleAction::List);
        let v = jsonschema::validator_for(&schema).unwrap();
        assert!(v.is_valid(&json!({})));
        assert!(!v.is_valid(&json!({ "stray": 1 })));
    }

    #[test]
    fn loop_start_flags_stringified_numeric_fields() {
        let schema = schema_for(ScheduleAction::LoopStart);
        let v = jsonschema::validator_for(&schema).unwrap();
        // A stringified `limit` is a type mismatch the repair catalog
        // localizes + coerces. (`interval` accepts strings, so it's clean.)
        assert!(!v.is_valid(&json!({ "limit": "1", "prompt": "p", "interval": 5 })));
        assert!(v.is_valid(&json!({ "limit": 1, "prompt": "p", "interval": 5 })));
        // A duration-string interval is clean (parser-tolerated).
        assert!(v.is_valid(&json!({ "interval": "30s", "prompt": "p" })));
    }

    #[test]
    fn background_tail_flags_stringified_lines() {
        let schema = schema_for(ScheduleAction::BackgroundTail);
        let v = jsonschema::validator_for(&schema).unwrap();
        assert!(!v.is_valid(&json!({ "job_id": "x", "lines": "40" })));
        assert!(v.is_valid(&json!({ "job_id": "x", "lines": 40 })));
    }
}
