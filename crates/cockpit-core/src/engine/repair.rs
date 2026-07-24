//! Tool-input repair — the §12 catalog (schema-driven validate-then-repair).
//!
//! The flow is the inverse of a preprocessing pass:
//!
//!   1. Compile the tool's own `parameters()` JSON Schema and **validate
//!      `args` as-is**. If it validates, the input is dispatched
//!      *untouched* (`Recovery::Clean`) — a clean input is never mutated.
//!   2. On failure, the validator hands us the exact *instance paths* it
//!      disagreed at. For each disagreeing path we walk a fixed catalog
//!      of one-step repairs, applying the single repair whose
//!      (expected-type-from-schema, actual-type, actual-value) signature
//!      matches at that path.
//!   3. We **re-validate**. Clean now → the repair succeeded. Still
//!      invalid → hard-fail with a model-readable retry message; we do
//!      not loop.
//!
//! Letting the validator complain first means the *schema* is the prior:
//! repair budget is spent only at the paths that actually disagreed, and
//! a `writeunlock` whose `content` happens to be JSON-shaped is never
//! rewritten because the schema never complained about it.
//!
//! ## The catalog (order is load-bearing)
//!
//!   1. `null_for_optional`     — a `null` value → omit the field
//!      (every cockpit tool treats missing == null for optionals).
//!   2. `parse_stringified_number` — a JSON *string* that parses to a
//!      number where the schema wants `integer`/`number` → the real
//!      number (a weak model emits `"limit":"1"` for a numeric field).
//!   3. `parse_stringified_array` — a JSON *string* that parses to an
//!      array where the schema wants an array → the real array.
//!   4. `wrap_bare_string`      — a bare string where the schema wants an
//!      array → `[s]`.
//!   5. `markdown_autolink_unwrap` — a degenerate markdown auto-link in a
//!      schema-declared **path** field → the bare path.
//!
//! ## Fabricated-absolute-path normalization (path fields, post-schema)
//!
//! Separate from the shape catalog above (it needs the project root + the
//! filesystem, which the shape stages never touch), [`normalize_paths`]
//! runs after a schema-valid call and rewrites a fabricated absolute path.
//! A weak model with no cwd anchor sometimes invents an absolute prefix
//! (`/home/user/repo/src/x.rs`) for a path it was handed as relative. When
//! such an absolute value (in an `x-cockpit-kind: path` field) does **not**
//! exist on disk but a root-relative *tail* of it **does** exist under the
//! real root (longest matching tail wins), the value is rewritten to that
//! tail and recorded as `shape_repair / absolute_prefix_rewrite` (§14
//! split: the model sees the canonical tail, the user sees the original
//! with a `⟲ repaired` chip). It runs **before** the sandbox / native-tool
//! cwd-confinement checks and never escapes them — a tail that would
//! resolve outside the canonical root is rejected, not rewritten. An
//! absolute path that exists (a legitimate in-project absolute, or a
//! permitted out-of-project read like `/etc/...`) is left untouched; one
//! that neither exists nor has a salvageable tail yields a clear,
//! model-legible error instead of a raw OS "No such file or directory".
//! The complementary anchor lives in the system prompt (GOALS §17g now
//! carries the absolute working directory).
//!
//! `parse_stringified_array` MUST precede `wrap_bare_string`: otherwise
//! `'["a","b"]'` would be wrapped into `['["a","b"]']` before the parse
//! stage ever sees it. Path fields are marked declaratively in each
//! tool's schema with `"x-cockpit-kind": "path"` (a non-prose annotation,
//! so token economy holds) and read back here — that plugs the
//! auto-link leak for every path field at once.
//!
//! ## Deferred — item 1c (`{}`-placeholder → array)
//!
//! The "empty placeholder" repair (a single arg wrapped in `{}` where the
//! schema wanted an array) is **deliberately not implemented**. Its exact
//! JSON shape is ambiguous in `tool-correction.txt`, and this module's
//! rule is that every repair must justify itself against a *logged*
//! failure mode. The `tool_input_invalid` telemetry event (emitted on
//! every unrecoverable failure) is the trigger: once it reveals the real
//! shape models emit, 1c lands as a fifth catalog stage between
//! `parse_stringified_array` and `wrap_bare_string`. No stub ships before
//! then.

use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::db::tool_calls::Recovery;

#[cfg(test)]
use crate::db::tool_calls::{NAME_REPAIR_STAGES, SHAPE_REPAIR_STAGES};

/// Schema annotation marking a property whose value is a filesystem path.
/// Read by [`markdown_autolink_unwrap`]; it is a single keyword, not prose
/// (token economy, §10).
pub const PATH_KIND_KEY: &str = "x-cockpit-kind";
pub const PATH_KIND_VALUE: &str = "path";

/// Schema annotation listing the recognized **alias** names for a property
/// (an array of strings). Read by [`rename_aliased_field`]; a single
/// non-prose keyword, never injected into the model-facing description text
/// (token economy, §10). A weak model that emits a property's alias
/// (`file_path` for `path`, `cmd` for `command`) has the alias renamed to
/// the canonical property before re-validation. See
/// implementation note.
pub const ALIASES_KEY: &str = "x-cockpit-aliases";

/// Schema annotation naming a tool's **primary field** — the single property a
/// bare-string whole-input should be wrapped into. Declared on the tool's
/// **root** schema (not on a property), e.g. `x-cockpit-primary-field:
/// "pattern"` for `search`. Read by [`wrap_root_string_as_object`]; a single
/// non-prose keyword, never injected into the model-facing description text
/// (token economy, §10). A tool *without* this annotation is never wrapped (no
/// guess). See implementation note.
pub const PRIMARY_FIELD_KEY: &str = "x-cockpit-primary-field";

/// Stage name recorded by the field-alias rename pass. Kept in
/// [`SHAPE_REPAIR_STAGES`] so the audit reader round-trips it.
const RENAME_ALIASED_FIELD: &str = "rename_aliased_field";

/// Stage name recorded by the root-string-wrap pre-pass. Kept in
/// [`SHAPE_REPAIR_STAGES`] so the audit reader round-trips it.
const WRAP_ROOT_STRING_AS_OBJECT: &str = "wrap_root_string_as_object";
const PARSE_ROOT_STRING_AS_OBJECT: &str = "parse_root_string_as_object";
const REPAIR_NOTE_MAX_CHARS: usize = 1024;
const REPAIR_NOTE_TRUNCATED_SUFFIX: &str = "... [truncated]";
const EXPECTED_SCHEMA_MAX_CHARS: usize = 360;
const SALVAGE_TAIL_MAX_COMPONENTS: usize = 256;

/// Fallback name for a sanitized tool name that coerces to the empty string
/// (`ai-sdk-heal`'s `sanitizeToolName` shape). Always matches
/// `^[a-zA-Z0-9_-]{1,64}$`.
pub const SANITIZE_FALLBACK_NAME: &str = "unknown_tool";

/// Outcome of the two-layer tool-name repair run *before* schema lookup and
/// dispatch (implementation note).
///
/// `name` is the form dispatch and history should use:
///   - the emitted name unchanged on a clean exact match (`recovery` is
///     `Clean`) — a zero-cost passthrough, byte-identical to today;
///   - the registered tool's canonical name on a layer-(a) **rebind**;
///   - the charset-sanitized (provider-valid) name on a layer-(b)
///     **sanitize** of a still-unknown name.
///
/// `recovery` is `Clean` only on the zero-cost exact-match path; otherwise it
/// is a [`Recovery::NameRepair`] carrying the original (emitted) name for the
/// §14 wire-vs-user split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameRepairOutcome {
    pub name: String,
    pub recovery: Recovery,
}

/// Two-layer tool-name repair (implementation note), run at
/// dispatch *before* the registry lookup and the args validate-then-repair
/// (§12). `emitted` is the name the model produced; `known` is the agent's
/// registered tool-name set.
///
/// Order of operations:
///   0. **Exact match first** — if `emitted` is already a registered name,
///      return it untouched with `Recovery::Clean`. Zero repair, no chip,
///      byte-identical to today (and idempotent: a clean name re-run is a
///      no-op).
///   1. **(a) Normalize-and-rebind** — deterministically normalize `emitted`
///      (trim, strip surrounding quotes/angle-brackets, drop a
///      `functions.`-style namespace prefix, lowercase) and exact-match the
///      result against `known`. On a unique match, rebind to that tool
///      (`NameRepair { stage: "rebind" }`). NEVER fuzzy/edit-distance — only
///      an exact match after deterministic transforms rebinds, so `reed`
///      never becomes `read`.
///   2. **(b) Charset-sanitize** — if (a) did not resolve, coerce `emitted`
///      to `^[a-zA-Z0-9_-]{1,64}$` (every other char → `_`, truncate to 64,
///      empty → [`SANITIZE_FALLBACK_NAME`]) so the failed (still-unknown)
///      `tool_use` left in history is provider-valid (`NameRepair { stage:
///      "sanitize" }`). The call still fails as "unknown tool" downstream.
pub fn repair_tool_name(emitted: &str, known: &[&str]) -> NameRepairOutcome {
    // 0. Exact match — the common path. Zero-cost passthrough, no recovery.
    if known.contains(&emitted) {
        return NameRepairOutcome {
            name: emitted.to_string(),
            recovery: Recovery::Clean,
        };
    }

    // 0b. Renamed-tool alias: a model that hallucinates a tool's former name is
    // recovered to its current name (not a durable second advertised name — see
    // implementation note). Only rebinds when the current name
    // is actually registered, and runs before normalize so it composes with the
    // text-embedded-recovery caller (implementation note).
    if let Some(canonical) = renamed_tool_alias(emitted)
        && known.contains(&canonical)
    {
        return NameRepairOutcome {
            name: canonical.to_string(),
            recovery: Recovery::NameRepair {
                stage: "rebind",
                original: emitted.to_string(),
            },
        };
    }

    // (a) Deterministic normalize, then exact-match (case-folded).
    let normalized = normalize_tool_name(emitted);
    if let Some(canonical) = known.iter().find(|k| **k == normalized) {
        return NameRepairOutcome {
            name: canonical.to_string(),
            recovery: Recovery::NameRepair {
                stage: "rebind",
                original: emitted.to_string(),
            },
        };
    }

    // (b) Charset-sanitize a still-unknown name so it can't 400 the provider.
    let sanitized = sanitize_tool_name(emitted);
    // Idempotence + zero-cost: if the sanitized form is byte-identical to the
    // emitted name (already provider-valid, just not a known tool), the call
    // fails as unknown-tool exactly as today, with no spurious recovery chip.
    if sanitized == emitted {
        return NameRepairOutcome {
            name: sanitized,
            recovery: Recovery::Clean,
        };
    }
    NameRepairOutcome {
        name: sanitized,
        recovery: Recovery::NameRepair {
            stage: "sanitize",
            original: emitted.to_string(),
        },
    }
}

/// Map a model-emitted *former* tool name to its current name, after a
/// case-fold (`Jobs`/`JOBS` → `schedule`). Returns `None` when there is no
/// rename. The caller only rebinds if the current name is registered, so this
/// is a defensive recovery for a hallucinated old name — never a durable alias.
fn renamed_tool_alias(emitted: &str) -> Option<&'static str> {
    match emitted.trim().to_lowercase().as_str() {
        // `jobs` collided with the POSIX `jobs` shell builtin and was renamed
        // (implementation note).
        "jobs" => Some("schedule"),
        _ => None,
    }
}

/// Deterministically normalize an emitted tool name for the layer-(a) exact
/// rebind match. Transforms only — never a fuzzy guess:
///   - trim surrounding whitespace / newlines;
///   - strip a single layer of surrounding quotes (`"`/`'`) or angle
///     brackets (`<…>`), re-trimming after each strip;
///   - drop a leading namespace prefix up to and including the last `.`
///     (`functions.read` → `read`, `namespace.functions.read` → `read`);
///   - lowercase (built-ins are uniquely-named lowercase, so this is an
///     unambiguous fold, not a guess).
fn normalize_tool_name(name: &str) -> String {
    let mut s = name.trim();
    // Peel surrounding quote/bracket wrappers, innermost-last, re-trimming so
    // `< "read" >`-style nestings collapse. Bounded by `s` shrinking each
    // iteration; stops when no wrapper remains.
    loop {
        let stripped = s
            .strip_prefix('<')
            .and_then(|inner| inner.strip_suffix('>'))
            .or_else(|| s.strip_prefix('"').and_then(|i| i.strip_suffix('"')))
            .or_else(|| s.strip_prefix('\'').and_then(|i| i.strip_suffix('\'')));
        match stripped {
            Some(inner) => s = inner.trim(),
            None => break,
        }
    }
    // Drop a leading namespace prefix (`functions.`, `tools.`, …). Everything
    // up to and including the last `.` is the namespace; the tail is the name.
    let tail = match s.rsplit_once('.') {
        Some((_, tail)) => tail,
        None => s,
    };
    tail.to_lowercase()
}

/// Charset-sanitize a tool name to `^[a-zA-Z0-9_-]{1,64}$` (`ai-sdk-heal`'s
/// `sanitizeToolName` shape): every char outside `[a-zA-Z0-9_-]` becomes `_`,
/// truncate to 64 chars, and an empty result becomes
/// [`SANITIZE_FALLBACK_NAME`]. Idempotent — a name already in the charset and
/// ≤64 chars is returned unchanged.
fn sanitize_tool_name(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if out.is_empty() {
        out.push_str(SANITIZE_FALLBACK_NAME);
    }
    out
}

/// Outcome of a validate-then-repair pass.
///
/// `recovery` is what gets persisted to the audit row (`Clean` when the
/// input validated as-is). `valid` is `true` when `args` validates after
/// any repair — the dispatcher proceeds to `Tool::call` only then.
/// `error` carries the model-readable diagnostic for the unrecoverable
/// case (`valid == false`); it's `None` on success.
///
/// `hints` carries one terse, model-facing correction line per repair rule
/// that actually fired, in catalog order
/// (implementation note) — e.g. ``Renamed `file_path`
/// to `path`; use `path` next time.`` for an alias rename, or ``Dropped
/// null `limit`; omit optional fields.`` for a stripped null. It is empty
/// on a `Clean` pass and for stages that have no useful hint. The
/// dispatcher prepends each as `<repair_note>{hint}</repair_note>` to the
/// **wire** tool_result only when `hintToolCallCorrections` resolves true
/// for the active model — otherwise it is ignored (silent canonical
/// rewrite + user chip, as before). Like `Recovery::ShapeRepair`'s `path`,
/// it is in-memory only (never a persisted DB column).
///
/// `telemetry` carries the §12 shape-fingerprint diagnostics for the call
/// (implementation note): the stable
/// `shape_fingerprint`, the deduped validator `issue_codes`, the
/// top-level `received_keys` summary (keys only — never values), and the
/// `rules_fired` stage names. It is `None` on a `Clean` pass (the input
/// validated as-is — there is no malformed shape to fingerprint) and
/// `Some` on **both** a recovered repair and an unrecoverable hard-fail,
/// so the dispatcher can emit it (with the active model) and persist the
/// fingerprint for grouping in `cockpit debug failed-calls`.
#[derive(Debug)]
pub struct RepairOutcome {
    pub recovery: Recovery,
    pub valid: bool,
    pub error: Option<String>,
    pub hints: Vec<String>,
    pub telemetry: Option<RepairTelemetry>,
}

/// Escape and bound model-facing repair-note text before it is inserted into
/// `<repair_note>...</repair_note>` scaffolding.
pub(crate) fn repair_note_for_prompt(note: &str) -> String {
    let mut escaped = String::with_capacity(note.len().min(REPAIR_NOTE_MAX_CHARS));
    for ch in note.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }

    if escaped.chars().count() <= REPAIR_NOTE_MAX_CHARS {
        return escaped;
    }

    let keep = REPAIR_NOTE_MAX_CHARS.saturating_sub(REPAIR_NOTE_TRUNCATED_SUFFIX.len());
    let mut truncated: String = escaped.chars().take(keep).collect();
    truncated.push_str(REPAIR_NOTE_TRUNCATED_SUFFIX);
    truncated
}

/// §12 repair-telemetry diagnostics for a non-clean tool call
/// (implementation note). Computed from the
/// validator's errors over the *original* (pre-repair) input; carried on
/// [`RepairOutcome`] so the dispatcher can emit it alongside the active
/// model and persist the fingerprint. Never carries argument **values** —
/// only keys, error codes, and the fingerprint (no secret leakage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairTelemetry {
    /// Short stable hash of `tool :: sorted[ instance_path | error_code |
    /// expected | received ]` over the validator's errors. Identical
    /// malformed shapes (differing only in concrete values) collapse to one
    /// fingerprint, so they're countable; a different missing field or type
    /// produces a different one.
    pub shape_fingerprint: String,
    /// The deduped, sorted set of validator error-kind codes (e.g.
    /// `required`, `type`), space-free and value-free.
    pub issue_codes: Vec<String>,
    /// The input's top-level keys, sorted and truncated to
    /// [`RECEIVED_KEYS_CAP`] with a `…+N` overflow marker. Keys only.
    pub received_keys: Vec<String>,
    /// The repair stage name(s) that fired, in the order recorded. Empty for
    /// an unrepairable hard-fail (no stage claimed the call).
    pub rules_fired: Vec<String>,
}

/// Max top-level keys listed in [`RepairTelemetry::received_keys`] before an
/// `…+N` overflow marker stands in for the rest (token economy §10).
pub const RECEIVED_KEYS_CAP: usize = 20;

impl RepairTelemetry {
    /// `issue_codes` joined for a compact single-field tracing value.
    pub fn issue_codes_csv(&self) -> String {
        self.issue_codes.join(",")
    }

    /// `received_keys` joined for a compact single-field tracing value.
    pub fn received_keys_csv(&self) -> String {
        self.received_keys.join(",")
    }

    /// `rules_fired` joined for a compact single-field tracing value.
    pub fn rules_fired_csv(&self) -> String {
        self.rules_fired.join(",")
    }
}

/// Validate `args` against `schema`; repair the disagreeing paths if it
/// fails; re-validate. See the module docs for the full contract.
///
/// `args` is mutated in place only when a repair fires. A clean input is
/// returned byte-for-byte unchanged with `Recovery::Clean`.
///
/// On a successful repair this emits a `tool_input_repaired` tracing
/// event; on an unrecoverable failure it emits `tool_input_invalid` and
/// returns `valid == false` with a model-readable `error`.
pub fn repair(args: &mut Value, schema: &Value, tool: &str) -> RepairOutcome {
    // A null/absent schema means "no declared shape" — nothing to
    // validate against, so the input is trivially clean.
    let validator = match compile(schema) {
        Some(v) => v,
        None => {
            return RepairOutcome {
                recovery: Recovery::Clean,
                valid: true,
                error: None,
                hints: Vec::new(),
                telemetry: None,
            };
        }
    };

    // Step 1: validate as-is. Clean inputs are dispatched untouched.
    if validator.is_valid(args) {
        return RepairOutcome {
            recovery: Recovery::Clean,
            valid: true,
            error: None,
            hints: Vec::new(),
            telemetry: None,
        };
    }

    // Fingerprint the malformed shape from the validator's errors over the
    // *original* (pre-repair) input — this is the stable signature shared by
    // a recovered repair and an unrecoverable hard-fail (the repair below
    // mutates `args`, so the snapshot is taken now). Never holds values.
    let shape_fingerprint = shape_fingerprint(&validator, args, tool);
    let issue_codes = issue_codes(&validator, args);
    let received_keys = received_keys(args);

    // We take the *first* repair that fires as the recorded recovery (one
    // row, one recovery — GOALS §14 keeps the single-Recovery shape) but
    // keep applying repairs everywhere so a call broken in two places can
    // still validate. `primary` carries `(stage, path, hint)`.
    let mut primary: Option<(&'static str, String, Option<String>)> = None;
    // One terse model-facing correction line per rule that fired, in catalog
    // order (implementation note). Surfaced to the model
    // only when `hintToolCallCorrections` is enabled.
    let mut hints: Vec<String> = Vec::new();
    // Every repair stage that fired this pass, in recorded order — the
    // `rules_fired` telemetry dimension (`repair-telemetry-
    // fingerprints.md`). A stage may fire at more than one key; we dedup so
    // the field stays a compact stage *set*.
    let mut fired: Vec<&'static str> = Vec::new();

    // Step 2.0 (root-level pre-pass): a bare string where the schema's root
    // type is `object` has no top-level key to walk, so the per-path stages
    // can never fire. Wrap it into the tool's declared primary field first;
    // the resulting object then flows through the alias + per-path stages
    // below (so a wrap can compose with a later coercion in the same pass).
    if let Some((stage, path, hint)) = wrap_root_string_as_object(args, schema) {
        hints.push(hint.clone());
        record_fired(&mut fired, stage);
        if primary.is_none() {
            primary = Some((stage, path, Some(hint)));
        }
    }

    // Step 2a: rename recognized alias fields to their canonical property
    // names. This is schema-property-driven, not failing-path-driven (a
    // missing-required field reports at the object root, not at the absent
    // key), so it runs ahead of the per-path shape stages — a renamed field
    // may itself then need a shape coercion, which step 2b handles.
    for (path, hint) in rename_aliased_fields(args, schema) {
        hints.push(hint.clone());
        record_fired(&mut fired, RENAME_ALIASED_FIELD);
        if primary.is_none() {
            primary = Some((RENAME_ALIASED_FIELD, path, Some(hint)));
        }
    }

    // Step 2b: walk the failing instance paths and repair at each.
    let failing_paths = failing_top_level_keys(&validator, args);
    for key in &failing_paths {
        if let Some(stage) = apply_one(args, schema, key) {
            if let Some(hint) = shape_stage_hint(stage, key) {
                hints.push(hint);
            }
            record_fired(&mut fired, stage);
            if primary.is_none() {
                primary = Some((stage, key.clone(), None));
            }
        }
    }

    // Step 3: re-validate.
    if validator.is_valid(args) {
        // `rules_fired` is every stage that claimed a repair this pass, in
        // recorded order. The primary stands first as the recorded recovery.
        let rules_fired: Vec<String> = fired.iter().map(|s| s.to_string()).collect();
        let telemetry = RepairTelemetry {
            shape_fingerprint,
            issue_codes,
            received_keys,
            rules_fired,
        };
        if let Some((stage, path, hint)) = primary {
            return RepairOutcome {
                recovery: Recovery::ShapeRepair { stage, path, hint },
                valid: true,
                error: None,
                hints,
                telemetry: Some(telemetry),
            };
        }
        // Re-validated clean but no catalog stage claimed credit (e.g.
        // the only fault was a stray null we stripped via a path the
        // catalog touched). Treat as clean — but the call *was* malformed,
        // so the telemetry rides along for the dispatch-site emission.
        return RepairOutcome {
            recovery: Recovery::Clean,
            valid: true,
            error: None,
            hints,
            telemetry: Some(telemetry),
        };
    }

    // Unrecoverable: build a model-readable message naming what the schema
    // expected vs what arrived, and hard-fail. `rules_fired` records any
    // stage that did mutate the call before validation still failed, so
    // telemetry distinguishes "no stage claimed it" from "a rewrite fired
    // but could not make the call valid".
    let msg = model_readable_error(&validator, args, schema, tool);
    let rules_fired: Vec<String> = fired.iter().map(|s| s.to_string()).collect();
    RepairOutcome {
        recovery: Recovery::Clean,
        valid: false,
        error: Some(msg),
        // No surfaced hints on an unrecoverable call — the model gets the
        // hard-fail error instead, which already says what to re-emit.
        hints: Vec::new(),
        telemetry: Some(RepairTelemetry {
            shape_fingerprint,
            issue_codes,
            received_keys,
            rules_fired,
        }),
    }
}

/// The terse, model-facing correction line for a per-path shape stage that
/// fired at top-level `key` (implementation note). One
/// line, no diff (token economy §10). The alias-rename and root-string-wrap
/// stages carry their own richer hints built where they fire, so they are
/// not handled here. Returns `None` for a stage with no useful hint.
fn shape_stage_hint(stage: &str, key: &str) -> Option<String> {
    let hint = match stage {
        "null_for_optional" => format!("Dropped null `{key}`; omit optional fields."),
        "parse_stringified_number" => {
            format!("Quoted number in `{key}`; send a number, not a string.")
        }
        "parse_stringified_array" => {
            format!("Quoted array in `{key}`; send an array, not a string.")
        }
        "wrap_bare_string" => format!("Wrapped `{key}` in an array; send an array."),
        "markdown_autolink_unwrap" => {
            format!("Unwrapped a markdown link in `{key}`; send a bare path.")
        }
        _ => return None,
    };
    Some(hint)
}

/// Compile a tool's `parameters()` schema into a reusable validator.
/// Returns `None` for `null`/empty schemas (no shape to enforce) or if
/// the schema itself is malformed (a build error in a hand-authored
/// schema is a programming bug, not a model fault — we degrade to "no
/// validation" rather than reject every call).
fn compile(schema: &Value) -> Option<jsonschema::Validator> {
    if schema.is_null() {
        return None;
    }
    match jsonschema::validator_for(schema) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::error!(target: "repair", error = %e, "tool schema failed to compile");
            None
        }
    }
}

/// Collect the distinct top-level object keys the validator disagreed at,
/// in deterministic order. A `Required` error has an empty instance path
/// but names the missing property; a per-field error (wrong type, etc.)
/// has an instance path whose first segment is the field. We localize to
/// the top-level key because every cockpit tool takes a flat object —
/// nested repair would need a path-walk the catalog doesn't yet have.
fn failing_top_level_keys(validator: &jsonschema::Validator, args: &Value) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    for err in validator.iter_errors(args) {
        if let Some(key) = first_path_segment(err.instance_path()) {
            if !keys.contains(&key) {
                keys.push(key);
            }
        } else if let jsonschema::error::ValidationErrorKind::Required { property } = err.kind()
            && let Some(name) = property.as_str()
            && !keys.contains(&name.to_string())
        {
            keys.push(name.to_string());
        }
    }
    keys
}

/// First property segment of an instance location, e.g. `/files` →
/// `"files"`. `None` for the root location or an index-rooted path.
fn first_path_segment(loc: &jsonschema::paths::Location) -> Option<String> {
    match loc.iter().next()? {
        jsonschema::paths::LocationSegment::Property(p) => Some(p.to_string()),
        jsonschema::paths::LocationSegment::Index(_) => None,
    }
}

/// Apply the one catalog repair whose signature matches at top-level
/// `key`, in catalog order. Returns the stage name that fired, or `None`
/// if no repair applied at this path.
fn apply_one(args: &mut Value, schema: &Value, key: &str) -> Option<&'static str> {
    let Value::Object(map) = args else {
        return None;
    };

    // 1. null_for_optional — strip a null value. (Validation only flags a
    //    null at a path that's typed non-null, so this is always the
    //    intended repair for a null at a disagreeing path.)
    if map.get(key).is_some_and(Value::is_null) {
        map.remove(key);
        return Some("null_for_optional");
    }

    let expects_array = schema_expects_array(schema, key);
    let is_path = schema_field_is_path(schema, key);

    // 2. parse_stringified_number — a JSON string that parses to a number,
    //    where the schema wants `integer`/`number`. A weak model emits a
    //    numeric field as a string (`"limit":"1"`); coerce it to the real
    //    number so the value-vs-type confusion never reaches the parser.
    if let Some(want) = schema_number_type(schema, key)
        && let Some(Value::String(s)) = map.get(key)
        && let Some(num) = parse_json_number(s.trim(), want)
    {
        map.insert(key.to_string(), num);
        return Some("parse_stringified_number");
    }

    // 3. parse_stringified_array — a JSON string that parses to an array,
    //    where the schema wants an array. MUST precede wrap_bare_string.
    if expects_array
        && let Some(Value::String(s)) = map.get(key)
        && let Ok(Value::Array(parsed)) = serde_json::from_str::<Value>(s)
    {
        map.insert(key.to_string(), Value::Array(parsed));
        return Some("parse_stringified_array");
    }

    // 4. wrap_bare_string — a bare string where the schema wants an array.
    if expects_array && let Some(v @ Value::String(_)) = map.get_mut(key) {
        let s = std::mem::replace(v, Value::Null);
        *v = Value::Array(vec![s]);
        return Some("wrap_bare_string");
    }

    // 5. markdown_autolink_unwrap — a degenerate auto-link in a path field.
    if is_path
        && let Some(Value::String(s)) = map.get(key)
        && let Some(unwrapped) = unwrap_degenerate_autolink(s)
    {
        map.insert(key.to_string(), Value::String(unwrapped));
        return Some("markdown_autolink_unwrap");
    }

    None
}

/// True when the schema declares property `key` as `type: "array"`.
fn schema_expects_array(schema: &Value, key: &str) -> bool {
    property_schema(schema, key)
        .and_then(|p| p.get("type"))
        .and_then(Value::as_str)
        == Some("array")
}

/// The numeric `type` a schema demands for property `key`, if any:
/// `Some(NumberType::Integer)` for `type: "integer"`,
/// `Some(NumberType::Number)` for `type: "number"`, else `None`.
///
/// A *union* type (`type: ["integer", "string"]`) deliberately returns
/// `None` — a string is already a valid member of the union, so the
/// validator never disagrees at that path and no coercion is wanted. The
/// stage only fires where the schema demands a numeric type *exclusively*.
fn schema_number_type(schema: &Value, key: &str) -> Option<NumberType> {
    match property_schema(schema, key)?.get("type")?.as_str()? {
        "integer" => Some(NumberType::Integer),
        "number" => Some(NumberType::Number),
        _ => None,
    }
}

/// The numeric type a schema field demands, narrowing what
/// [`parse_json_number`] will accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NumberType {
    /// `type: "integer"` — only an integral value (no fractional part).
    Integer,
    /// `type: "number"` — any JSON number.
    Number,
}

/// Parse a trimmed string into the JSON number the schema demands, or
/// `None` if it doesn't parse cleanly *as that type*. An `integer` field
/// rejects `"1.5"` (a non-integral value isn't the value-vs-type confusion
/// this stage repairs — it's a genuine type error left for the parser).
fn parse_json_number(s: &str, want: NumberType) -> Option<Value> {
    if s.is_empty() {
        return None;
    }
    match want {
        NumberType::Integer => {
            if let Ok(i) = s.parse::<i64>() {
                Some(Value::Number(i.into()))
            } else if let Ok(u) = s.parse::<u64>() {
                Some(Value::Number(u.into()))
            } else {
                None
            }
        }
        NumberType::Number => {
            // Try an exact integer first (preserves integrality), then a
            // float. `serde_json::Number::from_f64` rejects NaN/inf, so a
            // garbage `"inf"` correctly yields `None`.
            if let Ok(i) = s.parse::<i64>() {
                Some(Value::Number(i.into()))
            } else if let Ok(u) = s.parse::<u64>() {
                Some(Value::Number(u.into()))
            } else {
                let f = s.parse::<f64>().ok()?;
                serde_json::Number::from_f64(f).map(Value::Number)
            }
        }
    }
}

/// True when the schema marks property `key` with `x-cockpit-kind: path`.
fn schema_field_is_path(schema: &Value, key: &str) -> bool {
    property_schema(schema, key)
        .and_then(|p| p.get(PATH_KIND_KEY))
        .and_then(Value::as_str)
        == Some(PATH_KIND_VALUE)
}

fn schema_field_may_create_path(schema: &Value, key: &str) -> bool {
    property_schema(schema, key)
        .and_then(|p| p.get("x-cockpit-may-create"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// The sub-schema for top-level property `key`, if the schema is an object
/// schema declaring it.
fn property_schema<'a>(schema: &'a Value, key: &str) -> Option<&'a Value> {
    schema.get("properties").and_then(|p| p.get(key))
}

/// True when `v` is absent (`None`), JSON `null`, or an empty string. The
/// canonical-key "absent or empty" guard for [`rename_aliased_fields`].
fn is_absent_or_empty(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.is_empty(),
        Some(_) => false,
    }
}

/// True when `v` is present and a **non-empty** string. The alias-side guard:
/// an alias only counts toward the "exactly one alias present" test when it
/// carries a real value (an empty/null alias is ignored, never renamed).
fn is_nonempty_string(v: &Value) -> bool {
    matches!(v, Value::String(s) if !s.is_empty())
}

/// Rename recognized **alias** fields to their canonical property names,
/// schema-property-driven (implementation note).
///
/// For each property `P` in `schema` carrying [`ALIASES_KEY`], rename a
/// single recognized alias to `P` **only when it is unambiguous**:
///   - canonical key `P` is absent, `null`, or empty-string, AND
///   - **exactly one** of `P`'s aliases is present with a non-empty value.
///
/// The alias value is moved to `P` and the alias key deleted. An existing
/// non-empty canonical value is **never** overwritten; two-or-more present
/// aliases (or an already-set `P`) are left untouched for the hard-fail /
/// model retry (guessing is a silent-corruption hazard, §12).
///
/// Idempotent: a call already using canonical keys has no alias keys present,
/// so nothing fires and `args` is returned byte-identical. Returns one
/// `(canonical_path, hint)` per rename, in schema-property order; the caller
/// records the first as the single recovery.
fn rename_aliased_fields(args: &mut Value, schema: &Value) -> Vec<(String, String)> {
    let Value::Object(map) = args else {
        return Vec::new();
    };
    // Snapshot the schema's `(property, aliases)` pairs up front so we don't
    // borrow the schema while mutating `args`.
    let Some(Value::Object(props)) = schema.get("properties") else {
        return Vec::new();
    };
    let mut renames: Vec<(String, String)> = Vec::new();
    for (canonical, prop_schema) in props {
        let Some(aliases) = prop_schema
            .get(ALIASES_KEY)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        else {
            continue;
        };
        // Guard 1: never overwrite an existing non-empty canonical value.
        if !is_absent_or_empty(map.get(canonical.as_str())) {
            continue;
        }
        // Guard 2: exactly one alias present with a non-empty value.
        let present: Vec<&str> = aliases
            .iter()
            .copied()
            .filter(|a| map.get(*a).is_some_and(is_nonempty_string))
            .collect();
        let [alias] = present[..] else {
            continue;
        };
        // Move the alias value to the canonical key, delete the alias.
        if let Some(value) = map.remove(alias) {
            map.insert(canonical.clone(), value);
            renames.push((
                canonical.clone(),
                format!("Renamed `{alias}` to `{canonical}`; use `{canonical}` next time."),
            ));
        }
    }
    renames
}

/// Wrap a bare-string whole-input into the tool's declared **primary field**
/// when (and only when) the schema's root type is `object`
/// (implementation note).
///
/// Fires only when *all* of:
///   - `args` is a JSON `String` (the model sent a bare string as the entire
///     tool input), AND
///   - the schema's root `type` is `object`, AND
///   - the schema's root carries [`PRIMARY_FIELD_KEY`] naming a real property.
///
/// The string becomes `{<field>: <string>}`. If the primary field is itself
/// `type: "array"`, it is wrapped as a single-element array
/// (`"foo"` → `{<field>: ["foo"]}`) so the value satisfies the array schema.
/// A tool **without** the annotation is left untouched (no guess) and the bare
/// string hard-fails downstream exactly as before.
///
/// Idempotent: an already-wrapped object is not a `String`, so nothing fires
/// and `args` is returned byte-identical. Returns `(primary_field, hint)` on a
/// wrap, in which the caller records the single recovery; `None` otherwise.
fn wrap_root_string_as_object(
    args: &mut Value,
    schema: &Value,
) -> Option<(&'static str, String, String)> {
    // Only a bare string at the root is a candidate.
    let Value::String(s) = args else {
        return None;
    };
    // Only when the schema actually wants an object at the root.
    if schema.get("type").and_then(Value::as_str) != Some("object") {
        return None;
    }
    // Only when the tool declares its primary field (no guess otherwise).
    let field = schema.get(PRIMARY_FIELD_KEY)?.as_str()?.to_string();

    let value = std::mem::take(s);
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&value)
        && object_keys_declared_in_schema(&map, schema)
    {
        let path = map.keys().next().cloned().unwrap_or_else(|| field.clone());
        *args = Value::Object(map);
        return Some((
            PARSE_ROOT_STRING_AS_OBJECT,
            path,
            "Decoded a JSON string into an object; send the object directly next time.".to_string(),
        ));
    }
    let wrapped = if schema_expects_array(schema, &field) {
        Value::Array(vec![Value::String(value)])
    } else {
        Value::String(value)
    };
    let mut map = serde_json::Map::new();
    map.insert(field.clone(), wrapped);
    *args = Value::Object(map);

    let hint = format!(
        "Wrapped your bare string as `{{{field}: \"...\"}}`; call this tool with an object next time."
    );
    Some((WRAP_ROOT_STRING_AS_OBJECT, field, hint))
}

fn object_keys_declared_in_schema(map: &serde_json::Map<String, Value>, schema: &Value) -> bool {
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return map.is_empty();
    };
    map.keys().all(|key| properties.contains_key(key))
}

/// A single alias-invariant violation found by [`alias_invariants`]. Used by
/// the build/test-time conflict-avoidance invariant
/// (implementation note) — test-only, never invoked at
/// runtime (the runtime guard in [`rename_aliased_fields`] is the live
/// safeguard).
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasViolation {
    /// An alias equals a canonical property name in the same schema (it would
    /// shadow a real field and could rename a legitimate value).
    ShadowsCanonical { property: String, alias: String },
    /// An alias is claimed by two different properties in the same schema (a
    /// rename would be ambiguous).
    DoubleClaimed {
        alias: String,
        first: String,
        second: String,
    },
}

/// Check a single tool schema's alias declarations for the two unsafe
/// shapes: an alias that shadows a canonical property name, and an alias
/// double-claimed by two properties — both *within the same schema*.
/// Cross-tool collisions are harmless (resolution is per-tool-schema) and
/// are not checked here. Returns every violation found, in deterministic
/// (schema-property) order.
#[cfg(test)]
pub fn alias_invariants(schema: &Value) -> Vec<AliasViolation> {
    let Some(Value::Object(props)) = schema.get("properties") else {
        return Vec::new();
    };
    let mut violations = Vec::new();
    // alias -> the property that first claimed it (for double-claim detection).
    let mut claimed: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for (property, prop_schema) in props {
        let Some(aliases) = prop_schema.get(ALIASES_KEY).and_then(Value::as_array) else {
            continue;
        };
        for alias in aliases.iter().filter_map(Value::as_str) {
            if props.contains_key(alias) {
                violations.push(AliasViolation::ShadowsCanonical {
                    property: property.clone(),
                    alias: alias.to_string(),
                });
            }
            if let Some(first) = claimed.get(alias) {
                violations.push(AliasViolation::DoubleClaimed {
                    alias: alias.to_string(),
                    first: first.clone(),
                    second: property.clone(),
                });
            } else {
                claimed.insert(alias.to_string(), property.clone());
            }
        }
    }
    violations
}

/// Unwrap the degenerate markdown auto-link `[text](proto://text)` where
/// the link text equals the URL minus its protocol — the failure mode
/// where a model's chat-formatting prior leaks a path into a tool arg
/// (`[notes.md](http://notes.md)` → `notes.md`). A *real* link, where the
/// text differs from the URL (`[click](https://x.com)`), returns `None`
/// and passes through untouched. Returns `None` for anything that isn't
/// the degenerate shape.
fn unwrap_degenerate_autolink(s: &str) -> Option<String> {
    let s = s.trim();
    let rest = s.strip_prefix('[')?;
    let close = rest.find("](")?;
    let text = &rest[..close];
    let after = &rest[close + 2..];
    let url = after.strip_suffix(')')?;
    if text.is_empty() || url.is_empty() {
        return None;
    }
    // Strip the protocol (`scheme://`) from the URL, then compare.
    let url_no_proto = match url.split_once("://") {
        Some((_, tail)) => tail,
        None => url,
    };
    if url_no_proto == text {
        Some(text.to_string())
    } else {
        None
    }
}

/// Build the model-readable hard-fail message: name the first disagreeing
/// path, what the schema expected there, and what arrived. An `Error:`
/// prefix is correct here — this is a genuine invocation failure (distinct
/// from the soft, un-reddened relational-default Note the `read` tool
/// emits). The dispatcher wraps this in `invalid_input`.
fn model_readable_error(
    validator: &jsonschema::Validator,
    args: &Value,
    schema: &Value,
    tool: &str,
) -> String {
    let first = validator.iter_errors(args).next();
    match first {
        Some(err) => {
            // Missing-required-field case: name the field directly so a weak
            // model that sent empty / partial arguments knows exactly what to
            // supply, rather than a bare schema-validation string
            // (implementation note). The
            // rejection `reason` taxonomy is unchanged — only this model-facing
            // text is sharpened.
            if let jsonschema::error::ValidationErrorKind::Required { property } = err.kind()
                && let Some(field) = property.as_str()
            {
                let sent = if is_empty_args(args) {
                    "you sent empty arguments".to_string()
                } else {
                    format!("`{field}` is missing")
                };
                return format!(
                    "`{tool}` requires a `{field}` string; {sent}. Re-emit the call with `{field}` set."
                );
            }
            let loc = err.instance_path().as_str();
            let where_ = if loc.is_empty() {
                String::new()
            } else {
                format!(" at `{loc}`")
            };
            let expected = compact_expected_schema(schema, err.instance_path())
                .map(|schema| format!(" Expected schema{where_}: {schema}."))
                .unwrap_or_default();
            format!(
                "`{tool}` arguments failed schema validation{where_}: {err}.{expected} Re-emit the call with arguments matching the tool's schema."
            )
        }
        None => format!(
            "`{tool}` arguments failed schema validation. Re-emit the call with arguments matching the tool's schema."
        ),
    }
}

fn compact_expected_schema(schema: &Value, loc: &jsonschema::paths::Location) -> Option<String> {
    let subschema = schema_at_instance_path(schema, loc)?;
    let compact = compact_schema_value(subschema);
    let rendered = serde_json::to_string(&compact).ok()?;
    Some(truncate_chars(&rendered, EXPECTED_SCHEMA_MAX_CHARS))
}

fn schema_at_instance_path<'a>(
    schema: &'a Value,
    loc: &jsonschema::paths::Location,
) -> Option<&'a Value> {
    let mut cur = schema;
    for seg in loc.iter() {
        match seg {
            jsonschema::paths::LocationSegment::Property(p) => {
                cur = cur.get("properties")?.get(p.as_ref())?;
            }
            jsonschema::paths::LocationSegment::Index(_) => {
                cur = cur.get("items")?;
            }
        }
    }
    Some(cur)
}

fn compact_schema_value(schema: &Value) -> Value {
    let Some(obj) = schema.as_object() else {
        return schema.clone();
    };
    let mut out = serde_json::Map::new();
    for key in ["type", "enum", "const", "format"] {
        if let Some(value) = obj.get(key) {
            out.insert(key.to_string(), value.clone());
        }
    }
    if let Some(properties) = obj.get("properties").and_then(Value::as_object) {
        let mut keys = properties.keys().cloned().collect::<Vec<_>>();
        keys.sort();
        out.insert(
            "properties".to_string(),
            Value::Array(keys.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(required) = obj.get("required") {
        out.insert("required".to_string(), required.clone());
    }
    if let Some(items) = obj.get("items") {
        out.insert("items".to_string(), compact_schema_value(items));
    }
    if out.is_empty() {
        schema.clone()
    } else {
        Value::Object(out)
    }
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut out = value.chars().take(max_chars).collect::<String>();
    out.push_str("...");
    out
}

/// Whether the model sent effectively no arguments — `{}`, `null`, or a
/// non-object value. Used to phrase the missing-required-field rejection
/// ("you sent empty arguments") for the common empty-`{}` call.
fn is_empty_args(args: &Value) -> bool {
    match args {
        Value::Object(map) => map.is_empty(),
        Value::Null => true,
        _ => false,
    }
}

// ---- §12 repair telemetry (implementation note) -------

/// Record a fired repair stage in `fired`, deduped (a stage that fires at two
/// keys is one entry). Preserves first-seen order so `rules_fired` reads in
/// catalog order.
fn record_fired(fired: &mut Vec<&'static str>, stage: &'static str) {
    if !fired.contains(&stage) {
        fired.push(stage);
    }
}

/// A short **stable** hash of the malformed shape:
/// `tool :: sorted[ instance_path | error_code | expected | received ]` over
/// the validator's errors. Identical malformed shapes (differing only in
/// concrete values) collapse to one fingerprint regardless of values, so they
/// are countable; a different missing field or type yields a different one.
///
/// Stability matters across processes and releases, so this uses the repo's
/// established content-fingerprint primitive — `Sha256` + [`crate::intel::hex_lower`]
/// (the same pair `intel`, `guidance_diff`, and the MCP cache use) — truncated
/// to a short prefix. `std::hash::DefaultHasher` is deliberately avoided: its
/// output is not guaranteed stable across Rust versions, which would scatter
/// one shape across many fingerprints over time. No new dependency is added.
///
/// `expected`/`received` are **type-level** contributors (the error code and
/// the JSON type name at the path) — never the concrete value, so two calls
/// that differ only in their argument values share a fingerprint and no
/// secret can leak into it.
fn shape_fingerprint(validator: &jsonschema::Validator, args: &Value, tool: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut parts: Vec<String> = Vec::new();
    for err in validator.iter_errors(args) {
        let loc = err.instance_path().as_str().to_string();
        let code = error_code(err.kind());
        let expected = code; // the constraint code is the value-free "expected".
        let received = received_type(args, err.instance_path());
        parts.push(format!("{loc}|{code}|{expected}|{received}"));
    }
    // Sort so the fingerprint is order-independent across validator runs.
    parts.sort();
    parts.dedup();

    let mut hasher = Sha256::new();
    hasher.update(tool.as_bytes());
    hasher.update(b"::");
    hasher.update(parts.join("\n").as_bytes());
    let hex = crate::intel::hex_lower(&hasher.finalize());
    // 12 hex chars (48 bits) — ample to keep distinct shapes apart in the
    // failed-calls table while staying compact (token economy §10).
    hex[..12].to_string()
}

/// The deduped, sorted set of validator error-kind codes over `args` (e.g.
/// `required`, `type`). Value-free — only the constraint names.
fn issue_codes(validator: &jsonschema::Validator, args: &Value) -> Vec<String> {
    let mut codes: Vec<String> = validator
        .iter_errors(args)
        .map(|e| error_code(e.kind()).to_string())
        .collect();
    codes.sort();
    codes.dedup();
    codes
}

/// The stable, value-free code for a validator error kind. Derived from the
/// kind's variant name (the leading identifier of its `Debug` form, which
/// never includes the value), lowercased — so `Type { .. }` → `type`,
/// `Required { .. }` → `required`, `MaxLength { .. }` → `maxlength`. This
/// tracks the jsonschema error enum without an exhaustive match that would
/// silently rot when the upstream enum gains a variant.
fn error_code(kind: &jsonschema::error::ValidationErrorKind) -> &'static str {
    // The `Debug` of an enum variant begins with the variant identifier; take
    // the leading `[A-Za-z0-9]+` run and intern it to a small fixed set of
    // `&'static str`s. Unknown/future variants fall back to `other` rather
    // than leaking a freshly-allocated string into a `&'static` slot.
    let dbg = format!("{kind:?}");
    let name: String = dbg
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    intern_error_code(&name)
}

/// Intern a lowercased validator error-variant name to a `&'static str`. The
/// set mirrors `jsonschema::error::ValidationErrorKind`; an unrecognized name
/// (a future upstream variant) maps to `other` so the slot stays `&'static`.
fn intern_error_code(name: &str) -> &'static str {
    const CODES: &[&str] = &[
        "additionalitems",
        "additionalproperties",
        "anyof",
        "backtracklimitexceeded",
        "constant",
        "contains",
        "contentencoding",
        "contentmediatype",
        "custom",
        "enum",
        "exclusivemaximum",
        "exclusiveminimum",
        "falseschema",
        "format",
        "fromutf",
        "maximum",
        "maxitems",
        "maxlength",
        "maxproperties",
        "minimum",
        "minitems",
        "minlength",
        "minproperties",
        "multipleof",
        "not",
        "oneofmultiplevalid",
        "oneofnotvalid",
        "pattern",
        "propertynames",
        "referencing",
        "regexenginefailure",
        "required",
        "type",
        "unevaluateditems",
        "unevaluatedproperties",
        "uniqueitems",
    ];
    CODES
        .iter()
        .find(|c| **c == name)
        .copied()
        .unwrap_or("other")
}

/// The JSON **type name** of the value at `loc` in `args` — `string`,
/// `number`, `integer`, `boolean`, `array`, `object`, `null`, or `absent`
/// (no such path, e.g. a missing required field). A value-free contributor:
/// it never encodes the concrete value.
fn received_type(args: &Value, loc: &jsonschema::paths::Location) -> &'static str {
    let mut cur = args;
    for seg in loc.iter() {
        let next = match seg {
            jsonschema::paths::LocationSegment::Property(p) => cur.get(p.as_ref()),
            jsonschema::paths::LocationSegment::Index(i) => cur.get(i),
        };
        match next {
            Some(v) => cur = v,
            None => return "absent",
        }
    }
    json_type_name(cur)
}

/// The JSON type name of `v`, distinguishing integers from floats (the schema
/// distinction the repair catalog cares about). Value-free.
fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                "integer"
            } else {
                "number"
            }
        }
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// The input's top-level keys, sorted and truncated to [`RECEIVED_KEYS_CAP`]
/// with a trailing `…+N` overflow marker when there are more. Keys only —
/// values never enter the telemetry. A non-object input yields an empty list.
fn received_keys(args: &Value) -> Vec<String> {
    let Value::Object(map) = args else {
        return Vec::new();
    };
    let mut keys: Vec<String> = map.keys().cloned().collect();
    keys.sort();
    if keys.len() > RECEIVED_KEYS_CAP {
        let overflow = keys.len() - RECEIVED_KEYS_CAP;
        keys.truncate(RECEIVED_KEYS_CAP);
        keys.push(format!("…+{overflow}"));
    }
    keys
}

/// Outcome of [`normalize_paths`]. `recovery` is `ShapeRepair` when a
/// fabricated absolute prefix was salvaged (so the dispatcher folds it into
/// the §14 wire/user split), `Clean` when nothing was rewritten. `error`
/// carries a model-legible diagnostic for an absolute path that neither
/// exists nor salvages — the dispatcher treats it like a failed repair and
/// skips dispatch.
#[derive(Debug)]
pub struct PathNormalizeOutcome {
    pub recovery: Recovery,
    pub error: Option<String>,
    /// True when `error` is set *because* an `x-cockpit-kind: path` field
    /// pointed at a path that does not exist (the unsalvageable-absolute
    /// case) — as opposed to a genuine schema-repair failure. The
    /// dispatcher uses this to class the rejection as `path_not_found`
    /// (model path-hallucination) rather than `schema_invalid_unrepairable`,
    /// keeping repair-layer telemetry clean.
    pub not_found: bool,
}

/// Stage name for the fabricated-absolute-path rewrite. Kept in
/// [`SHAPE_REPAIR_STAGES`] so the audit reader round-trips it.
const ABSOLUTE_PREFIX_REWRITE: &str = "absolute_prefix_rewrite";

/// Normalize fabricated absolute paths in every `x-cockpit-kind: path`
/// field of a (already schema-valid) call, against the session `root`.
/// See the module docs for the full contract. Mutates `args` in place when
/// a salvage fires; returns the first salvage as the recorded recovery, or
/// the first unsalvageable absolute path as a hard error.
///
/// Runs **before** sandbox / native-tool cwd-confinement (the dispatcher
/// calls it ahead of `Tool::call`) and never bypasses confinement: a tail
/// that would resolve outside the canonical root is rejected, not rewritten.
pub fn normalize_paths(args: &mut Value, schema: &Value, root: &Path) -> PathNormalizeOutcome {
    let Value::Object(map) = args else {
        return clean_path_outcome();
    };
    // Collect path-typed keys up front so we don't borrow `map` mutably and
    // immutably at once while iterating the schema.
    let keys: Vec<String> = map
        .keys()
        .filter(|k| schema_field_is_path(schema, k))
        .cloned()
        .collect();

    let mut recovery: Option<(&'static str, String, Option<String>)> = None;
    let mut error: Option<String> = None;
    for key in keys {
        let Some(Value::String(s)) = map.get(&key) else {
            continue;
        };
        let mut current = s.clone();
        if let Some(unwrapped) = unwrap_degenerate_autolink(&current) {
            map.insert(key.clone(), Value::String(unwrapped.clone()));
            current = unwrapped;
            if recovery.is_none() {
                recovery = Some((
                    "markdown_autolink_unwrap",
                    key.clone(),
                    shape_stage_hint("markdown_autolink_unwrap", &key),
                ));
            }
        }
        let may_create = schema_field_may_create_path(schema, &key);
        match normalize_one_abs_path(&current, root, may_create) {
            AbsPathVerdict::Untouched => {}
            AbsPathVerdict::Rewrite(tail) => {
                map.insert(key.clone(), Value::String(tail));
                if recovery.is_none() {
                    recovery = Some((ABSOLUTE_PREFIX_REWRITE, key.clone(), None));
                }
            }
            AbsPathVerdict::Unsalvageable => {
                if error.is_none() {
                    error = Some(format!(
                        "`{current}` does not exist; no file matches it under the project root `{}`. Use a path relative to the working directory, or a correct absolute path.",
                        root.display()
                    ));
                }
            }
        }
    }

    // A salvage always wins over a hard error: we'd rather dispatch the
    // recovered call than refuse it, and the unsalvageable case only fires
    // when *no* field salvaged.
    if let Some((stage, path, hint)) = recovery {
        return PathNormalizeOutcome {
            recovery: Recovery::ShapeRepair { stage, path, hint },
            error: None,
            not_found: false,
        };
    }
    let not_found = error.is_some();
    PathNormalizeOutcome {
        recovery: Recovery::Clean,
        error,
        not_found,
    }
}

fn clean_path_outcome() -> PathNormalizeOutcome {
    PathNormalizeOutcome {
        recovery: Recovery::Clean,
        error: None,
        not_found: false,
    }
}

/// Per-field verdict from [`normalize_one_abs_path`].
enum AbsPathVerdict {
    /// Not absolute, or absolute and already valid — leave it alone.
    Untouched,
    /// Fabricated prefix salvaged: the root-relative tail that exists.
    Rewrite(String),
    /// Absolute, doesn't exist, and no salvageable tail — hard error.
    Unsalvageable,
}

/// Classify a single path value against `root`. Relative paths and existing
/// absolute paths are `Untouched`. A non-existent absolute path is salvaged
/// to its longest root-relative tail that exists *and* confines to `root`;
/// failing that it is `Unsalvageable`.
fn normalize_one_abs_path(value: &str, root: &Path, may_create: bool) -> AbsPathVerdict {
    let raw = Path::new(value);
    if !raw.is_absolute() {
        // Relative paths already anchor on cwd via `common::resolve`; the
        // fabricated-prefix failure mode is absolute-only.
        return AbsPathVerdict::Untouched;
    }
    // A legitimate absolute path (in-project absolute, or a permitted
    // out-of-project read like `/etc/...`) exists on disk → never rewrite.
    if raw.exists() {
        return AbsPathVerdict::Untouched;
    }
    if may_create && missing_abs_path_is_at_or_under_root(raw, root) {
        return AbsPathVerdict::Untouched;
    }
    if may_create {
        return AbsPathVerdict::Unsalvageable;
    }
    match salvage_tail(raw, root) {
        Some(tail) => AbsPathVerdict::Rewrite(tail),
        None => AbsPathVerdict::Unsalvageable,
    }
}

fn missing_abs_path_is_at_or_under_root(raw: &Path, root: &Path) -> bool {
    let Ok(canonical_root) = std::fs::canonicalize(root) else {
        return false;
    };
    let Some(mut ancestor) = lexical_normalize_path(raw).parent().map(Path::to_path_buf) else {
        return false;
    };
    loop {
        if ancestor.exists() {
            let Ok(canonical_ancestor) = std::fs::canonicalize(&ancestor) else {
                return false;
            };
            return crate::tools::sandbox::within_root(&canonical_root, &canonical_ancestor);
        }
        if !ancestor.pop() {
            return false;
        }
    }
}

fn lexical_normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Find the longest root-relative *tail* of `abs` such that `root/tail`
/// exists and stays at or under the canonicalized `root` (confinement).
/// Returns the tail as a `/`-joined relative string, or `None` if no tail
/// salvages. The longest match wins so a short coincidental suffix (e.g. a
/// bare `mod.rs` that exists somewhere) can't shadow the real file.
fn salvage_tail(abs: &Path, root: &Path) -> Option<String> {
    let canonical_root = std::fs::canonicalize(root).ok()?;
    // Collect the plain segments. A `..` anywhere makes the path
    // unsalvageable (we never climb out of the supplied prefix to fabricate
    // a different absolute path); the leading `/`, drive prefix, and `.` are
    // structural and dropped.
    let mut comps: Vec<&std::ffi::OsStr> = Vec::new();
    for c in abs.components() {
        match c {
            Component::Normal(p) => {
                comps.push(p);
                if comps.len() > SALVAGE_TAIL_MAX_COMPONENTS {
                    return None;
                }
            }
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            Component::ParentDir => return None,
        }
    }

    // Try the longest tail first: start the tail at component 0, then 1, …
    for start in 0..comps.len() {
        if comps.len() - start < 2 {
            continue;
        }
        let mut tail = PathBuf::new();
        for c in &comps[start..] {
            tail.push(c);
        }
        let candidate = canonical_root.join(&tail);
        if !candidate.exists() {
            continue;
        }
        // Confinement: the resolved candidate must stay at/under the root.
        // Reuse the sandbox check so normalization can never become an
        // escape hatch even if a future change loosens the segment filter.
        if crate::tools::sandbox::within_root(&canonical_root, &candidate) {
            return Some(tail.to_string_lossy().replace('\\', "/"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A schema with one required path field, one optional integer, and
    /// one array-of-string field — enough surface to exercise every
    /// catalog stage.
    fn schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "path":   { "type": "string", "x-cockpit-kind": "path" },
                "offset": { "type": "integer" },
                "files":  { "type": "array", "items": { "type": "string" } }
            },
            "required": ["path"]
        })
    }

    fn create_path_schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "x-cockpit-kind": "path",
                    "x-cockpit-may-create": true
                },
                "content": { "type": "string" }
            },
            "required": ["path", "content"]
        })
    }

    #[test]
    fn stringified_integer_coerced_for_integer_field() {
        let mut v = json!({ "path": "/x", "offset": "5" });
        let out = repair(&mut v, &schema(), "tool");
        assert!(out.valid);
        assert!(matches!(
            out.recovery,
            Recovery::ShapeRepair {
                stage: "parse_stringified_number",
                ..
            }
        ));
        assert_eq!(v["offset"], json!(5));
    }

    #[test]
    fn stringified_number_field_accepts_float() {
        let s = json!({
            "type": "object",
            "properties": { "ratio": { "type": "number" } }
        });
        let mut v = json!({ "ratio": "1.5" });
        let out = repair(&mut v, &s, "tool");
        assert!(out.valid);
        assert_eq!(v["ratio"], json!(1.5));
        // Stage precedes the array stages in the catalog.
        let num_idx = SHAPE_REPAIR_STAGES
            .iter()
            .position(|s| *s == "parse_stringified_number")
            .unwrap();
        let arr_idx = SHAPE_REPAIR_STAGES
            .iter()
            .position(|s| *s == "parse_stringified_array")
            .unwrap();
        assert!(num_idx < arr_idx);
    }

    #[test]
    fn non_integral_string_for_integer_field_is_not_coerced() {
        // `"1.5"` is not an integer; no coercion fires and the call stays
        // invalid (the integer field rejects a fractional value).
        let mut v = json!({ "path": "/x", "offset": "1.5" });
        let out = repair(&mut v, &schema(), "tool");
        assert!(!out.valid);
        assert_eq!(v["offset"], json!("1.5"), "left as-is for the hard fail");
    }

    #[test]
    fn garbage_string_for_integer_field_is_not_coerced() {
        let mut v = json!({ "path": "/x", "offset": "lots" });
        let out = repair(&mut v, &schema(), "tool");
        assert!(!out.valid);
        assert_eq!(v["offset"], json!("lots"));
    }

    #[test]
    fn union_type_string_member_is_left_alone() {
        // A `type: ["integer","string"]` union: a digit-string is already a
        // valid member, the validator never disagrees, and no coercion fires.
        let s = json!({
            "type": "object",
            "properties": { "interval": { "type": ["integer", "string"] } }
        });
        let mut v = json!({ "interval": "20000" });
        let before = v.clone();
        let out = repair(&mut v, &s, "tool");
        assert_eq!(out.recovery, Recovery::Clean);
        assert!(out.valid);
        assert_eq!(v, before, "union string member is untouched");
    }

    #[test]
    fn clean_passes_through_untouched() {
        let mut v = json!({ "path": "/x" });
        let before = v.clone();
        let out = repair(&mut v, &schema(), "read");
        assert_eq!(out.recovery, Recovery::Clean);
        assert!(out.valid);
        // Enforce: clean input is never mutated.
        assert_eq!(v, before);
    }

    #[test]
    fn path_normalize_allows_missing_absolute_path_for_create_schema_under_root() {
        let tmp = tempfile::tempdir().unwrap();
        let abs = tmp.path().join("new-file.md");
        let mut v = json!({ "path": abs.to_string_lossy(), "content": "body" });

        let out = normalize_paths(&mut v, &create_path_schema(), tmp.path());

        assert!(out.error.is_none(), "{out:?}");
        assert!(!out.not_found);
        assert_eq!(out.recovery, Recovery::Clean);
        assert_eq!(v["path"], json!(abs.to_string_lossy()));
    }

    #[test]
    fn path_normalize_allows_missing_absolute_create_path_with_missing_parents_under_root() {
        let tmp = tempfile::tempdir().unwrap();
        let abs = tmp.path().join("nested/deep/new-file.md");
        let mut v = json!({ "path": abs.to_string_lossy(), "content": "body" });

        let out = normalize_paths(&mut v, &create_path_schema(), tmp.path());

        assert!(out.error.is_none(), "{out:?}");
        assert!(!out.not_found);
        assert_eq!(out.recovery, Recovery::Clean);
        assert_eq!(v["path"], json!(abs.to_string_lossy()));
    }

    #[test]
    fn path_normalize_rejects_missing_absolute_path_without_create_schema() {
        let tmp = tempfile::tempdir().unwrap();
        let abs = tmp.path().join("missing.md");
        let mut v = json!({ "path": abs.to_string_lossy() });

        let out = normalize_paths(&mut v, &schema(), tmp.path());

        assert!(out.error.is_some(), "{out:?}");
        assert!(out.not_found);
    }

    #[test]
    fn null_for_optional_dropped() {
        let mut v = json!({ "path": "/x", "offset": null });
        let out = repair(&mut v, &schema(), "read");
        assert!(out.valid);
        assert!(matches!(
            out.recovery,
            Recovery::ShapeRepair {
                stage: "null_for_optional",
                ..
            }
        ));
        assert_eq!(v, json!({ "path": "/x" }));
    }

    #[test]
    fn bare_string_wrapped_for_array_field() {
        let mut v = json!({ "path": "/x", "files": "src/main.rs" });
        let out = repair(&mut v, &schema(), "tool");
        assert!(out.valid);
        assert!(matches!(
            out.recovery,
            Recovery::ShapeRepair {
                stage: "wrap_bare_string",
                ..
            }
        ));
        assert_eq!(v["files"], json!(["src/main.rs"]));
    }

    /// The load-bearing ordering: a stringified array must parse to a real
    /// array, NOT get wrapped into `['["a","b"]']`.
    #[test]
    fn stringified_array_parsed_not_wrapped() {
        let mut v = json!({ "path": "/x", "files": "[\"a\",\"b\"]" });
        let out = repair(&mut v, &schema(), "tool");
        assert!(out.valid);
        assert!(matches!(
            out.recovery,
            Recovery::ShapeRepair {
                stage: "parse_stringified_array",
                ..
            }
        ));
        assert_eq!(v["files"], json!(["a", "b"]));
        // Crucially NOT the double-wrapped form.
        assert_ne!(v["files"], json!(["[\"a\",\"b\"]"]));
    }

    #[test]
    fn parse_stringified_array_stage_precedes_wrap_in_catalog() {
        // Ordering invariant pinned at the data level too.
        let parse_idx = SHAPE_REPAIR_STAGES
            .iter()
            .position(|s| *s == "parse_stringified_array")
            .unwrap();
        let wrap_idx = SHAPE_REPAIR_STAGES
            .iter()
            .position(|s| *s == "wrap_bare_string")
            .unwrap();
        assert!(parse_idx < wrap_idx);
    }

    #[test]
    fn markdown_autolink_degenerate_unwrapped() {
        // A degenerate auto-link in a path field is a *valid* string for
        // the schema, so validation wouldn't flag it on its own. Drive the
        // unwrap helper directly — that's the unit under test — and assert
        // the catalog wires it for path fields.
        assert_eq!(
            unwrap_degenerate_autolink("[notes.md](http://notes.md)").as_deref(),
            Some("notes.md")
        );
        assert_eq!(
            unwrap_degenerate_autolink("[src/x.rs](https://src/x.rs)").as_deref(),
            Some("src/x.rs")
        );
    }

    #[test]
    fn markdown_autolink_real_link_preserved() {
        // text != url-minus-protocol → not the degenerate case → untouched.
        assert_eq!(unwrap_degenerate_autolink("[click](https://x.com)"), None);
        assert_eq!(unwrap_degenerate_autolink("plain/path.rs"), None);
        assert_eq!(unwrap_degenerate_autolink("[a](http://b)"), None);
    }

    #[test]
    fn autolink_repair_fires_only_on_path_fields() {
        // `path` is marked x-cockpit-kind=path; the degenerate link is a
        // valid string so the schema won't flag it — apply_one is what the
        // dispatcher would call if another path forced a re-walk. Assert
        // the stage on a forced apply.
        let mut v = json!({ "path": "[notes.md](http://notes.md)" });
        let stage = apply_one(&mut v, &schema(), "path");
        assert_eq!(stage, Some("markdown_autolink_unwrap"));
        assert_eq!(v["path"], json!("notes.md"));
    }

    #[test]
    fn validate_then_repair_localizes_and_revalidates() {
        // Two faults in one call: a null optional and a bare-string array.
        let mut v = json!({ "path": "/x", "offset": null, "files": "a.rs" });
        let out = repair(&mut v, &schema(), "tool");
        assert!(out.valid, "should re-validate clean after repairs");
        // Both faults fixed.
        assert!(v.get("offset").is_none());
        assert_eq!(v["files"], json!(["a.rs"]));
    }

    #[test]
    fn unrecoverable_input_hard_fails_with_model_readable_message() {
        // `path` is required and there's no catalog repair that conjures a
        // missing required string — this is a genuine hard fail. The
        // missing-required-field message names the tool AND the field
        // (implementation note).
        let mut v = json!({ "offset": 5 });
        let out = repair(&mut v, &schema(), "read");
        assert!(!out.valid);
        let msg = out.error.expect("expected a hard-fail message");
        assert!(msg.contains("`read`"), "got: {msg}");
        assert!(
            msg.contains("`path`"),
            "missing field must be named, got: {msg}"
        );
    }

    /// An empty-args call (`{}`) against a tool with a required field rejects
    /// with a message that NAMES the field and the empty-args case — e.g.
    /// `bash requires a `command` string; you sent empty arguments`
    /// (implementation note).
    #[test]
    fn empty_args_rejection_names_the_missing_field() {
        let bash_schema = json!({
            "type": "object",
            "properties": { "command": { "type": "string" } },
            "required": ["command"]
        });
        let mut v = json!({});
        let out = repair(&mut v, &bash_schema, "bash");
        assert!(!out.valid);
        let msg = out.error.expect("expected a hard-fail message");
        assert!(msg.contains("`command`"), "must name the field, got: {msg}");
        assert!(
            msg.contains("empty arguments"),
            "must flag the empty-args case, got: {msg}"
        );
    }

    #[test]
    fn schema_mismatch_error_echoes_compact_expected_schema() {
        let mode_schema = json!({
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["fast", "slow"]
                }
            },
            "required": ["mode"]
        });
        let mut v = json!({ "mode": 3 });
        let out = repair(&mut v, &mode_schema, "set_mode");

        assert!(!out.valid);
        let msg = out.error.expect("expected hard-fail message");
        assert!(msg.contains("Expected schema at `/mode`"), "{msg}");
        assert!(msg.contains(r#""type":"string""#), "{msg}");
        assert!(msg.contains(r#""enum":["fast","slow"]"#), "{msg}");
        assert!(
            msg.chars().count() <= EXPECTED_SCHEMA_MAX_CHARS + 240,
            "schema echo should be bounded, got {} chars: {msg}",
            msg.chars().count()
        );
    }

    #[test]
    fn missing_required_error_names_field_without_schema_dump() {
        let bash_schema = json!({
            "type": "object",
            "properties": { "command": { "type": "string" } },
            "required": ["command"]
        });
        let mut v = json!({});
        let out = repair(&mut v, &bash_schema, "bash");

        assert!(!out.valid);
        let msg = out.error.expect("expected hard-fail message");
        assert!(msg.contains("`command`"), "{msg}");
        assert!(!msg.contains("Expected schema"), "{msg}");
        assert!(!msg.contains(r#""type":"string""#), "{msg}");
    }

    #[test]
    fn wrong_type_required_field_is_unrecoverable() {
        // A required path sent as an integer: no catalog repair turns an
        // int into a string, so this hard-fails cleanly (no panic/loop).
        let mut v = json!({ "path": 7 });
        let out = repair(&mut v, &schema(), "read");
        assert!(!out.valid);
        assert!(out.error.is_some());
    }

    #[test]
    fn null_schema_treats_everything_as_clean() {
        let mut v = json!({ "anything": [1, 2, 3] });
        let before = v.clone();
        let out = repair(&mut v, &Value::Null, "noargs");
        assert_eq!(out.recovery, Recovery::Clean);
        assert!(out.valid);
        assert_eq!(v, before);
    }

    // ---- field-alias rename (implementation note) ---------

    /// A schema mirroring the real read/bash shape: a required `path` with a
    /// path-family alias set, a required `command` with the bash alias set,
    /// and an array field (to exercise rename-then-shape-coercion).
    fn alias_schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "path":    { "type": "string", "x-cockpit-kind": "path",
                             "x-cockpit-aliases": ["file_path", "filePath"] },
                "command": { "type": "string",
                             "x-cockpit-aliases": ["cmd", "shell"] },
                "files":   { "type": "array", "items": { "type": "string" },
                             "x-cockpit-aliases": ["paths"] }
            }
        })
    }

    /// Acceptance: `{"file_path":"x"}` renames to `{"path":"x"}` and records
    /// the `rename_aliased_field` stage with a terse hint.
    #[test]
    fn alias_file_path_renamed_to_path() {
        let s = json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "x-cockpit-kind": "path",
                          "x-cockpit-aliases": ["file_path", "filePath"] }
            },
            "required": ["path"]
        });
        let mut v = json!({ "file_path": "x" });
        let out = repair(&mut v, &s, "read");
        assert!(out.valid);
        assert_eq!(v, json!({ "path": "x" }));
        match out.recovery {
            Recovery::ShapeRepair { stage, path, hint } => {
                assert_eq!(stage, "rename_aliased_field");
                assert_eq!(path, "path");
                let hint = hint.expect("rename carries a hint");
                assert!(hint.contains("file_path"), "got: {hint}");
                assert!(hint.contains("path"), "got: {hint}");
            }
            other => panic!("expected ShapeRepair, got {other:?}"),
        }
    }

    /// Acceptance: `{"cmd":"ls"}` renames to `{"command":"ls"}` for bash.
    #[test]
    fn alias_cmd_renamed_to_command() {
        let s = json!({
            "type": "object",
            "properties": {
                "command": { "type": "string",
                             "x-cockpit-aliases": ["cmd", "shell"] }
            },
            "required": ["command"]
        });
        let mut v = json!({ "cmd": "ls" });
        let out = repair(&mut v, &s, "bash");
        assert!(out.valid);
        assert_eq!(v, json!({ "command": "ls" }));
        assert!(matches!(
            out.recovery,
            Recovery::ShapeRepair {
                stage: "rename_aliased_field",
                ..
            }
        ));
    }

    /// Acceptance: a call with BOTH `path` and `file_path` set is NOT
    /// renamed (never overwrite an existing non-empty canonical value).
    #[test]
    fn both_canonical_and_alias_present_is_not_renamed() {
        let s = json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "x-cockpit-kind": "path",
                          "x-cockpit-aliases": ["file_path"] }
            },
            "required": ["path"]
        });
        let mut v = json!({ "path": "keep", "file_path": "drop" });
        let before = v.clone();
        let renames = rename_aliased_fields(&mut v, &s);
        assert!(renames.is_empty(), "must not rename when canonical is set");
        assert_eq!(v, before, "args untouched");
    }

    /// Two-or-more aliases present → ambiguous → not renamed (left to the
    /// hard fail; guessing is a silent-corruption hazard).
    #[test]
    fn two_aliases_present_is_ambiguous_and_not_renamed() {
        let mut v = json!({ "file_path": "a", "filePath": "b" });
        let before = v.clone();
        let renames = rename_aliased_fields(&mut v, &alias_schema());
        assert!(renames.is_empty());
        assert_eq!(v, before);
    }

    /// An empty/null alias value does not count as "present" — it is ignored,
    /// never renamed onto the canonical key.
    #[test]
    fn empty_alias_value_is_not_renamed() {
        let mut v = json!({ "file_path": "" });
        let before = v.clone();
        let renames = rename_aliased_fields(&mut v, &alias_schema());
        assert!(renames.is_empty());
        assert_eq!(v, before);

        let mut vn = json!({ "file_path": null });
        let renames = rename_aliased_fields(&mut vn, &alias_schema());
        assert!(renames.is_empty());
    }

    /// Rename runs BEFORE the shape stages: an alias carrying a stringified
    /// array is first renamed to the canonical array field, then shape-coerced
    /// to a real array — both in one `repair` pass.
    #[test]
    fn rename_then_shape_coercion_in_one_pass() {
        // `files` is required so the alias-only call fails step-1 validation,
        // engaging the repair pass (rename → shape-coerce).
        let s = json!({
            "type": "object",
            "properties": {
                "files": { "type": "array", "items": { "type": "string" },
                           "x-cockpit-aliases": ["paths"] }
            },
            "required": ["files"]
        });
        let mut v = json!({ "paths": "[\"a\",\"b\"]" });
        let out = repair(&mut v, &s, "tool");
        assert!(out.valid);
        // Renamed `paths` -> `files`, then the stringified array parsed.
        assert_eq!(v, json!({ "files": ["a", "b"] }));
        // The rename is the recorded primary (it fired first).
        assert!(matches!(
            out.recovery,
            Recovery::ShapeRepair {
                stage: "rename_aliased_field",
                ..
            }
        ));
    }

    /// Idempotence: re-running `repair` on already-canonical args is `Clean`
    /// and byte-identical (no alias keys present → nothing fires).
    #[test]
    fn rename_is_idempotent_on_canonical_args() {
        let s = json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "x-cockpit-kind": "path",
                          "x-cockpit-aliases": ["file_path"] }
            },
            "required": ["path"]
        });
        let mut v = json!({ "path": "x" });
        let before = v.clone();
        let out = repair(&mut v, &s, "read");
        assert_eq!(out.recovery, Recovery::Clean);
        assert!(out.valid);
        assert_eq!(v, before);
    }

    /// `rename_aliased_field` is a registered shape stage and rounds through
    /// `db_fields` like the rest of the catalog.
    #[test]
    fn rename_aliased_field_is_a_known_shape_stage() {
        assert!(SHAPE_REPAIR_STAGES.contains(&"rename_aliased_field"));
        let r = Recovery::ShapeRepair {
            stage: "rename_aliased_field",
            path: "path".into(),
            hint: Some("Renamed `file_path` to `path`; use `path` next time.".into()),
        };
        assert_eq!(
            r.db_fields(),
            (Some("shape_repair"), Some("rename_aliased_field"))
        );
    }

    /// The conflict-avoidance invariant catches an alias that shadows a
    /// canonical property name in the same schema.
    #[test]
    fn invariant_catches_alias_shadowing_canonical() {
        let s = json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "x-cockpit-aliases": ["file"] },
                "file": { "type": "string" }
            }
        });
        let v = alias_invariants(&s);
        assert!(v.contains(&AliasViolation::ShadowsCanonical {
            property: "path".into(),
            alias: "file".into(),
        }));
    }

    /// The invariant catches an alias double-claimed by two properties in the
    /// same schema.
    #[test]
    fn invariant_catches_double_claimed_alias() {
        let s = json!({
            "type": "object",
            "properties": {
                "a": { "type": "string", "x-cockpit-aliases": ["x"] },
                "b": { "type": "string", "x-cockpit-aliases": ["x"] }
            }
        });
        let v = alias_invariants(&s);
        assert!(v.iter().any(|viol| matches!(
            viol,
            AliasViolation::DoubleClaimed { alias, .. } if alias == "x"
        )));
    }

    /// A clean alias schema (the real shape) has no violations.
    #[test]
    fn invariant_passes_on_well_formed_alias_schema() {
        assert!(alias_invariants(&alias_schema()).is_empty());
    }

    // ---- root-string wrap (implementation note) --------

    /// A schema mirroring `search`'s shape: an object root carrying
    /// `x-cockpit-primary-field: "pattern"` with a required string `pattern`.
    fn primary_field_schema() -> Value {
        json!({
            "type": "object",
            "x-cockpit-primary-field": "pattern",
            "properties": {
                "pattern": { "type": "string" },
                "path":    { "type": "string" }
            },
            "required": ["pattern"]
        })
    }

    /// Acceptance: `search` invoked with the bare string `"TODO"` dispatches
    /// with `{"pattern":"TODO"}` and records `wrap_root_string_as_object`.
    #[test]
    fn bare_string_wrapped_into_primary_field() {
        let mut v = json!("TODO");
        let out = repair(&mut v, &primary_field_schema(), "search");
        assert!(out.valid);
        assert_eq!(v, json!({ "pattern": "TODO" }));
        match out.recovery {
            Recovery::ShapeRepair { stage, path, hint } => {
                assert_eq!(stage, "wrap_root_string_as_object");
                assert_eq!(path, "pattern");
                let hint = hint.expect("wrap carries a hint");
                assert!(hint.contains("pattern"), "got: {hint}");
            }
            other => panic!("expected ShapeRepair, got {other:?}"),
        }
    }

    #[test]
    fn root_string_json_object_parses_instead_of_wrapping_as_literal() {
        let schema = json!({
            "type": "object",
            "x-cockpit-primary-field": "command",
            "properties": {
                "command": { "type": "string" }
            },
            "required": ["command"]
        });
        let mut v = json!(r#"{"command":"ls"}"#);
        let out = repair(&mut v, &schema, "bash");
        assert!(out.valid);
        assert_eq!(v, json!({ "command": "ls" }));
        match out.recovery {
            Recovery::ShapeRepair { stage, path, hint } => {
                assert_eq!(stage, "parse_root_string_as_object");
                assert_eq!(path, "command");
                assert_eq!(
                    hint.as_deref(),
                    Some(
                        "Decoded a JSON string into an object; send the object directly next time."
                    )
                );
            }
            other => panic!("expected parse-root ShapeRepair, got {other:?}"),
        }
    }

    /// A primary field that is array-typed wraps the bare string as a
    /// single-element array (`"foo"` → `{field: ["foo"]}`).
    #[test]
    fn bare_string_wrapped_as_single_element_array_for_array_field() {
        let s = json!({
            "type": "object",
            "x-cockpit-primary-field": "files",
            "properties": {
                "files": { "type": "array", "items": { "type": "string" } }
            },
            "required": ["files"]
        });
        let mut v = json!("src/main.rs");
        let out = repair(&mut v, &s, "tool");
        assert!(out.valid);
        assert_eq!(v, json!({ "files": ["src/main.rs"] }));
        assert!(matches!(
            out.recovery,
            Recovery::ShapeRepair {
                stage: "wrap_root_string_as_object",
                ..
            }
        ));
    }

    /// Acceptance: a tool with NO `x-cockpit-primary-field` and a bare-string
    /// input still hard-fails (no guess) — behavior is unchanged.
    #[test]
    fn bare_string_without_primary_field_hard_fails() {
        // `schema()` (the path/offset/files fixture) declares no primary field.
        let mut v = json!("TODO");
        let before = v.clone();
        let out = repair(&mut v, &schema(), "read");
        assert!(!out.valid);
        assert!(out.error.is_some());
        // The bare string is left exactly as the model emitted it.
        assert_eq!(v, before);
    }

    /// Acceptance: idempotence — re-running on the already-wrapped object is
    /// `Clean` and byte-identical (the root is no longer a string).
    #[test]
    fn root_wrap_is_idempotent_on_wrapped_object() {
        let mut v = json!({ "pattern": "TODO" });
        let before = v.clone();
        let out = repair(&mut v, &primary_field_schema(), "search");
        assert_eq!(out.recovery, Recovery::Clean);
        assert!(out.valid);
        assert_eq!(v, before);
    }

    /// The wrap only fires when the root type is `object`: a non-object root
    /// schema leaves the bare string untouched.
    #[test]
    fn root_wrap_skips_non_object_root_schema() {
        let s = json!({
            "type": "string",
            "x-cockpit-primary-field": "pattern"
        });
        let mut v = json!("TODO");
        let before = v.clone();
        let renamed = wrap_root_string_as_object(&mut v, &s);
        assert!(renamed.is_none());
        assert_eq!(v, before);
    }

    #[test]
    fn root_parse_object_records_shape_repair() {
        let mut v = json!(r#"{"pattern":"TODO"}"#);
        let renamed = wrap_root_string_as_object(&mut v, &primary_field_schema());

        assert_eq!(v, json!({ "pattern": "TODO" }));
        assert_eq!(
            renamed,
            Some((
                "parse_root_string_as_object",
                "pattern".to_string(),
                "Decoded a JSON string into an object; send the object directly next time."
                    .to_string()
            ))
        );
    }

    #[test]
    fn root_parse_object_adopts_when_all_keys_are_declared() {
        let mut v = json!(r#"{"pattern":"TODO","path":"src"}"#);
        let renamed = wrap_root_string_as_object(&mut v, &primary_field_schema());

        assert_eq!(v, json!({ "pattern": "TODO", "path": "src" }));
        assert!(matches!(
            renamed,
            Some(("parse_root_string_as_object", path, _)) if path == "path" || path == "pattern"
        ));
    }

    #[test]
    fn root_parse_object_rejects_undeclared_extra_key() {
        let schema = json!({
            "type": "object",
            "x-cockpit-primary-field": "command",
            "properties": {
                "command": { "type": "string" }
            },
            "required": ["command"]
        });
        let raw = r#"{"command":"ls","extra":true}"#;
        let mut v = json!(raw);
        let renamed = wrap_root_string_as_object(&mut v, &schema);

        assert_eq!(v, json!({ "command": raw }));
        assert!(matches!(
            renamed,
            Some(("wrap_root_string_as_object", path, _)) if path == "command"
        ));
    }

    #[test]
    fn root_parse_object_rejects_only_undeclared_keys() {
        let schema = json!({
            "type": "object",
            "x-cockpit-primary-field": "command",
            "properties": {
                "command": { "type": "string" }
            },
            "required": ["command"]
        });
        let raw = r#"{"cmd":"ls"}"#;
        let mut v = json!(raw);
        let renamed = wrap_root_string_as_object(&mut v, &schema);

        assert_eq!(v, json!({ "command": raw }));
        assert!(matches!(
            renamed,
            Some(("wrap_root_string_as_object", path, _)) if path == "command"
        ));
    }

    /// §14 split: the model emits a bare string (original), the wire/canonical
    /// args carry the wrapped object, and the recovery is a `ShapeRepair`
    /// (which the dispatcher keys the wire-vs-user split + the `⟲ repaired`
    /// chip off). The original bare string lives in the caller's pre-repair
    /// value; we keep a copy here.
    #[test]
    fn root_wrap_preserves_transcript_split() {
        let original = json!("TODO");
        let mut wire = original.clone();
        let out = repair(&mut wire, &primary_field_schema(), "search");
        assert!(out.valid);
        // Wire form is the wrapped object.
        assert_eq!(wire, json!({ "pattern": "TODO" }));
        // Original (model) form is still the bare string for the user view.
        assert_eq!(original, json!("TODO"));
        // Recovery is the wrap ShapeRepair carrying the hint.
        assert!(matches!(
            out.recovery,
            Recovery::ShapeRepair {
                stage: "wrap_root_string_as_object",
                ..
            }
        ));
    }

    #[test]
    fn root_parse_object_preserves_transcript_split() {
        let original = json!(r#"{"pattern":"TODO"}"#);
        let mut wire = original.clone();
        let out = repair(&mut wire, &primary_field_schema(), "search");

        assert!(out.valid);
        assert_eq!(wire, json!({ "pattern": "TODO" }));
        assert_eq!(original, json!(r#"{"pattern":"TODO"}"#));
        assert!(matches!(
            out.recovery,
            Recovery::ShapeRepair {
                stage: "parse_root_string_as_object",
                path,
                ..
            } if path == "pattern"
        ));
    }

    #[test]
    fn root_parse_empty_object_records_repair_then_hard_fails() {
        let mut v = json!(r#"{}"#);
        let out = repair(&mut v, &primary_field_schema(), "search");

        assert!(!out.valid);
        assert_eq!(v, json!({}));
        assert!(matches!(out.recovery, Recovery::Clean));
        let telemetry = out.telemetry.expect("hard fail still carries telemetry");
        assert_eq!(
            telemetry.rules_fired,
            vec!["parse_root_string_as_object".to_string()]
        );
    }

    #[test]
    fn root_parse_object_idempotent() {
        let mut v = json!({ "pattern": "TODO" });
        let before = v.clone();
        let renamed = wrap_root_string_as_object(&mut v, &primary_field_schema());
        assert!(renamed.is_none());
        assert_eq!(v, before);
    }

    /// `wrap_root_string_as_object` is a registered shape stage and rounds
    /// through `db_fields` like the rest of the catalog, and is ordered FIRST
    /// (it is the root-level pre-pass that runs before the per-path stages).
    #[test]
    fn wrap_root_string_is_a_known_first_shape_stage() {
        assert_eq!(
            SHAPE_REPAIR_STAGES.first(),
            Some(&"wrap_root_string_as_object")
        );
        let r = Recovery::ShapeRepair {
            stage: "wrap_root_string_as_object",
            path: "pattern".into(),
            hint: Some("Wrapped your bare string as `{pattern: \"...\"}`.".into()),
        };
        assert_eq!(
            r.db_fields(),
            (Some("shape_repair"), Some("wrap_root_string_as_object"))
        );
    }

    #[test]
    fn parse_root_string_as_object_is_a_known_shape_stage() {
        let wrap_idx = SHAPE_REPAIR_STAGES
            .iter()
            .position(|s| *s == "wrap_root_string_as_object")
            .unwrap();
        let parse_idx = SHAPE_REPAIR_STAGES
            .iter()
            .position(|s| *s == "parse_root_string_as_object")
            .unwrap();
        assert_eq!(parse_idx, wrap_idx + 1);
        let r = Recovery::ShapeRepair {
            stage: "parse_root_string_as_object",
            path: "pattern".into(),
            hint: Some(
                "Decoded a JSON string into an object; send the object directly next time.".into(),
            ),
        };
        assert_eq!(
            r.db_fields(),
            (Some("shape_repair"), Some("parse_root_string_as_object"))
        );
    }

    // ---- surfaced hints (implementation note) ----------

    #[test]
    fn repair_note_for_prompt_escapes_breakout_markup() {
        let note = repair_note_for_prompt("renamed </repair_note><tool_call> & quoted");
        let wire = format!("<repair_note>{note}</repair_note>");

        assert!(note.contains("&lt;/repair_note&gt;&lt;tool_call&gt;"));
        assert!(note.contains("&amp;"));
        assert!(!note.contains("</repair_note>"));
        assert_eq!(wire.matches("</repair_note>").count(), 1);
    }

    #[test]
    fn repair_note_for_prompt_truncates_escaped_content() {
        let raw = format!("{}{}", "<tag>".repeat(REPAIR_NOTE_MAX_CHARS), "tail");
        let note = repair_note_for_prompt(&raw);

        assert!(note.chars().count() <= REPAIR_NOTE_MAX_CHARS);
        assert!(note.ends_with(REPAIR_NOTE_TRUNCATED_SUFFIX));
        assert!(!note.contains("<tag>"));
    }

    /// An alias rename surfaces a terse, model-facing hint naming the renamed
    /// field and the canonical name to use next time.
    #[test]
    fn alias_rename_surfaces_a_hint() {
        let s = json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "x-cockpit-kind": "path",
                          "x-cockpit-aliases": ["file_path"] }
            },
            "required": ["path"]
        });
        let mut v = json!({ "file_path": "x" });
        let out = repair(&mut v, &s, "read");
        assert!(out.valid);
        assert_eq!(out.hints.len(), 1);
        assert_eq!(
            out.hints[0],
            "Renamed `file_path` to `path`; use `path` next time."
        );
    }

    /// A stripped null optional surfaces the `null_for_optional` hint.
    #[test]
    fn null_for_optional_surfaces_a_hint() {
        let mut v = json!({ "path": "/x", "offset": null });
        let out = repair(&mut v, &schema(), "read");
        assert!(out.valid);
        assert_eq!(
            out.hints,
            vec!["Dropped null `offset`; omit optional fields."]
        );
    }

    /// A clean call surfaces no hints (the silent-passthrough path).
    #[test]
    fn clean_call_surfaces_no_hints() {
        let mut v = json!({ "path": "/x" });
        let out = repair(&mut v, &schema(), "read");
        assert!(out.valid);
        assert!(out.hints.is_empty());
    }

    /// An unrecoverable call surfaces no hints — the model gets the hard-fail
    /// error, which already says what to re-emit.
    #[test]
    fn unrecoverable_call_surfaces_no_hints() {
        let mut v = json!({ "path": 7 });
        let out = repair(&mut v, &schema(), "read");
        assert!(!out.valid);
        assert!(out.hints.is_empty());
    }

    /// Two faults in one call surface one hint per fired rule, in catalog order.
    #[test]
    fn multiple_repairs_surface_one_hint_each() {
        let mut v = json!({ "path": "/x", "offset": null, "files": "a.rs" });
        let out = repair(&mut v, &schema(), "tool");
        assert!(out.valid);
        assert_eq!(out.hints.len(), 2);
        assert!(out.hints.iter().any(|h| h.contains("offset")));
        assert!(out.hints.iter().any(|h| h.contains("files")));
    }

    // ---- fabricated-absolute-path normalization --------------------------

    /// Build a project tree with `src/tui/settings/mod.rs` under `root`.
    fn project_root() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("src/tui/settings");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("mod.rs"), "// file").unwrap();
        tmp
    }

    #[test]
    fn fabricated_prefix_absolute_path_is_rewritten_to_relative_tail() {
        // The observed failure: a fabricated `/home/user/repo` prefix whose
        // root-relative tail exists under the real root.
        let tmp = project_root();
        let mut v = json!({ "path": "/home/user/repo/src/tui/settings/mod.rs" });
        let out = normalize_paths(&mut v, &schema(), tmp.path());
        assert!(out.error.is_none(), "should salvage, not error");
        assert!(matches!(
            out.recovery,
            Recovery::ShapeRepair {
                stage: "absolute_prefix_rewrite",
                ..
            }
        ));
        // The model-facing canonical form is the root-relative tail.
        assert_eq!(v["path"], json!("src/tui/settings/mod.rs"));
    }

    #[test]
    fn fabricated_prefix_emits_shape_repair_recovery_for_transcript_split() {
        // The recovery is a ShapeRepair (the §14 wire/user split keys off
        // exactly this), naming the rewritten field.
        let tmp = project_root();
        let mut v = json!({ "path": "/nope/whatever/src/tui/settings/mod.rs" });
        let out = normalize_paths(&mut v, &schema(), tmp.path());
        match out.recovery {
            Recovery::ShapeRepair { stage, path, .. } => {
                assert_eq!(stage, "absolute_prefix_rewrite");
                assert_eq!(path, "path");
            }
            other => panic!("expected ShapeRepair, got {other:?}"),
        }
    }

    #[test]
    fn longest_matching_tail_wins_over_short_coincidental_suffix() {
        // A bare `mod.rs` exists at the root too; the longest tail
        // (`src/tui/settings/mod.rs`) must win, not the coincidental short
        // suffix, so we rewrite to the file the model actually meant.
        let tmp = project_root();
        std::fs::write(tmp.path().join("mod.rs"), "// decoy").unwrap();
        let mut v = json!({ "path": "/fake/src/tui/settings/mod.rs" });
        let out = normalize_paths(&mut v, &schema(), tmp.path());
        assert_eq!(v["path"], json!("src/tui/settings/mod.rs"));
        assert!(matches!(out.recovery, Recovery::ShapeRepair { .. }));
    }

    #[test]
    fn read_salvage_rejects_single_component_tail() {
        let tmp = project_root();
        std::fs::write(tmp.path().join("Cargo.toml"), "[package]\n").unwrap();

        let mut v = json!({ "path": "/other/project/Cargo.toml" });
        let out = normalize_paths(&mut v, &schema(), tmp.path());

        assert_eq!(out.recovery, Recovery::Clean);
        assert!(
            out.error.is_some(),
            "single-component tail must not salvage"
        );
        assert_eq!(v["path"], json!("/other/project/Cargo.toml"));
        assert!(out.not_found);
    }

    #[test]
    fn read_salvage_allows_two_or_more_component_tail() {
        let tmp = project_root();

        let mut v = json!({ "path": "/other/project/src/tui/settings/mod.rs" });
        let out = normalize_paths(&mut v, &schema(), tmp.path());

        assert!(
            out.error.is_none(),
            "two-component-or-deeper tail should salvage"
        );
        assert!(matches!(out.recovery, Recovery::ShapeRepair { .. }));
        assert_eq!(v["path"], json!("src/tui/settings/mod.rs"));
    }

    #[test]
    fn read_salvage_rejects_excessive_component_count() {
        let tmp = project_root();
        let mut parts = vec!["".to_string()];
        parts.extend((0..=SALVAGE_TAIL_MAX_COMPONENTS).map(|i| format!("fake{i}")));
        parts.extend([
            "src".to_string(),
            "tui".to_string(),
            "settings".to_string(),
            "mod.rs".to_string(),
        ]);
        let fabricated = parts.join("/");
        let mut v = json!({ "path": fabricated });

        let out = normalize_paths(&mut v, &schema(), tmp.path());

        assert_eq!(out.recovery, Recovery::Clean);
        assert!(out.error.is_some(), "oversized path should fail bounded");
        assert!(out.not_found);
        assert_eq!(v["path"], json!(fabricated));
    }

    #[test]
    fn may_create_path_never_salvages_to_existing_file() {
        let tmp = project_root();

        let mut v = json!({
            "path": "/other/project/src/tui/settings/mod.rs",
            "content": "replacement"
        });
        let out = normalize_paths(&mut v, &create_path_schema(), tmp.path());

        assert_eq!(out.recovery, Recovery::Clean);
        assert!(
            out.error.is_some(),
            "write path must fail instead of salvage"
        );
        assert_eq!(v["path"], json!("/other/project/src/tui/settings/mod.rs"));
        assert!(out.not_found);
    }

    #[test]
    fn may_create_path_under_root_still_passes_without_salvage() {
        let tmp = project_root();
        let missing = tmp.path().join("src/new-file.rs");
        let mut v = json!({
            "path": missing.to_string_lossy().to_string(),
            "content": "new"
        });
        let before = v.clone();

        let out = normalize_paths(&mut v, &create_path_schema(), tmp.path());

        assert_eq!(out.recovery, Recovery::Clean);
        assert!(out.error.is_none());
        assert_eq!(v, before);
    }

    #[test]
    fn legitimate_out_of_project_absolute_path_is_untouched() {
        // An absolute path that *exists* outside the project (a permitted
        // read) passes through unchanged with no recovery and no error.
        let tmp = project_root();
        // `/` reliably exists on every platform CI runs on; on Windows the
        // canonical root the build runs under also exists — use a path we
        // know is present: the temp dir's own parent.
        let outside = tmp.path().parent().unwrap().to_path_buf();
        let outside_str = outside.to_string_lossy().to_string();
        let mut v = json!({ "path": outside_str });
        let before = v.clone();
        let out = normalize_paths(&mut v, &schema(), tmp.path());
        assert_eq!(out.recovery, Recovery::Clean);
        assert!(out.error.is_none());
        assert_eq!(v, before, "existing absolute path must not be rewritten");
    }

    #[test]
    fn unsalvageable_absolute_path_yields_clear_error() {
        // Absolute, doesn't exist, no root-relative tail matches → a
        // model-legible error (not a raw OS message), and no rewrite.
        let tmp = project_root();
        let mut v = json!({ "path": "/home/user/repo/does/not/exist.rs" });
        let out = normalize_paths(&mut v, &schema(), tmp.path());
        assert_eq!(out.recovery, Recovery::Clean);
        let msg = out.error.expect("expected a model-legible error");
        assert!(msg.contains("does not exist"), "got: {msg}");
        assert!(msg.contains("project root"), "got: {msg}");
        // The arg is left as the model emitted it (the dispatcher won't run).
        assert_eq!(v["path"], json!("/home/user/repo/does/not/exist.rs"));
        // The error is a path-not-found (model path-hallucination), flagged so
        // the dispatcher can class it as `path_not_found`, not a schema-repair
        // failure.
        assert!(out.not_found, "unsalvageable path must set `not_found`");
    }

    #[test]
    fn clean_outcomes_never_set_not_found() {
        // A relative path (left to cwd resolution) and an existing absolute
        // path both produce a clean outcome with `not_found` false — the flag
        // is exclusive to the nonexistent-path case.
        let tmp = project_root();
        let mut rel = json!({ "path": "src/tui/settings/mod.rs" });
        let out = normalize_paths(&mut rel, &schema(), tmp.path());
        assert!(!out.not_found);
        assert!(out.error.is_none());
    }

    #[test]
    fn rewrite_that_would_escape_root_is_rejected() {
        // A `..`-bearing absolute path could resolve outside the root if a
        // tail were joined naively. We never climb: such a path is treated
        // as unsalvageable, never rewritten to an out-of-root location.
        let tmp = project_root();
        // Put a real file *outside* the root, then craft a fabricated
        // absolute path whose only "matching" tail would require climbing
        // out via `..`.
        let outside = tmp.path().parent().unwrap().join("secret.rs");
        std::fs::write(&outside, "// secret").unwrap();
        let mut v = json!({ "path": "/fake/../secret.rs" });
        let out = normalize_paths(&mut v, &schema(), tmp.path());
        // No rewrite to the outside file; confinement preserved.
        assert!(
            !matches!(out.recovery, Recovery::ShapeRepair { .. }),
            "must not rewrite across `..` to an out-of-root file"
        );
        assert_ne!(v["path"], json!("secret.rs"));
    }

    #[test]
    fn relative_path_is_left_to_cwd_resolution() {
        // The fabricated-prefix mode is absolute-only; a relative path is
        // never touched here (cwd resolution handles it downstream).
        let tmp = project_root();
        let mut v = json!({ "path": "src/tui/settings/mod.rs" });
        let before = v.clone();
        let out = normalize_paths(&mut v, &schema(), tmp.path());
        assert_eq!(out.recovery, Recovery::Clean);
        assert!(out.error.is_none());
        assert_eq!(v, before);
    }

    #[test]
    fn normalize_paths_unwraps_autolink_single_path_field() {
        let tmp = project_root();
        let mut v = json!({ "path": "[notes.md](http://notes.md)" });

        let out = normalize_paths(&mut v, &schema(), tmp.path());

        assert!(out.error.is_none(), "{out:?}");
        assert_eq!(v["path"], json!("notes.md"));
        assert!(matches!(
            out.recovery,
            Recovery::ShapeRepair {
                stage: "markdown_autolink_unwrap",
                path,
                ..
            } if path == "path"
        ));
    }

    #[test]
    fn repair_then_normalize_unwraps_single_arg_autolink() {
        let tmp = project_root();
        let mut v = json!({ "path": "[notes.md](http://notes.md)" });

        let repaired = repair(&mut v, &schema(), "read");
        assert!(repaired.valid);
        assert_eq!(repaired.recovery, Recovery::Clean);

        let normalized = normalize_paths(&mut v, &schema(), tmp.path());
        assert!(normalized.error.is_none(), "{normalized:?}");
        assert_eq!(v["path"], json!("notes.md"));
        assert!(matches!(
            normalized.recovery,
            Recovery::ShapeRepair {
                stage: "markdown_autolink_unwrap",
                ..
            }
        ));
    }

    #[test]
    fn autolink_unwrap_then_absolute_salvage_composes() {
        let tmp = project_root();
        let mut v = json!({
            "path": "[/fake/src/tui/settings/mod.rs](http:///fake/src/tui/settings/mod.rs)"
        });

        let out = normalize_paths(&mut v, &schema(), tmp.path());

        assert!(out.error.is_none(), "{out:?}");
        assert_eq!(v["path"], json!("src/tui/settings/mod.rs"));
        assert!(matches!(
            out.recovery,
            Recovery::ShapeRepair {
                stage: "markdown_autolink_unwrap",
                path,
                ..
            } if path == "path"
        ));
    }

    #[test]
    fn autolink_unwrap_is_idempotent() {
        let tmp = project_root();
        let mut v = json!({ "path": "[notes.md](http://notes.md)" });
        let out = normalize_paths(&mut v, &schema(), tmp.path());
        assert!(matches!(
            out.recovery,
            Recovery::ShapeRepair {
                stage: "markdown_autolink_unwrap",
                ..
            }
        ));

        let repaired = repair(&mut v, &schema(), "read");
        let normalized = normalize_paths(&mut v, &schema(), tmp.path());

        assert!(repaired.valid);
        assert_eq!(repaired.recovery, Recovery::Clean);
        assert_eq!(normalized.recovery, Recovery::Clean);
        assert_eq!(v["path"], json!("notes.md"));
    }

    #[test]
    fn real_markdown_link_not_unwrapped_in_normalize() {
        let tmp = project_root();
        let mut v = json!({ "path": "[click](https://x.com)" });
        let before = v.clone();

        let out = normalize_paths(&mut v, &schema(), tmp.path());

        assert_eq!(out.recovery, Recovery::Clean);
        assert!(out.error.is_none());
        assert_eq!(v, before);
    }

    #[test]
    fn autolink_unwrap_surfaces_hint() {
        let tmp = project_root();
        let mut v = json!({ "path": "[notes.md](http://notes.md)" });

        let out = normalize_paths(&mut v, &schema(), tmp.path());

        match out.recovery {
            Recovery::ShapeRepair { hint, .. } => {
                assert_eq!(
                    hint.as_deref(),
                    Some("Unwrapped a markdown link in `path`; send a bare path.")
                );
            }
            other => panic!("expected ShapeRepair, got {other:?}"),
        }
    }

    #[test]
    fn non_path_fields_are_never_normalized() {
        // Only `x-cockpit-kind: path` fields are considered. A non-path
        // string that happens to look like an absolute path is untouched.
        let tmp = project_root();
        let s = json!({
            "type": "object",
            "properties": {
                "note": { "type": "string" }
            }
        });
        let mut v = json!({ "note": "/home/user/repo/src/tui/settings/mod.rs" });
        let before = v.clone();
        let out = normalize_paths(&mut v, &s, tmp.path());
        assert_eq!(out.recovery, Recovery::Clean);
        assert!(out.error.is_none());
        assert_eq!(v, before);
    }

    #[test]
    fn absolute_prefix_rewrite_is_a_known_shape_stage() {
        // The stage round-trips through the audit reader (db/tool_calls.rs)
        // because it's registered in the catalog list.
        assert!(SHAPE_REPAIR_STAGES.contains(&"absolute_prefix_rewrite"));
    }

    // ---- tool-name repair (implementation note) ------------

    /// The registered tool set used by the name-repair tests — built-in
    /// lowercase names plus a structural one, mirroring a real agent.
    const KNOWN: &[&str] = &["read", "edit", "bash", "task", "handoff"];

    /// A clean exact-match name is a zero-cost passthrough: byte-identical,
    /// no recovery, idempotent.
    #[test]
    fn clean_name_is_zero_cost_passthrough() {
        let out = repair_tool_name("read", KNOWN);
        assert_eq!(out.name, "read");
        assert_eq!(out.recovery, Recovery::Clean);
        // Idempotent: re-running on the resolved name is still a no-op.
        let again = repair_tool_name(&out.name, KNOWN);
        assert_eq!(again, out);
    }

    /// Each normalization transform, plus the acceptance examples, all rebind
    /// to `read` with a `NameRepair { stage: "rebind" }` carrying the original.
    #[test]
    fn each_normalization_transform_rebinds_to_read() {
        for emitted in [
            "read\n",                   // trailing newline
            "read ",                    // trailing space
            " read",                    // leading space
            "<read>",                   // angle brackets
            "\"read\"",                 // double quotes
            "'read'",                   // single quotes
            "functions.read",           // namespace prefix
            "namespace.functions.read", // multi-segment namespace
            "< \"read\" >",             // nested wrappers + whitespace
        ] {
            let out = repair_tool_name(emitted, KNOWN);
            assert_eq!(
                out.name, "read",
                "emitted {emitted:?} should rebind to read"
            );
            assert_eq!(
                out.recovery,
                Recovery::NameRepair {
                    stage: "rebind",
                    original: emitted.to_string(),
                },
                "emitted {emitted:?}"
            );
        }
    }

    /// Case-folding: `Read` → `read` (built-ins are uniquely lowercase, so the
    /// fold is unambiguous, not a guess).
    #[test]
    fn case_folding_rebinds() {
        let out = repair_tool_name("Read", KNOWN);
        assert_eq!(out.name, "read");
        assert!(matches!(
            out.recovery,
            Recovery::NameRepair {
                stage: "rebind",
                ..
            }
        ));
    }

    /// A model that hallucinates the former `jobs` tool name is recovered to
    /// the renamed `schedule` tool (implementation note) — a
    /// defensive rebind, not a durable alias. Case-insensitive.
    #[test]
    fn renamed_jobs_rebinds_to_schedule() {
        const WITH_SCHEDULE: &[&str] = &["read", "bash", "schedule"];
        for emitted in ["jobs", "Jobs", "JOBS"] {
            let out = repair_tool_name(emitted, WITH_SCHEDULE);
            assert_eq!(out.name, "schedule", "emitted {emitted:?}");
            assert_eq!(
                out.recovery,
                Recovery::NameRepair {
                    stage: "rebind",
                    original: emitted.to_string(),
                },
                "emitted {emitted:?}"
            );
        }
        // No rebind when `schedule` isn't a registered tool for this agent —
        // the alias only fires toward a real current name.
        let out = repair_tool_name("jobs", KNOWN);
        assert_ne!(out.name, "schedule");
    }

    /// The hard safety rule: NO fuzzy/edit-distance matching. `reed` has no
    /// exact normalized match, so it must NOT become `read` — it stays
    /// unknown (and, being already charset-clean, takes no recovery).
    #[test]
    fn no_fuzzy_match_reed_stays_unknown() {
        let out = repair_tool_name("reed", KNOWN);
        assert_eq!(out.name, "reed");
        assert_eq!(out.recovery, Recovery::Clean);
        assert!(!KNOWN.contains(&out.name.as_str()));
    }

    /// A genuinely-unknown name with out-of-charset bytes is sanitized to
    /// `^[a-zA-Z0-9_-]{1,64}$` and recorded as a `sanitize` name-repair; it
    /// still fails as unknown-tool downstream (the name isn't in `KNOWN`).
    #[test]
    fn unknown_name_is_charset_sanitized() {
        let out = repair_tool_name("flibber!!", KNOWN);
        assert_eq!(out.name, "flibber__");
        assert!(matches!(
            out.recovery,
            Recovery::NameRepair {
                stage: "sanitize",
                ..
            }
        ));
        let re_ok = !out.name.is_empty()
            && out.name.len() <= 64
            && out
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        assert!(re_ok, "{} must match ^[a-zA-Z0-9_-]{{1,64}}$", out.name);
        assert!(!KNOWN.contains(&out.name.as_str()));
    }

    /// An already-charset-valid unknown name (no out-of-charset bytes, no
    /// normalizable wrapper) is left exactly as emitted with NO recovery —
    /// it fails as unknown-tool just like today.
    #[test]
    fn already_valid_unknown_name_takes_no_recovery() {
        let out = repair_tool_name("custom_thing", KNOWN);
        assert_eq!(out.name, "custom_thing");
        assert_eq!(out.recovery, Recovery::Clean);
    }

    /// Sanitization truncates to 64 chars and never empties: a long junk name
    /// and an all-invalid name both land in range.
    #[test]
    fn sanitize_truncates_and_never_empties() {
        let long = "x".repeat(200);
        let out = repair_tool_name(&long, KNOWN);
        assert_eq!(out.name.len(), 64);

        // All-out-of-charset → all underscores (still in range, non-empty).
        let out = repair_tool_name("!!!", KNOWN);
        assert_eq!(out.name, "___");

        // Pure-symbol that empties only after sanitize would be impossible
        // (each symbol maps to `_`); the empty-input fallback is covered by
        // the helper directly.
        assert_eq!(sanitize_tool_name(""), SANITIZE_FALLBACK_NAME);
    }

    /// Idempotence on a sanitized name: re-running name repair on the already
    /// charset-valid result is a no-op (it just fails as unknown-tool, no new
    /// recovery).
    #[test]
    fn sanitize_is_idempotent() {
        let first = repair_tool_name("flibber!!", KNOWN);
        let second = repair_tool_name(&first.name, KNOWN);
        assert_eq!(second.name, first.name);
        assert_eq!(second.recovery, Recovery::Clean);
    }

    /// Ambiguity guard: normalization must never rebind when the normalized
    /// form is NOT an exact known name — even if it's a substring/superstring
    /// of one. (`rea` does not match `read`.)
    #[test]
    fn partial_overlap_does_not_rebind() {
        let out = repair_tool_name("rea", KNOWN);
        assert_eq!(out.name, "rea");
        assert_eq!(out.recovery, Recovery::Clean);
    }

    /// A malformed *structural* name normalizes the same way (the toolbox
    /// registers structural tools too), so `<task>` rebinds to `task`.
    #[test]
    fn structural_name_rebinds() {
        let out = repair_tool_name("<task>", KNOWN);
        assert_eq!(out.name, "task");
        assert!(matches!(
            out.recovery,
            Recovery::NameRepair {
                stage: "rebind",
                ..
            }
        ));
    }

    #[test]
    fn name_repair_stages_round_trip_in_db_fields() {
        let rebind = Recovery::NameRepair {
            stage: "rebind",
            original: "<read>".to_string(),
        };
        assert_eq!(rebind.db_fields(), (Some("name_repair"), Some("rebind")));
        let sanitize = Recovery::NameRepair {
            stage: "sanitize",
            original: "flibber!!".to_string(),
        };
        assert_eq!(
            sanitize.db_fields(),
            (Some("name_repair"), Some("sanitize"))
        );
        // Both stages are registered for the audit reader.
        assert!(NAME_REPAIR_STAGES.contains(&"rebind"));
        assert!(NAME_REPAIR_STAGES.contains(&"sanitize"));
    }

    // ---- COMPOSED dispatch-repair pipeline (order + idempotence) ----------
    // Pins the end-to-end contract of the per-call dispatch pipeline
    // (implementation note), composing the three
    // stages in the exact order `agent.rs` runs them:
    //   1. name normalize/rebind (`repair_tool_name`)
    //   2. §12 args input-repair (`repair`, schema by the RESOLVED name)
    //   3. path-normalize (`normalize_paths`)
    // The agent dispatch loop is the production caller; these tests drive the
    // same library functions in the same order so a reorder or a cross-stage
    // idempotence break trips here.

    /// Outcome of one composed dispatch-repair pass: the resolved name, the
    /// repaired args, and the recovery the row would record under the
    /// single-Recovery invariant (§14 — name repair is primary when it fired,
    /// else the args/path repair).
    struct Composed {
        name: String,
        args: Value,
        recovery: Recovery,
        valid: bool,
    }

    /// Run the three dispatch stages in `agent.rs` order against `known` +
    /// `schema` + project `root`, mirroring the dispatch site exactly
    /// (name-repair → repair → normalize_paths, with the §14 single-Recovery
    /// gate). Pure composition of the public library functions.
    fn run_dispatch(
        emitted: &str,
        known: &[&str],
        schema: &Value,
        root: &Path,
        mut args: Value,
    ) -> Composed {
        // 1. Name normalize/rebind — strictly before the schema lookup.
        let name_repair = repair_tool_name(emitted, known);
        let resolved = name_repair.name.clone();
        // 2. §12 args input-repair, schema looked up by the RESOLVED name.
        let mut outcome = repair(&mut args, schema, &resolved);
        let mut recovery = if matches!(name_repair.recovery, Recovery::Clean) {
            outcome.recovery
        } else {
            name_repair.recovery
        };
        // 3. Path-normalize — only on a schema-valid call.
        if outcome.valid {
            let norm = normalize_paths(&mut args, schema, root);
            if let Some(err) = norm.error {
                outcome.valid = false;
                outcome.error = Some(err);
            } else if matches!(recovery, Recovery::Clean) {
                recovery = norm.recovery;
            }
        }
        Composed {
            name: resolved,
            args,
            recovery,
            valid: outcome.valid,
        }
    }

    /// Composition: a call broken in BOTH the name (`<read>`) AND its args (a
    /// stringified-array field) is fully repaired in one dispatch pass — name
    /// rebound to `read`, args validated — and the row records exactly ONE
    /// recovery (the name repair, primary; §14 single-Recovery invariant).
    #[test]
    fn composed_dual_fault_name_and_args_repaired_in_one_pass() {
        let tmp = project_root();
        let out = run_dispatch(
            "<read>",
            KNOWN,
            &schema(),
            tmp.path(),
            // Relative `path` survives path-normalize untouched (cwd-resolved
            // downstream); the broken field is the stringified-array `files`.
            json!({ "path": "src/x.rs", "files": "[\"a\",\"b\"]" }),
        );
        assert!(out.valid);
        // Name rebound to the canonical registered tool.
        assert_eq!(out.name, "read");
        // Args validated: the stringified array is the real array.
        assert_eq!(out.args["files"], json!(["a", "b"]));
        // Single recorded recovery is the name repair (primary).
        assert_eq!(
            out.recovery,
            Recovery::NameRepair {
                stage: "rebind",
                original: "<read>".to_string(),
            }
        );
    }

    /// Idempotence: feeding the already-repaired (canonical) name + args back
    /// through the composed pipeline is a no-op — no rebind, no shape repair,
    /// no path rewrite, `Recovery::Clean`, args byte-identical.
    #[test]
    fn composed_pipeline_is_idempotent_on_canonical_input() {
        let tmp = project_root();
        // First pass repairs the dual fault.
        let first = run_dispatch(
            "<read>",
            KNOWN,
            &schema(),
            tmp.path(),
            json!({ "path": "src/x.rs", "files": "[\"a\",\"b\"]" }),
        );
        assert!(first.valid);
        // Second pass on the canonical output is a pure no-op.
        let before = first.args.clone();
        let second = run_dispatch(&first.name, KNOWN, &schema(), tmp.path(), first.args);
        assert_eq!(second.name, "read");
        assert_eq!(second.recovery, Recovery::Clean);
        assert!(second.valid);
        assert_eq!(second.args, before, "canonical input is never mutated");
    }

    /// Order dependency: name-repair MUST precede input-repair, because the
    /// args schema is looked up by the RESOLVED name. The malformed name
    /// `<read>` has no schema; only after the rebind to `read` does the
    /// stringified-array field validate against `read`'s real schema. Proven
    /// by running the stages in the WRONG order (input-repair on the malformed
    /// name first) and showing the args stay broken.
    #[test]
    fn composed_order_input_repair_uses_resolved_schema() {
        let tmp = project_root();
        // Wrong order: repair args before resolving the name → `<read>` is not
        // a registered tool, so its schema lookup yields `Value::Null` and the
        // broken args slip through unrepaired (no schema to disagree with).
        assert!(!KNOWN.contains(&"<read>"), "the malformed name is unknown");
        let mut wrong_args = json!({ "path": "/x", "files": "[\"a\",\"b\"]" });
        let wrong = repair(&mut wrong_args, &Value::Null, "<read>");
        assert!(wrong.valid, "no schema → trivially valid");
        assert_eq!(
            wrong_args["files"],
            json!("[\"a\",\"b\"]"),
            "without the resolved schema the stringified array is NOT repaired"
        );

        // Correct order (the production order): rebind first, then the args
        // validate against the resolved tool's real schema.
        let right = run_dispatch(
            "<read>",
            KNOWN,
            &schema(),
            tmp.path(),
            json!({ "path": "src/x.rs", "files": "[\"a\",\"b\"]" }),
        );
        assert_eq!(right.name, "read");
        assert_eq!(right.args["files"], json!(["a", "b"]));
    }

    /// Composition with the path-normalize stage: a call broken in name AND
    /// carrying a fabricated absolute path is fully repaired — name rebound,
    /// path salvaged to the root-relative tail — in one pass. The name repair
    /// stays the primary recorded recovery (§14), but the path IS rewritten.
    #[test]
    fn composed_name_and_path_normalize_in_one_pass() {
        let tmp = project_root();
        let out = run_dispatch(
            "<read>",
            KNOWN,
            &schema(),
            tmp.path(),
            json!({ "path": "/home/user/repo/src/tui/settings/mod.rs" }),
        );
        assert!(out.valid);
        assert_eq!(out.name, "read");
        // Path salvaged to the root-relative tail.
        assert_eq!(out.args["path"], json!("src/tui/settings/mod.rs"));
        // Name repair is the primary recorded recovery (§14).
        assert_eq!(
            out.recovery,
            Recovery::NameRepair {
                stage: "rebind",
                original: "<read>".to_string(),
            }
        );
    }

    /// §14 split for a field-alias rename: the model emits the alias form
    /// (`file_path`), the wire/canonical args carry `path`, and the recovery
    /// is a `ShapeRepair` (which is exactly what the dispatcher keys the
    /// wire-vs-user split + the `⟲ repaired` chip off). The original alias
    /// form lives in the caller's pre-repair value; we keep a copy here.
    #[test]
    fn composed_alias_rename_preserves_transcript_split() {
        let tmp = project_root();
        let s = json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "x-cockpit-kind": "path",
                          "x-cockpit-aliases": ["file_path"] }
            },
            "required": ["path"]
        });
        let original = json!({ "file_path": "src/tui/settings/mod.rs" });
        let out = run_dispatch("read", KNOWN, &s, tmp.path(), original.clone());
        assert!(out.valid);
        // Wire form is the canonical `path`; the alias key is gone.
        assert_eq!(out.args, json!({ "path": "src/tui/settings/mod.rs" }));
        // Original (model) form still carries the alias for the user view.
        assert_eq!(original["file_path"], json!("src/tui/settings/mod.rs"));
        // Recovery is the rename ShapeRepair carrying the hint.
        match out.recovery {
            Recovery::ShapeRepair { stage, path, hint } => {
                assert_eq!(stage, "rename_aliased_field");
                assert_eq!(path, "path");
                assert!(hint.unwrap().contains("file_path"));
            }
            other => panic!("expected ShapeRepair, got {other:?}"),
        }
    }

    /// A clean call (canonical name, valid args, relative path) composes to a
    /// pure passthrough: `Clean`, args untouched.
    #[test]
    fn composed_clean_call_is_passthrough() {
        let tmp = project_root();
        let original = json!({ "path": "src/tui/settings/mod.rs", "files": ["a.rs"] });
        let out = run_dispatch("read", KNOWN, &schema(), tmp.path(), original.clone());
        assert_eq!(out.name, "read");
        assert_eq!(out.recovery, Recovery::Clean);
        assert!(out.valid);
        assert_eq!(out.args, original);
    }

    // ---- §12 repair telemetry (implementation note) ----

    #[test]
    fn clean_call_has_no_telemetry() {
        // A valid call validates as-is: nothing malformed, so no fingerprint.
        let mut v = json!({ "path": "/x" });
        let out = repair(&mut v, &schema(), "read");
        assert!(out.valid);
        assert!(out.telemetry.is_none());
    }

    #[test]
    fn repaired_call_carries_telemetry_with_fired_rules() {
        let mut v = json!({ "path": "/x", "offset": "5" });
        let out = repair(&mut v, &schema(), "read");
        assert!(out.valid);
        let t = out.telemetry.expect("repaired call must carry telemetry");
        assert!(!t.shape_fingerprint.is_empty());
        assert_eq!(t.issue_codes, vec!["type".to_string()]);
        // Keys only — never values; sorted.
        assert_eq!(
            t.received_keys,
            vec!["offset".to_string(), "path".to_string()]
        );
        assert_eq!(t.rules_fired, vec!["parse_stringified_number".to_string()]);
    }

    #[test]
    fn unrepairable_call_carries_telemetry_with_empty_rules() {
        // Required `path` missing — no catalog stage conjures it.
        let mut v = json!({ "offset": 5 });
        let out = repair(&mut v, &schema(), "read");
        assert!(!out.valid);
        let t = out.telemetry.expect("hard-fail must carry telemetry");
        assert!(!t.shape_fingerprint.is_empty());
        assert_eq!(t.issue_codes, vec!["required".to_string()]);
        assert_eq!(t.received_keys, vec!["offset".to_string()]);
        // No stage recovered the call.
        assert!(t.rules_fired.is_empty());
    }

    #[test]
    fn structurally_identical_bad_calls_share_a_fingerprint() {
        // Same shape (offset is a stringified number), different concrete
        // values → SAME fingerprint.
        let mut a = json!({ "path": "/x", "offset": "5" });
        let mut b = json!({ "path": "/y", "offset": "9999" });
        let ta = repair(&mut a, &schema(), "read").telemetry.unwrap();
        let tb = repair(&mut b, &schema(), "read").telemetry.unwrap();
        assert_eq!(ta.shape_fingerprint, tb.shape_fingerprint);
    }

    #[test]
    fn different_fault_yields_different_fingerprint() {
        // A stringified-number fault vs a missing-required fault → DIFFERENT
        // fingerprints (different instance path + error code).
        let mut number_fault = json!({ "path": "/x", "offset": "5" });
        let mut missing_fault = json!({ "offset": 5 });
        let t_num = repair(&mut number_fault, &schema(), "read")
            .telemetry
            .unwrap();
        let t_missing = repair(&mut missing_fault, &schema(), "read")
            .telemetry
            .unwrap();
        assert_ne!(t_num.shape_fingerprint, t_missing.shape_fingerprint);
    }

    #[test]
    fn fingerprint_is_tool_scoped() {
        // The same malformed shape under two different tool names produces
        // different fingerprints (tool is part of the hashed input).
        let mut a = json!({ "offset": 5 });
        let mut b = json!({ "offset": 5 });
        let ta = repair(&mut a, &schema(), "read").telemetry.unwrap();
        let tb = repair(&mut b, &schema(), "write").telemetry.unwrap();
        assert_ne!(ta.shape_fingerprint, tb.shape_fingerprint);
    }

    #[test]
    fn received_keys_truncates_with_overflow_marker() {
        let mut map = serde_json::Map::new();
        // 25 keys (> RECEIVED_KEYS_CAP) plus a type fault so the call is
        // non-clean and telemetry is produced.
        for i in 0..24 {
            map.insert(format!("k{i:02}"), json!(1));
        }
        map.insert("offset".to_string(), json!("5"));
        let mut v = Value::Object(map);
        // A minimal schema where `offset` wants an integer so a fault fires.
        let s = json!({
            "type": "object",
            "properties": { "offset": { "type": "integer" } }
        });
        let t = repair(&mut v, &s, "read").telemetry.unwrap();
        assert_eq!(t.received_keys.len(), RECEIVED_KEYS_CAP + 1);
        let last = t.received_keys.last().unwrap();
        assert!(last.starts_with("…+"), "got {last}");
        assert_eq!(last, "…+5"); // 25 keys total - 20 cap = 5 overflow.
    }

    #[test]
    fn received_keys_never_contains_values() {
        // The received-keys summary lists keys, never the (secret-bearing)
        // values held against them.
        let mut v = json!({ "path": "/x", "offset": "supersecret-token-value" });
        let t = repair(&mut v, &schema(), "read").telemetry.unwrap();
        assert!(
            !t.received_keys
                .iter()
                .any(|k| k.contains("supersecret-token-value")),
            "values must never leak into received_keys"
        );
    }
}
