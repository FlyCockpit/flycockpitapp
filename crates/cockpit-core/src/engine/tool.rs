//! Tool abstraction for cockpit.
//!
//! Cockpit owns the tool loop: providers receive only
//! [`ToolDefinition`](crate::engine::message::ToolDefinition) schemas on
//! the completion request, and the host dispatches calls through this
//! module (not Rig's agent/`Tool` execution path). The §12 repair layer
//! needs a seam between JSON tool arguments and the typed dispatcher, so
//! every tool pins `type Args = Value` and can mutate arguments in place
//! via [`crate::engine::repair`] before `call()` runs.
//!
//! Concrete tools implement [`Tool`]; the dispatcher holds a
//! `BTreeMap<String, Arc<dyn Tool>>`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::engine::message::ToolDefinition;

pub use crate::daemon::proto::ToolFailKind;

/// JSON Schema extension marking a persisted tool field as display-only.
///
/// Values under a marked field stay in the durable timeline, but are removed
/// from the model-wire projection before that projection is stored.  The same
/// projection is used by the live turn and session rehydration, so a marked
/// value cannot enter a later model request.
pub const MODEL_EPHEMERAL_SCHEMA_KEY: &str = "x-cockpit-model-ephemeral";

/// Production consumer inventory for the marker contract:
///
/// - ordinary built-in and native/custom argument schemas are projected in
///   `agent::tool_dispatch` before `wire_input_json` is stored; the provider
///   choice and interrupted scheduler-continuation record are projected at
///   their own model-history insertion boundaries in `agent::turn_phases`;
/// - structured built-in and native/custom results are projected at the same
///   boundary and the projected canonical result is the restart authority;
/// - external MCP schemas/results remain unchanged, while Monty's host-owned
///   `show` lane is carried by `ToolOutput` display metadata marked below;
/// - the existing `ToolOutput` sandbox, exit-code, resource, and output-sidecar
///   exclusions are expressed by `ToolOutput::result_metadata_schema` below.
///
/// This is an ownership/type bound over every production `wire_input_json`
/// consumer. Deferred write/edit reconciliation reads that already-projected
/// row before applying its separate lifecycle elision; verification recipes and
/// compaction consume the same projected row. Escalation reads a prior `bash`
/// row only (the built-in `bash` schema declares no marker), and schedule
/// dispatch only copies scheduler-owned structural rows, whose fixed schemas
/// are outside `Tool`. None of these later consumers reintroduces a display
/// projection into model history.

/// Strip fields declared with [`MODEL_EPHEMERAL_SCHEMA_KEY`] from a JSON value.
///
/// The extension is intentionally a storage concern, not JSON-Schema
/// validation vocabulary: providers still receive the complete input schema
/// and may emit the field. Local refs, definitions, compositions, object
/// property selectors, and tuple/list arrays are followed recursively.
/// Malformed or unresolvable projection schema fails closed by removing the
/// value governed by that fragment.
pub fn strip_model_ephemeral_fields(value: &Value, schema: &Value) -> Value {
    project_model_value(value, schema, schema, "#", 0, true).unwrap_or(Value::Null)
}

const MAX_MODEL_EPHEMERAL_SCHEMA_DEPTH: usize = 64;

fn project_model_value(
    value: &Value,
    schema: &Value,
    root: &Value,
    schema_pointer: &str,
    depth: usize,
    follow_reference: bool,
) -> Option<Value> {
    if depth > MAX_MODEL_EPHEMERAL_SCHEMA_DEPTH {
        return None;
    }
    match schema {
        Value::Bool(true) => return Some(value.clone()),
        Value::Bool(false) => return None,
        Value::Object(_) => {}
        _ => return None,
    }
    if schema
        .get(MODEL_EPHEMERAL_SCHEMA_KEY)
        .and_then(Value::as_bool)
        == Some(true)
    {
        return None;
    }

    // JSON Schema permits sibling constraints next to `$ref`. Apply the
    // target first, then the local siblings, so a marker in either location
    // cannot be hidden by reference resolution.
    if follow_reference && let Some(reference) = schema.get("$ref") {
        let reference = reference.as_str()?;
        let pointer = reference.strip_prefix('#')?;
        let target = root.pointer(pointer)?;
        let projected = project_model_value(value, target, root, reference, depth + 1, true)?;
        // JSON Schema permits sibling constraints next to `$ref`. Revisit this
        // schema without following the reference so those siblings use their
        // original root-relative location for composition matching.
        return project_model_value(&projected, schema, root, schema_pointer, depth + 1, false);
    }

    let mut projected = value.clone();
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = schema.get(keyword) {
            let branches = branches.as_array()?;
            if matches!(keyword, "anyOf" | "oneOf") && branches.is_empty() {
                return None;
            }
            let branch_indexes: Vec<usize> = match keyword {
                "allOf" => (0..branches.len()).collect(),
                "anyOf" | "oneOf" => matching_composition_branches(
                    value,
                    root,
                    schema_pointer,
                    keyword,
                    branches.len(),
                )?,
                _ => unreachable!("composition keywords are fixed above"),
            };
            if keyword == "oneOf" && branch_indexes.len() != 1 {
                return None;
            }
            if matches!(keyword, "anyOf" | "oneOf") && branch_indexes.is_empty() {
                return None;
            }
            for index in branch_indexes {
                let branch_pointer = schema_pointer_child(
                    &schema_pointer_child(schema_pointer, keyword),
                    &index.to_string(),
                );
                projected = project_model_value(
                    &projected,
                    &branches[index],
                    root,
                    &branch_pointer,
                    depth + 1,
                    true,
                )?;
            }
        }
    }

    match &projected {
        Value::Object(object) => {
            let properties = match schema.get("properties") {
                Some(value) => Some(value.as_object()?),
                None => None,
            };
            let patterns = match schema.get("patternProperties") {
                Some(value) => Some(value.as_object()?),
                None => None,
            };
            let additional = schema.get("additionalProperties");
            let mut projected = serde_json::Map::with_capacity(object.len());
            for (name, field) in object {
                let mut field_value = Some(field.clone());
                let mut matched = false;
                if let Some(field_schema) = properties.and_then(|properties| properties.get(name)) {
                    matched = true;
                    field_value = field_value.and_then(|value| {
                        project_model_value(
                            &value,
                            field_schema,
                            root,
                            &schema_pointer_child(
                                &schema_pointer_child(schema_pointer, "properties"),
                                name,
                            ),
                            depth + 1,
                            true,
                        )
                    });
                }
                if let Some(patterns) = patterns {
                    for (pattern, field_schema) in patterns {
                        let regex = regex::Regex::new(pattern).ok()?;
                        if regex.is_match(name) {
                            matched = true;
                            field_value = field_value.and_then(|value| {
                                project_model_value(
                                    &value,
                                    field_schema,
                                    root,
                                    &schema_pointer_child(
                                        &schema_pointer_child(schema_pointer, "patternProperties"),
                                        pattern,
                                    ),
                                    depth + 1,
                                    true,
                                )
                            });
                        }
                    }
                }
                if !matched && let Some(additional) = additional {
                    field_value = match additional {
                        Value::Bool(false) => None,
                        Value::Bool(true) => field_value,
                        schema => field_value.and_then(|value| {
                            project_model_value(
                                &value,
                                schema,
                                root,
                                &schema_pointer_child(schema_pointer, "additionalProperties"),
                                depth + 1,
                                true,
                            )
                        }),
                    };
                }
                if let Some(field_value) = field_value {
                    projected.insert(name.clone(), field_value);
                }
            }
            Some(Value::Object(projected))
        }
        Value::Array(items) => {
            let prefix = match schema.get("prefixItems") {
                Some(value) => Some(value.as_array()?),
                None => None,
            };
            let item_schema = schema.get("items");
            let mut output = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                let schema = prefix.and_then(|prefix| prefix.get(index)).or(item_schema);
                let item_pointer = if prefix.is_some_and(|prefix| index < prefix.len()) {
                    schema_pointer_child(
                        &schema_pointer_child(schema_pointer, "prefixItems"),
                        &index.to_string(),
                    )
                } else {
                    schema_pointer_child(schema_pointer, "items")
                };
                let projected = match schema {
                    Some(Value::Bool(false)) => None,
                    Some(schema) => {
                        project_model_value(item, schema, root, &item_pointer, depth + 1, true)
                    }
                    None => Some(item.clone()),
                };
                if let Some(projected) = projected {
                    output.push(projected);
                }
            }
            Some(Value::Array(output))
        }
        _ => Some(projected),
    }
}

/// Return the `anyOf`/`oneOf` branches that validate the source instance.
///
/// Validators are addressed by their JSON pointer within the original schema
/// document, rather than compiled from an isolated branch. This keeps local
/// references and embedded resource scopes rooted exactly as authored.
fn matching_composition_branches(
    value: &Value,
    root: &Value,
    schema_pointer: &str,
    keyword: &str,
    branch_count: usize,
) -> Option<Vec<usize>> {
    let validators = jsonschema::validator_map_for(root).ok()?;
    let mut matching = Vec::new();
    for index in 0..branch_count {
        let branch_pointer = schema_pointer_child(
            &schema_pointer_child(schema_pointer, keyword),
            &index.to_string(),
        );
        let validator = validators.get(&branch_pointer)?;
        if validator.is_valid(value) {
            matching.push(index);
        }
    }
    Some(matching)
}

/// Add one URI-fragment JSON-Pointer segment.
fn schema_pointer_child(pointer: &str, segment: &str) -> String {
    let escaped = segment.replace('~', "~0").replace('/', "~1");
    format!("{pointer}/{escaped}")
}

/// Marker error a tool returns when the *arguments* were the problem
/// (see [`ToolFailKind::Invocation`]). The dispatcher downcasts to this
/// to classify the failure; build it with [`invalid_input`].
#[derive(Debug)]
pub struct InvalidToolInput(pub String);

impl std::fmt::Display for InvalidToolInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidToolInput {}

/// Build an [`InvalidToolInput`] error. Tools use this for missing /
/// wrong-type required args and for argument values that can't be
/// satisfied — anything that's the model's fault rather than the
/// environment's.
pub fn invalid_input(msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(InvalidToolInput(msg.into()))
}

/// Deserialize already-repaired tool arguments into a tool-local args type.
///
/// This deliberately sits below the repair layer: [`Tool::call`] still receives
/// raw [`serde_json::Value`], then individual tools call this helper inside
/// `call` after validation/repair/path-normalization has mutated that value.
pub fn typed_args<A: DeserializeOwned>(args: Value) -> Result<A> {
    serde_json::from_value(args)
        .map_err(|err| invalid_input(format!("invalid tool arguments: {err}")))
}

/// Classify a dispatch error: an [`InvalidToolInput`] anywhere in the
/// chain means the model built the call badly; everything else is an
/// execution failure.
pub fn classify_failure(err: &anyhow::Error) -> ToolFailKind {
    if err.downcast_ref::<InvalidToolInput>().is_some() {
        ToolFailKind::Invocation
    } else {
        ToolFailKind::Execution
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolEffect {
    ReadOnly,
    Mutating,
    Dynamic,
}

/// Shared permission predicate for Cockpit-owned tools. Transport-specific
/// callers must use this instead of reinterpreting [`ToolEffect`] locally so a
/// native call and a Monty `mcp.invoke('cockpit', ...)` call agree.
pub fn tool_requires_permission(tool: &dyn Tool) -> bool {
    !matches!(tool.effect(), ToolEffect::ReadOnly) && !tool.authorizes_own_effects()
}

pub const TOOL_PRESENTATION_SUMMARY_CHARS: usize = 240;
pub const TOOL_PRESENTATION_FULL_CHARS: usize = 2_000;

/// Display-neutral tool-call presentation.
///
/// Core owns the semantic choice of label, glyph key, and argument summary.
/// TUI code maps these plain strings onto terminal spans, colors, widths, and
/// glyph padding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPresentation {
    pub glyph: Option<&'static str>,
    pub label: String,
    pub summary: String,
    pub full_input: String,
}

impl ToolPresentation {
    pub fn default_for(tool: &str, args: &Value) -> Self {
        let (summary, full_input) = readable_args(args);
        Self {
            glyph: None,
            label: tool.to_string(),
            summary,
            full_input,
        }
    }

    pub fn with_parts(
        glyph: Option<&'static str>,
        label: impl Into<String>,
        summary: impl Into<String>,
        full_input: impl Into<String>,
    ) -> Self {
        Self {
            glyph,
            label: label.into(),
            summary: summary.into(),
            full_input: full_input.into(),
        }
    }
}

pub fn readable_args(args: &Value) -> (String, String) {
    (
        cockpit_host::text::format_args(
            args,
            cockpit_host::text::ArgFormatOptions::history(TOOL_PRESENTATION_SUMMARY_CHARS, false),
        ),
        cockpit_host::text::format_args(
            args,
            cockpit_host::text::ArgFormatOptions::history(TOOL_PRESENTATION_FULL_CHARS, true),
        ),
    )
}

pub fn path_or_readable_args(args: &Value) -> (String, String) {
    string_field(args, "path")
        .map(|path| (path.clone(), path))
        .unwrap_or_else(|| readable_args(args))
}

pub fn string_field(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(Value::as_str).map(str::to_string)
}

pub fn single_line_preview(s: &str, limit: usize) -> String {
    let mut first = s.lines().next().unwrap_or("").to_string();
    if s.contains('\n') {
        first.push_str(" …");
    }
    bounded_preview(&first, limit)
}

pub fn bounded_preview(s: &str, limit: usize) -> String {
    if s.chars().count() <= limit {
        return s.to_string();
    }
    let take = limit.saturating_sub(1);
    let mut out: String = s.chars().take(take).collect();
    out.push('…');
    out
}

pub fn known_tool_presentation(tool: &str, args: &Value) -> ToolPresentation {
    use crate::tools;
    match tool {
        "bash" => tools::bash::BashTool::new().presentation(args),
        "read" => tools::read::ReadTool.presentation(args),
        "unlock" => tools::unlock::UnlockTool.presentation(args),
        "write" => tools::write::WriteTool.presentation(args),
        "edit" => tools::edit::EditTool.presentation(args),
        "delete" => tools::delete::DeleteTool.presentation(args),
        "websearch" => tools::web::WebSearchTool.presentation(args),
        "webfetch" => tools::web::WebFetchTool.presentation(args),
        _ => ToolPresentation::default_for(tool, args),
    }
}

#[derive(Debug, Clone)]
pub struct ReviewCage {
    state: Arc<Mutex<ReviewCageState>>,
}

pub const SKILLS_REVIEW_ALLOWED_TOOLS: [&str; 5] =
    ["edit", "read", "skill", "skill_manage", "write"];
pub const SKILLS_REVIEW_MAX_DISPATCHES: u32 = 64;

#[derive(Debug)]
struct ReviewCageState {
    allowed_tools: HashSet<String>,
    viewed_skills: HashSet<String>,
    viewed_package_roots: HashSet<PathBuf>,
    preauthorized_package_roots: Vec<PathBuf>,
    auto_deny_approvals: bool,
    max_dispatches: u32,
    dispatches: u32,
}

impl ReviewCage {
    pub fn skills_review() -> Self {
        Self::skills_review_with_package_roots(Vec::new())
    }

    pub fn skills_review_with_package_roots(roots: impl IntoIterator<Item = PathBuf>) -> Self {
        Self {
            state: Arc::new(Mutex::new(ReviewCageState {
                allowed_tools: SKILLS_REVIEW_ALLOWED_TOOLS
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                viewed_skills: HashSet::new(),
                viewed_package_roots: HashSet::new(),
                preauthorized_package_roots: roots.into_iter().map(lexical_normalize).collect(),
                auto_deny_approvals: true,
                max_dispatches: SKILLS_REVIEW_MAX_DISPATCHES,
                dispatches: 0,
            })),
        }
    }

    pub fn allow_dispatch(&self, tool: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        if !state.allowed_tools.contains(tool) {
            return Err(invalid_input(format!(
                "background skill review cannot call `{tool}`; allowed tools: {}",
                sorted_csv(&state.allowed_tools)
            )));
        }
        if state.dispatches >= state.max_dispatches {
            return Err(invalid_input(format!(
                "background skill review stopped after {} tool dispatches",
                state.max_dispatches
            )));
        }
        state.dispatches = state.dispatches.saturating_add(1);
        Ok(())
    }

    pub fn auto_deny_approvals(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .auto_deny_approvals
    }

    pub fn record_skill_view(&self, name: &str) {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .viewed_skills
            .insert(name.to_string());
    }

    pub fn record_skill_package_view(&self, name: &str, package_root: &Path) {
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        let package_root = lexical_normalize(package_root);
        state.viewed_skills.insert(name.to_string());
        state.viewed_package_roots.insert(package_root.clone());
        if !state
            .preauthorized_package_roots
            .iter()
            .any(|root| root == &package_root)
        {
            state.preauthorized_package_roots.push(package_root);
        }
    }

    pub fn skill_was_viewed(&self, name: &str) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .viewed_skills
            .contains(name)
    }

    pub fn skill_package_was_viewed(&self, package_root: &Path) -> bool {
        let package_root = lexical_normalize(package_root);
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .viewed_package_roots
            .iter()
            .any(|viewed| paths_refer_to_same_directory(viewed, &package_root))
    }

    pub fn preauthorizes_package_path(&self, path: &Path) -> bool {
        let path = lexical_normalize(path);
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .preauthorized_package_roots
            .iter()
            .any(|root| path.starts_with(root) && path != *root)
    }

    pub fn allowed_tools(&self) -> HashSet<String> {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .allowed_tools
            .clone()
    }

    pub fn max_dispatches(&self) -> u32 {
        self.state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .max_dispatches
    }
}

fn paths_refer_to_same_directory(left: &Path, right: &Path) -> bool {
    left == right
        || matches!(
            (left.canonicalize(), right.canonicalize()),
            (Ok(left), Ok(right)) if left == right
        )
}

fn sorted_csv(values: &HashSet<String>) -> String {
    let mut values: Vec<&str> = values.iter().map(String::as_str).collect();
    values.sort_unstable();
    values.join(", ")
}

fn lexical_normalize(path: impl AsRef<Path>) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.as_ref().components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod model_ephemeral_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn strips_marked_args_and_structured_results_without_touching_display_value() {
        let schema = json!({
            "type": "object",
            "properties": {
                "visible": { "type": "string" },
                "ephemeral": { "x-cockpit-model-ephemeral": true },
                "nested": {
                    "type": "object",
                    "properties": {
                        "keep": { "type": "string" },
                        "drop": { "x-cockpit-model-ephemeral": true }
                    }
                }
            }
        });
        let display = json!({
            "visible": "shown",
            "ephemeral": "timeline-only",
            "nested": { "keep": "also shown", "drop": "never replayed" }
        });

        assert_eq!(
            strip_model_ephemeral_fields(&display, &schema),
            json!({ "visible": "shown", "nested": { "keep": "also shown" } })
        );
        assert_eq!(
            display["ephemeral"], "timeline-only",
            "the durable/display projection remains complete"
        );

        let contents = CanonicalToolResultContents::new(vec![
            crate::typed_media_result::CanonicalToolResultContent::Json { value: display },
        ])
        .unwrap();
        let projected = contents.strip_model_ephemeral_fields(&schema).unwrap();
        assert_eq!(
            projected.parts(),
            &[
                crate::typed_media_result::CanonicalToolResultContent::Json {
                    value: json!({ "visible": "shown", "nested": { "keep": "also shown" } })
                }
            ]
        );
    }

    #[test]
    fn result_metadata_schema_marks_existing_output_metadata() {
        let metadata = json!({
            "sandbox": { "enabled": true },
            "resource": { "cpu": 1 },
            "exit_code": 1,
            "output_sidecar": { "stdout": "full" },
            "display": "timeline only"
        });
        assert_eq!(
            strip_model_ephemeral_fields(&metadata, &ToolOutput::result_metadata_schema()),
            json!({}),
            "ToolOutput audit metadata remains model-ephemeral"
        );
    }

    #[test]
    fn native_result_schema_keeps_its_own_ref_root_and_field_namespace() {
        let native_schema = json!({
            "$defs": {
                "result": {
                    "type": "object",
                    "properties": {
                        "visible": { "type": "string" },
                        "secret": { "x-cockpit-model-ephemeral": true },
                        "sandbox": { "type": "string" },
                        "resource": { "type": "string" },
                        "exit_code": { "type": "integer" },
                        "output_sidecar": { "type": "string" }
                    }
                }
            },
            "$ref": "#/$defs/result"
        });
        let result = json!({
            "visible": "shown",
            "secret": "never replayed",
            "sandbox": "ordinary result field",
            "resource": "ordinary result field",
            "exit_code": 0,
            "output_sidecar": "ordinary result field"
        });

        assert_eq!(
            strip_model_ephemeral_fields(&result, &native_schema),
            json!({
                "visible": "shown",
                "sandbox": "ordinary result field",
                "resource": "ordinary result field",
                "exit_code": 0,
                "output_sidecar": "ordinary result field"
            }),
            "native schemas retain local $ref resolution and do not inherit ToolOutput metadata markers"
        );

        let native_schema = json!({
            "type": "object",
            "properties": {
                "visible": { "type": "string" },
                "secret": { "x-cockpit-model-ephemeral": true }
            }
        });
        assert_eq!(
            strip_model_ephemeral_fields(
                &json!({"visible": "shown", "secret": "never replayed"}),
                &native_schema,
            ),
            json!({"visible": "shown"}),
            "the native schema's own result-field markers remain active"
        );
    }

    #[test]
    fn traverses_refs_compositions_defs_tuples_patterns_and_additional_fields() {
        let schema = json!({
            "$defs": {
                "secret": { "x-cockpit-model-ephemeral": true },
                "entry": {
                    "allOf": [{
                        "type": "object",
                        "patternProperties": { "^private_": { "$ref": "#/$defs/secret" } },
                        "additionalProperties": { "type": "string" }
                    }]
                }
            },
            "type": "object",
            "properties": {
                "direct": { "$ref": "#/$defs/secret" },
                "ref_sibling": {
                    "$ref": "#/$defs/entry",
                    "x-cockpit-model-ephemeral": true
                },
                "composed": {
                    "anyOf": [
                        { "type": "string" },
                        { "$ref": "#/$defs/secret" }
                    ]
                },
                "tuple": {
                    "type": "array",
                    "prefixItems": [
                        { "type": "string" },
                        { "$ref": "#/$defs/secret" }
                    ],
                    "items": { "$ref": "#/$defs/entry" }
                }
            },
            "additionalProperties": { "$ref": "#/$defs/secret" }
        });
        assert_eq!(
            strip_model_ephemeral_fields(
                &json!({
                    "direct": "drop",
                    "ref_sibling": {"public": "drop"},
                    "composed": "drop",
                    "tuple": ["keep", "drop", {"public": "keep", "private_token": "drop"}],
                    "unknown": "drop"
                }),
                &schema
            ),
            json!({"tuple": ["keep", {"public": "keep"}]})
        );
        assert_eq!(
            strip_model_ephemeral_fields(
                &json!({"secret": "drop"}),
                &json!({"$ref": "#/$defs/missing"})
            ),
            Value::Null,
            "an unresolved projection reference fails closed"
        );
        assert_eq!(
            strip_model_ephemeral_fields(&json!({"secret": "drop"}), &json!({"properties": []})),
            Value::Null,
            "a malformed projection fragment fails closed"
        );
    }

    #[test]
    fn composition_markers_only_project_the_matching_discriminated_variant() {
        for keyword in ["anyOf", "oneOf"] {
            let mut variant_schema = json!({
                "$defs": {
                    "ephemeral_payload": { "x-cockpit-model-ephemeral": true },
                    "public": {
                        "type": "object",
                        "properties": {
                            "kind": { "const": "public" },
                            "payload": { "type": "string" }
                        },
                        "required": ["kind", "payload"],
                        "additionalProperties": false
                    },
                    "private": {
                        "type": "object",
                        "properties": {
                            "kind": { "const": "private" },
                            "payload": { "$ref": "#/$defs/ephemeral_payload" }
                        },
                        "required": ["kind", "payload"],
                        "additionalProperties": false
                    }
                }
            });
            variant_schema.as_object_mut().unwrap().insert(
                keyword.to_string(),
                json!([
                    { "$ref": "#/$defs/public" },
                    { "$ref": "#/$defs/private" }
                ]),
            );

            assert_eq!(
                strip_model_ephemeral_fields(
                    &json!({ "kind": "public", "payload": "keep this" }),
                    &variant_schema,
                ),
                json!({ "kind": "public", "payload": "keep this" }),
                "a nonmatching {keyword} branch must not remove a shared field"
            );
            assert_eq!(
                strip_model_ephemeral_fields(
                    &json!({ "kind": "private", "payload": "timeline-only" }),
                    &variant_schema,
                ),
                json!({ "kind": "private" }),
                "the matching {keyword} branch must still remove its marked field"
            );
        }
    }
}

#[cfg(test)]
mod typed_args_tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;
    use std::collections::BTreeSet;

    #[derive(Debug, Deserialize)]
    struct GlobArgs {
        pattern: String,
    }

    #[test]
    fn typed_args_deserializes_after_repair_normalizes_aliases() {
        let schema = json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "x-cockpit-aliases": ["query"]
                }
            },
            "required": ["pattern"]
        });
        let mut args = json!({ "query": "**/*.rs" });

        let outcome = crate::engine::repair::repair(&mut args, &schema, "glob");
        assert!(outcome.valid, "{outcome:?}");

        let parsed: GlobArgs = typed_args(args).unwrap();
        assert_eq!(parsed.pattern, "**/*.rs");
    }

    #[test]
    fn skills_review_cage_allowlist_matches_toolbox() {
        let cage = ReviewCage::skills_review();
        let allowed: BTreeSet<String> = cage.allowed_tools().into_iter().collect();
        assert_eq!(
            allowed,
            SKILLS_REVIEW_ALLOWED_TOOLS
                .into_iter()
                .map(str::to_string)
                .collect()
        );
    }

    #[test]
    fn review_cage_preauthorizes_only_skill_package_roots() {
        let root = PathBuf::from("/tmp/cockpit-skills/example");
        let sibling = PathBuf::from("/tmp/cockpit-skills/other/SKILL.md");
        let cage = ReviewCage::skills_review_with_package_roots([root.clone()]);

        assert!(cage.preauthorizes_package_path(&root.join("SKILL.md")));
        assert!(cage.preauthorizes_package_path(&root.join("references/guide.md")));
        assert!(!cage.preauthorizes_package_path(&root));
        assert!(!cage.preauthorizes_package_path(&sibling));
    }

    #[test]
    fn review_cage_viewed_package_becomes_preauthorized() {
        let root = PathBuf::from("/tmp/cockpit-skills/new-skill");
        let cage = ReviewCage::skills_review();

        assert!(!cage.preauthorizes_package_path(&root.join("SKILL.md")));
        cage.record_skill_package_view("new-skill", &root);
        assert!(cage.skill_package_was_viewed(&root));
        assert!(cage.preauthorizes_package_path(&root.join("SKILL.md")));
    }

    #[cfg(unix)]
    #[test]
    fn review_cage_matches_a_viewed_skill_through_workspace_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let physical = tmp.path().join("workspace");
        let package = physical.join(".agents/skills/example");
        std::fs::create_dir_all(&package).unwrap();
        let alias = tmp.path().join("workspace-alias");
        std::os::unix::fs::symlink(&physical, &alias).unwrap();
        let cage = ReviewCage::skills_review();

        cage.record_skill_package_view("example", &alias.join(".agents/skills/example"));

        assert!(cage.skill_package_was_viewed(&package));
    }

    #[test]
    fn skills_review_cage_keeps_auto_deny() {
        assert!(ReviewCage::skills_review().auto_deny_approvals());
    }

    #[test]
    fn skills_review_cage_dispatch_cap_is_finite() {
        let cage = ReviewCage::skills_review();
        let max = cage.max_dispatches();
        assert!(max > 16);
        assert!(max < 1_000);
        for _ in 0..max {
            cage.allow_dispatch("skill").unwrap();
        }
        let err = cage.allow_dispatch("skill").unwrap_err().to_string();
        assert!(err.contains(&max.to_string()), "{err}");
    }

    #[test]
    fn typed_args_failures_are_invocation_errors() {
        let err = typed_args::<GlobArgs>(json!({})).unwrap_err();

        assert_eq!(classify_failure(&err), ToolFailKind::Invocation);
    }
}

/// A locked-down tool whose argument type is always `serde_json::Value`.
///
/// Implementors get the args **after** §12 repair has run; the caller's
/// `ctx` is opaque and threaded for cross-cutting state (lock manager,
/// session reference, redaction table, etc.). The output is rendered to
/// a string for the model — JSON, markdown, raw text, whatever fits.
#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;

    /// One-sentence description per GOALS §10. Keep this terse enough for the
    /// default tool array; the invariant test treats ~200 chars as the
    /// hard ceiling for built-ins.
    /// This is the **terse** form (the token-economy budget the CI check
    /// enforces).
    fn description(&self) -> &str;

    /// The **verbose** description: explicit, steering prose rendered when the
    /// agent def's `toolSteering` is [`crate::agents::ToolSteering::Verbose`].
    /// `None` (the default) means "no verbose variant — fall back to the
    /// terse [`Self::description`]." Registry-driven tests enforce verbose
    /// coverage for built-ins that reach the normal agent surface; dynamic or
    /// user-authored tools may rely on the terse fallback where that is the
    /// correct wording.
    fn verbose_description(&self) -> Option<String> {
        None
    }

    /// Authoritative side-effect classification for approval policy. Dynamic
    /// tools must conservatively require approval unless the concrete call is
    /// proven read-only by that tool's own policy.
    fn effect(&self) -> ToolEffect {
        ToolEffect::Dynamic
    }

    /// Call-specific effect classification used by ephemeral idle wakes after
    /// a call has completed. `Dynamic` remains the conservative default: a
    /// tool that can prove this exact successful invocation was read-only
    /// overrides this method. This is deliberately separate from [`Self::effect`],
    /// whose capability/approval meaning must stay conservative before a call.
    fn completed_call_effect(&self, _args: &Value, _output: &ToolOutput) -> ToolEffect {
        self.effect()
    }

    /// Whether the tool owns a narrower, composite authorization chokepoint
    /// inside its implementation. Such a tool still advertises its real effect
    /// and remains subject to review-cage and loop controls, but ordinary-tool
    /// dispatch must not wrap it in a second generic `NativeTool` approval.
    fn authorizes_own_effects(&self) -> bool {
        false
    }

    /// Whether this is a REGISTERED ORDINARY built-in operation — not a
    /// user-authored / custom-bash / unregistered tool. A tool is admissible for
    /// surface-gated read-only CONCURRENT execution only when this is `true` AND
    /// its [`Self::effect`] is [`ToolEffect::ReadOnly`]: a user's custom-bash
    /// template marked `approval_exempt` claims a `ReadOnly` effect but runs an
    /// arbitrary shell command, so it must NOT count as a proven-read-only
    /// operation. Defaults `true` for the built-in tool set; custom/unregistered
    /// tools override it to `false`.
    fn is_registered_ordinary_operation(&self) -> bool {
        true
    }

    fn binary_requirements(&self) -> Vec<crate::capabilities::BinaryRequirement> {
        Vec::new()
    }

    fn presentation(&self, args: &Value) -> ToolPresentation {
        ToolPresentation::default_for(self.name(), args)
    }

    /// JSON Schema for the arguments. Returning `Value::Null` means "no
    /// arguments." See plan.md §12 for the conventions the schema must
    /// follow for the repair catalog to fire. This is the **terse** form
    /// (noun-phrase parameter descriptions).
    fn parameters(&self) -> Value;

    /// The **verbose** parameter schema: same structure + required set as
    /// [`Self::parameters`], with explicit steering parameter descriptions,
    /// rendered when the agent def's `toolSteering` is
    /// [`crate::agents::ToolSteering::Verbose`] (issue #75). `None` (the
    /// default) reuses [`Self::parameters`]. Tool *grants* never vary by
    /// steering — only how the schema's descriptions read — so the shape
    /// here must match.
    fn verbose_parameters(&self) -> Option<Value> {
        None
    }

    /// JSON Schema for structured tool-result fields. This is deliberately
    /// separate from the provider-visible argument schema: result fields are
    /// produced by the host, persisted for the transcript, and then projected
    /// into model history at store time. This schema governs canonical result
    /// contents only; [`ToolOutput`] audit metadata is projected independently
    /// with its own schema. The default carries no result-field markers.
    fn result_schema(&self) -> Value {
        serde_json::json!({})
    }

    /// Run the tool. The args have already passed through §12 repair (or
    /// validate-clean) before this call; the implementor only needs to
    /// look up the fields it cares about.
    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput>;

    /// Return the argument projection that may be stored in ordinary,
    /// unencrypted tool-call records and their co-persisted lifecycle events.
    /// Most tools persist their arguments verbatim. Tools that accept secret
    /// material must replace it here while preserving enough structure for
    /// transcript display.
    fn ledger_args(&self, args: &Value) -> Value {
        args.clone()
    }

    /// True for tools whose `call` future actively observes [`ToolCtx::cancel`]
    /// and performs its own cleanup before returning from cancellation.
    fn honors_dispatch_cancel(&self) -> bool {
        false
    }

    /// Cleanup hook invoked by the dispatcher after abandoning an in-flight
    /// call due to timeout or turn cancellation. Most tools are abandon-safe
    /// and keep the default no-op; transport-backed tools can override this to
    /// tear down poisoned protocol state before the next call.
    async fn on_abandon(&self, _ctx: &ToolCtx) -> Result<()> {
        Ok(())
    }
}

/// Tool output shape.
///
/// `content` is what the model sees on the next turn. `truncated` tells
/// the §10 spillover path whether to write a full version to disk.
///
/// `recovery` and `canonical_args` let a tool communicate that the call
/// it received was *recoverable* — it ran successfully, but only after
/// the tool normalized the args in a way the model should learn from.
/// The edit cascade (GOALS §13c) is the only v0 user: when an edit
/// matches at stage > 1, the tool sets `recovery = EditCascade { stage,
/// path: "old_string" }` and `canonical_args = <original args with
/// old_string replaced by the matched bytes>`. The dispatcher uses
/// these to persist the canonical form to the audit row's
/// `wire_input_json` and to rewrite the in-memory assistant message so
/// the next inference call carries canonical bytes.
#[derive(Debug, Clone)]
pub struct ToolOutput {
    pub content: CanonicalToolResultContents,
    /// Optional display-only text for the durable timeline and live UI. The
    /// model projection remains [`Self::content`]; this field is governed by
    /// [`MODEL_EPHEMERAL_SCHEMA_KEY`] in [`Self::result_metadata_schema`], so
    /// replay cannot accidentally promote it into model history.
    pub display_content: Option<String>,
    /// Optional short-circuit guidance for an immediately repeated call with
    /// the same final semantic input. A tool sets this when its *result* was a
    /// recoverable dead-end the model should not repeat verbatim. The
    /// dispatcher records it in session-local memory and, on the next identical
    /// call, returns the guidance without re-running the tool.
    pub repeat_guard: Option<RepeatGuard>,
    /// True when [`content`] is capped (per the §10 truncation marker).
    pub truncated: bool,
    /// Optional bounded source capture for a truncated result.  This carries
    /// host-side capture accounting independently from the model-visible body;
    /// the dispatcher turns it into an immutable text artifact together with
    /// the owning event.
    pub text_artifact_capture: Option<TextArtifactCapture>,
    /// Whether `text_artifact_capture` belongs only to the display projection.
    /// Such an artifact is retained with the durable event but must never
    /// replace the model result in live or rehydrated history.
    pub text_artifact_model_ephemeral: bool,
    /// Additional lane-tagged captures. This preserves the legacy singular
    /// capture API while allowing an envelope-producing tool to retain every
    /// independently spilled lane in the same owning event.
    pub text_artifact_captures: Vec<ToolTextArtifactCapture>,
    /// Host-owned human-only notices. The dispatcher publishes these only
    /// after the same result-injection recheck that governs the tool result.
    pub notices: Vec<String>,
    /// Optional recovery annotation. `None` means the tool ran without
    /// any normalization. The dispatcher prefers this over any
    /// shape-repair recovery that fired earlier in the same call.
    pub recovery: Option<crate::db::tool_calls::Recovery>,
    /// Optional canonical args. When `Some`, the dispatcher uses this
    /// as `wire_input_json` for the audit row and as the rewritten
    /// arguments in the assistant message's `ToolCall` in history.
    pub canonical_args: Option<serde_json::Value>,
    /// Optional sandbox-state metadata for the `tool_call` event (Part B).
    /// **Only `bash` populates it**; every other tool leaves it `None`, so
    /// the event omits the `sandbox` sub-object. It never enters the
    /// model's context (token economy, GOALS §10) — the dispatcher reads it
    /// solely to emit the timeline/export event.
    pub sandbox: Option<SandboxMeta>,
    /// Optional runtime resource-scheduler metadata for the `tool_call` event.
    /// Only `bash` populates it; it never enters model-facing content.
    pub resource: Option<ResourceMeta>,
    /// The structured process exit code for a `bash` call that ran a shell
    /// (export-audit fidelity). The authoritative source the exporter writes
    /// onto the `tool_call` event's `exit_code` field — distinct from the
    /// human-readable `exit: N` line kept in `content` for backward
    /// compatibility. `None` (key omitted) for every non-`bash` tool and on
    /// `bash`'s spawn/timeout/cancel paths (no shell exit to report). Never
    /// enters the model's context — the dispatcher reads it solely for the
    /// timeline/export event.
    pub exit_code: Option<i32>,
    /// Optional post-run artifact payload for audit export. Tools must not put
    /// this in model-facing content; the dispatcher scrubs string fields before
    /// persisting it onto the durable event, and the exporter writes it as a
    /// sidecar file.
    pub output_sidecar: Option<ToolOutputSidecar>,
    /// True when the dispatcher abandoned the call (timeout or cancel) after
    /// handing it to the tool. Host receipt is then unknown: a verification
    /// dispatch that already entered `executing` must settle `Unknown`, not
    /// `Succeeded`.
    pub host_effect_unknown: bool,
}

/// Canonical ordered tool-result union carried through the engine. The cached
/// text projection preserves the existing text-tool ergonomics while the
/// authoritative `parts` list keeps JSON/media variants typed and exhaustive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalToolResultContents {
    parts: Vec<crate::typed_media_result::CanonicalToolResultContent>,
    text_projection: String,
}

impl CanonicalToolResultContents {
    pub fn new(
        parts: Vec<crate::typed_media_result::CanonicalToolResultContent>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(!parts.is_empty(), "tool result content must not be empty");
        for part in &parts {
            part.validate_no_inline_media()?;
        }
        let mut text_projection = String::new();
        for part in &parts {
            match part {
                crate::typed_media_result::CanonicalToolResultContent::Text { text } => {
                    text_projection.push_str(text);
                }
                crate::typed_media_result::CanonicalToolResultContent::Json { value } => {
                    text_projection.push_str(&serde_json::to_string(value)?);
                }
                crate::typed_media_result::CanonicalToolResultContent::MediaReference {
                    ..
                } => {}
            }
        }
        Ok(Self {
            parts,
            text_projection,
        })
    }

    pub fn text(value: impl Into<String>) -> Self {
        let text_projection = value.into();
        Self {
            parts: vec![crate::typed_media_result::CanonicalToolResultContent::text(
                text_projection.clone(),
            )],
            text_projection,
        }
    }

    pub fn parts(&self) -> &[crate::typed_media_result::CanonicalToolResultContent] {
        &self.parts
    }

    pub fn into_parts(self) -> Vec<crate::typed_media_result::CanonicalToolResultContent> {
        self.parts
    }

    pub fn model_text(&self) -> &str {
        &self.text_projection
    }

    /// Convert the durable text/JSON variants into Rig's typed history form.
    /// Media references require the storage-backed late resolver and are
    /// deliberately rejected here so an unresolved reference can never be
    /// reduced to prose or silently omitted before provider dispatch.
    pub fn to_rig_contents(&self) -> anyhow::Result<Vec<rig::message::ToolResultContent>> {
        self.parts
            .iter()
            .map(|part| match part {
                crate::typed_media_result::CanonicalToolResultContent::Text { text } => {
                    Ok(rig::message::ToolResultContent::text(text.clone()))
                }
                crate::typed_media_result::CanonicalToolResultContent::Json { value } => {
                    Ok(rig::message::ToolResultContent::Json {
                        value: value.clone(),
                    })
                }
                crate::typed_media_result::CanonicalToolResultContent::MediaReference {
                    ..
                } => anyhow::bail!(
                    "media_reference_unavailable: storage-backed provider mapping was not resolved"
                ),
            })
            .collect()
    }

    pub fn has_non_text_content(&self) -> bool {
        self.parts.iter().any(|part| {
            !matches!(
                part,
                crate::typed_media_result::CanonicalToolResultContent::Text { .. }
            )
        })
    }

    /// Return the model-wire form of a structured result. Text and media are
    /// not field-addressable JSON and therefore pass through unchanged; JSON
    /// parts are projected by the tool's declared result schema.
    pub fn strip_model_ephemeral_fields(&self, schema: &Value) -> anyhow::Result<Self> {
        let parts = self
            .parts
            .iter()
            .map(|part| match part {
                crate::typed_media_result::CanonicalToolResultContent::Json { value } => {
                    crate::typed_media_result::CanonicalToolResultContent::Json {
                        value: crate::engine::tool::strip_model_ephemeral_fields(value, schema),
                    }
                }
                _ => part.clone(),
            })
            .collect();
        Self::new(parts)
    }

    pub fn push_str(&mut self, value: &str) {
        self.text_projection.push_str(value);
        match self.parts.last_mut() {
            Some(crate::typed_media_result::CanonicalToolResultContent::Text { text }) => {
                text.push_str(value);
            }
            _ => self
                .parts
                .push(crate::typed_media_result::CanonicalToolResultContent::text(
                    value,
                )),
        }
    }

    pub fn push(&mut self, value: char) {
        self.text_projection.push(value);
        match self.parts.last_mut() {
            Some(crate::typed_media_result::CanonicalToolResultContent::Text { text }) => {
                text.push(value);
            }
            _ => self
                .parts
                .push(crate::typed_media_result::CanonicalToolResultContent::text(
                    value.to_string(),
                )),
        }
    }
}

impl std::ops::Deref for CanonicalToolResultContents {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.text_projection
    }
}

impl std::fmt::Display for CanonicalToolResultContents {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.text_projection)
    }
}

impl PartialEq<str> for CanonicalToolResultContents {
    fn eq(&self, other: &str) -> bool {
        self.text_projection == other
    }
}

impl PartialEq<&str> for CanonicalToolResultContents {
    fn eq(&self, other: &&str) -> bool {
        self.text_projection == *other
    }
}

impl PartialEq<String> for CanonicalToolResultContents {
    fn eq(&self, other: &String) -> bool {
        self.text_projection == *other
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextArtifactCapture {
    /// Captured post-host-boundary bytes. This is never a hash or a path.
    pub content: String,
    /// Number of bytes retained at the host capture boundary.
    pub host_captured_bytes: usize,
    /// Number of bytes the source produced before that boundary.
    pub host_original_bytes: usize,
    /// Exact number of source bytes not captured at the host boundary.
    pub host_dropped_bytes: usize,
    /// Number of post-safety bytes eligible for durable retention.  Producers
    /// set this to `content.len()`; the dispatcher refuses a capture if the
    /// result safety boundary changed the delivered body.
    pub stored_source_bytes: usize,
}

/// The projection lane that owns a retained tool body. Only model-lane
/// artifacts may replace a tool result in model history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolArtifactLane {
    Model,
    Display,
    Attachment,
}

impl ToolArtifactLane {
    pub const fn is_model_ephemeral(self) -> bool {
        !matches!(self, Self::Model)
    }
}

/// A retained tool body together with its projection lane. `explicit` means
/// the tool requested retention even below the context spill threshold.
#[derive(Debug, Clone)]
pub struct ToolTextArtifactCapture {
    pub lane: ToolArtifactLane,
    pub capture: TextArtifactCapture,
    pub explicit: bool,
}

#[derive(Debug, Clone)]
pub struct ToolOutputSidecar {
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct RepeatGuard {
    pub message: String,
}

/// `bash`-only sandbox-state record for the `tool_call` event (Part B,
/// data/export — never model-facing). Captures which of the four sandbox
/// states a `bash` call took so an exported `events.json` is diagnosable:
/// sandbox-off-granted, sandbox-off-approved, confined-success, and
/// confined-fail-to-escalate (prompted or preauthorized).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxMeta {
    /// Sandboxing was on for this session + platform supports it.
    pub enabled: bool,
    /// The first run actually ran confined.
    pub confined: bool,
    /// A confined non-zero exit triggered the permission re-run path.
    pub escalated: bool,
    /// Every simple command had a qualifying stored grant, so a trusted
    /// confined failure may rerun unconfined without raising a prompt.
    pub escalation_preauthorized: bool,
    /// The scope chosen on the escalation approval (`once`/`session`/
    /// `project`/`global`), or `None` when not escalated / denied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_scope_recorded: Option<String>,
    /// Set **only** on the sandbox-unavailable refuse path: the diagnosed
    /// reason (the same `SandboxGate::Refuse { reason }` text, including the
    /// `sudo sysctl …=0` command when diagnosed). Carries the user-facing
    /// remedy out-of-band so the engine can raise a deterministic persistent
    /// indicator (`implementation notes` §6.5). Never model-facing (token economy
    /// §10); `None` on every non-refuse path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
    /// Optional command resource profiles applied to this bash invocation.
    /// This is export/event metadata only; it explains extra allowlisted
    /// roots such as Rust toolchain homes without entering model context.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_profiles: Vec<SandboxResourceProfileMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxResourceProfileMeta {
    pub profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition_source: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_commands: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub configured_wrappers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub introspection: Vec<SandboxResourceIntrospectionMeta>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roots: Vec<SandboxResourceRootMeta>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_roots: Vec<SandboxResourceRootMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxResourceRootMeta {
    pub kind: String,
    pub path: String,
    pub access: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributing_profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxResourceIntrospectionMeta {
    pub tool: String,
    pub command: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMeta {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub declared: BTreeMap<String, u32>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub policy: BTreeMap<String, u32>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub reviewer: BTreeMap<String, u32>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub effective: BTreeMap<String, u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduler_request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduler_display_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_position: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queued_at_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acquired_at_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
    pub acquired: bool,
    pub released_on_drop: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct ContextUsageSnapshot {
    pub ctx_pct: Option<f64>,
    pub used_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub compact_nudge_pct: u8,
    pub auto_compact_pct: u8,
}

impl ContextUsageSnapshot {
    pub fn unavailable() -> Self {
        Self {
            ctx_pct: None,
            used_tokens: None,
            total_tokens: None,
            compact_nudge_pct: crate::config::providers::ContextConfig::default().compact_nudge_pct,
            auto_compact_pct: 80,
        }
    }
}

#[cfg(test)]
mod context_usage_snapshot_tests {
    use super::ContextUsageSnapshot;

    #[test]
    fn unavailable_uses_definition_policy_default() {
        let snapshot = ContextUsageSnapshot::unavailable();
        assert_eq!(snapshot.auto_compact_pct, 80);
    }
}

impl ToolOutput {
    /// Schema for the structured, timeline-only metadata every tool output may
    /// carry. Keeping this marker list beside the output shape replaces the
    /// dispatcher's former hand-maintained model-exclusion list.
    pub fn result_metadata_schema() -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "sandbox": { "x-cockpit-model-ephemeral": true },
                "resource": { "x-cockpit-model-ephemeral": true },
                "exit_code": { "x-cockpit-model-ephemeral": true },
                "output_sidecar": { "x-cockpit-model-ephemeral": true },
                "display": { "x-cockpit-model-ephemeral": true }
            }
        })
    }

    /// Durable structured metadata, retained for the timeline/export surface.
    /// Its model projection is derived at dispatch through
    /// [`Self::result_metadata_schema`]. This is intentionally distinct from
    /// a native tool's result-content schema: the two describe different JSON
    /// object namespaces, and native schemas must retain their own `$ref`
    /// root.
    pub fn result_metadata(&self) -> serde_json::Map<String, Value> {
        let mut metadata = serde_json::Map::new();
        if let Some(sandbox) = &self.sandbox
            && let Ok(value) = serde_json::to_value(sandbox)
        {
            metadata.insert("sandbox".to_string(), value);
        }
        if let Some(resource) = &self.resource
            && let Ok(value) = serde_json::to_value(resource)
        {
            metadata.insert("resource".to_string(), value);
        }
        if let Some(exit_code) = self.exit_code {
            metadata.insert("exit_code".to_string(), Value::from(exit_code));
        }
        if let Some(sidecar) = &self.output_sidecar {
            metadata.insert("output_sidecar".to_string(), sidecar.payload.clone());
        }
        if let Some(display) = &self.display_content {
            metadata.insert("display".to_string(), Value::String(display.clone()));
        }
        metadata
    }

    pub fn text(content: impl Into<String>) -> Self {
        Self {
            content: CanonicalToolResultContents::text(content),
            display_content: None,
            repeat_guard: None,
            truncated: false,
            text_artifact_capture: None,
            text_artifact_model_ephemeral: false,
            text_artifact_captures: Vec::new(),
            notices: Vec::new(),
            recovery: None,
            canonical_args: None,
            sandbox: None,
            resource: None,
            exit_code: None,
            output_sidecar: None,
            host_effect_unknown: false,
        }
    }

    pub fn truncated_text(content: impl Into<String>) -> Self {
        Self {
            content: CanonicalToolResultContents::text(content),
            display_content: None,
            repeat_guard: None,
            truncated: true,
            text_artifact_capture: None,
            text_artifact_model_ephemeral: false,
            text_artifact_captures: Vec::new(),
            notices: Vec::new(),
            recovery: None,
            canonical_args: None,
            sandbox: None,
            resource: None,
            exit_code: None,
            output_sidecar: None,
            host_effect_unknown: false,
        }
    }

    pub fn canonical(
        content: Vec<crate::typed_media_result::CanonicalToolResultContent>,
    ) -> anyhow::Result<Self> {
        let mut output = Self::text("");
        output.content = CanonicalToolResultContents::new(content)?;
        Ok(output)
    }

    /// Mark this output as an abandoned timeout/cancel. Verification
    /// settlement must not treat it as a proven host receipt.
    pub fn with_unknown_host_effect(mut self) -> Self {
        self.host_effect_unknown = true;
        self
    }

    pub fn with_text_artifact_capture(mut self, capture: TextArtifactCapture) -> Self {
        self.text_artifact_capture = Some(capture);
        self
    }

    pub fn with_model_ephemeral_text_artifact_capture(
        mut self,
        capture: TextArtifactCapture,
    ) -> Self {
        self.text_artifact_capture = Some(capture);
        self.text_artifact_model_ephemeral = true;
        self
    }

    pub fn with_text_artifact_lane(
        mut self,
        lane: ToolArtifactLane,
        capture: TextArtifactCapture,
        explicit: bool,
    ) -> Self {
        self.text_artifact_captures.push(ToolTextArtifactCapture {
            lane,
            capture,
            explicit,
        });
        self
    }

    pub fn with_notices(mut self, notices: Vec<String>) -> Self {
        self.notices = notices;
        self
    }

    /// Supply the timeline/UI projection while retaining `content` as the
    /// only model-facing result.
    pub fn with_model_ephemeral_display(mut self, display: impl Into<String>) -> Self {
        self.display_content = Some(display.into());
        self
    }

    /// Attach `bash` sandbox-state metadata for the `tool_call` event
    /// (Part B). Only `bash` calls this; the content is unchanged.
    pub fn with_sandbox(mut self, sandbox: SandboxMeta) -> Self {
        self.sandbox = Some(sandbox);
        self
    }

    pub fn with_resource(mut self, resource: ResourceMeta) -> Self {
        self.resource = Some(resource);
        self
    }

    pub fn with_bash_meta(self, sandbox: SandboxMeta, resource: &Option<ResourceMeta>) -> Self {
        let out = self.with_sandbox(sandbox);
        match resource {
            Some(resource) => out.with_resource(resource.clone()),
            None => out,
        }
    }

    /// Attach the `bash` process exit code for the `tool_call` event's
    /// authoritative `exit_code` field (export-audit fidelity). Only `bash`
    /// calls this, and only on a run that produced a shell exit; the content
    /// is unchanged.
    pub fn with_exit_code(mut self, code: i32) -> Self {
        self.exit_code = Some(code);
        self
    }

    pub fn with_output_sidecar(mut self, sidecar: ToolOutputSidecar) -> Self {
        self.output_sidecar = Some(sidecar);
        self
    }

    pub fn with_repeat_guard(mut self, message: impl Into<String>) -> Self {
        self.repeat_guard = Some(RepeatGuard {
            message: message.into(),
        });
        self
    }

    /// Attach a recovery annotation and the canonical arg form. See the
    /// struct docs for the contract.
    pub fn with_recovery(
        mut self,
        recovery: crate::db::tool_calls::Recovery,
        canonical_args: serde_json::Value,
    ) -> Self {
        self.recovery = Some(recovery);
        self.canonical_args = Some(canonical_args);
        self
    }
}

/// State threaded into every tool call.
///
/// Holding `Arc`s here lets the crate-private dispatcher create explicitly
/// named dispatch clones without copying manager/session contents. The type
/// intentionally does not implement `Clone`: downstream tools receive only a
/// borrow and may retain the data-only [`ToolCtxView`] projection.
pub struct ToolCtx {
    pub(crate) agent_id: String,
    /// Local knowledge bases this concrete agent definition may access. `None`
    /// inherits the workspace registry; an empty set permits none.
    pub(crate) allowed_knowledge_bases: Option<std::collections::BTreeSet<String>>,
    /// History-read trust of the concrete tool frame. This is carried from the
    /// agent frame rather than inferred from the session's active model;
    /// delegated frames remain untrusted even when a host-selected fallback
    /// model is trusted, because their custody is redacted-untrusted.
    pub(crate) executing_model_trusted: bool,
    /// Provider/model trust for KB access. This intentionally remains distinct
    /// from `executing_model_trusted`: a delegated model may receive redacted
    /// history while still being explicitly trusted for a local KB.
    pub(crate) knowledge_access_trusted: bool,
    /// Exact provider/model identity of the agent that issued this tool call.
    ///
    /// This is intentionally dispatch-scoped rather than derived from the
    /// session's active-model preference: delegated and custom agents may run
    /// a different model. `None` is reserved for isolated/headless contexts
    /// and must be handled as untrusted by custody-sensitive tools.
    pub(crate) caller_model: Option<CallerModel>,
    /// Stable daemon-owned lifecycle identity for this concrete executor.
    /// `None` is reserved for isolated tests and legacy headless helpers;
    /// production driver frames always carry a durable instance id.
    pub(crate) agent_instance_id: Option<uuid::Uuid>,
    /// Lock-manager identity for this concrete agent instance. Defaults to
    /// `agent_id`; parallel same-named task children use distinct identities
    /// such as `builder#a` so they cannot self-own each other's locks.
    pub(crate) lock_identity: String,
    /// Optional subtree that write-capable native tools and shell sandboxes must
    /// confine writes to. Reads remain governed by the session boundary.
    pub(crate) write_scope: Option<std::path::PathBuf>,
    /// Knowledge-dream consent scope established by `knowledge_dream_sources`.
    /// When present, cross-session readers must only read these attached source
    /// sessions, and sibling/global short-id lookup is disabled.
    pub(crate) dream_read_scope:
        Arc<std::sync::RwLock<Option<std::collections::BTreeSet<uuid::Uuid>>>>,
    /// Host-issued workspace lease for this child. Path checks, the shell
    /// sandbox, and computer-use gating honor its visibility root and ops.
    pub(crate) workspace_lease: Option<std::sync::Arc<crate::workspace_lease::WorkspaceLease>>,
    /// Current outer model tool-call id, when this context was built for a
    /// live model-issued tool dispatch. Host-side tools can use it to parent
    /// synthetic UI/telemetry events without exposing the id to tool schemas or
    /// model-visible arguments. `bash` may echo it in sandbox failure text so
    /// the model can call `escalate` with the required id.
    pub(crate) current_tool_call_id: Option<String>,
    /// Daemon-owned scope for the concrete tool-call attempt. It names the
    /// driver-generated inference call and attempt ordinal, so provider call
    /// IDs may be used for retry correlation without becoming durable
    /// operation identities.
    pub(crate) current_tool_call_scope: Option<String>,
    /// The tool-description steering of the calling agent (issue #75). Read
    /// by tools that vary *behavior* (not just description prose) on the
    /// verbose/terse axis — today only `bash`, which appends a
    /// verbose-steering-only file/search routing nudge to its result body
    /// (implementation note). Mirrors `agent.tool_steering` at the dispatch
    /// site; `Terse` in test/headless contexts so the nudge is silent there.
    pub(crate) tool_steering: crate::agents::ToolSteering,
    pub(crate) locks: Arc<crate::locks::LockManager>,
    pub(crate) session: Arc<crate::session::Session>,
    pub(crate) cwd: std::path::PathBuf,
    /// Session-scoped, turn-pinned config reader. The single access path to
    /// resolved config for turn-scoped tools — tools read `config.extended()`
    /// / `config.providers()` instead of re-loading config from disk, so they
    /// observe the same generationed snapshot (and turn-boundary semantics) as
    /// the rest of the turn (`engine-config-snapshot-adoption`).
    pub(crate) config: crate::daemon::session_worker::SessionConfigHandle,
    /// The redaction chokepoint (GOALS §7). Tools that return strings
    /// destined for the model context don't have to call this
    /// themselves — `engine::agent::turn` scrubs every tool result
    /// before it lands in history. Threaded here too for tools that
    /// want to scrub *before* a long output is even allocated (e.g.
    /// `bash` capping output and only scrubbing what fits).
    pub(crate) redact: Arc<crate::redact::RedactionTable>,
    /// Per-session environment overlay from attached clients. Spawned tools
    /// merge this explicitly instead of mutating process-global env.
    pub(crate) env_overlay: Arc<std::sync::RwLock<std::collections::HashMap<String, String>>>,
    /// Interrupt wakeup hub (GOALS §3b). Structural tools that block on
    /// a human answer — today only `question` — raise an interrupt
    /// through this and await the resolution that arrives, out of band,
    /// on the daemon worker's `ResolveInterrupt` path. Threaded as an
    /// `Arc` so the same hub instance is shared with the worker.
    pub(crate) interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    /// Per-turn cancellation token (user ctrl+c → `CancelTurn`). Long-
    /// running tools — today `bash` — race their subprocess against
    /// `cancel.cancelled()` and kill it (process group on Unix) when the
    /// user aborts the turn, so a runaway test run dies promptly instead
    /// of holding the turn open. Fresh per turn; cancelling it never
    /// affects a later turn.
    pub(crate) cancel: tokio_util::sync::CancellationToken,
    /// Daemon shutdown gate shared by the active model for this turn. Utility
    /// models built inside tools (for example harness-result summarization)
    /// install it so background utility calls are abandoned during drain.
    pub(crate) shutdown_gate: crate::daemon::shutdown::ShutdownSignal,
    /// Command/path approval driver (sandboxing part 2). The `bash` tool
    /// consults it for the run-fail-escalate flow (broadened re-run on a
    /// non-zero sandboxed exit), and the native file/intel tools consult
    /// it via [`crate::tools::sandbox::check_native_access`] to escalate
    /// an out-of-boundary path access. `None` on paths with no client
    /// fan-out (tool tests/headless): a missing approver
    /// skips the prompt — it never silently denies. Shared `Arc` so one
    /// approver instance backs the whole delegation tree.
    pub(crate) approver: Option<Arc<crate::approval::Approver>>,
    /// Session-scoped image-generation dispatch funnel. The `generate_image`
    /// tool routes an authorized request through this to the central
    /// [`crate::approval::Approver`] chokepoint and, on `Allow`, a durable
    /// queued job. `None` until the daemon wires it with the runtime registry +
    /// owner context (lands with the upstream adapter-map reconciliation); a
    /// missing funnel makes the tool report that dispatch is unavailable in this
    /// session rather than fabricating an outcome.
    pub(crate) image_generation_dispatch:
        Option<std::sync::Arc<crate::image_generation_job::ImageGenerationDispatchService>>,
    /// Session-scoped audio-transcription dispatch: journal plus a provider
    /// route composed from one turn-pinned resolution. A missing service also
    /// removes `transcribe_audio` from the advertised toolbox.
    pub(crate) transcription_dispatch:
        Option<std::sync::Arc<crate::audio_transcription::journal::TranscriptionDispatchService>>,
    /// The current frame's deferred-log buffer (`plan.md §3d`). A subagent's
    /// `defer_to_orchestrator` tool appends out-of-scope asks here; the
    /// driver drains it when the frame pops and folds it into the report the
    /// parent ingests. `Default` (empty) for the root frame and for contexts
    /// with no subagent (tests/headless) — defer there is a no-op
    /// drain nobody reads.
    pub(crate) deferred_log: crate::engine::deferred::DeferredLog,
    /// Whether this tool call belongs to the foreground root frame. Driver-level
    /// controls such as agent-requested compaction are only valid there.
    pub(crate) root_agent_frame: bool,
    /// Trusted provenance for skill mutations. Ordinary foreground and test
    /// calls default to `Foreground`; the isolated self-improvement reviewer
    /// overrides this on its frame without exposing the field to model args.
    pub(crate) skill_write_origin: crate::skills::manage::SkillWriteOrigin,
    /// Optional dispatch/read-before-write cage for background self-improvement
    /// review. Foreground turns leave this unset.
    pub(crate) review_cage: Option<ReviewCage>,
    /// Turn-start context-pressure snapshot for model-facing introspection.
    pub(crate) context_usage: Option<ContextUsageSnapshot>,
    /// Exact tool names advertised to the calling agent for this turn. Skill
    /// package activation uses this session-local surface for Hermes
    /// `requires_tools` / `fallback_for_tools` gates.
    pub(crate) available_tools: Arc<std::collections::HashSet<String>>,
    /// Frozen Monty builtin registry for this agent/tool context. It contains
    /// the host control functions plus native tools made scriptable for the
    /// session's tool tier placement.
    pub(crate) mcp_builtin_registry: Arc<crate::mcp::builtin::BuiltinRegistry>,
    /// Whether the calling agent holds the `code` tool. Lets a tool steer a
    /// recovery hint to the caller's actual surface (e.g. `read` on a
    /// directory suggests code/tree only when the agent can use it) rather than
    /// name-guessing capabilities. Populated from the agent's `ToolBox` at the
    /// live dispatch site; `false` in test/headless contexts with no toolbox.
    pub(crate) has_tree: bool,
    /// Whether the calling agent holds the `bash` tool. The `bash` fallback for
    /// the same surface-aware recovery hints (used when `code` is absent).
    pub(crate) has_bash: bool,
    /// The per-turn event stream (`engine::agent::TurnEvent`), so a tool that
    /// blocks can surface a transient client indicator without inventing a
    /// second broadcast authority — it routes through the same seam the turn
    /// loop uses (implementation note). Today only
    /// `read` uses it, to emit the `WaitingForLock` start/clear pair while
    /// blocked on a contended lock. `None` in test/headless
    /// contexts with no client fan-out — emitting is then a silent no-op.
    pub(crate) events: Option<tokio::sync::mpsc::Sender<crate::engine::agent::TurnEvent>>,
    /// Daemon-owned LSP manager. `None` in tests/replay contexts; LSP is
    /// advisory, so tools skip diagnostics/navigation when absent.
    pub(crate) lsp: Option<Arc<crate::daemon::lsp::LspManager>>,
    /// Daemon-owned resource scheduler for runtime permit acquisition. `None`
    /// for tests/replay paths and ephemeral daemons that opt out of the shared
    /// machine/user queue.
    #[allow(dead_code)]
    pub(crate) resource_scheduler:
        Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    /// Server-private media authority for direct-native media tools.
    /// `None` in stripped/MCP/Monty/catalog contexts and tests; set only by
    /// the daemon/session-worker production composition on the direct-native
    /// dispatch path. `HostContext::from_tool_ctx` creates a structurally
    /// stripped clone with this field set to `None`, so MCP/Monty/external-MCP
    /// paths never inherit media authority. Media tools fail closed when this
    /// is `None`.
    pub(crate) media_authority: Option<Arc<crate::tool_media_authority::SessionMediaAuthority>>,
    /// Data-free media tool availability snapshot, created from the live
    /// authority before `ToolCtx` via `SpawnArgs`. Carries no principal,
    /// source, attachment, grant, or bypass data. Controls whether
    /// direct-native media tools are registered on the toolbox at all.
    pub(crate) media_availability: crate::tool_media_authority::MediaToolAvailability,
    /// Source-tagged MCP catalog for this agent. Built once per agent
    /// construction (or test `ToolCtx`) and passed read-only to every
    /// descendant context. Tool dispatch must not call
    /// [`crate::mcp::config::McpConfig::discover`] or re-read catalog files.
    pub(crate) mcp_resolver: Arc<crate::mcp::resolver::EffectiveCatalogResolver>,
}

/// Data-only snapshot available to downstream native tools.
///
/// It is intentionally cloneable and contains no session, lock, approval,
/// event, secret, registry, or media authority handles. `ToolCtx` itself is
/// non-`Clone` and has no public fields, so an external tool cannot retain the
/// capability-bearing dispatch context beyond the borrow used for its call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCtxView {
    pub agent_id: String,
    pub agent_instance_id: Option<uuid::Uuid>,
    pub cwd: std::path::PathBuf,
    pub tool_steering: crate::agents::ToolSteering,
    pub root_agent_frame: bool,
    pub available_tools: std::collections::HashSet<String>,
}

impl ToolCtx {
    /// Return the structurally stripped public snapshot. This is the only
    /// cloneable projection exposed outside `cockpit-core`.
    pub fn view(&self) -> ToolCtxView {
        ToolCtxView {
            agent_id: self.agent_id.clone(),
            agent_instance_id: self.agent_instance_id,
            cwd: self.cwd.clone(),
            tool_steering: self.tool_steering,
            root_agent_frame: self.root_agent_frame,
            available_tools: self.available_tools.as_ref().clone(),
        }
    }

    /// Internal dispatch clone. Kept as a crate-private named operation so
    /// downstream `Tool` implementations cannot retain the media capability.
    pub(crate) fn clone_for_dispatch(&self) -> Self {
        Self {
            agent_id: self.agent_id.clone(),
            allowed_knowledge_bases: self.allowed_knowledge_bases.clone(),
            executing_model_trusted: self.executing_model_trusted,
            knowledge_access_trusted: self.knowledge_access_trusted,
            caller_model: self.caller_model.clone(),
            agent_instance_id: self.agent_instance_id,
            lock_identity: self.lock_identity.clone(),
            write_scope: self.write_scope.clone(),
            dream_read_scope: self.dream_read_scope.clone(),
            workspace_lease: self.workspace_lease.clone(),
            current_tool_call_id: self.current_tool_call_id.clone(),
            current_tool_call_scope: self.current_tool_call_scope.clone(),
            tool_steering: self.tool_steering,
            locks: self.locks.clone(),
            session: self.session.clone(),
            cwd: self.cwd.clone(),
            config: self.config.clone(),
            redact: self.redact.clone(),
            env_overlay: self.env_overlay.clone(),
            interrupts: self.interrupts.clone(),
            cancel: self.cancel.clone(),
            shutdown_gate: self.shutdown_gate.clone(),
            approver: self.approver.clone(),
            image_generation_dispatch: self.image_generation_dispatch.clone(),
            transcription_dispatch: self.transcription_dispatch.clone(),
            deferred_log: self.deferred_log.clone(),
            root_agent_frame: self.root_agent_frame,
            skill_write_origin: self.skill_write_origin,
            review_cage: self.review_cage.clone(),
            context_usage: self.context_usage,
            available_tools: self.available_tools.clone(),
            mcp_builtin_registry: self.mcp_builtin_registry.clone(),
            has_tree: self.has_tree,
            has_bash: self.has_bash,
            events: self.events.clone(),
            lsp: self.lsp.clone(),
            resource_scheduler: self.resource_scheduler.clone(),
            media_authority: self.media_authority.clone(),
            media_availability: self.media_availability,
            mcp_resolver: self.mcp_resolver.clone(),
        }
    }

    /// Access the server-private media authority. Returns `None` in
    /// stripped/MCP/Monty contexts — media tools fail closed.
    pub(crate) fn media_authority(
        &self,
    ) -> Option<&crate::tool_media_authority::SessionMediaAuthority> {
        self.media_authority.as_deref()
    }

    /// Attach a media authority to this context. Production-only; the
    /// daemon/session-worker composition calls this on the direct-native
    /// dispatch path. Test-only constructors may use fakes.
    pub(crate) fn with_media_authority(
        mut self,
        authority: Arc<crate::tool_media_authority::SessionMediaAuthority>,
    ) -> Self {
        self.media_authority = Some(authority);
        self
    }

    /// Create a structurally stripped clone — media authority removed.
    /// This is what `HostContext::from_tool_ctx` uses so MCP/Monty/catalog
    /// paths never inherit media authority.
    pub(crate) fn clone_stripped(&self) -> Self {
        let available_tools = self
            .available_tools
            .iter()
            .filter(|name| {
                !crate::tool_media_authority::availability::MEDIA_TOOL_NAMES
                    .contains(&name.as_str())
            })
            .cloned()
            .collect();
        let mut stripped = self.clone_for_dispatch();
        stripped.media_authority = None;
        stripped.transcription_dispatch = None;
        stripped.media_availability =
            crate::tool_media_authority::MediaToolAvailability::unavailable();
        stripped.available_tools = Arc::new(available_tools);
        stripped
    }

    /// Revalidate durable workspace authority at an effect boundary.  The
    /// typed lease in a tool context is a confinement snapshot, never a
    /// durable authorization cache; ephemeral same-root/subdirectory tokens
    /// intentionally remain preflight/test-only and have no ledger row.
    pub async fn revalidate_workspace_lease_effect_boundary(&self) -> Result<()> {
        if let Some(lease) = self.workspace_lease.as_deref() {
            lease.revalidate_for_tools(&self.session.db).await?;
        }
        Ok(())
    }

    /// Clone this context for Stage 7 private investigation tool calls.
    ///
    /// Investigation reuses the author's sandbox, cwd, redaction, and
    /// cancellation, but snapshot reads must not write the author's §3c
    /// lock-read identity. Decision 4: the lock tracker is a freshness
    /// gate, not a log of who observed the file.
    pub fn for_private_investigation(&self) -> Self {
        let mut cloned = self.clone_for_dispatch();
        cloned.locks = Arc::new(self.locks.without_read_recording());
        cloned
    }
}

/// Non-secret identity of the model that issued a tool call.
///
/// `ToolCtx` carries this small value instead of a model handle so tools can
/// apply their own turn-pinned policy without retaining inference capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallerModel {
    provider_id: String,
    model_id: String,
}

impl CallerModel {
    pub(crate) fn new(provider_id: impl Into<String>, model_id: impl Into<String>) -> Self {
        Self {
            provider_id: provider_id.into(),
            model_id: model_id.into(),
        }
    }

    pub(crate) fn from_model(model: &crate::engine::model::Model) -> Self {
        Self::new(model.provider_id(), model.model_id_ref())
    }

    pub(crate) fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub(crate) fn model_id(&self) -> &str {
        &self.model_id
    }
}

/// A per-agent description override for a single tool, carried on the
/// [`ToolBox`] alongside the tool itself. The **same tool ID and the same
/// SCHEMA** are shared across every agent — only the *description text* is
/// selected per agent + per tool-description steering. This is the per-agent
/// axis that composes onto the steering axis applied in [`definition_of`]:
/// the override's text, when present for the active steering, *replaces* the
/// description the steering logic would otherwise render; the parameters are
/// never touched (schema variation would change validation/repair behavior —
/// project guidance design rule). Authored both by the built-in factories (via
/// [`ToolBox::with_override`]) and by markdown agent defs (their
/// `tool_descriptions:` frontmatter).
///
/// Each field is `None` by default → fall through to the tool's own base
/// (steering-selected) description, so an agent with no override behaves
/// byte-identically to today. Per the token-economy budget (§10) each
/// override stays one terse sentence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolDescOverride {
    /// The canonical (terse) description text, applied under
    /// [`crate::agents::ToolSteering::Terse`]. `None` → keep the tool's terse
    /// [`Tool::description`].
    pub text: Option<String>,
    /// The verbose description text, applied under
    /// [`crate::agents::ToolSteering::Verbose`]. `None` → keep the tool's
    /// [`Tool::verbose_description`] (or its terse fallback).
    pub verbose_text: Option<String>,
}

impl ToolDescOverride {
    /// The override text selected for `steering`, if this override supplies
    /// one.
    fn text_for(&self, steering: crate::agents::ToolSteering) -> Option<&str> {
        match steering {
            crate::agents::ToolSteering::Terse => self.text.as_deref(),
            crate::agents::ToolSteering::Verbose => self.verbose_text.as_deref(),
        }
    }

    /// True when neither steering carries an override — a no-op override that
    /// the builder can drop so the `ToolBox`'s serialized form stays
    /// byte-stable (an empty override is indistinguishable from no override).
    fn is_empty(&self) -> bool {
        self.text.is_none() && self.verbose_text.is_none()
    }
}

/// Project the `Tool` trait into a `ToolDefinition` rig understands.
///
/// This is the **single** place both description axes are applied. First the
/// `toolSteering` description-verbosity axis (issue #75): under
/// [`crate::agents::ToolSteering::Verbose`] we render each tool's
/// [`Tool::verbose_description`] / [`Tool::verbose_parameters`] when present,
/// falling back to the terse [`Tool::description`] / [`Tool::parameters`]
/// otherwise; under [`crate::agents::ToolSteering::Terse`] we always render
/// the terse form. Then the **per-agent** axis composes on top: when
/// `desc_override` supplies text for the active steering, it *replaces* the
/// description chosen above — the parameters (schema) are never overridden,
/// so the tool's ID and SCHEMA stay uniform across every agent. Both switches
/// live here and nowhere else — no per-tool conditionals at call sites.
pub fn definition_of(
    tool: &dyn Tool,
    steering: crate::agents::ToolSteering,
    desc_override: Option<&ToolDescOverride>,
) -> ToolDefinition {
    let (base_description, parameters) = match steering {
        crate::agents::ToolSteering::Verbose => (
            tool.verbose_description()
                .unwrap_or_else(|| tool.description().to_string()),
            tool.verbose_parameters()
                .unwrap_or_else(|| tool.parameters()),
        ),
        crate::agents::ToolSteering::Terse => (tool.description().to_string(), tool.parameters()),
    };
    // Per-agent axis: an override for the active steering wins over the base
    // description. Schema is intentionally untouched.
    let description = desc_override
        .and_then(|o| o.text_for(steering))
        .map(str::to_string)
        .unwrap_or(base_description);
    ToolDefinition {
        name: tool.name().to_string(),
        description,
        parameters,
    }
}

/// Behavioral capabilities gated on the agent-definition grant set.
///
/// [`definition_of`] above is the *description-verbosity* seam — it changes
/// how a tool's schema reads, never what the engine will accept. This is the
/// separate **behavioral** seam: a real capability check the engine consults
/// before *acting*, so a def can disable a feature outright rather than just
/// rewording its prose. [`Capability::enabled`] is the single predicate; the
/// engine calls it at the point of action (e.g. before minting a re-query
/// handle or honoring a `resume_handle`/`seed`), so a disabled capability is
/// rejected/inert regardless of what the model asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Re-queryable read-only noninteractive subagents + seeded tool calls
    /// (GOALS §3c): the follow-up handle, `resume_handle` rehydration, and
    /// `seed` injection. Available only to agent defs that grant it.
    FollowupSeed,
    /// Explicit sandbox escalation reruns. Available only to agent defs that
    /// grant it; the conservative `Careful`/`standard` posture gets the
    /// separate human-offer path instead.
    SandboxEscalate,
    /// Forking the delegating agent's transcript into a noninteractive child.
    /// Available only to agent defs that grant it.
    ForkContext,
    /// Parallel write-capable task fan-out in one worktree with hard scoped
    /// write confinement. Available only to agent defs that grant it.
    ScopedParallelWrite,
}

impl Capability {
    /// Whether this capability is available under `posture` (issue #75):
    /// membership in the agent def's resolved grant set decides. Disabled
    /// capabilities are gated at the engine's point of action, not merely
    /// hidden in description text.
    pub fn enabled(self, posture: &crate::agents::PostureResolution) -> bool {
        posture.capability_enabled(self)
    }
}

impl From<Capability> for crate::agents::AgentCapability {
    fn from(cap: Capability) -> Self {
        match cap {
            Capability::FollowupSeed => Self::FollowupSeed,
            Capability::SandboxEscalate => Self::SandboxEscalate,
            Capability::ForkContext => Self::ForkContext,
            Capability::ScopedParallelWrite => Self::ScopedParallelWrite,
        }
    }
}

/// Registry of tools available to an agent. Keyed by name for O(log n)
/// dispatch. Use [`ToolBox::with`] to add tools.
///
/// Alongside the tools, the box carries an optional **per-agent description
/// override** per tool name ([`ToolDescOverride`]), applied at
/// [`Self::definitions`] time. The override changes only the rendered
/// *description text* — never the tool's ID or SCHEMA — so the same tool can
/// encode different per-agent intent (e.g. `Build` "delegate-eager" vs a
/// "do-it-yourself" agent) while validation/repair stay uniform. Overrides are
/// fixed at agent-construction time, so the serialized tools array stays
/// byte-stable for a given `(agent, steering)` → prompt-cache hit preserved; this
/// adds **no** new mid-session mutation.
#[derive(Default, Clone)]
pub struct ToolBox {
    tools: BTreeMap<String, Arc<dyn Tool>>,
    /// Exact direct-native media tools selected by the agent definition but
    /// currently withheld by root authority, host runtime, or model capability.
    /// They are not returned by `names`, `get`, definitions, MCP, or Monty;
    /// the turn boundary moves them into `tools` only after revalidation.
    dormant_direct_native_media: BTreeMap<String, Arc<dyn Tool>>,
    /// The call-time reason a provider-visible direct-native media tool is
    /// dormant. This deliberately travels separately from its schema: a
    /// runtime/model/dispatch change must not perturb the cacheable tools
    /// prefix, but must still give a model call the actual diagnosis.
    direct_native_media_unavailable: BTreeMap<String, DirectNativeMediaUnavailable>,
    mcp_builtin_tools: BTreeMap<String, McpBuiltinToolEntry>,
    /// Per-tool-name description overrides. Empty (the default) means every
    /// tool renders its own steering-selected description — byte-identical to the
    /// pre-override behavior.
    overrides: BTreeMap<String, ToolDescOverride>,
    /// Rendered tool schemas for this finalized toolbox, keyed by steering.
    /// Builder-style mutations clear it so per-agent overrides stay exact.
    definition_cache: Arc<Mutex<HashMap<crate::agents::ToolSteering, Vec<ToolDefinition>>>>,
    capability_unavailable: BTreeMap<String, Vec<crate::capabilities::ToolCapabilityIssue>>,
    capability_description_suffixes: BTreeMap<String, Vec<String>>,
}

/// Whether a provider-advertised tool can be called in the current turn.
///
/// Provider schemas deliberately remain stable while capability probes and
/// direct-native media authority change.  Callers must therefore distinguish a
/// provider-visible but unavailable tool from a name the provider was never
/// told about; the latter is a hallucinated tool call, while the former gets a
/// normal call-time availability result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolCallAvailability {
    Callable,
    AdvertisedUnavailable,
    NotAdvertised,
}

/// Why a direct-native media schema is advertised but cannot be called in the
/// current turn. Kept private because callers need the rendered call result,
/// not another availability policy surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectNativeMediaUnavailable {
    AuthorityUnavailable,
    Availability(crate::tool_media_authority::MediaToolAvailabilityReason),
    TranscriptionDispatchUnavailable,
    TranscriptionAuthenticationFailed,
}

impl DirectNativeMediaUnavailable {
    fn message(self) -> &'static str {
        match self {
            Self::AuthorityUnavailable => "this session has no live media authority",
            Self::Availability(
                crate::tool_media_authority::MediaToolAvailabilityReason::AuthorityUnavailable,
            ) => "this session has no live media authority",
            Self::Availability(
                crate::tool_media_authority::MediaToolAvailabilityReason::RuntimeProfileUnsupported,
            ) => "the host media runtime does not support this operation",
            Self::Availability(
                crate::tool_media_authority::MediaToolAvailabilityReason::ModelCapabilityRequiresEntitlement,
            ) => "the current model requires an entitlement for this media capability",
            Self::Availability(
                crate::tool_media_authority::MediaToolAvailabilityReason::ModelCapabilityUnsupported,
            ) => "the current model does not support this media capability",
            Self::Availability(
                crate::tool_media_authority::MediaToolAvailabilityReason::ModelCapabilityUnknown,
            ) => "the current model's media capability is unknown",
            // `Present` cannot make a direct-native tool dormant. Keep the
            // fallback accurate if a future media tool adds a divergent gate.
            Self::Availability(
                crate::tool_media_authority::MediaToolAvailabilityReason::Present,
            ) => "it is not callable in this turn",
            Self::TranscriptionDispatchUnavailable => {
                "no authorized transcription dispatch is available for this session and current model"
            }
            Self::TranscriptionAuthenticationFailed => {
                "provider authentication failed while preparing transcription"
            }
        }
    }
}

#[derive(Clone)]
struct McpBuiltinToolEntry {
    tool: Arc<dyn Tool>,
    directly_callable: bool,
}

pub(crate) fn is_monty_builtin_adaptable(name: &str) -> bool {
    crate::agents::is_monty_builtin_adaptable(name)
}

impl ToolBox {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, tool: Arc<dyn Tool>) -> Self {
        let name = tool.name().to_string();
        if is_monty_builtin_adaptable(&name) {
            self.mcp_builtin_tools.insert(
                name.clone(),
                McpBuiltinToolEntry {
                    tool: tool.clone(),
                    directly_callable: true,
                },
            );
        }
        self.tools.insert(name.clone(), tool);
        self.direct_native_media_unavailable.remove(&name);
        self.capability_unavailable.remove(&name);
        self.capability_description_suffixes.remove(&name);
        self.definition_cache.lock().unwrap().clear();
        self
    }

    pub(crate) fn with_dormant_direct_native_media(mut self, tool: Arc<dyn Tool>) -> Self {
        let name = tool.name().to_string();
        debug_assert!(
            crate::tool_media_authority::availability::MEDIA_TOOL_NAMES.contains(&name.as_str())
        );
        self.dormant_direct_native_media.insert(name.clone(), tool);
        self.direct_native_media_unavailable
            .insert(name, DirectNativeMediaUnavailable::AuthorityUnavailable);
        self
    }

    pub(crate) fn activate_dormant_direct_native_media(
        mut self,
        availability: crate::tool_media_authority::MediaToolAvailability,
    ) -> Self {
        let dormant = std::mem::take(&mut self.dormant_direct_native_media);
        for (name, tool) in dormant {
            if availability.exposes_direct_tool(&name) {
                self.direct_native_media_unavailable.remove(&name);
                self.tools.insert(name, tool);
            } else {
                // Retain the schema-only dormant entry so a partial live
                // authority changes callability, never the cacheable tools
                // prefix advertised to the provider.
                self.direct_native_media_unavailable.insert(
                    name.clone(),
                    DirectNativeMediaUnavailable::Availability(availability.reason_for(&name)),
                );
                self.dormant_direct_native_media.insert(name, tool);
            }
        }
        self.definition_cache.lock().unwrap().clear();
        self
    }

    /// Whether this exact per-agent surface contains at least one
    /// direct-native media tool. This is the materialization proof used when
    /// deciding whether a `ToolCtx` may receive the private authority; a
    /// session-global authority alone is never sufficient.
    pub(crate) fn has_direct_native_media(&self) -> bool {
        self.tools.keys().any(|name| {
            crate::tool_media_authority::availability::MEDIA_TOOL_NAMES.contains(&name.as_str())
        })
    }

    /// Move a direct-native media tool out of the callable surface while
    /// retaining its schema in the stable provider projection.
    fn deactivate_direct_native_media(
        mut self,
        name: &str,
        reason: DirectNativeMediaUnavailable,
    ) -> Self {
        debug_assert!(crate::tool_media_authority::availability::MEDIA_TOOL_NAMES.contains(&name));
        if let Some(tool) = self.tools.remove(name) {
            self.dormant_direct_native_media
                .insert(name.to_string(), tool);
            self.definition_cache.lock().unwrap().clear();
        }
        if self.dormant_direct_native_media.contains_key(name) {
            self.direct_native_media_unavailable
                .insert(name.to_string(), reason);
        }
        self
    }

    /// Keep transcription's stable schema while returning the dispatch failure
    /// that actually made this turn non-callable.
    pub(crate) fn deactivate_direct_native_media_for_transcription_dispatch(self) -> Self {
        self.deactivate_direct_native_media(
            "transcribe_audio",
            DirectNativeMediaUnavailable::TranscriptionDispatchUnavailable,
        )
    }

    /// Keep transcription's stable schema while surfacing a failed provider
    /// auth command as authentication failure at the model-visible call site.
    pub(crate) fn deactivate_direct_native_media_for_transcription_authentication(self) -> Self {
        self.deactivate_direct_native_media(
            "transcribe_audio",
            DirectNativeMediaUnavailable::TranscriptionAuthenticationFailed,
        )
    }

    /// Deactivate every direct-native media tool for a turn without deleting
    /// the stable provider schema selected for this agent.
    pub(crate) fn deactivate_direct_native_media_tools(mut self) -> Self {
        for &name in crate::tool_media_authority::availability::MEDIA_TOOL_NAMES {
            self = self.deactivate_direct_native_media(
                name,
                DirectNativeMediaUnavailable::AuthorityUnavailable,
            );
        }
        self
    }

    /// Permanently strip direct-native media from a background clone.
    pub(crate) fn without_direct_native_media(mut self) -> Self {
        for name in crate::tool_media_authority::availability::MEDIA_TOOL_NAMES {
            self = self.without(name);
        }
        self
    }

    pub fn without(mut self, name: &str) -> Self {
        self.tools.remove(name);
        self.dormant_direct_native_media.remove(name);
        self.direct_native_media_unavailable.remove(name);
        self.mcp_builtin_tools.remove(name);
        self.overrides.remove(name);
        self.capability_unavailable.remove(name);
        self.capability_description_suffixes.remove(name);
        self.definition_cache.lock().unwrap().clear();
        self
    }

    /// Keep only built-in operations whose declared effect is read-only.
    ///
    /// This is a capability boundary, not a scheduling hint: an unregistered
    /// or user-authored tool is excluded even when it claims `ReadOnly`, since
    /// a custom shell template can make that claim while executing arbitrary
    /// code. Callers that need a constrained non-read-only escape hatch must
    /// add that tool back explicitly and own its effect accounting.
    pub(crate) fn registered_read_only_operations(mut self) -> Self {
        let is_safe = |tool: &Arc<dyn Tool>| {
            tool.is_registered_ordinary_operation() && tool.effect() == ToolEffect::ReadOnly
        };
        self.tools.retain(|_, tool| is_safe(tool));
        self.dormant_direct_native_media
            .retain(|_, tool| is_safe(tool));
        self.mcp_builtin_tools
            .retain(|_, entry| is_safe(&entry.tool));
        self.overrides
            .retain(|name, _| self.tools.contains_key(name));
        self.capability_unavailable
            .retain(|name, _| self.tools.contains_key(name));
        self.capability_description_suffixes
            .retain(|name, _| self.tools.contains_key(name));
        self.direct_native_media_unavailable
            .retain(|name, _| self.dormant_direct_native_media.contains_key(name));
        self.definition_cache.lock().unwrap().clear();
        self
    }

    /// Wrap every non-read-only callable operation on this toolbox.
    ///
    /// Background fork callers use this to retain the parent capability
    /// surface while making every possible effect cross their own durable
    /// accounting boundary. Direct-native media is normally stripped before
    /// this method is used, but keep the dormant registry coherent too.
    pub(crate) fn map_non_read_only_operations(
        mut self,
        map: impl Fn(Arc<dyn Tool>) -> Arc<dyn Tool>,
    ) -> Self {
        for tool in self.tools.values_mut() {
            if tool.effect() != ToolEffect::ReadOnly {
                *tool = map(tool.clone());
            }
        }
        for tool in self.dormant_direct_native_media.values_mut() {
            if tool.effect() != ToolEffect::ReadOnly {
                *tool = map(tool.clone());
            }
        }
        for entry in self.mcp_builtin_tools.values_mut() {
            if entry.tool.effect() != ToolEffect::ReadOnly {
                entry.tool = map(entry.tool.clone());
            }
        }
        self.definition_cache.lock().unwrap().clear();
        self
    }

    pub fn with_discoverable_mcp(mut self, tool: Arc<dyn Tool>) -> Self {
        let name = tool.name().to_string();
        if is_monty_builtin_adaptable(&name) {
            self.mcp_builtin_tools.insert(
                name,
                McpBuiltinToolEntry {
                    tool,
                    directly_callable: false,
                },
            );
        }
        // Discoverable tools are runtime-only Monty catalog entries. They do
        // not enter `tools`, so neither the native function schema nor its
        // rendered-definition cache changes.
        self
    }

    /// Retain rendered native-schema entries in a rebuilt toolbox only when
    /// their freshly rendered definitions are identical to the previous ones.
    ///
    /// A tool-surface refresh reconstructs the Monty catalog as well as the
    /// direct-native tools. Discoverable catalog changes must not invalidate a
    /// matching native schema, but matching names alone is insufficient: tool
    /// implementations, description overrides, and capability projection can
    /// all change a same-named definition. Rendering the rebuilt toolbox before
    /// comparison also gives it independent cache ownership, so a still-live
    /// previous toolbox cannot populate its cache after the rebuild.
    pub(crate) fn preserve_definition_cache_if_native_schema_matches(
        &mut self,
        previous: &Self,
    ) -> bool {
        let previous_entries = previous.definition_cache.lock().unwrap().clone();
        self.definition_cache.lock().unwrap().clear();
        previous_entries
            .iter()
            .all(|(steering, previous_definitions)| {
                self.definitions(*steering) == *previous_definitions
            })
    }

    /// Whether the provider-visible native schema is unchanged for the
    /// steering used by an active agent. Discoverable MCP tools are absent
    /// from this projection, so their catalog-only transitions compare equal.
    ///
    /// This is intentionally separate from `definition_cache`: an empty
    /// rendered-definition cache must not make a native-schema transition look
    /// cache-neutral.
    pub(crate) fn native_schema_matches(
        &self,
        previous: &Self,
        steering: crate::agents::ToolSteering,
    ) -> bool {
        self.advertised_definitions(steering) == previous.advertised_definitions(steering)
    }

    pub fn mcp_builtin_registry(&self) -> Arc<crate::mcp::builtin::BuiltinRegistry> {
        let funcs = self
            .mcp_builtin_tools
            .iter()
            .filter(|(name, _entry)| !self.capability_unavailable.contains_key(*name))
            .filter_map(|(_name, entry)| {
                let adapter =
                    crate::mcp::builtin::ToolOutputBuiltinAdapter::new(entry.tool.clone())
                        .with_direct_call_marker(entry.directly_callable);
                adapter.into_function().ok()
            })
            .collect();
        Arc::new(crate::mcp::builtin::BuiltinRegistry::for_agent(funcs))
    }

    /// Whether every native operation reachable through this agent's Monty
    /// registry is a registered read-only operation.  This deliberately
    /// describes the registry rather than the provider-visible `mcp` wrapper:
    /// a native-only Monty runtime cannot broaden a child beyond the tools the
    /// host put in this exact toolbox.
    pub(crate) fn mcp_native_operations_are_registered_read_only(&self) -> bool {
        let mut has_available_operation = false;
        for (name, entry) in &self.mcp_builtin_tools {
            if self.capability_unavailable.contains_key(name) {
                continue;
            }
            has_available_operation = true;
            if !entry.tool.is_registered_ordinary_operation()
                || entry.tool.effect() != ToolEffect::ReadOnly
            {
                return false;
            }
        }
        has_available_operation
    }

    pub(crate) fn discoverable_mcp_tool_names(&self) -> Vec<String> {
        self.mcp_builtin_tools
            .iter()
            .filter(|(name, entry)| {
                !entry.directly_callable && !self.capability_unavailable.contains_key(*name)
            })
            .map(|(name, _entry)| name.clone())
            .collect()
    }

    pub(crate) fn mcp_native_tool_names(&self) -> Vec<String> {
        self.mcp_builtin_tools.keys().cloned().collect()
    }

    /// Register a per-agent description override for the tool named `name`.
    /// The override only takes effect once a tool with that name is present
    /// (registering for an absent name is inert — the tools array is what the
    /// model sees). An empty override (no text for either mode) is dropped so
    /// the box's serialized form is unaffected. Called by the built-in agent
    /// factories and by the markdown-agent builder to author per-agent intent.
    pub fn with_override(mut self, name: &str, ov: ToolDescOverride) -> Self {
        self.set_override_if_changed(name, ov);
        self
    }

    pub fn set_override_if_changed(&mut self, name: &str, ov: ToolDescOverride) -> bool {
        let changed = if ov.is_empty() {
            self.overrides.remove(name).is_some()
        } else if self.overrides.get(name) == Some(&ov) {
            false
        } else {
            self.overrides.insert(name.to_string(), ov);
            true
        };
        if changed {
            self.definition_cache.lock().unwrap().clear();
        }
        changed
    }

    pub fn get(&self, name: &str) -> Option<&Arc<dyn Tool>> {
        if self.capability_unavailable.contains_key(name) {
            return None;
        }
        self.tools.get(name)
    }

    pub fn get_cloned(&self, name: &str) -> Option<Arc<dyn Tool>> {
        self.get(name).cloned()
    }

    /// Return a tool from the provider-visible schema, including a dormant
    /// direct-native media tool. Unlike [`Self::get`], this does not imply the
    /// tool is callable in this turn.
    pub(crate) fn advertised_tool(&self, name: &str) -> Option<&Arc<dyn Tool>> {
        self.tools
            .get(name)
            .or_else(|| self.dormant_direct_native_media.get(name))
    }

    /// Resolve the call-time status of a name against the stable provider
    /// schema. This is the sole boundary that distinguishes an unavailable
    /// advertised tool from a hallucinated name.
    pub(crate) fn call_availability(&self, name: &str) -> ToolCallAvailability {
        if self.get(name).is_some() {
            ToolCallAvailability::Callable
        } else if self.advertised_tool(name).is_some() {
            ToolCallAvailability::AdvertisedUnavailable
        } else {
            ToolCallAvailability::NotAdvertised
        }
    }

    /// Model-visible explanation for an advertised tool that cannot be called
    /// in this turn. Capability detail is retained when it is safe and useful,
    /// including the runtime/model/dispatch reason for dormant media tools.
    pub(crate) fn unavailable_call_message(&self, name: &str) -> Option<String> {
        if self.call_availability(name) != ToolCallAvailability::AdvertisedUnavailable {
            return None;
        }
        if let Some(issues) = self.capability_unavailable.get(name) {
            let notice = crate::capabilities::missing_required_notice(
                issues.iter().cloned(),
                crate::capabilities::RemedyPlatform::current(),
            )
            .unwrap_or_else(|| "required host capability is unavailable".to_string());
            return Some(format!("Tool `{name}` is currently unavailable: {notice}"));
        }
        let reason = self
            .direct_native_media_unavailable
            .get(name)
            .copied()
            .map(DirectNativeMediaUnavailable::message)
            .unwrap_or("it is not callable in this turn");
        Some(format!(
            "Tool `{name}` is currently unavailable because {reason}."
        ))
    }

    pub fn apply_capabilities(
        mut self,
        env: &std::collections::HashMap<String, String>,
        cwd: &std::path::Path,
        target: crate::capabilities::ExecutionTarget,
    ) -> Self {
        let cache = crate::capabilities::default_probe_cache();
        self.apply_capabilities_with_cache(env, cwd, target, &cache);
        self
    }

    pub fn apply_capabilities_with_cache(
        &mut self,
        env: &std::collections::HashMap<String, String>,
        cwd: &std::path::Path,
        target: crate::capabilities::ExecutionTarget,
        cache: &crate::capabilities::CapabilityProbeCache,
    ) {
        self.capability_unavailable.clear();
        self.capability_description_suffixes.clear();
        for (name, tool) in &self.tools {
            // A/V tools are materialized from the daemon-pinned catalog and
            // exact codec/modality snapshot. A second generic PATH lookup can
            // select different binaries and contradict that authoritative
            // decision, so retain declarations as metadata but do not gate
            // these tools through the generic capability probe.
            if crate::tool_media_authority::is_av_tool_name(name) {
                continue;
            }
            let requirements = tool.binary_requirements();
            let evaluation = crate::capabilities::evaluate_tool_requirements(
                name,
                &requirements,
                env,
                cwd,
                target,
                cache,
            );
            if !evaluation.unavailable.is_empty() {
                self.capability_unavailable
                    .insert(name.clone(), evaluation.unavailable);
            }
            if !evaluation.optional_missing.is_empty() {
                self.capability_description_suffixes.insert(
                    name.clone(),
                    evaluation
                        .optional_missing
                        .into_iter()
                        .map(|issue| {
                            format!(
                                " Optional `{}` missing: {}",
                                issue.requirement.name,
                                issue.render_remedy(crate::capabilities::RemedyPlatform::current())
                            )
                        })
                        .collect(),
                );
            }
        }
        self.definition_cache.lock().unwrap().clear();
    }

    pub fn capability_unavailable(
        &self,
    ) -> impl Iterator<Item = &crate::capabilities::ToolCapabilityIssue> {
        self.capability_unavailable
            .values()
            .flat_map(|issues| issues.iter())
    }

    pub fn capability_notice_text(&self) -> Option<String> {
        crate::capabilities::missing_required_notice(
            self.capability_unavailable().cloned(),
            crate::capabilities::RemedyPlatform::current(),
        )
    }

    pub fn capability_notice_fix_command(&self) -> Option<String> {
        crate::capabilities::first_copyable_install_command(
            self.capability_unavailable().cloned(),
            crate::capabilities::RemedyPlatform::current(),
        )
    }

    /// Project every tool to a `ToolDefinition`, rendering descriptions in
    /// the given `steering` and applying any per-agent override. The
    /// `steering` flows from the agent def's `toolSteering`; the
    /// overrides are the ones registered via [`Self::with_override`] at
    /// construction time.
    pub fn definitions(&self, steering: crate::agents::ToolSteering) -> Vec<ToolDefinition> {
        if let Some(cached) = self
            .definition_cache
            .lock()
            .unwrap()
            .get(&steering)
            .cloned()
        {
            return cached;
        }
        let definitions: Vec<ToolDefinition> = self
            .tools
            .values()
            .filter(|t| !self.capability_unavailable.contains_key(t.name()))
            .map(|t| {
                let mut definition = definition_of(&**t, steering, self.overrides.get(t.name()));
                if let Some(suffixes) = self.capability_description_suffixes.get(t.name()) {
                    definition.description.push_str(&suffixes.join(""));
                }
                definition
            })
            .collect();
        self.definition_cache
            .lock()
            .unwrap()
            .insert(steering, definitions.clone());
        definitions
    }

    /// Project the session-stable provider tool schema.
    ///
    /// A live capability probe or root-scoped media authority may make a tool
    /// temporarily non-callable, but it must not add or remove that tool from
    /// the provider's cacheable `tools[]` prefix.  The ordinary
    /// [`Self::definitions`] projection remains the operational view for UI and
    /// MCP; this projection includes dormant media tools and deliberately omits
    /// volatile capability-description suffixes. Dispatch uses this stable
    /// schema to distinguish an unavailable advertised call from a
    /// hallucinated name at call time.
    pub fn advertised_definitions(
        &self,
        steering: crate::agents::ToolSteering,
    ) -> Vec<ToolDefinition> {
        let tools: BTreeMap<&str, &Arc<dyn Tool>> = self
            .tools
            .iter()
            .map(|(name, tool)| (name.as_str(), tool))
            .chain(
                self.dormant_direct_native_media
                    .iter()
                    .map(|(name, tool)| (name.as_str(), tool)),
            )
            .collect();
        tools
            .into_values()
            .map(|tool| definition_of(&**tool, steering, self.overrides.get(tool.name())))
            .collect()
    }

    pub fn names(&self) -> Vec<&str> {
        self.tools
            .keys()
            .filter(|name| !self.capability_unavailable.contains_key(*name))
            .map(String::as_str)
            .collect()
    }

    // Registry-emptiness query; retained for the tool-registry API surface.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;
    use crate::agents::PostureResolution;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// Issue #75: a declared grant set is authoritative; the empty
    /// (undeclared) set enables none of the four capabilities.
    #[test]
    fn declared_grants_control_capabilities() {
        use crate::agents::AgentCapability;
        let mut grants = BTreeSet::new();
        grants.insert(AgentCapability::ForkContext);
        // A def that declares forkContext: the grant is on; undeclared
        // capabilities stay off.
        let mut def = crate::agents::embedded_default("Build").unwrap();
        def.vnext.as_mut().unwrap().capabilities = grants.clone();
        let posture = PostureResolution::from_def(&def);
        assert!(
            Capability::ForkContext.enabled(&posture),
            "declared grant is on"
        );
        assert!(
            !Capability::FollowupSeed.enabled(&posture),
            "an undeclared capability is off"
        );

        // Empty grant set disables everything.
        def.vnext.as_mut().unwrap().capabilities.clear();
        let posture_empty = PostureResolution::from_def(&def);
        assert!(!Capability::ForkContext.enabled(&posture_empty));
        assert!(!Capability::FollowupSeed.enabled(&posture_empty));

        // SandboxEscalate: a declared grant enables it (the tool-registration
        // seam consults the same posture).
        let mut escalate_grants = BTreeSet::new();
        escalate_grants.insert(AgentCapability::SandboxEscalate);
        def.vnext.as_mut().unwrap().capabilities = escalate_grants;
        let posture_escalate = PostureResolution::from_def(&def);
        assert!(Capability::SandboxEscalate.enabled(&posture_escalate));
        assert!(!Capability::FollowupSeed.enabled(&posture_escalate));
    }

    struct RequirementTool {
        name: &'static str,
        requirements: Vec<crate::capabilities::BinaryRequirement>,
    }

    #[async_trait]
    impl Tool for RequirementTool {
        fn name(&self) -> &str {
            self.name
        }

        fn description(&self) -> &str {
            "require external binary"
        }

        fn binary_requirements(&self) -> Vec<crate::capabilities::BinaryRequirement> {
            self.requirements.clone()
        }

        fn parameters(&self) -> Value {
            serde_json::json!({"type": "object", "properties": {}})
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            Ok(ToolOutput::text("ok"))
        }
    }

    struct ToolTestProbe {
        present: BTreeSet<String>,
        calls: AtomicUsize,
    }

    impl ToolTestProbe {
        fn new(present: &[&str]) -> Self {
            Self {
                present: present.iter().map(|name| (*name).to_string()).collect(),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl crate::capabilities::BinaryProbe for ToolTestProbe {
        fn resolve(
            &self,
            name: &str,
            _path: Option<&str>,
            _cwd: &Path,
            _budget: Duration,
        ) -> crate::capabilities::BinaryProbeStatus {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.present.contains(name) {
                crate::capabilities::BinaryProbeStatus::Present(PathBuf::from(format!(
                    "/bin/{name}"
                )))
            } else {
                crate::capabilities::BinaryProbeStatus::Missing
            }
        }
    }

    #[test]
    fn capability_tool_trait_defaults_empty_and_declared_requirement_round_trips() {
        struct NoRequirementTool;
        #[async_trait]
        impl Tool for NoRequirementTool {
            fn name(&self) -> &str {
                "none"
            }
            fn description(&self) -> &str {
                "none"
            }
            fn parameters(&self) -> Value {
                serde_json::json!({"type": "object", "properties": {}})
            }
            async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
                Ok(ToolOutput::text("ok"))
            }
        }

        assert!(NoRequirementTool.binary_requirements().is_empty());

        let tool = RequirementTool {
            name: "declared",
            requirements: vec![crate::capabilities::BinaryRequirement::required(
                "demo-bin",
                crate::capabilities::CapabilityRemedy::prose("Install demo-bin."),
            )],
        };
        let requirements = tool.binary_requirements();
        assert_eq!(requirements.len(), 1);
        assert_eq!(requirements[0].name, "demo-bin");
        assert_eq!(
            requirements[0].kind,
            crate::capabilities::BinaryRequirementKind::Required
        );
    }

    #[test]
    fn capability_required_binary_controls_callable_set_and_notice_dedupes() {
        let probe = std::sync::Arc::new(ToolTestProbe::new(&["present-bin"]));
        let cache = crate::capabilities::CapabilityProbeCache::new(probe, Duration::from_millis(1));
        let mut toolbox = ToolBox::new()
            .with(std::sync::Arc::new(RequirementTool {
                name: "present_tool",
                requirements: vec![crate::capabilities::BinaryRequirement::required(
                    "present-bin",
                    crate::capabilities::common_remedy("present-bin"),
                )],
            }))
            .with(std::sync::Arc::new(RequirementTool {
                name: "missing_a",
                requirements: vec![crate::capabilities::BinaryRequirement::required(
                    "missing-bin",
                    crate::capabilities::common_remedy("missing-bin"),
                )],
            }))
            .with(std::sync::Arc::new(RequirementTool {
                name: "missing_b",
                requirements: vec![crate::capabilities::BinaryRequirement::required(
                    "missing-bin",
                    crate::capabilities::common_remedy("missing-bin"),
                )],
            }));

        toolbox.apply_capabilities_with_cache(
            &std::collections::HashMap::from([("PATH".to_string(), "/bin".to_string())]),
            Path::new("/"),
            crate::capabilities::ExecutionTarget::Host,
            &cache,
        );

        assert!(toolbox.get("present_tool").is_some());
        assert!(toolbox.get("missing_a").is_none());
        assert!(toolbox.get("missing_b").is_none());
        let definitions = toolbox.definitions(crate::agents::ToolSteering::Terse);
        assert_eq!(definitions.len(), 1);
        assert_eq!(definitions[0].name, "present_tool");
        let notice = toolbox.capability_notice_text().unwrap();
        assert_eq!(notice.matches("`missing-bin` missing").count(), 1);
    }

    #[test]
    fn audio_video_capability_gate_uses_pinned_runtime_snapshot_not_path_probe() {
        let probe = std::sync::Arc::new(ToolTestProbe::new(&[]));
        let cache =
            crate::capabilities::CapabilityProbeCache::new(probe.clone(), Duration::from_millis(1));
        let mut toolbox = ToolBox::new().with(std::sync::Arc::new(RequirementTool {
            name: "inspect_video",
            requirements: vec![crate::capabilities::BinaryRequirement::required(
                "ffmpeg",
                crate::capabilities::common_remedy("ffmpeg"),
            )],
        }));

        toolbox.apply_capabilities_with_cache(
            &std::collections::HashMap::from([("PATH".to_string(), String::new())]),
            Path::new("/"),
            crate::capabilities::ExecutionTarget::Host,
            &cache,
        );

        assert!(toolbox.get("inspect_video").is_some());
        assert_eq!(
            probe.calls.load(Ordering::SeqCst),
            0,
            "generic PATH probing must not second-guess the pinned A/V snapshot"
        );
        assert!(toolbox.capability_notice_text().is_none());
    }

    #[test]
    fn capability_notice_ignores_missing_binary_for_ungranted_tool() {
        let probe = std::sync::Arc::new(ToolTestProbe::new(&[]));
        let cache =
            crate::capabilities::CapabilityProbeCache::new(probe.clone(), Duration::from_millis(1));
        let mut toolbox = ToolBox::new().with(std::sync::Arc::new(RequirementTool {
            name: "granted_tool",
            requirements: Vec::new(),
        }));

        toolbox.apply_capabilities_with_cache(
            &std::collections::HashMap::new(),
            Path::new("/"),
            crate::capabilities::ExecutionTarget::Host,
            &cache,
        );

        assert!(toolbox.capability_notice_text().is_none());
        assert_eq!(
            probe.calls.load(Ordering::SeqCst),
            0,
            "only granted toolbox tools are probed"
        );
    }

    #[test]
    fn capability_optional_binary_keeps_tool_callable_and_updates_description() {
        let cache = crate::capabilities::CapabilityProbeCache::new(
            std::sync::Arc::new(ToolTestProbe::new(&[])),
            Duration::from_millis(1),
        );
        let mut toolbox = ToolBox::new().with(std::sync::Arc::new(RequirementTool {
            name: "optional_tool",
            requirements: vec![crate::capabilities::BinaryRequirement::optional(
                "optional-bin",
                crate::capabilities::CapabilityRemedy::prose("Install optional-bin."),
            )],
        }));

        toolbox.apply_capabilities_with_cache(
            &std::collections::HashMap::new(),
            Path::new("/"),
            crate::capabilities::ExecutionTarget::Host,
            &cache,
        );

        assert!(toolbox.get("optional_tool").is_some());
        let definitions = toolbox.definitions(crate::agents::ToolSteering::Terse);
        assert_eq!(definitions.len(), 1);
        assert!(
            definitions[0]
                .description
                .contains("Optional `optional-bin` missing")
        );
    }

    #[test]
    fn capability_toolbox_rebuild_cache_is_keyed_by_path() {
        let probe = std::sync::Arc::new(ToolTestProbe::new(&[]));
        let cache =
            crate::capabilities::CapabilityProbeCache::new(probe.clone(), Duration::from_millis(1));
        let mut toolbox = ToolBox::new().with(std::sync::Arc::new(RequirementTool {
            name: "missing_tool",
            requirements: vec![crate::capabilities::BinaryRequirement::required(
                "missing-bin",
                crate::capabilities::common_remedy("missing-bin"),
            )],
        }));
        let env_a = std::collections::HashMap::from([("PATH".to_string(), "/a".to_string())]);
        let env_b = std::collections::HashMap::from([("PATH".to_string(), "/b".to_string())]);

        toolbox.apply_capabilities_with_cache(
            &env_a,
            Path::new("/"),
            crate::capabilities::ExecutionTarget::Host,
            &cache,
        );
        toolbox.apply_capabilities_with_cache(
            &env_a,
            Path::new("/"),
            crate::capabilities::ExecutionTarget::Host,
            &cache,
        );
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
        toolbox.apply_capabilities_with_cache(
            &env_b,
            Path::new("/"),
            crate::capabilities::ExecutionTarget::Host,
            &cache,
        );
        assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
    }
}

#[cfg(test)]
mod definition_cache_tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingTool {
        name: &'static str,
        calls: Arc<AtomicUsize>,
        parameters: Value,
    }

    #[async_trait]
    impl Tool for CountingTool {
        fn name(&self) -> &str {
            self.name
        }

        fn description(&self) -> &str {
            "count calls"
        }

        fn parameters(&self) -> Value {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.parameters.clone()
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            Ok(ToolOutput::text("ok"))
        }
    }

    #[test]
    fn definitions_build_schema_once_per_steering() {
        let calls = Arc::new(AtomicUsize::new(0));
        let toolbox = ToolBox::new().with(Arc::new(CountingTool {
            name: "counting",
            calls: calls.clone(),
            parameters: json!({ "type": "object", "properties": {} }),
        }));

        let first = toolbox.definitions(crate::agents::ToolSteering::Terse);
        let second = toolbox.definitions(crate::agents::ToolSteering::Terse);
        assert_eq!(first, second);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // A different steering is a different cache key → rebuild.
        let _ = toolbox.definitions(crate::agents::ToolSteering::Verbose);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn discoverable_catalog_change_preserves_native_schema_cache() {
        let native_calls = Arc::new(AtomicUsize::new(0));
        let discoverable_calls = Arc::new(AtomicUsize::new(0));
        let native = Arc::new(CountingTool {
            name: "native_counting",
            calls: native_calls.clone(),
            parameters: json!({ "type": "object", "properties": {} }),
        });
        let discoverable = Arc::new(CountingTool {
            name: "discoverable_counting",
            calls: discoverable_calls.clone(),
            parameters: json!({ "type": "object", "properties": {} }),
        });
        let previous = ToolBox::new().with(native.clone());
        let previous_definitions = previous.definitions(crate::agents::ToolSteering::Terse);
        let provider_schema = serde_json::to_vec(
            &previous.advertised_definitions(crate::agents::ToolSteering::Terse),
        )
        .unwrap();
        assert_eq!(native_calls.load(Ordering::SeqCst), 2);

        let mut rebuilt = ToolBox::new()
            .with(native)
            .with_discoverable_mcp(discoverable);
        assert!(rebuilt.preserve_definition_cache_if_native_schema_matches(&previous));
        assert_eq!(
            serde_json::to_vec(&rebuilt.definitions(crate::agents::ToolSteering::Terse)).unwrap(),
            serde_json::to_vec(&previous_definitions).unwrap(),
            "Discoverable tools must not change the cached native schema"
        );
        assert_eq!(
            serde_json::to_vec(
                &rebuilt.advertised_definitions(crate::agents::ToolSteering::Terse),
            )
            .unwrap(),
            provider_schema,
            "Discoverable tools must not change the provider cache key's tool schema"
        );
        let _ = rebuilt.definitions(crate::agents::ToolSteering::Terse);
        assert_eq!(
            native_calls.load(Ordering::SeqCst),
            4,
            "the rebuilt toolbox must cache its own verified native schema"
        );
        let _ = previous.definitions(crate::agents::ToolSteering::Verbose);
        let _ = rebuilt.definitions(crate::agents::ToolSteering::Verbose);
        assert_eq!(
            native_calls.load(Ordering::SeqCst),
            6,
            "rebuilt caches must not alias a still-live previous toolbox"
        );
        assert_eq!(
            discoverable_calls.load(Ordering::SeqCst),
            0,
            "discoverable tools must not be assembled into the native schema"
        );
    }

    #[test]
    fn enabled_membership_change_does_not_preserve_native_schema_cache() {
        let native_calls = Arc::new(AtomicUsize::new(0));
        let added_calls = Arc::new(AtomicUsize::new(0));
        let native = Arc::new(CountingTool {
            name: "native_counting",
            calls: native_calls.clone(),
            parameters: json!({ "type": "object", "properties": {} }),
        });
        let added = Arc::new(CountingTool {
            name: "added_counting",
            calls: added_calls.clone(),
            parameters: json!({ "type": "object", "properties": {} }),
        });
        let previous = ToolBox::new().with(native.clone());
        let provider_schema = serde_json::to_vec(
            &previous.advertised_definitions(crate::agents::ToolSteering::Terse),
        )
        .unwrap();
        let _ = previous.definitions(crate::agents::ToolSteering::Terse);

        let mut rebuilt = ToolBox::new().with(native).with(added);
        assert!(!rebuilt.preserve_definition_cache_if_native_schema_matches(&previous));
        assert_ne!(
            serde_json::to_vec(
                &rebuilt.advertised_definitions(crate::agents::ToolSteering::Terse),
            )
            .unwrap(),
            provider_schema,
            "an Enabled membership change must change the provider schema"
        );
        let _ = rebuilt.definitions(crate::agents::ToolSteering::Terse);
        assert_eq!(native_calls.load(Ordering::SeqCst), 4);
        assert_eq!(added_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn same_named_schema_change_does_not_preserve_definition_cache() {
        let previous_calls = Arc::new(AtomicUsize::new(0));
        let rebuilt_calls = Arc::new(AtomicUsize::new(0));
        let previous = ToolBox::new().with(Arc::new(CountingTool {
            name: "task",
            calls: previous_calls.clone(),
            parameters: json!({
                "type": "object",
                "properties": { "old_target": { "type": "string" } }
            }),
        }));
        let previous_definitions = previous.definitions(crate::agents::ToolSteering::Terse);
        assert_eq!(previous_calls.load(Ordering::SeqCst), 1);

        let mut rebuilt = ToolBox::new().with(Arc::new(CountingTool {
            name: "task",
            calls: rebuilt_calls.clone(),
            parameters: json!({
                "type": "object",
                "properties": { "new_target": { "type": "string" } }
            }),
        }));
        assert!(!rebuilt.preserve_definition_cache_if_native_schema_matches(&previous));
        let rebuilt_definitions = rebuilt.definitions(crate::agents::ToolSteering::Terse);
        assert_eq!(rebuilt_calls.load(Ordering::SeqCst), 1);
        assert_ne!(rebuilt_definitions, previous_definitions);
        assert!(
            rebuilt_definitions[0].parameters["properties"]
                .get("new_target")
                .is_some(),
            "the rebuilt schema must come from the current same-named tool implementation"
        );
    }

    struct DormantMediaTool(&'static str);

    #[async_trait]
    impl Tool for DormantMediaTool {
        fn name(&self) -> &str {
            self.0
        }

        fn description(&self) -> &str {
            "read a current-session image"
        }

        fn parameters(&self) -> Value {
            json!({ "type": "object", "properties": {} })
        }

        async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
            Ok(ToolOutput::text("unavailable without live media authority"))
        }
    }

    #[test]
    fn advertised_definitions_include_dormant_media_without_making_it_callable() {
        let toolbox = ToolBox::new()
            .with_dormant_direct_native_media(Arc::new(DormantMediaTool("read_image")));

        assert!(toolbox.get("read_image").is_none());
        assert_eq!(
            toolbox.call_availability("read_image"),
            ToolCallAvailability::AdvertisedUnavailable
        );
        assert!(
            toolbox
                .unavailable_call_message("read_image")
                .is_some_and(|message| message.contains("live media authority"))
        );
        assert!(
            toolbox
                .definitions(crate::agents::ToolSteering::Terse)
                .is_empty()
        );
        let advertised = toolbox.advertised_definitions(crate::agents::ToolSteering::Terse);
        assert_eq!(advertised.len(), 1);
        assert_eq!(advertised[0].name, "read_image");

        let activated = toolbox.clone().activate_dormant_direct_native_media(
            crate::tool_media_authority::MediaToolAvailability::available(),
        );
        assert!(activated.get("read_image").is_some());
        assert_eq!(
            serde_json::to_vec(&advertised).unwrap(),
            serde_json::to_vec(
                &activated.advertised_definitions(crate::agents::ToolSteering::Terse),
            )
            .unwrap(),
            "a media authority may change callability but never tools[]"
        );
    }

    #[test]
    fn dormant_media_call_reports_the_live_model_limitation() {
        let toolbox = ToolBox::new()
            .with_dormant_direct_native_media(Arc::new(DormantMediaTool("inspect_audio")))
            .activate_dormant_direct_native_media(
                crate::tool_media_authority::MediaToolAvailability::available_with(
                    crate::tool_media_authority::AvRuntimeProfile::FullClip,
                    crate::config::providers::CapabilityStatus::Supported,
                    crate::config::providers::CapabilityStatus::RequiresEntitlement,
                    crate::config::providers::CapabilityStatus::Supported,
                ),
            );

        assert_eq!(
            toolbox.call_availability("inspect_audio"),
            ToolCallAvailability::AdvertisedUnavailable,
            "the provider schema remains stable while the model limitation gates dispatch"
        );
        let message = toolbox
            .unavailable_call_message("inspect_audio")
            .expect("an advertised but dormant tool has a call-time result");
        assert!(message.contains("requires an entitlement"));
        assert!(!message.contains("no live media authority"));
    }

    #[test]
    fn dormant_transcription_call_reports_dispatch_unavailability() {
        let toolbox = ToolBox::new()
            .with(Arc::new(DormantMediaTool("transcribe_audio")))
            .deactivate_direct_native_media_for_transcription_dispatch();

        assert_eq!(
            toolbox.call_availability("transcribe_audio"),
            ToolCallAvailability::AdvertisedUnavailable
        );
        assert!(
            toolbox
                .unavailable_call_message("transcribe_audio")
                .is_some_and(|message| message.contains("authorized transcription dispatch"))
        );
    }
}

#[cfg(test)]
mod sandbox_meta_tests {
    use super::*;

    /// §6.5 separation of channels: on the refuse path `bash` attaches the
    /// diagnosed remedy ONLY out-of-band on `SandboxMeta.unavailable_reason`.
    /// The model-facing `ToolOutput.content` (what enters history / the
    /// outbound prompt) is the addressed-to-the-model error and is the only
    /// thing the model ever sees — `with_sandbox` does not splice the meta into
    /// `content`. This is what keeps the user-facing surfacing out of the LLM
    /// context: the remedy rides the meta → engine event → broadcast bus only.
    #[test]
    fn unavailable_reason_rides_meta_not_model_content() {
        let reason = "unprivileged user namespaces are restricted by AppArmor (Ubuntu 23.10+); \
             `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` re-enables confinement";
        let model_facing = "Error: the shell sandbox cannot start here (some reason); `bash` will \
             fail for the rest of the session until the user types `/sandbox off`";
        let meta = SandboxMeta {
            enabled: true,
            confined: false,
            escalated: false,
            escalation_preauthorized: false,
            approval_scope_recorded: None,
            unavailable_reason: Some(reason.to_string()),
            resource_profiles: Vec::new(),
        };
        let out = ToolOutput::text(model_facing).with_sandbox(meta);
        // The remedy lives on the meta…
        assert_eq!(
            out.sandbox.as_ref().unwrap().unavailable_reason.as_deref(),
            Some(reason)
        );
        // …and never in the model-facing body. The sysctl command in
        // particular must not leak into what the model sees.
        assert!(!out.content.contains("sudo sysctl"));
        assert!(!out.content.contains(reason));
    }

    /// The export sub-object omits `unavailable_reason` on every non-refuse
    /// path (token economy — the events.json `sandbox` key stays minimal).
    #[test]
    fn unavailable_reason_omitted_when_none() {
        let meta = SandboxMeta {
            enabled: true,
            confined: true,
            escalated: false,
            escalation_preauthorized: false,
            approval_scope_recorded: None,
            unavailable_reason: None,
            resource_profiles: Vec::new(),
        };
        let v = serde_json::to_value(&meta).unwrap();
        assert!(v.get("unavailable_reason").is_none());
    }

    #[test]
    fn resource_profiles_serialize_only_when_present() {
        let meta = SandboxMeta {
            enabled: true,
            confined: true,
            escalated: false,
            escalation_preauthorized: false,
            approval_scope_recorded: None,
            unavailable_reason: None,
            resource_profiles: vec![SandboxResourceProfileMeta {
                profile: "rust_toolchain".to_string(),
                definition_source: Some("builtin".to_string()),
                matched_commands: vec!["cargo test".to_string()],
                configured_wrappers: vec!["just test".to_string()],
                introspection: vec![SandboxResourceIntrospectionMeta {
                    tool: "go".to_string(),
                    command: "go env GOMODCACHE GOCACHE".to_string(),
                    status: "used".to_string(),
                    detail: None,
                }],
                roots: vec![SandboxResourceRootMeta {
                    kind: "cargo_home".to_string(),
                    path: "/home/me/.cargo".to_string(),
                    access: "read_write".to_string(),
                    source: Some("session_env".to_string()),
                    reason: None,
                    contributing_profiles: vec!["rust_toolchain".to_string()],
                }],
                denied_roots: Vec::new(),
            }],
        };

        let v = serde_json::to_value(&meta).unwrap();
        assert_eq!(v["resource_profiles"][0]["profile"], "rust_toolchain");
        assert_eq!(
            v["resource_profiles"][0]["matched_commands"][0],
            "cargo test"
        );
        assert_eq!(v["resource_profiles"][0]["roots"][0]["kind"], "cargo_home");
        assert_eq!(v["resource_profiles"][0]["definition_source"], "builtin");
        assert_eq!(
            v["resource_profiles"][0]["configured_wrappers"][0],
            "just test"
        );
        assert_eq!(
            v["resource_profiles"][0]["roots"][0]["source"],
            "session_env"
        );
        assert_eq!(
            v["resource_profiles"][0]["roots"][0]["contributing_profiles"][0],
            "rust_toolchain"
        );
        assert_eq!(
            v["resource_profiles"][0]["introspection"][0]["status"],
            "used"
        );
    }
}

#[cfg(test)]
mod steering_tests {
    use super::*;
    use crate::tools;

    fn all_builtin_tools() -> Vec<Arc<dyn Tool>> {
        crate::engine::builtin::invariant_builtin_tools()
    }

    fn tool_by_name(name: &str) -> Arc<dyn Tool> {
        all_builtin_tools()
            .into_iter()
            .find(|tool| tool.name() == name)
            .unwrap_or_else(|| panic!("built-in tool `{name}` missing from invariant registry"))
    }

    fn words(text: &str) -> std::collections::BTreeSet<String> {
        text.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .filter(|word| !word.is_empty())
            .map(|word| word.to_ascii_lowercase())
            .collect()
    }

    fn has_description_steering_shape(terse: &str, verbose: &str) -> bool {
        let terse_words = words(terse);
        let verbose_words = words(verbose);
        let added_distinct_words = verbose_words.difference(&terse_words).count();
        let verbose_lower = verbose.to_ascii_lowercase();
        let when_to_use_markers = [
            "use ",
            "call ",
            "read ",
            "write ",
            "replace ",
            "search ",
            "find ",
            "get ",
            "show ",
            "list ",
            "send ",
            "create ",
            "update ",
            "run ",
            "schedule ",
            "ask ",
            "spawn ",
            "emit ",
            "request ",
            "return ",
            "surface ",
        ];
        let when_not_to_use_markers = [
            " do not ",
            " don't ",
            " not ",
            " never ",
            " instead",
            " rather than",
            " avoid",
            " prefer",
            " without",
            " only ",
            " cannot",
            " can't",
            " must not",
            " must ",
            " fails",
            " rejected",
            " requires",
            " required",
            " takes no arguments",
            " no arguments",
            " no filesystem",
            " no network",
            " no environment",
            " scope with",
            " confined",
            " budget",
            " capped",
            " bounded",
            " limit",
            " reserve",
            " path-confined",
            " preview",
            " omit",
        ];
        added_distinct_words >= 8
            && when_to_use_markers
                .iter()
                .any(|marker| verbose_lower.contains(marker))
            && when_not_to_use_markers
                .iter()
                .any(|marker| verbose_lower.contains(marker))
    }

    /// CONFLICT-AVOIDANCE INVARIANT (implementation note):
    /// for every built-in tool, in BOTH its terse and verbose schema, no
    /// `x-cockpit-aliases` entry may (a) shadow a canonical property name or
    /// (b) be double-claimed by two properties — within that same schema.
    /// Cross-tool collisions are harmless (resolution is per-tool-schema).
    /// Registry-driven, so a future tool that adds a shadowing/double-claimed
    /// alias trips here (and CI), not at runtime.
    #[test]
    fn no_tool_schema_has_a_shadowing_or_double_claimed_alias() {
        use crate::engine::repair::alias_invariants;
        for tool in all_builtin_tools() {
            let mut schemas = vec![tool.parameters()];
            if let Some(d) = tool.verbose_parameters() {
                schemas.push(d);
            }
            for schema in &schemas {
                let violations = alias_invariants(schema);
                assert!(
                    violations.is_empty(),
                    "tool `{}` schema has alias-invariant violations: {:?}",
                    tool.name(),
                    violations
                );
            }
        }
    }

    /// PRIMARY-FIELD INVARIANT (implementation note): for
    /// every built-in tool, in BOTH its terse and verbose schema, an
    /// `x-cockpit-primary-field` annotation (when present) must name a real
    /// property of that same schema — otherwise the root-string wrap would
    /// produce an object that can never validate. Registry-driven, so a future
    /// tool that annotates a nonexistent field trips here (and CI), not at
    /// runtime.
    #[test]
    fn primary_field_annotation_names_a_real_property() {
        use crate::engine::repair::PRIMARY_FIELD_KEY;
        for tool in all_builtin_tools() {
            let mut schemas = vec![tool.parameters()];
            if let Some(d) = tool.verbose_parameters() {
                schemas.push(d);
            }
            for schema in &schemas {
                let Some(field) = schema.get(PRIMARY_FIELD_KEY) else {
                    continue;
                };
                let field = field.as_str().unwrap_or_else(|| {
                    panic!(
                        "tool `{}` has a non-string `{PRIMARY_FIELD_KEY}`",
                        tool.name()
                    )
                });
                let props = schema.get("properties").and_then(|p| p.as_object());
                assert!(
                    props.is_some_and(|p| p.contains_key(field)),
                    "tool `{}` declares primary field `{field}` which is not a property of its schema",
                    tool.name()
                );
            }
        }
    }

    /// FULL-SURFACE COVERAGE: every built-in tool must supply a non-empty
    /// verbose description that is meaningfully more explicit than its
    /// terse one — no terse-fallback gaps, no TODO tools. Registry-driven,
    /// so a future built-in tool can't silently skip.
    #[test]
    fn every_builtin_tool_has_a_verbose_description() {
        for tool in all_builtin_tools() {
            if tool.name() == "escalate" {
                // `escalate` is removed when the agent lacks the sandboxEscalate
                // grant, so a verbose variant is unrenderable by construction.
                // Keep this a named exemption so other built-ins cannot
                // silently lose verbose coverage.
                continue;
            }
            let terse = tool.description().to_string();
            let verbose = tool.verbose_description().unwrap_or_else(|| {
                panic!(
                    "built-in tool `{}` has no verbose_description — full-surface coverage requires one",
                    tool.name()
                )
            });
            assert!(
                !verbose.trim().is_empty(),
                "tool `{}` has an empty verbose description",
                tool.name()
            );
            // Verbose steering must be longer than the
            // terse one, not byte-identical, and add real use/avoid steering
            // rather than padding.
            assert!(
                verbose.len() > terse.len(),
                "tool `{}` verbose description is not more explicit than terse ({} <= {})",
                tool.name(),
                verbose.len(),
                terse.len()
            );
            assert!(
                has_description_steering_shape(&terse, &verbose),
                "tool `{}` verbose description lacks structural use/avoid steering or meaningful new vocabulary: {verbose}",
                tool.name()
            );
        }
    }

    #[test]
    fn padded_description_without_steering_fails_structural_check() {
        let terse = "Read a file.";
        let padded = "Read a file. padding padding padding padding padding padding padding padding padding padding padding padding padding padding.";
        assert!(padded.len() >= 80);
        assert!(!has_description_steering_shape(terse, padded));
    }

    #[test]
    fn description_quality_rewrites_pin_load_bearing_clauses() {
        let write = tool_by_name("write").description().to_ascii_lowercase();
        assert!(write.contains("complete new contents"));
        assert!(write.contains("omitted lines are deleted"));
        assert!(write.contains("edit"));

        let graph = tool_by_name("graph").description().to_ascii_lowercase();
        let change_impact = tool_by_name("change_impact")
            .description()
            .to_ascii_lowercase();
        assert!(graph.contains("change_impact"));
        assert!(change_impact.contains("graph"));

        let context_pack = tool_by_name("context_pack")
            .description()
            .to_ascii_lowercase();
        assert!(context_pack.contains("first move"));
        assert!(context_pack.contains("never prints file contents"));
        assert!(context_pack.contains("read"));

        let note = tool_by_name("note").description().to_ascii_lowercase();
        assert!(note.contains("live progress note"));
        assert!(!note.contains("now; it reaches"));

        let todo = tool_by_name("todo").description().to_ascii_lowercase();
        assert!(todo.contains("long-horizon"));
        assert!(todo.contains("task"));

        let names: std::collections::BTreeSet<_> = all_builtin_tools()
            .into_iter()
            .map(|tool| tool.name().to_string())
            .collect();
        assert!(names.contains("websearch"), "{names:?}");
        assert!(names.contains("webfetch"), "{names:?}");
        for name in ["websearch", "webfetch"] {
            let tool = tool_by_name(name);
            let terse = tool.description().to_string();
            let verbose = tool.verbose_description().unwrap();
            assert!(has_description_steering_shape(&terse, &verbose));
        }
    }

    #[test]
    fn sibling_disambiguation_terse_descriptions_name_siblings() {
        let cases: &[(&str, &[&str])] = &[
            ("search", &["grep", "code", "context_pack"]),
            ("grep", &["search", "code"]),
            (
                "code",
                &[
                    "search",
                    "grep",
                    "context_pack",
                    "read",
                    "graph",
                    "change_impact",
                ],
            ),
            (
                "graph",
                &["search", "code", "change_impact", "context_pack"],
            ),
            (
                "context_pack",
                &["search", "code", "graph", "change_impact", "read"],
            ),
            ("change_impact", &["graph", "code", "search"]),
            ("read", &["write", "edit"]),
            ("write", &["read", "edit"]),
            ("edit", &["read", "write"]),
            ("unlock", &["write", "edit"]),
            ("todo", &["task"]),
        ];
        for (name, siblings) in cases {
            let description = tool_by_name(name).description().to_ascii_lowercase();
            for sibling in *siblings {
                assert!(
                    description.contains(sibling),
                    "`{name}` terse description must name sibling `{sibling}`; got: {description}"
                );
            }
        }
    }

    #[test]
    fn intel_tool_surface_is_five_tools() {
        let expected: std::collections::BTreeSet<_> =
            ["search", "code", "graph", "context_pack", "change_impact"]
                .into_iter()
                .map(String::from)
                .collect();
        let builtin_names: std::collections::BTreeSet<_> = all_builtin_tools()
            .into_iter()
            .filter(|tool| {
                crate::engine::builtin::builtin_tool_inventory()
                    .iter()
                    .any(|item| item.family == "Intel" && item.name == tool.name())
            })
            .map(|tool| tool.name().to_string())
            .collect();
        let inventory_names: std::collections::BTreeSet<_> =
            crate::engine::builtin::builtin_tool_inventory()
                .iter()
                .filter(|item| item.family == "Intel")
                .map(|item| item.name.to_string())
                .collect();

        assert_eq!(builtin_names, expected);
        assert_eq!(inventory_names, expected);

        let registered_names: std::collections::BTreeSet<_> = all_builtin_tools()
            .into_iter()
            .map(|tool| tool.name().to_string())
            .collect();
        for removed in [
            "tree",
            "outline",
            "symbol_find",
            "word",
            "deps",
            "hot",
            "circular",
            "impact",
        ] {
            assert!(
                !registered_names.contains(removed),
                "{removed}: {registered_names:?}"
            );
        }
    }

    #[test]
    fn code_replaces_removed_structure_tool_names() {
        let builtin_names: std::collections::BTreeSet<_> = all_builtin_tools()
            .into_iter()
            .map(|tool| tool.name().to_string())
            .collect();
        let inventory_names: std::collections::BTreeSet<_> =
            crate::engine::builtin::builtin_tool_inventory()
                .iter()
                .filter(|item| item.family == "Intel")
                .map(|item| item.name)
                .collect();
        let grant_names: std::collections::BTreeSet<_> =
            crate::engine::builtin::known_agent_tool_names()
                .iter()
                .copied()
                .collect();

        assert!(builtin_names.contains("code"), "{builtin_names:?}");
        assert!(inventory_names.contains("code"), "{inventory_names:?}");
        assert!(grant_names.contains("code"), "{grant_names:?}");
        for removed in ["tree", "outline", "symbol_find", "word"] {
            assert!(
                !builtin_names.contains(removed),
                "{removed}: {builtin_names:?}"
            );
            assert!(
                !inventory_names.contains(removed),
                "{removed}: {inventory_names:?}"
            );
            assert!(!grant_names.contains(removed), "{removed}: {grant_names:?}");
        }
    }

    #[test]
    fn graph_replaces_removed_relationship_tool_names() {
        let builtin_names: std::collections::BTreeSet<_> = all_builtin_tools()
            .into_iter()
            .map(|tool| tool.name().to_string())
            .collect();
        let inventory_names: std::collections::BTreeSet<_> =
            crate::engine::builtin::builtin_tool_inventory()
                .iter()
                .filter(|item| item.family == "Intel")
                .map(|item| item.name)
                .collect();
        let grant_names: std::collections::BTreeSet<_> =
            crate::engine::builtin::known_agent_tool_names()
                .iter()
                .copied()
                .collect();

        assert!(builtin_names.contains("graph"), "{builtin_names:?}");
        assert!(inventory_names.contains("graph"), "{inventory_names:?}");
        assert!(grant_names.contains("graph"), "{grant_names:?}");
        for removed in ["deps", "circular", "impact", "hot"] {
            assert!(
                !builtin_names.contains(removed),
                "{removed}: {builtin_names:?}"
            );
            assert!(
                !inventory_names.contains(removed),
                "{removed}: {inventory_names:?}"
            );
            assert!(!grant_names.contains(removed), "{removed}: {grant_names:?}");
        }
    }

    #[test]
    fn prune_and_compact_seed_lists_name_registered_tools() {
        let builtin_names: std::collections::BTreeSet<_> = all_builtin_tools()
            .into_iter()
            .map(|tool| tool.name().to_string())
            .collect();
        for name in crate::engine::prune::SNAPSHOT_TOOLS
            .iter()
            .copied()
            .chain(crate::engine::compact::read_only_context_tag_tool_names())
        {
            assert!(
                builtin_names.contains(name),
                "seed/prune tool `{name}` is not registered: {builtin_names:?}"
            );
        }
    }

    /// Verbose parameters, when supplied, keep the SAME shape + required
    /// set as the terse parameters — tool grants never vary by steering, only
    /// how descriptions render. We compare the structural skeleton
    /// (property names + `required` + `enum`s), ignoring `description`.
    #[test]
    fn verbose_parameters_preserve_shape() {
        for tool in all_builtin_tools() {
            let Some(verbose) = tool.verbose_parameters() else {
                continue;
            };
            let terse = tool.parameters();
            assert_eq!(
                skeleton(&terse),
                skeleton(&verbose),
                "tool `{}` verbose parameters changed the schema shape",
                tool.name()
            );
        }
    }

    /// Strip every `description` field from a JSON schema, leaving the
    /// structural skeleton (types, property names, `required`, `enum`s).
    fn skeleton(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (k, val) in map {
                    if k == "description" {
                        continue;
                    }
                    out.insert(k.clone(), skeleton(val));
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(skeleton).collect())
            }
            other => other.clone(),
        }
    }

    /// The centralized rendering seam selects the terse or verbose description.
    /// The switch lives in `definition_of` and nowhere else.
    #[test]
    fn definition_of_switches_description_on_steering() {
        let tool = tools::read::ReadTool;
        let terse = definition_of(&tool, crate::agents::ToolSteering::Terse, None);
        let verbose = definition_of(&tool, crate::agents::ToolSteering::Verbose, None);
        assert_eq!(terse.description, tool.description());
        assert_eq!(verbose.description, tool.verbose_description().unwrap());
        assert_ne!(terse.description, verbose.description);
    }

    /// The search/navigation intel tools each render a verbose,
    /// bash-redirecting description under verbose steering (never the terse
    /// fallback). Anchored on a distinctive phrase from each tool's prose so a
    /// regression that drops back to the terse one-liner fails here.
    #[test]
    fn definition_of_intel_tools_steer_in_verbose_rendering() {
        // (tool, distinctive verbose-only substring from its prose).
        let cases: Vec<(Arc<dyn Tool>, &str)> = vec![
            (Arc::new(tools::intel::CodeTool), "one closed `kind`"),
            (
                Arc::new(tools::intel::SearchTool),
                "When you would reach for `rg`/`grep`",
            ),
            (Arc::new(tools::intel::GraphTool), "indexed graph"),
        ];
        for (tool, needle) in cases {
            let terse = definition_of(&*tool, crate::agents::ToolSteering::Terse, None);
            let verbose = definition_of(&*tool, crate::agents::ToolSteering::Verbose, None);
            assert_eq!(
                terse.description,
                tool.description(),
                "tool `{}` terse steering must use the terse description",
                tool.name()
            );
            assert_eq!(
                verbose.description,
                tool.verbose_description().unwrap(),
                "tool `{}` verbose steering must use the verbose description",
                tool.name()
            );
            assert_ne!(
                verbose.description,
                terse.description,
                "tool `{}` verbose must differ from terse",
                tool.name()
            );
            assert!(
                verbose.description.contains(needle),
                "tool `{}` verbose text missing steer `{needle}`: {}",
                tool.name(),
                verbose.description
            );
        }
    }

    /// The shared `bash` search-hint no longer implies searches should happen
    /// in bash: it is a pure `grep`/`find` → `rg`/`fd` substitution, with no
    /// `for searches` tail, in BOTH the terse and verbose descriptions.
    #[test]
    fn bash_search_hint_drops_for_searches_in_both_steerings() {
        let tool = tools::bash::BashTool::new();
        let terse = definition_of(&tool, crate::agents::ToolSteering::Terse, None);
        let verbose = definition_of(&tool, crate::agents::ToolSteering::Verbose, None);
        assert!(
            !terse.description.contains("for searches"),
            "terse bash description still says `for searches`: {}",
            terse.description
        );
        assert!(
            !verbose.description.contains("for searches"),
            "verbose bash description still says `for searches`: {}",
            verbose.description
        );
    }

    /// A tool with no verbose override falls back to the terse form under both
    /// steerings (the `None`-keeper path — custom-bash tools rely on this).
    #[test]
    fn definition_of_falls_back_when_no_verbose_variant() {
        struct Terse;
        #[async_trait]
        impl Tool for Terse {
            fn name(&self) -> &str {
                "terse"
            }
            fn description(&self) -> &str {
                "terse one-liner"
            }
            fn parameters(&self) -> Value {
                serde_json::json!({"type": "object", "properties": {}})
            }
            async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
                Ok(ToolOutput::text(""))
            }
        }
        let t = Terse;
        assert_eq!(
            definition_of(&t, crate::agents::ToolSteering::Terse, None).description,
            definition_of(&t, crate::agents::ToolSteering::Verbose, None).description,
            "a tool with no verbose variant renders identically under both steerings"
        );
    }

    /// TERSE-STEERING BUDGET GUARD: every built-in tool's terse description
    /// stays within the token-economy budget. Verbose growth is the intended
    /// tradeoff and is exempt. One sentence ≈ under ~200 chars is the terse
    /// bar; `bash` gets a larger budget because it is high-frequency and must
    /// steer models away from routing around the dedicated file/search tools.
    #[test]
    fn terse_mode_descriptions_stay_within_budget() {
        for tool in all_builtin_tools() {
            for steering in [crate::agents::ToolSteering::Terse] {
                let def = definition_of(&*tool, steering, None);
                let budget = match tool.name() {
                    "bash" => 400,
                    "schedule" => 280,
                    "write" => 240,
                    _ => 200,
                };
                assert!(
                    def.description.len() <= budget,
                    "tool `{}` {steering:?} description exceeds the terse budget ({} chars): {}",
                    tool.name(),
                    def.description.len(),
                    def.description
                );
            }
        }
    }

    /// PER-AGENT AXIS: an override replaces the rendered description text for
    /// the active steering while leaving the SCHEMA untouched, and composes
    /// with the terse/verbose axis. An absent steering override falls back to
    /// the tool's own rendering.
    #[test]
    fn definition_of_applies_per_agent_override_and_composes_with_steering() {
        let tool = tools::read::ReadTool;
        let ov = ToolDescOverride {
            text: Some("agent-specific terse intent".to_string()),
            verbose_text: Some("agent-specific explicit steering intent".to_string()),
        };
        let terse = definition_of(&tool, crate::agents::ToolSteering::Terse, Some(&ov));
        let verbose = definition_of(&tool, crate::agents::ToolSteering::Verbose, Some(&ov));
        // Per-agent text wins over the tool's own description in each steering.
        assert_eq!(terse.description, "agent-specific terse intent");
        assert_eq!(
            verbose.description,
            "agent-specific explicit steering intent"
        );
        // The two steerings select different text.
        assert_ne!(terse.description, verbose.description);
        // SCHEMA is identical to the no-override form — only the description
        // changed. The tool's own (steering-specific) parameters are untouched.
        assert_eq!(
            terse.parameters,
            definition_of(&tool, crate::agents::ToolSteering::Terse, None).parameters
        );
        assert_eq!(
            verbose.parameters,
            definition_of(&tool, crate::agents::ToolSteering::Verbose, None).parameters
        );
    }

    /// A partial override (text for only one steering) leaves the other on
    /// the tool's own base description — the fallback contract.
    #[test]
    fn definition_of_partial_override_falls_back_per_steering() {
        let tool = tools::read::ReadTool;
        let ov = ToolDescOverride {
            text: Some("only terse is overridden".to_string()),
            verbose_text: None,
        };
        assert_eq!(
            definition_of(&tool, crate::agents::ToolSteering::Terse, Some(&ov)).description,
            "only terse is overridden"
        );
        // Verbose falls through to the tool's own verbose description.
        assert_eq!(
            definition_of(&tool, crate::agents::ToolSteering::Verbose, Some(&ov)).description,
            tool.verbose_description().unwrap()
        );
    }

    #[test]
    fn override_cannot_silently_clobber_verbose_description() {
        struct FakeTool;

        #[async_trait]
        impl Tool for FakeTool {
            fn name(&self) -> &str {
                "fake"
            }

            fn description(&self) -> &str {
                "fake terse"
            }

            fn verbose_description(&self) -> Option<String> {
                Some("fake verbose".to_string())
            }

            fn parameters(&self) -> Value {
                serde_json::json!({"type": "object", "properties": {}})
            }

            async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
                Ok(ToolOutput::text(""))
            }
        }

        let tool = FakeTool;
        let ov = ToolDescOverride {
            text: Some("terse override only".to_string()),
            verbose_text: None,
        };

        assert_eq!(
            definition_of(&tool, crate::agents::ToolSteering::Terse, Some(&ov)).description,
            "terse override only"
        );
        // With no verbose_text, Verbose falls back to the tool's own verbose
        // description (the override only supplied terse text).
        assert_eq!(
            definition_of(&tool, crate::agents::ToolSteering::Verbose, Some(&ov)).description,
            tool.verbose_description().unwrap()
        );
    }

    /// SAME ID + SAME SCHEMA, DIFFERENT DESCRIPTION: two toolboxes holding the
    /// same tool but different per-agent overrides advertise the same tool ID
    /// and identical parameters, with different description text encoding
    /// different intent.
    #[test]
    fn two_agents_same_tool_differ_only_in_description() {
        let build_box = ToolBox::new()
            .with(Arc::new(tools::read::ReadTool))
            .with_override(
                "read",
                ToolDescOverride {
                    text: Some("Build: skim before delegating".to_string()),
                    verbose_text: None,
                },
            );
        let builder_box = ToolBox::new()
            .with(Arc::new(tools::read::ReadTool))
            .with_override(
                "read",
                ToolDescOverride {
                    text: Some("builder: read the file you will edit yourself".to_string()),
                    verbose_text: None,
                },
            );
        let a = &build_box.definitions(crate::agents::ToolSteering::Terse)[0];
        let b = &builder_box.definitions(crate::agents::ToolSteering::Terse)[0];
        // Same ID.
        assert_eq!(a.name, "read");
        assert_eq!(a.name, b.name);
        // Same SCHEMA.
        assert_eq!(a.parameters, b.parameters);
        // Different description text.
        assert_ne!(a.description, b.description);
    }

    /// CACHE-SAFETY: the serialized tools array is byte-stable across repeated
    /// renders for a given `(agent, steering)`. An empty override is dropped, so a
    /// box with a no-op override serializes identically to one without any.
    #[test]
    fn toolbox_definitions_are_byte_stable_with_overrides() {
        let tb = ToolBox::new()
            .with(Arc::new(tools::read::ReadTool))
            .with(Arc::new(tools::bash::BashTool::new()))
            .with_override(
                "read",
                ToolDescOverride {
                    text: Some("agent intent".to_string()),
                    verbose_text: Some("agent intent, explicit".to_string()),
                },
            );
        let first =
            serde_json::to_string(&tb.definitions(crate::agents::ToolSteering::Terse)).unwrap();
        let second =
            serde_json::to_string(&tb.definitions(crate::agents::ToolSteering::Terse)).unwrap();
        assert_eq!(first, second, "tools array must be byte-stable per render");

        // An all-`None` override is a no-op: the box serializes identically to
        // one that never registered it.
        let no_override = ToolBox::new()
            .with(Arc::new(tools::read::ReadTool))
            .with(Arc::new(tools::bash::BashTool::new()));
        let empty_override = no_override.clone().with_override(
            "read",
            ToolDescOverride {
                text: None,
                verbose_text: None,
            },
        );
        assert_eq!(
            serde_json::to_string(&no_override.definitions(crate::agents::ToolSteering::Terse))
                .unwrap(),
            serde_json::to_string(&empty_override.definitions(crate::agents::ToolSteering::Terse))
                .unwrap(),
            "an empty override must not change the serialized tools array"
        );
    }

    #[test]
    fn btw_tool_effect_metadata_complete() {
        let expected = [
            ("bash", ToolEffect::Dynamic),
            ("add-package", ToolEffect::Dynamic),
            ("change_impact", ToolEffect::ReadOnly),
            ("code", ToolEffect::Dynamic),
            ("context_pack", ToolEffect::Dynamic),
            ("defer_to_orchestrator", ToolEffect::Dynamic),
            ("delegation_payload_retrieve", ToolEffect::Dynamic),
            ("delete", ToolEffect::Dynamic),
            ("edit", ToolEffect::Dynamic),
            ("escalate", ToolEffect::Dynamic),
            // Media tools: audio/video inspection (read-only) and derivation
            // (mutating), image read (read-only), and image generation.
            ("inspect_audio", ToolEffect::ReadOnly),
            ("inspect_video", ToolEffect::ReadOnly),
            ("extract_video_clip", ToolEffect::Mutating),
            ("extract_audio", ToolEffect::Mutating),
            ("read_image", ToolEffect::ReadOnly),
            ("ask_image", ToolEffect::ReadOnly),
            #[cfg(feature = "extended")]
            ("list_image_generation_targets", ToolEffect::ReadOnly),
            #[cfg(feature = "extended")]
            ("generate_image", ToolEffect::Dynamic),
            #[cfg(feature = "extended")]
            ("get_image_generation_job", ToolEffect::ReadOnly),
            #[cfg(feature = "extended")]
            ("cancel_image_generation_job", ToolEffect::Dynamic),
            ("graph", ToolEffect::ReadOnly),
            ("glob", ToolEffect::ReadOnly),
            ("grep", ToolEffect::ReadOnly),
            ("harness_invoke", ToolEffect::Dynamic),
            ("harness_list", ToolEffect::Dynamic),
            ("list-packages", ToolEffect::Dynamic),
            ("lsp", ToolEffect::ReadOnly),
            ("mcp", ToolEffect::Dynamic),
            ("note", ToolEffect::Dynamic),
            ("question", ToolEffect::Dynamic),
            ("raise", ToolEffect::Mutating),
            ("read", ToolEffect::ReadOnly),
            ("return", ToolEffect::Dynamic),
            ("schedule", ToolEffect::Dynamic),
            ("search", ToolEffect::Dynamic),
            ("history_search", ToolEffect::ReadOnly),
            ("thread_start", ToolEffect::Mutating),
            ("skill", ToolEffect::Dynamic),
            ("skill_manage", ToolEffect::Dynamic),
            ("spawn", ToolEffect::Dynamic),
            ("start_build", ToolEffect::Dynamic),
            ("task", ToolEffect::Dynamic),
            ("todo", ToolEffect::Dynamic),
            ("transcribe_audio", ToolEffect::Mutating),
            ("unlock", ToolEffect::Dynamic),
            ("use_sealed_value", ToolEffect::Dynamic),
            ("webfetch", ToolEffect::Dynamic),
            ("websearch", ToolEffect::Dynamic),
            ("worktree_orchestrate", ToolEffect::Mutating),
            ("write", ToolEffect::Dynamic),
        ];
        let expected: BTreeMap<String, _> = expected
            .into_iter()
            .map(|(name, effect)| (name.to_string(), effect))
            .collect();
        let actual: BTreeMap<_, _> = crate::engine::builtin::invariant_builtin_tools()
            .into_iter()
            .map(|tool| (tool.name().to_string(), tool.effect()))
            .collect();

        assert_eq!(actual, expected);

        struct Unknown;
        #[async_trait]
        impl Tool for Unknown {
            fn name(&self) -> &str {
                "unknown"
            }

            fn description(&self) -> &str {
                "unknown dynamic tool"
            }

            fn parameters(&self) -> serde_json::Value {
                serde_json::Value::Null
            }

            async fn call(&self, _args: serde_json::Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
                Ok(ToolOutput::text("ok"))
            }
        }

        assert_eq!(Unknown.effect(), ToolEffect::Dynamic);
    }

    #[test]
    fn presentation_seam_has_a_default() {
        struct DefaultPresentationTool;
        #[async_trait]
        impl Tool for DefaultPresentationTool {
            fn name(&self) -> &str {
                "plain"
            }

            fn description(&self) -> &str {
                "plain test tool"
            }

            fn parameters(&self) -> serde_json::Value {
                serde_json::Value::Null
            }

            async fn call(&self, _args: serde_json::Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
                Ok(ToolOutput::text("ok"))
            }
        }

        struct CustomPresentationTool;
        #[async_trait]
        impl Tool for CustomPresentationTool {
            fn name(&self) -> &str {
                "custom"
            }

            fn description(&self) -> &str {
                "custom test tool"
            }

            fn parameters(&self) -> serde_json::Value {
                serde_json::Value::Null
            }

            fn presentation(&self, args: &serde_json::Value) -> ToolPresentation {
                let (summary, full_input) = readable_args(args);
                ToolPresentation::with_parts(Some("★"), "custom_label", summary, full_input)
            }

            async fn call(&self, _args: serde_json::Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
                Ok(ToolOutput::text("ok"))
            }
        }

        let args = serde_json::json!({ "path": "src/lib.rs" });
        let default = DefaultPresentationTool.presentation(&args);
        assert_eq!(default.glyph, None);
        assert_eq!(default.label, "plain");
        assert_eq!(default.summary, "path=\"src/lib.rs\"");

        let custom = CustomPresentationTool.presentation(&args);
        assert_eq!(custom.glyph, Some("★"));
        assert_eq!(custom.label, "custom_label");
        assert_eq!(custom.summary, "path=\"src/lib.rs\"");
    }
}
