use std::collections::BTreeSet;

use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbiguousTaskCall {
    pub action: String,
    pub task_call_id: String,
}

impl AmbiguousTaskCall {
    pub fn model_message(&self) -> String {
        format!(
            "`task` call was ambiguous:\n  - set `action=\"{}\"` and `task_call_id=\"{}\"` (query existing child)\n  - set `agent` and `prompt` (fresh delegation)\nFix it by removing one set or the other and retrying.",
            self.action, self.task_call_id
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskControlIntent {
    Models,
    List,
    Status,
    Cancel,
    Query,
    Steer,
}

impl TaskControlIntent {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "models" => Some(Self::Models),
            "list" => Some(Self::List),
            "status" => Some(Self::Status),
            "cancel" => Some(Self::Cancel),
            "query" => Some(Self::Query),
            "steer" => Some(Self::Steer),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Models => "models",
            Self::List => "list",
            Self::Status => "status",
            Self::Cancel => "cancel",
            Self::Query => "query",
            Self::Steer => "steer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedTaskArgs {
    Delegate {
        args: Value,
        notes: Vec<String>,
    },
    Batch {
        entries: Vec<Value>,
        why: String,
        notes: Vec<String>,
    },
    Control {
        intent: TaskControlIntent,
        control: Value,
        notes: Vec<String>,
    },
}

impl ParsedTaskArgs {
    pub fn notes(&self) -> &[String] {
        match self {
            Self::Delegate { notes, .. }
            | Self::Batch { notes, .. }
            | Self::Control { notes, .. } => notes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskArgsRepairError {
    Ambiguous(AmbiguousTaskCall),
    Invalid(String),
}

impl TaskArgsRepairError {
    pub fn model_message(&self) -> String {
        match self {
            Self::Ambiguous(err) => err.model_message(),
            Self::Invalid(msg) => msg.clone(),
        }
    }
}

const DELEGATE_KEYS: &[&str] = &[
    "agent",
    "prompt",
    "mode",
    "model",
    "why",
    "resume_handle",
    "grant_tools",
    "seed",
    "skill_seed",
    "todo_ids",
];

const CONTROL_KEYS: &[&str] = &["task_call_id", "label", "message"];

pub fn parse_task_args(
    args: &Value,
    known_task_call_ids: &BTreeSet<String>,
) -> Result<ParsedTaskArgs, TaskArgsRepairError> {
    let Some(original) = args.as_object() else {
        return Err(TaskArgsRepairError::Invalid(
            "`task` arguments must be an object with `intent` plus one payload".to_string(),
        ));
    };

    let had_empty_batch = empty_array(original.get("payload"))
        || empty_array(original.get("batch"))
        || empty_array(original.get("parallel"));
    let (normalized, dropped_empty_defaults) = prune_empty_defaults(args);
    let root = normalized
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut notes = Vec::new();
    if dropped_empty_defaults {
        notes.push("dropped empty/default task fields before intent selection".to_string());
    }

    if let Some(intent_value) = root.get("intent") {
        let Some(intent) = intent_value
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return Err(TaskArgsRepairError::Invalid(
                "`intent` must be a string".to_string(),
            ));
        };
        return parse_explicit_intent(intent, &root, had_empty_batch, notes);
    }

    parse_legacy_shape(&root, had_empty_batch, notes, known_task_call_ids)
}

fn parse_explicit_intent(
    intent: &str,
    root: &Map<String, Value>,
    had_empty_batch: bool,
    mut notes: Vec<String>,
) -> Result<ParsedTaskArgs, TaskArgsRepairError> {
    match intent {
        "delegate" => {
            let payload = meaningful_payload(root);
            if payload.is_some() {
                reject_non_empty_conflicts(
                    root,
                    &["delegate", "batch", "parallel", "control"],
                    "delegate",
                )?;
                reject_legacy_delegate_conflicts(root, "delegate")?;
                if meaningful_string(root.get("action")).is_some() {
                    return Err(ambiguous_shapes("delegate", "control"));
                }
                let delegate = payload_object(root, "delegate")?;
                validate_delegate(&delegate, "payload")?;
                notes.push("parsed canonical `payload` for `intent=\"delegate\"`".to_string());
                return Ok(ParsedTaskArgs::Delegate {
                    args: Value::Object(delegate),
                    notes,
                });
            }
            reject_non_empty_conflicts(root, &["batch", "parallel", "control"], "delegate")?;
            if meaningful_string(root.get("action")).is_some() {
                return Err(ambiguous_shapes("delegate", "control"));
            }
            let delegate = payload_or_legacy_delegate(root);
            validate_delegate(&delegate, "delegate")?;
            if root.get("delegate").is_some() {
                notes.push(
                    "converted legacy sibling `delegate` payload to canonical `payload`"
                        .to_string(),
                );
            }
            Ok(ParsedTaskArgs::Delegate {
                args: Value::Object(delegate),
                notes,
            })
        }
        "batch" => {
            let payload = meaningful_payload(root);
            let entries = if payload.is_some() {
                reject_non_empty_conflicts(
                    root,
                    &["delegate", "batch", "parallel", "control"],
                    "batch",
                )?;
                reject_legacy_delegate_conflicts(root, "batch")?;
                if meaningful_string(root.get("action")).is_some() {
                    return Err(ambiguous_shapes("batch", "control"));
                }
                let entries = payload_array(root, "batch")?;
                notes.push("parsed canonical `payload` for `intent=\"batch\"`".to_string());
                entries
            } else {
                reject_non_empty_conflicts(root, &["delegate", "control"], "batch")?;
                if has_meaningful_legacy_delegate(root) {
                    return Err(ambiguous_shapes("batch", "delegate"));
                }
                if meaningful_string(root.get("action")).is_some() {
                    return Err(ambiguous_shapes("batch", "control"));
                }
                root.get("batch")
                    .or_else(|| root.get("parallel"))
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
            };
            if entries.is_empty() {
                return Err(empty_batch_error(had_empty_batch));
            }
            if root.get("parallel").is_some() {
                notes.push(
                    "converted legacy top-level `parallel` to `intent=\"batch\"`".to_string(),
                );
            } else if root.get("batch").is_some() {
                notes.push(
                    "converted legacy sibling `batch` payload to canonical `payload`".to_string(),
                );
            }
            Ok(ParsedTaskArgs::Batch {
                entries: repair_batch_entries(entries, &mut notes),
                why: root
                    .get("why")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                notes,
            })
        }
        "models" | "list" | "status" | "cancel" | "query" | "steer" => {
            let payload = meaningful_payload(root);
            if payload.is_some() {
                reject_non_empty_conflicts(
                    root,
                    &["delegate", "batch", "parallel", "control"],
                    "control",
                )?;
                reject_legacy_delegate_conflicts(root, "control")?;
            } else {
                reject_non_empty_conflicts(root, &["delegate", "batch", "parallel"], "control")?;
                if has_meaningful_legacy_delegate(root) {
                    return Err(ambiguous_shapes("control", "delegate"));
                }
            }
            if let Some(action) = meaningful_string(root.get("action"))
                && action != intent
            {
                return Err(TaskArgsRepairError::Invalid(format!(
                    "`intent` is `{intent}` but legacy `action` is `{action}`; choose one task control intent"
                )));
            }
            let control = if payload.is_some() {
                notes.push(format!(
                    "parsed canonical `payload` for `intent=\"{intent}\"`"
                ));
                payload_object(root, intent)?
            } else {
                let control = payload_or_legacy_control(root);
                if root.get("control").is_some() {
                    notes.push(
                        "converted legacy sibling `control` payload to canonical `payload`"
                            .to_string(),
                    );
                }
                control
            };
            let intent = TaskControlIntent::parse(intent).expect("validated task intent");
            validate_control(
                &intent,
                &control,
                if payload.is_some() {
                    "payload"
                } else {
                    "control"
                },
            )?;
            Ok(ParsedTaskArgs::Control {
                intent,
                control: Value::Object(control),
                notes,
            })
        }
        other => Err(TaskArgsRepairError::Invalid(format!(
            "unknown task intent `{other}`; allowed values: delegate, batch, models, list, status, cancel, query, steer"
        ))),
    }
}

fn parse_legacy_shape(
    root: &Map<String, Value>,
    had_empty_batch: bool,
    mut notes: Vec<String>,
    known_task_call_ids: &BTreeSet<String>,
) -> Result<ParsedTaskArgs, TaskArgsRepairError> {
    let fresh = has_meaningful_legacy_delegate(root);
    let batch = root.get("parallel").and_then(Value::as_array).cloned();
    let action = meaningful_string(root.get("action"));

    if fresh {
        if let Some(items) = batch.as_ref()
            && !items.is_empty()
        {
            return Err(ambiguous_shapes("delegate", "batch"));
        }
        if let Some(action) = action {
            let task_call_id = root
                .get("task_call_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if let Some(task_call_id) = task_call_id
                && known_task_call_ids.contains(task_call_id)
            {
                return Err(TaskArgsRepairError::Ambiguous(AmbiguousTaskCall {
                    action: action.to_string(),
                    task_call_id: task_call_id.to_string(),
                }));
            }
            let agent = root
                .get("agent")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let unmatched_task_call_id =
                task_call_id.filter(|id| !known_task_call_ids.contains(*id));
            notes.push(fresh_action_dropped_note(agent, unmatched_task_call_id));
            if action == "list" {
                notes.push(
                    "you probably wanted `task({\"intent\":\"list\"})` with no other fields; did you mean to spawn a new delegation instead?"
                        .to_string(),
                );
            }
        }
        notes.push(
            "converted legacy top-level `agent`/`prompt` task call to `intent=\"delegate\"`"
                .to_string(),
        );
        let delegate = payload_or_legacy_delegate(root);
        validate_delegate(&delegate, "delegate")?;
        return Ok(ParsedTaskArgs::Delegate {
            args: Value::Object(delegate),
            notes,
        });
    }

    if let Some(entries) = batch
        && !entries.is_empty()
    {
        if action.is_some() {
            return Err(ambiguous_shapes("batch", "control"));
        }
        notes.push("converted legacy top-level `parallel` to `intent=\"batch\"`".to_string());
        return Ok(ParsedTaskArgs::Batch {
            entries: repair_batch_entries(entries, &mut notes),
            why: root
                .get("why")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            notes,
        });
    }

    if let Some(action) = action {
        let Some(intent) = TaskControlIntent::parse(action) else {
            return Err(TaskArgsRepairError::Invalid(format!(
                "unknown task action `{action}`; use `intent` with one of: delegate, batch, models, list, status, cancel, query, steer"
            )));
        };
        notes.push(format!(
            "converted legacy top-level `action` to `intent=\"{}\"`",
            intent.as_str()
        ));
        let control = payload_or_legacy_control(root);
        validate_control(&intent, &control, "control")?;
        return Ok(ParsedTaskArgs::Control {
            intent,
            control: Value::Object(control),
            notes,
        });
    }

    if had_empty_batch {
        return Err(empty_batch_error(true));
    }

    Err(TaskArgsRepairError::Invalid(
        "`task` needs one shape: {\"intent\":\"delegate\",\"delegate\":{\"agent\":\"builder\",\"prompt\":\"...\"}}, {\"intent\":\"batch\",\"batch\":[...]}, or a control intent like {\"intent\":\"models\"}".to_string(),
    ))
}

fn prune_empty_defaults(value: &Value) -> (Option<Value>, bool) {
    match value {
        Value::Null => (None, true),
        Value::String(s) if s.trim().is_empty() => (None, true),
        Value::Array(items) => {
            let mut changed = false;
            let mut out = Vec::new();
            for item in items {
                let (pruned, item_changed) = prune_empty_defaults(item);
                changed |= item_changed;
                if let Some(pruned) = pruned {
                    out.push(pruned);
                } else {
                    changed = true;
                }
            }
            if out.is_empty() {
                (None, true)
            } else {
                (Some(Value::Array(out)), changed)
            }
        }
        Value::Object(object) => {
            let mut changed = false;
            let mut out = Map::new();
            for (key, item) in object {
                let (pruned, item_changed) = prune_empty_defaults(item);
                changed |= item_changed;
                if let Some(pruned) = pruned {
                    out.insert(key.clone(), pruned);
                } else {
                    changed = true;
                }
            }
            if out.is_empty() {
                (None, true)
            } else {
                (Some(Value::Object(out)), changed)
            }
        }
        _ => (Some(value.clone()), false),
    }
}

fn payload_or_legacy_delegate(root: &Map<String, Value>) -> Map<String, Value> {
    let mut out = root
        .get("delegate")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for key in DELEGATE_KEYS {
        if !out.contains_key(*key)
            && let Some(value) = root.get(*key)
        {
            out.insert((*key).to_string(), value.clone());
        }
    }
    out
}

fn meaningful_payload(root: &Map<String, Value>) -> Option<&Value> {
    root.get("payload").filter(|value| is_meaningful(value))
}

fn payload_object(
    root: &Map<String, Value>,
    intent: &str,
) -> Result<Map<String, Value>, TaskArgsRepairError> {
    let Some(payload) = meaningful_payload(root) else {
        return Ok(Map::new());
    };
    payload.as_object().cloned().ok_or_else(|| {
        TaskArgsRepairError::Invalid(format!(
            "`payload` for task {intent} must be an object. {}",
            canonical_example(intent)
        ))
    })
}

fn payload_array(
    root: &Map<String, Value>,
    intent: &str,
) -> Result<Vec<Value>, TaskArgsRepairError> {
    let Some(payload) = meaningful_payload(root) else {
        return Ok(Vec::new());
    };
    payload.as_array().cloned().ok_or_else(|| {
        TaskArgsRepairError::Invalid(format!(
            "`payload` for task {intent} must be an array. {}",
            canonical_example(intent)
        ))
    })
}

fn payload_or_legacy_control(root: &Map<String, Value>) -> Map<String, Value> {
    let mut out = root
        .get("control")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for key in CONTROL_KEYS {
        if !out.contains_key(*key)
            && let Some(value) = root.get(*key)
        {
            out.insert((*key).to_string(), value.clone());
        }
    }
    out
}

fn repair_batch_entries(entries: Vec<Value>, notes: &mut Vec<String>) -> Vec<Value> {
    let mut out = Vec::new();
    for mut entry in entries {
        if let Some(object) = entry.as_object_mut()
            && object.remove("action").is_some()
        {
            let agent = object
                .get("agent")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            notes.push(fresh_action_dropped_note(&agent, None));
        }
        out.push(entry);
    }
    out
}

fn validate_delegate(delegate: &Map<String, Value>, path: &str) -> Result<(), TaskArgsRepairError> {
    if delegate
        .get("agent")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(TaskArgsRepairError::Invalid(format!(
            "`{path}.agent` is required for task delegate. {}",
            canonical_example("delegate")
        )));
    }
    if delegate
        .get("prompt")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(TaskArgsRepairError::Invalid(format!(
            "`{path}.prompt` is required for task delegate. {}",
            canonical_example("delegate")
        )));
    }
    Ok(())
}

fn validate_control(
    intent: &TaskControlIntent,
    control: &Map<String, Value>,
    path: &str,
) -> Result<(), TaskArgsRepairError> {
    if matches!(intent, TaskControlIntent::Query | TaskControlIntent::Steer)
        && control
            .get("message")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
    {
        return Err(TaskArgsRepairError::Invalid(format!(
            "`{path}.message` is required for task {}. {}",
            intent.as_str(),
            canonical_example(intent.as_str())
        )));
    }
    Ok(())
}

fn reject_legacy_delegate_conflicts(
    root: &Map<String, Value>,
    selected: &str,
) -> Result<(), TaskArgsRepairError> {
    let fields: Vec<&str> = DELEGATE_KEYS
        .iter()
        .copied()
        .filter(|key| !(selected == "batch" && *key == "why"))
        .filter(|key| root.get(*key).is_some())
        .collect();
    if fields.is_empty() {
        Ok(())
    } else {
        Err(TaskArgsRepairError::Invalid(format!(
            "`task` call mixes `{selected}` intent canonical `payload` with legacy top-level {}; {}",
            fields
                .iter()
                .map(|field| format!("`{field}`"))
                .collect::<Vec<_>>()
                .join(", "),
            canonical_example(selected)
        )))
    }
}

fn reject_non_empty_conflicts(
    root: &Map<String, Value>,
    keys: &[&str],
    selected: &str,
) -> Result<(), TaskArgsRepairError> {
    let fields: Vec<&str> = keys
        .iter()
        .copied()
        .filter(|key| root.get(*key).is_some())
        .collect();
    if fields.is_empty() {
        Ok(())
    } else {
        Err(TaskArgsRepairError::Invalid(format!(
            "`task` call mixes `{selected}` intent with non-empty {}; {}",
            fields
                .iter()
                .map(|field| format!("`{field}` payload"))
                .collect::<Vec<_>>()
                .join(", "),
            canonical_example(selected)
        )))
    }
}

fn has_meaningful_legacy_delegate(root: &Map<String, Value>) -> bool {
    DELEGATE_KEYS
        .iter()
        .any(|key| root.get(*key).is_some_and(is_meaningful))
}

fn is_meaningful(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(s) => !s.trim().is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        _ => true,
    }
}

fn meaningful_string(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn empty_array(value: Option<&Value>) -> bool {
    value.and_then(Value::as_array).is_some_and(Vec::is_empty)
}

fn ambiguous_shapes(a: &str, b: &str) -> TaskArgsRepairError {
    TaskArgsRepairError::Invalid(format!(
        "`task` call is ambiguous: it contains both {a} and {b} payloads. Use exactly one canonical payload shape: {}, {}, or {}.",
        canonical_example("delegate"),
        canonical_example("batch"),
        canonical_example("query")
    ))
}

fn canonical_example(intent: &str) -> &'static str {
    match intent {
        "delegate" => {
            "Use {\"intent\":\"delegate\",\"payload\":{\"agent\":\"builder\",\"prompt\":\"...\"}}"
        }
        "batch" => {
            "Use {\"intent\":\"batch\",\"payload\":[{\"label\":\"x\",\"agent\":\"explore\",\"prompt\":\"...\"}]}"
        }
        "query" | "steer" => {
            "Use {\"intent\":\"query\",\"payload\":{\"task_call_id\":\"...\",\"message\":\"...\"}}"
        }
        "status" => "Use {\"intent\":\"status\",\"payload\":{\"task_call_id\":\"...\"}}",
        "cancel" => "Use {\"intent\":\"cancel\",\"payload\":{\"task_call_id\":\"...\"}}",
        "models" => "Use {\"intent\":\"models\"}",
        "list" => "Use {\"intent\":\"list\"}",
        _ => "Use {\"intent\":\"delegate\",\"payload\":{\"agent\":\"builder\",\"prompt\":\"...\"}}",
    }
}

fn empty_batch_error(_had_empty_batch: bool) -> TaskArgsRepairError {
    TaskArgsRepairError::Invalid("`batch` must contain 1 to N entries".to_string())
}

fn fresh_action_dropped_note(agent: &str, unmatched_task_call_id: Option<&str>) -> String {
    let mut note = format!(
        "dropped `action` (incompatible with fresh delegation) — treating as fresh spawn of `agent={agent}`"
    );
    if let Some(task_call_id) = unmatched_task_call_id {
        note.push_str(&format!(
            "; task_call_id `{task_call_id}` did not match an active/recent child"
        ));
    }
    note
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn known() -> BTreeSet<String> {
        ["real-id".to_string()].into_iter().collect()
    }

    #[test]
    fn legacy_fresh_delegation_canonicalizes_to_delegate() {
        let args = json!({ "agent": "explore", "prompt": "look" });

        let parsed = parse_task_args(&args, &known()).unwrap();

        let ParsedTaskArgs::Delegate { args, notes } = parsed else {
            panic!("expected delegate");
        };
        assert_eq!(args, json!({ "agent": "explore", "prompt": "look" }));
        assert!(notes.iter().any(|note| note.contains("legacy top-level")));
    }

    #[test]
    fn canonical_payload_delegate_parses_to_delegate() {
        let args = json!({
            "intent": "delegate",
            "payload": {
                "agent": "explore",
                "prompt": "look",
                "model": "cheap_code",
                "grant_tools": ["mcp"]
            }
        });

        let parsed = parse_task_args(&args, &known()).unwrap();

        let ParsedTaskArgs::Delegate { args, notes } = parsed else {
            panic!("expected delegate");
        };
        assert_eq!(
            args,
            json!({
                "agent": "explore",
                "prompt": "look",
                "model": "cheap_code",
                "grant_tools": ["mcp"]
            })
        );
        assert!(
            notes
                .iter()
                .any(|note| note.contains("canonical `payload`"))
        );
    }

    #[test]
    fn canonical_payload_batch_parses_to_batch() {
        let args = json!({
            "intent": "batch",
            "payload": [
                { "label": "one", "agent": "explore", "prompt": "look", "cwd": "repo-a" },
                { "label": "two", "agent": "docs", "prompt": "check API", "cwd": "repo-b", "output_dir": "tmp/out" }
            ],
            "why": "fan out"
        });

        let parsed = parse_task_args(&args, &known()).unwrap();

        let ParsedTaskArgs::Batch {
            entries,
            why,
            notes,
        } = parsed
        else {
            panic!("expected batch");
        };
        assert_eq!(why, "fan out");
        assert_eq!(
            entries,
            vec![
                json!({ "label": "one", "agent": "explore", "prompt": "look", "cwd": "repo-a" }),
                json!({ "label": "two", "agent": "docs", "prompt": "check API", "cwd": "repo-b", "output_dir": "tmp/out" }),
            ]
        );
        assert!(
            notes
                .iter()
                .any(|note| note.contains("canonical `payload`"))
        );
    }

    #[test]
    fn canonical_payload_controls_parse_and_validate_messages() {
        for intent_name in ["status", "cancel"] {
            let args = json!({ "intent": intent_name, "payload": { "task_call_id": "real-id" } });
            let parsed = parse_task_args(&args, &known()).unwrap();
            let ParsedTaskArgs::Control {
                intent, control, ..
            } = parsed
            else {
                panic!("expected control");
            };
            assert_eq!(intent.as_str(), intent_name);
            assert_eq!(control, json!({ "task_call_id": "real-id" }));
        }

        for intent_name in ["query", "steer"] {
            let args = json!({
                "intent": intent_name,
                "payload": { "task_call_id": "real-id", "message": "continue" }
            });
            let parsed = parse_task_args(&args, &known()).unwrap();
            let ParsedTaskArgs::Control {
                intent, control, ..
            } = parsed
            else {
                panic!("expected control");
            };
            assert_eq!(intent.as_str(), intent_name);
            assert_eq!(
                control,
                json!({ "task_call_id": "real-id", "message": "continue" })
            );
        }

        for args in [
            json!({ "intent": "list" }),
            json!({ "intent": "list", "payload": null }),
            json!({ "intent": "list", "payload": {} }),
        ] {
            let parsed = parse_task_args(&args, &known()).unwrap();
            let ParsedTaskArgs::Control {
                intent, control, ..
            } = parsed
            else {
                panic!("expected control");
            };
            assert_eq!(intent, TaskControlIntent::List);
            assert_eq!(control, json!({}));
        }

        let err = parse_task_args(
            &json!({ "intent": "query", "payload": { "task_call_id": "real-id" } }),
            &known(),
        )
        .unwrap_err()
        .model_message();
        assert!(err.contains("`payload.message` is required"), "{err}");
    }

    #[test]
    fn action_with_fresh_delegation_is_dropped_with_hint() {
        let args = json!({ "agent": "explore", "prompt": "look", "action": "query" });

        let parsed = parse_task_args(&args, &known()).unwrap();

        let ParsedTaskArgs::Delegate { args, notes } = parsed else {
            panic!("expected delegate");
        };
        assert_eq!(args, json!({ "agent": "explore", "prompt": "look" }));
        assert!(notes.iter().any(|note| note.contains("dropped `action`")));
        assert!(notes.iter().any(|note| note.contains("agent=explore")));
    }

    #[test]
    fn empty_action_with_fresh_delegation_is_dropped() {
        let args = json!({ "agent": "explore", "prompt": "look", "action": "" });

        let parsed = parse_task_args(&args, &known()).unwrap();

        let ParsedTaskArgs::Delegate { args, notes } = parsed else {
            panic!("expected delegate");
        };
        assert_eq!(args, json!({ "agent": "explore", "prompt": "look" }));
        assert!(
            notes
                .iter()
                .any(|note| note.contains("empty/default task fields"))
        );
    }

    #[test]
    fn nonexistent_control_target_is_dropped_and_named() {
        let args = json!({
            "agent": "explore",
            "prompt": "look",
            "action": "query",
            "task_call_id": "missing-id"
        });

        let parsed = parse_task_args(&args, &known()).unwrap();

        let ParsedTaskArgs::Delegate { args, notes } = parsed else {
            panic!("expected delegate");
        };
        assert_eq!(args, json!({ "agent": "explore", "prompt": "look" }));
        assert!(
            notes
                .iter()
                .any(|note| note.contains("task_call_id `missing-id` did not match"))
        );
    }

    #[test]
    fn real_control_target_with_fresh_fields_is_ambiguous() {
        let args = json!({
            "agent": "explore",
            "prompt": "look",
            "action": "query",
            "task_call_id": "real-id"
        });

        let err = parse_task_args(&args, &known()).unwrap_err();
        let msg = err.model_message();

        assert!(msg.contains("ambiguous"), "{msg}");
        assert!(msg.contains("action=\"query\""), "{msg}");
        assert!(msg.contains("task_call_id=\"real-id\""), "{msg}");
        assert!(msg.contains("agent"), "{msg}");
        assert!(msg.contains("prompt"), "{msg}");
    }

    #[test]
    fn legacy_control_query_requires_message() {
        let args = json!({ "action": "query", "task_call_id": "real-id" });

        let err = parse_task_args(&args, &known()).unwrap_err();

        assert!(
            err.model_message()
                .contains("`control.message` is required for task query")
        );
    }

    #[test]
    fn legacy_control_list_canonicalizes() {
        let args = json!({ "action": "list" });

        let parsed = parse_task_args(&args, &known()).unwrap();

        let ParsedTaskArgs::Control {
            intent,
            control,
            notes,
        } = parsed
        else {
            panic!("expected control");
        };
        assert_eq!(intent, TaskControlIntent::List);
        assert_eq!(control, json!({}));
        assert!(
            notes
                .iter()
                .any(|note| note.contains("legacy top-level `action`"))
        );
    }

    #[test]
    fn parallel_entry_action_is_dropped_without_touching_other_entries() {
        let args = json!({
            "parallel": [
                { "label": "one", "agent": "explore", "prompt": "look", "action": "query" },
                { "label": "two", "agent": "explore", "prompt": "read" }
            ]
        });

        let parsed = parse_task_args(&args, &known()).unwrap();

        let ParsedTaskArgs::Batch {
            entries,
            why,
            notes,
        } = parsed
        else {
            panic!("expected batch");
        };
        assert!(why.is_empty());
        assert_eq!(
            entries,
            vec![
                json!({ "label": "one", "agent": "explore", "prompt": "look" }),
                json!({ "label": "two", "agent": "explore", "prompt": "read" }),
            ]
        );
        assert!(notes.iter().any(|note| note.contains("agent=explore")));
        assert!(
            notes
                .iter()
                .any(|note| note.contains("legacy top-level `parallel`"))
        );
    }

    #[test]
    fn envelope_delegate_ignores_empty_batch_default() {
        let args = json!({
            "intent": "delegate",
            "delegate": { "agent": "builder", "prompt": "fix it" },
            "batch": []
        });

        let parsed = parse_task_args(&args, &known()).unwrap();

        let ParsedTaskArgs::Delegate { args, notes } = parsed else {
            panic!("expected delegate");
        };
        assert_eq!(args, json!({ "agent": "builder", "prompt": "fix it" }));
        assert!(
            notes
                .iter()
                .any(|note| note.contains("empty/default task fields"))
        );
    }

    #[test]
    fn canonical_delegate_ignores_empty_legacy_payload_defaults() {
        let args = json!({
            "intent": "delegate",
            "payload": { "agent": "builder", "prompt": "fix it" },
            "delegate": {},
            "batch": [],
            "control": {}
        });

        let parsed = parse_task_args(&args, &known()).unwrap();

        let ParsedTaskArgs::Delegate { args, notes } = parsed else {
            panic!("expected delegate");
        };
        assert_eq!(args, json!({ "agent": "builder", "prompt": "fix it" }));
        assert!(
            notes
                .iter()
                .any(|note| note.contains("empty/default task fields"))
        );
        assert!(
            notes
                .iter()
                .any(|note| note.contains("canonical `payload`"))
        );
    }

    #[test]
    fn legacy_delegate_ignores_empty_parallel_default() {
        let args = json!({ "agent": "builder", "prompt": "fix it", "parallel": [] });

        let parsed = parse_task_args(&args, &known()).unwrap();

        let ParsedTaskArgs::Delegate { args, notes } = parsed else {
            panic!("expected delegate");
        };
        assert_eq!(args, json!({ "agent": "builder", "prompt": "fix it" }));
        assert!(
            notes
                .iter()
                .any(|note| note.contains("empty/default task fields"))
        );
    }

    #[test]
    fn envelope_batch_rejects_non_empty_delegate_sibling() {
        let args = json!({
            "intent": "batch",
            "batch": [{ "label": "a", "agent": "explore", "prompt": "look" }],
            "delegate": { "agent": "builder", "prompt": "write" }
        });

        let msg = parse_task_args(&args, &known())
            .unwrap_err()
            .model_message();

        assert!(msg.contains("ambiguous") || msg.contains("mixes"), "{msg}");
        assert!(msg.contains("delegate"), "{msg}");
        assert!(msg.contains("batch"), "{msg}");
    }

    #[test]
    fn canonical_batch_rejects_non_empty_delegate_sibling_with_correction() {
        let args = json!({
            "intent": "batch",
            "payload": [{ "label": "a", "agent": "explore", "prompt": "look" }],
            "delegate": { "agent": "builder", "prompt": "write" }
        });

        let msg = parse_task_args(&args, &known())
            .unwrap_err()
            .model_message();

        assert!(msg.contains("delegate"), "{msg}");
        assert!(msg.contains("payload"), "{msg}");
        assert!(
            msg.contains(
                "Use {\"intent\":\"batch\",\"payload\":[{\"label\":\"x\",\"agent\":\"explore\",\"prompt\":\"...\"}]}"
            ),
            "{msg}"
        );
    }

    #[test]
    fn canonical_delegate_rejects_non_empty_legacy_top_level_fields() {
        let args = json!({
            "intent": "delegate",
            "payload": { "agent": "explore", "prompt": "look" },
            "agent": "builder",
            "prompt": "write"
        });

        let msg = parse_task_args(&args, &known())
            .unwrap_err()
            .model_message();

        assert!(msg.contains("legacy top-level"), "{msg}");
        assert!(msg.contains("`agent`"), "{msg}");
        assert!(msg.contains("`prompt`"), "{msg}");
        assert!(
            msg.contains("Use {\"intent\":\"delegate\",\"payload\":{\"agent\":\"builder\",\"prompt\":\"...\"}}"),
            "{msg}"
        );
    }

    #[test]
    fn canonical_batch_empty_payload_is_error() {
        let args = json!({ "intent": "batch", "payload": [] });

        let msg = parse_task_args(&args, &known())
            .unwrap_err()
            .model_message();

        assert!(msg.contains("`batch` must contain 1 to N entries"), "{msg}");
    }

    #[test]
    fn batch_empty_without_other_intent_is_error() {
        let args = json!({ "batch": [] });

        let msg = parse_task_args(&args, &known())
            .unwrap_err()
            .model_message();

        assert!(msg.contains("`batch` must contain 1 to N entries"), "{msg}");
    }

    #[test]
    fn list_allows_empty_control_payload() {
        let args = json!({ "intent": "list", "control": {} });

        let parsed = parse_task_args(&args, &known()).unwrap();

        let ParsedTaskArgs::Control {
            intent, control, ..
        } = parsed
        else {
            panic!("expected control");
        };
        assert_eq!(intent, TaskControlIntent::List);
        assert_eq!(control, json!({}));
    }

    #[test]
    fn models_allows_empty_payload() {
        let args = json!({ "intent": "models" });

        let parsed = parse_task_args(&args, &known()).unwrap();

        let ParsedTaskArgs::Control {
            intent, control, ..
        } = parsed
        else {
            panic!("expected control");
        };
        assert_eq!(intent, TaskControlIntent::Models);
        assert_eq!(control, json!({}));
    }
}
