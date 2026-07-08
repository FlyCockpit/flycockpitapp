use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ToolValidationStatus {
    Valid,
    InvalidTool,
    InvalidSchema,
    UnavailableTool,
    WouldRequireApproval,
    WriteOrLockCapable,
    UnsupportedShape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ToolCategory {
    ReadOnly,
    WriteOrLockCapable,
    Shell,
    Delegation,
    ApprovalRequiring,
    Unknown,
}

#[derive(Debug, Serialize)]
struct ToolCallValidation {
    tool: String,
    status: ToolValidationStatus,
    schema_valid: bool,
    available: bool,
    category: ToolCategory,
    reasons: Vec<String>,
}

#[derive(Debug)]
struct ProposedToolCall {
    name: Option<String>,
    arguments: Option<Value>,
    unsupported: bool,
}

pub(crate) fn validate_tandem_tool_calls(
    request: &Value,
    response: Option<&Value>,
    session_root: &Path,
    tmp_dir: Option<&Path>,
) -> Value {
    let Some(response) = response else {
        return json!([]);
    };
    let available = available_tool_schemas(request);
    let known = known_tool_schemas();
    let calls = extract_tool_calls(response);
    let rows: Vec<ToolCallValidation> = calls
        .into_iter()
        .map(|call| validate_one(call, &available, &known, session_root, tmp_dir))
        .collect();
    json!(rows)
}

fn validate_one(
    call: ProposedToolCall,
    available: &BTreeMap<String, Value>,
    known: &BTreeMap<String, Value>,
    session_root: &Path,
    tmp_dir: Option<&Path>,
) -> ToolCallValidation {
    if call.unsupported {
        return ToolCallValidation {
            tool: call.name.unwrap_or_else(|| "<unknown>".to_string()),
            status: ToolValidationStatus::UnsupportedShape,
            schema_valid: false,
            available: false,
            category: ToolCategory::Unknown,
            reasons: vec!["tool call shape is not recognized".to_string()],
        };
    }

    let Some(name) = call.name else {
        return ToolCallValidation {
            tool: "<unknown>".to_string(),
            status: ToolValidationStatus::UnsupportedShape,
            schema_valid: false,
            available: false,
            category: ToolCategory::Unknown,
            reasons: vec!["tool call is missing a tool name".to_string()],
        };
    };

    let category = classify_tool(&name);
    let mut reasons = Vec::new();
    let is_available = available.contains_key(&name);
    let schema = if let Some(schema) = available.get(&name) {
        schema
    } else if known.contains_key(&name) {
        reasons.push("tool is known but was not available to this tandem turn".to_string());
        return ToolCallValidation {
            tool: name,
            status: ToolValidationStatus::UnavailableTool,
            schema_valid: false,
            available: false,
            category,
            reasons,
        };
    } else {
        reasons.push("tool name is not recognized".to_string());
        return ToolCallValidation {
            tool: name,
            status: ToolValidationStatus::InvalidTool,
            schema_valid: false,
            available: false,
            category,
            reasons,
        };
    };

    let mut args = call.arguments.unwrap_or(Value::Null);
    let repair = crate::engine::repair::repair(&mut args, schema, &name);
    if !repair.valid {
        reasons.push(
            repair
                .error
                .unwrap_or_else(|| "arguments do not satisfy the tool schema".to_string()),
        );
        return ToolCallValidation {
            tool: name,
            status: ToolValidationStatus::InvalidSchema,
            schema_valid: false,
            available: is_available,
            category,
            reasons,
        };
    }

    if name == "bash"
        && let Some(outside) = bash_boundary_violation(&args, session_root, tmp_dir)
    {
        reasons.push(format!(
            "cwd or directory-changing command resolves outside session root: {}",
            outside.display()
        ));
        return ToolCallValidation {
            tool: name,
            status: ToolValidationStatus::WouldRequireApproval,
            schema_valid: true,
            available: is_available,
            category,
            reasons,
        };
    }

    if category == ToolCategory::WriteOrLockCapable {
        reasons.push("tool can mutate files or lock state".to_string());
        return ToolCallValidation {
            tool: name,
            status: ToolValidationStatus::WriteOrLockCapable,
            schema_valid: true,
            available: is_available,
            category,
            reasons,
        };
    }

    ToolCallValidation {
        tool: name,
        status: ToolValidationStatus::Valid,
        schema_valid: true,
        available: is_available,
        category,
        reasons,
    }
}

fn bash_boundary_violation(args: &Value, root: &Path, tmp_dir: Option<&Path>) -> Option<PathBuf> {
    let cwd = args
        .get("cwd")
        .and_then(Value::as_str)
        .map(|s| crate::tools::common::resolve(s, root))
        .unwrap_or_else(|| root.to_path_buf());
    if let Some(outside) = crate::tools::bash::outside_session_boundary(&cwd, root, tmp_dir) {
        return Some(outside);
    }
    let command = args.get("command").and_then(Value::as_str)?;
    crate::tools::bash::command_directory_escape(command, &cwd, root, tmp_dir)
}

fn available_tool_schemas(request: &Value) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    let Some(tools) = request.get("tools").and_then(Value::as_array) else {
        return out;
    };
    for tool in tools {
        if let Some((name, schema)) = tool_name_schema(tool) {
            out.insert(name.to_string(), schema.clone());
        }
    }
    out
}

fn tool_name_schema(tool: &Value) -> Option<(&str, &Value)> {
    if let Some(function) = tool.get("function") {
        let name = function.get("name").and_then(Value::as_str)?;
        let schema = function
            .get("parameters")
            .or_else(|| function.get("input_schema"))
            .unwrap_or(&Value::Null);
        return Some((name, schema));
    }
    let name = tool.get("name").and_then(Value::as_str)?;
    let schema = tool
        .get("parameters")
        .or_else(|| tool.get("input_schema"))
        .unwrap_or(&Value::Null);
    Some((name, schema))
}

fn extract_tool_calls(response: &Value) -> Vec<ProposedToolCall> {
    let mut out = Vec::new();
    collect_tool_calls(response, &mut out);
    out
}

fn collect_tool_calls(value: &Value, out: &mut Vec<ProposedToolCall>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_tool_calls(item, out);
            }
        }
        Value::Object(obj) => {
            if let Some(items) = obj.get("tool_calls").and_then(Value::as_array) {
                for item in items {
                    out.push(parse_openai_tool_call(item));
                }
            }
            if obj
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|t| t == "tool_use" || t == "tool_call")
            {
                out.push(parse_content_tool_call(value));
                return;
            }
            if obj.get("function_call").is_some() {
                out.push(parse_function_call(obj.get("function_call").unwrap()));
            }
            for key in ["choice", "content", "message", "choices", "output"] {
                if let Some(next) = obj.get(key) {
                    collect_tool_calls(next, out);
                }
            }
        }
        _ => {}
    }
}

fn parse_openai_tool_call(value: &Value) -> ProposedToolCall {
    let Some(function) = value.get("function") else {
        return ProposedToolCall {
            name: value
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string),
            arguments: value.get("arguments").cloned(),
            unsupported: true,
        };
    };
    ProposedToolCall {
        name: function
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string),
        arguments: parse_arguments(function.get("arguments")),
        unsupported: false,
    }
}

fn parse_function_call(value: &Value) -> ProposedToolCall {
    ProposedToolCall {
        name: value
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string),
        arguments: parse_arguments(value.get("arguments")),
        unsupported: false,
    }
}

fn parse_content_tool_call(value: &Value) -> ProposedToolCall {
    ProposedToolCall {
        name: value
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string),
        arguments: value
            .get("input")
            .cloned()
            .or_else(|| parse_arguments(value.get("arguments"))),
        unsupported: false,
    }
}

fn parse_arguments(value: Option<&Value>) -> Option<Value> {
    match value {
        Some(Value::String(s)) => serde_json::from_str(s)
            .ok()
            .or_else(|| Some(Value::String(s.clone()))),
        Some(v) => Some(v.clone()),
        None => None,
    }
}

fn known_tool_schemas() -> BTreeMap<String, Value> {
    use crate::engine::tool::Tool;
    use crate::tools;

    let all: Vec<Box<dyn Tool>> = vec![
        Box::new(tools::read::ReadTool),
        Box::new(tools::readlock::ReadlockTool),
        Box::new(tools::writeunlock::WriteunlockTool),
        Box::new(tools::unlock::UnlockTool),
        Box::new(tools::editunlock::EditunlockTool),
        Box::new(tools::bash::BashTool::new()),
        Box::new(tools::intel::TreeTool),
        Box::new(tools::intel::OutlineTool),
        Box::new(tools::intel::SymbolFindTool),
        Box::new(tools::intel::WordTool),
        Box::new(tools::intel::DepsTool),
        Box::new(tools::intel::HotTool),
        Box::new(tools::intel::CircularTool),
        Box::new(tools::intel::SearchTool),
        Box::new(tools::intel::ImpactTool),
        Box::new(tools::task::TaskTool::with_subagents(&[
            "builder", "explore",
        ])),
        Box::new(tools::question::QuestionTool),
        Box::new(tools::skill::SkillTool),
        Box::new(tools::schedule::ScheduleTool),
        Box::new(tools::mcp_tool::McpTool),
    ];
    all.into_iter()
        .map(|tool| (tool.name().to_string(), tool.parameters()))
        .collect()
}

fn classify_tool(name: &str) -> ToolCategory {
    match name {
        "read" | "tree" | "outline" | "symbol_find" | "word" | "deps" | "hot" | "circular"
        | "search" | "impact" => ToolCategory::ReadOnly,
        "bash" => ToolCategory::Shell,
        "task" | "spawn" | "handoff" => ToolCategory::Delegation,
        "question" | "mcp" => ToolCategory::ApprovalRequiring,
        "readlock" | "writeunlock" | "editunlock" | "unlock" => ToolCategory::WriteOrLockCapable,
        _ => ToolCategory::Unknown,
    }
}

#[allow(dead_code)]
fn _known_tool_names_for_tests() -> BTreeSet<String> {
    known_tool_schemas().into_keys().collect()
}
