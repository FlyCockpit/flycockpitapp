//! `task` — delegate to a subagent.
//!
//! This is a structural tool: the engine's [`crate::engine::agent::turn`]
//! special-cases the name `task` and returns
//! [`crate::engine::agent::TurnOutcome::SpawnSubagent`] instead of
//! dispatching here. We still implement the trait so the tool
//! definition (name + description + parameter schema) advertises in
//! exactly one place — the agent.rs dispatcher loop is what enforces
//! the contract.
//!
//! If this ever runs (it shouldn't), we return an error so the
//! divergence is loud rather than silent.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput};

pub struct TaskTool {
    description: String,
    /// The explicit, steering verbose description, built
    /// from the same subagent list (implementation note).
    verbose_description: String,
    parameters: Value,
    /// The verbose parameter schema — same shape + `enum` + required set
    /// as `parameters`, with explicit parameter descriptions.
    verbose_parameters: Value,
}

impl TaskTool {
    /// Build the tool with the agent enum populated from the caller's
    /// available subagents — keeps the schema honest so the model
    /// can't ask to delegate to an agent that doesn't exist.
    ///
    /// `mode` is an optional override of the per-agent default
    /// interactivity. Omitted, the engine routes by the agent's own default
    /// (`builder` is the interactive handoff; everything else runs
    /// noninteractively). An explicit value selects the interactive or
    /// noninteractive subagent path for this call.
    pub fn with_subagents(agents: &[&str]) -> Self {
        Self::with_subagents_inner(agents, None, false)
    }

    pub fn with_recursive_subagents(
        agents: &[&str],
        remaining_depth: u32,
        same_model_only: bool,
    ) -> Self {
        Self::with_subagents_inner(agents, Some(remaining_depth), same_model_only)
    }

    fn with_subagents_inner(
        agents: &[&str],
        remaining_depth: Option<u32>,
        same_model_only: bool,
    ) -> Self {
        let list = agents.join("/");
        let recursion_note = remaining_depth
            .map(|depth| {
                if same_model_only {
                    format!(
                        " Recursive delegation is available with remaining_depth up to {depth}; omit model because the child uses your same resolved model."
                    )
                } else {
                    format!(
                        " Recursive delegation is available with remaining_depth up to {depth}; each child may reduce but not increase that value."
                    )
                }
            })
            .unwrap_or_default();
        let description = format!(
            "Delegate {list}: `intent` plus optional `payload`; separate calls get task IDs, `batch` groups/depends_on work. Use @file, @file:XX-YY, @dir/, or /skill. Backgrounded JSON: task_call_id controls.{recursion_note}"
        );
        // Verbose steering: decompose harder and
        // route narrow pieces through subagents so each does one focused job
        // in its own context and returns a small report
        // (implementation note). Single-writer +
        // leaf-termination are unchanged — they hold under every steering.
        let verbose_description = format!(
            "Hand a single, well-scoped piece of work to a subagent ({list}) instead of doing it \
             yourself inline. Prefer this for any non-trivial sub-task: break the work into \
             narrow pieces and delegate each one, so the subagent does its focused job in its \
             own context and returns just a short report — keeping your own context lean. Write \
             `payload.prompt` as a complete, standalone brief: the goal, the constraints, the exact \
             files involved, and what \"done\" looks like. Use @file, @file:XX-YY, @dir/, and /skill \
             tags in that handoff prompt when the child needs bounded source or skill context — the \
             subagent does NOT see your \
             conversation. An interactive subagent (e.g. the writer or the planning interviewer) \
             takes over the conversation with the user; the others run on their own and report \
             back. Only `builder` may write files, in either case. Use `intent=models` to discover \
             allowed structured model selectors. Model selectors choose capability, category, and \
             cost only: data custody is host policy, so you cannot request a capture-capable \
             child, and delegated routing always applies the redacted untrusted filter. \
             Use exactly one task intent: \
             - delegate: {{ \"intent\": \"delegate\", \"payload\": {{ \"agent\": \"builder\", \"prompt\": \"...\" }} }} \
             - batch: {{ \"intent\": \"batch\", \"payload\": [{{ \"label\": \"x\", \"agent\": \"explore\", \"prompt\": \"...\" }}] }} \
             - models: {{ \"intent\": \"models\" }} \
             - query: {{ \"intent\": \"query\", \"payload\": {{ \"task_call_id\": \"...\", \"message\": \"...\" }} }} \
             If a noninteractive task returns a backgrounded task_delegation JSON envelope, the original tool call is closed and the child is still running detached with result_pending=true. Do not treat it as the report or redelegate solely because it backgrounded; continue the current conversation and use the async task_delegation result or task status/query/list with task_call_id. Read each child status and optional error; backgrounded children can later complete, fail, be cancelled, or be lost. task steer applies at the next child turn boundary only if still running/actionable. resume_handle is not a universal background-task control channel. \
             When explore returns host-authored seed_reads and seed_reads_receipt fields, copy both unchanged to the promptly-following builder delegate payload; the builder executes those read-only calls before its first inference. Multiple independent delegate calls may be emitted separately; each keeps its own call/task lifecycle and the host may run proven read-only children concurrently. Use batch only for one grouped result or explicit depends_on edges. Do not add legacy delegate/batch/control siblings. Query/steer require message."
        );
        let model_selector_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "kind": {
                    "type": "string",
                    "enum": ["exact", "category"]
                },
                "selector": {
                    "type": "string"
                },
                "category": {
                    "type": "string"
                },
                "optimize": {
                    "type": "string",
                    "enum": ["quality", "cost", "balanced"]
                },
                "requires": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["tool_calling", "image_input", "audio_input", "video_input", "reasoning", "structured_outputs"]
                    }
                },
                "min_context_tokens": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "omit unless required"
                }
            },
            "required": ["kind"]
        });
        // A seed carries the exact arguments for one bounded read-only tool.
        // Keep the schema discriminated and closed rather than advertising a
        // free-form object: Responses strict mode rejects open objects, and
        // the tool-specific schemas keep the model from inventing arguments
        // that the implementation child could never replay.
        let seed_read_items: Vec<Value> = [
            ("read", crate::tools::read::ReadTool.parameters()),
            ("grep", crate::tools::grep::GrepTool.parameters()),
            ("code", crate::tools::intel::CodeTool.parameters()),
            ("graph", crate::tools::intel::GraphTool.parameters()),
            ("search", crate::tools::intel::SearchTool.parameters()),
        ]
        .into_iter()
        .map(|(tool, args)| {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "tool": { "type": "string", "enum": [tool] },
                    "args": args
                },
                "required": ["tool", "args"],
                "additionalProperties": false
            })
        })
        .collect();
        let seed_reads_schema = serde_json::json!({
            "type": "array",
            "maxItems": 32,
            "description": "Fresh read-only calls selected by explore; implementation child executes them before its first inference",
            "items": { "anyOf": seed_read_items }
        });
        let delegate_payload = serde_json::json!({
            "type": "object",
            "properties": {
                "agent":  {
                    "type": "string",
                    "description": "`docs` for dependency API usage; `knowledge` for cited KB retrieval; `explore`; `builder`",
                    "enum": agents
                },
                "prompt": {
                    "type": "string",
                    "description": "Brief"
                },
                "mode": {
                    "type": "string",
                    "enum": ["subagent", "subagent_interactive"]
                },
                "model": model_selector_schema.clone(),
                "context": {
                    "type": "string",
                    "enum": ["fresh", "fork"]
                },
                "why": {
                    "type": "string"
                },
                "resume_handle": {
                    "type": "string"
                },
                "cwd": {
                    "type": "string",
                    "description": "Relative paths resolve against the parent session cwd; must stay in workspace"
                },
                "write_scope": {
                    "type": "string",
                    "description": "Write-confined subtree"
                },
                "workspace_lease": {
                    "type": "string",
                    "description": "Containment kind or live host-issued lease UUID"
                },
                "grant_tools": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Extra tools"
                },
                "seed_reads": seed_reads_schema,
                "seed_reads_receipt": {
                    "type": "string",
                    "description": "Opaque host-issued receipt paired with explore-selected seed_reads; copy unchanged"
                },
                "todo_ids": {
                    "type": "array",
                    "items": { "type": "string" }
                },
                "remaining_depth": {
                    "type": "integer",
                    "minimum": 0
                },
                "budget": {
                    "type": "object",
                    "description": "Optional per-delegation spend overlay (maxRounds, maxInputTokens, maxOutputTokens, maxCostMicrousd, maxWallClockSecs). Values are finite integers or \"unlimited\"."
                }
            },
            "required": ["agent", "prompt"]
        });
        let batch_entry = serde_json::json!({
            "type": "object",
            "properties": {
                "label": { "type": "string" },
                "depends_on": {
                    "type": "array",
                    "items": { "type": "string", "minLength": 1 },
                    "description": "Optional sibling labels that must finish before this entry starts; unrelated entries still run concurrently"
                },
                "agent":  {
                    "type": "string",
                    "description": "`docs` for dependency API usage; `knowledge` for cited KB retrieval; `explore`",
                    "enum": agents
                },
                "prompt": {
                    "type": "string",
                    "description": "Brief"
                },
                "model": model_selector_schema.clone(),
                "context": {
                    "type": "string",
                    "enum": ["fresh", "fork"]
                },
                "resume_handle": {
                    "type": "string"
                },
                "cwd": {
                    "type": "string",
                    "description": "Relative paths resolve against the parent session cwd; must stay in workspace"
                },
                "grant_tools": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Extra tools"
                },
                "todo_ids": {
                    "type": "array",
                    "items": { "type": "string" }
                },
                "write_scope": {
                    "type": "string",
                    "description": "Required write-confined subtree"
                },
                "workspace_lease": {
                    "type": "string",
                    "description": "Containment kind or live host-issued lease UUID"
                },
                "remaining_depth": {
                    "type": "integer",
                    "minimum": 0
                },
                "budget": {
                    "type": "object",
                    "description": "Optional per-delegation spend overlay (maxRounds, maxInputTokens, maxOutputTokens, maxCostMicrousd, maxWallClockSecs). Values are finite integers or \"unlimited\"."
                }
            },
            "required": ["agent", "prompt"]
        });
        let control_payload = serde_json::json!({
            "type": "object",
            "properties": {
                "task_call_id": {
                    "type": "string"
                },
                "label": {
                    "type": "string"
                },
                "message": {
                    "type": "string",
                    "description": "Required for query and steer"
                }
            }
        });
        let payload_schema = serde_json::json!({
            "type": ["object", "array", "null"],
            "description": "Payload for intent; use docs for dependency API; query/steer require message",
            "properties": {
                "agent": delegate_payload["properties"]["agent"].clone(),
                "prompt": delegate_payload["properties"]["prompt"].clone(),
                "mode": delegate_payload["properties"]["mode"].clone(),
                "model": delegate_payload["properties"]["model"].clone(),
                "context": delegate_payload["properties"]["context"].clone(),
                "why": delegate_payload["properties"]["why"].clone(),
                "resume_handle": delegate_payload["properties"]["resume_handle"].clone(),
                "cwd": delegate_payload["properties"]["cwd"].clone(),
                "write_scope": delegate_payload["properties"]["write_scope"].clone(),
                "workspace_lease": delegate_payload["properties"]["workspace_lease"].clone(),
                "grant_tools": delegate_payload["properties"]["grant_tools"].clone(),
                "seed_reads": delegate_payload["properties"]["seed_reads"].clone(),
                "seed_reads_receipt": delegate_payload["properties"]["seed_reads_receipt"].clone(),
                "todo_ids": delegate_payload["properties"]["todo_ids"].clone(),
                "remaining_depth": delegate_payload["properties"]["remaining_depth"].clone(),
                "budget": delegate_payload["properties"]["budget"].clone(),
                "task_call_id": control_payload["properties"]["task_call_id"].clone(),
                "label": control_payload["properties"]["label"].clone(),
                "message": control_payload["properties"]["message"].clone()
            },
            "items": batch_entry
        });
        let parameters = serde_json::json!({
            "type": "object",
            "properties": {
                "intent": {
                    "type": "string",
                    "enum": ["delegate", "batch", "models", "list", "status", "cancel", "query", "steer"]
                },
                "payload": payload_schema
            },
            "required": ["intent"]
        });
        let mut verbose_parameters = parameters.clone();
        verbose_parameters["properties"]["payload"]["properties"]["agent"]["description"] = serde_json::json!(
            "Subagent name; for dependency API usage call `docs` first unless exact usage is already in local code; `knowledge` returns cited KB retrieval, `explore` investigates, `builder` writes/edits"
        );
        verbose_parameters["properties"]["payload"]["items"]["properties"]["agent"]["description"] = serde_json::json!(
            "Subagent name; batch entries must target noninteractive agents such as `knowledge`, `explore`, or `docs`; for dependency API usage call `docs` first unless exact usage is already in local code"
        );
        verbose_parameters["properties"]["payload"]["description"] = serde_json::json!(
            "Payload selected by `intent`: delegate uses an object with `agent`/`prompt` (for dependency API usage call `docs` first unless exact usage is already in local code); batch uses an array of entries; models/list may omit/null/{}; status/cancel/query/steer use control fields; query/steer require `message`"
        );
        let defensive_min_context = serde_json::json!(
            "Minimum context tokens; omit unless genuinely required because models with unknown context metadata are rejected when this field is set"
        );
        verbose_parameters["properties"]["payload"]["properties"]["model"]["properties"]["min_context_tokens"]
            ["description"] = defensive_min_context.clone();
        verbose_parameters["properties"]["payload"]["items"]["properties"]["model"]["properties"]
            ["min_context_tokens"]["description"] = defensive_min_context;
        // Data custody is host policy, not a delegation choice. Say so
        // explicitly in the Defensive schema so the model does not try to
        // reintroduce a `trust` field for "sensitive" work.
        let defensive_model_selector = serde_json::json!(
            "Capability/category/cost selector only. Data custody is host policy: there is no `trust` field, delegated routing always applies the redacted untrusted filter, and a capture-capable child cannot be requested here"
        );
        verbose_parameters["properties"]["payload"]["properties"]["model"]["description"] =
            defensive_model_selector.clone();
        verbose_parameters["properties"]["payload"]["items"]["properties"]["model"]["description"] =
            defensive_model_selector;
        Self {
            description,
            verbose_description,
            parameters,
            verbose_parameters,
        }
    }
}

#[async_trait]
impl Tool for TaskTool {
    fn name(&self) -> &str {
        "task"
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn verbose_description(&self) -> Option<String> {
        Some(self.verbose_description.clone())
    }

    fn parameters(&self) -> Value {
        self.parameters.clone()
    }

    fn verbose_parameters(&self) -> Option<Value> {
        Some(self.verbose_parameters.clone())
    }

    async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        Err(anyhow::anyhow!(
            "`task` is intercepted by the engine dispatcher; this code path should be unreachable"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The re-queryable-subagent fields (`why`, `resume_handle`, GOALS §3c)
    /// are present in BOTH the normal and defensive `task` schemas from
    /// session start — a fixed shape so enabling the follow-up path never
    /// reserializes the cached tool prefix (cache safety). They are optional
    /// (not in `required`).
    #[test]
    fn task_schema_carries_context_enum_in_both_modes() {
        let tool = TaskTool::with_subagents(&["explore", "builder"]);
        assert!(
            tool.description()
                .contains("`intent` plus optional `payload`")
        );
        assert!(tool.description().contains("Backgrounded JSON"));
        assert!(tool.description().contains("task_call_id controls"));
        assert!(tool.description().contains("@file"));
        assert!(tool.description().contains("@file:XX-YY"));
        assert!(tool.description().contains("@dir/"));
        assert!(tool.description().contains("/skill"));
        let verbose_description = tool.verbose_description().unwrap();
        assert!(verbose_description.contains("\"intent\": \"delegate\""));
        assert!(verbose_description.contains("\"intent\": \"batch\""));
        assert!(verbose_description.contains("\"intent\": \"query\""));
        assert!(verbose_description.contains("\"payload\""));
        assert!(verbose_description.contains("Query/steer require message"));
        assert!(verbose_description.contains("backgrounded task_delegation JSON envelope"));
        assert!(
            verbose_description
                .contains("resume_handle is not a universal background-task control channel")
        );
        assert!(
            verbose_description.contains(
                "backgrounded children can later complete, fail, be cancelled, or be lost"
            )
        );
        for schema in [tool.parameters(), tool.verbose_parameters().unwrap()] {
            let props = schema["properties"].as_object().unwrap();
            assert!(props.contains_key("intent"), "missing `intent`: {schema}");
            assert!(props.contains_key("payload"), "missing `payload`: {schema}");
            for forbidden in [
                "delegate", "batch", "control", "parallel", "action", "agent", "prompt",
            ] {
                assert!(
                    !props.contains_key(forbidden),
                    "legacy top-level `{forbidden}` must not be advertised: {schema}"
                );
            }
            assert!(
                schema
                    .get("required")
                    .and_then(Value::as_array)
                    .is_some_and(|required| {
                        required.iter().any(|value| value == "intent")
                            && !required.iter().any(|value| value == "payload")
                    }),
                "`intent` is required and `payload` stays optional: {schema}"
            );
            let payload = &props["payload"];
            let payload_desc = payload["description"].as_str().unwrap();
            assert!(
                payload_desc.contains("docs"),
                "payload description should mention docs: {payload_desc}"
            );
            let payload_props = payload["properties"].as_object().unwrap();
            let agent_desc = payload_props["agent"]["description"].as_str().unwrap();
            assert!(
                agent_desc.contains("docs"),
                "agent description should mention docs: {agent_desc}"
            );
            assert!(payload_props.contains_key("why"), "missing `why`: {schema}");
            assert_eq!(
                payload_props["mode"]["enum"],
                serde_json::json!(["subagent", "subagent_interactive"]),
                "delegation advertises exactly the two live modes: {schema}"
            );
            assert!(
                !payload_props.contains_key("value_id"),
                "the retired sealed-fetch target id must not be advertised: {schema}"
            );
            let context = payload_props.get("context").expect("missing context");
            assert_eq!(context["type"], "string");
            let context_enum = context["enum"].as_array().unwrap();
            assert!(context_enum.iter().any(|value| value == "fresh"));
            assert!(context_enum.iter().any(|value| value == "fork"));
            assert!(
                !payload_props["context"]
                    .get("default")
                    .is_some_and(|value| value == "fork"),
                "fork must not be the schema default: {schema}"
            );
            assert!(
                !payload["items"]["required"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|value| value == "context"),
                "batch context must be optional: {schema}"
            );
            assert!(
                payload["items"]["properties"].get("context").is_some(),
                "batch entry schema carries context: {schema}"
            );
            assert!(
                payload_props.contains_key("resume_handle"),
                "missing `resume_handle`: {schema}"
            );
            assert!(payload_props.contains_key("cwd"), "missing `cwd`: {schema}");
            assert!(
                payload_props["cwd"]["description"]
                    .as_str()
                    .unwrap()
                    .contains("Relative paths resolve against the parent session cwd"),
                "cwd describes relative resolution: {schema}"
            );
            // Per-delegation tool grants (`grant_tools`, prompt
            // `parent-granted-tools.md`): present in BOTH modes from session
            // start (cache-safe fixed shape) and optional.
            assert!(
                payload_props.contains_key("grant_tools"),
                "missing `grant_tools`: {schema}"
            );
            assert_eq!(
                payload_props["grant_tools"]["type"], "array",
                "grant_tools is an array: {schema}"
            );
            assert!(
                payload_props.contains_key("budget"),
                "missing per-delegation `budget`: {schema}"
            );
            assert_eq!(
                payload_props["budget"]["type"], "object",
                "budget is an object overlay: {schema}"
            );
            assert_eq!(
                payload_props["seed_reads"]["type"], "array",
                "seed_reads is an array: {schema}"
            );
            assert_eq!(
                payload_props["seed_reads"]["items"]["properties"]["tool"]["enum"],
                serde_json::json!(["read", "grep", "code", "graph", "search"]),
                "seed_reads exposes the closed read-only allowlist: {schema}"
            );
            assert_eq!(
                payload_props["seed_reads_receipt"]["type"], "string",
                "seed_reads carries the opaque host receipt needed to enforce explore provenance: {schema}"
            );
            assert!(
                !payload_props.contains_key("seed"),
                "`seed` should be replaced by handoff tags: {schema}"
            );
            assert!(
                !payload_props.contains_key("skill_seed"),
                "`skill_seed` should be replaced by /skill tags: {schema}"
            );
            assert!(
                !payload["items"]["properties"]
                    .as_object()
                    .unwrap()
                    .contains_key("seed"),
                "batch `seed` should be absent: {schema}"
            );
            assert!(
                !payload["items"]["properties"]
                    .as_object()
                    .unwrap()
                    .contains_key("skill_seed"),
                "batch `skill_seed` should be absent: {schema}"
            );
            assert!(
                payload_props.contains_key("model"),
                "missing `model`: {schema}"
            );
            assert_eq!(
                payload_props["model"]["type"], "object",
                "model selector is structured: {schema}"
            );
            assert!(
                payload_props["model"]["properties"].get("kind").is_some(),
                "model selector exposes kind: {schema}"
            );
            assert_eq!(
                payload["items"]["properties"]["model"]["type"], "object",
                "batch model selector is structured: {schema}"
            );
            assert!(
                payload_props.contains_key("todo_ids"),
                "missing `todo_ids`: {schema}"
            );
            let agent_enum = payload_props["agent"]["enum"].as_array().unwrap();
            assert!(agent_enum.iter().any(|value| value == "explore"));
            let batch_agent_enum = payload["items"]["properties"]["agent"]["enum"]
                .as_array()
                .unwrap();
            assert!(batch_agent_enum.iter().any(|value| value == "explore"));
            assert!(
                payload["items"]["properties"].get("cwd").is_some(),
                "batch entry schema carries cwd: {schema}"
            );
            if schema == tool.verbose_parameters().unwrap() {
                assert!(
                    agent_desc.contains("call `docs` first"),
                    "defensive agent description should steer docs first: {agent_desc}"
                );
                assert!(
                    payload_desc.contains("call `docs` first"),
                    "defensive payload description should steer docs first: {payload_desc}"
                );
            } else {
                assert!(
                    agent_desc.contains("dependency API usage"),
                    "normal agent description should expose docs affordance: {agent_desc}"
                );
            }
            assert!(
                payload.get("default").is_none(),
                "payload must not default to []"
            );
            let control_props = payload_props;
            assert!(
                control_props["message"]["description"]
                    .as_str()
                    .unwrap()
                    .contains("Required for query and steer")
            );
            assert!(schema.get("oneOf").is_none(), "schema must not use oneOf");
        }
    }

    #[test]
    fn task_schema_has_no_seed_or_skill_seed() {
        let tool = TaskTool::with_subagents(&["explore", "builder"]);

        for schema in [tool.parameters(), tool.verbose_parameters().unwrap()] {
            assert_schema_key_absent(&schema, "seed");
            assert_schema_key_absent(&schema, "skill_seed");
        }
    }

    /// AC7 (schema half). The Defensive presentation used to advertise a
    /// `trust` selector and tell the model to "prefer trusted models for
    /// sensitive delegated work" — that let an untrusted parent request
    /// capture-capable routing. Data custody is host policy, so the field is gone
    /// from both schemas and both descriptions say so.
    #[test]
    fn task_schema_has_no_model_trust_selector() {
        let tool = TaskTool::with_subagents(&["explore", "builder"]);
        for schema in [tool.parameters(), tool.verbose_parameters().unwrap()] {
            assert_schema_key_absent(&schema, "trust");
            assert_no_selectable_custody_value(&schema);
        }

        let verbose_description = tool.verbose_description().unwrap();
        assert!(
            !verbose_description.contains("prefer trusted models"),
            "removed steering must not return: {verbose_description}"
        );
        assert!(verbose_description.contains("data custody is host policy"));
        assert!(verbose_description.contains("redacted untrusted filter"));

        let defensive = tool.verbose_parameters().unwrap();
        for description in [
            defensive["properties"]["payload"]["properties"]["model"]["description"]
                .as_str()
                .unwrap(),
            defensive["properties"]["payload"]["items"]["properties"]["model"]["description"]
                .as_str()
                .unwrap(),
        ] {
            assert!(description.contains("Data custody is host policy"));
            assert!(description.contains("no `trust` field"));
        }
    }

    #[test]
    fn task_schema_uses_write_scope_not_output_dir() {
        let tool = TaskTool::with_subagents(&["explore", "builder"]);
        for schema in [tool.parameters(), tool.verbose_parameters().unwrap()] {
            let payload = &schema["properties"]["payload"];
            let payload_props = payload["properties"].as_object().unwrap();
            let batch_props = payload["items"]["properties"].as_object().unwrap();

            assert!(payload_props.contains_key("write_scope"), "{schema}");
            assert!(batch_props.contains_key("write_scope"), "{schema}");
            assert!(payload_props.contains_key("workspace_lease"), "{schema}");
            assert!(batch_props.contains_key("workspace_lease"), "{schema}");
            assert!(!payload_props.contains_key("output_dir"), "{schema}");
            assert!(!batch_props.contains_key("output_dir"), "{schema}");
            assert!(
                !payload["items"]["required"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|value| value == "write_scope"),
                "batch write_scope stays schema-optional: {schema}"
            );
            assert_schema_key_absent(&schema, "output_dir");
        }
    }

    /// No `enum` anywhere in the schema may offer a custody class as a
    /// selectable value.
    fn assert_no_selectable_custody_value(value: &Value) {
        match value {
            Value::Object(map) => {
                if let Some(Value::Array(values)) = map.get("enum") {
                    for entry in values {
                        assert!(
                            entry != "trusted" && entry != "untrusted",
                            "custody must not be selectable: {value}"
                        );
                    }
                }
                for child in map.values() {
                    assert_no_selectable_custody_value(child);
                }
            }
            Value::Array(items) => {
                for child in items {
                    assert_no_selectable_custody_value(child);
                }
            }
            _ => {}
        }
    }

    fn assert_schema_key_absent(value: &Value, key: &str) {
        match value {
            Value::Object(map) => {
                assert!(
                    !map.contains_key(key),
                    "schema still contains `{key}`: {value}"
                );
                for child in map.values() {
                    assert_schema_key_absent(child, key);
                }
            }
            Value::Array(items) => {
                for child in items {
                    assert_schema_key_absent(child, key);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn task_definition_shrinks_after_seed_removal() {
        let tool = TaskTool::with_subagents(&["explore", "builder"]);
        let len = serde_json::to_string(&tool.parameters()).unwrap().len();
        // Observed after seed schema removal plus scoped write support: ~3020
        // bytes; multimodal requires enums add ~200. Keep this low enough that
        // the seed blob cannot return.
        assert!(len < 3300, "task schema serialized to {len} bytes");
    }

    #[test]
    fn min_context_tokens_description_steers_omission() {
        let tool = TaskTool::with_subagents(&["explore", "builder"]);
        let normal = tool.parameters();
        let defensive = tool.verbose_parameters().unwrap();
        let normal_description = normal["properties"]["payload"]["properties"]["model"]
            ["properties"]["min_context_tokens"]["description"]
            .as_str()
            .unwrap();
        assert!(normal_description.contains("omit"));

        for description in [
            defensive["properties"]["payload"]["properties"]["model"]["properties"]
                ["min_context_tokens"]["description"]
                .as_str()
                .unwrap(),
            defensive["properties"]["payload"]["items"]["properties"]["model"]
                ["properties"]["min_context_tokens"]["description"]
                .as_str()
                .unwrap(),
        ] {
            assert!(description.contains("omit"));
            assert!(description.contains("unknown context metadata"));
            assert!(description.contains("rejected"));
        }
    }
}
