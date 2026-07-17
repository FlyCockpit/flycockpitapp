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
    /// The explicit, steering [`LlmMode::Defensive`] description, built
    /// from the same subagent list (implementation note).
    defensive_description: String,
    parameters: Value,
    /// The defensive parameter schema — same shape + `enum` + required set
    /// as `parameters`, with explicit parameter descriptions.
    defensive_parameters: Value,
}

impl TaskTool {
    /// Build the tool with the agent enum populated from the caller's
    /// available subagents — keeps the schema honest so the model
    /// can't ask to delegate to an agent that doesn't exist.
    ///
    /// `mode` is an optional override of the per-agent default
    /// interactivity. Omitted, the engine routes by the agent's own default
    /// (`builder` is the interactive handoff; everything else runs
    /// noninteractively). The explicit value is the seam the future
    /// LLM-strategy axis switches on (`open design questions`):
    /// the interactive-subagent path is the one wired today.
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
            "Delegate/control subagents ({list}) with `intent` plus optional `payload`. Backgrounded JSON means call closed, child detached/result pending; use task_call_id controls or async result.{recursion_note}"
        );
        // Defensive (`LlmMode::Defensive`) steering: decompose harder and
        // route narrow pieces through subagents so each does one focused job
        // in its own context and returns a small report
        // (implementation note). Single-writer +
        // leaf-termination are unchanged — they hold in every LLM mode.
        let defensive_description = format!(
            "Hand a single, well-scoped piece of work to a subagent ({list}) instead of doing it \
             yourself inline. Prefer this for any non-trivial sub-task: break the work into \
             narrow pieces and delegate each one, so the subagent does its focused job in its \
             own context and returns just a short report — keeping your own context lean. Write \
             `payload.prompt` as a complete, standalone brief: the goal, the constraints, the exact \
             files involved, and what \"done\" looks like — the subagent does NOT see your \
             conversation. An interactive subagent (e.g. the writer or the planning interviewer) \
             takes over the conversation with the user; the others run on their own and report \
             back. Only `builder` may write files, in either case. Use `intent=models` to discover \
             allowed structured model selectors; prefer trusted models for sensitive delegated work. \
             Use exactly one task intent: \
             - delegate: {{ \"intent\": \"delegate\", \"payload\": {{ \"agent\": \"builder\", \"prompt\": \"...\" }} }} \
             - batch: {{ \"intent\": \"batch\", \"payload\": [{{ \"label\": \"x\", \"agent\": \"explore\", \"prompt\": \"...\" }}] }} \
             - models: {{ \"intent\": \"models\" }} \
             - query: {{ \"intent\": \"query\", \"payload\": {{ \"task_call_id\": \"...\", \"message\": \"...\" }} }} \
             If a noninteractive task returns a backgrounded task_delegation JSON envelope, the original tool call is closed and the child is still running detached with result_pending=true. Do not treat it as the report or redelegate solely because it backgrounded; continue the current conversation and use the async task_delegation result or task status/query/list with task_call_id. Read each child status and optional error; backgrounded children can later complete, fail, be cancelled, or be lost. task steer applies at the next child turn boundary only if still running/actionable. resume_handle is not a universal background-task control channel. \
             Do not add legacy delegate/batch/control siblings. Query/steer require message."
        );
        let seed_schema = serde_json::json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "tool": { "type": "string" },
                    "args": { "type": "object" }
                },
                "required": ["tool", "args"]
            },
            "description": "Read-only tool calls re-executed in the child's cwd and pre-loaded into its context; omit otherwise"
        });
        let model_selector_schema = serde_json::json!({
            "type": "object",
            "description": "Optional structured subagent model selector. Discover allowed choices with intent=models. Exact: {\"kind\":\"exact\",\"selector\":\"provider:model\"}. Category: {\"kind\":\"category\",\"category\":\"cheap_code\",\"trust\":\"trusted\",\"optimize\":\"quality\"}. Optional constraints: requires, min_context_tokens",
            "properties": {
                "kind": {
                    "type": "string",
                    "enum": ["exact", "category"],
                    "description": "Selector kind"
                },
                "selector": {
                    "type": "string",
                    "description": "Exact provider:model selector; required when kind=exact"
                },
                "category": {
                    "type": "string",
                    "description": "Policy category such as cheap_code, smart_code, reasoning, or translation"
                },
                "trust": {
                    "type": "string",
                    "enum": ["trusted", "untrusted"],
                    "description": "Optional trust filter"
                },
                "optimize": {
                    "type": "string",
                    "enum": ["quality", "cost", "balanced"],
                    "description": "Category tie-break preference"
                },
                "requires": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["tool_calling", "images", "reasoning", "structured_outputs"]
                    },
                    "description": "Required model capabilities"
                },
                "min_context_tokens": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Minimum context tokens; omit unless the task genuinely requires a minimum"
                }
            },
            "required": ["kind"]
        });
        let delegate_payload = serde_json::json!({
            "type": "object",
            "properties": {
                "agent":  {
                    "type": "string",
                    "description": "Subagent name; `docs` answers dependency API usage from real source, `explore` investigates, `builder` writes/edits",
                    "enum": agents
                },
                "prompt": {
                    "type": "string",
                    "description": "Self-contained brief: goal, constraints, files, what \"done\" looks like"
                },
                "mode": {
                    "type": "string",
                    "description": "Delegation mode override",
                    "enum": ["subagent", "subagent_interactive"]
                },
                "model": model_selector_schema.clone(),
                "why": {
                    "type": "string",
                    "description": "Motivation for this delegation"
                },
                "resume_handle": {
                    "type": "string",
                    "description": "Handle of a prior read-only subagent to re-query"
                },
                "cwd": {
                    "type": "string",
                    "description": "Optional working directory for noninteractive child runs. Relative paths resolve against the parent session cwd; absolute paths must remain inside the trusted workspace and must name an existing directory"
                },
                "grant_tools": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Extra tools to grant this one delegation only if the task needs them (e.g. `mcp`); omit otherwise"
                },
                "seed": seed_schema,
                "skill_seed": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Names of active skills to seed (instructions + framing) into the child when its work is part of resolving that skill; omit otherwise"
                },
                "todo_ids": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Todo UUIDs this subagent is responsible for"
                },
                "remaining_depth": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Optional recursive child-edge budget to grant this child. Omit or use 0 for a leaf child; recursive callers may reduce but never increase their inherited budget"
                }
            },
            "required": ["agent", "prompt"]
        });
        let batch_entry = serde_json::json!({
            "type": "object",
            "properties": {
                "label": { "type": "string", "description": "Stable concise label for this child within the batch" },
                "agent":  {
                    "type": "string",
                    "description": "Subagent name; batch entries must target noninteractive agents such as `explore` or `docs`; use `docs` for dependency API uncertainty",
                    "enum": agents
                },
                "prompt": {
                    "type": "string",
                    "description": "Self-contained brief: goal, constraints, files, what \"done\" looks like"
                },
                "model": model_selector_schema.clone(),
                "resume_handle": {
                    "type": "string",
                    "description": "Handle of a prior read-only subagent to re-query"
                },
                "cwd": {
                    "type": "string",
                    "description": "Optional working directory for this noninteractive child. Relative paths resolve against the parent session cwd; absolute paths must remain inside the trusted workspace and must name an existing directory"
                },
                "grant_tools": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Extra tools to grant this one delegation only if the task needs them; omit otherwise"
                },
                "seed": seed_schema,
                "skill_seed": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Names of active skills to seed into the child"
                },
                "todo_ids": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Todo UUIDs this subagent is responsible for"
                },
                "output_dir": {
                    "type": "string",
                    "description": "Required for write-capable batch entries; child must keep writes under this directory"
                },
                "remaining_depth": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Optional recursive child-edge budget to grant this child. Omit or use 0 for a leaf child; recursive callers may reduce but never increase their inherited budget"
                }
            },
            "required": ["agent", "prompt"]
        });
        let control_payload = serde_json::json!({
            "type": "object",
            "properties": {
                "task_call_id": {
                    "type": "string",
                    "description": "Delegation task_call_id for status/cancel/query/steer when needed to disambiguate"
                },
                "label": {
                    "type": "string",
                    "description": "Child label within a delegation for status/cancel/query/steer"
                },
                "message": {
                    "type": "string",
                    "description": "Required for query and steer only: question for query or steering instruction for steer"
                }
            }
        });
        let payload_schema = serde_json::json!({
            "type": ["object", "array", "null"],
            "description": "Payload selected by `intent`: delegate uses an object with `agent`/`prompt` (use `docs` for dependency API uncertainty); batch uses an array of entries; models/list may omit/null/{}; status/cancel/query/steer use control fields; query/steer require `message`",
            "properties": {
                "agent": delegate_payload["properties"]["agent"].clone(),
                "prompt": delegate_payload["properties"]["prompt"].clone(),
                "mode": delegate_payload["properties"]["mode"].clone(),
                "model": delegate_payload["properties"]["model"].clone(),
                "why": delegate_payload["properties"]["why"].clone(),
                "resume_handle": delegate_payload["properties"]["resume_handle"].clone(),
                "cwd": delegate_payload["properties"]["cwd"].clone(),
                "grant_tools": delegate_payload["properties"]["grant_tools"].clone(),
                "seed": delegate_payload["properties"]["seed"].clone(),
                "skill_seed": delegate_payload["properties"]["skill_seed"].clone(),
                "todo_ids": delegate_payload["properties"]["todo_ids"].clone(),
                "remaining_depth": delegate_payload["properties"]["remaining_depth"].clone(),
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
                    "description": "Choose exactly one task operation: delegate, batch, models, list, status, cancel, query, or steer",
                    "enum": ["delegate", "batch", "models", "list", "status", "cancel", "query", "steer"]
                },
                "payload": payload_schema
            },
            "required": ["intent"]
        });
        let mut defensive_parameters = parameters.clone();
        defensive_parameters["properties"]["payload"]["properties"]["agent"]["description"] = serde_json::json!(
            "Subagent name; for dependency API usage call `docs` first unless exact usage is already in local code; `explore` investigates, `builder` writes/edits"
        );
        defensive_parameters["properties"]["payload"]["items"]["properties"]["agent"]["description"] = serde_json::json!(
            "Subagent name; batch entries must target noninteractive agents such as `explore` or `docs`; for dependency API usage call `docs` first unless exact usage is already in local code"
        );
        defensive_parameters["properties"]["payload"]["description"] = serde_json::json!(
            "Payload selected by `intent`: delegate uses an object with `agent`/`prompt` (for dependency API usage call `docs` first unless exact usage is already in local code); batch uses an array of entries; models/list may omit/null/{}; status/cancel/query/steer use control fields; query/steer require `message`"
        );
        let defensive_min_context = serde_json::json!(
            "Minimum context tokens; omit unless genuinely required because models with unknown context metadata are rejected when this field is set"
        );
        defensive_parameters["properties"]["payload"]["properties"]["model"]["properties"]["min_context_tokens"]
            ["description"] = defensive_min_context.clone();
        defensive_parameters["properties"]["payload"]["items"]["properties"]["model"]["properties"]
            ["min_context_tokens"]["description"] = defensive_min_context;
        Self {
            description,
            defensive_description,
            parameters,
            defensive_parameters,
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

    fn defensive_description(&self) -> Option<String> {
        Some(self.defensive_description.clone())
    }

    fn parameters(&self) -> Value {
        self.parameters.clone()
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(self.defensive_parameters.clone())
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
    fn schema_carries_followup_fields_in_both_modes_and_optional() {
        let tool = TaskTool::with_subagents(&["explore", "builder"]);
        assert!(
            tool.description()
                .contains("`intent` plus optional `payload`")
        );
        assert!(tool.description().contains("Backgrounded JSON"));
        assert!(tool.description().contains("task_call_id controls"));
        assert!(tool.description().len() <= 200);
        let defensive_description = tool.defensive_description().unwrap();
        assert!(defensive_description.contains("\"intent\": \"delegate\""));
        assert!(defensive_description.contains("\"intent\": \"batch\""));
        assert!(defensive_description.contains("\"intent\": \"query\""));
        assert!(defensive_description.contains("\"payload\""));
        assert!(defensive_description.contains("Query/steer require message"));
        assert!(defensive_description.contains("backgrounded task_delegation JSON envelope"));
        assert!(
            defensive_description
                .contains("resume_handle is not a universal background-task control channel")
        );
        assert!(
            defensive_description.contains(
                "backgrounded children can later complete, fail, be cancelled, or be lost"
            )
        );
        for schema in [tool.parameters(), tool.defensive_parameters().unwrap()] {
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
            // Caller→child read-only pre-seeding (`task.seed`,
            // implementation note): present in BOTH modes
            // from session start (cache-safe fixed shape) and optional.
            assert!(
                payload_props.contains_key("seed"),
                "missing `seed`: {schema}"
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
            assert_eq!(
                payload_props["seed"]["type"], "array",
                "seed is an array: {schema}"
            );
            // Parent→child skill seeding (`task.skill_seed`,
            // implementation note): present in BOTH modes
            // from session start (cache-safe fixed shape) and optional. A
            // separate mechanism from the read-only `seed` field — it carries
            // skill instructions, not a re-executed tool call.
            assert!(
                payload_props.contains_key("skill_seed"),
                "missing `skill_seed`: {schema}"
            );
            assert!(
                payload_props.contains_key("todo_ids"),
                "missing `todo_ids`: {schema}"
            );
            assert_eq!(
                payload_props["skill_seed"]["type"], "array",
                "skill_seed is an array: {schema}"
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
            if schema == tool.defensive_parameters().unwrap() {
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
    fn min_context_tokens_description_steers_omission() {
        let tool = TaskTool::with_subagents(&["explore", "builder"]);
        let normal = tool.parameters();
        let defensive = tool.defensive_parameters().unwrap();
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
