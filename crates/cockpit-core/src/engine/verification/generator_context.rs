//! Effective custody boundary for verification generators.
//!
//! A configured generator and the author slot meet only in the private constructor below.
//! The resulting value owns every provider-visible variable whose custody depends on that
//! decision. Estimation, reservation, and inference accept only its unforgeable request view.

use crate::agents::{GeneratorSpec, VerificationRecipe};
use crate::engine::agent::Agent;
use crate::engine::message::{Message, ToolCall, ToolDefinition};
use crate::engine::model::ModelParams;
use crate::engine::tool::{Tool, ToolEffect};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Clone)]
pub(in crate::engine::verification) struct EffectiveGeneratorContext {
    slot: String,
    recipe: VerificationRecipe,
    initial_history: Vec<Message>,
    params: ModelParams,
    tools: Vec<ToolDefinition>,
    investigation_tools: BTreeMap<String, Arc<dyn Tool>>,
    max_turns: u8,
}

/// A request view can only be minted by an effective context (or a conversation rooted in one).
/// Its fields deliberately stay private so downstream generator APIs cannot substitute raw author
/// history, parameters, or tools after the slot/recipe custody decision.
pub(in crate::engine::verification) struct EffectiveGeneratorRequest<'a> {
    history: &'a [Message],
    prompt: &'a str,
    tools: &'a [ToolDefinition],
    params: &'a ModelParams,
}

impl EffectiveGeneratorRequest<'_> {
    pub(in crate::engine::verification) fn history(&self) -> &[Message] {
        self.history
    }
    pub(in crate::engine::verification) fn prompt(&self) -> &str {
        self.prompt
    }
    pub(in crate::engine::verification) fn tools(&self) -> &[ToolDefinition] {
        self.tools
    }
    pub(in crate::engine::verification) fn params(&self) -> &ModelParams {
        self.params
    }
}

/// Generator-private conversation rooted in the context-owned initial projection.
pub(in crate::engine::verification) struct EffectiveGeneratorConversation<'a> {
    context: &'a EffectiveGeneratorContext,
    messages: Vec<Message>,
}

impl EffectiveGeneratorConversation<'_> {
    pub(in crate::engine::verification) fn request<'a>(
        &'a self,
        prompt: &'a str,
    ) -> EffectiveGeneratorRequest<'a> {
        EffectiveGeneratorRequest {
            history: &self.messages,
            prompt,
            tools: &self.context.tools,
            params: &self.context.params,
        }
    }

    pub(in crate::engine::verification) fn append_assistant(
        &mut self,
        content: Vec<rig::message::AssistantContent>,
    ) {
        self.messages.push(Message::Assistant { id: None, content });
    }

    pub(in crate::engine::verification) fn append_tool_result(
        &mut self,
        call: &ToolCall,
        text: String,
    ) {
        self.messages
            .push(crate::engine::message::tool_result_message_for(
                call,
                &call.function.name,
                text,
            ));
    }
}

impl EffectiveGeneratorContext {
    /// Establish custody at the only production seam where a spec meets author-slot identity.
    /// Author history, parameters, and schemas are copied only for author-slot `Inherit`.
    pub(super) fn new(
        spec: &GeneratorSpec,
        author_slot: &str,
        author: &Agent,
        author_history: &[Message],
    ) -> Self {
        let max_turns = spec
            .max_turns
            .max(1)
            .min(crate::agents::MAX_GENERATOR_TURNS);
        let author_inherit =
            spec.slot == author_slot && matches!(spec.recipe, VerificationRecipe::Inherit);
        let recipe = if matches!(spec.recipe, VerificationRecipe::Inherit) && !author_inherit {
            VerificationRecipe::clean_room_default()
        } else {
            spec.recipe.clone()
        };
        let initial_history = if author_inherit {
            author_history.to_vec()
        } else {
            Vec::new()
        };
        let params = if author_inherit {
            author.params.clone()
        } else {
            ModelParams::default()
        };
        let (mut tools, investigation_tools) = if max_turns > 1 {
            let mut investigation_tools = BTreeMap::new();
            let definitions = author
                .tools
                .definitions(author.tool_steering)
                .into_iter()
                .filter(|definition| {
                    let Some(tool) = author.tools.get_cloned(&definition.name) else {
                        return false;
                    };
                    if !is_private_investigation_tool(tool.as_ref()) {
                        return false;
                    }
                    investigation_tools.insert(definition.name.clone(), tool);
                    true
                })
                .collect();
            (definitions, investigation_tools)
        } else if author_inherit {
            (
                author.tools.definitions(author.tool_steering),
                BTreeMap::new(),
            )
        } else {
            (Vec::new(), BTreeMap::new())
        };
        tools.push(candidate_tool_definition());
        Self {
            slot: spec.slot.clone(),
            recipe,
            initial_history,
            params,
            tools,
            investigation_tools,
            max_turns,
        }
    }

    pub(in crate::engine::verification) fn slot(&self) -> &str {
        &self.slot
    }
    pub(in crate::engine::verification) fn recipe(&self) -> &VerificationRecipe {
        &self.recipe
    }

    pub(in crate::engine::verification) fn request<'a>(
        &'a self,
        prompt: &'a str,
    ) -> EffectiveGeneratorRequest<'a> {
        EffectiveGeneratorRequest {
            history: &self.initial_history,
            prompt,
            tools: &self.tools,
            params: &self.params,
        }
    }

    pub(in crate::engine::verification) fn start_conversation(
        &self,
    ) -> EffectiveGeneratorConversation<'_> {
        EffectiveGeneratorConversation {
            context: self,
            messages: self.initial_history.clone(),
        }
    }

    pub(in crate::engine::verification) fn max_turns(&self) -> u8 {
        self.max_turns
    }

    pub(in crate::engine::verification) fn investigation_tool(
        &self,
        name: &str,
    ) -> Option<&dyn Tool> {
        self.investigation_tools.get(name).map(Arc::as_ref)
    }
}

/// Read-only investigation tools: `ToolEffect::ReadOnly` names minus session and media tools.
pub(in crate::engine::verification) fn is_private_investigation_tool(tool: &dyn Tool) -> bool {
    let name = tool.name();
    tool.is_registered_ordinary_operation()
        && tool.effect() == ToolEffect::ReadOnly
        && !name.starts_with("session_")
        && !name.contains("image")
        && !name.contains("audio")
        && !name.contains("video")
        && !name.contains("generation")
}

pub(in crate::engine::verification) fn candidate_tool_definition() -> ToolDefinition {
    ToolDefinition {
        name: "verification_candidate".to_string(),
        description: "Return one verification candidate for the proposed write or edit."
            .to_string(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "kind": { "type": "string", "enum": ["revision", "approve_original", "flag"] },
                "args": { "type": ["object", "null"] },
                "critique": { "type": "string" }
            },
            "required": ["kind", "args", "critique"],
            "additionalProperties": false
        }),
    }
}
