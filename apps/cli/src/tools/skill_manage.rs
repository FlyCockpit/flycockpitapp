//! Guarded Agent Skills package mutations.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::daemon::proto::{
    InterruptOption, InterruptQuestion, InterruptQuestionSet, ResolveResponse,
};
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, typed_args};
use crate::skills::manage::{SkillManageArgs, SkillMutationService};

const APPROVE: &str = "approve";
const REJECT: &str = "reject";

pub struct SkillManageTool;

#[async_trait]
impl Tool for SkillManageTool {
    fn name(&self) -> &str {
        "skill_manage"
    }

    fn description(&self) -> &str {
        "Create and safely mutate writable Agent Skills packages"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Create, patch, rewrite, delete, or maintain support files for a reusable skill. Use \
             `patch` for ordinary SKILL.md changes and reserve `edit` for a complete rewrite. \
             Every mutation is path-confined, atomically written, and revalidated; a fuzzy \
             no-match returns a preview so you can correct the call."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        skill_manage_schema(false)
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(skill_manage_schema(true))
    }

    async fn call(&self, value: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let args: SkillManageArgs = typed_args(value)?;
        let extended = crate::config::extended::load_for_cwd(&ctx.cwd);
        let approval_required = extended.skills.write_approval
            || crate::engine::interrupt::pre_resolved_interrupt_pending();
        if approval_required && !approve_write(&args, ctx).await? {
            return Ok(ToolOutput::text(format!(
                "Skill {:?} for `{}` was not approved; nothing changed.",
                args.action, args.name
            )));
        }
        let result = SkillMutationService::new(&ctx.cwd, &extended.skills)
            .with_origin(ctx.skill_write_origin)
            .apply(&args)?;
        Ok(ToolOutput::text(result.message))
    }
}

async fn approve_write(args: &SkillManageArgs, ctx: &ToolCtx) -> Result<bool> {
    let question = InterruptQuestion::Single {
        prompt: format!(
            "Allow skill {:?} for `{}`? The exact tool call will be replayed only if approved.",
            args.action, args.name
        ),
        options: vec![
            InterruptOption {
                id: APPROVE.to_string(),
                label: "Allow once".to_string(),
                description: Some("Apply this exact skill mutation".to_string()),
                secondary: false,
            },
            InterruptOption {
                id: REJECT.to_string(),
                label: "Deny".to_string(),
                description: Some("Leave the skill library unchanged".to_string()),
                secondary: false,
            },
        ],
        allow_freetext: false,
        command_detail: None,
        permission: true,
        approval_class: None,
        sandbox_escalation: None,
    };
    let response = crate::engine::interrupt::raise_and_wait(
        &ctx.session.db,
        &ctx.interrupts,
        ctx.session.id,
        &ctx.agent_id,
        &format!("Skill write: {:?} `{}`", args.action, args.name),
        InterruptQuestionSet {
            questions: vec![question],
        },
        "skill write approval",
    )
    .await
    .into_response()?;
    Ok(matches!(
        response,
        ResolveResponse::Single { ref selected_id } if selected_id == APPROVE
    ) || matches!(
        response,
        ResolveResponse::Batch { ref responses }
            if matches!(responses.first(), Some(ResolveResponse::Single { selected_id }) if selected_id == APPROVE)
    ))
}

fn skill_manage_schema(defensive: bool) -> Value {
    let content_description = if defensive {
        "For create: the non-empty markdown body. For edit: the complete replacement SKILL.md, including valid YAML frontmatter. For write_file: support-file contents"
    } else {
        "Body, complete SKILL.md, or support-file contents (action-dependent)"
    };
    serde_json::json!({
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["create", "patch", "edit", "delete", "write_file", "remove_file"],
                "description": "Mutation operation"
            },
            "name": { "type": "string", "description": "Exact lowercase skill name" },
            "description": { "type": "string", "description": "Required only for create" },
            "content": { "type": "string", "description": content_description },
            "category": { "type": "string", "description": "Optional single category segment for create" },
            "root": { "type": "string", "description": "Optional configured skills.scan_dirs root for create" },
            "old_string": { "type": "string", "description": "Fuzzy find text required for patch" },
            "new_string": { "type": "string", "description": "Replacement text for patch; empty deletes the span" },
            "replace_all": { "type": "boolean", "description": "Replace every fuzzy match instead of requiring uniqueness" },
            "path": { "type": "string", "description": "Support path under references/, templates/, scripts/, or assets/" }
        },
        "required": ["action", "name"],
        "additionalProperties": false
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::db::needs_attention::{InterruptParkPayload, InterruptResumeAnchor};

    fn write_config(cwd: &std::path::Path, root: &std::path::Path, approval: bool) {
        let dir = cwd.join(".cockpit");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("config.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "skills": {
                    "scan_dirs": [root.to_string_lossy()],
                    "write_approval": approval
                }
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn create_value(name: &str) -> Value {
        serde_json::json!({
            "action": "create",
            "name": name,
            "description": "Approval replay skill",
            "content": "Apply the guarded workflow."
        })
    }

    #[tokio::test]
    async fn skill_write_gate_stages_and_replays() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        write_config(tmp.path(), &root, true);
        let (mut ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        let (events, _receiver) = tokio::sync::broadcast::channel(8);
        let redaction = Arc::new(std::sync::RwLock::new(Arc::new(
            crate::redact::RedactionTable::empty(),
        )));
        ctx.interrupts = Arc::new(crate::engine::interrupt::InterruptHub::new(
            events,
            redaction,
            Arc::new(std::sync::atomic::AtomicUsize::new(1)),
            db.clone(),
            ctx.session.id,
        ));
        let ctx = Arc::new(ctx);
        let args = create_value("gated-skill");
        let payload = InterruptParkPayload {
            tool: "skill_manage".to_string(),
            args: args.clone(),
            call_id: "skill-manage-call".to_string(),
            resume: InterruptResumeAnchor {
                agent_id: ctx.agent_id.clone(),
                call_id: "skill-manage-call".to_string(),
                provider_call_id: None,
                assistant_seq: None,
                call_origin: ctx.skill_write_origin,
            },
        };
        let task_ctx = ctx.clone();
        let task_args = args.clone();
        let task = tokio::spawn(async move {
            crate::engine::interrupt::with_interrupt_park_payload(payload, async {
                SkillManageTool.call(task_args, &task_ctx).await
            })
            .await
        });

        let interrupt_id = loop {
            if let Some(row) = db.list_open_interrupts(ctx.session.id).unwrap().first() {
                break row.interrupt_id;
            }
            tokio::task::yield_now().await;
        };
        assert_eq!(ctx.interrupts.park_all_registered(), 1);
        let error = task.await.unwrap().unwrap_err();
        assert!(crate::engine::interrupt::is_parked(&error));
        assert!(!root.join("gated-skill/SKILL.md").exists());
        let row = db.get_interrupt(interrupt_id).unwrap().unwrap();
        let parked = row.parked.unwrap();
        assert_eq!(parked.tool, "skill_manage");
        assert_eq!(parked.args, args);

        let output = crate::engine::interrupt::with_pre_resolved_interrupt(
            interrupt_id,
            ResolveResponse::Single {
                selected_id: APPROVE.to_string(),
            },
            SkillManageTool.call(args, &ctx),
        )
        .await
        .unwrap();
        assert!(output.content.contains("Created skill"));
        assert!(root.join("gated-skill/SKILL.md").is_file());

        write_config(tmp.path(), &root, false);
        let denied_args = create_value("denied-after-config-drift");
        let denied = crate::engine::interrupt::with_pre_resolved_interrupt(
            uuid::Uuid::new_v4(),
            ResolveResponse::Single {
                selected_id: REJECT.to_string(),
            },
            SkillManageTool.call(denied_args, &ctx),
        )
        .await
        .unwrap();
        assert!(denied.content.contains("not approved"));
        assert!(!root.join("denied-after-config-drift/SKILL.md").exists());

        SkillManageTool
            .call(create_value("direct-skill"), &ctx)
            .await
            .unwrap();
        assert!(root.join("direct-skill/SKILL.md").is_file());
    }
}
