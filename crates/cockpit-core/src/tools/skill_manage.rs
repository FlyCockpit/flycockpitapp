//! Guarded Agent Skills package mutations.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::daemon::proto::{
    InterruptOption, InterruptQuestion, InterruptQuestionSet, ResolveResponse,
};
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input, typed_args};
use crate::skills::manage::{SkillManageAction, SkillManageArgs, SkillMutationService};

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
        if let Some(cage) = &ctx.review_cage
            && requires_prior_view(args.action)
            && !cage.skill_was_viewed(&args.name)
        {
            return Err(invalid_input(format!(
                "background skill review must load `{}` with `skill` before {:?}",
                args.name, args.action
            )));
        }
        let extended = ctx.config.extended();
        let config_requires_approval = extended.skills.write_approval
            && ctx.skill_write_origin != crate::skills::manage::SkillWriteOrigin::BackgroundReview;
        let approval_required =
            config_requires_approval || crate::engine::interrupt::pre_resolved_interrupt_pending();
        if approval_required
            && ctx
                .review_cage
                .as_ref()
                .is_some_and(|cage| cage.auto_deny_approvals())
        {
            return Ok(ToolOutput::text(format!(
                "Skill {:?} for `{}` was automatically denied for background review; nothing changed.",
                args.action, args.name
            )));
        }
        if approval_required && !approve_write(&args, ctx).await? {
            return Ok(ToolOutput::text(format!(
                "Skill {:?} for `{}` was not approved; nothing changed.",
                args.action, args.name
            )));
        }
        let result = SkillMutationService::new(&ctx.cwd, &extended.skills)
            .with_origin(ctx.skill_write_origin)
            .with_db(&ctx.session.db)
            .apply(&args)?;
        Ok(ToolOutput::text(result.message))
    }
}

fn requires_prior_view(action: SkillManageAction) -> bool {
    !matches!(action, SkillManageAction::Create)
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
            "path": { "type": "string", "description": "Support path under references/, templates/, scripts/, or assets/" },
            "absorbed_into": { "type": "string", "description": "Required for delete: existing umbrella skill that absorbed the deleted skill" }
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

    fn extended_with_skills_root(
        root: &std::path::Path,
        write_approval: Option<bool>,
    ) -> crate::config::extended::ExtendedConfig {
        let mut skills = crate::config::extended::SkillsConfig {
            scan_dirs: vec![root.to_string_lossy().into_owned()],
            ..Default::default()
        };
        if let Some(write_approval) = write_approval {
            skills.write_approval = write_approval;
        }
        crate::config::extended::ExtendedConfig {
            skills,
            ..Default::default()
        }
    }

    fn apply_test_config(ctx: &mut ToolCtx, root: &std::path::Path, write_approval: Option<bool>) {
        ctx.config = crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                0,
                crate::config::providers::ProvidersConfig::default(),
                extended_with_skills_root(root, write_approval),
            ),
        );
    }

    fn ctx_with_interrupt_hub(
        cwd: &std::path::Path,
        root: &std::path::Path,
        write_approval: Option<bool>,
    ) -> (Arc<ToolCtx>, crate::db::Db) {
        let (mut ctx, db) = crate::tools::common::test_ctx_with_db(cwd);
        apply_test_config(&mut ctx, root, write_approval);
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
        (Arc::new(ctx), db)
    }

    async fn assert_parks_without_writing(
        ctx: Arc<ToolCtx>,
        db: &crate::db::Db,
        args: Value,
        call_id: &str,
    ) -> uuid::Uuid {
        let payload = InterruptParkPayload {
            tool: "skill_manage".to_string(),
            args: args.clone(),
            call_id: call_id.to_string(),
            resume: InterruptResumeAnchor {
                agent_id: ctx.agent_id.clone(),
                call_id: call_id.to_string(),
                provider_call_id: None,
                assistant_seq: None,
                call_origin: ctx.skill_write_origin,
            },
        };
        let task_ctx = ctx.clone();
        let task = tokio::spawn(async move {
            crate::engine::interrupt::with_interrupt_park_payload(payload, async {
                SkillManageTool.call(args, &task_ctx).await
            })
            .await
        });

        let mut interrupt_id = None;
        for _ in 0..1000 {
            if let Some(row) = db.list_open_interrupts(ctx.session.id).unwrap().first() {
                interrupt_id = Some(row.interrupt_id);
                break;
            }
            tokio::task::yield_now().await;
        }
        let interrupt_id = interrupt_id.expect("skill_manage call did not raise an interrupt");
        assert_eq!(ctx.interrupts.park_all_registered(), 1);
        let error = task.await.unwrap().unwrap_err();
        assert!(crate::engine::interrupt::is_parked(&error));
        interrupt_id
    }

    fn create_value(name: &str) -> Value {
        serde_json::json!({
            "action": "create",
            "name": name,
            "description": "Approval replay skill",
            "content": "Apply the guarded workflow."
        })
    }

    fn edit_value(name: &str, body: &str) -> Value {
        serde_json::json!({
            "action": "edit",
            "name": name,
            "content": body
        })
    }

    fn delete_value(name: &str) -> Value {
        serde_json::json!({
            "action": "delete",
            "name": name,
            "absorbed_into": "umbrella-skill"
        })
    }

    fn write_file_value(name: &str, path: &str, content: &str) -> Value {
        serde_json::json!({
            "action": "write_file",
            "name": name,
            "path": path,
            "content": content
        })
    }

    fn remove_file_value(name: &str, path: &str) -> Value {
        serde_json::json!({
            "action": "remove_file",
            "name": name,
            "path": path
        })
    }

    fn patch_value(name: &str, old: &str, new: &str) -> Value {
        serde_json::json!({
            "action": "patch",
            "name": name,
            "old_string": old,
            "new_string": new
        })
    }

    async fn create_seed_skill(cwd: &std::path::Path, root: &std::path::Path, name: &str) {
        create_foreground_skill(cwd, root, name).await;
        std::fs::create_dir_all(root.join(name).join("references")).unwrap();
        std::fs::write(root.join(name).join("references/old.md"), "old support").unwrap();
    }

    async fn create_foreground_skill(cwd: &std::path::Path, root: &std::path::Path, name: &str) {
        write_config(cwd, root, false);
        let (ctx, _db) = crate::tools::common::test_ctx_with_db(cwd);
        SkillManageTool
            .call(create_value(name), &ctx)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn foreground_write_requires_approval_by_default() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let (ctx, db) = ctx_with_interrupt_hub(tmp.path(), &root, None);
        assert!(ctx.config.extended().skills.write_approval);
        let args = create_value("default-gated");

        let interrupt_id =
            assert_parks_without_writing(ctx.clone(), &db, args.clone(), "default-gated-call")
                .await;

        assert!(!root.join("default-gated/SKILL.md").exists());
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
        assert!(root.join("default-gated/SKILL.md").is_file());
    }

    #[tokio::test]
    async fn background_review_bypasses_default_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let (mut ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        apply_test_config(&mut ctx, &root, None);
        ctx.review_cage = Some(crate::engine::tool::ReviewCage::skills_review());
        ctx.skill_write_origin = crate::skills::manage::SkillWriteOrigin::BackgroundReview;

        let output = SkillManageTool
            .call(create_value("background-default"), &ctx)
            .await
            .unwrap();

        assert!(output.content.contains("Created skill"));
        assert!(root.join("background-default/SKILL.md").is_file());
        assert!(db.list_open_interrupts(ctx.session.id).unwrap().is_empty());
    }

    #[tokio::test]
    async fn explicit_write_approval_false_still_bypasses_foreground() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        let mut ctx = ctx;
        apply_test_config(&mut ctx, &root, Some(false));

        let output = SkillManageTool
            .call(create_value("explicit-direct"), &ctx)
            .await
            .unwrap();

        assert!(output.content.contains("Created skill"));
        assert!(root.join("explicit-direct/SKILL.md").is_file());
        assert!(db.list_open_interrupts(ctx.session.id).unwrap().is_empty());
    }

    #[tokio::test]
    async fn gate_covers_every_action() {
        let cases = vec![
            (
                "create",
                create_value("gated-create"),
                "gated-create".to_string(),
                false,
            ),
            (
                "patch",
                patch_value(
                    "existing-workflow",
                    "Apply the guarded workflow.",
                    "mutated by patch",
                ),
                "existing-workflow".to_string(),
                true,
            ),
            (
                "edit",
                edit_value("existing-workflow", "mutated by edit"),
                "existing-workflow".to_string(),
                true,
            ),
            (
                "delete",
                delete_value("existing-workflow"),
                "existing-workflow".to_string(),
                true,
            ),
            (
                "write_file",
                write_file_value("existing-workflow", "references/new.md", "mutated support"),
                "existing-workflow".to_string(),
                true,
            ),
            (
                "remove_file",
                remove_file_value("existing-workflow", "references/old.md"),
                "existing-workflow".to_string(),
                true,
            ),
        ];

        for (action, args, skill_name, seed_existing) in cases {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("skills");
            if seed_existing {
                create_seed_skill(tmp.path(), &root, &skill_name).await;
            }
            let (ctx, db) = ctx_with_interrupt_hub(tmp.path(), &root, None);

            assert_parks_without_writing(ctx.clone(), &db, args, &format!("gate-{action}-call"))
                .await;

            if seed_existing {
                assert!(root.join(&skill_name).join("SKILL.md").is_file());
                assert!(
                    !std::fs::read_to_string(root.join(&skill_name).join("SKILL.md"))
                        .unwrap()
                        .contains("mutated")
                );
                assert_eq!(
                    std::fs::read_to_string(root.join(&skill_name).join("references/old.md"))
                        .unwrap(),
                    "old support"
                );
                assert!(!root.join(&skill_name).join("references/new.md").exists());
            } else {
                assert!(!root.join(&skill_name).join("SKILL.md").exists());
            }
        }
    }

    #[tokio::test]
    async fn review_auto_denies_approvals() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        write_config(tmp.path(), &root, true);
        let (mut ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        ctx.review_cage = Some(crate::engine::tool::ReviewCage::skills_review());

        let output = SkillManageTool
            .call(create_value("auto-denied"), &ctx)
            .await
            .unwrap();

        assert!(output.content.contains("automatically denied"));
        assert!(!root.join("auto-denied/SKILL.md").exists());
        assert!(db.list_open_interrupts(ctx.session.id).unwrap().is_empty());
    }

    #[tokio::test]
    async fn review_read_before_write() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        create_foreground_skill(tmp.path(), &root, "view-first").await;
        let (mut ctx, _db) = crate::tools::common::test_ctx_with_db(tmp.path());
        ctx.review_cage = Some(crate::engine::tool::ReviewCage::skills_review());
        ctx.skill_write_origin = crate::skills::manage::SkillWriteOrigin::BackgroundReview;

        let denied = SkillManageTool
            .call(
                patch_value(
                    "view-first",
                    "Apply the guarded workflow.",
                    "Apply reviewed steps.",
                ),
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(denied.to_string().contains("must load `view-first`"));

        crate::tools::skill::SkillTool
            .call(serde_json::json!({"name": "view-first"}), &ctx)
            .await
            .unwrap();
        let output = SkillManageTool
            .call(
                patch_value(
                    "view-first",
                    "Apply the guarded workflow.",
                    "Apply reviewed steps.",
                ),
                &ctx,
            )
            .await
            .unwrap();
        assert!(output.content.contains("Patched skill"));
        let body = std::fs::read_to_string(root.join("view-first/SKILL.md")).unwrap();
        assert!(body.contains("Apply reviewed steps."));
    }

    #[tokio::test]
    async fn review_writes_background_origin() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        write_config(tmp.path(), &root, false);
        let (mut ctx, _db) = crate::tools::common::test_ctx_with_db(tmp.path());
        ctx.review_cage = Some(crate::engine::tool::ReviewCage::skills_review());
        ctx.skill_write_origin = crate::skills::manage::SkillWriteOrigin::BackgroundReview;

        SkillManageTool
            .call(create_value("background-created"), &ctx)
            .await
            .unwrap();

        let provenance =
            std::fs::read_to_string(root.join("background-created/.cockpit-provenance.json"))
                .unwrap();
        assert!(provenance.contains("\"created_origin\": \"background_review\""));
        assert!(provenance.contains("\"origin\": \"background_review\""));
    }

    #[tokio::test]
    async fn review_patches_before_creating() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        create_foreground_skill(tmp.path(), &root, "existing-workflow").await;
        let (mut ctx, _db) = crate::tools::common::test_ctx_with_db(tmp.path());
        ctx.review_cage = Some(crate::engine::tool::ReviewCage::skills_review());
        ctx.skill_write_origin = crate::skills::manage::SkillWriteOrigin::BackgroundReview;

        crate::tools::skill::SkillTool
            .call(serde_json::json!({"name": "existing-workflow"}), &ctx)
            .await
            .unwrap();
        SkillManageTool
            .call(
                patch_value(
                    "existing-workflow",
                    "Apply the guarded workflow.",
                    "Apply the guarded workflow, then document the reusable retry check.",
                ),
                &ctx,
            )
            .await
            .unwrap();

        assert!(root.join("existing-workflow/SKILL.md").is_file());
        assert_eq!(
            std::fs::read_dir(&root)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_type().is_ok_and(|ty| ty.is_dir()))
                .count(),
            1
        );
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
        let mut ctx = Arc::new(ctx);
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
        // Config is snapshotted onto the ctx handle; refresh it after rewriting
        // the write-approval config on disk (`engine-config-snapshot-adoption`).
        // The spawned task has joined, so this is the sole `Arc` owner.
        Arc::get_mut(&mut ctx)
            .expect("sole ctx owner after task join")
            .config =
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path());
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
