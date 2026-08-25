//! Guarded Agent Skills package mutations.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Map;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::PathBuf;

use crate::daemon::proto::{InterruptOption, InterruptQuestion, InterruptQuestionSet};
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input, typed_args};
use crate::skills::manage::{SkillManageAction, SkillManageArgs, SkillMutationService};

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
            "Use `skill_manage` only to create a new reusable skill, delete a skill after guarded \
             consolidation, or remove an obsolete support file. Do not use it to patch, rewrite, \
             or write package files; instead load the package with `skill`, read the target file, \
             then call `edit` or `write` on the package path shown by `skill`."
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
        // Discovery is a real filesystem traversal, including configured
        // `external_dirs` which are read-only as mutation destinations. Do
        // not let `skill_manage` inspect those roots merely because a config
        // points at them: establish the native policy on every effective root
        // first, then replace the config spellings with the exact checked
        // paths used by the service.
        let (effective_skills, preflight_roots) =
            checked_skill_preflight_config(ctx, &extended.skills).await?;
        let service = SkillMutationService::new(&ctx.cwd, &effective_skills)
            .with_origin(ctx.skill_write_origin)
            .with_db(&ctx.session.db);
        // Preparation is deliberately before the potentially parked approval.
        // In particular, delete's durable pin/usage preflight cannot be an
        // await between the final capability claim and its destructive rename.
        // The resulting plan has already completed its host preflight, so a
        // cancellation/revision cannot reopen that window.
        // `prepare`'s first possible syscall is discovery/canonicalization of
        // a configured root. Claim every exact read access immediately before
        // entering it. `prepare` performs all filesystem preflight before its
        // sole durable await (delete's usage lookup), so no cancellation can
        // interpose between this fence and a root traversal.
        crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
            "skill_manage_preflight_native_access",
            &preflight_roots
                .iter()
                .map(|root| {
                    crate::tools::sandbox::native_access_effect(
                        root,
                        crate::tools::shell_sandbox::SandboxPathAccess::Read,
                    )
                })
                .collect::<Vec<_>>(),
        )
        .await?;
        let prepared = service.prepare(&args).await?;
        let config_requires_approval = effective_skills.write_approval
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
        // The plan is now immutable and identifies one configured writable
        // root. Establish its `ReadWrite` policy before any approval can
        // park. The ready native handoff remains distinct from the eventual
        // mutation approval and is atomically composed with it at the final
        // no-await boundary below.
        let mutation_root = crate::tools::sandbox::check_native_access(
            ctx,
            service.prepared_mutation_root(&prepared),
            crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
        )
        .await?;
        if approval_required && !approve_write(&args, ctx).await? {
            return Ok(ToolOutput::text(format!(
                "Skill {:?} for `{}` was not approved; nothing changed.",
                args.action, args.name
            )));
        }
        // Reconstruct the exact mutation commitment immediately before the
        // only service entry point that can alter a skill package.  The
        // approval candidate carries this same digest, so an approved prompt
        // for one body, root, support path, or consolidation target cannot be
        // reused for another mutation with the same action and skill name.
        let concrete_effects = skill_mutation_final_effects(&args, &mutation_root)?;
        crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
            "skill_manage_mutation",
            &concrete_effects,
        )
        .await?;
        // `apply_prepared` is synchronous by construction and begins with
        // its selected mutation. Ledger/bookkeeping is intentionally deferred
        // until that mutation has committed.
        let result = service.apply_prepared(&prepared)?;
        service.record_post_mutation(&prepared, &result).await;
        Ok(ToolOutput::text(result.message))
    }
}

/// Resolve the roots that `SkillMutationService::prepare` can actually touch,
/// establish native read policy for each, and return a semantically equivalent
/// config whose paths are the syscall-effective spellings that were checked.
///
/// `scan_dirs` remains distinct from `external_dirs`: the latter participates
/// in discovery only and must never become writable merely because it was
/// normalized for the preflight traversal.
async fn checked_skill_preflight_config(
    ctx: &ToolCtx,
    skills: &crate::config::extended::SkillsConfig,
) -> Result<(crate::config::extended::SkillsConfig, Vec<PathBuf>)> {
    let all_service = SkillMutationService::new(&ctx.cwd, skills);
    let all_roots = all_service.preflight_scan_roots();

    let mut writable_only = skills.clone();
    writable_only.external_dirs.clear();
    let writable_roots: HashSet<PathBuf> =
        SkillMutationService::new(&ctx.cwd, &writable_only)
            .preflight_scan_roots()
            .into_iter()
            .collect();

    let mut effective = skills.clone();
    effective.scan_dirs.clear();
    effective.external_dirs.clear();
    // The roots below are already fully expanded, including any ancestor
    // walk. Re-expanding them could silently add a path that was never passed
    // through native access policy.
    effective.ancestor_walk = false;

    let mut checked_roots = Vec::with_capacity(all_roots.len());
    for root in all_roots {
        // Classify before canonicalization: a configured writable root may be
        // a symlink, so its checked effective spelling need not compare equal
        // to the original config value.
        let is_writable_root = writable_roots.contains(&root);
        let root = crate::tools::sandbox::check_native_access(
            ctx,
            &root,
            crate::tools::shell_sandbox::SandboxPathAccess::Read,
        )
        .await?;
        if is_writable_root {
            effective.scan_dirs.push(root.display().to_string());
        } else {
            effective.external_dirs.push(root.display().to_string());
        }
        checked_roots.push(root);
    }
    Ok((effective, checked_roots))
}

fn requires_prior_view(action: SkillManageAction) -> bool {
    !matches!(action, SkillManageAction::Create)
}

/// Domain-separated commitment to every typed field that reaches
/// [`SkillMutationService::apply`].  The canonical wire value deliberately
/// uses `SkillManageArgs`' action-specific `params` serializer: it includes
/// every semantic mutation input and excludes impossible inactive-arm fields.
///
/// The durable host-approval record retains this commitment rather than the
/// source content, description, root, or support path in plaintext.
fn skill_mutation_payload_digest(args: &SkillManageArgs) -> Result<String> {
    let payload = serde_json::to_value(args)?;
    let canonical = crate::agent_tree::canonical_json_bytes(&payload)?;
    let mut hasher = Sha256::new();
    hasher.update(b"flycockpit.skill-manage-approval.v1\0");
    hasher.update(canonical);
    Ok(format!("{:x}", hasher.finalize()))
}

/// The exact effect shape persisted in the selected approval candidate and
/// reconstructed at the final mutation boundary.  Keep the payload digest in
/// this *effect*, rather than only in surrounding operation metadata: the
/// durable handoff matcher authorizes one selected candidate effect at a
/// time.
fn skill_mutation_execute_payload(args: &SkillManageArgs, payload_digest: &str) -> Value {
    serde_json::json!({
        "action": args.action.as_str(),
        "skill_name": &args.name,
        "payload_digest": payload_digest,
    })
}

fn skill_mutation_execute_effect(args: &SkillManageArgs) -> Result<Value> {
    let payload_digest = skill_mutation_payload_digest(args)?;
    Ok(serde_json::json!({
        "execute": skill_mutation_execute_payload(args, &payload_digest),
    }))
}

/// The final irreversible skill mutation needs both independent authorities:
/// the exact syscall-effective writable root and the exact typed mutation
/// payload. The host effect scope claims each matching ready capability in
/// this one fence, then `apply_prepared` runs without an await.
fn skill_mutation_final_effects(
    args: &SkillManageArgs,
    root: &std::path::Path,
) -> Result<[Value; 2]> {
    Ok([
        crate::tools::sandbox::native_access_effect(
            root,
            crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
        ),
        skill_mutation_execute_effect(args)?,
    ])
}

fn skill_mutation_approval_operation_input(args: &SkillManageArgs) -> Result<Value> {
    let payload_digest = skill_mutation_payload_digest(args)?;
    let execute = skill_mutation_execute_payload(args, &payload_digest);
    Ok(serde_json::json!({
        "action": args.action.as_str(),
        "skill_name": &args.name,
        "payload_digest": payload_digest,
        "candidate_effects": [
            {"selection": "approve", "execute": execute},
            {"selection": "reject", "effect": "deny"}
        ],
    }))
}

async fn approve_write(args: &SkillManageArgs, ctx: &ToolCtx) -> Result<bool> {
    use crate::approval::{ApprovalOptionId, ApprovalOptionSet};

    let set = ApprovalOptionSet::new(
        "skill_write_approval",
        [ApprovalOptionId::Approve, ApprovalOptionId::Reject],
    );
    let question = InterruptQuestion::Single {
        prompt: format!(
            "Allow skill {:?} for `{}`? The exact tool call will be replayed only if approved.",
            args.action, args.name
        ),
        options: vec![
            InterruptOption {
                id: ApprovalOptionId::Approve.as_str().to_string(),
                label: "Allow once".to_string(),
                description: Some("Apply this exact skill mutation".to_string()),
                secondary: false,
            },
            InterruptOption {
                id: ApprovalOptionId::Reject.as_str().to_string(),
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
    let description = format!("Skill write: {:?} `{}`", args.action, args.name);
    let operation_input = skill_mutation_approval_operation_input(args)?;
    loop {
        let operation = crate::agent_tree::HostApprovalOperation::new(
            "skill_manage_mutation",
            operation_input.clone(),
        )?;
        let response = crate::engine::interrupt::raise_and_wait_with_agent_tree(
            &ctx.session.db,
            &ctx.interrupts,
            ctx.session.id,
            &ctx.agent_id,
            ctx.agent_instance_id,
            &description,
            InterruptQuestionSet {
                questions: vec![question.clone()],
            },
            crate::agent_tree::HostDecisionSubject::HostApproval {
                operation,
            },
            "skill write approval",
        )
        .await
        .into_response()?;
        let Some(id) = (match crate::approval::decode_option_response(&response, &set) {
            Ok(id) => id,
            Err(foreign) => {
                crate::approval::warn_foreign_option_id(&foreign);
                continue;
            }
        }) else {
            return Ok(false);
        };
        return match id {
            ApprovalOptionId::Approve => Ok(true),
            ApprovalOptionId::Reject => Ok(false),
            _ => unreachable!("skill write accepted set is fixed"),
        };
    }
}

fn skill_manage_schema(defensive: bool) -> Value {
    let actions: Vec<&str> = SkillManageAction::ALL
        .into_iter()
        .map(SkillManageAction::as_str)
        .collect();
    let params_arms: Vec<Value> = SkillManageAction::ALL
        .into_iter()
        .map(|action| params_schema_for(action, defensive))
        .collect();
    serde_json::json!({
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": actions,
                "description": "Mutation operation"
            },
            "name": { "type": "string", "description": "Exact lowercase skill name" },
            "params": {
                "description": "Action-specific mutation parameters",
                "anyOf": params_arms
            }
        },
        "required": ["action", "name", "params"],
        "additionalProperties": false
    })
}

fn params_schema_for(action: SkillManageAction, defensive: bool) -> Value {
    match action {
        SkillManageAction::Create => object_schema(
            [
                property(
                    "description",
                    "string",
                    if defensive {
                        "Short frontmatter description for the reusable skill"
                    } else {
                        "Skill description"
                    },
                ),
                property(
                    "content",
                    "string",
                    if defensive {
                        "Non-empty markdown body for SKILL.md after the generated frontmatter"
                    } else {
                        "Skill body"
                    },
                ),
                property("category", "string", "Single category segment"),
                property("root", "string", "Configured skills.scan_dirs root"),
            ],
            ["description", "content"],
        ),
        SkillManageAction::Delete => object_schema(
            [property(
                "absorbed_into",
                "string",
                "Existing umbrella skill that documents the deleted skill's behavior",
            )],
            ["absorbed_into"],
        ),
        SkillManageAction::RemoveFile => object_schema(
            [property(
                "path",
                "string",
                "Support path under references/, templates/, scripts/, or assets/",
            )],
            ["path"],
        ),
    }
}

fn object_schema<const P: usize, const R: usize>(
    properties: [(&'static str, Value); P],
    required: [&'static str; R],
) -> Value {
    let mut map = Map::new();
    for (name, schema) in properties {
        map.insert(name.to_string(), schema);
    }
    let required: Vec<&str> = required.into_iter().collect();
    serde_json::json!({
        "type": "object",
        "properties": map,
        "required": required,
        "additionalProperties": false
    })
}

fn property(
    name: &'static str,
    kind: &'static str,
    description: &'static str,
) -> (&'static str, Value) {
    (
        name,
        serde_json::json!({
            "type": kind,
            "description": description
        }),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use super::*;

    use crate::daemon::proto::ResolveResponse;
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

    fn apply_test_config_with_external_dir(
        ctx: &mut ToolCtx,
        root: &std::path::Path,
        external_dir: &std::path::Path,
        write_approval: Option<bool>,
    ) {
        let mut config = extended_with_skills_root(root, write_approval);
        config.skills.external_dirs = vec![external_dir.to_string_lossy().into_owned()];
        ctx.config = crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                0,
                crate::config::providers::ProvidersConfig::default(),
                config,
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
                provider_item_id: None,
                provider_call_id: None,
                assistant_seq: None,
                call_origin: ctx.skill_write_origin,
            },
            gate: None,
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
            let open = db.list_open_interrupts(ctx.session.id).await.unwrap();
            if let Some(row) = open
                .iter()
                .find(|row| ctx.interrupts.has_waiter(row.interrupt_id))
            {
                let row_id = row.interrupt_id;
                if ctx.interrupts.park_all_registered().await == 1 {
                    interrupt_id = Some(row_id);
                    break;
                }
            }
            tokio::task::yield_now().await;
        }
        let interrupt_id = interrupt_id.expect("skill_manage call did not raise an interrupt");
        let error = task.await.unwrap().unwrap_err();
        assert!(crate::engine::interrupt::is_parked(&error));
        interrupt_id
    }

    fn create_value(name: &str) -> Value {
        serde_json::json!({
            "action": "create",
            "name": name,
            "params": {
                "description": "Approval replay skill",
                "content": "Apply the guarded workflow."
            }
        })
    }

    async fn replay_question_from_row(
        db: &crate::db::Db,
        interrupt_id: uuid::Uuid,
    ) -> crate::engine::interrupt::PreResolvedInterruptQuestion {
        let row = db
            .get_interrupt(interrupt_id)
            .await
            .unwrap()
            .expect("parked skill approval row");
        crate::engine::interrupt::PreResolvedInterruptQuestion {
            agent_instance_id: row.agent_instance_id,
            agent: row.agent_id,
            description: row.description,
            questions: row.questions.expect("parked skill approval question set"),
            occurrence: 1,
        }
    }

    fn skill_write_replay_question(
        ctx: &ToolCtx,
        args: &Value,
    ) -> crate::engine::interrupt::PreResolvedInterruptQuestion {
        let args: SkillManageArgs = typed_args(args.clone()).unwrap();
        let question = InterruptQuestion::Single {
            prompt: format!(
                "Allow skill {:?} for `{}`? The exact tool call will be replayed only if approved.",
                args.action, args.name
            ),
            options: vec![
                InterruptOption {
                    id: crate::approval::ID_APPROVE.to_string(),
                    label: "Allow once".to_string(),
                    description: Some("Apply this exact skill mutation".to_string()),
                    secondary: false,
                },
                InterruptOption {
                    id: crate::approval::ID_REJECT.to_string(),
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
        crate::engine::interrupt::PreResolvedInterruptQuestion {
            agent_instance_id: ctx.agent_instance_id,
            agent: ctx.agent_id.clone(),
            description: format!("Skill write: {:?} `{}`", args.action, args.name),
            questions: InterruptQuestionSet {
                questions: vec![question],
            },
            occurrence: 1,
        }
    }

    fn delete_value(name: &str) -> Value {
        serde_json::json!({
            "action": "delete",
            "name": name,
            "params": {
                "absorbed_into": "umbrella-skill"
            }
        })
    }

    fn remove_file_value(name: &str, path: &str) -> Value {
        serde_json::json!({
            "action": "remove_file",
            "name": name,
            "params": {
                "path": path
            }
        })
    }

    fn params_any_of(schema: &Value) -> &[Value] {
        schema["properties"]["params"]["anyOf"]
            .as_array()
            .expect("params anyOf")
    }

    fn string_set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn value_string_set(values: &Value) -> BTreeSet<String> {
        values
            .as_array()
            .expect("array")
            .iter()
            .map(|value| value.as_str().expect("string").to_string())
            .collect()
    }

    fn property_set(schema: &Value) -> BTreeSet<String> {
        schema["properties"]
            .as_object()
            .expect("properties")
            .keys()
            .cloned()
            .collect()
    }

    fn strip_descriptions(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut stripped = serde_json::Map::new();
                for (key, value) in object {
                    if key != "description" {
                        stripped.insert(key.clone(), strip_descriptions(value));
                    }
                }
                Value::Object(stripped)
            }
            Value::Array(values) => Value::Array(values.iter().map(strip_descriptions).collect()),
            other => other.clone(),
        }
    }

    fn minimal_args_for(action: SkillManageAction) -> Value {
        match action {
            SkillManageAction::Create => create_value("schema-runtime"),
            SkillManageAction::Delete => delete_value("schema-runtime"),
            SkillManageAction::RemoveFile => {
                remove_file_value("schema-runtime", "references/file.md")
            }
        }
    }

    #[test]
    fn skill_manage_advertises_only_retained_actions() {
        for schema in [skill_manage_schema(false), skill_manage_schema(true)] {
            assert_eq!(schema["type"], "object");
            assert_eq!(schema["additionalProperties"], false);
            assert_eq!(
                value_string_set(&schema["required"]),
                string_set(&["action", "name", "params"])
            );
            assert_eq!(
                property_set(&schema),
                string_set(&["action", "name", "params"])
            );
            assert_eq!(
                value_string_set(&schema["properties"]["action"]["enum"]),
                string_set(&["create", "delete", "remove_file"])
            );
            assert_eq!(params_any_of(&schema).len(), SkillManageAction::ALL.len());
            for arm in params_any_of(&schema) {
                assert_eq!(arm["type"], "object");
                assert_eq!(arm["additionalProperties"], false);
                assert!(
                    arm["properties"]
                        .as_object()
                        .is_some_and(|props| !props.is_empty())
                );
                assert!(
                    arm["required"]
                        .as_array()
                        .is_some_and(|required| !required.is_empty())
                );
            }
        }
    }

    #[test]
    fn every_arm_matches_the_runtime_requirements() {
        let cases = [
            (
                SkillManageAction::Create,
                &["description", "content", "category", "root"][..],
                &["description", "content"][..],
            ),
            (
                SkillManageAction::Delete,
                &["absorbed_into"][..],
                &["absorbed_into"][..],
            ),
            (SkillManageAction::RemoveFile, &["path"][..], &["path"][..]),
        ];

        for (action, properties, required) in cases {
            let arm = params_schema_for(action, false);
            assert_eq!(property_set(&arm), string_set(properties));
            assert_eq!(value_string_set(&arm["required"]), string_set(required));
            let args: SkillManageArgs =
                serde_json::from_value(minimal_args_for(action)).expect("minimal args parse");
            assert_eq!(args.action, action);
        }
    }

    #[test]
    fn approved_candidate_rejects_every_altered_skill_mutation_payload() {
        // The database host-effect fence compares a selected candidate's
        // concrete `execute` member structurally.  This ratchets the
        // skill_manage side of that contract: each action-specific field that
        // can reach SkillMutationService::apply must change the candidate
        // effect and therefore be rejected after a user approved a different
        // mutation.
        let create = SkillManageArgs {
            action: SkillManageAction::Create,
            name: "approval-binding".to_string(),
            description: Some("Original description".to_string()),
            content: Some("Original body".to_string()),
            category: Some("original-category".to_string()),
            root: Some("/original-root".to_string()),
            path: None,
            absorbed_into: None,
        };
        let delete = SkillManageArgs {
            action: SkillManageAction::Delete,
            name: "approval-binding".to_string(),
            description: None,
            content: None,
            category: None,
            root: None,
            path: None,
            absorbed_into: Some("original-umbrella".to_string()),
        };
        let remove_file = SkillManageArgs {
            action: SkillManageAction::RemoveFile,
            name: "approval-binding".to_string(),
            description: None,
            content: None,
            category: None,
            root: None,
            path: Some("references/original.md".to_string()),
            absorbed_into: None,
        };

        let mut altered_description = create.clone();
        altered_description.description = Some("Altered description".to_string());
        let mut altered_content = create.clone();
        altered_content.content = Some("Altered body".to_string());
        let mut altered_category = create.clone();
        altered_category.category = Some("altered-category".to_string());
        let mut altered_root = create.clone();
        altered_root.root = Some("/altered-root".to_string());
        let mut altered_absorbed_into = delete.clone();
        altered_absorbed_into.absorbed_into = Some("altered-umbrella".to_string());
        let mut altered_path = remove_file.clone();
        altered_path.path = Some("references/altered.md".to_string());

        let cases = [
            ("description", create.clone(), altered_description),
            ("content", create.clone(), altered_content),
            ("category", create.clone(), altered_category),
            ("root", create, altered_root),
            ("absorbed_into", delete, altered_absorbed_into),
            ("path", remove_file, altered_path),
        ];
        for (field, approved, altered) in cases {
            let operation = skill_mutation_approval_operation_input(&approved).unwrap();
            let candidate = operation["candidate_effects"][0].clone();
            let approved_effect = skill_mutation_execute_effect(&approved).unwrap();
            let altered_effect = skill_mutation_execute_effect(&altered).unwrap();

            assert_eq!(candidate.get("execute"), approved_effect.get("execute"));
            assert_eq!(
                operation["payload_digest"],
                candidate["execute"]["payload_digest"],
                "the selected candidate, not only surrounding operation metadata, binds {field}"
            );
            assert!(
                candidate
                    .pointer("/execute/payload_digest")
                    .and_then(Value::as_str)
                    .is_some_and(|digest| digest.len() == 64),
                "approved {field} candidate carries the full-payload commitment"
            );
            assert_ne!(
                candidate.get("execute"),
                altered_effect.get("execute"),
                "an approved mutation must reject altered {field} at the final host boundary"
            );
        }
    }

    #[test]
    fn every_skill_mutation_action_fences_native_root_and_exact_payload_together() {
        let root = std::path::Path::new("/checked-skill-root");
        for action in SkillManageAction::ALL {
            let args: SkillManageArgs =
                serde_json::from_value(minimal_args_for(action)).unwrap();
            let effects = skill_mutation_final_effects(&args, root).unwrap();
            assert_eq!(
                effects[0],
                crate::tools::sandbox::native_access_effect(
                    root,
                    crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
                ),
                "{action:?} must not mutate without the checked native root"
            );
            assert_eq!(effects[1], skill_mutation_execute_effect(&args).unwrap());
        }
    }

    #[test]
    fn terse_and_defensive_arms_agree_on_shape() {
        assert_eq!(
            strip_descriptions(&skill_manage_schema(false)),
            strip_descriptions(&skill_manage_schema(true))
        );
    }

    #[test]
    fn every_action_has_a_params_arm() {
        let schema = skill_manage_schema(false);
        let action_names: BTreeSet<String> = SkillManageAction::ALL
            .into_iter()
            .map(SkillManageAction::as_str)
            .map(str::to_string)
            .collect();
        assert_eq!(
            value_string_set(&schema["properties"]["action"]["enum"]),
            action_names
        );
        assert_eq!(params_any_of(&schema).len(), action_names.len());

        let distinct_arms: BTreeSet<String> = SkillManageAction::ALL
            .into_iter()
            .map(|action| params_schema_for(action, false))
            .map(|schema| serde_json::to_string(&schema).expect("schema serializes"))
            .collect();
        assert_eq!(distinct_arms.len(), action_names.len());
    }

    #[tokio::test]
    async fn wrong_arm_for_action_is_an_invocation_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        write_config(tmp.path(), &root, false);
        let (ctx, _db) = crate::tools::common::test_ctx_with_db(tmp.path());
        let args = serde_json::json!({
            "action": "delete",
            "name": "wrong-arm",
            "params": { "content": "this belongs to edit" }
        });

        let error = SkillManageTool.call(args, &ctx).await.unwrap_err();

        assert_eq!(
            crate::engine::tool::classify_failure(&error),
            crate::engine::tool::ToolFailKind::Invocation
        );
        let message = error.to_string();
        assert!(message.contains("`delete`"));
        assert!(message.contains("content"));
        assert!(!root.join("wrong-arm").exists());
    }

    #[tokio::test]
    async fn legacy_flat_args_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        write_config(tmp.path(), &root, false);
        let (ctx, _db) = crate::tools::common::test_ctx_with_db(tmp.path());
        let args = serde_json::json!({
            "action": "create",
            "name": "legacy-flat",
            "description": "Old flat shape",
            "content": "Do not accept this."
        });

        let error = SkillManageTool.call(args, &ctx).await.unwrap_err();

        assert_eq!(
            crate::engine::tool::classify_failure(&error),
            crate::engine::tool::ToolFailKind::Invocation
        );
        assert!(error.to_string().contains("params"));
        assert!(!root.join("legacy-flat").exists());
    }

    #[tokio::test]
    async fn skill_manage_removed_action_names_replacement_flow() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("skills");
        write_config(tmp.path(), &root, false);
        let (ctx, _db) = crate::tools::common::test_ctx_with_db(tmp.path());

        for action in ["patch", "edit", "write_file"] {
            let args = serde_json::json!({
                "action": action,
                "name": "retired-action",
                "params": {}
            });
            let error = SkillManageTool.call(args, &ctx).await.unwrap_err();
            let message = error.to_string();
            assert!(message.contains("retired"), "{message}");
            assert!(message.contains("skill"), "{message}");
            assert!(message.contains("read"), "{message}");
            assert!(
                message.contains("edit") || message.contains("write"),
                "{message}"
            );
        }
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
    async fn external_scan_root_requires_native_read_access_before_skill_preflight() {
        let workspace = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(external.path().join("shared-skill")).unwrap();
        std::fs::write(
            external.path().join("shared-skill/SKILL.md"),
            "---\nname: shared-skill\ndescription: Shared\n---\n\nRead only.\n",
        )
        .unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(workspace.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
            let writable = workspace.path().join("skills");
            let (mut ctx, _db) = crate::tools::common::test_ctx_with_db(workspace.path());
            apply_test_config_with_external_dir(&mut ctx, &writable, external.path(), Some(false));
            ctx.approver = None;
            ctx.session
                .set_approval_mode(crate::config::extended::ApprovalMode::Manual);

            let error = SkillManageTool
                .call(create_value("must-not-preflight"), &ctx)
                .await
                .unwrap_err();

            assert!(
                error
                    .to_string()
                    .contains("outside the session boundary and cannot be approved"),
                "{error:#}"
            );
            assert!(!writable.join("must-not-preflight/SKILL.md").exists());
        })
        .await;
    }

    #[tokio::test]
    async fn external_scan_root_is_read_only_and_internal_roots_do_not_prompt() {
        let workspace = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(workspace.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
            let writable = workspace.path().join("skills");
            let (mut ctx, _db) = crate::tools::common::test_ctx_with_db(workspace.path());
            apply_test_config_with_external_dir(&mut ctx, &writable, external.path(), Some(false));

            let output = SkillManageTool
                .call(create_value("native-root-ok"), &ctx)
                .await
                .unwrap();
            assert!(output.content.contains("Created skill"));
            assert!(writable.join("native-root-ok/SKILL.md").is_file());
            assert!(!external.path().join("native-root-ok/SKILL.md").exists());

            let internal = workspace.path().join("internal-skills");
            let (mut headless, _db) = crate::tools::common::test_ctx_with_db(workspace.path());
            apply_test_config(&mut headless, &internal, Some(false));
            headless.approver = None;
            headless
                .session
                .set_approval_mode(crate::config::extended::ApprovalMode::Manual);
            SkillManageTool
                .call(create_value("in-boundary-no-prompt"), &headless)
                .await
                .unwrap();
            assert!(internal.join("in-boundary-no-prompt/SKILL.md").is_file());
        })
        .await;
    }

    #[tokio::test]
    async fn foreground_write_requires_approval_by_default() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
            let root = tmp.path().join("skills");
            let (ctx, db) = ctx_with_interrupt_hub(tmp.path(), &root, None);
            assert!(ctx.config.extended().skills.write_approval);
            let args = create_value("default-gated");

            let interrupt_id =
                assert_parks_without_writing(ctx.clone(), &db, args.clone(), "default-gated-call")
                    .await;

            assert!(!root.join("default-gated/SKILL.md").exists());
            let question = replay_question_from_row(&db, interrupt_id).await;
            let output = crate::engine::interrupt::with_pre_resolved_interrupt_question(
                interrupt_id,
                ResolveResponse::Single {
                    selected_id: crate::approval::ID_APPROVE.to_string(),
                },
                question,
                SkillManageTool.call(args, &ctx),
            )
            .await
            .unwrap();
            assert!(output.content.contains("Created skill"));
            assert!(root.join("default-gated/SKILL.md").is_file());
        })
        .await;
    }

    #[tokio::test]
    async fn background_review_bypasses_default_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
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
            assert!(
                db.list_open_interrupts(ctx.session.id)
                    .await
                    .unwrap()
                    .is_empty()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn explicit_write_approval_false_still_bypasses_foreground() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
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
            assert!(
                db.list_open_interrupts(ctx.session.id)
                    .await
                    .unwrap()
                    .is_empty()
            );
        })
        .await;
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
                "delete",
                delete_value("existing-workflow"),
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
            let policy = crate::config::trust::WorkspaceTrustPolicy {
                root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
                mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
            };
            crate::config::trust::scope_workspace_trust_policy(policy, async {
                let root = tmp.path().join("skills");
                if seed_existing {
                    create_seed_skill(tmp.path(), &root, &skill_name).await;
                }
                let (ctx, db) = ctx_with_interrupt_hub(tmp.path(), &root, None);

                assert_parks_without_writing(
                    ctx.clone(),
                    &db,
                    args,
                    &format!("gate-{action}-call"),
                )
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
            })
            .await;
        }
    }

    #[tokio::test]
    async fn review_auto_denies_approvals() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
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
            assert!(
                db.list_open_interrupts(ctx.session.id)
                    .await
                    .unwrap()
                    .is_empty()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn review_writes_background_origin() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
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
        })
        .await;
    }

    #[tokio::test]
    async fn skill_write_gate_stages_and_replays() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, async {
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
                    provider_item_id: None,
                    provider_call_id: None,
                    assistant_seq: None,
                    call_origin: ctx.skill_write_origin,
                },
                gate: None,
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
                let open = db.list_open_interrupts(ctx.session.id).await.unwrap();
                if let Some(row) = open
                    .iter()
                    .find(|row| ctx.interrupts.has_waiter(row.interrupt_id))
                {
                    let interrupt_id = row.interrupt_id;
                    if ctx.interrupts.park_all_registered().await == 1 {
                        break interrupt_id;
                    }
                }
                tokio::task::yield_now().await;
            };
            let error = task.await.unwrap().unwrap_err();
            assert!(crate::engine::interrupt::is_parked(&error));
            assert!(!root.join("gated-skill/SKILL.md").exists());
            let row = db.get_interrupt(interrupt_id).await.unwrap().unwrap();
            let parked = row.parked.unwrap();
            assert_eq!(parked.tool, "skill_manage");
            assert_eq!(parked.args, args);

            let question = replay_question_from_row(&db, interrupt_id).await;
            let output = crate::engine::interrupt::with_pre_resolved_interrupt_question(
                interrupt_id,
                ResolveResponse::Single {
                    selected_id: crate::approval::ID_APPROVE.to_string(),
                },
                question,
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
            let denied_id = uuid::Uuid::new_v4();
            let denied_question = skill_write_replay_question(&ctx, &denied_args);
            let denied = crate::engine::interrupt::with_pre_resolved_interrupt_question(
                denied_id,
                ResolveResponse::Single {
                    selected_id: crate::approval::ID_REJECT.to_string(),
                },
                denied_question,
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
        })
        .await;
    }
}
