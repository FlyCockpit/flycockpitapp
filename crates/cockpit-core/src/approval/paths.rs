use super::*;
use crate::tools::shell_sandbox::SandboxPathAccess;
use sha2::{Digest as _, Sha256};

impl Approver {
    /// Decide a path access (part 2's native confinement). Granted →
    /// allow; else prompt showing the exact path. Paths are never
    /// wrappers, so all four scopes are offered.
    pub async fn approve_path(
        &self,
        path: &std::path::Path,
        required: SandboxPathAccess,
    ) -> Result<Decision> {
        self.approve_path_with_detail(path, required, None).await
    }

    pub(super) async fn approve_path_with_detail(
        &self,
        path: &std::path::Path,
        required: SandboxPathAccess,
        detail: Option<CommandDetail>,
    ) -> Result<Decision> {
        // Issue #297 fail-closed store health gate: path decisions consult
        // the approvals files for standing grants/rejects, and this entry is
        // also reached directly (outside `Approver::authorize`) by the
        // native sandbox path choke.
        self.ensure_approvals_store_healthy()?;
        let target = path.display().to_string();
        // Standing reject short-circuit (checked before allow). A rejected
        // path auto-denies the out-of-cwd access with no prompt; recorded with
        // the `StandingReject` source so the timeline reflects the reject.
        if self.store.is_path_rejected(path).await {
            self.record_permission_decision(
                "path",
                &target,
                &[],
                Decision::Deny,
                DecisionSource::StandingReject,
            )
            .await;
            return Ok(Decision::Deny);
        }
        if self.store.is_path_granted_for(path, required).await {
            let decision = Decision::Allow {
                scope: Scope::Session,
            };
            self.record_permission_decision(
                "path",
                &target,
                &[],
                decision,
                DecisionSource::AlreadyGranted,
            )
            .await;
            return Ok(decision);
        }
        if self.yolo_mode()
            || self
                .auto_allows(crate::agent_tree::HostEffectClass::Authorization, &target)
                .await
        {
            return Ok(Decision::Allow { scope: Scope::Once });
        }
        // Paths are never wrappers → all four scopes are offered.
        let offered = [Scope::Once, Scope::Session, Scope::Project, Scope::Global];
        let label = path_prompt_label(&target, required);
        let description = path_prompt_description(&target, required);
        let question = approval_question(
            &label,
            false,
            GrantKind::Path,
            Some(&description),
            detail,
            None,
            &offered,
            None,
        );
        let set = approval_option_set("path_approval", false, &offered, None);
        let choice = self
            .raise_and_decode(
                &description,
                question,
                "path_access",
                serde_json::json!({
                    "path": target.clone(),
                    "required_access": format!("{required:?}"),
                    "offered_scopes": offered.iter().map(|scope| scope_label(*scope)).collect::<Vec<_>>(),
                    "candidate_effects": offered.iter().map(|scope| serde_json::json!({
                        "selection": approve_option_id_for_scope(*scope).as_str(),
                        "access": {"path": target, "required_access": format!("{required:?}")},
                        "persist_grant": if *scope == Scope::Once { serde_json::Value::Null } else { serde_json::json!({"kind": "path", "path": target, "scope": scope_label(*scope), "access": format!("{required:?}")}) },
                    })).chain(offered.iter().copied().filter(|scope| *scope != Scope::Once).map(|scope| serde_json::json!({
                        "selection": reject_option_id_for_scope(scope).as_str(),
                        "persist_reject": {"kind": "path", "path": target, "scope": scope_label(scope), "access": format!("{required:?}")},
                    }))).chain(std::iter::once(serde_json::json!({
                        "selection": "reject", "persist_reject": {"kind": "path", "path": target}
                    }))).collect::<Vec<_>>(),
                }),
                |response| response_to_approval_choice(response, &set),
            )
            .await?;
        let decision = match choice {
            ApprovalChoice::Deny => Decision::Deny,
            ApprovalChoice::NoninteractiveDeny => Decision::NoninteractiveDeny,
            ApprovalChoice::Approve(Scope::Once) => {
                // A one-shot path approval has no durable grant to persist,
                // but it still authorizes the exact access candidate offered
                // to the user. Claim it before a following gate can advance
                // the agent revision (for example path access followed by a
                // command approval), otherwise that later gate would make
                // this ready capability stale at the actual host boundary.
                if crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                    "path_access_once",
                    &[serde_json::json!({
                        "access": {"path": &target, "required_access": format!("{required:?}")}
                    })],
                )
                .await
                .is_err()
                {
                    Decision::Deny
                } else {
                    Decision::Allow { scope: Scope::Once }
                }
            }
            ApprovalChoice::GrantPaths(_) => Decision::Deny,
            ApprovalChoice::Approve(scope) => {
                if crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                    "path_grant_persistence",
                    &[serde_json::json!({
                        "persist_grant": {"kind": "path", "path": &target, "scope": scope_label(scope), "access": format!("{required:?}")}
                    })],
                )
                .await
                .is_err()
                {
                    return Ok(Decision::Deny);
                }
                if let Err(error) = self.store.record_path(path, scope, required).await {
                    crate::engine::interrupt::record_host_approval_effect_boundary_outcome(false);
                    return Err(error.into());
                }
                Decision::Allow { scope }
            }
            ApprovalChoice::ApproveAllOnce => Decision::Deny,
            // A persistable path reject: record the standing reject, then deny
            // this access. (`Reject(Once)` is mapped to `Deny` upstream.)
            ApprovalChoice::Reject(scope) => {
                if crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                    "path_reject_persistence",
                    &[serde_json::json!({
                        "persist_reject": {"kind": "path", "path": &target, "scope": scope_label(scope), "access": format!("{required:?}")}
                    })],
                )
                .await
                .is_err()
                {
                    return Ok(Decision::Deny);
                }
                if let Err(error) = self.store.record_path_reject(path, scope).await {
                    crate::engine::interrupt::record_host_approval_effect_boundary_outcome(false);
                    return Err(error.into());
                }
                Decision::Deny
            }
        };
        self.record_permission_decision(
            "path",
            &target,
            &offered,
            decision,
            DecisionSource::UserPrompt,
        )
        .await;
        Ok(decision)
    }

    /// Two-stage approval for a gitignored `read`
    /// (implementation note). Stage 1 picks the glob
    /// **shape** — this exact file, its parent directory, or reject; stage 2
    /// (only on an approval) picks **persistence** — once / session / project.
    /// Both stages reuse the same `question`-tool interrupt path as every
    /// other approval; no bespoke dialog. `file_glob` and `parent_glob` are
    /// the project-relative gitignore-style globs the chosen shape records;
    /// `parent_label` is the human `./relative/parent/` shown on the stage-1
    /// option. Returns the resolved [`GitignoreReadOutcome`]; the caller
    /// (the read gate) performs the actual session/project persistence.
    ///
    /// A dismissal at either stage reads as **reject** — the safe default,
    /// consistent with the rest of the subsystem.
    pub async fn approve_gitignore_read(
        &self,
        display_path: &str,
        parent_label: &str,
        file_glob: &str,
        parent_glob: &str,
    ) -> Result<GitignoreReadOutcome> {
        if self.yolo_mode()
            || self
                .auto_allows(
                    crate::agent_tree::HostEffectClass::Authorization,
                    display_path,
                )
                .await
        {
            return Ok(GitignoreReadOutcome::ApproveOnce);
        }
        // Stage 1 — scope (file / parent dir / reject).
        let shape = self
            .prompt_gitignore_stage1(display_path, parent_label, file_glob, parent_glob)
            .await?;
        // Shape selection is itself an irreversible control decision: it
        // determines which immutable glob the next prompt may persist. Claim
        // that exact selector before carrying it into stage two, rather than
        // leaving an earlier ready handoff to poison the later persistence
        // boundary.
        let shape_effect = match shape {
            GitignoreShape::File => Some("gitignore_read_select_file"),
            GitignoreShape::Parent => Some("gitignore_read_select_parent"),
            GitignoreShape::Reject | GitignoreShape::NoninteractiveReject => None,
        };
        if let Some(effect) = shape_effect
            && crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                "gitignore_shape_selection",
                &[serde_json::json!({"effect": effect})],
            )
            .await
            .is_err()
        {
            return Ok(GitignoreReadOutcome::Reject);
        }
        validate_gitignore_shape_binding(file_glob, parent_glob, shape)?;
        let glob = match shape {
            GitignoreShape::NoninteractiveReject => {
                self.record_permission_decision(
                    "read",
                    display_path,
                    &[],
                    Decision::NoninteractiveDeny,
                    DecisionSource::HeadlessAutoReject,
                )
                .await;
                return Ok(GitignoreReadOutcome::NoninteractiveReject);
            }
            GitignoreShape::Reject => {
                self.record_permission_decision(
                    "read",
                    display_path,
                    &[],
                    Decision::Deny,
                    DecisionSource::UserPrompt,
                )
                .await;
                return Ok(GitignoreReadOutcome::Reject);
            }
            GitignoreShape::File => file_glob.to_string(),
            GitignoreShape::Parent => parent_glob.to_string(),
        };

        // Stage 2 — persistence (once / session / project).
        let offered = [Scope::Once, Scope::Session, Scope::Project];
        let persistence = self
            .prompt_gitignore_stage2(
                display_path,
                file_glob,
                parent_glob,
                match shape {
                    GitignoreShape::File => "file",
                    GitignoreShape::Parent => "parent",
                    // Reject branches returned above. Keep this arm explicit
                    // so a future new shape cannot accidentally receive a
                    // persistence prompt with an unbound effect.
                    GitignoreShape::Reject | GitignoreShape::NoninteractiveReject => {
                        unreachable!("gitignore rejection returned before persistence")
                    }
                },
                &glob,
            )
            .await?;
        validate_gitignore_persistence_binding(&glob, persistence)?;
        let (outcome, decision) = match persistence {
            GitignorePersistence::NoninteractiveReject => (
                GitignoreReadOutcome::NoninteractiveReject,
                Decision::NoninteractiveDeny,
            ),
            GitignorePersistence::Reject => (GitignoreReadOutcome::Reject, Decision::Deny),
            GitignorePersistence::Once => (
                GitignoreReadOutcome::ApproveOnce,
                Decision::Allow { scope: Scope::Once },
            ),
            GitignorePersistence::Session => (
                GitignoreReadOutcome::ApproveSession { glob: glob.clone() },
                Decision::Allow {
                    scope: Scope::Session,
                },
            ),
            GitignorePersistence::Project => (
                GitignoreReadOutcome::ApproveProject { glob: glob.clone() },
                Decision::Allow {
                    scope: Scope::Project,
                },
            ),
        };
        self.record_permission_decision(
            "read",
            display_path,
            &offered,
            decision,
            DecisionSource::UserPrompt,
        )
        .await;
        Ok(outcome)
    }

    /// Raise the stage-1 (scope) gitignore prompt and block for the answer.
    async fn prompt_gitignore_stage1(
        &self,
        display_path: &str,
        parent_label: &str,
        file_glob: &str,
        parent_glob: &str,
    ) -> Result<GitignoreShape> {
        let prompt = format!("`{display_path}` is gitignored. Allow the agent to read it?");
        let question = InterruptQuestion::Single {
            prompt,
            options: vec![
                opt(ApprovalOptionId::GitignoreFile, "Approve file"),
                opt(
                    ApprovalOptionId::GitignoreParent,
                    &format!("Approve parent directory ({parent_label})"),
                ),
                opt(ApprovalOptionId::GitignoreReject, "Reject"),
            ],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: Some(GrantKind::Path),
            sandbox_escalation: None,
        };
        let description = format!("`{display_path}` is gitignored — allow read?");
        let set = ApprovalOptionSet::new(
            "gitignore_shape",
            [
                ApprovalOptionId::GitignoreFile,
                ApprovalOptionId::GitignoreParent,
                ApprovalOptionId::GitignoreReject,
            ],
        );
        self.raise_and_decode(
            &description,
            question,
            "gitignore_read_shape",
            // Prompt text is not authority.  Bind both exact candidate globs
            // before showing the shape choice, so a later caller cannot
            // preserve the UI path while swapping the file/parent effect.
            serde_json::json!({
                "display_path": display_path,
                "parent_label": parent_label,
                "file_glob": file_glob,
                "parent_glob": parent_glob,
                "candidate_effects": [
                    {"selection": ID_GITIGNORE_FILE, "glob": file_glob, "effect": "gitignore_read_select_file"},
                    {"selection": ID_GITIGNORE_PARENT, "glob": parent_glob, "effect": "gitignore_read_select_parent"},
                    {"selection": ID_GITIGNORE_REJECT, "effect": "gitignore_read_reject"}
                ]
            }),
            |response| {
            if matches!(
                response,
                ResolveResponse::Freetext { text } if text == NONINTERACTIVE_RUN_DENIAL
            ) {
                return Ok(GitignoreShape::NoninteractiveReject);
            }
            let Some(id) = decode_option_response(response, &set)? else {
                return Ok(GitignoreShape::Reject);
            };
            Ok(match id {
                ApprovalOptionId::GitignoreFile => GitignoreShape::File,
                ApprovalOptionId::GitignoreParent => GitignoreShape::Parent,
                ApprovalOptionId::GitignoreReject => GitignoreShape::Reject,
                _ => return Err(ForeignOptionId::new(&set, id.as_str())),
            })
            },
        )
        .await
    }

    /// Raise the stage-2 (persistence) gitignore prompt and block for the
    /// answer.
    async fn prompt_gitignore_stage2(
        &self,
        display_path: &str,
        file_glob: &str,
        parent_glob: &str,
        selected_shape: &str,
        selected_glob: &str,
    ) -> Result<GitignorePersistence> {
        let prompt = format!("Allow reading `{display_path}` — for how long?");
        let question = InterruptQuestion::Single {
            prompt,
            options: vec![
                opt(ApprovalOptionId::ApproveOnce, "Approve once"),
                opt(ApprovalOptionId::ApproveSession, "Approve for this session"),
                opt(ApprovalOptionId::ApproveProject, "Approve for this project"),
            ],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: Some(GrantKind::Path),
            sandbox_escalation: None,
        };
        let description = format!("Allow reading `{display_path}` — persistence?");
        let set = ApprovalOptionSet::new(
            "gitignore_persistence",
            [
                ApprovalOptionId::ApproveOnce,
                ApprovalOptionId::ApproveSession,
                ApprovalOptionId::ApproveProject,
            ],
        );
        self.raise_and_decode(
            &description,
            question,
            "gitignore_read_persistence",
            // The persistence selection mutates an allowlist (or grants a
            // single read), so bind the whole operation candidate set, its
            // exact selected shape/glob, and every allowed persistence
            // scope.  Decode below remains a second, local revalidation of
            // the offered choices before the caller writes a session/project
            // grant.
            serde_json::json!({
                "display_path": display_path,
                "file_glob": file_glob,
                "parent_glob": parent_glob,
                "selected_shape": selected_shape,
                "selected_glob": selected_glob,
                "candidate_effects": [
                    {"selection": ID_APPROVE_ONCE, "effect": "gitignore_read_once", "glob": selected_glob},
                    {"selection": ID_APPROVE_SESSION, "effect": "gitignore_read_session_allow", "glob": selected_glob, "persist_grant": {"glob": selected_glob, "scope": "session"}},
                    {"selection": ID_APPROVE_PROJECT, "effect": "gitignore_read_project_allow", "glob": selected_glob, "persist_grant": {"glob": selected_glob, "scope": "project"}}
                ]
            }),
            |response| {
            if matches!(
                response,
                ResolveResponse::Freetext { text } if text == NONINTERACTIVE_RUN_DENIAL
            ) {
                return Ok(GitignorePersistence::NoninteractiveReject);
            }
            let Some(id) = decode_option_response(response, &set)? else {
                return Ok(GitignorePersistence::Reject);
            };
            Ok(match id {
                ApprovalOptionId::ApproveOnce => GitignorePersistence::Once,
                ApprovalOptionId::ApproveSession => GitignorePersistence::Session,
                ApprovalOptionId::ApproveProject => GitignorePersistence::Project,
                _ => return Err(ForeignOptionId::new(&set, id.as_str())),
            })
            },
        )
        .await
    }
}

/// Revalidate the post-prompt selection against the exact durable candidate
/// set.  The digest created before the prompt contains these values; this
/// local check keeps a malformed/stale response from turning a file choice
/// into a parent grant (or an empty glob into a broad allowlist) before the
/// host consumes the final effect.
fn validate_gitignore_shape_binding(
    file_glob: &str,
    parent_glob: &str,
    shape: GitignoreShape,
) -> Result<()> {
    anyhow::ensure!(
        !file_glob.is_empty() && !file_glob.contains('\0') && !parent_glob.contains('\0'),
        "gitignore approval candidates are invalid"
    );
    match shape {
        GitignoreShape::File => anyhow::ensure!(
            !file_glob.ends_with('/'),
            "gitignore file approval candidate is a directory"
        ),
        GitignoreShape::Parent => anyhow::ensure!(
            parent_glob.is_empty() || parent_glob.ends_with('/'),
            "gitignore parent approval candidate is not a directory glob"
        ),
        GitignoreShape::Reject | GitignoreShape::NoninteractiveReject => {}
    }
    Ok(())
}

fn validate_gitignore_persistence_binding(
    selected_glob: &str,
    persistence: GitignorePersistence,
) -> Result<()> {
    anyhow::ensure!(
        !selected_glob.contains('\0'),
        "gitignore persistence effect has an invalid selected glob"
    );
    // Every non-reject option is represented in the exact candidate set
    // bound before the prompt. Keep these variants exhaustive: adding a new
    // persistence scope requires adding its host-effect binding above.
    match persistence {
        GitignorePersistence::Once
        | GitignorePersistence::Session
        | GitignorePersistence::Project
        | GitignorePersistence::Reject
        | GitignorePersistence::NoninteractiveReject => Ok(()),
    }
}

#[cfg(test)]
mod gitignore_binding_tests {
    use super::*;

    #[test]
    fn gitignore_shape_requires_exact_nonempty_candidates() {
        assert!(
            validate_gitignore_shape_binding(
                "ignored/private.txt",
                "ignored/",
                GitignoreShape::File,
            )
            .is_ok()
        );
        assert!(validate_gitignore_shape_binding("", "ignored/", GitignoreShape::File).is_err());
        assert!(
            validate_gitignore_shape_binding(
                "ignored/private.txt",
                "not-a-directory",
                GitignoreShape::Parent,
            )
            .is_err()
        );
    }

    #[test]
    fn gitignore_root_parent_and_persistence_scope_are_not_reinterpreted() {
        assert!(
            validate_gitignore_shape_binding("ignored-at-root.txt", "", GitignoreShape::Parent,)
                .is_ok()
        );
        for persistence in [
            GitignorePersistence::Once,
            GitignorePersistence::Session,
            GitignorePersistence::Project,
        ] {
            assert!(validate_gitignore_persistence_binding("ignored/", persistence).is_ok());
        }
        assert!(
            validate_gitignore_persistence_binding("bad\0glob", GitignorePersistence::Once)
                .is_err()
        );
    }
}

/// Build the bounded preview shown before replacing an existing file. Core
/// deliberately produces plain text; terminal styling remains a TUI concern.
/// The diff truncation routes through the redacting truncator with the
/// session's redaction table so a registered secret straddling the
/// truncation boundary never leaves a PARTIAL in the emitted preview.
pub(crate) fn file_write_preview(
    redact: &crate::redact::RedactionTable,
    previous: &[u8],
    next: &[u8],
) -> WriteContentPreview {
    const CAP: usize = 12 * 1024;
    if crate::tools::common::looks_binary(previous) || crate::tools::common::looks_binary(next) {
        use sha2::{Digest as _, Sha256};
        let hash = |bytes: &[u8]| {
            Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        return WriteContentPreview {
            content: format!(
                "binary replacement: {} bytes (sha256 {}) → {} bytes (sha256 {})",
                previous.len(),
                hash(previous),
                next.len(),
                hash(next)
            ),
            dynamic: true,
        };
    }
    let before = String::from_utf8_lossy(previous);
    let after = String::from_utf8_lossy(next);
    let diff = similar::TextDiff::from_lines(before.as_ref(), after.as_ref())
        .unified_diff()
        .context_radius(3)
        .header("before", "after")
        .to_string();
    let content = if diff.len() > CAP {
        format!(
            "{}\n… [diff truncated; {} bytes omitted]",
            crate::tools::common::truncate_head_tail_redacted(redact, &diff, CAP),
            diff.len() - CAP
        )
    } else {
        diff
    };
    WriteContentPreview {
        content,
        dynamic: false,
    }
}

impl Approver {
    /// Authorize replacement of an existing non-empty file. Exact-file and
    /// parent-directory session grants share the existing path-grant store.
    pub(super) async fn approve_file_write(
        &self,
        path: &std::path::Path,
        previous: &[u8],
        next: &[u8],
    ) -> Result<Decision> {
        const FILE_SESSION: &str = "write_grant_file_session";
        const DIRECTORY_SESSION: &str = "write_grant_directory_session";
        if self.store.is_path_rejected(path).await {
            return Ok(Decision::Deny);
        }
        if !is_workspace_cockpit_path(self.store.cwd(), path)
            && self
                .store
                .is_path_granted_for(path, SandboxPathAccess::ReadWrite)
                .await
        {
            return Ok(Decision::Allow {
                scope: Scope::Session,
            });
        }
        let target = path.display().to_string();
        if self.yolo_mode()
            || self
                .auto_allows(crate::agent_tree::HostEffectClass::Destructive, &target)
                .await
        {
            return Ok(Decision::Allow { scope: Scope::Once });
        }
        // Session redaction snapshot for the write-preview diff truncation:
        // the preview must elide boundary-straddling secret partials just
        // like the model-facing truncators do.
        let redact = self
            .redact
            .as_ref()
            .map(|slot| {
                slot.read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone()
            })
            .unwrap_or_else(|| std::sync::Arc::new(crate::redact::RedactionTable::empty()));
        let question = InterruptQuestion::Single {
            prompt: format!("Replace existing file `{target}`?"),
            options: vec![
                InterruptOption {
                    id: "approve_once".to_string(),
                    label: "Approve once".to_string(),
                    description: None,
                    secondary: false,
                },
                InterruptOption {
                    id: FILE_SESSION.to_string(),
                    label: "Approve this file for this session".to_string(),
                    description: None,
                    secondary: false,
                },
                InterruptOption {
                    id: DIRECTORY_SESSION.to_string(),
                    label: "Approve this directory for this session".to_string(),
                    description: None,
                    secondary: false,
                },
                InterruptOption {
                    id: "reject".to_string(),
                    label: "Deny".to_string(),
                    description: None,
                    secondary: false,
                },
            ],
            allow_freetext: false,
            command_detail: Some(Box::new(CommandDetail {
                full_command: format!("replace {target}"),
                highlight: None,
                step: 1,
                step_count: 1,
                cwd: Some(self.store.cwd().display().to_string()),
                remembered_key: Some(target.clone()),
                write_content: Some(file_write_preview(&redact, previous, next)),
                risk_tier: Some("mutating".to_string()),
                risk_reasons: vec!["replaces existing file contents".to_string()],
                affected_targets: vec![target],
                native_tool_hints: Vec::new(),
                offered_scopes: vec![
                    "file".to_string(),
                    "directory".to_string(),
                    "session".to_string(),
                ],
                policy_cap: Some("session".to_string()),
                image_plan_review: None,
            })),
            permission: true,
            approval_class: Some(GrantKind::Path),
            sandbox_escalation: None,
        };
        let previous_commitment = write_content_commitment(previous);
        let next_commitment = write_content_commitment(next);
        let write_effect = serde_json::json!({
            "path": path.display().to_string(),
            "previous": previous_commitment,
            "next": next_commitment,
        });
        let choice = self
            .raise_and_decode(
                "Existing file modification requires approval",
                question,
                "existing_file_write",
                serde_json::json!({
                    "path": path.display().to_string(),
                    // Persist commitments, never the file body. The caller
                    // reconstructs these exact facts from the real before/
                    // after bytes on replay, while the digest keeps a large
                    // (and potentially sensitive) replacement out of the
                    // durable approval ledger.
                    "previous": write_effect["previous"].clone(),
                    "next": write_effect["next"].clone(),
                    // These are materially different persistent mutations:
                    // a session grant for this exact file versus its parent
                    // directory. Bind both complete candidate effects before
                    // the response can select one.
                    "candidate_effects": [
                        {"selection": "approve_once", "write": write_effect.clone()},
                        {"selection": FILE_SESSION, "write": write_effect.clone(), "persist_grant": {"kind": "path", "path": path.display().to_string(), "scope": "session", "access": "read_write"}},
                        {"selection": DIRECTORY_SESSION, "write": write_effect, "persist_grant": {"kind": "path", "path": path.parent().unwrap_or(path).display().to_string(), "scope": "session", "access": "read_write"}},
                        {"selection": "reject", "effect": "deny"}
                    ],
                }),
                |response| {
                    let selected = response_single_id(response).map(str::to_owned);
                    match selected.as_deref() {
                        None
                        | Some("approve_once" | FILE_SESSION | DIRECTORY_SESSION | "reject") => {
                            Ok(selected)
                        }
                        Some(received) => Err(ForeignOptionId {
                            kind: "file_write_approval",
                            offered: vec![
                                "approve_once",
                                FILE_SESSION,
                                DIRECTORY_SESSION,
                                "reject",
                            ],
                            received: received.to_string(),
                        }),
                    }
                },
            )
            .await?;
        match choice.as_deref() {
            Some("approve_once") => Ok(Decision::Allow { scope: Scope::Once }),
            Some(FILE_SESSION) => {
                if crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                    "file_write_grant_persistence",
                    &[serde_json::json!({
                        "persist_grant": {
                            "kind": "path",
                            "path": path.display().to_string(),
                            "scope": "session",
                            "access": "read_write",
                        }
                    })],
                )
                .await
                .is_err()
                {
                    return Ok(Decision::Deny);
                }
                if let Err(error) = self
                    .store
                    .record_path(path, Scope::Session, SandboxPathAccess::ReadWrite)
                    .await
                {
                    crate::engine::interrupt::record_host_approval_effect_boundary_outcome(false);
                    return Err(error.into());
                }
                Ok(Decision::Allow {
                    scope: Scope::Session,
                })
            }
            Some(DIRECTORY_SESSION) => {
                let parent = path.parent().unwrap_or(path);
                if crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                    "file_write_directory_grant_persistence",
                    &[serde_json::json!({
                        "persist_grant": {
                            "kind": "path",
                            "path": parent.display().to_string(),
                            "scope": "session",
                            "access": "read_write",
                        }
                    })],
                )
                .await
                .is_err()
                {
                    return Ok(Decision::Deny);
                }
                if let Err(error) = self
                    .store
                    .record_path(parent, Scope::Session, SandboxPathAccess::ReadWrite)
                    .await
                {
                    crate::engine::interrupt::record_host_approval_effect_boundary_outcome(false);
                    return Err(error.into());
                }
                Ok(Decision::Allow {
                    scope: Scope::Session,
                })
            }
            _ => Ok(Decision::Deny),
        }
    }
}

pub(crate) fn write_content_commitment(bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "byte_len": bytes.len(),
        "sha256": Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    })
}

#[cfg(test)]
mod file_write_preview_tests {
    use super::file_write_preview;

    fn empty_table() -> crate::redact::RedactionTable {
        crate::redact::RedactionTable::empty()
    }

    #[test]
    fn small_diff_includes_added_and_removed_lines() {
        let preview = file_write_preview(&empty_table(), b"old\nkeep\n", b"new\nkeep\n");
        assert!(preview.content.contains("-old"), "{}", preview.content);
        assert!(preview.content.contains("+new"), "{}", preview.content);
    }

    #[test]
    fn large_diff_is_truncated_and_marked() {
        let before = "old\n".repeat(5000);
        let after = "new\n".repeat(5000);
        let preview = file_write_preview(&empty_table(), before.as_bytes(), after.as_bytes());
        assert!(
            preview.content.contains("diff truncated"),
            "{}",
            preview.content
        );
    }

    #[test]
    fn binary_write_reports_summary() {
        let preview = file_write_preview(&empty_table(), b"\0old", b"\0new");
        assert!(preview.content.contains("binary replacement"));
        assert!(preview.content.contains("sha256"));
    }

    // A registered secret straddling the diff-truncation boundary leaves only
    // a PARTIAL in the retained head; the redacting truncator must elide it so
    // the whole-value scrub never sees a fragment it cannot match.
    #[test]
    fn large_diff_redacts_secret_straddling_truncation_boundary() {
        // 300-byte registered literal — wide enough that the head cut
        // (3/5 of the 12 KiB cap, just past the small unified-diff header)
        // lands inside it regardless of a few bytes of header drift.
        let secret = format!(
            "sk-live-PREVIEWSTRADDLE-{}",
            "s".repeat(300 - "sk-live-PREVIEWSTRADDLE-".len())
        );
        let table = crate::redact::RedactionTable::empty()
            .with_forced_literal(secret.clone(), "preview-leak-test".to_string())
            .unwrap();
        // The single deleted line starts ~40 bytes into the diff; place the
        // secret ~7290 bytes into that line so it spans the head cut (~7344).
        let before = format!("{}{secret}{}", "o".repeat(7290), "ld".repeat(6000));
        let after = "new\n".repeat(6000);
        let preview = file_write_preview(&table, before.as_bytes(), after.as_bytes());
        assert!(
            preview.content.contains("diff truncated"),
            "{}",
            preview.content
        );
        let prefix = &secret[..16];
        let scrubbed = table.scrub(&preview.content);
        assert!(
            !scrubbed.contains(prefix),
            "straddling prefix leaked into the preview: {}",
            &scrubbed[..80.min(scrubbed.len())]
        );
        assert!(!scrubbed.contains(&secret));
    }
}

#[cfg(test)]
mod file_write_grant_tests {
    use super::*;
    use std::sync::Arc;

    fn approver(cwd: &std::path::Path) -> Arc<Approver> {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = crate::session::Session::create_for_test(
            db.clone(),
            cwd.to_path_buf(),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let store = GrantStore::new(
            db.clone(),
            session.id,
            cwd.to_path_buf(),
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(cwd),
        );
        Arc::new(Approver::new(
            store,
            db,
            session.id,
            "builder",
            Arc::new(InterruptHub::detached()),
        ))
    }

    async fn resolve_next(approver: &Approver, selected_id: &str) {
        loop {
            let open = approver
                .db
                .list_open_interrupts(approver.session_id)
                .await
                .unwrap();
            if let Some(row) = open.first() {
                if !approver.interrupts.has_waiter(row.interrupt_id) {
                    tokio::task::yield_now().await;
                    continue;
                }
                let response = ResolveResponse::Single {
                    selected_id: selected_id.to_string(),
                };
                approver
                    .db
                    .resolve_interrupt(row.interrupt_id, &response)
                    .await
                    .unwrap();
                assert!(approver.interrupts.resolve(row.interrupt_id, response));
                return;
            }
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn write_grant_scopes_suppress_prompts() {
        let tmp = tempfile::tempdir().unwrap();
        let first = tmp.path().join("a.txt");
        let file_approver = approver(tmp.path());
        let task_approver = file_approver.clone();
        let task = tokio::spawn(async move {
            task_approver
                .approve_file_write(&first, b"old", b"new")
                .await
                .unwrap()
        });
        resolve_next(&file_approver, "write_grant_file_session").await;
        assert_eq!(
            task.await.unwrap(),
            Decision::Allow {
                scope: Scope::Session
            }
        );
        assert_eq!(
            file_approver
                .approve_file_write(&tmp.path().join("a.txt"), b"old", b"new")
                .await
                .unwrap(),
            Decision::Allow {
                scope: Scope::Session
            }
        );

        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("a.txt");
        let sibling = directory.path().join("b.txt");
        let directory_approver = approver(directory.path());
        let task_approver = directory_approver.clone();
        let task = tokio::spawn(async move {
            task_approver
                .approve_file_write(&first, b"old", b"new")
                .await
                .unwrap()
        });
        resolve_next(&directory_approver, "write_grant_directory_session").await;
        assert_eq!(
            task.await.unwrap(),
            Decision::Allow {
                scope: Scope::Session
            }
        );
        assert_eq!(
            directory_approver
                .approve_file_write(&sibling, b"old", b"new")
                .await
                .unwrap(),
            Decision::Allow {
                scope: Scope::Session
            }
        );
        let _ = sibling;
    }

    #[tokio::test]
    async fn workspace_grant_excludes_cockpit_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let approver = approver(tmp.path());
        approver
            .store()
            .record_path(tmp.path(), Scope::Session, SandboxPathAccess::ReadWrite)
            .await
            .unwrap();
        let target = tmp.path().join(".cockpit/mcp.json");
        let task_approver = approver.clone();
        let task = tokio::spawn(async move {
            task_approver
                .approve_file_write(&target, b"old", b"new")
                .await
                .unwrap()
        });
        resolve_next(&approver, "reject").await;
        assert_eq!(task.await.unwrap(), Decision::Deny);
    }
}

fn is_workspace_cockpit_path(cwd: &std::path::Path, path: &std::path::Path) -> bool {
    let Ok(relative) = path.strip_prefix(cwd) else {
        return false;
    };
    relative
        .components()
        .any(|component| component.as_os_str() == ".cockpit")
}
