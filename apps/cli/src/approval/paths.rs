use super::*;
use crate::tools::shell_sandbox::SandboxPathAccess;

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
        let target = path.display().to_string();
        // Standing reject short-circuit (checked before allow). A rejected
        // path auto-denies the out-of-cwd access with no prompt; recorded with
        // the `StandingReject` source so the timeline reflects the reject.
        if self.store.is_path_rejected(path) {
            self.record_permission_decision(
                "path",
                &target,
                &[],
                Decision::Deny,
                DecisionSource::StandingReject,
            );
            return Ok(Decision::Deny);
        }
        if self.store.is_path_granted_for(path, required) {
            let decision = Decision::Allow {
                scope: Scope::Session,
            };
            self.record_permission_decision(
                "path",
                &target,
                &[],
                decision,
                DecisionSource::AlreadyGranted,
            );
            return Ok(decision);
        }
        // Paths are never wrappers → all four scopes are offered.
        let offered = [Scope::Once, Scope::Session, Scope::Project, Scope::Global];
        let label = path_prompt_label(&target, required);
        let description = path_prompt_description(&target, required);
        let question = approval_question(&label, false, detail, None, &offered, None);
        let response = self.raise_and_wait(&description, question).await?;
        let choice = response_to_approval_choice(&response, false);
        let decision = match choice {
            ApprovalChoice::Deny => Decision::Deny,
            ApprovalChoice::Approve(Scope::Once) => Decision::Allow { scope: Scope::Once },
            ApprovalChoice::Approve(scope) => {
                self.store.record_path(path, scope, required)?;
                Decision::Allow { scope }
            }
            ApprovalChoice::ApproveAllOnce => Decision::Deny,
            // A persistable path reject: record the standing reject, then deny
            // this access. (`Reject(Once)` is mapped to `Deny` upstream.)
            ApprovalChoice::Reject(scope) => {
                self.store.record_path_reject(path, scope)?;
                Decision::Deny
            }
        };
        self.record_permission_decision(
            "path",
            &target,
            &offered,
            decision,
            DecisionSource::UserPrompt,
        );
        Ok(decision)
    }

    /// Two-stage approval for a gitignored `read`/`readlock`
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
        // Stage 1 — scope (file / parent dir / reject).
        let shape = self
            .prompt_gitignore_stage1(display_path, parent_label)
            .await?;
        let glob = match shape {
            GitignoreShape::Reject => {
                self.record_permission_decision(
                    "read",
                    display_path,
                    &[],
                    Decision::Deny,
                    DecisionSource::UserPrompt,
                );
                return Ok(GitignoreReadOutcome::Reject);
            }
            GitignoreShape::File => file_glob.to_string(),
            GitignoreShape::Parent => parent_glob.to_string(),
        };

        // Stage 2 — persistence (once / session / project).
        let offered = [Scope::Once, Scope::Session, Scope::Project];
        let persistence = self.prompt_gitignore_stage2(display_path).await?;
        let (outcome, decision) = match persistence {
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
        );
        Ok(outcome)
    }

    /// Raise the stage-1 (scope) gitignore prompt and block for the answer.
    async fn prompt_gitignore_stage1(
        &self,
        display_path: &str,
        parent_label: &str,
    ) -> Result<GitignoreShape> {
        let prompt = format!("`{display_path}` is gitignored. Allow the agent to read it?");
        let question = InterruptQuestion::Single {
            prompt,
            options: vec![
                opt(ID_GITIGNORE_FILE, "Approve file"),
                opt(
                    ID_GITIGNORE_PARENT,
                    &format!("Approve parent directory ({parent_label})"),
                ),
                opt(ID_GITIGNORE_REJECT, "Reject"),
            ],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            sandbox_escalation: None,
        };
        let description = format!("`{display_path}` is gitignored — allow read?");
        let response = self.raise_and_wait(&description, question).await?;
        Ok(match response_single_id(&response) {
            Some(id) if id == ID_GITIGNORE_FILE => GitignoreShape::File,
            Some(id) if id == ID_GITIGNORE_PARENT => GitignoreShape::Parent,
            // Reject / dismissal / unknown → reject (safe default).
            _ => GitignoreShape::Reject,
        })
    }

    /// Raise the stage-2 (persistence) gitignore prompt and block for the
    /// answer.
    async fn prompt_gitignore_stage2(&self, display_path: &str) -> Result<GitignorePersistence> {
        let prompt = format!("Allow reading `{display_path}` — for how long?");
        let question = InterruptQuestion::Single {
            prompt,
            options: vec![
                opt(ID_ONCE, "Approve once"),
                opt(ID_SESSION, "Approve for this session"),
                opt(ID_PROJECT, "Approve for this project"),
            ],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            sandbox_escalation: None,
        };
        let description = format!("Allow reading `{display_path}` — persistence?");
        let response = self.raise_and_wait(&description, question).await?;
        Ok(match response_single_id(&response) {
            Some(id) if id == ID_ONCE => GitignorePersistence::Once,
            Some(id) if id == ID_SESSION => GitignorePersistence::Session,
            Some(id) if id == ID_PROJECT => GitignorePersistence::Project,
            // Dismissal / unknown → reject (safe default).
            _ => GitignorePersistence::Reject,
        })
    }
}
