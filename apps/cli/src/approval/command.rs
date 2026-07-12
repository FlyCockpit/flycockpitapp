use super::*;

impl Approver {
    /// Decide a whole command string. Classifies it, then requires that
    /// **every** constituent simple command be allowed: an already-granted
    /// chain returns `Allow` with no prompt; any ungranted command (or a
    /// compound construct / wrapper) triggers a prompt for that command.
    /// A single ungranted/denied command denies the whole string.
    ///
    /// Empty/unparseable input is never auto-allowed — it returns `Deny`
    /// (the caller surfaces the parse error).
    pub async fn approve_command(&self, command: &str) -> Result<Decision> {
        self.approve_command_inner(command, None).await
    }

    /// Like [`Self::approve_command`], but for the `bash` run-fail-escalate
    /// path (sandboxing part 2): the command already ran **confined** and
    /// exited non-zero, so this prompt is the **distinct** escalation
    /// variant — it carries the confined exit code + stderr and the honest
    /// "failed while sandboxed; re-run without the sandbox?" framing rather
    /// than the first-time-approval wording. The framing rides on the first
    /// prompting constituent so a single dialog presents it. A non-`Once`
    /// approval here records the grant (future runs of that command skip the
    /// box silently — the cascade the dialog warns about); the returned
    /// `Decision::Allow { scope }` lets the caller record the chosen scope in
    /// the tool_call event.
    pub async fn approve_command_escalated(
        &self,
        command: &str,
        confined_exit: i32,
        confined_stderr: String,
    ) -> Result<Decision> {
        let escalation = SandboxEscalation {
            confined_exit,
            confined_stderr,
        };
        self.approve_command_inner(command, Some(escalation)).await
    }

    /// The shared command-approval core. `escalation` is `Some` only on the
    /// run-fail-escalate path; it rides on the first prompting constituent's
    /// prompt so the dialog renders the distinct escalation variant once.
    async fn approve_command_inner(
        &self,
        command: &str,
        escalation: Option<SandboxEscalation>,
    ) -> Result<Decision> {
        if let Some(decision) = self.approve_shell_write_targets(command).await? {
            return Ok(decision);
        }

        let classification = classify::classify(command);
        let simple_commands = match &classification {
            Classification::Parsed {
                simple_commands, ..
            } => simple_commands.clone(),
            // Nothing to run / can't reason about it → deny, don't guess.
            Classification::Empty | Classification::Unparseable(_) => return Ok(Decision::Deny),
        };
        let policies: Vec<ApprovalPromptPolicy> = simple_commands
            .iter()
            .map(|info| approval_policy_for(info, self.store.approval_policy()))
            .collect();

        // Standing reject short-circuit (the mirror of the already-granted
        // short-circuit): if any constituent carries a standing user reject,
        // the whole command is auto-denied with no prompt. Recorded with the
        // `StandingReject` source and an empty offered-scope set (no prompt
        // was raised) so the timeline reflects a reject decision, not a plain
        // deny (§14). A wrapper is never persistable, so it can't be rejected.
        if simple_commands
            .iter()
            .zip(policies.iter())
            .any(|(i, policy)| {
                !i.wrapper
                    && self
                        .store
                        .command_reject_scope(&i.key)
                        .is_some_and(|scope| scope.within(policy.max_scope))
            })
        {
            self.record_permission_decision(
                "bash",
                command,
                &[],
                Decision::Deny,
                DecisionSource::StandingReject,
            );
            return Ok(Decision::Deny);
        }

        // Pre-compute which constituents will actually prompt (a wrapper, or
        // one not already granted). `step_count` (M) is that count; each
        // prompting constituent's 1-based position within the sequence is
        // its `step` (N). Already-granted constituents are allowed silently
        // and don't advance the step counter — matching the spec's
        // "M = constituents that actually trigger a prompt".
        let prompting: Vec<(&SimpleCommandInfo, &ApprovalPromptPolicy)> = simple_commands
            .iter()
            .zip(policies.iter())
            .filter(|(info, policy)| self.will_prompt(info, policy))
            .collect();
        let step_count = prompting.len() as u32;

        // No constituent prompts → the whole chain is already granted at an
        // applicable scope. Resolve allow with no prompt and record the
        // `already_granted` source (the store short-circuit). The offered
        // scope set is empty because no prompt was raised.
        if step_count == 0 {
            let decision = Decision::Allow {
                scope: Scope::Session,
            };
            self.record_permission_decision(
                "bash",
                command,
                &[],
                decision,
                DecisionSource::AlreadyGranted,
            );
            return Ok(decision);
        }

        // A prompt is required for at least one constituent. The offered
        // scopes describe what the prompt presents (all four, unless every
        // prompting constituent is a wrapper → once only).
        let offered = offered_scopes(&prompting);
        let audit = PermissionDecisionAudit::from_prompting(&prompting);

        // Track the broadest scope we settled on, for the caller's info.
        // A chain is only as "remembered" as its narrowest decision; we
        // report `Once` if any command was only approved once.
        let mut widest = Scope::Global;
        let mut step: u32 = 0;
        for (idx, info) in simple_commands.iter().enumerate() {
            let policy = &policies[idx];
            let prompts = self.will_prompt(info, policy);
            if prompts {
                step += 1;
            }
            // The escalation framing rides on the FIRST prompting
            // constituent only, so a single dialog carries it (the box was
            // skipped per-command, but escalation is a whole-command event).
            let esc = if prompts && step == 1 {
                escalation.clone()
            } else {
                None
            };
            let decision = self
                .approve_one(info, policy, command, step, step_count, esc)
                .await?;
            match decision {
                Decision::Deny => {
                    self.record_permission_decision_with_audit(
                        "bash",
                        command,
                        &offered,
                        Decision::Deny,
                        DecisionSource::UserPrompt,
                        Some(audit.clone()),
                    );
                    return Ok(Decision::Deny);
                }
                Decision::Allow { scope } => {
                    widest = narrowest(widest, scope);
                }
            }
        }
        let decision = Decision::Allow { scope: widest };
        self.record_permission_decision_with_audit(
            "bash",
            command,
            &offered,
            decision,
            DecisionSource::UserPrompt,
            Some(audit),
        );
        Ok(decision)
    }

    async fn approve_shell_write_targets(&self, command: &str) -> Result<Option<Decision>> {
        let targets = match crate::tools::bash::shell_write_targets(command, self.store.cwd()) {
            crate::tools::bash::ShellWriteTargets::None
            | crate::tools::bash::ShellWriteTargets::Dynamic => return Ok(None),
            crate::tools::bash::ShellWriteTargets::Concrete(targets) => targets,
        };
        if targets.is_empty() {
            return Ok(None);
        }

        let preview = crate::tools::bash::shell_write_content_preview(command);
        let mut widest = Scope::Global;
        for target in targets {
            let detail = shell_write_command_detail(
                command,
                self.store.cwd(),
                std::slice::from_ref(&target),
                preview.clone(),
            );
            match self
                .approve_path_with_detail(
                    &target,
                    crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
                    Some(detail),
                )
                .await?
            {
                Decision::Deny => return Ok(Some(Decision::Deny)),
                Decision::Allow { scope } => {
                    widest = narrowest(widest, scope);
                }
            }
        }
        Ok(Some(Decision::Allow { scope: widest }))
    }

    /// Whether this constituent will raise a prompt rather than being
    /// allowed silently: a wrapper (never persistable) always prompts;
    /// otherwise it prompts only when not already granted.
    fn will_prompt(&self, info: &SimpleCommandInfo, policy: &ApprovalPromptPolicy) -> bool {
        info.wrapper
            || !self
                .store
                .command_grant_scope(&info.key)
                .is_some_and(|scope| scope.within(policy.max_scope))
    }

    /// Decide one simple command: granted → allow; else prompt. `step` /
    /// `step_count` describe this constituent's position among the
    /// prompting constituents (for the dialog's `step N of M`); they are
    /// only meaningful when this constituent prompts.
    async fn approve_one(
        &self,
        info: &SimpleCommandInfo,
        policy: &ApprovalPromptPolicy,
        full_command: &str,
        step: u32,
        step_count: u32,
        escalation: Option<SandboxEscalation>,
    ) -> Result<Decision> {
        // Standing reject short-circuit (checked before allow; the two are
        // mutually exclusive, so order is a safety belt). A wrapper is never
        // persistable in either polarity, so it can never carry a standing
        // reject — only non-wrappers are queried.
        if !info.wrapper
            && self
                .store
                .command_reject_scope(&info.key)
                .is_some_and(|scope| scope.within(policy.max_scope))
        {
            // Auto-deny with no prompt; the caller surfaces the terse guidance
            // error. The `StandingReject` source is recorded by the chain
            // driver (`approve_command_inner`).
            return Ok(Decision::Deny);
        }
        if !info.wrapper
            && let Some(scope) = self.store.command_grant_scope(&info.key)
            && scope.within(policy.max_scope)
        {
            // Already remembered at some applicable scope.
            return Ok(Decision::Allow { scope });
        }
        // The heading still shows the approval key — the exact thing a grant
        // would cover (`gh pr`, `cargo build`, `ls`) — so a "remember" choice
        // records the key, not the arg-laden command line. The full command
        // rides alongside as presentational detail (`CommandDetail`).
        let label = info.key.as_storage_str();
        let detail = command_detail(
            info,
            policy,
            full_command,
            self.store.cwd(),
            None,
            step,
            step_count,
        );
        let choice = self
            .prompt(
                &label,
                info.wrapper,
                detail,
                escalation,
                &policy.offered_scopes,
            )
            .await?;
        match choice {
            ApprovalChoice::Deny => Ok(Decision::Deny),
            ApprovalChoice::Approve(Scope::Once) => Ok(Decision::Allow { scope: Scope::Once }),
            ApprovalChoice::Approve(scope) => {
                if !scope.within(policy.max_scope) {
                    return Ok(Decision::Deny);
                }
                // Record BEFORE returning the decision (§3). A wrapper can
                // never reach here at a non-Once scope: the prompt only
                // offered Once for wrappers. The store rejects it anyway as
                // a belt-and-braces guard.
                self.store.record_command(info, scope)?;
                Ok(Decision::Allow { scope })
            }
            // `Reject(Once)` is mapped to `Deny` upstream; only a persistable
            // reject reaches here. Record the standing reject BEFORE returning
            // (mirrors the allow record), then deny this invocation.
            ApprovalChoice::Reject(scope) => {
                if !scope.within(policy.max_scope) {
                    return Ok(Decision::Deny);
                }
                self.store.record_command_reject(info, scope)?;
                Ok(Decision::Deny)
            }
        }
    }
}
