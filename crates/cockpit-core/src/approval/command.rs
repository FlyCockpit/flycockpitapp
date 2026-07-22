use super::*;

enum CommandStepDecision {
    Decision(Decision),
    ApproveAllOnce,
}

struct CommandPromptContext {
    step: u32,
    step_count: u32,
    escalation: Option<SandboxEscalation>,
    batch_count: Option<u32>,
}

fn batch_count_for_prompting(
    prompting: &[(&classify::SimpleCommandInfo, &ApprovalPromptPolicy)],
) -> Option<u32> {
    let step_count = prompting.len() as u32;
    (step_count > 1
        && prompting
            .iter()
            .all(|(info, _)| info.risk.tier < RiskTier::Destructive))
    .then_some(step_count)
}

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
    /// approval here records the grant so future trusted confined failures of
    /// that command can rerun unconfined without another prompt; the returned
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
            suggested_paths: Vec::new(),
            suggested_access: None,
        };
        self.approve_command_inner(command, Some(escalation)).await
    }

    /// Decide the explicit `escalate` tool's human prompt. When the agent
    /// suggested blocked paths, the user can grant those paths durably and
    /// retry confined. Without suggested paths, the prompt is a one-off
    /// unconfined rerun or deny; it never records command grants.
    pub async fn approve_sandbox_escalation(
        &self,
        command: &str,
        confined_exit: i32,
        confined_stderr: String,
        grant_offer: Option<&SandboxEscalationGrantOffer>,
        command_detail: Option<CommandDetail>,
    ) -> Result<SandboxEscalationApproval> {
        let offered_scopes = grant_offer
            .map(|_| self.store.recordable_path_scopes())
            .unwrap_or_default();
        let suggested_paths = grant_offer
            .map(|offer| {
                offer
                    .paths
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let suggested_access = grant_offer.map(|offer| offer.access.storage_str().to_string());
        let escalation = SandboxEscalation {
            confined_exit,
            confined_stderr,
            suggested_paths,
            suggested_access,
        };

        let accepted = if grant_offer.is_some() && !offered_scopes.is_empty() {
            let mut accepted = Vec::new();
            for scope in &offered_scopes {
                let id = match scope {
                    Scope::Session => ApprovalOptionId::EscalateGrantSession,
                    Scope::Project => ApprovalOptionId::EscalateGrantProject,
                    Scope::Global => ApprovalOptionId::EscalateGrantGlobal,
                    Scope::Once => continue,
                };
                accepted.push(id);
            }
            accepted.push(ApprovalOptionId::EscalateRunUnconfinedOnce);
            accepted.push(ApprovalOptionId::Reject);
            accepted
        } else {
            vec![
                ApprovalOptionId::EscalateRunUnconfinedOnce,
                ApprovalOptionId::Reject,
            ]
        };
        let options = accepted
            .iter()
            .map(|id| match id {
                ApprovalOptionId::EscalateGrantSession => opt(
                    *id,
                    &format!("Grant paths for {}", scope_label(Scope::Session)),
                ),
                ApprovalOptionId::EscalateGrantProject => opt(
                    *id,
                    &format!("Grant paths for {}", scope_label(Scope::Project)),
                ),
                ApprovalOptionId::EscalateGrantGlobal => opt(
                    *id,
                    &format!("Grant paths for {}", scope_label(Scope::Global)),
                ),
                ApprovalOptionId::EscalateRunUnconfinedOnce => opt(*id, "Run once without sandbox"),
                ApprovalOptionId::Reject => opt(*id, "Deny"),
                _ => unreachable!("sandbox escalation accepted set is fixed"),
            })
            .collect();

        let prompt = if grant_offer.is_some() {
            format!(
                "`{command}` failed while sandboxed. Grant the suggested paths and retry inside the sandbox?"
            )
        } else {
            format!("`{command}` failed while sandboxed. Re-run it without the sandbox?")
        };
        let question = InterruptQuestion::Single {
            prompt,
            options,
            allow_freetext: false,
            command_detail: command_detail.map(Box::new),
            permission: true,
            approval_class: Some(GrantKind::Command),
            sandbox_escalation: Some(escalation),
        };
        let set = ApprovalOptionSet::new("sandbox_escalation", accepted);
        let choice = self
            .raise_and_decode(
                "Sandboxed command failed — choose a remedy",
                question,
                |response| response_to_approval_choice(response, &set),
            )
            .await?;
        match choice {
            ApprovalChoice::NoninteractiveDeny => Ok(SandboxEscalationApproval::NoninteractiveDeny),
            ApprovalChoice::GrantPaths(scope) => {
                let Some(offer) = grant_offer else {
                    return Ok(SandboxEscalationApproval::Deny);
                };
                if !offered_scopes.contains(&scope) {
                    return Ok(SandboxEscalationApproval::Deny);
                }
                for path in &offer.paths {
                    self.store.record_path(path, scope, offer.access)?;
                    self.record_permission_decision(
                        "path",
                        &path.display().to_string(),
                        &offered_scopes,
                        Decision::Allow { scope },
                        DecisionSource::UserPrompt,
                    );
                }
                Ok(SandboxEscalationApproval::GrantAndRetryConfined { scope })
            }
            ApprovalChoice::Approve(Scope::Once) => {
                Ok(SandboxEscalationApproval::RunUnconfinedOnce)
            }
            _ => Ok(SandboxEscalationApproval::Deny),
        }
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
        let mut simple_commands = match &classification {
            Classification::Parsed {
                simple_commands, ..
            } => simple_commands.clone(),
            // Nothing to run / can't reason about it → deny, don't guess.
            Classification::Empty | Classification::Unparseable(_) => return Ok(Decision::Deny),
        };
        // Read the policy once at the start of the decision. The whole
        // decision — prompt offer, await, and resolution — uses this captured
        // policy, so a policy change landing mid-decision never re-evaluates
        // this in-flight prompt under new rules (the next decision reads the
        // new policy).
        let policy_cfg = self.store.approval_policy();
        super::apply_dangerous_flag_policy_to_all(&mut simple_commands, &policy_cfg);
        let policies: Vec<ApprovalPromptPolicy> = simple_commands
            .iter()
            .map(|info| approval_policy_for(info, &policy_cfg))
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
        let batch_count = batch_count_for_prompting(&prompting);

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
            // constituent only, so a single dialog carries it. Preauthorization
            // is per command key, but escalation is a whole-command event.
            let esc = if prompts && step == 1 {
                escalation.clone()
            } else {
                None
            };
            let context = CommandPromptContext {
                step,
                step_count,
                escalation: esc,
                batch_count: (prompts && step == 1).then_some(batch_count).flatten(),
            };
            let step_decision = self.approve_one(info, policy, command, &context).await?;
            if matches!(step_decision, CommandStepDecision::ApproveAllOnce) {
                let decision = Decision::Allow { scope: Scope::Once };
                self.record_permission_decision_with_audit(
                    "bash",
                    command,
                    &offered,
                    decision,
                    DecisionSource::UserPrompt,
                    Some(audit),
                );
                return Ok(decision);
            }
            let CommandStepDecision::Decision(decision) = step_decision else {
                unreachable!()
            };
            match decision {
                Decision::Deny | Decision::NoninteractiveDeny => {
                    self.record_permission_decision_with_audit(
                        "bash",
                        command,
                        &offered,
                        decision,
                        DecisionSource::UserPrompt,
                        Some(audit.clone()),
                    );
                    return Ok(decision);
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
                denial @ (Decision::Deny | Decision::NoninteractiveDeny) => {
                    return Ok(Some(denial));
                }
                Decision::Allow { scope } => {
                    widest = narrowest(widest, scope);
                }
            }
        }
        Ok(Some(Decision::Allow { scope: widest }))
    }

    /// Whether this constituent will raise a prompt rather than being
    /// allowed silently: a wrapper (never persistable) always prompts;
    /// otherwise it prompts only when not already granted at a scope and
    /// issue tier that cover this invocation.
    fn will_prompt(&self, info: &SimpleCommandInfo, policy: &ApprovalPromptPolicy) -> bool {
        info.wrapper
            || !self.store.command_grant(&info.key).is_some_and(|grant| {
                grant.scope.within(policy.max_scope) && info.risk.tier <= grant.granted_tier
            })
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
        context: &CommandPromptContext,
    ) -> Result<CommandStepDecision> {
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
            return Ok(CommandStepDecision::Decision(Decision::Deny));
        }
        let stored_grant = (!info.wrapper)
            .then(|| self.store.command_grant(&info.key))
            .flatten();
        if let Some(grant) = stored_grant
            && grant.scope.within(policy.max_scope)
            && info.risk.tier <= grant.granted_tier
        {
            // Already remembered at some applicable scope.
            return Ok(CommandStepDecision::Decision(Decision::Allow {
                scope: grant.scope,
            }));
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
            context.step,
            context.step_count,
        );
        let notice = stored_grant
            .filter(|grant| {
                grant.scope.within(policy.max_scope) && info.risk.tier > grant.granted_tier
            })
            .map(|grant| out_tiered_prompt_notice(full_command, info, grant.granted_tier));
        let choice = self
            .prompt(
                &label,
                info.wrapper,
                detail,
                context.escalation.clone(),
                &policy.offered_scopes,
                PromptExtras {
                    batch_count: context.batch_count,
                    notice,
                },
            )
            .await?;
        match choice {
            ApprovalChoice::ApproveAllOnce => Ok(CommandStepDecision::ApproveAllOnce),
            ApprovalChoice::Deny => Ok(CommandStepDecision::Decision(Decision::Deny)),
            ApprovalChoice::NoninteractiveDeny => {
                Ok(CommandStepDecision::Decision(Decision::NoninteractiveDeny))
            }
            ApprovalChoice::GrantPaths(_) => Ok(CommandStepDecision::Decision(Decision::Deny)),
            ApprovalChoice::Approve(Scope::Once) => {
                Ok(CommandStepDecision::Decision(Decision::Allow {
                    scope: Scope::Once,
                }))
            }
            ApprovalChoice::Approve(scope) => {
                if !scope.within(policy.max_scope) {
                    return Ok(CommandStepDecision::Decision(Decision::Deny));
                }
                // Record BEFORE returning the decision (§3). A wrapper can
                // never reach here at a non-Once scope: the prompt only
                // offered Once for wrappers. The store rejects it anyway as
                // a belt-and-braces guard.
                self.store.record_command(info, info.risk.tier, scope)?;
                Ok(CommandStepDecision::Decision(Decision::Allow { scope }))
            }
            // `Reject(Once)` is mapped to `Deny` upstream; only a persistable
            // reject reaches here. Record the standing reject BEFORE returning
            // (mirrors the allow record), then deny this invocation.
            ApprovalChoice::Reject(scope) => {
                if !scope.within(policy.max_scope) {
                    return Ok(CommandStepDecision::Decision(Decision::Deny));
                }
                self.store.record_command_reject(info, scope)?;
                Ok(CommandStepDecision::Decision(Decision::Deny))
            }
        }
    }
}

fn out_tiered_prompt_notice(
    full_command: &str,
    info: &SimpleCommandInfo,
    granted_tier: RiskTier,
) -> String {
    let reasons = display_risk_reasons(info);
    format!(
        "`{full_command}` is riskier than what you approved for `{}`\n({} vs {}): {reasons}.",
        info.key.as_storage_str(),
        info.risk.tier.as_str(),
        granted_tier.as_str()
    )
}

fn display_risk_reasons(info: &SimpleCommandInfo) -> String {
    let flags: Vec<&str> = info
        .args
        .iter()
        .filter_map(|arg| arg.starts_with('-').then_some(arg.as_str()))
        .collect();
    if !flags.is_empty() {
        return flags.join(", ");
    }
    if !info.risk.reasons.is_empty() {
        return info.risk.reasons.join(", ");
    }
    info.risk.tier.as_str().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ApprovalPromptPolicy {
        ApprovalPromptPolicy::new(Scope::Global)
    }

    #[test]
    fn batch_count_excludes_destructive_privileged_and_dynamic_constituents() {
        let policies = [policy(), policy(), policy()];

        let ordinary = classify::classify("echo a && mkdir b && touch c");
        let ordinary_commands = ordinary.simple_commands();
        let prompting: Vec<_> = ordinary_commands.iter().zip(policies.iter()).collect();
        assert_eq!(batch_count_for_prompting(&prompting), Some(3));

        let destructive = classify::classify("echo a && rm b && touch c");
        let destructive_commands = destructive.simple_commands();
        let prompting: Vec<_> = destructive_commands.iter().zip(policies.iter()).collect();
        assert_eq!(batch_count_for_prompting(&prompting), None);

        let privileged = classify::classify("echo a && sudo true && touch c");
        let privileged_commands = privileged.simple_commands();
        let prompting: Vec<_> = privileged_commands.iter().zip(policies.iter()).collect();
        assert_eq!(batch_count_for_prompting(&prompting), None);

        let dynamic = classify::classify("echo a && sh && touch c");
        let dynamic_commands = dynamic.simple_commands();
        let prompting: Vec<_> = dynamic_commands.iter().zip(policies.iter()).collect();
        assert_eq!(batch_count_for_prompting(&prompting), None);
    }

    #[test]
    fn out_tiered_prompt_names_tier_delta_and_reasons() {
        let info = classify::classify("git push --force origin main")
            .simple_commands()
            .first()
            .cloned()
            .expect("simple command");

        assert_eq!(
            out_tiered_prompt_notice("git push --force origin main", &info, RiskTier::Ordinary,),
            "`git push --force origin main` is riskier than what you approved for `git push`\n(destructive vs ordinary): --force."
        );
    }
}
