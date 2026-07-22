use super::*;

impl Approver {
    /// Persist → register → emit one `Single` interrupt and block on the
    /// answer, reusing the `question`-tool interrupt path verbatim (the same
    /// invariant ordering [`Self::prompt`] relies on). Shared by the two
    /// gitignore stages.
    pub(super) async fn raise_and_wait(
        &self,
        description: &str,
        question: InterruptQuestion,
    ) -> Result<ResolveResponse> {
        let set = InterruptQuestionSet {
            questions: vec![question],
        };
        Ok(crate::engine::interrupt::raise_and_wait(
            &self.db,
            &self.interrupts,
            self.session_id,
            &self.agent_id,
            description,
            set,
            "approval prompt",
        )
        .await
        .into_response()?)
    }

    pub(super) async fn raise_and_decode<T>(
        &self,
        description: &str,
        question: InterruptQuestion,
        mut decode: impl FnMut(&ResolveResponse) -> std::result::Result<T, ForeignOptionId>,
    ) -> Result<T> {
        loop {
            let response = self.raise_and_wait(description, question.clone()).await?;
            match decode(&response) {
                Ok(choice) => return Ok(choice),
                Err(foreign) => {
                    warn_foreign_option_id(&foreign);
                }
            }
        }
    }

    /// Decide a back-to-back identical tool call (the loop guard, GOALS
    /// §1/§12). The dispatcher calls this only once the same `(tool,
    /// wire_input)` signature has repeated to the configured threshold.
    ///
    /// Resolution order:
    /// 1. An always-* rule for this exact signature (session > project >
    ///    global, per [`GrantStore::loop_rule`]) is honored without
    ///    prompting.
    /// 2. Headless (no interactive client that can answer): **reject** —
    ///    never block waiting for input, and never silently re-run a
    ///    likely loop.
    /// 3. Otherwise raise the six-option approval prompt (reusing the
    ///    `question`-tool interrupt path) and act on the answer, recording
    ///    a session/project rule when the user chose an "always" option.
    ///
    /// `tool` + `wire_input` are the canonical post-repair call; the
    /// signature is derived from them so a rule keys on the exact call,
    /// never the tool name alone.
    pub async fn approve_repeat(
        &self,
        tool: &str,
        wire_input: &serde_json::Value,
        interactive: bool,
    ) -> Result<RepeatDecision> {
        let signature = GrantStore::loop_signature(tool, wire_input);
        // The decision target is the canonical wire call (what repeated).
        let target = wire_input.to_string();
        // A loop prompt offers accept/reject at once/session/project — no
        // Global for loop rules.
        let loop_offered = [Scope::Once, Scope::Session, Scope::Project];

        // 1. Standing rule wins, at any scope.
        if let Some(verdict) = self.store.loop_rule(&signature) {
            let repeat = match verdict {
                LoopVerdict::Accept => RepeatDecision::Accept,
                LoopVerdict::Reject => RepeatDecision::Reject,
            };
            self.record_permission_decision(
                tool,
                &target,
                &loop_offered,
                repeat_to_decision(repeat),
                DecisionSource::LoopGuardRule,
            );
            return Ok(repeat);
        }

        // 2. No human to ask → reject the repeat (the guidance error lets
        //    the model change course; re-running would bleed the window).
        if !interactive {
            self.record_permission_decision(
                tool,
                &target,
                &loop_offered,
                Decision::Deny,
                DecisionSource::HeadlessAutoReject,
            );
            return Ok(RepeatDecision::Reject);
        }

        // 3. Prompt with the six choices and act on the answer.
        let choice = self.prompt_repeat(tool).await?;
        let repeat = match choice {
            RepeatChoice::AcceptOnce => RepeatDecision::Accept,
            RepeatChoice::RejectOnce => RepeatDecision::Reject,
            RepeatChoice::Always { verdict, scope } => {
                // Record BEFORE returning, mirroring the command/path
                // approval contract. A record failure (e.g. Project scope
                // with no git root) must not strand the call: fall back to
                // applying the verdict this once and surface the error in
                // the log rather than aborting the turn.
                if let Err(e) = self.store.record_loop_rule(&signature, verdict, scope) {
                    tracing::warn!(error = %e, tool, ?scope, "recording loop-guard rule failed; applying once");
                }
                match verdict {
                    LoopVerdict::Accept => RepeatDecision::Accept,
                    LoopVerdict::Reject => RepeatDecision::Reject,
                }
            }
        };
        self.record_permission_decision(
            tool,
            &target,
            &loop_offered,
            repeat_to_decision(repeat),
            DecisionSource::UserPrompt,
        );
        Ok(repeat)
    }

    /// Raise the loop-guard approval prompt (six options) and block until
    /// the user answers, reusing the `question`-tool interrupt path
    /// verbatim. A dismissal (Esc/cancel) reads as reject-once — the safe
    /// default for a likely loop.
    pub(super) async fn prompt_repeat(&self, tool: &str) -> Result<RepeatChoice> {
        let question = repeat_question(tool);
        let set = InterruptQuestionSet {
            questions: vec![question],
        };
        let description = format!("Repeated `{tool}` call — likely a loop. Allow it?");

        self.raise_and_decode(
            &description,
            set.questions[0].clone(),
            response_to_repeat_choice,
        )
        .await
    }

    /// Raise an approval interrupt and block until the user answers,
    /// reusing the `question`-tool interrupt path verbatim. Returns the
    /// chosen scope, or `Deny` on dismissal. `detail` carries the optional
    /// bash command-detail block (the full verbatim command + highlight +
    /// step N/M); `None` for path approvals.
    pub(super) async fn prompt(
        &self,
        label: &str,
        wrapper: bool,
        detail: Option<CommandDetail>,
        escalation: Option<SandboxEscalation>,
        offered_scopes: &[Scope],
        extras: PromptExtras,
    ) -> Result<ApprovalChoice> {
        let mut description =
            prompt_description(label, wrapper, detail.as_ref(), escalation.as_ref());
        if let Some(notice) = extras.notice.as_deref() {
            description = format!("{notice}\n{description}");
        }
        let mut question = approval_question(
            label,
            wrapper,
            GrantKind::Command,
            None,
            detail,
            escalation,
            offered_scopes,
            extras.batch_count,
        );
        if let Some(notice) = extras.notice.as_deref() {
            let InterruptQuestion::Single { prompt, .. } = &mut question else {
                unreachable!("approval_question always returns Single")
            };
            *prompt = format!("{notice}\n{prompt}");
        }
        let set = approval_option_set(
            if wrapper {
                "wrapper_approval"
            } else {
                "command_approval"
            },
            wrapper,
            offered_scopes,
            extras.batch_count,
        );
        self.raise_and_decode(&description, question, |response| {
            response_to_approval_choice(response, &set)
        })
        .await
    }
}
