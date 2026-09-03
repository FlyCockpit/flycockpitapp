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
        operation: crate::agent_tree::HostApprovalOperation,
    ) -> Result<ResolveResponse> {
        let set = InterruptQuestionSet {
            questions: vec![question],
        };
        Ok(crate::engine::interrupt::raise_and_wait_with_agent_tree(
            &self.db,
            &self.interrupts,
            self.session_id,
            &self.agent_id,
            crate::engine::agent::current_agent_instance_id(),
            description,
            set,
            // The caller has already classified and canonically bound the
            // actual host effect before this prompt is persisted. Its complete
            // input—not this display description—becomes the durable approval
            // capability and is revalidated at consume/replay time.
            crate::agent_tree::HostDecisionSubject::HostApproval { operation },
            "approval prompt",
        )
        .await
        .into_response()?)
    }

    pub(super) async fn raise_and_decode<T>(
        &self,
        description: &str,
        question: InterruptQuestion,
        operation_kind: &str,
        operation_input: serde_json::Value,
        mut decode: impl FnMut(&ResolveResponse) -> std::result::Result<T, ForeignOptionId>,
    ) -> Result<T> {
        loop {
            let operation = crate::agent_tree::HostApprovalOperation::new(
                operation_kind,
                operation_input.clone(),
            )?;
            let response = self
                .raise_and_wait(description, question.clone(), operation)
                .await?;
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
        // Issue #297 fail-closed store health gate: the standing loop rule
        // below is persisted approval state, so a corrupt store (or
        // unrepaired quarantine residue) refuses the repeat decision with
        // a repair-oriented error — including in yolo mode, where a
        // dropped persisted loop reject would otherwise auto-accept the
        // repeated effect.
        self.ensure_approvals_store_healthy()?;
        let signature = GrantStore::loop_signature(tool, wire_input);
        // The decision target is the canonical wire call (what repeated).
        let target = wire_input.to_string();
        // A loop prompt offers accept/reject at once/session/project — no
        // Global for loop rules.
        let loop_offered = [Scope::Once, Scope::Session, Scope::Project];

        // 1. Standing rule wins, at any scope. The lookup itself fails
        // closed on a corrupt store (issue #297): corruption landing after
        // the health gate above still refuses this decision instead of
        // reading as "no rule".
        if let Some(verdict) = self.store.loop_rule(&signature).await? {
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
            )
            .await;
            return Ok(repeat);
        }

        // 2. Yolo is fully unattended, but standing rules above still win.
        if self.yolo_mode() {
            self.record_permission_decision(
                tool,
                &target,
                &loop_offered,
                Decision::Allow { scope: Scope::Once },
                DecisionSource::ModeAutoAllow,
            )
            .await;
            return Ok(RepeatDecision::Accept);
        }

        // 3. No human to ask → reject the repeat (the guidance error lets
        //    the model change course; re-running would bleed the window).
        if !interactive {
            self.record_permission_decision(
                tool,
                &target,
                &loop_offered,
                Decision::Deny,
                DecisionSource::HeadlessAutoReject,
            )
            .await;
            return Ok(RepeatDecision::Reject);
        }

        // 3. Prompt with the six choices and act on the answer.
        let choice = self.prompt_repeat(tool, wire_input).await?;
        let repeat = match choice {
            RepeatChoice::AcceptOnce => RepeatDecision::Accept,
            RepeatChoice::RejectOnce => RepeatDecision::Reject,
            RepeatChoice::Always { verdict, scope } => {
                // The persisted selection promises a rule mutation. A
                // failed write cannot be downgraded to a one-off execution:
                // reject the capability so the durable selection and the
                // effect that follows it never disagree.
                let verdict_label = match verdict {
                    LoopVerdict::Accept => "accept",
                    LoopVerdict::Reject => "reject",
                };
                let scope_label = match scope {
                    Scope::Session => "session",
                    Scope::Project => "project",
                    // Decoder policy never constructs these, but an invalid
                    // scope must fail the exact-candidate claim rather than
                    // skip the durable fence.
                    Scope::Once | Scope::Global => "invalid",
                };
                if crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                    "loop_rule_persistence",
                    &[serde_json::json!({
                        "persist_rule": {
                            "tool": tool,
                            "wire_input": wire_input,
                            "verdict": verdict_label,
                            "scope": scope_label,
                        }
                    })],
                )
                .await
                .is_err()
                {
                    RepeatDecision::Reject
                } else {
                    if let Err(e) = self
                        .store
                        .record_loop_rule(&signature, verdict, scope)
                        .await
                    {
                        tracing::warn!(error = %e, tool, ?scope, "recording loop-guard rule failed; rejecting selected capability");
                        crate::engine::interrupt::record_host_approval_effect_boundary_outcome(
                            false,
                        );
                        RepeatDecision::Reject
                    } else {
                        match verdict {
                            LoopVerdict::Accept => RepeatDecision::Accept,
                            LoopVerdict::Reject => RepeatDecision::Reject,
                        }
                    }
                }
            }
        };
        self.record_permission_decision(
            tool,
            &target,
            &loop_offered,
            repeat_to_decision(repeat),
            DecisionSource::UserPrompt,
        )
        .await;
        Ok(repeat)
    }

    /// Raise the loop-guard approval prompt (six options) and block until
    /// the user answers, reusing the `question`-tool interrupt path
    /// verbatim. A dismissal (Esc/cancel) reads as reject-once — the safe
    /// default for a likely loop.
    pub(super) async fn prompt_repeat(
        &self,
        tool: &str,
        wire_input: &serde_json::Value,
    ) -> Result<RepeatChoice> {
        let question = repeat_question(tool);
        let set = InterruptQuestionSet {
            questions: vec![question],
        };
        let description = format!("Repeated `{tool}` call — likely a loop. Allow it?");

        self.raise_and_decode(
            &description,
            set.questions[0].clone(),
            "loop_guard_repeat",
            serde_json::json!({
                "tool": tool,
                "wire_input": wire_input,
                "candidate_effects": [
                    {"selection": ID_LOOP_ACCEPT_ONCE, "execute": {"tool": tool, "wire_input": wire_input}},
                    {"selection": ID_LOOP_REJECT_ONCE, "effect": "deny"},
                    {"selection": ID_LOOP_ACCEPT_SESSION, "persist_rule": {"tool": tool, "wire_input": wire_input, "verdict": "accept", "scope": "session"}, "execute": {"tool": tool, "wire_input": wire_input}},
                    {"selection": ID_LOOP_REJECT_SESSION, "persist_rule": {"tool": tool, "wire_input": wire_input, "verdict": "reject", "scope": "session"}, "effect": "deny"},
                    {"selection": ID_LOOP_ACCEPT_PROJECT, "persist_rule": {"tool": tool, "wire_input": wire_input, "verdict": "accept", "scope": "project"}, "execute": {"tool": tool, "wire_input": wire_input}},
                    {"selection": ID_LOOP_REJECT_PROJECT, "persist_rule": {"tool": tool, "wire_input": wire_input, "verdict": "reject", "scope": "project"}, "effect": "deny"}
                ]
            }),
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
        full_command: &str,
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
        // Bind the actual command effect facts before they are moved into the
        // display question. `detail` carries the complete canonical command,
        // while escalation carries the concrete retry/target scope.
        let operation_input = serde_json::json!({
            // Bind the actual shell text that reaches the execution boundary,
            // not the display label or a command-detail projection.
            "command": full_command,
            "label": label,
            "wrapper": wrapper,
            "command_detail": detail.clone(),
            "sandbox_escalation": escalation.clone(),
            "offered_scopes": offered_scopes.iter().map(|scope| scope_label(*scope)).collect::<Vec<_>>(),
            "candidate_effects": offered_scopes.iter().map(|scope| serde_json::json!({
                "selection": if wrapper {
                    ApprovalOptionId::Approve.as_str()
                } else {
                    approve_option_id_for_scope(*scope).as_str()
                },
                "execute": {"command": full_command},
                // A non-wrapper scope records an exact command approval;
                // wrappers remain once-only and thus carry no grant mutation.
                "persist_grant": if wrapper || *scope == Scope::Once {
                    serde_json::Value::Null
                } else {
                    serde_json::json!({"kind": "command", "label": label, "scope": scope_label(*scope)})
                },
            })).chain(offered_scopes.iter().copied().filter(|scope| *scope != Scope::Once).map(|scope| serde_json::json!({
                "selection": reject_option_id_for_scope(scope).as_str(),
                "persist_reject": {"kind": "command", "label": label, "scope": scope_label(scope)},
            }))).chain((extras.batch_count.is_some_and(|count| count > 1)).then(|| serde_json::json!({
                "selection": "approve_all_once",
                "execute": {"command": full_command},
            })).into_iter()).chain(std::iter::once(serde_json::json!({
                "selection": "reject", "effect": "deny"
            }))).collect::<Vec<_>>(),
            "notice": extras.notice.as_deref(),
            "batch_count": extras.batch_count,
        });
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
        let operation_kind = if wrapper {
            "wrapper_tool_approval"
        } else {
            "command_approval"
        };
        self.raise_and_decode(
            &description,
            question,
            operation_kind,
            operation_input,
            |response| response_to_approval_choice(response, &set),
        )
        .await
    }
}
