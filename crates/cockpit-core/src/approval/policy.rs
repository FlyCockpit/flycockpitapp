use super::*;

impl Approver {
    pub fn new(
        store: GrantStore,
        db: crate::db::Db,
        session_id: uuid::Uuid,
        agent_id: impl Into<String>,
        interrupts: Arc<InterruptHub>,
    ) -> Self {
        Self {
            store,
            db,
            session_id,
            agent_id: agent_id.into(),
            interrupts,
        }
    }

    /// Read-only access to the underlying store (the §4 query API).
    pub fn store(&self) -> &GrantStore {
        &self.store
    }

    /// Record one resolved permission decision into the session timeline
    /// (and thus the export's `events.json`). Best-effort: a DB write
    /// failure is logged, never propagated — recording the audit trail must
    /// not strand the turn (priority #1: correctness over telemetry).
    ///
    /// `tool` is the tool whose call triggered the gate (`bash` for command
    /// approval, the loop-guard's tool name for a repeat, etc.); `target` is
    /// the command line or path being decided; `scopes` is the set of scopes
    /// that were offered (empty for a non-persistable once-only prompt);
    /// `decision` is the resolved verdict; `source` says how it was reached.
    pub(super) fn record_permission_decision(
        &self,
        tool: &str,
        target: &str,
        scopes: &[Scope],
        decision: Decision,
        source: DecisionSource,
    ) {
        self.record_permission_decision_with_audit(tool, target, scopes, decision, source, None);
    }

    pub(super) fn record_permission_decision_with_audit(
        &self,
        tool: &str,
        target: &str,
        scopes: &[Scope],
        decision: Decision,
        source: DecisionSource,
        audit: Option<PermissionDecisionAudit>,
    ) {
        let source = if matches!(decision, Decision::NoninteractiveDeny) {
            DecisionSource::HeadlessAutoReject
        } else {
            source
        };
        let offered: Vec<&str> = scopes.iter().map(|s| s.as_str()).collect();
        let (decision_str, scope) = match decision {
            Decision::Allow { scope } => ("allow", Some(scope.as_str())),
            Decision::Deny | Decision::NoninteractiveDeny => ("deny", None),
        };
        let mut data = serde_json::json!({
            "tool": tool,
            // `tool_call_id` is not threaded into the approval layer today;
            // record it as null so the field is always present for a reader.
            "tool_call_id": serde_json::Value::Null,
            "target": target,
            "offered_scopes": offered,
            "decision": decision_str,
            "scope": scope,
            "source": source.as_str(),
        });
        if let Some(audit) = audit
            && let Some(obj) = data.as_object_mut()
        {
            obj.insert("approval_risk".to_string(), audit.risk_json());
            obj.insert(
                "approval_policy".to_string(),
                serde_json::json!({
                    "policy_cap": audit.policy_cap.as_str(),
                    "offered_scopes": offered,
                    "selected_scope": scope,
                }),
            );
        }
        if let Err(e) = self.db.insert_session_event(
            self.session_id,
            crate::db::session_log::SessionEventKind::PermissionDecision,
            Some(&self.agent_id),
            None,
            &data,
        ) {
            tracing::warn!(error = %e, tool, source = source.as_str(), "recording permission_decision event failed");
        }
    }

    /// Escalate a single non-command tool call to the user (the
    /// command-safety gate's `auto` mode for `webfetch`/`mcp`, and
    /// its fail-closed path). Unlike [`Self::approve_command`] there is no
    /// command line to classify and no persistable key — the call's
    /// arguments vary per invocation — so this prompts **once-only** (no
    /// "remember" scopes), mirroring the wrapper-command prompt shape.
    /// `label` is the human description shown in the prompt (e.g.
    /// `` `webfetch` `` plus the URL). Returns `Allow { Once }` on approval,
    /// `Deny` on dismissal.
    pub async fn approve_tool_call(&self, label: &str) -> Result<Decision> {
        // `wrapper = true` makes the prompt offer only "Yes, once" — the
        // right shape for a non-persistable per-call approval. Nothing is
        // recorded; a later identical call prompts again.
        let choice = self
            .prompt(label, true, None, None, &[Scope::Once], None)
            .await?;
        let decision = match choice {
            // Wrapper mode: reject-once is mapped to `Deny` upstream, so a
            // `Reject` never reaches here; treat it as a deny defensively.
            ApprovalChoice::Deny
            | ApprovalChoice::Reject(_)
            | ApprovalChoice::ApproveAllOnce
            | ApprovalChoice::GrantPaths(_) => Decision::Deny,
            ApprovalChoice::NoninteractiveDeny => Decision::NoninteractiveDeny,
            ApprovalChoice::Approve(_) => Decision::Allow { scope: Scope::Once },
        };
        // Once-only per-call approval → the only offered scope is `Once`.
        self.record_permission_decision(
            "tool_call",
            label,
            &[Scope::Once],
            decision,
            DecisionSource::UserPrompt,
        );
        Ok(decision)
    }

    /// Gate the `docs` pipeline's auto-clone of a NEW dependency package
    /// (implementation note). Docs.1 runs
    /// noninteractively, but adding/cloning a package into the registry is a
    /// side effect that fetches third-party source over the network, so it
    /// requires explicit user approval — independent of the interactive
    /// `question`/handoff flow. The prompt displays the EXACT clone URL and
    /// the registry-grounded `rationale` (which official registry declared
    /// that repo) so the user sees what will be cloned and why; the rationale
    /// is never fabricated — the caller derives it from the registry metadata
    /// it actually resolved. Like [`Self::approve_tool_call`] this is a
    /// **once-only**, non-persistable per-clone approval (no "remember"
    /// scopes — each new package is its own decision). Returns `Allow { Once }`
    /// on approval, `Deny` on dismissal.
    pub async fn approve_package_add(
        &self,
        identifier: &str,
        clone_url: &str,
        rationale: &str,
    ) -> Result<Decision> {
        let prompt = format!(
            "Clone a new dependency `{identifier}` to answer a docs question?\n\nURL: {clone_url}\nWhy: {rationale}"
        );
        let question = InterruptQuestion::Single {
            prompt,
            // Once-only: each new package is its own decision, never
            // remembered (mirrors the wrapper/`approve_tool_call` shape).
            options: vec![opt(ID_ONCE, "Yes, clone it")],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: None,
            sandbox_escalation: None,
        };
        let description = format!("Clone `{identifier}` from {clone_url} for docs? ({rationale})");
        let response = self.raise_and_wait(&description, question).await?;
        // Any selection of the lone "clone it" option approves; a dismissal
        // (Cancel / unknown) reads as deny — the safe default.
        let decision = match response_single_id(&response) {
            Some(id) if id == ID_ONCE => Decision::Allow { scope: Scope::Once },
            _ => Decision::Deny,
        };
        self.record_permission_decision(
            "add-package",
            clone_url,
            &[Scope::Once],
            decision,
            DecisionSource::UserPrompt,
        );
        Ok(decision)
    }
}
