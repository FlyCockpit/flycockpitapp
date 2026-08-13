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
            session: None,
            redact: None,
        }
    }

    /// Construct the live session approver. The session supplies the shared
    /// Manual→Auto→Yolo mode for every agent context.
    pub fn new_for_session(
        store: GrantStore,
        db: crate::db::Db,
        session: Arc<crate::session::Session>,
        redact: Arc<std::sync::RwLock<Arc<crate::redact::RedactionTable>>>,
        agent_id: impl Into<String>,
        interrupts: Arc<InterruptHub>,
    ) -> Self {
        Self {
            store,
            db,
            session_id: session.id,
            agent_id: agent_id.into(),
            interrupts,
            session: Some(session),
            redact: Some(redact),
        }
    }

    pub(crate) fn approval_mode(&self) -> crate::config::extended::ApprovalMode {
        self.session
            .as_deref()
            .map(crate::session::Session::approval_mode)
            .unwrap_or(crate::config::extended::ApprovalMode::Manual)
    }

    pub(crate) fn yolo_mode(&self) -> bool {
        matches!(
            self.approval_mode(),
            crate::config::extended::ApprovalMode::Yolo
        )
    }

    pub(crate) async fn auto_allows(&self, effect: &str, payload: &str) -> bool {
        if !matches!(
            self.approval_mode(),
            crate::config::extended::ApprovalMode::Auto
        ) {
            return false;
        }
        let Some(redact) = self.redact.as_ref().map(|slot| {
            slot.read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }) else {
            return false;
        };
        let (extended, providers) = self.store.configs();
        matches!(crate::engine::safety_gate::evaluate(extended.guard_model_ref(), &providers, redact, None, effect, payload).await, crate::engine::safety_gate::SafetyOutcome::Rated(verdict) if verdict.safe)
    }

    /// Read-only access to the underlying store (the §4 query API).
    pub fn store(&self) -> &GrantStore {
        &self.store
    }

    pub async fn command_standing_reject_scope(&self, command: &str) -> Option<Scope> {
        let classification = crate::approval::classify::classify(command);
        for info in classification.simple_commands() {
            if !info.wrapper
                && !info.execution_bearing_option
                && let Some(scope) = self.store.command_reject_scope(&info.key).await
            {
                return Some(scope);
            }
        }
        None
    }

    pub async fn record_standing_reject_decision(&self, tool: &str, target: &str, scope: Scope) {
        self.record_permission_decision(
            tool,
            target,
            &[],
            Decision::StandingReject { scope },
            DecisionSource::StandingReject,
        )
        .await;
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
    pub(super) async fn record_permission_decision(
        &self,
        tool: &str,
        target: &str,
        scopes: &[Scope],
        decision: Decision,
        source: DecisionSource,
    ) {
        self.record_permission_decision_with_audit(tool, target, scopes, decision, source, None)
            .await;
    }

    pub(super) async fn record_permission_decision_with_audit(
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
            Decision::Deny | Decision::StandingReject { .. } | Decision::NoninteractiveDeny => {
                ("deny", None)
            }
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
        let data_json = match serde_json::to_string(&data) {
            Ok(data_json) => data_json,
            Err(e) => {
                tracing::warn!(error = %e, tool, source = source.as_str(), "serializing permission_decision event failed");
                return;
            }
        };
        let session_id = self.session_id;
        let agent_id = self.agent_id.clone();
        if let Err(e) = self
            .db
            .write(move |conn| {
                crate::db::Db::insert_session_event_json_conn(
                    conn,
                    session_id,
                    crate::db::session_log::SessionEventKind::PermissionDecision,
                    Some(&agent_id),
                    None,
                    crate::db::session_log::SessionEventContext::default(),
                    crate::db::session_log::now_ms(),
                    &data_json,
                )
            })
            .await
        {
            tracing::warn!(error = %e, tool, source = source.as_str(), "recording permission_decision event failed");
        }
    }

    /// Escalate a single non-command tool call to the user (the
    /// command-safety gate's `auto` mode for `mcp`, and its fail-closed path).
    /// Unlike [`Self::approve_command`] there is no
    /// command line to classify and no persistable key — the call's
    /// arguments vary per invocation — so this prompts **once-only** (no
    /// "remember" scopes), mirroring the wrapper-command prompt shape.
    /// `label` is the human description shown in the prompt (for example, an
    /// MCP server/tool call). Returns `Allow { Once }` on approval,
    /// `Deny` on dismissal.
    pub async fn approve_tool_call(&self, label: &str) -> Result<Decision> {
        self.authorize(AuthorizationRequest::NativeTool { label })
            .await
    }

    pub(super) async fn approve_tool_call_inner(&self, label: &str) -> Result<Decision> {
        if self.yolo_mode() || self.auto_allows("native_tool", label).await {
            return Ok(Decision::Allow { scope: Scope::Once });
        }
        // `wrapper = true` makes the prompt offer only "Yes, once" — the
        // right shape for a non-persistable per-call approval. Nothing is
        // recorded; a later identical call prompts again.
        let choice = self
            .prompt(
                label,
                true,
                None,
                None,
                &[Scope::Once],
                PromptExtras::default(),
            )
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
        )
        .await;
        Ok(decision)
    }

    /// Gate an external MCP server tool invocation. This is distinct from
    /// [`Self::approve_tool_call`]: the key is persistable as exact
    /// `(server, tool)`, so the user can remember a server's tool at
    /// session/project/global scope. Concurrent ungranted invocations may
    /// each prompt before either records a grant; that matches command/path
    /// behavior and avoids a per-key in-flight lock.
    pub async fn approve_mcp_tool(&self, server: &str, tool: &str) -> Result<Decision> {
        self.authorize(AuthorizationRequest::ExternalMcpTool { server, tool })
            .await
    }

    pub(super) async fn approve_mcp_tool_inner(
        &self,
        server: &str,
        tool: &str,
    ) -> Result<Decision> {
        let target = crate::approval::store::mcp_tool_key(server, tool);
        let offered = [Scope::Once, Scope::Session, Scope::Project, Scope::Global];
        if let Some(scope) = self.store.mcp_tool_reject_scope(server, tool).await {
            let decision = Decision::StandingReject { scope };
            self.record_permission_decision(
                "mcp_tool",
                &target,
                &offered,
                decision,
                DecisionSource::StandingReject,
            )
            .await;
            return Ok(decision);
        }
        if let Some(scope) = self.store.mcp_tool_grant_scope(server, tool).await {
            let decision = Decision::Allow { scope };
            self.record_permission_decision(
                "mcp_tool",
                &target,
                &offered,
                decision,
                DecisionSource::AlreadyGranted,
            )
            .await;
            return Ok(decision);
        }

        if self.yolo_mode() || self.auto_allows("mcp_tool", &target).await {
            return Ok(Decision::Allow { scope: Scope::Once });
        }
        let prompt = format!(
            "`{tool}` on MCP server `{server}` wants to run. This server is external to cockpit."
        );
        let question = approval_question(
            &target,
            false,
            GrantKind::McpTool,
            Some(&prompt),
            None,
            None,
            &offered,
            None,
        );
        let set = approval_option_set("mcp_tool_approval", false, &offered, None);
        let choice = self
            .raise_and_decode(&prompt, question, |response| {
                response_to_approval_choice(response, &set)
            })
            .await?;
        let decision = match choice {
            ApprovalChoice::NoninteractiveDeny => Decision::NoninteractiveDeny,
            ApprovalChoice::Approve(Scope::Once) => Decision::Allow { scope: Scope::Once },
            ApprovalChoice::Approve(scope) => {
                if let Err(e) = self.store.record_mcp_tool(server, tool, scope).await {
                    tracing::warn!(error = %e, server, tool, ?scope, "recording MCP tool grant failed; applying once");
                    Decision::Allow { scope: Scope::Once }
                } else {
                    Decision::Allow { scope }
                }
            }
            ApprovalChoice::Reject(scope) => {
                if let Err(e) = self.store.record_mcp_tool_reject(server, tool, scope).await {
                    tracing::warn!(error = %e, server, tool, ?scope, "recording MCP tool reject failed; denying once");
                }
                Decision::Deny
            }
            ApprovalChoice::Deny
            | ApprovalChoice::ApproveAllOnce
            | ApprovalChoice::GrantPaths(_) => Decision::Deny,
        };
        self.record_permission_decision(
            "mcp_tool",
            &target,
            &offered,
            decision,
            DecisionSource::UserPrompt,
        )
        .await;
        Ok(decision)
    }

    /// Gate a configured shell tool that would otherwise run outside the
    /// filesystem sandbox. Grants are exact `(agent, tool)` pairs; command
    /// text and arguments never broaden the authority.
    pub(super) async fn approve_custom_tool_inner(&self, tool: &str) -> Result<Decision> {
        let agent = self.agent_id.as_str();
        let target = crate::approval::store::mcp_tool_key(agent, tool);
        let offered = [Scope::Once, Scope::Session, Scope::Project, Scope::Global];
        if let Some(scope) = self.store.mcp_tool_reject_scope(agent, tool).await {
            let decision = Decision::StandingReject { scope };
            self.record_permission_decision(
                "custom_tool",
                &target,
                &offered,
                decision,
                DecisionSource::StandingReject,
            )
            .await;
            return Ok(decision);
        }
        if let Some(scope) = self.store.mcp_tool_grant_scope(agent, tool).await {
            let decision = Decision::Allow { scope };
            self.record_permission_decision(
                "custom_tool",
                &target,
                &offered,
                decision,
                DecisionSource::AlreadyGranted,
            )
            .await;
            return Ok(decision);
        }

        if self.yolo_mode() || self.auto_allows("custom_tool", &target).await {
            return Ok(Decision::Allow { scope: Scope::Once });
        }
        let prompt = format!(
            "Configured custom tool `{tool}` for agent `{agent}` wants to run outside Cockpit\x27s sandbox."
        );
        let question = approval_question(
            &target,
            false,
            GrantKind::McpTool,
            Some(&prompt),
            None,
            None,
            &offered,
            None,
        );
        let set = approval_option_set("custom_tool_approval", false, &offered, None);
        let choice = self
            .raise_and_decode(&prompt, question, |response| {
                response_to_approval_choice(response, &set)
            })
            .await?;
        let decision = match choice {
            ApprovalChoice::NoninteractiveDeny => Decision::NoninteractiveDeny,
            ApprovalChoice::Approve(Scope::Once) => Decision::Allow { scope: Scope::Once },
            ApprovalChoice::Approve(scope) => {
                if let Err(e) = self.store.record_mcp_tool(agent, tool, scope).await {
                    tracing::warn!(error = %e, agent, tool, ?scope, "recording custom tool grant failed; applying once");
                    Decision::Allow { scope: Scope::Once }
                } else {
                    Decision::Allow { scope }
                }
            }
            ApprovalChoice::Reject(scope) => {
                if let Err(e) = self.store.record_mcp_tool_reject(agent, tool, scope).await {
                    tracing::warn!(error = %e, agent, tool, ?scope, "recording custom tool reject failed; denying once");
                }
                Decision::Deny
            }
            ApprovalChoice::Deny
            | ApprovalChoice::ApproveAllOnce
            | ApprovalChoice::GrantPaths(_) => Decision::Deny,
        };
        self.record_permission_decision(
            "custom_tool",
            &target,
            &offered,
            decision,
            DecisionSource::UserPrompt,
        )
        .await;
        Ok(decision)
    }

    /// Gate server connection before stdio spawn or remote network egress.
    /// The grant key includes the resolved, non-secret connection identity.
    pub(super) async fn approve_mcp_server_connect_inner(
        &self,
        server: &str,
        identity: &str,
    ) -> Result<Decision> {
        let target = crate::approval::store::mcp_server_connect_key(server, identity);
        let offered = [Scope::Once, Scope::Session, Scope::Project, Scope::Global];
        if let Some(scope) = self
            .store
            .mcp_server_connect_reject_scope(server, identity)
            .await
        {
            let decision = Decision::StandingReject { scope };
            self.record_permission_decision(
                "mcp_server_connect",
                &target,
                &offered,
                decision,
                DecisionSource::StandingReject,
            )
            .await;
            return Ok(decision);
        }
        if let Some(scope) = self
            .store
            .mcp_server_connect_grant_scope(server, identity)
            .await
        {
            let decision = Decision::Allow { scope };
            self.record_permission_decision(
                "mcp_server_connect",
                &target,
                &offered,
                decision,
                DecisionSource::AlreadyGranted,
            )
            .await;
            return Ok(decision);
        }
        if self.yolo_mode() || self.auto_allows("mcp_server_connect", &target).await {
            return Ok(Decision::Allow { scope: Scope::Once });
        }
        let prompt = mcp_server_connect_prompt(server, identity);
        let question = approval_question(
            &target,
            false,
            GrantKind::McpTool,
            Some(&prompt),
            None,
            None,
            &offered,
            None,
        );
        let set = approval_option_set("mcp_server_connect_approval", false, &offered, None);
        let choice = self
            .raise_and_decode(&prompt, question, |response| {
                response_to_approval_choice(response, &set)
            })
            .await?;
        let decision = match choice {
            ApprovalChoice::NoninteractiveDeny => Decision::NoninteractiveDeny,
            ApprovalChoice::Approve(Scope::Once) => Decision::Allow { scope: Scope::Once },
            ApprovalChoice::Approve(scope) => {
                if let Err(error) = self
                    .store
                    .record_mcp_server_connect(server, identity, scope)
                    .await
                {
                    tracing::warn!(%error, server, identity, ?scope, "recording MCP server connect grant failed; applying once");
                    Decision::Allow { scope: Scope::Once }
                } else {
                    Decision::Allow { scope }
                }
            }
            ApprovalChoice::Reject(scope) => {
                if let Err(error) = self
                    .store
                    .record_mcp_server_connect_reject(server, identity, scope)
                    .await
                {
                    tracing::warn!(%error, server, identity, ?scope, "recording MCP server connect reject failed; denying once");
                }
                Decision::Deny
            }
            ApprovalChoice::Deny
            | ApprovalChoice::ApproveAllOnce
            | ApprovalChoice::GrantPaths(_) => Decision::Deny,
        };
        self.record_permission_decision(
            "mcp_server_connect",
            &target,
            &offered,
            decision,
            DecisionSource::UserPrompt,
        )
        .await;
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
        if self.yolo_mode() || self.auto_allows("package_clone", clone_url).await {
            return Ok(Decision::Allow { scope: Scope::Once });
        }
        let prompt = format!(
            "Clone a new dependency `{identifier}` to answer a docs question?\n\nURL: {clone_url}\nWhy: {rationale}"
        );
        let question = InterruptQuestion::Single {
            prompt,
            // Once-only: each new package is its own decision, never
            // remembered (mirrors the wrapper/`approve_tool_call` shape).
            options: vec![opt(ApprovalOptionId::ApproveOnce, "Yes, clone it")],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: None,
            sandbox_escalation: None,
        };
        let description = format!("Clone `{identifier}` from {clone_url} for docs? ({rationale})");
        let set = ApprovalOptionSet::new("package_add_approval", [ApprovalOptionId::ApproveOnce]);
        let decision = self
            .raise_and_decode(&description, question, |response| {
                let Some(id) = decode_option_response(response, &set)? else {
                    return Ok(Decision::Deny);
                };
                match id {
                    ApprovalOptionId::ApproveOnce => Ok(Decision::Allow { scope: Scope::Once }),
                    _ => Err(ForeignOptionId::new(&set, id.as_str())),
                }
            })
            .await?;
        self.record_permission_decision(
            "add-package",
            clone_url,
            &[Scope::Once],
            decision,
            DecisionSource::UserPrompt,
        )
        .await;
        Ok(decision)
    }

    /// Central authorization for every canonical computer-use action.
    ///
    /// The coordinator resolves tier before reaching this seam. "ask" pauses
    /// for a human response (raised as an interrupt); "yolo" emits no human
    /// request and imposes no semantic action/target denial — only capability
    /// boundaries, stale evidence, missing grants, and unsupported backends
    /// reject, which are checked by the coordinator before this point.
    ///
    /// This is a once-only, non-persistable per-action approval. Each
    /// provider call ID maps to one engine action/batch identity; there is
    /// no standing grant or reject for computer actions (the later lease
    /// prompt defines one-decision reuse).
    pub(super) async fn approve_computer_action_inner(
        &self,
        action_id: &str,
        tier: &str,
        action_label: &str,
    ) -> Result<Decision> {
        // Yolo tier: zero human requests, no semantic denial.
        if tier == "yolo" || self.yolo_mode() {
            return Ok(Decision::Allow { scope: Scope::Once });
        }

        // Ask tier: raise a human prompt. The action is blocked until the
        // user responds. Noninteractive clients get a noninteractive deny.
        let prompt = format!("Allow computer action `{action_label}` (id: {action_id})?");
        let question = InterruptQuestion::Single {
            prompt,
            options: vec![
                opt(ApprovalOptionId::ApproveOnce, "Yes, allow"),
                opt(ApprovalOptionId::Reject, "Deny"),
            ],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: None,
            sandbox_escalation: None,
        };
        let description = format!("Computer action `{action_label}` (id: {action_id})");
        let set = ApprovalOptionSet::new(
            "computer_action_approval",
            [ApprovalOptionId::ApproveOnce, ApprovalOptionId::Reject],
        );
        let decision = self
            .raise_and_decode(&description, question, |response| {
                // Dismissal (no selection) still denies.
                let Some(id) = decode_option_response(response, &set)? else {
                    return Ok(Decision::Deny);
                };
                match id {
                    ApprovalOptionId::ApproveOnce => Ok(Decision::Allow { scope: Scope::Once }),
                    ApprovalOptionId::Reject => Ok(Decision::Deny),
                    _ => Err(ForeignOptionId::new(&set, id.as_str())),
                }
            })
            .await?;
        self.record_permission_decision(
            "computer_action",
            action_id,
            &[Scope::Once],
            decision,
            DecisionSource::UserPrompt,
        )
        .await;
        Ok(decision)
    }
}

fn mcp_server_connect_prompt(server: &str, identity: &str) -> String {
    format!("Connect MCP server `{server}`? This runs or contacts: {identity}")
}

#[cfg(test)]
mod mcp_server_connect_tests {
    use super::*;

    #[test]
    fn server_connect_label_includes_command_and_args() {
        let prompt = mcp_server_connect_prompt(
            "filesystem",
            "stdio command=npx args=[\"-y\",\"@modelcontextprotocol/server-filesystem\"]",
        );
        assert!(prompt.contains("filesystem"));
        assert!(prompt.contains("command=npx"));
        assert!(prompt.contains("server-filesystem"));
    }
}

#[cfg(test)]
mod approval_mode_tests {
    use super::*;

    #[tokio::test]
    async fn session_approval_mode_shared_with_approver() {
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Arc::new(
            crate::session::Session::create(
                db.clone(),
                tmp.path().to_path_buf(),
                "builder",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        let store = GrantStore::new(
            db.clone(),
            session.id,
            tmp.path().to_path_buf(),
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path()),
        );
        let approver = Approver::new_for_session(
            store,
            db,
            session.clone(),
            Arc::new(std::sync::RwLock::new(Arc::new(
                crate::redact::RedactionTable::empty(),
            ))),
            "builder",
            Arc::new(InterruptHub::detached()),
        );
        session.set_approval_mode(crate::config::extended::ApprovalMode::Yolo);
        assert_eq!(
            approver.approval_mode(),
            crate::config::extended::ApprovalMode::Yolo
        );
        assert_eq!(
            approver.approve_mcp_tool("untrusted", "run").await.unwrap(),
            Decision::Allow { scope: Scope::Once }
        );
    }
}
