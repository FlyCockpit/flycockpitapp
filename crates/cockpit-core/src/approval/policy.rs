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

    pub(crate) async fn auto_allows(
        &self,
        effect: crate::agent_tree::HostEffectClass,
        payload: &str,
    ) -> bool {
        // The approval subsystem is an actual host-effect boundary, not a
        // classifier hint. Only the closed, host-owned local metadata ingress
        // is eligible for automatic resolution. Commands, credentials,
        // authorization changes, destructive writes, external/MCP/harness
        // calls, publish/purchase, and production effects always require an
        // explicit durable approval (or an already-recorded user grant).
        if effect != crate::agent_tree::HostEffectClass::LocalMetadataRefresh {
            return false;
        }
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
        matches!(crate::engine::safety_gate::evaluate(extended.guard_model_ref(), &providers, redact, None, "local_metadata_refresh", payload).await, crate::engine::safety_gate::SafetyOutcome::Rated(verdict) if verdict.safe)
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
        let input = serde_json::json!({"label": label});
        self.authorize(AuthorizationRequest::NativeTool {
            label,
            input: &input,
        })
            .await
    }

    pub(super) async fn approve_tool_call_inner(
        &self,
        label: &str,
        input: &serde_json::Value,
    ) -> Result<Decision> {
        if self.yolo_mode()
            || self
                .auto_allows(crate::agent_tree::HostEffectClass::Destructive, label)
                .await
        {
            return Ok(Decision::Allow { scope: Scope::Once });
        }
        // `wrapper = true` makes the prompt offer only "Yes, once" — the
        // right shape for a non-persistable per-call approval. Nothing is
        // recorded; a later identical call prompts again.
        let question = approval_question(
            label,
            true,
            GrantKind::Command,
            None,
            None,
            None,
            &[Scope::Once],
            None,
        );
        let set = approval_option_set("native_tool_approval", true, &[Scope::Once], None);
        let choice = self
            .raise_and_decode(
                label,
                question,
                "native_tool",
                serde_json::json!({
                    "label": label,
                    "wire_input": input,
                    "candidate_effects": [
                        // `label` is presentation only. The canonical wire
                        // input is the exact value the eventual native-tool
                        // dispatcher can re-derive at its concrete boundary.
                        {"selection": "approve", "execute": {"wire_input": input}},
                        {"selection": "reject", "effect": "deny"}
                    ],
                }),
                |response| response_to_approval_choice(response, &set),
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
    pub async fn approve_mcp_tool(
        &self,
        server: &str,
        tool: &str,
        input: &serde_json::Value,
        target: &serde_json::Value,
    ) -> Result<Decision> {
        self.authorize(AuthorizationRequest::ExternalMcpTool {
            server,
            tool,
            input,
            target,
        })
            .await
    }

    pub(super) async fn approve_mcp_tool_inner(
        &self,
        server: &str,
        tool: &str,
        input: &serde_json::Value,
        effect_target: &serde_json::Value,
    ) -> Result<Decision> {
        let grant_target = crate::approval::store::mcp_tool_key(server, tool);
        let offered = [Scope::Once, Scope::Session, Scope::Project, Scope::Global];
        if let Some(scope) = self.store.mcp_tool_reject_scope(server, tool).await {
            let decision = Decision::StandingReject { scope };
            self.record_permission_decision(
                "mcp_tool",
                &grant_target,
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
                &grant_target,
                &offered,
                decision,
                DecisionSource::AlreadyGranted,
            )
            .await;
            return Ok(decision);
        }

        if self.yolo_mode()
            || self
                .auto_allows(
                    crate::agent_tree::HostEffectClass::ExternalAction,
                    &grant_target,
                )
                .await
        {
            return Ok(Decision::Allow { scope: Scope::Once });
        }
        let prompt = format!(
            "`{tool}` on MCP server `{server}` wants to run. This server is external to cockpit."
        );
        let question = approval_question(
            &grant_target,
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
            .raise_and_decode(
                &prompt,
                question,
                "external_mcp_tool",
                serde_json::json!({
                    "server": server,
                    "tool": tool,
                    "wire_input": input,
                    "target": effect_target,
                    "offered_scopes": offered.iter().map(|scope| scope_label(*scope)).collect::<Vec<_>>(),
                    "candidate_effects": offered.iter().map(|scope| serde_json::json!({
                        "selection": approve_option_id_for_scope(*scope).as_str(),
                        "execute": {"server": server, "tool": tool, "wire_input": input, "target": effect_target},
                        "persist_grant": if *scope == Scope::Once { serde_json::Value::Null } else { serde_json::json!({"kind": "mcp_tool", "key": grant_target, "scope": scope_label(*scope)}) },
                    })).chain(offered.iter().copied().filter(|scope| *scope != Scope::Once).map(|scope| serde_json::json!({
                        "selection": reject_option_id_for_scope(scope).as_str(),
                        "persist_reject": {"kind": "mcp_tool", "key": grant_target, "scope": scope_label(scope)}
                    }))).chain(std::iter::once(serde_json::json!({
                        "selection": "reject", "effect": "deny"
                    }))).collect::<Vec<_>>(),
                }),
                |response| response_to_approval_choice(response, &set),
            )
            .await?;
        let decision = match choice {
            ApprovalChoice::NoninteractiveDeny => Decision::NoninteractiveDeny,
            ApprovalChoice::Approve(Scope::Once) => Decision::Allow { scope: Scope::Once },
            ApprovalChoice::Approve(scope) => {
                if crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                    "mcp_tool_grant_persistence",
                    &[serde_json::json!({"persist_grant": {"kind": "mcp_tool", "key": &grant_target, "scope": scope_label(scope)}})],
                ).await.is_err() {
                    Decision::Deny
                } else {
                    if let Err(e) = self.store.record_mcp_tool(server, tool, scope).await {
                        tracing::warn!(error = %e, server, tool, ?scope, "recording MCP tool grant failed; rejecting selected capability");
                        crate::engine::interrupt::record_host_approval_effect_boundary_outcome(false);
                        Decision::Deny
                    } else {
                        Decision::Allow { scope }
                    }
                }
            }
            ApprovalChoice::Reject(scope) => {
                if crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                    "mcp_tool_reject_persistence",
                    &[serde_json::json!({"persist_reject": {"kind": "mcp_tool", "key": &grant_target, "scope": scope_label(scope)}})],
                ).await.is_err() {
                    Decision::Deny
                } else {
                    if let Err(e) = self.store.record_mcp_tool_reject(server, tool, scope).await {
                        tracing::warn!(error = %e, server, tool, ?scope, "recording MCP tool reject failed; denying once");
                        crate::engine::interrupt::record_host_approval_effect_boundary_outcome(false);
                    }
                    Decision::Deny
                }
            }
            ApprovalChoice::Deny
            | ApprovalChoice::ApproveAllOnce
            | ApprovalChoice::GrantPaths(_) => Decision::Deny,
        };
        self.record_permission_decision(
            "mcp_tool",
            &grant_target,
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
    pub(super) async fn approve_custom_tool_inner(
        &self,
        tool: &str,
        command: &str,
        input: &serde_json::Value,
        cwd: &std::path::Path,
    ) -> Result<Decision> {
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

        if self.yolo_mode()
            || self
                .auto_allows(
                    crate::agent_tree::HostEffectClass::ExternalAction,
                    &target,
                )
                .await
        {
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
            .raise_and_decode(
                &prompt,
                question,
                "custom_tool",
                serde_json::json!({
                    "agent": agent,
                    "tool": tool,
                    "command": command,
                    "wire_input": input,
                    "cwd": cwd,
                    "offered_scopes": offered.iter().map(|scope| scope_label(*scope)).collect::<Vec<_>>(),
                    "candidate_effects": offered.iter().map(|scope| serde_json::json!({
                        "selection": approve_option_id_for_scope(*scope).as_str(),
                        "execute": {"agent": agent, "tool": tool, "command": command, "wire_input": input, "cwd": cwd},
                        "persist_grant": if *scope == Scope::Once { serde_json::Value::Null } else { serde_json::json!({"kind": "custom_tool", "key": target, "scope": scope_label(*scope)}) },
                    })).chain(offered.iter().copied().filter(|scope| *scope != Scope::Once).map(|scope| serde_json::json!({
                        "selection": reject_option_id_for_scope(scope).as_str(),
                        "persist_reject": {"kind": "custom_tool", "key": target, "scope": scope_label(scope)}
                    }))).chain(std::iter::once(serde_json::json!({
                        "selection": "reject", "effect": "deny"
                    }))).collect::<Vec<_>>(),
                }),
                |response| response_to_approval_choice(response, &set),
            )
            .await?;
        let decision = match choice {
            ApprovalChoice::NoninteractiveDeny => Decision::NoninteractiveDeny,
            ApprovalChoice::Approve(Scope::Once) => Decision::Allow { scope: Scope::Once },
            ApprovalChoice::Approve(scope) => {
                if crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                    "custom_tool_grant_persistence",
                    &[serde_json::json!({"persist_grant": {"kind": "custom_tool", "key": &target, "scope": scope_label(scope)}})],
                ).await.is_err() {
                    Decision::Deny
                } else {
                    if let Err(e) = self.store.record_mcp_tool(agent, tool, scope).await {
                        tracing::warn!(error = %e, agent, tool, ?scope, "recording custom tool grant failed; rejecting selected capability");
                        crate::engine::interrupt::record_host_approval_effect_boundary_outcome(false);
                        Decision::Deny
                    } else {
                        Decision::Allow { scope }
                    }
                }
            }
            ApprovalChoice::Reject(scope) => {
                if crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                    "custom_tool_reject_persistence",
                    &[serde_json::json!({"persist_reject": {"kind": "custom_tool", "key": &target, "scope": scope_label(scope)}})],
                ).await.is_err() {
                    Decision::Deny
                } else {
                    if let Err(e) = self.store.record_mcp_tool_reject(agent, tool, scope).await {
                        tracing::warn!(error = %e, agent, tool, ?scope, "recording custom tool reject failed; denying once");
                        crate::engine::interrupt::record_host_approval_effect_boundary_outcome(false);
                    }
                    Decision::Deny
                }
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
        if self.yolo_mode()
            || self
                .auto_allows(
                    crate::agent_tree::HostEffectClass::ExternalAction,
                    &target,
                )
                .await
        {
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
            .raise_and_decode(
                &prompt,
                question,
                "mcp_server_connect",
                serde_json::json!({
                    "server": server,
                    "identity": identity,
                    "offered_scopes": offered.iter().map(|scope| scope_label(*scope)).collect::<Vec<_>>(),
                    "candidate_effects": offered.iter().map(|scope| serde_json::json!({
                        "selection": approve_option_id_for_scope(*scope).as_str(),
                        "connect": {"server": server, "identity": identity},
                        "persist_grant": if *scope == Scope::Once { serde_json::Value::Null } else { serde_json::json!({"kind": "mcp_server_connect", "key": target, "scope": scope_label(*scope)}) },
                    })).chain(offered.iter().copied().filter(|scope| *scope != Scope::Once).map(|scope| serde_json::json!({
                        "selection": reject_option_id_for_scope(scope).as_str(),
                        "persist_reject": {"kind": "mcp_server_connect", "key": target, "scope": scope_label(scope)}
                    }))).chain(std::iter::once(serde_json::json!({
                        "selection": "reject", "effect": "deny"
                    }))).collect::<Vec<_>>(),
                }),
                |response| response_to_approval_choice(response, &set),
            )
            .await?;
        let decision = match choice {
            ApprovalChoice::NoninteractiveDeny => Decision::NoninteractiveDeny,
            ApprovalChoice::Approve(Scope::Once) => Decision::Allow { scope: Scope::Once },
            ApprovalChoice::Approve(scope) => {
                if crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                    "mcp_connect_grant_persistence",
                    &[serde_json::json!({"persist_grant": {"kind": "mcp_server_connect", "key": &target, "scope": scope_label(scope)}})],
                ).await.is_err() {
                    Decision::Deny
                } else {
                    if let Err(error) = self
                        .store
                        .record_mcp_server_connect(server, identity, scope)
                        .await
                    {
                        tracing::warn!(%error, server, identity, ?scope, "recording MCP server connect grant failed; rejecting selected capability");
                        crate::engine::interrupt::record_host_approval_effect_boundary_outcome(false);
                        Decision::Deny
                    } else {
                        Decision::Allow { scope }
                    }
                }
            }
            ApprovalChoice::Reject(scope) => {
                if crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
                    "mcp_connect_reject_persistence",
                    &[serde_json::json!({"persist_reject": {"kind": "mcp_server_connect", "key": &target, "scope": scope_label(scope)}})],
                ).await.is_err() {
                    Decision::Deny
                } else {
                    if let Err(error) = self
                        .store
                        .record_mcp_server_connect_reject(server, identity, scope)
                        .await
                    {
                        tracing::warn!(%error, server, identity, ?scope, "recording MCP server connect reject failed; denying once");
                        crate::engine::interrupt::record_host_approval_effect_boundary_outcome(false);
                    }
                    Decision::Deny
                }
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
        if self.yolo_mode()
            || self
                .auto_allows(
                    crate::agent_tree::HostEffectClass::ExternalAction,
                    clone_url,
                )
                .await
        {
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
            .raise_and_decode(
                &description,
                question,
                "package_clone",
                serde_json::json!({
                    "identifier": identifier,
                    "clone_url": clone_url,
                    "rationale": rationale,
                    "candidate_effects": [
                        {"selection": "approve_once", "execute": {"identifier": identifier, "clone_url": clone_url, "rationale": rationale}},
                        {"selection": "reject", "effect": "deny"}
                    ],
                }),
                |response| {
                let Some(id) = decode_option_response(response, &set)? else {
                    return Ok(Decision::Deny);
                };
                match id {
                    ApprovalOptionId::ApproveOnce => Ok(Decision::Allow { scope: Scope::Once }),
                    _ => Err(ForeignOptionId::new(&set, id.as_str())),
                }
                },
            )
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
        session_id: &str,
        delegation_id: &str,
        action_id: &str,
        tier: &str,
        action_label: &str,
        backend_kind: &str,
        focus_generation: u64,
        observation_generation: u64,
        has_host_lease: bool,
        provider_call_id: &str,
        batch_index: u32,
        geometry_generation: u64,
        action_class: &str,
        action_payload_digest: &str,
        lease_binding_digest: Option<&str>,
        target_evidence_binding_digest: &str,
    ) -> Result<Decision> {
        // Yolo tier: zero human requests, no semantic denial. Only the
        // *computer* effective tier grants this — the global session
        // `ApprovalMode::Yolo` must NOT auto-allow a computer action under
        // `computer_use=ask`. The computer path is gated independently of the
        // global approval mode, so an ask-tier computer action still prompts
        // even when the session is in global YOLO.
        if tier == "yolo" {
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
            .raise_and_decode(
                &description,
                question,
                "computer_action",
                serde_json::json!({
                    "session_id": session_id,
                    "delegation_id": delegation_id,
                    "action_id": action_id,
                    "tier": tier,
                    "action_label": action_label,
                    "backend_kind": backend_kind,
                    "focus_generation": focus_generation,
                    "observation_generation": observation_generation,
                    "geometry_generation": geometry_generation,
                    "provider_call_id": provider_call_id,
                    "batch_index": batch_index,
                    "action_class": action_class,
                    "has_host_lease": has_host_lease,
                    "lease_binding_digest": lease_binding_digest,
                    "target_evidence_binding_digest": target_evidence_binding_digest,
                    "payload_digest": action_payload_digest,
                    "candidate_effects": [
                        {"selection": "approve_once", "execute": {"session_id": session_id, "delegation_id": delegation_id, "action_id": action_id, "tier": tier, "action_label": action_label, "backend_kind": backend_kind, "focus_generation": focus_generation, "observation_generation": observation_generation, "geometry_generation": geometry_generation, "provider_call_id": provider_call_id, "batch_index": batch_index, "action_class": action_class, "has_host_lease": has_host_lease, "payload_digest": action_payload_digest, "lease_binding_digest": lease_binding_digest, "target_evidence_binding_digest": target_evidence_binding_digest}},
                        {"selection": "reject", "effect": "deny"}
                    ],
                }),
                |response| {
                // Dismissal (no selection) still denies.
                let Some(id) = decode_option_response(response, &set)? else {
                    return Ok(Decision::Deny);
                };
                match id {
                    ApprovalOptionId::ApproveOnce => Ok(Decision::Allow { scope: Scope::Once }),
                    ApprovalOptionId::Reject => Ok(Decision::Deny),
                    _ => Err(ForeignOptionId::new(&set, id.as_str())),
                }
                },
            )
            .await?;
        // No durable permission record for computer actions. The delegation
        // lease contract forbids standing computer grants: reuse of an Ask
        // approval is only via the in-memory `AskDelegationLease`, never a
        // persisted `permission_decision` row. (Contrast every other approval
        // path, which records the decision here.)
        Ok(decision)
    }

    /// The single central authorization for an external audio-transcription
    /// media egress (purpose `transcription`).
    ///
    /// This is the one decision issuer for transcription dispatch. The decision
    /// binds the exact `transcription_request_digest`, so every use independently
    /// re-authorizes the exact request — there is no global grant, and a standing
    /// grant identity is destination/project/purpose policy, never a blanket
    /// allow. The layers:
    ///
    /// 1. **Yolo** opens no human prompt and allows once after reaching this seam
    ///    (agent discretion; no grant persisted).
    /// 2. **Manual/Auto** honor a matching standing grant (fails closed this
    ///    increment; see [`Self::media_egress_grant_matches`]), else ask the
    ///    human, disclosing only the redacted provider/model/interval facts and
    ///    the digest prefix.
    ///
    /// Fail-closed everywhere: a missing grant never fakes an allow.
    pub(super) async fn approve_media_egress_inner(
        &self,
        facts: MediaEgressAuthzFacts<'_>,
    ) -> Result<Decision> {
        // Redacted audit of the exact request under decision. Every field is a
        // safe digest, identity, count, or boolean — the credential FINGERPRINT
        // digest is not the token, and no prompt/keyword/language string or
        // audio byte is present.
        tracing::debug!(
            purpose = facts.purpose,
            provider_id = facts.provider_id,
            model_id = facts.model_id,
            credential_fingerprint_digest = facts.credential_fingerprint_digest.as_str(),
            project_digest = facts.project_digest,
            session_id = facts.session_id,
            attachment_id = facts.attachment_id,
            attachment_checksum = facts.attachment_checksum,
            interval_start_us = facts.interval_start_us,
            interval_end_us = facts.interval_end_us,
            prompt_present = facts.prompt_present,
            keyword_count = facts.keyword_count,
            language_count = facts.language_count,
            timestamps = facts.timestamps,
            diarization = facts.diarization,
            request_digest = facts.request_digest.as_str(),
            "authorizing transcription media egress"
        );
        match self.approval_mode() {
            crate::config::extended::ApprovalMode::Yolo => {
                Ok(Decision::Allow { scope: Scope::Once })
            }
            crate::config::extended::ApprovalMode::Manual
            | crate::config::extended::ApprovalMode::Auto => {
                if self.media_egress_grant_matches(&facts) {
                    Ok(Decision::Allow { scope: Scope::Once })
                } else {
                    self.raise_media_egress_prompt(&facts).await
                }
            }
        }
    }

    /// Grant-matching hook for transcription media egress. A matching persisted
    /// grant lets Manual/Auto short-circuit to a standing allow without a prompt.
    ///
    /// TODO(audio-transcription-grant-persistence): this increment ships no
    /// session/project transcription grant store, so the seam fails closed — no
    /// grant ever matches, and Manual/Auto always ask the human, re-authorizing
    /// the exact digest each time. A later increment consults the store keyed by
    /// destination/project/purpose (never a global grant) and must fail closed on
    /// any lookup error and never fake a match.
    fn media_egress_grant_matches(&self, _facts: &MediaEgressAuthzFacts<'_>) -> bool {
        false
    }

    /// Raise the human transcription media-egress approval prompt (Manual/Auto
    /// without a matching grant). A single approve/deny question carrying only
    /// secret-free facts: provider/model, the media interval, and the digest
    /// prefix. No prompt text, keyword/language strings, credential token, or
    /// audio bytes are ever disclosed. Approve → allow once; deny/dismiss → deny.
    async fn raise_media_egress_prompt(
        &self,
        facts: &MediaEgressAuthzFacts<'_>,
    ) -> Result<Decision> {
        let digest_prefix: String = facts.request_digest.as_str().chars().take(12).collect();
        let prompt = format!(
            "Approve {} egress to `{}` model `{}` for attachment interval {}..{}us (request {})?",
            facts.purpose,
            facts.provider_id,
            facts.model_id,
            facts.interval_start_us,
            facts.interval_end_us,
            digest_prefix,
        );
        let question = InterruptQuestion::Single {
            prompt,
            options: vec![
                opt(ApprovalOptionId::ApproveOnce, "Yes, transcribe"),
                opt(ApprovalOptionId::Reject, "Deny"),
            ],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: None,
            sandbox_escalation: None,
        };
        let description = format!(
            "{} egress to `{}` model `{}` (request {})",
            facts.purpose, facts.provider_id, facts.model_id, digest_prefix,
        );
        let set = ApprovalOptionSet::new(
            "media_egress_approval",
            [ApprovalOptionId::ApproveOnce, ApprovalOptionId::Reject],
        );
        // This is the durable authority input, deliberately richer than the
        // display prompt. It carries every secret-free fact that can select or
        // scope the external egress and the exact request digest that binds
        // hidden prompt/audio/credential material. The concrete multipart
        // dispatch must re-present the matching `execute` member at its host
        // boundary; a rendered description is never effect authority.
        let egress = serde_json::json!({
            "purpose": facts.purpose,
            "request_digest": facts.request_digest.as_str(),
            "provider_id": facts.provider_id,
            "model_id": facts.model_id,
            "credential_fingerprint_digest": facts.credential_fingerprint_digest.as_str(),
            "project_digest": facts.project_digest,
            "session_id": facts.session_id,
            "attachment_id": facts.attachment_id,
            "attachment_checksum": facts.attachment_checksum,
            "interval_start_us": facts.interval_start_us,
            "interval_end_us": facts.interval_end_us,
            "prompt_present": facts.prompt_present,
            "keyword_count": facts.keyword_count,
            "language_count": facts.language_count,
            "timestamps": facts.timestamps,
            "diarization": facts.diarization,
        });
        self.raise_and_decode(
            &description,
            question,
            "media_egress_transcription",
            serde_json::json!({
                "egress": egress.clone(),
                "candidate_effects": [
                    {
                        "selection": ApprovalOptionId::ApproveOnce.as_str(),
                        "scope": "once",
                        "execute": {"media_egress": egress},
                    },
                    {
                        "selection": ApprovalOptionId::Reject.as_str(),
                        "effect": "deny",
                    },
                ],
            }),
            |response| {
            // Dismissal (no selection) denies, fail closed.
            let Some(id) = decode_option_response(response, &set)? else {
                return Ok(Decision::Deny);
            };
            match id {
                ApprovalOptionId::ApproveOnce => Ok(Decision::Allow { scope: Scope::Once }),
                ApprovalOptionId::Reject => Ok(Decision::Deny),
                _ => Err(ForeignOptionId::new(&set, id.as_str())),
            }
            },
        )
        .await
    }

    /// The single composite authorization for an image-generation dispatch.
    ///
    /// This is the one decision issuer for image generation — the deleted
    /// bespoke `authorize_generate_image` ladder had zero callers and is gone.
    /// The decision layers, in order:
    ///
    /// 1. **Hard gates** (destination enabled, capability fresh, reference-read
    ///    and output-write authority, insecure-transport policy, and the
    ///    unknown-cost dispatch rule). Any failure denies. Yolo cannot bypass
    ///    them.
    /// 2. **Pure risk tier** via
    ///    [`crate::image_generation_agent_tools::classify_risk`] — informs the
    ///    Auto safe-risk policy branch; it never issues a decision itself.
    /// 3. **Grant-matching seam** ([`Self::image_generation_grant_matches`]) —
    ///    a matching persisted grant lets Manual short-circuit to a standing
    ///    allow and Auto to a safe-risk policy allow without a prompt.
    /// 4. **Approval-mode dispatch** over the shared session mode: Yolo
    ///    auto-allows after the hard gates (agent discretion, no grant, no
    ///    prompt); Manual/Auto honor a matching grant, else ask the human.
    ///
    /// Fail-closed everywhere: a missing decision input (a grant that does not
    /// yet exist) never fakes an allow — Manual/Auto fall through to a human
    /// prompt rather than assume a grant.
    pub(super) async fn approve_image_generation_inner(
        &self,
        facts: ImageGenerationAuthzFacts<'_>,
    ) -> Result<Decision> {
        use crate::image_generation_agent_tools::{
            GenerateImageRiskTier, SpendPolicyChoice, classify_risk,
        };

        // 1. Hard gates. Any failure denies, before any provider contact or
        //    human prompt, and Yolo cannot bypass them.
        let mut hard_gate_failed = false;
        hard_gate_failed |= !facts.destination_enabled;
        hard_gate_failed |= !facts.capability_fresh;
        hard_gate_failed |= !facts.path_read_authorized;
        hard_gate_failed |= !facts.output_write_authorized;
        hard_gate_failed |= !facts.insecure_transport_allowed;

        // Unknown maximum cost may dispatch only when the request, session, and
        // project spend choices are all explicitly Unlimited.
        let unknown_cost = facts.cost_maximum.is_none();
        let unknown_dispatch_allowed = matches!(facts.spend_request, SpendPolicyChoice::Unlimited)
            && matches!(facts.spend_session, SpendPolicyChoice::Unlimited)
            && matches!(facts.spend_project, SpendPolicyChoice::Unlimited);
        if unknown_cost && !unknown_dispatch_allowed {
            hard_gate_failed = true;
        }

        if hard_gate_failed {
            // Fail closed. No prompt is raised and no provider is contacted.
            return Ok(Decision::Deny);
        }

        // 2. Pure risk tier (informational for the Auto safe-risk branch).
        let risk_tier = classify_risk(
            facts.fanout,
            facts.total_outputs,
            facts.cost_maximum,
            facts.reference_egress_unmatched,
            facts.base_threshold_usd_micros,
        );

        // 3. Grant-matching seam (fails closed this increment; see below).
        let grant_matches = self.image_generation_grant_matches(&facts);

        // 4. Approval-mode dispatch over the shared session mode.
        match self.approval_mode() {
            crate::config::extended::ApprovalMode::Yolo => {
                // Yolo opens no human prompt and records agent discretion after
                // every hard gate passed; it requires no grant and persists
                // none. (A later increment records the `agent_discretion`
                // disposition audit alongside grant persistence.)
                Ok(Decision::Allow { scope: Scope::Once })
            }
            crate::config::extended::ApprovalMode::Manual => {
                if grant_matches {
                    // A matching standing grant is an explicit prior user
                    // decision — short-circuit to a standing allow.
                    Ok(Decision::Allow { scope: Scope::Once })
                } else {
                    // No grant input available: ask the human. Never assume a
                    // grant that does not exist.
                    self.raise_image_generation_prompt(&facts).await
                }
            }
            crate::config::extended::ApprovalMode::Auto => {
                // Auto auto-allows only a base-risk request already covered by a
                // matching grant (the central safe-risk policy). Any elevated
                // risk, or the absence of a grant, asks the human.
                if grant_matches && matches!(risk_tier, GenerateImageRiskTier::Base) {
                    Ok(Decision::Allow { scope: Scope::Once })
                } else {
                    self.raise_image_generation_prompt(&facts).await
                }
            }
        }
    }

    /// Grant-matching hook for image generation. A matching persisted grant
    /// lets Manual short-circuit to a standing-grant allow and Auto to a
    /// safe-risk policy allow without a human prompt.
    ///
    /// TODO(image-generation-grant-persistence): this increment ships no
    /// once/session/project grant SQLite schema or store yet, so the seam fails
    /// closed — no grant ever matches, and Manual/Auto always ask the human. A
    /// later increment folds the grant store into `0001_initial.sql` and
    /// consults it here, keyed by the plan/destination digests carried on
    /// `facts`. It must fail closed on any lookup error and never fake a match.
    fn image_generation_grant_matches(&self, _facts: &ImageGenerationAuthzFacts<'_>) -> bool {
        false
    }

    /// Raise the human image-generation approval prompt (Manual/Auto without a
    /// matching grant). Mirrors the once-only computer-action prompt: a single
    /// approve/deny question carrying only the secret-free destination count
    /// and plan-digest prefix. Approve → allow once; deny/dismiss → deny.
    async fn raise_image_generation_prompt(
        &self,
        facts: &ImageGenerationAuthzFacts<'_>,
    ) -> Result<Decision> {
        let digest_prefix: String = facts.plan_digest.as_str().chars().take(12).collect();
        let destination_count = facts.destinations.len();
        // Disclose the redacted output write-authority identity so the human
        // sees WHERE artifacts will be written. It is a stable label/digest,
        // never a raw path or secret.
        let authority = facts.output_path_authority.as_str();
        let prompt = format!(
            "Approve image generation to {destination_count} destination(s) writing under `{authority}` (plan {digest_prefix})?"
        );
        let question = InterruptQuestion::Single {
            prompt,
            options: vec![
                opt(ApprovalOptionId::ApproveOnce, "Yes, generate"),
                opt(ApprovalOptionId::Reject, "Deny"),
            ],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: None,
            sandbox_escalation: None,
        };
        let description = format!(
            "Image generation to {destination_count} destination(s) writing under `{authority}` (plan {digest_prefix})"
        );
        let set = ApprovalOptionSet::new(
            "image_generation_approval",
            [ApprovalOptionId::ApproveOnce, ApprovalOptionId::Reject],
        );
        self.raise_and_decode(
            &description,
            question,
            "image_generation",
            serde_json::json!({
                "plan_digest": facts.plan_digest,
                "destinations": facts.destinations,
                "fanout": facts.fanout,
                "total_outputs": facts.total_outputs,
                "cost_maximum": facts.cost_maximum,
                "reference_egress_unmatched": facts.reference_egress_unmatched,
                "base_threshold_usd_micros": facts.base_threshold_usd_micros,
                "spend_request": facts.spend_request,
                "spend_session": facts.spend_session,
                "spend_project": facts.spend_project,
                "path_read_authorized": facts.path_read_authorized,
                "output_write_authorized": facts.output_write_authorized,
                "destination_enabled": facts.destination_enabled,
                "capability_fresh": facts.capability_fresh,
                "insecure_transport_allowed": facts.insecure_transport_allowed,
                "output_path_authority": facts.output_path_authority,
                "candidate_effects": [
                    {"selection": "approve_once", "execute": {"plan_digest": facts.plan_digest, "destinations": facts.destinations, "fanout": facts.fanout, "total_outputs": facts.total_outputs, "cost_maximum": facts.cost_maximum, "output_path_authority": facts.output_path_authority}},
                    {"selection": "reject", "effect": "deny"}
                ],
            }),
            |response| {
            // Dismissal (no selection) denies, fail closed.
            let Some(id) = decode_option_response(response, &set)? else {
                return Ok(Decision::Deny);
            };
            match id {
                ApprovalOptionId::ApproveOnce => Ok(Decision::Allow { scope: Scope::Once }),
                ApprovalOptionId::Reject => Ok(Decision::Deny),
                _ => Err(ForeignOptionId::new(&set, id.as_str())),
            }
            },
        )
        .await
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
            crate::session::Session::create_for_test(
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
            approver
                .approve_mcp_tool(
                    "untrusted",
                    "run",
                    &serde_json::json!({"query": "x"}),
                    &serde_json::json!({"endpoint": "https://example.invalid/mcp"}),
                )
                .await
                .unwrap(),
            Decision::Allow { scope: Scope::Once }
        );
    }
}
