use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MediaEgressPromptChoice {
    Approve,
    Reject,
    Dismissed,
}

/// Maximum typed-text characters rendered in the computer-action approval
/// prompt (issue #286). The bound applies AFTER secret-shaped withholding
/// and redaction-table scrubbing: truncating first would leak the surviving
/// prefix of a registered secret spanning the bound, because the truncated
/// fragment no longer literal-matches the table entry.
const MAX_PROMPT_TYPED_TEXT_CHARS: usize = 200;

/// Flatten a model-controlled fragment for interpolation into the one-line
/// approval prompt (issue #286). Control characters (newlines and ANSI
/// escape sequences included) become single spaces, and the prompt's own
/// structural punctuation — the backtick that delimits the action clause
/// and the double quote that delimits the typed-text display — is replaced
/// with a typographic lookalike. The provider chooses this content, so
/// without flattening it could visually terminate the action clause or
/// forge a second prompt line ("risk class: destructive", a pseudo
/// question). Structured option ids keep the decision itself unforgeable;
/// this keeps the *display* honest too.
fn flatten_prompt_fragment(fragment: &str) -> String {
    fragment
        .chars()
        .map(|ch| {
            if ch.is_control() {
                ' '
            } else if ch == '`' || ch == '"' {
                '\''
            } else {
                ch
            }
        })
        .collect()
}

/// Governed-network approvals are exact interactive host decisions. The
/// durable operation kind and canonical input classify them; no generic grant
/// class is exposed to noninteractive clients.
fn governed_network_question(label: &str, offered: &[Scope]) -> InterruptQuestion {
    let mut question = approval_question(
        label,
        true,
        GrantKind::Command,
        None,
        None,
        None,
        offered,
        None,
    );
    let InterruptQuestion::Single { approval_class, .. } = &mut question else {
        unreachable!("approval_question returns a single question")
    };
    *approval_class = None;
    question
}

#[cfg(test)]
mod governed_network_question_tests {
    use super::*;

    #[test]
    fn exact_network_decisions_expose_no_generic_grant_class() {
        let question = governed_network_question("network", &[Scope::Once]);
        assert!(matches!(
            question,
            InterruptQuestion::Single {
                permission: true,
                approval_class: None,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn noninteractive_approver_cannot_settle_monty_network_egress() {
        let root = tempfile::tempdir().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(root.path());
        let (events, _events_rx) = tokio::sync::broadcast::channel(4);
        let redaction = Arc::new(std::sync::RwLock::new(Arc::new(
            crate::redact::RedactionTable::empty(),
        )));
        let interrupts = Arc::new(crate::engine::interrupt::InterruptHub::new(
            events,
            redaction.clone(),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            db.clone(),
            ctx.session.id,
        ));
        let store = crate::approval::store::GrantStore::new(
            db.clone(),
            ctx.session.id,
            root.path().to_path_buf(),
            ctx.config.clone(),
        );
        let approver = Approver::new_for_session(
            store,
            db.clone(),
            ctx.session.clone(),
            redaction,
            ctx.agent_id,
            interrupts,
        );
        let decision = approver
            .approve_monty_network_egress(
                "Monty POST request",
                &serde_json::json!({
                    "method": "POST",
                    "url": "https://api.example.test/v1/items?limit=2",
                    "headers": {},
                    "body": null,
                    "destination": "api.example.test",
                }),
            )
            .await
            .unwrap();
        assert!(matches!(decision, Decision::NoninteractiveDeny));
        assert!(
            db.list_open_interrupts(ctx.session.id)
                .await
                .unwrap()
                .is_empty(),
            "headless callers cannot manufacture a settleable network prompt"
        );
    }

    #[tokio::test]
    async fn noninteractive_approver_cannot_settle_media_egress() {
        let root = tempfile::tempdir().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(root.path());
        let (events, _events_rx) = tokio::sync::broadcast::channel(4);
        let redaction = Arc::new(std::sync::RwLock::new(Arc::new(
            crate::redact::RedactionTable::empty(),
        )));
        let interrupts = Arc::new(crate::engine::interrupt::InterruptHub::new(
            events,
            redaction.clone(),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            db.clone(),
            ctx.session.id,
        ));
        let store = crate::approval::store::GrantStore::new(
            db.clone(),
            ctx.session.id,
            root.path().to_path_buf(),
            ctx.config.clone(),
        );
        let approver = Approver::new_for_session(
            store,
            db.clone(),
            ctx.session.clone(),
            redaction,
            ctx.agent_id,
            interrupts,
        );
        ctx.session
            .set_approval_mode(crate::config::extended::ApprovalMode::Manual);
        let request_digest =
            crate::audio_transcription::authorization::MediaEgressRequestDigest::from_raw_for_test(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            );
        let credential_fingerprint_digest =
            crate::image_sidecar::CredentialFingerprintDigest::from_raw_for_test(
                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            );
        let decision = approver
            .authorize(AuthorizationRequest::MediaEgress {
                request_digest: &request_digest,
                purpose: "transcription",
                provider_id: "openai",
                model_id: "gpt-transcribe",
                credential_fingerprint_digest: &credential_fingerprint_digest,
                origin: "api.openai.com",
                resolved_location: "us-east-1",
                project_digest: "project-digest",
                session_id: "session-1",
                attachment_id: "attachment-1",
                attachment_checksum: "checksum-1",
                interval_start_us: 0,
                interval_end_us: 1_000_000,
                prompt_present: false,
                keyword_count: 0,
                language_count: 0,
                timestamps: "off",
                diarization: false,
            })
            .await
            .unwrap();
        assert_eq!(decision, Decision::NoninteractiveDeny);
        assert!(
            db.list_open_interrupts(ctx.session.id)
                .await
                .unwrap()
                .is_empty(),
            "headless callers cannot manufacture a settleable media-egress prompt"
        );
    }
}

impl Approver {
    /// Prompt for an ACP-forwarded connect or tool effect without reading or
    /// writing any persistent grant/reject record. `Session` is presented as
    /// "always" by existing clients but is retained only by the live epoch.
    pub(super) async fn approve_forwarded_mcp_inner(
        &self,
        display_name: &str,
        tool: Option<&str>,
        transport: &str,
        identity: &str,
    ) -> Result<Decision> {
        let offered = [Scope::Once, Scope::Session];
        let operation = tool.map_or("connect", |_| "tool");
        // `display_name` is already host-owned/redacted.  Never make a
        // durable target from an editor declaration name.
        let target = format!("acp_forwarded:{operation}:{display_name}");
        if self.yolo_mode()
            || self
                .auto_allows(crate::agent_tree::HostEffectClass::ExternalAction, &target)
                .await
        {
            return Ok(Decision::Allow { scope: Scope::Once });
        }
        let prompt = match tool {
            Some(_) => format!(
                "An editor-provided MCP tool on `{display_name}` wants to run. Transport: `{transport}`; identity: `{identity}`. Approval lasts no longer than the active editor forwarding epoch."
            ),
            None => format!(
                "`{display_name}` wants to connect. Transport: `{transport}`; identity: `{identity}`. Approval lasts no longer than the active editor forwarding epoch."
            ),
        };
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
        let set = approval_option_set("acp_forwarded_mcp_approval", false, &offered, None);
        let choice = self
            .raise_and_decode(
                &prompt,
                question,
                "acp_forwarded_mcp",
                serde_json::json!({
                    "source": crate::mcp::forwarded::SOURCE_ACP_FORWARDED,
                    "server_display": display_name,
                    "transport": transport,
                    "identity": identity,
                    "operation": operation,
                    "offered_scopes": ["once", "epoch"],
                }),
                |response| response_to_approval_choice(response, &set),
            )
            .await?;
        let decision = match choice {
            ApprovalChoice::Approve(scope @ (Scope::Once | Scope::Session)) => {
                Decision::Allow { scope }
            }
            ApprovalChoice::NoninteractiveDeny => Decision::NoninteractiveDeny,
            ApprovalChoice::Reject(Scope::Session) => Decision::StandingReject {
                scope: Scope::Session,
            },
            ApprovalChoice::Deny
            | ApprovalChoice::Reject(_)
            | ApprovalChoice::Approve(_)
            | ApprovalChoice::ApproveAllOnce
            | ApprovalChoice::GrantPaths(_) => Decision::Deny,
        };
        self.record_permission_decision(
            "acp_forwarded_mcp",
            &target,
            &offered,
            decision,
            DecisionSource::UserPrompt,
        )
        .await;
        Ok(decision)
    }

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
        let args = serde_json::json!({ "target": payload });
        matches!(crate::engine::safety_gate::evaluate(extended.guard_model_ref(), &providers, redact, None, "local_metadata_refresh", &args).await, crate::engine::safety_gate::SafetyOutcome::Rated(verdict) if verdict.safe)
    }

    /// Read-only access to the underlying store (the §4 query API).
    pub fn store(&self) -> &GrantStore {
        &self.store
    }

    /// Standing command reject lookup for pre-decision gates (the Auto-mode
    /// safety gate and the escalation path). Fail closed on a
    /// corrupt/unreadable approvals store (issue #297): the caller surfaces
    /// the refusal instead of treating a corrupt store as "no rejects".
    pub async fn command_standing_reject_scope(&self, command: &str) -> Result<Option<Scope>> {
        let classification = crate::approval::classify::classify(command);
        for info in classification.simple_commands() {
            if info.wrapper || info.execution_bearing_option {
                continue;
            }
            if let Some(scope) = self.store.command_reject_scope(&info.key).await? {
                return Ok(Some(scope));
            }
        }
        Ok(None)
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
        let session_id = self
            .session
            .as_ref()
            .map(|session| session.live_id())
            .unwrap_or(self.session_id);
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
        if !self.interrupts.is_interactive_attached() {
            return Ok(Decision::NoninteractiveDeny);
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

    /// Approve a Monty network-policy mutation made by the session owner.
    ///
    /// This is deliberately separate from [`Self::approve_tool_call`]. A
    /// policy mutation can expand an agent's future egress authority, so Yolo
    /// and Auto are not authority to accept it. The only allow path is a
    /// response from a currently attached interactive client, and the prompt
    /// binds that response to the exact daemon-owned mutation input.
    pub async fn approve_owner_network_configuration(
        &self,
        label: &str,
        input: &serde_json::Value,
    ) -> Result<Decision> {
        self.authorize(AuthorizationRequest::OwnerNetworkConfiguration { label, input })
            .await
    }

    pub async fn approve_monty_network_egress(
        &self,
        label: &str,
        input: &serde_json::Value,
    ) -> Result<Decision> {
        self.authorize(AuthorizationRequest::MontyNetworkEgress { label, input })
            .await
    }

    pub(super) async fn approve_monty_network_egress_inner(
        &self,
        label: &str,
        input: &serde_json::Value,
    ) -> Result<Decision> {
        if !self.interrupts.is_interactive_attached() {
            return Ok(Decision::NoninteractiveDeny);
        }
        let offered = [Scope::Once];
        let question = governed_network_question(label, &offered);
        let set = approval_option_set("monty_network_egress", true, &offered, None);
        let choice = self
            .raise_and_decode(
                label,
                question,
                "monty_network_egress",
                serde_json::json!({
                    "wire_input": input,
                    "candidate_effects": [
                        {"selection": "approve", "execute": {"wire_input": input}},
                        {"selection": "reject", "effect": "deny"}
                    ],
                }),
                |response| response_to_approval_choice(response, &set),
            )
            .await?;
        Ok(match choice {
            ApprovalChoice::Approve(Scope::Once) => Decision::Allow { scope: Scope::Once },
            ApprovalChoice::Deny
            | ApprovalChoice::Reject(_)
            | ApprovalChoice::Approve(Scope::Session | Scope::Project | Scope::Global)
            | ApprovalChoice::ApproveAllOnce
            | ApprovalChoice::GrantPaths(_) => Decision::Deny,
            ApprovalChoice::NoninteractiveDeny => Decision::NoninteractiveDeny,
        })
    }

    pub(super) async fn approve_owner_network_configuration_inner(
        &self,
        label: &str,
        input: &serde_json::Value,
    ) -> Result<Decision> {
        // Do this before raising an interrupt and deliberately before any
        // approval-mode branch. An unattended or auto-allow run cannot grant
        // itself future network authority.
        if !self.interrupts.is_interactive_attached() {
            return Ok(Decision::NoninteractiveDeny);
        }
        let offered = [Scope::Once];
        let question = governed_network_question(label, &offered);
        let set = approval_option_set("owner_network_configuration", true, &offered, None);
        let choice = self
            .raise_and_decode(
                label,
                question,
                "owner_network_configuration",
                serde_json::json!({
                    "wire_input": input,
                    "candidate_effects": [
                        {"selection": "approve", "execute": {"wire_input": input}},
                        {"selection": "reject", "effect": "deny"}
                    ],
                }),
                |response| response_to_approval_choice(response, &set),
            )
            .await?;
        let decision = match choice {
            ApprovalChoice::Approve(Scope::Once) => Decision::Allow { scope: Scope::Once },
            ApprovalChoice::Deny
            | ApprovalChoice::Reject(_)
            | ApprovalChoice::Approve(Scope::Session | Scope::Project | Scope::Global)
            | ApprovalChoice::ApproveAllOnce
            | ApprovalChoice::GrantPaths(_) => Decision::Deny,
            ApprovalChoice::NoninteractiveDeny => Decision::NoninteractiveDeny,
        };
        self.record_permission_decision(
            "owner_network_configuration",
            label,
            &offered,
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
            agent: &self.agent_id,
            profile: crate::mcp::config::DEFAULT_PROFILE,
            server,
            tool,
            input,
            target,
        })
        .await
    }

    pub(super) async fn approve_mcp_tool_inner(
        &self,
        requesting_agent: &str,
        profile: &str,
        server: &str,
        tool: &str,
        input: &serde_json::Value,
        effect_target: &serde_json::Value,
    ) -> Result<Decision> {
        let agent_bound = effect_target
            .get("agent_bound")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let agent = agent_bound.then_some(requesting_agent);
        let grant_target = crate::approval::store::mcp_tool_key_for(agent, profile, server, tool);
        let offered = [Scope::Once, Scope::Session, Scope::Project, Scope::Global];
        if let Some(scope) = self
            .store
            .mcp_tool_reject_scope_for_key(&grant_target)
            .await?
        {
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
        if let Some(scope) = self
            .store
            .mcp_tool_grant_scope_for_key(&grant_target)
            .await?
        {
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
        let prompt = if agent_bound {
            format!(
                "`{tool}` on MCP server `{server}` wants to run for agent `{requesting_agent}` using credential profile `{profile}`. This server is external to cockpit."
            )
        } else {
            format!(
                "`{tool}` on MCP server `{server}` wants to run using credential profile `{profile}`. This server is external to cockpit."
            )
        };
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
                    if let Err(e) = self.store.record_mcp_tool_key(&grant_target, scope).await {
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
                    if let Err(e) = self.store.record_mcp_tool_reject_key(&grant_target, scope).await {
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
        if let Some(scope) = self.store.mcp_tool_reject_scope(agent, tool).await? {
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
        if let Some(scope) = self.store.mcp_tool_grant_scope(agent, tool).await? {
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
                .auto_allows(crate::agent_tree::HostEffectClass::ExternalAction, &target)
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
        requesting_agent: &str,
        profile: &str,
        server: &str,
        identity: &str,
        agent_bound: bool,
    ) -> Result<Decision> {
        let agent = agent_bound.then_some(requesting_agent);
        let target =
            crate::approval::store::mcp_server_connect_key_for(agent, profile, server, identity);
        let offered = [Scope::Once, Scope::Session, Scope::Project, Scope::Global];
        if let Some(scope) = self.store.mcp_tool_reject_scope_for_key(&target).await? {
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
        if let Some(scope) = self.store.mcp_tool_grant_scope_for_key(&target).await? {
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
                .auto_allows(crate::agent_tree::HostEffectClass::ExternalAction, &target)
                .await
        {
            return Ok(Decision::Allow { scope: Scope::Once });
        }
        let base_prompt = mcp_server_connect_prompt(server, identity);
        let prompt = if agent_bound {
            format!(
                "{base_prompt} Agent `{requesting_agent}` will use credential profile `{profile}`."
            )
        } else {
            format!("{base_prompt} Credential profile: `{profile}`.")
        };
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
                        .record_mcp_server_connect_key(&target, scope)
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
                        .record_mcp_server_connect_reject_key(&target, scope)
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

    /// Render the typed-text clause of a computer-action approval prompt
    /// (issue #286). This seam is the last fence before the rendered prompt
    /// is persisted in the interrupt record and broadcast to owner clients,
    /// so the full disclosure pipeline runs here, in this order:
    ///
    /// 1. secret-shaped text is withheld outright — novel credential
    ///    shapes (`ghp_…`, `sk-…`, JWTs, opaque token runs) never render
    ///    regardless of redaction-table presence, and the coordinator
    ///    withholds them too, so the invariant cannot depend on the far
    ///    side of the in-memory boundary;
    /// 2. registered literals are scrubbed from the FULL text through the
    ///    live redaction table;
    /// 3. control characters and the prompt's structural punctuation are
    ///    flattened; and
    /// 4. only then is the render bounded to
    ///    [`MAX_PROMPT_TYPED_TEXT_CHARS`] (scrub before bound, never bound
    ///    before scrub).
    ///
    /// With no redaction table available (a headless approver without a
    /// session), non-secret text is withheld rather than shown unredacted.
    fn computer_typed_text_display(&self, typed_text: Option<&str>) -> String {
        let Some(text) = typed_text else {
            return String::new();
        };
        if crate::redact::text_is_secret_shaped(text) {
            return " [text withheld: secret-shaped]".to_string();
        }
        let Some(redact) = self.redact.as_ref().map(|slot| {
            slot.read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }) else {
            return " [text withheld: no redaction table]".to_string();
        };
        let scrubbed = redact.scrub(text);
        let flattened = flatten_prompt_fragment(&scrubbed);
        let mut bounded: String = flattened
            .chars()
            .take(MAX_PROMPT_TYPED_TEXT_CHARS)
            .collect();
        if flattened.chars().count() > MAX_PROMPT_TYPED_TEXT_CHARS {
            bounded.push('…');
        }
        format!(" \"{}\"", bounded)
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
    ///
    /// The Ask prompt renders the concrete pending action (issue #286):
    /// action kind with coordinates/keys, the redacted typed text, the
    /// resolved target window, the advisory risk class, and — for a
    /// multi-action batch — a summary of every pending action.
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
        action_detail: &str,
        typed_text: Option<&str>,
        batch_detail: Option<&str>,
        target_window: Option<&str>,
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
        // The prompt must show what is actually being approved (issue #286),
        // never just an opaque `openai_call:N` batch label.
        let typed_display = self.computer_typed_text_display(typed_text);
        // Every interpolated fragment is either engine-generated from safe
        // enum data (`action_detail`, `batch_detail`, `backend_kind`,
        // `action_class`, `action_label`) or flattened here: the typed
        // text, the OS-derived window title hint, and the action id are
        // the three fragments a provider or the desktop controls. The
        // action id embeds the raw provider call id (validated only as
        // non-empty), so without flattening a crafted id could forge a
        // second prompt line in every owner client that honors newlines.
        // The raw id still travels in the structured interrupt metadata,
        // where JSON escaping contains it; only this display is flattened.
        let action_id_display = flatten_prompt_fragment(action_id);
        let target_line = match target_window {
            Some(window) => format!(" Target window: {}.", flatten_prompt_fragment(window)),
            None => format!(" Target: {backend_kind} display."),
        };
        let batch_line = batch_detail
            .map(|batch| format!(" Batch: {batch}."))
            .unwrap_or_default();
        let prompt = format!(
            "Allow computer action `{action_detail}{typed_display}` (risk class: {action_class})?{target_line}{batch_line} (call `{action_label}`, id: {action_id_display})"
        );
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
        // The description is the interrupt body every owner client renders
        // as its own line of text, so it carries the same flattened id as
        // the prompt — never the raw provider call id.
        let description = format!("Computer action `{action_detail}` (id: {action_id_display})");
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
        // No durable permission record for computer actions. The Ask lease
        // contract forbids standing computer grants: reuse of an Allow is
        // only via the in-memory `AskDelegationLease` (exact payload + live
        // focus, short action-count bound; destructive/credential classes
        // install none), never a persisted `permission_decision` row.
        // (Contrast every other approval path, which records the decision
        // here.)
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
    /// 1. **Standing reject** short-circuits every mode (including Yolo) with
    ///    no prompt — see [`Self::media_egress_reject_matches`].
    /// 2. **Standing grant** short-circuits every mode with no prompt — see
    ///    [`Self::media_egress_grant_matches`].
    /// 3. **Yolo** allows once with no prompt and no persistence.
    /// 4. **Manual/Auto** without a matching grant: fail closed with
    ///    [`Decision::NoninteractiveDeny`] when no interactive client is
    ///    attached; else ask the human, disclosing only the redacted
    ///    provider/model/interval facts and the digest prefix. Approving
    ///    records session-standing consent for the exact digest; denying
    ///    records a standing reject for it.
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
            origin = facts.origin,
            resolved_location = facts.resolved_location,
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
        if self.media_egress_reject_matches(&facts).await {
            let decision = Decision::StandingReject {
                scope: Scope::Session,
            };
            self.record_permission_decision(
                "media_egress",
                facts.request_digest.as_str(),
                &[Scope::Session],
                decision,
                crate::approval::DecisionSource::StandingReject,
            )
            .await;
            return Ok(decision);
        }
        if self.media_egress_grant_matches(&facts).await {
            let decision = Decision::Allow { scope: Scope::Once };
            self.record_permission_decision(
                "media_egress",
                facts.request_digest.as_str(),
                &[Scope::Session],
                decision,
                crate::approval::DecisionSource::AlreadyGranted,
            )
            .await;
            return Ok(decision);
        }
        if self.yolo_mode() {
            return Ok(Decision::Allow { scope: Scope::Once });
        }
        if !self.interrupts.is_interactive_attached() {
            return Ok(Decision::NoninteractiveDeny);
        }
        self.raise_media_egress_prompt(&facts).await
    }

    /// Grant-matching hook for transcription media egress. A matching persisted
    /// grant lets Manual/Auto short-circuit to a standing allow without a prompt.
    ///
    /// Consults the session-scoped [`GrantStore`] row keyed by purpose and the
    /// exact `transcription_request_digest`. Fails closed on any lookup error:
    /// no grant ever fakes an allow.
    async fn media_egress_grant_matches(&self, facts: &MediaEgressAuthzFacts<'_>) -> bool {
        self.store
            .media_egress_grant_matches(facts.purpose, facts.request_digest.as_str())
            .await
            .unwrap_or(false)
    }

    async fn media_egress_reject_matches(&self, facts: &MediaEgressAuthzFacts<'_>) -> bool {
        self.store
            .media_egress_reject_matches(facts.purpose, facts.request_digest.as_str())
            .await
            .unwrap_or(false)
    }

    /// Raise the human transcription media-egress approval prompt (Manual/Auto
    /// without a matching grant). A single approve/deny question carrying only
    /// secret-free facts: provider/model, the media interval, and the digest
    /// prefix. No prompt text, keyword/language strings, credential token, or
    /// audio bytes are ever disclosed. Approve → session-standing allow;
    /// explicit deny → session-standing reject; dismiss/cancel → deny once with
    /// no persistence.
    async fn raise_media_egress_prompt(
        &self,
        facts: &MediaEgressAuthzFacts<'_>,
    ) -> Result<Decision> {
        let digest_prefix: String = facts.request_digest.as_str().chars().take(12).collect();
        let prompt = format!(
            "Approve {} egress to `{}` at `{}` ({}) model `{}` for attachment interval {}..{}us (request {})? Approving remembers this exact request for this session.",
            facts.purpose,
            facts.provider_id,
            facts.origin,
            facts.resolved_location,
            facts.model_id,
            facts.interval_start_us,
            facts.interval_end_us,
            digest_prefix,
        );
        let question = InterruptQuestion::Single {
            prompt,
            options: vec![
                opt(
                    ApprovalOptionId::ApproveOnce,
                    "Yes, transcribe (remember for this session)",
                ),
                opt(ApprovalOptionId::Reject, "Deny (remember for this session)"),
            ],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: None,
            sandbox_escalation: None,
        };
        let description = format!(
            "{} egress to `{}` at `{}` ({}) model `{}` (request {})",
            facts.purpose,
            facts.provider_id,
            facts.origin,
            facts.resolved_location,
            facts.model_id,
            digest_prefix,
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
            "origin": facts.origin,
            "resolved_location": facts.resolved_location,
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
        let outcome = self
            .raise_and_decode(
                &description,
                question,
                "media_egress_transcription",
                serde_json::json!({
                    "egress": egress.clone(),
                    "candidate_effects": [
                        {
                            "selection": ApprovalOptionId::ApproveOnce.as_str(),
                            "scope": "session",
                            "execute": {"media_egress": egress},
                        },
                        {
                            "selection": ApprovalOptionId::Reject.as_str(),
                            "scope": "session",
                            "effect": "deny",
                        },
                    ],
                }),
                |response| {
                    let Some(id) = decode_option_response(response, &set)? else {
                        return Ok(MediaEgressPromptChoice::Dismissed);
                    };
                    match id {
                        ApprovalOptionId::ApproveOnce => Ok(MediaEgressPromptChoice::Approve),
                        ApprovalOptionId::Reject => Ok(MediaEgressPromptChoice::Reject),
                        _ => Err(ForeignOptionId::new(&set, id.as_str())),
                    }
                },
            )
            .await?;
        self.finish_media_egress_prompt(facts, outcome).await
    }

    async fn finish_media_egress_prompt(
        &self,
        facts: &MediaEgressAuthzFacts<'_>,
        choice: MediaEgressPromptChoice,
    ) -> Result<Decision> {
        let (decision, scopes, persist) = match choice {
            MediaEgressPromptChoice::Approve => (
                Decision::Allow { scope: Scope::Once },
                &[Scope::Session][..],
                true,
            ),
            MediaEgressPromptChoice::Reject => (Decision::Deny, &[Scope::Session][..], true),
            MediaEgressPromptChoice::Dismissed => (Decision::Deny, &[Scope::Once][..], false),
        };
        if persist {
            if let Some(session) = self.session.as_deref() {
                match choice {
                    MediaEgressPromptChoice::Approve => {
                        if let Err(error) = self
                            .store
                            .record_media_egress_grant(
                                &session.project_id,
                                facts.purpose,
                                facts.request_digest.as_str(),
                            )
                            .await
                        {
                            tracing::warn!(
                                %error,
                                purpose = facts.purpose,
                                request_digest = facts.request_digest.as_str(),
                                "recording media egress grant failed; consent will not stick"
                            );
                        }
                    }
                    MediaEgressPromptChoice::Reject => {
                        if let Err(error) = self
                            .store
                            .record_media_egress_reject(
                                &session.project_id,
                                facts.purpose,
                                facts.request_digest.as_str(),
                            )
                            .await
                        {
                            tracing::warn!(
                                %error,
                                purpose = facts.purpose,
                                request_digest = facts.request_digest.as_str(),
                                "recording media egress reject failed; standing deny will not stick"
                            );
                        }
                    }
                    MediaEgressPromptChoice::Dismissed => {}
                }
            }
        }
        self.record_permission_decision(
            "media_egress",
            facts.request_digest.as_str(),
            scopes,
            decision,
            crate::approval::DecisionSource::UserPrompt,
        )
        .await;
        Ok(decision)
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
    /// 2. **Grant-matching seam** ([`Self::image_generation_grant_matches`]) —
    ///    matches the raw egress fact. A later request matches only if it is
    ///    no broader than the stored envelope.
    /// 3. **Approval-mode dispatch** over the shared session mode: Yolo
    ///    auto-allows after the hard gates (agent discretion, no grant, no
    ///    prompt); Manual/Auto honor a matching grant, else ask the human.
    ///    Risk classification is not a second Auto decision issuer after a
    ///    matching grant.
    ///
    /// Fail-closed everywhere: a missing decision input (a grant that does not
    /// yet exist) never fakes an allow — Manual/Auto fall through to a human
    /// prompt rather than assume a grant.
    #[cfg(feature = "extended")]
    pub(super) async fn approve_image_generation_inner(
        &self,
        facts: ImageGenerationAuthzFacts<'_>,
    ) -> Result<Decision> {
        use crate::image_generation_agent_tools::SpendPolicyChoice;

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

        // 2. Match the persisted bounded grant against the raw egress fact.
        let matching_grant_scope = self.image_generation_grant_matches(&facts).await;
        let reference_egress_unmatched = facts.reference_egress && matching_grant_scope.is_none();

        // 3. Approval-mode dispatch over the shared session mode.
        match self.approval_mode() {
            crate::config::extended::ApprovalMode::Yolo => {
                // Yolo opens no human prompt and records agent discretion after
                // every hard gate passed; it requires no grant and persists
                // none.
                self.record_permission_decision(
                    "generate_image",
                    facts.plan_digest.as_str(),
                    &[Scope::Once],
                    Decision::Allow { scope: Scope::Once },
                    crate::approval::DecisionSource::AgentDiscretion,
                )
                .await;
                Ok(Decision::Allow { scope: Scope::Once })
            }
            crate::config::extended::ApprovalMode::Manual
            | crate::config::extended::ApprovalMode::Auto => {
                if let Some(scope) = matching_grant_scope {
                    // A matching standing grant is an explicit prior user
                    // decision — short-circuit to a standing allow and audit
                    // the exact matched scope rather than inventing a prompt.
                    // Auto honors any matching envelope, not only Base risk.
                    let decision = Decision::Allow { scope };
                    self.record_permission_decision(
                        "generate_image",
                        facts.plan_digest.as_str(),
                        &[scope],
                        decision,
                        crate::approval::DecisionSource::AlreadyGranted,
                    )
                    .await;
                    Ok(decision)
                } else {
                    // No grant input available: ask the human. Never assume a
                    // grant that does not exist.
                    self.raise_image_generation_prompt(&facts, reference_egress_unmatched)
                        .await
                }
            }
        }
    }

    /// Grant-matching hook for image generation. A matching persisted grant
    /// lets Manual/Auto short-circuit to a standing-grant allow without a
    /// human prompt.
    ///
    /// Consults the [`GrantStore`] bounded image-generation capability tuple:
    /// destination binding, output authority, reference egress, and maximum
    /// fanout/output/cost. Prompt and output stem deliberately do not enter
    /// the tuple; a later request matches only if it is no broader. Session
    /// scope is checked first, then project scope (bound to the live session's
    /// machine-local `project_id`). Fails closed on any lookup error or when no
    /// session is attached: no grant ever fakes an allow.
    #[cfg(feature = "extended")]
    async fn image_generation_grant_matches(
        &self,
        facts: &ImageGenerationAuthzFacts<'_>,
    ) -> Option<Scope> {
        let Some(session) = self.session.as_deref() else {
            return None;
        };
        self.store
            .image_generation_grant_scope_bounded(
                &session.project_id,
                crate::approval::store::ImageGenerationGrantBounds {
                    destination_binding_digest: facts.destination_grant_binding_digest,
                    output_path_authority: facts.output_path_authority.as_str(),
                    reference_egress: facts.reference_egress,
                    fanout: facts.fanout,
                    total_outputs: facts.total_outputs,
                    cost_maximum: facts.cost_maximum,
                },
            )
            .await
    }

    /// Raise the human image-generation approval prompt (Manual/Auto without a
    /// matching grant). Carries only the secret-free destination count, plan
    /// digest prefix, and redacted output write-authority identity. The human
    /// may approve once, for this session, or for this project; deny; or
    /// dismiss (deny). A session/project decision is persisted as a standing
    /// grant only after the dispatch service has durably queued the exact job,
    /// so a failed commit never leaves authorization behind.
    #[cfg(feature = "extended")]
    async fn raise_image_generation_prompt(
        &self,
        facts: &ImageGenerationAuthzFacts<'_>,
        reference_egress_unmatched: bool,
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
                opt(ApprovalOptionId::ApproveOnce, "Yes, generate once"),
                opt(ApprovalOptionId::ApproveSession, "Allow for this session"),
                opt(ApprovalOptionId::ApproveProject, "Allow for this project"),
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
            [
                ApprovalOptionId::ApproveOnce,
                ApprovalOptionId::ApproveSession,
                ApprovalOptionId::ApproveProject,
                ApprovalOptionId::Reject,
            ],
        );
        let decision = self
            .raise_and_decode(
                &description,
                question,
                "image_generation",
                serde_json::json!({
                    "plan_digest": facts.plan_digest.as_str(),
                    "destinations": facts.destinations,
                    "fanout": facts.fanout,
                    "total_outputs": facts.total_outputs,
                    "cost_maximum": facts.cost_maximum,
                    "reference_egress_unmatched": reference_egress_unmatched,
                    "base_threshold_usd_micros": facts.base_threshold_usd_micros,
                    "spend_request": facts.spend_request,
                    "spend_session": facts.spend_session,
                    "spend_project": facts.spend_project,
                    "path_read_authorized": facts.path_read_authorized,
                    "output_write_authorized": facts.output_write_authorized,
                    "destination_enabled": facts.destination_enabled,
                    "capability_fresh": facts.capability_fresh,
                    "insecure_transport_allowed": facts.insecure_transport_allowed,
                    "output_path_authority": facts.output_path_authority.as_str(),
                    "candidate_effects": [
                        {"selection": "approve_once", "execute": {"plan_digest": facts.plan_digest.as_str(), "destinations": facts.destinations, "fanout": facts.fanout, "total_outputs": facts.total_outputs, "cost_maximum": facts.cost_maximum, "output_path_authority": facts.output_path_authority.as_str()}},
                        {"selection": "approve_session", "persist_after_queued_job": {"scope": "session", "plan_digest": facts.plan_digest.as_str(), "output_path_authority": facts.output_path_authority.as_str()}},
                        {"selection": "approve_project", "persist_after_queued_job": {"scope": "project", "plan_digest": facts.plan_digest.as_str(), "output_path_authority": facts.output_path_authority.as_str()}},
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
                    ApprovalOptionId::ApproveSession => {
                        Ok(Decision::Allow { scope: Scope::Session })
                    }
                    ApprovalOptionId::ApproveProject => {
                        Ok(Decision::Allow { scope: Scope::Project })
                    }
                    ApprovalOptionId::Reject => Ok(Decision::Deny),
                    _ => Err(ForeignOptionId::new(&set, id.as_str())),
                }
                },
            )
            .await?;
        self.record_permission_decision(
            "generate_image",
            facts.plan_digest.as_str(),
            &[Scope::Once, Scope::Session, Scope::Project],
            decision,
            crate::approval::DecisionSource::UserPrompt,
        )
        .await;
        // Standing grants are persisted by the dispatch transaction after it
        // has durably queued this exact job. The audit above records the human
        // choice without creating an authorization for a failed queue commit.
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
