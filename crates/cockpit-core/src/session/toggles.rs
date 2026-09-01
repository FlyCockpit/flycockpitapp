#![allow(deprecated)]

use super::*;

impl Session {
    /// Whether any sandboxing mode is active for this session right now.
    /// Kept as a derived helper so native file-tool checks can remain boolean.
    pub fn sandbox_enabled(&self) -> bool {
        self.sandbox_mode().enabled()
    }

    pub fn sandbox_mode(&self) -> crate::tools::sandbox_mode::SandboxMode {
        sandbox_mode_from_u8(self.sandbox_mode.load(Ordering::Relaxed))
    }

    pub fn set_sandbox_mode(
        &self,
        mode: crate::tools::sandbox_mode::SandboxMode,
    ) -> crate::tools::sandbox_mode::SandboxMode {
        self.sandbox_mode
            .store(sandbox_mode_to_u8(mode), Ordering::Relaxed);
        mode
    }

    /// Legacy on/off setter used by existing callers until the UX prompt grows
    /// mode selection. `true` maps to the zerobox sandbox, `false` to off.
    pub fn set_sandbox_enabled(&self, enabled: bool) -> bool {
        self.set_sandbox_mode(crate::tools::sandbox_mode::SandboxMode::from_enabled(
            enabled,
        ));
        enabled
    }

    #[cfg(test)]
    pub fn toggle_sandbox_mode(&self) -> crate::tools::sandbox_mode::SandboxMode {
        let new = self.sandbox_mode().toggled_legacy();
        self.set_sandbox_mode(new)
    }

    #[cfg(test)]
    pub fn toggle_sandbox_enabled(&self) -> bool {
        self.toggle_sandbox_mode().enabled()
    }

    pub fn container_network_enabled(&self) -> bool {
        self.container_network_enabled.load(Ordering::Relaxed)
    }

    pub fn set_container_network_enabled(&self, enabled: bool) -> bool {
        self.container_network_enabled
            .store(enabled, Ordering::Relaxed);
        enabled
    }

    /// Apply an explicit user action to the process-local session allowlist.
    pub(crate) async fn mutate_monty_session_network_grants(
        &self,
        mutation: crate::mcp::network::SessionNetworkMutation,
    ) -> anyhow::Result<crate::mcp::network::SessionNetworkGrantSnapshot> {
        // Do not retain the std::sync::Mutex across an await. The exclusive
        // gate serializes this mutation against the shared egress permit;
        // once acquired, only this short in-memory update needs the mutex.
        let _revocation_fence = self.monty_network_egress_gate.write().await;
        let mut grants = self
            .monty_network_grants
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        grants.apply(mutation)
    }

    /// Acquire the shared session-grant fence. Governed egress retains this
    /// permit from its final session-policy read through `RequestBuilder::send`.
    pub(crate) async fn monty_network_egress_permit(&self) -> MontyNetworkEgressPermit {
        MontyNetworkEgressPermit {
            _guard: self.monty_network_egress_gate.clone().read_owned().await,
        }
    }

    pub(crate) fn monty_session_network_grant_snapshot(
        &self,
    ) -> crate::mcp::network::SessionNetworkGrantSnapshot {
        self.monty_network_grants
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot()
    }

    /// Whether explicit sandbox escalation retries are available in this
    /// session. Approval mode still decides how an allowed escalation is gated.
    pub fn sandbox_escalation_enabled(&self) -> bool {
        self.sandbox_escalation_enabled.load(Ordering::Relaxed)
    }

    /// Set the session's sandbox-escalation availability and return the new
    /// state. Used by the spawn path, `/settings`, and `/sandbox-escalate`.
    pub fn set_sandbox_escalation_enabled(&self, enabled: bool) -> bool {
        self.sandbox_escalation_enabled
            .store(enabled, Ordering::Relaxed);
        let eligible = self
            .active_sandbox_escalate_eligible
            .load(Ordering::Relaxed);
        let mut active_tools = self.active_tool_names.lock().unwrap();
        if enabled && eligible {
            active_tools.insert("escalate".to_string());
        } else {
            active_tools.remove("escalate");
        }
        enabled
    }

    /// Return the agent-facing sandbox-escalation tool-availability notice
    /// when actual tool presence has changed since the last model turn saw
    /// it. Toggling back before the next turn is a net no-op and emits
    /// nothing.
    pub fn sandbox_escalation_turn_notice(&self, tool_present: bool) -> Option<String> {
        let previous = self
            .sandbox_escalation_notice_state
            .swap(tool_present, Ordering::Relaxed);
        if previous == tool_present {
            return None;
        }
        Some(if tool_present {
            "Sandbox escalation is now available; you may use the `escalate` tool to re-run a sandbox-failed command after approval.".to_string()
        } else {
            "Sandbox escalation is now unavailable; the `escalate` tool is not present.".to_string()
        })
    }

    pub(crate) fn safety_gate_degrade_notice_needed(
        &self,
        reason: &str,
        model_ref: Option<&str>,
    ) -> bool {
        let key = (
            reason.to_string(),
            model_ref.map(std::string::ToString::to_string),
        );
        let mut last = self.safety_gate_degrade_notice_key.lock().unwrap();
        if last.as_ref() == Some(&key) {
            return false;
        }
        *last = Some(key);
        true
    }

    pub(crate) fn clear_safety_gate_degrade_notice(&self) {
        *self.safety_gate_degrade_notice_key.lock().unwrap() = None;
    }

    pub fn mcp_reserved_cockpit_server_notice(&self) -> Option<String> {
        if self
            .mcp_reserved_cockpit_notice_sent
            .swap(true, Ordering::Relaxed)
        {
            return None;
        }
        Some(
            "Ignoring configured MCP server `cockpit`; that server id is reserved for built-in cockpit functions."
                .to_string(),
        )
    }

    pub fn request_agent_compact(&self) {
        self.agent_compact_requested.store(true, Ordering::Relaxed);
    }

    pub fn take_agent_compact_request(&self) -> bool {
        self.agent_compact_requested.swap(false, Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn agent_compact_requested(&self) -> bool {
        self.agent_compact_requested.load(Ordering::Relaxed)
    }

    /// Effective command-approval mode for gated tool calls.
    /// Prefers an active run-invocation override (keyed by
    /// `client_submission_id`) when installed; otherwise the session mode.
    pub fn approval_mode(&self) -> crate::config::extended::ApprovalMode {
        let override_raw = self.invocation_approval_override.load(Ordering::Relaxed);
        if override_raw != 255 {
            return approval_mode_from_u8(override_raw);
        }
        self.session_approval_mode()
    }

    /// Session-owned approval mode only — never the run-invocation override.
    /// Used by SetApprovalMode and tests that assert session mode is unchanged.
    pub fn session_approval_mode(&self) -> crate::config::extended::ApprovalMode {
        approval_mode_from_u8(self.approval_mode.load(Ordering::Relaxed))
    }

    /// Install an invocation-scoped approval override for `client_submission_id`.
    /// Does not mutate [`Self::session_approval_mode`].
    pub fn set_invocation_approval_override(
        &self,
        client_submission_id: Uuid,
        mode: crate::config::extended::ApprovalMode,
    ) {
        self.invocation_approval_override
            .store(approval_mode_to_u8(mode), Ordering::Relaxed);
        *self
            .active_run_invocation_id
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(client_submission_id);
    }

    /// Clear the invocation-scoped approval override when the owning run ends.
    pub fn clear_invocation_approval_override(&self) {
        self.invocation_approval_override
            .store(255, Ordering::Relaxed);
        *self
            .active_run_invocation_id
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = None;
    }

    /// Active run invocation that owns the approval override, if any.
    pub fn active_run_invocation_id(&self) -> Option<Uuid> {
        *self
            .active_run_invocation_id
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    pub fn is_btw_fork(&self) -> bool {
        self.btw_parent_session_id.is_some()
    }

    /// Set the session's command-approval mode. Used by the spawn path to
    /// apply the config default and by `/settings` to flip it at runtime.
    /// Returns the new mode. Never touches the invocation override.
    pub fn set_approval_mode(
        &self,
        mode: crate::config::extended::ApprovalMode,
    ) -> crate::config::extended::ApprovalMode {
        if self.session_approval_mode() != mode {
            self.clear_safety_gate_degrade_notice();
        }
        self.approval_mode
            .store(approval_mode_to_u8(mode), Ordering::Relaxed);
        mode
    }

    /// Whether native shell-output compression is active for this session
    /// right now (implementation note). Read per `bash`
    /// call; when false the bash tool returns its output verbatim.
    pub fn shell_compression_enabled(&self) -> bool {
        self.shell_compression_enabled.load(Ordering::Relaxed)
    }

    /// Set the session's shell-compression flag from the config mode. Used
    /// by the spawn path to apply
    /// [`crate::config::extended::ExtendedConfig::shell_compression`].
    /// Returns the new state.
    pub fn set_shell_compression(&self, mode: crate::config::extended::ShellCompression) -> bool {
        let enabled = mode.is_enabled();
        self.shell_compression_enabled
            .store(enabled, Ordering::Relaxed);
        enabled
    }

    pub fn active_model(&self) -> Option<String> {
        self.model_selection
            .lock()
            .unwrap()
            .as_ref()
            .map(|selection| selection.model.clone())
    }

    pub fn active_provider(&self) -> Option<String> {
        self.model_selection
            .lock()
            .unwrap()
            .as_ref()
            .map(|selection| selection.provider.clone())
    }

    pub fn active_model_ref(&self) -> Option<crate::config::providers::ActiveModelRef> {
        self.model_selection.lock().unwrap().clone()
    }

    /// Stage a recovery selection for worker construction without touching a
    /// persisted session row. The registry commits it only after every
    /// fallible worker-start validation has succeeded.
    pub(crate) fn stage_active_model_ref_for_recovery(
        &self,
        selection: crate::config::providers::ActiveModelRef,
    ) {
        *self.model_selection.lock().unwrap() = Some(selection);
    }

    pub fn tool_surface_override_json(&self) -> Option<String> {
        self.tool_surface_override_json.lock().unwrap().clone()
    }

    #[allow(dead_code)]
    pub fn set_tool_surface_override_json(&self, override_json: Option<String>) -> Result<()> {
        if self.stage_pending_row(|row| {
            row.tool_surface_override_json = override_json.clone();
        }) {
            *self.tool_surface_override_json.lock().unwrap() = override_json;
            return Ok(());
        }
        let session_id = self.id;
        let persisted_override_json = override_json.clone();
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                let changed = conn
                    .execute(
                        "UPDATE sessions SET tool_surface_override_json = ?1 WHERE session_id = ?2",
                        params![persisted_override_json, session_id.to_string()],
                    )
                    .context("setting session tool surface override")?;
                if changed != 1 {
                    anyhow::bail!(
                        "session {session_id} not found while setting tool surface override"
                    );
                }
                Ok(())
            })
            .context("persisting session tool surface override")?;
        *self.tool_surface_override_json.lock().unwrap() = override_json;
        Ok(())
    }

    pub fn goal_settings_override_json(&self) -> Option<String> {
        self.goal_settings_override_json.lock().unwrap().clone()
    }

    pub fn goal_settings_override(&self) -> Option<crate::agents::GoalSettingsOverride> {
        self.goal_settings_override_json()
            .and_then(|raw| crate::agents::parse_goal_settings_override_json(&raw).ok())
    }

    pub fn set_goal_settings_override_json(&self, override_json: Option<String>) -> Result<()> {
        *self.goal_settings_override_json.lock().unwrap() = override_json.clone();
        if self.stage_pending_row(|row| {
            row.goal_settings_override_json = override_json.clone();
        }) {
            return Ok(());
        }
        let session_id = self.id;
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                conn.execute(
                    "UPDATE sessions SET goal_settings_override_json = ?1 WHERE session_id = ?2",
                    params![override_json, session_id.to_string()],
                )
                .context("setting session goal settings override")?;
                Ok(())
            })
            .context("persisting session goal settings override")?;
        Ok(())
    }

    #[cfg(test)]
    pub fn set_active_model(&self, provider: &str, model: &str) -> Result<()> {
        self.set_active_model_ref(crate::config::providers::ActiveModelRef {
            provider: provider.to_string(),
            model: model.to_string(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        })
    }

    pub fn set_active_model_ref(
        &self,
        selection: crate::config::providers::ActiveModelRef,
    ) -> Result<()> {
        let mut active = self.model_selection.lock().unwrap();
        let selection_json =
            serde_json::to_string(&selection).context("encoding session model selection")?;
        let provider = selection.provider.clone();
        let model = selection.model.clone();
        if self.stage_pending_row(|row| {
            row.provider = Some(provider.clone());
            row.model = Some(model.clone());
            row.model_selection_json = Some(selection_json.clone());
            row.active_model_revision = row.active_model_revision.saturating_add(1);
        }) {
            *active = Some(selection);
            return Ok(());
        }
        let session_id = self.id;
        let persisted_provider = provider.clone();
        let persisted_model = model.clone();
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                let changed = conn
                    .execute(
                        "UPDATE sessions
                            SET provider = ?1,
                                model = ?2,
                                model_selection_json = ?3,
                                active_model_revision = active_model_revision + 1
                          WHERE session_id = ?4",
                        params![
                            persisted_provider,
                            persisted_model,
                            selection_json,
                            session_id.to_string()
                        ],
                    )
                    .context("setting session model")?;
                if changed != 1 {
                    anyhow::bail!("session {session_id} not found while setting active model");
                }
                Ok(())
            })
            .context("persisting active model")?;
        *active = Some(selection);
        Ok(())
    }

    /// Current durable active-model revision for CAS coordination. Pending
    /// (not-yet-inserted) sessions return the staged revision.
    pub fn active_model_revision(&self) -> Result<i64> {
        if let Some(row) = self.pending_row.lock().unwrap().as_ref() {
            return Ok(row.active_model_revision);
        }
        let session_id = self.id;
        self.db
            .blocking_read_for_sync_ui(move |conn| {
                crate::db::Db::active_model_revision_conn(conn, session_id)?
                    .ok_or_else(|| anyhow::anyhow!("session {session_id} not found"))
            })
            .context("reading active_model_revision")
    }

    /// CAS-update the durable session model. On success advances the revision
    /// and updates the in-memory selection. A zero-row conflict returns
    /// `Ok(false)` without mutating memory.
    pub fn cas_set_active_model_ref(
        &self,
        expected_revision: i64,
        selection: crate::config::providers::ActiveModelRef,
    ) -> Result<bool> {
        let mut active = self.model_selection.lock().unwrap();
        let selection_json =
            serde_json::to_string(&selection).context("encoding session model selection")?;
        let provider = selection.provider.clone();
        let model = selection.model.clone();
        {
            let mut slot = self.pending_row.lock().unwrap();
            if let Some(row) = slot.as_mut() {
                if row.active_model_revision != expected_revision {
                    return Ok(false);
                }
                row.provider = Some(provider.clone());
                row.model = Some(model.clone());
                row.model_selection_json = Some(selection_json.clone());
                row.active_model_revision = expected_revision.saturating_add(1);
                *active = Some(selection);
                return Ok(true);
            }
        }
        let session_id = self.id;
        let persisted_provider = provider.clone();
        let persisted_model = model.clone();
        let selection_json_for_db = selection_json.clone();
        let ok = self
            .db
            .blocking_write_for_sync_maintenance(move |conn| {
                crate::db::Db::cas_set_active_model_conn(
                    conn,
                    session_id,
                    expected_revision,
                    &persisted_provider,
                    &persisted_model,
                    &selection_json_for_db,
                )
            })
            .context("CAS persisting active model")?;
        if ok {
            *active = Some(selection);
        }
        Ok(ok)
    }

    pub fn active_agent(&self) -> String {
        self.active_agent.lock().unwrap().clone()
    }

    /// Adopt the active root/model already committed by the agent-profile
    /// preparation transaction. This updates only the in-process mirrors so
    /// the live `Session` agrees with that durable write
    /// (`set_prepared_session_primary_model_conn` for `ClaimExisting`, or the
    /// atomic insert for `CreateMissing`). Callers must not call this before
    /// the database transaction succeeds and must not persist the selection
    /// again (that would bump `active_model_revision` a second time).
    pub(crate) fn adopt_prepared_active_root(
        &self,
        agent: &str,
        selection: crate::config::providers::ActiveModelRef,
    ) {
        *self.active_agent.lock().unwrap() = agent.to_string();
        *self.model_selection.lock().unwrap() = Some(selection);
    }

    pub fn set_active_agent(&self, agent: &str) -> Result<()> {
        if self.stage_pending_row(|row| {
            row.active_agent = agent.to_string();
        }) {
            *self.active_agent.lock().unwrap() = agent.to_string();
            return Ok(());
        }
        let session_id = self.id;
        let active_agent = agent.to_string();
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                conn.execute(
                    "UPDATE sessions SET active_agent = ?1, pending_remote_agent_selection = NULL WHERE session_id = ?2",
                    params![active_agent, session_id.to_string()],
                )
                .context("setting session agent")?;
                Ok(())
            })
            .context("persisting active agent")
            .inspect(|_| {
                *self.active_agent.lock().unwrap() = agent.to_string();
            })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn session_grant_mutation_waits_for_an_in_flight_egress_permit() {
        let session = Arc::new(
            Session::create_for_test(
                crate::db::Db::open_in_memory().unwrap(),
                PathBuf::from("/monty-network-fence"),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        let permit = session.monty_network_egress_permit().await;
        let mutating_session = Arc::clone(&session);
        let mutation = tokio::spawn(async move {
            mutating_session
                .mutate_monty_session_network_grants(
                    crate::mcp::network::SessionNetworkMutation::GrantHost(
                        "api.example.test".to_string(),
                    ),
                )
                .await
        });
        // Tokio's RwLock is fair/write-preferring: once the mutation has
        // attempted the exclusive fence, later read attempts are blocked even
        // while this first read permit remains held. Waiting for that state
        // makes the assertion below fail if the mutation ever stops taking its
        // write-side revocation fence, instead of merely racing one yield.
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if session.monty_network_egress_gate.try_read().is_err() {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("session grant mutation must attempt the write-side egress fence");
        assert!(
            !mutation.is_finished(),
            "session grant mutation committed while egress retained its permit"
        );
        drop(permit);
        mutation.await.unwrap().unwrap();
    }
}
