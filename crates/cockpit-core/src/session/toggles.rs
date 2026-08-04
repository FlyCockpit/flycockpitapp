#![allow(deprecated)]

use super::*;

fn llm_mode_from_label(value: &str) -> Option<crate::config::extended::LlmMode> {
    match value {
        "defensive" => Some(crate::config::extended::LlmMode::Defensive),
        "normal" => Some(crate::config::extended::LlmMode::Normal),
        "frontier" => Some(crate::config::extended::LlmMode::Frontier),
        _ => None,
    }
}

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

    /// The session's current command-approval mode
    /// (implementation note). Read per gated tool call.
    pub fn approval_mode(&self) -> crate::config::extended::ApprovalMode {
        approval_mode_from_u8(self.approval_mode.load(Ordering::Relaxed))
    }

    pub fn is_btw_fork(&self) -> bool {
        self.btw_parent_session_id.is_some()
    }

    /// Set the session's command-approval mode. Used by the spawn path to
    /// apply the config default and by `/settings` to flip it at runtime.
    /// Returns the new mode.
    pub fn set_approval_mode(
        &self,
        mode: crate::config::extended::ApprovalMode,
    ) -> crate::config::extended::ApprovalMode {
        if self.approval_mode() != mode {
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

    pub fn session_llm_mode_raw(&self) -> Option<String> {
        self.session_llm_mode.lock().unwrap().clone()
    }

    pub fn session_llm_mode(&self) -> Option<crate::config::extended::LlmMode> {
        self.session_llm_mode_raw()
            .and_then(|mode| llm_mode_from_label(&mode))
    }

    pub fn set_session_llm_mode(&self, mode: crate::config::extended::LlmMode) -> Result<()> {
        let raw = mode.as_str().to_string();
        *self.session_llm_mode.lock().unwrap() = Some(raw.clone());
        if self.stage_pending_row(|row| {
            row.session_llm_mode = Some(raw.clone());
        }) {
            return Ok(());
        }
        let session_id = self.id;
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                conn.execute(
                    "UPDATE sessions SET session_llm_mode = ?1 WHERE session_id = ?2",
                    params![raw, session_id.to_string()],
                )
                .context("setting session llm mode")?;
                Ok(())
            })
            .context("persisting session llm mode")?;
        Ok(())
    }

    pub fn tool_surface_override_json(&self) -> Option<String> {
        self.tool_surface_override_json.lock().unwrap().clone()
    }

    #[allow(dead_code)]
    pub fn set_tool_surface_override_json(&self, override_json: Option<String>) -> Result<()> {
        *self.tool_surface_override_json.lock().unwrap() = override_json.clone();
        if self.stage_pending_row(|row| {
            row.tool_surface_override_json = override_json.clone();
        }) {
            return Ok(());
        }
        let session_id = self.id;
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                conn.execute(
                    "UPDATE sessions SET tool_surface_override_json = ?1 WHERE session_id = ?2",
                    params![override_json, session_id.to_string()],
                )
                .context("setting session tool surface override")?;
                Ok(())
            })
            .context("persisting session tool surface override")?;
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
        }) {
            *active = Some(selection);
            return Ok(());
        }
        let session_id = self.id;
        let persisted_provider = provider.clone();
        let persisted_model = model.clone();
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                conn.execute(
                    "UPDATE sessions
                        SET provider = ?1, model = ?2, model_selection_json = ?3
                      WHERE session_id = ?4",
                    params![
                        persisted_provider,
                        persisted_model,
                        selection_json,
                        session_id.to_string()
                    ],
                )
                .context("setting session model")?;
                Ok(())
            })
            .context("persisting active model")?;
        *active = Some(selection);
        Ok(())
    }

    pub fn active_agent(&self) -> String {
        self.active_agent.lock().unwrap().clone()
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
                    "UPDATE sessions SET active_agent = ?1 WHERE session_id = ?2",
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
