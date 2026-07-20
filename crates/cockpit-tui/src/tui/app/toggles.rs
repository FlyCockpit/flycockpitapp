use super::*;

impl App {
    /// Send a redaction-source toggle to the daemon. `None` leaves a source
    /// unchanged; `Some(v)` sets it explicitly. The resulting state arrives
    /// back via the `RedactionState` event → toast (and tracked-state sync).
    pub(super) fn send_redaction_toggle(
        &mut self,
        scan_environment: Option<bool>,
        scan_dotenv: Option<bool>,
        scan_ssh_keys: Option<bool>,
    ) {
        self.send_daemon_request(
            "/toggle-redaction",
            cockpit_core::daemon::proto::Request::SetRedaction {
                scan_environment,
                scan_dotenv,
                scan_ssh_keys,
            },
            ControlApplied::None,
        );
    }

    /// Open the bare-`/toggle-redaction` multiselect: one checkbox per source
    /// pre-checked to the current per-source state. Driven locally (no daemon
    /// interrupt) like the `/init` existing-file prompt; the close handler
    /// matches the synthetic interrupt id and applies the selection.
    pub(super) fn open_redaction_toggle_dialog(&mut self) {
        use cockpit_core::daemon::proto::{
            InterruptOption, InterruptQuestion, InterruptQuestionSet,
        };
        let interrupt_id = uuid::Uuid::new_v4();
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Multi {
                prompt: "Redaction sources (session-only — reverts on restart):".to_string(),
                options: vec![
                    InterruptOption {
                        id: REDACT_OPT_ENV.into(),
                        label: "redact environment variables".into(),
                        description: None,
                        secondary: false,
                    },
                    InterruptOption {
                        id: REDACT_OPT_FILE.into(),
                        label: "redact environment files (default: .env)".into(),
                        description: None,
                        secondary: false,
                    },
                    InterruptOption {
                        id: REDACT_OPT_SSH.into(),
                        label: "redact private SSH keys (~/.ssh)".into(),
                        description: None,
                        secondary: false,
                    },
                ],
                // A blank multiselect (both unchecked) is a valid answer here:
                // it means "turn both off". No free-text custom row.
                allow_freetext: false,
            }],
        };
        let mut preselected: Vec<String> = Vec::new();
        if self.redact_scan_environment {
            preselected.push(REDACT_OPT_ENV.into());
        }
        if self.redact_scan_dotenv {
            preselected.push(REDACT_OPT_FILE.into());
        }
        if self.redact_scan_ssh_keys {
            preselected.push(REDACT_OPT_SSH.into());
        }
        let lockout = self.dialog_lockout();
        self.pending_local_choice = Some(LocalChoice::RedactionToggle(interrupt_id));
        self.question_dialog = Some(
            crate::tui::dialog::question::QuestionDialog::with_preselected(
                interrupt_id,
                String::new(),
                set,
                lockout,
                &[preselected],
            )
            .with_keyboard_enhancement_active(self.keyboard_enhancement_active),
        );
    }

    /// Resolve a closed bare-`/toggle-redaction` multiselect. `selected_ids`
    /// is the checked set (empty on a both-off confirm); `None` on Esc/cancel
    /// leaves the state untouched. Applies the selection by sending the
    /// resulting per-source booleans to the daemon.
    pub(super) fn resolve_redaction_toggle(&mut self, selected_ids: Option<&[String]>) {
        let Some(ids) = selected_ids else {
            return;
        };
        let env = ids.iter().any(|id| id == REDACT_OPT_ENV);
        let file = ids.iter().any(|id| id == REDACT_OPT_FILE);
        let ssh = ids.iter().any(|id| id == REDACT_OPT_SSH);
        self.send_redaction_toggle(Some(env), Some(file), Some(ssh));
    }

    /// Open the `/model-comparison` multiselect: every configured
    /// `(provider, model)` pair (same source as `/model`), with the **active**
    /// model excluded (no self-shadowing) and the current tandem set
    /// pre-checked (implementation note). Selecting
    /// updates the session's tandem set (session-only / in-memory). An empty
    /// confirm clears it — that is the OFF control. Driven locally (no daemon
    /// interrupt) like the bare `/toggle-redaction` picker; the close handler
    /// matches the synthetic id and routes the selection to the daemon.
    pub(super) fn open_model_comparison_dialog(&mut self) {
        use cockpit_core::daemon::proto::{
            InterruptOption, InterruptQuestion, InterruptQuestionSet,
        };

        // Configured `(provider, model)` pairs come from the held daemon
        // snapshot (`tui-config-single-source`); tandem models must have
        // working url/credentials, which the daemon resolves.
        let cfg = self.config_snapshot.providers.clone();
        if cfg.providers.is_empty() {
            self.push_plain(
                "/model-comparison: no cockpit config found — run `/settings` to add a provider"
                    .to_string(),
            );
            return;
        }

        // Build the (provider, model) option list, excluding the active model.
        let active = self.launch.active_model.clone();
        let mut pairs: Vec<(String, String)> = Vec::new();
        for (pid, entry) in &cfg.providers {
            for model in &entry.models {
                let pair = (pid.clone(), model.id.clone());
                if active.as_ref() == Some(&pair) {
                    continue; // never shadow the active model itself.
                }
                pairs.push(pair);
            }
        }
        pairs.sort();
        if pairs.is_empty() {
            self.push_plain(
                "/model-comparison: no other configured models to compare against".to_string(),
            );
            return;
        }

        // Option ids are the row index (stable for this dialog instance); the
        // index→pair mapping is held so the close handler resolves the checked
        // rows back to `(provider, model)` pairs without re-parsing labels
        // (model ids can contain `/`).
        let options: Vec<InterruptOption> = pairs
            .iter()
            .enumerate()
            .map(|(i, (p, m))| InterruptOption {
                id: i.to_string(),
                label: format!("{p}/{m}"),
                description: None,
                secondary: false,
            })
            .collect();
        // Pre-check rows already in the session's tandem set.
        let preselected: Vec<String> = pairs
            .iter()
            .enumerate()
            .filter(|(_, (p, m))| self.tandem_models.contains(&format!("{p}/{m}")))
            .map(|(i, _)| i.to_string())
            .collect();

        let interrupt_id = uuid::Uuid::new_v4();
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Multi {
                prompt:
                    "Tandem models to shadow every request to (session-only — reverts on restart):"
                        .to_string(),
                options,
                // A blank confirm (nothing checked) is valid — it turns the
                // feature off. No free-text custom row.
                allow_freetext: false,
            }],
        };
        let lockout = self.dialog_lockout();
        self.pending_local_choice = Some(LocalChoice::ModelComparison(interrupt_id));
        self.pending_tandem_options = pairs;
        self.question_dialog = Some(
            crate::tui::dialog::question::QuestionDialog::with_preselected(
                interrupt_id,
                String::new(),
                set,
                lockout,
                &[preselected],
            )
            .with_keyboard_enhancement_active(self.keyboard_enhancement_active),
        );
    }

    /// Resolve a closed `/model-comparison` multiselect. `selected_ids` is the
    /// checked set of row-index ids (empty on a clear-all confirm); `None` on
    /// Esc/cancel leaves the set untouched. Maps the checked rows back to
    /// `(provider, model)` pairs and sends them to the daemon, which builds the
    /// tandem models + routes them to the driver and broadcasts the resulting
    /// state (+ token-burn warning). Empty = feature off.
    pub(super) fn resolve_model_comparison_select(&mut self, selected_ids: Option<&[String]>) {
        let options = std::mem::take(&mut self.pending_tandem_options);
        let Some(ids) = selected_ids else {
            return;
        };
        let models: Vec<(String, String)> = ids
            .iter()
            .filter_map(|id| id.parse::<usize>().ok())
            .filter_map(|i| options.get(i).cloned())
            .collect();
        self.send_daemon_request(
            "/model-comparison",
            cockpit_core::daemon::proto::Request::SetTandemModels { models },
            ControlApplied::None,
        );
    }
}
