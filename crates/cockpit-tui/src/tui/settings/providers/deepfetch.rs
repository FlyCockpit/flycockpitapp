//! Explicit-confirmation UI for the billable provider deep-fetch probes.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(test)]
use cockpit_config::providers::{ConfigDoc, ProvidersConfig};
use cockpit_core::providers::deepfetch::{
    DeepfetchPlan, DeepfetchScope, DeepfetchTarget, collect_deepfetch_targets,
    deepfetch_confirmation_body, plan_deepfetch,
};
#[cfg(test)]
use cockpit_core::providers::deepfetch::{format_deepfetch_report, probe_target};

const TAIL_LINES: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeepFetchPhase {
    Confirm,
    Running,
    Done,
}

#[derive(Default)]
struct DeepFetchProgress {
    completed: usize,
    lines: Vec<String>,
    result: Option<Result<String, String>>,
    /// Latest authoritative catalog returned with a successful daemon probe.
    config: Option<cockpit_core::daemon::proto::ProviderConfigView>,
}

/// State is deliberately prepared from the config document, rather than from
/// the Edit page. Deep fetch writes only probe-derived model metadata.
pub(in crate::tui::settings) struct DeepFetchState {
    pub(super) provider_id: String,
    plan: DeepfetchPlan,
    targets: Vec<DeepfetchTarget>,
    phase: DeepFetchPhase,
    cursor: usize,
    progress: Arc<Mutex<DeepFetchProgress>>,
    cancel: Arc<AtomicBool>,
    spinner_tick: usize,
    pub(super) status: Option<String>,
}

impl DeepFetchState {
    #[cfg(test)]
    pub(super) fn prepare(
        config_path: &std::path::Path,
        provider_id: &str,
    ) -> Result<Self, String> {
        let config = ConfigDoc::load(config_path)
            .map_err(|error| format!("deep fetch failed: {error}"))?
            .providers();
        Self::prepare_from_config(&config, provider_id)
    }

    /// Production settings dialogs already hold the layer selected by the
    /// active workspace. Preparing from that snapshot avoids accidentally
    /// estimating a project operation from a global/XDG config path.
    pub(super) fn prepare_from_config(
        config: &cockpit_config::providers::ProvidersConfig,
        provider_id: &str,
    ) -> Result<Self, String> {
        let targets = collect_deepfetch_targets(
            config,
            &DeepfetchScope {
                provider: Some(provider_id.to_string()),
                model: None,
            },
        )
        .map_err(|error| format!("deep fetch failed: {error}"))?;
        if targets.is_empty() {
            return Err("deep fetch: no eligible OpenAI-compatible non-embedding models".into());
        }
        Ok(Self {
            provider_id: provider_id.to_string(),
            plan: plan_deepfetch(&targets),
            targets,
            phase: DeepFetchPhase::Confirm,
            cursor: 0,
            progress: Arc::new(Mutex::new(DeepFetchProgress::default())),
            cancel: Arc::new(AtomicBool::new(false)),
            spinner_tick: 0,
            status: None,
        })
    }

    fn start(&mut self, project_root: std::path::PathBuf) {
        debug_assert_eq!(self.phase, DeepFetchPhase::Confirm);
        self.phase = DeepFetchPhase::Running;
        self.status = None;
        let provider_id = self.provider_id.clone();
        let targets = self.targets.clone();
        let progress = Arc::clone(&self.progress);
        let cancel = Arc::clone(&self.cancel);
        tokio::spawn(async move {
            let result = run_deep_fetch(
                project_root.display().to_string(),
                provider_id,
                targets,
                &progress,
                &cancel,
            )
            .await;
            if let Ok(mut progress) = progress.lock() {
                progress.result = Some(result);
            }
        });
    }

    pub(super) fn set_pointer_choice(&mut self, choice: usize) -> bool {
        if self.phase != DeepFetchPhase::Confirm || choice > 1 {
            return false;
        }
        self.cursor = choice;
        true
    }

    pub(super) fn scroll_pointer_choice(&mut self, delta: isize) {
        if self.phase == DeepFetchPhase::Confirm {
            self.cursor = self.cursor.saturating_add_signed(delta).min(1);
        }
    }

    fn drain(&mut self) -> Option<Result<String, String>> {
        let mut progress = self.progress.lock().ok()?;
        progress.result.take()
    }

    fn completed_and_lines(&self) -> (usize, Vec<String>) {
        self.progress
            .lock()
            .map(|progress| (progress.completed, progress.lines.clone()))
            .unwrap_or_default()
    }

    pub(super) fn help_text(&self) -> &'static str {
        match self.phase {
            DeepFetchPhase::Confirm => "↑/↓/Tab/Shift+Tab  enter: choose  esc: cancel",
            DeepFetchPhase::Running => "deep fetch in progress…  esc: stop after current model",
            DeepFetchPhase::Done => "enter: back to provider",
        }
    }

    pub(in crate::tui::settings) fn advance_spinner(&mut self) {
        if self.phase == DeepFetchPhase::Running {
            self.spinner_tick = self.spinner_tick.wrapping_add(1);
        }
    }
}

async fn run_deep_fetch(
    project_root: String,
    provider_id: String,
    targets: Vec<DeepfetchTarget>,
    progress: &Arc<Mutex<DeepFetchProgress>>,
    cancel: &Arc<AtomicBool>,
) -> Result<String, String> {
    // The confirmation UI may inspect the non-secret configuration to estimate
    // cost, but the daemon owns credential resolution, probes, and persistence.
    // A settings config path may be the global XDG layer rather than a
    // workspace `.cockpit/config.json`; it is not a project-root authority.
    // The caller supplies the active dialog/picker workspace explicitly.
    let client = crate::tui::settings::settings_daemon_client()
        .await
        .map_err(|error| format!("deep fetch failed: {error}"))?;
    // Use one daemon operation per model. This keeps probing and persistence
    // daemon-owned while giving the TUI an observable target boundary: Esc
    // never interrupts an in-flight probe, but prevents the next request.
    for target in &targets {
        if cancel.load(Ordering::Acquire) {
            break;
        }
        append_line(
            progress,
            format!("→ {}:{}", target.provider_id, target.model_id),
        );
        let response = client
            .request(cockpit_core::daemon::proto::Request::FetchProviderModels {
                project_root: project_root.clone(),
                provider_id: Some(provider_id.clone()),
                model_id: Some(target.model_id.clone()),
                deep: true,
                on_unlisted: None,
                allow_fallback: false,
            })
            .await
            .map_err(|error| format!("deep fetch failed: {error}"))?
            .map_err(|error| format!("deep fetch failed: {error}"))?;
        let cockpit_core::daemon::proto::Response::ProviderModelsFetched { results, config } =
            response
        else {
            return Err("deep fetch failed: daemon returned unexpected response".into());
        };
        let result = results
            .into_iter()
            .next()
            .ok_or_else(|| "deep fetch failed: daemon returned no provider result".to_string())?;
        match result.outcome {
            cockpit_core::daemon::proto::ProviderModelFetchOutcome::Models { .. } => {
                append_line(progress, "  daemon deep fetch complete".to_string());
            }
            cockpit_core::daemon::proto::ProviderModelFetchOutcome::Error { message } => {
                return Err(format!("deep fetch failed: {message}"));
            }
            cockpit_core::daemon::proto::ProviderModelFetchOutcome::UnlistedModelsPreview {
                unlisted_count,
            } => {
                return Err(format!(
                    "deep fetch needs a keep/remove decision for {unlisted_count} configured model(s)"
                ));
            }
            cockpit_core::daemon::proto::ProviderModelFetchOutcome::Unsupported => {
                append_line(progress, "  provider does not publish /models".to_string());
            }
            cockpit_core::daemon::proto::ProviderModelFetchOutcome::FallbackAvailable {
                ..
            } => {
                append_line(progress, "  daemon returned fallback catalog".to_string());
            }
        }
        if let Ok(mut state) = progress.lock() {
            state.completed += 1;
            state.config = Some(config);
        }
    }
    let completed = progress
        .lock()
        .map(|progress| progress.completed)
        .unwrap_or_default();
    if cancel.load(Ordering::Acquire) && completed < targets.len() {
        return Ok(format!(
            "deep fetch cancelled: completed model results have already been saved ({completed}/{})",
            targets.len()
        ));
    }
    Ok(format!(
        "deep fetch complete: {} model(s), up to {} request(s)",
        targets.len(),
        plan_deepfetch(&targets).total_requests()
    ))
}

#[cfg(test)]
async fn run_deep_fetch_targets<C: cockpit_core::providers::deepfetch::DeepfetchProbeClient>(
    config_path: &std::path::Path,
    targets: &[DeepfetchTarget],
    progress: &Arc<Mutex<DeepFetchProgress>>,
    cancel: &Arc<AtomicBool>,
    config: &mut ProvidersConfig,
    client: &mut C,
) -> Result<(), String> {
    for target in targets {
        if cancel.load(Ordering::Acquire) {
            append_line(
                progress,
                "deep fetch cancelled; completed model results have already been saved".to_string(),
            );
            return Ok(());
        }
        append_line(
            progress,
            format!("→ {}:{}", target.provider_id, target.model_id),
        );
        let report = probe_target(client, config, target)
            .await
            .map_err(|error| format!("deep fetch failed: {error}"))?;
        append_line(progress, format!("  {}", format_deepfetch_report(&report)));
        persist_models(config_path, &target.provider_id, config)?;
        if let Ok(mut progress) = progress.lock() {
            progress.completed += 1;
        }
    }
    Ok(())
}

/// Test seam for the per-target loop. Production always constructs the HTTP
/// client in `run_deep_fetch`, after the confirmation action starts the task.
#[cfg(test)]
impl DeepFetchState {
    pub(super) fn is_confirming(&self) -> bool {
        self.phase == DeepFetchPhase::Confirm
    }

    pub(super) fn target_count(&self) -> usize {
        self.targets.len()
    }

    pub(super) fn plan_total_requests(&self) -> usize {
        self.plan.total_requests()
    }

    pub(super) fn is_running(&self) -> bool {
        self.phase == DeepFetchPhase::Running
    }

    pub(super) fn is_done(&self) -> bool {
        self.phase == DeepFetchPhase::Done
    }

    pub(super) fn cancellation_requested(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }

    pub(super) fn cancellation_handle_for_test(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancel)
    }

    pub(super) async fn run_with_client_for_test<
        C: cockpit_core::providers::deepfetch::DeepfetchProbeClient,
    >(
        &self,
        config_path: &std::path::Path,
        config: &mut ProvidersConfig,
        client: &mut C,
    ) -> Result<(), String> {
        run_deep_fetch_targets(
            config_path,
            &self.targets,
            &self.progress,
            &self.cancel,
            config,
            client,
        )
        .await
    }

    pub(super) fn completed_and_lines_for_test(&self) -> (usize, Vec<String>) {
        self.completed_and_lines()
    }

    pub(super) fn set_running_for_test(&mut self) {
        self.phase = DeepFetchPhase::Running;
    }

    pub(super) fn finish_for_test(&mut self, result: Result<String, String>, lines: Vec<String>) {
        let mut progress = self.progress.lock().expect("test progress lock");
        progress.lines = lines;
        progress.result = Some(result);
    }

    pub(super) fn finish_with_config_for_test(
        &mut self,
        result: Result<String, String>,
        lines: Vec<String>,
        config: &ProvidersConfig,
    ) {
        let mut progress = self.progress.lock().expect("test progress lock");
        progress.lines = lines;
        progress.config = Some(cockpit_core::secret_ref::redact_provider_view(config));
        progress.result = Some(result);
    }
}

fn append_line(progress: &Arc<Mutex<DeepFetchProgress>>, line: String) {
    if let Ok(mut progress) = progress.lock() {
        progress.lines.push(line);
    }
}

#[cfg(test)]
fn persist_models(
    config_path: &std::path::Path,
    provider_id: &str,
    config: &ProvidersConfig,
) -> Result<(), String> {
    let entry = config.providers.get(provider_id).ok_or_else(|| {
        format!("deep fetch failed: provider `{provider_id}` disappeared during probing")
    })?;
    let mut doc =
        ConfigDoc::load(config_path).map_err(|error| format!("deep fetch failed: {error}"))?;
    doc.write_provider_models(
        provider_id,
        &entry.models,
        entry.models_fetched_at,
        entry.model_catalog,
        entry.last_model_fetch.clone(),
    )
    .map_err(|error| format!("deep fetch failed: persisting provider `{provider_id}`: {error}"))
}

impl SettingsCx {
    pub(in crate::tui::settings) fn handle_deep_fetch_key(
        &mut self,
        key: KeyEvent,
        state: &mut DeepFetchState,
        parent: &mut Box<EditState>,
    ) -> Nav {
        match state.phase {
            DeepFetchPhase::Confirm => match key.code {
                KeyCode::Up | KeyCode::BackTab => state.cursor = state.cursor.saturating_sub(1),
                KeyCode::Down | KeyCode::Tab => state.cursor = (state.cursor + 1).min(1),
                KeyCode::Esc => return deep_fetch_back(parent, "deep fetch cancelled".into()),
                KeyCode::Enter if state.cursor == 0 => {
                    let Some(project_root) = self
                        .active_project_root
                        .as_deref()
                        .or(self.picker_cwd.as_deref())
                        .map(std::path::Path::to_path_buf)
                    else {
                        state.status =
                            Some("deep fetch requires the active settings workspace".into());
                        return Nav::Stay;
                    };
                    state.start(project_root);
                }
                KeyCode::Enter => return deep_fetch_back(parent, "deep fetch cancelled".into()),
                _ => {}
            },
            DeepFetchPhase::Running => match key.code {
                KeyCode::Char('q') => {
                    state.status =
                        Some("probes are in flight; Esc stops after the current model".into());
                }
                KeyCode::Esc => {
                    state.cancel.store(true, Ordering::Release);
                    state.status =
                        Some("cancellation requested; waiting for the in-flight probe".into());
                }
                _ => {}
            },
            DeepFetchPhase::Done => {
                if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
                    return deep_fetch_back(parent, state.status.clone().unwrap_or_default());
                }
            }
        }
        Nav::Stay
    }

    pub(in crate::tui::settings) fn render_deep_fetch(
        &self,
        frame: &mut Frame,
        area: Rect,
        state: &DeepFetchState,
    ) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let yellow = Style::default().fg(Color::Yellow);
        let red = Style::default().fg(Color::Red);
        let mut lines = vec![
            Line::from(vec![
                Span::styled("Provider: ", muted),
                Span::styled(
                    state.provider_id.clone(),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::default(),
        ];
        let mut bindings = Vec::new();
        match state.phase {
            DeepFetchPhase::Confirm => {
                lines.push(Line::from(Span::styled(
                    deepfetch_confirmation_body(&state.plan),
                    yellow,
                )));
                lines.push(Line::default());
                for (index, label) in ["Run deep fetch", "Cancel"].iter().enumerate() {
                    let selected = state.cursor == index;
                    bindings.push((
                        lines.len(),
                        super::super::pointer_actions::SettingsPointerAction::Providers(
                            super::super::pointer_actions::ProvidersAction::DeepFetchChoice(
                                super::super::pointer_actions::ProviderId(
                                    state.provider_id.clone(),
                                ),
                                if index == 0 {
                                    super::super::pointer_actions::DeepFetchChoice::Fetch
                                } else {
                                    super::super::pointer_actions::DeepFetchChoice::Cancel
                                },
                            ),
                        ),
                    ));
                    lines.push(Line::from(Span::styled(
                        format!("{}{}", if selected { "▸ " } else { "  " }, label),
                        if selected {
                            yellow.add_modifier(Modifier::BOLD)
                        } else {
                            Style::default()
                        },
                    )));
                }
            }
            DeepFetchPhase::Running | DeepFetchPhase::Done => {
                let (completed, all_lines) = state.completed_and_lines();
                let phase = if state.phase == DeepFetchPhase::Running {
                    format!(
                        "{} Deep fetch running…",
                        super::spinner_glyph(state.spinner_tick)
                    )
                } else {
                    "Deep fetch done".to_string()
                };
                lines.push(Line::from(Span::styled(
                    format!("{phase} {completed}/{} model(s)", state.targets.len()),
                    yellow,
                )));
                if let Some(status) = &state.status {
                    lines.push(Line::from(Span::styled(
                        status.clone(),
                        if status.starts_with("deep fetch failed:") {
                            red
                        } else {
                            muted
                        },
                    )));
                }
                lines.push(Line::default());
                lines.extend(
                    all_lines
                        .into_iter()
                        .rev()
                        .take(TAIL_LINES)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .map(Line::from),
                );
            }
        }
        self.scroll_states.render_bound_lines(
            frame,
            area,
            "providers:deep-fetch",
            (lines, None),
            bindings,
            (
                &self.pointer_surface,
                SettingsScrollRegionId("providers:deep-fetch"),
            )
                .into(),
        );
    }
}

impl SettingsDialog {
    pub(in crate::tui::settings) fn drain_deep_fetch(&mut self) {
        let Some(ProvidersPage::DeepFetch { state, parent }) =
            self.page.downcast_mut::<ProvidersPage>()
        else {
            return;
        };
        if state.phase != DeepFetchPhase::Running {
            return;
        }
        let Some(result) = state.drain() else {
            return;
        };
        // The daemon persisted the probe result. Adopt its returned catalog
        // before returning to the editor so a later editor save cannot put
        // stale model metadata back on disk.
        let catalog_update = if let Ok(mut progress) = state.progress.lock()
            && let Some(config) = progress.config.take()
            && let Some(entry) = config.providers.get(&state.provider_id)
        {
            let update = (state.provider_id.clone(), entry.entry.clone());
            *parent.entry = entry.entry.clone();
            Some(update)
        } else {
            None
        };
        state.phase = DeepFetchPhase::Done;
        state.status = Some(match result {
            // The daemon already persisted this fetch.  Do not reload a
            // mutable client-side config layer just to mirror its model
            // metadata; the next daemon catalog refresh is authoritative.
            Ok(summary) => summary,
            Err(error) => error,
        });
        let _ = state;
        let _ = parent;
        if let Some((provider_id, entry)) = catalog_update {
            self.config
                .providers
                .insert(provider_id.clone(), entry.clone());
            self.original_config.providers.insert(provider_id, entry);
        }
    }
}

fn deep_fetch_back(parent: &mut Box<EditState>, status: String) -> Nav {
    let mut owned = std::mem::replace(
        parent,
        Box::new(EditState::new(String::new(), ProviderEntry::default())),
    );
    owned.status = Some(status);
    Nav::Replace(super::super::providers_page(ProvidersPage::Edit(*owned)))
}
