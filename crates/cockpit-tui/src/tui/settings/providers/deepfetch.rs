//! Explicit-confirmation UI for the billable provider deep-fetch probes.

use super::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cockpit_config::providers::{ConfigDoc, ProvidersConfig};
use cockpit_core::providers::deepfetch::{
    DeepfetchPlan, DeepfetchScope, DeepfetchTarget, HttpDeepfetchProbeClient,
    collect_deepfetch_targets, deepfetch_confirmation_body, format_deepfetch_report,
    plan_deepfetch, probe_target,
};
use cockpit_core::providers::models_fetch;

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
    pub(super) fn prepare(
        config_path: &std::path::Path,
        provider_id: &str,
    ) -> Result<Self, String> {
        let config = ConfigDoc::load(config_path)
            .map_err(|error| format!("deep fetch failed: {error}"))?
            .providers();
        let targets = collect_deepfetch_targets(
            &config,
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

    fn start(&mut self, config_path: std::path::PathBuf) {
        debug_assert_eq!(self.phase, DeepFetchPhase::Confirm);
        self.phase = DeepFetchPhase::Running;
        self.status = None;
        let provider_id = self.provider_id.clone();
        let targets = self.targets.clone();
        let progress = Arc::clone(&self.progress);
        let cancel = Arc::clone(&self.cancel);
        tokio::spawn(async move {
            let result =
                run_deep_fetch(config_path, provider_id, targets, &progress, &cancel).await;
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
    config_path: std::path::PathBuf,
    provider_id: String,
    targets: Vec<DeepfetchTarget>,
    progress: &Arc<Mutex<DeepFetchProgress>>,
    cancel: &Arc<AtomicBool>,
) -> Result<String, String> {
    // This is intentionally inside the Run task: the confirmation screen must
    // not resolve credentials, construct an HTTP client, or issue a probe.
    let mut config = ConfigDoc::load(&config_path)
        .map_err(|error| format!("deep fetch failed: {error}"))?
        .providers();
    let entry = config.providers.get(&provider_id).cloned().ok_or_else(|| {
        format!("deep fetch failed: provider `{provider_id}` disappeared from config")
    })?;
    let resolved = models_fetch::resolve_provider_request_async(&provider_id, &entry)
        .await
        .map_err(|error| {
            format!("deep fetch failed: resolving provider `{provider_id}`: {error}")
        })?;
    let mut resolved_by_provider = BTreeMap::new();
    resolved_by_provider.insert(provider_id.clone(), resolved);
    let mut client = HttpDeepfetchProbeClient::new(resolved_by_provider, Duration::from_secs(20));

    run_deep_fetch_targets(
        &config_path,
        &targets,
        progress,
        cancel,
        &mut config,
        &mut client,
    )
    .await?;
    if cancel.load(Ordering::Acquire) {
        return Ok(format!(
            "deep fetch cancelled: completed model results have already been saved ({}/{})",
            progress
                .lock()
                .map(|progress| progress.completed)
                .unwrap_or_default(),
            targets.len()
        ));
    }
    Ok(format!(
        "deep fetch complete: {} model(s), up to {} request(s)",
        targets.len(),
        plan_deepfetch(&targets).total_requests()
    ))
}

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
}

fn append_line(progress: &Arc<Mutex<DeepFetchProgress>>, line: String) {
    if let Ok(mut progress) = progress.lock() {
        progress.lines.push(line);
    }
}

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
                KeyCode::Enter if state.cursor == 0 => state.start(self.config_path.clone()),
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
            lines,
            None,
            bindings,
            &self.pointer_surface,
            SettingsScrollRegionId("providers:deep-fetch"),
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
        state.phase = DeepFetchPhase::Done;
        state.status = Some(match result {
            Ok(summary) => {
                if let Ok(doc) = ConfigDoc::load(&self.cx.config_path) {
                    let disk = doc.providers();
                    if let Some(entry) = disk.providers.get(&state.provider_id).cloned() {
                        self.cx
                            .config
                            .providers
                            .insert(state.provider_id.clone(), entry.clone());
                        *parent.entry = entry;
                    }
                }
                summary
            }
            Err(error) => error,
        });
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
