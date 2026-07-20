use super::*;

pub(in crate::tui::settings) struct FetchAllState {
    pub(in crate::tui::settings) providers: Vec<String>,
    pub(in crate::tui::settings) in_flight: Vec<FetchHandle>,
    pub(in crate::tui::settings) finished: Vec<FetchedSummary>,
    pub(in crate::tui::settings) pre_fetch_models:
        std::collections::BTreeMap<String, Vec<ModelEntry>>,
    pub(in crate::tui::settings) policy_resolved: bool,
    /// 0 = Keep (default), 1 = Remove, 2 = Save & close
    pub(in crate::tui::settings) cursor: usize,
    pub(in crate::tui::settings) dont_ask_again: bool,
    /// Aggregated set of (provider_id, missing_model_id) the user must rule on.
    pub(in crate::tui::settings) unlisted: Vec<(String, String)>,
}

impl FetchAllState {
    /// Kick off one background `/models` fetch per configured provider,
    /// reusing the same [`FetchHandle`] machinery the Add/Edit pages use.
    /// Providers whose request can't even be resolved (missing
    /// env/credentials) land directly in `finished` as an error so one
    /// bad provider never blocks the rest — `tick` drains the live
    /// handles as they complete.
    pub(in crate::tui::settings) fn spawn(
        providers: &crate::config::providers::ProvidersConfig,
    ) -> Self {
        let mut ids: Vec<String> = providers.providers.keys().cloned().collect();
        ids.sort();
        let mut in_flight = Vec::new();
        let finished = Vec::new();
        let mut pre_fetch_models = std::collections::BTreeMap::new();
        for id in &ids {
            let Some(entry) = providers.providers.get(id) else {
                continue;
            };
            pre_fetch_models.insert(id.clone(), entry.models.clone());
            in_flight.push(FetchHandle::spawn(id.clone(), entry.clone()));
        }
        Self {
            providers: ids,
            in_flight,
            finished,
            pre_fetch_models,
            policy_resolved: false,
            cursor: 0,
            dont_ask_again: false,
            unlisted: Vec::new(),
        }
    }

    /// True while at least one per-provider fetch is still running.
    pub(in crate::tui::settings) fn is_fetching(&self) -> bool {
        !self.in_flight.is_empty()
    }
}

pub(in crate::tui::settings) struct FetchedSummary {
    pub(in crate::tui::settings) provider_id: String,
    pub(in crate::tui::settings) outcome: Result<FetchOutcome, String>,
}

enum FetchDegradedStatus {
    Unsupported,
    Failed(String),
}

pub(in crate::tui::settings) struct FetchOnePromptState {
    pub(in crate::tui::settings) provider_id: String,
    pub(in crate::tui::settings) remote: Vec<ModelEntry>,
    pub(in crate::tui::settings) catalog: ProviderModelCatalog,
    pub(in crate::tui::settings) pre_fetch_models: Vec<ModelEntry>,
    pub(in crate::tui::settings) unlisted: Vec<String>,
    /// 0 = Keep, 1 = Remove, 2 = Do not show again.
    pub(in crate::tui::settings) cursor: usize,
    pub(in crate::tui::settings) dont_ask_again: bool,
}

pub(in crate::tui::settings) struct FetchFallbackPromptState {
    pub(in crate::tui::settings) provider_id: String,
    pub(in crate::tui::settings) models: Vec<ModelEntry>,
    pub(in crate::tui::settings) catalog: ProviderModelCatalog,
    pub(in crate::tui::settings) reason: String,
    /// 0 = retry live, 1 = keep existing, 2 = use fallback, 3 = cancel.
    pub(in crate::tui::settings) cursor: usize,
}

impl SettingsDialog {
    /// Poll the in-flight handles of an active all-providers refetch.
    /// Each finished handle is removed from `in_flight` and recorded in
    /// `finished`; model config is not mutated until the unlisted-model
    /// policy is resolved. When `in_flight` empties, the aggregated
    /// unlisted-models set is built so [`Self::render_fetch_all`] can show
    /// the Keep/Remove prompt when needed.
    /// A per-provider failure is just an `Err` summary — it never aborts
    /// the others.
    pub(in crate::tui::settings) fn drain_fetch_all(&mut self) {
        let Some(ProvidersPage::FetchAll(s)) = self.page.downcast_mut::<ProvidersPage>() else {
            return;
        };
        if s.in_flight.is_empty() {
            if !s.finished.is_empty() && !s.policy_resolved {
                self.finish_fetch_all_if_ready();
            }
            return;
        }

        let mut newly_done: Vec<FetchedSummary> = Vec::new();
        s.in_flight.retain(|handle| match handle.take() {
            Some(outcome) => {
                newly_done.push(FetchedSummary {
                    provider_id: handle.provider_id.clone(),
                    outcome,
                });
                false
            }
            None => true,
        });
        if newly_done.is_empty() {
            return;
        }

        let all_done = {
            let Some(ProvidersPage::FetchAll(s)) = self.page.downcast_mut::<ProvidersPage>() else {
                return;
            };
            s.finished.extend(newly_done);
            s.in_flight.is_empty()
        };

        if all_done {
            self.finish_fetch_all_if_ready();
        }
    }

    fn finish_fetch_all_if_ready(&mut self) {
        if !matches!(
            self.page.downcast_ref::<ProvidersPage>(),
            Some(ProvidersPage::FetchAll(_))
        ) {
            return;
        }
        let unlisted = compute_unlisted(self);
        let degraded = fetch_all_degraded_statuses(self);
        let auto_policy = match self.config.on_unlisted_models_fetch {
            Some(OnUnlistedModelsFetch::Keep) => Some(ModelMergePolicy::KeepUnlisted),
            Some(OnUnlistedModelsFetch::Remove) => Some(ModelMergePolicy::RemoveUnlisted),
            Some(OnUnlistedModelsFetch::Ask) | None if unlisted.is_empty() => {
                Some(ModelMergePolicy::KeepUnlisted)
            }
            Some(OnUnlistedModelsFetch::Ask) | None => None,
        };
        if let Some(policy) = auto_policy {
            let merges = {
                let Some(ProvidersPage::FetchAll(s)) = self.page.downcast_ref::<ProvidersPage>()
                else {
                    return;
                };
                fetch_all_merges(s)
            };
            self.apply_fetch_all_policy(merges, policy);
        }
        self.apply_fetch_all_degraded_statuses(degraded);
        let _ = self.save_config();
        if let Some(ProvidersPage::FetchAll(s)) = self.page.downcast_mut::<ProvidersPage>() {
            s.unlisted = if auto_policy.is_some() {
                Vec::new()
            } else {
                unlisted
            };
            s.policy_resolved = true;
        }
    }

    fn apply_fetch_all_policy(
        &mut self,
        merges: Vec<(
            String,
            Vec<ModelEntry>,
            Vec<ModelEntry>,
            ProviderModelCatalog,
        )>,
        policy: ModelMergePolicy,
    ) {
        for (provider_id, pre_fetch_models, remote, catalog) in merges {
            if let Some(entry) = self.config.providers.get_mut(&provider_id) {
                entry.models = merge_fetched_models_with_policy(
                    entry.effective_template(&provider_id),
                    &pre_fetch_models,
                    remote,
                    policy,
                );
                entry.models_fetched_at = Some(Utc::now());
                entry.model_catalog = catalog;
                entry.mark_model_fetch_success(catalog);
            }
        }
    }

    fn apply_fetch_all_degraded_statuses(&mut self, degraded: Vec<(String, FetchDegradedStatus)>) {
        for (provider_id, status) in degraded {
            let Some(entry) = self.config.providers.get_mut(&provider_id) else {
                continue;
            };
            match status {
                FetchDegradedStatus::Unsupported => entry.mark_model_fetch_unsupported(),
                FetchDegradedStatus::Failed(reason) => {
                    entry.mark_model_fetch_failed_kept_existing(reason)
                }
            }
        }
    }
}

impl SettingsCx {
    pub(in crate::tui::settings) fn apply_fetch_all_policy(
        &mut self,
        merges: Vec<(
            String,
            Vec<ModelEntry>,
            Vec<ModelEntry>,
            ProviderModelCatalog,
        )>,
        policy: ModelMergePolicy,
    ) {
        for (provider_id, pre_fetch_models, remote, catalog) in merges {
            if let Some(entry) = self.config.providers.get_mut(&provider_id) {
                entry.models = merge_fetched_models_with_policy(
                    entry.effective_template(&provider_id),
                    &pre_fetch_models,
                    remote,
                    policy,
                );
                entry.models_fetched_at = Some(Utc::now());
                entry.model_catalog = catalog;
                entry.mark_model_fetch_success(catalog);
            }
        }
    }

    /// Enter the all-providers refetch flow, reusing the existing
    /// [`FetchAll`](ProvidersPage::FetchAll) page and its per-provider
    /// [`FetchHandle`] machinery. No-op (with a status) when no providers
    /// are configured; never stacks a second concurrent run because the
    /// only entry point is the List page and entering replaces it.
    pub(in crate::tui::settings) fn start_fetch_all(&mut self) -> Nav {
        if self.config.providers.is_empty() {
            return Nav::Replace(super::super::providers_page(ProvidersPage::List {
                cursor: 0,
                status: Some("no providers configured".into()),
                delete_pending: false,
            }));
        }
        let state = FetchAllState::spawn(&self.config);
        Nav::Replace(super::super::providers_page(ProvidersPage::FetchAll(state)))
    }

    pub(in crate::tui::settings) fn handle_fetch_all_key(
        &mut self,
        key: KeyEvent,
        s: &mut FetchAllState,
    ) -> Nav {
        // While the per-provider fetches are still running, the only
        // accepted key is Esc (cancel + return). The prompt rows aren't
        // live yet — `tick`/`drain_fetch_all` populates them once every
        // handle has reported.
        if s.is_fetching() {
            if matches!(key.code, KeyCode::Char('q')) {
                return Nav::Close;
            }
            if matches!(key.code, KeyCode::Esc) {
                return Nav::Replace(super::super::providers_page(ProvidersPage::List {
                    cursor: initial_list_cursor(&self.config),
                    status: Some("refetch-all cancelled".into()),
                    delete_pending: false,
                }));
            }
            return Nav::Stay;
        }

        // If the fetch finished but no model drifted out of the upstream
        // list, there's nothing to rule on — any key returns to the list
        // with a per-provider summary.
        if s.unlisted.is_empty() {
            return Nav::Replace(super::super::providers_page(ProvidersPage::List {
                cursor: initial_list_cursor(&self.config),
                status: Some(fetch_all_summary(s)),
                delete_pending: false,
            }));
        }

        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc => {
                return Nav::Replace(super::super::providers_page(ProvidersPage::List {
                    cursor: initial_list_cursor(&self.config),
                    status: Some("refetch-all cancelled".into()),
                    delete_pending: false,
                }));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                // 3 rows: confirm / cancel / "don't ask again".
                s.cursor = crate::tui::nav::wrap_prev(s.cursor, 3);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                s.cursor = crate::tui::nav::wrap_next(s.cursor, 3);
            }
            KeyCode::Char(' ') if s.cursor == 2 => {
                s.dont_ask_again = !s.dont_ask_again;
            }
            KeyCode::Enter => {
                let pick = match s.cursor {
                    0 => OnUnlistedModelsFetch::Keep,
                    1 => OnUnlistedModelsFetch::Remove,
                    _ => OnUnlistedModelsFetch::Keep,
                };
                let policy = match pick {
                    OnUnlistedModelsFetch::Remove => ModelMergePolicy::RemoveUnlisted,
                    OnUnlistedModelsFetch::Ask | OnUnlistedModelsFetch::Keep => {
                        ModelMergePolicy::KeepUnlisted
                    }
                };
                self.apply_fetch_all_policy(fetch_all_merges(s), policy);
                if s.dont_ask_again {
                    self.config.on_unlisted_models_fetch = Some(pick);
                }
                let summary = fetch_all_summary(s);
                let status = match self.save_config() {
                    Ok(()) => summary,
                    Err(e) => format!("save failed: {e}"),
                };
                return Nav::Replace(super::super::providers_page(ProvidersPage::List {
                    cursor: initial_list_cursor(&self.config),
                    status: Some(status),
                    delete_pending: false,
                }));
            }
            _ => {}
        }
        Nav::Stay
    }
}

/// Render the per-provider outcome rows of an all-providers refetch:
/// `✓ provider — N model(s)`, `· provider — no /models endpoint`, or
/// `✗ provider — <error>`. Shared by the in-flight and completed views.
pub(in crate::tui::settings) fn render_fetch_all_results(
    lines: &mut Vec<Line<'static>>,
    s: &FetchAllState,
    muted: Style,
    green: Style,
    red: Style,
) {
    for f in &s.finished {
        let (glyph, text, style) = match &f.outcome {
            Ok(FetchOutcome::Models { models, catalog }) => (
                "✓",
                format!(
                    "{} — {} model(s){}",
                    f.provider_id,
                    models.len(),
                    provider_catalog_suffix(*catalog)
                ),
                green,
            ),
            Ok(FetchOutcome::Unsupported) => (
                "·",
                format!("{} — no /models endpoint (skipped)", f.provider_id),
                muted,
            ),
            Ok(FetchOutcome::FallbackAvailable { reason, .. }) => (
                "✗",
                format!(
                    "{} — live fetch failed; fallback available: {reason}",
                    f.provider_id,
                    reason = redact_model_fetch_reason(reason.as_str())
                ),
                red,
            ),
            Err(e) => (
                "✗",
                format!(
                    "{} — {}",
                    f.provider_id,
                    redact_model_fetch_reason(e.as_str())
                ),
                red,
            ),
        };
        lines.push(Line::from(vec![
            Span::raw(format!("  {glyph} ")),
            Span::styled(text, style),
        ]));
    }
}

/// One-line per-provider summary of a finished all-providers refetch:
/// how many succeeded, how many failed, and (when any did) the first
/// failing provider so the user has a thread to pull on.
fn fetch_all_summary(s: &FetchAllState) -> String {
    let total = s.finished.len();
    let failed: Vec<&FetchedSummary> = s
        .finished
        .iter()
        .filter(|f| {
            f.outcome.is_err() || matches!(f.outcome, Ok(FetchOutcome::FallbackAvailable { .. }))
        })
        .collect();
    let ok = total - failed.len();
    if failed.is_empty() {
        format!("refetched /models for {ok}/{total} provider(s)")
    } else {
        let first = &failed[0];
        let reason = match &first.outcome {
            Err(e) => redact_model_fetch_reason(e.as_str()),
            Ok(FetchOutcome::FallbackAvailable { reason, .. }) => {
                redact_model_fetch_reason(reason.as_str())
            }
            Ok(_) => String::new(),
        };
        format!(
            "refetched {ok}/{total} provider(s); {} failed (e.g. `{}`: {reason})",
            failed.len(),
            first.provider_id,
        )
    }
}

fn fetch_all_merges(
    s: &FetchAllState,
) -> Vec<(
    String,
    Vec<ModelEntry>,
    Vec<ModelEntry>,
    ProviderModelCatalog,
)> {
    s.finished
        .iter()
        .filter_map(|summary| match &summary.outcome {
            Ok(FetchOutcome::Models { models, catalog }) => Some((
                summary.provider_id.clone(),
                s.pre_fetch_models
                    .get(&summary.provider_id)
                    .cloned()
                    .unwrap_or_default(),
                models.clone(),
                *catalog,
            )),
            _ => None,
        })
        .collect()
}

fn fetch_all_degraded_statuses(dialog: &SettingsDialog) -> Vec<(String, FetchDegradedStatus)> {
    let Some(ProvidersPage::FetchAll(s)) = dialog.page.downcast_ref::<ProvidersPage>() else {
        return Vec::new();
    };
    s.finished
        .iter()
        .filter_map(|summary| match &summary.outcome {
            Ok(FetchOutcome::Unsupported) => Some((
                summary.provider_id.clone(),
                FetchDegradedStatus::Unsupported,
            )),
            Ok(FetchOutcome::FallbackAvailable { reason, .. }) => Some((
                summary.provider_id.clone(),
                FetchDegradedStatus::Failed(redact_model_fetch_reason(reason.as_str())),
            )),
            Err(error) => Some((
                summary.provider_id.clone(),
                FetchDegradedStatus::Failed(redact_model_fetch_reason(error.as_str())),
            )),
            Ok(FetchOutcome::Models { .. }) => None,
        })
        .collect()
}

/// Build the (provider_id, model_id) set of configured models that are
/// absent from the freshly-fetched upstream list, across every provider
/// that reported a successful `Models` outcome in the active FetchAll.
fn compute_unlisted(dialog: &SettingsDialog) -> Vec<(String, String)> {
    let Some(ProvidersPage::FetchAll(s)) = dialog.page.downcast_ref::<ProvidersPage>() else {
        return Vec::new();
    };
    let mut unlisted: Vec<(String, String)> = Vec::new();
    for summary in &s.finished {
        if let Ok(FetchOutcome::Models { models: remote, .. }) = &summary.outcome
            && let Some(existing) = s.pre_fetch_models.get(&summary.provider_id)
        {
            for model_id in compute_unlisted_for_models(existing, remote) {
                unlisted.push((summary.provider_id.clone(), model_id));
            }
        }
    }
    unlisted
}

pub(in crate::tui::settings) fn compute_unlisted_for_models(
    existing: &[ModelEntry],
    remote: &[ModelEntry],
) -> Vec<String> {
    existing
        .iter()
        .filter(|m| !m.manual)
        .filter(|m| !remote.iter().any(|r| r.id == m.id))
        .map(|m| m.id.clone())
        .collect()
}
