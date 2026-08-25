//! Interactive image-generation spend policy settings page.

use std::any::Any;
#[cfg(test)]
use std::sync::{Arc, Condvar, Mutex, mpsc};

use cockpit_config::config::image_spend::{
    BudgetPolicy, ImageSpendSettings, ImageSpendSuggestions, ProjectEpochPolicy,
};
#[cfg(test)]
use cockpit_proto::{Request, Response};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Wrap};

use super::{Nav, PageBox, SettingsCx, SettingsPage, SettingsPointerSurfaceKind};

/// The subset of the daemon-owned image spend policy this page renders and
/// re-opens. The owner-remoted `GetImageSpendPolicy` / `SaveImageSpendPolicy`
/// RPCs return only the reviewed settings and their policy version; the
/// server-owned epoch bookkeeping (`epoch_sequence`, effective rolling anchor)
/// never crosses the wire, so it is deliberately absent here rather than
/// reconstructed with placeholder values.
#[derive(Debug, Clone, PartialEq)]
#[cfg(test)]
struct LoadedImageSpendPolicy {
    settings: ImageSpendSettings,
    policy_version: u64,
}

#[cfg(test)]
type LoadResult = Result<Option<LoadedImageSpendPolicy>, String>;

#[cfg(test)]
#[derive(Default)]
struct WorkerCompletion {
    complete: Mutex<bool>,
    changed: Condvar,
}

#[cfg(test)]
impl WorkerCompletion {
    fn finish(&self) {
        *self.complete.lock().unwrap() = true;
        self.changed.notify_all();
    }

    fn is_finished(&self) -> bool {
        *self.complete.lock().unwrap()
    }

    #[cfg(test)]
    fn wait(&self) {
        let mut complete = self.complete.lock().unwrap();
        while !*complete {
            complete = self.changed.wait(complete).unwrap();
        }
    }
}

#[cfg(test)]
struct WorkerCompletionGuard(Arc<WorkerCompletion>);

#[cfg(test)]
impl Drop for WorkerCompletionGuard {
    fn drop(&mut self) {
        self.0.finish();
    }
}

#[cfg(test)]
trait ImageSpendPersistence: Send + Sync {
    fn load(&self, project_key: String) -> LoadResult;
    fn save(
        &self,
        project_key: String,
        settings: ImageSpendSettings,
        expected_version: Option<u64>,
    ) -> Result<LoadedImageSpendPolicy, String>;
}

/// Production persistence: the daemon owner is the single authority for the
/// image spend ledger. This page never opens the SQLite ledger in-process; it
/// loads and persists exclusively through the owner-remoted daemon RPCs
/// (`GetImageSpendPolicy` / `SaveImageSpendPolicy`), reusing the same
/// `settings_daemon_client` boundary every other owner-remoted settings
/// mutation uses. The daemon handler runs the `owner_only` `activate_saved_policy`.
///
/// The page issues these RPCs from a background worker thread so the UI never
/// blocks. That worker is a bare OS thread with no ambient Tokio runtime, so it
/// cannot reach the daemon client on its own. We therefore capture the
/// long-lived application runtime `Handle` at page construction (the settings
/// reducer runs on that runtime) and drive each request with `Handle::block_on`
/// from the worker. Routing through the app runtime — rather than a throwaway
/// per-call runtime — keeps the memoized daemon client and its I/O task alive.
#[cfg(test)]
struct DefaultImageSpendPersistence {
    runtime: Option<tokio::runtime::Handle>,
}

#[cfg(test)]
impl DefaultImageSpendPersistence {
    /// Capture the ambient application runtime handle. Called from the settings
    /// reducer, which executes on that runtime; absent a runtime the persistence
    /// fails closed (see [`Self::block_on`]) rather than opening the ledger.
    fn capture() -> Self {
        Self {
            runtime: tokio::runtime::Handle::try_current().ok(),
        }
    }

    /// Drive a daemon RPC future to completion on the captured application
    /// runtime from the worker thread. Fails closed when no runtime was captured
    /// (L11): the TUI must never fall back to opening the ledger directly.
    fn block_on<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        // This is a hard thread-boundary assertion, not merely documentation:
        // reducers/event handlers run with an ambient Tokio runtime and must
        // never drive this synchronous persistence adapter.
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(
                "image spend persistence may run only on its dedicated OS worker".to_string(),
            );
        }
        let handle = self
            .runtime
            .as_ref()
            .ok_or_else(|| "image spend settings require the application runtime".to_string())?;
        handle.block_on(future)
    }
}

#[cfg(test)]
impl ImageSpendPersistence for DefaultImageSpendPersistence {
    fn load(&self, project_key: String) -> LoadResult {
        self.block_on(async move {
            let client = super::settings_daemon_client()
                .await
                .map_err(|error| error.to_string())?;
            match client
                .request(Request::GetImageSpendPolicy { project_key })
                .await
                .map_err(|error| error.to_string())?
            {
                Ok(Response::ImageSpendPolicy {
                    settings,
                    policy_version,
                }) => match (settings, policy_version) {
                    (Some(settings), Some(policy_version)) => Ok(Some(LoadedImageSpendPolicy {
                        settings,
                        policy_version,
                    })),
                    (None, None) => Ok(None),
                    _ => Err("daemon returned an inconsistent image spend policy".into()),
                },
                Ok(other) => Err(format!("unexpected image spend read response: {other:?}")),
                Err(error) => Err(error.to_string()),
            }
        })
    }

    fn save(
        &self,
        project_key: String,
        settings: ImageSpendSettings,
        expected_version: Option<u64>,
    ) -> Result<LoadedImageSpendPolicy, String> {
        // Serialize before the request builds the exact wire shape the CLI uses;
        // the daemon owner validates and activates the policy. On success the
        // daemon persisted precisely these reviewed settings, so the page
        // re-opens them alongside the returned authoritative version.
        let settings_json = serde_json::to_string(&settings).map_err(|error| error.to_string())?;
        self.block_on(async move {
            let client = super::settings_daemon_client()
                .await
                .map_err(|error| error.to_string())?;
            match client
                .request(Request::SaveImageSpendPolicy {
                    client_operation_id: uuid::Uuid::now_v7().to_string(),
                    project_key,
                    settings_json,
                    expected_policy_version: expected_version,
                })
                .await
                .map_err(|error| error.to_string())?
            {
                Ok(Response::ImageSpendPolicySaved {
                    result_policy_version: policy_version,
                    ..
                }) => Ok(LoadedImageSpendPolicy {
                    settings,
                    policy_version,
                }),
                Ok(other) => Err(format!("unexpected image spend save response: {other:?}")),
                Err(error) => Err(error.to_string()),
            }
        })
    }
}

/// Current-thread runtime used only by the `#[cfg(test)]` file-backed
/// persistence seam. Production persistence runs on the captured application
/// runtime handle through [`DefaultImageSpendPersistence::block_on`].
#[cfg(test)]
fn image_spend_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())
}

pub(super) fn page(project_key: String, cx: &mut SettingsCx) -> PageBox {
    let page_instance_id = uuid::Uuid::new_v4();
    cx.queue_image_spend_load(project_key.clone(), page_instance_id);
    Box::new(ImageSpendPage {
        page_instance_id,
        daemon_owned: true,
        project_key,
        cursor: 0,
        editing_time_zone: false,
        time_zone_before_edit: None,
        editing_micros: None,
        micros_buffer: String::new(),
        draft: ImageSpendSettings::default(),
        saved: ImageSpendSettings::default(),
        version: None,
        status: "Loading saved policy…".into(),
        #[cfg(test)]
        load: Mutex::new(None),
        #[cfg(test)]
        save: Mutex::new(None),
        #[cfg(test)]
        load_completion: Arc::new(WorkerCompletion {
            complete: Mutex::new(false),
            changed: Condvar::new(),
        }),
        #[cfg(test)]
        save_completion: Mutex::new(None),
        #[cfg(test)]
        persistence: Arc::new(DefaultImageSpendPersistence { runtime: None }),
    })
}

#[cfg(test)]
fn page_with_persistence(
    project_key: String,
    persistence: Arc<dyn ImageSpendPersistence>,
) -> PageBox {
    let (tx, rx) = mpsc::sync_channel(1);
    let load_completion = Arc::new(WorkerCompletion::default());
    let key = project_key.clone();
    let loader = persistence.clone();
    let worker_completion = load_completion.clone();
    std::thread::spawn(move || {
        let _completion = WorkerCompletionGuard(worker_completion);
        let _ = tx.send(loader.load(key));
    });
    Box::new(ImageSpendPage {
        page_instance_id: uuid::Uuid::new_v4(),
        daemon_owned: false,
        project_key,
        cursor: 0,
        editing_time_zone: false,
        time_zone_before_edit: None,
        editing_micros: None,
        micros_buffer: String::new(),
        draft: ImageSpendSettings::default(),
        saved: ImageSpendSettings::default(),
        version: None,
        status: "Loading saved policy…".into(),
        load: Mutex::new(Some(rx)),
        save: Mutex::new(None),
        load_completion,
        save_completion: Mutex::new(None),
        persistence,
    })
}

pub(super) struct ImageSpendPage {
    page_instance_id: uuid::Uuid,
    daemon_owned: bool,
    project_key: String,
    cursor: usize,
    editing_time_zone: bool,
    time_zone_before_edit: Option<String>,
    editing_micros: Option<usize>,
    micros_buffer: String,
    draft: ImageSpendSettings,
    saved: ImageSpendSettings,
    version: Option<u64>,
    status: String,
    #[cfg(test)]
    load: Mutex<Option<mpsc::Receiver<LoadResult>>>,
    #[cfg(test)]
    save: Mutex<Option<mpsc::Receiver<Result<LoadedImageSpendPolicy, String>>>>,
    #[cfg(test)]
    load_completion: Arc<WorkerCompletion>,
    #[cfg(test)]
    save_completion: Mutex<Option<Arc<WorkerCompletion>>>,
    #[cfg(test)]
    persistence: Arc<dyn ImageSpendPersistence>,
}

impl ImageSpendPage {
    pub(super) fn apply_daemon_completion(&mut self, completion: super::ImageSpendCompletion) {
        match completion {
            super::ImageSpendCompletion::Loaded {
                page_instance_id,
                settings,
                policy_version,
            } if page_instance_id == self.page_instance_id => match (settings, policy_version) {
                (Some(settings), Some(policy_version)) => {
                    self.version = Some(policy_version);
                    self.saved = settings.clone();
                    self.draft = settings;
                    self.status = "Saved policy loaded.".into();
                }
                (None, None) => {
                    self.status = "No saved policy; paid dispatch is blocked.".into();
                }
                _ => {
                    self.status = "Could not load policy: inconsistent daemon snapshot".into();
                }
            },
            super::ImageSpendCompletion::Saved {
                page_instance_id,
                settings,
                policy_version,
            } if page_instance_id == self.page_instance_id => {
                self.version = Some(policy_version);
                self.saved = settings.clone();
                self.draft = settings;
                self.status = format!("Saved policy version {policy_version}.");
            }
            super::ImageSpendCompletion::Failed {
                page_instance_id,
                message,
            } if page_instance_id == self.page_instance_id => {
                self.status = format!("Policy operation failed: {message}");
            }
            _ => {}
        }
    }

    fn edit_micros(&mut self, code: KeyCode) {
        let Some(scope) = self.editing_micros else {
            return;
        };
        match code {
            KeyCode::Esc => {
                self.editing_micros = None;
                self.micros_buffer.clear();
            }
            KeyCode::Backspace => {
                self.micros_buffer.pop();
            }
            KeyCode::Char(character) if character.is_ascii_digit() => {
                self.micros_buffer.push(character);
            }
            KeyCode::Enter => match self.micros_buffer.parse::<u64>() {
                Ok(value) if value > 0 => {
                    let policy = match scope {
                        0 => &mut self.draft.request,
                        1 => &mut self.draft.session,
                        _ => &mut self.draft.project,
                    };
                    *policy = BudgetPolicy::Finite { usd_micros: value };
                    self.editing_micros = None;
                    self.micros_buffer.clear();
                    self.status = "Finite micros updated; save to authorize.".into();
                }
                _ => self.status = "Enter a positive whole u64 micros value.".into(),
            },
            _ => {}
        }
    }

    fn edit_time_zone(&mut self, code: KeyCode) {
        let Some(ProjectEpochPolicy::CalendarMonth { time_zone }) = &mut self.draft.project_epoch
        else {
            self.editing_time_zone = false;
            return;
        };
        match code {
            KeyCode::Enter => {
                self.time_zone_before_edit = None;
                self.editing_time_zone = false;
            }
            KeyCode::Esc => {
                if let Some(previous) = self.time_zone_before_edit.take() {
                    *time_zone = previous;
                }
                self.editing_time_zone = false;
            }
            KeyCode::Backspace => {
                time_zone.pop();
            }
            KeyCode::Char(character)
                if character.is_ascii_alphanumeric()
                    || matches!(character, '/' | '_' | '-' | '+') =>
            {
                time_zone.push(character);
            }
            _ => {}
        }
    }

    pub(super) fn poll(&mut self) {
        if self.daemon_owned {
            return;
        }
        #[cfg(test)]
        self.poll_test_persistence();
    }

    #[cfg(test)]
    fn poll_test_persistence(&mut self) {
        let load_result = {
            let load = self.load.lock().unwrap();
            load.as_ref().and_then(|rx| match rx.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Empty) if self.load_completion.is_finished() => {
                    Some(Err("policy load worker stopped without a result".into()))
                }
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("policy load worker stopped without a result".into()))
                }
            })
        };
        if let Some(result) = load_result {
            self.load.lock().unwrap().take();
            match result {
                Ok(Some(current)) => {
                    self.version = Some(current.policy_version);
                    self.saved = current.settings.clone();
                    self.draft = current.settings;
                    self.status = "Saved policy loaded.".into();
                }
                Ok(None) => self.status = "No saved policy; paid dispatch is blocked.".into(),
                Err(error) => self.status = format!("Could not load policy: {error}"),
            }
        }
        let save_result = {
            let save = self.save.lock().unwrap();
            let save_finished = self
                .save_completion
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|completion| completion.is_finished());
            save.as_ref().and_then(|rx| match rx.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Empty) if save_finished => {
                    Some(Err("policy save worker stopped without a result".into()))
                }
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("policy save worker stopped without a result".into()))
                }
            })
        };
        if let Some(result) = save_result {
            self.save.lock().unwrap().take();
            match result {
                Ok(current) => {
                    self.version = Some(current.policy_version);
                    self.saved = current.settings.clone();
                    self.draft = current.settings;
                    self.status = format!("Saved policy version {}.", current.policy_version);
                }
                Err(error) => self.status = format!("Policy was not saved: {error}"),
            }
        }
    }

    fn cycle_scope(policy: &mut BudgetPolicy, suggestion: u64) {
        *policy = match policy {
            BudgetPolicy::Unconfigured => BudgetPolicy::Finite {
                usd_micros: suggestion,
            },
            BudgetPolicy::Finite { .. } => BudgetPolicy::Unlimited,
            BudgetPolicy::Unlimited => BudgetPolicy::Unconfigured,
        };
    }

    /// The one review gate every save path shares: an invalid draft never
    /// reaches persistence, and both entry points report it identically.
    fn validate_draft_or_status(&mut self) -> bool {
        if let Err(reason) = self.draft.validate() {
            self.status = format!("Not saved: {reason:?}. Review every required choice.");
            return false;
        }
        true
    }

    fn save(&mut self, cx: &mut SettingsCx) {
        if !self.validate_draft_or_status() {
            return;
        }
        if self.daemon_owned {
            if let Err(error) = cx.queue_image_spend_save(
                self.project_key.clone(),
                self.draft.clone(),
                self.version,
                self.page_instance_id,
            ) {
                self.status = format!("Policy was not saved: {error}");
            } else {
                self.status = "Saving reviewed policy…".into();
            }
            return;
        }
        #[cfg(test)]
        {
            self.persist_locally();
        }
    }

    #[cfg(test)]
    fn persist_locally(&mut self) {
        let (tx, rx) = mpsc::sync_channel(1);
        let project_key = self.project_key.clone();
        let draft = self.draft.clone();
        let version = self.version;
        let persistence = self.persistence.clone();
        let completion = Arc::new(WorkerCompletion::default());
        let worker_completion = completion.clone();
        std::thread::spawn(move || {
            let _completion = WorkerCompletionGuard(worker_completion);
            let _ = tx.send(persistence.save(project_key, draft, version));
        });
        *self.save.lock().unwrap() = Some(rx);
        *self.save_completion.lock().unwrap() = Some(completion);
        self.status = "Saving reviewed policy…".into();
    }

    /// Test-only save entry point for non-daemon-owned pages. Mirrors
    /// [`Self::save`] without requiring a live [`SettingsCx`].
    #[cfg(test)]
    fn save_for_test(&mut self) {
        if !self.validate_draft_or_status() {
            return;
        }
        self.persist_locally();
    }

    fn adjust_selected(&mut self, increase: bool) {
        let policy = match self.cursor {
            0 => &mut self.draft.request,
            1 => &mut self.draft.session,
            2 => &mut self.draft.project,
            3 => {
                if let Some(ProjectEpochPolicy::Rolling {
                    duration_seconds, ..
                }) = &mut self.draft.project_epoch
                {
                    *duration_seconds = if increase {
                        duration_seconds.saturating_add(86_400).min(31_622_400)
                    } else {
                        duration_seconds.saturating_sub(86_400).max(86_400)
                    };
                }
                return;
            }
            _ => return,
        };
        if let BudgetPolicy::Finite { usd_micros } = policy {
            *usd_micros = if increase {
                usd_micros.saturating_add(1_000_000)
            } else {
                usd_micros.saturating_sub(1_000_000).max(1)
            };
        }
    }
}

fn policy_label(policy: BudgetPolicy) -> String {
    match policy {
        BudgetPolicy::Unconfigured => "unconfigured (blocked)".into(),
        BudgetPolicy::Finite { usd_micros } => format!(
            "finite ${}.{:06}",
            usd_micros / 1_000_000,
            usd_micros % 1_000_000
        ),
        BudgetPolicy::Unlimited => "unlimited (explicit)".into(),
    }
}

impl SettingsPage for ImageSpendPage {
    fn pointer_surface_kind(&self) -> SettingsPointerSurfaceKind {
        SettingsPointerSurfaceKind::Category
    }

    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        self.poll();
        if self.editing_micros.is_some() {
            self.edit_micros(key.code);
            return Nav::Stay;
        }
        if self.editing_time_zone {
            self.edit_time_zone(key.code);
            return Nav::Stay;
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Left | KeyCode::Char('h') => Nav::Back,
            KeyCode::Up | KeyCode::Char('k') => {
                self.cursor = self.cursor.saturating_sub(1);
                Nav::Stay
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.cursor = (self.cursor + 1).min(4);
                Nav::Stay
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                let suggestions = ImageSpendSuggestions::DISPLAY_ONLY;
                match self.cursor {
                    0 => Self::cycle_scope(&mut self.draft.request, suggestions.request_usd_micros),
                    1 => Self::cycle_scope(&mut self.draft.session, suggestions.session_usd_micros),
                    2 => Self::cycle_scope(&mut self.draft.project, suggestions.project_usd_micros),
                    3 => {
                        self.draft.project_epoch = match self.draft.project_epoch {
                            None => Some(ProjectEpochPolicy::CalendarMonth {
                                time_zone: String::new(),
                            }),
                            Some(ProjectEpochPolicy::CalendarMonth { .. }) => {
                                // The rolling anchor is server-owned and stamped
                                // on save; the editor supplies only the window
                                // length.
                                Some(ProjectEpochPolicy::Rolling {
                                    duration_seconds: 30 * 86_400,
                                })
                            }
                            Some(ProjectEpochPolicy::Rolling { .. }) => None,
                        }
                    }
                    4 => self.save(cx),
                    _ => {}
                }
                Nav::Stay
            }
            KeyCode::Char('+') | KeyCode::Char('=') => {
                self.adjust_selected(true);
                Nav::Stay
            }
            KeyCode::Char('-') => {
                self.adjust_selected(false);
                Nav::Stay
            }
            KeyCode::Char('e') if self.cursor < 3 => {
                self.editing_micros = Some(self.cursor);
                let policy = match self.cursor {
                    0 => self.draft.request,
                    1 => self.draft.session,
                    _ => self.draft.project,
                };
                self.micros_buffer = match policy {
                    BudgetPolicy::Finite { usd_micros } => usd_micros.to_string(),
                    _ => String::new(),
                };
                Nav::Stay
            }
            KeyCode::Char('e')
                if self.cursor == 3
                    && matches!(
                        self.draft.project_epoch,
                        Some(ProjectEpochPolicy::CalendarMonth { .. })
                    ) =>
            {
                self.time_zone_before_edit = match &self.draft.project_epoch {
                    Some(ProjectEpochPolicy::CalendarMonth { time_zone }) => {
                        Some(time_zone.clone())
                    }
                    _ => None,
                };
                self.editing_time_zone = true;
                Nav::Stay
            }
            _ => Nav::Stay,
        }
    }

    fn render(&self, _cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        let marker = |row| if self.cursor == row { ">" } else { " " };
        let suggestions = ImageSpendSuggestions::DISPLAY_ONLY;
        let epoch = match &self.draft.project_epoch {
            None => "unconfigured (blocked when project is finite)".into(),
            Some(ProjectEpochPolicy::CalendarMonth { time_zone }) => {
                format!("calendar month ({time_zone})")
            }
            Some(ProjectEpochPolicy::Rolling {
                duration_seconds, ..
            }) => format!("rolling ({duration_seconds}s, saved anchor)"),
        };
        let lines = vec![
            Line::from("Image generation spend policy"),
            Line::from("Suggestions are display-only until you select and save them."),
            Line::from(format!(
                "{} Request: {}  [suggestion $1]",
                marker(0),
                policy_label(self.draft.request)
            )),
            Line::from(format!(
                "{} Session: {}  [suggestion $10]",
                marker(1),
                policy_label(self.draft.session)
            )),
            Line::from(format!(
                "{} Project: {}  [suggestion $100]",
                marker(2),
                policy_label(self.draft.project)
            )),
            Line::from(format!("{} Project window: {epoch}", marker(3))),
            Line::from(format!("{} Save reviewed choices", marker(4))),
            Line::from(format!("Status: {}", self.status)),
            Line::from(if self.editing_micros.is_some() {
                format!("Exact micros input: {}", self.micros_buffer)
            } else if self.editing_time_zone {
                "IANA timezone input active (Enter accepts, Esc restores).".into()
            } else {
                String::new()
            }),
            Line::from(format!(
                "Display suggestions: {}/{}/{} micros",
                suggestions.request_usd_micros,
                suggestions.session_usd_micros,
                suggestions.project_usd_micros
            )),
        ];
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }

    fn title(&self, _cx: &SettingsCx) -> String {
        "Image spend budgets".into()
    }
    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        "↑/↓: select  enter: choose/save  e: exact u64 micros/IANA zone  +/-: adjust  esc: back"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "ImageSpend"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct FilePersistence {
        path: PathBuf,
        saved_at_ms: i64,
    }

    impl ImageSpendPersistence for FilePersistence {
        fn load(&self, project_key: String) -> LoadResult {
            let store =
                cockpit_config::config::image_spend::TestImageSpendPolicyStore::open(&self.path)
                    .map_err(|error| error.to_string())?;
            image_spend_runtime()?
                .block_on(store.current(project_key))
                .map(|current| {
                    current.map(|policy| LoadedImageSpendPolicy {
                        settings: policy.settings,
                        policy_version: policy.policy_version,
                    })
                })
                .map_err(|error| error.to_string())
        }

        fn save(
            &self,
            project_key: String,
            settings: ImageSpendSettings,
            expected_version: Option<u64>,
        ) -> Result<LoadedImageSpendPolicy, String> {
            let store =
                cockpit_config::config::image_spend::TestImageSpendPolicyStore::open(&self.path)
                    .map_err(|error| error.to_string())?;
            image_spend_runtime()?
                .block_on(store.activate(project_key, settings, expected_version, self.saved_at_ms))
                .map(|policy| LoadedImageSpendPolicy {
                    settings: policy.settings,
                    policy_version: policy.policy_version,
                })
                .map_err(|error| error.to_string())
        }
    }

    fn poll_after_worker_completion(page: &mut ImageSpendPage) {
        if page.load.lock().unwrap().is_some() {
            page.load_completion.wait();
        }
        let save_completion = page.save_completion.lock().unwrap().clone();
        if let Some(completion) = save_completion {
            completion.wait();
        }
        page.poll();
        assert!(page.load.lock().unwrap().is_none());
        assert!(page.save.lock().unwrap().is_none());
    }

    fn persisted_page(path: PathBuf) -> PageBox {
        page_with_persistence(
            "project".into(),
            Arc::new(FilePersistence {
                path,
                saved_at_ms: 1_000,
            }),
        )
    }

    fn fixture() -> ImageSpendPage {
        ImageSpendPage {
            page_instance_id: uuid::Uuid::new_v4(),
            daemon_owned: false,
            project_key: "project".into(),
            cursor: 0,
            editing_time_zone: false,
            time_zone_before_edit: None,
            editing_micros: None,
            micros_buffer: String::new(),
            draft: ImageSpendSettings::default(),
            saved: ImageSpendSettings::default(),
            version: None,
            status: String::new(),
            load: Mutex::new(None),
            save: Mutex::new(None),
            load_completion: Arc::new(WorkerCompletion::default()),
            save_completion: Mutex::new(None),
            persistence: Arc::new(DefaultImageSpendPersistence { runtime: None }),
        }
    }

    #[test]
    fn suggestions_require_explicit_selection_and_invalid_save_does_not_mutate_saved() {
        let mut page = fixture();
        assert_eq!(page.draft, ImageSpendSettings::default());
        assert_eq!(page.saved, ImageSpendSettings::default());
        ImageSpendPage::cycle_scope(
            &mut page.draft.request,
            ImageSpendSuggestions::DISPLAY_ONLY.request_usd_micros,
        );
        assert_eq!(
            page.draft.request,
            BudgetPolicy::Finite {
                usd_micros: 1_000_000
            }
        );
        page.save_for_test();
        assert_eq!(page.saved, ImageSpendSettings::default());
        assert!(page.save.lock().unwrap().is_none());
        assert!(page.status.contains("SessionUnconfigured"));
    }

    #[test]
    fn loaded_policy_reopens_exact_explicit_scopes_and_epoch() {
        let mut page = fixture();
        let settings = ImageSpendSettings {
            request: BudgetPolicy::Unlimited,
            session: BudgetPolicy::Finite { usd_micros: 2 },
            project: BudgetPolicy::Finite { usd_micros: 3 },
            project_epoch: Some(ProjectEpochPolicy::CalendarMonth {
                time_zone: "America/Chicago".into(),
            }),
        };
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send(Ok(Some(LoadedImageSpendPolicy {
            settings: settings.clone(),
            policy_version: 4,
        })))
        .unwrap();
        *page.load.lock().unwrap() = Some(rx);
        page.poll();
        assert_eq!(page.draft, settings);
        assert_eq!(page.saved, settings);
        assert_eq!(page.version, Some(4));
    }

    #[test]
    fn calendar_epoch_starts_empty_and_accepts_arbitrary_explicit_iana_zone() {
        let mut page = fixture();
        page.cursor = 3;
        page.draft.project_epoch = Some(ProjectEpochPolicy::CalendarMonth {
            time_zone: String::new(),
        });
        page.editing_time_zone = true;
        for character in "Pacific/Auckland".chars() {
            page.edit_time_zone(KeyCode::Char(character));
        }
        assert!(matches!(
            page.draft.project_epoch,
            Some(ProjectEpochPolicy::CalendarMonth { ref time_zone }) if time_zone == "Pacific/Auckland"
        ));
    }

    #[test]
    fn escape_restores_timezone_value_from_before_edit() {
        let mut page = fixture();
        page.draft.project_epoch = Some(ProjectEpochPolicy::CalendarMonth {
            time_zone: "America/Chicago".into(),
        });
        page.time_zone_before_edit = Some("America/Chicago".into());
        page.editing_time_zone = true;
        page.edit_time_zone(KeyCode::Backspace);
        page.edit_time_zone(KeyCode::Esc);
        assert!(
            matches!(page.draft.project_epoch, Some(ProjectEpochPolicy::CalendarMonth { ref time_zone }) if time_zone == "America/Chicago")
        );
    }

    #[test]
    fn exact_micros_editor_accepts_full_positive_u64_without_float_conversion() {
        let mut page = fixture();
        page.editing_micros = Some(0);
        for character in u64::MAX.to_string().chars() {
            page.edit_micros(KeyCode::Char(character));
        }
        page.edit_micros(KeyCode::Enter);
        assert_eq!(
            page.draft.request,
            BudgetPolicy::Finite {
                usd_micros: u64::MAX
            }
        );
    }

    #[test]
    fn page_edits_saves_and_reopens_exact_policy_through_file_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image-spend.db");
        let mut boxed = persisted_page(path.clone());
        let page = boxed.as_any_mut().downcast_mut::<ImageSpendPage>().unwrap();
        poll_after_worker_completion(page);

        page.draft.request = BudgetPolicy::Unlimited;
        page.draft.session = BudgetPolicy::Finite { usd_micros: 7 };
        page.draft.project = BudgetPolicy::Finite { usd_micros: 1 };
        page.draft.project_epoch = Some(ProjectEpochPolicy::CalendarMonth {
            time_zone: String::new(),
        });
        page.editing_time_zone = true;
        for character in "Pacific/Auckland".chars() {
            page.edit_time_zone(KeyCode::Char(character));
        }
        page.edit_time_zone(KeyCode::Enter);
        page.editing_micros = Some(2);
        page.micros_buffer.clear();
        for character in u64::MAX.to_string().chars() {
            page.edit_micros(KeyCode::Char(character));
        }
        page.edit_micros(KeyCode::Enter);
        page.save_for_test();
        poll_after_worker_completion(page);
        assert_eq!(page.version, Some(1));

        drop(boxed);
        let mut reopened = persisted_page(path.clone());
        let reopened = reopened
            .as_any_mut()
            .downcast_mut::<ImageSpendPage>()
            .unwrap();
        poll_after_worker_completion(reopened);
        assert_eq!(reopened.draft.request, BudgetPolicy::Unlimited);
        assert_eq!(
            reopened.draft.session,
            BudgetPolicy::Finite { usd_micros: 7 }
        );
        assert_eq!(
            reopened.draft.project,
            BudgetPolicy::Finite {
                usd_micros: u64::MAX
            }
        );
        assert!(matches!(
            reopened.draft.project_epoch,
            Some(ProjectEpochPolicy::CalendarMonth { ref time_zone })
                if time_zone == "Pacific/Auckland"
        ));

        reopened.draft.session = BudgetPolicy::Unconfigured;
        reopened.save_for_test();
        assert!(reopened.save.lock().unwrap().is_none());
        let store =
            cockpit_config::config::image_spend::TestImageSpendPolicyStore::open(&path).unwrap();
        let persisted = image_spend_runtime()
            .unwrap()
            .block_on(store.current("project".into()))
            .unwrap()
            .unwrap();
        assert_eq!(persisted.policy_version, 1);
        assert_eq!(persisted.settings, reopened.saved);
    }

    /// The production persistence path is owner-remoted: it loads and saves the
    /// image-spend policy exclusively through the daemon RPCs and NEVER opens
    /// the SQLite ledger in the TUI process.
    ///
    /// Non-vacuity guard (L7): `open_default_call_count()` is a thread-local
    /// tally of in-process database-open calls. The removed direct-ledger
    /// implementation opened the ledger *synchronously on this thread* (a
    /// current-thread runtime driving `activate_saved_policy_default` /
    /// `current_saved_policy_default`), so it would leave the counter `>= 1`.
    /// The owner-remoted RPC path leaves it at `0`: the daemon, on its own
    /// threads, is the only opener. A regression back to a direct ledger open
    /// therefore fails these assertions.
    #[test]
    fn production_persistence_routes_through_owner_daemon_rpc_without_opening_ledger() {
        let _env = cockpit_test_support::TestEnvGuard::isolated_cockpit_home();
        let _daemon = cockpit_core::daemon::enable_in_process_auto_promote_with_production_config();

        // The production worker thread has no ambient runtime; production
        // captures the long-lived app runtime handle. Mirror that here with a
        // multi-thread runtime that outlives the calls, and drive the sync
        // persistence methods from this (non-async) test thread exactly as the
        // worker does.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("image spend rpc test runtime");
        let persistence = DefaultImageSpendPersistence {
            runtime: Some(runtime.handle().clone()),
        };
        // All budgets `unlimited` so `validate` passes without a project epoch,
        // and the daemon reaches the ledger write rather than a rejection.
        let settings = ImageSpendSettings {
            request: BudgetPolicy::Unlimited,
            session: BudgetPolicy::Unlimited,
            project: BudgetPolicy::Unlimited,
            project_epoch: None,
        };

        // Warm up the lazily-promoted in-process daemon on this thread BEFORE
        // the counter assertions: booting the daemon opens its DB, and doing so
        // here (rather than under a measured call) keeps that one-time open out
        // of the tallies below. The load also asserts the precondition — no
        // policy is stored yet — so a later load hit is caused by the save and
        // not a pre-existing value. This warm-up read already exercises the
        // owner-remoted `GetImageSpendPolicy` RPC.
        assert_eq!(persistence.load("rpc-project".into()), Ok(None));

        cockpit_core::test_env::reset_direct_ledger_open_count();
        let saved = persistence
            .save("rpc-project".into(), settings.clone(), None)
            .expect("owner daemon accepts the reviewed policy");
        assert_eq!(
            cockpit_core::test_env::direct_ledger_open_count(),
            0,
            "the save must reach the daemon RPC, never open the database in-process"
        );
        assert_eq!(saved.policy_version, 1);
        assert_eq!(saved.settings, settings);

        // The reviewed policy round-trips back through the same owner RPC.
        cockpit_core::test_env::reset_direct_ledger_open_count();
        let loaded = persistence
            .load("rpc-project".into())
            .expect("owner daemon returns the saved policy")
            .expect("a policy is now stored");
        assert_eq!(
            cockpit_core::test_env::direct_ledger_open_count(),
            0,
            "the reload must reach the daemon RPC, never open the database in-process"
        );
        assert_eq!(loaded.policy_version, 1);
        assert_eq!(loaded.settings, settings);
    }
}
