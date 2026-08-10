//! Interactive image-generation spend policy settings page.

use std::any::Any;
use std::sync::{Mutex, mpsc};

use cockpit_config::config::image_spend::{
    BudgetPolicy, CurrentImageSpendPolicy, ImageSpendSettings, ImageSpendSuggestions,
    ProjectEpochPolicy,
};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Wrap};

use super::{Nav, PageBox, SettingsCx, SettingsPage, SettingsPointerSurfaceKind};

type LoadResult = Result<Option<CurrentImageSpendPolicy>, String>;

pub(super) fn page(project_key: String) -> PageBox {
    let (tx, rx) = mpsc::sync_channel(1);
    let key = project_key.clone();
    std::thread::spawn(move || {
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())
            .and_then(|runtime| {
                runtime
                    .block_on(
                        cockpit_config::config::image_spend::current_saved_policy_default(key),
                    )
                    .map_err(|error| error.to_string())
            });
        let _ = tx.send(result);
    });
    Box::new(ImageSpendPage {
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
    })
}

pub(super) struct ImageSpendPage {
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
    load: Mutex<Option<mpsc::Receiver<LoadResult>>>,
    save: Mutex<Option<mpsc::Receiver<Result<CurrentImageSpendPolicy, String>>>>,
}

impl ImageSpendPage {
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
        if let Some(result) = self
            .load
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|rx| rx.try_recv().ok())
        {
            *self.load.lock().unwrap() = None;
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
        if let Some(result) = self
            .save
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|rx| rx.try_recv().ok())
        {
            *self.save.lock().unwrap() = None;
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

    fn save(&mut self) {
        if let Err(reason) = self.draft.validate() {
            self.status = format!("Not saved: {reason:?}. Review every required choice.");
            return;
        }
        let (tx, rx) = mpsc::sync_channel(1);
        let project_key = self.project_key.clone();
        let draft = self.draft.clone();
        let version = self.version;
        std::thread::spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())
                .and_then(|runtime| {
                    runtime
                        .block_on(
                            cockpit_config::config::image_spend::activate_saved_policy_default(
                                project_key,
                                draft,
                                version,
                                chrono::Utc::now().timestamp_millis(),
                            ),
                        )
                        .map_err(|error| error.to_string())
                });
            let _ = tx.send(result);
        });
        *self.save.lock().unwrap() = Some(rx);
        self.status = "Saving reviewed policy…".into();
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

    fn handle_key(&mut self, _cx: &mut SettingsCx, key: KeyEvent) -> Nav {
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
                                Some(ProjectEpochPolicy::Rolling {
                                    duration_seconds: 30 * 86_400,
                                    anchor: cockpit_config::config::image_spend::SavedInstant {
                                        // Placeholder only. The DB replaces it with its
                                        // authoritative saved instant transactionally.
                                        unix_ms: 0,
                                        monotonic_sequence: 0,
                                    },
                                })
                            }
                            Some(ProjectEpochPolicy::Rolling { .. }) => None,
                        }
                    }
                    4 => self.save(),
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

    fn fixture() -> ImageSpendPage {
        ImageSpendPage {
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
        page.save();
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
        tx.send(Ok(Some(CurrentImageSpendPolicy {
            settings: settings.clone(),
            policy_version: 4,
            epoch_policy_version: 2,
            epoch_sequence: Some(8),
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
}
