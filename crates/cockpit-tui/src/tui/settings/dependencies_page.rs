//! Read-only dependency health Settings page.

use super::{Nav, PageBox, SettingsCx, SettingsPage};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::Rect,
    text::Line,
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::{
    any::Any,
    path::PathBuf,
    sync::{Mutex, mpsc},
};

type DependencyRefreshResult = Result<cockpit_core::external_runtime::DependencyProjection, String>;
type PendingDependencyRefresh = Option<(u64, mpsc::Receiver<DependencyRefreshResult>)>;

pub(super) fn page(cwd: PathBuf) -> PageBox {
    let bundle = cockpit_core::external_runtime::global_health_store().current_bundle();
    let mut state = match bundle {
        Some((snapshot, descriptors)) => {
            cockpit_core::external_runtime::DependenciesPageState::first_paint(
                Some(snapshot.as_ref()),
                &descriptors,
            )
        }
        None => cockpit_core::external_runtime::DependenciesPageState::first_paint(
            None,
            &cockpit_core::external_runtime::global_registry().descriptors(),
        ),
    };
    let generation = state.begin_refresh();
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = cockpit_core::diagnostics::dependency_projection_with_deadline_and_publish(
            cwd,
            std::time::Duration::from_secs(2),
        )
        .map_err(|error| error.to_string());
        let _ = tx.send(result);
    });
    Box::new(DependenciesPage {
        state: Mutex::new(state),
        refresh: Mutex::new(Some((generation, rx))),
        scroll: 0,
    })
}

pub(super) struct DependenciesPage {
    state: Mutex<cockpit_core::external_runtime::DependenciesPageState>,
    refresh: Mutex<PendingDependencyRefresh>,
    scroll: u16,
}

impl DependenciesPage {
    pub(super) fn tick(&mut self) {
        let mut refresh = self.refresh.lock().unwrap_or_else(|p| p.into_inner());
        let completed = refresh
            .as_ref()
            .and_then(|(generation, rx)| match rx.try_recv() {
                Ok(result) => Some((*generation, result)),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => Some((
                    *generation,
                    Err("dependency refresh stopped before producing a snapshot".to_owned()),
                )),
            });
        if let Some((generation, result)) = completed {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            match result {
                Ok(projection) => {
                    state.apply_success(generation, projection);
                }
                Err(error) => {
                    state.apply_failure(generation, error);
                }
            }
            *refresh = None;
        }
    }
}

impl SettingsPage for DependenciesPage {
    fn handle_key(&mut self, _cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Left | KeyCode::Char('h') => {
                self.state.lock().unwrap_or_else(|p| p.into_inner()).close();
                Nav::Back
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll = self.scroll.saturating_sub(1);
                Nav::Stay
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll = self.scroll.saturating_add(1);
                Nav::Stay
            }
            _ => Nav::Stay,
        }
    }
    fn render(&self, _cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let mut lines = Vec::new();
        let mut group = None;
        for row in &state.displayed.rows {
            let next = match row.importance {
                cockpit_core::external_runtime::DependencyImportance::RequiredForDefaultSafety => "Default safety",
                cockpit_core::external_runtime::DependencyImportance::RequiredWhenFeatureSelected => "Selected features",
                cockpit_core::external_runtime::DependencyImportance::OptionalIntegration => "Optional integrations",
                cockpit_core::external_runtime::DependencyImportance::OptionalAccelerator => "Optional accelerators",
            }.to_string();
            if group.as_deref() != Some(next.as_str()) {
                if !lines.is_empty() {
                    lines.push(Line::default());
                }
                lines.push(Line::from(next.clone()));
                group = Some(next);
            }
            let versions = match (&row.required_version, &row.discovered_version) {
                (Some(required), Some(found)) => format!(" required {required}, found {found}"),
                (Some(required), None) => format!(" required {required}"),
                (None, Some(found)) => format!(" version {found}"),
                (None, None) => String::new(),
            };
            lines.push(Line::from(format!(
                "  {} [{:?}/{:?}]{versions}: {}",
                row.id, row.state, row.target, row.reason
            )));
        }
        if lines.is_empty() {
            lines.push(Line::from(
                "No complete snapshot; dependencies are Unknown.",
            ));
        }
        if let Some(error) = &state.refresh_failure {
            lines.push(Line::from(format!("Refresh failed: {error}")));
        }
        frame.render_widget(
            Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Dependencies "),
                )
                .wrap(Wrap { trim: false })
                .scroll((self.scroll, 0)),
            area,
        );
    }
    fn title(&self, _cx: &SettingsCx) -> String {
        "Dependencies".to_owned()
    }
    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        "↑/↓: scroll  h/esc: back  read-only"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "Dependencies"
    }
}
