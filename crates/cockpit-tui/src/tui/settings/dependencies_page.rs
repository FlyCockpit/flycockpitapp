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

#[cfg(test)]
pub(super) fn page_after_first_paint(cwd: PathBuf, sandbox_enabled: bool) -> PageBox {
    let store = cockpit_core::external_runtime::global_health_store();
    let state = match store.current_complete_bundle() {
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
    Box::new(DependenciesPage {
        state: Mutex::new(state),
        refresh: Mutex::new(None),
        scroll: 0,
        max_scroll: std::cell::Cell::new(0),
        cwd,
        sandbox_enabled,
        refresh_after_paint: false,
    })
}

pub(super) fn page(cwd: PathBuf, sandbox_enabled: bool) -> PageBox {
    let store = cockpit_core::external_runtime::global_health_store();
    let state = match store.current_complete_bundle() {
        Some((snapshot, descriptors)) => {
            cockpit_core::external_runtime::DependenciesPageState::first_paint(
                Some(snapshot.as_ref()),
                &descriptors,
            )
        }
        None => {
            let partial = store.current_bundle();
            let mut descriptors = cockpit_core::external_runtime::global_registry().descriptors();
            if let Some((_, live_descriptors)) = &partial {
                for descriptor in live_descriptors {
                    if let Some(existing) = descriptors
                        .iter_mut()
                        .find(|existing| existing.id == descriptor.id)
                    {
                        *existing = descriptor.clone();
                    } else {
                        descriptors.push(descriptor.clone());
                    }
                }
            }
            cockpit_core::external_runtime::DependenciesPageState::first_paint(
                partial.as_ref().map(|(snapshot, _)| snapshot.as_ref()),
                &descriptors,
            )
        }
    };
    Box::new(DependenciesPage {
        state: Mutex::new(state),
        refresh: Mutex::new(None),
        scroll: 0,
        max_scroll: std::cell::Cell::new(0),
        cwd,
        sandbox_enabled,
        refresh_after_paint: true,
    })
}

pub(super) struct DependenciesPage {
    state: Mutex<cockpit_core::external_runtime::DependenciesPageState>,
    refresh: Mutex<PendingDependencyRefresh>,
    scroll: u16,
    /// Largest in-bounds scroll offset, recomputed from the wrapped content
    /// height each render (interior-mutable so the `&self` render can update it).
    /// `Down` clamps against it so the list can't scroll past its end into blank.
    max_scroll: std::cell::Cell<u16>,
    cwd: PathBuf,
    sandbox_enabled: bool,
    refresh_after_paint: bool,
}

impl DependenciesPage {
    pub(super) fn tick(&mut self) {
        if self.refresh_after_paint {
            self.refresh_after_paint = false;
            self.start_in_process_refresh_without_cx();
        }
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

    fn start_in_process_refresh_without_cx(&mut self) {
        if self
            .refresh
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some()
        {
            return;
        }
        let generation = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .begin_refresh();
        let (tx, rx) = mpsc::sync_channel(1);
        let cwd = self.cwd.clone();
        let sandbox_enabled = self.sandbox_enabled;
        std::thread::spawn(move || {
            let result =
                cockpit_core::diagnostics::dependency_projection_with_deadline_and_publish_for_run(
                    cwd,
                    std::time::Duration::from_secs(2),
                    sandbox_enabled,
                )
                .map_err(|error| error.to_string());
            let _ = tx.send(result);
        });
        *self.refresh.lock().unwrap_or_else(|p| p.into_inner()) = Some((generation, rx));
    }
}

impl SettingsPage for DependenciesPage {
    fn pointer_surface_kind(&self) -> super::SettingsPointerSurfaceKind {
        super::SettingsPointerSurfaceKind::Dependencies
    }

    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
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
                // Clamp to the last-rendered max so the list can't scroll past
                // its end into blank space.
                self.scroll = self.scroll.saturating_add(1).min(self.max_scroll.get());
                Nav::Stay
            }
            KeyCode::Char('r') => {
                if self
                    .refresh
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .is_some()
                {
                    return Nav::Stay;
                }
                cx.dependency_refresh_calls = cx.dependency_refresh_calls.saturating_add(1);
                if let Some(hook) = cx.dependency_refresh.clone() {
                    hook();
                    let (tx, rx) = mpsc::sync_channel(1);
                    drop(tx);
                    *self.refresh.lock().unwrap_or_else(|p| p.into_inner()) = Some((0, rx));
                } else if cx.daemon_attached {
                    let _ = cx.refresh_host_capabilities();
                    self.start_in_process_refresh_without_cx();
                } else {
                    self.start_in_process_refresh_without_cx();
                }
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
        // Clamp the scroll to the wrapped content that actually overflows the
        // bordered viewport, so a stale/over-run offset never shows blank space.
        let inner_width = area.width.saturating_sub(2);
        let inner_height = area.height.saturating_sub(2);
        let content_rows = if inner_width == 0 {
            lines.len()
        } else {
            Paragraph::new(lines.clone())
                .wrap(Wrap { trim: false })
                .line_count(inner_width)
        };
        let max_scroll =
            (content_rows.saturating_sub(inner_height as usize)).min(u16::MAX as usize) as u16;
        self.max_scroll.set(max_scroll);
        let scroll = self.scroll.min(max_scroll);
        frame.render_widget(
            Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Dependencies "),
                )
                .wrap(Wrap { trim: false })
                .scroll((scroll, 0)),
            area,
        );
    }
    fn title(&self, _cx: &SettingsCx) -> String {
        "Dependencies".to_owned()
    }
    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        "↑/↓: scroll  r: refresh  h/esc: back"
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
