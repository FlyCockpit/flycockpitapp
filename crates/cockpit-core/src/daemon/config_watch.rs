use std::path::{Path, PathBuf};
use std::time::Duration;

use notify::{Event, EventKind, RecursiveMode, Watcher};
#[cfg(test)]
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::daemon::config_refresh::{ConfigRefreshFailureDeduper, refresh_session_config};
use crate::daemon::config_source::{ConfigSource, ConfigWatchPaths};
use crate::daemon::session_worker::SessionWorkerHandle;
use crate::db::Db;

const CONFIG_WATCH_QUIET_WINDOW: Duration = Duration::from_millis(300);
const CONFIG_WATCH_MAX_DELAY: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConfigWatchSignal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigWatchDecision {
    RefreshNow,
}

#[derive(Debug, Clone)]
pub(crate) struct ConfigWatchDebouncer {
    quiet_window: Duration,
    max_delay: Duration,
    pending: Option<PendingBurst>,
}

#[derive(Debug, Clone)]
struct PendingBurst {
    first_signal: Instant,
    last_signal: Instant,
}

impl ConfigWatchDebouncer {
    pub(crate) fn new(quiet_window: Duration, max_delay: Duration) -> Self {
        Self {
            quiet_window,
            max_delay,
            pending: None,
        }
    }

    pub(crate) fn signal(&mut self, now: Instant) {
        match &mut self.pending {
            Some(pending) => pending.last_signal = now,
            None => {
                self.pending = Some(PendingBurst {
                    first_signal: now,
                    last_signal: now,
                });
            }
        }
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        let pending = self.pending.as_ref()?;
        Some((pending.last_signal + self.quiet_window).min(pending.first_signal + self.max_delay))
    }

    pub(crate) fn fire_if_due(&mut self, now: Instant) -> Option<ConfigWatchDecision> {
        let deadline = self.next_deadline()?;
        if now < deadline {
            return None;
        }
        self.pending = None;
        Some(ConfigWatchDecision::RefreshNow)
    }
}

impl Default for ConfigWatchDebouncer {
    fn default() -> Self {
        Self::new(CONFIG_WATCH_QUIET_WINDOW, CONFIG_WATCH_MAX_DELAY)
    }
}

#[cfg(test)]
pub(crate) async fn run_config_watch_debouncer(
    mut signals: mpsc::UnboundedReceiver<ConfigWatchSignal>,
    decisions: mpsc::UnboundedSender<ConfigWatchDecision>,
    mut debouncer: ConfigWatchDebouncer,
) {
    let mut signals_open = true;
    loop {
        match debouncer.next_deadline() {
            Some(deadline) => {
                tokio::select! {
                    signal = signals.recv(), if signals_open => {
                        if signal.is_some() {
                            debouncer.signal(Instant::now());
                        } else {
                            signals_open = false;
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        if let Some(decision) = debouncer.fire_if_due(Instant::now()) {
                            let _ = decisions.send(decision);
                        }
                    }
                }
            }
            None if signals_open => match signals.recv().await {
                Some(_) => debouncer.signal(Instant::now()),
                None => signals_open = false,
            },
            None => break,
        }
    }
}

pub(crate) fn config_watch_path_matches(paths: &ConfigWatchPaths, path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if is_atomic_write_temp_name(file_name) {
        return false;
    }
    if paths.config_files.iter().any(|candidate| candidate == path) {
        return true;
    }
    paths.provider_dirs.iter().any(|provider_dir| {
        path.parent() == Some(provider_dir.as_path())
            && path.extension().and_then(|ext| ext.to_str()) == Some("json")
    })
}

pub(crate) fn config_watch_event_matches(paths: &ConfigWatchPaths, event: &Event) -> bool {
    event_kind_may_change_config(event.kind)
        && event
            .paths
            .iter()
            .any(|path| config_watch_path_matches(paths, path))
}

fn is_atomic_write_temp_name(file_name: &str) -> bool {
    file_name.starts_with('.') && file_name.ends_with(".tmp")
}

fn event_kind_may_change_config(kind: EventKind) -> bool {
    matches!(
        kind,
        EventKind::Any | EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    )
}

pub(crate) fn spawn_config_watcher(
    project_root: PathBuf,
    db: Db,
    config_source: ConfigSource,
    handle: SessionWorkerHandle,
) -> Option<JoinHandle<()>> {
    let watch_paths = config_source.watch_paths(&project_root);
    let watch_dirs = watch_paths.watched_dirs();
    if watch_dirs.is_empty() {
        return None;
    }

    let (event_tx, event_rx) = watch::channel(ConfigWatchSignal);
    let watch_paths_for_callback = watch_paths.clone();
    let mut watcher = match notify::recommended_watcher(move |result| match result {
        Ok(event) if config_watch_event_matches(&watch_paths_for_callback, &event) => {
            let _ = event_tx.send(ConfigWatchSignal);
        }
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(error = %error, "config file watcher event failed");
        }
    }) {
        Ok(watcher) => watcher,
        Err(error) => {
            tracing::warn!(error = %error, "config file watcher setup failed");
            return None;
        }
    };

    let mut watched = 0usize;
    for dir in watch_dirs {
        if !dir.is_dir() {
            continue;
        }
        match watcher.watch(&dir, RecursiveMode::NonRecursive) {
            Ok(()) => watched += 1,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    path = %dir.display(),
                    "config file watcher could not watch path"
                );
            }
        }
    }
    if watched == 0 {
        return None;
    }

    Some(tokio::spawn(run_config_watcher_task(
        db,
        config_source,
        handle,
        watcher,
        event_rx,
    )))
}

async fn run_config_watcher_task(
    db: Db,
    config_source: ConfigSource,
    handle: SessionWorkerHandle,
    watcher: notify::RecommendedWatcher,
    mut event_rx: watch::Receiver<ConfigWatchSignal>,
) {
    let mut debouncer = ConfigWatchDebouncer::default();
    let mut failure_deduper = ConfigRefreshFailureDeduper::default();
    loop {
        match debouncer.next_deadline() {
            Some(deadline) => {
                let _keep_watcher_alive = &watcher;
                tokio::select! {
                    signal = event_rx.changed() => {
                        if signal.is_err() {
                            break;
                        }
                        debouncer.signal(Instant::now());
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        if debouncer.fire_if_due(Instant::now()).is_some()
                            && let Err(error) = refresh_session_config(
                                &db,
                                &config_source,
                                &handle,
                                Some(&mut failure_deduper),
                            )
                            .await
                        {
                            tracing::warn!(error = %error, "config file watcher refresh failed");
                        }
                    }
                }
            }
            None => {
                let _keep_watcher_alive = &watcher;
                if event_rx.changed().await.is_err() {
                    break;
                }
                debouncer.signal(Instant::now());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::dirs::CONFIG_FILE;

    async fn assert_no_decision(rx: &mut mpsc::UnboundedReceiver<ConfigWatchDecision>) {
        tokio::task::yield_now().await;
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn config_watch_debouncer_coalesces_burst_into_one_refresh() {
        let (signal_tx, signal_rx) = mpsc::unbounded_channel();
        let (decision_tx, mut decision_rx) = mpsc::unbounded_channel();
        tokio::spawn(run_config_watch_debouncer(
            signal_rx,
            decision_tx,
            ConfigWatchDebouncer::default(),
        ));

        for _ in 0..5 {
            signal_tx.send(ConfigWatchSignal).unwrap();
            tokio::time::advance(Duration::from_millis(50)).await;
        }
        assert_no_decision(&mut decision_rx).await;
        tokio::time::advance(CONFIG_WATCH_QUIET_WINDOW).await;

        assert_eq!(
            decision_rx.recv().await,
            Some(ConfigWatchDecision::RefreshNow)
        );
        assert!(decision_rx.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn config_watch_debouncer_fires_after_quiet_window() {
        let (signal_tx, signal_rx) = mpsc::unbounded_channel();
        let (decision_tx, mut decision_rx) = mpsc::unbounded_channel();
        tokio::spawn(run_config_watch_debouncer(
            signal_rx,
            decision_tx,
            ConfigWatchDebouncer::default(),
        ));

        signal_tx.send(ConfigWatchSignal).unwrap();
        tokio::time::advance(CONFIG_WATCH_QUIET_WINDOW - Duration::from_millis(1)).await;
        assert_no_decision(&mut decision_rx).await;
        tokio::time::advance(Duration::from_millis(1)).await;

        assert_eq!(
            decision_rx.recv().await,
            Some(ConfigWatchDecision::RefreshNow)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn config_watch_debouncer_max_delay_prevents_starvation() {
        let (signal_tx, signal_rx) = mpsc::unbounded_channel();
        let (decision_tx, mut decision_rx) = mpsc::unbounded_channel();
        tokio::spawn(run_config_watch_debouncer(
            signal_rx,
            decision_tx,
            ConfigWatchDebouncer::default(),
        ));

        signal_tx.send(ConfigWatchSignal).unwrap();
        for _ in 0..7 {
            tokio::time::advance(Duration::from_millis(250)).await;
            signal_tx.send(ConfigWatchSignal).unwrap();
        }
        assert_no_decision(&mut decision_rx).await;
        tokio::time::advance(Duration::from_millis(250)).await;

        assert_eq!(
            decision_rx.recv().await,
            Some(ConfigWatchDecision::RefreshNow)
        );
    }

    #[test]
    fn config_watch_path_filter_accepts_config_and_provider_files() {
        let root = PathBuf::from("/repo/.cockpit");
        let paths =
            ConfigWatchPaths::new(vec![root.join(CONFIG_FILE)], vec![root.join("providers")]);

        assert!(config_watch_path_matches(&paths, &root.join(CONFIG_FILE)));
        assert!(config_watch_path_matches(
            &paths,
            &root.join("providers/openai.json")
        ));
    }

    #[test]
    fn config_watch_path_filter_rejects_atomic_write_temp_files() {
        let root = PathBuf::from("/repo/.cockpit");
        let paths =
            ConfigWatchPaths::new(vec![root.join(CONFIG_FILE)], vec![root.join("providers")]);

        assert!(!config_watch_path_matches(
            &paths,
            &root.join(".config.json.1234.5678.tmp")
        ));
        assert!(!config_watch_path_matches(&paths, &root.join("mcp.json")));
        assert!(!config_watch_path_matches(
            &paths,
            &root.join("agents/foo.md")
        ));
        assert!(!config_watch_path_matches(
            &paths,
            &root.join("providers/nested/openai.json")
        ));
    }
}
