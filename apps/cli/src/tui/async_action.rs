#![allow(dead_code)]

use std::collections::HashMap;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AsyncActionId(u64);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AsyncActionKind {
    #[allow(dead_code)]
    DaemonRpc(&'static str),
    Blocking(&'static str),
    Refresh(&'static str),
    Internal(&'static str),
}

#[derive(Debug, Clone)]
pub enum AsyncActionPayload {
    Unit,
    Text(String),
    Bool(bool),
    #[allow(dead_code)]
    DaemonResponse(Box<crate::daemon::proto::Response>),
    Sessions(Vec<crate::daemon::proto::SessionSummary>),
    SessionLiveStatus(std::collections::HashMap<uuid::Uuid, (bool, bool)>),
    ResourceSnapshot(crate::engine::resource_scheduler::ResourceSchedulerSnapshot),
    PromoteResource {
        status: crate::daemon::proto::ResourcePromoteStatus,
        message: String,
        snapshot: crate::engine::resource_scheduler::ResourceSchedulerSnapshot,
    },
    ForkCreated {
        parent_session_id: uuid::Uuid,
        socket: std::path::PathBuf,
        session_id: uuid::Uuid,
        short_id: String,
        seed_composer: Option<String>,
    },
    NoteRecorded {
        text: String,
    },
    DelegationSteer(crate::daemon::proto::DelegationSteerResult),
    GuidanceEstimate(crate::tui::agent_runner::GuidanceEstimate),
    StartupGuidanceEstimate {
        cwd: std::path::PathBuf,
        active_model: Option<(String, String)>,
        estimate: crate::tui::agent_runner::GuidanceEstimate,
    },
    ContainerAvailability(crate::container::ContainerAvailability),
    RemoteDisclosures {
        org: Option<crate::db::org_sync::OrgSyncDisclosure>,
        connector: Option<crate::db::connector::ConnectorDisclosure>,
    },
    ProviderUsage(Vec<crate::providers::usage::ProviderUsageSnapshot>),
    LocalCommand {
        label: String,
        raw_output: String,
        failed: bool,
        git_args: Option<String>,
    },
    DaemonProbe {
        cwd: std::path::PathBuf,
        status: crate::daemon::DaemonStatus,
    },
    OAuthCodexBegin(crate::auth::codex_oauth::DeviceLogin),
    OAuthCodexComplete {
        logged_in: bool,
    },
    OAuthGrokBegin {
        login: crate::auth::xai_oauth::ManualLogin,
        auto_attempted: bool,
        browser_error: Option<String>,
    },
    OAuthGrokComplete {
        logged_in: bool,
    },
}

#[derive(Debug, Clone)]
pub struct AsyncActionResult {
    pub id: AsyncActionId,
    pub kind: AsyncActionKind,
    pub payload: Result<AsyncActionPayload, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsyncActionKey(Arc<str>);

impl AsyncActionKey {
    pub fn new(value: impl Into<Arc<str>>) -> Self {
        Self(value.into())
    }
}

impl Hash for AsyncActionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsyncActionPolicy {
    AllowConcurrent,
    Dedupe(AsyncActionKey),
    Replace(AsyncActionKey),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncActionStart {
    Started(AsyncActionId),
    Existing(AsyncActionId),
}

impl AsyncActionStart {
    pub fn id(self) -> AsyncActionId {
        match self {
            AsyncActionStart::Started(id) | AsyncActionStart::Existing(id) => id,
        }
    }
}

#[derive(Debug)]
struct PendingAction {
    kind: AsyncActionKind,
    generation: u64,
    key: Option<AsyncActionKey>,
    handle: JoinHandle<()>,
}

#[derive(Debug)]
struct CompletedAction {
    id: AsyncActionId,
    generation: u64,
    kind: AsyncActionKind,
    payload: Result<AsyncActionPayload, String>,
}

#[derive(Debug)]
pub struct AsyncActionRunner {
    next_id: AtomicU64,
    next_generation: AtomicU64,
    pending: HashMap<AsyncActionId, PendingAction>,
    keyed: HashMap<AsyncActionKey, AsyncActionId>,
    tx: mpsc::UnboundedSender<CompletedAction>,
    rx: mpsc::UnboundedReceiver<CompletedAction>,
    notify: Arc<Notify>,
}

impl Default for AsyncActionRunner {
    fn default() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            next_id: AtomicU64::new(1),
            next_generation: AtomicU64::new(1),
            pending: HashMap::new(),
            keyed: HashMap::new(),
            tx,
            rx,
            notify: Arc::new(Notify::new()),
        }
    }
}

impl AsyncActionRunner {
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn notifier(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }

    pub fn is_pending(&self, id: AsyncActionId) -> bool {
        self.pending.contains_key(&id)
    }

    pub fn start<F>(
        &mut self,
        kind: AsyncActionKind,
        policy: AsyncActionPolicy,
        future: F,
    ) -> AsyncActionStart
    where
        F: Future<Output = Result<AsyncActionPayload, String>> + Send + 'static,
    {
        self.start_with(kind, policy, |tx, notify, id, generation, kind| {
            tokio::spawn(async move {
                let payload = future.await;
                let _ = tx.send(CompletedAction {
                    id,
                    generation,
                    kind,
                    payload,
                });
                notify.notify_one();
            })
        })
    }

    pub fn start_blocking<F>(
        &mut self,
        kind: AsyncActionKind,
        policy: AsyncActionPolicy,
        work: F,
    ) -> AsyncActionStart
    where
        F: FnOnce() -> Result<AsyncActionPayload, String> + Send + 'static,
    {
        self.start_with(kind, policy, |tx, notify, id, generation, kind| {
            tokio::task::spawn_blocking(move || {
                let payload = work();
                let _ = tx.send(CompletedAction {
                    id,
                    generation,
                    kind,
                    payload,
                });
                notify.notify_one();
            })
        })
    }

    fn start_with<F>(
        &mut self,
        kind: AsyncActionKind,
        policy: AsyncActionPolicy,
        spawn: F,
    ) -> AsyncActionStart
    where
        F: FnOnce(
            mpsc::UnboundedSender<CompletedAction>,
            Arc<Notify>,
            AsyncActionId,
            u64,
            AsyncActionKind,
        ) -> JoinHandle<()>,
    {
        let key = match policy {
            AsyncActionPolicy::AllowConcurrent => None,
            AsyncActionPolicy::Dedupe(key) => {
                if let Some(id) = self.keyed.get(&key).copied()
                    && self.pending.contains_key(&id)
                {
                    return AsyncActionStart::Existing(id);
                }
                Some(key)
            }
            AsyncActionPolicy::Replace(key) => {
                if let Some(id) = self.keyed.remove(&key)
                    && let Some(pending) = self.pending.remove(&id)
                {
                    pending.handle.abort();
                }
                Some(key)
            }
        };

        let id = AsyncActionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let handle = spawn(
            self.tx.clone(),
            Arc::clone(&self.notify),
            id,
            generation,
            kind.clone(),
        );
        if let Some(key) = &key {
            self.keyed.insert(key.clone(), id);
        }
        self.pending.insert(
            id,
            PendingAction {
                kind,
                generation,
                key,
                handle,
            },
        );
        AsyncActionStart::Started(id)
    }

    pub fn drain_completed(&mut self) -> Vec<AsyncActionResult> {
        let mut results = Vec::new();
        while let Ok(completed) = self.rx.try_recv() {
            let Some(pending) = self.pending.remove(&completed.id) else {
                continue;
            };
            if pending.generation != completed.generation || pending.kind != completed.kind {
                continue;
            }
            if let Some(key) = pending.key
                && self.keyed.get(&key) == Some(&completed.id)
            {
                self.keyed.remove(&key);
            }
            results.push(AsyncActionResult {
                id: completed.id,
                kind: completed.kind,
                payload: completed.payload,
            });
        }
        results
    }

    pub fn shutdown(&mut self) {
        for (_, pending) in self.pending.drain() {
            pending.handle.abort();
        }
        self.keyed.clear();
        while self.rx.try_recv().is_ok() {}
    }

    pub fn abort_key(&mut self, key: &AsyncActionKey) -> bool {
        let Some(id) = self.keyed.remove(key) else {
            return false;
        };
        let Some(pending) = self.pending.remove(&id) else {
            return false;
        };
        pending.handle.abort();
        true
    }
}

impl Drop for AsyncActionRunner {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::oneshot;
    use tokio::time::{Duration, sleep};

    async fn wait_for_results(runner: &mut AsyncActionRunner) -> Vec<AsyncActionResult> {
        for _ in 0..20 {
            let results = runner.drain_completed();
            if !results.is_empty() {
                return results;
            }
            sleep(Duration::from_millis(10)).await;
        }
        Vec::new()
    }

    fn assert_text_payload(result: &AsyncActionResult, expected: &str) {
        assert!(matches!(
            &result.payload,
            Ok(AsyncActionPayload::Text(text)) if text == expected
        ));
    }

    fn assert_bool_payload(result: &AsyncActionResult, expected: bool) {
        assert!(matches!(
            &result.payload,
            Ok(AsyncActionPayload::Bool(value)) if *value == expected
        ));
    }

    #[tokio::test]
    async fn starting_action_records_pending() {
        let mut runner = AsyncActionRunner::default();
        let (_tx, rx) = oneshot::channel::<()>();

        let start = runner.start(
            AsyncActionKind::Internal("pending"),
            AsyncActionPolicy::AllowConcurrent,
            async move {
                let _ = rx.await;
                Ok(AsyncActionPayload::Unit)
            },
        );

        assert!(matches!(start, AsyncActionStart::Started(_)));
        assert_eq!(runner.pending_count(), 1);
        assert!(runner.is_pending(start.id()));
    }

    #[tokio::test]
    async fn completing_delivers_exactly_one_typed_result() {
        let mut runner = AsyncActionRunner::default();
        let (tx, rx) = oneshot::channel::<&'static str>();
        let id = runner
            .start(
                AsyncActionKind::Internal("complete"),
                AsyncActionPolicy::AllowConcurrent,
                async move {
                    let text = rx.await.map_err(|e| e.to_string())?;
                    Ok(AsyncActionPayload::Text(text.to_string()))
                },
            )
            .id();

        tx.send("done").unwrap();
        let results = wait_for_results(&mut runner).await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, id);
        assert_eq!(results[0].kind, AsyncActionKind::Internal("complete"));
        assert_text_payload(&results[0], "done");
        assert!(runner.drain_completed().is_empty());
    }

    #[tokio::test]
    async fn superseding_action_ignores_late_result() {
        let mut runner = AsyncActionRunner::default();
        let key = AsyncActionKey::new("refresh");
        let (first_tx, first_rx) = oneshot::channel::<()>();
        let (second_tx, second_rx) = oneshot::channel::<()>();
        let first = runner
            .start(
                AsyncActionKind::Refresh("status"),
                AsyncActionPolicy::Replace(key.clone()),
                async move {
                    let _ = first_rx.await;
                    Ok(AsyncActionPayload::Text("first".to_string()))
                },
            )
            .id();
        let second = runner
            .start(
                AsyncActionKind::Refresh("status"),
                AsyncActionPolicy::Replace(key),
                async move {
                    let _ = second_rx.await;
                    Ok(AsyncActionPayload::Text("second".to_string()))
                },
            )
            .id();

        let _ = first_tx.send(());
        second_tx.send(()).unwrap();
        let results = wait_for_results(&mut runner).await;

        assert_ne!(first, second);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, second);
        assert_text_payload(&results[0], "second");
    }

    #[tokio::test]
    async fn oauth_payload_delivers_and_replace_aborts_prior_generation() {
        let mut runner = AsyncActionRunner::default();
        let key = AsyncActionKey::new("oauth.codex");
        let (first_tx, first_rx) = oneshot::channel::<()>();
        let (second_tx, second_rx) = oneshot::channel::<()>();

        runner.start(
            AsyncActionKind::Internal("oauth.codex.begin"),
            AsyncActionPolicy::Replace(key.clone()),
            async move {
                let _ = first_rx.await;
                Ok(AsyncActionPayload::OAuthCodexComplete { logged_in: false })
            },
        );
        let second = runner
            .start(
                AsyncActionKind::Internal("oauth.codex.begin"),
                AsyncActionPolicy::Replace(key),
                async move {
                    let _ = second_rx.await;
                    Ok(AsyncActionPayload::OAuthCodexComplete { logged_in: true })
                },
            )
            .id();

        first_tx.send(()).unwrap();
        second_tx.send(()).unwrap();
        let results = wait_for_results(&mut runner).await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, second);
        assert!(matches!(
            results[0].payload,
            Ok(AsyncActionPayload::OAuthCodexComplete { logged_in: true })
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_action_runs_off_event_loop() {
        let mut runner = AsyncActionRunner::default();
        let event_loop_thread = std::thread::current().id();

        runner.start_blocking(
            AsyncActionKind::Blocking("thread-check"),
            AsyncActionPolicy::AllowConcurrent,
            move || {
                Ok(AsyncActionPayload::Bool(
                    std::thread::current().id() != event_loop_thread,
                ))
            },
        );

        let results = wait_for_results(&mut runner).await;
        assert_eq!(results.len(), 1);
        assert_bool_payload(&results[0], true);
    }

    #[tokio::test]
    async fn refresh_action_can_dedupe_in_flight() {
        let mut runner = AsyncActionRunner::default();
        let key = AsyncActionKey::new("dedupe");
        let starts = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = oneshot::channel::<()>();
        let starts_for_first = Arc::clone(&starts);

        let first = runner.start(
            AsyncActionKind::Refresh("dedupe"),
            AsyncActionPolicy::Dedupe(key.clone()),
            async move {
                starts_for_first.fetch_add(1, Ordering::SeqCst);
                let _ = rx.await;
                Ok(AsyncActionPayload::Unit)
            },
        );
        let starts_for_second = Arc::clone(&starts);
        let second = runner.start(
            AsyncActionKind::Refresh("dedupe"),
            AsyncActionPolicy::Dedupe(key),
            async move {
                starts_for_second.fetch_add(1, Ordering::SeqCst);
                Ok(AsyncActionPayload::Unit)
            },
        );

        assert_eq!(second, AsyncActionStart::Existing(first.id()));
        tx.send(()).unwrap();
        assert_eq!(wait_for_results(&mut runner).await.len(), 1);
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn shutdown_ignores_in_flight_actions_without_panic() {
        let mut runner = AsyncActionRunner::default();
        let (_tx, rx) = oneshot::channel::<()>();
        runner.start(
            AsyncActionKind::Internal("shutdown"),
            AsyncActionPolicy::AllowConcurrent,
            async move {
                let _ = rx.await;
                Ok(AsyncActionPayload::Unit)
            },
        );

        runner.shutdown();

        assert_eq!(runner.pending_count(), 0);
        assert!(runner.drain_completed().is_empty());
    }
}
