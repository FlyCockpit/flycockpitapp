//! Publication and use of the daemon-global redaction table.
//!
//! The daemon-global table scrubs every event delivered on the daemon-global
//! bus. It is republished by three producers — a stale broadcast, an explicit
//! refresh, and the vault's owner-publication callback — and read by every
//! global event sender. [`GlobalCoverage`] is the one place that:
//!
//! * publishes a table together with the exact coverage key and authority
//!   epoch its admitted generation was published under
//!   ([`CoverageStamp`]), in one critical section, so the table and its stamp
//!   can never disagree. The key is the capture's own (the authority admits
//!   a generation only when its capture-boundary and publication-fence
//!   revisions equal it): vault inventory generation and command-secret
//!   fingerprint, environment, installation redact policy, and the digest of
//!   the file-backed sources (dotenv bytes, SSH key material) the capture
//!   consumed. Nothing is sampled around the capture;
//! * decides, for every global send, whether the published table is current
//!   by recomputing that key from the live sources — re-reading the
//!   configured dotenv files and SSH keys — and comparing it with the
//!   published stamp ([`GlobalCoverage::deliver`]). A mismatch republishes,
//!   and the sender uses the table *it* acquired (never whatever happens to
//!   be published), so every send is scrubbed with a table whose key equals
//!   the live key it observed;
//! * applies the same use-time check to the originating session's table of a
//!   session-originated event: when that session's file-backed sources
//!   changed since its table was captured, the origin coverage is stale and
//!   non-owners get the content-free form.
//!
//! When coverage cannot be confirmed the event is delivered to owners
//! unchanged and to everyone else only in its content-free form
//! ([`content_free_global_event`]), or not at all.

use std::sync::{Arc, Mutex, Weak};

use anyhow::{Context, Result};

use super::{EventEnvelope, EventScrub, EventSender, SharedRedactionTable, proto};
use crate::redact::RedactionTable;
use crate::redact::coverage_authority::{CoverageScope, RedactionCoverageKey};

/// Where a republish reads its sources. The vault and the registry's command
/// cache are held weakly. The ownership graph is acyclic: the vault's
/// owner-publication callback holds only a [`WeakGlobalCoverage`], so the
/// vault never keeps this state alive, while this state keeps the
/// [`ConfigSource`](crate::daemon::config_source::ConfigSource) (which holds
/// the vault) alive for as long as the daemon context does.
struct GlobalCoverageSources {
    authority: crate::redact::coverage_authority::RedactionCoverageAuthority,
    config_source: crate::daemon::config_source::ConfigSource,
    vault: Weak<crate::secure_key::SecretVault>,
    command_cache:
        Arc<dyn Fn() -> Option<Arc<crate::secret_command::CommandSecretCache>> + Send + Sync>,
}

/// The exact coverage key and authority epoch of an admitted daemon-global
/// generation (see the module documentation).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CoverageStamp {
    key: RedactionCoverageKey,
    epoch: u64,
}

impl std::fmt::Debug for CoverageStamp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoverageStamp")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl CoverageStamp {
    pub(crate) fn new(key: RedactionCoverageKey, epoch: u64) -> Self {
        Self { key, epoch }
    }
}

/// A daemon-global table together with the stamp of the generation it was
/// admitted as.
pub(crate) struct AdmittedGlobalCoverage {
    pub(crate) table: Arc<RedactionTable>,
    pub(crate) stamp: CoverageStamp,
}

struct GlobalCoverageInner {
    table: SharedRedactionTable,
    /// The stamp of the published table. `None` for a table that was never
    /// admitted (a test fixture): it is never current, so first use
    /// republishes. Lock order: `published`, then `table`.
    published: Mutex<Option<CoverageStamp>>,
    /// `None` only for a fixed test table, which is always current.
    sources: Option<GlobalCoverageSources>,
}

/// The daemon-global redaction table and its publication state.
#[derive(Clone)]
pub struct GlobalCoverage {
    inner: Arc<GlobalCoverageInner>,
}

/// A non-owning handle to [`GlobalCoverage`], for holders (the vault's
/// owner-publication callback) that must not keep it alive.
#[derive(Clone)]
pub(crate) struct WeakGlobalCoverage {
    inner: Weak<GlobalCoverageInner>,
}

impl WeakGlobalCoverage {
    pub(crate) fn upgrade(&self) -> Option<GlobalCoverage> {
        self.inner.upgrade().map(|inner| GlobalCoverage { inner })
    }
}

impl std::fmt::Debug for GlobalCoverage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GlobalCoverage")
            .finish_non_exhaustive()
    }
}

impl GlobalCoverage {
    /// Construct the daemon's publication state around the boot table and
    /// the stamp it was admitted under (`None`: never admitted; the first use
    /// republishes).
    pub(crate) fn new(
        table: Arc<RedactionTable>,
        stamp: Option<CoverageStamp>,
        authority: crate::redact::coverage_authority::RedactionCoverageAuthority,
        config_source: crate::daemon::config_source::ConfigSource,
        vault: &Arc<crate::secure_key::SecretVault>,
        registry: crate::daemon::registry::WeakSessionRegistry,
    ) -> Self {
        Self {
            inner: Arc::new(GlobalCoverageInner {
                table: Arc::new(std::sync::RwLock::new(table)),
                published: Mutex::new(stamp),
                sources: Some(GlobalCoverageSources {
                    authority,
                    config_source,
                    vault: Arc::downgrade(vault),
                    command_cache: Arc::new(move || {
                        registry
                            .upgrade()
                            .map(|registry| registry.command_secret_cache())
                    }),
                }),
            }),
        }
    }

    /// A fixed table with no sources: always current, never republished.
    /// For unit tests of global-bus producers.
    #[cfg(test)]
    pub(crate) fn fixed(table: Arc<RedactionTable>) -> Self {
        Self {
            inner: Arc::new(GlobalCoverageInner {
                table: Arc::new(std::sync::RwLock::new(table)),
                published: Mutex::new(None),
                sources: None,
            }),
        }
    }

    /// Whether the published table carries an admitted generation's stamp.
    #[cfg(test)]
    pub(crate) fn has_admitted_stamp_for_test(&self) -> bool {
        self.inner
            .published
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
    }

    pub(crate) fn downgrade(&self) -> WeakGlobalCoverage {
        WeakGlobalCoverage {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// The published table (read side shared with the terminal host).
    pub fn shared_table(&self) -> SharedRedactionTable {
        self.inner.table.clone()
    }

    /// The currently published table, current or not.
    pub fn table(&self) -> Arc<RedactionTable> {
        super::current_redaction(&self.inner.table)
    }

    fn sources(&self) -> Option<&GlobalCoverageSources> {
        self.inner.sources.as_ref()
    }

    fn acquisition_inputs(
        sources: &GlobalCoverageSources,
    ) -> Result<(
        Arc<crate::secure_key::SecretVault>,
        Arc<crate::secret_command::CommandSecretCache>,
    )> {
        let vault = sources
            .vault
            .upgrade()
            .context("daemon vault is no longer available")?;
        let cache =
            (sources.command_cache)().context("daemon session registry is no longer available")?;
        Ok((vault, cache))
    }

    /// The stamp a capture starting now would be admitted under: the key
    /// recomputed from the live sources (re-reading every file-backed source)
    /// and the authority's live epoch. Blocking I/O.
    fn live_stamp(sources: &GlobalCoverageSources) -> Result<CoverageStamp> {
        let (vault, cache) = Self::acquisition_inputs(sources)?;
        // Read the epoch first: an invalidation racing the key computation
        // then makes the stamp compare unequal rather than stale-equal.
        let epoch = sources.authority.epoch();
        let key = crate::daemon::server::daemon_global_live_coverage_key(
            &sources.config_source,
            &vault,
            &cache,
        )?;
        Ok(CoverageStamp::new(key, epoch))
    }

    /// The published table when its stamp equals `live`, read under the same
    /// lock that publishes table and stamp together.
    fn published_matching(&self, live: &CoverageStamp) -> Option<Arc<RedactionTable>> {
        let published = self
            .inner
            .published
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (published.as_ref() == Some(live)).then(|| self.table())
    }

    /// Publish an admitted table with its own stamp. Table and stamp change
    /// in one critical section, so the published pair always describes
    /// itself; which of two racing captures ends up published does not
    /// matter for correctness, because every use recomputes the live stamp.
    fn install(&self, admitted: &AdmittedGlobalCoverage) {
        let mut published = self
            .inner
            .published
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        super::set_current_redaction(&self.inner.table, admitted.table.clone());
        *published = Some(admitted.stamp.clone());
    }

    /// Acquire and publish a fresh table from a synchronous context. Returns
    /// the table this call acquired.
    pub(crate) fn republish_blocking(&self, purpose: CoverageScope) -> Result<Arc<RedactionTable>> {
        let Some(sources) = self.sources() else {
            return Ok(self.table());
        };
        let (vault, cache) = Self::acquisition_inputs(sources)?;
        let admitted = crate::daemon::server::acquire_daemon_redaction_table_blocking(
            sources.authority.clone(),
            sources.config_source.clone(),
            vault,
            cache,
            purpose,
        )?;
        self.install(&admitted);
        Ok(admitted.table)
    }

    /// Acquire and publish a fresh table. Returns the table this call
    /// acquired.
    pub(crate) async fn republish(&self, purpose: CoverageScope) -> Result<Arc<RedactionTable>> {
        let Some(sources) = self.sources() else {
            return Ok(self.table());
        };
        let (vault, cache) = Self::acquisition_inputs(sources)?;
        let admitted = crate::daemon::server::acquire_daemon_redaction_table(
            sources.authority.clone(),
            &sources.config_source,
            &vault,
            &cache,
            purpose,
        )
        .await?;
        self.install(&admitted);
        Ok(admitted.table)
    }

    /// A table whose stamp equals the live stamp: the published one when it
    /// matches, otherwise one freshly acquired by this call.
    pub(crate) fn current_or_republish_blocking(&self) -> Result<Arc<RedactionTable>> {
        let Some(sources) = self.sources() else {
            return Ok(self.table());
        };
        // The live stamp re-reads files and the vault; on a multi-thread
        // runtime worker, tell the runtime this thread blocks.
        if let Ok(live) = blocking_io(|| Self::live_stamp(sources))
            && let Some(table) = self.published_matching(&live)
        {
            return Ok(table);
        }
        self.republish_blocking(CoverageScope::DaemonGlobalEvent)
    }

    async fn current_or_republish(&self) -> Result<Arc<RedactionTable>> {
        if self.sources().is_none() {
            return Ok(self.table());
        }
        // The live stamp re-reads files and the vault: keep it off the
        // async worker.
        let probe = self.clone();
        let current = tokio::task::spawn_blocking(move || {
            let sources = probe.sources()?;
            let live = Self::live_stamp(sources).ok()?;
            probe.published_matching(&live)
        })
        .await
        .ok()
        .flatten();
        if let Some(table) = current {
            return Ok(table);
        }
        self.republish(CoverageScope::DaemonGlobalEvent).await
    }

    /// Publish a terminal-host event on the daemon-global bus. The PTY
    /// stream (output, viewers, close, protocol violation) carries no free
    /// text and is intentionally unscrubbed, so it rides the published table
    /// without a currency check (one check per output chunk would re-read
    /// every source). `TerminalClipboard` text is scrubbed, so it goes
    /// through [`Self::deliver`]: current coverage, or the content-free form
    /// (withheld) for non-owners.
    pub fn send_terminal_event(&self, tx: &EventSender, event: proto::Event) {
        match event {
            event @ proto::Event::TerminalClipboard { .. } => self.deliver(tx, None, event),
            event => {
                let _ = tx.send(EventEnvelope {
                    event,
                    redact: EventScrub::single(self.table()),
                });
            }
        }
    }

    /// A fixed table with no sources, for tests outside this crate (the CLI
    /// terminal host's unit tests). Never current-checked or republished.
    #[cfg(any(test, feature = "test-support"))]
    pub fn fixed_for_tests(table: Arc<RedactionTable>) -> Self {
        Self {
            inner: Arc::new(GlobalCoverageInner {
                table: Arc::new(std::sync::RwLock::new(table)),
                published: Mutex::new(None),
                sources: None,
            }),
        }
    }

    /// The one delivery funnel for the daemon-global bus.
    ///
    /// `origin` is the table of the session the event originates in, if
    /// any; the event is then scrubbed with the current global table and
    /// that table matched together ([`EventScrub::with_origin`]), provided
    /// the origin table's file-backed sources are unchanged since it was
    /// captured ([`RedactionTable::machine_sources_current`]). When current
    /// coverage cannot be established, or the two tables cannot be combined,
    /// owners still receive the event and every other principal receives
    /// only its content-free form (or nothing).
    pub(crate) fn deliver(
        &self,
        tx: &EventSender,
        origin: Option<&Arc<RedactionTable>>,
        event: proto::Event,
    ) {
        let coverage = self.current_or_republish_blocking();
        let origin = origin.map(|origin| blocking_io(|| origin_coverage(origin)));
        send_with_coverage(tx, coverage, origin, event);
    }

    /// [`Self::deliver`] for async producers.
    pub(crate) async fn deliver_async(
        &self,
        tx: &EventSender,
        origin: Option<&Arc<RedactionTable>>,
        event: proto::Event,
    ) {
        let coverage = self.current_or_republish().await;
        let origin = match origin {
            Some(origin) => {
                let origin = origin.clone();
                Some(
                    tokio::task::spawn_blocking(move || origin_coverage(&origin))
                        .await
                        .unwrap_or_else(|_| Err(anyhow::anyhow!("origin coverage probe panicked"))),
                )
            }
            None => None,
        };
        send_with_coverage(tx, coverage, origin, event);
    }
}

/// Run blocking I/O from a synchronous caller that may be on a Tokio
/// worker thread: on a multi-thread runtime the runtime is told the thread
/// blocks (`block_in_place` is unavailable on a current-thread runtime).
fn blocking_io<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

/// The originating session's table, when its file-backed sources are
/// unchanged since capture. Blocking I/O.
fn origin_coverage(origin: &Arc<RedactionTable>) -> Result<Arc<RedactionTable>> {
    if origin
        .machine_sources_current()
        .context("re-reading the originating session's redaction sources")?
    {
        Ok(origin.clone())
    } else {
        anyhow::bail!("the originating session's redaction sources changed since capture")
    }
}

fn send_with_coverage(
    tx: &EventSender,
    coverage: Result<Arc<RedactionTable>>,
    origin: Option<Result<Arc<RedactionTable>>>,
    event: proto::Event,
) {
    let redact = coverage.and_then(|global| match origin {
        None => Ok(EventScrub::single(global)),
        Some(origin) => {
            let origin = origin?;
            EventScrub::with_origin(&global, &origin)
                .context("combining daemon-global and originating-session coverage")
        }
    });
    let redact = match redact {
        Ok(redact) => redact,
        Err(error) => {
            tracing::warn!(
                error = %format!("{error:#}"),
                "daemon-global coverage unavailable; non-owners receive the event without free text"
            );
            EventScrub::content_free()
        }
    };
    let _ = tx.send(EventEnvelope { event, redact });
}

/// Fixed text that replaces a free-text reason in a content-free host
/// capability snapshot.
pub(crate) const CONTENT_FREE_REASON: &str = "details withheld";

/// The content-free form of an event, delivered to non-owners when coverage
/// for its free text cannot be established. Structural fields clients act on
/// are kept and every free-text field is removed. `None` means the event has
/// no such form and is withheld from non-owners.
///
/// Every variant is listed, so a new event does not compile until its author
/// decides whether it has a content-free form.
pub(crate) fn content_free_global_event(event: proto::Event) -> Option<proto::Event> {
    use proto::Event as E;
    match event {
        // No free text at all.
        event @ (E::DaemonDraining { .. }
        | E::DaemonLifetimeChanged { .. }
        | E::Reconnect { .. }
        | E::OnboardingBootstrap(_)) => Some(event),
        #[cfg(feature = "extended")]
        event @ E::ImageControlConfigChanged { .. } => Some(event),
        E::CaffeinateState {
            active,
            lid_close_guaranteed,
            message: _,
        } => Some(E::CaffeinateState {
            active,
            lid_close_guaranteed,
            message: None,
        }),
        #[cfg(feature = "remote")]
        E::ConnectorStatus {
            enabled,
            status,
            relay_url,
            relay_id,
            relay_region,
            last_error: _,
        } => Some(E::ConnectorStatus {
            enabled,
            status,
            relay_url,
            relay_id,
            relay_region,
            last_error: None,
        }),
        E::HostCapabilitiesChanged { snapshot } => Some(E::HostCapabilitiesChanged {
            snapshot: content_free_host_capability_snapshot(snapshot),
        }),
        E::EnvDriftWarning {
            baseline,
            candidate,
            diff,
            policy,
        } => Some(E::EnvDriftWarning {
            baseline,
            candidate,
            diff: proto::EnvDiffSummary {
                baseline_digest: diff.baseline_digest,
                candidate_digest: diff.candidate_digest,
                added_keys: diff.added_keys,
                removed_keys: diff.removed_keys,
                changed_keys: diff.changed_keys,
                changed_secret_keys: Vec::new(),
                path_added: Vec::new(),
                path_removed: Vec::new(),
            },
            policy,
        }),
        // The event *is* its free text.
        E::LspNotice { .. } => None,
        // Session-scoped events: produced on a session's own bus with that
        // session's coverage, never on the daemon-global bus. Withheld if
        // one ever reaches this projection.
        E::ConfigSnapshot { .. }
        | E::QueueUpdated { .. }
        | E::ForegroundInputTarget { .. }
        | E::ActiveModelState { .. }
        | E::ModelSelectionResult { .. }
        | E::DefaultModelUpdateResult { .. }
        | E::ThinkingStarted { .. }
        | E::Reconnecting { .. }
        | E::InferenceWarning { .. }
        | E::AssistantTextDelta { .. }
        | E::ReasoningDelta { .. }
        | E::AssistantDisplayTextDelta { .. }
        | E::AssistantDisplayReasoningDelta { .. }
        | E::AssistantDisplayAttemptReset { .. }
        | E::AssistantDisplayComplete { .. }
        | E::AssistantDisplayError { .. }
        | E::AssistantText { .. }
        | E::UserMessageRecorded { .. }
        | E::UserMessageRemoved { .. }
        | E::QueuedUserMessagesFolded { .. }
        | E::SessionPersistFailed { .. }
        | E::SessionDriverFailed { .. }
        | E::PreflightStarted { .. }
        | E::UserMessagesTerminated { .. }
        | E::UserMessageRetracted { .. }
        | E::Notice { .. }
        | E::EventStreamLagged { .. }
        | E::SkillAutoInjected { .. }
        | E::ToolStart { .. }
        | E::ToolProgress { .. }
        | E::ToolEnd { .. }
        | E::ResourceWait { .. }
        | E::ResourceStart { .. }
        | E::ResourceClear { .. }
        | E::ToolError { .. }
        | E::InferenceFailed { .. }
        | E::InferenceSucceeded { .. }
        | E::BackupUsed { .. }
        | E::SubagentSpawned { .. }
        | E::SubagentRouting { .. }
        | E::SubagentReport { .. }
        | E::SubagentCompacted { .. }
        | E::NestedTurn { .. }
        | E::Usage { .. }
        | E::InterruptRaised { .. }
        | E::InterruptQueueChanged { .. }
        | E::InterruptResolved { .. }
        | E::InterruptInterrupted { .. }
        | E::HistoryReplay { .. }
        | E::AgentIdle { .. }
        | E::GoalSupervisionProgress { .. }
        | E::PrimarySwapped { .. }
        | E::SessionEnded { .. }
        | E::ScheduleStarted { .. }
        | E::ScheduleProgress { .. }
        | E::ScheduleNote { .. }
        | E::ScheduleCompleted { .. }
        | E::ContextProjection { .. }
        | E::Pruned { .. }
        | E::CompactReady { .. }
        | E::SandboxState { .. }
        | E::SandboxEscalationState { .. }
        | E::SandboxUnavailable { .. }
        | E::CommandCapabilityUnavailable { .. }
        | E::RedactionState { .. }
        | E::PreflightState { .. }
        | E::LongcacheState { .. }
        | E::ApprovalModeState { .. }
        | E::DelegationRecursionState { .. }
        | E::TandemState { .. }
        | E::GitignoreAllow { .. }
        | E::PausedWorkAvailable { .. }
        | E::WaitingForLock { .. }
        | E::AgentTreeChanged { .. }
        | E::WorkspaceTrustReconciliation { .. } => None,
        // The terminal host publishes on the global bus through its own
        // owner-shell path, never through this projection.
        E::TerminalOutput { .. }
        | E::TerminalClipboard { .. }
        | E::TerminalViewers { .. }
        | E::TerminalClosed { .. }
        | E::Osc52ProtocolViolation { .. } => None,
        E::Unknown => None,
    }
}

/// Host capabilities without free text: states, ids, importance and targets
/// are kept; every reason becomes [`CONTENT_FREE_REASON`] and every other
/// free-text or probe-derived field is dropped.
pub(crate) fn content_free_host_capability_snapshot(
    snapshot: proto::HostCapabilitySnapshot,
) -> proto::HostCapabilitySnapshot {
    proto::HostCapabilitySnapshot {
        generation: snapshot.generation,
        features: snapshot
            .features
            .into_iter()
            .map(|row| proto::FeatureCapabilityRow {
                id: row.id,
                state: row.state,
                reason: CONTENT_FREE_REASON.to_string(),
                fix_command: None,
                remedy_text: None,
                dependency_ids: row.dependency_ids,
            })
            .collect(),
        dependencies: snapshot
            .dependencies
            .into_iter()
            .map(|row| proto::CatalogDependencyRow {
                id: row.id,
                state: row.state,
                importance: row.importance,
                target: row.target,
                required_version: row.required_version,
                discovered_version: None,
                cause: None,
                remedy: None,
                reason: CONTENT_FREE_REASON.to_string(),
            })
            .collect(),
        secret_store: proto::SecretStoreSnapshot {
            intent: snapshot.secret_store.intent,
            effective_placement: snapshot.secret_store.effective_placement,
            fail_closed_reason: snapshot
                .secret_store
                .fail_closed_reason
                .map(|_| CONTENT_FREE_REASON.to_string()),
            fix_command: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp(material: &[u8], epoch: u64) -> CoverageStamp {
        use crate::redact::coverage_authority::CoverageBinding;
        let binding = |domain: &[u8]| CoverageBinding::derive(domain, material);
        CoverageStamp::new(
            RedactionCoverageKey::daemon_global(
                binding(b"principal"),
                binding(b"owner-authorization"),
                binding(b"environment"),
                binding(b"credential-vault"),
                binding(b"policy"),
                binding(b"sealed"),
                binding(b"override"),
                binding(b"machine-sources"),
            ),
            epoch,
        )
    }

    /// Whatever order captures finish in, the published table and its stamp
    /// describe each other, and a use only accepts the published table when
    /// its stamp equals the stamp the user observed live: a caller whose own
    /// observation is newer (or merely different) never receives a table
    /// that does not cover it.
    #[test]
    fn published_table_is_used_only_for_its_own_stamp() {
        let coverage = GlobalCoverage::fixed(Arc::new(RedactionTable::empty()));
        let newer = AdmittedGlobalCoverage {
            table: Arc::new(RedactionTable::empty()),
            stamp: stamp(b"rotated-key", 2),
        };
        let older = AdmittedGlobalCoverage {
            table: Arc::new(RedactionTable::empty()),
            stamp: stamp(b"old-key", 1),
        };
        coverage.install(&newer);
        coverage.install(&older);
        assert!(Arc::ptr_eq(&coverage.table(), &older.table));
        assert_eq!(
            coverage.inner.published.lock().unwrap().as_ref(),
            Some(&older.stamp),
            "the stamp describes the published table"
        );
        assert!(
            coverage.published_matching(&newer.stamp).is_none(),
            "a caller that observed the newer sources must not get the older table"
        );
        assert!(
            coverage.published_matching(&stamp(b"old-key", 2)).is_none(),
            "a later invalidation epoch makes the published table stale"
        );
        assert!(Arc::ptr_eq(
            &coverage.published_matching(&older.stamp).unwrap(),
            &older.table
        ));
    }

    /// The vault's owner-publication callback holds only a weak handle, so it
    /// never keeps the publication state (and through it the config source
    /// and vault) alive.
    #[test]
    fn weak_handle_does_not_keep_coverage_alive() {
        let coverage = GlobalCoverage::fixed(Arc::new(RedactionTable::empty()));
        let weak = coverage.downgrade();
        assert!(weak.upgrade().is_some());
        drop(coverage);
        assert!(weak.upgrade().is_none());
    }
}
