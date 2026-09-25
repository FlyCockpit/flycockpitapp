//! Publication and use of the daemon-global redaction table.
//!
//! The daemon-global table scrubs every event delivered on the daemon-global
//! bus. It is republished by three producers — a stale broadcast, an explicit
//! refresh, and the vault's owner-publication callback — and read by every
//! global event sender. [`GlobalCoverage`] is the one place that:
//!
//! * publishes a table together with the freshness stamps (vault inventory
//!   generation and coverage-authority epoch) it was acquired under, in one
//!   critical section, so the table and its stamps can never disagree;
//! * refuses to let an older capture overwrite a newer one (the published
//!   stamps only move forward);
//! * decides, for every global send, whether the published table is current
//!   and republishes it when not ([`GlobalCoverage::deliver`]), so a
//!   session-originated event gets the same freshness check as a plain
//!   daemon-global broadcast.
//!
//! When coverage cannot be confirmed the event is delivered to owners
//! unchanged and to everyone else only in its content-free form
//! ([`content_free_global_event`]), or not at all.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use anyhow::{Context, Result};

use super::{EventEnvelope, EventScrub, EventSender, SharedRedactionTable, proto};
use crate::redact::RedactionTable;
use crate::redact::coverage_authority::CoverageScope;

/// Where a republish reads its sources. The vault and the registry's command
/// cache are held weakly: the vault's publication callback and the registry's
/// global bus both hold this value, and neither may keep the other alive.
struct GlobalCoverageSources {
    authority: crate::redact::coverage_authority::RedactionCoverageAuthority,
    config_source: crate::daemon::config_source::ConfigSource,
    vault: Weak<crate::secure_key::SecretVault>,
    command_cache:
        Arc<dyn Fn() -> Option<Arc<crate::secret_command::CommandSecretCache>> + Send + Sync>,
}

/// The freshness stamps a published table was acquired under, plus the
/// publication ticket that orders captures with identical stamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CoverageStamp {
    ticket: u64,
    generation: u64,
    epoch: u64,
}

impl CoverageStamp {
    /// Whether a capture stamped `self` may replace the published `current`.
    /// Both counters are monotonic, so a capture is newer only when neither
    /// counter moved backwards; equal counters are ordered by ticket. An
    /// incomparable capture (one counter ahead, the other behind) is not
    /// installed: it is not at least as fresh as what is published.
    fn supersedes(&self, current: &Self) -> bool {
        self.generation >= current.generation
            && self.epoch >= current.epoch
            && (self.generation > current.generation
                || self.epoch > current.epoch
                || self.ticket > current.ticket)
    }
}

struct GlobalCoverageInner {
    table: SharedRedactionTable,
    published: Mutex<CoverageStamp>,
    next_ticket: AtomicU64,
    /// `None` only for a fixed test table, which is always current.
    sources: Option<GlobalCoverageSources>,
}

/// The daemon-global redaction table and its publication state.
#[derive(Clone)]
pub struct GlobalCoverage {
    inner: Arc<GlobalCoverageInner>,
}

impl std::fmt::Debug for GlobalCoverage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GlobalCoverage")
            .finish_non_exhaustive()
    }
}

impl GlobalCoverage {
    /// Construct the daemon's publication state around the boot table.
    /// `generation`/`epoch` are the stamps that table was admitted under;
    /// `0`/`0` forces a republish on first use.
    pub(crate) fn new(
        table: Arc<RedactionTable>,
        generation: u64,
        epoch: u64,
        authority: crate::redact::coverage_authority::RedactionCoverageAuthority,
        config_source: crate::daemon::config_source::ConfigSource,
        vault: &Arc<crate::secure_key::SecretVault>,
        registry: crate::daemon::registry::WeakSessionRegistry,
    ) -> Self {
        Self {
            inner: Arc::new(GlobalCoverageInner {
                table: Arc::new(std::sync::RwLock::new(table)),
                published: Mutex::new(CoverageStamp {
                    ticket: 0,
                    generation,
                    epoch,
                }),
                next_ticket: AtomicU64::new(0),
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
                published: Mutex::new(CoverageStamp {
                    ticket: 0,
                    generation: 0,
                    epoch: 0,
                }),
                next_ticket: AtomicU64::new(0),
                sources: None,
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn published_generation_for_test(&self) -> u64 {
        self.inner
            .published
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .generation
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

    fn live_stamps(sources: &GlobalCoverageSources) -> Result<(u64, u64)> {
        let vault = sources
            .vault
            .upgrade()
            .context("daemon vault is no longer available")?;
        let generation = vault
            .current_inventory_generation()
            .context("reading daemon redaction source revision")?;
        Ok((generation, sources.authority.epoch()))
    }

    /// Whether the published table reflects the live vault generation *and*
    /// the live coverage-authority epoch.
    pub(crate) fn is_current(&self) -> bool {
        let Some(sources) = self.sources() else {
            return true;
        };
        let Ok((generation, epoch)) = Self::live_stamps(sources) else {
            return false;
        };
        let published = self
            .inner
            .published
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        published.generation == generation && published.epoch == epoch
    }

    /// Take a publication ticket and read the stamps a capture starting now
    /// is acquired under. The ticket is taken first so a later capture never
    /// holds an earlier ticket.
    fn begin(&self, sources: &GlobalCoverageSources) -> Result<CoverageStamp> {
        let ticket = self.inner.next_ticket.fetch_add(1, Ordering::SeqCst) + 1;
        let (generation, epoch) = Self::live_stamps(sources)?;
        Ok(CoverageStamp {
            ticket,
            generation,
            epoch,
        })
    }

    /// Publish `table` with `stamp` unless a newer capture is already
    /// published. Table and stamps change in one critical section. Returns
    /// the table that is published afterwards (this one, or the newer one).
    fn install(&self, stamp: CoverageStamp, table: Arc<RedactionTable>) -> Arc<RedactionTable> {
        let mut published = self
            .inner
            .published
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if stamp.supersedes(&published) {
            super::set_current_redaction(&self.inner.table, table.clone());
            *published = stamp;
            table
        } else {
            self.table()
        }
    }

    fn acquisition_inputs(
        &self,
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

    /// Acquire and publish a fresh table from a synchronous context.
    pub(crate) fn republish_blocking(&self, purpose: CoverageScope) -> Result<Arc<RedactionTable>> {
        let Some(sources) = self.sources() else {
            return Ok(self.table());
        };
        let stamp = self.begin(sources)?;
        let (vault, cache) = self.acquisition_inputs(sources)?;
        let table = crate::daemon::server::acquire_daemon_redaction_table_blocking(
            sources.authority.clone(),
            sources.config_source.clone(),
            vault,
            cache,
            purpose,
        )?;
        Ok(self.install(stamp, table))
    }

    /// Acquire and publish a fresh table.
    pub(crate) async fn republish(&self, purpose: CoverageScope) -> Result<Arc<RedactionTable>> {
        let Some(sources) = self.sources() else {
            return Ok(self.table());
        };
        let stamp = self.begin(sources)?;
        let (vault, cache) = self.acquisition_inputs(sources)?;
        let table = crate::daemon::server::acquire_daemon_redaction_table(
            sources.authority.clone(),
            &sources.config_source,
            &vault,
            &cache,
            purpose,
        )
        .await?;
        Ok(self.install(stamp, table))
    }

    /// The published table when current, otherwise a freshly republished one.
    pub(crate) fn current_or_republish_blocking(&self) -> Result<Arc<RedactionTable>> {
        if self.is_current() {
            return Ok(self.table());
        }
        self.republish_blocking(CoverageScope::DaemonGlobalEvent)
    }

    async fn current_or_republish(&self) -> Result<Arc<RedactionTable>> {
        if self.is_current() {
            return Ok(self.table());
        }
        self.republish(CoverageScope::DaemonGlobalEvent).await
    }

    /// The one delivery funnel for the daemon-global bus.
    ///
    /// `origin` is the table of the session the event originates in, if
    /// any; the event is then scrubbed with the current global table and
    /// that table matched together ([`EventScrub::with_origin`]). When
    /// current global coverage cannot be established, or the two tables
    /// cannot be combined, owners still receive the event and every other
    /// principal receives only its content-free form (or nothing).
    pub(crate) fn deliver(
        &self,
        tx: &EventSender,
        origin: Option<&Arc<RedactionTable>>,
        event: proto::Event,
    ) {
        let coverage = self.current_or_republish_blocking();
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
        send_with_coverage(tx, coverage, origin, event);
    }
}

fn send_with_coverage(
    tx: &EventSender,
    coverage: Result<Arc<RedactionTable>>,
    origin: Option<&Arc<RedactionTable>>,
    event: proto::Event,
) {
    let redact = coverage.and_then(|global| match origin {
        None => Ok(EventScrub::single(global)),
        Some(origin) => EventScrub::with_origin(&global, origin)
            .context("combining daemon-global and originating-session coverage"),
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
fn content_free_host_capability_snapshot(
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

    #[test]
    fn stamps_only_move_forward() {
        let stamp = |ticket, generation, epoch| CoverageStamp {
            ticket,
            generation,
            epoch,
        };
        let published = stamp(5, 10, 3);
        assert!(
            stamp(6, 10, 3).supersedes(&published),
            "same stamps, later ticket"
        );
        assert!(
            stamp(1, 11, 3).supersedes(&published),
            "newer generation wins over ticket"
        );
        assert!(
            stamp(1, 10, 4).supersedes(&published),
            "newer epoch wins over ticket"
        );
        assert!(
            !stamp(4, 10, 3).supersedes(&published),
            "earlier ticket, same stamps"
        );
        assert!(
            !stamp(9, 9, 3).supersedes(&published),
            "older generation never wins"
        );
        assert!(
            !stamp(9, 10, 2).supersedes(&published),
            "older epoch never wins"
        );
        assert!(
            !stamp(9, 11, 2).supersedes(&published),
            "incomparable stamps never win"
        );
    }

    /// A delayed capture that finishes after a newer one never replaces the
    /// newer table, and the published stamps stay with the published table.
    #[test]
    fn an_older_capture_never_overwrites_a_newer_publication() {
        let boot = Arc::new(RedactionTable::empty());
        let coverage = GlobalCoverage::fixed(boot);
        let newer = Arc::new(RedactionTable::empty());
        let older = Arc::new(RedactionTable::empty());
        let newer_stamp = CoverageStamp {
            ticket: 2,
            generation: 5,
            epoch: 2,
        };
        let older_stamp = CoverageStamp {
            ticket: 1,
            generation: 5,
            epoch: 1,
        };
        assert!(Arc::ptr_eq(
            &coverage.install(newer_stamp, newer.clone()),
            &newer
        ));
        let after = coverage.install(older_stamp, older.clone());
        assert!(Arc::ptr_eq(&after, &newer), "the older capture is dropped");
        assert!(Arc::ptr_eq(&coverage.table(), &newer));
        assert_eq!(
            *coverage.inner.published.lock().unwrap(),
            newer_stamp,
            "stamps describe the published table"
        );
    }
}
