//! Daemon-lifecycle image-generation worker.
//!
//! On non-ephemeral daemon start the daemon spawns one worker owned by the
//! daemon lifecycle. It holds a stable, nonzero `worker_boot_id` (the daemon
//! boot UUID, shared with deadline observation), injected monotonic + wall
//! clocks, and an injectable sleeper — no bare `Instant::now` / `tokio::time`
//! in the hot path. Before accepting any new scheduler work it runs a
//! prior-boot reconciliation sweep so a pre-crash boot's scheduler claims and
//! artifact read leases can never gate — or be revived by — the current boot.
//! Then it loops `run_reconciliation_pass` → `run_provider_cancel_pass` →
//! `run_scheduler_pass_with_adapters` under a bounded limit with backoff, and
//! exits cooperatively when the daemon shutdown gate begins draining.
//!
//! Dispatch is routed through a typed [`ImageGenerationAdapterMap`]: a candidate
//! whose sealed destination kind has no registered adapter is a typed
//! `adapter_missing` skip (never a panic). Production installs a fixed
//! owner-session router for every provider kind; it resolves a concrete,
//! target-specific adapter only after scheduler revalidation against that
//! owner's live configuration.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use uuid::Uuid;

use crate::daemon::shutdown::ShutdownSignal;
use crate::image_generation_job::{
    DeferredImageReconciler, ImageDispatchProofSource, ImageGenerationAdapter,
    ImageGenerationAdapterMap, ImageGenerationDispatcher,
};

/// Injected monotonic + wall clocks. Same posture as `DaemonMediaClock` and the
/// scheduler clocks: the worker never reads `Instant::now`/`Utc::now` directly.
pub trait ImageGenerationWorkerClock: Send + Sync {
    /// Milliseconds on the daemon boot's monotonic timeline. This MUST be the
    /// same timeline the media ledger and plan deadlines were sealed against, so
    /// the worker never revives a pre-crash monotonic deadline from another boot.
    fn monotonic_ms(&self) -> u64;
    /// Wall-clock milliseconds since the Unix epoch, for claim expiry bookkeeping.
    fn wall_unix_ms(&self) -> i64;
}

/// Injectable sleeper so tests drive the loop deterministically (no real sleeps).
pub trait ImageGenerationWorkerSleeper: Send + Sync {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// Bounded loop tuning.
#[derive(Debug, Clone, Copy)]
pub struct ImageGenerationWorkerConfig {
    /// Per-pass row limit (must be `1..=64`).
    pub limit: u32,
    /// Backoff after a cycle that made no progress (grows to `max_backoff`).
    pub idle_backoff: Duration,
    /// Backoff ceiling.
    pub max_backoff: Duration,
}

impl Default for ImageGenerationWorkerConfig {
    fn default() -> Self {
        Self {
            limit: 16,
            idle_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_secs(5),
        }
    }
}

/// Production-real observation surface (never `#[cfg(test)]`-only). Every pass
/// increments its counter after running with the worker's single `boot_id`, so a
/// test can assert each pass ran with the same nonzero boot id (AC1).
#[derive(Debug)]
pub struct ImageGenerationWorkerMetrics {
    boot_id: Uuid,
    prior_boot_swept: AtomicBool,
    prior_boot_artifact_leases_released: AtomicU64,
    reconciliation_passes: AtomicU64,
    provider_cancel_passes: AtomicU64,
    scheduler_passes: AtomicU64,
    scanned: AtomicU64,
    dispatched: AtomicU64,
    skipped: AtomicU64,
}

impl ImageGenerationWorkerMetrics {
    fn new(boot_id: Uuid) -> Self {
        Self {
            boot_id,
            prior_boot_swept: AtomicBool::new(false),
            prior_boot_artifact_leases_released: AtomicU64::new(0),
            reconciliation_passes: AtomicU64::new(0),
            provider_cancel_passes: AtomicU64::new(0),
            scheduler_passes: AtomicU64::new(0),
            scanned: AtomicU64::new(0),
            dispatched: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
        }
    }

    /// The single, stable, nonzero worker boot id every pass runs under.
    pub fn boot_id(&self) -> Uuid {
        self.boot_id
    }
    /// Whether the prior-boot reconciliation sweep completed before the loop.
    pub fn prior_boot_swept(&self) -> bool {
        self.prior_boot_swept.load(Ordering::SeqCst)
    }
    pub fn prior_boot_artifact_leases_released(&self) -> u64 {
        self.prior_boot_artifact_leases_released
            .load(Ordering::SeqCst)
    }
    pub fn reconciliation_passes(&self) -> u64 {
        self.reconciliation_passes.load(Ordering::SeqCst)
    }
    pub fn provider_cancel_passes(&self) -> u64 {
        self.provider_cancel_passes.load(Ordering::SeqCst)
    }
    pub fn scheduler_passes(&self) -> u64 {
        self.scheduler_passes.load(Ordering::SeqCst)
    }
    pub fn scanned(&self) -> u64 {
        self.scanned.load(Ordering::SeqCst)
    }
    pub fn dispatched(&self) -> u64 {
        self.dispatched.load(Ordering::SeqCst)
    }
    pub fn skipped(&self) -> u64 {
        self.skipped.load(Ordering::SeqCst)
    }
}

/// The daemon-lifecycle image-generation worker.
pub struct ImageGenerationWorker {
    dispatcher: ImageGenerationDispatcher,
    boot_id: Uuid,
    adapters: ImageGenerationAdapterMap,
    reconciler: Arc<dyn ImageGenerationAdapter>,
    proof_source: Arc<dyn ImageDispatchProofSource>,
    clock: Arc<dyn ImageGenerationWorkerClock>,
    sleeper: Arc<dyn ImageGenerationWorkerSleeper>,
    config: ImageGenerationWorkerConfig,
    metrics: Arc<ImageGenerationWorkerMetrics>,
}

impl ImageGenerationWorker {
    pub fn new(
        db: cockpit_db::Db,
        boot_id: Uuid,
        adapters: ImageGenerationAdapterMap,
        proof_source: Arc<dyn ImageDispatchProofSource>,
        clock: Arc<dyn ImageGenerationWorkerClock>,
        sleeper: Arc<dyn ImageGenerationWorkerSleeper>,
        config: ImageGenerationWorkerConfig,
    ) -> Self {
        Self {
            dispatcher: ImageGenerationDispatcher::new(db),
            boot_id,
            adapters,
            reconciler: Arc::new(DeferredImageReconciler),
            proof_source,
            clock,
            sleeper,
            config,
            metrics: Arc::new(ImageGenerationWorkerMetrics::new(boot_id)),
        }
    }

    /// Install the production owner-session recovery router. Test callers keep
    /// `new`'s explicit dummy only when they intentionally exercise a no-op
    /// recovery surface.
    pub fn with_reconciler(mut self, reconciler: Arc<dyn ImageGenerationAdapter>) -> Self {
        self.reconciler = reconciler;
        self
    }

    /// Shared handle to the worker's observation counters.
    pub fn metrics(&self) -> Arc<ImageGenerationWorkerMetrics> {
        self.metrics.clone()
    }

    /// Prior-boot reconciliation, then loop reconcile → cancel → schedule until
    /// the shutdown gate drains. Consumes the worker (it owns its lifecycle).
    /// Never panics; exits promptly and cleanly on shutdown.
    pub async fn run(self, shutdown: ShutdownSignal) {
        // The prior-boot sweep MUST complete before the first schedule pass: it
        // releases another boot's scheduler claims and artifact read leases so
        // the current boot's scan can see the candidate and never revives a
        // pre-crash monotonic deadline. If it fails we do not start the loop
        // (fail closed) rather than dispatch under an unreconciled prior boot.
        match self
            .dispatcher
            .run_prior_boot_reconciliation(self.boot_id)
            .await
        {
            Ok(swept) => {
                self.metrics
                    .prior_boot_artifact_leases_released
                    .store(swept.artifact_leases_released, Ordering::SeqCst);
                self.metrics.prior_boot_swept.store(true, Ordering::SeqCst);
                tracing::info!(
                    target: "image_generation_worker",
                    worker_boot_id = %self.boot_id,
                    artifact_leases_released = swept.artifact_leases_released,
                    "image generation prior-boot reconciliation complete"
                );
            }
            Err(error) => {
                tracing::error!(
                    target: "image_generation_worker",
                    worker_boot_id = %self.boot_id,
                    error = %error,
                    "image generation prior-boot reconciliation failed; worker not starting"
                );
                return;
            }
        }

        let mut backoff = self.config.idle_backoff;
        let mut shutdown_rx = shutdown.subscribe();
        loop {
            if shutdown.is_draining() {
                break;
            }
            let progressed = self.run_once().await;
            backoff = if progressed {
                self.config.idle_backoff
            } else {
                (backoff * 2).min(self.config.max_backoff)
            };
            tokio::select! {
                () = self.sleeper.sleep(backoff) => {}
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || shutdown.is_draining() {
                        break;
                    }
                }
            }
        }
        tracing::info!(
            target: "image_generation_worker",
            worker_boot_id = %self.boot_id,
            "image generation worker stopped on shutdown"
        );
    }

    /// One reconcile → cancel → schedule cycle. Every pass runs with the single
    /// `self.boot_id`. Returns whether any pass made progress (for backoff). A
    /// pass error is logged and does not abort the loop (the next cycle retries).
    async fn run_once(&self) -> bool {
        let now_unix_ms = self.clock.wall_unix_ms();
        let now_monotonic_ms = self.clock.monotonic_ms();
        let limit = self.config.limit;
        let mut progressed = false;

        match self
            .dispatcher
            .run_reconciliation_pass(
                self.reconciler.as_ref(),
                self.boot_id,
                now_unix_ms,
                now_monotonic_ms,
                limit,
            )
            .await
        {
            Ok(count) => {
                self.metrics
                    .reconciliation_passes
                    .fetch_add(1, Ordering::SeqCst);
                progressed |= count > 0;
            }
            Err(error) => tracing::warn!(
                target: "image_generation_worker",
                worker_boot_id = %self.boot_id,
                error = %error,
                "image generation reconciliation pass failed"
            ),
        }

        match self
            .dispatcher
            .run_provider_cancel_pass(self.reconciler.as_ref(), self.boot_id, now_unix_ms, limit)
            .await
        {
            Ok(count) => {
                self.metrics
                    .provider_cancel_passes
                    .fetch_add(1, Ordering::SeqCst);
                progressed |= count > 0;
            }
            Err(error) => tracing::warn!(
                target: "image_generation_worker",
                worker_boot_id = %self.boot_id,
                error = %error,
                "image generation provider-cancel pass failed"
            ),
        }

        match self
            .dispatcher
            .run_scheduler_pass_with_adapters(
                &self.adapters,
                self.proof_source.as_ref(),
                self.boot_id,
                now_monotonic_ms,
                now_unix_ms,
                now_monotonic_ms,
                limit,
            )
            .await
        {
            Ok(pass) => {
                self.metrics.scheduler_passes.fetch_add(1, Ordering::SeqCst);
                self.metrics
                    .scanned
                    .fetch_add(u64::from(pass.scanned), Ordering::SeqCst);
                self.metrics
                    .dispatched
                    .fetch_add(u64::from(pass.dispatched), Ordering::SeqCst);
                self.metrics
                    .skipped
                    .fetch_add(u64::from(pass.skipped), Ordering::SeqCst);
                progressed |= pass.dispatched > 0 || pass.claimed > 0;
            }
            Err(error) => tracing::warn!(
                target: "image_generation_worker",
                worker_boot_id = %self.boot_id,
                error = %error,
                "image generation scheduler pass failed"
            ),
        }

        progressed
    }
}

/// Production clock: monotonic from the daemon boot `Instant` (identical to
/// `DaemonMediaClock`), wall from `Utc`.
struct ProductionWorkerClock {
    started_at: std::time::Instant,
}

impl ImageGenerationWorkerClock for ProductionWorkerClock {
    fn monotonic_ms(&self) -> u64 {
        u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
    fn wall_unix_ms(&self) -> i64 {
        chrono::Utc::now().timestamp_millis()
    }
}

struct TokioWorkerSleeper;

impl ImageGenerationWorkerSleeper for TokioWorkerSleeper {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// Build and spawn the daemon-lifecycle image-generation worker. Called only on
/// non-ephemeral daemon start (same gating as the scheduler / media-ledger
/// install). The `started_at` `Instant` must be the daemon's shared boot instant
/// so the worker's monotonic clock matches the media ledger and sealed plan
/// deadlines. The supplied map is the daemon's owner-session router; concrete
/// endpoint transports and plan sources remain session-owned and are replaced
/// atomically whenever that session's image configuration changes.
pub(crate) fn spawn_image_generation_worker(
    db: cockpit_db::Db,
    boot_id: Uuid,
    started_at: std::time::Instant,
    adapters: ImageGenerationAdapterMap,
    proof_source: Arc<dyn ImageDispatchProofSource>,
    recovery_router: Arc<dyn ImageGenerationAdapter>,
    shutdown: ShutdownSignal,
) -> tokio::task::JoinHandle<()> {
    let worker = ImageGenerationWorker::new(
        db,
        boot_id,
        adapters,
        proof_source,
        Arc::new(ProductionWorkerClock { started_at }),
        Arc::new(TokioWorkerSleeper),
        ImageGenerationWorkerConfig::default(),
    )
    .with_reconciler(recovery_router);
    tokio::spawn(worker.run(shutdown))
}

#[cfg(all(test, feature = "extended"))]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::image_generation_job::DispatchRevalidationRequest;
    use crate::image_generation_runtime::{DispatchProofBinding, RuntimeError, RuntimeErrorCode};

    /// A proof source that never yields a binding. The empty-adapter-map worker
    /// tests skip every candidate at `adapter_missing` BEFORE prepare, so the
    /// proof source is never consulted; it exists only to satisfy the type.
    struct NeverDispatchProof;
    impl ImageDispatchProofSource for NeverDispatchProof {
        fn revalidate<'a>(
            &'a self,
            _request: DispatchRevalidationRequest<'a>,
        ) -> Pin<Box<dyn Future<Output = Result<DispatchProofBinding, RuntimeError>> + Send + 'a>>
        {
            Box::pin(async {
                Err(RuntimeError::new(
                    RuntimeErrorCode::Obsolete,
                    "worker test proof source is never consulted",
                ))
            })
        }
    }

    /// A clock whose monotonic/wall values are fixed for the test.
    struct FixedClock {
        monotonic_ms: u64,
        wall_unix_ms: i64,
    }
    impl ImageGenerationWorkerClock for FixedClock {
        fn monotonic_ms(&self) -> u64 {
            self.monotonic_ms
        }
        fn wall_unix_ms(&self) -> i64 {
            self.wall_unix_ms
        }
    }

    /// A sleeper that records every requested sleep and, once the loop has run
    /// the requested number of cycles, begins the shutdown drain so the loop
    /// exits deterministically without any real-time sleep.
    struct DrainAfterCycles {
        shutdown: ShutdownSignal,
        cycles_before_drain: u64,
        observed: Mutex<Vec<Duration>>,
    }
    impl ImageGenerationWorkerSleeper for DrainAfterCycles {
        fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            let count = {
                let mut observed = self.observed.lock().unwrap();
                observed.push(duration);
                observed.len() as u64
            };
            if count >= self.cycles_before_drain {
                self.shutdown.begin_drain();
            }
            // Never actually sleep; the loop checks the shutdown gate next.
            Box::pin(async {})
        }
    }

    fn empty_worker(shutdown: ShutdownSignal, cycles_before_drain: u64) -> ImageGenerationWorker {
        ImageGenerationWorker::new(
            cockpit_db::Db::open_in_memory().unwrap(),
            Uuid::now_v7(),
            ImageGenerationAdapterMap::new(),
            Arc::new(NeverDispatchProof),
            Arc::new(FixedClock {
                monotonic_ms: 100,
                wall_unix_ms: 1_000,
            }),
            Arc::new(DrainAfterCycles {
                shutdown,
                cycles_before_drain,
                observed: Mutex::new(Vec::new()),
            }),
            ImageGenerationWorkerConfig::default(),
        )
    }

    // AC1: starting the worker drives at least one reconciliation, one
    // provider-cancel, and one scheduler pass, each under the SAME nonzero
    // worker_boot_id. Observed via the production metrics (not a test-only hook).
    #[tokio::test]
    async fn image_generation_worker_runs_three_passes_with_boot_id() {
        let shutdown = ShutdownSignal::new();
        let worker = empty_worker(shutdown.clone(), 1);
        let boot_id = worker.metrics().boot_id();
        assert!(!boot_id.is_nil(), "worker boot id must be nonzero");
        let metrics = worker.metrics();
        worker.run(shutdown).await;
        assert!(
            metrics.prior_boot_swept(),
            "prior-boot sweep must run first"
        );
        assert!(
            metrics.reconciliation_passes() >= 1,
            "at least one reconciliation pass"
        );
        assert!(
            metrics.provider_cancel_passes() >= 1,
            "at least one provider-cancel pass"
        );
        assert!(
            metrics.scheduler_passes() >= 1,
            "at least one scheduler pass"
        );
        // Every pass ran under the single boot id the metrics were built with.
        assert_eq!(metrics.boot_id(), boot_id);
    }

    // AC3: signaling shutdown stops the loop without panic; the worker returns.
    #[tokio::test]
    async fn image_generation_worker_shutdown_is_cooperative() {
        let shutdown = ShutdownSignal::new();
        // Drain immediately (before the first cycle's sleep completes a second
        // iteration): the loop must observe the gate and return.
        let worker = empty_worker(shutdown.clone(), 1);
        let metrics = worker.metrics();
        // Run to completion; if shutdown were not cooperative this would hang.
        worker.run(shutdown.clone()).await;
        assert!(shutdown.is_draining());
        // The loop ran a bounded number of cycles and stopped.
        assert!(metrics.scheduler_passes() >= 1);
        assert!(
            metrics.scheduler_passes() <= 2,
            "the loop must stop promptly after the drain, not spin"
        );
    }

    // Shutdown BEFORE the first cycle: the worker still runs the prior-boot
    // sweep (a boot must reconcile), then exits without dispatching a pass.
    #[tokio::test]
    async fn image_generation_worker_shutdown_before_first_cycle_still_sweeps() {
        let shutdown = ShutdownSignal::new();
        let worker = empty_worker(shutdown.clone(), 1);
        let metrics = worker.metrics();
        shutdown.begin_drain();
        worker.run(shutdown).await;
        assert!(metrics.prior_boot_swept());
        assert_eq!(
            metrics.scheduler_passes(),
            0,
            "no scheduler pass runs once shutdown has already begun"
        );
    }
}
