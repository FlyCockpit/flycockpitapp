//! Integration tests for the single authorized invocation pipeline.
//!
//! Every test drives the real [`SidecarPipeline::invoke`] entry point with a
//! real [`SidecarResolver`] selection, a real [`DestinationGrantStore`], and —
//! for the reservation/SQLite proofs — the real
//! [`LedgerReservationAcquirer`] over an in-memory [`cockpit_db::Db`]. Provider
//! contact is observed through a call-counting spy transport so a denial can be
//! proven to make ZERO provider calls.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cockpit_db::Db;
use rusqlite::OptionalExtension;

use super::*;
use crate::config::config::media_budget::MediaResourcePolicy;
use crate::config::config::providers::{
    CapabilityStatus, ModelEntry, ModelLocation, ModelTrust, ProviderEntry, ProvidersConfig,
};
use crate::image_sidecar::dossier::{
    AskImageAnswer, AskImageAnswerProvenance, AskImageAttachmentKind, DossierCache,
    DossierProvenance, DurableImageRef, FakeDossierClock, ImageSidecarDossier,
    MultiImageDossierRequest, MultiImageEntry,
};
use crate::image_sidecar::{
    ApprovalMode, CAPABILITY_CONTRACT_REVISION, DestinationGrantStore, DestinationPolicy,
    DestinationTuple, EgressFields, GrantScope, HardGateFailureReason, MediaClass, ProjectIdentity,
    Purpose, PurposeBody, ReservationSettleError, SelectedSidecar, SidecarInvocationCap,
    SidecarInvocationCapProvenance, SidecarMode, SidecarProviderModel, SidecarResolver,
    SidecarSelectionConfig,
};
use crate::media_reservation::{MediaReservationLedger, MonotonicClock};

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

type OrderLog = Arc<Mutex<Vec<&'static str>>>;

struct ZeroClock;
impl MonotonicClock for ZeroClock {
    fn now_ms(&self) -> u64 {
        0
    }
}

/// A resolver that returns a fixed resolution and records ordering.
struct FakeResolver {
    resolved: ResolvedImageAttachment,
    log: OrderLog,
}

#[async_trait]
impl SidecarAttachmentResolver for FakeResolver {
    async fn resolve(
        &self,
        _attachment_id: &str,
        _session_id: &str,
    ) -> Result<ResolvedImageAttachment, SidecarInvokeError> {
        self.log.lock().unwrap().push("resolve");
        Ok(self.resolved.clone())
    }
}

/// A resolver that returns `first` on the first call and `rest` on every
/// subsequent call — used to fail `verify()` once, then succeed.
struct SwitchableResolver {
    first: Mutex<Option<ResolvedImageAttachment>>,
    rest: ResolvedImageAttachment,
}

impl SwitchableResolver {
    fn new(first: ResolvedImageAttachment, rest: ResolvedImageAttachment) -> Self {
        Self {
            first: Mutex::new(Some(first)),
            rest,
        }
    }
}

#[async_trait]
impl SidecarAttachmentResolver for SwitchableResolver {
    async fn resolve(
        &self,
        _attachment_id: &str,
        _session_id: &str,
    ) -> Result<ResolvedImageAttachment, SidecarInvokeError> {
        if let Some(first) = self.first.lock().unwrap().take() {
            Ok(first)
        } else {
            Ok(self.rest.clone())
        }
    }
}

/// Wraps any acquirer to count acquisitions/settlements and record ordering.
#[derive(Default)]
struct AcquirerCounts {
    reserves: AtomicUsize,
    settles: AtomicUsize,
}

struct RecordingAcquirer {
    inner: Arc<dyn ReservationAcquirer>,
    counts: Arc<AcquirerCounts>,
    log: OrderLog,
}

#[async_trait]
impl ReservationAcquirer for RecordingAcquirer {
    async fn acquire(&self, request: ReservationRequest) -> ReservationAcquisition {
        self.counts.reserves.fetch_add(1, Ordering::SeqCst);
        self.log.lock().unwrap().push("reserve");
        self.inner.acquire(request).await
    }
    async fn settle(&self, reservation_id: &str) -> Result<(), ReservationSettleError> {
        self.counts.settles.fetch_add(1, Ordering::SeqCst);
        self.log.lock().unwrap().push("settle");
        self.inner.settle(reservation_id).await
    }
}

/// An acquirer whose `settle` always FAILS, to prove the pipeline fails closed
/// (never reports a clean success) when terminalization cannot complete.
struct SettleFailAcquirer {
    inner: Arc<dyn ReservationAcquirer>,
}

#[async_trait]
impl ReservationAcquirer for SettleFailAcquirer {
    async fn acquire(&self, request: ReservationRequest) -> ReservationAcquisition {
        self.inner.acquire(request).await
    }
    async fn settle(&self, _reservation_id: &str) -> Result<(), ReservationSettleError> {
        Err(ReservationSettleError::new("settle forced failure"))
    }
}

/// A call-counting scripted transport. `dispatch` pops the next scripted
/// result; the call counter proves whether the provider was contacted.
struct SpyTransport {
    calls: Arc<AtomicUsize>,
    scripted: Mutex<VecDeque<Result<SidecarProviderResponse, SidecarInvokeError>>>,
    log: OrderLog,
}

impl SpyTransport {
    fn new(
        scripted: Vec<Result<SidecarProviderResponse, SidecarInvokeError>>,
        log: OrderLog,
    ) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            scripted: Mutex::new(scripted.into_iter().collect()),
            log,
        }
    }
}

#[async_trait]
impl SidecarProviderTransport for SpyTransport {
    async fn dispatch(
        &self,
        _request: &SidecarProviderRequest,
    ) -> Result<SidecarProviderResponse, SidecarInvokeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.log.lock().unwrap().push("dispatch");
        self.scripted
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(SidecarInvokeError::Transport {
                message: "no scripted response".into(),
                ambiguous_handoff: false,
            }))
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const BODY_MARKER: &str = "SIDECARBODYSECRETMARKERZZZ";

fn image_capable_model(id: &str) -> ModelEntry {
    let mut model = ModelEntry {
        id: id.to_string(),
        ..Default::default()
    };
    model.capabilities.image_input = CapabilityStatus::Supported;
    model
}

fn text_only_model(id: &str) -> ModelEntry {
    let mut model = ModelEntry {
        id: id.to_string(),
        ..Default::default()
    };
    model.capabilities.image_input = CapabilityStatus::Unsupported;
    model
}

/// Build a real `SelectedSidecar` via the real resolver (per-primary override
/// forces the image-capable sidecar candidate).
fn selected_sidecar() -> SelectedSidecar {
    let mut providers = ProvidersConfig::default();
    let mut primary = ProviderEntry {
        url: "https://primary.example/v1".to_string(),
        trust: Some(ModelTrust::Trusted),
        location: Some(ModelLocation::Local),
        credential_ref: Some("primary-cred".to_string()),
        ..Default::default()
    };
    primary.models.push(text_only_model("pmodel"));
    let mut vision = ProviderEntry {
        url: "https://vision.example/v1".to_string(),
        trust: Some(ModelTrust::Untrusted),
        location: Some(ModelLocation::Remote),
        credential_ref: Some("vision-cred".to_string()),
        ..Default::default()
    };
    vision.models.push(image_capable_model("vmodel"));
    providers.providers.insert("primary".to_string(), primary);
    providers.providers.insert("vision".to_string(), vision);

    let config = SidecarSelectionConfig {
        mode: SidecarMode::Always,
        per_primary_override: Some(SidecarProviderModel {
            provider: "vision".to_string(),
            model: "vmodel".to_string(),
        }),
        ..Default::default()
    };
    let policy = MediaResourcePolicy::default();
    let resolver = SidecarResolver::new(&providers, &policy, &config, 7);
    let resolution = resolver.resolve("primary", "pmodel", false);
    resolution
        .selected
        .expect("resolver selects the image-capable override sidecar")
}

fn tuple_for(selected: &SelectedSidecar, purpose: Purpose) -> DestinationTuple {
    DestinationTuple {
        provider: selected.provider.clone(),
        model: selected.model.clone(),
        endpoint_origin: selected.endpoint_origin.clone(),
        connected_location: selected.location,
        credential_fingerprint: selected.credential_fingerprint.clone(),
        project_identity: ProjectIdentity::default(),
        destination_policy_digest: selected.destination_policy_digest.clone(),
        media_class: MediaClass::Image,
        purpose,
    }
}

fn durable_resolved() -> ResolvedImageAttachment {
    ResolvedImageAttachment {
        durable: DurableImageRef {
            attachment_id: "att-1".to_string(),
            session_id: "s1".to_string(),
            checksum_hex: "deadbeef".to_string(),
            quarantined: false,
            over_limit: false,
            expired: false,
        },
        kind: AskImageAttachmentKind::Durable,
        image_artifact_id: "art-1".to_string(),
        source_width_px: 100,
        source_height_px: 100,
    }
}

fn invoke_ctx(selected: SelectedSidecar, invocation_id: &str) -> SidecarInvokeContext {
    SidecarInvokeContext {
        selected,
        attachment_id: "att-1".to_string(),
        session_id: "s1".to_string(),
        project: None,
        approval_mode: ApprovalMode::Ask,
        scope: GrantScope::Session,
        session_authorized: true,
        invocation_id: invocation_id.to_string(),
        parent_operation: "op-1".to_string(),
        source_order: 0,
        reservation_cap: SidecarInvocationCap {
            value: 16,
            provenance: SidecarInvocationCapProvenance::Configured,
        },
        provider_concurrency_max: 4,
        current_provider_concurrency: 0,
        current_session_usage: 0,
    }
}

fn valid_dossier(marker: &str) -> ImageSidecarDossier {
    ImageSidecarDossier {
        schema_version: 1,
        summary: format!("A screenshot. {marker}"),
        ocr_regions: vec![],
        layout_regions: vec![],
        facts: vec![],
        uncertainty: vec![],
        recreation_guidance: String::new(),
        ui_elements: vec![],
        provenance: DossierProvenance {
            source_width_px: 100,
            source_height_px: 100,
            source_order: 0,
            attachment_checksum_hex: "deadbeef".to_string(),
            schema_version: 1,
            sidecar_provider: "vision".to_string(),
            sidecar_model: "vmodel".to_string(),
            config_generation: 7,
            created_at_ms: 0,
        },
    }
}

fn dossier_response(marker: &str) -> SidecarProviderResponse {
    SidecarProviderResponse {
        output_text: serde_json::to_string(&valid_dossier(marker)).unwrap(),
    }
}

fn ask_image_answer(answer: &str) -> AskImageAnswer {
    AskImageAnswer {
        answer: answer.to_string(),
        provenance: AskImageAnswerProvenance {
            sidecar_provider: "vision".to_string(),
            sidecar_model: "vmodel".to_string(),
            attachment_checksum_hex: "deadbeef".to_string(),
            created_at_ms: 0,
            status_note: None,
        },
        uncertainty: vec![],
    }
}

fn ask_image_response(answer: &str) -> SidecarProviderResponse {
    SidecarProviderResponse {
        output_text: serde_json::to_string(&ask_image_answer(answer)).unwrap(),
    }
}

fn cache() -> Arc<DossierCache> {
    Arc::new(DossierCache::new())
}

/// Dump every cell of every table in the DB into one string so a test can scan
/// SQLite content for a planted dossier-body marker.
async fn dump_all_sqlite(db: &Db) -> String {
    db.read(|conn| {
        use rusqlite::types::ValueRef;
        let mut out = String::new();
        let names: Vec<String> = {
            let mut stmt = conn.prepare("SELECT name FROM sqlite_master WHERE type='table'")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for table in names {
            let mut stmt = conn.prepare(&format!("SELECT * FROM \"{table}\""))?;
            let ncol = stmt.column_count();
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                for i in 0..ncol {
                    match row.get_ref(i)? {
                        ValueRef::Null => {}
                        ValueRef::Integer(v) => out.push_str(&v.to_string()),
                        ValueRef::Real(v) => out.push_str(&v.to_string()),
                        ValueRef::Text(v) => out.push_str(&String::from_utf8_lossy(v)),
                        ValueRef::Blob(v) => out.push_str(&String::from_utf8_lossy(v)),
                    }
                    out.push('\u{1}');
                }
            }
        }
        Ok(out)
    })
    .await
    .unwrap()
}

// ===========================================================================
// AC1 — denial blocks provider contact (zero provider calls)
// ===========================================================================

#[tokio::test]
async fn sidecar_pipeline_denial_blocks_provider() {
    let selected = selected_sidecar();
    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    let counts = Arc::new(AcquirerCounts::default());

    // No grant recorded -> egress denies in Ask mode.
    let grants = Arc::new(DestinationGrantStore::new());
    let acquirer = Arc::new(RecordingAcquirer {
        inner: Arc::new(crate::image_sidecar::FakeReservationAcquirer::new(4)),
        counts: counts.clone(),
        log: log.clone(),
    });
    let transport = Arc::new(SpyTransport::new(
        vec![Ok(dossier_response("x"))],
        log.clone(),
    ));
    let calls = transport.calls.clone();
    let pipeline = SidecarPipeline::new(
        grants,
        cache(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved: durable_resolved(),
            log: log.clone(),
        }),
        acquirer,
        transport,
    );

    let err = pipeline
        .invoke(&PurposeBody::dossier(), &invoke_ctx(selected, "inv-1"))
        .await
        .unwrap_err();

    assert_eq!(err, SidecarInvokeError::EgressNotAuthorized);
    // Egress precedes reservation and dispatch: neither was reached.
    assert_eq!(
        counts.reserves.load(Ordering::SeqCst),
        0,
        "no reservation on denial"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "zero provider calls on denial"
    );
}

#[tokio::test]
async fn sidecar_pipeline_reservation_denial_blocks_provider() {
    let selected = selected_sidecar();
    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));

    // Grant present so egress passes, but the reservation is refused
    // (cap already exhausted) -> still zero provider calls.
    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Session,
            tuple_for(&selected, Purpose::Dossier),
            Some("s1"),
            None,
            0,
        )
        .unwrap();

    let transport = Arc::new(SpyTransport::new(
        vec![Ok(dossier_response("x"))],
        log.clone(),
    ));
    let calls = transport.calls.clone();
    let pipeline = SidecarPipeline::new(
        grants,
        cache(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved: durable_resolved(),
            log: log.clone(),
        }),
        Arc::new(crate::image_sidecar::FakeReservationAcquirer::new(4)),
        transport,
    );

    // current_session_usage >= cap -> the fake acquirer rolls back.
    let mut ctx = invoke_ctx(selected, "inv-1");
    ctx.current_session_usage = 16;

    let err = pipeline
        .invoke(&PurposeBody::dossier(), &ctx)
        .await
        .unwrap_err();
    assert_eq!(
        err,
        SidecarInvokeError::ReservationFailed(
            crate::image_sidecar::ReservationFailureReason::CapExhausted
        )
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "zero provider calls on reservation denial"
    );
}

// ===========================================================================
// AC2 — happy path: resolve -> egress -> reserve -> dispatch, real reservation
// ===========================================================================

#[tokio::test]
async fn sidecar_pipeline_happy_path_uses_resolver_and_egress() {
    let selected = selected_sidecar();
    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    let counts = Arc::new(AcquirerCounts::default());

    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Session,
            tuple_for(&selected, Purpose::Dossier),
            Some("s1"),
            None,
            0,
        )
        .unwrap();

    // Real ledger over an in-memory DB -> a real reservation row.
    let db = Db::open_in_memory().unwrap();
    let ledger = MediaReservationLedger::new(db.clone(), Arc::new(ZeroClock));
    let real_acquirer = LedgerReservationAcquirer::new(
        ledger,
        MediaResourcePolicy::default(),
        "project-hash".to_string(),
    );
    let acquirer = Arc::new(RecordingAcquirer {
        inner: Arc::new(real_acquirer),
        counts: counts.clone(),
        log: log.clone(),
    });

    let transport = Arc::new(SpyTransport::new(
        vec![Ok(dossier_response("ok"))],
        log.clone(),
    ));
    let calls = transport.calls.clone();
    let dossier_cache = cache();
    let pipeline = SidecarPipeline::new(
        grants,
        dossier_cache.clone(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved: durable_resolved(),
            log: log.clone(),
        }),
        acquirer,
        transport,
    );

    // Session lifecycle is host-owned; the host starts the session.
    dossier_cache.session_start("s1");

    let outcome = pipeline
        .invoke(
            &PurposeBody::dossier(),
            &invoke_ctx(selected.clone(), "inv-1"),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, SidecarInvokeOutcome::Dossier(_)));

    // Spies prove the exact order: resolve -> reserve -> dispatch, then terminal
    // settle (egress runs between resolve and reserve; see the denial test that
    // egress gates both).
    assert_eq!(
        *log.lock().unwrap(),
        vec!["resolve", "reserve", "dispatch", "settle"]
    );
    assert_eq!(counts.reserves.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Exactly one real reservation row exists (under a FRESH pipeline-generated
    // id derived from the base "inv-1") and, after a successful handoff, is
    // SETTLED terminally (not left `reserved_queued`) — no leaked row.
    let (count, state) = db
        .read(|conn| {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM media_reservations WHERE reservation_id LIKE 'inv-1#%'",
                [],
                |r| r.get(0),
            )?;
            let state: Option<String> = conn
                .query_row(
                    "SELECT state FROM media_reservations WHERE reservation_id LIKE 'inv-1#%'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            Ok((count, state))
        })
        .await
        .unwrap();
    assert_eq!(count, 1, "exactly one fresh reservation row present");
    assert_eq!(
        state.as_deref(),
        Some("released"),
        "reservation settled terminally, not leaked as reserved_queued"
    );

    // Selection identity + config generation are recorded on the selection.
    assert_eq!(selected.config_generation, 7);
    // The validated dossier was cached memory-only.
    assert_eq!(dossier_cache.len(), 1);
}

// ===========================================================================
// AC4 — transient + wrong-session rejected with zero provider calls
// ===========================================================================

#[tokio::test]
async fn ask_image_rejects_transient_and_wrong_session() {
    let selected = selected_sidecar();

    // (a) Transient frame -> TransientNotAllowed before any provider contact.
    {
        let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
        let grants = Arc::new(DestinationGrantStore::new());
        grants
            .record(
                GrantScope::Session,
                tuple_for(&selected, Purpose::AskImage),
                Some("s1"),
                None,
                0,
            )
            .unwrap();
        let mut resolved = durable_resolved();
        resolved.kind = AskImageAttachmentKind::Transient;
        let transport = Arc::new(SpyTransport::new(
            vec![Ok(ask_image_response("hi"))],
            log.clone(),
        ));
        let calls = transport.calls.clone();
        let pipeline = SidecarPipeline::new(
            grants,
            cache(),
            Arc::new(FakeDossierClock::new(0)),
            Arc::new(FakeResolver {
                resolved,
                log: log.clone(),
            }),
            Arc::new(crate::image_sidecar::FakeReservationAcquirer::new(4)),
            transport,
        );
        let err = pipeline
            .invoke(
                &PurposeBody::ask_image("what is this?").unwrap(),
                &invoke_ctx(selected.clone(), "inv-t"),
            )
            .await
            .unwrap_err();
        assert_eq!(err, SidecarInvokeError::TransientNotAllowed);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    // (b) Wrong-session durable attachment -> AttachmentRejected(WrongSession).
    {
        let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
        let grants = Arc::new(DestinationGrantStore::new());
        grants
            .record(
                GrantScope::Session,
                tuple_for(&selected, Purpose::AskImage),
                Some("s1"),
                None,
                0,
            )
            .unwrap();
        let mut resolved = durable_resolved();
        resolved.durable.session_id = "other-session".to_string();
        let transport = Arc::new(SpyTransport::new(
            vec![Ok(ask_image_response("hi"))],
            log.clone(),
        ));
        let calls = transport.calls.clone();
        let pipeline = SidecarPipeline::new(
            grants,
            cache(),
            Arc::new(FakeDossierClock::new(0)),
            Arc::new(FakeResolver {
                resolved,
                log: log.clone(),
            }),
            Arc::new(crate::image_sidecar::FakeReservationAcquirer::new(4)),
            transport,
        );
        let err = pipeline
            .invoke(
                &PurposeBody::ask_image("what is this?").unwrap(),
                &invoke_ctx(selected.clone(), "inv-w"),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, SidecarInvokeError::AttachmentRejected(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

// ===========================================================================
// AC3 (pipeline half) — ask_image goes through the SAME pipeline and returns a
// sanitized answer that is NOT cached as a dossier.
// ===========================================================================

#[tokio::test]
async fn ask_image_answer_not_cached_as_dossier() {
    let selected = selected_sidecar();
    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Session,
            tuple_for(&selected, Purpose::AskImage),
            Some("s1"),
            None,
            0,
        )
        .unwrap();
    let dossier_cache = cache();
    let transport = Arc::new(SpyTransport::new(
        vec![Ok(ask_image_response("It is a login screen."))],
        log.clone(),
    ));
    let pipeline = SidecarPipeline::new(
        grants,
        dossier_cache.clone(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved: durable_resolved(),
            log: log.clone(),
        }),
        Arc::new(crate::image_sidecar::FakeReservationAcquirer::new(4)),
        transport,
    );

    let outcome = pipeline
        .invoke(
            &PurposeBody::ask_image("what is this?").unwrap(),
            &invoke_ctx(selected, "inv-a"),
        )
        .await
        .unwrap();
    match outcome {
        SidecarInvokeOutcome::AskImage(answer) => {
            assert_eq!(answer.answer, "It is a login screen.");
        }
        other => panic!("expected ask-image answer, got {other:?}"),
    }
    // ask_image answers are ordinary tool results; the dossier cache stays empty.
    assert_eq!(dossier_cache.len(), 0);
}

// ===========================================================================
// AC5 — dossier body never persisted to SQLite (real Db)
// ===========================================================================

#[tokio::test]
async fn dossier_body_never_persisted_to_sqlite() {
    let selected = selected_sidecar();
    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Session,
            tuple_for(&selected, Purpose::Dossier),
            Some("s1"),
            None,
            0,
        )
        .unwrap();

    let db = Db::open_in_memory().unwrap();
    let ledger = MediaReservationLedger::new(db.clone(), Arc::new(ZeroClock));
    let acquirer = Arc::new(LedgerReservationAcquirer::new(
        ledger,
        MediaResourcePolicy::default(),
        "project-hash".to_string(),
    ));

    let dossier_cache = cache();
    let transport = Arc::new(SpyTransport::new(
        vec![Ok(dossier_response(BODY_MARKER))],
        log.clone(),
    ));
    let pipeline = SidecarPipeline::new(
        grants,
        dossier_cache.clone(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved: durable_resolved(),
            log: log.clone(),
        }),
        acquirer,
        transport,
    );

    dossier_cache.session_start("s1");

    let outcome = pipeline
        .invoke(&PurposeBody::dossier(), &invoke_ctx(selected, "inv-db"))
        .await
        .unwrap();

    // Precondition: the processed dossier really carried the secret marker.
    match &outcome {
        SidecarInvokeOutcome::Dossier(d) => assert!(d.summary.contains(BODY_MARKER)),
        other => panic!("expected dossier, got {other:?}"),
    }

    let dump = dump_all_sqlite(&db).await;
    // The reservation metadata row IS written (proves the pipeline touched
    // SQLite) but the dossier body is NOT.
    assert!(
        dump.contains("inv-db"),
        "reservation metadata row present in SQLite"
    );
    assert!(
        !dump.contains(BODY_MARKER),
        "dossier body must never reach SQLite"
    );
    // The body lives only in the memory-only cache.
    assert_eq!(dossier_cache.len(), 1);
}

// ===========================================================================
// AC6 — production composition uses the real ledger acquirer, never the fake
// ===========================================================================

#[tokio::test]
async fn fake_reservation_not_used_in_production_composition() {
    // The production acquirer is constructed from the real ledger; it produces
    // a durable reservation row. `FakeReservationAcquirer` is `#[cfg(test)]`
    // and therefore cannot appear in any production composition.
    let db = Db::open_in_memory().unwrap();
    let ledger = MediaReservationLedger::new(db.clone(), Arc::new(ZeroClock));
    let acquirer = LedgerReservationAcquirer::new(
        ledger,
        MediaResourcePolicy::default(),
        "project-hash".to_string(),
    );
    let acq = acquirer
        .acquire(ReservationRequest {
            invocation_id: "prod-1".to_string(),
            session_id: "s1".to_string(),
            sidecar_invocation_cap: SidecarInvocationCap {
                value: 16,
                provenance: SidecarInvocationCapProvenance::Configured,
            },
            current_session_usage: 0,
            provider_concurrency_max: 4,
            current_provider_concurrency: 0,
        })
        .await;
    match acq {
        ReservationAcquisition::Committed {
            media_reservation_id,
            ..
        } => assert_eq!(media_reservation_id, "prod-1"),
        other => panic!("expected committed reservation, got {other:?}"),
    }
    let present = db
        .read(|conn| {
            Ok(conn
                .query_row(
                    "SELECT 1 FROM media_reservations WHERE reservation_id=?1",
                    rusqlite::params!["prod-1"],
                    |_| Ok(()),
                )
                .optional()?
                .is_some())
        })
        .await
        .unwrap();
    assert!(present, "real ledger row created by production acquirer");
}

// ===========================================================================
// AC7 — multi-image issues N independent invocations; repair is capped at one
// ===========================================================================

#[tokio::test]
async fn multi_image_issues_independent_invocations() {
    let selected = selected_sidecar();
    let plan = MultiImageDossierRequest {
        session_id: "s1".to_string(),
        images: vec![
            MultiImageEntry {
                attachment_id: "att-1".to_string(),
                attachment_checksum_hex: "deadbeef".to_string(),
                crop_identity: None,
                order: 0,
            },
            MultiImageEntry {
                attachment_id: "att-2".to_string(),
                attachment_checksum_hex: "deadbeef".to_string(),
                crop_identity: None,
                order: 1,
            },
        ],
    }
    .plan();
    assert_eq!(plan.invocations.len(), 2);

    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    let counts = Arc::new(AcquirerCounts::default());
    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Session,
            tuple_for(&selected, Purpose::Dossier),
            Some("s1"),
            None,
            0,
        )
        .unwrap();
    let transport = Arc::new(SpyTransport::new(
        vec![Ok(dossier_response("a")), Ok(dossier_response("b"))],
        log.clone(),
    ));
    let calls = transport.calls.clone();
    let acquirer = Arc::new(RecordingAcquirer {
        inner: Arc::new(crate::image_sidecar::FakeReservationAcquirer::new(8)),
        counts: counts.clone(),
        log: log.clone(),
    });
    let pipeline = SidecarPipeline::new(
        grants,
        cache(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved: durable_resolved(),
            log: log.clone(),
        }),
        acquirer,
        transport,
    );

    // One independent full-pipeline invocation per planned image, in order.
    for (idx, inv) in plan.invocations.iter().enumerate() {
        assert!(inv.single_image);
        let outcome = pipeline
            .invoke(
                &PurposeBody::dossier(),
                &invoke_ctx(selected.clone(), &format!("inv-{idx}")),
            )
            .await
            .unwrap();
        assert!(matches!(outcome, SidecarInvokeOutcome::Dossier(_)));
    }
    // N reservations and N dispatches — each image went through the full path.
    assert_eq!(counts.reserves.load(Ordering::SeqCst), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn repair_reauthorizes_reserves_and_is_capped_at_one() {
    let selected = selected_sidecar();
    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    let counts = Arc::new(AcquirerCounts::default());
    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Session,
            tuple_for(&selected, Purpose::Dossier),
            Some("s1"),
            None,
            0,
        )
        .unwrap();

    // First response is invalid JSON -> triggers exactly one repair; the second
    // response is a valid dossier.
    let transport = Arc::new(SpyTransport::new(
        vec![
            Ok(SidecarProviderResponse {
                output_text: "not a dossier".to_string(),
            }),
            Ok(dossier_response("repaired")),
        ],
        log.clone(),
    ));
    let calls = transport.calls.clone();
    let acquirer = Arc::new(RecordingAcquirer {
        inner: Arc::new(crate::image_sidecar::FakeReservationAcquirer::new(8)),
        counts: counts.clone(),
        log: log.clone(),
    });
    let pipeline = SidecarPipeline::new(
        grants,
        cache(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved: durable_resolved(),
            log: log.clone(),
        }),
        acquirer,
        transport,
    );

    let outcome = pipeline
        .invoke(&PurposeBody::dossier(), &invoke_ctx(selected, "inv-r"))
        .await
        .unwrap();
    assert!(matches!(outcome, SidecarInvokeOutcome::Dossier(_)));
    // The repair independently re-authorized + re-reserved and dispatched once
    // more: two reservations, two provider calls.
    assert_eq!(
        counts.reserves.load(Ordering::SeqCst),
        2,
        "repair re-reserves once"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "repair dispatches once more"
    );
}

#[tokio::test]
async fn repair_second_invalid_output_fails_closed() {
    let selected = selected_sidecar();
    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Session,
            tuple_for(&selected, Purpose::Dossier),
            Some("s1"),
            None,
            0,
        )
        .unwrap();
    // Both responses invalid -> repair runs once, still invalid -> InvalidOutput.
    let transport = Arc::new(SpyTransport::new(
        vec![
            Ok(SidecarProviderResponse {
                output_text: "bad-1".to_string(),
            }),
            Ok(SidecarProviderResponse {
                output_text: "bad-2".to_string(),
            }),
        ],
        log.clone(),
    ));
    let calls = transport.calls.clone();
    let pipeline = SidecarPipeline::new(
        grants,
        cache(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved: durable_resolved(),
            log: log.clone(),
        }),
        Arc::new(crate::image_sidecar::FakeReservationAcquirer::new(8)),
        transport,
    );
    let err = pipeline
        .invoke(&PurposeBody::dossier(), &invoke_ctx(selected, "inv-r2"))
        .await
        .unwrap_err();
    assert_eq!(err, SidecarInvokeError::InvalidOutput);
    // Exactly one repair attempt: two dispatches total, no third.
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

// ===========================================================================
// HIGH #1 — a forged/mismatched destination binding is rejected before egress
// ===========================================================================

#[tokio::test]
async fn forged_destination_binding_is_rejected() {
    // A legitimate selection, then tamper with its provider while keeping the
    // carried (approved) digest. The pipeline recomputes the digest from the
    // ACTUAL provider/model and must reject the mismatch with zero provider
    // contact — even though a grant exists for the carried digest.
    let mut selected = selected_sidecar();
    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Session,
            tuple_for(&selected, Purpose::Dossier),
            Some("s1"),
            None,
            0,
        )
        .unwrap();

    // Tamper: keep the carried digest, change the destination provider.
    selected.provider = "attacker-provider".to_string();

    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    let transport = Arc::new(SpyTransport::new(
        vec![Ok(dossier_response("x"))],
        log.clone(),
    ));
    let calls = transport.calls.clone();
    let pipeline = SidecarPipeline::new(
        grants,
        cache(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved: durable_resolved(),
            log: log.clone(),
        }),
        Arc::new(crate::image_sidecar::FakeReservationAcquirer::new(4)),
        transport,
    );

    let err = pipeline
        .invoke(&PurposeBody::dossier(), &invoke_ctx(selected, "inv-forge"))
        .await
        .unwrap_err();
    assert_eq!(err, SidecarInvokeError::DestinationBindingMismatch);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "forged binding makes zero provider calls"
    );
}

// ===========================================================================
// HIGH #2 — a `Once` grant authorizes exactly one invocation
// ===========================================================================

#[tokio::test]
async fn once_grant_authorizes_exactly_one_invocation() {
    let selected = selected_sidecar();
    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Once,
            tuple_for(&selected, Purpose::Dossier),
            None,
            None,
            0,
        )
        .unwrap();

    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    let transport = Arc::new(SpyTransport::new(
        vec![
            Ok(dossier_response("first")),
            Ok(dossier_response("second")),
        ],
        log.clone(),
    ));
    let calls = transport.calls.clone();
    let pipeline = SidecarPipeline::new(
        grants,
        cache(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved: durable_resolved(),
            log: log.clone(),
        }),
        Arc::new(crate::image_sidecar::FakeReservationAcquirer::new(8)),
        transport,
    );

    let mut ctx = invoke_ctx(selected, "inv-once-1");
    ctx.scope = GrantScope::Once;

    // First invocation consumes the Once grant.
    let first = pipeline
        .invoke(&PurposeBody::dossier(), &ctx)
        .await
        .unwrap();
    assert!(matches!(first, SidecarInvokeOutcome::Dossier(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Second invocation with the same (now consumed) grant fails closed and
    // makes no further provider call.
    let mut ctx2 = ctx.clone();
    ctx2.invocation_id = "inv-once-2".to_string();
    let err = pipeline
        .invoke(&PurposeBody::dossier(), &ctx2)
        .await
        .unwrap_err();
    assert_eq!(
        err,
        SidecarInvokeError::EgressDenied(HardGateFailureReason::DestinationDenied)
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "consumed Once grant makes zero further provider calls"
    );
}

// ===========================================================================
// HIGH #3 / MEDIUM #3 — every terminal outcome settles (releases) the
// reservation; no `reserved_queued` row ever leaks on success OR failure.
// ===========================================================================

#[tokio::test]
async fn dispatch_failure_settles_reservation_no_leak() {
    let selected = selected_sidecar();
    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Session,
            tuple_for(&selected, Purpose::Dossier),
            Some("s1"),
            None,
            0,
        )
        .unwrap();

    let db = Db::open_in_memory().unwrap();
    let ledger = MediaReservationLedger::new(db.clone(), Arc::new(ZeroClock));
    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    let counts = Arc::new(AcquirerCounts::default());
    let acquirer = Arc::new(RecordingAcquirer {
        inner: Arc::new(LedgerReservationAcquirer::new(
            ledger,
            MediaResourcePolicy::default(),
            "project-hash".to_string(),
        )),
        counts: counts.clone(),
        log: log.clone(),
    });

    // A transport error (the ambiguous flag is carried but not acted on in this
    // tree — every transport error settles the same safe way).
    let transport = Arc::new(SpyTransport::new(
        vec![Err(SidecarInvokeError::Transport {
            message: "connection refused".into(),
            ambiguous_handoff: false,
        })],
        log.clone(),
    ));
    let pipeline = SidecarPipeline::new(
        grants,
        cache(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved: durable_resolved(),
            log: log.clone(),
        }),
        acquirer,
        transport,
    );

    let err = pipeline
        .invoke(&PurposeBody::dossier(), &invoke_ctx(selected, "inv-fail"))
        .await
        .unwrap_err();
    assert!(matches!(err, SidecarInvokeError::Transport { .. }));

    // Settled exactly once on failure, and the row is terminal (released).
    assert_eq!(
        counts.settles.load(Ordering::SeqCst),
        1,
        "settle on failure"
    );
    let state = db
        .read(|conn| {
            Ok(conn
                .query_row(
                    "SELECT state FROM media_reservations WHERE reservation_id LIKE 'inv-fail#%'",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .optional()?)
        })
        .await
        .unwrap();
    assert_eq!(
        state.as_deref(),
        Some("released"),
        "no leaked reserved_queued row on failure"
    );
}

// ===========================================================================
// HIGH #3 — a settlement failure fails closed (no clean success over a leak)
// ===========================================================================

#[tokio::test]
async fn settle_failure_fails_closed() {
    let selected = selected_sidecar();
    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Session,
            tuple_for(&selected, Purpose::Dossier),
            Some("s1"),
            None,
            0,
        )
        .unwrap();

    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    // A well-formed successful dossier, but settlement always fails.
    let acquirer = Arc::new(SettleFailAcquirer {
        inner: Arc::new(crate::image_sidecar::FakeReservationAcquirer::new(4)),
    });
    let dossier_cache = cache();
    let pipeline = SidecarPipeline::new(
        grants,
        dossier_cache.clone(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved: durable_resolved(),
            log: log.clone(),
        }),
        acquirer,
        Arc::new(SpyTransport::new(
            vec![Ok(dossier_response("ok"))],
            log.clone(),
        )),
    );
    dossier_cache.session_start("s1");

    // Despite a valid dossier, the pipeline fails closed because the reservation
    // could not be terminally settled (a leak would otherwise be reported as a
    // clean success).
    let err = pipeline
        .invoke(
            &PurposeBody::dossier(),
            &invoke_ctx(selected, "inv-settlefail"),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SidecarInvokeError::ReservationNotSettled(_)));
}

// ===========================================================================
// MEDIUM #1 — provider-supplied dossier provenance is overwritten by the host
// ===========================================================================

#[tokio::test]
async fn provider_provenance_overwritten_by_host() {
    let selected = selected_sidecar();
    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Session,
            tuple_for(&selected, Purpose::Dossier),
            Some("s1"),
            None,
            0,
        )
        .unwrap();

    // Attacker smuggles text into provenance identity strings AND lies about
    // every numeric dimension/order/schema field.
    let mut dossier = valid_dossier("clean");
    dossier.provenance.sidecar_provider = "EVIL_SMUGGLED_PROVIDER".to_string();
    dossier.provenance.sidecar_model = "EVIL_SMUGGLED_MODEL".to_string();
    dossier.provenance.attachment_checksum_hex = "EVIL_CHECKSUM".to_string();
    dossier.provenance.source_width_px = 9999;
    dossier.provenance.source_height_px = 8888;
    dossier.provenance.source_order = 77;
    dossier.provenance.schema_version = 9;
    let response = SidecarProviderResponse {
        output_text: serde_json::to_string(&dossier).unwrap(),
    };

    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    let dossier_cache = cache();
    let pipeline = SidecarPipeline::new(
        grants,
        dossier_cache.clone(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved: durable_resolved(),
            log: log.clone(),
        }),
        Arc::new(crate::image_sidecar::FakeReservationAcquirer::new(4)),
        Arc::new(SpyTransport::new(vec![Ok(response)], log.clone())),
    );
    dossier_cache.session_start("s1");

    let outcome = pipeline
        .invoke(&PurposeBody::dossier(), &invoke_ctx(selected, "inv-prov"))
        .await
        .unwrap();
    let SidecarInvokeOutcome::Dossier(d) = outcome else {
        panic!("expected dossier");
    };
    // Host-authoritative provenance replaces EVERY smuggled/lied value.
    assert_eq!(d.provenance.sidecar_provider, "vision");
    assert_eq!(d.provenance.sidecar_model, "vmodel");
    assert_eq!(d.provenance.attachment_checksum_hex, "deadbeef");
    assert_eq!(d.provenance.source_width_px, 100, "host source width");
    assert_eq!(d.provenance.source_height_px, 100, "host source height");
    assert_eq!(d.provenance.source_order, 0, "host source order");
    assert_eq!(d.provenance.schema_version, 1, "host schema version");
    // And the exported "safe metadata" carries the host values, not the smuggle.
    let exported = dossier_cache.export_metadata();
    assert_eq!(exported.len(), 1);
    assert_eq!(exported[0].provenance.sidecar_provider, "vision");
    assert!(!exported[0].provenance.sidecar_provider.contains("EVIL"));
    assert_eq!(exported[0].provenance.source_width_px, 100);
    assert_eq!(exported[0].provenance.schema_version, 1);
}

// ===========================================================================
// MEDIUM #2 — ask_image provenance identity is overwritten by the host too
// ===========================================================================

#[tokio::test]
async fn ask_image_provenance_overwritten_by_host() {
    let selected = selected_sidecar();
    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Session,
            tuple_for(&selected, Purpose::AskImage),
            Some("s1"),
            None,
            0,
        )
        .unwrap();

    // Attacker misattributes the ask_image answer provenance.
    let mut answer = ask_image_answer("It is a login screen.");
    answer.provenance.sidecar_provider = "EVIL_PROVIDER".to_string();
    answer.provenance.sidecar_model = "EVIL_MODEL".to_string();
    answer.provenance.attachment_checksum_hex = "EVIL_CHECKSUM".to_string();
    let response = SidecarProviderResponse {
        output_text: serde_json::to_string(&answer).unwrap(),
    };

    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    let pipeline = SidecarPipeline::new(
        grants,
        cache(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved: durable_resolved(),
            log: log.clone(),
        }),
        Arc::new(crate::image_sidecar::FakeReservationAcquirer::new(4)),
        Arc::new(SpyTransport::new(vec![Ok(response)], log.clone())),
    );

    let outcome = pipeline
        .invoke(
            &PurposeBody::ask_image("what is this?").unwrap(),
            &invoke_ctx(selected, "inv-askprov"),
        )
        .await
        .unwrap();
    let SidecarInvokeOutcome::AskImage(a) = outcome else {
        panic!("expected ask-image answer");
    };
    assert_eq!(a.provenance.sidecar_provider, "vision");
    assert_eq!(a.provenance.sidecar_model, "vmodel");
    assert_eq!(a.provenance.attachment_checksum_hex, "deadbeef");
    // The answer body itself remains provider evidence.
    assert_eq!(a.answer, "It is a login screen.");
}

// ===========================================================================
// MEDIUM #2 — a resolver that substitutes a different attachment is rejected
// ===========================================================================

#[tokio::test]
async fn resolver_substituting_attachment_is_rejected() {
    let selected = selected_sidecar();
    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Session,
            tuple_for(&selected, Purpose::Dossier),
            Some("s1"),
            None,
            0,
        )
        .unwrap();

    // Resolver returns a DIFFERENT current-session attachment than requested.
    let mut resolved = durable_resolved();
    resolved.durable.attachment_id = "some-other-attachment".to_string();

    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    let transport = Arc::new(SpyTransport::new(
        vec![Ok(dossier_response("x"))],
        log.clone(),
    ));
    let calls = transport.calls.clone();
    let pipeline = SidecarPipeline::new(
        grants,
        cache(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved,
            log: log.clone(),
        }),
        Arc::new(crate::image_sidecar::FakeReservationAcquirer::new(4)),
        transport,
    );

    let err = pipeline
        .invoke(&PurposeBody::dossier(), &invoke_ctx(selected, "inv-sub"))
        .await
        .unwrap_err();
    assert_eq!(err, SidecarInvokeError::ResolvedAttachmentMismatch);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "substituted attachment makes zero provider calls"
    );
}

// ===========================================================================
// MEDIUM #3 — the pipeline does not resurrect/cache for an inactive session
// ===========================================================================

#[tokio::test]
async fn ended_session_not_recached() {
    let selected = selected_sidecar();
    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Session,
            tuple_for(&selected, Purpose::Dossier),
            Some("s1"),
            None,
            0,
        )
        .unwrap();

    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    let dossier_cache = cache();
    // Simulate a session that started and then ENDED before caching.
    dossier_cache.session_start("s1");
    dossier_cache.session_end("s1");

    let pipeline = SidecarPipeline::new(
        grants,
        dossier_cache.clone(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved: durable_resolved(),
            log: log.clone(),
        }),
        Arc::new(crate::image_sidecar::FakeReservationAcquirer::new(4)),
        Arc::new(SpyTransport::new(
            vec![Ok(dossier_response("x"))],
            log.clone(),
        )),
    );

    let outcome = pipeline
        .invoke(&PurposeBody::dossier(), &invoke_ctx(selected, "inv-ended"))
        .await
        .unwrap();
    assert!(matches!(outcome, SidecarInvokeOutcome::Dossier(_)));
    // The invocation succeeds, but nothing is cached for the ended session:
    // the pipeline never re-starts it.
    assert_eq!(
        dossier_cache.len(),
        0,
        "ended session is not resurrected/cached"
    );
}

// ---------------------------------------------------------------------------
// Project-bound grant tuple helper (mirrors the pipeline's authorization digest)
// ---------------------------------------------------------------------------

/// Build a grant tuple whose digest folds in `project`, using the production
/// `DestinationPolicy::digest`. This is what a grant recorded for a specific
/// project looks like.
fn tuple_for_project(
    selected: &SelectedSidecar,
    purpose: Purpose,
    project: ProjectIdentity,
) -> DestinationTuple {
    let digest = DestinationPolicy {
        provider: selected.provider.clone(),
        model: selected.model.clone(),
        endpoint_origin: selected.endpoint_origin.clone(),
        connected_location: selected.location,
        credential_fingerprint: selected.credential_fingerprint.clone(),
        project_identity: project.clone(),
        image_capability_value: selected.capability_evidence.status,
        capability_contract_revision: CAPABILITY_CONTRACT_REVISION,
        egress_fields: EgressFields::default(),
    }
    .digest();
    DestinationTuple {
        provider: selected.provider.clone(),
        model: selected.model.clone(),
        endpoint_origin: selected.endpoint_origin.clone(),
        connected_location: selected.location,
        credential_fingerprint: selected.credential_fingerprint.clone(),
        project_identity: project,
        destination_policy_digest: digest,
        media_class: MediaClass::Image,
        purpose,
    }
}

// ===========================================================================
// HIGH #1 — reused invocation_id still acquires a FRESH, distinct reservation
// ===========================================================================

#[tokio::test]
async fn reused_invocation_id_acquires_fresh_reservation() {
    let selected = selected_sidecar();
    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Session,
            tuple_for(&selected, Purpose::Dossier),
            Some("s1"),
            None,
            0,
        )
        .unwrap();

    let db = Db::open_in_memory().unwrap();
    let ledger = MediaReservationLedger::new(db.clone(), Arc::new(ZeroClock));
    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    let counts = Arc::new(AcquirerCounts::default());
    let acquirer = Arc::new(RecordingAcquirer {
        inner: Arc::new(LedgerReservationAcquirer::new(
            ledger,
            MediaResourcePolicy::default(),
            "project-hash".to_string(),
        )),
        counts: counts.clone(),
        log: log.clone(),
    });
    let pipeline = SidecarPipeline::new(
        grants,
        cache(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved: durable_resolved(),
            log: log.clone(),
        }),
        acquirer,
        Arc::new(SpyTransport::new(
            vec![Ok(dossier_response("a")), Ok(dossier_response("b"))],
            log.clone(),
        )),
    );

    // Two invocations that reuse the SAME caller invocation id.
    pipeline
        .invoke(
            &PurposeBody::dossier(),
            &invoke_ctx(selected.clone(), "inv-dup"),
        )
        .await
        .unwrap();
    pipeline
        .invoke(&PurposeBody::dossier(), &invoke_ctx(selected, "inv-dup"))
        .await
        .unwrap();

    // Each acquisition reserved fresh: two reserve calls and two DISTINCT rows.
    assert_eq!(counts.reserves.load(Ordering::SeqCst), 2);
    let distinct: i64 = db
        .read(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(DISTINCT reservation_id) FROM media_reservations WHERE reservation_id LIKE 'inv-dup#%'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(
        distinct, 2,
        "reused invocation id still yields two fresh reservations"
    );
}

// ===========================================================================
// HIGH #2 — a Session grant is project-bound (no cross-project authorization)
// ===========================================================================

#[tokio::test]
async fn session_grant_is_project_bound() {
    let selected = selected_sidecar();
    let project_a = ProjectIdentity::from_root("/project/a");
    let project_b = ProjectIdentity::from_root("/project/b");

    // A Session grant approved for (session s1, project A).
    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Session,
            tuple_for_project(&selected, Purpose::Dossier, project_a.clone()),
            Some("s1"),
            None,
            0,
        )
        .unwrap();

    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    let transport = Arc::new(SpyTransport::new(
        vec![Ok(dossier_response("a")), Ok(dossier_response("b"))],
        log.clone(),
    ));
    let calls = transport.calls.clone();
    let dossier_cache = cache();
    let pipeline = SidecarPipeline::new(
        grants,
        dossier_cache.clone(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(FakeResolver {
            resolved: durable_resolved(),
            log: log.clone(),
        }),
        Arc::new(crate::image_sidecar::FakeReservationAcquirer::new(8)),
        transport,
    );
    dossier_cache.session_start("s1");

    // Same session, DIFFERENT project B -> rejected, zero provider calls.
    let mut ctx_b = invoke_ctx(selected.clone(), "inv-b");
    ctx_b.project = Some(project_b);
    let err = pipeline
        .invoke(&PurposeBody::dossier(), &ctx_b)
        .await
        .unwrap_err();
    assert_eq!(err, SidecarInvokeError::EgressNotAuthorized);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "cross-project grant makes zero provider calls"
    );

    // Positive control: the SAME project A is authorized.
    let mut ctx_a = invoke_ctx(selected, "inv-a");
    ctx_a.project = Some(project_a);
    let ok = pipeline
        .invoke(&PurposeBody::dossier(), &ctx_a)
        .await
        .unwrap();
    assert!(matches!(ok, SidecarInvokeOutcome::Dossier(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

// ===========================================================================
// MEDIUM #1 — a request that fails verify() does NOT consume the Once grant
// ===========================================================================

#[tokio::test]
async fn verify_failure_does_not_consume_once_grant() {
    let selected = selected_sidecar();
    let grants = Arc::new(DestinationGrantStore::new());
    grants
        .record(
            GrantScope::Once,
            tuple_for(&selected, Purpose::Dossier),
            None,
            None,
            0,
        )
        .unwrap();

    let log: OrderLog = Arc::new(Mutex::new(Vec::new()));
    let transport = Arc::new(SpyTransport::new(
        vec![Ok(dossier_response("ok"))],
        log.clone(),
    ));
    let calls = transport.calls.clone();

    // First: a resolver that returns an EMPTY artifact id -> request fails
    // `verify()` (missing image) AFTER reserve but BEFORE consume.
    let mut bad_resolved = durable_resolved();
    bad_resolved.image_artifact_id = String::new();

    let dossier_cache = cache();
    let pipeline = SidecarPipeline::new(
        grants.clone(),
        dossier_cache.clone(),
        Arc::new(FakeDossierClock::new(0)),
        Arc::new(SwitchableResolver::new(bad_resolved, durable_resolved())),
        Arc::new(crate::image_sidecar::FakeReservationAcquirer::new(8)),
        transport,
    );
    dossier_cache.session_start("s1");

    let mut ctx = invoke_ctx(selected, "inv-verify");
    ctx.scope = GrantScope::Once;

    // Verify fails -> RequestBoundary, and the Once grant is NOT consumed.
    let err = pipeline
        .invoke(&PurposeBody::dossier(), &ctx)
        .await
        .unwrap_err();
    assert!(matches!(err, SidecarInvokeError::RequestBoundary(_)));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "verify failure makes zero provider calls"
    );

    // The Once grant is still usable: a second call (now with a good artifact)
    // succeeds, proving the grant was not burned by the malformed request.
    let mut ctx2 = ctx.clone();
    ctx2.invocation_id = "inv-verify-2".to_string();
    let ok = pipeline
        .invoke(&PurposeBody::dossier(), &ctx2)
        .await
        .unwrap();
    assert!(matches!(ok, SidecarInvokeOutcome::Dossier(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
