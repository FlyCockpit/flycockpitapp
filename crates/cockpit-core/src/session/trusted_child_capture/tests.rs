//! Tests for the exact single-use trusted-child capture authority
//! (leak-report AC7 `trusted_child_capture_is_exact_and_non_oracular` + AC8's
//! in-process transfer), sub-increment 2c-2.
//!
//! Every test drives the real [`TrustedChildCaptureRegistry`] mint + verify
//! seam and asserts against the live [`Session`] store (sealed-value existence,
//! vault item, and the persisted redaction table), never a hand-built object.
//! The planted secret is a distinctive marker withheld from every other path,
//! so a fail-closed rejection is proven by its total absence from the vault, the
//! `sealed_values` row, and the redaction table.
//!
//! These fail against current production because the `TrustedChildCapture`
//! ingress variant had no minting, verify, or consumer before this increment.

use std::path::PathBuf;

use super::*;
use crate::db::Db;
use crate::leak_report::{LeakReportSource, OwnerWriteDisposition};
use crate::redact::RedactionTable;
use crate::sealed::OwnerAuthority;

const RECORD_ID: &str = "3f2e1d0c-9b8a-4c7d-8e6f-5a4b3c2d1e0f";
const VALUE_ID: &str = "captured_secret";
const REASON: &str = "trusted-child acquisition";
const ORIGIN: &str = "trusted_child";
const GENERATION: i64 = 7;
const VERSION: i64 = 1;
const TOOL_CALL: &str = "toolcall-abc";
const NOW_MS: i64 = 1_000_000;
/// A distinctive marker withheld from every other path. Passes
/// `validate_sealed_value` (>= 12 chars, not a rejected literal).
const SECRET: &str = "planted-trusted-child-secret-9f3a2b";

fn new_session() -> Session {
    let db = Db::open_in_memory().unwrap();
    Session::create_for_test(
        db,
        PathBuf::from("/repo"),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap()
}

/// Mint the happy-path authority for `session`.
fn begin(reg: &TrustedChildCaptureRegistry, session: &Session) -> TrustedChildCaptureAuthority {
    reg.begin_capture(
        session, RECORD_ID, VALUE_ID, REASON, ORIGIN, GENERATION, VERSION, TOOL_CALL, NOW_MS,
    )
    .expect("first acquisition is admitted")
}

async fn publish_audit(session: &Session) {
    session
        .db
        .begin_sealed_value_acquisition_audit(
            crate::db::sealed_scope::NewSealedValueAcquisitionAudit {
                acquisition_id: RECORD_ID.to_owned(),
                record_id: RECORD_ID.to_owned(),
                session_id: session.id.to_string(),
                project_key: session.project_id.clone(),
                name: VALUE_ID.to_owned(),
                description: REASON.to_owned(),
                child_agent: "sealed-acquisition".to_owned(),
                consent_mode: "audit_only".to_owned(),
                created_at_ms: NOW_MS,
            },
        )
        .await
        .unwrap();
}

/// Assert the planted secret never reached the vault, the `sealed_values` row,
/// or the live redaction table for `session`.
async fn assert_no_store(session: &Session) {
    // Precondition: the marker is what we claim, so absence is meaningful.
    assert!(SECRET.len() >= crate::session::sealed_values::MIN_SEALED_VALUE_LENGTH);

    assert!(
        !session
            .sealed_value_exists(OwnerAuthority::for_test("owner"), VALUE_ID)
            .await
            .unwrap(),
        "no sealed value row may exist on a fail-closed path"
    );

    let vault = crate::secure_key::vault_for_db(&session.db).unwrap();
    let item_id = crate::secure_key::session_sealed_item_id(&session.id.to_string(), VALUE_ID, 1);
    assert!(
        vault
            .get_item(
                cockpit_db::secret_vault::SecretVaultKind::SessionSealedValue,
                &item_id,
            )
            .is_err(),
        "no vault item may hold the captured literal on a fail-closed path"
    );

    // The live redaction table must not scrub the planted secret (it was never
    // installed). `None` means nothing was persisted, which is also fail-closed.
    if let Some(table) = session.persisted_redaction_table().unwrap() {
        assert_eq!(
            table.scrub(SECRET),
            SECRET,
            "the planted secret must not be installed in the redaction table"
        );
    }
}

/// The exact happy-path claim minted for `session`.
fn exact_claim() -> ProtectedSensitiveIngress {
    ProtectedSensitiveIngress::TrustedChildCapture {
        record_id: RECORD_ID.to_owned(),
        project: "/repo".to_owned(),
        session: String::new(), // filled by the caller from the live session id
        generation: GENERATION,
        version: VERSION,
        source_tool_call_id: TOOL_CALL.to_owned(),
    }
}

#[tokio::test]
async fn exact_live_authority_captures_installs_redaction_and_consumes_single_use() {
    let session = new_session();
    let reg = TrustedChildCaptureRegistry::new();
    let authority = begin(&reg, &session);
    publish_audit(&session).await;

    // The minted authority derives project/session from the host session.
    assert_eq!(authority.project(), session.project_id);
    assert_eq!(authority.session(), session.id.to_string());
    assert_eq!(authority.record_id(), RECORD_ID);
    assert_eq!(authority.generation(), GENERATION);
    assert_eq!(authority.version(), VERSION);
    assert_eq!(authority.source_tool_call_id(), TOOL_CALL);

    let table = RedactionTable::empty();
    // Precondition (L7): a fresh table does not scrub the marker, so the
    // post-capture scrub is a real signal.
    assert_eq!(table.scrub(SECRET), SECRET);

    let outcome = reg
        .verify_and_capture(
            &session,
            &table,
            &authority.to_ingress(),
            SealedCaptureValue::new(SECRET.to_owned()),
            NOW_MS,
        )
        .await;
    assert_eq!(
        outcome,
        TrustedChildCaptureOutcome::Captured {
            record_id: RECORD_ID.to_owned()
        }
    );

    // The value was transferred in-process: the sealed row exists, the vault
    // holds the literal, and the live redaction table now scrubs it.
    assert!(
        session
            .sealed_value_exists(OwnerAuthority::for_test("owner"), VALUE_ID)
            .await
            .unwrap()
    );
    let vault = crate::secure_key::vault_for_db(&session.db).unwrap();
    let item_id = crate::secure_key::session_sealed_item_id(&session.id.to_string(), VALUE_ID, 1);
    let got = vault
        .get_item(
            cockpit_db::secret_vault::SecretVaultKind::SessionSealedValue,
            &item_id,
        )
        .unwrap();
    assert_eq!(got.as_slice(), SECRET.as_bytes());
    let installed = session.persisted_redaction_table().unwrap().unwrap();
    assert!(!installed.scrub(SECRET).contains(SECRET));
    let record = session
        .db
        .sealed_value_record(RECORD_ID.to_owned())
        .await
        .unwrap()
        .expect("agent-acquired scoped record exists");
    assert_eq!(record.owner_principal, "agent-acquired");
    assert_eq!(record.active_version, 1);
    let audit = session
        .db
        .list_sealed_value_acquisition_audit(Some(session.id.to_string()), 10)
        .await
        .unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].outcome, "sealed");
    assert_eq!(audit[0].source_tool_call_id.as_deref(), Some(TOOL_CALL));

    // Single-use: a replay of the exact same authority is now denied and stores
    // nothing new (the record was consumed).
    assert!(!reg.has_in_flight(&session.id.to_string(), NOW_MS));
    let replay = reg
        .verify_and_capture(
            &session,
            &installed,
            &authority.to_ingress(),
            SealedCaptureValue::new(SECRET.to_owned()),
            NOW_MS,
        )
        .await;
    assert_eq!(replay, TrustedChildCaptureOutcome::Denied);
}

#[test]
fn reserved_capture_binds_the_source_exactly_once() {
    let session = new_session();
    let reg = TrustedChildCaptureRegistry::new();
    reg.reserve_capture(
        &session,
        "acq-distinct",
        RECORD_ID,
        VALUE_ID,
        REASON,
        ORIGIN,
        GENERATION,
        VERSION,
        NOW_MS,
    )
    .unwrap();
    let authority = reg
        .bind_source_tool_call(&session.id.to_string(), "acq-distinct", TOOL_CALL, NOW_MS)
        .expect("first exact source binding succeeds");
    assert_eq!(authority.source_tool_call_id(), TOOL_CALL);
    assert!(
        reg.bind_source_tool_call(&session.id.to_string(), "acq-distinct", "other", NOW_MS)
            .is_none(),
        "a reserved authority cannot be redirected to another source"
    );
}

#[test]
fn stale_acquisition_cannot_bind_or_cancel_a_recycled_session_slot() {
    let session = new_session();
    let reg = TrustedChildCaptureRegistry::new();
    reg.reserve_capture(
        &session, "acq-a", RECORD_ID, VALUE_ID, REASON, ORIGIN, GENERATION, VERSION, NOW_MS,
    )
    .unwrap();
    let replacement_time = NOW_MS + TRUSTED_CHILD_CAPTURE_TTL_MS + 1;
    reg.reserve_capture(
        &session,
        "acq-b",
        "4f2e1d0c-9b8a-4c7d-8e6f-5a4b3c2d1e0f",
        "replacement_secret",
        REASON,
        ORIGIN,
        GENERATION,
        VERSION,
        replacement_time,
    )
    .unwrap();

    assert!(
        reg.bind_source_tool_call(
            &session.id.to_string(),
            "acq-a",
            TOOL_CALL,
            replacement_time
        )
        .is_none()
    );
    assert!(!reg.cancel(&session.id.to_string(), "acq-a"));
    assert!(reg.has_in_flight(&session.id.to_string(), replacement_time));
}

#[test]
fn create_only_capture_rejects_noninitial_value_version() {
    let session = new_session();
    let reg = TrustedChildCaptureRegistry::new();
    let error = reg
        .reserve_capture(
            &session,
            "acq-version",
            RECORD_ID,
            VALUE_ID,
            REASON,
            ORIGIN,
            GENERATION,
            2,
            NOW_MS,
        )
        .unwrap_err();
    assert_eq!(error, BeginCaptureError::InvalidCreateVersion);
    assert!(!reg.has_in_flight(&session.id.to_string(), NOW_MS));
}

#[tokio::test]
async fn agent_capture_cannot_replace_an_owner_authored_slot() {
    const AGENT_RECORD: &str = "4f2e1d0c-9b8a-4c7d-8e6f-5a4b3c2d1e0f";
    const OWNER_SECRET: &str = "owner-authored-secret-value-123";
    let session = new_session();
    let table = RedactionTable::empty();
    session
        .set_sealed_value(
            OwnerAuthority::for_test("owner"),
            &table,
            VALUE_ID,
            OWNER_SECRET,
            "owner supplied",
            "owner",
        )
        .await
        .unwrap();
    session
        .db
        .begin_sealed_value_acquisition_audit(
            crate::db::sealed_scope::NewSealedValueAcquisitionAudit {
                acquisition_id: "acq-collision".to_owned(),
                record_id: AGENT_RECORD.to_owned(),
                session_id: session.id.to_string(),
                project_key: session.project_id.clone(),
                name: VALUE_ID.to_owned(),
                description: REASON.to_owned(),
                child_agent: "sealed-acquisition".to_owned(),
                consent_mode: "audit_only".to_owned(),
                created_at_ms: NOW_MS,
            },
        )
        .await
        .unwrap();

    let reg = TrustedChildCaptureRegistry::new();
    reg.reserve_capture(
        &session,
        "acq-collision",
        AGENT_RECORD,
        VALUE_ID,
        REASON,
        ORIGIN,
        GENERATION,
        VERSION,
        NOW_MS,
    )
    .unwrap();
    let authority = reg
        .bind_source_tool_call(&session.id.to_string(), "acq-collision", TOOL_CALL, NOW_MS)
        .unwrap();
    let outcome = reg
        .verify_and_capture(
            &session,
            &table,
            &authority.to_ingress(),
            SealedCaptureValue::new(SECRET.to_owned()),
            NOW_MS,
        )
        .await;
    assert_eq!(outcome, TrustedChildCaptureOutcome::Denied);
    assert!(
        session
            .db
            .sealed_value_record(AGENT_RECORD.to_owned())
            .await
            .unwrap()
            .is_none()
    );
    let vault = crate::secure_key::vault_for_db(&session.db).unwrap();
    let item_id = crate::secure_key::session_sealed_item_id(&session.id.to_string(), VALUE_ID, 1);
    let stored = vault
        .get_item(
            cockpit_db::secret_vault::SecretVaultKind::SessionSealedValue,
            &item_id,
        )
        .unwrap();
    assert_eq!(stored.as_slice(), OWNER_SECRET.as_bytes());
}

/// Each wrong-field / lifecycle / non-trusted case must fail closed BEFORE the
/// value is parsed or stored, returning the indistinguishable `Denied`.
#[tokio::test]
async fn wrong_binding_and_lifecycle_cases_fail_closed_before_store() {
    // Wrong record id.
    {
        let session = new_session();
        let reg = TrustedChildCaptureRegistry::new();
        let _ = begin(&reg, &session);
        let mut claim = exact_claim();
        if let ProtectedSensitiveIngress::TrustedChildCapture {
            session: s,
            record_id,
            ..
        } = &mut claim
        {
            *s = session.id.to_string();
            *record_id = "rec-OTHER".to_owned();
        }
        let outcome = verify(&reg, &session, &claim).await;
        assert_eq!(outcome, TrustedChildCaptureOutcome::Denied);
        assert_no_store(&session).await;
    }

    // Wrong project.
    {
        let session = new_session();
        let reg = TrustedChildCaptureRegistry::new();
        let _ = begin(&reg, &session);
        let mut claim = exact_claim();
        if let ProtectedSensitiveIngress::TrustedChildCapture {
            session: s,
            project,
            ..
        } = &mut claim
        {
            *s = session.id.to_string();
            *project = "/some/other/project".to_owned();
        }
        assert_eq!(
            verify(&reg, &session, &claim).await,
            TrustedChildCaptureOutcome::Denied
        );
        assert_no_store(&session).await;
    }

    // Wrong session (claim names a different session than the one verified /
    // than the live record).
    {
        let session = new_session();
        let reg = TrustedChildCaptureRegistry::new();
        let _ = begin(&reg, &session);
        let mut claim = exact_claim();
        if let ProtectedSensitiveIngress::TrustedChildCapture { session: s, .. } = &mut claim {
            *s = "ffffffff-ffff-ffff-ffff-ffffffffffff".to_owned();
        }
        assert_eq!(
            verify(&reg, &session, &claim).await,
            TrustedChildCaptureOutcome::Denied
        );
        assert_no_store(&session).await;
    }

    // Wrong generation.
    {
        let session = new_session();
        let reg = TrustedChildCaptureRegistry::new();
        let _ = begin(&reg, &session);
        let mut claim = exact_claim();
        if let ProtectedSensitiveIngress::TrustedChildCapture {
            session: s,
            generation,
            ..
        } = &mut claim
        {
            *s = session.id.to_string();
            *generation = GENERATION + 1;
        }
        assert_eq!(
            verify(&reg, &session, &claim).await,
            TrustedChildCaptureOutcome::Denied
        );
        assert_no_store(&session).await;
    }

    // Wrong version.
    {
        let session = new_session();
        let reg = TrustedChildCaptureRegistry::new();
        let _ = begin(&reg, &session);
        let mut claim = exact_claim();
        if let ProtectedSensitiveIngress::TrustedChildCapture {
            session: s,
            version,
            ..
        } = &mut claim
        {
            *s = session.id.to_string();
            *version = VERSION + 1;
        }
        assert_eq!(
            verify(&reg, &session, &claim).await,
            TrustedChildCaptureOutcome::Denied
        );
        assert_no_store(&session).await;
    }

    // Wrong source tool-call id.
    {
        let session = new_session();
        let reg = TrustedChildCaptureRegistry::new();
        let _ = begin(&reg, &session);
        let mut claim = exact_claim();
        if let ProtectedSensitiveIngress::TrustedChildCapture {
            session: s,
            source_tool_call_id,
            ..
        } = &mut claim
        {
            *s = session.id.to_string();
            *source_tool_call_id = "toolcall-OTHER".to_owned();
        }
        assert_eq!(
            verify(&reg, &session, &claim).await,
            TrustedChildCaptureOutcome::Denied
        );
        assert_no_store(&session).await;
    }
}

#[tokio::test]
async fn non_trusted_child_authority_is_denied_before_store() {
    // An OwnerWrite ingress.
    {
        let session = new_session();
        let reg = TrustedChildCaptureRegistry::new();
        let _ = begin(&reg, &session);
        let claim = ProtectedSensitiveIngress::OwnerWrite {
            record_id: Some(RECORD_ID.to_owned()),
            scope_version: "v1".to_owned(),
            disposition: OwnerWriteDisposition::Create,
        };
        assert_eq!(
            verify(&reg, &session, &claim).await,
            TrustedChildCaptureOutcome::Denied
        );
        assert_no_store(&session).await;
    }
    // A ReportLeak ingress.
    {
        let session = new_session();
        let reg = TrustedChildCaptureRegistry::new();
        let _ = begin(&reg, &session);
        let claim = ProtectedSensitiveIngress::ReportLeak {
            source: LeakReportSource::EnvLeak,
        };
        assert_eq!(
            verify(&reg, &session, &claim).await,
            TrustedChildCaptureOutcome::Denied
        );
        assert_no_store(&session).await;
    }
}

#[tokio::test]
async fn replay_after_consume_is_denied() {
    let session = new_session();
    let reg = TrustedChildCaptureRegistry::new();
    let authority = begin(&reg, &session);
    let claim = authority.to_ingress();
    publish_audit(&session).await;

    let first = reg
        .verify_and_capture(
            &session,
            &RedactionTable::empty(),
            &claim,
            SealedCaptureValue::new(SECRET.to_owned()),
            NOW_MS,
        )
        .await;
    assert_eq!(
        first,
        TrustedChildCaptureOutcome::Captured {
            record_id: RECORD_ID.to_owned()
        }
    );

    // The exact same authority a second time: consumed → Denied.
    let second = verify(&reg, &session, &claim).await;
    assert_eq!(second, TrustedChildCaptureOutcome::Denied);
}

#[tokio::test]
async fn expired_authority_is_denied_before_store() {
    let session = new_session();
    let reg = TrustedChildCaptureRegistry::new();
    let authority = begin(&reg, &session);

    let past_expiry = NOW_MS + TRUSTED_CHILD_CAPTURE_TTL_MS + 1;
    let outcome = reg
        .verify_and_capture(
            &session,
            &RedactionTable::empty(),
            &authority.to_ingress(),
            SealedCaptureValue::new(SECRET.to_owned()),
            past_expiry,
        )
        .await;
    assert_eq!(outcome, TrustedChildCaptureOutcome::Denied);
    assert_no_store(&session).await;
}

#[tokio::test]
async fn cancelled_authority_is_denied_before_store() {
    let session = new_session();
    let reg = TrustedChildCaptureRegistry::new();
    let authority = begin(&reg, &session);
    reg.cancel(&session.id.to_string(), RECORD_ID);

    let outcome = reg
        .verify_and_capture(
            &session,
            &RedactionTable::empty(),
            &authority.to_ingress(),
            SealedCaptureValue::new(SECRET.to_owned()),
            NOW_MS,
        )
        .await;
    assert_eq!(outcome, TrustedChildCaptureOutcome::Denied);
    assert_no_store(&session).await;
}

#[tokio::test]
async fn second_in_flight_acquisition_per_session_is_refused() {
    let session = new_session();
    let reg = TrustedChildCaptureRegistry::new();
    let _first = begin(&reg, &session);

    // A second acquisition while the first is live is refused (rate limit: one
    // in flight per session).
    let second = reg.begin_capture(
        &session,
        "rec-2",
        "other_slot",
        REASON,
        ORIGIN,
        GENERATION,
        VERSION,
        "toolcall-2",
        NOW_MS,
    );
    assert_eq!(second.unwrap_err(), BeginCaptureError::AlreadyInFlight);

    // After the live one expires, a new acquisition is admitted again.
    let after_expiry = NOW_MS + TRUSTED_CHILD_CAPTURE_TTL_MS + 1;
    assert!(
        reg.begin_capture(
            &session,
            "rec-3",
            "third_slot",
            REASON,
            ORIGIN,
            GENERATION,
            VERSION,
            "toolcall-3",
            after_expiry,
        )
        .is_ok()
    );
}

/// Drive verify with a fresh planted value; used where the value must be
/// rejected before parse/store.
async fn verify(
    reg: &TrustedChildCaptureRegistry,
    session: &Session,
    claim: &ProtectedSensitiveIngress,
) -> TrustedChildCaptureOutcome {
    reg.verify_and_capture(
        session,
        &RedactionTable::empty(),
        claim,
        SealedCaptureValue::new(SECRET.to_owned()),
        NOW_MS,
    )
    .await
}
