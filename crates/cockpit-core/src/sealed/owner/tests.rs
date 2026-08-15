//! Tests for the hardened sensitive Owner channel: Begin -> Frame ->
//! contained/revealed, injected-time expiry, atomic one-use replay and
//! concurrent double-apply, cancel through the real consume path, wrong-owner
//! (mint + apply), wrong-scope / wrong-version via crafted capabilities and race
//! rotate, the closed frame/disposition mapping, and redaction of every literal.
//!
//! These drive the library core directly (the RPC facade and daemon capability
//! table are wired in a follow-up). Every test is written so a broken
//! implementation gives a different answer.

use cockpit_db::db::Db;

use super::*;
use crate::sealed::action::OwnerAuthority;
use crate::sealed::compartment::{SealedCompartment, SealedLiteral};
use crate::sealed::identity::{
    SealedDescription, SealedName, SealedProjectKey, SealedRecordId, SealedScopeRef,
};
use crate::sealed::store::{CreateSealedValue, SealedValueDirectory};
use zeroize::Zeroizing;

const TEST_LITERAL: &str = "sk-live-9f2c41ab77de4c0b83e5aa16d9c7b204";
const MINT_MS: i64 = 1_000;

struct OwnerFixture {
    directory: SealedValueDirectory,
    _dir: tempfile::TempDir,
}

impl OwnerFixture {
    async fn new() -> Self {
        let db = Db::open_in_memory().expect("in-memory db");
        db.create_session("proj", "/repo", "Build")
            .await
            .expect("session row");
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = crate::secure_key::vault_for_db(&db).expect("in-memory vault");
        let compartment = SealedCompartment::from_vault(vault);
        let directory = SealedValueDirectory::new(db, compartment);
        Self {
            directory,
            _dir: dir,
        }
    }

    fn directory(&self) -> &SealedValueDirectory {
        &self.directory
    }

    fn owner() -> OwnerAuthority {
        OwnerAuthority::for_test("owner")
    }

    fn project_scope() -> SealedScopeRef {
        SealedScopeRef::Project(SealedProjectKey::from_canonical("proj"))
    }
}

/// Plant a project-scope record owned by `owner_principal`, returning its id.
async fn seed_project_value_owned(
    fixture: &OwnerFixture,
    name: &str,
    owner_principal: &'static str,
    literal: &str,
) -> SealedRecordId {
    let summary = fixture
        .directory()
        .create(
            OwnerAuthority::for_test(owner_principal),
            CreateSealedValue {
                scope: OwnerFixture::project_scope(),
                name: SealedName::canonical(name).unwrap(),
                description: SealedDescription::parse("deployment credential").unwrap(),
                owner_principal: owner_principal.to_string(),
            },
            SealedLiteral::new(literal),
            MINT_MS,
        )
        .await
        .unwrap();
    summary.record_id
}

async fn seed_project_value(fixture: &OwnerFixture, name: &str) -> SealedRecordId {
    seed_project_value_owned(fixture, name, "owner", TEST_LITERAL).await
}

// ---- Begin -> Frame -> contained/revealed ----------------------------------

#[tokio::test]
async fn begin_and_frame_write_returns_contained() {
    let fixture = OwnerFixture::new().await;
    let result = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Create {
            scope: OwnerFixture::project_scope(),
            name: SealedName::canonical("deploy_token").unwrap(),
            description: SealedDescription::parse("Deploy token").unwrap(),
        },
        MINT_MS,
    )
    .await
    .unwrap();
    assert_eq!(result.capability.owner_principal(), "owner");
    let frame = SensitiveOwnerFrame::for_write(
        &result.capability,
        Zeroizing::new(TEST_LITERAL.to_string()),
    );
    let outcome = frame
        .apply(OwnerFixture::owner(), fixture.directory(), MINT_MS)
        .await
        .unwrap();
    match outcome {
        SensitiveFrameOutcome::Contained { summary } => {
            assert_eq!(summary.name.as_str(), "deploy_token");
            assert_eq!(summary.owner_principal, "owner");
        }
        _ => panic!("expected Contained"),
    }
    assert!(result.capability.is_consumed());
}

#[tokio::test]
async fn begin_recover_binds_live_version_and_reveals_literal() {
    let fixture = OwnerFixture::new().await;
    let record_id = seed_project_value(&fixture, "deploy_token").await;

    let result = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Recover { record_id },
        MINT_MS,
    )
    .await
    .unwrap();
    // The daemon bound the row's live scope + exact version — the client sent
    // only a record id.
    assert_eq!(
        result.capability.operation().version,
        VersionBinding::Exact(1)
    );
    assert_eq!(
        result.capability.operation().scope,
        OwnerFixture::project_scope()
    );
    assert_eq!(
        result.capability.operation().disposition,
        SensitiveOwnerDisposition::Recover
    );

    let frame = SensitiveOwnerFrame::for_recover(&result.capability);
    let outcome = frame
        .apply(OwnerFixture::owner(), fixture.directory(), MINT_MS)
        .await
        .unwrap();
    match outcome {
        SensitiveFrameOutcome::Revealed { literal } => {
            assert_eq!(literal.as_str(), TEST_LITERAL);
        }
        _ => panic!("expected Revealed"),
    }
    assert!(result.capability.is_consumed());
}

// ---- injected-time expiry (no sleeps) --------------------------------------

#[tokio::test]
async fn capability_expires_via_injected_now_ms() {
    let fixture = OwnerFixture::new().await;
    let result = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Create {
            scope: OwnerFixture::project_scope(),
            name: SealedName::canonical("deploy_token").unwrap(),
            description: SealedDescription::parse("Deploy token").unwrap(),
        },
        MINT_MS,
    )
    .await
    .unwrap();
    // 60_001 ms after mint is past the 60_000 ms TTL.
    let too_late = MINT_MS + CAPABILITY_TTL_MS + 1;
    let frame = SensitiveOwnerFrame::for_write(
        &result.capability,
        Zeroizing::new(TEST_LITERAL.to_string()),
    );
    let err = frame
        .apply(OwnerFixture::owner(), fixture.directory(), too_late)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("expired"),
        "error should mention expiry: {err}"
    );
    // An expired apply rejects before the consume point, leaving the capability
    // usable for a fresh, in-window apply.
    assert!(!result.capability.is_consumed());
}

// ---- atomic one-use: real replay + concurrent double-apply -----------------

#[tokio::test]
async fn second_apply_is_rejected_as_replay() {
    let fixture = OwnerFixture::new().await;
    let result = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Create {
            scope: OwnerFixture::project_scope(),
            name: SealedName::canonical("deploy_token").unwrap(),
            description: SealedDescription::parse("Deploy token").unwrap(),
        },
        MINT_MS,
    )
    .await
    .unwrap();

    let first = SensitiveOwnerFrame::for_write(
        &result.capability,
        Zeroizing::new(TEST_LITERAL.to_string()),
    );
    assert!(matches!(
        first
            .apply(OwnerFixture::owner(), fixture.directory(), MINT_MS)
            .await
            .unwrap(),
        SensitiveFrameOutcome::Contained { .. }
    ));

    // A genuine second apply on the same capability must fail as replay.
    let second = SensitiveOwnerFrame::for_write(
        &result.capability,
        Zeroizing::new("another-high-entropy-literal-000".to_string()),
    );
    let err = second
        .apply(OwnerFixture::owner(), fixture.directory(), MINT_MS)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("replay"), "expected replay rejection: {err}");
}

#[tokio::test]
async fn concurrent_double_apply_admits_exactly_one() {
    // Regression for the TOCTOU: with the old read-then-set-after-execute code
    // both applies would pass validation and execute. The compare-and-swap
    // consume-before-execute admits exactly one.
    let fixture = OwnerFixture::new().await;
    let result = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Create {
            scope: OwnerFixture::project_scope(),
            name: SealedName::canonical("deploy_token").unwrap(),
            description: SealedDescription::parse("Deploy token").unwrap(),
        },
        MINT_MS,
    )
    .await
    .unwrap();

    let frame_a = SensitiveOwnerFrame::for_write(
        &result.capability,
        Zeroizing::new(TEST_LITERAL.to_string()),
    );
    let frame_b = SensitiveOwnerFrame::for_write(
        &result.capability,
        Zeroizing::new("literal-b-high-entropy-1234567890".to_string()),
    );

    let (a, b) = tokio::join!(
        frame_a.apply(OwnerFixture::owner(), fixture.directory(), MINT_MS),
        frame_b.apply(OwnerFixture::owner(), fixture.directory(), MINT_MS),
    );
    let successes = [&a, &b].iter().filter(|r| r.is_ok()).count();
    assert_eq!(successes, 1, "exactly one concurrent apply may succeed");
    let loser = if a.is_err() { a } else { b };
    assert!(
        loser.unwrap_err().to_string().contains("replay"),
        "the losing apply must reject as replay"
    );
}

// ---- cancel through the real consume path ----------------------------------

#[tokio::test]
async fn cancelled_capability_rejects_later_apply() {
    let fixture = OwnerFixture::new().await;
    let result = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Create {
            scope: OwnerFixture::project_scope(),
            name: SealedName::canonical("deploy_token").unwrap(),
            description: SealedDescription::parse("Deploy token").unwrap(),
        },
        MINT_MS,
    )
    .await
    .unwrap();

    // Cancel through the same CAS apply uses.
    assert!(result.capability.cancel(), "first cancel consumes");
    assert!(!result.capability.cancel(), "second cancel is a no-op");
    assert!(result.capability.is_consumed());

    let frame = SensitiveOwnerFrame::for_write(
        &result.capability,
        Zeroizing::new(TEST_LITERAL.to_string()),
    );
    let err = frame
        .apply(OwnerFixture::owner(), fixture.directory(), MINT_MS)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("replay"),
        "apply after cancel must reject: {err}"
    );
}

// ---- 16 KiB boundary (before store touch) ----------------------------------

#[tokio::test]
async fn literal_at_16kib_is_accepted() {
    let fixture = OwnerFixture::new().await;
    let result = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Create {
            scope: OwnerFixture::project_scope(),
            name: SealedName::canonical("big_token").unwrap(),
            description: SealedDescription::parse("Big token").unwrap(),
        },
        MINT_MS,
    )
    .await
    .unwrap();
    let frame = SensitiveOwnerFrame::for_write(
        &result.capability,
        Zeroizing::new("x".repeat(MAX_SENSITIVE_FRAME_BYTES)),
    );
    assert!(
        frame
            .apply(OwnerFixture::owner(), fixture.directory(), MINT_MS)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn literal_over_16kib_is_rejected_before_consume() {
    let fixture = OwnerFixture::new().await;
    let result = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Create {
            scope: OwnerFixture::project_scope(),
            name: SealedName::canonical("big_token").unwrap(),
            description: SealedDescription::parse("Big token").unwrap(),
        },
        MINT_MS,
    )
    .await
    .unwrap();
    let frame = SensitiveOwnerFrame::for_write(
        &result.capability,
        Zeroizing::new("x".repeat(MAX_SENSITIVE_FRAME_BYTES + 1)),
    );
    let err = frame
        .apply(OwnerFixture::owner(), fixture.directory(), MINT_MS)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("exceeds"), "error should mention size: {err}");
    // Rejected before the consume point: the capability is still usable.
    assert!(!result.capability.is_consumed());
}

// ---- closed frame/disposition mapping --------------------------------------

#[tokio::test]
async fn write_frame_on_recover_capability_is_rejected() {
    let fixture = OwnerFixture::new().await;
    let record_id = seed_project_value(&fixture, "deploy_token").await;
    let result = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Recover { record_id },
        MINT_MS,
    )
    .await
    .unwrap();
    // A recover-disposition capability rejects a write frame before parse.
    let frame = SensitiveOwnerFrame::for_write(
        &result.capability,
        Zeroizing::new(TEST_LITERAL.to_string()),
    );
    let err = frame
        .apply(OwnerFixture::owner(), fixture.directory(), MINT_MS)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("frame kind"),
        "expected mapping rejection: {err}"
    );
    assert!(!result.capability.is_consumed());
}

#[tokio::test]
async fn recover_frame_on_write_capability_is_rejected() {
    let fixture = OwnerFixture::new().await;
    let record_id = seed_project_value(&fixture, "deploy_token").await;
    let result = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Rotate { record_id },
        MINT_MS,
    )
    .await
    .unwrap();
    let frame = SensitiveOwnerFrame::for_recover(&result.capability);
    let err = frame
        .apply(OwnerFixture::owner(), fixture.directory(), MINT_MS)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("frame kind"),
        "expected mapping rejection: {err}"
    );
}

// ---- rotate creates a new version; recover reveals the new literal ---------

#[tokio::test]
async fn rotate_creates_new_version_then_recover_reveals_it() {
    let fixture = OwnerFixture::new().await;
    let record_id = seed_project_value(&fixture, "deploy_token").await;

    let rotate = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Rotate { record_id },
        MINT_MS,
    )
    .await
    .unwrap();
    let frame = SensitiveOwnerFrame::for_write(
        &rotate.capability,
        Zeroizing::new("rotated-high-entropy-literal-123456".to_string()),
    );
    match frame
        .apply(OwnerFixture::owner(), fixture.directory(), 2_000)
        .await
        .unwrap()
    {
        SensitiveFrameOutcome::Contained { summary } => assert_eq!(summary.version, 2),
        _ => panic!("expected Contained"),
    }

    let recover = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Recover { record_id },
        2_000,
    )
    .await
    .unwrap();
    assert_eq!(
        recover.capability.operation().version,
        VersionBinding::Exact(2)
    );
    let frame = SensitiveOwnerFrame::for_recover(&recover.capability);
    match frame
        .apply(OwnerFixture::owner(), fixture.directory(), 2_000)
        .await
        .unwrap()
    {
        SensitiveFrameOutcome::Revealed { literal } => {
            assert_eq!(literal.as_str(), "rotated-high-entropy-literal-123456");
        }
        _ => panic!("expected Revealed"),
    }
}

// ---- wrong owner: mint-time and apply-time ---------------------------------

#[tokio::test]
async fn mint_rejects_wrong_owner() {
    let fixture = OwnerFixture::new().await;
    // Row owned by "owner"; begin under a synthetic "alice" authority.
    let record_id = seed_project_value(&fixture, "deploy_token").await;
    let err = BeginSensitiveOwnerOperation::begin(
        OwnerAuthority::for_test("alice"),
        fixture.directory(),
        BeginSensitiveInput::Recover { record_id },
        MINT_MS,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("not owned"),
        "wrong-owner begin must reject: {err}"
    );
    // No literal appears in the rejection.
    assert!(!err.contains(TEST_LITERAL));
}

#[tokio::test]
async fn apply_rejects_wrong_owner() {
    let fixture = OwnerFixture::new().await;
    // Plant an alice-owned row; begin under alice (mint succeeds, stamped
    // "alice"); apply under "owner" -> principal mismatch.
    let record_id = seed_project_value_owned(&fixture, "alice_token", "alice", TEST_LITERAL).await;
    let result = BeginSensitiveOwnerOperation::begin(
        OwnerAuthority::for_test("alice"),
        fixture.directory(),
        BeginSensitiveInput::Recover { record_id },
        MINT_MS,
    )
    .await
    .unwrap();
    assert_eq!(result.capability.owner_principal(), "alice");
    let frame = SensitiveOwnerFrame::for_recover(&result.capability);
    let err = frame
        .apply(OwnerFixture::owner(), fixture.directory(), MINT_MS)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("principal mismatch"),
        "apply under a different owner must reject: {err}"
    );
    assert!(!err.contains(TEST_LITERAL));
    // The mismatched apply did not spend the legitimate capability.
    assert!(!result.capability.is_consumed());
}

// ---- wrong scope / wrong version via craft + race --------------------------

#[tokio::test]
async fn apply_rejects_crafted_wrong_scope() {
    let fixture = OwnerFixture::new().await;
    let record_id = seed_project_value(&fixture, "deploy_token").await;
    // Craft a recover capability bound to a foreign project key.
    let crafted = OneUseCapability::craft(
        SensitiveOwnerOperation::recover(
            record_id,
            SealedScopeRef::Project(SealedProjectKey::from_canonical("otherproj")),
            1,
        ),
        "owner",
        MINT_MS,
    );
    let frame = SensitiveOwnerFrame::for_recover(&crafted);
    let err = frame
        .apply(OwnerFixture::owner(), fixture.directory(), MINT_MS)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("scope mismatch"),
        "expected scope mismatch: {err}"
    );
    assert!(!err.contains(TEST_LITERAL));
}

#[tokio::test]
async fn apply_rejects_crafted_wrong_version_no_zero_escape() {
    let fixture = OwnerFixture::new().await;
    let record_id = seed_project_value(&fixture, "deploy_token").await;
    // Version 0 is not a skip sentinel any more: an Exact(0) binding mismatches
    // the live version 1 and rejects (the old `version != 0` escape is gone).
    let crafted = OneUseCapability::craft(
        SensitiveOwnerOperation::recover(record_id, OwnerFixture::project_scope(), 0),
        "owner",
        MINT_MS,
    );
    let frame = SensitiveOwnerFrame::for_recover(&crafted);
    let err = frame
        .apply(OwnerFixture::owner(), fixture.directory(), MINT_MS)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("version mismatch"),
        "expected version mismatch: {err}"
    );
    assert!(!err.contains(TEST_LITERAL));
}

#[tokio::test]
async fn recover_after_racing_rotate_rejects_stale_version() {
    // Canonical wrong-version path: mint a recover at v1, rotate to v2, then
    // apply the stale recover -> version mismatch, superseded literal never
    // returned.
    let fixture = OwnerFixture::new().await;
    let record_id = seed_project_value(&fixture, "deploy_token").await;

    let recover = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Recover { record_id },
        MINT_MS,
    )
    .await
    .unwrap();
    assert_eq!(
        recover.capability.operation().version,
        VersionBinding::Exact(1)
    );

    // Rotate the record to v2 after the recover capability was minted.
    fixture
        .directory()
        .rotate(
            OwnerFixture::owner(),
            record_id,
            SealedLiteral::new("rotated-secret-abcdefghijklmnop"),
            2_000,
        )
        .await
        .unwrap();

    let frame = SensitiveOwnerFrame::for_recover(&recover.capability);
    let err = frame
        .apply(OwnerFixture::owner(), fixture.directory(), 2_000)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("version mismatch"),
        "expected version mismatch: {err}"
    );
    assert!(!err.contains(TEST_LITERAL));
}

#[tokio::test]
async fn concurrent_rotate_never_lets_recover_reveal_newer_value() {
    // TOCTOU regression (Finding 1): the version fence must be ATOMIC with the
    // literal read. A recover minted at v1, applied CONCURRENTLY with a rotate
    // to v2, may only ever reveal the bound v1 literal or reject — it must NEVER
    // return the v2 literal. The old separate revalidate-then-read could pass
    // revalidation at v1 and then read v2; this interleaving exercises that gap.
    const V2_LITERAL: &str = "rotated-v2-secret-abcdefghijklmno";
    let fixture = OwnerFixture::new().await;
    let record_id = seed_project_value(&fixture, "deploy_token").await; // v1 = TEST_LITERAL

    let recover = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Recover { record_id },
        MINT_MS,
    )
    .await
    .unwrap();
    assert_eq!(
        recover.capability.operation().version,
        VersionBinding::Exact(1)
    );
    let frame = SensitiveOwnerFrame::for_recover(&recover.capability);

    // Interleave an external rotate to v2 against the recover apply.
    let (rotate_result, recover_result) = tokio::join!(
        fixture.directory().rotate(
            OwnerFixture::owner(),
            record_id,
            SealedLiteral::new(V2_LITERAL),
            2_000,
        ),
        frame.apply(OwnerFixture::owner(), fixture.directory(), 2_000),
    );
    let rotated = rotate_result.expect("the external rotate itself succeeds");
    assert_eq!(rotated.version, 2, "the record advances to v2");

    match recover_result {
        Ok(SensitiveFrameOutcome::Revealed { literal }) => {
            // If the recover won the race it may only reveal the bound v1 value.
            assert_eq!(
                literal.as_str(),
                TEST_LITERAL,
                "recover may reveal only the bound v1 literal"
            );
            assert_ne!(
                literal.as_str(),
                V2_LITERAL,
                "recover must NEVER reveal the raced-in v2 literal"
            );
        }
        Ok(other) => panic!("recover produced a non-revealed outcome: {other:?}"),
        Err(err) => {
            // Or it lost the race and rejects fail-closed; never a leak.
            let err = err.to_string();
            assert!(!err.contains(V2_LITERAL));
            assert!(!err.contains(TEST_LITERAL));
        }
    }
}

#[tokio::test]
async fn session_recover_reveals_bound_literal() {
    // Deterministic session-scope recover happy path: the atomic single-query
    // session fence returns exactly the bound literal.
    use crate::sealed::tests::SealedFixture;
    let fx = SealedFixture::new().await;
    let dir = fx.directory();
    let created = dir
        .create(
            OwnerAuthority::for_test("owner"),
            CreateSealedValue {
                scope: SealedScopeRef::Session(fx.session_id),
                name: SealedName::canonical("session_token").unwrap(),
                description: SealedDescription::parse("session cred").unwrap(),
                owner_principal: "owner".to_string(),
            },
            SealedLiteral::new(TEST_LITERAL),
            1_000,
        )
        .await
        .unwrap();
    let record_id = created.record_id;

    let recover = BeginSensitiveOwnerOperation::begin(
        OwnerAuthority::for_test("owner"),
        &dir,
        BeginSensitiveInput::Recover { record_id },
        MINT_MS,
    )
    .await
    .unwrap();
    assert_eq!(
        recover.capability.operation().version,
        VersionBinding::Exact(1)
    );
    let outcome = SensitiveOwnerFrame::for_recover(&recover.capability)
        .apply(OwnerAuthority::for_test("owner"), &dir, MINT_MS)
        .await
        .unwrap();
    match outcome {
        SensitiveFrameOutcome::Revealed { literal } => assert_eq!(literal.as_str(), TEST_LITERAL),
        _ => panic!("expected Revealed"),
    }
}

#[tokio::test]
async fn concurrent_session_rotate_never_lets_recover_reveal_newer_value() {
    // Finding A regression: SESSION-scope recover must be atomic against a
    // racing session rotate. `sealed_session_literal_for_action` was a two-read
    // TOCTOU (version read then value read on a non-transactional connection);
    // a session rotate committing between them would hand a v1 claim the v2
    // plaintext. Interleave a session rotate to v2 with the recover apply of a
    // v1-bound capability; the recover may only reveal the bound v1 literal or
    // reject — never the v2 literal.
    use crate::sealed::tests::SealedFixture;
    const SESSION_V2_LITERAL: &str = "session-rotated-v2-secret-abcdefgh";
    let fx = SealedFixture::new().await;
    let dir = fx.directory();
    let created = dir
        .create(
            OwnerAuthority::for_test("owner"),
            CreateSealedValue {
                scope: SealedScopeRef::Session(fx.session_id),
                name: SealedName::canonical("session_token").unwrap(),
                description: SealedDescription::parse("session cred").unwrap(),
                owner_principal: "owner".to_string(),
            },
            SealedLiteral::new(TEST_LITERAL),
            1_000,
        )
        .await
        .unwrap();
    let record_id = created.record_id;

    let recover = BeginSensitiveOwnerOperation::begin(
        OwnerAuthority::for_test("owner"),
        &dir,
        BeginSensitiveInput::Recover { record_id },
        MINT_MS,
    )
    .await
    .unwrap();
    assert_eq!(
        recover.capability.operation().version,
        VersionBinding::Exact(1)
    );
    let frame = SensitiveOwnerFrame::for_recover(&recover.capability);

    let (rotate_result, recover_result) = tokio::join!(
        dir.rotate(
            OwnerAuthority::for_test("owner"),
            record_id,
            SealedLiteral::new(SESSION_V2_LITERAL),
            2_000,
        ),
        frame.apply(OwnerAuthority::for_test("owner"), &dir, 2_000),
    );
    let rotated = rotate_result.expect("the session rotate itself succeeds");
    assert_eq!(rotated.version, 2, "the record advances to v2");

    match recover_result {
        Ok(SensitiveFrameOutcome::Revealed { literal }) => {
            assert_eq!(
                literal.as_str(),
                TEST_LITERAL,
                "session recover may reveal only the bound v1 literal"
            );
            assert_ne!(
                literal.as_str(),
                SESSION_V2_LITERAL,
                "session recover must NEVER reveal the raced-in v2 literal"
            );
        }
        Ok(other) => panic!("recover produced a non-revealed outcome: {other:?}"),
        Err(err) => {
            let err = err.to_string();
            assert!(!err.contains(SESSION_V2_LITERAL));
            assert!(!err.contains(TEST_LITERAL));
        }
    }
}

#[tokio::test]
async fn session_literal_fence_rejects_stale_claimed_version() {
    // Direct, deterministic proof of the single-query session fence predicate:
    // once a session value is rotated past the claimed version, the atomic
    // accessor returns None — never the newer literal — and the None is the
    // fence rejecting, not the record vanishing (the live claim still resolves).
    // Complements the concurrent race test, which cannot deterministically pin
    // the interleaving against a single-statement query.
    use crate::sealed::tests::SealedFixture;
    const V2_LITERAL: &str = "session-v2-fence-secret-0123456789";
    let fx = SealedFixture::new().await;
    let dir = fx.directory();
    let created = dir
        .create(
            OwnerAuthority::for_test("owner"),
            CreateSealedValue {
                scope: SealedScopeRef::Session(fx.session_id),
                name: SealedName::canonical("session_token").unwrap(),
                description: SealedDescription::parse("session cred").unwrap(),
                owner_principal: "owner".to_string(),
            },
            SealedLiteral::new(TEST_LITERAL),
            1_000,
        )
        .await
        .unwrap();
    let record_id = created.record_id.to_string();

    // v1 is live: the claim resolves to the v1 literal.
    assert_eq!(
        fx.db
            .sealed_session_literal_for_action(record_id.clone(), 1)
            .await
            .unwrap()
            .as_deref(),
        Some(TEST_LITERAL),
    );

    // Rotate to v2.
    dir.rotate(
        OwnerAuthority::for_test("owner"),
        created.record_id,
        SealedLiteral::new(V2_LITERAL),
        2_000,
    )
    .await
    .unwrap();

    // The stale v1 claim now returns None (the fence predicate rejects it) — and
    // not because the record vanished: the live v2 claim still resolves.
    assert!(
        fx.db
            .sealed_session_literal_for_action(record_id.clone(), 1)
            .await
            .unwrap()
            .is_none(),
        "a claim for the superseded version must return None"
    );
    assert_eq!(
        fx.db
            .sealed_session_literal_for_action(record_id, 2)
            .await
            .unwrap()
            .as_deref(),
        Some(V2_LITERAL),
    );
}

#[tokio::test]
async fn crafted_wrong_version_rejects_write_frame_too() {
    let fixture = OwnerFixture::new().await;
    let record_id = seed_project_value(&fixture, "deploy_token").await;
    // A write (rotate) frame revalidates version too.
    let crafted = OneUseCapability::craft(
        SensitiveOwnerOperation::rotate(record_id, OwnerFixture::project_scope(), 99),
        "owner",
        MINT_MS,
    );
    let frame = SensitiveOwnerFrame::for_write(
        &crafted,
        Zeroizing::new("would-be-rotated-secret-0000000".to_string()),
    );
    let err = frame
        .apply(OwnerFixture::owner(), fixture.directory(), MINT_MS)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("version mismatch"),
        "expected version mismatch: {err}"
    );
}

// ---- mint-time create checks -----------------------------------------------

#[tokio::test]
async fn mint_rejects_create_over_existing_name() {
    let fixture = OwnerFixture::new().await;
    seed_project_value(&fixture, "deploy_token").await;
    let err = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Create {
            scope: OwnerFixture::project_scope(),
            name: SealedName::canonical("deploy_token").unwrap(),
            description: SealedDescription::parse("Deploy token").unwrap(),
        },
        MINT_MS,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("already exists"), "expected collision: {err}");
}

#[tokio::test]
async fn mint_rejects_unknown_record() {
    let fixture = OwnerFixture::new().await;
    let missing = SealedRecordId::generate();
    let err = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Rotate { record_id: missing },
        MINT_MS,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("does not exist"), "expected not-found: {err}");
}

// ---- redaction: no literal in outcome debug / begin response ---------------

#[tokio::test]
async fn contained_and_revealed_debug_never_render_literal() {
    let fixture = OwnerFixture::new().await;
    let record_id = seed_project_value(&fixture, "deploy_token").await;

    // Contained (create) debug.
    let create = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Create {
            scope: OwnerFixture::project_scope(),
            name: SealedName::canonical("secret_token").unwrap(),
            description: SealedDescription::parse("Secret").unwrap(),
        },
        MINT_MS,
    )
    .await
    .unwrap();
    let contained = SensitiveOwnerFrame::for_write(
        &create.capability,
        Zeroizing::new(TEST_LITERAL.to_string()),
    )
    .apply(OwnerFixture::owner(), fixture.directory(), MINT_MS)
    .await
    .unwrap();
    assert!(!format!("{contained:?}").contains(TEST_LITERAL));

    // Revealed (recover) debug is redacted even though it holds the literal.
    let recover = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Recover { record_id },
        MINT_MS,
    )
    .await
    .unwrap();
    let revealed = SensitiveOwnerFrame::for_recover(&recover.capability)
        .apply(OwnerFixture::owner(), fixture.directory(), MINT_MS)
        .await
        .unwrap();
    match &revealed {
        SensitiveFrameOutcome::Revealed { literal } => assert_eq!(literal.as_str(), TEST_LITERAL),
        _ => panic!("expected Revealed"),
    }
    assert!(!format!("{revealed:?}").contains(TEST_LITERAL));
}

#[tokio::test]
async fn begin_response_representation_carries_no_literal() {
    // The full Begin response (capability + expiry) never carries a literal:
    // begin takes none, and no field of the response holds one.
    let fixture = OwnerFixture::new().await;
    let result = BeginSensitiveOwnerOperation::begin(
        OwnerFixture::owner(),
        fixture.directory(),
        BeginSensitiveInput::Create {
            scope: OwnerFixture::project_scope(),
            name: SealedName::canonical("deploy_token").unwrap(),
            description: SealedDescription::parse("Deploy token").unwrap(),
        },
        MINT_MS,
    )
    .await
    .unwrap();
    let debug = format!("{result:?}");
    assert!(!debug.contains(TEST_LITERAL));
    assert_eq!(result.expires_at_ms, MINT_MS + CAPABILITY_TTL_MS);
}
