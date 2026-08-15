//! AC2 `sealed_cross_store_lifecycle_sagas`
//!
//! Every crash boundary of the create / rotate / delete sagas, plus verified
//! rollback, cleanup, version pinning, name collision, name reuse, and the
//! absence of any resolvable partial state.

use super::*;
use crate::sealed::SealedCompartmentKey;
use crate::sealed::identity::SealedRecordId;

/// Is this record currently resolvable *and* is its literal actually there?
///
/// "No resolvable partial state" means these two must never disagree: a record
/// the authorization layer would accept must always have a literal behind it.
async fn resolvable_with_literal(fixture: &SealedFixture, record_id: SealedRecordId) -> bool {
    let Some(row) = fixture
        .db
        .sealed_value_record(record_id.to_string())
        .await
        .expect("record read")
    else {
        return false;
    };
    if !row.is_resolvable() {
        return false;
    }
    let Some(raw) = row.compartment_key.as_deref() else {
        // Session scope: literal lives in the wrap-key vault; metadata stays in SQLite.
        let Some(vault) = fixture.compartment.vault() else {
            return false;
        };
        let item_id = crate::secure_key::session_sealed_item_id(
            &row.scope_key,
            &row.name,
            row.active_version,
        );
        return vault
            .get_item(
                cockpit_db::secret_vault::SecretVaultKind::SessionSealedValue,
                &item_id,
            )
            .is_ok();
    };
    let key = SealedCompartmentKey::parse(raw).expect("locator parses");
    fixture
        .compartment
        .get_exact(&key)
        .expect("exact read")
        .is_some()
}

async fn literal_of(fixture: &SealedFixture, record_id: SealedRecordId) -> Option<String> {
    let row = fixture
        .db
        .sealed_value_record(record_id.to_string())
        .await
        .expect("record read")?;
    let raw = row.compartment_key.as_deref()?;
    let key = SealedCompartmentKey::parse(raw).expect("locator parses");
    fixture
        .compartment
        .get_exact(&key)
        .expect("exact read")
        .map(|literal| literal.handle().expose().to_string())
}

/// Live (unrevoked) grants on one record.
async fn live_grants(fixture: &SealedFixture, record_id: SealedRecordId) -> i64 {
    fixture
        .db
        .read({
            let record_id = record_id.to_string();
            move |conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(1) FROM sealed_action_grants
                      WHERE record_id = ?1 AND revoked_at_ms IS NULL",
                    rusqlite::params![record_id],
                    |row| row.get(0),
                )?)
            }
        })
        .await
        .expect("grant count")
}

fn create_request(fixture: &SealedFixture, name: &str) -> CreateSealedValue {
    CreateSealedValue {
        scope: SealedScopeRef::Project(fixture.project_key.clone()),
        name: SealedName::canonical(name).expect("name"),
        description: SealedDescription::parse("deployment credential").expect("description"),
        owner_principal: "owner".to_string(),
    }
}

#[tokio::test]
async fn sealed_cross_store_lifecycle_sagas() {
    let owner = SealedFixture::owner();

    // =====================================================================
    // CREATE — crash after prepare, before the literal is staged.
    // =====================================================================
    {
        let fixture = SealedFixture::new().await;
        let directory = fixture.directory();
        let ticket = directory
            .prepare_create(owner, create_request(&fixture, "deploy_token"), 1_000)
            .await
            .expect("prepared");
        assert!(
            !resolvable_with_literal(&fixture, ticket.record_id).await,
            "a staged create is never resolvable"
        );

        let report = directory.recover(owner).await.expect("recovery");
        assert_eq!(report.rolled_back, vec![ticket.op_id.clone()]);
        assert!(report.rolled_forward.is_empty());
        assert!(
            fixture
                .db
                .sealed_value_record(ticket.record_id.to_string())
                .await
                .expect("record read")
                .is_none(),
            "rollback removes the staged record entirely"
        );
        assert!(
            fixture
                .db
                .unresolved_sealed_value_sagas()
                .await
                .expect("saga list")
                .is_empty(),
            "recovery leaves no unresolved saga"
        );
        // The name was never live, so it was never tombstoned and stays free.
        directory
            .create(
                owner,
                create_request(&fixture, "deploy_token"),
                SealedLiteral::new(TEST_LITERAL),
                2_000,
            )
            .await
            .expect("a rolled-back name is still available");
    }

    // =====================================================================
    // CREATE — crash after the literal is staged, before commit.
    // =====================================================================
    {
        let fixture = SealedFixture::new().await;
        let directory = fixture.directory();
        let ticket = directory
            .prepare_create(owner, create_request(&fixture, "deploy_token"), 1_000)
            .await
            .expect("prepared");
        directory
            .stage_literal(&ticket, SealedLiteral::new(TEST_LITERAL))
            .expect("staged literal");
        let staged_key = ticket.staged_key.clone().expect("staged locator");
        assert!(
            fixture
                .compartment
                .get_exact(&staged_key)
                .expect("exact read")
                .is_some(),
            "the literal is staged in the compartment"
        );
        assert!(
            !resolvable_with_literal(&fixture, ticket.record_id).await,
            "a staged-but-uncommitted create is still not resolvable"
        );

        directory.recover(owner).await.expect("recovery");
        assert!(
            fixture
                .compartment
                .get_exact(&staged_key)
                .expect("exact read")
                .is_none(),
            "rollback reclaims the staged literal — no orphan in the compartment"
        );
        assert!(
            fixture
                .db
                .sealed_value_record(ticket.record_id.to_string())
                .await
                .expect("record read")
                .is_none()
        );
    }

    // =====================================================================
    // CREATE — crash after commit, before saga cleanup. Rolls forward.
    // =====================================================================
    {
        let fixture = SealedFixture::new().await;
        let directory = fixture.directory();
        let ticket = directory
            .prepare_create(owner, create_request(&fixture, "deploy_token"), 1_000)
            .await
            .expect("prepared");
        directory
            .stage_literal(&ticket, SealedLiteral::new(TEST_LITERAL))
            .expect("staged literal");
        let summary = directory
            .commit_create(owner, &ticket, 2_000)
            .await
            .expect("committed");
        assert_eq!(summary.version, 1);
        assert!(resolvable_with_literal(&fixture, ticket.record_id).await);

        let report = directory.recover(owner).await.expect("recovery");
        assert_eq!(report.rolled_forward, vec![ticket.op_id.clone()]);
        assert!(report.rolled_back.is_empty());
        assert!(
            resolvable_with_literal(&fixture, ticket.record_id).await,
            "a committed create stays live through recovery"
        );
        assert_eq!(
            literal_of(&fixture, ticket.record_id).await.as_deref(),
            Some(TEST_LITERAL)
        );
    }

    // =====================================================================
    // ROTATE — crash before commit. Previous version stays live.
    // =====================================================================
    {
        let fixture = SealedFixture::new().await;
        let directory = fixture.directory();
        let seeded = fixture
            .seed_value(
                SealedScopeRef::Project(fixture.project_key.clone()),
                "deploy_token",
            )
            .await;
        let old_key = SealedCompartmentKey::parse(
            fixture
                .db
                .sealed_value_record(seeded.record_id.to_string())
                .await
                .expect("record read")
                .expect("record")
                .compartment_key
                .as_deref()
                .expect("locator"),
        )
        .expect("locator parses");

        let ticket = directory
            .prepare_rotate(owner, seeded.record_id, 3_000)
            .await
            .expect("prepared rotate");
        assert_eq!(ticket.target_version, 2, "rotation bumps monotonically");
        directory
            .stage_literal(&ticket, SealedLiteral::new("rotated-literal-value-0002"))
            .expect("staged literal");

        // Mid-saga the old version is still the live one.
        assert_eq!(
            literal_of(&fixture, seeded.record_id).await.as_deref(),
            Some(TEST_LITERAL),
            "the previous version serves until the rotation commits"
        );

        let report = directory.recover(owner).await.expect("recovery");
        assert_eq!(report.rolled_back, vec![ticket.op_id.clone()]);
        let staged_key = ticket.staged_key.clone().expect("staged locator");
        assert!(
            fixture
                .compartment
                .get_exact(&staged_key)
                .expect("exact read")
                .is_none(),
            "rollback reclaims the staged rotation literal"
        );
        let row = fixture
            .db
            .sealed_value_record(seeded.record_id.to_string())
            .await
            .expect("record read")
            .expect("record");
        assert_eq!(row.active_version, 1, "rollback keeps the previous version");
        assert_eq!(row.compartment_key.as_deref(), Some(old_key.as_str()));
        assert_eq!(
            literal_of(&fixture, seeded.record_id).await.as_deref(),
            Some(TEST_LITERAL)
        );
    }

    // =====================================================================
    // ROTATE — crash after commit, before cleanup. Superseded key reclaimed.
    // =====================================================================
    {
        let fixture = SealedFixture::new().await;
        let directory = fixture.directory();
        let seeded = fixture
            .seed_value(
                SealedScopeRef::Project(fixture.project_key.clone()),
                "deploy_token",
            )
            .await;
        let old_key = SealedCompartmentKey::parse(
            fixture
                .db
                .sealed_value_record(seeded.record_id.to_string())
                .await
                .expect("record read")
                .expect("record")
                .compartment_key
                .as_deref()
                .expect("locator"),
        )
        .expect("locator parses");

        let ticket = directory
            .prepare_rotate(owner, seeded.record_id, 3_000)
            .await
            .expect("prepared rotate");
        directory
            .stage_literal(&ticket, SealedLiteral::new("rotated-literal-value-0002"))
            .expect("staged literal");
        let rotated = directory
            .commit_rotate(owner, &ticket, 4_000)
            .await
            .expect("committed rotate");
        assert_eq!(rotated.version, 2);
        // The superseded literal is still in the compartment at this instant.
        assert!(
            fixture
                .compartment
                .get_exact(&old_key)
                .expect("exact read")
                .is_some()
        );

        let report = directory.recover(owner).await.expect("recovery");
        assert_eq!(report.rolled_forward, vec![ticket.op_id.clone()]);
        assert!(
            fixture
                .compartment
                .get_exact(&old_key)
                .expect("exact read")
                .is_none(),
            "roll-forward reclaims the superseded literal"
        );
        assert_eq!(
            literal_of(&fixture, seeded.record_id).await.as_deref(),
            Some("rotated-literal-value-0002")
        );
    }

    // =====================================================================
    // DELETE — crash after prepare. Denies immediately, rolls forward.
    // =====================================================================
    {
        let fixture = SealedFixture::new().await;
        let directory = fixture.directory();
        let seeded = fixture
            .seed_value(
                SealedScopeRef::Project(fixture.project_key.clone()),
                "deploy_token",
            )
            .await;
        let key = SealedCompartmentKey::parse(
            fixture
                .db
                .sealed_value_record(seeded.record_id.to_string())
                .await
                .expect("record read")
                .expect("record")
                .compartment_key
                .as_deref()
                .expect("locator"),
        )
        .expect("locator parses");

        let ticket = directory
            .prepare_delete(owner, seeded.record_id, 5_000)
            .await
            .expect("prepared delete");
        assert!(
            !resolvable_with_literal(&fixture, seeded.record_id).await,
            "a prepared delete denies use from that instant"
        );

        let report = directory.recover(owner).await.expect("recovery");
        assert_eq!(report.rolled_forward, vec![ticket.op_id.clone()]);
        assert!(
            fixture
                .db
                .sealed_value_record(seeded.record_id.to_string())
                .await
                .expect("record read")
                .is_none(),
            "roll-forward reclaims the record row"
        );
        assert!(
            fixture
                .compartment
                .get_exact(&key)
                .expect("exact read")
                .is_none(),
            "roll-forward reclaims the literal"
        );

        // Deleted names are never reused.
        let error = directory
            .create(
                owner,
                create_request(&fixture, "deploy_token"),
                SealedLiteral::new(TEST_LITERAL),
                6_000,
            )
            .await
            .expect_err("a retired name is never reusable");
        assert!(error.to_string().contains("never reused"), "{error}");
    }

    // =====================================================================
    // DELETE converting a *committed* rotation whose cleanup has not run.
    //
    // The rotation published the new locator and still owes cleanup of the
    // pre-rotation one, so at this instant two literals are live in the
    // compartment and a single saga row owes both. The delete inherits that
    // debt. Regression: the conversion used to overwrite the saga's
    // `superseded_compartment_key` with the record's *current* key, which
    // after a committed rotation is the new one. Both slots then named the
    // same locator, recovery reclaimed it twice, and the pre-rotation literal
    // stayed on disk forever with nothing referencing it.
    // =====================================================================
    {
        let fixture = SealedFixture::new().await;
        let directory = fixture.directory();
        let seeded = fixture
            .seed_value(
                SealedScopeRef::Project(fixture.project_key.clone()),
                "deploy_token",
            )
            .await;
        let pre_rotation_key = SealedCompartmentKey::parse(
            fixture
                .db
                .sealed_value_record(seeded.record_id.to_string())
                .await
                .expect("record read")
                .expect("record")
                .compartment_key
                .as_deref()
                .expect("locator"),
        )
        .expect("locator parses");

        let rotate_ticket = directory
            .prepare_rotate(owner, seeded.record_id, 5_000)
            .await
            .expect("prepared rotate");
        directory
            .stage_literal(
                &rotate_ticket,
                SealedLiteral::new("rotated-literal-value-0003"),
            )
            .expect("staged literal");
        directory
            .commit_rotate(owner, &rotate_ticket, 5_100)
            .await
            .expect("committed rotate");

        let live_key = SealedCompartmentKey::parse(
            fixture
                .db
                .sealed_value_record(seeded.record_id.to_string())
                .await
                .expect("record read")
                .expect("record")
                .compartment_key
                .as_deref()
                .expect("locator"),
        )
        .expect("locator parses");
        // Compared as keys, not strings: the type's `Debug` deliberately
        // redacts, so a failure here cannot print a live locator.
        assert_ne!(
            live_key, pre_rotation_key,
            "the rotation must have published a distinct locator"
        );
        // Cleanup has not run: both literals are on disk right now.
        for key in [&pre_rotation_key, &live_key] {
            assert!(
                fixture
                    .compartment
                    .get_exact(key)
                    .expect("exact read")
                    .is_some(),
                "both literals are live before the delete converts the saga"
            );
        }

        // Delete before the rotation's cleanup runs; then crash.
        let delete_ticket = directory
            .prepare_delete(owner, seeded.record_id, 5_200)
            .await
            .expect("prepared delete");
        assert!(
            !resolvable_with_literal(&fixture, seeded.record_id).await,
            "a prepared delete denies use from that instant"
        );

        let report = directory.recover(owner).await.expect("recovery");
        assert_eq!(report.rolled_forward, vec![delete_ticket.op_id.clone()]);
        assert!(
            fixture
                .db
                .sealed_value_record(seeded.record_id.to_string())
                .await
                .expect("record read")
                .is_none(),
            "roll-forward reclaims the record row"
        );
        // The point of the case: *neither* literal may survive. The
        // pre-rotation one is the one the old code stranded.
        assert!(
            fixture
                .compartment
                .get_exact(&pre_rotation_key)
                .expect("exact read")
                .is_none(),
            "the pre-rotation literal must not be stranded by a delete that \
             converted a committed rotation"
        );
        assert!(
            fixture
                .compartment
                .get_exact(&live_key)
                .expect("exact read")
                .is_none(),
            "the deleted value's live literal must be reclaimed"
        );
    }

    // =====================================================================
    // Name collision within a scope, and independence across scopes.
    // =====================================================================
    {
        let fixture = SealedFixture::new().await;
        let directory = fixture.directory();
        directory
            .create(
                owner,
                create_request(&fixture, "deploy_token"),
                SealedLiteral::new(TEST_LITERAL),
                1_000,
            )
            .await
            .expect("first create");
        // Canonicalization means a differently-cased/spaced name collides.
        let collision = directory
            .create(
                owner,
                create_request(&fixture, "  Deploy_Token  "),
                SealedLiteral::new(TEST_LITERAL),
                2_000,
            )
            .await;
        assert!(
            collision.is_err(),
            "canonical names are unique within a scope"
        );

        // The same canonical name in a different scope is a different value.
        directory
            .create(
                owner,
                CreateSealedValue {
                    scope: SealedScopeRef::Global,
                    name: SealedName::canonical("deploy_token").expect("name"),
                    description: SealedDescription::parse("org credential").expect("description"),
                    owner_principal: "owner".to_string(),
                },
                SealedLiteral::new(TEST_LITERAL),
                3_000,
            )
            .await
            .expect("global scope is independent of project scope");
    }

    // =====================================================================
    // A Session rotation between claim and read denies; it never substitutes.
    // =====================================================================
    {
        let fixture = SealedFixture::new().await;
        let seeded = fixture
            .seed_value(SealedScopeRef::Session(fixture.session_id), "session_token")
            .await;
        // Issue a real grant, or the fencing assertion below is vacuous.
        fixture
            .directory()
            .issue_action_grant(
                owner,
                crate::sealed::IssueSealedGrant {
                    record_id: seeded.record_id,
                    value_version: 1,
                    project_key: fixture.project_key.clone(),
                    session_id: fixture.session_id,
                    session_generation: 0,
                    action_id: crate::sealed::SealedActionId::parse("probe.publish")
                        .expect("action id"),
                    action_revision: crate::sealed::SealedActionRevision::new(1).expect("revision"),
                    issued_at_ms: 2_000,
                    expires_at_ms: None,
                },
            )
            .await
            .expect("grant issued");
        assert_eq!(
            live_grants(&fixture, seeded.record_id).await,
            1,
            "the grant is live before rotation"
        );

        fixture
            .directory()
            .rotate(
                owner,
                seeded.record_id,
                SealedLiteral::new("rotated-session-literal-02"),
                4_000,
            )
            .await
            .expect("session rotate");

        // A claim pinned to v1 is denied, not silently handed the v2 literal.
        assert!(
            fixture
                .db
                .sealed_session_literal_for_action(seeded.record_id.to_string(), 1)
                .await
                .expect("session literal read")
                .is_none(),
            "a v1 claim must be denied after rotation, never served the v2 literal"
        );
        // v2 still resolves for a caller that claimed v2.
        assert_eq!(
            fixture
                .db
                .sealed_session_literal_for_action(seeded.record_id.to_string(), 2)
                .await
                .expect("session literal read")
                .as_deref(),
            Some("rotated-session-literal-02")
        );
        // And Session rotation fences grants exactly as persistent rotation does.
        assert_eq!(
            live_grants(&fixture, seeded.record_id).await,
            0,
            "session rotation fences every outstanding grant"
        );
    }

    // =====================================================================
    // Session scope is a single store: atomic, no saga, no partial state.
    // =====================================================================
    {
        let fixture = SealedFixture::new().await;
        let directory = fixture.directory();
        let seeded = fixture
            .seed_value(SealedScopeRef::Session(fixture.session_id), "session_token")
            .await;
        assert_eq!(seeded.version, 1);
        assert!(resolvable_with_literal(&fixture, seeded.record_id).await);
        assert!(
            fixture
                .db
                .unresolved_sealed_value_sagas()
                .await
                .expect("saga list")
                .is_empty(),
            "session scope never opens a cross-store saga"
        );

        let rotated = directory
            .rotate(
                owner,
                seeded.record_id,
                SealedLiteral::new("rotated-session-literal-02"),
                4_000,
            )
            .await
            .expect("session rotate");
        assert_eq!(rotated.version, 2);
        assert_eq!(
            fixture
                .db
                .sealed_session_literal_for_action(seeded.record_id.to_string(), 2)
                .await
                .expect("session literal read")
                .as_deref(),
            Some("rotated-session-literal-02")
        );

        assert!(
            directory
                .delete(owner, seeded.record_id, 5_000)
                .await
                .expect("session delete")
        );
        assert!(
            fixture
                .db
                .sealed_session_literal_for_action(seeded.record_id.to_string(), 2)
                .await
                .expect("session literal read")
                .is_none(),
            "deleting a session record deletes its literal in the same transaction"
        );
        assert!(
            fixture
                .db
                .sealed_value_name_retired(
                    crate::sealed::SealedScopeKind::Session,
                    fixture.session_id.to_string(),
                    "session_token".to_string()
                )
                .await
                .expect("tombstone read"),
            "session names are tombstoned too"
        );
    }

    // =====================================================================
    // Recovery is idempotent: running it twice changes nothing.
    // =====================================================================
    {
        let fixture = SealedFixture::new().await;
        let directory = fixture.directory();
        let seeded = fixture
            .seed_value(
                SealedScopeRef::Project(fixture.project_key.clone()),
                "deploy_token",
            )
            .await;
        assert!(directory.recover(owner).await.expect("recovery").is_empty());
        assert!(directory.recover(owner).await.expect("recovery").is_empty());
        assert!(resolvable_with_literal(&fixture, seeded.record_id).await);
    }
}
