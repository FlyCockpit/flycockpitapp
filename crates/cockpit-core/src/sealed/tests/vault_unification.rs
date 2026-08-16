use super::*;
use cockpit_db::db::sealed_scope::{NewSealedValueRecord, stage_session_sealed_create_conn};

#[tokio::test]
async fn sealed_vault_create_rotate_delete_preserves_invariants() {
    let fixture = SealedFixture::new().await;
    let directory = fixture.directory();
    let owner = SealedFixture::owner();
    let created = directory
        .create(
            owner,
            CreateSealedValue {
                scope: SealedScopeRef::Project(fixture.project_key.clone()),
                name: SealedName::canonical("deploy_token").unwrap(),
                description: SealedDescription::parse("deployment credential").unwrap(),
                owner_principal: "owner".into(),
            },
            SealedLiteral::new(TEST_LITERAL),
            1_000,
        )
        .await
        .unwrap();
    assert_eq!(created.version, 1);
    let row = fixture
        .db
        .sealed_value_record(created.record_id.to_string())
        .await
        .unwrap()
        .unwrap();
    assert!(row.is_resolvable());

    let rotated = directory
        .rotate(
            owner,
            created.record_id,
            SealedLiteral::new("sk-live-rotated-literal-aaaaaaaaaaaa"),
            2_000,
        )
        .await
        .unwrap();
    assert_eq!(rotated.version, 2);

    assert!(
        directory
            .delete(owner, created.record_id, 3_000)
            .await
            .unwrap()
    );
    let gone = fixture
        .db
        .sealed_value_record(created.record_id.to_string())
        .await
        .unwrap();
    assert!(gone.is_none() || gone.unwrap().deleted_at_ms.is_some());
    let tombstoned: i64 = fixture
        .db
        .read({
            let key = fixture.project_key.as_str().to_string();
            move |conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(1) FROM sealed_value_name_tombstones
                      WHERE scope = 'project' AND scope_key = ?1 AND name = 'deploy_token'",
                    rusqlite::params![key],
                    |row| row.get(0),
                )?)
            }
        })
        .await
        .unwrap();
    assert_eq!(tombstoned, 1);
}

#[tokio::test]
async fn sealed_vault_stale_grant_rejected_after_rotate() {
    let fixture = SealedFixture::new().await;
    let directory = fixture.directory();
    let owner = SealedFixture::owner();
    let created = directory
        .create(
            owner,
            CreateSealedValue {
                scope: SealedScopeRef::Session(fixture.session_id),
                name: SealedName::canonical("session_token").unwrap(),
                description: SealedDescription::parse("deployment credential").unwrap(),
                owner_principal: "owner".into(),
            },
            SealedLiteral::new(TEST_LITERAL),
            1_000,
        )
        .await
        .unwrap();
    directory
        .issue_action_grant(
            owner,
            crate::sealed::store::IssueSealedGrant {
                record_id: created.record_id,
                value_version: 1,
                project_key: fixture.project_key.clone(),
                session_id: fixture.session_id,
                session_generation: 0,
                action_id: crate::sealed::action::SealedActionId::parse(PROBE_ACTION).unwrap(),
                action_revision: crate::sealed::action::SealedActionRevision::new(1).unwrap(),
                issued_at_ms: 1_000,
                expires_at_ms: None,
            },
        )
        .await
        .unwrap();
    directory
        .rotate(
            owner,
            created.record_id,
            SealedLiteral::new("sk-live-rotated-literal-bbbbbbbbbbbb"),
            2_000,
        )
        .await
        .unwrap();

    let record = fixture
        .db
        .sealed_value_record(created.record_id.to_string())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.active_version, 2);
    let grant_version: i64 = fixture
        .db
        .read({
            let record_id = created.record_id.to_string();
            move |conn| {
                Ok(conn.query_row(
                    "SELECT value_version FROM sealed_action_grants WHERE record_id = ?1",
                    rusqlite::params![record_id],
                    |row| row.get(0),
                )?)
            }
        })
        .await
        .unwrap();
    assert_eq!(grant_version, 1);
    assert_ne!(
        grant_version, record.active_version,
        "grant pinned to v1 must not resolve v2"
    );
}

#[tokio::test]
async fn sealed_vault_crash_recovery_create_rolls_back() {
    let fixture = SealedFixture::new().await;
    let record = NewSealedValueRecord {
        record_id: crate::sealed::identity::SealedRecordId::generate().to_string(),
        scope: cockpit_db::db::sealed_scope::SealedScopeKind::Session,
        scope_key: fixture.session_id.to_string(),
        name: "crash_create".into(),
        description: "deployment credential".into(),
        owner_principal: "owner".into(),
        created_at_ms: 1_000,
    };
    fixture
        .db
        .transaction({
            let record = record.clone();
            move |conn| {
                stage_session_sealed_create_conn(conn, &record, "reason", "origin")?;
                Ok(())
            }
        })
        .await
        .unwrap();
    let row = fixture
        .db
        .sealed_value_record(record.record_id.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.active_version, 0);
    assert!(!row.is_resolvable());
}

#[tokio::test]
async fn sealed_vault_crash_recovery_delete_rolls_forward() {
    let fixture = SealedFixture::new().await;
    let directory = fixture.directory();
    let owner = SealedFixture::owner();
    let created = directory
        .create(
            owner,
            CreateSealedValue {
                scope: SealedScopeRef::Project(fixture.project_key.clone()),
                name: SealedName::canonical("delete_token").unwrap(),
                description: SealedDescription::parse("deployment credential").unwrap(),
                owner_principal: "owner".into(),
            },
            SealedLiteral::new(TEST_LITERAL),
            1_000,
        )
        .await
        .unwrap();
    let ticket = directory
        .prepare_delete(owner, created.record_id, 2_000)
        .await
        .unwrap();
    let report = directory.recover(owner).await.unwrap();
    assert!(report.rolled_forward.contains(&ticket.op_id));
    let tombstoned: i64 = fixture
        .db
        .read({
            let key = fixture.project_key.as_str().to_string();
            move |conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(1) FROM sealed_value_name_tombstones
                      WHERE scope = 'project' AND scope_key = ?1 AND name = 'delete_token'",
                    rusqlite::params![key],
                    |row| row.get(0),
                )?)
            }
        })
        .await
        .unwrap();
    assert_eq!(tombstoned, 1);
}
