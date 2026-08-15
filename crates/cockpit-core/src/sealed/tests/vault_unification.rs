use super::*;
use crate::sealed::SealedCompartmentKey;
use cockpit_db::db::sealed_scope::{NewSealedValueRecord, stage_session_sealed_create_conn};
use cockpit_db::secret_vault::SecretVaultKind;

#[tokio::test]
async fn import_sealed_compartment_then_delete_file() {
    let tmp = tempfile::tempdir().unwrap();
    let db = crate::db::Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let vault = crate::secure_key::vault_for_db(&db).unwrap();
    let path = tmp.path().join("sealed-compartment.json");
    let file = SealedCompartment::at(path.clone());
    let key = SealedCompartmentKey::generate();
    file.put(&key, &SealedLiteral::new(TEST_LITERAL)).unwrap();
    assert!(path.exists());

    crate::secure_key::import_sealed_compartment_from_path(
        &vault,
        &path,
        &crate::secure_key::VaultFault::default(),
    )
    .unwrap();
    assert!(!path.exists(), "sealed-compartment.json must be deleted");

    let compartment = SealedCompartment::from_vault(vault);
    let got = compartment.get_exact(&key).unwrap().unwrap();
    assert_eq!(got.handle().expose(), TEST_LITERAL);
}

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

#[tokio::test]
async fn sealed_vault_legacy_adoption() {
    let tmp = tempfile::tempdir().unwrap();
    let db = crate::db::Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let session = db.create_session("p", "/repo", "Build").await.unwrap();
    db.blocking_write_for_sync_maintenance({
        let sid = session.session_id.to_string();
        move |conn| {
            conn.execute(
                "INSERT INTO sealed_values (session_id, value_id, value, reason, origin, created_at)
                 VALUES (?1, 'legacy', 'legacy-plaintext-literal', 'r', 'user', 1)",
                rusqlite::params![sid],
            )?;
            Ok(())
        }
    })
    .unwrap();
    let path = tmp.path().join("sealed-compartment.json");
    let file = SealedCompartment::at(path.clone());
    let key = SealedCompartmentKey::generate();
    file.put(&key, &SealedLiteral::new(TEST_LITERAL)).unwrap();

    let vault = crate::secure_key::vault_for_db(&db).unwrap();
    crate::secure_key::unify_remaining_stores(&vault, &crate::secure_key::VaultFault::default())
        .unwrap();

    let raw: Option<String> = db
        .blocking_write_for_sync_maintenance({
            let sid = session.session_id.to_string();
            move |conn| {
                Ok(conn.query_row(
                    "SELECT value FROM sealed_values WHERE session_id = ?1 AND value_id = 'legacy'",
                    rusqlite::params![sid],
                    |row| row.get(0),
                )?)
            }
        })
        .unwrap();
    assert!(
        raw.as_deref()
            .is_none_or(|v| v != "legacy-plaintext-literal"),
        "raw SQL value must not stay plaintext"
    );
    assert!(
        !path.exists()
            || !std::fs::read_to_string(&path)
                .unwrap()
                .contains(TEST_LITERAL)
    );
    let item_id =
        crate::secure_key::session_sealed_item_id(&session.session_id.to_string(), "legacy", 1);
    let got = vault
        .get_item(SecretVaultKind::SessionSealedValue, &item_id)
        .unwrap();
    assert_eq!(got.as_slice(), b"legacy-plaintext-literal");
}
