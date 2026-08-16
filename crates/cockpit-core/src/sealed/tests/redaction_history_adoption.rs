//! AC8: sealed literals journal protected redaction history wherever a literal
//! is adopted into a session — including the store's own session-OWNING
//! create/rotate (the sealed row is itself the durability event, decision 10.1)
//! — but never on a bare compartment commit (no session).
//!
//! Every case drives a production entry point — the store's session-scoped
//! `SealedValueDirectory::create` / `rotate`, `Session::set_sealed_value`, a
//! trusted `record_inference_request` whose session table already carries a
//! project-scoped sealed entry, and the LIVE production sealed-adoption route
//! `InterruptHub::seal_redaction_with_identity` via `SessionRedactionSink` —
//! and reads the durable history rows back through the db API. Session-scoped
//! create/rotate journal one Sealed row each (create v1, rotate v2) with zero
//! artifact refs and fail closed if the resolver faults; compartment-backed
//! commits (persistent scope) journal nothing.

use super::*;
use crate::redact::RedactionTable;
use crate::redact::protected_redaction_history::{RedactionArtifactKind, RedactionHistorySource};
use crate::sealed::identity::{SealedRecordId, SealedRedactionIdentity, SealedScopeKind};
use crate::session::Session;
use cockpit_db::db::Db;
use uuid::Uuid;

fn directory(fx: &SealedFixture) -> SealedValueDirectory {
    // The fixture installs a redaction-history resolver so session-scoped
    // create/rotate journal the adoption (decision 10.1).
    fx.directory()
}

async fn history_count(db: &Db) -> i64 {
    db.read(|conn| {
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM protected_redaction_history",
            [],
            |r| r.get(0),
        )?;
        Ok(n)
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn sealed_session_adoption_journals_protected_history() {
    // (a) Session-scoped store create + rotate OWN a real session, so the sealed
    //     row is itself the durability event: each journals ONE Sealed row on
    //     adoption (decision 10.1), in the same transaction that persists the
    //     sealed row, carrying the typed identity (create v1, rotate v2), the
    //     session id, and zero artifact refs. (Compartment-backed commits, which
    //     have no session, still journal nothing — cases d, e.)
    {
        let fx = SealedFixture::new().await;
        let dir = directory(&fx);
        let sid = fx.session_id.to_string();

        let created = dir
            .create(
                OwnerAuthority::for_test("owner"),
                CreateSealedValue {
                    scope: SealedScopeRef::Session(fx.session_id),
                    name: SealedName::canonical("deploy_token").unwrap(),
                    description: SealedDescription::parse("deploy credential").unwrap(),
                    owner_principal: "owner".to_string(),
                },
                SealedLiteral::new("sealed-session-adopt-literal-one-abc"),
                1_000,
            )
            .await
            .unwrap();
        let rid = created.record_id.to_string();

        let rows = fx.db.protected_redaction_history_list(&sid).await.unwrap();
        assert_eq!(
            rows.len(),
            1,
            "session-scoped store create journals one Sealed row on adoption"
        );
        assert_eq!(rows[0].source, RedactionHistorySource::Sealed);
        assert_eq!(
            rows[0].sealed_record_id.as_deref(),
            Some(rid.as_str()),
            "the create carries the typed sealed record id"
        );
        assert_eq!(rows[0].sealed_version, Some(1), "create adopts version 1");
        assert_eq!(rows[0].session_id, sid);
        assert_eq!(
            rows[0].ref_count, 0,
            "the session adoption is the durability event: zero artifact refs"
        );

        // Rotate journals a second Sealed row at version 2 under the same record.
        dir.rotate(
            OwnerAuthority::for_test("owner"),
            created.record_id,
            SealedLiteral::new("sealed-session-adopt-literal-two-xyz"),
            2_000,
        )
        .await
        .unwrap();
        let rows = fx.db.protected_redaction_history_list(&sid).await.unwrap();
        assert_eq!(
            rows.len(),
            2,
            "session-scoped store rotate journals a second Sealed row on adoption"
        );
        let rotated_row = rows
            .iter()
            .find(|row| row.sealed_version == Some(2))
            .expect("rotate journals version 2");
        assert_eq!(rotated_row.source, RedactionHistorySource::Sealed);
        assert_eq!(
            rotated_row.sealed_record_id.as_deref(),
            Some(rid.as_str()),
            "the rotate carries the same record id at the bumped version"
        );
        assert_eq!(rotated_row.session_id, sid);
        assert_eq!(
            rotated_row.ref_count, 0,
            "the rotate adoption is the durability event: zero artifact refs"
        );
        assert!(
            rows.iter().any(|row| row.sealed_version == Some(1)),
            "the version-1 create row remains alongside the rotation"
        );
    }

    // (a2) Fail-closed: a session-scoped create/rotate whose redaction-history
    //      resolver faults rolls the WHOLE operation back — no sealed row, no
    //      history row — so a sealed literal is never persisted half-journaled or
    //      unjournaled (decisions 10.1 + 16).
    {
        use crate::redact::protected_redaction_history::{
            RedactionHistoryKey, RedactionKeyResolver,
        };

        struct FaultedKeyResolver;
        #[async_trait::async_trait]
        impl RedactionKeyResolver for FaultedKeyResolver {
            async fn ensure_active(&self) -> anyhow::Result<i64> {
                anyhow::bail!("key store offline")
            }
            async fn ensure_version(&self, _version: i64) -> anyhow::Result<()> {
                anyhow::bail!("key store offline")
            }
            fn resolve(&self, _version: i64) -> anyhow::Result<RedactionHistoryKey> {
                anyhow::bail!("key store offline")
            }
            fn active_version(&self) -> anyhow::Result<i64> {
                anyhow::bail!("key store offline")
            }
        }

        let fx = SealedFixture::new().await;
        let dir = SealedValueDirectory::new(fx.db.clone(), fx.compartment.clone())
            .with_redaction_resolver(std::sync::Arc::new(FaultedKeyResolver));

        let create_result = dir
            .create(
                OwnerAuthority::for_test("owner"),
                CreateSealedValue {
                    scope: SealedScopeRef::Session(fx.session_id),
                    name: SealedName::canonical("faulted_token").unwrap(),
                    description: SealedDescription::parse("deploy credential").unwrap(),
                    owner_principal: "owner".to_string(),
                },
                SealedLiteral::new("sealed-session-faulted-literal-abc"),
                1_000,
            )
            .await;
        assert!(
            create_result.is_err(),
            "a faulted resolver must fail the session-scoped create closed"
        );
        assert_eq!(
            history_count(&fx.db).await,
            0,
            "a rolled-back create journals nothing"
        );
        assert!(
            !fx.db
                .sealed_value_exists(fx.session_id, "faulted_token")
                .await
                .unwrap(),
            "a rolled-back create persists no sealed row"
        );

        // Seed a resolvable session value with a working directory, then prove a
        // faulted rotate rolls back leaving the value at its pre-rotate version.
        let seeded = fx
            .directory()
            .create(
                OwnerAuthority::for_test("owner"),
                CreateSealedValue {
                    scope: SealedScopeRef::Session(fx.session_id),
                    name: SealedName::canonical("rotate_token").unwrap(),
                    description: SealedDescription::parse("deploy credential").unwrap(),
                    owner_principal: "owner".to_string(),
                },
                SealedLiteral::new("sealed-session-prerotate-literal-abc"),
                1_000,
            )
            .await
            .unwrap();
        let history_after_seed = history_count(&fx.db).await;

        let rotate_result = dir
            .rotate(
                OwnerAuthority::for_test("owner"),
                seeded.record_id,
                SealedLiteral::new("sealed-session-faulted-rotate-literal-xyz"),
                2_000,
            )
            .await;
        assert!(
            rotate_result.is_err(),
            "a faulted resolver must fail the session-scoped rotate closed"
        );
        assert_eq!(
            history_count(&fx.db).await,
            history_after_seed,
            "a rolled-back rotate journals nothing (no extra history row)"
        );
        let after = fx
            .db
            .sealed_value_record(seeded.record_id.to_string())
            .await
            .unwrap()
            .expect("seeded record still exists");
        assert_eq!(
            after.active_version, 1,
            "a rolled-back rotate leaves the sealed row at its pre-rotate version"
        );
    }

    // (b) `Session::set_sealed_value` adopts a legacy session literal (no record
    //     id / version) and journals one Sealed row.
    {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Session::create_for_test(
            db.clone(),
            std::path::PathBuf::from("/proj"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let table = RedactionTable::empty();
        session
            .set_sealed_value(
                OwnerAuthority::for_test("owner"),
                &table,
                "prod_token",
                "high-entropy-sealed-session-value-123",
                "deploy",
                "user",
            )
            .await
            .unwrap();

        let sid = session.id.to_string();
        let rows = db.protected_redaction_history_list(&sid).await.unwrap();
        assert_eq!(rows.len(), 1, "set_sealed_value journals one row");
        assert_eq!(rows[0].source, RedactionHistorySource::Sealed);
        assert_eq!(
            rows[0].sealed_record_id, None,
            "a legacy session entry has no record id"
        );
        assert_eq!(rows[0].sealed_version, None);
        assert_eq!(rows[0].session_id, sid);
    }

    // (c) A trusted request whose session table already carries a *project*-scoped
    //     sealed entry journals it on first match, with the typed record id /
    //     version from the identity.
    {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Session::create_for_test(
            db.clone(),
            std::path::PathBuf::from("/proj"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let record_id = SealedRecordId::generate();
        const SEALED_LIT: &str = "project-sealed-literal-in-session-000";
        let identity = SealedRedactionIdentity {
            scope: SealedScopeKind::Project,
            record_id: Some(record_id),
            name: SealedName::canonical("deploy_token").unwrap(),
            version: 7,
        };
        let table = RedactionTable::empty()
            .with_forced_sealed_literal(SEALED_LIT.to_string(), identity)
            .unwrap();

        let call_id = Uuid::new_v4();
        session
            .record_inference_request(
                call_id,
                &serde_json::json!({"messages": [{"content": format!("uses {SEALED_LIT}")}]}),
                crate::db::session_log::InferenceRequestStatus::Completed,
                &table,
                true,
            )
            .await
            .unwrap();

        let sid = session.id.to_string();
        let rid = record_id.to_string();
        let rows = db.protected_redaction_history_list(&sid).await.unwrap();
        assert_eq!(rows.len(), 1, "the matched project sealed literal journals");
        assert_eq!(rows[0].source, RedactionHistorySource::Sealed);
        assert_eq!(rows[0].sealed_record_id.as_deref(), Some(rid.as_str()));
        assert_eq!(rows[0].sealed_version, Some(7));
        let req_refs = db
            .protected_redaction_artifact_refs_for_artifact(
                RedactionArtifactKind::Request,
                &call_id.to_string(),
            )
            .await
            .unwrap();
        assert_eq!(req_refs.len(), 1, "trusted request attaches a Request ref");
    }

    // (d) A compartment-backed (project-scope) create runs the whole
    //     prepare/stage/commit saga and journals NOTHING — no zero-ref orphan.
    {
        let fx = SealedFixture::new().await;
        let dir = directory(&fx);
        dir.create(
            OwnerAuthority::for_test("owner"),
            CreateSealedValue {
                scope: SealedScopeRef::Project(fx.project_key.clone()),
                name: SealedName::canonical("proj_secret").unwrap(),
                description: SealedDescription::parse("project credential").unwrap(),
                owner_principal: "owner".to_string(),
            },
            SealedLiteral::new(TEST_LITERAL),
            3_000,
        )
        .await
        .unwrap();
        assert_eq!(
            history_count(&fx.db).await,
            0,
            "compartment-backed commit_create journals nothing"
        );
    }

    // (e) A saga that fails before session adoption (staged but never committed)
    //     journals nothing.
    {
        let fx = SealedFixture::new().await;
        let dir = directory(&fx);
        let ticket = dir
            .prepare_create(
                OwnerAuthority::for_test("owner"),
                CreateSealedValue {
                    scope: SealedScopeRef::Project(fx.project_key.clone()),
                    name: SealedName::canonical("proj_secret_2").unwrap(),
                    description: SealedDescription::parse("project credential").unwrap(),
                    owner_principal: "owner".to_string(),
                },
                4_000,
            )
            .await
            .unwrap();
        dir.stage_literal(&ticket, SealedLiteral::new(TEST_LITERAL))
            .unwrap();
        // Never commit: no session ever adopts the literal.
        assert_eq!(
            history_count(&fx.db).await,
            0,
            "a saga that fails before session adoption journals nothing"
        );
    }

    // (f) The LIVE production path: `InterruptHub::seal_redaction_with_identity`
    //     via `SessionRedactionSink` (the route `SealedRuntime::use_sealed_value`
    //     drives) journals one Sealed row atomically with the redaction-table
    //     persist, carrying the typed identity — and re-adopting the same literal
    //     dedups to an attach.
    {
        use crate::engine::interrupt::InterruptHub;
        use crate::sealed::runtime::{SealedRedactionSink, SessionRedactionSink};

        let db = crate::db::Db::open_in_memory().unwrap();
        let session = std::sync::Arc::new(
            Session::create_for_test(
                db.clone(),
                std::path::PathBuf::from("/proj"),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        let redaction: crate::daemon::SharedRedactionTable = std::sync::Arc::new(
            std::sync::RwLock::new(std::sync::Arc::new(RedactionTable::empty())),
        );
        let (events, _rx) = tokio::sync::broadcast::channel(16);
        let hub = std::sync::Arc::new(InterruptHub::new(
            events,
            redaction.clone(),
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1)),
            db.clone(),
            session.id,
        ));
        let sink = SessionRedactionSink::new(hub.clone(), session.clone());

        let record_id = SealedRecordId::generate();
        const LIVE_LIT: &str = "live-sealed-adoption-literal-abc-000";
        let identity = SealedRedactionIdentity {
            scope: SealedScopeKind::Project,
            record_id: Some(record_id),
            name: SealedName::canonical("deploy_token").unwrap(),
            version: 4,
        };
        sink.register_before_use(&SealedLiteral::new(LIVE_LIT), &identity)
            .await
            .unwrap();

        let sid = session.id.to_string();
        let rid = record_id.to_string();
        let rows = db.protected_redaction_history_list(&sid).await.unwrap();
        assert_eq!(rows.len(), 1, "the live seal path journals one Sealed row");
        assert_eq!(rows[0].source, RedactionHistorySource::Sealed);
        assert_eq!(rows[0].sealed_record_id.as_deref(), Some(rid.as_str()));
        assert_eq!(rows[0].sealed_version, Some(4));
        assert_eq!(rows[0].session_id, sid);
        assert_eq!(
            rows[0].ref_count, 0,
            "the redaction-table adoption is the durability event: zero artifact refs"
        );

        // The live redaction table now scrubs the literal, and the persisted
        // table reflects the adoption — the swap happened only because the
        // journal committed.
        let live = redaction.read().unwrap().clone();
        assert!(!live.scrub(LIVE_LIT).contains(LIVE_LIT));
        assert!(
            !session
                .persisted_redaction_table()
                .unwrap()
                .unwrap()
                .scrub(LIVE_LIT)
                .contains(LIVE_LIT)
        );

        // Re-adopting the SAME literal dedups to an attach: still one row.
        sink.register_before_use(&SealedLiteral::new(LIVE_LIT), &identity)
            .await
            .unwrap();
        let rows = db.protected_redaction_history_list(&sid).await.unwrap();
        assert_eq!(
            rows.len(),
            1,
            "re-adopting the same sealed literal dedups (no duplicate row)"
        );
    }

    // (g) The LIVE path is fail-closed and atomic: when journaling cannot
    //     complete (key store unavailable), the WHOLE adoption rolls back — no
    //     history row, and the live/persisted redaction table is never swapped to
    //     the unioned-but-unjournaled table.
    {
        use crate::engine::interrupt::InterruptHub;
        use crate::redact::protected_redaction_history::{
            RedactionHistoryKey, RedactionKeyResolver,
        };
        use crate::sealed::runtime::{SealedRedactionSink, SessionRedactionSink};

        struct FailingKeyResolver;
        #[async_trait::async_trait]
        impl RedactionKeyResolver for FailingKeyResolver {
            async fn ensure_active(&self) -> anyhow::Result<i64> {
                anyhow::bail!("key store offline")
            }
            async fn ensure_version(&self, _version: i64) -> anyhow::Result<()> {
                anyhow::bail!("key store offline")
            }
            fn resolve(&self, _version: i64) -> anyhow::Result<RedactionHistoryKey> {
                anyhow::bail!("key store offline")
            }
            fn active_version(&self) -> anyhow::Result<i64> {
                anyhow::bail!("key store offline")
            }
        }

        let db = crate::db::Db::open_in_memory().unwrap();
        let session = std::sync::Arc::new(
            Session::create_for_test(
                db.clone(),
                std::path::PathBuf::from("/proj"),
                "Build",
                std::sync::Arc::new(FailingKeyResolver),
            )
            .unwrap(),
        );
        let redaction: crate::daemon::SharedRedactionTable = std::sync::Arc::new(
            std::sync::RwLock::new(std::sync::Arc::new(RedactionTable::empty())),
        );
        let (events, _rx) = tokio::sync::broadcast::channel(16);
        let hub = std::sync::Arc::new(InterruptHub::new(
            events,
            redaction.clone(),
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1)),
            db.clone(),
            session.id,
        ));
        let sink = SessionRedactionSink::new(hub.clone(), session.clone());

        let identity = SealedRedactionIdentity {
            scope: SealedScopeKind::Project,
            record_id: Some(SealedRecordId::generate()),
            name: SealedName::canonical("deploy_token").unwrap(),
            version: 1,
        };
        const LIT: &str = "fail-closed-sealed-literal-xyz-000";
        let result = sink
            .register_before_use(&SealedLiteral::new(LIT), &identity)
            .await;
        assert!(
            result.is_err(),
            "a journaling failure must fail the sealed adoption closed"
        );

        assert_eq!(
            history_count(&db).await,
            0,
            "a rolled-back adoption journals nothing"
        );
        // The live table was never swapped and nothing was persisted: the
        // literal is NOT redacted (no half-adoption).
        let live = redaction.read().unwrap().clone();
        assert!(
            live.scrub(LIT).contains(LIT),
            "the live redaction table must not adopt the literal when journaling fails"
        );
        assert!(
            session.persisted_redaction_table().unwrap().is_none(),
            "no redaction table is persisted when the adoption rolls back"
        );
    }
}

/// H1 regression: a NON-sealed redaction-table writer (approved-secret-file
/// registration) running concurrently with a sealed adoption must lose NEITHER
/// literal. The sealed literal must survive in both the live and the durable
/// table (its egress redaction and its history row must stay consistent), and
/// the secret-file literal must survive in the live table. Both writers
/// serialize on the `InterruptHub`'s per-session `redaction_table_write_lock`
/// and each unions its delta onto the LATEST table read under that lock, so no
/// committed union is ever clobbered — even though the sealed adoption holds the
/// lock across an `await` window (key load + AEAD + journal transaction) here
/// widened by a delaying key resolver to force real contention.
#[tokio::test]
async fn concurrent_sealed_adoption_and_secret_file_registration_lose_neither_literal() {
    use crate::engine::interrupt::InterruptHub;
    use crate::redact::protected_redaction_history::{
        MapKeyResolver, RedactionHistoryKey, RedactionKeyResolver,
    };
    use crate::sealed::runtime::{SealedRedactionSink, SessionRedactionSink};

    // A key resolver whose async `ensure_active` sleeps, widening the sealed
    // adoption's locked await window so the concurrent registration is forced to
    // contend for the write lock while the adoption is mid-flight (holding it).
    struct DelayingKeyResolver {
        inner: MapKeyResolver,
        delay: std::time::Duration,
    }
    #[async_trait::async_trait]
    impl RedactionKeyResolver for DelayingKeyResolver {
        async fn ensure_active(&self) -> anyhow::Result<i64> {
            tokio::time::sleep(self.delay).await;
            self.inner.ensure_active().await
        }
        async fn ensure_version(&self, version: i64) -> anyhow::Result<()> {
            self.inner.ensure_version(version).await
        }
        fn resolve(&self, version: i64) -> anyhow::Result<RedactionHistoryKey> {
            self.inner.resolve(version)
        }
        fn active_version(&self) -> anyhow::Result<i64> {
            self.inner.active_version()
        }
    }

    let tmp = tempfile::TempDir::new().unwrap();
    let secret_env = tmp.path().join("approved.env");
    const FILE_LIT: &str = "approved-secret-file-literal-abcdefghij-000";
    std::fs::write(&secret_env, format!("APPROVED_TOKEN={FILE_LIT}\n")).unwrap();

    let db = crate::db::Db::open_in_memory().unwrap();
    let resolver = std::sync::Arc::new(DelayingKeyResolver {
        inner: MapKeyResolver::new().with_version(1, [7u8; 32]),
        delay: std::time::Duration::from_millis(150),
    });
    let session = std::sync::Arc::new(
        Session::create_for_test(db.clone(), tmp.path().to_path_buf(), "Build", resolver).unwrap(),
    );
    let redaction: crate::daemon::SharedRedactionTable = std::sync::Arc::new(
        std::sync::RwLock::new(std::sync::Arc::new(RedactionTable::empty())),
    );
    let (events, _rx) = tokio::sync::broadcast::channel(16);
    let hub = std::sync::Arc::new(InterruptHub::new(
        events,
        redaction.clone(),
        std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1)),
        db.clone(),
        session.id,
    ));

    const SEALED_LIT: &str = "concurrent-sealed-literal-klmnop-000";
    let identity = SealedRedactionIdentity {
        scope: SealedScopeKind::Project,
        record_id: Some(SealedRecordId::generate()),
        name: SealedName::canonical("deploy_token").unwrap(),
        version: 2,
    };
    let cfg = crate::config::extended::RedactConfig::default();

    // Drive both writers concurrently. `tokio::join!` polls the sealed adoption
    // first, so it grabs the write lock and parks in its delayed journal; the
    // registration then contends for the SAME lock and, once it wins, unions onto
    // the committed adoption instead of a stale snapshot.
    let sink = SessionRedactionSink::new(hub.clone(), session.clone());
    let sealed_literal = SealedLiteral::new(SEALED_LIT);
    let seal_fut = sink.register_before_use(&sealed_literal, &identity);
    let reg_hub = hub.clone();
    let reg_session = session.clone();
    let reg_cfg = cfg.clone();
    let reg_path = secret_env.clone();
    let reg_fut = async move {
        // Yield first so the sealed adoption reaches the lock ahead of us.
        tokio::task::yield_now().await;
        reg_hub
            .register_approved_secret_file(&reg_session, &reg_cfg, &reg_path)
            .await
    };
    let (seal_res, reg_res) = tokio::join!(seal_fut, reg_fut);
    seal_res.expect("sealed adoption succeeds");
    reg_res
        .expect("registration does not error")
        .expect("approved-secret-file registration returns a table");

    // The final LIVE table scrubs BOTH literals — neither writer clobbered the
    // other's committed union.
    let live = redaction.read().unwrap().clone();
    assert!(
        !live.scrub(SEALED_LIT).contains(SEALED_LIT),
        "the sealed literal survives in the live table despite the concurrent registration"
    );
    assert!(
        !live.scrub(FILE_LIT).contains(FILE_LIT),
        "the approved-secret-file literal survives in the live table despite the concurrent sealed adoption"
    );

    // The DURABLE table keeps the sealed literal (disk-derived approved-file
    // values are intentionally excluded from persistence). This is the core H1
    // property: a concurrent non-sealed persist did NOT drop the committed sealed
    // adoption from `redaction_table_json`, so the live table and the still-
    // committed history row stay consistent (decision 10.1 adopted-table invariant).
    let persisted = session.persisted_redaction_table().unwrap().unwrap();
    assert!(
        !persisted.scrub(SEALED_LIT).contains(SEALED_LIT),
        "the sealed literal survives in the durable redaction table"
    );

    // Exactly one Sealed history row committed and remains.
    let rows = db
        .protected_redaction_history_list(&session.id.to_string())
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "the sealed adoption journaled exactly one row"
    );
    assert_eq!(rows[0].source, RedactionHistorySource::Sealed);
}
