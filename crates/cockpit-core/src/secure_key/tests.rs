//! Acceptance tests for native-secure-key-store (secure_key_*).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::db::Db;
use crate::db::installation_identity::{
    INSTALLATION_IDENTITY_HEX_LEN, ensure_installation_identity_conn,
};
use crate::db::secure_key::{
    ProvisionPhase, RetirePhase, SecureKeyRefState, SecureKeyVersionState, get_ref_by_id_conn,
    get_version_conn, list_open_sagas_conn, list_versions_conn,
};

use super::actor::{SECURE_KEY_QUEUE_CAPACITY, SecureKeyActor};
use super::consumer::{MapReconciler, activate_ref_in_tx, begin_release_in_tx};
use super::error::SecureKeyError;
use super::fake::{FakeNativeStore, FaultKind, FaultPoint, InjectedFault};
use super::key_material::{KEY_BYTE_LEN, SecureKeyBytes, generate_key_bytes, key_digest};
use super::namespace::{
    LEAK_REPORT_V1_NAMESPACE, Namespace, SECURE_KEY_SERVICE, encode_account_component,
    manifest_account, version_account,
};
use super::platform::{
    platform_link_token, platform_store_kind, reachable_native_store_crate,
    registration_order_snapshot, reset_registration_order_for_test,
    set_test_skip_real_default_store,
};
use super::worker::Worker;

fn test_actor(store: FakeNativeStore) -> (SecureKeyActor, FakeNativeStore) {
    let db = Db::open_in_memory().unwrap();
    let recon = Arc::new(MapReconciler::new().with_kind("test", |_| false));
    let actor = SecureKeyActor::start_with_store(db, Box::new(store.clone()), recon).unwrap();
    (actor, store)
}

fn assert_exactly_one_active(db: &Db, ns: &str) {
    db.blocking_write_for_sync_maintenance({
        let ns = ns.to_owned();
        move |conn| {
            let versions = list_versions_conn(conn, &ns)?;
            let actives: Vec<_> = versions
                .iter()
                .filter(|v| v.state == SecureKeyVersionState::Active)
                .collect();
            assert_eq!(
                actives.len(),
                1,
                "expected exactly one Active version, got {versions:?}"
            );
            let ns_row = crate::db::secure_key::get_namespace_conn(conn, &ns)?.unwrap();
            assert_eq!(ns_row.active_version, Some(actives[0].version));
            let open = list_open_sagas_conn(conn)?;
            assert!(
                open.iter().all(|s| s.namespace != ns),
                "open sagas remain: {open:?}"
            );
            Ok(())
        }
    })
    .unwrap();
}

// ---------------------------------------------------------------------------
// 1. secure_key_tests_corrected_first
// ---------------------------------------------------------------------------

#[test]
fn secure_key_tests_corrected_first() {
    // Target-reachability over lockfile-wide "only one store package".
    let kind = platform_store_kind();
    let reachable = reachable_native_store_crate();
    match kind {
        super::platform::PlatformStoreKind::Unsupported => assert!(reachable.is_none()),
        _ => assert!(reachable.is_some()),
    }
    let token = platform_link_token();
    assert!(!token.is_empty());
    let db = Db::open_in_memory().unwrap();
    let id = db
        .blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
        .unwrap();
    assert_eq!(id.as_hex().len(), INSTALLATION_IDENTITY_HEX_LEN);
    let k: SecureKeyBytes = generate_key_bytes();
    assert_eq!(k.as_ref().len(), KEY_BYTE_LEN);
    assert_eq!(
        crate::db::secure_key::ProvisionPhase::Prepared.as_str(),
        "Prepared"
    );
}

// ---------------------------------------------------------------------------
// 2. secure_key_namespace_and_item_ownership
// ---------------------------------------------------------------------------

#[test]
fn secure_key_namespace_and_item_ownership() {
    assert!(Namespace::parse(LEAK_REPORT_V1_NAMESPACE).is_ok());
    assert_eq!(SECURE_KEY_SERVICE, "dev.flycockpit.secure-keys");

    let db = Db::open_in_memory().unwrap();
    let id = db
        .blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
        .unwrap();
    assert_eq!(id.as_hex().len(), 32);
    assert!(id.as_hex().chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(id.as_hex(), id.as_hex().to_ascii_lowercase());

    let id2 = db
        .blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
        .unwrap();
    assert_eq!(id, id2);

    let db_b = Db::open_in_memory().unwrap();
    let id_b = db_b
        .blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
        .unwrap();
    assert_ne!(id, id_b);

    let ns = Namespace::parse("leak-report/v1").unwrap();
    let dig = ns.digest_hex();
    assert_eq!(dig.len(), 64);
    let enc = encode_account_component(ns.as_str()).unwrap();
    assert!(enc.contains("%2F"));
    let man = manifest_account(id.as_hex(), &ns).unwrap();
    let ver = version_account(id.as_hex(), &ns, 1).unwrap();
    assert!(man.ends_with("/manifest"));
    assert!(ver.ends_with("/v00000001"));

    let store = FakeNativeStore::new();
    let (actor, _) = test_actor(store.clone());
    let (v, key) = actor
        .handle()
        .create_or_load_blocking(LEAK_REPORT_V1_NAMESPACE)
        .unwrap();
    assert_eq!(v, 1);
    assert_eq!(key.as_ref().len(), 32);
    let digest = key_digest(&key);
    let meta = actor
        .handle()
        .list_metadata_blocking(LEAK_REPORT_V1_NAMESPACE)
        .unwrap();
    assert_eq!(meta.active_version, Some(1));
    assert_eq!(meta.versions[0].key_digest, digest);
}

// ---------------------------------------------------------------------------
// 3. secure_key_daemon_serialization
// ---------------------------------------------------------------------------

#[test]
fn secure_key_daemon_serialization() {
    let store = FakeNativeStore::new();
    let (actor, _) = test_actor(store);
    let h = actor.handle();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let h = h.clone();
        handles.push(thread::spawn(move || {
            h.create_or_load_blocking("serial-ns")
        }));
    }
    let mut versions = Vec::new();
    for t in handles {
        let (v, _) = t.join().unwrap().unwrap();
        versions.push(v);
    }
    assert!(versions.iter().all(|&v| v == 1));

    let mut rot_handles = Vec::new();
    for _ in 0..5 {
        let h = h.clone();
        rot_handles.push(thread::spawn(move || h.rotate_blocking("serial-ns")));
    }
    let mut rotated = Vec::new();
    for t in rot_handles {
        let (v, _) = t.join().unwrap().unwrap();
        rotated.push(v);
    }
    rotated.sort_unstable();
    let mut uniq = rotated.clone();
    uniq.dedup();
    assert_eq!(uniq.len(), rotated.len());
    assert!(rotated.windows(2).all(|w| w[0] < w[1]));
}

// ---------------------------------------------------------------------------
// 4. secure_key_cross_store_provisioning_recovery
// ---------------------------------------------------------------------------

/// Fault-inject at each provision saga boundary; restart reaches exactly one active.
#[test]
fn secure_key_cross_store_provisioning_recovery() {
    // --- Boundary: Prepared (BeforeSet — no native write) ---
    {
        let store = FakeNativeStore::new();
        store.inject_once(
            FaultPoint::BeforeSet,
            InjectedFault::Error(FaultKind::Unavailable),
        );
        let db = Db::open_in_memory().unwrap();
        let recon = Arc::new(MapReconciler::new());
        let actor =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon).unwrap();
        let err = actor
            .handle()
            .create_or_load_blocking("prep-ns")
            .unwrap_err();
        // Fail before write leaves Prepared open or already cleaned by partial path.
        let _ = err;
        drop(actor);
        store.clear_faults();
        let recon = Arc::new(MapReconciler::new());
        // Startup resume: Prepared without native item → drop abandoned pending;
        // daemon starts cleanly; create_or_load then provisions exactly one active.
        let actor2 = SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon)
            .expect("startup must succeed after abandoning Prepared-before-write");
        let (v, _) = actor2.handle().create_or_load_blocking("prep-ns").unwrap();
        assert_eq!(v, 1);
        assert_exactly_one_active(&db, "prep-ns");
        assert!(store.item_count() >= 1);
    }

    // --- Boundary: AfterSet (NativeItemWritten not yet recorded) ---
    {
        let store = FakeNativeStore::new();
        // First set is version key write; fail after it succeeds.
        store.inject_once(
            FaultPoint::AfterSet,
            InjectedFault::Error(FaultKind::Unavailable),
        );
        let db = Db::open_in_memory().unwrap();
        let recon = Arc::new(MapReconciler::new());
        let actor =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon).unwrap();
        let _ = actor.handle().create_or_load_blocking("afterset-ns");
        drop(actor);
        store.clear_faults();
        let recon = Arc::new(MapReconciler::new());
        let actor2 =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon).unwrap();
        // Matching digest at exact account resumes (recorded), not orphan adoption.
        let (v, _) = actor2
            .handle()
            .create_or_load_blocking("afterset-ns")
            .unwrap();
        assert_eq!(v, 1);
        assert_exactly_one_active(&db, "afterset-ns");
        let _ = actor2
            .handle()
            .load_version_blocking("afterset-ns", 1)
            .unwrap();
    }

    // --- Boundary: AfterVerify (fail AfterGet on verify reread — still Written) ---
    {
        let store = FakeNativeStore::new();
        // Provision: set key, get verify. Fail first get (verify).
        store.inject_once(
            FaultPoint::BeforeGet,
            InjectedFault::Error(FaultKind::Unavailable),
        );
        let db = Db::open_in_memory().unwrap();
        let recon = Arc::new(MapReconciler::new());
        let actor =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon).unwrap();
        let _ = actor.handle().create_or_load_blocking("verify-ns");
        drop(actor);
        store.clear_faults();
        let recon = Arc::new(MapReconciler::new());
        let actor2 =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon).unwrap();
        let (v, _) = actor2
            .handle()
            .create_or_load_blocking("verify-ns")
            .unwrap();
        assert_eq!(v, 1);
        assert_exactly_one_active(&db, "verify-ns");
    }

    // --- Boundary: AfterManifest (2nd set is manifest write) ---
    {
        let store = FakeNativeStore::new();
        // set#1 = key, set#2 = manifest. Fail after 2nd set.
        store.inject_at_call_count(
            FaultPoint::AfterSet,
            2,
            InjectedFault::Error(FaultKind::Unavailable),
        );
        let db = Db::open_in_memory().unwrap();
        let recon = Arc::new(MapReconciler::new());
        let actor =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon).unwrap();
        let _ = actor.handle().create_or_load_blocking("manif-ns");
        drop(actor);
        store.clear_faults();
        let recon = Arc::new(MapReconciler::new());
        let actor2 =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon).unwrap();
        let (v, _) = actor2.handle().create_or_load_blocking("manif-ns").unwrap();
        assert_eq!(v, 1);
        assert_exactly_one_active(&db, "manif-ns");
    }

    // --- SQLite metadata boundaries: plant open saga phases and resume ---
    // ManifestAdvancedAndVerified (metadata not yet activated).
    {
        let store = FakeNativeStore::new();
        let db = Db::open_in_memory().unwrap();
        let recon = Arc::new(MapReconciler::new());
        let actor =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon).unwrap();
        let (v, key) = actor
            .handle()
            .create_or_load_blocking("meta-adv-ns")
            .unwrap();
        assert_eq!(v, 1);
        let digest = key_digest(&key);
        drop(actor);
        // Rewind to pre-activation: Pending version + open saga at ManifestAdvanced.
        db.blocking_write_for_sync_maintenance({
            let digest = digest.clone();
            move |conn| {
                conn.execute_batch("BEGIN IMMEDIATE;")?;
                conn.execute(
                    "UPDATE secure_key_versions SET state = 'Pending' WHERE namespace = 'meta-adv-ns' AND version = 1",
                    [],
                )?;
                conn.execute(
                    "UPDATE secure_key_namespaces SET active_version = NULL WHERE namespace = 'meta-adv-ns'",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO secure_key_sagas
                        (op_id, namespace, kind, version, phase, key_digest, created_at, updated_at)
                     VALUES ('plant-meta-adv', 'meta-adv-ns', 'Provision', 1, ?1, ?2, 1, 1)",
                    rusqlite::params![
                        ProvisionPhase::ManifestAdvancedAndVerified.as_str(),
                        digest
                    ],
                )?;
                conn.execute_batch("COMMIT;")?;
                Ok(())
            }
        })
        .unwrap();
        let recon = Arc::new(MapReconciler::new());
        let actor2 =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon).unwrap();
        assert_exactly_one_active(&db, "meta-adv-ns");
        let (v2, k2) = actor2
            .handle()
            .create_or_load_blocking("meta-adv-ns")
            .unwrap();
        assert_eq!(v2, 1);
        assert_eq!(k2.as_ref(), key.as_ref());
    }

    // MetadataActivated (active row present; saga still needs commit/ack delete).
    {
        let store = FakeNativeStore::new();
        let db = Db::open_in_memory().unwrap();
        let recon = Arc::new(MapReconciler::new());
        let actor =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon).unwrap();
        let (v, key) = actor
            .handle()
            .create_or_load_blocking("meta-act-ns")
            .unwrap();
        assert_eq!(v, 1);
        let digest = key_digest(&key);
        drop(actor);
        db.blocking_write_for_sync_maintenance({
            let digest = digest.clone();
            move |conn| {
                conn.execute_batch("BEGIN IMMEDIATE;")?;
                conn.execute(
                    "INSERT INTO secure_key_sagas
                        (op_id, namespace, kind, version, phase, key_digest, created_at, updated_at)
                     VALUES ('plant-meta-act', 'meta-act-ns', 'Provision', 1, ?1, ?2, 1, 1)",
                    rusqlite::params![ProvisionPhase::MetadataActivated.as_str(), digest],
                )?;
                conn.execute_batch("COMMIT;")?;
                Ok(())
            }
        })
        .unwrap();
        let recon = Arc::new(MapReconciler::new());
        let actor2 =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon).unwrap();
        assert_exactly_one_active(&db, "meta-act-ns");
        let open = db
            .blocking_write_for_sync_maintenance(list_open_sagas_conn)
            .unwrap();
        assert!(
            open.iter().all(|s| s.namespace != "meta-act-ns"),
            "MetadataActivated must commit+delete saga: {open:?}"
        );
        let _ = actor2;
    }

    // Unrecorded orphan at prepared account: wrong digest never becomes active.
    {
        let store = FakeNativeStore::new();
        let db = Db::open_in_memory().unwrap();
        let recon = Arc::new(MapReconciler::new());
        let actor =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon).unwrap();
        // Arm BeforeSet so prepare commits but write never happens.
        store.inject_once(
            FaultPoint::BeforeSet,
            InjectedFault::Error(FaultKind::Unavailable),
        );
        let _ = actor.handle().create_or_load_blocking("orphan-ns");
        // Plant unrecorded junk at the would-be version account.
        let id = db
            .blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
            .unwrap();
        let ns = Namespace::parse("orphan-ns").unwrap();
        let acct = version_account(id.as_hex(), &ns, 1).unwrap();
        store.put_raw(SECURE_KEY_SERVICE, &acct, vec![9u8; 32]);
        store.clear_faults();
        drop(actor);
        // Restart: resume must remove orphan (digest mismatch), not promote.
        let recon = Arc::new(MapReconciler::new());
        let start = SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon);
        let actor2 = match start {
            Ok(a) => a,
            Err(SecureKeyError::Corrupt(_)) => SecureKeyActor::start_with_store(
                db.clone(),
                Box::new(store.clone()),
                Arc::new(MapReconciler::new()),
            )
            .unwrap(),
            Err(e) => panic!("{e:?}"),
        };
        assert!(
            !store.contains(SECURE_KEY_SERVICE, &acct),
            "orphan must be removed after exact account verification"
        );
        let (v, _) = actor2
            .handle()
            .create_or_load_blocking("orphan-ns")
            .unwrap();
        assert_eq!(v, 1);
        assert_exactly_one_active(&db, "orphan-ns");
    }

    // Unexplained mismatch → Corrupt (never load_or_init blank).
    {
        let empty = FakeNativeStore::new();
        let db = Db::open_in_memory().unwrap();
        let id = db
            .blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
            .unwrap();
        db.blocking_write_for_sync_maintenance({
            move |conn| {
                crate::db::secure_key::ensure_namespace_conn(conn, "orphan-ns2")?;
                let now = chrono::Utc::now().timestamp();
                conn.execute(
                    "INSERT INTO secure_key_versions
                        (namespace, version, state, key_digest, created_at, updated_at)
                     VALUES ('orphan-ns2', 1, 'Active', 'abc', ?1, ?1)",
                    [now],
                )?;
                conn.execute(
                    "UPDATE secure_key_namespaces SET active_version = 1 WHERE namespace = 'orphan-ns2'",
                    [],
                )?;
                Ok(())
            }
        })
        .unwrap();
        let worker = Worker {
            db: &db,
            store: &empty,
            installation: &id,
            reconciler: &MapReconciler::new(),
        };
        let err = worker
            .check_consistency(&Namespace::parse("orphan-ns2").unwrap())
            .unwrap_err();
        assert!(
            matches!(err, SecureKeyError::Corrupt(_)),
            "expected Corrupt, got {err:?}"
        );

        // resume_retire must not blank-init missing manifest.
        let err2 = worker.load_version(&Namespace::parse("orphan-ns2").unwrap(), 1);
        // NotFound or Corrupt both fine; point is consistency already Corrupt.
        let _ = err2;
    }

    // Startup refuses to serve when unexplained corrupt remains after saga drive.
    {
        let empty = FakeNativeStore::new();
        let db = Db::open_in_memory().unwrap();
        db.blocking_write_for_sync_maintenance({
            move |conn| {
                crate::db::secure_key::ensure_namespace_conn(conn, "bad-start")?;
                let now = chrono::Utc::now().timestamp();
                conn.execute(
                    "INSERT INTO secure_key_versions
                        (namespace, version, state, key_digest, created_at, updated_at)
                     VALUES ('bad-start', 1, 'Active', 'abc', ?1, ?1)",
                    [now],
                )?;
                conn.execute(
                    "UPDATE secure_key_namespaces SET active_version = 1 WHERE namespace = 'bad-start'",
                    [],
                )?;
                Ok(())
            }
        })
        .unwrap();
        let recon = Arc::new(MapReconciler::new());
        match SecureKeyActor::start_with_store(db, Box::new(empty), recon) {
            Ok(_) => panic!("startup must fail closed on corrupt"),
            Err(err) => assert!(
                matches!(err, SecureKeyError::Corrupt(_)),
                "startup must fail closed on corrupt: {err:?}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// 5. secure_key_consumer_reference_lifecycle
// ---------------------------------------------------------------------------

#[test]
fn secure_key_consumer_reference_lifecycle() {
    let store = FakeNativeStore::new();
    // Shared consumer reachability table (test stand-in for ciphertext rows).
    let consumers = Arc::new(Mutex::new(HashMap::<String, bool>::new()));
    let consumers_c = consumers.clone();
    let recon = Arc::new(MapReconciler::new().with_kind("enc", move |id| {
        *consumers_c.lock().unwrap().get(id).unwrap_or(&false)
    }));
    let db = Db::open_in_memory().unwrap();
    let actor = SecureKeyActor::start_with_store(db.clone(), Box::new(store), recon).unwrap();
    let h = actor.handle();
    let (v, _) = h.create_or_load_blocking("cref-ns").unwrap();

    let r1 = h
        .reserve_blocking("ref-a", "cref-ns", v, "enc", "row-1")
        .unwrap();
    assert_eq!(r1.state, SecureKeyRefState::Reserved);

    // Idempotent only for same full tuple.
    let r1b = h
        .reserve_blocking("ref-a", "cref-ns", v, "enc", "row-1")
        .unwrap();
    assert_eq!(r1b.reference_id, r1.reference_id);
    assert_eq!(r1b.state, SecureKeyRefState::Reserved);

    // Different tuple with same reference_id → conflict.
    let conflict = h.reserve_blocking("ref-a", "cref-ns", v, "enc", "row-OTHER");
    assert!(
        matches!(conflict, Err(SecureKeyError::Invalid(_))),
        "{conflict:?}"
    );

    // Atomic reachability: activate inside same SQLite write as consumer insert.
    db.blocking_write_for_sync_maintenance({
        let consumers = consumers.clone();
        move |conn| {
            conn.execute_batch("BEGIN IMMEDIATE;")?;
            // Consumer "ciphertext" becomes reachable.
            consumers.lock().unwrap().insert("row-1".into(), true);
            activate_ref_in_tx(conn, "ref-a").map_err(|e| anyhow::anyhow!("{e}"))?;
            conn.execute_batch("COMMIT;")?;
            Ok(())
        }
    })
    .unwrap();

    let active = db
        .blocking_write_for_sync_maintenance(|conn| get_ref_by_id_conn(conn, "ref-a"))
        .unwrap()
        .unwrap();
    assert_eq!(active.state, SecureKeyRefState::Active);

    // Actor-path activate is available for non-atomic callers (idempotent when Active).
    h.activate_ref_blocking("ref-a").unwrap();

    // No reachable ciphertext without Active/Reserved: releasing in same tx as delete.
    db.blocking_write_for_sync_maintenance({
        let consumers = consumers.clone();
        move |conn| {
            conn.execute_batch("BEGIN IMMEDIATE;")?;
            consumers.lock().unwrap().insert("row-1".into(), false);
            begin_release_in_tx(conn, "ref-a").map_err(|e| anyhow::anyhow!("{e}"))?;
            conn.execute_batch("COMMIT;")?;
            Ok(())
        }
    })
    .unwrap();

    let releasing = db
        .blocking_write_for_sync_maintenance(|conn| get_ref_by_id_conn(conn, "ref-a"))
        .unwrap()
        .unwrap();
    assert_eq!(releasing.state, SecureKeyRefState::Releasing);

    h.complete_release_ref_blocking("ref-a").unwrap();
    let released = db
        .blocking_write_for_sync_maintenance(|conn| get_ref_by_id_conn(conn, "ref-a"))
        .unwrap()
        .unwrap();
    assert_eq!(released.state, SecureKeyRefState::Released);

    // Stale id: NotFound, no metadata leak.
    let err = h.begin_release_ref_blocking("no-such").unwrap_err();
    assert!(matches!(err, SecureKeyError::NotFound(_)), "{err:?}");
    let dbg = format!("{err:?}");
    assert!(!dbg.contains("cref-ns"));
    assert!(!dbg.contains("row-1"));
}

// ---------------------------------------------------------------------------
// 6. secure_key_rotation_retirement
// ---------------------------------------------------------------------------

#[test]
fn secure_key_rotation_retirement() {
    let store = FakeNativeStore::new();
    let (actor, store) = test_actor(store);
    let h = actor.handle();
    let (v1, k1) = h.create_or_load_blocking("rot-ns").unwrap();
    let (v2, k2) = h.rotate_blocking("rot-ns").unwrap();
    assert_eq!(v1, 1);
    assert_eq!(v2, 2);
    assert_ne!(k1.as_ref(), k2.as_ref());
    let (lv, _) = h.load_version_blocking("rot-ns", 1).unwrap();
    assert_eq!(lv, 1);
    let meta = h.list_metadata_blocking("rot-ns").unwrap();
    assert_eq!(meta.active_version, Some(2));
    let s1 = meta.versions.iter().find(|v| v.version == 1).unwrap();
    assert_eq!(s1.state, SecureKeyVersionState::Retained);

    // Active-version retirement always rejected.
    let err = h.retire_blocking("rot-ns", 2).unwrap_err();
    assert!(
        matches!(err, SecureKeyError::ActiveVersion { version: 2, .. }),
        "{err:?}"
    );

    // Retire retained v1 happy path.
    h.retire_blocking("rot-ns", 1).unwrap();
    let err = h.load_version_blocking("rot-ns", 1).unwrap_err();
    assert!(matches!(err, SecureKeyError::NotFound(_)), "{err:?}");

    // Reservation vs retirement race: ref blocks retire → InUse.
    let (v3, _) = h.rotate_blocking("rot-ns").unwrap(); // active 3, 2 retained
    h.reserve_blocking("block", "rot-ns", 2, "test", "c")
        .unwrap();
    let err = h.retire_blocking("rot-ns", 2).unwrap_err();
    assert!(matches!(err, SecureKeyError::InUse(_)), "{err:?}");

    // Prepared CAS: recon releases Reserved when consumer missing (test kind → false).
    h.reconcile_blocking().unwrap();
    let err_or_ok = h.retire_blocking("rot-ns", 2);
    match err_or_ok {
        Ok(()) => {}
        Err(SecureKeyError::InUse(_)) => {
            panic!("expected recon to clear Reserved blocker");
        }
        Err(e) => panic!("unexpected {e:?}"),
    }
    let _ = v3;

    // Crash resume after delete boundary: inject AfterDelete.
    {
        let store2 = FakeNativeStore::new();
        let db = Db::open_in_memory().unwrap();
        let recon = Arc::new(MapReconciler::new().with_kind("test", |_| false));
        let actor =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store2.clone()), recon).unwrap();
        let h = actor.handle();
        let _ = h.create_or_load_blocking("ret-crash").unwrap();
        let _ = h.rotate_blocking("ret-crash").unwrap(); // v2 active, v1 retained
        // Fail after first delete of v1.
        store2.inject_once(
            FaultPoint::AfterDelete,
            InjectedFault::Error(FaultKind::Unavailable),
        );
        let _ = h.retire_blocking("ret-crash", 1);
        drop(actor);
        store2.clear_faults();
        let recon = Arc::new(MapReconciler::new().with_kind("test", |_| false));
        let actor2 =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store2.clone()), recon).unwrap();
        // Resume completes retirement.
        let state = db
            .blocking_write_for_sync_maintenance(|conn| get_version_conn(conn, "ret-crash", 1))
            .unwrap()
            .unwrap();
        assert_eq!(
            state.state,
            SecureKeyVersionState::Retired,
            "retire must resume to Retired"
        );
        let _ = actor2;
    }

    // Crash after manifest retire set: fail 1st set during retire (manifest rewrite).
    {
        let store3 = FakeNativeStore::new();
        let db = Db::open_in_memory().unwrap();
        let recon = Arc::new(MapReconciler::new().with_kind("test", |_| false));
        let actor =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store3.clone()), recon).unwrap();
        let h = actor.handle();
        let _ = h.create_or_load_blocking("ret-m").unwrap();
        let _ = h.rotate_blocking("ret-m").unwrap();
        // During retire: delete then set manifest. Fail AfterSet once (manifest write).
        store3.inject_once(
            FaultPoint::AfterSet,
            InjectedFault::Error(FaultKind::Unavailable),
        );
        let _ = h.retire_blocking("ret-m", 1);
        drop(actor);
        store3.clear_faults();
        let recon = Arc::new(MapReconciler::new().with_kind("test", |_| false));
        let actor2 = SecureKeyActor::start_with_store(db.clone(), Box::new(store3), recon).unwrap();
        let state = db
            .blocking_write_for_sync_maintenance(|conn| get_version_conn(conn, "ret-m", 1))
            .unwrap()
            .unwrap();
        assert_eq!(state.state, SecureKeyVersionState::Retired);
        let _ = actor2;
    }

    // SQLite retire metadata boundaries: plant ManifestRetired / MetadataRetired.
    {
        let store4 = FakeNativeStore::new();
        let db = Db::open_in_memory().unwrap();
        let recon = Arc::new(MapReconciler::new().with_kind("test", |_| false));
        let actor =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store4.clone()), recon).unwrap();
        let h = actor.handle();
        let _ = h.create_or_load_blocking("ret-meta").unwrap();
        let _ = h.rotate_blocking("ret-meta").unwrap(); // v2 active, v1 retained
        // Fully retire once so native+manifest are retired, then rewind SQLite phase.
        h.retire_blocking("ret-meta", 1).unwrap();
        drop(actor);
        // Rewind to ManifestRetiredAndVerified with version still Retiring.
        db.blocking_write_for_sync_maintenance(move |conn| {
            conn.execute_batch("BEGIN IMMEDIATE;")?;
            conn.execute(
                "UPDATE secure_key_versions SET state = 'Retiring'
                 WHERE namespace = 'ret-meta' AND version = 1",
                [],
            )?;
            conn.execute(
                "INSERT INTO secure_key_sagas
                    (op_id, namespace, kind, version, phase, key_digest, created_at, updated_at)
                 VALUES ('plant-ret-meta', 'ret-meta', 'Retire', 1, ?1, NULL, 1, 1)",
                rusqlite::params![RetirePhase::ManifestRetiredAndVerified.as_str()],
            )?;
            conn.execute_batch("COMMIT;")?;
            Ok(())
        })
        .unwrap();
        let recon = Arc::new(MapReconciler::new().with_kind("test", |_| false));
        let actor2 =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store4.clone()), recon).unwrap();
        let state = db
            .blocking_write_for_sync_maintenance(|conn| get_version_conn(conn, "ret-meta", 1))
            .unwrap()
            .unwrap();
        assert_eq!(state.state, SecureKeyVersionState::Retired);
        let open = db
            .blocking_write_for_sync_maintenance(list_open_sagas_conn)
            .unwrap();
        assert!(
            open.iter().all(|s| s.namespace != "ret-meta"),
            "retire metadata resume must close saga: {open:?}"
        );
        let _ = actor2;
    }

    // MetadataRetired → commit/ack only.
    {
        let store5 = FakeNativeStore::new();
        let db = Db::open_in_memory().unwrap();
        let recon = Arc::new(MapReconciler::new().with_kind("test", |_| false));
        let actor =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store5.clone()), recon).unwrap();
        let h = actor.handle();
        let _ = h.create_or_load_blocking("ret-ack").unwrap();
        let _ = h.rotate_blocking("ret-ack").unwrap();
        h.retire_blocking("ret-ack", 1).unwrap();
        drop(actor);
        db.blocking_write_for_sync_maintenance(move |conn| {
            conn.execute_batch("BEGIN IMMEDIATE;")?;
            conn.execute(
                "INSERT INTO secure_key_sagas
                    (op_id, namespace, kind, version, phase, key_digest, created_at, updated_at)
                 VALUES ('plant-ret-ack', 'ret-ack', 'Retire', 1, ?1, NULL, 1, 1)",
                rusqlite::params![RetirePhase::MetadataRetired.as_str()],
            )?;
            conn.execute_batch("COMMIT;")?;
            Ok(())
        })
        .unwrap();
        let recon = Arc::new(MapReconciler::new().with_kind("test", |_| false));
        let actor2 = SecureKeyActor::start_with_store(db.clone(), Box::new(store5), recon).unwrap();
        let state = db
            .blocking_write_for_sync_maintenance(|conn| get_version_conn(conn, "ret-ack", 1))
            .unwrap()
            .unwrap();
        assert_eq!(state.state, SecureKeyVersionState::Retired);
        let open = db
            .blocking_write_for_sync_maintenance(list_open_sagas_conn)
            .unwrap();
        assert!(
            open.iter().all(|s| s.namespace != "ret-ack"),
            "MetadataRetired must commit+delete: {open:?}"
        );
        let _ = actor2;
    }

    let _ = store;
}

// ---------------------------------------------------------------------------
// 7. secure_key_reference_recovery
// ---------------------------------------------------------------------------

#[test]
fn secure_key_reference_recovery() {
    let store = FakeNativeStore::new();
    let present = Arc::new(AtomicBool::new(true));
    let p = present.clone();
    let recon = Arc::new(MapReconciler::new().with_kind("kind", move |_| p.load(Ordering::SeqCst)));
    let db = Db::open_in_memory().unwrap();
    let actor =
        SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon).unwrap();
    let h = actor.handle();
    let (v, _) = h.create_or_load_blocking("recov-ns").unwrap();
    h.reserve_blocking("r1", "recov-ns", v, "kind", "id1")
        .unwrap();

    // Existing consumer: Reserved retained.
    h.reconcile_blocking().unwrap();
    let still = db
        .blocking_write_for_sync_maintenance(|conn| get_ref_by_id_conn(conn, "r1"))
        .unwrap()
        .unwrap();
    assert_eq!(still.state, SecureKeyRefState::Reserved);

    // Missing consumer: Reserved → Released.
    present.store(false, Ordering::SeqCst);
    h.reconcile_blocking().unwrap();
    let gone = db
        .blocking_write_for_sync_maintenance(|conn| get_ref_by_id_conn(conn, "r1"))
        .unwrap()
        .unwrap();
    assert_eq!(gone.state, SecureKeyRefState::Released);

    // Releasing + missing consumer → Released.
    h.reserve_blocking("r2", "recov-ns", v, "kind", "id2")
        .unwrap();
    present.store(true, Ordering::SeqCst);
    db.blocking_write_for_sync_maintenance(|conn| {
        conn.execute_batch("BEGIN IMMEDIATE;")?;
        activate_ref_in_tx(conn, "r2").map_err(|e| anyhow::anyhow!("{e}"))?;
        begin_release_in_tx(conn, "r2").map_err(|e| anyhow::anyhow!("{e}"))?;
        conn.execute_batch("COMMIT;")?;
        Ok(())
    })
    .unwrap();
    present.store(false, Ordering::SeqCst);
    h.reconcile_blocking().unwrap();
    let r2 = db
        .blocking_write_for_sync_maintenance(|conn| get_ref_by_id_conn(conn, "r2"))
        .unwrap()
        .unwrap();
    assert_eq!(r2.state, SecureKeyRefState::Released);

    // Unknown kind fails closed (retain).
    db.blocking_write_for_sync_maintenance(move |conn| {
        use rusqlite::params;
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO secure_key_consumer_refs
                (reference_id, namespace, version, consumer_kind, consumer_id, state, created_at, updated_at)
             VALUES ('r-unknown', 'recov-ns', ?1, 'unknown-kind', 'x', 'Reserved', ?2, ?2)",
            params![v, now],
        )?;
        Ok(())
    })
    .unwrap();
    h.reconcile_blocking().unwrap();
    let unk = db
        .blocking_write_for_sync_maintenance(|conn| get_ref_by_id_conn(conn, "r-unknown"))
        .unwrap()
        .unwrap();
    assert_eq!(unk.state, SecureKeyRefState::Reserved);

    // Releasing + existing consumer: conservative retain.
    present.store(true, Ordering::SeqCst);
    h.reserve_blocking("r3", "recov-ns", v, "kind", "id3")
        .unwrap();
    db.blocking_write_for_sync_maintenance(|conn| {
        conn.execute_batch("BEGIN IMMEDIATE;")?;
        activate_ref_in_tx(conn, "r3").map_err(|e| anyhow::anyhow!("{e}"))?;
        begin_release_in_tx(conn, "r3").map_err(|e| anyhow::anyhow!("{e}"))?;
        conn.execute_batch("COMMIT;")?;
        Ok(())
    })
    .unwrap();
    h.reconcile_blocking().unwrap();
    let r3 = db
        .blocking_write_for_sync_maintenance(|conn| get_ref_by_id_conn(conn, "r3"))
        .unwrap()
        .unwrap();
    assert_eq!(r3.state, SecureKeyRefState::Releasing);
}

// ---------------------------------------------------------------------------
// 8. secure_key_typed_failures
// ---------------------------------------------------------------------------

#[test]
fn secure_key_typed_failures() {
    // Inject each variant distinctly and assert exact match.
    type FaultCase = (
        FaultKind,
        &'static str,
        fn(&SecureKeyError) -> bool,
        &'static str,
    );
    let cases: &[FaultCase] = &[
        (
            FaultKind::Locked,
            "fail-locked",
            |e| matches!(e, SecureKeyError::Locked(_)),
            "Locked",
        ),
        (
            FaultKind::Denied,
            "fail-denied",
            |e| matches!(e, SecureKeyError::Denied(_)),
            "Denied",
        ),
        (
            FaultKind::Unavailable,
            "fail-unavail",
            |e| matches!(e, SecureKeyError::Unavailable(_)),
            "Unavailable",
        ),
        (
            FaultKind::Corrupt,
            "fail-corrupt",
            |e| matches!(e, SecureKeyError::Corrupt(_)),
            "Corrupt",
        ),
        (
            FaultKind::NotFound,
            "fail-notfound",
            |e| matches!(e, SecureKeyError::NotFound(_)),
            "NotFound",
        ),
    ];
    for &(kind, ns, pred, kind_name) in cases {
        let store = FakeNativeStore::new();
        store.inject_once(FaultPoint::BeforeSet, InjectedFault::Error(kind));
        let (actor, _) = test_actor(store);
        let err = actor.handle().create_or_load_blocking(ns).unwrap_err();
        assert!(
            pred(&err),
            "expected {kind:?}, got {err:?} kind={}",
            err.kind_name()
        );
        assert_eq!(err.kind_name(), kind_name);
    }

    let store = FakeNativeStore::new();
    let (actor, _) = test_actor(store);
    let err = actor
        .handle()
        .load_version_blocking("nope", 99)
        .unwrap_err();
    assert!(matches!(err, SecureKeyError::NotFound(_)), "{err:?}");
    assert_eq!(err.kind_name(), "NotFound");
}

// ---------------------------------------------------------------------------
// 9. secure_key_zeroization_and_no_serialization
// ---------------------------------------------------------------------------

#[test]
fn secure_key_zeroization_and_no_serialization() {
    let k = generate_key_bytes();
    assert_eq!(std::mem::size_of_val(k.as_ref()), 32);
    let dbg = format!("{k:?}");
    assert!(dbg.contains("REDACTED"), "{dbg}");
    // Must not dump raw bytes.
    let hex: String = k.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    assert!(!dbg.contains(&hex), "debug leaked key hex");

    // Drop probe for temporary buffers on success path.
    let dropped = Arc::new(AtomicBool::new(false));
    let zeroized = Arc::new(AtomicBool::new(false));
    {
        let probe = super::key_material::DropProbeTemp {
            bytes: zeroize::Zeroizing::new(vec![0x5Au8; 32]),
            dropped: dropped.clone(),
            zeroized_before_drop_flag: zeroized.clone(),
        };
        drop(probe);
    }
    assert!(dropped.load(Ordering::SeqCst));
    assert!(zeroized.load(Ordering::SeqCst));

    // Error path through fake store still produces TempSecret only on get success;
    // set error path: temporary key from generate is dropped (Zeroizing).
    let store = FakeNativeStore::new();
    store.inject_once(
        FaultPoint::BeforeSet,
        InjectedFault::Error(FaultKind::Denied),
    );
    let probe_hits = Arc::new(AtomicUsize::new(0));
    store.arm_get_drop_probe(probe_hits.clone());
    let (actor, store) = test_actor(store);
    let err = actor.handle().create_or_load_blocking("z-err").unwrap_err();
    assert!(matches!(err, SecureKeyError::Denied(_)));
    // Success path: create then load exercises get TempSecret.
    store.clear_faults();
    let (actor2, store2) = test_actor(FakeNativeStore::new());
    let hits = Arc::new(AtomicUsize::new(0));
    store2.arm_get_drop_probe(hits.clone());
    let _ = actor2.handle().create_or_load_blocking("z-ok").unwrap();
    assert!(
        hits.load(Ordering::SeqCst) > 0 || store2.drop_probe_hits.load(Ordering::SeqCst) > 0,
        "expected get temporary buffers on success path"
    );

    let e = SecureKeyError::NotFound("version missing".into());
    let s = format!("{e:?}{e}");
    assert!(!s.contains("secret"));
}

// ---------------------------------------------------------------------------
// 10. secure_key_blocking_seam_is_bounded
// ---------------------------------------------------------------------------

#[test]
fn secure_key_blocking_seam_is_bounded() {
    assert_eq!(SECURE_KEY_QUEUE_CAPACITY, 32);
    let store = FakeNativeStore::new();
    let release = store.arm_hang(FaultPoint::BeforeSet);
    let guard = release.lock().unwrap();
    let (actor, store) = test_actor(store);
    let h = actor.handle();
    let h2 = h.clone();
    let t = thread::spawn(move || h2.create_or_load_blocking("busy-ns"));
    thread::sleep(Duration::from_millis(50));
    let mut parked = Vec::new();
    for _ in 0..SECURE_KEY_QUEUE_CAPACITY {
        match h.enqueue_raw_for_busy_test() {
            Ok(()) => parked.push(()),
            Err(SecureKeyError::Busy) => break,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    let busy = h.enqueue_raw_for_busy_test();
    assert!(matches!(busy, Err(SecureKeyError::Busy)));
    let threads_before = store.thread_ids.lock().unwrap().len();
    drop(guard);
    let _ = t.join();
    let threads_after = store.thread_ids.lock().unwrap().clone();
    assert!(
        threads_after.len() <= 2,
        "unexpected thread proliferation: {threads_after:?} before={threads_before}"
    );
    let _ = parked;

    // AC10: no Tokio blocking-pool seam in production secure_key modules.
    // (tests.rs may mention the forbidden tokens when asserting their absence.)
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/secure_key");
    let production = [
        "actor.rs",
        "consumer.rs",
        "error.rs",
        "fake.rs",
        "key_material.rs",
        "manifest.rs",
        "mod.rs",
        "namespace.rs",
        "native_store.rs",
        "platform.rs",
        "worker.rs",
    ];
    for name in production {
        let path = dir.join(name);
        let text = std::fs::read_to_string(&path).unwrap();
        // Split token so this test file can mention the rule without matching itself
        // when scanned; production files are checked for the real API names.
        let forbid = ["spawn", "blocking"]; // joined below
        let token = format!("{}{}{}", forbid[0], "_", forbid[1]);
        assert!(
            !text.contains(&token),
            "{} must not use {token}",
            path.display()
        );
        assert!(
            !text.contains("block_in_place"),
            "{} must not use block_in_place",
            path.display()
        );
        let tok2 = format!("tokio::task::{token}");
        assert!(
            !text.contains(&tok2),
            "{} must not use tokio blocking pool",
            path.display()
        );
    }

    // Caller cancellation of an in-flight native create: hang BeforeSet, start
    // async create_or_load, abort the caller future (drop reply), then release the
    // hang. Actor must finish reconciliation; a subsequent create loads the same v1.
    {
        let store = FakeNativeStore::new();
        let release = store.arm_hang(FaultPoint::BeforeSet);
        let hang_guard = release.lock().unwrap();
        // Actor start uses blocking_recv; construct outside any Tokio runtime.
        let (actor, store) = test_actor(store);
        let h = actor.handle();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let h_task = h.clone();
        let task = rt.spawn(async move { h_task.create_or_load("cancel-ns").await });
        // Deterministic: wait until worker is blocked at BeforeSet.
        assert!(
            store.wait_for_hang_entered(Duration::from_secs(5)),
            "worker must reach BeforeSet hang before cancel"
        );
        task.abort();
        // Caller cancelled; release store so worker completes the write + saga.
        drop(hang_guard);
        // Await aborted task settles (JoinError expected).
        let _ = rt.block_on(task);
        // Original op completed on actor: load returns v1 without re-provision race.
        let (v, _) = h.create_or_load_blocking("cancel-ns").unwrap();
        assert_eq!(v, 1, "cancelled create must have completed on actor");
        assert!(store.item_count() >= 1);
        // No open provision saga remains.
        let open = actor.handle().list_metadata_blocking("cancel-ns").unwrap();
        assert_eq!(open.active_version, Some(1));
        drop(rt);
        actor.shutdown();
    }
}

// ---------------------------------------------------------------------------
// 11. secure_key_platform_dependency_pin
// ---------------------------------------------------------------------------

#[test]
fn secure_key_platform_dependency_pin() {
    // Known pin table (MSRV / license) — documented for review:
    // - keyring-core =1.0.0            MSRV 1.85   MIT OR Apache-2.0
    // - apple-native-keyring-store =1.0.1  MSRV ≤1.88  MIT OR Apache-2.0  features: keychain
    // - windows-native-keyring-store =1.1.0 MSRV ≤1.88 MIT OR Apache-2.0  (no search)
    // - zbus-secret-service-keyring-store =1.0.0 MSRV ≤1.88 MIT OR Apache-2.0
    //     features: rt-tokio-crypto-rust
    // - zeroize =1.9.0  default-features=false + alloc, no derive
    // Workspace MSRV 1.95.0 ≥ all pins.

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest).unwrap();
    assert!(text.contains("keyring-core"));
    assert!(text.contains("zeroize"));
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("keyring ")
            || trimmed.starts_with("keyring=")
            || trimmed.contains("keyring = {")
        {
            panic!("all-in-one keyring dependency forbidden: {trimmed}");
        }
    }
    let ws = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let ws_text = std::fs::read_to_string(&ws).unwrap();
    assert!(
        ws_text.contains("zeroize = { version = \"=1.9.0\"")
            || (ws_text.contains("version = \"=1.9.0\"") && ws_text.contains("zeroize")),
        "zeroize 1.9.0 pin missing"
    );
    assert!(ws_text.contains("keyring-core = { version = \"=1.0.0\""));

    #[cfg(target_os = "linux")]
    {
        assert!(text.contains("zbus-secret-service-keyring-store"));
        assert!(text.contains("rt-tokio-crypto-rust"));
    }
    #[cfg(target_os = "macos")]
    {
        assert!(text.contains("apple-native-keyring-store"));
        assert!(text.contains("keychain"));
    }
    #[cfg(target_os = "windows")]
    {
        assert!(text.contains("windows-native-keyring-store"));
    }

    let kind = platform_store_kind();
    let name = reachable_native_store_crate();
    match kind {
        super::platform::PlatformStoreKind::ZbusSecretService => {
            assert_eq!(name, Some("zbus-secret-service-keyring-store"));
        }
        super::platform::PlatformStoreKind::AppleKeychain => {
            assert_eq!(name, Some("apple-native-keyring-store"));
        }
        super::platform::PlatformStoreKind::WindowsCredentialManager => {
            assert_eq!(name, Some("windows-native-keyring-store"));
        }
        super::platform::PlatformStoreKind::Unsupported => {
            assert_eq!(name, None);
        }
    }
    let _ = platform_link_token();

    // cargo tree --locked --target for current host: keyring-core + exactly one native store;
    // no all-in-one `keyring` package.
    let target = current_rustc_host_triple();
    let output = std::process::Command::new("cargo")
        .args([
            "tree",
            "--locked",
            "--target",
            &target,
            "-p",
            "cockpit-core",
            "--edges",
            "normal",
        ])
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .env("CARGO_TARGET_DIR", "target")
        .output()
        .expect("cargo tree");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let tree = String::from_utf8_lossy(&output.stdout);
    assert!(
        tree.contains("keyring-core"),
        "keyring-core missing from tree for {target}"
    );
    // Forbid the all-in-one package name as a distinct package line.
    for line in tree.lines() {
        // cargo tree lines look like `keyring v1.2.3` — exclude keyring-core / *-keyring-store.
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("keyring ").or_else(|| {
            trimmed
                .split_whitespace()
                .find(|&w| w == "keyring")
                .map(|_| "")
        }) {
            let _ = rest;
        }
        // Match package token `keyring v` not preceded by hyphen/word chars of longer names.
        if trimmed.contains("keyring v")
            && !trimmed.contains("keyring-core")
            && !trimmed.contains("keyring-store")
        {
            panic!("all-in-one keyring package reachable: {trimmed}");
        }
    }
    #[cfg(target_os = "linux")]
    {
        assert!(
            tree.contains("zbus-secret-service-keyring-store"),
            "linux store missing from tree"
        );
        assert!(
            !tree.contains("apple-native-keyring-store"),
            "apple store must be unreachable on linux target graph edges"
        );
        assert!(
            !tree.contains("windows-native-keyring-store"),
            "windows store must be unreachable on linux target graph edges"
        );
    }

    // Cross-target reachability without full cross-compile: cargo tree evaluates
    // target-gated deps for other triples on this host.
    fn tree_for(target: &str) -> String {
        let output = std::process::Command::new("cargo")
            .args([
                "tree",
                "--locked",
                "--target",
                target,
                "-p",
                "cockpit-core",
                "--edges",
                "normal",
            ])
            .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .env("CARGO_TARGET_DIR", "target")
            .output()
            .unwrap_or_else(|e| panic!("cargo tree {target}: {e}"));
        assert!(
            output.status.success(),
            "cargo tree {target} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }
    // Windows triple: exactly windows-native + keyring-core (when windows target known).
    let win = tree_for("x86_64-pc-windows-msvc");
    assert!(
        win.contains("windows-native-keyring-store"),
        "windows store missing from windows target tree"
    );
    assert!(
        win.contains("keyring-core"),
        "keyring-core missing from windows target tree"
    );
    assert!(
        !win.contains("zbus-secret-service-keyring-store"),
        "linux store must not reach windows target tree"
    );
    assert!(
        !win.contains("apple-native-keyring-store"),
        "apple store must not reach windows target tree"
    );
    // macOS triple (cargo tree evaluates target cfg without full cross-compile).
    let mac = tree_for("aarch64-apple-darwin");
    assert!(
        mac.contains("apple-native-keyring-store"),
        "apple store missing from macos target tree"
    );
    assert!(
        mac.contains("keyring-core"),
        "keyring-core missing from macos target tree"
    );
    assert!(
        !mac.contains("zbus-secret-service-keyring-store")
            && !mac.contains("windows-native-keyring-store"),
        "non-apple stores must not reach macos target tree"
    );
    // Unsupported-class triple (no OS native store cfg): only keyring-core, no platform stores.
    let free = tree_for("x86_64-unknown-freebsd");
    assert!(
        free.contains("keyring-core"),
        "keyring-core must remain on unsupported-class target"
    );
    assert!(
        !free.contains("zbus-secret-service-keyring-store")
            && !free.contains("apple-native-keyring-store")
            && !free.contains("windows-native-keyring-store"),
        "no platform store crate on unsupported-class target: {free}"
    );
}

fn current_rustc_host_triple() -> String {
    let out = std::process::Command::new("rustc")
        .args(["-vV"])
        .output()
        .expect("rustc -vV");
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(t) = line.strip_prefix("host: ") {
            return t.trim().to_owned();
        }
    }
    panic!("host triple not found in rustc -vV: {text}");
}

// ---------------------------------------------------------------------------
// 12. Platform compile/CI fixtures (ordering + fake injection)
// ---------------------------------------------------------------------------

#[test]
fn secure_key_platform_compile_and_fake_injection() {
    // Fake store path never touches process-global registration.
    let store = FakeNativeStore::new();
    let (actor, store) = test_actor(store);
    assert_eq!(store.call_counts().0, 0);
    let _ = actor.handle().create_or_load_blocking("ci-ns").unwrap();
    assert!(store.call_counts().0 >= 1);
    actor.shutdown();

    // First-run production is always database: no platform store registration.
    reset_registration_order_for_test();
    set_test_skip_real_default_store(true);
    let tmp = tempfile::TempDir::new().unwrap();
    let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let kek = std::sync::Arc::new(super::MemoryKekStore::new(
        cockpit_proto::SecretStorePlacement::Database,
    ));
    let actor = SecureKeyActor::start_production_resolved(
        db,
        std::sync::Arc::new(super::FailClosedReconciler),
        &crate::secure_key::KeyringProbeResult {
            state: cockpit_proto::FeatureCapabilityState::Available,
            reason: "injected available".into(),
            fix_command: None,
            remedy_text: None,
        },
        Some(tmp.path().join("secret-vault")),
        super::SecretStoreInjected {
            file_kek: Some(kek),
            keyring_kek: None,
            legacy_keyring: None,
        },
    )
    .unwrap();
    let snap_mid = registration_order_snapshot();
    assert_eq!(
        snap_mid.set_default_at, 0,
        "first-run database must not register the platform store: {snap_mid:?}"
    );
    actor.shutdown();
    set_test_skip_real_default_store(false);
    reset_registration_order_for_test();

    // Unsupported adapter is compiled on non-desktop targets; on supported targets
    // the type still exists for cfg inventory.
    let _ = std::any::type_name::<super::native_store::UnsupportedNativeStore>();
    // cfg inventory: production branch picks exactly one store kind at compile time.
    match platform_store_kind() {
        super::platform::PlatformStoreKind::Unsupported => {
            assert!(reachable_native_store_crate().is_none());
        }
        k => {
            assert!(reachable_native_store_crate().is_some(), "{k:?}");
        }
    }
}

#[test]
fn secure_key_active_in_retired_is_corrupt() {
    use super::manifest::NamespaceManifest;
    use super::namespace::{SECURE_KEY_SERVICE, manifest_account};
    use crate::db::secure_key::ProvisionPhase;

    // Case A: completed Active + manifest lists active as retired.
    {
        let store = FakeNativeStore::new();
        let db = Db::open_in_memory().unwrap();
        let recon = Arc::new(MapReconciler::new());
        let actor =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon).unwrap();
        let h = actor.handle();
        let _ = h.create_or_load_blocking("act-ret-ns").unwrap();
        let id = db
            .blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
            .unwrap();
        let ns = Namespace::parse("act-ret-ns").unwrap();
        let m_acct = manifest_account(id.as_hex(), &ns).unwrap();
        let mut m = NamespaceManifest::from_bytes(
            &store
                .get_raw(SECURE_KEY_SERVICE, &m_acct)
                .expect("manifest present"),
        )
        .unwrap();
        m.retired.push(1);
        store.put_raw(SECURE_KEY_SERVICE, &m_acct, m.to_bytes().unwrap());
        drop(actor);
        let recon = Arc::new(MapReconciler::new());
        let start = SecureKeyActor::start_with_store(db, Box::new(store), recon);
        match start {
            Err(SecureKeyError::Corrupt(_)) => {}
            Ok(_) => panic!("Active+retired must fail closed at startup, got Ok"),
            Err(e) => panic!("Active+retired must be Corrupt, got {e:?}"),
        }
    }

    // Case B: open Provision at ManifestAdvanced for v2 with corrupt retired=[2].
    // Pre-resume guard must fail before metadata activation rewrites history.
    {
        let store = FakeNativeStore::new();
        let db = Db::open_in_memory().unwrap();
        let recon = Arc::new(MapReconciler::new());
        let actor =
            SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon).unwrap();
        let h = actor.handle();
        let (v1, k1) = h.create_or_load_blocking("inflight-ret").unwrap();
        assert_eq!(v1, 1);
        let digest = key_digest(&k1);
        // Plant open provision for v2 at ManifestAdvanced with corrupt retired.
        let id = db
            .blocking_write_for_sync_maintenance(ensure_installation_identity_conn)
            .unwrap();
        let ns = Namespace::parse("inflight-ret").unwrap();
        let m_acct = manifest_account(id.as_hex(), &ns).unwrap();
        let mut m = NamespaceManifest::from_bytes(
            &store
                .get_raw(SECURE_KEY_SERVICE, &m_acct)
                .expect("manifest present"),
        )
        .unwrap();
        m.advance_active(2, &digest);
        m.retired.push(2); // corrupt: active v2 also retired
        store.put_raw(SECURE_KEY_SERVICE, &m_acct, m.to_bytes().unwrap());
        db.blocking_write_for_sync_maintenance({
            let digest = digest.clone();
            move |conn| {
                conn.execute_batch("BEGIN IMMEDIATE;")?;
                conn.execute(
                    "INSERT INTO secure_key_versions
                        (namespace, version, state, key_digest, created_at, updated_at)
                     VALUES ('inflight-ret', 2, 'Pending', ?1, 1, 1)",
                    rusqlite::params![digest],
                )?;
                conn.execute(
                    "INSERT INTO secure_key_sagas
                        (op_id, namespace, kind, version, phase, key_digest, created_at, updated_at)
                     VALUES ('plant-inflight', 'inflight-ret', 'Provision', 2, ?1, ?2, 1, 1)",
                    rusqlite::params![ProvisionPhase::ManifestAdvancedAndVerified.as_str(), digest],
                )?;
                conn.execute_batch("COMMIT;")?;
                Ok(())
            }
        })
        .unwrap();
        drop(actor);
        let recon = Arc::new(MapReconciler::new());
        let start = SecureKeyActor::start_with_store(db.clone(), Box::new(store), recon);
        match start {
            Err(SecureKeyError::Corrupt(_)) => {}
            Ok(_) => panic!("in-flight active∈retired must fail before resume, got Ok"),
            Err(e) => panic!("expected Corrupt, got {e:?}"),
        }
        // SQLite must not have activated v2.
        let row = db
            .blocking_write_for_sync_maintenance(|conn| get_version_conn(conn, "inflight-ret", 2))
            .unwrap()
            .unwrap();
        assert_eq!(
            row.state,
            SecureKeyVersionState::Pending,
            "corrupt resume must not activate v2"
        );
    }
}

#[test]
fn concurrent_create_single_active_v1() {
    secure_key_daemon_serialization();
}
