//! Acceptance tests for native-secure-sealed-state-store (`sealed_state_*`).

use std::sync::Arc;
use std::thread;

use crate::db::Db;
use crate::db::secure_key::SEALED_STATE_CONSUMER_KIND;

use crate::db::secure_key::{
    SecureKeyRefState, get_ref_by_id_conn, list_blocking_refs_conn, sealed_state_ref_id,
};

use super::actor::SecureKeyActor;
use super::consumer::MapReconciler;
use super::error::SecureKeyError;
use super::fake::{FakeNativeStore, FaultKind, FaultPoint, InjectedFault};
use super::key_material::SecureKeyBytes;
use super::namespace::{Namespace, SECURE_KEY_SERVICE};
use super::platform::{PlatformStoreKind, platform_store_kind, reachable_native_store_crate};
use super::sealed_state::{
    MAX_PAYLOAD_LEN, SealedHealth, SealedPayload, SealedSlot, SealedStateView,
    encode_item_base64url, payload_digest, sealed_state_account,
};

fn test_actor(store: FakeNativeStore) -> (SecureKeyActor, FakeNativeStore) {
    let db = Db::open_in_memory().unwrap();
    let recon = Arc::new(
        MapReconciler::new()
            .with_kind("test", |_| false)
            .with_kind(SEALED_STATE_CONSUMER_KIND, |_| true),
    );
    let actor = SecureKeyActor::start_with_store(db, Box::new(store.clone()), recon).unwrap();
    (actor, store)
}

/// Actor + store + shared Db for SQLite ref inspection.
fn test_actor_with_db(store: FakeNativeStore) -> (SecureKeyActor, FakeNativeStore, Db) {
    let db = Db::open_in_memory().unwrap();
    let recon = Arc::new(
        MapReconciler::new()
            .with_kind("test", |_| false)
            .with_kind(SEALED_STATE_CONSUMER_KIND, |_| true),
    );
    let actor =
        SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon).unwrap();
    (actor, store, db)
}

fn install_hex_from_store(store: &FakeNativeStore) -> String {
    let state_a = store
        .accounts()
        .into_iter()
        .find(|(svc, a)| svc == SECURE_KEY_SERVICE && a.ends_with("/state-a"))
        .expect("state-a account")
        .1;
    state_a
        .split('/')
        .next()
        .expect("install hex prefix")
        .to_owned()
}

fn put_encoded_slot(
    store: &FakeNativeStore,
    install_hex: &str,
    slot: SealedSlot,
    generation: u64,
    key_version: u32,
    payload: &SealedPayload,
    key: &SecureKeyBytes,
) {
    let ns = Namespace::parse(NS).unwrap();
    let mut install = [0u8; 16];
    for i in 0..16 {
        install[i] = u8::from_str_radix(&install_hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    let b64 =
        encode_item_base64url(&install, &ns, slot, generation, key_version, payload, key).unwrap();
    let acct = sealed_state_account(install_hex, &ns, slot).unwrap();
    store.put_raw(SECURE_KEY_SERVICE, &acct, b64.into_bytes());
}

const NS: &str = "audit-head/v1";

fn opposite_suffix(target_acct: &str) -> &'static str {
    if target_acct.ends_with("/state-a") {
        "state-b"
    } else {
        "state-a"
    }
}

fn target_suffix(target_acct: &str) -> &'static str {
    if target_acct.ends_with("/state-a") {
        "state-a"
    } else {
        "state-b"
    }
}

fn dig_hex(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn sealed_state_two_slot_matrix() {
    let store = FakeNativeStore::new();
    let (actor, store) = test_actor(store);
    let h = actor.handle();

    // NotFound then generation-1 state-a creation.
    assert!(matches!(
        h.sealed_load_blocking(NS),
        Err(SecureKeyError::NotFound(_))
    ));
    let v1 = h
        .sealed_create_or_load_blocking(NS, SealedPayload::empty())
        .unwrap();
    assert_eq!(v1.meta.generation, 1);
    assert_eq!(v1.meta.current_slot, SealedSlot::A);
    assert_eq!(v1.meta.health, SealedHealth::Degraded);
    assert!(v1.payload.is_empty());

    // Alternating exact accounts / slot bytes via CAS.
    let d1 = v1.meta.payload_digest;
    let p2 = SealedPayload::new(vec![0x00, 0xff, 0x41]).unwrap();
    let v2 = h
        .sealed_compare_and_swap_blocking(NS, 1, d1, p2.clone())
        .unwrap();
    assert_eq!(v2.meta.generation, 2);
    assert_eq!(v2.meta.current_slot, SealedSlot::B);
    assert_eq!(v2.payload.as_slice(), p2.as_slice());

    // Highest unequal generation selects higher (A gen3 over B gen2).
    let d2 = v2.meta.payload_digest;
    let v3 = h
        .sealed_compare_and_swap_blocking(NS, 2, d2, SealedPayload::new(vec![7]).unwrap())
        .unwrap();
    assert_eq!(v3.meta.current_slot, SealedSlot::A);
    assert_eq!(v3.meta.generation, 3);

    // One-valid-one-absent degraded: remove lower slot B (gen2).
    let state_b = store
        .accounts()
        .into_iter()
        .find(|(svc, acct)| svc == SECURE_KEY_SERVICE && acct.ends_with("/state-b"))
        .expect("state-b account");
    assert!(store.remove_raw(&state_b.0, &state_b.1));
    let degraded = h.sealed_load_blocking(NS).unwrap();
    assert_eq!(degraded.meta.generation, 3);
    assert_eq!(degraded.meta.current_slot, SealedSlot::A);
    assert_eq!(degraded.meta.health, SealedHealth::Degraded);

    // Stale expected generation → Conflict.
    let err = h
        .sealed_compare_and_swap_blocking(NS, 99, [0u8; 32], SealedPayload::empty())
        .unwrap_err();
    assert!(matches!(err, SecureKeyError::Conflict { .. }));

    // Payload too large rejected at construction.
    assert!(SealedPayload::new(vec![0u8; MAX_PAYLOAD_LEN + 1]).is_err());

    // After removing B, only A remains: gen3 degraded is still authoritative.
    let loaded = h.sealed_load_blocking(NS).unwrap();
    assert_eq!(loaded.meta.generation, 3);
    assert_eq!(loaded.meta.health, SealedHealth::Degraded);
    assert_eq!(loaded.meta.current_slot, SealedSlot::A);

    // Next CAS restores both slots → Healthy.
    let d3 = loaded.meta.payload_digest;
    let restored = h
        .sealed_compare_and_swap_blocking(NS, 3, d3, SealedPayload::new(vec![9]).unwrap())
        .unwrap();
    assert_eq!(restored.meta.generation, 4);
    assert_eq!(restored.meta.current_slot, SealedSlot::B);
    let both = h.sealed_load_blocking(NS).unwrap();
    assert_eq!(both.meta.health, SealedHealth::Healthy);
}

#[test]
fn sealed_state_cas() {
    let store = FakeNativeStore::new();
    let (actor, _) = test_actor(store);
    let h = actor.handle();
    let init = SealedPayload::new(b"one".to_vec()).unwrap();
    let v1 = h.sealed_create_or_load_blocking(NS, init.clone()).unwrap();
    assert_eq!(v1.meta.generation, 1);
    assert_eq!(v1.payload.as_slice(), b"one");

    let d1 = payload_digest(b"one");
    assert_eq!(v1.meta.payload_digest, d1);

    // Exact match CAS
    let v2 = h
        .sealed_compare_and_swap_blocking(NS, 1, d1, SealedPayload::new(b"two".to_vec()).unwrap())
        .unwrap();
    assert_eq!(v2.meta.generation, 2);
    assert_eq!(v2.payload.as_slice(), b"two");
    let d2 = v2.meta.payload_digest;

    // Wrong digest → Conflict with safe metadata
    let err = h
        .sealed_compare_and_swap_blocking(NS, 2, d1, SealedPayload::empty())
        .unwrap_err();
    match err {
        SecureKeyError::Conflict {
            generation,
            payload_digest: pd,
            ..
        } => {
            assert_eq!(generation, 2);
            assert_eq!(pd, d2);
        }
        other => panic!("expected Conflict, got {other:?}"),
    }

    // Lost-ack replay: after gen2, retry expected=1 with the same new payload.
    let lost = h
        .sealed_compare_and_swap_blocking(NS, 1, d1, SealedPayload::new(b"two".to_vec()).unwrap())
        .expect("lost-ack replay must succeed without rewrite");
    assert_eq!(lost.meta.generation, 2);
    assert_eq!(lost.payload.as_slice(), b"two");
    assert_eq!(lost.meta.payload_digest, d2);

    // Concurrent writers: one wins
    let d_now = h.sealed_load_blocking(NS).unwrap().meta.payload_digest;
    let gen_now = h.sealed_load_blocking(NS).unwrap().meta.generation;
    let h2 = h.clone();
    let p_a = SealedPayload::new(b"a".to_vec()).unwrap();
    let p_b = SealedPayload::new(b"b".to_vec()).unwrap();
    let t1 = thread::spawn({
        let h = h.clone();
        let p = p_a.clone();
        move || h.sealed_compare_and_swap_blocking(NS, gen_now, d_now, p)
    });
    let t2 = thread::spawn(move || h2.sealed_compare_and_swap_blocking(NS, gen_now, d_now, p_b));
    let r1 = t1.join().unwrap();
    let r2 = t2.join().unwrap();
    let wins = [r1.is_ok(), r2.is_ok()].iter().filter(|x| **x).count();
    assert_eq!(wins, 1, "exactly one concurrent CAS must win");
    let loser = if r1.is_err() { r1 } else { r2 };
    assert!(matches!(loser, Err(SecureKeyError::Conflict { .. })));
}

#[test]
fn sealed_state_crash_recovery() {
    let store = FakeNativeStore::new();
    let (actor, store) = test_actor(store);
    let h = actor.handle();
    let v1 = h
        .sealed_create_or_load_blocking(NS, SealedPayload::new(b"base".to_vec()).unwrap())
        .unwrap();
    let d1 = v1.meta.payload_digest;

    // Fault after set: native write landed; resume must complete to gen2.
    store.inject_once(
        FaultPoint::AfterSet,
        InjectedFault::Error(FaultKind::Unavailable),
    );
    let err = h.sealed_compare_and_swap_blocking(
        NS,
        1,
        d1,
        SealedPayload::new(b"next".to_vec()).unwrap(),
    );
    assert!(err.is_err());
    store.clear_faults();
    h.reconcile_blocking().unwrap();
    let recovered = h.sealed_load_blocking(NS).unwrap();
    assert_eq!(
        recovered.meta.generation, 2,
        "AfterSet lands the write; recovery must expose verified gen2"
    );
    assert_eq!(recovered.payload.as_slice(), b"next");

    // BeforeSet: no native write; prior remains authoritative.
    let cur = h.sealed_load_blocking(NS).unwrap();
    store.inject_once(
        FaultPoint::BeforeSet,
        InjectedFault::Error(FaultKind::Denied),
    );
    let err = h.sealed_compare_and_swap_blocking(
        NS,
        cur.meta.generation,
        cur.meta.payload_digest,
        SealedPayload::new(b"later".to_vec()).unwrap(),
    );
    assert!(matches!(err, Err(SecureKeyError::Denied(_))));
    store.clear_faults();
    let still = h.sealed_load_blocking(NS).unwrap();
    assert_eq!(still.meta.generation, cur.meta.generation);
    assert_eq!(still.payload.as_slice(), cur.payload.as_slice());
}

#[test]
fn sealed_state_key_lifecycle() {
    let store = FakeNativeStore::new();
    let (actor, _) = test_actor(store);
    let h = actor.handle();
    let v = h
        .sealed_create_or_load_blocking(NS, SealedPayload::empty())
        .unwrap();
    assert_eq!(v.meta.key_version, 1);
    // Consumer ref for sealed_state on v1 should exist (Active).
    let meta = h.list_metadata_blocking(NS).unwrap();
    assert_eq!(meta.active_version, Some(1));
    // Rotation of secure key retains versions when sealed slots name them.
    let (v2, _) = h.rotate_blocking(NS).unwrap();
    assert_eq!(v2, 2);
    // Sealed state still loads under key v1 until next sealed write.
    let loaded = h.sealed_load_blocking(NS).unwrap();
    assert_eq!(loaded.meta.key_version, 1);
    // New CAS uses active key v2.
    let d = loaded.meta.payload_digest;
    let next = h
        .sealed_compare_and_swap_blocking(NS, loaded.meta.generation, d, SealedPayload::empty())
        .unwrap();
    assert_eq!(next.meta.key_version, 2);
}

#[test]
fn sealed_state_bounded_private_actor_path() {
    let store = FakeNativeStore::new();
    let (actor, _) = test_actor(store);
    let h = actor.handle();
    let max = SealedPayload::new(vec![0xab; 1024]).unwrap();
    let v = h.sealed_create_or_load_blocking(NS, max).unwrap();
    assert_eq!(v.payload.len(), 1024);
    // SealedPayload / SealedStateView intentionally omit Debug.
    // Busy queue pressure: hang the worker first so enqueued ops cannot drain.
    let store = FakeNativeStore::new();
    let release = store.arm_hang(FaultPoint::BeforeSet);
    let guard = release.lock().unwrap();
    let (actor2, store2) = test_actor(store);
    let h2 = actor2.handle();
    let h2c = h2.clone();
    let blocker = std::thread::spawn(move || {
        let _ = h2c.sealed_create_or_load_blocking("busy-block/v1", SealedPayload::empty());
    });
    assert!(
        store2.wait_for_hang_entered(std::time::Duration::from_secs(5)),
        "worker must enter hang before queue fill"
    );
    for _ in 0..super::actor::SECURE_KEY_QUEUE_CAPACITY {
        match h2.enqueue_raw_for_busy_test() {
            Ok(()) => {}
            Err(SecureKeyError::Busy) => break,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    let busy = h2.sealed_load_blocking(NS);
    assert!(
        matches!(busy, Err(SecureKeyError::Busy)),
        "full queue must return Busy, got {busy:?}"
    );
    drop(guard);
    let _ = blocker.join();
}

#[test]
fn sealed_state_namespace_syntax() {
    assert!(Namespace::parse("audit-head/v1").is_ok());
    let store = FakeNativeStore::new();
    let (actor, _) = test_actor(store);
    let err = actor
        .handle()
        .sealed_create_or_load_blocking("Bad", SealedPayload::empty());
    assert!(matches!(err, Err(SecureKeyError::Invalid(_))));
}

#[test]
fn sealed_state_third_account_is_corrupt() {
    let store = FakeNativeStore::new();
    let (actor, store) = test_actor(store);
    let h = actor.handle();
    h.sealed_create_or_load_blocking(NS, SealedPayload::empty())
        .unwrap();
    // Inject an unexpected third sealed-state account under the same namespace prefix.
    let state_a = store
        .accounts()
        .into_iter()
        .find(|(svc, a)| svc == SECURE_KEY_SERVICE && a.ends_with("/state-a"))
        .expect("state-a");
    let rogue = state_a.1.replace("/state-a", "/state-c");
    store.put_raw(SECURE_KEY_SERVICE, &rogue, b"junk".to_vec());
    let err = h.sealed_load_blocking(NS).unwrap_err();
    assert!(
        matches!(err, SecureKeyError::Corrupt(_)),
        "expected Corrupt for third account, got {err}"
    );
}

#[test]
fn sealed_state_equal_generation_benign_and_disagreement() {
    let store = FakeNativeStore::new();
    let (actor, store) = test_actor(store);
    let h = actor.handle();
    let payload = SealedPayload::new(b"same".to_vec()).unwrap();
    let v1 = h
        .sealed_create_or_load_blocking(NS, payload.clone())
        .unwrap();
    assert_eq!(v1.meta.generation, 1);
    let install_hex = install_hex_from_store(&store);
    let key = h.load_version_blocking(NS, 1).unwrap().1;

    // Benign equal-generation replica on B: identical logical state → select A Healthy.
    put_encoded_slot(&store, &install_hex, SealedSlot::B, 1, 1, &payload, &key);
    let both = h.sealed_load_blocking(NS).unwrap();
    assert_eq!(both.meta.generation, 1);
    assert_eq!(both.meta.current_slot, SealedSlot::A);
    assert_eq!(both.meta.health, SealedHealth::Healthy);
    assert_eq!(both.payload.as_slice(), b"same");

    // Equal generation, different payload → Corrupt.
    put_encoded_slot(
        &store,
        &install_hex,
        SealedSlot::B,
        1,
        1,
        &SealedPayload::new(b"diff".to_vec()).unwrap(),
        &key,
    );
    assert!(matches!(
        h.sealed_load_blocking(NS),
        Err(SecureKeyError::Corrupt(_))
    ));

    // Restore B as identical replica, then disagree on key_version field only.
    put_encoded_slot(&store, &install_hex, SealedSlot::B, 1, 1, &payload, &key);
    // Spin a second key version so B can name a different key_version.
    let (v2, key2) = h.rotate_blocking(NS).unwrap();
    assert_eq!(v2, 2);
    put_encoded_slot(&store, &install_hex, SealedSlot::B, 1, 2, &payload, &key2);
    // Equal gen, different key_version → Corrupt.
    assert!(matches!(
        h.sealed_load_blocking(NS),
        Err(SecureKeyError::Corrupt(_))
    ));
}

#[test]
fn sealed_state_invalid_slot_matrix() {
    let store = FakeNativeStore::new();
    let (actor, store) = test_actor(store);
    let h = actor.handle();
    h.sealed_create_or_load_blocking(NS, SealedPayload::new(b"ok".to_vec()).unwrap())
        .unwrap();
    // Valid A, invalid (junk) B → unexplained invalid is Corrupt.
    let state_b = store
        .accounts()
        .into_iter()
        .find(|(svc, a)| svc == SECURE_KEY_SERVICE && a.ends_with("/state-b"));
    // Ensure B exists as junk even if absent.
    let install_hex = install_hex_from_store(&store);
    let ns = Namespace::parse(NS).unwrap();
    let acct_b = sealed_state_account(&install_hex, &ns, SealedSlot::B).unwrap();
    store.put_raw(SECURE_KEY_SERVICE, &acct_b, b"not-base64!!!".to_vec());
    let _ = state_b;
    assert!(matches!(
        h.sealed_load_blocking(NS),
        Err(SecureKeyError::Corrupt(_))
    ));

    // Invalid higher slot only: remove A, leave junk B → Corrupt (not NotFound).
    store.remove_raw(
        SECURE_KEY_SERVICE,
        &sealed_state_account(&install_hex, &ns, SealedSlot::A).unwrap(),
    );
    assert!(matches!(
        h.sealed_load_blocking(NS),
        Err(SecureKeyError::Corrupt(_))
    ));
}

#[test]
fn sealed_state_cas_replay_predicates() {
    let store = FakeNativeStore::new();
    let (actor, _) = test_actor(store);
    let h = actor.handle();
    let v1 = h
        .sealed_create_or_load_blocking(NS, SealedPayload::new(b"one".to_vec()).unwrap())
        .unwrap();
    let d1 = v1.meta.payload_digest;
    let v2 = h
        .sealed_compare_and_swap_blocking(NS, 1, d1, SealedPayload::new(b"two".to_vec()).unwrap())
        .unwrap();
    let d2 = v2.meta.payload_digest;

    // Lost-ack requires all three: gen+1, matching new payload, retained previous.
    // Wrong previous digest → Conflict (not silent success).
    let wrong_prev = [0u8; 32];
    let err = h
        .sealed_compare_and_swap_blocking(
            NS,
            1,
            wrong_prev,
            SealedPayload::new(b"two".to_vec()).unwrap(),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        SecureKeyError::Conflict { generation: 2, .. }
    ));

    // Wrong new payload bytes for gen+1 claim → Conflict.
    let err = h
        .sealed_compare_and_swap_blocking(NS, 1, d1, SealedPayload::new(b"nope".to_vec()).unwrap())
        .unwrap_err();
    assert!(matches!(
        err,
        SecureKeyError::Conflict { generation: 2, .. }
    ));

    // Later same-payload generation: write gen3 with payload two again.
    let v3 = h
        .sealed_compare_and_swap_blocking(NS, 2, d2, SealedPayload::new(b"two".to_vec()).unwrap())
        .unwrap();
    assert_eq!(v3.meta.generation, 3);
    assert_eq!(v3.payload.as_slice(), b"two");
    // Lost-ack for expected=2 would require current=3 and other slot gen2 digest d2.
    let replay = h
        .sealed_compare_and_swap_blocking(NS, 2, d2, SealedPayload::new(b"two".to_vec()).unwrap())
        .expect("adjacent lost-ack");
    assert_eq!(replay.meta.generation, 3);
    // Older request expected=1 after later same-payload gen3 must Conflict (not succeed).
    let err = h
        .sealed_compare_and_swap_blocking(NS, 1, d1, SealedPayload::new(b"two".to_vec()).unwrap())
        .unwrap_err();
    assert!(matches!(
        err,
        SecureKeyError::Conflict { generation: 3, .. }
    ));

    // Overflow expected against lower current → Conflict (not Corrupt).
    let err = h
        .sealed_compare_and_swap_blocking(NS, u64::MAX, d2, SealedPayload::empty())
        .unwrap_err();
    assert!(matches!(err, SecureKeyError::Conflict { .. }));
}

#[test]
fn sealed_state_key_lifecycle_refs_and_release() {
    let store = FakeNativeStore::new();
    let (actor, _, db) = test_actor_with_db(store);
    let h = actor.handle();
    let v1 = h
        .sealed_create_or_load_blocking(NS, SealedPayload::empty())
        .unwrap();
    assert_eq!(v1.meta.key_version, 1);
    let ref_v1 = sealed_state_ref_id(NS, 1);
    db.blocking_write_for_sync_maintenance({
        let id = ref_v1.clone();
        move |conn| {
            let r = get_ref_by_id_conn(conn, &id)?.expect("sealed_state ref v1");
            assert_eq!(r.consumer_kind, SEALED_STATE_CONSUMER_KIND);
            assert_eq!(r.state, SecureKeyRefState::Active);
            Ok(())
        }
    })
    .unwrap();

    // Rotate secure key; sealed still names v1 → both versions retained.
    let (v2, _) = h.rotate_blocking(NS).unwrap();
    assert_eq!(v2, 2);
    // Retire v1 blocked while sealed_state ref active.
    let err = h.retire_blocking(NS, 1);
    assert!(
        matches!(err, Err(SecureKeyError::InUse(_))),
        "expected InUse while sealed slot names v1, got {err:?}"
    );

    // First CAS under active key v2: previous slot still names v1 → both refs Active.
    let loaded = h.sealed_load_blocking(NS).unwrap();
    let next = h
        .sealed_compare_and_swap_blocking(
            NS,
            loaded.meta.generation,
            loaded.meta.payload_digest,
            SealedPayload::new(b"x".to_vec()).unwrap(),
        )
        .unwrap();
    assert_eq!(next.meta.key_version, 2);
    db.blocking_write_for_sync_maintenance({
        let id = ref_v1.clone();
        move |conn| {
            let r = get_ref_by_id_conn(conn, &id)?.expect("v1 still named by retained prior slot");
            assert_eq!(r.state, SecureKeyRefState::Active);
            let r2 = get_ref_by_id_conn(conn, &sealed_state_ref_id(NS, 2))?
                .expect("sealed ref v2 active");
            assert_eq!(r2.state, SecureKeyRefState::Active);
            Ok(())
        }
    })
    .unwrap();
    // Retire still blocked while prior slot names v1.
    assert!(matches!(
        h.retire_blocking(NS, 1),
        Err(SecureKeyError::InUse(_))
    ));

    // Second CAS replaces the old slot: v1 un-named → ref released; retire succeeds.
    let loaded2 = h.sealed_load_blocking(NS).unwrap();
    let next2 = h
        .sealed_compare_and_swap_blocking(
            NS,
            loaded2.meta.generation,
            loaded2.meta.payload_digest,
            SealedPayload::new(b"y".to_vec()).unwrap(),
        )
        .unwrap();
    assert_eq!(next2.meta.key_version, 2);
    db.blocking_write_for_sync_maintenance({
        let id = ref_v1.clone();
        move |conn| {
            if let Some(r) = get_ref_by_id_conn(conn, &id)? {
                assert_eq!(
                    r.state,
                    SecureKeyRefState::Released,
                    "old sealed ref should be released after prior slot replaced"
                );
            }
            let r2 = get_ref_by_id_conn(conn, &sealed_state_ref_id(NS, 2))?
                .expect("sealed ref v2 active");
            assert_eq!(r2.state, SecureKeyRefState::Active);
            let _ = list_blocking_refs_conn(conn, NS, 2)?;
            Ok(())
        }
    })
    .unwrap();
    h.retire_blocking(NS, 1).expect("retire un-named key v1");
}

#[test]
fn sealed_state_invalid_lower_and_higher_orientations() {
    let store = FakeNativeStore::new();
    let (actor, store) = test_actor(store);
    let h = actor.handle();
    // Create then CAS so both slots valid; corrupt A (lower gen) while B is current.
    h.sealed_create_or_load_blocking(NS, SealedPayload::new(b"a".to_vec()).unwrap())
        .unwrap();
    let v = h.sealed_load_blocking(NS).unwrap();
    let v2 = h
        .sealed_compare_and_swap_blocking(
            NS,
            v.meta.generation,
            v.meta.payload_digest,
            SealedPayload::new(b"b".to_vec()).unwrap(),
        )
        .unwrap();
    assert_eq!(v2.meta.current_slot, SealedSlot::B);
    let install_hex = install_hex_from_store(&store);
    let ns = Namespace::parse(NS).unwrap();
    // Valid B, invalid A (lower/other) → Corrupt.
    store.put_raw(
        SECURE_KEY_SERVICE,
        &sealed_state_account(&install_hex, &ns, SealedSlot::A).unwrap(),
        b"junk-a".to_vec(),
    );
    assert!(matches!(
        h.sealed_load_blocking(NS),
        Err(SecureKeyError::Corrupt(_))
    ));
    // Recreate clean state; invalidate B (higher/current) → Corrupt.
    let store2 = FakeNativeStore::new();
    let (actor2, store2) = test_actor(store2);
    let h2 = actor2.handle();
    h2.sealed_create_or_load_blocking(NS, SealedPayload::new(b"a".to_vec()).unwrap())
        .unwrap();
    let vv = h2.sealed_load_blocking(NS).unwrap();
    h2.sealed_compare_and_swap_blocking(
        NS,
        vv.meta.generation,
        vv.meta.payload_digest,
        SealedPayload::new(b"b".to_vec()).unwrap(),
    )
    .unwrap();
    let install2 = install_hex_from_store(&store2);
    store2.put_raw(
        SECURE_KEY_SERVICE,
        &sealed_state_account(&install2, &ns, SealedSlot::B).unwrap(),
        b"junk-b".to_vec(),
    );
    assert!(matches!(
        h2.sealed_load_blocking(NS),
        Err(SecureKeyError::Corrupt(_))
    ));
}

#[test]
fn sealed_state_lost_ack_requires_retained_previous() {
    let store = FakeNativeStore::new();
    let (actor, store) = test_actor(store);
    let h = actor.handle();
    let v1 = h
        .sealed_create_or_load_blocking(NS, SealedPayload::new(b"one".to_vec()).unwrap())
        .unwrap();
    let d1 = v1.meta.payload_digest;
    let v2 = h
        .sealed_compare_and_swap_blocking(NS, 1, d1, SealedPayload::new(b"two".to_vec()).unwrap())
        .unwrap();
    assert_eq!(v2.meta.generation, 2);
    // Remove retained previous (A gen1): lost-ack for expected=1 must Conflict.
    let install_hex = install_hex_from_store(&store);
    let ns = Namespace::parse(NS).unwrap();
    store.remove_raw(
        SECURE_KEY_SERVICE,
        &sealed_state_account(&install_hex, &ns, SealedSlot::A).unwrap(),
    );
    let err = h
        .sealed_compare_and_swap_blocking(NS, 1, d1, SealedPayload::new(b"two".to_vec()).unwrap())
        .unwrap_err();
    assert!(matches!(
        err,
        SecureKeyError::Conflict { generation: 2, .. }
    ));
}

#[test]
fn sealed_state_stale_saga_does_not_delete_newer() {
    // A saga for gen2 must not delete a valid native gen3 at the same account.
    let store = FakeNativeStore::new();
    let (actor, store, db) = test_actor_with_db(store);
    let h = actor.handle();
    let v1 = h
        .sealed_create_or_load_blocking(NS, SealedPayload::new(b"base".to_vec()).unwrap())
        .unwrap();
    let d1 = v1.meta.payload_digest;
    // Force AfterSet fault so a saga remains while write for gen2 landed... actually
    // complete gen2 then plant a stale saga claiming gen2 while native is gen3.
    let v2 = h
        .sealed_compare_and_swap_blocking(NS, 1, d1, SealedPayload::new(b"two".to_vec()).unwrap())
        .unwrap();
    let d2 = v2.meta.payload_digest;
    let v3 = h
        .sealed_compare_and_swap_blocking(NS, 2, d2, SealedPayload::new(b"three".to_vec()).unwrap())
        .unwrap();
    assert_eq!(v3.meta.generation, 3);
    // Plant stale CAS saga expected=1→2 targeting state-a, which now holds gen3 (newer).
    let install_hex = install_hex_from_store(&store);
    let ns = Namespace::parse(NS).unwrap();
    let target = sealed_state_account(&install_hex, &ns, SealedSlot::A).unwrap();
    let pd_hex = dig_hex(&d2); // claimed new payload for gen2, not what's on A
    let exp_hex = dig_hex(&d1);
    db.blocking_write_for_sync_maintenance({
        let target = target.clone();
        let pd_hex = pd_hex.clone();
        let exp_hex = exp_hex.clone();
        move |conn| {
            crate::db::secure_key::insert_sealed_state_saga_conn(
                conn, "stale-op", NS, "state-a", &target, 1, 2, &pd_hex, &exp_hex, "state-b", 1,
            )?;
            Ok(())
        }
    })
    .unwrap();
    h.reconcile_blocking().unwrap();
    let loaded = h.sealed_load_blocking(NS).unwrap();
    assert_eq!(
        loaded.meta.generation, 3,
        "stale saga must not delete newer valid native generation"
    );
    assert_eq!(loaded.payload.as_slice(), b"three");
}

#[test]
fn sealed_state_u64_max_saga_round_trip() {
    // Full u64 generations persist as decimal TEXT and resume correctly.
    let store = FakeNativeStore::new();
    let (actor, store, db) = test_actor_with_db(store);
    let h = actor.handle();
    h.sealed_create_or_load_blocking(NS, SealedPayload::new(b"hi".to_vec()).unwrap())
        .unwrap();
    let install_hex = install_hex_from_store(&store);
    let ns = Namespace::parse(NS).unwrap();
    let key = h.load_version_blocking(NS, 1).unwrap().1;
    let high = u64::MAX - 1;
    let max = u64::MAX;
    // Plant authoritative slot at u64::MAX under state-a.
    put_encoded_slot(
        &store,
        &install_hex,
        SealedSlot::A,
        max,
        1,
        &SealedPayload::new(b"max".to_vec()).unwrap(),
        &key,
    );
    // Plant open CAS saga claiming write of max on A (already present) for resume completion.
    // Also plant prior B at high so shape + optional prior checks are well-formed.
    put_encoded_slot(
        &store,
        &install_hex,
        SealedSlot::B,
        high,
        1,
        &SealedPayload::new(b"hi".to_vec()).unwrap(),
        &key,
    );
    let acct = sealed_state_account(&install_hex, &ns, SealedSlot::A).unwrap();
    let pd = payload_digest(b"max");
    let pd_hex = dig_hex(&pd);
    let exp_hex = dig_hex(&payload_digest(b"hi"));
    db.blocking_write_for_sync_maintenance({
        let acct = acct.clone();
        let pd_hex = pd_hex.clone();
        let exp_hex = exp_hex.clone();
        move |conn| {
            crate::db::secure_key::insert_sealed_state_saga_conn(
                conn,
                "u64-max-op",
                NS,
                "state-a",
                &acct,
                high,
                max,
                &pd_hex,
                &exp_hex,
                "state-b",
                1,
            )?;
            let row = crate::db::secure_key::get_sealed_state_saga_conn(conn, "u64-max-op")?
                .expect("saga");
            assert_eq!(row.expected_generation, high);
            assert_eq!(row.new_generation, max);
            Ok(())
        }
    })
    .unwrap();
    h.reconcile_blocking().unwrap();
    let loaded = h.sealed_load_blocking(NS).unwrap();
    assert_eq!(loaded.meta.generation, max);
    assert_eq!(loaded.payload.as_slice(), b"max");
    // Overflow from authoritative MAX is Corrupt.
    assert!(matches!(
        h.sealed_compare_and_swap_blocking(
            NS,
            max,
            loaded.meta.payload_digest,
            SealedPayload::empty()
        ),
        Err(SecureKeyError::Corrupt(_))
    ));
}

#[test]
fn sealed_state_malformed_saga_rejected_before_mutation() {
    let store = FakeNativeStore::new();
    let (actor, store, db) = test_actor_with_db(store);
    let h = actor.handle();
    h.sealed_create_or_load_blocking(NS, SealedPayload::new(b"keep".to_vec()).unwrap())
        .unwrap();
    let install_hex = install_hex_from_store(&store);
    let ns = Namespace::parse(NS).unwrap();
    let acct_b = sealed_state_account(&install_hex, &ns, SealedSlot::B).unwrap();
    // Malformed multi-step generation pair: should Corrupt on resume without deleting A.
    db.blocking_write_for_sync_maintenance({
        let acct = acct_b.clone();
        move |conn| {
            crate::db::secure_key::insert_sealed_state_saga_conn(
                conn,
                "bad-step",
                NS,
                "state-b",
                &acct,
                1,
                99, // not expected+1
                &"0".repeat(64),
                &"0".repeat(64),
                "state-a",
                1,
            )?;
            Ok(())
        }
    })
    .unwrap();
    let err = h.sealed_load_blocking(NS);
    assert!(
        matches!(err, Err(SecureKeyError::Corrupt(_))),
        "malformed saga must Corrupt, got {err:?}"
    );
    // Authoritative A still present.
    store.clear_faults();
    // Drop bad saga via direct delete to recover and prove A intact.
    db.blocking_write_for_sync_maintenance(move |conn| {
        crate::db::secure_key::delete_sealed_state_saga_conn(conn, "bad-step")?;
        Ok(())
    })
    .unwrap();
    let ok = h.sealed_load_blocking(NS).unwrap();
    assert_eq!(ok.payload.as_slice(), b"keep");
}

#[test]
fn sealed_state_released_ref_rearm_only_sealed_kind() {
    let store = FakeNativeStore::new();
    let (actor, _, db) = test_actor_with_db(store);
    let h = actor.handle();
    h.sealed_create_or_load_blocking(NS, SealedPayload::empty())
        .unwrap();
    let ref_id = sealed_state_ref_id(NS, 1);
    // Mark sealed ref Released, then reconcile re-arms it.
    db.blocking_write_for_sync_maintenance({
        let id = ref_id.clone();
        move |conn| {
            crate::db::secure_key::begin_release_consumer_ref_conn(conn, &id)?;
            crate::db::secure_key::mark_consumer_ref_released_conn(conn, &id)?;
            Ok(())
        }
    })
    .unwrap();
    h.reconcile_blocking().unwrap();
    db.blocking_write_for_sync_maintenance({
        let id = ref_id.clone();
        move |conn| {
            let r = get_ref_by_id_conn(conn, &id)?.expect("re-armed");
            assert_eq!(r.state, SecureKeyRefState::Active);
            Ok(())
        }
    })
    .unwrap();
    // Non-sealed Released ref stays terminal (Idempotent Released, not re-inserted Active).
    db.blocking_write_for_sync_maintenance(move |conn| {
        let other = "other-ref-id";
        // Need a version row - use same ns v1
        match crate::db::secure_key::reserve_consumer_ref_conn(
            conn,
            other,
            NS,
            1,
            "test-kind",
            "cid",
        )? {
            crate::db::secure_key::ReserveResult::Reserved(_) => {}
            other => panic!("reserve other {other:?}"),
        }
        crate::db::secure_key::activate_consumer_ref_conn(conn, other)?;
        crate::db::secure_key::begin_release_consumer_ref_conn(conn, other)?;
        crate::db::secure_key::mark_consumer_ref_released_conn(conn, other)?;
        match crate::db::secure_key::reserve_consumer_ref_conn(
            conn,
            other,
            NS,
            1,
            "test-kind",
            "cid",
        )? {
            crate::db::secure_key::ReserveResult::Idempotent(r) => {
                assert_eq!(r.state, SecureKeyRefState::Released);
            }
            other => panic!("non-sealed Released must stay terminal, got {other:?}"),
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn sealed_state_preverify_old_target_requires_intact_prior() {
    // Prepared saga + authentic older target + rolled-back prior → Corrupt.
    let store = FakeNativeStore::new();
    let (actor, store, db) = test_actor_with_db(store);
    let h = actor.handle();
    let v1 = h
        .sealed_create_or_load_blocking(NS, SealedPayload::new(b"one".to_vec()).unwrap())
        .unwrap();
    let d1 = v1.meta.payload_digest;
    let v2 = h
        .sealed_compare_and_swap_blocking(NS, 1, d1, SealedPayload::new(b"two".to_vec()).unwrap())
        .unwrap();
    assert_eq!(v2.meta.generation, 2);
    assert_eq!(v2.meta.current_slot, SealedSlot::B);
    let install_hex = install_hex_from_store(&store);
    let ns = Namespace::parse(NS).unwrap();
    let key = h.load_version_blocking(NS, 1).unwrap().1;
    // Plant Prepared saga for expected A/gen2 → B/gen3, but leave B as old gen (absent write)
    // and roll A back to gen1 so prior proof fails.
    put_encoded_slot(
        &store,
        &install_hex,
        SealedSlot::A,
        1,
        1,
        &SealedPayload::new(b"one".to_vec()).unwrap(),
        &key,
    );
    let target_b = sealed_state_account(&install_hex, &ns, SealedSlot::B).unwrap();
    let pd3 = payload_digest(b"three");
    let pd_hex: String = pd3.iter().map(|b| format!("{b:02x}")).collect();
    let d2_hex: String = v2
        .meta
        .payload_digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    db.blocking_write_for_sync_maintenance({
        let target_b = target_b.clone();
        let pd_hex = pd_hex.clone();
        let d2_hex = d2_hex.clone();
        move |conn| {
            crate::db::secure_key::insert_sealed_state_saga_conn(
                conn,
                "preverify-old",
                NS,
                "state-b", // target (would write gen3)
                &target_b,
                2,
                3,
                &pd_hex,
                &d2_hex,   // expected prior digest
                "state-a", // prior was A after... wait after gen2 current is B
                1,
            )?;
            Ok(())
        }
    })
    .unwrap();
    // Fix: after gen2 current is B; CAS to gen3 targets A. Adjust plant for realism.
    // Re-plant correctly: prior=B gen2, target=A for gen3.
    db.blocking_write_for_sync_maintenance(move |conn| {
        crate::db::secure_key::delete_sealed_state_saga_conn(conn, "preverify-old")?;
        Ok(())
    })
    .unwrap();
    let target_a = sealed_state_account(&install_hex, &ns, SealedSlot::A).unwrap();
    // A already rolled to gen1 (old); B is gen2 authentic.
    // Target A has authentic old gen1; prior B should still be gen2 for proof to pass...
    // Roll B away to force prior failure while A is old authentic target residue.
    store.remove_raw(SECURE_KEY_SERVICE, &target_b);
    put_encoded_slot(
        &store,
        &install_hex,
        SealedSlot::B,
        1,
        1,
        &SealedPayload::new(b"one".to_vec()).unwrap(),
        &key,
    );
    db.blocking_write_for_sync_maintenance({
        let target_a = target_a.clone();
        let pd_hex = pd_hex.clone();
        let d2_hex = d2_hex.clone();
        move |conn| {
            crate::db::secure_key::insert_sealed_state_saga_conn(
                conn,
                "preverify-old",
                NS,
                "state-a",
                &target_a,
                2,
                3,
                &pd_hex,
                &d2_hex,
                "state-b",
                1,
            )?;
            Ok(())
        }
    })
    .unwrap();
    let err = h.sealed_load_blocking(NS);
    assert!(
        matches!(err, Err(SecureKeyError::Corrupt(_))),
        "pre-verify old target with bad prior must Corrupt, got {err:?}"
    );
}

#[test]
fn sealed_state_create_saga_equal_b_is_corrupt() {
    // Create saga while authentic B gen1 exists → Corrupt (not silent drop).
    let store = FakeNativeStore::new();
    let (actor, store, db) = test_actor_with_db(store);
    let h = actor.handle();
    h.sealed_create_or_load_blocking(NS, SealedPayload::new(b"a".to_vec()).unwrap())
        .unwrap();
    // Force a second create-style saga after state exists: plant create saga expecting empty.
    let install_hex = install_hex_from_store(&store);
    let ns = Namespace::parse(NS).unwrap();
    // Move current to B so A is free, plant create-like saga targeting A while B has gen1-equivalent content.
    let v = h.sealed_load_blocking(NS).unwrap();
    h.sealed_compare_and_swap_blocking(
        NS,
        v.meta.generation,
        v.meta.payload_digest,
        SealedPayload::new(b"b".to_vec()).unwrap(),
    )
    .unwrap();
    // Remove A so create could target A; B has gen2. Plant create saga (expected 0→1) with B present equal-ish.
    // Create proof fails if B is valid with generation <= 1. Put gen1-like on B by overwriting.
    let key = h.load_version_blocking(NS, 1).unwrap().1;
    put_encoded_slot(
        &store,
        &install_hex,
        SealedSlot::B,
        1,
        1,
        &SealedPayload::new(b"x".to_vec()).unwrap(),
        &key,
    );
    store.remove_raw(
        SECURE_KEY_SERVICE,
        &sealed_state_account(&install_hex, &ns, SealedSlot::A).unwrap(),
    );
    let acct_a = sealed_state_account(&install_hex, &ns, SealedSlot::A).unwrap();
    let pd = payload_digest(b"new");
    let pd_hex: String = pd.iter().map(|b| format!("{b:02x}")).collect();
    db.blocking_write_for_sync_maintenance({
        let acct_a = acct_a.clone();
        move |conn| {
            crate::db::secure_key::insert_sealed_state_saga_conn(
                conn,
                "create-eq-b",
                NS,
                "state-a",
                &acct_a,
                0,
                1,
                &pd_hex,
                "",
                "",
                1,
            )?;
            // Residue on A (invalid) so resume attempts strip → create prior proof.
            Ok(())
        }
    })
    .unwrap();
    store.put_raw(SECURE_KEY_SERVICE, &acct_a, b"junk".to_vec());
    let err = h.sealed_load_blocking(NS);
    assert!(
        matches!(err, Err(SecureKeyError::Corrupt(_))),
        "create with equal B must Corrupt, got {err:?}"
    );
}

#[test]
fn sealed_state_verified_phase_older_target_is_corrupt() {
    // NativeVerified saga + authentic older target → Corrupt (not silent rollback).
    let store = FakeNativeStore::new();
    let (actor, store, db) = test_actor_with_db(store);
    let h = actor.handle();
    let v1 = h
        .sealed_create_or_load_blocking(NS, SealedPayload::new(b"one".to_vec()).unwrap())
        .unwrap();
    let d1 = v1.meta.payload_digest;
    let v2 = h
        .sealed_compare_and_swap_blocking(NS, 1, d1, SealedPayload::new(b"two".to_vec()).unwrap())
        .unwrap();
    let d2 = v2.meta.payload_digest;
    let v3 = h
        .sealed_compare_and_swap_blocking(NS, 2, d2, SealedPayload::new(b"three".to_vec()).unwrap())
        .unwrap();
    assert_eq!(v3.meta.generation, 3);
    let install_hex = install_hex_from_store(&store);
    let ns = Namespace::parse(NS).unwrap();
    let key = h.load_version_blocking(NS, 1).unwrap().1;
    // Roll target current slot back to authentic gen1 (older than verified gen3).
    put_encoded_slot(
        &store,
        &install_hex,
        v3.meta.current_slot,
        1,
        1,
        &SealedPayload::new(b"one".to_vec()).unwrap(),
        &key,
    );
    let target = sealed_state_account(&install_hex, &ns, v3.meta.current_slot).unwrap();
    let pd_hex = dig_hex(&payload_digest(b"three"));
    let exp_hex = dig_hex(&d2);
    let tgt = target_suffix(&target);
    let prior = opposite_suffix(&target);
    db.blocking_write_for_sync_maintenance({
        let target = target.clone();
        let pd_hex = pd_hex.clone();
        let exp_hex = exp_hex.clone();
        move |conn| {
            crate::db::secure_key::insert_sealed_state_saga_conn(
                conn,
                "verified-rollback",
                NS,
                tgt,
                &target,
                2,
                3,
                &pd_hex,
                &exp_hex,
                prior,
                1,
            )?;
            crate::db::secure_key::set_sealed_state_saga_phase_conn(
                conn,
                "verified-rollback",
                crate::db::secure_key::SealedStateSagaPhase::NativeVerified,
            )?;
            Ok(())
        }
    })
    .unwrap();
    let err = h.sealed_load_blocking(NS);
    assert!(
        matches!(err, Err(SecureKeyError::Corrupt(_))),
        "verified older target must Corrupt, got {err:?}"
    );
}

#[test]
fn sealed_state_malformed_digest_and_phase_are_corrupt() {
    // Non-ASCII / wrong-length digest and invalid phase must not panic or return Internal.
    let store = FakeNativeStore::new();
    let (actor, store, db) = test_actor_with_db(store);
    let h = actor.handle();
    h.sealed_create_or_load_blocking(NS, SealedPayload::empty())
        .unwrap();
    let install_hex = install_hex_from_store(&store);
    let ns = Namespace::parse(NS).unwrap();
    let acct = sealed_state_account(&install_hex, &ns, SealedSlot::B).unwrap();
    // Invalid phase text in SQLite row → Corrupt (not Internal).
    db.blocking_write_for_sync_maintenance({
        let acct = acct.clone();
        move |conn| {
            conn.execute(
                "INSERT INTO sealed_state_sagas
                    (op_id, namespace, target_slot, target_account, expected_generation,
                     new_generation, payload_digest_hex, expected_payload_digest_hex, prior_slot,
                     key_version, phase, created_at, updated_at)
                 VALUES ('bad-phase', ?1, 'state-b', ?2, '1', '2', ?3, ?3, 'state-a', 1,
                         'NotAPhase', 0, 0)",
                rusqlite::params![NS, acct, "0".repeat(64)],
            )?;
            Ok(())
        }
    })
    .unwrap();
    let err = h.sealed_load_blocking(NS);
    assert!(
        matches!(err, Err(SecureKeyError::Corrupt(_))),
        "invalid phase must Corrupt, got {err:?}"
    );
    db.blocking_write_for_sync_maintenance(move |conn| {
        crate::db::secure_key::delete_sealed_state_saga_conn(conn, "bad-phase")?;
        Ok(())
    })
    .unwrap();
    // Non-ASCII hex digest on a well-shaped row path (parse_digest_hex).
    let non_ascii = "é".repeat(32); // not 64 ASCII hex
    db.blocking_write_for_sync_maintenance({
        let acct = sealed_state_account(&install_hex, &ns, SealedSlot::B).unwrap();
        move |conn| {
            crate::db::secure_key::insert_sealed_state_saga_conn(
                conn,
                "bad-dig",
                NS,
                "state-b",
                &acct,
                1,
                2,
                &non_ascii,
                &"0".repeat(64),
                "state-a",
                1,
            )?;
            Ok(())
        }
    })
    .unwrap();
    let err = h.sealed_load_blocking(NS);
    assert!(
        matches!(err, Err(SecureKeyError::Corrupt(_))),
        "non-ascii digest must Corrupt without panic, got {err:?}"
    );
}

#[test]
fn sealed_state_malformed_prior_slot_is_corrupt() {
    // Non-create saga with empty prior_slot must Corrupt even when target matches new gen.
    let store = FakeNativeStore::new();
    let (actor, store, db) = test_actor_with_db(store);
    let h = actor.handle();
    let v1 = h
        .sealed_create_or_load_blocking(NS, SealedPayload::new(b"a".to_vec()).unwrap())
        .unwrap();
    let d1 = v1.meta.payload_digest;
    let v2 = h
        .sealed_compare_and_swap_blocking(NS, 1, d1, SealedPayload::new(b"b".to_vec()).unwrap())
        .unwrap();
    let install_hex = install_hex_from_store(&store);
    let ns = Namespace::parse(NS).unwrap();
    let target = sealed_state_account(&install_hex, &ns, v2.meta.current_slot).unwrap();
    let pd_hex = dig_hex(&v2.meta.payload_digest);
    db.blocking_write_for_sync_maintenance({
        let target = target.clone();
        let pd_hex = pd_hex.clone();
        let tgt = target_suffix(&target);
        move |conn| {
            crate::db::secure_key::insert_sealed_state_saga_conn(
                conn,
                "bad-prior",
                NS,
                tgt,
                &target,
                1,
                2,
                &pd_hex,
                &pd_hex, // digest present but prior empty
                "",      // empty prior → shape Corrupt
                1,
            )?;
            Ok(())
        }
    })
    .unwrap();
    let err = h.sealed_load_blocking(NS);
    assert!(
        matches!(err, Err(SecureKeyError::Corrupt(_))),
        "empty prior on CAS saga must Corrupt, got {err:?}"
    );
}

#[test]
fn sealed_state_phase_matrix_resume() {
    // Plant sagas at RefReserved / NativeWritten / RefActivated and prove resume outcomes.
    let store = FakeNativeStore::new();
    let (actor, store, db) = test_actor_with_db(store);
    let h = actor.handle();
    let v1 = h
        .sealed_create_or_load_blocking(NS, SealedPayload::new(b"base".to_vec()).unwrap())
        .unwrap();
    let d1 = v1.meta.payload_digest;
    let install_hex = install_hex_from_store(&store);
    let ns = Namespace::parse(NS).unwrap();
    let key = h.load_version_blocking(NS, 1).unwrap().1;
    // Write gen2 bytes to B as if AfterSet completed; leave saga at NativeWritten.
    put_encoded_slot(
        &store,
        &install_hex,
        SealedSlot::B,
        2,
        1,
        &SealedPayload::new(b"next".to_vec()).unwrap(),
        &key,
    );
    let acct_b = sealed_state_account(&install_hex, &ns, SealedSlot::B).unwrap();
    let pd_hex = dig_hex(&payload_digest(b"next"));
    let exp_hex = dig_hex(&d1);
    db.blocking_write_for_sync_maintenance({
        let acct_b = acct_b.clone();
        let pd_hex = pd_hex.clone();
        let exp_hex = exp_hex.clone();
        move |conn| {
            crate::db::secure_key::insert_sealed_state_saga_conn(
                conn, "phase-nw", NS, "state-b", &acct_b, 1, 2, &pd_hex, &exp_hex, "state-a", 1,
            )?;
            crate::db::secure_key::set_sealed_state_saga_phase_conn(
                conn,
                "phase-nw",
                crate::db::secure_key::SealedStateSagaPhase::NativeWritten,
            )?;
            Ok(())
        }
    })
    .unwrap();
    h.reconcile_blocking().unwrap();
    let loaded = h.sealed_load_blocking(NS).unwrap();
    assert_eq!(loaded.meta.generation, 2);
    assert_eq!(loaded.payload.as_slice(), b"next");

    // RefActivated + matching target → complete (drop saga).
    let v = h.sealed_load_blocking(NS).unwrap();
    let d = v.meta.payload_digest;
    put_encoded_slot(
        &store,
        &install_hex,
        SealedSlot::A,
        3,
        1,
        &SealedPayload::new(b"third".to_vec()).unwrap(),
        &key,
    );
    let acct_a = sealed_state_account(&install_hex, &ns, SealedSlot::A).unwrap();
    let pd3 = dig_hex(&payload_digest(b"third"));
    let exp2 = dig_hex(&d);
    db.blocking_write_for_sync_maintenance({
        let acct_a = acct_a.clone();
        let pd3 = pd3.clone();
        let exp2 = exp2.clone();
        move |conn| {
            crate::db::secure_key::insert_sealed_state_saga_conn(
                conn, "phase-ra", NS, "state-a", &acct_a, 2, 3, &pd3, &exp2, "state-b", 1,
            )?;
            crate::db::secure_key::set_sealed_state_saga_phase_conn(
                conn,
                "phase-ra",
                crate::db::secure_key::SealedStateSagaPhase::RefActivated,
            )?;
            Ok(())
        }
    })
    .unwrap();
    h.reconcile_blocking().unwrap();
    let loaded = h.sealed_load_blocking(NS).unwrap();
    assert_eq!(loaded.meta.generation, 3);
    assert_eq!(loaded.payload.as_slice(), b"third");
}

#[test]
fn sealed_state_stale_saga_rotated_key_preserves_newer() {
    // Stale saga under key v1 must not delete a newer gen under key v2.
    let store = FakeNativeStore::new();
    let (actor, store, db) = test_actor_with_db(store);
    let h = actor.handle();
    h.sealed_create_or_load_blocking(NS, SealedPayload::new(b"v1".to_vec()).unwrap())
        .unwrap();
    h.rotate_blocking(NS).unwrap();
    let loaded = h.sealed_load_blocking(NS).unwrap();
    // Two CAS under v2 so native generation is strictly > stale saga new_generation.
    let mid = h
        .sealed_compare_and_swap_blocking(
            NS,
            loaded.meta.generation,
            loaded.meta.payload_digest,
            SealedPayload::new(b"v2a".to_vec()).unwrap(),
        )
        .unwrap();
    assert_eq!(mid.meta.key_version, 2);
    let v3 = h
        .sealed_compare_and_swap_blocking(
            NS,
            mid.meta.generation,
            mid.meta.payload_digest,
            SealedPayload::new(b"v2-payload".to_vec()).unwrap(),
        )
        .unwrap();
    assert_eq!(v3.meta.generation, 3);
    let install_hex = install_hex_from_store(&store);
    let ns = Namespace::parse(NS).unwrap();
    // Stale CAS saga expected=1→2 under key v1 targeting current gen3 slot (newer).
    let target = sealed_state_account(&install_hex, &ns, v3.meta.current_slot).unwrap();
    let pd_hex = dig_hex(&payload_digest(b"old"));
    let exp_hex = dig_hex(&payload_digest(b"v1"));
    let tgt = target_suffix(&target);
    let prior = opposite_suffix(&target);
    db.blocking_write_for_sync_maintenance({
        let target = target.clone();
        let pd_hex = pd_hex.clone();
        let exp_hex = exp_hex.clone();
        move |conn| {
            crate::db::secure_key::insert_sealed_state_saga_conn(
                conn,
                "stale-rotated",
                NS,
                tgt,
                &target,
                1,
                2,
                &pd_hex,
                &exp_hex,
                prior,
                1, // saga still names key v1
            )?;
            Ok(())
        }
    })
    .unwrap();
    h.reconcile_blocking().unwrap();
    let after = h.sealed_load_blocking(NS).unwrap();
    assert_eq!(after.meta.generation, 3);
    assert_eq!(after.payload.as_slice(), b"v2-payload");
    assert_eq!(after.meta.key_version, 2);
}

#[test]
fn sealed_state_crash_before_get_and_after_get() {
    let store = FakeNativeStore::new();
    let (actor, store) = test_actor(store);
    let h = actor.handle();
    let v1 = h
        .sealed_create_or_load_blocking(NS, SealedPayload::new(b"base".to_vec()).unwrap())
        .unwrap();
    let d1 = v1.meta.payload_digest;

    // BeforeGet during CAS probe: no write; prior remains.
    store.inject_once(
        FaultPoint::BeforeGet,
        InjectedFault::Error(FaultKind::Unavailable),
    );
    let err = h.sealed_compare_and_swap_blocking(
        NS,
        1,
        d1,
        SealedPayload::new(b"next".to_vec()).unwrap(),
    );
    assert!(matches!(err, Err(SecureKeyError::Unavailable(_))));
    store.clear_faults();
    let still = h.sealed_load_blocking(NS).unwrap();
    assert_eq!(still.meta.generation, 1);
    assert_eq!(still.payload.as_slice(), b"base");

    // AfterSet → write landed; recovery completes gen2.
    store.inject_once(
        FaultPoint::AfterSet,
        InjectedFault::Error(FaultKind::Locked),
    );
    let err = h.sealed_compare_and_swap_blocking(
        NS,
        1,
        d1,
        SealedPayload::new(b"landed".to_vec()).unwrap(),
    );
    assert!(matches!(
        err,
        Err(SecureKeyError::Locked(_)) | Err(SecureKeyError::Unavailable(_))
    ));
    store.clear_faults();
    h.reconcile_blocking().unwrap();
    let rec = h.sealed_load_blocking(NS).unwrap();
    assert_eq!(rec.meta.generation, 2);
    assert_eq!(rec.payload.as_slice(), b"landed");
}

#[test]
fn sealed_state_platform_adapter_fixtures() {
    // No real secure store touched: kind + unreachable store crate mapping only.
    let kind = platform_store_kind();
    let reachable = reachable_native_store_crate();
    match kind {
        PlatformStoreKind::Unsupported => assert!(reachable.is_none()),
        PlatformStoreKind::ZbusSecretService => {
            assert_eq!(reachable, Some("zbus-secret-service-keyring-store"));
        }
        PlatformStoreKind::AppleKeychain => {
            assert_eq!(reachable, Some("apple-native-keyring-store"));
        }
        PlatformStoreKind::WindowsCredentialManager => {
            assert_eq!(reachable, Some("windows-native-keyring-store"));
        }
    }
    // Unsupported adapter fails closed without fallback.
    let unsup = super::native_store::UnsupportedNativeStore;
    use super::native_store::NativeKeyStore;
    assert!(matches!(
        unsup.list_accounts(SECURE_KEY_SERVICE),
        Ok(v) if v.is_empty()
    ));
    assert!(matches!(
        unsup.get_secret(SECURE_KEY_SERVICE, "x"),
        Err(SecureKeyError::Unavailable(_))
    ));
}

#[test]
fn sealed_state_missing_key_version_is_corrupt() {
    let store = FakeNativeStore::new();
    let (actor, store) = test_actor(store);
    let h = actor.handle();
    h.sealed_create_or_load_blocking(NS, SealedPayload::empty())
        .unwrap();
    let install_hex = install_hex_from_store(&store);
    let key = h.load_version_blocking(NS, 1).unwrap().1;
    // Overwrite A with item naming key_version 99 which does not exist.
    put_encoded_slot(
        &store,
        &install_hex,
        SealedSlot::A,
        1,
        99,
        &SealedPayload::empty(),
        &key, // MAC uses v1 material but claims version 99
    );
    // decode requires key 99 → NotFound → Corrupt for missing named key.
    let err = h.sealed_load_blocking(NS).unwrap_err();
    assert!(
        matches!(err, SecureKeyError::Corrupt(_)),
        "missing named key must be Corrupt, got {err}"
    );
}

#[test]
fn sealed_state_enumeration_does_not_adopt_extra() {
    // Enumeration finds third account but never loads it as current.
    // Covered by third_account Corrupt; additionally ensure only fixed a/b are writable paths.
    let store = FakeNativeStore::new();
    let (actor, store) = test_actor(store);
    let h = actor.handle();
    h.sealed_create_or_load_blocking(NS, SealedPayload::new(b"a".to_vec()).unwrap())
        .unwrap();
    let install_hex = install_hex_from_store(&store);
    let ns = Namespace::parse(NS).unwrap();
    // Put junk at a non-state account under prefix (version-like) — ignored, load still works.
    let junk = format!("{}/audit-head%2Fv1/v99999999", install_hex);
    store.put_raw(SECURE_KEY_SERVICE, &junk, b"ignore".to_vec());
    let v = h.sealed_load_blocking(NS).unwrap();
    assert_eq!(v.payload.as_slice(), b"a");
    // Manifest-like pointer under sealed suffix is not a third state-* slot.
    let fake_manifest = format!("{}/audit-head%2Fv1/manifest-pointer", install_hex);
    store.put_raw(SECURE_KEY_SERVICE, &fake_manifest, b"not-a-slot".to_vec());
    let v2 = h.sealed_load_blocking(NS).unwrap();
    assert_eq!(v2.payload.as_slice(), b"a");
    let _ = ns;
}

#[test]
fn sealed_state_equal_generation_payload_length_disagreement() {
    // Equal gen with same digest claim but different payload bytes is already Corrupt;
    // also equal gen with different payload lengths.
    let store = FakeNativeStore::new();
    let (actor, store) = test_actor(store);
    let h = actor.handle();
    let short = SealedPayload::new(b"ab".to_vec()).unwrap();
    h.sealed_create_or_load_blocking(NS, short.clone()).unwrap();
    let install_hex = install_hex_from_store(&store);
    let key = h.load_version_blocking(NS, 1).unwrap().1;
    put_encoded_slot(
        &store,
        &install_hex,
        SealedSlot::B,
        1,
        1,
        &SealedPayload::new(b"abc".to_vec()).unwrap(),
        &key,
    );
    assert!(matches!(
        h.sealed_load_blocking(NS),
        Err(SecureKeyError::Corrupt(_))
    ));
}

#[test]
fn sealed_state_both_slots_invalid_is_corrupt() {
    let store = FakeNativeStore::new();
    let (actor, store) = test_actor(store);
    let h = actor.handle();
    h.sealed_create_or_load_blocking(NS, SealedPayload::empty())
        .unwrap();
    let install_hex = install_hex_from_store(&store);
    let ns = Namespace::parse(NS).unwrap();
    let a = sealed_state_account(&install_hex, &ns, SealedSlot::A).unwrap();
    let b = sealed_state_account(&install_hex, &ns, SealedSlot::B).unwrap();
    store.put_raw(SECURE_KEY_SERVICE, &a, b"junk-a".to_vec());
    store.put_raw(SECURE_KEY_SERVICE, &b, b"junk-b".to_vec());
    assert!(matches!(
        h.sealed_load_blocking(NS),
        Err(SecureKeyError::Corrupt(_))
    ));
}

#[test]
fn sealed_state_zero_generation_item_is_corrupt() {
    // Encoder rejects gen0; present-but-unauthenticated item is always Corrupt.
    let store = FakeNativeStore::new();
    let (actor, store) = test_actor(store);
    let h = actor.handle();
    h.sealed_create_or_load_blocking(NS, SealedPayload::empty())
        .unwrap();
    let install_hex = install_hex_from_store(&store);
    let ns = Namespace::parse(NS).unwrap();
    // Load key before planting corrupt residue (reconcile fails closed on Invalid).
    let key = h.load_version_blocking(NS, 1).unwrap().1;
    let install = {
        let mut a = [0u8; 16];
        for i in 0..16 {
            a[i] = u8::from_str_radix(&install_hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        a
    };
    assert!(
        super::sealed_state::encode_item_base64url(
            &install,
            &ns,
            SealedSlot::A,
            0,
            1,
            &SealedPayload::empty(),
            &key,
        )
        .is_err()
    );
    assert!(
        super::sealed_state::encode_item_base64url(
            &install,
            &ns,
            SealedSlot::A,
            1,
            0,
            &SealedPayload::empty(),
            &key,
        )
        .is_err()
    );
    let acct = sealed_state_account(&install_hex, &ns, SealedSlot::A).unwrap();
    store.put_raw(
        SECURE_KEY_SERVICE,
        &acct,
        b"not-a-valid-sealed-item".to_vec(),
    );
    assert!(matches!(
        h.sealed_load_blocking(NS),
        Err(SecureKeyError::Corrupt(_))
    ));
}

#[test]
fn sealed_state_crash_restart_new_actor() {
    // Simulate process restart: same FakeNativeStore + Db, new actor, reconcile.
    let store = FakeNativeStore::new();
    let db = Db::open_in_memory().unwrap();
    let recon = Arc::new(
        MapReconciler::new()
            .with_kind("test", |_| false)
            .with_kind(SEALED_STATE_CONSUMER_KIND, |_| true),
    );
    let actor1 =
        SecureKeyActor::start_with_store(db.clone(), Box::new(store.clone()), recon.clone())
            .unwrap();
    let h1 = actor1.handle();
    let v1 = h1
        .sealed_create_or_load_blocking(NS, SealedPayload::new(b"base".to_vec()).unwrap())
        .unwrap();
    let d1 = v1.meta.payload_digest;
    store.inject_once(
        FaultPoint::AfterSet,
        InjectedFault::Error(FaultKind::Unavailable),
    );
    let _ = h1.sealed_compare_and_swap_blocking(
        NS,
        1,
        d1,
        SealedPayload::new(b"next".to_vec()).unwrap(),
    );
    store.clear_faults();
    // Drop first actor (end process) and start second with same db/store.
    drop(actor1);
    let actor2 = SecureKeyActor::start_with_store(db, Box::new(store.clone()), recon).unwrap();
    let h2 = actor2.handle();
    h2.reconcile_blocking().unwrap();
    let rec = h2.sealed_load_blocking(NS).unwrap();
    assert_eq!(
        rec.meta.generation, 2,
        "AfterSet restart must complete verified gen2"
    );
    assert_eq!(rec.payload.as_slice(), b"next");
}

#[test]
fn sealed_state_payload_privacy_surfaces() {
    // SealedPayload / SealedStateView must not leak payload bytes via Debug.
    let p = SealedPayload::new(b"secret-payload-bytes".to_vec()).unwrap();
    let view = SealedStateView {
        meta: super::sealed_state::SealedStateMeta {
            namespace: NS.to_owned(),
            generation: 1,
            payload_digest: payload_digest(b"secret-payload-bytes"),
            key_version: 1,
            health: SealedHealth::Healthy,
            current_slot: SealedSlot::A,
        },
        payload: p,
    };
    let dbg = format!("{view:?}");
    assert!(
        !dbg.contains("secret-payload-bytes"),
        "Debug must redact payload, got {dbg}"
    );
    assert!(dbg.contains("REDACTED") || dbg.contains("payload"));
    // SealedPayload is not Debug (unwrap_err would not compile on Ok(SealedPayload)).
    // Runtime: oversized payload error must not include raw payload bytes.
    match SealedPayload::new(vec![0xab; MAX_PAYLOAD_LEN + 1]) {
        Err(err) => {
            let msg = format!("{err}");
            assert!(!msg.contains('\u{ab}'));
        }
        Ok(_) => panic!("oversized payload must be rejected"),
    }
}

#[test]
fn sealed_state_sqlite_ref_rollback_reblocks() {
    // If SQLite sealed_state ref is deleted while native slot still names the key,
    // startup reconcile re-pins Active and retirement of the retained key stays blocked.
    let store = FakeNativeStore::new();
    let (actor, _, db) = test_actor_with_db(store);
    let h = actor.handle();
    h.sealed_create_or_load_blocking(NS, SealedPayload::empty())
        .unwrap();
    // Rotate so key v1 is Retained (not Active); sealed slot still names v1.
    let (v2, _) = h.rotate_blocking(NS).unwrap();
    assert_eq!(v2, 2);
    let ref_id = sealed_state_ref_id(NS, 1);
    db.blocking_write_for_sync_maintenance({
        let id = ref_id.clone();
        move |conn| {
            conn.execute(
                "DELETE FROM secure_key_consumer_refs WHERE reference_id = ?1",
                rusqlite::params![id],
            )?;
            Ok(())
        }
    })
    .unwrap();
    // Without re-pin, Retained v1 would be retireable — reconcile must re-pin from slots.
    h.reconcile_blocking().unwrap();
    db.blocking_write_for_sync_maintenance({
        let id = ref_id.clone();
        move |conn| {
            let r = get_ref_by_id_conn(conn, &id)?.expect("ref re-pinned from native slot");
            assert_eq!(r.state, SecureKeyRefState::Active);
            Ok(())
        }
    })
    .unwrap();
    assert!(
        matches!(h.retire_blocking(NS, 1), Err(SecureKeyError::InUse(_))),
        "re-pinned sealed_state ref must block retirement"
    );
}
