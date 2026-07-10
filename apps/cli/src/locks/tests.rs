use super::*;
use std::fs;
use tempfile::TempDir;

fn setup() -> (Db, Uuid) {
    let db = Db::open_in_memory().unwrap();
    let s = db.create_session("p", "/x", "builder").unwrap();
    (db, s.session_id)
}

fn touch(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, "").unwrap();
    p
}

fn fail_lock_reads_inserts(db: &Db) {
    db.write_blocking(move |conn| {
        conn.execute_batch(
            "CREATE TEMP TRIGGER fail_lock_reads_insert
                 BEFORE INSERT ON lock_reads
                 BEGIN
                     SELECT RAISE(FAIL, 'forced lock_reads insert failure');
                 END;",
        )?;
        Ok(())
    })
    .unwrap();
}

fn fail_lock_reads_deletes(db: &Db) {
    db.write_blocking(move |conn| {
        conn.execute_batch(
            "CREATE TEMP TRIGGER fail_lock_reads_delete
                 BEFORE DELETE ON lock_reads
                 BEGIN
                     SELECT RAISE(FAIL, 'forced lock_reads delete failure');
                 END;",
        )?;
        Ok(())
    })
    .unwrap();
}

fn fail_lock_state_deletes(db: &Db) {
    db.write_blocking(move |conn| {
        conn.execute_batch(
            "CREATE TEMP TRIGGER fail_lock_state_delete
                 BEFORE DELETE ON lock_state
                 BEGIN
                     SELECT RAISE(FAIL, 'forced lock_state delete failure');
                 END;",
        )?;
        Ok(())
    })
    .unwrap();
}

#[test]
fn acquire_and_release_round_trip() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db.clone());
    lm.acquire(&p, "builder", sid).unwrap();
    assert_eq!(lm.holder(&p).map(|(_, a)| a).as_deref(), Some("builder"));
    // Mirror landed in the DB too.
    assert_eq!(db.list_held_locks().unwrap().len(), 1);
    lm.release(&p, "builder", sid).unwrap();
    assert!(lm.holder(&p).is_none());
    assert!(db.list_held_locks().unwrap().is_empty());
}

#[test]
fn double_acquire_by_same_holder_idempotent() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    lm.acquire(&p, "builder", sid).unwrap();
    lm.acquire(&p, "builder", sid).unwrap();
}

#[test]
fn acquire_rolls_back_memory_when_read_persist_fails() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid) = setup();
    fail_lock_reads_inserts(&db);
    let lm = LockManager::in_memory(db.clone());

    let err = lm.acquire(&p, "builder", sid).unwrap_err().to_string();

    assert!(err.contains("persisting lock_acquire/read"), "{err}");
    assert!(lm.holder(&p).is_none());
    assert!(!lm.has_read(&p, "builder", sid));
    assert!(db.list_held_locks().unwrap().is_empty());
    assert!(db.list_reads_for_session(sid).unwrap().is_empty());
}

#[test]
fn swarm_disjoint_scopes_coexist_same_path_serializes() {
    // The single-writer-per-tree invariant is extended for `Swarm`
    // (GOALS §24): multiple concurrent writers coexist when their write
    // scopes are disjoint (each branch its own dedicated folder), while a
    // same-path write is still serialized/rejected as today. The lock
    // manager is already path-granular and keyed by `(session, agent)`, so
    // two distinct swarm-branch writers on disjoint paths both acquire;
    // a third targeting an already-held path is rejected.
    let tmp = TempDir::new().unwrap();
    let a = touch(tmp.path(), "branch-ca.json");
    let b = touch(tmp.path(), "branch-ny.json");
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    // Two swarm branches, distinct agent ids, disjoint dedicated paths:
    // both acquire — disjoint scopes coexist.
    lm.acquire(&a, "swarm-branch-1", sid).unwrap();
    lm.acquire(&b, "swarm-branch-2", sid).unwrap();
    assert_eq!(
        lm.holder(&a).map(|(_, ag)| ag).as_deref(),
        Some("swarm-branch-1")
    );
    assert_eq!(
        lm.holder(&b).map(|(_, ag)| ag).as_deref(),
        Some("swarm-branch-2")
    );
    // A third branch targeting branch-1's path is rejected — same-path
    // contention is still serialized (not silently weakened to a no-op).
    assert!(
        lm.acquire(&a, "swarm-branch-3", sid).is_err(),
        "same-path write by a different branch must still be rejected"
    );
    // And `check_write_permitted` agrees: branch-3 can't write a's path.
    assert!(lm.check_write_permitted(&a, "swarm-branch-3", sid).is_err());
}

#[test]
fn different_session_cannot_acquire_held_lock() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid_a) = setup();
    let s_b = db.create_session("p", "/x", "explore").unwrap();
    let lm = LockManager::in_memory(db);
    lm.acquire(&p, "builder", sid_a).unwrap();
    assert!(lm.acquire(&p, "builder", s_b.session_id).is_err());
}

#[test]
fn write_requires_prior_read_per_session() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    assert!(lm.check_write_permitted(&p, "builder", sid).is_err());
    lm.note_read(&p, "builder", sid);
    lm.check_write_permitted(&p, "builder", sid).unwrap();
}

#[test]
fn note_read_persistence_failure_does_not_mutate_memory() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid) = setup();
    fail_lock_reads_inserts(&db);
    let lm = LockManager::in_memory(db);

    lm.note_read(&p, "builder", sid);

    assert!(!lm.has_read(&p, "builder", sid));
}

#[test]
fn lock_holder_can_write() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    lm.acquire(&p, "builder", sid).unwrap();
    lm.check_write_permitted(&p, "builder", sid).unwrap();
}

#[test]
fn release_of_unheld_lock_is_noop() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    lm.release(&p, "builder", sid).unwrap();
}

#[test]
fn release_persist_failure_keeps_memory_held() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db.clone());
    lm.acquire(&p, "builder", sid).unwrap();
    fail_lock_state_deletes(&db);

    let err = lm.release(&p, "builder", sid).unwrap_err().to_string();

    assert!(err.contains("persisting lock_release"), "{err}");
    assert_eq!(
        lm.holder(&p).map(|(_, agent)| agent),
        Some("builder".into())
    );
}

#[test]
fn force_memory_release_drops_memory_when_persist_fails() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db.clone());
    lm.acquire(&p, "builder", sid).unwrap();
    fail_lock_state_deletes(&db);

    let persist_ok = lm.release_force_memory(&p, "builder", sid);

    assert!(!persist_ok);
    assert!(lm.holder(&p).is_none(), "held no longer contains canon");
    assert!(
        lm.acquire(&p, "other", sid).is_ok(),
        "another agent can acquire after forced in-memory release"
    );
}

#[tokio::test]
async fn force_memory_release_wakes_waiters_when_persist_fails() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid) = setup();
    let lm = std::sync::Arc::new(LockManager::in_memory(db.clone()));
    lm.acquire(&p, "builder", sid).unwrap();
    fail_lock_state_deletes(&db);

    let waiter_lm = lm.clone();
    let waiter_path = p.clone();
    let cancel = tokio_util::sync::CancellationToken::new();
    let waiter = tokio::spawn(async move {
        waiter_lm
            .acquire_wait(&waiter_path, "other", sid, &cancel, |_| {})
            .await
    });
    tokio::task::yield_now().await;

    assert!(!lm.release_force_memory(&p, "builder", sid));

    let acquired = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
        .await
        .expect("waiter should be notified")
        .expect("wait task should not panic")
        .expect("waiter acquire should succeed");
    assert_eq!(acquired, AcquireWait::Acquired);
    assert_eq!(lm.holder(&p).map(|(_, agent)| agent), Some("other".into()));
}

#[test]
fn release_by_wrong_agent_errors() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    lm.acquire(&p, "builder", sid).unwrap();
    assert!(lm.release(&p, "explore", sid).is_err());
}

#[test]
fn same_agent_in_different_session_cannot_release_lock() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid_a) = setup();
    let s_b = db.create_session("p", "/x", "explore").unwrap();
    let lm = LockManager::in_memory(db.clone());

    lm.acquire(&p, "builder", sid_a).unwrap();

    let err = lm.release(&p, "builder", s_b.session_id).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("another session"),
        "wrong-session release should explain ownership scope: {msg}"
    );
    assert_eq!(lm.holder(&p).map(|(s, _)| s), Some(sid_a));
    assert_eq!(db.list_held_locks().unwrap().len(), 1);

    lm.release(&p, "builder", sid_a).unwrap();
    assert!(lm.holder(&p).is_none());
    assert!(db.list_held_locks().unwrap().is_empty());
}

#[test]
fn suspend_releases_locks_and_records_hashes() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("a.rs");
    fs::write(&p, "hello").unwrap();
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    lm.acquire(&p, "builder", sid).unwrap();
    let released = lm.suspend_agent("builder", sid).unwrap();
    assert_eq!(released.len(), 1);
    assert!(lm.holder(&p).is_none());
}

#[test]
fn suspend_session_preserves_read_state_for_resume() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("a.rs");
    fs::write(&p, "hello").unwrap();
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    lm.acquire(&p, "builder", sid).unwrap();

    let released = lm.suspend_session(sid).unwrap();

    assert_eq!(released.len(), 1);
    assert!(lm.holder(&p).is_none());
    assert!(lm.has_read(&p, "builder", sid));
    let reacquired = lm.resume_session(sid).unwrap();
    assert_eq!(reacquired.len(), 1);
    assert_eq!(lm.holder(&p).map(|(_, a)| a).as_deref(), Some("builder"));
    assert!(lm.has_read(&p, "builder", sid));
}

#[test]
fn resume_reacquires_when_hash_matches() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("a.rs");
    fs::write(&p, "hello").unwrap();
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    lm.acquire(&p, "builder", sid).unwrap();
    lm.suspend_agent("builder", sid).unwrap();
    // No change to the file — resume should reacquire.
    let reacquired = lm.resume_agent("builder", sid).unwrap();
    assert_eq!(reacquired.len(), 1);
    assert_eq!(lm.holder(&p).map(|(_, a)| a).as_deref(), Some("builder"));
}

#[test]
fn transfer_agent_locks_moves_holder_and_read_guard() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("a.rs");
    fs::write(&p, "hello").unwrap();
    let (db, sid) = setup();
    let lm = LockManager::from_db(db.clone()).unwrap();

    lm.acquire(&p, "Build", sid).unwrap();
    let transferred = lm.transfer_agent_locks("Build", "Swarm", sid).unwrap();

    assert_eq!(transferred, vec![canonicalize(&p)]);
    assert_eq!(lm.holder(&p).map(|(_, a)| a).as_deref(), Some("Swarm"));
    assert!(lm.has_read(&p, "Swarm", sid));
    assert!(!lm.has_read(&p, "Build", sid));
    let held = db.list_held_locks().unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].agent_id, "Swarm");
    let reads = db.list_lock_reads().unwrap();
    assert_eq!(reads.len(), 1);
    assert_eq!(reads[0].1, "Swarm");
}

#[test]
fn transfer_agent_locks_noop_without_held_locks() {
    let (db, sid) = setup();
    let lm = LockManager::from_db(db).unwrap();
    let transferred = lm.transfer_agent_locks("Build", "Swarm", sid).unwrap();
    assert!(transferred.is_empty());
}

#[test]
fn resume_skips_when_file_changed() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("a.rs");
    fs::write(&p, "hello").unwrap();
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db.clone());
    lm.acquire(&p, "builder", sid).unwrap();
    lm.suspend_agent("builder", sid).unwrap();
    fs::write(&p, "drift").unwrap();
    let reacquired = lm.resume_agent("builder", sid).unwrap();
    assert!(reacquired.is_empty());
    assert!(lm.holder(&p).is_none());
    // §3c: stale content invalidates the read record too.
    assert!(!lm.has_read(&p, "builder", sid));
    assert!(db.list_reads_for_session(sid).unwrap().is_empty());
}

#[test]
fn resume_skips_when_another_agent_grabbed_lock() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("a.rs");
    fs::write(&p, "hello").unwrap();
    let (db, sid) = setup();
    let s_b = db.create_session("p", "/x", "builder").unwrap();
    let lm = LockManager::in_memory(db);
    lm.acquire(&p, "builder", sid).unwrap();
    lm.suspend_agent("builder", sid).unwrap();
    // Another (session, agent) takes the lock while we're suspended.
    lm.acquire(&p, "builder", s_b.session_id).unwrap();
    let reacquired = lm.resume_agent("builder", sid).unwrap();
    assert!(reacquired.is_empty());
    assert_eq!(lm.holder(&p).map(|(s, _)| s), Some(s_b.session_id));
}

// ── Multi-writer acceptance (prompt `lock-manager-multi-writer.md`) ──
//
// The lock authority is path-granular and keyed by `(session, agent)`, so
// multiple write-capable agents (no hard-coded `builder` name) coexist on
// disjoint paths while same-path contention is serialized/rejected and the
// §3c write-existing-file guard holds per writer. These assert that
// contract for two arbitrarily-named writers.

/// Two distinct write-capable agents writing **disjoint** paths both
/// succeed — disjoint-scope concurrency, no hard-coded writer name.
#[test]
fn two_writers_disjoint_paths_both_write() {
    let tmp = TempDir::new().unwrap();
    let a = touch(tmp.path(), "a.rs");
    let b = touch(tmp.path(), "b.rs");
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    // Two arbitrarily-named writers, disjoint scopes.
    lm.acquire(&a, "writer-1", sid).unwrap();
    lm.acquire(&b, "writer-2", sid).unwrap();
    // Each may write its own held path; neither blocks the other.
    lm.check_write_permitted(&a, "writer-1", sid).unwrap();
    lm.check_write_permitted(&b, "writer-2", sid).unwrap();
}

/// A second writer targeting a path the first holds is rejected with a
/// clear error — serialized/rejected, **never** silently dropped to a
/// no-op (the path stays held by the first writer).
#[test]
fn two_writers_same_path_is_rejected_not_noop() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "shared.rs");
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    lm.acquire(&p, "writer-1", sid).unwrap();
    // Acquire by the second writer is rejected, not silently accepted.
    let err = lm.acquire(&p, "writer-2", sid).unwrap_err().to_string();
    assert!(err.contains("writer-1"), "{err}");
    // And the write-permission check agrees — writer-2 cannot write it,
    // with a recovery-oriented message naming the holder and the next step.
    let werr = lm
        .check_write_permitted(&p, "writer-2", sid)
        .unwrap_err()
        .to_string();
    assert!(werr.contains("writer-1"), "{werr}");
    assert!(werr.contains("holds the lock"), "{werr}");
    // The lock was NOT weakened to a no-op: writer-1 still holds it.
    assert_eq!(lm.holder(&p).map(|(_, a)| a).as_deref(), Some("writer-1"));
    lm.check_write_permitted(&p, "writer-1", sid).unwrap();
}

/// The §3c write-existing-file guard holds for a **second** writer: a
/// writer that never read the file cannot write it even though another
/// writer is active on a different path.
#[test]
fn write_existing_file_guard_holds_for_second_writer() {
    let tmp = TempDir::new().unwrap();
    let owned = touch(tmp.path(), "owned.rs");
    let other = touch(tmp.path(), "other.rs");
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    // Writer-1 reads + holds `owned`. Writer-2 has read nothing.
    lm.acquire(&owned, "writer-1", sid).unwrap();
    // Writer-2 may not write a file it never read (no lock held on it).
    assert!(lm.check_write_permitted(&other, "writer-2", sid).is_err());
    // After an explicit read, writer-2 may write its own disjoint file.
    lm.note_read(&other, "writer-2", sid);
    lm.check_write_permitted(&other, "writer-2", sid).unwrap();
}

/// Single-writer-per-tree is preserved across two distinct write-capable
/// agents via suspend/resume: when the parent writer suspends (a child
/// writer takes the active slot) the child can acquire the same path; on
/// resume the parent reacquires it (hash unchanged).
#[test]
fn suspend_resume_serializes_two_writers_in_a_tree() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("f.rs");
    fs::write(&p, "v1").unwrap();
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    // Parent writer holds the path, then suspends (child takes the slot).
    lm.acquire(&p, "parent-writer", sid).unwrap();
    let released = lm.suspend_agent("parent-writer", sid).unwrap();
    assert_eq!(released.len(), 1);
    // The child writer (distinct agent) now acquires the freed path —
    // single active writer at a time, no overlap.
    lm.acquire(&p, "child-writer", sid).unwrap();
    assert_eq!(
        lm.holder(&p).map(|(_, a)| a).as_deref(),
        Some("child-writer")
    );
    // Child releases; parent resumes and reacquires (hash unchanged).
    lm.release(&p, "child-writer", sid).unwrap();
    let reacquired = lm.resume_agent("parent-writer", sid).unwrap();
    assert_eq!(reacquired.len(), 1);
    assert_eq!(
        lm.holder(&p).map(|(_, a)| a).as_deref(),
        Some("parent-writer")
    );
}

/// Hash-mismatch on resume forces a re-read before write for an arbitrary
/// writer: if the file drifted while the writer was suspended, resume does
/// not reacquire and the §3c read record is dropped, so a later write must
/// `readlock` again.
#[test]
fn hash_mismatch_on_resume_forces_reread_for_any_writer() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("f.rs");
    fs::write(&p, "v1").unwrap();
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    lm.acquire(&p, "writer-x", sid).unwrap();
    lm.suspend_agent("writer-x", sid).unwrap();
    // External drift while suspended.
    fs::write(&p, "v2-drift").unwrap();
    let reacquired = lm.resume_agent("writer-x", sid).unwrap();
    assert!(reacquired.is_empty(), "drifted file must not reacquire");
    assert!(lm.holder(&p).is_none());
    // Read record invalidated → write is now refused until a fresh read.
    assert!(!lm.has_read(&p, "writer-x", sid));
    assert!(lm.check_write_permitted(&p, "writer-x", sid).is_err());
}

#[test]
fn from_db_restores_state() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid) = setup();
    {
        let lm = LockManager::in_memory(db.clone());
        lm.acquire(&p, "builder", sid).unwrap();
        lm.note_read(&p, "builder", sid);
        // Drop the manager; the DB mirror persists.
    }
    let restored = LockManager::from_db(db).unwrap();
    let canon = std::fs::canonicalize(&p).unwrap();
    assert_eq!(restored.holder(&p), Some((sid, "builder".to_string())));
    assert!(restored.has_read(&canon, "builder", sid));
}

#[test]
fn from_db_restores_read_without_held_lock() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid) = setup();
    {
        let lm = LockManager::in_memory(db.clone());
        lm.note_read(&p, "builder", sid);
        assert!(lm.holder(&p).is_none());
    }

    let restored = LockManager::from_db(db).unwrap();
    assert!(restored.holder(&p).is_none());
    restored.check_write_permitted(&p, "builder", sid).unwrap();
}

#[test]
fn write_guard_serializes_two_read_but_unlocked_writers() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "shared.rs");
    let (db, sid_a) = setup();
    let sid_b = db.create_session("p", "/b", "builder").unwrap().session_id;
    let lm = LockManager::in_memory(db);
    lm.note_read(&p, "writer-a", sid_a);
    lm.note_read(&p, "writer-b", sid_b);
    assert!(lm.holder(&p).is_none());

    let guard = lm.begin_write(&p, "writer-a", sid_a).unwrap();
    let err = lm
        .begin_write(&p, "writer-b", sid_b)
        .unwrap_err()
        .to_string();

    assert!(err.contains("writer-a"), "{err}");
    assert!(err.contains("holds the lock"), "{err}");
    assert_eq!(lm.holder(&p), Some((sid_a, "writer-a".to_string())));
    drop(guard);
    assert!(lm.holder(&p).is_none());
}

#[test]
fn missing_path_spellings_normalize_to_existing_parent() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("src");
    fs::create_dir(&dir).unwrap();
    let direct = dir.join("new.rs");
    let dotted = dir.join(".").join("new.rs");
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);

    lm.note_read(&direct, "builder", sid);
    let guard = lm.begin_write(&dotted, "builder", sid).unwrap();

    assert_eq!(lm.holder(&direct), Some((sid, "builder".to_string())));
    assert_eq!(lm.holder(&dotted), Some((sid, "builder".to_string())));
    drop(guard);
    assert!(lm.holder(&direct).is_none());
}

#[test]
fn missing_path_canonicalization_matches_boundary_helper_through_symlink_dotdot() {
    let root = TempDir::new().unwrap();
    let outside_parent = TempDir::new().unwrap();
    let outside_child = outside_parent.path().join("child");
    fs::create_dir(&outside_child).unwrap();
    let link = root.path().join("link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside_child, &link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&outside_child, &link).unwrap();
    let target = link.join("../new.txt");
    let expected = crate::tools::sandbox::effective_native_path(&target).unwrap();

    assert_eq!(canonicalize(&target), expected);
    assert_eq!(expected, outside_parent.path().join("new.txt"));
}

// ── Waiter queue + idle-expiry (`readlock-wait-and-lock-expiry.md`) ──

use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// A no-op `on_wait` for tests that don't assert on the wait callback.
fn noop_on_wait(_: &(Uuid, AgentId)) {}

/// Acquire-immediately fast path: a free lock resolves to `Acquired`
/// without ever blocking (the `on_wait` callback never fires).
#[tokio::test]
async fn acquire_wait_free_path_acquires_immediately() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    let cancel = CancellationToken::new();
    let waited = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let w = waited.clone();
    let out = lm
        .acquire_wait(&p, "builder", sid, &cancel, |_| {
            w.store(true, std::sync::atomic::Ordering::Relaxed);
        })
        .await
        .unwrap();
    assert_eq!(out, AcquireWait::Acquired);
    assert!(
        !waited.load(std::sync::atomic::Ordering::Relaxed),
        "free path must not signal a wait"
    );
    assert_eq!(lm.holder(&p).map(|(_, a)| a).as_deref(), Some("builder"));
}

/// The same `(session, agent)` re-acquiring an already-held lock is
/// idempotent on the waiting path too (no block).
#[tokio::test]
async fn acquire_wait_same_holder_idempotent() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    let cancel = CancellationToken::new();
    lm.acquire(&p, "builder", sid).unwrap();
    let out = lm
        .acquire_wait(&p, "builder", sid, &cancel, noop_on_wait)
        .await
        .unwrap();
    assert_eq!(out, AcquireWait::Acquired);
}

/// WAITER QUEUE: agent A (session 1) holds the lock; agent B (session 2)
/// calls the waiting acquire. B does not error and does not return until A
/// releases — then B holds it. Ordering is asserted via a controlled
/// release (a watch channel) + `tokio::time`, never a real sleep on the
/// acquire path.
#[tokio::test(start_paused = true)]
async fn acquire_wait_blocks_until_holder_releases() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid_a) = setup();
    let s_b = db.create_session("p", "/x", "explore").unwrap();
    let lm = Arc::new(LockManager::in_memory(db));

    // A holds the lock.
    lm.acquire(&p, "builder", sid_a).unwrap();

    // B starts waiting in a task.
    let cancel = CancellationToken::new();
    let lm_b = lm.clone();
    let p_b = p.clone();
    let waited_holder = Arc::new(std::sync::Mutex::new(None::<AgentId>));
    let wh = waited_holder.clone();
    let handle = tokio::spawn(async move {
        lm_b.acquire_wait(&p_b, "builder", s_b.session_id, &cancel, move |(_, a)| {
            *crate::sync::lock_or_recover(&wh) = Some(a.clone());
        })
        .await
    });

    // Let B reach its blocked state. The task is still pending: B must NOT
    // have acquired while A holds it.
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(!handle.is_finished(), "B must block while A holds the lock");
    assert_eq!(
        crate::sync::lock_or_recover(&waited_holder).as_deref(),
        Some("builder"),
        "the wait callback names the holder B is waiting on"
    );
    // A still holds it.
    assert_eq!(lm.holder(&p).map(|(s, _)| s), Some(sid_a));

    // Controlled release: A releases → B's waiter wakes, re-contends, wins.
    lm.release(&p, "builder", sid_a).unwrap();
    let out = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
        .await
        .expect("B's wait resolves promptly after release")
        .expect("join")
        .expect("acquire_wait ok");
    assert_eq!(out, AcquireWait::Acquired);
    // B now holds it (session 2).
    assert_eq!(lm.holder(&p).map(|(s, _)| s), Some(s_b.session_id));
}

/// CANCELLED WAIT: a wait cancelled via the per-turn token returns
/// `Cancelled` promptly, acquires nothing, and leaves no registered
/// waiter — a subsequent release wakes nobody and the lock stays free for
/// the original holder's re-acquire.
#[tokio::test(start_paused = true)]
async fn acquire_wait_cancelled_leaves_no_waiter() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid_a) = setup();
    let s_b = db.create_session("p", "/x", "explore").unwrap();
    let lm = Arc::new(LockManager::in_memory(db));
    lm.acquire(&p, "builder", sid_a).unwrap();

    let cancel = CancellationToken::new();
    let lm_b = lm.clone();
    let p_b = p.clone();
    let cancel_b = cancel.clone();
    let handle = tokio::spawn(async move {
        lm_b.acquire_wait(&p_b, "builder", s_b.session_id, &cancel_b, noop_on_wait)
            .await
    });

    // B blocks.
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(!handle.is_finished());

    // Cancel the turn → B aborts promptly with `Cancelled`.
    cancel.cancel();
    let out = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
        .await
        .expect("cancel aborts the wait promptly")
        .expect("join")
        .expect("acquire_wait ok");
    assert_eq!(out, AcquireWait::Cancelled);

    // No phantom waiter: B never acquired (A still holds it), and a
    // subsequent release leaves the lock free with no stranded waiter.
    assert_eq!(lm.holder(&p).map(|(s, _)| s), Some(sid_a));
    lm.release(&p, "builder", sid_a).unwrap();
    assert!(lm.holder(&p).is_none());
}

/// IDLE EXPIRY: a lock whose last-touched is backdated past the threshold
/// is reclaimed by the sweep (called directly with a clock-controlled
/// `now`), and the §3c read-record for the former holder is invalidated.
#[test]
fn sweep_reclaims_idle_lock_and_invalidates_read_record() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let canon = std::fs::canonicalize(&p).unwrap();
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db.clone());
    lm.acquire(&p, "builder", sid).unwrap();
    assert!(lm.has_read(&canon, "builder", sid));

    // Backdate the stored last-touched well past the threshold, then sweep
    // at "now". (No wall-clock sleep — the timestamp is the clock.)
    let now = now_secs();
    {
        let mut state = crate::sync::lock_or_recover(&lm.inner);
        *state.touched.get_mut(&canon).unwrap() = now - LOCK_IDLE_TIMEOUT.as_secs() as i64 - 1;
    }
    let reclaimed = lm.sweep_expired(now).unwrap();
    assert_eq!(reclaimed.len(), 1);
    assert!(lm.holder(&p).is_none(), "idle lock must be reclaimed");
    // §3c read-record invalidated: a later write is refused until re-read.
    assert!(!lm.has_read(&canon, "builder", sid));
    assert!(lm.check_write_permitted(&p, "builder", sid).is_err());
    assert!(db.list_reads_for_session(sid).unwrap().is_empty());
}

#[test]
fn sweep_expired_rolls_back_when_read_delete_fails() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let canon = std::fs::canonicalize(&p).unwrap();
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db.clone());
    lm.acquire(&p, "builder", sid).unwrap();
    let now = now_secs();
    {
        let mut state = crate::sync::lock_or_recover(&lm.inner);
        *state.touched.get_mut(&canon).unwrap() = now - LOCK_IDLE_TIMEOUT.as_secs() as i64 - 1;
    }
    fail_lock_reads_deletes(&db);

    assert!(lm.sweep_expired(now).is_err());

    assert_eq!(lm.holder(&p), Some((sid, "builder".to_string())));
    assert!(lm.has_read(&p, "builder", sid));
    assert_eq!(db.list_held_locks().unwrap().len(), 1);
    assert_eq!(db.list_reads_for_session(sid).unwrap().len(), 1);
}

#[test]
fn sweep_skips_path_reacquired_by_other_holder_between_phases() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let canon = std::fs::canonicalize(&p).unwrap();
    let (db, sid) = setup();
    let other = db
        .create_session("p", "/other", "builder")
        .unwrap()
        .session_id;
    let lm = LockManager::in_memory(db.clone());
    lm.acquire(&p, "builder", sid).unwrap();
    let now = now_secs();
    {
        let mut state = crate::sync::lock_or_recover(&lm.inner);
        *state.touched.get_mut(&canon).unwrap() = now - LOCK_IDLE_TIMEOUT.as_secs() as i64 - 1;
    }

    let reclaimed = lm
        .sweep_expired_with_hook(now, || {
            db.lock_acquire_with_read(&canon, "builder", other).unwrap();
            let mut state = crate::sync::lock_or_recover(&lm.inner);
            state
                .held
                .insert(canon.clone(), (other, "builder".to_string()));
            state.touched.insert(canon.clone(), now);
            state
                .read_tracker
                .entry((other, "builder".to_string()))
                .or_default()
                .insert(canon.clone());
        })
        .unwrap();

    assert!(reclaimed.is_empty());
    assert_eq!(lm.holder(&p), Some((other, "builder".to_string())));
    assert!(lm.has_read(&p, "builder", other));
    let held = db.list_held_locks().unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].session_id, other);
}

#[test]
fn sweep_skips_holder_refreshed_between_collect_and_mutate() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let canon = std::fs::canonicalize(&p).unwrap();
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db.clone());
    lm.acquire(&p, "builder", sid).unwrap();
    let now = now_secs();
    {
        let mut state = crate::sync::lock_or_recover(&lm.inner);
        *state.touched.get_mut(&canon).unwrap() = now - LOCK_IDLE_TIMEOUT.as_secs() as i64 - 1;
    }

    let reclaimed = lm
        .sweep_expired_with_hook(now, || {
            db.lock_acquire_with_read(&canon, "builder", sid).unwrap();
            let mut state = crate::sync::lock_or_recover(&lm.inner);
            state.touched.insert(canon.clone(), now);
            state
                .read_tracker
                .entry((sid, "builder".to_string()))
                .or_default()
                .insert(canon.clone());
        })
        .unwrap();

    assert!(reclaimed.is_empty());
    assert_eq!(lm.holder(&p), Some((sid, "builder".to_string())));
    assert!(lm.has_read(&p, "builder", sid));
    let held = db.list_held_locks().unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].session_id, sid);
}

#[tokio::test(start_paused = true)]
async fn sweep_returns_only_actually_evicted_count() {
    let tmp = TempDir::new().unwrap();
    let evicted = touch(tmp.path(), "evicted.rs");
    let survived = touch(tmp.path(), "survived.rs");
    let evicted_canon = std::fs::canonicalize(&evicted).unwrap();
    let survived_canon = std::fs::canonicalize(&survived).unwrap();
    let (db, sid) = setup();
    let other = db
        .create_session("p", "/other", "builder")
        .unwrap()
        .session_id;
    let waiter_session = db.create_session("p", "/waiter", "builder").unwrap();
    let lm = Arc::new(LockManager::in_memory(db.clone()));
    lm.acquire(&evicted, "builder", sid).unwrap();
    lm.acquire(&survived, "builder", sid).unwrap();

    let cancel = CancellationToken::new();
    let evicted_waiter_lm = lm.clone();
    let evicted_waiter_path = evicted.clone();
    let evicted_cancel = cancel.clone();
    let evicted_waiter = tokio::spawn(async move {
        evicted_waiter_lm
            .acquire_wait(
                &evicted_waiter_path,
                "builder",
                waiter_session.session_id,
                &evicted_cancel,
                noop_on_wait,
            )
            .await
    });

    let survived_waiter_lm = lm.clone();
    let survived_waiter_path = survived.clone();
    let survived_cancel = cancel.clone();
    let survived_waiter = tokio::spawn(async move {
        survived_waiter_lm
            .acquire_wait(
                &survived_waiter_path,
                "builder",
                waiter_session.session_id,
                &survived_cancel,
                noop_on_wait,
            )
            .await
    });

    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(!evicted_waiter.is_finished());
    assert!(!survived_waiter.is_finished());

    let now = now_secs();
    {
        let mut state = crate::sync::lock_or_recover(&lm.inner);
        *state.touched.get_mut(&evicted_canon).unwrap() =
            now - LOCK_IDLE_TIMEOUT.as_secs() as i64 - 1;
        *state.touched.get_mut(&survived_canon).unwrap() =
            now - LOCK_IDLE_TIMEOUT.as_secs() as i64 - 1;
    }

    let reclaimed = lm
        .sweep_expired_with_hook(now, || {
            db.lock_acquire_with_read(&survived_canon, "builder", other)
                .unwrap();
            let mut state = crate::sync::lock_or_recover(&lm.inner);
            state
                .held
                .insert(survived_canon.clone(), (other, "builder".to_string()));
            state.touched.insert(survived_canon.clone(), now);
            state
                .read_tracker
                .entry((other, "builder".to_string()))
                .or_default()
                .insert(survived_canon.clone());
        })
        .unwrap();

    assert_eq!(reclaimed, vec![evicted_canon.clone()]);
    let out = tokio::time::timeout(std::time::Duration::from_secs(5), evicted_waiter)
        .await
        .expect("evicted path waiter wakes")
        .expect("join")
        .expect("acquire_wait ok");
    assert_eq!(out, AcquireWait::Acquired);
    tokio::task::yield_now().await;
    assert!(
        !survived_waiter.is_finished(),
        "waiter for a skipped path must remain blocked"
    );
    cancel.cancel();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), survived_waiter).await;
    assert_eq!(lm.holder(&survived), Some((other, "builder".to_string())));
}

#[test]
fn permanent_session_end_purges_session_state_only() {
    let tmp = TempDir::new().unwrap();
    let p1 = touch(tmp.path(), "a.rs");
    let p2 = touch(tmp.path(), "b.rs");
    let p3 = touch(tmp.path(), "c.rs");
    let (db, sid) = setup();
    let other = db
        .create_session("p", "/other", "builder")
        .unwrap()
        .session_id;
    let lm = LockManager::in_memory(db.clone());
    lm.acquire(&p1, "builder", sid).unwrap();
    lm.note_read(&p2, "explore", sid);
    lm.acquire(&p3, "builder", other).unwrap();
    {
        let mut state = crate::sync::lock_or_recover(&lm.inner);
        state
            .suspended
            .insert((sid, "builder".to_string()), HashMap::new());
        state.session_released.insert(sid, HashMap::new());
    }

    lm.end_session(sid).unwrap();

    assert!(lm.holder(&p1).is_none());
    assert_eq!(lm.holder(&p3), Some((other, "builder".to_string())));
    assert!(!lm.has_read(&p2, "explore", sid));
    assert!(lm.has_read(&p3, "builder", other));
    assert!(db.list_reads_for_session(sid).unwrap().is_empty());
    assert_eq!(db.list_reads_for_session(other).unwrap().len(), 1);
    let held = db.list_held_locks().unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].session_id, other);
    let state = crate::sync::lock_or_recover(&lm.inner);
    assert!(!state.suspended.keys().any(|(s, _)| *s == sid));
    assert!(!state.session_released.contains_key(&sid));
}

/// COMPLEMENT: a lock refreshed within the window is NOT reclaimed.
#[test]
fn sweep_spares_recently_touched_lock() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    lm.acquire(&p, "builder", sid).unwrap();
    // Refresh the deadline (as a tool call would), then sweep at "now".
    lm.touch_holder("builder", sid);
    let now = now_secs();
    let reclaimed = lm.sweep_expired(now).unwrap();
    assert!(
        reclaimed.is_empty(),
        "a freshly-touched lock must not be reclaimed"
    );
    assert_eq!(lm.holder(&p).map(|(_, a)| a).as_deref(), Some("builder"));
}

/// `touch_holder` pushes an about-to-expire lock back outside the window,
/// so the very next sweep spares it (the liveness-refresh contract).
#[test]
fn touch_holder_refreshes_deadline_and_survives_next_sweep() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let canon = std::fs::canonicalize(&p).unwrap();
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    lm.acquire(&p, "builder", sid).unwrap();
    let now = now_secs();
    // Drive the lock to the brink of expiry…
    {
        let mut state = crate::sync::lock_or_recover(&lm.inner);
        *state.touched.get_mut(&canon).unwrap() = now - LOCK_IDLE_TIMEOUT.as_secs() as i64 - 1;
    }
    // …then a tool call refreshes it.
    lm.touch_holder("builder", sid);
    let reclaimed = lm.sweep_expired(now).unwrap();
    assert!(reclaimed.is_empty(), "refresh must spare the lock");
    assert_eq!(lm.holder(&p).map(|(_, a)| a).as_deref(), Some("builder"));
}

/// WAITER WOKEN ON EXPIRY: a blocked `acquire_wait` proceeds when the
/// holder's lock idle-expires (the sweeper wakes waiters), with no
/// `*unlock` ever called.
#[tokio::test(start_paused = true)]
async fn waiter_woken_when_holder_lock_expires() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let canon = std::fs::canonicalize(&p).unwrap();
    let (db, sid_a) = setup();
    let s_b = db.create_session("p", "/x", "explore").unwrap();
    let lm = Arc::new(LockManager::in_memory(db));
    lm.acquire(&p, "builder", sid_a).unwrap();

    // B blocks waiting on A's lock.
    let cancel = CancellationToken::new();
    let lm_b = lm.clone();
    let p_b = p.clone();
    let handle = tokio::spawn(async move {
        lm_b.acquire_wait(&p_b, "builder", s_b.session_id, &cancel, noop_on_wait)
            .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(!handle.is_finished(), "B blocks while A holds the lock");

    // A's lock idle-expires; the sweep reclaims it and wakes B.
    let now = now_secs();
    {
        let mut state = crate::sync::lock_or_recover(&lm.inner);
        *state.touched.get_mut(&canon).unwrap() = now - LOCK_IDLE_TIMEOUT.as_secs() as i64 - 1;
    }
    let reclaimed = lm.sweep_expired(now).unwrap();
    assert_eq!(reclaimed.len(), 1);

    let out = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
        .await
        .expect("expiry wakes the waiter promptly")
        .expect("join")
        .expect("acquire_wait ok");
    assert_eq!(out, AcquireWait::Acquired);
    assert_eq!(lm.holder(&p).map(|(s, _)| s), Some(s_b.session_id));
}

#[tokio::test(start_paused = true)]
async fn acquire_wait_times_out_with_holder_context() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "held.rs");
    let (db, sid_a) = setup();
    let sid_b = db.create_session("p", "/b", "builder").unwrap().session_id;
    let lm = Arc::new(LockManager::in_memory(db));
    lm.acquire(&p, "holder", sid_a).unwrap();

    let cancel = CancellationToken::new();
    let waiter_lm = lm.clone();
    let waiter_path = p.clone();
    let handle = tokio::spawn(async move {
        waiter_lm
            .acquire_wait(&waiter_path, "waiter", sid_b, &cancel, noop_on_wait)
            .await
    });

    tokio::task::yield_now().await;
    tokio::time::advance(LOCK_WAIT_TIMEOUT + std::time::Duration::from_secs(1)).await;
    let err = handle.await.expect("join").unwrap_err().to_string();

    assert!(err.contains("timed out"), "{err}");
    assert!(err.contains("held.rs"), "{err}");
    assert!(err.contains("holder"), "{err}");
    assert_eq!(lm.holder(&p), Some((sid_a, "holder".to_string())));
}

#[tokio::test(start_paused = true)]
async fn acquire_wait_reports_wait_for_cycle_with_paths_and_holders() {
    let tmp = TempDir::new().unwrap();
    let a = touch(tmp.path(), "a.rs");
    let b = touch(tmp.path(), "b.rs");
    let (db, sid_a) = setup();
    let sid_b = db.create_session("p", "/b", "builder").unwrap().session_id;
    let lm = Arc::new(LockManager::in_memory(db));
    lm.acquire(&a, "agent-a", sid_a).unwrap();
    lm.acquire(&b, "agent-b", sid_b).unwrap();

    let cancel_a = CancellationToken::new();
    let wait_a_lm = lm.clone();
    let b_for_a = b.clone();
    let cancel_a_task = cancel_a.clone();
    let wait_a = tokio::spawn(async move {
        wait_a_lm
            .acquire_wait(&b_for_a, "agent-a", sid_a, &cancel_a_task, noop_on_wait)
            .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(!wait_a.is_finished());

    let cancel_b = CancellationToken::new();
    let err = lm
        .acquire_wait(&a, "agent-b", sid_b, &cancel_b, noop_on_wait)
        .await
        .unwrap_err()
        .to_string();

    assert!(err.contains("cycle"), "{err}");
    assert!(err.contains("agent-a"), "{err}");
    assert!(err.contains("agent-b"), "{err}");
    assert!(err.contains("a.rs"), "{err}");
    assert!(err.contains("b.rs"), "{err}");
    cancel_a.cancel();
    let out = wait_a.await.expect("join").unwrap();
    assert_eq!(out, AcquireWait::Cancelled);
}

#[tokio::test(start_paused = true)]
async fn ordered_multi_lock_acquire_avoids_reversed_path_deadlock() {
    let tmp = TempDir::new().unwrap();
    let a = touch(tmp.path(), "a.rs");
    let b = touch(tmp.path(), "b.rs");
    let (db, sid_a) = setup();
    let sid_b = db.create_session("p", "/b", "builder").unwrap().session_id;
    let lm = Arc::new(LockManager::in_memory(db));

    let cancel_a = CancellationToken::new();
    let first_lm = lm.clone();
    let first_a = a.clone();
    let first_b = b.clone();
    let (acquired_tx, acquired_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let first = tokio::spawn(async move {
        first_lm
            .acquire_wait_all_ordered(
                &[first_a.clone(), first_b.clone()],
                "agent-a",
                sid_a,
                &cancel_a,
            )
            .await
            .unwrap();
        acquired_tx.send(()).unwrap();
        release_rx.await.unwrap();
        first_lm.release(&first_b, "agent-a", sid_a).unwrap();
        first_lm.release(&first_a, "agent-a", sid_a).unwrap();
    });
    acquired_rx.await.unwrap();

    let cancel_b = CancellationToken::new();
    let second_lm = lm.clone();
    let second_a = a.clone();
    let second_b = b.clone();
    let second = tokio::spawn(async move {
        second_lm
            .acquire_wait_all_ordered(&[second_b, second_a], "agent-b", sid_b, &cancel_b)
            .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(
        !second.is_finished(),
        "second requester waits instead of deadlocking"
    );

    release_tx.send(()).unwrap();
    first.await.unwrap();
    let out = tokio::time::timeout(std::time::Duration::from_secs(5), second)
        .await
        .expect("ordered waiter completes after release")
        .expect("join")
        .expect("acquire all ok");
    assert_eq!(out, AcquireWait::Acquired);
    assert_eq!(lm.holder(&a), Some((sid_b, "agent-b".to_string())));
    assert_eq!(lm.holder(&b), Some((sid_b, "agent-b".to_string())));
}

// ── Session-scoped suspend/resume (`session-detach-lock-release.md`) ──

/// `suspend_session` releases every lock held by ANY agent under the
/// session (not just one), leaving read-records intact, and snapshots each
/// file's hash so a later `resume_session` can reacquire it.
#[test]
fn suspend_session_releases_all_agents_locks() {
    let tmp = TempDir::new().unwrap();
    let a = tmp.path().join("a.rs");
    let b = tmp.path().join("b.rs");
    fs::write(&a, "x").unwrap();
    fs::write(&b, "y").unwrap();
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    // Two distinct agents under the SAME session each hold a file.
    lm.acquire(&a, "builder", sid).unwrap();
    lm.acquire(&b, "bee", sid).unwrap();
    let released = lm.suspend_session(sid).unwrap();
    assert_eq!(released.len(), 2, "both agents' locks released");
    assert!(lm.holder(&a).is_none());
    assert!(lm.holder(&b).is_none());
    // Read-records left intact (like `suspend_agent`).
    assert!(lm.has_read(&a, "builder", sid));
    assert!(lm.has_read(&b, "bee", sid));
}

/// A session-scoped release wakes a blocked cross-session waiter, which then
/// acquires the freed path — the release/wake hook reuses `notify_waiters`.
#[tokio::test(start_paused = true)]
async fn suspend_session_wakes_cross_session_waiter() {
    let tmp = TempDir::new().unwrap();
    let p = touch(tmp.path(), "a.rs");
    let (db, sid_a) = setup();
    let s_b = db.create_session("p", "/x", "explore").unwrap();
    let lm = Arc::new(LockManager::in_memory(db));
    lm.acquire(&p, "builder", sid_a).unwrap();

    // B (a different session) blocks waiting on A's lock.
    let cancel = CancellationToken::new();
    let lm_b = lm.clone();
    let p_b = p.clone();
    let handle = tokio::spawn(async move {
        lm_b.acquire_wait(&p_b, "builder", s_b.session_id, &cancel, noop_on_wait)
            .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(!handle.is_finished(), "B blocks while A holds the lock");

    // Session A's last client detaches while idle → session-scoped release.
    let released = lm.suspend_session(sid_a).unwrap();
    assert_eq!(released.len(), 1);

    let out = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
        .await
        .expect("session release wakes the waiter promptly")
        .expect("join")
        .expect("acquire_wait ok");
    assert_eq!(out, AcquireWait::Acquired);
    assert_eq!(lm.holder(&p).map(|(s, _)| s), Some(s_b.session_id));
}

/// `resume_session` reacquires the lock for an unchanged file, restoring the
/// original `(session, agent)` holder.
#[test]
fn resume_session_reacquires_unchanged_file() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("a.rs");
    fs::write(&p, "hello").unwrap();
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    lm.acquire(&p, "builder", sid).unwrap();
    lm.suspend_session(sid).unwrap();
    assert!(lm.holder(&p).is_none());
    // No change to the file — reattach reacquires for the same holder.
    let reacquired = lm.resume_session(sid).unwrap();
    assert_eq!(reacquired.len(), 1);
    assert_eq!(lm.holder(&p), Some((sid, "builder".to_string())));
}

/// A file changed while the session was detached is NOT reacquired and its
/// §3c read-record is invalidated (a later write must `readlock` again).
#[test]
fn resume_session_skips_changed_file_and_invalidates_read() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("a.rs");
    fs::write(&p, "hello").unwrap();
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db.clone());
    lm.acquire(&p, "builder", sid).unwrap();
    lm.suspend_session(sid).unwrap();
    fs::write(&p, "drift").unwrap();
    let reacquired = lm.resume_session(sid).unwrap();
    assert!(reacquired.is_empty(), "drifted file must not reacquire");
    assert!(lm.holder(&p).is_none());
    assert!(!lm.has_read(&p, "builder", sid));
    assert!(lm.check_write_permitted(&p, "builder", sid).is_err());
    assert!(db.list_reads_for_session(sid).unwrap().is_empty());
}

/// A path taken by another `(session, agent)` while detached is NOT
/// reacquired on resume, and the detached session's read-record for it is
/// dropped so its later write must `readlock` again.
#[test]
fn resume_session_skips_taken_file_and_invalidates_read() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("a.rs");
    fs::write(&p, "hello").unwrap();
    let (db, sid) = setup();
    let s_b = db.create_session("p", "/x", "builder").unwrap();
    let lm = LockManager::in_memory(db.clone());
    lm.acquire(&p, "builder", sid).unwrap();
    lm.suspend_session(sid).unwrap();
    // Another session grabs the (unchanged) file while we're detached.
    lm.acquire(&p, "builder", s_b.session_id).unwrap();
    let reacquired = lm.resume_session(sid).unwrap();
    assert!(reacquired.is_empty(), "taken file must not reacquire");
    assert_eq!(lm.holder(&p).map(|(s, _)| s), Some(s_b.session_id));
    // The detached session's read-record is invalidated.
    assert!(!lm.has_read(&p, "builder", sid));
    assert!(db.list_reads_for_session(sid).unwrap().is_empty());
    assert_eq!(db.list_reads_for_session(s_b.session_id).unwrap().len(), 1);
}

/// `resume_session` with no release snapshot is a no-op — the path that
/// makes a second concurrent reattach (multi-attach) trigger nothing.
#[test]
fn resume_session_without_snapshot_is_noop() {
    let (db, sid) = setup();
    let lm = LockManager::in_memory(db);
    let reacquired = lm.resume_session(sid).unwrap();
    assert!(reacquired.is_empty());
    // And a second resume after a real one is also a no-op (snapshot is
    // consumed by the first), so only the FIRST reattach reacquires.
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("a.rs");
    fs::write(&p, "hello").unwrap();
    lm.acquire(&p, "builder", sid).unwrap();
    lm.suspend_session(sid).unwrap();
    assert_eq!(lm.resume_session(sid).unwrap().len(), 1);
    assert!(
        lm.resume_session(sid).unwrap().is_empty(),
        "snapshot consumed: a second reattach reacquires nothing"
    );
}
