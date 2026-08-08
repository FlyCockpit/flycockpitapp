use super::*;
use crate::clipboard::types::Confidence;

fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().join("clipboard-recovery");
    (tmp, dir)
}

// ---------------------------------------------------------------------
// AC2: clipboard_recovery_off_writes_nothing (failed/unverified/confirmed).
// ---------------------------------------------------------------------

#[test]
fn off_mode_performs_zero_filesystem_operations_for_every_outcome() {
    let (tmp, dir) = scratch();
    for confidence in [
        Confidence::Failed,
        Confidence::Unverified,
        Confidence::Confirmed,
    ] {
        let outcome = observe_delivery_at(ClipboardRecovery::Off, confidence, "secret text", &dir);
        assert_eq!(outcome, RecoveryOutcome::Skipped(SkipReason::RecoveryOff));
    }
    assert!(
        !dir.exists(),
        "Off must never create the recovery directory"
    );
    drop(tmp);
}

#[test]
fn confirmed_copy_writes_nothing_even_when_recovery_is_on() {
    let (_tmp, dir) = scratch();
    let outcome = observe_delivery_at(
        ClipboardRecovery::PrivateFile,
        Confidence::Confirmed,
        "secret",
        &dir,
    );
    assert_eq!(
        outcome,
        RecoveryOutcome::Skipped(SkipReason::ContentConfirmedDelivered)
    );
    assert!(!dir.exists());
}

#[test]
fn empty_content_never_creates_an_artifact() {
    let (_tmp, dir) = scratch();
    let outcome = observe_delivery_at(ClipboardRecovery::PrivateFile, Confidence::Failed, "", &dir);
    assert_eq!(outcome, RecoveryOutcome::Skipped(SkipReason::ContentEmpty));
    assert!(!dir.exists());
}

/// [`observe_delivery`] resolves the real state directory; this composes
/// the *same two real production functions it calls* —
/// [`skip_reason`]/[`observe_delivery_write`] — with an injected
/// directory, so a regression in either (e.g. `Off` no longer short
/// -circuiting, or the write path losing a guard) fails these tests. It is
/// deliberately not a second implementation of the dispatch logic.
fn observe_delivery_at(
    mode: ClipboardRecovery,
    confidence: Confidence,
    content: &str,
    dir: &std::path::Path,
) -> RecoveryOutcome {
    match skip_reason(mode, confidence, content) {
        Some(reason) => RecoveryOutcome::Skipped(reason),
        None => observe_delivery_write(dir, content),
    }
}

// ---------------------------------------------------------------------
// AC3: clipboard_recovery_private_file (Unix perms/containment/nofollow,
// cap, flush/fsync, expiry, one-artifact steady state).
// ---------------------------------------------------------------------

#[cfg(unix)]
mod unix_private_file {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn writes_owner_only_dir_and_file_with_recoverable_content() {
        let (_tmp, dir) = scratch();
        let report = write_artifact(&dir, b"unverified clipboard text").unwrap();
        assert_eq!(report.unsafe_entries_reported, 0);

        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);

        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "exactly one live artifact");
        let artifact_path = dir.join(&names[0]);
        let file_mode = std::fs::metadata(&artifact_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(
            std::fs::read(&artifact_path).unwrap(),
            b"unverified clipboard text"
        );
    }

    #[test]
    fn cap_rejects_content_over_one_mebibyte() {
        let (_tmp, dir) = scratch();
        let oversized = vec![b'x'; MAX_ARTIFACT_BYTES + 1];
        let outcome = observe_delivery_at(
            ClipboardRecovery::PrivateFile,
            Confidence::Failed,
            &String::from_utf8(oversized).unwrap(),
            &dir,
        );
        assert_eq!(
            outcome,
            RecoveryOutcome::Skipped(SkipReason::ContentTooLarge)
        );
        assert!(
            !dir.exists(),
            "over-cap content must never touch the filesystem"
        );
    }

    #[test]
    fn exactly_at_cap_is_accepted() {
        let (_tmp, dir) = scratch();
        let exact = "a".repeat(MAX_ARTIFACT_BYTES);
        let outcome = observe_delivery_at(
            ClipboardRecovery::PrivateFile,
            Confidence::Failed,
            &exact,
            &dir,
        );
        assert!(matches!(outcome, RecoveryOutcome::Written { .. }));
    }

    #[test]
    fn replacement_keeps_exactly_one_live_artifact() {
        let (_tmp, dir) = scratch();
        write_artifact(&dir, b"first").unwrap();
        let first_names: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(first_names.len(), 1);

        write_artifact(&dir, b"second").unwrap();
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            names.len(),
            1,
            "replacement must retire the previous artifact"
        );
        let contents = std::fs::read(dir.join(&names[0])).unwrap();
        assert_eq!(contents, b"second");
    }

    #[test]
    fn expired_artifact_is_pruned_and_reported_absent() {
        let (_tmp, dir) = scratch();
        write_artifact(&dir, b"stale").unwrap();
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        let artifact = dir.join(&names[0]);
        // Backdate mtime past the expiry window.
        let stale_time = std::time::SystemTime::now() - ARTIFACT_EXPIRY - Duration::from_secs(60);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&artifact)
            .unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(stale_time))
            .unwrap();
        drop(file);

        let status = artifact_status(&dir).unwrap();
        assert!(
            status.present,
            "artifact_status still reports the stale entry"
        );
        assert!(status.expired);

        let report = reconcile_startup(&dir).unwrap();
        assert!(!report.kept);
        assert_eq!(report.removed, 1);
        assert!(!artifact.exists());
    }
}

// ---------------------------------------------------------------------
// AC4: clipboard_recovery_crash_reconcile — every write/rename/retire
// barrier and repeated startup.
// ---------------------------------------------------------------------

#[cfg(unix)]
mod crash_reconcile {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn startup_keeps_newest_of_two_crash_duplicates() {
        let (_tmp, dir) = scratch();
        // Simulate a crash between "new artifact durable" and "old
        // retired": two verified artifacts coexist.
        write_artifact(&dir, b"older").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let dir_handle_paths: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(dir_handle_paths.len(), 1);
        // Manually inject a second verified artifact (mimics the crash
        // window: the code that would have retired it never ran).
        let second = dir.join("11111111111111111111111111111111");
        std::fs::write(&second, b"newer").unwrap();
        std::fs::set_permissions(&second, std::fs::Permissions::from_mode(0o600)).unwrap();

        let report = reconcile_startup(&dir).unwrap();
        assert!(report.kept);
        assert_eq!(report.removed, 1);
        let remaining: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(
            remaining.len(),
            1,
            "exactly one artifact survives reconcile"
        );
    }

    #[test]
    fn reconcile_startup_is_idempotent_across_repeated_calls() {
        let (_tmp, dir) = scratch();
        write_artifact(&dir, b"payload").unwrap();
        let first = reconcile_startup(&dir).unwrap();
        let second = reconcile_startup(&dir).unwrap();
        let third = reconcile_startup(&dir).unwrap();
        assert_eq!(first, second);
        assert_eq!(second, third);
        assert!(first.kept);
        assert_eq!(first.removed, 0);
    }
}

// ---------------------------------------------------------------------
// AC5: clipboard_recovery_unsafe_entries — Unix symlink/hardlink/owner/
// type/path-escape cases, never opened or deleted.
// ---------------------------------------------------------------------

#[cfg(unix)]
mod unsafe_entries {
    use super::*;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    #[test]
    fn symlinked_entry_is_reported_and_never_opened_or_deleted() {
        let (tmp, dir) = scratch();
        DirHandle::open_or_create(&dir).unwrap();
        // The symlink target lives genuinely *outside* the recovery
        // directory (a sibling of `dir`, not inside it) so that exactly
        // one entry inside `dir` — the symlink itself — is unsafe. Placing
        // the target file inside `dir` would itself be a second,
        // independently-unsafe entry (default `std::fs::write`
        // permissions are not the required 0600), conflating two
        // conditions this test exists to isolate.
        let target = tmp.path().join("outside-secret");
        std::fs::write(&target, b"do not touch").unwrap();
        let link = dir.join("00000000000000000000000000000000");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let status = artifact_status(&dir).unwrap();
        assert!(!status.present);
        assert_eq!(status.unsafe_entries_reported, 1);
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert!(target.exists(), "the symlink target must be untouched");

        // A write must not clobber the unsafe entry either.
        write_artifact(&dir, b"new content").unwrap();
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    }

    #[test]
    fn hardlinked_entry_is_reported_and_never_opened_or_deleted() {
        // The realistic attack this proves against — and the one AC5 names
        // ("path escape") — is a hard link placed *inside* the private
        // recovery directory pointing at a file *outside* it: unlike a
        // symlink, `openat(O_NOFOLLOW)` does not refuse a hard link (it is
        // a completely ordinary directory entry pointing directly at the
        // target inode, not an indirection), so the nlink check is the
        // only thing that catches it. The moment the hard link is made,
        // the external file's link count becomes 2, which fails
        // `verify_unix_file`'s `nlink == 1` requirement for the one new
        // entry inside `dir` — while the external file itself is never
        // opened, read, or touched by this scan.
        let (tmp, dir) = scratch();
        DirHandle::open_or_create(&dir).unwrap();
        let external = tmp.path().join("outside-secret");
        std::fs::write(&external, b"do not touch").unwrap();
        std::fs::hard_link(&external, dir.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).unwrap();

        let status = artifact_status(&dir).unwrap();
        assert!(!status.present);
        assert_eq!(status.unsafe_entries_reported, 1);
        assert!(
            dir.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").exists(),
            "the unsafe entry is left in place, never deleted"
        );
        assert_eq!(
            std::fs::read(&external).unwrap(),
            b"do not touch",
            "the external hardlink target is never opened or touched"
        );
    }

    #[test]
    fn wrong_mode_entry_is_reported_and_never_opened_or_deleted() {
        let (_tmp, dir) = scratch();
        let handle = DirHandle::open_or_create(&dir).unwrap();
        let file = handle
            .create_file_exclusive("cccccccccccccccccccccccccccccccc")
            .unwrap();
        drop(file);
        std::fs::set_permissions(
            dir.join("cccccccccccccccccccccccccccccccc"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let status = artifact_status(&dir).unwrap();
        assert!(!status.present);
        assert_eq!(status.unsafe_entries_reported, 1);
        assert!(dir.join("cccccccccccccccccccccccccccccccc").exists());
    }

    #[test]
    fn directory_entry_is_reported_and_never_opened_or_deleted() {
        let (_tmp, dir) = scratch();
        DirHandle::open_or_create(&dir).unwrap();
        std::fs::create_dir(dir.join("dddddddddddddddddddddddddddddddd")).unwrap();

        let status = artifact_status(&dir).unwrap();
        assert!(!status.present);
        assert_eq!(status.unsafe_entries_reported, 1);
        assert!(dir.join("dddddddddddddddddddddddddddddddd").is_dir());
    }

    /// M4: a FIFO must be rejected by *type*, before ever being opened —
    /// not merely detected after an `O_RDWR` open (which does not block on
    /// Linux/macOS for a FIFO, but is still a real interaction with the
    /// pipe: it can complete a peer's blocked `open()` as a side effect).
    /// Uses a real `mkfifo`, not a stand-in.
    #[test]
    fn fifo_entry_is_reported_by_type_without_being_opened() {
        let (_tmp, dir) = scratch();
        DirHandle::open_or_create(&dir).unwrap();
        let fifo_path = dir.join("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        let cpath = std::ffi::CString::new(fifo_path.to_str().unwrap()).unwrap();
        // SAFETY: `cpath` is a live NUL-terminated string for the call.
        let made = unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
        assert_eq!(made, 0, "test setup: mkfifo failed");

        let status = artifact_status(&dir).unwrap();
        assert!(!status.present);
        assert_eq!(status.unsafe_entries_reported, 1);
        assert!(
            fifo_path.symlink_metadata().unwrap().file_type().is_fifo(),
            "the FIFO must be left exactly as found, never opened or deleted"
        );
    }

    #[test]
    fn symlinked_recovery_directory_leaf_is_refused() {
        let (tmp, _dir) = scratch();
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let link_as_dir = tmp.path().join("clipboard-recovery-link");
        std::os::unix::fs::symlink(&outside, &link_as_dir).unwrap();

        // Opening the recovery dir itself through a symlinked leaf must fail
        // rather than silently writing into `outside/`.
        assert!(DirHandle::open_or_create(&link_as_dir).is_err());
        assert!(
            std::fs::read_dir(&outside).unwrap().next().is_none(),
            "nothing must be written through a symlinked leaf"
        );
    }
}

/// Follow-up finding on M5: `retire_verified` used to close the verified
/// handle and then `unlinkat` by name a second time, leaving the same gap
/// M5 already described — a swap between verification and deletion. These
/// tests exercise `DirHandle::remove_verified` directly (the mechanism the
/// fix now routes through) rather than through the full write/reconcile
/// path, so the swap can be injected deterministically instead of relying
/// on real concurrency.
#[cfg(unix)]
mod remove_verified_toctou {
    use super::*;

    #[test]
    fn swapped_entry_is_left_alone_not_deleted_on_the_strength_of_an_earlier_verification() {
        let (_tmp, dir) = scratch();
        let handle = DirHandle::open_or_create(&dir).unwrap();
        let name = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        handle.create_file_exclusive(name).unwrap();

        // Verify — obtaining the held handle `remove_verified` will check
        // identity against — exactly what `retire_verified` does.
        let verified = match handle.open_file_verified(name).unwrap() {
            CheckedEntry::Ok(file) => file,
            _ => panic!("expected a verified file"),
        };

        // Simulate the swap: between verification and removal, the name is
        // repointed at a completely different (still otherwise-valid)
        // file. A same-user attacker able to write into this 0700
        // directory could do exactly this.
        std::fs::remove_file(dir.join(name)).unwrap();
        let replacement = handle.create_file_exclusive(name).unwrap();
        drop(replacement);

        let removed = handle.remove_verified(name, verified).unwrap();
        assert!(
            !removed,
            "a name that no longer identifies the verified object must not be removed"
        );
        assert!(
            dir.join(name).exists(),
            "the swapped-in replacement must survive untouched"
        );
    }

    #[test]
    fn unswapped_verified_entry_is_removed() {
        let (_tmp, dir) = scratch();
        let handle = DirHandle::open_or_create(&dir).unwrap();
        let name = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        handle.create_file_exclusive(name).unwrap();

        let verified = match handle.open_file_verified(name).unwrap() {
            CheckedEntry::Ok(file) => file,
            _ => panic!("expected a verified file"),
        };
        let removed = handle.remove_verified(name, verified).unwrap();
        assert!(removed, "an unswapped verified entry must be removed");
        assert!(!dir.join(name).exists());
    }
}

// ---------------------------------------------------------------------
// AC7: doctor_clipboard_metadata_only — no content read, sentinel-free
// output.
// ---------------------------------------------------------------------

#[test]
fn doctor_reports_off_without_touching_the_filesystem() {
    let (_tmp, dir) = scratch();
    let (lines, has_failures) = doctor::doctor_lines(ClipboardRecovery::Off, &dir);
    assert!(!has_failures);
    assert!(lines.iter().any(|l| l.contains("off")));
    assert!(!dir.exists());
}

#[test]
fn doctor_output_never_contains_recovered_content() {
    let (_tmp, dir) = scratch();
    const SENTINEL: &str = "SENTINEL-DO-NOT-LEAK-9f3c7a";
    write_artifact(&dir, SENTINEL.as_bytes()).unwrap();

    let (lines, has_failures) = doctor::doctor_lines(ClipboardRecovery::PrivateFile, &dir);
    assert!(!has_failures);
    let joined = lines.join("\n");
    assert!(
        !joined.contains(SENTINEL),
        "doctor output leaked content: {joined}"
    );
    assert!(joined.contains("present"));
}

/// Stronger than the sentinel-in-output check above: proves the artifact's
/// *bytes are never read at all*, not merely that they never end up in the
/// rendered string. A regression that reads the content, computes some
/// metadata from it, and discards the bytes without ever formatting them
/// into a line would pass the sentinel check above unchanged but is caught
/// here via the [`super::ARTIFACT_CONTENT_READS`] injected read-tracking
/// seam (see `inspect`'s `ReadTrackedFile` wrapper).
#[test]
fn doctor_never_reads_artifact_bytes() {
    use std::sync::atomic::Ordering;
    let (_tmp, dir) = scratch();
    write_artifact(&dir, b"content that must never be read back").unwrap();

    ARTIFACT_CONTENT_READS.store(0, Ordering::SeqCst);
    let (_lines, has_failures) = doctor::doctor_lines(ClipboardRecovery::PrivateFile, &dir);
    assert!(!has_failures);
    assert_eq!(
        ARTIFACT_CONTENT_READS.load(Ordering::SeqCst),
        0,
        "doctor must never call Read::read on the artifact file"
    );
}

#[test]
fn doctor_reports_absent_when_no_artifact_exists() {
    let (_tmp, dir) = scratch();
    let (lines, has_failures) = doctor::doctor_lines(ClipboardRecovery::PrivateFile, &dir);
    assert!(!has_failures);
    assert!(lines.iter().any(|l| l.contains("none")));
    assert!(
        !dir.exists(),
        "a /doctor read must not be what first creates the recovery directory"
    );
}

#[cfg(unix)]
#[test]
fn doctor_reports_unsafe_entry_count_without_opening_it() {
    let (_tmp, dir) = scratch();
    DirHandle::open_or_create(&dir).unwrap();
    std::os::unix::fs::symlink(
        std::env::current_exe().unwrap(),
        dir.join("00000000000000000000000000000000"),
    )
    .unwrap();
    let (lines, _) = doctor::doctor_lines(ClipboardRecovery::PrivateFile, &dir);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("unsafe entries ignored: 1"))
    );
}
