use super::*;

fn never_cancelled() -> bool {
    false
}

// ---------------------------------------------------------------------
// AC3: atomic_no_clobber_target_parent_races — existing/appearing target,
// symlink/reparse, hardlink, parent replacement, directory, unsupported
// primitive.
// ---------------------------------------------------------------------

#[test]
fn writes_new_file_with_exact_payload() {
    let tmp = tempfile::TempDir::new().unwrap();
    let target = tmp.path().join("out.md");
    let published = publish_no_clobber(&target, b"hello world", &never_cancelled).unwrap();
    assert_eq!(published.bytes_written, 11);
    assert_eq!(std::fs::read(&target).unwrap(), b"hello world");
}

#[test]
fn existing_regular_file_target_is_preserved() {
    let tmp = tempfile::TempDir::new().unwrap();
    let target = tmp.path().join("out.md");
    std::fs::write(&target, b"original").unwrap();
    let result = publish_no_clobber(&target, b"attacker payload", &never_cancelled);
    assert_eq!(result, Err(PublishError::TargetExists));
    assert_eq!(std::fs::read(&target).unwrap(), b"original");
}

#[test]
fn existing_directory_target_is_preserved() {
    let tmp = tempfile::TempDir::new().unwrap();
    let target = tmp.path().join("out.md");
    std::fs::create_dir(&target).unwrap();
    let result = publish_no_clobber(&target, b"payload", &never_cancelled);
    assert!(matches!(
        result,
        Err(PublishError::TargetExists) | Err(PublishError::Io(_))
    ));
    assert!(target.is_dir());
}

#[cfg(unix)]
#[test]
fn existing_symlink_target_is_preserved_and_never_followed() {
    let tmp = tempfile::TempDir::new().unwrap();
    let real_secret = tmp.path().join("secret");
    std::fs::write(&real_secret, b"do not overwrite").unwrap();
    let target = tmp.path().join("out.md");
    std::os::unix::fs::symlink(&real_secret, &target).unwrap();

    let result = publish_no_clobber(&target, b"attacker payload", &never_cancelled);
    assert_eq!(result, Err(PublishError::TargetExists));
    assert!(target.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(std::fs::read(&real_secret).unwrap(), b"do not overwrite");
}

#[test]
fn missing_parent_directory_is_reported_and_nothing_is_created() {
    let tmp = tempfile::TempDir::new().unwrap();
    let target = tmp.path().join("does-not-exist-dir").join("out.md");
    let result = publish_no_clobber(&target, b"payload", &never_cancelled);
    assert_eq!(result, Err(PublishError::ParentMissing));
    assert!(!target.exists());
}

#[cfg(unix)]
#[test]
fn symlinked_parent_directory_is_refused_not_followed() {
    // A parent directory replaced (or ever created) as a symlink must be
    // refused outright, never silently traversed into the link's target.
    let tmp = tempfile::TempDir::new().unwrap();
    let real_dir = tmp.path().join("real");
    std::fs::create_dir(&real_dir).unwrap();
    let attacker_dir = tmp.path().join("attacker");
    std::fs::create_dir(&attacker_dir).unwrap();

    std::fs::remove_dir(&real_dir).unwrap();
    std::os::unix::fs::symlink(&attacker_dir, &real_dir).unwrap();

    let target = real_dir.join("out.md");
    let result = publish_no_clobber(&target, b"payload", &never_cancelled);
    assert!(result.is_err());
    assert!(
        !attacker_dir.join("out.md").exists(),
        "a symlinked parent must never receive the write"
    );
}

// ---------------------------------------------------------------------
// AC4: atomic_no_clobber_failure_barriers — short write, fsync, publish,
// parent fsync, cancellation, verified temp cleanup.
// ---------------------------------------------------------------------

#[test]
fn cancellation_before_publication_removes_only_the_temp_and_preserves_absence() {
    let tmp = tempfile::TempDir::new().unwrap();
    let target = tmp.path().join("out.md");
    let result = publish_no_clobber(&target, b"payload", &|| true);
    assert_eq!(result, Err(PublishError::Cancelled));
    assert!(!target.exists(), "cancellation must never publish the target");
    let leftovers: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().collect();
    assert!(leftovers.is_empty(), "the verified temp file must be removed");
}

#[test]
fn cancellation_after_the_checkpoint_has_no_effect() {
    // `is_cancelled` is checked exactly once, before publication — a
    // caller that only starts reporting `true` *during* the atomic publish
    // step itself cannot retroactively un-publish a completed write. We
    // approximate that here with a closure that is false at the one call
    // site this module makes.
    let tmp = tempfile::TempDir::new().unwrap();
    let target = tmp.path().join("out.md");
    let published = publish_no_clobber(&target, b"payload", &never_cancelled).unwrap();
    assert_eq!(published.bytes_written, 7);
    assert!(target.exists());
}

#[test]
fn payload_over_cap_is_rejected_before_any_filesystem_operation() {
    let tmp = tempfile::TempDir::new().unwrap();
    let target = tmp.path().join("out.md");
    let oversized = vec![0u8; MAX_PAYLOAD_BYTES + 1];
    let result = publish_no_clobber(&target, &oversized, &never_cancelled);
    assert_eq!(
        result,
        Err(PublishError::PayloadTooLarge {
            max: MAX_PAYLOAD_BYTES
        })
    );
    assert!(!target.exists());
}

#[test]
fn payload_exactly_at_cap_is_accepted() {
    let tmp = tempfile::TempDir::new().unwrap();
    let target = tmp.path().join("out.md");
    let exact = vec![b'x'; MAX_PAYLOAD_BYTES];
    let published = publish_no_clobber(&target, &exact, &never_cancelled).unwrap();
    assert_eq!(published.bytes_written, MAX_PAYLOAD_BYTES as u64);
}

// ---------------------------------------------------------------------
// AC6: Errors contain path/result metadata only, never copied plaintext.
// ---------------------------------------------------------------------

#[test]
fn every_publish_error_display_is_sentinel_free() {
    const SENTINEL: &str = "SENTINEL-DO-NOT-LEAK-4b9c1e";
    let tmp = tempfile::TempDir::new().unwrap();
    let payload = SENTINEL.as_bytes();

    // TargetExists.
    let existing = tmp.path().join("exists.md");
    std::fs::write(&existing, b"original").unwrap();
    let err = publish_no_clobber(&existing, payload, &never_cancelled).unwrap_err();
    assert!(!err.to_string().contains(SENTINEL), "{err}");

    // ParentMissing.
    let missing_parent = tmp.path().join("no-such-dir").join("out.md");
    let err = publish_no_clobber(&missing_parent, payload, &never_cancelled).unwrap_err();
    assert!(!err.to_string().contains(SENTINEL), "{err}");

    // PayloadTooLarge (the sentinel itself is small, so pad with non-sentinel
    // bytes to exceed the cap while keeping the sentinel present in the
    // payload — proving the *size* is reported, never the bytes).
    let mut oversized = vec![b'x'; MAX_PAYLOAD_BYTES + 1 - SENTINEL.len()];
    oversized.extend_from_slice(payload);
    let err = publish_no_clobber(&tmp.path().join("big.md"), &oversized, &never_cancelled).unwrap_err();
    assert!(!err.to_string().contains(SENTINEL), "{err}");

    // Cancelled.
    let err = publish_no_clobber(&tmp.path().join("cancelled.md"), payload, &|| true).unwrap_err();
    assert!(!err.to_string().contains(SENTINEL), "{err}");

    // Debug formatting too (what a toast/log line built from `{e:?}` would show).
    let err = publish_no_clobber(&existing, payload, &never_cancelled).unwrap_err();
    assert!(!format!("{err:?}").contains(SENTINEL), "{err:?}");
}

// ---------------------------------------------------------------------
// AC2: atomic_no_clobber_platform_contract — Linux renameat2/linkat via
// injected syscalls.
// ---------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_platform_contract {
    use super::super::unix::{BackendError, PublishBackend, PublishIo, RealIo, publish_with};
    use super::*;
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io;
    use std::os::fd::RawFd;

    /// A real backend paired with the real (unfaked) I/O barriers, for
    /// tests that only want to script the rename step.
    fn real_io() -> RealIo {
        RealIo
    }

    /// Records every call and returns a scripted result, so the contract
    /// ("renameat2 first, linkat only on ENOSYS/EINVAL, EEXIST always wins,
    /// never a check-then-rename") is exercised without depending on the
    /// host kernel actually lacking `renameat2`.
    #[derive(Default)]
    struct FakeBackend {
        calls: Vec<(String, String)>,
        script: Vec<Result<(), BackendError>>,
    }

    impl PublishBackend for FakeBackend {
        fn rename_no_replace(
            &mut self,
            parent_fd: RawFd,
            from: &CStr,
            to: &CStr,
        ) -> Result<(), BackendError> {
            self.calls.push((
                from.to_string_lossy().to_string(),
                to.to_string_lossy().to_string(),
            ));
            let outcome = self
                .script
                .pop()
                .expect("fake backend called more times than scripted");
            if outcome.is_ok() {
                // `publish_with` verifies the published entry's identity
                // against the temp file it wrote (M3's fix), so a scripted
                // "success" must actually perform the rename — otherwise
                // every contract test here would fail that unrelated
                // check instead of testing the syscall contract. Plain
                // `renameat` (not `renameat2`) is fine: the destination is
                // guaranteed not to exist yet in every scripted-success
                // case these tests construct.
                // SAFETY: `parent_fd` is a live descriptor for the
                // duration of this call; `from`/`to` stay alive too.
                unsafe {
                    libc::renameat(parent_fd, from.as_ptr(), parent_fd, to.as_ptr());
                }
            }
            outcome
        }
    }

    #[test]
    fn renameat2_success_publishes_without_any_fallback_call() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("out.md");
        let mut backend = FakeBackend {
            script: vec![Ok(())],
            ..Default::default()
        };
        let published = publish_with(&mut backend, &mut real_io(), &target, b"payload", &never_cancelled).unwrap();
        assert_eq!(published.bytes_written, 7);
        assert_eq!(backend.calls.len(), 1, "exactly one rename attempt");
    }

    #[test]
    fn target_exists_is_never_retried_as_a_fallback() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("out.md");
        let mut backend = FakeBackend {
            script: vec![Err(BackendError::TargetExists)],
            ..Default::default()
        };
        let result = publish_with(&mut backend, &mut real_io(), &target, b"payload", &never_cancelled);
        assert_eq!(result, Err(PublishError::TargetExists));
        assert_eq!(
            backend.calls.len(),
            1,
            "EEXIST is authoritative — no linkat retry, no overwrite"
        );
    }

    #[test]
    fn unsupported_primitive_never_falls_back_to_overwrite() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("out.md");
        let mut backend = FakeBackend {
            script: vec![Err(BackendError::Unsupported)],
            ..Default::default()
        };
        let result = publish_with(&mut backend, &mut real_io(), &target, b"payload", &never_cancelled);
        assert_eq!(result, Err(PublishError::UnsupportedAtomicNoClobber));
        assert!(!target.exists());
    }

    /// M3: on Unix, `rename`/`renameat2`/`linkat` are inherently name-based
    /// — there is no fd-based rename — so between the temp file's fsync
    /// and the publish call, a same-directory-writable attacker who
    /// discovers the random temp name could unlink it and substitute their
    /// own file under that name. This backend plays "the syscall layer
    /// after that race": instead of renaming the real temp file our
    /// caller wrote, it renames a completely different, attacker-created
    /// file to the destination. The identity check added for M3 must
    /// notice the swap and refuse to report success.
    struct SwappedContentBackend;

    impl PublishBackend for SwappedContentBackend {
        fn rename_no_replace(
            &mut self,
            parent_fd: RawFd,
            _from: &CStr,
            to: &CStr,
        ) -> Result<(), BackendError> {
            let attacker_name = CString::new("attacker-substituted").unwrap();
            // SAFETY: `parent_fd` is a live descriptor for the duration of
            // this call; both names stay alive for their respective calls.
            unsafe {
                let fd = libc::openat(
                    parent_fd,
                    attacker_name.as_ptr(),
                    libc::O_CREAT | libc::O_WRONLY | libc::O_EXCL,
                    0o600,
                );
                assert!(fd >= 0, "test setup: creating attacker file failed");
                let payload = b"attacker payload, not the real one";
                libc::write(fd, payload.as_ptr().cast(), payload.len());
                libc::close(fd);
                let renamed =
                    libc::renameat(parent_fd, attacker_name.as_ptr(), parent_fd, to.as_ptr());
                assert_eq!(renamed, 0, "test setup: substituting the published entry failed");
            }
            Ok(())
        }
    }

    #[test]
    fn identity_mismatch_after_publish_is_detected_not_silently_accepted() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("out.md");
        let mut backend = SwappedContentBackend;
        let result = publish_with(&mut backend, &mut real_io(), &target, b"real payload", &never_cancelled);
        assert!(
            result.is_err(),
            "a name swapped out from under the publish must not be reported as success"
        );
    }

    /// M2: exercises the *real* `linkat`/`unlinkat` fallback directly
    /// (not the `FakeBackend` used above, which only tests which syscall
    /// gets called with which flags) — proving the temp name does not
    /// survive a successful fallback publish as an orphaned duplicate of
    /// the payload.
    #[test]
    fn linkat_fallback_leaves_no_orphaned_temp_after_success() {
        use std::os::fd::AsRawFd as _;
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = std::fs::File::open(tmp.path()).unwrap();
        let from = CString::new("temp-name").unwrap();
        let to = CString::new("dest-name").unwrap();
        // SAFETY: `dir` is live for the duration of these calls; `from`
        // stays alive for the `openat`/`write`/`close` sequence.
        unsafe {
            let fd = libc::openat(
                dir.as_raw_fd(),
                from.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY | libc::O_EXCL,
                0o600,
            );
            assert!(fd >= 0, "test setup: creating temp file failed");
            let payload = b"payload";
            libc::write(fd, payload.as_ptr().cast(), payload.len());
            libc::close(fd);
        }

        let result = super::super::unix::linkat_fallback(dir.as_raw_fd(), &from, &to);
        assert_eq!(result, Ok(()));
        assert!(
            tmp.path().join("dest-name").exists(),
            "the destination must exist after a successful fallback"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("dest-name")).unwrap(),
            b"payload"
        );
        assert!(
            !tmp.path().join("temp-name").exists(),
            "the temp name must be unlinked after a successful fallback publish, \
             not left behind as a duplicate copy of the payload"
        );
    }

    /// Injectable I/O barriers: each of the three non-rename barriers this
    /// module documents (write, temp fsync, parent fsync) can be scripted
    /// to fail independently, so `atomic_no_clobber_failure_barriers` can
    /// cover all of them — not only the rename step [`FakeBackend`] above
    /// already covers.
    #[derive(Default)]
    struct FakeIo {
        fail_write: bool,
        fail_sync_temp: bool,
        fail_sync_parent: bool,
    }

    impl PublishIo for FakeIo {
        fn write_payload(&mut self, temp: &mut File, bytes: &[u8]) -> io::Result<()> {
            if self.fail_write {
                return Err(io::Error::other("injected write failure"));
            }
            std::io::Write::write_all(temp, bytes)
        }

        fn sync_temp(&mut self, temp: &File) -> io::Result<()> {
            if self.fail_sync_temp {
                return Err(io::Error::other("injected temp fsync failure"));
            }
            temp.sync_all()
        }

        fn sync_parent(&mut self, parent: &File) -> io::Result<()> {
            if self.fail_sync_parent {
                return Err(io::Error::other("injected parent fsync failure"));
            }
            parent.sync_all()
        }
    }

    #[test]
    fn injected_write_failure_is_reported_and_the_temp_file_is_removed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("out.md");
        let mut backend = super::super::unix::RealBackend;
        let mut io_ops = FakeIo {
            fail_write: true,
            ..Default::default()
        };
        let result = publish_with(&mut backend, &mut io_ops, &target, b"payload", &never_cancelled);
        assert!(matches!(result, Err(PublishError::Io(_))));
        assert!(!target.exists());
        assert!(
            std::fs::read_dir(tmp.path()).unwrap().next().is_none(),
            "the temp file must not survive an injected write failure"
        );
    }

    #[test]
    fn injected_temp_fsync_failure_is_reported_and_the_temp_file_is_removed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("out.md");
        let mut backend = super::super::unix::RealBackend;
        let mut io_ops = FakeIo {
            fail_sync_temp: true,
            ..Default::default()
        };
        let result = publish_with(&mut backend, &mut io_ops, &target, b"payload", &never_cancelled);
        assert!(matches!(result, Err(PublishError::Io(_))));
        assert!(!target.exists());
        assert!(
            std::fs::read_dir(tmp.path()).unwrap().next().is_none(),
            "the temp file must not survive an injected fsync failure"
        );
    }

    /// The vacuity-proof case for the HIGH finding: a parent-directory
    /// fsync failure must be reported as a successful, durability
    /// -unconfirmed publish (the file really is on disk) — never as an
    /// ordinary `Err` a caller would read as "the copy failed".
    #[test]
    fn injected_parent_fsync_failure_reports_success_with_durability_unconfirmed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("out.md");
        let mut backend = super::super::unix::RealBackend;
        let mut io_ops = FakeIo {
            fail_sync_parent: true,
            ..Default::default()
        };
        let published =
            publish_with(&mut backend, &mut io_ops, &target, b"payload", &never_cancelled)
                .expect("a parent-fsync failure must not be reported as a publish failure");
        assert!(
            !published.durability_confirmed,
            "the caller must be able to tell durability is unconfirmed"
        );
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"payload",
            "the file is genuinely on disk despite the fsync failure"
        );
    }

    #[test]
    fn ordinary_publish_reports_durability_confirmed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("out.md");
        let published = publish_no_clobber(&target, b"payload", &never_cancelled).unwrap();
        assert!(published.durability_confirmed);
    }
}
