use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use anyhow::Result;
use std::collections::HashMap;

use super::super::{
    RedactionTable,
    coverage_authority::{
        COVERAGE_LIMITS, CoverageBinding, CoverageBuild, CoverageError, CoverageOwnerMode,
        CoverageScope, OwnerAuthorization, RedactionCoverageAuthority, RedactionCoverageKey,
        UnsupportedSourceDetailClass,
    },
    coverage_bindings::OwnedSourceRevisions,
};

const REDACTED: &str = "**REDACTED BY COCKPIT - DO NOT TRY TO OBTAIN BY WORKAROUND**";

fn binding(value: u8) -> CoverageBinding {
    CoverageBinding::from_daemon_bytes([value; 16])
}

fn key(parts: [u8; 10]) -> RedactionCoverageKey {
    RedactionCoverageKey::session(
        binding(parts[0]),
        binding(parts[1]),
        binding(parts[2]),
        binding(parts[3]),
        binding(parts[4]),
        binding(parts[5]),
        binding(parts[6]),
        binding(parts[7]),
        binding(parts[8]),
        binding(parts[9]),
    )
}

fn boundary_for(parts: [u8; 10]) -> OwnedSourceRevisions {
    OwnedSourceRevisions {
        environment: binding(parts[4]),
        credential_vault: binding(parts[5]),
        policy: binding(parts[6]),
        sealed: binding(parts[7]),
        override_revision: binding(parts[8]),
        machine_sources: binding(parts[9]),
    }
}

fn capture(
    counter: Arc<AtomicUsize>,
    parts: [u8; 10],
) -> impl FnOnce() -> Result<CoverageBuild> + Send + 'static {
    let boundary = boundary_for(parts);
    move || {
        counter.fetch_add(1, Ordering::SeqCst);
        let table = RedactionTable::empty().with_forced_literal(
            "coverage-canary-secret".to_string(),
            "$test:coverage".to_string(),
        )?;
        Ok(CoverageBuild::from_complete_table(table, boundary))
    }
}

#[tokio::test]
async fn bound_keys_never_coalesce_across_principal_session_root_env_vault_policy_or_sealed() {
    let authority = RedactionCoverageAuthority::default();
    let captures = Arc::new(AtomicUsize::new(0));
    let base = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let first = authority
        .acquire(
            key(base),
            CoverageScope::SessionSubmission,
            capture(captures.clone(), base),
        )
        .await
        .expect("first complete capture is admitted");
    let same = authority
        .acquire(
            key(base),
            CoverageScope::DriverTurn,
            capture(captures.clone(), base),
        )
        .await
        .expect("same bound capture reuses its generation");
    let mut distinct = Vec::new();
    for index in 0..base.len() {
        let mut changed = base;
        changed[index] = changed[index].saturating_add(40);
        distinct.push(
            authority
                .acquire(
                    key(changed),
                    CoverageScope::SessionSubmission,
                    capture(captures.clone(), changed),
                )
                .await
                .expect("every changed source binding requires a distinct generation"),
        );
    }

    assert_eq!(captures.load(Ordering::SeqCst), 11);
    assert_eq!(same.purpose(), CoverageScope::DriverTurn);
    first
        .use_at_sink(|table| {
            assert_eq!(table.scrub("coverage-canary-secret"), REDACTED);
            Ok(())
        })
        .expect("bound lease admits exactly its sink");
    same.use_at_sink(|table| {
        assert_eq!(table.scrub("coverage-canary-secret"), REDACTED);
        Ok(())
    })
    .expect("same binding remains independently leased");
    for admission in distinct {
        admission
            .use_at_sink(|table| {
                assert_eq!(table.scrub("coverage-canary-secret"), REDACTED);
                Ok(())
            })
            .expect("different binding has its own admitted capture");
    }
    let projections = serde_json::to_string(&(
        cockpit_proto::RedactionCoverageStatusProjection {
            state: cockpit_proto::RedactionCoverageState::Ready,
            owner_diagnostic: None,
            rendered_context: Some("redacted context".into()),
        },
        cockpit_proto::InputPredictionProjection {
            text: Some("safe".into()),
        },
        cockpit_proto::TagPreviewProjection {
            wire: "safe".into(),
            expansions: Vec::new(),
        },
    ))
    .expect("projection serialization");
    for forbidden in [
        "matcher",
        "candidate",
        "fingerprint",
        "source_cache",
        "source_inventory",
    ] {
        assert!(!projections.contains(forbidden));
    }
}

#[tokio::test]
async fn coverage_admission_is_one_operation_and_stale_results_are_inert() {
    let authority = RedactionCoverageAuthority::default();
    let captures = Arc::new(AtomicUsize::new(0));
    let base = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let admission = authority
        .acquire(
            key(base),
            CoverageScope::SessionSubmission,
            capture(captures.clone(), base),
        )
        .await
        .expect("complete capture is admitted");

    authority.invalidate();
    let result = admission.use_at_sink(|_| Ok(()));
    assert_eq!(result, Err(CoverageError::Invalidated));

    authority
        .acquire(
            key(base),
            CoverageScope::DriverTurn,
            capture(captures.clone(), base),
        )
        .await
        .expect("invalidated work requires a fresh complete capture")
        .use_at_sink(|table| {
            assert_eq!(table.scrub("coverage-canary-secret"), REDACTED);
            Ok(())
        })
        .expect("fresh generation is admitted at its sink");
    assert_eq!(captures.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn bound_sink_refuses_scrub_after_invalidation() {
    crate::redact::coverage_route_behavior::tests::assert_bound_sink_scrub_refuses_stale_binding()
        .await;
}

#[tokio::test]
async fn coverage_limits_are_identical_in_persistent_ephemeral_and_inprocess_modes() {
    let expected = (
        2,
        32,
        64,
        16,
        256,
        256,
        64,
        4 * 1024 * 1024,
        32 * 1024 * 1024,
    );
    for mode in [
        CoverageOwnerMode::Persistent,
        CoverageOwnerMode::Ephemeral,
        CoverageOwnerMode::InProcess,
    ] {
        let authority = RedactionCoverageAuthority::new(mode);
        let limits = authority.limits();
        assert_eq!(authority.owner_mode(), mode);
        assert_eq!(
            (
                limits.workers,
                limits.queued,
                limits.flight_keys,
                limits.waiters_per_key,
                limits.waiters,
                limits.admissions,
                limits.resident_generations,
                limits.artifact_bytes_per_generation,
                limits.artifact_bytes_total,
            ),
            expected,
        );
        assert_eq!(limits, COVERAGE_LIMITS);

        let admissions_parts = [3, 3, 3, 3, 3, 3, 3, 3, 3, 3];
        let admissions_key = key(admissions_parts);
        let captures = Arc::new(AtomicUsize::new(0));
        let mut admissions = Vec::new();
        for _ in 0..limits.admissions {
            admissions.push(
                authority
                    .acquire(
                        admissions_key.clone(),
                        CoverageScope::SessionSubmission,
                        capture(captures.clone(), admissions_parts),
                    )
                    .await
                    .expect("admission within exact cap"),
            );
        }
        assert!(matches!(
            authority
                .acquire(
                    admissions_key.clone(),
                    CoverageScope::SessionSubmission,
                    capture(captures.clone(), admissions_parts),
                )
                .await,
            Err(CoverageError::Saturated)
        ));
        assert_eq!(captures.load(Ordering::SeqCst), 1);
        drop(admissions);

        let stale = authority
            .acquire(
                admissions_key.clone(),
                CoverageScope::DriverTurn,
                capture(captures.clone(), admissions_parts),
            )
            .await
            .expect("pre-rebind admission");
        authority.rebind();
        assert_eq!(
            stale.use_at_sink(|_| Ok(())),
            Err(CoverageError::Invalidated)
        );
        authority
            .acquire(
                admissions_key,
                CoverageScope::DriverTurn,
                capture(captures.clone(), admissions_parts),
            )
            .await
            .expect("new epoch capture")
            .use_at_sink(|_| Ok(()))
            .expect("new epoch admission");
        assert_eq!(captures.load(Ordering::SeqCst), 2);

        let oversize_parts = [5, 5, 5, 5, 5, 5, 5, 5, 5, 5];
        let oversize_boundary = boundary_for(oversize_parts);
        let oversize_key = key(oversize_parts);
        assert!(matches!(
            authority
                .acquire(oversize_key, CoverageScope::SessionSubmission, move || {
                    Ok(CoverageBuild::from_complete_table_and_artifact_bytes(
                        RedactionTable::empty(),
                        COVERAGE_LIMITS.artifact_bytes_per_generation + 1,
                        oversize_boundary,
                    ))
                })
                .await,
            Err(CoverageError::Unavailable)
        ));

        let pinned_parts = [6, 6, 6, 6, 6, 6, 6, 6, 6, 6];
        let pinned_key = key(pinned_parts);
        let pinned = authority
            .acquire(
                pinned_key,
                CoverageScope::SessionSubmission,
                capture(captures.clone(), pinned_parts),
            )
            .await
            .expect("active resident generation");
        for index in 0..COVERAGE_LIMITS.resident_generations {
            let eviction_parts = [70 + index as u8; 10];
            authority
                .acquire(
                    key(eviction_parts),
                    CoverageScope::DriverTurn,
                    capture(captures.clone(), eviction_parts),
                )
                .await
                .expect("bounded LRU insertion")
                .use_at_sink(|_| Ok(()))
                .expect("LRU operation");
        }
        pinned
            .use_at_sink(|table| {
                assert_eq!(table.scrub("coverage-canary-secret"), REDACTED);
                Ok(())
            })
            .expect("active generation is not evicted");

        // A running flight whose final waiter disconnects is allowed to finish
        // only cleanup. Shutdown revokes it immediately and the daemon-owned
        // coordination future remains pending until the blocking capture has
        // actually returned; its late result cannot reopen acquisition.
        let late_key = key([4, 4, 4, 4, 4, 4, 4, 4, 4, 4]);
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let worker_release = release.clone();
        let late_authority = authority.clone();
        let late = tokio::spawn(async move {
            late_authority
                .acquire(late_key, CoverageScope::SessionSubmission, move || {
                    entered_tx.send(()).expect("running flight entry signal");
                    let (lock, wake) = &*worker_release;
                    let mut released = lock.lock().expect("running flight barrier");
                    while !*released {
                        released = wake.wait(released).expect("running flight wake");
                    }
                    Ok(CoverageBuild::from_complete_table(
                        RedactionTable::empty().with_forced_literal(
                            "late-cancelled-coverage-canary".to_string(),
                            "$test:late-cancelled".to_string(),
                        )?,
                        boundary_for([4, 4, 4, 4, 4, 4, 4, 4, 4, 4]),
                    ))
                })
                .await
        });
        tokio::task::spawn_blocking(move || entered_rx.recv().expect("running flight entered"))
            .await
            .expect("running flight entry waiter");
        late.abort();
        assert!(matches!(late.await, Err(error) if error.is_cancelled()));

        let mut shutdown = Box::pin(authority.shutdown_and_wait());
        assert!(futures::poll!(&mut shutdown).is_pending());
        {
            let (lock, wake) = &*release;
            *lock.lock().expect("release running flight") = true;
            wake.notify_all();
        }
        shutdown.await;
        assert!(matches!(
            authority
                .acquire(
                    key([4, 4, 4, 4, 4, 4, 4, 4, 4, 4]),
                    CoverageScope::SessionSubmission,
                    capture(captures.clone(), [4, 4, 4, 4, 4, 4, 4, 4, 4, 4]),
                )
                .await,
            Err(CoverageError::Unavailable)
        ));
    }
}

#[test]
fn complete_capture_keeps_hidden_ignored_extra_and_symlink_sources() {
    let root = tempfile::tempdir().expect("workspace root");
    let outside = tempfile::tempdir().expect("explicit source root");
    std::fs::write(root.path().join(".gitignore"), ".hidden/\nignored/\n")
        .expect("gitignore fixture");
    std::fs::create_dir_all(root.path().join(".hidden")).expect("hidden dir");
    std::fs::create_dir_all(root.path().join("ignored/deep")).expect("ignored dir");
    std::fs::write(
        root.path().join(".hidden/.env"),
        "HIDDEN=hidden-coverage-canary\n",
    )
    .expect("hidden dotenv");
    std::fs::write(
        root.path().join("ignored/deep/.env.local"),
        "IGNORED=ignored-coverage-canary\n",
    )
    .expect("ignored dotenv");
    let extra = outside.path().join("explicit.secrets");
    std::fs::write(&extra, "EXTRA=extra-coverage-canary\n").expect("extra dotenv");

    let ssh_dir = root.path().join("configured-ssh");
    std::fs::create_dir_all(&ssh_dir).expect("ssh dir");
    let ssh_target = outside.path().join("actual-private-key");
    let ssh_secret = concat!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "symlinked-private-key-coverage-canary-material\n",
        "-----END OPENSSH PRIVATE KEY-----\n"
    );
    std::fs::write(&ssh_target, ssh_secret).expect("ssh target");
    let ssh_link = ssh_dir.join("id_fixture");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&ssh_target, &ssh_link).expect("ssh symlink");
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&ssh_target, &ssh_link).expect("ssh symlink");

    let mut cfg = crate::config::extended::RedactConfig {
        enabled: false,
        scan_environment: true,
        scan_dotenv: true,
        scan_ssh_keys: true,
        ..crate::config::extended::RedactConfig::default()
    };
    cfg.extra_dotenv_paths = vec![extra];
    cfg.ssh_key_dir = Some(ssh_dir);
    let env = HashMap::from([(
        "COVERAGE_TOKEN".to_string(),
        "environment-coverage-canary".to_string(),
    )]);
    let table = RedactionTable::build_with_env_and_secrets(
        &cfg,
        root.path(),
        &env,
        [
            (
                "vault-entry".to_string(),
                "vault-coverage-canary".to_string(),
            ),
            (
                "store-entry".to_string(),
                "store-coverage-canary".to_string(),
            ),
            (
                "post-read-entry".to_string(),
                "post-read-coverage-canary".to_string(),
            ),
        ],
    )
    .expect("complete capture");

    // The ordinary view honors enabled=false, while the mandatory admitted
    // view keeps every source and both matcher paths aligned.
    assert_eq!(
        table.scrub("hidden-coverage-canary"),
        "hidden-coverage-canary"
    );
    let enforced = table.enforced();
    for secret in [
        "hidden-coverage-canary",
        "ignored-coverage-canary",
        "extra-coverage-canary",
        "environment-coverage-canary",
        "vault-coverage-canary",
        "store-coverage-canary",
        "post-read-coverage-canary",
        "symlinked-private-key-coverage-canary-material",
    ] {
        assert_eq!(enforced.scrub(secret), REDACTED, "missing {secret}");
    }
}

#[tokio::test]
async fn owner_unsupported_source_diagnostic_is_bound_authorized_and_deduplicated() {
    let authority = RedactionCoverageAuthority::default();
    let captures = Arc::new(AtomicUsize::new(0));
    let base = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let key = key(base);
    let owner = authority
        .acquire(
            key.clone(),
            CoverageScope::DebugContext,
            capture(captures.clone(), base),
        )
        .await
        .expect("owner diagnostic admission")
        .unsupported_source_projection(
            OwnerAuthorization::after_principal_check(true),
            std::path::Path::new("/raw-parent-path-canary/coverage-canary-secret.env"),
            UnsupportedSourceDetailClass::UnsupportedFormat,
        )
        .expect("owner projection");
    let diagnostic = owner
        .owner_diagnostic
        .as_ref()
        .expect("first owner notice is visible");
    assert_eq!(diagnostic.display_path, format!("{REDACTED}.env"));

    let duplicate = authority
        .acquire(
            key.clone(),
            CoverageScope::DebugContext,
            capture(captures.clone(), base),
        )
        .await
        .expect("duplicate diagnostic admission")
        .unsupported_source_projection(
            OwnerAuthorization::after_principal_check(true),
            std::path::Path::new("/another-raw-parent/coverage-canary-secret.env"),
            UnsupportedSourceDetailClass::Unreadable,
        )
        .expect("duplicate projection");
    assert!(duplicate.owner_diagnostic.is_none());

    let non_owner = authority
        .acquire(
            key,
            CoverageScope::DebugContext,
            capture(captures.clone(), base),
        )
        .await
        .expect("generic diagnostic admission")
        .unsupported_source_projection(
            OwnerAuthorization::after_principal_check(false),
            std::path::Path::new("/raw-parent-path-canary/coverage-canary-secret.env"),
            UnsupportedSourceDetailClass::ChangedDuringCapture,
        )
        .expect("generic projection");
    assert_eq!(non_owner.state, "unsupported_coverage");
    assert!(non_owner.owner_diagnostic.is_none());
    assert_eq!(captures.load(Ordering::SeqCst), 1);

    let encoded = serde_json::to_string(&(owner, duplicate, non_owner)).expect("projection JSON");
    for forbidden in [
        "raw-parent-path-canary",
        "another-raw-parent",
        "coverage-canary-secret",
        "matcher",
        "candidate",
        "fingerprint",
        "source_cache",
        "source_inventory",
        "dedupe",
        "generation_id",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "projection exposed {forbidden}"
        );
    }
}

#[tokio::test]
async fn accepted_operation_reuses_one_capture_across_submission_driver_and_inference() {
    let authority = RedactionCoverageAuthority::default();
    let captures = Arc::new(AtomicUsize::new(0));
    let base = [9, 8, 7, 6, 5, 4, 3, 2, 1, 10];
    let key = key(base);
    for purpose in [
        CoverageScope::SessionSubmission,
        CoverageScope::DriverTurn,
        CoverageScope::AutoTitle,
    ] {
        let admission = authority
            .acquire(key.clone(), purpose, capture(captures.clone(), base))
            .await
            .expect("unchanged accepted operation coverage");
        assert_eq!(admission.purpose(), purpose);
        admission
            .use_at_sink(|table| {
                assert_eq!(table.scrub("coverage-canary-secret"), REDACTED);
                Ok(())
            })
            .expect("operation sink");
    }
    assert_eq!(captures.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_mutation_before_completed_scan_boundary_retries_or_refuses() {
    let sources = tempfile::tempdir().expect("mutable source root");
    let dotenv = sources.path().join(".env");
    std::fs::write(&dotenv, "TOKEN=before-boundary-secret\n").expect("initial dotenv");
    let dotenv_result =
        super::super::dotenv::collect_env_file_candidates_with_fence(&dotenv, &[], || {
            std::fs::write(&dotenv, "TOKEN=replaced-before-boundary-secret\n")
                .expect("replace dotenv at capture fence");
        });
    assert!(matches!(dotenv_result, super::super::EnvFileScan::Changed));

    let ssh_dir = sources.path().join("ssh");
    std::fs::create_dir(&ssh_dir).expect("SSH source root");
    let first_target = sources.path().join("first-key");
    let second_target = sources.path().join("second-key");
    let pem = |marker: &str| {
        format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{marker}-private-key-material\n-----END OPENSSH PRIVATE KEY-----\n"
        )
    };
    std::fs::write(&first_target, pem("first")).expect("first key target");
    std::fs::write(&second_target, pem("second")).expect("second key target");
    let link = ssh_dir.join("id_capture");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&first_target, &link).expect("initial SSH symlink");
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&first_target, &link).expect("initial SSH symlink");
    let ssh_result =
        super::super::ssh::collect_ssh_key_candidates_with_fence(Some(&ssh_dir), |_| {
            std::fs::remove_file(&link).expect("remove old SSH symlink");
            #[cfg(unix)]
            std::os::unix::fs::symlink(&second_target, &link).expect("retarget SSH symlink");
            #[cfg(windows)]
            std::os::windows::fs::symlink_file(&second_target, &link)
                .expect("retarget SSH symlink");
        });
    assert!(
        ssh_result.is_err(),
        "retargeted SSH input must refuse capture"
    );

    let changing_ssh_dir = sources.path().join("changing-ssh-inventory");
    std::fs::create_dir(&changing_ssh_dir).expect("changing SSH source root");
    std::fs::write(changing_ssh_dir.join("id_first"), pem("inventory-first"))
        .expect("first inventory key");
    let added_key = changing_ssh_dir.join("id_added");
    // A key added during capture is not in the captured table, and the
    // captured-bytes binding no longer matches a fresh read, so the authority
    // refuses to publish (the collector itself tolerates directory churn).
    let captured =
        super::super::ssh::collect_ssh_key_candidates_with_fence(Some(&changing_ssh_dir), |_| {
            std::fs::write(&added_key, pem("inventory-added"))
                .expect("add SSH source during capture");
        })
        .expect("directory churn does not fail the collector");
    let fresh = super::super::ssh::collect_ssh_key_candidates(Some(&changing_ssh_dir))
        .expect("fresh SSH read");
    assert_ne!(
        super::super::coverage_bindings::ssh_candidates_digest(&captured),
        super::super::coverage_bindings::ssh_candidates_digest(&fresh),
        "a changed SSH key set must change the source binding, refusing publication"
    );

    let authority = RedactionCoverageAuthority::default();
    let source_key = key([1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let worker_release = release.clone();
    let pending_authority = authority.clone();
    let pending_key = source_key.clone();
    let pending = tokio::spawn(async move {
        pending_authority
            .acquire(pending_key, CoverageScope::SessionSubmission, move || {
                entered_tx.send(()).expect("publish capture-entry signal");
                let (lock, wake) = &*worker_release;
                let mut released = lock.lock().expect("capture barrier");
                while !*released {
                    released = wake.wait(released).expect("capture barrier wake");
                }
                let table = RedactionTable::empty().with_forced_literal(
                    "stale-before-boundary-secret".to_string(),
                    "$test:stale".to_string(),
                )?;
                Ok(CoverageBuild::from_complete_table(
                    table,
                    boundary_for([1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
                ))
            })
            .await
    });
    tokio::task::spawn_blocking(move || entered_rx.recv().expect("capture entered"))
        .await
        .expect("capture entry waiter");

    // Represents every known owned source mutation fence (dotenv/symlink
    // replacement, vault/credential rotation, sealed/config/override change)
    // before the completed-scan publication boundary.
    authority.invalidate();
    {
        let (lock, wake) = &*release;
        *lock.lock().expect("release capture") = true;
        wake.notify_all();
    }
    assert!(matches!(
        pending.await.expect("capture task"),
        Err(CoverageError::Invalidated)
    ));

    let captures = Arc::new(AtomicUsize::new(0));
    let base = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
    authority
        .acquire(
            source_key,
            CoverageScope::SessionSubmission,
            capture(captures.clone(), base),
        )
        .await
        .expect("fresh complete capture after mutation")
        .use_at_sink(|table| {
            assert_eq!(table.scrub("coverage-canary-secret"), REDACTED);
            Ok(())
        })
        .expect("fresh post-mutation admission");
    assert_eq!(captures.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unbound_tables_support_derived_transforms() {
    crate::redact::coverage_route_behavior::tests::assert_unbound_tables_support_derived_transforms()
        .await;
}

#[tokio::test]
async fn resident_generation_survives_lru_while_admitted() {
    crate::redact::coverage_route_behavior::tests::assert_resident_generation_survives_lru_while_admitted()
        .await;
}

#[tokio::test]
async fn one_shot_admission_refuses_after_invalidation() {
    crate::redact::coverage_route_behavior::tests::assert_one_shot_admission_refuses_after_invalidation()
        .await;
}

#[tokio::test]
async fn union_refuses_mismatched_generation_bindings() {
    crate::redact::coverage_route_behavior::tests::assert_union_refuses_mismatched_bindings().await;
}

#[tokio::test]
async fn union_adopts_newer_binding_not_right_operand() {
    crate::redact::coverage_route_behavior::tests::assert_union_adopts_newer_binding_not_right_operand()
        .await;
}

#[tokio::test]
async fn async_sink_revalidates_before_result_escapes() {
    crate::redact::coverage_route_behavior::tests::assert_async_sink_revalidates_before_result_escapes()
        .await;
}

#[tokio::test]
async fn publish_fence_rejects_stale_owned_revisions() {
    crate::redact::coverage_route_behavior::tests::assert_publish_fence_rejects_stale_owned_revisions()
        .await;
}
