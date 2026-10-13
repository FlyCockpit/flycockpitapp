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

/// Throwaway OpenSSH private keys generated once with `ssh-keygen` for these
/// tests only (key comments `cockpit-test-only-*`); they protect nothing.
/// Only the base64 bodies are checked in, so no file carries a PEM armor line
/// for repository secret scanners; [`test_only_private_key`] restores it.
/// Fixed fixtures keep the regressions platform-independent (no
/// `ssh-keygen`) and their artifact sizes deterministic.
const RSA_4096_TEST_KEY_BODIES: [&str; 10] = [
    include_str!("fixtures/ssh_test_keys/test_only_rsa4096_01.body"),
    include_str!("fixtures/ssh_test_keys/test_only_rsa4096_02.body"),
    include_str!("fixtures/ssh_test_keys/test_only_rsa4096_03.body"),
    include_str!("fixtures/ssh_test_keys/test_only_rsa4096_04.body"),
    include_str!("fixtures/ssh_test_keys/test_only_rsa4096_05.body"),
    include_str!("fixtures/ssh_test_keys/test_only_rsa4096_06.body"),
    include_str!("fixtures/ssh_test_keys/test_only_rsa4096_07.body"),
    include_str!("fixtures/ssh_test_keys/test_only_rsa4096_08.body"),
    include_str!("fixtures/ssh_test_keys/test_only_rsa4096_09.body"),
    include_str!("fixtures/ssh_test_keys/test_only_rsa4096_10.body"),
];
const ED25519_TEST_KEY_BODIES: [&str; 2] = [
    include_str!("fixtures/ssh_test_keys/test_only_ed25519_01.body"),
    include_str!("fixtures/ssh_test_keys/test_only_ed25519_02.body"),
];

/// Reassemble a fixture body into the OpenSSH private-key file `ssh-keygen`
/// wrote (LF line endings regardless of checkout).
fn test_only_private_key(body: &str) -> String {
    let mut key = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n"); // pragma: allowlist secret
    for line in body.lines().map(str::trim).filter(|line| !line.is_empty()) {
        key.push_str(line);
        key.push('\n');
    }
    key.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    key
}

/// Every representation the table registers for one private key: the whole
/// key, each line, and the encoded variants of each.
fn private_key_representations(secret: &str) -> Vec<String> {
    let mut variants = super::super::encoded_secret_variants(secret);
    assert_eq!(variants.len(), 4);
    for line in secret.lines() {
        variants.push(line.to_owned());
        variants.extend(super::super::encoded_secret_variants(line));
    }
    variants.push(secret.to_owned());
    variants
}

#[tokio::test]
async fn ssh_private_key_coverage_admits_and_scrubs_every_encoding() {
    let env = crate::test_env::lock_async().await;
    let home = tempfile::tempdir().unwrap();
    env.set_isolated_home(home.path());
    let ssh = home.path().join("home/.ssh");
    std::fs::create_dir(&ssh).unwrap();
    let key_path = ssh.join("id_ed25519");
    // Disposable fixture material; never depend on a developer's SSH keys.
    std::fs::write(&key_path, test_only_private_key(ED25519_TEST_KEY_BODIES[0])).unwrap();
    let secret = std::fs::read_to_string(key_path).unwrap();
    let secret = secret.trim().to_owned();
    let cfg = crate::config::extended::RedactConfig {
        scan_environment: false,
        scan_dotenv: false,
        ..Default::default()
    };
    let table = RedactionTable::build_scoped(
        &cfg,
        super::super::RedactionSourceScope::DaemonGlobal,
        &HashMap::new(),
        std::iter::empty(),
    )
    .expect("complete private-key capture");
    let artifact_bytes = table.measured_immutable_artifact_bytes();
    let parts = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let authority = RedactionCoverageAuthority::default();
    let admission = authority
        .acquire(
            key(parts),
            CoverageScope::DaemonGlobalBootstrap,
            move || {
                Ok(CoverageBuild::from_complete_table(
                    table,
                    boundary_for(parts),
                ))
            },
        )
        .await
        .unwrap_or_else(|error| {
            panic!(
                "private-key coverage must be admitted: {error}; artifact_bytes={artifact_bytes}"
            )
        });
    admission
        .use_at_sink(|table| {
            let variants = private_key_representations(&secret);
            for (index, variant) in variants.iter().enumerate() {
                assert!(
                    table.scrub(variant) == REDACTED,
                    "private-key variant {index} must be fully redacted"
                );
            }
            assert_eq!(table.scrub("ordinary public text"), "ordinary public text");
            Ok(())
        })
        .expect("admitted SSH coverage is usable at the sink");

    // An unavailable configured source must still refuse a fresh admission.
    authority.invalidate();
    let missing = crate::config::extended::RedactConfig {
        ssh_key_dir: Some(ssh.join("missing")),
        ..cfg
    };
    let refused = authority
        .acquire(
            key(parts),
            CoverageScope::DaemonGlobalBootstrap,
            move || {
                let table = RedactionTable::build_scoped(
                    &missing,
                    super::super::RedactionSourceScope::DaemonGlobal,
                    &HashMap::new(),
                    std::iter::empty(),
                )?;
                Ok(CoverageBuild::from_complete_table(
                    table,
                    boundary_for(parts),
                ))
            },
        )
        .await;
    assert!(matches!(refused, Err(CoverageError::Unavailable)));
}

/// Several large keys in one profile (work, personal, deploy, ...) plus a
/// typical environment must admit within the unchanged per-generation budget,
/// and every representation of every key must still scrub to the placeholder
/// (issue #527).
#[tokio::test]
async fn ssh_coverage_admits_ten_rsa_4096_keys_with_an_environment() {
    let env = crate::test_env::lock_async().await;
    let home = tempfile::tempdir().unwrap();
    env.set_isolated_home(home.path());
    let ssh = home.path().join("home/.ssh");
    std::fs::create_dir(&ssh).unwrap();
    let mut secrets = Vec::new();
    for (index, body) in RSA_4096_TEST_KEY_BODIES.iter().enumerate() {
        let key = test_only_private_key(body);
        std::fs::write(ssh.join(format!("id_rsa_{index}")), &key).unwrap();
        secrets.push(key.trim().to_owned());
    }
    for (index, body) in ED25519_TEST_KEY_BODIES.iter().enumerate() {
        let key = test_only_private_key(body);
        std::fs::write(ssh.join(format!("id_ed25519_{index}")), &key).unwrap();
        secrets.push(key.trim().to_owned());
    }
    // A developer environment: credential-shaped values (registered with
    // their encodings and case variants) beside ordinary settings.
    let mut environment: HashMap<String, String> = (0..40)
        .map(|index| {
            (
                format!("SERVICE_{index:02}_API_TOKEN"),
                format!("tok-{index:02}-test-only-9f8e7d6c5b4a3210fedcba98"),
            )
        })
        .collect();
    environment.insert("EDITOR".into(), "nvim".into());
    environment.insert("GIT_AUTHOR_NAME".into(), "Test Only".into());
    let cfg = crate::config::extended::RedactConfig {
        scan_environment: true,
        scan_dotenv: false,
        ..Default::default()
    };
    let table = RedactionTable::build_scoped(
        &cfg,
        super::super::RedactionSourceScope::DaemonGlobal,
        &environment,
        std::iter::empty(),
    )
    .expect("complete private-key capture");
    let artifact_bytes = table.measured_immutable_artifact_bytes();
    eprintln!("ten_rsa_4096_two_ed25519_forty_env artifact_bytes={artifact_bytes}");
    assert!(
        artifact_bytes <= COVERAGE_LIMITS.artifact_bytes_per_generation,
        "artifact_bytes={artifact_bytes} exceeds the per-generation budget"
    );
    let parts = [7, 2, 7, 2, 7, 2, 7, 2, 7, 2];
    let authority = RedactionCoverageAuthority::default();
    let admission = authority
        .acquire(
            key(parts),
            CoverageScope::DaemonGlobalBootstrap,
            move || {
                Ok(CoverageBuild::from_complete_table(
                    table,
                    boundary_for(parts),
                ))
            },
        )
        .await
        .unwrap_or_else(|error| {
            panic!("multi-key coverage must be admitted: {error}; artifact_bytes={artifact_bytes}")
        });
    admission
        .use_at_sink(|table| {
            for (key_index, secret) in secrets.iter().enumerate() {
                for (index, variant) in private_key_representations(secret).iter().enumerate() {
                    assert!(
                        table.scrub(variant) == REDACTED,
                        "key {key_index} representation {index} must be fully redacted"
                    );
                }
            }
            for value in environment
                .values()
                .filter(|value| value.starts_with("tok-"))
            {
                assert_eq!(table.scrub(value), REDACTED);
            }
            // Two keys pasted into one body with ordinary text around them.
            let body = format!("before\n{}\nbetween\n{}\nafter", secrets[0], secrets[9]);
            assert_eq!(
                table.scrub(&body),
                format!("before\n{REDACTED}\nbetween\n{REDACTED}\nafter")
            );
            assert_eq!(table.scrub("ordinary public text"), "ordinary public text");
            Ok(())
        })
        .expect("admitted SSH coverage is usable at the sink");
}

/// A capture over the per-generation budget still fails closed, and the
/// refusal names private SSH key material and the settings that bound it
/// when keys are part of the artifact.
#[tokio::test]
async fn over_budget_coverage_names_ssh_key_remediation() {
    let env = crate::test_env::lock_async().await;
    let home = tempfile::tempdir().unwrap();
    env.set_isolated_home(home.path());
    let ssh = home.path().join("home/.ssh");
    std::fs::create_dir(&ssh).unwrap();
    std::fs::write(
        ssh.join("id_ed25519"),
        test_only_private_key(ED25519_TEST_KEY_BODIES[1]),
    )
    .unwrap();
    let cfg = crate::config::extended::RedactConfig {
        scan_environment: false,
        scan_dotenv: false,
        ..Default::default()
    };
    let with_keys = RedactionTable::build_scoped(
        &cfg,
        super::super::RedactionSourceScope::DaemonGlobal,
        &HashMap::new(),
        std::iter::empty(),
    )
    .expect("complete private-key capture");
    let authority = RedactionCoverageAuthority::default();
    let parts = [8, 1, 8, 1, 8, 1, 8, 1, 8, 1];
    let refused = authority
        .acquire(
            key(parts),
            CoverageScope::DaemonGlobalBootstrap,
            move || {
                Ok(CoverageBuild::from_complete_table_and_artifact_bytes(
                    with_keys,
                    COVERAGE_LIMITS.artifact_bytes_per_generation + 1,
                    boundary_for(parts),
                ))
            },
        )
        .await
        .map(|_| ())
        .expect_err("an over-budget artifact never publishes");
    assert_eq!(
        refused,
        CoverageError::ArtifactOverBudget {
            ssh_key_material: true
        }
    );
    let message = refused.to_string();
    for needle in ["SSH key", "`redact.ssh_key_dir`", "`redact.scan_ssh_keys`"] {
        assert!(message.contains(needle), "{message}");
    }
    assert!(!message.contains(&ssh.display().to_string()));

    let parts = [8, 2, 8, 2, 8, 2, 8, 2, 8, 2];
    let refused = authority
        .acquire(
            key(parts),
            CoverageScope::DaemonGlobalBootstrap,
            move || {
                Ok(CoverageBuild::from_complete_table_and_artifact_bytes(
                    RedactionTable::empty(),
                    COVERAGE_LIMITS.artifact_bytes_per_generation + 1,
                    boundary_for(parts),
                ))
            },
        )
        .await
        .map(|_| ())
        .expect_err("an over-budget artifact never publishes");
    assert_eq!(
        refused,
        CoverageError::ArtifactOverBudget {
            ssh_key_material: false
        }
    );
    assert!(!refused.to_string().contains("ssh"));
}

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
            Err(CoverageError::ArtifactOverBudget {
                ssh_key_material: false
            })
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
    let ssh_result = super::super::ssh::collect_ssh_key_candidates_with_fence(
        Some(&super::super::ssh::SshKeyDir::configured(&ssh_dir)),
        |_| {
            std::fs::remove_file(&link).expect("remove old SSH symlink");
            #[cfg(unix)]
            std::os::unix::fs::symlink(&second_target, &link).expect("retarget SSH symlink");
            #[cfg(windows)]
            std::os::windows::fs::symlink_file(&second_target, &link)
                .expect("retarget SSH symlink");
        },
    );
    assert!(
        ssh_result.is_err(),
        "retargeted SSH input must refuse capture"
    );

    let changing_ssh_dir = sources.path().join("changing-ssh-inventory");
    std::fs::create_dir(&changing_ssh_dir).expect("changing SSH source root");
    std::fs::write(changing_ssh_dir.join("id_first"), pem("inventory-first"))
        .expect("first inventory key");
    let added_key = changing_ssh_dir.join("id_added");
    // A key added while the collector runs (this collector is also the
    // publication fence) is refused by its source-set closure check.
    let changing = super::super::ssh::SshKeyDir::configured(&changing_ssh_dir);
    let captured =
        super::super::ssh::collect_ssh_key_candidates_with_fence(Some(&changing), |_| {
            std::fs::write(&added_key, pem("inventory-added"))
                .expect("add SSH source during capture");
        });
    assert!(
        captured
            .as_ref()
            .is_err_and(|error| format!("{error:#}").contains("a key was added")),
        "a key added during capture must refuse capture: {captured:?}"
    );
    // And the key set is part of the source binding, so a capture taken
    // before the addition never matches a fresh read after it.
    std::fs::remove_file(&added_key).expect("remove added key");
    let before =
        super::super::ssh::collect_ssh_key_candidates(Some(&changing)).expect("stable SSH read");
    std::fs::write(&added_key, pem("inventory-added")).expect("add SSH source");
    let fresh =
        super::super::ssh::collect_ssh_key_candidates(Some(&changing)).expect("fresh SSH read");
    assert_ne!(
        super::super::coverage_bindings::ssh_candidates_digest(&before),
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
