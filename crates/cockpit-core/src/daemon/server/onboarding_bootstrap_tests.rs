use cockpit_db::secret_vault::{SecretVaultFileKekMode, SecretVaultPlacement};
use cockpit_proto::{
    ApplyOnboardingSecureIntent, ApplyOnboardingTransition, BeginOrReopenOnboarding, ErrorCode,
    OnboardingSecurePlacement, OnboardingStage, OnboardingTransitionKind, Request, Response,
};

use super::{BootServices, LockedServices, boot_with_db, handle_locked_in_process_request};

async fn fresh_locked_services() -> (tempfile::TempDir, super::LockedServices) {
    let tmp = tempfile::tempdir().expect("temporary daemon installation");
    let db = crate::db::Db::open(&tmp.path().join("cockpit.db")).expect("fresh database");
    let mut extended = crate::config::extended::ExtendedConfig::default();
    extended.daemon.boot.secret_store_backend =
        crate::config::extended::DaemonSecretStoreBackend::File;
    extended.daemon.boot.secret_store_path = Some(tmp.path().join("secret-vault"));
    let mut timer = crate::startup::PhaseTimer::start("locked_onboarding_test");
    let services = boot_with_db(
        crate::daemon::DaemonPaths {
            socket: tmp.path().join("cockpit.sock"),
            pid_file: tmp.path().join("cockpit.pid"),
            ephemeral: true,
        },
        db,
        &mut timer,
        crate::daemon::terminal::test_host_factory(),
        crate::daemon::config_source::ConfigSource::fixed(
            crate::config::providers::ProvidersConfig::default(),
            extended,
        ),
    )
    .await
    .expect("vault-free boot");
    match services {
        BootServices::Locked(locked) => (tmp, locked),
        BootServices::Ready(_) => panic!("fresh boot must not materialize a default vault"),
    }
}

async fn advance_to_secure_store(
    locked: &super::LockedServices,
) -> cockpit_proto::OnboardingBootstrapSnapshot {
    let (welcome, _) = locked
        .onboarding
        .begin_or_reopen(
            BeginOrReopenOnboarding {
                expected_revision: None,
                client_operation_id: "begin-locked".into(),
                reentry: false,
            },
            locked.host_capabilities.clone(),
        )
        .await
        .expect("begin onboarding");
    let (profile, _) = locked
        .onboarding
        .apply_transition(
            ApplyOnboardingTransition {
                run_id: welcome.run_id,
                attempt_id: welcome.attempt_id,
                expected_revision: welcome.revision,
                client_operation_id: "commit-welcome".into(),
                transition: OnboardingTransitionKind::Advance,
                settlement: None,
            },
            locked.host_capabilities.clone(),
        )
        .await
        .expect("commit welcome");
    locked
        .onboarding
        .apply_transition(
            ApplyOnboardingTransition {
                run_id: profile.run_id,
                attempt_id: profile.attempt_id,
                expected_revision: profile.revision,
                client_operation_id: "commit-profile".into(),
                transition: OnboardingTransitionKind::Advance,
                settlement: None,
            },
            locked.host_capabilities.clone(),
        )
        .await
        .expect("commit profile")
        .0
}

async fn ready_construction() -> (
    tempfile::TempDir,
    std::sync::Arc<LockedServices>,
    cockpit_proto::OnboardingTransitionResult,
) {
    let (tmp, locked) = fresh_locked_services().await;
    let locked = std::sync::Arc::new(locked);
    let secure = advance_to_secure_store(&locked).await;
    let result = locked
        .apply_secure_intent(ApplyOnboardingSecureIntent {
            run_id: secure.run_id,
            attempt_id: secure.attempt_id,
            expected_revision: secure.revision,
            client_operation_id: "construct-ready".into(),
            placement: OnboardingSecurePlacement::MachineBoundFile,
            passphrase: None,
        })
        .await
        .expect("apply secure-store intent");
    (tmp, locked, result)
}

#[tokio::test]
async fn fresh_boot_is_locked_and_materializes_only_the_explicit_machine_bound_choice() {
    let (_tmp, locked) = fresh_locked_services().await;
    assert!(!locked.vault_authority_exists().expect("authority query"));
    let before = locked
        .db
        .read(|conn| {
            Ok((
                conn.query_row("SELECT count(*) FROM secret_vault_authority", [], |row| {
                    row.get::<_, i64>(0)
                })?,
                conn.query_row("SELECT count(*) FROM secret_vault_keys", [], |row| {
                    row.get::<_, i64>(0)
                })?,
            ))
        })
        .await
        .expect("inspect locked database");
    assert_eq!(before, (0, 0));

    let secure = advance_to_secure_store(&locked).await;
    let result = locked
        .apply_secure_intent(ApplyOnboardingSecureIntent {
            run_id: secure.run_id,
            attempt_id: secure.attempt_id,
            expected_revision: secure.revision,
            client_operation_id: "choose-machine-bound".into(),
            placement: OnboardingSecurePlacement::MachineBoundFile,
            passphrase: None,
        })
        .await
        .expect("explicit machine-bound materialization");
    assert_eq!(result.snapshot.stage, OnboardingStage::Provider);
    let authority = locked
        .db
        .blocking_write_for_sync_maintenance(cockpit_db::secret_vault::load_authority_conn)
        .expect("load vault authority")
        .expect("selected authority row");
    assert_eq!(authority.active_placement, SecretVaultPlacement::Database);
    assert_eq!(
        authority.file_kek_mode,
        Some(SecretVaultFileKekMode::MachineBound)
    );
}

#[tokio::test]
async fn locked_dispatch_denies_ordinary_reads_with_the_typed_error() {
    let (_tmp, locked) = fresh_locked_services().await;
    let hello = handle_locked_in_process_request(&locked, Request::DaemonStatus)
        .await
        .expect("locked hello");
    assert!(matches!(hello, Response::LockedBootstrapHello(_)));

    let denied = handle_locked_in_process_request(&locked, Request::GetStorageReport)
        .await
        .expect_err("ordinary read must stay unavailable before vault intent");
    assert_eq!(denied.code, ErrorCode::BootstrapLocked);
    assert_eq!(denied.message, "daemon bootstrap is locked");
}

#[tokio::test]
async fn ready_transition_keeps_the_acquired_permit_until_return_publication() {
    let (_tmp, locked, _) = ready_construction().await;
    let constructed = locked
        .finish_ready_transition()
        .await
        .expect("construct ready services");

    assert!(
        locked
            .ready_transition_inflight
            .load(std::sync::atomic::Ordering::Acquire),
        "the exact acquired permit must survive ready construction"
    );
    assert!(locked.closing.load(std::sync::atomic::Ordering::Acquire));

    let ready = constructed.publish_returned();
    assert!(locked.ready.load(std::sync::atomic::Ordering::Acquire));
    assert!(
        !locked
            .ready_transition_inflight
            .load(std::sync::atomic::Ordering::Acquire),
        "publication releases the transition permit"
    );
    drop(ready);
}

#[tokio::test]
async fn dropped_ready_construction_retains_permit_through_rollback() {
    let (_tmp, locked, _) = ready_construction().await;
    let constructed = locked
        .finish_ready_transition()
        .await
        .expect("construct ready services");

    drop(constructed);
    assert!(
        locked
            .ready_transition_inflight
            .load(std::sync::atomic::Ordering::Acquire),
        "a detached rollback must retain exclusive transition ownership"
    );
    assert!(locked.closing.load(std::sync::atomic::Ordering::Acquire));
}

#[tokio::test]
async fn stored_ready_handoff_without_lifecycle_receiver_rolls_back_under_permit() {
    let (_tmp, locked, _) = ready_construction().await;
    let constructed = locked
        .finish_ready_transition()
        .await
        .expect("construct ready services");

    constructed.publish_stored();
    assert!(
        locked
            .ready_transition_inflight
            .load(std::sync::atomic::Ordering::Acquire),
        "failed lifecycle delivery must retain exclusive transition ownership"
    );
    assert!(locked.closing.load(std::sync::atomic::Ordering::Acquire));
}

#[tokio::test]
async fn stored_ready_handoff_rolls_back_when_notified_lifecycle_consumer_is_cancelled() {
    let (_tmp, locked, _) = ready_construction().await;
    let mut lifecycle = locked.subscribe_ready_handoff();
    let mut sibling_lifecycle = locked.subscribe_ready_handoff();
    let constructed = locked
        .finish_ready_transition()
        .await
        .expect("construct ready services");

    constructed.publish_stored();
    tokio::time::timeout(std::time::Duration::from_secs(1), lifecycle.changed())
        .await
        .expect("ready notification must be accepted")
        .expect("ready notification sender must remain open");
    assert!(*lifecycle.borrow_and_update());
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        sibling_lifecycle.changed(),
    )
    .await
    .expect("sibling ready notification must be accepted")
    .expect("ready notification sender must remain open");

    drop(lifecycle);
    {
        let handoff = locked.ready_handoff.lock().unwrap();
        assert_eq!(handoff.consumers, 1);
        assert!(
            handoff.achieved.is_some(),
            "one cancelled subscriber must not steal from a surviving lifecycle consumer"
        );
    }
    drop(sibling_lifecycle);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while locked
            .ready_transition_inflight
            .load(std::sync::atomic::Ordering::Acquire)
            || locked.closing.load(std::sync::atomic::Ordering::Acquire)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled lifecycle consumer must complete rollback");

    assert!(!locked.ready.load(std::sync::atomic::Ordering::Acquire));
    assert!(locked.take_achieved_ready().is_none());
    let weak = std::sync::Arc::downgrade(&locked);
    drop(locked);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled handoff must release ready resources and locked services");
}

#[tokio::test]
async fn retry_snapshot_failure_retains_permit_for_detached_rollback() {
    let (_tmp, locked, _) = ready_construction().await;
    locked
        .fail_next_onboarding_snapshot
        .store(true, std::sync::atomic::Ordering::Release);

    let error = match locked.prepare_retry_ready_handoff().await {
        Ok(_) => panic!("injected snapshot failure must reject retry publication"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("injected onboarding snapshot failure")
    );
    assert!(
        locked
            .ready_transition_inflight
            .load(std::sync::atomic::Ordering::Acquire),
        "snapshot-failure rollback must retain exclusive transition ownership"
    );
    assert!(locked.closing.load(std::sync::atomic::Ordering::Acquire));
}

#[tokio::test]
async fn sensitive_wire_disconnect_retains_permit_through_rollback() {
    let (_tmp, locked, result) = ready_construction().await;
    let constructed = locked
        .finish_ready_transition()
        .await
        .expect("construct ready services");
    let (mut writer, reader) = tokio::io::duplex(64);
    drop(reader);

    assert!(
        constructed
            .finalize_sensitive_wire(&mut writer, result)
            .await
            .is_err(),
        "disconnected sensitive peer must prevent publication"
    );
    assert!(
        locked
            .ready_transition_inflight
            .load(std::sync::atomic::Ordering::Acquire),
        "wire-delivery rollback must retain exclusive transition ownership"
    );
    assert!(locked.closing.load(std::sync::atomic::Ordering::Acquire));
}
