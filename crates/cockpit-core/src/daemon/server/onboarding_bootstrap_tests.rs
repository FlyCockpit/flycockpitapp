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

/// The profile stage precedes the secure-store choice (#391), so its wizard
/// settlement is the one ordinary config mutation that must complete while
/// locked. The admission is scoped to exactly that: the onboarding profile
/// wizard at the Profile stage. Every other wizard apply — and this wizard
/// at any other stage — stays on the deny-by-default locked matrix.
#[tokio::test]
async fn locked_bootstrap_settles_only_the_onboarding_profile_wizard_apply() {
    let (tmp, locked) = fresh_locked_services().await;
    let _env = crate::test_env::TestEnvGuard::isolate_cockpit_home_at_async(tmp.path()).await;
    // The fixture daemon is ephemeral; an authorized (pre-existing) global
    // layer keeps the ephemeral create-global-layer refusal out of this
    // admission test, which is about the matrix and the publication.
    std::fs::create_dir_all(
        crate::config::dirs::global_config_dir().expect("isolated global config dir"),
    )
    .expect("authorize the global config layer");

    let (welcome, _) = locked
        .onboarding
        .begin_or_reopen(
            BeginOrReopenOnboarding {
                expected_revision: None,
                client_operation_id: "begin-profile-settlement".into(),
                reentry: false,
            },
            locked.host_capabilities.clone(),
        )
        .await
        .expect("begin onboarding");
    assert_eq!(welcome.stage, OnboardingStage::Welcome);

    let mut run = crate::wizard::WizardRun::new(crate::wizard::onboarding_profile_descriptor())
        .expect("onboarding profile descriptor");
    run.submit(crate::wizard::WizardAnswer::Text("Ada".into()))
        .expect("profile name answer");
    let answers_json = run.answers_json().expect("client profile answers");
    let profile_apply =
        |client_operation_id: &str, wizard_id: &str, answers: String| Request::ApplySetupWizard {
            client_operation_id: client_operation_id.into(),
            project_root: tmp.path().display().to_string(),
            wizard_id: wizard_id.into(),
            answers_json: answers,
        };

    // The profile settlement is legal only at the Profile stage.
    let denied_at_welcome = handle_locked_in_process_request(
        &locked,
        profile_apply(
            "settle-at-welcome",
            crate::wizard::ONBOARDING_PROFILE_WIZARD_ID,
            answers_json.clone(),
        ),
    )
    .await
    .expect_err("the profile settlement is only valid at the Profile stage");
    assert_eq!(denied_at_welcome.code, ErrorCode::BootstrapLocked);

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
        .expect("advance to the Profile stage");
    assert_eq!(profile.stage, OnboardingStage::Profile);

    // Every other wizard apply stays denied while locked.
    let denied_other_wizard = handle_locked_in_process_request(
        &locked,
        profile_apply(
            "settle-security",
            crate::wizard::SECURITY_WIZARD_ID,
            "{}".into(),
        ),
    )
    .await
    .expect_err("ordinary wizard applies stay denied while locked");
    assert_eq!(denied_other_wizard.code, ErrorCode::BootstrapLocked);

    // The scoped admission settles the wizard exactly like the ready
    // dispatch: the write is durable and the receipt carries the published
    // post-apply config generation.
    let applied = match handle_locked_in_process_request(
        &locked,
        profile_apply(
            "settle-profile",
            crate::wizard::ONBOARDING_PROFILE_WIZARD_ID,
            answers_json.clone(),
        ),
    )
    .await
    .expect("the locked onboarding profile settlement")
    {
        Response::SetupWizardApplied {
            changed,
            model_file_written,
            default_scope,
            config_generation,
            ..
        } => (
            changed,
            model_file_written,
            default_scope,
            config_generation,
        ),
        other => panic!("unexpected settlement response: {other:?}"),
    };
    let (changed, model_file_written, default_scope, published_generation) = applied;
    assert!(changed, "a fresh name is a durable config change");
    assert!(!model_file_written);
    assert_eq!(default_scope, None);
    assert!(
        published_generation >= 1,
        "a changed apply publishes a config generation"
    );
    let config_path = crate::config::dirs::global_config_file().expect("isolated global config");
    let config = crate::config::extended::ExtendedConfigDoc::load(&config_path)
        .expect("the locked settlement wrote the global config")
        .config();
    assert_eq!(config.name.as_deref(), Some("Ada"));

    // A replay of the same answers is an idempotent no-op: nothing changed,
    // so the receipt keeps the current generation.
    let replayed = match handle_locked_in_process_request(
        &locked,
        profile_apply(
            "settle-profile-replay",
            crate::wizard::ONBOARDING_PROFILE_WIZARD_ID,
            answers_json,
        ),
    )
    .await
    .expect("the locked onboarding profile settlement replay")
    {
        Response::SetupWizardApplied {
            changed,
            config_generation,
            ..
        } => (changed, config_generation),
        other => panic!("unexpected settlement replay response: {other:?}"),
    };
    assert!(!replayed.0, "an identical apply must not rewrite the name");
    assert!(replayed.1 >= published_generation);

    // Once the stage leaves Profile the settlement closes again: the
    // admission is a profile-stage bootstrap operation, not a general
    // config-write window.
    let (secure, _) = locked
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
        .expect("advance past the Profile stage");
    assert_eq!(secure.stage, OnboardingStage::SecureStore);
    let denied_after_advance = handle_locked_in_process_request(
        &locked,
        profile_apply(
            "settle-after-advance",
            crate::wizard::ONBOARDING_PROFILE_WIZARD_ID,
            "{}".into(),
        ),
    )
    .await
    .expect_err("the profile settlement closes once the stage advances");
    assert_eq!(denied_after_advance.code, ErrorCode::BootstrapLocked);

    // The pre-vault transition admission also covers Back from the
    // secure-store choice: the shell offers that Escape choice, so denying
    // it would make the secure-store screen uncompletable in the other
    // direction. The authority's legality rules stay the only transition
    // gate inside the admission.
    let back = match handle_locked_in_process_request(
        &locked,
        Request::ApplyOnboardingTransition {
            run_id: secure.run_id,
            attempt_id: secure.attempt_id,
            expected_revision: secure.revision,
            client_operation_id: "back-from-secure-store".into(),
            transition: OnboardingTransitionKind::Back,
            settlement: None,
        },
    )
    .await
    .expect("Back from the secure-store choice is admissible while locked")
    {
        Response::OnboardingTransition(result) => result.snapshot,
        other => panic!("unexpected locked back transition: {other:?}"),
    };
    assert_eq!(back.stage, OnboardingStage::Profile);
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
