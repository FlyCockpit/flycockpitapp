use cockpit_db::secret_vault::{SecretVaultFileKekMode, SecretVaultPlacement};
use cockpit_proto::{
    ApplyOnboardingProfile, ApplyOnboardingSecureIntent, ApplyOnboardingTransition,
    BeginOrReopenOnboarding, ErrorCode, OnboardingSecurePlacement, OnboardingStage,
    OnboardingTransitionKind, Request, Response,
};

use super::{
    BootServices, LockedProbeFuture, LockedProbePlan, LockedServices, boot_with_db_and_probe_plan,
    handle_locked_in_process_request,
};

type ProbeInputs = crate::host_capabilities::HostCapabilityProbeInputs;

async fn fresh_locked_services() -> (tempfile::TempDir, super::LockedServices) {
    locked_services_with_probe_plan(LockedProbePlan::production()).await
}

async fn locked_services_with_probe_plan(
    probe_plan: LockedProbePlan,
) -> (tempfile::TempDir, super::LockedServices) {
    let tmp = tempfile::tempdir().expect("temporary daemon installation");
    let db = crate::db::Db::open(&tmp.path().join("cockpit.db")).expect("fresh database");
    let mut extended = crate::config::extended::ExtendedConfig::default();
    // Locked/ready transition tests exercise lifecycle publication, not source
    // discovery. Keep their fixed config hermetic so ready construction never
    // walks the checkout, process environment, or the developer's SSH home.
    extended.redact.scan_environment = false;
    extended.redact.scan_dotenv = false;
    extended.redact.scan_ssh_keys = false;
    extended.daemon.boot.secret_store_backend =
        crate::config::extended::DaemonSecretStoreBackend::File;
    extended.daemon.boot.secret_store_path = Some(tmp.path().join("secret-vault"));
    let mut timer = crate::startup::PhaseTimer::start("locked_onboarding_test");
    let services = boot_with_db_and_probe_plan(
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
        probe_plan,
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
            locked.host_capabilities(),
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
            locked.host_capabilities(),
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
            locked.host_capabilities(),
        )
        .await
        .expect("commit profile")
        .0
}

pub(super) async fn ready_construction() -> (
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
    assert!(denied.message.contains("bootstrap is locked"));
}

#[tokio::test]
async fn locked_in_process_dispatch_admits_workspace_trust_and_stop() {
    let (tmp, locked) = fresh_locked_services().await;

    let trust = handle_locked_in_process_request(
        &locked,
        Request::GetWorkspaceTrust {
            project_root: tmp.path().display().to_string(),
        },
    )
    .await
    .expect("workspace trust remains readable during bootstrap");
    assert!(matches!(trust, Response::WorkspaceTrust { mode: None, .. }));

    let stopped =
        handle_locked_in_process_request(&locked, Request::StopDaemon { grace_secs: None })
            .await
            .expect("locked daemon accepts stop");
    assert!(matches!(stopped, Response::Ack));

    let denied = handle_locked_in_process_request(&locked, Request::GetStorageReport)
        .await
        .expect_err("stop closes further locked admission");
    assert_eq!(denied.code, ErrorCode::BootstrapLocked);
}

/// A locked-path handler failure must not be flattened into an opaque
/// refusal (#425): the code stays `BootstrapLocked`, but the underlying
/// cause rides in the message so the visible error names the real reason.
#[tokio::test]
async fn locked_dispatch_carries_the_handler_cause_in_the_message() {
    let (_tmp, locked) = fresh_locked_services().await;
    let (welcome, _) = locked
        .onboarding
        .begin_or_reopen(
            BeginOrReopenOnboarding {
                expected_revision: None,
                client_operation_id: "begin-cause".into(),
                reentry: false,
            },
            locked.host_capabilities(),
        )
        .await
        .expect("begin onboarding");

    // An admitted verb (the stage is Welcome) whose authority check fails:
    // the revision CAS rejects the stale client revision.
    let denied = handle_locked_in_process_request(
        &locked,
        Request::ApplyOnboardingTransition(ApplyOnboardingTransition {
            run_id: welcome.run_id,
            attempt_id: welcome.attempt_id,
            expected_revision: welcome.revision + 7,
            client_operation_id: "stale-revision".into(),
            transition: OnboardingTransitionKind::Advance,
            settlement: None,
        }),
    )
    .await
    .expect_err("the stale revision must be rejected");
    assert_eq!(denied.code, ErrorCode::BootstrapLocked);
    assert!(
        denied.message.starts_with("daemon bootstrap is locked: "),
        "the cause must ride in the message: {}",
        denied.message
    );
    assert!(
        denied.message.contains("revision"),
        "the cause must name the revision conflict: {}",
        denied.message
    );
}

/// An acknowledged locked-mode `StopDaemon` must stop the daemon without
/// waiting for other attached clients (the onboarding wizard) to disconnect:
/// their handlers stay blocked in `recv`, so the locked run loop has to tear
/// them down with the ready handoff's abort semantics. Otherwise
/// `cockpit daemon stop`/`restart` stall waiting for the pid release until
/// their command deadline.
#[cfg(unix)]
#[tokio::test]
async fn acknowledged_locked_stop_tears_down_attached_wizard_clients() {
    let (tmp, locked) = fresh_locked_services().await;
    let locked = std::sync::Arc::new(locked);
    let socket = locked.paths.socket.clone();

    // Owner-class wire authentication: install launch provenance bound to
    // this test process and persist the matching follower ticket the wire
    // client resolves next to the socket.
    let ticket = crate::daemon::peer_authority::mint_launch_ticket();
    let pid = std::process::id();
    let (uid, gid) = cockpit_host::daemon_lifecycle::read_process_credentials(pid)
        .expect("test process uid/gid");
    let launcher = cockpit_host::peer_cred::PeerIdentity {
        pid,
        uid,
        gid,
        process_start: cockpit_host::daemon_lifecycle::process_start_identity(pid)
            .expect("test process start identity"),
    };
    locked
        .peer_credential_registry
        .install_launch_provenance_for_test(&ticket, launcher);
    crate::daemon::peer_authority::persist_launch_ticket(&socket, &ticket)
        .expect("persist locked launch ticket");

    let listener = crate::daemon::bind_private_socket(&socket).expect("bind control listener");
    let reveal = crate::daemon::leak_reveal_socket::bind_reveal_socket(&locked.paths)
        .expect("bind leak-reveal socket");
    let loop_locked = locked.clone();
    let run = tokio::spawn(async move {
        super::run_locked_until_ready(loop_locked, listener, reveal)
            .await
            .expect("locked run loop")
    });

    // The attached wizard: a live owner connection that never disconnects
    // and whose server-side handler stays blocked in recv.
    let wizard = cockpit_client::DaemonClient::connect(&socket)
        .await
        .expect("wizard attaches to the locked daemon");
    let stopper = cockpit_client::DaemonClient::connect(&socket)
        .await
        .expect("stopper attaches to the locked daemon");
    let response = stopper
        .request(Request::StopDaemon { grace_secs: None })
        .await
        .expect("deliver locked stop over the wire")
        .expect("locked stop is acknowledged, not refused");
    assert!(matches!(response, Response::Ack));

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), run)
        .await
        .expect("acknowledged locked stop must not wait for the wizard to disconnect")
        .expect("locked run loop task joined");
    assert!(matches!(outcome, super::LockedRunOutcome::Shutdown));
    drop(wizard);
    drop(stopper);
    drop(locked);
    drop(tmp);
}

/// The profile stage precedes the secure-store choice (#391), so its display
/// name write is the one ordinary config mutation that must complete while
/// locked. The admission is scoped to exactly that: the Profile stage. Every
/// other wizard apply stays on the deny-by-default locked matrix.
#[tokio::test]
async fn locked_bootstrap_settles_only_the_onboarding_profile_apply() {
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
            locked.host_capabilities(),
        )
        .await
        .expect("begin onboarding");
    assert_eq!(welcome.stage, OnboardingStage::Welcome);

    let profile_apply = |client_operation_id: &str, display_name: &str| {
        Request::ApplyOnboardingProfile(ApplyOnboardingProfile {
            client_operation_id: client_operation_id.into(),
            display_name: display_name.into(),
        })
    };

    // The profile settlement is legal only at the Profile stage.
    let denied_at_welcome =
        handle_locked_in_process_request(&locked, profile_apply("settle-at-welcome", "Ada"))
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
            locked.host_capabilities(),
        )
        .await
        .expect("advance to the Profile stage");
    assert_eq!(profile.stage, OnboardingStage::Profile);

    // Every other wizard apply stays denied while locked.
    let denied_other_wizard = handle_locked_in_process_request(
        &locked,
        Request::ApplySetupWizard {
            client_operation_id: "settle-security".into(),
            project_root: tmp.path().display().to_string(),
            wizard_id: crate::wizard::SECURITY_WIZARD_ID.into(),
            answers_json: "{}".into(),
        },
    )
    .await
    .expect_err("ordinary wizard applies stay denied while locked");
    assert_eq!(denied_other_wizard.code, ErrorCode::BootstrapLocked);

    // The scoped admission writes durably and the receipt carries the published
    // post-apply config generation.
    let applied =
        match handle_locked_in_process_request(&locked, profile_apply("settle-profile", "Ada"))
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

    // A replay of the same name is an idempotent no-op: nothing changed,
    // so the receipt keeps the current generation.
    let replayed = match handle_locked_in_process_request(
        &locked,
        profile_apply("settle-profile-replay", "Ada"),
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
            locked.host_capabilities(),
        )
        .await
        .expect("advance past the Profile stage");
    assert_eq!(secure.stage, OnboardingStage::SecureStore);
    let denied_after_advance =
        handle_locked_in_process_request(&locked, profile_apply("settle-after-advance", "Ada"))
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
        Request::ApplyOnboardingTransition(ApplyOnboardingTransition {
            run_id: secure.run_id,
            attempt_id: secure.attempt_id,
            expected_revision: secure.revision,
            client_operation_id: "back-from-secure-store".into(),
            transition: OnboardingTransitionKind::Back,
            settlement: None,
        }),
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

/// A locked probe plan whose run blocks on `gate`, then returns hermetic
/// (injected) probes that keep the configured keyring source. Dropping the
/// sender also releases the gate.
fn gated_probe_plan(gate: tokio::sync::oneshot::Receiver<()>) -> LockedProbePlan {
    let runner = move |inputs: ProbeInputs| -> LockedProbeFuture {
        Box::pin(async move {
            let _ = gate.await;
            let mut hermetic = ProbeInputs::for_unit_tests(inputs.cwd.clone());
            hermetic.keyring = inputs.keyring.clone();
            crate::host_capabilities::collect_shared_host_probes(&hermetic, false).await
        })
    };
    LockedProbePlan::injected(Box::new(runner), std::time::Duration::from_secs(30))
}

fn hello_capabilities(response: Response) -> cockpit_proto::HostCapabilitySnapshot {
    match response {
        Response::LockedBootstrapHello(hello) => hello.host_capabilities,
        other => panic!("expected a locked bootstrap hello, got {other:?}"),
    }
}

/// Onboarding is shown first: the locked hello is served while the host
/// probes are still running (the probing placeholder, generation 0), and the
/// settled snapshot is published at a strictly newer generation afterwards.
#[tokio::test]
async fn locked_hello_is_served_before_slow_probes_and_generation_bumps_after() {
    let (release, gate) = tokio::sync::oneshot::channel();
    let (_tmp, locked) = locked_services_with_probe_plan(gated_probe_plan(gate)).await;

    let probing = hello_capabilities(
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handle_locked_in_process_request(&locked, Request::DaemonStatus),
        )
        .await
        .expect("the locked hello must not wait for host probes")
        .expect("locked hello"),
    );
    assert_eq!(probing.generation, 0, "probing placeholder is generation 0");
    assert!(
        probing.features.is_empty(),
        "no capability row may be reported before the probes settle"
    );
    assert!(
        locked.host_capabilities().features.is_empty(),
        "the gated probe run must still be pending"
    );

    release.send(()).expect("release the gated probe run");
    let settled = locked
        .host_probes
        .settled()
        .await
        .expect("released probes settle");
    assert!(settled.snapshot.generation > probing.generation);
    assert!(
        settled
            .snapshot
            .feature(crate::host_capabilities::FEATURE_SECRET_STORE_FILE)
            .is_some(),
        "the settled snapshot carries the secure-store rows"
    );

    let published = hello_capabilities(
        handle_locked_in_process_request(&locked, Request::DaemonStatus)
            .await
            .expect("locked hello after settle"),
    );
    assert_eq!(published, settled.snapshot);
    let bootstrap =
        match handle_locked_in_process_request(&locked, Request::GetOnboardingBootstrapSnapshot)
            .await
            .expect("bootstrap snapshot")
        {
            Response::OnboardingBootstrapSnapshot(snapshot) => snapshot,
            other => panic!("unexpected bootstrap response: {other:?}"),
        };
    assert!(
        bootstrap.is_none_or(|snapshot| snapshot.host_capabilities == settled.snapshot),
        "the onboarding projection refreshes to the settled snapshot"
    );
}

/// A secure-store choice made while the probes are still running waits for
/// them (bounded) instead of reporting the placement unavailable.
#[tokio::test]
async fn apply_secure_intent_awaits_a_pending_probe() {
    let (release, gate) = tokio::sync::oneshot::channel();
    let (_tmp, locked) = locked_services_with_probe_plan(gated_probe_plan(gate)).await;
    let locked = std::sync::Arc::new(locked);
    let secure = advance_to_secure_store(&locked).await;
    assert_eq!(secure.stage, OnboardingStage::SecureStore);
    assert_eq!(secure.host_capabilities.generation, 0);

    let applying = tokio::spawn({
        let locked = locked.clone();
        async move {
            locked
                .apply_secure_intent(ApplyOnboardingSecureIntent {
                    run_id: secure.run_id,
                    attempt_id: secure.attempt_id,
                    expected_revision: secure.revision,
                    client_operation_id: "choose-while-probing".into(),
                    placement: OnboardingSecurePlacement::MachineBoundFile,
                    passphrase: None,
                })
                .await
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !applying.is_finished(),
        "the intent must wait for the pending probe, not reject it as unpublished"
    );
    assert!(!locked.vault_authority_exists().expect("authority query"));

    release.send(()).expect("release the gated probe run");
    let result = tokio::time::timeout(std::time::Duration::from_secs(30), applying)
        .await
        .expect("the intent settles once the probes land")
        .expect("apply task joined")
        .expect("machine-bound placement materializes after the probe settles");
    assert_eq!(result.snapshot.stage, OnboardingStage::Provider);
    assert!(locked.vault_authority_exists().expect("authority query"));
}

/// A probe run that cannot finish settles fail-closed at its deadline: the
/// rows are failed, never available on faith, and a keyring placement is
/// refused as unavailable.
#[tokio::test]
async fn probe_timeout_settles_fail_closed() {
    let never = |_inputs: ProbeInputs| -> LockedProbeFuture { Box::pin(std::future::pending()) };
    let plan = LockedProbePlan::injected(Box::new(never), std::time::Duration::from_millis(50));
    let (_tmp, locked) = locked_services_with_probe_plan(plan).await;
    let secure = advance_to_secure_store(&locked).await;

    let settled = locked
        .host_probes
        .settled()
        .await
        .expect("a timed-out probe run still settles");
    assert!(settled.snapshot.generation > 0);
    let keyring = settled
        .snapshot
        .feature(crate::host_capabilities::FEATURE_SECRET_STORE_KEYRING)
        .expect("keyring row");
    assert_eq!(keyring.state, cockpit_proto::FeatureCapabilityState::Failed);
    assert!(
        keyring.reason.contains("did not finish"),
        "{}",
        keyring.reason
    );
    let sandbox = settled
        .snapshot
        .feature(crate::host_capabilities::FEATURE_SANDBOX_HOST)
        .expect("sandbox row");
    assert!(!sandbox.state.is_available());
    assert_eq!(
        settled.keyring.state,
        cockpit_proto::FeatureCapabilityState::Failed
    );

    let rejected = locked
        .apply_secure_intent(ApplyOnboardingSecureIntent {
            run_id: secure.run_id,
            attempt_id: secure.attempt_id,
            expected_revision: secure.revision,
            client_operation_id: "keyring-after-timeout".into(),
            placement: OnboardingSecurePlacement::Automatic,
            passphrase: None,
        })
        .await
        .expect_err("a timed-out keyring probe must fail the keyring placement closed");
    assert_eq!(
        rejected,
        cockpit_proto::SensitiveOnboardingIntentError::PlacementUnavailable(
            cockpit_proto::SecurePlacementFailureReason::CapabilityUnavailable,
        )
    );
    assert!(!locked.vault_authority_exists().expect("authority query"));
}
