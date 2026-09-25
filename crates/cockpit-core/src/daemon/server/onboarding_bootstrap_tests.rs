use cockpit_db::secret_vault::{SecretVaultFileKekMode, SecretVaultPlacement};
use cockpit_proto::{
    ApplyOnboardingProfile, ApplyOnboardingSecureIntent, ApplyOnboardingTransition,
    BeginOrReopenOnboarding, ErrorCode, OnboardingSecurePlacement, OnboardingStage,
    OnboardingTransitionKind, Request, Response,
};

use super::{
    LockedProbeFuture, LockedProbePlan, LockedServices, boot_with_db_and_probe_plan,
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
    assert!(
        !services.vault_committed(),
        "fresh boot must not materialize a default vault"
    );
    (tmp, services)
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

/// A locked first-run owner must survive the gap between a one-shot client
/// (a version-skew probe, a CLI command, a fixture) closing and its caller's
/// retained connection attaching, and must still tear down once that
/// retained client leaves and the handoff grace elapses with nobody attached.
#[cfg(unix)]
#[tokio::test]
async fn locked_owner_holds_the_last_client_handoff_grace() {
    let (tmp, locked) = fresh_locked_services().await;
    let locked = std::sync::Arc::new(locked);
    let socket = locked.paths.socket.clone();
    let listener = crate::daemon::bind_private_socket(&socket).expect("bind control listener");
    let reveal = crate::daemon::leak_reveal_socket::bind_reveal_socket(&locked.paths)
        .expect("bind leak-reveal socket");
    let loop_locked = locked.clone();
    let mut run = tokio::spawn(async move {
        super::run_locked_until_ready(loop_locked, listener, reveal)
            .await
            .expect("locked run loop")
    });

    // One-shot client: a lifetime reference that closes immediately.
    let probe = cockpit_client::DaemonClient::connect(&socket)
        .await
        .expect("one-shot client attaches to the locked daemon");
    drop(probe);
    tokio::time::sleep(super::LAST_CLIENT_HANDOFF_GRACE / 3).await;
    assert!(
        !run.is_finished(),
        "the locked owner must not drain inside the handoff grace"
    );

    // The retained successor attaches inside the grace and outlives it.
    let retained = cockpit_client::DaemonClient::connect(&socket)
        .await
        .expect("retained client attaches inside the handoff grace");
    tokio::time::sleep(super::LAST_CLIENT_HANDOFF_GRACE + std::time::Duration::from_millis(500))
        .await;
    assert!(
        !run.is_finished(),
        "an attached client keeps the locked owner serving"
    );
    let status = retained
        .request(Request::DaemonStatus)
        .await
        .expect("retained client transport stays live")
        .expect("retained client is still served");
    assert!(matches!(status, Response::LockedBootstrapHello(..)));

    // Abandoned: the owner still exits once the grace elapses.
    drop(retained);
    let outcome = tokio::time::timeout(
        super::LAST_CLIENT_HANDOFF_GRACE + std::time::Duration::from_secs(5),
        &mut run,
    )
    .await
    .expect("an abandoned locked owner drains after the handoff grace")
    .expect("locked run loop task joined");
    assert!(matches!(outcome, super::LockedRunOutcome::Shutdown));
    drop(locked);
    drop(tmp);
}

/// A locked owner whose last client leaves while a ready transition is in
/// flight must still reap once that transition rolls back: the rollback and
/// the permit release change the loop's teardown predicate without any
/// client-presence edge, so they have to wake the loop themselves.
#[cfg(unix)]
#[tokio::test]
async fn locked_owner_abandoned_during_a_rolled_back_transition_still_reaps() {
    let (tmp, locked) = fresh_locked_services().await;
    let locked = std::sync::Arc::new(locked);
    let socket = locked.paths.socket.clone();
    let listener = crate::daemon::bind_private_socket(&socket).expect("bind control listener");
    let reveal = crate::daemon::leak_reveal_socket::bind_reveal_socket(&locked.paths)
        .expect("bind leak-reveal socket");
    let loop_locked = locked.clone();
    let mut run = tokio::spawn(async move {
        super::run_locked_until_ready(loop_locked, listener, reveal)
            .await
            .expect("locked run loop")
    });

    // Ready construction is attempted from the secure-store stage.
    advance_to_secure_store(&locked).await;
    let client = cockpit_client::DaemonClient::connect(&socket)
        .await
        .expect("lifetime client attaches to the locked daemon");

    // A ready transition takes the permit and closes admission.
    assert!(locked.try_acquire_ready_transition());
    let permit = super::ReadyTransitionPermit::new(locked.clone());
    locked
        .closing
        .store(true, std::sync::atomic::Ordering::Release);

    // The last client leaves mid-transition: the loop must defer teardown.
    drop(client);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        !run.is_finished(),
        "teardown is deferred while the ready transition is in flight"
    );

    // Construction fails and rolls back; nobody is attached any more.
    permit.rollback();
    let outcome = tokio::time::timeout(
        super::LAST_CLIENT_HANDOFF_GRACE + std::time::Duration::from_secs(5),
        &mut run,
    )
    .await
    .expect("an owner abandoned during a rolled-back transition must still reap")
    .expect("locked run loop task joined");
    assert!(matches!(outcome, super::LockedRunOutcome::Shutdown));
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

/// An abandoned constructed graph (never handed to a lifecycle owner) rolls
/// back in memory at once: the permit is released, admission reopens, and
/// the phase reports the retryable failure. Nothing durable is written.
#[tokio::test]
async fn dropped_ready_construction_rolls_back_in_memory_and_releases_the_permit() {
    let (_tmp, locked, _) = ready_construction().await;
    let constructed = locked
        .finish_ready_transition()
        .await
        .expect("construct ready services");

    drop(constructed);
    assert!(
        !locked
            .ready_transition_inflight
            .load(std::sync::atomic::Ordering::Acquire),
        "an abandoned attempt releases its permit"
    );
    assert!(!locked.closing.load(std::sync::atomic::Ordering::Acquire));
    assert_eq!(
        locked.ready_construction_phase(),
        cockpit_proto::LockedReadyConstruction::Failed
    );
}

#[tokio::test]
async fn stored_ready_handoff_without_lifecycle_receiver_rolls_back() {
    let (_tmp, locked, _) = ready_construction().await;
    let constructed = locked
        .finish_ready_transition()
        .await
        .expect("construct ready services");

    constructed.publish_stored();
    assert!(
        !locked
            .ready_transition_inflight
            .load(std::sync::atomic::Ordering::Acquire),
        "undeliverable publication rolls back and releases the permit"
    );
    assert_eq!(
        locked.ready_construction_phase(),
        cockpit_proto::LockedReadyConstruction::Failed
    );
    assert!(!locked.ready.load(std::sync::atomic::Ordering::Acquire));
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

/// Budget for a full ready construction in the served-owner tests. Generous:
/// construction builds the whole ready graph and runs under a loaded shared
/// test host.
#[cfg(unix)]
const READY_CONSTRUCTION_TEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(180);

/// Test-process peer identity, as the kernel reports it for a socket this
/// process connects.
#[cfg(unix)]
fn test_process_peer() -> cockpit_host::peer_cred::PeerIdentity {
    let pid = std::process::id();
    let (uid, gid) = cockpit_host::daemon_lifecycle::read_process_credentials(pid)
        .expect("test process uid/gid");
    cockpit_host::peer_cred::PeerIdentity {
        pid,
        uid,
        gid,
        process_start: cockpit_host::daemon_lifecycle::process_start_identity(pid)
            .expect("test process start identity"),
    }
}

/// A served locked owner on real sockets, with an owner-class credential
/// minted for this test process.
#[cfg(unix)]
struct ServedLockedOwner {
    tmp: tempfile::TempDir,
    locked: std::sync::Arc<LockedServices>,
    run: tokio::task::JoinHandle<super::LockedRunOutcome>,
    owner_token: String,
}

#[cfg(unix)]
async fn serve_locked_owner() -> ServedLockedOwner {
    let (tmp, locked) = fresh_locked_services().await;
    let locked = std::sync::Arc::new(locked);
    let listener =
        crate::daemon::bind_private_socket(&locked.paths.socket).expect("bind control listener");
    let reveal = crate::daemon::leak_reveal_socket::bind_reveal_socket(&locked.paths)
        .expect("bind leak-reveal socket");
    // Owner-class control connections: launch provenance bound to this test
    // process plus the follower ticket the wire client resolves.
    let ticket = crate::daemon::peer_authority::mint_launch_ticket();
    locked
        .peer_credential_registry
        .install_launch_provenance_for_test(&ticket, test_process_peer());
    crate::daemon::peer_authority::persist_launch_ticket(&locked.paths.socket, &ticket)
        .expect("persist locked launch ticket");
    let owner_token = locked
        .peer_credential_registry
        .mint(
            test_process_peer(),
            uuid::Uuid::new_v4(),
            crate::daemon::principal::LocalClientRole::Tui,
            Vec::new(),
        )
        .0;
    let loop_locked = locked.clone();
    let run = tokio::spawn(async move {
        super::run_locked_until_ready(loop_locked, listener, reveal)
            .await
            .expect("locked run loop")
    });
    ServedLockedOwner {
        tmp,
        locked,
        run,
        owner_token,
    }
}

/// Send one secure-store intent on the sensitive sibling exactly as the
/// client transport frames it. `read_response: false` models a client that
/// gave up or was superseded: it closes without reading the answer.
#[cfg(unix)]
async fn send_secure_intent_on_wire(
    served: &ServedLockedOwner,
    secure: &cockpit_proto::OnboardingBootstrapSnapshot,
    client_operation_id: &str,
    read_response: bool,
) -> Option<cockpit_proto::SensitiveOnboardingIntentResponse> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let payload = cockpit_proto::encode_sensitive_onboarding_intent(
        cockpit_proto::SensitiveOnboardingIntentFrame {
            connection_id: uuid::Uuid::nil(),
            owner_capability: Some(cockpit_proto::OwnerCapabilityToken::new(
                served.owner_token.clone(),
            )),
            request: ApplyOnboardingSecureIntent {
                run_id: secure.run_id,
                attempt_id: secure.attempt_id,
                expected_revision: secure.revision,
                client_operation_id: client_operation_id.into(),
                placement: OnboardingSecurePlacement::MachineBoundFile,
                passphrase: None,
            },
        },
    )
    .expect("encode secure intent");
    let mut stream = tokio::net::UnixStream::connect(served.locked.paths.leak_reveal_socket())
        .await
        .expect("connect sensitive sibling");
    stream.write_all(&payload).await.expect("write intent");
    stream.flush().await.expect("flush intent");
    stream.shutdown().await.expect("half-close intent");
    if !read_response {
        drop(stream);
        return None;
    }
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read intent response");
    Some(cockpit_proto::decode_sensitive_onboarding_response(&response).expect("decode response"))
}

#[cfg(unix)]
async fn wait_for_phase(locked: &LockedServices, phase: cockpit_proto::LockedReadyConstruction) {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while locked.ready_construction_phase() != phase {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("locked owner never reached {phase:?}"));
}

/// Root cause of the first-run restart storm: ready construction used to be
/// owned by the sensitive connection that committed the vault. The response
/// was written only after construction, so a client that gave up (a hello
/// timeout retry budget, a superseding `Replace` request) closed the stream;
/// the write failed with EPIPE, the constructed ready graph was dropped, and
/// the rollback recorded `bootstrap_state = failed` while the vault stayed
/// committed. Construction is now daemon-owned: an abandoned response
/// changes nothing and the owner still publishes ready services.
#[cfg(unix)]
#[tokio::test]
async fn abandoned_secure_intent_response_never_discards_ready_construction() {
    let served = serve_locked_owner().await;
    let secure = advance_to_secure_store(&served.locked).await;
    // The client closes without reading: its response is undeliverable.
    assert!(
        send_secure_intent_on_wire(&served, &secure, "abandoned-intent", false)
            .await
            .is_none()
    );
    let outcome = tokio::time::timeout(READY_CONSTRUCTION_TEST_BUDGET, served.run)
        .await
        .expect("ready construction must complete without its requesting client")
        .expect("locked run loop joined");
    assert!(
        matches!(outcome, super::LockedRunOutcome::Ready(..)),
        "an abandoned response must not discard the constructed ready graph"
    );
    let snapshot = served
        .locked
        .onboarding
        .snapshot(served.locked.host_capabilities())
        .await
        .expect("read onboarding checkpoint")
        .expect("onboarding run exists");
    assert_eq!(snapshot.stage, OnboardingStage::Provider);
    assert_eq!(
        snapshot.bootstrap_state,
        cockpit_proto::OnboardingBootstrapState::Ready,
        "an undeliverable response must never record a ready-construction failure"
    );
    drop(served.locked);
    drop(served.tmp);
}

/// While ready construction runs the locked owner keeps accepting
/// connections and answers every hello with the `constructing` phase. The
/// previous design ran construction inline in the accept loop, so every new
/// connection's hello timed out for the whole construction.
#[cfg(unix)]
#[tokio::test]
async fn locked_owner_answers_hellos_with_constructing_phase_during_construction() {
    let served = serve_locked_owner().await;
    let (release, gate) = tokio::sync::oneshot::channel();
    *served.locked.construction_gate.lock().unwrap() = Some(gate);
    let secure = advance_to_secure_store(&served.locked).await;
    let response = send_secure_intent_on_wire(&served, &secure, "gated-intent", true)
        .await
        .expect("response is read");
    let cockpit_proto::SensitiveOnboardingIntentResponse::Applied(result) = response else {
        panic!("committed intent must answer Applied before construction completes");
    };
    assert_eq!(result.snapshot.stage, OnboardingStage::Provider);
    wait_for_phase(
        &served.locked,
        cockpit_proto::LockedReadyConstruction::Constructing,
    )
    .await;

    // A brand-new bootstrap connection completes its hello while
    // construction is held (a ready-services `connect` would wait).
    let client = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        cockpit_client::DaemonClient::connect_bootstrap(&served.locked.paths.socket),
    )
    .await
    .expect("hello must not wait for ready construction")
    .expect("connect during ready construction");
    let status = client
        .request(Request::DaemonStatus)
        .await
        .expect("status transport")
        .expect("status answered");
    let Response::LockedBootstrapHello(hello) = status else {
        panic!("a locked owner answers status with its locked hello");
    };
    assert_eq!(
        hello.ready_construction,
        cockpit_proto::LockedReadyConstruction::Constructing
    );
    // Locked mutations are refused with the named in-progress cause.
    let refused = client
        .request(Request::BeginOrReopenOnboarding(BeginOrReopenOnboarding {
            expected_revision: None,
            client_operation_id: "during-construction".into(),
            reentry: true,
        }))
        .await
        .expect("refusal is a response, not a closed connection");
    let error = refused.expect_err("mutation during construction is refused");
    assert_eq!(error.code, ErrorCode::RetryLater);
    assert!(
        error.message.contains("ready construction is in progress"),
        "{}",
        error.message
    );
    assert!(!served.run.is_finished());

    release.send(()).expect("release construction");
    let outcome = tokio::time::timeout(READY_CONSTRUCTION_TEST_BUDGET, served.run)
        .await
        .expect("construction completes after release")
        .expect("locked run loop joined");
    assert!(matches!(outcome, super::LockedRunOutcome::Ready(..)));
    drop(client);
    drop(served.locked);
    drop(served.tmp);
}

/// A stop (StopDaemon, or the forwarded first shutdown signal) that arrives
/// while construction runs waits for construction to settle instead of
/// cancelling it mid-way, and a construction that succeeded is not recorded
/// as a failure: the next boot opens the committed vault ready.
#[cfg(unix)]
#[tokio::test]
async fn stop_during_ready_construction_settles_before_exit() {
    let served = serve_locked_owner().await;
    let (release, gate) = tokio::sync::oneshot::channel();
    *served.locked.construction_gate.lock().unwrap() = Some(gate);
    let secure = advance_to_secure_store(&served.locked).await;
    send_secure_intent_on_wire(&served, &secure, "stopped-intent", true)
        .await
        .expect("response is read");
    wait_for_phase(
        &served.locked,
        cockpit_proto::LockedReadyConstruction::Constructing,
    )
    .await;
    served.locked.request_locked_stop();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !served.run.is_finished(),
        "a stop must not cancel an in-flight ready construction"
    );
    release.send(()).expect("release construction");
    let outcome = tokio::time::timeout(READY_CONSTRUCTION_TEST_BUDGET, served.run)
        .await
        .expect("stop completes once construction settles")
        .expect("locked run loop joined");
    assert!(
        matches!(outcome, super::LockedRunOutcome::Shutdown),
        "an acknowledged stop still wins over publishing the constructed graph"
    );
    let snapshot = served
        .locked
        .onboarding
        .snapshot(served.locked.host_capabilities())
        .await
        .expect("read onboarding checkpoint")
        .expect("onboarding run exists");
    assert_eq!(
        snapshot.bootstrap_state,
        cockpit_proto::OnboardingBootstrapState::Ready,
        "a successful construction retired by stop is not a failure"
    );
    assert!(
        !served
            .locked
            .ready_transition_inflight
            .load(std::sync::atomic::Ordering::Acquire)
    );
    drop(served.locked);
    drop(served.tmp);
}

/// Commit the secure-store choice directly (no construction started yet).
async fn commit_secure_store(
    locked: &super::LockedServices,
    secure: &cockpit_proto::OnboardingBootstrapSnapshot,
    client_operation_id: &str,
) -> cockpit_proto::OnboardingTransitionResult {
    locked
        .apply_secure_intent(ApplyOnboardingSecureIntent {
            run_id: secure.run_id,
            attempt_id: secure.attempt_id,
            expected_revision: secure.revision,
            client_operation_id: client_operation_id.into(),
            placement: OnboardingSecurePlacement::MachineBoundFile,
            passphrase: None,
        })
        .await
        .expect("commit secure intent without starting construction")
}

/// The production signal forwarder drives the stop: the first SIGTERM is an
/// acknowledged locked stop that lets an in-flight construction settle (the
/// owner keeps running while it is held), a repeated signal is the explicit
/// force, and once released the settled construction ends in `Shutdown`.
/// Signals are process-wide, so the scenario runs in an isolated child
/// process of this test binary.
#[cfg(unix)]
#[tokio::test]
async fn shutdown_signals_stop_after_construction_settles_and_repeat_forces() {
    const CHILD: &str = "COCKPIT_LOCKED_SIGNAL_FORWARDER_CHILD";
    const OK: &str = "locked-signal-forwarder-child-ok";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .env(CHILD, "1")
            .args([
                "--exact",
                "daemon::server::onboarding_bootstrap_tests::shutdown_signals_stop_after_construction_settles_and_repeat_forces",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .expect("run the isolated signal scenario");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "child failed:\n{stdout}\n{stderr}");
        assert!(
            stderr.contains(OK) || stdout.contains(OK),
            "child did not run the scenario:\n{stdout}\n{stderr}"
        );
        return;
    }
    let served = serve_locked_owner().await;
    let secure = advance_to_secure_store(&served.locked).await;
    commit_secure_store(&served.locked, &secure, "signal-intent").await;
    let (release, gate) = tokio::sync::oneshot::channel();
    *served.locked.construction_gate.lock().unwrap() = Some(gate);
    served
        .locked
        .start_ready_construction()
        .expect("construction admitted");
    let force = std::sync::Arc::new(tokio::sync::Notify::new());
    let signals = crate::daemon::BootstrapShutdownSignals::new();
    let forwarder = tokio::spawn(crate::daemon::forward_locked_bootstrap_signals(
        served.locked.clone(),
        force.clone(),
        signals,
    ));
    // SAFETY: raising a signal this process handles (tokio streams above).
    assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !served
            .locked
            .stop_requested
            .load(std::sync::atomic::Ordering::Acquire)
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the first signal requests the locked stop");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(300), force.notified())
            .await
            .is_err(),
        "one signal is never a force"
    );
    assert!(
        !served.run.is_finished(),
        "a signalled stop waits for the in-flight construction"
    );
    // SAFETY: as above.
    assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
    tokio::time::timeout(std::time::Duration::from_secs(5), force.notified())
        .await
        .expect("a repeated signal is the explicit force");
    forwarder.await.expect("forwarder joined");
    release.send(()).expect("release construction");
    let outcome = tokio::time::timeout(READY_CONSTRUCTION_TEST_BUDGET, served.run)
        .await
        .expect("the stop completes once construction settles")
        .expect("locked run loop joined");
    assert!(matches!(outcome, super::LockedRunOutcome::Shutdown));
    eprintln!("{OK}");
}

/// A real construction failure (an injected error on the production path,
/// not a hand-set phase) rolls back to the retryable `failed` phase; the
/// retry is idempotent and daemon-owned: it answers at once, a duplicate
/// while construction runs starts nothing, and the owner then publishes
/// ready services.
#[cfg(unix)]
#[tokio::test]
async fn ready_construction_retry_is_idempotent_and_daemon_owned() {
    let served = serve_locked_owner().await;
    let secure = advance_to_secure_store(&served.locked).await;
    commit_secure_store(&served.locked, &secure, "retry-intent").await;
    served
        .locked
        .fail_next_construction
        .store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(
        served
            .locked
            .start_ready_construction()
            .expect("first attempt admitted"),
        super::ReadyConstructionStart::Started
    );
    wait_for_phase(
        &served.locked,
        cockpit_proto::LockedReadyConstruction::Failed,
    )
    .await;
    assert!(
        !served.run.is_finished(),
        "a failed construction keeps the owner serving"
    );

    let (release, gate) = tokio::sync::oneshot::channel();
    *served.locked.construction_gate.lock().unwrap() = Some(gate);
    let first = super::retry_locked_ready_construction(&served.locked)
        .await
        .expect("retry admitted");
    assert!(matches!(
        first,
        Response::OnboardingBootstrapSnapshot(Some(_))
    ));
    assert_eq!(
        served.locked.ready_construction_phase(),
        cockpit_proto::LockedReadyConstruction::Constructing
    );
    assert_eq!(
        served
            .locked
            .start_ready_construction()
            .expect("duplicate retry"),
        super::ReadyConstructionStart::AlreadyInProgress
    );
    release.send(()).expect("release construction");
    let outcome = tokio::time::timeout(READY_CONSTRUCTION_TEST_BUDGET, served.run)
        .await
        .expect("retried construction completes")
        .expect("locked run loop joined");
    assert!(matches!(outcome, super::LockedRunOutcome::Ready(..)));
    drop(served.locked);
    drop(served.tmp);
}

/// A retry whose snapshot read fails after it admitted construction reports
/// the error to its caller, but the spawned construction it started is not
/// the caller's: it still completes and publishes ready services.
#[cfg(unix)]
#[tokio::test]
async fn failed_retry_snapshot_cannot_cancel_the_spawned_construction() {
    let served = serve_locked_owner().await;
    let secure = advance_to_secure_store(&served.locked).await;
    commit_secure_store(&served.locked, &secure, "retry-snapshot-intent").await;
    served
        .locked
        .fail_next_construction
        .store(true, std::sync::atomic::Ordering::Release);
    served
        .locked
        .start_ready_construction()
        .expect("first attempt admitted");
    wait_for_phase(
        &served.locked,
        cockpit_proto::LockedReadyConstruction::Failed,
    )
    .await;
    served
        .locked
        .fail_next_retry_snapshot
        .store(true, std::sync::atomic::Ordering::Release);
    let error = super::retry_locked_ready_construction(&served.locked)
        .await
        .expect_err("the injected snapshot failure reaches the caller");
    assert!(
        error.message.contains("injected retry snapshot failure"),
        "{}",
        error.message
    );
    let outcome = tokio::time::timeout(READY_CONSTRUCTION_TEST_BUDGET, served.run)
        .await
        .expect("construction completes despite the failed retry response")
        .expect("locked run loop joined");
    assert!(matches!(outcome, super::LockedRunOutcome::Ready(..)));
    drop(served.locked);
    drop(served.tmp);
}

/// A secure intent that already committed replays idempotently — but only
/// the exact operation: same ids, the `secure_store` operation kind, and the
/// same request parameters. A different placement under the same id, the id
/// of a different (begin) operation, or a still-pending secure-store receipt
/// never replays as `Applied`.
#[tokio::test]
async fn committed_secure_intent_replays_only_the_exact_operation() {
    let (_tmp, locked, committed) = ready_construction().await;
    let intent = |client_operation_id: &str, placement| ApplyOnboardingSecureIntent {
        run_id: committed.receipt.run_id,
        attempt_id: committed.receipt.attempt_id,
        expected_revision: committed.receipt.consumed_revision,
        client_operation_id: client_operation_id.into(),
        placement,
        passphrase: None,
    };
    let replay = locked
        .apply_secure_intent_span(intent(
            "construct-ready",
            OnboardingSecurePlacement::MachineBoundFile,
        ))
        .await
        .expect("replay of the committed operation");
    assert_eq!(replay.receipt, committed.receipt);
    assert_eq!(replay.snapshot.stage, OnboardingStage::Provider);

    for (label, request) in [
        (
            "another client operation",
            intent("another-click", OnboardingSecurePlacement::MachineBoundFile),
        ),
        (
            "different parameters",
            intent("construct-ready", OnboardingSecurePlacement::Keyring),
        ),
        // `commit-profile` is an ordinary transition receipt in this run.
        (
            "an ordinary transition's id",
            intent(
                "commit-profile",
                OnboardingSecurePlacement::MachineBoundFile,
            ),
        ),
    ] {
        assert!(
            matches!(
                locked.apply_secure_intent_span(request).await,
                Err(cockpit_proto::SensitiveOnboardingIntentError::InvalidRequest)
            ),
            "{label} must not replay"
        );
    }
}

/// A pending secure-store receipt (materialization not yet settled) is not
/// evidence of a commit: its operation does not replay as `Applied`.
#[tokio::test]
async fn pending_secure_intent_receipt_does_not_replay() {
    let (_tmp, locked) = fresh_locked_services().await;
    let secure = advance_to_secure_store(&locked).await;
    let current = locked
        .db
        .onboarding_snapshot()
        .await
        .expect("snapshot")
        .expect("run exists");
    locked
        .db
        .onboarding_secure_intent_pending(
            current,
            "pending-intent".into(),
            cockpit_db::onboarding::OnboardingSecurePlacement::MachineBoundFile,
            false,
            0,
        )
        .await
        .expect("record the pending intent");
    let replay = locked
        .onboarding
        .committed_secure_intent_replay(
            &ApplyOnboardingSecureIntent {
                run_id: secure.run_id,
                attempt_id: secure.attempt_id,
                expected_revision: secure.revision,
                client_operation_id: "pending-intent".into(),
                placement: OnboardingSecurePlacement::MachineBoundFile,
                passphrase: None,
            },
            locked.host_capabilities(),
        )
        .await
        .expect("replay lookup");
    assert!(
        replay.is_none(),
        "a pending receipt is not a committed replay"
    );
}

/// A client operation id of the maximum wire length completes end to end:
/// the daemon's own follow-up operation ids are fixed-width in a reserved
/// namespace, never derived by appending to the client id.
#[tokio::test]
async fn maximum_length_secure_intent_operation_id_completes() {
    let (_tmp, locked) = fresh_locked_services().await;
    let secure = advance_to_secure_store(&locked).await;
    let id = "x".repeat(128);
    let result = commit_secure_store(&locked, &secure, &id).await;
    assert_eq!(result.snapshot.stage, OnboardingStage::Provider);
    assert_eq!(
        result.receipt.status,
        cockpit_proto::OnboardingReceiptStatus::Committed
    );
    let reserved = locked
        .apply_secure_intent(ApplyOnboardingSecureIntent {
            run_id: secure.run_id,
            attempt_id: secure.attempt_id,
            expected_revision: secure.revision,
            client_operation_id: "cockpit-internal:bootstrap-reconcile:1".into(),
            placement: OnboardingSecurePlacement::MachineBoundFile,
            passphrase: None,
        })
        .await;
    assert!(reserved.is_err(), "the internal namespace is reserved");
}

/// D1: a boot with a committed vault comes up as the locked bootstrap owner
/// right after DB/config initialization — its hello reports `constructing`,
/// never `awaiting_secure_store` — and publishes ready services once the
/// daemon-owned construction completes. There is no durable `failed` state
/// to heal: the vault alone makes every boot reconstruct.
#[cfg(unix)]
#[tokio::test]
async fn vault_present_boot_serves_the_bootstrap_hello_then_publishes_ready() {
    let (tmp, locked, _) = ready_construction().await;
    let config_dir = tmp.path().to_path_buf();
    drop(locked);

    let db = crate::db::Db::open(&config_dir.join("cockpit.db")).expect("reopen installation");
    let mut extended = crate::config::extended::ExtendedConfig::default();
    extended.redact.scan_environment = false;
    extended.redact.scan_dotenv = false;
    extended.redact.scan_ssh_keys = false;
    extended.daemon.boot.secret_store_backend =
        crate::config::extended::DaemonSecretStoreBackend::File;
    extended.daemon.boot.secret_store_path = Some(config_dir.join("secret-vault"));
    let mut timer = crate::startup::PhaseTimer::start("vault_present_reboot");
    let locked = std::sync::Arc::new(
        boot_with_db_and_probe_plan(
            crate::daemon::DaemonPaths {
                socket: config_dir.join("cockpit.sock"),
                pid_file: config_dir.join("cockpit.pid"),
                ephemeral: true,
            },
            db,
            &mut timer,
            crate::daemon::terminal::test_host_factory(),
            crate::daemon::config_source::ConfigSource::fixed(
                crate::config::providers::ProvidersConfig::default(),
                extended,
            ),
            LockedProbePlan::production(),
        )
        .await
        .expect("reboot the onboarded installation"),
    );
    assert!(locked.vault_committed());
    assert_eq!(
        locked.ready_construction_phase(),
        cockpit_proto::LockedReadyConstruction::Constructing,
        "a vault-present owner never reports awaiting_secure_store"
    );
    let listener =
        crate::daemon::bind_private_socket(&locked.paths.socket).expect("bind control listener");
    let reveal = crate::daemon::leak_reveal_socket::bind_reveal_socket(&locked.paths)
        .expect("bind leak-reveal socket");
    let (release, gate) = tokio::sync::oneshot::channel();
    *locked.construction_gate.lock().unwrap() = Some(gate);
    let loop_locked = locked.clone();
    let run = tokio::spawn(async move {
        super::run_locked_until_ready(loop_locked, listener, reveal)
            .await
            .expect("locked run loop")
    });
    locked
        .start_ready_construction()
        .expect("boot starts ready construction");
    // The bootstrap surface answers while ready services are still held.
    let phase = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        cockpit_client::probe_owner_hello_phase(&locked.paths.socket),
    )
    .await
    .expect("the hello does not wait for ready services")
    .expect("hello read");
    assert_eq!(
        phase,
        Some(cockpit_proto::LockedReadyConstruction::Constructing)
    );
    let bootstrap = cockpit_client::DaemonClient::connect_bootstrap(&locked.paths.socket)
        .await
        .expect("bootstrap connection during construction");
    let snapshot = match bootstrap
        .request(Request::GetOnboardingBootstrapSnapshot)
        .await
        .expect("snapshot transport")
    {
        // Unauthenticated peers get the minimal surface; the phase is the
        // contract here, the snapshot read is owner-only.
        Ok(response) => Some(response),
        Err(error) => {
            assert_eq!(error.code, ErrorCode::BootstrapLocked);
            None
        }
    };
    drop(snapshot);
    release.send(()).expect("release construction");
    let outcome = tokio::time::timeout(READY_CONSTRUCTION_TEST_BUDGET, run)
        .await
        .expect("construction completes")
        .expect("locked run loop joined");
    assert!(matches!(outcome, super::LockedRunOutcome::Ready(..)));
    drop(bootstrap);
    drop(locked);
    drop(tmp);
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
