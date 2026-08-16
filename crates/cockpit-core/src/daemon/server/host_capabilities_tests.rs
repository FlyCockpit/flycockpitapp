//! Host capability snapshot dispatch and boot tests.

use super::dispatch::handle_request;
use super::tests::test_ctx;
use super::*;
use crate::host_capabilities::{
    CatalogProbeSource, ContainerProbeSource, FEATURE_MEDIA_DECODE, FEATURE_SANDBOX_CONTAINER,
    FEATURE_SANDBOX_HOST, FEATURE_SECRET_STORE_KEYRING, HostCapabilityProbeInputs,
    HostCapabilitySnapshotStore, KeyringProbeSource, SandboxProbeSource,
    build_host_capability_snapshot, collect_shared_host_probes, publish_initial_host_capabilities,
};
use crate::secure_key::{
    KeyringProbeResult, default_platform_store_is_registered, probe_platform_keyring,
    probe_platform_keyring_refresh, probe_platform_keyring_with,
    reset_keyring_probe_cache_for_test,
};
use crate::tools::shell_sandbox::SandboxAvailability;
use cockpit_proto::{
    CatalogDependencyImportance, CatalogDependencyState, ContainerAvailability,
    ContainerRuntimeKind, ContainerUnavailableReason, FeatureCapabilityState,
    HostCapabilitySnapshot, Request, Response, SecretStoreIntent, SecretStorePlacement,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

static KEYRING_PROBE_TEST_LOCK: Mutex<()> = Mutex::new(());

fn lock_keyring_probe_tests() -> MutexGuard<'static, ()> {
    KEYRING_PROBE_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn missing_keyring() -> KeyringProbeResult {
    KeyringProbeResult {
        state: FeatureCapabilityState::Missing,
        reason: "DBUS_SESSION_BUS_ADDRESS unset; secret service unavailable".into(),
        fix_command: None,
        remedy_text: Some("Set DBUS_SESSION_BUS_ADDRESS".into()),
    }
}

fn injected_probes(
    tmp: &tempfile::TempDir,
    keyring_calls: Arc<AtomicUsize>,
) -> HostCapabilityProbeInputs {
    HostCapabilityProbeInputs {
        keyring: KeyringProbeSource::Injected {
            result: missing_keyring(),
            calls: keyring_calls,
        },
        sandbox: SandboxProbeSource::Injected(SandboxAvailability::Unavailable {
            reason: "injected sandbox missing".into(),
            fix_command: None,
        }),
        container: ContainerProbeSource::Injected {
            availability: ContainerAvailability {
                runtime: None,
                harness_in_container: false,
                available: false,
                reason: Some(ContainerUnavailableReason::NoRuntime),
            },
            detect_calls: Arc::new(AtomicUsize::new(0)),
        },
        catalog: CatalogProbeSource::Injected(empty_catalog()),
        platform: crate::external_runtime::HostPlatform::GenericLinux,
        cwd: tmp.path().to_path_buf(),
    }
}

fn empty_catalog() -> crate::external_runtime::ExternalRuntimeSnapshot {
    crate::external_runtime::ExternalRuntimeSnapshot::empty(
        1,
        crate::external_runtime::HostPlatform::GenericLinux,
    )
}

fn tempdir_ctx(probes: HostCapabilityProbeInputs) -> (tempfile::TempDir, Arc<DaemonContext>) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db = crate::db::Db::open_in_memory().expect("in-memory db");
    let locks = Arc::new(crate::locks::LockManager::in_memory(db.clone()));
    let ctx = Arc::new(
        DaemonContext::new(
            db,
            locks,
            DaemonPaths {
                socket: tmp.path().join("cockpit-hostcap.sock"),
                pid_file: tmp.path().join("cockpit-hostcap.pid"),
                ephemeral: true,
            },
            crate::daemon::terminal::test_host_factory(),
            crate::daemon::config_source::ConfigSource::fixed(
                crate::config::providers::ProvidersConfig::default(),
                crate::config::extended::ExtendedConfig::default(),
            ),
        )
        .with_host_capability_probes(probes),
    );
    (tmp, ctx)
}

#[tokio::test]
async fn host_capabilities_boot_populates_snapshot_when_keyring_missing() {
    let _guard = lock_keyring_probe_tests();
    reset_keyring_probe_cache_for_test();
    let tmp = tempfile::tempdir().expect("tempdir");
    let calls = Arc::new(AtomicUsize::new(0));
    let probes = injected_probes(&tmp, calls.clone());
    let (_tmp, ctx) = tempdir_ctx(probes.clone());
    publish_initial_host_capabilities(&ctx.host_capabilities, &probes).await;
    let snapshot = ctx
        .host_capabilities
        .current()
        .expect("snapshot must be Some after shared probes");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "keyring probe invoked once"
    );
    assert_eq!(
        snapshot
            .feature(FEATURE_SECRET_STORE_KEYRING)
            .map(|row| row.state),
        Some(FeatureCapabilityState::Missing)
    );
    assert_eq!(
        snapshot.secret_store.intent,
        SecretStoreIntent::Unconfigured
    );
    assert_eq!(
        snapshot.secret_store.effective_placement,
        SecretStorePlacement::Unavailable
    );
}

#[tokio::test]
async fn host_capabilities_get_returns_features_and_secret_store() {
    let _guard = lock_keyring_probe_tests();
    reset_keyring_probe_cache_for_test();
    let tmp = tempfile::tempdir().expect("tempdir");
    let probes = injected_probes(&tmp, Arc::new(AtomicUsize::new(0)));
    let (_tmp, ctx) = tempdir_ctx(probes.clone());
    publish_initial_host_capabilities(&ctx.host_capabilities, &probes).await;

    let mut state = MutableClientState::detached_for_test();
    let response = handle_request(Request::GetHostCapabilities, &mut state, &ctx)
        .await
        .expect("get host capabilities");
    let Response::HostCapabilities { snapshot } = response else {
        panic!("expected HostCapabilities, got {response:?}");
    };
    for id in [
        FEATURE_SECRET_STORE_KEYRING,
        FEATURE_SANDBOX_HOST,
        FEATURE_SANDBOX_CONTAINER,
        FEATURE_MEDIA_DECODE,
    ] {
        assert!(
            snapshot.feature(id).is_some(),
            "missing feature family {id}"
        );
    }
    assert_eq!(
        snapshot.secret_store.intent,
        SecretStoreIntent::Unconfigured
    );
    assert_eq!(
        snapshot.secret_store.effective_placement,
        SecretStorePlacement::Unavailable
    );
    assert!(snapshot.secret_store.fail_closed_reason.is_none());
    assert!(snapshot.secret_store.fix_command.is_none());
    let encoded = serde_json::to_value(&snapshot).expect("serialize snapshot");
    assert!(encoded.get("secretStore").is_some(), "secretStore wire key");
    assert!(encoded["secretStore"].get("intent").is_some());
    assert!(encoded["secretStore"].get("effective_placement").is_some());
    assert!(encoded["secretStore"].get("fail_closed_reason").is_some());
    assert!(encoded["secretStore"].get("fix_command").is_some());
}

#[tokio::test]
async fn host_capabilities_refresh_emits_changed_and_discards_stale_generation() {
    let _guard = lock_keyring_probe_tests();
    reset_keyring_probe_cache_for_test();
    let tmp = tempfile::tempdir().expect("tempdir");
    let probes = injected_probes(&tmp, Arc::new(AtomicUsize::new(0)));
    let (_tmp, ctx) = tempdir_ctx(probes.clone());
    publish_initial_host_capabilities(&ctx.host_capabilities, &probes).await;
    let first_generation = ctx.host_capabilities.current().unwrap().generation;

    let mut events = ctx.subscribe_global();
    let mut state = MutableClientState::detached_for_test();
    let response = handle_request(Request::RefreshHostCapabilities, &mut state, &ctx)
        .await
        .expect("refresh");
    let Response::HostCapabilities { snapshot } = response else {
        panic!("expected HostCapabilities");
    };
    assert!(snapshot.generation > first_generation);
    let event = events.try_recv().expect("HostCapabilitiesChanged");
    assert!(matches!(
        event.event,
        proto::Event::HostCapabilitiesChanged { .. }
    ));

    let store = HostCapabilitySnapshotStore::new();
    let stale = store.begin_refresh();
    let current = store.begin_refresh();
    let probes = collect_shared_host_probes(&probes, false).await;
    let stale_snapshot = build_host_capability_snapshot(
        stale,
        &probes,
        cockpit_proto::SecretStoreSnapshot::unconfigured_placeholder(),
    );
    let current_snapshot = build_host_capability_snapshot(
        current,
        &probes,
        cockpit_proto::SecretStoreSnapshot::unconfigured_placeholder(),
    );
    assert!(
        !store.publish(stale_snapshot),
        "stale generation must be discarded"
    );
    assert!(store.publish(current_snapshot));
    assert_eq!(store.current().unwrap().generation, current);
}

#[tokio::test]
async fn migrate_refresh_publishes_post_migrate_secret_store() {
    use crate::host_capabilities::refresh_host_capabilities_with_secret_store;
    use cockpit_proto::SecretStoreSnapshot;

    let _guard = lock_keyring_probe_tests();
    reset_keyring_probe_cache_for_test();
    let tmp = tempfile::tempdir().expect("tempdir");
    let probes = injected_probes(&tmp, Arc::new(AtomicUsize::new(0)));
    let store = HostCapabilitySnapshotStore::new();
    publish_initial_host_capabilities(&store, &probes).await;
    assert_eq!(
        store.current().unwrap().secret_store.effective_placement,
        SecretStorePlacement::Unavailable
    );

    let migrated = SecretStoreSnapshot {
        intent: SecretStoreIntent::Database,
        effective_placement: SecretStorePlacement::Database,
        fail_closed_reason: None,
        fix_command: None,
    };
    let (snapshot, published) =
        refresh_host_capabilities_with_secret_store(&store, &probes, migrated.clone())
            .await
            .expect("refresh with migrated store");
    assert!(published);
    assert_eq!(
        snapshot.secret_store.effective_placement,
        SecretStorePlacement::Database
    );
    assert_eq!(
        store.current().unwrap().secret_store.effective_placement,
        SecretStorePlacement::Database,
        "store must publish the post-migrate placement, not the pre-refresh one"
    );
    assert_eq!(store.current().unwrap().secret_store, snapshot.secret_store);
}

#[tokio::test]
async fn host_capabilities_linux_keyring_missing_without_secret_service() {
    let _guard = lock_keyring_probe_tests();
    reset_keyring_probe_cache_for_test();
    let tmp = tempfile::tempdir().expect("tempdir");
    let probes = injected_probes(&tmp, Arc::new(AtomicUsize::new(0)));
    let collected = collect_shared_host_probes(&probes, false).await;
    let snapshot = build_host_capability_snapshot(
        1,
        &collected,
        cockpit_proto::SecretStoreSnapshot::unconfigured_placeholder(),
    );
    let row = snapshot
        .dependency(crate::external_runtime::ID_KEYRING)
        .expect("security.keyring catalog row");
    assert_ne!(row.state, CatalogDependencyState::Available);
    assert_eq!(
        snapshot
            .feature(FEATURE_SECRET_STORE_KEYRING)
            .map(|row| row.state),
        Some(FeatureCapabilityState::Missing)
    );
}

#[tokio::test]
async fn host_capabilities_daemon_compose_selects_media_decode() {
    let _guard = lock_keyring_probe_tests();
    reset_keyring_probe_cache_for_test();
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut catalog = empty_catalog();
    for id in [
        crate::external_runtime::ID_MEDIA_FFMPEG,
        crate::external_runtime::ID_MEDIA_FFPROBE,
    ] {
        catalog.entries.insert(
            id.to_string(),
            crate::external_runtime::HealthEntry {
                id: crate::external_runtime::ExternalRuntimeId::new(id),
                state: crate::external_runtime::HealthState::Missing,
                importance:
                    crate::external_runtime::DependencyImportance::RequiredWhenFeatureSelected,
                target: crate::capabilities::ExecutionTarget::Host,
                remedy: None,
                platform: crate::external_runtime::HostPlatform::GenericLinux,
            },
        );
    }
    let mut probes = injected_probes(&tmp, Arc::new(AtomicUsize::new(0)));
    probes.catalog = CatalogProbeSource::Injected(catalog);
    let collected = collect_shared_host_probes(&probes, false).await;
    let snapshot = build_host_capability_snapshot(
        1,
        &collected,
        cockpit_proto::SecretStoreSnapshot::unconfigured_placeholder(),
    );
    for id in [
        crate::external_runtime::ID_MEDIA_FFMPEG,
        crate::external_runtime::ID_MEDIA_FFPROBE,
    ] {
        let row = snapshot.dependency(id).expect(id);
        assert_eq!(
            row.importance,
            CatalogDependencyImportance::RequiredWhenFeatureSelected,
            "{id} must be required-when-selected in the daemon snapshot"
        );
        assert_ne!(row.state, CatalogDependencyState::NotApplicable);
    }
}

#[tokio::test]
async fn host_capabilities_container_rows_reuse_one_detect_call() {
    crate::container::reset_detect_runtime_call_count();
    crate::container::set_detect_runtime_override(Some((
        None,
        ContainerAvailability {
            runtime: Some(ContainerRuntimeKind::Docker),
            harness_in_container: false,
            available: true,
            reason: None,
        },
    )));
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut probes = injected_probes(&tmp, Arc::new(AtomicUsize::new(0)));
    probes.container = ContainerProbeSource::ReuseSnapshot;
    let _ctx = test_ctx();
    let before = crate::container::detect_runtime_call_count();
    let collected = collect_shared_host_probes(&probes, false).await;
    let after = crate::container::detect_runtime_call_count();
    crate::container::set_detect_runtime_override(None);
    assert_eq!(
        after, before,
        "capability path must reuse the existing ContainerAvailability detect"
    );
    let snapshot = build_host_capability_snapshot(
        1,
        &collected,
        cockpit_proto::SecretStoreSnapshot::unconfigured_placeholder(),
    );
    assert!(
        snapshot
            .dependency(crate::external_runtime::ID_DOCKER)
            .is_some()
    );
    assert!(
        snapshot
            .dependency(crate::external_runtime::ID_PODMAN)
            .is_some()
    );
}

#[test]
fn host_capabilities_probes_forbid_mutating_docker_verbs() {
    use crate::external_runtime::{
        FORBIDDEN_MUTATING_PROBE_VERBS, container_probe_argv_is_readonly,
        probe_argv_forbids_mutation, safety_adapter_descriptors,
    };
    let descriptors = safety_adapter_descriptors().expect("safety descriptors");
    for descriptor in descriptors {
        if !matches!(
            descriptor.id.as_str(),
            crate::external_runtime::ID_DOCKER | crate::external_runtime::ID_PODMAN
        ) {
            continue;
        }
        let policy = descriptor.probe_policy.as_trusted_catalog().unwrap();
        assert!(container_probe_argv_is_readonly(policy.version_argv()));
        assert!(probe_argv_forbids_mutation(policy.version_argv()));
        if let Some(functional) = policy.functional_argv() {
            assert!(container_probe_argv_is_readonly(functional));
            assert!(probe_argv_forbids_mutation(functional));
            for verb in FORBIDDEN_MUTATING_PROBE_VERBS {
                assert!(
                    !functional.iter().any(|arg| arg.eq_ignore_ascii_case(verb)),
                    "mutating verb {verb} in {}",
                    descriptor.id.as_str()
                );
            }
        }
    }
}

#[test]
fn host_capabilities_probe_platform_keyring_unsets_on_failure_and_caches() {
    let _guard = lock_keyring_probe_tests();
    reset_keyring_probe_cache_for_test();
    let construct_calls = Arc::new(AtomicUsize::new(0));
    let calls = construct_calls.clone();
    let first = probe_platform_keyring_with(
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            let store = keyring_core::mock::Store::new().expect("mock store");
            keyring_core::set_default_store(store);
            assert!(default_platform_store_is_registered());
            Err(crate::secure_key::SecureKeyError::Unavailable(
                "injected construct failure".into(),
            ))
        },
        false,
    );
    assert_eq!(first.state, FeatureCapabilityState::Missing);
    assert!(
        !default_platform_store_is_registered(),
        "failed construct must not leave a process-global store registered"
    );
    assert_eq!(construct_calls.load(Ordering::SeqCst), 1);

    let second = probe_platform_keyring();
    assert_eq!(second, first);
    assert_eq!(
        construct_calls.load(Ordering::SeqCst),
        1,
        "second call must not construct unless refresh was requested"
    );

    let refresh_calls = construct_calls.clone();
    let _ = probe_platform_keyring_with(
        move || {
            refresh_calls.fetch_add(1, Ordering::SeqCst);
            Err(crate::secure_key::SecureKeyError::Unavailable(
                "refresh construct".into(),
            ))
        },
        true,
    );
    assert_eq!(construct_calls.load(Ordering::SeqCst), 2);
    let _ = probe_platform_keyring_refresh();
    reset_keyring_probe_cache_for_test();
}

#[test]
fn host_capabilities_refresh_preserves_existing_platform_store() {
    let _guard = lock_keyring_probe_tests();
    reset_keyring_probe_cache_for_test();
    let actor_store = keyring_core::mock::Store::new().expect("actor store");
    keyring_core::set_default_store(actor_store);
    let entry = keyring_core::Entry::new("cockpit-hostcap", "wrap-kek").expect("entry");
    entry.set_secret(b"actor-kek").expect("set actor kek");

    let refresh = probe_platform_keyring_with(
        || {
            let probe_store = keyring_core::mock::Store::new().expect("probe store");
            keyring_core::set_default_store(probe_store);
            Ok(())
        },
        true,
    );
    assert_eq!(refresh.state, FeatureCapabilityState::Available);
    assert!(
        default_platform_store_is_registered(),
        "refresh must restore the actor's process-global store"
    );
    let kept = keyring_core::Entry::new("cockpit-hostcap", "wrap-kek")
        .expect("restored entry")
        .get_secret()
        .expect("actor kek must survive refresh");
    assert_eq!(kept.as_slice(), b"actor-kek");
    keyring_core::unset_default_store();
    reset_keyring_probe_cache_for_test();
}

#[tokio::test]
async fn host_capabilities_windows_host_sandbox_is_unsupported() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut probes = injected_probes(&tmp, Arc::new(AtomicUsize::new(0)));
    probes.platform = crate::external_runtime::HostPlatform::Windows;
    probes.sandbox = SandboxProbeSource::Injected(SandboxAvailability::Available);
    let collected = collect_shared_host_probes(&probes, false).await;
    let snapshot = build_host_capability_snapshot(
        1,
        &collected,
        cockpit_proto::SecretStoreSnapshot::unconfigured_placeholder(),
    );
    assert_eq!(
        snapshot.feature(FEATURE_SANDBOX_HOST).map(|row| row.state),
        Some(FeatureCapabilityState::Unsupported)
    );
}

#[test]
fn host_capabilities_snapshot_wire_includes_secret_store() {
    let snapshot = HostCapabilitySnapshot {
        generation: 1,
        features: Vec::new(),
        dependencies: Vec::new(),
        secret_store: cockpit_proto::SecretStoreSnapshot::unconfigured_placeholder(),
    };
    let value = serde_json::to_value(&snapshot).unwrap();
    assert!(value.get("secretStore").expect("secretStore").is_object());
    assert_eq!(value["secretStore"]["intent"], "unconfigured");
    assert_eq!(value["secretStore"]["effective_placement"], "unavailable");
    assert!(value["secretStore"]["fail_closed_reason"].is_null());
    assert!(value["secretStore"]["fix_command"].is_null());
}

#[tokio::test]
async fn host_capabilities_boot_with_db_populates_snapshot_when_keyring_missing() {
    let _guard = lock_keyring_probe_tests();
    reset_keyring_probe_cache_for_test();
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("cockpit.db");
    let db = crate::db::Db::open(&db_path).expect("temp db");
    let mut timer = crate::startup::PhaseTimer::start("host_capabilities_boot_with_db");
    let ctx = boot_with_db(
        DaemonPaths {
            socket: tmp.path().join("cockpit-hostcap-boot.sock"),
            pid_file: tmp.path().join("cockpit-hostcap-boot.pid"),
            ephemeral: true,
        },
        db,
        &mut timer,
        crate::daemon::terminal::test_host_factory(),
    )
    .await
    .expect("boot_with_db");
    let snapshot = ctx
        .host_capabilities
        .current()
        .expect("boot_with_db must publish a snapshot after shared probes");
    assert_eq!(
        crate::secure_key::keyring_probe_construct_count(),
        1,
        "boot path must invoke the keyring probe once"
    );
    assert_eq!(
        snapshot
            .feature(FEATURE_SECRET_STORE_KEYRING)
            .map(|row| row.state),
        Some(FeatureCapabilityState::Missing)
    );
    assert_eq!(
        snapshot.secret_store.intent,
        SecretStoreIntent::Unconfigured
    );
    reset_keyring_probe_cache_for_test();
}
