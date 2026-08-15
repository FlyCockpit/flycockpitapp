//! Attach / start tests for wrap-key vault boot.

use std::sync::Arc;

use cockpit_proto::{FeatureCapabilityState, SecretStorePlacement};

use crate::secure_key::{
    FailClosedReconciler, KeyringProbeResult, MemoryKekStore, SecretStoreInjected, SecureKeyActor,
};

fn missing_probe() -> KeyringProbeResult {
    KeyringProbeResult {
        state: FeatureCapabilityState::Missing,
        reason: "injected keyring missing".into(),
        fix_command: Some("install gnome-keyring".into()),
        remedy_text: None,
    }
}

#[test]
fn attach_succeeds_when_platform_keyring_unavailable() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = crate::db::Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let file_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    let actor = SecureKeyActor::start_production_resolved(
        db.clone(),
        Arc::new(FailClosedReconciler),
        &missing_probe(),
        Some(tmp.path().join("secret-vault")),
        SecretStoreInjected {
            file_kek: Some(file_kek),
            keyring_kek: None,
            legacy_keyring: None,
        },
    )
    .expect("first-run database must attach without a platform keyring");

    let locks = Arc::new(crate::locks::LockManager::in_memory(db.clone()));
    let mut ctx = super::DaemonContext::new(
        db,
        locks,
        crate::daemon::DaemonPaths {
            socket: tmp.path().join("cockpit.sock"),
            pid_file: tmp.path().join("cockpit.pid"),
            ephemeral: true,
        },
        crate::daemon::terminal::test_host_factory(),
        crate::daemon::config_source::ConfigSource::fixed(
            crate::config::providers::ProvidersConfig::default(),
            crate::config::extended::ExtendedConfig::default(),
        ),
    );
    ctx.attach_secure_key_actor(actor);
    ctx.redaction_key_resolver()
        .expect("resolver must be installed after vault start");
}
