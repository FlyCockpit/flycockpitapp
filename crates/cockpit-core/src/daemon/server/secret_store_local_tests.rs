//! Local-only secret-store boot coverage.

use std::sync::Arc;

use cockpit_proto::{FeatureCapabilityState, SecretStorePlacement};

use crate::secure_key::{
    FailClosedReconciler, KeyringProbeResult, MemoryKekStore, SecretStoreInjected, SecureKeyActor,
};

#[test]
fn attach_succeeds_when_platform_keyring_unavailable() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = crate::db::Db::open(&tmp.path().join("cockpit.db")).unwrap();
    let file_kek = Arc::new(MemoryKekStore::new(SecretStorePlacement::Database));
    let probe = KeyringProbeResult {
        state: FeatureCapabilityState::Missing,
        reason: "injected keyring missing".into(),
        fix_command: Some("install a platform keyring".into()),
        remedy_text: None,
    };
    let actor = SecureKeyActor::start_production_resolved(
        db.clone(),
        Arc::new(FailClosedReconciler),
        &probe,
        Some(tmp.path().join("secret-vault")),
        SecretStoreInjected {
            file_kek: Some(file_kek),
            keyring_kek: None,
            legacy_keyring: None,
        },
    )
    .expect("first-run database must attach without a platform keyring");

    let ctx_db = crate::db::Db::open_in_memory().expect("in-memory context db");
    let locks = Arc::new(crate::locks::LockManager::in_memory(ctx_db.clone()));
    let mut ctx = super::DaemonContext::new(
        ctx_db,
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
