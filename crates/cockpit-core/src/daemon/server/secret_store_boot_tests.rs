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

#[tokio::test]
async fn connector_status_redacts_vault_only_instance_token() {
    let ctx = super::tests::test_ctx();
    let token = "fci_vault_only_instance_token_r9_redaction_probe";
    let credential = cockpit_proto::StoredFlycockpitCredential {
        server_url: "https://app.example.test".into(),
        instance_id: "inst-redact".into(),
        instance_token: token.into(),
        account: cockpit_proto::AccountInfo {
            user_id: "user-redact".into(),
            email: "redact@example.test".into(),
        },
        display_name: None,
        relay_choice: None,
    };
    ctx.store_flycockpit_credential(&credential)
        .expect("vault-only flycockpit credential stores");

    let mut rx = ctx.subscribe_global();
    ctx.broadcast_global(cockpit_proto::Event::ConnectorStatus {
        enabled: true,
        status: "error".into(),
        relay_url: None,
        relay_id: None,
        relay_region: None,
        last_error: Some(format!("upstream rejected bearer {token}")),
    });
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    let envelope = loop {
        let envelope = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .expect("connector status event")
            .expect("global event");
        if matches!(envelope.event, cockpit_proto::Event::ConnectorStatus { .. }) {
            break envelope;
        }
    };
    let scrubbed = match envelope.event {
        cockpit_proto::Event::ConnectorStatus { last_error, .. } => {
            envelope.redact.scrub(&last_error.expect("last_error"))
        }
        other => panic!("expected connector status, got {other:?}"),
    };
    assert!(
        !scrubbed.contains(token),
        "connector last_error leaked vault instance token: {scrubbed}"
    );
    assert_ne!(scrubbed, format!("upstream rejected bearer {token}"));
}
