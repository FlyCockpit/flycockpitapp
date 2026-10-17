//! Attach / start tests for wrap-key vault boot.

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
