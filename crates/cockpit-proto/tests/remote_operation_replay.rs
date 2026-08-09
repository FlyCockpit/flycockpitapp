use cockpit_proto::{Body, Envelope};

#[test]
fn shared_remote_replay_vectors_are_strict_and_exact() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/remote-operation-replay-v2.json"
    ))
    .unwrap();
    for key in ["request", "response", "ack"] {
        let envelope: Envelope = serde_json::from_value(fixture[key].clone()).unwrap();
        assert_eq!(serde_json::to_value(envelope).unwrap(), fixture[key]);
    }
    for invalid in fixture["invalidRequests"].as_array().unwrap() {
        assert!(serde_json::from_value::<Envelope>(invalid.clone()).is_err());
    }
    let request: Envelope = serde_json::from_value(fixture["request"].clone()).unwrap();
    assert!(matches!(request.body, Body::RemoteReplayRequest { .. }));
}
