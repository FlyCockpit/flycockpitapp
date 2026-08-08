use cockpit_proto::remote_wire_magic_registry::{assert_registered, parse_registry};
#[test]
fn remote_wire_magic_registry_cross_language_vectors() {
    let json = include_str!(
        "../../../packages/cockpit-protocol/fixtures/remote-wire-magic-registry-v1.json"
    );
    let registry = parse_registry(json).expect("shared registry parses");
    assert!(!registry.is_empty());
    assert_registered(
        &registry,
        &[
            ("FCIP", "RemoteIdentityProposalV1"),
            ("FCEN", "EnrollmentTranscriptV1"),
            ("FCCE", "RemoteIdentityCustodyEvidenceV1"),
            ("FCPC", "RemoteIdentityPossessionContextV1"),
            ("FCPP", "RemoteIdentityPossessionProofV1"),
            ("FCCF", "RemoteEnrollmentConfirmationV1"),
        ],
    )
    .unwrap();
    assert!(parse_registry("[]").is_err());
}
