use cockpit_proto::remote_identity_protocol::{
    PossessionContext, PossessionPurpose, possession_challenge_domain, possession_signature_domain,
};
#[test]
fn remote_identity_protocol_cross_language_vectors() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/remote-identity-protocol-v1.json"
    ))
    .unwrap();
    assert!(fixture["valid"]["magics"].as_array().unwrap().len() > 0);
    assert!(fixture["malformed"].as_array().unwrap().len() > 0);
    let d = Some([7; 32]);
    for purpose in [
        PossessionPurpose::EnrollProposed,
        PossessionPurpose::RenewCurrent,
        PossessionPurpose::RotateCurrent,
        PossessionPurpose::RotateProposed,
        PossessionPurpose::AttemptClient,
        PossessionPurpose::AttemptDaemon,
        PossessionPurpose::RevokeCurrent,
    ] {
        let v = match purpose {
            PossessionPurpose::EnrollProposed => PossessionContext {
                purpose,
                current_certificate_digest: None,
                proposed_identity_digest: d,
                enrollment_transcript_digest: d,
                attempt_request_digest: None,
                revocation_request_digest: None,
            },
            PossessionPurpose::RenewCurrent
            | PossessionPurpose::RotateCurrent
            | PossessionPurpose::RotateProposed => PossessionContext {
                purpose,
                current_certificate_digest: d,
                proposed_identity_digest: d,
                enrollment_transcript_digest: None,
                attempt_request_digest: None,
                revocation_request_digest: None,
            },
            PossessionPurpose::AttemptClient | PossessionPurpose::AttemptDaemon => {
                PossessionContext {
                    purpose,
                    current_certificate_digest: d,
                    proposed_identity_digest: None,
                    enrollment_transcript_digest: None,
                    attempt_request_digest: d,
                    revocation_request_digest: None,
                }
            }
            PossessionPurpose::RevokeCurrent => PossessionContext {
                purpose,
                current_certificate_digest: d,
                proposed_identity_digest: None,
                enrollment_transcript_digest: None,
                attempt_request_digest: None,
                revocation_request_digest: d,
            },
        };
        let bytes = v.encode().unwrap();
        assert_eq!(PossessionContext::decode(&bytes).unwrap(), v);
        assert_eq!(possession_challenge_domain(purpose).last(), Some(&0));
        assert_eq!(possession_signature_domain(purpose).last(), Some(&0));
    }
}
