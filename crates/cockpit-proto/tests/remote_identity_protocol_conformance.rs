use cockpit_proto::remote_identity_protocol::{
    CustodyEvidence, EnrollmentConfirmation, EnrollmentRole, EnrollmentTranscript,
    PossessionContext, PossessionProof, PossessionPurpose, Proposal, derive_possession_challenge,
    enrollment_confirmation_signing_digest, parse_remote_identity_certificate_jws,
    possession_proof_signing_digest,
};
use serde_json::Value;
fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

#[test]
fn remote_identity_derivation_vectors() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/remote-identity-protocol-v1.json"
    ))
    .unwrap();
    let valid = fixture["valid"].as_array().unwrap();
    let derived = fixture["derivations"].as_array().unwrap();
    let find = |name: &str| {
        unhex(
            derived.iter().find(|v| v["name"] == name).unwrap()["hex"]
                .as_str()
                .unwrap(),
        )
    };
    let artifact = |name: &str| {
        unhex(
            valid.iter().find(|v| v["name"] == name).unwrap()["hex"]
                .as_str()
                .unwrap(),
        )
    };
    for (name, purpose) in [
        ("enroll_proposed", PossessionPurpose::EnrollProposed),
        ("renew_current", PossessionPurpose::RenewCurrent),
        ("rotate_current", PossessionPurpose::RotateCurrent),
        ("rotate_proposed", PossessionPurpose::RotateProposed),
        ("attempt_client", PossessionPurpose::AttemptClient),
        ("attempt_daemon", PossessionPurpose::AttemptDaemon),
        ("revoke_current", PossessionPurpose::RevokeCurrent),
    ] {
        let context = artifact(&format!("context_{name}"));
        let proof = artifact(&format!("proof_{name}"));
        assert_eq!(
            derive_possession_challenge(purpose, &[16; 32], &[15; 16], &context)
                .unwrap()
                .as_slice(),
            find(&format!("challenge_{name}"))
        );
        assert_eq!(
            possession_proof_signing_digest(&proof[..175], purpose)
                .unwrap()
                .as_slice(),
            find(&format!("proof_signature_{name}"))
        );
    }
    for (name, role) in [
        ("proposed_subject", EnrollmentRole::ProposedSubject),
        ("enrolled_counterpart", EnrollmentRole::EnrolledCounterpart),
        (
            "control_plane_authorizer",
            EnrollmentRole::ControlPlaneAuthorizer,
        ),
    ] {
        let value = artifact(&format!("confirmation_{name}"));
        assert_eq!(
            enrollment_confirmation_signing_digest(&value[..104], role)
                .unwrap()
                .as_slice(),
            find(&format!("confirmation_signature_{name}"))
        );
    }
}
fn reconstruct(codec: &str, bytes: &[u8]) -> Result<Vec<u8>, String> {
    match codec {
        "FCIP" => Proposal::decode(bytes)
            .and_then(|v| v.encode())
            .map_err(|e| e.to_string()),
        "FCEN" => EnrollmentTranscript::decode(bytes)
            .and_then(|v| v.encode())
            .map_err(|e| e.to_string()),
        "FCCE" => CustodyEvidence::decode(bytes)
            .and_then(|v| v.encode())
            .map_err(|e| e.to_string()),
        "FCPC" => PossessionContext::decode(bytes)
            .and_then(|v| v.encode())
            .map_err(|e| e.to_string()),
        "FCPP" => PossessionProof::decode(bytes)
            .and_then(|v| v.encode())
            .map_err(|e| e.to_string()),
        "FCCF" => EnrollmentConfirmation::decode(bytes)
            .and_then(|v| v.encode())
            .map_err(|e| e.to_string()),
        "JWS" => parse_remote_identity_certificate_jws(
            std::str::from_utf8(bytes).map_err(|e| e.to_string())?,
        )
        .map(|_| bytes.to_vec())
        .map_err(|e| e.to_string()),
        _ => Err("unknown fixture codec".into()),
    }
}
#[test]
fn remote_identity_protocol_cross_language_vectors() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/remote-identity-protocol-v1.json"
    ))
    .unwrap();
    let valid = fixture["valid"].as_array().unwrap();
    let malformed = fixture["malformed"].as_array().unwrap();
    assert!(!valid.is_empty() && !malformed.is_empty());
    for vector in valid {
        let bytes = unhex(vector["hex"].as_str().unwrap());
        assert!(!bytes.is_empty());
        assert_eq!(
            reconstruct(vector["codec"].as_str().unwrap(), &bytes).unwrap(),
            bytes
        );
    }
    for vector in malformed {
        assert!(
            reconstruct(
                vector["codec"].as_str().unwrap(),
                &unhex(vector["hex"].as_str().unwrap())
            )
            .is_err()
        );
    }
}
