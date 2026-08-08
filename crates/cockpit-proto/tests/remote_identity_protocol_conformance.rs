use cockpit_proto::remote_identity_protocol::{
    CustodyEvidence, EnrollmentConfirmation, EnrollmentTranscript, PossessionContext,
    PossessionProof, Proposal, parse_remote_identity_certificate_jws,
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
