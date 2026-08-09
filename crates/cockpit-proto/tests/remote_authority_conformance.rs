use cockpit_proto::remote_identity_protocol::canonical_json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write;
#[test]
fn remote_authority_canonical_digest_vectors() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../packages/api/fixtures/remote-authority-v1.json"
    ))
    .unwrap();
    let bytes = canonical_json(&fixture["canonicalRing"]).unwrap();
    assert_eq!(bytes, fixture["canonicalUtf8"].as_str().unwrap());
    let mut digest_hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes.as_bytes()) {
        write!(&mut digest_hex, "{byte:02x}").expect("writing to String");
    }
    assert_eq!(digest_hex, fixture["digest"].as_str().unwrap());
    for value in fixture["u64Boundaries"].as_array().unwrap() {
        cockpit_proto::remote_protocol_id::parse_canonical_u64_decimal_string(
            value.as_str().unwrap(),
        )
        .unwrap();
    }
}
