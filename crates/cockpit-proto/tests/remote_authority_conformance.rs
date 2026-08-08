use serde_json::Value;
use sha2::{Digest, Sha256};
fn canonical(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_string(value).unwrap()
        }
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        Value::Object(values) => {
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort();
            format!(
                "{{{}}}",
                keys.into_iter()
                    .map(|key| format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap(),
                        canonical(&values[key])
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}
#[test]
fn remote_authority_canonical_digest_vectors() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../packages/api/fixtures/remote-authority-v1.json"
    ))
    .unwrap();
    let bytes = canonical(&fixture["canonicalRing"]);
    assert_eq!(bytes, fixture["canonicalUtf8"].as_str().unwrap());
    assert_eq!(
        format!("{:x}", Sha256::digest(bytes.as_bytes())),
        fixture["digest"].as_str().unwrap()
    );
    for value in fixture["u64Boundaries"].as_array().unwrap() {
        cockpit_proto::remote_protocol_id::parse_canonical_u64_decimal_string(
            value.as_str().unwrap(),
        )
        .unwrap();
    }
}
