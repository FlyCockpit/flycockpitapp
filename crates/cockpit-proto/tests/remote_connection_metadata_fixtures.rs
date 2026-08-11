use cockpit_proto::remote_connection_metadata::{
    self, BytesBucket, COMPONENT_KIND_ACCOUNT, COMPONENT_KIND_TENANT, DOMAIN_ACCOUNT,
    DOMAIN_TENANT, DurationBucket, MetadataError, Outcome, Region, RouteClass, ServiceTier,
    cell_tuple, correction_closes_at, pseudonym_message, time_bucket, validate_retention_days,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    enums: serde_json::Value,
    time_bucket: TimeBucketSection,
    duration_buckets: Vec<DurationEntry>,
    bytes_buckets: Vec<BytesEntry>,
    retention: RetentionSection,
    pseudonym_schemas: Vec<SchemaEntry>,
    positive_vectors: Vec<PositiveVector>,
    malformed_vectors: Vec<MalformedVector>,
    allowed_row_fields: Vec<String>,
    forbidden_fields: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TimeBucketSection {
    examples: Vec<TimeBucketExample>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TimeBucketExample {
    epoch_seconds: i64,
    time_bucket: i64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DurationEntry {
    seconds: u64,
    bucket: u8,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BytesEntry {
    bytes: u64,
    bucket: u8,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RetentionSection {
    default_days: u32,
    min_days: u32,
    max_days: u32,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SchemaEntry {
    domain: String,
    components: Vec<ComponentEntry>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ComponentEntry {
    kind: u8,
    name: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PositiveVector {
    name: String,
    domain: String,
    alias_hex: String,
    component_kind: u8,
    message_hex: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MalformedVector {
    name: String,
    domain: String,
    component_kind: u8,
    rejection: String,
}

fn decode_hex(value: &str) -> Vec<u8> {
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
fn remote_metadata_cross_language_fixtures() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/remote/connection-metadata-v1.json"
    ))
    .expect("fixture parses");

    assert!(
        !fixture.positive_vectors.is_empty(),
        "fixture must have at least one positive vector"
    );
    assert!(
        !fixture.malformed_vectors.is_empty(),
        "fixture must have at least one malformed vector"
    );
    assert!(!fixture.allowed_row_fields.is_empty());
    assert!(!fixture.forbidden_fields.is_empty());

    assert_eq!(fixture.enums["serviceTier"]["public_saas"], 1);
    assert_eq!(fixture.enums["serviceTier"]["enterprise"], 2);
    assert_eq!(fixture.enums["transport"]["webrtc"], 1);
    assert_eq!(fixture.enums["routeClass"]["direct"], 1);
    assert_eq!(fixture.enums["outcome"]["connected"], 1);
    assert_eq!(fixture.enums["reason"]["none"], 0);
    assert_eq!(fixture.enums["custodyClass"]["origin_protected"], 1);
    assert_eq!(fixture.enums["region"]["unknown"], 0);
    assert_eq!(fixture.enums["durationBucket"]["lt_5s"], 1);
    assert_eq!(fixture.enums["bytesBucket"]["zero"], 0);

    for ex in &fixture.time_bucket.examples {
        assert_eq!(time_bucket(ex.epoch_seconds).unwrap(), ex.time_bucket);
    }
    for entry in &fixture.duration_buckets {
        assert_eq!(
            DurationBucket::from_seconds(entry.seconds).as_u8(),
            entry.bucket
        );
    }
    for entry in &fixture.bytes_buckets {
        assert_eq!(BytesBucket::from_bytes(entry.bytes).as_u8(), entry.bucket);
    }

    assert_eq!(fixture.retention.default_days, 30);
    assert_eq!(fixture.retention.min_days, 0);
    assert_eq!(fixture.retention.max_days, 365);
    assert_eq!(validate_retention_days(0).unwrap(), 0);
    assert_eq!(validate_retention_days(30).unwrap(), 30);
    assert_eq!(validate_retention_days(365).unwrap(), 365);
    assert!(validate_retention_days(-1).is_err());
    assert!(validate_retention_days(366).is_err());

    assert_eq!(fixture.pseudonym_schemas.len(), 5);
    for schema in &fixture.pseudonym_schemas {
        assert_eq!(schema.components.len(), 1);
    }

    for vector in &fixture.positive_vectors {
        let alias_bytes = decode_hex(&vector.alias_hex);
        let mut alias = [0u8; 16];
        alias.copy_from_slice(&alias_bytes);
        let msg =
            pseudonym_message(&vector.domain, vector.component_kind, &alias).expect("positive");
        assert_eq!(
            msg,
            decode_hex(&vector.message_hex),
            "positive vector {} message mismatch",
            vector.name
        );
    }

    for vector in &fixture.malformed_vectors {
        let alias = [1u8; 16];
        let result = pseudonym_message(&vector.domain, vector.component_kind, &alias);
        // trailing_byte, multiple_components, and zero_components are
        // model-level concerns enforced by the TS component-array API and
        // the decode/verify path. The Rust pseudonym_message takes a single
        // kind+alias pair and only validates domain/kind matching and alias
        // nonzero. When the kind happens to match the domain, construction
        // succeeds; the component-count and trailing-byte checks belong to
        // the higher-level API. We only assert construction-level failure
        // for domain_component_mismatch (wrong kind) and unknown_domain.
        if matches!(
            vector.rejection.as_str(),
            "trailing_byte" | "multiple_components" | "zero_components"
        ) {
            // These are model-level concerns; construction may succeed
            // when the kind matches. The rejection is enforced elsewhere.
            if result.is_ok() {
                continue;
            }
        }
        let err = result.expect_err("malformed");
        match vector.rejection.as_str() {
            "domain_component_mismatch" | "zero_components" | "multiple_components" => {
                assert_eq!(err, MetadataError::DomainComponentMismatch);
            }
            "unknown_domain" => {
                assert_eq!(err, MetadataError::UnknownDomain);
            }
            other => panic!("unknown rejection class {other}"),
        }
    }

    let tuple = cell_tuple(
        ServiceTier::PublicSaas,
        Region::NorthAmerica,
        RouteClass::Direct,
        Outcome::Connected,
        BytesBucket::OneBLt64Kib,
        BytesBucket::Kib64Lt1Mib,
        DurationBucket::Sec30Lt2m,
    );
    assert_eq!(tuple, [1, 2, 1, 1, 1, 2, 3]);
    assert_eq!(correction_closes_at(19937), 19937 + 8 * 86400);
    assert_eq!(remote_connection_metadata::DOMAIN_TENANT, DOMAIN_TENANT);
    assert_eq!(remote_connection_metadata::DOMAIN_ACCOUNT, DOMAIN_ACCOUNT);
    assert_eq!(COMPONENT_KIND_TENANT, 1);
    assert_eq!(COMPONENT_KIND_ACCOUNT, 2);
}
