use cockpit_proto::remote_connection_metadata::{
    self, BytesBucket, COMPONENT_KIND_ACCOUNT, COMPONENT_KIND_TENANT, DOMAIN_ACCOUNT,
    DOMAIN_TENANT, DurationBucket, MetadataError, Outcome, PseudonymComponent, Region, RouteClass,
    ServiceTier, cell_tuple, correction_closes_at, decode_pseudonym_message, pseudonym_message,
    time_bucket, validate_retention_days,
};
use serde::Deserialize;
use std::collections::BTreeSet;

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
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MalformedVector {
    name: String,
    rejection: String,
    message_hex: String,
    construction: Construction,
}
/// Present-required, explicitly-nullable `construction` (Decision 5 mandates an
/// explicit `construction: null` for `trailing_byte`, never an omitted key).
///
/// A custom `Deserialize` that calls `deserialize_any` — NOT `deserialize_option`
/// — is what enforces presence. serde's missing-field path hands the field a
/// `MissingFieldDeserializer` whose only non-erroring method is
/// `deserialize_option`; a `#[serde(transparent)]` newtype over `Option` would
/// forward through to it and silently accept an ABSENT key as `None`. By calling
/// `deserialize_any`, an absent key errors with `missing field \`construction\``,
/// while a present JSON `null` maps to `None` and a present object to `Some`.
#[derive(Debug)]
struct Construction(Option<MalformedConstruction>);

impl<'de> serde::Deserialize<'de> for Construction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ConstructionVisitor;
        impl<'de> serde::de::Visitor<'de> for ConstructionVisitor {
            type Value = Construction;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("null or a construction object")
            }
            fn visit_unit<E>(self) -> Result<Construction, E>
            where
                E: serde::de::Error,
            {
                Ok(Construction(None))
            }
            fn visit_none<E>(self) -> Result<Construction, E>
            where
                E: serde::de::Error,
            {
                Ok(Construction(None))
            }
            fn visit_map<A>(self, map: A) -> Result<Construction, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let inner = MalformedConstruction::deserialize(
                    serde::de::value::MapAccessDeserializer::new(map),
                )?;
                Ok(Construction(Some(inner)))
            }
        }
        deserializer.deserialize_any(ConstructionVisitor)
    }
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MalformedConstruction {
    domain: String,
    components: Vec<ConstructionComponent>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConstructionComponent {
    kind: u8,
    alias_hex: String,
}

fn decode_hex(value: &str) -> Vec<u8> {
    // Reject malformed input up front: `chunks_exact(2)` would silently DROP an
    // odd trailing nibble, so a `messageHex` corrupted from `...00` to `...000`
    // would decode to the original bytes and defeat the exact-byte contract.
    assert!(
        value.len().is_multiple_of(2),
        "hex string must have even length: {value:?}"
    );
    assert!(
        value.bytes().all(|b| b.is_ascii_hexdigit()),
        "hex string must contain only hex digits: {value:?}"
    );
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
        let component = PseudonymComponent {
            kind: vector.component_kind,
            bytes: alias,
        };
        let expected = decode_hex(&vector.message_hex);
        let msg = pseudonym_message(&vector.domain, std::slice::from_ref(&component))
            .expect("positive construction");
        assert_eq!(
            msg, expected,
            "positive vector {} message mismatch",
            vector.name
        );
        // Every positive vector decodes back to its domain and component, and
        // re-encoding reproduces the fixture bytes exactly.
        let decoded = decode_pseudonym_message(&expected).expect("positive decode");
        assert_eq!(decoded.domain, vector.domain, "{}", vector.name);
        assert_eq!(
            decoded.component.kind, vector.component_kind,
            "{}",
            vector.name
        );
        assert_eq!(decoded.component.bytes, alias, "{}", vector.name);
        let reencoded =
            pseudonym_message(&decoded.domain, std::slice::from_ref(&decoded.component))
                .expect("re-encode");
        assert_eq!(
            reencoded, expected,
            "positive vector {} round-trip mismatch",
            vector.name
        );
    }

    // Every malformed vector is enforced by a real assertion: decode of the
    // byte payload must fail with the exact mapped variant, and where a builder
    // can express the shape, construction must fail with the same class. There
    // is no `is_ok()`/`continue` escape and no per-class skip.
    for vector in &fixture.malformed_vectors {
        // Presence contract: `trailing_byte` is the only class no builder can
        // emit, so it must carry `construction: null`; every other class must
        // carry a non-null construction that the construction API also rejects.
        // (An omitted `construction` key already fails deserialization above.)
        match vector.rejection.as_str() {
            "trailing_byte" => assert!(
                vector.construction.0.is_none(),
                "{} must carry construction: null",
                vector.name
            ),
            _ => assert!(
                vector.construction.0.is_some(),
                "{} must carry a non-null construction",
                vector.name
            ),
        }

        let decode_err = decode_pseudonym_message(&decode_hex(&vector.message_hex))
            .expect_err("malformed vector must fail decode");
        match vector.rejection.as_str() {
            "domain_component_mismatch" => {
                assert_eq!(
                    decode_err,
                    MetadataError::DomainComponentMismatch,
                    "{}",
                    vector.name
                )
            }
            "zero_components" | "multiple_components" => {
                assert_eq!(decode_err, MetadataError::ComponentCount, "{}", vector.name)
            }
            "unknown_domain" => {
                assert_eq!(decode_err, MetadataError::UnknownDomain, "{}", vector.name)
            }
            "trailing_byte" => {
                assert_eq!(decode_err, MetadataError::TrailingByte, "{}", vector.name)
            }
            other => panic!("unknown rejection class {other}"),
        }

        // Construction-level rejection, where the builder can produce the shape.
        // `trailing_byte` has `construction: null` — no builder emits a trailing
        // byte — so it is asserted only through decode.
        if let Some(construction) = &vector.construction.0 {
            let components: Vec<PseudonymComponent> = construction
                .components
                .iter()
                .map(|c| {
                    let alias_bytes = decode_hex(&c.alias_hex);
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&alias_bytes);
                    PseudonymComponent {
                        kind: c.kind,
                        bytes,
                    }
                })
                .collect();
            let ctor_err = pseudonym_message(&construction.domain, &components)
                .expect_err("malformed vector must fail construction");
            match vector.rejection.as_str() {
                "domain_component_mismatch" => {
                    assert_eq!(
                        ctor_err,
                        MetadataError::DomainComponentMismatch,
                        "{}",
                        vector.name
                    )
                }
                "zero_components" | "multiple_components" => {
                    assert_eq!(ctor_err, MetadataError::ComponentCount, "{}", vector.name)
                }
                "unknown_domain" => {
                    assert_eq!(ctor_err, MetadataError::UnknownDomain, "{}", vector.name)
                }
                other => panic!("construction present for non-constructable rejection {other}"),
            }
        }
    }
    // The corpus is fixed at exactly five vectors with an exact name→rejection
    // mapping. Asserting the SET of classes alone would miss a 6th duplicate-
    // class vector (caught here by the length check) and a renamed vector
    // (caught by the pair set) — so both cardinality and names are pinned.
    assert_eq!(
        fixture.malformed_vectors.len(),
        5,
        "malformed corpus is fixed at exactly 5 vectors"
    );
    let actual_pairs: BTreeSet<(&str, &str)> = fixture
        .malformed_vectors
        .iter()
        .map(|v| (v.name.as_str(), v.rejection.as_str()))
        .collect();
    let expected_pairs: BTreeSet<(&str, &str)> = BTreeSet::from([
        ("wrong_domain_type_pairing", "domain_component_mismatch"),
        ("zero_components", "zero_components"),
        ("multiple_components", "multiple_components"),
        ("unknown_domain", "unknown_domain"),
        ("trailing_byte", "trailing_byte"),
    ]);
    assert_eq!(
        actual_pairs, expected_pairs,
        "malformed vectors must be exactly the five named name→rejection pairs"
    );

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

// --- Negative-deserialization proofs for the strict malformed-vector schema ---
// These make the present-required `construction` and the `deny_unknown_fields`
// guards non-vacuous: they prove that a malformed fixture entry is REJECTED, not
// silently normalized.

#[test]
fn malformed_vector_requires_construction_key() {
    // An OMITTED `construction` must fail — Decision 5 requires an explicit
    // `construction: null`, never absence. (This is exactly what the earlier
    // `#[serde(transparent)] Option` newtype wrongly accepted as `None`.)
    let json = r#"{"name":"x","rejection":"trailing_byte","messageHex":"00"}"#;
    let err = serde_json::from_str::<MalformedVector>(json).unwrap_err();
    assert!(
        err.to_string().contains("construction"),
        "expected a missing-`construction` error, got: {err}"
    );
}

#[test]
fn malformed_vector_accepts_explicit_null_construction() {
    let json = r#"{"name":"x","rejection":"trailing_byte","messageHex":"00","construction":null}"#;
    let v: MalformedVector = serde_json::from_str(json).expect("explicit null parses");
    assert!(v.construction.0.is_none());
}

#[test]
fn malformed_vector_accepts_object_construction() {
    let json = r#"{"name":"x","rejection":"unknown_domain","messageHex":"00","construction":{"domain":"d","components":[]}}"#;
    let v: MalformedVector = serde_json::from_str(json).expect("object construction parses");
    assert!(v.construction.0.is_some());
}

#[test]
fn malformed_vector_rejects_legacy_top_level_field() {
    // A stale HEAD field (`componentKind`) grafted back must be rejected by the
    // outer `deny_unknown_fields`.
    let json = r#"{"name":"x","rejection":"trailing_byte","messageHex":"00","construction":null,"componentKind":1}"#;
    assert!(serde_json::from_str::<MalformedVector>(json).is_err());
}

#[test]
fn malformed_vector_rejects_unknown_nested_construction_field() {
    // A stale field INSIDE `construction` must be rejected end-to-end, proving
    // the nested `deny_unknown_fields` is wired through the custom deserializer.
    let json = r#"{"name":"x","rejection":"unknown_domain","messageHex":"00","construction":{"domain":"d","components":[],"legacy":true}}"#;
    assert!(serde_json::from_str::<MalformedVector>(json).is_err());
}
