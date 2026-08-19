//! Cross-language conformance: the Rust foundation replays the shared corpus
//! (`packages/cockpit-protocol/fixtures/remote/public-service-policy-v1.json`)
//! through the REAL production entry points and must agree byte-for-byte with
//! the TypeScript pair on canonical bytes, digests, verify verdicts, codec
//! results (incl. tampered/revoked negatives), and vocabulary pins.

use cockpit_proto::remote_protocol_id::CanonicalU64DecimalStringV1;
use cockpit_proto::remote_public_service_policy::{
    self as policy, ChangeClass, ConsumerGroupState, PolicyKeyUsage, PolicyRowState,
    RemoteAttachmentCapabilityV1, RemoteAuthorizedTupleSetV1, RemoteConnectionPolicyV1,
    RemotePermissionCeilingV1, RemoteProjectCapabilityV1, RemotePublicServicePolicyV1,
    ReplicaLeaseState,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

const RAW: &str = include_str!(
    "../../../packages/cockpit-protocol/fixtures/remote/public-service-policy-v1.json"
);

#[derive(Debug, Deserialize)]
struct Fixture {
    rings: BTreeMap<String, Value>,
    #[serde(rename = "jwsVectors")]
    jws_vectors: Vec<JwsVector>,
    #[serde(rename = "policyVectors")]
    policy_vectors: Vec<PolicyVector>,
    #[serde(rename = "importWindowVectors")]
    import_window_vectors: Vec<ImportWindowVector>,
    #[serde(rename = "u64Boundaries")]
    u64_boundaries: BTreeMap<String, String>,
    #[serde(rename = "jsonNumberRejection")]
    json_number_rejection: String,
    #[serde(rename = "classificationVectors")]
    classification_vectors: Vec<ClassificationVector>,
    #[serde(rename = "ceilingVectors")]
    ceiling_vectors: Vec<CeilingVector>,
    #[serde(rename = "transportBitVectors")]
    transport_bit_vectors: Vec<TransportBitVector>,
    #[serde(rename = "tupleSetVectors")]
    tuple_set_vectors: Vec<TupleSetVector>,
    vocabulary: Vocabulary,
}

#[derive(Debug, Deserialize)]
struct JwsVector {
    id: String,
    ring: String,
    usage: String,
    compact: String,
    expect: String,
}

#[derive(Debug, Deserialize)]
struct PolicyVector {
    id: String,
    policy: RemotePublicServicePolicyV1,
    #[serde(rename = "canonicalJson")]
    canonical_json: String,
    #[serde(rename = "payloadDigestHex")]
    payload_digest_hex: String,
}

#[derive(Debug, Deserialize)]
struct ImportWindowVector {
    id: String,
    policy: RemotePublicServicePolicyV1,
    #[serde(rename = "importTime")]
    import_time: String,
    expect: String,
}

#[derive(Debug, Deserialize)]
struct ClassificationVector {
    id: String,
    previous: RemoteConnectionPolicyV1,
    next: RemoteConnectionPolicyV1,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct CeilingProject {
    #[serde(rename = "idHex")]
    id_hex: String,
    caps: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct CeilingVector {
    id: String,
    kind: String,
    #[serde(default)]
    att: Vec<u8>,
    #[serde(default)]
    projects: Vec<CeilingProject>,
    #[serde(default)]
    #[serde(rename = "bytesHex")]
    bytes_hex: Option<String>,
    #[serde(default)]
    #[serde(rename = "digestHex")]
    digest_hex: Option<String>,
    expect: String,
}

#[derive(Debug, Deserialize)]
struct TransportBitVector {
    bits: u8,
    expect: String,
}

#[derive(Debug, Deserialize)]
struct TupleSetVector {
    id: String,
    kind: String,
    #[serde(default)]
    #[serde(rename = "tupleIds")]
    tuple_ids: Vec<u16>,
    revoked: Vec<u16>,
    #[serde(default)]
    #[serde(rename = "bytesHex")]
    bytes_hex: Option<String>,
    expect: String,
}

#[derive(Debug, Deserialize)]
struct Vocabulary {
    #[serde(rename = "policyRowStates")]
    policy_row_states: Vec<String>,
    #[serde(rename = "consumerGroupStates")]
    consumer_group_states: Vec<String>,
    #[serde(rename = "replicaLeaseStates")]
    replica_lease_states: Vec<String>,
    #[serde(rename = "criticalConsumerIds")]
    critical_consumer_ids: Vec<String>,
    timing: Timing,
}

#[derive(Debug, Deserialize)]
struct Timing {
    #[serde(rename = "convergenceTimeoutSeconds")]
    convergence_timeout_seconds: i64,
    #[serde(rename = "replicaLeaseRenewSeconds")]
    replica_lease_renew_seconds: i64,
    #[serde(rename = "replicaLeaseTtlSeconds")]
    replica_lease_ttl_seconds: i64,
    #[serde(rename = "staleReapGraceSeconds")]
    stale_reap_grace_seconds: i64,
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn load() -> Fixture {
    serde_json::from_str(RAW).expect("public service policy fixture parses")
}

fn usage_of(s: &str) -> PolicyKeyUsage {
    match s {
        "import" => PolicyKeyUsage::Import,
        "verify_imported" => PolicyKeyUsage::VerifyImported,
        other => panic!("unknown usage {other}"),
    }
}

/// Every JWS branch family that must remain in the corpus. Dropping or
/// relabeling any one fails the suite (P3: per-family coverage, not just
/// "≥1 accept / ≥1 reject").
const REQUIRED_JWS_IDS: [&str; 18] = [
    "valid_current_import",
    "valid_current_reverify",
    "previous_reverify_accept",
    "previous_import_reject",
    "next_import_reject",
    "next_reverify_reject",
    "unknown_kid",
    "tampered_payload",
    "tampered_signature",
    "high_s",
    "zero_r",
    "zero_s",
    "der_signature",
    "noncanonical_base64url",
    "header_extra_key",
    "header_wrong_typ",
    "header_wrong_alg",
    "header_empty_kid",
];

#[test]
fn remote_public_service_policy_jws_verify_vectors() {
    let fx = load();
    assert!(!fx.jws_vectors.is_empty(), "nonzero jws vectors");
    let ids: Vec<&str> = fx.jws_vectors.iter().map(|v| v.id.as_str()).collect();
    for required in REQUIRED_JWS_IDS {
        assert!(
            ids.contains(&required),
            "JWS corpus is missing required family {required}"
        );
    }

    let mut accepts = 0;
    let mut rejects = 0;
    for v in &fx.jws_vectors {
        let ring_json =
            serde_json::to_string(fx.rings.get(&v.ring).expect("ring present")).expect("ring json");
        let ring = policy::parse_policy_jwks(&ring_json).expect("ring parses");
        let result = policy::verify_policy_jws(&v.compact, &ring, usage_of(&v.usage));
        match v.expect.as_str() {
            "accept" => {
                assert!(
                    result.is_ok(),
                    "vector {} expected accept: {result:?}",
                    v.id
                );
                accepts += 1;
            }
            "reject" => {
                assert!(result.is_err(), "vector {} expected reject", v.id);
                rejects += 1;
            }
            other => panic!("unknown expect {other}"),
        }
    }
    // Both a valid and an invalid branch must exist, or the corpus proves nothing.
    assert!(
        accepts > 0 && rejects > 0,
        "need both accept and reject vectors"
    );
}

#[test]
fn remote_public_service_policy_import_window_vectors() {
    let fx = load();
    assert!(
        !fx.import_window_vectors.is_empty(),
        "nonzero import-window vectors"
    );
    let mut far_future_rejected = false;
    for v in &fx.import_window_vectors {
        let import_time: i64 = v.import_time.parse().expect("importTime i64");
        let result = v.policy.validate_for_import(import_time);
        match v.expect.as_str() {
            "accept" => assert!(
                result.is_ok(),
                "window {} expected accept: {result:?}",
                v.id
            ),
            "reject" => assert!(result.is_err(), "window {} expected reject", v.id),
            other => panic!("unknown expect {other}"),
        }
        if v.id == "far_future_u64_max" {
            // A u64::MAX issuedAt must be rejected as far-future — proving the
            // i128 comparison did not wrap it to a negative i64.
            assert_eq!(v.expect, "reject");
            assert!(result.is_err());
            far_future_rejected = true;
        }
    }
    assert!(
        far_future_rejected,
        "corpus must include the u64::MAX far-future rejection"
    );
}

#[test]
fn remote_public_service_policy_payload_digests() {
    let fx = load();
    assert!(!fx.policy_vectors.is_empty(), "nonzero policy vectors");
    for v in &fx.policy_vectors {
        assert_eq!(
            v.policy.canonical_json().expect("canonical"),
            v.canonical_json,
            "canonical JSON mismatch for {}",
            v.id
        );
        assert_eq!(
            v.policy.payload_digest_hex().expect("digest"),
            v.payload_digest_hex,
            "payload digest mismatch for {}",
            v.id
        );
    }

    // u64 boundary decimal strings parse and round-trip; a JSON number is rejected.
    for (name, value) in &fx.u64_boundaries {
        let parsed = CanonicalU64DecimalStringV1::parse(value)
            .unwrap_or_else(|_| panic!("boundary {name} parses"));
        assert_eq!(parsed.as_str(), value);
    }
    #[derive(Deserialize)]
    struct Wrap {
        #[serde(rename = "serviceVersion")]
        _sv: CanonicalU64DecimalStringV1,
    }
    assert!(
        serde_json::from_str::<Wrap>(&fx.json_number_rejection).is_err(),
        "JSON number for serviceVersion must be rejected"
    );
}

#[test]
fn remote_public_service_policy_classification_vectors() {
    let fx = load();
    assert!(
        !fx.classification_vectors.is_empty(),
        "nonzero classification vectors"
    );
    let class_ids: Vec<&str> = fx
        .classification_vectors
        .iter()
        .map(|v| v.id.as_str())
        .collect();
    for required in ["narrowing", "widening", "mixed"] {
        assert!(
            class_ids.contains(&required),
            "missing classification family {required}"
        );
    }
    let mut mixed = 0;
    for v in &fx.classification_vectors {
        let got = policy::classify_policy_change(&v.previous, &v.next);
        let expected = match v.expected.as_str() {
            "narrowing_or_equal" => policy::PolicyChangeClassification::NarrowingOrEqual,
            "widening" => policy::PolicyChangeClassification::Widening,
            "mixed" => policy::PolicyChangeClassification::Mixed,
            other => panic!("unknown classification {other}"),
        };
        assert_eq!(got, expected, "classification mismatch for {}", v.id);
        if expected == policy::PolicyChangeClassification::Mixed {
            mixed += 1;
        }
    }
    assert!(mixed > 0, "corpus must include a mixed classification");
}

#[test]
fn remote_public_service_policy_ceiling_and_transport_vectors() {
    let fx = load();
    assert!(!fx.ceiling_vectors.is_empty(), "nonzero ceiling vectors");
    let ceiling_ids: Vec<&str> = fx.ceiling_vectors.iter().map(|v| v.id.as_str()).collect();
    for required in [
        "empty",
        "minimum",
        "maximum_exceeds_512",
        "unsorted_attachment",
        "trailing_byte",
        "one_byte_mutation",
    ] {
        assert!(
            ceiling_ids.contains(&required),
            "missing ceiling family {required}"
        );
    }
    let ceiling_accepts = fx
        .ceiling_vectors
        .iter()
        .filter(|v| v.expect == "accept")
        .count();
    let ceiling_rejects = fx
        .ceiling_vectors
        .iter()
        .filter(|v| v.expect == "reject")
        .count();
    assert!(
        ceiling_accepts > 0 && ceiling_rejects > 0,
        "ceiling needs both branches"
    );
    for v in &fx.ceiling_vectors {
        match (v.kind.as_str(), v.expect.as_str()) {
            ("struct", "accept") => {
                let ceiling = build_ceiling(v);
                let bytes = ceiling.encode().expect("encode");
                assert_eq!(
                    policy_hex(&bytes),
                    *v.bytes_hex.as_ref().expect("bytesHex"),
                    "ceiling bytes mismatch {}",
                    v.id
                );
                let digest = policy::permission_ceiling_digest(&ceiling).expect("digest");
                assert_eq!(
                    policy_hex(digest.as_bytes()),
                    *v.digest_hex.as_ref().expect("digestHex"),
                    "ceiling digest mismatch {}",
                    v.id
                );
                // Round-trips through decode.
                assert_eq!(
                    RemotePermissionCeilingV1::decode(&bytes).expect("decode"),
                    ceiling
                );
            }
            ("struct", "reject") => {
                let ceiling = build_ceiling(v);
                assert!(
                    ceiling.encode().is_err(),
                    "ceiling {} expected encode reject",
                    v.id
                );
            }
            ("bytes", "reject") => {
                let bytes = from_hex(v.bytes_hex.as_ref().expect("bytesHex"));
                assert!(
                    RemotePermissionCeilingV1::decode(&bytes).is_err(),
                    "ceiling {} expected decode reject",
                    v.id
                );
            }
            other => panic!("unhandled ceiling vector {other:?}"),
        }
    }

    assert!(
        !fx.transport_bit_vectors.is_empty(),
        "nonzero transport vectors"
    );
    let transport_accepts = fx
        .transport_bit_vectors
        .iter()
        .filter(|v| v.expect == "accept")
        .count();
    let transport_rejects = fx
        .transport_bit_vectors
        .iter()
        .filter(|v| v.expect == "reject")
        .count();
    assert!(
        transport_accepts > 0 && transport_rejects > 0,
        "transport needs both branches"
    );
    for v in &fx.transport_bit_vectors {
        let ok = policy::validate_transport_bits(v.bits).is_ok();
        assert_eq!(
            ok,
            v.expect == "accept",
            "transport bits {} verdict",
            v.bits
        );
    }
}

fn build_ceiling(v: &CeilingVector) -> RemotePermissionCeilingV1 {
    let attachment_capabilities = v
        .att
        .iter()
        .map(|&o| RemoteAttachmentCapabilityV1::from_ordinal(o).expect("attachment ordinal"))
        .collect();
    let projects = v
        .projects
        .iter()
        .map(|p| {
            let mut id = [0u8; 16];
            id.copy_from_slice(&from_hex(&p.id_hex));
            let caps = p
                .caps
                .iter()
                .map(|&o| RemoteProjectCapabilityV1::from_ordinal(o).expect("project ordinal"))
                .collect();
            (id, caps)
        })
        .collect();
    RemotePermissionCeilingV1 {
        attachment_capabilities,
        projects,
    }
}

fn policy_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn remote_public_service_policy_tuple_set_vectors() {
    let fx = load();
    assert!(
        !fx.tuple_set_vectors.is_empty(),
        "nonzero tuple set vectors"
    );
    let tuple_ids: Vec<&str> = fx.tuple_set_vectors.iter().map(|v| v.id.as_str()).collect();
    for required in [
        "valid_v1",
        "encode_revoked_member",
        "decode_revoked_member",
        "unknown_tuple",
        "zero_revoked",
    ] {
        assert!(
            tuple_ids.contains(&required),
            "missing tuple family {required}"
        );
    }
    let mut revoked_reject = 0;
    for v in &fx.tuple_set_vectors {
        match (v.kind.as_str(), v.expect.as_str()) {
            ("struct", "accept") => {
                let set = RemoteAuthorizedTupleSetV1 {
                    tuple_ids: v.tuple_ids.clone(),
                };
                let bytes = set.encode(&v.revoked).expect("encode");
                assert_eq!(
                    policy_hex(&bytes),
                    *v.bytes_hex.as_ref().expect("bytesHex"),
                    "tuple bytes mismatch {}",
                    v.id
                );
                assert_eq!(
                    RemoteAuthorizedTupleSetV1::decode(&bytes, &v.revoked).expect("decode"),
                    set
                );
            }
            ("struct", "reject") => {
                let set = RemoteAuthorizedTupleSetV1 {
                    tuple_ids: v.tuple_ids.clone(),
                };
                assert!(
                    set.encode(&v.revoked).is_err(),
                    "tuple {} expected encode reject",
                    v.id
                );
                if v.revoked.contains(&1) {
                    revoked_reject += 1;
                }
            }
            ("bytes", "reject") => {
                let bytes = from_hex(v.bytes_hex.as_ref().expect("bytesHex"));
                assert!(
                    RemoteAuthorizedTupleSetV1::decode(&bytes, &v.revoked).is_err(),
                    "tuple {} expected decode reject",
                    v.id
                );
                if v.revoked.contains(&1) {
                    revoked_reject += 1;
                }
            }
            other => panic!("unhandled tuple vector {other:?}"),
        }
    }
    // The revoked-member rejection must fail against the pre-change codec (which
    // ignored revocation) — proving the new branch is real.
    assert!(
        revoked_reject > 0,
        "corpus must include a revoked-member rejection"
    );
}

fn ser_name<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn remote_public_service_policy_vocabulary_pins() {
    let fx = load();
    // Serialized state-enum names produced by the REAL serde derives, compared
    // to the independently-authored fixture (not a hand-copied literal array).
    let row: Vec<String> = [
        PolicyRowState::Scheduled,
        PolicyRowState::Preparing,
        PolicyRowState::ActiveConverging,
        PolicyRowState::Active,
        PolicyRowState::ActiveConvergenceFailed,
        PolicyRowState::ScheduledFailed,
    ]
    .iter()
    .map(ser_name)
    .collect();
    assert_eq!(row, fx.vocabulary.policy_row_states);
    let groups: Vec<String> = [
        ConsumerGroupState::Disabled,
        ConsumerGroupState::Required,
        ConsumerGroupState::Draining,
        ConsumerGroupState::Retired,
    ]
    .iter()
    .map(ser_name)
    .collect();
    assert_eq!(groups, fx.vocabulary.consumer_group_states);
    let leases: Vec<String> = [
        ReplicaLeaseState::Starting,
        ReplicaLeaseState::Ready,
        ReplicaLeaseState::Draining,
        ReplicaLeaseState::Stale,
    ]
    .iter()
    .map(ser_name)
    .collect();
    assert_eq!(leases, fx.vocabulary.replica_lease_states);
    let consumers: Vec<String> = policy::CRITICAL_CONSUMER_IDS
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(consumers, fx.vocabulary.critical_consumer_ids);
    assert_eq!(
        policy::CONVERGENCE_TIMEOUT_SECONDS,
        fx.vocabulary.timing.convergence_timeout_seconds
    );
    assert_eq!(
        policy::REPLICA_LEASE_RENEW_SECONDS,
        fx.vocabulary.timing.replica_lease_renew_seconds
    );
    assert_eq!(
        policy::REPLICA_LEASE_TTL_SECONDS,
        fx.vocabulary.timing.replica_lease_ttl_seconds
    );
    assert_eq!(
        policy::STALE_REAP_GRACE_SECONDS,
        fx.vocabulary.timing.stale_reap_grace_seconds
    );

    // ChangeClass round-trips through the pinned names too.
    assert_eq!(
        serde_json::to_string(&ChangeClass::NarrowingOrEqual).unwrap(),
        "\"narrowing_or_equal\""
    );
    assert_eq!(
        serde_json::to_string(&ChangeClass::Widening).unwrap(),
        "\"widening\""
    );
}
