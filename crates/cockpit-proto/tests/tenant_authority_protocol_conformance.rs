//! Cross-language conformance test for the tenant-authority protocol.
//!
//! Consumes the same checked-in manifest as the TypeScript mirror:
//! packages/cockpit-protocol/fixtures/tenant-authority-protocol-v1.json
//! The test name is exactly tenant_authority_protocol_cross_language_vectors.

use cockpit_proto::remote_tenant_authority_protocol::*;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    operations: Vec<NamedDiscriminant>,
    device_enrollment_actions: Vec<NamedDiscriminant>,
    credential_registry_actions: Vec<NamedDiscriminant>,
    recovery_lifecycle_actions: Vec<NamedDiscriminant>,
    identity_revocation_actions: Vec<NamedDiscriminant>,
    evidence_types: Vec<EvidenceTypeFixture>,
    result_kinds: Vec<NamedDiscriminant>,
    reason_codes: Vec<NamedDiscriminant>,
    jws_kinds: Vec<JwsKindFixture>,
    signing_domains: Vec<String>,
    envelope: EnvelopeFixture,
    fctir_reasons: Vec<NamedDiscriminant>,
    statement_lifetimes: StatementLifetimes,
    wire_magics: WireMagicsFixture,
    cross_protocol_magics: CrossProtocolMagicsFixture,
}

#[derive(Debug, Deserialize)]
struct NamedDiscriminant {
    discriminant: u8,
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceTypeFixture {
    discriminant: u8,
    name: String,
    category: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    magic: Option<String>,
    cap: usize,
}

#[derive(Debug, Deserialize)]
struct JwsKindFixture {
    name: String,
    typ: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnvelopeFixture {
    magic: String,
    version: u8,
    max_body_bytes: usize,
    max_request_bytes: usize,
    max_result_bytes: usize,
    max_statement_jws_bytes: usize,
    max_artifact_bytes: usize,
    max_fctv_bytes: usize,
    validity_seconds: i64,
    future_issued_tolerance_seconds: i64,
    network_deadline_seconds: i64,
    idempotency_retention_hours: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatementLifetimes {
    attempt: i64,
    activation: i64,
    denial: i64,
    status: i64,
    verifier_cache_seconds: i64,
    verifier_skew_seconds: i64,
    retention_floor_seconds: i64,
}

#[derive(Debug, Deserialize)]
struct WireMagicsFixture {
    fcta: String,
    fcto: String,
    fctv: String,
    fcir: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CrossProtocolMagicsFixture {
    turn: String,
    relationship_consent: String,
}

fn load_fixture() -> Fixture {
    let raw = include_str!(
        "../../../packages/cockpit-protocol/fixtures/tenant-authority-protocol-v1.json"
    );
    serde_json::from_str(raw).expect("tenant-authority-protocol-v1.json must parse")
}

#[test]
fn tenant_authority_protocol_cross_language_vectors() {
    let f = load_fixture();

    // 1. Closed surface: exactly eleven operations.
    closed_surface_guard();
    foundation_consumption_guard();
    assert_eq!(f.operations.len(), 11);
    for (i, op) in f.operations.iter().enumerate() {
        assert_eq!(op.discriminant as usize, i + 1);
        let parsed = TenantAuthorityOperation::from_discriminant(op.discriminant).unwrap();
        assert_eq!(parsed.name(), op.name);
    }
    assert_eq!(TenantAuthorityOperation::ALL.len(), 11);

    // 2. Device-enrollment actions.
    assert_eq!(f.device_enrollment_actions.len(), 3);
    for (i, a) in f.device_enrollment_actions.iter().enumerate() {
        assert_eq!(a.discriminant as usize, i + 1);
        let parsed = DeviceEnrollmentAction::from_discriminant(a.discriminant).unwrap();
        assert_eq!(parsed.name(), a.name);
    }

    assert_eq!(f.credential_registry_actions.len(), 4);
    for (i, a) in f.credential_registry_actions.iter().enumerate() {
        assert_eq!(a.discriminant as usize, i + 1);
        let parsed = CredentialRegistryAction::from_discriminant(a.discriminant).unwrap();
        assert_eq!(parsed.name(), a.name);
    }

    assert_eq!(f.recovery_lifecycle_actions.len(), 4);
    for (i, a) in f.recovery_lifecycle_actions.iter().enumerate() {
        assert_eq!(a.discriminant as usize, i + 1);
        let parsed = RecoveryLifecycleAction::from_discriminant(a.discriminant).unwrap();
        assert_eq!(parsed.name(), a.name);
    }

    assert_eq!(f.identity_revocation_actions.len(), 2);
    for (i, a) in f.identity_revocation_actions.iter().enumerate() {
        assert_eq!(a.discriminant as usize, i + 1);
        let parsed = IdentityRevocationAction::from_discriminant(a.discriminant).unwrap();
        assert_eq!(parsed.name(), a.name);
    }

    // 3. Twenty evidence types.
    assert_eq!(f.evidence_types.len(), 20);
    let mut jws_count = 0;
    let mut json_count = 0;
    let mut bin_count = 0;
    for (i, et) in f.evidence_types.iter().enumerate() {
        assert_eq!(et.discriminant as usize, i + 1);
        let parsed = EvidenceType::from_discriminant(et.discriminant).unwrap();
        assert_eq!(parsed.name(), et.name);
        assert_eq!(parsed.cap(), et.cap);
        match et.category.as_str() {
            "compact_jws" => {
                assert_eq!(parsed.category(), EvidenceCategory::CompactJws);
                assert_eq!(parsed.jws_typ(), et.typ.as_deref());
                jws_count += 1;
            }
            "canonical_json" => {
                assert_eq!(parsed.category(), EvidenceCategory::CanonicalJson);
                json_count += 1;
            }
            "binary" => {
                assert_eq!(parsed.category(), EvidenceCategory::Binary);
                if let Some(magic) = &et.magic {
                    let expected = magic.as_bytes();
                    assert_eq!(parsed.wire_magic().unwrap(), expected);
                }
                bin_count += 1;
            }
            _ => panic!("unknown category {}", et.category),
        }
    }
    assert_eq!(jws_count, 6);
    assert_eq!(json_count, 1);
    assert_eq!(bin_count, 13);

    // Cross-category substitution is malformed evidence.
    let fcir = FcirRevocationRequest {
        subject_kind: cockpit_proto::remote_identity_protocol::SubjectKind::Client,
        subject_id: [1; 16],
        generation: 1,
        reason: FcirReason::UserRequested,
        requested_at: 1_000,
    }
    .encode()
    .unwrap();
    assert!(EvidenceType::AuthorityRing.validate(&fcir).is_err());
    assert!(EvidenceType::QuotaRequest.validate(&fcir).is_err());

    // 4. Five FCTO result kinds and nineteen reason codes.
    assert_eq!(f.result_kinds.len(), 5);
    for (i, rk) in f.result_kinds.iter().enumerate() {
        assert_eq!(rk.discriminant as usize, i + 1);
        let parsed = FctoResultKind::from_discriminant(rk.discriminant).unwrap();
        assert_eq!(parsed.name(), rk.name);
    }
    assert_eq!(f.reason_codes.len(), 19);
    for (i, rc) in f.reason_codes.iter().enumerate() {
        assert_eq!(rc.discriminant as u16, i as u16);
        let parsed = FctoReasonCode::from_discriminant(rc.discriminant as u16).unwrap();
        assert_eq!(parsed.name(), rc.name);
    }
    assert_eq!(FctoReasonCode::None.discriminant(), 0);
    let denial_reasons: Vec<_> = FctoReasonCode::ALL.iter().filter(|r| r.is_denial_reason()).collect();
    assert_eq!(denial_reasons.len(), 5);
    let error_reasons: Vec<_> = FctoReasonCode::ALL.iter().filter(|r| r.is_error_reason()).collect();
    assert_eq!(error_reasons.len(), 13);

    // 5. JWS kinds and signing domains.
    assert_eq!(f.jws_kinds.len(), 5);
    for jk in &f.jws_kinds {
        let domain = SigningDomain::ALL.iter().find(|d| d.name() == jk.name).unwrap();
        assert_eq!(domain.jws_typ(), Some(jk.typ.as_str()));
    }
    assert_eq!(f.signing_domains.len(), 6);
    for name in &f.signing_domains {
        assert!(SigningDomain::ALL.iter().any(|d| d.name() == name));
    }

    // 6. Envelope constants.
    assert_eq!(f.envelope.max_body_bytes, MAX_BODY_BYTES);
    assert_eq!(f.envelope.max_request_bytes, MAX_REQUEST_BYTES);
    assert_eq!(f.envelope.max_result_bytes, MAX_RESULT_BYTES);
    assert_eq!(f.envelope.max_statement_jws_bytes, MAX_STATEMENT_JWS_BYTES);
    assert_eq!(f.envelope.max_artifact_bytes, MAX_ARTIFACT_BYTES);
    assert_eq!(f.envelope.max_fctv_bytes, MAX_FCTV_RESULT_BYTES);
    assert_eq!(f.envelope.validity_seconds, FCTA_VALIDITY_SECONDS);
    assert_eq!(f.envelope.future_issued_tolerance_seconds, FUTURE_ISSUED_TOLERANCE_SECONDS);
    assert_eq!(f.envelope.network_deadline_seconds, NETWORK_DEADLINE_SECONDS);
    assert_eq!(f.envelope.idempotency_retention_hours, IDEMPOTENCY_RETENTION_HOURS);

    // 7. FCIR reasons.
    assert_eq!(f.fctir_reasons.len(), 5);
    for (i, r) in f.fctir_reasons.iter().enumerate() {
        assert_eq!(r.discriminant as usize, i + 1);
        let parsed = FcirReason::from_discriminant(r.discriminant).unwrap();
        assert_eq!(parsed.name(), r.name);
    }

    // 8. Statement lifetimes.
    assert_eq!(f.statement_lifetimes.attempt, STATEMENT_LIFETIME_ATTEMPT);
    assert_eq!(f.statement_lifetimes.activation, STATEMENT_LIFETIME_HIGH_ASSURANCE);
    assert_eq!(f.statement_lifetimes.denial, STATEMENT_LIFETIME_DENIAL_STATUS);
    assert_eq!(f.statement_lifetimes.status, STATEMENT_LIFETIME_DENIAL_STATUS);
    assert_eq!(f.statement_lifetimes.verifier_cache_seconds, VERIFIER_CACHE_SECONDS);
    assert_eq!(f.statement_lifetimes.verifier_skew_seconds, VERIFIER_SKEW_SECONDS);
    assert_eq!(f.statement_lifetimes.retention_floor_seconds, RETENTION_FLOOR_SECONDS);

    // 9. Wire-magic registry.
    assert_eq!(f.wire_magics.fcta, "FCTA");
    assert_eq!(f.wire_magics.fcto, "FCTO");
    assert_eq!(f.wire_magics.fctv, "FCTV");
    assert_eq!(f.wire_magics.fcir, "FCIR");
    let registry_json = include_str!(
        "../../../packages/cockpit-protocol/fixtures/remote-wire-magic-registry-v1.json"
    );
    assert_tenant_authority_wire_magics(registry_json).unwrap();
    assert_eq!(f.cross_protocol_magics.turn, "FCTR");
    assert_eq!(f.cross_protocol_magics.relationship_consent, "FCRS");
    assert!(is_cross_protocol_magic(&FCTR));
    assert!(is_cross_protocol_magic(&FCRS));

    // 10. FCTA/FCTO round-trip.
    let body = vec![1u8, 0, 0];
    let body_digest = sha256(&body);
    let env = FctaEnvelope {
        operation: 9,
        request_id: [1; 16],
        tenant_id: [2; 16],
        authority_id: [3; 16],
        issuer: "https://tenant.flycockpit.example".to_string(),
        governance_epoch: 1,
        policy_epoch: 1,
        issued_at: 1_000,
        expires_at: 1_060,
        body_digest,
        body,
    };
    let encoded = env.encode().unwrap();
    let decoded = FctaEnvelope::decode(&encoded).unwrap();
    assert_eq!(decoded, env);
    let mut bad = FCTR.to_vec();
    bad.push(1);
    assert!(matches!(FctaEnvelope::decode(&bad).unwrap_err(), TenantAuthorityProtocolError::Magic(_)));

    let fcto = FctoEnvelope {
        operation: 9,
        request_id: [1; 16],
        tenant_id: [2; 16],
        authority_id: [3; 16],
        result_kind: 3,
        reason_code: 0,
        statement_jws: vec![],
        artifact: vec![0xAB; 100],
    };
    let fcto_encoded = fcto.encode().unwrap();
    let fcto_decoded = FctoEnvelope::decode(&fcto_encoded).unwrap();
    assert_eq!(fcto_decoded, fcto);

    // 11. Approval cardinality matrix.
    for op in [TenantAuthorityOperation::AttemptGrant, TenantAuthorityOperation::TenantAuthorityStatus, TenantAuthorityOperation::TenantIdentityRevocationStatus] {
        assert_eq!(approval_cardinality(op, None).unwrap(), ApprovalCardinality::None);
    }
    for op in [TenantAuthorityOperation::AuthorityActivation, TenantAuthorityOperation::AuthorityRotation, TenantAuthorityOperation::RecoveryExecution, TenantAuthorityOperation::CredentialRegistryRevision] {
        assert_eq!(approval_cardinality(op, None).unwrap(), ApprovalCardinality::OwnerPlusSecurityAdmin);
    }

    // 12. FCIR and FCQR round-trips.
    let fcir = FcirRevocationRequest {
        subject_kind: cockpit_proto::remote_identity_protocol::SubjectKind::Client,
        subject_id: [1; 16],
        generation: 1,
        reason: FcirReason::UserRequested,
        requested_at: 1_000,
    };
    let fcir_bytes = fcir.encode().unwrap();
    assert_eq!(fcir_bytes.len(), 39);
    assert_eq!(FcirRevocationRequest::decode(&fcir_bytes).unwrap(), fcir);

    let fcqr = FcqrQuotaRequest {
        requested_turn_bytes: 1000,
        requested_turn_seconds: 60,
        requested_websocket_bytes: 2000,
        requested_websocket_seconds: 120,
        budget_generation: 1,
        policy_digest: [0xAB; 32],
    };
    let fcqr_bytes = fcqr.encode().unwrap();
    assert_eq!(fcqr_bytes.len(), 77);
    assert_eq!(FcqrQuotaRequest::decode(&fcqr_bytes).unwrap(), fcqr);
}
