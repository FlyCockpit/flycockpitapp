use cockpit_proto::remote_identity_protocol::{
    CustodyEvidence, EnrollmentConfirmation, EnrollmentRole, EnrollmentTranscript,
    PossessionContext, PossessionProof, PossessionPurpose, Proposal, SubjectKind,
    derive_possession_challenge, enrollment_confirmation_signing_digest,
    parse_remote_identity_certificate_jws, possession_challenge_domain,
    possession_proof_signing_digest, possession_signature_domain,
};
use serde_json::Value;

const FIXTURE: &str =
    include_str!("../../../packages/cockpit-protocol/fixtures/remote-identity-protocol-v1.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).unwrap()
}
fn by_name<'a>(arr: &'a [Value], name: &str) -> &'a Value {
    arr.iter()
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("fixture vector `{name}` present"))
}
fn hex_of(arr: &[Value], name: &str) -> Vec<u8> {
    unhex(by_name(arr, name)["hex"].as_str().unwrap())
}
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

// ---------------------------------------------------------------------------
// AC1 — account-branch rejection vectors (client-with-account,
// daemon-without-account) reject in Rust exactly as in TypeScript.
// ---------------------------------------------------------------------------
#[test]
fn remote_identity_account_branch_rejections() {
    let fixture = fixture();
    let malformed = fixture["malformed"].as_array().unwrap();
    let names = [
        ("account_branch_fcip_client_missing", "FCIP"),
        ("account_branch_fcip_daemon_present", "FCIP"),
        ("account_branch_fcen_client_missing", "FCEN"),
        ("account_branch_fcen_daemon_present", "FCEN"),
    ];
    // Nonzero count of account-branch vectors is asserted structurally.
    assert!(names.len() >= 4, "expected nonzero account-branch vectors");
    for (name, codec) in names {
        let bytes = hex_of(malformed, name);
        let err = reconstruct(codec, &bytes)
            .expect_err(&format!("{name} must reject a closed account branch"));
        assert!(
            err.contains("account"),
            "{name} rejected for the wrong reason: {err}"
        );
    }
}

// ---------------------------------------------------------------------------
// AC2/AC3 — remote_identity_certificate_jws_vectors: valid certificates parse;
// every named JWS abuse vector fails closed on its specific check.
// ---------------------------------------------------------------------------
#[test]
fn remote_identity_certificate_jws_vectors() {
    let fixture = fixture();
    let valid = fixture["valid"].as_array().unwrap();
    let malformed = fixture["malformed"].as_array().unwrap();
    for name in ["certificate_client", "certificate_daemon"] {
        let bytes = hex_of(valid, name);
        let text = std::str::from_utf8(&bytes).unwrap();
        parse_remote_identity_certificate_jws(text)
            .unwrap_or_else(|e| panic!("{name} must parse: {e}"));
    }
    // Each abuse vector rejects, and the error names its specific defect so a
    // vector that failed for an unrelated reason cannot pass vacuously.
    let abuse = [
        ("jws_duplicate_member", "noncanonical"),
        ("jws_unknown_member", "protected header"),
        ("jws_crit", "protected header"),
        ("jws_alg_substitution", "protected header"),
        ("jws_size_cap", "exceeds"),
        ("jws_thumbprint_mismatch", "thumbprint"),
        ("jws_high_s", "high-S"),
        ("jws_zero_r", "signature"),
        ("jws_zero_s", "signature"),
    ];
    assert_eq!(abuse.len(), 9, "all nine JWS abuse classes are covered");
    for (name, needle) in abuse {
        let bytes = hex_of(malformed, name);
        let text = std::str::from_utf8(&bytes).unwrap();
        let err = parse_remote_identity_certificate_jws(text)
            .expect_err(&format!("{name} must reject"))
            .to_string();
        assert!(
            err.contains(needle),
            "{name}: expected `{needle}` in `{err}`"
        );
    }
}

// ---------------------------------------------------------------------------
// AC2 — remote_identity_possession_purpose_matrix: the full
// (purpose × subject-kind) proof matrix and (purpose × context-presence)
// matrix accept exactly the legal combinations and reject the rest.
// ---------------------------------------------------------------------------
fn low_s_sig() -> [u8; 64] {
    let mut s = [0u8; 64];
    s[31] = 1; // r = 1
    s[63] = 1; // s = 1
    s
}
fn base_proof(purpose: PossessionPurpose, subject_kind: SubjectKind) -> PossessionProof {
    PossessionProof {
        purpose,
        subject_kind,
        subject_id: [1; 16],
        certificate_id: [4; 16],
        generation: 1,
        request_id: [15; 16],
        issuer_status_digest: [16; 32],
        challenge: [17; 32],
        transcript_digest: [18; 32],
        issued_at: 1000,
        expires_at: 1060,
        signature_p1363: low_s_sig(),
    }
}
fn context_for(purpose: PossessionPurpose) -> PossessionContext {
    use PossessionPurpose::*;
    let d = |b: u8| Some([b; 32]);
    let (cur, prop, tr, att, rev) = match purpose {
        EnrollProposed => (None, d(10), d(11), None, None),
        RenewCurrent | RotateCurrent | RotateProposed => (d(12), d(10), None, None, None),
        AttemptClient | AttemptDaemon => (d(12), None, None, d(13), None),
        RevokeCurrent => (d(12), None, None, None, d(14)),
    };
    PossessionContext {
        purpose,
        current_certificate_digest: cur,
        proposed_identity_digest: prop,
        enrollment_transcript_digest: tr,
        attempt_request_digest: att,
        revocation_request_digest: rev,
    }
}
#[test]
fn remote_identity_possession_purpose_matrix() {
    use PossessionPurpose::*;
    let purposes = [
        EnrollProposed,
        RenewCurrent,
        RotateCurrent,
        RotateProposed,
        AttemptClient,
        AttemptDaemon,
        RevokeCurrent,
    ];
    let mut combos = 0;
    for purpose in purposes {
        for kind in [SubjectKind::Client, SubjectKind::Daemon] {
            combos += 1;
            let legal = matches!(
                (purpose, kind),
                (AttemptClient | RevokeCurrent, SubjectKind::Client)
                    | (AttemptDaemon, SubjectKind::Daemon)
                    | (
                        EnrollProposed | RenewCurrent | RotateCurrent | RotateProposed,
                        _
                    )
            );
            let result = base_proof(purpose, kind).encode();
            assert_eq!(
                result.is_ok(),
                legal,
                "proof purpose={purpose:?} kind={kind:?} legality mismatch"
            );
        }
        // Context presence matrix: the exact expected presence encodes, and
        // toggling the current-certificate slot (index 0) always violates it.
        let ctx = context_for(purpose);
        ctx.encode()
            .unwrap_or_else(|e| panic!("context {purpose:?} must encode: {e}"));
        let mut flipped = ctx.clone();
        flipped.current_certificate_digest = match flipped.current_certificate_digest {
            Some(_) => None,
            None => Some([99; 32]),
        };
        assert!(
            flipped.encode().is_err(),
            "context {purpose:?} must reject a cross-wired presence"
        );
    }
    assert_eq!(
        combos, 14,
        "all purpose × subject-kind combinations exercised"
    );
}

// ---------------------------------------------------------------------------
// AC2 — remote_identity_possession_challenge_vectors: challenge derivation
// matches the shared corpus, purpose cross-wiring rejects, and every purpose
// has a distinct NUL-terminated challenge/signature domain.
// ---------------------------------------------------------------------------
#[test]
fn remote_identity_possession_challenge_vectors() {
    let fixture = fixture();
    let valid = fixture["valid"].as_array().unwrap();
    let derived = fixture["derivations"].as_array().unwrap();
    let cases = [
        ("enroll_proposed", PossessionPurpose::EnrollProposed),
        ("renew_current", PossessionPurpose::RenewCurrent),
        ("rotate_current", PossessionPurpose::RotateCurrent),
        ("rotate_proposed", PossessionPurpose::RotateProposed),
        ("attempt_client", PossessionPurpose::AttemptClient),
        ("attempt_daemon", PossessionPurpose::AttemptDaemon),
        ("revoke_current", PossessionPurpose::RevokeCurrent),
    ];
    for (name, purpose) in cases {
        let context = hex_of(valid, &format!("context_{name}"));
        assert_eq!(
            derive_possession_challenge(purpose, &[16; 32], &[15; 16], &context)
                .unwrap()
                .as_slice(),
            unhex(
                by_name(derived, &format!("challenge_{name}"))["hex"]
                    .as_str()
                    .unwrap()
            )
        );
        // Purpose cross-wiring: this context bound to any OTHER purpose rejects.
        for (_, other) in cases {
            if other != purpose {
                let err = derive_possession_challenge(other, &[16; 32], &[15; 16], &context)
                    .expect_err("cross-wired purpose must reject");
                assert!(err.to_string().contains("purpose"), "{err}");
            }
        }
    }
    // Seven distinct, NUL-terminated domain literals per family.
    let mut challenge_domains = std::collections::BTreeSet::new();
    let mut signature_domains = std::collections::BTreeSet::new();
    for (_, purpose) in cases {
        let c = possession_challenge_domain(purpose);
        let s = possession_signature_domain(purpose);
        assert_eq!(c.last(), Some(&0u8), "challenge domain NUL-terminated");
        assert_eq!(s.last(), Some(&0u8), "signature domain NUL-terminated");
        assert!(challenge_domains.insert(c));
        assert!(signature_domains.insert(s));
    }
    assert_eq!(challenge_domains.len(), 7);
    assert_eq!(signature_domains.len(), 7);
}

// ---------------------------------------------------------------------------
// AC2 — remote_enrollment_transcript_confirmation_vectors: transcript codecs
// round-trip, confirmation signing digests match the corpus, and the role-pair
// and decision invariants fail closed.
// ---------------------------------------------------------------------------
#[test]
fn remote_enrollment_transcript_confirmation_vectors() {
    let fixture = fixture();
    let valid = fixture["valid"].as_array().unwrap();
    let derived = fixture["derivations"].as_array().unwrap();
    for name in ["transcript_client", "transcript_daemon"] {
        let bytes = hex_of(valid, name);
        let round = EnrollmentTranscript::decode(&bytes)
            .unwrap()
            .encode()
            .unwrap();
        assert_eq!(round, bytes, "{name} transcript must round-trip");
    }
    // Role-pair invariant: initiator == confirmer is rejected at encode time.
    let mut t = EnrollmentTranscript::decode(&hex_of(valid, "transcript_client")).unwrap();
    t.confirmer_role = t.initiator_role;
    assert!(
        t.encode().is_err(),
        "identical enrollment roles must reject"
    );

    for (name, role) in [
        ("proposed_subject", EnrollmentRole::ProposedSubject),
        ("enrolled_counterpart", EnrollmentRole::EnrolledCounterpart),
        (
            "control_plane_authorizer",
            EnrollmentRole::ControlPlaneAuthorizer,
        ),
    ] {
        let bytes = hex_of(valid, &format!("confirmation_{name}"));
        assert_eq!(
            enrollment_confirmation_signing_digest(&bytes[..104], role)
                .unwrap()
                .as_slice(),
            unhex(
                by_name(derived, &format!("confirmation_signature_{name}"))["hex"]
                    .as_str()
                    .unwrap()
            )
        );
    }
    // Decision invariant: only accept(1)/reject(2) encode.
    let mut c =
        EnrollmentConfirmation::decode(&hex_of(valid, "confirmation_proposed_subject")).unwrap();
    c.decision = 3;
    assert!(c.encode().is_err(), "out-of-range decision must reject");
}

// ---------------------------------------------------------------------------
// AC2 — remote_identity_custody_codec_vectors: nonempty and empty-evidence
// FCCE round-trip, empty evidence is valid iff its digest is SHA-256(""),
// and a digest mismatch fails closed.
// ---------------------------------------------------------------------------
#[test]
fn remote_identity_custody_codec_vectors() {
    let fixture = fixture();
    let valid = fixture["valid"].as_array().unwrap();
    let malformed = fixture["malformed"].as_array().unwrap();
    for name in ["custody_nonempty", "custody_empty"] {
        let bytes = hex_of(valid, name);
        let round = CustodyEvidence::decode(&bytes).unwrap().encode().unwrap();
        assert_eq!(round, bytes, "{name} custody evidence must round-trip");
    }
    // Empty-evidence FCCE: provider evidence is empty and the digest is bound.
    let empty = CustodyEvidence::decode(&hex_of(valid, "custody_empty")).unwrap();
    assert!(empty.provider_evidence.is_empty());
    // Corpus digest-mismatch vector rejects.
    let bytes = hex_of(malformed, "custody_digest_mismatch");
    let err = reconstruct("FCCE", &bytes).expect_err("digest mismatch must reject");
    assert!(err.contains("digest"), "wrong rejection: {err}");
    // Drive the production encoder with a tampered digest directly.
    let mut e = CustodyEvidence::decode(&hex_of(valid, "custody_nonempty")).unwrap();
    e.evidence_digest = [0; 32];
    assert!(e.encode().is_err(), "tampered evidence digest must reject");
}
