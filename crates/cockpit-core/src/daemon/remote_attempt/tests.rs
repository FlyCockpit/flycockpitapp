//! Tests for the attempt-grant verification ceremony, endpoint-proof gate, and
//! principal derivation. Grants and FCFP proofs are minted in-test with the
//! module's own canonical serializer and real ES256 signatures, so every
//! judgment is produced by the production `verify_attempt_grant` /
//! `EndpointProofGate::consume` / `construct_principal_from_grant` entry points.

use super::*;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};

const NOW: i64 = 1_700_000_000;

/// P-256 group order n, big-endian (for constructing high-S counterparts).
const N_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let d = a[i] as i16 - b[i] as i16 - borrow;
        if d < 0 {
            out[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            out[i] = d as u8;
            borrow = 0;
        }
    }
    out
}

fn keypair(seed: u8) -> (SigningKey, Es256PublicKey) {
    let sk = SigningKey::from_slice(&[seed | 0x01; 32]).expect("valid scalar");
    let vk = sk.verifying_key();
    let point = vk.to_encoded_point(false);
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(point.x().expect("x").as_slice());
    y.copy_from_slice(point.y().expect("y").as_slice());
    (sk, Es256PublicKey { x, y })
}

fn sign_low_s(sk: &SigningKey, msg: &[u8]) -> [u8; 64] {
    let sig: Signature = sk.sign(msg);
    let low = sig.normalize_s().unwrap_or(sig);
    let mut out = [0u8; 64];
    out.copy_from_slice(low.to_bytes().as_slice());
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// Grant minting helpers (test-only)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct TestGrantParams {
    schema_version: u8,
    iss: String,
    aud: String,
    tenant_id: [u8; 16],
    account_id: [u8; 16],
    instance_id: [u8; 16],
    logical_attachment_id: [u8; 16],
    child_attempt_id: [u8; 16],
    jti: [u8; 16],
    client: GrantDeviceIdentity,
    daemon: GrantDeviceIdentity,
    server_nonce: [u8; 32],
    service_version: u64,
    service_policy_digest: [u8; 32],
    policy_epoch: u64,
    policy_digest: [u8; 32],
    authority_epoch: u64,
    attachment_caps: Vec<u8>,
    projects: Vec<([u8; 16], Vec<u8>)>,
    ceiling_digest_override: Option<[u8; 32]>,
    tenant_authorization_digest: Option<[u8; 32]>,
    authorized_transports: u8,
    compatible_tuple_ids: Vec<u16>,
    iat: i64,
    nbf: i64,
    exp: i64,
}

fn identity(device: u8, cert: u8, generation: u64, thumb: u8) -> GrantDeviceIdentity {
    GrantDeviceIdentity {
        device_id: [device; 16],
        certificate_id: [cert; 16],
        generation,
        p256_thumbprint: [thumb; 32],
    }
}

fn default_params() -> TestGrantParams {
    TestGrantParams {
        schema_version: GRANT_SCHEMA_VERSION,
        iss: "issuer-1".into(),
        aud: "audience-1".into(),
        tenant_id: [1; 16],
        account_id: [2; 16],
        instance_id: [3; 16],
        logical_attachment_id: [4; 16],
        child_attempt_id: [5; 16],
        jti: [6; 16],
        client: identity(7, 8, 1, 0xaa),
        daemon: identity(9, 10, 1, 0xbb),
        server_nonce: [0xcc; 32],
        service_version: 1,
        service_policy_digest: [0xdd; 32],
        policy_epoch: 1,
        policy_digest: [0xee; 32],
        authority_epoch: 1,
        // sorted-ascending attachment ordinals: AttachmentRead=1, SessionCreate=3
        attachment_caps: vec![1, 3],
        // one project, sorted-ascending capability ordinals
        projects: vec![([0x0a; 16], vec![1, 2])],
        ceiling_digest_override: None,
        tenant_authorization_digest: None,
        authorized_transports: 0x03,
        compatible_tuple_ids: vec![1],
        iat: NOW,
        nbf: NOW,
        exp: NOW + 300,
    }
}

impl TestGrantParams {
    fn ceiling(&self) -> RemotePermissionCeilingV1 {
        RemotePermissionCeilingV1 {
            attachment_capabilities: self
                .attachment_caps
                .iter()
                .map(|o| RemoteAttachmentCapabilityV1::from_ordinal(*o).unwrap())
                .collect(),
            projects: self
                .projects
                .iter()
                .map(|(id, caps)| {
                    (
                        *id,
                        caps.iter()
                            .map(|o| RemoteProjectCapabilityV1::from_ordinal(*o).unwrap())
                            .collect(),
                    )
                })
                .collect(),
        }
    }

    fn ceiling_digest(&self) -> [u8; 32] {
        if let Some(d) = self.ceiling_digest_override {
            return d;
        }
        *permission_ceiling_digest(&self.ceiling())
            .unwrap()
            .as_bytes()
    }

    fn identity_value(id: &GrantDeviceIdentity) -> Value {
        json!({
            "deviceId": account_alias(&id.device_id),
            "certificateId": account_alias(&id.certificate_id),
            "generation": id.generation.to_string(),
            "p256Thumbprint": hex_lower(&id.p256_thumbprint),
        })
    }

    fn payload_value(&self) -> Value {
        let projects: Vec<Value> = self
            .projects
            .iter()
            .map(|(id, caps)| {
                json!({
                    "projectId": hex_lower(id),
                    "capabilities": caps,
                })
            })
            .collect();
        json!({
            "schemaVersion": self.schema_version,
            "iss": self.iss,
            "aud": self.aud,
            "tenantId": account_alias(&self.tenant_id),
            "accountId": account_alias(&self.account_id),
            "instanceId": account_alias(&self.instance_id),
            "logicalAttachmentId": account_alias(&self.logical_attachment_id),
            "childAttemptId": account_alias(&self.child_attempt_id),
            "jti": account_alias(&self.jti),
            "client": Self::identity_value(&self.client),
            "daemon": Self::identity_value(&self.daemon),
            "serverNonce": hex_lower(&self.server_nonce),
            "serviceVersion": self.service_version.to_string(),
            "servicePolicyDigest": hex_lower(&self.service_policy_digest),
            "policyEpoch": self.policy_epoch.to_string(),
            "policyDigest": hex_lower(&self.policy_digest),
            "authorityEpoch": self.authority_epoch.to_string(),
            "attachmentCapabilities": self.attachment_caps,
            "projectCapabilities": projects,
            "permissionCeilingDigest": hex_lower(&self.ceiling_digest()),
            "authorizedTransports": self.authorized_transports,
            "compatibleTupleIds": self.compatible_tuple_ids,
            "tenantAuthorizationDigest": self.tenant_authorization_digest.map(|d| hex_lower(&d)),
            "iat": self.iat.to_string(),
            "nbf": self.nbf.to_string(),
            "exp": self.exp.to_string(),
        })
    }

    fn expectations(&self) -> GrantVerificationExpectations {
        GrantVerificationExpectations {
            issuer: self.iss.clone(),
            audience: self.aud.clone(),
            tenant_id: self.tenant_id,
            account_id: self.account_id,
            instance_id: self.instance_id,
            logical_attachment_id: self.logical_attachment_id,
            child_attempt_id: self.child_attempt_id,
            client: self.client.clone(),
            daemon: self.daemon.clone(),
            server_nonce: self.server_nonce,
            service_version: self.service_version,
            service_policy_digest: self.service_policy_digest,
            policy_epoch: self.policy_epoch,
            policy_digest: self.policy_digest,
            authority_epoch: self.authority_epoch,
            tenant_authorization: match self.tenant_authorization_digest {
                None => TenantAuthorizationExpectation::ControlPlane,
                Some(d) => TenantAuthorizationExpectation::Enterprise(d),
            },
        }
    }

    fn mint(&self, kid: &str, sk: &SigningKey) -> Vec<u8> {
        self.mint_with_extra(kid, sk, &[])
    }

    /// Mint a signed compact JWS, optionally injecting extra (non-canonical
    /// schema) claim members to exercise unknown-claim rejection.
    fn mint_with_extra(&self, kid: &str, sk: &SigningKey, extra: &[(&str, Value)]) -> Vec<u8> {
        let header = json!({"alg": "ES256", "kid": kid, "typ": GRANT_JWS_TYP});
        let mut payload = self.payload_value();
        if !extra.is_empty() {
            let obj = payload.as_object_mut().unwrap();
            for (k, v) in extra {
                obj.insert((*k).to_string(), v.clone());
            }
        }
        let mut hbuf = String::new();
        canonical_json(&header, &mut hbuf).unwrap();
        let mut pbuf = String::new();
        canonical_json(&payload, &mut pbuf).unwrap();
        let header_seg = URL_SAFE_NO_PAD.encode(hbuf.as_bytes());
        let payload_seg = URL_SAFE_NO_PAD.encode(pbuf.as_bytes());
        let signing_input = format!("{header_seg}.{payload_seg}");
        let sig = sign_low_s(sk, signing_input.as_bytes());
        let sig_seg = URL_SAFE_NO_PAD.encode(sig);
        format!("{header_seg}.{payload_seg}.{sig_seg}").into_bytes()
    }
}

fn authority() -> (SigningKey, AttemptGrantKeyRing) {
    let (sk, pk) = keypair(0x10);
    let ring = AttemptGrantKeyRing::new().with_key("k1", pk);
    (sk, ring)
}

// ---------------------------------------------------------------------------
// FCFP proof minting
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn sign_fcfp(
    role: u8,
    transport: u8,
    grant_digest: &[u8; 32],
    child: &[u8; 16],
    epoch: &[u8; 16],
    seq: u64,
    negotiation: &[u8; 32],
    binding: &[u8; 96],
    cert_id: &[u8; 16],
    cert_gen: u64,
    jti: &[u8; 16],
    sk: &SigningKey,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(313);
    b.extend_from_slice(b"FCFP");
    b.push(1);
    b.push(role);
    b.push(transport);
    b.extend_from_slice(child);
    b.extend_from_slice(epoch);
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(grant_digest);
    b.extend_from_slice(negotiation);
    b.extend_from_slice(&96u16.to_be_bytes());
    b.extend_from_slice(binding);
    b.extend_from_slice(jti);
    b.extend_from_slice(cert_id);
    b.extend_from_slice(&cert_gen.to_be_bytes());
    let hash = fcfp_signature_hash(&b[0..FCFP_SIGNED_LEN]);
    let sig = sign_low_s(sk, &hash);
    b.extend_from_slice(&sig);
    b
}

struct GateFixture {
    client_bytes: Vec<u8>,
    daemon_bytes: Vec<u8>,
    expectations: FinalProofExpectations,
}

/// Build a matching client/daemon FCFP pair plus expectations for a grant.
fn gate_fixture(params: &TestGrantParams, grant_digest: [u8; 32]) -> GateFixture {
    let (client_sk, client_pk) = keypair(0x20);
    let (daemon_sk, daemon_pk) = keypair(0x30);
    let child = params.child_attempt_id;
    let epoch = [8u8; 16];
    let negotiation = [0x11u8; 32];
    let binding = [0x22u8; 96];
    let transport = 1u8;
    let client_bytes = sign_fcfp(
        1,
        transport,
        &grant_digest,
        &child,
        &epoch,
        1,
        &negotiation,
        &binding,
        &params.client.certificate_id,
        params.client.generation,
        &[0x91; 16],
        &client_sk,
    );
    let daemon_bytes = sign_fcfp(
        2,
        transport,
        &grant_digest,
        &child,
        &epoch,
        1,
        &negotiation,
        &binding,
        &params.daemon.certificate_id,
        params.daemon.generation,
        &[0x92; 16],
        &daemon_sk,
    );
    let expectations = FinalProofExpectations {
        grant_digest,
        child_attempt_id: child,
        transport_tag: transport,
        authorized_transports: params.authorized_transports,
        transport_epoch: epoch,
        negotiation_digest: negotiation,
        transport_binding: binding,
        client_key: client_pk,
        daemon_key: daemon_pk,
        client_certificate_id: params.client.certificate_id,
        client_certificate_generation: params.client.generation,
        daemon_certificate_id: params.daemon.certificate_id,
        daemon_certificate_generation: params.daemon.generation,
    };
    GateFixture {
        client_bytes,
        daemon_bytes,
        expectations,
    }
}

/// A fully verified grant + a matching gate, the common setup for principal and
/// FCFP tests.
fn verified_grant_and_gate() -> (VerifiedAttemptGrant, EndpointProofGate) {
    let (sk, ring) = authority();
    let params = default_params();
    let compact = params.mint("k1", &sk);
    let verified = verify_attempt_grant(&compact, &ring, &params.expectations(), NOW)
        .expect("valid grant verifies");
    let fx = gate_fixture(&params, verified.grant_digest());
    let gate = EndpointProofGate::consume(&fx.client_bytes, &fx.daemon_bytes, &fx.expectations)
        .expect("gate consumes matching proofs");
    (verified, gate)
}

// ===========================================================================
// AC-3: grant signature verification (cheap-before-crypto order)
// ===========================================================================

#[test]
fn remote_attempt_grant_signature_verification() {
    let (sk, ring) = authority();
    let params = default_params();
    let exp = params.expectations();
    let compact = params.mint("k1", &sk);

    // A fixture-signed grant verifies.
    verify_attempt_grant(&compact, &ring, &exp, NOW).expect("valid grant verifies");

    let s = String::from_utf8(compact.clone()).unwrap();
    let mut segs = s.split('.');
    let header_seg = segs.next().unwrap().to_string();
    let payload_seg = segs.next().unwrap().to_string();
    let sig_seg = segs.next().unwrap().to_string();

    // Oversize — fails before any decode (size is checked first).
    let oversize = vec![b'a'; GRANT_MAX_BYTES + 1];
    assert!(matches!(
        verify_attempt_grant(&oversize, &ring, &exp, NOW),
        Err(AttemptGrantError::Jws(_))
    ));

    // Four segments.
    let four = format!("{header_seg}.{payload_seg}.{sig_seg}.extra");
    assert!(matches!(
        verify_attempt_grant(four.as_bytes(), &ring, &exp, NOW),
        Err(AttemptGrantError::Jws(_))
    ));

    // Padded base64url (append '=' to header segment).
    let padded = format!("{header_seg}=.{payload_seg}.{sig_seg}");
    assert!(matches!(
        verify_attempt_grant(padded.as_bytes(), &ring, &exp, NOW),
        Err(AttemptGrantError::Jws(_))
    ));

    // Wrong alg.
    let bad_header = json!({"alg": "RS256", "kid": "k1", "typ": GRANT_JWS_TYP});
    let mut hbuf = String::new();
    canonical_json(&bad_header, &mut hbuf).unwrap();
    let bad_header_seg = URL_SAFE_NO_PAD.encode(hbuf.as_bytes());
    let wrong_alg = format!("{bad_header_seg}.{payload_seg}.{sig_seg}");
    assert!(matches!(
        verify_attempt_grant(wrong_alg.as_bytes(), &ring, &exp, NOW),
        Err(AttemptGrantError::Jws(_))
    ));

    // Wrong typ.
    let bad_typ = json!({"alg": "ES256", "kid": "k1", "typ": "JWT"});
    let mut tbuf = String::new();
    canonical_json(&bad_typ, &mut tbuf).unwrap();
    let bad_typ_seg = URL_SAFE_NO_PAD.encode(tbuf.as_bytes());
    let wrong_typ = format!("{bad_typ_seg}.{payload_seg}.{sig_seg}");
    assert!(matches!(
        verify_attempt_grant(wrong_typ.as_bytes(), &ring, &exp, NOW),
        Err(AttemptGrantError::Jws(_))
    ));

    // Extra header member (crit/cty).
    let extra_header = json!({"alg": "ES256", "cty": "json", "kid": "k1", "typ": GRANT_JWS_TYP});
    let mut ebuf = String::new();
    canonical_json(&extra_header, &mut ebuf).unwrap();
    let extra_header_seg = URL_SAFE_NO_PAD.encode(ebuf.as_bytes());
    let extra = format!("{extra_header_seg}.{payload_seg}.{sig_seg}");
    assert!(matches!(
        verify_attempt_grant(extra.as_bytes(), &ring, &exp, NOW),
        Err(AttemptGrantError::Jws(_))
    ));

    // Non-canonical payload (inject a space) — fails at canonicality (step 4),
    // before signature.
    let canonical_payload = URL_SAFE_NO_PAD.decode(payload_seg.as_bytes()).unwrap();
    let mut noncanon = canonical_payload.clone();
    // insert a space just after the opening brace
    noncanon.insert(1, b' ');
    let noncanon_seg = URL_SAFE_NO_PAD.encode(&noncanon);
    let noncanon_jws = format!("{header_seg}.{noncanon_seg}.{sig_seg}");
    assert!(matches!(
        verify_attempt_grant(noncanon_jws.as_bytes(), &ring, &exp, NOW),
        Err(AttemptGrantError::Jws(_))
    ));

    // Duplicate member — raw longer than canonical re-encode.
    let payload_str = String::from_utf8(canonical_payload.clone()).unwrap();
    let dup_str = payload_str.replacen(
        "\"iss\":\"issuer-1\",",
        "\"iss\":\"issuer-1\",\"iss\":\"issuer-1\",",
        1,
    );
    assert_ne!(dup_str, payload_str);
    let dup_seg = URL_SAFE_NO_PAD.encode(dup_str.as_bytes());
    let dup_jws = format!("{header_seg}.{dup_seg}.{sig_seg}");
    assert!(matches!(
        verify_attempt_grant(dup_jws.as_bytes(), &ring, &exp, NOW),
        Err(AttemptGrantError::Jws(_))
    ));

    // Unknown claim `role` (canonical bytes, rejected at claim typing).
    let role_jws = params.mint_with_extra("k1", &sk, &[("role", json!("client"))]);
    assert!(matches!(
        verify_attempt_grant(&role_jws, &ring, &exp, NOW),
        Err(AttemptGrantError::Claims(_))
    ));

    // Unknown claim `permissionCapabilities` (flat list).
    let flat_jws = params.mint_with_extra("k1", &sk, &[("permissionCapabilities", json!([1, 2]))]);
    assert!(matches!(
        verify_attempt_grant(&flat_jws, &ring, &exp, NOW),
        Err(AttemptGrantError::Claims(_))
    ));

    // Unknown kid — fails closed at signature-key lookup.
    let unknown_ring = AttemptGrantKeyRing::new().with_key("other", keypair(0x10).1);
    assert!(matches!(
        verify_attempt_grant(&compact, &unknown_ring, &exp, NOW),
        Err(AttemptGrantError::Signature(_))
    ));

    // Wrong signing key — signature verification fails.
    let (wrong_sk, _) = keypair(0x40);
    let wrong_sig_jws = params.mint("k1", &wrong_sk);
    assert!(matches!(
        verify_attempt_grant(&wrong_sig_jws, &ring, &exp, NOW),
        Err(AttemptGrantError::Signature(_))
    ));

    // High-S signature — rejected by low-S enforcement.
    let raw_sig = URL_SAFE_NO_PAD.decode(sig_seg.as_bytes()).unwrap();
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&raw_sig[32..64]);
    let high_s = sub_be(&N_BE, &s_bytes);
    let mut high = raw_sig.clone();
    high[32..64].copy_from_slice(&high_s);
    let high_seg = URL_SAFE_NO_PAD.encode(&high);
    let high_jws = format!("{header_seg}.{payload_seg}.{high_seg}");
    assert!(matches!(
        verify_attempt_grant(high_jws.as_bytes(), &ring, &exp, NOW),
        Err(AttemptGrantError::Signature(_))
    ));

    // Every single-byte mutation of the signed compact bytes fails.
    for i in 0..compact.len() {
        // Skip the two '.' delimiters (mutating them just changes structure,
        // still an error, but keep the assertion focused on content bytes).
        if compact[i] == b'.' {
            continue;
        }
        let mut mutated = compact.clone();
        mutated[i] = mutated[i].wrapping_add(1);
        // A base64url alphabet wrap could rarely produce an invalid char; either
        // way the result must not verify.
        assert!(
            verify_attempt_grant(&mutated, &ring, &exp, NOW).is_err(),
            "single-byte mutation at {i} must fail"
        );
    }
}

// ===========================================================================
// AC-4: claim binding matrix — every single-claim mutation FAILS
// ===========================================================================

#[test]
fn remote_attempt_grant_claim_binding_matrix() {
    let (sk, ring) = authority();
    let base = default_params();
    let exp = base.expectations();

    // Base grant verifies.
    let ok = base.mint("k1", &sk);
    verify_attempt_grant(&ok, &ring, &exp, NOW).expect("base grant verifies");

    // Helper: mutate params, mint, and assert verification FAILS against the
    // unmutated expectations.
    let fails = |mutate: &dyn Fn(&mut TestGrantParams), label: &str| {
        let mut p = base.clone();
        mutate(&mut p);
        let compact = p.mint("k1", &sk);
        let r = verify_attempt_grant(&compact, &ring, &exp, NOW);
        assert!(r.is_err(), "mutation `{label}` must fail, got {r:?}");
    };

    // Identity claims (client + daemon device/certificate/generation/thumbprint).
    fails(&|p| p.client.device_id = [99; 16], "client.deviceId");
    fails(
        &|p| p.client.certificate_id = [99; 16],
        "client.certificateId",
    );
    fails(&|p| p.client.generation = 99, "client.generation");
    fails(
        &|p| p.client.p256_thumbprint = [0x99; 32],
        "client.p256Thumbprint",
    );
    fails(&|p| p.daemon.device_id = [99; 16], "daemon.deviceId");
    fails(
        &|p| p.daemon.certificate_id = [99; 16],
        "daemon.certificateId",
    );
    fails(&|p| p.daemon.generation = 99, "daemon.generation");
    fails(
        &|p| p.daemon.p256_thumbprint = [0x99; 32],
        "daemon.p256Thumbprint",
    );

    // Tenant / account / instance / attachment / child ids.
    fails(&|p| p.tenant_id = [99; 16], "tenantId");
    fails(&|p| p.account_id = [99; 16], "accountId");
    fails(&|p| p.instance_id = [99; 16], "instanceId");
    fails(
        &|p| p.logical_attachment_id = [99; 16],
        "logicalAttachmentId",
    );
    fails(&|p| p.child_attempt_id = [99; 16], "childAttemptId");

    // Issuer / audience.
    fails(&|p| p.iss = "unexpected-issuer".into(), "iss");
    fails(&|p| p.aud = "unexpected-audience".into(), "aud");

    // Server nonce, service version, service-policy digest.
    fails(&|p| p.server_nonce = [0x99; 32], "serverNonce");
    fails(&|p| p.service_version = 99, "serviceVersion");
    fails(
        &|p| p.service_policy_digest = [0x99; 32],
        "servicePolicyDigest",
    );

    // Policy epoch / digest, authority epoch.
    fails(&|p| p.policy_epoch = 99, "policyEpoch");
    fails(&|p| p.policy_digest = [0x99; 32], "policyDigest");
    fails(&|p| p.authority_epoch = 99, "authorityEpoch");

    // Tenant-authorization digest: present when control-plane expected.
    fails(
        &|p| p.tenant_authorization_digest = Some([0xf0; 32]),
        "tenantAuthorizationDigest present-when-control-plane",
    );

    // Transport bits, tuple set, ceiling digest, schema version.
    fails(&|p| p.authorized_transports = 0, "transportBits zero");
    fails(&|p| p.authorized_transports = 4, "transportBits four");
    fails(&|p| p.compatible_tuple_ids = vec![], "tupleSet empty");
    fails(
        &|p| p.compatible_tuple_ids = vec![1, 1],
        "tupleSet duplicate",
    );
    fails(
        &|p| p.ceiling_digest_override = Some([0; 32]),
        "permissionCeilingDigest mismatch",
    );
    fails(&|p| p.schema_version = 2, "schemaVersion");

    // Time-ordering violations.
    fails(&|p| p.exp = p.iat - 1, "exp before iat");
    fails(&|p| p.exp = p.iat + 301, "lifetime over cap");
    fails(
        &|p| {
            p.iat = NOW - 400;
            p.nbf = NOW - 400;
            p.exp = NOW - 100;
        },
        "expired",
    );
    fails(
        &|p| {
            p.iat = NOW + 120;
            p.nbf = NOW + 120;
            p.exp = NOW + 420;
        },
        "not yet valid beyond skew",
    );

    // Enterprise expectation with a wrong tenant digest.
    let mut ent_params = base.clone();
    ent_params.tenant_authorization_digest = Some([0xab; 32]);
    let mut ent_exp = base.expectations();
    ent_exp.tenant_authorization = TenantAuthorizationExpectation::Enterprise([0xcd; 32]);
    let ent = ent_params.mint("k1", &sk);
    assert!(verify_attempt_grant(&ent, &ring, &ent_exp, NOW).is_err());
    // The matching enterprise digest verifies.
    let mut ent_ok_exp = base.expectations();
    ent_ok_exp.tenant_authorization = TenantAuthorizationExpectation::Enterprise([0xab; 32]);
    verify_attempt_grant(&ent, &ring, &ent_ok_exp, NOW)
        .expect("matching enterprise digest verifies");

    // Companion: any byte mutation of the signed compact fails signature.
    let signed = base.mint("k1", &sk);
    let mut m = signed.clone();
    let last = m.len() - 1;
    m[last] = m[last].wrapping_add(1);
    assert!(verify_attempt_grant(&m, &ring, &exp, NOW).is_err());
}

// ===========================================================================
// AC-6: principal derivation from the verified ceiling (never Owner)
// ===========================================================================

#[test]
fn remote_attempt_principal_construction() {
    let (verified, gate) = verified_grant_and_gate();
    let params = default_params();

    let principal = construct_principal_from_grant(&verified, &gate).expect("principal derives");

    // Never Owner.
    assert!(!principal.is_owner());

    // Carries exactly the grant's ceiling.
    let auth = principal
        .attempt_grant_authorization()
        .expect("attempt-grant principal");
    assert_eq!(
        auth.ceiling.attachment_capabilities,
        verified.permission_ceiling().attachment_capabilities
    );
    assert_eq!(
        auth.ceiling.projects,
        verified.permission_ceiling().projects
    );

    // user_id equals the account-id alias.
    let expected_alias = account_alias(&params.account_id);
    assert_eq!(
        principal.tag().unwrap(),
        format!("flycockpit:{expected_alias}")
    );
    assert_eq!(auth.account_alias, expected_alias);

    // Device binding is sourced from verified grant claims.
    assert_eq!(
        auth.device_binding.client_device_id,
        params.client.device_id
    );
    assert_eq!(
        auth.device_binding.logical_attachment_id,
        params.logical_attachment_id
    );
    assert_eq!(
        auth.device_binding.child_attempt_id,
        params.child_attempt_id
    );

    // A gate binding a different grant digest yields Err.
    let other_digest = [0xab; 32];
    let fx = gate_fixture(&params, other_digest);
    let other_gate =
        EndpointProofGate::consume(&fx.client_bytes, &fx.daemon_bytes, &fx.expectations).unwrap();
    assert!(construct_principal_from_grant(&verified, &other_gate).is_err());

    // A gate binding a different child attempt id yields Err.
    let mut child_params = default_params();
    child_params.child_attempt_id = [77; 16];
    let child_fx = gate_fixture(&child_params, verified.grant_digest());
    let child_gate = EndpointProofGate::consume(
        &child_fx.client_bytes,
        &child_fx.daemon_bytes,
        &child_fx.expectations,
    )
    .unwrap();
    assert!(construct_principal_from_grant(&verified, &child_gate).is_err());
}

// ===========================================================================
// AC-10: endpoint-proof gate binds expectations and verifies FCFP signatures
// ===========================================================================

#[test]
fn remote_attempt_endpoint_proof_gate() {
    let (sk, ring) = authority();
    let params = default_params();
    let compact = params.mint("k1", &sk);
    let verified = verify_attempt_grant(&compact, &ring, &params.expectations(), NOW).unwrap();
    let grant_digest = verified.grant_digest();

    let fx = gate_fixture(&params, grant_digest);
    let gate =
        EndpointProofGate::consume(&fx.client_bytes, &fx.daemon_bytes, &fx.expectations).unwrap();
    assert_eq!(gate.client_proof.role, 1);
    assert_eq!(gate.daemon_proof.role, 2);
    assert_eq!(gate.grant_digest(), grant_digest);

    // transport_epoch returns the agreement bytes 17..33 by value.
    assert_eq!(gate.transport_epoch(), [8u8; 16]);

    // Same-byte replay returns the identical set digest.
    let gate2 =
        EndpointProofGate::consume(&fx.client_bytes, &fx.daemon_bytes, &fx.expectations).unwrap();
    assert_eq!(gate.set_digest, gate2.set_digest);

    // A same-width signature mutation fails FCFP verification.
    let mut bad_sig = fx.client_bytes.clone();
    let last = bad_sig.len() - 1;
    bad_sig[last] ^= 0x01;
    assert!(EndpointProofGate::consume(&bad_sig, &fx.daemon_bytes, &fx.expectations).is_err());

    // Certificate id mismatch against the verified grant fails.
    let mut wrong_cert_exp = fx.expectations.clone();
    wrong_cert_exp.client_certificate_id = [0x55; 16];
    assert!(
        EndpointProofGate::consume(&fx.client_bytes, &fx.daemon_bytes, &wrong_cert_exp).is_err()
    );

    // Certificate generation mismatch fails.
    let mut wrong_gen_exp = fx.expectations.clone();
    wrong_gen_exp.client_certificate_generation = 999;
    assert!(
        EndpointProofGate::consume(&fx.client_bytes, &fx.daemon_bytes, &wrong_gen_exp).is_err()
    );

    // A transport tag not authorized by the grant fails: grant authorizes only
    // webrtc (0x01), proofs claim websocket-data (2).
    let mut webrtc_only = default_params();
    webrtc_only.authorized_transports = 0x01;
    let compact2 = webrtc_only.mint("k1", &sk);
    let verified2 =
        verify_attempt_grant(&compact2, &ring, &webrtc_only.expectations(), NOW).unwrap();
    let mut ws_fx = gate_fixture(&webrtc_only, verified2.grant_digest());
    // Rebuild proofs with transport tag 2 (websocket-data).
    let (client_sk, client_pk) = keypair(0x20);
    let (daemon_sk, daemon_pk) = keypair(0x30);
    let child = webrtc_only.child_attempt_id;
    let epoch = [8u8; 16];
    let neg = [0x11u8; 32];
    let bind = [0x22u8; 96];
    ws_fx.client_bytes = sign_fcfp(
        1,
        2,
        &verified2.grant_digest(),
        &child,
        &epoch,
        1,
        &neg,
        &bind,
        &webrtc_only.client.certificate_id,
        1,
        &[0x91; 16],
        &client_sk,
    );
    ws_fx.daemon_bytes = sign_fcfp(
        2,
        2,
        &verified2.grant_digest(),
        &child,
        &epoch,
        1,
        &neg,
        &bind,
        &webrtc_only.daemon.certificate_id,
        1,
        &[0x92; 16],
        &daemon_sk,
    );
    ws_fx.expectations.client_key = client_pk;
    ws_fx.expectations.daemon_key = daemon_pk;
    ws_fx.expectations.transport_tag = 2;
    ws_fx.expectations.authorized_transports = 0x01;
    assert!(
        EndpointProofGate::consume(
            &ws_fx.client_bytes,
            &ws_fx.daemon_bytes,
            &ws_fx.expectations
        )
        .is_err(),
        "transport tag not authorized by grant must fail"
    );

    // Role swap fails (client role 2 / daemon role 1).
    let swap_client = sign_fcfp(
        2,
        1,
        &grant_digest,
        &params.child_attempt_id,
        &[8u8; 16],
        1,
        &[0x11u8; 32],
        &[0x22u8; 96],
        &params.client.certificate_id,
        1,
        &[0x91; 16],
        &keypair(0x20).0,
    );
    assert!(EndpointProofGate::consume(&swap_client, &fx.daemon_bytes, &fx.expectations).is_err());
}

// ===========================================================================
// AC-11: transport-neutral binding suites (no Noise/WebRTC imports)
// ===========================================================================

fn binding_substitution_matrix(transport_tag: u8, binding_seed: u8, negotiation_seed: u8) {
    let (sk, ring) = authority();
    let mut params = default_params();
    params.authorized_transports = 0x03;
    let compact = params.mint("k1", &sk);
    let verified = verify_attempt_grant(&compact, &ring, &params.expectations(), NOW).unwrap();
    let grant_digest = verified.grant_digest();

    let (client_sk, client_pk) = keypair(0x20);
    let (daemon_sk, daemon_pk) = keypair(0x30);
    let child = params.child_attempt_id;
    let epoch = [0x44u8; 16];
    let negotiation = [negotiation_seed; 32];
    let binding = [binding_seed; 96];

    let build = |neg: &[u8; 32], bind: &[u8; 96], tag: u8| {
        let c = sign_fcfp(
            1,
            tag,
            &grant_digest,
            &child,
            &epoch,
            1,
            neg,
            bind,
            &params.client.certificate_id,
            1,
            &[0x91; 16],
            &client_sk,
        );
        let d = sign_fcfp(
            2,
            tag,
            &grant_digest,
            &child,
            &epoch,
            1,
            neg,
            bind,
            &params.daemon.certificate_id,
            1,
            &[0x92; 16],
            &daemon_sk,
        );
        (c, d)
    };

    let expectations = FinalProofExpectations {
        grant_digest,
        child_attempt_id: child,
        transport_tag,
        authorized_transports: 0x03,
        transport_epoch: epoch,
        negotiation_digest: negotiation,
        transport_binding: binding,
        client_key: client_pk,
        daemon_key: daemon_pk,
        client_certificate_id: params.client.certificate_id,
        client_certificate_generation: 1,
        daemon_certificate_id: params.daemon.certificate_id,
        daemon_certificate_generation: 1,
    };

    // Matching case passes.
    let (c, d) = build(&negotiation, &binding, transport_tag);
    EndpointProofGate::consume(&c, &d, &expectations).expect("matching binding passes");

    // Substituting the binding fails.
    let (c2, d2) = build(&negotiation, &[binding_seed ^ 0xff; 96], transport_tag);
    assert!(EndpointProofGate::consume(&c2, &d2, &expectations).is_err());

    // Substituting the negotiation digest (version substitution) fails.
    let (c3, d3) = build(&[negotiation_seed ^ 0xff; 32], &binding, transport_tag);
    assert!(EndpointProofGate::consume(&c3, &d3, &expectations).is_err());

    // Substituting the transport tag fails (proofs carry the other transport).
    let other_tag = if transport_tag == 1 { 2 } else { 1 };
    let (c4, d4) = build(&negotiation, &binding, other_tag);
    assert!(EndpointProofGate::consume(&c4, &d4, &expectations).is_err());
}

#[test]
fn remote_attempt_webrtc_fingerprint_binding() {
    // WebRTC-tagged binding representing DTLS-fingerprint/offer-answer material.
    binding_substitution_matrix(1, 0xd1, 0xe1);
}

#[test]
fn remote_attempt_noise_transcript_binding() {
    // Websocket-data/Noise-tagged binding representing prologue/handshake
    // transcript material, including version substitution via negotiation digest.
    binding_substitution_matrix(2, 0xb0, 0xf2);
}

// ===========================================================================
// AC-12: single-outcome 512-byte cap
// ===========================================================================

#[test]
fn remote_attempt_permission_ceiling() {
    // 16 projects x 15 caps + 13 attachment ordinals = 528 bytes -> Err.
    let mut over_projects = Vec::new();
    for i in 0..16u8 {
        let mut pid = [0u8; 16];
        pid[15] = i + 1;
        over_projects.push((pid, RemoteProjectCapabilityV1::all().to_vec()));
    }
    let over = RemotePermissionCeilingV1 {
        attachment_capabilities: RemoteAttachmentCapabilityV1::all().to_vec(),
        projects: over_projects,
    };
    assert!(
        over.encode().is_err(),
        "528-byte maximal ceiling must exceed the 512 cap"
    );

    // 15 projects x 15 caps + 13 attachment ordinals = 496 bytes -> Ok.
    let mut fit_projects = Vec::new();
    for i in 0..15u8 {
        let mut pid = [0u8; 16];
        pid[15] = i + 1;
        fit_projects.push((pid, RemoteProjectCapabilityV1::all().to_vec()));
    }
    let fit = RemotePermissionCeilingV1 {
        attachment_capabilities: RemoteAttachmentCapabilityV1::all().to_vec(),
        projects: fit_projects,
    };
    let bytes = fit.encode().expect("496-byte ceiling fits");
    assert!(bytes.len() <= 512);
    assert_eq!(bytes.len(), 496);

    // The grant carries the exact helper-produced digest, and a wrong digest
    // fails validation (behavioral coverage of the digest helper on the path).
    let params = default_params();
    let (sk, ring) = authority();
    let compact = params.mint("k1", &sk);
    verify_attempt_grant(&compact, &ring, &params.expectations(), NOW).expect("valid ceiling");

    let mut wrong = default_params();
    wrong.ceiling_digest_override = Some([0; 32]);
    let compact_wrong = wrong.mint("k1", &sk);
    assert!(matches!(
        verify_attempt_grant(&compact_wrong, &ring, &wrong.expectations(), NOW),
        Err(AttemptGrantError::Ceiling(_))
    ));
}

// ===========================================================================
// AC-5 / AC-8 / AC-15: static guards as nonvacuous syn source scans
// ===========================================================================

/// Forbidden identifiers this module must never reference.
const FORBIDDEN_IDENTS: &[&str] = &[
    "relay_envelope",
    "flycockpit_relay_protocol",
    "relay_protocol",
    "from_relay",
    "remote_webrtc_endpoint",
    "remote_transport",
    "cockpit_noise",
    "snow",
];

struct IdentCollector {
    idents: std::collections::BTreeSet<String>,
    verified_grant_literals: usize,
}

impl<'ast> syn::visit::Visit<'ast> for IdentCollector {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        self.idents.insert(ident.to_string());
    }
    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        if let Some(seg) = node.path.segments.last()
            && seg.ident == "VerifiedAttemptGrant"
        {
            self.verified_grant_literals += 1;
        }
        syn::visit::visit_expr_struct(self, node);
    }
}

fn collect(src: &str) -> IdentCollector {
    let file = syn::parse_file(src).expect("module source parses as Rust");
    let mut c = IdentCollector {
        idents: std::collections::BTreeSet::new(),
        verified_grant_literals: 0,
    };
    syn::visit::visit_file(&mut c, &file);
    c
}

fn forbidden_hits(src: &str) -> Vec<String> {
    let c = collect(src);
    FORBIDDEN_IDENTS
        .iter()
        .filter(|f| c.idents.contains(**f))
        .map(|f| (*f).to_string())
        .collect()
}

/// Whether `validate_permission_ceiling` calls the foundation digest helper.
fn ceiling_fn_calls_digest_helper(src: &str) -> bool {
    let file = syn::parse_file(src).expect("parses");
    for item in &file.items {
        if let syn::Item::Impl(imp) = item {
            for it in &imp.items {
                if let syn::ImplItem::Fn(f) = it
                    && f.sig.ident == "validate_permission_ceiling"
                {
                    let mut c = IdentCollector {
                        idents: std::collections::BTreeSet::new(),
                        verified_grant_literals: 0,
                    };
                    syn::visit::visit_block(&mut c, &f.block);
                    return c.idents.contains("permission_ceiling_digest");
                }
            }
        }
    }
    false
}

#[test]
fn remote_attempt_static_guards() {
    let src = include_str!("../remote_attempt.rs");

    // 1. No forbidden relay/Noise/WebRTC references in this module.
    let hits = forbidden_hits(src);
    assert!(hits.is_empty(), "forbidden references present: {hits:?}");

    // Nonvacuity: the same scan rejects a negative fixture for each token.
    for token in FORBIDDEN_IDENTS {
        let snippet = format!("use crate::daemon::{token}::Thing; fn f() {{ let _ = {token}; }}");
        // `snow` / `from_relay` etc. as bare paths.
        let neg = format!("fn g() {{ let _ = {token}::call(); }}\n{snippet}");
        assert!(
            forbidden_hits(&neg).contains(&token.to_string()),
            "scan must detect forbidden token `{token}`"
        );
    }

    // 2. VerifiedAttemptGrant struct-literal construction appears exactly once
    // (inside verify_attempt_grant), i.e. only inside this module.
    let c = collect(src);
    assert_eq!(
        c.verified_grant_literals, 1,
        "VerifiedAttemptGrant must be constructed exactly once, in this module"
    );
    // Nonvacuity: the scan detects an external literal in a negative fixture.
    let neg_literal = "fn evil() { let _ = VerifiedAttemptGrant { grant: todo!() }; }";
    assert_eq!(collect(neg_literal).verified_grant_literals, 1);

    // 3. The foundation digest helper is called on the ceiling validation path.
    assert!(
        ceiling_fn_calls_digest_helper(src),
        "validate_permission_ceiling must call permission_ceiling_digest"
    );
    // Nonvacuity: a fixture whose body omits the call is rejected.
    let neg_no_digest =
        "impl X { pub fn validate_permission_ceiling(&self) -> Result<(), ()> { Ok(()) } }";
    assert!(!ceiling_fn_calls_digest_helper(neg_no_digest));
}

// ===========================================================================
// Retained coverage adapted to the new API
// ===========================================================================

#[test]
fn remote_attempt_grant_mint_byte_idempotency() {
    let (sk, _ring) = authority();
    let params = default_params();
    let g1 = params.mint("k1", &sk);
    let g2 = params.mint("k1", &sk);
    // Deterministic canonical bytes (signatures are deterministic for a fixed
    // key + message under RFC 6979).
    assert_eq!(g1, g2);
    let d1: [u8; 32] = Sha256::digest(&g1).into();
    let mut g3 = g1.clone();
    g3[0] = g3[0].wrapping_add(1);
    let d3: [u8; 32] = Sha256::digest(&g3).into();
    assert_ne!(d1, d3);
}

#[test]
fn remote_attempt_daemon_offer_authenticated_delivery() {
    let mut body = Vec::new();
    body.extend_from_slice(b"FCDO");
    body.push(1);
    body.extend_from_slice(&[1u8; 16]);
    body.extend_from_slice(&[2u8; 16]);
    body.extend_from_slice(&1u64.to_be_bytes());
    body.extend_from_slice(&[3u8; 16]);
    body.extend_from_slice(&1u64.to_be_bytes());
    body.extend_from_slice(&[4u8; 16]);
    body.extend_from_slice(&[5u8; 16]);
    body.extend_from_slice(&[6u8; 16]);
    body.extend_from_slice(&[0xaa; 32]);
    body.extend_from_slice(&[0xcc; 32]);
    body.extend_from_slice(&1u64.to_be_bytes());
    body.extend_from_slice(&1u64.to_be_bytes());
    body.extend_from_slice(&[0xee; 32]);
    body.push(0);
    body.push(0x03);
    body.push(1);
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&[7u8; 16]);
    body.extend_from_slice(&1_700_000_000i64.to_be_bytes());
    body.extend_from_slice(&1_700_000_300i64.to_be_bytes());
    let signature = [0xdd; 64];
    let mut envelope = Vec::new();
    envelope.extend_from_slice(&(body.len() as u16).to_be_bytes());
    envelope.extend_from_slice(&body);
    envelope.extend_from_slice(&signature);

    let verified = verify_daemon_admission_offer(&envelope).unwrap();
    assert_eq!(verified.child_attempt_id, [5u8; 16]);
    let expected: [u8; 32] = Sha256::digest(&envelope).into();
    assert_eq!(verified.offer_digest, expected);
    let body_hash: [u8; 32] = Sha256::digest(&body).into();
    assert_ne!(verified.offer_digest, body_hash);
    let mut tampered = envelope.clone();
    tampered[4] ^= 0x01;
    assert!(verify_daemon_admission_offer(&tampered).is_err());

    assert_eq!(
        FCDO_DOMAIN,
        b"flycockpit.remote.daemon-admission-offer.v1\0"
    );
    assert_eq!(
        FCCP_DOMAIN,
        b"flycockpit.remote.client-admission-proof.v1\0"
    );
    assert_eq!(FCFP_DOMAIN, b"flycockpit.remote.endpoint-final-proof.v1\0");
    assert_ne!(FCDO_DOMAIN, FCCP_DOMAIN);
    assert_ne!(FCDO_DOMAIN, FCFP_DOMAIN);
    assert_ne!(FCCP_DOMAIN, FCFP_DOMAIN);
}

#[test]
fn remote_attempt_client_verifies_daemon_before_proof() {
    let bad = [0u8; 100];
    assert!(verify_daemon_admission_offer(&bad).is_err());
    let bad_fccp = [0u8; 100];
    assert!(verify_client_admission_proof(&bad_fccp).is_err());
    assert_ne!(fcdo_signature_hash(b"test"), fccp_signature_hash(b"test"));
    assert_ne!(fcfp_signature_hash(b"test"), fcdo_signature_hash(b"test"));
}

#[test]
fn remote_attempt_enterprise_authorization_profile() {
    // Control-plane grant: null tenantAuthorizationDigest verifies.
    let (sk, ring) = authority();
    let params = default_params();
    let compact = params.mint("k1", &sk);
    verify_attempt_grant(&compact, &ring, &params.expectations(), NOW).unwrap();

    // Cross-tenant/unexpected issuer now FAILS at expectation binding.
    let mut cross = default_params();
    cross.iss = "unexpected-issuer".into();
    let cross_jws = cross.mint("k1", &sk);
    assert!(
        verify_attempt_grant(&cross_jws, &ring, &params.expectations(), NOW).is_err(),
        "cross-tenant issuer must be rejected"
    );
}
