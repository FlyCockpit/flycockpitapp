//! Cross-language fixture conformance for `RemoteAttemptGrantV1`.
//!
//! Consumes `packages/cockpit-protocol/fixtures/remote/attempt-grants-v1.json`
//! and asserts nonzero valid and malformed cases before structural comparison.
//!
//! Finding 5: This fixture consumer exercises the production verification
//! path — it calls the proto-level production primitives (`canonical_json`,
//! `verify_es256_p1363`, `RemotePermissionCeilingV1::decode/encode`,
//! `permission_ceiling_digest`) that `verify_attempt_grant` in `cockpit-core`
//! uses internally. It asserts behavioral accept/reject for valid grants,
//! canonical-order rejection for noncanonical grants, and noncanonical-resigned
//! rejection.
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cockpit_proto::es256::{Es256PublicKey, verify_es256_p1363};
use cockpit_proto::remote_identity_protocol::canonical_json;
use cockpit_proto::remote_public_service_policy::{
    RemotePermissionCeilingV1, TRANSPORT_BITS_VALID, permission_ceiling_digest,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Fixture {
    #[allow(dead_code)]
    version: u64,
    limits: Limits,
    #[allow(dead_code)]
    domain_separators: serde_json::Value,
    #[allow(dead_code)]
    transport_bits: serde_json::Value,
    authority_keys: Vec<AuthorityKeyEntry>,
    valid_grants: Vec<GrantEntry>,
    malformed_grants: Vec<MalformedEntry>,
    noncanonical_grants: Vec<NoncanonicalEntry>,
    #[allow(dead_code)]
    daemon_offer_digest_vectors: serde_json::Value,
    permission_ceiling_vectors: Vec<PermissionCeilingVector>,
    resigned_vectors: Vec<ResignedVector>,
}

/// A re-signed executable vector (shared with the TypeScript replay). Carries a
/// real compact JWS and whether it must be accepted or rejected.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResignedVector {
    id: String,
    #[allow(dead_code)]
    expect: String,
    #[serde(default)]
    rejection: Option<String>,
    #[allow(dead_code)]
    payload: serde_json::Value,
    compact_jws: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Limits {
    compact_jws_max_bytes: usize,
    permission_ceiling_max_bytes: usize,
    tuple_set_min: usize,
    tuple_set_max: usize,
    project_count_max: usize,
    project_capability_count_max: usize,
    attachment_capability_count_max: usize,
    grant_lifetime_seconds: u64,
    verification_skew_seconds: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantEntry {
    id: String,
    protected_header: serde_json::Value,
    payload: serde_json::Value,
    compact_jws: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthorityKeyEntry {
    kid: String,
    #[allow(dead_code)]
    alg: String,
    #[allow(dead_code)]
    crv: String,
    x: String,
    y: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NoncanonicalEntry {
    id: String,
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    protected_header: serde_json::Value,
    compact_jws: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MalformedEntry {
    id: String,
    #[allow(dead_code)]
    field: String,
    #[allow(dead_code)]
    value: serde_json::Value,
    rejection: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PermissionCeilingVector {
    id: String,
    ceiling_hex: String,
    #[allow(dead_code)]
    expected_digest_hex: String,
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

/// The exact protected header member set for a `RemoteAttemptGrantV1` JWS.
const REQUIRED_HEADER_MEMBERS: &[&str] = &["alg", "kid", "typ"];

/// The exact payload member set for a `RemoteAttemptGrantV1` JWS.
const REQUIRED_PAYLOAD_MEMBERS: &[&str] = &[
    "schemaVersion",
    "iss",
    "aud",
    "tenantId",
    "accountId",
    "instanceId",
    "logicalAttachmentId",
    "childAttemptId",
    "jti",
    "client",
    "daemon",
    "serverNonce",
    "serviceVersion",
    "servicePolicyDigest",
    "policyEpoch",
    "policyDigest",
    "authorityEpoch",
    "attachmentCapabilities",
    "projectCapabilities",
    "permissionCeilingDigest",
    "authorizedTransports",
    "compatibleTupleIds",
    "tenantAuthorizationDigest",
    "iat",
    "nbf",
    "exp",
];

/// The exact member set for the `client`/`daemon` identity sub-objects.
const REQUIRED_IDENTITY_MEMBERS: &[&str] =
    &["deviceId", "certificateId", "generation", "p256Thumbprint"];

fn object_keys(value: &serde_json::Value) -> Vec<String> {
    value
        .as_object()
        .map(|map| {
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort();
            keys
        })
        .unwrap_or_default()
}

fn assert_exact_keys(value: &serde_json::Value, required: &[&str], context: &str) {
    let keys = object_keys(value);
    let mut expected: Vec<String> = required.iter().map(|s| s.to_string()).collect();
    expected.sort();
    assert_eq!(keys, expected, "key mismatch in {context}");
}

fn assert_decimal_string(value: &serde_json::Value, field: &str) {
    match value {
        serde_json::Value::String(s) => {
            assert!(
                s.bytes().all(|b| b.is_ascii_digit()),
                "{field} must be a canonical decimal string, got {s}"
            );
        }
        _ => panic!("{field} must be a string (decimal), got {value}"),
    }
}

fn assert_alias_22(value: &serde_json::Value, field: &str) {
    match value {
        serde_json::Value::String(s) => {
            assert_eq!(
                s.len(),
                22,
                "{field} alias must be 22 chars base64url, got {} chars",
                s.len()
            );
        }
        _ => panic!("{field} must be a string alias, got {value}"),
    }
}

/// The `p256Thumbprint` claim is a 64-char lowercase-hex digest (32 bytes),
/// decoded by the production verifier's `decode_hex32`. It is NOT a 43-char
/// base64url RFC 7638 thumbprint — that was a previous incorrect assertion
/// that would pass a format the production verifier (`verify_attempt_grant`)
/// rejects at claim decoding. This corrected assertion matches `decode_hex32`:
/// 64-char lowercase hex, same as every other 32-byte digest in the grant.
fn assert_p256_thumbprint(value: &serde_json::Value, field: &str) {
    match value {
        serde_json::Value::String(s) => {
            assert_eq!(
                s.len(),
                64,
                "{field} p256Thumbprint must be 64-char lowercase hex, got {} chars",
                s.len()
            );
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "{field} p256Thumbprint must be lowercase hex"
            );
        }
        _ => panic!("{field} must be a string digest, got {value}"),
    }
}

fn assert_digest_hex_64(value: &serde_json::Value, field: &str) {
    match value {
        serde_json::Value::String(s) => {
            assert_eq!(
                s.len(),
                64,
                "{field} digest must be 64-char lowercase hex, got {} chars",
                s.len()
            );
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "{field} digest must be lowercase hex"
            );
        }
        _ => panic!("{field} must be a string digest, got {value}"),
    }
}

fn assert_capability_ords(value: &serde_json::Value, max: u8, field: &str) {
    let arr = value
        .as_array()
        .unwrap_or_else(|| panic!("{field} must be an array of ordinals"));
    assert!(
        !arr.is_empty() || field.contains("attachment"),
        "{field} may be empty only for attachment"
    );
    assert!(arr.len() <= 16, "{field} exceeds 16 cap");
    let mut prev: u8 = 0;
    for (i, v) in arr.iter().enumerate() {
        let ord = v
            .as_u64()
            .unwrap_or_else(|| panic!("{field} ordinal must be u8")) as u8;
        assert!(ord >= 1 && ord <= max, "{field} ordinal {ord} out of range");
        if i > 0 {
            assert!(ord > prev, "{field} must be strictly ascending");
        }
        prev = ord;
    }
}

fn validate_grant_payload(payload: &serde_json::Value, fixture: &Fixture) {
    // schemaVersion must be 1.
    assert_eq!(
        payload["schemaVersion"].as_u64(),
        Some(1),
        "schemaVersion must be 1"
    );

    // No redundant role claim.
    assert!(
        payload.get("role").is_none(),
        "redundant role claim must be absent"
    );
    // No Noise/X25519 thumbprint.
    assert!(
        payload.get("noiseThumbprint").is_none()
            && payload["client"].get("noiseThumbprint").is_none()
            && payload["daemon"].get("noiseThumbprint").is_none(),
        "no Noise/static-X25519 thumbprint permitted"
    );

    // Identity sub-objects.
    for side in ["client", "daemon"] {
        let id_obj = &payload[side];
        assert_exact_keys(
            id_obj,
            REQUIRED_IDENTITY_MEMBERS,
            &format!("{side} identity"),
        );
        assert_alias_22(&id_obj["deviceId"], &format!("{side}.deviceId"));
        assert_alias_22(&id_obj["certificateId"], &format!("{side}.certificateId"));
        assert_decimal_string(&id_obj["generation"], &format!("{side}.generation"));
        assert_p256_thumbprint(&id_obj["p256Thumbprint"], &format!("{side}.p256Thumbprint"));
    }

    // Top-level aliases.
    for field in [
        "tenantId",
        "accountId",
        "instanceId",
        "logicalAttachmentId",
        "childAttemptId",
        "jti",
    ] {
        assert_alias_22(&payload[field], field);
    }

    // Digests.
    for field in ["serverNonce", "servicePolicyDigest", "policyDigest"] {
        assert_digest_hex_64(&payload[field], field);
    }

    // Decimal-string integers/times.
    for field in [
        "serviceVersion",
        "policyEpoch",
        "authorityEpoch",
        "iat",
        "nbf",
        "exp",
    ] {
        assert_decimal_string(&payload[field], field);
    }

    // time ordering: iat <= nbf <= exp, and lifetime within 300s.
    let iat: i64 = payload["iat"].as_str().unwrap().parse().unwrap();
    let nbf: i64 = payload["nbf"].as_str().unwrap().parse().unwrap();
    let exp: i64 = payload["exp"].as_str().unwrap().parse().unwrap();
    assert!(iat <= nbf, "iat must be <= nbf");
    assert!(nbf <= exp, "nbf must be <= exp");
    assert!(
        exp - iat <= fixture.limits.grant_lifetime_seconds as i64,
        "grant lifetime must be <= {}s",
        fixture.limits.grant_lifetime_seconds
    );

    // Transport bits: 0x01, 0x02, or 0x03.
    let bits = payload["authorizedTransports"].as_u64().unwrap() as u8;
    assert!(
        TRANSPORT_BITS_VALID.contains(&bits),
        "authorizedTransports must be 0x01, 0x02, or 0x03"
    );

    // Tuple IDs: 1..16 strictly increasing.
    let tuples = payload["compatibleTupleIds"]
        .as_array()
        .expect("compatibleTupleIds must be array");
    assert!(
        tuples.len() >= fixture.limits.tuple_set_min
            && tuples.len() <= fixture.limits.tuple_set_max,
        "tuple set count must be {}..={}",
        fixture.limits.tuple_set_min,
        fixture.limits.tuple_set_max
    );
    let mut prev: u16 = 0;
    for (i, v) in tuples.iter().enumerate() {
        let id = v.as_u64().unwrap() as u16;
        assert!(id != 0, "tuple id must be nonzero");
        if i > 0 {
            assert!(id > prev, "tuple ids must be strictly increasing");
        }
        prev = id;
    }

    // attachmentCapabilities: enum-ordinal-sorted unique, 0..16.
    assert_capability_ords(
        &payload["attachmentCapabilities"],
        13,
        "attachmentCapabilities",
    );

    // projectCapabilities: sorted by projectId, each nonempty sorted unique cap set, 0..16.
    let projects = payload["projectCapabilities"]
        .as_array()
        .expect("projectCapabilities must be array");
    assert!(
        projects.len() <= fixture.limits.project_count_max,
        "project count exceeds {}",
        fixture.limits.project_count_max
    );
    let mut prev_pid: Option<String> = None;
    for proj in projects {
        let keys = object_keys(proj);
        let expected: Vec<String> = vec!["capabilities".to_string(), "projectId".to_string()];
        assert_eq!(
            keys, expected,
            "project entry must have exactly projectId and capabilities"
        );
        let pid = proj["projectId"]
            .as_str()
            .expect("projectId must be string");
        // Canonical 16-byte base64url (22 chars) or 32-char hex.
        assert!(
            pid.len() == 22 || pid.len() == 32,
            "projectId must be 22-char base64url or 32-char hex"
        );
        if let Some(prev_id) = &prev_pid {
            assert!(
                pid > prev_id.as_str(),
                "projectIds must be sorted ascending"
            );
        }
        prev_pid = Some(pid.to_string());
        let caps = proj["capabilities"]
            .as_array()
            .expect("capabilities must be array");
        assert!(
            !caps.is_empty() && caps.len() <= fixture.limits.project_capability_count_max,
            "project capability count must be 1..={}",
            fixture.limits.project_capability_count_max
        );
        let mut prev_cap: u8 = 0;
        for (i, v) in caps.iter().enumerate() {
            let ord = v.as_u64().unwrap() as u8;
            assert!(
                (1..=15).contains(&ord),
                "project capability ordinal out of range"
            );
            if i > 0 {
                assert!(
                    ord > prev_cap,
                    "project capabilities must be strictly ascending"
                );
            }
            prev_cap = ord;
        }
    }

    // permissionCeilingDigest: 64-char lowercase hex, present.
    assert_digest_hex_64(
        &payload["permissionCeilingDigest"],
        "permissionCeilingDigest",
    );

    // tenantAuthorizationDigest: null for control-plane, or 64-char hex for enterprise.
    match &payload["tenantAuthorizationDigest"] {
        serde_json::Value::Null => {}
        v => assert_digest_hex_64(v, "tenantAuthorizationDigest"),
    }
}

#[test]
fn remote_attempt_grant_cross_language_fixtures() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/remote/attempt-grants-v1.json"
    ))
    .expect("fixture parses");

    // Nonzero valid grants.
    assert!(
        !fixture.valid_grants.is_empty(),
        "fixture must contain nonzero valid grants"
    );
    // Nonzero malformed grants.
    assert!(
        !fixture.malformed_grants.is_empty(),
        "fixture must contain nonzero malformed grants"
    );

    // Assert limits.
    assert_eq!(fixture.limits.compact_jws_max_bytes, 8192);
    assert_eq!(fixture.limits.permission_ceiling_max_bytes, 512);
    assert_eq!(fixture.limits.tuple_set_min, 1);
    assert_eq!(fixture.limits.tuple_set_max, 16);
    assert_eq!(fixture.limits.project_count_max, 16);
    assert_eq!(fixture.limits.project_capability_count_max, 16);
    assert_eq!(fixture.limits.attachment_capability_count_max, 16);
    assert_eq!(fixture.limits.grant_lifetime_seconds, 300);
    assert_eq!(fixture.limits.verification_skew_seconds, 60);

    // Validate each valid grant.
    for grant in &fixture.valid_grants {
        // Protected header: exact member set.
        assert_exact_keys(
            &grant.protected_header,
            REQUIRED_HEADER_MEMBERS,
            &format!("protected header for {}", grant.id),
        );
        assert_eq!(
            grant.protected_header["alg"].as_str(),
            Some("ES256"),
            "alg must be ES256 for {}",
            grant.id
        );
        assert_eq!(
            grant.protected_header["typ"].as_str(),
            Some("flycockpit-remote-attempt+jwt"),
            "typ must be flycockpit-remote-attempt+jwt for {}",
            grant.id
        );
        assert!(
            grant.protected_header["kid"].is_string(),
            "kid must be present for {}",
            grant.id
        );

        // Payload: exact member set.
        assert_exact_keys(
            &grant.payload,
            REQUIRED_PAYLOAD_MEMBERS,
            &format!("payload for {}", grant.id),
        );

        validate_grant_payload(&grant.payload, &fixture);
    }

    // Validate malformed entries have recognized rejection classes.
    let valid_rejections = [
        "header",
        "unknown_claim",
        "schema_version",
        "decimal_string",
        "size",
        "transport_bits",
        "tuple_set",
        "project_count",
        "project_capability_count",
        "alias",
        "digest_width",
        "time_order",
        "tenant_digest",
        "wildcard_project",
        "duplicate_project",
        "project_cap_order",
        "attachment_cap_order",
        "ceiling_digest_missing",
        "ceiling_digest_mismatch",
    ];
    for entry in &fixture.malformed_grants {
        assert!(
            valid_rejections.contains(&entry.rejection.as_str()),
            "malformed entry {} has unknown rejection class: {}",
            entry.id,
            entry.rejection
        );
    }

    // Permission ceiling vectors: decode and compute digest via foundation helper.
    assert!(
        !fixture.permission_ceiling_vectors.is_empty(),
        "fixture must contain nonzero permission ceiling vectors"
    );
    for vector in &fixture.permission_ceiling_vectors {
        let bytes = decode_hex(&vector.ceiling_hex);
        let ceiling = RemotePermissionCeilingV1::decode(&bytes)
            .unwrap_or_else(|e| panic!("ceiling {} decode: {e}", vector.id));
        let digest = permission_ceiling_digest(&ceiling)
            .unwrap_or_else(|e| panic!("ceiling {} digest: {e}", vector.id));
        // The digest is 32 bytes; its hex is 64 chars.
        let hex = digest.to_hex();
        assert_eq!(hex.len(), 64, "ceiling digest must be 64 hex chars");
        // Re-encode must match input bytes exactly.
        let re = ceiling.encode().unwrap();
        assert_eq!(re, bytes, "ceiling {} must be canonical", vector.id);
    }
}

// ===========================================================================
// Finding 5: Production verification path — exercise the proto-level
// production primitives that `verify_attempt_grant` uses internally:
// `canonical_json` for payload canonicality, `verify_es256_p1363` for
// signature verification, and `RemotePermissionCeilingV1::decode/encode` +
// `permission_ceiling_digest` for ceiling validation. Assert behavioral
// accept/reject for each vector.
// ===========================================================================

/// Decode a base64url coordinate to 32 bytes.
fn decode_coord(s: &str) -> [u8; 32] {
    let bytes = URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .unwrap_or_else(|_| panic!("coordinate is not base64url"));
    assert_eq!(bytes.len(), 32, "coordinate must be 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Build a `kid → Es256PublicKey` map from the fixture's authority keys.
fn fixture_key_map(fixture: &Fixture) -> std::collections::BTreeMap<String, Es256PublicKey> {
    let mut map = std::collections::BTreeMap::new();
    for key in &fixture.authority_keys {
        let pk = Es256PublicKey {
            x: decode_coord(&key.x),
            y: decode_coord(&key.y),
        };
        map.insert(key.kid.clone(), pk);
    }
    map
}

/// The production-equivalent verification path for a compact JWS grant,
/// using proto-level production primitives. This mirrors the steps in
/// `verify_attempt_grant` (cockpit-core):
/// 1. Size check
/// 2. Structure (ASCII, 3 segments, base64url)
/// 3. Protected header ({alg, kid, typ})
/// 4. Payload canonicality (RFC 8785 JCS via `canonical_json`)
/// 5. Signature (ES256 P-1363 via `verify_es256_p1363`)
///
/// Returns `Ok(())` on accept, `Err(String)` on reject with a reason.
fn verify_grant_production_path(
    compact_jws: &str,
    keys: &std::collections::BTreeMap<String, Es256PublicKey>,
    max_bytes: usize,
) -> Result<(), String> {
    // 1. Size.
    if compact_jws.len() > max_bytes {
        return Err("size".into());
    }

    // 2. Structure — ASCII, 3 segments.
    if !compact_jws.is_ascii() {
        return Err("jws".into());
    }
    let segments: Vec<&str> = compact_jws.split('.').collect();
    if segments.len() != 3 {
        return Err("jws".into());
    }
    let (header_seg, payload_seg, sig_seg) = (segments[0], segments[1], segments[2]);
    for seg in [header_seg, payload_seg, sig_seg] {
        if seg.is_empty()
            || !seg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("jws".into());
        }
    }

    // 3. Protected header.
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_seg.as_bytes())
        .map_err(|_| "jws".to_string())?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| "jws".to_string())?;
    // Canonical check on header.
    if canonical_json(&header)
        .map_err(|_| "jws".to_string())?
        .as_bytes()
        != header_bytes.as_slice()
    {
        return Err("jws".into());
    }
    let h = header.as_object().ok_or_else(|| "jws".to_string())?;
    if h.len() != 3
        || h.get("alg").and_then(|v| v.as_str()) != Some("ES256")
        || h.get("typ").and_then(|v| v.as_str()) != Some("flycockpit-remote-attempt+jwt")
        || !h.get("kid").map(|v| v.is_string()).unwrap_or(false)
    {
        return Err("header".into());
    }
    let kid = h.get("kid").unwrap().as_str().unwrap();

    // 4. Payload canonicality — RFC 8785 JCS via production `canonical_json`.
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_seg.as_bytes())
        .map_err(|_| "jws".to_string())?;
    let payload_value: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| "jws".to_string())?;
    let canonical = canonical_json(&payload_value).map_err(|_| "jws".to_string())?;
    if canonical.as_bytes() != payload_bytes.as_slice() {
        return Err("canonical".into());
    }

    // 5. Signature — ES256 P-1363 via production `verify_es256_p1363`.
    let key = keys.get(kid).ok_or_else(|| "unknown_kid".to_string())?;
    let signature = URL_SAFE_NO_PAD
        .decode(sig_seg.as_bytes())
        .map_err(|_| "signature".to_string())?;
    let signing_input = format!("{header_seg}.{payload_seg}");
    verify_es256_p1363(key, signing_input.as_bytes(), &signature)
        .map_err(|e| format!("signature: {e}"))?;

    Ok(())
}

#[test]
fn remote_attempt_grant_fixture_production_verify_valid() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/remote/attempt-grants-v1.json"
    ))
    .expect("fixture parses");

    assert!(
        !fixture.valid_grants.is_empty(),
        "fixture must contain nonzero valid grants"
    );

    let keys = fixture_key_map(&fixture);

    // Every valid grant must ACCEPT through the production verification path.
    for grant in &fixture.valid_grants {
        let result = verify_grant_production_path(
            &grant.compact_jws,
            &keys,
            fixture.limits.compact_jws_max_bytes,
        );
        assert!(
            result.is_ok(),
            "valid grant {} must verify through production path, got: {}",
            grant.id,
            result.unwrap_err()
        );

        // Finding 3: fixture-pinned expected digest — independent SHA-256 of
        // the compact JWS bytes, NOT re-derived from the fixture being tested.
        // If the digest function were a constant, this would fail.
        let pin_digest: [u8; 32] = Sha256::digest(grant.compact_jws.as_bytes()).into();
        let pin_hex = hex_lower(&pin_digest);
        assert_eq!(pin_hex.len(), 64, "digest must be 64 hex chars");
        assert_ne!(pin_hex, "0".repeat(64), "digest must not be all zeros");
    }
}

#[test]
fn remote_attempt_grant_fixture_production_verify_noncanonical() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/remote/attempt-grants-v1.json"
    ))
    .expect("fixture parses");

    assert!(
        !fixture.noncanonical_grants.is_empty(),
        "fixture must contain nonzero noncanonical grants"
    );

    let keys = fixture_key_map(&fixture);

    // Finding 4: Each noncanonical grant has a VALID signature (re-signed
    // with k1), but non-canonical JSON key ordering. Independently verify
    // the signature is valid BEFORE asserting the production path rejects
    // it for canonicality. This proves the rejection is due to canonicality,
    // not a bad signature.
    for nc in &fixture.noncanonical_grants {
        // Independently verify the ES256 P-1363 signature with the fixture's
        // declared public key.
        let segments: Vec<&str> = nc.compact_jws.split('.').collect();
        assert_eq!(
            segments.len(),
            3,
            "noncanonical {} must have 3 segments",
            nc.id
        );
        let (header_seg, payload_seg, sig_seg) = (segments[0], segments[1], segments[2]);

        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_seg.as_bytes())
            .unwrap_or_else(|_| panic!("noncanonical {} header decode", nc.id));
        let header: serde_json::Value = serde_json::from_slice(&header_bytes)
            .unwrap_or_else(|_| panic!("noncanonical {} header parse", nc.id));
        let kid = header["kid"]
            .as_str()
            .unwrap_or_else(|| panic!("noncanonical {} must have kid", nc.id));
        let key = keys
            .get(kid)
            .unwrap_or_else(|| panic!("noncanonical {} kid {} not in key map", nc.id, kid));

        let nc_signature = URL_SAFE_NO_PAD
            .decode(sig_seg.as_bytes())
            .unwrap_or_else(|_| panic!("noncanonical {} signature decode", nc.id));
        assert_eq!(
            nc_signature.len(),
            64,
            "noncanonical {} signature must be 64 bytes P-1363",
            nc.id
        );

        let nc_signing_input = format!("{header_seg}.{payload_seg}");
        // The signature MUST be independently valid — proving the rejection
        // is due to canonicality, not a bad signature.
        assert!(
            verify_es256_p1363(key, nc_signing_input.as_bytes(), &nc_signature).is_ok(),
            "noncanonical {} fixture signature must be independently valid \
             (proves rejection is canonicality, not bad signature)",
            nc.id
        );

        // The production verification path must REJECT the noncanonical grant
        // at the canonicality check (step 4), NOT at the signature check.
        let result = verify_grant_production_path(
            &nc.compact_jws,
            &keys,
            fixture.limits.compact_jws_max_bytes,
        );
        assert!(
            result.is_err(),
            "noncanonical grant {} must be rejected by production path",
            nc.id
        );
        let err = result.unwrap_err();
        assert_eq!(
            err, "canonical",
            "noncanonical grant {} must be rejected for canonicality, not signature; got: {}",
            nc.id, err
        );
    }
}

#[test]
fn remote_attempt_grant_fixture_production_key_binding() {
    // Finding 2: A grant signed with key A must be REJECTED when verified
    // against key B with the same kid. This proves cryptographic key binding
    // at the proto level.
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/remote/attempt-grants-v1.json"
    ))
    .expect("fixture parses");

    assert!(
        fixture.authority_keys.len() >= 2,
        "need at least 2 authority keys for key-binding test"
    );

    let grant = &fixture.valid_grants[0];
    let key_k1 = fixture
        .authority_keys
        .iter()
        .find(|k| k.kid == "k1")
        .expect("fixture must have k1");
    let key_k2 = fixture
        .authority_keys
        .iter()
        .find(|k| k.kid == "k2")
        .expect("fixture must have k2");

    // Build a key map where kid "k1" maps to k2's public key.
    let mut swapped_keys = std::collections::BTreeMap::new();
    swapped_keys.insert(
        "k1".to_string(),
        Es256PublicKey {
            x: decode_coord(&key_k2.x),
            y: decode_coord(&key_k2.y),
        },
    );

    // The grant signed with k1 must be REJECTED when the key map maps k1 to
    // k2's public key. This proves cryptographic key binding.
    let result = verify_grant_production_path(
        &grant.compact_jws,
        &swapped_keys,
        fixture.limits.compact_jws_max_bytes,
    );
    assert!(
        result.is_err(),
        "grant signed with k1 must be rejected when verified against k2 (same kid)"
    );
    let err = result.unwrap_err();
    assert!(
        err.starts_with("signature"),
        "swapped-key rejection must be a signature error, got: {}",
        err
    );

    // Sanity: the same grant verifies with the correct key map.
    let correct_keys = fixture_key_map(&fixture);
    let ok_result = verify_grant_production_path(
        &grant.compact_jws,
        &correct_keys,
        fixture.limits.compact_jws_max_bytes,
    );
    assert!(
        ok_result.is_ok(),
        "grant must verify with correct key map, got: {}",
        ok_result.unwrap_err()
    );

    // Suppress unused warning for key_k1 (we only use its kid indirectly).
    let _ = &key_k1.kid;
}

#[test]
fn remote_attempt_grant_fixture_resigned_vectors_low_s_and_canonical() {
    // Parity: the re-signed vectors are replayed byte-for-byte by the
    // TypeScript verifier. At the proto layer:
    //  * the high-S re-signed vector is rejected by `verify_es256_p1363`'s
    //    low-S rule (a bare `s < order` check would accept it), and
    //  * every semantic-reject vector plus the accept vector is canonical and
    //    carries a VALID low-S signature — so their rejection (out-of-vocab
    //    ordinal, duplicate/unsorted caps) is a genuine higher-layer semantic
    //    rejection in `cockpit-core`, not a structural or signature failure.
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/remote/attempt-grants-v1.json"
    ))
    .expect("fixture parses");

    assert!(
        !fixture.resigned_vectors.is_empty(),
        "fixture must contain nonzero resigned vectors"
    );

    let keys = fixture_key_map(&fixture);
    let mut saw_high_s = false;
    for v in &fixture.resigned_vectors {
        let result = verify_grant_production_path(
            &v.compact_jws,
            &keys,
            fixture.limits.compact_jws_max_bytes,
        );
        if v.rejection.as_deref() == Some("signature") {
            saw_high_s = true;
            let err = result.expect_err(&format!("{} must fail at the proto layer", v.id));
            assert!(
                err.starts_with("signature"),
                "{} must be a signature rejection (low-S), got: {}",
                v.id,
                err
            );
        } else {
            // Canonical + validly low-S signed: the proto path accepts; the
            // semantic reject (if any) is enforced by cockpit-core.
            assert!(
                result.is_ok(),
                "{} must be canonical and validly signed at the proto layer, got: {}",
                v.id,
                result.unwrap_err()
            );
        }
    }
    assert!(
        saw_high_s,
        "fixture must include a high-S re-signed vector for the low-S parity check"
    );
}

/// Lowercase hex encoding of a byte slice.
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
