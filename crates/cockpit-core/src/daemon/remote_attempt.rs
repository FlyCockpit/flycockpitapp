//! Device-bound remote connection attempt grants.
//!
//! This module owns the semantic mint/verify bindings, compact-JWS parsing and
//! ES256 signature verification, certificate/status/signature verification, and
//! endpoint consumption for `RemoteAttemptGrantV1` — a short-lived,
//! attempt-specific ES256 authorization grant bound to the enrolled client
//! device, exact daemon instance, signaling attempt, authorized data
//! transports, permission ceiling, and negotiated cryptographic transcript.
//!
//! # What this module owns
//!
//! - Compact-JWS grant parsing, RFC 8785 canonical payload byte-equality, and
//!   ES256 signature verification against an injected authority key ring.
//! - Grant claim validation and expectation-binding checks (`verify_attempt_grant`).
//! - Bilateral admission offer/proof verification (FCDO/FCCP cryptographic
//!   semantics only; canonical bytes are owned by
//!   `remote-signaling-attempt-store`).
//! - Transport-neutral final-proof gate consumption (FCFP), including
//!   `FCFP_DOMAIN`-domain-separated dual endpoint-signature verification.
//! - Daemon-side principal construction from a verified grant, deriving the
//!   client principal from the verified permission ceiling — never `Owner`.
//!
//! # What this module does NOT own
//!
//! - The raw ES256 verifier (`cockpit_proto::es256::verify_es256_p1363`) and
//!   the single workspace `p256` pin — owned by the public-service-policy
//!   prompt. This module consumes them; it never opens a second verify path.
//! - Canonical event codecs, agreement checks, committed bytes, or the
//!   final-proof-set digest (owned by `remote-signaling-attempt-store`).
//! - Capability discriminants, binary ownership, or permission-ceiling
//!   digest derivation (owned by `remote-public-service-policy-foundation`).
//! - Noise/WebRTC implementations or concrete transport code.
//!
//! # Static guards
//!
//! This module never imports relay envelopes/tokens or concrete Noise/WebRTC
//! modules, never references `from_relay`, and `VerifiedAttemptGrant` is
//! constructed only inside this module. These properties are enforced
//! nonvacuously by `remote_attempt_static_guards`, which parses this module's
//! own source with `syn` and rejects the forbidden patterns (each scan carries
//! a companion negative fixture proving it is not vacuous).

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::daemon::principal::{
    AttemptGrantAuthorization, ClientPrincipal, GrantDeviceBinding, RemoteCeilingAuthorization,
};
use cockpit_proto::es256::{Es256PublicKey, verify_es256_p1363};
use cockpit_proto::remote_public_service_policy::{
    RemoteAttachmentCapabilityV1, RemoteAuthorizedTupleSetV1, RemotePermissionCeilingV1,
    RemoteProjectCapabilityV1, TRANSPORT_BITS_VALID, permission_ceiling_digest,
};
use cockpit_proto::remote_signaling_attempt_store::{
    RemoteEndpointFinalProofV1, daemon_admission_offer_digest, final_proof_set_digest,
    validate_fccp, validate_fcdo,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Compact JWS protected-header `typ` value.
pub const GRANT_JWS_TYP: &str = "flycockpit-remote-attempt+jwt";
/// JWS `alg` for attempt grants.
pub const GRANT_JWS_ALG: &str = "ES256";
/// Maximum compact JWS size in bytes.
pub const GRANT_MAX_BYTES: usize = 8_192;
/// Maximum grant lifetime in seconds (5 minutes).
pub const GRANT_LIFETIME_SECONDS: i64 = 300;
/// Verification clock-skew tolerance in seconds.
pub const GRANT_SKEW_SECONDS: i64 = 60;
/// FCDO signature domain separator.
pub const FCDO_DOMAIN: &[u8] = b"flycockpit.remote.daemon-admission-offer.v1\0";
/// FCCP signature domain separator.
pub const FCCP_DOMAIN: &[u8] = b"flycockpit.remote.client-admission-proof.v1\0";
/// FCFP per-endpoint final-proof signature domain separator. Distinct from the
/// set-digest domain (`flycockpit.remote.endpoint-final-proof-set.v1\0`) owned
/// by the signaling store; mirrored by the TypeScript `remote-attempt-grants`
/// module and consumed by the WebRTC/websocket adapter prompts.
pub const FCFP_DOMAIN: &[u8] = b"flycockpit.remote.endpoint-final-proof.v1\0";
/// Schema version for `RemoteAttemptGrantV1`.
pub const GRANT_SCHEMA_VERSION: u8 = 1;

// FCFP wire layout (313 bytes total). Signature covers bytes[0..249].
const FCFP_SIGNED_LEN: usize = 249;
const FCFP_TOTAL_LEN: usize = 313;
const FCFP_CERT_ID: std::ops::Range<usize> = 225..241;
const FCFP_CERT_GEN: std::ops::Range<usize> = 241..249;
const FCFP_SIGNATURE: std::ops::Range<usize> = 249..313;

// Agreement layout (201 bytes, produced by RemoteEndpointFinalProofV1::decode):
//   transport(1) | childAttemptId(16) | transportEpoch(16) | admissionSequence(8)
//   | grantDigest(32) | negotiationDigest(32) | binding(96)
const AGR_EPOCH: std::ops::Range<usize> = 17..33;
const AGR_GRANT_DIGEST: std::ops::Range<usize> = 41..73;
const AGR_NEGOTIATION_DIGEST: std::ops::Range<usize> = 73..105;
const AGR_BINDING: std::ops::Range<usize> = 105..201;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttemptGrantError {
    #[error("invalid grant JWS: {0}")]
    Jws(String),
    #[error("grant signature verification failed: {0}")]
    Signature(String),
    #[error("invalid grant claims: {0}")]
    Claims(String),
    #[error("invalid permission ceiling: {0}")]
    Ceiling(String),
    #[error("invalid transport bits: {0}")]
    Transport(String),
    #[error("invalid tuple set: {0}")]
    TupleSet(String),
    #[error("admission offer verification failed: {0}")]
    Offer(String),
    #[error("admission proof verification failed: {0}")]
    Proof(String),
    #[error("final proof gate failed: {0}")]
    FinalProof(String),
    #[error("certificate or authority verification failed: {0}")]
    Certificate(String),
    #[error("time validation failed: {0}")]
    Time(String),
}

// ---------------------------------------------------------------------------
// Grant claims (semantic model)
// ---------------------------------------------------------------------------

/// Device identity claims bound into a grant. Contains only P-256
/// certificate IDs, generations, and RFC 7638 thumbprints. No Noise or
/// X25519 thumbprint exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantDeviceIdentity {
    pub device_id: [u8; 16],
    pub certificate_id: [u8; 16],
    pub generation: u64,
    pub p256_thumbprint: [u8; 32],
}

/// Permission ceiling projection in a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantPermissionCeiling {
    pub attachment_capabilities: Vec<RemoteAttachmentCapabilityV1>,
    pub projects: Vec<([u8; 16], Vec<RemoteProjectCapabilityV1>)>,
}

/// The semantic model of a `RemoteAttemptGrantV1` after JWS parsing and
/// claim extraction. This is the verified-claims view; the compact JWS
/// bytes are retained separately for digest computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAttemptGrantV1 {
    pub schema_version: u8,
    pub issuer: String,
    pub audience: String,
    pub tenant_id: [u8; 16],
    pub account_id: [u8; 16],
    pub instance_id: [u8; 16],
    pub logical_attachment_id: [u8; 16],
    pub child_attempt_id: [u8; 16],
    pub jti: [u8; 16],
    pub client: GrantDeviceIdentity,
    pub daemon: GrantDeviceIdentity,
    pub server_nonce: [u8; 32],
    pub service_version: u64,
    pub service_policy_digest: [u8; 32],
    pub policy_epoch: u64,
    pub policy_digest: [u8; 32],
    pub authority_epoch: u64,
    pub permission_ceiling: GrantPermissionCeiling,
    pub permission_ceiling_digest: [u8; 32],
    pub authorized_transports: u8,
    pub compatible_tuple_ids: Vec<u16>,
    pub tenant_authorization_digest: Option<[u8; 32]>,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    /// The complete compact JWS bytes (byte-identical across retries).
    pub compact_jws: Vec<u8>,
}

impl RemoteAttemptGrantV1 {
    /// Compute SHA-256 of the complete compact JWS bytes.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.compact_jws).into()
    }

    /// Validate the grant's time claims against a verification clock,
    /// applying the 60-second skew tolerance. Skew cannot extend `exp`.
    pub fn validate_time(&self, now: i64) -> Result<(), AttemptGrantError> {
        if self.iat > self.nbf || self.nbf > self.exp {
            return Err(AttemptGrantError::Time(
                "iat/nbf/exp ordering violation".into(),
            ));
        }
        if self.exp - self.iat > GRANT_LIFETIME_SECONDS {
            return Err(AttemptGrantError::Time(format!(
                "grant lifetime {}s exceeds {}s cap",
                self.exp - self.iat,
                GRANT_LIFETIME_SECONDS
            )));
        }
        // nbf with skew tolerance.
        if now + GRANT_SKEW_SECONDS < self.nbf {
            return Err(AttemptGrantError::Time("grant not yet valid".into()));
        }
        // exp without skew extension.
        if now > self.exp {
            return Err(AttemptGrantError::Time("grant expired".into()));
        }
        Ok(())
    }

    /// Validate the authorized transport bits against the foundation-owned
    /// valid set.
    pub fn validate_transport_bits(&self) -> Result<(), AttemptGrantError> {
        if !TRANSPORT_BITS_VALID.contains(&self.authorized_transports) {
            return Err(AttemptGrantError::Transport(format!(
                "transport bits 0x{:02x} not in valid set",
                self.authorized_transports
            )));
        }
        Ok(())
    }

    /// Validate the compatible tuple set against the foundation codec. The
    /// policy revocation set is caller-supplied (never hardcoded here): a
    /// tuple ID that is registry-absent or present in `revoked` is rejected.
    pub fn validate_tuple_set(&self, revoked: &[u16]) -> Result<(), AttemptGrantError> {
        let tuple_set = RemoteAuthorizedTupleSetV1 {
            tuple_ids: self.compatible_tuple_ids.clone(),
        };
        tuple_set
            .encode(revoked)
            .map_err(|e| AttemptGrantError::TupleSet(e.to_string()))?;
        Ok(())
    }

    /// Validate the permission ceiling: re-encode the canonical binary,
    /// compute the digest via the foundation helper, and assert it
    /// matches the grant's `permissionCeilingDigest`. Omission, mismatch,
    /// caller supply, alternate re-encoding, or local derivation are
    /// all rejected.
    pub fn validate_permission_ceiling(&self) -> Result<(), AttemptGrantError> {
        let ceiling = RemotePermissionCeilingV1 {
            attachment_capabilities: self.permission_ceiling.attachment_capabilities.clone(),
            projects: self.permission_ceiling.projects.clone(),
        };
        let digest = permission_ceiling_digest(&ceiling)
            .map_err(|e| AttemptGrantError::Ceiling(e.to_string()))?;
        if digest.as_bytes() != &self.permission_ceiling_digest {
            return Err(AttemptGrantError::Ceiling(
                "permissionCeilingDigest does not match foundation helper output".into(),
            ));
        }
        Ok(())
    }

    /// Perform all semantic claim validation (time, transport, tuple,
    /// ceiling). This is called after signature verification and before
    /// expectation binding. `revoked` is the policy-owned revocation set
    /// threaded from the enclosing public API; the outermost caller that owns
    /// no policy context yet passes an explicit empty slice.
    pub fn validate_claims(&self, now: i64, revoked: &[u16]) -> Result<(), AttemptGrantError> {
        if self.schema_version != GRANT_SCHEMA_VERSION {
            return Err(AttemptGrantError::Claims(format!(
                "schemaVersion must be {}, got {}",
                GRANT_SCHEMA_VERSION, self.schema_version
            )));
        }
        self.validate_time(now)?;
        self.validate_transport_bits()?;
        self.validate_tuple_set(revoked)?;
        self.validate_permission_ceiling()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Grant verification ceremony
// ---------------------------------------------------------------------------

/// Injected authority key ring: `kid` → ES256 public key. The verifier looks up
/// the grant's `kid` here; an unknown `kid` fails closed. No network, env, or
/// on-disk key acquisition happens in the verification path.
#[derive(Debug, Clone, Default)]
pub struct AttemptGrantKeyRing {
    keys: BTreeMap<String, Es256PublicKey>,
}

impl AttemptGrantKeyRing {
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Register a `kid` → public key mapping.
    pub fn with_key(mut self, kid: impl Into<String>, key: Es256PublicKey) -> Self {
        self.keys.insert(kid.into(), key);
        self
    }

    fn get(&self, kid: &str) -> Option<&Es256PublicKey> {
        self.keys.get(kid)
    }
}

/// The caller's expectation for the grant's tenant-authorization claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantAuthorizationExpectation {
    /// Control-plane grant: `tenantAuthorizationDigest` must be null.
    ControlPlane,
    /// Enterprise grant: `tenantAuthorizationDigest` must equal this digest.
    Enterprise([u8; 32]),
}

/// Values the daemon already knows independently and pins exactly. Every claim
/// is bound to one of these; a single mismatch fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantVerificationExpectations {
    pub issuer: String,
    pub audience: String,
    pub tenant_id: [u8; 16],
    pub account_id: [u8; 16],
    pub instance_id: [u8; 16],
    pub logical_attachment_id: [u8; 16],
    pub child_attempt_id: [u8; 16],
    pub client: GrantDeviceIdentity,
    pub daemon: GrantDeviceIdentity,
    pub server_nonce: [u8; 32],
    pub service_version: u64,
    pub service_policy_digest: [u8; 32],
    pub policy_epoch: u64,
    pub policy_digest: [u8; 32],
    pub authority_epoch: u64,
    pub tenant_authorization: TenantAuthorizationExpectation,
}

/// A grant whose compact-JWS signature, canonical encoding, semantic claims,
/// and every expectation binding have all been verified.
///
/// **Sealed capability:** all fields are private and there is no public
/// constructor other than [`verify_attempt_grant`]. A `VerifiedAttemptGrant`
/// value is therefore proof that the full verification ceremony ran; principal
/// derivation consumes only this type, so a forged/unverified grant can never
/// reach [`construct_principal_from_grant`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttemptGrant {
    grant: RemoteAttemptGrantV1,
}

impl VerifiedAttemptGrant {
    /// SHA-256 of the complete verified compact JWS bytes.
    pub fn grant_digest(&self) -> [u8; 32] {
        self.grant.digest()
    }
    /// The verified permission ceiling.
    pub fn permission_ceiling(&self) -> &GrantPermissionCeiling {
        &self.grant.permission_ceiling
    }
    /// The verified client device identity.
    pub fn client_identity(&self) -> &GrantDeviceIdentity {
        &self.grant.client
    }
    /// The verified daemon device identity.
    pub fn daemon_identity(&self) -> &GrantDeviceIdentity {
        &self.grant.daemon
    }
    /// The authorized transport bits (a ceiling; local policy may only narrow).
    pub fn authorized_transports(&self) -> u8 {
        self.grant.authorized_transports
    }
    pub fn child_attempt_id(&self) -> [u8; 16] {
        self.grant.child_attempt_id
    }
    pub fn logical_attachment_id(&self) -> [u8; 16] {
        self.grant.logical_attachment_id
    }
    pub fn account_id(&self) -> [u8; 16] {
        self.grant.account_id
    }
    /// Read-only access to the full verified claims view.
    pub fn claims(&self) -> &RemoteAttemptGrantV1 {
        &self.grant
    }
}

/// Strict protected header. Unknown members (including `crit`, `cty`) are
/// rejected by `deny_unknown_fields`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHeader {
    alg: String,
    kid: String,
    typ: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdentity {
    #[serde(rename = "deviceId")]
    device_id: String,
    #[serde(rename = "certificateId")]
    certificate_id: String,
    generation: String,
    #[serde(rename = "p256Thumbprint")]
    p256_thumbprint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProjectCap {
    #[serde(rename = "projectId")]
    project_id: String,
    capabilities: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClaims {
    #[serde(rename = "schemaVersion")]
    schema_version: u8,
    iss: String,
    aud: String,
    #[serde(rename = "tenantId")]
    tenant_id: String,
    #[serde(rename = "accountId")]
    account_id: String,
    #[serde(rename = "instanceId")]
    instance_id: String,
    #[serde(rename = "logicalAttachmentId")]
    logical_attachment_id: String,
    #[serde(rename = "childAttemptId")]
    child_attempt_id: String,
    jti: String,
    client: RawIdentity,
    daemon: RawIdentity,
    #[serde(rename = "serverNonce")]
    server_nonce: String,
    #[serde(rename = "serviceVersion")]
    service_version: String,
    #[serde(rename = "servicePolicyDigest")]
    service_policy_digest: String,
    #[serde(rename = "policyEpoch")]
    policy_epoch: String,
    #[serde(rename = "policyDigest")]
    policy_digest: String,
    #[serde(rename = "authorityEpoch")]
    authority_epoch: String,
    #[serde(rename = "attachmentCapabilities")]
    attachment_capabilities: Vec<u8>,
    #[serde(rename = "projectCapabilities")]
    project_capabilities: Vec<RawProjectCap>,
    #[serde(rename = "permissionCeilingDigest")]
    permission_ceiling_digest: String,
    #[serde(rename = "authorizedTransports")]
    authorized_transports: u8,
    #[serde(rename = "compatibleTupleIds")]
    compatible_tuple_ids: Vec<u16>,
    #[serde(rename = "tenantAuthorizationDigest")]
    tenant_authorization_digest: Option<String>,
    iat: String,
    nbf: String,
    exp: String,
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Decode a 64-char lowercase-hex digest to 32 bytes. Uppercase, wrong length,
/// or non-hex is rejected.
fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_val(b[2 * i])?;
        let lo = hex_val(b[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Decode a 22-char canonical base64url (no padding) alias to 16 bytes. A
/// non-canonical alias (one that re-encodes differently) is rejected.
fn decode_alias16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 22 {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()?;
    if bytes.len() != 16 {
        return None;
    }
    if URL_SAFE_NO_PAD.encode(&bytes) != s {
        return None;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Encode 16 bytes to the canonical 22-char base64url alias.
pub fn account_alias(bytes: &[u8; 16]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Parse a strict decimal-string unsigned integer (no sign, no whitespace).
fn parse_decimal_u64(s: &str) -> Option<u64> {
    if s.is_empty() || s.bytes().any(|b| !b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok()
}

/// Parse a strict decimal-string signed timestamp (non-negative digits only).
fn parse_decimal_i64(s: &str) -> Option<i64> {
    if s.is_empty() || s.bytes().any(|b| !b.is_ascii_digit()) {
        return None;
    }
    s.parse::<i64>().ok()
}

fn is_base64url_segment(seg: &str) -> bool {
    !seg.is_empty()
        && seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

// ---- RFC 8785 canonical JSON (subset over serde_json::Value) --------------

fn canonical_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Emit RFC 8785 canonical JSON for the subset used by grant payloads:
/// objects (keys sorted by UTF-8 bytes — grant keys are ASCII), arrays,
/// strings, non-negative integers, booleans, and null. A non-integer number is
/// rejected as non-canonical.
fn canonical_json(value: &serde_json::Value, out: &mut String) -> Result<(), AttemptGrantError> {
    use serde_json::Value;
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                return Err(AttemptGrantError::Jws(
                    "non-canonical (non-integer) number in payload".into(),
                ));
            }
        }
        Value::String(s) => canonical_json_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json_string(k, out);
                out.push(':');
                canonical_json(&map[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Verify a compact-JWS attempt grant end to end and return the sealed
/// verified grant. Steps run in the mandated cheap-before-crypto order.
pub fn verify_attempt_grant(
    compact_jws: &[u8],
    keys: &AttemptGrantKeyRing,
    expected: &GrantVerificationExpectations,
    now: i64,
) -> Result<VerifiedAttemptGrant, AttemptGrantError> {
    // 1. Size — before any decoding.
    if compact_jws.len() > GRANT_MAX_BYTES {
        return Err(AttemptGrantError::Jws(format!(
            "compact JWS is {} bytes; cap is {}",
            compact_jws.len(),
            GRANT_MAX_BYTES
        )));
    }

    // 2. Structure — ASCII, exactly three non-empty base64url segments.
    let compact = std::str::from_utf8(compact_jws)
        .map_err(|_| AttemptGrantError::Jws("compact JWS is not ASCII".into()))?;
    if !compact.is_ascii() {
        return Err(AttemptGrantError::Jws("compact JWS is not ASCII".into()));
    }
    let segments: Vec<&str> = compact.split('.').collect();
    if segments.len() != 3 {
        return Err(AttemptGrantError::Jws(format!(
            "compact JWS must have exactly 3 segments, got {}",
            segments.len()
        )));
    }
    let (header_seg, payload_seg, signature_seg) = (segments[0], segments[1], segments[2]);
    for seg in [header_seg, payload_seg, signature_seg] {
        if !is_base64url_segment(seg) {
            return Err(AttemptGrantError::Jws(
                "segment is empty or not padding-free base64url".into(),
            ));
        }
    }

    // 3. Protected header — strict {alg, kid, typ}.
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_seg.as_bytes())
        .map_err(|_| AttemptGrantError::Jws("header is not base64url".into()))?;
    let header: RawHeader = serde_json::from_slice(&header_bytes).map_err(|_| {
        AttemptGrantError::Jws("header is not the strict {alg,kid,typ} object".into())
    })?;
    if header.alg != GRANT_JWS_ALG {
        return Err(AttemptGrantError::Jws(format!(
            "alg must be {GRANT_JWS_ALG}"
        )));
    }
    if header.typ != GRANT_JWS_TYP {
        return Err(AttemptGrantError::Jws(format!(
            "typ must be {GRANT_JWS_TYP}"
        )));
    }
    if header.kid.is_empty() {
        return Err(AttemptGrantError::Jws("kid must be non-empty".into()));
    }

    // 4. Payload canonicality — canonical re-encode must byte-equal the payload.
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_seg.as_bytes())
        .map_err(|_| AttemptGrantError::Jws("payload is not base64url".into()))?;
    let payload_value: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| AttemptGrantError::Jws("payload is not JSON".into()))?;
    let mut canonical = String::new();
    canonical_json(&payload_value, &mut canonical)?;
    if canonical.as_bytes() != payload_bytes.as_slice() {
        return Err(AttemptGrantError::Jws(
            "payload is not RFC 8785 canonical (ordering, whitespace, duplicate, or number form)"
                .into(),
        ));
    }

    // 5. Claim typing — strict member set + typed decoding.
    let raw: RawClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|_| AttemptGrantError::Claims("unknown or malformed claim member".into()))?;
    let grant = decode_claims(raw, compact_jws.to_vec())?;

    // 6. Signature — kid lookup fails closed; ES256 over "header.payload".
    let key = keys
        .get(&header.kid)
        .ok_or_else(|| AttemptGrantError::Signature("unknown kid".into()))?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_seg.as_bytes())
        .map_err(|_| AttemptGrantError::Signature("signature is not base64url".into()))?;
    let signing_input = format!("{header_seg}.{payload_seg}");
    verify_es256_p1363(key, signing_input.as_bytes(), &signature)
        .map_err(|_| AttemptGrantError::Signature("ES256 verification failed".into()))?;

    // 7. Semantic claims (time, transport, tuple, ceiling digest).
    grant.validate_claims(now, &[])?;

    // 8. Expectation binding — every claim pinned to caller-known values.
    bind_expectations(&grant, expected)?;

    Ok(VerifiedAttemptGrant { grant })
}

fn decode_identity(raw: RawIdentity) -> Result<GrantDeviceIdentity, AttemptGrantError> {
    let device_id = decode_alias16(&raw.device_id)
        .ok_or_else(|| AttemptGrantError::Claims("deviceId".into()))?;
    let certificate_id = decode_alias16(&raw.certificate_id)
        .ok_or_else(|| AttemptGrantError::Claims("certificateId".into()))?;
    let generation = parse_decimal_u64(&raw.generation)
        .ok_or_else(|| AttemptGrantError::Claims("generation".into()))?;
    let p256_thumbprint = decode_hex32(&raw.p256_thumbprint)
        .ok_or_else(|| AttemptGrantError::Claims("p256Thumbprint".into()))?;
    Ok(GrantDeviceIdentity {
        device_id,
        certificate_id,
        generation,
        p256_thumbprint,
    })
}

fn decode_claims(
    raw: RawClaims,
    compact_jws: Vec<u8>,
) -> Result<RemoteAttemptGrantV1, AttemptGrantError> {
    let tenant_id = decode_alias16(&raw.tenant_id)
        .ok_or_else(|| AttemptGrantError::Claims("tenantId".into()))?;
    let account_id = decode_alias16(&raw.account_id)
        .ok_or_else(|| AttemptGrantError::Claims("accountId".into()))?;
    let instance_id = decode_alias16(&raw.instance_id)
        .ok_or_else(|| AttemptGrantError::Claims("instanceId".into()))?;
    let logical_attachment_id = decode_alias16(&raw.logical_attachment_id)
        .ok_or_else(|| AttemptGrantError::Claims("logicalAttachmentId".into()))?;
    let child_attempt_id = decode_alias16(&raw.child_attempt_id)
        .ok_or_else(|| AttemptGrantError::Claims("childAttemptId".into()))?;
    let jti = decode_alias16(&raw.jti).ok_or_else(|| AttemptGrantError::Claims("jti".into()))?;
    let client = decode_identity(raw.client)?;
    let daemon = decode_identity(raw.daemon)?;
    let server_nonce = decode_hex32(&raw.server_nonce)
        .ok_or_else(|| AttemptGrantError::Claims("serverNonce".into()))?;
    let service_version = parse_decimal_u64(&raw.service_version)
        .ok_or_else(|| AttemptGrantError::Claims("serviceVersion".into()))?;
    let service_policy_digest = decode_hex32(&raw.service_policy_digest)
        .ok_or_else(|| AttemptGrantError::Claims("servicePolicyDigest".into()))?;
    let policy_epoch = parse_decimal_u64(&raw.policy_epoch)
        .ok_or_else(|| AttemptGrantError::Claims("policyEpoch".into()))?;
    let policy_digest = decode_hex32(&raw.policy_digest)
        .ok_or_else(|| AttemptGrantError::Claims("policyDigest".into()))?;
    let authority_epoch = parse_decimal_u64(&raw.authority_epoch)
        .ok_or_else(|| AttemptGrantError::Claims("authorityEpoch".into()))?;

    let attachment_capabilities = raw
        .attachment_capabilities
        .iter()
        .map(|o| {
            RemoteAttachmentCapabilityV1::from_ordinal(*o)
                .map_err(|_| AttemptGrantError::Claims("attachmentCapabilities".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut projects = Vec::with_capacity(raw.project_capabilities.len());
    for p in raw.project_capabilities {
        let pid = decode_hex_id16(&p.project_id)
            .ok_or_else(|| AttemptGrantError::Claims("projectCapabilities.projectId".into()))?;
        let caps = p
            .capabilities
            .iter()
            .map(|o| {
                RemoteProjectCapabilityV1::from_ordinal(*o).map_err(|_| {
                    AttemptGrantError::Claims("projectCapabilities.capabilities".into())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        projects.push((pid, caps));
    }

    let permission_ceiling_digest = decode_hex32(&raw.permission_ceiling_digest)
        .ok_or_else(|| AttemptGrantError::Claims("permissionCeilingDigest".into()))?;

    let tenant_authorization_digest = match raw.tenant_authorization_digest {
        None => None,
        Some(s) => Some(
            decode_hex32(&s)
                .ok_or_else(|| AttemptGrantError::Claims("tenantAuthorizationDigest".into()))?,
        ),
    };

    let iat = parse_decimal_i64(&raw.iat).ok_or_else(|| AttemptGrantError::Claims("iat".into()))?;
    let nbf = parse_decimal_i64(&raw.nbf).ok_or_else(|| AttemptGrantError::Claims("nbf".into()))?;
    let exp = parse_decimal_i64(&raw.exp).ok_or_else(|| AttemptGrantError::Claims("exp".into()))?;

    Ok(RemoteAttemptGrantV1 {
        schema_version: raw.schema_version,
        issuer: raw.iss,
        audience: raw.aud,
        tenant_id,
        account_id,
        instance_id,
        logical_attachment_id,
        child_attempt_id,
        jti,
        client,
        daemon,
        server_nonce,
        service_version,
        service_policy_digest,
        policy_epoch,
        policy_digest,
        authority_epoch,
        permission_ceiling: GrantPermissionCeiling {
            attachment_capabilities,
            projects,
        },
        permission_ceiling_digest,
        authorized_transports: raw.authorized_transports,
        compatible_tuple_ids: raw.compatible_tuple_ids,
        tenant_authorization_digest,
        iat,
        nbf,
        exp,
        compact_jws,
    })
}

/// Decode a 32-char lowercase-hex project id to 16 bytes.
fn decode_hex_id16(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = hex_val(b[2 * i])?;
        let lo = hex_val(b[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn bind_expectations(
    grant: &RemoteAttemptGrantV1,
    expected: &GrantVerificationExpectations,
) -> Result<(), AttemptGrantError> {
    macro_rules! bind {
        ($lhs:expr, $rhs:expr, $name:literal) => {
            if $lhs != $rhs {
                return Err(AttemptGrantError::Claims($name.into()));
            }
        };
    }
    bind!(grant.issuer, expected.issuer, "iss");
    bind!(grant.audience, expected.audience, "aud");
    bind!(grant.tenant_id, expected.tenant_id, "tenantId");
    bind!(grant.account_id, expected.account_id, "accountId");
    bind!(grant.instance_id, expected.instance_id, "instanceId");
    bind!(
        grant.logical_attachment_id,
        expected.logical_attachment_id,
        "logicalAttachmentId"
    );
    bind!(
        grant.child_attempt_id,
        expected.child_attempt_id,
        "childAttemptId"
    );
    bind!(grant.client, expected.client, "client");
    bind!(grant.daemon, expected.daemon, "daemon");
    bind!(grant.server_nonce, expected.server_nonce, "serverNonce");
    bind!(
        grant.service_version,
        expected.service_version,
        "serviceVersion"
    );
    bind!(
        grant.service_policy_digest,
        expected.service_policy_digest,
        "servicePolicyDigest"
    );
    bind!(grant.policy_epoch, expected.policy_epoch, "policyEpoch");
    bind!(grant.policy_digest, expected.policy_digest, "policyDigest");
    bind!(
        grant.authority_epoch,
        expected.authority_epoch,
        "authorityEpoch"
    );
    match &expected.tenant_authorization {
        TenantAuthorizationExpectation::ControlPlane => {
            if grant.tenant_authorization_digest.is_some() {
                return Err(AttemptGrantError::Claims(
                    "tenantAuthorizationDigest".into(),
                ));
            }
        }
        TenantAuthorizationExpectation::Enterprise(digest) => {
            if grant.tenant_authorization_digest.as_ref() != Some(digest) {
                return Err(AttemptGrantError::Claims(
                    "tenantAuthorizationDigest".into(),
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Bilateral admission verification
// ---------------------------------------------------------------------------

/// Verified daemon admission offer fields extracted from the FCDO envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDaemonAdmissionOffer {
    pub child_attempt_id: [u8; 16],
    pub offer_digest: [u8; 32],
    pub offer_bytes: Vec<u8>,
}

/// Verify a `DaemonAdmissionOfferV1` (FCDO) envelope structurally and compute
/// its digest. Signature verification is performed separately by the caller
/// using the enrolled daemon P-256 key.
pub fn verify_daemon_admission_offer(
    fcdo_bytes: &[u8],
) -> Result<VerifiedDaemonAdmissionOffer, AttemptGrantError> {
    let child_attempt_id = validate_fcdo(fcdo_bytes)
        .map_err(|e| AttemptGrantError::Offer(format!("FCDO structural validation: {e}")))?;
    let offer_digest = daemon_admission_offer_digest(fcdo_bytes)
        .map_err(|e| AttemptGrantError::Offer(format!("FCDO digest: {e}")))?;
    Ok(VerifiedDaemonAdmissionOffer {
        child_attempt_id,
        offer_digest,
        offer_bytes: fcdo_bytes.to_vec(),
    })
}

/// Verified client admission proof fields extracted from the FCCP envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClientAdmissionProof {
    pub child_attempt_id: [u8; 16],
    pub proof_bytes: Vec<u8>,
}

/// Verify a `ClientAdmissionProofV1` (FCCP) envelope structurally.
pub fn verify_client_admission_proof(
    fccp_bytes: &[u8],
) -> Result<VerifiedClientAdmissionProof, AttemptGrantError> {
    let child_attempt_id = validate_fccp(fccp_bytes)
        .map_err(|e| AttemptGrantError::Proof(format!("FCCP structural validation: {e}")))?;
    Ok(VerifiedClientAdmissionProof {
        child_attempt_id,
        proof_bytes: fccp_bytes.to_vec(),
    })
}

/// Compute the FCDO signature pre-hash input: `SHA-256(domain || body)`.
pub fn fcdo_signature_hash(body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FCDO_DOMAIN);
    hash.update(body);
    hash.finalize().into()
}

/// Compute the FCCP signature pre-hash input: `SHA-256(domain || body)`.
pub fn fccp_signature_hash(body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FCCP_DOMAIN);
    hash.update(body);
    hash.finalize().into()
}

/// Compute the FCFP per-endpoint signature pre-hash input:
/// `SHA-256(FCFP_DOMAIN || bytes[0..249])`.
pub fn fcfp_signature_hash(signed_prefix: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FCFP_DOMAIN);
    hash.update(signed_prefix);
    hash.finalize().into()
}

// ---------------------------------------------------------------------------
// Final-proof gate
// ---------------------------------------------------------------------------

/// Caller-supplied expectations for the endpoint-proof gate. Every value is
/// known independently by the daemon (the verified grant, the resolved
/// certificate keys, the locally-reconstructed negotiation digest and transport
/// binding) and pinned exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalProofExpectations {
    /// SHA-256 of the verified grant's compact JWS.
    pub grant_digest: [u8; 32],
    /// The child attempt id both proofs must carry.
    pub child_attempt_id: [u8; 16],
    /// The transport tag (1 = webrtc, 2 = websocket-data) both proofs must
    /// carry; it must be authorized by `authorized_transports`.
    pub transport_tag: u8,
    /// The verified grant's authorized transport bits (a ceiling).
    pub authorized_transports: u8,
    /// The transport epoch both proofs must carry (agreement bytes 17..33).
    pub transport_epoch: [u8; 16],
    /// The locally-reconstructed negotiation digest (agreement bytes 73..105).
    pub negotiation_digest: [u8; 32],
    /// The opaque 96-byte transport binding supplied by the transport layer.
    pub transport_binding: [u8; 96],
    /// The certificate-verified client endpoint key.
    pub client_key: Es256PublicKey,
    /// The certificate-verified daemon endpoint key.
    pub daemon_key: Es256PublicKey,
    /// The verified grant's client certificate id / generation.
    pub client_certificate_id: [u8; 16],
    pub client_certificate_generation: u64,
    /// The verified grant's daemon certificate id / generation.
    pub daemon_certificate_id: [u8; 16],
    pub daemon_certificate_generation: u64,
}

/// The final-proof gate consumes the two exact stored proof events plus their
/// set digest, verifies both FCFP endpoint signatures against the
/// caller-resolved keys, and binds every agreement field to caller
/// expectations before lanes/application bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointProofGate {
    pub client_proof: RemoteEndpointFinalProofV1,
    pub daemon_proof: RemoteEndpointFinalProofV1,
    pub set_digest: [u8; 32],
    client_grant_digest: [u8; 32],
    child_attempt_id: [u8; 16],
    transport_epoch: [u8; 16],
}

impl EndpointProofGate {
    /// Consume the two exact stored proof bytes and verify structure, roles,
    /// agreement equality, set digest, FCFP endpoint signatures, and every
    /// caller expectation. Any mismatch is a hard error, never a retry.
    pub fn consume(
        client_proof_bytes: &[u8],
        daemon_proof_bytes: &[u8],
        expected: &FinalProofExpectations,
    ) -> Result<Self, AttemptGrantError> {
        // The transport tag must be a single valid transport authorized by the
        // grant's transport bits.
        if expected.transport_tag != 1 && expected.transport_tag != 2 {
            return Err(AttemptGrantError::FinalProof(
                "transport tag must be 1 (webrtc) or 2 (websocket-data)".into(),
            ));
        }
        if expected.authorized_transports & expected.transport_tag != expected.transport_tag {
            return Err(AttemptGrantError::FinalProof(
                "transport tag is not authorized by the verified grant".into(),
            ));
        }

        let set_digest = final_proof_set_digest(client_proof_bytes, daemon_proof_bytes)
            .map_err(|e| AttemptGrantError::FinalProof(format!("set digest: {e}")))?;

        let client_proof = RemoteEndpointFinalProofV1::decode(client_proof_bytes)
            .map_err(|e| AttemptGrantError::FinalProof(format!("client proof decode: {e}")))?;
        let daemon_proof = RemoteEndpointFinalProofV1::decode(daemon_proof_bytes)
            .map_err(|e| AttemptGrantError::FinalProof(format!("daemon proof decode: {e}")))?;

        if client_proof.role != 1 {
            return Err(AttemptGrantError::FinalProof(format!(
                "client proof role must be 1, got {}",
                client_proof.role
            )));
        }
        if daemon_proof.role != 2 {
            return Err(AttemptGrantError::FinalProof(format!(
                "daemon proof role must be 2, got {}",
                daemon_proof.role
            )));
        }

        if client_proof.agreement != daemon_proof.agreement {
            return Err(AttemptGrantError::FinalProof(
                "client and daemon proof agreements must match".into(),
            ));
        }
        if client_proof.child_attempt_id != daemon_proof.child_attempt_id {
            return Err(AttemptGrantError::FinalProof(
                "client and daemon proof child attempt IDs must match".into(),
            ));
        }

        // Transport tag pinned on both proofs.
        if client_proof.transport != expected.transport_tag {
            return Err(AttemptGrantError::FinalProof(
                "proof transport tag does not match expected/authorized transport".into(),
            ));
        }

        // Bind agreement fields to caller expectations.
        let agr = &client_proof.agreement;
        let grant_digest: [u8; 32] = agr[AGR_GRANT_DIGEST]
            .try_into()
            .map_err(|_| AttemptGrantError::FinalProof("grant digest extraction".into()))?;
        let transport_epoch: [u8; 16] = agr[AGR_EPOCH]
            .try_into()
            .map_err(|_| AttemptGrantError::FinalProof("transport epoch extraction".into()))?;
        let negotiation_digest: [u8; 32] = agr[AGR_NEGOTIATION_DIGEST]
            .try_into()
            .map_err(|_| AttemptGrantError::FinalProof("negotiation digest extraction".into()))?;
        let binding: [u8; 96] = agr[AGR_BINDING]
            .try_into()
            .map_err(|_| AttemptGrantError::FinalProof("binding extraction".into()))?;

        if grant_digest != expected.grant_digest {
            return Err(AttemptGrantError::FinalProof(
                "proof grantDigest does not match verified grant".into(),
            ));
        }
        if client_proof.child_attempt_id != expected.child_attempt_id {
            return Err(AttemptGrantError::FinalProof(
                "proof childAttemptId does not match expectation".into(),
            ));
        }
        if transport_epoch != expected.transport_epoch {
            return Err(AttemptGrantError::FinalProof(
                "proof transportEpoch does not match expectation".into(),
            ));
        }
        if negotiation_digest != expected.negotiation_digest {
            return Err(AttemptGrantError::FinalProof(
                "proof negotiationDigest does not match expectation".into(),
            ));
        }
        if binding != expected.transport_binding {
            return Err(AttemptGrantError::FinalProof(
                "proof transport binding does not match expectation".into(),
            ));
        }

        // Bind certificate id / generation to the verified grant identities.
        check_certificate(
            client_proof_bytes,
            &expected.client_certificate_id,
            expected.client_certificate_generation,
            "client",
        )?;
        check_certificate(
            daemon_proof_bytes,
            &expected.daemon_certificate_id,
            expected.daemon_certificate_generation,
            "daemon",
        )?;

        // Verify both FCFP endpoint signatures against the resolved keys.
        verify_fcfp_signature(client_proof_bytes, &expected.client_key, "client")?;
        verify_fcfp_signature(daemon_proof_bytes, &expected.daemon_key, "daemon")?;

        Ok(Self {
            client_proof,
            daemon_proof,
            set_digest,
            client_grant_digest: grant_digest,
            child_attempt_id: expected.child_attempt_id,
            transport_epoch,
        })
    }

    /// The transport epoch shared by both proofs (agreement bytes 17..33),
    /// returned by value.
    pub fn transport_epoch(&self) -> [u8; 16] {
        self.transport_epoch
    }

    /// The grant digest both proofs bind to.
    pub fn grant_digest(&self) -> [u8; 32] {
        self.client_grant_digest
    }

    /// The child attempt id both proofs bind to.
    pub fn child_attempt_id(&self) -> [u8; 16] {
        self.child_attempt_id
    }
}

fn check_certificate(
    proof_bytes: &[u8],
    expected_id: &[u8; 16],
    expected_generation: u64,
    role: &str,
) -> Result<(), AttemptGrantError> {
    if proof_bytes.len() != FCFP_TOTAL_LEN {
        return Err(AttemptGrantError::FinalProof(format!(
            "{role} proof length"
        )));
    }
    let cert_id = &proof_bytes[FCFP_CERT_ID];
    if cert_id != expected_id.as_slice() {
        return Err(AttemptGrantError::FinalProof(format!(
            "{role} proof certificate id does not match grant identity"
        )));
    }
    let generation = u64::from_be_bytes(
        proof_bytes[FCFP_CERT_GEN]
            .try_into()
            .map_err(|_| AttemptGrantError::FinalProof("certificate generation".into()))?,
    );
    if generation != expected_generation {
        return Err(AttemptGrantError::FinalProof(format!(
            "{role} proof certificate generation does not match grant identity"
        )));
    }
    Ok(())
}

fn verify_fcfp_signature(
    proof_bytes: &[u8],
    key: &Es256PublicKey,
    role: &str,
) -> Result<(), AttemptGrantError> {
    if proof_bytes.len() != FCFP_TOTAL_LEN {
        return Err(AttemptGrantError::FinalProof(format!(
            "{role} proof length"
        )));
    }
    let hash = fcfp_signature_hash(&proof_bytes[0..FCFP_SIGNED_LEN]);
    let signature = &proof_bytes[FCFP_SIGNATURE];
    verify_es256_p1363(key, &hash, signature).map_err(|_| {
        AttemptGrantError::FinalProof(format!("{role} proof FCFP signature verification failed"))
    })
}

// ---------------------------------------------------------------------------
// Principal construction
// ---------------------------------------------------------------------------

/// The daemon is the final verifier and principal constructor. After
/// independently verifying the grant JWS (`verify_attempt_grant`), the
/// certificate chains/status, the bilateral admission result, and the final
/// proof, the daemon derives a `ClientPrincipal` **from the verified permission
/// ceiling** — never a hardcoded `Owner`.
///
/// Because `VerifiedAttemptGrant` is sealed, this function is only reachable
/// through the full verification ceremony. It re-asserts that the gate's proofs
/// bind this grant's digest and child attempt id before constructing anything,
/// then builds an `AttemptGrant` principal carrying the typed ceiling verbatim.
/// A grant can never produce `Owner`.
pub fn construct_principal_from_grant(
    grant: &VerifiedAttemptGrant,
    gate: &EndpointProofGate,
) -> Result<ClientPrincipal, AttemptGrantError> {
    if gate.grant_digest() != grant.grant_digest() {
        return Err(AttemptGrantError::FinalProof(
            "endpoint proof gate does not bind this grant's digest".into(),
        ));
    }
    if gate.child_attempt_id() != grant.child_attempt_id() {
        return Err(AttemptGrantError::FinalProof(
            "endpoint proof gate does not bind this grant's child attempt id".into(),
        ));
    }

    let alias = account_alias(&grant.account_id());
    let ceiling = RemoteCeilingAuthorization {
        attachment_capabilities: grant.permission_ceiling().attachment_capabilities.clone(),
        projects: grant.permission_ceiling().projects.clone(),
    };
    let device_binding = GrantDeviceBinding {
        client_device_id: grant.client_identity().device_id,
        client_certificate_id: grant.client_identity().certificate_id,
        client_generation: grant.client_identity().generation,
        logical_attachment_id: grant.logical_attachment_id(),
        child_attempt_id: grant.child_attempt_id(),
    };
    // `actor_binding` is left `None` on the grant path: it is never sourced from
    // a relay envelope (see the module guard scans), and the verified device
    // binding above carries the device/attachment identity instead.
    let authorization = AttemptGrantAuthorization {
        account_alias: alias.clone(),
        ceiling,
        device_binding,
    };
    Ok(ClientPrincipal::from_attempt_grant(
        alias,
        authorization,
        None,
    ))
}

#[cfg(all(test, feature = "remote"))]
mod tests;
