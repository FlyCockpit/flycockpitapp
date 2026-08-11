//! Remote identity enrollment and lifecycle service — protocol surface.
//!
//! This module owns the phishing-resistant enrollment, certificate-lifecycle,
//! revocation, and server-side state-machine *protocol surface* that consumes
//! the canonical durable remote-identity foundation. Platform-specific
//! private-key custody remains in separate browser, native, and daemon prompts
//! (consumed through the [`RemoteIdentityCustodyProvider`] seam below); no
//! cross-platform abstraction silently weakens a platform.
//!
//! ## What this module owns
//!
//! - The SAS-V1 shared-authentication-code derivation (fixed HKDF inputs,
//!   40-bit big-endian rejection sampling, exhaustion rule, display format,
//!   and the committed cross-language vectors).
//! - Strict enrollment discovery-link parsing/formatting (exact HTTPS and
//!   typed deep-link bytes/order/length/origin, single-use discovery
//!   capability, no extra parameters).
//! - The platform-neutral [`RemoteIdentityCustodyProvider`] seam: durable
//!   P-256-only signing handles that never return private bytes and report the
//!   foundation-owned `RemoteIdentityCustodyClassV1` / `RemoteIdentityPresenceModeV1`
//!   discriminants. No X25519/DH provider is exposed here — `cockpit-noise`
//!   exclusively owns fresh per-child X25519 creation, use, and destruction.
//! - The closed enrollment/certificate-lifecycle/revocation state and
//!   terminal-reason enums consumed by the server-side state machines, plus
//!   the closed `enroll | renew | rotate` action reducer shared with the
//!   tenant signer.
//! - Foundation consumption and closed-surface guards that statically reject a
//!   second local identity schema, enum, challenge, or signature-input
//!   definition.
//!
//! ## What this module does NOT own
//!
//! It never redefines the foundation certificate/FCIP/FCEN/FCCE/FCPC/FCPP/FCCF
//! codecs, identity enums, challenges, or signature inputs — those live in
//! [`crate::remote_identity_protocol`]. It never transmits private keys and
//! never logs matching codes, enrollment capabilities, certificate bodies, or
//! full public-key material.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::remote_identity_protocol as identity;

/// Wire/constants reused from the foundation identity protocol.
pub use crate::remote_identity_protocol::{
    CustodyClass as RemoteIdentityCustodyClassV1, CustodyEvidence as RemoteIdentityCustodyEvidenceV1,
    EnrollmentRole as RemoteEnrollmentRoleV1, PresenceMode as RemoteIdentityPresenceModeV1,
    SubjectKind as RemoteSubjectKindV1,
};

type HmacSha256 = Hmac<Sha256>;

// ─────────────────────────────────────────────────────────────────────────
// SAS-V1 shared authentication code
// ─────────────────────────────────────────────────────────────────────────

/// HKDF prefix: `flycockpit-remote-enrollment-sas-v1` (UTF-8, no NUL).
pub const SAS_V1_PREFIX: &[u8] = b"flycockpit-remote-enrollment-sas-v1";

/// Single NUL separator byte (`0x00`) used between HKDF label segments.
pub const SAS_V1_NUL: u8 = 0x00;

/// HKDF output length in bytes: 8160 bytes = 1632 nonoverlapping five-byte
/// blocks (the exhaustion ceiling).
pub const SAS_V1_OKM_LEN: usize = 8160;

/// Number of nonoverlapping five-byte blocks read from the HKDF OKM before
/// exhaustion is terminal [`SasError::DerivationFailed`].
pub const SAS_V1_BLOCK_COUNT: usize = 1632;

/// Rejection threshold: 40-bit big-endian block values `>=` this constant are
/// rejected and the next block is read.
pub const SAS_V1_REJECT_THRESHOLD: u64 = 1_090_000_000_000;

/// Modulus used to reduce the first accepted 40-bit block to ten decimal
/// digits: `n mod 10_000_000_000`.
pub const SAS_V1_MODULUS: u64 = 10_000_000_000;

/// Displayed digit width (zero-padded): `12345 67890`.
pub const SAS_V1_DIGITS: usize = 10;

/// Committed salt preimage: `prefix || NUL || "salt"`.
pub const SAS_V1_SALT_PREIMAGE: &[u8] = b"flycockpit-remote-enrollment-sas-v1\x00salt";

/// Committed info preimage: `prefix || NUL || "digits" || NUL || "v1"`.
pub const SAS_V1_INFO_PREIMAGE: &[u8] = b"flycockpit-remote-enrollment-sas-v1\x00digits\x00v1";

/// Committed salt digest (`SHA-256(SAS_V1_SALT_PREIMAGE)`):
/// `5927e846e8ccc0210d666fa104e2aa7af9dcda3039ee97cae6b2978cc97b0508`.
pub const SAS_V1_SALT_DIGEST: [u8; 32] = [
    0x59, 0x27, 0xe8, 0x46, 0xe8, 0xcc, 0xc0, 0x21, 0x0d, 0x66, 0x6f, 0xa1, 0x04, 0xe2, 0xaa, 0x7a,
    0xf9, 0xdc, 0xda, 0x30, 0x39, 0xee, 0x97, 0xca, 0xe6, 0xb2, 0x97, 0x8c, 0xc9, 0x7b, 0x05, 0x08,
];

/// Two-byte sequence `\0` (ASCII backslash + `0`, hex `5c 30`) that MUST NOT
/// appear in a canonical SAS preimage — the separator is a literal NUL byte,
/// never its escaped form. The committed-vector guard rejects any preimage
/// where a `0x00` separator is replaced by `5c30`.
pub const SAS_V1_FORBIDDEN_ESCAPE: [u8; 2] = [0x5c, 0x30];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SasError {
    /// Exhausting all 1632 five-byte blocks without an accepted value is
    /// terminal `sas_derivation_failed`.
    #[error("sas derivation failed: no accepted block within 1632 five-byte blocks")]
    DerivationFailed,
    /// A preimage contained the forbidden `\0` escape (`5c30`) in place of a
    /// NUL separator, an ASCII `0` byte, or a backslash.
    #[error("invalid sas preimage: forbidden escape or digit byte present")]
    InvalidPreimage,
}

/// Build the canonical SAS-V1 HKDF salt preimage:
/// `prefix || NUL || "salt"`.
///
/// The returned bytes never contain a backslash (`0x5c`) or ASCII `0` (`0x30`)
/// byte; the only separator is the literal NUL (`0x00`).
pub fn sas_v1_salt_preimage() -> Vec<u8> {
    let mut buf = Vec::with_capacity(SAS_V1_PREFIX.len() + 1 + 4);
    buf.extend_from_slice(SAS_V1_PREFIX);
    buf.push(SAS_V1_NUL);
    buf.extend_from_slice(b"salt");
    assert_sas_preimage_invariants(&buf);
    buf
}

/// Build the canonical SAS-V1 HKDF info preimage:
/// `prefix || NUL || "digits" || NUL || "v1"`.
pub fn sas_v1_info_preimage() -> Vec<u8> {
    let mut buf = Vec::with_capacity(SAS_V1_PREFIX.len() + 1 + 6 + 1 + 2);
    buf.extend_from_slice(SAS_V1_PREFIX);
    buf.push(SAS_V1_NUL);
    buf.extend_from_slice(b"digits");
    buf.push(SAS_V1_NUL);
    buf.extend_from_slice(b"v1");
    assert_sas_preimage_invariants(&buf);
    buf
}

/// Assert that a SAS preimage contains no backslash, no ASCII `0` byte, and no
/// `\0` escape (`5c30`); the only permitted separator is a literal NUL.
fn assert_sas_preimage_invariants(bytes: &[u8]) {
    assert!(
        !bytes.contains(&0x5c),
        "SAS preimage must not contain a backslash"
    );
    assert!(
        !bytes.contains(&b'0'),
        "SAS preimage must not contain an ASCII '0' byte"
    );
    // No `5c30` run can exist because there is no `0x5c` at all.
    let _ = SAS_V1_FORBIDDEN_ESCAPE;
}

/// Validate that a candidate preimage uses literal NUL separators and never the
/// `\0` escape (`5c30`), a backslash, or an ASCII `0` byte. Used by the
/// committed-vector guard to prove replacing a `0x00` separator with `5c30`
/// fails.
pub fn validate_sas_preimage(bytes: &[u8]) -> Result<(), SasError> {
    if bytes.contains(&0x5c) || bytes.contains(&b'0') {
        return Err(SasError::InvalidPreimage);
    }
    // Reject the explicit `5c30` run even though no `0x5c` is permitted above;
    // this makes the committed-replacement guard exact.
    for window in bytes.windows(2) {
        if window == SAS_V1_FORBIDDEN_ESCAPE {
            return Err(SasError::InvalidPreimage);
        }
    }
    Ok(())
}

/// HKDF-Extract(salt, IKM) per RFC 5869 with SHA-256.
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    // RFC 5869: PRK = HMAC-Hash(salt, IKM). When salt is empty, a string of
    // HashLen zero bytes is used; SAS-V1 always supplies a nonempty salt.
    let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(ikm);
    mac.finalize()
        .into_bytes()
        .as_slice()
        .try_into()
        .expect("HMAC-SHA256 output is 32 bytes")
}

/// HKDF-Expand(PRK, info, L) per RFC 5869 with SHA-256.
///
/// Panics if `l` exceeds `255 * 32` (the RFC 5869 expansion ceiling). SAS-V1
/// requests `L = 8160`, well within the ceiling.
fn hkdf_expand(prk: &[u8; 32], info: &[u8], l: usize) -> Vec<u8> {
    assert!(
        l <= 255 * 32,
        "HKDF-Expand length exceeds 255 * HashLen ceiling"
    );
    let mut okm = Vec::with_capacity(l);
    let mut previous: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while okm.len() < l {
        let mut mac = HmacSha256::new_from_slice(prk).expect("HMAC accepts any key length");
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter]);
        let t = mac.finalize().into_bytes();
        previous = t.as_slice().to_vec();
        okm.extend_from_slice(&previous);
        // SAFETY: the outer `assert!` bounds `l` to 255*32, so at most 255
        // iterations are required and `counter` cannot exceed 255 before the
        // loop terminates.
        counter = counter.wrapping_add(1);
    }
    okm.truncate(l);
    okm
}

/// Compute the complete SAS-V1 HKDF OKM (`L = 8160`) from a transcript digest.
///
/// `transcript_digest` is `SHA-256(the complete canonical FCEN bytes)` — never
/// a partial or reinterpreted transcript. The salt and info preimages are the
/// committed canonical bytes; replacements are rejected by
/// [`validate_sas_preimage`].
pub fn sas_v1_okm(transcript_digest: &[u8; 32]) -> Vec<u8> {
    let salt_preimage = sas_v1_salt_preimage();
    let info_preimage = sas_v1_info_preimage();
    let salt = Sha256::digest(&salt_preimage);
    let prk = hkdf_extract(&salt, transcript_digest);
    hkdf_expand(&prk, &info_preimage, SAS_V1_OKM_LEN)
}

/// A derived SAS-V1 code: the ten-digit zero-padded integer plus the first
/// accepted 40-bit block index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SasV1 {
    /// The accepted 40-bit big-endian block value, before modulus reduction.
    pub accepted_block: u64,
    /// Zero-based index of the accepted block within the 1632-block OKM.
    pub accepted_index: usize,
    /// The ten-digit zero-padded decimal string (`n mod 10_000_000_000`).
    pub digits: String,
}

impl SasV1 {
    /// Display the code as `12345 67890` (five digits, space, five digits).
    pub fn display(&self) -> String {
        debug_assert_eq!(self.digits.len(), SAS_V1_DIGITS);
        format!("{} {}", &self.digits[..5], &self.digits[5..])
    }
}

/// Derive the SAS-V1 code from a transcript digest by reading consecutive
/// nonoverlapping five-byte blocks as unsigned 40-bit big-endian integers,
/// rejecting values `>= 1_090_000_000_000`, and returning the first accepted
/// value reduced mod `10_000_000_000` zero-padded to ten digits.
///
/// Exhausting all 1632 blocks without an accepted value is terminal
/// [`SasError::DerivationFailed`].
pub fn derive_sas_v1(transcript_digest: &[u8; 32]) -> Result<SasV1, SasError> {
    let okm = sas_v1_okm(transcript_digest);
    for (index, block) in okm.chunks_exact(5).enumerate() {
        if index >= SAS_V1_BLOCK_COUNT {
            break;
        }
        let mut buf = [0u8; 8];
        buf[3..8].copy_from_slice(block);
        let value = u64::from_be_bytes(buf);
        if value < SAS_V1_REJECT_THRESHOLD {
            let reduced = value % SAS_V1_MODULUS;
            return Ok(SasV1 {
                accepted_block: value,
                accepted_index: index,
                digits: format!("{reduced:0>10}"),
            });
        }
    }
    Err(SasError::DerivationFailed)
}

// ─────────────────────────────────────────────────────────────────────────
// Enrollment discovery links
// ─────────────────────────────────────────────────────────────────────────

/// Enrollment link protocol version query value. The link is the only place the
/// discovery capability ever appears as a bearer value, and the link is
/// single-use, never logged or referrer-propagated.
pub const ENROLLMENT_LINK_VERSION: u8 = 1;

/// Length of the random enrollment ID (`enrollmentId`): 16 bytes, base64url
/// without padding → 22 characters.
pub const ENROLLMENT_ID_LEN: usize = 16;

/// Length of the random discovery capability (`cap`): 32 bytes, base64url
/// without padding → 43 characters.
pub const DISCOVERY_CAPABILITY_LEN: usize = 32;

/// Lowercase discovery path shared by both link kinds.
pub const ENROLLMENT_LINK_PATH: &str = "/remote/enroll";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnrollmentLinkError {
    #[error("malformed enrollment link: {0}")]
    Malformed(String),
    #[error("invalid enrollment link origin: {0}")]
    Origin(String),
}

/// A parsed single-use enrollment discovery link.
///
/// Redis stores only `SHA-256(capability)`; the raw capability is accepted only
/// by redemption and never logged, referrer-propagated, or placed in another
/// authorization scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentDiscoveryLink {
    /// Normalized HTTPS origin (`https://<configured-public-origin>`).
    pub public_origin: String,
    /// Random 16-byte enrollment ID.
    pub enrollment_id: [u8; 16],
    /// Random 32-byte discovery capability.
    pub discovery_capability: [u8; 32],
}

impl EnrollmentDiscoveryLink {
    /// Build the exact HTTPS QR/universal link:
    /// `https://<origin>/remote/enroll?v=1&id=<base64url-16>&cap=<base64url-32>`.
    ///
    /// Query keys/order, lowercase path, base64url-without-padding lengths,
    /// exact origin, and no extra parameters are mandatory.
    pub fn https_url(&self) -> String {
        // `public_origin` is stored as a normalized `https://` origin; the link
        // format requires a single `https://` prefix followed by the bare
        // authority, so strip the stored scheme and re-emit it exactly once.
        let authority = self
            .public_origin
            .strip_prefix("https://")
            .expect("validated origin starts with https://");
        format!(
            "https://{}{}?v={}&id={}&cap={}",
            authority,
            ENROLLMENT_LINK_PATH,
            ENROLLMENT_LINK_VERSION,
            URL_SAFE_NO_PAD.encode(self.enrollment_id),
            URL_SAFE_NO_PAD.encode(self.discovery_capability),
        )
    }

    /// Build the exact typed deep link:
    /// `flycockpit://remote/enroll?v=1&id=<base64url-16>&cap=<base64url-32>`.
    pub fn deep_link(&self) -> String {
        format!(
            "flycockpit://remote/enroll?v={}&id={}&cap={}",
            ENROLLMENT_LINK_VERSION,
            URL_SAFE_NO_PAD.encode(self.enrollment_id),
            URL_SAFE_NO_PAD.encode(self.discovery_capability),
        )
    }
}

/// Validate a normalized HTTPS public origin (lowercase, no trailing slash, no
/// path/query/fragment, no `:443`). Mirrors the foundation origin rules.
fn validate_link_origin(origin: &str) -> Result<(), EnrollmentLinkError> {
    let authority = origin.strip_prefix("https://").ok_or_else(|| {
        EnrollmentLinkError::Origin("origin must use HTTPS".into())
    })?;
    if !(1..=255).contains(&origin.len())
        || authority.is_empty()
        || authority
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_uppercase())
        || authority.contains(['/', '?', '#', '@'])
        || authority.ends_with(":443")
    {
        return Err(EnrollmentLinkError::Origin(
            "origin must be a normalized HTTPS origin".into(),
        ));
    }
    let host = authority.split_once(':').map_or(authority, |(host, port)| {
        if port.is_empty()
            || port.starts_with('0')
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().is_err()
        {
            ""
        } else {
            host
        }
    });
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        return Err(EnrollmentLinkError::Origin("origin host is noncanonical".into()));
    }
    Ok(())
}

/// Construct a discovery link from its parts, validating the origin and ID
/// lengths. The enrollment ID and capability MUST be random and nonzero.
pub fn build_discovery_link(
    public_origin: &str,
    enrollment_id: [u8; 16],
    discovery_capability: [u8; 32],
) -> Result<EnrollmentDiscoveryLink, EnrollmentLinkError> {
    validate_link_origin(public_origin)?;
    if enrollment_id.iter().all(|&b| b == 0) {
        return Err(EnrollmentLinkError::Malformed("enrollmentId is zero".into()));
    }
    if discovery_capability.iter().all(|&b| b == 0) {
        return Err(EnrollmentLinkError::Malformed(
            "discovery capability is zero".into(),
        ));
    }
    Ok(EnrollmentDiscoveryLink {
        public_origin: public_origin.to_string(),
        enrollment_id,
        discovery_capability,
    })
}

/// Strictly parse an HTTPS enrollment discovery link.
///
/// Accepts only the exact bytes/order/length/origin: scheme `https`, lowercase
/// path `/remote/enroll`, query keys `v=1`, `id=<base64url-16>`,
/// `cap=<base64url-32>` in that order, and no extra parameters, fragments, or
/// padding. Malformed/extra/padded variants are rejected.
pub fn parse_https_enrollment_link(url: &str) -> Result<EnrollmentDiscoveryLink, EnrollmentLinkError> {
    let (origin, query) = url
        .split_once(ENROLLMENT_LINK_PATH)
        .ok_or_else(|| EnrollmentLinkError::Malformed("missing lowercase /remote/enroll path".into()))?;
    let origin = origin
        .strip_prefix("https://")
        .ok_or_else(|| EnrollmentLinkError::Malformed("link must use https".into()))?;
    if origin.is_empty() {
        return Err(EnrollmentLinkError::Malformed("empty origin".into()));
    }
    let full_origin = format!("https://{origin}");
    validate_link_origin(&full_origin)?;
    let query = query.strip_prefix('?').ok_or_else(|| {
        EnrollmentLinkError::Malformed("query must begin with '?' immediately after path".into())
    })?;
    // No fragment permitted.
    if query.contains('#') {
        return Err(EnrollmentLinkError::Malformed("fragment rejected".into()));
    }
    let mut parts = query.split('&');
    let v = parts
        .next()
        .ok_or_else(|| EnrollmentLinkError::Malformed("missing v parameter".into()))?;
    if v != "v=1" {
        return Err(EnrollmentLinkError::Malformed("v must be 1".into()));
    }
    let id_part = parts
        .next()
        .ok_or_else(|| EnrollmentLinkError::Malformed("missing id parameter".into()))?;
    let id_value = id_part
        .strip_prefix("id=")
        .ok_or_else(|| EnrollmentLinkError::Malformed("id parameter malformed".into()))?;
    let cap_part = parts
        .next()
        .ok_or_else(|| EnrollmentLinkError::Malformed("missing cap parameter".into()))?;
    let cap_value = cap_part
        .strip_prefix("cap=")
        .ok_or_else(|| EnrollmentLinkError::Malformed("cap parameter malformed".into()))?;
    if parts.next().is_some() {
        return Err(EnrollmentLinkError::Malformed("extra query parameters rejected".into()));
    }
    let enrollment_id = decode_b64url_fixed::<16>(id_value, "enrollmentId")?;
    let discovery_capability = decode_b64url_fixed::<32>(cap_value, "capability")?;
    if enrollment_id.iter().all(|&b| b == 0) {
        return Err(EnrollmentLinkError::Malformed("enrollmentId is zero".into()));
    }
    if discovery_capability.iter().all(|&b| b == 0) {
        return Err(EnrollmentLinkError::Malformed("capability is zero".into()));
    }
    Ok(EnrollmentDiscoveryLink {
        public_origin: full_origin,
        enrollment_id,
        discovery_capability,
    })
}

/// Strictly parse a typed deep link `flycockpit://remote/enroll?v=1&id=...&cap=...`.
pub fn parse_deep_enrollment_link(url: &str) -> Result<EnrollmentDiscoveryLink, EnrollmentLinkError> {
    let rest = url
        .strip_prefix("flycockpit://remote/enroll")
        .ok_or_else(|| EnrollmentLinkError::Malformed("deep link must start with flycockpit://remote/enroll".into()))?;
    let query = rest.strip_prefix('?').ok_or_else(|| {
        EnrollmentLinkError::Malformed("deep link query must begin with '?'".into())
    })?;
    if query.contains('#') {
        return Err(EnrollmentLinkError::Malformed("fragment rejected".into()));
    }
    let mut parts = query.split('&');
    if parts.next() != Some("v=1") {
        return Err(EnrollmentLinkError::Malformed("v must be 1".into()));
    }
    let id_value = parts
        .next()
        .and_then(|p| p.strip_prefix("id="))
        .ok_or_else(|| EnrollmentLinkError::Malformed("id parameter malformed".into()))?;
    let cap_value = parts
        .next()
        .and_then(|p| p.strip_prefix("cap="))
        .ok_or_else(|| EnrollmentLinkError::Malformed("cap parameter malformed".into()))?;
    if parts.next().is_some() {
        return Err(EnrollmentLinkError::Malformed("extra query parameters rejected".into()));
    }
    let enrollment_id = decode_b64url_fixed::<16>(id_value, "enrollmentId")?;
    let discovery_capability = decode_b64url_fixed::<32>(cap_value, "capability")?;
    if enrollment_id.iter().all(|&b| b == 0) {
        return Err(EnrollmentLinkError::Malformed("enrollmentId is zero".into()));
    }
    if discovery_capability.iter().all(|&b| b == 0) {
        return Err(EnrollmentLinkError::Malformed("capability is zero".into()));
    }
    // Deep links carry no origin; reuse a placeholder canonical origin for the
    // typed value so the structured link round-trips through the HTTPS printer
    // only when an explicit origin is supplied by the caller.
    Ok(EnrollmentDiscoveryLink {
        public_origin: String::new(),
        enrollment_id,
        discovery_capability,
    })
}

fn decode_b64url_fixed<const N: usize>(
    value: &str,
    field: &str,
) -> Result<[u8; N], EnrollmentLinkError> {
    if value.is_empty() || value.contains('=') {
        return Err(EnrollmentLinkError::Malformed(format!(
            "{field} must be unpadded base64url"
        )));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| EnrollmentLinkError::Malformed(format!("{field} is not valid base64url")))?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(EnrollmentLinkError::Malformed(format!(
            "{field} is noncanonical base64url"
        )));
    }
    decoded
        .try_into()
        .map_err(|_| EnrollmentLinkError::Malformed(format!("{field} has wrong length")))
}

// ─────────────────────────────────────────────────────────────────────────
// RemoteIdentityCustodyProvider seam
// ─────────────────────────────────────────────────────────────────────────

/// A durable, non-exportable P-256 signing identity handle.
///
/// Handles are opaque to the control plane: they sign only the
/// foundation-defined inputs through [`RemoteIdentityCustodyProvider`] and
/// never expose their private bytes. A handle is stable across certificate
/// renewal and is destroyed (not exported) on rotation or device loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RemoteIdentityCustodyHandleId(pub [u8; 16]);

impl RemoteIdentityCustodyHandleId {
    /// True when the handle ID is the all-zero sentinel (never allocated).
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

/// The P-256 public key of a durable custody handle, in uncompressed
/// coordinates. X25519/DH keys are categorically absent from this surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteIdentityP256PublicKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// A typed custody-provider failure. A provider must complete capability proof
/// before Redis allocation and return an actionable typed failure; it never
/// generates a weaker replacement.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RemoteIdentityCustodyError {
    #[error("custody provider unavailable: {0}")]
    Unavailable(String),
    #[error("custody provider rejected evidence: {0}")]
    InvalidEvidence(String),
    #[error("custody provider policy denied: {0}")]
    PolicyDenied(String),
    #[error("custody provider does not permit exporting private bytes")]
    PrivateBytesNotExportable,
    #[error("custody handle not found")]
    NotFound,
}

/// The platform-neutral durable-P-256 custody provider seam.
///
/// Browser, native, and daemon durable-P-256 matrices belong to the custody
/// prompts and implement this trait. This package and all custody prompts
/// expose no X25519/DH provider: `cockpit-noise` exclusively owns fresh
/// per-child X25519 creation, use, and destruction after the Noise foundation
/// lands.
///
/// Every method signs only the foundation-defined inputs without returning
/// private bytes and reports the foundation-owned closed
/// [`RemoteIdentityCustodyClassV1`] and [`RemoteIdentityPresenceModeV1`] values.
/// Custody prompts consume those discriminants and
/// [`RemoteIdentityCustodyEvidenceV1`] rather than redefining them.
pub trait RemoteIdentityCustodyProvider {
    /// Generate a fresh durable non-exportable P-256 signing identity for a
    /// subject and report its public key, custody class, and presence mode.
    /// Private bytes never cross this seam.
    fn generate(
        &mut self,
        subject_kind: RemoteSubjectKindV1,
        custody_class: RemoteIdentityCustodyClassV1,
        presence_mode: RemoteIdentityPresenceModeV1,
        provider_evidence: &[u8],
    ) -> Result<
        (
            RemoteIdentityCustodyHandleId,
            RemoteIdentityP256PublicKey,
            RemoteIdentityCustodyEvidenceV1,
        ),
        RemoteIdentityCustodyError,
    >;

    /// Reopen an existing durable handle, returning its public key and custody
    /// discriminants without ever returning private bytes.
    fn reopen(
        &self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<
        (
            RemoteIdentityP256PublicKey,
            RemoteIdentityCustodyClassV1,
            RemoteIdentityPresenceModeV1,
        ),
        RemoteIdentityCustodyError,
    >;

    /// Rotate a durable handle to a fresh P-256 key and the next generation,
    /// destroying the old private key. The new public key and custody evidence
    /// are returned; private bytes are never exported.
    fn rotate(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        provider_evidence: &[u8],
    ) -> Result<
        (
            RemoteIdentityP256PublicKey,
            RemoteIdentityCustodyEvidenceV1,
        ),
        RemoteIdentityCustodyError,
    >;

    /// Destroy a durable handle and its private key irreversibly.
    fn destroy(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<(), RemoteIdentityCustodyError>;

    /// Sign the foundation-defined possession-proof signing digest with the
    /// durable handle, returning a low-S P1363 signature. The provider signs
    /// only the supplied digest; it never returns private bytes.
    fn sign_possession_proof(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        signing_digest: &[u8; 32],
    ) -> Result<[u8; 64], RemoteIdentityCustodyError>;

    /// Sign the foundation-defined enrollment-confirmation signing digest with
    /// the durable handle, returning a low-S P1363 signature.
    fn sign_enrollment_confirmation(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        signing_digest: &[u8; 32],
    ) -> Result<[u8; 64], RemoteIdentityCustodyError>;
}

// ─────────────────────────────────────────────────────────────────────────
// Closed enrollment/certificate-lifecycle/revocation enums
// ─────────────────────────────────────────────────────────────────────────

/// Enrollment ceremony state machine.
///
/// `state` is `reserved | awaiting_redemption | awaiting_contributions |
/// code_ready | awaiting_confirmations | authorization_pending |
/// issuance_pending | issued | rejected | expired | cancelled | superseded`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EnrollmentState {
    Reserved = 1,
    AwaitingRedemption = 2,
    AwaitingContributions = 3,
    CodeReady = 4,
    AwaitingConfirmations = 5,
    AuthorizationPending = 6,
    IssuancePending = 7,
    Issued = 8,
    Rejected = 9,
    Expired = 10,
    Cancelled = 11,
    Superseded = 12,
}

impl EnrollmentState {
    pub const ALL: [Self; 12] = [
        Self::Reserved,
        Self::AwaitingRedemption,
        Self::AwaitingContributions,
        Self::CodeReady,
        Self::AwaitingConfirmations,
        Self::AuthorizationPending,
        Self::IssuancePending,
        Self::Issued,
        Self::Rejected,
        Self::Expired,
        Self::Cancelled,
        Self::Superseded,
    ];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::AwaitingRedemption => "awaiting_redemption",
            Self::AwaitingContributions => "awaiting_contributions",
            Self::CodeReady => "code_ready",
            Self::AwaitingConfirmations => "awaiting_confirmations",
            Self::AuthorizationPending => "authorization_pending",
            Self::IssuancePending => "issuance_pending",
            Self::Issued => "issued",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Superseded => "superseded",
        }
    }
    /// True for states whose projection requires `terminalReason`.
    pub fn requires_terminal_reason(self) -> bool {
        matches!(
            self,
            Self::Rejected | Self::Expired | Self::Cancelled | Self::Superseded
        )
    }
    /// True for non-terminal states where `terminalReason` is exactly null.
    pub fn null_terminal_reason(self) -> bool {
        !self.requires_terminal_reason()
    }
}

/// Terminal reason for an unsuccessful enrollment ceremony.
///
/// `rejected` permits `explicit_reject|mismatch_limit|policy_denied|issuance_failed`,
/// `expired` requires `expired`, `cancelled` requires `cancelled`, and
/// `superseded` requires `superseded`. No other state/reason pair parses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EnrollmentTerminalReason {
    ExplicitReject = 1,
    MismatchLimit = 2,
    PolicyDenied = 3,
    IssuanceFailed = 4,
    Expired = 5,
    Cancelled = 6,
    Superseded = 7,
}

impl EnrollmentTerminalReason {
    pub const ALL: [Self; 7] = [
        Self::ExplicitReject,
        Self::MismatchLimit,
        Self::PolicyDenied,
        Self::IssuanceFailed,
        Self::Expired,
        Self::Cancelled,
        Self::Superseded,
    ];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::ExplicitReject => "explicit_reject",
            Self::MismatchLimit => "mismatch_limit",
            Self::PolicyDenied => "policy_denied",
            Self::IssuanceFailed => "issuance_failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Superseded => "superseded",
        }
    }
    /// Validate the exact state/reason pair mapping. Returns `Ok(())` only for
    /// a legal pair; otherwise an error describing the mismatch.
    pub fn validate_pair(self, state: EnrollmentState) -> Result<(), &'static str> {
        match (state, self) {
            (EnrollmentState::Rejected, _)
                if matches!(
                    self,
                    Self::ExplicitReject
                        | Self::MismatchLimit
                        | Self::PolicyDenied
                        | Self::IssuanceFailed
                ) =>
            {
                Ok(())
            }
            (EnrollmentState::Expired, Self::Expired) => Ok(()),
            (EnrollmentState::Cancelled, Self::Cancelled) => Ok(()),
            (EnrollmentState::Superseded, Self::Superseded) => Ok(()),
            _ => Err("illegal enrollment state/terminal-reason pair"),
        }
    }
}

/// Closed certificate-lifecycle action reducer shared with the tenant signer:
/// `enroll | renew | rotate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CertificateLifecycleAction {
    Enroll = 1,
    Renew = 2,
    Rotate = 3,
}

impl CertificateLifecycleAction {
    pub const ALL: [Self; 3] = [Self::Enroll, Self::Renew, Self::Rotate];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Enroll => "enroll",
            Self::Renew => "renew",
            Self::Rotate => "rotate",
        }
    }
}

/// Certificate operation state machine (renew/rotate).
///
/// `state` is `reserved | proof_pending | signer_pending | issued | denied |
/// expired | cancelled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CertificateOperationState {
    Reserved = 1,
    ProofPending = 2,
    SignerPending = 3,
    Issued = 4,
    Denied = 5,
    Expired = 6,
    Cancelled = 7,
}

impl CertificateOperationState {
    pub const ALL: [Self; 7] = [
        Self::Reserved,
        Self::ProofPending,
        Self::SignerPending,
        Self::Issued,
        Self::Denied,
        Self::Expired,
        Self::Cancelled,
    ];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::ProofPending => "proof_pending",
            Self::SignerPending => "signer_pending",
            Self::Issued => "issued",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
    pub fn requires_terminal_reason(self) -> bool {
        matches!(self, Self::Denied | Self::Expired | Self::Cancelled)
    }
    pub fn null_terminal_reason(self) -> bool {
        !self.requires_terminal_reason()
    }
}

/// Terminal reason for a denied/expired/cancelled certificate operation.
///
/// `denied` requires exactly one of
/// `invalid_current|invalid_proof|revoked|policy_denied|signer_unavailable`;
/// `expired` requires `expired`; `cancelled` requires `cancelled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CertificateOperationTerminalReason {
    InvalidCurrent = 1,
    InvalidProof = 2,
    Revoked = 3,
    PolicyDenied = 4,
    SignerUnavailable = 5,
    Expired = 6,
    Cancelled = 7,
}

impl CertificateOperationTerminalReason {
    pub const ALL: [Self; 7] = [
        Self::InvalidCurrent,
        Self::InvalidProof,
        Self::Revoked,
        Self::PolicyDenied,
        Self::SignerUnavailable,
        Self::Expired,
        Self::Cancelled,
    ];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::InvalidCurrent => "invalid_current",
            Self::InvalidProof => "invalid_proof",
            Self::Revoked => "revoked",
            Self::PolicyDenied => "policy_denied",
            Self::SignerUnavailable => "signer_unavailable",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
    pub fn validate_pair(self, state: CertificateOperationState) -> Result<(), &'static str> {
        match (state, self) {
            (CertificateOperationState::Denied, _)
                if matches!(
                    self,
                    Self::InvalidCurrent
                        | Self::InvalidProof
                        | Self::Revoked
                        | Self::PolicyDenied
                        | Self::SignerUnavailable
                ) =>
            {
                Ok(())
            }
            (CertificateOperationState::Expired, Self::Expired) => Ok(()),
            (CertificateOperationState::Cancelled, Self::Cancelled) => Ok(()),
            _ => Err("illegal certificate-operation state/terminal-reason pair"),
        }
    }
}

/// Revocation operation state machine.
///
/// `state` is `proof_pending | approval_pending | signer_pending |
/// pending_reconciliation | revoked | denied | expired | cancelled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RevocationState {
    ProofPending = 1,
    ApprovalPending = 2,
    SignerPending = 3,
    PendingReconciliation = 4,
    Revoked = 5,
    Denied = 6,
    Expired = 7,
    Cancelled = 8,
}

impl RevocationState {
    pub const ALL: [Self; 8] = [
        Self::ProofPending,
        Self::ApprovalPending,
        Self::SignerPending,
        Self::PendingReconciliation,
        Self::Revoked,
        Self::Denied,
        Self::Expired,
        Self::Cancelled,
    ];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::ProofPending => "proof_pending",
            Self::ApprovalPending => "approval_pending",
            Self::SignerPending => "signer_pending",
            Self::PendingReconciliation => "pending_reconciliation",
            Self::Revoked => "revoked",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
    pub fn requires_terminal_reason(self) -> bool {
        matches!(self, Self::Denied | Self::Expired | Self::Cancelled)
    }
}

/// Revocation terminal reason.
///
/// `denied` requires exactly one of
/// `invalid_current|invalid_proof|invalid_approval|policy_denied|signer_unavailable`;
/// `expired` requires `expired`; `cancelled` requires `cancelled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RevocationTerminalReason {
    InvalidCurrent = 1,
    InvalidProof = 2,
    InvalidApproval = 3,
    PolicyDenied = 4,
    SignerUnavailable = 5,
    Expired = 6,
    Cancelled = 7,
}

impl RevocationTerminalReason {
    pub const ALL: [Self; 7] = [
        Self::InvalidCurrent,
        Self::InvalidProof,
        Self::InvalidApproval,
        Self::PolicyDenied,
        Self::SignerUnavailable,
        Self::Expired,
        Self::Cancelled,
    ];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::InvalidCurrent => "invalid_current",
            Self::InvalidProof => "invalid_proof",
            Self::InvalidApproval => "invalid_approval",
            Self::PolicyDenied => "policy_denied",
            Self::SignerUnavailable => "signer_unavailable",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
    pub fn validate_pair(self, state: RevocationState) -> Result<(), &'static str> {
        match (state, self) {
            (RevocationState::Denied, _)
                if matches!(
                    self,
                    Self::InvalidCurrent
                        | Self::InvalidProof
                        | Self::InvalidApproval
                        | Self::PolicyDenied
                        | Self::SignerUnavailable
                ) =>
            {
                Ok(())
            }
            (RevocationState::Expired, Self::Expired) => Ok(()),
            (RevocationState::Cancelled, Self::Cancelled) => Ok(()),
            _ => Err("illegal revocation state/terminal-reason pair"),
        }
    }
}

/// Closed revocation actor mode derived from authenticated state, never the
/// body: `public_self_account`, `public_instance_owner`, `self_client`, or
/// `security_admin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RevocationActorMode {
    PublicSelfAccount = 1,
    PublicInstanceOwner = 2,
    SelfClient = 3,
    SecurityAdmin = 4,
}

impl RevocationActorMode {
    pub const ALL: [Self; 4] = [
        Self::PublicSelfAccount,
        Self::PublicInstanceOwner,
        Self::SelfClient,
        Self::SecurityAdmin,
    ];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::PublicSelfAccount => "public_self_account",
            Self::PublicInstanceOwner => "public_instance_owner",
            Self::SelfClient => "self_client",
            Self::SecurityAdmin => "security_admin",
        }
    }
}

/// Enrolled device lifecycle: `reserved | pending | active | rotation_pending |
/// revoked | deleted | abandoned`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RemoteDeviceLifecycle {
    Reserved = 1,
    Pending = 2,
    Active = 3,
    RotationPending = 4,
    Revoked = 5,
    Deleted = 6,
    Abandoned = 7,
}

impl RemoteDeviceLifecycle {
    pub const ALL: [Self; 7] = [
        Self::Reserved,
        Self::Pending,
        Self::Active,
        Self::RotationPending,
        Self::Revoked,
        Self::Deleted,
        Self::Abandoned,
    ];
    pub fn discriminant(self) -> u8 {
        self as u8
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Pending => "pending",
            Self::Active => "active",
            Self::RotationPending => "rotation_pending",
            Self::Revoked => "revoked",
            Self::Deleted => "deleted",
            Self::Abandoned => "abandoned",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Foundation consumption and closed-surface guards
// ─────────────────────────────────────────────────────────────────────────

/// Foundation consumption guard.
///
/// Statically references every foundation identity codec/enum so a second local
/// identity schema, enum, challenge, or signature-input definition fails to
/// link when this module is the sole consumer. This workflow owns no alternate
/// identity wire format.
pub fn remote_identity_protocol_consumption_guard() {
    let _ = identity::FCIP;
    let _ = identity::FCEN;
    let _ = identity::FCCE;
    let _ = identity::FCPC;
    let _ = identity::FCPP;
    let _ = identity::FCCF;
    let _ = identity::SubjectKind::Client;
    let _ = identity::SubjectKind::Daemon;
    let _ = identity::CustodyClass::OriginProtected;
    let _ = identity::PresenceMode::Unattended;
    let _ = identity::EnrollmentRole::ProposedSubject;
    let _ = identity::PossessionPurpose::EnrollProposed;
    let _ = identity::PossessionPurpose::RenewCurrent;
    let _ = identity::PossessionPurpose::RotateCurrent;
    let _ = identity::PossessionPurpose::RotateProposed;
    let _ = identity::PossessionPurpose::RevokeCurrent;
    let _ = identity::Proposal::decode as fn(&[u8]) -> _;
    let _ = identity::EnrollmentTranscript::decode as fn(&[u8]) -> _;
    let _ = identity::CustodyEvidence::decode as fn(&[u8]) -> _;
    let _ = identity::PossessionContext::decode as fn(&[u8]) -> _;
    let _ = identity::PossessionProof::decode as fn(&[u8]) -> _;
    let _ = identity::EnrollmentConfirmation::decode as fn(&[u8]) -> _;
    let _ = identity::parse_remote_identity_certificate_jws as fn(&str) -> _;
    let _ = identity::derive_possession_challenge as fn(_, _, _, _) -> _;
    let _ = identity::possession_proof_signing_digest as fn(&[u8], _) -> _;
    let _ = identity::enrollment_confirmation_signing_digest as fn(&[u8], _) -> _;
}

/// Closed-surface guard. Asserts the exact cardinality of every enum this
/// module owns so an accidental addition or removal fails loudly.
pub fn closed_surface_guard() {
    assert_eq!(EnrollmentState::ALL.len(), 12);
    assert_eq!(EnrollmentTerminalReason::ALL.len(), 7);
    assert_eq!(CertificateLifecycleAction::ALL.len(), 3);
    assert_eq!(CertificateOperationState::ALL.len(), 7);
    assert_eq!(CertificateOperationTerminalReason::ALL.len(), 7);
    assert_eq!(RevocationState::ALL.len(), 8);
    assert_eq!(RevocationTerminalReason::ALL.len(), 7);
    assert_eq!(RevocationActorMode::ALL.len(), 4);
    assert_eq!(RemoteDeviceLifecycle::ALL.len(), 7);
    for (i, s) in EnrollmentState::ALL.iter().enumerate() {
        assert_eq!(s.discriminant() as usize, i + 1);
    }
    for (i, s) in CertificateOperationState::ALL.iter().enumerate() {
        assert_eq!(s.discriminant() as usize, i + 1);
    }
    for (i, s) in RevocationState::ALL.iter().enumerate() {
        assert_eq!(s.discriminant() as usize, i + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(value: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        let bytes = value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        out.copy_from_slice(&bytes);
        out
    }

    #[test]
    fn sas_v1_salt_and_info_preimages_match_committed_vectors() {
        // Committed salt preimage hex:
        // 666c79636f636b7069742d72656d6f74652d656e726f6c6c6d656e742d7361732d76310073616c74
        let expected_salt_hex = "666c79636f636b7069742d72656d6f74652d656e726f6c6c6d656e742d7361732d76310073616c74";
        let expected_salt_preimage: Vec<u8> = expected_salt_hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(sas_v1_salt_preimage(), expected_salt_preimage);
        assert_eq!(SAS_V1_SALT_PREIMAGE, expected_salt_preimage.as_slice());

        // Committed info hex:
        // 666c79636f636b7069742d72656d6f74652d656e726f6c6c6d656e742d7361732d763100646967697473007631
        let expected_info_hex = "666c79636f636b7069742d72656d6f74652d656e726f6c6c6d656e742d7361732d763100646967697473007631";
        let expected_info_preimage: Vec<u8> = expected_info_hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(sas_v1_info_preimage(), expected_info_preimage);
        assert_eq!(SAS_V1_INFO_PREIMAGE, expected_info_preimage.as_slice());

        // Committed salt digest: 5927e846e8ccc0210d666fa104e2aa7af9dcda3039ee97cae6b2978cc97b0508
        let salt = Sha256::digest(sas_v1_salt_preimage());
        assert_eq!(salt.as_slice(), SAS_V1_SALT_DIGEST);

        // Replacing either 0x00 separator with 5c30 must fail.
        let mut bad_salt = sas_v1_salt_preimage();
        let nul_pos = bad_salt
            .iter()
            .position(|&b| b == SAS_V1_NUL)
            .expect("salt preimage has a NUL separator");
        bad_salt.splice(nul_pos..nul_pos + 1, [0x5c, 0x30]);
        assert!(validate_sas_preimage(&bad_salt).is_err());

        let mut bad_info = sas_v1_info_preimage();
        // First NUL in info.
        let nul_pos_info = bad_info
            .iter()
            .position(|&b| b == SAS_V1_NUL)
            .expect("info preimage has a NUL separator");
        bad_info.splice(nul_pos_info..nul_pos_info + 1, [0x5c, 0x30]);
        assert!(validate_sas_preimage(&bad_info).is_err());

        // Canonical preimages validate.
        assert!(validate_sas_preimage(&sas_v1_salt_preimage()).is_ok());
        assert!(validate_sas_preimage(&sas_v1_info_preimage()).is_ok());
    }

    #[test]
    fn sas_v1_zero_transcript_vector() {
        // T = 00…00: block 74d1690507, integer 501729527047, SAS 17295 27047
        let t = [0u8; 32];
        let sas = derive_sas_v1(&t).unwrap();
        assert_eq!(sas.accepted_index, 0);
        assert_eq!(format!("{:010x}", sas.accepted_block), "74d1690507");
        assert_eq!(sas.accepted_block, 501729527047);
        assert_eq!(sas.digits, "00001729527047"[4..]); // ten digits
        assert_eq!(sas.digits, "1729527047");
        assert_eq!(sas.display(), "17295 27047");
    }

    #[test]
    fn sas_v1_incrementing_transcript_vector() {
        // T = 000102…1f: block 3e0688fa1e, integer 266397612574, SAS 63976 12574
        let mut t = [0u8; 32];
        for (i, b) in t.iter_mut().enumerate() {
            *b = i as u8;
        }
        let sas = derive_sas_v1(&t).unwrap();
        assert_eq!(format!("{:010x}", sas.accepted_block), "3e0688fa1e");
        assert_eq!(sas.accepted_block, 266397612574);
        assert_eq!(sas.digits, "6397612574");
        assert_eq!(sas.display(), "63976 12574");
    }

    #[test]
    fn sas_v1_all_ones_transcript_vector() {
        // T = ff…ff: block 33b5c5ee12, integer 222092979730, SAS 20929 79730
        let t = [0xff; 32];
        let sas = derive_sas_v1(&t).unwrap();
        assert_eq!(format!("{:010x}", sas.accepted_block), "33b5c5ee12");
        assert_eq!(sas.accepted_block, 222092979730);
        assert_eq!(sas.digits, "2092979730");
        assert_eq!(sas.display(), "20929 79730");
    }

    #[test]
    fn sas_v1_rejection_vector() {
        // T = 696cbdedfc57246ef9fffd892f1981dae7710c3752df13555d14bd756145543b:
        // reject block 0 fdeaff5e8c / 1090569330316, accept block 1 98ef896679
        // / 656853788281, SAS 68537 88281
        let t = unhex("696cbdedfc57246ef9fffd892f1981dae7710c3752df13555d14bd756145543b");
        let okm = sas_v1_okm(&t);
        // Block 0 (rejected).
        let mut buf0 = [0u8; 8];
        buf0[3..8].copy_from_slice(&okm[0..5]);
        assert_eq!(format!("{:010x}", u64::from_be_bytes(buf0)), "fdeaff5e8c");
        assert_eq!(u64::from_be_bytes(buf0), 1090569330316);
        assert!(u64::from_be_bytes(buf0) >= SAS_V1_REJECT_THRESHOLD);
        // Block 1 (accepted).
        let mut buf1 = [0u8; 8];
        buf1[3..8].copy_from_slice(&okm[5..10]);
        assert_eq!(format!("{:010x}", u64::from_be_bytes(buf1)), "98ef896679");
        assert_eq!(u64::from_be_bytes(buf1), 656853788281);
        assert!(u64::from_be_bytes(buf1) < SAS_V1_REJECT_THRESHOLD);

        let sas = derive_sas_v1(&t).unwrap();
        assert_eq!(sas.accepted_index, 1);
        assert_eq!(sas.accepted_block, 656853788281);
        assert_eq!(sas.digits, "6853788281");
        assert_eq!(sas.display(), "68537 88281");
    }

    #[test]
    fn sas_v1_okm_length_is_exactly_8160_bytes() {
        let t = [0u8; 32];
        let okm = sas_v1_okm(&t);
        assert_eq!(okm.len(), SAS_V1_OKM_LEN);
        assert_eq!(okm.len() / 5, SAS_V1_BLOCK_COUNT);
    }

    #[test]
    fn sas_v1_preimages_contain_no_backslash_or_ascii_zero() {
        let salt = sas_v1_salt_preimage();
        let info = sas_v1_info_preimage();
        assert!(!salt.contains(&0x5c));
        assert!(!salt.contains(&b'0'));
        assert!(!info.contains(&0x5c));
        assert!(!info.contains(&b'0'));
    }

    #[test]
    fn enrollment_https_link_round_trip_and_strictness() {
        let origin = "https://enroll.flycockpit.example";
        let enrollment_id = [0xAB; 16];
        let capability = [0xCD; 32];
        let link = build_discovery_link(origin, enrollment_id, capability).unwrap();
        let url = link.https_url();
        assert_eq!(
            url,
            format!(
                "https://enroll.flycockpit.example/remote/enroll?v=1&id={}&cap={}",
                URL_SAFE_NO_PAD.encode(enrollment_id),
                URL_SAFE_NO_PAD.encode(capability),
            )
        );
        assert!(url.starts_with("https://enroll.flycockpit.example/remote/enroll?v=1&id="));
        let parsed = parse_https_enrollment_link(&url).unwrap();
        assert_eq!(parsed, link);

        // Deep link round-trip.
        let deep = link.deep_link();
        assert!(deep.starts_with("flycockpit://remote/enroll?v=1&id="));
        let parsed_deep = parse_deep_enrollment_link(&deep).unwrap();
        assert_eq!(parsed_deep.enrollment_id, enrollment_id);
        assert_eq!(parsed_deep.discovery_capability, capability);
    }

    #[test]
    fn enrollment_link_rejects_malformed_variants() {
        let origin = "https://enroll.flycockpit.example";
        let enrollment_id = [0xAB; 16];
        let capability = [0xCD; 32];
        let link = build_discovery_link(origin, enrollment_id, capability).unwrap();
        let good = link.https_url();

        // Extra parameter rejected.
        let mut extra = good.clone();
        extra.push_str("&foo=bar");
        assert!(parse_https_enrollment_link(&extra).is_err());

        // Wrong version rejected.
        let bad_version = good.replace("v=1", "v=2");
        assert!(parse_https_enrollment_link(&bad_version).is_err());

        // Wrong path case rejected.
        let bad_path = good.replace("/remote/enroll", "/Remote/Enroll");
        assert!(parse_https_enrollment_link(&bad_path).is_err());

        // Non-https rejected.
        let bad_scheme = good.replacen("https://", "http://", 1);
        assert!(parse_https_enrollment_link(&bad_scheme).is_err());

        // Padded base64url rejected.
        let padded = good.replace("id=", "id=");
        let padded = format!("{padded}=");
        assert!(parse_https_enrollment_link(&padded).is_err());

        // Fragment rejected.
        let with_fragment = format!("{good}#frag");
        assert!(parse_https_enrollment_link(&with_fragment).is_err());

        // Wrong query order rejected.
        let swapped = format!(
            "https://enroll.flycockpit.example/remote/enroll?v=1&cap={}&id={}",
            URL_SAFE_NO_PAD.encode(capability),
            URL_SAFE_NO_PAD.encode(enrollment_id),
        );
        assert!(parse_https_enrollment_link(&swapped).is_err());

        // Noncanonical origin rejected.
        assert!(build_discovery_link("https://Enroll.flycockpit.example", enrollment_id, capability)
            .is_err());
        assert!(build_discovery_link("https://enroll.flycockpit.example:443", enrollment_id, capability)
            .is_err());
        assert!(build_discovery_link("http://enroll.flycockpit.example", enrollment_id, capability)
            .is_err());

        // Zero IDs rejected.
        assert!(build_discovery_link(origin, [0; 16], capability).is_err());
        assert!(build_discovery_link(origin, enrollment_id, [0; 32]).is_err());
    }

    #[test]
    fn closed_surface_and_foundation_consumption_guards_pass() {
        closed_surface_guard();
        remote_identity_protocol_consumption_guard();
    }

    #[test]
    fn enrollment_state_terminal_reason_pairs_validate() {
        // Issued and all non-terminal states have null terminal reason.
        for state in EnrollmentState::ALL {
            assert_eq!(state.null_terminal_reason(), !state.requires_terminal_reason());
        }
        // Legal pairs.
        assert!(EnrollmentTerminalReason::ExplicitReject
            .validate_pair(EnrollmentState::Rejected)
            .is_ok());
        assert!(EnrollmentTerminalReason::Expired
            .validate_pair(EnrollmentState::Expired)
            .is_ok());
        assert!(EnrollmentTerminalReason::Cancelled
            .validate_pair(EnrollmentState::Cancelled)
            .is_ok());
        assert!(EnrollmentTerminalReason::Superseded
            .validate_pair(EnrollmentState::Superseded)
            .is_ok());
        // Illegal pairs.
        assert!(EnrollmentTerminalReason::Expired
            .validate_pair(EnrollmentState::Rejected)
            .is_err());
        assert!(EnrollmentTerminalReason::ExplicitReject
            .validate_pair(EnrollmentState::Issued)
            .is_err());
        assert!(EnrollmentTerminalReason::MismatchLimit
            .validate_pair(EnrollmentState::Expired)
            .is_err());
    }

    #[test]
    fn certificate_operation_state_terminal_reason_pairs_validate() {
        assert!(CertificateOperationTerminalReason::InvalidCurrent
            .validate_pair(CertificateOperationState::Denied)
            .is_ok());
        assert!(CertificateOperationTerminalReason::SignerUnavailable
            .validate_pair(CertificateOperationState::Denied)
            .is_ok());
        assert!(CertificateOperationTerminalReason::Expired
            .validate_pair(CertificateOperationState::Expired)
            .is_ok());
        assert!(CertificateOperationTerminalReason::Cancelled
            .validate_pair(CertificateOperationState::Cancelled)
            .is_ok());
        // Illegal: denied reason on issued state.
        assert!(CertificateOperationTerminalReason::InvalidCurrent
            .validate_pair(CertificateOperationState::Issued)
            .is_err());
        // Illegal: expired reason on cancelled state.
        assert!(CertificateOperationTerminalReason::Expired
            .validate_pair(CertificateOperationState::Cancelled)
            .is_err());
    }

    #[test]
    fn revocation_state_terminal_reason_pairs_validate() {
        assert!(RevocationTerminalReason::InvalidApproval
            .validate_pair(RevocationState::Denied)
            .is_ok());
        assert!(RevocationTerminalReason::Expired
            .validate_pair(RevocationState::Expired)
            .is_ok());
        assert!(RevocationTerminalReason::Cancelled
            .validate_pair(RevocationState::Cancelled)
            .is_ok());
        // Illegal: denied reason on revoked state (revoked has null reason).
        assert!(RevocationTerminalReason::InvalidCurrent
            .validate_pair(RevocationState::Revoked)
            .is_err());
    }

    #[test]
    fn certificate_lifecycle_action_reducer_is_closed() {
        assert_eq!(
            CertificateLifecycleAction::ALL
                .iter()
                .map(|a| a.name())
                .collect::<Vec<_>>(),
            vec!["enroll", "renew", "rotate"]
        );
    }
}
