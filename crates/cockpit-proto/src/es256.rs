//! The workspace's sole ES256 (ECDSA/P-256/SHA-256) verifier.
//!
//! This module is the single Rust owner of raw IEEE-P1363 ES256 signature
//! verification. Downstream policy/grant verifiers (`verify_policy_jws`,
//! `attempt-grant-verification-and-principal-derivation`, and any later FCFP
//! verifiers) call [`verify_es256_p1363`] rather than importing `p256`
//! directly or opening a second inline verify path.
//!
//! Verification is strict and fail-closed:
//! - exactly 64-byte IEEE-P1363 `r || s` (DER and any other length rejected),
//! - `r = 0` and `s = 0` rejected,
//! - **low-S enforced**: a high-S signature (`s > n/2`) is rejected, so the
//!   same signature bytes verify identically in Rust and in the TypeScript
//!   WebCrypto path and the cross-language fixture corpus stays byte-identical,
//! - the public key coordinates are imported through `p256` (SEC1
//!   uncompressed), so an off-curve / identity point is rejected.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};

/// A P-256 public key in the same 32-byte affine-coordinate form used by the
/// remote identity thumbprint coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Es256PublicKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// ES256 verification failure modes. Every variant is a hard rejection; there
/// is no "verified with a warning" outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Es256Error {
    #[error("signature must be exactly 64 bytes of IEEE-P1363 r||s")]
    SignatureLength,
    #[error("signature scalar r or s is zero")]
    ZeroScalar,
    #[error("signature is malformed")]
    MalformedSignature,
    #[error("signature is high-S; only low-S (s <= n/2) is accepted")]
    HighS,
    #[error("public key is not a valid P-256 point")]
    InvalidKey,
    #[error("signature verification failed")]
    VerificationFailed,
}

impl Es256PublicKey {
    /// SEC1 uncompressed encoding `0x04 || x || y`.
    fn to_sec1_uncompressed(self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..33].copy_from_slice(&self.x);
        out[33..65].copy_from_slice(&self.y);
        out
    }
}

/// Verify an ES256 (ECDSA/P-256 over SHA-256) signature in raw IEEE-P1363
/// `r || s` form over `signing_input`.
///
/// SHA-256 is applied to `signing_input` internally by the verifier. The
/// signature must be exactly 64 bytes; DER-encoded or otherwise-sized inputs,
/// zero scalars, and high-S signatures are rejected before the point/verify
/// step. The key coordinates are imported through `p256`, rejecting off-curve
/// and identity points.
pub fn verify_es256_p1363(
    key: &Es256PublicKey,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), Es256Error> {
    // Exactly 64 bytes (DER, truncated, or over-length all rejected here).
    if signature.len() != 64 {
        return Err(Es256Error::SignatureLength);
    }
    // Reject zero r / zero s explicitly for a distinct, fail-closed error.
    if signature[0..32].iter().all(|&b| b == 0) || signature[32..64].iter().all(|&b| b == 0) {
        return Err(Es256Error::ZeroScalar);
    }

    // Parse the raw P1363 scalars (also rejects out-of-range / zero scalars).
    let sig = Signature::from_slice(signature).map_err(|_| Es256Error::MalformedSignature)?;

    // Low-S enforcement: `normalize_s` returns `Some` only when the input was
    // high-S. A high-S signature is rejected outright (never silently
    // normalized) so both languages accept exactly the same signature bytes.
    if sig.normalize_s().is_some() {
        return Err(Es256Error::HighS);
    }

    // Import the public key; an off-curve / identity point fails here.
    let sec1 = key.to_sec1_uncompressed();
    let verifying_key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| Es256Error::InvalidKey)?;

    verifying_key
        .verify(signing_input, &sig)
        .map_err(|_| Es256Error::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    /// P-256 group order n, big-endian.
    const N_BE: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];

    /// Big-endian 32-byte subtraction `a - b` (used to build `n - s`).
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

    fn test_keypair(seed: u8) -> (SigningKey, Es256PublicKey) {
        // A fixed nonzero scalar well below n produces a deterministic key.
        let sk_bytes = [seed | 0x01; 32];
        let sk = SigningKey::from_slice(&sk_bytes).expect("valid scalar");
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(point.x().expect("x coordinate").as_slice());
        y.copy_from_slice(point.y().expect("y coordinate").as_slice());
        (sk, Es256PublicKey { x, y })
    }

    /// Sign and return the raw 64-byte signature, explicitly normalized to
    /// low-S (independent of the crate's default S normalization).
    fn sign_low_s(sk: &SigningKey, msg: &[u8]) -> [u8; 64] {
        let sig: Signature = sk.sign(msg);
        let low = sig.normalize_s().unwrap_or(sig);
        let bytes = low.to_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(bytes.as_slice());
        out
    }

    #[test]
    fn es256_known_good_signature_verifies() {
        let (sk, pk) = test_keypair(0x10);
        let msg = b"es256 known-good vector";
        let sig = sign_low_s(&sk, msg);
        assert!(verify_es256_p1363(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn es256_wrong_key_fails() {
        let (sk, _pk) = test_keypair(0x10);
        let (_sk2, other_pk) = test_keypair(0x22);
        let msg = b"es256 wrong-key vector";
        let sig = sign_low_s(&sk, msg);
        assert_eq!(
            verify_es256_p1363(&other_pk, msg, &sig),
            Err(Es256Error::VerificationFailed)
        );
    }

    #[test]
    fn es256_mutated_input_fails() {
        let (sk, pk) = test_keypair(0x10);
        let msg = b"es256 mutated-input vector";
        let sig = sign_low_s(&sk, msg);
        let mut tampered = msg.to_vec();
        tampered[0] ^= 0xff;
        assert_eq!(
            verify_es256_p1363(&pk, &tampered, &sig),
            Err(Es256Error::VerificationFailed)
        );
    }

    #[test]
    fn es256_truncated_signature_fails() {
        let (sk, pk) = test_keypair(0x10);
        let msg = b"es256 truncated vector";
        let sig = sign_low_s(&sk, msg);
        assert_eq!(
            verify_es256_p1363(&pk, msg, &sig[..63]),
            Err(Es256Error::SignatureLength)
        );
    }

    #[test]
    fn es256_der_signature_fails() {
        let (sk, pk) = test_keypair(0x10);
        let msg = b"es256 der vector";
        let sig: Signature = sk.sign(msg);
        // DER encoding is not 64 bytes (typically 70-72), so it is rejected on
        // length before any parse.
        let der = sig.to_der();
        assert_eq!(
            verify_es256_p1363(&pk, msg, der.as_bytes()),
            Err(Es256Error::SignatureLength)
        );
    }

    #[test]
    fn es256_high_s_signature_fails() {
        let (sk, pk) = test_keypair(0x10);
        let msg = b"es256 high-s vector";
        let low = sign_low_s(&sk, msg);
        // The low-S signature must verify.
        assert!(verify_es256_p1363(&pk, msg, &low).is_ok());
        // Build the high-S counterpart: s' = n - s (still a valid ECDSA
        // signature, but must be rejected by the low-S rule).
        let mut s = [0u8; 32];
        s.copy_from_slice(&low[32..64]);
        let high_s = sub_be(&N_BE, &s);
        let mut high = [0u8; 64];
        high[0..32].copy_from_slice(&low[0..32]);
        high[32..64].copy_from_slice(&high_s);
        assert_eq!(
            verify_es256_p1363(&pk, msg, &high),
            Err(Es256Error::HighS)
        );
    }

    #[test]
    fn es256_zero_scalar_signature_fails() {
        let (_sk, pk) = test_keypair(0x10);
        let msg = b"es256 zero-scalar vector";
        // r = 0.
        let mut zero_r = [0u8; 64];
        zero_r[63] = 1;
        assert_eq!(
            verify_es256_p1363(&pk, msg, &zero_r),
            Err(Es256Error::ZeroScalar)
        );
        // s = 0.
        let mut zero_s = [0u8; 64];
        zero_s[0] = 1;
        assert_eq!(
            verify_es256_p1363(&pk, msg, &zero_s),
            Err(Es256Error::ZeroScalar)
        );
    }

    #[test]
    fn es256_off_curve_key_fails() {
        let (sk, _pk) = test_keypair(0x10);
        let msg = b"es256 off-curve vector";
        let sig = sign_low_s(&sk, msg);
        // A coordinate pair of all-0x01 bytes is 32-byte nonzero but not a
        // point on P-256, so key import fails.
        let bad_key = Es256PublicKey {
            x: [0x01; 32],
            y: [0x01; 32],
        };
        assert_eq!(
            verify_es256_p1363(&bad_key, msg, &sig),
            Err(Es256Error::InvalidKey)
        );
    }
}
