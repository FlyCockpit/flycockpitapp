//! Sealed-locator V1: XChaCha20-Poly1305 with HKDF-SHA-256 key derivation.
//!
//! The locator is sealed using the referenced secure-key version:
//! - XChaCha20-Poly1305 AEAD with a `[u8;24]` random nonce and combined
//!   ciphertext/tag.
//! - 32-byte HKDF-SHA-256 key derived from the secure-key version's raw bytes.
//! - Salt is `SHA-256("flycockpit.tool-media-subject-binding.salt.v1\0" ||
//!   session_id || client_submission_id)`.
//! - Info is `"flycockpit.tool-media-subject-binding.key.v1\0"`.
//! - AAD is `"flycockpit.tool-media-subject-binding.v1\0" || session_id ||
//!   client_submission_id || receipt bytes`.
//!
//! Do not reuse HMAC-only sealed state — this is a separate, confidential
//! AEAD scheme.

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::locator::LocatorV1;

/// Domain prefix for the HKDF salt.
const SALT_DOMAIN: &[u8] = b"flycockpit.tool-media-subject-binding.salt.v1\0";
/// HKDF info string.
const INFO: &[u8] = b"flycockpit.tool-media-subject-binding.key.v1\0";
/// AAD domain prefix.
const AAD_DOMAIN: &[u8] = b"flycockpit.tool-media-subject-binding.v1\0";
/// Seal version.
pub const SEAL_VERSION: u8 = 1;
/// Nonce length for XChaCha20-Poly1305.
pub const NONCE_LEN: usize = 24;
/// Tag length for Poly1305.
pub const TAG_LEN: usize = 16;
/// Derived key length.
const DERIVED_KEY_LEN: usize = 32;

/// A sealed locator — ciphertext + nonce + metadata, no plaintext.
///
/// Debug never prints ciphertext or nonce material.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedLocator {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for SealedLocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedLocator")
            .field("nonce_len", &self.nonce.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

/// The unsealed locator recovered after successful AEAD decryption.
///
/// This is server-internal only; never expose to model/wire/history.
pub struct UnsealedLocator {
    locator: LocatorV1,
}

impl UnsealedLocator {
    pub(crate) fn locator(&self) -> &LocatorV1 {
        &self.locator
    }
}

impl std::fmt::Debug for UnsealedLocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnsealedLocator")
            .field("len", &self.locator.len())
            .finish_non_exhaustive()
    }
}

/// Error during sealing or unsealing.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SealError {
    #[error("AEAD encryption failed")]
    Encrypt,
    #[error("AEAD decryption failed — wrong key, nonce, AAD, or ciphertext")]
    Decrypt,
    #[error("ciphertext too short ({0} bytes, need > {TAG_LEN})")]
    CiphertextTooShort(usize),
    #[error("key material length {0}, expected 32")]
    KeyLength(usize),
}

/// Derive the 32-byte AEAD key from the secure-key version's raw bytes.
///
/// Uses HKDF-SHA-256 with:
/// - salt = `SHA-256(SALT_DOMAIN || session_id || client_submission_id)`
/// - info = `INFO`
fn derive_key(
    key_bytes: &[u8; 32],
    session_id: &[u8; 16],
    client_submission_id: &[u8; 16],
) -> Zeroizing<[u8; DERIVED_KEY_LEN]> {
    // Salt = SHA-256(SALT_DOMAIN || session_id || client_submission_id)
    let mut salt_hasher = sha2::Sha256::new();
    salt_hasher.update(SALT_DOMAIN);
    salt_hasher.update(session_id);
    salt_hasher.update(client_submission_id);
    let salt = salt_hasher.finalize();

    let hk = Hkdf::<Sha256>::new(Some(&salt), key_bytes);
    let mut okm = Zeroizing::new([0u8; DERIVED_KEY_LEN]);
    hk.expand(INFO, okm.as_mut())
        .expect("32-byte HKDF-SHA-256 expand is infallible");
    okm
}

/// Build the AAD for the seal.
///
/// AAD = `AAD_DOMAIN || session_id || client_submission_id || receipt_bytes`
fn build_aad(
    session_id: &[u8; 16],
    client_submission_id: &[u8; 16],
    receipt_bytes: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 16 + 16 + receipt_bytes.len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(session_id);
    aad.extend_from_slice(client_submission_id);
    aad.extend_from_slice(receipt_bytes);
    aad
}

/// Seal a locator using XChaCha20-Poly1305 with an HKDF-SHA-256 derived key.
///
/// `key_bytes` is the raw 32-byte secure-key version material. A fresh random
/// nonce is generated.
pub fn seal_locator(
    key_bytes: &[u8; 32],
    session_id: &[u8; 16],
    client_submission_id: &[u8; 16],
    receipt_bytes: &[u8],
    locator: &LocatorV1,
) -> Result<SealedLocator, SealError> {
    let derived = derive_key(key_bytes, session_id, client_submission_id);
    let aad = build_aad(session_id, client_submission_id, receipt_bytes);

    let cipher = XChaCha20Poly1305::new(derived.as_ref().into());
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(&nonce.into(), aead_payload(locator.raw_bytes(), &aad))
        .map_err(|_| SealError::Encrypt)?;

    Ok(SealedLocator { nonce, ciphertext })
}

/// Unseal a locator using XChaCha20-Poly1305 with an HKDF-SHA-256 derived key.
///
/// Returns `Err(SealError::Decrypt)` on any authentication failure — wrong
/// key, nonce, AAD, or ciphertext. No plaintext is returned on failure.
pub fn unseal_locator(
    key_bytes: &[u8; 32],
    session_id: &[u8; 16],
    client_submission_id: &[u8; 16],
    receipt_bytes: &[u8],
    sealed: &SealedLocator,
) -> Result<UnsealedLocator, SealError> {
    if sealed.ciphertext.len() <= TAG_LEN {
        return Err(SealError::CiphertextTooShort(sealed.ciphertext.len()));
    }

    let derived = derive_key(key_bytes, session_id, client_submission_id);
    let aad = build_aad(session_id, client_submission_id, receipt_bytes);

    let cipher = XChaCha20Poly1305::new(derived.as_ref().into());
    let plaintext = cipher
        .decrypt(&sealed.nonce.into(), aead_payload(&sealed.ciphertext, &aad))
        .map_err(|_| SealError::Decrypt)?;

    // Reconstruct the locator from decrypted bytes.
    let locator = reconstruct_locator(&plaintext)?;
    Ok(UnsealedLocator { locator })
}

/// Reconstruct a `LocatorV1` from decrypted plaintext bytes.
fn reconstruct_locator(bytes: &[u8]) -> Result<LocatorV1, SealError> {
    if bytes == super::locator::LOCAL_OWNER_BYTES {
        return Ok(LocatorV1::local_owner());
    }
    if bytes.len() == 25 && bytes[0] == 2 {
        let device_uuid: [u8; 16] = bytes[1..17].try_into().map_err(|_| SealError::Decrypt)?;
        let device_generation = u64::from_be_bytes(bytes[17..25].try_into().unwrap());
        return Ok(LocatorV1::remote_device(device_uuid, device_generation));
    }
    Err(SealError::Decrypt)
}

// Helper for chacha20poly1305 Aead encrypt/decrypt payloads.
fn aead_payload<'a>(msg: &'a [u8], aad: &'a [u8]) -> Payload<'a> {
    Payload { msg, aad }
}

#[cfg(test)]
mod tests {
    use super::super::locator::LocatorV1;
    use super::super::receipt::{IssuerKind, ToolMediaSubjectReceiptV1};
    use super::*;

    fn make_receipt(locator: &LocatorV1) -> (ToolMediaSubjectReceiptV1, [u8; 16], [u8; 16]) {
        let project_uuid = [0xAB; 16];
        let project_digest = LocatorV1::project_digest(&project_uuid);
        let session_id = [0xCD; 16];
        let client_submission_id = [0xEF; 16];
        let receipt = ToolMediaSubjectReceiptV1::new(
            IssuerKind::LocalOwner,
            locator,
            project_digest,
            session_id,
            1,
        );
        (receipt, session_id, client_submission_id)
    }

    #[test]
    fn seal_unseal_round_trip_local() {
        let locator = LocatorV1::local_owner();
        let (receipt, session_id, client_submission_id) = make_receipt(&locator);
        let receipt_bytes = receipt.canonical_bytes();
        let key = [0x42; 32];

        let sealed = seal_locator(
            &key,
            &session_id,
            &client_submission_id,
            &receipt_bytes,
            &locator,
        )
        .unwrap();

        assert_eq!(sealed.nonce.len(), NONCE_LEN);
        assert!(sealed.ciphertext.len() > TAG_LEN);

        let unsealed = unseal_locator(
            &key,
            &session_id,
            &client_submission_id,
            &receipt_bytes,
            &sealed,
        )
        .unwrap();

        assert_eq!(unsealed.locator().raw_bytes(), locator.raw_bytes());
        assert!(unsealed.locator().is_local_owner());
    }

    #[test]
    fn seal_unseal_round_trip_remote() {
        let locator = LocatorV1::remote_device([0x11; 16], 77);
        let (receipt, session_id, client_submission_id) = make_receipt(&locator);
        let receipt_bytes = receipt.canonical_bytes();
        let key = [0x99; 32];

        let sealed = seal_locator(
            &key,
            &session_id,
            &client_submission_id,
            &receipt_bytes,
            &locator,
        )
        .unwrap();

        let unsealed = unseal_locator(
            &key,
            &session_id,
            &client_submission_id,
            &receipt_bytes,
            &sealed,
        )
        .unwrap();

        assert_eq!(unsealed.locator().raw_bytes(), locator.raw_bytes());
    }

    #[test]
    fn wrong_key_fails() {
        let locator = LocatorV1::local_owner();
        let (receipt, session_id, client_submission_id) = make_receipt(&locator);
        let receipt_bytes = receipt.canonical_bytes();

        let sealed = seal_locator(
            &[0x42; 32],
            &session_id,
            &client_submission_id,
            &receipt_bytes,
            &locator,
        )
        .unwrap();

        let result = unseal_locator(
            &[0x43; 32],
            &session_id,
            &client_submission_id,
            &receipt_bytes,
            &sealed,
        );
        assert!(result.is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let locator = LocatorV1::local_owner();
        let (receipt, session_id, client_submission_id) = make_receipt(&locator);
        let receipt_bytes = receipt.canonical_bytes();

        let sealed = seal_locator(
            &[0x42; 32],
            &session_id,
            &client_submission_id,
            &receipt_bytes,
            &locator,
        )
        .unwrap();

        // Tamper receipt bytes in AAD.
        let mut bad_receipt = receipt_bytes.clone();
        bad_receipt[0] ^= 1;
        let result = unseal_locator(
            &[0x42; 32],
            &session_id,
            &client_submission_id,
            &bad_receipt,
            &sealed,
        );
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let locator = LocatorV1::local_owner();
        let (receipt, session_id, client_submission_id) = make_receipt(&locator);
        let receipt_bytes = receipt.canonical_bytes();

        let mut sealed = seal_locator(
            &[0x42; 32],
            &session_id,
            &client_submission_id,
            &receipt_bytes,
            &locator,
        )
        .unwrap();

        sealed.ciphertext[0] ^= 0xFF;
        let result = unseal_locator(
            &[0x42; 32],
            &session_id,
            &client_submission_id,
            &receipt_bytes,
            &sealed,
        );
        assert!(result.is_err());
    }

    #[test]
    fn different_submissions_different_ciphertext() {
        let locator = LocatorV1::local_owner();
        let (receipt, session_id, client_submission_id) = make_receipt(&locator);
        let receipt_bytes = receipt.canonical_bytes();
        let key = [0x42; 32];

        let sealed1 = seal_locator(
            &key,
            &session_id,
            &client_submission_id,
            &receipt_bytes,
            &locator,
        )
        .unwrap();

        let other_submission = [0xEE; 16];
        let sealed2 = seal_locator(
            &key,
            &session_id,
            &other_submission,
            &receipt_bytes,
            &locator,
        )
        .unwrap();

        // Different salt/AAD → different ciphertext (with overwhelming
        // probability; nonce is also random).
        assert_ne!(sealed1.ciphertext, sealed2.ciphertext);
    }

    #[test]
    fn debug_redacts_material() {
        let locator = LocatorV1::local_owner();
        let (receipt, session_id, client_submission_id) = make_receipt(&locator);
        let receipt_bytes = receipt.canonical_bytes();
        let sealed = seal_locator(
            &[0x42; 32],
            &session_id,
            &client_submission_id,
            &receipt_bytes,
            &locator,
        )
        .unwrap();
        let dbg = format!("{sealed:?}");
        assert!(!dbg.contains("nonce"));
        assert!(dbg.contains("nonce_len"));
        assert!(dbg.contains("ciphertext_len"));
    }
}
