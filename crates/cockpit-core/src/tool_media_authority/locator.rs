//! `LocatorV1` — server-only identity locator encoding and digests.
//!
//! Locator V1 is server-only:
//! - Local bytes are exactly ASCII `flycockpit.local_owner.v1` (25 bytes).
//! - Remote bytes are `u8 issuer=2 | [u8;16] device UUID network order | u64
//!   device generation big-endian`.
//!
//! `principal_digest = SHA-256("flycockpit.tool-media-principal.v1\0" ||
//! locator_v1)`.
//!
//! `project_digest = SHA-256("flycockpit.tool-media-project.v1\0" || project
//! UUID network bytes)`.

use sha2::{Digest, Sha256};

/// Domain prefix for `principal_digest`.
const PRINCIPAL_DOMAIN: &[u8] = b"flycockpit.tool-media-principal.v1\0";
/// Domain prefix for `project_digest`.
const PROJECT_DOMAIN: &[u8] = b"flycockpit.tool-media-project.v1\0";

/// The fixed ASCII bytes for the local-owner locator.
pub(crate) const LOCAL_OWNER_BYTES: &[u8] = b"flycockpit.local_owner.v1";

/// `LocatorV1` — the server-only identity locator.
///
/// This type intentionally has no `Debug` impl that prints locator bytes;
/// it uses a redacted debug. The raw bytes are never exposed to model/wire/
/// history surfaces — only digests and sealed ciphertext leave this module.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LocatorV1 {
    bytes: Vec<u8>,
}

impl LocatorV1 {
    /// Local-owner singleton locator. Bytes are exactly
    /// `flycockpit.local_owner.v1` (25 bytes).
    pub(crate) fn local_owner() -> Self {
        Self {
            bytes: LOCAL_OWNER_BYTES.to_vec(),
        }
    }

    /// Remote-device locator. Bytes are `u8 issuer=2 | [u8;16] device UUID
    /// network order | u64 device generation big-endian` (25 bytes total).
    pub(crate) fn remote_device(device_uuid: [u8; 16], device_generation: u64) -> Self {
        let mut bytes = Vec::with_capacity(25);
        bytes.push(2u8);
        bytes.extend_from_slice(&device_uuid);
        bytes.extend_from_slice(&device_generation.to_be_bytes());
        Self { bytes }
    }

    /// Raw locator bytes — server-internal only; never expose to model/wire.
    pub(crate) fn raw_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// `principal_digest = SHA-256(PRINCIPAL_DOMAIN || locator_v1)`.
    pub(crate) fn principal_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PRINCIPAL_DOMAIN);
        hasher.update(&self.bytes);
        hasher.finalize().into()
    }

    /// `project_digest = SHA-256(PROJECT_DOMAIN || project UUID network bytes)`.
    pub(crate) fn project_digest(project_uuid: &[u8; 16]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PROJECT_DOMAIN);
        hasher.update(project_uuid);
        hasher.finalize().into()
    }

    /// Byte length of the locator (25 for both local and remote).
    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the locator is the local-owner singleton.
    pub(crate) fn is_local_owner(&self) -> bool {
        self.bytes == LOCAL_OWNER_BYTES
    }
}

impl std::fmt::Debug for LocatorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocatorV1")
            .field("len", &self.bytes.len())
            .field("is_local_owner", &self.is_local_owner())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_owner_bytes() {
        let loc = LocatorV1::local_owner();
        assert_eq!(loc.len(), 25);
        assert!(loc.is_local_owner());
        assert_eq!(&loc.raw_bytes()[..], b"flycockpit.local_owner.v1");
    }

    #[test]
    fn remote_device_bytes() {
        let uuid = [0x11; 16];
        let loc = LocatorV1::remote_device(uuid, 99);
        assert_eq!(loc.len(), 25);
        assert!(!loc.is_local_owner());
        assert_eq!(loc.raw_bytes()[0], 2u8);
        assert_eq!(&loc.raw_bytes()[1..17], &uuid);
        assert_eq!(
            u64::from_be_bytes(loc.raw_bytes()[17..25].try_into().unwrap()),
            99
        );
    }

    #[test]
    fn principal_digest_stable() {
        let loc = LocatorV1::local_owner();
        let d1 = loc.principal_digest();
        let d2 = loc.principal_digest();
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 32);
    }

    #[test]
    fn project_digest_stable() {
        let uuid = [0x22; 16];
        let d1 = LocatorV1::project_digest(&uuid);
        let d2 = LocatorV1::project_digest(&uuid);
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 32);
    }

    #[test]
    fn different_locators_different_digests() {
        let local = LocatorV1::local_owner();
        let remote = LocatorV1::remote_device([0xFF; 16], 1);
        assert_ne!(local.principal_digest(), remote.principal_digest());
    }

    #[test]
    fn debug_redacts_bytes() {
        let loc = LocatorV1::remote_device([0xDE; 16], 0xAD);
        let dbg = format!("{loc:?}");
        assert!(!dbg.contains("0xDE"));
        assert!(!dbg.contains("173"));
    }
}
