//! macOS daemon custody adapter (`#[cfg(target_os = "macos")]`).
//!
//! Nonexportable P-256 in the Secure Enclave (`kSecAttrTokenIDSecureEnclave`)
//! for [`DaemonCustodyProfile::MacosSecureEnclave`] or a software-backed
//! nonexportable Keychain SecKey for [`DaemonCustodyProfile::MacosKeychain`],
//! with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` accessibility and no
//! `kSecAttrSynchronizable`. Signing uses
//! `ecdsaSignatureMessageX962SHA256`... except the Rust seam is digest-based, so
//! this adapter signs the precomputed digest with the pre-hashed X9.62 variant
//! and normalizes the DER result to low-S P1363 via
//! [`super::der_signature_to_low_s_p1363`].
//!
//! `SecKey` and the CoreFoundation handles are ref-counted RAII values owned by
//! the `security-framework` wrappers; they release on drop. Every `SecKey`
//! failure is translated to a typed [`RemoteIdentityCustodyError`]. This module
//! compiles and is exercised only on the macOS CI matrix leg — it cannot be
//! built on the Linux gate box.

use cockpit_proto::remote_device_identity_enrollment::{
    RemoteIdentityCustodyError, RemoteIdentityCustodyHandleId, RemoteIdentityP256PublicKey,
    RemoteSubjectKindV1 as SubjectKind,
};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};

use super::{AdapterKeyMaterial, DaemonCustodyAdapter, DaemonCustodyProfile};

fn unavailable(context: &str, error: impl std::fmt::Display) -> RemoteIdentityCustodyError {
    RemoteIdentityCustodyError::Unavailable(format!("macos custody {context}: {error}"))
}

/// macOS Secure Enclave / Keychain custody adapter. The configured profile
/// selects the token; caller-supplied bytes never influence it.
pub struct MacosCustodyAdapter {
    profile: DaemonCustodyProfile,
    // Live SecKey handles keyed by (handle, generation), cached for the process
    // lifetime.
    //
    // TODO(native-platform): reopen-across-restart and durable delete are NOT
    // implemented. A production adapter must reopen from the Keychain via
    // `SecItemCopyMatching` and delete via `SecItemDelete`, keyed by the
    // ThisDeviceOnly application tag below. Until then this in-memory map is a
    // process-lifetime cache, NOT a durable store: after a restart the map is
    // empty, so `reopen` returns `NotFound` (fails closed) rather than silently
    // succeeding. These SecItem calls compile and are exercised only on the
    // macOS CI leg — they cannot be built on the Linux gate box. See
    // apps/native/modules/remote-identity-custody/NATIVE-PLATFORM-TODO.md and the
    // batch report.
    handles: std::collections::BTreeMap<([u8; 16], u64), SecKey>,
}

impl MacosCustodyAdapter {
    /// Construct an adapter for a macOS profile.
    pub fn new(profile: DaemonCustodyProfile) -> Result<Self, RemoteIdentityCustodyError> {
        match profile {
            DaemonCustodyProfile::MacosSecureEnclave | DaemonCustodyProfile::MacosKeychain => {
                Ok(Self {
                    profile,
                    handles: std::collections::BTreeMap::new(),
                })
            }
            other => Err(RemoteIdentityCustodyError::PolicyDenied(format!(
                "{} is not a macOS custody profile",
                other.platform_label()
            ))),
        }
    }

    fn application_tag(handle: RemoteIdentityCustodyHandleId, generation: u64) -> String {
        // Non-synchronizable, ThisDeviceOnly Keychain tag encoding the handle id
        // AND the generation, so a key and its record can never desync.
        format!(
            "com.flycockpit.remote.daemon.custody.{}.{generation}",
            hex16(&handle.0)
        )
    }

    fn generate_key(
        &self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<SecKey, RemoteIdentityCustodyError> {
        // ThisDeviceOnly accessibility, no synchronizable flag; the private key
        // is non-extractable (Secure Enclave, or a Keychain-permanent SecKey).
        let access_control = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            0,
        )
        .map_err(|e| unavailable("access control", e))?;

        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_access_control(access_control)
            .set_label(Self::application_tag(handle, generation));
        if self.profile == DaemonCustodyProfile::MacosSecureEnclave {
            options.set_token(Token::SecureEnclave);
        }
        SecKey::new(&options).map_err(|e| unavailable("generate", e))
    }

    fn public_key_of(
        key: &SecKey,
    ) -> Result<RemoteIdentityP256PublicKey, RemoteIdentityCustodyError> {
        let public = key
            .public_key()
            .ok_or_else(|| unavailable("public_key", "no public key"))?;
        // SEC1 uncompressed external representation: 0x04 || X(32) || Y(32).
        let data = public
            .external_representation()
            .ok_or_else(|| unavailable("external_representation", "unavailable"))?;
        let bytes = data.to_vec();
        if bytes.len() != 65 || bytes[0] != 0x04 {
            return Err(RemoteIdentityCustodyError::InvalidEvidence(
                "unexpected SecKey public representation".into(),
            ));
        }
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&bytes[1..33]);
        y.copy_from_slice(&bytes[33..65]);
        Ok(RemoteIdentityP256PublicKey { x, y })
    }

    fn attestation(&self, public_key: &RemoteIdentityP256PublicKey) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut fingerprint = Sha256::new();
        fingerprint.update(public_key.x);
        fingerprint.update(public_key.y);
        let mut evidence = Vec::new();
        evidence.extend_from_slice(self.profile.platform_label().as_bytes());
        evidence.push(0x00);
        evidence.extend_from_slice(&fingerprint.finalize());
        evidence
    }
}

impl DaemonCustodyAdapter for MacosCustodyAdapter {
    fn create(
        &mut self,
        _profile: DaemonCustodyProfile,
        _subject_kind: SubjectKind,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<AdapterKeyMaterial, RemoteIdentityCustodyError> {
        let key = self.generate_key(handle, generation)?;
        let public_key = Self::public_key_of(&key)?;
        let provider_evidence = self.attestation(&public_key);
        self.handles.insert((handle.0, generation), key);
        Ok(AdapterKeyMaterial {
            public_key,
            provider_evidence,
        })
    }

    fn reopen(
        &self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<RemoteIdentityP256PublicKey, RemoteIdentityCustodyError> {
        // TODO(native-platform): reopen from the Keychain via SecItemCopyMatching
        // keyed by the (handle, generation) application tag. Until then this only
        // finds keys created in THIS process; after a restart the cache is empty
        // and this returns NotFound (fails closed) — it never fabricates a hit.
        let key = self
            .handles
            .get(&(handle.0, generation))
            .ok_or(RemoteIdentityCustodyError::NotFound)?;
        Self::public_key_of(key)
    }

    fn sign(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
        digest: &[u8; 32],
    ) -> Result<[u8; 64], RemoteIdentityCustodyError> {
        let key = self
            .handles
            .get(&(handle.0, generation))
            .ok_or(RemoteIdentityCustodyError::NotFound)?;
        // Digest-based signing (the Rust seam supplies a precomputed digest); the
        // X9.62 DER result is normalized to low-S P1363.
        let der = key
            .create_signature(Algorithm::ECDSASignatureDigestX962SHA256, digest)
            .map_err(|e| unavailable("create_signature", e))?;
        super::der_signature_to_low_s_p1363(&der)
    }

    fn retire(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<(), RemoteIdentityCustodyError> {
        // Production must also SecItemDelete the Keychain item for this
        // (handle, generation) application tag.
        self.handles
            .remove(&(handle.0, generation))
            .map(|_| ())
            .ok_or(RemoteIdentityCustodyError::NotFound)
    }

    fn destroy_all(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<(), RemoteIdentityCustodyError> {
        let before = self.handles.len();
        self.handles.retain(|(h, _), _| *h != handle.0);
        if self.handles.len() < before {
            Ok(())
        } else {
            Err(RemoteIdentityCustodyError::NotFound)
        }
    }
}

fn hex16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
