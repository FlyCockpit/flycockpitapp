//! macOS daemon custody adapter (`#[cfg(target_os = "macos")]`).
//!
//! TODO(native-platform): the real nonexportable P-256 adapter — Secure Enclave
//! (`kSecAttrTokenIDSecureEnclave`) for [`DaemonCustodyProfile::MacosSecureEnclave`]
//! or a software-backed Keychain `SecKey` for [`DaemonCustodyProfile::MacosKeychain`],
//! with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, digest signing via
//! `ecdsaSignatureDigestX962SHA256`, DER→low-S P1363 normalization, and
//! reopen/delete through `SecItemCopyMatching`/`SecItemDelete` keyed by a
//! ThisDeviceOnly application tag — must be built AND run on the macOS CI matrix
//! leg. It cannot be compiled or exercised on the Linux gate box, so it is NOT
//! shipped here.
//!
//! Until that CI leg lands, this adapter is a deliberate **fail-closed stub**:
//! every operation returns `Unavailable`/`NotFound` rather than a
//! plausible-but-wrong value, so macOS daemon custody is *unavailable*, never
//! silently insecure. The provider / store / policy-gate logic in the parent
//! module is fully exercised on every platform through
//! [`super::FakeDaemonCustodyAdapter`]. Nothing constructs this adapter yet (the
//! daemon custody module is landed core, not wired into a runtime path).
//! See `apps/native/modules/remote-identity-custody/NATIVE-PLATFORM-TODO.md`.

use cockpit_proto::remote_device_identity_enrollment::{
    RemoteIdentityCustodyError, RemoteIdentityCustodyHandleId, RemoteIdentityP256PublicKey,
    RemoteSubjectKindV1 as SubjectKind,
};

use super::{AdapterKeyMaterial, DaemonCustodyAdapter, DaemonCustodyProfile};

/// Fail-closed macOS custody adapter stub. See the module docs — the real
/// Secure Enclave / Keychain adapter is verified only on the macOS CI leg.
pub struct MacosCustodyAdapter {
    // Retained so the real adapter (which selects the token from the profile) is
    // a drop-in replacement; unread while this is a stub.
    #[allow(dead_code)]
    profile: DaemonCustodyProfile,
}

impl MacosCustodyAdapter {
    /// Construct an adapter for a macOS profile. Non-macOS profiles are rejected
    /// exactly as the real adapter will reject them.
    pub fn new(profile: DaemonCustodyProfile) -> Result<Self, RemoteIdentityCustodyError> {
        match profile {
            DaemonCustodyProfile::MacosSecureEnclave | DaemonCustodyProfile::MacosKeychain => {
                Ok(Self { profile })
            }
            other => Err(RemoteIdentityCustodyError::PolicyDenied(format!(
                "{} is not a macOS custody profile",
                other.platform_label()
            ))),
        }
    }
}

fn unimplemented_macos(op: &str) -> RemoteIdentityCustodyError {
    RemoteIdentityCustodyError::Unavailable(format!(
        "macOS daemon custody {op} is not implemented in this build; the real Secure Enclave / \
         Keychain adapter is compiled and verified only on the macOS CI leg (TODO native-platform)"
    ))
}

impl DaemonCustodyAdapter for MacosCustodyAdapter {
    fn create(
        &mut self,
        _profile: DaemonCustodyProfile,
        _subject_kind: SubjectKind,
        _handle: RemoteIdentityCustodyHandleId,
        _generation: u64,
    ) -> Result<AdapterKeyMaterial, RemoteIdentityCustodyError> {
        Err(unimplemented_macos("create"))
    }

    fn reopen(
        &self,
        _handle: RemoteIdentityCustodyHandleId,
        _generation: u64,
    ) -> Result<RemoteIdentityP256PublicKey, RemoteIdentityCustodyError> {
        // Fail closed: never fabricate a hit for a key this build cannot open.
        Err(RemoteIdentityCustodyError::NotFound)
    }

    fn sign(
        &mut self,
        _handle: RemoteIdentityCustodyHandleId,
        _generation: u64,
        _digest: &[u8; 32],
    ) -> Result<[u8; 64], RemoteIdentityCustodyError> {
        Err(unimplemented_macos("sign"))
    }

    fn retire(
        &mut self,
        _handle: RemoteIdentityCustodyHandleId,
        _generation: u64,
    ) -> Result<(), RemoteIdentityCustodyError> {
        Err(unimplemented_macos("retire"))
    }

    fn destroy_all(
        &mut self,
        _handle: RemoteIdentityCustodyHandleId,
    ) -> Result<(), RemoteIdentityCustodyError> {
        Err(unimplemented_macos("destroy"))
    }
}
