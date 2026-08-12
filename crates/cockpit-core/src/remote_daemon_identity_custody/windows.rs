//! Windows daemon custody adapter (`#[cfg(target_os = "windows")]`).
//!
//! Nonexportable P-256 via CNG/NCrypt: the Platform Crypto Provider (TPM) for
//! [`DaemonCustodyProfile::WindowsCngTpm`] or the Microsoft Software KSP for
//! [`DaemonCustodyProfile::WindowsSoftwareKsp`]. Keys are created with
//! `NCRYPT_ALLOW_EXPORT_FLAG` cleared (export policy = 0), so the private key is
//! nonexportable. `NCryptSignHash` signs the precomputed digest and returns a
//! raw P1363 (`r || s`) signature, normalized to low-S via
//! [`super::normalize_p1363_low_s`].
//!
//! Every owned `NCRYPT_PROV_HANDLE` / `NCRYPT_KEY_HANDLE` is wrapped in an RAII
//! guard that calls `NCryptFreeObject` on drop; no unwind crosses the FFI, and
//! each `SECURITY_STATUS` is translated to a typed
//! [`RemoteIdentityCustodyError`].
//!
//! TODO(native-platform): this NCrypt FFI compiles and is exercised ONLY on the
//! Windows CI matrix leg (`cargo build/clippy --target x86_64-pc-windows-msvc`);
//! it cannot be built or run on the Linux gate box and has not been executed
//! here. Treat every call surface below as verified only on that CI leg. See
//! apps/native/modules/remote-identity-custody/NATIVE-PLATFORM-TODO.md.

use std::ffi::c_void;

use cockpit_proto::remote_device_identity_enrollment::{
    RemoteIdentityCustodyError, RemoteIdentityCustodyHandleId, RemoteIdentityP256PublicKey,
    RemoteSubjectKindV1 as SubjectKind,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECCKEY_BLOB, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM,
    BCRYPT_ECDSA_PUBLIC_P256_MAGIC, MS_KEY_STORAGE_PROVIDER, MS_PLATFORM_CRYPTO_PROVIDER,
    NCRYPT_ALLOW_EXPORT_FLAG, NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_KEY_HANDLE,
    NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_PROV_HANDLE, NCryptCreatePersistedKey, NCryptDeleteKey,
    NCryptEnumKeys, NCryptExportKey, NCryptFinalizeKey, NCryptFreeBuffer, NCryptFreeObject,
    NCryptKeyName, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
};

use super::{AdapterKeyMaterial, DaemonCustodyAdapter, DaemonCustodyProfile};

/// `NTE_NO_MORE_ITEMS` — the terminal status from `NCryptEnumKeys`.
const NTE_NO_MORE_ITEMS: i32 = 0x8009_002Au32 as i32;

fn status(context: &str, code: i32) -> Result<(), RemoteIdentityCustodyError> {
    if code == 0 {
        Ok(())
    } else {
        Err(RemoteIdentityCustodyError::Unavailable(format!(
            "windows custody {context}: SECURITY_STATUS 0x{code:08x}"
        )))
    }
}

/// Copy a NUL-terminated wide string returned by NCrypt into an owned `String`.
///
/// # Safety
/// `ptr` must point at a valid NUL-terminated UTF-16 string owned by NCrypt.
unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: caller guarantees a NUL-terminated string.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` counts the UTF-16 code units before the NUL.
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}

/// RAII wrapper for an owned NCrypt provider or key handle. Frees on drop.
struct NcryptHandle(usize);
impl Drop for NcryptHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: `self.0` is a live NCrypt handle we own; freeing once.
            unsafe {
                NCryptFreeObject(self.0);
            }
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The Windows CNG/NCrypt custody adapter. The configured profile selects the
/// provider; caller-supplied bytes never influence it.
pub struct WindowsCustodyAdapter {
    profile: DaemonCustodyProfile,
}

impl WindowsCustodyAdapter {
    pub fn new(profile: DaemonCustodyProfile) -> Result<Self, RemoteIdentityCustodyError> {
        match profile {
            DaemonCustodyProfile::WindowsCngTpm | DaemonCustodyProfile::WindowsSoftwareKsp => {
                Ok(Self { profile })
            }
            other => Err(RemoteIdentityCustodyError::PolicyDenied(format!(
                "{} is not a Windows custody profile",
                other.platform_label()
            ))),
        }
    }

    fn provider_name(&self) -> *const u16 {
        match self.profile {
            DaemonCustodyProfile::WindowsCngTpm => MS_PLATFORM_CRYPTO_PROVIDER,
            _ => MS_KEY_STORAGE_PROVIDER,
        }
    }

    fn open_provider(&self) -> Result<NcryptHandle, RemoteIdentityCustodyError> {
        let mut provider: NCRYPT_PROV_HANDLE = 0;
        // SAFETY: out-pointer is valid; provider name is a static PCWSTR.
        let code = unsafe { NCryptOpenStorageProvider(&mut provider, self.provider_name(), 0) };
        status("open provider", code)?;
        Ok(NcryptHandle(provider as usize))
    }

    /// Key-name prefix shared by every generation of a handle (for enumeration).
    fn key_name_prefix(handle: RemoteIdentityCustodyHandleId) -> String {
        format!(
            "flycockpit-remote-daemon-custody-{}.",
            handle
                .0
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    }

    /// Key name for `(handle, generation)`: `<prefix><generation>`, so a key and
    /// its record can never desync and generations coexist during rotation.
    fn key_name(handle: RemoteIdentityCustodyHandleId, generation: u64) -> Vec<u16> {
        wide(&format!("{}{generation}", Self::key_name_prefix(handle)))
    }

    fn export_public(
        key: NCRYPT_KEY_HANDLE,
    ) -> Result<RemoteIdentityP256PublicKey, RemoteIdentityCustodyError> {
        let mut needed: u32 = 0;
        // SAFETY: first call queries the required buffer size.
        let code = unsafe {
            NCryptExportKey(
                key,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
                &mut needed,
                0,
            )
        };
        status("export size", code)?;
        let mut buffer = vec![0u8; needed as usize];
        // SAFETY: buffer is `needed` bytes; NCrypt writes at most that many.
        let code = unsafe {
            NCryptExportKey(
                key,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                std::ptr::null(),
                buffer.as_mut_ptr(),
                needed,
                &mut needed,
                0,
            )
        };
        status("export", code)?;
        parse_ecc_public_blob(&buffer)
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

    fn create_key(
        &self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<RemoteIdentityP256PublicKey, RemoteIdentityCustodyError> {
        let provider = self.open_provider()?;
        let name = Self::key_name(handle, generation);
        let mut key: NCRYPT_KEY_HANDLE = 0;
        // SAFETY: provider handle is live; name is a NUL-terminated PCWSTR.
        let code = unsafe {
            NCryptCreatePersistedKey(
                provider.0 as NCRYPT_PROV_HANDLE,
                &mut key,
                BCRYPT_ECDSA_P256_ALGORITHM,
                name.as_ptr(),
                0,
                NCRYPT_OVERWRITE_KEY_FLAG,
            )
        };
        status("create key", code)?;
        let key_guard = NcryptHandle(key as usize);

        // Export policy = 0: the private key is nonexportable.
        let export_policy: u32 = 0;
        let _ = NCRYPT_ALLOW_EXPORT_FLAG; // documented: we clear it (policy = 0).
        // SAFETY: property name is a static PCWSTR; input is a 4-byte u32.
        let code = unsafe {
            NCryptSetProperty(
                key,
                NCRYPT_EXPORT_POLICY_PROPERTY,
                &export_policy as *const u32 as *const u8,
                std::mem::size_of::<u32>() as u32,
                0,
            )
        };
        status("set export policy", code)?;

        // SAFETY: key handle is live and not yet finalized.
        let code = unsafe { NCryptFinalizeKey(key, 0) };
        status("finalize", code)?;

        let public_key = Self::export_public(key)?;
        drop(key_guard);
        drop(provider);
        Ok(public_key)
    }

    fn open_key(
        &self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<(NcryptHandle, NcryptHandle), RemoteIdentityCustodyError> {
        let provider = self.open_provider()?;
        let name = Self::key_name(handle, generation);
        let mut key: NCRYPT_KEY_HANDLE = 0;
        // SAFETY: provider handle live; name is a NUL-terminated PCWSTR.
        let code = unsafe {
            NCryptOpenKey(
                provider.0 as NCRYPT_PROV_HANDLE,
                &mut key,
                name.as_ptr(),
                0,
                0,
            )
        };
        if code != 0 {
            return Err(RemoteIdentityCustodyError::NotFound);
        }
        Ok((provider, NcryptHandle(key as usize)))
    }
}

impl WindowsCustodyAdapter {
    /// Delete every generation's key for a handle by enumerating the provider's
    /// keys and matching the handle's shared name prefix.
    fn delete_all_matching(
        &self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<bool, RemoteIdentityCustodyError> {
        let provider = self.open_provider()?;
        let prefix = Self::key_name_prefix(handle);
        let mut enum_state: *mut c_void = std::ptr::null_mut();
        let mut deleted = false;
        loop {
            let mut name_ptr: *mut NCryptKeyName = std::ptr::null_mut();
            // SAFETY: provider is live; enum_state is carried across iterations.
            let code = unsafe {
                NCryptEnumKeys(
                    provider.0 as NCRYPT_PROV_HANDLE,
                    std::ptr::null(),
                    &mut name_ptr,
                    &mut enum_state,
                    0,
                )
            };
            if code == NTE_NO_MORE_ITEMS {
                break;
            }
            status("enum keys", code)?;
            // SAFETY: NCrypt returned a valid NCryptKeyName with a NUL-terminated
            // pszName; we copy it out before freeing.
            let name = unsafe { wide_ptr_to_string((*name_ptr).pszName) };
            unsafe { NCryptFreeBuffer(name_ptr as *mut c_void) };
            if name.starts_with(&prefix) {
                let wname = wide(&name);
                let mut key: NCRYPT_KEY_HANDLE = 0;
                // SAFETY: provider live; wname is NUL-terminated.
                let opened = unsafe {
                    NCryptOpenKey(
                        provider.0 as NCRYPT_PROV_HANDLE,
                        &mut key,
                        wname.as_ptr(),
                        0,
                        0,
                    )
                };
                if opened == 0 {
                    // SAFETY: key is live; NCryptDeleteKey consumes it.
                    let code = unsafe { NCryptDeleteKey(key, 0) };
                    status("delete key(enum)", code)?;
                    deleted = true;
                }
            }
        }
        if !enum_state.is_null() {
            unsafe { NCryptFreeBuffer(enum_state) };
        }
        Ok(deleted)
    }
}

impl DaemonCustodyAdapter for WindowsCustodyAdapter {
    fn create(
        &mut self,
        _profile: DaemonCustodyProfile,
        _subject_kind: SubjectKind,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<AdapterKeyMaterial, RemoteIdentityCustodyError> {
        let public_key = self.create_key(handle, generation)?;
        let provider_evidence = self.attestation(&public_key);
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
        let (_provider, key) = self.open_key(handle, generation)?;
        Self::export_public(key.0 as NCRYPT_KEY_HANDLE)
    }

    fn retire(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
    ) -> Result<(), RemoteIdentityCustodyError> {
        let (_provider, key) = self.open_key(handle, generation)?;
        // SAFETY: key handle is live; NCryptDeleteKey consumes it.
        let code = unsafe { NCryptDeleteKey(key.0 as NCRYPT_KEY_HANDLE, 0) };
        std::mem::forget(key); // deleted; do not double-free.
        status("delete key(retire)", code)
    }

    fn destroy_all(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
    ) -> Result<(), RemoteIdentityCustodyError> {
        if self.delete_all_matching(handle)? {
            Ok(())
        } else {
            Err(RemoteIdentityCustodyError::NotFound)
        }
    }

    fn sign(
        &mut self,
        handle: RemoteIdentityCustodyHandleId,
        generation: u64,
        digest: &[u8; 32],
    ) -> Result<[u8; 64], RemoteIdentityCustodyError> {
        let (_provider, key) = self.open_key(handle, generation)?;
        let mut needed: u32 = 0;
        // SAFETY: query the signature length (null padding info for ECDSA).
        let code = unsafe {
            NCryptSignHash(
                key.0 as NCRYPT_KEY_HANDLE,
                std::ptr::null::<c_void>(),
                digest.as_ptr(),
                digest.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut needed,
                0,
            )
        };
        status("sign size", code)?;
        let mut signature = vec![0u8; needed as usize];
        // SAFETY: signature buffer is `needed` bytes.
        let code = unsafe {
            NCryptSignHash(
                key.0 as NCRYPT_KEY_HANDLE,
                std::ptr::null::<c_void>(),
                digest.as_ptr(),
                digest.len() as u32,
                signature.as_mut_ptr(),
                needed,
                &mut needed,
                0,
            )
        };
        status("sign", code)?;
        signature.truncate(needed as usize);
        let raw: [u8; 64] = signature.as_slice().try_into().map_err(|_| {
            RemoteIdentityCustodyError::InvalidEvidence("NCrypt signature length".into())
        })?;
        super::normalize_p1363_low_s(&raw)
    }
}

/// Parse a `BCRYPT_ECCPUBLIC_BLOB` (a `BCRYPT_ECCKEY_BLOB` header followed by X
/// then Y, each `cbKey` bytes) into affine coordinates.
fn parse_ecc_public_blob(
    blob: &[u8],
) -> Result<RemoteIdentityP256PublicKey, RemoteIdentityCustodyError> {
    let header = std::mem::size_of::<BCRYPT_ECCKEY_BLOB>();
    let malformed =
        || RemoteIdentityCustodyError::InvalidEvidence("malformed BCRYPT_ECCPUBLIC_BLOB".into());
    if blob.len() < header {
        return Err(malformed());
    }
    // SAFETY: length checked; the header is plain-old-data.
    let ecc: BCRYPT_ECCKEY_BLOB =
        unsafe { std::ptr::read_unaligned(blob.as_ptr() as *const BCRYPT_ECCKEY_BLOB) };
    if ecc.dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || ecc.cbKey != 32 {
        return Err(malformed());
    }
    let body = &blob[header..];
    if body.len() < 64 {
        return Err(malformed());
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&body[..32]);
    y.copy_from_slice(&body[32..64]);
    Ok(RemoteIdentityP256PublicKey { x, y })
}
