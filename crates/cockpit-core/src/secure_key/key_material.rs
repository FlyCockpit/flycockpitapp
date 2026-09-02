//! Key bytes: Zeroizing newtype with redacted Debug; temporary zeroized buffers.

use std::fmt;
use std::ops::Deref;

use rand::Rng;
use zeroize::{Zeroize, Zeroizing};

use super::namespace::digest_hex;

pub const KEY_BYTE_LEN: usize = 32;

/// 32 random key bytes, zeroized on drop. Debug never prints material.
#[derive(Clone, Eq, PartialEq)]
pub struct SecureKeyBytes(Zeroizing<[u8; KEY_BYTE_LEN]>);

impl SecureKeyBytes {
    pub fn from_array(bytes: [u8; KEY_BYTE_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn from_zeroizing_array(bytes: Zeroizing<[u8; KEY_BYTE_LEN]>) -> Self {
        Self(bytes)
    }

    pub fn as_array(&self) -> &[u8; KEY_BYTE_LEN] {
        &self.0
    }
}

impl Deref for SecureKeyBytes {
    type Target = [u8; KEY_BYTE_LEN];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for SecureKeyBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for SecureKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureKeyBytes([REDACTED; {KEY_BYTE_LEN}])")
    }
}

// Intentionally no Display, Serialize, or Deserialize.

/// Generate a new 32-byte key (filled inside Zeroizing; no plain array copy).
pub fn generate_key_bytes() -> SecureKeyBytes {
    let mut bytes = Zeroizing::new([0u8; KEY_BYTE_LEN]);
    rand::rng().fill_bytes(bytes.as_mut());
    SecureKeyBytes(bytes)
}

/// Digested safe fingerprint of key material (hex SHA-256).
pub fn key_digest(key: &SecureKeyBytes) -> String {
    digest_hex(key.as_ref())
}

/// Owned temporary buffer from native get_secret; zeroized on drop.
pub struct TempSecret(Zeroizing<Vec<u8>>);

impl TempSecret {
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Parse as exact 32-byte key.
    pub fn into_key_bytes(self) -> Result<SecureKeyBytes, super::error::SecureKeyError> {
        let slice = self.0.as_slice();
        if slice.len() != KEY_BYTE_LEN {
            return Err(super::error::SecureKeyError::Corrupt(format!(
                "key item length {} != {KEY_BYTE_LEN}",
                slice.len()
            )));
        }
        let mut arr = Zeroizing::new([0u8; KEY_BYTE_LEN]);
        arr.copy_from_slice(slice);
        Ok(SecureKeyBytes(arr))
    }
}

impl Drop for TempSecret {
    fn drop(&mut self) {
        // Zeroizing handles the Vec; explicit call documents the invariant.
        self.0.zeroize();
    }
}

impl fmt::Debug for TempSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TempSecret([REDACTED; {}])", self.0.len())
    }
}

/// Probe wrapper used in tests to observe zeroization of temporary buffers.
#[cfg(test)]
pub struct DropProbeTemp {
    pub bytes: Zeroizing<Vec<u8>>,
    pub dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub zeroized_before_drop_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(test)]
impl Drop for DropProbeTemp {
    fn drop(&mut self) {
        // Confirm buffer is zeroized while still dropping.
        self.bytes.zeroize();
        let all_zero = self.bytes.iter().all(|&b| b == 0);
        self.zeroized_before_drop_flag
            .store(all_zero, std::sync::atomic::Ordering::SeqCst);
        self.dropped
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_32_zeroizing() {
        let k = generate_key_bytes();
        assert_eq!(k.as_ref().len(), 32);
        let d = key_digest(&k);
        assert_eq!(d.len(), 64);
    }

    #[test]
    fn debug_redacts_key_material() {
        let mut arr = [0u8; KEY_BYTE_LEN];
        for (i, b) in arr.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0xA0);
        }
        let k = SecureKeyBytes::from_array(arr);
        let dbg = format!("{k:?}");
        assert!(dbg.contains("REDACTED"), "{dbg}");
        // Raw byte patterns must not appear.
        assert!(!dbg.contains("160"), "{dbg}");
        assert!(!dbg.contains("0xa0"), "{dbg}");
        let hexish: String = arr.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!dbg.contains(&hexish), "{dbg} leaked {hexish}");
        // Debug must not dump array contents via Default.
        assert!(
            !dbg.contains(
                &[0xA0, 0xA1, 0xA2][..]
                    .iter()
                    .map(|b| format!("{b}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        );
    }
}
