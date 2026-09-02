//! Central typed resource-exhaustion limits for the daemon.
//!
//! Every allocation, reservation, decompression, and image-decode bound in
//! this crate must read from [`ResourceLimits`]. Call sites must not invent
//! their own byte, pixel, or lease constants. Defaults are conservative and
//! documented next to each field.
//!
//! Wire-visible protocol ceilings (per-operation terminal ingress, per-transfer
//! bulk length) stay in `cockpit-proto` so the CLI and TUI can share them
//! without depending on this crate's policy. Compile-time asserts below keep
//! those copies equal to this module.

use std::path::Path;

use sha2::{Digest, Sha256};

use cockpit_host::bounded::{self, BoundedIoError};

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// Daemon-wide resource-exhaustion policy.
///
/// Construct only through [`ResourceLimits::defaults`]. Tests that need a
/// smaller ceiling pass an explicit value into the helper that accepts a cap;
/// they do not clone this struct and patch a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Hard maximum size of a file `fs_read` will even open. Larger files
    /// fail closed instead of hashing or streaming for unbounded time.
    /// 64 MiB covers a file-tree click without letting a 50 GiB sparse file
    /// stall the daemon.
    pub fs_read_max_file_bytes: u64,
    /// Bytes of text content `fs_read` returns. Matches the tool output cap
    /// so a file-tree open cannot exceed what the read tool would emit.
    pub fs_read_text_bytes: usize,
    /// Bytes of binary/base64 content `fs_read` returns.
    pub fs_read_binary_bytes: usize,
    /// Maximum existing-file body `write` / `delete` will load for the
    /// prior-content / change-detection path. Larger files fail closed.
    pub fs_mutation_read_bytes: u64,
    /// Maximum LSP `Content-Length` the daemon will allocate. The subprocess
    /// supplies this number; it is not trusted.
    pub lsp_message_bytes: usize,
    /// Maximum bytes of one LSP header line, including `Content-Length`.
    pub lsp_header_line_bytes: usize,
    /// Maximum LSP header lines before the blank separator.
    pub lsp_header_line_count: usize,
    /// Per-operation terminal-ingress payload. Must equal
    /// [`cockpit_proto::terminal::TERMINAL_INGRESS_MAX_BYTES`].
    pub terminal_ingress_operation_bytes: u64,
    /// Per-chunk terminal-ingress payload. Must equal
    /// [`cockpit_proto::terminal::TERMINAL_INGRESS_MAX_CHUNK_BYTES`].
    pub terminal_ingress_chunk_bytes: usize,
    /// Aggregate prepared terminal-ingress reservations one client may hold
    /// across every terminal. One 10 MiB operation is allowed; a second
    /// concurrent 10 MiB prepare is not.
    pub terminal_ingress_client_prepared_bytes: u64,
    /// Concurrent prepared terminal-ingress operations one client may hold.
    pub terminal_ingress_client_prepared_ops: usize,
    /// Global bulk-staging reservation. Must equal
    /// [`cockpit_proto::bulk_transfer::MAX_TRANSFER_BYTES`].
    pub bulk_staged_bytes_global: u64,
    /// Bulk-staging reservation one client may hold. Strictly less than the
    /// global budget so one peer cannot squat the store.
    pub bulk_staged_bytes_per_client: u64,
    /// Global bulk-staging entry cap (including zero-length transfers).
    pub bulk_staged_transfers_global: usize,
    /// Bulk-staging entries one client may hold.
    pub bulk_staged_transfers_per_client: usize,
    /// Non-renewable bulk-staging lease, milliseconds from first reservation.
    /// Writes do not extend it.
    pub bulk_lease_ms: u64,
    /// Image decode: maximum width in pixels.
    pub image_max_width: u32,
    /// Image decode: maximum height in pixels.
    pub image_max_height: u32,
    /// Image decode: maximum `width * height`.
    pub image_max_pixels: u64,
    /// Image decode: maximum RGBA allocation. `pixels * 4` must fit.
    pub image_max_alloc_bytes: u64,
    /// Encoded image input bytes accepted before decode.
    pub image_max_input_bytes: usize,
    /// Encoded image output bytes accepted after encode.
    pub image_max_output_bytes: usize,
    /// Session-archive ZIP, compressed, on disk or in staging.
    pub archive_compressed_bytes: u64,
    /// Session-archive ZIP, total decompressed bytes actually read. Header
    /// `uncompressed_size` is never trusted as an allocation size.
    pub archive_decompressed_bytes: u64,
    /// Session-archive ZIP entry count.
    pub archive_entry_count: usize,
    /// Single ZIP member decompressed size.
    pub archive_entry_bytes: u64,
}

impl ResourceLimits {
    /// Conservative production defaults. These are the only numbers the
    /// daemon uses; keep comments next to the fields in lockstep with the
    /// values.
    pub const fn defaults() -> Self {
        Self {
            fs_read_max_file_bytes: 64 * MIB,
            fs_read_text_bytes: 8 * 1024,
            fs_read_binary_bytes: 256 * 1024,
            fs_mutation_read_bytes: 64 * MIB,
            lsp_message_bytes: 8 * 1024 * 1024,
            lsp_header_line_bytes: 8 * 1024,
            lsp_header_line_count: 32,
            terminal_ingress_operation_bytes: 10 * MIB,
            terminal_ingress_chunk_bytes: 48 * 1024,
            terminal_ingress_client_prepared_bytes: 16 * MIB,
            terminal_ingress_client_prepared_ops: 2,
            bulk_staged_bytes_global: 512 * MIB,
            bulk_staged_bytes_per_client: 64 * MIB,
            bulk_staged_transfers_global: 256,
            bulk_staged_transfers_per_client: 32,
            bulk_lease_ms: 5 * 60 * 1000,
            image_max_width: 8_192,
            image_max_height: 8_192,
            image_max_pixels: 40_000_000,
            image_max_alloc_bytes: 160_000_000,
            image_max_input_bytes: 64 * 1024 * 1024,
            image_max_output_bytes: 64 * 1024 * 1024,
            archive_compressed_bytes: 512 * MIB,
            archive_decompressed_bytes: GIB,
            archive_entry_count: 16_384,
            archive_entry_bytes: 32 * MIB,
        }
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self::defaults()
    }
}

const _: () = {
    let limits = ResourceLimits::defaults();
    assert!(limits.fs_read_text_bytes > 0);
    assert!(limits.fs_read_binary_bytes >= limits.fs_read_text_bytes);
    assert!(limits.fs_read_max_file_bytes >= limits.fs_read_binary_bytes as u64);
    assert!(limits.bulk_staged_bytes_per_client < limits.bulk_staged_bytes_global);
    assert!(limits.bulk_staged_transfers_per_client < limits.bulk_staged_transfers_global);
    assert!(
        limits.terminal_ingress_client_prepared_bytes >= limits.terminal_ingress_operation_bytes
    );
    assert!(limits.image_max_alloc_bytes >= limits.image_max_pixels.saturating_mul(4));
    assert!(
        limits.terminal_ingress_operation_bytes
            == cockpit_proto::terminal::TERMINAL_INGRESS_MAX_BYTES
    );
    assert!(
        limits.terminal_ingress_chunk_bytes
            == cockpit_proto::terminal::TERMINAL_INGRESS_MAX_CHUNK_BYTES
    );
    assert!(limits.bulk_staged_bytes_global == cockpit_proto::bulk_transfer::MAX_TRANSFER_BYTES);
};

/// Stable per-client quota identity. Opaque 32-byte key so this module does
/// not depend on principal or terminal types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientQuotaKey([u8; 32]);

impl ClientQuotaKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn hash_material(label: &[u8], material: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(label);
        hasher.update(material);
        Self(hasher.finalize().into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    pub fn for_test(tag: u8) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0] = tag;
        bytes[31] = 1;
        Self(bytes)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ResourceLimitError {
    #[error("{what} exceeds the {limit} byte limit ({actual} bytes)")]
    ByteLimit {
        what: &'static str,
        limit: u64,
        actual: u64,
    },
    #[error(transparent)]
    Io(#[from] BoundedIoError),
}

impl ResourceLimitError {
    pub fn byte_limit(what: &'static str, limit: u64, actual: u64) -> Self {
        Self::ByteLimit {
            what,
            limit,
            actual,
        }
    }
}

/// Load an existing file for `write` / `delete` prior-content checks.
pub fn read_existing_for_mutation(path: &Path) -> Result<Vec<u8>, ResourceLimitError> {
    let cap = ResourceLimits::defaults().fs_mutation_read_bytes;
    bounded::read_at_most(path, cap).map_err(|error| match error {
        BoundedIoError::Limit { actual, .. } => {
            ResourceLimitError::byte_limit("existing file", cap, actual)
        }
        other => ResourceLimitError::Io(other),
    })
}

/// Streamed equality check so mutation tools never hold the file twice.
pub fn existing_file_unchanged(path: &Path, previous: &[u8]) -> Result<bool, ResourceLimitError> {
    Ok(bounded::contents_equal(path, previous).map_err(BoundedIoError::from)?)
}

/// `fs_read` streaming seam: prefix for the response plus a full-file digest.
pub fn read_for_fs_read(path: &Path) -> Result<bounded::PrefixedFile, ResourceLimitError> {
    let limits = ResourceLimits::defaults();
    let prefix_cap = limits.fs_read_text_bytes.max(limits.fs_read_binary_bytes);
    bounded::read_prefix_and_hash(path, prefix_cap, limits.fs_read_max_file_bytes).map_err(
        |error| match error {
            BoundedIoError::Limit { actual, .. } => ResourceLimitError::byte_limit(
                "filesystem read",
                limits.fs_read_max_file_bytes,
                actual,
            ),
            other => ResourceLimitError::Io(other),
        },
    )
}

/// Refuse a declared length before `vec![0; len]` or `with_capacity`.
pub fn ensure_declared_len(
    len: u64,
    cap: u64,
    what: &'static str,
) -> Result<(), ResourceLimitError> {
    if len > cap {
        return Err(ResourceLimitError::byte_limit(what, cap, len));
    }
    Ok(())
}

/// Hex SHA-256 of `bytes`. Shared so `fs_read` does not keep a private hasher.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

pub fn sha256_hex_array(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn defaults_are_strictly_layered() {
        let limits = ResourceLimits::defaults();
        assert!(limits.bulk_staged_bytes_per_client < limits.bulk_staged_bytes_global);
        assert!(limits.bulk_staged_transfers_per_client < limits.bulk_staged_transfers_global);
        assert!(limits.terminal_ingress_client_prepared_ops >= 1);
        assert_eq!(
            limits.terminal_ingress_operation_bytes,
            cockpit_proto::terminal::TERMINAL_INGRESS_MAX_BYTES
        );
        assert_eq!(
            limits.bulk_staged_bytes_global,
            cockpit_proto::bulk_transfer::MAX_TRANSFER_BYTES
        );
        assert_eq!(
            limits.fs_read_text_bytes,
            crate::tools::common::OUTPUT_BYTE_CAP
        );
    }

    #[test]
    fn ensure_declared_len_rejects_over_cap() {
        let err = ensure_declared_len(9, 8, "LSP message").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("LSP message"), "{text}");
        assert!(text.contains("8"), "{text}");
        assert!(text.contains("9"), "{text}");
    }

    #[test]
    fn mutation_read_rejects_an_oversized_sparse_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sparse");
        let file = File::create(&path).unwrap();
        let over = ResourceLimits::defaults().fs_mutation_read_bytes + 1;
        file.set_len(over).unwrap();
        drop(file);
        let err = read_existing_for_mutation(&path).unwrap_err();
        match err {
            ResourceLimitError::ByteLimit { actual, limit, .. } => {
                assert_eq!(actual, over);
                assert_eq!(limit, ResourceLimits::defaults().fs_mutation_read_bytes);
            }
            other => panic!("expected byte limit, got {other}"),
        }
    }

    #[test]
    fn mutation_read_accepts_a_small_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small");
        std::fs::write(&path, b"hello").unwrap();
        assert_eq!(read_existing_for_mutation(&path).unwrap(), b"hello");
        assert!(existing_file_unchanged(&path, b"hello").unwrap());
        assert!(!existing_file_unchanged(&path, b"hellp").unwrap());
    }

    #[test]
    fn fs_read_helper_rejects_over_max_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("over");
        let file = File::create(&path).unwrap();
        let over = ResourceLimits::defaults().fs_read_max_file_bytes + 1;
        file.set_len(over).unwrap();
        drop(file);
        let err = read_for_fs_read(&path).unwrap_err();
        assert!(err.to_string().contains("filesystem read"), "{err}");
    }

    #[test]
    fn quota_keys_are_stable_and_distinct() {
        let a = ClientQuotaKey::hash_material(b"label", b"alice");
        let b = ClientQuotaKey::hash_material(b"label", b"bob");
        assert_eq!(a, ClientQuotaKey::hash_material(b"label", b"alice"));
        assert_ne!(a, b);
        assert_ne!(ClientQuotaKey::for_test(1), ClientQuotaKey::for_test(2));
    }
}
