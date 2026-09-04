//! Daemon-private owner capability for in-process clients.
//!
//! Pre-launch mitigation for issue #296: confined children are denied the
//! control-plane paths via sandbox deny lists. Socket admission (issue #337)
//! uses peer-bound credentials from `SO_PEERCRED` attestation, not this file.

use std::path::Path;

use anyhow::{Context, Result};
use rand::RngExt as _;

use super::DaemonPaths;

/// In-memory owner capability minted once per daemon boot.
#[derive(Clone)]
pub struct OwnerCapability {
    token: String,
}

impl std::fmt::Debug for OwnerCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OwnerCapability([redacted])")
    }
}

impl OwnerCapability {
    pub fn mint() -> Self {
        let mut bytes = [0_u8; 32];
        rand::rng().fill(&mut bytes);
        Self {
            token: crate::intel::hex_lower(&bytes),
        }
    }

    pub fn verify(&self, presented: &str) -> bool {
        constant_time_eq(self.token.as_bytes(), presented.as_bytes())
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    /// Write the token to the 0600 file next to the control socket for
    /// sandbox deny-path tests and fixtures. Socket peers must not use this
    /// file for owner admission (issue #337).
    pub fn publish(&self, socket: &Path) -> Result<()> {
        let path = DaemonPaths::owner_capability_path_for_socket(socket);
        if let Some(parent) = path.parent() {
            cockpit_host::private_fs::ensure_private_dir(parent)
                .with_context(|| format!("securing {}", parent.display()))?;
        }
        cockpit_host::private_fs::write_private_file(&path, self.token.as_bytes())
            .with_context(|| format!("writing {}", path.display()))
    }
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_accepts_the_minted_token_and_rejects_anything_else() {
        let capability = OwnerCapability::mint();
        assert!(capability.verify(capability.token()));
        assert!(!capability.verify(""));
        assert!(!capability.verify("00".repeat(32).as_str()));
        let other = OwnerCapability::mint();
        assert!(!capability.verify(other.token()));
        assert_ne!(capability.token(), other.token());
    }

    #[test]
    fn debug_does_not_include_the_token() {
        let capability = OwnerCapability::mint();
        let rendered = format!("{capability:?}");
        assert_eq!(rendered, "OwnerCapability([redacted])");
        assert!(!rendered.contains(capability.token()));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn publish_writes_a_private_file_next_to_the_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("cockpit.sock");
        let capability = OwnerCapability::mint();
        capability.publish(&socket).expect("publish");
        let path = DaemonPaths::owner_capability_path_for_socket(&socket);
        let bytes = std::fs::read(&path).expect("read capability");
        assert_eq!(bytes, capability.token().as_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
