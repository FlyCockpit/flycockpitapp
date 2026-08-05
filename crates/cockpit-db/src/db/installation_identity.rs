//! Canonical installation identity singleton.
//!
//! One row of 16 random bytes. Exposed to callers as 32 lowercase hex
//! characters. Never derived from hostname, machine-id, user, config, env,
//! or caller input. Database loss yields a fresh identity; native items from
//! a prior identity are never adopted.

use anyhow::{Context, Result, bail};
use chrono::Utc;
use rand::Rng;
use rusqlite::{OptionalExtension, params};

use crate::db::Db;

/// Exactly 16 random identity bytes.
pub const INSTALLATION_IDENTITY_BYTE_LEN: usize = 16;
/// Lowercase hex encoding of [`INSTALLATION_IDENTITY_BYTE_LEN`].
pub const INSTALLATION_IDENTITY_HEX_LEN: usize = INSTALLATION_IDENTITY_BYTE_LEN * 2;

/// Singleton installation identity as 32 lowercase hex characters.
#[derive(Clone, PartialEq, Eq)]
pub struct InstallationIdentity {
    hex: String,
}

impl InstallationIdentity {
    pub fn as_hex(&self) -> &str {
        &self.hex
    }

    pub fn into_hex(self) -> String {
        self.hex
    }

    /// Construct from already-validated lowercase hex (tests / roundtrips).
    pub fn from_hex_checked(hex: impl Into<String>) -> Result<Self> {
        let hex = hex.into();
        if hex.len() != INSTALLATION_IDENTITY_HEX_LEN {
            bail!("installation identity hex must be {INSTALLATION_IDENTITY_HEX_LEN} characters");
        }
        if !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            bail!("installation identity hex must be lowercase hex");
        }
        Ok(Self { hex })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != INSTALLATION_IDENTITY_BYTE_LEN {
            bail!(
                "installation identity must be {INSTALLATION_IDENTITY_BYTE_LEN} bytes, got {}",
                bytes.len()
            );
        }
        Ok(Self {
            hex: bytes.iter().map(|b| format!("{b:02x}")).collect(),
        })
    }
}

impl std::fmt::Debug for InstallationIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallationIdentity")
            .field("hex", &self.hex)
            .finish()
    }
}

impl std::fmt::Display for InstallationIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Identity is nonsecret coordination material (not key bytes).
        f.write_str(&self.hex)
    }
}

impl Db {
    /// Load the singleton installation identity, creating it with 16 random
    /// bytes in the same transaction when absent.
    pub async fn ensure_installation_identity(&self) -> Result<InstallationIdentity> {
        self.write(ensure_installation_identity_conn).await
    }

    /// Load the singleton without creating it.
    pub async fn load_installation_identity(&self) -> Result<Option<InstallationIdentity>> {
        self.read(load_installation_identity_conn).await
    }
}

/// Create-or-load the singleton on a writer connection (transactional).
pub fn ensure_installation_identity_conn(
    conn: &rusqlite::Connection,
) -> Result<InstallationIdentity> {
    if let Some(existing) = load_installation_identity_conn(conn)? {
        return Ok(existing);
    }
    let mut bytes = [0u8; INSTALLATION_IDENTITY_BYTE_LEN];
    rand::rng().fill_bytes(&mut bytes);
    let now = Utc::now().timestamp();
    conn.execute(
        "INSERT INTO installation_identity (id, identity_bytes, created_at)
         VALUES (1, ?1, ?2)",
        params![bytes.as_slice(), now],
    )
    .context("inserting installation identity")?;
    InstallationIdentity::from_bytes(&bytes)
}

/// Read the singleton without creating it.
pub fn load_installation_identity_conn(
    conn: &rusqlite::Connection,
) -> Result<Option<InstallationIdentity>> {
    let row: Option<Vec<u8>> = conn
        .query_row(
            "SELECT identity_bytes FROM installation_identity WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("loading installation identity")?;
    match row {
        Some(bytes) => Ok(Some(InstallationIdentity::from_bytes(&bytes)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn creates_stable_hex_identity() {
        let db = Db::open_in_memory().unwrap();
        let first = db.ensure_installation_identity().await.unwrap();
        assert_eq!(first.as_hex().len(), INSTALLATION_IDENTITY_HEX_LEN);
        assert!(
            first
                .as_hex()
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        );
        let second = db.ensure_installation_identity().await.unwrap();
        assert_eq!(first, second);
        let loaded = db.load_installation_identity().await.unwrap().unwrap();
        assert_eq!(loaded, first);
    }

    #[tokio::test]
    async fn loss_yields_new_identity() {
        let a = Db::open_in_memory().unwrap();
        let id_a = a.ensure_installation_identity().await.unwrap();
        let b = Db::open_in_memory().unwrap();
        let id_b = b.ensure_installation_identity().await.unwrap();
        // Independent databases almost surely differ; both are valid hex.
        assert_eq!(id_a.as_hex().len(), INSTALLATION_IDENTITY_HEX_LEN);
        assert_eq!(id_b.as_hex().len(), INSTALLATION_IDENTITY_HEX_LEN);
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn rejects_caller_supplied_non_hex() {
        assert!(InstallationIdentity::from_hex_checked("not-hex").is_err());
        assert!(InstallationIdentity::from_hex_checked("AA".repeat(16)).is_err());
    }
}
