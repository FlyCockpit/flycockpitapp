//! Protected redaction history: durable encrypted literal store for redacting
//! historical trusted-provider artifacts.
//!
//! This module implements the sole writer API
//! [`ProtectedRedactionHistory::append_and_attach`] and the bounded zeroizing
//! local rehydration frame [`RedactionRehydrationFrame`].
//!
//! ## Design
//!
//! Every artifact-bearing sensitive ingress atomically commits its protected
//! history reference before its raw trusted artifact can become durable. The
//! literal is stored ONLY as encrypted ciphertext + nonce, keyed by an opaque
//! history ID and the local key-store key version. No plaintext, prefix,
//! length, ciphertext, nonce, or key version ever appears in ordinary query,
//! protocol, diagnostics, or export data.
//!
//! The closed source set ([`RedactionHistorySource`]) is exhaustive: no
//! caller may introduce a new source without a matching closed-writer
//! classification here. The sole writer API classifies, encrypts, journals,
//! and attaches in one local SQLite transaction; a crash at either ordering
//! point commits neither the history row nor the artifact reference.
//!
//! Rehydration is bounded and zeroized: literals live only inside a
//! [`RedactionRehydrationFrame`] that is dropped (zeroized) at scope exit,
//! never serialized into persisted ordinary redaction JSON, and never read
//! outside an Owner-sensitive or export-redaction frame.

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::db::Db;
use crate::db::protected_redaction_history::{
    AppendHistoryResult, ProtectedRedactionHistoryAppend, ProtectedRedactionHistoryRow,
    append_history_conn, attach_artifact_ref_conn, list_history_for_artifact_conn,
};

/// Re-export the closed source set so callers do not depend on the db crate
/// directly for these types.
pub use crate::db::protected_redaction_history::ProtectedRedactionSource as RedactionHistorySource;

/// Re-export the artifact kind for callers.
pub use crate::db::protected_redaction_history::ProtectedRedactionArtifactKind as RedactionArtifactKind;

/// Maximum literal length accepted by the rehydration frame (16 KiB).
pub const MAX_LITERAL_LEN: usize = 16 * 1024;

/// Nonce length for AEAD encryption (96-bit GCM nonce).
pub const NONCE_LEN: usize = 12;

/// Key length for the local redaction-history encryption key (256-bit).
pub const REDACTION_KEY_LEN: usize = 32;

/// The secure-key namespace for protected redaction-history encryption keys.
pub const REDACTION_HISTORY_NAMESPACE: &str = "redaction-history/v1";

/// One closed sensitive literal prepared for journaling. The literal lives
/// only inside a [`Zeroizing`] wrapper and is never exposed in Debug.
pub struct ProtectedLiteral {
    literal: Zeroizing<Vec<u8>>,
    source: RedactionHistorySource,
    sealed_record_id: Option<String>,
    sealed_version: Option<i64>,
}

impl ProtectedLiteral {
    /// Create a new protected literal from a sensitive string. The string is
    /// zeroized on drop. Fails if the literal exceeds [`MAX_LITERAL_LEN`].
    pub fn new(
        literal: String,
        source: RedactionHistorySource,
        sealed_record_id: Option<String>,
        sealed_version: Option<i64>,
    ) -> Result<Self> {
        if literal.len() > MAX_LITERAL_LEN {
            bail!(
                "protected literal length {} exceeds {MAX_LITERAL_LEN}",
                literal.len()
            );
        }
        Ok(Self {
            literal: Zeroizing::new(literal.into_bytes()),
            source,
            sealed_record_id,
            sealed_version,
        })
    }

    /// SHA-256 fingerprint of the literal (safe deduplication key).
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(&self.literal);
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The source classification.
    pub fn source(&self) -> RedactionHistorySource {
        self.source
    }

    /// The optional sealed-value record ID.
    pub fn sealed_record_id(&self) -> Option<&str> {
        self.sealed_record_id.as_deref()
    }

    /// The optional sealed-value version.
    pub fn sealed_version(&self) -> Option<i64> {
        self.sealed_version
    }

    /// The literal bytes (local rehydration frame only).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.literal
    }
}

impl std::fmt::Debug for ProtectedLiteral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtectedLiteral")
            .field("source", &self.source)
            .field("sealed_record_id", &self.sealed_record_id)
            .field("sealed_version", &self.sealed_version)
            .field(
                "literal",
                &format_args!("[REDACTED; {}]", self.literal.len()),
            )
            .finish()
    }
}

/// Local encryption key for protected redaction-history literals. Zeroized on
/// drop. In production this is resolved from the native secure key store; in
/// tests it is injected directly.
#[derive(Clone)]
pub struct RedactionHistoryKey {
    key: Zeroizing<[u8; REDACTION_KEY_LEN]>,
    version: i64,
}

impl RedactionHistoryKey {
    /// Create a key from raw bytes and a key-store version.
    pub fn new(bytes: [u8; REDACTION_KEY_LEN], version: i64) -> Self {
        Self {
            key: Zeroizing::new(bytes),
            version,
        }
    }

    /// The key-store version that this key belongs to.
    pub fn version(&self) -> i64 {
        self.version
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &*self.key
    }
}

impl std::fmt::Debug for RedactionHistoryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedactionHistoryKey")
            .field("version", &self.version)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Trait for resolving the local encryption key for a given key version.
/// In production this goes through the native secure key store; in tests it
/// is a simple map.
pub trait RedactionKeyResolver: Send + Sync {
    /// Resolve the key for the given version. Fails closed on any error.
    fn resolve(&self, version: i64) -> Result<RedactionHistoryKey>;
}

/// Test-only key resolver backed by a simple version-to-key map.
#[derive(Debug, Clone, Default)]
pub struct MapKeyResolver {
    keys: HashMap<i64, [u8; REDACTION_KEY_LEN]>,
}

impl MapKeyResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_version(mut self, version: i64, key: [u8; REDACTION_KEY_LEN]) -> Self {
        self.keys.insert(version, key);
        self
    }

    pub fn insert(&mut self, version: i64, key: [u8; REDACTION_KEY_LEN]) {
        self.keys.insert(version, key);
    }
}

impl RedactionKeyResolver for MapKeyResolver {
    fn resolve(&self, version: i64) -> Result<RedactionHistoryKey> {
        let key = self
            .keys
            .get(&version)
            .copied()
            .with_context(|| format!("no redaction key for version {version}"))?;
        Ok(RedactionHistoryKey::new(key, version))
    }
}

/// Encrypt a literal with the given key using a simple XOR-based stream cipher
/// seeded from SHA-256(key || nonce). This is a local-at-rest encryption
/// layer; the key itself lives in the native secure key store. The ciphertext
/// and nonce are stored in the history row.
///
/// Note: This is a deterministic stream cipher for local at-rest protection.
/// The security boundary is the key store custody, not the cipher itself.
/// A future iteration may use a proper AEAD; the schema and API are
/// AEAD-shaped (ciphertext + nonce + key version) to accommodate that.
fn encrypt_literal(key: &RedactionHistoryKey, nonce: &[u8], literal: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_LEN {
        bail!("nonce length must be {NONCE_LEN}");
    }
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    h.update(nonce);
    let seed = h.finalize();
    // Expand the 32-byte seed into a keystream long enough for the literal.
    let mut keystream = Vec::with_capacity(literal.len());
    let mut counter: u32 = 0;
    while keystream.len() < literal.len() {
        let mut block_hash = Sha256::new();
        block_hash.update(seed);
        block_hash.update(counter.to_be_bytes());
        let block = block_hash.finalize();
        keystream.extend_from_slice(&block);
        counter += 1;
    }
    let ciphertext: Vec<u8> = literal
        .iter()
        .zip(keystream.iter())
        .map(|(l, k)| l ^ k)
        .collect();
    Ok(ciphertext)
}

/// Decrypt a literal previously encrypted by [`encrypt_literal`].
fn decrypt_literal(
    key: &RedactionHistoryKey,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN {
        bail!("nonce length must be {NONCE_LEN}");
    }
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    h.update(nonce);
    let seed = h.finalize();
    let mut keystream = Vec::with_capacity(ciphertext.len());
    let mut counter: u32 = 0;
    while keystream.len() < ciphertext.len() {
        let mut block_hash = Sha256::new();
        block_hash.update(seed);
        block_hash.update(counter.to_be_bytes());
        let block = block_hash.finalize();
        keystream.extend_from_slice(&block);
        counter += 1;
    }
    let plaintext: Vec<u8> = ciphertext
        .iter()
        .zip(keystream.iter())
        .map(|(c, k)| c ^ k)
        .collect();
    Ok(Zeroizing::new(plaintext))
}

/// Generate a random nonce.
fn generate_nonce() -> Vec<u8> {
    use rand::Rng;
    let mut nonce = vec![0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// A rehydrated literal inside a bounded zeroizing frame. Dropping this
/// zeroizes the literal. The literal is never serialized into persisted
/// ordinary redaction JSON.
pub struct RehydratedLiteral {
    literal: Zeroizing<Vec<u8>>,
    fingerprint: String,
    source: RedactionHistorySource,
}

impl RehydratedLiteral {
    /// The literal as a string (local frame only). Fails if the bytes are
    /// not valid UTF-8.
    pub fn as_str(&self) -> Result<Zeroizing<String>> {
        let s = String::from_utf8(self.literal.clone().as_slice().to_vec())
            .context("rehydrated literal is not valid UTF-8")?;
        Ok(Zeroizing::new(s))
    }

    /// The literal bytes (local frame only).
    pub fn as_bytes(&self) -> &[u8] {
        &self.literal
    }

    /// SHA-256 fingerprint of the literal (safe to expose).
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The source classification (safe to expose).
    pub fn source(&self) -> RedactionHistorySource {
        self.source
    }
}

impl std::fmt::Debug for RehydratedLiteral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RehydratedLiteral")
            .field("fingerprint", &self.fingerprint)
            .field("source", &self.source)
            .field(
                "literal",
                &format_args!("[REDACTED; {}]", self.literal.len()),
            )
            .finish()
    }
}

/// A bounded zeroizing local redaction rehydration frame. Holds rehydrated
/// literals for the duration of a redaction pass and zeroizes them on drop.
/// No literal in this frame is ever serialized into persisted ordinary
/// redaction JSON.
pub struct RedactionRehydrationFrame {
    literals: Vec<RehydratedLiteral>,
}

impl RedactionRehydrationFrame {
    /// Create an empty frame.
    pub fn new() -> Self {
        Self {
            literals: Vec::new(),
        }
    }

    /// Add a rehydrated literal to this frame.
    pub fn push(&mut self, literal: RehydratedLiteral) {
        self.literals.push(literal);
    }

    /// Iterate over the rehydrated literals in this frame.
    pub fn iter(&self) -> impl Iterator<Item = &RehydratedLiteral> {
        self.literals.iter()
    }

    /// Number of literals in this frame.
    pub fn len(&self) -> usize {
        self.literals.len()
    }

    /// Whether this frame is empty.
    pub fn is_empty(&self) -> bool {
        self.literals.is_empty()
    }

    /// Collect the literals as zeroizing strings for redaction table
    /// construction. The caller must not persist these; they are for the
    /// live redaction matcher only.
    pub fn into_literals(self) -> Vec<Zeroizing<String>> {
        self.literals
            .into_iter()
            .filter_map(|l| l.as_str().ok())
            .collect()
    }
}

impl Default for RedactionRehydrationFrame {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RedactionRehydrationFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedactionRehydrationFrame")
            .field("count", &self.literals.len())
            .finish()
    }
}

/// The artifact reference for `append_and_attach`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRef {
    pub kind: RedactionArtifactKind,
    pub id: String,
}

impl ArtifactRef {
    pub fn new(kind: RedactionArtifactKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
        }
    }
}

/// The sole writer API for protected redaction history.
///
/// `append_and_attach` atomically appends (or deduplicates) a protected
/// history row and attaches opaque references to every durable artifact in
/// one local SQLite transaction. A crash at either ordering point commits
/// neither. Unknown raw sensitive material cannot persist as a trusted
/// artifact until this API classifies/journals it; failure discards/redacts
/// the artifact.
pub struct ProtectedRedactionHistory<'a> {
    db: &'a Db,
    key_resolver: &'a dyn RedactionKeyResolver,
}

impl<'a> ProtectedRedactionHistory<'a> {
    /// Create a new protected redaction history writer bound to a database
    /// and key resolver.
    pub fn new(db: &'a Db, key_resolver: &'a dyn RedactionKeyResolver) -> Self {
        Self { db, key_resolver }
    }

    /// The sole writer API. Atomically:
    /// 1. Encrypts the literal with the current key version.
    /// 2. Appends (or deduplicates) a protected history row.
    /// 3. Attaches opaque artifact references to that history row.
    ///
    /// All three steps run inside one [`Db::transaction`]. If any step fails,
    /// neither the history row nor the artifact references are committed.
    ///
    /// `source` must match the closed-writer classification. `literal` is
    /// consumed and zeroized. `artifacts` is the list of durable artifacts
    /// that reference this literal.
    pub async fn append_and_attach(
        &self,
        session_id: &str,
        literal: ProtectedLiteral,
        artifacts: Vec<ArtifactRef>,
    ) -> Result<String> {
        let session_id = session_id.to_owned();
        let fingerprint = literal.fingerprint();
        let source = literal.source();
        let sealed_record_id = literal.sealed_record_id().map(|s| s.to_owned());
        let sealed_version = literal.sealed_version();

        // Resolve the current key.
        let key_version = self.current_key_version();
        let key = self.key_resolver.resolve(key_version)?;

        // Encrypt the literal.
        let nonce = generate_nonce();
        let ciphertext = encrypt_literal(&key, &nonce, literal.as_bytes())?;

        // Build the append input.
        let append_input = ProtectedRedactionHistoryAppend {
            session_id: session_id.clone(),
            sealed_record_id: sealed_record_id.clone(),
            sealed_version,
            source,
            fingerprint: fingerprint.clone(),
            ciphertext,
            nonce,
            key_version,
        };

        // Run the append + attach in one transaction. The closure captures
        // only owned data (append_input, artifacts); the key resolver is not
        // needed inside the transaction because encryption already happened.
        let history_id = self
            .db
            .transaction(move |conn| {
                let result = append_history_conn(conn, &append_input)?;
                let history_id = match result {
                    AppendHistoryResult::Created { history_id } => history_id,
                    AppendHistoryResult::Existing { history_id } => history_id,
                };
                for artifact in &artifacts {
                    attach_artifact_ref_conn(conn, artifact.kind, &artifact.id, &history_id)?;
                }
                Ok(history_id)
            })
            .await?;

        Ok(history_id)
    }

    /// Rehydrate the literals referenced by one artifact into a bounded
    /// zeroizing frame. Fails closed on any key-store failure, integrity
    /// mismatch, or missing reference.
    pub async fn rehydrate_for_artifact(
        &self,
        artifact_kind: RedactionArtifactKind,
        artifact_id: &str,
    ) -> Result<RedactionRehydrationFrame> {
        let artifact_id = artifact_id.to_owned();
        let rows = self
            .db
            .read(move |conn| list_history_for_artifact_conn(conn, artifact_kind, &artifact_id))
            .await?;

        let mut frame = RedactionRehydrationFrame::new();
        for row in rows {
            let literal = self.rehydrate_row(&row)?;
            frame.push(literal);
        }
        Ok(frame)
    }

    /// Rehydrate one history row into a literal. Fails closed on any error.
    fn rehydrate_row(&self, row: &ProtectedRedactionHistoryRow) -> Result<RehydratedLiteral> {
        if row.retired_at_ms.is_some() {
            bail!("cannot rehydrate retired protected redaction history row");
        }
        let key = self.key_resolver.resolve(row.key_version)?;
        let plaintext = decrypt_literal(&key, &row.nonce, &row.ciphertext)?;

        // Verify fingerprint integrity.
        let digest = Sha256::digest(&plaintext);
        let computed_fingerprint: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        if computed_fingerprint != row.fingerprint {
            bail!("protected redaction history fingerprint mismatch (integrity failure)");
        }

        Ok(RehydratedLiteral {
            literal: plaintext,
            fingerprint: row.fingerprint.clone(),
            source: row.source,
        })
    }

    /// Get the current key version. In this implementation, version 1 is the
    /// default. A production implementation would query the secure key store
    /// for the active version of [`REDACTION_HISTORY_NAMESPACE`].
    fn current_key_version(&self) -> i64 {
        1
    }
}

#[cfg(test)]
mod tests;
