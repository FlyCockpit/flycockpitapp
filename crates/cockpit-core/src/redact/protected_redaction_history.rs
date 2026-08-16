//! Protected redaction history: durable encrypted literal store for redacting
//! historical trusted-provider artifacts.
//!
//! This module implements the sole writer API
//! ([`ProtectedRedactionHistory::prepare_append`] +
//! [`append_and_attach_conn`], with [`ProtectedRedactionHistory::append_and_attach`]
//! as the one-transaction convenience form) and the bounded zeroizing local
//! rehydration frame [`RedactionRehydrationFrame`].
//!
//! ## Cryptography
//!
//! Literals are encrypted with **ChaCha20-Poly1305** (a real AEAD with a 16-byte
//! authentication tag): any tamper of the ciphertext, nonce, or the bound row
//! context fails closed on decrypt. The 32-byte key-store root key for a version
//! is split into two domain-separated subkeys via HMAC-SHA-256:
//! `encrypt-key` and `fingerprint-key`. Both subkeys live in [`Zeroizing`]
//! buffers.
//!
//! The plaintext is framed as `4-byte BE length ‖ literal ‖ zero padding` and
//! padded to the smallest bucket in `{256, 1024, 4096, 16388}` bytes before
//! encryption, so the stored ciphertext length (bucket + 16-byte tag ∈
//! `{272, 1040, 4112, 16404}`) reveals only a coarse bucket, never the literal
//! length. The AEAD associated data binds `session_id ‖ 0x00 ‖ source ‖ 0x00 ‖
//! key_version`, so a row whose session or source columns were tampered fails
//! the tag check.
//!
//! The stored `fingerprint` is a **keyed MAC** (`HMAC-SHA-256(fingerprint-key,
//! literal)`), not a plain unkeyed digest: it is not an offline guessing oracle.
//! It is used only for same-session deduplication and as a defense-in-depth
//! integrity check after the AEAD tag; it is **not** exported (see
//! `ProtectedRedactionHistoryRef`, which carries no fingerprint field).
//!
//! ## Design
//!
//! Every artifact-bearing sensitive ingress atomically commits its protected
//! history reference before its raw trusted artifact can become durable. The
//! literal is stored ONLY as encrypted ciphertext + nonce, keyed by an opaque
//! history ID and the local key-store key version. No plaintext, prefix, exact
//! length, ciphertext, nonce, or key version ever appears in ordinary query,
//! protocol, diagnostics, or export data.
//!
//! The closed source set ([`RedactionHistorySource`]) is exhaustive: no
//! caller may introduce a new source without a matching closed-writer
//! classification here. The pipeline is split: classification happens upstream
//! (`match_sensitive_literals`), and encryption happens in the async
//! `prepare_append` (subkey derivation, keyed fingerprint, padding, and AEAD)
//! *before* any transaction is opened — no DB access there. Only dedup, row
//! insertion, and artifact attachment run inside the one local SQLite
//! transaction; a crash at either ordering point commits neither the history
//! row nor the artifact reference.
//!
//! Rehydration is bounded and zeroized: literals live only inside a
//! [`RedactionRehydrationFrame`] (or a single [`RehydratedLiteral`]) that is
//! dropped (zeroized) at scope exit, never serialized into persisted ordinary
//! redaction JSON, and never read outside an Owner-sensitive or export-redaction
//! frame. Retirement overwrites ciphertext, nonce, and fingerprint with zeros in
//! the db layer, so a retired row can no longer be decrypted at all.

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use hmac::{Hmac, KeyInit as _, Mac};
use rusqlite::Connection;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::db::Db;
use crate::db::protected_redaction_history::{
    AppendHistoryResult, ProtectedRedactionHistoryAppend, ProtectedRedactionHistoryRow,
    append_history_conn, attach_artifact_ref_conn, get_history_conn,
    list_history_for_artifact_conn,
};

/// Re-export the closed source set so callers do not depend on the db crate
/// directly for these types.
pub use crate::db::protected_redaction_history::ProtectedRedactionSource as RedactionHistorySource;

/// Re-export the artifact kind for callers.
pub use crate::db::protected_redaction_history::ProtectedRedactionArtifactKind as RedactionArtifactKind;

type HmacSha256 = Hmac<Sha256>;

/// Maximum literal length accepted by the rehydration frame (16 KiB).
pub const MAX_LITERAL_LEN: usize = 16 * 1024;

/// Nonce length for AEAD encryption (96-bit ChaCha20-Poly1305 nonce).
pub const NONCE_LEN: usize = 12;

/// Length of the appended Poly1305 authentication tag.
pub const AEAD_TAG_LEN: usize = 16;

/// Key length for the local redaction-history root key (256-bit).
pub const REDACTION_KEY_LEN: usize = 32;

/// Domain-separation label for the ChaCha20-Poly1305 encryption subkey.
const KDF_ENCRYPT_LABEL: &[u8] = b"cockpit/redaction-history/v1/encrypt-key";

/// Domain-separation label for the keyed-fingerprint MAC subkey.
const KDF_FINGERPRINT_LABEL: &[u8] = b"cockpit/redaction-history/v1/fingerprint-key";

/// Padding buckets for the framed plaintext (`4-byte len ‖ literal ‖ zeros`).
/// `16388 = MAX_LITERAL_LEN + 4`, so the cap is representable. Stored ciphertext
/// length is one of these plus [`AEAD_TAG_LEN`]: `{272, 1040, 4112, 16404}`.
const PLAINTEXT_BUCKETS: [usize; 4] = [256, 1024, 4096, 16388];

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

    /// Create a new protected literal from an already-zeroizing secret. Unlike
    /// [`ProtectedLiteral::new`], no un-zeroized plaintext copy of the literal is
    /// ever materialized: the bytes are copied straight into a [`Zeroizing`]
    /// buffer, and on the oversize-reject path the caller's `Zeroizing<String>`
    /// is dropped (and scrubbed) intact. Fails if the literal exceeds
    /// [`MAX_LITERAL_LEN`].
    pub fn from_zeroizing(
        literal: Zeroizing<String>,
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
            literal: Zeroizing::new(literal.as_bytes().to_vec()),
            source,
            sealed_record_id,
            sealed_version,
        })
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

/// Local root key for protected redaction-history literals. Zeroized on drop.
/// In production this is resolved from the native secure key store; in tests it
/// is injected directly. Encryption and the keyed fingerprint use
/// domain-separated subkeys derived from this root, never the root directly.
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

/// Trait for resolving the local root key for a given key version and the
/// active version to write under.
///
/// The async `ensure_*` methods load key material from the secure-key actor and
/// warm an internal cache; the sync [`RedactionKeyResolver::resolve`] and
/// [`RedactionKeyResolver::active_version`] are **cache-only** so they can run
/// inside a synchronous SQLite callback without blocking a runtime worker.
/// Callers must `ensure_*` before entering a sync `Db` callback / transaction.
#[async_trait]
pub trait RedactionKeyResolver: Send + Sync {
    /// Ensure the active key version exists and is cached; return that version.
    /// First use creates version 1. Loads from the secure-key store.
    async fn ensure_active(&self) -> Result<i64>;

    /// Ensure a specific historical version is cached. Loads from the store.
    async fn ensure_version(&self, version: i64) -> Result<()>;

    /// Resolve the root key for `version` from the warm cache only. A miss
    /// fails closed; it never enqueues actor work or blocks.
    fn resolve(&self, version: i64) -> Result<RedactionHistoryKey>;

    /// The active key version to write under, from the warm cache only.
    fn active_version(&self) -> Result<i64>;
}

/// Test-only key resolver backed by a simple version-to-key map. Gated to
/// `cfg(test)` so the workspace clippy gate does not flag it as dead in a
/// production build and so no production path can depend on it.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct MapKeyResolver {
    keys: std::collections::HashMap<i64, [u8; REDACTION_KEY_LEN]>,
    active: Option<i64>,
}

#[cfg(test)]
impl std::fmt::Debug for MapKeyResolver {
    /// Redact the raw redaction-history root keys; show only their count and the
    /// active version so `{:?}`/panic diagnostics never print key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapKeyResolver")
            .field(
                "keys",
                &format_args!("[REDACTED; {} keys]", self.keys.len()),
            )
            .field("active", &self.active)
            .finish()
    }
}

#[cfg(test)]
impl MapKeyResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_version(mut self, version: i64, key: [u8; REDACTION_KEY_LEN]) -> Self {
        self.keys.insert(version, key);
        if self.active.is_none() {
            self.active = Some(version);
        }
        self
    }
}

#[cfg(test)]
#[async_trait]
impl RedactionKeyResolver for MapKeyResolver {
    async fn ensure_active(&self) -> Result<i64> {
        self.active_version()
    }

    async fn ensure_version(&self, version: i64) -> Result<()> {
        if self.keys.contains_key(&version) {
            Ok(())
        } else {
            bail!("no redaction key for version {version}")
        }
    }

    fn resolve(&self, version: i64) -> Result<RedactionHistoryKey> {
        let key = self
            .keys
            .get(&version)
            .copied()
            .with_context(|| format!("no redaction key for version {version}"))?;
        Ok(RedactionHistoryKey::new(key, version))
    }

    fn active_version(&self) -> Result<i64> {
        self.active
            .context("no active redaction key version registered")
    }
}

// ---- Cryptographic primitives ---------------------------------------------

/// Derive a 32-byte domain-separated subkey from the root key via HMAC-SHA-256.
fn derive_subkey(root: &[u8], label: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(root).expect("HMAC accepts any key length");
    mac.update(label);
    // `into_bytes` materializes the derived subkey in a plain `GenericArray`;
    // copy it into a `Zeroizing` buffer and scrub the intermediate so no
    // un-zeroized copy of the key survives this function.
    let mut out = mac.finalize().into_bytes();
    let mut sub = Zeroizing::new([0u8; 32]);
    sub.copy_from_slice(&out);
    out.as_mut_slice().zeroize();
    sub
}

/// Keyed fingerprint: `hex(HMAC-SHA-256(fingerprint-key, literal))` (64 hex
/// chars). Not an offline guessing oracle: it is keyed by a store-derived
/// subkey.
fn keyed_fingerprint(mac_key: &[u8], literal: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(literal);
    let out = mac.finalize().into_bytes();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

/// AEAD associated data binding the row's context so tampering a column fails
/// the tag check: `session_id ‖ 0x00 ‖ source ‖ 0x00 ‖ key_version(BE)`.
fn compute_aad(session_id: &str, source: RedactionHistorySource, key_version: i64) -> Vec<u8> {
    let source = source.as_str();
    let mut aad = Vec::with_capacity(session_id.len() + source.len() + 10);
    aad.extend_from_slice(session_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(source.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&key_version.to_be_bytes());
    aad
}

/// Smallest plaintext bucket that fits `frame_len`.
fn bucket_for(frame_len: usize) -> Result<usize> {
    PLAINTEXT_BUCKETS
        .iter()
        .copied()
        .find(|&b| frame_len <= b)
        .with_context(|| format!("protected literal frame length {frame_len} exceeds max bucket"))
}

/// Build the padded plaintext frame `4-byte BE len ‖ literal ‖ zero padding`
/// inside a zeroizing buffer.
fn build_frame(literal: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let len = literal.len();
    let frame_len = 4 + len;
    let bucket = bucket_for(frame_len)?;
    let mut frame = Zeroizing::new(vec![0u8; bucket]);
    frame[0..4].copy_from_slice(&(len as u32).to_be_bytes());
    frame[4..4 + len].copy_from_slice(literal);
    Ok(frame)
}

/// Encrypt a padded frame, returning ciphertext with the 16-byte tag appended.
fn encrypt_frame(enc_key: &[u8], nonce: &[u8], aad: &[u8], frame: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_LEN {
        bail!("nonce length must be {NONCE_LEN}");
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(enc_key));
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: frame, aad })
        .map_err(|_| anyhow!("AEAD encryption failed"))
}

/// Decrypt a stored ciphertext into a zeroizing padded-frame buffer, verifying
/// the AEAD tag over the bound associated data. In-place decrypt (no plain
/// intermediate `Vec` of plaintext).
fn decrypt_to_frame(
    enc_key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN {
        bail!("nonce length must be {NONCE_LEN}");
    }
    if ciphertext.len() < AEAD_TAG_LEN {
        bail!("protected redaction ciphertext too short");
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(enc_key));
    let (body, tag) = ciphertext.split_at(ciphertext.len() - AEAD_TAG_LEN);
    // Copy ciphertext body into a zeroizing buffer; decrypt overwrites it with
    // plaintext in place, so no un-zeroized plaintext copy is ever produced.
    let mut frame = Zeroizing::new(body.to_vec());
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(nonce),
            aad,
            frame.as_mut_slice(),
            Tag::from_slice(tag),
        )
        .map_err(|_| {
            anyhow!("AEAD authentication failed (tampered ciphertext, nonce, or bound context)")
        })?;
    Ok(frame)
}

/// Validate and strip a decrypted padded frame back to the literal bytes,
/// failing closed on a bad length prefix or non-zero padding.
fn strip_frame(frame: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if frame.len() < 4 {
        bail!("decrypted protected frame too short");
    }
    let len = u32::from_be_bytes(frame[0..4].try_into().unwrap()) as usize;
    if len > MAX_LITERAL_LEN {
        bail!("decrypted protected literal length {len} exceeds {MAX_LITERAL_LEN}");
    }
    if 4 + len > frame.len() {
        bail!("decrypted protected literal length exceeds frame");
    }
    if frame[4 + len..].iter().any(|&b| b != 0) {
        bail!("decrypted protected frame padding is not all zero (integrity failure)");
    }
    Ok(Zeroizing::new(frame[4..4 + len].to_vec()))
}

/// Generate a random AEAD nonce.
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
    /// The row's keyed fingerprint (keyed MAC hex). Keyed, so it is not an
    /// offline guessing oracle, but it is session-scoped sensitive metadata:
    /// per decision 6 it is excluded from every export / protocol / diagnostics
    /// projection and is used only for same-session dedup and local
    /// (Owner-sensitive) leak-report correlation.
    fingerprint: String,
    source: RedactionHistorySource,
}

impl RehydratedLiteral {
    /// The literal as a string (local frame only). Fails if the bytes are
    /// not valid UTF-8. No intermediate un-zeroized copy: validates in place
    /// then allocates the owned string directly into a zeroizing wrapper.
    pub fn as_str(&self) -> Result<Zeroizing<String>> {
        let s =
            std::str::from_utf8(&self.literal).context("rehydrated literal is not valid UTF-8")?;
        Ok(Zeroizing::new(s.to_owned()))
    }

    /// The row's keyed fingerprint (keyed MAC hex). Keyed, not an offline
    /// guessing oracle; kept off every export / protocol / diagnostics
    /// projection (decision 6) and used only for same-session dedup and local
    /// (Owner-sensitive) leak-report correlation.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

impl std::fmt::Debug for RehydratedLiteral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The keyed MAC (`fingerprint`) is session-scoped sensitive metadata kept
        // off every diagnostics projection (decision 6/14); mirror
        // `ProtectedLiteral`'s Debug and never print it (G4d).
        f.debug_struct("RehydratedLiteral")
            .field(
                "fingerprint",
                &format_args!("[REDACTED; {}]", self.fingerprint.len()),
            )
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

/// The artifact reference for the sole writer API.
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

/// A protected append prepared off the DB thread: key material has been loaded,
/// subkeys derived, the literal MAC'd, padded, and AEAD-encrypted, and the
/// plaintext consumed and zeroized. Carries only ciphertext / nonce /
/// fingerprint / key version / source / sealed identity — no plaintext.
///
/// Hand this to [`append_and_attach_conn`] inside a caller's own
/// `Db::transaction` / `db.write` callback to compose the journal write with the
/// caller's artifact writes in one transaction.
#[derive(Clone)]
pub struct PreparedProtectedAppend {
    session_id: String,
    source: RedactionHistorySource,
    sealed_record_id: Option<String>,
    sealed_version: Option<i64>,
    fingerprint: String,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    key_version: i64,
}

impl std::fmt::Debug for PreparedProtectedAppend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The keyed MAC (`fingerprint`) is session-scoped sensitive metadata kept
        // off every diagnostics projection (decision 6/14); the derived Debug
        // emitted it verbatim, so redact it here and reduce the ciphertext/nonce
        // to lengths (G4d).
        f.debug_struct("PreparedProtectedAppend")
            .field("session_id", &self.session_id)
            .field("source", &self.source)
            .field("sealed_record_id", &self.sealed_record_id)
            .field("sealed_version", &self.sealed_version)
            .field(
                "fingerprint",
                &format_args!("[REDACTED; {}]", self.fingerprint.len()),
            )
            .field(
                "ciphertext",
                &format_args!("[{} bytes]", self.ciphertext.len()),
            )
            .field("nonce", &format_args!("[{} bytes]", self.nonce.len()))
            .field("key_version", &self.key_version)
            .finish()
    }
}

impl PreparedProtectedAppend {
    /// The keyed fingerprint (keyed MAC hex) for this prepared literal. Keyed,
    /// so not an offline guessing oracle, but session-scoped sensitive metadata:
    /// kept off every export / protocol / diagnostics projection (decision 6). Used
    /// only by callers that dedupe or locally correlate by fingerprint (the
    /// leak-report keyed dedup fingerprint).
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    fn to_append(&self) -> ProtectedRedactionHistoryAppend {
        ProtectedRedactionHistoryAppend {
            session_id: self.session_id.clone(),
            sealed_record_id: self.sealed_record_id.clone(),
            sealed_version: self.sealed_version,
            source: self.source,
            fingerprint: self.fingerprint.clone(),
            ciphertext: self.ciphertext.clone(),
            nonce: self.nonce.clone(),
            key_version: self.key_version,
        }
    }
}

/// Connection-scoped sole writer: append (or deduplicate) the prepared protected
/// history row and attach every artifact reference, all on `conn` so the caller
/// composes it inside one [`Db::transaction`] alongside its own artifact writes.
/// A crash at any ordering point commits nothing.
pub fn append_and_attach_conn(
    conn: &Connection,
    prepared: &PreparedProtectedAppend,
    artifacts: &[ArtifactRef],
) -> Result<String> {
    let append_input = prepared.to_append();
    let result = append_history_conn(conn, &append_input)?;
    let history_id = match result {
        AppendHistoryResult::Created { history_id } => history_id,
        AppendHistoryResult::Existing { history_id } => history_id,
    };
    for artifact in artifacts {
        attach_artifact_ref_conn(conn, artifact.kind, &artifact.id, &history_id)?;
    }
    Ok(history_id)
}

/// The sole writer API for protected redaction history.
///
/// The two composition forms are:
/// * [`ProtectedRedactionHistory::prepare_append`] (async; loads key material,
///   derives subkeys, MACs, pads, and AEAD-encrypts — no DB access) followed by
///   [`append_and_attach_conn`] inside the caller's own transaction; and
/// * [`ProtectedRedactionHistory::append_and_attach`] (the convenience form that
///   wraps `prepare_append` + one transaction).
///
/// A crash at either ordering point commits neither the history row nor the
/// artifact references.
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

    /// Prepare a protected append off the DB thread: resolve the active key
    /// version, derive subkeys, compute the keyed fingerprint, pad, and
    /// AEAD-encrypt. The `literal` is consumed and zeroized here. The returned
    /// [`PreparedProtectedAppend`] carries no plaintext and is ready for the
    /// connection-scoped writer.
    pub async fn prepare_append(
        &self,
        session_id: &str,
        literal: ProtectedLiteral,
    ) -> Result<PreparedProtectedAppend> {
        let key_version = self.key_resolver.ensure_active().await?;
        let key = self.key_resolver.resolve(key_version)?;
        let enc_key = derive_subkey(key.as_bytes(), KDF_ENCRYPT_LABEL);
        let mac_key = derive_subkey(key.as_bytes(), KDF_FINGERPRINT_LABEL);

        let source = literal.source();
        let sealed_record_id = literal.sealed_record_id().map(str::to_owned);
        let sealed_version = literal.sealed_version();

        let fingerprint = keyed_fingerprint(&*mac_key, literal.as_bytes());
        let aad = compute_aad(session_id, source, key_version);
        let frame = build_frame(literal.as_bytes())?;
        let nonce = generate_nonce();
        let ciphertext = encrypt_frame(&*enc_key, &nonce, &aad, &frame)?;
        // `literal` and `frame` are zeroized on drop at end of scope.

        Ok(PreparedProtectedAppend {
            session_id: session_id.to_owned(),
            source,
            sealed_record_id,
            sealed_version,
            fingerprint,
            ciphertext,
            nonce,
            key_version,
        })
    }

    /// The convenience sole writer. Prepares the append, then runs
    /// [`append_and_attach_conn`] in one [`Db::transaction`]. If any step
    /// fails, neither the history row nor the artifact references are committed.
    ///
    /// `literal` is consumed and zeroized. `artifacts` is the list of durable
    /// artifacts that reference this literal.
    pub async fn append_and_attach(
        &self,
        session_id: &str,
        literal: ProtectedLiteral,
        artifacts: Vec<ArtifactRef>,
    ) -> Result<String> {
        let prepared = self.prepare_append(session_id, literal).await?;
        self.db
            .transaction(move |conn| append_and_attach_conn(conn, &prepared, &artifacts))
            .await
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
            // Warm the cache for this row's version before the sync decrypt.
            self.key_resolver.ensure_version(row.key_version).await?;
            let literal = self.rehydrate_row(&row)?;
            frame.push(literal);
        }
        Ok(frame)
    }

    /// Rehydrate one history row by its opaque history id. Used by the
    /// leaks-page reveal path to recover the literal on the protected local
    /// channel. Fails closed on any key-store failure, integrity mismatch,
    /// missing row, or retired row. The returned literal lives only inside
    /// the zeroizing [`RehydratedLiteral`] frame.
    pub async fn rehydrate_by_history_id(&self, history_id: &str) -> Result<RehydratedLiteral> {
        let history_id = history_id.to_owned();
        let row = self
            .db
            .read(move |conn| get_history_conn(conn, &history_id))
            .await?;
        let row =
            row.ok_or_else(|| anyhow::anyhow!("protected redaction history row not found"))?;
        self.key_resolver.ensure_version(row.key_version).await?;
        self.rehydrate_row(&row)
    }

    /// Rehydrate one history row into a literal. Fails closed on any error. The
    /// row's key version must already be warm in the resolver cache.
    fn rehydrate_row(&self, row: &ProtectedRedactionHistoryRow) -> Result<RehydratedLiteral> {
        if row.retired_at_ms.is_some() {
            bail!("cannot rehydrate retired protected redaction history row");
        }
        let key = self.key_resolver.resolve(row.key_version)?;
        let enc_key = derive_subkey(key.as_bytes(), KDF_ENCRYPT_LABEL);
        let mac_key = derive_subkey(key.as_bytes(), KDF_FINGERPRINT_LABEL);
        let aad = compute_aad(&row.session_id, row.source, row.key_version);
        let frame = decrypt_to_frame(&*enc_key, &row.nonce, &aad, &row.ciphertext)?;
        let plaintext = strip_frame(&frame)?;

        // Defense-in-depth: the keyed MAC must match after the AEAD tag.
        let computed = keyed_fingerprint(&*mac_key, &plaintext);
        if computed != row.fingerprint {
            bail!("protected redaction history fingerprint mismatch (integrity failure)");
        }

        Ok(RehydratedLiteral {
            literal: plaintext,
            fingerprint: row.fingerprint.clone(),
            source: row.source,
        })
    }
}

#[cfg(test)]
mod tests;
