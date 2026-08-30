//! Owner-only sealed-value administration through the protected sensitive
//! channel.
//!
//! This module implements the hardened library core of the Owner channel:
//!
//! * [`BeginSensitiveOwnerOperation::begin`] — mints a single-use,
//!   60-second capability bound to one exact operation, owner principal,
//!   daemon-loaded scope, and exact version. For non-create dispositions it
//!   loads the record row under the applying [`OwnerAuthority`], rejects a
//!   missing/deleted row or an ownership mismatch, and binds the row's live
//!   [`SealedScopeRef`] and [`VersionBinding::Exact`] into the capability; the
//!   client supplies only a record id, never scope or version.
//! * [`SensitiveOwnerFrame`] — carries the capability plus an optional literal
//!   into a contained or revealed outcome, zeroizing on every path.
//!
//! ## Enforced properties (each backed by a test in `tests.rs`)
//!
//! * **16 KiB bounded frame.** A literal larger than
//!   [`MAX_SENSITIVE_FRAME_BYTES`] is rejected before any store touch.
//! * **Zeroization.** Every literal is held in a [`Zeroizing`] frame and moved
//!   into the store without an intermediate plaintext copy; a revealed literal
//!   is returned inside [`Zeroizing`].
//! * **60-second capability expiry** via caller-threaded `now_ms`; there is no
//!   caller-overridable `now` and no `Instant`.
//! * **Atomic one use.** A capability is consumed by a single
//!   compare-and-swap *before* the operation executes; exactly one of N
//!   concurrent applies proceeds and the rest reject as replay. A consumed
//!   capability that then fails the store step is still spent (fail closed).
//! * **Cancel.** [`OneUseCapability::cancel`] consumes the capability through
//!   the same compare-and-swap without applying; a later apply rejects.
//! * **Owner-principal match.** A capability records the minting authority's
//!   principal and an apply under a different authority is rejected before any
//!   literal is touched.
//! * **Live-row scope + version revalidation** for every non-create apply: a
//!   capability whose bound scope or version no longer matches the live record
//!   (e.g. a rotation raced a recover) is rejected before parse. There is no
//!   version-0 escape: the binding is a closed [`VersionBinding`] enum.
//! * **First-class recover.** Recover is a distinct
//!   [`SensitiveOwnerDisposition`] variant, never encoded as `Rotate`. Write
//!   frames map to Create/Replace/Rotate; recover frames map to Recover, and a
//!   frame/disposition mismatch rejects before parse.
//!
//! ## Recovery audit (audit-before-reveal)
//!
//! A recover apply commits a [`sealed_recovery_audit`](cockpit_db) row —
//! carrying only safe metadata (record id, scope, version, owner principal,
//! minting session, closed `revealed` outcome) and **never** the literal — and
//! that write must succeed durably *before* the resolved plaintext is returned.
//! An audit-commit failure propagates as an error, the ephemeral literal is
//! dropped (zeroized), and no `Revealed` outcome is constructed; the capability
//! is already spent, so the owner re-begins (fail closed).
//!
//! The daemon capability table (which enforces the minting-session match before
//! building a recover frame and supplies its `minting_session`), proto Request /
//! Response wiring, and the `/sealed` TUI live outside this module; this module
//! supplies the protocol primitives, the Owner-facing operations, and the
//! audit-before-reveal ordering.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use cockpit_db::db::sealed_actions::{SealedRecoveryAuditEntry, SealedRecoveryOutcome};
use cockpit_db::db::sealed_scope::{SealedScopeKind, SealedValueRecordRow};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::action::OwnerAuthority;
use super::compartment::{SealedCompartmentKey, SealedLiteral};
use super::identity::{
    SealedDescription, SealedKnowledgeBaseId, SealedName, SealedProjectKey, SealedRecordId,
    SealedScopeRef,
};
use super::store::{CreateSealedValue, SealedValueDirectory, SealedValueSummary};

/// Maximum literal payload carried in one sensitive frame, in bytes.
pub const MAX_SENSITIVE_FRAME_BYTES: usize = 16 * 1024;

/// A sensitive-owner capability is valid for this many milliseconds after
/// minting. Expiry is evaluated against caller-threaded `now_ms`, never against
/// an internal clock.
pub const CAPABILITY_TTL_MS: i64 = 60_000;

/// Re-export the leak-report ingress disposition. This is the `OwnerWrite`
/// ingress family's closed set (`Create | Replace | Rotate`) and is *not* the
/// operation disposition used by this channel — see [`SensitiveOwnerDisposition`],
/// which adds a first-class `Recover` variant.
pub use crate::leak_report::OwnerWriteDisposition;

/// The closed disposition a sensitive-owner capability permits.
///
/// Recover is a first-class variant, never encoded as `Rotate`. The mapping to
/// frame kind is closed and mechanical (see [`SensitiveOwnerDisposition::frame_kind`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveOwnerDisposition {
    Create,
    Replace,
    Rotate,
    Recover,
}

impl SensitiveOwnerDisposition {
    /// The frame kind this disposition requires. Write ↔ Create/Replace/Rotate;
    /// Recover ↔ Recover.
    pub fn frame_kind(self) -> SensitiveFrameKind {
        match self {
            Self::Create | Self::Replace | Self::Rotate => SensitiveFrameKind::Write,
            Self::Recover => SensitiveFrameKind::Recover,
        }
    }
}

/// The version a capability is bound to. A closed enum, not a `u32` sentinel:
/// there is no representable "skip the version check" state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionBinding {
    /// Create binds to no pre-existing version.
    Create,
    /// Every non-create capability binds to exactly one live version (`>= 1`),
    /// re-checked against the record row at apply.
    Exact(u32),
}

/// The thin, per-disposition client input to [`BeginSensitiveOwnerOperation::begin`].
///
/// It carries **no** principal (identity comes solely from the applying
/// [`OwnerAuthority`]), **no** scope for replace/rotate/recover (the daemon
/// loads and binds the row's scope), and **no** version for any disposition
/// (create binds `Create`; non-create binds the row's live version).
#[derive(Debug, Clone)]
pub enum BeginSensitiveInput {
    /// Create carries the ambient scope, name, and safe description.
    Create {
        scope: SealedScopeRef,
        name: SealedName,
        description: SealedDescription,
    },
    /// Replace addresses an existing record by id only.
    Replace { record_id: SealedRecordId },
    /// Rotate addresses an existing record by id only.
    Rotate { record_id: SealedRecordId },
    /// Recover addresses an existing record by id only.
    Recover { record_id: SealedRecordId },
}

/// The closed, daemon-bound operation a capability permits.
///
/// This is the capability-table payload built by [`BeginSensitiveOwnerOperation::begin`]
/// *after* the daemon loads and binds the record. Its scope and version are
/// never populated from client input on the wire; the daemon binds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveOwnerOperation {
    pub disposition: SensitiveOwnerDisposition,
    pub record_id: Option<SealedRecordId>,
    pub scope: SealedScopeRef,
    pub version: VersionBinding,
    /// Required for create; the canonical name of the new value.
    pub name: Option<SealedName>,
    /// Required for create; the safe description.
    pub description: Option<SealedDescription>,
}

impl SensitiveOwnerOperation {
    /// Build a create operation bound to an ambient scope and `VersionBinding::Create`.
    pub fn create(scope: SealedScopeRef, name: SealedName, description: SealedDescription) -> Self {
        Self {
            disposition: SensitiveOwnerDisposition::Create,
            record_id: None,
            scope,
            version: VersionBinding::Create,
            name: Some(name),
            description: Some(description),
        }
    }

    /// Build a replace operation bound to an exact version.
    pub fn replace(record_id: SealedRecordId, scope: SealedScopeRef, version: u32) -> Self {
        Self::bound(
            SensitiveOwnerDisposition::Replace,
            record_id,
            scope,
            version,
        )
    }

    /// Build a rotate operation bound to an exact version.
    pub fn rotate(record_id: SealedRecordId, scope: SealedScopeRef, version: u32) -> Self {
        Self::bound(SensitiveOwnerDisposition::Rotate, record_id, scope, version)
    }

    /// Build a recover operation bound to an exact version. Recover is
    /// first-class here — it is never encoded as `Rotate`.
    pub fn recover(record_id: SealedRecordId, scope: SealedScopeRef, version: u32) -> Self {
        Self::bound(
            SensitiveOwnerDisposition::Recover,
            record_id,
            scope,
            version,
        )
    }

    fn bound(
        disposition: SensitiveOwnerDisposition,
        record_id: SealedRecordId,
        scope: SealedScopeRef,
        version: u32,
    ) -> Self {
        Self {
            disposition,
            record_id: Some(record_id),
            scope,
            version: VersionBinding::Exact(version),
            name: None,
            description: None,
        }
    }
}

/// A single-use, time-bounded capability minted by
/// [`BeginSensitiveOwnerOperation::begin`].
///
/// The capability is bound to one exact operation, one owner principal, and one
/// minting instant (`minted_at_ms`). It is consumed exactly once — by
/// [`SensitiveOwnerFrame::apply`] or [`OneUseCapability::cancel`] — through an
/// atomic compare-and-swap; a replayed, cancelled, expired, or mismatched
/// capability fails before secret parse.
#[derive(Debug, Clone)]
pub struct OneUseCapability {
    capability_id: Uuid,
    operation: SensitiveOwnerOperation,
    owner_principal: &'static str,
    minted_at_ms: i64,
    consumed: Arc<AtomicBool>,
}

impl OneUseCapability {
    /// The opaque capability id. Safe to log; it carries no literal.
    pub fn capability_id(&self) -> Uuid {
        self.capability_id
    }

    /// The operation this capability permits.
    pub fn operation(&self) -> &SensitiveOwnerOperation {
        &self.operation
    }

    /// Whether this capability has been consumed (applied or cancelled).
    pub fn is_consumed(&self) -> bool {
        self.consumed.load(Ordering::SeqCst)
    }

    /// Whether this capability has expired, judged against caller-threaded
    /// milliseconds.
    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms - self.minted_at_ms > CAPABILITY_TTL_MS
    }

    /// The owner principal this capability is bound to.
    pub fn owner_principal(&self) -> &str {
        self.owner_principal
    }

    /// The wall-clock milliseconds this capability expires at.
    pub fn expires_at_ms(&self) -> i64 {
        self.minted_at_ms + CAPABILITY_TTL_MS
    }

    /// Consume this capability without applying it (cancel). Returns `true` if
    /// this call consumed it, `false` if it was already consumed (replay or
    /// double-cancel). Uses the same compare-and-swap as apply.
    pub fn cancel(&self) -> bool {
        self.try_consume()
    }

    /// Atomic one-use consume. Exactly one caller across all concurrent
    /// apply/cancel attempts observes `true`.
    fn try_consume(&self) -> bool {
        self.consumed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
}

#[cfg(test)]
impl OneUseCapability {
    /// Test-only: craft a capability directly with a bound operation, principal,
    /// and mint time, bypassing the mint-time load/bind. This is how wrong-scope
    /// and wrong-version unit tests build a capability whose binding mismatches
    /// the live record row without spoofing scope/version on a begin RPC.
    pub(crate) fn craft(
        operation: SensitiveOwnerOperation,
        owner_principal: &'static str,
        minted_at_ms: i64,
    ) -> Self {
        Self {
            capability_id: Uuid::new_v4(),
            operation,
            owner_principal,
            minted_at_ms,
            consumed: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl PartialEq for OneUseCapability {
    fn eq(&self, other: &Self) -> bool {
        self.capability_id == other.capability_id
    }
}

impl Eq for OneUseCapability {}

/// The result of [`BeginSensitiveOwnerOperation::begin`]: the minted capability
/// and its expiry. Carries **no** literal.
#[derive(Debug, Clone)]
pub struct BeginResult {
    pub capability: OneUseCapability,
    pub expires_at_ms: i64,
}

/// The sensitive-channel entry point. Mints single-use capabilities for Owner
/// write/recover operations, loading and binding the record row at mint time
/// for non-create dispositions.
pub struct BeginSensitiveOwnerOperation;

impl BeginSensitiveOwnerOperation {
    /// Mint a single-use capability for one operation.
    ///
    /// Identity comes solely from `owner`; the capability's `owner_principal` is
    /// stamped from it. For replace/rotate/recover the record is loaded under
    /// `owner`, an ownership mismatch or missing/deleted row is rejected with a
    /// content-free error (no capability is minted), and the row's live scope
    /// and version are bound into the capability. For create the ambient scope
    /// is bound with `VersionBinding::Create`, an active name+scope collision is
    /// rejected, and an incomplete scope is rejected.
    pub async fn begin(
        owner: OwnerAuthority,
        directory: &SealedValueDirectory,
        input: BeginSensitiveInput,
        now_ms: i64,
    ) -> Result<BeginResult> {
        let operation = match input {
            BeginSensitiveInput::Create {
                scope,
                name,
                description,
            } => {
                validate_ambient_scope(&scope)?;
                // Mint-time collision check: reject if an active record already
                // exists for this name+scope (store create enforces uniqueness
                // authoritatively; this is the immediate, safe pre-echo error).
                let existing = directory.inventory(owner, &scope).await?;
                if existing.iter().any(|s| s.name == name) {
                    bail!("a sealed value with that name already exists in this scope");
                }
                SensitiveOwnerOperation::create(scope, name, description)
            }
            BeginSensitiveInput::Replace { record_id } => {
                load_and_bind(
                    owner,
                    directory,
                    SensitiveOwnerDisposition::Replace,
                    record_id,
                )
                .await?
            }
            BeginSensitiveInput::Rotate { record_id } => {
                load_and_bind(
                    owner,
                    directory,
                    SensitiveOwnerDisposition::Rotate,
                    record_id,
                )
                .await?
            }
            BeginSensitiveInput::Recover { record_id } => {
                load_and_bind(
                    owner,
                    directory,
                    SensitiveOwnerDisposition::Recover,
                    record_id,
                )
                .await?
            }
        };

        let capability = OneUseCapability {
            capability_id: Uuid::new_v4(),
            operation,
            owner_principal: owner.principal(),
            minted_at_ms: now_ms,
            consumed: Arc::new(AtomicBool::new(false)),
        };
        let expires_at_ms = capability.expires_at_ms();
        Ok(BeginResult {
            capability,
            expires_at_ms,
        })
    }
}

/// Load a record row for a non-create disposition and bind its live scope and
/// version into a capability operation. Rejects a missing/deleted row and an
/// ownership mismatch (row principal != authority principal) with content-free
/// errors, minting no capability.
async fn load_and_bind(
    owner: OwnerAuthority,
    directory: &SealedValueDirectory,
    disposition: SensitiveOwnerDisposition,
    record_id: SealedRecordId,
) -> Result<SensitiveOwnerOperation> {
    let row = directory
        .db()
        .sealed_value_record(record_id.to_string())
        .await?
        .filter(|row| row.deleted_at_ms.is_none())
        .context("sealed value record does not exist")?;
    if row.owner_principal != owner.principal() {
        // Fail closed: name only the safe fact, never scope/version/literal.
        bail!("sealed value record is not owned by the requesting owner");
    }
    let scope = scope_ref_from_row(&row)?;
    let active = u32::try_from(row.active_version).unwrap_or(0);
    if active < 1 {
        bail!("sealed value record has no active version to bind");
    }
    Ok(SensitiveOwnerOperation {
        disposition,
        record_id: Some(record_id),
        scope,
        version: VersionBinding::Exact(active),
        name: None,
        description: None,
    })
}

/// Reconstruct the typed [`SealedScopeRef`] from a persisted record row.
fn scope_ref_from_row(row: &SealedValueRecordRow) -> Result<SealedScopeRef> {
    Ok(match row.scope {
        SealedScopeKind::Session => SealedScopeRef::Session(
            Uuid::parse_str(&row.scope_key).context("record scope key is not a session id")?,
        ),
        SealedScopeKind::Project => {
            SealedScopeRef::Project(SealedProjectKey::from_canonical(row.scope_key.clone()))
        }
        SealedScopeKind::Global => SealedScopeRef::Global,
        SealedScopeKind::KnowledgeBase => SealedScopeRef::KnowledgeBase(
            SealedKnowledgeBaseId::parse(&row.scope_key)
                .context("record scope key is not a knowledge-base id")?,
        ),
    })
}

/// Reject an incomplete ambient scope on a create begin.
fn validate_ambient_scope(scope: &SealedScopeRef) -> Result<()> {
    match scope {
        SealedScopeRef::Session(_) | SealedScopeRef::Global => Ok(()),
        SealedScopeRef::Project(key) => {
            if key.as_str().is_empty() {
                bail!("project-scope create requires a non-empty project key");
            }
            Ok(())
        }
        SealedScopeRef::KnowledgeBase(_) => {
            bail!("knowledge-base sealed values are created through KnowledgeBaseSealedStore")
        }
    }
}

/// The kind of frame: write (carries a literal) or recover (reveals one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveFrameKind {
    Write,
    Recover,
}

/// The outcome of a sensitive frame: either the literal was contained (write
/// succeeded, no literal returned) or revealed (recover succeeded, literal
/// available in an ephemeral zeroizing frame).
pub enum SensitiveFrameOutcome {
    /// The write/replace/rotate succeeded. No literal is returned. Carries the
    /// updated safe summary.
    Contained { summary: SealedValueSummary },
    /// The recover succeeded. The literal is available in an ephemeral
    /// zeroizing frame that is zeroized on drop. Never terminal output.
    Revealed { literal: Zeroizing<String> },
}

impl std::fmt::Debug for SensitiveFrameOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Contained { summary } => f
                .debug_struct("Contained")
                .field("summary", summary)
                .finish(),
            // The revealed literal is ephemeral plaintext; never print it.
            Self::Revealed { literal } => f
                .debug_struct("Revealed")
                .field("literal", &format_args!("[REDACTED; {}]", literal.len()))
                .finish(),
        }
    }
}

/// The sensitive frame: carries a capability plus an optional literal into a
/// contained or revealed outcome.
pub struct SensitiveOwnerFrame<'a> {
    capability: &'a OneUseCapability,
    literal: Option<Zeroizing<String>>,
    kind: SensitiveFrameKind,
    /// The minting session this recover attempt is bound to. `Some` only for a
    /// recover frame: it is the connection identity that minted the capability,
    /// recorded verbatim into the [`sealed_recovery_audit`](cockpit_db) row that
    /// commits *before* the plaintext is revealed. A write frame carries `None`;
    /// writes are not audited through this ledger.
    minting_session: Option<String>,
}

impl<'a> SensitiveOwnerFrame<'a> {
    /// Create a frame for a write/replace/rotate. The literal is required and is
    /// consumed into a zeroizing frame.
    pub fn for_write(capability: &'a OneUseCapability, literal: Zeroizing<String>) -> Self {
        Self {
            capability,
            literal: Some(literal),
            kind: SensitiveFrameKind::Write,
            minting_session: None,
        }
    }

    /// Create a frame for a recover. No literal is supplied; the outcome reveals
    /// one.
    ///
    /// `minting_session` is the connection identity the capability was minted
    /// in. It is not re-checked here (the daemon capability table enforces the
    /// minting-session match before building this frame); it is recorded into
    /// the recovery-audit row that commits before the literal is revealed.
    pub fn for_recover(
        capability: &'a OneUseCapability,
        minting_session: impl Into<String>,
    ) -> Self {
        Self {
            capability,
            literal: None,
            kind: SensitiveFrameKind::Recover,
            minting_session: Some(minting_session.into()),
        }
    }

    /// The kind of this frame.
    pub fn kind(&self) -> SensitiveFrameKind {
        self.kind
    }

    /// Apply this frame against a [`SealedValueDirectory`].
    ///
    /// Order (fail closed):
    /// 1. Pre-consume validation that does not spend the capability: expiry,
    ///    owner-principal match, frame/disposition mapping, and the 16 KiB bound.
    /// 2. Atomic compare-and-swap consume — from here the capability is spent
    ///    regardless of the operation's outcome.
    /// 3. Execute: non-create applies revalidate the live row's scope + version
    ///    before any literal parse or store touch, then perform the operation.
    ///
    /// The literal is moved into the store (or revealed) without an
    /// intermediate plaintext copy, and every error names only safe fields.
    pub async fn apply(
        self,
        owner: OwnerAuthority,
        directory: &SealedValueDirectory,
        now_ms: i64,
    ) -> Result<SensitiveFrameOutcome> {
        // 1. Cheap, deterministic validation that must NOT spend the capability
        //    (a wrong-owner or expired apply leaves the legitimate capability
        //    usable).
        self.validate_before_consume(owner, now_ms)?;

        // 2. Atomic one-use: consume before executing. Exactly one of N
        //    concurrent applies wins; the rest reject as replay. A cancelled
        //    capability also fails here.
        if !self.capability.try_consume() {
            bail!("sensitive owner capability already used (replay rejected)");
        }

        // 3. From here the capability is spent even if the store step fails.
        self.execute(owner, directory, now_ms).await
    }

    /// Validation performed before the capability is consumed. A failure here
    /// does not spend the capability.
    fn validate_before_consume(&self, owner: OwnerAuthority, now_ms: i64) -> Result<()> {
        if self.capability.is_expired(now_ms) {
            bail!("sensitive owner capability expired");
        }
        if self.capability.owner_principal != owner.principal() {
            // Owner-principal match, always. Names no literal.
            bail!("sensitive owner capability principal mismatch");
        }
        // Frame kind must match the bound disposition.
        if self.capability.operation.disposition.frame_kind() != self.kind {
            bail!("sensitive owner frame kind does not match the bound operation disposition");
        }
        // A write frame must carry a literal; a recover frame must not.
        match (self.kind, self.literal.is_some()) {
            (SensitiveFrameKind::Write, true) => {}
            (SensitiveFrameKind::Write, false) => bail!("write frame requires a literal"),
            (SensitiveFrameKind::Recover, false) => {}
            (SensitiveFrameKind::Recover, true) => {
                bail!("recover frame must not carry a literal")
            }
        }
        // Bound the literal before any store touch.
        if let Some(literal) = &self.literal
            && literal.len() > MAX_SENSITIVE_FRAME_BYTES
        {
            bail!("sensitive frame literal exceeds {MAX_SENSITIVE_FRAME_BYTES} bytes");
        }
        Ok(())
    }

    /// Perform the bound operation. Runs only after the capability is consumed.
    async fn execute(
        self,
        owner: OwnerAuthority,
        directory: &SealedValueDirectory,
        now_ms: i64,
    ) -> Result<SensitiveFrameOutcome> {
        let op = self.capability.operation.clone();
        match self.kind {
            SensitiveFrameKind::Write => {
                let literal = self.literal.context("write frame requires a literal")?;
                let sealed_literal = SealedLiteral::from_zeroizing(literal);
                let summary = match op.disposition {
                    SensitiveOwnerDisposition::Create => {
                        let name = op.name.context("create requires a name")?;
                        let description =
                            op.description.context("create requires a description")?;
                        let request = CreateSealedValue {
                            scope: op.scope,
                            name,
                            description,
                            owner_principal: self.capability.owner_principal.to_string(),
                        };
                        directory
                            .create(owner, request, sealed_literal, now_ms)
                            .await?
                    }
                    SensitiveOwnerDisposition::Replace | SensitiveOwnerDisposition::Rotate => {
                        let record_id = op
                            .record_id
                            .context("replace/rotate requires a record id")?;
                        // Scope + owner are immutable per record, so check them
                        // up front. The version fence is applied ATOMICALLY
                        // inside `rotate_at_version` (fused with the mutation),
                        // not as a separate revalidate-then-write.
                        revalidate_scope_and_owner(directory, owner, &record_id, &op.scope).await?;
                        let expected = exact_version(op.version)?;
                        directory
                            .rotate_at_version(owner, record_id, sealed_literal, now_ms, expected)
                            .await?
                    }
                    SensitiveOwnerDisposition::Recover => {
                        bail!("recover disposition cannot be applied as a write frame")
                    }
                };
                Ok(SensitiveFrameOutcome::Contained { summary })
            }
            SensitiveFrameKind::Recover => {
                let record_id = op.record_id.context("recover requires a record id")?;
                let expected = exact_version(op.version)?;
                // Scope + owner + the version-fenced literal read all happen
                // inside `resolve_literal_for_recover`: the version is fused with
                // the authoritative literal read, so a rotation racing the
                // recovery can never reveal a newer value.
                let literal =
                    resolve_literal_for_recover(directory, owner, &record_id, &op.scope, expected)
                        .await?;
                // Audit BEFORE reveal (publish-before-destroy). The literal is
                // resolved but not yet returned; the `revealed` audit row must
                // commit durably before it leaves this function. A failed audit
                // write propagates here, the `Zeroizing` literal is dropped
                // (zeroized), and no `Revealed` outcome is ever constructed — the
                // capability is already spent, which is the fail-closed posture
                // (the owner re-begins). The audit row carries only safe metadata
                // and the closed `revealed` outcome; never the literal.
                let minting_session = self.minting_session.clone().context(
                    "recover frame requires a minting session to write the recovery-audit row",
                )?;
                let audit = SealedRecoveryAuditEntry {
                    audit_id: Uuid::new_v4().to_string(),
                    record_id: record_id.to_string(),
                    scope: op.scope.kind().as_str().to_string(),
                    scope_key: op.scope.scope_key(),
                    version: i64::from(expected),
                    owner_principal: self.capability.owner_principal.to_string(),
                    minting_session,
                    outcome: SealedRecoveryOutcome::Revealed,
                    created_at_ms: now_ms,
                };
                directory
                    .db()
                    .insert_sealed_recovery_audit(audit)
                    .await
                    .context("recovery audit must commit before the literal is revealed")?;
                Ok(SensitiveFrameOutcome::Revealed { literal })
            }
        }
    }
}

/// Extract the exact bound version from a non-create capability. A create
/// binding carries no exact version and must never drive a non-create apply.
fn exact_version(binding: VersionBinding) -> Result<u32> {
    match binding {
        VersionBinding::Exact(v) => Ok(v),
        VersionBinding::Create => {
            bail!("a create-bound capability cannot drive a replace/rotate/recover apply")
        }
    }
}

/// Revalidate the *immutable* fields of a non-create capability against the live
/// record row: the row must still exist, be owned by the applying authority, and
/// match the bound scope (kind + key).
///
/// The version is deliberately **not** checked here — scope and owner never
/// change for a record, but the version can be advanced by a concurrent
/// rotation, so a read-then-act version check would be a TOCTOU. Version
/// enforcement is fused into the authoritative store operation instead
/// (`rotate_at_version` for writes, `resolve_literal_for_recover` for reads).
async fn revalidate_scope_and_owner(
    directory: &SealedValueDirectory,
    owner: OwnerAuthority,
    record_id: &SealedRecordId,
    bound_scope: &SealedScopeRef,
) -> Result<()> {
    let row = directory
        .db()
        .sealed_value_record(record_id.to_string())
        .await?
        .filter(|row| row.deleted_at_ms.is_none())
        .context("sealed value record does not exist")?;
    if row.owner_principal != owner.principal() {
        bail!("sensitive owner capability principal mismatch");
    }
    let live_scope = scope_ref_from_row(&row)?;
    if &live_scope != bound_scope {
        bail!("sensitive owner capability scope mismatch");
    }
    Ok(())
}

/// Resolve a literal for Owner recovery, returning it inside [`Zeroizing`] with
/// no plaintext copy. Scope + owner + version are all validated here, and the
/// version check is **fused with the authoritative literal read** so a rotation
/// racing the recovery can never reveal a newer value:
///
/// * Session scope: the version fence is a single DB statement
///   (`sealed_session_version_fence`); the plaintext is then unwrapped from
///   the vault item for that exact version, so a bumped record returns
///   `None` → rejection, atomically.
/// * Compartment scope: the record row is read once; if its `active_version` is
///   not `expected_version` the recovery rejects, and otherwise the locator from
///   that same snapshot is read. A committed rotation both advances the version
///   and reclaims the superseded locator, so any interleaving yields either the
///   bound literal or a fail-closed miss — never a newer version.
async fn resolve_literal_for_recover(
    directory: &SealedValueDirectory,
    owner: OwnerAuthority,
    record_id: &SealedRecordId,
    bound_scope: &SealedScopeRef,
    expected_version: u32,
) -> Result<Zeroizing<String>> {
    let row = directory
        .db()
        .sealed_value_record(record_id.to_string())
        .await?
        .filter(|row| row.deleted_at_ms.is_none())
        .context("sealed value record does not exist")?;
    if row.owner_principal != owner.principal() {
        bail!("sensitive owner capability principal mismatch");
    }
    let live_scope = scope_ref_from_row(&row)?;
    if &live_scope != bound_scope {
        bail!("sensitive owner capability scope mismatch");
    }
    match bound_scope.kind() {
        SealedScopeKind::Session => {
            let literal = directory
                .session_literal_for_action(
                    owner,
                    record_id.to_string(),
                    i64::from(expected_version),
                )
                .await?
                .context("session sealed value literal not found (version superseded)")?;
            Ok(Zeroizing::new(literal))
        }
        SealedScopeKind::Project | SealedScopeKind::Global => {
            let active = u32::try_from(row.active_version).unwrap_or(0);
            if active != expected_version {
                bail!(
                    "version mismatch: capability bound to version {expected_version} but record is at version {active}"
                );
            }
            let raw = row
                .compartment_key
                .as_deref()
                .context("compartment locator missing")?;
            let key = SealedCompartmentKey::parse(raw)?;
            let literal = directory
                .compartment()
                .get_exact_zeroizing(&key)?
                .context("compartment literal not found (version superseded)")?;
            Ok(literal)
        }
        SealedScopeKind::KnowledgeBase => {
            bail!("knowledge-base sealed values do not use owner recovery")
        }
    }
}

#[cfg(test)]
mod tests;
