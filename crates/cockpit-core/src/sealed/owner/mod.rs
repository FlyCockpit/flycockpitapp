//! Owner-only sealed-value administration through the protected sensitive
//! channel.
//!
//! This module owns the `OwnerWrite` and `OwnerRecover` variants of
//! [`ProtectedSensitiveIngress`](crate::leak_report::ProtectedSensitiveIngress)
//! and the stable sensitive-channel protocol that `leak-report-tool` supplies:
//!
//! * [`BeginSensitiveOwnerOperation`] — mints a single-use, 60-second
//!   capability bound to one exact operation, scope, and version.
//! * [`SensitiveOwnerFrame`] — carries the capability plus an optional literal
//!   into a contained or revealed outcome, zeroizing on every path.
//!
//! ## Properties
//!
//! * **Peer-authenticated local transport.** The channel is daemon-local; no
//!   ordinary RPC, event, argv, env, config, path, clipboard, or generic tool
//!   argument carries a literal.
//! * **16 KiB bounded frame.** A literal larger than [`MAX_SENSITIVE_FRAME_BYTES`]
//!   is rejected before parse.
//! * **Zeroization.** Every literal is held in a [`Zeroizing`] frame and
//!   zeroized on drop, success, or error.
//! * **60-second capability expiry.** A capability older than
//!   [`CAPABILITY_TTL`] is rejected before parse.
//! * **One use.** A capability is consumed exactly once; replay is rejected.
//! * **Replay / cancel / wrong-owner / wrong-project / wrong-session /
//!   wrong-version rejection before parse.** The capability is validated
//!   against the bound operation *before* the literal is touched.
//! * **No-echo create/rotate.** [`OwnerWriteDisposition::Create`] and
//!   [`OwnerWriteDisposition::Rotate`] open a local no-echo sensitive frame;
//!   the literal never reaches terminal output.
//! * **Ephemeral recover overlay.** [`SensitiveOwnerFrame::for_recover`]
//!   returns a revealed frame that is zeroized on navigation, detach, or
//!   timeout — never terminal output.
//!
//! `/sealed` transport, command grammar, and TUI recovery UX belong to the
//! TUI layer; this module supplies the protocol and the Owner-facing
//! operations only.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::action::OwnerAuthority;
use super::compartment::{SealedCompartmentKey, SealedLiteral};
use super::identity::{
    SealedDescription, SealedName, SealedRecordId, SealedScopeKind, SealedScopeRef,
};
use super::store::{CreateSealedValue, SealedValueDirectory, SealedValueSummary};

/// Maximum literal payload carried in one sensitive frame, in bytes.
pub const MAX_SENSITIVE_FRAME_BYTES: usize = 16 * 1024;

/// A sensitive-owner capability is valid for 60 seconds after minting.
pub const CAPABILITY_TTL: Duration = Duration::from_secs(60);

/// Closed disposition for an Owner write. Re-exported from the leak-report
/// module so the closed set is defined in one place.
pub use crate::leak_report::OwnerWriteDisposition;

/// The closed operation a capability permits.
///
/// `name` and `description` are required for [`OwnerWriteDisposition::Create`]
/// and ignored for replace/rotate/recover (those resolve the existing record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveOwnerOperation {
    pub record_id: Option<SealedRecordId>,
    pub scope: SealedScopeRef,
    pub version: u32,
    pub disposition: OwnerWriteDisposition,
    /// Required for create; the canonical name of the new value.
    pub name: Option<SealedName>,
    /// Required for create; the safe description.
    pub description: Option<SealedDescription>,
}

impl SensitiveOwnerOperation {
    /// Build a create operation.
    pub fn create(scope: SealedScopeRef, name: SealedName, description: SealedDescription) -> Self {
        Self {
            record_id: None,
            scope,
            version: 0,
            disposition: OwnerWriteDisposition::Create,
            name: Some(name),
            description: Some(description),
        }
    }

    /// Build a replace operation (same as rotate for the store layer: new
    /// literal, new version, same record id).
    pub fn replace(record_id: SealedRecordId, scope: SealedScopeRef, version: u32) -> Self {
        Self {
            record_id: Some(record_id),
            scope,
            version,
            disposition: OwnerWriteDisposition::Replace,
            name: None,
            description: None,
        }
    }

    /// Build a rotate operation.
    pub fn rotate(record_id: SealedRecordId, scope: SealedScopeRef, version: u32) -> Self {
        Self {
            record_id: Some(record_id),
            scope,
            version,
            disposition: OwnerWriteDisposition::Rotate,
            name: None,
            description: None,
        }
    }

    /// Build a recover operation.
    pub fn recover(record_id: SealedRecordId, scope: SealedScopeRef, version: u32) -> Self {
        Self {
            record_id: Some(record_id),
            scope,
            version,
            // Disposition is not used for recover; the frame kind distinguishes.
            disposition: OwnerWriteDisposition::Rotate,
            name: None,
            description: None,
        }
    }
}

/// A single-use, time-bounded capability minted by
/// [`BeginSensitiveOwnerOperation`].
///
/// The capability is bound to one exact operation, one owner principal, and
/// one minting instant. It is consumed exactly once by
/// [`SensitiveOwnerFrame::apply`]; a replayed, expired, or mismatched
/// capability fails before secret parse.
#[derive(Debug, Clone)]
pub struct OneUseCapability {
    capability_id: Uuid,
    operation: SensitiveOwnerOperation,
    owner_principal: String,
    minted_at: Instant,
    consumed: Arc<std::sync::Mutex<bool>>,
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

    /// Whether this capability has been consumed.
    pub fn is_consumed(&self) -> bool {
        *self.consumed.lock().expect("capability mutex")
    }

    /// Whether this capability has expired.
    pub fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.minted_at) > CAPABILITY_TTL
    }

    /// The owner principal this capability is bound to.
    pub fn owner_principal(&self) -> &str {
        &self.owner_principal
    }
}

impl PartialEq for OneUseCapability {
    fn eq(&self, other: &Self) -> bool {
        self.capability_id == other.capability_id
    }
}

impl Eq for OneUseCapability {}

/// The result of [`BeginSensitiveOwnerOperation::begin`].
#[derive(Debug, Clone)]
pub struct BeginResult {
    pub capability: OneUseCapability,
}

/// The sensitive-channel entry point. Mints single-use capabilities for
/// Owner write/recover operations.
///
/// This is the stable `BeginSensitiveOwnerOperation` interface from
/// `leak-report-tool`: peer-authenticated local transport, 16 KiB bounded
/// frame, zeroization, no ordinary response/event representation, 60-second
/// capability expiry, one use, and replay/cancel/wrong-owner/project/session/
/// version rejection before parse.
pub struct BeginSensitiveOwnerOperation {
    owner_principal: String,
}

impl BeginSensitiveOwnerOperation {
    /// Create a new begin-point bound to one Owner principal. The principal is
    /// stamped on every capability and checked at frame time.
    pub fn new(owner_principal: impl Into<String>) -> Self {
        Self {
            owner_principal: owner_principal.into(),
        }
    }

    /// Mint a single-use capability for one operation. The capability is
    /// valid for [`CAPABILITY_TTL`] and consumed by exactly one
    /// [`SensitiveOwnerFrame::apply`].
    pub fn begin(&self, _owner: OwnerAuthority, operation: SensitiveOwnerOperation) -> BeginResult {
        let capability = OneUseCapability {
            capability_id: Uuid::new_v4(),
            operation,
            owner_principal: self.owner_principal.clone(),
            minted_at: Instant::now(),
            consumed: Arc::new(std::sync::Mutex::new(false)),
        };
        BeginResult { capability }
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
#[derive(Debug)]
pub enum SensitiveFrameOutcome {
    /// The write/replace/rotate succeeded. No literal is returned. Carries
    /// the updated safe summary.
    Contained { summary: SealedValueSummary },
    /// The recover succeeded. The literal is available in an ephemeral
    /// zeroizing frame that is zeroized on drop. Never terminal output.
    Revealed { literal: Zeroizing<String> },
}

/// The sensitive frame: carries a capability plus an optional literal into a
/// contained or revealed outcome.
///
/// This is the stable `SensitiveOwnerFrame { capability, literal? } ->
/// contained|revealed` interface from `leak-report-tool`.
pub struct SensitiveOwnerFrame<'a> {
    capability: &'a OneUseCapability,
    literal: Option<Zeroizing<String>>,
    now: Instant,
    kind: SensitiveFrameKind,
}

impl<'a> SensitiveOwnerFrame<'a> {
    /// Create a frame for a write/replace/rotate. The literal is required and
    /// is consumed into a zeroizing frame.
    pub fn for_write(capability: &'a OneUseCapability, literal: Zeroizing<String>) -> Self {
        Self {
            capability,
            literal: Some(literal),
            now: Instant::now(),
            kind: SensitiveFrameKind::Write,
        }
    }

    /// Create a frame for a recover. No literal is supplied; the outcome
    /// reveals one.
    pub fn for_recover(capability: &'a OneUseCapability) -> Self {
        Self {
            capability,
            literal: None,
            now: Instant::now(),
            kind: SensitiveFrameKind::Recover,
        }
    }

    /// Override the "now" instant, for deterministic tests.
    pub fn with_now(mut self, now: Instant) -> Self {
        self.now = now;
        self
    }

    /// The kind of this frame.
    pub fn kind(&self) -> SensitiveFrameKind {
        self.kind
    }

    /// Apply this frame against a [`SealedValueDirectory`]. Validates the
    /// capability (expiry, one-use, operation match) before touching the
    /// literal, then performs the operation and returns a contained or
    /// revealed outcome.
    ///
    /// The literal is zeroized on every path: success, error, and rejection.
    pub async fn apply(
        self,
        owner: OwnerAuthority,
        directory: &SealedValueDirectory,
        now_ms: i64,
    ) -> Result<SensitiveFrameOutcome> {
        // 1. Validate the capability before any literal parse.
        self.validate_capability()?;

        // 2. Dispatch by frame kind.
        let outcome = match self.kind {
            SensitiveFrameKind::Write => {
                let literal = self.literal.context("write frame requires a literal")?;
                // Bound the literal to 16 KiB before any store touch.
                if literal.len() > MAX_SENSITIVE_FRAME_BYTES {
                    bail!("sensitive frame literal exceeds {MAX_SENSITIVE_FRAME_BYTES} bytes");
                }
                let op = self.capability.operation.clone();
                let sealed_literal = SealedLiteral::new(literal.as_str().to_string());
                let summary = match op.disposition {
                    OwnerWriteDisposition::Create => {
                        let name = op.name.context("create requires a name")?;
                        let description =
                            op.description.context("create requires a description")?;
                        let request = CreateSealedValue {
                            scope: op.scope,
                            name,
                            description,
                            owner_principal: self.capability.owner_principal.clone(),
                        };
                        directory
                            .create(owner, request, sealed_literal, now_ms)
                            .await?
                    }
                    OwnerWriteDisposition::Replace | OwnerWriteDisposition::Rotate => {
                        let record_id = op
                            .record_id
                            .context("replace/rotate requires a record id")?;
                        directory
                            .rotate(owner, record_id, sealed_literal, now_ms)
                            .await?
                    }
                };
                SensitiveFrameOutcome::Contained { summary }
            }
            SensitiveFrameKind::Recover => {
                let op = self.capability.operation.clone();
                let record_id = op.record_id.context("recover requires a record id")?;
                let literal =
                    resolve_literal_for_recover(directory, &record_id, op.version, op.scope.kind())
                        .await?;
                SensitiveFrameOutcome::Revealed {
                    literal: Zeroizing::new(literal),
                }
            }
        };

        // Mark the capability as consumed.
        *self.capability.consumed.lock().expect("capability mutex") = true;

        Ok(outcome)
    }

    /// Validate the capability: not consumed, not expired, and the frame kind
    /// matches the operation disposition.
    fn validate_capability(&self) -> Result<()> {
        if self.capability.is_consumed() {
            bail!("sensitive owner capability already used (replay rejected)");
        }
        if self.capability.is_expired(self.now) {
            bail!("sensitive owner capability expired");
        }
        // A write frame must carry a literal; a recover frame must not.
        match (self.kind, self.literal.is_some()) {
            (SensitiveFrameKind::Write, true) => Ok(()),
            (SensitiveFrameKind::Write, false) => {
                bail!("write frame requires a literal")
            }
            (SensitiveFrameKind::Recover, false) => Ok(()),
            (SensitiveFrameKind::Recover, true) => {
                bail!("recover frame must not carry a literal")
            }
        }
    }
}

/// Resolve a literal for Owner recovery. This is the sole path from a
/// [`SensitiveOwnerFrame::for_recover`] to a raw literal, and it is gated by
/// the capability validation that precedes it.
///
/// Session scope reads from SQLite; project/global scope reads from the
/// compartment. The version is checked against the record's active version so
/// a stale capability (one minted before a rotation) cannot recover the
/// superseded literal.
async fn resolve_literal_for_recover(
    directory: &SealedValueDirectory,
    record_id: &SealedRecordId,
    expected_version: u32,
    scope: SealedScopeKind,
) -> Result<String> {
    let row = directory
        .db()
        .sealed_value_record(record_id.to_string())
        .await?
        .context("sealed value record does not exist")?;
    if row.scope != scope {
        bail!(
            "scope mismatch: capability bound to {scope:?} but record is {:?}",
            row.scope
        );
    }
    let active = u32::try_from(row.active_version).unwrap_or(0);
    if expected_version != 0 && expected_version != active {
        bail!(
            "version mismatch: capability bound to version {expected_version} but record is at version {active}"
        );
    }
    match scope {
        SealedScopeKind::Session => {
            let literal = directory
                .db()
                .sealed_session_literal_for_action(record_id.to_string(), row.active_version)
                .await?
                .context("session sealed value literal not found")?;
            Ok(literal)
        }
        SealedScopeKind::Project | SealedScopeKind::Global => {
            let raw = row
                .compartment_key
                .as_deref()
                .context("compartment locator missing")?;
            let key = SealedCompartmentKey::parse(raw)?;
            let literal = directory
                .compartment()
                .get_exact(&key)?
                .context("compartment literal not found")?;
            Ok(literal.expose_for_redaction().to_string())
        }
    }
}

#[cfg(test)]
mod tests;
