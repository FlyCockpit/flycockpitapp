//! The sealed marker capability predicate.
//!
//! This is the seam downstream renderer and export consumers read. It exposes
//! exactly three things and nothing else:
//!
//! 1. **Typed canonical identity** — [`SealedMarkerIdentity`].
//! 2. **Active exact value/version/action capability** — a two-state predicate
//!    ([`SealedCapabilityState`]) over one exact tuple.
//! 3. **Historical redaction inventory** —
//!    [`historical_redaction_inventory`], the canonical typed identity of
//!    every sealed entry a redaction table carries.
//!
//! What it deliberately does **not** do, because each belongs to a different
//! owner: render provider-facing copy (`sealed-value-untrusted-inference-
//! marker`), select subagents or model modes (the trusted-child coordinator),
//! compile or create actions and validate adapter attributes
//! (`sealed-value-owner-management`), or implement export behavior
//! (`portable-redacted-debug-export`).
//!
//! The capability predicate is intentionally *not* an authorization result. It
//! answers "is this tuple currently capable", which a renderer needs to decide
//! whether to show a live marker. It never consults or reveals a grant, so it
//! cannot be used as an authorization oracle: a caller learns nothing about
//! who may use the value, only whether the value/version/action tuple is
//! itself still live.

use anyhow::Result;
use cockpit_db::db::Db;
use cockpit_db::db::sealed_scope::SealedScopeKind;

use super::action::{SealedActionId, SealedActionRegistry, SealedActionRevision};
use super::identity::{SealedName, SealedRecordId, SealedRedactionIdentity};

/// Canonical typed identity of one sealed value, for renderers and exports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMarkerIdentity {
    pub record_id: SealedRecordId,
    pub scope: SealedScopeKind,
    pub name: SealedName,
    pub version: u32,
}

/// Whether an exact value/version/action tuple is currently capable.
///
/// Two states only. There is no "revoked", "expired", or "missing" variant,
/// because distinguishing them would reintroduce the status branching that
/// use denial deliberately collapses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedCapabilityState {
    Active,
    Inactive,
}

impl SealedCapabilityState {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// The read-only predicate surface handed to downstream consumers.
#[derive(Debug, Clone)]
pub struct SealedMarkerPredicate {
    db: Db,
}

impl SealedMarkerPredicate {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Canonical typed identity for one record, or `None` if it is not live.
    pub async fn identity(
        &self,
        record_id: SealedRecordId,
    ) -> Result<Option<SealedMarkerIdentity>> {
        let Some(row) = self.db.sealed_value_record(record_id.to_string()).await? else {
            return Ok(None);
        };
        if !row.is_resolvable() {
            return Ok(None);
        }
        Ok(Some(SealedMarkerIdentity {
            record_id,
            scope: row.scope,
            name: SealedName::canonical(&row.name)?,
            version: u32::try_from(row.active_version).unwrap_or(0),
        }))
    }

    /// Is this exact `(value, version, action, revision)` tuple live?
    ///
    /// Active requires all of: the record resolves, its active version is
    /// exactly `version`, the action id resolves in the closed registry, and
    /// that instance's revision is exactly `revision`. Anything else is
    /// `Inactive`. This never compiles an action and never reads a literal.
    pub async fn active_capability(
        &self,
        record_id: SealedRecordId,
        version: u32,
        action_id: &SealedActionId,
        revision: SealedActionRevision,
        registry: &SealedActionRegistry,
    ) -> Result<SealedCapabilityState> {
        let Some(row) = self.db.sealed_value_record(record_id.to_string()).await? else {
            return Ok(SealedCapabilityState::Inactive);
        };
        if !row.is_resolvable() || row.active_version != i64::from(version) {
            return Ok(SealedCapabilityState::Inactive);
        }
        let Some(action) = registry.resolve(action_id) else {
            return Ok(SealedCapabilityState::Inactive);
        };
        if action.descriptor().revision != revision {
            return Ok(SealedCapabilityState::Inactive);
        }
        Ok(SealedCapabilityState::Active)
    }
}

/// The canonical typed identity of every sealed entry in a redaction table.
///
/// Redaction is monotonic: revoking, deleting, or rotating a value never
/// removes its historical entry, so this inventory keeps naming values that
/// are no longer usable. That is the point — a transcript written while the
/// value was live must stay scrubbed forever.
///
/// This reads the typed classification directly via
/// `RedactionTable::sealed_identities`, which returns canonical identities,
/// never values, so no literal can pass through here.
pub fn historical_redaction_inventory(
    table: &crate::redact::RedactionTable,
) -> Vec<SealedRedactionIdentity> {
    let mut inventory: Vec<_> = table.sealed_identities();
    inventory.sort_by(|a, b| {
        (a.scope.as_str(), a.name.as_str(), a.version).cmp(&(
            b.scope.as_str(),
            b.name.as_str(),
            b.version,
        ))
    });
    inventory.dedup();
    inventory
}

/// The same inventory, read from a persisted redaction table.
pub fn historical_redaction_inventory_from_persisted(
    json: &str,
) -> Result<Vec<SealedRedactionIdentity>> {
    let table = crate::redact::RedactionTable::from_persisted_json(json)?;
    Ok(historical_redaction_inventory(&table))
}
