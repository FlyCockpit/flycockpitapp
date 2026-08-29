//! The exact grant tuple, and authorization that completes before lookup.
//!
//! A grant is exact: `(grant UUID, value/version, canonical project,
//! session/generation, action id/revision, timestamps)`. It never encodes a
//! wildcard target, an environment name, a child id, or a caller dispatch
//! identity — there is no field in which such a thing could be written.
//!
//! Two properties matter more than anything else here:
//!
//! * **Authorization completes before lookup.** Every check below reads only
//!   metadata: the grant row, the record row, and the registry descriptor. The
//!   literal is not touched until [`authorize_sealed_use`] has already
//!   returned `Ok`. A denial therefore costs *zero* secret reads.
//! * **Denial is one content-free result.** Wrong, stale, revoked, expired,
//!   missing, and unavailable all collapse into [`SealedUseDenied`], a
//!   fieldless type with one fixed message. A caller cannot distinguish "no
//!   such value" from "revoked" from "wrong session", so use is not an oracle
//!   over the inventory.

use std::fmt;
use std::sync::Arc;

use cockpit_db::db::sealed_scope::{
    SealedActionGrantRow, SealedGrantSelector, SealedScopeKind, SealedValueRecordRow,
};
use uuid::Uuid;

use super::action::{SealedActionId, SealedActionRegistry, SealedHostAction, SealedParams};
use super::identity::{SealedProjectKey, SealedProjectTrust, SealedRecordId};

/// The single message every denial renders. Byte-identical across branches.
pub const SEALED_USE_DENIED_MESSAGE: &str = "sealed value unavailable";

/// The one content-free denial.
///
/// Fieldless on purpose: there is nowhere to put a reason, so no future edit
/// can accidentally reintroduce a distinguishable branch. `Debug` and
/// `Display` both render exactly [`SEALED_USE_DENIED_MESSAGE`].
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct SealedUseDenied;

impl fmt::Display for SealedUseDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(SEALED_USE_DENIED_MESSAGE)
    }
}

impl fmt::Debug for SealedUseDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(SEALED_USE_DENIED_MESSAGE)
    }
}

impl std::error::Error for SealedUseDenied {}

/// The sole use request shape exposed to untrusted models, built-in tools, and
/// Monty tools. Three fields, and none of them is a destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UseSealedValueRequest {
    pub sealed_value_id: SealedRecordId,
    pub action_id: SealedActionId,
    pub parameters: std::collections::BTreeMap<String, super::action::SealedParamValue>,
}

/// Everything about the caller that authorization consults.
///
/// `caller_trust` is the custody axis; steering posture is not carried here
/// (issue #75); reference-only use is identical for every caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedUseContext {
    pub caller_trust: crate::config::providers::ModelTrust,
    pub project_key: SealedProjectKey,
    pub project_trust: SealedProjectTrust,
    pub session_id: Uuid,
    pub session_generation: u64,
    pub now_ms: i64,
}

/// A completed authorization. Holding one proves every exact check passed and
/// the deterministic use claim was won.
///
/// Deliberately not constructible outside this module: the only way to obtain
/// one is to pass [`authorize_sealed_use`].
pub struct AuthorizedSealedUse {
    pub(super) record: SealedValueRecordRow,
    pub(super) grant: SealedActionGrantRow,
    pub(super) action: Arc<dyn SealedHostAction>,
    pub(super) params: SealedParams,
}

impl AuthorizedSealedUse {
    /// The grant this authorization resolved.
    ///
    /// There is deliberately no `record()` accessor. The record read *before*
    /// authorization must not be reachable from here: the literal is resolved
    /// from what the claim transaction returns, so a superseded or deleted
    /// locator is unpassable rather than merely unused.
    pub(super) fn grant(&self) -> &SealedActionGrantRow {
        &self.grant
    }
}

impl fmt::Debug for AuthorizedSealedUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedSealedUse")
            .field("record_id", &self.record.record_id)
            .field("grant_id", &self.grant.grant_id)
            .finish()
    }
}

/// The metadata authorization needs, gathered by the caller.
///
/// Bundling it keeps [`authorize_sealed_use`] a pure function of metadata:
/// it performs no I/O, so it structurally cannot read a literal.
pub struct SealedAuthorizationInputs {
    pub record: Option<SealedValueRecordRow>,
    pub grant: Option<SealedActionGrantRow>,
    /// For a Global record, whether the Owner granted it to this canonical
    /// project. `true` for non-global scopes, which carry their own scope key.
    pub global_reaches_project: bool,
}

/// Build the exact selector for a grant lookup. Every field is required, so a
/// caller must already name the whole tuple; there is no partial-match probe.
pub fn sealed_grant_selector(
    request: &UseSealedValueRequest,
    ctx: &SealedUseContext,
) -> SealedGrantSelector {
    SealedGrantSelector {
        record_id: request.sealed_value_id.to_string(),
        action_id: request.action_id.as_str().to_string(),
        project_key: ctx.project_key.as_str().to_string(),
        session_id: ctx.session_id.to_string(),
        session_generation: ctx.session_generation as i64,
    }
}

/// Authorize one use, from metadata alone.
///
/// This function performs **no I/O**. It is handed already-read metadata and
/// the closed registry, and it decides. That is the mechanical guarantee that
/// authorization completes before lookup: there is no lookup available to it.
///
/// Every failure path returns the same [`SealedUseDenied`].
pub fn authorize_sealed_use(
    request: &UseSealedValueRequest,
    ctx: &SealedUseContext,
    inputs: SealedAuthorizationInputs,
    registry: &SealedActionRegistry,
) -> Result<AuthorizedSealedUse, SealedUseDenied> {
    // The canonical project must currently be trusted. A trust change denies
    // immediately, before anything else is considered.
    if !ctx.project_trust.is_trusted() {
        return Err(SealedUseDenied);
    }

    // The action must resolve in the closed registry. Resolution is an exact
    // opaque-id lookup; it never compiles or creates an action.
    let Some(action) = registry.resolve(&request.action_id) else {
        return Err(SealedUseDenied);
    };
    let descriptor = action.descriptor();

    // Bounded typed parameters are checked first, so a malformed request never
    // reaches the grant table, let alone a literal.
    let Ok(params) = descriptor.bind_parameters(&request.parameters) else {
        return Err(SealedUseDenied);
    };

    let Some(record) = inputs.record else {
        return Err(SealedUseDenied);
    };
    let Some(grant) = inputs.grant else {
        return Err(SealedUseDenied);
    };

    // Record must be live: not deleted, and past its create commit.
    if !record.is_resolvable() {
        return Err(SealedUseDenied);
    }
    if record.record_id != request.sealed_value_id.to_string() {
        return Err(SealedUseDenied);
    }

    // Global reach is an explicit Owner grant to this canonical project.
    if record.scope == SealedScopeKind::Global && !inputs.global_reaches_project {
        return Err(SealedUseDenied);
    }
    // Project-scope records only resolve inside their own canonical project.
    if record.scope == SealedScopeKind::Project && record.scope_key != ctx.project_key.as_str() {
        return Err(SealedUseDenied);
    }
    // Session-scope records only resolve inside their own session.
    if record.scope == SealedScopeKind::Session && record.scope_key != ctx.session_id.to_string() {
        return Err(SealedUseDenied);
    }

    // Grant targeting must match exactly on every axis.
    if grant.record_id != record.record_id
        || grant.action_id != request.action_id.as_str()
        || grant.project_key != ctx.project_key.as_str()
        || grant.session_id != ctx.session_id.to_string()
        || grant.session_generation != ctx.session_generation as i64
    {
        return Err(SealedUseDenied);
    }

    // Version pinning: a rotation invalidates every grant pinned to the old
    // version rather than silently upgrading it to the new secret.
    if grant.value_version != record.active_version {
        return Err(SealedUseDenied);
    }

    // Action revision pinning: a revised action instance invalidates grants
    // issued against the previous revision.
    if grant.action_revision != i64::from(descriptor.revision.get()) {
        return Err(SealedUseDenied);
    }

    // Revocation and expiry.
    if grant.revoked_at_ms.is_some() {
        return Err(SealedUseDenied);
    }
    if let Some(expires_at) = grant.expires_at_ms
        && expires_at <= ctx.now_ms
    {
        return Err(SealedUseDenied);
    }

    Ok(AuthorizedSealedUse {
        record,
        grant,
        action: Arc::clone(action),
        params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denial_is_one_indistinguishable_content_free_value() {
        let a = SealedUseDenied;
        // A second, independently constructed denial. `SealedUseDenied` is a
        // unit struct, so this is the only distinct way to make one — which is
        // itself the property under test.
        let b = SealedUseDenied;
        assert_eq!(a, b);
        assert_eq!(a.to_string(), SEALED_USE_DENIED_MESSAGE);
        assert_eq!(format!("{a:?}"), SEALED_USE_DENIED_MESSAGE);
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
        assert_eq!(std::mem::size_of::<SealedUseDenied>(), 0);
    }
}
