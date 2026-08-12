//! Deriving the active sealed-value set for interactive untrusted egress.
//!
//! This is the seam the interactive completion chokepoint reads to decide which
//! sealed literals may render their actionable `use_sealed_value` marker on an
//! untrusted wire. It answers exactly one question: *which sealed value ids hold
//! a live exact grant in this session generation?* — reusing the existing
//! grant-liveness logic ([`SealedMarkerPredicate::active_capability`] plus the
//! grant row's revocation/expiry), never a reimplementation of it.
//!
//! It resolves no literal and returns none: the result is a set of canonical
//! value ids, so nothing here can put a secret on any wire. The redaction table
//! then keys sealed entries against this set in
//! [`crate::redact::RedactionTable::with_sealed_replacements`].

use std::collections::HashSet;

use anyhow::Result;
use cockpit_db::db::Db;
use uuid::Uuid;

use super::action::{SealedActionId, SealedActionRegistry, SealedActionRevision};
use super::identity::{SealedRecordId, sealed_legacy_active_key, sealed_scoped_active_key};
use super::marker::SealedMarkerPredicate;

/// The set of canonical sealed value ids that have a LIVE exact grant for
/// `(session_id, session_generation)`.
///
/// A grant contributes its value id iff every liveness check the sealed-use
/// authorization family enforces holds: the grant is not revoked and not
/// expired (grant-row metadata), and the record resolves with the pinned active
/// version, the action resolves in the closed registry, and the action's
/// revision matches (the [`SealedMarkerPredicate::active_capability`] predicate,
/// reused verbatim — no liveness is reimplemented here).
///
/// The set is keyed the way [`RedactionTable::with_sealed_replacements`] keys
/// sealed entries: a VERSION-SCOPED, namespaced key over the record id (scoped
/// entries) *and* the record's canonical name (legacy session entries registered
/// before scoping), so the marker activates regardless of which keying an entry
/// used. Because the version is part of the key, a live grant for version N
/// activates only an entry sealed at version N of that record — never a stale
/// prior-version entry, and never a legacy same-name entry of a different record
/// (legacy entries are version 0). A malformed persisted grant value fails
/// closed (the grant is skipped → generic rendering), never open.
///
/// [`RedactionTable::with_sealed_replacements`]:
///     crate::redact::RedactionTable::with_sealed_replacements
pub async fn active_sealed_value_ids(
    db: &Db,
    registry: &SealedActionRegistry,
    session_id: Uuid,
    session_generation: u64,
    now_ms: i64,
) -> Result<HashSet<String>> {
    let grants = db
        .sealed_action_grants_for_session(session_id.to_string(), session_generation as i64)
        .await?;
    let predicate = SealedMarkerPredicate::new(db.clone());
    let mut active: HashSet<String> = HashSet::new();

    for grant in grants {
        // Grant-level liveness: a revoked or expired grant is never live.
        if grant.revoked_at_ms.is_some() {
            continue;
        }
        if let Some(expires_at) = grant.expires_at_ms
            && expires_at <= now_ms
        {
            continue;
        }

        // Parse the grant's exact tuple into typed keys. Any malformed persisted
        // field fails closed (skip → generic), never open.
        let Ok(record_id) = SealedRecordId::parse(&grant.record_id) else {
            continue;
        };
        let Ok(version) = u32::try_from(grant.value_version) else {
            continue;
        };
        let Ok(action_id) = SealedActionId::parse(&grant.action_id) else {
            continue;
        };
        let Ok(revision_u32) = u32::try_from(grant.action_revision) else {
            continue;
        };
        let Ok(revision) = SealedActionRevision::new(revision_u32) else {
            continue;
        };

        // Record/version/action/revision liveness — the existing predicate.
        if !predicate
            .active_capability(record_id, version, &action_id, revision, registry)
            .await?
            .is_active()
        {
            continue;
        }

        // Key the active set the way [`RedactionTable::with_sealed_replacements`]
        // keys sealed entries: VERSION-SCOPED on both sides. The grant's version
        // binds the key so this live grant activates ONLY an entry sealed at the
        // exact same version of the record — never a stale prior-version entry.
        active.insert(sealed_scoped_active_key(&record_id.to_string(), version));
        // Legacy session entries key the redaction table by canonical name; add
        // the version-scoped legacy key so a marker activates under either keying
        // scheme. Because a legacy entry is version 0 and this grant is version
        // >= 1, this can never activate a legacy same-name entry of a DIFFERENT
        // record (that collision is exactly what the version binding closes).
        if let Some(identity) = predicate.identity(record_id).await? {
            active.insert(sealed_legacy_active_key(identity.name.as_str(), version));
        }
    }

    Ok(active)
}

/// The interactive completion chokepoint's sealed-egress decision, extracted as
/// one production seam so it is drivable end-to-end in tests (removing the
/// derivation here fails those tests) rather than reimplemented in a test.
///
/// Returns `Some(table)` — the model's effective table with sealed entries
/// re-rendered as their actionable `use_sealed_value` marker — WHEN AND ONLY
/// WHEN every gate holds: the target is untrusted, the request is interactive,
/// this request's tool roster exposes a callable `use_sealed_value`, and at
/// least one sealed entry holds a live exact grant in this session generation.
/// Otherwise returns `None`, and the caller uses the model's own effective
/// (generic) table. Derivation is fresh per attempt (revoke between attempts →
/// marker then generic), the `Model` never gets a DB handle (the caller derives
/// this and passes the table to `prepare_completion_request`), and a DB error
/// falls back to `None` — fail closed to safe generic rendering, never to a
/// stale marker, a raw literal, or a dispatch error. Trusted targets keep raw
/// custody (`None`).
pub async fn derive_untrusted_interactive_sealed_egress(
    model: &crate::engine::model::Model,
    interactive: bool,
    tools: &[crate::engine::message::ToolDefinition],
    db: &Db,
    registry: &SealedActionRegistry,
    session_id: Uuid,
    session_generation: u64,
    now_ms: i64,
) -> Option<std::sync::Arc<crate::redact::RedactionTable>> {
    if model.is_trusted()
        || !interactive
        || !tools
            .iter()
            .any(|tool| tool.name == super::USE_SEALED_VALUE_TOOL)
    {
        return None;
    }
    match active_sealed_value_ids(db, registry, session_id, session_generation, now_ms).await {
        Ok(active_ids) if !active_ids.is_empty() => Some(std::sync::Arc::new(
            model.redact_table().with_sealed_replacements(&active_ids),
        )),
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "sealed grant derivation failed; untrusted egress stays generic"
            );
            None
        }
    }
}
