//! Shared named-secret ownership funnel.
//!
//! The `secrets-owner-rpc-v1` batch introduced an in-transaction cross-kind
//! ownership guard for the daemon provider/MCP save paths. This module factors
//! those primitives out of `daemon::server::dispatch` so EVERY config-write and
//! secret-mutation path (provider save, MCP save, policy import, `cockpit mcp
//! add` via the daemon RPC, credential refresh) plus owner-scoped resolution can
//! share ONE ownership model rather than re-deriving it.
//!
//! Ownership tables (`0001_initial.sql`):
//!   * `secret_named_ownership(item_id, owner_kind ∈ {provider,mcp}, project_root)`
//!   * `secret_credential_ownership(item_id, provider_id, project_root)`
//!
//! All the `*_on_conn` primitives run on a caller-supplied connection so they
//! compose inside the writer's `BEGIN IMMEDIATE` transaction — the SQLite write
//! lock is held across the whole closure, so no other process can interpose a
//! conflicting claim between a check and the subsequent write.

use std::collections::BTreeSet;

use rusqlite::OptionalExtension;

use crate::db::Db;
use crate::secure_key::SecretVault;

/// Named-secret owner kinds. `mcp:`-prefixed item ids are reserved for MCP
/// owners; every other name is provider-ownable. This prefix convention lets
/// owner-scoped resolution attribute a legacy (unclaimed) secret to the config
/// kind that references it without mis-attributing an MCP token to a provider.
pub(crate) const OWNER_KIND_PROVIDER: &str = "provider";
pub(crate) const OWNER_KIND_MCP: &str = "mcp";

const MCP_ITEM_PREFIX: &str = "mcp:";

/// Canonical workspace-root key for every ownership row, query, claim, journal,
/// and owner-scoped resolution.
///
/// The daemon's authz layer anchors path containment on
/// [`crate::daemon::fs_api::canonical_project_root`] (`std::fs::canonicalize` —
/// symlinks resolved, trailing slash stripped, absolute). Ownership rows were
/// keyed on raw wire/`cwd` strings, so a symlinked, trailing-slash, or otherwise
/// non-canonical spelling of the SAME workspace produced a DIFFERENT owner
/// string — a claim written under one spelling would not match resolution under
/// another (a fail-closed outage, or a claim that silently fails to protect the
/// canonical root). This funnels every ownership path through the SAME canonical
/// form the authz layer trusts.
///
/// A path that cannot be canonicalized (it does not exist on this host) falls
/// back to a lexical trailing-slash strip so the key stays deterministic rather
/// than erroring — synthetic test roots and not-yet-created directories still
/// produce a stable key. When the directory does exist (every real daemon
/// workspace), the symlink-resolved canonical path is used, exactly matching the
/// authz layer.
pub(crate) fn canonical_owner_root(project_root: &str) -> String {
    match std::fs::canonicalize(project_root) {
        Ok(path) => path.to_string_lossy().into_owned(),
        Err(_) => {
            let trimmed = project_root.trim_end_matches('/');
            if trimmed.is_empty() {
                project_root.to_string()
            } else {
                trimmed.to_string()
            }
        }
    }
}

/// Whether `item_id` may legitimately be owned by `owner_kind` under the
/// `mcp:`-prefix reservation. An `mcp:` name is MCP-only; any other name is
/// provider-only. Used to gate legacy backfill so a provider config that
/// references an `mcp:` name (or vice-versa) can never adopt it.
pub(crate) fn owner_kind_may_own(owner_kind: &str, item_id: &str) -> bool {
    match owner_kind {
        OWNER_KIND_MCP => item_id.starts_with(MCP_ITEM_PREFIX),
        _ => !item_id.starts_with(MCP_ITEM_PREFIX),
    }
}

/// Typed marker carried out of a vault-mutation transaction when the
/// in-transaction cross-kind ownership guard rejects a named secret. It lets the
/// async caller re-map a genuine ownership conflict to a `BadRequest` while a
/// real DB fault still surfaces as `internal`.
#[derive(Debug)]
pub(crate) struct NamedSecretClaimConflict {
    item_id: String,
}

impl std::fmt::Display for NamedSecretClaimConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "named secret `{}` is already claimed by a provider or another workspace",
            self.item_id
        )
    }
}

impl std::error::Error for NamedSecretClaimConflict {}

/// Reject any existing `secret_named_ownership` row for `item_id` that is not
/// held by this exact (`owner_kind`, `project_root`) owner, using the SAME
/// connection (and therefore the same `BEGIN IMMEDIATE` transaction) that then
/// writes the vault value and inserts the claim.
///
/// This is the atomic core of the cross-kind admission check. The daemon's
/// writer runs every `Db::transaction` under `BEGIN IMMEDIATE`, which holds the
/// SQLite write lock for the whole closure; no other daemon process can commit
/// an interposing claim between this SELECT and the subsequent write. Running
/// the conflict check as a separate `Db::read` before the transaction (as the
/// admission precheck does) leaves a cross-process TOCTOU window where a
/// provider could claim the name after the check but before the mutation — this
/// guard closes it. On conflict it returns [`NamedSecretClaimConflict`] so the
/// enclosing transaction rolls back with no vault write and no claim insert.
pub(crate) fn reject_conflicting_named_ownership_on_conn(
    conn: &rusqlite::Connection,
    item_id: &str,
    owner_kind: &str,
    project_root: &str,
) -> anyhow::Result<()> {
    let conflict: Option<(String, String)> = conn
        .query_row(
            "SELECT owner_kind, project_root FROM secret_named_ownership
             WHERE item_id = ?1 AND NOT (owner_kind = ?2 AND project_root = ?3)
             LIMIT 1",
            rusqlite::params![item_id, owner_kind, project_root],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if conflict.is_some() {
        return Err(anyhow::Error::new(NamedSecretClaimConflict {
            item_id: item_id.to_string(),
        }));
    }
    Ok(())
}

/// Atomic in-transaction admission for a named reference that is NOT staged in
/// this transaction (an existing static `credential_ref`): the value must
/// already be owned by exactly this (`owner_kind`, `project_root`) AND back a
/// live vault row, both verified on THIS connection (hence inside the same
/// `BEGIN IMMEDIATE` transaction as the config publish). This is the atomic
/// backstop for the pre-transaction `ensure_*_references_claimable` read: a
/// cross-process actor could release/rotate the claim (or delete the vault row)
/// between that read and this commit, so re-verifying here — under the writer
/// lock, right before publish/journal — closes the TOCTOU window. A missing
/// claim or vanished vault row fails closed as a [`NamedSecretClaimConflict`]
/// so the enclosing transaction rolls back with no config publication.
pub(crate) fn ensure_static_named_reference_owned_on_conn(
    conn: &rusqlite::Connection,
    vault: &SecretVault,
    reference: &str,
    owner_kind: &str,
    project_root: &str,
) -> anyhow::Result<()> {
    reject_conflicting_named_ownership_on_conn(conn, reference, owner_kind, project_root)?;
    let claimed: bool = conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM secret_named_ownership
             WHERE item_id = ?1 AND owner_kind = ?2 AND project_root = ?3
         )",
        rusqlite::params![reference, owner_kind, project_root],
        |row| row.get(0),
    )?;
    if !claimed {
        return Err(anyhow::Error::new(NamedSecretClaimConflict {
            item_id: reference.to_string(),
        }));
    }
    vault
        .get_item_on_conn(
            conn,
            cockpit_db::secret_vault::SecretVaultKind::NamedSecret,
            reference,
        )
        .map_err(|_| {
            anyhow::Error::new(NamedSecretClaimConflict {
                item_id: reference.to_string(),
            })
        })?;
    Ok(())
}

/// Atomic in-transaction admission for the FULL normalized MCP reference set —
/// staged names, existing static `credential_ref`s, AND flow-managed OAuth keys
/// (`mcp:<server>`) — run on the SAME connection (hence the same
/// `BEGIN IMMEDIATE` transaction) that publishes/journals the MCP config.
///
/// The pre-transaction `ensure_mcp_references_claimable` read validates the
/// same set, but a cross-process actor can interpose a foreign claim on a
/// non-staged or OAuth reference between that read and this commit (e.g.
/// workspace B stages+claims `mcp:example` after workspace A's OAuth-server
/// pre-check passes but before A commits). Because the staged-secret loop only
/// re-checks the staged names, that interposed claim would otherwise never be
/// re-examined and A would consume B's foreign secret. This guard re-checks
/// EVERY reference here:
///   * `all_refs` — every reference gets the cross-kind / foreign-owner
///     rejection. A flow-managed OAuth key that is ABSENT (no ownership row)
///     passes, keeping configure-then-authenticate permissive; only a foreign
///     or cross-kind row is rejected.
///   * `static_nonstaged_refs` — existing static references (neither staged in
///     this transaction nor flow-managed OAuth) must additionally already be
///     owned by this exact `mcp`/root and back a live vault row.
///
/// A conflict fails closed as [`NamedSecretClaimConflict`]; the enclosing
/// transaction rolls back with no config publication and no journal row.
pub(crate) fn guard_mcp_reference_ownership_on_conn(
    conn: &rusqlite::Connection,
    vault: &SecretVault,
    all_refs: &BTreeSet<String>,
    static_nonstaged_refs: &BTreeSet<String>,
    project_root: &str,
) -> anyhow::Result<()> {
    for reference in all_refs {
        reject_conflicting_named_ownership_on_conn(conn, reference, OWNER_KIND_MCP, project_root)?;
    }
    for reference in static_nonstaged_refs {
        ensure_static_named_reference_owned_on_conn(
            conn,
            vault,
            reference,
            OWNER_KIND_MCP,
            project_root,
        )?;
    }
    Ok(())
}

/// True iff `(item_id, owner_kind, project_root)` holds a claim.
pub(crate) fn owner_owns_named_reference_on_conn(
    conn: &rusqlite::Connection,
    item_id: &str,
    owner_kind: &str,
    project_root: &str,
) -> anyhow::Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM secret_named_ownership
             WHERE item_id = ?1 AND owner_kind = ?2 AND project_root = ?3
         )",
        rusqlite::params![item_id, owner_kind, project_root],
        |row| row.get::<_, bool>(0),
    )?)
}

/// True iff NO ownership row of any kind/root exists for `item_id` (a legacy,
/// unclaimed named secret that owner-scoped resolution may backfill to the
/// config that references it).
pub(crate) fn named_reference_is_unclaimed_on_conn(
    conn: &rusqlite::Connection,
    item_id: &str,
) -> anyhow::Result<bool> {
    let any: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM secret_named_ownership WHERE item_id = ?1)",
        rusqlite::params![item_id],
        |row| row.get::<_, bool>(0),
    )?;
    Ok(!any)
}

/// Whether a credential RECORD (`credential_record` vault kind, e.g. a legacy
/// `mcp:<server>` OAuth blob or a provider credential record) may resolve for a
/// workspace `project_root`, per the `secret_credential_ownership` table.
///
/// Owner-scoped resolution (gap 1) filters named `secrets` but the credential
/// `records` map was left whole, and the MCP resolution path falls back to it
/// (`store.get()`), so a legacy `mcp:victim` record owned for workspace A was
/// usable by an MCP config for `victim` in workspace B. A record resolves iff it
/// carries NO ownership row at all (a legacy unclaimed record — unchanged
/// permissive behavior, and how the Flycockpit global-account credential, which
/// is never claimed, keeps resolving), OR it has a row for exactly this
/// `project_root`. A record owned only by a DIFFERENT workspace fails closed.
/// The record ownership key is the workspace root (any `provider_id`), so this
/// is owner-kind-agnostic and protects provider records and `mcp:` records
/// alike.
pub(crate) fn credential_record_resolves_for_root_on_conn(
    conn: &rusqlite::Connection,
    item_id: &str,
    project_root: &str,
) -> anyhow::Result<bool> {
    let any_owned: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM secret_credential_ownership WHERE item_id = ?1)",
        rusqlite::params![item_id],
        |row| row.get(0),
    )?;
    if !any_owned {
        return Ok(true);
    }
    let mine: bool = conn.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM secret_credential_ownership
             WHERE item_id = ?1 AND project_root = ?2
         )",
        rusqlite::params![item_id, project_root],
        |row| row.get(0),
    )?;
    Ok(mine)
}

/// Filter a set of credential-record item ids to those that resolve for
/// `project_root` (see [`credential_record_resolves_for_root_on_conn`]), in one
/// read pass. Used by the owner-scoped credential store so its `records` view is
/// scoped the same way its `secrets` view is.
pub(crate) fn scope_credential_records(
    db: &Db,
    project_root: &str,
    record_ids: &BTreeSet<String>,
) -> anyhow::Result<BTreeSet<String>> {
    let project_root = project_root.to_string();
    let record_ids: Vec<String> = record_ids.iter().cloned().collect();
    db.blocking_read_for_sync_ui(move |conn| {
        let mut resolvable = BTreeSet::new();
        for id in &record_ids {
            if credential_record_resolves_for_root_on_conn(conn, id, &project_root)? {
                resolvable.insert(id.clone());
            }
        }
        Ok(resolvable)
    })
}

/// Backfill: claim an unclaimed reference for (`owner_kind`, `project_root`) on
/// the caller's `BEGIN IMMEDIATE` connection. Fails closed
/// ([`NamedSecretClaimConflict`]) if any foreign claim raced in first, so the
/// enclosing transaction rolls back.
pub(crate) fn claim_named_reference_on_conn(
    conn: &rusqlite::Connection,
    item_id: &str,
    owner_kind: &str,
    project_root: &str,
) -> anyhow::Result<()> {
    reject_conflicting_named_ownership_on_conn(conn, item_id, owner_kind, project_root)?;
    conn.execute(
        "INSERT OR IGNORE INTO secret_named_ownership
         (item_id, owner_kind, project_root, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            item_id,
            owner_kind,
            project_root,
            chrono::Utc::now().timestamp_millis()
        ],
    )?;
    Ok(())
}

/// Compute the set of named-secret item ids that resolve for a referencing
/// context `(owner_kind, project_root)`, backfilling legacy (unclaimed)
/// references the config actually uses — but only when this context is the
/// PROVABLE sole owner.
///
/// This is the resolution-side owner scope (gap 1). Given every named-secret id
/// currently present in the vault (`present_names`) and the subset the
/// referencing config references (`referenced_names`), a name resolves iff:
///   * it is already owned by exactly this (`owner_kind`, `project_root`), OR
///   * `foreign_scope_references` is `Some(foreign)` (the caller proved
///     sole-ownership by scanning every OTHER known config), the name is
///     referenced by this config, is prefix-legitimate for this kind
///     (`owner_kind_may_own`), is currently UNCLAIMED, and is NOT referenced by
///     any config under a different `(kind, root)` (i.e. NOT in `foreign`) — in
///     which case it is atomically backfilled to this owner and then resolves.
///
/// A name owned by a different (kind, root) is excluded (fail closed), so a
/// config owned by A can never resolve a secret owned by B.
///
/// Backfill is deterministic and SAFE against first-resolver-steals:
///   * `foreign_scope_references == None` — sole-ownership is UNPROVABLE in this
///     context (no cross-config scan is available at the boundary, e.g. the
///     session/MCP/policy resolution paths). No legacy name is ever claimed;
///     only already-owned names resolve. An unclaimed reference is left out and
///     fails closed at resolution (a `migration required` diagnostic is logged),
///     never silently forwarding a literal and never racing a foreign owner.
///   * `foreign_scope_references == Some(foreign)` — the daemon scanned every
///     durably-known config. A referenced unclaimed name is claimed ONLY when it
///     is the SOLE eligible owner (absent from `foreign`). A name ALSO referenced
///     by a different-scope config is AMBIGUOUS: it is neither claimed nor
///     resolved here (fail closed with a `migration required / ambiguous
///     ownership` diagnostic), so two different-owner configs can never race to
///     steal a shared unclaimed name, and a config cannot claim a guessed name
///     another workspace already references.
///
/// A name that already has ANY ownership row is never re-attributed (the
/// unclaimed check plus the in-transaction re-check below both fail closed).
pub(crate) fn scope_named_secret_ownership(
    db: &Db,
    owner_kind: &str,
    project_root: &str,
    present_names: &BTreeSet<String>,
    referenced_names: &BTreeSet<String>,
    foreign_scope_references: Option<&BTreeSet<String>>,
) -> anyhow::Result<BTreeSet<String>> {
    // Phase 1 (read-only): classify every present name.
    let (mut scoped, to_backfill) = {
        let owner_kind = owner_kind.to_string();
        let project_root = project_root.to_string();
        let present: Vec<String> = present_names.iter().cloned().collect();
        let referenced = referenced_names.clone();
        let foreign = foreign_scope_references.cloned();
        db.blocking_read_for_sync_ui(move |conn| {
            let mut owned = BTreeSet::new();
            let mut backfill = Vec::new();
            for name in &present {
                if owner_owns_named_reference_on_conn(conn, name, &owner_kind, &project_root)? {
                    owned.insert(name.clone());
                } else if referenced.contains(name)
                    && owner_kind_may_own(&owner_kind, name)
                    && named_reference_is_unclaimed_on_conn(conn, name)?
                {
                    // A referenced, prefix-legitimate, currently-unclaimed legacy
                    // name. Only claim it when sole-ownership is PROVABLE.
                    match &foreign {
                        Some(foreign) if !foreign.contains(name) => backfill.push(name.clone()),
                        Some(_) => tracing::warn!(
                            item_id = %name,
                            owner_kind = %owner_kind,
                            "named secret referenced by configs under multiple owners; \
                             leaving unresolved (migration required / ambiguous ownership)"
                        ),
                        None => tracing::warn!(
                            item_id = %name,
                            owner_kind = %owner_kind,
                            "unclaimed named secret cannot be proven sole-owned in this \
                             context; leaving unresolved (migration required)"
                        ),
                    }
                }
            }
            Ok((owned, backfill))
        })?
    };

    if to_backfill.is_empty() {
        return Ok(scoped);
    }

    // Phase 2 (write, only when a legacy reference needs a claim): re-check and
    // claim each candidate under the writer lock so a concurrent foreign claim
    // fails closed. Returns the names successfully attributable to this owner.
    let owner_kind_owned = owner_kind.to_string();
    let project_root_owned = project_root.to_string();
    let claimed = db.blocking_write_for_sync_maintenance(move |conn| {
        conn.execute_batch("BEGIN IMMEDIATE;")?;
        let result = (|| -> anyhow::Result<BTreeSet<String>> {
            let mut claimed = BTreeSet::new();
            for name in &to_backfill {
                if owner_owns_named_reference_on_conn(
                    conn,
                    name,
                    &owner_kind_owned,
                    &project_root_owned,
                )? {
                    // A concurrent construction already claimed it for us.
                    claimed.insert(name.clone());
                } else if named_reference_is_unclaimed_on_conn(conn, name)? {
                    claim_named_reference_on_conn(
                        conn,
                        name,
                        &owner_kind_owned,
                        &project_root_owned,
                    )?;
                    claimed.insert(name.clone());
                }
                // Else a foreign owner raced in first: leave it out (fail closed).
            }
            Ok(claimed)
        })();
        match result {
            Ok(claimed) => {
                conn.execute_batch("COMMIT;")?;
                Ok(claimed)
            }
            Err(error) => {
                let _ = conn.execute_batch("ROLLBACK;");
                Err(error)
            }
        }
    })?;
    scoped.extend(claimed);
    Ok(scoped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_owner_root_collapses_symlink_and_trailing_slash() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("workspace");
        std::fs::create_dir(&real).unwrap();
        let canonical = canonical_owner_root(&real.display().to_string());

        // The canonical form matches the authz layer's `std::fs::canonicalize`.
        assert_eq!(
            canonical,
            std::fs::canonicalize(&real).unwrap().to_string_lossy()
        );

        // A trailing slash must not change the key.
        let with_slash = format!("{}/", real.display());
        assert_eq!(canonical_owner_root(&with_slash), canonical);

        // A symlink to the same directory must resolve to the same key.
        #[cfg(unix)]
        {
            let link = tmp.path().join("link");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert_eq!(canonical_owner_root(&link.display().to_string()), canonical);
        }

        // A non-existent path falls back to a deterministic lexical key.
        assert_eq!(canonical_owner_root("/no/such/dir/"), "/no/such/dir");
    }

    #[test]
    fn claim_under_symlink_resolves_from_canonical_root() {
        // A claim written under a non-canonical spelling of a workspace resolves
        // under the canonical spelling, because every ownership path funnels
        // through `canonical_owner_root`.
        let db = crate::db::Db::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("workspace");
        std::fs::create_dir(&real).unwrap();

        // Claim via a non-canonical spelling of the workspace root.
        #[cfg(unix)]
        let claim_spelling = {
            let link = tmp.path().join("link");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            link.display().to_string()
        };
        #[cfg(not(unix))]
        let claim_spelling = format!("{}/", real.display());

        let claim_root = canonical_owner_root(&claim_spelling);
        {
            let claim_root = claim_root.clone();
            db.blocking_write_for_sync_maintenance(move |conn| {
                conn.execute_batch("BEGIN IMMEDIATE;")?;
                claim_named_reference_on_conn(conn, "openai", OWNER_KIND_PROVIDER, &claim_root)?;
                conn.execute_batch("COMMIT;")?;
                Ok(())
            })
            .unwrap();
        }

        // Resolve via the canonical (real) spelling of the same workspace.
        let resolve_root = canonical_owner_root(&real.display().to_string());
        assert_eq!(
            claim_root, resolve_root,
            "both spellings map to one canonical key"
        );
        let owns = db
            .blocking_read_for_sync_ui(move |conn| {
                owner_owns_named_reference_on_conn(
                    conn,
                    "openai",
                    OWNER_KIND_PROVIDER,
                    &resolve_root,
                )
            })
            .unwrap();
        assert!(
            owns,
            "a claim under the symlink spelling resolves canonically"
        );
    }
}
