//! Daemon-owned, in-memory sealed-owner capability table.
//!
//! The library core (`crate::sealed::owner`) mints a [`OneUseCapability`] but is
//! deliberately session-unaware: a capability records only its owner principal,
//! bound operation, and mint time. The *connection identity* a capability was
//! minted in — the applying session — lives here, in the daemon, alongside the
//! capability it belongs to.
//!
//! `BeginSealedOwnerOperation` inserts a freshly minted capability bound to the
//! minting connection's `client_instance_id`. `Apply`/`Cancel` look it up by
//! opaque id, enforce that the *current* connection is the same one that minted
//! it (a capability minted in connection A can never be applied or cancelled
//! from connection B — fail closed, without spending the capability), and then
//! drive the shared compare-and-swap.
//!
//! In-memory only: a daemon restart drops every outstanding capability
//! (fail-closed), and no minted capability or literal is ever written to disk.

use std::collections::HashMap;

use uuid::Uuid;

use crate::sealed::owner::OneUseCapability;

/// One stored capability plus the connection identity it was minted in.
#[derive(Clone)]
pub(crate) struct StoredSealedCapability {
    pub capability: OneUseCapability,
    /// The `client_instance_id` of the connection that minted this capability.
    /// Apply/Cancel from any other connection is rejected fail-closed.
    pub minting_session: Uuid,
}

/// Hard ceiling on outstanding (unspent, unexpired) sealed-owner capabilities.
///
/// The sealed-owner channel is an interactive, one-operation-at-a-time surface;
/// a handful of concurrent begins is the realistic maximum. This cap keeps a
/// runaway or buggy owner client from growing the in-memory table without bound
/// (a local-owner denial of service) — pruning alone reclaims only *spent* and
/// *expired* entries, so it is cleanup, not a bound. When the table is full of
/// still-valid capabilities, a new `begin` fails closed until some are applied,
/// cancelled, or expire.
pub(crate) const MAX_OUTSTANDING_SEALED_OWNER_CAPABILITIES: usize = 128;

/// The daemon's in-memory sealed-owner capability table.
#[derive(Default)]
pub(crate) struct SealedOwnerCapabilityTable {
    entries: HashMap<Uuid, StoredSealedCapability>,
}

impl SealedOwnerCapabilityTable {
    /// Insert a freshly minted capability bound to its minting connection.
    ///
    /// Consumed or expired entries are evicted first. Returns `false` WITHOUT
    /// inserting when the table is already at
    /// [`MAX_OUTSTANDING_SEALED_OWNER_CAPABILITIES`] live entries after that
    /// prune — the caller must then fail the `begin` closed. The just-minted
    /// capability is dropped (never stored), so it can never be applied.
    #[must_use]
    pub fn insert(
        &mut self,
        capability: OneUseCapability,
        minting_session: Uuid,
        now_ms: i64,
    ) -> bool {
        self.prune(now_ms);
        if self.entries.len() >= MAX_OUTSTANDING_SEALED_OWNER_CAPABILITIES {
            return false;
        }
        self.entries.insert(
            capability.capability_id(),
            StoredSealedCapability {
                capability,
                minting_session,
            },
        );
        true
    }

    /// Look up a stored capability by id without removing it.
    ///
    /// Returns a clone; the capability's single-use flag is an `Arc<AtomicBool>`,
    /// so consuming the returned clone consumes the stored capability through the
    /// same compare-and-swap.
    pub fn get(&self, capability_id: Uuid) -> Option<StoredSealedCapability> {
        self.entries.get(&capability_id).cloned()
    }

    /// Remove a capability by id. Called once it is spent (applied or cancelled)
    /// or when a fatal lookup determines it will never be usable.
    pub fn remove(&mut self, capability_id: Uuid) {
        self.entries.remove(&capability_id);
    }

    /// Number of live entries. Test/inspection surface.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    fn prune(&mut self, now_ms: i64) {
        self.entries.retain(|_, entry| {
            !entry.capability.is_consumed() && !entry.capability.is_expired(now_ms)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed::identity::{
        SealedDescription, SealedName, SealedProjectKey, SealedScopeRef,
    };
    use crate::sealed::owner::{CAPABILITY_TTL_MS, OneUseCapability, SensitiveOwnerOperation};

    fn craft_capability(minted_at_ms: i64) -> OneUseCapability {
        let op = SensitiveOwnerOperation::create(
            SealedScopeRef::Project(SealedProjectKey::from_canonical("proj")),
            SealedName::canonical("token").unwrap(),
            SealedDescription::parse("a deploy token").unwrap(),
        );
        OneUseCapability::craft(op, "owner", minted_at_ms)
    }

    #[test]
    fn stores_and_returns_minting_session() {
        let mut table = SealedOwnerCapabilityTable::default();
        let session = Uuid::new_v4();
        let cap = craft_capability(1_000);
        let id = cap.capability_id();
        assert!(table.insert(cap, session, 1_000));
        assert_eq!(table.len(), 1);
        let stored = table.get(id).expect("capability present");
        assert_eq!(
            stored.minting_session, session,
            "the table must return the exact minting session it stored"
        );
        table.remove(id);
        assert!(table.get(id).is_none(), "removed entry is gone");
    }

    #[test]
    fn insert_evicts_consumed_and_expired_entries() {
        let mut table = SealedOwnerCapabilityTable::default();
        // A consumed capability is pruned on the next insert.
        let consumed = craft_capability(1_000);
        let consumed_id = consumed.capability_id();
        assert!(table.insert(consumed.clone(), Uuid::new_v4(), 1_000));
        assert!(consumed.cancel(), "consume via the shared compare-and-swap");

        // An expired capability (minted at 2_000, past its TTL by the insert
        // clock below) is pruned too.
        let expired = craft_capability(2_000);
        let expired_id = expired.capability_id();
        assert!(table.insert(expired, Uuid::new_v4(), 2_000));

        // Insert a fresh, still-valid capability at a clock past the expired
        // one's TTL but within the fresh one's own window.
        let now = 2_000 + CAPABILITY_TTL_MS + 1;
        let fresh = craft_capability(now);
        let fresh_id = fresh.capability_id();
        assert!(table.insert(fresh, Uuid::new_v4(), now));

        assert!(table.get(consumed_id).is_none(), "consumed entry evicted");
        assert!(table.get(expired_id).is_none(), "expired entry evicted");
        assert!(table.get(fresh_id).is_some(), "fresh entry retained");
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn insert_is_bounded_and_fails_closed_when_full() {
        let mut table = SealedOwnerCapabilityTable::default();
        // Fill the table to its hard ceiling with still-valid capabilities.
        for _ in 0..MAX_OUTSTANDING_SEALED_OWNER_CAPABILITIES {
            assert!(table.insert(craft_capability(1_000), Uuid::new_v4(), 1_000));
        }
        assert_eq!(table.len(), MAX_OUTSTANDING_SEALED_OWNER_CAPABILITIES);

        // A further insert of a still-valid capability is refused (fail closed);
        // the just-minted capability is dropped, never stored.
        let overflow = craft_capability(1_000);
        let overflow_id = overflow.capability_id();
        assert!(
            !table.insert(overflow, Uuid::new_v4(), 1_000),
            "a full table must refuse a new capability"
        );
        assert!(table.get(overflow_id).is_none(), "refused entry not stored");
        assert_eq!(table.len(), MAX_OUTSTANDING_SEALED_OWNER_CAPABILITIES);

        // Once outstanding capabilities expire, the prune on the next insert
        // reclaims room and a fresh capability is admitted again.
        let later = 1_000 + CAPABILITY_TTL_MS + 1;
        let admitted = craft_capability(later);
        let admitted_id = admitted.capability_id();
        assert!(table.insert(admitted, Uuid::new_v4(), later));
        assert!(
            table.get(admitted_id).is_some(),
            "space reclaimed after expiry"
        );
        assert_eq!(table.len(), 1);
    }
}
