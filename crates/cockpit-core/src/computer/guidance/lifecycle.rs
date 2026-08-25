//! Daemon-memory custody for pending computer-use guidance proposals.
//!
//! Authoritative contract: `prompts/flycockpitapp/complete/
//! computer-use-guidance-proposals.md` (§ lifecycle). Typed proposal values and
//! the optional rationale live **in daemon memory only** — they are never
//! persisted. This module owns exactly that memory half of the lifecycle:
//!
//! - at most one pending proposal per
//!   `(session, delegation, canonical project, provider, model)` scope
//!   (a concurrent create loses with [`ProposalReserveError::AlreadyPending`],
//!   surfaced to the model as `proposal_already_pending`);
//! - injected-clock expiry ten minutes ([`super::PROPOSAL_EXPIRY_SECS`]) after
//!   creation;
//! - drop of typed values + rationale on accept / reject / expiry, and on any
//!   delegation/session terminal state or project/provider/model/
//!   config-generation change (whichever occurs first).
//!
//! What this module deliberately does NOT own (it belongs to the durable half,
//! landed separately once the audit writer + `0001` receipt schema exist): the
//! content-free `guidance_proposal_receipt`, the durable 3-per-delegation /
//! 10-per-session creation counters, the audit-event append, and the startup
//! `expired_on_restart` reconciliation. Quota is authoritative in the durable
//! layer precisely because memory is lost on restart; this store never counts
//! quota.
//!
//! ## Ordering the durable orchestrator must follow
//!
//! The store is single-owner (`&mut self`); the daemon coordinator that holds it
//! is the serialization point, so create-vs-create races are ordered and the
//! second observes the first. The two-phase surface makes the contract's
//! ordering explicit so no durable write can be wasted and no memory record can
//! be dropped before its durable transition succeeds:
//!
//! - **Create.** [`reserve`](PendingProposalStore::reserve) the scope FIRST
//!   (fails `AlreadyPending` without any durable work). Then commit the durable
//!   `guidance_proposal_receipt` + counters + `guidance_proposal_created` in one
//!   transaction. Only after commit [`install`](PendingProposalStore::install)
//!   the typed values + rationale; on durable failure
//!   [`release`](PendingProposalStore::release) the reservation.
//! - **Accept / reject.** Read the values with [`get`](PendingProposalStore::get)
//!   (accept compiles the rules), commit the durable CAS to `accepted|rejected`
//!   + the matching audit event, then
//!   [`remove_committed`](PendingProposalStore::remove_committed) — an
//!   id-conditional removal that only drops memory after the durable transition.
//! - **Expiry / invalidation.** Enumerate non-mutating
//!   [`expired_candidates`](PendingProposalStore::expired_candidates) /
//!   [`invalidation_candidates`](PendingProposalStore::invalidation_candidates),
//!   commit each durable CAS + audit, then `remove_committed`. A durable failure
//!   leaves the memory record intact and the transition retryable. An
//!   invalidation sweep MUST also cancel any in-flight reservation for an
//!   affected scope via [`reserved_candidates`](PendingProposalStore::reserved_candidates)
//!   + [`release`](PendingProposalStore::release): the racing
//!   [`install`](PendingProposalStore::install) then fails closed
//!   ([`ProposalInstallError::NotReserved`]), so memory is never restored for a
//!   scope that was invalidated mid-create.
//!
//! The `proposal_id` is the reservation capability: [`reserve`], [`install`],
//! [`release`], and [`remove_committed`] are all id-conditional, so a stale or
//! duplicate cleanup from one create can never disturb a later reservation or
//! proposal that reused the same scope.

use std::collections::HashMap;

use super::{ComputerGuidanceRuleV1, PROPOSAL_EXPIRY_SECS};

/// A proposal identifier (a 16-byte UUID in network-order bytes, matching the
/// receipt/audit `proposal_id`). Opaque to this module — used for equality and
/// to name a proposal back to the durable orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProposalId(pub [u8; 16]);

/// The exact scope a pending proposal is keyed by. Mirrors the durable
/// receipt/audit scope: the session and delegation identities plus the three
/// opaque scope digests (`canonical_project_digest` / `provider_digest` /
/// `model_digest`, each a SHA-256). At most one pending proposal (or in-flight
/// reservation) may exist per distinct key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProposalScopeKey {
    /// Session UUID, network-order bytes.
    pub session_id: [u8; 16],
    /// Delegation UUID, network-order bytes.
    pub delegation_id: [u8; 16],
    /// Canonical machine-local project identity digest.
    pub project_digest: [u8; 32],
    /// Provider identity digest.
    pub provider_digest: [u8; 32],
    /// Model identity digest.
    pub model_digest: [u8; 32],
}

/// A pending proposal's memory-only contents: the typed rules and the optional
/// rationale, plus the injected-clock timestamps. `rationale` is inert plain
/// text and is dropped (with the whole record) the instant the proposal leaves
/// the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingProposal {
    /// The proposal identity (also lives in the durable receipt).
    pub proposal_id: ProposalId,
    /// One to six unique typed rules (validated by the caller before install).
    pub rules: Vec<ComputerGuidanceRuleV1>,
    /// Optional inert-plaintext rationale. Memory-only; never persisted.
    pub rationale: Option<String>,
    /// Injected-clock creation time (seconds).
    pub created_at: i64,
    /// Absolute expiry time (seconds): `created_at + PROPOSAL_EXPIRY_SECS`.
    pub expires_at: i64,
}

impl PendingProposal {
    /// True when `now` (injected clock, seconds) is at or past the expiry.
    pub fn is_expired_at(&self, now: i64) -> bool {
        now >= self.expires_at
    }
}

/// A pending proposal named for a lifecycle transition, WITHOUT removing it.
/// The durable orchestrator commits the transition for `proposal_id`, then calls
/// [`PendingProposalStore::remove_committed`] with this `(key, proposal_id)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalCandidate {
    /// The scope the proposal occupies.
    pub key: ProposalScopeKey,
    /// The proposal identity to commit and then remove.
    pub proposal_id: ProposalId,
}

/// Failure to reserve a scope for a new proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalReserveError {
    /// The scope already holds a pending proposal or an in-flight reservation.
    /// Surfaced to the model as `proposal_already_pending`.
    AlreadyPending,
}

impl ProposalReserveError {
    /// The stable model-facing reason string.
    pub fn wire_reason(self) -> &'static str {
        match self {
            ProposalReserveError::AlreadyPending => "proposal_already_pending",
        }
    }
}

/// Failure to install values into a reserved scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalInstallError {
    /// No reservation exists for the scope. `install` must follow a successful
    /// [`PendingProposalStore::reserve`] for the same key (protocol violation).
    NotReserved,
}

/// In-memory custody of the currently pending proposals, one per scope, plus the
/// in-flight reservations that occupy a scope during a create transaction.
///
/// Single-owner: the daemon coordinator holds it behind `&mut`, which is the
/// serialization point for create-vs-create races. This store holds ONLY
/// memory-resident typed values + rationale; it never persists and never counts
/// durable quota.
#[derive(Debug, Default)]
pub struct PendingProposalStore {
    /// Scopes reserved by an in-flight create whose durable transaction has not
    /// yet committed, mapped to the reserving `proposal_id` (the reservation
    /// capability). They occupy the scope (block a second create) but carry no
    /// values.
    reserved: HashMap<ProposalScopeKey, ProposalId>,
    /// Installed pending proposals (values committed durably, now memory-resident).
    pending: HashMap<ProposalScopeKey, PendingProposal>,
}

impl PendingProposalStore {
    /// A store with no proposals and no reservations.
    pub fn new() -> Self {
        Self {
            reserved: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Number of installed pending proposals. NOT a quota count — quota is
    /// durable and independent of how many are memory-resident.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// True when no proposal is installed. (Reservations may still be in flight.)
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// True when an installed pending proposal exists for `key`.
    pub fn contains(&self, key: &ProposalScopeKey) -> bool {
        self.pending.contains_key(key)
    }

    /// True when `key` is occupied by an installed proposal OR an in-flight
    /// reservation — the exact condition [`Self::reserve`] rejects.
    pub fn is_scope_occupied(&self, key: &ProposalScopeKey) -> bool {
        self.reserved.contains_key(key) || self.pending.contains_key(key)
    }

    /// Borrow the installed pending proposal for `key`, if any (for the review UI
    /// to render typed values + inert rationale, or accept to read the rules to
    /// compile). Does not remove it.
    pub fn get(&self, key: &ProposalScopeKey) -> Option<&PendingProposal> {
        self.pending.get(key)
    }

    /// Reserve `key` under `proposal_id` for a new proposal, BEFORE the durable
    /// create transaction. Atomically enforces one pending per scope: fails
    /// [`ProposalReserveError::AlreadyPending`] if the scope already holds a
    /// proposal or a reservation, so the caller performs no wasted durable work.
    /// On success the scope is occupied until [`Self::install`] (success) or
    /// [`Self::release`] (durable failure or mid-create invalidation). The
    /// `proposal_id` is the capability that [`Self::install`]/[`Self::release`]
    /// must present.
    pub fn reserve(
        &mut self,
        key: ProposalScopeKey,
        proposal_id: ProposalId,
    ) -> Result<(), ProposalReserveError> {
        if self.is_scope_occupied(&key) {
            return Err(ProposalReserveError::AlreadyPending);
        }
        self.reserved.insert(key, proposal_id);
        Ok(())
    }

    /// Release the reservation for `key` held under `proposal_id` — on durable
    /// create failure or when an invalidation cancels an in-flight create.
    /// Id-conditional: frees the scope ONLY if the current reservation's id
    /// matches, so a stale release can never cancel a later create's
    /// reservation for the same scope. Returns whether a matching reservation
    /// was released.
    pub fn release(&mut self, key: &ProposalScopeKey, proposal_id: ProposalId) -> bool {
        match self.reserved.get(key) {
            Some(id) if *id == proposal_id => {
                self.reserved.remove(key);
                true
            }
            _ => false,
        }
    }

    /// Install typed values + rationale into a scope reserved under
    /// `proposal_id`, AFTER the durable create transaction has committed. Fails
    /// [`ProposalInstallError::NotReserved`] (installing nothing) if the scope
    /// has no reservation or its reservation was made under a different id — the
    /// latter is exactly how a mid-create invalidation (which
    /// [`Self::release`]d the reservation) makes this install fail closed rather
    /// than restore memory for an invalidated scope. Expiry is derived as
    /// `created_at + PROPOSAL_EXPIRY_SECS` from the injected clock.
    pub fn install(
        &mut self,
        key: ProposalScopeKey,
        proposal_id: ProposalId,
        rules: Vec<ComputerGuidanceRuleV1>,
        rationale: Option<String>,
        created_at: i64,
    ) -> Result<(), ProposalInstallError> {
        match self.reserved.get(&key) {
            Some(id) if *id == proposal_id => {
                self.reserved.remove(&key);
            }
            _ => return Err(ProposalInstallError::NotReserved),
        }
        self.pending.insert(
            key,
            PendingProposal {
                proposal_id,
                rules,
                rationale,
                created_at,
                expires_at: created_at.saturating_add(PROPOSAL_EXPIRY_SECS),
            },
        );
        Ok(())
    }

    /// Remove an installed proposal AFTER its durable transition (accept / reject
    /// / expiry / invalidation) has committed. Id-conditional: removes and
    /// returns the record ONLY if a pending proposal exists for `key` and its
    /// `proposal_id` equals `expected_id`; otherwise the store is untouched and
    /// this returns `None` (a duplicate removal, or a scope since replaced by a
    /// different proposal, is a safe no-op). The returned record — including the
    /// rationale — is gone from memory when this returns.
    pub fn remove_committed(
        &mut self,
        key: &ProposalScopeKey,
        expected_id: ProposalId,
    ) -> Option<PendingProposal> {
        match self.pending.get(key) {
            Some(proposal) if proposal.proposal_id == expected_id => self.pending.remove(key),
            _ => None,
        }
    }

    /// Non-mutating enumeration of every installed proposal whose injected-clock
    /// expiry has passed (`now >= expires_at`). The orchestrator commits each
    /// `guidance_proposal_expired` CAS + audit, then calls
    /// [`Self::remove_committed`]; nothing is dropped here.
    pub fn expired_candidates(&self, now: i64) -> Vec<ProposalCandidate> {
        self.pending
            .iter()
            .filter(|(_, proposal)| proposal.is_expired_at(now))
            .map(|(key, proposal)| ProposalCandidate {
                key: key.clone(),
                proposal_id: proposal.proposal_id,
            })
            .collect()
    }

    /// Non-mutating enumeration of every installed proposal whose scope matches
    /// `predicate` — used for a delegation/session terminal state or a
    /// project/provider/model/config-generation change (the caller supplies the
    /// predicate identifying the affected scopes). The orchestrator commits each
    /// transition, then calls [`Self::remove_committed`]; nothing is dropped here.
    pub fn invalidation_candidates(
        &self,
        predicate: impl Fn(&ProposalScopeKey) -> bool,
    ) -> Vec<ProposalCandidate> {
        self.pending
            .iter()
            .filter(|(key, _)| predicate(key))
            .map(|(key, proposal)| ProposalCandidate {
                key: key.clone(),
                proposal_id: proposal.proposal_id,
            })
            .collect()
    }

    /// Non-mutating enumeration of every IN-FLIGHT reservation whose scope
    /// matches `predicate` — the reserved counterpart to
    /// [`Self::invalidation_candidates`]. An invalidation sweep enumerates these
    /// and [`Self::release`]s each so a create whose durable transaction is
    /// still in flight cannot later [`Self::install`] memory for a scope that was
    /// invalidated mid-create (the id-conditional install then fails closed).
    pub fn reserved_candidates(
        &self,
        predicate: impl Fn(&ProposalScopeKey) -> bool,
    ) -> Vec<ProposalCandidate> {
        self.reserved
            .iter()
            .filter(|(key, _)| predicate(key))
            .map(|(key, proposal_id)| ProposalCandidate {
                key: key.clone(),
                proposal_id: *proposal_id,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::computer::guidance::ObservationCadence;

    fn key(session: u8, delegation: u8, project: u8, provider: u8, model: u8) -> ProposalScopeKey {
        ProposalScopeKey {
            session_id: [session; 16],
            delegation_id: [delegation; 16],
            project_digest: [project; 32],
            provider_digest: [provider; 32],
            model_digest: [model; 32],
        }
    }

    fn rule() -> ComputerGuidanceRuleV1 {
        ComputerGuidanceRuleV1::ObservationCadence(ObservationCadence::BeforeEachAction)
    }

    /// Create flow: reserve → (durable commit) → install → get.
    #[test]
    fn reserve_then_install_makes_values_readable_with_derived_expiry() {
        let mut store = PendingProposalStore::new();
        let k = key(1, 2, 3, 4, 5);
        store
            .reserve(k.clone(), ProposalId([9; 16]))
            .expect("first reserve wins");
        assert!(store.is_scope_occupied(&k));
        assert!(!store.contains(&k), "reserved but not yet installed");

        store
            .install(
                k.clone(),
                ProposalId([9; 16]),
                vec![rule()],
                Some("why".into()),
                100,
            )
            .expect("install after durable commit");
        let p = store.get(&k).expect("installed");
        assert_eq!(p.rationale.as_deref(), Some("why"));
        assert_eq!(p.expires_at, 100 + PROPOSAL_EXPIRY_SECS);
    }

    #[test]
    fn reserve_rejects_a_second_create_for_the_same_scope() {
        let mut store = PendingProposalStore::new();
        let k = key(1, 2, 3, 4, 5);
        store
            .reserve(k.clone(), ProposalId([1; 16]))
            .expect("first reserve wins");
        // A second reserve loses BEFORE any durable work — even under a new id.
        let err = store
            .reserve(k.clone(), ProposalId([2; 16]))
            .expect_err("second reserve loses");
        assert_eq!(err, ProposalReserveError::AlreadyPending);
        assert_eq!(err.wire_reason(), "proposal_already_pending");

        // Still rejected once installed.
        store
            .install(k.clone(), ProposalId([1; 16]), vec![rule()], None, 0)
            .unwrap();
        assert_eq!(
            store.reserve(k.clone(), ProposalId([3; 16])),
            Err(ProposalReserveError::AlreadyPending)
        );
    }

    #[test]
    fn release_is_id_conditional_and_frees_the_scope() {
        let mut store = PendingProposalStore::new();
        let k = key(1, 2, 3, 4, 5);
        store.reserve(k.clone(), ProposalId([9; 16])).unwrap();
        // A stale release under the wrong id does nothing.
        assert!(!store.release(&k, ProposalId([8; 16])));
        assert!(store.is_scope_occupied(&k));
        // The matching id frees it.
        assert!(
            store.release(&k, ProposalId([9; 16])),
            "reservation released"
        );
        assert!(!store.is_scope_occupied(&k));
        // A later create may now proceed.
        store
            .reserve(k.clone(), ProposalId([1; 16]))
            .expect("scope is free again");
    }

    #[test]
    fn install_without_reservation_or_with_wrong_id_is_rejected() {
        let mut store = PendingProposalStore::new();
        let k = key(1, 2, 3, 4, 5);
        // No reservation at all.
        assert_eq!(
            store.install(k.clone(), ProposalId([1; 16]), vec![rule()], None, 0),
            Err(ProposalInstallError::NotReserved)
        );
        // Reserved under a different id: install fails closed, installs nothing.
        store.reserve(k.clone(), ProposalId([1; 16])).unwrap();
        assert_eq!(
            store.install(k.clone(), ProposalId([2; 16]), vec![rule()], None, 0),
            Err(ProposalInstallError::NotReserved)
        );
        assert!(!store.contains(&k));
        // The original reservation survives the mismatched install.
        assert!(store.is_scope_occupied(&k));
    }

    /// A terminal/config-change event arriving between `reserve` and `install`
    /// is addressable: the invalidation sweep releases the in-flight reservation,
    /// and the racing install then fails closed rather than restoring memory for
    /// an invalidated scope.
    #[test]
    fn mid_create_invalidation_releases_reservation_and_install_fails_closed() {
        let mut store = PendingProposalStore::new();
        let k = key(7, 2, 3, 4, 5);
        store.reserve(k.clone(), ProposalId([9; 16])).unwrap();

        // Invalidation targets session 7: it finds the in-flight reservation...
        let reserved = store.reserved_candidates(|k| k.session_id == [7; 16]);
        assert_eq!(reserved.len(), 1);
        assert_eq!(reserved[0].proposal_id, ProposalId([9; 16]));
        // ...and releases it.
        assert!(store.release(&reserved[0].key, reserved[0].proposal_id));

        // The create's durable commit lands late and tries to install: fails closed.
        assert_eq!(
            store.install(k.clone(), ProposalId([9; 16]), vec![rule()], None, 0),
            Err(ProposalInstallError::NotReserved)
        );
        assert!(
            !store.contains(&k),
            "no memory restored for an invalidated scope"
        );
    }

    /// remove_committed drops memory only after the durable transition, and is
    /// id-conditional so a duplicate/stale removal is a safe no-op.
    #[test]
    fn remove_committed_is_id_conditional_and_idempotent() {
        let mut store = PendingProposalStore::new();
        let k = key(1, 2, 3, 4, 5);
        store.reserve(k.clone(), ProposalId([9; 16])).unwrap();
        store
            .install(
                k.clone(),
                ProposalId([9; 16]),
                vec![rule()],
                Some("r".into()),
                0,
            )
            .unwrap();

        // Wrong id: nothing removed.
        assert!(store.remove_committed(&k, ProposalId([8; 16])).is_none());
        assert!(store.contains(&k), "stale id must not drop the incumbent");

        // Correct id: removed exactly once.
        let removed = store
            .remove_committed(&k, ProposalId([9; 16]))
            .expect("matching id removes");
        assert_eq!(removed.rationale.as_deref(), Some("r"));
        assert!(!store.contains(&k));
        // Duplicate removal is a no-op.
        assert!(store.remove_committed(&k, ProposalId([9; 16])).is_none());
    }

    #[test]
    fn expired_candidates_enumerate_without_mutating_at_the_boundary() {
        let mut store = PendingProposalStore::new();
        let k = key(1, 1, 1, 1, 1);
        store.reserve(k.clone(), ProposalId([1; 16])).unwrap();
        store
            .install(
                k.clone(),
                ProposalId([1; 16]),
                vec![rule()],
                Some("r".into()),
                0,
            )
            .unwrap();

        // One second before expiry: no candidates, nothing removed.
        assert!(
            store
                .expired_candidates(PROPOSAL_EXPIRY_SECS - 1)
                .is_empty()
        );
        assert!(store.contains(&k));

        // Exactly at expiry: enumerated but NOT removed (non-mutating).
        let due = store.expired_candidates(PROPOSAL_EXPIRY_SECS);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].proposal_id, ProposalId([1; 16]));
        assert!(store.contains(&k), "enumeration must not drop the record");

        // Orchestrator commits the durable expiry, then removes.
        assert!(
            store
                .remove_committed(&due[0].key, due[0].proposal_id)
                .is_some()
        );
        assert!(store.is_empty());
    }

    #[test]
    fn invalidation_candidates_select_only_matching_scopes() {
        let mut store = PendingProposalStore::new();
        for (session, id) in [(7u8, 1u8), (8, 2)] {
            let k = key(session, 2, 3, 4, 5);
            store.reserve(k.clone(), ProposalId([id; 16])).unwrap();
            store
                .install(k, ProposalId([id; 16]), vec![rule()], None, 0)
                .unwrap();
        }
        let matched = store.invalidation_candidates(|k| k.session_id == [7; 16]);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].proposal_id, ProposalId([1; 16]));
        // Non-matching scope untouched by enumeration.
        assert!(store.contains(&key(8, 2, 3, 4, 5)));
    }
}
