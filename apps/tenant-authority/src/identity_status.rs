//! Signer-owned identity-status table.
//!
//! Keyed by exact `(tenantId,authorityId,subjectKind,subjectId,generation)`
//! and stores internal `active|superseded|revoked`, authority epoch, subject
//! state generation, and safe timestamps, with exactly one active generation
//! per subject. A successful `AuthorizeDeviceEnrollmentV1(action=enroll)`
//! reserve/finalize transaction atomically inserts the one `active` row with
//! the authorization result; the proposed subject supplies no FCTV. A
//! successful `action=rotate` commit atomically CAS-closes the old active row
//! as `superseded`, inserts the exact next active generation, and finalizes
//! the same FCTO/audit/outbox; partial transition is impossible. Operation 10
//! emits external `revoked` for a known superseded generation, never active,
//! while unknown/wrong-scope remains non-enumerating.

pub use cockpit_proto::remote_identity_protocol::SubjectKind;

/// Internal identity-status row state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityStatusState {
    Active,
    Superseded,
    Revoked,
}

/// One identity-status record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityStatusRecord {
    pub tenant_id: [u8; 16],
    pub authority_id: [u8; 16],
    pub subject_kind: SubjectKind,
    pub subject_id: [u8; 16],
    pub generation: u64,
    pub state: IdentityStatusState,
    pub authority_epoch: u64,
    pub subject_state_generation: u64,
    pub recorded_at: i64,
}

impl IdentityStatusRecord {
    /// The exact key `(tenantId,authorityId,subjectKind,subjectId,generation)`.
    pub fn key(&self) -> ([u8; 16], [u8; 16], SubjectKind, [u8; 16], u64) {
        (
            self.tenant_id,
            self.authority_id,
            self.subject_kind,
            self.subject_id,
            self.generation,
        )
    }
}

/// In-memory identity-status table for unit/state-machine tests. Production
/// persistence is PostgreSQL with `SERIALIZABLE` transactions and generation
/// preconditions; this pure table exercises the same CAS transitions.
#[derive(Debug, Default)]
pub struct IdentityStatusTable {
    rows: Vec<IdentityStatusRecord>,
}

impl IdentityStatusTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically insert the one `active` row for an enroll. The proposed
    /// subject supplies no FCTV. Partial transition is impossible.
    pub fn enroll(&mut self, record: IdentityStatusRecord) -> Result<(), IdentityStatusError> {
        if record.state != IdentityStatusState::Active {
            return Err(IdentityStatusError::InvalidInitialState);
        }
        if self
            .rows
            .iter()
            .any(|r| r.key() == record.key() && r.state == IdentityStatusState::Active)
        {
            return Err(IdentityStatusError::AlreadyActive);
        }
        // exactly one active generation per subject.
        let subject_active = self.rows.iter().any(|r| {
            r.tenant_id == record.tenant_id
                && r.authority_id == record.authority_id
                && r.subject_kind == record.subject_kind
                && r.subject_id == record.subject_id
                && r.state == IdentityStatusState::Active
        });
        if subject_active {
            return Err(IdentityStatusError::AlreadyActive);
        }
        self.rows.push(record);
        Ok(())
    }

    /// Atomically CAS-close the old active row as `superseded` and insert the
    /// next active generation. Partial transition is impossible.
    pub fn rotate(
        &mut self,
        tenant_id: [u8; 16],
        authority_id: [u8; 16],
        subject_kind: SubjectKind,
        subject_id: [u8; 16],
        old_generation: u64,
        new_record: IdentityStatusRecord,
    ) -> Result<(), IdentityStatusError> {
        if new_record.state != IdentityStatusState::Active {
            return Err(IdentityStatusError::InvalidInitialState);
        }
        if new_record.generation <= old_generation {
            return Err(IdentityStatusError::GenerationRollback);
        }
        let old_idx = self.rows.iter().position(|r| {
            r.tenant_id == tenant_id
                && r.authority_id == authority_id
                && r.subject_kind == subject_kind
                && r.subject_id == subject_id
                && r.generation == old_generation
                && r.state == IdentityStatusState::Active
        });
        let Some(idx) = old_idx else {
            return Err(IdentityStatusError::OldGenerationNotFound);
        };
        // CAS: close old as superseded, insert next active, atomically.
        self.rows[idx].state = IdentityStatusState::Superseded;
        self.rows.push(new_record);
        Ok(())
    }

    /// Operation 11: CAS-transition a row `active` to `revoked`, increment
    /// state generation. Returns the updated record.
    pub fn revoke(
        &mut self,
        tenant_id: [u8; 16],
        authority_id: [u8; 16],
        subject_kind: SubjectKind,
        subject_id: [u8; 16],
        generation: u64,
        at: i64,
    ) -> Result<IdentityStatusRecord, IdentityStatusError> {
        let idx = self.rows.iter().position(|r| {
            r.tenant_id == tenant_id
                && r.authority_id == authority_id
                && r.subject_kind == subject_kind
                && r.subject_id == subject_id
                && r.generation == generation
        });
        let Some(idx) = idx else {
            // Unknown/wrong-generation/cross-scope rows are the same
            // non-enumerating error.
            return Err(IdentityStatusError::NotFound);
        };
        if self.rows[idx].state != IdentityStatusState::Active {
            return Err(IdentityStatusError::NotActive);
        }
        self.rows[idx].state = IdentityStatusState::Revoked;
        self.rows[idx].subject_state_generation += 1;
        self.rows[idx].recorded_at = at;
        Ok(self.rows[idx].clone())
    }

    /// Load a row for operation 10 (identity-revocation-status). Operation 10
    /// emits external `revoked` for a known superseded generation, never
    /// active; unknown/wrong-scope remains non-enumerating.
    pub fn load_for_status(
        &self,
        tenant_id: [u8; 16],
        authority_id: [u8; 16],
        subject_kind: SubjectKind,
        subject_id: [u8; 16],
        generation: u64,
    ) -> Result<&IdentityStatusRecord, IdentityStatusError> {
        self.rows
            .iter()
            .find(|r| {
                r.tenant_id == tenant_id
                    && r.authority_id == authority_id
                    && r.subject_kind == subject_kind
                    && r.subject_id == subject_id
                    && r.generation == generation
            })
            .ok_or(IdentityStatusError::NotFound)
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityStatusError {
    #[error("invalid initial state")]
    InvalidInitialState,
    #[error("subject already active")]
    AlreadyActive,
    #[error("old generation not found")]
    OldGenerationNotFound,
    #[error("generation rollback")]
    GenerationRollback,
    #[error("not found (non-enumerating)")]
    NotFound,
    #[error("row not active")]
    NotActive,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(generation: u64, state: IdentityStatusState) -> IdentityStatusRecord {
        IdentityStatusRecord {
            tenant_id: [1; 16],
            authority_id: [2; 16],
            subject_kind: SubjectKind::Client,
            subject_id: [3; 16],
            generation,
            state,
            authority_epoch: 1,
            subject_state_generation: 0,
            recorded_at: 1,
        }
    }

    #[test]
    fn enroll_inserts_one_active() {
        let mut t = IdentityStatusTable::new();
        t.enroll(rec(1, IdentityStatusState::Active)).unwrap();
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn enroll_rejects_second_active() {
        let mut t = IdentityStatusTable::new();
        t.enroll(rec(1, IdentityStatusState::Active)).unwrap();
        assert!(t.enroll(rec(2, IdentityStatusState::Active)).is_err());
    }

    #[test]
    fn rotate_supersedes_and_activates() {
        let mut t = IdentityStatusTable::new();
        t.enroll(rec(1, IdentityStatusState::Active)).unwrap();
        t.rotate(
            [1; 16],
            [2; 16],
            SubjectKind::Client,
            [3; 16],
            1,
            rec(2, IdentityStatusState::Active),
        )
        .unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(t.rows[0].state, IdentityStatusState::Superseded);
        assert_eq!(t.rows[1].state, IdentityStatusState::Active);
    }

    #[test]
    fn rotate_rejects_rollback() {
        let mut t = IdentityStatusTable::new();
        t.enroll(rec(2, IdentityStatusState::Active)).unwrap();
        assert!(
            t.rotate(
                [1; 16],
                [2; 16],
                SubjectKind::Client,
                [3; 16],
                2,
                rec(1, IdentityStatusState::Active)
            )
            .is_err()
        );
    }

    #[test]
    fn revoke_transitions_active_to_revoked() {
        let mut t = IdentityStatusTable::new();
        t.enroll(rec(1, IdentityStatusState::Active)).unwrap();
        let r = t
            .revoke([1; 16], [2; 16], SubjectKind::Client, [3; 16], 1, 99)
            .unwrap();
        assert_eq!(r.state, IdentityStatusState::Revoked);
        assert_eq!(r.subject_state_generation, 1);
    }

    #[test]
    fn revoke_rejects_already_revoked() {
        let mut t = IdentityStatusTable::new();
        t.enroll(rec(1, IdentityStatusState::Active)).unwrap();
        t.revoke([1; 16], [2; 16], SubjectKind::Client, [3; 16], 1, 99)
            .unwrap();
        assert!(
            t.revoke([1; 16], [2; 16], SubjectKind::Client, [3; 16], 1, 100)
                .is_err()
        );
    }

    #[test]
    fn unknown_row_is_non_enumerating() {
        let t = IdentityStatusTable::new();
        assert_eq!(
            t.load_for_status([1; 16], [2; 16], SubjectKind::Client, [3; 16], 1),
            Err(IdentityStatusError::NotFound)
        );
    }
}
