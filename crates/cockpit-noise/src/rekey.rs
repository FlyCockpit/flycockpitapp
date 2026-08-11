use crate::record::{RecordKind, RekeyPrepareV1};
use crate::{NoiseError, Result};

pub const MAX_RECORDS: u32 = 1_048_576;
pub const MAX_APPLICATION_BYTES: u64 = 1_073_741_824;
pub const LAST_OPEN_RECORD: u32 = MAX_RECORDS - 1;
pub const HARD_SEQUENCE_LIMIT: u64 = 1_u64 << 32;
pub const REKEY_DEADLINE_MILLIS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectionalState {
    Open,
    Draining,
    PrepareSent,
    PrepareReceived,
    CommitQueued,
    WaitCommit,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RekeyEvent {
    LocalRecordRequest { kind: RecordKind, data_bytes: u64 },
    PriorRecordsAcked,
    ReassemblyEmpty,
    PeerPrepare(RekeyPrepareV1),
    CommitDurablyQueued { key_epoch: u32 },
    PeerCommitAuthenticated { key_epoch: u32 },
    Deadline { elapsed_millis: u64 },
    Close,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RekeyAction {
    SendPrepare(RekeyPrepareV1),
    SendCommit { direction: u8, key_epoch: u32 },
    ApplySendRekey { key_epoch: u32 },
    ApplyReceiveRekey { key_epoch: u32 },
    Open { sequence: u64, key_epoch: u32 },
    Close,
}

#[derive(Clone, Debug)]
pub struct DirectionalRekey {
    pub direction: u8,
    pub absolute_sequence: u64,
    pub key_epoch: u32,
    pub records_under_key: u32,
    pub application_plaintext_bytes_under_key: u64,
    pub state: DirectionalState,
    acked: bool,
    reassembly_empty: bool,
    pending_prepare: Option<RekeyPrepareV1>,
    prior_prepare: Option<RekeyPrepareV1>,
    prior_prepare_result: Option<Vec<RekeyAction>>,
    prior_commit_epoch: Option<u32>,
    prior_commit_result: Option<Vec<RekeyAction>>,
}

impl DirectionalRekey {
    pub fn new(direction: u8) -> Result<Self> {
        if !matches!(direction, 1 | 2) {
            return Err(NoiseError::InvalidRekey);
        }
        Ok(Self {
            direction,
            absolute_sequence: 0,
            key_epoch: 0,
            records_under_key: 0,
            application_plaintext_bytes_under_key: 0,
            state: DirectionalState::Open,
            acked: false,
            reassembly_empty: false,
            pending_prepare: None,
            prior_prepare: None,
            prior_prepare_result: None,
            prior_commit_epoch: None,
            prior_commit_result: None,
        })
    }

    pub fn reduce(&mut self, event: RekeyEvent) -> Result<Vec<RekeyAction>> {
        if self.state == DirectionalState::Closed {
            return Err(NoiseError::Closed);
        }
        let result = match event {
            RekeyEvent::Close => {
                self.state = DirectionalState::Closed;
                Ok(vec![RekeyAction::Close])
            }
            RekeyEvent::Deadline { elapsed_millis } => {
                if self.state == DirectionalState::Open || elapsed_millis < REKEY_DEADLINE_MILLIS {
                    return Ok(Vec::new());
                }
                self.state = DirectionalState::Closed;
                Ok(vec![RekeyAction::Close])
            }
            RekeyEvent::LocalRecordRequest { kind, data_bytes } => {
                self.local_record_request(kind, data_bytes)
            }
            RekeyEvent::PriorRecordsAcked => {
                self.acked = true;
                self.maybe_send_prepare()
            }
            RekeyEvent::ReassemblyEmpty => {
                self.reassembly_empty = true;
                self.maybe_send_prepare()
            }
            RekeyEvent::PeerPrepare(prepare) => self.peer_prepare(prepare),
            RekeyEvent::CommitDurablyQueued { key_epoch } => self.commit_queued(key_epoch),
            RekeyEvent::PeerCommitAuthenticated { key_epoch } => self.peer_commit(key_epoch),
        };
        if result.is_err() {
            self.state = DirectionalState::Closed;
        }
        result
    }

    pub fn admit_authenticated_peer_record(
        &mut self,
        kind: RecordKind,
        data_bytes: u64,
    ) -> Result<()> {
        if self.state == DirectionalState::Closed || self.absolute_sequence >= HARD_SEQUENCE_LIMIT {
            return Err(NoiseError::Closed);
        }
        if self.records_under_key >= MAX_RECORDS {
            return Err(NoiseError::BudgetExceeded);
        }
        if kind == RecordKind::Data {
            if self.state != DirectionalState::Open
                || self
                    .application_plaintext_bytes_under_key
                    .checked_add(data_bytes)
                    .is_none_or(|next| next > MAX_APPLICATION_BYTES)
            {
                return Err(NoiseError::BudgetExceeded);
            }
        } else if kind == RecordKind::Ack && self.state != DirectionalState::Open {
            return Err(NoiseError::InvalidState);
        }
        let _ = self.consume_record(if kind == RecordKind::Data {
            data_bytes
        } else {
            0
        })?;
        if kind == RecordKind::Close {
            self.state = DirectionalState::Closed;
        }
        Ok(())
    }

    /// Accounts a generated commit under this independent send key.
    pub fn reserve_generated_commit(&mut self) -> Result<u64> {
        if self.state != DirectionalState::Open
            || self.absolute_sequence >= HARD_SEQUENCE_LIMIT
            || self.records_under_key >= LAST_OPEN_RECORD
        {
            self.state = DirectionalState::Closed;
            return Err(NoiseError::BudgetExceeded);
        }
        self.consume_record(0)
    }

    fn local_record_request(
        &mut self,
        kind: RecordKind,
        data_bytes: u64,
    ) -> Result<Vec<RekeyAction>> {
        if self.state != DirectionalState::Open {
            return Err(NoiseError::InvalidState);
        }
        if self.absolute_sequence >= HARD_SEQUENCE_LIMIT {
            self.state = DirectionalState::Closed;
            return Ok(vec![RekeyAction::Close]);
        }
        if kind == RecordKind::Close {
            if self.records_under_key >= MAX_RECORDS {
                return Err(NoiseError::BudgetExceeded);
            }
            let sequence = self.consume_record(0)?;
            self.state = DirectionalState::Closed;
            return Ok(vec![
                RekeyAction::Open {
                    sequence,
                    key_epoch: self.key_epoch,
                },
                RekeyAction::Close,
            ]);
        }
        if matches!(kind, RecordKind::RekeyPrepare | RecordKind::RekeyCommit) {
            return Err(NoiseError::InvalidState);
        }
        let data_over = kind == RecordKind::Data
            && self
                .application_plaintext_bytes_under_key
                .checked_add(data_bytes)
                .is_none_or(|next| next > MAX_APPLICATION_BYTES);
        if self.records_under_key >= LAST_OPEN_RECORD || data_over {
            self.state = DirectionalState::Draining;
            return Ok(Vec::new());
        }
        let sequence = self.consume_record(if kind == RecordKind::Data {
            data_bytes
        } else {
            0
        })?;
        Ok(vec![RekeyAction::Open {
            sequence,
            key_epoch: self.key_epoch,
        }])
    }

    fn consume_record(&mut self, data_bytes: u64) -> Result<u64> {
        let sequence = self.absolute_sequence;
        self.absolute_sequence = self
            .absolute_sequence
            .checked_add(1)
            .ok_or(NoiseError::SequenceExhausted)?;
        self.records_under_key = self
            .records_under_key
            .checked_add(1)
            .ok_or(NoiseError::BudgetExceeded)?;
        self.application_plaintext_bytes_under_key = self
            .application_plaintext_bytes_under_key
            .checked_add(data_bytes)
            .ok_or(NoiseError::BudgetExceeded)?;
        Ok(sequence)
    }

    fn maybe_send_prepare(&mut self) -> Result<Vec<RekeyAction>> {
        if self.state != DirectionalState::Draining || !self.acked || !self.reassembly_empty {
            return Ok(Vec::new());
        }
        // The final slot is reserved for prepare, but the byte budget can force a
        // drain before the record budget does. In that case prepare consumes the
        // next available slot rather than padding the epoch with application data.
        if self.records_under_key >= MAX_RECORDS || self.absolute_sequence == 0 {
            return Err(NoiseError::InvalidRekey);
        }
        let next_key_epoch = self
            .key_epoch
            .checked_add(1)
            .ok_or(NoiseError::InvalidRekey)?;
        let prepare = RekeyPrepareV1 {
            direction: self.direction,
            key_epoch: self.key_epoch,
            next_key_epoch,
            through_sequence: self.absolute_sequence - 1,
        };
        let _ = self.consume_record(0)?;
        self.pending_prepare = Some(prepare);
        self.state = DirectionalState::WaitCommit;
        Ok(vec![RekeyAction::SendPrepare(prepare)])
    }

    fn peer_prepare(&mut self, prepare: RekeyPrepareV1) -> Result<Vec<RekeyAction>> {
        if self.prior_prepare == Some(prepare) {
            return self
                .prior_prepare_result
                .clone()
                .ok_or(NoiseError::InvalidRekey);
        }
        if self.pending_prepare.is_some()
            || !matches!(
                self.state,
                DirectionalState::Open | DirectionalState::Draining
            )
            || prepare.direction != self.direction
            || prepare.key_epoch != self.key_epoch
            || prepare.next_key_epoch
                != self
                    .key_epoch
                    .checked_add(1)
                    .ok_or(NoiseError::InvalidRekey)?
            || self.absolute_sequence == 0
            || prepare.through_sequence != self.absolute_sequence - 1
        {
            return Err(NoiseError::InvalidRekey);
        }
        let action = RekeyAction::SendCommit {
            direction: self.direction,
            key_epoch: prepare.next_key_epoch,
        };
        self.pending_prepare = Some(prepare);
        self.prior_prepare = Some(prepare);
        self.prior_prepare_result = Some(vec![action.clone()]);
        self.state = DirectionalState::PrepareReceived;
        Ok(vec![action])
    }

    fn commit_queued(&mut self, key_epoch: u32) -> Result<Vec<RekeyAction>> {
        if self.prior_commit_epoch == Some(key_epoch) {
            return self
                .prior_commit_result
                .clone()
                .ok_or(NoiseError::InvalidRekey);
        }
        let prepare = self.pending_prepare.ok_or(NoiseError::InvalidRekey)?;
        if self.state != DirectionalState::PrepareReceived || key_epoch != prepare.next_key_epoch {
            return Err(NoiseError::InvalidRekey);
        }
        let action = RekeyAction::ApplyReceiveRekey { key_epoch };
        self.prior_commit_epoch = Some(key_epoch);
        let result = vec![
            action,
            RekeyAction::Open {
                sequence: self.absolute_sequence,
                key_epoch,
            },
        ];
        self.prior_commit_result = Some(result.clone());
        self.apply_epoch(key_epoch);
        Ok(result)
    }

    fn peer_commit(&mut self, key_epoch: u32) -> Result<Vec<RekeyAction>> {
        if self.prior_commit_epoch == Some(key_epoch) {
            return self
                .prior_commit_result
                .clone()
                .ok_or(NoiseError::InvalidRekey);
        }
        let prepare = self.pending_prepare.ok_or(NoiseError::InvalidRekey)?;
        if self.state != DirectionalState::WaitCommit || key_epoch != prepare.next_key_epoch {
            return Err(NoiseError::InvalidRekey);
        }
        let action = RekeyAction::ApplySendRekey { key_epoch };
        self.prior_commit_epoch = Some(key_epoch);
        let result = vec![
            action,
            RekeyAction::Open {
                sequence: self.absolute_sequence,
                key_epoch,
            },
        ];
        self.prior_commit_result = Some(result.clone());
        self.apply_epoch(key_epoch);
        Ok(result)
    }

    fn apply_epoch(&mut self, key_epoch: u32) {
        self.key_epoch = key_epoch;
        self.records_under_key = 0;
        self.application_plaintext_bytes_under_key = 0;
        self.state = DirectionalState::Open;
        self.acked = false;
        self.reassembly_empty = false;
        self.pending_prepare = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_noise_rekey_barrier() {
        let mut send = DirectionalRekey::new(1).unwrap();
        send.records_under_key = LAST_OPEN_RECORD;
        send.absolute_sequence = u64::from(LAST_OPEN_RECORD);
        assert!(
            send.reduce(RekeyEvent::LocalRecordRequest {
                kind: RecordKind::Data,
                data_bytes: 1
            })
            .unwrap()
            .is_empty()
        );
        assert_eq!(send.state, DirectionalState::Draining);
        assert!(
            send.reduce(RekeyEvent::PriorRecordsAcked)
                .unwrap()
                .is_empty()
        );
        let actions = send.reduce(RekeyEvent::ReassemblyEmpty).unwrap();
        let prepare = match actions.as_slice() {
            [RekeyAction::SendPrepare(value)] => *value,
            other => panic!("unexpected actions: {other:?}"),
        };
        assert_eq!(send.records_under_key, MAX_RECORDS);
        assert_eq!(send.state, DirectionalState::WaitCommit);
        let applied = send
            .reduce(RekeyEvent::PeerCommitAuthenticated { key_epoch: 1 })
            .unwrap();
        assert!(matches!(
            applied[0],
            RekeyAction::ApplySendRekey { key_epoch: 1 }
        ));
        assert_eq!(send.absolute_sequence, u64::from(MAX_RECORDS));
        assert_eq!(send.records_under_key, 0);
        assert_eq!(send.key_epoch, 1);
        assert_eq!(send.state, DirectionalState::Open);

        let mut receive = DirectionalRekey::new(1).unwrap();
        receive.absolute_sequence = prepare.through_sequence + 1;
        let commit = receive.reduce(RekeyEvent::PeerPrepare(prepare)).unwrap();
        assert!(matches!(
            commit[0],
            RekeyAction::SendCommit { key_epoch: 1, .. }
        ));
        assert_eq!(
            receive.reduce(RekeyEvent::PeerPrepare(prepare)).unwrap(),
            commit
        );
        let applied = receive
            .reduce(RekeyEvent::CommitDurablyQueued { key_epoch: 1 })
            .unwrap();
        assert!(matches!(
            applied[0],
            RekeyAction::ApplyReceiveRekey { key_epoch: 1 }
        ));
        assert_eq!(
            receive
                .reduce(RekeyEvent::CommitDurablyQueued { key_epoch: 1 })
                .unwrap(),
            applied
        );
        assert_eq!(
            receive.reduce(RekeyEvent::PeerPrepare(prepare)).unwrap(),
            commit
        );
    }

    #[test]
    fn remote_noise_rekey_rejects_changed_duplicates_timeout_and_sequence_limit() {
        let mut direction = DirectionalRekey::new(2).unwrap();
        direction.state = DirectionalState::Draining;
        assert_eq!(
            direction
                .reduce(RekeyEvent::Deadline {
                    elapsed_millis: REKEY_DEADLINE_MILLIS
                })
                .unwrap(),
            vec![RekeyAction::Close]
        );
        assert_eq!(direction.reduce(RekeyEvent::Close), Err(NoiseError::Closed));

        let mut exhausted = DirectionalRekey::new(1).unwrap();
        exhausted.absolute_sequence = HARD_SEQUENCE_LIMIT;
        assert_eq!(
            exhausted
                .reduce(RekeyEvent::LocalRecordRequest {
                    kind: RecordKind::Ack,
                    data_bytes: 0
                })
                .unwrap(),
            vec![RekeyAction::Close]
        );

        let mut receiver = DirectionalRekey::new(1).unwrap();
        receiver.absolute_sequence = 8;
        let prepare = RekeyPrepareV1 {
            direction: 1,
            key_epoch: 0,
            next_key_epoch: 1,
            through_sequence: 7,
        };
        receiver.reduce(RekeyEvent::PeerPrepare(prepare)).unwrap();
        let mut changed = prepare;
        changed.through_sequence = 6;
        assert_eq!(
            receiver.reduce(RekeyEvent::PeerPrepare(changed)),
            Err(NoiseError::InvalidRekey)
        );
    }

    #[test]
    fn remote_noise_all_kind_and_application_budgets() {
        let mut direction = DirectionalRekey::new(1).unwrap();
        direction.application_plaintext_bytes_under_key = MAX_APPLICATION_BYTES;
        assert!(
            direction
                .reduce(RekeyEvent::LocalRecordRequest {
                    kind: RecordKind::Data,
                    data_bytes: 1
                })
                .unwrap()
                .is_empty()
        );
        assert_eq!(direction.absolute_sequence, 0);

        for kind in [RecordKind::Data, RecordKind::Ack, RecordKind::Close] {
            let mut candidate = DirectionalRekey::new(1).unwrap();
            candidate.records_under_key = LAST_OPEN_RECORD;
            candidate.absolute_sequence = u64::from(LAST_OPEN_RECORD);
            let result = candidate.reduce(RekeyEvent::LocalRecordRequest {
                kind,
                data_bytes: if kind == RecordKind::Data { 1 } else { 0 },
            });
            assert!(result.is_ok());
        }
    }

    #[test]
    fn remote_noise_generated_reducer_state_event_matrix_is_total() {
        let states = [
            DirectionalState::Open,
            DirectionalState::Draining,
            DirectionalState::PrepareSent,
            DirectionalState::PrepareReceived,
            DirectionalState::CommitQueued,
            DirectionalState::WaitCommit,
            DirectionalState::Closed,
        ];
        let prepare = RekeyPrepareV1 {
            direction: 1,
            key_epoch: 0,
            next_key_epoch: 1,
            through_sequence: 0,
        };
        let events = [
            RekeyEvent::LocalRecordRequest {
                kind: RecordKind::Data,
                data_bytes: 1,
            },
            RekeyEvent::LocalRecordRequest {
                kind: RecordKind::Ack,
                data_bytes: 0,
            },
            RekeyEvent::LocalRecordRequest {
                kind: RecordKind::Close,
                data_bytes: 0,
            },
            RekeyEvent::PriorRecordsAcked,
            RekeyEvent::ReassemblyEmpty,
            RekeyEvent::PeerPrepare(prepare),
            RekeyEvent::CommitDurablyQueued { key_epoch: 1 },
            RekeyEvent::PeerCommitAuthenticated { key_epoch: 1 },
            RekeyEvent::Deadline {
                elapsed_millis: REKEY_DEADLINE_MILLIS,
            },
            RekeyEvent::Close,
        ];
        let mut visited = 0;
        for state in states {
            for event in &events {
                let mut reducer = DirectionalRekey::new(1).unwrap();
                reducer.state = state;
                reducer.absolute_sequence = 1;
                let _result = reducer.reduce(event.clone());
                visited += 1;
            }
        }
        assert_eq!(visited, states.len() * events.len());
    }
}
