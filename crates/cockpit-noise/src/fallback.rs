use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::{NoiseError, RemoteNoiseRecordV1, Result};

pub const FALLBACK_OUTER_HEADER_LEN: usize = 28;
pub const FALLBACK_MAX_MESSAGE: usize = 65_563;
pub const FALLBACK_MAX_CIPHERTEXT: usize = 65_535;
pub const FALLBACK_MIN_CIPHERTEXT: usize = 30;
pub const FALLBACK_WINDOW_RECORDS: usize = 64;
pub const FALLBACK_WINDOW_BYTES: usize = 4 * 1024 * 1024;
pub const ACK_WIRE_LEN: usize = 9;
pub const ACK_NONE: u64 = u64::MAX;
pub const ACK_BATCH: u8 = 8;
pub const ACK_DEADLINE_MILLIS: u64 = 25;
pub const RETRY_MILLIS: [u64; 3] = [750, 1_500, 3_000];
const FALLBACK_SEQUENCE_LIMIT: u64 = 1_u64 << 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FallbackDirection {
    ClientToDaemon = 0,
    DaemonToClient = 1,
}

impl TryFrom<u8> for FallbackDirection {
    type Error = NoiseError;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::ClientToDaemon),
            1 => Ok(Self::DaemonToClient),
            _ => Err(NoiseError::InvalidFallback),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackOuterRecordV1 {
    pub route_generation: u64,
    pub direction: FallbackDirection,
    pub record_sequence: u64,
    pub peer_seen_through: u64,
    pub ciphertext: Vec<u8>,
}

impl FallbackOuterRecordV1 {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.route_generation == 0
            || self.record_sequence >= FALLBACK_SEQUENCE_LIMIT
            || self.ciphertext.len() < FALLBACK_MIN_CIPHERTEXT
            || self.ciphertext.len() > FALLBACK_MAX_CIPHERTEXT
        {
            return Err(NoiseError::InvalidFallback);
        }
        let length =
            u16::try_from(self.ciphertext.len()).map_err(|_| NoiseError::InvalidFallback)?;
        let mut out = Vec::with_capacity(FALLBACK_OUTER_HEADER_LEN + self.ciphertext.len());
        out.push(1);
        out.extend_from_slice(&self.route_generation.to_be_bytes());
        out.push(self.direction as u8);
        out.extend_from_slice(&self.record_sequence.to_be_bytes());
        out.extend_from_slice(&self.peer_seen_through.to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < FALLBACK_OUTER_HEADER_LEN
            || bytes.len() > FALLBACK_MAX_MESSAGE
            || bytes[0] != 1
        {
            return Err(NoiseError::InvalidFallback);
        }
        let length = usize::from(u16::from_be_bytes(
            bytes[26..28]
                .try_into()
                .map_err(|_| NoiseError::InvalidFallback)?,
        ));
        if !(FALLBACK_MIN_CIPHERTEXT..=FALLBACK_MAX_CIPHERTEXT).contains(&length)
            || bytes.len() != FALLBACK_OUTER_HEADER_LEN + length
        {
            return Err(NoiseError::InvalidFallback);
        }
        let route_generation = u64::from_be_bytes(
            bytes[1..9]
                .try_into()
                .map_err(|_| NoiseError::InvalidFallback)?,
        );
        let record_sequence = u64::from_be_bytes(
            bytes[10..18]
                .try_into()
                .map_err(|_| NoiseError::InvalidFallback)?,
        );
        if route_generation == 0 || record_sequence >= FALLBACK_SEQUENCE_LIMIT {
            return Err(NoiseError::InvalidFallback);
        }
        Ok(Self {
            route_generation,
            direction: bytes[9].try_into()?,
            record_sequence,
            peer_seen_through: u64::from_be_bytes(
                bytes[18..26]
                    .try_into()
                    .map_err(|_| NoiseError::InvalidFallback)?,
            ),
            ciphertext: bytes[28..].to_vec(),
        })
    }
}

pub fn validate_authenticated_outer(
    outer: &FallbackOuterRecordV1,
    inner: &RemoteNoiseRecordV1,
) -> Result<()> {
    let watermark = inner
        .payload
        .get(..8)
        .ok_or(NoiseError::InvalidFallback)
        .and_then(|bytes| bytes.try_into().map_err(|_| NoiseError::InvalidFallback))
        .map(u64::from_be_bytes)?;
    if inner.sequence != outer.record_sequence || watermark != outer.peer_seen_through {
        return Err(NoiseError::InvalidFallback);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CumulativeAckV1 {
    pub largest_contiguous: u64,
}

impl CumulativeAckV1 {
    #[must_use]
    pub fn encode(self) -> [u8; ACK_WIRE_LEN] {
        let mut out = [0_u8; ACK_WIRE_LEN];
        out[0] = 1;
        out[1..].copy_from_slice(&self.largest_contiguous.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ACK_WIRE_LEN || bytes[0] != 1 {
            return Err(NoiseError::InvalidFallback);
        }
        Ok(Self {
            largest_contiguous: u64::from_be_bytes(
                bytes[1..]
                    .try_into()
                    .map_err(|_| NoiseError::InvalidFallback)?,
            ),
        })
    }
}

#[derive(Clone, Debug)]
struct CachedRecord {
    bytes: Vec<u8>,
    byte_cost: usize,
    digest: [u8; 32],
    tracked: bool,
    retry_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveDisposition {
    Buffered,
    Duplicate { acknowledge: CumulativeAckV1 },
    Contiguous(Vec<FallbackOuterRecordV1>),
}

#[derive(Debug)]
pub struct FallbackReceiveWindow {
    next_sequence: u64,
    bytes: usize,
    pending: BTreeMap<u64, CachedRecord>,
    accepted: BTreeMap<u64, [u8; 32]>,
    newly_admitted: u8,
    last_ack_millis: u64,
}

impl FallbackReceiveWindow {
    #[must_use]
    pub fn new(now_millis: u64) -> Self {
        Self {
            next_sequence: 0,
            bytes: 0,
            pending: BTreeMap::new(),
            accepted: BTreeMap::new(),
            newly_admitted: 0,
            last_ack_millis: now_millis,
        }
    }

    pub fn observe(&mut self, bytes: Vec<u8>) -> Result<ReceiveDisposition> {
        let outer = FallbackOuterRecordV1::decode(&bytes)?;
        let byte_cost = outer.ciphertext.len();
        let sequence = outer.record_sequence;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if sequence < self.next_sequence {
            return match self.accepted.get(&sequence) {
                Some(prior) if *prior == digest => Ok(ReceiveDisposition::Duplicate {
                    acknowledge: self.ack(),
                }),
                _ => Err(NoiseError::InvalidFallback),
            };
        }
        if sequence.saturating_sub(self.next_sequence) >= FALLBACK_WINDOW_RECORDS as u64 {
            return Err(NoiseError::FallbackWindowExceeded);
        }
        if let Some(prior) = self.pending.get(&sequence) {
            return if prior.digest == digest {
                Ok(ReceiveDisposition::Duplicate {
                    acknowledge: self.ack(),
                })
            } else {
                Err(NoiseError::InvalidFallback)
            };
        }
        if self.pending.len() >= FALLBACK_WINDOW_RECORDS
            || self.bytes.saturating_add(byte_cost) > FALLBACK_WINDOW_BYTES
        {
            return Err(NoiseError::FallbackWindowExceeded);
        }
        self.bytes += byte_cost;
        self.pending.insert(
            sequence,
            CachedRecord {
                bytes,
                byte_cost,
                digest,
                tracked: false,
                retry_index: 0,
            },
        );
        if sequence != self.next_sequence {
            return Ok(ReceiveDisposition::Buffered);
        }
        let mut contiguous = Vec::new();
        while let Some(cached) = self.pending.remove(&self.next_sequence) {
            self.bytes -= cached.byte_cost;
            let decoded = FallbackOuterRecordV1::decode(&cached.bytes)?;
            self.accepted.insert(self.next_sequence, cached.digest);
            while self.accepted.len() > FALLBACK_WINDOW_RECORDS {
                let first = *self
                    .accepted
                    .first_key_value()
                    .ok_or(NoiseError::InvalidFallback)?
                    .0;
                self.accepted.remove(&first);
            }
            self.next_sequence = self
                .next_sequence
                .checked_add(1)
                .ok_or(NoiseError::SequenceExhausted)?;
            self.newly_admitted = self.newly_admitted.saturating_add(1);
            contiguous.push(decoded);
        }
        Ok(ReceiveDisposition::Contiguous(contiguous))
    }

    #[must_use]
    pub fn ack(&self) -> CumulativeAckV1 {
        CumulativeAckV1 {
            largest_contiguous: self.next_sequence.checked_sub(1).unwrap_or(ACK_NONE),
        }
    }

    pub fn ack_due(
        &mut self,
        now_millis: u64,
        immediate: bool,
        received_ack_only: bool,
    ) -> Option<CumulativeAckV1> {
        if received_ack_only && !immediate {
            return None;
        }
        if immediate
            || self.newly_admitted >= ACK_BATCH
            || now_millis.saturating_sub(self.last_ack_millis) >= ACK_DEADLINE_MILLIS
        {
            self.newly_admitted = 0;
            self.last_ack_millis = now_millis;
            Some(self.ack())
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct FallbackSendWindow {
    bytes: usize,
    records: BTreeMap<u64, CachedRecord>,
    next_sequence: u64,
    delivery_ack: u64,
    peer_seen_through: u64,
}

impl FallbackSendWindow {
    #[must_use]
    pub fn new() -> Self {
        Self {
            bytes: 0,
            records: BTreeMap::new(),
            next_sequence: 0,
            delivery_ack: ACK_NONE,
            peer_seen_through: ACK_NONE,
        }
    }

    pub fn insert(
        &mut self,
        sequence: u64,
        ciphertext: Vec<u8>,
        delivery_tracked: bool,
    ) -> Result<()> {
        let outer = FallbackOuterRecordV1::decode(&ciphertext)?;
        if outer.record_sequence != sequence {
            return Err(NoiseError::InvalidFallback);
        }
        let ciphertext_bytes = outer.ciphertext.len();
        if sequence != self.next_sequence
            || self.records.contains_key(&sequence)
            || self.records.len() >= FALLBACK_WINDOW_RECORDS
            || self.bytes.saturating_add(ciphertext_bytes) > FALLBACK_WINDOW_BYTES
        {
            return Err(NoiseError::FallbackWindowExceeded);
        }
        self.bytes += ciphertext_bytes;
        self.records.insert(
            sequence,
            CachedRecord {
                digest: Sha256::digest(&ciphertext).into(),
                bytes: ciphertext,
                byte_cost: ciphertext_bytes,
                tracked: delivery_tracked,
                retry_index: 0,
            },
        );
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(NoiseError::SequenceExhausted)?;
        Ok(())
    }

    pub fn acknowledge(&mut self, largest_contiguous: u64) -> Result<()> {
        if largest_contiguous == ACK_NONE {
            return if self.delivery_ack == ACK_NONE {
                Ok(())
            } else {
                Err(NoiseError::InvalidFallback)
            };
        }
        if largest_contiguous >= self.next_sequence
            || (self.delivery_ack != ACK_NONE && largest_contiguous < self.delivery_ack)
        {
            return Err(NoiseError::InvalidFallback);
        }
        self.delivery_ack = largest_contiguous;
        for record in self
            .records
            .range_mut(..=largest_contiguous)
            .map(|(_, record)| record)
        {
            record.tracked = false;
        }
        Ok(())
    }

    pub fn retransmit_from(&self, next_missing: u64) -> Vec<&[u8]> {
        self.records
            .range(next_missing..)
            .map(|(_, record)| record.bytes.as_slice())
            .collect()
    }

    pub fn retry_due(&mut self, elapsed_millis: u64) -> Result<Vec<&[u8]>> {
        let mut due = Vec::new();
        for record in self.records.values_mut().filter(|record| record.tracked) {
            if record.retry_index < RETRY_MILLIS.len()
                && elapsed_millis >= RETRY_MILLIS[record.retry_index]
            {
                record.retry_index += 1;
                due.push(record.bytes.as_slice());
            } else if record.retry_index == RETRY_MILLIS.len() && elapsed_millis > RETRY_MILLIS[2] {
                return Err(NoiseError::FallbackRetryExhausted);
            }
        }
        Ok(due)
    }

    pub fn release_peer_seen_through(&mut self, watermark: u64) -> Result<()> {
        if watermark == ACK_NONE {
            return if self.peer_seen_through == ACK_NONE {
                Ok(())
            } else {
                Err(NoiseError::InvalidFallback)
            };
        }
        if watermark >= self.next_sequence
            || (self.peer_seen_through != ACK_NONE && watermark < self.peer_seen_through)
        {
            return Err(NoiseError::InvalidFallback);
        }
        self.peer_seen_through = watermark;
        let keys: Vec<u64> = self
            .records
            .range(..=watermark)
            .map(|(key, _)| *key)
            .collect();
        for key in keys {
            if let Some(record) = self.records.remove(&key) {
                self.bytes -= record.byte_cost;
            }
        }
        Ok(())
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.values().all(|record| !record.tracked)
    }
    #[must_use]
    pub fn cache_is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl Default for FallbackSendWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outer(sequence: u64, fill: u8) -> Vec<u8> {
        FallbackOuterRecordV1 {
            route_generation: 7,
            direction: FallbackDirection::ClientToDaemon,
            record_sequence: sequence,
            peer_seen_through: ACK_NONE,
            ciphertext: vec![fill; 32],
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn remote_fallback_wire_and_ack_bounds() {
        let maximum = FallbackOuterRecordV1 {
            route_generation: 1,
            direction: FallbackDirection::DaemonToClient,
            record_sequence: 2,
            peer_seen_through: ACK_NONE,
            ciphertext: vec![1; FALLBACK_MAX_CIPHERTEXT],
        }
        .encode()
        .unwrap();
        assert_eq!(maximum.len(), FALLBACK_MAX_MESSAGE);
        assert_eq!(
            FallbackOuterRecordV1::decode(&maximum)
                .unwrap()
                .record_sequence,
            2
        );
        assert_eq!(
            CumulativeAckV1 {
                largest_contiguous: ACK_NONE
            }
            .encode(),
            [1, 255, 255, 255, 255, 255, 255, 255, 255]
        );
    }

    #[test]
    fn remote_fallback_reorder_window_is_contiguous_and_duplicate_safe() {
        let mut receive = FallbackReceiveWindow::new(0);
        assert_eq!(
            receive.observe(outer(1, 2)).unwrap(),
            ReceiveDisposition::Buffered
        );
        assert!(matches!(
            receive.observe(outer(1, 2)).unwrap(),
            ReceiveDisposition::Duplicate { .. }
        ));
        assert_eq!(
            receive.observe(outer(1, 3)),
            Err(NoiseError::InvalidFallback)
        );

        let mut receive = FallbackReceiveWindow::new(0);
        receive.observe(outer(1, 2)).unwrap();
        let admitted = receive.observe(outer(0, 1)).unwrap();
        assert!(
            matches!(admitted, ReceiveDisposition::Contiguous(records) if records.iter().map(|record| record.record_sequence).collect::<Vec<_>>() == vec![0, 1])
        );
        assert_eq!(receive.ack().largest_contiguous, 1);
        assert!(matches!(
            receive.observe(outer(0, 1)).unwrap(),
            ReceiveDisposition::Duplicate { .. }
        ));
        assert_eq!(
            receive.observe(outer(66, 1)),
            Err(NoiseError::FallbackWindowExceeded)
        );
    }

    #[test]
    fn remote_fallback_retransmit_schedule_and_gap_feedback_are_byte_identical() {
        let mut send = FallbackSendWindow::new();
        let zero = outer(0, 1);
        let ack_only = outer(1, 2);
        send.insert(0, zero.clone(), true).unwrap();
        send.insert(1, ack_only.clone(), false).unwrap();
        assert_eq!(send.retry_due(749).unwrap().len(), 0);
        assert_eq!(send.retry_due(750).unwrap()[0], zero);
        assert_eq!(send.retransmit_from(1), vec![ack_only.as_slice()]);
        send.acknowledge(0).unwrap();
        assert_eq!(send.retransmit_from(1), vec![ack_only.as_slice()]);
        send.release_peer_seen_through(1).unwrap();
        assert!(send.is_empty());
        assert!(send.cache_is_empty());
    }

    #[test]
    fn remote_fallback_ack_triggers_do_not_loop_on_ack_only() {
        let mut receive = FallbackReceiveWindow::new(0);
        assert!(receive.ack_due(24, false, false).is_none());
        assert!(receive.ack_due(25, false, true).is_none());
        assert!(receive.ack_due(25, true, true).is_some());
    }
}
