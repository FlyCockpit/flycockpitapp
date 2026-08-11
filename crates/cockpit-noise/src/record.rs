use crate::{NoiseError, Result};

pub const RECORD_HEADER_LEN: usize = 14;
pub const TAG_LEN: usize = 16;
pub const MAX_CIPHERTEXT: usize = 65_535;
pub const MAX_PLAINTEXT: usize = MAX_CIPHERTEXT - TAG_LEN;
pub const MAX_PAYLOAD: usize = MAX_PLAINTEXT - RECORD_HEADER_LEN;
pub const LANE_FRAGMENT_HEADER_LEN: usize = 26;
pub const MAX_LANE_FRAGMENT: usize = 65_497;
pub const MAX_LANE_FRAGMENT_PAYLOAD: usize = MAX_LANE_FRAGMENT - LANE_FRAGMENT_HEADER_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecordKind {
    Data = 1,
    Ack = 2,
    RekeyPrepare = 3,
    RekeyCommit = 4,
    Close = 5,
}

impl TryFrom<u8> for RecordKind {
    type Error = NoiseError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Data),
            2 => Ok(Self::Ack),
            3 => Ok(Self::RekeyPrepare),
            4 => Ok(Self::RekeyCommit),
            5 => Ok(Self::Close),
            _ => Err(NoiseError::InvalidRecord),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteNoiseRecordV1 {
    pub kind: RecordKind,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

impl RemoteNoiseRecordV1 {
    pub fn encode_plaintext(&self) -> Result<Vec<u8>> {
        if self.payload.len() > MAX_PAYLOAD {
            return Err(NoiseError::RecordTooLarge);
        }
        let payload_len =
            u32::try_from(self.payload.len()).map_err(|_| NoiseError::RecordTooLarge)?;
        let mut out = Vec::with_capacity(RECORD_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&[1, self.kind as u8]);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode_plaintext(bytes: &[u8], routing_sequence: u64) -> Result<Self> {
        if bytes.len() < RECORD_HEADER_LEN || bytes.len() > MAX_PLAINTEXT {
            return Err(NoiseError::InvalidRecord);
        }
        let kind = RecordKind::try_from(bytes[1])?;
        let sequence = u64::from_be_bytes(
            bytes[2..10]
                .try_into()
                .map_err(|_| NoiseError::InvalidRecord)?,
        );
        let length = usize::try_from(u32::from_be_bytes(
            bytes[10..14]
                .try_into()
                .map_err(|_| NoiseError::InvalidRecord)?,
        ))
        .map_err(|_| NoiseError::InvalidRecord)?;
        if bytes[0] != 1 || length > MAX_PAYLOAD || bytes.len() != RECORD_HEADER_LEN + length {
            return Err(NoiseError::InvalidRecord);
        }
        if sequence != routing_sequence {
            return Err(NoiseError::SequenceMismatch);
        }
        Ok(Self {
            kind,
            sequence,
            payload: bytes[RECORD_HEADER_LEN..].to_vec(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RekeyPrepareV1 {
    pub direction: u8,
    pub key_epoch: u32,
    pub next_key_epoch: u32,
    pub through_sequence: u64,
}

impl RekeyPrepareV1 {
    pub const LEN: usize = 17;
    #[must_use]
    pub fn encode(self) -> [u8; Self::LEN] {
        let mut out = [0_u8; Self::LEN];
        out[0] = self.direction;
        out[1..5].copy_from_slice(&self.key_epoch.to_be_bytes());
        out[5..9].copy_from_slice(&self.next_key_epoch.to_be_bytes());
        out[9..17].copy_from_slice(&self.through_sequence.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::LEN || !matches!(bytes[0], 1 | 2) {
            return Err(NoiseError::InvalidRekey);
        }
        Ok(Self {
            direction: bytes[0],
            key_epoch: u32::from_be_bytes(
                bytes[1..5]
                    .try_into()
                    .map_err(|_| NoiseError::InvalidRekey)?,
            ),
            next_key_epoch: u32::from_be_bytes(
                bytes[5..9]
                    .try_into()
                    .map_err(|_| NoiseError::InvalidRekey)?,
            ),
            through_sequence: u64::from_be_bytes(
                bytes[9..17]
                    .try_into()
                    .map_err(|_| NoiseError::InvalidRekey)?,
            ),
        })
    }
}
