use sha2::{Digest, Sha256};

use crate::{NoiseError, Result};

pub const DOMAIN: &[u8] = b"flycockpit-remote-noise-prologue-v1\0";
pub const BODY_LEN: usize = 186;
pub const ENCODED_LEN: usize = DOMAIN.len() + BODY_LEN;
pub const MAGIC: &[u8; 4] = b"FCNP";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteNoisePrologueV1 {
    pub child_attempt_id: [u8; 16],
    pub grant_jti: [u8; 16],
    pub client_certificate_id: [u8; 16],
    pub client_certificate_generation: u64,
    pub daemon_certificate_id: [u8; 16],
    pub daemon_certificate_generation: u64,
    pub selected_tuple_id: u16,
    pub negotiation_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub connection_nonce: [u8; 32],
}

impl RemoteNoisePrologueV1 {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENCODED_LEN);
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(MAGIC);
        out.push(1);
        out.extend_from_slice(&self.child_attempt_id);
        out.extend_from_slice(&self.grant_jti);
        out.extend_from_slice(&self.client_certificate_id);
        out.extend_from_slice(&self.client_certificate_generation.to_be_bytes());
        out.extend_from_slice(&self.daemon_certificate_id);
        out.extend_from_slice(&self.daemon_certificate_generation.to_be_bytes());
        out.extend_from_slice(&self.selected_tuple_id.to_be_bytes());
        out.extend_from_slice(&self.negotiation_digest);
        out.extend_from_slice(&self.policy_digest);
        out.extend_from_slice(&self.connection_nonce);
        out.extend_from_slice(&[1, 2, 2]);
        debug_assert_eq!(out.len(), ENCODED_LEN);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ENCODED_LEN || !bytes.starts_with(DOMAIN) {
            return Err(NoiseError::InvalidPrologue);
        }
        let body = &bytes[DOMAIN.len()..];
        if &body[..4] != MAGIC || body[4] != 1 || body[183..] != [1, 2, 2] {
            return Err(NoiseError::InvalidPrologue);
        }
        let mut cursor = 5;
        let child_attempt_id = take_array::<16>(body, &mut cursor)?;
        let grant_jti = take_array::<16>(body, &mut cursor)?;
        let client_certificate_id = take_array::<16>(body, &mut cursor)?;
        let client_certificate_generation = u64::from_be_bytes(take_array(body, &mut cursor)?);
        let daemon_certificate_id = take_array::<16>(body, &mut cursor)?;
        let daemon_certificate_generation = u64::from_be_bytes(take_array(body, &mut cursor)?);
        let selected_tuple_id = u16::from_be_bytes(take_array(body, &mut cursor)?);
        let negotiation_digest = take_array::<32>(body, &mut cursor)?;
        let policy_digest = take_array::<32>(body, &mut cursor)?;
        let connection_nonce = take_array::<32>(body, &mut cursor)?;
        if cursor != 183 {
            return Err(NoiseError::InvalidPrologue);
        }
        Ok(Self {
            child_attempt_id,
            grant_jti,
            client_certificate_id,
            client_certificate_generation,
            daemon_certificate_id,
            daemon_certificate_generation,
            selected_tuple_id,
            negotiation_digest,
            policy_digest,
            connection_nonce,
        })
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
}

fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    let end = cursor.checked_add(N).ok_or(NoiseError::InvalidPrologue)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(NoiseError::InvalidPrologue)?
        .try_into()
        .map_err(|_| NoiseError::InvalidPrologue)?;
    *cursor = end;
    Ok(value)
}
