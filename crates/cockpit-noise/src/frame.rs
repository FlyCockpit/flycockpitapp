use crate::{NoiseError, Result};

pub const HANDSHAKE_HEADER_LEN: usize = 4;
pub const MAX_HANDSHAKE_MESSAGE: usize = 4_096;
pub const ABSOLUTE_CIPHERTEXT_CAP: usize = 65_535;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeFrame {
    pub message_index: u8,
    pub message: Vec<u8>,
}

impl HandshakeFrame {
    pub fn encode(message_index: u8, message: &[u8]) -> Result<Vec<u8>> {
        if !matches!(message_index, 1 | 2)
            || message.is_empty()
            || message.len() > MAX_HANDSHAKE_MESSAGE
        {
            return Err(NoiseError::InvalidHandshakeFrame);
        }
        let length = u16::try_from(message.len()).map_err(|_| NoiseError::InvalidHandshakeFrame)?;
        let mut out = Vec::with_capacity(HANDSHAKE_HEADER_LEN + message.len());
        out.extend_from_slice(&[1, message_index]);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(message);
        Ok(out)
    }

    pub fn decode(bytes: &[u8], expected_index: u8) -> Result<Self> {
        if bytes.len() < HANDSHAKE_HEADER_LEN || bytes.len() > ABSOLUTE_CIPHERTEXT_CAP {
            return Err(NoiseError::InvalidHandshakeFrame);
        }
        let header: [u8; 4] = bytes[..4]
            .try_into()
            .map_err(|_| NoiseError::InvalidHandshakeFrame)?;
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        if header[0] != 1
            || header[1] != expected_index
            || !matches!(header[1], 1 | 2)
            || length == 0
            || length > MAX_HANDSHAKE_MESSAGE
            || bytes.len() != HANDSHAKE_HEADER_LEN + length
        {
            return Err(NoiseError::InvalidHandshakeFrame);
        }
        Ok(Self {
            message_index: header[1],
            message: bytes[4..].to_vec(),
        })
    }
}
