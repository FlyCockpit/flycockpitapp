//! Canonical signaling-attempt request and commit-ack codecs.
use sha2::{Digest, Sha256};

pub const REQUEST_MAGIC: &[u8; 4] = b"FCSE";
pub const ACK_MAGIC: &[u8; 4] = b"FCAK";
pub const HEADER_BYTES: usize = 44;
pub const MAX_REQUEST_BYTES: usize = 131_072;
pub const MAX_PAYLOAD_BYTES: usize = MAX_REQUEST_BYTES - HEADER_BYTES;

fn preamble(bytes: &[u8], magic: &[u8; 4]) -> Result<(), SignalingCodecError> {
    if bytes.len() < 5 || &bytes[..4] != magic || bytes[4] != 1 {
        return Err(SignalingCodecError::Preamble);
    }
    Ok(())
}
fn take<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    size: usize,
) -> Result<&'a [u8], SignalingCodecError> {
    let end = offset
        .checked_add(size)
        .ok_or(SignalingCodecError::Length)?;
    let value = bytes.get(*offset..end).ok_or(SignalingCodecError::Length)?;
    *offset = end;
    Ok(value)
}
fn take_u8(bytes: &[u8], offset: &mut usize) -> Result<u8, SignalingCodecError> {
    Ok(take(bytes, offset, 1)?[0])
}
fn take_u16(bytes: &[u8], offset: &mut usize) -> Result<u16, SignalingCodecError> {
    Ok(u16::from_be_bytes(
        take(bytes, offset, 2)?.try_into().unwrap(),
    ))
}
fn take_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, SignalingCodecError> {
    Ok(u64::from_be_bytes(
        take(bytes, offset, 8)?.try_into().unwrap(),
    ))
}
fn take_id(bytes: &[u8], offset: &mut usize) -> Result<[u8; 16], SignalingCodecError> {
    let id: [u8; 16] = take(bytes, offset, 16)?.try_into().unwrap();
    nonzero(&id)?;
    Ok(id)
}
fn tuples(bytes: &[u8], offset: &mut usize) -> Result<Vec<u16>, SignalingCodecError> {
    let count = take_u8(bytes, offset)? as usize;
    if !(1..=16).contains(&count) {
        return Err(SignalingCodecError::Length);
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let value = take_u16(bytes, offset)?;
        if values.last().is_some_and(|last| value <= *last) {
            return Err(SignalingCodecError::Combination);
        }
        values.push(value);
    }
    Ok(values)
}
fn signed_body<'a>(
    bytes: &'a [u8],
    cap: usize,
    magic: &[u8; 4],
) -> Result<&'a [u8], SignalingCodecError> {
    if bytes.len() < 66 || bytes.len() > cap + 66 {
        return Err(SignalingCodecError::Length);
    }
    let length = u16::from_be_bytes(bytes[..2].try_into().unwrap()) as usize;
    if length > cap || length + 66 != bytes.len() {
        return Err(SignalingCodecError::Length);
    }
    let body = &bytes[2..2 + length];
    preamble(body, magic)?;
    Ok(body)
}

pub fn validate_fcab(bytes: &[u8]) -> Result<[u8; 16], SignalingCodecError> {
    if bytes.len() > 98_304 {
        return Err(SignalingCodecError::Length);
    }
    preamble(bytes, b"FCAB")?;
    let mut o = 5;
    let child = take_id(bytes, &mut o)?;
    for cap in [8192, 4096, 4096, 16384, 16384] {
        let n = take_u16(bytes, &mut o)? as usize;
        if n == 0 || n > cap {
            return Err(SignalingCodecError::Length);
        }
        take(bytes, &mut o, n)?;
    }
    match take_u8(bytes, &mut o)? {
        0 => {}
        1 => {
            let n = take_u16(bytes, &mut o)? as usize;
            if n == 0 || n > 16384 {
                return Err(SignalingCodecError::Length);
            }
            take(bytes, &mut o, n)?;
        }
        _ => return Err(SignalingCodecError::Discriminant),
    }
    if o != bytes.len() {
        return Err(SignalingCodecError::Length);
    }
    Ok(child)
}
pub fn validate_fcdo(bytes: &[u8]) -> Result<[u8; 16], SignalingCodecError> {
    let body = signed_body(bytes, 328, b"FCDO")?;
    let mut o = 5;
    take_id(body, &mut o)?;
    take_id(body, &mut o)?;
    if take_u64(body, &mut o)? == 0 {
        return Err(SignalingCodecError::Combination);
    }
    take_id(body, &mut o)?;
    if take_u64(body, &mut o)? == 0 {
        return Err(SignalingCodecError::Combination);
    }
    take_id(body, &mut o)?;
    let child = take_id(body, &mut o)?;
    take_id(body, &mut o)?;
    take(body, &mut o, 32)?;
    take(body, &mut o, 32)?;
    if take_u64(body, &mut o)? == 0 || take_u64(body, &mut o)? == 0 {
        return Err(SignalingCodecError::Combination);
    }
    take(body, &mut o, 32)?;
    match take_u8(body, &mut o)? {
        0 => {}
        1 => {
            take(body, &mut o, 32)?;
        }
        _ => return Err(SignalingCodecError::Discriminant),
    }
    let bits = take_u8(body, &mut o)?;
    if bits == 0 || bits > 3 {
        return Err(SignalingCodecError::Discriminant);
    }
    tuples(body, &mut o)?;
    take_id(body, &mut o)?;
    let issued = take_u64(body, &mut o)? as i64;
    let expires = take_u64(body, &mut o)? as i64;
    if issued >= expires || o != body.len() {
        return Err(SignalingCodecError::Combination);
    }
    Ok(child)
}
pub fn daemon_admission_offer_digest(bytes: &[u8]) -> Result<[u8; 32], SignalingCodecError> {
    validate_fcdo(bytes)?;
    Ok(Sha256::digest(bytes).into())
}
pub fn validate_fccp(bytes: &[u8]) -> Result<[u8; 16], SignalingCodecError> {
    let body = signed_body(bytes, 443, b"FCCP")?;
    let mut o = 5;
    take_id(body, &mut o)?;
    take_id(body, &mut o)?;
    take_id(body, &mut o)?;
    if take_u64(body, &mut o)? == 0 {
        return Err(SignalingCodecError::Combination);
    }
    take_id(body, &mut o)?;
    if take_u64(body, &mut o)? == 0 {
        return Err(SignalingCodecError::Combination);
    }
    take_id(body, &mut o)?;
    let child = take_id(body, &mut o)?;
    take_id(body, &mut o)?;
    take(body, &mut o, 32)?;
    take(body, &mut o, 32)?;
    take_id(body, &mut o)?;
    if !matches!(take_u8(body, &mut o)?, 1 | 2) {
        return Err(SignalingCodecError::Discriminant);
    }
    let client = tuples(body, &mut o)?;
    let daemon = tuples(body, &mut o)?;
    let selected = take_u16(body, &mut o)?;
    if !client.contains(&selected) || !daemon.contains(&selected) {
        return Err(SignalingCodecError::Combination);
    }
    take(body, &mut o, 32)?;
    match take_u8(body, &mut o)? {
        0 => {}
        1 => {
            take(body, &mut o, 32)?;
        }
        _ => return Err(SignalingCodecError::Discriminant),
    }
    take(body, &mut o, 32)?;
    take(body, &mut o, 32)?;
    let issued = take_u64(body, &mut o)? as i64;
    let expires = take_u64(body, &mut o)? as i64;
    take_id(body, &mut o)?;
    if issued >= expires || o != body.len() {
        return Err(SignalingCodecError::Combination);
    }
    Ok(child)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEndpointFinalProofV1 {
    pub role: u8,
    pub transport: u8,
    pub child_attempt_id: [u8; 16],
    pub proof_jti: [u8; 16],
    pub agreement: Vec<u8>,
}
impl RemoteEndpointFinalProofV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, SignalingCodecError> {
        if bytes.len() != 313 {
            return Err(SignalingCodecError::Length);
        }
        preamble(bytes, b"FCFP")?;
        if !matches!(bytes[5], 1 | 2) || !matches!(bytes[6], 1 | 2) {
            return Err(SignalingCodecError::Discriminant);
        }
        let child: [u8; 16] = bytes[7..23].try_into().unwrap();
        nonzero(&child)?;
        let epoch: [u8; 16] = bytes[23..39].try_into().unwrap();
        nonzero(&epoch)?;
        if u64::from_be_bytes(bytes[39..47].try_into().unwrap()) == 0
            || u16::from_be_bytes(bytes[111..113].try_into().unwrap()) != 96
        {
            return Err(SignalingCodecError::Combination);
        }
        let proof_jti: [u8; 16] = bytes[209..225].try_into().unwrap();
        nonzero(&proof_jti)?;
        let cert: [u8; 16] = bytes[225..241].try_into().unwrap();
        nonzero(&cert)?;
        if u64::from_be_bytes(bytes[241..249].try_into().unwrap()) == 0 {
            return Err(SignalingCodecError::Combination);
        }
        let mut agreement = Vec::with_capacity(201);
        agreement.push(bytes[6]);
        agreement.extend_from_slice(&bytes[7..111]);
        agreement.extend_from_slice(&bytes[113..209]);
        Ok(Self {
            role: bytes[5],
            transport: bytes[6],
            child_attempt_id: child,
            proof_jti,
            agreement,
        })
    }
}

pub fn validate_webrtc_description(
    bytes: &[u8],
    answer: bool,
) -> Result<[u8; 16], SignalingCodecError> {
    if bytes.len() < 59 || bytes.len() > 122_938 {
        return Err(SignalingCodecError::Length);
    }
    preamble(bytes, if answer { b"FCWN" } else { b"FCWO" })?;
    if bytes[5] != if answer { 2 } else { 1 } {
        return Err(SignalingCodecError::Combination);
    }
    let child: [u8; 16] = bytes[6..22].try_into().unwrap();
    nonzero(&child)?;
    nonzero(&bytes[22..38].try_into().unwrap())?;
    nonzero(&bytes[38..54].try_into().unwrap())?;
    let length = u32::from_be_bytes(bytes[54..58].try_into().unwrap()) as usize;
    if !(1..=122_880).contains(&length) || 58 + length != bytes.len() {
        return Err(SignalingCodecError::Length);
    }
    let sdp = std::str::from_utf8(&bytes[58..]).map_err(|_| SignalingCodecError::Combination)?;
    if sdp.starts_with('\u{feff}')
        || sdp.contains('\0')
        || !sdp.ends_with("\r\n")
        || sdp.replace("\r\n", "").contains('\r')
        || sdp.replace("\r\n", "").contains('\n')
    {
        return Err(SignalingCodecError::Combination);
    }
    Ok(child)
}

pub fn validate_webrtc_candidate(bytes: &[u8]) -> Result<[u8; 16], SignalingCodecError> {
    if !(61..=4096).contains(&bytes.len()) {
        return Err(SignalingCodecError::Length);
    }
    preamble(bytes, b"FCWC")?;
    if !matches!(bytes[5], 1 | 2) {
        return Err(SignalingCodecError::Discriminant);
    }
    let child: [u8; 16] = bytes[6..22].try_into().unwrap();
    nonzero(&child)?;
    nonzero(&bytes[22..38].try_into().unwrap())?;
    nonzero(&bytes[38..54].try_into().unwrap())?;
    let mid_len = bytes[54] as usize;
    if mid_len == 0 || 59 + mid_len > bytes.len() {
        return Err(SignalingCodecError::Length);
    }
    let mid = &bytes[55..55 + mid_len];
    if !mid.iter().all(|b| (0x21..=0x7e).contains(b)) {
        return Err(SignalingCodecError::Combination);
    }
    let candidate_len =
        u16::from_be_bytes(bytes[57 + mid_len..59 + mid_len].try_into().unwrap()) as usize;
    if 59 + mid_len + candidate_len != bytes.len() {
        return Err(SignalingCodecError::Length);
    }
    let candidate = std::str::from_utf8(&bytes[59 + mid_len..])
        .map_err(|_| SignalingCodecError::Combination)?;
    if !candidate.starts_with("candidate:")
        || candidate.starts_with(' ')
        || candidate.ends_with(' ')
        || candidate.contains("  ")
        || !candidate.bytes().all(|b| (0x20..=0x7e).contains(&b))
    {
        return Err(SignalingCodecError::Combination);
    }
    Ok(child)
}
pub fn validate_webrtc_ice_complete(bytes: &[u8]) -> Result<[u8; 16], SignalingCodecError> {
    if bytes.len() != 38 {
        return Err(SignalingCodecError::Length);
    }
    preamble(bytes, b"FCWE")?;
    if !matches!(bytes[5], 1 | 2) {
        return Err(SignalingCodecError::Discriminant);
    }
    let child = bytes[6..22].try_into().unwrap();
    nonzero(&child)?;
    nonzero(&bytes[22..38].try_into().unwrap())?;
    Ok(child)
}
pub fn validate_fallback_pair(bytes: &[u8]) -> Result<(), SignalingCodecError> {
    if bytes.len() != 88 {
        return Err(SignalingCodecError::Length);
    }
    nonzero(&bytes[..16].try_into().unwrap())?;
    for chunk in bytes[16..56].chunks_exact(8) {
        if u64::from_be_bytes(chunk.try_into().unwrap()) == 0 {
            return Err(SignalingCodecError::Combination);
        }
    }
    Ok(())
}
pub fn validate_fallback_noise(bytes: &[u8]) -> Result<(), SignalingCodecError> {
    if bytes.len() != 121 {
        return Err(SignalingCodecError::Length);
    }
    if !matches!(bytes[0], 1 | 2) {
        return Err(SignalingCodecError::Discriminant);
    }
    nonzero(&bytes[1..17].try_into().unwrap())?;
    if u64::from_be_bytes(bytes[17..25].try_into().unwrap()) == 0 {
        return Err(SignalingCodecError::Combination);
    }
    Ok(())
}
pub fn validate_ready(bytes: &[u8]) -> Result<(), SignalingCodecError> {
    if bytes.len() != 48 {
        return Err(SignalingCodecError::Length);
    }
    nonzero(&bytes[..16].try_into().unwrap())?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSignalingEventRequestV1 {
    pub transport: u8,
    pub producer_role: u8,
    pub event_kind: u8,
    pub child_attempt_id: [u8; 16],
    pub event_id: [u8; 16],
    pub payload: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSignalingCommitAckV1 {
    pub event_id: [u8; 16],
    pub sequence: u64,
    pub event_digest: [u8; 32],
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignalingCodecError {
    #[error("truncated or trailing bytes")]
    Length,
    #[error("wrong magic or version")]
    Preamble,
    #[error("unknown transport, role, or event kind")]
    Discriminant,
    #[error("zero identifier")]
    ZeroId,
    #[error("transport or role disagrees with event kind")]
    Combination,
}
fn nonzero(id: &[u8; 16]) -> Result<(), SignalingCodecError> {
    (!id.iter().all(|byte| *byte == 0))
        .then_some(())
        .ok_or(SignalingCodecError::ZeroId)
}
fn combination(transport: u8, role: u8, kind: u8) -> Result<(), SignalingCodecError> {
    let valid = match kind {
        1 => role == 1,
        2 => role == 3,
        3 => role == 2,
        4 => transport == 1 && role == 2,
        5 => transport == 1 && role == 3,
        8 => transport == 2 && role == 1,
        9 => transport == 2 && (role == 2 || role == 3),
        10 => role == 2,
        11 => role == 3,
        6 | 7 => transport == 1 && (role == 2 || role == 3),
        12 | 14 => role == 2 || role == 3,
        13 => role == 1 || role == 3,
        15 => role == 1,
        _ => true,
    };
    valid.then_some(()).ok_or(SignalingCodecError::Combination)
}
fn terminal_payload(request: &RemoteSignalingEventRequestV1) -> Result<(), SignalingCodecError> {
    match request.event_kind {
        13 | 14 => {
            if request.payload.len() != 2 || request.payload[0] != 1 {
                return Err(SignalingCodecError::Length);
            }
            let allowed: &[u8] = if request.event_kind == 13 {
                &[1, 2, 3, 4, 6, 7, 9, 10, 11]
            } else {
                &[4, 5, 7, 8, 9, 10, 11]
            };
            if !allowed.contains(&request.payload[1]) {
                return Err(SignalingCodecError::Combination);
            }
        }
        15 => {
            let replacement: [u8; 16] = request
                .payload
                .as_slice()
                .try_into()
                .map_err(|_| SignalingCodecError::Length)?;
            nonzero(&replacement)?;
            if replacement == request.child_attempt_id {
                return Err(SignalingCodecError::Combination);
            }
        }
        _ => {}
    }
    Ok(())
}
impl RemoteSignalingEventRequestV1 {
    pub fn encode(&self) -> Result<Vec<u8>, SignalingCodecError> {
        if !(1..=2).contains(&self.transport)
            || !(1..=3).contains(&self.producer_role)
            || !(1..=15).contains(&self.event_kind)
        {
            return Err(SignalingCodecError::Discriminant);
        }
        nonzero(&self.child_attempt_id)?;
        nonzero(&self.event_id)?;
        combination(self.transport, self.producer_role, self.event_kind)?;
        terminal_payload(self)?;
        if self.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(SignalingCodecError::Length);
        }
        let mut out = Vec::with_capacity(HEADER_BYTES + self.payload.len());
        out.extend_from_slice(REQUEST_MAGIC);
        out.push(1);
        out.push(self.transport);
        out.push(self.producer_role);
        out.push(self.event_kind);
        out.extend_from_slice(&self.child_attempt_id);
        out.extend_from_slice(&self.event_id);
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, SignalingCodecError> {
        if bytes.len() < HEADER_BYTES || bytes.len() > MAX_REQUEST_BYTES {
            return Err(SignalingCodecError::Length);
        }
        if &bytes[..4] != REQUEST_MAGIC || bytes[4] != 1 {
            return Err(SignalingCodecError::Preamble);
        }
        let length = u32::from_be_bytes(bytes[40..44].try_into().unwrap()) as usize;
        if length > MAX_PAYLOAD_BYTES || HEADER_BYTES.checked_add(length) != Some(bytes.len()) {
            return Err(SignalingCodecError::Length);
        }
        let request = Self {
            transport: bytes[5],
            producer_role: bytes[6],
            event_kind: bytes[7],
            child_attempt_id: bytes[8..24].try_into().unwrap(),
            event_id: bytes[24..40].try_into().unwrap(),
            payload: bytes[44..].to_vec(),
        };
        if !(1..=2).contains(&request.transport)
            || !(1..=3).contains(&request.producer_role)
            || !(1..=15).contains(&request.event_kind)
        {
            return Err(SignalingCodecError::Discriminant);
        }
        nonzero(&request.child_attempt_id)?;
        nonzero(&request.event_id)?;
        combination(request.transport, request.producer_role, request.event_kind)?;
        terminal_payload(&request)?;
        Ok(request)
    }
    pub fn digest(bytes: &[u8]) -> Result<[u8; 32], SignalingCodecError> {
        Self::decode(bytes)?;
        let mut hash = Sha256::new();
        hash.update(b"flycockpit.remote.signaling-event-request.v1\0");
        hash.update(bytes);
        Ok(hash.finalize().into())
    }
}
impl RemoteSignalingCommitAckV1 {
    pub fn encode(&self) -> Result<[u8; 61], SignalingCodecError> {
        nonzero(&self.event_id)?;
        if self.sequence == 0 {
            return Err(SignalingCodecError::Length);
        }
        let mut out = [0; 61];
        out[..4].copy_from_slice(ACK_MAGIC);
        out[4] = 1;
        out[5..21].copy_from_slice(&self.event_id);
        out[21..29].copy_from_slice(&self.sequence.to_be_bytes());
        out[29..].copy_from_slice(&self.event_digest);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, SignalingCodecError> {
        if bytes.len() != 61 {
            return Err(SignalingCodecError::Length);
        }
        if &bytes[..4] != ACK_MAGIC || bytes[4] != 1 {
            return Err(SignalingCodecError::Preamble);
        }
        let ack = Self {
            event_id: bytes[5..21].try_into().unwrap(),
            sequence: u64::from_be_bytes(bytes[21..29].try_into().unwrap()),
            event_digest: bytes[29..61].try_into().unwrap(),
        };
        nonzero(&ack.event_id)?;
        if ack.sequence == 0 {
            return Err(SignalingCodecError::Length);
        }
        Ok(ack)
    }
}

pub fn final_proof_set_digest(
    client: &[u8],
    daemon: &[u8],
) -> Result<[u8; 32], SignalingCodecError> {
    if client.is_empty() || client.len() > 512 || daemon.is_empty() || daemon.len() > 512 {
        return Err(SignalingCodecError::Length);
    }
    let client_proof = RemoteEndpointFinalProofV1::decode(client)?;
    let daemon_proof = RemoteEndpointFinalProofV1::decode(daemon)?;
    if client_proof.role != 1
        || daemon_proof.role != 2
        || client_proof.agreement != daemon_proof.agreement
    {
        return Err(SignalingCodecError::Combination);
    }
    let mut hash = Sha256::new();
    hash.update(b"flycockpit.remote.endpoint-final-proof-set.v1\0");
    hash.update((client.len() as u16).to_be_bytes());
    hash.update(client);
    hash.update((daemon.len() as u16).to_be_bytes());
    hash.update(daemon);
    Ok(hash.finalize().into())
}
