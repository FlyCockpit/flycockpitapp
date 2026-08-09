use sha2::{Digest, Sha256};
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use zeroize::Zeroize;

use crate::frame::{HandshakeFrame, MAX_HANDSHAKE_MESSAGE};
use crate::prologue::RemoteNoisePrologueV1;
use crate::record::{MAX_CIPHERTEXT, MAX_PLAINTEXT, RecordKind, RemoteNoiseRecordV1};
use crate::rekey::{DirectionalRekey, RekeyAction, RekeyEvent};
use crate::{NoiseError, Result};

const SUITE: &str = "Noise_NN_25519_ChaChaPoly_SHA256";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointRole {
    ClientInitiator,
    DaemonResponder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandshakePhase {
    WriteOne,
    ReadOne,
    WriteTwo,
    ReadTwo,
    AwaitAuthorization,
    Transport,
    Closed,
}

pub struct TranscriptAuthorizationRequest<'a> {
    pub child_attempt_id: [u8; 16],
    pub transport_epoch: u32,
    pub handshake_hash: [u8; 32],
    pub prologue_digest: [u8; 32],
    pub connection_nonce: [u8; 32],
    pub initiator_ephemeral: [u8; 32],
    pub responder_ephemeral: [u8; 32],
    pub client_final_proof: &'a [u8],
    pub daemon_final_proof: &'a [u8],
}

pub trait TranscriptAuthorizationGate {
    fn authorize(
        &self,
        request: &TranscriptAuthorizationRequest<'_>,
    ) -> Result<AuthorizationCapability>;
}

#[derive(Debug)]
pub struct AuthorizationCapability {
    _private: (),
}

impl AuthorizationCapability {
    pub fn verified() -> Self {
        Self { _private: () }
    }
}

pub struct NoiseChild {
    role: EndpointRole,
    phase: HandshakePhase,
    prologue: RemoteNoisePrologueV1,
    transport_epoch: u32,
    handshake: Option<HandshakeState>,
    transport: Option<TransportState>,
    initiator_ephemeral: Option<[u8; 32]>,
    responder_ephemeral: Option<[u8; 32]>,
    send_sequence: u64,
    receive_sequence: u64,
    send_rekey: DirectionalRekey,
    receive_rekey: DirectionalRekey,
    pending_control_action: Option<RekeyAction>,
    last_control_ciphertext: Option<(RekeyAction, Vec<u8>)>,
    closed_due_to_failure: bool,
}

impl NoiseChild {
    pub fn initiator(prologue_bytes: &[u8], transport_epoch: u32) -> Result<Self> {
        Self::new(
            EndpointRole::ClientInitiator,
            prologue_bytes,
            transport_epoch,
        )
    }

    pub fn responder(prologue_bytes: &[u8], transport_epoch: u32) -> Result<Self> {
        Self::new(
            EndpointRole::DaemonResponder,
            prologue_bytes,
            transport_epoch,
        )
    }

    fn new(role: EndpointRole, prologue_bytes: &[u8], transport_epoch: u32) -> Result<Self> {
        let prologue = RemoteNoisePrologueV1::decode(prologue_bytes)?;
        let params = SUITE.parse().map_err(|_| NoiseError::CryptoUnavailable)?;
        let builder = Builder::new(params)
            .prologue(prologue_bytes)
            .map_err(|_| NoiseError::CryptoUnavailable)?;
        let handshake = match role {
            EndpointRole::ClientInitiator => builder.build_initiator(),
            EndpointRole::DaemonResponder => builder.build_responder(),
        }
        .map_err(|_| NoiseError::CryptoUnavailable)?;
        Ok(Self {
            role,
            phase: match role {
                EndpointRole::ClientInitiator => HandshakePhase::WriteOne,
                EndpointRole::DaemonResponder => HandshakePhase::ReadOne,
            },
            prologue,
            transport_epoch,
            handshake: Some(handshake),
            transport: None,
            initiator_ephemeral: None,
            responder_ephemeral: None,
            send_sequence: 0,
            receive_sequence: 0,
            send_rekey: DirectionalRekey::new(match role {
                EndpointRole::ClientInitiator => 1,
                EndpointRole::DaemonResponder => 2,
            })?,
            receive_rekey: DirectionalRekey::new(match role {
                EndpointRole::ClientInitiator => 2,
                EndpointRole::DaemonResponder => 1,
            })?,
            pending_control_action: None,
            last_control_ciphertext: None,
            closed_due_to_failure: false,
        })
    }

    pub fn write_handshake(&mut self) -> Result<Vec<u8>> {
        let index = match self.phase {
            HandshakePhase::WriteOne => 1,
            HandshakePhase::WriteTwo => 2,
            _ => return self.invalid_state(),
        };
        let state = self.handshake.as_mut().ok_or(NoiseError::InvalidState)?;
        let mut output = vec![0_u8; MAX_HANDSHAKE_MESSAGE];
        let written = match state.write_message(&[], &mut output) {
            Ok(written) => written,
            Err(_) => return self.fail(NoiseError::AuthenticationFailed),
        };
        output.truncate(written);
        if let Err(error) = Self::capture_ephemeral(
            index,
            &output,
            &mut self.initiator_ephemeral,
            &mut self.responder_ephemeral,
        ) {
            return self.fail(error);
        }
        self.phase = if index == 1 {
            HandshakePhase::ReadTwo
        } else {
            HandshakePhase::AwaitAuthorization
        };
        HandshakeFrame::encode(index, &output)
    }

    pub fn read_handshake(&mut self, framed: &[u8]) -> Result<()> {
        let expected = match self.phase {
            HandshakePhase::ReadOne => 1,
            HandshakePhase::ReadTwo => 2,
            _ => return self.invalid_state(),
        };
        let frame = match HandshakeFrame::decode(framed, expected) {
            Ok(frame) => frame,
            Err(error) => return self.fail(error),
        };
        if let Err(error) = Self::capture_ephemeral(
            expected,
            &frame.message,
            &mut self.initiator_ephemeral,
            &mut self.responder_ephemeral,
        ) {
            return self.fail(error);
        }
        let state = self.handshake.as_mut().ok_or(NoiseError::InvalidState)?;
        let mut payload = [0_u8; 1];
        let read = match state.read_message(&frame.message, &mut payload) {
            Ok(read) => read,
            Err(_) => return self.fail(NoiseError::AuthenticationFailed),
        };
        if read != 0 {
            return self.fail(NoiseError::HandshakePayloadForbidden);
        }
        self.phase = if expected == 1 {
            HandshakePhase::WriteTwo
        } else {
            HandshakePhase::AwaitAuthorization
        };
        Ok(())
    }

    fn capture_ephemeral(
        index: u8,
        message: &[u8],
        initiator: &mut Option<[u8; 32]>,
        responder: &mut Option<[u8; 32]>,
    ) -> Result<()> {
        let key: [u8; 32] = message
            .get(..32)
            .ok_or(NoiseError::InvalidHandshakeFrame)?
            .try_into()
            .map_err(|_| NoiseError::InvalidHandshakeFrame)?;
        if key.iter().all(|byte| *byte == 0) {
            return Err(NoiseError::LowOrderKey);
        }
        let slot = if index == 1 { initiator } else { responder };
        if slot.replace(key).is_some() {
            return Err(NoiseError::InvalidState);
        }
        Ok(())
    }

    pub fn authorize<G: TranscriptAuthorizationGate>(
        &mut self,
        gate: &G,
        client_final_proof: &[u8],
        daemon_final_proof: &[u8],
    ) -> Result<()> {
        if self.phase != HandshakePhase::AwaitAuthorization
            || client_final_proof.is_empty()
            || daemon_final_proof.is_empty()
        {
            return self.fail(NoiseError::AuthorizationDenied);
        }
        let state = self.handshake.as_ref().ok_or(NoiseError::InvalidState)?;
        if !state.is_handshake_finished() {
            return self.invalid_state();
        }
        let handshake_hash: [u8; 32] = state
            .get_handshake_hash()
            .try_into()
            .map_err(|_| NoiseError::InvalidState)?;
        let request = TranscriptAuthorizationRequest {
            child_attempt_id: self.prologue.child_attempt_id,
            transport_epoch: self.transport_epoch,
            handshake_hash,
            prologue_digest: self.prologue.digest(),
            connection_nonce: self.prologue.connection_nonce,
            initiator_ephemeral: self.initiator_ephemeral.ok_or(NoiseError::InvalidState)?,
            responder_ephemeral: self.responder_ephemeral.ok_or(NoiseError::InvalidState)?,
            client_final_proof,
            daemon_final_proof,
        };
        let _capability = match gate.authorize(&request) {
            Ok(capability) => capability,
            Err(_) => return self.fail(NoiseError::AuthorizationDenied),
        };
        let handshake = self.handshake.take().ok_or(NoiseError::InvalidState)?;
        self.transport = Some(match handshake.into_transport_mode() {
            Ok(transport) => transport,
            Err(_) => return self.fail(NoiseError::AuthenticationFailed),
        });
        self.phase = HandshakePhase::Transport;
        Ok(())
    }

    pub fn encrypt_record(&mut self, kind: RecordKind, payload: &[u8]) -> Result<Vec<u8>> {
        if self.phase != HandshakePhase::Transport {
            return self.invalid_state();
        }
        let actions = match self.send_rekey.reduce(RekeyEvent::LocalRecordRequest {
            kind,
            data_bytes: u64::try_from(payload.len()).map_err(|_| NoiseError::RecordTooLarge)?,
        }) {
            Ok(actions) => actions,
            Err(error) => return self.fail(error),
        };
        let sequence = actions
            .iter()
            .find_map(|action| match action {
                RekeyAction::Open { sequence, .. } => Some(*sequence),
                _ => None,
            })
            .ok_or(NoiseError::BudgetExceeded)?;
        if sequence != self.send_sequence {
            return self.fail(NoiseError::SequenceMismatch);
        }
        let plaintext = RemoteNoiseRecordV1 {
            kind,
            sequence,
            payload: payload.to_vec(),
        }
        .encode_plaintext()?;
        let state = self.transport.as_mut().ok_or(NoiseError::InvalidState)?;
        let mut ciphertext = vec![0_u8; MAX_CIPHERTEXT];
        let written = match state.write_message(&plaintext, &mut ciphertext) {
            Ok(written) => written,
            Err(_) => return self.fail(NoiseError::AuthenticationFailed),
        };
        if written > MAX_CIPHERTEXT {
            return self.fail(NoiseError::RecordTooLarge);
        }
        ciphertext.truncate(written);
        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or(NoiseError::SequenceExhausted)?;
        Ok(ciphertext)
    }

    pub fn decrypt_record(
        &mut self,
        routing_sequence: u64,
        ciphertext: &[u8],
    ) -> Result<RemoteNoiseRecordV1> {
        if self.phase != HandshakePhase::Transport {
            return self.invalid_state();
        }
        if ciphertext.len() > MAX_CIPHERTEXT {
            return self.fail(NoiseError::RecordTooLarge);
        }
        if routing_sequence != self.receive_sequence {
            return self.fail(NoiseError::SequenceMismatch);
        }
        let state = self.transport.as_mut().ok_or(NoiseError::InvalidState)?;
        let mut plaintext = vec![0_u8; MAX_PLAINTEXT];
        let read = match state.read_message(ciphertext, &mut plaintext) {
            Ok(read) => read,
            Err(_) => {
                plaintext.zeroize();
                return self.fail(NoiseError::AuthenticationFailed);
            }
        };
        plaintext.truncate(read);
        let record = match RemoteNoiseRecordV1::decode_plaintext(&plaintext, routing_sequence) {
            Ok(record) => record,
            Err(error) => {
                plaintext.zeroize();
                return self.fail(error);
            }
        };
        if let Err(error) = self.receive_rekey.admit_authenticated_peer_record(
            record.kind,
            u64::try_from(record.payload.len()).map_err(|_| NoiseError::RecordTooLarge)?,
        ) {
            plaintext.zeroize();
            return self.fail(error);
        }
        self.receive_sequence = self
            .receive_sequence
            .checked_add(1)
            .ok_or(NoiseError::SequenceExhausted)?;
        plaintext.zeroize();
        Ok(record)
    }

    /// Encrypts a reducer-emitted rekey control action exactly once.
    /// Repeating the identical action returns the retained ciphertext without
    /// advancing Snow or the absolute sequence a second time.
    pub fn encrypt_rekey_action(&mut self, action: &RekeyAction) -> Result<Vec<u8>> {
        if self.phase != HandshakePhase::Transport {
            return self.invalid_state();
        }
        if let Some((prior, ciphertext)) = &self.last_control_ciphertext
            && prior == action
        {
            return Ok(ciphertext.clone());
        }
        if self.pending_control_action.as_ref() != Some(action) {
            return self.fail(NoiseError::InvalidRekey);
        }
        let (kind, sequence, payload) = match action {
            RekeyAction::SendPrepare(prepare) => {
                let sequence = self
                    .send_rekey
                    .absolute_sequence
                    .checked_sub(1)
                    .ok_or(NoiseError::InvalidRekey)?;
                (
                    RecordKind::RekeyPrepare,
                    sequence,
                    prepare.encode().to_vec(),
                )
            }
            RekeyAction::SendCommit {
                direction,
                key_epoch,
            } => {
                let sequence = match self.send_rekey.reserve_generated_commit() {
                    Ok(sequence) => sequence,
                    Err(error) => return self.fail(error),
                };
                let mut payload = Vec::with_capacity(5);
                payload.push(*direction);
                payload.extend_from_slice(&key_epoch.to_be_bytes());
                (RecordKind::RekeyCommit, sequence, payload)
            }
            _ => return self.fail(NoiseError::InvalidRekey),
        };
        if sequence != self.send_sequence {
            return self.fail(NoiseError::SequenceMismatch);
        }
        let plaintext = RemoteNoiseRecordV1 {
            kind,
            sequence,
            payload,
        }
        .encode_plaintext()?;
        let mut ciphertext = vec![0_u8; MAX_CIPHERTEXT];
        let written = match self
            .transport
            .as_mut()
            .ok_or(NoiseError::InvalidState)?
            .write_message(&plaintext, &mut ciphertext)
        {
            Ok(written) => written,
            Err(_) => return self.fail(NoiseError::AuthenticationFailed),
        };
        ciphertext.truncate(written);
        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or(NoiseError::SequenceExhausted)?;
        self.last_control_ciphertext = Some((action.clone(), ciphertext.clone()));
        self.pending_control_action = None;
        Ok(ciphertext)
    }

    pub fn handle_send_rekey_event(&mut self, event: RekeyEvent) -> Result<Vec<RekeyAction>> {
        if self.phase != HandshakePhase::Transport {
            return self.invalid_state();
        }
        let actions = match self.send_rekey.reduce(event) {
            Ok(actions) => actions,
            Err(error) => return self.fail(error),
        };
        for action in &actions {
            match action {
                RekeyAction::SendPrepare(_) => self.pending_control_action = Some(action.clone()),
                RekeyAction::ApplySendRekey { .. } => self
                    .transport
                    .as_mut()
                    .ok_or(NoiseError::InvalidState)?
                    .rekey_outgoing(),
                RekeyAction::ApplyReceiveRekey { .. } => {
                    return self.invalid_state();
                }
                _ => {}
            }
        }
        Ok(actions)
    }

    pub fn handle_receive_rekey_event(&mut self, event: RekeyEvent) -> Result<Vec<RekeyAction>> {
        if self.phase != HandshakePhase::Transport {
            return self.invalid_state();
        }
        let actions = match self.receive_rekey.reduce(event) {
            Ok(actions) => actions,
            Err(error) => return self.fail(error),
        };
        for action in &actions {
            match action {
                RekeyAction::SendCommit { .. } => {
                    self.pending_control_action = Some(action.clone())
                }
                RekeyAction::ApplyReceiveRekey { .. } => self
                    .transport
                    .as_mut()
                    .ok_or(NoiseError::InvalidState)?
                    .rekey_incoming(),
                RekeyAction::ApplySendRekey { .. } => return self.invalid_state(),
                _ => {}
            }
        }
        Ok(actions)
    }

    pub fn close(&mut self) {
        self.handshake = None;
        self.transport = None;
        self.phase = HandshakePhase::Closed;
        self.send_sequence = 0;
        self.receive_sequence = 0;
        self.last_control_ciphertext = None;
        self.pending_control_action = None;
    }

    #[must_use]
    pub fn handshake_hash(&self) -> Option<[u8; 32]> {
        let hash = self.handshake.as_ref()?.get_handshake_hash();
        hash.try_into().ok()
    }

    #[must_use]
    pub fn endpoint_role(&self) -> EndpointRole {
        self.role
    }

    fn fail<T>(&mut self, error: NoiseError) -> Result<T> {
        let closed_due_to_failure = self.phase == HandshakePhase::Transport;
        self.close();
        self.closed_due_to_failure = closed_due_to_failure;
        Err(error)
    }

    fn invalid_state<T>(&mut self) -> Result<T> {
        if self.phase == HandshakePhase::Closed && self.closed_due_to_failure {
            Err(NoiseError::Closed)
        } else {
            self.fail(NoiseError::InvalidState)
        }
    }
}

/// Executes a normative Noise vector with deterministic ephemeral keys.
///
/// This seam is deliberately absent unless the non-production `test-entropy`
/// feature is selected. Production constructors always validate FCNP and use
/// Snow's CSPRNG resolver.
#[cfg(feature = "test-entropy")]
pub fn run_nn_test_vector(
    prologue: &[u8],
    initiator_ephemeral: &[u8; 32],
    responder_ephemeral: &[u8; 32],
    payloads: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>> {
    if payloads.len() < 2 {
        return Err(NoiseError::InvalidHandshakeFrame);
    }
    let params: NoiseParams = SUITE.parse().map_err(|_| NoiseError::CryptoUnavailable)?;
    let mut initiator = Builder::new(params.clone())
        .prologue(prologue)
        .map_err(|_| NoiseError::CryptoUnavailable)?
        .fixed_ephemeral_key_for_testing_only(initiator_ephemeral)
        .build_initiator()
        .map_err(|_| NoiseError::CryptoUnavailable)?;
    let mut responder = Builder::new(params)
        .prologue(prologue)
        .map_err(|_| NoiseError::CryptoUnavailable)?
        .fixed_ephemeral_key_for_testing_only(responder_ephemeral)
        .build_responder()
        .map_err(|_| NoiseError::CryptoUnavailable)?;
    let mut result = Vec::with_capacity(payloads.len());
    let mut message = vec![0_u8; MAX_CIPHERTEXT];
    let mut plaintext = vec![0_u8; MAX_PLAINTEXT];

    let first = initiator
        .write_message(&payloads[0], &mut message)
        .map_err(|_| NoiseError::AuthenticationFailed)?;
    result.push(message[..first].to_vec());
    let read = responder
        .read_message(&message[..first], &mut plaintext)
        .map_err(|_| NoiseError::AuthenticationFailed)?;
    if plaintext[..read] != payloads[0] {
        return Err(NoiseError::AuthenticationFailed);
    }

    let second = responder
        .write_message(&payloads[1], &mut message)
        .map_err(|_| NoiseError::AuthenticationFailed)?;
    result.push(message[..second].to_vec());
    let read = initiator
        .read_message(&message[..second], &mut plaintext)
        .map_err(|_| NoiseError::AuthenticationFailed)?;
    if plaintext[..read] != payloads[1] {
        return Err(NoiseError::AuthenticationFailed);
    }

    let mut initiator = initiator
        .into_transport_mode()
        .map_err(|_| NoiseError::AuthenticationFailed)?;
    let mut responder = responder
        .into_transport_mode()
        .map_err(|_| NoiseError::AuthenticationFailed)?;
    for (index, payload) in payloads[2..].iter().enumerate() {
        let (sender, receiver) = if index % 2 == 0 {
            (&mut initiator, &mut responder)
        } else {
            (&mut responder, &mut initiator)
        };
        let written = sender
            .write_message(payload, &mut message)
            .map_err(|_| NoiseError::AuthenticationFailed)?;
        result.push(message[..written].to_vec());
        let read = receiver
            .read_message(&message[..written], &mut plaintext)
            .map_err(|_| NoiseError::AuthenticationFailed)?;
        if plaintext[..read] != *payload.as_slice() {
            return Err(NoiseError::AuthenticationFailed);
        }
    }
    plaintext.zeroize();
    message.zeroize();
    Ok(result)
}

impl Drop for NoiseChild {
    fn drop(&mut self) {
        self.close();
    }
}

#[must_use]
pub fn final_proof_binding_bytes(
    role: u8,
    child_attempt_id: [u8; 16],
    transport_epoch: u32,
    initiator_ephemeral: [u8; 32],
    responder_ephemeral: [u8; 32],
    prologue_digest: [u8; 32],
    handshake_hash: [u8; 32],
    connection_nonce: [u8; 32],
    grant_digest: [u8; 32],
    policy_digest: [u8; 32],
    peer_certificate_generation: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(286);
    bytes.extend_from_slice(b"flycockpit-remote-endpoint-final-proof-noise-v1\0");
    bytes.push(role);
    bytes.extend_from_slice(&child_attempt_id);
    bytes.extend_from_slice(&transport_epoch.to_be_bytes());
    bytes.extend_from_slice(&initiator_ephemeral);
    bytes.extend_from_slice(&responder_ephemeral);
    bytes.extend_from_slice(&prologue_digest);
    bytes.extend_from_slice(&handshake_hash);
    bytes.extend_from_slice(&connection_nonce);
    bytes.extend_from_slice(&grant_digest);
    bytes.extend_from_slice(&policy_digest);
    bytes.extend_from_slice(&peer_certificate_generation.to_be_bytes());
    bytes
}

#[must_use]
pub fn final_proof_binding_digest(
    role: u8,
    child_attempt_id: [u8; 16],
    transport_epoch: u32,
    initiator_ephemeral: [u8; 32],
    responder_ephemeral: [u8; 32],
    prologue_digest: [u8; 32],
    handshake_hash: [u8; 32],
    connection_nonce: [u8; 32],
    grant_digest: [u8; 32],
    policy_digest: [u8; 32],
    peer_certificate_generation: u64,
) -> [u8; 32] {
    Sha256::digest(final_proof_binding_bytes(
        role,
        child_attempt_id,
        transport_epoch,
        initiator_ephemeral,
        responder_ephemeral,
        prologue_digest,
        handshake_hash,
        connection_nonce,
        grant_digest,
        policy_digest,
        peer_certificate_generation,
    ))
    .into()
}
