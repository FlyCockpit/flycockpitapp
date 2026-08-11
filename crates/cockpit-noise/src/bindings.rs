use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::{
    AuthorizationCapability, FallbackReceiveWindow, FallbackSendWindow, NoiseChild,
    ReceiveDisposition, RecordKind, TranscriptAuthorizationGate, TranscriptAuthorizationRequest,
};

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static HANDLES: OnceLock<Mutex<HashMap<u64, NoiseChild>>> = OnceLock::new();
static FALLBACK_HANDLES: OnceLock<Mutex<HashMap<u64, FallbackBindingState>>> = OnceLock::new();

struct FallbackBindingState {
    receive: FallbackReceiveWindow,
    send: FallbackSendWindow,
}

fn handles() -> &'static Mutex<HashMap<u64, NoiseChild>> {
    HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}
fn fallback_handles() -> &'static Mutex<HashMap<u64, FallbackBindingState>> {
    FALLBACK_HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug, thiserror::Error)]
pub enum NoiseBindingError {
    #[error("invalid_input")]
    InvalidInput,
    #[error("invalid_state")]
    InvalidState,
    #[error("authentication_failed")]
    AuthenticationFailed,
    #[error("closed")]
    Closed,
    #[error("internal")]
    Internal,
}

#[derive(Clone, Debug)]
pub struct BindingAuthorizationRequest {
    pub child_attempt_id: Vec<u8>,
    pub transport_epoch: u32,
    pub handshake_hash: Vec<u8>,
    pub prologue_digest: Vec<u8>,
    pub connection_nonce: Vec<u8>,
    pub initiator_ephemeral: Vec<u8>,
    pub responder_ephemeral: Vec<u8>,
    pub client_final_proof: Vec<u8>,
    pub daemon_final_proof: Vec<u8>,
}

pub trait BindingAuthorizationGate: Send + Sync {
    fn authorize(&self, request: BindingAuthorizationRequest) -> bool;
}

struct GateAdapter(Box<dyn BindingAuthorizationGate>);

impl TranscriptAuthorizationGate for GateAdapter {
    fn authorize(
        &self,
        request: &TranscriptAuthorizationRequest<'_>,
    ) -> crate::Result<AuthorizationCapability> {
        let allowed = self.0.authorize(BindingAuthorizationRequest {
            child_attempt_id: request.child_attempt_id.to_vec(),
            transport_epoch: request.transport_epoch,
            handshake_hash: request.handshake_hash.to_vec(),
            prologue_digest: request.prologue_digest.to_vec(),
            connection_nonce: request.connection_nonce.to_vec(),
            initiator_ephemeral: request.initiator_ephemeral.to_vec(),
            responder_ephemeral: request.responder_ephemeral.to_vec(),
            client_final_proof: request.client_final_proof.to_vec(),
            daemon_final_proof: request.daemon_final_proof.to_vec(),
        });
        allowed
            .then(AuthorizationCapability::verified)
            .ok_or(crate::NoiseError::AuthorizationDenied)
    }
}

impl From<crate::NoiseError> for NoiseBindingError {
    fn from(value: crate::NoiseError) -> Self {
        match value {
            crate::NoiseError::AuthenticationFailed | crate::NoiseError::LowOrderKey => {
                Self::AuthenticationFailed
            }
            crate::NoiseError::Closed => Self::Closed,
            crate::NoiseError::InvalidPrologue
            | crate::NoiseError::InvalidHandshakeFrame
            | crate::NoiseError::InvalidRecord
            | crate::NoiseError::RecordTooLarge => Self::InvalidInput,
            _ => Self::InvalidState,
        }
    }
}

pub fn noise_create_initiator(
    prologue: Vec<u8>,
    transport_epoch: u32,
) -> Result<u64, NoiseBindingError> {
    insert(NoiseChild::initiator(&prologue, transport_epoch)?)
}

pub fn noise_create_responder(
    prologue: Vec<u8>,
    transport_epoch: u32,
) -> Result<u64, NoiseBindingError> {
    insert(NoiseChild::responder(&prologue, transport_epoch)?)
}

fn insert(child: NoiseChild) -> Result<u64, NoiseBindingError> {
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    if handle == 0 {
        return Err(NoiseBindingError::Internal);
    }
    handles()
        .lock()
        .map_err(|_| NoiseBindingError::Internal)?
        .insert(handle, child);
    Ok(handle)
}

pub fn noise_write_handshake(handle: u64) -> Result<Vec<u8>, NoiseBindingError> {
    with_handle(handle, NoiseChild::write_handshake)
}

pub fn noise_read_handshake(handle: u64, frame: Vec<u8>) -> Result<(), NoiseBindingError> {
    with_handle(handle, |child| child.read_handshake(&frame))
}

pub fn noise_handshake_hash(handle: u64) -> Result<Vec<u8>, NoiseBindingError> {
    with_handle(handle, |child| {
        child
            .handshake_hash()
            .map(|hash| hash.to_vec())
            .ok_or(crate::NoiseError::InvalidState)
    })
}

pub fn noise_authorize(
    handle: u64,
    client_final_proof: Vec<u8>,
    daemon_final_proof: Vec<u8>,
    gate: Box<dyn BindingAuthorizationGate>,
) -> Result<(), NoiseBindingError> {
    with_handle(handle, |child| {
        child.authorize(&GateAdapter(gate), &client_final_proof, &daemon_final_proof)
    })
}

pub fn noise_encrypt_record(
    handle: u64,
    kind: u8,
    payload: Vec<u8>,
) -> Result<Vec<u8>, NoiseBindingError> {
    let kind = RecordKind::try_from(kind)?;
    with_handle(handle, |child| child.encrypt_record(kind, &payload))
}

pub fn noise_encrypt_fallback_record(
    handle: u64,
    kind: u8,
    route_generation: u64,
    direction: u8,
    peer_seen_through: u64,
    payload: Vec<u8>,
) -> Result<Vec<u8>, NoiseBindingError> {
    if route_generation == 0 {
        return Err(NoiseBindingError::InvalidInput);
    }
    let kind = RecordKind::try_from(kind)?;
    let direction = crate::FallbackDirection::try_from(direction)?;
    with_handle(handle, |child| {
        if child.fallback_route_generation() != Some(route_generation) {
            child.close();
            return Err(crate::NoiseError::InvalidFallback);
        }
        let expected = match child.endpoint_role() {
            crate::EndpointRole::ClientInitiator => crate::FallbackDirection::ClientToDaemon,
            crate::EndpointRole::DaemonResponder => crate::FallbackDirection::DaemonToClient,
        };
        if direction != expected {
            child.close();
            return Err(crate::NoiseError::InvalidFallback);
        }
        let sequence = child.next_send_sequence();
        let mut authenticated_payload = Vec::with_capacity(8 + payload.len());
        authenticated_payload.extend_from_slice(&peer_seen_through.to_be_bytes());
        authenticated_payload.extend_from_slice(&payload);
        let ciphertext = child.encrypt_record(kind, &authenticated_payload)?;
        crate::FallbackOuterRecordV1 {
            route_generation,
            direction,
            record_sequence: sequence,
            peer_seen_through,
            ciphertext,
        }
        .encode()
    })
}

pub fn noise_encrypt_fallback_rekey_action(
    handle: u64,
    kind: u8,
    route_generation: u64,
    direction: u8,
    peer_seen_through: u64,
    control_payload: Vec<u8>,
) -> Result<Vec<u8>, NoiseBindingError> {
    let direction = crate::FallbackDirection::try_from(direction)?;
    let action = match RecordKind::try_from(kind)? {
        RecordKind::RekeyPrepare => {
            crate::RekeyAction::SendPrepare(crate::RekeyPrepareV1::decode(&control_payload)?)
        }
        RecordKind::RekeyCommit if control_payload.len() == 5 => crate::RekeyAction::SendCommit {
            direction: control_payload[0],
            key_epoch: u32::from_be_bytes(
                control_payload[1..5]
                    .try_into()
                    .map_err(|_| NoiseBindingError::InvalidInput)?,
            ),
        },
        _ => return Err(NoiseBindingError::InvalidInput),
    };
    with_handle(handle, |child| {
        if route_generation == 0 || child.fallback_route_generation() != Some(route_generation) {
            child.close();
            return Err(crate::NoiseError::InvalidFallback);
        }
        let expected = match child.endpoint_role() {
            crate::EndpointRole::ClientInitiator => crate::FallbackDirection::ClientToDaemon,
            crate::EndpointRole::DaemonResponder => crate::FallbackDirection::DaemonToClient,
        };
        if direction != expected {
            child.close();
            return Err(crate::NoiseError::InvalidFallback);
        }
        let sequence = child.next_send_sequence();
        let ciphertext =
            child.encrypt_rekey_action_with_prefix(&action, &peer_seen_through.to_be_bytes())?;
        crate::FallbackOuterRecordV1 {
            route_generation,
            direction,
            record_sequence: sequence,
            peer_seen_through,
            ciphertext,
        }
        .encode()
    })
}

pub fn noise_decrypt_record(
    handle: u64,
    routing_sequence: u64,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, NoiseBindingError> {
    with_handle(handle, |child| {
        child
            .decrypt_record(routing_sequence, &ciphertext)
            .and_then(|record| record.encode_plaintext())
    })
}

pub fn noise_decrypt_fallback_record(
    handle: u64,
    outer_bytes: Vec<u8>,
) -> Result<Vec<u8>, NoiseBindingError> {
    let outer = crate::FallbackOuterRecordV1::decode(&outer_bytes)?;
    with_handle(handle, |child| {
        if child.fallback_route_generation() != Some(outer.route_generation) {
            child.close();
            return Err(crate::NoiseError::InvalidFallback);
        }
        let expected = match child.endpoint_role() {
            crate::EndpointRole::ClientInitiator => crate::FallbackDirection::DaemonToClient,
            crate::EndpointRole::DaemonResponder => crate::FallbackDirection::ClientToDaemon,
        };
        if outer.direction != expected {
            child.close();
            return Err(crate::NoiseError::InvalidFallback);
        }
        let record = child.decrypt_record(outer.record_sequence, &outer.ciphertext)?;
        crate::validate_authenticated_outer(&outer, &record)?;
        record.encode_plaintext()
    })
}

pub fn noise_bind_fallback_route(
    handle: u64,
    route_generation: u64,
) -> Result<(), NoiseBindingError> {
    with_handle(handle, |child| {
        child.bind_fallback_route_generation(route_generation)
    })
}

fn with_handle<T>(
    handle: u64,
    callback: impl FnOnce(&mut NoiseChild) -> crate::Result<T>,
) -> Result<T, NoiseBindingError> {
    let mut guard = handles().lock().map_err(|_| NoiseBindingError::Internal)?;
    let child = guard.get_mut(&handle).ok_or(NoiseBindingError::Closed)?;
    callback(child).map_err(Into::into)
}

pub fn noise_close(handle: u64) {
    if let Ok(mut guard) = handles().lock()
        && let Some(mut child) = guard.remove(&handle)
    {
        child.close();
    }
}

pub fn fallback_create(now_millis: u64) -> Result<u64, NoiseBindingError> {
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    if handle == 0 {
        return Err(NoiseBindingError::Internal);
    }
    fallback_handles()
        .lock()
        .map_err(|_| NoiseBindingError::Internal)?
        .insert(
            handle,
            FallbackBindingState {
                receive: FallbackReceiveWindow::new(now_millis),
                send: FallbackSendWindow::new(),
            },
        );
    Ok(handle)
}

fn encode_byte_list(values: &[&[u8]]) -> Result<Vec<u8>, NoiseBindingError> {
    let count = u16::try_from(values.len()).map_err(|_| NoiseBindingError::Internal)?;
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_be_bytes());
    for value in values {
        out.extend_from_slice(
            &u32::try_from(value.len())
                .map_err(|_| NoiseBindingError::Internal)?
                .to_be_bytes(),
        );
        out.extend_from_slice(value);
    }
    Ok(out)
}

pub fn fallback_observe(handle: u64, outer_record: Vec<u8>) -> Result<Vec<u8>, NoiseBindingError> {
    let mut guard = fallback_handles()
        .lock()
        .map_err(|_| NoiseBindingError::Internal)?;
    let state = guard.get_mut(&handle).ok_or(NoiseBindingError::Closed)?;
    match state.receive.observe(outer_record)? {
        ReceiveDisposition::Buffered => {
            let mut out = vec![0];
            out.extend_from_slice(&state.receive.ack().encode());
            Ok(out)
        }
        ReceiveDisposition::Duplicate { acknowledge } => {
            let mut out = vec![1];
            out.extend_from_slice(&acknowledge.encode());
            Ok(out)
        }
        ReceiveDisposition::Contiguous(records) => {
            let gap_filled = records.len() > 1;
            let encoded: Result<Vec<Vec<u8>>, _> = records
                .iter()
                .map(crate::FallbackOuterRecordV1::encode)
                .collect();
            let encoded = encoded?;
            let borrowed: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
            let mut out = vec![2];
            out.push(u8::from(gap_filled));
            if gap_filled {
                out.extend_from_slice(&state.receive.ack().encode());
            }
            out.extend_from_slice(&encode_byte_list(&borrowed)?);
            Ok(out)
        }
    }
}

pub fn fallback_ack_due(
    handle: u64,
    now_millis: u64,
    immediate: bool,
    received_ack_only: bool,
) -> Result<Vec<u8>, NoiseBindingError> {
    let mut guard = fallback_handles()
        .lock()
        .map_err(|_| NoiseBindingError::Internal)?;
    let state = guard.get_mut(&handle).ok_or(NoiseBindingError::Closed)?;
    Ok(state
        .receive
        .ack_due(now_millis, immediate, received_ack_only)
        .map(|ack| ack.encode().to_vec())
        .unwrap_or_default())
}

pub fn fallback_cache_outgoing(
    handle: u64,
    sequence: u64,
    ciphertext: Vec<u8>,
    kind: u8,
) -> Result<(), NoiseBindingError> {
    let kind = RecordKind::try_from(kind)?;
    let mut guard = fallback_handles()
        .lock()
        .map_err(|_| NoiseBindingError::Internal)?;
    guard
        .get_mut(&handle)
        .ok_or(NoiseBindingError::Closed)?
        .send
        .insert(sequence, ciphertext, kind != RecordKind::Ack)
        .map_err(Into::into)
}

pub fn fallback_acknowledge(handle: u64, largest_contiguous: u64) -> Result<(), NoiseBindingError> {
    let mut guard = fallback_handles()
        .lock()
        .map_err(|_| NoiseBindingError::Internal)?;
    guard
        .get_mut(&handle)
        .ok_or(NoiseBindingError::Closed)?
        .send
        .acknowledge(largest_contiguous)
        .map_err(Into::into)
}

pub fn fallback_gap_retransmit(
    handle: u64,
    next_missing: u64,
) -> Result<Vec<u8>, NoiseBindingError> {
    let guard = fallback_handles()
        .lock()
        .map_err(|_| NoiseBindingError::Internal)?;
    let values = guard
        .get(&handle)
        .ok_or(NoiseBindingError::Closed)?
        .send
        .retransmit_from(next_missing);
    encode_byte_list(&values)
}

pub fn fallback_retry_due(handle: u64, elapsed_millis: u64) -> Result<Vec<u8>, NoiseBindingError> {
    let mut guard = fallback_handles()
        .lock()
        .map_err(|_| NoiseBindingError::Internal)?;
    let values = guard
        .get_mut(&handle)
        .ok_or(NoiseBindingError::Closed)?
        .send
        .retry_due(elapsed_millis)?;
    encode_byte_list(&values)
}

pub fn fallback_close(handle: u64) {
    if let Ok(mut guard) = fallback_handles().lock() {
        guard.remove(&handle);
    }
}

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
mod wasm {
    use js_sys::{Array, Function, Uint8Array};
    use wasm_bindgen::prelude::*;

    struct JsGate(Function);

    impl crate::TranscriptAuthorizationGate for JsGate {
        fn authorize(
            &self,
            request: &crate::TranscriptAuthorizationRequest<'_>,
        ) -> crate::Result<crate::AuthorizationCapability> {
            let fields = Array::new();
            let transport_epoch = request.transport_epoch.to_be_bytes();
            for field in [
                request.child_attempt_id.as_slice(),
                transport_epoch.as_slice(),
                request.handshake_hash.as_slice(),
                request.prologue_digest.as_slice(),
                request.connection_nonce.as_slice(),
                request.initiator_ephemeral.as_slice(),
                request.responder_ephemeral.as_slice(),
                request.client_final_proof,
                request.daemon_final_proof,
            ] {
                fields.push(&Uint8Array::from(field));
            }
            let allowed = self
                .0
                .call1(&JsValue::NULL, &fields)
                .ok()
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            allowed
                .then(crate::AuthorizationCapability::verified)
                .ok_or(crate::NoiseError::AuthorizationDenied)
        }
    }

    #[wasm_bindgen(js_name = createInitiator)]
    pub fn create_initiator(prologue: Vec<u8>, transport_epoch: u32) -> Result<u64, JsError> {
        super::noise_create_initiator(prologue, transport_epoch)
            .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = createResponder)]
    pub fn create_responder(prologue: Vec<u8>, transport_epoch: u32) -> Result<u64, JsError> {
        super::noise_create_responder(prologue, transport_epoch)
            .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = writeHandshake)]
    pub fn write_handshake(handle: u64) -> Result<Vec<u8>, JsError> {
        super::noise_write_handshake(handle).map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = readHandshake)]
    pub fn read_handshake(handle: u64, frame: Vec<u8>) -> Result<(), JsError> {
        super::noise_read_handshake(handle, frame).map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = handshakeHash)]
    pub fn handshake_hash(handle: u64) -> Result<Vec<u8>, JsError> {
        super::noise_handshake_hash(handle).map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = authorize)]
    pub fn authorize(
        handle: u64,
        client_final_proof: Vec<u8>,
        daemon_final_proof: Vec<u8>,
        gate: Function,
    ) -> Result<(), JsError> {
        super::with_handle(handle, |child| {
            child.authorize(&JsGate(gate), &client_final_proof, &daemon_final_proof)
        })
        .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = encryptRecord)]
    pub fn encrypt_record(handle: u64, kind: u8, payload: Vec<u8>) -> Result<Vec<u8>, JsError> {
        super::noise_encrypt_record(handle, kind, payload)
            .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = encryptFallbackRecord)]
    pub fn encrypt_fallback_record(
        handle: u64,
        kind: u8,
        route_generation: u64,
        direction: u8,
        peer_seen_through: u64,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, JsError> {
        super::noise_encrypt_fallback_record(
            handle,
            kind,
            route_generation,
            direction,
            peer_seen_through,
            payload,
        )
        .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = bindFallbackRoute)]
    pub fn bind_fallback_route(handle: u64, route_generation: u64) -> Result<(), JsError> {
        super::noise_bind_fallback_route(handle, route_generation)
            .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = encryptFallbackRekeyAction)]
    pub fn encrypt_fallback_rekey_action(
        handle: u64,
        kind: u8,
        route_generation: u64,
        direction: u8,
        peer_seen_through: u64,
        control_payload: Vec<u8>,
    ) -> Result<Vec<u8>, JsError> {
        super::noise_encrypt_fallback_rekey_action(
            handle,
            kind,
            route_generation,
            direction,
            peer_seen_through,
            control_payload,
        )
        .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = decryptRecord)]
    pub fn decrypt_record(
        handle: u64,
        routing_sequence: u64,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, JsError> {
        super::noise_decrypt_record(handle, routing_sequence, ciphertext)
            .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = decryptFallbackRecord)]
    pub fn decrypt_fallback_record(handle: u64, outer_record: Vec<u8>) -> Result<Vec<u8>, JsError> {
        super::noise_decrypt_fallback_record(handle, outer_record)
            .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = close)]
    pub fn close(handle: u64) {
        super::noise_close(handle);
    }

    #[wasm_bindgen(js_name = fallbackCreate)]
    pub fn fallback_create(now_millis: u64) -> Result<u64, JsError> {
        super::fallback_create(now_millis).map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = fallbackObserve)]
    pub fn fallback_observe(handle: u64, outer_record: Vec<u8>) -> Result<Vec<u8>, JsError> {
        super::fallback_observe(handle, outer_record)
            .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = fallbackAckDue)]
    pub fn fallback_ack_due(
        handle: u64,
        now_millis: u64,
        immediate: bool,
        received_ack_only: bool,
    ) -> Result<Vec<u8>, JsError> {
        super::fallback_ack_due(handle, now_millis, immediate, received_ack_only)
            .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = fallbackCacheOutgoing)]
    pub fn fallback_cache_outgoing(
        handle: u64,
        sequence: u64,
        ciphertext: Vec<u8>,
        kind: u8,
    ) -> Result<(), JsError> {
        super::fallback_cache_outgoing(handle, sequence, ciphertext, kind)
            .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = fallbackAcknowledge)]
    pub fn fallback_acknowledge(handle: u64, largest_contiguous: u64) -> Result<(), JsError> {
        super::fallback_acknowledge(handle, largest_contiguous)
            .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = fallbackGapRetransmit)]
    pub fn fallback_gap_retransmit(handle: u64, next_missing: u64) -> Result<Vec<u8>, JsError> {
        super::fallback_gap_retransmit(handle, next_missing)
            .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = fallbackRetryDue)]
    pub fn fallback_retry_due(handle: u64, elapsed_millis: u64) -> Result<Vec<u8>, JsError> {
        super::fallback_retry_due(handle, elapsed_millis)
            .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = fallbackClose)]
    pub fn fallback_close(handle: u64) {
        super::fallback_close(handle);
    }
}
