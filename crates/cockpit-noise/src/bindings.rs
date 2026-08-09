use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::{
    AuthorizationCapability, NoiseChild, RecordKind, TranscriptAuthorizationGate,
    TranscriptAuthorizationRequest,
};

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static HANDLES: OnceLock<Mutex<HashMap<u64, NoiseChild>>> = OnceLock::new();

fn handles() -> &'static Mutex<HashMap<u64, NoiseChild>> {
    HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "native-bindings", derive(uniffi::Error))]
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

struct GateAdapter(Arc<dyn BindingAuthorizationGate>);

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
    gate: Arc<dyn BindingAuthorizationGate>,
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

    #[wasm_bindgen(js_name = decryptRecord)]
    pub fn decrypt_record(
        handle: u64,
        routing_sequence: u64,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, JsError> {
        super::noise_decrypt_record(handle, routing_sequence, ciphertext)
            .map_err(|error| JsError::new(&error.to_string()))
    }

    #[wasm_bindgen(js_name = close)]
    pub fn close(handle: u64) {
        super::noise_close(handle);
    }
}

#[cfg(feature = "native-bindings")]
uniffi::include_scaffolding!("cockpit_noise");
