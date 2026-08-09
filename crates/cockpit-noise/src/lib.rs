#![forbid(unsafe_code)]

mod bindings;
mod core;
mod frame;
mod prologue;
mod record;
mod rekey;

pub use bindings::{
    BindingAuthorizationGate, BindingAuthorizationRequest, NoiseBindingError, noise_authorize,
    noise_close, noise_create_initiator, noise_create_responder, noise_decrypt_record,
    noise_encrypt_record, noise_handshake_hash, noise_read_handshake, noise_write_handshake,
};
#[cfg(feature = "test-entropy")]
pub use core::run_nn_test_vector;
pub use core::{
    AuthorizationCapability, EndpointRole, NoiseChild, TranscriptAuthorizationGate,
    TranscriptAuthorizationRequest, final_proof_binding_bytes, final_proof_binding_digest,
};
pub use frame::{
    ABSOLUTE_CIPHERTEXT_CAP, HANDSHAKE_HEADER_LEN, HandshakeFrame, MAX_HANDSHAKE_MESSAGE,
};
pub use prologue::{
    BODY_LEN as PROLOGUE_BODY_LEN, DOMAIN as PROLOGUE_DOMAIN, ENCODED_LEN as PROLOGUE_ENCODED_LEN,
    RemoteNoisePrologueV1,
};
pub use record::{
    LANE_FRAGMENT_HEADER_LEN, MAX_CIPHERTEXT, MAX_LANE_FRAGMENT, MAX_LANE_FRAGMENT_PAYLOAD,
    MAX_PAYLOAD, MAX_PLAINTEXT, RECORD_HEADER_LEN, RecordKind, RekeyPrepareV1, RemoteNoiseRecordV1,
    TAG_LEN,
};
pub use rekey::{
    DirectionalRekey, DirectionalState, HARD_SEQUENCE_LIMIT, LAST_OPEN_RECORD,
    MAX_APPLICATION_BYTES, MAX_RECORDS, REKEY_DEADLINE_MILLIS, RekeyAction, RekeyEvent,
};

pub type Result<T> = std::result::Result<T, NoiseError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NoiseError {
    #[error("invalid_prologue")]
    InvalidPrologue,
    #[error("invalid_handshake_frame")]
    InvalidHandshakeFrame,
    #[error("handshake_payload_forbidden")]
    HandshakePayloadForbidden,
    #[error("invalid_record")]
    InvalidRecord,
    #[error("record_too_large")]
    RecordTooLarge,
    #[error("sequence_mismatch")]
    SequenceMismatch,
    #[error("sequence_exhausted")]
    SequenceExhausted,
    #[error("invalid_rekey")]
    InvalidRekey,
    #[error("budget_exceeded")]
    BudgetExceeded,
    #[error("invalid_state")]
    InvalidState,
    #[error("authorization_denied")]
    AuthorizationDenied,
    #[error("authentication_failed")]
    AuthenticationFailed,
    #[error("low_order_key")]
    LowOrderKey,
    #[error("crypto_unavailable")]
    CryptoUnavailable,
    #[error("closed")]
    Closed,
}
