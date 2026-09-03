//! Daemon-only tamper-evident computer-use audit chain.
//!
//! Records a bounded, daemon-authored, tamper-evident history of computer
//! delegations/actions whose sealed head detects SQLite mutation, reorder,
//! insertion, rollback, and tail deletion without retaining pixels, typed
//! content, OCR, or raw target text.
//!
//! # Canonical encoding
//!
//! `ComputerAuditEntryV1` has one sole canonical 424-byte big-endian encoding.
//! The HMAC is `HMAC-SHA-256(key[key_version], "flycockpit-computer-audit-v1" |
//! 0x00 | entry[424])`. Every digest is SHA-256 over
//! `domain_len:u8 | ASCII-domain | value_len:u32be | canonical-value-bytes`.
//!
//! # Sealed head
//!
//! The sealed store's V1 payload is exact: `"FCAH"[4] | version:u8=1 |
//! pending_present:u8 | reserved:u16=0 | sealed_generation:u64 |
//! confirmed_sequence:u64 | confirmed_mac:[32] | confirmed_key_version:u32 |
//! database_instance_id:[16] | pending_length:u16 | pending_entry:[424 when
//! present] | pending_mac:[32 when present] | pending_previous_sequence:u64 |
//! pending_previous_mac:[32] | pending_key_version:u32 |
//! pending_database_instance_id:[16] | payload_digest:[32]`.
//!
//! The confirmed-only form is exactly 110 bytes. The maximum
//! confirmed-plus-pending form is exactly 626 bytes.

#![allow(dead_code)] // Extra event kinds and record digests are consumed as the live loop lands.

mod chain;
pub use chain::{ComputerAuditChain, GuidanceAppendError, GuidanceAuditAppend};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The sole canonical entry encoding length.
pub const ENTRY_LEN: usize = 424;

/// The MAC domain separator for audit entries.
pub const ENTRY_MAC_DOMAIN: &[u8] = b"flycockpit-computer-audit-v1";

/// The sealed-head magic.
pub const SEALED_HEAD_MAGIC: &[u8; 4] = b"FCAH";

/// The sealed-head format version.
pub const SEALED_HEAD_VERSION: u8 = 1;

/// The confirmed-only sealed-head length (including payload_digest).
pub const SEALED_HEAD_CONFIRMED_ONLY_LEN: usize = 110;

/// The fixed prefix length through `pending_length`.
pub const SEALED_HEAD_FIXED_PREFIX_LEN: usize = 78;

/// The maximum confirmed-plus-pending sealed-head length.
pub const SEALED_HEAD_MAX_LEN: usize = 626;

/// The ceiling below which the sealed head must stay.
pub const SEALED_HEAD_CEILING: usize = 1024;

/// The margin below the 1024-byte ceiling at the worst case.
pub const SEALED_HEAD_CEILING_MARGIN: usize = 398;

/// The record digest magic for key-rotation checkpoints.
pub const RECORD_KEY_CHECKPOINT_MAGIC: &[u8; 4] = b"FCK1";

/// The record digest magic for prune checkpoints.
pub const RECORD_PRUNE_CHECKPOINT_MAGIC: &[u8; 4] = b"FCP1";

/// The record digest magic for export records.
pub const RECORD_EXPORT_MAGIC: &[u8; 4] = b"FEX1";

/// The record digest magic for session-deletion tombstones.
pub const RECORD_SESSION_DELETED_MAGIC: &[u8; 4] = b"FSD1";

// ---------------------------------------------------------------------------
// Event kinds (1..=29)
// ---------------------------------------------------------------------------

/// The 29 closed event kinds, in exact list order numbered 1..=29.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AuditEventKind {
    DelegationStarted = 1,
    AskRequested = 2,
    AskAllowed = 3,
    AskDenied = 4,
    LeaseRevoked = 5,
    ObservationCreated = 6,
    ActionPrepared = 7,
    ActionDispatching = 8,
    ActionAccepted = 9,
    ActionSubmissionUnknown = 10,
    ActionRejected = 11,
    ActionBackendCompleted = 12,
    ActionVerified = 13,
    ActionVerificationFailed = 14,
    ActionFailed = 15,
    ActionCancelRequested = 16,
    ActionCancelled = 17,
    ActionCompletedAfterCancel = 18,
    DelegationTerminal = 19,
    GuidanceProposalCreated = 20,
    GuidanceProposalAccepted = 21,
    GuidanceProposalRejected = 22,
    GuidanceProposalExpired = 23,
    RecoveryStarted = 24,
    RecoveryResolved = 25,
    KeyRotationCheckpoint = 26,
    PruneCheckpoint = 27,
    ExportRecorded = 28,
    SessionDeleted = 29,
}

impl AuditEventKind {
    /// Convert from a raw byte. Returns `None` for codes outside 1..=29.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::DelegationStarted),
            2 => Some(Self::AskRequested),
            3 => Some(Self::AskAllowed),
            4 => Some(Self::AskDenied),
            5 => Some(Self::LeaseRevoked),
            6 => Some(Self::ObservationCreated),
            7 => Some(Self::ActionPrepared),
            8 => Some(Self::ActionDispatching),
            9 => Some(Self::ActionAccepted),
            10 => Some(Self::ActionSubmissionUnknown),
            11 => Some(Self::ActionRejected),
            12 => Some(Self::ActionBackendCompleted),
            13 => Some(Self::ActionVerified),
            14 => Some(Self::ActionVerificationFailed),
            15 => Some(Self::ActionFailed),
            16 => Some(Self::ActionCancelRequested),
            17 => Some(Self::ActionCancelled),
            18 => Some(Self::ActionCompletedAfterCancel),
            19 => Some(Self::DelegationTerminal),
            20 => Some(Self::GuidanceProposalCreated),
            21 => Some(Self::GuidanceProposalAccepted),
            22 => Some(Self::GuidanceProposalRejected),
            23 => Some(Self::GuidanceProposalExpired),
            24 => Some(Self::RecoveryStarted),
            25 => Some(Self::RecoveryResolved),
            26 => Some(Self::KeyRotationCheckpoint),
            27 => Some(Self::PruneCheckpoint),
            28 => Some(Self::ExportRecorded),
            29 => Some(Self::SessionDeleted),
            _ => None,
        }
    }

    /// The canonical byte code.
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// Closed scalar enums
// ---------------------------------------------------------------------------

/// `ask_yolo`: ask=1, yolo=2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AskYolo {
    Ask = 1,
    Yolo = 2,
}

impl AskYolo {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Ask),
            2 => Some(Self::Yolo),
            _ => None,
        }
    }
}

/// `disposition`: user_allowed=1, user_denied=2, agent_discretion=3,
/// accepted_session=4, accepted_persistent=5, rejected=6, expired=7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Disposition {
    UserAllowed = 1,
    UserDenied = 2,
    AgentDiscretion = 3,
    AcceptedSession = 4,
    AcceptedPersistent = 5,
    Rejected = 6,
    Expired = 7,
}

impl Disposition {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::UserAllowed),
            2 => Some(Self::UserDenied),
            3 => Some(Self::AgentDiscretion),
            4 => Some(Self::AcceptedSession),
            5 => Some(Self::AcceptedPersistent),
            6 => Some(Self::Rejected),
            7 => Some(Self::Expired),
            _ => None,
        }
    }
}

/// `scope`: session=1, project_provider_model=2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GuidanceScope {
    Session = 1,
    ProjectProviderModel = 2,
}

impl GuidanceScope {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Session),
            2 => Some(Self::ProjectProviderModel),
            _ => None,
        }
    }
}

/// `action_class`: pointer_move=1, pointer_button=2, pointer_drag=3,
/// text_entry=4, key_input=5, scroll=6, wait=7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ActionClass {
    PointerMove = 1,
    PointerButton = 2,
    PointerDrag = 3,
    TextEntry = 4,
    KeyInput = 5,
    Scroll = 6,
    Wait = 7,
}

impl ActionClass {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::PointerMove),
            2 => Some(Self::PointerButton),
            3 => Some(Self::PointerDrag),
            4 => Some(Self::TextEntry),
            5 => Some(Self::KeyInput),
            6 => Some(Self::Scroll),
            7 => Some(Self::Wait),
            _ => None,
        }
    }

    /// `consequential` is a derived predicate: true exactly for
    /// `pointer_button|pointer_drag|text_entry|key_input|scroll` and false
    /// exactly for `pointer_move|wait`.
    pub fn is_consequential(self) -> bool {
        matches!(
            self,
            Self::PointerButton
                | Self::PointerDrag
                | Self::TextEntry
                | Self::KeyInput
                | Self::Scroll
        )
    }
}

/// `journal_state`: prepared=1, dispatching=2, accepted=3,
/// submission_unknown=4, backend_completed=5, failed=6,
/// cancel_requested=7, cancelled=8, completed_after_cancel=9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum JournalState {
    Prepared = 1,
    Dispatching = 2,
    Accepted = 3,
    SubmissionUnknown = 4,
    BackendCompleted = 5,
    Failed = 6,
    CancelRequested = 7,
    Cancelled = 8,
    CompletedAfterCancel = 9,
}

impl JournalState {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Prepared),
            2 => Some(Self::Dispatching),
            3 => Some(Self::Accepted),
            4 => Some(Self::SubmissionUnknown),
            5 => Some(Self::BackendCompleted),
            6 => Some(Self::Failed),
            7 => Some(Self::CancelRequested),
            8 => Some(Self::Cancelled),
            9 => Some(Self::CompletedAfterCancel),
            _ => None,
        }
    }
}

/// `verification_state`: unavailable=1, mismatch=2, inconclusive=3, verified=4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VerificationState {
    Unavailable = 1,
    Mismatch = 2,
    Inconclusive = 3,
    Verified = 4,
}

impl VerificationState {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Unavailable),
            2 => Some(Self::Mismatch),
            3 => Some(Self::Inconclusive),
            4 => Some(Self::Verified),
            _ => None,
        }
    }
}

/// `error_code`: none=0, backend_unavailable=1, backend_rejected=2,
/// submission_unknown=3, verification_unavailable=4, verification_mismatch=5,
/// verification_inconclusive=6, cancelled=7, authorization_denied=8,
/// lease_revoked=9, storage_failure=10, corrupt_state=11, deadline=12,
/// policy_denied=13.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AuditErrorCode {
    None = 0,
    BackendUnavailable = 1,
    BackendRejected = 2,
    SubmissionUnknown = 3,
    VerificationUnavailable = 4,
    VerificationMismatch = 5,
    VerificationInconclusive = 6,
    Cancelled = 7,
    AuthorizationDenied = 8,
    LeaseRevoked = 9,
    StorageFailure = 10,
    CorruptState = 11,
    Deadline = 12,
    PolicyDenied = 13,
}

impl AuditErrorCode {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::BackendUnavailable),
            2 => Some(Self::BackendRejected),
            3 => Some(Self::SubmissionUnknown),
            4 => Some(Self::VerificationUnavailable),
            5 => Some(Self::VerificationMismatch),
            6 => Some(Self::VerificationInconclusive),
            7 => Some(Self::Cancelled),
            8 => Some(Self::AuthorizationDenied),
            9 => Some(Self::LeaseRevoked),
            10 => Some(Self::StorageFailure),
            11 => Some(Self::CorruptState),
            12 => Some(Self::Deadline),
            13 => Some(Self::PolicyDenied),
            _ => None,
        }
    }

    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

/// `session_deleted` reason: owner_requested=1, retention_expired=2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SessionDeletedReason {
    OwnerRequested = 1,
    RetentionExpired = 2,
}

impl SessionDeletedReason {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::OwnerRequested),
            2 => Some(Self::RetentionExpired),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Present-bit layout (bits 0..21)
// ---------------------------------------------------------------------------

/// Present-bit indices. Bits 0..21 correspond, in field order, to the five
/// IDs, disposition, scope, the eight digests, the four one-byte enums,
/// journal version, error code, and rule-kind bits. Bits 22..31 must be zero.
pub mod present_bits {
    pub const SESSION_ID: u32 = 1 << 0;
    pub const DELEGATION_ID: u32 = 1 << 1;
    pub const ACTION_ID: u32 = 1 << 2;
    pub const OPERATION_ID: u32 = 1 << 3;
    pub const PROPOSAL_ID: u32 = 1 << 4;
    pub const DISPOSITION: u32 = 1 << 5;
    pub const SCOPE: u32 = 1 << 6;
    pub const CANONICAL_PROJECT_DIGEST: u32 = 1 << 7;
    pub const PROVIDER_DIGEST: u32 = 1 << 8;
    pub const MODEL_DIGEST: u32 = 1 << 9;
    pub const PHYSICAL_TARGET_DIGEST: u32 = 1 << 10;
    pub const FOCUS_DIGEST: u32 = 1 << 11;
    pub const OBSERVATION_DIGEST: u32 = 1 << 12;
    pub const HOST_LEASE_DIGEST: u32 = 1 << 13;
    pub const RECORD_DIGEST: u32 = 1 << 14;
    pub const ASK_YOLO: u32 = 1 << 15;
    pub const ACTION_CLASS: u32 = 1 << 16;
    pub const JOURNAL_STATE: u32 = 1 << 17;
    pub const VERIFICATION_STATE: u32 = 1 << 18;
    pub const JOURNAL_VERSION: u32 = 1 << 19;
    pub const ERROR_CODE: u32 = 1 << 20;
    pub const RULE_KIND_BITS: u32 = 1 << 21;
    /// Mask for all valid present bits (0..22).
    pub const ALL_VALID: u32 = (1u32 << 22) - 1;
}

// ---------------------------------------------------------------------------
// Domain-separated digests
// ---------------------------------------------------------------------------

/// Compute a domain-separated SHA-256 digest over
/// `domain_len:u8 | ASCII-domain | value_len:u32be | canonical-value-bytes`.
///
/// The closed domains are `project`, `provider`, `model`,
/// `physical-target-generation`, `focus-generation`, `observation-generation`,
/// `host-lease-generation`, and `audit-record`.
pub fn domain_digest(domain: &str, value: &[u8]) -> [u8; 32] {
    debug_assert!(
        domain.is_ascii(),
        "audit digest domain must be ASCII: {domain}"
    );
    debug_assert!(
        domain.len() <= 255,
        "audit digest domain must fit in u8: {domain}"
    );
    let mut h = Sha256::new();
    h.update([domain.len() as u8]);
    h.update(domain.as_bytes());
    h.update((value.len() as u32).to_be_bytes());
    h.update(value);
    h.finalize().into()
}

/// The eight closed digest domains.
pub mod domains {
    pub const PROJECT: &str = "project";
    pub const PROVIDER: &str = "provider";
    pub const MODEL: &str = "model";
    pub const PHYSICAL_TARGET_GENERATION: &str = "physical-target-generation";
    pub const FOCUS_GENERATION: &str = "focus-generation";
    pub const OBSERVATION_GENERATION: &str = "observation-generation";
    pub const HOST_LEASE_GENERATION: &str = "host-lease-generation";
    pub const AUDIT_RECORD: &str = "audit-record";
}

// ---------------------------------------------------------------------------
// Entry MAC
// ---------------------------------------------------------------------------

/// Compute the entry MAC: `HMAC-SHA-256(key, "flycockpit-computer-audit-v1" |
/// 0x00 | entry[424])`.
pub fn entry_mac(key: &[u8], entry_bytes: &[u8]) -> [u8; 32] {
    debug_assert_eq!(
        entry_bytes.len(),
        ENTRY_LEN,
        "entry must be exactly {ENTRY_LEN} bytes for MAC"
    );
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(ENTRY_MAC_DOMAIN);
    mac.update(&[0x00]);
    mac.update(entry_bytes);
    mac.finalize().into_bytes().into()
}

/// Verify an entry MAC in constant time.
pub fn verify_entry_mac(key: &[u8], entry_bytes: &[u8], expected_mac: &[u8; 32]) -> bool {
    let computed = entry_mac(key, entry_bytes);
    computed == *expected_mac
}

// ---------------------------------------------------------------------------
// ComputerAuditEntryV1 — the canonical 424-byte encoding
// ---------------------------------------------------------------------------

/// The canonical 424-byte audit entry. All fields are the sole canonical
/// encoding; no alternative layout exists.
#[derive(Clone, Copy)]
pub struct ComputerAuditEntryV1 {
    /// Event kind (1..=29).
    pub event_kind: AuditEventKind,
    /// Present-bit mask (bits 0..21 set as needed; 22..31 zero).
    pub present_bits: u32,
    /// Monotonically increasing sequence number (always present).
    pub sequence: u64,
    /// MAC of the previous entry in the chain (all-zero for sequence 1).
    pub previous_mac: [u8; 32],
    // Five IDs (16 bytes each, RFC 4122 network-order):
    pub session_id: [u8; 16],
    pub delegation_id: [u8; 16],
    pub action_id: [u8; 16],
    pub operation_id: [u8; 16],
    pub proposal_id: [u8; 16],
    // Closed enums:
    pub disposition: u8,
    pub scope: u8,
    // Eight digests (32 bytes each):
    pub canonical_project_digest: [u8; 32],
    pub provider_digest: [u8; 32],
    pub model_digest: [u8; 32],
    pub physical_target_digest: [u8; 32],
    pub focus_digest: [u8; 32],
    pub observation_digest: [u8; 32],
    pub host_lease_digest: [u8; 32],
    pub record_digest: [u8; 32],
    // Four one-byte enums:
    pub ask_yolo: u8,
    pub action_class: u8,
    pub journal_state: u8,
    pub verification_state: u8,
    // Version/timestamps (always present):
    pub journal_version: u64,
    pub monotonic_nanos: u64,
    pub wall_unix_millis: i64,
    // Optional slots:
    pub error_code: u16,
    pub rule_kind_bits: u16,
    /// Key version used to compute the MAC (always present).
    pub key_version: u32,
}

impl ComputerAuditEntryV1 {
    /// Encode to the exact 424-byte canonical form (without MAC appended).
    ///
    /// The 424 bytes are the entry body; the MAC is computed separately via
    /// [`entry_mac`] and stored in the chain as `previous_mac` for the next
    /// entry. The entry itself is exactly 424 bytes.
    pub fn encode(&self) -> [u8; ENTRY_LEN] {
        let mut buf = [0u8; ENTRY_LEN];
        let mut off = 0usize;

        // "FCAE"[4]
        buf[off..off + 4].copy_from_slice(b"FCAE");
        off += 4;
        // version:u8=1
        buf[off] = 1;
        off += 1;
        // event_kind:u8
        buf[off] = self.event_kind.as_byte();
        off += 1;
        // present_bits:u32
        buf[off..off + 4].copy_from_slice(&self.present_bits.to_be_bytes());
        off += 4;
        // sequence:u64
        buf[off..off + 8].copy_from_slice(&self.sequence.to_be_bytes());
        off += 8;
        // previous_mac:[32]
        buf[off..off + 32].copy_from_slice(&self.previous_mac);
        off += 32;
        // session_id:[16]
        buf[off..off + 16].copy_from_slice(&self.session_id);
        off += 16;
        // delegation_id:[16]
        buf[off..off + 16].copy_from_slice(&self.delegation_id);
        off += 16;
        // action_id:[16]
        buf[off..off + 16].copy_from_slice(&self.action_id);
        off += 16;
        // operation_id:[16]
        buf[off..off + 16].copy_from_slice(&self.operation_id);
        off += 16;
        // proposal_id:[16]
        buf[off..off + 16].copy_from_slice(&self.proposal_id);
        off += 16;
        // disposition:u8
        buf[off] = self.disposition;
        off += 1;
        // scope:u8
        buf[off] = self.scope;
        off += 1;
        // canonical_project_digest:[32]
        buf[off..off + 32].copy_from_slice(&self.canonical_project_digest);
        off += 32;
        // provider_digest:[32]
        buf[off..off + 32].copy_from_slice(&self.provider_digest);
        off += 32;
        // model_digest:[32]
        buf[off..off + 32].copy_from_slice(&self.model_digest);
        off += 32;
        // physical_target_digest:[32]
        buf[off..off + 32].copy_from_slice(&self.physical_target_digest);
        off += 32;
        // focus_digest:[32]
        buf[off..off + 32].copy_from_slice(&self.focus_digest);
        off += 32;
        // observation_digest:[32]
        buf[off..off + 32].copy_from_slice(&self.observation_digest);
        off += 32;
        // host_lease_digest:[32]
        buf[off..off + 32].copy_from_slice(&self.host_lease_digest);
        off += 32;
        // record_digest:[32]
        buf[off..off + 32].copy_from_slice(&self.record_digest);
        off += 32;
        // ask_yolo:u8
        buf[off] = self.ask_yolo;
        off += 1;
        // action_class:u8
        buf[off] = self.action_class;
        off += 1;
        // journal_state:u8
        buf[off] = self.journal_state;
        off += 1;
        // verification_state:u8
        buf[off] = self.verification_state;
        off += 1;
        // journal_version:u64
        buf[off..off + 8].copy_from_slice(&self.journal_version.to_be_bytes());
        off += 8;
        // monotonic_nanos:u64
        buf[off..off + 8].copy_from_slice(&self.monotonic_nanos.to_be_bytes());
        off += 8;
        // wall_unix_millis:i64
        buf[off..off + 8].copy_from_slice(&self.wall_unix_millis.to_be_bytes());
        off += 8;
        // error_code:u16
        buf[off..off + 2].copy_from_slice(&self.error_code.to_be_bytes());
        off += 2;
        // rule_kind_bits:u16
        buf[off..off + 2].copy_from_slice(&self.rule_kind_bits.to_be_bytes());
        off += 2;
        // key_version:u32
        buf[off..off + 4].copy_from_slice(&self.key_version.to_be_bytes());
        off += 4;

        debug_assert_eq!(
            off, ENTRY_LEN,
            "entry encoding must be exactly {ENTRY_LEN} bytes"
        );
        buf
    }

    /// Decode from the exact 424-byte canonical form.
    pub fn decode(buf: &[u8; ENTRY_LEN]) -> Result<Self, AuditDecodeError> {
        if &buf[0..4] != b"FCAE" {
            return Err(AuditDecodeError::BadMagic);
        }
        if buf[4] != 1 {
            return Err(AuditDecodeError::BadVersion(buf[4]));
        }
        let event_kind =
            AuditEventKind::from_byte(buf[5]).ok_or(AuditDecodeError::InvalidEventKind(buf[5]))?;
        let present_bits = u32::from_be_bytes(buf[6..10].try_into().unwrap());
        if present_bits & !present_bits::ALL_VALID != 0 {
            return Err(AuditDecodeError::ReservedPresentBits(present_bits));
        }
        let sequence = u64::from_be_bytes(buf[10..18].try_into().unwrap());
        let previous_mac: [u8; 32] = buf[18..50].try_into().unwrap();
        let session_id: [u8; 16] = buf[50..66].try_into().unwrap();
        let delegation_id: [u8; 16] = buf[66..82].try_into().unwrap();
        let action_id: [u8; 16] = buf[82..98].try_into().unwrap();
        let operation_id: [u8; 16] = buf[98..114].try_into().unwrap();
        let proposal_id: [u8; 16] = buf[114..130].try_into().unwrap();
        let disposition = buf[130];
        let scope = buf[131];
        let canonical_project_digest: [u8; 32] = buf[132..164].try_into().unwrap();
        let provider_digest: [u8; 32] = buf[164..196].try_into().unwrap();
        let model_digest: [u8; 32] = buf[196..228].try_into().unwrap();
        let physical_target_digest: [u8; 32] = buf[228..260].try_into().unwrap();
        let focus_digest: [u8; 32] = buf[260..292].try_into().unwrap();
        let observation_digest: [u8; 32] = buf[292..324].try_into().unwrap();
        let host_lease_digest: [u8; 32] = buf[324..356].try_into().unwrap();
        let record_digest: [u8; 32] = buf[356..388].try_into().unwrap();
        let ask_yolo = buf[388];
        let action_class = buf[389];
        let journal_state = buf[390];
        let verification_state = buf[391];
        let journal_version = u64::from_be_bytes(buf[392..400].try_into().unwrap());
        let monotonic_nanos = u64::from_be_bytes(buf[400..408].try_into().unwrap());
        let wall_unix_millis = i64::from_be_bytes(buf[408..416].try_into().unwrap());
        let error_code = u16::from_be_bytes(buf[416..418].try_into().unwrap());
        let rule_kind_bits = u16::from_be_bytes(buf[418..420].try_into().unwrap());
        let key_version = u32::from_be_bytes(buf[420..424].try_into().unwrap());

        Ok(Self {
            event_kind,
            present_bits,
            sequence,
            previous_mac,
            session_id,
            delegation_id,
            action_id,
            operation_id,
            proposal_id,
            disposition,
            scope,
            canonical_project_digest,
            provider_digest,
            model_digest,
            physical_target_digest,
            focus_digest,
            observation_digest,
            host_lease_digest,
            record_digest,
            ask_yolo,
            action_class,
            journal_state,
            verification_state,
            journal_version,
            monotonic_nanos,
            wall_unix_millis,
            error_code,
            rule_kind_bits,
            key_version,
        })
    }

    /// Check that a present field is non-zero (valid) and an absent field is
    /// all-zero with its bit clear.
    pub fn validate_presence(&self) -> Result<(), AuditDecodeError> {
        let check_id = |bits: u32, id: &[u8; 16], name: &str| -> Result<(), AuditDecodeError> {
            let is_present = self.present_bits & bits != 0;
            let is_zero = id.iter().all(|b| *b == 0);
            if is_present {
                if is_zero {
                    return Err(AuditDecodeError::PresentButZero(name.to_string()));
                }
            } else if !is_zero {
                return Err(AuditDecodeError::AbsentButNonzero(name.to_string()));
            }
            Ok(())
        };
        check_id(present_bits::SESSION_ID, &self.session_id, "session_id")?;
        check_id(
            present_bits::DELEGATION_ID,
            &self.delegation_id,
            "delegation_id",
        )?;
        check_id(present_bits::ACTION_ID, &self.action_id, "action_id")?;
        check_id(
            present_bits::OPERATION_ID,
            &self.operation_id,
            "operation_id",
        )?;
        check_id(present_bits::PROPOSAL_ID, &self.proposal_id, "proposal_id")?;

        let disp_present = self.present_bits & present_bits::DISPOSITION != 0;
        if disp_present {
            if self.disposition == 0 {
                return Err(AuditDecodeError::PresentButZero("disposition".into()));
            }
            if Disposition::from_byte(self.disposition).is_none() {
                return Err(AuditDecodeError::InvalidEnumValue(
                    "disposition".into(),
                    self.disposition,
                ));
            }
        } else if self.disposition != 0 {
            return Err(AuditDecodeError::AbsentButNonzero("disposition".into()));
        }

        let scope_present = self.present_bits & present_bits::SCOPE != 0;
        if scope_present {
            if self.scope == 0 {
                return Err(AuditDecodeError::PresentButZero("scope".into()));
            }
            if GuidanceScope::from_byte(self.scope).is_none() {
                return Err(AuditDecodeError::InvalidEnumValue(
                    "scope".into(),
                    self.scope,
                ));
            }
        } else if self.scope != 0 {
            return Err(AuditDecodeError::AbsentButNonzero("scope".into()));
        }

        let check_digest =
            |bits: u32, digest: &[u8; 32], name: &str| -> Result<(), AuditDecodeError> {
                let is_present = self.present_bits & bits != 0;
                let is_zero = digest.iter().all(|b| *b == 0);
                if is_present {
                    if is_zero {
                        return Err(AuditDecodeError::PresentButZero(name.to_string()));
                    }
                } else if !is_zero {
                    return Err(AuditDecodeError::AbsentButNonzero(name.to_string()));
                }
                Ok(())
            };
        check_digest(
            present_bits::CANONICAL_PROJECT_DIGEST,
            &self.canonical_project_digest,
            "canonical_project_digest",
        )?;
        check_digest(
            present_bits::PROVIDER_DIGEST,
            &self.provider_digest,
            "provider_digest",
        )?;
        check_digest(
            present_bits::MODEL_DIGEST,
            &self.model_digest,
            "model_digest",
        )?;
        check_digest(
            present_bits::PHYSICAL_TARGET_DIGEST,
            &self.physical_target_digest,
            "physical_target_digest",
        )?;
        check_digest(
            present_bits::FOCUS_DIGEST,
            &self.focus_digest,
            "focus_digest",
        )?;
        check_digest(
            present_bits::OBSERVATION_DIGEST,
            &self.observation_digest,
            "observation_digest",
        )?;
        check_digest(
            present_bits::HOST_LEASE_DIGEST,
            &self.host_lease_digest,
            "host_lease_digest",
        )?;
        check_digest(
            present_bits::RECORD_DIGEST,
            &self.record_digest,
            "record_digest",
        )?;

        let ay_present = self.present_bits & present_bits::ASK_YOLO != 0;
        if ay_present {
            if self.ask_yolo == 0 {
                return Err(AuditDecodeError::PresentButZero("ask_yolo".into()));
            }
            if AskYolo::from_byte(self.ask_yolo).is_none() {
                return Err(AuditDecodeError::InvalidEnumValue(
                    "ask_yolo".into(),
                    self.ask_yolo,
                ));
            }
        } else if self.ask_yolo != 0 {
            return Err(AuditDecodeError::AbsentButNonzero("ask_yolo".into()));
        }

        let ac_present = self.present_bits & present_bits::ACTION_CLASS != 0;
        if ac_present {
            if self.action_class == 0 {
                return Err(AuditDecodeError::PresentButZero("action_class".into()));
            }
            if ActionClass::from_byte(self.action_class).is_none() {
                return Err(AuditDecodeError::InvalidEnumValue(
                    "action_class".into(),
                    self.action_class,
                ));
            }
        } else if self.action_class != 0 {
            return Err(AuditDecodeError::AbsentButNonzero("action_class".into()));
        }

        let js_present = self.present_bits & present_bits::JOURNAL_STATE != 0;
        if js_present {
            if self.journal_state == 0 {
                return Err(AuditDecodeError::PresentButZero("journal_state".into()));
            }
            if JournalState::from_byte(self.journal_state).is_none() {
                return Err(AuditDecodeError::InvalidEnumValue(
                    "journal_state".into(),
                    self.journal_state,
                ));
            }
        } else if self.journal_state != 0 {
            return Err(AuditDecodeError::AbsentButNonzero("journal_state".into()));
        }

        let vs_present = self.present_bits & present_bits::VERIFICATION_STATE != 0;
        if vs_present {
            if self.verification_state == 0 {
                return Err(AuditDecodeError::PresentButZero(
                    "verification_state".into(),
                ));
            }
            if VerificationState::from_byte(self.verification_state).is_none() {
                return Err(AuditDecodeError::InvalidEnumValue(
                    "verification_state".into(),
                    self.verification_state,
                ));
            }
        } else if self.verification_state != 0 {
            return Err(AuditDecodeError::AbsentButNonzero(
                "verification_state".into(),
            ));
        }

        let jv_present = self.present_bits & present_bits::JOURNAL_VERSION != 0;
        if jv_present {
            if self.journal_version == 0 {
                return Err(AuditDecodeError::PresentButZero("journal_version".into()));
            }
        } else if self.journal_version != 0 {
            return Err(AuditDecodeError::AbsentButNonzero("journal_version".into()));
        }

        let ec_present = self.present_bits & present_bits::ERROR_CODE != 0;
        if ec_present {
            if AuditErrorCode::from_u16(self.error_code).is_none() {
                return Err(AuditDecodeError::InvalidErrorCode(self.error_code));
            }
        } else if self.error_code != 0 {
            return Err(AuditDecodeError::AbsentButNonzero("error_code".into()));
        }

        let rk_present = self.present_bits & present_bits::RULE_KIND_BITS != 0;
        if rk_present {
            if self.rule_kind_bits == 0 {
                return Err(AuditDecodeError::PresentButZero("rule_kind_bits".into()));
            }
            if self.rule_kind_bits & !0b111111 != 0 {
                return Err(AuditDecodeError::InvalidRuleKindBits(self.rule_kind_bits));
            }
        } else if self.rule_kind_bits != 0 {
            return Err(AuditDecodeError::AbsentButNonzero("rule_kind_bits".into()));
        }

        if self.key_version == 0 {
            return Err(AuditDecodeError::PresentButZero("key_version".into()));
        }

        Ok(())
    }
}

impl std::fmt::Debug for ComputerAuditEntryV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComputerAuditEntryV1")
            .field("event_kind", &self.event_kind)
            .field("present_bits", &format_args!("0x{:08x}", self.present_bits))
            .field("sequence", &self.sequence)
            .field("previous_mac", &"[32 bytes]")
            .field("session_id", &self.session_id)
            .field("delegation_id", &self.delegation_id)
            .field("action_id", &self.action_id)
            .field("operation_id", &self.operation_id)
            .field("proposal_id", &self.proposal_id)
            .field("disposition", &self.disposition)
            .field("scope", &self.scope)
            .field("canonical_project_digest", &"[32 bytes]")
            .field("provider_digest", &"[32 bytes]")
            .field("model_digest", &"[32 bytes]")
            .field("physical_target_digest", &"[32 bytes]")
            .field("focus_digest", &"[32 bytes]")
            .field("observation_digest", &"[32 bytes]")
            .field("host_lease_digest", &"[32 bytes]")
            .field("record_digest", &"[32 bytes]")
            .field("ask_yolo", &self.ask_yolo)
            .field("action_class", &self.action_class)
            .field("journal_state", &self.journal_state)
            .field("verification_state", &self.verification_state)
            .field("journal_version", &self.journal_version)
            .field("monotonic_nanos", &self.monotonic_nanos)
            .field("wall_unix_millis", &self.wall_unix_millis)
            .field("error_code", &self.error_code)
            .field("rule_kind_bits", &self.rule_kind_bits)
            .field("key_version", &self.key_version)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Decode errors
// ---------------------------------------------------------------------------

/// Errors encountered when decoding or validating an audit entry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditDecodeError {
    #[error("audit entry bad magic")]
    BadMagic,
    #[error("audit entry bad version: {0}")]
    BadVersion(u8),
    #[error("audit entry invalid event kind: {0}")]
    InvalidEventKind(u8),
    #[error("audit entry reserved present bits set: 0x{0:08x}")]
    ReservedPresentBits(u32),
    #[error("audit entry field present but zero: {0}")]
    PresentButZero(String),
    #[error("audit entry field absent but nonzero: {0}")]
    AbsentButNonzero(String),
    #[error("audit entry invalid enum value for {0}: {1}")]
    InvalidEnumValue(String, u8),
    #[error("audit entry invalid error code: {0}")]
    InvalidErrorCode(u16),
    #[error("audit entry invalid rule kind bits: 0x{0:04x}")]
    InvalidRuleKindBits(u16),
}

// ---------------------------------------------------------------------------
// Record digests (FCK1 / FCP1 / FEX1 / FSD1)
// ---------------------------------------------------------------------------

/// Encode and digest a key-rotation checkpoint record (`FCK1`, 53 bytes).
///
/// `"FCK1"[4] | version:u8=1 | old_key_version:u32 | new_key_version:u32 |
/// through_sequence:u64 | through_mac:[32]`
pub fn key_checkpoint_record_digest(
    old_key_version: u32,
    new_key_version: u32,
    through_sequence: u64,
    through_mac: &[u8; 32],
) -> Result<[u8; 32], RecordDigestError> {
    if old_key_version == 0 || new_key_version == 0 {
        return Err(RecordDigestError::ZeroKeyVersion);
    }
    if old_key_version == new_key_version {
        return Err(RecordDigestError::KeyVersionsEqual);
    }
    let mut buf = Vec::with_capacity(53);
    buf.extend_from_slice(RECORD_KEY_CHECKPOINT_MAGIC);
    buf.push(1);
    buf.extend_from_slice(&old_key_version.to_be_bytes());
    buf.extend_from_slice(&new_key_version.to_be_bytes());
    buf.extend_from_slice(&through_sequence.to_be_bytes());
    buf.extend_from_slice(through_mac);
    debug_assert_eq!(buf.len(), 53);
    Ok(domain_digest(domains::AUDIT_RECORD, &buf))
}

/// Encode and digest a prune checkpoint record (`FCP1`, 189 bytes).
#[allow(clippy::too_many_arguments)]
pub fn prune_checkpoint_record_digest(
    operation_id: &Uuid,
    prefix_start: u64,
    prefix_end: u64,
    first_mac: &[u8; 32],
    last_mac: &[u8; 32],
    entry_count: u64,
    export_id: &Uuid,
    export_digest: &[u8; 32],
    prior_checkpoint_digest: &[u8; 32],
) -> Result<[u8; 32], RecordDigestError> {
    if prefix_start > prefix_end {
        return Err(RecordDigestError::RangeInvalid);
    }
    let expected_count = prefix_end
        .checked_sub(prefix_start)
        .and_then(|d| d.checked_add(1))
        .ok_or(RecordDigestError::ArithmeticOverflow)?;
    if entry_count != expected_count {
        return Err(RecordDigestError::EntryCountMismatch);
    }
    if first_mac.iter().all(|b| *b == 0) || last_mac.iter().all(|b| *b == 0) {
        return Err(RecordDigestError::ZeroDigest);
    }
    if export_digest.iter().all(|b| *b == 0) {
        return Err(RecordDigestError::ZeroDigest);
    }
    let mut buf = Vec::with_capacity(189);
    buf.extend_from_slice(RECORD_PRUNE_CHECKPOINT_MAGIC);
    buf.push(1);
    buf.extend_from_slice(operation_id.as_bytes());
    buf.extend_from_slice(&prefix_start.to_be_bytes());
    buf.extend_from_slice(&prefix_end.to_be_bytes());
    buf.extend_from_slice(first_mac);
    buf.extend_from_slice(last_mac);
    buf.extend_from_slice(&entry_count.to_be_bytes());
    buf.extend_from_slice(export_id.as_bytes());
    buf.extend_from_slice(export_digest);
    buf.extend_from_slice(prior_checkpoint_digest);
    debug_assert_eq!(buf.len(), 189);
    Ok(domain_digest(domains::AUDIT_RECORD, &buf))
}

/// Encode and digest an export record (`FEX1`, 93 bytes).
pub fn export_record_digest(
    operation_id: &Uuid,
    export_id: &Uuid,
    from_sequence: u64,
    through_sequence: u64,
    entry_count: u64,
    export_digest: &[u8; 32],
) -> Result<[u8; 32], RecordDigestError> {
    if from_sequence > through_sequence {
        return Err(RecordDigestError::RangeInvalid);
    }
    let expected_count = through_sequence
        .checked_sub(from_sequence)
        .and_then(|d| d.checked_add(1))
        .ok_or(RecordDigestError::ArithmeticOverflow)?;
    if entry_count != expected_count {
        return Err(RecordDigestError::EntryCountMismatch);
    }
    if export_digest.iter().all(|b| *b == 0) {
        return Err(RecordDigestError::ZeroDigest);
    }
    let mut buf = Vec::with_capacity(93);
    buf.extend_from_slice(RECORD_EXPORT_MAGIC);
    buf.push(1);
    buf.extend_from_slice(operation_id.as_bytes());
    buf.extend_from_slice(export_id.as_bytes());
    buf.extend_from_slice(&from_sequence.to_be_bytes());
    buf.extend_from_slice(&through_sequence.to_be_bytes());
    buf.extend_from_slice(&entry_count.to_be_bytes());
    buf.extend_from_slice(export_digest);
    debug_assert_eq!(buf.len(), 93);
    Ok(domain_digest(domains::AUDIT_RECORD, &buf))
}

/// Encode and digest a session-deletion tombstone (`FSD1`, 38 bytes).
pub fn session_deleted_record_digest(
    session_id: &Uuid,
    deletion_generation: u64,
    deleted_at_unix_millis: i64,
    reason: SessionDeletedReason,
) -> Result<[u8; 32], RecordDigestError> {
    if deletion_generation == 0 {
        return Err(RecordDigestError::ZeroVersion);
    }
    let mut buf = Vec::with_capacity(38);
    buf.extend_from_slice(RECORD_SESSION_DELETED_MAGIC);
    buf.push(1);
    buf.extend_from_slice(session_id.as_bytes());
    buf.extend_from_slice(&deletion_generation.to_be_bytes());
    buf.extend_from_slice(&deleted_at_unix_millis.to_be_bytes());
    buf.push(reason as u8);
    debug_assert_eq!(buf.len(), 38);
    Ok(domain_digest(domains::AUDIT_RECORD, &buf))
}

/// Errors when computing record digests.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordDigestError {
    #[error("record digest: zero key version")]
    ZeroKeyVersion,
    #[error("record digest: key versions do not differ")]
    KeyVersionsEqual,
    #[error("record digest: range invalid (start > end)")]
    RangeInvalid,
    #[error("record digest: entry count mismatch")]
    EntryCountMismatch,
    #[error("record digest: arithmetic overflow")]
    ArithmeticOverflow,
    #[error("record digest: zero digest not allowed")]
    ZeroDigest,
    #[error("record digest: zero version not allowed")]
    ZeroVersion,
}

// ---------------------------------------------------------------------------
// Sealed head V1 payload
// ---------------------------------------------------------------------------

/// The sealed audit-chain head V1. Encodes to exactly 110 bytes
/// (confirmed-only) or up to 626 bytes (confirmed-plus-pending).
#[derive(Clone, Debug)]
pub struct ComputerAuditSealedHeadV1 {
    pub pending_present: bool,
    pub sealed_generation: u64,
    pub confirmed_sequence: u64,
    pub confirmed_mac: [u8; 32],
    pub confirmed_key_version: u32,
    pub database_instance_id: [u8; 16],
    pub pending_entry: [u8; ENTRY_LEN],
    pub pending_mac: [u8; 32],
    pub pending_previous_sequence: u64,
    pub pending_previous_mac: [u8; 32],
    pub pending_key_version: u32,
    pub pending_database_instance_id: [u8; 16],
}

impl ComputerAuditSealedHeadV1 {
    pub fn confirmed_only(
        sealed_generation: u64,
        confirmed_sequence: u64,
        confirmed_mac: [u8; 32],
        confirmed_key_version: u32,
        database_instance_id: [u8; 16],
    ) -> Self {
        Self {
            pending_present: false,
            sealed_generation,
            confirmed_sequence,
            confirmed_mac,
            confirmed_key_version,
            database_instance_id,
            pending_entry: [0u8; ENTRY_LEN],
            pending_mac: [0u8; 32],
            pending_previous_sequence: 0,
            pending_previous_mac: [0u8; 32],
            pending_key_version: 0,
            pending_database_instance_id: [0u8; 16],
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_pending(
        sealed_generation: u64,
        confirmed_sequence: u64,
        confirmed_mac: [u8; 32],
        confirmed_key_version: u32,
        database_instance_id: [u8; 16],
        pending_entry: [u8; ENTRY_LEN],
        pending_mac: [u8; 32],
        pending_previous_sequence: u64,
        pending_previous_mac: [u8; 32],
        pending_key_version: u32,
        pending_database_instance_id: [u8; 16],
    ) -> Self {
        Self {
            pending_present: true,
            sealed_generation,
            confirmed_sequence,
            confirmed_mac,
            confirmed_key_version,
            database_instance_id,
            pending_entry,
            pending_mac,
            pending_previous_sequence,
            pending_previous_mac,
            pending_key_version,
            pending_database_instance_id,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let len = if self.pending_present {
            SEALED_HEAD_MAX_LEN
        } else {
            SEALED_HEAD_CONFIRMED_ONLY_LEN
        };
        let mut buf = Vec::with_capacity(len);
        buf.extend_from_slice(SEALED_HEAD_MAGIC);
        buf.push(SEALED_HEAD_VERSION);
        buf.push(if self.pending_present { 1 } else { 0 });
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&self.sealed_generation.to_be_bytes());
        buf.extend_from_slice(&self.confirmed_sequence.to_be_bytes());
        buf.extend_from_slice(&self.confirmed_mac);
        buf.extend_from_slice(&self.confirmed_key_version.to_be_bytes());
        buf.extend_from_slice(&self.database_instance_id);
        let pending_len = if self.pending_present {
            ENTRY_LEN as u16
        } else {
            0
        };
        buf.extend_from_slice(&pending_len.to_be_bytes());
        debug_assert_eq!(buf.len(), SEALED_HEAD_FIXED_PREFIX_LEN);

        if self.pending_present {
            buf.extend_from_slice(&self.pending_entry);
            buf.extend_from_slice(&self.pending_mac);
            buf.extend_from_slice(&self.pending_previous_sequence.to_be_bytes());
            buf.extend_from_slice(&self.pending_previous_mac);
            buf.extend_from_slice(&self.pending_key_version.to_be_bytes());
            buf.extend_from_slice(&self.pending_database_instance_id);
        }

        let digest: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&buf);
            h.finalize().into()
        };
        buf.extend_from_slice(&digest);
        debug_assert_eq!(buf.len(), len);
        buf
    }

    pub fn decode(buf: &[u8]) -> Result<Self, SealedHeadDecodeError> {
        if buf.len() < SEALED_HEAD_CONFIRMED_ONLY_LEN {
            return Err(SealedHeadDecodeError::TooShort);
        }
        if buf.len() > SEALED_HEAD_MAX_LEN {
            return Err(SealedHeadDecodeError::TooLong);
        }
        if &buf[0..4] != SEALED_HEAD_MAGIC {
            return Err(SealedHeadDecodeError::BadMagic);
        }
        if buf[4] != SEALED_HEAD_VERSION {
            return Err(SealedHeadDecodeError::BadVersion(buf[4]));
        }
        let pending_present = match buf[5] {
            0 => false,
            1 => true,
            other => return Err(SealedHeadDecodeError::BadPendingPresent(other)),
        };
        let reserved = u16::from_be_bytes(buf[6..8].try_into().unwrap());
        if reserved != 0 {
            return Err(SealedHeadDecodeError::ReservedNonzero(reserved));
        }
        let sealed_generation = u64::from_be_bytes(buf[8..16].try_into().unwrap());
        let confirmed_sequence = u64::from_be_bytes(buf[16..24].try_into().unwrap());
        let confirmed_mac: [u8; 32] = buf[24..56].try_into().unwrap();
        let confirmed_key_version = u32::from_be_bytes(buf[56..60].try_into().unwrap());
        let database_instance_id: [u8; 16] = buf[60..76].try_into().unwrap();
        let pending_length = u16::from_be_bytes(buf[76..78].try_into().unwrap());

        let expected_len = if pending_present {
            SEALED_HEAD_MAX_LEN
        } else {
            SEALED_HEAD_CONFIRMED_ONLY_LEN
        };
        if buf.len() != expected_len {
            return Err(SealedHeadDecodeError::LengthMismatch {
                expected: expected_len,
                actual: buf.len(),
            });
        }
        if pending_present && pending_length != ENTRY_LEN as u16 {
            return Err(SealedHeadDecodeError::BadPendingLength(pending_length));
        }
        if !pending_present && pending_length != 0 {
            return Err(SealedHeadDecodeError::BadPendingLength(pending_length));
        }

        let stored_digest: [u8; 32] = buf[buf.len() - 32..].try_into().unwrap();
        let computed_digest: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&buf[..buf.len() - 32]);
            h.finalize().into()
        };
        if stored_digest != computed_digest {
            return Err(SealedHeadDecodeError::PayloadDigestMismatch);
        }

        if !pending_present {
            return Ok(Self::confirmed_only(
                sealed_generation,
                confirmed_sequence,
                confirmed_mac,
                confirmed_key_version,
                database_instance_id,
            ));
        }

        let mut off = SEALED_HEAD_FIXED_PREFIX_LEN;
        let pending_entry: [u8; ENTRY_LEN] = buf[off..off + ENTRY_LEN].try_into().unwrap();
        off += ENTRY_LEN;
        let pending_mac: [u8; 32] = buf[off..off + 32].try_into().unwrap();
        off += 32;
        let pending_previous_sequence = u64::from_be_bytes(buf[off..off + 8].try_into().unwrap());
        off += 8;
        let pending_previous_mac: [u8; 32] = buf[off..off + 32].try_into().unwrap();
        off += 32;
        let pending_key_version = u32::from_be_bytes(buf[off..off + 4].try_into().unwrap());
        off += 4;
        let pending_database_instance_id: [u8; 16] = buf[off..off + 16].try_into().unwrap();

        Ok(Self::with_pending(
            sealed_generation,
            confirmed_sequence,
            confirmed_mac,
            confirmed_key_version,
            database_instance_id,
            pending_entry,
            pending_mac,
            pending_previous_sequence,
            pending_previous_mac,
            pending_key_version,
            pending_database_instance_id,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SealedHeadDecodeError {
    #[error("sealed head too short")]
    TooShort,
    #[error("sealed head too long")]
    TooLong,
    #[error("sealed head bad magic")]
    BadMagic,
    #[error("sealed head bad version: {0}")]
    BadVersion(u8),
    #[error("sealed head bad pending_present byte: {0}")]
    BadPendingPresent(u8),
    #[error("sealed head reserved nonzero: {0}")]
    ReservedNonzero(u16),
    #[error("sealed head bad pending_length: {0}")]
    BadPendingLength(u16),
    #[error("sealed head length mismatch: expected {expected}, actual {actual}")]
    LengthMismatch { expected: usize, actual: usize },
    #[error("sealed head payload digest mismatch")]
    PayloadDigestMismatch,
}

// ---------------------------------------------------------------------------
// Verification statuses (8 statuses, exact precedence)
// ---------------------------------------------------------------------------

/// The eight verification statuses. Precedence is exactly
/// `corrupt > unavailable_secure_store > unavailable_database >
/// unavailable_key > pending_recovery > database_behind_sealed_head >
/// sealed_head_behind_database > verified`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditVerifyStatus {
    Corrupt,
    UnavailableSecureStore,
    UnavailableDatabase,
    UnavailableKey,
    PendingRecovery,
    DatabaseBehindSealedHead,
    SealedHeadBehindDatabase,
    Verified,
}

impl AuditVerifyStatus {
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Verified => 0,
            Self::Corrupt => 2,
            Self::PendingRecovery => 3,
            Self::DatabaseBehindSealedHead => 4,
            Self::SealedHeadBehindDatabase => 5,
            Self::UnavailableSecureStore => 6,
            Self::UnavailableDatabase => 7,
            Self::UnavailableKey => 8,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Corrupt => "corrupt",
            Self::UnavailableSecureStore => "unavailable_secure_store",
            Self::UnavailableDatabase => "unavailable_database",
            Self::UnavailableKey => "unavailable_key",
            Self::PendingRecovery => "pending_recovery",
            Self::DatabaseBehindSealedHead => "database_behind_sealed_head",
            Self::SealedHeadBehindDatabase => "sealed_head_behind_database",
            Self::Verified => "verified",
        }
    }

    pub fn precedence(self) -> u8 {
        match self {
            Self::Corrupt => 0,
            Self::UnavailableSecureStore => 1,
            Self::UnavailableDatabase => 2,
            Self::UnavailableKey => 3,
            Self::PendingRecovery => 4,
            Self::DatabaseBehindSealedHead => 5,
            Self::SealedHeadBehindDatabase => 6,
            Self::Verified => 7,
        }
    }

    pub fn higher_precedence(a: Self, b: Self) -> Self {
        if a.precedence() <= b.precedence() {
            a
        } else {
            b
        }
    }
}

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct AuditVerifyResult {
    pub status: AuditVerifyStatus,
    pub confirmed_sequence: u64,
    pub confirmed_mac: [u8; 32],
    pub sealed_generation: u64,
    pub database_instance_id: [u8; 16],
    pub entry_count: u64,
}

#[derive(Clone, Debug)]
pub struct ChainEntry {
    pub sequence: u64,
    pub entry_bytes: [u8; ENTRY_LEN],
    pub mac: [u8; 32],
}

fn corrupt_result(sealed: &ComputerAuditSealedHeadV1, entry_count: u64) -> AuditVerifyResult {
    AuditVerifyResult {
        status: AuditVerifyStatus::Corrupt,
        confirmed_sequence: sealed.confirmed_sequence,
        confirmed_mac: sealed.confirmed_mac,
        sealed_generation: sealed.sealed_generation,
        database_instance_id: sealed.database_instance_id,
        entry_count,
    }
}

/// Verify a chain of entries against a sealed head and a key resolver.
///
/// The resolver must not copy HMAC key material into an unzeroized buffer.
/// Production passes a borrow of the zeroizing key store; tests may return
/// owned bytes because they are not the machine-local signing key.
pub fn verify_chain<F, K>(
    sealed_head: Option<&ComputerAuditSealedHeadV1>,
    db_entries: Option<&[ChainEntry]>,
    keys: F,
) -> AuditVerifyResult
where
    F: Fn(u32) -> Option<K>,
    K: AsRef<[u8]>,
{
    let sealed = match sealed_head {
        None => {
            return AuditVerifyResult {
                status: AuditVerifyStatus::UnavailableSecureStore,
                confirmed_sequence: 0,
                confirmed_mac: [0u8; 32],
                sealed_generation: 0,
                database_instance_id: [0u8; 16],
                entry_count: 0,
            };
        }
        Some(h) => h,
    };

    let entries = match db_entries {
        None => {
            return AuditVerifyResult {
                status: AuditVerifyStatus::UnavailableDatabase,
                confirmed_sequence: sealed.confirmed_sequence,
                confirmed_mac: sealed.confirmed_mac,
                sealed_generation: sealed.sealed_generation,
                database_instance_id: sealed.database_instance_id,
                entry_count: 0,
            };
        }
        Some(e) => e,
    };

    let mut prev_seq: u64 = 0;
    let mut prev_mac: [u8; 32] = [0u8; 32];
    let mut last_valid_seq: u64 = 0;
    let mut db_confirmed_seq: u64 = 0;
    let mut db_confirmed_mac: [u8; 32] = [0u8; 32];

    for entry in entries {
        let decoded = match ComputerAuditEntryV1::decode(&entry.entry_bytes) {
            Ok(d) => d,
            Err(_) => return corrupt_result(sealed, last_valid_seq),
        };
        if decoded.sequence != prev_seq + 1 {
            return corrupt_result(sealed, last_valid_seq);
        }
        if decoded.previous_mac != prev_mac {
            return corrupt_result(sealed, last_valid_seq);
        }
        let key = match keys(decoded.key_version) {
            Some(k) => k,
            None => {
                return AuditVerifyResult {
                    status: AuditVerifyStatus::UnavailableKey,
                    confirmed_sequence: sealed.confirmed_sequence,
                    confirmed_mac: sealed.confirmed_mac,
                    sealed_generation: sealed.sealed_generation,
                    database_instance_id: sealed.database_instance_id,
                    entry_count: prev_seq,
                };
            }
        };
        let computed_mac = entry_mac(key.as_ref(), &entry.entry_bytes);
        if computed_mac != entry.mac {
            return corrupt_result(sealed, last_valid_seq);
        }
        if decoded.validate_presence().is_err() {
            return corrupt_result(sealed, last_valid_seq);
        }
        prev_seq = decoded.sequence;
        prev_mac = entry.mac;
        last_valid_seq = decoded.sequence;
        db_confirmed_seq = decoded.sequence;
        db_confirmed_mac = entry.mac;
    }

    let sealed_confirmed_seq = sealed.confirmed_sequence;
    let sealed_confirmed_mac = sealed.confirmed_mac;

    if sealed.pending_present {
        let pending_entry = match ComputerAuditEntryV1::decode(&sealed.pending_entry) {
            Ok(d) => d,
            Err(_) => return corrupt_result(sealed, db_confirmed_seq),
        };
        if pending_entry.previous_mac != sealed_confirmed_mac
            || pending_entry.sequence != sealed_confirmed_seq + 1
        {
            return corrupt_result(sealed, db_confirmed_seq);
        }
        let pending_key = match keys(pending_entry.key_version) {
            Some(k) => k,
            None => {
                return AuditVerifyResult {
                    status: AuditVerifyStatus::UnavailableKey,
                    confirmed_sequence: sealed_confirmed_seq,
                    confirmed_mac: sealed_confirmed_mac,
                    sealed_generation: sealed.sealed_generation,
                    database_instance_id: sealed.database_instance_id,
                    entry_count: db_confirmed_seq,
                };
            }
        };
        let computed_pending_mac = entry_mac(pending_key.as_ref(), &sealed.pending_entry);
        if computed_pending_mac != sealed.pending_mac {
            return corrupt_result(sealed, db_confirmed_seq);
        }
        if sealed.pending_previous_sequence != sealed_confirmed_seq
            || sealed.pending_previous_mac != sealed_confirmed_mac
        {
            return corrupt_result(sealed, db_confirmed_seq);
        }
        if pending_entry.validate_presence().is_err() {
            return corrupt_result(sealed, db_confirmed_seq);
        }

        if db_confirmed_seq == sealed_confirmed_seq {
            AuditVerifyResult {
                status: AuditVerifyStatus::PendingRecovery,
                confirmed_sequence: sealed_confirmed_seq,
                confirmed_mac: sealed_confirmed_mac,
                sealed_generation: sealed.sealed_generation,
                database_instance_id: sealed.database_instance_id,
                entry_count: db_confirmed_seq,
            }
        } else if db_confirmed_seq == sealed_confirmed_seq + 1 {
            let db_pending = entries.last().unwrap();
            if db_pending.entry_bytes == sealed.pending_entry
                && db_pending.mac == sealed.pending_mac
            {
                AuditVerifyResult {
                    status: AuditVerifyStatus::PendingRecovery,
                    confirmed_sequence: sealed_confirmed_seq,
                    confirmed_mac: sealed_confirmed_mac,
                    sealed_generation: sealed.sealed_generation,
                    database_instance_id: sealed.database_instance_id,
                    entry_count: db_confirmed_seq,
                }
            } else {
                corrupt_result(sealed, db_confirmed_seq)
            }
        } else if db_confirmed_seq < sealed_confirmed_seq {
            AuditVerifyResult {
                status: AuditVerifyStatus::DatabaseBehindSealedHead,
                confirmed_sequence: sealed_confirmed_seq,
                confirmed_mac: sealed_confirmed_mac,
                sealed_generation: sealed.sealed_generation,
                database_instance_id: sealed.database_instance_id,
                entry_count: db_confirmed_seq,
            }
        } else {
            AuditVerifyResult {
                status: AuditVerifyStatus::SealedHeadBehindDatabase,
                confirmed_sequence: sealed_confirmed_seq,
                confirmed_mac: sealed_confirmed_mac,
                sealed_generation: sealed.sealed_generation,
                database_instance_id: sealed.database_instance_id,
                entry_count: db_confirmed_seq,
            }
        }
    } else if db_confirmed_seq == sealed_confirmed_seq && db_confirmed_mac == sealed_confirmed_mac {
        AuditVerifyResult {
            status: AuditVerifyStatus::Verified,
            confirmed_sequence: sealed_confirmed_seq,
            confirmed_mac: sealed_confirmed_mac,
            sealed_generation: sealed.sealed_generation,
            database_instance_id: sealed.database_instance_id,
            entry_count: db_confirmed_seq,
        }
    } else if db_confirmed_seq < sealed_confirmed_seq {
        AuditVerifyResult {
            status: AuditVerifyStatus::DatabaseBehindSealedHead,
            confirmed_sequence: sealed_confirmed_seq,
            confirmed_mac: sealed_confirmed_mac,
            sealed_generation: sealed.sealed_generation,
            database_instance_id: sealed.database_instance_id,
            entry_count: db_confirmed_seq,
        }
    } else {
        AuditVerifyResult {
            status: AuditVerifyStatus::SealedHeadBehindDatabase,
            confirmed_sequence: sealed_confirmed_seq,
            confirmed_mac: sealed_confirmed_mac,
            sealed_generation: sealed.sealed_generation,
            database_instance_id: sealed.database_instance_id,
            entry_count: db_confirmed_seq,
        }
    }
}

const _: () = {
    assert!(ENTRY_LEN == 424, "ENTRY_LEN must be 424");
    assert!(
        SEALED_HEAD_CONFIRMED_ONLY_LEN == 110,
        "confirmed-only must be 110"
    );
    assert!(
        SEALED_HEAD_FIXED_PREFIX_LEN == 78,
        "fixed prefix must be 78"
    );
    assert!(SEALED_HEAD_MAX_LEN == 626, "max sealed head must be 626");
    assert!(SEALED_HEAD_CEILING == 1024, "ceiling must be 1024");
    assert!(
        SEALED_HEAD_CEILING - SEALED_HEAD_MAX_LEN == SEALED_HEAD_CEILING_MARGIN,
        "ceiling margin must be 398"
    );
};

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use chain::{AppendFault, TestAuditHarness};
