//! `ToolMediaSubjectReceiptV1` canonical encoding and digest.
//!
//! The receipt has only:
//! `{schema_version, issuer_kind, principal_digest, project_digest, session_id,
//!   authorization_epoch, subject_digest}`
//!
//! Canonical bytes are:
//! `u8 version=1 | u8 issuer (1 local_owner, 2 remote_device) | [u8;32]
//!  principal_digest | [u8;32] project_digest | [u8;16] session UUID network
//!  order | u64 epoch big-endian`
//!
//! `subject_digest = SHA-256("flycockpit.tool-media-subject.v1\0" || preceding
//! bytes)`.

use sha2::{Digest, Sha256};

use super::locator::LocatorV1;

/// Receipt schema version — always 1.
pub const RECEIPT_VERSION: u8 = 1;

/// Issuer kind: 1 = local_owner, 2 = remote_device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IssuerKind {
    LocalOwner = 1,
    RemoteDevice = 2,
}

impl IssuerKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::LocalOwner),
            2 => Some(Self::RemoteDevice),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The domain-separation prefix for `subject_digest`.
const SUBJECT_DOMAIN: &[u8] = b"flycockpit.tool-media-subject.v1\0";

/// `ToolMediaSubjectReceiptV1` — the canonical, replayable authority receipt.
///
/// Only the fields listed in the prompt are present. The `subject_digest` is
/// derived from the preceding canonical bytes and is NOT independently
/// controllable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ToolMediaSubjectReceiptV1 {
    pub issuer_kind: IssuerKind,
    pub principal_digest: [u8; 32],
    pub project_digest: [u8; 32],
    /// Raw RFC UUID 16-byte network-order representation.
    pub session_id: [u8; 16],
    pub authorization_epoch: u64,
    /// Derived from canonical bytes; validated on decode.
    pub subject_digest: [u8; 32],
}

impl ToolMediaSubjectReceiptV1 {
    /// Build a receipt from its constituent fields, computing `subject_digest`.
    ///
    /// `locator` is used to derive `principal_digest` (and the caller supplies
    /// `project_digest` from the project UUID). The `authorization_epoch` is
    /// read from the current epoch row for the key tuple.
    pub fn new(
        issuer_kind: IssuerKind,
        locator: &LocatorV1,
        project_digest: [u8; 32],
        session_id: [u8; 16],
        authorization_epoch: u64,
    ) -> Self {
        let principal_digest = locator.principal_digest();
        let preceding = canonical_preceding_bytes(
            issuer_kind,
            &principal_digest,
            &project_digest,
            &session_id,
            authorization_epoch,
        );
        let subject_digest = subject_digest(&preceding);
        Self {
            issuer_kind,
            principal_digest,
            project_digest,
            session_id,
            authorization_epoch,
            subject_digest,
        }
    }

    /// Encode the full canonical bytes (preceding + subject_digest).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let preceding = canonical_preceding_bytes(
            self.issuer_kind,
            &self.principal_digest,
            &self.project_digest,
            &self.session_id,
            self.authorization_epoch,
        );
        let mut out = preceding;
        out.extend_from_slice(&self.subject_digest);
        out
    }

    /// Decode canonical bytes, validating `subject_digest`.
    pub fn decode(bytes: &[u8]) -> Result<Self, ReceiptDecodeError> {
        if bytes.len() != CANONICAL_LEN {
            return Err(ReceiptDecodeError::Length {
                expected: CANONICAL_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0] != RECEIPT_VERSION {
            return Err(ReceiptDecodeError::Version(bytes[0]));
        }
        let issuer_kind =
            IssuerKind::from_u8(bytes[1]).ok_or(ReceiptDecodeError::Issuer(bytes[1]))?;
        let principal_digest: [u8; 32] =
            bytes[2..34]
                .try_into()
                .map_err(|_| ReceiptDecodeError::Length {
                    expected: CANONICAL_LEN,
                    actual: bytes.len(),
                })?;
        let project_digest: [u8; 32] =
            bytes[34..66]
                .try_into()
                .map_err(|_| ReceiptDecodeError::Length {
                    expected: CANONICAL_LEN,
                    actual: bytes.len(),
                })?;
        let session_id: [u8; 16] =
            bytes[66..82]
                .try_into()
                .map_err(|_| ReceiptDecodeError::Length {
                    expected: CANONICAL_LEN,
                    actual: bytes.len(),
                })?;
        let authorization_epoch = u64::from_be_bytes(bytes[82..90].try_into().unwrap());
        let subject_digest: [u8; 32] =
            bytes[90..122]
                .try_into()
                .map_err(|_| ReceiptDecodeError::Length {
                    expected: CANONICAL_LEN,
                    actual: bytes.len(),
                })?;

        let preceding = &bytes[..90];
        let expected = subject_digest(preceding);
        if subject_digest != expected {
            return Err(ReceiptDecodeError::SubjectDigestMismatch);
        }

        Ok(Self {
            issuer_kind,
            principal_digest,
            project_digest,
            session_id,
            authorization_epoch,
            subject_digest,
        })
    }
}

/// Total canonical byte length: 1 + 1 + 32 + 32 + 16 + 8 + 32 = 122.
pub const CANONICAL_LEN: usize = 122;

/// Preceding bytes length (without subject_digest): 1 + 1 + 32 + 32 + 16 + 8 = 90.
pub const PRECEDING_LEN: usize = 90;

fn canonical_preceding_bytes(
    issuer_kind: IssuerKind,
    principal_digest: &[u8; 32],
    project_digest: &[u8; 32],
    session_id: &[u8; 16],
    authorization_epoch: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(PRECEDING_LEN);
    out.push(RECEIPT_VERSION);
    out.push(issuer_kind.as_u8());
    out.extend_from_slice(principal_digest);
    out.extend_from_slice(project_digest);
    out.extend_from_slice(session_id);
    out.extend_from_slice(&authorization_epoch.to_be_bytes());
    out
}

fn subject_digest(preceding: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SUBJECT_DOMAIN);
    hasher.update(preceding);
    hasher.finalize().into()
}

/// Error decoding a receipt.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ReceiptDecodeError {
    #[error("receipt length {actual}, expected {expected}")]
    Length { expected: usize, actual: usize },
    #[error("receipt version {0}, expected 1")]
    Version(u8),
    #[error("receipt issuer {0}, expected 1 or 2")]
    Issuer(u8),
    #[error("subject_digest does not match canonical bytes")]
    SubjectDigestMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_round_trip() {
        let locator = LocatorV1::local_owner();
        let project_uuid = [0xAB; 16];
        let project_digest = LocatorV1::project_digest(&project_uuid);
        let session_id = [0xCD; 16];
        let receipt = ToolMediaSubjectReceiptV1::new(
            IssuerKind::LocalOwner,
            &locator,
            project_digest,
            session_id,
            42,
        );
        let bytes = receipt.canonical_bytes();
        assert_eq!(bytes.len(), CANONICAL_LEN);
        let decoded = ToolMediaSubjectReceiptV1::decode(&bytes).unwrap();
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn receipt_tamper_fails() {
        let locator = LocatorV1::local_owner();
        let project_uuid = [0xAB; 16];
        let project_digest = LocatorV1::project_digest(&project_uuid);
        let session_id = [0xCD; 16];
        let receipt = ToolMediaSubjectReceiptV1::new(
            IssuerKind::LocalOwner,
            &locator,
            project_digest,
            session_id,
            42,
        );
        let mut bytes = receipt.canonical_bytes();
        bytes[5] ^= 0x01; // tamper principal_digest
        assert!(ToolMediaSubjectReceiptV1::decode(&bytes).is_err());
    }

    #[test]
    fn receipt_remote_device() {
        let device_uuid = [0xEF; 16];
        let locator = LocatorV1::remote_device(device_uuid, 7);
        let project_uuid = [0xAB; 16];
        let project_digest = LocatorV1::project_digest(&project_uuid);
        let session_id = [0xCD; 16];
        let receipt = ToolMediaSubjectReceiptV1::new(
            IssuerKind::RemoteDevice,
            &locator,
            project_digest,
            session_id,
            0,
        );
        let bytes = receipt.canonical_bytes();
        assert_eq!(bytes[1], 2); // remote_device
        let decoded = ToolMediaSubjectReceiptV1::decode(&bytes).unwrap();
        assert_eq!(receipt, decoded);
    }
}
