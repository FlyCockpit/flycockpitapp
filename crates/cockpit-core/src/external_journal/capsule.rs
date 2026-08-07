//! Fixed 64-KiB two-slot recovery capsule format.
//!
//! A capsule is exactly two alternating 32-KiB authenticated slots. Each slot
//! holds a fixed header (magic, format version, slot index, operation
//! identity), the monotonically increasing journal version, the sanitized
//! canonical projection, zero padding, the payload digest, the key version,
//! and an HMAC over all of it. A checksum alone is not sufficient: without
//! keyed authenticity a hostile replacement would import cleanly.
//!
//! The layout is fixed so that after handoff a fallback transition rewrites
//! one already-allocated slot in place — never a new file, directory entry, or
//! disk block.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use cockpit_db::external_journal::ExternalJournalState;

use super::ExternalJournalError;
use super::keys::SpoolKeyRing;

type HmacSha256 = Hmac<Sha256>;

/// Exact allocated capsule size.
pub const CAPSULE_BYTES: usize = 65_536;

/// Exact slot size. Two slots exactly fill a capsule.
pub const SLOT_BYTES: usize = 32_768;

/// Fixed header length at the front of every slot.
pub const SLOT_HEADER_BYTES: usize = 64;

/// Offset of the payload digest inside a slot.
pub const SLOT_DIGEST_OFFSET: usize = SLOT_BYTES - 64;

/// Offset of the HMAC tag inside a slot.
pub const SLOT_TAG_OFFSET: usize = SLOT_BYTES - 32;

/// Bytes available for the projection plus its zero padding.
pub const SLOT_BODY_BYTES: usize = SLOT_DIGEST_OFFSET - SLOT_HEADER_BYTES;

/// Fixed 16-byte capsule magic. Never a path, name, or user value.
pub const CAPSULE_MAGIC: &[u8; 16] = b"FLYCKPT-XJCAPS\x01\x00";

/// Capsule format version, distinct from the journal record version.
pub const CAPSULE_FORMAT_VERSION: u16 = 1;

/// Domain separator for every slot HMAC.
const DOMAIN_SLOT_MAC: &[u8] = b"flycockpit-external-journal-capsule-slot-mac-v1\0";

/// Domain separator for the pre-write sentinel pattern.
const DOMAIN_SENTINEL: &[u8] = b"flycockpit-external-journal-capsule-sentinel-v1\0";

const _: () = {
    assert!(SLOT_BYTES * 2 == CAPSULE_BYTES);
    assert!(SLOT_BODY_BYTES >= super::projection::MAX_PROJECTION_BYTES);
};

/// One authenticated capsule slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleSlot {
    pub slot_index: u8,
    pub operation_id: Uuid,
    /// Journal record version this slot asserts. Monotonically increasing.
    pub journal_version: u64,
    pub key_version: u32,
    pub state: ExternalJournalState,
    pub updated_at_wall_ms: i64,
    pub projection: Vec<u8>,
}

/// Why a capsule was quarantined instead of imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineReason {
    /// Both slots failed authentication or structural validation.
    NoAuthenticSlot,
    /// Two authentic slots claim the same version but disagree.
    EqualVersionDisagreement,
    /// The slot authenticates but names a different operation.
    OwnerMismatch,
}

impl QuarantineReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoAuthenticSlot => "no authentic slot",
            Self::EqualVersionDisagreement => "equal-version slot disagreement",
            Self::OwnerMismatch => "slot owner mismatch",
        }
    }
}

/// Result of reading a capsule's two slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotChoice {
    /// The unique highest authenticated slot.
    Authentic(Box<CapsuleSlot>),
    /// Quarantine and block new dispatch.
    Quarantine(QuarantineReason),
}

/// Map a journal state onto a stable numeric slot header code.
fn state_code(state: ExternalJournalState) -> u32 {
    ExternalJournalState::ALL
        .iter()
        .position(|candidate| *candidate == state)
        .map(|index| index as u32)
        .unwrap_or(u32::MAX)
}

fn state_from_code(code: u32) -> Result<ExternalJournalState, ExternalJournalError> {
    ExternalJournalState::ALL
        .get(code as usize)
        .copied()
        .ok_or_else(|| ExternalJournalError::Capsule(format!("unknown slot state code {code}")))
}

fn slot_tag(key: &[u8], authenticated: &[u8]) -> Result<[u8; 32], ExternalJournalError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| ExternalJournalError::Capsule("slot hmac key length".to_string()))?;
    mac.update(DOMAIN_SLOT_MAC);
    mac.update(authenticated);
    Ok(mac.finalize().into_bytes().into())
}

impl CapsuleSlot {
    /// Encode this slot into its exact 32,768 authenticated bytes.
    pub fn encode(&self, keys: &SpoolKeyRing) -> Result<Vec<u8>, ExternalJournalError> {
        if self.projection.len() > super::projection::MAX_PROJECTION_BYTES {
            return Err(ExternalJournalError::ProjectionTooLarge {
                len: self.projection.len(),
                cap: super::projection::MAX_PROJECTION_BYTES,
            });
        }
        if self.slot_index > 1 {
            return Err(ExternalJournalError::Capsule(format!(
                "slot index {} is out of range",
                self.slot_index
            )));
        }
        let key = keys.key_for_version(self.key_version)?;

        let mut bytes = vec![0u8; SLOT_BYTES];
        bytes[0..16].copy_from_slice(CAPSULE_MAGIC);
        bytes[16..18].copy_from_slice(&CAPSULE_FORMAT_VERSION.to_le_bytes());
        bytes[18..20].copy_from_slice(&u16::from(self.slot_index).to_le_bytes());
        bytes[20..36].copy_from_slice(self.operation_id.as_bytes());
        bytes[36..44].copy_from_slice(&self.journal_version.to_le_bytes());
        bytes[44..48].copy_from_slice(&self.key_version.to_le_bytes());
        let projection_len = u32::try_from(self.projection.len())
            .map_err(|_| ExternalJournalError::Capsule("projection length overflow".to_string()))?;
        bytes[48..52].copy_from_slice(&projection_len.to_le_bytes());
        bytes[52..60].copy_from_slice(&self.updated_at_wall_ms.to_le_bytes());
        bytes[60..64].copy_from_slice(&state_code(self.state).to_le_bytes());
        // Body: projection then zero padding, already zeroed above.
        bytes[SLOT_HEADER_BYTES..SLOT_HEADER_BYTES + self.projection.len()]
            .copy_from_slice(&self.projection);

        let digest: [u8; 32] = Sha256::digest(&self.projection).into();
        bytes[SLOT_DIGEST_OFFSET..SLOT_DIGEST_OFFSET + 32].copy_from_slice(&digest);

        let tag = slot_tag(key.as_ref(), &bytes[..SLOT_TAG_OFFSET])?;
        bytes[SLOT_TAG_OFFSET..].copy_from_slice(&tag);
        Ok(bytes)
    }

    /// Decode and authenticate one slot.
    ///
    /// Every failure mode — wrong magic, wrong format, unknown or retired key
    /// version, wrong length, digest mismatch, HMAC mismatch, owner mismatch —
    /// returns an error, which the caller turns into quarantine.
    pub fn decode(
        bytes: &[u8],
        expected_operation_id: Uuid,
        keys: &SpoolKeyRing,
    ) -> Result<Self, ExternalJournalError> {
        if bytes.len() != SLOT_BYTES {
            return Err(ExternalJournalError::Capsule(format!(
                "slot is {} bytes; expected {SLOT_BYTES}",
                bytes.len()
            )));
        }
        if &bytes[0..16] != CAPSULE_MAGIC.as_slice() {
            return Err(ExternalJournalError::Capsule(
                "bad capsule magic".to_string(),
            ));
        }
        let format_version = u16::from_le_bytes([bytes[16], bytes[17]]);
        if format_version != CAPSULE_FORMAT_VERSION {
            return Err(ExternalJournalError::Capsule(format!(
                "unsupported capsule format version {format_version}"
            )));
        }
        let slot_index = u16::from_le_bytes([bytes[18], bytes[19]]);
        if slot_index > 1 {
            return Err(ExternalJournalError::Capsule(format!(
                "slot index {slot_index} is out of range"
            )));
        }
        let mut id_bytes = [0u8; 16];
        id_bytes.copy_from_slice(&bytes[20..36]);
        let operation_id = Uuid::from_bytes(id_bytes);
        if operation_id != expected_operation_id {
            return Err(ExternalJournalError::Capsule(
                "slot names a different operation".to_string(),
            ));
        }
        let journal_version = u64::from_le_bytes(bytes[36..44].try_into().expect("8 bytes"));
        let key_version = u32::from_le_bytes(bytes[44..48].try_into().expect("4 bytes"));
        let projection_len =
            u32::from_le_bytes(bytes[48..52].try_into().expect("4 bytes")) as usize;
        if projection_len > super::projection::MAX_PROJECTION_BYTES {
            return Err(ExternalJournalError::ProjectionTooLarge {
                len: projection_len,
                cap: super::projection::MAX_PROJECTION_BYTES,
            });
        }
        let updated_at_wall_ms = i64::from_le_bytes(bytes[52..60].try_into().expect("8 bytes"));
        let state = state_from_code(u32::from_le_bytes(
            bytes[60..64].try_into().expect("4 bytes"),
        ))?;

        // Authenticate before trusting any of the above for import.
        let key = keys.key_for_version(key_version)?;
        let mut mac = HmacSha256::new_from_slice(key.as_ref())
            .map_err(|_| ExternalJournalError::Capsule("slot hmac key length".to_string()))?;
        mac.update(DOMAIN_SLOT_MAC);
        mac.update(&bytes[..SLOT_TAG_OFFSET]);
        // Constant-time verification supplied by `hmac`.
        mac.verify_slice(&bytes[SLOT_TAG_OFFSET..])
            .map_err(|_| ExternalJournalError::Capsule("slot hmac mismatch".to_string()))?;

        let projection = bytes[SLOT_HEADER_BYTES..SLOT_HEADER_BYTES + projection_len].to_vec();
        let digest: [u8; 32] = Sha256::digest(&projection).into();
        if digest.as_slice() != &bytes[SLOT_DIGEST_OFFSET..SLOT_DIGEST_OFFSET + 32] {
            return Err(ExternalJournalError::Capsule(
                "slot payload digest mismatch".to_string(),
            ));
        }
        // Padding must be zero: a nonzero tail would be an out-of-band channel.
        if bytes[SLOT_HEADER_BYTES + projection_len..SLOT_DIGEST_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ExternalJournalError::Capsule(
                "slot padding is not zero".to_string(),
            ));
        }

        Ok(Self {
            slot_index: slot_index as u8,
            operation_id,
            journal_version,
            key_version,
            state,
            updated_at_wall_ms,
            projection,
        })
    }
}

/// Choose the authoritative slot from a capsule's two decoded slots.
///
/// Slot disagreement chooses the unique highest valid version. Equal-version
/// disagreement or two invalid slots quarantines and blocks.
pub fn choose_slot(
    first: Result<CapsuleSlot, ExternalJournalError>,
    second: Result<CapsuleSlot, ExternalJournalError>,
) -> SlotChoice {
    match authentic_slots(first, second) {
        Err(reason) => SlotChoice::Quarantine(reason),
        Ok(mut slots) => {
            slots.sort_by_key(|slot| slot.journal_version);
            let highest = slots.pop().expect("authentic_slots returns at least one");
            SlotChoice::Authentic(Box::new(highest))
        }
    }
}

/// Every authentic slot, ascending by journal version.
///
/// Recovery needs the whole chain, not just the top: a capsule can hold two
/// consecutive fallback transitions (say `accepted` at v3 in one slot and
/// `completed_after_cancel` at v4 in the other) while the database is still at
/// v2. Importing only the highest would ask the database for an illegal
/// `dispatching -> completed_after_cancel` edge and strand the terminal
/// outcome, so the caller replays the versions in order instead.
pub fn authentic_slots(
    first: Result<CapsuleSlot, ExternalJournalError>,
    second: Result<CapsuleSlot, ExternalJournalError>,
) -> Result<Vec<CapsuleSlot>, QuarantineReason> {
    match (first, second) {
        (Err(_), Err(_)) => Err(QuarantineReason::NoAuthenticSlot),
        (Ok(slot), Err(_)) | (Err(_), Ok(slot)) => Ok(vec![slot]),
        (Ok(a), Ok(b)) => match a.journal_version.cmp(&b.journal_version) {
            std::cmp::Ordering::Greater => Ok(vec![b, a]),
            std::cmp::Ordering::Less => Ok(vec![a, b]),
            std::cmp::Ordering::Equal => {
                // Two authentic slots at the same version must be byte-identical
                // facts. `key_version` is part of that: the same version signed
                // under two different keys is a rotation or substitution race,
                // not a benign duplicate, so it quarantines like any other
                // equal-version disagreement.
                let identical = a.state == b.state
                    && a.key_version == b.key_version
                    && a.projection == b.projection
                    && a.updated_at_wall_ms == b.updated_at_wall_ms;
                if identical {
                    Ok(vec![a])
                } else {
                    Err(QuarantineReason::EqualVersionDisagreement)
                }
            }
        },
    }
}

/// Deterministic pre-write sentinel for one slot.
///
/// Creation writes this into both slots and reads it back, which proves the
/// full 65,536-byte extent is physically backed before any external handoff.
pub fn sentinel_slot_bytes(capsule_uuid: Uuid, slot_index: u8) -> Vec<u8> {
    let mut seed = Sha256::new();
    seed.update(DOMAIN_SENTINEL);
    seed.update(capsule_uuid.as_bytes());
    seed.update([slot_index]);
    let block: [u8; 32] = seed.finalize().into();
    let mut bytes = Vec::with_capacity(SLOT_BYTES);
    while bytes.len() < SLOT_BYTES {
        bytes.extend_from_slice(&block);
    }
    bytes.truncate(SLOT_BYTES);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_journal::keys::SpoolKeyRing;
    use crate::external_journal::projection::{Digest, OperationBody, SanitizedProjection};

    fn ring() -> SpoolKeyRing {
        SpoolKeyRing::for_test(&[(1, [7u8; 32]), (2, [9u8; 32])], 2).unwrap()
    }

    fn projection_bytes() -> Vec<u8> {
        SanitizedProjection::new(OperationBody::ComputerInput {
            target_digest: Digest::of(b"target"),
            action_count: 2,
        })
        .encode()
        .unwrap()
    }

    fn slot(version: u64, state: ExternalJournalState, index: u8) -> CapsuleSlot {
        CapsuleSlot {
            slot_index: index,
            operation_id: Uuid::from_u128(42),
            journal_version: version,
            key_version: 2,
            state,
            updated_at_wall_ms: 1_000,
            projection: projection_bytes(),
        }
    }

    #[test]
    fn external_journal_recovery_capsule_layout_is_exact() {
        assert_eq!(CAPSULE_BYTES, 65_536);
        assert_eq!(SLOT_BYTES, 32_768);
        assert_eq!(SLOT_BYTES * 2, CAPSULE_BYTES);
        assert_eq!(SLOT_DIGEST_OFFSET, 32_704);
        assert_eq!(SLOT_TAG_OFFSET, 32_736);
        assert_eq!(SLOT_BODY_BYTES, 32_640);
        const { assert!(SLOT_BODY_BYTES >= 24 * 1024) };
        assert_eq!(CAPSULE_MAGIC.len(), 16);
    }

    #[test]
    fn external_journal_recovery_capsule_slot_roundtrip() {
        let keys = ring();
        let original = slot(7, ExternalJournalState::Dispatching, 1);
        let encoded = original.encode(&keys).unwrap();
        assert_eq!(encoded.len(), SLOT_BYTES);
        let decoded = CapsuleSlot::decode(&encoded, original.operation_id, &keys).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn external_journal_spool_security_rejects_tampering_and_wrong_owner() {
        let keys = ring();
        let original = slot(7, ExternalJournalState::Accepted, 0);
        let encoded = original.encode(&keys).unwrap();

        // A single flipped projection byte breaks the digest and the HMAC.
        let mut tampered = encoded.clone();
        tampered[SLOT_HEADER_BYTES] ^= 0x01;
        assert!(CapsuleSlot::decode(&tampered, original.operation_id, &keys).is_err());

        // Rewriting the state code without the key breaks authenticity, so a
        // checksum-only design would have accepted this.
        let mut restated = encoded.clone();
        restated[60..64]
            .copy_from_slice(&state_code(ExternalJournalState::Succeeded).to_le_bytes());
        assert!(CapsuleSlot::decode(&restated, original.operation_id, &keys).is_err());

        // A well-formed slot belonging to a different operation is rejected.
        assert!(CapsuleSlot::decode(&encoded, Uuid::from_u128(43), &keys).is_err());

        // Nonzero padding is rejected as an out-of-band channel.
        let mut padded = encoded.clone();
        padded[SLOT_DIGEST_OFFSET - 1] = 0xff;
        assert!(CapsuleSlot::decode(&padded, original.operation_id, &keys).is_err());
    }

    #[test]
    fn external_journal_spool_security_key_version_rotation_and_retention() {
        let keys = ring();
        let old = CapsuleSlot {
            key_version: 1,
            ..slot(3, ExternalJournalState::Prepared, 0)
        };
        let encoded = old.encode(&keys).unwrap();
        // While version 1 is retained the record still imports.
        assert!(CapsuleSlot::decode(&encoded, old.operation_id, &keys).is_ok());

        // Dropping a still-referenced version makes the record unauthenticated
        // rather than silently trusted, so the caller must quarantine it.
        let rotated = SpoolKeyRing::for_test(&[(2, [9u8; 32])], 2).unwrap();
        let error = CapsuleSlot::decode(&encoded, old.operation_id, &rotated).unwrap_err();
        assert!(
            matches!(error, ExternalJournalError::UnknownKeyVersion(1)),
            "unexpected error: {error:?}"
        );

        // A different key of the same version fails authentication.
        let wrong = SpoolKeyRing::for_test(&[(1, [8u8; 32])], 1).unwrap();
        assert!(CapsuleSlot::decode(&encoded, old.operation_id, &wrong).is_err());
    }

    #[test]
    fn external_journal_recovery_capsule_slot_disagreement_rules() {
        let low = slot(3, ExternalJournalState::Dispatching, 0);
        let high = slot(4, ExternalJournalState::Accepted, 1);

        match choose_slot(Ok(low.clone()), Ok(high.clone())) {
            SlotChoice::Authentic(chosen) => assert_eq!(chosen.journal_version, 4),
            other => panic!("expected the higher version, got {other:?}"),
        }
        match choose_slot(
            Ok(high.clone()),
            Err(ExternalJournalError::Capsule("x".into())),
        ) {
            SlotChoice::Authentic(chosen) => assert_eq!(chosen.journal_version, 4),
            other => panic!("expected the surviving slot, got {other:?}"),
        }
        assert_eq!(
            choose_slot(
                Err(ExternalJournalError::Capsule("a".into())),
                Err(ExternalJournalError::Capsule("b".into()))
            ),
            SlotChoice::Quarantine(QuarantineReason::NoAuthenticSlot)
        );

        // Equal version, different content: quarantine and block.
        let conflicting = CapsuleSlot {
            slot_index: 1,
            state: ExternalJournalState::Rejected,
            ..low.clone()
        };
        assert_eq!(
            choose_slot(Ok(low.clone()), Ok(conflicting)),
            SlotChoice::Quarantine(QuarantineReason::EqualVersionDisagreement)
        );

        // Equal version, same state, but signed under a different key version:
        // a rotation or substitution race, not a benign duplicate.
        let rekeyed = CapsuleSlot {
            slot_index: 1,
            key_version: 1,
            ..low.clone()
        };
        assert_eq!(
            choose_slot(Ok(low.clone()), Ok(rekeyed)),
            SlotChoice::Quarantine(QuarantineReason::EqualVersionDisagreement)
        );

        // Equal version, identical content: benign, keep it.
        let twin = CapsuleSlot {
            slot_index: 1,
            ..low.clone()
        };
        assert!(matches!(
            choose_slot(Ok(low.clone()), Ok(twin)),
            SlotChoice::Authentic(_)
        ));

        // The full chain is returned ascending so recovery can replay it.
        let chain = authentic_slots(Ok(high.clone()), Ok(low.clone())).unwrap();
        assert_eq!(
            chain
                .iter()
                .map(|slot| slot.journal_version)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );
    }

    #[test]
    fn external_journal_recovery_capsule_sentinel_covers_the_whole_slot() {
        let a = sentinel_slot_bytes(Uuid::from_u128(1), 0);
        let b = sentinel_slot_bytes(Uuid::from_u128(1), 1);
        assert_eq!(a.len(), SLOT_BYTES);
        assert_eq!(b.len(), SLOT_BYTES);
        assert_ne!(a, b, "slots must not share a sentinel pattern");
        assert!(
            a.iter().any(|byte| *byte != 0),
            "sentinel must not be zeros"
        );
        assert_eq!(a, sentinel_slot_bytes(Uuid::from_u128(1), 0));
    }
}
