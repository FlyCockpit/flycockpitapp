//! Tests for the computer-use audit chain.

use super::*;

fn test_key() -> Vec<u8> {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = i as u8;
    }
    k.to_vec()
}

fn test_key_v2() -> Vec<u8> {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i + 100) as u8;
    }
    k.to_vec()
}

fn nonzero_uuid(n: u8) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[0] = n;
    id[15] = n;
    id
}

fn nonzero_digest(n: u8) -> [u8; 32] {
    let mut d = [0u8; 32];
    for b in d.iter_mut() {
        *b = n;
    }
    d
}

fn base_entry() -> ComputerAuditEntryV1 {
    ComputerAuditEntryV1 {
        event_kind: AuditEventKind::DelegationStarted,
        present_bits: present_bits::SESSION_ID
            | present_bits::DELEGATION_ID
            | present_bits::ASK_YOLO,
        sequence: 1,
        previous_mac: [0u8; 32],
        session_id: nonzero_uuid(1),
        delegation_id: nonzero_uuid(2),
        action_id: [0u8; 16],
        operation_id: [0u8; 16],
        proposal_id: [0u8; 16],
        disposition: 0,
        scope: 0,
        canonical_project_digest: [0u8; 32],
        provider_digest: [0u8; 32],
        model_digest: [0u8; 32],
        physical_target_digest: [0u8; 32],
        focus_digest: [0u8; 32],
        observation_digest: [0u8; 32],
        host_lease_digest: [0u8; 32],
        record_digest: [0u8; 32],
        ask_yolo: AskYolo::Ask as u8,
        action_class: 0,
        journal_state: 0,
        verification_state: 0,
        journal_version: 0,
        monotonic_nanos: 1000,
        wall_unix_millis: 2000,
        error_code: 0,
        rule_kind_bits: 0,
        key_version: 1,
    }
}

fn make_chain_entry(
    sequence: u64,
    previous_mac: [u8; 32],
    key_version: u32,
    key: &[u8],
) -> ChainEntry {
    let mut entry = base_entry();
    entry.sequence = sequence;
    entry.previous_mac = previous_mac;
    entry.key_version = key_version;
    let encoded = entry.encode();
    let mac = entry_mac(key, &encoded);
    ChainEntry {
        sequence,
        entry_bytes: encoded,
        mac,
    }
}

// -- computer_audit_event_matrix --

#[test]
fn computer_audit_event_matrix_entry_len_is_424() {
    let entry = base_entry();
    let encoded = entry.encode();
    assert_eq!(encoded.len(), ENTRY_LEN);
    assert_eq!(&encoded[0..4], b"FCAE");
    assert_eq!(encoded[4], 1);
    assert_eq!(encoded[5], AuditEventKind::DelegationStarted.as_byte());
}

#[test]
fn computer_audit_event_matrix_round_trip() {
    let entry = base_entry();
    let encoded = entry.encode();
    let decoded = ComputerAuditEntryV1::decode(&encoded).unwrap();
    assert_eq!(decoded.event_kind, entry.event_kind);
    assert_eq!(decoded.present_bits, entry.present_bits);
    assert_eq!(decoded.sequence, entry.sequence);
    assert_eq!(decoded.session_id, entry.session_id);
    assert_eq!(decoded.delegation_id, entry.delegation_id);
    assert_eq!(decoded.ask_yolo, entry.ask_yolo);
    assert_eq!(decoded.key_version, entry.key_version);
}

#[test]
fn computer_audit_event_matrix_all_29_event_kinds() {
    for code in 1u8..=29 {
        let kind = AuditEventKind::from_byte(code).unwrap();
        assert_eq!(kind.as_byte(), code);
    }
    assert!(AuditEventKind::from_byte(0).is_none());
    assert!(AuditEventKind::from_byte(30).is_none());
}

#[test]
fn computer_audit_event_matrix_present_bits_reserved_rejected() {
    let mut entry = base_entry();
    entry.present_bits = present_bits::ALL_VALID | (1u32 << 22);
    let encoded = entry.encode();
    let err = ComputerAuditEntryV1::decode(&encoded).unwrap_err();
    assert!(matches!(err, AuditDecodeError::ReservedPresentBits(_)));
}

#[test]
fn computer_audit_event_matrix_present_but_zero_rejected() {
    let mut entry = base_entry();
    entry.session_id = [0u8; 16];
    let err = entry.validate_presence().unwrap_err();
    assert!(matches!(err, AuditDecodeError::PresentButZero(s) if s == "session_id"));
}

#[test]
fn computer_audit_event_matrix_absent_but_nonzero_rejected() {
    let mut entry = base_entry();
    entry.action_id = nonzero_uuid(5);
    let err = entry.validate_presence().unwrap_err();
    assert!(matches!(err, AuditDecodeError::AbsentButNonzero(s) if s == "action_id"));
}

#[test]
fn computer_audit_event_matrix_action_class_consequential() {
    assert!(!ActionClass::PointerMove.is_consequential());
    assert!(ActionClass::PointerButton.is_consequential());
    assert!(ActionClass::PointerDrag.is_consequential());
    assert!(ActionClass::TextEntry.is_consequential());
    assert!(ActionClass::KeyInput.is_consequential());
    assert!(ActionClass::Scroll.is_consequential());
    assert!(!ActionClass::Wait.is_consequential());
}

#[test]
fn computer_audit_event_matrix_action_class_from_byte() {
    for code in 1u8..=7 {
        assert!(ActionClass::from_byte(code).is_some());
    }
    assert!(ActionClass::from_byte(0).is_none());
    assert!(ActionClass::from_byte(8).is_none());
}

#[test]
fn computer_audit_event_matrix_hmac_vector() {
    let entry = base_entry();
    let encoded = entry.encode();
    let key = test_key();
    let mac = entry_mac(&key, &encoded);
    assert_eq!(mac.len(), 32);
    let mac2 = entry_mac(&key, &encoded);
    assert_eq!(mac, mac2);
    let mac3 = entry_mac(&test_key_v2(), &encoded);
    assert_ne!(mac, mac3);
}

#[test]
fn computer_audit_event_matrix_key_version_always_present() {
    let mut entry = base_entry();
    entry.key_version = 0;
    let err = entry.validate_presence().unwrap_err();
    assert!(matches!(err, AuditDecodeError::PresentButZero(s) if s == "key_version"));
}

// -- domain digests --

#[test]
fn computer_audit_domain_digest_deterministic() {
    let d1 = domain_digest(domains::PROJECT, b"my-project");
    let d2 = domain_digest(domains::PROJECT, b"my-project");
    assert_eq!(d1, d2);
    let d3 = domain_digest(domains::PROVIDER, b"my-project");
    assert_ne!(d1, d3);
    let d4 = domain_digest(domains::PROJECT, b"other-project");
    assert_ne!(d1, d4);
}

#[test]
fn computer_audit_domain_digest_all_closed_domains() {
    let value = b"test-value";
    let _ = domain_digest(domains::PROJECT, value);
    let _ = domain_digest(domains::PROVIDER, value);
    let _ = domain_digest(domains::MODEL, value);
    let _ = domain_digest(domains::PHYSICAL_TARGET_GENERATION, value);
    let _ = domain_digest(domains::FOCUS_GENERATION, value);
    let _ = domain_digest(domains::OBSERVATION_GENERATION, value);
    let _ = domain_digest(domains::HOST_LEASE_GENERATION, value);
    let _ = domain_digest(domains::AUDIT_RECORD, value);
}

// -- record digests --

#[test]
fn computer_audit_record_digest_key_checkpoint_53_bytes() {
    let mac = nonzero_digest(1);
    let d = key_checkpoint_record_digest(1, 2, 10, &mac).unwrap();
    assert_ne!(d, [0u8; 32]);
}

#[test]
fn computer_audit_record_digest_key_checkpoint_zero_version_rejected() {
    let mac = nonzero_digest(1);
    assert!(key_checkpoint_record_digest(0, 2, 10, &mac).is_err());
    assert!(key_checkpoint_record_digest(1, 0, 10, &mac).is_err());
}

#[test]
fn computer_audit_record_digest_key_checkpoint_equal_versions_rejected() {
    let mac = nonzero_digest(1);
    assert!(key_checkpoint_record_digest(2, 2, 10, &mac).is_err());
}

#[test]
fn computer_audit_record_digest_prune_checkpoint_189_bytes() {
    let op_id = Uuid::nil();
    let export_id = Uuid::nil();
    let first_mac = nonzero_digest(1);
    let last_mac = nonzero_digest(2);
    let export_digest = nonzero_digest(3);
    let prior = nonzero_digest(4);
    let d = prune_checkpoint_record_digest(
        &op_id,
        1,
        10,
        &first_mac,
        &last_mac,
        10,
        &export_id,
        &export_digest,
        &prior,
    )
    .unwrap();
    assert_ne!(d, [0u8; 32]);
}

#[test]
fn computer_audit_record_digest_prune_checkpoint_range_invalid() {
    let op_id = Uuid::nil();
    let first_mac = nonzero_digest(1);
    let last_mac = nonzero_digest(2);
    let export_digest = nonzero_digest(3);
    let prior = nonzero_digest(4);
    assert!(
        prune_checkpoint_record_digest(
            &op_id,
            10,
            1,
            &first_mac,
            &last_mac,
            0,
            &Uuid::nil(),
            &export_digest,
            &prior,
        )
        .is_err()
    );
}

#[test]
fn computer_audit_record_digest_prune_checkpoint_count_mismatch() {
    let op_id = Uuid::nil();
    let first_mac = nonzero_digest(1);
    let last_mac = nonzero_digest(2);
    let export_digest = nonzero_digest(3);
    let prior = nonzero_digest(4);
    assert!(
        prune_checkpoint_record_digest(
            &op_id,
            1,
            10,
            &first_mac,
            &last_mac,
            9,
            &Uuid::nil(),
            &export_digest,
            &prior,
        )
        .is_err()
    );
}

#[test]
fn computer_audit_record_digest_export_93_bytes() {
    let export_digest = nonzero_digest(5);
    let d = export_record_digest(&Uuid::nil(), &Uuid::nil(), 1, 10, 10, &export_digest).unwrap();
    assert_ne!(d, [0u8; 32]);
}

#[test]
fn computer_audit_record_digest_export_range_invalid() {
    let export_digest = nonzero_digest(5);
    assert!(export_record_digest(&Uuid::nil(), &Uuid::nil(), 10, 1, 0, &export_digest).is_err());
}

#[test]
fn computer_audit_record_digest_session_deleted_38_bytes() {
    let d =
        session_deleted_record_digest(&Uuid::nil(), 1, 1000, SessionDeletedReason::OwnerRequested)
            .unwrap();
    assert_ne!(d, [0u8; 32]);
}

#[test]
fn computer_audit_record_digest_session_deleted_zero_generation_rejected() {
    assert!(
        session_deleted_record_digest(&Uuid::nil(), 0, 1000, SessionDeletedReason::OwnerRequested)
            .is_err()
    );
}

// -- sealed head --

#[test]
fn computer_audit_sealed_head_confirmed_only_110_bytes() {
    let head =
        ComputerAuditSealedHeadV1::confirmed_only(1, 5, nonzero_digest(1), 1, nonzero_uuid(1));
    let encoded = head.encode();
    assert_eq!(encoded.len(), SEALED_HEAD_CONFIRMED_ONLY_LEN);
    assert_eq!(&encoded[0..4], SEALED_HEAD_MAGIC);
    assert_eq!(encoded[4], SEALED_HEAD_VERSION);
    assert_eq!(encoded[5], 0);
}

#[test]
fn computer_audit_sealed_head_max_626_bytes() {
    let head = ComputerAuditSealedHeadV1::with_pending(
        1,
        5,
        nonzero_digest(1),
        1,
        nonzero_uuid(1),
        [0u8; ENTRY_LEN],
        nonzero_digest(2),
        5,
        nonzero_digest(1),
        1,
        nonzero_uuid(2),
    );
    let encoded = head.encode();
    assert_eq!(encoded.len(), SEALED_HEAD_MAX_LEN);
    assert_eq!(encoded[5], 1);
}

#[test]
fn computer_audit_sealed_head_ceiling_margin_398() {
    assert_eq!(
        SEALED_HEAD_CEILING - SEALED_HEAD_MAX_LEN,
        SEALED_HEAD_CEILING_MARGIN
    );
    assert_eq!(SEALED_HEAD_CEILING_MARGIN, 398);
}

#[test]
fn computer_audit_sealed_head_round_trip_confirmed_only() {
    let head =
        ComputerAuditSealedHeadV1::confirmed_only(3, 10, nonzero_digest(7), 2, nonzero_uuid(9));
    let encoded = head.encode();
    let decoded = ComputerAuditSealedHeadV1::decode(&encoded).unwrap();
    assert!(!decoded.pending_present);
    assert_eq!(decoded.sealed_generation, 3);
    assert_eq!(decoded.confirmed_sequence, 10);
    assert_eq!(decoded.confirmed_mac, nonzero_digest(7));
    assert_eq!(decoded.confirmed_key_version, 2);
    assert_eq!(decoded.database_instance_id, nonzero_uuid(9));
}

#[test]
fn computer_audit_sealed_head_round_trip_with_pending() {
    let head = ComputerAuditSealedHeadV1::with_pending(
        3,
        10,
        nonzero_digest(7),
        2,
        nonzero_uuid(9),
        [0u8; ENTRY_LEN],
        nonzero_digest(8),
        10,
        nonzero_digest(7),
        2,
        nonzero_uuid(10),
    );
    let encoded = head.encode();
    let decoded = ComputerAuditSealedHeadV1::decode(&encoded).unwrap();
    assert!(decoded.pending_present);
    assert_eq!(decoded.sealed_generation, 3);
    assert_eq!(decoded.confirmed_sequence, 10);
    assert_eq!(decoded.pending_mac, nonzero_digest(8));
    assert_eq!(decoded.pending_previous_sequence, 10);
}

#[test]
fn computer_audit_sealed_head_bad_magic_rejected() {
    let head = ComputerAuditSealedHeadV1::confirmed_only(1, 0, [0u8; 32], 1, [0u8; 16]);
    let mut encoded = head.encode();
    encoded[0] = b'X';
    assert!(ComputerAuditSealedHeadV1::decode(&encoded).is_err());
}

#[test]
fn computer_audit_sealed_head_payload_digest_mismatch_rejected() {
    let head = ComputerAuditSealedHeadV1::confirmed_only(1, 0, [0u8; 32], 1, [0u8; 16]);
    let mut encoded = head.encode();
    let last = encoded.len() - 1;
    encoded[last] ^= 0x01;
    assert!(ComputerAuditSealedHeadV1::decode(&encoded).is_err());
}

#[test]
fn computer_audit_sealed_head_reserved_nonzero_rejected() {
    let head = ComputerAuditSealedHeadV1::confirmed_only(1, 0, [0u8; 32], 1, [0u8; 16]);
    let mut encoded = head.encode();
    encoded[6] = 0x01;
    let err = ComputerAuditSealedHeadV1::decode(&encoded).unwrap_err();
    assert!(matches!(err, SealedHeadDecodeError::ReservedNonzero(_)));
}

// -- verification statuses --

#[test]
fn computer_audit_verify_status_exit_codes() {
    assert_eq!(AuditVerifyStatus::Verified.exit_code(), 0);
    assert_eq!(AuditVerifyStatus::Corrupt.exit_code(), 2);
    assert_eq!(AuditVerifyStatus::PendingRecovery.exit_code(), 3);
    assert_eq!(AuditVerifyStatus::DatabaseBehindSealedHead.exit_code(), 4);
    assert_eq!(AuditVerifyStatus::SealedHeadBehindDatabase.exit_code(), 5);
    assert_eq!(AuditVerifyStatus::UnavailableSecureStore.exit_code(), 6);
    assert_eq!(AuditVerifyStatus::UnavailableDatabase.exit_code(), 7);
    assert_eq!(AuditVerifyStatus::UnavailableKey.exit_code(), 8);
}

#[test]
fn computer_audit_verify_status_strings() {
    assert_eq!(AuditVerifyStatus::Verified.as_str(), "verified");
    assert_eq!(AuditVerifyStatus::Corrupt.as_str(), "corrupt");
    assert_eq!(
        AuditVerifyStatus::PendingRecovery.as_str(),
        "pending_recovery"
    );
    assert_eq!(
        AuditVerifyStatus::DatabaseBehindSealedHead.as_str(),
        "database_behind_sealed_head"
    );
    assert_eq!(
        AuditVerifyStatus::SealedHeadBehindDatabase.as_str(),
        "sealed_head_behind_database"
    );
    assert_eq!(
        AuditVerifyStatus::UnavailableSecureStore.as_str(),
        "unavailable_secure_store"
    );
    assert_eq!(
        AuditVerifyStatus::UnavailableDatabase.as_str(),
        "unavailable_database"
    );
    assert_eq!(
        AuditVerifyStatus::UnavailableKey.as_str(),
        "unavailable_key"
    );
}

#[test]
fn computer_audit_verify_status_precedence() {
    assert!(
        AuditVerifyStatus::Corrupt.precedence()
            < AuditVerifyStatus::UnavailableSecureStore.precedence()
    );
    assert!(
        AuditVerifyStatus::UnavailableSecureStore.precedence()
            < AuditVerifyStatus::UnavailableDatabase.precedence()
    );
    assert!(
        AuditVerifyStatus::UnavailableDatabase.precedence()
            < AuditVerifyStatus::UnavailableKey.precedence()
    );
    assert!(
        AuditVerifyStatus::UnavailableKey.precedence()
            < AuditVerifyStatus::PendingRecovery.precedence()
    );
    assert!(
        AuditVerifyStatus::PendingRecovery.precedence()
            < AuditVerifyStatus::DatabaseBehindSealedHead.precedence()
    );
    assert!(
        AuditVerifyStatus::DatabaseBehindSealedHead.precedence()
            < AuditVerifyStatus::SealedHeadBehindDatabase.precedence()
    );
    assert!(
        AuditVerifyStatus::SealedHeadBehindDatabase.precedence()
            < AuditVerifyStatus::Verified.precedence()
    );
}

#[test]
fn computer_audit_verify_status_higher_precedence() {
    assert_eq!(
        AuditVerifyStatus::higher_precedence(
            AuditVerifyStatus::Corrupt,
            AuditVerifyStatus::Verified
        ),
        AuditVerifyStatus::Corrupt
    );
    assert_eq!(
        AuditVerifyStatus::higher_precedence(
            AuditVerifyStatus::Verified,
            AuditVerifyStatus::Corrupt
        ),
        AuditVerifyStatus::Corrupt
    );
    assert_eq!(
        AuditVerifyStatus::higher_precedence(
            AuditVerifyStatus::PendingRecovery,
            AuditVerifyStatus::Verified
        ),
        AuditVerifyStatus::PendingRecovery
    );
}

// -- chain verification --

#[test]
fn computer_audit_verify_verified_empty_chain() {
    let head = ComputerAuditSealedHeadV1::confirmed_only(1, 0, [0u8; 32], 1, nonzero_uuid(1));
    let entries: Vec<ChainEntry> = vec![];
    let key = test_key();
    let result = verify_chain(Some(&head), Some(&entries), |v| {
        if v == 1 { Some(key.clone()) } else { None }
    });
    assert_eq!(result.status, AuditVerifyStatus::Verified);
}

#[test]
fn computer_audit_verify_unavailable_secure_store() {
    let entries: Vec<ChainEntry> = vec![];
    let result = verify_chain(None, Some(&entries), |_| None);
    assert_eq!(result.status, AuditVerifyStatus::UnavailableSecureStore);
}

#[test]
fn computer_audit_verify_unavailable_database() {
    let head = ComputerAuditSealedHeadV1::confirmed_only(1, 0, [0u8; 32], 1, nonzero_uuid(1));
    let result = verify_chain(Some(&head), None, |_| None);
    assert_eq!(result.status, AuditVerifyStatus::UnavailableDatabase);
}

#[test]
fn computer_audit_verify_unavailable_key() {
    let key = test_key();
    let entry1 = make_chain_entry(1, [0u8; 32], 1, &key);
    let entries = vec![entry1];
    let head = ComputerAuditSealedHeadV1::confirmed_only(1, 1, entries[0].mac, 1, nonzero_uuid(1));
    let result = verify_chain(Some(&head), Some(&entries), |v| {
        if v == 99 { Some(key.clone()) } else { None }
    });
    assert_eq!(result.status, AuditVerifyStatus::UnavailableKey);
}

#[test]
fn computer_audit_verify_corrupt_bad_mac() {
    let key = test_key();
    let mut entry1 = make_chain_entry(1, [0u8; 32], 1, &key);
    entry1.mac[0] ^= 0x01;
    let entries = vec![entry1];
    let head = ComputerAuditSealedHeadV1::confirmed_only(1, 1, entries[0].mac, 1, nonzero_uuid(1));
    let result = verify_chain(Some(&head), Some(&entries), |v| {
        if v == 1 { Some(key.clone()) } else { None }
    });
    assert_eq!(result.status, AuditVerifyStatus::Corrupt);
}

#[test]
fn computer_audit_verify_corrupt_bad_link() {
    let key = test_key();
    let entry1 = make_chain_entry(1, [0u8; 32], 1, &key);
    let mut entry2 = base_entry();
    entry2.sequence = 2;
    entry2.previous_mac = nonzero_digest(99);
    entry2.key_version = 1;
    let enc2 = entry2.encode();
    let mac2 = entry_mac(&key, &enc2);
    let entries = vec![
        entry1.clone(),
        ChainEntry {
            sequence: 2,
            entry_bytes: enc2,
            mac: mac2,
        },
    ];
    let head = ComputerAuditSealedHeadV1::confirmed_only(1, 2, mac2, 1, nonzero_uuid(1));
    let result = verify_chain(Some(&head), Some(&entries), |v| {
        if v == 1 { Some(key.clone()) } else { None }
    });
    assert_eq!(result.status, AuditVerifyStatus::Corrupt);
}

#[test]
fn computer_audit_verify_database_behind_sealed_head() {
    let key = test_key();
    let entry1 = make_chain_entry(1, [0u8; 32], 1, &key);
    let entries = vec![entry1.clone()];
    let head =
        ComputerAuditSealedHeadV1::confirmed_only(1, 5, nonzero_digest(99), 1, nonzero_uuid(1));
    let result = verify_chain(Some(&head), Some(&entries), |v| {
        if v == 1 { Some(key.clone()) } else { None }
    });
    assert_eq!(result.status, AuditVerifyStatus::DatabaseBehindSealedHead);
}

#[test]
fn computer_audit_verify_sealed_head_behind_database() {
    let key = test_key();
    let entry1 = make_chain_entry(1, [0u8; 32], 1, &key);
    let entry2 = make_chain_entry(2, entry1.mac, 1, &key);
    let entries = vec![entry1.clone(), entry2.clone()];
    let head = ComputerAuditSealedHeadV1::confirmed_only(1, 1, entry1.mac, 1, nonzero_uuid(1));
    let result = verify_chain(Some(&head), Some(&entries), |v| {
        if v == 1 { Some(key.clone()) } else { None }
    });
    assert_eq!(result.status, AuditVerifyStatus::SealedHeadBehindDatabase);
}

#[test]
fn computer_audit_verify_pending_recovery_absent_from_db() {
    let key = test_key();
    let entry1 = make_chain_entry(1, [0u8; 32], 1, &key);
    let entries = vec![entry1.clone()];
    let mut pending = base_entry();
    pending.sequence = 2;
    pending.previous_mac = entry1.mac;
    pending.key_version = 1;
    let pending_encoded = pending.encode();
    let pending_mac = entry_mac(&key, &pending_encoded);
    let head = ComputerAuditSealedHeadV1::with_pending(
        1,
        1,
        entry1.mac,
        1,
        nonzero_uuid(1),
        pending_encoded,
        pending_mac,
        1,
        entry1.mac,
        1,
        nonzero_uuid(1),
    );
    let result = verify_chain(Some(&head), Some(&entries), |v| {
        if v == 1 { Some(key.clone()) } else { None }
    });
    assert_eq!(result.status, AuditVerifyStatus::PendingRecovery);
}

#[test]
fn computer_audit_verify_pending_recovery_present_byte_identical() {
    let key = test_key();
    let entry1 = make_chain_entry(1, [0u8; 32], 1, &key);
    let mut pending = base_entry();
    pending.sequence = 2;
    pending.previous_mac = entry1.mac;
    pending.key_version = 1;
    let pending_encoded = pending.encode();
    let pending_mac = entry_mac(&key, &pending_encoded);
    let entries = vec![
        entry1.clone(),
        ChainEntry {
            sequence: 2,
            entry_bytes: pending_encoded,
            mac: pending_mac,
        },
    ];
    let head = ComputerAuditSealedHeadV1::with_pending(
        1,
        1,
        entry1.mac,
        1,
        nonzero_uuid(1),
        pending_encoded,
        pending_mac,
        1,
        entry1.mac,
        1,
        nonzero_uuid(1),
    );
    let result = verify_chain(Some(&head), Some(&entries), |v| {
        if v == 1 { Some(key.clone()) } else { None }
    });
    assert_eq!(result.status, AuditVerifyStatus::PendingRecovery);
}

#[test]
fn computer_audit_verify_corrupt_pending_different_bytes() {
    let key = test_key();
    let entry1 = make_chain_entry(1, [0u8; 32], 1, &key);
    let mut pending = base_entry();
    pending.sequence = 2;
    pending.previous_mac = entry1.mac;
    pending.key_version = 1;
    let pending_encoded = pending.encode();
    let pending_mac = entry_mac(&key, &pending_encoded);
    let mut different_entry = base_entry();
    different_entry.sequence = 2;
    different_entry.previous_mac = entry1.mac;
    different_entry.key_version = 1;
    different_entry.monotonic_nanos = 9999;
    let different_encoded = different_entry.encode();
    let different_mac = entry_mac(&key, &different_encoded);
    let entries = vec![
        entry1.clone(),
        ChainEntry {
            sequence: 2,
            entry_bytes: different_encoded,
            mac: different_mac,
        },
    ];
    let head = ComputerAuditSealedHeadV1::with_pending(
        1,
        1,
        entry1.mac,
        1,
        nonzero_uuid(1),
        pending_encoded,
        pending_mac,
        1,
        entry1.mac,
        1,
        nonzero_uuid(1),
    );
    let result = verify_chain(Some(&head), Some(&entries), |v| {
        if v == 1 { Some(key.clone()) } else { None }
    });
    assert_eq!(result.status, AuditVerifyStatus::Corrupt);
}

// -- tamper tests --

#[test]
fn computer_audit_tamper_mutation_detected() {
    let key = test_key();
    let entry1 = make_chain_entry(1, [0u8; 32], 1, &key);
    let mut tampered = entry1.clone();
    tampered.entry_bytes[100] ^= 0x01;
    let entries = vec![tampered];
    let head = ComputerAuditSealedHeadV1::confirmed_only(1, 1, entry1.mac, 1, nonzero_uuid(1));
    let result = verify_chain(Some(&head), Some(&entries), |v| {
        if v == 1 { Some(key.clone()) } else { None }
    });
    assert_eq!(result.status, AuditVerifyStatus::Corrupt);
}

#[test]
fn computer_audit_tamper_reorder_detected() {
    let key = test_key();
    let entry1 = make_chain_entry(1, [0u8; 32], 1, &key);
    let entry2 = make_chain_entry(2, entry1.mac, 1, &key);
    let entries = vec![entry2.clone(), entry1.clone()];
    let head = ComputerAuditSealedHeadV1::confirmed_only(1, 2, entry2.mac, 1, nonzero_uuid(1));
    let result = verify_chain(Some(&head), Some(&entries), |v| {
        if v == 1 { Some(key.clone()) } else { None }
    });
    assert_eq!(result.status, AuditVerifyStatus::Corrupt);
}

#[test]
fn computer_audit_tamper_insertion_detected() {
    let key = test_key();
    let entry1 = make_chain_entry(1, [0u8; 32], 1, &key);
    let entry2 = make_chain_entry(2, entry1.mac, 1, &key);
    let fake = make_chain_entry(2, entry1.mac, 1, &key);
    let entries = vec![entry1.clone(), fake, entry2.clone()];
    let head = ComputerAuditSealedHeadV1::confirmed_only(1, 3, entry2.mac, 1, nonzero_uuid(1));
    let result = verify_chain(Some(&head), Some(&entries), |v| {
        if v == 1 { Some(key.clone()) } else { None }
    });
    assert_eq!(result.status, AuditVerifyStatus::Corrupt);
}

#[test]
fn computer_audit_tamper_tail_deletion_detected() {
    let key = test_key();
    let entry1 = make_chain_entry(1, [0u8; 32], 1, &key);
    let entry2 = make_chain_entry(2, entry1.mac, 1, &key);
    let entry3 = make_chain_entry(3, entry2.mac, 1, &key);
    let entries = vec![entry1.clone(), entry2.clone()];
    let head = ComputerAuditSealedHeadV1::confirmed_only(1, 3, entry3.mac, 1, nonzero_uuid(1));
    let result = verify_chain(Some(&head), Some(&entries), |v| {
        if v == 1 { Some(key.clone()) } else { None }
    });
    assert_eq!(result.status, AuditVerifyStatus::DatabaseBehindSealedHead);
}

#[test]
fn computer_audit_tamper_middle_deletion_detected() {
    let key = test_key();
    let entry1 = make_chain_entry(1, [0u8; 32], 1, &key);
    let entry2 = make_chain_entry(2, entry1.mac, 1, &key);
    let entry3 = make_chain_entry(3, entry2.mac, 1, &key);
    let entries = vec![entry1.clone(), entry3.clone()];
    let head = ComputerAuditSealedHeadV1::confirmed_only(1, 3, entry3.mac, 1, nonzero_uuid(1));
    let result = verify_chain(Some(&head), Some(&entries), |v| {
        if v == 1 { Some(key.clone()) } else { None }
    });
    assert_eq!(result.status, AuditVerifyStatus::Corrupt);
}

// -- pending entry reconstruction --

#[test]
fn computer_audit_pending_entry_reconstruction_confirmed_only_110() {
    let head =
        ComputerAuditSealedHeadV1::confirmed_only(1, 5, nonzero_digest(1), 1, nonzero_uuid(1));
    let encoded = head.encode();
    assert_eq!(encoded.len(), SEALED_HEAD_CONFIRMED_ONLY_LEN);
    let decoded = ComputerAuditSealedHeadV1::decode(&encoded).unwrap();
    assert!(!decoded.pending_present);
}

#[test]
fn computer_audit_pending_entry_reconstruction_max_626() {
    let head = ComputerAuditSealedHeadV1::with_pending(
        1,
        5,
        nonzero_digest(1),
        1,
        nonzero_uuid(1),
        [0u8; ENTRY_LEN],
        nonzero_digest(2),
        5,
        nonzero_digest(1),
        1,
        nonzero_uuid(2),
    );
    let encoded = head.encode();
    assert_eq!(encoded.len(), SEALED_HEAD_MAX_LEN);
    assert_eq!(
        SEALED_HEAD_CEILING - encoded.len(),
        SEALED_HEAD_CEILING_MARGIN
    );
}

#[test]
fn computer_audit_pending_entry_reconstruction_idempotent_promotion() {
    let key = test_key();
    let entry1 = make_chain_entry(1, [0u8; 32], 1, &key);
    let mut pending = base_entry();
    pending.sequence = 2;
    pending.previous_mac = entry1.mac;
    pending.key_version = 1;
    let pending_encoded = pending.encode();
    let pending_mac = entry_mac(&key, &pending_encoded);
    let entries = vec![
        entry1.clone(),
        ChainEntry {
            sequence: 2,
            entry_bytes: pending_encoded,
            mac: pending_mac,
        },
    ];
    let head = ComputerAuditSealedHeadV1::with_pending(
        1,
        1,
        entry1.mac,
        1,
        nonzero_uuid(1),
        pending_encoded,
        pending_mac,
        1,
        entry1.mac,
        1,
        nonzero_uuid(1),
    );
    let result = verify_chain(Some(&head), Some(&entries), |v| {
        if v == 1 { Some(key.clone()) } else { None }
    });
    assert_eq!(result.status, AuditVerifyStatus::PendingRecovery);
}

#[test]
fn computer_audit_pending_entry_reconstruction_fail_closed_mismatch() {
    let key = test_key();
    let entry1 = make_chain_entry(1, [0u8; 32], 1, &key);
    let mut pending = base_entry();
    pending.sequence = 2;
    pending.previous_mac = nonzero_digest(99);
    pending.key_version = 1;
    let pending_encoded = pending.encode();
    let pending_mac = entry_mac(&key, &pending_encoded);
    let head = ComputerAuditSealedHeadV1::with_pending(
        1,
        1,
        entry1.mac,
        1,
        nonzero_uuid(1),
        pending_encoded,
        pending_mac,
        1,
        entry1.mac,
        1,
        nonzero_uuid(1),
    );
    let entries = vec![entry1.clone()];
    let result = verify_chain(Some(&head), Some(&entries), |v| {
        if v == 1 { Some(key.clone()) } else { None }
    });
    assert_eq!(result.status, AuditVerifyStatus::Corrupt);
}

// -- key rotation --

#[test]
fn computer_audit_key_rotation_checkpoint_order() {
    let mac = nonzero_digest(1);
    let d = key_checkpoint_record_digest(1, 2, 10, &mac).unwrap();
    assert_ne!(d, [0u8; 32]);
    let d2 = key_checkpoint_record_digest(2, 1, 10, &mac).unwrap();
    assert_ne!(d, d2);
}

#[test]
fn computer_audit_key_rotation_missing_key_classified() {
    let key = test_key();
    let entry1 = make_chain_entry(1, [0u8; 32], 2, &key);
    let entries = vec![entry1.clone()];
    let head = ComputerAuditSealedHeadV1::confirmed_only(1, 1, entry1.mac, 2, nonzero_uuid(1));
    let result = verify_chain(Some(&head), Some(&entries), |v| {
        if v == 1 { Some(key.clone()) } else { None }
    });
    assert_eq!(result.status, AuditVerifyStatus::UnavailableKey);
}
