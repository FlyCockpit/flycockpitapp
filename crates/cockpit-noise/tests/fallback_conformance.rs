use cockpit_noise::{
    ACK_NONE, FallbackDirection, FallbackOuterRecordV1, fallback_ack_due, fallback_acknowledge,
    fallback_cache_outgoing, fallback_close, fallback_create, fallback_gap_retransmit,
    fallback_observe, fallback_retry_due,
};

fn outer(sequence: u64, fill: u8) -> Vec<u8> {
    FallbackOuterRecordV1 {
        route_generation: 1,
        direction: FallbackDirection::ClientToDaemon,
        record_sequence: sequence,
        peer_seen_through: ACK_NONE,
        ciphertext: vec![fill; 32],
    }
    .encode()
    .unwrap()
}

fn gap_filled_observation_wire(records: &[&[u8]]) -> Vec<u8> {
    let mut wire = vec![2, 1];
    wire.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 1]);
    wire.extend_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
    for record in records {
        wire.extend_from_slice(&u32::try_from(record.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(record);
    }
    wire
}

#[test]
fn remote_fallback_binding_conformance_uses_opaque_rust_windows() {
    let handle = fallback_create(0).unwrap();
    let delayed = outer(1, 2);
    let leading = outer(0, 1);
    assert_eq!(
        fallback_observe(handle, delayed.clone()).unwrap(),
        [vec![0, 1], ACK_NONE.to_be_bytes().to_vec()].concat()
    );
    assert_eq!(
        fallback_observe(handle, delayed.clone()).unwrap(),
        [vec![1, 1], ACK_NONE.to_be_bytes().to_vec()].concat()
    );
    assert_eq!(
        fallback_observe(handle, leading.clone()).unwrap(),
        gap_filled_observation_wire(&[leading.as_slice(), delayed.as_slice()])
    );
    assert_eq!(fallback_ack_due(handle, 25, false, false).unwrap().len(), 9);

    fallback_cache_outgoing(handle, 0, outer(0, 1), 1).unwrap();
    fallback_cache_outgoing(handle, 1, outer(1, 2), 2).unwrap();
    assert!(fallback_retry_due(handle, 750).unwrap().len() > 2);
    fallback_acknowledge(handle, 0).unwrap();
    assert!(fallback_gap_retransmit(handle, 1).unwrap().len() > 2);
    fallback_close(handle);
    assert!(fallback_observe(handle, outer(2, 3)).is_err());
}
