use cockpit_noise::{
    AuthorizationCapability, HandshakeFrame, NoiseChild, NoiseError, PROLOGUE_BODY_LEN,
    PROLOGUE_DOMAIN, PROLOGUE_ENCODED_LEN, RecordKind, RemoteNoisePrologueV1, RemoteNoiseRecordV1,
    TranscriptAuthorizationGate, TranscriptAuthorizationRequest,
};
use sha2::{Digest, Sha256};

fn prologue() -> RemoteNoisePrologueV1 {
    RemoteNoisePrologueV1 {
        child_attempt_id: [1; 16],
        grant_jti: [2; 16],
        client_certificate_id: [3; 16],
        client_certificate_generation: 4,
        daemon_certificate_id: [5; 16],
        daemon_certificate_generation: 6,
        selected_tuple_id: 7,
        negotiation_digest: [8; 32],
        policy_digest: [9; 32],
        connection_nonce: [10; 32],
    }
}

struct Gate;
impl TranscriptAuthorizationGate for Gate {
    fn authorize(
        &self,
        request: &TranscriptAuthorizationRequest<'_>,
    ) -> cockpit_noise::Result<AuthorizationCapability> {
        assert_eq!(request.child_attempt_id, [1; 16]);
        assert_eq!(request.transport_epoch, 11);
        assert_ne!(request.initiator_ephemeral, request.responder_ephemeral);
        assert_eq!(request.client_final_proof, b"client-proof");
        assert_eq!(request.daemon_final_proof, b"daemon-proof");
        Ok(AuthorizationCapability::verified())
    }
}

fn authorized_pair() -> (NoiseChild, NoiseChild) {
    let bytes = prologue().encode();
    let mut client = NoiseChild::initiator(&bytes, 11).unwrap();
    let mut daemon = NoiseChild::responder(&bytes, 11).unwrap();
    let one = client.write_handshake().unwrap();
    daemon.read_handshake(&one).unwrap();
    let two = daemon.write_handshake().unwrap();
    client.read_handshake(&two).unwrap();
    assert_eq!(client.handshake_hash(), daemon.handshake_hash());
    client
        .authorize(&Gate, b"client-proof", b"daemon-proof")
        .unwrap();
    daemon
        .authorize(&Gate, b"client-proof", b"daemon-proof")
        .unwrap();
    (client, daemon)
}

#[test]
fn remote_noise_prologue_binding_matrix() {
    let value = prologue();
    let encoded = value.encode();
    assert_eq!(PROLOGUE_BODY_LEN, 186);
    assert_eq!(encoded.len(), PROLOGUE_ENCODED_LEN);
    assert!(encoded.starts_with(PROLOGUE_DOMAIN));
    let body = &encoded[PROLOGUE_DOMAIN.len()..];
    assert_eq!(&body[..5], b"FCNP\x01");
    assert_eq!(&body[5..21], &[1; 16]);
    assert_eq!(&body[21..37], &[2; 16]);
    assert_eq!(&body[37..53], &[3; 16]);
    assert_eq!(&body[53..61], &4_u64.to_be_bytes());
    assert_eq!(&body[61..77], &[5; 16]);
    assert_eq!(&body[77..85], &6_u64.to_be_bytes());
    assert_eq!(&body[85..87], &7_u16.to_be_bytes());
    assert_eq!(&body[87..119], &[8; 32]);
    assert_eq!(&body[119..151], &[9; 32]);
    assert_eq!(&body[151..183], &[10; 32]);
    assert_eq!(&body[183..], &[1, 2, 2]);
    assert_eq!(value.digest(), <[u8; 32]>::from(Sha256::digest(&encoded)));
    for index in 0..encoded.len() {
        let mut changed = encoded.clone();
        changed[index] ^= 1;
        assert_ne!(Sha256::digest(&changed), Sha256::digest(&encoded));
    }
    assert_eq!(RemoteNoisePrologueV1::decode(&encoded).unwrap(), value);
    assert!(RemoteNoisePrologueV1::decode(&[encoded, vec![0]].concat()).is_err());
}

#[test]
fn remote_noise_handshake_frame_bounds() {
    let frame = HandshakeFrame::encode(1, &[7; 32]).unwrap();
    assert_eq!(&frame[..4], &[1, 1, 0, 32]);
    assert_eq!(
        HandshakeFrame::decode(&frame, 1).unwrap().message,
        vec![7; 32]
    );
    assert!(HandshakeFrame::encode(0, &[1]).is_err());
    assert!(HandshakeFrame::encode(1, &[0; 4097]).is_err());
    assert!(HandshakeFrame::decode(&[frame, vec![0]].concat(), 1).is_err());

    let mut responder = NoiseChild::responder(&prologue().encode(), 11).unwrap();
    let all_zero = HandshakeFrame::encode(1, &[0; 32]).unwrap();
    assert_eq!(
        responder.read_handshake(&all_zero),
        Err(NoiseError::LowOrderKey)
    );
    assert_eq!(
        responder.read_handshake(&all_zero),
        Err(NoiseError::InvalidState)
    );
}

#[test]
fn remote_noise_transcript_gate_and_record_parser_bounds() {
    let bytes = prologue().encode();
    let mut sealed = NoiseChild::initiator(&bytes, 11).unwrap();
    assert_eq!(
        sealed.encrypt_record(RecordKind::Data, b"sealed"),
        Err(NoiseError::InvalidState)
    );
    let (mut client, mut daemon) = authorized_pair();
    let ciphertext = client.encrypt_record(RecordKind::Data, b"hello").unwrap();
    assert!(ciphertext.len() <= 65_535);
    let record = daemon.decrypt_record(0, &ciphertext).unwrap();
    assert_eq!(record.payload, b"hello");
    assert_eq!(record.sequence, 0);
    assert_eq!(
        daemon.decrypt_record(0, &ciphertext),
        Err(NoiseError::SequenceMismatch)
    );

    let maximum = RemoteNoiseRecordV1 {
        kind: RecordKind::Data,
        sequence: 4,
        payload: vec![0; 65_505],
    };
    assert_eq!(maximum.encode_plaintext().unwrap().len(), 65_519);
    let oversized = RemoteNoiseRecordV1 {
        kind: RecordKind::Data,
        sequence: 5,
        payload: vec![0; 65_506],
    };
    assert_eq!(
        oversized.encode_plaintext(),
        Err(NoiseError::RecordTooLarge)
    );
}

#[test]
fn remote_noise_uses_fresh_ephemeral_keys_per_child() {
    let bytes = prologue().encode();
    let mut first = NoiseChild::initiator(&bytes, 11).unwrap();
    let mut second = NoiseChild::initiator(&bytes, 11).unwrap();
    let first_message = HandshakeFrame::decode(&first.write_handshake().unwrap(), 1).unwrap();
    let second_message = HandshakeFrame::decode(&second.write_handshake().unwrap(), 1).unwrap();
    assert_ne!(&first_message.message[..32], &second_message.message[..32]);
}

#[test]
fn remote_noise_state_misuse_and_reorder() {
    let (mut client, mut daemon) = authorized_pair();
    let first = client.encrypt_record(RecordKind::Ack, b"").unwrap();
    assert_eq!(
        daemon.decrypt_record(1, &first),
        Err(NoiseError::SequenceMismatch)
    );
    assert_eq!(daemon.decrypt_record(0, &first), Err(NoiseError::Closed));
    client.close();
    assert_eq!(
        client.encrypt_record(RecordKind::Data, b"x"),
        Err(NoiseError::InvalidState)
    );
}

#[test]
fn remote_noise_errors_are_secret_free_stable_codes() {
    let secret = b"never-log-this-plaintext";
    let errors = [
        NoiseError::InvalidPrologue,
        NoiseError::AuthenticationFailed,
        NoiseError::AuthorizationDenied,
        NoiseError::Closed,
    ];
    for error in errors {
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(
            !display
                .as_bytes()
                .windows(secret.len())
                .any(|part| part == secret)
        );
        assert!(
            !debug
                .as_bytes()
                .windows(secret.len())
                .any(|part| part == secret)
        );
        assert!(
            display
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        );
    }
}

#[test]
fn remote_noise_official_vector_conformance_has_nonzero_pinned_corpus() {
    let fixture = include_str!("../fixtures/noise-c-nn-25519-chachapoly-sha256.json");
    assert!(fixture.contains("Noise_NN_25519_ChaChaPoly_SHA256"));
    assert!(fixture.contains("cfe25410979a87391bb9ac8d4d4bef64e9f268c6"));
    assert!(fixture.contains("e1b0c4100b6c6e76378705a4954c3293f3752a55b586a3a252cecbfc937538c9"));
    assert!(fixture.matches("ciphertext").count() > 0);
}

struct BindingGate;
impl cockpit_noise::BindingAuthorizationGate for BindingGate {
    fn authorize(&self, request: cockpit_noise::BindingAuthorizationRequest) -> bool {
        request.handshake_hash.len() == 32
            && request.transport_epoch == 11
            && request.prologue_digest.len() == 32
            && request.initiator_ephemeral.len() == 32
            && request.responder_ephemeral.len() == 32
            && request.client_final_proof == b"client-proof"
            && request.daemon_final_proof == b"daemon-proof"
    }
}

#[test]
fn remote_noise_binding_conformance_uses_the_same_opaque_core() {
    let bytes = prologue().encode();
    let client = cockpit_noise::noise_create_initiator(bytes.clone(), 11).unwrap();
    let daemon = cockpit_noise::noise_create_responder(bytes, 11).unwrap();
    let one = cockpit_noise::noise_write_handshake(client).unwrap();
    cockpit_noise::noise_read_handshake(daemon, one).unwrap();
    let two = cockpit_noise::noise_write_handshake(daemon).unwrap();
    cockpit_noise::noise_read_handshake(client, two).unwrap();
    assert_eq!(
        cockpit_noise::noise_handshake_hash(client).unwrap(),
        cockpit_noise::noise_handshake_hash(daemon).unwrap()
    );
    cockpit_noise::noise_authorize(
        client,
        b"client-proof".to_vec(),
        b"daemon-proof".to_vec(),
        Box::new(BindingGate),
    )
    .unwrap();
    cockpit_noise::noise_authorize(
        daemon,
        b"client-proof".to_vec(),
        b"daemon-proof".to_vec(),
        Box::new(BindingGate),
    )
    .unwrap();
    let ciphertext = cockpit_noise::noise_encrypt_record(client, 1, b"binding".to_vec()).unwrap();
    let plaintext = cockpit_noise::noise_decrypt_record(daemon, 0, ciphertext).unwrap();
    assert_eq!(
        RemoteNoiseRecordV1::decode_plaintext(&plaintext, 0)
            .unwrap()
            .payload,
        b"binding"
    );
    cockpit_noise::noise_close(client);
    assert!(cockpit_noise::noise_write_handshake(client).is_err());
    cockpit_noise::noise_close(daemon);
}

#[test]
fn remote_fallback_binding_authenticates_outer_sequence_watermark_and_route() {
    let bytes = prologue().encode();
    let client = cockpit_noise::noise_create_initiator(bytes.clone(), 11).unwrap();
    let daemon = cockpit_noise::noise_create_responder(bytes, 11).unwrap();
    let one = cockpit_noise::noise_write_handshake(client).unwrap();
    cockpit_noise::noise_read_handshake(daemon, one).unwrap();
    let two = cockpit_noise::noise_write_handshake(daemon).unwrap();
    cockpit_noise::noise_read_handshake(client, two).unwrap();
    let gate: Arc<dyn cockpit_noise::BindingAuthorizationGate> = Arc::new(BindingGate);
    cockpit_noise::noise_authorize(
        client,
        b"client-proof".to_vec(),
        b"daemon-proof".to_vec(),
        Arc::clone(&gate),
    )
    .unwrap();
    cockpit_noise::noise_authorize(
        daemon,
        b"client-proof".to_vec(),
        b"daemon-proof".to_vec(),
        gate,
    )
    .unwrap();
    cockpit_noise::noise_bind_fallback_route(client, 7).unwrap();
    cockpit_noise::noise_bind_fallback_route(daemon, 7).unwrap();
    let outer = cockpit_noise::noise_encrypt_fallback_record(
        client,
        1,
        7,
        0,
        u64::MAX,
        b"fragment".to_vec(),
    )
    .unwrap();
    let plaintext = cockpit_noise::noise_decrypt_fallback_record(daemon, outer).unwrap();
    let record = RemoteNoiseRecordV1::decode_plaintext(&plaintext, 0).unwrap();
    assert_eq!(&record.payload[..8], &u64::MAX.to_be_bytes());
    assert_eq!(&record.payload[8..], b"fragment");
    cockpit_noise::noise_close(client);
    cockpit_noise::noise_close(daemon);
}

#[cfg(feature = "test-entropy")]
#[test]
fn remote_noise_official_vector_conformance_executes_pinned_case() {
    fn hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }
    let prologue = hex("4a6f686e2047616c74");
    let initiator: [u8; 32] =
        hex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")
            .try_into()
            .unwrap();
    let responder: [u8; 32] =
        hex("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b")
            .try_into()
            .unwrap();
    let payloads = [
        "4c756477696720766f6e204d69736573",
        "4d757272617920526f746862617264",
        "462e20412e20486179656b",
        "4361726c204d656e676572",
        "4a65616e2d426170746973746520536179",
        "457567656e2042f6686d20766f6e2042617765726b",
    ]
    .map(hex);
    let expected = [
        "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573",
        "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843a0ff96bdf86b579ef7dbf94e812a7470b903c20a85a87e3a1fe863264ae547",
        "eb1a3e3d80c1792b1bb9cb0e1382f8d8322bfb1ca7c4c8517bb686",
        "c781b198d2a974eb1da2c7d518c000cf6396de87ca540963c03713",
        "c77048eb6919fdfe8fe45842bfc5b8d1ff50d1e20c717453ccdfe6176d805b996d",
        "61834d7069dcfb7a1adf8d5ac910f83fa04c73a67789895c6f5f995c5db2ce88e49b124178",
    ].map(hex);
    let actual =
        cockpit_noise::run_nn_test_vector(&prologue, &initiator, &responder, &payloads).unwrap();
    assert_eq!(actual, expected);
}
