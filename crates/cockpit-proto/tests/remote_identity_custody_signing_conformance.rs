//! Cross-language custody-signing conformance. Consumes the SAME committed
//! fixture as the TypeScript `remote-identity-custody-signing.test.ts`, byte for
//! byte, and proves the digest-vs-message contract closes:
//! `digest == SHA-256(message)`, `message == domain || unsigned`, the pinned
//! low-S signature verifies with `p256`, and the production `PossessionProof`
//! codec accepts it (while rejecting the high-S companion).

use cockpit_proto::remote_identity_protocol::{
    PossessionProof, PossessionPurpose, possession_proof_signing_digest,
    possession_signature_domain, sha256,
};
use p256::ecdsa::signature::{Verifier, hazmat::PrehashVerifier};
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::Value;

fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn remote_identity_custody_signing_fixture_conformance() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../packages/cockpit-protocol/fixtures/remote-identity-custody-signing-v1.json"
    ))
    .unwrap();

    let purpose_byte = u8::try_from(fixture["purpose"].as_u64().unwrap()).unwrap();
    let purpose = PossessionPurpose::try_from(purpose_byte).unwrap();
    assert_eq!(purpose, PossessionPurpose::AttemptDaemon);

    let unsigned = unhex(fixture["unsignedProof"].as_str().unwrap());
    let domain = unhex(fixture["domain"].as_str().unwrap());
    let message = unhex(fixture["message"].as_str().unwrap());
    let digest = unhex(fixture["digest"].as_str().unwrap());
    let low_s = unhex(fixture["signatureLowS"].as_str().unwrap());
    let high_s = unhex(fixture["signatureHighS"].as_str().unwrap());
    let pub_x = unhex(fixture["publicKey"]["x"].as_str().unwrap());
    let pub_y = unhex(fixture["publicKey"]["y"].as_str().unwrap());

    assert_eq!(unsigned.len(), 175);
    assert_eq!(low_s.len(), 64);

    // message == domain || unsigned, and domain is the production signature domain.
    assert_eq!(domain, possession_signature_domain(purpose));
    let mut rebuilt = domain.clone();
    rebuilt.extend_from_slice(&unsigned);
    assert_eq!(rebuilt, message);

    // digest == SHA-256(message), recomputed via the production helper.
    assert_eq!(sha256(&message).to_vec(), digest);
    let recomputed = possession_proof_signing_digest(&unsigned, purpose).unwrap();
    assert_eq!(recomputed.to_vec(), digest);

    // Cryptographically verify the pinned low-S signature with p256, both over
    // the message (hash internally) and over the pinned prehash digest.
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&pub_x);
    sec1[33..65].copy_from_slice(&pub_y);
    let verifying_key = VerifyingKey::from_sec1_bytes(&sec1).expect("valid P-256 point");
    let signature = Signature::from_slice(&low_s).expect("valid P1363 signature");
    verifying_key
        .verify(&message, &signature)
        .expect("low-S signature verifies over the message");
    verifying_key
        .verify_prehash(&digest, &signature)
        .expect("low-S signature verifies over the pinned digest");

    // The high-S companion also verifies cryptographically (both s and n-s
    // verify) — which is exactly why provider-side low-S normalization exists.
    let high_signature = Signature::from_slice(&high_s).expect("valid P1363 signature");
    verifying_key
        .verify(&message, &high_signature)
        .expect("high-S companion also verifies");

    // The PRODUCTION codec accepts the low-S signed proof and round-trips it.
    let mut proof_bytes = [0u8; 239];
    proof_bytes[..175].copy_from_slice(&unsigned);
    proof_bytes[175..].copy_from_slice(&low_s);
    let decoded = PossessionProof::decode(&proof_bytes).expect("codec accepts low-S proof");
    assert_eq!(decoded.purpose, purpose);
    assert_eq!(decoded.encode().unwrap(), proof_bytes.to_vec());

    // ... and rejects the high-S companion (validate_low_s gate).
    let mut high_proof = [0u8; 239];
    high_proof[..175].copy_from_slice(&unsigned);
    high_proof[175..].copy_from_slice(&high_s);
    assert!(PossessionProof::decode(&high_proof).is_err());
}
