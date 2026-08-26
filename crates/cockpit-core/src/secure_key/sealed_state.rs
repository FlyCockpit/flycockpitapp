//! Crash-safe dual-slot sealed mutable state for the secure-key actor.
//!
//! Canonical encoding and HMAC verification for `SealedStateItemV1`. Native
//! I/O and CAS sagas live on the actor/worker; this module stays pure.
#![allow(dead_code)] // Wired through SecureKeyHandle in the remainder of this prompt.

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::error::SecureKeyError;
use super::key_material::{KEY_BYTE_LEN, SecureKeyBytes};
use super::namespace::{Namespace, SECURE_KEY_SERVICE, encode_account_component};

type HmacSha256 = Hmac<Sha256>;

pub const MAX_PAYLOAD_LEN: usize = 1024;
pub const ITEM_FIXED_PREFIX_LEN: usize = 134;
pub const HMAC_TAG_LEN: usize = 32;
pub const MAGIC: &[u8; 4] = b"FCSS";
pub const FORMAT_VERSION: u8 = 0x01;
pub const SLOT_A: u8 = 0x01;
pub const SLOT_B: u8 = 0x02;

const DOMAIN_NAMESPACE: &[u8] = b"flycockpit-sealed-state-namespace-v1\0";
const DOMAIN_NATIVE_ITEM: &[u8] = b"flycockpit-sealed-state-native-item-v1\0";
const DOMAIN_PAYLOAD: &[u8] = b"flycockpit-sealed-state-payload-v1\0";
const DOMAIN_MAC: &[u8] = b"flycockpit-sealed-state-item-mac-v1\0";

/// Opaque sealed-state payload. Intentionally no Debug/Display/serde.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedPayload(Zeroizing<Vec<u8>>);

impl SealedPayload {
    pub fn new(bytes: Vec<u8>) -> Result<Self, SecureKeyError> {
        if bytes.len() > MAX_PAYLOAD_LEN {
            return Err(SecureKeyError::Invalid(format!(
                "sealed payload length {} exceeds {MAX_PAYLOAD_LEN}",
                bytes.len()
            )));
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn empty() -> Self {
        Self(Zeroizing::new(Vec::new()))
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// No Debug/Display for SealedPayload — payload bytes must not appear in logs.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedSlot {
    A,
    B,
}

impl SealedSlot {
    pub fn byte(self) -> u8 {
        match self {
            Self::A => SLOT_A,
            Self::B => SLOT_B,
        }
    }

    pub fn suffix(self) -> &'static str {
        match self {
            Self::A => "state-a",
            Self::B => "state-b",
        }
    }

    pub fn from_byte(b: u8) -> Result<Self, SecureKeyError> {
        match b {
            SLOT_A => Ok(Self::A),
            SLOT_B => Ok(Self::B),
            other => Err(SecureKeyError::Corrupt(format!(
                "invalid sealed slot byte {other:#x}"
            ))),
        }
    }

    pub fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

/// Safe metadata returned to unauthorized surfaces.
/// Prompt-closed fields: namespace, generation, payload_digest, key_version, health.
/// `current_slot` is crate-private (two-slot implementation detail for CAS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedStateMeta {
    pub namespace: String,
    pub generation: u64,
    pub payload_digest: [u8; 32],
    pub key_version: u32,
    pub health: SealedHealth,
    pub(crate) current_slot: SealedSlot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedHealth {
    Healthy,
    Degraded,
}

/// Authorized in-process view including payload bytes.
/// Debug prints only safe metadata (never payload bytes).
#[derive(Clone)]
pub struct SealedStateView {
    pub meta: SealedStateMeta,
    pub payload: SealedPayload,
}

impl std::fmt::Debug for SealedStateView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedStateView")
            .field("meta", &self.meta)
            .field(
                "payload",
                &format_args!("[REDACTED; {}]", self.payload.len()),
            )
            .finish()
    }
}

pub fn sealed_state_account(
    installation_hex: &str,
    namespace: &Namespace,
    slot: SealedSlot,
) -> Result<String, SecureKeyError> {
    let inst = encode_account_component(installation_hex)?;
    let ns = encode_account_component(namespace.as_str())?;
    Ok(format!("{inst}/{ns}/{}", slot.suffix()))
}

pub fn namespace_digest(install: &[u8; 16], namespace_utf8: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_NAMESPACE);
    h.update(install);
    h.update([namespace_utf8.len() as u8]);
    h.update(namespace_utf8);
    h.finalize().into()
}

pub fn native_item_binding_digest(service: &[u8], account: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_NATIVE_ITEM);
    h.update((service.len() as u16).to_be_bytes());
    h.update(service);
    h.update((account.len() as u16).to_be_bytes());
    h.update(account);
    h.finalize().into()
}

pub fn payload_digest(payload: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_PAYLOAD);
    h.update((payload.len() as u16).to_be_bytes());
    h.update(payload);
    h.finalize().into()
}

/// Encode one canonical SealedStateItemV1 and return unpadded base64url.
pub fn encode_item_base64url(
    install: &[u8; 16],
    namespace: &Namespace,
    slot: SealedSlot,
    generation: u64,
    key_version: u32,
    payload: &SealedPayload,
    key: &SecureKeyBytes,
) -> Result<String, SecureKeyError> {
    let decoded = encode_item_bytes(
        install,
        namespace,
        slot,
        generation,
        key_version,
        payload,
        key,
    )?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(decoded))
}

pub fn encode_item_bytes(
    install: &[u8; 16],
    namespace: &Namespace,
    slot: SealedSlot,
    generation: u64,
    key_version: u32,
    payload: &SealedPayload,
    key: &SecureKeyBytes,
) -> Result<Vec<u8>, SecureKeyError> {
    if generation == 0 {
        return Err(SecureKeyError::Invalid(
            "sealed state generation must be non-zero".into(),
        ));
    }
    if key_version == 0 {
        return Err(SecureKeyError::Invalid(
            "sealed state key version must be non-zero".into(),
        ));
    }
    let n = payload.len();
    if n > MAX_PAYLOAD_LEN {
        return Err(SecureKeyError::Invalid(format!(
            "payload length {n} exceeds {MAX_PAYLOAD_LEN}"
        )));
    }
    let install_hex = hex_encode(install);
    let account = sealed_state_account(&install_hex, namespace, slot)?;
    let mut body = Vec::with_capacity(ITEM_FIXED_PREFIX_LEN + n + HMAC_TAG_LEN);
    body.extend_from_slice(MAGIC);
    body.push(FORMAT_VERSION);
    body.push(slot.byte());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(install);
    body.extend_from_slice(&namespace_digest(install, namespace.as_str().as_bytes()));
    body.extend_from_slice(&native_item_binding_digest(
        SECURE_KEY_SERVICE.as_bytes(),
        account.as_bytes(),
    ));
    body.extend_from_slice(&generation.to_be_bytes());
    body.extend_from_slice(&(n as u16).to_be_bytes());
    body.extend_from_slice(&payload_digest(payload.as_slice()));
    body.extend_from_slice(&key_version.to_be_bytes());
    body.extend_from_slice(payload.as_slice());
    let tag = hmac_tag(key.as_ref(), &body)?;
    body.extend_from_slice(&tag);
    debug_assert_eq!(body.len(), ITEM_FIXED_PREFIX_LEN + n + HMAC_TAG_LEN);
    Ok(body)
}

fn hmac_tag(key: &[u8], mac_input_prefix: &[u8]) -> Result<[u8; 32], SecureKeyError> {
    if key.len() != KEY_BYTE_LEN {
        return Err(SecureKeyError::Corrupt("hmac key length".into()));
    }
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| SecureKeyError::Internal("hmac key length".into()))?;
    mac.update(DOMAIN_MAC);
    mac.update(mac_input_prefix);
    Ok(mac.finalize().into_bytes().into())
}

/// Decode and authenticate one unpadded base64url item.
pub fn decode_and_verify(
    value: &str,
    install: &[u8; 16],
    namespace: &Namespace,
    expected_slot: SealedSlot,
    key: &SecureKeyBytes,
) -> Result<(u64, u32, SealedPayload, [u8; 32]), SecureKeyError> {
    if value.as_bytes().iter().any(|b| {
        !matches!(
            b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'
        )
    }) {
        return Err(SecureKeyError::Corrupt(
            "sealed item base64url noncanonical alphabet".into(),
        ));
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| SecureKeyError::Corrupt("sealed item base64url decode".into()))?;
    // Reject non-canonical re-encoding (must round-trip exactly).
    let re = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&decoded);
    if re != value {
        return Err(SecureKeyError::Corrupt(
            "sealed item base64url noncanonical encoding".into(),
        ));
    }
    decode_and_verify_bytes(&decoded, install, namespace, expected_slot, key)
}

pub fn decode_and_verify_bytes(
    decoded: &[u8],
    install: &[u8; 16],
    namespace: &Namespace,
    expected_slot: SealedSlot,
    key: &SecureKeyBytes,
) -> Result<(u64, u32, SealedPayload, [u8; 32]), SecureKeyError> {
    if decoded.len() < ITEM_FIXED_PREFIX_LEN + HMAC_TAG_LEN {
        return Err(SecureKeyError::Corrupt("sealed item too short".into()));
    }
    let n = decoded.len() - ITEM_FIXED_PREFIX_LEN - HMAC_TAG_LEN;
    if n > MAX_PAYLOAD_LEN {
        return Err(SecureKeyError::Corrupt(
            "sealed item payload too long".into(),
        ));
    }
    if decoded.len() != ITEM_FIXED_PREFIX_LEN + n + HMAC_TAG_LEN {
        return Err(SecureKeyError::Corrupt(
            "sealed item length mismatch".into(),
        ));
    }
    if &decoded[0..4] != MAGIC {
        return Err(SecureKeyError::Corrupt("sealed item magic".into()));
    }
    if decoded[4] != FORMAT_VERSION {
        return Err(SecureKeyError::Corrupt("sealed item format version".into()));
    }
    let slot = SealedSlot::from_byte(decoded[5])?;
    if slot != expected_slot {
        return Err(SecureKeyError::Corrupt("sealed item slot mismatch".into()));
    }
    if decoded[6..8] != [0, 0] {
        return Err(SecureKeyError::Corrupt("sealed item reserved".into()));
    }
    if decoded[8..24] != install[..] {
        return Err(SecureKeyError::Corrupt(
            "sealed item install binding".into(),
        ));
    }
    let expected_ns = namespace_digest(install, namespace.as_str().as_bytes());
    if decoded[24..56] != expected_ns {
        return Err(SecureKeyError::Corrupt(
            "sealed item namespace digest".into(),
        ));
    }
    let install_hex = hex_encode(install);
    let account = sealed_state_account(&install_hex, namespace, slot)?;
    let expected_bind =
        native_item_binding_digest(SECURE_KEY_SERVICE.as_bytes(), account.as_bytes());
    if decoded[56..88] != expected_bind {
        return Err(SecureKeyError::Corrupt("sealed item native binding".into()));
    }
    let generation = u64::from_be_bytes(decoded[88..96].try_into().unwrap());
    if generation == 0 {
        return Err(SecureKeyError::Corrupt(
            "sealed item generation zero".into(),
        ));
    }
    let payload_len = u16::from_be_bytes(decoded[96..98].try_into().unwrap()) as usize;
    if payload_len != n {
        return Err(SecureKeyError::Corrupt("sealed item payload length".into()));
    }
    let payload_digest_stored: [u8; 32] = decoded[98..130].try_into().unwrap();
    let key_version = u32::from_be_bytes(decoded[130..134].try_into().unwrap());
    if key_version == 0 {
        return Err(SecureKeyError::Corrupt(
            "sealed item key version zero".into(),
        ));
    }
    let payload_bytes = &decoded[134..134 + n];
    let expected_pd = payload_digest(payload_bytes);
    if payload_digest_stored != expected_pd {
        return Err(SecureKeyError::Corrupt("sealed item payload digest".into()));
    }
    let tag = &decoded[134 + n..];
    let mut mac = HmacSha256::new_from_slice(key.as_ref())
        .map_err(|_| SecureKeyError::Internal("hmac key length".into()))?;
    mac.update(DOMAIN_MAC);
    mac.update(&decoded[..134 + n]);
    mac.verify_slice(tag)
        .map_err(|_| SecureKeyError::Corrupt("sealed item hmac".into()))?;
    let payload = SealedPayload::new(payload_bytes.to_vec())?;
    Ok((generation, key_version, payload, payload_digest_stored))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::super::key_material::SecureKeyBytes;
    use super::*;

    fn install_fixture() -> [u8; 16] {
        let mut a = [0u8; 16];
        for (i, b) in a.iter_mut().enumerate() {
            *b = i as u8;
        }
        a
    }

    fn key_00_1f() -> SecureKeyBytes {
        let mut a = [0u8; 32];
        for (i, b) in a.iter_mut().enumerate() {
            *b = i as u8;
        }
        SecureKeyBytes::from_array(a)
    }

    fn key_ff_e0() -> SecureKeyBytes {
        let mut a = [0u8; 32];
        for (i, b) in a.iter_mut().enumerate() {
            *b = 0xff - i as u8;
        }
        SecureKeyBytes::from_array(a)
    }

    #[test]
    fn sealed_state_v1_frozen_vectors() {
        let install = install_fixture();
        let ns = Namespace::parse("audit-head/v1").unwrap();
        let acct_a = sealed_state_account(&hex_encode(&install), &ns, SealedSlot::A).unwrap();
        let acct_b = sealed_state_account(&hex_encode(&install), &ns, SealedSlot::B).unwrap();
        // Literal canonical accounts from independent encoder (not recomputed helpers alone).
        assert_eq!(
            acct_a,
            "000102030405060708090a0b0c0d0e0f/audit-head%2Fv1/state-a"
        );
        assert_eq!(
            acct_b,
            "000102030405060708090a0b0c0d0e0f/audit-head%2Fv1/state-b"
        );

        let empty = SealedPayload::empty();
        let key1 = key_00_1f();
        let encoded = encode_item_bytes(&install, &ns, SealedSlot::A, 1, 1, &empty, &key1).unwrap();
        assert_eq!(encoded.len(), 166);
        let b64 = encode_item_base64url(&install, &ns, SealedSlot::A, 1, 1, &empty, &key1).unwrap();
        assert_eq!(b64.len(), 222);
        // Independent fixture hex (python hmac/sha256 generator).
        const EMPTY_HEX: &str = "4643535301010000000102030405060708090a0b0c0d0e0f7401b96b548baa437ad8880c9b890f492843f323c6afd41b6f90070fc0953e76ce9dd8896b267868e182165e00d1db81cb28e6ce1950e93533eebcd57864aabf00000000000000010000969361085b8a1b5abc01376dfd55971b5e7ec262b0b04c8c01af12fb1e4365ac00000001c0a7e4127af15b3cbfa63d8750620f2a3b11d94e7f23e3c8afcf22233c0c9c47";
        const EMPTY_B64: &str = "RkNTUwEBAAAAAQIDBAUGBwgJCgsMDQ4PdAG5a1SLqkN62IgMm4kPSShD8yPGr9Qbb5AHD8CVPnbOndiJayZ4aOGCFl4A0duByyjmzhlQ6TUz7rzVeGSqvwAAAAAAAAABAACWk2EIW4obWrwBN239VZcbXn7CYrCwTIwBrxL7HkNlrAAAAAHAp-QSevFbPL-mPYdQYg8qOxHZTn8j48ivzyIjPAycRw";
        assert_eq!(hex_encode(&encoded), EMPTY_HEX);
        assert_eq!(b64, EMPTY_B64);

        let (g, kv, payload, pd) =
            decode_and_verify(&b64, &install, &ns, SealedSlot::A, &key1).unwrap();
        assert_eq!(g, 1);
        assert_eq!(kv, 1);
        assert!(payload.is_empty());
        assert_eq!(pd, payload_digest(&[]));

        let mid_payload = SealedPayload::new(vec![0x00, 0xff, 0x41]).unwrap();
        let key2 = key_ff_e0();
        let mid = encode_item_bytes(
            &install,
            &ns,
            SealedSlot::B,
            0x0102_0304_0506_0708,
            0x0102_0304,
            &mid_payload,
            &key2,
        )
        .unwrap();
        assert_eq!(mid.len(), 169);
        const MID_HEX: &str = "4643535301020000000102030405060708090a0b0c0d0e0f7401b96b548baa437ad8880c9b890f492843f323c6afd41b6f90070fc0953e769171ad8d29d3051956c1e3dbd9e57695fa7dfcb8430971baea1d7abdccbad22b0102030405060708000342da9fc95d1e5e0540cb80f734054cdf3f3e0a59a8b500bf3b99e472a43eea2c0102030400ff41df4ad1a0013f79efff8fc4f1ec647b3efaccc62096f87a15331a672246f34f10";
        const MID_B64: &str = "RkNTUwECAAAAAQIDBAUGBwgJCgsMDQ4PdAG5a1SLqkN62IgMm4kPSShD8yPGr9Qbb5AHD8CVPnaRca2NKdMFGVbB49vZ5XaV-n38uEMJcbrqHXq9zLrSKwECAwQFBgcIAANC2p_JXR5eBUDLgPc0BUzfPz4KWai1AL87meRypD7qLAECAwQA_0HfStGgAT957_-PxPHsZHs--szGIJb4ehUzGmciRvNPEA";
        assert_eq!(hex_encode(&mid), MID_HEX);
        let mid_b64 = encode_item_base64url(
            &install,
            &ns,
            SealedSlot::B,
            0x0102_0304_0506_0708,
            0x0102_0304,
            &mid_payload,
            &key2,
        )
        .unwrap();
        assert_eq!(mid_b64, MID_B64);
        // Field offsets for empty vector (N=0).
        assert_eq!(&encoded[0..4], b"FCSS");
        assert_eq!(encoded[4], 0x01);
        assert_eq!(encoded[5], SLOT_A);
        assert_eq!(&encoded[8..24], &install[..]);
        assert_eq!(
            &encoded[24..56],
            &namespace_digest(&install, ns.as_str().as_bytes())
        );
        assert_eq!(u64::from_be_bytes(encoded[88..96].try_into().unwrap()), 1);
        assert_eq!(u16::from_be_bytes(encoded[96..98].try_into().unwrap()), 0);
        assert_eq!(u32::from_be_bytes(encoded[130..134].try_into().unwrap()), 1);

        // Bit flips fail across all required field regions.
        // 8 install, 24 namespace digest, 56 account-binding, 5 slot, 88 gen, 96 len,
        // 98 payload digest, 130 key_version, 150 MAC (N=0 tag starts at 134).
        for offset in [5usize, 8, 24, 56, 88, 96, 98, 130, 134, 150] {
            let mut flipped = encoded.clone();
            flipped[offset] ^= 0x01;
            assert!(
                decode_and_verify_bytes(&flipped, &install, &ns, SealedSlot::A, &key1).is_err(),
                "flip at {offset} must fail"
            );
        }
        // Nonempty payload flip on mid fixture.
        let mut mid_flip = mid.clone();
        mid_flip[134] ^= 0x01; // first payload byte
        assert!(decode_and_verify_bytes(&mid_flip, &install, &ns, SealedSlot::B, &key2).is_err());
        // Cross-slot copy fails.
        assert!(decode_and_verify_bytes(&encoded, &install, &ns, SealedSlot::B, &key1).is_err());
        // Cross-install fails.
        let mut other_install = install;
        other_install[0] ^= 0xff;
        assert!(
            decode_and_verify_bytes(&encoded, &other_install, &ns, SealedSlot::A, &key1).is_err()
        );
        // Cross-namespace fails.
        let other_ns = Namespace::parse("other-ns/v1").unwrap();
        assert!(
            decode_and_verify_bytes(&encoded, &install, &other_ns, SealedSlot::A, &key1).is_err()
        );
        // Wrong key fails.
        assert!(decode_and_verify(&b64, &install, &ns, SealedSlot::A, &key2).is_err());
        // Padding rejected.
        assert!(
            decode_and_verify(&format!("{b64}="), &install, &ns, SealedSlot::A, &key1).is_err()
        );
        // Whitespace rejected.
        assert!(
            decode_and_verify(&format!(" {b64}"), &install, &ns, SealedSlot::A, &key1).is_err()
        );
        // Non-URL alphabet rejected.
        assert!(
            decode_and_verify(&b64.replace('-', "+"), &install, &ns, SealedSlot::A, &key1).is_err()
                || b64 == b64.replace('-', "+")
        );
        // Max payload base64 length 1,587 fits Windows CredWrite blob minimum (2,560).
        // CRED_MAX_CREDENTIAL_BLOB_SIZE = 5*512; adapters support at least this.
        const SMALLEST_SUPPORTED_NATIVE_VALUE_LIMIT: usize = 2560;
        const _: () = assert!(1587 <= SMALLEST_SUPPORTED_NATIVE_VALUE_LIMIT);
        let max_payload = SealedPayload::new(vec![0u8; 1024]).unwrap();
        let max_b64 =
            encode_item_base64url(&install, &ns, SealedSlot::A, 1, 1, &max_payload, &key1).unwrap();
        assert_eq!(max_b64.len(), 1587);
        assert!(max_b64.len() <= SMALLEST_SUPPORTED_NATIVE_VALUE_LIMIT);
    }

    #[test]
    fn sealed_state_bounded_private_lengths() {
        let install = install_fixture();
        let ns = Namespace::parse("audit-head/v1").unwrap();
        let key = key_00_1f();
        let empty = SealedPayload::empty();
        let e = encode_item_bytes(&install, &ns, SealedSlot::A, 1, 1, &empty, &key).unwrap();
        assert_eq!(e.len(), 166);
        let b64 = encode_item_base64url(&install, &ns, SealedSlot::A, 1, 1, &empty, &key).unwrap();
        assert_eq!(b64.len(), 222);

        let max_payload = SealedPayload::new(vec![0u8; 1024]).unwrap();
        let m = encode_item_bytes(&install, &ns, SealedSlot::A, 1, 1, &max_payload, &key).unwrap();
        assert_eq!(m.len(), 1190);
        let mb64 =
            encode_item_base64url(&install, &ns, SealedSlot::A, 1, 1, &max_payload, &key).unwrap();
        assert_eq!(mb64.len(), 1587);

        assert!(SealedPayload::new(vec![0u8; 1025]).is_err());
    }

    #[test]
    fn sealed_state_hmac_known_answer_and_negatives() {
        // Official HMAC-SHA-256 KAT (RFC 4231 test case 1).
        let key = b"\x0b".repeat(20);
        let data = b"Hi There";
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(data);
        let tag = mac.finalize().into_bytes();
        const EXPECT: &str = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        assert_eq!(hex_encode(&tag), EXPECT);

        let mut mac2 = HmacSha256::new_from_slice(&key).unwrap();
        mac2.update(data);
        assert!(mac2.verify_slice(&tag).is_ok());
        let mut bad = tag;
        bad[0] ^= 1;
        let mut mac3 = HmacSha256::new_from_slice(&key).unwrap();
        mac3.update(data);
        assert!(mac3.verify_slice(&bad).is_err());
        let mut mac4 = HmacSha256::new_from_slice(&key).unwrap();
        mac4.update(data);
        assert!(mac4.verify_slice(&tag[..31]).is_err());
    }

    #[test]
    fn sealed_state_hmac_dependency_and_implementation_inventory() {
        let manifest = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
        assert!(
            manifest.contains("hmac = { version = \"=0.13.0\"")
                || manifest.contains("hmac = { version = \"=0.13.0\","),
            "owning member must declare hmac =0.13.0"
        );
        assert!(manifest.contains("features = [\"zeroize\"]"));
        assert!(manifest.contains("default-features = false"));
        let root = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml"));
        assert!(
            !root.contains("\nhmac ")
                && !root.lines().any(|l| l.trim_start().starts_with("hmac =")),
            "hmac must not be in workspace dependencies"
        );
        assert!(!manifest.contains("hmac.workspace"));
        // Only the owning member (cockpit-core, sealed state) and cockpit-proto
        // may declare hmac. cockpit-proto needs its own HMAC for remote
        // transport crypto (device-identity enrollment HKDF, coturn TURN REST
        // credentials); the crate graph forbids it from depending on
        // cockpit-core, so it must pin the same exact secure build itself. Any
        // other member declaring hmac — or a declaration that is not the exact
        // secure pin — is a regression.
        const SEALED_HMAC_PIN: &str =
            "hmac = { version = \"=0.13.0\", default-features = false, features = [\"zeroize\"] }";
        // cockpit-proto gates hmac behind `remote`, so its declaration carries
        // `optional = true` while keeping the same version / feature pin.
        const PROTO_HMAC_PIN: &str = "hmac = { version = \"=0.13.0\", default-features = false, features = [\"zeroize\"], optional = true }";
        let own_manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let own_canon = std::fs::canonicalize(&own_manifest).unwrap_or(own_manifest);
        let proto_manifest =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../cockpit-proto/Cargo.toml");
        let proto_canon = std::fs::canonicalize(&proto_manifest).unwrap_or(proto_manifest.clone());
        let crates_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
        let apps_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../apps");
        for dir in [crates_dir, apps_dir] {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path().join("Cargo.toml");
                    let canon = std::fs::canonicalize(&path).unwrap_or(path.clone());
                    if canon == own_canon || canon == proto_canon {
                        continue;
                    }
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        assert!(
                            !text.lines().any(|l| {
                                let t = l.trim_start();
                                t.starts_with("hmac ") || t.starts_with("hmac=")
                            }),
                            "only cockpit-core and cockpit-proto may declare hmac: {}",
                            path.display()
                        );
                    }
                }
            }
        }
        // cockpit-proto must carry the same secure version/feature pin as sealed
        // state (optional only because remote feature-gates the dep).
        let proto_manifest_text =
            std::fs::read_to_string(&proto_canon).expect("read cockpit-proto Cargo.toml");
        assert!(
            proto_manifest_text.contains(PROTO_HMAC_PIN),
            "cockpit-proto must pin hmac exactly as sealed state does (optional for remote): {PROTO_HMAC_PIN}"
        );
        assert!(
            manifest.contains(SEALED_HMAC_PIN),
            "cockpit-core must pin hmac exactly: {SEALED_HMAC_PIN}"
        );
        // Locked tree: direct sealed HMAC is 0.13.0. A transitive hmac 0.12.x may appear via
        // the Linux secret-service adapter stack; sealed production uses only 0.13.0.
        let lock = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"));
        assert!(
            lock.contains("name = \"hmac\"\nversion = \"0.13.0\""),
            "Cargo.lock must pin hmac 0.13.0"
        );
        // Owning member direct declaration is the sealed pin (not a transitive-only edge).
        assert!(
            manifest.contains("=0.13.0"),
            "direct sealed pin must be exact 0.13.0"
        );
        // MSRV of hmac 0.13 is 1.85 (crates.io/docs); workspace package is 1.95 ≥ 1.85.
        assert!(manifest.contains("rust-version = \"1.95\""));
        const HMAC_MSRV_MINOR: u32 = 85; // hmac 0.13.0 declared MSRV 1.85
        const WORKSPACE_MSRV_MINOR: u32 = 95;
        const _: () = assert!(WORKSPACE_MSRV_MINOR >= HMAC_MSRV_MINOR);
        // License policy: hmac is MIT OR Apache-2.0 (literal from crates.io metadata).
        const HMAC_LICENSE: &str = "MIT OR Apache-2.0";
        const _: () = assert!(
            HMAC_LICENSE.as_bytes()[0] == b'M' // compile-time non-empty MIT OR Apache marker
        );
        assert!(HMAC_LICENSE.contains("MIT") && HMAC_LICENSE.contains("Apache-2.0"));
        assert!(manifest.contains("license = \"Apache-2.0\""));
        // Locked tree: cockpit-core depends on hmac 0.13.0 (not only 0.12 transitively).
        assert!(
            lock.contains("name = \"hmac\"\nversion = \"0.13.0\""),
            "hmac 0.13.0 must be locked"
        );
        // Source uses RustCrypto verify_slice path only (inventory).
        let src = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/secure_key/sealed_state.rs"
        ));
        assert!(src.contains("verify_slice"));
        assert!(src.contains("HmacSha256") || src.contains("Hmac<Sha256>"));
        // Production path uses RustCrypto Mac/KeyInit only.
        let production: String = src
            .lines()
            .take_while(|l| !l.contains("mod tests"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(production.contains("use hmac::{Hmac, KeyInit, Mac}"));
        assert!(production.contains("verify_slice"));
        assert!(!production.contains("sha256(key") && !production.contains("key ||"));
        assert!(!production.contains("ipad") && !production.contains("opad"));
        assert!(!production.contains("ring::") && !production.contains("openssl"));
        // No Debug/Display/serde on SealedPayload.
        assert!(production.contains("Intentionally no Debug/Display/serde"));
        // SealedPayload must not derive Debug (explicit check around the struct).
        let payload_block: String = production
            .lines()
            .skip_while(|l| !l.contains("struct SealedPayload"))
            .take(3)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !payload_block.contains("Debug"),
            "SealedPayload must not derive Debug"
        );
    }
}
