//! Opaque 16-byte remote protocol identifiers and CanonicalU64DecimalStringV1.
//! Paired with packages/cockpit-protocol/src/remote-protocol-id.ts.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::marker::PhantomData;

pub const REMOTE_PROTOCOL_ID_BYTES: usize = 16;
pub const REMOTE_PROTOCOL_ID_B64URL_LEN: usize = 22;
pub const U64_MAX: u64 = u64::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteProtocolIdKind {
    Tenant,
    Account,
    Instance,
    Project,
    /// Ephemeral per-frame identifier (`RemoteTransportFrameV1.frameId`).
    Frame,
    /// Ephemeral per-transfer identifier (`RemoteBulk*.transferId`).
    Transfer,
}

impl RemoteProtocolIdKind {
    /// Stable snake_case spelling shared with the TypeScript mirror.
    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteProtocolIdKind::Tenant => "tenant",
            RemoteProtocolIdKind::Account => "account",
            RemoteProtocolIdKind::Instance => "instance",
            RemoteProtocolIdKind::Project => "project",
            RemoteProtocolIdKind::Frame => "frame",
            RemoteProtocolIdKind::Transfer => "transfer",
        }
    }
}

/// Marker ZSTs for nominal kind separation (sealed to the closed kind set).
///
/// `Frame` and `Transfer` are the ephemeral transport kinds added by
/// `remote-transport-logical-lanes`. They deliberately reuse this codec rather
/// than introducing a second 16-byte identifier encoding.
pub mod kind {
    /// Sealed: only the closed kind set implements this.
    pub trait ProtocolIdKind: sealed::Sealed + Copy + Send + Sync + 'static {
        const KIND: super::RemoteProtocolIdKind;
    }

    mod sealed {
        pub trait Sealed {}
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct Tenant;
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct Account;
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct Instance;
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct Project;
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct Frame;
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct Transfer;

    macro_rules! seal_kind {
        ($($ty:ident => $variant:ident),+ $(,)?) => {
            $(
                impl sealed::Sealed for $ty {}
                impl ProtocolIdKind for $ty {
                    const KIND: super::RemoteProtocolIdKind =
                        super::RemoteProtocolIdKind::$variant;
                }
            )+
        };
    }

    seal_kind! {
        Tenant => Tenant,
        Account => Account,
        Instance => Instance,
        Project => Project,
        Frame => Frame,
        Transfer => Transfer,
    }
}

/// Kind-branded 16-byte protocol id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RemoteProtocolId<K> {
    bytes: [u8; REMOTE_PROTOCOL_ID_BYTES],
    _kind: PhantomData<K>,
}

impl<K> RemoteProtocolId<K> {
    pub fn as_bytes(&self) -> &[u8; REMOTE_PROTOCOL_ID_BYTES] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RemoteProtocolIdError {
    #[error("{0}")]
    Invalid(String),
}

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

pub fn encode_protocol_id_base64url(bytes: &[u8]) -> Result<String, RemoteProtocolIdError> {
    if bytes.len() != REMOTE_PROTOCOL_ID_BYTES {
        return Err(RemoteProtocolIdError::Invalid(format!(
            "protocol id must be {REMOTE_PROTOCOL_ID_BYTES} bytes"
        )));
    }
    if is_all_zero(bytes) {
        return Err(RemoteProtocolIdError::Invalid(
            "all-zero protocol id rejected".into(),
        ));
    }
    let text = URL_SAFE_NO_PAD.encode(bytes);
    if text.len() != REMOTE_PROTOCOL_ID_B64URL_LEN || text.contains('=') {
        return Err(RemoteProtocolIdError::Invalid(
            "internal noncanonical protocol id encoding".into(),
        ));
    }
    Ok(text)
}

pub fn decode_protocol_id_base64url(text: &str) -> Result<[u8; 16], RemoteProtocolIdError> {
    if text.len() != REMOTE_PROTOCOL_ID_B64URL_LEN {
        return Err(RemoteProtocolIdError::Invalid(format!(
            "protocol id text must be {REMOTE_PROTOCOL_ID_B64URL_LEN} chars"
        )));
    }
    if text.contains('=')
        || text.contains('+')
        || text.contains('/')
        || text.chars().any(|c| c.is_whitespace())
    {
        return Err(RemoteProtocolIdError::Invalid(
            "protocol id text noncanonical base64url".into(),
        ));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(text.as_bytes())
        .map_err(|_| RemoteProtocolIdError::Invalid("protocol id text decode failed".into()))?;
    if decoded.len() != REMOTE_PROTOCOL_ID_BYTES {
        return Err(RemoteProtocolIdError::Invalid(
            "protocol id decoded length mismatch".into(),
        ));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&decoded);
    if is_all_zero(&out) {
        return Err(RemoteProtocolIdError::Invalid(
            "all-zero protocol id rejected".into(),
        ));
    }
    let re = encode_protocol_id_base64url(&out)?;
    if re != text {
        return Err(RemoteProtocolIdError::Invalid(
            "protocol id text noncanonical re-encoding".into(),
        ));
    }
    Ok(out)
}

/// Decode wire text into a kind-branded id (kind is compile-time; bytes validated).
pub fn decode_protocol_id_as_kind<K: kind::ProtocolIdKind>(
    text: &str,
) -> Result<RemoteProtocolId<K>, RemoteProtocolIdError> {
    let bytes = decode_protocol_id_base64url(text)?;
    Ok(RemoteProtocolId {
        bytes,
        _kind: PhantomData,
    })
}

pub fn tag_protocol_id_bytes<K: kind::ProtocolIdKind>(
    bytes: [u8; REMOTE_PROTOCOL_ID_BYTES],
) -> Result<RemoteProtocolId<K>, RemoteProtocolIdError> {
    if is_all_zero(&bytes) {
        return Err(RemoteProtocolIdError::Invalid(
            "all-zero protocol id rejected".into(),
        ));
    }
    Ok(RemoteProtocolId {
        bytes,
        _kind: PhantomData,
    })
}

impl<K: kind::ProtocolIdKind> RemoteProtocolId<K> {
    /// Canonical raw identifier bytes for binary protocol codecs.
    pub fn as_bytes(&self) -> &[u8; REMOTE_PROTOCOL_ID_BYTES] {
        &self.bytes
    }
}

/// JSON form of every kind-branded id is the 22-character unpadded base64url
/// spelling — the single identifier codec, with no per-kind mapping row.
impl<K: kind::ProtocolIdKind> serde::Serialize for RemoteProtocolId<K> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = encode_protocol_id_base64url(&self.bytes).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&text)
    }
}

impl<'de, K: kind::ProtocolIdKind> serde::Deserialize<'de> for RemoteProtocolId<K> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        decode_protocol_id_as_kind::<K>(&text).map_err(serde::de::Error::custom)
    }
}

/// Ephemeral 16-byte frame identifier carried raw in binary frames.
pub type RemoteFrameId = RemoteProtocolId<kind::Frame>;
/// Ephemeral 16-byte bulk-transfer identifier carried raw in binary frames.
pub type RemoteTransferId = RemoteProtocolId<kind::Transfer>;

/// Nominal CanonicalU64DecimalStringV1 wire type (never a JSON number).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalU64DecimalStringV1(String);

impl CanonicalU64DecimalStringV1 {
    pub fn parse(input: &str) -> Result<Self, RemoteProtocolIdError> {
        let v = parse_canonical_u64_decimal_string(input)?;
        Ok(Self(format_canonical_u64_decimal_string(v)))
    }

    pub fn from_u64(value: u64) -> Self {
        Self(format_canonical_u64_decimal_string(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn value(&self) -> u64 {
        parse_canonical_u64_decimal_string(&self.0).expect("canonical u64 invariant")
    }
}

impl serde::Serialize for CanonicalU64DecimalStringV1 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for CanonicalU64DecimalStringV1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// CanonicalU64DecimalStringV1 parser.
pub fn parse_canonical_u64_decimal_string(input: &str) -> Result<u64, RemoteProtocolIdError> {
    if input.is_empty() {
        return Err(RemoteProtocolIdError::Invalid(
            "u64 decimal spelling invalid".into(),
        ));
    }
    if input == "0" {
        return Ok(0);
    }
    if !input
        .as_bytes()
        .first()
        .is_some_and(|b| (b'1'..=b'9').contains(b))
    {
        return Err(RemoteProtocolIdError::Invalid(
            "u64 decimal spelling invalid".into(),
        ));
    }
    if input.len() > 20 || !input.bytes().all(|b| b.is_ascii_digit()) {
        return Err(RemoteProtocolIdError::Invalid(
            "u64 decimal spelling invalid".into(),
        ));
    }
    let v: u64 = input
        .parse()
        .map_err(|_| RemoteProtocolIdError::Invalid("u64 decimal overflow".into()))?;
    if v.to_string() != input {
        return Err(RemoteProtocolIdError::Invalid(
            "u64 decimal noncanonical".into(),
        ));
    }
    Ok(v)
}

pub fn format_canonical_u64_decimal_string(value: u64) -> String {
    value.to_string()
}

/// Network-byte-order u64 for binary protocols.
pub fn encode_u64_be(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

pub fn decode_u64_be(bytes: &[u8]) -> Result<u64, RemoteProtocolIdError> {
    if bytes.len() != 8 {
        return Err(RemoteProtocolIdError::Invalid(
            "u64be requires 8 bytes".into(),
        ));
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Vectors {
        protocol_id_bytes_hex: String,
        protocol_id_b64url: String,
        u64_boundaries: U64Boundaries,
    }

    #[derive(Debug, Deserialize)]
    struct U64Boundaries {
        #[serde(rename = "0")]
        zero: String,
        #[serde(rename = "1")]
        one: String,
        #[serde(rename = "2_53_minus_1")]
        two_53_minus_1: String,
        #[serde(rename = "2_53")]
        two_53: String,
        #[serde(rename = "2_53_plus_1")]
        two_53_plus_1: String,
        u64_max: String,
    }

    fn load_vectors() -> Vectors {
        let raw = include_str!(
            "../../../packages/cockpit-protocol/fixtures/remote-protocol-id-vectors.json"
        );
        serde_json::from_str(raw).expect("shared remote-protocol-id vectors")
    }

    #[test]
    fn remote_protocol_identifier_cross_language_vectors() {
        let vectors = load_vectors();
        let mut bytes = [0u8; 16];
        for (i, chunk) in vectors
            .protocol_id_bytes_hex
            .as_bytes()
            .chunks(2)
            .enumerate()
        {
            let hex = std::str::from_utf8(chunk).unwrap();
            bytes[i] = u8::from_str_radix(hex, 16).unwrap();
        }
        let text = encode_protocol_id_base64url(&bytes).unwrap();
        assert_eq!(text, vectors.protocol_id_b64url);
        assert_eq!(text.len(), REMOTE_PROTOCOL_ID_B64URL_LEN);
        assert!(!text.contains('='));
        let back = decode_protocol_id_base64url(&text).unwrap();
        assert_eq!(back, bytes);
        assert!(decode_protocol_id_base64url(&format!("{text}=")).is_err());
        assert!(encode_protocol_id_base64url(&[0u8; 16]).is_err());

        let tenant = tag_protocol_id_bytes::<kind::Tenant>(bytes).unwrap();
        let account = tag_protocol_id_bytes::<kind::Account>(bytes).unwrap();
        assert_eq!(tenant.as_bytes(), account.as_bytes());
        let _tenant2: RemoteProtocolId<kind::Tenant> = decode_protocol_id_as_kind(&text).unwrap();

        assert_eq!(
            parse_canonical_u64_decimal_string(&vectors.u64_boundaries.zero).unwrap(),
            0
        );
        assert_eq!(
            parse_canonical_u64_decimal_string(&vectors.u64_boundaries.one).unwrap(),
            1
        );
        assert_eq!(
            parse_canonical_u64_decimal_string(&vectors.u64_boundaries.two_53_minus_1).unwrap(),
            (1u64 << 53) - 1
        );
        assert_eq!(
            parse_canonical_u64_decimal_string(&vectors.u64_boundaries.two_53).unwrap(),
            1u64 << 53
        );
        assert_eq!(
            parse_canonical_u64_decimal_string(&vectors.u64_boundaries.two_53_plus_1).unwrap(),
            (1u64 << 53) + 1
        );
        assert_eq!(
            parse_canonical_u64_decimal_string(&vectors.u64_boundaries.u64_max).unwrap(),
            u64::MAX
        );

        for v in [0u64, 1, (1u64 << 53) + 1, u64::MAX] {
            assert_eq!(decode_u64_be(&encode_u64_be(v)).unwrap(), v);
        }

        let nominal =
            CanonicalU64DecimalStringV1::parse(&vectors.u64_boundaries.two_53_plus_1).unwrap();
        assert_eq!(nominal.value(), (1u64 << 53) + 1);
        let json = serde_json::to_string(&nominal).unwrap();
        assert_eq!(json, "\"9007199254740993\"");
        assert!(serde_json::from_str::<CanonicalU64DecimalStringV1>("9007199254740993").is_err());
        let back: CanonicalU64DecimalStringV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(back, nominal);
    }

    #[test]
    fn remote_u64_decimal_string_boundaries() {
        let cases = [
            0u64,
            1,
            (1u64 << 53) - 1,
            1u64 << 53,
            (1u64 << 53) + 1,
            u64::MAX,
        ];
        for v in cases {
            let s = format_canonical_u64_decimal_string(v);
            assert_eq!(parse_canonical_u64_decimal_string(&s).unwrap(), v);
        }
        for bad in [
            "",
            "+1",
            "-1",
            "01",
            "1.0",
            "1e2",
            " 1",
            "18446744073709551616",
        ] {
            assert!(parse_canonical_u64_decimal_string(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn remote_protocol_identifier_grounding_fails_first() {
        let cuid = b"clxxxxxxxxxxxxxxxxxxxx";
        assert_ne!(cuid.len(), REMOTE_PROTOCOL_ID_BYTES);
        assert!(decode_protocol_id_base64url(std::str::from_utf8(cuid).unwrap()).is_err());
    }
}
