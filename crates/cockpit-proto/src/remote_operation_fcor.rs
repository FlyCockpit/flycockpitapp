//! Canonical outer request framing for durable remote-operation identity.

use anyhow::{Result, bail, ensure};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

pub const FCOR_MAGIC: [u8; 4] = *b"FCOR";
pub const FCOR_SCHEMA_VERSION: u8 = 1;
pub const MAX_FCOR_V1_BYTES: u64 = u32::MAX as u64;
pub const FCM2_MAGIC: [u8; 4] = *b"FCM2";
pub const MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES: usize = 2_631_500;

/// Foundation-owned semantic validation seam for an opaque canonical codec.
/// The ledger never parses or re-encodes the returned bytes.
pub trait OpaqueCanonicalParamsDecoder {
    fn owner(&self) -> &'static str;
    fn validate(&self, bytes: &[u8]) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpaqueCanonicalParamsRegistrationV1 {
    pub request_kind: &'static str,
    pub magic: [u8; 4],
    pub maximum_bytes: usize,
    pub owner: &'static str,
}

pub const SEND_USER_MESSAGE_V2_REGISTRATION: OpaqueCanonicalParamsRegistrationV1 =
    OpaqueCanonicalParamsRegistrationV1 {
        request_kind: "send_user_message",
        magic: FCM2_MAGIC,
        maximum_bytes: MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES,
        owner: "message-attachment-protocol-foundation",
    };

pub fn validate_registered_opaque_params(
    registration: OpaqueCanonicalParamsRegistrationV1,
    bytes: &[u8],
    decoder: &dyn OpaqueCanonicalParamsDecoder,
) -> Result<()> {
    ensure!(
        registration == SEND_USER_MESSAGE_V2_REGISTRATION,
        "unknown opaque canonical parameter registration"
    );
    ensure!(
        bytes.len() <= registration.maximum_bytes,
        "opaque params exceed registered maximum"
    );
    ensure!(
        bytes.starts_with(&registration.magic),
        "opaque params have wrong magic"
    );
    ensure!(
        decoder.owner() == registration.owner,
        "opaque decoder owner mismatch"
    );
    decoder.validate(bytes)
}

pub fn checked_fcor_v1_size(
    request_kind_len: u64,
    resource_value_lengths: impl IntoIterator<Item = u64>,
    params_len: u64,
) -> Result<u64> {
    ensure!(
        (1..=u8::MAX as u64).contains(&request_kind_len),
        "invalid request kind length"
    );
    ensure!(params_len <= u32::MAX as u64, "params exceed u32 length");
    let mut total = 4_u64
        .checked_add(1)
        .and_then(|v| v.checked_add(1))
        .and_then(|v| v.checked_add(request_kind_len))
        .and_then(|v| v.checked_add(2))
        .and_then(|v| v.checked_add(4))
        .and_then(|v| v.checked_add(params_len))
        .ok_or_else(|| anyhow::anyhow!("FCOR size overflow"))?;
    let mut count = 0_u64;
    for length in resource_value_lengths {
        ensure!(length <= u32::MAX as u64, "resource exceeds u32 length");
        count = count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("resource count overflow"))?;
        ensure!(count <= u16::MAX as u64, "too many resources");
        total = total
            .checked_add(5)
            .and_then(|v| v.checked_add(length))
            .ok_or_else(|| anyhow::anyhow!("FCOR size overflow"))?;
    }
    ensure!(total <= MAX_FCOR_V1_BYTES, "FCOR exceeds maximum size");
    Ok(total)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CanonicalParamsV1(Vec<u8>);

impl CanonicalParamsV1 {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
    pub fn push_u8(&mut self, value: u8) {
        self.0.push(value);
    }
    pub fn push_bool(&mut self, value: bool) {
        self.push_u8(u8::from(value));
    }
    pub fn push_u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    pub fn push_u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    pub fn push_u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    pub fn push_i64(&mut self, value: i64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    pub fn push_uuid(&mut self, value: Uuid) {
        self.0.extend_from_slice(value.as_bytes());
    }

    pub fn push_bytes(&mut self, value: &[u8]) -> Result<()> {
        self.push_u32(u32::try_from(value.len())?);
        self.0.extend_from_slice(value);
        Ok(())
    }

    pub fn push_string(&mut self, value: &str) -> Result<()> {
        ensure!(!value.contains('\0'), "canonical string contains NUL");
        ensure!(value.nfc().eq(value.chars()), "canonical string is not NFC");
        self.push_bytes(value.as_bytes())
    }

    pub fn push_optional<T>(
        &mut self,
        value: Option<&T>,
        encode: impl FnOnce(&mut Self, &T) -> Result<()>,
    ) -> Result<()> {
        match value {
            Some(value) => {
                let mut nested = Self::new();
                encode(&mut nested, value)?;
                self.push_u8(1);
                self.0.extend(nested.0);
                Ok(())
            }
            None => {
                self.push_u8(0);
                Ok(())
            }
        }
    }

    pub fn push_list<'a, T: 'a>(
        &mut self,
        values: impl IntoIterator<Item = &'a T>,
        mut encode: impl FnMut(&mut Self, &T) -> Result<()>,
    ) -> Result<()> {
        let mut items = Vec::new();
        for value in values {
            let mut item = Self::new();
            encode(&mut item, value)?;
            items.push(item.0);
        }
        self.push_u32(u32::try_from(items.len())?);
        for item in items {
            self.0.extend(item);
        }
        Ok(())
    }

    pub fn push_string_map<'a>(
        &mut self,
        entries: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<()> {
        let mut encoded = Vec::new();
        for (key, value) in entries {
            ensure!(!key.contains('\0'), "canonical map key contains NUL");
            let normalized_key = key.nfc().collect::<String>();
            let mut key_bytes = Self::new();
            key_bytes.push_string(&normalized_key)?;
            let mut value_bytes = Self::new();
            value_bytes.push_string(value)?;
            encoded.push((normalized_key, key_bytes.0, value_bytes.0));
        }
        encoded.sort_by(|left, right| left.1.cmp(&right.1));
        ensure!(
            encoded.windows(2).all(|pair| pair[0].0 != pair[1].0),
            "duplicate NFC map key"
        );
        self.push_u32(u32::try_from(encoded.len())?);
        for (_, key, value) in encoded {
            self.0.extend(key);
            self.0.extend(value);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RemoteOperationResourceKind {
    SessionUuid = 1,
    ProjectId = 2,
    ProjectRoot = 3,
    FilePath = 4,
    TerminalUuid = 5,
    UploadUuid = 6,
    InterruptUuid = 7,
    SchedulerId = 8,
    QueueUuid = 9,
    ProviderModel = 10,
    DaemonGlobal = 11,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteOperationResource<'a> {
    pub kind: RemoteOperationResourceKind,
    pub value: &'a [u8],
}

fn validate_stable_resource_shape(kind: u8, value: &[u8]) -> Result<()> {
    match kind {
        1 | 5 | 6 | 7 | 9 => ensure!(value.len() == 16, "UUID resource must be 16 bytes"),
        11 => ensure!(value.is_empty(), "daemon_global resource must be empty"),
        // Text/path canonicalization is descriptor-specific because paths must
        // first pass through the daemon authorization resolver.
        2 | 3 | 4 | 8 | 10 => {}
        _ => bail!("unknown resource kind"),
    }
    Ok(())
}

pub fn encode_fcor_v1(
    request_kind: &str,
    resources: &[RemoteOperationResource<'_>],
    canonical_params: &[u8],
) -> Result<Vec<u8>> {
    let kind = request_kind.as_bytes();
    ensure!(
        !kind.is_empty() && kind.len() <= u8::MAX as usize,
        "invalid request kind length"
    );
    ensure!(
        kind.iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_'),
        "request kind must be lowercase ASCII"
    );
    let resource_count = u16::try_from(resources.len())?;
    let params_len = u32::try_from(canonical_params.len())?;
    let total = checked_fcor_v1_size(
        kind.len() as u64,
        resources.iter().map(|resource| resource.value.len() as u64),
        canonical_params.len() as u64,
    )?;
    let mut out = Vec::with_capacity(usize::try_from(total)?);
    out.extend_from_slice(&FCOR_MAGIC);
    out.push(FCOR_SCHEMA_VERSION);
    out.push(kind.len() as u8);
    out.extend_from_slice(kind);
    out.extend_from_slice(&resource_count.to_be_bytes());
    for resource in resources {
        validate_stable_resource_shape(resource.kind as u8, resource.value)?;
        let value_len = u32::try_from(resource.value.len())?;
        out.push(resource.kind as u8);
        out.extend_from_slice(&value_len.to_be_bytes());
        out.extend_from_slice(resource.value);
    }
    out.extend_from_slice(&params_len.to_be_bytes());
    out.extend_from_slice(canonical_params);
    Ok(out)
}

pub fn hash_fcor_v1(bytes: &[u8]) -> Result<[u8; 32]> {
    validate_fcor_v1(bytes)?;
    Ok(Sha256::digest(bytes).into())
}

pub fn validate_fcor_v1(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() >= 12 && bytes[..4] == FCOR_MAGIC,
        "invalid FCOR magic"
    );
    ensure!(bytes[4] == FCOR_SCHEMA_VERSION, "unsupported FCOR schema");
    let mut offset = 5;
    let kind_len = bytes[offset] as usize;
    offset += 1;
    ensure!(
        kind_len > 0 && offset + kind_len + 2 <= bytes.len(),
        "invalid request kind length"
    );
    let kind = &bytes[offset..offset + kind_len];
    ensure!(
        kind.iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_'),
        "invalid request kind"
    );
    offset += kind_len;
    let resource_count = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;
    for _ in 0..resource_count {
        ensure!(offset + 5 <= bytes.len(), "truncated resource");
        ensure!((1..=11).contains(&bytes[offset]), "unknown resource kind");
        let resource_kind = bytes[offset];
        offset += 1;
        let len = u32::from_be_bytes(bytes[offset..offset + 4].try_into()?) as usize;
        offset += 4;
        offset = offset
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("resource length overflow"))?;
        ensure!(offset <= bytes.len(), "truncated resource value");
        validate_stable_resource_shape(resource_kind, &bytes[offset - len..offset])?;
    }
    ensure!(offset + 4 <= bytes.len(), "missing params length");
    let len = u32::from_be_bytes(bytes[offset..offset + 4].try_into()?) as usize;
    offset += 4;
    ensure!(
        offset.checked_add(len) == Some(bytes.len()),
        "truncated or trailing FCOR bytes"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fcor_cross_language_vector_is_exact() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../packages/cockpit-protocol/fixtures/remote-operation-fcor-v1.json"
        ))
        .unwrap();
        let bytes = encode_fcor_v1(
            fixture["requestKind"].as_str().unwrap(),
            &[RemoteOperationResource {
                kind: RemoteOperationResourceKind::DaemonGlobal,
                value: &[],
            }],
            &[],
        )
        .unwrap();
        assert_eq!(hex(&bytes), fixture["canonicalHex"].as_str().unwrap());
        assert_eq!(
            hex(&hash_fcor_v1(&bytes).unwrap()),
            fixture["sha256Hex"].as_str().unwrap()
        );
        assert!(encode_fcor_v1("DaemonStatus", &[], &[]).is_err());
        for malformed in fixture["malformed"].as_array().unwrap() {
            let mut candidate = bytes.clone();
            if let Some(replacement) = malformed["replaceByte"].as_array() {
                candidate[replacement[0].as_u64().unwrap() as usize] =
                    replacement[1].as_u64().unwrap() as u8;
            }
            if let Some(truncate_by) = malformed["truncateBy"].as_u64() {
                candidate.truncate(candidate.len() - truncate_by as usize);
            }
            if let Some(append_hex) = malformed["appendHex"].as_str() {
                candidate.extend_from_slice(&decode_hex(append_hex));
            }
            assert!(
                validate_fcor_v1(&candidate).is_err(),
                "malformed vector unexpectedly valid: {}",
                malformed["name"]
            );
        }
        let rich = &fixture["richPositive"];
        let rich_values: Vec<Vec<u8>> = rich["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|resource| decode_hex(resource["valueHex"].as_str().unwrap()))
            .collect();
        let rich_resources: Vec<_> = rich["resources"]
            .as_array()
            .unwrap()
            .iter()
            .zip(&rich_values)
            .map(|(resource, value)| RemoteOperationResource {
                kind: match resource["kind"].as_str().unwrap() {
                    "project_root" => RemoteOperationResourceKind::ProjectRoot,
                    "file_path" => RemoteOperationResourceKind::FilePath,
                    other => panic!("unexpected fixture kind {other}"),
                },
                value,
            })
            .collect();
        let rich_bytes = encode_fcor_v1(
            rich["requestKind"].as_str().unwrap(),
            &rich_resources,
            &decode_hex(rich["paramsHex"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(hex(&rich_bytes), rich["canonicalHex"].as_str().unwrap());
        assert_eq!(
            hex(&hash_fcor_v1(&rich_bytes).unwrap()),
            rich["sha256Hex"].as_str().unwrap()
        );
        for boundary in fixture["sizeCases"].as_array().unwrap() {
            let result = checked_fcor_v1_size(
                boundary["kindLength"].as_u64().unwrap(),
                boundary["resourceLengths"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_u64().unwrap()),
                boundary["paramsLength"].as_u64().unwrap(),
            );
            assert_eq!(result.is_ok(), boundary["valid"].as_bool().unwrap());
        }
        for shape in fixture["shapeCases"].as_array().unwrap() {
            let value = vec![0; shape["valueLength"].as_u64().unwrap() as usize];
            let kind = match shape["kind"].as_str().unwrap() {
                "daemon_global" => RemoteOperationResourceKind::DaemonGlobal,
                "session_uuid" => RemoteOperationResourceKind::SessionUuid,
                other => panic!("unexpected fixture kind {other}"),
            };
            let result = encode_fcor_v1(
                "status",
                &[RemoteOperationResource {
                    kind,
                    value: &value,
                }],
                &[],
            );
            assert_eq!(result.is_ok(), shape["valid"].as_bool().unwrap());
        }
        let mut primitive = CanonicalParamsV1::new();
        primitive.push_u8(0xff);
        primitive.push_bool(true);
        primitive.push_u16(0x1234);
        primitive.push_u32(0x01020304);
        primitive.push_u64(0x0102030405060708);
        primitive.push_i64(-2);
        primitive.push_uuid(Uuid::from_bytes(core::array::from_fn(|index| index as u8)));
        assert_eq!(
            hex(&primitive.into_bytes()),
            fixture["canonicalParams"]["primitiveHex"].as_str().unwrap()
        );
        let mut map = CanonicalParamsV1::new();
        map.push_string_map([("b", "y"), ("a", "x")]).unwrap();
        assert_eq!(
            hex(&map.into_bytes()),
            fixture["canonicalParams"]["sortedStringMapHex"]
                .as_str()
                .unwrap()
        );
        for invalid in fixture["invalidCanonicalCases"].as_array().unwrap() {
            let rejected = match invalid["kind"].as_str().unwrap() {
                "string" => CanonicalParamsV1::new()
                    .push_string(invalid["value"].as_str().unwrap())
                    .is_err(),
                "utf16_string" => {
                    let units: Vec<u16> = invalid["codeUnits"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|unit| unit.as_u64().unwrap() as u16)
                        .collect();
                    String::from_utf16(&units).is_err()
                }
                "string_map" => {
                    let entries: Vec<(&str, &str)> = invalid["entries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|entry| {
                            let pair = entry.as_array().unwrap();
                            (pair[0].as_str().unwrap(), pair[1].as_str().unwrap())
                        })
                        .collect();
                    CanonicalParamsV1::new().push_string_map(entries).is_err()
                }
                other => panic!("unknown invalid canonical case {other}"),
            };
            assert!(rejected, "{}", invalid["errorClass"]);
        }
        let boundary = |encode: fn(&mut CanonicalParamsV1) -> Result<()>| {
            let mut params = CanonicalParamsV1::new();
            encode(&mut params).unwrap();
            hex(&params.into_bytes())
        };
        assert_eq!(
            boundary(|p| {
                p.push_u64(u64::MAX);
                Ok(())
            }),
            fixture["canonicalParams"]["u64MaxHex"]
        );
        assert_eq!(
            boundary(|p| {
                p.push_i64(i64::MIN);
                Ok(())
            }),
            fixture["canonicalParams"]["i64MinHex"]
        );
        assert_eq!(
            boundary(|p| {
                p.push_i64(i64::MAX);
                Ok(())
            }),
            fixture["canonicalParams"]["i64MaxHex"]
        );
        assert_eq!(
            boundary(|p| p.push_optional::<u8>(None, |_, _| Ok(()))),
            fixture["canonicalParams"]["optionNoneHex"]
        );
        assert_eq!(
            boundary(|p| p.push_optional(Some(&0x1234_u16), |nested, value| {
                nested.push_u16(*value);
                Ok(())
            })),
            fixture["canonicalParams"]["optionSomeU16Hex"]
        );
        assert_eq!(
            boundary(|p| p.push_bytes(&[])),
            fixture["canonicalParams"]["emptyBytesHex"]
        );
        assert_eq!(
            boundary(|p| p.push_string("é")),
            fixture["canonicalParams"]["composedStringHex"]
        );
        assert_eq!(
            boundary(|p| p.push_string_map([("aa", "y"), ("b", "x")])),
            fixture["canonicalParams"]["encodedLengthSortedMapHex"]
        );
        let mut rollback = CanonicalParamsV1::new();
        assert!(
            rollback
                .push_optional(Some(&1_u8), |nested, _| {
                    nested.push_u8(7);
                    bail!("fail")
                })
                .is_err()
        );
        assert!(rollback.into_bytes().is_empty());
        for item in fixture["primitiveBoundaryCases"].as_array().unwrap() {
            let value = item["value"].as_str().unwrap();
            let mut params = CanonicalParamsV1::new();
            let result = match item["codec"].as_str().unwrap() {
                "u8" => value.parse::<u8>().map(|value| params.push_u8(value)),
                "u16" => value.parse::<u16>().map(|value| params.push_u16(value)),
                "u32" => value.parse::<u32>().map(|value| params.push_u32(value)),
                "u64" => value.parse::<u64>().map(|value| params.push_u64(value)),
                other => panic!("unknown primitive codec {other}"),
            };
            assert_eq!(result.is_ok(), item["valid"].as_bool().unwrap());
            if result.is_ok() {
                assert_eq!(hex(&params.into_bytes()), item["hex"].as_str().unwrap());
            }
        }
        assert_eq!(
            boundary(|p| {
                p.push_bool(false);
                Ok(())
            }),
            fixture["collectionCases"]["boolFalseHex"]
        );
        assert_eq!(
            boundary(|p| {
                p.push_bool(true);
                Ok(())
            }),
            fixture["collectionCases"]["boolTrueHex"]
        );
        assert_eq!(
            boundary(|p| p.push_bytes(&[0, 255])),
            fixture["collectionCases"]["nonemptyBytesHex"]
        );
        assert_eq!(
            boundary(|p| p.push_string("a")),
            fixture["collectionCases"]["nonemptyStringHex"]
        );
        assert_eq!(
            boundary(|p| p.push_string_map([])),
            fixture["collectionCases"]["emptyMapHex"]
        );
        assert_eq!(
            boundary(|p| p.push_string_map([("a", "x")])),
            fixture["collectionCases"]["singleMapHex"]
        );
        assert_eq!(
            boundary(|p| p.push_list(std::iter::empty::<&u8>(), |_, _| Ok(()))),
            fixture["collectionCases"]["emptyListHex"]
        );
        assert_eq!(
            boundary(|p| p.push_list([1_u16, 258].iter(), |item, value| {
                item.push_u16(*value);
                Ok(())
            })),
            fixture["collectionCases"]["u16ListHex"]
        );
        let mut list_rollback = CanonicalParamsV1::new();
        assert!(
            list_rollback
                .push_list([1_u8].iter(), |item, _| {
                    item.push_u8(7);
                    bail!("fail")
                })
                .is_err()
        );
        assert!(list_rollback.into_bytes().is_empty());

        struct FoundationDecoder;
        impl OpaqueCanonicalParamsDecoder for FoundationDecoder {
            fn owner(&self) -> &'static str {
                "message-attachment-protocol-foundation"
            }
            fn validate(&self, bytes: &[u8]) -> Result<()> {
                ensure!(bytes == b"FCM2foundation-owned", "semantic rejection");
                Ok(())
            }
        }
        let opaque = b"FCM2foundation-owned";
        validate_registered_opaque_params(
            SEND_USER_MESSAGE_V2_REGISTRATION,
            opaque,
            &FoundationDecoder,
        )
        .unwrap();
        let fcor = encode_fcor_v1("send_user_message", &[], opaque).unwrap();
        assert!(
            fcor.ends_with(opaque),
            "ledger must embed FCM2 byte-identically"
        );
        assert!(
            validate_registered_opaque_params(
                OpaqueCanonicalParamsRegistrationV1 {
                    request_kind: "other",
                    ..SEND_USER_MESSAGE_V2_REGISTRATION
                },
                opaque,
                &FoundationDecoder,
            )
            .is_err()
        );
        struct RejectingFoundationDecoder;
        impl OpaqueCanonicalParamsDecoder for RejectingFoundationDecoder {
            fn owner(&self) -> &'static str {
                "message-attachment-protocol-foundation"
            }
            fn validate(&self, _bytes: &[u8]) -> Result<()> {
                bail!("semantic rejection")
            }
        }
        assert!(
            validate_registered_opaque_params(
                SEND_USER_MESSAGE_V2_REGISTRATION,
                opaque,
                &RejectingFoundationDecoder,
            )
            .is_err()
        );
        assert!(
            validate_registered_opaque_params(
                SEND_USER_MESSAGE_V2_REGISTRATION,
                b"BAD!foundation-owned",
                &FoundationDecoder,
            )
            .is_err()
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn decode_hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
}
