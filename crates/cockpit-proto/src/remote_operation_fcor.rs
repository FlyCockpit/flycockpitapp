//! Canonical outer request framing for durable remote-operation identity.

use anyhow::{Result, bail, ensure};
use sha2::{Digest, Sha256};

pub const FCOR_MAGIC: [u8; 4] = *b"FCOR";
pub const FCOR_SCHEMA_VERSION: u8 = 1;

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
    let mut out = Vec::new();
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
