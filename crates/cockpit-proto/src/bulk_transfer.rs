//! Transport-neutral staged bulk-transfer contract.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

pub const BULK_TRANSFER_ID_BYTES: usize = 16;
pub const MAX_BULK_CHUNK_PAYLOAD_BYTES: usize = 524_255;
pub const MAX_TRANSFER_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BulkTransferId([u8; BULK_TRANSFER_ID_BYTES]);

impl BulkTransferId {
    pub fn from_bytes(bytes: [u8; BULK_TRANSFER_ID_BYTES]) -> Result<Self, String> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err("all-zero bulk transfer id rejected".into());
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; BULK_TRANSFER_ID_BYTES] {
        &self.0
    }
}

impl Serialize for BulkTransferId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for BulkTransferId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() != 22 || text.contains('=') {
            return Err(serde::de::Error::custom(
                "bulk transfer id is not canonical",
            ));
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(text.as_bytes())
            .map_err(|_| serde::de::Error::custom("bulk transfer id decode failed"))?;
        let bytes: [u8; BULK_TRANSFER_ID_BYTES] = decoded
            .try_into()
            .map_err(|_| serde::de::Error::custom("bulk transfer id length mismatch"))?;
        let id = Self::from_bytes(bytes).map_err(serde::de::Error::custom)?;
        if URL_SAFE_NO_PAD.encode(id.0) != text {
            return Err(serde::de::Error::custom(
                "bulk transfer id is not canonical",
            ));
        }
        Ok(id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BulkMimeClass {
    Image,
    ImageSet,
    Archive,
    Export,
    Opaque,
    RedactedExport,
}

impl BulkMimeClass {
    pub const fn max_total_length(self) -> u64 {
        match self {
            Self::Image => crate::MAX_SINGLE_IMAGE_BYTES as u64,
            Self::ImageSet => crate::MAX_TOTAL_IMAGE_BYTES as u64,
            Self::Archive | Self::Export | Self::Opaque | Self::RedactedExport => {
                MAX_TRANSFER_BYTES
            }
        }
    }
}

#[derive(Deserialize)]
struct BulkTransferRefWire {
    transfer_id: BulkTransferId,
    total_length: crate::wire_scalar::CanonicalU64DecimalStringV1,
    #[serde(with = "hex32")]
    sha256: [u8; 32],
    mime_class: BulkMimeClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "BulkTransferRefWire")]
pub struct BulkTransferRef {
    pub transfer_id: BulkTransferId,
    pub total_length: crate::wire_scalar::CanonicalU64DecimalStringV1,
    #[serde(with = "hex32")]
    pub sha256: [u8; 32],
    pub mime_class: BulkMimeClass,
}

impl TryFrom<BulkTransferRefWire> for BulkTransferRef {
    type Error = String;
    fn try_from(value: BulkTransferRefWire) -> Result<Self, Self::Error> {
        Self::new(
            value.transfer_id,
            value.total_length.value(),
            value.sha256,
            value.mime_class,
        )
    }
}

impl BulkTransferRef {
    pub fn new(
        transfer_id: BulkTransferId,
        total_length: u64,
        sha256: [u8; 32],
        mime_class: BulkMimeClass,
    ) -> Result<Self, String> {
        if total_length > mime_class.max_total_length() {
            return Err("bulk transfer exceeds its MIME-class limit".into());
        }
        Ok(Self {
            transfer_id,
            total_length: crate::wire_scalar::CanonicalU64DecimalStringV1::from_u64(total_length),
            sha256,
            mime_class,
        })
    }

    pub fn total_length_value(&self) -> u64 {
        self.total_length.value()
    }
}

mod hex32 {
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        let text: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        serializer.serialize_str(&text)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() != 64
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(serde::de::Error::custom(
                "SHA-256 must be lowercase hexadecimal",
            ));
        }
        let mut bytes = [0_u8; 32];
        for (index, output) in bytes.iter_mut().enumerate() {
            *output = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
                .map_err(|_| serde::de::Error::custom("invalid SHA-256"))?;
        }
        Ok(bytes)
    }
}

pub fn transfer_id_from_bytes(bytes: [u8; 16]) -> Result<BulkTransferId, String> {
    BulkTransferId::from_bytes(bytes)
}
