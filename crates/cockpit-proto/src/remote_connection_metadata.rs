//! Privacy-minimal remote connection metadata retention — closed v1 buckets,
//! pseudonym schemas, and classification guard.
//!
//! @see prompts/flycockpitapp/ready/remote-connection-metadata-retention.md
//!
//! This module defines the closed enums, bucket boundary functions, pseudonym
//! framing schemas, and the forbidden-field classification guard for the
//! pseudonymous connection-metadata ledger. It never persists raw IP,
//! candidate, SDP, credential, key body, content, or transcript.

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Closed v1 enums.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceTier {
    PublicSaas = 1,
    Enterprise = 2,
}

impl ServiceTier {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::PublicSaas),
            2 => Some(Self::Enterprise),
            _ => None,
        }
    }
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Webrtc = 1,
    WebsocketData = 2,
}

impl Transport {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Webrtc),
            2 => Some(Self::WebsocketData),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteClass {
    Direct = 1,
    Turn = 2,
    WebsocketGateway = 3,
}

impl RouteClass {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Direct),
            2 => Some(Self::Turn),
            3 => Some(Self::WebsocketGateway),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Connected = 1,
    Rejected = 2,
    Cancelled = 3,
    Superseded = 4,
    Failed = 5,
    Revoked = 6,
    Expired = 7,
}

impl Outcome {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Connected),
            2 => Some(Self::Rejected),
            3 => Some(Self::Cancelled),
            4 => Some(Self::Superseded),
            5 => Some(Self::Failed),
            6 => Some(Self::Revoked),
            7 => Some(Self::Expired),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    None = 0,
    Policy = 1,
    Authentication = 2,
    Authorization = 3,
    Dependency = 4,
    Network = 5,
    Quota = 6,
    Protocol = 7,
    User = 8,
    Revocation = 9,
    Timeout = 10,
    Internal = 11,
}

impl Reason {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Policy),
            2 => Some(Self::Authentication),
            3 => Some(Self::Authorization),
            4 => Some(Self::Dependency),
            5 => Some(Self::Network),
            6 => Some(Self::Quota),
            7 => Some(Self::Protocol),
            8 => Some(Self::User),
            9 => Some(Self::Revocation),
            10 => Some(Self::Timeout),
            11 => Some(Self::Internal),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyClass {
    OriginProtected = 1,
    OsProtected = 2,
    HardwareOrExternal = 3,
}

impl CustodyClass {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::OriginProtected),
            2 => Some(Self::OsProtected),
            3 => Some(Self::HardwareOrExternal),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    Unknown = 0,
    Local = 1,
    NorthAmerica = 2,
    SouthAmerica = 3,
    Europe = 4,
    Africa = 5,
    MiddleEast = 6,
    AsiaPacific = 7,
    Oceania = 8,
}

impl Region {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Unknown),
            1 => Some(Self::Local),
            2 => Some(Self::NorthAmerica),
            3 => Some(Self::SouthAmerica),
            4 => Some(Self::Europe),
            5 => Some(Self::Africa),
            6 => Some(Self::MiddleEast),
            7 => Some(Self::AsiaPacific),
            8 => Some(Self::Oceania),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurationBucket {
    Lt5s = 1,
    Sec5Lt30s = 2,
    Sec30Lt2m = 3,
    Min2Lt10m = 4,
    Min10Lt1h = 5,
    Gte1h = 6,
}

impl DurationBucket {
    pub fn from_seconds(seconds: u64) -> Self {
        if seconds < 5 {
            Self::Lt5s
        } else if seconds < 30 {
            Self::Sec5Lt30s
        } else if seconds < 120 {
            Self::Sec30Lt2m
        } else if seconds < 600 {
            Self::Min2Lt10m
        } else if seconds < 3600 {
            Self::Min10Lt1h
        } else {
            Self::Gte1h
        }
    }
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BytesBucket {
    Zero = 0,
    OneBLt64Kib = 1,
    Kib64Lt1Mib = 2,
    Mib1Lt16Mib = 3,
    Mib16Lt256Mib = 4,
    Kib256Lt1Gib = 5,
    Gte1Gib = 6,
}

impl BytesBucket {
    pub fn from_bytes(bytes: u64) -> Self {
        if bytes == 0 {
            Self::Zero
        } else if bytes < 65536 {
            Self::OneBLt64Kib
        } else if bytes < 1_048_576 {
            Self::Kib64Lt1Mib
        } else if bytes < 16_777_216 {
            Self::Mib1Lt16Mib
        } else if bytes < 268_435_456 {
            Self::Mib16Lt256Mib
        } else if bytes < 1_073_741_824 {
            Self::Kib256Lt1Gib
        } else {
            Self::Gte1Gib
        }
    }
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// Retention bounds.
// ---------------------------------------------------------------------------

pub const DEFAULT_RETENTION_DAYS: u32 = 30;
pub const MIN_RETENTION_DAYS: u32 = 0;
pub const MAX_RETENTION_DAYS: u32 = 365;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetadataError {
    #[error("retention days must be integer 0..365")]
    InvalidRetention,
    #[error("epoch seconds must be nonnegative")]
    InvalidEpoch,
    #[error("unknown pseudonym domain")]
    UnknownDomain,
    #[error("exactly one component required")]
    ComponentCount,
    #[error("domain-component kind mismatch")]
    DomainComponentMismatch,
    #[error("component bytes must be nonzero 16 bytes")]
    InvalidComponentBytes,
    #[error("digest must be 32 bytes")]
    InvalidDigest,
    #[error("pseudonym must be 16 bytes")]
    InvalidPseudonym,
    #[error("unknown enum discriminant")]
    UnknownDiscriminant,
}

pub fn validate_retention_days(days: i64) -> Result<u32, MetadataError> {
    if !(0..=365).contains(&days) {
        return Err(MetadataError::InvalidRetention);
    }
    Ok(days as u32)
}

/// `timeBucket = floor(epochSeconds / 3600) * 3600`.
pub fn time_bucket(epoch_seconds: i64) -> Result<i64, MetadataError> {
    if epoch_seconds < 0 {
        return Err(MetadataError::InvalidEpoch);
    }
    Ok((epoch_seconds / 3600) * 3600)
}

// ---------------------------------------------------------------------------
// Aggregate cell tuple — canonical 7-discriminant fixed-width.
// ---------------------------------------------------------------------------

pub fn cell_tuple(
    tier: ServiceTier,
    region: Region,
    route: RouteClass,
    outcome: Outcome,
    ingress: BytesBucket,
    egress: BytesBucket,
    duration: DurationBucket,
) -> [u8; 7] {
    [
        tier.as_u8(),
        region as u8,
        route as u8,
        outcome as u8,
        ingress.as_u8(),
        egress.as_u8(),
        duration.as_u8(),
    ]
}

// ---------------------------------------------------------------------------
// Pseudonym schemas — five literal and exhaustive domains.
// ---------------------------------------------------------------------------

pub const DOMAIN_TENANT: &str = "flycockpit.remote.metadata.tenant.v1";
pub const DOMAIN_ACCOUNT: &str = "flycockpit.remote.metadata.account.v1";
pub const DOMAIN_DEVICE: &str = "flycockpit.remote.metadata.device.v1";
pub const DOMAIN_INSTANCE: &str = "flycockpit.remote.metadata.instance.v1";
pub const DOMAIN_ATTEMPT: &str = "flycockpit.remote.metadata.attempt.v1";

pub const HKDF_SALT_DOMAIN: &str = "flycockpit.remote.metadata.hkdf.salt.v1";
pub const TENANT_KEY_INFO_DOMAIN: &str = "flycockpit.remote.metadata.tenant-key.v1";
pub const CARDINALITY_DOMAIN: &str = "flycockpit.remote.metadata.cardinality.v1";

pub const COMPONENT_KIND_TENANT: u8 = 1;
pub const COMPONENT_KIND_ACCOUNT: u8 = 2;
pub const COMPONENT_KIND_DEVICE: u8 = 3;
pub const COMPONENT_KIND_INSTANCE: u8 = 4;
pub const COMPONENT_KIND_ATTEMPT: u8 = 5;

fn required_kind_for_domain(domain: &str) -> Option<u8> {
    match domain {
        DOMAIN_TENANT => Some(COMPONENT_KIND_TENANT),
        DOMAIN_ACCOUNT => Some(COMPONENT_KIND_ACCOUNT),
        DOMAIN_DEVICE => Some(COMPONENT_KIND_DEVICE),
        DOMAIN_INSTANCE => Some(COMPONENT_KIND_INSTANCE),
        DOMAIN_ATTEMPT => Some(COMPONENT_KIND_ATTEMPT),
        _ => None,
    }
}

fn nonzero_16(bytes: &[u8; 16]) -> Result<(), MetadataError> {
    if bytes.iter().all(|&b| b == 0) {
        return Err(MetadataError::InvalidComponentBytes);
    }
    Ok(())
}

/// Builds the canonical HMAC message for a pseudonym schema:
/// `domainUtf8 | 0x00 | componentCount:u8 | components`.
/// Each component is `kind:u8 | length:u16be | bytes`.
pub fn pseudonym_message(
    domain: &str,
    kind: u8,
    alias: &[u8; 16],
) -> Result<Vec<u8>, MetadataError> {
    let required = required_kind_for_domain(domain).ok_or(MetadataError::UnknownDomain)?;
    if kind != required {
        return Err(MetadataError::DomainComponentMismatch);
    }
    nonzero_16(alias)?;
    let domain_utf8 = domain.as_bytes();
    let mut out = Vec::with_capacity(domain_utf8.len() + 3 + 16);
    out.extend_from_slice(domain_utf8);
    out.push(0x00);
    out.push(1);
    out.push(kind);
    out.extend_from_slice(&16u16.to_be_bytes());
    out.extend_from_slice(alias);
    Ok(out)
}

/// HKDF-SHA-256 salt = SHA-256("flycockpit.remote.metadata.hkdf.salt.v1").
pub fn hkdf_salt() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HKDF_SALT_DOMAIN.as_bytes());
    hasher.finalize().into()
}

/// HKDF info = "flycockpit.remote.metadata.tenant-key.v1\0" | T[16] | V:u32be.
pub fn tenant_key_info(tenant_id: &[u8; 16], version: u32) -> Vec<u8> {
    let mut info = Vec::with_capacity(TENANT_KEY_INFO_DOMAIN.len() + 1 + 16 + 4);
    info.extend_from_slice(TENANT_KEY_INFO_DOMAIN.as_bytes());
    info.push(0x00);
    info.extend_from_slice(tenant_id);
    info.extend_from_slice(&version.to_be_bytes());
    info
}

/// Cardinality token: first 16 bytes of HMAC-SHA-256(K, domain | alias | utcDay:u64be).
pub fn cardinality_token(key: &[u8; 32], tenant_alias: &[u8; 16], utc_day: i64) -> [u8; 16] {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts 32-byte key");
    mac.update(CARDINALITY_DOMAIN.as_bytes());
    mac.update(&[0x00u8]);
    mac.update(tenant_alias);
    mac.update(&utc_day.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result[..16]);
    out
}

/// Pseudonym = first 16 bytes of HMAC-SHA-256.
pub fn pseudonym_from_digest(digest: &[u8; 32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

pub fn pseudonym_to_hex(pseudonym: &[u8; 16]) -> String {
    pseudonym.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Correction horizon.
// ---------------------------------------------------------------------------

pub const SMALL_CELL_THRESHOLD: usize = 20;
pub const CORRECTION_HORIZON_DAYS: i64 = 7;

/// `correctionClosesAt = utcDay + 8 * 86_400`.
pub fn correction_closes_at(utc_day: i64) -> i64 {
    utc_day + 8 * 86_400
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_bucket_floors_to_hour() {
        assert_eq!(time_bucket(0).unwrap(), 0);
        assert_eq!(time_bucket(3600).unwrap(), 3600);
        assert_eq!(time_bucket(3601).unwrap(), 3600);
        assert_eq!(time_bucket(7199).unwrap(), 3600);
        assert_eq!(time_bucket(7200).unwrap(), 7200);
    }

    #[test]
    fn duration_bucket_boundaries() {
        assert_eq!(DurationBucket::from_seconds(0), DurationBucket::Lt5s);
        assert_eq!(DurationBucket::from_seconds(4), DurationBucket::Lt5s);
        assert_eq!(DurationBucket::from_seconds(5), DurationBucket::Sec5Lt30s);
        assert_eq!(DurationBucket::from_seconds(29), DurationBucket::Sec5Lt30s);
        assert_eq!(DurationBucket::from_seconds(30), DurationBucket::Sec30Lt2m);
        assert_eq!(DurationBucket::from_seconds(119), DurationBucket::Sec30Lt2m);
        assert_eq!(DurationBucket::from_seconds(120), DurationBucket::Min2Lt10m);
        assert_eq!(DurationBucket::from_seconds(599), DurationBucket::Min2Lt10m);
        assert_eq!(DurationBucket::from_seconds(600), DurationBucket::Min10Lt1h);
        assert_eq!(
            DurationBucket::from_seconds(3599),
            DurationBucket::Min10Lt1h
        );
        assert_eq!(DurationBucket::from_seconds(3600), DurationBucket::Gte1h);
        assert_eq!(DurationBucket::from_seconds(99999), DurationBucket::Gte1h);
    }

    #[test]
    fn bytes_bucket_boundaries() {
        assert_eq!(BytesBucket::from_bytes(0), BytesBucket::Zero);
        assert_eq!(BytesBucket::from_bytes(1), BytesBucket::OneBLt64Kib);
        assert_eq!(BytesBucket::from_bytes(65535), BytesBucket::OneBLt64Kib);
        assert_eq!(BytesBucket::from_bytes(65536), BytesBucket::Kib64Lt1Mib);
        assert_eq!(BytesBucket::from_bytes(1048575), BytesBucket::Kib64Lt1Mib);
        assert_eq!(BytesBucket::from_bytes(1048576), BytesBucket::Mib1Lt16Mib);
        assert_eq!(BytesBucket::from_bytes(16777215), BytesBucket::Mib1Lt16Mib);
        assert_eq!(
            BytesBucket::from_bytes(16777216),
            BytesBucket::Mib16Lt256Mib
        );
        assert_eq!(
            BytesBucket::from_bytes(268435455),
            BytesBucket::Mib16Lt256Mib
        );
        assert_eq!(
            BytesBucket::from_bytes(268435456),
            BytesBucket::Kib256Lt1Gib
        );
        assert_eq!(
            BytesBucket::from_bytes(1073741823),
            BytesBucket::Kib256Lt1Gib
        );
        assert_eq!(BytesBucket::from_bytes(1073741824), BytesBucket::Gte1Gib);
    }

    #[test]
    fn retention_validation() {
        assert_eq!(validate_retention_days(0).unwrap(), 0);
        assert_eq!(validate_retention_days(30).unwrap(), 30);
        assert_eq!(validate_retention_days(365).unwrap(), 365);
        assert!(validate_retention_days(-1).is_err());
        assert!(validate_retention_days(366).is_err());
    }

    #[test]
    fn pseudonym_message_tenant_is_exact() {
        let alias: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let msg = pseudonym_message(DOMAIN_TENANT, COMPONENT_KIND_TENANT, &alias).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(DOMAIN_TENANT.as_bytes());
        expected.push(0x00);
        expected.push(1);
        expected.push(1);
        expected.extend_from_slice(&16u16.to_be_bytes());
        expected.extend_from_slice(&alias);
        assert_eq!(msg, expected);
    }

    #[test]
    fn pseudonym_message_rejects_wrong_kind() {
        let alias = [1u8; 16];
        assert!(matches!(
            pseudonym_message(DOMAIN_TENANT, COMPONENT_KIND_ACCOUNT, &alias),
            Err(MetadataError::DomainComponentMismatch)
        ));
    }

    #[test]
    fn pseudonym_message_rejects_unknown_domain() {
        let alias = [1u8; 16];
        assert!(matches!(
            pseudonym_message("flycockpit.remote.metadata.unknown.v1", 1, &alias),
            Err(MetadataError::UnknownDomain)
        ));
    }

    #[test]
    fn pseudonym_message_rejects_zero_alias() {
        let alias = [0u8; 16];
        assert!(matches!(
            pseudonym_message(DOMAIN_TENANT, COMPONENT_KIND_TENANT, &alias),
            Err(MetadataError::InvalidComponentBytes)
        ));
    }

    #[test]
    fn cell_tuple_is_canonical_seven() {
        let tuple = cell_tuple(
            ServiceTier::PublicSaas,
            Region::NorthAmerica,
            RouteClass::Direct,
            Outcome::Connected,
            BytesBucket::OneBLt64Kib,
            BytesBucket::Kib64Lt1Mib,
            DurationBucket::Sec30Lt2m,
        );
        assert_eq!(tuple, [1, 2, 1, 1, 1, 2, 3]);
    }

    #[test]
    fn correction_horizon_is_eight_days() {
        assert_eq!(correction_closes_at(19937), 19937 + 8 * 86400);
    }
}
