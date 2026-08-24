//! Transport-neutral canonical scalar codecs used by local and remote wires.
//!
//! These values are protocol primitives, not remote-service identities.  Keep
//! them available in the default local profile without compiling a remote
//! protocol module merely to encode an integer.

use serde::Deserialize as _;

/// A malformed or non-canonical wire scalar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireScalarError(pub String);

impl std::fmt::Display for WireScalarError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for WireScalarError {}

/// Nominal canonical decimal `u64` wire type (never a JSON number).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalU64DecimalStringV1(String);

impl CanonicalU64DecimalStringV1 {
    pub fn parse(input: &str) -> Result<Self, WireScalarError> {
        let value = parse_canonical_u64_decimal_string(input)?;
        Ok(Self(format_canonical_u64_decimal_string(value)))
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
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

pub fn parse_canonical_u64_decimal_string(input: &str) -> Result<u64, WireScalarError> {
    if input.is_empty() || (input != "0" && input.starts_with('0')) {
        return Err(WireScalarError("u64 decimal spelling invalid".into()));
    }
    if input.len() > 20 || !input.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(WireScalarError("u64 decimal spelling invalid".into()));
    }
    let value = input
        .parse::<u64>()
        .map_err(|_| WireScalarError("u64 decimal overflow".into()))?;
    if value.to_string() != input {
        return Err(WireScalarError("u64 decimal noncanonical".into()));
    }
    Ok(value)
}

pub fn format_canonical_u64_decimal_string(value: u64) -> String {
    value.to_string()
}

pub fn encode_u64_be(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

pub fn decode_u64_be(bytes: &[u8]) -> Result<u64, WireScalarError> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| WireScalarError("u64be requires 8 bytes".into()))?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_decimal_rejects_noncanonical_spellings() {
        for invalid in ["", "00", "01", "+1", "-1", " 1", "1 ", "18446744073709551616"] {
            assert!(parse_canonical_u64_decimal_string(invalid).is_err(), "{invalid}");
        }
        assert_eq!(parse_canonical_u64_decimal_string("0").unwrap(), 0);
        assert_eq!(
            parse_canonical_u64_decimal_string("18446744073709551615").unwrap(),
            u64::MAX
        );
    }
}
