//! Namespace syntax and account component encoding.

use sha2::{Digest, Sha256};

use super::error::SecureKeyError;

/// Service name for every secure-key native item.
pub const SECURE_KEY_SERVICE: &str = "dev.flycockpit.secure-keys";

/// Namespace: `[a-z0-9][a-z0-9._/-]{0,63}` (1..=64 chars).
pub const NAMESPACE_MAX_LEN: usize = 64;

/// Caller-owned stable namespace for leak reports.
pub const LEAK_REPORT_V1_NAMESPACE: &str = "leak-report/v1";

/// Caller-owned stable namespace for protected redaction-history encryption
/// keys (`harden-and-wire-protected-redaction-history`).
pub const REDACTION_HISTORY_V1_NAMESPACE: &str = "redaction-history/v1";

/// Max encoded length for any single account component before joining.
/// Sized for a full 64-char namespace with worst-case percent-encoding (×3).
pub const ACCOUNT_COMPONENT_MAX_ENCODED: usize = 192;

/// Validated namespace string.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Namespace(String);

impl Namespace {
    pub fn parse(raw: &str) -> Result<Self, SecureKeyError> {
        if raw.is_empty() || raw.len() > NAMESPACE_MAX_LEN {
            return Err(SecureKeyError::Invalid(format!(
                "namespace length must be 1..={NAMESPACE_MAX_LEN}"
            )));
        }
        let bytes = raw.as_bytes();
        let first = bytes[0];
        if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
            return Err(SecureKeyError::Invalid(
                "namespace must start with [a-z0-9]".into(),
            ));
        }
        for &b in &bytes[1..] {
            let ok = b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'_' | b'/' | b'-');
            if !ok {
                return Err(SecureKeyError::Invalid(format!(
                    "namespace contains invalid byte {b:#x}"
                )));
            }
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest_hex(&self) -> String {
        digest_hex(self.0.as_bytes())
    }
}

impl std::fmt::Debug for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Namespace").field(&self.0).finish()
    }
}

impl std::fmt::Display for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn digest_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Encode one account path component: percent-encode `/` and bound length.
pub fn encode_account_component(raw: &str) -> Result<String, SecureKeyError> {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        match b {
            b'/' => out.push_str("%2F"),
            b'%' => out.push_str("%25"),
            b if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') => {
                out.push(b as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    if out.len() > ACCOUNT_COMPONENT_MAX_ENCODED {
        return Err(SecureKeyError::Invalid(format!(
            "account component encoded length {} exceeds {ACCOUNT_COMPONENT_MAX_ENCODED}",
            out.len()
        )));
    }
    if out.is_empty() {
        return Err(SecureKeyError::Invalid(
            "account component must not be empty".into(),
        ));
    }
    Ok(out)
}

/// Build manifest account: `{installation-id}/{namespace}/manifest`.
pub fn manifest_account(
    installation_hex: &str,
    namespace: &Namespace,
) -> Result<String, SecureKeyError> {
    let inst = encode_account_component(installation_hex)?;
    let ns = encode_account_component(namespace.as_str())?;
    Ok(format!("{inst}/{ns}/manifest"))
}

/// Build version account: `{installation-id}/{namespace}/vNNNNNNNN`.
pub fn version_account(
    installation_hex: &str,
    namespace: &Namespace,
    version: i64,
) -> Result<String, SecureKeyError> {
    if !(1..=99_999_999).contains(&version) {
        return Err(SecureKeyError::Invalid(format!(
            "version {version} out of accountable range"
        )));
    }
    let inst = encode_account_component(installation_hex)?;
    let ns = encode_account_component(namespace.as_str())?;
    Ok(format!("{inst}/{ns}/v{version:08}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_leak_report_namespace() {
        let ns = Namespace::parse(LEAK_REPORT_V1_NAMESPACE).unwrap();
        assert_eq!(ns.as_str(), "leak-report/v1");
        let acct = version_account("aabbccddeeff00112233445566778899", &ns, 1).unwrap();
        assert!(acct.ends_with("/v00000001"));
        assert!(acct.contains("%2F")); // slash in namespace encoded
    }

    #[test]
    fn rejects_bad_namespace() {
        assert!(Namespace::parse("").is_err());
        assert!(Namespace::parse("Bad").is_err());
        assert!(Namespace::parse(&"a".repeat(65)).is_err());
        assert!(Namespace::parse("-leading").is_err());
    }
}
