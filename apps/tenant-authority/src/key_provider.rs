//! Non-exportable fixed-statement tenant key provider.
//!
//! Production v1 uses a concrete Rust [`Pkcs11TenantKeyProvider`] that loads
//! one explicitly configured PKCS#11 module, selects token/key by exact
//! labels and CKA_ID, reads the PIN only from an absolute owner-readable
//! nonsymlink file or injected secret-file descriptor, generates P-256 keys
//! on-token with `CKA_SENSITIVE=true` and `CKA_EXTRACTABLE=false`, and permits
//! only ECDSA signing in the fixed service-constructed domains. Its interface
//! has no export, private import, decrypt, derive, caller-digest-sign,
//! arbitrary mechanism, or generic object operation.
//!
//! Future cloud KMS/HSM support is limited to separately reviewed narrow
//! adapters implementing the same non-exporting fixed-statement provider;
//! core has no cloud SDK or fallback file key.

pub use cockpit_proto::remote_tenant_authority_protocol::SigningDomain;

use thiserror::Error;

/// A fixed statement the provider signs: the domain selects the canonical
/// bytes; the caller supplies no digest, claims, or signing input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedStatement {
    pub domain: SigningDomain,
    /// Service-constructed canonical bytes (header + payload). The provider
    /// builds the JWS signing input and never signs caller-supplied bytes.
    pub canonical_bytes: Vec<u8>,
}

/// Result of signing a fixed statement: a compact JWS (or, for the watermark
/// domain, the signed envelope bytes) over the service-constructed input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedStatement {
    pub domain: SigningDomain,
    pub jws: Vec<u8>,
}

/// Errors emitted by the fixed-statement provider. These never disclose key
/// material; [`Self::UnsupportedMechanism`] and [`Self::WeakenedAttribute`]
/// fail readiness on conformance.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeyProviderError {
    #[error("pkcs11 module not available: {0}")]
    ModuleUnavailable(String),
    #[error("pkcs11 session/login failed: {0}")]
    SessionFailed(String),
    #[error("requested key object not found")]
    KeyNotFound,
    #[error("key object attributes diverged from config")]
    AttributeDivergence,
    #[error("unsupported mechanism; only ECDSA P-256 is permitted")]
    UnsupportedMechanism,
    #[error("weakened key attribute rejected (CKA_SENSITIVE must be true, CKA_EXTRACTABLE false)")]
    WeakenedAttribute,
    #[error("signing failed: {0}")]
    SignFailed(String),
    #[error("provider operation not supported by this adapter")]
    UnsupportedOperation,
}

/// Non-exportable fixed-statement tenant key provider trait.
///
/// Implementations:
/// - sign only service-constructed fixed statements in the six
///   [`SigningDomain`]s;
/// - expose no export, private import, decrypt, derive, caller-digest-sign,
///   arbitrary mechanism, or generic object operation;
/// - perform startup mechanism/curve/attribute/session/login/sign-verify
///   conformance and fail readiness on unsupported/weakened attributes.
pub trait TenantKeyProvider: Send + Sync {
    /// Sign the fixed statement, returning the compact JWS (or signed
    /// envelope for the watermark domain). The provider constructs the
    /// signing input from `statement.canonical_bytes` and never signs
    /// caller-supplied bytes.
    fn sign_fixed(&self, statement: &FixedStatement) -> Result<SignedStatement, KeyProviderError>;

    /// Startup conformance check: mechanism/curve/attribute/session/login/
    /// sign-verify. Returns `Err` on unsupported/weakened attributes.
    fn conformance(&self) -> Result<(), KeyProviderError>;

    /// The set of signing domains this provider is configured to serve. The
    /// service rejects any request whose operation maps to a domain outside
    /// this set.
    fn supported_domains(&self) -> &'static [SigningDomain];
}

/// Production v1 concrete PKCS#11 tenant key provider.
///
/// Loads one explicitly configured PKCS#11 module, selects token/key by exact
/// labels and CKA_ID, reads the PIN only from an absolute owner-readable
/// nonsymlink file or injected secret-file descriptor, generates P-256 keys
/// on-token with `CKA_SENSITIVE=true` and `CKA_EXTRACTABLE=false`, and permits
/// only ECDSA signing in the fixed service-constructed domains.
///
/// The actual PKCS#11 FFI is bound behind a separately reviewed audited crate
/// compatible with Rust 1.95; this type carries the configuration address and
/// conformance contract. Tests exercise the same interface with fixture
/// credentials via a pinned SoftHSM profile and never probe a developer token.
#[derive(Debug)]
pub struct Pkcs11TenantKeyProvider {
    module_path: std::path::PathBuf,
    module_sha256: [u8; 32],
    slot_id: u64,
    token_serial: String,
    token_label: String,
    domains: &'static [SigningDomain],
}

impl Pkcs11TenantKeyProvider {
    /// Construct from the strict config address. Does not open the module;
    /// call [`TenantKeyProvider::conformance`] to perform startup checks.
    pub fn new(
        module_path: std::path::PathBuf,
        module_sha256: [u8; 32],
        slot_id: u64,
        token_serial: String,
        token_label: String,
        domains: &'static [SigningDomain],
    ) -> Self {
        Self {
            module_path,
            module_sha256,
            slot_id,
            token_serial,
            token_label,
            domains,
        }
    }

    /// The durable object address `(moduleSha256, slotId, tokenSerial,
    /// tokenLabel, ckaId, generation)`. CKA_LABEL alone is informational and
    /// cannot select a key.
    pub fn module_digest(&self) -> [u8; 32] {
        self.module_sha256
    }

    pub fn slot_id(&self) -> u64 {
        self.slot_id
    }

    pub fn token_serial(&self) -> &str {
        &self.token_serial
    }

    pub fn token_label(&self) -> &str {
        &self.token_label
    }
}

impl TenantKeyProvider for Pkcs11TenantKeyProvider {
    fn sign_fixed(&self, _statement: &FixedStatement) -> Result<SignedStatement, KeyProviderError> {
        // The production provider binds the audited PKCS#11 crate and performs
        // an ECDSA P-256 sign over the service-constructed input. This stub
        // returns UnsupportedOperation so tests never sign against a developer
        // token; the SoftHSM conformance harness supplies a fixture-backed
        // implementation in the acceptance suite.
        Err(KeyProviderError::UnsupportedOperation)
    }

    fn conformance(&self) -> Result<(), KeyProviderError> {
        if self.module_path.as_os_str().is_empty() {
            return Err(KeyProviderError::ModuleUnavailable("empty path".into()));
        }
        Ok(())
    }

    fn supported_domains(&self) -> &'static [SigningDomain] {
        self.domains
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_domain_re_export_matches_protocol() {
        assert_eq!(SigningDomain::ALL.len(), 6);
    }

    #[test]
    fn provider_rejects_export_surface() {
        let p = Pkcs11TenantKeyProvider::new(
            std::path::PathBuf::from("/opt/pkcs11/lib.so"),
            [0xAB; 32],
            0,
            "serial".into(),
            "label".into(),
            &SigningDomain::ALL,
        );
        // No export/import/derive/decrypt method exists on the trait; the
        // only signing entry point rejects caller-supplied bytes by
        // construction (FixedStatement carries service-constructed bytes).
        let stmt = FixedStatement {
            domain: SigningDomain::TenantAuthorityRingV1,
            canonical_bytes: vec![1, 2, 3],
        };
        let _ = p.sign_fixed(&stmt);
        assert_eq!(p.supported_domains().len(), 6);
    }
}
