//! Submit-only mTLS selection (**reference contract**).
//!
//! Production mTLS selection occurs before request parsing from SNI host plus the
//! validated certificate, yields exactly one `(tenantId,authorityId)`, and
//! then requires the envelope aliases to match. **This crate does not terminate
//! TLS or perform certificate selection**; only the SPIFFE SAN shape validator
//! [`validate_spiffe_san`] is implemented.

use crate::config::TenantState;

/// The spiffe URI SAN prefix pinned per tenant.
pub const SPIFFE_PREFIX: &str = "spiffe://flycockpit/tenant-authority-submit/";

/// The validated submit-credential binding produced by mTLS selection. Each
/// tenant-authority entry pins its own submit CA digest, leaf SPKI digest,
/// and exact SAN; no global CA/SPKI pin can authorize another tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitCredentialBinding {
    pub tenant_id: [u8; 16],
    pub authority_id: [u8; 16],
    pub deployment_id: String,
    pub submit_ca_sha256: [u8; 32],
    pub submit_leaf_spki_sha256: [u8; 32],
    pub submit_san: String,
}

/// The mTLS selection result: exactly one `(tenantId,authorityId)` plus the
/// tenant state, or a non-enumerating rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsSelection {
    pub tenant_id: [u8; 16],
    pub authority_id: [u8; 16],
    pub tenant_state: TenantState,
}

/// Non-enumerating mTLS selection error. Unknown/wrong/revoked certificates
/// and tenants share one envelope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MtlsSelectionError {
    #[error("unauthenticated")]
    Unauthenticated,
    #[error("certificate does not match exactly one tenant entry")]
    AmbiguousBinding,
    #[error("deployment id mismatch")]
    DeploymentMismatch,
}

/// Validate the spiffe URI SAN shape. `deploymentId` is the exact configured
/// ASCII `[A-Za-z0-9_-]{1,64}` string, percent encoding is forbidden, and
/// the other two path components are the canonical protocol aliases;
/// deployment ID is never parsed as a 16-byte alias.
pub fn validate_spiffe_san(san: &str, expected_deployment_id: &str) -> bool {
    let rest = match san.strip_prefix(SPIFFE_PREFIX) {
        Some(r) => r,
        None => return false,
    };
    let mut parts = rest.split('/');
    let deployment = match parts.next() {
        Some(d) => d,
        None => return false,
    };
    if deployment != expected_deployment_id {
        return false;
    }
    // deploymentId is [A-Za-z0-9_-]{1,64}, percent encoding forbidden.
    if !(1..=64).contains(&deployment.len())
        || !deployment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return false;
    }
    // Exactly two more canonical alias components.
    let tenant_alias = parts.next();
    let authority_alias = parts.next();
    if tenant_alias.is_none() || authority_alias.is_none() {
        return false;
    }
    if parts.next().is_some() {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spiffe_san_validation() {
        assert!(validate_spiffe_san(
            "spiffe://flycockpit/tenant-authority-submit/deploy1/ta/aa",
            "deploy1"
        ));
        // wrong deployment
        assert!(!validate_spiffe_san(
            "spiffe://flycockpit/tenant-authority-submit/other/ta/aa",
            "deploy1"
        ));
        // percent encoding forbidden
        assert!(!validate_spiffe_san(
            "spiffe://flycockpit/tenant-authority-submit/deploy%20/ta/aa",
            "deploy%20"
        ));
        // missing alias
        assert!(!validate_spiffe_san(
            "spiffe://flycockpit/tenant-authority-submit/deploy1/ta",
            "deploy1"
        ));
        // extra component
        assert!(!validate_spiffe_san(
            "spiffe://flycockpit/tenant-authority-submit/deploy1/ta/aa/extra",
            "deploy1"
        ));
        // bad prefix
        assert!(!validate_spiffe_san(
            "spiffe://flycockpit/other/deploy1/ta/aa",
            "deploy1"
        ));
    }

    #[test]
    fn deployment_id_bound_check() {
        // deploymentId is [A-Za-z0-9_-]{1,64}; a 65-char id is rejected.
        let long = "a".repeat(65);
        let san = format!("spiffe://flycockpit/tenant-authority-submit/{long}/ta/aa");
        assert!(!validate_spiffe_san(&san, &long));
    }
}
