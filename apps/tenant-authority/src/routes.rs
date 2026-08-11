//! The eleven and only eleven public mTLS routes exposed by the service.
//!
//! No raw sign/JWS/JWK endpoint exists. The routes map 1:1 to the protocol
//! package's [`TenantAuthorityOperation`] discriminants. The wire service is
//! exact HTTP/2 over TLS 1.3 with mandatory client certificates; HTTP/1.1,
//! TLS ≤1.2, renegotiation, cleartext upgrade, redirects, query strings,
//! cookies, form/JSON bodies, response compression, and WebSocket/gRPC
//! surfaces are disabled.

use cockpit_proto::remote_tenant_authority_protocol::TenantAuthorityOperation;

/// One public mTLS route binding: method, path, and the closed operation it
/// serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantAuthorityRoute {
    pub method: &'static str,
    pub path: &'static str,
    pub operation: TenantAuthorityOperation,
}

/// The exact eleven public mTLS routes, in operation-discriminant order.
pub const TENANT_AUTHORITY_ROUTES: [TenantAuthorityRoute; 11] = [
    TenantAuthorityRoute {
        method: "POST",
        path: "/v1/authorize/authority-activation",
        operation: TenantAuthorityOperation::AuthorityActivation,
    },
    TenantAuthorityRoute {
        method: "POST",
        path: "/v1/authorize/device-enrollment",
        operation: TenantAuthorityOperation::DeviceEnrollment,
    },
    TenantAuthorityRoute {
        method: "POST",
        path: "/v1/authorize/policy-revision",
        operation: TenantAuthorityOperation::PolicyRevision,
    },
    TenantAuthorityRoute {
        method: "POST",
        path: "/v1/authorize/attempt-grant",
        operation: TenantAuthorityOperation::AttemptGrant,
    },
    TenantAuthorityRoute {
        method: "POST",
        path: "/v1/authorize/authority-rotation",
        operation: TenantAuthorityOperation::AuthorityRotation,
    },
    TenantAuthorityRoute {
        method: "POST",
        path: "/v1/authorize/credential-registry-revision",
        operation: TenantAuthorityOperation::CredentialRegistryRevision,
    },
    TenantAuthorityRoute {
        method: "POST",
        path: "/v1/authorize/recovery-lifecycle",
        operation: TenantAuthorityOperation::RecoveryLifecycle,
    },
    TenantAuthorityRoute {
        method: "POST",
        path: "/v1/authorize/recovery-execution",
        operation: TenantAuthorityOperation::RecoveryExecution,
    },
    TenantAuthorityRoute {
        method: "POST",
        path: "/v1/authority-status",
        operation: TenantAuthorityOperation::TenantAuthorityStatus,
    },
    TenantAuthorityRoute {
        method: "POST",
        path: "/v1/identity-revocation-status",
        operation: TenantAuthorityOperation::TenantIdentityRevocationStatus,
    },
    TenantAuthorityRoute {
        method: "POST",
        path: "/v1/authorize/identity-revocation",
        operation: TenantAuthorityOperation::IdentityRevocation,
    },
];

/// Returns the route bound to `path`, or `None` if no closed handler exists.
/// Unknown paths have no handler and no raw/generic signing surface.
pub fn route_for_path(path: &str) -> Option<TenantAuthorityRoute> {
    TENANT_AUTHORITY_ROUTES
        .iter()
        .copied()
        .find(|r| r.path == path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_eleven_routes() {
        assert_eq!(TENANT_AUTHORITY_ROUTES.len(), 11);
    }

    #[test]
    fn routes_map_one_to_one_to_operations() {
        let mut ops: Vec<_> = TENANT_AUTHORITY_ROUTES
            .iter()
            .map(|r| r.operation.discriminant())
            .collect();
        ops.sort_unstable();
        let expected: Vec<u8> = (1..=11).collect();
        assert_eq!(ops, expected);
    }

    #[test]
    fn no_raw_signing_surface() {
        for r in TENANT_AUTHORITY_ROUTES {
            assert!(!r.path.contains("sign"));
            assert!(!r.path.contains("jws"));
            assert!(!r.path.contains("jwk"));
            assert_eq!(r.method, "POST");
        }
    }
}
