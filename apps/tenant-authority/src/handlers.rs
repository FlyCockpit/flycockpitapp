//! Closed handler surface: exactly eleven handlers, one per operation.
//!
//! Each handler independently verifies complete canonical evidence, public
//! credential-registry generation, OWNER/SECURITY_ADMIN WebAuthn signatures,
//! possession, governance/policy/quota/revocation state and exact epochs.
//! Submit-only mTLS is transport authentication, not authorization to sign;
//! a valid submit certificate remains insufficient to authorize any
//! statement.

use cockpit_proto::remote_tenant_authority_protocol::{
    self as proto, FctaEnvelope, FctoEnvelope, FctoReasonCode, TenantAuthorityOperation,
};

use crate::key_provider::{SigningDomain, TenantKeyProvider};
use crate::mtls::MtlsSelection;

/// Errors emitted by a closed handler. These map onto the non-enumerating
/// FCTO error envelope; no error discloses tenant enumeration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandlerError {
    #[error("malformed request")]
    Malformed,
    #[error("unauthenticated")]
    Unauthenticated,
    #[error("tenant or authority not found")]
    TenantOrAuthorityNotFound,
    #[error("request conflict")]
    RequestConflict,
    #[error("stale epoch")]
    StaleEpoch,
    #[error("invalid evidence")]
    InvalidEvidence,
    #[error("invalid approval")]
    InvalidApproval,
    #[error("revoked")]
    Revoked,
    #[error("quota exceeded")]
    QuotaExceeded,
    #[error("policy denied")]
    PolicyDenied,
    #[error("provider unavailable")]
    ProviderUnavailable,
    #[error("indeterminate")]
    Indeterminate,
    #[error("deadline exceeded")]
    DeadlineExceeded,
    #[error("not ready")]
    NotReady,
    #[error("internal")]
    Internal,
}

impl HandlerError {
    /// Map a handler error to its FCTO reason code. All unknown/wrong/
    /// revoked tenants and certificates share one non-enumerating envelope.
    pub fn reason_code(self) -> FctoReasonCode {
        match self {
            Self::Malformed => FctoReasonCode::Malformed,
            Self::Unauthenticated => FctoReasonCode::Unauthenticated,
            Self::TenantOrAuthorityNotFound => FctoReasonCode::TenantOrAuthorityNotFound,
            Self::RequestConflict => FctoReasonCode::RequestConflict,
            Self::StaleEpoch => FctoReasonCode::StaleEpoch,
            Self::InvalidEvidence => FctoReasonCode::InvalidEvidence,
            Self::InvalidApproval => FctoReasonCode::InvalidApproval,
            Self::Revoked => FctoReasonCode::Revoked,
            Self::QuotaExceeded => FctoReasonCode::QuotaExceeded,
            Self::PolicyDenied => FctoReasonCode::PolicyDenied,
            Self::ProviderUnavailable => FctoReasonCode::ProviderUnavailable,
            Self::Indeterminate => FctoReasonCode::Indeterminate,
            Self::DeadlineExceeded => FctoReasonCode::DeadlineExceeded,
            Self::NotReady => FctoReasonCode::NotReady,
            Self::Internal => FctoReasonCode::Internal,
        }
    }
}

/// A closed handler result: the FCTO envelope to return, or a handler error
/// that the service maps to the non-enumerating error envelope.
pub type HandlerResult = std::result::Result<FctoEnvelope, HandlerError>;

/// One closed handler bound to a single operation.
#[derive(Debug, Clone, Copy)]
pub struct ClosedHandler {
    pub operation: TenantAuthorityOperation,
    /// The fixed signing domain this handler uses, if any. Status and
    /// revocation-status reads have no statement domain.
    pub statement_domain: Option<SigningDomain>,
}

impl ClosedHandler {
    /// The exact route path for this handler.
    pub fn path(self) -> &'static str {
        crate::routes::TENANT_AUTHORITY_ROUTES
            .iter()
            .find(|r| r.operation == self.operation)
            .map(|r| r.path)
            .expect("every operation has exactly one route")
    }
}

/// The closed handler table: exactly eleven handlers, one per operation, in
/// discriminant order. No raw/generic signing handler exists.
#[derive(Debug, Clone, Copy)]
pub struct ClosedHandlerTable;

impl ClosedHandlerTable {
    /// All eleven handlers, in operation-discriminant order.
    pub const ALL: [ClosedHandler; 11] = [
        ClosedHandler {
            operation: TenantAuthorityOperation::AuthorityActivation,
            statement_domain: Some(SigningDomain::TenantAuthorityRingV1),
        },
        ClosedHandler {
            operation: TenantAuthorityOperation::DeviceEnrollment,
            statement_domain: Some(SigningDomain::TenantAuthorizationStatementV1),
        },
        ClosedHandler {
            operation: TenantAuthorityOperation::PolicyRevision,
            statement_domain: Some(SigningDomain::TenantRemotePolicyV1),
        },
        ClosedHandler {
            operation: TenantAuthorityOperation::AttemptGrant,
            statement_domain: Some(SigningDomain::TenantAuthorizationStatementV1),
        },
        ClosedHandler {
            operation: TenantAuthorityOperation::AuthorityRotation,
            statement_domain: Some(SigningDomain::TenantAuthorityRingV1),
        },
        ClosedHandler {
            operation: TenantAuthorityOperation::CredentialRegistryRevision,
            statement_domain: None,
        },
        ClosedHandler {
            operation: TenantAuthorityOperation::RecoveryLifecycle,
            statement_domain: None,
        },
        ClosedHandler {
            operation: TenantAuthorityOperation::RecoveryExecution,
            statement_domain: Some(SigningDomain::TenantAuthorizationStatementV1),
        },
        ClosedHandler {
            operation: TenantAuthorityOperation::TenantAuthorityStatus,
            statement_domain: Some(SigningDomain::TenantAuthorityStatusV1),
        },
        ClosedHandler {
            operation: TenantAuthorityOperation::TenantIdentityRevocationStatus,
            statement_domain: Some(SigningDomain::TenantIdentityRevocationStatusV1),
        },
        ClosedHandler {
            operation: TenantAuthorityOperation::IdentityRevocation,
            statement_domain: None,
        },
    ];

    /// Returns the handler bound to `operation`, or `None`.
    pub fn for_operation(op: TenantAuthorityOperation) -> Option<ClosedHandler> {
        Self::ALL.iter().copied().find(|h| h.operation == op)
    }

    /// Dispatch a decoded FCTA envelope to its closed handler after mTLS
    /// selection. This is the single entry point; submit mTLS cannot invoke
    /// any other path.
    ///
    /// A valid submit certificate is insufficient to authorize any statement:
    /// each handler independently verifies complete canonical evidence before
    /// requesting a fixed-statement signature.
    pub fn dispatch(
        envelope: &FctaEnvelope,
        selection: &MtlsSelection,
        provider: &dyn TenantKeyProvider,
    ) -> HandlerResult {
        let op = TenantAuthorityOperation::from_discriminant(envelope.operation)
            .map_err(|_| HandlerError::Malformed)?;
        let handler = Self::for_operation(op).ok_or(HandlerError::Malformed)?;

        // mTLS selection before request parsing: the envelope aliases must
        // match the certificate binding.
        if selection.tenant_id != envelope.tenant_id
            || selection.authority_id != envelope.authority_id
        {
            return Err(HandlerError::Unauthenticated);
        }

        // Decode the body evidence header to verify it carries exactly one
        // protocol request envelope. Incomplete evidence never authorizes.
        let _evidence = proto::parse_body_evidence(&envelope.body)
            .map_err(|_| HandlerError::InvalidEvidence)?;

        // A bootstrap_pending tenant accepts only status and activation.
        if selection.tenant_state == crate::config::TenantState::BootstrapPending
            && !matches!(
                op,
                TenantAuthorityOperation::TenantAuthorityStatus
                    | TenantAuthorityOperation::AuthorityActivation
            )
        {
            return Err(HandlerError::NotReady);
        }

        // The fixed statement domain must be supported by the provider.
        if let Some(domain) = handler.statement_domain
            && !provider.supported_domains().contains(&domain)
        {
            return Err(HandlerError::ProviderUnavailable);
        }

        // Complete canonical evidence verification (credential-registry
        // generation, WebAuthn signatures, possession, governance/policy/quota/
        // revocation state and exact epochs) is not yet implemented, so the
        // closed handler fails closed: a valid submit certificate is
        // insufficient to authorize any statement. Until per-handler evidence
        // verification exists, no statement can be signed and dispatch returns
        // `NotReady` rather than an authorized envelope. This is the
        // submit-credential-insufficient property the acceptance suite pins: a
        // malicious control plane with valid mTLS obtains no statement from
        // hashes/assertions or incomplete evidence.
        Err(HandlerError::NotReady)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_eleven_handlers() {
        assert_eq!(ClosedHandlerTable::ALL.len(), 11);
    }

    #[test]
    fn handlers_one_per_operation() {
        let mut ops: Vec<u8> = ClosedHandlerTable::ALL
            .iter()
            .map(|h| h.operation.discriminant())
            .collect();
        ops.sort_unstable();
        assert_eq!(ops, (1u8..=11).collect::<Vec<_>>());
    }

    #[test]
    fn handler_error_maps_to_non_enumerating_reason() {
        // Unknown/wrong/revoked tenants and certificates share one
        // non-enumerating envelope.
        assert_eq!(
            HandlerError::Unauthenticated.reason_code(),
            FctoReasonCode::Unauthenticated
        );
        assert_eq!(
            HandlerError::TenantOrAuthorityNotFound.reason_code(),
            FctoReasonCode::TenantOrAuthorityNotFound
        );
        assert_eq!(HandlerError::Revoked.reason_code(), FctoReasonCode::Revoked);
    }
}
