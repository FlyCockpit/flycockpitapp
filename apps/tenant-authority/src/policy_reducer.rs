//! Pure policy reducer for `AuthorizePolicyRevisionV1`.
//!
//! After activation, `AuthorizePolicyRevisionV1` accepts only exact current
//! + proposed policy JWS bytes and persists the accepted successor plus
//! policy epoch/status/outbox atomically; no unsigned policy JSON,
//! config-file policy mutation, or second bootstrap path is valid.

use cockpit_proto::remote_tenant_authority_protocol::{self as proto, TenantAuthorityOperation};

/// The closed policy-revision action discriminants.
pub const POLICY_REVISION_ACTION_EQUAL_OR_STRENGTHEN: u8 = 1;
pub const POLICY_REVISION_ACTION_WEAKEN: u8 = 2;

/// Outcome of a policy-revision reduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyRevisionOutcome {
    /// The successor policy was accepted; the new policy epoch and signed
    /// successor JWS bytes are returned.
    Accepted {
        new_policy_epoch: u64,
        successor_jws: Vec<u8>,
    },
    /// The proposed policy was denied for the given reason.
    Denied(proto::FctoReasonCode),
}

/// Pure policy reducer. Verifies the current and proposed policy JWS bytes
/// carry the correct typ and that the action discriminant is one of the two
/// closed values. No unsigned policy JSON is accepted.
#[derive(Debug, Clone, Copy)]
pub struct PolicyReducer {
    current_policy_epoch: u64,
}

impl PolicyReducer {
    pub fn new(current_policy_epoch: u64) -> Self {
        Self {
            current_policy_epoch,
        }
    }

    /// Reduce a policy-revision request. `current_jws` must be the exact
    /// current signed tenant policy; `proposed_jws` the exact proposed signed
    /// tenant policy; `action` one of the two closed discriminants.
    pub fn reduce(
        &self,
        current_jws: &[u8],
        proposed_jws: &[u8],
        action: u8,
    ) -> PolicyRevisionOutcome {
        // No unsigned policy JSON, no second bootstrap path.
        if !matches!(
            action,
            POLICY_REVISION_ACTION_EQUAL_OR_STRENGTHEN | POLICY_REVISION_ACTION_WEAKEN
        ) {
            return PolicyRevisionOutcome::Denied(proto::FctoReasonCode::Malformed);
        }
        // Both must be valid compact JWS with the tenant-policy typ.
        if proto::EvidenceType::TenantPolicy
            .validate(current_jws)
            .is_err()
            || proto::EvidenceType::TenantPolicy
                .validate(proposed_jws)
                .is_err()
        {
            return PolicyRevisionOutcome::Denied(proto::FctoReasonCode::InvalidEvidence);
        }
        // Exact current+proposed bytes: current must not equal proposed.
        if current_jws == proposed_jws {
            return PolicyRevisionOutcome::Denied(proto::FctoReasonCode::RequestConflict);
        }
        PolicyRevisionOutcome::Accepted {
            new_policy_epoch: self.current_policy_epoch + 1,
            successor_jws: proposed_jws.to_vec(),
        }
    }

    /// The operation this reducer serves.
    pub const OPERATION: TenantAuthorityOperation = TenantAuthorityOperation::PolicyRevision;
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    fn valid_tenant_policy_jws() -> Vec<u8> {
        // Construct a minimal compact JWS with the tenant-policy typ and
        // ES256 alg, three non-empty segments.
        let header = serde_json::json!({
            "typ": "flycockpit-tenant-remote-policy+jws",
            "alg": "ES256",
            "kid": "k1",
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"payload");
        let sig_b64 = URL_SAFE_NO_PAD.encode(b"sig");
        format!("{header_b64}.{payload_b64}.{sig_b64}").into_bytes()
    }

    #[test]
    fn accepts_valid_revision() {
        let r = PolicyReducer::new(5);
        let current = valid_tenant_policy_jws();
        // Make proposed differ but keep it a valid compact JWS.
        let header = serde_json::json!({
            "typ": "flycockpit-tenant-remote-policy+jws",
            "alg": "ES256",
            "kid": "k2",
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(b"payload2");
        let sig_b64 = URL_SAFE_NO_PAD.encode(b"sig2");
        let proposed = format!("{header_b64}.{payload_b64}.{sig_b64}").into_bytes();

        match r.reduce(
            &current,
            &proposed,
            POLICY_REVISION_ACTION_EQUAL_OR_STRENGTHEN,
        ) {
            PolicyRevisionOutcome::Accepted {
                new_policy_epoch,
                successor_jws,
            } => {
                assert_eq!(new_policy_epoch, 6);
                assert_eq!(successor_jws, proposed);
            }
            _ => panic!("expected accepted"),
        }
    }

    #[test]
    fn rejects_unsigned_policy_json() {
        let r = PolicyReducer::new(5);
        let current = valid_tenant_policy_jws();
        let proposed = b"{ \"policy\": \"unsigned\" }".to_vec();
        assert!(matches!(
            r.reduce(&current, &proposed, 1),
            PolicyRevisionOutcome::Denied(proto::FctoReasonCode::InvalidEvidence)
        ));
    }

    #[test]
    fn rejects_identical_current_proposed() {
        let r = PolicyReducer::new(5);
        let jws = valid_tenant_policy_jws();
        assert!(matches!(
            r.reduce(&jws, &jws, 1),
            PolicyRevisionOutcome::Denied(proto::FctoReasonCode::RequestConflict)
        ));
    }

    #[test]
    fn rejects_unknown_action() {
        let r = PolicyReducer::new(5);
        let current = valid_tenant_policy_jws();
        let proposed = format!("{}.{}.{}", "Y", "Y", "Y").into_bytes();
        assert!(matches!(
            r.reduce(&current, &proposed, 9),
            PolicyRevisionOutcome::Denied(proto::FctoReasonCode::Malformed)
        ));
    }
}
