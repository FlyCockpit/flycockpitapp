//! Versioned enterprise remote-connection policy.
//!
//! This module gives enterprise administrators a versioned database-backed
//! policy surface for remote connectivity while preserving deployment
//! configuration and daemon-local policy as non-bypassable ceilings. It
//! publishes signed monotonic policy epochs so replicas and connected daemons
//! converge without redeployment.
//!
//! It imports the immutable `RemoteConnectionPolicyV1` schema, parser, and
//! canonical fixtures owned by [`crate::remote_public_service_policy`].
//! Enterprise code may not redefine or fork it.
//!
//! The effective policy is the monotonic intersection:
//! `deployment -> signed public-service policy or enterprise entitlement ->
//! tenant revision -> daemon local -> participant/IP-consent -> live quota`.
//! Every field's meet cannot widen — the meet of two policies is always at
//! least as strict as the stricter of the two.
//!
//! Canonical digest is SHA-256 over RFC 8785 canonical JSON of exactly
//! `{policyId, tenantId, epoch, policy}`. `policyId` is a random 16-byte ID
//! and `tenantId` is the dependency-owned tenant alias, both encoded as
//! 22-character base64url; arrays are prevalidated/sorted; every `u64`
//! including epoch and byte limits is a canonical decimal string and JSON
//! numeric input fails. The digest is stored as lowercase hex.
//!
//! Policy epoch is monotonic u64 per tenant. Signed authorization comes only
//! from the dependency-owned signer flow: high-assurance activation includes
//! the customer-operated signer result over exact digest/epoch; this module
//! never holds/uses a tenant private key or substitutes control-plane signing.

use crate::remote_protocol_id::{
    CanonicalU64DecimalStringV1, RemoteProtocolId, RemoteProtocolIdError,
    decode_protocol_id_base64url, encode_protocol_id_base64url, kind,
};
use crate::remote_public_service_policy::{
    self as policy, ALLOWED_TRANSPORTS, ALLOWED_TURN_REGIONS, ChangeClass, ClientCustodyPolicy,
    DaemonCustodyPolicy, DirectIpMode, RemoteConnectionLimitsV1, RemoteConnectionPolicyV1,
    SharedSessionRoute, TenantAuthorization, canonical_json_value,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnterprisePolicyError {
    #[error("invalid enterprise policy: {0}")]
    Invalid(String),
    #[error("authorization denied: {0}")]
    AuthorizationDenied(String),
    #[error("stale epoch: {0}")]
    StaleEpoch(String),
    #[error("digest mismatch: {0}")]
    DigestMismatch(String),
    #[error("signer denied: {0}")]
    SignerDenied(String),
}

type Result<T> = std::result::Result<T, EnterprisePolicyError>;
fn invalid<T>(s: impl Into<String>) -> Result<T> {
    Err(EnterprisePolicyError::Invalid(s.into()))
}
fn auth_denied<T>(s: impl Into<String>) -> Result<T> {
    Err(EnterprisePolicyError::AuthorizationDenied(s.into()))
}

// ---------------------------------------------------------------------------
// Enterprise admin roles (corrected from ORG_ADMIN | MEMBER)
// ---------------------------------------------------------------------------

/// Enterprise admin roles. The dependency
/// `remote-enterprise-passkey-administration` owns the global Prisma/
/// authorization replacement of `ORG_ADMIN | MEMBER` with
/// `OWNER | SECURITY_ADMIN | MEMBER`. This enum mirrors that schema for the
/// policy authorization surface and does not duplicate the role schema — it
/// is the typed policy-side consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseAdminRole {
    Owner,
    SecurityAdmin,
    Member,
}

impl EnterpriseAdminRole {
    /// SECURITY_ADMIN alone may create and activate a strengthening/equal
    /// revision. OWNER alone cannot author remote policy. Any weakening
    /// requires two distinct portable approvals (one OWNER + one
    /// SECURITY_ADMIN). MEMBER/staff/operator are denied.
    pub fn can_author_strengthening(self) -> bool {
        matches!(self, Self::SecurityAdmin)
    }

    /// OWNER alone cannot author remote policy.
    pub fn can_author_alone(self) -> bool {
        matches!(self, Self::SecurityAdmin)
    }

    /// MEMBER/staff/operator are denied all remote policy authorship.
    pub fn is_denied(self) -> bool {
        matches!(self, Self::Member)
    }
}

/// The two closed policy-revision actions: strengthening/equal or weakening.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRevisionAction {
    /// Strengthening or equal revision: SECURITY_ADMIN alone may author.
    EqualOrStrengthening,
    /// Weakening revision: requires exactly one OWNER plus one SECURITY_ADMIN
    /// approval (two distinct portable approvals).
    Weakening,
}

impl PolicyRevisionAction {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::EqualOrStrengthening => 1,
            Self::Weakening => 2,
        }
    }
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::EqualOrStrengthening),
            2 => Ok(Self::Weakening),
            _ => invalid(format!("unknown policy revision action {v}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Approval identity (portable, dual-control)
// ---------------------------------------------------------------------------

/// A portable approval identity. Two weakening approvals must be from
/// distinct principals with distinct credentials.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalIdentity {
    pub principal_id: String,
    pub credential_id_hash: String,
    pub role: EnterpriseAdminRole,
}

/// Validate that the approval set satisfies the action's cardinality.
///
/// - EqualOrStrengthening: exactly one SECURITY_ADMIN approval.
/// - Weakening: exactly two approvals, one OWNER plus one SECURITY_ADMIN,
///   distinct principals and distinct credentials.
pub fn validate_approval_cardinality(
    action: PolicyRevisionAction,
    approvals: &[ApprovalIdentity],
) -> Result<()> {
    match action {
        PolicyRevisionAction::EqualOrStrengthening => {
            if approvals.len() != 1 {
                return auth_denied("equal_or_strengthening requires exactly one approval");
            }
            let a = &approvals[0];
            if !a.role.can_author_strengthening() {
                return auth_denied("equal_or_strengthening approver must be SECURITY_ADMIN");
            }
            Ok(())
        }
        PolicyRevisionAction::Weakening => {
            if approvals.len() != 2 {
                return auth_denied("weakening requires exactly two approvals");
            }
            // Distinct principals.
            if approvals[0].principal_id == approvals[1].principal_id {
                return auth_denied("weakening approvals must be from distinct principals");
            }
            // Distinct credentials.
            if approvals[0].credential_id_hash == approvals[1].credential_id_hash {
                return auth_denied("weakening approvals must use distinct credentials");
            }
            // Exactly one OWNER and one SECURITY_ADMIN.
            let roles: Vec<_> = approvals.iter().map(|a| a.role).collect();
            let has_owner = roles.contains(&EnterpriseAdminRole::Owner);
            let has_sec = roles.contains(&EnterpriseAdminRole::SecurityAdmin);
            if !has_owner || !has_sec {
                return auth_denied("weakening requires exactly one OWNER plus one SECURITY_ADMIN");
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Tenant revision envelope
// ---------------------------------------------------------------------------

/// The tenant alias (dependency-owned 16-byte typed alias encoded as
/// 22-character base64url).
pub type TenantAlias = RemoteProtocolId<kind::Tenant>;

/// The policy ID (random 16-byte ID encoded as 22-character base64url).
pub type PolicyId = RemoteProtocolId<kind::PublicPolicy>;

/// A signed tenant policy revision envelope: `{policyId, tenantId, epoch,
/// policy}`.
///
/// The canonical digest is SHA-256 over RFC 8785 canonical JSON of exactly
/// this object. `epoch` is a monotonic u64 per tenant carried as a canonical
/// decimal string. `policyId` and `tenantId` are 22-character base64url.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantPolicyRevisionV1 {
    pub policy_id: PolicyId,
    pub tenant_id: TenantAlias,
    pub epoch: CanonicalU64DecimalStringV1,
    pub policy: RemoteConnectionPolicyV1,
}

impl TenantPolicyRevisionV1 {
    /// Validate the revision: policy field constraints, cross-field rules,
    /// nonzero epoch.
    pub fn validate(&self) -> Result<()> {
        self.policy
            .validate()
            .map_err(|e| EnterprisePolicyError::Invalid(e.to_string()))?;
        if self.epoch.value() == 0 {
            return invalid("epoch must be nonzero (monotonic u64 per tenant)");
        }
        Ok(())
    }

    /// RFC 8785 canonical JSON of exactly `{policyId, tenantId, epoch, policy}`.
    pub fn canonical_json(&self) -> Result<String> {
        let value = serde_json::to_value(self)
            .map_err(|e| EnterprisePolicyError::Invalid(e.to_string()))?;
        canonical_json_value(&value).map_err(|e| EnterprisePolicyError::Invalid(e.to_string()))
    }

    /// SHA-256 over the canonical JSON, returned as lowercase 64-char hex.
    pub fn digest_hex(&self) -> Result<String> {
        let canonical = self.canonical_json()?;
        let digest = Sha256::digest(canonical.as_bytes());
        let mut hex = String::with_capacity(64);
        for b in digest {
            use std::fmt::Write;
            write!(&mut hex, "{b:02x}").expect("writing to String");
        }
        Ok(hex)
    }
}

// ---------------------------------------------------------------------------
// Effective policy meet (fieldwise intersection)
// ---------------------------------------------------------------------------

/// Meet for transport sets: sorted intersection (subset of both). The meet
/// of two transport sets is the set of transports allowed by both. Fails
/// closed (empty) if the intersection is empty.
pub fn meet_transports(a: &[String], b: &[String]) -> Result<Vec<String>> {
    let mut result: Vec<String> = Vec::new();
    for t in ALLOWED_TRANSPORTS {
        if a.iter().any(|x| x == t) && b.iter().any(|x| x == t) {
            result.push(t.to_string());
        }
    }
    // result is already sorted because ALLOWED_TRANSPORTS is sorted.
    if result.is_empty() {
        return invalid("transport meet is empty (fail closed)");
    }
    Ok(result)
}

/// Meet for TURN region sets: sorted unique intersection. May be empty (no
/// regions required for websocket-only policies).
pub fn meet_turn_regions(a: &[String], b: &[String]) -> Vec<String> {
    let mut result: Vec<String> = Vec::new();
    for r in ALLOWED_TURN_REGIONS {
        if a.iter().any(|x| x == r) && b.iter().any(|x| x == r) {
            result.push(r.to_string());
        }
    }
    result
}

/// Meet for booleans: logical AND (stricter = false).
pub fn meet_bool(a: bool, b: bool) -> bool {
    a && b
}

/// Meet for numeric limits: minimum (stricter = smaller).
pub fn meet_u64(a: u64, b: u64) -> u64 {
    a.min(b)
}

/// Meet for `DirectIpMode`: delegates to the dependency-owned `meet` table.
/// `forbid < mutual_consent`; meet chooses the stricter (forbid).
pub fn meet_direct_ip_mode(a: DirectIpMode, b: DirectIpMode) -> DirectIpMode {
    a.meet(b)
}

/// Meet for `SharedSessionRoute`: delegates to the dependency-owned `meet`
/// table. `relay_only < per_leg_policy`; meet chooses the stricter
/// (relay_only).
pub fn meet_shared_session_route(
    a: SharedSessionRoute,
    b: SharedSessionRoute,
) -> SharedSessionRoute {
    a.meet(b)
}

/// Meet for `TenantAuthorization`: delegates to the dependency-owned `meet`
/// table. `tenant_signer_required < control_plane`; meet chooses the
/// stricter signer requirement.
pub fn meet_tenant_authorization(
    a: TenantAuthorization,
    b: TenantAuthorization,
) -> TenantAuthorization {
    a.meet(b)
}

/// Meet for daemon custody: delegates to the dependency-owned total meet
/// table and selects the stricter minimum requirement.
pub fn meet_daemon_custody(a: DaemonCustodyPolicy, b: DaemonCustodyPolicy) -> DaemonCustodyPolicy {
    a.meet(b)
}

/// Meet for client custody: delegates to the dependency-owned total meet
/// table and selects the stricter minimum requirement.
pub fn meet_client_custody(a: ClientCustodyPolicy, b: ClientCustodyPolicy) -> ClientCustodyPolicy {
    a.meet(b)
}

/// Meet for limits: fieldwise minimum.
pub fn meet_limits(
    a: &RemoteConnectionLimitsV1,
    b: &RemoteConnectionLimitsV1,
) -> RemoteConnectionLimitsV1 {
    RemoteConnectionLimitsV1 {
        registered_daemons: CanonicalU64DecimalStringV1::from_u64(meet_u64(
            a.registered_daemons.value(),
            b.registered_daemons.value(),
        )),
        concurrent_attachments: CanonicalU64DecimalStringV1::from_u64(meet_u64(
            a.concurrent_attachments.value(),
            b.concurrent_attachments.value(),
        )),
        concurrent_children_per_attachment: CanonicalU64DecimalStringV1::from_u64(meet_u64(
            a.concurrent_children_per_attachment.value(),
            b.concurrent_children_per_attachment.value(),
        )),
        concurrent_participants_per_session: CanonicalU64DecimalStringV1::from_u64(meet_u64(
            a.concurrent_participants_per_session.value(),
            b.concurrent_participants_per_session.value(),
        )),
        turn_bytes_per_attachment: CanonicalU64DecimalStringV1::from_u64(meet_u64(
            a.turn_bytes_per_attachment.value(),
            b.turn_bytes_per_attachment.value(),
        )),
        turn_duration_seconds: CanonicalU64DecimalStringV1::from_u64(meet_u64(
            a.turn_duration_seconds.value(),
            b.turn_duration_seconds.value(),
        )),
        websocket_bytes_per_attachment: CanonicalU64DecimalStringV1::from_u64(meet_u64(
            a.websocket_bytes_per_attachment.value(),
            b.websocket_bytes_per_attachment.value(),
        )),
        websocket_duration_seconds: CanonicalU64DecimalStringV1::from_u64(meet_u64(
            a.websocket_duration_seconds.value(),
            b.websocket_duration_seconds.value(),
        )),
    }
}

/// Meet for metadata retention days: minimum (stricter = shorter retention).
pub fn meet_retention_days(a: u64, b: u64) -> u64 {
    meet_u64(a, b)
}

/// Compute the fieldwise meet of two `RemoteConnectionPolicyV1` values.
/// The meet cannot widen: every field's meet is at least as strict as the
/// stricter of the two. Fails closed if the transport meet is empty.
///
/// When the transport meet removes `websocket_data`, `websocket_fallback`
/// is automatically set to `false` — the fallback flag is meaningless
/// without the websocket_data transport, and keeping it true would violate
/// the cross-field rule. This is a semantic meet, not a blind fieldwise AND.
pub fn meet_policies(
    a: &RemoteConnectionPolicyV1,
    b: &RemoteConnectionPolicyV1,
) -> Result<RemoteConnectionPolicyV1> {
    let allowed_transports = meet_transports(&a.allowed_transports, &b.allowed_transports)?;
    let allowed_turn_regions = meet_turn_regions(&a.allowed_turn_regions, &b.allowed_turn_regions);
    let limits = meet_limits(&a.limits, &b.limits);
    let metadata_retention_days = CanonicalU64DecimalStringV1::from_u64(meet_retention_days(
        a.metadata_retention_days.value(),
        b.metadata_retention_days.value(),
    ));

    // Semantic meet for websocket_fallback: the boolean AND is the base,
    // but if the transport meet excluded websocket_data, the fallback must
    // be false (you cannot fall back to a transport that is not allowed).
    let websocket_fallback = meet_bool(a.websocket_fallback, b.websocket_fallback)
        && allowed_transports
            .iter()
            .any(|t| t == "websocket_data");

    let result = RemoteConnectionPolicyV1 {
        allowed_transports,
        direct_ip_mode: meet_direct_ip_mode(a.direct_ip_mode, b.direct_ip_mode),
        shared_session_route: meet_shared_session_route(
            a.shared_session_route,
            b.shared_session_route,
        ),
        websocket_fallback,
        tenant_authorization: meet_tenant_authorization(
            a.tenant_authorization,
            b.tenant_authorization,
        ),
        minimum_daemon_custody: meet_daemon_custody(
            a.minimum_daemon_custody,
            b.minimum_daemon_custody,
        ),
        minimum_client_custody: meet_client_custody(
            a.minimum_client_custody,
            b.minimum_client_custody,
        ),
        sharing_enabled: meet_bool(a.sharing_enabled, b.sharing_enabled),
        limits,
        allowed_turn_regions,
        metadata_retention_days,
    };
    // Validate the meet result satisfies all cross-field rules.
    result
        .validate()
        .map_err(|e| EnterprisePolicyError::Invalid(format!("meet result invalid: {e}")))?;
    Ok(result)
}

// ---------------------------------------------------------------------------
// Change classification (widening vs narrowing/equal)
// ---------------------------------------------------------------------------

/// Classify a proposed policy relative to the current policy.
///
/// A proposed policy is "widening" if any single dimension is more
/// permissive than the current. Otherwise it is "narrowing_or_equal".
///
/// The comparison is fieldwise:
/// - Transports: widening if the proposed set has any transport not in current.
/// - Regions: widening if the proposed set has any region not in current.
/// - Booleans (websocket_fallback, sharing_enabled): widening if proposed
///   is true and current is false.
/// - Numeric limits: widening if any proposed limit is strictly greater.
/// - Custody: widening if proposed is strictly less strict (lower rank).
/// - directIpMode: widening if proposed rank > current rank.
/// - sharedSessionRoute: widening if proposed rank > current rank.
/// - tenantAuthorization: widening if proposed rank > current rank.
/// - metadataRetentionDays: widening if proposed is strictly greater.
pub fn classify_revision(
    current: &RemoteConnectionPolicyV1,
    proposed: &RemoteConnectionPolicyV1,
) -> ChangeClass {
    // Transports: widening if proposed has any transport not in current.
    let transport_widening = proposed
        .allowed_transports
        .iter()
        .any(|t| !current.allowed_transports.contains(t));

    // Regions: widening if proposed has any region not in current.
    let region_widening = proposed
        .allowed_turn_regions
        .iter()
        .any(|r| !current.allowed_turn_regions.contains(r));

    // Booleans: widening if proposed is true and current is false.
    let websocket_fallback_widening = proposed.websocket_fallback && !current.websocket_fallback;
    let sharing_widening = proposed.sharing_enabled && !current.sharing_enabled;

    // Numeric limits: widening if any proposed limit is strictly greater.
    let limits_widening = proposed.limits.registered_daemons.value()
        > current.limits.registered_daemons.value()
        || proposed.limits.concurrent_attachments.value()
            > current.limits.concurrent_attachments.value()
        || proposed.limits.concurrent_children_per_attachment.value()
            > current.limits.concurrent_children_per_attachment.value()
        || proposed.limits.concurrent_participants_per_session.value()
            > current.limits.concurrent_participants_per_session.value()
        || proposed.limits.turn_bytes_per_attachment.value()
            > current.limits.turn_bytes_per_attachment.value()
        || proposed.limits.turn_duration_seconds.value()
            > current.limits.turn_duration_seconds.value()
        || proposed.limits.websocket_bytes_per_attachment.value()
            > current.limits.websocket_bytes_per_attachment.value()
        || proposed.limits.websocket_duration_seconds.value()
            > current.limits.websocket_duration_seconds.value();

    // Custody: widening if proposed is strictly less strict.
    let daemon_custody_widening =
        proposed.minimum_daemon_custody.rank() < current.minimum_daemon_custody.rank();
    let client_custody_widening =
        proposed.minimum_client_custody.rank() < current.minimum_client_custody.rank();

    // directIpMode: forbid(0) < mutual_consent(1). Widening if proposed
    // rank > current rank.
    let direct_ip_widening = proposed.direct_ip_mode.rank() > current.direct_ip_mode.rank();

    // sharedSessionRoute: relay_only(0) < per_leg_policy(1).
    let route_widening = proposed.shared_session_route.rank() > current.shared_session_route.rank();

    // tenantAuthorization: tenant_signer_required(0) < control_plane(1).
    let auth_widening = proposed.tenant_authorization.rank() > current.tenant_authorization.rank();

    // metadataRetentionDays: widening if strictly greater.
    let retention_widening =
        proposed.metadata_retention_days.value() > current.metadata_retention_days.value();

    let any_widening = transport_widening
        || region_widening
        || websocket_fallback_widening
        || sharing_widening
        || limits_widening
        || daemon_custody_widening
        || client_custody_widening
        || direct_ip_widening
        || route_widening
        || auth_widening
        || retention_widening;

    if any_widening {
        ChangeClass::Widening
    } else {
        ChangeClass::NarrowingOrEqual
    }
}

// ---------------------------------------------------------------------------
// Per-field narrowing/widening detection for lease revocation
// ---------------------------------------------------------------------------

/// The set of fields that narrowed in a revision. Widening tenant policy
/// affects new child attempts only; narrowing produces a signed sequenced
/// event and revokes/limits active leases.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NarrowedFields {
    pub transports: bool,
    pub turn_regions: bool,
    pub websocket_fallback: bool,
    pub sharing_enabled: bool,
    pub limits: bool,
    pub daemon_custody: bool,
    pub client_custody: bool,
    pub direct_ip_mode: bool,
    pub shared_session_route: bool,
    pub tenant_authorization: bool,
    pub metadata_retention_days: bool,
}

impl NarrowedFields {
    pub fn any_narrowed(&self) -> bool {
        self.transports
            || self.turn_regions
            || self.websocket_fallback
            || self.sharing_enabled
            || self.limits
            || self.daemon_custody
            || self.client_custody
            || self.direct_ip_mode
            || self.shared_session_route
            || self.tenant_authorization
            || self.metadata_retention_days
    }
}

/// Detect which fields narrowed in a revision (proposed is stricter than
/// current). Used to determine which active leases must be revoked/limited.
pub fn detect_narrowed_fields(
    current: &RemoteConnectionPolicyV1,
    proposed: &RemoteConnectionPolicyV1,
) -> NarrowedFields {
    // Transports narrowed if proposed is a strict subset of current.
    let transports_narrowed = proposed
        .allowed_transports
        .iter()
        .all(|t| current.allowed_transports.contains(t))
        && proposed.allowed_transports.len() < current.allowed_transports.len();

    // Regions narrowed if proposed is a strict subset of current.
    let regions_narrowed = proposed
        .allowed_turn_regions
        .iter()
        .all(|r| current.allowed_turn_regions.contains(r))
        && proposed.allowed_turn_regions.len() < current.allowed_turn_regions.len();

    NarrowedFields {
        transports: transports_narrowed,
        turn_regions: regions_narrowed,
        websocket_fallback: current.websocket_fallback && !proposed.websocket_fallback,
        sharing_enabled: current.sharing_enabled && !proposed.sharing_enabled,
        limits: proposed.limits.registered_daemons.value()
            < current.limits.registered_daemons.value()
            || proposed.limits.concurrent_attachments.value()
                < current.limits.concurrent_attachments.value()
            || proposed.limits.concurrent_children_per_attachment.value()
                < current.limits.concurrent_children_per_attachment.value()
            || proposed.limits.concurrent_participants_per_session.value()
                < current.limits.concurrent_participants_per_session.value()
            || proposed.limits.turn_bytes_per_attachment.value()
                < current.limits.turn_bytes_per_attachment.value()
            || proposed.limits.turn_duration_seconds.value()
                < current.limits.turn_duration_seconds.value()
            || proposed.limits.websocket_bytes_per_attachment.value()
                < current.limits.websocket_bytes_per_attachment.value()
            || proposed.limits.websocket_duration_seconds.value()
                < current.limits.websocket_duration_seconds.value(),
        daemon_custody: proposed.minimum_daemon_custody.rank()
            > current.minimum_daemon_custody.rank(),
        client_custody: proposed.minimum_client_custody.rank()
            > current.minimum_client_custody.rank(),
        direct_ip_mode: proposed.direct_ip_mode.rank() < current.direct_ip_mode.rank(),
        shared_session_route: proposed.shared_session_route.rank()
            < current.shared_session_route.rank(),
        tenant_authorization: proposed.tenant_authorization.rank()
            < current.tenant_authorization.rank(),
        metadata_retention_days: proposed.metadata_retention_days.value()
            < current.metadata_retention_days.value(),
    }
}

// ---------------------------------------------------------------------------
// Optimistic revision race (one epoch winner)
// ---------------------------------------------------------------------------

/// Result of an optimistic revision attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevisionRaceOutcome {
    /// This revision won the epoch race; the new epoch is returned.
    Winner { new_epoch: u64 },
    /// The precondition epoch was stale; another revision won. No revision
    /// was created.
    StalePrecondition {
        expected_epoch: u64,
        actual_epoch: u64,
    },
}

/// Attempt an optimistic revision. The caller provides the expected current
/// epoch (precondition) and the actual current epoch. If they match, the
/// revision wins and the new epoch is `current + 1`. If they don't match,
/// the precondition is stale and no revision is created.
pub fn attempt_optimistic_revision(expected_epoch: u64, actual_epoch: u64) -> RevisionRaceOutcome {
    if expected_epoch != actual_epoch {
        return RevisionRaceOutcome::StalePrecondition {
            expected_epoch,
            actual_epoch,
        };
    }
    // One epoch winner: the new epoch is current + 1.
    // Overflow protection: u64::MAX epoch cannot be incremented.
    if actual_epoch == u64::MAX {
        return RevisionRaceOutcome::StalePrecondition {
            expected_epoch,
            actual_epoch,
        };
    }
    RevisionRaceOutcome::Winner {
        new_epoch: actual_epoch + 1,
    }
}

// ---------------------------------------------------------------------------
// Commit/outbox (Postgres authoritative, Redis wakeup-only)
// ---------------------------------------------------------------------------

/// The outbox event kind for a committed policy revision.
pub const POLICY_REVISION_OUTBOX_KIND: &str = "remote_enterprise_policy_revised";

/// The outbox event kind for a narrowing that revokes active leases.
pub const POLICY_NARROWING_OUTBOX_KIND: &str = "remote_enterprise_policy_narrowed";

/// The outbox event kind for a widening (affects new attempts only).
pub const POLICY_WIDENING_OUTBOX_KIND: &str = "remote_enterprise_policy_widened";

/// The outbox event kind for a rollback (new revision, not a delete).
pub const POLICY_ROLLBACK_OUTBOX_KIND: &str = "remote_enterprise_policy_rollback";

/// Result of a transactional commit: the revision row, audit row, and
/// outbox row are committed atomically. Redis receives only a wakeup after
/// commit; consumers replay the database outbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitResult {
    /// The new policy epoch.
    pub new_epoch: u64,
    /// The digest of the committed revision.
    pub digest_hex: String,
    /// The outbox event kind to publish after commit.
    pub outbox_kind: &'static str,
    /// Whether the commit narrowed (revokes active leases) or widened
    /// (affects new attempts only).
    pub change_class: ChangeClass,
}

/// Commit a policy revision transactionally. Postgres is authoritative;
/// Redis receives only wakeups after commit; consumers replay the database
/// outbox. The revision/epoch/audit/outbox are committed atomically.
///
/// This pure function computes the commit result; the actual database
/// transaction is the caller's responsibility. The caller must commit
/// revision + epoch + audit + outbox in a single transaction, then publish
/// the Redis wakeup. If the Redis publish fails after commit, recovery is
/// from the Postgres outbox.
pub fn commit_revision(
    revision: &TenantPolicyRevisionV1,
    current_policy: &RemoteConnectionPolicyV1,
    action: PolicyRevisionAction,
    approvals: &[ApprovalIdentity],
    step_up_performed: bool,
    signer_accepted: bool,
) -> Result<CommitResult> {
    // Validate the revision.
    revision.validate()?;

    // Validate fresh step-up was performed.
    validate_step_up(action, step_up_performed)?;

    // Validate approval cardinality for the action.
    validate_approval_cardinality(action, approvals)?;

    // Classify the change.
    let change_class = classify_revision(current_policy, &revision.policy);

    // Verify the action matches the classification.
    match (action, change_class) {
        (PolicyRevisionAction::EqualOrStrengthening, ChangeClass::NarrowingOrEqual) => {}
        (PolicyRevisionAction::Weakening, ChangeClass::Widening) => {}
        (PolicyRevisionAction::EqualOrStrengthening, ChangeClass::Widening) => {
            return auth_denied("equal_or_strengthening action cannot produce a widening revision");
        }
        (PolicyRevisionAction::Weakening, ChangeClass::NarrowingOrEqual) => {
            return auth_denied("weakening action cannot produce a narrowing/equal revision");
        }
    }

    // For weakening (high-assurance), the external tenant signer must
    // independently accept the structured request. This module never holds
    // or uses a tenant private key.
    if action == PolicyRevisionAction::Weakening && !signer_accepted {
        return Err(EnterprisePolicyError::SignerDenied(
            "weakening requires external tenant signer acceptance".into(),
        ));
    }

    // Compute the digest.
    let digest_hex = revision.digest_hex()?;

    // Determine the outbox kind.
    let outbox_kind = match change_class {
        ChangeClass::NarrowingOrEqual => POLICY_NARROWING_OUTBOX_KIND,
        ChangeClass::Widening => POLICY_WIDENING_OUTBOX_KIND,
    };

    Ok(CommitResult {
        new_epoch: revision.epoch.value(),
        digest_hex,
        outbox_kind,
        change_class,
    })
}

// ---------------------------------------------------------------------------
// Passkey step-up gate
// ---------------------------------------------------------------------------

/// Whether a fresh passkey/security-key step-up is required for the action.
/// Strengthening/equal revisions require passkey step-up from the
/// SECURITY_ADMIN. Weakening revisions require step-up from both approvers.
pub fn requires_fresh_step_up(action: PolicyRevisionAction) -> bool {
    // Both action types require fresh step-up.
    let _ = action;
    true
}

/// Validate that a fresh step-up was performed. The step-up freshness,
/// credential binding, and challenge verification are owned by
/// `remote-enterprise-passkey-administration`; this module only checks that
/// the step-up flag is true.
pub fn validate_step_up(action: PolicyRevisionAction, step_up_performed: bool) -> Result<()> {
    if requires_fresh_step_up(action) && !step_up_performed {
        return auth_denied("fresh passkey/security-key step-up required");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tenant signer gate
// ---------------------------------------------------------------------------

/// The structured tenant signer request for high-assurance activation.
/// This is sent to the customer-operated signer; the signer result includes
/// acceptance over the exact digest/epoch. This module never holds or uses
/// a tenant private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantSignerRequest {
    pub digest_hex: String,
    pub epoch: CanonicalU64DecimalStringV1,
    pub tenant_id: TenantAlias,
    pub policy_id: PolicyId,
}

/// The tenant signer result. `accepted=true` means the signer independently
/// accepts the structured request. `accepted=false` means denial or outage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantSignerResult {
    pub accepted: bool,
    pub digest_hex: String,
    pub epoch: CanonicalU64DecimalStringV1,
}

/// Validate a tenant signer result against a request. The digest and epoch
/// must match exactly.
pub fn validate_signer_result(
    request: &TenantSignerRequest,
    result: &TenantSignerResult,
) -> Result<()> {
    if !result.accepted {
        return Err(EnterprisePolicyError::SignerDenied(
            "tenant signer denied the request".into(),
        ));
    }
    if request.digest_hex != result.digest_hex {
        return Err(EnterprisePolicyError::DigestMismatch(
            "signer result digest does not match request".into(),
        ));
    }
    if request.epoch.value() != result.epoch.value() {
        return Err(EnterprisePolicyError::DigestMismatch(
            "signer result epoch does not match request".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Rollback (as a new revision, not a delete)
// ---------------------------------------------------------------------------

/// Rollback is always a new revision, not a delete of a prior revision.
/// The rollback restores a prior policy as a new epoch with a new digest.
pub fn rollback_as_new_revision(
    current_epoch: u64,
    prior_policy: &RemoteConnectionPolicyV1,
    policy_id: PolicyId,
    tenant_id: TenantAlias,
    signer_accepted: bool,
) -> Result<TenantPolicyRevisionV1> {
    if !signer_accepted {
        return Err(EnterprisePolicyError::SignerDenied(
            "rollback requires external tenant signer acceptance".into(),
        ));
    }
    if current_epoch == u64::MAX {
        return invalid("epoch overflow: cannot increment u64::MAX");
    }
    let revision = TenantPolicyRevisionV1 {
        policy_id,
        tenant_id,
        epoch: CanonicalU64DecimalStringV1::from_u64(current_epoch + 1),
        policy: prior_policy.clone(),
    };
    revision.validate()?;
    Ok(revision)
}

// ---------------------------------------------------------------------------
// Daemon local ceiling (non-bypassable)
// ---------------------------------------------------------------------------

/// The daemon local policy is a non-bypassable ceiling. Remote/admin paths
/// cannot widen local policy. The effective policy is the meet of all
/// layers, and the daemon local layer is always included.
pub fn apply_daemon_local_ceiling(
    effective_without_daemon: &RemoteConnectionPolicyV1,
    daemon_local: &RemoteConnectionPolicyV1,
) -> Result<RemoteConnectionPolicyV1> {
    // The daemon local ceiling is always applied; the meet cannot widen.
    meet_policies(effective_without_daemon, daemon_local)
}

// ---------------------------------------------------------------------------
// Audit record (immutable)
// ---------------------------------------------------------------------------

/// Immutable audit record for a policy revision. UI/audit omit key/
/// signature bytes, IPs, peer tiers, and stable device identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyAuditRecord {
    pub policy_id: PolicyId,
    pub tenant_id: TenantAlias,
    pub epoch: CanonicalU64DecimalStringV1,
    pub digest_hex: String,
    pub action: PolicyRevisionAction,
    pub change_class: ChangeClass,
    /// The principal IDs of the approvers (no credential hashes, no IPs).
    pub approver_principal_ids: Vec<String>,
    /// Whether the tenant signer accepted (no signature bytes).
    pub signer_accepted: bool,
    /// Whether fresh step-up was performed (no key bytes).
    pub step_up_performed: bool,
    /// Timestamp (epoch millis) — no IP or device identifier.
    pub committed_at_ms: i64,
}

// ---------------------------------------------------------------------------
// Foundation consumption guard
// ---------------------------------------------------------------------------

/// Prove this module consumes the foundation types and does not redefine
/// them.
pub fn foundation_consumption_guard() {
    let _ = policy::RemoteConnectionPolicyV1 {
        allowed_transports: vec![],
        direct_ip_mode: policy::DirectIpMode::Forbid,
        shared_session_route: policy::SharedSessionRoute::RelayOnly,
        websocket_fallback: false,
        tenant_authorization: policy::TenantAuthorization::ControlPlane,
        minimum_daemon_custody: policy::DaemonCustodyPolicy::OsProtected,
        minimum_client_custody: policy::ClientCustodyPolicy::OriginProtected,
        sharing_enabled: false,
        limits: policy::RemoteConnectionLimitsV1 {
            registered_daemons: CanonicalU64DecimalStringV1::from_u64(1),
            concurrent_attachments: CanonicalU64DecimalStringV1::from_u64(1),
            concurrent_children_per_attachment: CanonicalU64DecimalStringV1::from_u64(1),
            concurrent_participants_per_session: CanonicalU64DecimalStringV1::from_u64(1),
            turn_bytes_per_attachment: CanonicalU64DecimalStringV1::from_u64(1),
            turn_duration_seconds: CanonicalU64DecimalStringV1::from_u64(1),
            websocket_bytes_per_attachment: CanonicalU64DecimalStringV1::from_u64(1),
            websocket_duration_seconds: CanonicalU64DecimalStringV1::from_u64(1),
        },
        allowed_turn_regions: vec![],
        metadata_retention_days: CanonicalU64DecimalStringV1::from_u64(0),
    };
    let _ = policy::ALLOWED_TRANSPORTS.len();
    let _ = policy::ALLOWED_TURN_REGIONS.len();
    let _ = CanonicalU64DecimalStringV1::from_u64(1);
    let _ = encode_protocol_id_base64url
        as fn(&[u8]) -> std::result::Result<String, RemoteProtocolIdError>;
    let _ = decode_protocol_id_base64url
        as fn(&str) -> std::result::Result<[u8; 16], RemoteProtocolIdError>;
    // Consume the dependency-owned meet tables (no redefinition/fork).
    let _ = DirectIpMode::Forbid.meet(DirectIpMode::MutualConsent);
    let _ = SharedSessionRoute::RelayOnly.meet(SharedSessionRoute::PerLegPolicy);
    let _ = TenantAuthorization::TenantSignerRequired.meet(TenantAuthorization::ControlPlane);
    let _ = DaemonCustodyPolicy::OsProtected.meet(DaemonCustodyPolicy::HardwareOrExternal);
    let _ = ClientCustodyPolicy::OriginProtected.meet(ClientCustodyPolicy::Hardware);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_public_service_policy::initial_service_version_1_policy;
    use serde_json::Value;

    fn sample_tenant_id() -> TenantAlias {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        crate::remote_protocol_id::tag_protocol_id_bytes(bytes).unwrap()
    }

    fn sample_policy_id() -> PolicyId {
        let bytes = [
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
            0x1f, 0x20,
        ];
        crate::remote_protocol_id::tag_protocol_id_bytes(bytes).unwrap()
    }

    fn sample_revision(epoch: u64) -> TenantPolicyRevisionV1 {
        TenantPolicyRevisionV1 {
            policy_id: sample_policy_id(),
            tenant_id: sample_tenant_id(),
            epoch: CanonicalU64DecimalStringV1::from_u64(epoch),
            policy: initial_service_version_1_policy(),
        }
    }

    fn sec_admin_approval() -> ApprovalIdentity {
        ApprovalIdentity {
            principal_id: "principal-sec".to_string(),
            credential_id_hash: "cred-hash-sec".to_string(),
            role: EnterpriseAdminRole::SecurityAdmin,
        }
    }

    fn owner_approval() -> ApprovalIdentity {
        ApprovalIdentity {
            principal_id: "principal-owner".to_string(),
            credential_id_hash: "cred-hash-owner".to_string(),
            role: EnterpriseAdminRole::Owner,
        }
    }

    // --- Acceptance criterion 1: corrected enterprise roles ---

    #[test]
    fn remote_policy_correct_enterprise_roles_first() {
        // SECURITY_ADMIN alone may create and activate a strengthening/equal revision.
        assert!(EnterpriseAdminRole::SecurityAdmin.can_author_strengthening());
        assert!(EnterpriseAdminRole::SecurityAdmin.can_author_alone());

        // OWNER alone cannot author remote policy.
        assert!(!EnterpriseAdminRole::Owner.can_author_alone());
        assert!(!EnterpriseAdminRole::Owner.can_author_strengthening());

        // MEMBER/staff/operator are denied.
        assert!(EnterpriseAdminRole::Member.is_denied());
        assert!(!EnterpriseAdminRole::Member.can_author_alone());
        assert!(!EnterpriseAdminRole::Member.can_author_strengthening());

        // Strengthening/equal requires exactly one SECURITY_ADMIN.
        assert!(
            validate_approval_cardinality(
                PolicyRevisionAction::EqualOrStrengthening,
                &[sec_admin_approval()],
            )
            .is_ok()
        );

        // OWNER alone cannot author strengthening.
        assert!(
            validate_approval_cardinality(
                PolicyRevisionAction::EqualOrStrengthening,
                &[owner_approval()],
            )
            .is_err()
        );

        // MEMBER alone is denied.
        let member_approval = ApprovalIdentity {
            principal_id: "p".to_string(),
            credential_id_hash: "c".to_string(),
            role: EnterpriseAdminRole::Member,
        };
        assert!(
            validate_approval_cardinality(
                PolicyRevisionAction::EqualOrStrengthening,
                &[member_approval],
            )
            .is_err()
        );

        // Weakening requires exactly one OWNER plus one SECURITY_ADMIN.
        assert!(
            validate_approval_cardinality(
                PolicyRevisionAction::Weakening,
                &[owner_approval(), sec_admin_approval()],
            )
            .is_ok()
        );

        // Two SECURITY_ADMINs is not enough for weakening.
        let sec2 = ApprovalIdentity {
            principal_id: "principal-sec2".to_string(),
            credential_id_hash: "cred-hash-sec2".to_string(),
            role: EnterpriseAdminRole::SecurityAdmin,
        };
        assert!(
            validate_approval_cardinality(
                PolicyRevisionAction::Weakening,
                &[sec_admin_approval(), sec2],
            )
            .is_err()
        );

        // Two OWNERs is not enough for weakening.
        let owner2 = ApprovalIdentity {
            principal_id: "principal-owner2".to_string(),
            credential_id_hash: "cred-hash-owner2".to_string(),
            role: EnterpriseAdminRole::Owner,
        };
        assert!(
            validate_approval_cardinality(
                PolicyRevisionAction::Weakening,
                &[owner_approval(), owner2],
            )
            .is_err()
        );

        // Same principal for both weakening approvals is rejected.
        let same_principal_owner = ApprovalIdentity {
            principal_id: "principal-owner".to_string(),
            credential_id_hash: "cred-hash-other".to_string(),
            role: EnterpriseAdminRole::Owner,
        };
        assert!(
            validate_approval_cardinality(
                PolicyRevisionAction::Weakening,
                &[owner_approval(), same_principal_owner],
            )
            .is_err()
        );

        // Same credential for both weakening approvals is rejected.
        let same_cred_sec = ApprovalIdentity {
            principal_id: "principal-other".to_string(),
            credential_id_hash: "cred-hash-owner".to_string(),
            role: EnterpriseAdminRole::SecurityAdmin,
        };
        assert!(
            validate_approval_cardinality(
                PolicyRevisionAction::Weakening,
                &[owner_approval(), same_cred_sec],
            )
            .is_err()
        );

        // Three approvals for weakening is rejected.
        let owner3 = ApprovalIdentity {
            principal_id: "principal-owner3".to_string(),
            credential_id_hash: "cred-hash-owner3".to_string(),
            role: EnterpriseAdminRole::Owner,
        };
        assert!(
            validate_approval_cardinality(
                PolicyRevisionAction::Weakening,
                &[owner_approval(), sec_admin_approval(), owner3],
            )
            .is_err()
        );

        // Zero approvals is rejected.
        assert!(
            validate_approval_cardinality(PolicyRevisionAction::EqualOrStrengthening, &[],)
                .is_err()
        );
    }

    // --- Acceptance criterion 2: v1 schema matrix (cross-field rules) ---

    #[test]
    fn remote_policy_v1_schema_matrix() {
        let p = initial_service_version_1_policy();
        assert!(p.validate().is_ok());

        // websocketFallback=true requires websocket_data.
        let mut bad = p.clone();
        bad.allowed_transports = vec!["webrtc".to_string()];
        assert!(bad.validate().is_err());

        // websocketFallback=false with websocket_data-only is OK.
        let mut ok = p.clone();
        ok.allowed_transports = vec!["websocket_data".to_string()];
        ok.websocket_fallback = false;
        ok.shared_session_route = SharedSessionRoute::PerLegPolicy;
        ok.allowed_turn_regions = vec![];
        assert!(ok.validate().is_ok());

        // sharedSessionRoute=relay_only requires webrtc+region or websocket fallback.
        let mut bad = p.clone();
        bad.allowed_transports = vec!["websocket_data".to_string()];
        bad.websocket_fallback = false;
        bad.shared_session_route = SharedSessionRoute::RelayOnly;
        bad.allowed_turn_regions = vec![];
        assert!(bad.validate().is_err());

        // sharedSessionRoute=relay_only with webrtc+region is OK (no websocket fallback).
        let mut ok = p.clone();
        ok.allowed_transports = vec!["webrtc".to_string()];
        ok.websocket_fallback = false;
        ok.shared_session_route = SharedSessionRoute::RelayOnly;
        ok.allowed_turn_regions = vec!["europe".to_string()];
        assert!(ok.validate().is_ok());

        // sharedSessionRoute=relay_only with websocket fallback and no webrtc is OK.
        let mut ok = p.clone();
        ok.allowed_transports = vec!["websocket_data".to_string()];
        ok.websocket_fallback = true;
        ok.shared_session_route = SharedSessionRoute::RelayOnly;
        ok.allowed_turn_regions = vec![];
        assert!(ok.validate().is_ok());

        // Missing/unknown fields, duplicate/unsorted arrays fail.
        let mut bad = p.clone();
        bad.allowed_transports = vec!["webrtc".to_string(), "webrtc".to_string()];
        assert!(bad.validate().is_err());

        // Zero limits fail.
        let mut bad = p.clone();
        bad.limits.registered_daemons = CanonicalU64DecimalStringV1::from_u64(0);
        assert!(bad.validate().is_err());

        // Retention over 365 fails.
        let mut bad = p.clone();
        bad.metadata_retention_days = CanonicalU64DecimalStringV1::from_u64(366);
        assert!(bad.validate().is_err());
    }

    // --- Acceptance criterion 3: canonical digest vectors ---

    #[test]
    fn remote_policy_canonical_digest_vectors() {
        let rev = sample_revision(1);

        // Canonical JSON is RFC 8785: sorted keys, no whitespace.
        let canonical = rev.canonical_json().unwrap();
        assert!(!canonical.contains(' '));
        assert!(!canonical.contains('\n'));

        // Keys are sorted: epoch < policy < policyId < tenantId.
        let epoch_pos = canonical.find("\"epoch\"").unwrap();
        let policy_pos = canonical.find("\"policy\"").unwrap();
        let policy_id_pos = canonical.find("\"policyId\"").unwrap();
        let tenant_id_pos = canonical.find("\"tenantId\"").unwrap();
        assert!(epoch_pos < policy_pos);
        assert!(policy_pos < policy_id_pos);
        assert!(policy_id_pos < tenant_id_pos);

        // epoch is a string, not a JSON number.
        assert!(canonical.contains("\"epoch\":\"1\""));

        // Digest is lowercase 64-char hex.
        let digest = rev.digest_hex().unwrap();
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );

        // Digest is stable.
        let digest2 = rev.digest_hex().unwrap();
        assert_eq!(digest, digest2);

        // Different epoch produces different digest.
        let rev2 = sample_revision(2);
        let digest2 = rev2.digest_hex().unwrap();
        assert_ne!(digest, digest2);

        // JSON numeric epoch input fails (CanonicalU64DecimalStringV1 rejects numbers).
        let bad = r#"{"epoch":1}"#;
        #[derive(Deserialize)]
        struct Wrap {
            #[serde(rename = "epoch")]
            _epoch: CanonicalU64DecimalStringV1,
        }
        assert!(serde_json::from_str::<Wrap>(bad).is_err());

        // policyId/tenantId are 22-char base64url.
        let policy_id_text = serde_json::to_string(&rev.policy_id).unwrap();
        assert_eq!(policy_id_text.len(), 24); // 22 chars + 2 quotes
        let tenant_id_text = serde_json::to_string(&rev.tenant_id).unwrap();
        assert_eq!(tenant_id_text.len(), 24);
    }

    // --- Acceptance criterion 4: precedence matrix (meet cannot widen) ---

    #[test]
    fn remote_policy_precedence_matrix() {
        let baseline = initial_service_version_1_policy();

        // Transport meet: intersection cannot widen.
        let mut narrower = baseline.clone();
        narrower.allowed_transports = vec!["webrtc".to_string()];
        let meet = meet_policies(&baseline, &narrower).unwrap();
        assert_eq!(meet.allowed_transports, vec!["webrtc".to_string()]);

        // Region meet: intersection cannot widen.
        let mut narrower = baseline.clone();
        narrower.allowed_turn_regions = vec!["europe".to_string()];
        let meet = meet_policies(&baseline, &narrower).unwrap();
        assert_eq!(meet.allowed_turn_regions, vec!["europe".to_string()]);

        // Boolean meet: logical AND cannot widen.
        let mut narrower = baseline.clone();
        narrower.sharing_enabled = false;
        let meet = meet_policies(&baseline, &narrower).unwrap();
        assert!(!meet.sharing_enabled);

        // Numeric limit meet: minimum cannot widen.
        let mut narrower = baseline.clone();
        narrower.limits.concurrent_attachments = CanonicalU64DecimalStringV1::from_u64(1);
        let meet = meet_policies(&baseline, &narrower).unwrap();
        assert_eq!(meet.limits.concurrent_attachments.value(), 1);

        // Custody meet: stricter cannot widen.
        let mut narrower = baseline.clone();
        narrower.minimum_daemon_custody = DaemonCustodyPolicy::HardwareOrExternal;
        let meet = meet_policies(&baseline, &narrower).unwrap();
        assert_eq!(
            meet.minimum_daemon_custody,
            DaemonCustodyPolicy::HardwareOrExternal
        );

        // directIpMode meet: forbid < mutual_consent, meet chooses forbid.
        let mut narrower = baseline.clone();
        narrower.direct_ip_mode = DirectIpMode::Forbid;
        let meet = meet_policies(&baseline, &narrower).unwrap();
        assert_eq!(meet.direct_ip_mode, DirectIpMode::Forbid);

        // sharedSessionRoute meet: relay_only < per_leg_policy.
        let mut narrower = baseline.clone();
        narrower.shared_session_route = SharedSessionRoute::RelayOnly;
        let meet = meet_policies(&baseline, &narrower).unwrap();
        assert_eq!(meet.shared_session_route, SharedSessionRoute::RelayOnly);

        // tenantAuthorization meet: tenant_signer_required < control_plane.
        let mut narrower = baseline.clone();
        narrower.tenant_authorization = TenantAuthorization::TenantSignerRequired;
        let meet = meet_policies(&baseline, &narrower).unwrap();
        assert_eq!(
            meet.tenant_authorization,
            TenantAuthorization::TenantSignerRequired
        );

        // metadataRetentionDays meet: minimum.
        let mut narrower = baseline.clone();
        narrower.metadata_retention_days = CanonicalU64DecimalStringV1::from_u64(7);
        let meet = meet_policies(&baseline, &narrower).unwrap();
        assert_eq!(meet.metadata_retention_days.value(), 7);

        // Symmetry: meet(a,b) == meet(b,a) for transports.
        let m1 = meet_policies(&baseline, &narrower).unwrap();
        let m2 = meet_policies(&narrower, &baseline).unwrap();
        assert_eq!(m1.allowed_transports, m2.allowed_transports);

        // Empty transport meet fails closed.
        let mut disjoint = baseline.clone();
        disjoint.allowed_transports = vec!["websocket_data".to_string()];
        disjoint.websocket_fallback = true;
        disjoint.shared_session_route = SharedSessionRoute::PerLegPolicy;
        disjoint.allowed_turn_regions = vec![];
        let mut other = baseline.clone();
        other.allowed_transports = vec!["webrtc".to_string()];
        other.websocket_fallback = false;
        other.shared_session_route = SharedSessionRoute::RelayOnly;
        other.allowed_turn_regions = vec!["europe".to_string()];
        assert!(meet_policies(&disjoint, &other).is_err());
    }

    // --- Acceptance criterion 5: optimistic revision race ---

    #[test]
    fn remote_policy_optimistic_revision_race() {
        // One winner: matching precondition wins.
        let outcome = attempt_optimistic_revision(5, 5);
        assert!(matches!(
            outcome,
            RevisionRaceOutcome::Winner { new_epoch: 6 }
        ));

        // Stale precondition: non-matching epoch creates no revision.
        let outcome = attempt_optimistic_revision(5, 6);
        assert!(matches!(
            outcome,
            RevisionRaceOutcome::StalePrecondition {
                expected_epoch: 5,
                actual_epoch: 6
            }
        ));

        // Two concurrent revisions: only one wins (the one that matches first).
        let o1 = attempt_optimistic_revision(5, 5);
        let o2 = attempt_optimistic_revision(5, 6); // after o1 won, epoch is now 6
        assert!(matches!(o1, RevisionRaceOutcome::Winner { new_epoch: 6 }));
        assert!(matches!(o2, RevisionRaceOutcome::StalePrecondition { .. }));

        // u64::MAX epoch cannot be incremented (overflow protection).
        let outcome = attempt_optimistic_revision(u64::MAX, u64::MAX);
        assert!(matches!(
            outcome,
            RevisionRaceOutcome::StalePrecondition { .. }
        ));
    }

    // --- Acceptance criterion 6: passkey and signer gate ---

    #[test]
    fn remote_policy_passkey_and_signer_gate() {
        // Fresh step-up is required for both action types.
        assert!(requires_fresh_step_up(
            PolicyRevisionAction::EqualOrStrengthening
        ));
        assert!(requires_fresh_step_up(PolicyRevisionAction::Weakening));

        // Missing step-up is rejected.
        assert!(validate_step_up(PolicyRevisionAction::EqualOrStrengthening, false).is_err());
        assert!(validate_step_up(PolicyRevisionAction::Weakening, false).is_err());

        // Present step-up is accepted.
        assert!(validate_step_up(PolicyRevisionAction::EqualOrStrengthening, true).is_ok());
        assert!(validate_step_up(PolicyRevisionAction::Weakening, true).is_ok());

        // Structured signer request/result with digest/epoch binding.
        let rev = sample_revision(1);
        let digest = rev.digest_hex().unwrap();
        let request = TenantSignerRequest {
            digest_hex: digest.clone(),
            epoch: CanonicalU64DecimalStringV1::from_u64(1),
            tenant_id: rev.tenant_id,
            policy_id: rev.policy_id,
        };
        let result_accepted = TenantSignerResult {
            accepted: true,
            digest_hex: digest.clone(),
            epoch: CanonicalU64DecimalStringV1::from_u64(1),
        };
        assert!(validate_signer_result(&request, &result_accepted).is_ok());

        // Denial is rejected.
        let result_denied = TenantSignerResult {
            accepted: false,
            digest_hex: digest.clone(),
            epoch: CanonicalU64DecimalStringV1::from_u64(1),
        };
        assert!(validate_signer_result(&request, &result_denied).is_err());

        // Outage (denied) is rejected.
        assert!(matches!(
            validate_signer_result(&request, &result_denied),
            Err(EnterprisePolicyError::SignerDenied(_))
        ));

        // Digest mismatch is rejected.
        let result_bad_digest = TenantSignerResult {
            accepted: true,
            digest_hex: "a".repeat(64),
            epoch: CanonicalU64DecimalStringV1::from_u64(1),
        };
        assert!(validate_signer_result(&request, &result_bad_digest).is_err());

        // Epoch mismatch is rejected.
        let result_bad_epoch = TenantSignerResult {
            accepted: true,
            digest_hex: digest,
            epoch: CanonicalU64DecimalStringV1::from_u64(2),
        };
        assert!(validate_signer_result(&request, &result_bad_epoch).is_err());

        // No control-plane tenant signing credential: this module has no
        // function that signs or holds a tenant private key. The only
        // signing surface is the dependency-owned signer flow.
        // (Structural assertion: no sign function exists in this module.)
    }

    // --- Acceptance criterion 7: commit/outbox before wakeup ---

    #[test]
    fn remote_policy_commit_outbox_before_wakeup() {
        let baseline = initial_service_version_1_policy();
        let rev = sample_revision(1);

        // Strengthening commit: SECURITY_ADMIN approval, step-up, signer not
        // required for strengthening.
        let result = commit_revision(
            &rev,
            &baseline,
            PolicyRevisionAction::EqualOrStrengthening,
            &[sec_admin_approval()],
            true,  // step-up performed
            false, // signer not required for strengthening
        );
        // The baseline == proposed, so classify_revision returns
        // NarrowingOrEqual, which matches EqualOrStrengthening.
        let result = result.unwrap();
        assert_eq!(result.new_epoch, 1);
        assert_eq!(result.change_class, ChangeClass::NarrowingOrEqual);
        assert_eq!(result.outbox_kind, POLICY_NARROWING_OUTBOX_KIND);

        // Missing step-up is rejected.
        assert!(
            commit_revision(
                &rev,
                &baseline,
                PolicyRevisionAction::EqualOrStrengthening,
                &[sec_admin_approval()],
                false,
                false,
            )
            .is_err()
        );

        // Wrong approval cardinality is rejected.
        assert!(
            commit_revision(
                &rev,
                &baseline,
                PolicyRevisionAction::EqualOrStrengthening,
                &[owner_approval()],
                true,
                false,
            )
            .is_err()
        );

        // Weakening requires OWNER+SECURITY_ADMIN and signer acceptance.
        let mut weakened = baseline.clone();
        weakened.limits.concurrent_attachments = CanonicalU64DecimalStringV1::from_u64(
            baseline.limits.concurrent_attachments.value() + 1,
        );
        let weakening_rev = TenantPolicyRevisionV1 {
            policy_id: sample_policy_id(),
            tenant_id: sample_tenant_id(),
            epoch: CanonicalU64DecimalStringV1::from_u64(2),
            policy: weakened,
        };
        // Without signer acceptance, weakening is rejected.
        assert!(
            commit_revision(
                &weakening_rev,
                &baseline,
                PolicyRevisionAction::Weakening,
                &[owner_approval(), sec_admin_approval()],
                true,
                false,
            )
            .is_err()
        );

        // With signer acceptance, weakening is accepted.
        let result = commit_revision(
            &weakening_rev,
            &baseline,
            PolicyRevisionAction::Weakening,
            &[owner_approval(), sec_admin_approval()],
            true,
            true,
        )
        .unwrap();
        assert_eq!(result.change_class, ChangeClass::Widening);
        assert_eq!(result.outbox_kind, POLICY_WIDENING_OUTBOX_KIND);

        // Action/class mismatch is rejected: strengthening action with
        // widening revision.
        assert!(
            commit_revision(
                &weakening_rev,
                &baseline,
                PolicyRevisionAction::EqualOrStrengthening,
                &[sec_admin_approval()],
                true,
                false,
            )
            .is_err()
        );

        // Action/class mismatch: weakening action with equal revision.
        assert!(
            commit_revision(
                &rev,
                &baseline,
                PolicyRevisionAction::Weakening,
                &[owner_approval(), sec_admin_approval()],
                true,
                true,
            )
            .is_err()
        );
    }

    // --- Acceptance criterion 8: narrowing revokes, widening waits ---

    #[test]
    fn remote_policy_narrowing_revokes_widening_waits() {
        let baseline = initial_service_version_1_policy();

        // Narrowing: fewer transports.
        let mut narrowed = baseline.clone();
        narrowed.allowed_transports = vec!["webrtc".to_string()];
        let nf = detect_narrowed_fields(&baseline, &narrowed);
        assert!(nf.transports);
        assert!(nf.any_narrowed());

        // Narrowing: lower limit.
        let mut narrowed = baseline.clone();
        narrowed.limits.concurrent_attachments = CanonicalU64DecimalStringV1::from_u64(1);
        let nf = detect_narrowed_fields(&baseline, &narrowed);
        assert!(nf.limits);
        assert!(nf.any_narrowed());

        // Narrowing: stricter custody.
        let mut narrowed = baseline.clone();
        narrowed.minimum_daemon_custody = DaemonCustodyPolicy::HardwareOrExternal;
        let nf = detect_narrowed_fields(&baseline, &narrowed);
        assert!(nf.daemon_custody);

        // Narrowing: directIpMode forbid.
        let mut narrowed = baseline.clone();
        narrowed.direct_ip_mode = DirectIpMode::Forbid;
        let nf = detect_narrowed_fields(&baseline, &narrowed);
        assert!(nf.direct_ip_mode);

        // Narrowing: sharedSessionRoute relay_only (baseline is already relay_only).
        let mut narrowed = baseline.clone();
        narrowed.shared_session_route = SharedSessionRoute::RelayOnly;
        let nf = detect_narrowed_fields(&baseline, &narrowed);
        assert!(!nf.shared_session_route);

        // Narrowing: tenantAuthorization tenant_signer_required.
        let mut narrowed = baseline.clone();
        narrowed.tenant_authorization = TenantAuthorization::TenantSignerRequired;
        let nf = detect_narrowed_fields(&baseline, &narrowed);
        assert!(nf.tenant_authorization);

        // Narrowing: shorter retention.
        let mut narrowed = baseline.clone();
        narrowed.metadata_retention_days = CanonicalU64DecimalStringV1::from_u64(7);
        let nf = detect_narrowed_fields(&baseline, &narrowed);
        assert!(nf.metadata_retention_days);

        // Widening: higher limit (not narrowed).
        let mut widened = baseline.clone();
        widened.limits.concurrent_attachments = CanonicalU64DecimalStringV1::from_u64(
            baseline.limits.concurrent_attachments.value() + 10,
        );
        let nf = detect_narrowed_fields(&baseline, &widened);
        assert!(!nf.limits);
        assert!(!nf.any_narrowed());

        // Widening classification.
        assert_eq!(
            classify_revision(&baseline, &widened),
            ChangeClass::Widening
        );

        // Narrowing classification.
        let mut narrowed = baseline.clone();
        narrowed.limits.concurrent_attachments = CanonicalU64DecimalStringV1::from_u64(1);
        assert_eq!(
            classify_revision(&baseline, &narrowed),
            ChangeClass::NarrowingOrEqual
        );

        // Equal classification.
        assert_eq!(
            classify_revision(&baseline, &baseline),
            ChangeClass::NarrowingOrEqual
        );
    }

    // --- Acceptance criterion 9: daemon local ceiling ---

    #[test]
    fn remote_policy_daemon_local_ceiling() {
        let enterprise = initial_service_version_1_policy();

        // Daemon local with stricter custody: meet cannot widen.
        let mut daemon_local = enterprise.clone();
        daemon_local.minimum_daemon_custody = DaemonCustodyPolicy::HardwareOrExternal;
        let effective = apply_daemon_local_ceiling(&enterprise, &daemon_local).unwrap();
        assert_eq!(
            effective.minimum_daemon_custody,
            DaemonCustodyPolicy::HardwareOrExternal
        );

        // Daemon local with forbid direct IP: meet cannot widen.
        let mut daemon_local = enterprise.clone();
        daemon_local.direct_ip_mode = DirectIpMode::Forbid;
        let effective = apply_daemon_local_ceiling(&enterprise, &daemon_local).unwrap();
        assert_eq!(effective.direct_ip_mode, DirectIpMode::Forbid);

        // Daemon local with lower limit: meet cannot widen.
        let mut daemon_local = enterprise.clone();
        daemon_local.limits.concurrent_attachments = CanonicalU64DecimalStringV1::from_u64(1);
        let effective = apply_daemon_local_ceiling(&enterprise, &daemon_local).unwrap();
        assert_eq!(effective.limits.concurrent_attachments.value(), 1);

        // Enterprise cannot widen daemon local: even if enterprise is more
        // permissive, the meet is daemon-local-stricter.
        let mut permissive_enterprise = enterprise.clone();
        permissive_enterprise.limits.concurrent_attachments =
            CanonicalU64DecimalStringV1::from_u64(100);
        let mut strict_daemon = enterprise.clone();
        strict_daemon.limits.concurrent_attachments = CanonicalU64DecimalStringV1::from_u64(2);
        let effective = apply_daemon_local_ceiling(&permissive_enterprise, &strict_daemon).unwrap();
        assert_eq!(effective.limits.concurrent_attachments.value(), 2);
    }

    // --- Acceptance criterion 10: rollback as new revision ---

    #[test]
    fn remote_policy_rollback_as_new_revision() {
        let baseline = initial_service_version_1_policy();
        let policy_id = sample_policy_id();
        let tenant_id = sample_tenant_id();

        // Rollback requires signer acceptance.
        assert!(rollback_as_new_revision(5, &baseline, policy_id, tenant_id, false,).is_err());

        // Rollback with signer acceptance creates a new epoch.
        let rollback = rollback_as_new_revision(5, &baseline, policy_id, tenant_id, true).unwrap();
        assert_eq!(rollback.epoch.value(), 6);
        assert_eq!(rollback.policy, baseline);

        // Rollback from u64::MAX epoch is rejected (overflow).
        assert!(
            rollback_as_new_revision(u64::MAX, &baseline, policy_id, tenant_id, true,).is_err()
        );
    }

    // --- Audit record omits sensitive data ---

    #[test]
    fn remote_policy_audit_omits_sensitive_data() {
        let rev = sample_revision(1);
        let digest = rev.digest_hex().unwrap();
        let audit = PolicyAuditRecord {
            policy_id: rev.policy_id,
            tenant_id: rev.tenant_id,
            epoch: rev.epoch,
            digest_hex: digest,
            action: PolicyRevisionAction::EqualOrStrengthening,
            change_class: ChangeClass::NarrowingOrEqual,
            approver_principal_ids: vec!["principal-sec".to_string()],
            signer_accepted: false,
            step_up_performed: true,
            committed_at_ms: 1_000_000,
        };
        let json = serde_json::to_string(&audit).unwrap();
        // No credential hashes, no IP addresses, no signature bytes, no
        // stable device identifiers. The checks use specific field names
        // rather than generic substrings (e.g. "ip" would false-match
        // "PrincipalIds").
        assert!(!json.contains("credential_id_hash"));
        assert!(!json.contains("credentialIdHash"));
        assert!(!json.contains("signature"));
        assert!(!json.contains("ipAddress"));
        assert!(!json.contains("ip_address"));
        assert!(!json.contains("peerIp"));
        assert!(!json.contains("device_id"));
        assert!(!json.contains("deviceId"));
    }

    // --- Foundation consumption guard ---

    #[test]
    fn remote_policy_foundation_consumption_guard() {
        foundation_consumption_guard();
    }

    // --- u64 boundary vectors in revision ---

    #[test]
    fn remote_policy_u64_boundary_epoch() {
        // 2^53 epoch.
        let rev = sample_revision(1u64 << 53);
        assert!(rev.validate().is_ok());
        let canonical = rev.canonical_json().unwrap();
        assert!(canonical.contains("\"epoch\":\"9007199254740992\""));

        // u64::MAX epoch.
        let rev = sample_revision(u64::MAX);
        assert!(rev.validate().is_ok());
        let canonical = rev.canonical_json().unwrap();
        assert!(canonical.contains("\"epoch\":\"18446744073709551615\""));
    }

    // --- Meet helpers are correct ---

    #[test]
    fn meet_helpers_correct() {
        // Transports.
        let a = vec!["webrtc".to_string(), "websocket_data".to_string()];
        let b = vec!["webrtc".to_string()];
        assert_eq!(meet_transports(&a, &b).unwrap(), vec!["webrtc".to_string()]);

        // Regions.
        let a = vec!["europe".to_string(), "north_america".to_string()];
        let b = vec!["europe".to_string()];
        assert_eq!(meet_turn_regions(&a, &b), vec!["europe".to_string()]);

        // Booleans.
        assert!(!meet_bool(true, false));
        assert!(meet_bool(true, true));

        // u64.
        assert_eq!(meet_u64(10, 5), 5);

        // DirectIpMode.
        assert_eq!(
            meet_direct_ip_mode(DirectIpMode::Forbid, DirectIpMode::MutualConsent),
            DirectIpMode::Forbid
        );

        // SharedSessionRoute.
        assert_eq!(
            meet_shared_session_route(
                SharedSessionRoute::RelayOnly,
                SharedSessionRoute::PerLegPolicy
            ),
            SharedSessionRoute::RelayOnly
        );

        // TenantAuthorization.
        assert_eq!(
            meet_tenant_authorization(
                TenantAuthorization::TenantSignerRequired,
                TenantAuthorization::ControlPlane
            ),
            TenantAuthorization::TenantSignerRequired
        );

        // Custody.
        assert_eq!(
            meet_daemon_custody(
                DaemonCustodyPolicy::OsProtected,
                DaemonCustodyPolicy::HardwareOrExternal
            ),
            DaemonCustodyPolicy::HardwareOrExternal
        );
        assert_eq!(
            meet_client_custody(
                ClientCustodyPolicy::OriginProtected,
                ClientCustodyPolicy::Hardware
            ),
            ClientCustodyPolicy::Hardware
        );
    }

    // --- PolicyRevisionAction round-trip ---

    #[test]
    fn policy_revision_action_round_trip() {
        assert_eq!(
            PolicyRevisionAction::from_u8(1).unwrap(),
            PolicyRevisionAction::EqualOrStrengthening
        );
        assert_eq!(
            PolicyRevisionAction::from_u8(2).unwrap(),
            PolicyRevisionAction::Weakening
        );
        assert!(PolicyRevisionAction::from_u8(3).is_err());
        assert_eq!(PolicyRevisionAction::EqualOrStrengthening.as_u8(), 1);
        assert_eq!(PolicyRevisionAction::Weakening.as_u8(), 2);
    }

    // --- TenantPolicyRevisionV1 digest excludes extra fields ---

    #[test]
    fn revision_digest_exact_fields() {
        let rev = sample_revision(1);
        let canonical = rev.canonical_json().unwrap();
        // Exactly four top-level keys.
        let value: Value = serde_json::from_str(&canonical).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.len(), 4);
        assert!(obj.contains_key("policyId"));
        assert!(obj.contains_key("tenantId"));
        assert!(obj.contains_key("epoch"));
        assert!(obj.contains_key("policy"));
    }
}
