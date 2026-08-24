#![cfg(feature = "remote")]

//! Customer-operated tenant-authority reference service.
//!
//! Standalone Rust service implementing the eleven closed canonical tenant-
//! authority operations over submit-only mTLS (HTTP/2 over TLS 1.3 with
//! mandatory client certificates), backed by non-exportable PKCS#11 tenant
//! ES256 private keys. It imports the paired Rust protocol crate
//! [`cockpit_proto::remote_tenant_authority_protocol`] and never control-plane
//! API internals, TypeScript API code, or a generic signing surface.
//!
//! # Surface contract
//!
//! - Exactly eleven public mTLS routes; no raw sign/JWS/JWK endpoint.
//! - mTLS selection occurs before request parsing from SNI host plus the
//!   validated certificate, yielding exactly one `(tenantId,authorityId)`,
//!   then requires the envelope aliases to match.
//! - Submit-only mTLS is transport authentication, not authorization to sign;
//!   complete canonical evidence and signer-owned state remain mandatory.
//! - Private keys are non-exportable; providers sign only service-constructed
//!   fixed statements in the six [`SigningDomain`]s.
//! - Bootstrap, candidate preparation, and replica administration are
//!   fixed-purpose local OS-owner/PKCS#11-authenticated commands with no
//!   public route.
//!
//! This crate owns the closed handler surface, strict config/replica/
//! credential file schemas, the fixed-statement provider trait, the pure
//! policy reducer, durable idempotency/epoch/preparation stores, mTLS
//! adapter, and readiness/shutdown. Production persistence is one
//! customer-operated PostgreSQL database. The non-Unix build retains every
//! codec, validator, pure state-machine test, and bootstrap parser but the
//! service binary exits before opening a listener with typed
//! [`UnsupportedPlatform`].

#![forbid(unsafe_code)]

pub mod config;
pub mod handlers;
pub mod identity_status;
pub mod key_provider;
pub mod mtls;
pub mod policy_reducer;
pub mod routes;
pub mod service;
pub mod unsupported;

pub use config::{
    CredentialFile, ReplicaFile, SharedConfig, TenantConfigEntry, TenantKeyGeneration, TenantState,
};
pub use handlers::{ClosedHandler, ClosedHandlerTable, HandlerError, HandlerResult};
pub use identity_status::{
    IdentityStatusRecord, IdentityStatusState, SubjectKind as IdentitySubjectKind,
};
pub use key_provider::{FixedStatement, Pkcs11TenantKeyProvider, SigningDomain, TenantKeyProvider};
pub use mtls::{MtlsSelection, SubmitCredentialBinding};
pub use policy_reducer::{PolicyReducer, PolicyRevisionOutcome};
pub use routes::TENANT_AUTHORITY_ROUTES;
pub use service::{Service, ServiceReadiness, UnsupportedPlatform};

/// The exact media type for tenant-authority v1 request and result envelopes.
pub const TENANT_AUTHORITY_MEDIA_TYPE: &str =
    "application/vnd.flycockpit.tenant-authority-v1+octet-stream";

/// Maximum request body bytes accepted by the wire service (262,144).
pub const MAX_REQUEST_BYTES: usize =
    cockpit_proto::remote_tenant_authority_protocol::MAX_REQUEST_BYTES;

/// Maximum result body bytes emitted by the wire service (16,384).
pub const MAX_RESULT_BYTES: usize =
    cockpit_proto::remote_tenant_authority_protocol::MAX_RESULT_BYTES;

/// Fixed server deadline in seconds (10).
pub const REQUEST_DEADLINE_SECONDS: i64 =
    cockpit_proto::remote_tenant_authority_protocol::NETWORK_DEADLINE_SECONDS;

/// Retained idempotency window in hours (24).
pub const IDEMPOTENCY_HOURS: i64 =
    cockpit_proto::remote_tenant_authority_protocol::IDEMPOTENCY_RETENTION_HOURS;
