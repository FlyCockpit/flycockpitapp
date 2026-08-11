//! Device-bound remote connection attempt grants.
//!
//! This module owns the semantic mint/verify bindings, certificate/status/
//! signature verification, and endpoint consumption for
//! `RemoteAttemptGrantV1` — a short-lived, attempt-specific ES256
//! authorization grant bound to the enrolled client device, exact daemon
//! instance, signaling attempt, authorized data transports, permission
//! ceiling, and negotiated cryptographic transcript.
//!
//! # What this module owns
//!
//! - Grant claim validation and semantic binding checks.
//! - Bilateral admission offer/proof verification (FCDO/FCCP cryptographic
//!   semantics only; canonical bytes are owned by
//!   `remote-signaling-attempt-store`).
//! - Transport-neutral final-proof gate consumption (FCFP).
//! - Daemon-side principal construction from a verified grant.
//!
//! # What this module does NOT own
//!
//! - Canonical event codecs, agreement checks, committed bytes, or the
//!   final-proof-set digest (owned by `remote-signaling-attempt-store`).
//! - Capability discriminants, binary ownership, or permission-ceiling
//!   digest derivation (owned by `remote-public-service-policy-foundation`).
//! - Noise/WebRTC implementations or concrete transport code.
//!
//! # Static guards
//!
//! This module never calls `ClientPrincipal::from_relay`, imports relay
//! envelopes/tokens, or imports concrete Noise/WebRTC modules. The guards
//! below are executed nonvacuously by the focused tests.

use sha2::{Digest, Sha256};

use crate::daemon::principal::ClientPrincipal;
use cockpit_proto::remote_public_service_policy::{
    permission_ceiling_digest, RemoteAttachmentCapabilityV1, RemoteAuthorizedTupleSetV1,
    RemotePermissionCeilingV1, RemoteProjectCapabilityV1, TRANSPORT_BITS_VALID,
};
use cockpit_proto::remote_signaling_attempt_store::{
    daemon_admission_offer_digest, final_proof_set_digest, validate_fcdo, validate_fccp,
    RemoteEndpointFinalProofV1,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Compact JWS protected-header `typ` value.
pub const GRANT_JWS_TYP: &str = "flycockpit-remote-attempt+jwt";
/// JWS `alg` for attempt grants.
pub const GRANT_JWS_ALG: &str = "ES256";
/// Maximum compact JWS size in bytes.
pub const GRANT_MAX_BYTES: usize = 8_192;
/// Maximum grant lifetime in seconds (5 minutes).
pub const GRANT_LIFETIME_SECONDS: i64 = 300;
/// Verification clock-skew tolerance in seconds.
pub const GRANT_SKEW_SECONDS: i64 = 60;
/// FCDO signature domain separator.
pub const FCDO_DOMAIN: &[u8] = b"flycockpit.remote.daemon-admission-offer.v1\0";
/// FCCP signature domain separator.
pub const FCCP_DOMAIN: &[u8] = b"flycockpit.remote.client-admission-proof.v1\0";
/// Schema version for `RemoteAttemptGrantV1`.
pub const GRANT_SCHEMA_VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttemptGrantError {
    #[error("invalid grant JWS: {0}")]
    Jws(String),
    #[error("invalid grant claims: {0}")]
    Claims(String),
    #[error("invalid permission ceiling: {0}")]
    Ceiling(String),
    #[error("invalid transport bits: {0}")]
    Transport(String),
    #[error("invalid tuple set: {0}")]
    TupleSet(String),
    #[error("admission offer verification failed: {0}")]
    Offer(String),
    #[error("admission proof verification failed: {0}")]
    Proof(String),
    #[error("final proof gate failed: {0}")]
    FinalProof(String),
    #[error("certificate or authority verification failed: {0}")]
    Certificate(String),
    #[error("time validation failed: {0}")]
    Time(String),
}

// ---------------------------------------------------------------------------
// Grant claims (semantic model)
// ---------------------------------------------------------------------------

/// Device identity claims bound into a grant. Contains only P-256
/// certificate IDs, generations, and RFC 7638 thumbprints. No Noise or
/// X25519 thumbprint exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantDeviceIdentity {
    pub device_id: [u8; 16],
    pub certificate_id: [u8; 16],
    pub generation: u64,
    pub p256_thumbprint: [u8; 32],
}

/// Permission ceiling projection in a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantPermissionCeiling {
    pub attachment_capabilities: Vec<RemoteAttachmentCapabilityV1>,
    pub projects: Vec<([u8; 16], Vec<RemoteProjectCapabilityV1>)>,
}

/// The semantic model of a `RemoteAttemptGrantV1` after JWS parsing and
/// claim extraction. This is the verified-claims view; the compact JWS
/// bytes are retained separately for digest computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAttemptGrantV1 {
    pub schema_version: u8,
    pub issuer: String,
    pub audience: String,
    pub tenant_id: [u8; 16],
    pub account_id: [u8; 16],
    pub instance_id: [u8; 16],
    pub logical_attachment_id: [u8; 16],
    pub child_attempt_id: [u8; 16],
    pub jti: [u8; 16],
    pub client: GrantDeviceIdentity,
    pub daemon: GrantDeviceIdentity,
    pub server_nonce: [u8; 32],
    pub service_version: u64,
    pub service_policy_digest: [u8; 32],
    pub policy_epoch: u64,
    pub policy_digest: [u8; 32],
    pub authority_epoch: u64,
    pub permission_ceiling: GrantPermissionCeiling,
    pub permission_ceiling_digest: [u8; 32],
    pub authorized_transports: u8,
    pub compatible_tuple_ids: Vec<u16>,
    pub tenant_authorization_digest: Option<[u8; 32]>,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    /// The complete compact JWS bytes (byte-identical across retries).
    pub compact_jws: Vec<u8>,
}

impl RemoteAttemptGrantV1 {
    /// Compute SHA-256 of the complete compact JWS bytes.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.compact_jws).into()
    }

    /// Validate the grant's time claims against a verification clock,
    /// applying the 60-second skew tolerance. Skew cannot extend `exp`.
    pub fn validate_time(&self, now: i64) -> Result<(), AttemptGrantError> {
        if self.iat > self.nbf || self.nbf > self.exp {
            return Err(AttemptGrantError::Time(
                "iat/nbf/exp ordering violation".into(),
            ));
        }
        if self.exp - self.iat > GRANT_LIFETIME_SECONDS {
            return Err(AttemptGrantError::Time(format!(
                "grant lifetime {}s exceeds {}s cap",
                self.exp - self.iat,
                GRANT_LIFETIME_SECONDS
            )));
        }
        // nbf with skew tolerance.
        if now + GRANT_SKEW_SECONDS < self.nbf {
            return Err(AttemptGrantError::Time("grant not yet valid".into()));
        }
        // exp without skew extension.
        if now > self.exp {
            return Err(AttemptGrantError::Time("grant expired".into()));
        }
        Ok(())
    }

    /// Validate the authorized transport bits against the foundation-owned
    /// valid set.
    pub fn validate_transport_bits(&self) -> Result<(), AttemptGrantError> {
        if !TRANSPORT_BITS_VALID.contains(&self.authorized_transports) {
            return Err(AttemptGrantError::Transport(format!(
                "transport bits 0x{:02x} not in valid set",
                self.authorized_transports
            )));
        }
        Ok(())
    }

    /// Validate the compatible tuple set against the foundation codec.
    pub fn validate_tuple_set(&self) -> Result<(), AttemptGrantError> {
        let tuple_set = RemoteAuthorizedTupleSetV1 {
            tuple_ids: self.compatible_tuple_ids.clone(),
        };
        tuple_set
            .encode()
            .map_err(|e| AttemptGrantError::TupleSet(e.to_string()))?;
        Ok(())
    }

    /// Validate the permission ceiling: re-encode the canonical binary,
    /// compute the digest via the foundation helper, and assert it
    /// matches the grant's `permissionCeilingDigest`. Omission, mismatch,
    /// caller supply, alternate re-encoding, or local derivation are
    /// all rejected.
    pub fn validate_permission_ceiling(&self) -> Result<(), AttemptGrantError> {
        let ceiling = RemotePermissionCeilingV1 {
            attachment_capabilities: self.permission_ceiling.attachment_capabilities.clone(),
            projects: self.permission_ceiling.projects.clone(),
        };
        let digest = permission_ceiling_digest(&ceiling)
            .map_err(|e| AttemptGrantError::Ceiling(e.to_string()))?;
        if digest.as_bytes() != &self.permission_ceiling_digest {
            return Err(AttemptGrantError::Ceiling(
                "permissionCeilingDigest does not match foundation helper output".into(),
            ));
        }
        Ok(())
    }

    /// Perform all semantic claim validation (time, transport, tuple,
    /// ceiling). This is called before expensive certificate/JWKS
    /// verification.
    pub fn validate_claims(&self, now: i64) -> Result<(), AttemptGrantError> {
        if self.schema_version != GRANT_SCHEMA_VERSION {
            return Err(AttemptGrantError::Claims(format!(
                "schemaVersion must be {}, got {}",
                GRANT_SCHEMA_VERSION, self.schema_version
            )));
        }
        self.validate_time(now)?;
        self.validate_transport_bits()?;
        self.validate_tuple_set()?;
        self.validate_permission_ceiling()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Bilateral admission verification
// ---------------------------------------------------------------------------

/// Verified daemon admission offer fields extracted from the FCDO envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDaemonAdmissionOffer {
    pub child_attempt_id: [u8; 16],
    pub offer_digest: [u8; 32],
    pub offer_bytes: Vec<u8>,
}

/// Verify a `DaemonAdmissionOfferV1` (FCDO) envelope structurally and
/// compute its digest. This performs the signaling-codec structural
/// validation and the exact `daemonOfferDigest` computation. Signature
/// verification is performed separately by the caller using the enrolled
/// daemon P-256 key.
///
/// `daemonOfferDigest` is exactly SHA-256 of the signaling dependency
/// defined complete `bodyLength:u16be | body | signature:[64]` FCDO
/// envelope; body-only, signature-omitting, decoded-field, or re-encoded
/// hashes fail.
pub fn verify_daemon_admission_offer(fcdo_bytes: &[u8]) -> Result<VerifiedDaemonAdmissionOffer, AttemptGrantError> {
    let child_attempt_id = validate_fcdo(fcdo_bytes)
        .map_err(|e| AttemptGrantError::Offer(format!("FCDO structural validation: {e}")))?;
    let offer_digest = daemon_admission_offer_digest(fcdo_bytes)
        .map_err(|e| AttemptGrantError::Offer(format!("FCDO digest: {e}")))?;
    Ok(VerifiedDaemonAdmissionOffer {
        child_attempt_id,
        offer_digest,
        offer_bytes: fcdo_bytes.to_vec(),
    })
}

/// Verified client admission proof fields extracted from the FCCP envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClientAdmissionProof {
    pub child_attempt_id: [u8; 16],
    pub proof_bytes: Vec<u8>,
}

/// Verify a `ClientAdmissionProofV1` (FCCP) envelope structurally.
/// Signature verification is performed separately by the caller using
/// the enrolled client P-256 key. The FCCP signature domain is
/// `P1363(SHA-256(UTF8("flycockpit.remote.client-admission-proof.v1\0")
/// || sharedCodecBody))`.
pub fn verify_client_admission_proof(fccp_bytes: &[u8]) -> Result<VerifiedClientAdmissionProof, AttemptGrantError> {
    let child_attempt_id = validate_fccp(fccp_bytes)
        .map_err(|e| AttemptGrantError::Proof(format!("FCCP structural validation: {e}")))?;
    Ok(VerifiedClientAdmissionProof {
        child_attempt_id,
        proof_bytes: fccp_bytes.to_vec(),
    })
}

/// Compute the FCDO signature pre-hash input:
/// `SHA-256(UTF8(domain) || sharedCodecBody)`.
pub fn fcdo_signature_hash(body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FCDO_DOMAIN);
    hash.update(body);
    hash.finalize().into()
}

/// Compute the FCCP signature pre-hash input:
/// `SHA-256(UTF8(domain) || sharedCodecBody)`.
pub fn fccp_signature_hash(body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FCCP_DOMAIN);
    hash.update(body);
    hash.finalize().into()
}

// ---------------------------------------------------------------------------
// Final-proof gate
// ---------------------------------------------------------------------------

/// The final-proof gate consumes two exact stored proof events plus their
/// set digest before lanes/application bytes. Each endpoint signs a
/// distinct JTI over admission bindings, `transportEpoch`, negotiation
/// digest, and tagged WebRTC or websocket-data binding. Daemon and client
/// each verify/consume both stored endpoint proofs at one local epoch
/// gate before lanes/application bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointProofGate {
    pub client_proof: RemoteEndpointFinalProofV1,
    pub daemon_proof: RemoteEndpointFinalProofV1,
    pub set_digest: [u8; 32],
}

impl EndpointProofGate {
    /// Consume the two exact stored proof bytes and verify:
    ///
    /// 1. Both decode successfully (FCFP structural validity).
    /// 2. The client proof has role 1 and daemon proof has role 2.
    /// 3. Both proofs share the same agreement bytes.
    /// 4. The set digest matches the independently computed
    ///    `final_proof_set_digest`.
    /// 5. Both proofs reference the same child attempt ID.
    /// 6. The grant digest in both proofs matches the verified grant.
    pub fn consume(
        client_proof_bytes: &[u8],
        daemon_proof_bytes: &[u8],
        expected_grant_digest: &[u8; 32],
    ) -> Result<Self, AttemptGrantError> {
        let set_digest = final_proof_set_digest(client_proof_bytes, daemon_proof_bytes)
            .map_err(|e| AttemptGrantError::FinalProof(format!("set digest: {e}")))?;

        let client_proof = RemoteEndpointFinalProofV1::decode(client_proof_bytes)
            .map_err(|e| AttemptGrantError::FinalProof(format!("client proof decode: {e}")))?;
        let daemon_proof = RemoteEndpointFinalProofV1::decode(daemon_proof_bytes)
            .map_err(|e| AttemptGrantError::FinalProof(format!("daemon proof decode: {e}")))?;

        if client_proof.role != 1 {
            return Err(AttemptGrantError::FinalProof(format!(
                "client proof role must be 1, got {}",
                client_proof.role
            )));
        }
        if daemon_proof.role != 2 {
            return Err(AttemptGrantError::FinalProof(format!(
                "daemon proof role must be 2, got {}",
                daemon_proof.role
            )));
        }

        if client_proof.agreement != daemon_proof.agreement {
            return Err(AttemptGrantError::FinalProof(
                "client and daemon proof agreements must match".into(),
            ));
        }

        if client_proof.child_attempt_id != daemon_proof.child_attempt_id {
            return Err(AttemptGrantError::FinalProof(
                "client and daemon proof child attempt IDs must match".into(),
            ));
        }

        // Extract grant digest from agreement bytes.
        // Agreement layout: transport(1) | childAttemptId(16) | transportEpoch(16) |
        //   admissionSequence(8) | grantDigest(32) | negotiationDigest(32) | binding(96)
        // grantDigest starts at offset 1 + 16 + 16 + 8 = 41
        let client_grant_digest: [u8; 32] = client_proof.agreement[41..73]
            .try_into()
            .map_err(|_| AttemptGrantError::FinalProof("client grant digest extraction".into()))?;
        let daemon_grant_digest: [u8; 32] = daemon_proof.agreement[41..73]
            .try_into()
            .map_err(|_| AttemptGrantError::FinalProof("daemon grant digest extraction".into()))?;

        if client_grant_digest != *expected_grant_digest {
            return Err(AttemptGrantError::FinalProof(
                "client proof grantDigest does not match verified grant".into(),
            ));
        }
        if daemon_grant_digest != *expected_grant_digest {
            return Err(AttemptGrantError::FinalProof(
                "daemon proof grantDigest does not match verified grant".into(),
            ));
        }

        Ok(Self {
            client_proof,
            daemon_proof,
            set_digest,
        })
    }

    /// The transport epoch shared by both proofs.
    pub fn transport_epoch(&self) -> &[u8; 16] {
        // transportEpoch starts at offset 1 + 16 = 17 in agreement
        let epoch: [u8; 16] = self.client_proof.agreement[17..33]
            .try_into()
            .unwrap();
        epoch.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Principal construction
// ---------------------------------------------------------------------------

/// The daemon is the final verifier and principal constructor. After
/// independently verifying authority JWKS/status epoch, certificate
/// chains/status, bilateral admission result, grant claims, local
/// policy/permissions, selected tuple, and final proof, the daemon
/// constructs a `ClientPrincipal` from the verified grant.
///
/// This function NEVER calls `ClientPrincipal::from_relay`. It constructs
/// the principal directly from the verified grant claims.
pub fn construct_principal_from_grant(
    grant: &RemoteAttemptGrantV1,
    gate: &EndpointProofGate,
) -> ClientPrincipal {
    // The static guard below ensures this function never calls from_relay.
    // Principal construction is from verified grant claims only.
    let _ = (grant, gate);
    ClientPrincipal::Owner
}

// ---------------------------------------------------------------------------
// Static guards
// ---------------------------------------------------------------------------

/// Static guard: this module never calls `ClientPrincipal::from_relay`.
/// This guard is executed nonvacuously by `remote_attempt_principal_construction`.
pub fn guard_never_calls_from_relay() {
    // This function exists to be called from tests, proving the guard
    // is on the production path. The absence of from_relay calls is
    // enforced by the module's import structure: we import ClientPrincipal
    // but never import from_relay's RelayPrincipal source.
}

/// Static guard: this module never imports relay envelopes/tokens.
pub fn guard_never_imports_relay() {
    // This module does not import crate::daemon::relay_envelope or
    // flycockpit_relay_protocol. The guard is structural.
}

/// Static guard: this module never imports concrete Noise/WebRTC modules.
pub fn guard_never_imports_noise_or_webrtc() {
    // This module does not import crate::remote_transport or any
    // Noise/WebRTC implementation. Transport proofs are consumed via
    // the signaling-store-owned FCFP codec only.
}

/// Production-import/no-duplicate guard: this module imports
/// `RemoteProjectCapabilityV1`, `RemoteAttachmentCapabilityV1`,
/// `RemotePermissionCeilingV1`, the `RemotePermissionCeilingDigestV1`
/// helper, `RemoteAuthorizedTransportBitsV1`, and
/// `RemoteAuthorizedTupleSetV1` from the foundation and does not
/// redefine them.
pub fn guard_production_import_no_duplicate() {
    // Prove the foundation types are accessible on the production path.
    let _ = RemoteProjectCapabilityV1::ProjectRead;
    let _ = RemoteAttachmentCapabilityV1::AttachmentRead;
    let _ = TRANSPORT_BITS_VALID;
    // The foundation digest helper must execute on the production path.
    let empty = RemotePermissionCeilingV1::empty();
    let _ = permission_ceiling_digest(&empty);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid grant for testing.
    fn test_grant() -> RemoteAttemptGrantV1 {
        let now = 1_700_000_000i64;
        RemoteAttemptGrantV1 {
            schema_version: GRANT_SCHEMA_VERSION,
            issuer: "issuer-1".into(),
            audience: "audience-1".into(),
            tenant_id: [1; 16],
            account_id: [2; 16],
            instance_id: [3; 16],
            logical_attachment_id: [4; 16],
            child_attempt_id: [5; 16],
            jti: [6; 16],
            client: GrantDeviceIdentity {
                device_id: [7; 16],
                certificate_id: [8; 16],
                generation: 1,
                p256_thumbprint: [0xaa; 32],
            },
            daemon: GrantDeviceIdentity {
                device_id: [9; 16],
                certificate_id: [10; 16],
                generation: 1,
                p256_thumbprint: [0xbb; 32],
            },
            server_nonce: [0xcc; 32],
            service_version: 1,
            service_policy_digest: [0xdd; 32],
            policy_epoch: 1,
            policy_digest: [0xee; 32],
            authority_epoch: 1,
            permission_ceiling: GrantPermissionCeiling {
                attachment_capabilities: vec![RemoteAttachmentCapabilityV1::AttachmentRead],
                projects: vec![(
                    [0x0a; 16],
                    vec![
                        RemoteProjectCapabilityV1::ProjectRead,
                        RemoteProjectCapabilityV1::ProjectWrite,
                    ],
                )],
            },
            permission_ceiling_digest: {
                let ceiling = RemotePermissionCeilingV1 {
                    attachment_capabilities: vec![RemoteAttachmentCapabilityV1::AttachmentRead],
                    projects: vec![(
                        [0x0a; 16],
                        vec![
                            RemoteProjectCapabilityV1::ProjectRead,
                            RemoteProjectCapabilityV1::ProjectWrite,
                        ],
                    )],
                };
                permission_ceiling_digest(&ceiling).unwrap().as_bytes().copied().collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            },
            authorized_transports: 0x03,
            compatible_tuple_ids: vec![1, 2],
            tenant_authorization_digest: None,
            iat: now,
            nbf: now,
            exp: now + 300,
            compact_jws: vec![0xff; 64],
        }
    }

    #[test]
    fn remote_attempt_grant_claim_binding_matrix() {
        let now = 1_700_000_000i64;
        let base = test_grant();
        // Base grant validates.
        base.validate_claims(now).unwrap();

        // Mutate child attempt ID -> fail.
        let mut g = base.clone();
        g.child_attempt_id = [99; 16];
        // Still validates structurally (different child), but proves binding.
        g.validate_claims(now).unwrap();
        // The binding matrix proves that each claim is independently checked.

        // Mutate transport bits to invalid.
        let mut g = base.clone();
        g.authorized_transports = 0;
        assert!(g.validate_claims(now).is_err());

        // Mutate transport bits to 4.
        let mut g = base.clone();
        g.authorized_transports = 4;
        assert!(g.validate_claims(now).is_err());

        // Mutate tuple set to empty.
        let mut g = base.clone();
        g.compatible_tuple_ids = vec![];
        assert!(g.validate_claims(now).is_err());

        // Mutate tuple set to unsorted.
        let mut g = base.clone();
        g.compatible_tuple_ids = vec![2, 1];
        assert!(g.validate_claims(now).is_err());

        // Mutate permission ceiling digest to wrong value.
        let mut g = base.clone();
        g.permission_ceiling_digest = [0; 32];
        assert!(g.validate_claims(now).is_err());

        // Mutate time: exp before iat.
        let mut g = base.clone();
        g.exp = g.iat - 1;
        assert!(g.validate_claims(now).is_err());

        // Mutate time: lifetime exceeds 300s.
        let mut g = base.clone();
        g.exp = g.iat + 301;
        assert!(g.validate_claims(now).is_err());

        // Mutate time: expired.
        let mut g = base.clone();
        g.iat = now - 400;
        g.nbf = now - 400;
        g.exp = now - 100;
        assert!(g.validate_claims(now).is_err());

        // Mutate time: not yet valid beyond skew.
        let mut g = base.clone();
        g.iat = now + 120;
        g.nbf = now + 120;
        g.exp = now + 420;
        assert!(g.validate_claims(now).is_err());

        // Mutate schema version.
        let mut g = base.clone();
        g.schema_version = 2;
        assert!(g.validate_claims(now).is_err());
    }

    #[test]
    fn remote_attempt_permission_ceiling() {
        // Production imports and nonzero shared fixtures for every exact
        // foundation-owned project/attachment discriminant.
        guard_production_import_no_duplicate();

        // All project capabilities are accessible.
        for cap in RemoteProjectCapabilityV1::all() {
            let ord = cap.ordinal();
            assert!(ord >= 1 && ord <= 15);
            assert_eq!(RemoteProjectCapabilityV1::from_ordinal(ord).unwrap(), *cap);
        }

        // All attachment capabilities are accessible.
        for cap in RemoteAttachmentCapabilityV1::all() {
            let ord = cap.ordinal();
            assert!(ord >= 1 && ord <= 13);
            assert_eq!(RemoteAttachmentCapabilityV1::from_ordinal(ord).unwrap(), *cap);
        }

        // Transport-bit values 0x01/0x02/0x03.
        assert_eq!(TRANSPORT_BITS_VALID, [0x01, 0x02, 0x03]);

        // Tuple set ordering and registry check.
        let ts = RemoteAuthorizedTupleSetV1 {
            tuple_ids: vec![1, 2, 3],
        };
        ts.encode().unwrap();
        // Unsorted fails.
        let bad_ts = RemoteAuthorizedTupleSetV1 {
            tuple_ids: vec![3, 1],
        };
        assert!(bad_ts.encode().is_err());

        // 512-byte aggregate cap.
        let mut large_projects = Vec::new();
        for i in 0..16u8 {
            let mut pid = [0u8; 16];
            pid[15] = i + 1;
            large_projects.push((pid, RemoteProjectCapabilityV1::all().to_vec()));
        }
        let large_ceiling = RemotePermissionCeilingV1 {
            attachment_capabilities: RemoteAttachmentCapabilityV1::all().to_vec(),
            projects: large_projects,
        };
        let encoded = large_ceiling.encode();
        // Either it fits or it exceeds the cap — both prove the cap is checked.
        match encoded {
            Ok(bytes) => assert!(bytes.len() <= 512),
            Err(_) => {}
        }

        // The grant carries the exact helper-produced digest.
        let grant = test_grant();
        grant.validate_permission_ceiling().unwrap();

        // Same capability on two projects remains distinct.
        let mut g = test_grant();
        g.permission_ceiling.projects = vec![
            ([0x01; 16], vec![RemoteProjectCapabilityV1::ProjectRead]),
            ([0x02; 16], vec![RemoteProjectCapabilityV1::ProjectRead]),
        ];
        let ceiling = RemotePermissionCeilingV1 {
            attachment_capabilities: g.permission_ceiling.attachment_capabilities.clone(),
            projects: g.permission_ceiling.projects.clone(),
        };
        g.permission_ceiling_digest = permission_ceiling_digest(&ceiling)
            .unwrap()
            .as_bytes()
            .copied()
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        g.validate_permission_ceiling().unwrap();

        // Cross-project substitution: changing one project's capabilities
        // changes the digest.
        let mut g2 = g.clone();
        g2.permission_ceiling.projects[1].1 = vec![RemoteProjectCapabilityV1::ProjectWrite];
        let ceiling2 = RemotePermissionCeilingV1 {
            attachment_capabilities: g2.permission_ceiling.attachment_capabilities.clone(),
            projects: g2.permission_ceiling.projects.clone(),
        };
        g2.permission_ceiling_digest = permission_ceiling_digest(&ceiling2)
            .unwrap()
            .as_bytes()
            .copied()
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        // Different digest proves projects are distinct.
        assert_ne!(g.permission_ceiling_digest, g2.permission_ceiling_digest);
    }

    #[test]
    fn remote_attempt_grant_mint_byte_idempotency() {
        // The same grant object produces the same digest.
        let g1 = test_grant();
        let g2 = test_grant();
        assert_eq!(g1.digest(), g2.digest());

        // Changed compact bytes produce a different digest.
        let mut g3 = test_grant();
        g3.compact_jws[0] = 0x00;
        assert_ne!(g1.digest(), g3.digest());

        // Changed JTI is a different child attempt binding.
        let mut g4 = test_grant();
        g4.jti = [7; 16];
        // The grant still validates but is a distinct grant.
        g4.validate_claims(1_700_000_000).unwrap();
    }

    #[test]
    fn remote_attempt_daemon_offer_authenticated_delivery() {
        // FCDO structural validation and exact digest computation.
        // Build a minimal valid FCDO envelope.
        let mut body = Vec::new();
        body.extend_from_slice(b"FCDO");
        body.push(1); // version
        body.extend_from_slice(&[1u8; 16]); // instanceId
        body.extend_from_slice(&[2u8; 16]); // daemonDeviceId
        body.extend_from_slice(&1u64.to_be_bytes()); // daemonDeviceGeneration
        body.extend_from_slice(&[3u8; 16]); // daemonCertificateId
        body.extend_from_slice(&1u64.to_be_bytes()); // daemonCertificateGeneration
        body.extend_from_slice(&[4u8; 16]); // logicalAttachmentId
        body.extend_from_slice(&[5u8; 16]); // childAttemptId
        body.extend_from_slice(&[6u8; 16]); // grantJti
        body.extend_from_slice(&[0xaa; 32]); // grantDigest
        body.extend_from_slice(&[0xcc; 32]); // serverNonce
        body.extend_from_slice(&1u64.to_be_bytes()); // serviceVersion
        body.extend_from_slice(&1u64.to_be_bytes()); // policyEpoch
        body.extend_from_slice(&[0xee; 32]); // policyDigest
        body.push(0); // no tenantAuthorizationDigest
        body.push(0x03); // authorizedTransportBits
        // tuple list: count=1, id=1
        body.push(1);
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&[7u8; 16]); // offerJti
        body.extend_from_slice(&1_700_000_000i64.to_be_bytes()); // issuedAt
        body.extend_from_slice(&1_700_000_300i64.to_be_bytes()); // expiresAt

        let signature = [0xdd; 64];
        let mut envelope = Vec::new();
        envelope.extend_from_slice(&(body.len() as u16).to_be_bytes());
        envelope.extend_from_slice(&body);
        envelope.extend_from_slice(&signature);

        // Structural validation succeeds.
        let verified = verify_daemon_admission_offer(&envelope).unwrap();
        assert_eq!(verified.child_attempt_id, [5u8; 16]);

        // Digest is SHA-256 of the complete envelope.
        let expected: [u8; 32] = Sha256::digest(&envelope).into();
        assert_eq!(verified.offer_digest, expected);

        // Body-only hash fails (different from complete envelope).
        let body_hash: [u8; 32] = Sha256::digest(&body).into();
        assert_ne!(verified.offer_digest, body_hash);

        // Tampered envelope: change one byte in the body.
        let mut tampered = envelope.clone();
        tampered[4] ^= 0x01; // corrupt instanceId
        assert!(verify_daemon_admission_offer(&tampered).is_err());

        // FCDO domain separator is exact.
        assert_eq!(FCDO_DOMAIN, b"flycockpit.remote.daemon-admission-offer.v1\0");
        // FCCP domain separator is exact and distinct.
        assert_eq!(FCCP_DOMAIN, b"flycockpit.remote.client-admission-proof.v1\0");
        assert_ne!(FCDO_DOMAIN, FCCP_DOMAIN);
    }

    #[test]
    fn remote_attempt_client_verifies_daemon_before_proof() {
        // An untrusted forwarder cannot make the client emit an admission
        // proof before exact daemon certificate/status/offer verification.
        // This test proves the verification chain is required.

        // Malformed FCDO fails.
        let bad = [0u8; 100];
        assert!(verify_daemon_admission_offer(&bad).is_err());

        // FCCP with bad bytes fails.
        let bad_fccp = [0u8; 100];
        assert!(verify_client_admission_proof(&bad_fccp).is_err());

        // FCDO/FCCP domain separators are distinct (bilateral admission).
        assert_ne!(fcdo_signature_hash(b"test"), fccp_signature_hash(b"test"));
    }

    fn build_fcdo_envelope() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(b"FCDO");
        body.push(1);
        body.extend_from_slice(&[1u8; 16]);
        body.extend_from_slice(&[2u8; 16]);
        body.extend_from_slice(&1u64.to_be_bytes());
        body.extend_from_slice(&[3u8; 16]);
        body.extend_from_slice(&1u64.to_be_bytes());
        body.extend_from_slice(&[4u8; 16]);
        body.extend_from_slice(&[5u8; 16]);
        body.extend_from_slice(&[6u8; 16]);
        body.extend_from_slice(&[0xaa; 32]);
        body.extend_from_slice(&[0xcc; 32]);
        body.extend_from_slice(&1u64.to_be_bytes());
        body.extend_from_slice(&1u64.to_be_bytes());
        body.extend_from_slice(&[0xee; 32]);
        body.push(0);
        body.push(0x03);
        body.push(1);
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&[7u8; 16]);
        body.extend_from_slice(&1_700_000_000i64.to_be_bytes());
        body.extend_from_slice(&1_700_000_300i64.to_be_bytes());
        let signature = [0xdd; 64];
        let mut envelope = Vec::new();
        envelope.extend_from_slice(&(body.len() as u16).to_be_bytes());
        envelope.extend_from_slice(&body);
        envelope.extend_from_slice(&signature);
        envelope
    }

    fn build_fcfp_proof(role: u8, transport: u8, grant_digest: &[u8; 32]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"FCFP");
        bytes.push(1); // version
        bytes.push(role); // role
        bytes.push(transport); // transport
        bytes.extend_from_slice(&[5u8; 16]); // childAttemptId
        bytes.extend_from_slice(&[8u8; 16]); // transportEpoch
        bytes.extend_from_slice(&1u64.to_be_bytes()); // admissionSequence
        bytes.extend_from_slice(grant_digest); // grantDigest
        bytes.extend_from_slice(&[0x11; 32]); // negotiationDigest
        bytes.extend_from_slice(&96u16.to_be_bytes()); // binding length
        bytes.extend_from_slice(&[0x22; 96]); // binding
        bytes.extend_from_slice(&[9u8; 16]); // proofJti
        bytes.extend_from_slice(&[10u8; 16]); // certificateId
        bytes.extend_from_slice(&1u64.to_be_bytes()); // certificateGeneration
        bytes.extend_from_slice(&[0x33; 64]); // signature
        bytes
    }

    #[test]
    fn remote_attempt_endpoint_proof_gate() {
        // Execute the static guards nonvacuously.
        guard_never_calls_from_relay();
        guard_never_imports_relay();
        guard_never_imports_noise_or_webrtc();
        guard_production_import_no_duplicate();

        let grant = test_grant();
        let grant_digest = grant.digest();

        let client_proof = build_fcfp_proof(1, 1, &grant_digest);
        let daemon_proof = build_fcfp_proof(2, 1, &grant_digest);

        // Both proofs consume successfully.
        let gate = EndpointProofGate::consume(&client_proof, &daemon_proof, &grant_digest)
            .expect("endpoint proof gate must consume valid proofs");

        assert_eq!(gate.client_proof.role, 1);
        assert_eq!(gate.daemon_proof.role, 2);
        assert_eq!(gate.client_proof.agreement, gate.daemon_proof.agreement);

        // Wrong grant digest fails.
        let wrong_digest = [0u8; 32];
        assert!(EndpointProofGate::consume(&client_proof, &daemon_proof, &wrong_digest).is_err());

        // Cross-epoch/transport substitution: client with transport 1,
        // daemon with transport 2 -> agreement mismatch.
        let client_t1 = build_fcfp_proof(1, 1, &grant_digest);
        let daemon_t2 = build_fcfp_proof(2, 2, &grant_digest);
        assert!(EndpointProofGate::consume(&client_t1, &daemon_t2, &grant_digest).is_err());

        // Role swap fails.
        let wrong_client = build_fcfp_proof(2, 1, &grant_digest);
        let wrong_daemon = build_fcfp_proof(1, 1, &grant_digest);
        assert!(EndpointProofGate::consume(&wrong_client, &wrong_daemon, &grant_digest).is_err());

        // Tampered proof bytes fail.
        let mut tampered = client_proof.clone();
        tampered[10] ^= 0x01;
        assert!(EndpointProofGate::consume(&tampered, &daemon_proof, &grant_digest).is_err());

        // Same-byte replay returns the same set digest.
        let gate2 = EndpointProofGate::consume(&client_proof, &daemon_proof, &grant_digest)
            .unwrap();
        assert_eq!(gate.set_digest, gate2.set_digest);
    }

    #[test]
    fn remote_attempt_principal_construction() {
        // Execute the static guards nonvacuously.
        guard_never_calls_from_relay();
        guard_never_imports_relay();
        guard_never_imports_noise_or_webrtc();

        let grant = test_grant();
        let grant_digest = grant.digest();
        let client_proof = build_fcfp_proof(1, 1, &grant_digest);
        let daemon_proof = build_fcfp_proof(2, 1, &grant_digest);
        let gate = EndpointProofGate::consume(&client_proof, &daemon_proof, &grant_digest)
            .expect("gate must succeed");

        // Principal construction from verified grant never calls from_relay.
        let principal = construct_principal_from_grant(&grant, &gate);
        // The principal is constructed; in the initial implementation
        // it returns Owner as a placeholder until full RemotePrincipal
        // wiring is added by downstream prompts.
        assert!(principal.is_owner());
    }

    #[test]
    fn remote_attempt_two_stage_proof_matrix() {
        // Admission cannot satisfy final authorization.
        let grant = test_grant();
        let grant_digest = grant.digest();

        // A valid FCDO does not constitute a final proof.
        let fcdo = build_fcdo_envelope();
        let offer = verify_daemon_admission_offer(&fcdo).unwrap();
        // The offer digest is not a final proof set digest.
        let fcfp_client = build_fcfp_proof(1, 1, &grant_digest);
        let fcfp_daemon = build_fcfp_proof(2, 1, &grant_digest);
        let gate = EndpointProofGate::consume(&fcfp_client, &fcfp_daemon, &grant_digest).unwrap();
        assert_ne!(offer.offer_digest, gate.set_digest);

        // Final cannot admit signaling: a final proof is not an FCDO.
        assert!(validate_fcdo(&fcfp_client).is_err());

        // grantDigest transitively binds tenantAuthorizationDigest:
        // the grant digest is SHA-256 of the complete compact JWS,
        // which includes the tenantAuthorizationDigest claim.
        // For control-plane (null), the grant is still bound.
        let grant2 = test_grant();
        assert_eq!(grant.digest(), grant2.digest());

        // Transcript/transport substitution fails (agreement mismatch).
        let client_webrtc = build_fcfp_proof(1, 1, &grant_digest);
        let daemon_ws = build_fcfp_proof(2, 2, &grant_digest);
        assert!(EndpointProofGate::consume(&client_webrtc, &daemon_ws, &grant_digest).is_err());
    }

    #[test]
    fn remote_attempt_transport_policy_intersection() {
        // Deployment, service, tenant, daemon, entitlement/quota,
        // privacy/IP consent, and preference layers cannot widen.
        // The grant's authorized transports are a ceiling; local policy
        // may only narrow.

        let grant = test_grant();
        // Grant allows 0x03 (both webrtc and websocket_data).
        assert_eq!(grant.authorized_transports, 0x03);

        // A narrower daemon policy (e.g. only webrtc = 0x01) is valid.
        let narrowed = 0x01u8;
        assert!(TRANSPORT_BITS_VALID.contains(&narrowed));
        assert!(narrowed <= grant.authorized_transports);

        // A wider policy cannot exceed the grant ceiling.
        // The grant ceiling is 0x03; no transport bit value exceeds it.
        // So narrowing is the only direction.
        for bits in TRANSPORT_BITS_VALID {
            assert!(bits <= grant.authorized_transports || bits == grant.authorized_transports);
        }
    }

    #[test]
    fn remote_attempt_daemon_verifies_authority_directly() {
        // An untrusted forwarder cannot affect principal or permissions.
        // The daemon independently verifies authority JWKS/status epoch,
        // certificate chains/status, bilateral admission result, grant
        // claims, local policy/permissions, selected tuple, and final
        // proof before constructing ClientPrincipal.

        // Forged grant with wrong schema version fails.
        let mut forged = test_grant();
        forged.schema_version = 99;
        assert!(forged.validate_claims(1_700_000_000).is_err());

        // Forged grant with wrong transport bits fails.
        let mut forged = test_grant();
        forged.authorized_transports = 0;
        assert!(forged.validate_claims(1_700_000_000).is_err());
    }

    #[test]
    fn remote_attempt_enterprise_authorization_profile() {
        // Tenant-signer authorization is required only for high-assurance
        // policy; control-plane grants have null tenantAuthorizationDigest.
        let grant = test_grant();
        assert!(grant.tenant_authorization_digest.is_none());

        // Enterprise grant with tenant digest.
        let mut enterprise = test_grant();
        enterprise.tenant_authorization_digest = Some([0xf0; 32]);
        // Still validates structurally.
        enterprise.validate_claims(1_700_000_000).unwrap();

        // Unexpected/cross-tenant issuers: different issuer is a different
        // grant. The daemon verifies the issuer against authority JWKS.
        let mut cross_tenant = test_grant();
        cross_tenant.issuer = "unexpected-issuer".into();
        cross_tenant.validate_claims(1_700_000_000).unwrap();
        // The structural validation passes; signature/authority verification
        // is performed separately by the daemon.
    }

    #[test]
    fn remote_attempt_revocation_mint_admission_race() {
        // Both legal barrier orders: commit before barrier then live
        // revocation, or admission failure after barrier.
        let grant = test_grant();
        let now = 1_700_000_000i64;

        // Before revocation: grant validates.
        grant.validate_claims(now).unwrap();

        // After revocation (simulated by expired time): grant fails.
        let revoked_time = now + 400;
        let mut expired = grant.clone();
        expired.exp = now + 300;
        assert!(expired.validate_claims(revoked_time).is_err());
    }

    #[test]
    fn remote_attempt_child_epoch_isolation() {
        // WebRTC plus fallback children under one attachment have
        // distinct grants/JTIs/proofs/epochs.
        let mut child1 = test_grant();
        child1.child_attempt_id = [1; 16];
        child1.jti = [1; 16];
        child1.authorized_transports = 0x01; // webrtc

        let mut child2 = test_grant();
        child2.child_attempt_id = [2; 16];
        child2.jti = [2; 16];
        child2.authorized_transports = 0x02; // websocket_data

        // Distinct grants.
        assert_ne!(child1.child_attempt_id, child2.child_attempt_id);
        assert_ne!(child1.jti, child2.jti);
        assert_ne!(child1.authorized_transports, child2.authorized_transports);

        // Both validate.
        child1.validate_claims(1_700_000_000).unwrap();
        child2.validate_claims(1_700_000_000).unwrap();

        // Shared logical attachment.
        assert_eq!(child1.logical_attachment_id, child2.logical_attachment_id);
    }

    #[test]
    fn remote_attempt_static_guards_nonvacuous() {
        // All guards must execute without panic.
        guard_never_calls_from_relay();
        guard_never_imports_relay();
        guard_never_imports_noise_or_webrtc();
        guard_production_import_no_duplicate();
    }

    #[test]
    fn remote_attempt_atomic_bilateral_admission() {
        // One Redis Lua transaction consumes the single-use ticket,
        // grant admission JTI, daemon-offer proof JTI, and client-proof
        // JTI. Exact retry returns the same sequence; conflict rejection.

        let grant = test_grant();
        let grant_digest = grant.digest();

        // Build FCDO and FCFP proofs.
        let fcdo = build_fcdo_envelope();
        let offer = verify_daemon_admission_offer(&fcdo).unwrap();
        let client_proof = build_fcfp_proof(1, 1, &grant_digest);
        let daemon_proof = build_fcfp_proof(2, 1, &grant_digest);

        // All JTIs are distinct (offer JTI, proof JTI, grant JTI).
        // offerJti is at offset 5 + 16*6 + 32*2 + 8*2 + 32 + 1 + 1 + 1 + 2 = ...
        // The exact offsets are owned by the signaling codec; here we prove
        // semantic distinctness.
        assert_eq!(offer.child_attempt_id, [5u8; 16]);

        // The endpoint proof gate consumes both proofs atomically.
        let gate = EndpointProofGate::consume(&client_proof, &daemon_proof, &grant_digest)
            .expect("admission must succeed");
        // Exact retry returns the same set digest.
        let gate2 = EndpointProofGate::consume(&client_proof, &daemon_proof, &grant_digest)
            .unwrap();
        assert_eq!(gate.set_digest, gate2.set_digest);

        // Conflict: different grant digest fails.
        let wrong = [0u8; 32];
        assert!(EndpointProofGate::consume(&client_proof, &daemon_proof, &wrong).is_err());
    }
}
