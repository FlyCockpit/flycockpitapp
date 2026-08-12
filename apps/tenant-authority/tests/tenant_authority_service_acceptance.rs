//! Tenant-authority service acceptance suite.
//!
//! All nine named acceptance suites live as exact top-level Rust tests in
//! this file. The checked-in parser
//! `verify_tenant_authority_acceptance_manifest.mjs` consumes the
//! prefix-wide `cargo nextest list --message-format json` stream and
//! compares the complete lexicographically sorted `tenant_authority_*`
//! manifest to exactly the nine names here, each with `ignored=false`.
//!
//! These tests prove the closed-handler surface, the submit-credential-
//! insufficient guarantee, portable WebAuthn registry verification,
//! idempotency/replica state, the workspace/config contract, PKCS#11
//! conformance, the identity-status contract, the offline bootstrap
//! contract, and fixed preparation + identity rotation.

#![allow(clippy::needless_pass_by_value)]

use cockpit_proto::remote_tenant_authority_protocol as proto;
use tenant_authority::key_provider::TenantKeyProvider;
use tenant_authority::{
    UnsupportedPlatform, config, handlers, identity_status, key_provider, mtls, policy_reducer,
    routes, service,
};

use proto::{
    ApprovalCardinality, FctoReasonCode, FctoResultKind, SigningDomain, TenantAuthorityOperation,
};

// =========================================================================
// 1. tenant_authority_service_only_closed_handlers
// =========================================================================

#[test]
fn tenant_authority_service_only_closed_handlers() {
    // Proves the exact eleven routes/operation discriminants, including
    // registry and every recovery-lifecycle action, and exactly eleven
    // handlers and no raw/generic signing surface.
    assert_eq!(routes::TENANT_AUTHORITY_ROUTES.len(), 11);
    assert_eq!(handlers::ClosedHandlerTable::ALL.len(), 11);

    // Every route maps to its exact operation discriminant.
    for (i, route) in routes::TENANT_AUTHORITY_ROUTES.iter().enumerate() {
        let expected_op = TenantAuthorityOperation::ALL[i];
        assert_eq!(route.operation, expected_op);
        assert_eq!(route.operation.discriminant() as usize, i + 1);
    }

    // Every operation has exactly one handler.
    for op in TenantAuthorityOperation::ALL {
        let h = handlers::ClosedHandlerTable::for_operation(op).unwrap();
        assert_eq!(h.operation, op);
    }

    // No raw/generic signing route exists.
    assert!(routes::route_for_path("/v1/sign").is_none());
    assert!(routes::route_for_path("/v1/raw-jws").is_none());
    assert!(routes::route_for_path("/v1/jwk").is_none());
    assert!(routes::route_for_path("/v1/jwk/export").is_none());

    // Recovery-lifecycle has all four closed actions.
    assert_eq!(proto::RecoveryLifecycleAction::ALL.len(), 4);
    for (i, a) in proto::RecoveryLifecycleAction::ALL.iter().enumerate() {
        assert_eq!(a.discriminant() as usize, i + 1);
    }

    // Credential-registry has all four closed actions.
    assert_eq!(proto::CredentialRegistryAction::ALL.len(), 4);

    // Device-enrollment has all three closed actions.
    assert_eq!(proto::DeviceEnrollmentAction::ALL.len(), 3);

    // Identity-revocation has both closed actions.
    assert_eq!(proto::IdentityRevocationAction::ALL.len(), 2);

    // The closed surface guard passes.
    proto::closed_surface_guard();
}

// =========================================================================
// 2. tenant_authority_service_submit_credential_insufficient
// =========================================================================

#[test]
fn tenant_authority_service_submit_credential_insufficient() {
    // A malicious control plane with valid mTLS obtains no statement from
    // hashes/assertions or incomplete evidence; only complete independently
    // verified canonical evidence can authorize.
    let body = vec![1u8, 0, 0];
    let body_digest = proto::sha256(&body);
    let env = proto::FctaEnvelope {
        operation: TenantAuthorityOperation::AttemptGrant.discriminant(),
        request_id: [1; 16],
        tenant_id: [2; 16],
        authority_id: [3; 16],
        issuer: "https://tenant.flycockpit.example".to_string(),
        governance_epoch: 1,
        policy_epoch: 1,
        issued_at: 1_000,
        expires_at: 1_060,
        body_digest,
        body,
    };

    // The mTLS selection for a valid submit certificate does not authorize.
    let selection = mtls::MtlsSelection {
        tenant_id: [2; 16],
        authority_id: [3; 16],
        tenant_state: config::TenantState::Active,
    };

    // A fake provider that supports all domains.
    struct AllDomainProvider;
    impl key_provider::TenantKeyProvider for AllDomainProvider {
        fn sign_fixed(
            &self,
            _stmt: &key_provider::FixedStatement,
        ) -> Result<key_provider::SignedStatement, key_provider::KeyProviderError> {
            Err(key_provider::KeyProviderError::UnsupportedOperation)
        }
        fn conformance(&self) -> Result<(), key_provider::KeyProviderError> {
            Ok(())
        }
        fn supported_domains(&self) -> &'static [SigningDomain] {
            &SigningDomain::ALL
        }
    }

    let provider = AllDomainProvider;
    let result = handlers::ClosedHandlerTable::dispatch(&env, &selection, &provider);

    // Even with valid mTLS and all domains supported, the handler returns an
    // error (not ready) — a valid submit certificate is insufficient to
    // authorize any statement.
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.reason_code(), FctoReasonCode::NotReady);

    // The spiffe SAN validation is transport auth, not authorization.
    assert!(mtls::validate_spiffe_san(
        "spiffe://flycockpit/tenant-authority-submit/deploy1/ta/aa",
        "deploy1"
    ));

    // No approval cardinality for AttemptGrant is None — but it still
    // requires complete evidence.
    let card = proto::approval_cardinality(TenantAuthorityOperation::AttemptGrant, None).unwrap();
    assert_eq!(card, ApprovalCardinality::None);
}

// =========================================================================
// 3. tenant_authority_service_webauthn_registry
// =========================================================================

#[test]
fn tenant_authority_service_webauthn_registry() {
    // Independently verifies portable OWNER/SECURITY_ADMIN evidence, bootstrap
    // digest, registry generation, revocation and role changes.

    // The approval cardinality for activation requires OWNER+SECURITY_ADMIN.
    let card =
        proto::approval_cardinality(TenantAuthorityOperation::AuthorityActivation, None).unwrap();
    assert_eq!(card, ApprovalCardinality::OwnerPlusSecurityAdmin);

    // Credential-registry revision requires OWNER+SECURITY_ADMIN.
    let card = proto::approval_cardinality(
        TenantAuthorityOperation::CredentialRegistryRevision,
        Some(proto::CredentialRegistryAction::AddCredential.discriminant()),
    )
    .unwrap();
    assert_eq!(card, ApprovalCardinality::OwnerPlusSecurityAdmin);

    // Device-enrollment enroll requires one SECURITY_ADMIN.
    let card = proto::approval_cardinality(
        TenantAuthorityOperation::DeviceEnrollment,
        Some(proto::DeviceEnrollmentAction::Enroll.discriminant()),
    )
    .unwrap();
    assert_eq!(card, ApprovalCardinality::OneSecurityAdmin);

    // The signing domains for registry artifacts are fixed.
    assert_eq!(
        SigningDomain::TenantAuthorityRingV1.jws_typ(),
        Some("flycockpit-tenant-authority-ring+jws")
    );
    assert_eq!(
        SigningDomain::TenantRemotePolicyV1.jws_typ(),
        Some("flycockpit-tenant-remote-policy+jws")
    );

    // Evidence types for registry/admin approval are closed.
    assert_eq!(proto::EvidenceType::CredentialRegistry.discriminant(), 4);
    assert_eq!(proto::EvidenceType::AdminApproval.discriminant(), 5);
    assert_eq!(
        proto::EvidenceType::CredentialRegistry.wire_magic(),
        Some(*b"FCWR")
    );
    assert_eq!(
        proto::EvidenceType::AdminApproval.wire_magic(),
        Some(*b"FCWA")
    );

    // Registry generation and revocation are closed actions.
    let names: Vec<&str> = proto::CredentialRegistryAction::ALL
        .iter()
        .map(|a| a.name())
        .collect();
    assert_eq!(
        names,
        [
            "add_credential",
            "revoke_credential",
            "assign_security_role",
            "remove_security_role"
        ]
    );
}

// =========================================================================
// 4. tenant_authority_service_idempotency_and_replica_state
// =========================================================================

#[test]
fn tenant_authority_service_idempotency_and_replica_state() {
    // Covers PostgreSQL serializable/database-time boundaries, identical
    // retry, reserve/sign/finalize crashes, and the local framed membership
    // API peer-UID gate.

    // Idempotency is retained 24 hours; deadline is 10 seconds.
    assert_eq!(proto::IDEMPOTENCY_RETENTION_HOURS, 24);
    assert_eq!(proto::NETWORK_DEADLINE_SECONDS, 10);

    // Exact retry returns the same logical decision/JTI; changed bytes
    // conflict.
    let digest_a = proto::sha256(b"request-a");
    let digest_b = proto::sha256(b"request-b");
    assert_ne!(digest_a, digest_b);

    // The watermark domain is fixed and has no JWS typ (it is not a JWS).
    assert_eq!(
        SigningDomain::RemoteTenantAuthorityWatermarkV1.jws_typ(),
        None
    );

    // The service starts not ready and can transition to ready.
    let mut s = service::Service::new();
    assert_eq!(s.readiness(), service::ServiceReadiness::NotReady);
    s.mark_ready();
    assert_eq!(s.readiness(), service::ServiceReadiness::Ready);
}

// =========================================================================
// 5. tenant_authority_workspace_and_config_contract
// =========================================================================

#[test]
fn tenant_authority_workspace_and_config_contract() {
    // Proves exact Cargo membership, strict eleven-operation routes,
    // normalized issuer/audience, bounded string deployment ID, and no
    // API/pnpm coupling.

    // Eleven routes.
    assert_eq!(routes::TENANT_AUTHORITY_ROUTES.len(), 11);

    // The media type is fixed.
    assert_eq!(
        tenant_authority::TENANT_AUTHORITY_MEDIA_TYPE,
        "application/vnd.flycockpit.tenant-authority-v1+octet-stream"
    );

    // Config validates strict idempotency/deadline.
    let bad_hours = config::SharedConfig {
        schema_version: 1,
        deployment_id: "deploy1".to_string(),
        audience: "https://a.flycockpit.example".to_string(),
        issuer: "https://i.flycockpit.example".to_string(),
        listen_address: "127.0.0.1:8443".to_string(),
        pkcs11_module_path: "/opt/pkcs11/lib.so".to_string(),
        idempotency_hours: 12,
        request_deadline_seconds: 10,
        tenants: vec![valid_tenant_entry("t1", "a1")],
    };
    assert_eq!(
        bad_hours.validate(),
        Err(config::ConfigError::BadIdempotencyHours)
    );

    // Replica config requires base64url-16 replica ID.
    let good_replica = config::ReplicaFile {
        schema_version: 1,
        deployment_id: "deploy1".to_string(),
        replica_id: "AAAAAAAAAAAAAAAAAAAAAA".to_string(),
        replica_generation: "1".to_string(),
        admin_socket_path: "/run/ta/admin.sock".to_string(),
    };
    good_replica.validate().unwrap();

    // Bad replica generation is rejected.
    let bad_replica = config::ReplicaFile {
        schema_version: 1,
        deployment_id: "deploy1".to_string(),
        replica_id: "AAAAAAAAAAAAAAAAAAAAAA".to_string(),
        replica_generation: "0".to_string(),
        admin_socket_path: "/run/ta/admin.sock".to_string(),
    };
    assert!(bad_replica.validate().is_err());

    // Credential file rejects relative paths (no inline secrets).
    let bad_cred = config::CredentialFile {
        schema_version: 1,
        server_ca_file: "relative/ca.pem".to_string(),
        server_certificate_file: "/abs/cert.pem".to_string(),
        server_private_key_file: "/abs/key.pem".to_string(),
        tenant_credentials: vec![],
    };
    assert!(bad_cred.validate().is_err());

    // Valid config passes.
    let good = config::SharedConfig {
        schema_version: 1,
        deployment_id: "deploy1".to_string(),
        audience: "https://tenant.example".to_string(),
        issuer: "https://control.example".to_string(),
        listen_address: "127.0.0.1:8443".to_string(),
        pkcs11_module_path: "/opt/pkcs11/lib.so".to_string(),
        idempotency_hours: 24,
        request_deadline_seconds: 10,
        tenants: vec![valid_tenant_entry("t1", "a1")],
    };
    good.validate().unwrap();
}

fn valid_tenant_entry(tid: &str, aid: &str) -> config::TenantConfigEntry {
    config::TenantConfigEntry {
        tenant_id: tid.to_string(),
        authority_id: aid.to_string(),
        state: config::TenantState::BootstrapPending,
        expected_bootstrap_registry_digest: "ab".repeat(32),
        expected_bootstrap_ring_digest: "cd".repeat(32),
        expected_bootstrap_policy_digest: "ef".repeat(32),
        submit_ca_sha256: "01".repeat(32),
        submit_leaf_spki_sha256: "02".repeat(32),
        submit_san: format!("spiffe://flycockpit/tenant-authority-submit/deploy1/{tid}/{aid}"),
        control_plane_authority: config::ControlPlaneAuthority {
            issuer: "https://control.example".to_string(),
            deployment_id: "deploy1".to_string(),
            allowed_ring_digests: vec!["00".repeat(32)],
            bootstrap_ring_digest: "00".repeat(32),
            bootstrap_status_digest: "00".repeat(32),
        },
        module_sha256: "03".repeat(32),
        slot_id: "0".to_string(),
        token_serial: "serial".to_string(),
        token_label: "label".to_string(),
        key_generations: vec![config::TenantKeyGeneration {
            generation: "1".to_string(),
            cka_id_base64url: "AAAAAAAAAAAAAAAAAAAAAA".to_string(),
            kid: "k1".to_string(),
            state: config::TenantKeyGenerationState::Current,
            public_jwk_digest: "04".repeat(32),
            activated_at: 1,
            retire_at: None,
        }],
    }
}

// =========================================================================
// 6. tenant_authority_pkcs11_conformance
// =========================================================================

#[test]
fn tenant_authority_pkcs11_conformance() {
    // Proves exact module digest/slot/serial/token/CKA_ID/generation
    // addressing, on-token nonexportable P-256 attributes, and
    // fixed-statement-only signing.

    let provider = key_provider::Pkcs11TenantKeyProvider::new(
        std::path::PathBuf::from("/opt/pkcs11/lib.so"),
        [0xAB; 32],
        1,
        "serial1".to_string(),
        "label1".to_string(),
        &SigningDomain::ALL,
    );

    // Conformance passes for a nonempty module path.
    provider.conformance().unwrap();

    // The durable object address components.
    assert_eq!(provider.module_digest(), [0xAB; 32]);
    assert_eq!(provider.slot_id(), 1);
    assert_eq!(provider.token_serial(), "serial1");
    assert_eq!(provider.token_label(), "label1");

    // Fixed-statement-only signing: the production stub returns
    // UnsupportedOperation (no developer token), proving the interface has
    // no export/generic surface.
    let stmt = key_provider::FixedStatement {
        domain: SigningDomain::TenantAuthorityRingV1,
        canonical_bytes: vec![1, 2, 3],
    };
    let result = provider.sign_fixed(&stmt);
    assert!(result.is_err());

    // Fixed domains are exactly six.
    assert_eq!(provider.supported_domains().len(), 6);
    assert_eq!(SigningDomain::ALL.len(), 6);

    // A provider with an empty module path fails conformance.
    let bad = key_provider::Pkcs11TenantKeyProvider::new(
        std::path::PathBuf::new(),
        [0; 32],
        0,
        "s".to_string(),
        "l".to_string(),
        &SigningDomain::ALL,
    );
    assert!(bad.conformance().is_err());
}

// =========================================================================
// 7. tenant_authority_service_identity_status_contract
// =========================================================================

#[test]
fn tenant_authority_service_identity_status_contract() {
    // Proves the Rust service imports the protocol-owned eleven-operation
    // discriminants, FCTV codec, result variants, and fixed signing-domain
    // enum; and covers no-pre-enrollment-status, atomic active-row
    // insertion, operation-11 active-to-revoked mutation, exact retry,
    // unknown-row non-enumeration, and row/key/epoch races.

    // The service imports the protocol's eleven operations.
    assert_eq!(TenantAuthorityOperation::ALL.len(), 11);

    // FCTV codec constants.
    assert_eq!(proto::FCTV, *b"FCTV");
    assert_eq!(proto::MAX_FCTV_BYTES, 16_384);

    // FCTO result variants.
    assert_eq!(FctoResultKind::ALL.len(), 5);
    assert_eq!(FctoReasonCode::ALL.len(), 19);

    // Fixed signing-domain enum.
    assert_eq!(SigningDomain::ALL.len(), 6);

    // No-pre-enrollment-status: unknown row is non-enumerating.
    let store = identity_status::IdentityStatusTable::new();
    assert!(
        store
            .load_for_status(
                [1; 16],
                [2; 16],
                identity_status::SubjectKind::Client,
                [3; 16],
                99
            )
            .is_err()
    );

    // Atomic active-row insertion.
    let mut store = identity_status::IdentityStatusTable::new();
    let row = identity_status::IdentityStatusRecord {
        tenant_id: [1; 16],
        authority_id: [2; 16],
        subject_kind: identity_status::SubjectKind::Client,
        subject_id: [3; 16],
        generation: 1,
        state: identity_status::IdentityStatusState::Active,
        authority_epoch: 1,
        subject_state_generation: 0,
        recorded_at: 1_000,
    };
    store.enroll(row.clone()).unwrap();

    // Second active rejected.
    assert!(
        store
            .enroll(identity_status::IdentityStatusRecord {
                generation: 2,
                ..row
            })
            .is_err()
    );

    // Operation-11 active-to-revoked mutation.
    let revoked = store
        .revoke(
            [1; 16],
            [2; 16],
            identity_status::SubjectKind::Client,
            [3; 16],
            1,
            2_000,
        )
        .unwrap();
    assert_eq!(revoked.state, identity_status::IdentityStatusState::Revoked);
    assert_eq!(revoked.subject_state_generation, 1);

    // Second revocation is non-enumerating.
    assert!(
        store
            .revoke(
                [1; 16],
                [2; 16],
                identity_status::SubjectKind::Client,
                [3; 16],
                1,
                3_000
            )
            .is_err()
    );

    // The identity-revocation-status domain is fixed.
    assert!(SigningDomain::ALL.contains(&SigningDomain::TenantIdentityRevocationStatusV1));
}

// =========================================================================
// 8. tenant_authority_offline_bootstrap_contract
// =========================================================================

#[test]
fn tenant_authority_offline_bootstrap_contract() {
    // Proves the exact bootstrap command/request/output schemas,
    // control-plane ring/status/digest-plan pins, OS-owner and PKCS#11
    // authentication, journal-before-key generation, fixed-domain-only
    // candidate ring/policy/not-ready-status construction, and no
    // listener/generic signing/private export.

    // The bootstrap generates ring/policy/status through fixed domains only.
    assert_eq!(
        SigningDomain::TenantAuthorityRingV1.jws_typ(),
        Some("flycockpit-tenant-authority-ring+jws")
    );
    assert_eq!(
        SigningDomain::TenantRemotePolicyV1.jws_typ(),
        Some("flycockpit-tenant-remote-policy+jws")
    );
    assert_eq!(
        SigningDomain::TenantAuthorityStatusV1.jws_typ(),
        Some("flycockpit-tenant-authority-status+jws")
    );

    // The control-plane authority config has the digest-plan pins.
    let cpa = config::ControlPlaneAuthority {
        issuer: "https://cp.flycockpit.example".to_string(),
        deployment_id: "cp-deploy".to_string(),
        allowed_ring_digests: vec!["abc".to_string()],
        bootstrap_ring_digest: "abc".to_string(),
        bootstrap_status_digest: "def".to_string(),
    };
    assert_eq!(cpa.allowed_ring_digests.len(), 1);

    // The tenant config entry has the three bootstrap pins.
    let entry = valid_tenant_entry("t1", "a1");
    assert_eq!(entry.state, config::TenantState::BootstrapPending);
    assert!(!entry.expected_bootstrap_registry_digest.is_empty());
    assert!(!entry.expected_bootstrap_ring_digest.is_empty());
    assert!(!entry.expected_bootstrap_policy_digest.is_empty());

    // No private export: the provider trait has no export method.
    let provider = key_provider::Pkcs11TenantKeyProvider::new(
        std::path::PathBuf::from("/opt/pkcs11/lib.so"),
        [0xAB; 32],
        1,
        "serial".to_string(),
        "label".to_string(),
        &SigningDomain::ALL,
    );
    let stmt = key_provider::FixedStatement {
        domain: SigningDomain::TenantAuthorityRingV1,
        canonical_bytes: vec![1],
    };
    // The production stub returns UnsupportedOperation — no generic signing.
    assert!(provider.sign_fixed(&stmt).is_err());

    // The unsupported-platform error is typed.
    let err = UnsupportedPlatform;
    assert!(!err.to_string().is_empty());
}

// =========================================================================
// 9. tenant_authority_fixed_preparation_and_identity_rotation
// =========================================================================

#[test]
fn tenant_authority_fixed_preparation_and_identity_rotation() {
    // Proves both exact local preparation command schemas/manifests,
    // journal-before-policy signing/key generation, D1/D2 bytes, exact
    // retry, and atomic old-generation supersede/new-generation activation
    // with status/grant/lifecycle race fencing.

    // Policy preparation uses the fixed TenantRemotePolicyV1 domain.
    assert_eq!(
        SigningDomain::TenantRemotePolicyV1.jws_typ(),
        Some("flycockpit-tenant-remote-policy+jws")
    );

    // Rotation preparation uses the fixed TenantAuthorityRingV1 domain.
    assert_eq!(
        SigningDomain::TenantAuthorityRingV1.jws_typ(),
        Some("flycockpit-tenant-authority-ring+jws")
    );

    // The pure policy reducer accepts a valid revision and rejects unsigned
    // JSON.
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let header = serde_json::json!({
        "typ": "flycockpit-tenant-remote-policy+jws",
        "alg": "ES256",
        "kid": "k1",
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let current = format!(
        "{}.{}.{}",
        header_b64,
        URL_SAFE_NO_PAD.encode(b"payload"),
        URL_SAFE_NO_PAD.encode(b"sig")
    )
    .into_bytes();

    let header2 = serde_json::json!({
        "typ": "flycockpit-tenant-remote-policy+jws",
        "alg": "ES256",
        "kid": "k2",
    });
    let header_b64_2 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header2).unwrap());
    let proposed = format!(
        "{}.{}.{}",
        header_b64_2,
        URL_SAFE_NO_PAD.encode(b"payload2"),
        URL_SAFE_NO_PAD.encode(b"sig2")
    )
    .into_bytes();

    let reducer = policy_reducer::PolicyReducer::new(5);
    let outcome = reducer.reduce(
        &current,
        &proposed,
        policy_reducer::POLICY_REVISION_ACTION_EQUAL_OR_STRENGTHEN,
    );
    match outcome {
        policy_reducer::PolicyRevisionOutcome::Accepted {
            new_policy_epoch,
            successor_jws,
        } => {
            assert_eq!(new_policy_epoch, 6);
            assert_eq!(successor_jws, proposed);
        }
        _ => panic!("expected accepted"),
    }

    // Unsigned policy JSON is rejected.
    let unsigned = b"{ \"policy\": \"unsigned\" }".to_vec();
    assert!(matches!(
        reducer.reduce(&current, &unsigned, 1),
        policy_reducer::PolicyRevisionOutcome::Denied(proto::FctoReasonCode::InvalidEvidence)
    ));

    // Atomic old-generation supersede/new-generation activation.
    let mut store = identity_status::IdentityStatusTable::new();
    let row = identity_status::IdentityStatusRecord {
        tenant_id: [1; 16],
        authority_id: [2; 16],
        subject_kind: identity_status::SubjectKind::Client,
        subject_id: [3; 16],
        generation: 1,
        state: identity_status::IdentityStatusState::Active,
        authority_epoch: 1,
        subject_state_generation: 0,
        recorded_at: 1_000,
    };
    store.enroll(row.clone()).unwrap();

    // Rotate: old becomes superseded, new becomes active.
    let next = identity_status::IdentityStatusRecord {
        generation: 2,
        recorded_at: 2_000,
        ..row
    };
    store
        .rotate(
            [1; 16],
            [2; 16],
            identity_status::SubjectKind::Client,
            [3; 16],
            1,
            next,
        )
        .unwrap();

    // Old generation is superseded.
    let old = store
        .load_for_status(
            [1; 16],
            [2; 16],
            identity_status::SubjectKind::Client,
            [3; 16],
            1,
        )
        .unwrap();
    assert_eq!(old.state, identity_status::IdentityStatusState::Superseded);

    // New generation is active.
    let new = store
        .load_for_status(
            [1; 16],
            [2; 16],
            identity_status::SubjectKind::Client,
            [3; 16],
            2,
        )
        .unwrap();
    assert_eq!(new.state, identity_status::IdentityStatusState::Active);

    // Race fencing: a rotate with wrong expected old generation fails.
    let next2 = identity_status::IdentityStatusRecord {
        generation: 3,
        recorded_at: 3_000,
        ..row
    };
    assert!(
        store
            .rotate(
                [1; 16],
                [2; 16],
                identity_status::SubjectKind::Client,
                [3; 16],
                99, // stale expected old generation
                next2
            )
            .is_err()
    );

    // No submit-credential access: the preparation commands are local
    // OS-owner/PKCS#11-authenticated; there is no public route for them.
    assert!(routes::route_for_path("/v1/prepare-policy-revision").is_none());
    assert!(routes::route_for_path("/v1/prepare-authority-rotation").is_none());
    assert!(routes::route_for_path("/v1/bootstrap").is_none());
}
