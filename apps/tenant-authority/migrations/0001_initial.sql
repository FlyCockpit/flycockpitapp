-- Tenant-authority governance/credential/policy/revocation/quota/idempotency/
-- replica-membership/watermark-ACK, control-plane authority trust state,
-- fixed policy/rotation preparation journals, hash-chained audit, signing
-- reservations/results, and transactional outbox.
--
-- Every authorization uses SERIALIZABLE, PostgreSQL transaction time,
-- generation preconditions, and one retry classifier. Signing is
-- reserve→provider→finalize with stable request/claims bytes; nothing is
-- delivered before finalized DB state/outbox.

-- Idempotency: exact retry within 24 hours returns the same logical
-- decision/JTI; changed bytes conflict.
CREATE TABLE IF NOT EXISTS tenant_authority_idempotency (
    tenant_id BYTEA NOT NULL,
    authority_id BYTEA NOT NULL,
    request_id BYTEA NOT NULL,
    request_digest BYTEA NOT NULL,
    result_kind SMALLINT NOT NULL,
    reason_code SMALLINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, authority_id, request_id)
);

-- Authority state: highest accepted ring revision/epoch/digest/current kid
-- and highest matching status generation/bytes.
CREATE TABLE IF NOT EXISTS tenant_authority_state (
    tenant_id BYTEA NOT NULL,
    authority_id BYTEA NOT NULL,
    ring_revision BIGINT NOT NULL,
    ring_epoch BIGINT NOT NULL,
    ring_digest BYTEA NOT NULL,
    current_kid TEXT NOT NULL,
    status_generation BIGINT NOT NULL,
    status_bytes BYTEA NOT NULL,
    governance_epoch BIGINT NOT NULL,
    policy_epoch BIGINT NOT NULL,
    credential_registry_generation BIGINT NOT NULL,
    authority_database_generation BIGINT NOT NULL,
    watermark_pending BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (tenant_id, authority_id)
);

-- Signer-owned identity-status table: keyed by exact
-- (tenantId, authorityId, subjectKind, subjectId, generation) with exactly
-- one active generation per subject.
CREATE TABLE IF NOT EXISTS tenant_authority_identity_status (
    tenant_id BYTEA NOT NULL,
    authority_id BYTEA NOT NULL,
    subject_kind SMALLINT NOT NULL,
    subject_id BYTEA NOT NULL,
    generation BIGINT NOT NULL,
    status SMALLINT NOT NULL, -- 1=active, 2=superseded, 3=revoked
    authority_epoch BIGINT NOT NULL,
    subject_state_generation BIGINT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, authority_id, subject_kind, subject_id, generation)
);

-- Hash-chained audit: stores request-ID hash, operation, object digest,
-- decision class, epochs and approval references only. No body/session/
-- network/authenticator/FlyCockpit database data.
CREATE TABLE IF NOT EXISTS tenant_authority_audit (
    seq BIGSERIAL PRIMARY KEY,
    tenant_id BYTEA NOT NULL,
    authority_id BYTEA NOT NULL,
    request_id_hash BYTEA NOT NULL,
    operation SMALLINT NOT NULL,
    object_digest BYTEA NOT NULL,
    decision_class SMALLINT NOT NULL,
    governance_epoch BIGINT NOT NULL,
    policy_epoch BIGINT NOT NULL,
    approval_refs BYTEA NOT NULL,
    authority_database_generation BIGINT NOT NULL,
    prev_audit_digest BYTEA NOT NULL,
    audit_digest BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Signing reservations: reserve→provider→finalize with stable bytes.
CREATE TABLE IF NOT EXISTS tenant_authority_signing_reservation (
    reservation_id BYTEA NOT NULL PRIMARY KEY,
    tenant_id BYTEA NOT NULL,
    authority_id BYTEA NOT NULL,
    operation SMALLINT NOT NULL,
    request_digest BYTEA NOT NULL,
    state SMALLINT NOT NULL, -- 1=reserved, 2=finalized, 3=failed
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finalized_at TIMESTAMPTZ
);

-- Signing results: the finalized FCTO bytes.
CREATE TABLE IF NOT EXISTS tenant_authority_signing_result (
    reservation_id BYTEA NOT NULL PRIMARY KEY,
    result_bytes BYTEA NOT NULL,
    finalized_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Transactional outbox: nothing is delivered before finalized DB state.
CREATE TABLE IF NOT EXISTS tenant_authority_outbox (
    seq BIGSERIAL PRIMARY KEY,
    tenant_id BYTEA NOT NULL,
    authority_id BYTEA NOT NULL,
    kind TEXT NOT NULL,
    payload BYTEA NOT NULL,
    authority_database_generation BIGINT NOT NULL,
    delivered BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Replica membership: controlled only by the local admin interface.
CREATE TABLE IF NOT EXISTS tenant_authority_replica_membership (
    membership_generation BIGINT PRIMARY KEY,
    state TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Watermark ACK: keyed by
-- (membershipGeneration, replicaId, replicaGeneration, tenantId,
--  authorityId, authorityDatabaseGeneration, watermarkDigest).
CREATE TABLE IF NOT EXISTS tenant_authority_watermark_ack (
    membership_generation BIGINT NOT NULL,
    replica_id TEXT NOT NULL,
    replica_generation BIGINT NOT NULL,
    tenant_id BYTEA NOT NULL,
    authority_id BYTEA NOT NULL,
    authority_database_generation BIGINT NOT NULL,
    watermark_digest BYTEA NOT NULL,
    acked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (membership_generation, replica_id, tenant_id, authority_id)
);

-- Control-plane authority trust state.
CREATE TABLE IF NOT EXISTS tenant_authority_control_plane_trust (
    tenant_id BYTEA NOT NULL,
    authority_id BYTEA NOT NULL,
    issuer TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    allowed_ring_digests BYTEA NOT NULL,
    bootstrap_ring_digest BYTEA NOT NULL,
    bootstrap_status_digest BYTEA NOT NULL,
    current_ring_digest BYTEA NOT NULL,
    current_status_digest BYTEA NOT NULL,
    refreshed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, authority_id)
);

-- Fixed policy preparation journal.
CREATE TABLE IF NOT EXISTS tenant_authority_policy_preparation (
    preparation_id BYTEA NOT NULL PRIMARY KEY,
    tenant_id BYTEA NOT NULL,
    authority_id BYTEA NOT NULL,
    request_digest BYTEA NOT NULL,
    current_policy_digest BYTEA NOT NULL,
    candidate_policy_digest BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fixed rotation preparation journal.
CREATE TABLE IF NOT EXISTS tenant_authority_rotation_preparation (
    preparation_id BYTEA NOT NULL PRIMARY KEY,
    tenant_id BYTEA NOT NULL,
    authority_id BYTEA NOT NULL,
    request_digest BYTEA NOT NULL,
    current_ring_digest BYTEA NOT NULL,
    published_ring_digest BYTEA NOT NULL,
    promoted_ring_digest BYTEA,
    cka_id_base64url TEXT NOT NULL,
    kid TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
