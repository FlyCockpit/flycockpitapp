-- This is intentionally append-only instead of being folded into 0001: deployed
-- databases persist the SHA-256 of immutable 0001 and 0002, and amending either
-- migration makes checksum-enforcing startup reject an otherwise valid database.
-- This unreleased 0003 is finalized as one stable migration before merge.
-- Durable authority for media admission. Limits are deliberately absent:
-- every acquisition carries the evaluated config-policy plan/version.
CREATE TABLE media_reservations (
    reservation_id TEXT PRIMARY KEY,
    policy_version INTEGER NOT NULL CHECK(policy_version > 0),
    project_id TEXT NOT NULL,
    owner_session_key TEXT NOT NULL,
    operation TEXT NOT NULL,
    purpose TEXT NOT NULL,
    recovery_id TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK(state IN ('reserved_queued','executing_local','dispatching_external','external_pending','reconciling_external','cancellation_requested','overage_quarantined','settling','released','accounting_corrupt')),
    version INTEGER NOT NULL CHECK(version >= 1),
    queue_sequence INTEGER NOT NULL UNIQUE CHECK(queue_sequence >= 1),
    deadline_monotonic_ms INTEGER NOT NULL CHECK(deadline_monotonic_ms >= 0),
    created_wall_ms INTEGER NOT NULL,
    external_operation_id TEXT UNIQUE REFERENCES external_journal_operations(operation_id),
    quarantined INTEGER NOT NULL DEFAULT 0 CHECK(quarantined IN (0,1)),
    published INTEGER NOT NULL DEFAULT 0 CHECK(published IN (0,1)),
    cancellation_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancellation_requested IN (0,1))
);
CREATE INDEX idx_media_reservation_owner_purpose ON media_reservations(project_id, owner_session_key, purpose, state);
CREATE TABLE media_reservation_plan_facts (
    reservation_id TEXT NOT NULL REFERENCES media_reservations(reservation_id),
    dimension TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    PRIMARY KEY(reservation_id, dimension)
);
CREATE TRIGGER media_plan_fact_immutable_update BEFORE UPDATE ON media_reservation_plan_facts BEGIN SELECT RAISE(ABORT,'media plan facts are immutable'); END;
CREATE TRIGGER media_plan_fact_immutable_delete BEFORE DELETE ON media_reservation_plan_facts BEGIN SELECT RAISE(ABORT,'media plan facts are immutable'); END;
CREATE TABLE media_reservation_versions (
    reservation_id TEXT NOT NULL REFERENCES media_reservations(reservation_id),
    version INTEGER NOT NULL CHECK(version >= 1),
    state TEXT NOT NULL,
    recorded_wall_ms INTEGER NOT NULL,
    PRIMARY KEY(reservation_id, version)
);
CREATE TRIGGER media_reservation_version_insert AFTER INSERT ON media_reservations BEGIN
    INSERT INTO media_reservation_versions(reservation_id,version,state,recorded_wall_ms) VALUES(NEW.reservation_id,NEW.version,NEW.state,NEW.created_wall_ms);
END;
CREATE TRIGGER media_reservation_version_update AFTER UPDATE OF version ON media_reservations BEGIN
    INSERT INTO media_reservation_versions(reservation_id,version,state,recorded_wall_ms) VALUES(NEW.reservation_id,NEW.version,NEW.state,CAST(strftime('%s','now') AS INTEGER)*1000);
END;
CREATE TABLE media_queue_sequence (singleton INTEGER PRIMARY KEY CHECK(singleton=1), next_value INTEGER NOT NULL CHECK(next_value >= 1));
INSERT INTO media_queue_sequence(singleton,next_value) VALUES(1,1);
CREATE TABLE media_scheduler_cursor (singleton INTEGER PRIMARY KEY CHECK(singleton=1), last_session_id TEXT);
INSERT INTO media_scheduler_cursor(singleton,last_session_id) VALUES(1,NULL);
-- A reservation is schedulable only after its owner has finished collecting
-- input. Keeping readiness durable lets the atomic fair claimant distinguish
-- a slow upload from work that is actually waiting for an execution permit.
CREATE TABLE media_execution_ready (
    reservation_id TEXT PRIMARY KEY REFERENCES media_reservations(reservation_id),
    ready_wall_ms INTEGER NOT NULL
);
CREATE TABLE media_reservation_deltas (
    delta_id INTEGER PRIMARY KEY AUTOINCREMENT,
    reservation_id TEXT NOT NULL REFERENCES media_reservations(reservation_id),
    reservation_version INTEGER NOT NULL CHECK(reservation_version >= 1),
    dimension TEXT NOT NULL, scope_kind TEXT NOT NULL, scope_id TEXT NOT NULL,
    estimated INTEGER NOT NULL CHECK(estimated >= 0), delta INTEGER NOT NULL,
    charged_after INTEGER NOT NULL CHECK(charged_after >= 0),
    fact_kind TEXT NOT NULL CHECK(fact_kind IN ('reserve','promote','release','actual','overage','durable_invocation','cleanup')),
    created_wall_ms INTEGER NOT NULL,
    UNIQUE(reservation_id, reservation_version, dimension, fact_kind)
);
CREATE INDEX idx_media_delta_owner ON media_reservation_deltas(scope_kind, scope_id, dimension);
CREATE TRIGGER media_delta_immutable_update BEFORE UPDATE ON media_reservation_deltas BEGIN SELECT RAISE(ABORT,'media delta facts are immutable'); END;
CREATE TRIGGER media_delta_immutable_delete BEFORE DELETE ON media_reservation_deltas BEGIN SELECT RAISE(ABORT,'media delta facts are immutable'); END;
CREATE TABLE media_resource_counters (
    scope_kind TEXT NOT NULL, scope_id TEXT NOT NULL, dimension TEXT NOT NULL,
    charged INTEGER NOT NULL CHECK(charged >= 0), generation INTEGER NOT NULL CHECK(generation >= 0),
    PRIMARY KEY(scope_kind, scope_id, dimension)
);
CREATE TABLE media_accounting_blocks (
    scope_kind TEXT NOT NULL, scope_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation >= 1), reason TEXT NOT NULL,
    PRIMARY KEY(scope_kind, scope_id)
);
CREATE TABLE media_artifact_facts (
    artifact_id TEXT PRIMARY KEY, reservation_id TEXT NOT NULL REFERENCES media_reservations(reservation_id),
    dimension TEXT NOT NULL, byte_count INTEGER NOT NULL CHECK(byte_count >= 0), checksum TEXT NOT NULL,
    quarantined INTEGER NOT NULL CHECK(quarantined IN (0,1)), deletion_tombstone_checksum TEXT
);
CREATE TRIGGER media_artifact_immutable_delete BEFORE DELETE ON media_artifact_facts BEGIN SELECT RAISE(ABORT,'media artifact facts are immutable'); END;
CREATE TRIGGER media_artifact_immutable_update BEFORE UPDATE ON media_artifact_facts
WHEN NEW.artifact_id!=OLD.artifact_id OR NEW.reservation_id!=OLD.reservation_id OR NEW.dimension!=OLD.dimension OR NEW.byte_count!=OLD.byte_count OR NEW.checksum!=OLD.checksum OR NEW.quarantined!=OLD.quarantined OR OLD.deletion_tombstone_checksum IS NOT NULL OR NEW.deletion_tombstone_checksum IS NULL
BEGIN SELECT RAISE(ABORT,'media artifact facts are immutable'); END;
CREATE TABLE media_cleanup_attestations (
    reservation_id TEXT NOT NULL REFERENCES media_reservations(reservation_id), dimension TEXT NOT NULL,
    attestation_kind TEXT NOT NULL CHECK(attestation_kind='zero_materialized_or_verified_cleaned'),
    checksum TEXT NOT NULL, created_wall_ms INTEGER NOT NULL, PRIMARY KEY(reservation_id,dimension)
);
CREATE TRIGGER media_cleanup_attestation_immutable_update BEFORE UPDATE ON media_cleanup_attestations BEGIN SELECT RAISE(ABORT,'media cleanup attestations are immutable'); END;
CREATE TRIGGER media_cleanup_attestation_immutable_delete BEFORE DELETE ON media_cleanup_attestations BEGIN SELECT RAISE(ABORT,'media cleanup attestations are immutable'); END;
CREATE TABLE media_accounting_corruption_facts (
    reservation_id TEXT NOT NULL REFERENCES media_reservations(reservation_id), reservation_version INTEGER NOT NULL CHECK(reservation_version >= 1),
    dimension TEXT NOT NULL, unrepresentable_actual TEXT NOT NULL, reason TEXT NOT NULL, created_wall_ms INTEGER NOT NULL,
    PRIMARY KEY(reservation_id, reservation_version, dimension)
);
CREATE TRIGGER media_corruption_fact_immutable_update BEFORE UPDATE ON media_accounting_corruption_facts BEGIN SELECT RAISE(ABORT,'media corruption facts are immutable'); END;
CREATE TRIGGER media_corruption_fact_immutable_delete BEFORE DELETE ON media_accounting_corruption_facts BEGIN SELECT RAISE(ABORT,'media corruption facts are immutable'); END;
CREATE TABLE media_repair_attempts (
    attempt_id TEXT PRIMARY KEY, scope_kind TEXT NOT NULL, scope_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE, request_digest TEXT NOT NULL, plan_digest TEXT NOT NULL,
    expected_block_generation INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('planned','rebuilding','verifying','committed','failed')),
    outcome TEXT, current_counter_digest TEXT NOT NULL, rebuilt_counter_digest TEXT,
    created_wall_ms INTEGER NOT NULL, updated_wall_ms INTEGER NOT NULL
);
CREATE INDEX idx_media_repair_scope ON media_repair_attempts(scope_kind, scope_id, created_wall_ms);
CREATE TRIGGER media_repair_state_graph BEFORE UPDATE OF state ON media_repair_attempts WHEN NOT (
    (OLD.state='planned' AND NEW.state='rebuilding') OR (OLD.state='rebuilding' AND NEW.state='verifying') OR
    (OLD.state='verifying' AND NEW.state IN ('committed','failed')) OR OLD.state=NEW.state
) BEGIN SELECT RAISE(ABORT, 'invalid media repair state transition'); END;
CREATE TABLE media_counter_shadow (
    attempt_id TEXT NOT NULL REFERENCES media_repair_attempts(attempt_id) ON DELETE CASCADE,
    dimension TEXT NOT NULL, charged INTEGER NOT NULL CHECK(charged >= 0), PRIMARY KEY(attempt_id, dimension)
);
CREATE TABLE media_downstream_ownership (
    reservation_id TEXT PRIMARY KEY REFERENCES media_reservations(reservation_id),
    invocation_id TEXT NOT NULL,
    bound_wall_ms INTEGER NOT NULL,
    released_wall_ms INTEGER
);
CREATE INDEX idx_media_downstream_invocation ON media_downstream_ownership(invocation_id);
