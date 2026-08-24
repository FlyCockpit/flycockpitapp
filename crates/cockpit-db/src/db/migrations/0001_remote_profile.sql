-- Remote-only schema extension for the opt-in `remote` Cargo profile.
-- Applied after the complete local base schema. Object order is dependency-safe.

-- ---- sync_state ------------------------------------------------------------------------------------
-- Enterprise org-policy session log sync state. One row per control-plane
-- org/server pair. The cursor is the last session_events.seq the daemon
-- has fully considered for upload. Rows skipped by org policy filters
-- still advance the cursor so disabled event kinds do not block future
-- batches.

CREATE TABLE sync_state (
    server_url        TEXT    NOT NULL,
    org_id            TEXT    NOT NULL,
    cursor_seq        INTEGER NOT NULL DEFAULT 0,
    policy_version    TEXT,
    policy_json       TEXT,
    enabled           INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    last_synced_at_ms INTEGER,
    last_error        TEXT,
    updated_at_ms     INTEGER NOT NULL,
    PRIMARY KEY (server_url, org_id)
);

CREATE INDEX idx_sync_state_server ON sync_state (server_url, enabled);

-- ---- connector_state ---------------------------------------------------------------------------------
-- Control-plane relay connector state, one row per server/instance pair.

CREATE TABLE connector_state (
    server_url           TEXT    NOT NULL,
    instance_id          TEXT    NOT NULL,
    enabled              INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    status               TEXT    NOT NULL DEFAULT 'off' CHECK (status IN ('off', 'reconnecting', 'connected')),
    relay_url            TEXT,
    relay_id             TEXT,
    relay_region         TEXT,
    last_connected_at_ms INTEGER,
    last_error           TEXT,
    updated_at_ms        INTEGER NOT NULL,
    PRIMARY KEY (server_url, instance_id)
);

CREATE INDEX idx_connector_state_enabled ON connector_state (enabled, status);

-- ---- remote_audit_upload_state -----------------------------------------------------------------------
-- Cursor state for uploading remote-principal audit rows to the app-side
-- instance audit endpoint. The cursor is the last remote_principal_audit.audit_id
-- the daemon has fully considered for upload; poison rows that are skipped still
-- advance it so one malformed row cannot wedge the pipeline.

CREATE TABLE remote_audit_upload_state (
    server_url          TEXT    NOT NULL,
    instance_id         TEXT    NOT NULL,
    cursor_audit_id     INTEGER NOT NULL DEFAULT 0,
    last_uploaded_at_ms INTEGER,
    last_error          TEXT,
    updated_at_ms       INTEGER NOT NULL,
    PRIMARY KEY (server_url, instance_id)
);

CREATE INDEX idx_remote_audit_upload_state_server
    ON remote_audit_upload_state (server_url, instance_id);

-- ---- remote_principal_audit -----------------------------------------------------------------------------
-- Audit trail for remote-principal requests (attribution columns on
-- sessions/session_events carry the per-row provenance).

CREATE TABLE remote_principal_audit (
    audit_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms        INTEGER NOT NULL,
    principal    TEXT    NOT NULL,
    request_kind TEXT    NOT NULL,
    session_id   TEXT,
    verdict      TEXT    NOT NULL CHECK (verdict IN ('allowed', 'denied')),
    path         TEXT,                              -- path attribution for project-file audit rows
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_remote_principal_audit_ts        ON remote_principal_audit (ts_ms);
CREATE INDEX idx_remote_principal_audit_principal ON remote_principal_audit (principal, ts_ms);
CREATE INDEX idx_remote_principal_audit_path      ON remote_principal_audit (path);
CREATE INDEX idx_remote_principal_audit_session   ON remote_principal_audit (session_id);


-- ---- remote attachment operation ledger ----------------------------------
-- Canonical request bytes and transport metadata are deliberately absent.
-- The daemon retains only their SHA-256 digest and a bounded safe response.
CREATE TABLE remote_attachment_operations (
    logical_attachment_id          TEXT    NOT NULL CHECK (
        length(logical_attachment_id) = 36 AND logical_attachment_id = lower(logical_attachment_id)
        AND substr(logical_attachment_id, 9, 1) = '-' AND substr(logical_attachment_id, 14, 1) = '-'
        AND substr(logical_attachment_id, 19, 1) = '-' AND substr(logical_attachment_id, 24, 1) = '-'
        AND substr(logical_attachment_id, 20, 1) GLOB '[89ab]'
        AND length(replace(logical_attachment_id, '-', '')) = 32
        AND replace(logical_attachment_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        AND replace(logical_attachment_id, '-', '') <> '00000000000000000000000000000000'
    ),
    operation_id                   TEXT    NOT NULL CHECK (
        length(operation_id) = 36 AND operation_id = lower(operation_id)
        AND substr(operation_id, 9, 1) = '-' AND substr(operation_id, 14, 1) = '-'
        AND substr(operation_id, 15, 1) = '7'
        AND substr(operation_id, 19, 1) = '-' AND substr(operation_id, 20, 1) GLOB '[89ab]'
        AND substr(operation_id, 24, 1) = '-'
        AND length(replace(operation_id, '-', '')) = 32
        AND replace(operation_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        AND replace(operation_id, '-', '') <> '00000000000000000000000000000000'
    ),
    authenticated_device_id        TEXT    NOT NULL CHECK (
        length(authenticated_device_id) = 36 AND authenticated_device_id = lower(authenticated_device_id)
        AND substr(authenticated_device_id, 9, 1) = '-' AND substr(authenticated_device_id, 14, 1) = '-'
        AND substr(authenticated_device_id, 19, 1) = '-' AND substr(authenticated_device_id, 24, 1) = '-'
        AND substr(authenticated_device_id, 20, 1) GLOB '[89ab]'
        AND length(replace(authenticated_device_id, '-', '')) = 32
        AND replace(authenticated_device_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        AND replace(authenticated_device_id, '-', '') <> '00000000000000000000000000000000'
    ),
    authenticated_device_generation INTEGER NOT NULL CHECK (authenticated_device_generation > 0),
    operation_seq                  INTEGER NOT NULL CHECK (operation_seq > 0),
    operation_class                TEXT    NOT NULL CHECK (operation_class IN (
        'transactional_mutation', 'idempotent_adapter_mutation', 'nonrepeatable_mutation'
    )),
    operation_kind                 TEXT    NOT NULL DEFAULT 'generic' CHECK (operation_kind IN ('generic','staged_rename')),
    state                          TEXT    NOT NULL CHECK (state IN (
        'reserved', 'dispatched', 'committed', 'rejected', 'outcome_unknown'
    )),
    dispatch_generation            INTEGER NOT NULL DEFAULT 0 CHECK (dispatch_generation >= 0),
    request_hash                   BLOB    NOT NULL CHECK (length(request_hash) = 32),
    safe_response                  BLOB CHECK (safe_response IS NULL OR length(safe_response) <= 524288),
    event_high_water_mark          INTEGER CHECK (event_high_water_mark IS NULL OR event_high_water_mark >= 0),
    created_at_ms                  INTEGER NOT NULL,
    updated_at_ms                  INTEGER NOT NULL,
    retire_at_ms                   INTEGER,
    CHECK (
        (state IN ('reserved', 'dispatched') AND safe_response IS NULL AND event_high_water_mark IS NULL)
        OR (state IN ('committed', 'rejected') AND safe_response IS NOT NULL AND event_high_water_mark IS NOT NULL)
        OR (state = 'outcome_unknown' AND safe_response IS NOT NULL)
    ),
    PRIMARY KEY (logical_attachment_id, operation_id),
    UNIQUE (logical_attachment_id, operation_seq)
);

CREATE INDEX idx_remote_attachment_operations_retire
    ON remote_attachment_operations (retire_at_ms)
    WHERE retire_at_ms IS NOT NULL;

CREATE TABLE remote_attachment_lifecycle (
    logical_attachment_id TEXT PRIMARY KEY CHECK (
        length(logical_attachment_id) = 36 AND logical_attachment_id = lower(logical_attachment_id)
        AND substr(logical_attachment_id, 9, 1) = '-' AND substr(logical_attachment_id, 14, 1) = '-'
        AND substr(logical_attachment_id, 19, 1) = '-' AND substr(logical_attachment_id, 24, 1) = '-'
        AND substr(logical_attachment_id, 20, 1) GLOB '[89ab]'
        AND length(replace(logical_attachment_id, '-', '')) = 32
        AND replace(logical_attachment_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        AND replace(logical_attachment_id, '-', '') <> '00000000000000000000000000000000'
    ),
    closed_at_ms INTEGER NOT NULL CHECK(closed_at_ms >= 0),
    retain_until_ms INTEGER NOT NULL CHECK(retain_until_ms >= closed_at_ms),
    CHECK(retain_until_ms - closed_at_ms = 2592000000)
);

CREATE TRIGGER remote_attachment_lifecycle_immutable
BEFORE UPDATE ON remote_attachment_lifecycle
BEGIN
    SELECT RAISE(ABORT, 'remote attachment close authority is immutable');
END;

CREATE TABLE remote_rename_journal (
    logical_attachment_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL UNIQUE CHECK (
      length(artifact_id)=36 AND artifact_id=lower(artifact_id)
      AND substr(artifact_id,9,1)='-' AND substr(artifact_id,14,1)='-'
      AND substr(artifact_id,19,1)='-' AND substr(artifact_id,24,1)='-'
      AND substr(artifact_id,20,1) GLOB '[89ab]'
      AND length(replace(artifact_id,'-',''))=32
      AND replace(artifact_id,'-','') NOT GLOB '*[^0-9a-f]*'
      AND replace(artifact_id,'-','')<>'00000000000000000000000000000000'
    ),
    source_identity BLOB NOT NULL CHECK(length(source_identity) = 57 AND substr(source_identity,1,4)=X'52464931' AND ((substr(source_identity,29,1)=X'01' AND substr(hex(source_identity),79,1)='8') OR (substr(source_identity,29,1)=X'02' AND substr(hex(source_identity),79,1)='4')) AND substr(source_identity,50,8)<>zeroblob(8)),
    source_parent_identity BLOB NOT NULL CHECK(length(source_parent_identity) = 57 AND substr(source_parent_identity,1,4)=X'52464931' AND substr(source_parent_identity,29,1)=X'02' AND substr(hex(source_parent_identity),79,1)='4' AND substr(source_parent_identity,50,8)<>zeroblob(8)),
    target_parent_identity BLOB NOT NULL CHECK(length(target_parent_identity) = 57 AND substr(target_parent_identity,1,4)=X'52464931' AND substr(target_parent_identity,29,1)=X'02' AND substr(hex(target_parent_identity),79,1)='4' AND substr(target_parent_identity,50,8)<>zeroblob(8)),
    observed_target_identity BLOB CHECK(observed_target_identity IS NULL OR (length(observed_target_identity)=57 AND substr(observed_target_identity,1,4)=X'52464931')),
    dispatch_generation INTEGER NOT NULL CHECK(dispatch_generation > 0),
    state TEXT NOT NULL CHECK(state IN ('prepared','artifact_synced','renamed','source_parent_synced','target_parent_synced','applied','applied_mismatch','effect_unknown','ledger_committed')),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    CHECK((state='applied_mismatch') = (observed_target_identity IS NOT NULL)),
    PRIMARY KEY(logical_attachment_id,operation_id),
    FOREIGN KEY(logical_attachment_id,operation_id)
      REFERENCES remote_attachment_operations(logical_attachment_id,operation_id) ON DELETE CASCADE
);

CREATE TRIGGER remote_rename_journal_insert_authority
BEFORE INSERT ON remote_rename_journal
WHEN NOT EXISTS (
  SELECT 1 FROM remote_attachment_operations
  WHERE logical_attachment_id=NEW.logical_attachment_id
    AND operation_id=NEW.operation_id
    AND operation_kind='staged_rename'
    AND operation_class='idempotent_adapter_mutation'
    AND state='dispatched'
    AND dispatch_generation=NEW.dispatch_generation
)
BEGIN
    SELECT RAISE(ABORT, 'remote rename journal requires staged rename authority');
END;

CREATE TRIGGER remote_rename_journal_guard
BEFORE UPDATE ON remote_rename_journal
WHEN NEW.logical_attachment_id IS NOT OLD.logical_attachment_id
  OR NEW.operation_id IS NOT OLD.operation_id
  OR NEW.artifact_id IS NOT OLD.artifact_id
  OR NEW.source_identity IS NOT OLD.source_identity
  OR NEW.source_parent_identity IS NOT OLD.source_parent_identity
  OR NEW.target_parent_identity IS NOT OLD.target_parent_identity
  OR (OLD.observed_target_identity IS NOT NULL AND NEW.observed_target_identity IS NOT OLD.observed_target_identity)
  OR NEW.dispatch_generation < OLD.dispatch_generation
  OR NEW.updated_at_ms < OLD.updated_at_ms
  OR CASE OLD.state
       WHEN 'prepared' THEN NEW.state NOT IN ('prepared','artifact_synced','effect_unknown')
       WHEN 'artifact_synced' THEN NEW.state NOT IN ('artifact_synced','renamed','applied_mismatch','effect_unknown')
       WHEN 'renamed' THEN NEW.state NOT IN ('renamed','source_parent_synced','effect_unknown')
       WHEN 'source_parent_synced' THEN NEW.state NOT IN ('source_parent_synced','target_parent_synced','effect_unknown')
       WHEN 'target_parent_synced' THEN NEW.state NOT IN ('target_parent_synced','applied','effect_unknown')
       WHEN 'applied' THEN NEW.state NOT IN ('applied','ledger_committed')
       WHEN 'applied_mismatch' THEN NEW.state <> OLD.state
       WHEN 'effect_unknown' THEN NEW.state <> OLD.state
       ELSE NEW.state <> OLD.state
     END
BEGIN
    SELECT RAISE(ABORT, 'remote rename journal is immutable, monotonic, and generation bound');
END;

CREATE TABLE remote_rename_artifact_cleanup_intents (
    logical_attachment_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY(logical_attachment_id,operation_id),
    FOREIGN KEY(logical_attachment_id,operation_id)
      REFERENCES remote_rename_journal(logical_attachment_id,operation_id) ON DELETE CASCADE
);

CREATE TRIGGER remote_rename_artifact_cleanup_intents_immutable
BEFORE UPDATE ON remote_rename_artifact_cleanup_intents
BEGIN
    SELECT RAISE(ABORT, 'remote rename artifact cleanup intent is immutable');
END;

CREATE TRIGGER remote_rename_journal_cleanup_obligation
BEFORE DELETE ON remote_rename_journal
WHEN EXISTS (
    SELECT 1 FROM remote_rename_artifact_cleanup_intents
    WHERE logical_attachment_id=OLD.logical_attachment_id
      AND operation_id=OLD.operation_id
)
BEGIN
    SELECT RAISE(ABORT, 'remote rename artifact cleanup remains outstanding');
END;

CREATE TRIGGER remote_attachment_operation_reservation_insert
BEFORE INSERT ON remote_attachment_operations
WHEN NEW.state <> 'reserved' OR NEW.safe_response IS NOT NULL OR NEW.event_high_water_mark IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'remote operation insert must be a bounded reservation');
END;

CREATE TRIGGER remote_attachment_operation_capacity_insert
BEFORE INSERT ON remote_attachment_operations
WHEN (SELECT COUNT(*) FROM remote_attachment_operations
      WHERE logical_attachment_id = NEW.logical_attachment_id) >= 100000
BEGIN
    SELECT RAISE(ABORT, 'attachment_ledger_capacity');
END;

CREATE TRIGGER remote_attachment_operation_response_capacity
BEFORE UPDATE OF safe_response ON remote_attachment_operations
WHEN (SELECT COALESCE(SUM(length(safe_response)), 0)
      FROM remote_attachment_operations
      WHERE logical_attachment_id = NEW.logical_attachment_id)
     - COALESCE(length(OLD.safe_response), 0)
     + COALESCE(length(NEW.safe_response), 0) > 536870912
BEGIN
    SELECT RAISE(ABORT, 'attachment_ledger_capacity');
END;

-- Operation identity, actor binding, request digest, class, and sequence are
-- immutable after reservation. Reuse with changed bytes or actor generation
-- is resolved as a typed conflict by the reservation API, never by UPDATE.
CREATE TRIGGER remote_attachment_operation_binding_immutable
BEFORE UPDATE ON remote_attachment_operations
WHEN NEW.logical_attachment_id IS NOT OLD.logical_attachment_id
  OR NEW.operation_id IS NOT OLD.operation_id
  OR NEW.authenticated_device_id IS NOT OLD.authenticated_device_id
  OR NEW.authenticated_device_generation IS NOT OLD.authenticated_device_generation
  OR NEW.operation_seq IS NOT OLD.operation_seq
  OR NEW.operation_class IS NOT OLD.operation_class
  OR (NEW.operation_kind IS NOT OLD.operation_kind AND NOT (
      OLD.operation_kind='generic' AND NEW.operation_kind='staged_rename' AND OLD.state='reserved'
  ))
  OR NEW.request_hash IS NOT OLD.request_hash
  OR NEW.created_at_ms IS NOT OLD.created_at_ms
BEGIN
    SELECT RAISE(ABORT, 'remote attachment operation binding is immutable');
END;

CREATE TRIGGER remote_attachment_operation_transition_guard
BEFORE UPDATE ON remote_attachment_operations
WHEN (OLD.state NOT IN ('reserved', 'dispatched') AND NEW.state <> OLD.state)
  OR (OLD.state = 'reserved' AND NEW.state NOT IN ('reserved', 'dispatched', 'committed', 'rejected', 'outcome_unknown'))
  OR (OLD.state = 'dispatched' AND NEW.state NOT IN ('dispatched', 'committed', 'rejected', 'outcome_unknown'))
  OR NEW.dispatch_generation < OLD.dispatch_generation
  OR NEW.updated_at_ms < OLD.updated_at_ms
  OR (OLD.safe_response IS NOT NULL AND NEW.safe_response IS NOT OLD.safe_response)
  OR (OLD.event_high_water_mark IS NOT NULL
      AND (NEW.event_high_water_mark IS NULL OR NEW.event_high_water_mark < OLD.event_high_water_mark))
  OR (OLD.retire_at_ms IS NOT NULL
      AND (NEW.retire_at_ms IS NULL OR NEW.retire_at_ms <> OLD.retire_at_ms))
  OR (NEW.state IN ('committed', 'rejected') AND NOT EXISTS (
      SELECT 1 FROM remote_attachment_outbox
      WHERE logical_attachment_id = OLD.logical_attachment_id
        AND operation_seq = OLD.operation_seq
        AND event_seq = NEW.event_high_water_mark
  ))
BEGIN
    SELECT RAISE(ABORT, 'illegal remote attachment operation transition');
END;

CREATE TABLE remote_attachment_outbox (
    logical_attachment_id TEXT    NOT NULL,
    event_seq              INTEGER NOT NULL CHECK (event_seq > 0),
    delivery_id            TEXT    NOT NULL CHECK (
        length(delivery_id) = 36 AND delivery_id = lower(delivery_id)
        AND substr(delivery_id, 9, 1) = '-' AND substr(delivery_id, 14, 1) = '-'
        AND substr(delivery_id, 19, 1) = '-' AND substr(delivery_id, 20, 1) GLOB '[89ab]'
        AND substr(delivery_id, 24, 1) = '-'
        AND length(replace(delivery_id, '-', '')) = 32
        AND replace(delivery_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        AND replace(delivery_id, '-', '') <> '00000000000000000000000000000000'
    ),
    operation_seq          INTEGER CHECK (operation_seq IS NULL OR operation_seq > 0),
    kind                   TEXT    NOT NULL CHECK (length(kind) BETWEEN 1 AND 255),
    canonical_payload      BLOB    NOT NULL CHECK (length(canonical_payload) <= 524288),
    created_at_ms          INTEGER NOT NULL,
    PRIMARY KEY (logical_attachment_id, event_seq),
    UNIQUE (logical_attachment_id, delivery_id),
    FOREIGN KEY (logical_attachment_id, operation_seq)
        REFERENCES remote_attachment_operations(logical_attachment_id, operation_seq)
        ON DELETE RESTRICT
);

CREATE INDEX idx_remote_attachment_outbox_operation
    ON remote_attachment_outbox (logical_attachment_id, operation_seq)
    WHERE operation_seq IS NOT NULL;

-- Delivery attempts are consumer-local and never authorize replay compaction.
-- The immutable event row remains the sole application replay authority.
CREATE TABLE remote_attachment_outbox_deliveries (
    logical_attachment_id TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    consumer_kind TEXT NOT NULL CHECK (length(consumer_kind) BETWEEN 1 AND 64),
    state TEXT NOT NULL CHECK (state IN ('leased', 'acked')),
    lease_id TEXT CHECK (lease_id IS NULL OR (
        length(lease_id) = 36 AND lease_id = lower(lease_id)
        AND substr(lease_id, 9, 1) = '-' AND substr(lease_id, 14, 1) = '-'
        AND substr(lease_id, 19, 1) = '-' AND substr(lease_id, 20, 1) GLOB '[89ab]'
        AND substr(lease_id, 24, 1) = '-'
        AND length(replace(lease_id, '-', '')) = 32
        AND replace(lease_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        AND replace(lease_id, '-', '') <> '00000000000000000000000000000000'
    )),
    lease_expires_at_ms INTEGER,
    attempts INTEGER NOT NULL CHECK (attempts BETWEEN 1 AND 1000000),
    first_claimed_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    acked_at_ms INTEGER,
    PRIMARY KEY (logical_attachment_id, delivery_id, consumer_kind),
    FOREIGN KEY (logical_attachment_id, delivery_id)
        REFERENCES remote_attachment_outbox(logical_attachment_id, delivery_id)
        ON DELETE CASCADE,
    CHECK ((state = 'leased' AND lease_id IS NOT NULL AND lease_expires_at_ms IS NOT NULL AND acked_at_ms IS NULL)
        OR (state = 'acked' AND lease_id IS NULL AND lease_expires_at_ms IS NULL AND acked_at_ms IS NOT NULL)),
    CHECK (updated_at_ms >= first_claimed_at_ms),
    CHECK (acked_at_ms IS NULL OR acked_at_ms >= first_claimed_at_ms)
);

CREATE INDEX idx_remote_attachment_outbox_deliveries_claim
    ON remote_attachment_outbox_deliveries (consumer_kind, state, lease_expires_at_ms);

CREATE TRIGGER remote_attachment_outbox_delivery_monotonic
BEFORE UPDATE ON remote_attachment_outbox_deliveries
WHEN NEW.logical_attachment_id <> OLD.logical_attachment_id
  OR NEW.delivery_id <> OLD.delivery_id
  OR NEW.consumer_kind <> OLD.consumer_kind
  OR NEW.first_claimed_at_ms <> OLD.first_claimed_at_ms
  OR NEW.attempts < OLD.attempts
  OR NEW.updated_at_ms < OLD.updated_at_ms
  OR OLD.state = 'acked'
BEGIN
    SELECT RAISE(ABORT, 'illegal remote outbox delivery transition');
END;

CREATE TRIGGER remote_attachment_outbox_capacity_insert
BEFORE INSERT ON remote_attachment_outbox
WHEN (SELECT COUNT(*) FROM remote_attachment_outbox
      WHERE logical_attachment_id = NEW.logical_attachment_id) >= 200000
  OR (SELECT COALESCE(SUM(length(canonical_payload)), 0)
      FROM remote_attachment_outbox
      WHERE logical_attachment_id = NEW.logical_attachment_id)
     + length(NEW.canonical_payload) > 2147483648
BEGIN
    SELECT RAISE(ABORT, 'attachment_outbox_capacity');
END;

CREATE TRIGGER remote_attachment_outbox_immutable
BEFORE UPDATE ON remote_attachment_outbox
BEGIN
    SELECT RAISE(ABORT, 'remote attachment outbox is append-only');
END;

CREATE TRIGGER remote_attachment_outbox_delete_forbidden
BEFORE DELETE ON remote_attachment_outbox
WHEN NOT EXISTS (
    SELECT 1 FROM remote_attachment_outbox_snapshots
    WHERE logical_attachment_id = OLD.logical_attachment_id
      AND compacted_through_event_seq >= OLD.event_seq
)
BEGIN
    SELECT RAISE(ABORT, 'remote attachment outbox deletion lacks snapshot authority');
END;

CREATE TABLE remote_attachment_outbox_snapshots (
    logical_attachment_id       TEXT PRIMARY KEY CHECK (
        length(logical_attachment_id) = 36 AND logical_attachment_id = lower(logical_attachment_id)
        AND substr(logical_attachment_id, 9, 1) = '-' AND substr(logical_attachment_id, 14, 1) = '-'
        AND substr(logical_attachment_id, 19, 1) = '-' AND substr(logical_attachment_id, 24, 1) = '-'
        AND substr(logical_attachment_id, 20, 1) GLOB '[89ab]'
        AND length(replace(logical_attachment_id, '-', '')) = 32
        AND replace(logical_attachment_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        AND replace(logical_attachment_id, '-', '') <> '00000000000000000000000000000000'
    ),
    compacted_through_event_seq INTEGER NOT NULL CHECK (compacted_through_event_seq >= 0),
    snapshot_high_water_mark    INTEGER NOT NULL CHECK (snapshot_high_water_mark >= compacted_through_event_seq),
    updated_at_ms               INTEGER NOT NULL
);

CREATE TRIGGER remote_attachment_snapshot_monotonic
BEFORE UPDATE ON remote_attachment_outbox_snapshots
WHEN NEW.compacted_through_event_seq < OLD.compacted_through_event_seq
  OR NEW.snapshot_high_water_mark < OLD.snapshot_high_water_mark
  OR NEW.updated_at_ms < OLD.updated_at_ms
BEGIN
    SELECT RAISE(ABORT, 'remote attachment snapshot cursor is monotonic');
END;



-- ---- remote_daemon_custody_generation_seq ----------------------------------
-- Monotonic high-water sequence for daemon durable-P-256 custody generations.
-- Exactly one row (id = 1). `high_water` only ever increases; `destroy` never
-- resets or deletes it, so a destroyed + regenerated identity always receives a
-- strictly greater generation. Possession proofs bind (certificateId,
-- generation), so a reused generation would let a superseded proof replay.
CREATE TABLE remote_daemon_custody_generation_seq (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    high_water  INTEGER NOT NULL CHECK (high_water >= 0)
);

CREATE TRIGGER remote_daemon_custody_generation_seq_monotonic
BEFORE UPDATE ON remote_daemon_custody_generation_seq
WHEN NEW.high_water < OLD.high_water BEGIN
  SELECT RAISE(ABORT, 'remote daemon custody generation sequence must not decrease');
END;

-- ---- remote_daemon_custody_records -----------------------------------------
-- Durable daemon custody generation records. One row per live handle. The row
-- is the crash-safe unit: a generation is durable only once its handle id,
-- public key, custody discriminants, generation, and evidence digest are all
-- persisted together (inside one transaction with the sequence bump). Never
-- stores private key bytes — the private key lives only in the platform
-- keystore behind the handle. `profile` is the construction-time configured
-- daemon custody profile label, never caller-supplied evidence.
CREATE TABLE remote_daemon_custody_records (
    handle_id        BLOB    PRIMARY KEY CHECK (length(handle_id) = 16),
    subject_kind     INTEGER NOT NULL CHECK (subject_kind IN (1, 2)),
    custody_class    INTEGER NOT NULL CHECK (custody_class IN (1, 2, 3)),
    presence_mode    INTEGER NOT NULL CHECK (presence_mode IN (1, 2, 3, 4)),
    profile          TEXT    NOT NULL,
    generation       INTEGER NOT NULL CHECK (generation >= 1),
    public_key_x     BLOB    NOT NULL CHECK (length(public_key_x) = 32),
    public_key_y     BLOB    NOT NULL CHECK (length(public_key_y) = 32),
    evidence_digest  BLOB    NOT NULL CHECK (length(evidence_digest) = 32),
    created_at       INTEGER NOT NULL
);


