-- 0001_initial.sql — the complete cockpit DB schema at launch (0.1.0).
--
-- Pre-launch development accumulated 60 incremental migrations; they were
-- consolidated into this single migration before the first public release
-- (the per-change history and rationale live in git history). Tables mirror
-- the persistence surfaces called out in the design notes (§14, §15b, §3b,
-- §8b) plus the file-lock mirror that lets the daemon survive a crash
-- (plan §4.1).
--
-- PRAGMAs (`foreign_keys = ON`, `journal_mode = WAL`) live on the
-- connection itself rather than in migration SQL. The runner owns the
-- temporary foreign-key toggle for table rebuilds and validates with
-- `foreign_key_check`; see `migrate_with` in `mod.rs`.


-- ---- assistants ------------------------------------------------------------

CREATE TABLE assistants (
    name         TEXT    PRIMARY KEY,
    created_at   INTEGER NOT NULL,
    home_dir     TEXT    NOT NULL,
    config_json  TEXT    NOT NULL DEFAULT '{}',
    content_hash TEXT    NOT NULL
);

-- ---- scheduled_jobs --------------------------------------------------------

CREATE TABLE scheduled_jobs (
    id                TEXT    PRIMARY KEY,
    owner             TEXT    NOT NULL,
    schedule_json     TEXT    NOT NULL,
    payload_json      TEXT    NOT NULL,
    enabled           INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    missed_run_policy TEXT    NOT NULL CHECK (missed_run_policy IN ('skip', 'run_once_on_start')),
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    last_run_at       INTEGER,
    next_run_at       INTEGER,
    last_result_json  TEXT,
    failure_count     INTEGER NOT NULL DEFAULT 0,
    backoff_until     INTEGER,
    disabled_notice   TEXT
);

CREATE INDEX idx_scheduled_jobs_next_run
    ON scheduled_jobs(enabled, next_run_at);

CREATE INDEX idx_scheduled_jobs_owner
    ON scheduled_jobs(owner);

-- ---- sessions --------------------------------------------------------------

CREATE TABLE sessions (
    session_id      TEXT    PRIMARY KEY,
    project_id      TEXT    NOT NULL,
    project_root    TEXT    NOT NULL,
    started_at      INTEGER NOT NULL,            -- epoch seconds
    last_active_at  INTEGER NOT NULL,
    ended_at        INTEGER,
    provider        TEXT,
    model           TEXT,
    model_selection_json TEXT,
    -- Durable CAS token for active-model mutations (picker, recovery, controls).
    active_model_revision INTEGER NOT NULL DEFAULT 0,
    session_llm_mode TEXT CHECK (session_llm_mode IN ('defensive', 'normal', 'frontier')),
    tool_surface_override_json TEXT,
    goal_settings_override_json TEXT,
    active_agent    TEXT    NOT NULL DEFAULT 'orchestrator-build',
    assistant_name  TEXT,

    -- fork tree + auto-titling (GOALS §17). SQLite owns parent integrity
    -- and cascades deletion through the complete fork subtree.
    parent_session_id  TEXT,                     -- NULL = root
    fork_point_turn_id TEXT,                     -- turn in parent where fork branched; NULL = root
    title              TEXT,                     -- utility-model-generated label (§17d)
    user_renamed       INTEGER NOT NULL DEFAULT 0 CHECK (user_renamed IN (0, 1)), -- 1 = user set title; locks out auto-titling
    short_id           TEXT,                     -- 6-char Crockford base32 display id

    -- read/unread + archive state for the session browser (GOALS §17f).
    -- A session is UNREAD when the latest agent-produced event is newer
    -- than last_viewed_at (NULL = never viewed). archived_at is a
    -- recoverable soft-delete; NULL = live. Archive cascades the fork
    -- subtree app-side (src/db/sessions.rs).
    last_viewed_at INTEGER,
    archived_at    INTEGER,

    -- live guidance-file diff injection: hash + path of the resolved
    -- agent-guidance body baked into this session's frozen system block,
    -- so a mid-session in-place edit is detected and injected as a
    -- trailing diff exactly once. Both NULL when no guidance file
    -- resolved at session start.
    guidance_baseline_hash TEXT,
    guidance_baseline_path TEXT,

    -- Accumulated session egress redaction table. Stores literal redaction
    -- candidates so resumed raw transcripts remain covered even if the
    -- original env/dotenv source has changed or disappeared.
    redaction_table_json TEXT,

    -- Frozen model-specific system-prompt snapshot for this conversation
    -- lineage. JSON object keyed provider id -> model id -> prompt body.
    model_system_prompt_snapshot_json TEXT NOT NULL DEFAULT '{}',

    -- 1 for hidden side-conversation forks. Legacy `/side` rows are
    -- throwaway and swept on daemon boot; BTW rows carry
    -- btw_parent_session_id and are persistent until explicit end or parent
    -- deletion.
    ephemeral INTEGER NOT NULL DEFAULT 0 CHECK (ephemeral IN (0, 1)),

    -- Persistent `/btw` side-conversation linkage. A BTW row is also a
    -- fork-tree child via parent_session_id, but this typed linkage is the
    -- authoritative lifecycle marker and uniqueness key.
    btw_parent_session_id TEXT,
    btw_tangent INTEGER NOT NULL DEFAULT 0 CHECK (btw_tangent IN (0, 1)),

    -- persisted auto-title progress (GOALS §17d): running cl100k_base
    -- estimate of RAW typed user content, and the last consumed scheduled
    -- title slot (0, 1, 2, 4, 8, or 16) so a resumed session never repeats
    -- the same automatic title opportunity.
    user_content_tokens INTEGER NOT NULL DEFAULT 0,
    title_stage         INTEGER NOT NULL DEFAULT 0,

    -- remote principal attribution + collaborator sharing.
    created_by_principal TEXT,
    shared_with_collaborators INTEGER NOT NULL DEFAULT 0 CHECK (shared_with_collaborators IN (0, 1)),

    -- Deletion barrier lifecycle (cross-platform-descendant-process-containment).
    -- 'active' accepts work; 'deleting' rejects new work until every bound
    -- execution containment is ProvenEmpty, then the session row may drop.
    lifecycle TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'deleting')),

    CHECK (parent_session_id IS NULL OR parent_session_id <> session_id),
    FOREIGN KEY (parent_session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY (btw_parent_session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

-- ---- typed media attachments ----------------------------------------------
-- Full-range monotonic values are canonical decimal text because SQLite's
-- INTEGER is signed i64. Application codecs reject zero, leading zeroes and
-- values outside u64 before any mutation.
CREATE TABLE media_attachments (
    attachment_id                  TEXT PRIMARY KEY,
    session_id                     TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    canonical_project_digest       TEXT NOT NULL,
    media_kind                     TEXT NOT NULL CHECK (media_kind IN ('image', 'audio', 'video')),
    source_kind                    TEXT NOT NULL CHECK (source_kind IN ('local_path', 'retained_https', 'authenticated_session_upload')),
    canonical_container            TEXT NOT NULL,
    canonical_mime                 TEXT NOT NULL,
    availability                   TEXT NOT NULL CHECK (availability IN (
        'registered', 'quarantined', 'probing', 'decoding', 'normalizing',
        'ready', 'model_derivative_unavailable', 'source_changed', 'failed',
        'security_blocked', 'owned_cleanup_pending', 'retained_copy_deleted',
        'borrowed_cleanup_pending', 'borrowed_derivatives_deleted', 'metadata_deleted'
    )),
    attachment_version             TEXT NOT NULL,
    availability_generation        TEXT NOT NULL,
    reference_generation           TEXT NOT NULL,
    captured_capability_generation TEXT NOT NULL,
    source_identity_digest         TEXT NOT NULL,
    source_byte_length             TEXT NOT NULL,
    source_sha256                  TEXT NOT NULL,
    selected_video_stream_json     TEXT,
    selected_audio_stream_json     TEXT,
    created_at_unix_ms             INTEGER NOT NULL,
    updated_at_unix_ms             INTEGER NOT NULL,
    draft_expires_at_unix_ms       INTEGER,
    first_referenced_at_unix_ms    INTEGER,
    UNIQUE (attachment_id, attachment_version),
    CHECK (length(canonical_project_digest) = 64 AND canonical_project_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(source_identity_digest) = 64 AND source_identity_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(source_sha256) = 64 AND source_sha256 NOT GLOB '*[^0-9a-f]*'),
    CHECK ((source_kind = 'authenticated_session_upload') OR draft_expires_at_unix_ms IS NULL)
);

CREATE INDEX idx_media_attachments_session
    ON media_attachments(session_id, created_at_unix_ms, attachment_id);
CREATE INDEX idx_media_attachments_cleanup
    ON media_attachments(availability, draft_expires_at_unix_ms);

CREATE TABLE media_attachment_failure_reasons (
    attachment_id TEXT PRIMARY KEY REFERENCES media_attachments(attachment_id) ON DELETE CASCADE,
    reason TEXT NOT NULL CHECK (reason IN (
        'ambiguous_or_unsupported_container', 'unsupported_codec',
        'unsupported_color_profile', 'invalid_media', 'resource_limit',
        'decode_failed', 'normalization_failed', 'storage_failure'
    )),
    recorded_at_unix_ms INTEGER NOT NULL
);

CREATE TRIGGER media_attachment_identity_immutable
BEFORE UPDATE ON media_attachments
WHEN NEW.attachment_id <> OLD.attachment_id
  OR NEW.session_id <> OLD.session_id
  OR NEW.canonical_project_digest <> OLD.canonical_project_digest
  OR NEW.media_kind <> OLD.media_kind
  OR NEW.source_kind <> OLD.source_kind
  OR NEW.attachment_version <> OLD.attachment_version
  OR NEW.captured_capability_generation <> OLD.captured_capability_generation
  OR NEW.source_identity_digest <> OLD.source_identity_digest
  OR NEW.source_byte_length <> OLD.source_byte_length
  OR NEW.source_sha256 <> OLD.source_sha256
BEGIN
    SELECT RAISE(ABORT, 'media attachment identity is immutable');
END;

CREATE TABLE media_attachment_components (
    component_id          TEXT PRIMARY KEY,
    attachment_id         TEXT NOT NULL,
    attachment_version    TEXT NOT NULL,
    component_kind        TEXT NOT NULL CHECK (component_kind IN ('quarantined_original', 'image_model', 'browser_thumbnail', 'audio_model', 'video_model', 'upload_temporary')),
    storage_id            TEXT NOT NULL UNIQUE,
    lifecycle_state       TEXT NOT NULL CHECK (lifecycle_state IN ('temporary', 'ready', 'cleanup_pending', 'deleted', 'security_blocked')),
    component_generation  TEXT NOT NULL,
    stable_identity_digest TEXT NOT NULL,
    byte_length           TEXT NOT NULL,
    sha256                TEXT NOT NULL,
    reservation_id        TEXT NOT NULL,
    deletion_evidence_digest TEXT,
    created_at_unix_ms    INTEGER NOT NULL,
    updated_at_unix_ms    INTEGER NOT NULL,
    CHECK (length(stable_identity_digest) = 64 AND stable_identity_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    CHECK (deletion_evidence_digest IS NULL OR (length(deletion_evidence_digest) = 64 AND deletion_evidence_digest NOT GLOB '*[^0-9a-f]*')),
    FOREIGN KEY (attachment_id, attachment_version)
        REFERENCES media_attachments(attachment_id, attachment_version) ON DELETE CASCADE
);

CREATE INDEX idx_media_attachment_components_attachment
    ON media_attachment_components(attachment_id, component_id);

CREATE TABLE media_image_component_dimensions (
    component_id TEXT PRIMARY KEY REFERENCES media_attachment_components(component_id) ON DELETE CASCADE,
    width INTEGER NOT NULL CHECK(width > 0 AND width <= 8192),
    height INTEGER NOT NULL CHECK(height > 0 AND height <= 8192)
);

CREATE TABLE media_attachment_transition_evidence (
    attachment_id TEXT NOT NULL REFERENCES media_attachments(attachment_id) ON DELETE CASCADE,
    availability_generation TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    committed_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY(attachment_id, availability_generation)
);

CREATE TABLE media_av_normalization_evidence (
    attachment_id TEXT PRIMARY KEY REFERENCES media_attachments(attachment_id) ON DELETE CASCADE,
    runtime_fingerprint TEXT NOT NULL,
    probe_digest TEXT NOT NULL,
    decode_digest TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    derivative_version TEXT GENERATED ALWAYS AS (plan_digest) STORED,
    derivative_checksum TEXT NOT NULL,
    CHECK (length(runtime_fingerprint) = 64 AND runtime_fingerprint NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(probe_digest) = 64 AND probe_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(decode_digest) = 64 AND decode_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(plan_digest) = 64 AND plan_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(derivative_version) = 64 AND derivative_version NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(derivative_checksum) = 64 AND derivative_checksum NOT GLOB '*[^0-9a-f]*')
);

CREATE TABLE media_storage_publication_intents (
    upload_id TEXT PRIMARY KEY REFERENCES media_uploads(upload_id) ON DELETE CASCADE,
    temporary_storage_id TEXT NOT NULL,
    quarantine_storage_id TEXT NOT NULL,
    derivative_storage_ids_json TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL
);

CREATE TRIGGER media_attachment_component_compatibility_insert
BEFORE INSERT ON media_attachment_components
WHEN NOT EXISTS (
    SELECT 1 FROM media_attachments a
    WHERE a.attachment_id = NEW.attachment_id
      AND a.attachment_version = NEW.attachment_version
      AND (
        (NEW.component_kind = 'quarantined_original' AND a.source_kind <> 'local_path') OR
        (NEW.component_kind = 'upload_temporary' AND a.source_kind = 'authenticated_session_upload') OR
        (NEW.component_kind IN ('image_model', 'browser_thumbnail') AND a.media_kind = 'image') OR
        (NEW.component_kind = 'audio_model' AND a.media_kind = 'audio') OR
        (NEW.component_kind = 'video_model' AND a.media_kind = 'video')
      )
      AND (NEW.lifecycle_state <> 'temporary' OR NEW.component_kind IN ('quarantined_original', 'upload_temporary'))
)
BEGIN
    SELECT RAISE(ABORT, 'media component incompatible with attachment');
END;

CREATE TRIGGER media_attachment_component_compatibility_update
BEFORE UPDATE OF attachment_id, attachment_version, component_kind, lifecycle_state
ON media_attachment_components
WHEN NOT EXISTS (
    SELECT 1 FROM media_attachments a
    WHERE a.attachment_id = NEW.attachment_id
      AND a.attachment_version = NEW.attachment_version
      AND (
        (NEW.component_kind = 'quarantined_original' AND a.source_kind <> 'local_path') OR
        (NEW.component_kind = 'upload_temporary' AND a.source_kind = 'authenticated_session_upload') OR
        (NEW.component_kind IN ('image_model', 'browser_thumbnail') AND a.media_kind = 'image') OR
        (NEW.component_kind = 'audio_model' AND a.media_kind = 'audio') OR
        (NEW.component_kind = 'video_model' AND a.media_kind = 'video')
      )
      AND (NEW.lifecycle_state <> 'temporary' OR NEW.component_kind IN ('quarantined_original', 'upload_temporary'))
)
BEGIN
    SELECT RAISE(ABORT, 'media component incompatible with attachment');
END;

CREATE TABLE media_attachment_references (
    reference_id          TEXT PRIMARY KEY,
    attachment_id         TEXT NOT NULL,
    attachment_version    TEXT NOT NULL,
    consumer_kind         TEXT NOT NULL CHECK (consumer_kind IN ('message', 'tool', 'job')),
    consumer_id           TEXT NOT NULL,
    acquired_generation   TEXT NOT NULL,
    acquired_at_unix_ms   INTEGER NOT NULL,
    released_at_unix_ms   INTEGER,
    UNIQUE (attachment_id, attachment_version, consumer_kind, consumer_id),
    FOREIGN KEY (attachment_id, attachment_version)
        REFERENCES media_attachments(attachment_id, attachment_version) ON DELETE CASCADE
);

CREATE INDEX idx_media_attachment_references_live
    ON media_attachment_references(attachment_id, released_at_unix_ms);

-- Short-lived held-handle leases serialize every consumer with cleanup.  The
-- capability generation is captured at acquisition so a daemon authority
-- rotation invalidates new work without weakening an already-held read.
CREATE TABLE media_attachment_component_leases (
    lease_id                       TEXT PRIMARY KEY,
    attachment_id                  TEXT NOT NULL,
    attachment_version             TEXT NOT NULL,
    component_id                   TEXT NOT NULL REFERENCES media_attachment_components(component_id) ON DELETE CASCADE,
    lease_kind                     TEXT NOT NULL CHECK (lease_kind IN ('preview', 'model')),
    expected_availability_generation TEXT NOT NULL,
    captured_capability_generation TEXT NOT NULL,
    owner_session_id                TEXT NOT NULL,
    canonical_project_digest        TEXT NOT NULL,
    lease_purpose                   TEXT NOT NULL CHECK(lease_purpose IN ('preview','model_input')),
    lease_expires_at_unix_ms        INTEGER NOT NULL,
    acquired_at_unix_ms            INTEGER NOT NULL,
    released_at_unix_ms            INTEGER,
    FOREIGN KEY (attachment_id, attachment_version)
        REFERENCES media_attachments(attachment_id, attachment_version) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_media_attachment_component_leases_live_id
    ON media_attachment_component_leases(lease_id)
    WHERE released_at_unix_ms IS NULL;
CREATE INDEX idx_media_attachment_component_leases_live_attachment
    ON media_attachment_component_leases(attachment_id, attachment_version, released_at_unix_ms);

CREATE TABLE media_component_lease_reconciliation_evidence (
    lease_id TEXT PRIMARY KEY REFERENCES media_attachment_component_leases(lease_id) ON DELETE CASCADE,
    reason TEXT NOT NULL CHECK(reason = 'daemon_restart'),
    released_at_unix_ms INTEGER NOT NULL
);

CREATE TABLE media_component_security_evidence (
    lease_id TEXT PRIMARY KEY REFERENCES media_attachment_component_leases(lease_id) ON DELETE CASCADE,
    attachment_id TEXT NOT NULL,
    component_id TEXT NOT NULL,
    reason TEXT NOT NULL CHECK(reason = 'storage_security_violation'),
    recorded_at_unix_ms INTEGER NOT NULL,
    FOREIGN KEY (attachment_id) REFERENCES media_attachments(attachment_id) ON DELETE CASCADE,
    FOREIGN KEY (component_id) REFERENCES media_attachment_components(component_id) ON DELETE CASCADE
);

CREATE TABLE media_attachment_cleanup_intents (
    intent_id                         TEXT PRIMARY KEY,
    attachment_id                    TEXT NOT NULL UNIQUE,
    attachment_version               TEXT NOT NULL,
    expected_availability_generation TEXT NOT NULL,
    expected_reference_generation    TEXT NOT NULL,
    component_set_digest             TEXT NOT NULL,
    reason                           TEXT NOT NULL CHECK (reason IN ('discard', 'draft_expired', 'session_retention', 'session_deleted', 'security_recovery')),
    created_at_unix_ms               INTEGER NOT NULL,
    completed_at_unix_ms             INTEGER,
    CHECK (length(component_set_digest) = 64 AND component_set_digest NOT GLOB '*[^0-9a-f]*'),
    FOREIGN KEY (attachment_id, attachment_version)
        REFERENCES media_attachments(attachment_id, attachment_version) ON DELETE CASCADE
);

CREATE TABLE media_component_deletion_intents (
    component_id TEXT PRIMARY KEY REFERENCES media_attachment_components(component_id) ON DELETE CASCADE,
    attachment_id TEXT NOT NULL,
    storage_id TEXT NOT NULL,
    stable_identity_digest TEXT NOT NULL,
    byte_length TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    intent_digest TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL,
    CHECK(length(intent_digest)=64 AND intent_digest NOT GLOB '*[^0-9a-f]*')
);

-- Deliberately has no attachment/component FK: deletion proof must survive a
-- borrowed attachment's subsequent metadata deletion.
CREATE TABLE media_component_deletion_evidence (
    component_id TEXT PRIMARY KEY,
    attachment_id TEXT NOT NULL,
    intent_digest TEXT NOT NULL,
    deletion_evidence_digest TEXT NOT NULL,
    deletion_kind TEXT NOT NULL CHECK(deletion_kind IN ('verified_unlink','interrupted_unlink_reconciled')),
    committed_at_unix_ms INTEGER NOT NULL,
    CHECK(length(intent_digest)=64 AND intent_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK(length(deletion_evidence_digest)=64 AND deletion_evidence_digest NOT GLOB '*[^0-9a-f]*')
);

CREATE TABLE media_cleanup_security_evidence (
    component_id TEXT PRIMARY KEY,
    attachment_id TEXT NOT NULL,
    reason TEXT NOT NULL CHECK(reason='storage_security_violation'),
    recorded_at_unix_ms INTEGER NOT NULL
);

CREATE TABLE media_security_recovery_operations (
    local_request_id       TEXT PRIMARY KEY,
    owner_principal_digest TEXT NOT NULL,
    attachment_id          TEXT NOT NULL,
    attachment_version     TEXT NOT NULL,
    request_digest         TEXT NOT NULL,
    affected_set_digest    TEXT NOT NULL,
    receipt_json           TEXT NOT NULL,
    committed_at_unix_ms   INTEGER NOT NULL,
    CHECK (length(owner_principal_digest) = 64 AND owner_principal_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(affected_set_digest) = 64 AND affected_set_digest NOT GLOB '*[^0-9a-f]*'),
    FOREIGN KEY (attachment_id, attachment_version)
        REFERENCES media_attachments(attachment_id, attachment_version) ON DELETE CASCADE
);

CREATE TABLE media_local_path_registration_operations (
    local_operation_id       TEXT PRIMARY KEY,
    authoritative_operation_id TEXT NOT NULL,
    session_id               TEXT NOT NULL,
    canonical_project_digest TEXT NOT NULL,
    client_draft_id          TEXT NOT NULL,
    request_binding_digest   TEXT NOT NULL,
    operation_request_digest TEXT NOT NULL,
    semantic_command_digest  TEXT NOT NULL,
    receipt_json             TEXT NOT NULL,
    committed_at_unix_ms     INTEGER NOT NULL,
    is_alias                 INTEGER NOT NULL CHECK (is_alias IN (0,1))
);
CREATE UNIQUE INDEX uq_media_local_path_registration_domain
ON media_local_path_registration_operations(session_id, canonical_project_digest, client_draft_id)
WHERE is_alias = 0;

CREATE TABLE media_local_path_registration_evidence (
    attachment_id             TEXT PRIMARY KEY,
    canonical_path_digest     TEXT NOT NULL,
    path_authority_digest     TEXT NOT NULL,
    source_evidence_digest    TEXT NOT NULL,
    source_mtime_unix_ns      TEXT NOT NULL,
    reservation_id           TEXT NOT NULL,
    reservation_digest       TEXT NOT NULL,
    FOREIGN KEY (attachment_id) REFERENCES media_attachments(attachment_id) ON DELETE CASCADE
);

CREATE TABLE media_local_path_registration_audit (
    local_operation_id TEXT PRIMARY KEY,
    outcome            TEXT NOT NULL,
    committed_at_unix_ms INTEGER NOT NULL
);

CREATE TABLE media_retained_https_operations (
    local_operation_id         TEXT PRIMARY KEY,
    authoritative_operation_id TEXT NOT NULL,
    session_id                 TEXT NOT NULL,
    canonical_project_digest   TEXT NOT NULL,
    client_draft_id            TEXT NOT NULL,
    request_binding_digest     TEXT NOT NULL,
    operation_request_digest   TEXT NOT NULL,
    semantic_command_digest    TEXT NOT NULL,
    receipt_json               TEXT NOT NULL,
    committed_at_unix_ms       INTEGER NOT NULL,
    is_alias                   INTEGER NOT NULL CHECK (is_alias IN (0,1)),
    CHECK (length(canonical_project_digest) = 64 AND canonical_project_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(request_binding_digest) = 64 AND request_binding_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(operation_request_digest) = 64 AND operation_request_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(semantic_command_digest) = 64 AND semantic_command_digest NOT GLOB '*[^0-9a-f]*')
);
CREATE UNIQUE INDEX uq_media_retained_https_domain
ON media_retained_https_operations(session_id, canonical_project_digest, client_draft_id)
WHERE is_alias = 0;

CREATE TABLE media_retained_https_evidence (
    attachment_id             TEXT PRIMARY KEY,
    source_evidence_digest    TEXT NOT NULL,
    redirect_classes_json     TEXT NOT NULL,
    path_segment_count        INTEGER NOT NULL CHECK(path_segment_count >= 0),
    safe_basename             TEXT,
    fetched_at_unix_ms        INTEGER NOT NULL,
    reservation_id           TEXT NOT NULL,
    reservation_digest       TEXT NOT NULL,
    CHECK (length(source_evidence_digest) = 64 AND source_evidence_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(reservation_digest) = 64 AND reservation_digest NOT GLOB '*[^0-9a-f]*'),
    FOREIGN KEY (attachment_id) REFERENCES media_attachments(attachment_id) ON DELETE CASCADE
);

CREATE TABLE media_retained_https_audit (
    local_operation_id   TEXT PRIMARY KEY,
    outcome              TEXT NOT NULL CHECK(outcome IN ('retained','rejected')),
    committed_at_unix_ms INTEGER NOT NULL
);

CREATE TABLE media_retained_https_publication_intents (
    local_operation_id TEXT PRIMARY KEY,
    storage_id         TEXT NOT NULL UNIQUE,
    created_at_unix_ms INTEGER NOT NULL
);

CREATE TABLE media_retained_https_orphan_cleanup_evidence (
    local_operation_id TEXT PRIMARY KEY,
    storage_id         TEXT NOT NULL,
    evidence_digest    TEXT NOT NULL,
    outcome            TEXT NOT NULL CHECK(outcome IN ('verified_unlink','verified_absent_before_create')),
    completed_at_unix_ms INTEGER NOT NULL,
    CHECK (length(evidence_digest) = 64 AND evidence_digest NOT GLOB '*[^0-9a-f]*')
);

CREATE TABLE media_attachment_processing_jobs (
    job_id                           TEXT PRIMARY KEY,
    attachment_id                   TEXT NOT NULL UNIQUE,
    expected_attachment_version     TEXT NOT NULL,
    expected_availability_generation TEXT NOT NULL,
    source_evidence_digest          TEXT NOT NULL,
    state                            TEXT NOT NULL CHECK(state IN ('pending','claimed','completed')),
    claimed_at_unix_ms               INTEGER,
    claim_attempt                    INTEGER NOT NULL DEFAULT 0,
    created_at_unix_ms               INTEGER NOT NULL,
    completed_at_unix_ms             INTEGER,
    FOREIGN KEY (attachment_id) REFERENCES media_attachments(attachment_id) ON DELETE CASCADE
);
CREATE TABLE media_attachment_processing_security_evidence (
    job_id             TEXT PRIMARY KEY REFERENCES media_attachment_processing_jobs(job_id) ON DELETE CASCADE,
    attachment_id      TEXT NOT NULL,
    component_id       TEXT NOT NULL,
    reason             TEXT NOT NULL CHECK(reason = 'storage_security_violation'),
    recorded_at_unix_ms INTEGER NOT NULL,
    FOREIGN KEY (attachment_id) REFERENCES media_attachments(attachment_id) ON DELETE CASCADE,
    FOREIGN KEY (component_id) REFERENCES media_attachment_components(component_id) ON DELETE CASCADE
);
CREATE TABLE media_attachment_processing_publication_intents (
    job_id          TEXT PRIMARY KEY REFERENCES media_attachment_processing_jobs(job_id) ON DELETE CASCADE,
    output_ids_json TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL
);
CREATE TABLE media_attachment_processing_cleanup_evidence (
    job_id          TEXT PRIMARY KEY REFERENCES media_attachment_processing_jobs(job_id) ON DELETE CASCADE,
    evidence_digest TEXT NOT NULL,
    completed_at_unix_ms INTEGER NOT NULL,
    CHECK (length(evidence_digest)=64 AND evidence_digest NOT GLOB '*[^0-9a-f]*')
);
CREATE TABLE media_attachment_processing_failure_evidence (
    job_id TEXT PRIMARY KEY REFERENCES media_attachment_processing_jobs(job_id) ON DELETE CASCADE,
    attachment_id TEXT NOT NULL,
    reason TEXT NOT NULL CHECK(reason IN ('processing_failed','model_runtime_unavailable')),
    recorded_at_unix_ms INTEGER NOT NULL,
    FOREIGN KEY (attachment_id) REFERENCES media_attachments(attachment_id) ON DELETE CASCADE
);
CREATE TABLE media_attachment_processing_output_security_evidence (
    job_id TEXT PRIMARY KEY REFERENCES media_attachment_processing_jobs(job_id) ON DELETE CASCADE,
    attachment_id TEXT NOT NULL,
    output_ids_json TEXT NOT NULL,
    reason TEXT NOT NULL CHECK(reason='storage_security_violation'),
    recorded_at_unix_ms INTEGER NOT NULL,
    FOREIGN KEY (attachment_id) REFERENCES media_attachments(attachment_id) ON DELETE CASCADE
);

CREATE TABLE media_uploads (
    upload_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, canonical_project_digest TEXT NOT NULL,
    client_draft_id TEXT NOT NULL, media_kind TEXT NOT NULL CHECK(media_kind IN ('image','audio','video')),
    state TEXT NOT NULL CHECK(state IN ('open','finalizing','materialized','cancelled','expired','failed')),
    upload_generation TEXT NOT NULL, declared_total_bytes TEXT NOT NULL, acknowledged_chunks INTEGER NOT NULL,
    acknowledged_bytes TEXT NOT NULL, next_chunk_index INTEGER, expires_at_unix_ms INTEGER NOT NULL,
    reservation_id TEXT NOT NULL UNIQUE, reservation_digest TEXT NOT NULL, temporary_storage_id TEXT NOT NULL UNIQUE,
    attachment_id TEXT, attachment_version TEXT, terminal_reason TEXT, cleanup_evidence_digest TEXT, last_transition_json TEXT NOT NULL,
    creation_sequence INTEGER NOT NULL UNIQUE, created_at_unix_ms INTEGER NOT NULL, updated_at_unix_ms INTEGER NOT NULL,
    UNIQUE(session_id,canonical_project_digest,client_draft_id),
    CHECK(length(canonical_project_digest)=64 AND canonical_project_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK(length(reservation_digest)=64 AND reservation_digest NOT GLOB '*[^0-9a-f]*')
);
CREATE TABLE media_upload_chunks (
    upload_id TEXT NOT NULL, chunk_index INTEGER NOT NULL, byte_length INTEGER NOT NULL,
    sha256 TEXT NOT NULL, storage_offset TEXT NOT NULL, acknowledged_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY(upload_id,chunk_index), FOREIGN KEY(upload_id) REFERENCES media_uploads(upload_id) ON DELETE CASCADE,
    CHECK(byte_length>0 AND byte_length<=262144), CHECK(length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*')
);
CREATE TRIGGER media_upload_publication_intent_complete
AFTER UPDATE OF state ON media_uploads
WHEN NEW.state='materialized'
BEGIN
    DELETE FROM media_storage_publication_intents WHERE upload_id=NEW.upload_id;
END;
CREATE TABLE media_attachment_upload_origins(
    attachment_id TEXT PRIMARY KEY,client_draft_id TEXT NOT NULL,upload_id TEXT NOT NULL UNIQUE,upload_generation TEXT NOT NULL,
    FOREIGN KEY(attachment_id) REFERENCES media_attachments(attachment_id) ON DELETE CASCADE
);
CREATE TABLE local_media_operations (
    local_operation_id TEXT PRIMARY KEY, authoritative_operation_id TEXT NOT NULL, action TEXT NOT NULL,
    domain_key TEXT NOT NULL, operation_request_digest TEXT NOT NULL, semantic_command_digest TEXT NOT NULL,
    receipt_json TEXT NOT NULL, is_alias INTEGER NOT NULL CHECK(is_alias IN(0,1)), committed_at_unix_ms INTEGER NOT NULL
);
CREATE UNIQUE INDEX uq_local_media_operation_domain ON local_media_operations(action,domain_key) WHERE is_alias=0;
CREATE TABLE local_media_operation_audit(local_operation_id TEXT PRIMARY KEY,outcome TEXT NOT NULL,committed_at_unix_ms INTEGER NOT NULL);
CREATE TABLE media_creation_sequence(singleton INTEGER PRIMARY KEY CHECK(singleton=1),next_value INTEGER NOT NULL);
INSERT INTO media_creation_sequence(singleton,next_value) VALUES(1,1);

CREATE INDEX idx_sessions_project_started ON sessions (project_id, started_at DESC);
CREATE INDEX idx_sessions_last_active     ON sessions (last_active_at DESC);
CREATE INDEX idx_sessions_open            ON sessions (ended_at) WHERE ended_at IS NULL;
CREATE INDEX idx_sessions_parent          ON sessions (parent_session_id);
-- Partial so rows whose short_id is still NULL (lazily backfilled on next
-- touch by src/db/sessions.rs) don't trip the uniqueness constraint.
CREATE UNIQUE INDEX idx_sessions_short_id_project
    ON sessions (project_id, short_id)
    WHERE short_id IS NOT NULL;
CREATE INDEX idx_sessions_archived  ON sessions (archived_at);
CREATE INDEX idx_sessions_ephemeral ON sessions (ephemeral);
CREATE INDEX idx_sessions_btw_parent ON sessions (btw_parent_session_id);
CREATE UNIQUE INDEX idx_sessions_one_live_btw
    ON sessions (btw_parent_session_id)
    WHERE btw_parent_session_id IS NOT NULL;
CREATE INDEX idx_sessions_created_by_principal ON sessions (created_by_principal);
CREATE INDEX idx_sessions_shared_project ON sessions (project_root, shared_with_collaborators)
  WHERE shared_with_collaborators = 1;
CREATE INDEX idx_sessions_assistant ON sessions (assistant_name, last_active_at DESC)
  WHERE assistant_name IS NOT NULL;

-- ---- sealed_values ---------------------------------------------------------
-- Session-owned write-only values.  The literal is deliberately kept in the
-- private session database, like persisted transcript and redaction data.
CREATE TABLE sealed_values (
    session_id TEXT NOT NULL,
    value_id   TEXT NOT NULL,
    value      TEXT NOT NULL,
    reason     TEXT NOT NULL,
    origin     TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (session_id, value_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_sealed_values_session_created
    ON sealed_values(session_id, created_at ASC, value_id ASC);

-- ---- app_flags -------------------------------------------------------------
-- Machine-local one-time UI flags. These are deliberately outside project
-- config so onboarding notices do not depend on workspace trust state.

CREATE TABLE app_flags (
    key     TEXT    PRIMARY KEY,
    seen_at INTEGER NOT NULL
);

-- ---- tool_call_events (GOALS §15b) ----------------------------------------

CREATE TABLE tool_call_events (
    event_id            TEXT    PRIMARY KEY,
    session_id          TEXT    NOT NULL,
    call_id             TEXT    NOT NULL,
    parent_call_id      TEXT    DEFAULT NULL,
    parent_child_index  INTEGER DEFAULT NULL,
    timestamp           INTEGER NOT NULL,

    -- denormalized for fast group-bys; model/provider/project rarely
    -- change inside a call.
    model               TEXT    NOT NULL DEFAULT '',
    provider            TEXT    NOT NULL DEFAULT '',
    project_id          TEXT    NOT NULL,
    project_root        TEXT    NOT NULL,

    agent               TEXT    NOT NULL,
    tool                TEXT    NOT NULL,
    mcp_server          TEXT    DEFAULT NULL,
    path                TEXT,
    language            TEXT,

    -- recovery telemetry (GOALS §14 / §15b)
    recovery_kind       TEXT,                       -- NULL | edit_cascade | shape_repair | relational_default
    recovery_stage      TEXT,
    hard_fail           INTEGER NOT NULL DEFAULT 0 CHECK (hard_fail IN (0, 1)),

    -- structured bash/sandbox outcome fields for escalation lookup. NULL
    -- exit_code means no shell exit was produced (spawn/cancel/signaled).
    exit_code           INTEGER DEFAULT NULL,
    sandbox_enabled     INTEGER NOT NULL DEFAULT 0 CHECK (sandbox_enabled IN (0, 1)),
    sandboxed           INTEGER NOT NULL DEFAULT 0 CHECK (sandboxed IN (0, 1)),
    sandbox_unavailable_reason TEXT DEFAULT NULL,

    -- audit: the two projections live on the same row (GOALS §14a)
    original_input_json TEXT    NOT NULL,
    wire_input_json     TEXT    NOT NULL,

    output              TEXT    NOT NULL DEFAULT '',
    truncated           INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0, 1)),
    duration_ms         INTEGER,

    -- tool-call mining across versions: CARGO_PKG_VERSION at call time,
    -- and the LLM steering mode (defensive/normal) at call time.
    cockpit_version     TEXT    DEFAULT NULL,
    llm_mode            TEXT CHECK (llm_mode IN ('defensive', 'normal', 'frontier')),

    -- §12 repair shape fingerprint: a short stable hash of the malformed
    -- input shape (tool :: sorted[ instance_path | error_code | expected |
    -- received ]) so `cockpit debug failed-calls` can group failures by
    -- model + fingerprint. NULL for clean calls.
    shape_fingerprint   TEXT    DEFAULT NULL,

    -- post-result hint layer (`engine::bash_hints`): JSON `{ kind, text,
    -- severity }` when a rule matched on a bash call; NULL otherwise.
    hint                TEXT    DEFAULT NULL,

    -- provider wire identity for the call: the provider-native item/call
    -- ids, where the call id came from, the wire API flavor, and the
    -- provider family.
    provider_item_id        TEXT DEFAULT NULL,
    provider_call_id        TEXT DEFAULT NULL,
    provider_call_id_source TEXT DEFAULT NULL,
    wire_api                TEXT DEFAULT NULL,
    provider_family         TEXT DEFAULT NULL,

    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_tce_session_ts ON tool_call_events (session_id, timestamp);
CREATE INDEX idx_tce_project_ts ON tool_call_events (project_id, timestamp);
CREATE INDEX idx_tce_model_ts   ON tool_call_events (model, timestamp);
CREATE INDEX idx_tce_tool_ts    ON tool_call_events (tool, timestamp);
CREATE INDEX idx_tce_lang_ts    ON tool_call_events (language, timestamp);
CREATE INDEX idx_tce_parent     ON tool_call_events (parent_call_id);

-- ---- inference_calls -------------------------------------------------------

CREATE TABLE inference_calls (
    call_id             TEXT    PRIMARY KEY,
    session_id          TEXT    NOT NULL,
    project_id          TEXT    NOT NULL,
    project_root        TEXT    NOT NULL,
    model               TEXT    NOT NULL,
    provider            TEXT    NOT NULL,
    timestamp           INTEGER NOT NULL,
    input_tokens        INTEGER NOT NULL,
    output_tokens       INTEGER NOT NULL,
    cached_input_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd_micros     INTEGER,                    -- NULL unless prices.json is available

    -- 1 = made by the utility model / background machinery (auto-titling,
    -- auto-router, prompt-injection guard, `/compact` brief, …) rather
    -- than a foreground user turn, so `/export debug` can split them out.
    is_utility INTEGER NOT NULL DEFAULT 0 CHECK (is_utility IN (0, 1)),

    -- input tokens *written into* the prompt cache on a miss (Anthropic
    -- `cache_creation`), as distinct from cached_input_tokens (served
    -- from cache on a hit). Validates the pruning policy's cache-hit
    -- expectation (GOALS §10) against measured reality.
    cache_creation_input_tokens INTEGER NOT NULL DEFAULT 0,

    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_ic_session_ts ON inference_calls (session_id, timestamp);
CREATE INDEX idx_ic_project_ts ON inference_calls (project_id, timestamp);
CREATE INDEX idx_ic_model_ts   ON inference_calls (model, timestamp);

-- ---- file-lock mirror (plan §4.1) -------------------------------------------

CREATE TABLE lock_state (
    path        TEXT    PRIMARY KEY,
    agent_id    TEXT    NOT NULL,
    session_id  TEXT    NOT NULL,
    acquired_at INTEGER NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_lock_state_session ON lock_state (session_id);

CREATE TABLE lock_reads (
    session_id  TEXT    NOT NULL,
    agent_id    TEXT    NOT NULL,
    path        TEXT    NOT NULL,
    read_at     INTEGER NOT NULL,
    read_hash   INTEGER,
    PRIMARY KEY (session_id, agent_id, path),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

-- ---- needs_attention (GOALS §3b) --------------------------------------------
-- The `question` tool raises one interrupt carrying an ARRAY of questions
-- (tool dispatch is sequential, so everything the agent needs has to ride
-- in a single call). `questions_json` holds a serialized
-- proto::InterruptQuestionSet; the single-question `question_json` column
-- serves the `jobs` needs-attention nudge. A row never populates both.

CREATE TABLE needs_attention (
    interrupt_id   TEXT    PRIMARY KEY,
    session_id     TEXT    NOT NULL,
    agent_id       TEXT    NOT NULL,
    description    TEXT    NOT NULL,
    state          TEXT    NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'parked', 'executing', 'interrupted', 'resolved')),
    question_json  TEXT,                            -- serialized proto::InterruptQuestion or NULL
    raised_at      INTEGER NOT NULL,
    resolved_at    INTEGER,
    response_json  TEXT,                            -- serialized proto::ResolveResponse, NULL if unresolved
    questions_json TEXT,                            -- serialized proto::InterruptQuestionSet or NULL
    parked_tool    TEXT,                            -- wire tool name for parked replay, or NULL
    parked_args_json TEXT,                          -- verbatim replay wire args; same exposure boundary as session_events.wire_input_json
    parked_call_id TEXT,                            -- assistant tool-call id for parked replay, or NULL
    parked_resume_json TEXT,                        -- serialized resume anchor, or NULL
    parked_gate_json TEXT,                          -- serialized per-call gate replay memo, or NULL
    CHECK (question_json IS NULL OR questions_json IS NULL),
    CHECK (
        (parked_tool IS NULL AND parked_args_json IS NULL AND parked_call_id IS NULL AND parked_resume_json IS NULL)
        OR
        (parked_tool IS NOT NULL AND parked_args_json IS NOT NULL AND parked_call_id IS NOT NULL AND parked_resume_json IS NOT NULL)
    ),
    CHECK (state <> 'executing' OR parked_tool IS NOT NULL),
    CHECK ((state = 'resolved') = (resolved_at IS NOT NULL)),
    CHECK (state IN ('executing', 'interrupted', 'resolved') OR response_json IS NULL),
    CHECK (state <> 'executing' OR response_json IS NOT NULL),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_na_session_open ON needs_attention (session_id, state);

-- ---- tool_call_stats view ----------------------------------------------------

CREATE VIEW tool_call_stats AS
SELECT
    event_id, session_id, call_id, timestamp,
    model, provider, project_id, project_root,
    tool, path, language,
    recovery_kind, recovery_stage, hard_fail,
    llm_mode, shape_fingerprint,

    CASE
        WHEN recovery_kind IS NOT NULL
         AND recovery_kind != 'relational_default'
         AND hard_fail = 0
        THEN 1 ELSE 0
    END AS recoverable,

    CASE
        WHEN hard_fail = 1                                  THEN 1.0
        WHEN recovery_kind IS NULL                          THEN 0.0
        WHEN recovery_kind = 'relational_default'           THEN 0.0
        WHEN recovery_kind = 'edit_cascade'
             AND recovery_stage = 'line_trim'               THEN 0.10
        WHEN recovery_kind = 'shape_repair'
             AND recovery_stage = 'null_for_optional'       THEN 0.20
        WHEN recovery_kind = 'edit_cascade'
             AND recovery_stage = 'whitespace_normalized'   THEN 0.30
        WHEN recovery_kind = 'shape_repair'
             AND recovery_stage = 'wrap_bare_string'        THEN 0.30
        WHEN recovery_kind = 'edit_cascade'
             AND recovery_stage = 'indent_flexible'         THEN 0.40
        WHEN recovery_kind = 'shape_repair'
             AND recovery_stage = 'parse_stringified_array' THEN 0.40
        WHEN recovery_kind = 'edit_cascade'
             AND recovery_stage = 'escape_normalized'       THEN 0.50
        WHEN recovery_kind = 'shape_repair'
             AND recovery_stage = 'wrap_single_arg'         THEN 0.50
        WHEN recovery_kind = 'edit_cascade'
             AND recovery_stage = 'block_anchor'            THEN 0.60
        WHEN recovery_kind = 'edit_cascade'
             AND recovery_stage = 'trimmed_boundary'        THEN 0.70
        WHEN recovery_kind = 'edit_cascade'
             AND recovery_stage = 'context_aware'           THEN 0.90
        ELSE 0.50                                            -- unknown stage; safe middle
    END AS severity
FROM tool_call_events;

-- ---- usage_events ------------------------------------------------------------
-- Frequency tally for autocomplete tie-breaking (models, slash commands,
-- @ tags). One row per accepted pick; a rolling 30-day window is applied
-- at aggregation time, and rows older than the window are pruned on
-- daemon startup.

CREATE TABLE usage_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT    NOT NULL CHECK (kind IN ('model', 'slash', 'tag')),
    key         TEXT    NOT NULL,   -- 'provider/model' | command name | relative tag path
    project_id  TEXT,               -- NULL for model+slash (global); set for tag
    ts          INTEGER NOT NULL    -- unix seconds
);

CREATE INDEX idx_usage_kind_ts      ON usage_events (kind, ts);
CREATE INDEX idx_usage_kind_proj_ts ON usage_events (kind, project_id, ts);

-- ---- tokenizer_calibration -----------------------------------------------------
-- Per-(provider, model) tokenizer calibration: the tiktoken strategy +
-- scale factor that best matches the provider's reported counts. Learned
-- in-memory over a session and persisted here with a 90-day expiry. A
-- stale row still beats the global cl100k_base default, so the resolver
-- returns it even when expired (and a fresh window recomputes in the
-- background).

CREATE TABLE tokenizer_calibration (
    provider           TEXT    NOT NULL,
    model              TEXT    NOT NULL,
    strategy           TEXT    NOT NULL,
    scale              REAL    NOT NULL,
    computed_at        INTEGER NOT NULL,
    expires_at         INTEGER NOT NULL,   -- computed_at + 90 days
    sample_total_tokens INTEGER NOT NULL,
    sample_calls       INTEGER NOT NULL,
    PRIMARY KEY (provider, model)
);

-- ---- codebase-intelligence index (GOALS §21) -----------------------------------
-- Project-scoped: every row carries the project `root` so multi-project
-- (§M6) is an additive change later. Tables are prefixed `intel_` to avoid
-- collisions in the shared cockpit DB.
--
-- The index is on-demand (no file watcher): the central `index_target`
-- helper re-stats tracked files on each tool call and re-indexes
-- stale/removed ones before answering. `intel_files` is the parent; the
-- per-file tables FK to it ON DELETE CASCADE so dropping a deleted or
-- stale file's row purges its symbols/imports/identifiers/deps/callsites
-- in one statement.

CREATE TABLE intel_meta (
    root  TEXT    NOT NULL,
    key   TEXT    NOT NULL,
    value INTEGER NOT NULL,
    PRIMARY KEY (root, key)
);

CREATE TABLE intel_files (
    root         TEXT NOT NULL,
    path         TEXT NOT NULL,
    language     TEXT NOT NULL,
    mtime_ns     INTEGER NOT NULL,
    size         INTEGER NOT NULL,
    lines        INTEGER,
    content_hash TEXT NOT NULL,
    indexed_at   INTEGER NOT NULL,
    PRIMARY KEY (root, path)
);

CREATE TABLE intel_symbols (
    root       TEXT NOT NULL,
    path       TEXT NOT NULL,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL,
    line       INTEGER NOT NULL,
    end_line   INTEGER NOT NULL,
    parent     TEXT,
    visibility TEXT,
    signature  TEXT,
    FOREIGN KEY (root, path) REFERENCES intel_files(root, path) ON DELETE CASCADE
);

CREATE TABLE intel_imports (
    root   TEXT NOT NULL,
    path   TEXT NOT NULL,
    target TEXT NOT NULL,
    line   INTEGER NOT NULL,
    FOREIGN KEY (root, path) REFERENCES intel_files(root, path) ON DELETE CASCADE
);

CREATE TABLE intel_identifiers (
    root  TEXT NOT NULL,
    path  TEXT NOT NULL,
    token TEXT NOT NULL,
    line  INTEGER NOT NULL,
    FOREIGN KEY (root, path) REFERENCES intel_files(root, path) ON DELETE CASCADE
);

CREATE TABLE intel_deps (
    root       TEXT NOT NULL,
    importer   TEXT NOT NULL,
    importee   TEXT,
    raw_target TEXT NOT NULL,
    line       INTEGER NOT NULL,
    FOREIGN KEY (root, importer) REFERENCES intel_files(root, path) ON DELETE CASCADE
);

CREATE TABLE intel_callsites (
    root          TEXT NOT NULL,
    caller_file   TEXT NOT NULL,
    caller_line   INTEGER NOT NULL,
    caller_symbol TEXT,
    callee_name   TEXT NOT NULL,
    callee_kind   TEXT,
    FOREIGN KEY (root, caller_file) REFERENCES intel_files(root, path) ON DELETE CASCADE
);

CREATE INDEX intel_symbols_name      ON intel_symbols(name);
CREATE INDEX intel_symbols_file      ON intel_symbols(root, path);
CREATE INDEX intel_identifiers_token ON intel_identifiers(token);
CREATE INDEX intel_identifiers_file  ON intel_identifiers(root, path);
CREATE INDEX intel_imports_file      ON intel_imports(root, path);
CREATE INDEX intel_deps_importer     ON intel_deps(root, importer);
CREATE INDEX intel_deps_importee     ON intel_deps(root, importee);
CREATE INDEX intel_callsites_callee  ON intel_callsites(root, callee_name);
CREATE INDEX intel_callsites_file    ON intel_callsites(root, caller_file);

-- Call-graph centrality materialization (GOALS §21): a small per-file
-- score table recomputed wholesale once per `ensure_fresh` pass that
-- wrote any chunk. `score` is the weighted in-degree per file. Purely an
-- additive ranking signal, never a filter; no FK to intel_files because
-- the table is rebuilt wholesale each pass.

CREATE TABLE intel_centrality (
    root  TEXT NOT NULL,
    path  TEXT NOT NULL,
    score REAL NOT NULL,
    PRIMARY KEY (root, path)
);

-- ---- packages (GOALS §3a docs agent) --------------------------------------------
-- Cockpit-owned package registry. User-global, NOT project-scoped: the
-- docs agent answers questions about third-party dependencies whose
-- source clones are shared across every project on the device. `source_url`
-- is indexed so Git packages dedupe by repo. `source_type` is 'git' or
-- 'local'.

CREATE TABLE packages (
    id            TEXT PRIMARY KEY,
    identifier    TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL,
    source_type   TEXT NOT NULL CHECK (source_type IN ('git', 'local')),
    source_url    TEXT,
    source_branch TEXT,
    path          TEXT NOT NULL,
    shallow       INTEGER NOT NULL DEFAULT 1 CHECK (shallow IN (0, 1)),
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    -- kcl package preparation scope imported from the portable
    -- `kcl packages export` manifest.
    prepare_scope TEXT NOT NULL DEFAULT 'global' CHECK (prepare_scope IN ('global', 'branch'))
);

CREATE INDEX packages_source_url ON packages(source_url);

-- ---- session-log export capture (session-log-export) --------------------------------
-- Two always-on capture surfaces feeding `cockpit export <session>`:
--
--   * inference_requests — the FULL assembled outbound request body for
--     every inference call, captured at the engine→provider boundary
--     AFTER redaction (we store exactly what hit the wire). Keyed by the
--     SAME `call_id` as the `inference_calls` metadata row, so the two
--     join. Written at DISPATCH with status `pending`, then updated on
--     settle: pending → completed | errored | timed_out | cancelled — so
--     an export of a hung/failed turn still contains the attempt.
--
--   * session_events — a per-session event timeline. `seq` is a globally
--     monotonic INTEGER (AUTOINCREMENT rowid) — the authoritative sort
--     and correlation key across the whole fork tree. `ts_ms` is
--     millisecond resolution. The `type` discriminant aligns with the
--     engine `TurnEvent` vocabulary; per-type fields ride in `data_json`
--     so the schema stays stable as the event set grows.

CREATE TABLE inference_requests (
    call_id      TEXT    PRIMARY KEY,           -- == inference_calls.call_id
    session_id   TEXT    NOT NULL,
    ts_ms        INTEGER NOT NULL,              -- epoch milliseconds
    payload_json TEXT    NOT NULL,              -- full post-redaction request
    status       TEXT    NOT NULL DEFAULT 'completed' CHECK (status IN ('pending', 'completed', 'errored', 'timed_out', 'cancelled')),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_ireq_session ON inference_requests (session_id);

CREATE TABLE session_events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT, -- globally monotonic order
    session_id  TEXT    NOT NULL,
    ts_ms       INTEGER NOT NULL,                  -- epoch milliseconds
    type        TEXT    NOT NULL CHECK (type IN (
        'user_message', 'user_note', 'assistant_message', 'inference_request',
        'tool_call', 'tandem_inference', 'tool_call_started',
        'tool_call_completed', 'subagent_spawned', 'subagent_routing',
        'subagent_report', 'context_pruned', 'session_compacted',
        'permission_decision', 'interrupt_decision', 'tool_rejected',
        'primary_swap', 'inference_failure', 'failed_turn_recovery',
        'turn_interrupted', 'skill_auto_select', 'auto_prune_diagnostic',
        'goal_progress_diagnostic', 'resource_promotion', 'notice',
        'model_switch', 'hook_run'
    )),
    agent       TEXT,                              -- emitting agent, when known
    call_id     TEXT,                              -- correlation key, when applicable
    task_call_id TEXT,                             -- owning delegation run, when inside a child
    label       TEXT,                              -- delegation label paired with task_call_id
    data_json   TEXT    NOT NULL DEFAULT '{}',     -- per-type payload
    -- assistant-turn reasoning projected out of `data_json` so queries and
    -- exports can read it column-wise without parsing JSON (the same idiom
    -- the FTS triggers use against `$.text`). VIRTUAL: computed on read.
    reasoning TEXT
        GENERATED ALWAYS AS (json_extract(data_json, '$.reasoning')) VIRTUAL,
    origin_principal TEXT,                         -- remote principal attribution
    provider_id TEXT,                              -- authoring model provider id, NULL for model-less events
    model_id TEXT,                                 -- authoring model id, NULL for model-less events
    llm_mode TEXT CHECK (llm_mode IN ('defensive', 'normal', 'frontier')), -- authoring LLM mode, NULL for model-less events
    model_trust TEXT,                              -- write-time resolved model trust, NULL for model-less events
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX uq_session_events_session_seq ON session_events (session_id, seq);
CREATE INDEX idx_sevents_call        ON session_events (call_id);
CREATE INDEX idx_sevents_task_child  ON session_events (session_id, task_call_id, label, seq)
  WHERE task_call_id IS NOT NULL;
CREATE INDEX idx_sevents_origin_principal ON session_events (origin_principal)
  WHERE origin_principal IS NOT NULL;
-- History trust filters scan one session in seq order while excluding trusted-authored rows.
CREATE INDEX idx_sevents_session_trust_seq ON session_events (session_id, model_trust, seq)
  WHERE model_trust IS NOT NULL;

-- Durable idempotency tombstones for accepted client submissions that never
-- become user_message events. A removed, cancelled, or preflight-rejected
-- UUID must remain terminal across worker/daemon restarts; otherwise an
-- ambiguous exact retry could execute work the user already discarded.
CREATE TABLE client_submission_terminal_receipts (
    session_id          TEXT NOT NULL,
    client_submission_id TEXT NOT NULL,
    fingerprint         TEXT NOT NULL,
    wire_fingerprint    TEXT NOT NULL,
    origin_principal    TEXT,
    disposition         TEXT NOT NULL CHECK (disposition IN (
        'removed', 'cancelled', 'preflight_rejected'
    )),
    created_at_ms       INTEGER NOT NULL,
    PRIMARY KEY (session_id, client_submission_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

-- Large compaction records spill out of the inline event JSON as one canonical
-- payload (brief + handoff + serialized tail). The `session_compacted` event
-- remains authoritative and carries this opaque, session-scoped id.
CREATE TABLE compaction_handoffs (
    handoff_id   TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_compaction_handoffs_session ON compaction_handoffs(session_id);

-- One durable speculative compaction shadow per non-ephemeral session. The
-- payload is owned by cockpit-core so it can evolve from a ready shadow brief
-- to a prepared compaction without another schema change.
CREATE TABLE compaction_shadows (
    session_id   TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

-- ---- approval_grants (sandboxing part 1, §2) -------------------------------------
-- Session-scope command/path/MCP-tool approval grants; a present row skips the
-- approval prompt. Project- and Global-scope grants persist outside the
-- DB in the layered `.cockpit/` config dirs — only Session belongs in
-- SQLite (dropped with the session via CASCADE).
--
-- `grant_kind` is 'command' (keyed by argv[0]+subcommand, e.g. `gh pr`),
-- 'path', 'mcp_tool' (keyed by external MCP server/tool), or 'harness'
-- (keyed by configured external harness name). Wrapper/eval commands are
-- NEVER persisted here — the store layer rejects them before insert.
-- `risk_tier` records the command tier
-- displayed when an allow grant was issued, so future invocations of the
-- same coarse command key only skip the prompt when their recomputed tier
-- is no higher. Path grants, MCP-tool grants, and rejects carry no tier.
-- `verdict` carries the polarity; the (session_id, grant_kind, grant_key)
-- PK means allow and reject for the same key can never coexist — the
-- recorder flips the verdict in place via INSERT OR REPLACE.

CREATE TABLE approval_grants (
    session_id  TEXT    NOT NULL,
    grant_kind  TEXT    NOT NULL CHECK (grant_kind IN ('command', 'path', 'mcp_tool', 'harness')),
    grant_key   TEXT    NOT NULL,
    granted_at  INTEGER NOT NULL,
    verdict     TEXT    NOT NULL DEFAULT 'allow'
        CHECK (verdict IN ('allow', 'reject')),
    access      TEXT
        CHECK (
            (grant_kind = 'path' AND access IN ('read', 'read-write'))
            OR (grant_kind <> 'path' AND access IS NULL)
        ),
    risk_tier   TEXT
        CHECK (
            (grant_kind = 'command' AND verdict = 'allow' AND risk_tier IS NOT NULL
             AND risk_tier IN ('ordinary','mutating','destructive','privileged','dynamic'))
            OR ((grant_kind <> 'command' OR verdict <> 'allow') AND risk_tier IS NULL)
        ),
    PRIMARY KEY (session_id, grant_kind, grant_key),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_approval_grants_session ON approval_grants (session_id);

-- ---- loop_guard_rules ---------------------------------------------------------
-- Session-scope loop-guard rules: the loop guard prompts when the model
-- emits a tool call whose signature (tool name + canonical `wire_input`)
-- is identical to the immediately-preceding call. "Always accept/reject
-- for this session" records a rule here so an exact repeat is
-- auto-resolved. `signature` is a stable hash — see
-- `GrantStore::loop_signature`. Project-/Global-scope rules persist in
-- `.cockpit/` `approvals.json`.

CREATE TABLE loop_guard_rules (
    session_id    TEXT    NOT NULL,
    signature     TEXT    NOT NULL,
    rule_verdict  TEXT    NOT NULL CHECK (rule_verdict IN ('accept', 'reject')),
    recorded_at   INTEGER NOT NULL,
    PRIMARY KEY (session_id, signature),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_loop_guard_rules_session ON loop_guard_rules (session_id);

-- ---- session full-text search (`session_search` / `session_read`) -----------------
-- A single FTS5 virtual table indexes the *searchable* surface of every
-- session: the session TITLE plus the text of `user_message` /
-- `assistant_message` events and model-written compaction briefs/handoffs.
-- Tool outputs, tool-call args, and raw inference payloads are deliberately
-- NOT indexed — they're noise for recall and a token/privacy hazard.
--
-- Layout choice: a contentless FTS5 table (`content=''`) with one indexed
-- text column, because the searchable text is spread across two base
-- tables (sessions.title + session_events.data_json) and lives inside a
-- JSON blob in the events case — there is no single column FTS5 could
-- shadow. The `session_fts_docs` side table maps FTS rowids back to a
-- thread (`session_id`) and, for message rows, an in-thread location
-- (`seq`); it stores identifiers only, never a second copy of text.
--
--   row_kind   — 'title' | 'message' | 'compaction', so readers can window
--                messages separately from compaction summary matches.
--   seq        — session_events.seq for a message row; NULL for a title.

CREATE VIRTUAL TABLE session_fts USING fts5(
    body,
    content=''
);

CREATE TABLE session_fts_docs (
    rowid      INTEGER PRIMARY KEY,
    row_kind   TEXT NOT NULL CHECK (row_kind IN ('title', 'message', 'compaction')),
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    seq        INTEGER,
    FOREIGN KEY (session_id, seq)
        REFERENCES session_events(session_id, seq) ON DELETE CASCADE,
    UNIQUE(row_kind, session_id, seq)
);

CREATE UNIQUE INDEX session_fts_docs_one_title
    ON session_fts_docs(session_id)
    WHERE row_kind = 'title';

CREATE INDEX session_fts_docs_session_idx
    ON session_fts_docs(session_id);

-- Event sync: `user_message` / `assistant_message` rows carry conversational
-- text at data_json.'$.text'. `session_compacted` rows carry model-written
-- summaries at data_json.'$.brief_text' / '$.handoff_text', or in the spilled
-- compaction_handoffs payload referenced by '$.handoff_ref'. Tool events stay
-- out of FTS. Because the table is contentless, UPDATE/DELETE use FTS5's
-- special delete command with the old canonical text, then reconcile the
-- identifier-only rowid mapping.

CREATE TRIGGER session_fts_events_ai AFTER INSERT ON session_events
WHEN (new.type IN ('user_message', 'assistant_message')
      AND json_extract(new.data_json, '$.text') IS NOT NULL)
   OR (new.type = 'session_compacted'
      AND COALESCE(
        json_extract(new.data_json, '$.brief_text'),
        json_extract(new.data_json, '$.handoff_text'),
        (SELECT json_extract(payload_json, '$.brief_text')
           FROM compaction_handoffs
          WHERE handoff_id = json_extract(new.data_json, '$.handoff_ref')
            AND session_id = new.session_id),
        (SELECT json_extract(payload_json, '$.handoff_text')
           FROM compaction_handoffs
          WHERE handoff_id = json_extract(new.data_json, '$.handoff_ref')
            AND session_id = new.session_id)
      ) IS NOT NULL)
BEGIN
    INSERT INTO session_fts_docs (row_kind, session_id, seq)
    VALUES (
      CASE WHEN new.type = 'session_compacted' THEN 'compaction' ELSE 'message' END,
      new.session_id,
      new.seq
    );
    INSERT INTO session_fts (rowid, body)
    VALUES (
      last_insert_rowid(),
      CASE WHEN new.type = 'session_compacted' THEN
        COALESCE(
          json_extract(new.data_json, '$.brief_text'),
          json_extract(new.data_json, '$.handoff_text'),
          (SELECT json_extract(payload_json, '$.brief_text')
             FROM compaction_handoffs
            WHERE handoff_id = json_extract(new.data_json, '$.handoff_ref')
              AND session_id = new.session_id),
          (SELECT json_extract(payload_json, '$.handoff_text')
             FROM compaction_handoffs
            WHERE handoff_id = json_extract(new.data_json, '$.handoff_ref')
              AND session_id = new.session_id)
        )
      ELSE json_extract(new.data_json, '$.text') END
    );
END;

CREATE TRIGGER session_fts_events_ad AFTER DELETE ON session_events
WHEN old.type IN ('user_message', 'assistant_message', 'session_compacted')
BEGIN
    INSERT INTO session_fts (session_fts, rowid, body)
    SELECT 'delete',
           rowid,
           CASE WHEN old.type = 'session_compacted' THEN
             COALESCE(
               json_extract(old.data_json, '$.brief_text'),
               json_extract(old.data_json, '$.handoff_text'),
               (SELECT json_extract(payload_json, '$.brief_text')
                  FROM compaction_handoffs
                 WHERE handoff_id = json_extract(old.data_json, '$.handoff_ref')
                   AND session_id = old.session_id),
               (SELECT json_extract(payload_json, '$.handoff_text')
                  FROM compaction_handoffs
                 WHERE handoff_id = json_extract(old.data_json, '$.handoff_ref')
                   AND session_id = old.session_id)
             )
           ELSE json_extract(old.data_json, '$.text') END
    FROM session_fts_docs
    WHERE row_kind IN ('message', 'compaction') AND seq = old.seq;
    DELETE FROM session_fts_docs
    WHERE row_kind IN ('message', 'compaction') AND seq = old.seq;
END;

CREATE TRIGGER session_fts_events_au AFTER UPDATE ON session_events
WHEN old.type IN ('user_message', 'assistant_message')
     OR old.type = 'session_compacted'
     OR new.type IN ('user_message', 'assistant_message')
     OR new.type = 'session_compacted'
BEGIN
    INSERT INTO session_fts (session_fts, rowid, body)
    SELECT 'delete',
           rowid,
           CASE WHEN old.type = 'session_compacted' THEN
             COALESCE(
               json_extract(old.data_json, '$.brief_text'),
               json_extract(old.data_json, '$.handoff_text'),
               (SELECT json_extract(payload_json, '$.brief_text')
                  FROM compaction_handoffs
                 WHERE handoff_id = json_extract(old.data_json, '$.handoff_ref')
                   AND session_id = old.session_id),
               (SELECT json_extract(payload_json, '$.handoff_text')
                  FROM compaction_handoffs
                 WHERE handoff_id = json_extract(old.data_json, '$.handoff_ref')
                   AND session_id = old.session_id)
             )
           ELSE json_extract(old.data_json, '$.text') END
    FROM session_fts_docs
    WHERE row_kind IN ('message', 'compaction') AND seq = old.seq;
    DELETE FROM session_fts_docs
    WHERE row_kind IN ('message', 'compaction') AND seq = old.seq;
    INSERT INTO session_fts_docs (row_kind, session_id, seq)
    SELECT CASE WHEN new.type = 'session_compacted' THEN 'compaction' ELSE 'message' END,
           new.session_id,
           new.seq
    WHERE (new.type IN ('user_message', 'assistant_message')
           AND json_extract(new.data_json, '$.text') IS NOT NULL)
       OR (new.type = 'session_compacted'
           AND COALESCE(
             json_extract(new.data_json, '$.brief_text'),
             json_extract(new.data_json, '$.handoff_text'),
             (SELECT json_extract(payload_json, '$.brief_text')
                FROM compaction_handoffs
               WHERE handoff_id = json_extract(new.data_json, '$.handoff_ref')
                 AND session_id = new.session_id),
             (SELECT json_extract(payload_json, '$.handoff_text')
                FROM compaction_handoffs
               WHERE handoff_id = json_extract(new.data_json, '$.handoff_ref')
                 AND session_id = new.session_id)
           ) IS NOT NULL);
    INSERT INTO session_fts (rowid, body)
    SELECT last_insert_rowid(),
           CASE WHEN new.type = 'session_compacted' THEN
             COALESCE(
               json_extract(new.data_json, '$.brief_text'),
               json_extract(new.data_json, '$.handoff_text'),
               (SELECT json_extract(payload_json, '$.brief_text')
                  FROM compaction_handoffs
                 WHERE handoff_id = json_extract(new.data_json, '$.handoff_ref')
                   AND session_id = new.session_id),
               (SELECT json_extract(payload_json, '$.handoff_text')
                  FROM compaction_handoffs
                 WHERE handoff_id = json_extract(new.data_json, '$.handoff_ref')
                   AND session_id = new.session_id)
             )
           ELSE json_extract(new.data_json, '$.text') END
    WHERE (new.type IN ('user_message', 'assistant_message')
           AND json_extract(new.data_json, '$.text') IS NOT NULL)
       OR (new.type = 'session_compacted'
           AND COALESCE(
             json_extract(new.data_json, '$.brief_text'),
             json_extract(new.data_json, '$.handoff_text'),
             (SELECT json_extract(payload_json, '$.brief_text')
                FROM compaction_handoffs
               WHERE handoff_id = json_extract(new.data_json, '$.handoff_ref')
                 AND session_id = new.session_id),
             (SELECT json_extract(payload_json, '$.handoff_text')
                FROM compaction_handoffs
               WHERE handoff_id = json_extract(new.data_json, '$.handoff_ref')
                 AND session_id = new.session_id)
           ) IS NOT NULL);
END;

-- Title sync: a session's title is searchable too. Titles change via
-- UPDATE (set / auto-title / rename), so the update trigger handles
-- NULL→text, text→text, and text→NULL transitions.

CREATE TRIGGER session_fts_title_ai AFTER INSERT ON sessions
WHEN new.title IS NOT NULL AND new.title <> ''
BEGIN
    INSERT INTO session_fts_docs (row_kind, session_id, seq)
    VALUES ('title', new.session_id, NULL);
    INSERT INTO session_fts (rowid, body)
    VALUES (last_insert_rowid(), new.title);
END;

CREATE TRIGGER session_fts_title_au AFTER UPDATE OF title ON sessions
BEGIN
    INSERT INTO session_fts (session_fts, rowid, body)
    SELECT 'delete', rowid, old.title
    FROM session_fts_docs
    WHERE row_kind = 'title' AND session_id = old.session_id;
    DELETE FROM session_fts_docs
    WHERE row_kind = 'title' AND session_id = old.session_id;
    INSERT INTO session_fts_docs (row_kind, session_id, seq)
    SELECT 'title', new.session_id, NULL
    WHERE new.title IS NOT NULL AND new.title <> '';
    INSERT INTO session_fts (rowid, body)
    SELECT last_insert_rowid(), new.title
    WHERE new.title IS NOT NULL AND new.title <> '';
END;

CREATE TRIGGER session_fts_sessions_ad AFTER DELETE ON sessions
BEGIN
    INSERT INTO session_fts (session_fts, rowid, body)
    SELECT 'delete', d.rowid,
           CASE d.row_kind
             WHEN 'title' THEN old.title
             ELSE json_extract(e.data_json, '$.text')
           END
    FROM session_fts_docs AS d
    LEFT JOIN session_events AS e ON e.seq = d.seq
    WHERE d.session_id = old.session_id;
    DELETE FROM session_fts_docs WHERE session_id = old.session_id;
END;

-- ---- guidance_contents ---------------------------------------------------------
-- Content-addressed store of guidance bodies: hash → exact body. Holds the
-- start-of-session baseline (see sessions.guidance_baseline_hash) plus
-- every subsequent injected version, so a diff can always be computed from
-- the prior stored contents. Inserts are idempotent (hash PRIMARY KEY +
-- INSERT OR IGNORE).

CREATE TABLE guidance_contents (
    hash       TEXT PRIMARY KEY,
    contents   TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- ---- subagent_handles (GOALS §3c, plan §3d) ---------------------------------------
-- Re-queryable subagents: when a read-only noninteractive subagent (e.g.
-- `explore`) reports back in `normal` mode, its full transcript is
-- persisted here keyed by an opaque handle surfaced to the caller. A
-- follow-up `task(resume_handle=…)` rehydrates the transcript and re-runs
-- the subagent with full knowledge of what it already did.
-- `transcript_json` is the JSON-serialized `Vec<rig::message::Message>`;
-- `agent` records which subagent it belongs to; `cwd` the directory it
-- ran in.

CREATE TABLE subagent_handles (
    handle          TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL
        REFERENCES sessions (session_id) ON DELETE CASCADE,
    agent           TEXT NOT NULL,
    transcript_json TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    cwd             TEXT
);

CREATE INDEX idx_subagent_handles_session ON subagent_handles (session_id);

-- ---- project_notes ---------------------------------------------------------------
-- Project-scoped scratchpad notes: a floating TUI dialog lets the user
-- jot/organize markdown notes while working. Scoped to the **project
-- root** (git/worktree root, or launch cwd outside a repo), NOT to a
-- session. TUI/DB state only — never enters any outbound model prompt
-- (token economy, GOALS §10). `(project_root, name)` is unique;
-- `position` gives a stable sidebar ordering.

CREATE TABLE project_notes (
    id           TEXT PRIMARY KEY,
    project_root TEXT NOT NULL,
    name         TEXT NOT NULL,
    -- Markdown source. Empty string for a freshly-created, not-yet-edited
    -- note.
    content      TEXT NOT NULL DEFAULT '',
    position     INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    UNIQUE (project_root, name)
);

CREATE INDEX project_notes_root ON project_notes(project_root);

-- ---- pins --------------------------------------------------------------------------
-- Pinned messages: a lightweight "come back to this later" reference on
-- any conversation message. TUI/DB state ONLY — never enters the outbound
-- model prompt. A pin stores a REFERENCE by stable id, never a snapshot:
-- `/prune` and `/compact` never mutate `session_events`, so the original
-- text stays durable and a pin always renders it. CASCADE-deletes with
-- both its session and its referenced event, so a pin can never dangle;
-- the PK makes pinning idempotent.

CREATE TABLE pins (
    session_id  TEXT    NOT NULL,
    seq         INTEGER NOT NULL,             -- == session_events.seq
    pinned_ms   INTEGER NOT NULL,             -- epoch milliseconds (pin order)
    PRIMARY KEY (session_id, seq),
    FOREIGN KEY (session_id, seq)
        REFERENCES session_events(session_id, seq) ON DELETE CASCADE
);

CREATE INDEX idx_pins_session ON pins (session_id, pinned_ms);

-- ---- prune_ledger --------------------------------------------------------------------
-- Session resume prune-ledger: resuming must be a TRUE CONTINUATION.
-- `session_events` stays the single source of truth for *content*; this
-- table is the small durable delta that reproduces the *pruned* form —
-- the on-disk twin of the in-memory prune state (`src/engine/prune.rs`).
-- Persisted at EVERY inference boundary and on every `/prune`, so
-- continuity survives an unclean daemon kill. One row per session
-- (upsert); `ledger_json` is the JSON-serialized `prune::PruneLedger`.
-- Empty/absent ledger = nothing pruned.

CREATE TABLE prune_ledger (
    session_id  TEXT PRIMARY KEY
        REFERENCES sessions (session_id) ON DELETE CASCADE,
    ledger_json TEXT NOT NULL,
    updated_at  INTEGER NOT NULL
);

-- ---- tandem_inference ------------------------------------------------------------------
-- Model-comparison tandem (shadow) inference: session-only "model
-- comparison" mode shadows every SUBSTANTIVE inference request to one or
-- more user-selected tandem `(provider, model)` pairs. Each tandem call
-- is a pure observer — it never feeds back into the agentic loop — and
-- its captured outcome is persisted here so `/export debug` ships it
-- alongside the main model's request. Unlike `inference_requests`, a
-- tandem record also stores the FULL raw completion (`response_json`)
-- and token usage (`usage_json`). Multiple tandem models can shadow the
-- same parent call, so the PK is a per-row id, not `parent_call_id`.

CREATE TABLE tandem_inference (
    id            TEXT    PRIMARY KEY,              -- per (parent call, tandem model)
    session_id    TEXT    NOT NULL,
    parent_call_id TEXT   NOT NULL,                 -- == the main call this shadows
    parent_seq    INTEGER,                          -- main call's timeline seq, when known
    agent         TEXT,                             -- agent that ran the shadowed turn
    provider      TEXT    NOT NULL,                 -- tandem provider id
    model         TEXT    NOT NULL,                 -- tandem model id
    ts_ms         INTEGER NOT NULL,                 -- epoch milliseconds (dispatch)
    request_json  TEXT    NOT NULL,                 -- full post-redaction request body
    response_json TEXT,                             -- full raw completion (text + tool calls)
    usage_json    TEXT,                             -- provider-reported token usage
    status        TEXT    NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'errored', 'timed_out', 'cancelled')),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_tandem_session ON tandem_inference (session_id);
CREATE INDEX idx_tandem_parent  ON tandem_inference (parent_call_id);

-- ---- task todos + notes + assignments --------------------------------------------------
-- Durable session todos and append-only task notes/deltas. Assignments
-- link a todo to the delegated child run (`task_call_id` + `label`) that
-- is working it.

CREATE TABLE task_todos (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'in_progress', 'completed', 'cancelled')),
    priority INTEGER NOT NULL DEFAULT 0,
    position INTEGER NOT NULL,
    outcome_summary TEXT,
    version INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX idx_task_todos_session_position
    ON task_todos(session_id, position);

CREATE INDEX idx_task_todos_session_status_priority
    ON task_todos(session_id, status, priority DESC, position);

CREATE TABLE task_todo_notes (
    id TEXT PRIMARY KEY,
    todo_id TEXT NOT NULL REFERENCES task_todos(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('summary', 'finding', 'decision', 'artifact', 'blocker', 'handoff')),
    body TEXT NOT NULL,
    author_agent TEXT NOT NULL,
    child_session_id TEXT,
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_task_todo_notes_todo_kind_time
    ON task_todo_notes(todo_id, kind, created_at);

CREATE INDEX idx_task_todo_notes_session
    ON task_todo_notes(session_id);

CREATE TABLE task_todo_assignments (
    id TEXT PRIMARY KEY,
    todo_id TEXT NOT NULL REFERENCES task_todos(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    task_call_id TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT 'default',
    child_agent TEXT NOT NULL,
    child_session_id TEXT,
    state TEXT NOT NULL CHECK (state IN ('running', 'completed', 'error', 'cancelled')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(todo_id, task_call_id, label)
);

CREATE INDEX idx_task_todo_assignments_session
    ON task_todo_assignments(session_id, task_call_id, label, created_at);

-- ---- session_goals (`/goal`) --------------------------------------------------------------

CREATE TABLE session_goals (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    project_id TEXT NOT NULL,
    objective TEXT NOT NULL,
    context TEXT,
    status TEXT NOT NULL CHECK (status IN ('active', 'paused', 'blocked', 'pending_verification', 'complete', 'budget_limited', 'usage_limited')),
    token_budget INTEGER,
    tokens_used INTEGER NOT NULL DEFAULT 0,
    blocked_attempts INTEGER NOT NULL DEFAULT 0,
    completion_evidence TEXT,
    verification_rounds INTEGER NOT NULL DEFAULT 0,
    last_read_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- At most one goal in a non-terminal status per session.
CREATE UNIQUE INDEX idx_session_goals_one_open
    ON session_goals(session_id)
    WHERE status IN ('active', 'paused', 'blocked', 'pending_verification', 'budget_limited', 'usage_limited');

CREATE INDEX idx_session_goals_session_status
    ON session_goals(session_id, status, updated_at DESC);

-- ---- compressed_tool_results ------------------------------------------------------------
-- Durable retrieval records for compressed/truncated non-file tool
-- results.

CREATE TABLE compressed_tool_results (
    hash                  TEXT    NOT NULL,
    session_id            TEXT    NOT NULL,
    agent_id              TEXT    NOT NULL,
    tool                  TEXT    NOT NULL,
    call_id               TEXT    NOT NULL,
    original_byte_len     INTEGER NOT NULL,
    compressed_byte_len   INTEGER,
    created_at            INTEGER NOT NULL,
    kind                  TEXT    NOT NULL,
    content               TEXT    NOT NULL,
    PRIMARY KEY (session_id, hash),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_ctr_session_created ON compressed_tool_results (session_id, created_at);
CREATE INDEX idx_ctr_hash ON compressed_tool_results (hash);

-- ---- workspace_trust ----------------------------------------------------------------------
-- Per-root workspace trust decisions.

CREATE TABLE workspace_trust (
    root_path TEXT PRIMARY KEY,
    mode TEXT NOT NULL CHECK (mode IN ('trust', 'ignore-config', 'untrusted')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX idx_workspace_trust_updated_at
    ON workspace_trust(updated_at DESC);

-- ---- task delegations -----------------------------------------------------------------------
-- Durable state for delegated `task` runs: one job per task call, one
-- child row per labeled child run, plus pending steer messages and the
-- (possibly sidecar-spilled) prompt payloads. Delivery flags let the
-- parent session pick results up exactly once across daemon restarts.

CREATE TABLE task_delegation_jobs (
    task_call_id TEXT PRIMARY KEY,
    function_call_id TEXT,
    parent_session_id TEXT NOT NULL,
    parent_agent TEXT NOT NULL,
    original_args_json TEXT,
    status TEXT NOT NULL CHECK (status IN (
        'running',
        'backgrounded',
        'completed',
        'failed',
        'cancelled',
        'paused_pending_tool',
        'lost'
    )),
    ack_delivered INTEGER NOT NULL DEFAULT 0 CHECK (ack_delivered IN (0, 1)),
    final_delivered INTEGER NOT NULL DEFAULT 0 CHECK (final_delivered IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (parent_session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE task_delegation_children (
    task_call_id TEXT NOT NULL,
    label TEXT NOT NULL,
    child_agent TEXT NOT NULL,
    model TEXT,
    status TEXT NOT NULL CHECK (status IN (
        'running',
        'backgrounded',
        'completed',
        'failed',
        'cancelled',
        'paused_pending_tool',
        'lost'
    )),
    report TEXT,
    output_dir TEXT,
    todo_ids_json TEXT,
    snapshot_json TEXT,
    result_delivered INTEGER NOT NULL DEFAULT 0 CHECK (result_delivered IN (0, 1)),
    started_at INTEGER,
    finished_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    requested_cwd TEXT,
    resolved_cwd TEXT,
    PRIMARY KEY (task_call_id, label),
    FOREIGN KEY (task_call_id) REFERENCES task_delegation_jobs(task_call_id) ON DELETE CASCADE
);

CREATE INDEX idx_task_delegation_jobs_session_status
    ON task_delegation_jobs(parent_session_id, status, updated_at DESC);

CREATE INDEX idx_task_delegation_children_status
    ON task_delegation_children(status, updated_at DESC);

CREATE TABLE task_delegation_steers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_call_id TEXT NOT NULL,
    label TEXT NOT NULL,
    body TEXT NOT NULL,
    origin_principal TEXT NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0 CHECK (delivered IN (0, 1)),
    created_at INTEGER NOT NULL,
    delivered_at INTEGER,
    FOREIGN KEY (task_call_id, label) REFERENCES task_delegation_children(task_call_id, label) ON DELETE CASCADE
);

CREATE INDEX idx_task_delegation_steers_pending
    ON task_delegation_steers(task_call_id, label, delivered, id);

CREATE TABLE task_delegation_payloads (
    task_call_id TEXT NOT NULL,
    label TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    parent_session_id TEXT NOT NULL,
    parent_agent TEXT NOT NULL,
    function_call_id TEXT,
    child_agent TEXT NOT NULL,
    prompt_byte_len INTEGER NOT NULL,
    body_inline TEXT,
    sidecar_path TEXT,
    created_at INTEGER NOT NULL,
    delivered_at INTEGER,
    PRIMARY KEY (task_call_id, label),
    FOREIGN KEY (task_call_id) REFERENCES task_delegation_jobs(task_call_id) ON DELETE CASCADE,
    FOREIGN KEY (parent_session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    CHECK ((body_inline IS NOT NULL) OR (sidecar_path IS NOT NULL))
);

CREATE UNIQUE INDEX idx_task_delegation_payloads_session_hash_label
    ON task_delegation_payloads(parent_session_id, payload_hash, task_call_id, label);

CREATE INDEX idx_task_delegation_payloads_session_created
    ON task_delegation_payloads(parent_session_id, created_at ASC);

-- ---- paused_session_work ----------------------------------------------------------------------
-- Sessions the daemon paused mid-work (e.g. across an upgrade restart)
-- and must resume or resolve on next boot.

CREATE TABLE paused_session_work (
    session_id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN (
        'paused',
        'resumed',
        'cancelled',
        'failed_to_pause',
        'lost'
    )),
    active_agent TEXT NOT NULL,
    project_root TEXT NOT NULL,
    reason TEXT NOT NULL,
    pending_tool_count INTEGER NOT NULL DEFAULT 0,
    daemon_version TEXT NOT NULL,
    client_version TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    resolved_at INTEGER,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_paused_session_work_status_updated
    ON paused_session_work(status, updated_at DESC);

-- ---- skill_pairs --------------------------------------------------------------------------------
-- Per-call skill ownership: which skill owns a given tool call, and
-- whether the pairing came from an intentional user steer.

CREATE TABLE skill_pairs (
    session_id TEXT NOT NULL,
    call_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    intentional_steer INTEGER NOT NULL DEFAULT 0 CHECK (intentional_steer IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (session_id, call_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_skill_pairs_session_owner
    ON skill_pairs(session_id, owner, intentional_steer);

-- ---- skill_usage -------------------------------------------------------------------------------
-- Durable Agent Skills usage/lifecycle ledger. Source paths remain text so
-- global, project, hub, and future package stores can share one table.

CREATE TABLE skill_usage (
    name             TEXT    PRIMARY KEY,
    source_path      TEXT    NOT NULL,
    archive_path     TEXT,
    created_by       TEXT    NOT NULL CHECK (created_by IN ('foreground', 'background')),
    use_count        INTEGER NOT NULL DEFAULT 0,
    view_count       INTEGER NOT NULL DEFAULT 0,
    last_used_at     INTEGER,
    last_viewed_at   INTEGER,
    patch_count      INTEGER NOT NULL DEFAULT 0,
    last_patched_at  INTEGER,
    created_at       INTEGER NOT NULL,
    state            TEXT    NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'stale', 'archived')),
    pinned           INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
    archived_at      INTEGER,
    updated_at       INTEGER NOT NULL
);

CREATE INDEX idx_skill_usage_state_activity
    ON skill_usage(state, pinned, created_by, last_used_at, created_at);

CREATE TABLE skill_curator_snapshots (
    id         TEXT    PRIMARY KEY,
    path       TEXT    NOT NULL,
    reason     TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_skill_curator_snapshots_created
    ON skill_curator_snapshots(created_at DESC, id DESC);

-- ---- retention_meta -------------------------------------------------------------------------------
-- Global metadata for DB retention housekeeping.

CREATE TABLE retention_meta (
    key   TEXT    PRIMARY KEY,
    value INTEGER NOT NULL
);

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

-- ---- session_plan_docs -------------------------------------------------------------------------------------
-- The session's living plan document (plan mode), one row per session.

CREATE TABLE session_plan_docs (
    session_id TEXT PRIMARY KEY REFERENCES sessions(session_id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);

-- ---- installation_identity -------------------------------------------------
-- Singleton installation identity for native secure-key account scoping.
-- Exactly one row (id = 1). 16 random bytes; callers see 32 lowercase hex.
-- Never derived from hostname, machine-id, user, config, env, or caller input.

CREATE TABLE installation_identity (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    identity_bytes  BLOB    NOT NULL CHECK (length(identity_bytes) = 16),
    created_at      INTEGER NOT NULL
);

-- ---- secure_key_namespaces -------------------------------------------------
-- Nonsecret coordination for versioned native secure keys.

CREATE TABLE secure_key_namespaces (
    namespace       TEXT    PRIMARY KEY,
    active_version  INTEGER,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

-- ---- secure_key_versions ---------------------------------------------------

CREATE TABLE secure_key_versions (
    namespace    TEXT    NOT NULL,
    version     INTEGER NOT NULL,
    state       TEXT    NOT NULL CHECK (state IN (
                    'Pending', 'Active', 'Retained', 'Retiring', 'Retired'
                )),
    key_digest  TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (namespace, version),
    FOREIGN KEY (namespace) REFERENCES secure_key_namespaces(namespace)
);

CREATE INDEX idx_secure_key_versions_state
    ON secure_key_versions (namespace, state);

-- ---- secure_key_sagas ------------------------------------------------------
-- Cross-store provision/retire phase ledger. Safe digests/metadata only.

CREATE TABLE secure_key_sagas (
    op_id       TEXT    PRIMARY KEY,
    namespace   TEXT    NOT NULL,
    kind        TEXT    NOT NULL CHECK (kind IN ('Provision', 'Retire')),
    version     INTEGER NOT NULL,
    phase       TEXT    NOT NULL,
    key_digest  TEXT,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    FOREIGN KEY (namespace) REFERENCES secure_key_namespaces(namespace)
);

CREATE INDEX idx_secure_key_sagas_ns ON secure_key_sagas (namespace, kind);

-- ---- secure_key_consumer_refs ----------------------------------------------
-- Durable consumer references; no key or ciphertext.

CREATE TABLE secure_key_consumer_refs (
    reference_id    TEXT    PRIMARY KEY,
    namespace       TEXT    NOT NULL,
    version         INTEGER NOT NULL,
    consumer_kind   TEXT    NOT NULL,
    consumer_id     TEXT    NOT NULL,
    state           TEXT    NOT NULL CHECK (state IN (
                        'Reserved', 'Active', 'Releasing', 'Released'
                    )),
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    UNIQUE (namespace, version, consumer_kind, consumer_id),
    FOREIGN KEY (namespace, version)
        REFERENCES secure_key_versions(namespace, version)
);

CREATE INDEX idx_secure_key_refs_version_state
    ON secure_key_consumer_refs (namespace, version, state);
CREATE INDEX idx_secure_key_refs_recon
    ON secure_key_consumer_refs (state)
    WHERE state IN ('Reserved', 'Releasing');

-- ---- sealed_state_sagas ----------------------------------------------------
-- In-flight dual-slot sealed-state writes. Safe digests/accounts only.

CREATE TABLE sealed_state_sagas (
    op_id               TEXT    PRIMARY KEY,
    namespace           TEXT    NOT NULL,
    target_slot         TEXT    NOT NULL CHECK (target_slot IN ('state-a', 'state-b')),
    target_account      TEXT    NOT NULL,
    -- Full u64 range as decimal text (SQLite INTEGER is signed i64 only).
    expected_generation TEXT    NOT NULL,
    new_generation      TEXT    NOT NULL,
    -- New payload digest (hex). Empty expected digest means create (no prior).
    payload_digest_hex  TEXT    NOT NULL,
    expected_payload_digest_hex TEXT NOT NULL,
    -- Prior/current slot at CAS start: 'state-a'/'state-b', or '' for create.
    prior_slot          TEXT    NOT NULL,
    key_version         INTEGER NOT NULL,
    phase               TEXT    NOT NULL,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);

CREATE INDEX idx_sealed_state_sagas_ns
    ON sealed_state_sagas (namespace);

-- ---- run_invocations -------------------------------------------------------
-- Daemon-global durable run identity keyed solely by client_submission_id
-- (canonical lowercase hyphenated UUIDv4). No session CASCADE: rows outlive
-- session deletion and receive cancelled_session_deleted terminalization.
-- InvocationNotFound equalization relies on content-free columns only.

CREATE TABLE run_invocations (
    client_submission_id    TEXT PRIMARY KEY,
    origin_principal_digest TEXT NOT NULL,
    session_id              TEXT NOT NULL,
    options_json            TEXT NOT NULL,
    options_digest          TEXT NOT NULL,
    content_digest          TEXT NOT NULL,
    state                   TEXT NOT NULL CHECK (state IN (
        'accepted', 'queued', 'dispatching', 'submission_unknown', 'running',
        'cancellation_requested', 'succeeded', 'failed', 'cancelled',
        'timeout_expired', 'max_turns_exceeded', 'clock_rollback_timed_out',
        'outcome_unknown'
    )),
    state_version           INTEGER NOT NULL,
    created_at_wall_ms      INTEGER NOT NULL,
    updated_at_wall_ms      INTEGER NOT NULL,
    last_observed_wall_ms   INTEGER NOT NULL,
    remaining_ms            INTEGER,
    reserved_turns          INTEGER NOT NULL DEFAULT 0,
    max_turns               INTEGER,
    timeout_ms              INTEGER,
    cancel_requested        INTEGER NOT NULL DEFAULT 0,
    cancel_result           TEXT CHECK (
        cancel_result IS NULL OR cancel_result IN (
            'cancellation_requested', 'already_cancelled', 'already_terminal'
        )
    ),
    terminal_reason         TEXT CHECK (
        terminal_reason IS NULL OR terminal_reason IN (
            'succeeded', 'failed', 'cancelled', 'cancelled_session_deleted',
            'timeout_expired', 'max_turns_exceeded', 'clock_rollback_timed_out',
            'outcome_unknown'
        )
    ),
    terminal_at_wall_ms     INTEGER,
    expires_at_wall_ms      INTEGER,
    accounted_bytes         INTEGER NOT NULL
);

CREATE INDEX idx_run_invocations_session
    ON run_invocations (session_id);
CREATE INDEX idx_run_invocations_principal
    ON run_invocations (origin_principal_digest);
CREATE INDEX idx_run_invocations_expires
    ON run_invocations (expires_at_wall_ms)
    WHERE expires_at_wall_ms IS NOT NULL;
CREATE INDEX idx_run_invocations_active_session
    ON run_invocations (session_id)
    WHERE terminal_at_wall_ms IS NULL;

-- Content-free rejected-before-acceptance tombstones. Same global UUID key as
-- run_invocations. Never enumerated, listed, or distinguished from NotFound.

CREATE TABLE run_invocation_tombstones (
    client_submission_id     TEXT PRIMARY KEY,
    claiming_principal_digest TEXT NOT NULL,
    created_at_wall_ms       INTEGER NOT NULL,
    expires_at_wall_ms       INTEGER NOT NULL,
    accounted_bytes          INTEGER NOT NULL
);

CREATE INDEX idx_run_invocation_tombstones_principal
    ON run_invocation_tombstones (claiming_principal_digest);
CREATE INDEX idx_run_invocation_tombstones_expires
    ON run_invocation_tombstones (expires_at_wall_ms);


-- ---- execution_containments ------------------------------------------------
-- Daemon-owned generation-bound descendant containment recovery rows.
-- Safe platform locators/digests only — never command args, env, output, or
-- secrets. States: Creating/Active/Stopping/Empty/Uncertain.

CREATE TABLE execution_containments (
    containment_id          TEXT PRIMARY KEY,
    session_id              TEXT NOT NULL,
    operation_id            TEXT NOT NULL,
    generation              INTEGER NOT NULL,
    platform_kind           TEXT NOT NULL CHECK (platform_kind IN (
        'linux_cgroup', 'windows_job', 'macos_unsupported',
        'docker', 'podman', 'fake', 'unsupported'
    )),
    state                   TEXT NOT NULL CHECK (state IN (
        'creating', 'active', 'stopping', 'empty', 'uncertain'
    )),
    guarantee               TEXT NOT NULL CHECK (guarantee IN ('proven', 'unsupported')),
    platform_locator_json   TEXT NOT NULL DEFAULT '{}',
    runtime_context_digest  TEXT,
    unsupported_reason      TEXT,
    created_at_wall_ms      INTEGER NOT NULL,
    updated_at_wall_ms      INTEGER NOT NULL,
    emptied_at_wall_ms      INTEGER,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_execution_containments_session
    ON execution_containments (session_id);
CREATE INDEX idx_execution_containments_session_state
    ON execution_containments (session_id, state);
CREATE INDEX idx_execution_containments_nonempty
    ON execution_containments (session_id)
    WHERE state NOT IN ('empty');


-- ---- write-scope leases / transfers / permits -------------------------------
-- Durable hierarchical write authority. A lease is one owner's exclusive write
-- authority over a canonical directory subtree. A transfer moves a *strict*
-- sub-scope from a parent lease to a child lease through an ordered, crash-safe
-- phase sequence. A permit is the durable-generation right to perform one
-- filesystem mutation (`mutation`) or to run arbitrary user code that can
-- influence a scope (`execution`).
--
-- Authority is durable, never in-memory-only: every authority-changing
-- transition increments the affected lease generation, which invalidates every
-- older token. Generations never decrement and are never reused, so a late
-- write carrying an old generation fails without reacquiring.
--
-- Paths are canonical absolute host paths. Reads are never scoped here; write
-- scope is a *write* authority only.

CREATE TABLE write_scope_leases (
    lease_id                TEXT PRIMARY KEY,
    -- NULL for a root lease (the session's base writable authority).
    parent_lease_id         TEXT,
    session_id              TEXT NOT NULL,
    -- Owning task / async job, when the lease is bound to delegated work.
    task_id                 TEXT,
    -- Canonical absolute directory subtree this lease grants write authority over.
    scope_path              TEXT NOT NULL,
    -- Bumped by every authority-changing transition; invalidates older tokens.
    generation              INTEGER NOT NULL,
    state                   TEXT NOT NULL CHECK (state IN (
        'active', 'transferring', 'delegated', 'returning', 'released'
    )),
    -- Opaque owner identity (agent/job); never a command, secret, or payload.
    owner_id                TEXT NOT NULL,
    -- Optimistic-concurrency version for same-parent transfer serialization.
    version                 INTEGER NOT NULL,
    created_at_wall_ms      INTEGER NOT NULL,
    updated_at_wall_ms      INTEGER NOT NULL,
    released_at_wall_ms     INTEGER,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY (parent_lease_id) REFERENCES write_scope_leases(lease_id) ON DELETE RESTRICT
);

CREATE INDEX idx_write_scope_leases_session
    ON write_scope_leases (session_id);
CREATE INDEX idx_write_scope_leases_parent
    ON write_scope_leases (parent_lease_id);
CREATE INDEX idx_write_scope_leases_live
    ON write_scope_leases (session_id, state)
    WHERE state NOT IN ('released');

-- Generation monotonicity: never decrement, never reuse after rollback or
-- recovery. A recovery that rolls an authority back still moves forward.
CREATE TRIGGER write_scope_leases_generation_monotonic
BEFORE UPDATE ON write_scope_leases
WHEN NEW.generation < OLD.generation
BEGIN
    SELECT RAISE(ABORT, 'write scope lease generation must never decrement');
END;

-- Version is the CAS token for same-parent transfer serialization; a stale
-- contender must lose rather than silently overwrite a newer version.
CREATE TRIGGER write_scope_leases_version_monotonic
BEFORE UPDATE ON write_scope_leases
WHEN NEW.version <= OLD.version AND NEW.state IS NOT OLD.state
BEGIN
    SELECT RAISE(ABORT, 'write scope lease version must advance on state change');
END;

-- The legal authority transition graph, enforced by the storage layer rather
-- than only by the caller. A durable layer that accepts `active -> delegated`
-- would let a caller skip the exclusion barrier entirely.
CREATE TRIGGER write_scope_leases_legal_transition
BEFORE UPDATE ON write_scope_leases
WHEN NEW.state <> OLD.state
 AND (OLD.state || '>' || NEW.state) NOT IN (
    'active>transferring',
    'active>released',
    'transferring>delegated',
    -- Unwind: a failed acquisition returns authority to the parent.
    'transferring>active',
    -- An owner that already delegated one sub-scope may delegate another.
    'delegated>transferring',
    'delegated>returning',
    'delegated>released',
    'returning>active',
    -- Returning while other children remain delegated.
    'returning>delegated',
    'returning>released'
 )
BEGIN
    SELECT RAISE(ABORT, 'write scope lease transition rejected by durable constraint');
END;

-- Released is terminal: a released authority is never resurrected, because a
-- descendant token from an older generation must never become valid again.
CREATE TRIGGER write_scope_leases_released_is_final
BEFORE UPDATE ON write_scope_leases
WHEN OLD.state = 'released' AND NEW.state <> 'released'
BEGIN
    SELECT RAISE(ABORT, 'released write scope lease is final');
END;

-- The scope a lease covers is fixed at creation. Re-pointing an existing lease
-- would silently move authority without a generation bump.
CREATE TRIGGER write_scope_leases_scope_immutable
BEFORE UPDATE ON write_scope_leases
WHEN NEW.scope_path <> OLD.scope_path
BEGIN
    SELECT RAISE(ABORT, 'write scope lease scope_path is immutable');
END;


CREATE TABLE write_scope_transfers (
    transfer_id                 TEXT PRIMARY KEY,
    session_id                  TEXT NOT NULL,
    parent_lease_id             TEXT NOT NULL,
    -- NULL until ChildActivated; a loser or an unsupported transfer never
    -- creates a child lease at all.
    child_lease_id              TEXT,
    -- The strict canonical sub-scope being delegated.
    sub_scope_path              TEXT NOT NULL,
    phase                       TEXT NOT NULL CHECK (phase IN (
        'prepared', 'parent_excluded', 'child_activated',
        'child_terminal', 'parent_restored', 'committed'
    )),
    -- Parent generation observed by the Prepared CAS (`g`).
    prepare_parent_generation   INTEGER NOT NULL,
    -- Parent generation after Prepared (`g+1`), reissued at ParentExcluded.
    parent_generation           INTEGER NOT NULL,
    -- Child generation created at ChildActivated (`g+2`).
    child_generation            INTEGER,
    -- Fresh full-authority parent generation issued at ParentRestored.
    restored_parent_generation  INTEGER,
    -- Which ScopedWriteBackend answered the capability probe.
    backend_kind                TEXT NOT NULL,
    -- Closed capability: strict writable delegation requires 'proven'.
    capability                  TEXT NOT NULL CHECK (capability IN (
        'proven', 'unsupported'
    )),
    unsupported_reason          TEXT,
    -- Containment generation that must return ProvenEmpty before return.
    containment_id              TEXT,
    -- The containment's OWN generation, which is a different counter from any
    -- lease generation. The return barrier compares the oracle's reported
    -- generation against this, so a ProvenEmpty for a different generation is
    -- never mistaken for evidence about this child.
    containment_generation      INTEGER,
    -- Inode identity the backend recorded for the publication target when the
    -- child started. A change means the target or an ancestor was replaced.
    publication_identity        TEXT,
    -- Execution-wide permit held across every descendant of the child.
    execution_permit_id         TEXT,
    -- Startup reconciliation marker; 'denied' is a permanent refusal to
    -- restore authority under ambiguity.
    recovery_phase              TEXT CHECK (recovery_phase IN (
        'pending', 'reconciled', 'denied'
    )),
    version                     INTEGER NOT NULL,
    created_at_wall_ms          INTEGER NOT NULL,
    updated_at_wall_ms          INTEGER NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY (parent_lease_id) REFERENCES write_scope_leases(lease_id) ON DELETE RESTRICT,
    FOREIGN KEY (child_lease_id) REFERENCES write_scope_leases(lease_id) ON DELETE RESTRICT
);

CREATE INDEX idx_write_scope_transfers_parent
    ON write_scope_transfers (parent_lease_id);
CREATE INDEX idx_write_scope_transfers_child
    ON write_scope_transfers (child_lease_id);
CREATE INDEX idx_write_scope_transfers_session_phase
    ON write_scope_transfers (session_id, phase);
CREATE INDEX idx_write_scope_transfers_open
    ON write_scope_transfers (session_id)
    WHERE phase NOT IN ('committed');

-- Phases advance by exactly one step. The single exception is closing out a
-- transfer that never activated a child (`child_lease_id IS NULL`): recovery
-- must be able to retire an abandoned Prepared/ParentExcluded row, and doing so
-- hands no authority to anyone because no child ever existed.
CREATE TRIGGER write_scope_transfers_phase_adjacent
BEFORE UPDATE ON write_scope_transfers
WHEN ((CASE NEW.phase
        WHEN 'prepared' THEN 0
        WHEN 'parent_excluded' THEN 1
        WHEN 'child_activated' THEN 2
        WHEN 'child_terminal' THEN 3
        WHEN 'parent_restored' THEN 4
        WHEN 'committed' THEN 5 END)
      -
      (CASE OLD.phase
        WHEN 'prepared' THEN 0
        WHEN 'parent_excluded' THEN 1
        WHEN 'child_activated' THEN 2
        WHEN 'child_terminal' THEN 3
        WHEN 'parent_restored' THEN 4
        WHEN 'committed' THEN 5 END)) > 1
 AND NOT (NEW.phase = 'committed' AND OLD.child_lease_id IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'transfer phase advance rejected by durable constraint');
END;

-- Phases never rewind: a rewind could restore parent authority while a child
-- still owns the sub-scope.
CREATE TRIGGER write_scope_transfers_phase_forward_only
BEFORE UPDATE ON write_scope_transfers
WHEN (CASE NEW.phase
        WHEN 'prepared' THEN 0
        WHEN 'parent_excluded' THEN 1
        WHEN 'child_activated' THEN 2
        WHEN 'child_terminal' THEN 3
        WHEN 'parent_restored' THEN 4
        WHEN 'committed' THEN 5 END)
     < (CASE OLD.phase
        WHEN 'prepared' THEN 0
        WHEN 'parent_excluded' THEN 1
        WHEN 'child_activated' THEN 2
        WHEN 'child_terminal' THEN 3
        WHEN 'parent_restored' THEN 4
        WHEN 'committed' THEN 5 END)
BEGIN
    SELECT RAISE(ABORT, 'write scope transfer phase must not rewind');
END;

-- Committed is terminal.
CREATE TRIGGER write_scope_transfers_committed_is_final
BEFORE UPDATE ON write_scope_transfers
WHEN OLD.phase = 'committed' AND NEW.phase <> 'committed'
BEGIN
    SELECT RAISE(ABORT, 'committed write scope transfer is final');
END;

-- A child lease may only be attached once, at ChildActivated. Re-pointing it
-- would orphan a live owner.
CREATE TRIGGER write_scope_transfers_child_lease_write_once
BEFORE UPDATE ON write_scope_transfers
WHEN OLD.child_lease_id IS NOT NULL
 AND NEW.child_lease_id IS NOT OLD.child_lease_id
BEGIN
    SELECT RAISE(ABORT, 'write scope transfer child lease is write-once');
END;

-- The delegated sub-scope is fixed at Prepared: the containment decision was
-- made against exactly this path.
CREATE TRIGGER write_scope_transfers_subscope_immutable
BEFORE UPDATE ON write_scope_transfers
WHEN NEW.sub_scope_path <> OLD.sub_scope_path
BEGIN
    SELECT RAISE(ABORT, 'write scope transfer sub_scope_path is immutable');
END;

-- Strict writable delegation never proceeds past exclusion without a Proven
-- backend. Encoding it here means no code path can bypass the barrier.
CREATE TRIGGER write_scope_transfers_requires_proven_backend
BEFORE UPDATE ON write_scope_transfers
WHEN NEW.capability <> 'proven'
 AND NEW.phase NOT IN ('prepared')
BEGIN
    SELECT RAISE(ABORT, 'write scope transfer requires a proven scoped-write backend');
END;


CREATE TABLE write_scope_permits (
    permit_id               TEXT PRIMARY KEY,
    session_id              TEXT NOT NULL,
    lease_id                TEXT NOT NULL,
    -- Durable generation the permit was issued under; a transition that bumps
    -- the lease generation invalidates the permit for new work but must still
    -- drain the in-flight ones.
    generation              INTEGER NOT NULL,
    kind                    TEXT NOT NULL CHECK (kind IN ('mutation', 'execution')),
    -- Which filesystem operation this permit protects. Needed to decide whether
    -- two overlapping permits actually conflict: two content writes to distinct
    -- files may proceed in parallel, but anything that can change what another
    -- path *means* may not.
    influence_kind          TEXT NOT NULL DEFAULT 'write_content',
    -- Highest ancestor whose namespace this operation can influence. Overlap is
    -- computed against this, not the target path: renaming/removing/replacing/
    -- linking an ancestor changes the meaning of every descendant path.
    influence_root          TEXT NOT NULL,
    -- The concrete target (mutation) or the execution's effective write root.
    target_path             TEXT NOT NULL,
    state                   TEXT NOT NULL CHECK (state IN ('held', 'released')),
    -- Execution permits only: the containment generation that must return
    -- ProvenEmpty before the permit may be released.
    containment_id          TEXT,
    acquired_at_wall_ms     INTEGER NOT NULL,
    released_at_wall_ms     INTEGER,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY (lease_id) REFERENCES write_scope_leases(lease_id) ON DELETE RESTRICT
);

CREATE INDEX idx_write_scope_permits_lease
    ON write_scope_permits (lease_id);
CREATE INDEX idx_write_scope_permits_session_state
    ON write_scope_permits (session_id, state);
CREATE INDEX idx_write_scope_permits_held
    ON write_scope_permits (session_id)
    WHERE state = 'held';

-- A released permit is final; resurrection would let a drained transfer barrier
-- be re-entered after the authority already moved.
CREATE TRIGGER write_scope_permits_released_is_final
BEFORE UPDATE ON write_scope_permits
WHEN OLD.state = 'released' AND NEW.state <> 'released'
BEGIN
    SELECT RAISE(ABORT, 'released write scope permit is final');
END;

-- Overlap is computed from the influence root, so it may not be narrowed after
-- acquisition — that would shrink the barrier a transfer is waiting on.
CREATE TRIGGER write_scope_permits_influence_immutable
BEFORE UPDATE ON write_scope_permits
WHEN NEW.influence_root <> OLD.influence_root OR NEW.kind <> OLD.kind
BEGIN
    SELECT RAISE(ABORT, 'write scope permit influence root and kind are immutable');
END;


-- ---- external side-effect journal ------------------------------------------
-- One bounded, restart-safe, idempotent journal for non-idempotent external
-- actions (computer input, transcription, sidecars, image generation,
-- inference recovery) so no consumer invents a second spool. SQLite is
-- authoritative; the 64-KiB two-slot filesystem capsule owned by
-- `cockpit-core::external_journal` only carries the minimum sanitized
-- projection needed when the database cannot record a post-handoff
-- transition.
--
-- Identity is (operation_kind, owner_session_id, idempotency_key) with an
-- immutable payload digest and a monotonically increasing version. Rows hold
-- digests and bounded tokens only — never prompts, typed input, pixels, raw
-- paths/URLs, credentials, headers, provider payloads, or signed query
-- values, and never spool HMAC key material.
--
-- Deliberately NOT `ON DELETE CASCADE` from sessions: session deletion writes
-- an external_journal_session_tombstones row and unresolved operations
-- survive it, so late provider evidence still resolves exactly once without
-- recreating session content.

CREATE TABLE external_journal_operations (
    operation_id                      TEXT    PRIMARY KEY,
    operation_kind                    TEXT    NOT NULL,
    owner_session_id                  TEXT    NOT NULL,
    idempotency_key                   TEXT    NOT NULL,
    -- Immutable canonical projection facts. Length is capped at the encoder
    -- bound (24 KiB) that the capsule slot body is sized for.
    payload_digest                    TEXT    NOT NULL,
    payload_len                       INTEGER NOT NULL CHECK (
        payload_len >= 0 AND payload_len <= 24576
    ),
    state                             TEXT    NOT NULL CHECK (state IN (
        'prepared', 'dispatching', 'accepted', 'rejected',
        'submission_unknown', 'reconciling', 'cancellation_requested',
        'cancelled', 'expired', 'completed_after_cancel',
        'succeeded', 'failed'
    )),
    -- Monotonic compare-and-set version. Every committed transition bumps it.
    version                           INTEGER NOT NULL CHECK (version >= 1),
    -- Provider idempotency may permit retry only when BOTH the key and the
    -- contract it was issued under are recorded.
    provider_idempotency_key          TEXT,
    provider_idempotency_contract     TEXT,
    -- Orthogonal monotonic cancellation fact. Set exactly once by the first
    -- cancellation request; no later transition may clear or replace it.
    cancellation_requested_at_wall_ms INTEGER,
    cancellation_requested_version    INTEGER,
    created_at_wall_ms                INTEGER NOT NULL,
    updated_at_wall_ms                INTEGER NOT NULL,
    -- Durable proof of whether external handoff could have begun. `expired`
    -- is legal only while this stays NULL.
    dispatch_started_at_wall_ms       INTEGER,
    terminal_at_wall_ms               INTEGER,
    UNIQUE (operation_kind, owner_session_id, idempotency_key),
    CHECK (
        (cancellation_requested_at_wall_ms IS NULL)
        = (cancellation_requested_version IS NULL)
    ),
    CHECK (
        provider_idempotency_key IS NULL
        OR provider_idempotency_contract IS NOT NULL
    ),
    CHECK (state <> 'expired' OR dispatch_started_at_wall_ms IS NULL),
    CHECK (state <> 'succeeded' OR cancellation_requested_at_wall_ms IS NULL)
);

CREATE INDEX idx_external_journal_ops_session
    ON external_journal_operations (owner_session_id);
CREATE INDEX idx_external_journal_ops_state
    ON external_journal_operations (state, updated_at_wall_ms);
CREATE INDEX idx_external_journal_ops_unresolved
    ON external_journal_operations (updated_at_wall_ms)
    WHERE state IN (
        'dispatching', 'accepted', 'submission_unknown',
        'cancellation_requested', 'reconciling'
    );
CREATE INDEX idx_external_journal_ops_prepared
    ON external_journal_operations (created_at_wall_ms)
    WHERE state = 'prepared';

-- Append-only transition log. The partial unique index is the database-level
-- proof that an operation emits at most one terminal event: a duplicate
-- transition returns the current record instead of writing a second row.

CREATE TABLE external_journal_events (
    event_id                          TEXT    PRIMARY KEY,
    operation_id                      TEXT    NOT NULL,
    version                           INTEGER NOT NULL CHECK (version >= 1),
    from_state                        TEXT    NOT NULL,
    to_state                          TEXT    NOT NULL,
    terminal                          INTEGER NOT NULL CHECK (terminal IN (0, 1)),
    -- Cancellation-aware projection: accepted/reconciling/failed terminals
    -- keep exposing the original cancellation fact.
    cancellation_requested_at_wall_ms INTEGER,
    emitted_at_wall_ms                INTEGER NOT NULL,
    FOREIGN KEY (operation_id)
        REFERENCES external_journal_operations (operation_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX uq_external_journal_events_version
    ON external_journal_events (operation_id, version);
CREATE UNIQUE INDEX uq_external_journal_events_terminal
    ON external_journal_events (operation_id)
    WHERE terminal = 1;
CREATE INDEX idx_external_journal_events_operation
    ON external_journal_events (operation_id, emitted_at_wall_ms);

-- Capsule capacity ledger. Admission and recovery draw from one fixed
-- partition each (3,072 capsules / 192 MiB admission, 1,024 / 64 MiB reserved)
-- so a successful handoff can never discover that no durable fallback
-- capacity remains. Every capsule is exactly 65,536 bytes.

CREATE TABLE external_journal_spool_capsules (
    operation_id       TEXT    PRIMARY KEY,
    capsule_uuid       TEXT    NOT NULL UNIQUE,
    key_version        INTEGER NOT NULL CHECK (key_version >= 1),
    allocated_bytes    INTEGER NOT NULL CHECK (allocated_bytes = 65536),
    capacity_partition TEXT    NOT NULL CHECK (capacity_partition IN (
        'admission', 'recovery'
    )),
    quarantined        INTEGER NOT NULL DEFAULT 0 CHECK (quarantined IN (0, 1)),
    created_at_wall_ms INTEGER NOT NULL,
    FOREIGN KEY (operation_id)
        REFERENCES external_journal_operations (operation_id) ON DELETE CASCADE
);

CREATE INDEX idx_external_journal_capsules_partition
    ON external_journal_spool_capsules (capacity_partition);
CREATE INDEX idx_external_journal_capsules_key_version
    ON external_journal_spool_capsules (key_version);
CREATE INDEX idx_external_journal_capsules_quarantined
    ON external_journal_spool_capsules (created_at_wall_ms)
    WHERE quarantined = 1;

-- Consumer-owned queued domain records that have not yet created a
-- dispatching journal state. These expire in their OWN terminal state and
-- never invent an external-journal operation row.

CREATE TABLE external_journal_queue_entries (
    queue_entry_id       TEXT    PRIMARY KEY,
    operation_kind       TEXT    NOT NULL,
    owner_session_id     TEXT    NOT NULL,
    idempotency_key      TEXT    NOT NULL,
    state                TEXT    NOT NULL CHECK (state IN (
        'queued', 'journaled', 'cancelled', 'expired'
    )),
    journal_operation_id TEXT,
    created_at_wall_ms   INTEGER NOT NULL,
    updated_at_wall_ms   INTEGER NOT NULL,
    UNIQUE (operation_kind, owner_session_id, idempotency_key),
    CHECK ((state = 'journaled') = (journal_operation_id IS NOT NULL))
);

CREATE INDEX idx_external_journal_queue_queued
    ON external_journal_queue_entries (created_at_wall_ms)
    WHERE state = 'queued';

-- Session deletion tombstone. Writing one never deletes an unresolved
-- operation; resolution afterwards emits owner-visible recovery status
-- without recreating session content.

-- Durable integrity latch. The in-memory latch dies with the process, but a
-- spool that failed verification, an unreachable authenticated outcome, or a
-- simultaneous database+spool failure must keep doctor critical across
-- restarts and must be visible to a doctor run that holds no journal
-- instance. Single row by construction.

CREATE TABLE external_journal_integrity_faults (
    fault_id           TEXT    PRIMARY KEY CHECK (fault_id = 'current'),
    detail             TEXT    NOT NULL,
    observed_at_wall_ms INTEGER NOT NULL
);

CREATE TABLE external_journal_session_tombstones (
    owner_session_id       TEXT    PRIMARY KEY,
    deleted_at_wall_ms     INTEGER NOT NULL,
    unresolved_at_deletion INTEGER NOT NULL CHECK (unresolved_at_deletion >= 0)
);

-- Integrity that SQLite can enforce on its own, so a writer that bypasses
-- `crates/cockpit-db/src/db/external_journal.rs` still cannot create an
-- impossible history. The module validates the same rules first and returns
-- typed errors; these triggers are the backstop, not the primary check.

-- The exact edge set from the state graph. `from_state = to_state` is the
-- creation event a `prepared` insert emits and is deliberately exempt.
CREATE TRIGGER external_journal_events_legal_edge
BEFORE INSERT ON external_journal_events
WHEN NEW.from_state <> NEW.to_state
 AND (NEW.from_state || '>' || NEW.to_state) NOT IN (
     'prepared>dispatching',
     'prepared>cancelled',
     'prepared>expired',
     'dispatching>accepted',
     'dispatching>rejected',
     'dispatching>submission_unknown',
     'dispatching>cancellation_requested',
     'accepted>succeeded',
     'accepted>completed_after_cancel',
     'accepted>failed',
     'accepted>cancellation_requested',
     'submission_unknown>reconciling',
     'submission_unknown>cancellation_requested',
     'reconciling>accepted',
     'reconciling>rejected',
     'reconciling>submission_unknown',
     'reconciling>failed',
     'reconciling>cancellation_requested',
     'cancellation_requested>cancelled',
     'cancellation_requested>accepted',
     'cancellation_requested>completed_after_cancel',
     'cancellation_requested>failed',
     'cancellation_requested>submission_unknown',
     'cancellation_requested>reconciling'
 )
BEGIN
    SELECT RAISE(ABORT, 'illegal external journal transition');
END;

-- The terminal flag must agree with the terminal state set, or the partial
-- unique index that proves "at most one terminal event" could be bypassed by
-- simply writing terminal = 0.
CREATE TRIGGER external_journal_events_terminal_flag
BEFORE INSERT ON external_journal_events
WHEN NEW.terminal <> (NEW.to_state IN (
    'cancelled', 'expired', 'completed_after_cancel',
    'succeeded', 'failed', 'rejected'
))
BEGIN
    SELECT RAISE(ABORT, 'external journal terminal flag disagrees with state');
END;

-- Plain `succeeded` is unreachable once cancellation was requested; the
-- authoritative successful completion is `completed_after_cancel`.
CREATE TRIGGER external_journal_events_succeeded_after_cancel
BEFORE INSERT ON external_journal_events
WHEN NEW.to_state = 'succeeded'
 AND NEW.cancellation_requested_at_wall_ms IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'succeeded is forbidden after a cancellation request');
END;

-- The operations-table triggers below deliberately carry NO `OF <column>`
-- list. A `BEFORE UPDATE OF x` trigger fires only when the statement's SET
-- list mentions `x`, so a writer that changed `state` without mentioning
-- `version` — or that never wrote a matching event row — would slip past
-- column-scoped guards entirely. These fire on every update of the table.

-- The cancellation fact is monotonic: the first request sets it and no later
-- transition may clear or replace it.
CREATE TRIGGER external_journal_ops_cancellation_immutable
BEFORE UPDATE ON external_journal_operations
WHEN OLD.cancellation_requested_at_wall_ms IS NOT NULL
 AND (NEW.cancellation_requested_at_wall_ms IS NOT OLD.cancellation_requested_at_wall_ms
   OR NEW.cancellation_requested_version IS NOT OLD.cancellation_requested_version)
BEGIN
    SELECT RAISE(ABORT, 'external journal cancellation fact is immutable');
END;

-- Versions are monotonic, which is what makes every transition a genuine
-- compare-and-set rather than a last-writer-wins overwrite.
CREATE TRIGGER external_journal_ops_version_monotonic
BEFORE UPDATE ON external_journal_operations
WHEN NEW.version < OLD.version
BEGIN
    SELECT RAISE(ABORT, 'external journal version must increase');
END;

-- Any state change is a transition, so it must bump the version even if the
-- writer never inserted an event row.
CREATE TRIGGER external_journal_ops_state_change_bumps_version
BEFORE UPDATE ON external_journal_operations
WHEN NEW.state <> OLD.state AND NEW.version <= OLD.version
BEGIN
    SELECT RAISE(ABORT, 'external journal state change must increase the version');
END;

-- The edge set, enforced on the row itself rather than only on the event.
CREATE TRIGGER external_journal_ops_legal_edge
BEFORE UPDATE ON external_journal_operations
WHEN NEW.state <> OLD.state
 AND (OLD.state || '>' || NEW.state) NOT IN (
     'prepared>dispatching',
     'prepared>cancelled',
     'prepared>expired',
     'dispatching>accepted',
     'dispatching>rejected',
     'dispatching>submission_unknown',
     'dispatching>cancellation_requested',
     'accepted>succeeded',
     'accepted>completed_after_cancel',
     'accepted>failed',
     'accepted>cancellation_requested',
     'submission_unknown>reconciling',
     'submission_unknown>cancellation_requested',
     'reconciling>accepted',
     'reconciling>rejected',
     'reconciling>submission_unknown',
     'reconciling>failed',
     'reconciling>cancellation_requested',
     'cancellation_requested>cancelled',
     'cancellation_requested>accepted',
     'cancellation_requested>completed_after_cancel',
     'cancellation_requested>failed',
     'cancellation_requested>submission_unknown',
     'cancellation_requested>reconciling'
 )
BEGIN
    SELECT RAISE(ABORT, 'illegal external journal transition');
END;

-- Durable no-dispatch proof is one-way. Once a record records that handoff
-- could have begun, nothing may erase or rewrite that fact, because `expired`
-- and `cancelled`-while-prepared both depend on it.
CREATE TRIGGER external_journal_ops_dispatch_proof_immutable
BEFORE UPDATE ON external_journal_operations
WHEN OLD.dispatch_started_at_wall_ms IS NOT NULL
 AND NEW.dispatch_started_at_wall_ms IS NOT OLD.dispatch_started_at_wall_ms
BEGIN
    SELECT RAISE(ABORT, 'external journal dispatch proof is immutable');
END;

-- Terminal states accept no further transition.
CREATE TRIGGER external_journal_ops_terminal_is_final
BEFORE UPDATE ON external_journal_operations
WHEN OLD.state IN (
    'cancelled', 'expired', 'completed_after_cancel',
    'succeeded', 'failed', 'rejected'
) AND NEW.state <> OLD.state
BEGIN
    SELECT RAISE(ABORT, 'external journal terminal state is final');
END;

-- ---- scoped sealed values --------------------------------------------------
-- Owner-managed sealed values across Session, Project, and Global scope.
--
-- Only Session literals live in SQLite (the pre-existing `sealed_values`
-- table above). Project and Global literals live in a dedicated sealed-value
-- compartment outside this database, addressed by a random opaque 32-byte
-- exact key held in `compartment_key`. That key is a *locator*, never key
-- material and never secret-derived: it is drawn from the OS CSPRNG with no
-- relation to the literal, so possessing this table yields no oracle over any
-- literal's content, length, or encoding.
--
-- `active_version` is 0 while a create saga is still prepared. A record is
-- resolvable only at `active_version >= 1` with `deleted_at_ms IS NULL`, which
-- is what makes an interrupted cross-store saga non-resolvable rather than
-- half-live.
CREATE TABLE sealed_value_records (
    record_id       TEXT    PRIMARY KEY,
    scope           TEXT    NOT NULL CHECK (scope IN ('session', 'project', 'global')),
    -- session_id for session scope, canonical project key for project scope,
    -- and the empty string for global scope (global names are unique globally).
    scope_key       TEXT    NOT NULL,
    name            TEXT    NOT NULL,
    description     TEXT    NOT NULL,
    owner_principal TEXT    NOT NULL,
    active_version  INTEGER NOT NULL DEFAULT 0 CHECK (active_version >= 0),
    compartment_key TEXT,
    created_at_ms   INTEGER NOT NULL,
    updated_at_ms   INTEGER NOT NULL,
    deleted_at_ms   INTEGER,
    -- Session literals never leave SQLite, so a session record never carries a
    -- compartment locator.
    CHECK (scope <> 'session' OR compartment_key IS NULL),
    -- Global records are unique globally; their scope key is always empty.
    CHECK ((scope = 'global') = (scope_key = '')),
    UNIQUE (scope, scope_key, name)
);


-- Session-scope records follow their session out of existence. There is no
-- foreign key because `scope_key` is polymorphic across the three scopes.
CREATE TRIGGER sealed_value_records_session_cascade
AFTER DELETE ON sessions
BEGIN
    DELETE FROM sealed_value_records
     WHERE scope = 'session' AND scope_key = OLD.session_id;
END;

-- Deleted names are never reused. The tombstone outlives the record row so a
-- later create of the same canonical name in the same scope is refused.
CREATE TABLE sealed_value_name_tombstones (
    scope         TEXT    NOT NULL CHECK (scope IN ('session', 'project', 'global')),
    scope_key     TEXT    NOT NULL,
    name          TEXT    NOT NULL,
    retired_at_ms INTEGER NOT NULL,
    PRIMARY KEY (scope, scope_key, name)
);

-- Crash-resumable prepared/committed saga ledger for the cross-store
-- (SQLite + compartment) lifecycle. `prepared` create/rotate roll back;
-- `prepared` delete and every `committed` phase roll forward. The row is
-- removed once cleanup has run, so a resumable saga is exactly a live row.
CREATE TABLE sealed_value_sagas (
    op_id                      TEXT    PRIMARY KEY,
    record_id                  TEXT    NOT NULL,
    kind                       TEXT    NOT NULL CHECK (kind IN ('create', 'rotate', 'delete')),
    phase                      TEXT    NOT NULL CHECK (phase IN ('prepared', 'committed')),
    target_version             INTEGER NOT NULL CHECK (target_version >= 0),
    prepared_compartment_key   TEXT,
    superseded_compartment_key TEXT,
    created_at_ms              INTEGER NOT NULL,
    updated_at_ms              INTEGER NOT NULL,
    -- A create or rotate saga always stages a new locator. A delete normally
    -- stages none, but a delete that *converted* an in-flight rotate inherits
    -- that rotation's staged locator so cleanup can still reclaim it; without
    -- that, the staged plaintext of a deleted value would be referenced by
    -- nothing and survive on disk forever.
    CHECK (kind = 'delete' OR prepared_compartment_key IS NOT NULL)
);

-- At most one in-flight lifecycle saga per record: concurrent create/rotate/
-- delete on one record is a deterministic first-writer-wins race. This unique
-- index is also the record lookup path, so no separate index is needed.
CREATE UNIQUE INDEX uq_sealed_value_sagas_record ON sealed_value_sagas (record_id);

-- Explicit Owner grant of a Global sealed value to one canonical project.
-- Global scope carries no implicit project reach.
CREATE TABLE sealed_global_project_grants (
    record_id     TEXT    NOT NULL,
    project_key   TEXT    NOT NULL,
    granted_at_ms INTEGER NOT NULL,
    PRIMARY KEY (record_id, project_key),
    FOREIGN KEY (record_id) REFERENCES sealed_value_records(record_id) ON DELETE CASCADE
);

-- The exact grant tuple for one immutable action instance. Every targeting
-- column is exact and NOT NULL: there is no wildcard target, environment name,
-- child id, or caller dispatch identity anywhere in this table.
--
-- `use_epoch` is the deterministic compare-and-swap ownership token. A use
-- claims the grant by bumping it; the loser of a race changes zero rows and
-- performs no literal lookup and no outbound action.
CREATE TABLE sealed_action_grants (
    grant_id           TEXT    PRIMARY KEY,
    record_id          TEXT    NOT NULL,
    value_version      INTEGER NOT NULL CHECK (value_version >= 1),
    project_key        TEXT    NOT NULL,
    session_id         TEXT    NOT NULL,
    session_generation INTEGER NOT NULL CHECK (session_generation >= 0),
    action_id          TEXT    NOT NULL,
    action_revision    INTEGER NOT NULL CHECK (action_revision >= 1),
    use_epoch          INTEGER NOT NULL DEFAULT 0 CHECK (use_epoch >= 0),
    issued_at_ms       INTEGER NOT NULL,
    expires_at_ms      INTEGER,
    revoked_at_ms      INTEGER,
    FOREIGN KEY (record_id) REFERENCES sealed_value_records(record_id) ON DELETE CASCADE,
    -- A grant names an exact session. When that session is deleted the grant
    -- must go with it: an outstanding grant naming a dead session would be a
    -- capability nobody can see and nobody can revoke.
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_sealed_action_grants_lookup
    ON sealed_action_grants (record_id, action_id, project_key, session_id);

-- Session deletion cascades through this table, so the cascade needs an index
-- it can seek on. Both indexes above lead with `record_id`, which SQLite
-- cannot use for a `session_id` lookup, so deleting a session would scan every
-- grant. Leads with `session_id` for that reason.
CREATE INDEX idx_sealed_action_grants_session ON sealed_action_grants (session_id);

-- One live grant per exact (record, action, project, session, generation)
-- tuple, so authorization resolves a single row without ranking.
CREATE UNIQUE INDEX uq_sealed_action_grants_tuple
    ON sealed_action_grants (record_id, action_id, project_key, session_id, session_generation);

-- A grant's targeting columns are immutable once issued. Only the revocation
-- stamp and the use-ownership epoch may move.
CREATE TRIGGER sealed_action_grants_targeting_immutable
BEFORE UPDATE ON sealed_action_grants
WHEN NEW.record_id          IS NOT OLD.record_id
  OR NEW.value_version      IS NOT OLD.value_version
  OR NEW.project_key        IS NOT OLD.project_key
  OR NEW.session_id         IS NOT OLD.session_id
  OR NEW.session_generation IS NOT OLD.session_generation
  OR NEW.action_id          IS NOT OLD.action_id
  OR NEW.action_revision    IS NOT OLD.action_revision
  OR NEW.issued_at_ms       IS NOT OLD.issued_at_ms
BEGIN
    SELECT RAISE(ABORT, 'sealed action grant targeting is immutable');
END;

-- Revocation is one-way; a revoked grant is never un-revoked.
CREATE TRIGGER sealed_action_grants_revocation_final
BEFORE UPDATE ON sealed_action_grants
WHEN OLD.revoked_at_ms IS NOT NULL AND NEW.revoked_at_ms IS NULL
BEGIN
    SELECT RAISE(ABORT, 'sealed action grant revocation is final');
END;

-- The use-ownership epoch only advances.
CREATE TRIGGER sealed_action_grants_epoch_monotonic
BEFORE UPDATE ON sealed_action_grants
WHEN NEW.use_epoch < OLD.use_epoch
BEGIN
    SELECT RAISE(ABORT, 'sealed action grant use epoch is monotonic');
END;

-- Explicit, versioned image-generation monetary policy. JSON is validated by
-- the typed boundary before insertion; old versions remain referenced by the
-- immutable ledger and are never rewritten by a settings change.
CREATE TABLE image_spend_policy_versions (
    project_key  TEXT NOT NULL,
    version      INTEGER NOT NULL CHECK(version >= 1),
    epoch_policy_version INTEGER NOT NULL CHECK(epoch_policy_version >= 1),
    settings_json TEXT NOT NULL,
    saved_at_ms  INTEGER NOT NULL,
    PRIMARY KEY(project_key, version)
);

CREATE TABLE image_spend_reservations (
    reservation_id TEXT PRIMARY KEY,
    plan_digest TEXT NOT NULL,
    session_id TEXT NOT NULL,
    project_key TEXT NOT NULL,
    policy_version INTEGER NOT NULL CHECK(policy_version >= 1),
    epoch_policy_version INTEGER NOT NULL CHECK(epoch_policy_version >= 1),
    epoch_sequence INTEGER NOT NULL CHECK(epoch_sequence >= 0),
    reserved_usd_micros BLOB CHECK(reserved_usd_micros IS NULL OR length(reserved_usd_micros)=8),
    cost_unknown INTEGER NOT NULL CHECK(cost_unknown IN (0,1)),
    state TEXT NOT NULL CHECK(state IN ('reserved','released','reconciled','budget_violation')),
    release_proof_identity TEXT,
    created_at_ms INTEGER NOT NULL,
    released_at_ms INTEGER,
    FOREIGN KEY(project_key,policy_version) REFERENCES image_spend_policy_versions(project_key,version),
    CHECK((cost_unknown=1 AND reserved_usd_micros IS NULL) OR (cost_unknown=0 AND reserved_usd_micros IS NOT NULL))
);

CREATE TABLE image_spend_attempts (
    reservation_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    maximum_usd_micros BLOB CHECK(maximum_usd_micros IS NULL OR length(maximum_usd_micros)=8),
    PRIMARY KEY(reservation_id,attempt_id),
    FOREIGN KEY(reservation_id) REFERENCES image_spend_reservations(reservation_id) ON DELETE RESTRICT
);

-- One immutable external-effect identity per paid attempt. The referenced
-- journal row is prepared in the same transaction as this binding and must
-- reach `dispatching` before provider contact. Acceptance ambiguity and
-- definitive rejection therefore come only from the generic journal graph.
CREATE TABLE image_spend_attempt_dispatches (
    reservation_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    external_operation_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY(reservation_id,attempt_id),
    FOREIGN KEY(reservation_id,attempt_id) REFERENCES image_spend_attempts(reservation_id,attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY(external_operation_id) REFERENCES external_journal_operations(operation_id) ON DELETE RESTRICT
);

CREATE TABLE image_spend_scope_usage (
    reservation_id TEXT NOT NULL,
    scope_kind TEXT NOT NULL CHECK(scope_kind IN ('request','session','project')),
    scope_key TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    epoch_policy_version INTEGER NOT NULL CHECK(epoch_policy_version >= 0),
    epoch_sequence INTEGER NOT NULL CHECK(epoch_sequence >= 0),
    reserved_usd_micros BLOB NOT NULL CHECK(length(reserved_usd_micros)=8),
    charged_usd_micros BLOB NOT NULL CHECK(length(charged_usd_micros)=8),
    debt_usd_micros BLOB NOT NULL CHECK(length(debt_usd_micros)=8),
    PRIMARY KEY(reservation_id,scope_kind),
    FOREIGN KEY(reservation_id) REFERENCES image_spend_reservations(reservation_id) ON DELETE RESTRICT
);
CREATE INDEX idx_image_spend_scope_budget ON image_spend_scope_usage(scope_kind,scope_key,policy_version,epoch_sequence);
CREATE INDEX idx_image_spend_reservation_policy ON image_spend_reservations(project_key,policy_version);

-- Raw provider billing payloads are intentionally absent. Only a normalized,
-- non-secret evidence reference and authoritative integer amount are durable.
CREATE TABLE image_spend_cost_events (
    cost_identity TEXT PRIMARY KEY,
    reservation_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    actual_usd_micros BLOB NOT NULL CHECK(length(actual_usd_micros)=8),
    evidence_ref TEXT NOT NULL,
    recorded_at_ms INTEGER NOT NULL,
    FOREIGN KEY(reservation_id,attempt_id) REFERENCES image_spend_attempts(reservation_id,attempt_id) ON DELETE RESTRICT
);
CREATE INDEX idx_image_spend_cost_reservation ON image_spend_cost_events(reservation_id);
CREATE UNIQUE INDEX uq_image_spend_cost_attempt ON image_spend_cost_events(reservation_id,attempt_id);

CREATE TABLE image_spend_debt_resolutions (
    reservation_id TEXT NOT NULL,
    resolution_ref TEXT NOT NULL,
    resolved_debt_usd_micros BLOB NOT NULL CHECK(length(resolved_debt_usd_micros)=8 AND resolved_debt_usd_micros <> X'0000000000000000'),
    resolved_at_ms INTEGER NOT NULL,
    PRIMARY KEY(reservation_id,resolution_ref),
    FOREIGN KEY(reservation_id) REFERENCES image_spend_reservations(reservation_id) ON DELETE RESTRICT
);

CREATE TABLE image_spend_epoch_heads (
    project_key TEXT NOT NULL,
    epoch_policy_version INTEGER NOT NULL,
    epoch_sequence INTEGER NOT NULL CHECK(epoch_sequence >= 1),
    membership_key TEXT NOT NULL,
    interval_start_ms INTEGER NOT NULL,
    resolved_at_ms INTEGER NOT NULL,
    PRIMARY KEY(project_key,epoch_policy_version)
);

-- Provider-neutral image generation. Plans are immutable canonical bytes;
-- mutable projections cite monotonically increasing row and journal versions.
CREATE TABLE image_generation_plans (
    job_id TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
    plan_digest TEXT NOT NULL UNIQUE CHECK(length(plan_digest) = 64),
    canonical_plan BLOB NOT NULL,
    slot_count INTEGER NOT NULL CHECK(slot_count > 0),
    max_attempt_count INTEGER NOT NULL CHECK(max_attempt_count > 0),
    enqueue_started_monotonic_ms INTEGER NOT NULL CHECK(enqueue_started_monotonic_ms >= 0),
    operation_deadline_monotonic_ms INTEGER NOT NULL,
    CHECK(operation_deadline_monotonic_ms > enqueue_started_monotonic_ms)
);

CREATE TABLE image_generation_jobs (
    job_id TEXT PRIMARY KEY REFERENCES image_generation_plans(job_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK(state IN ('created','validating','awaiting_authorization','queued','dispatching','submission_unknown','running','cancellation_requested','downloading','validating_output','publishing','completed','completed_after_cancel','partially_failed','failed','cancelled')),
    version INTEGER NOT NULL CHECK(version >= 1),
    terminal_event_version INTEGER,
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    CHECK(terminal_event_version IS NULL OR terminal_event_version >= 1)
);

CREATE TABLE image_generation_slots (
    job_id TEXT NOT NULL REFERENCES image_generation_jobs(job_id) ON DELETE RESTRICT,
    slot_id TEXT NOT NULL,
    slot_index INTEGER NOT NULL CHECK(slot_index >= 0),
    sample_index INTEGER NOT NULL CHECK(sample_index >= 0),
    managed_artifact_id TEXT NOT NULL,
    max_attempt_count INTEGER NOT NULL CHECK(max_attempt_count > 0),
    state TEXT NOT NULL CHECK(state IN ('planned','queued','dispatching','submission_unknown','running','cancellation_requested','downloading','validating','ready_to_publish','published','late_quarantined','failed','cancelled','discarded')),
    version INTEGER NOT NULL CHECK(version >= 1),
    applied_cancellation_version INTEGER,
    result_after_cancel INTEGER NOT NULL DEFAULT 0 CHECK(result_after_cancel IN (0,1)),
    failure_reason TEXT,
    PRIMARY KEY(job_id,slot_id),
    UNIQUE(job_id,slot_index),
    UNIQUE(managed_artifact_id),
    CHECK(
      (state IN ('planned','queued','ready_to_publish') AND applied_cancellation_version IS NULL AND result_after_cancel=0) OR
      (state IN ('dispatching','submission_unknown','running','downloading') AND result_after_cancel=0) OR
      (state='cancellation_requested' AND applied_cancellation_version IS NOT NULL AND result_after_cancel=0) OR
      (state='validating' AND ((applied_cancellation_version IS NULL AND result_after_cancel=0) OR (applied_cancellation_version IS NOT NULL AND result_after_cancel=1))) OR
      (state='published' AND ((applied_cancellation_version IS NULL AND result_after_cancel=0) OR (applied_cancellation_version IS NOT NULL AND result_after_cancel=1))) OR
      (state IN ('late_quarantined','discarded') AND applied_cancellation_version IS NOT NULL AND result_after_cancel=1) OR
      (state='cancelled' AND applied_cancellation_version IS NOT NULL AND result_after_cancel=0) OR
      (state='failed' AND ((applied_cancellation_version IS NULL AND result_after_cancel=0) OR applied_cancellation_version IS NOT NULL))
    )
);

CREATE TABLE image_generation_attempts (
    job_id TEXT NOT NULL,
    slot_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL CHECK(attempt_number >= 1),
    provider_request_identity TEXT NOT NULL,
    provider_idempotency_identity TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('planned','preparing','prepared','dispatching','accepted','submission_unknown','reconciling','running','downloading','cancellation_requested','response_adopted','failed_not_submitted','rejected_not_accepted','cancelled','succeeded','completed_after_cancel','failed_after_acceptance')),
    version INTEGER NOT NULL CHECK(version >= 1),
    external_operation_id TEXT UNIQUE,
    observed_journal_version INTEGER,
    applied_cancellation_version INTEGER,
    response_digest TEXT CHECK(response_digest IS NULL OR length(response_digest)=64),
    nonacceptance_evidence_digest TEXT CHECK(nonacceptance_evidence_digest IS NULL OR length(nonacceptance_evidence_digest)=64),
    PRIMARY KEY(job_id,slot_id,attempt_number),
    UNIQUE(provider_request_identity),
    UNIQUE(provider_idempotency_identity),
    FOREIGN KEY(job_id,slot_id) REFERENCES image_generation_slots(job_id,slot_id) ON DELETE RESTRICT,
    FOREIGN KEY(external_operation_id) REFERENCES external_journal_operations(operation_id) ON DELETE RESTRICT,
    CHECK((external_operation_id IS NULL AND observed_journal_version IS NULL) OR (external_operation_id IS NOT NULL AND observed_journal_version >= 1))
);

CREATE TABLE image_generation_cancellation_facts (
    job_id TEXT PRIMARY KEY REFERENCES image_generation_jobs(job_id) ON DELETE RESTRICT,
    cancellation_version INTEGER NOT NULL CHECK(cancellation_version >= 1),
    requested_at_unix_ms INTEGER NOT NULL,
    request_operation_id TEXT NOT NULL UNIQUE,
    UNIQUE(job_id,cancellation_version)
);

CREATE TABLE image_generation_cancelled_result_facts (
    job_id TEXT NOT NULL,
    slot_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    cancellation_version INTEGER NOT NULL,
    response_digest TEXT NOT NULL CHECK(length(response_digest)=64),
    journal_terminal_version INTEGER NOT NULL CHECK(journal_terminal_version >= 1),
    ordering TEXT NOT NULL CHECK(ordering IN ('response_after_cancellation','response_adopted_before_cancellation')),
    PRIMARY KEY(job_id,slot_id,attempt_number),
    FOREIGN KEY(job_id,slot_id,attempt_number) REFERENCES image_generation_attempts(job_id,slot_id,attempt_number) ON DELETE RESTRICT,
    FOREIGN KEY(job_id,cancellation_version) REFERENCES image_generation_cancellation_facts(job_id,cancellation_version) ON DELETE RESTRICT
);

CREATE TABLE image_generation_publication_right_facts (
    job_id TEXT NOT NULL,
    slot_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL,
    slot_version INTEGER NOT NULL CHECK(slot_version >= 1),
    artifact_generation INTEGER NOT NULL CHECK(artifact_generation >= 1),
    committed_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY(job_id,slot_id),
    FOREIGN KEY(job_id,slot_id,attempt_number) REFERENCES image_generation_attempts(job_id,slot_id,attempt_number) ON DELETE RESTRICT
);
CREATE TABLE image_generation_reconciliation_evidence (
 job_id TEXT NOT NULL, slot_id TEXT NOT NULL, attempt_number INTEGER NOT NULL,
 journal_version INTEGER NOT NULL CHECK(journal_version>=1),
 evidence_digest TEXT NOT NULL CHECK(length(evidence_digest)=64 AND evidence_digest NOT GLOB '*[^0-9a-f]*'),
 provider_request_identity TEXT NOT NULL,
 provider_idempotency_identity TEXT NOT NULL,
 journal_payload_digest TEXT NOT NULL CHECK(length(journal_payload_digest)=64 AND journal_payload_digest NOT GLOB '*[^0-9a-f]*'),
 outcome TEXT NOT NULL CHECK(outcome IN ('authoritative_nonacceptance','authoritative_failure')),
 PRIMARY KEY(job_id,slot_id,attempt_number,journal_version),
 FOREIGN KEY(job_id,slot_id,attempt_number) REFERENCES image_generation_attempts(job_id,slot_id,attempt_number) ON DELETE RESTRICT
);

-- Managed image artifacts are a separate retained aggregate. They are never
-- attachment rows and user-published copies are never members of this graph.
CREATE TABLE image_generation_artifacts (
 artifact_id TEXT PRIMARY KEY,
 job_id TEXT NOT NULL,
 slot_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('allocating','writing','retained','late_quarantined','cleanup_pending','deleting','tombstoned','security_blocked')),
 generation INTEGER NOT NULL CHECK(generation>=1),
 expected_component_count INTEGER NOT NULL CHECK(expected_component_count>=1),
 active_lease_count INTEGER NOT NULL DEFAULT 0 CHECK(active_lease_count>=0),
 component_set_digest TEXT NOT NULL CHECK(length(component_set_digest)=64 AND component_set_digest NOT GLOB '*[^0-9a-f]*'),
 component_set_json TEXT NOT NULL,
 eligibility_at_unix_ms INTEGER,
 immediate_cleanup INTEGER NOT NULL DEFAULT 0 CHECK(immediate_cleanup IN (0,1)),
 terminal_reason TEXT,
 created_at_unix_ms INTEGER NOT NULL,
 updated_at_unix_ms INTEGER NOT NULL,
 UNIQUE(job_id,slot_id),
 FOREIGN KEY(job_id,slot_id) REFERENCES image_generation_slots(job_id,slot_id) ON DELETE RESTRICT,
 CHECK((state='tombstoned' AND terminal_reason IS NOT NULL) OR state!='tombstoned')
);

CREATE TABLE image_generation_artifact_components (
 artifact_id TEXT NOT NULL REFERENCES image_generation_artifacts(artifact_id) ON DELETE RESTRICT,
 component_id TEXT NOT NULL,
 component_kind TEXT NOT NULL CHECK(component_kind IN ('primary','normalized_raster','sanitized_svg','thumbnail','model_payload')),
 state TEXT NOT NULL CHECK(state IN ('planned','writing','ready','cleanup_pending','deleting','tombstoned','security_blocked')),
 generation INTEGER NOT NULL CHECK(generation>=1),
 relative_storage_key TEXT NOT NULL,
 byte_length_decimal TEXT NOT NULL CHECK(byte_length_decimal<>'' AND byte_length_decimal NOT GLOB '*[^0-9]*'),
 sha256 TEXT NOT NULL CHECK(length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
 stable_identity_json TEXT,
 expected_link_count INTEGER NOT NULL DEFAULT 1 CHECK(expected_link_count=1),
 resource_reservation_id TEXT NOT NULL,
 release_operation_id TEXT NOT NULL UNIQUE,
 deletion_evidence_digest TEXT CHECK(deletion_evidence_digest IS NULL OR (length(deletion_evidence_digest)=64 AND deletion_evidence_digest NOT GLOB '*[^0-9a-f]*')),
 PRIMARY KEY(artifact_id,component_id),
 UNIQUE(artifact_id,component_kind),
 UNIQUE(relative_storage_key),
 CHECK((state='tombstoned' AND deletion_evidence_digest IS NOT NULL) OR state!='tombstoned')
);

CREATE TABLE image_generation_artifact_cleanup_intents (
 cleanup_operation_id TEXT PRIMARY KEY,
 artifact_id TEXT NOT NULL REFERENCES image_generation_artifacts(artifact_id) ON DELETE RESTRICT,
 expected_artifact_generation INTEGER NOT NULL CHECK(expected_artifact_generation>=1),
 reason TEXT NOT NULL CHECK(reason IN ('retention_expired','discard_late_result','invalid_output','restart_recovery','owner_recovery')),
 state TEXT NOT NULL CHECK(state IN ('pending','deleting','completed','security_blocked')),
 version INTEGER NOT NULL CHECK(version>=1),
 created_at_unix_ms INTEGER NOT NULL,
 completed_at_unix_ms INTEGER,
 UNIQUE(artifact_id),
 CHECK((state='completed')=(completed_at_unix_ms IS NOT NULL))
);

CREATE TABLE image_generation_component_release_facts (
 artifact_id TEXT NOT NULL,
 component_id TEXT NOT NULL,
 release_operation_id TEXT NOT NULL,
 deletion_evidence_digest TEXT NOT NULL CHECK(length(deletion_evidence_digest)=64 AND deletion_evidence_digest NOT GLOB '*[^0-9a-f]*'),
 committed_at_unix_ms INTEGER NOT NULL,
 PRIMARY KEY(artifact_id,component_id),
 UNIQUE(release_operation_id),
 FOREIGN KEY(artifact_id,component_id) REFERENCES image_generation_artifact_components(artifact_id,component_id) ON DELETE RESTRICT
);

CREATE TABLE image_generation_artifact_references (
 reference_id TEXT PRIMARY KEY,
 artifact_id TEXT NOT NULL REFERENCES image_generation_artifacts(artifact_id) ON DELETE RESTRICT,
 reference_kind TEXT NOT NULL CHECK(reference_kind IN ('message','tool','publication_operation')),
 released_at_unix_ms INTEGER
);

CREATE TABLE image_generation_artifact_leases (
 lease_id TEXT PRIMARY KEY,
 artifact_id TEXT NOT NULL,
 artifact_generation INTEGER NOT NULL CHECK(artifact_generation>=1),
 owning_job_id TEXT NOT NULL,
 owning_job_generation INTEGER NOT NULL CHECK(owning_job_generation>=1),
 owning_slot_id TEXT NOT NULL,
 owning_slot_generation INTEGER NOT NULL CHECK(owning_slot_generation>=1),
 published_disposition TEXT NOT NULL CHECK(published_disposition IN ('ordinary','late_authorized')),
 published_disposition_generation INTEGER NOT NULL CHECK(published_disposition_generation>=1),
 component_id TEXT NOT NULL,
 component_kind TEXT NOT NULL CHECK(component_kind IN ('primary','normalized_raster','sanitized_svg','thumbnail','model_payload')),
 component_generation INTEGER NOT NULL CHECK(component_generation>=1),
 component_checksum TEXT NOT NULL CHECK(length(component_checksum)=64 AND component_checksum NOT GLOB '*[^0-9a-f]*'),
 consumer_purpose TEXT NOT NULL CHECK(consumer_purpose IN ('serve_artifact','serve_thumbnail','tool_input','model_input','internal_verification','internal_cleanup')),
 consumer_route TEXT NOT NULL CHECK(consumer_route IN ('artifact_full','artifact_range','thumbnail','tool','model_payload','verification','cleanup')),
 read_kind TEXT NOT NULL CHECK(read_kind IN ('full','range')),
 range_start_decimal TEXT NOT NULL CHECK(range_start_decimal<>'' AND range_start_decimal NOT GLOB '*[^0-9]*'),
 requested_length_decimal TEXT NOT NULL CHECK(requested_length_decimal<>'' AND requested_length_decimal NOT GLOB '*[^0-9]*'),
 component_set_digest TEXT NOT NULL CHECK(length(component_set_digest)=64 AND component_set_digest NOT GLOB '*[^0-9a-f]*'),
 authorization_digest TEXT NOT NULL CHECK(length(authorization_digest)=64 AND authorization_digest NOT GLOB '*[^0-9a-f]*'),
 daemon_boot_id TEXT NOT NULL,
 committed_at_monotonic INTEGER NOT NULL CHECK(committed_at_monotonic>=0),
 deadline_monotonic INTEGER NOT NULL,
 released_at INTEGER,
 FOREIGN KEY(artifact_id,component_id) REFERENCES image_generation_artifact_components(artifact_id,component_id) ON DELETE RESTRICT,
 FOREIGN KEY(owning_job_id,owning_slot_id) REFERENCES image_generation_slots(job_id,slot_id) ON DELETE RESTRICT,
 CHECK(deadline_monotonic=committed_at_monotonic+60000),
 CHECK((consumer_purpose='serve_artifact' AND consumer_route IN ('artifact_full','artifact_range')) OR
       (consumer_purpose='serve_thumbnail' AND consumer_route='thumbnail') OR
       (consumer_purpose='tool_input' AND consumer_route='tool') OR
       (consumer_purpose='model_input' AND consumer_route='model_payload') OR
       (consumer_purpose='internal_verification' AND consumer_route='verification') OR
       (consumer_purpose='internal_cleanup' AND consumer_route='cleanup')),
 CHECK((read_kind='range' AND consumer_route='artifact_range' AND requested_length_decimal!='0') OR
       (read_kind='full' AND consumer_route!='artifact_range' AND range_start_decimal='0'))
);

CREATE TABLE image_generation_late_publication_leases (
 publication_operation_id TEXT PRIMARY KEY,
 artifact_id TEXT NOT NULL REFERENCES image_generation_artifacts(artifact_id) ON DELETE RESTRICT,
 artifact_generation INTEGER NOT NULL CHECK(artifact_generation>=1),
 job_id TEXT NOT NULL,
 slot_id TEXT NOT NULL,
 expected_slot_version INTEGER NOT NULL CHECK(expected_slot_version>=1),
 component_set_digest TEXT NOT NULL CHECK(length(component_set_digest)=64 AND component_set_digest NOT GLOB '*[^0-9a-f]*'),
 component_set_json TEXT NOT NULL,
 authorization_digest TEXT NOT NULL CHECK(length(authorization_digest)=64 AND authorization_digest NOT GLOB '*[^0-9a-f]*'),
 output_authority_digest TEXT NOT NULL CHECK(length(output_authority_digest)=64 AND output_authority_digest NOT GLOB '*[^0-9a-f]*'),
 output_authority_generation INTEGER NOT NULL CHECK(output_authority_generation>=1),
 destination_name TEXT NOT NULL,
 temporary_name TEXT NOT NULL,
 created_at_unix_ms INTEGER NOT NULL,
 deadline_unix_ms INTEGER NOT NULL,
 worker_boot_id TEXT,
 claim_generation INTEGER CHECK(claim_generation IS NULL OR claim_generation>=1),
 state TEXT NOT NULL CHECK(state IN ('reserved','copy_authorized','copy_committed','published','aborted','expired','security_blocked')),
 version INTEGER NOT NULL CHECK(version>=1),
 temporary_evidence_json TEXT,
 output_evidence_json TEXT,
 recovery_evidence_json TEXT,
 FOREIGN KEY(job_id,slot_id) REFERENCES image_generation_slots(job_id,slot_id) ON DELETE RESTRICT,
 CHECK(deadline_unix_ms=created_at_unix_ms+300000),
 CHECK((worker_boot_id IS NULL)=(claim_generation IS NULL))
);
CREATE UNIQUE INDEX image_generation_one_live_late_publication
ON image_generation_late_publication_leases(artifact_id)
WHERE state IN ('reserved','copy_authorized','copy_committed');

CREATE TABLE image_generation_artifact_transitions(from_state TEXT NOT NULL,to_state TEXT NOT NULL,PRIMARY KEY(from_state,to_state));
INSERT INTO image_generation_artifact_transitions VALUES
('allocating','writing'),('allocating','cleanup_pending'),('allocating','security_blocked'),
('writing','retained'),('writing','late_quarantined'),('writing','cleanup_pending'),('writing','security_blocked'),
('retained','cleanup_pending'),('retained','security_blocked'),
('late_quarantined','retained'),('late_quarantined','cleanup_pending'),('late_quarantined','security_blocked'),
('cleanup_pending','deleting'),('cleanup_pending','security_blocked'),
('deleting','tombstoned'),('deleting','security_blocked'),
('security_blocked','cleanup_pending');
CREATE TABLE image_generation_component_transitions(from_state TEXT NOT NULL,to_state TEXT NOT NULL,PRIMARY KEY(from_state,to_state));
INSERT INTO image_generation_component_transitions VALUES
('planned','writing'),('planned','cleanup_pending'),('planned','security_blocked'),
('writing','ready'),('writing','cleanup_pending'),('writing','security_blocked'),
('ready','cleanup_pending'),('ready','security_blocked'),
('cleanup_pending','deleting'),('cleanup_pending','security_blocked'),
('deleting','tombstoned'),('deleting','security_blocked'),
('security_blocked','cleanup_pending');
CREATE TABLE image_generation_cleanup_transitions(from_state TEXT NOT NULL,to_state TEXT NOT NULL,PRIMARY KEY(from_state,to_state));
INSERT INTO image_generation_cleanup_transitions VALUES
('pending','deleting'),('pending','security_blocked'),('deleting','completed'),('deleting','security_blocked'),('security_blocked','pending');
CREATE TABLE image_generation_late_publication_transitions(from_state TEXT NOT NULL,to_state TEXT NOT NULL,PRIMARY KEY(from_state,to_state));
INSERT INTO image_generation_late_publication_transitions VALUES
('reserved','copy_authorized'),('reserved','aborted'),('reserved','expired'),('reserved','security_blocked'),
('copy_authorized','copy_committed'),('copy_authorized','aborted'),('copy_authorized','security_blocked'),
('copy_committed','published'),('copy_committed','security_blocked'),('security_blocked','published'),('security_blocked','aborted');

CREATE TRIGGER image_generation_artifact_transition_guard BEFORE UPDATE OF state,generation ON image_generation_artifacts
WHEN NEW.generation!=OLD.generation+1 OR NOT EXISTS(SELECT 1 FROM image_generation_artifact_transitions WHERE from_state=OLD.state AND to_state=NEW.state)
BEGIN SELECT RAISE(ABORT,'forbidden image artifact transition'); END;
CREATE TRIGGER image_generation_artifact_slot_binding_guard BEFORE INSERT ON image_generation_artifacts
WHEN NOT EXISTS(SELECT 1 FROM image_generation_slots s WHERE s.job_id=NEW.job_id AND s.slot_id=NEW.slot_id AND s.managed_artifact_id=NEW.artifact_id)
BEGIN SELECT RAISE(ABORT,'image artifact is not the sealed slot artifact'); END;
CREATE TRIGGER image_generation_artifact_identity_immutable BEFORE UPDATE OF artifact_id,job_id,slot_id,expected_component_count,component_set_digest,component_set_json,created_at_unix_ms ON image_generation_artifacts
BEGIN SELECT RAISE(ABORT,'image artifact identity graph is immutable'); END;
CREATE TRIGGER image_generation_artifact_delete_forbidden BEFORE DELETE ON image_generation_artifacts
BEGIN SELECT RAISE(ABORT,'image artifact tombstones are retained'); END;
CREATE TRIGGER image_generation_component_insert_guard BEFORE INSERT ON image_generation_artifact_components
WHEN (SELECT state FROM image_generation_artifacts WHERE artifact_id=NEW.artifact_id)!='allocating'
BEGIN SELECT RAISE(ABORT,'image artifact component graph is sealed'); END;
CREATE TRIGGER image_generation_component_identity_immutable BEFORE UPDATE OF artifact_id,component_id,component_kind,relative_storage_key,byte_length_decimal,sha256,expected_link_count,resource_reservation_id,release_operation_id ON image_generation_artifact_components
BEGIN SELECT RAISE(ABORT,'image artifact component identity is immutable'); END;
CREATE TRIGGER image_generation_component_delete_forbidden BEFORE DELETE ON image_generation_artifact_components
BEGIN SELECT RAISE(ABORT,'image artifact component tombstones are retained'); END;
CREATE TRIGGER image_generation_component_transition_guard BEFORE UPDATE OF state,generation ON image_generation_artifact_components
WHEN NEW.generation!=OLD.generation+1 OR NOT EXISTS(SELECT 1 FROM image_generation_component_transitions WHERE from_state=OLD.state AND to_state=NEW.state)
BEGIN SELECT RAISE(ABORT,'forbidden image artifact component transition'); END;
CREATE TRIGGER image_generation_cleanup_transition_guard BEFORE UPDATE OF state,version ON image_generation_artifact_cleanup_intents
WHEN NEW.version!=OLD.version+1 OR NOT EXISTS(SELECT 1 FROM image_generation_cleanup_transitions WHERE from_state=OLD.state AND to_state=NEW.state)
BEGIN SELECT RAISE(ABORT,'forbidden image artifact cleanup transition'); END;
CREATE TRIGGER image_generation_late_publication_transition_guard BEFORE UPDATE OF state,version ON image_generation_late_publication_leases
WHEN NEW.version!=OLD.version+1 OR NOT EXISTS(SELECT 1 FROM image_generation_late_publication_transitions WHERE from_state=OLD.state AND to_state=NEW.state)
BEGIN SELECT RAISE(ABORT,'forbidden late image publication transition'); END;
CREATE TRIGGER image_generation_artifact_retained_projection_guard BEFORE UPDATE OF state ON image_generation_artifacts
WHEN NEW.state IN ('retained','late_quarantined') AND (((SELECT count(*) FROM image_generation_artifact_components c WHERE c.artifact_id=NEW.artifact_id)!=NEW.expected_component_count) OR ((SELECT count(*) FROM image_generation_artifact_components c WHERE c.artifact_id=NEW.artifact_id AND c.state='ready')!=NEW.expected_component_count))
BEGIN SELECT RAISE(ABORT,'retained image artifact lacks complete ready component set'); END;
CREATE TRIGGER image_generation_artifact_late_publication_guard BEFORE UPDATE OF state ON image_generation_artifacts
WHEN OLD.state='late_quarantined' AND NEW.state='retained' AND NOT EXISTS(SELECT 1 FROM image_generation_late_publication_leases p WHERE p.artifact_id=NEW.artifact_id AND p.state='published' AND p.artifact_generation=OLD.generation)
BEGIN SELECT RAISE(ABORT,'late artifact retention lacks exact published disposition lease'); END;
CREATE TRIGGER image_generation_artifact_security_recovery_guard BEFORE UPDATE OF state ON image_generation_artifacts
WHEN OLD.state='security_blocked' AND NEW.state='cleanup_pending' AND NOT EXISTS(SELECT 1 FROM image_generation_artifact_cleanup_intents i WHERE i.artifact_id=NEW.artifact_id AND i.reason='owner_recovery' AND i.expected_artifact_generation=NEW.generation)
BEGIN SELECT RAISE(ABORT,'security-blocked artifact lacks Owner recovery intent'); END;
CREATE TRIGGER image_generation_component_security_recovery_guard BEFORE UPDATE OF state ON image_generation_artifact_components
WHEN OLD.state='security_blocked' AND NEW.state='cleanup_pending' AND NOT EXISTS(SELECT 1 FROM image_generation_artifact_cleanup_intents i WHERE i.artifact_id=NEW.artifact_id AND i.reason='owner_recovery')
BEGIN SELECT RAISE(ABORT,'security-blocked component lacks Owner recovery intent'); END;
CREATE TRIGGER image_generation_artifact_tombstone_projection_guard BEFORE UPDATE OF state ON image_generation_artifacts
WHEN NEW.state='tombstoned' AND (EXISTS(SELECT 1 FROM image_generation_artifact_components c WHERE c.artifact_id=NEW.artifact_id AND c.state!='tombstoned') OR EXISTS(SELECT 1 FROM image_generation_artifact_components c LEFT JOIN image_generation_component_release_facts r ON r.artifact_id=c.artifact_id AND r.component_id=c.component_id WHERE c.artifact_id=NEW.artifact_id AND r.component_id IS NULL))
BEGIN SELECT RAISE(ABORT,'image artifact tombstone lacks component deletion and release evidence'); END;
CREATE TRIGGER image_generation_component_tombstone_guard BEFORE UPDATE OF state ON image_generation_artifact_components
WHEN NEW.state='tombstoned' AND NOT EXISTS(SELECT 1 FROM image_generation_component_release_facts r WHERE r.artifact_id=NEW.artifact_id AND r.component_id=NEW.component_id AND r.deletion_evidence_digest=NEW.deletion_evidence_digest)
BEGIN SELECT RAISE(ABORT,'component tombstone lacks matching release evidence'); END;
CREATE TRIGGER image_generation_release_guard BEFORE INSERT ON image_generation_component_release_facts
WHEN NOT EXISTS(SELECT 1 FROM image_generation_artifact_components c WHERE c.artifact_id=NEW.artifact_id AND c.component_id=NEW.component_id AND c.state='deleting' AND c.release_operation_id=NEW.release_operation_id AND c.deletion_evidence_digest=NEW.deletion_evidence_digest)
BEGIN SELECT RAISE(ABORT,'resource release precedes verified component deletion evidence'); END;
CREATE TRIGGER image_generation_release_immutable BEFORE UPDATE ON image_generation_component_release_facts BEGIN SELECT RAISE(ABORT,'component release evidence is immutable'); END;
CREATE TRIGGER image_generation_release_delete_forbidden BEFORE DELETE ON image_generation_component_release_facts BEGIN SELECT RAISE(ABORT,'component release evidence is immutable'); END;
CREATE TRIGGER image_generation_cleanup_identity_immutable BEFORE UPDATE OF cleanup_operation_id,artifact_id,expected_artifact_generation,reason,created_at_unix_ms ON image_generation_artifact_cleanup_intents BEGIN SELECT RAISE(ABORT,'cleanup intent identity is immutable'); END;
CREATE TRIGGER image_generation_cleanup_delete_forbidden BEFORE DELETE ON image_generation_artifact_cleanup_intents BEGIN SELECT RAISE(ABORT,'cleanup intent is durable'); END;
CREATE TRIGGER image_generation_lease_identity_immutable BEFORE UPDATE OF lease_id,artifact_id,artifact_generation,owning_job_id,owning_job_generation,owning_slot_id,owning_slot_generation,published_disposition,published_disposition_generation,component_id,component_kind,component_generation,component_checksum,consumer_purpose,consumer_route,read_kind,range_start_decimal,requested_length_decimal,component_set_digest,authorization_digest,daemon_boot_id,committed_at_monotonic,deadline_monotonic ON image_generation_artifact_leases BEGIN SELECT RAISE(ABORT,'artifact lease identity is immutable'); END;
CREATE TRIGGER image_generation_lease_delete_forbidden BEFORE DELETE ON image_generation_artifact_leases BEGIN SELECT RAISE(ABORT,'artifact lease is durable'); END;
CREATE TRIGGER image_generation_late_publication_identity_immutable BEFORE UPDATE OF publication_operation_id,artifact_id,artifact_generation,job_id,slot_id,expected_slot_version,component_set_digest,component_set_json,authorization_digest,output_authority_digest,output_authority_generation,destination_name,temporary_name,created_at_unix_ms,deadline_unix_ms ON image_generation_late_publication_leases BEGIN SELECT RAISE(ABORT,'late publication identity is immutable'); END;
CREATE TRIGGER image_generation_late_publication_delete_forbidden BEFORE DELETE ON image_generation_late_publication_leases BEGIN SELECT RAISE(ABORT,'late publication lease is durable'); END;
CREATE TRIGGER image_generation_artifact_transition_registry_sealed BEFORE INSERT ON image_generation_artifact_transitions BEGIN SELECT RAISE(ABORT,'image artifact transition registry is sealed'); END;
CREATE TRIGGER image_generation_artifact_transition_registry_update_sealed BEFORE UPDATE ON image_generation_artifact_transitions BEGIN SELECT RAISE(ABORT,'image artifact transition registry is sealed'); END;
CREATE TRIGGER image_generation_artifact_transition_registry_delete_sealed BEFORE DELETE ON image_generation_artifact_transitions BEGIN SELECT RAISE(ABORT,'image artifact transition registry is sealed'); END;
CREATE TRIGGER image_generation_component_transition_registry_sealed BEFORE INSERT ON image_generation_component_transitions BEGIN SELECT RAISE(ABORT,'image component transition registry is sealed'); END;
CREATE TRIGGER image_generation_component_transition_registry_update_sealed BEFORE UPDATE ON image_generation_component_transitions BEGIN SELECT RAISE(ABORT,'image component transition registry is sealed'); END;
CREATE TRIGGER image_generation_component_transition_registry_delete_sealed BEFORE DELETE ON image_generation_component_transitions BEGIN SELECT RAISE(ABORT,'image component transition registry is sealed'); END;
CREATE TRIGGER image_generation_cleanup_transition_registry_sealed BEFORE INSERT ON image_generation_cleanup_transitions BEGIN SELECT RAISE(ABORT,'image cleanup transition registry is sealed'); END;
CREATE TRIGGER image_generation_cleanup_transition_registry_update_sealed BEFORE UPDATE ON image_generation_cleanup_transitions BEGIN SELECT RAISE(ABORT,'image cleanup transition registry is sealed'); END;
CREATE TRIGGER image_generation_cleanup_transition_registry_delete_sealed BEFORE DELETE ON image_generation_cleanup_transitions BEGIN SELECT RAISE(ABORT,'image cleanup transition registry is sealed'); END;
CREATE TRIGGER image_generation_late_publication_transition_registry_sealed BEFORE INSERT ON image_generation_late_publication_transitions BEGIN SELECT RAISE(ABORT,'late publication transition registry is sealed'); END;
CREATE TRIGGER image_generation_late_publication_transition_registry_update_sealed BEFORE UPDATE ON image_generation_late_publication_transitions BEGIN SELECT RAISE(ABORT,'late publication transition registry is sealed'); END;
CREATE TRIGGER image_generation_late_publication_transition_registry_delete_sealed BEFORE DELETE ON image_generation_late_publication_transitions BEGIN SELECT RAISE(ABORT,'late publication transition registry is sealed'); END;

CREATE TABLE image_generation_job_transitions (from_state TEXT NOT NULL,to_state TEXT NOT NULL,PRIMARY KEY(from_state,to_state));
INSERT INTO image_generation_job_transitions VALUES
('created','validating'),('created','failed'),('created','cancelled'),
('validating','awaiting_authorization'),('validating','queued'),('validating','failed'),('validating','cancelled'),
('awaiting_authorization','queued'),('awaiting_authorization','failed'),('awaiting_authorization','cancelled'),
('queued','dispatching'),('queued','cancellation_requested'),('queued','failed'),('queued','cancelled'),
('dispatching','submission_unknown'),('dispatching','running'),('dispatching','cancellation_requested'),('dispatching','downloading'),('dispatching','partially_failed'),('dispatching','failed'),('dispatching','cancelled'),
('submission_unknown','running'),('submission_unknown','cancellation_requested'),('submission_unknown','downloading'),('submission_unknown','completed_after_cancel'),('submission_unknown','partially_failed'),('submission_unknown','failed'),
('running','cancellation_requested'),('running','downloading'),('running','partially_failed'),('running','failed'),
('cancellation_requested','cancelled'),('cancellation_requested','downloading'),('cancellation_requested','completed_after_cancel'),('cancellation_requested','partially_failed'),('cancellation_requested','failed'),
('downloading','validating_output'),('downloading','cancellation_requested'),('downloading','completed_after_cancel'),('downloading','partially_failed'),('downloading','failed'),
('validating_output','publishing'),('validating_output','cancellation_requested'),('validating_output','completed_after_cancel'),('validating_output','partially_failed'),('validating_output','failed'),
('publishing','completed'),('publishing','cancellation_requested'),('publishing','completed_after_cancel'),('publishing','partially_failed'),('publishing','failed');

CREATE TABLE image_generation_slot_transitions (from_state TEXT NOT NULL,to_state TEXT NOT NULL,PRIMARY KEY(from_state,to_state));
INSERT INTO image_generation_slot_transitions VALUES
('planned','queued'),('planned','failed'),('planned','cancelled'),('queued','dispatching'),('queued','failed'),('queued','cancelled'),
('dispatching','submission_unknown'),('dispatching','running'),('dispatching','downloading'),('dispatching','cancellation_requested'),('dispatching','failed'),('dispatching','cancelled'),
('submission_unknown','running'),('submission_unknown','downloading'),('submission_unknown','cancellation_requested'),('submission_unknown','failed'),('submission_unknown','cancelled'),
('running','downloading'),('running','cancellation_requested'),('running','failed'),
('cancellation_requested','cancelled'),('cancellation_requested','submission_unknown'),('cancellation_requested','downloading'),('cancellation_requested','failed'),
('downloading','validating'),('downloading','cancellation_requested'),('downloading','failed'),
('validating','ready_to_publish'),('validating','late_quarantined'),('validating','cancellation_requested'),('validating','failed'),
('ready_to_publish','published'),('ready_to_publish','late_quarantined'),('ready_to_publish','failed'),
('late_quarantined','published'),('late_quarantined','discarded');

CREATE TABLE image_generation_attempt_transitions (from_state TEXT NOT NULL,to_state TEXT NOT NULL,PRIMARY KEY(from_state,to_state));
INSERT INTO image_generation_attempt_transitions VALUES
('planned','preparing'),('planned','cancelled'),('planned','failed_not_submitted'),('preparing','prepared'),('preparing','cancelled'),('preparing','failed_not_submitted'),('prepared','dispatching'),('prepared','cancelled'),('prepared','failed_not_submitted'),
('dispatching','accepted'),('dispatching','submission_unknown'),('dispatching','rejected_not_accepted'),('dispatching','cancellation_requested'),('dispatching','failed_not_submitted'),
('accepted','running'),('accepted','downloading'),('accepted','cancellation_requested'),('accepted','response_adopted'),('accepted','failed_after_acceptance'),
('submission_unknown','reconciling'),('submission_unknown','cancellation_requested'),
('reconciling','accepted'),('reconciling','submission_unknown'),('reconciling','rejected_not_accepted'),('reconciling','downloading'),('reconciling','cancellation_requested'),('reconciling','failed_after_acceptance'),
('running','downloading'),('running','cancellation_requested'),('running','failed_after_acceptance'),
('downloading','response_adopted'),('downloading','completed_after_cancel'),('downloading','cancellation_requested'),('downloading','failed_after_acceptance'),
('cancellation_requested','cancelled'),('cancellation_requested','submission_unknown'),('cancellation_requested','reconciling'),('cancellation_requested','accepted'),('cancellation_requested','downloading'),('cancellation_requested','completed_after_cancel'),('cancellation_requested','failed_after_acceptance'),
('response_adopted','succeeded'),('response_adopted','completed_after_cancel'),('response_adopted','failed_after_acceptance');

CREATE TRIGGER image_generation_job_transition_guard BEFORE UPDATE OF state,version ON image_generation_jobs
WHEN NEW.version != OLD.version+1 OR NOT EXISTS(SELECT 1 FROM image_generation_job_transitions WHERE from_state=OLD.state AND to_state=NEW.state)
BEGIN SELECT RAISE(ABORT,'forbidden image generation job transition'); END;
CREATE TRIGGER image_generation_slot_transition_guard BEFORE UPDATE OF state,version ON image_generation_slots
WHEN NEW.version != OLD.version+1 OR (
 (NEW.state != OLD.state AND NOT EXISTS(SELECT 1 FROM image_generation_slot_transitions WHERE from_state=OLD.state AND to_state=NEW.state)) OR
 (NEW.state = OLD.state AND NOT (OLD.state='validating' AND OLD.applied_cancellation_version IS NULL AND OLD.result_after_cancel=0 AND NEW.applied_cancellation_version IS NOT NULL AND NEW.result_after_cancel=1))
)
BEGIN SELECT RAISE(ABORT,'forbidden image generation slot transition'); END;
CREATE TRIGGER image_generation_attempt_transition_guard BEFORE UPDATE OF state,version ON image_generation_attempts
WHEN NEW.version != OLD.version+1 OR NOT EXISTS(SELECT 1 FROM image_generation_attempt_transitions WHERE from_state=OLD.state AND to_state=NEW.state)
BEGIN SELECT RAISE(ABORT,'forbidden image generation attempt transition'); END;
CREATE TRIGGER image_generation_attempt_retry_guard BEFORE UPDATE OF state ON image_generation_attempts
WHEN OLD.state='planned' AND NEW.state='preparing' AND NEW.attempt_number>1 AND NOT EXISTS(
 SELECT 1 FROM image_generation_attempts prior WHERE prior.job_id=NEW.job_id AND prior.slot_id=NEW.slot_id
 AND prior.attempt_number=NEW.attempt_number-1 AND prior.state IN ('failed_not_submitted','rejected_not_accepted'))
BEGIN SELECT RAISE(ABORT,'image generation retry lacks authoritative nonacceptance'); END;
CREATE TRIGGER image_generation_attempt_plan_bound_guard BEFORE INSERT ON image_generation_attempts
WHEN NEW.attempt_number > (SELECT max_attempt_count FROM image_generation_slots WHERE job_id=NEW.job_id AND slot_id=NEW.slot_id)
BEGIN SELECT RAISE(ABORT,'image generation attempt exceeds sealed plan'); END;
CREATE TRIGGER image_generation_slot_plan_bound_guard BEFORE INSERT ON image_generation_slots
WHEN NEW.slot_index >= (SELECT slot_count FROM image_generation_plans WHERE job_id=NEW.job_id)
BEGIN SELECT RAISE(ABORT,'image generation slot exceeds sealed plan'); END;
CREATE TRIGGER image_generation_response_adopted_guard AFTER UPDATE OF state ON image_generation_attempts
WHEN NEW.state='response_adopted' AND (
 NEW.applied_cancellation_version IS NOT NULL OR NEW.response_digest IS NULL OR NOT EXISTS(
  SELECT 1 FROM external_journal_operations j WHERE j.operation_id=NEW.external_operation_id
  AND j.state='succeeded' AND j.version=NEW.observed_journal_version)
 OR EXISTS(SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=NEW.job_id))
BEGIN SELECT RAISE(ABORT,'response-adopted attempt lacks exact uncancelled journal evidence'); END;
CREATE TRIGGER image_generation_attempt_reconciliation_failure_guard BEFORE UPDATE OF state ON image_generation_attempts
WHEN OLD.state IN ('submission_unknown','reconciling') AND NEW.state IN ('rejected_not_accepted','failed_after_acceptance') AND NOT EXISTS(
 SELECT 1 FROM image_generation_reconciliation_evidence e WHERE e.job_id=NEW.job_id AND e.slot_id=NEW.slot_id AND e.attempt_number=NEW.attempt_number AND e.journal_version=NEW.observed_journal_version)
BEGIN SELECT RAISE(ABORT,'attempt failure lacks authoritative reconciliation evidence'); END;
CREATE TRIGGER image_generation_slot_reconciliation_failure_guard BEFORE UPDATE OF state ON image_generation_slots
WHEN OLD.state IN ('submission_unknown','cancellation_requested') AND NEW.state='failed' AND NOT EXISTS(
 SELECT 1 FROM image_generation_attempts a JOIN image_generation_reconciliation_evidence e ON e.job_id=a.job_id AND e.slot_id=a.slot_id AND e.attempt_number=a.attempt_number AND e.journal_version=a.observed_journal_version
 WHERE a.job_id=NEW.job_id AND a.slot_id=NEW.slot_id)
BEGIN SELECT RAISE(ABORT,'slot failure lacks authoritative reconciliation evidence'); END;
CREATE TRIGGER image_generation_job_reconciliation_failure_guard BEFORE UPDATE OF state ON image_generation_jobs
WHEN OLD.state='submission_unknown' AND NEW.state='failed' AND NOT EXISTS(
 SELECT 1 FROM image_generation_reconciliation_evidence e WHERE e.job_id=NEW.job_id)
BEGIN SELECT RAISE(ABORT,'job failure lacks authoritative reconciliation evidence'); END;
CREATE TRIGGER image_generation_failed_not_submitted_guard BEFORE UPDATE OF state ON image_generation_attempts
WHEN OLD.state='dispatching' AND NEW.state='failed_not_submitted' AND NEW.nonacceptance_evidence_digest IS NULL
BEGIN SELECT RAISE(ABORT,'dispatch failure lacks zero-handoff evidence'); END;
CREATE TRIGGER image_generation_job_cancellation_fact_guard BEFORE UPDATE OF state ON image_generation_jobs
WHEN NEW.state IN ('cancellation_requested','cancelled','completed_after_cancel') AND NOT EXISTS(
 SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=NEW.job_id)
BEGIN SELECT RAISE(ABORT,'image generation cancellation projection lacks fact'); END;
CREATE TRIGGER image_generation_slot_cancellation_fact_guard BEFORE UPDATE OF state ON image_generation_slots
WHEN NEW.state IN ('cancellation_requested','cancelled','late_quarantined','discarded') AND NOT EXISTS(
 SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=NEW.job_id AND c.cancellation_version=NEW.applied_cancellation_version)
BEGIN SELECT RAISE(ABORT,'image generation slot cancellation projection lacks fact'); END;
CREATE TRIGGER image_generation_job_transition_registry_sealed BEFORE INSERT ON image_generation_job_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;
CREATE TRIGGER image_generation_job_transition_registry_update_sealed BEFORE UPDATE ON image_generation_job_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;
CREATE TRIGGER image_generation_job_transition_registry_delete_sealed BEFORE DELETE ON image_generation_job_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;
CREATE TRIGGER image_generation_slot_transition_registry_sealed BEFORE INSERT ON image_generation_slot_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;
CREATE TRIGGER image_generation_slot_transition_registry_update_sealed BEFORE UPDATE ON image_generation_slot_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;
CREATE TRIGGER image_generation_slot_transition_registry_delete_sealed BEFORE DELETE ON image_generation_slot_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;
CREATE TRIGGER image_generation_attempt_transition_registry_sealed BEFORE INSERT ON image_generation_attempt_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;
CREATE TRIGGER image_generation_attempt_transition_registry_update_sealed BEFORE UPDATE ON image_generation_attempt_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;
CREATE TRIGGER image_generation_attempt_transition_registry_delete_sealed BEFORE DELETE ON image_generation_attempt_transitions BEGIN SELECT RAISE(ABORT,'image generation transition registry is sealed'); END;

CREATE TRIGGER image_generation_slot_cancellation_vector_insert BEFORE INSERT ON image_generation_slots
WHEN NEW.applied_cancellation_version IS NOT NULL AND NOT EXISTS(
  SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=NEW.job_id AND c.cancellation_version=NEW.applied_cancellation_version)
BEGIN SELECT RAISE(ABORT,'image generation slot cites unknown cancellation'); END;
CREATE TRIGGER image_generation_slot_cancellation_vector_update BEFORE UPDATE ON image_generation_slots
WHEN NEW.applied_cancellation_version IS NOT NULL AND NOT EXISTS(
  SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=NEW.job_id AND c.cancellation_version=NEW.applied_cancellation_version)
BEGIN SELECT RAISE(ABORT,'image generation slot cites unknown cancellation'); END;
CREATE TRIGGER image_generation_attempt_cancellation_vector_update BEFORE UPDATE ON image_generation_attempts
WHEN NEW.applied_cancellation_version IS NOT NULL AND NOT EXISTS(
  SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=NEW.job_id AND c.cancellation_version=NEW.applied_cancellation_version)
BEGIN SELECT RAISE(ABORT,'image generation attempt cites unknown cancellation'); END;
CREATE TRIGGER image_generation_cancelled_attempt_fact_guard AFTER UPDATE OF state ON image_generation_attempts
WHEN NEW.state='completed_after_cancel' AND NOT EXISTS(
  SELECT 1 FROM image_generation_cancelled_result_facts f WHERE f.job_id=NEW.job_id AND f.slot_id=NEW.slot_id AND f.attempt_number=NEW.attempt_number AND f.cancellation_version=NEW.applied_cancellation_version)
BEGIN SELECT RAISE(ABORT,'completed-after-cancel attempt lacks exact fact'); END;
CREATE TRIGGER image_generation_succeeded_attempt_fact_guard AFTER UPDATE OF state ON image_generation_attempts
WHEN NEW.state='succeeded' AND (NEW.applied_cancellation_version IS NOT NULL OR NOT EXISTS(
  SELECT 1 FROM image_generation_publication_right_facts f WHERE f.job_id=NEW.job_id AND f.slot_id=NEW.slot_id AND f.attempt_number=NEW.attempt_number))
BEGIN SELECT RAISE(ABORT,'succeeded attempt lacks ordinary publication right'); END;
CREATE TRIGGER image_generation_cancelled_result_ordering_guard BEFORE INSERT ON image_generation_cancelled_result_facts
WHEN NOT EXISTS(
 SELECT 1 FROM image_generation_attempts a JOIN external_journal_operations j ON j.operation_id=a.external_operation_id
 WHERE a.job_id=NEW.job_id AND a.slot_id=NEW.slot_id AND a.attempt_number=NEW.attempt_number
 AND j.version=NEW.journal_terminal_version
 AND ((NEW.ordering='response_after_cancellation' AND j.state='completed_after_cancel') OR (NEW.ordering='response_adopted_before_cancellation' AND j.state='succeeded')))
BEGIN SELECT RAISE(ABORT,'cancelled-result ordering lacks journal evidence'); END;
CREATE TRIGGER image_generation_publication_right_guard BEFORE INSERT ON image_generation_publication_right_facts
WHEN EXISTS(SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=NEW.job_id)
 OR NOT EXISTS(SELECT 1 FROM image_generation_attempts a JOIN image_generation_slots s ON s.job_id=a.job_id AND s.slot_id=a.slot_id
   WHERE a.job_id=NEW.job_id AND a.slot_id=NEW.slot_id AND a.attempt_number=NEW.attempt_number
   AND a.state='response_adopted' AND a.applied_cancellation_version IS NULL AND s.state='ready_to_publish'
   AND s.version=NEW.slot_version AND s.applied_cancellation_version IS NULL AND s.result_after_cancel=0)
BEGIN SELECT RAISE(ABORT,'ordinary publication right lost its compare-and-set'); END;

CREATE TRIGGER image_generation_plans_immutable
BEFORE UPDATE ON image_generation_plans BEGIN
  SELECT RAISE(ABORT, 'image generation plans are immutable');
END;
CREATE TRIGGER image_generation_cancellations_immutable
BEFORE UPDATE ON image_generation_cancellation_facts BEGIN
  SELECT RAISE(ABORT, 'image generation cancellation facts are immutable');
END;
CREATE TRIGGER image_generation_cancelled_results_immutable
BEFORE UPDATE ON image_generation_cancelled_result_facts BEGIN
  SELECT RAISE(ABORT, 'image generation cancelled-result facts are immutable');
END;
CREATE TRIGGER image_generation_publication_rights_immutable
BEFORE UPDATE ON image_generation_publication_right_facts BEGIN
  SELECT RAISE(ABORT, 'image generation publication-right facts are immutable');
END;
