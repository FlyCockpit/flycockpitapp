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
    name         TEXT    PRIMARY KEY CHECK (length(CAST(name AS BLOB)) BETWEEN 1 AND 255),
    -- Daemon-observed wall-clock time, signed Unix milliseconds.
    created_at_unix_ms INTEGER NOT NULL,
    home_dir     TEXT    NOT NULL CHECK (length(CAST(home_dir AS BLOB)) BETWEEN 1 AND 32768),
    config_json  TEXT    NOT NULL DEFAULT '{}' CHECK (
        json_valid(config_json) AND json_type(config_json) = 'object'
        AND length(CAST(config_json AS BLOB)) <= 1048576
    ),
    -- Historical column name retained inside the prerelease squash; values
    -- are HMAC-SHA-256 identities under the installation vault DEK, never
    -- unkeyed definition digests.
    content_hash TEXT    NOT NULL CHECK (
        length(content_hash) = 64
        AND content_hash = lower(content_hash)
        AND content_hash NOT GLOB '*[^0-9a-f]*'
    )
);

-- ---- per-assistant thread inbox ------------------------------------------

-- Structured upward communication from a persistent assistant thread to its
-- assistant's main session.  This is intentionally not a generic
-- thread-to-thread transport: both backlinks are durable and delivery is
-- claimed only by the resolved main session at a turn boundary.
CREATE TABLE assistant_inbox_items (
    inbox_item_id      TEXT PRIMARY KEY CHECK (
        length(inbox_item_id) = 36 AND inbox_item_id = lower(inbox_item_id)
        AND substr(inbox_item_id, 9, 1) = '-' AND substr(inbox_item_id, 14, 1) = '-'
        AND substr(inbox_item_id, 19, 1) = '-' AND substr(inbox_item_id, 24, 1) = '-'
        AND length(replace(inbox_item_id, '-', '')) = 32
        AND replace(inbox_item_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    assistant_name     TEXT NOT NULL REFERENCES assistants(name) ON DELETE CASCADE,
    main_session_id    TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    raising_session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    -- Daemon-owned inference/replay scope. Provider tool-call IDs are only
    -- idempotency correlations, not globally unique operation identities.
    operation_scope    TEXT NOT NULL CHECK (length(CAST(operation_scope AS BLOB)) BETWEEN 1 AND 128),
    operation_id       TEXT NOT NULL CHECK (length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 1024),
    summary            TEXT NOT NULL CHECK (length(CAST(summary AS BLOB)) BETWEEN 1 AND 4000),
    delivery           TEXT NOT NULL CHECK (delivery IN ('immediate', 'defer', 'notify')),
    created_at_unix_ms INTEGER NOT NULL,
    delivered_at_unix_ms INTEGER CHECK (delivered_at_unix_ms IS NULL OR delivered_at_unix_ms >= created_at_unix_ms),
    -- Human visibility is independent of agent delivery. A delivery can be
    -- consumed at a main-turn boundary while the item remains unread in the
    -- user's inbox; notify entries have no agent delivery at all.
    human_read_at_unix_ms INTEGER CHECK (human_read_at_unix_ms IS NULL OR human_read_at_unix_ms >= created_at_unix_ms),
    CHECK (main_session_id <> raising_session_id)
);
CREATE UNIQUE INDEX assistant_inbox_items_raise_operation_idx
    ON assistant_inbox_items(raising_session_id, operation_scope, operation_id);
CREATE INDEX assistant_inbox_items_main_pending_idx
    ON assistant_inbox_items(main_session_id, delivered_at_unix_ms, created_at_unix_ms);
CREATE INDEX assistant_inbox_items_main_unread_idx
    ON assistant_inbox_items(main_session_id, human_read_at_unix_ms, created_at_unix_ms);
CREATE INDEX assistant_inbox_items_assistant_rate_idx
    ON assistant_inbox_items(assistant_name, created_at_unix_ms);

-- ---- projects / sessions ---------------------------------------------------

-- Private durable identity for a project. `project_id` remains the host-facing
-- lookup key; security receipts bind this randomly assigned UUID's raw RFC
-- network-order bytes and never derive an identity by hashing the legacy key.
CREATE TABLE project_identities (
    project_id   TEXT PRIMARY KEY CHECK (length(CAST(project_id AS BLOB)) BETWEEN 1 AND 1024),
    project_uuid BLOB NOT NULL UNIQUE CHECK (
        typeof(project_uuid) = 'blob' AND length(project_uuid) = 16
        AND project_uuid <> zeroblob(16)
    ),
    created_at_unix_ms INTEGER NOT NULL
);

CREATE TABLE sessions (
    session_id      TEXT    PRIMARY KEY CHECK (
        length(session_id) = 36 AND session_id = lower(session_id)
        AND substr(session_id, 9, 1) = '-' AND substr(session_id, 14, 1) = '-'
        AND substr(session_id, 19, 1) = '-' AND substr(session_id, 24, 1) = '-'
        AND length(replace(session_id, '-', '')) = 32
        AND replace(session_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    project_id      TEXT    NOT NULL CHECK (length(CAST(project_id AS BLOB)) BETWEEN 1 AND 1024),
    project_root    TEXT    NOT NULL CHECK (length(CAST(project_root AS BLOB)) BETWEEN 1 AND 32768),
    -- Daemon-observed wall-clock times, signed Unix milliseconds.
    started_at_unix_ms      INTEGER NOT NULL,
    last_active_at_unix_ms  INTEGER NOT NULL CHECK (last_active_at_unix_ms >= started_at_unix_ms),
    ended_at_unix_ms        INTEGER CHECK (ended_at_unix_ms IS NULL OR ended_at_unix_ms >= started_at_unix_ms),
    -- [relationship:denormalized] Immutable-attribution display snapshots;
    -- provider/model registry changes never rewrite session history.
    provider        TEXT,
    model           TEXT,
    model_selection_json TEXT CHECK (
        model_selection_json IS NULL OR (
            json_valid(model_selection_json)
            AND json_type(model_selection_json) = 'object'
            AND length(CAST(model_selection_json AS BLOB)) <= 65536
        )
    ),
    -- Durable CAS token for active-model mutations (picker, recovery, controls).
    active_model_revision INTEGER NOT NULL DEFAULT 0 CHECK (active_model_revision >= 0),
    session_entry_mode TEXT NOT NULL DEFAULT 'code'
        CHECK (session_entry_mode IN ('code', 'assistant', 'computer')),
    tool_surface_override_json TEXT CHECK (
        tool_surface_override_json IS NULL OR (
            json_valid(tool_surface_override_json)
            AND json_type(tool_surface_override_json) = 'object'
            AND length(CAST(tool_surface_override_json AS BLOB)) <= 1048576
        )
    ),
    goal_settings_override_json TEXT CHECK (
        goal_settings_override_json IS NULL OR (
            json_valid(goal_settings_override_json)
            AND json_type(goal_settings_override_json) = 'object'
            AND length(CAST(goal_settings_override_json AS BLOB)) <= 65536
        )
    ),
    active_agent    TEXT    NOT NULL DEFAULT 'orchestrator-build',
    -- One-shot provenance for an installed root selected by a committed
    -- remote adapter operation but not yet consumed by profile preparation.
    -- NULL for local/legacy selection and after successful reconciliation.
    -- [relationship:denormalized] Pending agent label bound to active_agent;
    -- definition deletion does not erase interrupted-operation provenance.
    pending_remote_agent_selection TEXT CHECK (
        pending_remote_agent_selection IS NULL OR
        (
            pending_remote_agent_selection = active_agent AND
            length(CAST(pending_remote_agent_selection AS BLOB)) BETWEEN 1 AND 255
        )
    ),
    -- [relationship:denormalized] Historical assistant label. Assistant
    -- deletion is RESTRICT-free by design because sessions preserve history.
    assistant_name  TEXT,

    -- fork tree + auto-titling (GOALS §17). SQLite owns parent integrity
    -- and cascades deletion through the complete fork subtree.
    -- [relationship:foreign] parent_session_id owns the fork subtree.
    parent_session_id  TEXT,                     -- NULL = root
    -- [relationship:foreign] Optional historical event sequence in that exact
    -- parent session. NULL means the parent's durable tail at fork time.
    fork_point_turn_id TEXT,
    -- First-class assistant thread marker. A thread is a persistent,
    -- message-anchored child; ordinary forks and `/btw` children must never
    -- enter the assistant thread surface merely because they have a parent.
    is_assistant_thread INTEGER NOT NULL DEFAULT 0 CHECK (is_assistant_thread IN (0, 1)),
    title              TEXT,                     -- utility-model-generated label (§17d)
    description        TEXT CHECK (
        description IS NULL OR length(CAST(description AS BLOB)) BETWEEN 1 AND 4000
    ),                                            -- generated old-session context (§17d)
    -- A generated description is model-authored durable content. Preserve its
    -- exact source identity so history search can apply the same trust fence
    -- as it does to event-owned FTS rows. All provenance is absent together
    -- for sessions without a description; a description may never fail open
    -- through NULL trust.
    description_provider_id TEXT,
    description_model_id    TEXT,
    description_model_trust TEXT,
    user_renamed       INTEGER NOT NULL DEFAULT 0 CHECK (user_renamed IN (0, 1)), -- 1 = user set title; locks out auto-titling
    short_id           TEXT CHECK (
        short_id IS NULL OR (
            length(short_id) = 6
            AND short_id = lower(short_id)
            AND short_id NOT GLOB '*[^0123456789abcdefghjkmnpqrstvwxyz]*'
        )
    ),                     -- 6-char Crockford base32 display id

    -- read/unread + archive state for the session browser (GOALS §17f).
    -- A session is UNREAD when the latest agent-produced event is newer
    -- than last_viewed_at_unix_ms (NULL = never viewed). archived_at_unix_ms is a
    -- recoverable soft-delete; NULL = live. Archive cascades the fork
    -- subtree app-side (src/db/sessions.rs).
    last_viewed_at_unix_ms INTEGER,
    archived_at_unix_ms    INTEGER,

    -- Dream orchestrator/worker transcripts are retained for auditing, but
    -- are process noise: default history recall and future dream runs must
    -- never select them. Explicit session addressing remains available.
    is_dream_session INTEGER NOT NULL DEFAULT 0 CHECK (is_dream_session IN (0, 1)),

    -- live guidance-file diff injection: hash + path of the resolved
    -- agent-guidance body baked into this session's frozen system block,
    -- so a mid-session in-place edit is detected and injected as a
    -- trailing diff exactly once. Both NULL when no guidance file
    -- resolved at session start.
    guidance_baseline_hash TEXT CHECK (
        guidance_baseline_hash IS NULL OR (
            length(guidance_baseline_hash) = 64
            AND guidance_baseline_hash = lower(guidance_baseline_hash)
            AND guidance_baseline_hash NOT GLOB '*[^0-9a-f]*'
        )
    ),
    guidance_baseline_path TEXT CHECK (
        guidance_baseline_path IS NULL OR length(CAST(guidance_baseline_path AS BLOB)) BETWEEN 1 AND 32768
    ),

    -- Accumulated session egress redaction table. Stores literal redaction
    -- candidates so resumed raw transcripts remain covered even if the
    -- original env/dotenv source has changed or disappeared.
    redaction_table_json TEXT CHECK (
        redaction_table_json IS NULL OR (
            json_valid(redaction_table_json)
            AND json_type(redaction_table_json) IN ('array', 'object')
            AND length(CAST(redaction_table_json AS BLOB)) <= 8388608
        )
    ),

    -- Frozen model-specific system-prompt snapshot for this conversation
    -- lineage. JSON object keyed provider id -> model id -> prompt body.
    model_system_prompt_snapshot_json TEXT NOT NULL DEFAULT '{}' CHECK (
        json_valid(model_system_prompt_snapshot_json)
        AND json_type(model_system_prompt_snapshot_json) = 'object'
        AND length(CAST(model_system_prompt_snapshot_json AS BLOB)) <= 8388608
    ),

    -- Frozen knowledge-base identity and freshness snapshot for this
    -- conversation lineage. The daemon injects any later dream completion as
    -- history rather than rewriting this cached system-prompt prefix.
    knowledge_base_prompt_snapshot_json TEXT NOT NULL DEFAULT '{}' CHECK (
        json_valid(knowledge_base_prompt_snapshot_json)
        AND json_type(knowledge_base_prompt_snapshot_json) = 'object'
        AND length(CAST(knowledge_base_prompt_snapshot_json AS BLOB)) <= 8388608
    ),

    -- An empty snapshot is a valid completed capture. Keep its completion
    -- state separate so a row persisted before first-worker root binding is
    -- retried on resume rather than treated as an empty attachment set.
    knowledge_base_prompt_snapshot_captured INTEGER NOT NULL DEFAULT 0 CHECK (
        knowledge_base_prompt_snapshot_captured IN (0, 1)
    ),

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
    user_content_tokens INTEGER NOT NULL DEFAULT 0 CHECK (user_content_tokens >= 0),
    title_stage         INTEGER NOT NULL DEFAULT 0 CHECK (title_stage IN (0, 1, 2, 4, 8, 16)),
    -- Monotonic ownership fence for an in-flight same-model metadata fork.
    metadata_fork_generation INTEGER NOT NULL DEFAULT 0 CHECK (metadata_fork_generation >= 0),

    -- Durable one-shot post-auto-title-failure recovery nudge latch (issue
    -- #23): 0 = none, 1 = pending (a title attempt failed and a nudge is
    -- armed), 2 = consumed (the nudge was atomically claimed before
    -- main-model dispatch). Defaults `none`; never inherited by a
    -- fork/tangent/copy. Carries no title text, prompt, or provider body.
    title_recovery_nudge_state INTEGER NOT NULL DEFAULT 0
        CHECK (title_recovery_nudge_state IN (0, 1, 2)),

    -- remote principal attribution + collaborator sharing.
    created_by_principal TEXT,
    shared_with_collaborators INTEGER NOT NULL DEFAULT 0 CHECK (shared_with_collaborators IN (0, 1)),

    -- Deletion barrier lifecycle (cross-platform-descendant-process-containment).
    -- 'active' accepts work; 'deleting' rejects new work until every bound
    -- execution containment is ProvenEmpty, then the session row may drop.
    lifecycle TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'deleting')),

    CHECK (
        (description IS NULL
         AND description_provider_id IS NULL
         AND description_model_id IS NULL
         AND description_model_trust IS NULL)
        OR
        (description IS NOT NULL
         AND description_provider_id IS NOT NULL
         AND description_model_id IS NOT NULL
         AND description_model_trust IN ('trusted', 'untrusted'))
    ),
    CHECK (parent_session_id IS NULL OR parent_session_id <> session_id),
    CHECK (fork_point_turn_id IS NULL OR (
        parent_session_id IS NOT NULL
        AND length(fork_point_turn_id) > 0
        AND fork_point_turn_id NOT GLOB '*[^0-9]*'
        AND fork_point_turn_id = CAST(CAST(fork_point_turn_id AS INTEGER) AS TEXT)
    )),
    CHECK (is_assistant_thread = 0 OR (
        parent_session_id IS NOT NULL
        AND fork_point_turn_id IS NOT NULL
        AND ephemeral = 0
        AND btw_parent_session_id IS NULL
        AND assistant_name IS NOT NULL
        AND is_dream_session = 0
    )),
    CHECK (btw_parent_session_id IS NULL OR btw_parent_session_id <> session_id),
    CHECK ((guidance_baseline_path IS NULL) = (guidance_baseline_hash IS NULL)),
    CHECK (last_viewed_at_unix_ms IS NULL OR last_viewed_at_unix_ms >= started_at_unix_ms),
    CHECK (archived_at_unix_ms IS NULL OR archived_at_unix_ms >= started_at_unix_ms),
    FOREIGN KEY (parent_session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (parent_session_id, fork_point_turn_id)
        REFERENCES session_events(session_id, seq)
        ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (btw_parent_session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

-- Parent links form an acyclic ownership graph. The recursive UNION is also
-- cycle-safe if a pre-release database was externally corrupted before this
-- trigger existed; valid mutations fail before introducing another cycle.
CREATE TRIGGER sessions_parent_cycle_guard
BEFORE UPDATE OF parent_session_id, btw_parent_session_id ON sessions
WHEN EXISTS (
    WITH RECURSIVE ancestors(session_id) AS (
        SELECT NEW.parent_session_id WHERE NEW.parent_session_id IS NOT NULL
        UNION
        SELECT NEW.btw_parent_session_id WHERE NEW.btw_parent_session_id IS NOT NULL
        UNION
        SELECT s.parent_session_id FROM sessions s JOIN ancestors a ON s.session_id=a.session_id
          WHERE s.parent_session_id IS NOT NULL
        UNION
        SELECT s.btw_parent_session_id FROM sessions s JOIN ancestors a ON s.session_id=a.session_id
          WHERE s.btw_parent_session_id IS NOT NULL
    )
    SELECT 1 FROM ancestors WHERE session_id=NEW.session_id
)
BEGIN
    SELECT RAISE(ABORT, 'session parent cycle');
END;

-- INSERT needs the same graph guard. This matters for multi-row INSERTs: an
-- earlier row in the statement is visible to the trigger for a later row, so
-- cycles assembled inside one statement are rejected before commit.
CREATE TRIGGER sessions_parent_cycle_guard_insert
BEFORE INSERT ON sessions
WHEN EXISTS (
    WITH RECURSIVE ancestors(session_id) AS (
        SELECT NEW.parent_session_id WHERE NEW.parent_session_id IS NOT NULL
        UNION
        SELECT NEW.btw_parent_session_id WHERE NEW.btw_parent_session_id IS NOT NULL
        UNION
        SELECT s.parent_session_id FROM sessions s JOIN ancestors a ON s.session_id=a.session_id
          WHERE s.parent_session_id IS NOT NULL
        UNION
        SELECT s.btw_parent_session_id FROM sessions s JOIN ancestors a ON s.session_id=a.session_id
          WHERE s.btw_parent_session_id IS NOT NULL
    )
    SELECT 1 FROM ancestors WHERE session_id=NEW.session_id
)
BEGIN
    SELECT RAISE(ABORT, 'session parent cycle');
END;

-- ---- typed media attachments ----------------------------------------------
-- Full-range monotonic values are canonical decimal text because SQLite's
-- INTEGER is signed i64. Application codecs reject zero, leading zeroes and
-- values outside u64 before any mutation.
CREATE TABLE media_attachments (
    attachment_id                  TEXT PRIMARY KEY CHECK (
        length(attachment_id) = 36 AND attachment_id = lower(attachment_id)
        AND substr(attachment_id, 9, 1) = '-' AND substr(attachment_id, 14, 1) = '-'
        AND substr(attachment_id, 19, 1) = '-' AND substr(attachment_id, 24, 1) = '-'
        AND length(replace(attachment_id, '-', '')) = 32
        AND replace(attachment_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
    session_id                     TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    canonical_project_digest       TEXT NOT NULL,
    media_kind                     TEXT NOT NULL CHECK (media_kind IN ('image', 'audio', 'video')),
    source_kind                    TEXT NOT NULL CHECK (source_kind IN ('local_path', 'retained_https', 'authenticated_session_upload', 'tool_admitted_source', 'tool_derivative')),
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
    selected_video_stream_json     TEXT CHECK (selected_video_stream_json IS NULL OR (
        json_valid(selected_video_stream_json)
        AND json_type(selected_video_stream_json) = 'array'
        AND json_array_length(selected_video_stream_json) = 2
        AND json_type(selected_video_stream_json, '$[0]') = 'integer'
        AND json_extract(selected_video_stream_json, '$[0]') BETWEEN 0 AND 4294967295
        AND json_type(selected_video_stream_json, '$[1]') = 'text'
        AND length(CAST(json_extract(selected_video_stream_json, '$[1]') AS BLOB)) BETWEEN 1 AND 255
        AND length(CAST(selected_video_stream_json AS BLOB)) <= 65536
    )),
    selected_audio_stream_json     TEXT CHECK (selected_audio_stream_json IS NULL OR (
        json_valid(selected_audio_stream_json)
        AND json_type(selected_audio_stream_json) = 'array'
        AND json_array_length(selected_audio_stream_json) = 2
        AND json_type(selected_audio_stream_json, '$[0]') = 'integer'
        AND json_extract(selected_audio_stream_json, '$[0]') BETWEEN 0 AND 4294967295
        AND json_type(selected_audio_stream_json, '$[1]') = 'text'
        AND length(CAST(json_extract(selected_audio_stream_json, '$[1]') AS BLOB)) BETWEEN 1 AND 255
        AND length(CAST(selected_audio_stream_json AS BLOB)) <= 65536
    )),
    -- Daemon-observed wall-clock times, signed Unix milliseconds.
    created_at_unix_ms             INTEGER NOT NULL,
    updated_at_unix_ms             INTEGER NOT NULL,
    draft_expires_at_unix_ms       INTEGER,
    first_referenced_at_unix_ms    INTEGER,
    UNIQUE (attachment_id, attachment_version),
    CHECK (length(canonical_project_digest) = 64 AND canonical_project_digest = lower(canonical_project_digest) AND canonical_project_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(source_identity_digest) = 64 AND source_identity_digest = lower(source_identity_digest) AND source_identity_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(source_sha256) = 64 AND source_sha256 = lower(source_sha256) AND source_sha256 NOT GLOB '*[^0-9a-f]*'),
    CHECK (attachment_version NOT GLOB '*[^0-9]*' AND attachment_version GLOB '[1-9]*'),
    CHECK (availability_generation NOT GLOB '*[^0-9]*' AND availability_generation GLOB '[1-9]*'),
    CHECK (reference_generation NOT GLOB '*[^0-9]*' AND reference_generation GLOB '[1-9]*'),
    CHECK (captured_capability_generation NOT GLOB '*[^0-9]*' AND captured_capability_generation GLOB '[1-9]*'),
    CHECK (source_byte_length NOT GLOB '*[^0-9]*' AND source_byte_length GLOB '[1-9]*'),
    CHECK (updated_at_unix_ms >= created_at_unix_ms),
    CHECK (draft_expires_at_unix_ms IS NULL OR draft_expires_at_unix_ms >= created_at_unix_ms),
    CHECK (first_referenced_at_unix_ms IS NULL OR first_referenced_at_unix_ms >= created_at_unix_ms),
    CHECK ((source_kind = 'authenticated_session_upload') OR draft_expires_at_unix_ms IS NULL)
);

CREATE INDEX idx_media_attachments_session
    ON media_attachments(session_id, created_at_unix_ms, attachment_id);
CREATE INDEX idx_media_attachments_cleanup
    ON media_attachments(availability, draft_expires_at_unix_ms);

CREATE TABLE media_attachment_failure_reasons (
    attachment_id TEXT PRIMARY KEY REFERENCES media_attachments(attachment_id) ON DELETE CASCADE ON UPDATE RESTRICT,
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
    component_id          TEXT PRIMARY KEY CHECK (
        length(component_id) = 36 AND component_id = lower(component_id)
        AND substr(component_id, 9, 1) = '-' AND substr(component_id, 14, 1) = '-'
        AND substr(component_id, 19, 1) = '-' AND substr(component_id, 24, 1) = '-'
        AND length(replace(component_id, '-', '')) = 32
        AND replace(component_id, '-', '') NOT GLOB '*[^0-9a-f]*'
    ),
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
    CHECK (length(stable_identity_digest) = 64 AND stable_identity_digest = lower(stable_identity_digest) AND stable_identity_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(sha256) = 64 AND sha256 = lower(sha256) AND sha256 NOT GLOB '*[^0-9a-f]*'),
    CHECK (deletion_evidence_digest IS NULL OR (length(deletion_evidence_digest) = 64 AND deletion_evidence_digest = lower(deletion_evidence_digest) AND deletion_evidence_digest NOT GLOB '*[^0-9a-f]*')),
    CHECK (component_generation NOT GLOB '*[^0-9]*' AND component_generation GLOB '[1-9]*'),
    CHECK (byte_length NOT GLOB '*[^0-9]*' AND byte_length GLOB '[1-9]*'),
    CHECK (updated_at_unix_ms >= created_at_unix_ms),
    FOREIGN KEY (attachment_id, attachment_version)
        REFERENCES media_attachments(attachment_id, attachment_version) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE INDEX idx_media_attachment_components_attachment
    ON media_attachment_components(attachment_id, component_id);

CREATE TABLE media_image_component_dimensions (
    component_id TEXT PRIMARY KEY REFERENCES media_attachment_components(component_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    width INTEGER NOT NULL CHECK(width > 0 AND width <= 8192),
    height INTEGER NOT NULL CHECK(height > 0 AND height <= 8192)
);

CREATE TABLE media_attachment_transition_evidence (
    attachment_id TEXT NOT NULL REFERENCES media_attachments(attachment_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    availability_generation TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    committed_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY(attachment_id, availability_generation)
);

CREATE TABLE media_av_normalization_evidence (
    attachment_id TEXT PRIMARY KEY REFERENCES media_attachments(attachment_id) ON DELETE CASCADE ON UPDATE RESTRICT,
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
    upload_id TEXT PRIMARY KEY REFERENCES media_uploads(upload_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    temporary_storage_id TEXT NOT NULL,
    quarantine_storage_id TEXT NOT NULL,
    derivative_storage_ids_json TEXT NOT NULL CHECK (
        json_valid(derivative_storage_ids_json)
        AND json_type(derivative_storage_ids_json) = 'array'
        AND json(derivative_storage_ids_json) = derivative_storage_ids_json
        AND length(CAST(derivative_storage_ids_json AS BLOB)) <= 1048576
    ),
    created_at_unix_ms INTEGER NOT NULL
);

CREATE TRIGGER media_storage_publication_derivative_ids_insert
BEFORE INSERT ON media_storage_publication_intents
WHEN EXISTS (
    SELECT 1 FROM json_each(NEW.derivative_storage_ids_json)
    WHERE type <> 'text' OR length(value) <> 36 OR value <> lower(value)
       OR substr(value, 9, 1) <> '-' OR substr(value, 14, 1) <> '-'
       OR substr(value, 19, 1) <> '-' OR substr(value, 24, 1) <> '-'
       OR length(replace(value, '-', '')) <> 32
       OR replace(value, '-', '') GLOB '*[^0-9a-f]*'
)
BEGIN
    SELECT RAISE(ABORT, 'media derivative storage ids must be canonical UUIDs');
END;

CREATE TRIGGER media_storage_publication_derivative_ids_update
BEFORE UPDATE OF derivative_storage_ids_json ON media_storage_publication_intents
WHEN EXISTS (
    SELECT 1 FROM json_each(NEW.derivative_storage_ids_json)
    WHERE type <> 'text' OR length(value) <> 36 OR value <> lower(value)
       OR substr(value, 9, 1) <> '-' OR substr(value, 14, 1) <> '-'
       OR substr(value, 19, 1) <> '-' OR substr(value, 24, 1) <> '-'
       OR length(replace(value, '-', '')) <> 32
       OR replace(value, '-', '') GLOB '*[^0-9a-f]*'
)
BEGIN
    SELECT RAISE(ABORT, 'media derivative storage ids must be canonical UUIDs');
END;

-- Crash fence for daemon-owned clipboard/private-terminal ingress. The
-- opaque admission id is the client idempotency identity; the retained
-- object is not visible until its attachment row and reservation publication
-- commit atomically and this intent is removed.
CREATE TABLE media_ingress_publication_intents (
    admission_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    reservation_id TEXT NOT NULL UNIQUE REFERENCES media_reservations(reservation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    storage_id TEXT NOT NULL UNIQUE,
    source_sha256 TEXT NOT NULL,
    request_source_digest TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL,
    CHECK (length(admission_id) = 36),
    CHECK (length(source_sha256) = 64 AND source_sha256 NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(request_source_digest) = 64 AND request_source_digest NOT GLOB '*[^0-9a-f]*')
);

CREATE TABLE media_ingress_admission_receipts (
    admission_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    attachment_id TEXT NOT NULL UNIQUE REFERENCES media_attachments(attachment_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    attachment_version TEXT NOT NULL,
    availability_generation TEXT NOT NULL,
    reservation_id TEXT NOT NULL UNIQUE REFERENCES media_reservations(reservation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    normalized_sha256 TEXT NOT NULL,
    request_source_digest TEXT NOT NULL,
    normalized_byte_length TEXT NOT NULL,
    width INTEGER NOT NULL,
    height INTEGER NOT NULL,
    committed_at_unix_ms INTEGER NOT NULL,
    CHECK (length(admission_id) = 36),
    CHECK (CAST(attachment_version AS INTEGER) > 0),
    CHECK (CAST(availability_generation AS INTEGER) > 0),
    CHECK (length(normalized_sha256) = 64 AND normalized_sha256 NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(request_source_digest) = 64 AND request_source_digest NOT GLOB '*[^0-9a-f]*'),
    CHECK (CAST(normalized_byte_length AS INTEGER) > 0),
    CHECK (width > 0 AND height > 0)
);

CREATE INDEX idx_media_ingress_publication_intents_session
    ON media_ingress_publication_intents(session_id);
CREATE INDEX idx_media_ingress_admission_receipts_session
    ON media_ingress_admission_receipts(session_id);

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
        REFERENCES media_attachments(attachment_id, attachment_version) ON DELETE CASCADE ON UPDATE RESTRICT
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
    component_id                   TEXT NOT NULL REFERENCES media_attachment_components(component_id) ON DELETE CASCADE ON UPDATE RESTRICT,
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
        REFERENCES media_attachments(attachment_id, attachment_version) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE UNIQUE INDEX idx_media_attachment_component_leases_live_id
    ON media_attachment_component_leases(lease_id)
    WHERE released_at_unix_ms IS NULL;
CREATE INDEX idx_media_attachment_component_leases_live_attachment
    ON media_attachment_component_leases(attachment_id, attachment_version, released_at_unix_ms);

CREATE TABLE media_component_lease_reconciliation_evidence (
    lease_id TEXT PRIMARY KEY REFERENCES media_attachment_component_leases(lease_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    reason TEXT NOT NULL CHECK(reason = 'daemon_restart'),
    released_at_unix_ms INTEGER NOT NULL
);

CREATE TABLE media_component_security_evidence (
    lease_id TEXT PRIMARY KEY REFERENCES media_attachment_component_leases(lease_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    attachment_id TEXT NOT NULL,
    component_id TEXT NOT NULL,
    reason TEXT NOT NULL CHECK(reason = 'storage_security_violation'),
    recorded_at_unix_ms INTEGER NOT NULL,
    FOREIGN KEY (attachment_id) REFERENCES media_attachments(attachment_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (component_id) REFERENCES media_attachment_components(component_id) ON DELETE CASCADE ON UPDATE RESTRICT
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
        REFERENCES media_attachments(attachment_id, attachment_version) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE media_component_deletion_intents (
    component_id TEXT PRIMARY KEY REFERENCES media_attachment_components(component_id) ON DELETE CASCADE ON UPDATE RESTRICT,
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
        REFERENCES media_attachments(attachment_id, attachment_version) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE media_local_path_registration_operations (
    local_operation_id       TEXT PRIMARY KEY,
    authoritative_operation_id TEXT NOT NULL,
    session_id               TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
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
    FOREIGN KEY (attachment_id) REFERENCES media_attachments(attachment_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE media_local_path_registration_audit (
    local_operation_id TEXT PRIMARY KEY,
    outcome            TEXT NOT NULL,
    committed_at_unix_ms INTEGER NOT NULL
);

CREATE TABLE media_retained_https_operations (
    local_operation_id         TEXT PRIMARY KEY,
    authoritative_operation_id TEXT NOT NULL,
    session_id                 TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
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
    FOREIGN KEY (attachment_id) REFERENCES media_attachments(attachment_id) ON DELETE CASCADE ON UPDATE RESTRICT
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
    FOREIGN KEY (attachment_id) REFERENCES media_attachments(attachment_id) ON DELETE CASCADE ON UPDATE RESTRICT
);
CREATE TABLE media_attachment_processing_security_evidence (
    job_id             TEXT PRIMARY KEY REFERENCES media_attachment_processing_jobs(job_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    attachment_id      TEXT NOT NULL,
    component_id       TEXT NOT NULL,
    reason             TEXT NOT NULL CHECK(reason = 'storage_security_violation'),
    recorded_at_unix_ms INTEGER NOT NULL,
    FOREIGN KEY (attachment_id) REFERENCES media_attachments(attachment_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (component_id) REFERENCES media_attachment_components(component_id) ON DELETE CASCADE ON UPDATE RESTRICT
);
CREATE TABLE media_attachment_processing_publication_intents (
    job_id          TEXT PRIMARY KEY REFERENCES media_attachment_processing_jobs(job_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    output_ids_json TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL
);
CREATE TABLE media_attachment_processing_cleanup_evidence (
    job_id          TEXT PRIMARY KEY REFERENCES media_attachment_processing_jobs(job_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    evidence_digest TEXT NOT NULL,
    completed_at_unix_ms INTEGER NOT NULL,
    CHECK (length(evidence_digest)=64 AND evidence_digest NOT GLOB '*[^0-9a-f]*')
);
-- Crash fence for direct-native tool media objects. The row is committed
-- before any object is created and removed only by the attachment publication
-- transaction or a writer-locked recovery claim. Reconciliation may unlink
-- listed objects only while this row is still live on the writer connection.
CREATE TABLE media_tool_publication_intents (
    attachment_id TEXT PRIMARY KEY,
    reservation_id TEXT NOT NULL UNIQUE REFERENCES media_reservations(reservation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    storage_ids_json TEXT NOT NULL CHECK (
        json_valid(storage_ids_json)
        AND json_type(storage_ids_json) = 'array'
        AND json(storage_ids_json) = storage_ids_json
    ),
    created_at_unix_ms INTEGER NOT NULL
);
CREATE TABLE media_attachment_processing_failure_evidence (
    job_id TEXT PRIMARY KEY REFERENCES media_attachment_processing_jobs(job_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    attachment_id TEXT NOT NULL,
    reason TEXT NOT NULL CHECK(reason IN ('processing_failed','model_runtime_unavailable')),
    recorded_at_unix_ms INTEGER NOT NULL,
    FOREIGN KEY (attachment_id) REFERENCES media_attachments(attachment_id) ON DELETE CASCADE ON UPDATE RESTRICT
);
CREATE TABLE media_attachment_processing_output_security_evidence (
    job_id TEXT PRIMARY KEY REFERENCES media_attachment_processing_jobs(job_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    attachment_id TEXT NOT NULL,
    output_ids_json TEXT NOT NULL,
    reason TEXT NOT NULL CHECK(reason='storage_security_violation'),
    recorded_at_unix_ms INTEGER NOT NULL,
    FOREIGN KEY (attachment_id) REFERENCES media_attachments(attachment_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE media_uploads (
    upload_id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT, canonical_project_digest TEXT NOT NULL,
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
    PRIMARY KEY(upload_id,chunk_index), FOREIGN KEY(upload_id) REFERENCES media_uploads(upload_id) ON DELETE CASCADE ON UPDATE RESTRICT,
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
    FOREIGN KEY(attachment_id) REFERENCES media_attachments(attachment_id) ON DELETE CASCADE ON UPDATE RESTRICT
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
    external_operation_id TEXT UNIQUE REFERENCES external_journal_operations(operation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    quarantined INTEGER NOT NULL DEFAULT 0 CHECK(quarantined IN (0,1)),
    published INTEGER NOT NULL DEFAULT 0 CHECK(published IN (0,1)),
    cancellation_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancellation_requested IN (0,1))
);
CREATE INDEX idx_media_reservation_owner_purpose ON media_reservations(project_id, owner_session_key, purpose, state);
-- Backstop for ReservationState::allows. Same-state no-ops are rejected;
-- dispatching_external cannot return to executing_local.
CREATE TRIGGER media_reservation_state_graph BEFORE UPDATE OF state ON media_reservations
WHEN (OLD.state || '>' || NEW.state) NOT IN (
    'reserved_queued>executing_local',
    'reserved_queued>dispatching_external',
    'reserved_queued>cancellation_requested',
    'reserved_queued>settling',
    'executing_local>dispatching_external',
    'executing_local>cancellation_requested',
    'executing_local>settling',
    'executing_local>overage_quarantined',
    'executing_local>accounting_corrupt',
    'dispatching_external>external_pending',
    'dispatching_external>cancellation_requested',
    'dispatching_external>settling',
    'dispatching_external>overage_quarantined',
    'dispatching_external>accounting_corrupt',
    'external_pending>reconciling_external',
    'external_pending>cancellation_requested',
    'external_pending>settling',
    'external_pending>overage_quarantined',
    'external_pending>accounting_corrupt',
    'reconciling_external>external_pending',
    'reconciling_external>cancellation_requested',
    'reconciling_external>settling',
    'reconciling_external>overage_quarantined',
    'reconciling_external>accounting_corrupt',
    'cancellation_requested>external_pending',
    'cancellation_requested>reconciling_external',
    'cancellation_requested>settling',
    'cancellation_requested>overage_quarantined',
    'cancellation_requested>accounting_corrupt',
    'overage_quarantined>settling',
    'overage_quarantined>accounting_corrupt',
    'settling>released',
    'settling>overage_quarantined',
    'settling>accounting_corrupt'
)
BEGIN SELECT RAISE(ABORT, 'illegal media reservation state transition'); END;
CREATE TABLE media_reservation_plan_facts (
    reservation_id TEXT NOT NULL REFERENCES media_reservations(reservation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    dimension TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    PRIMARY KEY(reservation_id, dimension)
);
CREATE TRIGGER media_plan_fact_immutable_update BEFORE UPDATE ON media_reservation_plan_facts BEGIN SELECT RAISE(ABORT,'media plan facts are immutable'); END;
CREATE TRIGGER media_plan_fact_immutable_delete BEFORE DELETE ON media_reservation_plan_facts BEGIN SELECT RAISE(ABORT,'media plan facts are immutable'); END;
CREATE TABLE media_reservation_versions (
    reservation_id TEXT NOT NULL REFERENCES media_reservations(reservation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
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
    reservation_id TEXT PRIMARY KEY REFERENCES media_reservations(reservation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    ready_wall_ms INTEGER NOT NULL
);
CREATE TABLE media_reservation_deltas (
    delta_id INTEGER PRIMARY KEY AUTOINCREMENT,
    reservation_id TEXT NOT NULL REFERENCES media_reservations(reservation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
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
    artifact_id TEXT PRIMARY KEY, reservation_id TEXT NOT NULL REFERENCES media_reservations(reservation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    dimension TEXT NOT NULL, byte_count INTEGER NOT NULL CHECK(byte_count >= 0), checksum TEXT NOT NULL,
    quarantined INTEGER NOT NULL CHECK(quarantined IN (0,1)), deletion_tombstone_checksum TEXT
);
CREATE TRIGGER media_artifact_immutable_delete BEFORE DELETE ON media_artifact_facts BEGIN SELECT RAISE(ABORT,'media artifact facts are immutable'); END;
CREATE TRIGGER media_artifact_immutable_update BEFORE UPDATE ON media_artifact_facts
WHEN NEW.artifact_id!=OLD.artifact_id OR NEW.reservation_id!=OLD.reservation_id OR NEW.dimension!=OLD.dimension OR NEW.byte_count!=OLD.byte_count OR NEW.checksum!=OLD.checksum OR NEW.quarantined!=OLD.quarantined OR OLD.deletion_tombstone_checksum IS NOT NULL OR NEW.deletion_tombstone_checksum IS NULL
BEGIN SELECT RAISE(ABORT,'media artifact facts are immutable'); END;
CREATE TABLE media_cleanup_attestations (
    reservation_id TEXT NOT NULL REFERENCES media_reservations(reservation_id) ON DELETE RESTRICT ON UPDATE RESTRICT, dimension TEXT NOT NULL,
    attestation_kind TEXT NOT NULL CHECK(attestation_kind='zero_materialized_or_verified_cleaned'),
    checksum TEXT NOT NULL, created_wall_ms INTEGER NOT NULL, PRIMARY KEY(reservation_id,dimension)
);
CREATE TRIGGER media_cleanup_attestation_immutable_update BEFORE UPDATE ON media_cleanup_attestations BEGIN SELECT RAISE(ABORT,'media cleanup attestations are immutable'); END;
CREATE TRIGGER media_cleanup_attestation_immutable_delete BEFORE DELETE ON media_cleanup_attestations BEGIN SELECT RAISE(ABORT,'media cleanup attestations are immutable'); END;
CREATE TABLE media_accounting_corruption_facts (
    reservation_id TEXT NOT NULL REFERENCES media_reservations(reservation_id) ON DELETE RESTRICT ON UPDATE RESTRICT, reservation_version INTEGER NOT NULL CHECK(reservation_version >= 1),
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
    attempt_id TEXT NOT NULL REFERENCES media_repair_attempts(attempt_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    dimension TEXT NOT NULL, charged INTEGER NOT NULL CHECK(charged >= 0), PRIMARY KEY(attempt_id, dimension)
);
CREATE TABLE media_downstream_ownership (
    reservation_id TEXT PRIMARY KEY REFERENCES media_reservations(reservation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    invocation_id TEXT NOT NULL,
    bound_wall_ms INTEGER NOT NULL,
    released_wall_ms INTEGER
);
CREATE INDEX idx_media_downstream_invocation ON media_downstream_ownership(invocation_id);

CREATE INDEX idx_sessions_project_started ON sessions (project_id, started_at_unix_ms DESC);
CREATE INDEX idx_sessions_last_active     ON sessions (last_active_at_unix_ms DESC);
CREATE INDEX idx_sessions_open
    ON sessions (ephemeral, last_active_at_unix_ms DESC)
    WHERE ended_at_unix_ms IS NULL;
CREATE INDEX idx_sessions_parent_fork_point ON sessions(parent_session_id, fork_point_turn_id);
CREATE INDEX idx_sessions_parent_started ON sessions (parent_session_id, started_at_unix_ms DESC);
CREATE INDEX idx_sessions_parent          ON sessions (parent_session_id);
-- Partial so rows whose short_id is still NULL (lazily backfilled on next
-- touch by src/db/sessions.rs) don't trip the uniqueness constraint.
CREATE UNIQUE INDEX idx_sessions_short_id_project
    ON sessions (project_id, short_id)
    WHERE short_id IS NOT NULL;
CREATE INDEX idx_sessions_archived  ON sessions (archived_at_unix_ms);
CREATE INDEX idx_sessions_ephemeral ON sessions (ephemeral);
CREATE INDEX idx_sessions_btw_parent ON sessions (btw_parent_session_id);
CREATE UNIQUE INDEX idx_sessions_one_live_btw
    ON sessions (btw_parent_session_id)
    WHERE btw_parent_session_id IS NOT NULL;
CREATE INDEX idx_sessions_created_by_principal ON sessions (created_by_principal);
CREATE INDEX idx_sessions_shared_project ON sessions (project_root, shared_with_collaborators)
  WHERE shared_with_collaborators = 1;
CREATE INDEX idx_sessions_assistant ON sessions (assistant_name, last_active_at_unix_ms DESC)
  WHERE assistant_name IS NOT NULL;
CREATE INDEX idx_sessions_assistant_threads
    ON sessions (assistant_name, project_id, last_active_at_unix_ms DESC)
    WHERE is_assistant_thread = 1
      AND ephemeral = 0
      AND archived_at_unix_ms IS NULL
      AND is_dream_session = 0;

-- ---- knowledge dream scope + completion ledger ----------------------------
-- Attachment is the explicit consent boundary for cross-session dream reads.
-- KB definitions remain configuration-owned, so kb_id intentionally has no
-- foreign key to a duplicated SQLite registry.
CREATE TABLE knowledge_base_session_attachments (
    kb_id       TEXT NOT NULL CHECK (length(CAST(kb_id AS BLOB)) BETWEEN 1 AND 255),
    project_root TEXT NOT NULL CHECK (length(CAST(project_root AS BLOB)) BETWEEN 1 AND 32768),
    session_id  TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    attached_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (kb_id, project_root, session_id)
);
CREATE INDEX idx_kb_session_attachments_session
    ON knowledge_base_session_attachments(session_id, project_root, kb_id);

-- Immutable completion facts. consumer_id is the local installation identity
-- today and is reserved for hosted MCP-token consumers without a schema change.
CREATE TABLE knowledge_dreamed_sessions (
    kb_id       TEXT NOT NULL CHECK (length(CAST(kb_id AS BLOB)) BETWEEN 1 AND 255),
    project_root TEXT NOT NULL CHECK (length(CAST(project_root AS BLOB)) BETWEEN 1 AND 32768),
    consumer_id TEXT NOT NULL CHECK (length(CAST(consumer_id AS BLOB)) BETWEEN 1 AND 255),
    session_id  TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    dreamed_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (kb_id, project_root, consumer_id, session_id)
);
CREATE INDEX idx_knowledge_dreamed_sessions_last
    ON knowledge_dreamed_sessions(kb_id, project_root, consumer_id, dreamed_at_unix_ms DESC);

-- Monotonic identity for successful dream completions. Wall-clock time is
-- presentation only: completion_revision advances even when the clock repeats
-- or moves backwards, so a live session can never miss a later completion.
CREATE TABLE knowledge_dream_completion_state (
    kb_id                 TEXT NOT NULL CHECK (length(CAST(kb_id AS BLOB)) BETWEEN 1 AND 255),
    project_root          TEXT NOT NULL CHECK (length(CAST(project_root AS BLOB)) BETWEEN 1 AND 32768),
    consumer_id           TEXT NOT NULL CHECK (length(CAST(consumer_id AS BLOB)) BETWEEN 1 AND 255),
    completion_revision   INTEGER NOT NULL CHECK (completion_revision > 0),
    completed_at_unix_ms  INTEGER NOT NULL,
    PRIMARY KEY (kb_id, project_root, consumer_id)
);

-- Per-machine daemon dream scheduler state.  The completion ledger above is
-- immutable evidence about individual source sessions; this row records the
-- daemon's schedule cursor and also makes an empty scheduled fire visible to
-- users as a successful check.
CREATE TABLE knowledge_dream_schedule_state (
    kb_id                       TEXT NOT NULL CHECK (length(CAST(kb_id AS BLOB)) BETWEEN 1 AND 255),
    project_root                TEXT NOT NULL CHECK (length(CAST(project_root AS BLOB)) BETWEEN 1 AND 32768),
    consumer_id                 TEXT NOT NULL CHECK (length(CAST(consumer_id AS BLOB)) BETWEEN 1 AND 255),
    last_scheduled_at_unix_ms   INTEGER NOT NULL,
    last_dreamed_at_unix_ms     INTEGER,
    PRIMARY KEY (kb_id, project_root, consumer_id)
);
CREATE INDEX idx_knowledge_dream_schedule_state_last
    ON knowledge_dream_schedule_state(kb_id, project_root, consumer_id, last_scheduled_at_unix_ms DESC);

-- One monotonic freshness boundary per concrete KB attachment. The attachment
-- UUID, rather than the mutable registry id, prevents a replacement source
-- from inheriting the predecessor's dream state.
CREATE TABLE knowledge_dream_ledger (
    project_uuid BLOB NOT NULL UNIQUE CHECK (
        typeof(project_uuid) = 'blob' AND length(project_uuid) = 16
        AND project_uuid <> zeroblob(16)
    ) REFERENCES project_identities(project_uuid) ON DELETE CASCADE ON UPDATE RESTRICT,
    knowledge_base_attachment_id BLOB NOT NULL CHECK (
        typeof(knowledge_base_attachment_id) = 'blob'
        AND length(knowledge_base_attachment_id) = 16
        AND knowledge_base_attachment_id <> zeroblob(16)
    ),
    last_dreamed_session_event_seq INTEGER NOT NULL CHECK (last_dreamed_session_event_seq >= 0),
    updated_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (project_uuid, knowledge_base_attachment_id)
);

-- ---- sealed_values ---------------------------------------------------------
-- Session-owned write-only values. The literal column is nullable so a vault
-- item can replace the plaintext without a rebuild dance.
CREATE TABLE sealed_values (
    session_id TEXT NOT NULL,
    source_key TEXT CHECK (
        source_key IS NULL OR length(CAST(source_key AS BLOB)) BETWEEN 1 AND 128
    ),
    value_id   TEXT NOT NULL,
    value      TEXT,
    reason     TEXT NOT NULL,
    origin     TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (session_id, value_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
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

-- Durable daemon-owned work left after a session's relational deletion has
-- committed but its fenced directory could not yet be unlinked. The path is
-- an opaque staging pathname produced by the storage daemon, never UI input.
CREATE TABLE storage_directory_cleanup_intents (
    staged_path TEXT PRIMARY KEY,
    created_at_unix_ms INTEGER NOT NULL
);

-- ---- tool_call_events (GOALS §15b) ----------------------------------------

CREATE TABLE tool_call_events (
    event_id            TEXT    PRIMARY KEY,
    session_id          TEXT    NOT NULL,
    call_id             TEXT    NOT NULL,
    -- [relationship:foreign] Same-session parent tool call attribution.
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

    -- tool-call mining across versions: CARGO_PKG_VERSION at call time.
    cockpit_version     TEXT    DEFAULT NULL,

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
    -- [relationship:external] Provider-owned opaque wire identifiers, not
    -- local registry keys and therefore intentionally not foreign keys.
    provider_item_id        TEXT DEFAULT NULL,
    provider_call_id        TEXT DEFAULT NULL,
    provider_call_id_source TEXT DEFAULT NULL,
    wire_api                TEXT DEFAULT NULL,
    provider_family         TEXT DEFAULT NULL,

    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (session_id, parent_call_id)
        REFERENCES tool_call_events(session_id, call_id)
        ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE INDEX idx_tce_session_ts ON tool_call_events (session_id, timestamp);
CREATE INDEX idx_tce_project_ts ON tool_call_events (project_id, timestamp);
CREATE INDEX idx_tce_model_ts   ON tool_call_events (model, timestamp);
CREATE INDEX idx_tce_tool_ts    ON tool_call_events (tool, timestamp);
CREATE INDEX idx_tce_lang_ts    ON tool_call_events (language, timestamp);
CREATE UNIQUE INDEX uq_tce_session_call ON tool_call_events(session_id, call_id);
CREATE INDEX idx_tce_parent     ON tool_call_events (session_id, parent_call_id);

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

    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
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
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE INDEX idx_lock_state_session ON lock_state (session_id);

CREATE TABLE lock_reads (
    session_id  TEXT    NOT NULL,
    agent_id    TEXT    NOT NULL,
    path        TEXT    NOT NULL,
    read_at     INTEGER NOT NULL,
    read_hash   INTEGER,
    PRIMARY KEY (session_id, agent_id, path),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

-- ---- needs_attention (GOALS §3b) --------------------------------------------
-- The `question` tool raises one interrupt carrying an ARRAY of questions
-- (tool dispatch is sequential, so everything the agent needs has to ride
-- in a single call). `questions_json` holds a serialized
-- proto::InterruptQuestionSet; the single-question `question_json` column
-- serves the `jobs` needs-attention nudge. A row never populates both.

-- ---- recursive agent tree and decision persistence ---------------------------
-- These rows are daemon-owned durable control state. Contracts below are
-- redacted summaries, never a prompt, credential, or resolver context.
CREATE TABLE agent_instances (
    agent_instance_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    parent_agent_instance_id TEXT,
    -- A task job can have several child agents.  The child UUID below is the
    -- stable one-to-one binding; making the job id unique would silently
    -- reject every sibling after the first.
    task_delegation_job_id TEXT,
    task_delegation_child_uuid TEXT UNIQUE,
    -- Stable daemon runtime identity for root/utility agents that are not
    -- represented by a task child.  It is session-scoped and never carries
    -- model context or a user-visible display name.
    runtime_key TEXT,
    resolved_profile_snapshot_id TEXT,
    -- Immutable installation identity of this exact node. Delegated nodes
    -- select their own child binding evidence from the session-pinned profile;
    -- they must never infer this from a mutable display name or inherit the
    -- root installation merely because they share its profile snapshot.
    resolved_installation_id TEXT,
    -- Opaque daemon-owned workspace identity.  This is deliberately not a
    -- resolver packet or a client-supplied filesystem authority.
    workspace_ref TEXT,
    -- Auto-resolution starts disabled and can only be enabled for this one
    -- durable agent by a host-resolved profile/session reduction.
    auto_answer_enabled INTEGER NOT NULL DEFAULT 0 CHECK (auto_answer_enabled IN (0, 1)),
    state TEXT NOT NULL CHECK (state IN (
        'created', 'running', 'waiting_for_user', 'waiting_for_approval',
        'completed', 'failed', 'cancelled'
    )),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    -- Effective-settings revision for the per-node session-override CAS. It is
    -- deliberately independent of the lifecycle `revision` above so a state
    -- transition and an override edit never contend for the same token. Each
    -- accepted `ApplyAgentSessionOverride` compares and increments it.
    override_revision INTEGER NOT NULL DEFAULT 0 CHECK (override_revision >= 0),
    -- The not-yet-consumed, daemon-authorized session override accumulated
    -- across accepted apply requests (NULL = none). It can only preserve or
    -- reduce the immutable profile/host envelope; the daemon validates
    -- non-escalation before it is ever written here. Consumed into
    -- `effective_override_json` at the node's next model-turn boundary.
    pending_override_json TEXT CHECK (pending_override_json IS NULL OR json_valid(pending_override_json)),
    -- The override consumed into effect at the last turn boundary (NULL until
    -- the first consumption). The engine reads this as the node's effective
    -- session override for the turn.
    effective_override_json TEXT CHECK (effective_override_json IS NULL OR json_valid(effective_override_json)),
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    UNIQUE (agent_instance_id, session_id),
    UNIQUE (session_id, runtime_key),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (parent_agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY (task_delegation_job_id) REFERENCES task_delegation_jobs(task_call_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY (task_delegation_child_uuid) REFERENCES task_delegation_children(child_uuid) ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY (resolved_profile_snapshot_id, session_id)
        REFERENCES agent_profile_snapshots(snapshot_id, session_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY (resolved_installation_id)
        REFERENCES agent_installations(installation_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE INDEX idx_agent_instances_session_state
    ON agent_instances(session_id, state, updated_at_unix_ms);
CREATE INDEX idx_agent_instances_parent
    ON agent_instances(parent_agent_instance_id)
    WHERE parent_agent_instance_id IS NOT NULL;

CREATE INDEX idx_agent_instances_task_job
    ON agent_instances(session_id, task_delegation_job_id)
    WHERE task_delegation_job_id IS NOT NULL;

-- The root has no task-delegation row to borrow for restart.  Its exact
-- private continuation is therefore stored in its own one-per-session record
-- before a late steer can cross a provider boundary.  The nullable
-- continuation id is a durable proof that the snapshot belongs to the
-- accepted steer rather than an arbitrary earlier root turn.
CREATE TABLE root_agent_continuations (
    session_id TEXT PRIMARY KEY,
    agent_instance_id TEXT NOT NULL,
    continuation_id TEXT,
    snapshot_json TEXT NOT NULL CHECK (json_valid(snapshot_json)),
    updated_at_unix_ms INTEGER NOT NULL,
    FOREIGN KEY (agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);
CREATE INDEX idx_root_agent_continuations_recovery
    ON root_agent_continuations(session_id, agent_instance_id, continuation_id);

-- Private replay authority for every source call claimed by the turn
-- scheduler. Canonical wire input deliberately lives here instead of the
-- exportable tool_call_scheduling event. A worker crash can therefore settle
-- calls that never reached a tool_call/subagent row without exposing arguments
-- on the public timeline.
CREATE TABLE turn_scheduler_continuations (
    session_id TEXT NOT NULL,
    turn_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    source_index INTEGER NOT NULL CHECK (source_index >= 0),
    call_id TEXT NOT NULL,
    provider_item_id TEXT,
    provider_call_id TEXT,
    resolved_tool TEXT NOT NULL,
    wire_input_json TEXT NOT NULL CHECK (json_valid(wire_input_json)),
    classification TEXT NOT NULL CHECK (classification IN ('parallel_lane', 'deferred_delegate', 'serial_barrier')),
    terminal_outcome TEXT CHECK (terminal_outcome IS NULL OR terminal_outcome IN ('completed', 'refused', 'transitioned', 'cancelled')),
    -- The canonical paired result body for a terminal scheduler-owned source
    -- call. This private replay field is deliberately separate from the
    -- exportable scheduling event: it can restore a structural result without
    -- exposing provider bodies or tool arguments on the timeline.
    terminal_result_body TEXT,
    created_at_unix_ms INTEGER NOT NULL,
    settled_at_unix_ms INTEGER,
    PRIMARY KEY (session_id, turn_id, source_index),
    UNIQUE (session_id, call_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CHECK ((terminal_outcome IS NULL) = (settled_at_unix_ms IS NULL)),
    CHECK ((terminal_outcome IS NULL) = (terminal_result_body IS NULL))
);
CREATE INDEX idx_turn_scheduler_continuations_recovery
    ON turn_scheduler_continuations(session_id, terminal_outcome, turn_id, source_index);

-- Recursive noninteractive children are not compatibility `task` rows. Their
-- immutable launch descriptor and newest exact continuation therefore have a
-- dedicated one-to-one durable record rather than borrowing (and overwriting)
-- the enclosing task child's snapshot.
CREATE TABLE recursive_noninteractive_executors (
    agent_instance_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    parent_agent_instance_id TEXT NOT NULL,
    launch_json TEXT NOT NULL CHECK (json_valid(launch_json) AND json_type(launch_json) = 'object'),
    snapshot_json TEXT NOT NULL CHECK (json_valid(snapshot_json) AND json_type(snapshot_json) = 'object'),
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    FOREIGN KEY (agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (parent_agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE INDEX idx_recursive_noninteractive_executors_parent
    ON recursive_noninteractive_executors(session_id, parent_agent_instance_id);

-- A recursive batch persists each child outcome before releasing declared
-- dependents.  The parent checkpoint can therefore survive a crash midway
-- through a DAG without re-running an already-completed predecessor or
-- losing its authored report during final aggregation.
CREATE TABLE recursive_noninteractive_outcomes (
    agent_instance_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    parent_agent_instance_id TEXT NOT NULL,
    label TEXT NOT NULL,
    child_agent TEXT NOT NULL,
    report TEXT NOT NULL,
    failed INTEGER NOT NULL CHECK (failed IN (0, 1)),
    completed_at_unix_ms INTEGER NOT NULL,
    FOREIGN KEY (agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (parent_agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE INDEX idx_recursive_noninteractive_outcomes_parent
    ON recursive_noninteractive_outcomes(session_id, parent_agent_instance_id);

-- One restart epoch may schedule a durable agent revision once. The daemon
-- supplies a fresh boot UUID, so a later crash/restart can resume the same
-- still-running revision without turning duplicate recovery calls in one boot
-- into duplicate workers.
CREATE TABLE agent_resume_claims (
    agent_instance_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    agent_revision INTEGER NOT NULL CHECK (agent_revision >= 0),
    recovery_epoch TEXT NOT NULL,
    claimed_at_unix_ms INTEGER NOT NULL,
    -- Claim consumption happens only after a fresh executor has accepted the
    -- continuation.  A row with this field NULL is observable recovery work,
    -- never a log-and-drop marker.
    consumed_at_unix_ms INTEGER,
    PRIMARY KEY (agent_instance_id, agent_revision, recovery_epoch),
    FOREIGN KEY (agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE decision_requests (
    decision_request_id TEXT PRIMARY KEY,
    agent_instance_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    -- These two references are copied only from the owning durable agent in
    -- the decision-creation transaction.  Presentation selectors supplied by
    -- a tool, model, or protocol client are deliberately never persisted.
    -- `task_call_id_ref` is an opaque compatibility/task lineage id, not a
    -- prompt or a capability; `workspace_ref` is the daemon-minted workspace
    -- identity already bound to the owner.
    task_call_id_ref TEXT,
    workspace_ref TEXT,
    options_contract_json TEXT NOT NULL,
    free_text_contract_json TEXT,
    recommendation_json TEXT,
    rationale_redaction_class TEXT NOT NULL CHECK (rationale_redaction_class IN ('public', 'sensitive', 'secret')),
    -- Host-classified decision category.  The resolver never accepts an
    -- agent-authored risk label as permission to auto-resolve.
    decision_class TEXT NOT NULL CHECK (decision_class IN (
        'user_question', 'low_risk', 'credential', 'authorization', 'destructive',
        'external_action', 'publish', 'purchase', 'production', 'host_approval'
    )),
    -- Present only for a host-approval decision. The identity is allocated by
    -- the trusted daemon host and checked again in the terminal CAS.
    host_approval_operation_id TEXT UNIQUE,
    deadline_unix_ms INTEGER,
    policy_receipt_json TEXT NOT NULL,
    resolver_route TEXT CHECK (resolver_route IN (
        'user', 'warm_parent', 'policy', 'utility', 'timeout', 'cancellation'
    )),
    state TEXT NOT NULL CHECK (state IN ('pending', 'resolving', 'answered', 'auto_resolved', 'timed_out', 'cancelled')),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    UNIQUE (decision_request_id, session_id),
    FOREIGN KEY (agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE INDEX idx_decision_requests_agent_state
    ON decision_requests(agent_instance_id, state, updated_at_unix_ms);

-- Bounded recovery scans use this exact keyset order. Keeping the state
-- predicate in the index makes a large settled history irrelevant to each
-- maintenance turn, while the UUID tie-breaker prevents equal timestamps
-- from being skipped.
CREATE INDEX idx_decision_requests_recoverable_page
    ON decision_requests(session_id, created_at_unix_ms, decision_request_id)
    WHERE state IN ('pending', 'resolving');

-- The public decision contract exposes only daemon-minted opaque option
-- tokens.  This table is the private continuation-side mapping back to the
-- caller's local option ID; it is deliberately never joined into Attention,
-- resolver packets, or daemon wire DTOs.
CREATE TABLE decision_private_option_mappings (
    decision_request_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    opaque_option_id TEXT NOT NULL,
    continuation_option_id TEXT NOT NULL,
    PRIMARY KEY (decision_request_id, opaque_option_id),
    UNIQUE (decision_request_id, continuation_option_id),
    FOREIGN KEY (decision_request_id, session_id)
        REFERENCES decision_requests(decision_request_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE decision_receipts (
    decision_request_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    terminal_state TEXT NOT NULL CHECK (terminal_state IN ('answered', 'auto_resolved', 'timed_out', 'cancelled')),
    terminal_revision INTEGER NOT NULL CHECK (terminal_revision >= 0),
    receipt_json TEXT NOT NULL,
    -- The approved answer envelope is an internal durable continuation input.
    -- It is never projected through Attention or event APIs.
    resume_payload_json TEXT,
    session_event_seq INTEGER,
    created_at_unix_ms INTEGER NOT NULL,
    FOREIGN KEY (decision_request_id, session_id)
        REFERENCES decision_requests(decision_request_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (session_id, session_event_seq)
        REFERENCES session_events(session_id, seq) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE agent_transition_receipts (
    agent_instance_id TEXT NOT NULL,
    terminal_state TEXT NOT NULL CHECK (terminal_state IN ('completed', 'failed', 'cancelled')),
    session_id TEXT NOT NULL,
    terminal_revision INTEGER NOT NULL CHECK (terminal_revision >= 0),
    receipt_json TEXT NOT NULL,
    session_event_seq INTEGER,
    created_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (agent_instance_id, terminal_state),
    FOREIGN KEY (agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (session_id, session_event_seq)
        REFERENCES session_events(session_id, seq) ON DELETE RESTRICT ON UPDATE RESTRICT
);

-- Only the trusted daemon host creates these identities, before it raises a
-- host-approval decision.  Resolution joins this record rather than trusting
-- a caller-authored boolean or a string-shaped "operation" token.
CREATE TABLE agent_host_approval_operations (
    operation_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL,
    -- Immutable host-owned effect binding. The prompt UUID alone is never
    -- authority: the exact operation class and canonical candidate facts must
    -- match again at the consume CAS immediately before the host resumes it.
    operation_kind TEXT NOT NULL CHECK (length(operation_kind) BETWEEN 1 AND 128),
    canonical_input_json TEXT NOT NULL CHECK (json_valid(canonical_input_json)),
    input_digest TEXT NOT NULL CHECK (length(input_digest) = 64),
    -- The real host composition point reserves the final operation before an
    -- interactive decision exists. Binding it later is a one-way operation
    -- checked by the trigger below; decision creation may never mint one.
    decision_request_id TEXT UNIQUE,
    -- `dispatching` is deliberately not replayable.  It is reached only
    -- after a durable effect handoff has committed and before the host may
    -- invoke a non-idempotent command/MCP/harness/filesystem action. A crash
    -- there is submission-unknown, never permission to run it again.
    state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'dispatching', 'completed', 'rejected', 'cancelled', 'submission_unknown')),
    -- Approval belongs to one exact live executor revision.  The consume CAS
    -- compares this value against `agent_instances` so a cancellation or a
    -- later decision cannot dispatch an operation that an earlier revision
    -- happened to approve.
    approved_agent_revision INTEGER,
    -- The exact response selected from the durable prompt. It is recorded in
    -- the same transaction that approves this operation, so candidate facts
    -- cannot be detached from the terminal selection during recovery.
    selected_response_json TEXT CHECK (selected_response_json IS NULL OR json_valid(selected_response_json)),
    -- The canonical candidate selected by that response. Persisting the
    -- candidate itself (rather than only its UI option id) binds both the
    -- exact final host effect and any persistent grant mutation/scope that
    -- choice authorizes.
    selected_candidate_json TEXT CHECK (selected_candidate_json IS NULL OR json_valid(selected_candidate_json)),
    created_at_unix_ms INTEGER NOT NULL,
    resolved_at_unix_ms INTEGER,
    FOREIGN KEY (agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

-- The operation row proves a user approved one canonical host effect. This
-- companion journal proves the different and stricter fact that the host
-- handed that exact effect to its execution boundary.  The idempotency key is
-- intentionally the preallocated operation UUID, not a prompt UUID or UI
-- path.  Recovery may complete/reconcile a known handoff, but it may never
-- issue another non-idempotent dispatch for a `dispatching` record.
CREATE TABLE agent_host_approval_effect_handoffs (
    operation_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL,
    operation_kind TEXT NOT NULL CHECK (length(operation_kind) BETWEEN 1 AND 128),
    canonical_input_json TEXT NOT NULL CHECK (json_valid(canonical_input_json)),
    input_digest TEXT NOT NULL CHECK (length(input_digest) = 64),
    selected_candidate_json TEXT NOT NULL CHECK (json_valid(selected_candidate_json)),
    idempotency_key TEXT NOT NULL UNIQUE,
    -- `ready` means approval was accepted but no concrete host boundary has
    -- yet claimed this capability.  Only `dispatching` is an irrevocable
    -- submission state; boot reconciliation turns that state into
    -- `submission_unknown` and never replays it.
    state TEXT NOT NULL CHECK (state IN ('ready', 'dispatching', 'succeeded', 'rejected', 'submission_unknown')),
    dispatch_started_at_unix_ms INTEGER NOT NULL,
    completed_at_unix_ms INTEGER,
    completion_receipt_json TEXT,
    FOREIGN KEY (operation_id) REFERENCES agent_host_approval_operations(operation_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);
CREATE INDEX idx_agent_host_approval_effect_handoffs_agent_session
    ON agent_host_approval_effect_handoffs(agent_instance_id, session_id);

CREATE TRIGGER agent_host_approval_effect_handoff_matches_operation
BEFORE INSERT ON agent_host_approval_effect_handoffs
WHEN NOT EXISTS (
    SELECT 1 FROM agent_host_approval_operations operation
     WHERE operation.operation_id = NEW.operation_id
       AND operation.session_id = NEW.session_id
       AND operation.agent_instance_id = NEW.agent_instance_id
       AND operation.operation_kind = NEW.operation_kind
       AND operation.canonical_input_json = NEW.canonical_input_json
       AND operation.input_digest = NEW.input_digest
       AND operation.selected_candidate_json = NEW.selected_candidate_json
)
BEGIN
    SELECT RAISE(ABORT, 'host approval effect handoff does not match canonical operation');
END;

-- The handoff is an immutable record of the one effect offered to its
-- boundary.  Completion may change only its lifecycle fields; neither a
-- recovery worker nor a generic SQL caller may retarget an already-dispatched
-- operation while keeping its idempotency key.
CREATE TRIGGER agent_host_approval_effect_handoff_binding_immutable
BEFORE UPDATE OF operation_id, session_id, agent_instance_id, operation_kind, canonical_input_json, input_digest, selected_candidate_json, idempotency_key
ON agent_host_approval_effect_handoffs
WHEN NEW.operation_id IS NOT OLD.operation_id
 OR NEW.session_id IS NOT OLD.session_id
 OR NEW.agent_instance_id IS NOT OLD.agent_instance_id
 OR NEW.operation_kind IS NOT OLD.operation_kind
 OR NEW.canonical_input_json IS NOT OLD.canonical_input_json
 OR NEW.input_digest IS NOT OLD.input_digest
 OR NEW.selected_candidate_json IS NOT OLD.selected_candidate_json
 OR NEW.idempotency_key IS NOT OLD.idempotency_key
BEGIN
    SELECT RAISE(ABORT, 'host approval effect handoff binding is immutable');
END;

CREATE TRIGGER agent_host_approval_effect_handoff_state_is_forward_only
BEFORE UPDATE OF state ON agent_host_approval_effect_handoffs
WHEN NOT (
    (OLD.state = 'ready' AND NEW.state IN ('dispatching', 'rejected'))
    OR (OLD.state = 'dispatching' AND NEW.state IN ('succeeded', 'rejected', 'submission_unknown'))
)
BEGIN
    SELECT RAISE(ABORT, 'host approval effect handoff state transition is invalid');
END;

CREATE UNIQUE INDEX idx_agent_host_approval_pending
    ON agent_host_approval_operations(session_id, agent_instance_id)
    WHERE state = 'pending';

-- A host operation is reserved first by the host composition boundary. It may
-- not be inserted already bound by a generic decision caller.
CREATE TRIGGER agent_host_approval_operation_matches_decision
BEFORE UPDATE OF decision_request_id ON agent_host_approval_operations
WHEN NEW.decision_request_id IS NULL
 OR NOT EXISTS (
    SELECT 1 FROM decision_requests d
    WHERE d.decision_request_id = NEW.decision_request_id
      AND d.session_id = NEW.session_id
      AND d.agent_instance_id = NEW.agent_instance_id
      AND d.decision_class = 'host_approval'
      AND d.host_approval_operation_id = NEW.operation_id
)
BEGIN
    SELECT RAISE(ABORT, 'host approval operation does not match final decision operation');
END;

CREATE TRIGGER agent_host_approval_operation_must_start_unbound
BEFORE INSERT ON agent_host_approval_operations
WHEN NEW.decision_request_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'host approval operation must exist before its decision');
END;

CREATE TRIGGER agent_host_approval_operation_binding_immutable
BEFORE UPDATE OF operation_kind, canonical_input_json, input_digest ON agent_host_approval_operations
WHEN NEW.operation_kind IS NOT OLD.operation_kind
 OR NEW.canonical_input_json IS NOT OLD.canonical_input_json
 OR NEW.input_digest IS NOT OLD.input_digest
BEGIN
    SELECT RAISE(ABORT, 'host approval operation binding is immutable');
END;

-- The approved candidate is a one-time resolution of an immutable candidate
-- set. It may be introduced only by the pending→approved transition and can
-- never be altered, cleared, or paired with a different selected response.
CREATE TRIGGER agent_host_approval_operation_selected_candidate_is_bound
BEFORE UPDATE OF selected_response_json, selected_candidate_json, state
ON agent_host_approval_operations
WHEN (
    (OLD.selected_response_json IS NOT NULL AND NEW.selected_response_json IS NOT OLD.selected_response_json)
    OR (OLD.selected_candidate_json IS NOT NULL AND NEW.selected_candidate_json IS NOT OLD.selected_candidate_json)
    OR (
        OLD.selected_response_json IS NULL
        AND NEW.selected_response_json IS NOT NULL
        AND (
            OLD.state <> 'pending'
            OR NEW.state <> 'approved'
            OR NEW.selected_candidate_json IS NULL
        )
    )
    OR (
        OLD.selected_candidate_json IS NULL
        AND NEW.selected_candidate_json IS NOT NULL
        AND (
            OLD.state <> 'pending'
            OR NEW.state <> 'approved'
            OR NEW.selected_response_json IS NULL
        )
    )
    OR (
        OLD.state = 'pending'
        AND NEW.state = 'approved'
        AND (
            NEW.selected_response_json IS NULL
            OR NEW.selected_candidate_json IS NULL
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'host approval selected candidate is not bound to its approval transition');
END;

-- Host-approval state is a one-way handoff protocol. In particular,
-- `dispatching` cannot become `approved` after a restart: that would turn an
-- unknown external submission into permission to perform it again.
CREATE TRIGGER agent_host_approval_operation_state_is_forward_only
BEFORE UPDATE OF state ON agent_host_approval_operations
WHEN NOT (
    (OLD.state = 'pending' AND NEW.state IN ('approved', 'cancelled'))
    OR (OLD.state = 'approved' AND NEW.state IN ('dispatching', 'rejected', 'cancelled'))
    OR (OLD.state = 'dispatching' AND NEW.state IN ('completed', 'rejected', 'submission_unknown'))
)
BEGIN
    SELECT RAISE(ABORT, 'host approval operation state transition is invalid');
END;

-- Refreshing the daemon-local host capability snapshot is a low-risk effect,
-- but it still crosses a real host probe boundary.  Its request/interrupt/
-- decision identity and execution phase must survive a worker restart: an
-- accepted decision is not permission for an in-memory task to disappear.
--
-- This is deliberately daemon-global rather than session-scoped. A refresh
-- receipt can be recovered by a worker for a different session, and a newly
-- started process must never reuse a generation which an older process has
-- already reserved or published. Every real probe claim reserves exactly one
-- successor in the same IMMEDIATE transaction as its execution fence.
CREATE TABLE host_capability_refresh_generation_allocator (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    high_water_generation INTEGER NOT NULL CHECK (high_water_generation >= 0)
);
INSERT INTO host_capability_refresh_generation_allocator(singleton, high_water_generation)
VALUES (1, 0);

-- The host-refresh child is not an ordinary model executor.  It needs a
-- durable identity before the real QuestionTool row exists, because creating
-- a child and then crashing before its interrupt/decision binding otherwise
-- leaves an unclassifiable nonterminal descendant which recovery cannot
-- safely attach or cancel.  This initialization descriptor is inserted in
-- the same transaction as that child.  The later decision transaction either
-- binds all of interrupt/decision/operation together or leaves this row in
-- `initializing`, which boot terminalizes deterministically.
CREATE TABLE host_capability_refresh_initializations (
    operation_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL UNIQUE,
    parent_agent_instance_id TEXT NOT NULL,
    interrupt_id TEXT UNIQUE,
    decision_request_id TEXT UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('initializing', 'bound', 'cancelled')),
    terminal_reason TEXT,
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    completed_at_unix_ms INTEGER,
    FOREIGN KEY (agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (parent_agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY (interrupt_id) REFERENCES needs_attention(interrupt_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY (decision_request_id, session_id)
        REFERENCES decision_requests(decision_request_id, session_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK (
        (state = 'initializing'
            AND interrupt_id IS NULL AND decision_request_id IS NULL
            AND terminal_reason IS NULL AND completed_at_unix_ms IS NULL)
        OR (state = 'bound'
            AND interrupt_id IS NOT NULL AND decision_request_id IS NOT NULL
            AND terminal_reason IS NULL AND completed_at_unix_ms IS NULL)
        OR (state = 'cancelled'
            AND interrupt_id IS NULL AND decision_request_id IS NULL
            AND terminal_reason IS NOT NULL AND completed_at_unix_ms IS NOT NULL)
    )
);

CREATE INDEX idx_host_capability_refresh_initializations_recovery
    ON host_capability_refresh_initializations(session_id, state, created_at_unix_ms)
    WHERE state = 'initializing';

CREATE TRIGGER host_capability_refresh_initialization_state_is_forward_only
BEFORE UPDATE OF state ON host_capability_refresh_initializations
WHEN NOT (
    OLD.state = 'initializing' AND NEW.state IN ('bound', 'cancelled')
)
BEGIN
    SELECT RAISE(ABORT, 'host capability refresh initialization state transition is invalid');
END;

CREATE TRIGGER host_capability_refresh_initialization_binding_is_immutable
BEFORE UPDATE OF operation_id, request_id, session_id, agent_instance_id,
                 parent_agent_instance_id, interrupt_id, decision_request_id
ON host_capability_refresh_initializations
WHEN NEW.operation_id IS NOT OLD.operation_id
 OR NEW.request_id IS NOT OLD.request_id
 OR NEW.session_id IS NOT OLD.session_id
 OR NEW.agent_instance_id IS NOT OLD.agent_instance_id
 OR NEW.parent_agent_instance_id IS NOT OLD.parent_agent_instance_id
 OR (OLD.state <> 'initializing'
     AND (NEW.interrupt_id IS NOT OLD.interrupt_id
          OR NEW.decision_request_id IS NOT OLD.decision_request_id))
 OR (OLD.state = 'initializing' AND NEW.state = 'initializing'
     AND (NEW.interrupt_id IS NOT OLD.interrupt_id
          OR NEW.decision_request_id IS NOT OLD.decision_request_id))
BEGIN
    SELECT RAISE(ABORT, 'host capability refresh initialization binding is immutable');
END;

CREATE TABLE host_capability_refresh_operations (
    operation_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL,
    interrupt_id TEXT NOT NULL UNIQUE,
    decision_request_id TEXT UNIQUE,
    -- The exact nonterminal owner revision that crossed the probe boundary.
    -- Completion must still observe this revision, so a cancellation or newer
    -- lifecycle transition between probing and publication fences the staged
    -- result instead of exposing it after its authority disappeared.
    execution_agent_revision INTEGER CHECK (
        execution_agent_revision IS NULL OR execution_agent_revision >= 0
    ),
    -- A monotonic execution epoch plus an opaque task-owned lease token fence
    -- each actual local probe. The process may renew only this exact claim;
    -- reaping and terminal writes never trust an operation id by itself.
    execution_epoch INTEGER NOT NULL DEFAULT 0 CHECK (execution_epoch >= 0),
    execution_lease_owner_token TEXT,
    execution_lease_expires_at_unix_ms INTEGER,
    -- Reserved at allowed→executing, before the probe begins. The completed
    -- receipt must carry this exact generation; a caller cannot choose it.
    reserved_snapshot_generation INTEGER CHECK (
        reserved_snapshot_generation IS NULL OR reserved_snapshot_generation >= 1
    ),
    state TEXT NOT NULL CHECK (state IN (
        'pending', 'allowed', 'executing', 'completed', 'failed', 'cancelled'
    )),
    result_snapshot_json TEXT CHECK (
        result_snapshot_json IS NULL OR json_valid(result_snapshot_json)
    ),
    -- Canonical, parsed snapshot identity. The JSON body is retained for
    -- recovery, but publication and acknowledgement use these independently
    -- persisted values so a raw write cannot acknowledge different bytes.
    result_snapshot_generation INTEGER CHECK (
        result_snapshot_generation IS NULL OR result_snapshot_generation >= 1
    ),
    result_snapshot_digest TEXT CHECK (
        result_snapshot_digest IS NULL
        OR (length(result_snapshot_digest) = 64
            AND result_snapshot_digest NOT GLOB '*[^0-9a-f]*')
    ),
    -- Completion and publication are two different durability boundaries.
    -- A process can die after committing the exact snapshot but before the
    -- in-memory capability store observes it. Keep an explicit outbox fence
    -- so the next worker publishes that same generation once instead of
    -- probing again or silently losing the committed result.
    published_at_unix_ms INTEGER,
    error_text TEXT,
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    completed_at_unix_ms INTEGER,
    FOREIGN KEY (agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (interrupt_id) REFERENCES needs_attention(interrupt_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (decision_request_id, session_id)
        REFERENCES decision_requests(decision_request_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CHECK (state NOT IN ('executing', 'completed') OR execution_agent_revision IS NOT NULL),
    CHECK (
        state <> 'executing' OR (
            execution_epoch > 0
            AND execution_lease_owner_token IS NOT NULL
            AND execution_lease_expires_at_unix_ms IS NOT NULL
            AND reserved_snapshot_generation IS NOT NULL
        )
    ),
    CHECK (
        (execution_lease_owner_token IS NULL AND execution_lease_expires_at_unix_ms IS NULL)
        OR (execution_lease_owner_token IS NOT NULL AND execution_lease_expires_at_unix_ms IS NOT NULL)
    ),
    CHECK (published_at_unix_ms IS NULL OR state = 'completed'),
    CHECK (
        (state IN ('pending', 'allowed', 'executing')
            AND result_snapshot_json IS NULL
            AND result_snapshot_generation IS NULL
            AND result_snapshot_digest IS NULL
            AND error_text IS NULL
            AND completed_at_unix_ms IS NULL)
        OR (state = 'completed'
            AND result_snapshot_json IS NOT NULL
            AND result_snapshot_generation = reserved_snapshot_generation
            AND result_snapshot_digest IS NOT NULL
            AND error_text IS NULL
            AND completed_at_unix_ms IS NOT NULL)
        OR (state IN ('failed', 'cancelled')
            AND result_snapshot_json IS NULL
            AND result_snapshot_generation IS NULL
            AND result_snapshot_digest IS NULL
            AND error_text IS NOT NULL
            AND completed_at_unix_ms IS NOT NULL)
    )
);

CREATE INDEX idx_host_capability_refresh_recovery
    ON host_capability_refresh_operations(session_id, created_at_unix_ms)
    WHERE state IN ('pending', 'allowed', 'executing')
       OR (state = 'completed' AND published_at_unix_ms IS NULL);

-- Maintenance reads are explicitly keyset-paginated. These partial indexes
-- match their exact predicates and orderings so a large durable backlog does
-- not become an unbounded scan before a worker applies its per-turn limit.
CREATE INDEX idx_host_capability_refresh_allowed_page
    ON host_capability_refresh_operations(session_id, created_at_unix_ms, operation_id)
    WHERE state = 'allowed';

CREATE INDEX idx_host_capability_refresh_completed_outbox_page
    ON host_capability_refresh_operations(
        result_snapshot_generation, completed_at_unix_ms, operation_id
    )
    WHERE state = 'completed' AND published_at_unix_ms IS NULL;

CREATE TRIGGER host_capability_refresh_operation_state_is_forward_only
BEFORE UPDATE OF state ON host_capability_refresh_operations
WHEN NOT (
    OLD.state = NEW.state
    OR (OLD.state = 'pending' AND NEW.state IN ('allowed', 'cancelled', 'failed'))
    OR (OLD.state = 'allowed' AND NEW.state IN ('executing', 'cancelled', 'failed'))
    -- Subtree/root cancellation remains the terminal authority even after a
    -- daemon-local probe crossed its execution boundary. The cancelled row
    -- fences that in-flight result and is paired atomically with the child.
    OR (OLD.state = 'executing' AND NEW.state IN ('completed', 'failed', 'cancelled'))
)
BEGIN
    SELECT RAISE(ABORT, 'host capability refresh operation state transition is invalid');
END;

CREATE TRIGGER host_capability_refresh_operation_binding_immutable
BEFORE UPDATE OF operation_id, request_id, session_id, agent_instance_id, interrupt_id,
                 decision_request_id ON host_capability_refresh_operations
WHEN NEW.operation_id IS NOT OLD.operation_id
 OR NEW.request_id IS NOT OLD.request_id
 OR NEW.session_id IS NOT OLD.session_id
 OR NEW.agent_instance_id IS NOT OLD.agent_instance_id
 OR NEW.interrupt_id IS NOT OLD.interrupt_id
 OR (OLD.decision_request_id IS NOT NULL
     AND NEW.decision_request_id IS NOT OLD.decision_request_id)
BEGIN
    SELECT RAISE(ABORT, 'host capability refresh operation binding is immutable');
END;

-- Publication is a one-way outbox acknowledgement. It is intentionally
-- separate from `state`: completion is the linearization point, and a later
-- subtree cancellation must not erase the completed winner while a successor
-- worker is still making its exact durable snapshot visible.
CREATE TRIGGER host_capability_refresh_operation_publication_is_forward_only
BEFORE UPDATE OF published_at_unix_ms ON host_capability_refresh_operations
WHEN NEW.published_at_unix_ms IS NULL
 OR OLD.published_at_unix_ms IS NOT NULL
 OR OLD.state <> 'completed'
 OR NEW.state <> 'completed'
BEGIN
    SELECT RAISE(ABORT, 'host capability refresh publication acknowledgement is invalid');
END;

-- The revision fence is written exactly once with the allowed→executing
-- probe-boundary transition.  A later update must not replace it with a newer
-- owner revision, otherwise a cancelled/revived subtree could publish the
-- old probe under fresh authority.
CREATE TRIGGER host_capability_refresh_operation_execution_revision_is_bound
BEFORE UPDATE OF execution_agent_revision ON host_capability_refresh_operations
WHEN NEW.execution_agent_revision IS NULL
 OR OLD.execution_agent_revision IS NOT NULL
 OR OLD.state <> 'allowed'
 OR NEW.state <> 'executing'
BEGIN
    SELECT RAISE(ABORT, 'host capability refresh execution revision is immutable');
END;

-- The execution identity is written exactly once with the
-- allowed→executing transition. Expiry changes are permitted only by the
-- token-fenced renewal query in the DB owner; the epoch/token itself cannot
-- be replaced by a stale worker after the probe boundary has been crossed.
CREATE TRIGGER host_capability_refresh_operation_execution_lease_identity_is_bound
BEFORE UPDATE OF execution_epoch, execution_lease_owner_token ON host_capability_refresh_operations
WHEN NEW.execution_epoch <= OLD.execution_epoch
 OR OLD.execution_epoch <> 0
 OR OLD.state <> 'allowed'
 OR NEW.state <> 'executing'
 OR NEW.execution_lease_owner_token IS NULL
 OR NEW.execution_lease_expires_at_unix_ms IS NULL
BEGIN
    SELECT RAISE(ABORT, 'host capability refresh execution lease identity is immutable');
END;

CREATE TRIGGER host_capability_refresh_operation_reserved_generation_is_bound
BEFORE UPDATE OF reserved_snapshot_generation ON host_capability_refresh_operations
WHEN NEW.reserved_snapshot_generation IS NULL
 OR OLD.reserved_snapshot_generation IS NOT NULL
 OR OLD.state <> 'allowed'
 OR NEW.state <> 'executing'
BEGIN
    SELECT RAISE(ABORT, 'host capability refresh reserved generation is immutable');
END;

-- The globally allocated generation is a durable monotonic counter. No raw
-- repair may reset, skip backwards, or delete this singleton after a daemon
-- has observed a receipt.
CREATE TRIGGER host_capability_refresh_generation_allocator_is_monotonic
BEFORE UPDATE OF high_water_generation ON host_capability_refresh_generation_allocator
WHEN NEW.singleton <> 1
 OR NEW.high_water_generation <> OLD.high_water_generation + 1
BEGIN
    SELECT RAISE(ABORT, 'host capability refresh generation allocator must advance by one');
END;

CREATE TRIGGER host_capability_refresh_generation_allocator_delete_forbidden
BEFORE DELETE ON host_capability_refresh_generation_allocator
BEGIN
    SELECT RAISE(ABORT, 'host capability refresh generation allocator is durable');
END;

-- A completed receipt is an append-only exact fact. In particular, an
-- outbox reader which parsed snapshot A must not subsequently acknowledge a
-- raw-mutated snapshot B. Completion code also carries digest and generation
-- in its acknowledgement CAS, but this trigger makes a bypass fail closed.
CREATE TRIGGER host_capability_refresh_completed_receipt_is_immutable
BEFORE UPDATE OF result_snapshot_json, result_snapshot_generation,
                 result_snapshot_digest, reserved_snapshot_generation
ON host_capability_refresh_operations
WHEN OLD.state = 'completed'
 AND (
        NEW.result_snapshot_json IS NOT OLD.result_snapshot_json
     OR NEW.result_snapshot_generation IS NOT OLD.result_snapshot_generation
     OR NEW.result_snapshot_digest IS NOT OLD.result_snapshot_digest
     OR NEW.reserved_snapshot_generation IS NOT OLD.reserved_snapshot_generation
 )
BEGIN
    SELECT RAISE(ABORT, 'host capability refresh completed receipt is immutable');
END;

-- A user reply that arrives after an automatic resolution is a new durable
-- steer to the requesting agent. It deliberately does not rewrite the
-- immutable automatic receipt. One decision has one idempotent late steer;
-- a retried client request therefore cannot restart the agent twice.
CREATE TABLE agent_decision_steers (
    steer_id TEXT PRIMARY KEY,
    -- A steer owns one immutable continuation identity.  It is also the
    -- inference idempotency identity for the turn which consumes the steer;
    -- recovery must resume this identity, never manufacture a second turn.
    continuation_id TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL,
    -- The decision owner which requested the original automatic resolution.
    -- Most steers target this same agent. A daemon-owned host-operation child
    -- has no model mailbox, so its one post-auto user steer is durably
    -- rerouted to its direct requesting parent while retaining this immutable
    -- provenance field.
    requesting_agent_instance_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL,
    decision_request_id TEXT NOT NULL UNIQUE,
    origin_principal TEXT NOT NULL CHECK (origin_principal = 'user'),
    payload_json TEXT NOT NULL,
    -- A post-auto user steer is ordered after the exact parked QuestionTool
    -- replay that consumed the automatic terminal result.  This is a durable
    -- predecessor identity, not an advisory worker flag: recovery cannot
    -- claim the steer until that same interrupt reached `resolved`.
    predecessor_interrupt_id TEXT,
    created_at_unix_ms INTEGER NOT NULL,
    claimed_recovery_epoch TEXT,
    -- This is a monotonic continuation state machine, rather than an advisory
    -- delivery bit.  In particular, an `accepted` steer is a durable
    -- no-redelivery fence: a successor must resume its exact checkpoint or
    -- reconcile its result, never enqueue the user body again.
    execution_state TEXT NOT NULL DEFAULT 'pending'
        CHECK (execution_state IN ('pending', 'accepted', 'completed', 'rejected')),
    -- The exact executor persists acceptance and an immutable restart
    -- checkpoint before it begins the continuation. A completed invocation is
    -- then receipt-only recoverable; a rejected one is terminal (for example
    -- because its owner subtree was cancelled).
    accepted_recovery_epoch TEXT,
    accepted_at_unix_ms INTEGER,
    -- Acceptance snapshots the exact owner revision and byte-exact payload
    -- length.  Recovery verifies these fields against both the canonical row
    -- and its immutable checkpoint before it can reattach a model turn.
    accepted_agent_revision INTEGER,
    payload_bytes INTEGER,
    continuation_checkpoint_json TEXT,
    completed_at_unix_ms INTEGER,
    rejected_at_unix_ms INTEGER,
    rejection_reason TEXT,
    delivered_at_unix_ms INTEGER,
    CHECK (
        (execution_state = 'pending'
            AND accepted_recovery_epoch IS NULL
            AND accepted_at_unix_ms IS NULL
            AND continuation_checkpoint_json IS NULL
            AND completed_at_unix_ms IS NULL
            AND rejected_at_unix_ms IS NULL
            AND rejection_reason IS NULL)
        OR (execution_state = 'accepted'
            AND accepted_recovery_epoch IS NOT NULL
            AND accepted_at_unix_ms IS NOT NULL
            AND accepted_agent_revision IS NOT NULL
            AND payload_bytes IS NOT NULL
            AND continuation_checkpoint_json IS NOT NULL
            AND completed_at_unix_ms IS NULL
            AND rejected_at_unix_ms IS NULL
            AND rejection_reason IS NULL)
        OR (execution_state = 'completed'
            AND accepted_recovery_epoch IS NOT NULL
            AND accepted_at_unix_ms IS NOT NULL
            AND accepted_agent_revision IS NOT NULL
            AND payload_bytes IS NOT NULL
            AND continuation_checkpoint_json IS NOT NULL
            AND completed_at_unix_ms IS NOT NULL
            AND rejected_at_unix_ms IS NULL
            AND rejection_reason IS NULL)
        OR (execution_state = 'rejected'
            AND completed_at_unix_ms IS NULL
            AND rejected_at_unix_ms IS NOT NULL
            AND rejection_reason IS NOT NULL)
    ),
    FOREIGN KEY (agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (requesting_agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (decision_request_id, session_id)
        REFERENCES decision_requests(decision_request_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE INDEX idx_agent_decision_steers_pending
    ON agent_decision_steers(session_id, created_at_unix_ms)
    WHERE delivered_at_unix_ms IS NULL;
CREATE INDEX idx_agent_decision_steers_agent_session
    ON agent_decision_steers(agent_instance_id, session_id);
CREATE INDEX idx_agent_decision_steers_requesting_agent_session
    ON agent_decision_steers(requesting_agent_instance_id, session_id);
CREATE INDEX idx_agent_decision_steers_decision_session
    ON agent_decision_steers(decision_request_id, session_id);

-- Late steers are an immutable user-authored continuation.  In particular a
-- recovery worker may move its delivery lease, but it may never retarget the
-- owner/decision/continuation, replace the user body, or rewrite the
-- acceptance checkpoint that fences an inference identity.
CREATE TRIGGER agent_decision_steers_immutable_identity
BEFORE UPDATE OF steer_id, continuation_id, session_id, requesting_agent_instance_id, agent_instance_id,
                 decision_request_id, origin_principal, payload_json,
                 predecessor_interrupt_id, created_at_unix_ms
ON agent_decision_steers
BEGIN
    SELECT RAISE(ABORT, 'agent decision steer identity and payload are immutable');
END;

CREATE TRIGGER agent_decision_steers_checkpoint_immutable_after_accept
BEFORE UPDATE OF accepted_recovery_epoch, accepted_at_unix_ms,
                 accepted_agent_revision, payload_bytes,
                 continuation_checkpoint_json
ON agent_decision_steers
WHEN OLD.execution_state IN ('accepted', 'completed', 'rejected')
  OR OLD.accepted_recovery_epoch IS NOT NULL
  OR OLD.accepted_at_unix_ms IS NOT NULL
  OR OLD.accepted_agent_revision IS NOT NULL
  OR OLD.payload_bytes IS NOT NULL
  OR OLD.continuation_checkpoint_json IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'accepted agent decision steer checkpoint is immutable');
END;

-- `rejected` is a cancellation terminal winner; completed continuation
-- receipts remain completed and are acknowledged without being relabelled.
CREATE TRIGGER agent_decision_steers_execution_state_forward_only
BEFORE UPDATE OF execution_state ON agent_decision_steers
WHEN NOT (
    OLD.execution_state = NEW.execution_state
    OR (OLD.execution_state = 'pending' AND NEW.execution_state IN ('accepted', 'rejected'))
    OR (OLD.execution_state = 'accepted' AND NEW.execution_state IN ('completed', 'rejected'))
)
BEGIN
    SELECT RAISE(ABORT, 'agent decision steer execution state is not forward-only');
END;

CREATE TRIGGER decision_receipts_immutable
BEFORE UPDATE ON decision_receipts
BEGIN
    SELECT RAISE(ABORT, 'decision receipts are immutable');
END;

CREATE TRIGGER agent_transition_receipts_immutable
BEFORE UPDATE ON agent_transition_receipts
BEGIN
    SELECT RAISE(ABORT, 'agent transition receipts are immutable');
END;

CREATE TABLE needs_attention (
    interrupt_id   TEXT    PRIMARY KEY,
    session_id     TEXT    NOT NULL,
    -- Human-readable executor/profile name for display only. Never use this
    -- mutable/shared label to choose a parked continuation.
    agent_id       TEXT    NOT NULL,
    -- Exact durable owner of an AgentTree QuestionTool continuation. Legacy
    -- attention rows have no tree owner and retain NULL. This must remain
    -- separate from `agent_id`: recursive siblings may share a display name.
    agent_instance_id TEXT,
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
    parked_verification_json TEXT,                  -- serialized verification replay memo, or NULL
    -- Recursive-agent decisions use this typed ownership edge. A linked real
    -- QuestionTool interrupt retains its immutable question and parked-call
    -- continuation; synthetic attention rows carry neither.
    decision_request_id TEXT UNIQUE,
    -- A decision-owned row is a durable projection of its decision state,
    -- rather than an independently mutable interrupt.  Legacy rows retain
    -- their historical unversioned API; the decision state machine advances
    -- this revision under its own transaction-only guard.
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    CHECK (question_json IS NULL OR questions_json IS NULL),
    CHECK (
        (parked_tool IS NULL AND parked_args_json IS NULL AND parked_call_id IS NULL AND parked_resume_json IS NULL)
        OR
        (parked_tool IS NOT NULL AND parked_args_json IS NOT NULL AND parked_call_id IS NOT NULL AND parked_resume_json IS NOT NULL)
    ),
    -- Tool-call parks must carry their replay anchor. A linked QuestionTool
    -- question row may enter `executing` without one: its continuation is the
    -- question payload, and settlement cannot add parked_* after bind.
    CHECK (
        state <> 'executing'
        OR parked_tool IS NOT NULL
        OR question_json IS NOT NULL
        OR questions_json IS NOT NULL
    ),
    CHECK ((state = 'resolved') = (resolved_at IS NOT NULL)),
    CHECK (state IN ('executing', 'interrupted', 'resolved') OR response_json IS NULL),
    CHECK (state <> 'executing' OR response_json IS NOT NULL),
    CHECK (
        decision_request_id IS NULL
        -- Synthetic decision Attention has no legacy continuation.
        OR (question_json IS NULL AND questions_json IS NULL
            AND parked_tool IS NULL AND parked_args_json IS NULL
            AND parked_call_id IS NULL AND parked_resume_json IS NULL
            AND parked_gate_json IS NULL
            AND parked_verification_json IS NULL)
        -- A real QuestionTool row is linked after it has durably captured its
        -- exact question and optional parked replay anchor. The decision
        -- state machine owns terminal projection, not the data itself.
        OR question_json IS NOT NULL OR questions_json IS NOT NULL
    ),
    FOREIGN KEY (decision_request_id) REFERENCES decision_requests(decision_request_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE INDEX idx_na_session_open ON needs_attention (session_id, state);

-- `agent_tree_decisions` installs this guard only for the short portion of
-- its transaction which resolves a decision-owned projection.  Existing
-- interrupt APIs never create a guard, so they cannot accidentally race or
-- mutate rows owned by the decision state machine.  It is intentionally
-- empty outside that transaction (and is removed before commit).
CREATE TABLE decision_attention_mutation_guards (
    decision_request_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    FOREIGN KEY (decision_request_id, session_id)
        REFERENCES decision_requests(decision_request_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TRIGGER needs_attention_decision_session_insert
BEFORE INSERT ON needs_attention
WHEN NEW.decision_request_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM decision_requests d
    WHERE d.decision_request_id = NEW.decision_request_id
      AND d.session_id = NEW.session_id
      AND d.agent_instance_id = NEW.agent_instance_id
 )
BEGIN
    SELECT RAISE(ABORT, 'decision needs-attention session mismatch');
END;

CREATE TRIGGER needs_attention_decision_session_update
BEFORE UPDATE OF decision_request_id, session_id, agent_instance_id ON needs_attention
WHEN NEW.decision_request_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM decision_requests d
    WHERE d.decision_request_id = NEW.decision_request_id
      AND d.session_id = NEW.session_id
      AND d.agent_instance_id = NEW.agent_instance_id
 )
BEGIN
    SELECT RAISE(ABORT, 'decision needs-attention session mismatch');
END;

CREATE TRIGGER needs_attention_decision_owned_update
BEFORE UPDATE ON needs_attention
WHEN OLD.decision_request_id IS NOT NULL
 AND (
    NEW.interrupt_id IS NOT OLD.interrupt_id
    OR NEW.session_id IS NOT OLD.session_id
    OR NEW.agent_id IS NOT OLD.agent_id
    OR NEW.agent_instance_id IS NOT OLD.agent_instance_id
    OR NEW.description IS NOT OLD.description
    OR NEW.question_json IS NOT OLD.question_json
    OR NEW.raised_at IS NOT OLD.raised_at
    OR NEW.questions_json IS NOT OLD.questions_json
    OR NEW.parked_tool IS NOT OLD.parked_tool
    OR NEW.parked_args_json IS NOT OLD.parked_args_json
    OR NEW.parked_call_id IS NOT OLD.parked_call_id
    OR NEW.parked_resume_json IS NOT OLD.parked_resume_json
    OR NEW.parked_gate_json IS NOT OLD.parked_gate_json
    OR NEW.parked_verification_json IS NOT OLD.parked_verification_json
    OR NEW.decision_request_id IS NOT OLD.decision_request_id
    OR NOT (
        (NEW.state = 'resolved' AND NEW.resolved_at IS NOT NULL)
        OR (
            (OLD.question_json IS NOT NULL OR OLD.questions_json IS NOT NULL)
            AND OLD.state IN ('parked', 'executing')
            AND NEW.state = 'executing'
            AND NEW.resolved_at IS OLD.resolved_at
        )
        OR (
            (OLD.question_json IS NOT NULL OR OLD.questions_json IS NOT NULL)
            AND OLD.state = 'open'
            AND NEW.state = 'parked'
            AND NEW.resolved_at IS OLD.resolved_at
        )
        -- Crash recovery: a linked host-approval (or other side-effecting)
        -- continuation was `executing` when the worker died. Replaying it
        -- would re-run the approved tool; the decision is already terminal,
        -- so the projection may move to `interrupted` under the same guard.
        OR (
            (OLD.question_json IS NOT NULL OR OLD.questions_json IS NOT NULL)
            AND OLD.state = 'executing'
            AND NEW.state = 'interrupted'
            AND NEW.resolved_at IS OLD.resolved_at
        )
    )
    OR NEW.revision <> OLD.revision + 1
    OR NOT EXISTS (
        SELECT 1 FROM decision_attention_mutation_guards g
        WHERE g.decision_request_id = OLD.decision_request_id
          AND g.session_id = OLD.session_id
    )
    OR NOT EXISTS (
        SELECT 1 FROM decision_requests d
        WHERE d.decision_request_id = OLD.decision_request_id
          AND d.session_id = OLD.session_id
          AND (
              d.state IN ('answered', 'auto_resolved', 'timed_out', 'cancelled')
              OR (
                  (OLD.question_json IS NOT NULL OR OLD.questions_json IS NOT NULL)
                  AND OLD.state = 'open'
                  AND NEW.state = 'parked'
              )
          )
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'decision-owned needs-attention is managed by decision state machine');
END;

-- ---- tool_call_stats view ----------------------------------------------------

CREATE VIEW tool_call_stats AS
SELECT
    event_id, session_id, call_id, timestamp,
    model, provider, project_id, project_root,
    tool, path, language,
    recovery_kind, recovery_stage, hard_fail,
    shape_fingerprint,

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
-- per-file tables FK to it ON DELETE CASCADE ON UPDATE RESTRICT so dropping a deleted or
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
    FOREIGN KEY (root, path) REFERENCES intel_files(root, path) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE intel_imports (
    root   TEXT NOT NULL,
    path   TEXT NOT NULL,
    target TEXT NOT NULL,
    line   INTEGER NOT NULL,
    FOREIGN KEY (root, path) REFERENCES intel_files(root, path) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE intel_identifiers (
    root  TEXT NOT NULL,
    path  TEXT NOT NULL,
    token TEXT NOT NULL,
    line  INTEGER NOT NULL,
    FOREIGN KEY (root, path) REFERENCES intel_files(root, path) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE intel_deps (
    root       TEXT NOT NULL,
    importer   TEXT NOT NULL,
    importee   TEXT,
    raw_target TEXT NOT NULL,
    line       INTEGER NOT NULL,
    FOREIGN KEY (root, importer) REFERENCES intel_files(root, path) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE intel_callsites (
    root          TEXT NOT NULL,
    caller_file   TEXT NOT NULL,
    caller_line   INTEGER NOT NULL,
    caller_symbol TEXT,
    callee_name   TEXT NOT NULL,
    callee_kind   TEXT,
    FOREIGN KEY (root, caller_file) REFERENCES intel_files(root, path) ON DELETE CASCADE ON UPDATE RESTRICT
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

-- One row per DISPATCHED TARGET ATTEMPT of a logical inference call. The
-- primary attempt is ordinal 0; each backup/failover attempt shares the logical
-- `call_id` and takes the next ordinal (same-target HTTP retries reuse the row).
-- `payload_json` is the IMMUTABLE post-render request body for that target,
-- written once at dispatch and never rewritten. Lifecycle metadata lives beside
-- it: `status` plus dedicated nullable phase-timestamp columns (ms from
-- dispatch), advanced monotonically by the status-advance path only. Per-attempt
-- `provider` / `model` / `trust` record where and under which custody the body
-- was rendered so cross-trust failover attempts are individually auditable.
CREATE TABLE inference_requests (
    call_id        TEXT    NOT NULL,            -- == inference_calls.call_id
    ordinal        INTEGER NOT NULL DEFAULT 0,  -- dispatched-target attempt index
    session_id     TEXT    NOT NULL,
    ts_ms          INTEGER NOT NULL,            -- epoch milliseconds (dispatch)
    payload_json   TEXT    NOT NULL,            -- immutable post-render request body
    status         TEXT    NOT NULL DEFAULT 'completed' CHECK (status IN ('pending', 'completed', 'errored', 'timed_out', 'cancelled')),
    provider       TEXT,                        -- per-attempt provider id
    model          TEXT,                        -- per-attempt model id
    trust          TEXT,                        -- per-attempt custody ('trusted'|'untrusted')
    first_token_ms INTEGER,                     -- phase: dispatch -> first token (ms)
    completed_ms   INTEGER,                     -- phase: dispatch -> completion (ms)
    failed_ms      INTEGER,                     -- phase: dispatch -> failure/timeout (ms)
    goal_id TEXT,                               -- immutable host-goal attribution at dispatch
    goal_attempt_generation INTEGER,            -- attempt generation captured with goal_id
    PRIMARY KEY (call_id, ordinal),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE INDEX idx_ireq_session ON inference_requests (session_id);
CREATE INDEX idx_ireq_goal_provenance
    ON inference_requests (goal_id, goal_attempt_generation);

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
        'model_switch', 'hook_run', 'tool_call_scheduling', 'agent_tree',
        'thread_anchor'
    )),
    agent       TEXT,                              -- emitting agent, when known
    call_id     TEXT,                              -- correlation key, when applicable
    task_call_id TEXT,                             -- owning delegation run, when inside a child
    label       TEXT,                              -- delegation label paired with task_call_id
    data_json   TEXT    NOT NULL DEFAULT '{}' CHECK (
        json_valid(data_json)
        AND json_type(data_json) = 'object'
        AND length(CAST(data_json AS BLOB)) <= 8388608
    ),                                             -- per-type payload
    -- assistant-turn reasoning projected out of `data_json` so queries and
    -- exports can read it column-wise without parsing JSON (the same idiom
    -- the FTS triggers use against `$.text`). VIRTUAL: computed on read.
    reasoning TEXT
        GENERATED ALWAYS AS (json_extract(data_json, '$.reasoning')) VIRTUAL,
    origin_principal TEXT,                         -- remote principal attribution
    provider_id TEXT,                              -- authoring model provider id, NULL for model-less events
    model_id TEXT,                                 -- authoring model id, NULL for model-less events
    model_trust TEXT,                              -- write-time resolved model trust, NULL for model-less events
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
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

-- ---- ACP Code-root projection ---------------------------------------------
-- The projection is a redacted delivery ledger, not an ACP session store.
-- Cockpit's session/agent/decision tables remain authoritative. Attachment
-- capabilities and discovery snapshots are deliberately absent: they are
-- boot-local daemon authorities and become invalid on restart.
CREATE TABLE code_root_projection_deliveries (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_id TEXT NOT NULL UNIQUE CHECK (
        length(delivery_id) = 36 AND delivery_id = lower(delivery_id)
    ),
    replay_cursor TEXT NOT NULL UNIQUE CHECK (
        length(replay_cursor) = 32
        AND replay_cursor = lower(replay_cursor)
        AND replay_cursor NOT GLOB '*[^0-9a-f]*'
    ),
    session_id TEXT NOT NULL,
    source_key TEXT CHECK (
        source_key IS NULL OR length(CAST(source_key AS BLOB)) BETWEEN 1 AND 128
    ),
    kind TEXT NOT NULL CHECK (kind IN (
        'history', 'attention', 'root_state_changed', 'client_incompatible'
    )),
    payload_json TEXT NOT NULL CHECK (
        json_valid(payload_json)
        AND json_type(payload_json) = 'object'
        AND length(CAST(payload_json AS BLOB)) <= 524288
    ),
    created_at_unix_ms INTEGER NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE INDEX idx_code_root_projection_session_sequence
    ON code_root_projection_deliveries(session_id, sequence);
CREATE UNIQUE INDEX uq_code_root_projection_source
    ON code_root_projection_deliveries(session_id, kind, source_key)
    WHERE source_key IS NOT NULL;

-- Durable logical-client ACK state. The capability authenticates each live
-- request in memory; only the bounded caller id and acknowledged projection
-- position survive so session/load can resume after a daemon restart.
CREATE TABLE code_root_replay_cursors (
    session_id TEXT NOT NULL,
    logical_client_id TEXT NOT NULL CHECK (
        length(CAST(logical_client_id AS BLOB)) BETWEEN 1 AND 128
        AND logical_client_id NOT GLOB '*[^ -~]*'
    ),
    acknowledged_sequence INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged_sequence >= 0),
    updated_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (session_id, logical_client_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        ON DELETE CASCADE ON UPDATE RESTRICT
);

-- First-wins, durable receipts for ACP decision resolution. The boot-local
-- attachment capability authorizes a live call; this row lets the same
-- logical client recover its accepted terminal result after reconnect/restart.
CREATE TABLE code_root_interrupt_receipts (
    session_id TEXT NOT NULL,
    logical_client_id TEXT NOT NULL CHECK (
        length(CAST(logical_client_id AS BLOB)) BETWEEN 1 AND 128
        AND logical_client_id NOT GLOB '*[^ -~]*'
    ),
    client_request_id TEXT NOT NULL CHECK (
        length(CAST(client_request_id AS BLOB)) BETWEEN 1 AND 128
        AND client_request_id NOT GLOB '*[^ -~]*'
    ),
    fingerprint BLOB NOT NULL CHECK (length(fingerprint) = 32),
    outcome TEXT NOT NULL CHECK (outcome IN (
        'accepted', 'already_resolved_same', 'already_resolved_other',
        'cancelled', 'expired'
    )),
    resolved_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (session_id, logical_client_id, client_request_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        ON DELETE CASCADE ON UPDATE RESTRICT
);

-- ---- verification ledger ----------------------------------------------------
-- Verification work is daemon-owned audit state.  Rows deliberately contain
-- only bounded classifications, opaque identifiers, and SHA-256 digests.  The
-- selected executable artifact, provider receipt, candidate body, and raw
-- verifier evidence remain volatile host state and are never recoverable from
-- SQLite.
CREATE TABLE verification_operations (
    operation_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    agent_instance_id TEXT NOT NULL,
    requested_candidate_count INTEGER NOT NULL CHECK (requested_candidate_count >= 0 AND requested_candidate_count <= 64),
    effective_candidate_count INTEGER NOT NULL CHECK (effective_candidate_count >= 0 AND effective_candidate_count <= requested_candidate_count),
    total_token_ceiling INTEGER NOT NULL CHECK (total_token_ceiling >= 0),
    estimated_cost_ceiling_microunits INTEGER NOT NULL CHECK (estimated_cost_ceiling_microunits >= 0),
    cost_unit TEXT NOT NULL CHECK (cost_unit IN ('microusd')),
    collection_deadline_unix_ms INTEGER NOT NULL,
    collection_duration_ms INTEGER NOT NULL CHECK (collection_duration_ms >= 0),
    conservative_token_reservation INTEGER NOT NULL CHECK (conservative_token_reservation >= 0),
    conservative_cost_reservation_microunits INTEGER NOT NULL CHECK (conservative_cost_reservation_microunits >= 0),
    estimate_state TEXT NOT NULL CHECK (estimate_state IN ('available', 'estimate_unavailable')),
    budget_action TEXT CHECK (budget_action IN ('refuse', 'dispatch_original')),
    original_operation_digest TEXT NOT NULL CHECK (length(original_operation_digest) = 64 AND original_operation_digest NOT GLOB '*[^0-9a-f]*'),
    pretool_context_capability_digest TEXT NOT NULL CHECK (length(pretool_context_capability_digest) = 64 AND pretool_context_capability_digest NOT GLOB '*[^0-9a-f]*'),
    state TEXT NOT NULL CHECK (state IN ('created', 'collecting', 'synthesizing', 'dispatching', 'succeeded', 'failed', 'cancelled', 'aborted', 'skipped_budget_refused', 'unknown')),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    collection_closed_at_unix_ms INTEGER,
    collection_revision INTEGER NOT NULL DEFAULT 0 CHECK (collection_revision >= 0),
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    UNIQUE (operation_id, session_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK (estimate_state = 'available' OR budget_action IS NOT NULL),
    CHECK ((state = 'skipped_budget_refused') = (budget_action = 'refuse')),
    -- Both estimate-unavailable dispositions are pre-candidate branches.
    -- `refuse` suppresses the operation while `dispatch_original` dispatches
    -- the original operation, but neither reserves verification candidates.
    -- A normal estimable operation may legitimately use an effective count of
    -- zero, so do not make zero count imply one particular budget action.
    CHECK (budget_action IS NULL OR effective_candidate_count = 0)
);

CREATE INDEX idx_verification_operations_session_state
    ON verification_operations(session_id, state, updated_at_unix_ms);

CREATE TABLE verification_candidates (
    candidate_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('proposed_call', 'write_change_set')),
    canonical_call_digest TEXT NOT NULL CHECK (length(canonical_call_digest) = 64 AND canonical_call_digest NOT GLOB '*[^0-9a-f]*'),
    artifact_union_digest TEXT NOT NULL CHECK (length(artifact_union_digest) = 64 AND artifact_union_digest NOT GLOB '*[^0-9a-f]*'),
    redacted_summary_json TEXT NOT NULL,
    reserved_tokens INTEGER NOT NULL CHECK (reserved_tokens >= 0),
    reserved_cost_microunits INTEGER NOT NULL CHECK (reserved_cost_microunits >= 0),
    state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'valid', 'invalid', 'cancelled', 'timed_out', 'malformed')),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    UNIQUE (candidate_id, operation_id),
    UNIQUE (candidate_id, session_id),
    FOREIGN KEY (operation_id, session_id)
        REFERENCES verification_operations(operation_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE INDEX idx_verification_candidates_operation_state
    ON verification_candidates(operation_id, state, created_at_unix_ms);

-- A write candidate's file-level union is digest-only: callers can prove a
-- synthesis is composed entirely of valid candidates without persisting a raw
-- path, diff, binary body, or mode string in the ledger.
CREATE TABLE verification_candidate_artifacts (
    candidate_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    operation_kind TEXT NOT NULL CHECK (operation_kind IN ('add', 'delete', 'modify', 'rename', 'mode')),
    affected_path_digest TEXT NOT NULL CHECK (length(affected_path_digest) = 64 AND affected_path_digest NOT GLOB '*[^0-9a-f]*'),
    prior_path_digest TEXT CHECK (length(prior_path_digest) = 64 AND prior_path_digest NOT GLOB '*[^0-9a-f]*'),
    content_digest TEXT CHECK (length(content_digest) = 64 AND content_digest NOT GLOB '*[^0-9a-f]*'),
    binary_metadata_digest TEXT CHECK (length(binary_metadata_digest) = 64 AND binary_metadata_digest NOT GLOB '*[^0-9a-f]*'),
    mode_digest TEXT CHECK (length(mode_digest) = 64 AND mode_digest NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (candidate_id, ordinal),
    FOREIGN KEY (candidate_id, operation_id)
        REFERENCES verification_candidates(candidate_id, operation_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (candidate_id, session_id)
        REFERENCES verification_candidates(candidate_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CHECK ((operation_kind = 'rename') = (prior_path_digest IS NOT NULL)),
    CHECK ((operation_kind = 'mode') = (mode_digest IS NOT NULL))
);

CREATE TABLE verification_late_results (
    late_result_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    result_kind TEXT NOT NULL CHECK (result_kind IN ('valid', 'invalid', 'malformed', 'failed')),
    result_digest TEXT NOT NULL CHECK (length(result_digest) = 64 AND result_digest NOT GLOB '*[^0-9a-f]*'),
    received_at_unix_ms INTEGER NOT NULL,
    UNIQUE (candidate_id, result_digest),
    FOREIGN KEY (candidate_id, operation_id)
        REFERENCES verification_candidates(candidate_id, operation_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (candidate_id, session_id)
        REFERENCES verification_candidates(candidate_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (operation_id, session_id)
        REFERENCES verification_operations(operation_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE verification_syntheses (
    synthesis_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'selected', 'synthesized_write', 'refused', 'no_valid_candidate', 'failed')),
    selected_candidate_id TEXT,
    artifact_kind TEXT CHECK (artifact_kind IN ('proposed_call', 'write_change_set')),
    canonical_call_digest TEXT CHECK (length(canonical_call_digest) = 64 AND canonical_call_digest NOT GLOB '*[^0-9a-f]*'),
    write_union_receipt_digest TEXT CHECK (length(write_union_receipt_digest) = 64 AND write_union_receipt_digest NOT GLOB '*[^0-9a-f]*'),
    redacted_summary_json TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 0),
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    UNIQUE (operation_id, session_id),
    FOREIGN KEY (operation_id, session_id)
        REFERENCES verification_operations(operation_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (selected_candidate_id, operation_id)
        REFERENCES verification_candidates(candidate_id, operation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK ((state = 'selected' AND artifact_kind = 'proposed_call' AND canonical_call_digest IS NOT NULL)
        OR (state = 'synthesized_write' AND selected_candidate_id IS NULL AND artifact_kind = 'write_change_set' AND write_union_receipt_digest IS NOT NULL)
        OR (state IN ('pending', 'refused', 'no_valid_candidate', 'failed') AND selected_candidate_id IS NULL))
);

-- A synthesized write is a digest-only union of exact members owned by valid
-- write candidates. This proves no output path or operation kind was invented
-- outside the candidate set without retaining raw path or patch data.
CREATE TABLE verification_synthesis_artifacts (
    synthesis_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    source_candidate_id TEXT NOT NULL,
    source_artifact_ordinal INTEGER NOT NULL CHECK (source_artifact_ordinal >= 0),
    PRIMARY KEY (synthesis_id, ordinal),
    UNIQUE (synthesis_id, source_candidate_id, source_artifact_ordinal),
    FOREIGN KEY (synthesis_id) REFERENCES verification_syntheses(synthesis_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (source_candidate_id, source_artifact_ordinal)
        REFERENCES verification_candidate_artifacts(candidate_id, ordinal) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE verification_projection_envelopes (
    envelope_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL,
    prepared_projection_id TEXT NOT NULL UNIQUE,
    prepared_projection_digest TEXT NOT NULL CHECK (length(prepared_projection_digest) = 64 AND prepared_projection_digest NOT GLOB '*[^0-9a-f]*'),
    batch_digest TEXT NOT NULL CHECK (length(batch_digest) = 64 AND batch_digest NOT GLOB '*[^0-9a-f]*'),
    surrogate_kind TEXT NOT NULL CHECK (surrogate_kind IN ('selected_call', 'synthesized_write', 'normalized_original')),
    model_visible_projection_json TEXT NOT NULL,
    retention_state TEXT NOT NULL CHECK (retention_state IN ('retained', 'cleaned')),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    UNIQUE (operation_id, session_id),
    FOREIGN KEY (operation_id, session_id)
        REFERENCES verification_operations(operation_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE verification_dispatch_attempts (
    attempt_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL,
    host_idempotency_key TEXT NOT NULL UNIQUE,
    dispatch_digest TEXT NOT NULL CHECK (length(dispatch_digest) = 64 AND dispatch_digest NOT GLOB '*[^0-9a-f]*'),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'executing', 'succeeded', 'failed', 'unknown', 'cancelled_no_submission')),
    redacted_receipt_json TEXT,
    receipt_digest TEXT CHECK (length(receipt_digest) = 64 AND receipt_digest NOT GLOB '*[^0-9a-f]*'),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL,
    UNIQUE (operation_id, session_id),
    FOREIGN KEY (operation_id, session_id)
        REFERENCES verification_operations(operation_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE verification_projections (
    projection_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('suppressed', 'committed')),
    batch_digest TEXT NOT NULL CHECK (length(batch_digest) = 64 AND batch_digest NOT GLOB '*[^0-9a-f]*'),
    redacted_result_json TEXT,
    created_at_unix_ms INTEGER NOT NULL,
    UNIQUE (projection_id, session_id),
    UNIQUE (operation_id, session_id),
    FOREIGN KEY (operation_id, session_id)
        REFERENCES verification_operations(operation_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE verification_projection_events (
    projection_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    session_id TEXT NOT NULL,
    session_event_seq INTEGER NOT NULL,
    PRIMARY KEY (projection_id, ordinal),
    UNIQUE (projection_id, session_event_seq),
    FOREIGN KEY (projection_id, session_id)
        REFERENCES verification_projections(projection_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (session_id, session_event_seq)
        REFERENCES session_events(session_id, seq) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE INDEX idx_verification_projection_events_session
    ON verification_projection_events(session_id, session_event_seq);

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
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

-- Authoritative terminal receipts for config-only SetDefaultModel requests.
-- The request returns Ack and the result travels on the event stream, so the
-- durable receipt is the recovery/idempotency source of truth.  It is written
-- before an event is attempted and before the private config transaction
-- journal is retired; reusing an id can therefore replay only this exact safe
-- terminal outcome, never perform a second configuration mutation.
CREATE TABLE default_model_update_receipts (
    session_id          TEXT NOT NULL,
    default_update_id   TEXT NOT NULL,
    outcome_json        TEXT NOT NULL CHECK (
        typeof(outcome_json) = 'text'
        AND length(CAST(outcome_json AS BLOB)) BETWEEN 2 AND 65536
        AND json_valid(outcome_json)
    ),
    -- Opaque retained-attachment receipt fence.  Both values are present for
    -- a retained authority-bound terminal result (Applied or a recovered
    -- Restored rejection) and absent for a pre-mutation rejection; raw
    -- paths/configuration never enter this ledger.
    authority_revision  TEXT CHECK (
        authority_revision IS NULL
        OR (
            length(authority_revision) = 64
            AND authority_revision NOT GLOB '*[^0-9a-f]*'
        )
    ),
    config_generation   INTEGER CHECK (
        config_generation IS NULL OR config_generation >= 0
    ),
    created_at_ms       INTEGER NOT NULL,
    CHECK ((authority_revision IS NULL) = (config_generation IS NULL)),
    PRIMARY KEY (session_id, default_update_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

-- Authoritative exactly-once ledger for typed user-message submissions. UUID
-- identities that cross the canonical binary boundary are RFC-byte BLOBs;
-- actor identity is deliberately absent for the local-owner tuple.
CREATE TABLE message_operation_receipts (
    session_id             TEXT NOT NULL,
    operation_id           BLOB NOT NULL CHECK (typeof(operation_id) = 'blob' AND length(operation_id) = 16 AND operation_id <> zeroblob(16)),
    actor_kind             TEXT NOT NULL CHECK (actor_kind IN ('local_owner', 'external_principal')),
    actor_id               BLOB,
    -- Canonical unsigned big-endian u64: zeroblob(8) for local owner and a
    -- nonzero value for a remote-device generation.
    actor_generation       BLOB NOT NULL CHECK (typeof(actor_generation) = 'blob' AND length(actor_generation) = 8),
    request_hash           BLOB NOT NULL CHECK (typeof(request_hash) = 'blob' AND length(request_hash) = 32),
    message_request_digest BLOB NOT NULL CHECK (typeof(message_request_digest) = 'blob' AND length(message_request_digest) = 32),
    client_submission_id   BLOB NOT NULL CHECK (typeof(client_submission_id) = 'blob' AND length(client_submission_id) = 16 AND client_submission_id <> zeroblob(16)),
    state                  TEXT NOT NULL CHECK (state IN ('accepted', 'materialized', 'terminal_rejected', 'removed')),
    safe_outcome           BLOB NOT NULL CHECK (typeof(safe_outcome) = 'blob'),
    artifact_terminal_reason TEXT CHECK (artifact_terminal_reason IS NULL OR artifact_terminal_reason IN ('artifact_reservation_expired', 'artifact_quota_exhausted', 'artifact_too_large', 'artifact_security_rejected', 'artifact_preflight_rejected', 'artifact_idempotency_conflict', 'artifact_persistence_failed')),
    -- The FCM2 v2 envelope is frozen.  Explicit model fencing for an
    -- oversized submission therefore belongs to this durable receipt rather
    -- than its canonical-wire bytes, and survives lease materialization.
    artifact_model_fence_generation TEXT CHECK(artifact_model_fence_generation IS NULL OR (typeof(artifact_model_fence_generation) = 'text' AND artifact_model_fence_generation NOT GLOB '*[^0-9]*' AND length(artifact_model_fence_generation) BETWEEN 1 AND 20 AND (artifact_model_fence_generation = '0' OR substr(artifact_model_fence_generation, 1, 1) <> '0') AND (length(artifact_model_fence_generation) < 20 OR artifact_model_fence_generation <= '18446744073709551615'))),
    artifact_model_fence_json TEXT CHECK(artifact_model_fence_json IS NULL OR (typeof(artifact_model_fence_json) = 'text' AND length(CAST(artifact_model_fence_json AS BLOB)) <= 8192 AND json_valid(artifact_model_fence_json) AND json_type(artifact_model_fence_json) = 'object' AND json(artifact_model_fence_json) = artifact_model_fence_json)),
    outbox_sequence        INTEGER NOT NULL CHECK (outbox_sequence >= 0),
    created_at             INTEGER NOT NULL,
    updated_at             INTEGER NOT NULL,
    PRIMARY KEY (session_id, operation_id),
    UNIQUE (session_id, client_submission_id),
    UNIQUE (session_id, operation_id, client_submission_id, message_request_digest),
    CHECK (
      (actor_kind = 'local_owner' AND actor_id IS NULL AND actor_generation = zeroblob(8)) OR
      (actor_kind = 'external_principal' AND typeof(actor_id) = 'blob' AND length(actor_id) = 16 AND actor_id <> zeroblob(16) AND actor_generation <> zeroblob(8))
    ),
    CHECK (state = 'terminal_rejected' OR artifact_terminal_reason IS NULL),
    CHECK ((artifact_model_fence_generation IS NULL) = (artifact_model_fence_json IS NULL)),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE message_submission_receipts (
    session_id             TEXT NOT NULL,
    client_submission_id   BLOB NOT NULL CHECK (typeof(client_submission_id) = 'blob' AND length(client_submission_id) = 16 AND client_submission_id <> zeroblob(16)),
    operation_id           BLOB NOT NULL CHECK (typeof(operation_id) = 'blob' AND length(operation_id) = 16 AND operation_id <> zeroblob(16)),
    message_request_digest BLOB NOT NULL CHECK (typeof(message_request_digest) = 'blob' AND length(message_request_digest) = 32),
    attachment_set_digest  BLOB NOT NULL CHECK (typeof(attachment_set_digest) = 'blob' AND length(attachment_set_digest) = 32),
    -- Durable replay identity for the private binding. The randomized seal
    -- row may be released after the turn; this canonical receipt remains.
    tool_media_subject_receipt BLOB CHECK (
        tool_media_subject_receipt IS NULL OR (
            typeof(tool_media_subject_receipt) = 'blob'
            AND length(tool_media_subject_receipt) = 122
        )
    ),
    state                  TEXT NOT NULL CHECK (state IN ('accepted', 'materialized', 'terminal_rejected', 'removed')),
    queue_item_id          BLOB NOT NULL CHECK (typeof(queue_item_id) = 'blob' AND length(queue_item_id) = 16 AND queue_item_id <> zeroblob(16)),
    message_seq            INTEGER CHECK (message_seq IS NULL OR message_seq > 0),
    fold_ordinal           INTEGER CHECK (fold_ordinal IS NULL OR fold_ordinal >= 0),
    safe_outcome           BLOB NOT NULL CHECK (typeof(safe_outcome) = 'blob'),
    artifact_terminal_reason TEXT CHECK (artifact_terminal_reason IS NULL OR artifact_terminal_reason IN ('artifact_reservation_expired', 'artifact_quota_exhausted', 'artifact_too_large', 'artifact_security_rejected', 'artifact_preflight_rejected', 'artifact_idempotency_conflict', 'artifact_persistence_failed')),
    created_at             INTEGER NOT NULL,
    updated_at             INTEGER NOT NULL,
    PRIMARY KEY (session_id, client_submission_id),
    UNIQUE (session_id, operation_id),
    UNIQUE (session_id, operation_id, client_submission_id, message_request_digest),
    CHECK ((state = 'materialized') = (message_seq IS NOT NULL AND fold_ordinal IS NOT NULL)),
    CHECK (state = 'terminal_rejected' OR artifact_terminal_reason IS NULL),
    FOREIGN KEY (session_id, operation_id)
      REFERENCES message_operation_receipts(session_id, operation_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (session_id, operation_id, client_submission_id, message_request_digest)
      REFERENCES message_operation_receipts(session_id, operation_id, client_submission_id, message_request_digest)
      ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE message_queue_items (
    session_id           TEXT NOT NULL,
    queue_item_id        BLOB NOT NULL CHECK (typeof(queue_item_id) = 'blob' AND length(queue_item_id) = 16 AND queue_item_id <> zeroblob(16)),
    client_submission_id BLOB NOT NULL CHECK (typeof(client_submission_id) = 'blob' AND length(client_submission_id) = 16 AND client_submission_id <> zeroblob(16)),
    canonical_message    BLOB NOT NULL CHECK (
        typeof(canonical_message) = 'blob'
        AND length(canonical_message) BETWEEN 5 AND 17439564
        AND substr(canonical_message, 1, 4) = X'46434D32'
    ),
    state                TEXT NOT NULL CHECK (state IN ('accepted', 'folding', 'materialized', 'terminal_rejected', 'removed')),
    artifact_terminal_reason TEXT CHECK (artifact_terminal_reason IS NULL OR artifact_terminal_reason IN ('artifact_reservation_expired', 'artifact_quota_exhausted', 'artifact_too_large', 'artifact_security_rejected', 'artifact_preflight_rejected', 'artifact_idempotency_conflict', 'artifact_persistence_failed')),
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL,
    PRIMARY KEY (session_id, queue_item_id),
    UNIQUE (session_id, client_submission_id),
    CHECK (state = 'terminal_rejected' OR artifact_terminal_reason IS NULL),
    FOREIGN KEY (session_id, client_submission_id)
      REFERENCES message_submission_receipts(session_id, client_submission_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE message_attachment_references (
    session_id           TEXT NOT NULL,
    client_submission_id BLOB NOT NULL CHECK (typeof(client_submission_id) = 'blob' AND length(client_submission_id) = 16 AND client_submission_id <> zeroblob(16)),
    ordinal              INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 16),
    attachment_id        BLOB NOT NULL CHECK (typeof(attachment_id) = 'blob' AND length(attachment_id) = 16 AND attachment_id <> zeroblob(16)),
    -- Canonical unsigned big-endian u64. SQLite INTEGER cannot represent the
    -- upper half of the wire domain without lossy signed coercion.
    attachment_version   BLOB NOT NULL CHECK (typeof(attachment_version) = 'blob' AND length(attachment_version) = 8 AND attachment_version <> zeroblob(8)),
    checksum             BLOB NOT NULL CHECK (typeof(checksum) = 'blob' AND length(checksum) = 32),
    kind                 INTEGER NOT NULL CHECK (kind IN (1, 2, 3)),
    acquired_at          INTEGER NOT NULL,
    released_at          INTEGER,
    PRIMARY KEY (session_id, client_submission_id, ordinal),
    UNIQUE (session_id, client_submission_id, attachment_id),
    CHECK (released_at IS NULL OR released_at >= acquired_at),
    FOREIGN KEY (session_id, client_submission_id)
      REFERENCES message_submission_receipts(session_id, client_submission_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

-- Large compaction records spill out of the inline event JSON as one canonical
-- payload (brief + handoff + serialized tail). The `session_compacted` event
-- remains authoritative and carries this opaque, session-scoped id.
CREATE TABLE compaction_handoffs (
    handoff_id   TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
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
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
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
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
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
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE INDEX idx_loop_guard_rules_session ON loop_guard_rules (session_id);

-- ---- image_generation_grants --------------------------------------------------
-- Standing image-generation dispatch grants recorded after a human approval
-- prompt resolves "allow for session/project". They are bounded capabilities,
-- not exact replays of an earlier prompt: the persisted tuple binds destination
-- and output authority and grants only a no-broader reference-egress, fanout,
-- output-count, and cost envelope. Scoped to once/session/project
-- ONLY — there is no global scope: the `scope` CHECK rejects any value other
-- than 'session' or 'project'. Prompt text/digest and output stem are never
-- stored or matched. `verdict` mirrors the
-- approval_grants polarity toggle; `revoked_at_unix_ms` marks a revoked grant
-- so it can no longer short-circuit a prompt. Session-scope rows bind an
-- exact session (session_id NOT NULL, FK cascade); project-scope rows bind the
-- machine-local project identity (session_id NULL) and require a current
-- session membership audit at match time (the caller passes the live session's
-- project_id, so a foreign project's grant never matches).

CREATE TABLE image_generation_grants (
    grant_id              TEXT    PRIMARY KEY CHECK (length(CAST(grant_id AS BLOB)) = 36),
    scope                 TEXT    NOT NULL CHECK (scope IN ('session', 'project')),
    session_id            TEXT    CHECK (
        (scope = 'session' AND session_id IS NOT NULL)
        OR (scope = 'project' AND session_id IS NULL)
    ),
    project_id            TEXT    NOT NULL CHECK (length(CAST(project_id AS BLOB)) BETWEEN 1 AND 1024),
    destination_binding_digest TEXT NOT NULL CHECK (
        length(destination_binding_digest) = 64
        AND destination_binding_digest = lower(destination_binding_digest)
        AND destination_binding_digest NOT GLOB '*[^0-9a-f]*'
    ),
    output_path_authority TEXT    NOT NULL CHECK (length(CAST(output_path_authority AS BLOB)) BETWEEN 1 AND 255),
    reference_egress      INTEGER NOT NULL CHECK (reference_egress IN (0, 1)),
    maximum_fanout        INTEGER NOT NULL CHECK (maximum_fanout BETWEEN 1 AND 64),
    maximum_total_outputs INTEGER NOT NULL CHECK (maximum_total_outputs BETWEEN 1 AND 4096),
    maximum_known_cost_usd_micros INTEGER CHECK (maximum_known_cost_usd_micros >= 0),
    unknown_cost_allowed  INTEGER NOT NULL CHECK (unknown_cost_allowed IN (0, 1)),
    verdict               TEXT    NOT NULL DEFAULT 'allow'
        CHECK (verdict IN ('allow', 'reject')),
    granted_at_unix_ms    INTEGER NOT NULL,
    revoked_at_unix_ms    INTEGER,
    CHECK (maximum_known_cost_usd_micros IS NOT NULL OR unknown_cost_allowed = 1),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

-- One live grant per bounded capability tuple.
-- `ifnull` collapses the NULL session_id of project-scope rows so two
-- project-scope allow grants for the same plan cannot coexist.
CREATE UNIQUE INDEX uq_image_generation_grants_match
    ON image_generation_grants (scope, ifnull(session_id, ''), project_id, destination_binding_digest, output_path_authority, reference_egress, maximum_fanout, maximum_total_outputs, ifnull(maximum_known_cost_usd_micros, -1), unknown_cost_allowed, verdict);

CREATE INDEX idx_image_generation_grants_session ON image_generation_grants (session_id);
CREATE INDEX idx_image_generation_grants_project ON image_generation_grants (project_id, destination_binding_digest);

-- ---- scheduled jobs --------------------------------------------------------
-- The immutable insertion identity fences stale asynchronous actions when a
-- user-chosen job id is deleted and later reused.
CREATE TABLE scheduled_jobs (
    id                TEXT    PRIMARY KEY,
    row_identity      TEXT    NOT NULL UNIQUE,
    owner             TEXT    NOT NULL,
    schedule_json     TEXT    NOT NULL CHECK (
        json_valid(schedule_json) AND json_type(schedule_json) = 'object'
        AND length(CAST(schedule_json AS BLOB)) <= 65536
    ),
    payload_json      TEXT    NOT NULL CHECK (
        json_valid(payload_json)
        AND length(CAST(payload_json AS BLOB)) <= 1048576
    ),
    enabled           INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    missed_run_policy TEXT    NOT NULL CHECK (missed_run_policy IN ('skip', 'run_once_on_start')),
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL CHECK (updated_at >= created_at),
    last_run_at       INTEGER,
    next_run_at       INTEGER,
    last_result_json  TEXT CHECK (
        last_result_json IS NULL OR (
            json_valid(last_result_json)
            AND length(CAST(last_result_json AS BLOB)) <= 1048576
        )
    ),
    failure_count     INTEGER NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    backoff_until     INTEGER,
    disabled_notice   TEXT
);

CREATE INDEX idx_scheduled_jobs_next_run ON scheduled_jobs(enabled, next_run_at);
CREATE INDEX idx_scheduled_jobs_owner ON scheduled_jobs(owner);

CREATE TRIGGER scheduled_jobs_row_identity_immutable
BEFORE UPDATE OF row_identity ON scheduled_jobs
BEGIN
    SELECT RAISE(ABORT, 'scheduled job row identity is immutable');
END;

-- ---- session full-text search (`history_search` / `cockpit://` recall) ------------
-- A single FTS5 virtual table indexes the *searchable* surface of every
-- session: the session title/description, the text of `user_message` /
-- `assistant_message` events, model-written compaction briefs/handoffs, and
-- session-owned text artifacts. Raw inference payloads remain unindexed.
--
-- Layout choice: a contentless FTS5 table (`content=''`) with one indexed
-- text column, because the searchable text is spread across two base
-- tables (sessions.title + session_events.data_json) and lives inside a
-- JSON blob in the events case — there is no single column FTS5 could
-- shadow. The `session_fts_docs` side table maps FTS rowids back to a
-- thread (`session_id`) and, for message rows, an in-thread location
-- (`seq`); it stores identifiers only, never a second copy of text.
--
--   row_kind   — 'title' | 'description' | 'message' | 'compaction' |
--                'artifact', preserving the canonical recall target.
--   seq        — session_events.seq for a message row; NULL for a title.

CREATE VIRTUAL TABLE session_fts USING fts5(
    body,
    content=''
);

CREATE TABLE session_fts_docs (
    rowid      INTEGER PRIMARY KEY,
    row_kind   TEXT NOT NULL CHECK (row_kind IN ('title', 'description', 'message', 'compaction', 'artifact')),
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    seq        INTEGER,
    artifact_id TEXT,
    FOREIGN KEY (session_id, seq)
        REFERENCES session_events(session_id, seq) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (session_id, artifact_id)
        REFERENCES session_text_artifacts(session_id, artifact_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    UNIQUE(row_kind, session_id, artifact_id)
);

CREATE UNIQUE INDEX session_fts_docs_one_title
    ON session_fts_docs(session_id)
    WHERE row_kind = 'title';

CREATE UNIQUE INDEX session_fts_docs_one_description
    ON session_fts_docs(session_id)
    WHERE row_kind = 'description';

-- An event has at most one message or compaction document of a given kind,
-- but it may own several separately-addressable artifact documents.
CREATE UNIQUE INDEX session_fts_docs_one_non_artifact_event_kind
    ON session_fts_docs(row_kind, session_id, seq)
    WHERE row_kind <> 'artifact';

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
    WHERE row_kind IN ('message', 'compaction')
      AND session_id = old.session_id AND seq = old.seq;
    DELETE FROM session_fts_docs
    WHERE row_kind IN ('message', 'compaction')
      AND session_id = old.session_id AND seq = old.seq;
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
    WHERE row_kind IN ('message', 'compaction')
      AND session_id = old.session_id AND seq = old.seq;
    DELETE FROM session_fts_docs
    WHERE row_kind IN ('message', 'compaction')
      AND session_id = old.session_id AND seq = old.seq;
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
WHEN (new.title IS NOT NULL AND new.title <> '')
  OR (new.description IS NOT NULL AND new.description <> '')
BEGIN
    INSERT INTO session_fts_docs (row_kind, session_id, seq)
    SELECT 'title', new.session_id, NULL
    WHERE new.title IS NOT NULL AND new.title <> '';
    INSERT INTO session_fts_docs (row_kind, session_id, seq)
    SELECT 'description', new.session_id, NULL
    WHERE new.description IS NOT NULL AND new.description <> '';
    INSERT INTO session_fts (rowid, body)
    SELECT rowid, CASE row_kind
      WHEN 'title' THEN new.title
      ELSE new.description
    END
    FROM session_fts_docs
    WHERE session_id = new.session_id
      AND row_kind IN ('title', 'description');
END;

CREATE TRIGGER session_fts_title_au AFTER UPDATE OF title, description ON sessions
BEGIN
    INSERT INTO session_fts (session_fts, rowid, body)
    SELECT 'delete', rowid, CASE row_kind
      WHEN 'title' THEN old.title
      ELSE old.description
    END
    FROM session_fts_docs
    WHERE row_kind IN ('title', 'description') AND session_id = old.session_id;
    DELETE FROM session_fts_docs
    WHERE row_kind IN ('title', 'description') AND session_id = old.session_id;
    INSERT INTO session_fts_docs (row_kind, session_id, seq)
    SELECT 'title', new.session_id, NULL
    WHERE new.title IS NOT NULL AND new.title <> '';
    INSERT INTO session_fts_docs (row_kind, session_id, seq)
    SELECT 'description', new.session_id, NULL
    WHERE new.description IS NOT NULL AND new.description <> '';
    INSERT INTO session_fts (rowid, body)
    SELECT rowid, CASE row_kind
      WHEN 'title' THEN new.title
      ELSE new.description
    END
    FROM session_fts_docs
    WHERE session_id = new.session_id
      AND row_kind IN ('title', 'description');
END;

CREATE TRIGGER session_fts_sessions_ad AFTER DELETE ON sessions
BEGIN
    INSERT INTO session_fts (session_fts, rowid, body)
    SELECT 'delete', d.rowid,
           CASE d.row_kind
             WHEN 'title' THEN old.title
             WHEN 'description' THEN old.description
             WHEN 'artifact' THEN a.content
             ELSE json_extract(e.data_json, '$.text')
           END
    FROM session_fts_docs AS d
    LEFT JOIN session_events AS e
           ON e.session_id = d.session_id AND e.seq = d.seq
    LEFT JOIN session_text_artifacts AS a
           ON a.session_id = d.session_id AND a.artifact_id = d.artifact_id
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
    hash       TEXT PRIMARY KEY CHECK (
        length(hash) = 64 AND hash = lower(hash) AND hash NOT GLOB '*[^0-9a-f]*'
    ),
    contents   TEXT NOT NULL CHECK (length(CAST(contents AS BLOB)) <= 8388608),
    -- Daemon-observed wall-clock time, signed Unix milliseconds.
    created_at_unix_ms INTEGER NOT NULL
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
        REFERENCES sessions (session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
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
        REFERENCES session_events(session_id, seq) ON DELETE CASCADE ON UPDATE RESTRICT
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
        REFERENCES sessions (session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
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
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE INDEX idx_tandem_session ON tandem_inference (session_id);
CREATE INDEX idx_tandem_parent  ON tandem_inference (parent_call_id);

-- ---- task todos + notes + assignments --------------------------------------------------
-- Durable session todos and append-only task notes/deltas. Assignments
-- link a todo to the delegated child run (`task_call_id` + `label`) that
-- is working it.

CREATE TABLE task_todos (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
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
    todo_id TEXT NOT NULL REFERENCES task_todos(id) ON DELETE CASCADE ON UPDATE RESTRICT,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
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
    todo_id TEXT NOT NULL REFERENCES task_todos(id) ON DELETE CASCADE ON UPDATE RESTRICT,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
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
-- Host-supervised goal loop: disposition/phase lifecycle plus durable
-- control-job and root-turn tables. Pre-release: this is the only definition.

CREATE TABLE session_goals (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    project_id TEXT NOT NULL,
    objective TEXT NOT NULL,
    context TEXT,
    disposition TEXT NOT NULL CHECK (disposition IN ('running', 'user_paused', 'infra_paused', 'blocked', 'no_progress_paused', 'budget_limited', 'complete', 'cleared')),
    phase TEXT CHECK (phase IS NULL OR phase IN ('planning', 'executing', 'evaluating', 'verifying')),
    resume_phase TEXT CHECK (resume_phase IS NULL OR resume_phase IN ('planning', 'executing', 'evaluating', 'verifying')),
    pause_reason TEXT,
    attempt_generation INTEGER NOT NULL DEFAULT 0 CHECK (attempt_generation >= 0),
    contract_json TEXT,
    resolved_policy_json TEXT NOT NULL,
    evaluator_outcome_json TEXT,
    verifier_outcome_json TEXT,
    unresolved_gaps_json TEXT NOT NULL DEFAULT '[]',
    gap_fingerprints_json TEXT NOT NULL DEFAULT '[]',
    previous_gap_set_hash TEXT,
    blocker_key TEXT,
    blocker_key_streak INTEGER NOT NULL DEFAULT 0,
    token_budget INTEGER NOT NULL CHECK (token_budget > 0),
    token_accounting_baseline INTEGER NOT NULL DEFAULT 0,
    tokens_used INTEGER NOT NULL DEFAULT 0,
    elapsed_active_ms INTEGER NOT NULL DEFAULT 0 CHECK (elapsed_active_ms >= 0),
    active_since INTEGER,
    lifecycle_history_json TEXT NOT NULL DEFAULT '[]',
    blocked_attempts INTEGER NOT NULL DEFAULT 0,
    completion_evidence TEXT,
    verification_rounds INTEGER NOT NULL DEFAULT 0,
    last_read_at INTEGER,
    cleared_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    CHECK ((disposition = 'running' AND phase IS NOT NULL AND resume_phase IS NULL)
        OR (disposition <> 'running' AND phase IS NULL)),
    CHECK ((disposition IN ('complete', 'cleared') AND resume_phase IS NULL)
        OR disposition NOT IN ('complete', 'cleared'))
);

CREATE UNIQUE INDEX idx_session_goals_one_open
    ON session_goals(session_id)
    WHERE disposition IN ('running', 'user_paused', 'infra_paused', 'blocked', 'no_progress_paused', 'budget_limited');
CREATE INDEX idx_session_goals_session_status
    ON session_goals(session_id, disposition, updated_at DESC);

CREATE TABLE goal_control_jobs (
    job_id TEXT PRIMARY KEY,
    goal_id TEXT NOT NULL REFERENCES session_goals(id) ON DELETE CASCADE ON UPDATE RESTRICT,
    attempt_generation INTEGER NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('planner', 'evaluator', 'gatekeeper', 'cold_skeptic')),
    slot INTEGER NOT NULL CHECK (slot >= 0),
    request_json TEXT NOT NULL,
    result_json TEXT,
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'finished', 'cancelled')),
    lease_expires_at INTEGER,
    cancel_reason TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(goal_id, attempt_generation, role, slot)
);
CREATE INDEX idx_goal_control_jobs_registered
    ON goal_control_jobs(goal_id, state, attempt_generation);

CREATE TABLE goal_root_turns (
    goal_id TEXT NOT NULL REFERENCES session_goals(id) ON DELETE CASCADE ON UPDATE RESTRICT,
    attempt_generation INTEGER NOT NULL,
    turn_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'finished', 'cancelled')),
    audit_excerpt TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(goal_id, attempt_generation, turn_id)
);

-- ---- session_text_artifacts --------------------------------------------------------------
-- Immutable, session-owned captured UTF-8.  The five counters keep host loss,
-- post-safety source, and stored representation separate; quota is always the
-- exact UTF-8 byte length of `content`.
--
-- `export_redacted` is not an ordinary storage representation.  It can only
-- enter through the archive-import composition, which first records an opaque
-- import provenance row.  A fork may retain that same provenance because it
-- is copying an irreversible imported body; it must never turn it into raw.
CREATE TABLE session_text_artifact_archive_imports (
    import_id TEXT PRIMARY KEY CHECK(
        typeof(import_id) = 'text' AND length(import_id) = 36
        AND substr(import_id, 9, 1) = '-' AND substr(import_id, 14, 1) = '-'
        AND substr(import_id, 19, 1) = '-' AND substr(import_id, 24, 1) = '-'
    ),
    imported_at INTEGER NOT NULL CHECK(typeof(imported_at) = 'integer' AND imported_at BETWEEN -9223372036854775808 AND 9223372036854775807)
);

CREATE TABLE session_text_artifacts (
    session_id TEXT NOT NULL CHECK(typeof(session_id) = 'text' AND length(session_id) > 0),
    artifact_id TEXT NOT NULL CHECK(
        typeof(artifact_id) = 'text' AND length(artifact_id) = 36
        AND substr(artifact_id, 9, 1) = '-' AND substr(artifact_id, 14, 1) = '-'
        AND substr(artifact_id, 19, 1) = '-' AND substr(artifact_id, 24, 1) = '-'
    ),
    kind TEXT NOT NULL CHECK(typeof(kind) = 'text' AND kind IN ('tool_result', 'user_input_source', 'user_input_projection')),
    capture_reason TEXT NOT NULL CHECK(typeof(capture_reason) = 'text' AND capture_reason IN ('display_truncation', 'prune_boundary', 'oversized_user_input')),
    content_representation TEXT NOT NULL CHECK(typeof(content_representation) = 'text' AND content_representation IN ('raw', 'export_redacted')),
    archive_import_id TEXT,
    owner_event_seq INTEGER NOT NULL CHECK(typeof(owner_event_seq) = 'integer' AND owner_event_seq > 0),
    owner_relation TEXT NOT NULL CHECK(typeof(owner_relation) = 'text' AND owner_relation IN ('source_user_input', 'model_user_input_projection', 'model_context_tool_result')),
    -- A source edge has no public projection slot.  The private -1 sentinel
    -- makes that nullable SQL shape participate in the owning FK below.
    owner_slot INTEGER NOT NULL CHECK(typeof(owner_slot) = 'integer' AND owner_slot >= -1),
    content TEXT NOT NULL CHECK(typeof(content) = 'text'),
    host_captured_bytes INTEGER NOT NULL CHECK(typeof(host_captured_bytes) = 'integer' AND host_captured_bytes BETWEEN 0 AND 9223372036854775807),
    host_original_bytes INTEGER NOT NULL CHECK(typeof(host_original_bytes) = 'integer' AND host_original_bytes BETWEEN 0 AND 9223372036854775807),
    host_dropped_bytes INTEGER NOT NULL CHECK(typeof(host_dropped_bytes) = 'integer' AND host_dropped_bytes BETWEEN 0 AND 9223372036854775807),
    stored_source_bytes INTEGER NOT NULL CHECK(typeof(stored_source_bytes) = 'integer' AND stored_source_bytes BETWEEN 0 AND 9223372036854775807),
    content_bytes INTEGER NOT NULL CHECK(typeof(content_bytes) = 'integer' AND content_bytes BETWEEN 1 AND 8388608),
    provenance_json TEXT NOT NULL CHECK(typeof(provenance_json) = 'text' AND length(CAST(provenance_json AS BLOB)) <= 256 AND json_valid(provenance_json) AND json_type(provenance_json) = 'object'),
    created_at INTEGER NOT NULL CHECK(typeof(created_at) = 'integer' AND created_at BETWEEN -9223372036854775808 AND 9223372036854775807),
    PRIMARY KEY(session_id, artifact_id),
    CHECK(host_original_bytes >= host_captured_bytes),
    CHECK(host_dropped_bytes = host_original_bytes - host_captured_bytes),
    CHECK(stored_source_bytes <= host_captured_bytes),
    CHECK(json_extract(provenance_json, '$.blob_path') IS NOT NULL OR content_bytes = length(CAST(content AS BLOB))),
    CHECK(content_bytes = stored_source_bytes),
    CHECK((kind = 'tool_result' AND capture_reason IN ('display_truncation', 'prune_boundary')) OR (kind IN ('user_input_source', 'user_input_projection') AND capture_reason = 'oversized_user_input')),
    CHECK((owner_relation = 'source_user_input' AND owner_slot = -1) OR (owner_relation <> 'source_user_input' AND owner_slot >= 0)),
    CHECK((content_representation = 'raw' AND archive_import_id IS NULL) OR (content_representation = 'export_redacted' AND archive_import_id IS NOT NULL)),
    FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY(archive_import_id) REFERENCES session_text_artifact_archive_imports(import_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    -- This deferred circular ownership FK is intentionally the database-level
    -- backstop for direct SQL: an artifact cannot commit without exactly its
    -- one matching ref, while the normal composition can insert the immutable
    -- body before its ref in the same transaction.
    FOREIGN KEY(session_id,artifact_id,owner_event_seq,owner_relation,owner_slot)
      REFERENCES session_text_artifact_event_refs(session_id,artifact_id,event_seq,relation,owner_slot)
      ON DELETE CASCADE ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX idx_session_text_artifacts_session_created
    ON session_text_artifacts(session_id, created_at, artifact_id);

-- Artifact bodies are immutable and have a canonical cockpit pseudofile, so
-- they may participate in `history_search` discovery without exposing the
-- whole body in the tool result. The owner event sequence carries the same
-- model-trust filter as message and compaction rows.
CREATE TRIGGER session_fts_artifacts_ai AFTER INSERT ON session_text_artifacts
BEGIN
    INSERT INTO session_fts_docs (row_kind, session_id, seq, artifact_id)
    VALUES ('artifact', new.session_id, new.owner_event_seq, new.artifact_id);
    INSERT INTO session_fts (rowid, body)
    VALUES (last_insert_rowid(), new.content);
END;

CREATE TRIGGER session_fts_artifacts_ad BEFORE DELETE ON session_text_artifacts
BEGIN
    INSERT INTO session_fts (session_fts, rowid, body)
    SELECT 'delete', rowid, old.content
    FROM session_fts_docs
    WHERE row_kind = 'artifact'
      AND session_id = old.session_id
      AND artifact_id = old.artifact_id;
    DELETE FROM session_fts_docs
    WHERE row_kind = 'artifact'
      AND session_id = old.session_id
      AND artifact_id = old.artifact_id;
END;

-- The accepted model-facing composition for an artifact-backed user turn.
-- Authored bytes are never duplicated here: the sole `authored_text` slot is
-- replaced with the durable artifact frame on live dispatch and rehydrate.
CREATE TABLE session_user_message_model_envelopes (
    session_id TEXT NOT NULL CHECK(typeof(session_id) = 'text' AND length(session_id) > 0),
    event_seq INTEGER NOT NULL CHECK(typeof(event_seq) = 'integer' AND event_seq > 0),
    envelope_json TEXT NOT NULL CHECK(typeof(envelope_json) = 'text' AND length(CAST(envelope_json AS BLOB)) <= 131072 AND json_valid(envelope_json) AND json_type(envelope_json) = 'object'),
    PRIMARY KEY(session_id, event_seq),
    FOREIGN KEY(session_id, event_seq) REFERENCES session_events(session_id, seq) ON DELETE CASCADE ON UPDATE RESTRICT
);

-- An accepted submission is immutable.  In particular, a restart must never
-- silently replace its already accepted model composition with whatever the
-- current driver happens to assemble.
CREATE TRIGGER session_user_message_model_envelopes_no_update
BEFORE UPDATE ON session_user_message_model_envelopes
BEGIN
    SELECT RAISE(ABORT, 'user message model envelope is immutable');
END;

CREATE TABLE session_text_artifact_event_refs (
    session_id TEXT NOT NULL CHECK(typeof(session_id) = 'text' AND length(session_id) > 0),
    event_seq INTEGER NOT NULL CHECK(typeof(event_seq) = 'integer' AND event_seq > 0),
    relation TEXT NOT NULL CHECK(typeof(relation) = 'text' AND relation IN ('source_user_input', 'model_user_input_projection', 'model_context_tool_result')),
    projection_slot INTEGER CHECK(projection_slot IS NULL OR (typeof(projection_slot) = 'integer' AND projection_slot >= 0)),
    owner_slot INTEGER NOT NULL CHECK(typeof(owner_slot) = 'integer' AND owner_slot >= -1),
    artifact_id TEXT NOT NULL CHECK(typeof(artifact_id) = 'text' AND length(artifact_id) = 36),
    PRIMARY KEY(session_id, artifact_id),
    FOREIGN KEY(session_id, event_seq) REFERENCES session_events(session_id, seq) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY(session_id, artifact_id) REFERENCES session_text_artifacts(session_id, artifact_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CHECK((relation = 'source_user_input' AND projection_slot IS NULL AND owner_slot = -1) OR (relation <> 'source_user_input' AND projection_slot IS NOT NULL AND owner_slot = projection_slot)),
    UNIQUE(session_id,artifact_id,event_seq,relation,owner_slot)
);
-- SQLite treats NULLs as distinct in a normal unique index, so these two
-- partial indexes are deliberately separate.
CREATE UNIQUE INDEX uq_text_artifact_source_slot
    ON session_text_artifact_event_refs(session_id, event_seq, relation)
    WHERE projection_slot IS NULL;
CREATE UNIQUE INDEX uq_text_artifact_model_slot
    ON session_text_artifact_event_refs(session_id, event_seq, relation, projection_slot)
    WHERE projection_slot IS NOT NULL;

-- Every durable `available` projection must be backed by exactly one ref at
-- commit. SQLite has deferred foreign keys but no deferred CHECK trigger, so
-- an event insert creates one deliberately-unsatisfied, deferred pending row
-- per declared available slot. The matching immutable ref clears that row in
-- the same outer composition transaction. The sentinel intentionally has no
-- rows and its write guards make it impossible to satisfy a pending row by
-- direct SQL instead of supplying the owner ref.
CREATE TABLE session_text_artifact_projection_pending_sentinel (
    unresolved INTEGER PRIMARY KEY CHECK(unresolved = 1)
);

CREATE TABLE session_text_artifact_projection_pending_slots (
    session_id TEXT NOT NULL,
    event_seq INTEGER NOT NULL,
    projection_slot INTEGER NOT NULL CHECK(typeof(projection_slot) = 'integer' AND projection_slot >= 0),
    unresolved INTEGER NOT NULL DEFAULT 1 CHECK(unresolved = 1),
    PRIMARY KEY(session_id, event_seq, projection_slot),
    FOREIGN KEY(session_id, event_seq) REFERENCES session_events(session_id, seq) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY(unresolved) REFERENCES session_text_artifact_projection_pending_sentinel(unresolved)
        ON DELETE RESTRICT ON UPDATE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TRIGGER text_artifact_projection_pending_sentinel_reject_insert
BEFORE INSERT ON session_text_artifact_projection_pending_sentinel
BEGIN SELECT RAISE(ABORT, 'text artifact projection pending sentinel is not writable'); END;
CREATE TRIGGER text_artifact_projection_pending_sentinel_reject_update
BEFORE UPDATE ON session_text_artifact_projection_pending_sentinel
BEGIN SELECT RAISE(ABORT, 'text artifact projection pending sentinel is immutable'); END;
CREATE TRIGGER text_artifact_projection_pending_sentinel_reject_delete
BEFORE DELETE ON session_text_artifact_projection_pending_sentinel
BEGIN SELECT RAISE(ABORT, 'text artifact projection pending sentinel is immutable'); END;

-- Validate the entire declared durable state before a ref exists. The ref
-- trigger below then binds each available state to its exact immutable body;
-- this trigger closes the opposite direction (including all-unavailable
-- prune arrays, which otherwise have no ref insertion to inspect).
CREATE TRIGGER text_artifact_projection_event_validate_insert
AFTER INSERT ON session_events
WHEN NEW.type IN ('tool_call', 'context_pruned')
 AND (
    json_type(NEW.data_json, '$.artifact_projection') IS NOT NULL
    OR json_type(NEW.data_json, '$.artifact_projections') IS NOT NULL
 )
BEGIN
    SELECT CASE WHEN NEW.type = 'tool_call' AND NOT EXISTS (
        SELECT 1
         WHERE json_type(NEW.data_json, '$.artifact_projection') = 'object'
           AND json_type(NEW.data_json, '$.artifact_projections') IS NULL
           AND (SELECT count(*) FROM json_each(json_extract(NEW.data_json, '$.artifact_projection'))) = 15
           AND json_extract(NEW.data_json, '$.artifact_projection.version') = 1
           AND json_type(NEW.data_json, '$.artifact_projection.status') = 'text'
           AND json_extract(NEW.data_json, '$.artifact_projection.status') IN ('available', 'unavailable')
	           AND ((json_extract(NEW.data_json, '$.artifact_projection.status') = 'available'
	                 AND json_type(NEW.data_json, '$.artifact_projection.reason') = 'null')
	                OR (json_extract(NEW.data_json, '$.artifact_projection.status') = 'unavailable'
	                    AND json_type(NEW.data_json, '$.artifact_projection.reason') = 'text'
		                    AND json_extract(NEW.data_json, '$.artifact_projection.reason') IN ('artifact_limit', 'session_quota', 'persistence_unavailable')))
           AND json_extract(NEW.data_json, '$.artifact_projection.kind') = 'tool_result'
           AND json_extract(NEW.data_json, '$.artifact_projection.capture_reason') = 'display_truncation'
           AND json_type(NEW.data_json, '$.artifact_projection.projection_slot') = 'integer'
           AND json_extract(NEW.data_json, '$.artifact_projection.projection_slot') = 0
           AND json_type(NEW.data_json, '$.artifact_projection.host_captured_bytes') = 'integer'
           AND json_extract(NEW.data_json, '$.artifact_projection.host_captured_bytes') >= 0
           AND json_type(NEW.data_json, '$.artifact_projection.host_original_bytes') = 'integer'
           AND json_extract(NEW.data_json, '$.artifact_projection.host_original_bytes') >= json_extract(NEW.data_json, '$.artifact_projection.host_captured_bytes')
           AND json_type(NEW.data_json, '$.artifact_projection.host_dropped_bytes') = 'integer'
           AND json_extract(NEW.data_json, '$.artifact_projection.host_dropped_bytes') = json_extract(NEW.data_json, '$.artifact_projection.host_original_bytes') - json_extract(NEW.data_json, '$.artifact_projection.host_captured_bytes')
           AND json_type(NEW.data_json, '$.artifact_projection.stored_source_bytes') = 'integer'
           AND (json_extract(NEW.data_json, '$.artifact_projection.stored_source_bytes') BETWEEN 1 AND json_extract(NEW.data_json, '$.artifact_projection.host_captured_bytes')
                OR (json_extract(NEW.data_json, '$.artifact_projection.reason') = 'persistence_unavailable'
                    AND json_extract(NEW.data_json, '$.artifact_projection.stored_source_bytes') = 0))
           AND json_type(NEW.data_json, '$.artifact_projection.content_bytes') = 'integer'
           AND json_extract(NEW.data_json, '$.artifact_projection.content_bytes') = json_extract(NEW.data_json, '$.artifact_projection.stored_source_bytes')
           -- `artifact_limit` means this exact candidate exceeded the per-artifact
           -- cap; `session_quota` is only meaningful for a candidate that could
           -- otherwise fit; `persistence_unavailable` owns no stored body at all.
           -- Keep that closed durable meaning true even when a direct SQL caller
           -- writes an unavailable-only projection with no ref.
           AND (json_extract(NEW.data_json, '$.artifact_projection.status') = 'available'
                OR (json_extract(NEW.data_json, '$.artifact_projection.reason') = 'artifact_limit'
                    AND json_extract(NEW.data_json, '$.artifact_projection.content_bytes') > 8388608)
                OR (json_extract(NEW.data_json, '$.artifact_projection.reason') = 'session_quota'
                    AND json_extract(NEW.data_json, '$.artifact_projection.content_bytes') <= 8388608)
                OR (json_extract(NEW.data_json, '$.artifact_projection.reason') = 'persistence_unavailable'
                    AND json_extract(NEW.data_json, '$.artifact_projection.content_bytes') = 0))
           AND json_type(NEW.data_json, '$.artifact_projection.line_count') = 'integer'
           AND (json_extract(NEW.data_json, '$.artifact_projection.line_count') >= 1
                OR (json_extract(NEW.data_json, '$.artifact_projection.reason') = 'persistence_unavailable'
                    AND json_extract(NEW.data_json, '$.artifact_projection.line_count') = 0))
           AND json_type(NEW.data_json, '$.artifact_projection.preview_head') = 'text'
           AND json_type(NEW.data_json, '$.artifact_projection.preview_tail') = 'text'
           AND json_type(NEW.data_json, '$.artifact_projection.provenance') = 'object'
           AND (SELECT count(*) FROM json_each(json_extract(NEW.data_json, '$.artifact_projection.provenance'))) = 3
           AND json_type(NEW.data_json, '$.artifact_projection.provenance.tool') = 'text'
           AND length(CAST(json_extract(NEW.data_json, '$.artifact_projection.provenance.tool') AS BLOB)) BETWEEN 1 AND 256
           AND json_extract(NEW.data_json, '$.artifact_projection.provenance.tool') NOT GLOB '*[' || char(1) || '-' || char(31) || ']*'
           AND json_type(NEW.data_json, '$.artifact_projection.provenance.call_id') = 'text'
           AND length(CAST(json_extract(NEW.data_json, '$.artifact_projection.provenance.call_id') AS BLOB)) BETWEEN 1 AND 256
           AND json_extract(NEW.data_json, '$.artifact_projection.provenance.call_id') NOT GLOB '*[' || char(1) || '-' || char(31) || ']*'
           AND json_extract(NEW.data_json, '$.artifact_projection.provenance.call_id') = NEW.call_id
           AND (json_type(NEW.data_json, '$.artifact_projection.provenance.agent_id') = 'null'
                OR (json_type(NEW.data_json, '$.artifact_projection.provenance.agent_id') = 'text'
                    AND length(CAST(json_extract(NEW.data_json, '$.artifact_projection.provenance.agent_id') AS BLOB)) <= 256
                    AND json_extract(NEW.data_json, '$.artifact_projection.provenance.agent_id') NOT GLOB '*[' || char(1) || '-' || char(31) || ']*'))
           AND ((json_type(NEW.data_json, '$.artifact_projection.provenance.agent_id') = 'null' AND NEW.agent IS NULL)
                OR json_extract(NEW.data_json, '$.artifact_projection.provenance.agent_id') = NEW.agent)
    ) THEN RAISE(ABORT, 'tool artifact durable projection declaration is invalid') END;

    SELECT CASE WHEN NEW.type = 'context_pruned' AND NOT EXISTS (
        SELECT 1
         WHERE json_type(NEW.data_json, '$.artifact_projections') = 'array'
           AND json_type(NEW.data_json, '$.artifact_projection') IS NULL
           AND json_array_length(NEW.data_json, '$.artifact_projections') > 0
           AND NOT EXISTS (
               SELECT 1 FROM json_each(NEW.data_json, '$.artifact_projections') p
                WHERE json_type(p.value) IS NOT 'object'
                   OR (SELECT count(*) FROM json_each(p.value)) IS NOT 15
                   OR json_extract(p.value, '$.version') IS NOT 1
                   OR json_type(p.value, '$.status') IS NOT 'text'
                   OR (json_extract(p.value, '$.status') IS NOT 'available'
                       AND json_extract(p.value, '$.status') IS NOT 'unavailable')
                   OR (json_extract(p.value, '$.status') = 'available'
                       AND json_type(p.value, '$.reason') IS NOT 'null')
                   OR (json_extract(p.value, '$.status') = 'unavailable'
                       AND (json_type(p.value, '$.reason') IS NOT 'text'
                            OR (json_extract(p.value, '$.reason') IS NOT 'artifact_limit'
                                AND json_extract(p.value, '$.reason') IS NOT 'session_quota')))
                   OR json_extract(p.value, '$.kind') IS NOT 'tool_result'
                   OR json_extract(p.value, '$.capture_reason') IS NOT 'prune_boundary'
                   OR json_type(p.value, '$.projection_slot') IS NOT 'integer'
                   OR json_extract(p.value, '$.projection_slot') IS NOT CAST(p.key AS INTEGER)
                   OR json_type(p.value, '$.host_captured_bytes') IS NOT 'integer'
                   OR json_extract(p.value, '$.host_captured_bytes') < 0
                   OR json_type(p.value, '$.host_original_bytes') IS NOT 'integer'
                   OR json_extract(p.value, '$.host_original_bytes') < json_extract(p.value, '$.host_captured_bytes')
                   OR json_type(p.value, '$.host_dropped_bytes') IS NOT 'integer'
                   OR json_extract(p.value, '$.host_dropped_bytes') IS NOT json_extract(p.value, '$.host_original_bytes') - json_extract(p.value, '$.host_captured_bytes')
                   OR json_type(p.value, '$.stored_source_bytes') IS NOT 'integer'
                   OR json_extract(p.value, '$.stored_source_bytes') NOT BETWEEN 1 AND json_extract(p.value, '$.host_captured_bytes')
	                   OR json_type(p.value, '$.content_bytes') IS NOT 'integer'
	                   OR json_extract(p.value, '$.content_bytes') IS NOT json_extract(p.value, '$.stored_source_bytes')
	                   OR (json_extract(p.value, '$.status') = 'unavailable'
	                       AND ((json_extract(p.value, '$.reason') = 'artifact_limit'
	                             AND json_extract(p.value, '$.content_bytes') <= 8388608)
	                            OR (json_extract(p.value, '$.reason') = 'session_quota'
	                                AND json_extract(p.value, '$.content_bytes') > 8388608)))
	                   OR json_type(p.value, '$.line_count') IS NOT 'integer'
                   OR json_extract(p.value, '$.line_count') < 1
                   OR json_type(p.value, '$.preview_head') IS NOT 'text'
                   OR json_type(p.value, '$.preview_tail') IS NOT 'text'
                   OR json_type(p.value, '$.provenance') IS NOT 'object'
                   OR (SELECT count(*) FROM json_each(json_extract(p.value, '$.provenance'))) IS NOT 3
                   OR json_type(p.value, '$.provenance.tool') IS NOT 'text'
                   OR length(CAST(json_extract(p.value, '$.provenance.tool') AS BLOB)) NOT BETWEEN 1 AND 256
                   OR json_extract(p.value, '$.provenance.tool') GLOB '*[' || char(1) || '-' || char(31) || ']*'
                   OR json_type(p.value, '$.provenance.call_id') IS NOT 'text'
                   OR length(CAST(json_extract(p.value, '$.provenance.call_id') AS BLOB)) NOT BETWEEN 1 AND 256
                   OR json_extract(p.value, '$.provenance.call_id') GLOB '*[' || char(1) || '-' || char(31) || ']*'
                   OR (json_type(p.value, '$.provenance.agent_id') IS NOT 'text'
                       AND json_type(p.value, '$.provenance.agent_id') IS NOT 'null')
                   OR (json_type(p.value, '$.provenance.agent_id') = 'text'
                       AND (length(CAST(json_extract(p.value, '$.provenance.agent_id') AS BLOB)) > 256
                            OR json_extract(p.value, '$.provenance.agent_id') GLOB '*[' || char(1) || '-' || char(31) || ']*'))
                   OR ((json_type(p.value, '$.provenance.agent_id') = 'null' AND NEW.agent IS NOT NULL)
                       OR (json_type(p.value, '$.provenance.agent_id') = 'text'
                           AND json_extract(p.value, '$.provenance.agent_id') IS NOT NEW.agent))
           )
    ) THEN RAISE(ABORT, 'context-pruned text artifact projection declaration is invalid') END;

    INSERT INTO session_text_artifact_projection_pending_slots(session_id,event_seq,projection_slot)
    SELECT NEW.session_id, NEW.seq, 0
     WHERE NEW.type = 'tool_call'
       AND json_extract(NEW.data_json, '$.artifact_projection.status') = 'available';

    INSERT INTO session_text_artifact_projection_pending_slots(session_id,event_seq,projection_slot)
    SELECT NEW.session_id, NEW.seq, CAST(p.key AS INTEGER)
      FROM json_each(NEW.data_json, '$.artifact_projections') p
     WHERE NEW.type = 'context_pruned'
       AND json_extract(p.value, '$.status') = 'available';
END;

CREATE TRIGGER text_artifact_projection_pending_reject_update
BEFORE UPDATE ON session_text_artifact_projection_pending_slots
BEGIN SELECT RAISE(ABORT, 'text artifact projection pending state is immutable'); END;
-- A pending declaration can clear only after the matching immutable owner
-- edge exists. Parent cascades remain legal because their event/session is
-- already absent when the child row is reached.
CREATE TRIGGER text_artifact_projection_pending_reject_unresolved_delete
BEFORE DELETE ON session_text_artifact_projection_pending_slots
WHEN EXISTS (SELECT 1 FROM sessions s WHERE s.session_id = OLD.session_id)
 AND EXISTS (
     SELECT 1 FROM session_events e
      WHERE e.session_id = OLD.session_id AND e.seq = OLD.event_seq
 )
 AND NOT EXISTS (
     SELECT 1 FROM session_text_artifact_event_refs r
      WHERE r.session_id = OLD.session_id AND r.event_seq = OLD.event_seq
        AND r.relation = 'model_context_tool_result'
        AND r.projection_slot = OLD.projection_slot
 )
BEGIN SELECT RAISE(ABORT, 'available text artifact projection lacks its owner ref'); END;

CREATE TRIGGER text_artifact_ref_clear_projection_pending
AFTER INSERT ON session_text_artifact_event_refs
WHEN NEW.relation = 'model_context_tool_result'
BEGIN
    DELETE FROM session_text_artifact_projection_pending_slots
     WHERE session_id = NEW.session_id AND event_seq = NEW.event_seq
       AND projection_slot = NEW.projection_slot;
END;

CREATE TRIGGER text_artifact_ref_validate_insert
BEFORE INSERT ON session_text_artifact_event_refs
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM session_text_artifacts a
         WHERE a.session_id = NEW.session_id AND a.artifact_id = NEW.artifact_id
    ) THEN RAISE(ABORT, 'text artifact reference must own a same-session artifact') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM session_text_artifacts a
         WHERE a.session_id = NEW.session_id AND a.artifact_id = NEW.artifact_id
           AND a.owner_event_seq = NEW.event_seq AND a.owner_relation = NEW.relation
           AND a.owner_slot = NEW.owner_slot
    ) THEN RAISE(ABORT, 'text artifact reference must match its immutable owner') END;
    SELECT CASE WHEN NEW.relation = 'source_user_input' AND NOT EXISTS (
        SELECT 1 FROM session_text_artifacts a JOIN session_events e
          ON e.session_id = NEW.session_id AND e.seq = NEW.event_seq
         WHERE a.session_id = NEW.session_id AND a.artifact_id = NEW.artifact_id
           AND a.kind = 'user_input_source' AND a.capture_reason = 'oversized_user_input'
           AND a.content_bytes > 65536
           AND e.type = 'user_message'
           AND json_type(a.provenance_json, '$.event_seq') = 'integer'
           AND (SELECT count(*) FROM json_each(a.provenance_json)) = 1
           AND json_extract(a.provenance_json, '$.event_seq') = NEW.event_seq
           AND json_type(e.data_json, '$.text') = 'text'
           AND json_extract(e.data_json, '$.text') = a.content
    ) THEN RAISE(ABORT, 'source user artifact binding is invalid') END;
    SELECT CASE WHEN NEW.relation = 'model_user_input_projection' AND NOT EXISTS (
        SELECT 1 FROM session_text_artifacts a JOIN session_events e
          ON e.session_id = NEW.session_id AND e.seq = NEW.event_seq
         WHERE a.session_id = NEW.session_id AND a.artifact_id = NEW.artifact_id
           AND a.kind = 'user_input_projection' AND a.capture_reason = 'oversized_user_input'
           AND NEW.projection_slot = 0 AND e.type = 'user_message'
           AND json_type(a.provenance_json, '$.source_artifact_id') = 'text'
           AND json_type(a.provenance_json, '$.preprocessing_version') = 'integer'
           AND json_extract(a.provenance_json, '$.preprocessing_version') = 1
           AND (SELECT count(*) FROM json_each(a.provenance_json)) = 2
           AND EXISTS (
               SELECT 1 FROM session_text_artifact_event_refs source_ref
               JOIN session_text_artifacts source ON source.session_id = source_ref.session_id AND source.artifact_id = source_ref.artifact_id
                WHERE source_ref.session_id = NEW.session_id AND source_ref.event_seq = NEW.event_seq
                  AND source_ref.relation = 'source_user_input' AND source_ref.projection_slot IS NULL
                  AND source.artifact_id = json_extract(a.provenance_json, '$.source_artifact_id')
                  AND source.content <> a.content
           )
    ) THEN RAISE(ABORT, 'derived user artifact binding is invalid') END;
    SELECT CASE WHEN NEW.relation = 'model_context_tool_result' AND NOT EXISTS (
        SELECT 1 FROM session_text_artifacts a JOIN session_events e
          ON e.session_id = NEW.session_id AND e.seq = NEW.event_seq
         WHERE a.session_id = NEW.session_id AND a.artifact_id = NEW.artifact_id
           AND a.kind = 'tool_result' AND e.type IN ('tool_call', 'context_pruned')
           AND (
               (e.type = 'tool_call' AND a.capture_reason = 'display_truncation' AND NEW.projection_slot = 0)
               OR (e.type = 'context_pruned' AND a.capture_reason = 'prune_boundary')
           )
           AND json_type(a.provenance_json, '$.tool') = 'text'
           AND length(CAST(json_extract(a.provenance_json, '$.tool') AS BLOB)) BETWEEN 1 AND 256
           AND json_extract(a.provenance_json, '$.tool') NOT GLOB '*[' || char(1) || '-' || char(31) || ']*'
           AND json_type(a.provenance_json, '$.call_id') = 'text'
           AND length(CAST(json_extract(a.provenance_json, '$.call_id') AS BLOB)) BETWEEN 1 AND 256
           AND json_extract(a.provenance_json, '$.call_id') NOT GLOB '*[' || char(1) || '-' || char(31) || ']*'
           AND (
               json_type(a.provenance_json, '$.agent_id') = 'null'
               OR (
                   json_type(a.provenance_json, '$.agent_id') = 'text'
                   AND length(CAST(json_extract(a.provenance_json, '$.agent_id') AS BLOB)) BETWEEN 1 AND 256
                   AND json_extract(a.provenance_json, '$.agent_id') NOT GLOB '*[' || char(1) || '-' || char(31) || ']*'
               )
           )
           AND (
               (json_type(a.provenance_json, '$.agent_id') = 'null' AND e.agent IS NULL)
               OR json_extract(a.provenance_json, '$.agent_id') = e.agent
           )
           AND (
               e.type = 'context_pruned'
               OR json_extract(a.provenance_json, '$.call_id') = e.call_id
           )
           AND (SELECT count(*) FROM json_each(a.provenance_json)) = 3
    ) THEN RAISE(ABORT, 'tool artifact binding is invalid') END;
    -- The event-owned projection state is the authority for model context.
    -- Do not allow direct SQL to attach a real body to a made-up tool slot,
    -- a stale single projection, or a sparse/misaligned prune array.
    SELECT CASE WHEN NEW.relation = 'model_context_tool_result' AND NOT EXISTS (
        SELECT 1
          FROM session_text_artifacts a
          JOIN session_events e ON e.session_id = NEW.session_id AND e.seq = NEW.event_seq
         WHERE a.session_id = NEW.session_id AND a.artifact_id = NEW.artifact_id
           AND (
                (
                    e.type = 'tool_call' AND NEW.projection_slot = 0
                    AND json_type(e.data_json, '$.artifact_projection') = 'object'
                    AND json_type(e.data_json, '$.artifact_projections') IS NULL
                    AND (SELECT count(*) FROM json_each(json_extract(e.data_json, '$.artifact_projection'))) = 15
                    AND json_extract(e.data_json, '$.artifact_projection.version') = 1
                    AND json_extract(e.data_json, '$.artifact_projection.status') = 'available'
                    AND json_type(e.data_json, '$.artifact_projection.reason') = 'null'
                    AND json_extract(e.data_json, '$.artifact_projection.kind') = 'tool_result'
                    AND json_extract(e.data_json, '$.artifact_projection.capture_reason') = a.capture_reason
                    AND json_extract(e.data_json, '$.artifact_projection.projection_slot') = 0
                    AND json_type(e.data_json, '$.artifact_projection.host_captured_bytes') = 'integer'
                    AND json_extract(e.data_json, '$.artifact_projection.host_captured_bytes') = a.host_captured_bytes
                    AND json_type(e.data_json, '$.artifact_projection.host_original_bytes') = 'integer'
                    AND json_extract(e.data_json, '$.artifact_projection.host_original_bytes') = a.host_original_bytes
                    AND json_type(e.data_json, '$.artifact_projection.host_dropped_bytes') = 'integer'
                    AND json_extract(e.data_json, '$.artifact_projection.host_dropped_bytes') = a.host_dropped_bytes
                    AND json_type(e.data_json, '$.artifact_projection.stored_source_bytes') = 'integer'
                    AND json_extract(e.data_json, '$.artifact_projection.stored_source_bytes') = a.stored_source_bytes
                    AND json_type(e.data_json, '$.artifact_projection.content_bytes') = 'integer'
                    AND json_extract(e.data_json, '$.artifact_projection.content_bytes') = a.content_bytes
                    AND json_type(e.data_json, '$.artifact_projection.line_count') = 'integer'
                    AND json_extract(e.data_json, '$.artifact_projection.line_count') =
                        length(a.content) - length(replace(a.content, char(10), ''))
                        + CASE WHEN substr(a.content, -1) = char(10) THEN 0 ELSE 1 END
                    AND json_type(e.data_json, '$.artifact_projection.preview_head') = 'text'
                    AND json_type(e.data_json, '$.artifact_projection.preview_tail') = 'text'
                    AND json_type(e.data_json, '$.artifact_projection.provenance') = 'object'
                    AND (SELECT count(*) FROM json_each(json_extract(e.data_json, '$.artifact_projection.provenance'))) = 3
                    AND json_extract(e.data_json, '$.artifact_projection.provenance.tool') = json_extract(a.provenance_json, '$.tool')
                    AND json_extract(e.data_json, '$.artifact_projection.provenance.call_id') = json_extract(a.provenance_json, '$.call_id')
                    AND json_type(e.data_json, '$.artifact_projection.provenance.agent_id') = json_type(a.provenance_json, '$.agent_id')
                    AND (json_type(a.provenance_json, '$.agent_id') = 'null' OR json_extract(e.data_json, '$.artifact_projection.provenance.agent_id') = json_extract(a.provenance_json, '$.agent_id'))
                )
                OR (
                    e.type = 'context_pruned'
                    AND json_type(e.data_json, '$.artifact_projections') = 'array'
                    AND json_type(e.data_json, '$.artifact_projection') IS NULL
                    AND json_array_length(e.data_json, '$.artifact_projections') > NEW.projection_slot
                    AND NOT EXISTS (
                        SELECT 1 FROM json_each(e.data_json, '$.artifact_projections') p
                         WHERE json_type(p.value) IS NOT 'object'
                            OR (SELECT count(*) FROM json_each(p.value)) IS NOT 15
                            OR json_extract(p.value, '$.version') IS NOT 1
                            OR json_type(p.value, '$.projection_slot') IS NOT 'integer'
                            OR json_extract(p.value, '$.projection_slot') IS NOT CAST(p.key AS INTEGER)
                            OR json_type(p.value, '$.status') IS NOT 'text'
                            OR (json_extract(p.value, '$.status') IS NOT 'available'
                                AND json_extract(p.value, '$.status') IS NOT 'unavailable')
                            OR (json_extract(p.value, '$.status') = 'available'
                                AND json_type(p.value, '$.reason') IS NOT 'null')
                            OR (json_extract(p.value, '$.status') = 'unavailable'
                                AND (json_type(p.value, '$.reason') IS NOT 'text'
                                     OR (json_extract(p.value, '$.reason') IS NOT 'artifact_limit'
                                         AND json_extract(p.value, '$.reason') IS NOT 'session_quota')))
                            OR json_extract(p.value, '$.kind') IS NOT 'tool_result'
                            OR json_extract(p.value, '$.capture_reason') IS NOT 'prune_boundary'
                            OR json_type(p.value, '$.host_captured_bytes') IS NOT 'integer'
                            OR json_extract(p.value, '$.host_captured_bytes') < 0
                            OR json_type(p.value, '$.host_original_bytes') IS NOT 'integer'
                            OR json_extract(p.value, '$.host_original_bytes') < json_extract(p.value, '$.host_captured_bytes')
                            OR json_type(p.value, '$.host_dropped_bytes') IS NOT 'integer'
                            OR json_extract(p.value, '$.host_dropped_bytes') IS NOT json_extract(p.value, '$.host_original_bytes') - json_extract(p.value, '$.host_captured_bytes')
                            OR json_type(p.value, '$.stored_source_bytes') IS NOT 'integer'
                            OR json_extract(p.value, '$.stored_source_bytes') < 0
                            OR json_extract(p.value, '$.stored_source_bytes') > json_extract(p.value, '$.host_captured_bytes')
                            OR json_type(p.value, '$.content_bytes') IS NOT 'integer'
                            OR json_extract(p.value, '$.content_bytes') IS NOT json_extract(p.value, '$.stored_source_bytes')
                            OR json_type(p.value, '$.line_count') IS NOT 'integer'
                            OR json_extract(p.value, '$.line_count') < 1
                            OR json_type(p.value, '$.preview_head') IS NOT 'text'
                            OR json_type(p.value, '$.preview_tail') IS NOT 'text'
                            OR json_type(p.value, '$.provenance') IS NOT 'object'
                            OR (SELECT count(*) FROM json_each(json_extract(p.value, '$.provenance'))) IS NOT 3
                            OR json_type(p.value, '$.provenance.tool') IS NOT 'text'
                            OR json_type(p.value, '$.provenance.call_id') IS NOT 'text'
                            OR (json_type(p.value, '$.provenance.agent_id') IS NOT 'text'
                                AND json_type(p.value, '$.provenance.agent_id') IS NOT 'null')
                    )
                    AND json_extract(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].version') = 1
                    AND json_extract(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].status') = 'available'
                    AND json_type(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].reason') = 'null'
                    AND json_extract(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].kind') = 'tool_result'
                    AND json_extract(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].capture_reason') = a.capture_reason
                    AND json_extract(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].projection_slot') = NEW.projection_slot
                    AND json_type(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].host_captured_bytes') = 'integer'
                    AND json_extract(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].host_captured_bytes') = a.host_captured_bytes
                    AND json_type(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].host_original_bytes') = 'integer'
                    AND json_extract(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].host_original_bytes') = a.host_original_bytes
                    AND json_type(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].host_dropped_bytes') = 'integer'
                    AND json_extract(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].host_dropped_bytes') = a.host_dropped_bytes
                    AND json_type(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].stored_source_bytes') = 'integer'
                    AND json_extract(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].stored_source_bytes') = a.stored_source_bytes
                    AND json_type(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].content_bytes') = 'integer'
                    AND json_extract(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].content_bytes') = a.content_bytes
                    AND json_type(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].line_count') = 'integer'
                    AND json_extract(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].line_count') =
                        length(a.content) - length(replace(a.content, char(10), ''))
                        + CASE WHEN substr(a.content, -1) = char(10) THEN 0 ELSE 1 END
                    AND json_type(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].preview_head') = 'text'
                    AND json_type(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].preview_tail') = 'text'
                    AND json_type(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].provenance') = 'object'
                    AND (SELECT count(*) FROM json_each(json_extract(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].provenance'))) = 3
                    AND json_extract(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].provenance.tool') = json_extract(a.provenance_json, '$.tool')
                    AND json_extract(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].provenance.call_id') = json_extract(a.provenance_json, '$.call_id')
                    AND json_type(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].provenance.agent_id') = json_type(a.provenance_json, '$.agent_id')
                    AND (json_type(a.provenance_json, '$.agent_id') = 'null' OR json_extract(e.data_json, '$.artifact_projections[' || NEW.projection_slot || '].provenance.agent_id') = json_extract(a.provenance_json, '$.agent_id'))
                )
           )
    ) THEN RAISE(ABORT, 'tool artifact durable projection state is invalid') END;
END;
CREATE TRIGGER text_artifact_ref_reject_update
BEFORE UPDATE ON session_text_artifact_event_refs
BEGIN SELECT RAISE(ABORT, 'session text artifact references are immutable'); END;
-- Deleting an edge directly would make an otherwise-available canonical event
-- unreconstructable. Event/session cascades remain legal: SQLite has already
-- removed the owning event/session before their child edge is visited.
CREATE TRIGGER text_artifact_ref_reject_independent_delete
BEFORE DELETE ON session_text_artifact_event_refs
WHEN EXISTS (
    SELECT 1 FROM sessions s WHERE s.session_id = OLD.session_id
)
 AND EXISTS (
    SELECT 1 FROM session_events e
     WHERE e.session_id = OLD.session_id AND e.seq = OLD.event_seq
)
BEGIN SELECT RAISE(ABORT, 'session text artifact references may only be deleted by their owner cascade'); END;
CREATE TRIGGER text_artifact_reject_update
BEFORE UPDATE ON session_text_artifacts
BEGIN SELECT RAISE(ABORT, 'session text artifacts are immutable'); END;
-- An artifact can disappear only via its owner/event/session cascade.  This
-- closes the direct-SQL delete escape hatch without interfering with FK
-- cascades: by the time a parent ref/event/session cascade reaches this row,
-- the owning ref or session is no longer visible.
CREATE TRIGGER text_artifact_reject_independent_delete
BEFORE DELETE ON session_text_artifacts
WHEN EXISTS (SELECT 1 FROM sessions s WHERE s.session_id = OLD.session_id)
 AND EXISTS (
     SELECT 1 FROM session_text_artifact_event_refs r
      WHERE r.session_id = OLD.session_id AND r.artifact_id = OLD.artifact_id
 )
BEGIN SELECT RAISE(ABORT, 'session text artifacts may only be deleted by their owner cascade'); END;
-- Once a typed projection has an owner edge, its event JSON is immutable as
-- well. Without this guard direct SQL could rewrite an available slot after
-- the ref trigger proved its state, breaking restart/rehydration determinism.
CREATE TRIGGER text_artifact_projection_event_reject_update
BEFORE UPDATE OF data_json ON session_events
WHEN OLD.type IN ('tool_call', 'context_pruned')
 AND (
    json_type(OLD.data_json, '$.artifact_projection') IS NOT NULL
    OR json_type(OLD.data_json, '$.artifact_projections') IS NOT NULL
    OR json_type(NEW.data_json, '$.artifact_projection') IS NOT NULL
    OR json_type(NEW.data_json, '$.artifact_projections') IS NOT NULL
 )
BEGIN SELECT RAISE(ABORT, 'session text artifact projection state is immutable'); END;
CREATE TABLE session_text_artifact_quota_reservations (
    session_id TEXT NOT NULL CHECK(typeof(session_id) = 'text' AND length(session_id) > 0),
    client_submission_id BLOB NOT NULL CHECK(typeof(client_submission_id) = 'blob' AND length(client_submission_id) = 16 AND client_submission_id <> zeroblob(16)),
    operation_id BLOB NOT NULL CHECK(typeof(operation_id) = 'blob' AND length(operation_id) = 16 AND operation_id <> zeroblob(16)),
    queue_item_id BLOB NOT NULL CHECK(typeof(queue_item_id) = 'blob' AND length(queue_item_id) = 16 AND queue_item_id <> zeroblob(16)),
    source_digest BLOB NOT NULL CHECK(typeof(source_digest) = 'blob' AND length(source_digest) = 32),
    source_bytes INTEGER NOT NULL CHECK(typeof(source_bytes) = 'integer' AND source_bytes BETWEEN 65537 AND 8388608),
    reserved_bytes INTEGER NOT NULL CHECK(typeof(reserved_bytes) = 'integer' AND reserved_bytes = source_bytes + 8388608),
    -- Set only by the atomic oversized-run phase-one composition. It makes
    -- terminalization ownership explicit instead of inferring it from a UUID
    -- that can also name an unrelated global invocation.
    run_invocation_bound INTEGER NOT NULL DEFAULT 0 CHECK(typeof(run_invocation_bound) = 'integer' AND run_invocation_bound IN (0, 1)),
    -- Explicit model fences are outside frozen FCM2 v2 bytes. Generation is a
    -- canonical decimal u64 and the model is a bounded JSON object; the pair
    -- is all-or-nothing so restart cannot degrade an explicit request.
    model_fence_generation TEXT CHECK(model_fence_generation IS NULL OR (typeof(model_fence_generation) = 'text' AND model_fence_generation NOT GLOB '*[^0-9]*' AND length(model_fence_generation) BETWEEN 1 AND 20 AND (model_fence_generation = '0' OR substr(model_fence_generation, 1, 1) <> '0') AND (length(model_fence_generation) < 20 OR model_fence_generation <= '18446744073709551615'))),
    model_fence_json TEXT CHECK(model_fence_json IS NULL OR (typeof(model_fence_json) = 'text' AND length(CAST(model_fence_json AS BLOB)) <= 8192 AND json_valid(model_fence_json) AND json_type(model_fence_json) = 'object' AND json(model_fence_json) = model_fence_json)),
    lease_token TEXT NOT NULL CHECK(typeof(lease_token) = 'text' AND length(lease_token) = 36
        AND substr(lease_token, 9, 1) = '-' AND substr(lease_token, 14, 1) = '-'
        AND substr(lease_token, 19, 1) = '-' AND substr(lease_token, 24, 1) = '-'),
    expires_at INTEGER NOT NULL CHECK(typeof(expires_at) = 'integer' AND expires_at BETWEEN -9223372036854775808 AND 9223372036854775807),
    created_at INTEGER NOT NULL CHECK(typeof(created_at) = 'integer' AND created_at BETWEEN -9223372036854775808 AND 9223372036854775807),
    updated_at INTEGER NOT NULL CHECK(typeof(updated_at) = 'integer' AND updated_at BETWEEN -9223372036854775808 AND 9223372036854775807),
    PRIMARY KEY(session_id, client_submission_id),
    CHECK((model_fence_generation IS NULL) = (model_fence_json IS NULL)),
    FOREIGN KEY(session_id, client_submission_id) REFERENCES message_submission_receipts(session_id, client_submission_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY(session_id, operation_id) REFERENCES message_operation_receipts(session_id, operation_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY(session_id, queue_item_id) REFERENCES message_queue_items(session_id, queue_item_id) ON DELETE CASCADE ON UPDATE RESTRICT
);
-- The Rust admission planner is an optimization only. These transaction-safe
-- SQL guards make committed bodies plus live worst-case reservations a hard
-- 64 MiB session invariant even for direct SQL and concurrent writers.
CREATE TRIGGER text_artifact_quota_validate_insert
BEFORE INSERT ON session_text_artifacts
BEGIN
    SELECT CASE WHEN
        (SELECT COALESCE(SUM(content_bytes), 0) FROM session_text_artifacts WHERE session_id = NEW.session_id)
        + (SELECT COALESCE(SUM(reserved_bytes), 0) FROM session_text_artifact_quota_reservations WHERE session_id = NEW.session_id)
        + NEW.content_bytes > 67108864
    THEN RAISE(ABORT, 'session text artifact quota exceeded') END;
END;
CREATE TRIGGER text_artifact_reservation_quota_validate_insert
BEFORE INSERT ON session_text_artifact_quota_reservations
BEGIN
    SELECT CASE WHEN
        (SELECT COALESCE(SUM(content_bytes), 0) FROM session_text_artifacts WHERE session_id = NEW.session_id)
        + (SELECT COALESCE(SUM(reserved_bytes), 0) FROM session_text_artifact_quota_reservations WHERE session_id = NEW.session_id)
        + NEW.reserved_bytes > 67108864
    THEN RAISE(ABORT, 'session text artifact quota exceeded') END;
END;
CREATE TRIGGER text_artifact_reservation_validate_insert
BEFORE INSERT ON session_text_artifact_quota_reservations
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM message_operation_receipts o
        JOIN message_submission_receipts s ON s.session_id=o.session_id AND s.operation_id=o.operation_id
        JOIN message_queue_items q ON q.session_id=s.session_id AND q.queue_item_id=s.queue_item_id
         WHERE o.session_id=NEW.session_id AND o.operation_id=NEW.operation_id
           AND o.client_submission_id=NEW.client_submission_id AND o.state='accepted'
           AND s.client_submission_id=NEW.client_submission_id AND s.state='accepted'
           AND q.queue_item_id=NEW.queue_item_id AND q.client_submission_id=NEW.client_submission_id AND q.state='accepted'
    ) THEN RAISE(ABORT, 'text artifact reservation receipt identity is not accepted') END;
END;
-- The receipt is the single authoritative identity record for an explicit
-- fence.  The reservation retains a byte-for-byte copy solely for restart
-- materialization, so reject direct-SQL disagreement instead of allowing two
-- replay authorities to diverge.
CREATE TRIGGER text_artifact_reservation_fence_matches_receipt
BEFORE INSERT ON session_text_artifact_quota_reservations
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM message_operation_receipts o
         WHERE o.session_id=NEW.session_id AND o.operation_id=NEW.operation_id
           AND o.client_submission_id=NEW.client_submission_id
           AND o.artifact_model_fence_generation IS NEW.model_fence_generation
           AND o.artifact_model_fence_json IS NEW.model_fence_json
    ) THEN RAISE(ABORT, 'text artifact reservation fence differs from receipt') END;
END;
-- The receipt is written before the companion reservation in phase one.  Its
-- fence may therefore make one NULL-pair -> canonical-pair transition while
-- the accepted receipt has no reservation; after that it is immutable.  This
-- prevents direct SQL from creating a replay authority that disagrees with a
-- live lease or from rewriting a materialized receipt later.
CREATE TRIGGER text_artifact_receipt_fence_reject_mutation
BEFORE UPDATE OF artifact_model_fence_generation, artifact_model_fence_json
ON message_operation_receipts
WHEN NOT (
    (OLD.artifact_model_fence_generation IS NEW.artifact_model_fence_generation
     AND OLD.artifact_model_fence_json IS NEW.artifact_model_fence_json)
    OR (
        OLD.artifact_model_fence_generation IS NULL
        AND OLD.artifact_model_fence_json IS NULL
        AND NEW.state = 'accepted'
        AND NOT EXISTS (
            SELECT 1 FROM session_text_artifact_quota_reservations r
             WHERE r.session_id=OLD.session_id
               AND r.client_submission_id=OLD.client_submission_id
        )
    )
)
BEGIN SELECT RAISE(ABORT, 'text artifact receipt fence is immutable'); END;
CREATE TRIGGER text_artifact_reservation_reject_update_identity
BEFORE UPDATE OF session_id, client_submission_id, operation_id, queue_item_id, source_digest, source_bytes, reserved_bytes, run_invocation_bound, model_fence_generation, model_fence_json, created_at ON session_text_artifact_quota_reservations
BEGIN SELECT RAISE(ABORT, 'text artifact reservation identity is immutable'); END;
CREATE INDEX idx_text_artifact_reservations_expiry
    ON session_text_artifact_quota_reservations(expires_at, session_id, client_submission_id);

-- ---- workspace_trust ----------------------------------------------------------------------
-- Per-root workspace trust decisions.

CREATE TABLE workspace_trust (
    root_path TEXT PRIMARY KEY CHECK (length(CAST(root_path AS BLOB)) BETWEEN 1 AND 32768),
    mode TEXT NOT NULL CHECK (mode IN ('trust', 'ignore-config', 'untrusted')),
    -- Monotonic per-root policy fence.  Timestamps are observability only and
    -- cannot safely linearize two decisions made in the same clock tick.
    revision INTEGER NOT NULL,
    -- Daemon-observed wall-clock times, signed Unix milliseconds.
    created_at_unix_ms INTEGER NOT NULL,
    updated_at_unix_ms INTEGER NOT NULL CHECK (updated_at_unix_ms >= created_at_unix_ms)
);

CREATE INDEX idx_workspace_trust_updated_at
    ON workspace_trust(updated_at_unix_ms DESC);

-- ---- workspace history recall scope ----------------------------------------
-- Independent from execution sandbox and workspace trust. Missing rows are
-- fail-closed, keeping recall in the current workspace only.
CREATE TABLE workspace_history_scopes (
    project_id TEXT PRIMARY KEY CHECK (length(CAST(project_id AS BLOB)) BETWEEN 1 AND 4096),
    outbound_enabled INTEGER NOT NULL DEFAULT 0 CHECK (outbound_enabled IN (0, 1)),
    inbound_enabled INTEGER NOT NULL DEFAULT 0 CHECK (inbound_enabled IN (0, 1)),
    updated_at_unix_ms INTEGER NOT NULL
);

-- Reserved onboarding default. Recall uses explicit per-workspace decisions;
-- a missing row remains fail-closed.
CREATE TABLE machine_history_scope_default (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    cross_workspace_recall_enabled INTEGER NOT NULL DEFAULT 0
        CHECK (cross_workspace_recall_enabled IN (0, 1)),
    updated_at_unix_ms INTEGER NOT NULL
);

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
        'created',
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
    FOREIGN KEY (parent_session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE TABLE task_delegation_children (
    task_call_id TEXT NOT NULL,
    label TEXT NOT NULL,
    child_uuid TEXT NOT NULL UNIQUE,
    child_agent TEXT NOT NULL,
    model TEXT,
    status TEXT NOT NULL CHECK (status IN (
        'created',
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
    FOREIGN KEY (task_call_id) REFERENCES task_delegation_jobs(task_call_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE INDEX idx_task_delegation_jobs_session_status
    ON task_delegation_jobs(parent_session_id, status, updated_at DESC);

CREATE INDEX idx_task_delegation_children_status
    ON task_delegation_children(status, updated_at DESC);

-- The task batch DAG is host-validated at ingress and retained independently
-- of ephemeral executor state. A dependent edge is an ordering relationship
-- only; it never transfers the predecessor's authority, prompt, or report.
CREATE TABLE task_delegation_dependency_edges (
    task_call_id TEXT NOT NULL,
    dependent_label TEXT NOT NULL,
    prerequisite_label TEXT NOT NULL,
    PRIMARY KEY (task_call_id, dependent_label, prerequisite_label),
    CHECK (dependent_label <> prerequisite_label),
    FOREIGN KEY (task_call_id, dependent_label)
        REFERENCES task_delegation_children(task_call_id, label) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (task_call_id, prerequisite_label)
        REFERENCES task_delegation_children(task_call_id, label) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE INDEX idx_task_delegation_dependency_edges_prerequisite
    ON task_delegation_dependency_edges(task_call_id, prerequisite_label);

CREATE TABLE task_delegation_steers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_call_id TEXT NOT NULL,
    label TEXT NOT NULL,
    body TEXT NOT NULL,
    origin_principal TEXT NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0 CHECK (delivered IN (0, 1)),
    created_at INTEGER NOT NULL,
    delivered_at INTEGER,
    FOREIGN KEY (task_call_id, label) REFERENCES task_delegation_children(task_call_id, label) ON DELETE CASCADE ON UPDATE RESTRICT
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
    FOREIGN KEY (task_call_id) REFERENCES task_delegation_jobs(task_call_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (parent_session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    CHECK ((body_inline IS NOT NULL) OR (sidecar_path IS NOT NULL))
);

CREATE UNIQUE INDEX idx_task_delegation_payloads_session_hash_label
    ON task_delegation_payloads(parent_session_id, payload_hash, task_call_id, label);

CREATE INDEX idx_task_delegation_payloads_session_created
    ON task_delegation_payloads(parent_session_id, created_at ASC);

-- A durable pathname has exactly one live payload owner. Recovery may use
-- this as row-reference proof before retiring a prepare/cleanup intent.
CREATE UNIQUE INDEX idx_task_delegation_payloads_sidecar_path
    ON task_delegation_payloads(sidecar_path)
    WHERE sidecar_path IS NOT NULL;

-- Filesystem deletion cannot participate in the session-row transaction.
-- Copy the relative sidecar identity here before cascading payload rows so a
-- crash after commit leaves durable, boot-replayable cleanup work.
CREATE TABLE task_delegation_sidecar_cleanup_intents (
    sidecar_path TEXT PRIMARY KEY CHECK (
        length(sidecar_path) BETWEEN 1 AND 4096
        AND sidecar_path NOT LIKE '/%'
        AND sidecar_path NOT LIKE '\\%'
        AND sidecar_path NOT LIKE '%..%'
    ),
    session_id TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0)
);

CREATE INDEX idx_task_delegation_sidecar_cleanup_created
    ON task_delegation_sidecar_cleanup_intents(created_at_unix_ms, sidecar_path);

-- Text-artifact bodies are daemon-private files, while a session cascade is
-- owned by SQLite.  Preserve every blob identity before the cascade so every
-- deletion path (retention, boot sweep, direct transaction, and RPC) leaves
-- replayable filesystem cleanup work after commit.
CREATE TABLE text_artifact_blob_cleanup_intents (
    blob_path TEXT PRIMARY KEY CHECK (
        length(blob_path) BETWEEN 1 AND 4096
        AND blob_path LIKE 'text-artifacts/%'
        AND blob_path NOT LIKE '%..%'
        AND blob_path NOT LIKE '%\n%'
        AND blob_path NOT LIKE '%\r%'
    ),
    session_id TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0)
);

CREATE INDEX idx_text_artifact_blob_cleanup_created
    ON text_artifact_blob_cleanup_intents(created_at_unix_ms, blob_path);

-- A sidecar is published before its referencing payload transaction starts.
-- This intent is committed first, so boot recovery can remove a file left by
-- a crash between durable rename and the payload-row commit.
CREATE TABLE task_delegation_sidecar_prepare_intents (
    sidecar_path TEXT PRIMARY KEY CHECK (
        length(sidecar_path) BETWEEN 1 AND 4096
        AND sidecar_path NOT LIKE '/%'
        AND sidecar_path NOT LIKE '\\%'
        AND sidecar_path NOT LIKE '%..%'
    ),
    session_id TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0)
);
CREATE INDEX idx_task_delegation_sidecar_prepare_created
    ON task_delegation_sidecar_prepare_intents(created_at_unix_ms, sidecar_path);

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
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
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
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
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

-- ---- session_plan_docs -------------------------------------------------------------------------------------
-- The session's living plan document (plan mode), one row per session.

CREATE TABLE session_plan_docs (
    session_id TEXT PRIMARY KEY REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    content TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    model_trust TEXT CHECK (model_trust IS NULL OR model_trust IN ('trusted', 'untrusted'))
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
    FOREIGN KEY (namespace) REFERENCES secure_key_namespaces(namespace) ON DELETE RESTRICT ON UPDATE RESTRICT
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
    FOREIGN KEY (namespace) REFERENCES secure_key_namespaces(namespace) ON DELETE RESTRICT ON UPDATE RESTRICT
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
        REFERENCES secure_key_versions(namespace, version) ON DELETE RESTRICT ON UPDATE RESTRICT
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

-- An oversized run's lease is not authorized by a boolean or by deriving a
-- UUID from an FCM2 receipt.  This companion edge is the durable, exact
-- phase-one relation to the globally keyed invocation, including the
-- principal which owns that invocation.
CREATE TABLE session_text_artifact_run_invocation_bindings (
    session_id TEXT NOT NULL,
    client_submission_id BLOB NOT NULL CHECK(typeof(client_submission_id) = 'blob' AND length(client_submission_id) = 16 AND client_submission_id <> zeroblob(16)),
    run_invocation_id TEXT NOT NULL,
    origin_principal_digest TEXT NOT NULL,
    PRIMARY KEY(session_id, client_submission_id),
    FOREIGN KEY(session_id, client_submission_id) REFERENCES session_text_artifact_quota_reservations(session_id, client_submission_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY(run_invocation_id) REFERENCES run_invocations(client_submission_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE TRIGGER text_artifact_run_binding_validate_insert
BEFORE INSERT ON session_text_artifact_run_invocation_bindings
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM session_text_artifact_quota_reservations r
         JOIN run_invocations i ON i.client_submission_id=NEW.run_invocation_id
         WHERE r.session_id=NEW.session_id
           AND r.client_submission_id=NEW.client_submission_id
           AND r.run_invocation_bound=1
           AND i.session_id=NEW.session_id
           AND i.origin_principal_digest=NEW.origin_principal_digest
    ) THEN RAISE(ABORT, 'text artifact run binding is not the reservation invocation') END;
END;
CREATE TRIGGER text_artifact_run_binding_reject_update
BEFORE UPDATE ON session_text_artifact_run_invocation_bindings
BEGIN SELECT RAISE(ABORT, 'text artifact run binding is immutable'); END;

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
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
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
    -- Recursive-agent ownership is an edge from the lease to its agent, not
    -- an agent-held lease capability. Legacy task leases leave this NULL.
    agent_instance_id       TEXT,
    -- Canonical absolute directory subtree this lease grants write authority over.
    scope_path              TEXT NOT NULL,
    -- Bumped by every authority-changing transition. Invalidates older tokens.
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
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY (parent_lease_id) REFERENCES write_scope_leases(lease_id) ON DELETE RESTRICT ON UPDATE RESTRICT
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
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (parent_lease_id) REFERENCES write_scope_leases(lease_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY (child_lease_id) REFERENCES write_scope_leases(lease_id) ON DELETE RESTRICT ON UPDATE RESTRICT
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
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (lease_id) REFERENCES write_scope_leases(lease_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE INDEX idx_write_scope_permits_lease
    ON write_scope_permits (lease_id);
CREATE INDEX idx_write_scope_permits_session_state
    ON write_scope_permits (session_id, state);
CREATE INDEX idx_write_scope_permits_held
    ON write_scope_permits (session_id)
    WHERE state = 'held';

-- ---- workspace leases and commitless task artifacts -----------------------
-- These rows are daemon-owned recovery metadata, never filesystem handles or
-- file content. Canonical roots identify the host worktree; every mutable
-- observation is represented by a SHA-256 receipt.
CREATE TABLE workspace_leases (
    workspace_lease_id        TEXT PRIMARY KEY,
    session_id                TEXT NOT NULL,
    agent_instance_id         TEXT NOT NULL,
    write_scope_lease_id      TEXT NOT NULL,
    -- A child workspace lease remains live only while this durable parent is
    -- live.  This is workspace-lease lineage, distinct from write-scope
    -- transfer lineage, and is intentionally immutable provenance.
    parent_workspace_lease_id TEXT,
    canonical_repository_id   TEXT NOT NULL,
    canonical_root            TEXT NOT NULL,
    kind                      TEXT NOT NULL CHECK (kind IN ('same_root', 'subdirectory', 'managed_worktree')),
    allowed_ops               INTEGER NOT NULL CHECK (allowed_ops BETWEEN 0 AND 15),
    host_issued               INTEGER NOT NULL DEFAULT 0 CHECK (host_issued IN (0, 1)),
    base_sha_digest           TEXT NOT NULL CHECK (length(base_sha_digest) = 64 AND base_sha_digest NOT GLOB '*[^0-9a-f]*'),
    base_ref_digest           TEXT NOT NULL CHECK (length(base_ref_digest) = 64 AND base_ref_digest NOT GLOB '*[^0-9a-f]*'),
    managed_path              TEXT NOT NULL,
    private_ref_digest        TEXT NOT NULL CHECK (length(private_ref_digest) = 64 AND private_ref_digest NOT GLOB '*[^0-9a-f]*'),
    state                     TEXT NOT NULL CHECK (state IN ('active', 'grace', 'cleaning', 'cleaned', 'uncertain')),
    expires_at_unix_ms        INTEGER NOT NULL,
    revision                  INTEGER NOT NULL CHECK (revision >= 0),
    terminal_reason           TEXT CHECK (terminal_reason IN ('expired', 'identity_mismatch', 'missing_managed_path', 'host_cleanup', 'restart_uncertain')),
    uncertain_reason          TEXT CHECK (uncertain_reason IN ('expired', 'identity_mismatch', 'missing_managed_path', 'restart_uncertain')),
    pinned_at_unix_ms         INTEGER,
    pinned_by_agent_instance_id TEXT,
    created_at_unix_ms        INTEGER NOT NULL,
    updated_at_unix_ms        INTEGER NOT NULL,
    UNIQUE (workspace_lease_id, session_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY (write_scope_lease_id) REFERENCES write_scope_leases(lease_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY (parent_workspace_lease_id, session_id)
        REFERENCES workspace_leases(workspace_lease_id, session_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY (pinned_by_agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CHECK ((pinned_at_unix_ms IS NULL) = (pinned_by_agent_instance_id IS NULL)),
    CHECK ((state = 'cleaned') = (terminal_reason IS NOT NULL)),
    CHECK (
        (state = 'active' AND terminal_reason IS NULL AND uncertain_reason IS NULL)
        OR (state = 'grace' AND terminal_reason IS NULL AND uncertain_reason = 'expired')
        OR (state = 'cleaning' AND terminal_reason IS NULL AND uncertain_reason = 'expired')
        OR (state = 'uncertain' AND terminal_reason IS NULL AND uncertain_reason IS NOT NULL)
        OR (state = 'cleaned' AND terminal_reason IS NOT NULL)
    )
);

CREATE INDEX idx_workspace_leases_session_owner_state
    ON workspace_leases (session_id, agent_instance_id, state, expires_at_unix_ms);
-- Same-root and subtree leases are shareable delegated authority, not an
-- exclusive host resource. Only an exact active managed destination is
-- exclusive; its UUID path is daemon-created and cannot be reused.
CREATE UNIQUE INDEX uq_workspace_leases_live_managed_path
    ON workspace_leases (session_id, managed_path)
    WHERE kind = 'managed_worktree' AND state IN ('active', 'grace', 'cleaning', 'uncertain');

-- The lifecycle is storage-enforced so a maintenance caller cannot resurrect
-- an ambiguous worktree or silently skip grace. Every mutation is a CAS
-- revision advance; pinning and renewal are same-state mutations.
CREATE TRIGGER workspace_leases_revision_monotonic
BEFORE UPDATE ON workspace_leases
WHEN NEW.revision <> OLD.revision + 1
BEGIN
    SELECT RAISE(ABORT, 'workspace lease revision must advance exactly once');
END;

CREATE TRIGGER workspace_leases_legal_transition
BEFORE UPDATE ON workspace_leases
WHEN NEW.state <> OLD.state
 AND (OLD.state || '>' || NEW.state) NOT IN (
    'active>grace', 'active>uncertain', 'grace>cleaning',
    'grace>cleaned', 'grace>uncertain', 'cleaning>grace',
    'cleaning>cleaned', 'cleaning>uncertain', 'uncertain>cleaned'
 )
BEGIN
    SELECT RAISE(ABORT, 'workspace lease transition rejected');
END;

CREATE TRIGGER workspace_leases_cleaned_final
BEFORE UPDATE ON workspace_leases
WHEN OLD.state = 'cleaned'
BEGIN
    SELECT RAISE(ABORT, 'cleaned workspace lease is final');
END;

-- A lease's identity and provenance are an immutable recovery receipt. The
-- only mutable lease data are lifecycle state/revision, expiry, pin retention,
-- transition reasons, and its update timestamp.
CREATE TRIGGER workspace_leases_provenance_immutable
BEFORE UPDATE ON workspace_leases
WHEN NEW.workspace_lease_id <> OLD.workspace_lease_id
  OR NEW.session_id <> OLD.session_id
  OR NEW.agent_instance_id <> OLD.agent_instance_id
  OR NEW.write_scope_lease_id <> OLD.write_scope_lease_id
  OR NEW.parent_workspace_lease_id IS NOT OLD.parent_workspace_lease_id
  OR NEW.canonical_repository_id <> OLD.canonical_repository_id
  OR NEW.canonical_root <> OLD.canonical_root
  OR NEW.kind <> OLD.kind
  OR NEW.allowed_ops <> OLD.allowed_ops
  OR NEW.host_issued <> OLD.host_issued
  OR NEW.base_sha_digest <> OLD.base_sha_digest
  OR NEW.base_ref_digest <> OLD.base_ref_digest
  OR NEW.managed_path <> OLD.managed_path
  OR NEW.private_ref_digest <> OLD.private_ref_digest
  OR NEW.created_at_unix_ms <> OLD.created_at_unix_ms
BEGIN
    SELECT RAISE(ABORT, 'workspace lease provenance is immutable');
END;

CREATE TRIGGER workspace_leases_terminal_reason_immutable
BEFORE UPDATE ON workspace_leases
WHEN NEW.terminal_reason IS NOT OLD.terminal_reason
 AND NOT (OLD.terminal_reason IS NULL AND NEW.state = 'cleaned')
BEGIN
    SELECT RAISE(ABORT, 'workspace lease terminal reason is immutable');
END;

CREATE TRIGGER workspace_leases_uncertain_reason_transition_only
BEFORE UPDATE ON workspace_leases
WHEN NEW.uncertain_reason IS NOT OLD.uncertain_reason
 AND NOT (NEW.state <> OLD.state AND NEW.state IN ('grace', 'uncertain'))
BEGIN
    SELECT RAISE(ABORT, 'workspace lease uncertainty reason may change only with transition');
END;

CREATE TRIGGER workspace_leases_scope_owner_matches
BEFORE INSERT ON workspace_leases
WHEN NOT EXISTS (
    SELECT 1 FROM write_scope_leases w
    WHERE w.lease_id = NEW.write_scope_lease_id
      AND w.session_id = NEW.session_id
      AND w.state = 'active'
      AND (
          -- A daemon-issued lease is bound to the session-root write scope,
          -- including descendant rows that inherit that host root, but
          -- remains model-facing owner-scoped through workspace_leases.
          (
              NEW.host_issued = 1
              AND w.owner_id = 'session-root'
              AND w.parent_lease_id IS NULL
              AND w.agent_instance_id IS NULL
          )
          OR
          -- Host-issued managed children (fan-out / conflict specialist)
          -- keep host provenance on the workspace lease while binding a
          -- narrower agent-owned child write-scope at the managed root.
          (
              NEW.host_issued = 1
              AND NEW.parent_workspace_lease_id IS NOT NULL
              AND NEW.kind = 'managed_worktree'
              AND w.owner_id = NEW.agent_instance_id
              AND w.scope_path = NEW.canonical_root
              AND w.parent_lease_id IS NOT NULL
          )
          OR
          -- Ordinary leases must remain exactly bound to the caller-owned
          -- scope and root; they cannot borrow the daemon root authority.
          (
              NEW.host_issued = 0
              AND w.owner_id = NEW.agent_instance_id
              AND w.scope_path = NEW.canonical_root
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'workspace lease requires active owned write scope');
END;

CREATE TABLE task_artifacts (
    artifact_id                 TEXT PRIMARY KEY,
    source_workspace_lease_id   TEXT NOT NULL,
    session_id                  TEXT NOT NULL,
    agent_instance_id           TEXT NOT NULL,
    base_head_digest            TEXT NOT NULL CHECK (length(base_head_digest) = 64 AND base_head_digest NOT GLOB '*[^0-9a-f]*'),
    base_ref_digest             TEXT NOT NULL CHECK (length(base_ref_digest) = 64 AND base_ref_digest NOT GLOB '*[^0-9a-f]*'),
    base_index_digest           TEXT NOT NULL CHECK (length(base_index_digest) = 64 AND base_index_digest NOT GLOB '*[^0-9a-f]*'),
    touched_manifest_digest     TEXT NOT NULL CHECK (length(touched_manifest_digest) = 64 AND touched_manifest_digest NOT GLOB '*[^0-9a-f]*'),
    untracked_manifest_digest   TEXT NOT NULL CHECK (length(untracked_manifest_digest) = 64 AND untracked_manifest_digest NOT GLOB '*[^0-9a-f]*'),
    ordered_patch_digest        TEXT NOT NULL CHECK (length(ordered_patch_digest) = 64 AND ordered_patch_digest NOT GLOB '*[^0-9a-f]*'),
    validation_receipt_digest   TEXT NOT NULL CHECK (length(validation_receipt_digest) = 64 AND validation_receipt_digest NOT GLOB '*[^0-9a-f]*'),
    parent_result_json          TEXT NOT NULL,
    state                       TEXT NOT NULL CHECK (state IN ('produced', 'integrating', 'integrated', 'stale', 'conflict', 'cancelled', 'failed')),
    revision                    INTEGER NOT NULL CHECK (revision >= 0),
    created_at_unix_ms          INTEGER NOT NULL,
    updated_at_unix_ms          INTEGER NOT NULL,
    UNIQUE (artifact_id, session_id),
    -- Artifact provenance is session-owned even though its source lease and
    -- agent references use restrictive composite FKs for normal lifecycle
    -- operations. Session teardown must collect the whole recovery graph.
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (source_workspace_lease_id, session_id)
        REFERENCES workspace_leases(workspace_lease_id, session_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    FOREIGN KEY (agent_instance_id, session_id)
        REFERENCES agent_instances(agent_instance_id, session_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE INDEX idx_task_artifacts_source_state
    ON task_artifacts (source_workspace_lease_id, state);
CREATE INDEX idx_task_artifacts_session_owner
    ON task_artifacts (session_id, agent_instance_id, created_at_unix_ms);

CREATE TRIGGER task_artifacts_source_owner_matches
BEFORE INSERT ON task_artifacts
WHEN NOT EXISTS (
    SELECT 1 FROM workspace_leases w
    WHERE w.workspace_lease_id = NEW.source_workspace_lease_id
      AND w.session_id = NEW.session_id
      AND w.agent_instance_id = NEW.agent_instance_id
      AND w.state = 'active'
)
BEGIN
    SELECT RAISE(ABORT, 'task artifact requires active owned workspace lease');
END;

CREATE TABLE task_artifact_integration_receipts (
    artifact_id                 TEXT PRIMARY KEY,
    session_id                  TEXT NOT NULL,
    target_canonical_repository_id TEXT NOT NULL,
    target_canonical_root       TEXT NOT NULL,
    target_head_digest          TEXT NOT NULL CHECK (length(target_head_digest) = 64 AND target_head_digest NOT GLOB '*[^0-9a-f]*'),
    target_ref_digest           TEXT NOT NULL CHECK (length(target_ref_digest) = 64 AND target_ref_digest NOT GLOB '*[^0-9a-f]*'),
    target_index_digest         TEXT NOT NULL CHECK (length(target_index_digest) = 64 AND target_index_digest NOT GLOB '*[^0-9a-f]*'),
    changed_path_manifest_digest TEXT NOT NULL CHECK (length(changed_path_manifest_digest) = 64 AND changed_path_manifest_digest NOT GLOB '*[^0-9a-f]*'),
    target_write_scope_lease_id TEXT NOT NULL,
    expected_target_generation  INTEGER NOT NULL CHECK (expected_target_generation >= 0),
    expected_target_revision    INTEGER NOT NULL CHECK (expected_target_revision >= 0),
    result_state                TEXT NOT NULL CHECK (result_state = 'integrated'),
    created_at_unix_ms          INTEGER NOT NULL,
    UNIQUE (artifact_id, session_id),
    -- Keep the immutable receipt in the session-owned cascade graph as well
    -- as under its artifact. This avoids a restrictive target-scope FK
    -- disconnecting receipt cleanup from session lifecycle ownership.
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (artifact_id, session_id)
        REFERENCES task_artifacts(artifact_id, session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    FOREIGN KEY (target_write_scope_lease_id) REFERENCES write_scope_leases(lease_id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE INDEX idx_task_artifact_receipts_target
    ON task_artifact_integration_receipts (target_write_scope_lease_id, session_id);

CREATE INDEX idx_task_artifact_receipts_session
    ON task_artifact_integration_receipts (session_id, artifact_id);

CREATE TRIGGER task_artifacts_revision_monotonic
BEFORE UPDATE ON task_artifacts
WHEN NEW.revision <> OLD.revision + 1
BEGIN
    SELECT RAISE(ABORT, 'task artifact revision must advance exactly once');
END;

CREATE TRIGGER task_artifacts_legal_transition
BEFORE UPDATE ON task_artifacts
WHEN NEW.state <> OLD.state
 AND (OLD.state || '>' || NEW.state) NOT IN (
    'produced>integrating', 'produced>cancelled',
    'integrating>produced', 'integrating>integrated',
    'integrating>stale', 'integrating>conflict',
    'integrating>cancelled', 'integrating>failed'
 )
BEGIN
    SELECT RAISE(ABORT, 'task artifact transition rejected');
END;

CREATE TRIGGER task_artifacts_terminal_final
BEFORE UPDATE ON task_artifacts
WHEN OLD.state IN ('integrated', 'stale', 'conflict', 'cancelled', 'failed')
BEGIN
    SELECT RAISE(ABORT, 'terminal task artifact is final');
END;

CREATE TRIGGER task_artifacts_provenance_immutable
BEFORE UPDATE ON task_artifacts
WHEN NEW.artifact_id <> OLD.artifact_id
  OR NEW.source_workspace_lease_id <> OLD.source_workspace_lease_id
  OR NEW.session_id <> OLD.session_id
  OR NEW.agent_instance_id <> OLD.agent_instance_id
  OR NEW.base_head_digest <> OLD.base_head_digest
  OR NEW.base_ref_digest <> OLD.base_ref_digest
  OR NEW.base_index_digest <> OLD.base_index_digest
  OR NEW.touched_manifest_digest <> OLD.touched_manifest_digest
  OR NEW.untracked_manifest_digest <> OLD.untracked_manifest_digest
  OR NEW.ordered_patch_digest <> OLD.ordered_patch_digest
  OR NEW.validation_receipt_digest <> OLD.validation_receipt_digest
  OR NEW.parent_result_json <> OLD.parent_result_json
  OR NEW.created_at_unix_ms <> OLD.created_at_unix_ms
BEGIN
    SELECT RAISE(ABORT, 'task artifact provenance is immutable');
END;

CREATE TRIGGER task_artifact_integrated_requires_receipt
BEFORE UPDATE OF state ON task_artifacts
WHEN NEW.state = 'integrated'
 AND NOT EXISTS (
    SELECT 1 FROM task_artifact_integration_receipts r
    WHERE r.artifact_id = OLD.artifact_id AND r.session_id = OLD.session_id
 )
BEGIN
    SELECT RAISE(ABORT, 'integrated artifact requires immutable receipt');
END;

CREATE TRIGGER task_artifact_receipt_requires_integrating
BEFORE INSERT ON task_artifact_integration_receipts
WHEN NOT EXISTS (
    SELECT 1 FROM task_artifacts a
    WHERE a.artifact_id = NEW.artifact_id
      AND a.session_id = NEW.session_id
      AND a.state = 'integrating'
 )
BEGIN
    SELECT RAISE(ABORT, 'integration receipt requires integrating artifact');
END;

CREATE TRIGGER task_artifact_receipt_target_owner_matches
BEFORE INSERT ON task_artifact_integration_receipts
WHEN NOT EXISTS (
    SELECT 1
    FROM task_artifacts a
    JOIN workspace_leases source
      ON source.workspace_lease_id = a.source_workspace_lease_id
     AND source.session_id = a.session_id
    JOIN write_scope_leases w ON w.lease_id = NEW.target_write_scope_lease_id
    WHERE a.artifact_id = NEW.artifact_id
      AND a.session_id = NEW.session_id
      AND w.session_id = a.session_id
      AND w.state = 'active'
      AND w.scope_path = NEW.target_canonical_root
      AND source.canonical_repository_id = NEW.target_canonical_repository_id
      AND w.generation = NEW.expected_target_generation
      AND w.version = NEW.expected_target_revision
      AND (
          (
              w.owner_id = a.agent_instance_id
              AND (w.agent_instance_id IS NULL OR w.agent_instance_id = a.agent_instance_id)
          )
          OR (
              w.owner_id = 'session-root'
              AND w.parent_lease_id IS NULL
              AND w.agent_instance_id IS NULL
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'integration receipt target scope is not owned or current');
END;

CREATE TRIGGER task_artifact_receipts_immutable
BEFORE UPDATE ON task_artifact_integration_receipts
BEGIN
    SELECT RAISE(ABORT, 'task artifact integration receipt is immutable');
END;

CREATE TRIGGER task_artifact_receipts_not_deletable
BEFORE DELETE ON task_artifact_integration_receipts
-- Direct deletion remains forbidden while the owning session exists. During
-- session teardown, SQLite removes the parent row before applying FK actions,
-- so the session-owned cascade can delete this otherwise immutable receipt.
WHEN EXISTS (
    SELECT 1 FROM sessions WHERE session_id = OLD.session_id
)
BEGIN
    SELECT RAISE(ABORT, 'task artifact integration receipt cannot be deleted');
END;

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
-- Deliberately NOT `ON DELETE CASCADE ON UPDATE RESTRICT` from sessions: session deletion writes
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
        REFERENCES external_journal_operations (operation_id) ON DELETE CASCADE ON UPDATE RESTRICT
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
        REFERENCES external_journal_operations (operation_id) ON DELETE CASCADE ON UPDATE RESTRICT
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
    FOREIGN KEY (record_id) REFERENCES sealed_value_records(record_id) ON DELETE CASCADE ON UPDATE RESTRICT
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
    FOREIGN KEY (record_id) REFERENCES sealed_value_records(record_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    -- A grant names an exact session. When that session is deleted the grant
    -- must go with it: an outstanding grant naming a dead session would be a
    -- capability nobody can see and nobody can revoke.
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
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

-- ---- sealed action instances -----------------------------------------------
-- The durable, immutable snapshot of one Owner-compiled action instance. This
-- is the persisted backing for the in-memory action directory: it is the
-- *only* source the HTTPS executor compiles an egress target from, so the
-- origin allowlist, credential PLACEMENT (never the credential value, which is
-- a separate sealed value), request path template, projection, and bounded
-- non-secret parameters all live in `kind_json`. No agent/project/plugin/
-- environment/remote/model input can add a row; every row is an explicit
-- Owner record whose `action_id` is a daemon-minted UUID the caller never
-- chooses.
--
-- One live row per `action_id`. A revise bumps `revision` and rewrites the
-- snapshot in place; a retire stamps `retired_at_ms` and disables the row. In
-- both cases the dependent grants are revoked in the SAME transaction that
-- changes this row, so a crash can never leave a retired/revised action with a
-- live grant (or a live action whose grants were already revoked).
CREATE TABLE sealed_action_instances (
    action_id     TEXT    PRIMARY KEY,
    revision      INTEGER NOT NULL CHECK (revision >= 1),
    -- The serialized closed `SealedActionKind` (origins, credential placement,
    -- path template, projection, bounded params). Owner-authored; carries no
    -- literal and no credential value.
    kind_json     TEXT    NOT NULL,
    -- Model-visible safe description. Never a destination, never a literal.
    description   TEXT    NOT NULL,
    -- Canonical project key the instance is scoped to.
    project_key   TEXT    NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at_ms INTEGER NOT NULL,
    retired_at_ms INTEGER
);

CREATE INDEX idx_sealed_action_instances_live
    ON sealed_action_instances (retired_at_ms, action_id);

-- ---- sealed recovery audit -------------------------------------------------
-- A durable audit row committed BEFORE an Owner recover reveals the plaintext
-- to the owner (publish-before-destroy). The reveal fails closed on an audit
-- write failure: no literal is returned unless this row is durably committed
-- first. The row carries only safe metadata and a closed outcome
-- (`revealed`/`rejected`) — never the literal, its length, or any oracle over
-- it.
CREATE TABLE sealed_recovery_audit (
    audit_id        TEXT    PRIMARY KEY,
    record_id       TEXT    NOT NULL,
    scope           TEXT    NOT NULL CHECK (scope IN ('session', 'project', 'global')),
    scope_key       TEXT    NOT NULL,
    version         INTEGER NOT NULL CHECK (version >= 1),
    owner_principal TEXT    NOT NULL,
    -- The minting session the recover capability was bound to (AC8). Safe to
    -- store; it is a connection identity, never a secret.
    minting_session TEXT    NOT NULL,
    outcome         TEXT    NOT NULL CHECK (outcome IN ('revealed', 'rejected')),
    created_at_ms   INTEGER NOT NULL
);

CREATE INDEX idx_sealed_recovery_audit_record
    ON sealed_recovery_audit (record_id, created_at_ms);

-- ---- protected redaction history -------------------------------------------
--
-- Durable AEAD-encrypted literal store for redacting historical
-- trusted-provider artifacts. Each row holds the literal ONLY as
-- ChaCha20-Poly1305 ciphertext + nonce, keyed by an opaque history ID (UUID)
-- and the local key-store key version. The plaintext is bucket-padded before
-- encryption, so the stored ciphertext length reveals only a coarse bucket
-- (one of 272 / 1040 / 4112 / 16404 = padded plaintext {256,1024,4096,16388}
-- plus the 16-byte tag), never the literal length. No plaintext, prefix, exact
-- length, ciphertext, nonce, key version, or fingerprint ever appears in the
-- export/diagnostics projection — those columns are consumed solely by the
-- local Owner-sensitive rehydration frame in `cockpit-core`.
--
-- The `fingerprint` is a keyed MAC (`HMAC-SHA-256` under a store-derived
-- subkey), not an unkeyed digest, so it is not an offline guessing oracle.
--
-- `source` is a closed set: Sealed | Environment | Credential | ContainedLeak.
-- Retirement is **forget**: `retire`-ing a row (only after no artifact
-- reference remains) zeroes ciphertext, nonce, and fingerprint in the same
-- UPDATE that stamps retired_at_ms. Deduplication is on (session_id,
-- fingerprint) among LIVE rows only (partial unique index below): the same
-- literal in the same session reuses one encrypted row *while the current key
-- version produces the same keyed MAC* (attaching an artifact reference bumps
-- its ref_count; adoption-only journaling attaches no ref and leaves ref_count 0).
-- The fingerprint is keyed by a store-derived subkey (decision 5), so after a
-- key rotation the identical literal MACs to a DIFFERENT fingerprint and a
-- second live row is created — dedup collapses only rows sharing the current
-- key/MAC, not across rotations. A retired row's zeroed fingerprint never
-- blocks or aliases a fresh append.
CREATE TABLE protected_redaction_history (
    history_id       TEXT    PRIMARY KEY,
    session_id       TEXT    NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    sealed_record_id TEXT,
    sealed_version   INTEGER,
    source           TEXT    NOT NULL CHECK (source IN ('Sealed', 'Environment', 'Credential', 'ContainedLeak')),
    -- Keyed-MAC fingerprint of the literal (HMAC-SHA-256 under a store-derived
    -- subkey; never the literal, prefix, or length). Zeroed to 64 '0' chars on
    -- retirement.
    fingerprint      TEXT    NOT NULL,
    -- AEAD ciphertext with appended 16-byte tag (local rehydration frame only).
    -- Length is bucketed so it reveals only a coarse bucket. Zeroed on retire.
    ciphertext       BLOB    NOT NULL,
    nonce            BLOB    NOT NULL,
    key_version      INTEGER NOT NULL CHECK (key_version >= 1),
    ref_count        INTEGER NOT NULL DEFAULT 0 CHECK (ref_count >= 0),
    created_at_ms    INTEGER NOT NULL,
    retired_at_ms    INTEGER,
    CHECK (length(history_id) = 36),
    CHECK (length(fingerprint) = 64),
    CHECK (length(nonce) = 12),
    -- Ciphertext length is one of the four bucket lengths (padded plaintext
    -- bucket + 16-byte tag). Length-preserving retire-zeroing keeps this true.
    CHECK (length(ciphertext) IN (272, 1040, 4112, 16404)),
    -- A retired row may never be re-attached, so its ref_count must be 0.
    CHECK ((retired_at_ms IS NULL) OR (ref_count = 0))
);

CREATE INDEX idx_protected_redaction_history_session
    ON protected_redaction_history (session_id, created_at_ms);

-- Deduplicate the same literal within a session among LIVE rows only. A
-- retired row (retired_at_ms set, fingerprint zeroed) is excluded, so it never
-- blocks re-journaling the same literal.
CREATE UNIQUE INDEX idx_protected_redaction_history_dedup
    ON protected_redaction_history (session_id, fingerprint)
    WHERE retired_at_ms IS NULL;

-- Opaque artifact-to-history references. Carries no literal, ciphertext,
-- nonce, or key version — only opaque IDs and the artifact kind. The
-- (artifact_kind, artifact_id, history_id) triple is unique so attaches are
-- idempotent and ref_count transitions are deterministic. A history row may
-- only be referenced while it is not retired (enforced in the writer).
CREATE TABLE protected_redaction_artifact_refs (
    artifact_kind TEXT    NOT NULL CHECK (artifact_kind IN ('request', 'response', 'tool', 'event', 'attempt')),
    artifact_id   TEXT    NOT NULL,
    history_id    TEXT    NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (artifact_kind, artifact_id, history_id),
    FOREIGN KEY (history_id) REFERENCES protected_redaction_history(history_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE INDEX idx_protected_redaction_artifact_refs_history
    ON protected_redaction_artifact_refs (history_id);

CREATE INDEX idx_protected_redaction_artifact_refs_artifact
    ON protected_redaction_artifact_refs (artifact_kind, artifact_id);

-- Protected leak containment records. One row per accepted `report_leak`
-- call. Carries NO plaintext, prefix, length-derived identity, ciphertext,
-- nonce, or key version: the encrypted literal lives in
-- `protected_redaction_history` (source = 'ContainedLeak') and is referenced
-- by `history_id`. This table holds only safe metadata: report id, keyed
-- fingerprint, host-derived provenance, closed source, closed category,
-- optional canonical connector id, status, timestamps, and rotation
-- disposition. A `pending` row is not listable by generic audit/list/export;
-- only `contained`/`rotated`/`superseded` rows are. Deduplication is on
-- (session_id, leak_fingerprint): a re-report of the same literal updates
-- safe `seen` metadata and clears rotation state.
CREATE TABLE protected_leak_records (
    report_id        TEXT    PRIMARY KEY,
    session_id       TEXT    NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    history_id       TEXT    NOT NULL,
    -- Keyed fingerprint: SHA-256(session_id || source || literal_fingerprint).
    -- Safe to expose; does not reveal the literal.
    leak_fingerprint TEXT    NOT NULL,
    -- Closed source set: model_output | tool_output | reasoning | env_leak |
    -- credential_leak | other.
    source           TEXT    NOT NULL CHECK (source IN
        ('model_output', 'tool_output', 'reasoning', 'env_leak', 'credential_leak', 'other')),
    -- Closed category: secret | token | key | password | pii | other.
    category         TEXT    NOT NULL CHECK (category IN
        ('secret', 'token', 'key', 'password', 'pii', 'other')),
    -- Host-derived provenance: provider id, model id, generation. Never
    -- model-supplied; the host stamps these from the active route.
    provider_id      TEXT,
    model_id         TEXT,
    generation       INTEGER,
    -- Optional canonical connector id, host-derived.
    connector_id     TEXT,
    -- Closed status: pending | contained | rotated | superseded | deleted.
    status           TEXT    NOT NULL CHECK (status IN
        ('pending', 'contained', 'rotated', 'superseded', 'deleted')),
    -- Number of times this fingerprint was reported in this session.
    seen_count       INTEGER NOT NULL CHECK (seen_count >= 1) DEFAULT 1,
    -- Rotation disposition: none | pending_user | rotated | not_applicable.
    rotation         TEXT    NOT NULL CHECK (rotation IN
        ('none', 'pending_user', 'rotated', 'not_applicable')) DEFAULT 'none',
    first_reported_ms INTEGER NOT NULL,
    last_reported_ms  INTEGER NOT NULL,
    contained_at_ms   INTEGER,
    retired_at_ms     INTEGER,
    FOREIGN KEY (history_id) REFERENCES protected_redaction_history(history_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    UNIQUE (session_id, leak_fingerprint)
);
CREATE INDEX idx_protected_leak_records_session
    ON protected_leak_records (session_id, status, last_reported_ms);
CREATE INDEX idx_protected_leak_records_history
    ON protected_leak_records (history_id);

-- ---- wrap-key secret vault -------------------------------------------------
-- Coordination + AEAD ciphertext + wrapped DEKs only. KEK bytes and DEK
-- plaintext never live in SQLite. First-run persists intent=keyring /
-- active_placement=keyring when the OS keyring probe is available, else
-- database. dest=database is rejected while the probe is available.

-- Installation-scoped authority singleton. No secret bytes.
CREATE TABLE secret_vault_authority (
    id                    INTEGER PRIMARY KEY CHECK (id = 1),
    intent                TEXT    NOT NULL CHECK (intent IN ('database', 'keyring')),
    active_placement      TEXT    NOT NULL CHECK (active_placement IN ('database', 'keyring')),
    kek_fingerprint       TEXT    NOT NULL,
    kek_version           INTEGER NOT NULL CHECK (kek_version >= 1),
    wrap_version          INTEGER NOT NULL CHECK (wrap_version = 1),
    updated_at            INTEGER NOT NULL
);

-- Wrapped DEKs. No KEK bytes. No DEK plaintext.
CREATE TABLE secret_vault_keys (
    key_version   INTEGER PRIMARY KEY CHECK (key_version >= 1),
    kek_version   INTEGER NOT NULL CHECK (kek_version >= 1),
    wrap_version  INTEGER NOT NULL CHECK (wrap_version = 1),
    algorithm     TEXT    NOT NULL CHECK (algorithm = 'chacha20poly1305'),
    wrap_nonce    BLOB    NOT NULL CHECK (length(wrap_nonce) = 12),
    wrapped_dek   BLOB    NOT NULL CHECK (length(wrapped_dek) = 48),
    active        INTEGER NOT NULL CHECK (active IN (0, 1)),
    created_at    INTEGER NOT NULL
);
CREATE UNIQUE INDEX secret_vault_keys_wrap_nonce ON secret_vault_keys(wrap_nonce);
CREATE UNIQUE INDEX secret_vault_keys_one_active ON secret_vault_keys(active) WHERE active = 1;

-- AEAD items. AAD is rebuilt from columns + installation_identity; no stored AAD blob.
CREATE TABLE secret_vault_items (
    kind          TEXT    NOT NULL CHECK (kind IN (
        'secure_key_root',
        'secure_key_manifest',
        'sealed_state',
        'credential_record',
        'named_secret',
        'command_secret',
        'subscription_ack',
        'sealed_compartment',
        'session_sealed_value',
        'redaction_table'
    )),
    item_id       TEXT    NOT NULL,
    key_version   INTEGER NOT NULL REFERENCES secret_vault_keys(key_version) ON DELETE RESTRICT ON UPDATE RESTRICT,
    nonce         BLOB    NOT NULL CHECK (length(nonce) = 12),
    ciphertext    BLOB    NOT NULL CHECK (length(ciphertext) >= 16),
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    revision      INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
    PRIMARY KEY (kind, item_id)
);
CREATE UNIQUE INDEX secret_vault_items_key_nonce ON secret_vault_items(key_version, nonce);

CREATE TABLE secret_vault_item_revisions (
    kind       TEXT NOT NULL,
    item_id    TEXT NOT NULL,
    revision   INTEGER NOT NULL CHECK (revision >= 0),
    PRIMARY KEY (kind, item_id)
);
INSERT INTO secret_vault_item_revisions (kind, item_id, revision)
SELECT kind, item_id, revision FROM secret_vault_items;

-- Durable owner-inventory cursor generation. Triggers advance this token for
-- every visible secret-vault mutation, including writes from another process.
CREATE TABLE secret_vault_inventory_state (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    generation INTEGER NOT NULL CHECK (generation >= 1)
);
INSERT INTO secret_vault_inventory_state (id, generation) VALUES (1, 1);
-- `command_secret` is intentionally EXCLUDED from these inventory-generation
-- triggers: it is storage-only until its wire kind + inventory read path land
-- together (command-backed secret inc4). Nothing can enumerate a command secret
-- yet, so its mutations must not advance the inventory cursor (which would churn
-- the version / conflict paginated reads for an invisible kind). Add it to all
-- three WHEN clauses in the same change that makes it inventory-visible.
CREATE TRIGGER secret_vault_inventory_insert_generation
AFTER INSERT ON secret_vault_items
WHEN NEW.kind IN ('named_secret', 'credential_record', 'subscription_ack')
BEGIN
    UPDATE secret_vault_inventory_state
    SET generation = generation + 1
    WHERE id = 1;
END;
CREATE TRIGGER secret_vault_inventory_update_generation
AFTER UPDATE ON secret_vault_items
WHEN NEW.kind IN ('named_secret', 'credential_record', 'subscription_ack')
     OR OLD.kind IN ('named_secret', 'credential_record', 'subscription_ack')
BEGIN
    UPDATE secret_vault_inventory_state
    SET generation = generation + 1
    WHERE id = 1;
END;
CREATE TRIGGER secret_vault_inventory_delete_generation
AFTER DELETE ON secret_vault_items
WHEN OLD.kind IN ('named_secret', 'credential_record', 'subscription_ack')
BEGIN
    UPDATE secret_vault_inventory_state
    SET generation = generation + 1
    WHERE id = 1;
END;

-- Durable KEK-placement migrate. Coordination only; no secret bytes.
CREATE TABLE secret_vault_sagas (
    op_id              TEXT    PRIMARY KEY,
    source_placement   TEXT    NOT NULL CHECK (source_placement IN ('database', 'keyring')),
    dest_placement     TEXT    NOT NULL CHECK (dest_placement IN ('database', 'keyring')),
    kek_fingerprint    TEXT    NOT NULL,
    phase              TEXT    NOT NULL CHECK (phase IN (
        'prepared',
        'activated',
        'source_deleted',
        'complete'
    )),
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL
);

-- Recoverable bridge between the SQLite-backed owner vault and provider
-- configuration files.  The entry payload contains only $secret references;
-- private bytes are staged in secret_vault_items in the same transaction.
CREATE TABLE provider_config_journals (
    journal_id       TEXT PRIMARY KEY,
    owner_digest     TEXT,
    client_operation_id TEXT,
    request_hash     BLOB CHECK (request_hash IS NULL OR (typeof(request_hash) = 'blob' AND length(request_hash) = 32)),
    fencing_generation INTEGER CHECK (fencing_generation IS NULL OR fencing_generation > 0),
    terminal_response_json TEXT CHECK (terminal_response_json IS NULL OR json_valid(terminal_response_json)),
    project_root     TEXT NOT NULL,
    provider_id      TEXT NOT NULL,
    action           TEXT NOT NULL CHECK (action IN ('save', 'delete', 'batch')),
    config_path      TEXT,
    consumed_revision TEXT CHECK (consumed_revision IS NULL OR length(consumed_revision) = 64),
    intended_revision TEXT CHECK (intended_revision IS NULL OR length(intended_revision) = 64),
    consumed_config_generation INTEGER CHECK (consumed_config_generation IS NULL OR consumed_config_generation >= 0),
    intended_config_generation INTEGER CHECK (intended_config_generation IS NULL OR intended_config_generation > 0),
    entry_json       TEXT,
    cleanup_named_json TEXT NOT NULL
        CHECK (json_valid(cleanup_named_json) AND json_type(cleanup_named_json) = 'array'),
    cleanup_credential_json TEXT NOT NULL
        CHECK (json_valid(cleanup_credential_json) AND json_type(cleanup_credential_json) = 'array'),
    settlement_phase TEXT NOT NULL DEFAULT 'publication_pending'
        CHECK (settlement_phase IN ('publication_pending', 'cleanup_pending')),
    created_at       INTEGER NOT NULL,
    CHECK (length(trim(journal_id)) > 0),
    CHECK (length(trim(project_root)) > 0),
    CHECK ((owner_digest IS NOT NULL) = (client_operation_id IS NOT NULL)
       AND (owner_digest IS NOT NULL) = (request_hash IS NOT NULL)
       AND (owner_digest IS NOT NULL) = (fencing_generation IS NOT NULL)
       AND (owner_digest IS NOT NULL) = (terminal_response_json IS NOT NULL)),
    CHECK (
        (action = 'save' AND provider_id <> '__provider_batch__'
            AND entry_json IS NOT NULL AND json_valid(entry_json))
        OR (action = 'delete' AND provider_id <> '__provider_batch__'
            AND entry_json IS NULL)
        OR (action = 'batch' AND provider_id = '__provider_batch__'
            AND entry_json IS NOT NULL AND json_valid(entry_json)
            AND json_type(entry_json) = 'object')
    ),
    CHECK (config_path IS NOT NULL
       AND consumed_revision IS NOT NULL
       AND intended_revision IS NOT NULL
       AND consumed_config_generation IS NOT NULL
       AND intended_config_generation IS NOT NULL),
    CHECK (consumed_config_generation IS NULL
       OR intended_config_generation = consumed_config_generation + 1),
    CHECK (config_path IS NULL OR length(trim(config_path)) > 0)
);
CREATE INDEX provider_config_journals_scope
ON provider_config_journals(project_root, provider_id, created_at);
CREATE UNIQUE INDEX provider_config_journals_operation
ON provider_config_journals(owner_digest, client_operation_id);

-- Recoverable bridge between the owner vault and the MCP configuration file.
-- `config_json` is the exact authored target recovery image, never a flattened
-- effective projection. Newly touched credential fields are reference-only;
-- untouched legacy/unknown fields are preserved byte-semantically.
CREATE TABLE mcp_config_journals (
    journal_id        TEXT PRIMARY KEY,
    owner_digest      TEXT NOT NULL,
    client_operation_id TEXT NOT NULL,
    request_hash      BLOB NOT NULL CHECK (typeof(request_hash) = 'blob' AND length(request_hash) = 32),
    fencing_generation INTEGER NOT NULL CHECK (fencing_generation > 0),
    terminal_response_json TEXT NOT NULL CHECK (json_valid(terminal_response_json)),
    project_root      TEXT NOT NULL,
    config_path       TEXT NOT NULL,
    config_json       TEXT NOT NULL,
    patch_intent_json TEXT NOT NULL CHECK (json_valid(patch_intent_json)),
    consumed_revision TEXT NOT NULL CHECK (length(consumed_revision) = 64),
    intended_revision TEXT NOT NULL CHECK (length(intended_revision) = 64),
    intended_config_generation INTEGER NOT NULL CHECK (intended_config_generation > 0),
    cleanup_names_json TEXT NOT NULL,
    phase             TEXT NOT NULL CHECK (phase IN ('staged', 'published')),
    settlement_phase  TEXT NOT NULL DEFAULT 'publication_pending'
        CHECK (settlement_phase IN ('publication_pending', 'cleanup_pending')),
    created_at        INTEGER NOT NULL
);
CREATE INDEX mcp_config_journals_scope
ON mcp_config_journals(project_root, created_at);
CREATE UNIQUE INDEX mcp_config_journals_operation
ON mcp_config_journals(owner_digest, client_operation_id);

-- Owner-scoped durable settlement ledger for local daemon mutations. Request
-- bodies and secret material never enter this table: `request_hash` binds the
-- authenticated owner/idempotency key to the exact request, while the terminal
-- response is a deliberately secret-free protocol receipt. A prepared row is
-- retained across restart so clients never receive permission to blindly
-- repeat an operation whose response was lost.
CREATE TABLE local_operation_receipts (
    owner_digest        TEXT NOT NULL,
    client_operation_id TEXT NOT NULL,
    operation_kind      TEXT NOT NULL,
    request_hash        BLOB NOT NULL
        CHECK (typeof(request_hash) = 'blob' AND length(request_hash) = 32),
    state               TEXT NOT NULL CHECK (state IN (
        'prepared', 'executing', 'terminal_success', 'terminal_error', 'terminal_cancelled'
    )),
    fencing_generation  INTEGER NOT NULL CHECK (fencing_generation > 0),
    execution_started_at_unix_ms INTEGER,
    execution_expires_at_unix_ms INTEGER,
    terminal_outcome_json TEXT
        CHECK (terminal_outcome_json IS NULL OR json_valid(terminal_outcome_json)),
    created_at_unix_ms  INTEGER NOT NULL,
    updated_at_unix_ms  INTEGER NOT NULL,
    PRIMARY KEY (owner_digest, client_operation_id),
    CHECK (length(trim(owner_digest)) > 0),
    CHECK (length(trim(client_operation_id)) > 0),
    CHECK (length(trim(operation_kind)) > 0),
    CHECK ((state LIKE 'terminal_%') = (terminal_outcome_json IS NOT NULL)),
    CHECK ((state = 'executing') = (execution_expires_at_unix_ms IS NOT NULL)),
    CHECK (execution_started_at_unix_ms IS NULL OR execution_started_at_unix_ms >= created_at_unix_ms),
    CHECK (execution_expires_at_unix_ms IS NULL OR execution_expires_at_unix_ms >= execution_started_at_unix_ms),
    CHECK (updated_at_unix_ms >= created_at_unix_ms)
);
CREATE INDEX local_operation_receipts_unsettled
ON local_operation_receipts(updated_at_unix_ms)
WHERE state IN ('prepared', 'executing');
CREATE INDEX local_operation_receipts_terminal_retention
ON local_operation_receipts(updated_at_unix_ms)
WHERE state LIKE 'terminal_%';
CREATE TRIGGER local_operation_receipts_identity_immutable
BEFORE UPDATE ON local_operation_receipts
WHEN NEW.owner_digest <> OLD.owner_digest
  OR NEW.client_operation_id <> OLD.client_operation_id
  OR NEW.operation_kind <> OLD.operation_kind
  OR NEW.request_hash <> OLD.request_hash
  OR NEW.created_at_unix_ms <> OLD.created_at_unix_ms
BEGIN
    SELECT RAISE(ABORT, 'local operation identity is immutable');
END;
CREATE TRIGGER local_operation_receipts_terminal_is_final
BEFORE UPDATE ON local_operation_receipts
WHEN OLD.state LIKE 'terminal_%'
BEGIN
    SELECT RAISE(ABORT, 'local operation terminal receipt is final');
END;

-- Hash-only recovery bridge for the global assistant registry mutations used
-- by the daemon-connected TUI and CLI. Definition markdown is deliberately
-- absent: the existing no-follow filesystem journal owns byte recovery, while
-- this row binds its resulting projection to the authenticated local receipt.
CREATE TABLE assistant_mutation_journals (
    owner_digest          TEXT NOT NULL,
    client_operation_id   TEXT NOT NULL,
    request_hash          BLOB NOT NULL CHECK (
        typeof(request_hash) = 'blob' AND length(request_hash) = 32
    ),
    fencing_generation    INTEGER NOT NULL CHECK (fencing_generation > 0),
    mutation_intent_hash  TEXT NOT NULL CHECK (
        length(mutation_intent_hash) = 64
        AND mutation_intent_hash = lower(mutation_intent_hash)
    ),
    requested_project_root TEXT NOT NULL,
    project_root          TEXT NOT NULL,
    assistant_name        TEXT NOT NULL,
    action                TEXT NOT NULL CHECK (action IN ('save', 'delete')),
    consumed_revision     TEXT NOT NULL,
    intended_content_identity BLOB CHECK (
        intended_content_identity IS NULL OR (
            typeof(intended_content_identity) = 'blob'
            AND length(intended_content_identity) = 32
        )
    ),
    consumed_config_generation INTEGER NOT NULL CHECK (consumed_config_generation >= 0),
    created_at_unix_ms    INTEGER NOT NULL,
    PRIMARY KEY (owner_digest, client_operation_id),
    FOREIGN KEY (owner_digest, client_operation_id)
        REFERENCES local_operation_receipts(owner_digest, client_operation_id)
        ON DELETE CASCADE ON UPDATE RESTRICT,
    CHECK (length(trim(owner_digest)) > 0),
    CHECK (length(trim(client_operation_id)) > 0),
    CHECK (length(trim(requested_project_root)) > 0),
    CHECK (length(trim(project_root)) > 0),
    CHECK (length(trim(assistant_name)) > 0),
    CHECK (length(trim(consumed_revision)) > 0),
    CHECK ((action = 'save') = (intended_content_identity IS NOT NULL))
);
CREATE INDEX assistant_mutation_journals_created
ON assistant_mutation_journals(created_at_unix_ms);
CREATE TRIGGER assistant_mutation_journals_identity_immutable
BEFORE UPDATE ON assistant_mutation_journals
WHEN NEW.owner_digest <> OLD.owner_digest
  OR NEW.client_operation_id <> OLD.client_operation_id
  OR NEW.request_hash <> OLD.request_hash
  OR NEW.fencing_generation <> OLD.fencing_generation
  OR NEW.mutation_intent_hash <> OLD.mutation_intent_hash
  OR NEW.requested_project_root <> OLD.requested_project_root
  OR NEW.project_root <> OLD.project_root
  OR NEW.assistant_name <> OLD.assistant_name
  OR NEW.action <> OLD.action
  OR NEW.consumed_revision <> OLD.consumed_revision
  OR NEW.intended_content_identity IS NOT OLD.intended_content_identity
  OR NEW.consumed_config_generation <> OLD.consumed_config_generation
  OR NEW.created_at_unix_ms <> OLD.created_at_unix_ms
BEGIN
    SELECT RAISE(ABORT, 'assistant mutation journal identity is immutable');
END;

-- Hash-only recovery bridge for daemon-owned agent definition mutations.
-- Agent markdown never enters SQLite.  The journal is inserted before the
-- authoritative atomic file publication and binds the owner receipt fence to
-- the consumed and intended filesystem projections.  Boot reconciliation can
-- therefore prove a commit after a lost response without replaying a stale
-- create/save/delete/reset against a different document revision.
CREATE TABLE agent_mutation_journals (
    owner_digest          TEXT NOT NULL,
    client_operation_id   TEXT NOT NULL,
    request_hash          BLOB NOT NULL CHECK (
        typeof(request_hash) = 'blob' AND length(request_hash) = 32
    ),
    keyed_request_identity BLOB NOT NULL CHECK (
        typeof(keyed_request_identity) = 'blob' AND length(keyed_request_identity) = 32
    ),
    fencing_generation    INTEGER NOT NULL CHECK (fencing_generation > 0),
    project_root          TEXT NOT NULL,
    request_project_root  TEXT NOT NULL,
    agent_name            TEXT,
    action                TEXT NOT NULL CHECK (action IN (
        'eject_builtin', 'save_definition', 'create_definition',
        'delete_custom', 'reset_builtin', 'reset_all_builtins',
        'save_goal_supervision', 'add_mcp_server'
    )),
    consumed_revision     TEXT,
    affected_hint         INTEGER NOT NULL CHECK (affected_hint >= 0),
    changed_hint          INTEGER NOT NULL CHECK (changed_hint IN (0, 1)),
    consumed_config_generation INTEGER NOT NULL CHECK (consumed_config_generation >= 0),
    mutation_intent_hash  TEXT NOT NULL CHECK (
        length(mutation_intent_hash) = 64
        AND mutation_intent_hash = lower(mutation_intent_hash)
    ),
    consumed_projection_identity TEXT NOT NULL CHECK (
        length(consumed_projection_identity) = 64
        AND consumed_projection_identity = lower(consumed_projection_identity)
    ),
    intended_projection_identity TEXT NOT NULL CHECK (
        length(intended_projection_identity) = 64
        AND intended_projection_identity = lower(intended_projection_identity)
    ),
    terminal_response_json TEXT CHECK (
        terminal_response_json IS NULL OR json_valid(terminal_response_json)
    ),
    credential_compensation_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(credential_compensation_json)),
    created_at_unix_ms    INTEGER NOT NULL,
    PRIMARY KEY (owner_digest, client_operation_id),
    CHECK (length(trim(owner_digest)) > 0),
    CHECK (length(trim(client_operation_id)) > 0),
    CHECK (length(trim(project_root)) > 0),
    CHECK (length(trim(request_project_root)) > 0),
    CHECK ((action = 'reset_all_builtins') = (agent_name IS NULL)),
    CHECK (agent_name IS NULL OR length(trim(agent_name)) > 0),
    CHECK (consumed_revision IS NULL OR length(trim(consumed_revision)) > 0)
);
CREATE INDEX agent_mutation_journals_created
ON agent_mutation_journals(created_at_unix_ms);
CREATE TRIGGER agent_mutation_journals_identity_immutable
BEFORE UPDATE ON agent_mutation_journals
WHEN NEW.owner_digest <> OLD.owner_digest
  OR NEW.client_operation_id <> OLD.client_operation_id
  OR NEW.request_hash <> OLD.request_hash
  OR NEW.keyed_request_identity <> OLD.keyed_request_identity
  OR NEW.fencing_generation <> OLD.fencing_generation
  OR NEW.project_root <> OLD.project_root
  OR NEW.request_project_root <> OLD.request_project_root
  OR NEW.agent_name IS NOT OLD.agent_name
  OR NEW.action <> OLD.action
  OR NEW.consumed_revision IS NOT OLD.consumed_revision
  OR NEW.affected_hint <> OLD.affected_hint
  OR NEW.changed_hint <> OLD.changed_hint
  OR NEW.consumed_config_generation <> OLD.consumed_config_generation
  OR NEW.mutation_intent_hash <> OLD.mutation_intent_hash
  OR NEW.consumed_projection_identity <> OLD.consumed_projection_identity
  OR NEW.intended_projection_identity <> OLD.intended_projection_identity
  OR NEW.created_at_unix_ms <> OLD.created_at_unix_ms
BEGIN
    SELECT RAISE(ABORT, 'agent mutation journal identity is immutable');
END;

-- External editor leases are durable authority, not frontend/UI state. The
-- markdown submitted at completion is represented only by an installation-
-- and vault-keyed identity; a retry must supply the same bytes. An open lease
-- references an owner-bound AEAD payload in the secret vault by opaque handle;
-- plaintext edit snapshots never enter this table. Terminal rows retain only
-- target/revision metadata, the completion identity, and a secret-free
-- result/error receipt until bounded retention removes them. Reservation
-- atomically replaces the edit snapshot with an owner-bound sealed completion
-- payload so daemon and client crashes cannot strand an unverifiable write.
CREATE TABLE agent_editor_leases (
    owner_digest        TEXT NOT NULL,
    client_operation_id TEXT NOT NULL,
    lease_id            TEXT NOT NULL UNIQUE,
    project_root        TEXT NOT NULL,
    agent_name          TEXT NOT NULL,
    consumed_revision   TEXT NOT NULL,
    snapshot_handle     TEXT,
    snapshot_identity   BLOB NOT NULL CHECK (
        typeof(snapshot_identity) = 'blob' AND length(snapshot_identity) = 32
    ),
    state               TEXT NOT NULL CHECK (state IN ('open', 'completing', 'terminal')),
    completion_identity BLOB CHECK (
        completion_identity IS NULL OR
        (typeof(completion_identity) = 'blob' AND length(completion_identity) = 32)
    ),
    completion_handle TEXT,
    completion_operation_id TEXT,
    publication_phase TEXT NOT NULL DEFAULT 'none' CHECK (
        publication_phase IN ('none', 'intent', 'published')
    ),
    consumed_projection_identity TEXT CHECK (
        consumed_projection_identity IS NULL OR (
            length(consumed_projection_identity) = 64 AND
            consumed_projection_identity NOT GLOB '*[^0-9a-f]*'
        )
    ),
    intended_projection_identity TEXT CHECK (
        intended_projection_identity IS NULL OR (
            length(intended_projection_identity) = 64 AND
            intended_projection_identity NOT GLOB '*[^0-9a-f]*'
        )
    ),
    publication_result_revision TEXT CHECK (
        publication_result_revision IS NULL OR length(trim(publication_result_revision)) > 0
    ),
    consumed_config_generation INTEGER CHECK (
        consumed_config_generation IS NULL OR consumed_config_generation >= 0
    ),
    result_config_generation INTEGER CHECK (
        result_config_generation IS NULL OR result_config_generation >= 0
    ),
    terminal_result_json TEXT CHECK (
        terminal_result_json IS NULL OR json_valid(terminal_result_json)
    ),
    terminal_error_json TEXT CHECK (
        terminal_error_json IS NULL OR json_valid(terminal_error_json)
    ),
    expires_at_unix_ms  INTEGER NOT NULL,
    created_at_unix_ms  INTEGER NOT NULL,
    updated_at_unix_ms  INTEGER NOT NULL,
    PRIMARY KEY (owner_digest, client_operation_id),
    CHECK (length(trim(owner_digest)) > 0),
    CHECK (length(trim(client_operation_id)) > 0),
    CHECK (length(trim(project_root)) > 0),
    CHECK (length(trim(agent_name)) > 0),
    CHECK (length(trim(consumed_revision)) > 0),
    CHECK (snapshot_handle IS NULL OR length(trim(snapshot_handle)) > 0),
    CHECK (completion_handle IS NULL OR length(trim(completion_handle)) > 0),
    CHECK (completion_operation_id IS NULL OR length(trim(completion_operation_id)) > 0),
    CHECK ((state = 'open') = (completion_operation_id IS NULL)),
    CHECK ((state = 'open') = (completion_identity IS NULL)),
    CHECK ((state = 'completing') = (completion_handle IS NOT NULL)),
    CHECK ((publication_phase = 'none') = (consumed_projection_identity IS NULL)),
    CHECK ((publication_phase = 'none') = (intended_projection_identity IS NULL)),
    CHECK (publication_phase = 'none' OR state IN ('completing', 'terminal')),
    CHECK ((publication_phase = 'published') = (publication_result_revision IS NOT NULL)),
    CHECK ((consumed_config_generation IS NULL) = (result_config_generation IS NULL)),
    CHECK (result_config_generation IS NULL OR result_config_generation >= consumed_config_generation),
    CHECK (publication_phase = 'none' OR consumed_config_generation IS NOT NULL),
    CHECK (publication_phase <> 'published' OR result_config_generation IS NOT NULL),
    CHECK (publication_result_revision IS NULL OR state IN ('completing', 'terminal')),
    CHECK ((state = 'terminal') = ((terminal_result_json IS NOT NULL) OR (terminal_error_json IS NOT NULL))),
    CHECK (terminal_result_json IS NULL OR terminal_error_json IS NULL),
    CHECK ((state = 'open') = (snapshot_handle IS NOT NULL)),
    CHECK (updated_at_unix_ms >= created_at_unix_ms)
);
CREATE INDEX agent_editor_leases_open
ON agent_editor_leases(expires_at_unix_ms)
WHERE state <> 'terminal';
CREATE INDEX agent_editor_leases_terminal_retention
ON agent_editor_leases(updated_at_unix_ms)
WHERE state = 'terminal';
CREATE TRIGGER agent_editor_leases_identity_immutable
BEFORE UPDATE ON agent_editor_leases
WHEN NEW.owner_digest <> OLD.owner_digest
  OR NEW.client_operation_id <> OLD.client_operation_id
  OR NEW.lease_id <> OLD.lease_id
  OR NEW.project_root <> OLD.project_root
  OR NEW.agent_name <> OLD.agent_name
  OR NEW.consumed_revision <> OLD.consumed_revision
  OR NEW.snapshot_identity <> OLD.snapshot_identity
  OR (OLD.completion_operation_id IS NOT NULL AND NEW.completion_operation_id IS NOT OLD.completion_operation_id)
  OR (OLD.completion_handle IS NOT NULL AND NEW.completion_handle IS NOT OLD.completion_handle AND NEW.state <> 'terminal')
  OR (OLD.publication_result_revision IS NOT NULL AND NEW.publication_result_revision IS NOT OLD.publication_result_revision)
  OR (OLD.consumed_config_generation IS NOT NULL AND NEW.consumed_config_generation IS NOT OLD.consumed_config_generation)
  OR (OLD.result_config_generation IS NOT NULL AND NEW.result_config_generation IS NOT OLD.result_config_generation)
  OR (OLD.publication_phase = 'none' AND NEW.publication_phase NOT IN ('none', 'intent'))
  OR (OLD.publication_phase = 'intent' AND NEW.publication_phase NOT IN ('intent', 'published'))
  OR (OLD.publication_phase = 'published' AND NEW.publication_phase <> 'published')
  OR (OLD.consumed_projection_identity IS NOT NULL AND NEW.consumed_projection_identity IS NOT OLD.consumed_projection_identity)
  OR (OLD.intended_projection_identity IS NOT NULL AND NEW.intended_projection_identity IS NOT OLD.intended_projection_identity)
  OR (NEW.snapshot_handle IS NOT OLD.snapshot_handle AND NEW.state NOT IN ('completing', 'terminal'))
  OR NEW.expires_at_unix_ms <> OLD.expires_at_unix_ms
  OR NEW.created_at_unix_ms <> OLD.created_at_unix_ms
BEGIN
    SELECT RAISE(ABORT, 'agent editor lease identity is immutable');
END;
CREATE TRIGGER agent_editor_leases_terminal_is_final
BEFORE UPDATE ON agent_editor_leases
WHEN OLD.state = 'terminal'
BEGIN
    SELECT RAISE(ABORT, 'agent editor terminal receipt is final');
END;

-- Secret-safe recovery intent for typed extended-config publication. Raw
-- merged configuration (which may contain unknown secret-bearing keys) never
-- enters SQLite: recovery compares only authoritative file hashes and replays
-- the already-redacted terminal response.
CREATE TABLE extended_config_patch_journals (
    owner_digest          TEXT NOT NULL,
    client_operation_id   TEXT NOT NULL,
    request_hash          BLOB NOT NULL CHECK (typeof(request_hash) = 'blob' AND length(request_hash) = 32),
    fencing_generation    INTEGER NOT NULL CHECK (fencing_generation > 0),
    project_root          TEXT NOT NULL,
    target_path           TEXT NOT NULL,
    consumed_content_hash TEXT NOT NULL CHECK (length(consumed_content_hash) = 64 AND consumed_content_hash = lower(consumed_content_hash)),
    intended_content_hash TEXT NOT NULL CHECK (length(intended_content_hash) = 64 AND intended_content_hash = lower(intended_content_hash)),
    terminal_response_json TEXT NOT NULL CHECK (json_valid(terminal_response_json)),
    created_at_unix_ms    INTEGER NOT NULL,
    PRIMARY KEY (owner_digest, client_operation_id),
    CHECK (length(trim(project_root)) > 0),
    CHECK (length(trim(target_path)) > 0)
);
CREATE INDEX extended_config_patch_journals_created
ON extended_config_patch_journals(created_at_unix_ms);

-- Secret-safe recovery intent for the dedicated image-generation registry
-- writer. The registry can contain credential references, headers, signed
-- evidence URLs, and opaque workflow graphs, so SQLite retains hashes and the
-- redacted terminal receipt only; raw intended configuration stays solely in
-- the atomically-published config document.
CREATE TABLE image_config_mutation_journals (
    owner_digest           TEXT NOT NULL,
    client_operation_id    TEXT NOT NULL,
    request_hash           BLOB NOT NULL CHECK (typeof(request_hash) = 'blob' AND length(request_hash) = 32),
    fencing_generation     INTEGER NOT NULL CHECK (fencing_generation > 0),
    mutation_intent_hash   TEXT NOT NULL CHECK (length(mutation_intent_hash) = 64 AND mutation_intent_hash = lower(mutation_intent_hash)),
    project_root           TEXT NOT NULL,
    target_path            TEXT NOT NULL,
    consumed_revision      TEXT NOT NULL CHECK (length(consumed_revision) = 64 AND consumed_revision = lower(consumed_revision)),
    intended_revision      TEXT NOT NULL CHECK (length(intended_revision) = 64 AND intended_revision = lower(intended_revision)),
    consumed_generation    INTEGER NOT NULL CHECK (consumed_generation >= 0),
    publication_phase      TEXT NOT NULL CHECK (publication_phase IN ('prepared', 'publication_authorized')),
    terminal_response_json TEXT NOT NULL CHECK (json_valid(terminal_response_json)),
    created_at_unix_ms     INTEGER NOT NULL,
    PRIMARY KEY (owner_digest, client_operation_id),
    FOREIGN KEY (owner_digest, client_operation_id)
        REFERENCES local_operation_receipts(owner_digest, client_operation_id)
        ON DELETE CASCADE ON UPDATE RESTRICT,
    CHECK (length(trim(project_root)) > 0),
    CHECK (length(trim(target_path)) > 0)
);
CREATE INDEX image_config_mutation_journals_created
ON image_config_mutation_journals(created_at_unix_ms);
CREATE TRIGGER image_config_mutation_journals_identity_immutable
BEFORE UPDATE ON image_config_mutation_journals
WHEN NEW.owner_digest <> OLD.owner_digest
  OR NEW.client_operation_id <> OLD.client_operation_id
  OR NEW.request_hash <> OLD.request_hash
  OR NEW.fencing_generation <> OLD.fencing_generation
  OR NEW.mutation_intent_hash <> OLD.mutation_intent_hash
  OR NEW.project_root <> OLD.project_root
  OR NEW.target_path <> OLD.target_path
  OR NEW.consumed_revision <> OLD.consumed_revision
  OR NEW.intended_revision <> OLD.intended_revision
  OR NEW.consumed_generation <> OLD.consumed_generation
  OR (OLD.publication_phase = 'publication_authorized' AND NEW.publication_phase <> OLD.publication_phase)
  OR NEW.created_at_unix_ms <> OLD.created_at_unix_ms
BEGIN
    SELECT RAISE(ABORT, 'image config mutation journal identity is immutable and publication phase is monotonic');
END;

-- Durable ownership claims for daemon-generated provider/MCP named secrets.
-- Claims survive journal retirement so cleanup decisions do not depend on a
-- pending write being present. Multiple roots may claim a shared reference;
-- cleanup must retain it until every claim is retired.
CREATE TABLE secret_named_ownership (
    item_id       TEXT NOT NULL,
    owner_kind    TEXT NOT NULL CHECK (owner_kind IN ('provider', 'mcp')),
    project_root  TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    PRIMARY KEY (item_id, owner_kind, project_root)
);
CREATE INDEX secret_named_ownership_item ON secret_named_ownership(item_id);

CREATE TABLE secret_credential_ownership (
    item_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    project_root TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (item_id, provider_id, project_root)
);

CREATE INDEX secret_credential_ownership_item
ON secret_credential_ownership(item_id);

-- ---- versioned agent installations ---------------------------------------
--
-- The daemon owns definition resolution and provider configuration.  This
-- schema deliberately records only the resulting non-secret identities,
-- digests, and canonical snapshots.  In particular, there is no credential,
-- token, API-key, or provider-route payload column in this subsystem.

CREATE TABLE agent_installations (
    installation_id              TEXT PRIMARY KEY,
    scope                        TEXT NOT NULL CHECK (scope IN ('global', 'workspace_private', 'workspace_shared')),
    -- Empty only for global.  A non-null key avoids SQLite's NULL-unique
    -- behaviour making two global same-name definitions accidentally distinct.
    scope_workspace_key          TEXT NOT NULL DEFAULT '',
    canonical_workspace_id       TEXT,
    source_agent_id              TEXT NOT NULL,
    source_identity              TEXT NOT NULL,
    source_revision              TEXT,
    source_digest                TEXT NOT NULL,
    fetched_at_unix_ms           INTEGER NOT NULL,
    installation_revision        INTEGER NOT NULL DEFAULT 1 CHECK (installation_revision >= 1),
    deleted_at_unix_ms            INTEGER,
    CHECK ((scope = 'global' AND scope_workspace_key = '' AND canonical_workspace_id IS NULL)
        OR (scope <> 'global' AND scope_workspace_key <> '' AND canonical_workspace_id = scope_workspace_key)),
    UNIQUE (scope, scope_workspace_key, source_agent_id)
);

CREATE TABLE installation_observations (
    installation_id              TEXT PRIMARY KEY REFERENCES agent_installations(installation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    observed_digest              TEXT NOT NULL,
    observation_revision         INTEGER NOT NULL CHECK (observation_revision >= 1),
    review_state                  TEXT NOT NULL CHECK (review_state IN ('reviewed', 'rebind_required')),
    observed_at_unix_ms           INTEGER NOT NULL
);

CREATE TABLE agent_model_bindings (
    binding_id                    TEXT PRIMARY KEY,
    installation_id               TEXT NOT NULL REFERENCES agent_installations(installation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    definition_digest             TEXT NOT NULL,
    slot_id                       TEXT NOT NULL,
    provider_profile_handle       TEXT NOT NULL,
    model_id                      TEXT NOT NULL,
    -- Canonical redacted non-secret provenance: recommendation ids/order,
    -- upstream identities, aliases, capability result, etc.  This is an
    -- opaque DB payload; it is resolved and validated by the caller.
    provenance_payload            BLOB NOT NULL,
    provenance_digest             TEXT NOT NULL,
    -- Bind is admitted only after daemon-side hard capability validation.
    -- Persist the result so a snapshot must prove its evidence against an
    -- immutable accepted binding, rather than trusting a caller-provided bit.
    hard_capability_verified      INTEGER NOT NULL CHECK (hard_capability_verified = 1),
    binding_revision              INTEGER NOT NULL CHECK (binding_revision >= 1),
    -- Exactly one live default per slot is enforced by the partial unique
    -- index below. Durable identity is (provider_profile_handle, model_id),
    -- never a positional choice_id.
    is_default                    INTEGER NOT NULL CHECK (is_default IN (0, 1)),
    retired_at_unix_ms            INTEGER,
    created_at_unix_ms            INTEGER NOT NULL,
    UNIQUE (installation_id, definition_digest, slot_id, provider_profile_handle, model_id, binding_revision)
);
CREATE UNIQUE INDEX agent_model_bindings_current_slot
    ON agent_model_bindings(installation_id, definition_digest, slot_id, provider_profile_handle, model_id)
    WHERE retired_at_unix_ms IS NULL;
CREATE UNIQUE INDEX agent_model_bindings_current_slot_default
    ON agent_model_bindings(installation_id, definition_digest, slot_id)
    WHERE retired_at_unix_ms IS NULL AND is_default = 1;
CREATE TRIGGER agent_model_bindings_live_alternate_requires_default
BEFORE INSERT ON agent_model_bindings
WHEN NEW.retired_at_unix_ms IS NULL AND NEW.is_default = 0
 AND NOT EXISTS (
    SELECT 1 FROM agent_model_bindings b
    WHERE b.installation_id = NEW.installation_id
      AND b.definition_digest = NEW.definition_digest
      AND b.slot_id = NEW.slot_id
      AND b.retired_at_unix_ms IS NULL AND b.is_default = 1
 )
BEGIN
    SELECT RAISE(ABORT, 'live agent model binding slot requires exactly one default');
END;
CREATE TRIGGER agent_model_bindings_live_default_cannot_retire_first
BEFORE UPDATE OF installation_id, definition_digest, slot_id, retired_at_unix_ms, is_default ON agent_model_bindings
WHEN OLD.retired_at_unix_ms IS NULL AND OLD.is_default = 1
 AND (
    NEW.retired_at_unix_ms IS NOT NULL
    OR NEW.is_default = 0
    OR NEW.installation_id <> OLD.installation_id
    OR NEW.definition_digest <> OLD.definition_digest
    OR NEW.slot_id <> OLD.slot_id
 )
 AND EXISTS (
    SELECT 1 FROM agent_model_bindings b
    WHERE b.installation_id = OLD.installation_id
      AND b.definition_digest = OLD.definition_digest
      AND b.slot_id = OLD.slot_id
      AND b.binding_id <> OLD.binding_id
      AND b.retired_at_unix_ms IS NULL
 )
BEGIN
    SELECT RAISE(ABORT, 'live agent model binding default cannot leave a nonempty slot');
END;
CREATE TRIGGER agent_model_bindings_live_update_requires_default
BEFORE UPDATE OF installation_id, definition_digest, slot_id, retired_at_unix_ms, is_default ON agent_model_bindings
WHEN NEW.retired_at_unix_ms IS NULL AND NEW.is_default = 0
 AND NOT EXISTS (
    SELECT 1 FROM agent_model_bindings b
    WHERE b.installation_id = NEW.installation_id
      AND b.definition_digest = NEW.definition_digest
      AND b.slot_id = NEW.slot_id
      AND b.binding_id <> NEW.binding_id
      AND b.retired_at_unix_ms IS NULL
      AND b.is_default = 1
 )
BEGIN
    SELECT RAISE(ABORT, 'live agent model binding slot requires exactly one default');
END;
CREATE TRIGGER agent_model_bindings_live_default_cannot_delete_first
BEFORE DELETE ON agent_model_bindings
WHEN OLD.retired_at_unix_ms IS NULL AND OLD.is_default = 1
 AND EXISTS (
    SELECT 1 FROM agent_model_bindings b
    WHERE b.installation_id = OLD.installation_id
      AND b.definition_digest = OLD.definition_digest
      AND b.slot_id = OLD.slot_id
      AND b.binding_id <> OLD.binding_id
      AND b.retired_at_unix_ms IS NULL
 )
BEGIN
    SELECT RAISE(ABORT, 'delete live agent model alternates before their default');
END;

-- The daemon installation service owns these operation rows.  They are
-- deliberately separate from `agent_installations`: replay/recovery may
-- observe or finish a file journal, but it must invoke the installation
-- transaction above as the sole authority that changes binding/snapshot/
-- revision state.
CREATE TABLE installation_operations (
    operation_id                 TEXT PRIMARY KEY,
    idempotency_key              TEXT NOT NULL UNIQUE,
    request_fingerprint          TEXT NOT NULL,
    operation_kind               TEXT NOT NULL CHECK (operation_kind IN ('install', 'update', 'bind', 'create')),
    canonical_workspace_id       TEXT,
    state                        TEXT NOT NULL CHECK (state IN ('pending_choice', 'running', 'terminal')),
    terminal_receipt_json        TEXT,
    created_at_unix_ms           INTEGER NOT NULL,
    updated_at_unix_ms           INTEGER NOT NULL,
    CHECK ((state = 'terminal') = (terminal_receipt_json IS NOT NULL))
);

CREATE TABLE installation_continuations (
    continuation_token           TEXT PRIMARY KEY,
    operation_id                 TEXT NOT NULL UNIQUE REFERENCES installation_operations(operation_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    choice_set_json              TEXT NOT NULL,
    expires_at_unix_ms           INTEGER NOT NULL,
    submitted_choice_id          TEXT,
    state                        TEXT NOT NULL CHECK (state IN ('pending', 'claimed', 'expired', 'completed')),
    created_at_unix_ms           INTEGER NOT NULL,
    updated_at_unix_ms           INTEGER NOT NULL
);
CREATE INDEX installation_continuations_expiry
ON installation_continuations(state, expires_at_unix_ms);

CREATE TABLE installation_journals (
    journal_id                   TEXT PRIMARY KEY,
    operation_id                 TEXT NOT NULL UNIQUE REFERENCES installation_operations(operation_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    checkpoint                   TEXT NOT NULL CHECK (checkpoint IN ('staged', 'db_committed', 'file_renamed', 'complete')),
    staged_file_metadata_json    TEXT,
    prior_file_metadata_json     TEXT,
    expected_digest              TEXT NOT NULL,
    created_at_unix_ms           INTEGER NOT NULL,
    updated_at_unix_ms           INTEGER NOT NULL
);

-- Bind requests get their own receipt because a retry must be distinguished
-- from a different mutation that happens to choose identical model metadata.
CREATE TABLE agent_binding_receipts (
    installation_id               TEXT NOT NULL REFERENCES agent_installations(installation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    definition_digest             TEXT NOT NULL,
    slot_id                       TEXT NOT NULL,
    idempotency_key               TEXT NOT NULL,
    request_fingerprint           TEXT NOT NULL,
    binding_id                    TEXT NOT NULL REFERENCES agent_model_bindings(binding_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    created_at_unix_ms            INTEGER NOT NULL,
    PRIMARY KEY (installation_id, definition_digest, slot_id, idempotency_key)
);
CREATE INDEX idx_agent_binding_receipts_binding_id
    ON agent_binding_receipts(binding_id);

CREATE TABLE agent_profile_snapshots (
    snapshot_id                   TEXT PRIMARY KEY,
    -- A session has one prepared/root snapshot but may also pin distinct
    -- immutable snapshots for delegated children. The preparation receipt
    -- owns root selection; a UNIQUE session_id here would silently force
    -- every child utility decision onto the root binding.
    session_id                    TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    installation_id               TEXT NOT NULL REFERENCES agent_installations(installation_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    schema_version                INTEGER NOT NULL CHECK (schema_version >= 1),
    canonical_payload             BLOB NOT NULL,
    canonical_payload_digest      TEXT NOT NULL,
    definition_digest             TEXT NOT NULL,
    binding_revision_map_payload  BLOB NOT NULL,
    binding_revision_map_digest   TEXT NOT NULL,
    created_at_unix_ms            INTEGER NOT NULL,
    UNIQUE (snapshot_id, session_id)
);

CREATE TABLE agent_session_preparations (
    session_id                    TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    idempotency_key               TEXT NOT NULL,
    request_fingerprint           TEXT NOT NULL,
    snapshot_id                   TEXT NOT NULL UNIQUE REFERENCES agent_profile_snapshots(snapshot_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    -- This receipt is the module-owned Prepared marker.  A pre-existing
    -- ordinary active session can never acquire a profile snapshot later.
    -- `0` means the caller atomically claimed a pre-registered, idle
    -- session through `agent_session_preparation_claims`; `1` means this
    -- transaction created the session.  Neither spelling permits attaching a
    -- profile to an arbitrary active session.
    created_session               INTEGER NOT NULL CHECK (created_session IN (0, 1)),
    lifecycle_state               TEXT NOT NULL CHECK (lifecycle_state IN ('prepared', 'running', 'terminal')),
    created_at_unix_ms            INTEGER NOT NULL,
    started_at_unix_ms            INTEGER,
    terminal_at_unix_ms           INTEGER,
    PRIMARY KEY (session_id, idempotency_key)
);

-- An existing normal session is preparable only after its owner records this
-- durable, single-use marker.  Preparation CASes `eligible` to `claimed` in
-- the same transaction as its immutable snapshot; an ordinary active session
-- has no marker and is therefore never silently adopted.
CREATE TABLE agent_session_preparation_claims (
    session_id                    TEXT PRIMARY KEY REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    claim_token                   TEXT NOT NULL UNIQUE,
    claim_state                   TEXT NOT NULL CHECK (claim_state IN ('eligible', 'claimed', 'running', 'terminal')),
    created_at_unix_ms            INTEGER NOT NULL,
    claimed_at_unix_ms            INTEGER,
    terminal_at_unix_ms           INTEGER
);
CREATE INDEX idx_agent_session_preparation_claims_recovery
    ON agent_session_preparation_claims(claim_state, session_id);

-- Once an owner has offered an existing idle session to agent preparation,
-- ordinary dispatch must not race in work before the preparation claim either
-- starts or terminals.  The start CAS changes the marker to `running` before
-- any event can be recorded.
CREATE TRIGGER agent_session_preparation_claim_blocks_events
BEFORE INSERT ON session_events
WHEN EXISTS (
    SELECT 1 FROM agent_session_preparation_claims AS claim
    WHERE claim.session_id = NEW.session_id
      AND claim.claim_state IN ('eligible', 'claimed')
)
BEGIN
    SELECT RAISE(ABORT, 'agent session preparation claim is pending');
END;

CREATE TRIGGER agent_profile_snapshot_immutable
BEFORE UPDATE ON agent_profile_snapshots
BEGIN
    SELECT RAISE(ABORT, 'agent profile snapshots are immutable');
END;

CREATE INDEX agent_profile_snapshots_session_root_lookup
    ON agent_profile_snapshots(session_id, created_at_unix_ms, snapshot_id);

CREATE INDEX agent_model_bindings_lookup
    ON agent_model_bindings(installation_id, definition_digest, slot_id, retired_at_unix_ms);

-- ---- message_tool_media_subject_bindings -----------------------------------
-- Durable, server-private authenticated binding between an accepted message
-- submission and the media subject authority that admitted its attachments.
-- The locator is sealed with XChaCha20-Poly1305 using an HKDF-SHA-256 key
-- derived from the referenced secure-key version. Core owns receipt/seal
-- encoding; cockpit-db validates byte-shape constraints only and never
-- depends on cockpit-core crypto types.
CREATE TABLE message_tool_media_subject_bindings (
    session_id             TEXT NOT NULL,
    client_submission_id   BLOB NOT NULL CHECK (typeof(client_submission_id) = 'blob' AND length(client_submission_id) = 16),
    receipt_version        INTEGER NOT NULL CHECK (receipt_version = 1),
    issuer_kind            INTEGER NOT NULL CHECK (issuer_kind IN (1, 2)),
    principal_digest       BLOB NOT NULL CHECK (typeof(principal_digest) = 'blob' AND length(principal_digest) = 32),
    project_digest         BLOB NOT NULL CHECK (typeof(project_digest) = 'blob' AND length(project_digest) = 32),
    authorization_epoch    INTEGER NOT NULL CHECK (authorization_epoch >= 0),
    subject_digest         BLOB NOT NULL CHECK (typeof(subject_digest) = 'blob' AND length(subject_digest) = 32),
    seal_version           INTEGER NOT NULL CHECK (seal_version = 1),
    key_namespace          TEXT NOT NULL CHECK (key_namespace = 'tool_media_subject_binding'),
    key_version            INTEGER NOT NULL CHECK (key_version > 0),
    nonce                  BLOB NOT NULL CHECK (typeof(nonce) = 'blob' AND length(nonce) = 24),
    ciphertext             BLOB NOT NULL CHECK (typeof(ciphertext) = 'blob' AND length(ciphertext) > 16),
    secure_key_reference_id TEXT NOT NULL UNIQUE,
    created_at             INTEGER NOT NULL,
    updated_at             INTEGER NOT NULL,
    PRIMARY KEY (session_id, client_submission_id),
    UNIQUE (session_id, client_submission_id, subject_digest),
    FOREIGN KEY (session_id, client_submission_id)
        REFERENCES message_submission_receipts(session_id, client_submission_id) ON DELETE CASCADE ON UPDATE RESTRICT
);
CREATE INDEX idx_message_tool_media_subject_bindings_epoch
    ON message_tool_media_subject_bindings (session_id, authorization_epoch);

-- Integrity backstop for a caller that deletes a submission receipt without
-- first using the explicit DB release funnel. The binding FK will cascade
-- after this BEFORE trigger, so move its still-reachable consumer reference
-- out of Active while the reference id can still be selected. The explicit
-- funnel already performs the same transition before deleting the binding;
-- this trigger is therefore a no-op on that path.
CREATE TRIGGER release_tool_media_subject_ref_before_submission_delete
BEFORE DELETE ON message_submission_receipts
BEGIN
    UPDATE secure_key_consumer_refs
       SET state = 'Releasing', updated_at = MAX(updated_at, unixepoch())
     WHERE reference_id IN (
               SELECT secure_key_reference_id
                 FROM message_tool_media_subject_bindings
                WHERE session_id = OLD.session_id
                  AND client_submission_id = OLD.client_submission_id
           )
       AND state = 'Active';
END;

-- ---- tool_media_authorization_epochs ---------------------------------------
-- Per-(issuer, principal, session, project) monotonic epoch incremented on
-- every authority-affecting control-state change (device revocation, authority
-- status transition, local membership/read-path change, installation
-- ownership change). A binding's authorization_epoch must match the current
-- epoch for the key tuple to remain valid.
CREATE TABLE tool_media_authorization_epochs (
    issuer_kind            INTEGER NOT NULL CHECK (issuer_kind IN (1, 2)),
    principal_digest       BLOB NOT NULL CHECK (typeof(principal_digest) = 'blob' AND length(principal_digest) = 32),
    session_id             TEXT NOT NULL,
    project_digest         BLOB NOT NULL CHECK (typeof(project_digest) = 'blob' AND length(project_digest) = 32),
    epoch                  INTEGER NOT NULL CHECK (epoch >= 0),
    created_at             INTEGER NOT NULL,
    updated_at             INTEGER NOT NULL,
    PRIMARY KEY (issuer_kind, principal_digest, session_id, project_digest)
);

-- Durable sanitized computer-action outcome receipts. Identity is
-- (session, delegation, provider_call_id, batch_index) plus payload digest.
-- Columns hold sanitized serde / digests / ids only: never pixels or wire
-- payloads.
CREATE TABLE computer_outcome_store (
    session_id        TEXT    NOT NULL,
    delegation_id     TEXT    NOT NULL,
    provider_call_id  TEXT    NOT NULL,
    batch_index       INTEGER NOT NULL CHECK (batch_index >= 0),
    payload_digest    TEXT    NOT NULL CHECK (
        length(payload_digest) = 64
        AND payload_digest = lower(payload_digest)
        AND payload_digest NOT GLOB '*[^0-9a-f]*'
    ),
    outcome_json      TEXT    NOT NULL CHECK (
        json_valid(outcome_json)
        AND length(CAST(outcome_json AS BLOB)) <= 1048576
    ),
    state             TEXT    NOT NULL CHECK (state IN ('claimed', 'completed')),
    committed_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY (session_id, delegation_id, provider_call_id, batch_index),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

CREATE INDEX idx_computer_outcome_store_session_delegation
    ON computer_outcome_store(session_id, delegation_id);

-- ---- guidance_proposal_receipts (issue #59) --------------------------------
-- Content-free durable receipts for the user-reviewed typed computer-use
-- guidance proposal lifecycle. Typed rule values and rationale live ONLY in
-- daemon memory (PendingProposalStore) and are NEVER persisted here — this
-- table holds IDs, three opaque scope digests, the config generation, the
-- rule-kind bitmask, timestamps, and the terminal state. Caps (3 per
-- delegation / 10 per session) are enforced transactionally against the
-- companion `guidance_proposal_counters` table at create time; a receipt
-- remains counted once created regardless of its terminal state.
--
-- `state` transitions: created → {accepted, rejected, expired,
-- expired_on_restart}. `expired_on_restart` is the startup-reconciliation
-- terminal for receipts still `created` after a daemon restart (their
-- memory-only values are unrecoverable); it audits exactly once and never
-- re-increments counters. `accepted_scope` is set only on `accepted`
-- receipts (session | persistent). At most one live `created` receipt may
-- exist per (session_id, delegation_id, canonical_project_digest,
-- provider_digest, model_digest) — enforced by the partial unique index.
CREATE TABLE guidance_proposal_receipts (
    proposal_id              TEXT    PRIMARY KEY CHECK (
        length(proposal_id) = 32
        AND proposal_id = lower(proposal_id)
        AND proposal_id NOT GLOB '*[^0-9a-f]*'
    ),
    -- The session UUID text (matches sessions.session_id spelling) — no FK
    -- because a receipt may outlive its session row during retention.
    session_id               TEXT    NOT NULL CHECK (length(session_id) BETWEEN 1 AND 64),
    delegation_id            TEXT    NOT NULL CHECK (length(delegation_id) BETWEEN 1 AND 64),
    canonical_project_digest TEXT    NOT NULL CHECK (
        length(canonical_project_digest) = 64
        AND canonical_project_digest = lower(canonical_project_digest)
        AND canonical_project_digest NOT GLOB '*[^0-9a-f]*'
    ),
    provider_digest          TEXT    NOT NULL CHECK (
        length(provider_digest) = 64
        AND provider_digest = lower(provider_digest)
        AND provider_digest NOT GLOB '*[^0-9a-f]*'
    ),
    model_digest             TEXT    NOT NULL CHECK (
        length(model_digest) = 64
        AND model_digest = lower(model_digest)
        AND model_digest NOT GLOB '*[^0-9a-f]*'
    ),
    config_generation        INTEGER NOT NULL CHECK (config_generation >= 0),
    -- Bitmask over the six closed rule kinds (bits 0..5); at least one bit
    -- must be set and only bits 0..5 are valid.
    rule_kind_bits           INTEGER NOT NULL CHECK (
        rule_kind_bits BETWEEN 1 AND 63
    ),
    -- Daemon-observed wall-clock times, signed Unix milliseconds.
    created_at_unix_ms       INTEGER NOT NULL,
    expires_at_unix_ms       INTEGER NOT NULL CHECK (expires_at_unix_ms >= created_at_unix_ms),
    state                    TEXT    NOT NULL DEFAULT 'created'
        CHECK (state IN ('created', 'accepted', 'rejected', 'expired', 'expired_on_restart')),
    accepted_scope           TEXT    CHECK (
        accepted_scope IS NULL OR accepted_scope IN ('session', 'persistent')
    ),
    transitioned_at_unix_ms  INTEGER CHECK (
        transitioned_at_unix_ms IS NULL OR transitioned_at_unix_ms >= created_at_unix_ms
    ),
    -- Invariant: accepted_scope is non-NULL only when state = 'accepted'.
    CHECK (
        (state = 'accepted' AND accepted_scope IS NOT NULL)
        OR (state != 'accepted' AND accepted_scope IS NULL)
    )
);

CREATE INDEX idx_guidance_proposal_receipts_session
    ON guidance_proposal_receipts(session_id);
CREATE INDEX idx_guidance_proposal_receipts_delegation
    ON guidance_proposal_receipts(delegation_id);
CREATE INDEX idx_guidance_proposal_receipts_state
    ON guidance_proposal_receipts(state, created_at_unix_ms);
-- At most one live `created` receipt per pending-proposal scope. Terminal
-- rows remain counted by the companion counters; they just leave this index
-- so a later create on the same scope can reuse it.
CREATE UNIQUE INDEX uq_guidance_proposal_receipts_one_created_per_scope
    ON guidance_proposal_receipts(
        session_id,
        delegation_id,
        canonical_project_digest,
        provider_digest,
        model_digest
    )
    WHERE state = 'created';

-- Per-session and per-delegation creation counters for the 3/10 caps. A
-- counter is incremented in the same transaction as the receipt insert and
-- is never decremented: accepted/rejected/expired receipts remain counted
-- (creation consumed quota). Startup `expired_on_restart` reconciliation
-- does NOT re-increment these counters.
CREATE TABLE guidance_proposal_counters (
    scope_kind TEXT    NOT NULL CHECK (scope_kind IN ('session', 'delegation')),
    scope_id   TEXT    NOT NULL CHECK (length(scope_id) BETWEEN 1 AND 64),
    count      INTEGER NOT NULL DEFAULT 0 CHECK (count >= 0),
    PRIMARY KEY (scope_kind, scope_id)
);

-- Machine-local accepted guidance.  Unlike proposal receipts, an accepted
-- persistent rule necessarily contains its typed three-byte value.  It is
-- deliberately isolated from config/export tables and keyed only by opaque
-- local scope digests.  Session-scoped accepted rules never enter SQLite.
CREATE TABLE accepted_persistent_guidance_rules (
    canonical_project_digest TEXT NOT NULL CHECK (length(canonical_project_digest) = 64),
    provider_digest          TEXT NOT NULL CHECK (length(provider_digest) = 64),
    model_digest             TEXT NOT NULL CHECK (length(model_digest) = 64),
    rule_kind                INTEGER NOT NULL CHECK (rule_kind BETWEEN 1 AND 6),
    encoded_rule             BLOB NOT NULL CHECK (length(encoded_rule) = 3),
    updated_at_unix_ms       INTEGER NOT NULL,
    PRIMARY KEY (canonical_project_digest, provider_digest, model_digest, rule_kind)
);

-- Durable audit outbox.  Receipt transition and outbox insertion are one
-- transaction, closing the CAS-before-audit crash window.  Payload fields are
-- the receipt's content-free metadata; typed values and rationale never enter
-- this table.  A delivered row is retained for idempotent recovery.
CREATE TABLE guidance_proposal_audit_outbox (
    proposal_id       TEXT NOT NULL,
    terminal_state    TEXT NOT NULL CHECK (terminal_state IN ('created','accepted','rejected','expired','expired_on_restart')),
    accepted_scope    TEXT CHECK (accepted_scope IS NULL OR accepted_scope IN ('session','persistent')),
    transitioned_at_unix_ms INTEGER NOT NULL,
    delivered_at_unix_ms INTEGER,
    PRIMARY KEY (proposal_id, terminal_state),
    FOREIGN KEY (proposal_id) REFERENCES guidance_proposal_receipts(proposal_id) ON DELETE CASCADE ON UPDATE RESTRICT
);

-- Local image-sidecar destination grants are daemon-owned durable authority.
-- There is intentionally no global scope. Invocation audit rows are added
-- only with the live provider handoff; an unavailable pipeline must not mint
-- fictional records.
CREATE TABLE image_sidecar_entities (
    project_id TEXT PRIMARY KEY CHECK (length(project_id) BETWEEN 1 AND 4096),
    entity_version INTEGER NOT NULL CHECK (entity_version >= 0)
);

CREATE TABLE image_sidecar_grants (
    grant_id TEXT PRIMARY KEY CHECK (length(grant_id) BETWEEN 1 AND 128),
    project_id TEXT NOT NULL REFERENCES image_sidecar_entities(project_id) ON DELETE CASCADE ON UPDATE RESTRICT,
    session_id TEXT,
    invocation_id TEXT,
    destination TEXT NOT NULL CHECK (length(destination) BETWEEN 1 AND 2048),
    media_class TEXT NOT NULL DEFAULT 'image' CHECK (media_class = 'image'),
    purpose TEXT NOT NULL CHECK (purpose IN ('dossier', 'ask_image')),
    scope TEXT NOT NULL CHECK (scope IN ('once', 'session', 'project')),
    created_at_unix_ms INTEGER NOT NULL,
    last_used_at_unix_ms INTEGER,
    revoked_at_unix_ms INTEGER,
    consumed_at_unix_ms INTEGER,
    version INTEGER NOT NULL CHECK (version >= 1),
    CHECK (
        (scope = 'once' AND session_id IS NOT NULL AND invocation_id IS NOT NULL)
        OR (scope = 'session' AND session_id IS NOT NULL AND invocation_id IS NULL)
        OR (scope = 'project' AND session_id IS NULL AND invocation_id IS NULL)
    )
);
CREATE INDEX image_sidecar_grants_project_created
    ON image_sidecar_grants(project_id, created_at_unix_ms, grant_id);

-- Leading child indexes required so every foreign key is prefixed by a
-- non-partial child index in declaration order. Composite agent-tree and
-- verification FKs keep (identity, session_id) as the leading pair; existing
-- session-leading recovery indexes stay for their own scans.
CREATE INDEX idx_media_attachment_components_attachment_version
    ON media_attachment_components(attachment_id, attachment_version);
CREATE INDEX idx_media_attachment_component_leases_component
    ON media_attachment_component_leases(component_id);
CREATE INDEX idx_media_component_security_evidence_attachment
    ON media_component_security_evidence(attachment_id);
CREATE INDEX idx_media_component_security_evidence_component
    ON media_component_security_evidence(component_id);
CREATE INDEX idx_media_attachment_cleanup_intents_attachment
    ON media_attachment_cleanup_intents(attachment_id, attachment_version);
CREATE INDEX idx_media_security_recovery_operations_attachment
    ON media_security_recovery_operations(attachment_id, attachment_version);
CREATE INDEX idx_media_local_path_registration_operations_session
    ON media_local_path_registration_operations(session_id);
CREATE INDEX idx_media_retained_https_operations_session
    ON media_retained_https_operations(session_id);
CREATE INDEX idx_media_attachment_processing_security_evidence_attachment
    ON media_attachment_processing_security_evidence(attachment_id);
CREATE INDEX idx_media_attachment_processing_security_evidence_component
    ON media_attachment_processing_security_evidence(component_id);
CREATE INDEX idx_media_attachment_processing_failure_evidence_attachment
    ON media_attachment_processing_failure_evidence(attachment_id);
CREATE INDEX idx_media_attachment_processing_output_security_evidence_attachment
    ON media_attachment_processing_output_security_evidence(attachment_id);
CREATE INDEX idx_media_artifact_facts_reservation
    ON media_artifact_facts(reservation_id);
CREATE INDEX idx_agent_instances_parent_session
    ON agent_instances(parent_agent_instance_id, session_id);
CREATE INDEX idx_agent_instances_task_delegation_job
    ON agent_instances(task_delegation_job_id);
CREATE INDEX idx_agent_instances_resolved_profile_session
    ON agent_instances(resolved_profile_snapshot_id, session_id);
CREATE INDEX idx_agent_instances_resolved_installation
    ON agent_instances(resolved_installation_id);
CREATE INDEX idx_root_agent_continuations_agent_session
    ON root_agent_continuations(agent_instance_id, session_id);
CREATE INDEX idx_recursive_noninteractive_executors_agent_session
    ON recursive_noninteractive_executors(agent_instance_id, session_id);
CREATE INDEX idx_recursive_noninteractive_executors_parent_session
    ON recursive_noninteractive_executors(parent_agent_instance_id, session_id);
CREATE INDEX idx_recursive_noninteractive_outcomes_agent_session
    ON recursive_noninteractive_outcomes(agent_instance_id, session_id);
CREATE INDEX idx_recursive_noninteractive_outcomes_parent_session
    ON recursive_noninteractive_outcomes(parent_agent_instance_id, session_id);
CREATE INDEX idx_agent_resume_claims_agent_session
    ON agent_resume_claims(agent_instance_id, session_id);
CREATE INDEX idx_decision_requests_agent_session
    ON decision_requests(agent_instance_id, session_id);
CREATE INDEX idx_decision_private_option_mappings_decision_session
    ON decision_private_option_mappings(decision_request_id, session_id);
CREATE INDEX idx_decision_receipts_decision_session
    ON decision_receipts(decision_request_id, session_id);
CREATE INDEX idx_decision_receipts_session_event
    ON decision_receipts(session_id, session_event_seq);
CREATE INDEX idx_agent_transition_receipts_agent_session
    ON agent_transition_receipts(agent_instance_id, session_id);
CREATE INDEX idx_agent_transition_receipts_session_event
    ON agent_transition_receipts(session_id, session_event_seq);
CREATE INDEX idx_agent_host_approval_operations_agent_session
    ON agent_host_approval_operations(agent_instance_id, session_id);
CREATE INDEX idx_host_capability_refresh_initializations_agent_session
    ON host_capability_refresh_initializations(agent_instance_id, session_id);
CREATE INDEX idx_host_capability_refresh_initializations_parent_session
    ON host_capability_refresh_initializations(parent_agent_instance_id, session_id);
CREATE INDEX idx_host_capability_refresh_initializations_decision_session
    ON host_capability_refresh_initializations(decision_request_id, session_id);
CREATE INDEX idx_host_capability_refresh_operations_agent_session
    ON host_capability_refresh_operations(agent_instance_id, session_id);
CREATE INDEX idx_host_capability_refresh_operations_decision_session
    ON host_capability_refresh_operations(decision_request_id, session_id);
CREATE INDEX idx_needs_attention_agent_session
    ON needs_attention(agent_instance_id, session_id);
CREATE INDEX idx_decision_attention_mutation_guards_decision_session
    ON decision_attention_mutation_guards(decision_request_id, session_id);
CREATE INDEX idx_verification_operations_agent_session
    ON verification_operations(agent_instance_id, session_id);
CREATE INDEX idx_verification_candidates_operation_session
    ON verification_candidates(operation_id, session_id);
CREATE INDEX idx_verification_candidate_artifacts_candidate_operation
    ON verification_candidate_artifacts(candidate_id, operation_id);
CREATE INDEX idx_verification_candidate_artifacts_candidate_session
    ON verification_candidate_artifacts(candidate_id, session_id);
CREATE INDEX idx_verification_late_results_candidate_operation
    ON verification_late_results(candidate_id, operation_id);
CREATE INDEX idx_verification_late_results_candidate_session
    ON verification_late_results(candidate_id, session_id);
CREATE INDEX idx_verification_late_results_operation_session
    ON verification_late_results(operation_id, session_id);
CREATE INDEX idx_verification_syntheses_selected_candidate_operation
    ON verification_syntheses(selected_candidate_id, operation_id);
CREATE INDEX idx_verification_synthesis_artifacts_source_candidate
    ON verification_synthesis_artifacts(source_candidate_id, source_artifact_ordinal);
CREATE INDEX idx_verification_projection_events_projection_session
    ON verification_projection_events(projection_id, session_id);
CREATE INDEX idx_session_fts_docs_session_seq
    ON session_fts_docs(session_id, seq);
CREATE INDEX idx_session_text_artifacts_archive_import
    ON session_text_artifacts(archive_import_id);
CREATE INDEX idx_session_text_artifacts_owner_ref
    ON session_text_artifacts(session_id, artifact_id, owner_event_seq, owner_relation, owner_slot);
CREATE INDEX idx_session_text_artifact_event_refs_session_event
    ON session_text_artifact_event_refs(session_id, event_seq);
CREATE INDEX idx_session_text_artifact_projection_pending_slots_unresolved
    ON session_text_artifact_projection_pending_slots(unresolved);
CREATE INDEX idx_session_text_artifact_quota_reservations_operation
    ON session_text_artifact_quota_reservations(session_id, operation_id);
CREATE INDEX idx_session_text_artifact_quota_reservations_queue_item
    ON session_text_artifact_quota_reservations(session_id, queue_item_id);
CREATE INDEX idx_session_text_artifact_run_invocation_bindings_invocation
    ON session_text_artifact_run_invocation_bindings(run_invocation_id);
CREATE INDEX idx_write_scope_leases_agent_session
    ON write_scope_leases(agent_instance_id, session_id);
CREATE INDEX idx_workspace_leases_agent_session
    ON workspace_leases(agent_instance_id, session_id);
CREATE INDEX idx_workspace_leases_write_scope
    ON workspace_leases(write_scope_lease_id);
CREATE INDEX idx_workspace_leases_parent_session
    ON workspace_leases(parent_workspace_lease_id, session_id);
CREATE INDEX idx_workspace_leases_pinned_by_session
    ON workspace_leases(pinned_by_agent_instance_id, session_id);
CREATE INDEX idx_task_artifacts_source_session
    ON task_artifacts(source_workspace_lease_id, session_id);
CREATE INDEX idx_task_artifacts_agent_session
    ON task_artifacts(agent_instance_id, session_id);
CREATE INDEX idx_agent_profile_snapshots_installation
    ON agent_profile_snapshots(installation_id);
