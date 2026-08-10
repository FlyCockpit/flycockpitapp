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

-- Authoritative exactly-once ledger for typed user-message submissions. UUID
-- identities that cross the canonical binary boundary are RFC-byte BLOBs;
-- actor identity is deliberately absent for the local-owner tuple.
CREATE TABLE message_operation_receipts (
    session_id             TEXT NOT NULL,
    operation_id           BLOB NOT NULL CHECK (typeof(operation_id) = 'blob' AND length(operation_id) = 16 AND operation_id <> zeroblob(16)),
    actor_kind             TEXT NOT NULL CHECK (actor_kind IN ('local_owner', 'remote_device')),
    actor_id               BLOB,
    -- Canonical unsigned big-endian u64: zeroblob(8) for local owner and a
    -- nonzero value for a remote-device generation.
    actor_generation       BLOB NOT NULL CHECK (typeof(actor_generation) = 'blob' AND length(actor_generation) = 8),
    request_hash           BLOB NOT NULL CHECK (typeof(request_hash) = 'blob' AND length(request_hash) = 32),
    message_request_digest BLOB NOT NULL CHECK (typeof(message_request_digest) = 'blob' AND length(message_request_digest) = 32),
    client_submission_id   BLOB NOT NULL CHECK (typeof(client_submission_id) = 'blob' AND length(client_submission_id) = 16 AND client_submission_id <> zeroblob(16)),
    state                  TEXT NOT NULL CHECK (state IN ('accepted', 'materialized', 'terminal_rejected', 'removed')),
    safe_outcome           BLOB NOT NULL CHECK (typeof(safe_outcome) = 'blob'),
    outbox_sequence        INTEGER NOT NULL CHECK (outbox_sequence >= 0),
    created_at             INTEGER NOT NULL,
    updated_at             INTEGER NOT NULL,
    PRIMARY KEY (session_id, operation_id),
    UNIQUE (session_id, client_submission_id),
    UNIQUE (session_id, operation_id, client_submission_id, message_request_digest),
    CHECK (
      (actor_kind = 'local_owner' AND actor_id IS NULL AND actor_generation = zeroblob(8)) OR
      (actor_kind = 'remote_device' AND typeof(actor_id) = 'blob' AND length(actor_id) = 16 AND actor_id <> zeroblob(16) AND actor_generation <> zeroblob(8))
    ),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE message_submission_receipts (
    session_id             TEXT NOT NULL,
    client_submission_id   BLOB NOT NULL CHECK (typeof(client_submission_id) = 'blob' AND length(client_submission_id) = 16 AND client_submission_id <> zeroblob(16)),
    operation_id           BLOB NOT NULL CHECK (typeof(operation_id) = 'blob' AND length(operation_id) = 16 AND operation_id <> zeroblob(16)),
    message_request_digest BLOB NOT NULL CHECK (typeof(message_request_digest) = 'blob' AND length(message_request_digest) = 32),
    attachment_set_digest  BLOB NOT NULL CHECK (typeof(attachment_set_digest) = 'blob' AND length(attachment_set_digest) = 32),
    state                  TEXT NOT NULL CHECK (state IN ('accepted', 'materialized', 'terminal_rejected', 'removed')),
    queue_item_id          BLOB NOT NULL CHECK (typeof(queue_item_id) = 'blob' AND length(queue_item_id) = 16 AND queue_item_id <> zeroblob(16)),
    message_seq            INTEGER CHECK (message_seq IS NULL OR message_seq > 0),
    fold_ordinal           INTEGER CHECK (fold_ordinal IS NULL OR fold_ordinal >= 0),
    safe_outcome           BLOB NOT NULL CHECK (typeof(safe_outcome) = 'blob'),
    created_at             INTEGER NOT NULL,
    updated_at             INTEGER NOT NULL,
    PRIMARY KEY (session_id, client_submission_id),
    UNIQUE (session_id, operation_id),
    UNIQUE (session_id, operation_id, client_submission_id, message_request_digest),
    CHECK ((state = 'materialized') = (message_seq IS NOT NULL AND fold_ordinal IS NOT NULL)),
    FOREIGN KEY (session_id, operation_id)
      REFERENCES message_operation_receipts(session_id, operation_id) ON DELETE CASCADE,
    FOREIGN KEY (session_id, operation_id, client_submission_id, message_request_digest)
      REFERENCES message_operation_receipts(session_id, operation_id, client_submission_id, message_request_digest)
      ON DELETE CASCADE
);

CREATE TABLE message_queue_items (
    session_id           TEXT NOT NULL,
    queue_item_id        BLOB NOT NULL CHECK (typeof(queue_item_id) = 'blob' AND length(queue_item_id) = 16 AND queue_item_id <> zeroblob(16)),
    client_submission_id BLOB NOT NULL CHECK (typeof(client_submission_id) = 'blob' AND length(client_submission_id) = 16 AND client_submission_id <> zeroblob(16)),
    canonical_message    BLOB NOT NULL CHECK (typeof(canonical_message) = 'blob' AND length(canonical_message) <= 2631500),
    state                TEXT NOT NULL CHECK (state IN ('accepted', 'folding', 'materialized', 'terminal_rejected', 'removed')),
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL,
    PRIMARY KEY (session_id, queue_item_id),
    UNIQUE (session_id, client_submission_id),
    FOREIGN KEY (session_id, client_submission_id)
      REFERENCES message_submission_receipts(session_id, client_submission_id) ON DELETE CASCADE
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
      REFERENCES message_submission_receipts(session_id, client_submission_id) ON DELETE CASCADE
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
       WHEN 'prepared' THEN NEW.state NOT IN ('prepared','artifact_synced')
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
