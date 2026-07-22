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

-- Exact identity for the amended pre-release squash. Unlike the
-- `schema_version` migration ledger, this changes whenever 0001 is amended so
-- an older development database cannot silently masquerade as current.
PRAGMA user_version = 6;

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
    active_agent    TEXT    NOT NULL DEFAULT 'orchestrator-build',
    assistant_name  TEXT,

    -- fork tree + auto-titling (GOALS §17). Parent/fork integrity and the
    -- fork-subtree deletion cascade are enforced at the application layer
    -- (src/db/sessions.rs), not by an FK.
    parent_session_id  TEXT,                     -- NULL = root
    fork_point_turn_id TEXT,                     -- turn in parent where fork branched; NULL = root
    title              TEXT,                     -- utility-model-generated label (§17d)
    user_renamed       INTEGER NOT NULL DEFAULT 0, -- 1 = user set title; locks out auto-titling
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
    ephemeral INTEGER NOT NULL DEFAULT 0,

    -- Persistent `/btw` side-conversation linkage. A BTW row is also a
    -- fork-tree child via parent_session_id, but this typed linkage is the
    -- authoritative lifecycle marker and uniqueness key.
    btw_parent_session_id TEXT,
    btw_tangent INTEGER NOT NULL DEFAULT 0,

    -- persisted auto-title progress (GOALS §17d): running cl100k_base
    -- estimate of RAW typed user content, and the last consumed scheduled
    -- title slot (0, 1, 2, 4, 8, or 16) so a resumed session never repeats
    -- the same automatic title opportunity.
    user_content_tokens INTEGER NOT NULL DEFAULT 0,
    title_stage         INTEGER NOT NULL DEFAULT 0,

    -- remote principal attribution + collaborator sharing.
    created_by_principal TEXT,
    shared_with_collaborators INTEGER NOT NULL DEFAULT 0,

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
    hard_fail           INTEGER NOT NULL DEFAULT 0,

    -- structured bash/sandbox outcome fields for escalation lookup. NULL
    -- exit_code means no shell exit was produced (spawn/cancel/signaled).
    exit_code           INTEGER DEFAULT NULL,
    sandbox_enabled     INTEGER NOT NULL DEFAULT 0,
    sandboxed           INTEGER NOT NULL DEFAULT 0,
    sandbox_unavailable_reason TEXT DEFAULT NULL,

    -- audit: the two projections live on the same row (GOALS §14a)
    original_input_json TEXT    NOT NULL,
    wire_input_json     TEXT    NOT NULL,

    output              TEXT    NOT NULL DEFAULT '',
    truncated           INTEGER NOT NULL DEFAULT 0,
    duration_ms         INTEGER,

    -- tool-call mining across versions: CARGO_PKG_VERSION at call time,
    -- and the LLM steering mode (defensive/normal) at call time.
    cockpit_version     TEXT    DEFAULT NULL,
    llm_mode            TEXT    DEFAULT '',

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
    is_utility INTEGER NOT NULL DEFAULT 0,

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
    state          TEXT    NOT NULL DEFAULT 'open',
    question_json  TEXT,                            -- serialized proto::InterruptQuestion or NULL
    raised_at      INTEGER NOT NULL,
    resolved_at    INTEGER,
    response_json  TEXT,                            -- serialized proto::ResolveResponse, NULL if unresolved
    questions_json TEXT,                            -- serialized proto::InterruptQuestionSet or NULL
    parked_tool    TEXT,                            -- wire tool name for parked replay, or NULL
    parked_args_json TEXT,                          -- verbatim replay wire args; same exposure boundary as session_events.wire_input_json
    parked_call_id TEXT,                            -- assistant tool-call id for parked replay, or NULL
    parked_resume_json TEXT,                        -- serialized resume anchor, or NULL
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
    kind        TEXT    NOT NULL,   -- 'model' | 'slash' | 'tag'
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
    source_type   TEXT NOT NULL,
    source_url    TEXT,
    source_branch TEXT,
    path          TEXT NOT NULL,
    shallow       INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    -- kcl package preparation scope imported from the portable
    -- `kcl packages export` manifest.
    prepare_scope TEXT NOT NULL DEFAULT 'global'
);

CREATE INDEX packages_source_url ON packages(source_url);

-- ---- seed_tools (`/compact`, plan.md T6.e) ----------------------------------------
-- When `/compact` creates a fresh session, the seed-tool plan (read-only /
-- idempotent tool calls that reconstruct the working set) is persisted
-- here keyed by the *new* session id. The new session's worker drains
-- this on its first turn and RE-EXECUTES each tool (never replays the old
-- output), then deletes the rows. JSON-encoded `(tool, args)` per row;
-- `seq` preserves derivation order.

CREATE TABLE seed_tools (
    session_id TEXT NOT NULL
        REFERENCES sessions (session_id) ON DELETE CASCADE,
    seq        INTEGER NOT NULL,
    tool       TEXT NOT NULL,
    args_json  TEXT NOT NULL,
    PRIMARY KEY (session_id, seq)
);

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
    status       TEXT    NOT NULL DEFAULT 'completed',
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_ireq_session ON inference_requests (session_id);

CREATE TABLE session_events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT, -- globally monotonic order
    session_id  TEXT    NOT NULL,
    ts_ms       INTEGER NOT NULL,                  -- epoch milliseconds
    type        TEXT    NOT NULL,                  -- TurnEvent-aligned discriminant
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
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_sevents_session_seq ON session_events (session_id, seq);
CREATE INDEX idx_sevents_call        ON session_events (call_id);
CREATE INDEX idx_sevents_task_child  ON session_events (session_id, task_call_id, label, seq)
  WHERE task_call_id IS NOT NULL;
CREATE INDEX idx_sevents_origin_principal ON session_events (origin_principal)
  WHERE origin_principal IS NOT NULL;

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
-- `grant_kind` is 'command' (keyed by argv[0]+subcommand, e.g. `gh pr`)
-- or 'path' or 'mcp_tool' (keyed by external MCP server/tool). Wrapper/eval
-- commands are NEVER persisted here — the store layer rejects them before
-- insert. `risk_tier` records the command tier
-- displayed when an allow grant was issued, so future invocations of the
-- same coarse command key only skip the prompt when their recomputed tier
-- is no higher. Path grants, MCP-tool grants, and rejects carry no tier.
-- `verdict` carries the polarity; the (session_id, grant_kind, grant_key)
-- PK means allow and reject for the same key can never coexist — the
-- recorder flips the verdict in place via INSERT OR REPLACE.

CREATE TABLE approval_grants (
    session_id  TEXT    NOT NULL,
    grant_kind  TEXT    NOT NULL CHECK (grant_kind IN ('command', 'path', 'mcp_tool')),
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
-- `assistant_message` events. Tool outputs, tool-call args, and raw
-- inference payloads are deliberately NOT indexed — they're noise for
-- recall and a token/privacy hazard.
--
-- Layout choice: a contentless FTS5 table (`content=''`) with one indexed
-- text column, because the searchable text is spread across two base
-- tables (sessions.title + session_events.data_json) and lives inside a
-- JSON blob in the events case — there is no single column FTS5 could
-- shadow. The `session_fts_docs` side table maps FTS rowids back to a
-- thread (`session_id`) and, for message rows, an in-thread location
-- (`seq`); it stores identifiers only, never a second copy of text.
--
--   row_kind   — 'title' | 'message', so `session_read` windows correctly.
--   seq        — session_events.seq for a message row; NULL for a title.

CREATE VIRTUAL TABLE session_fts USING fts5(
    body,
    content=''
);

CREATE TABLE session_fts_docs (
    rowid      INTEGER PRIMARY KEY,
    row_kind   TEXT NOT NULL CHECK (row_kind IN ('title', 'message')),
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    seq        INTEGER REFERENCES session_events(seq) ON DELETE CASCADE,
    UNIQUE(row_kind, session_id, seq)
);

CREATE UNIQUE INDEX session_fts_docs_one_title
    ON session_fts_docs(session_id)
    WHERE row_kind = 'title';

CREATE INDEX session_fts_docs_session_idx
    ON session_fts_docs(session_id);

-- Message-event sync: only `user_message` / `assistant_message` rows carry
-- conversational text; every other event type is skipped at the trigger so
-- the index stays clean. The text lives at data_json.'$.text'. Because the
-- FTS table is contentless, UPDATE/DELETE use FTS5's special delete
-- command with the old canonical text, then reconcile the identifier-only
-- rowid mapping.

CREATE TRIGGER session_fts_events_ai AFTER INSERT ON session_events
WHEN new.type IN ('user_message', 'assistant_message')
     AND json_extract(new.data_json, '$.text') IS NOT NULL
BEGIN
    INSERT INTO session_fts_docs (row_kind, session_id, seq)
    VALUES ('message', new.session_id, new.seq);
    INSERT INTO session_fts (rowid, body)
    VALUES (last_insert_rowid(), json_extract(new.data_json, '$.text'));
END;

CREATE TRIGGER session_fts_events_ad AFTER DELETE ON session_events
WHEN old.type IN ('user_message', 'assistant_message')
BEGIN
    INSERT INTO session_fts (session_fts, rowid, body)
    SELECT 'delete', rowid, json_extract(old.data_json, '$.text')
    FROM session_fts_docs
    WHERE row_kind = 'message' AND seq = old.seq;
    DELETE FROM session_fts_docs
    WHERE row_kind = 'message' AND seq = old.seq;
END;

CREATE TRIGGER session_fts_events_au AFTER UPDATE ON session_events
WHEN old.type IN ('user_message', 'assistant_message')
     OR new.type IN ('user_message', 'assistant_message')
BEGIN
    INSERT INTO session_fts (session_fts, rowid, body)
    SELECT 'delete', rowid, json_extract(old.data_json, '$.text')
    FROM session_fts_docs
    WHERE row_kind = 'message' AND seq = old.seq;
    DELETE FROM session_fts_docs
    WHERE row_kind = 'message' AND seq = old.seq;
    INSERT INTO session_fts_docs (row_kind, session_id, seq)
    SELECT 'message', new.session_id, new.seq
    WHERE new.type IN ('user_message', 'assistant_message')
      AND json_extract(new.data_json, '$.text') IS NOT NULL;
    INSERT INTO session_fts (rowid, body)
    SELECT last_insert_rowid(), json_extract(new.data_json, '$.text')
    WHERE new.type IN ('user_message', 'assistant_message')
      AND json_extract(new.data_json, '$.text') IS NOT NULL;
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
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY (seq)        REFERENCES session_events(seq)  ON DELETE CASCADE
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
    status        TEXT    NOT NULL DEFAULT 'pending',
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
    status TEXT NOT NULL,
    token_budget INTEGER,
    tokens_used INTEGER NOT NULL DEFAULT 0,
    blocked_attempts INTEGER NOT NULL DEFAULT 0,
    last_read_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- At most one goal in a non-terminal status per session.
CREATE UNIQUE INDEX idx_session_goals_one_open
    ON session_goals(session_id)
    WHERE status IN ('draft', 'active', 'paused', 'blocked', 'budget_limited', 'usage_limited');

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
    updated_at INTEGER NOT NULL
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
    enabled           INTEGER NOT NULL DEFAULT 0,
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
    enabled              INTEGER NOT NULL DEFAULT 1,
    status               TEXT    NOT NULL DEFAULT 'off',
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
    verdict      TEXT    NOT NULL,
    path         TEXT,                              -- path attribution for project-file audit rows
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE SET NULL
);

CREATE INDEX idx_remote_principal_audit_ts        ON remote_principal_audit (ts_ms);
CREATE INDEX idx_remote_principal_audit_principal ON remote_principal_audit (principal, ts_ms);
CREATE INDEX idx_remote_principal_audit_path      ON remote_principal_audit (path);

-- ---- session_plan_docs -------------------------------------------------------------------------------------
-- The session's living plan document (plan mode), one row per session.

CREATE TABLE session_plan_docs (
    session_id TEXT PRIMARY KEY REFERENCES sessions(session_id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);
