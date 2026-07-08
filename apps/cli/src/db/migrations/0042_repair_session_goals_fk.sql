-- 0042_repair_session_goals_fk.sql — repair session_goals FK from sessions(id).

-- Some dev/user DBs reached schema version 41 without the 0041 table being
-- present. Keep this repair migration tolerant: if the table is missing,
-- create an empty correctly-shaped source table so the copy below is a no-op.
CREATE TABLE IF NOT EXISTS session_goals (
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

CREATE TABLE session_goals_new (
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

INSERT INTO session_goals_new (
    id,
    session_id,
    project_id,
    objective,
    context,
    status,
    token_budget,
    tokens_used,
    blocked_attempts,
    last_read_at,
    created_at,
    updated_at
)
SELECT
    id,
    session_id,
    project_id,
    objective,
    context,
    status,
    token_budget,
    tokens_used,
    blocked_attempts,
    last_read_at,
    created_at,
    updated_at
FROM session_goals;

DROP TABLE session_goals;
ALTER TABLE session_goals_new RENAME TO session_goals;

CREATE UNIQUE INDEX idx_session_goals_one_open
    ON session_goals(session_id)
    WHERE status IN ('draft', 'active', 'paused', 'blocked', 'budget_limited', 'usage_limited');

CREATE INDEX idx_session_goals_session_status
    ON session_goals(session_id, status, updated_at DESC);
