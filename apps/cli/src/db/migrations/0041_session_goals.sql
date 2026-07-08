-- 0041_session_goals.sql — persisted session goals (`/goal`).

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

CREATE UNIQUE INDEX idx_session_goals_one_open
    ON session_goals(session_id)
    WHERE status IN ('draft', 'active', 'paused', 'blocked', 'budget_limited', 'usage_limited');

CREATE INDEX idx_session_goals_session_status
    ON session_goals(session_id, status, updated_at DESC);
