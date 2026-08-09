-- Forward-only upgrade from the immutable historical v1 goal schema.
DROP INDEX idx_session_goals_one_open;
DROP INDEX idx_session_goals_session_status;

ALTER TABLE session_goals RENAME TO session_goals_v1;

CREATE TABLE session_goals (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
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

INSERT INTO session_goals (
    id, session_id, project_id, objective, context, disposition, phase,
    resume_phase, pause_reason, attempt_generation, resolved_policy_json,
    token_budget, tokens_used, blocked_attempts, completion_evidence,
    verification_rounds, last_read_at, created_at, updated_at
)
SELECT id, session_id, project_id, objective, context,
       CASE WHEN status = 'complete' THEN 'complete' ELSE 'user_paused' END,
       NULL,
       CASE WHEN status = 'complete' THEN NULL ELSE 'planning' END,
       CASE WHEN status = 'complete' THEN NULL ELSE 'restart' END,
       0,
       '{}',
       MAX(COALESCE(token_budget, 200000), 1),
       MAX(tokens_used, 0), blocked_attempts, completion_evidence,
       verification_rounds, last_read_at, created_at, updated_at
  FROM session_goals_v1;

DROP TABLE session_goals_v1;

CREATE UNIQUE INDEX idx_session_goals_one_open
    ON session_goals(session_id)
    WHERE disposition IN ('running', 'user_paused', 'infra_paused', 'blocked', 'no_progress_paused', 'budget_limited');
CREATE INDEX idx_session_goals_session_status
    ON session_goals(session_id, disposition, updated_at DESC);

CREATE TABLE goal_control_jobs (
    job_id TEXT PRIMARY KEY,
    goal_id TEXT NOT NULL REFERENCES session_goals(id) ON DELETE CASCADE,
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
    goal_id TEXT NOT NULL REFERENCES session_goals(id) ON DELETE CASCADE,
    attempt_generation INTEGER NOT NULL,
    turn_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'finished', 'cancelled')),
    audit_excerpt TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(goal_id, attempt_generation, turn_id)
);

-- Immutable attribution captured at inference dispatch.
ALTER TABLE inference_requests ADD COLUMN goal_id TEXT;
ALTER TABLE inference_requests ADD COLUMN goal_attempt_generation INTEGER;
CREATE INDEX idx_ireq_goal_provenance
    ON inference_requests (goal_id, goal_attempt_generation);
