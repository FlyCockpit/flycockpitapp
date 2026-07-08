-- 0011_approval_grants.sql — Session-scope command/path approval grants
-- (command-approval & escalation subsystem, sandboxing part 1, §2).
--
-- The store records grants so a future access skips the approval prompt.
-- Session-scope grants live here, in the session DB, so they survive for
-- the session's lifetime and are dropped with the session (ON DELETE
-- CASCADE). Project- and Global-scope grants persist outside the DB, in
-- the layered `.cockpit/` config dirs, per cockpit's existing config
-- discovery — only Session belongs in SQLite.
--
-- `grant_kind` is 'command' (keyed by argv[0]+subcommand, e.g. `gh pr`)
-- or 'path' (an absolute path or path prefix, for part 2's native
-- confinement). `grant_key` is the stable storage string of either kind.
-- Wrapper/eval commands are NEVER persisted here — the store layer
-- rejects them before insert — so this table only ever holds keys that
-- are safe to remember.

CREATE TABLE approval_grants (
    session_id  TEXT    NOT NULL,
    grant_kind  TEXT    NOT NULL CHECK (grant_kind IN ('command', 'path')),
    grant_key   TEXT    NOT NULL,
    granted_at  INTEGER NOT NULL,
    PRIMARY KEY (session_id, grant_kind, grant_key),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_approval_grants_session ON approval_grants (session_id);
