-- 0007_seed_tools.sql — `/compact` seed-tool handoff (plan.md T6.e).
--
-- When `/compact` creates a fresh session, the seed-tool plan (read-only
-- / idempotent tool calls that reconstruct the working set) is persisted
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
