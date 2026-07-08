-- 0012_loop_guard_rules.sql — Session-scope loop-guard rules.
--
-- The loop guard fires an approval prompt when the model emits a tool
-- call whose signature (tool name + canonical `wire_input`) is identical
-- to the immediately-preceding tool call. The user can answer "always
-- accept/reject for this session", which records a rule here so a future
-- back-to-back repeat of that *exact* signature is auto-resolved without
-- re-prompting.
--
-- Unlike the command/path `approval_grants` table (which is allow-only —
-- a present row means "granted"), a loop-guard rule carries a *verdict*:
-- `accept` or `reject`. The verdict lives in `rule_verdict`. `signature`
-- is a stable hash of (tool name + canonical `wire_input` JSON) — see
-- `GrantStore::loop_signature`. Hashing keeps the key bounded regardless
-- of how large the tool input is, and the exact-match semantics the spec
-- requires hold because identical inputs hash identically.
--
-- Project- and Global-scope rules persist outside the DB, in the layered
-- `.cockpit/` `approvals.json` (the same file the command/path grants
-- use), so only Session belongs in SQLite. Dropped with the session
-- (ON DELETE CASCADE).

CREATE TABLE loop_guard_rules (
    session_id    TEXT    NOT NULL,
    signature     TEXT    NOT NULL,
    rule_verdict  TEXT    NOT NULL CHECK (rule_verdict IN ('accept', 'reject')),
    recorded_at   INTEGER NOT NULL,
    PRIMARY KEY (session_id, signature),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_loop_guard_rules_session ON loop_guard_rules (session_id);
