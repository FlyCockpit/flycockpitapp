-- 0036_approval_grant_verdict.sql — Add a reject polarity to session-scope
-- command/path approval grants (implementation note).
--
-- Until now `approval_grants` was allow-only: a present row meant "granted"
-- (sandboxing part 1, §2, migration 0011). The approval dialog is now
-- symmetric — the user can persist a *reject* at the same four scopes — so a
-- session-scope grant row must carry its polarity.
--
-- `verdict` is 'allow' (the original meaning) or 'reject'. Existing rows
-- predate the column; the `DEFAULT 'allow'` backfills them so pre-migration
-- grants keep reading as allows (backward compatible). The (session_id,
-- grant_kind, grant_key) primary key is unchanged: a key holds at most one
-- row, so allow and reject for the same key can never coexist at session
-- scope — the recorder flips the verdict in place via `INSERT OR REPLACE`,
-- mirroring the mutual-exclusivity the design guarantees.

ALTER TABLE approval_grants
    ADD COLUMN verdict TEXT NOT NULL DEFAULT 'allow'
        CHECK (verdict IN ('allow', 'reject'));
