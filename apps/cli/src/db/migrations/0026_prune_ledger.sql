-- 0026_prune_ledger.sql — session resume prune-ledger
-- (implementation note).
--
-- Resuming a session must be a TRUE CONTINUATION: after `/prune`, `/exit`,
-- a daemon stop+restart, and `/resume`, the prior conversation is rebuilt
-- from the durable transcript (`session_events` + `tool_call_events`) and
-- re-pruned to the form the model last saw. `session_events` stays the
-- single source of truth for the *content*; this table is the small
-- durable delta that reproduces the *pruned* form — the on-disk twin of
-- the in-memory prune state `src/engine/prune.rs` keeps
-- (`current_elided_ids` + the driver's `prune_watermark`).
--
-- Persisted at EVERY inference boundary (after each turn) and on every
-- `/prune`, so continuity survives an unclean daemon kill, not just a
-- graceful `/exit`. One row per session (upsert); `ledger_json` is the
-- JSON-serialized `prune::PruneLedger` (the elided-id set with each
-- elision's `original_event_id` + canonical `reason`, plus the watermark).
-- Empty/absent ledger = nothing pruned (rebuild returns the full form).

CREATE TABLE prune_ledger (
    session_id  TEXT PRIMARY KEY
        REFERENCES sessions (session_id) ON DELETE CASCADE,
    ledger_json TEXT NOT NULL,
    updated_at  INTEGER NOT NULL
);
