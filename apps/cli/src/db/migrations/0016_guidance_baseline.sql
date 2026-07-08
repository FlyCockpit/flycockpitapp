-- 0016_guidance_baseline.sql — live instructions-file diff injection
-- (prompt `instructions-file-live-diff.md`).
--
-- Snapshots the resolved agent-guidance file body (the `AGENTS.md` /
-- `project guidance` baked into the cached system block) at session start, so a
-- mid-session in-place edit can be detected and injected as a trailing
-- diff without busting the cached system prefix.

-- Per-session baseline hash: the content hash of the guidance body that
-- went into this session's frozen system block. NULL when no guidance
-- file resolved at session start (feature is inert for that session). The
-- check-and-inject path advances this to the new hash each time it injects
-- a change, so a given edit is injected exactly once.
ALTER TABLE sessions ADD COLUMN guidance_baseline_hash TEXT;

-- Absolute path of the resolved guidance file the baseline came from.
-- Needed to detect the out-of-scope "file switched" case (e.g. `AGENTS.md`
-- deleted so `project guidance` now wins): on every outbound request we
-- re-resolve the guidance file and only treat a hash change as injectable
-- when the resolved path still equals this baseline path (an in-place
-- edit). NULL exactly when `guidance_baseline_hash` is NULL.
ALTER TABLE sessions ADD COLUMN guidance_baseline_path TEXT;

-- Content-addressed store of guidance bodies: hash → exact body. Holds the
-- start-of-session baseline plus every subsequent injected version, so a
-- diff can always be computed from the prior stored contents. Inserts are
-- idempotent (the hash PRIMARY KEY + INSERT OR IGNORE dedup identical
-- bodies — content-addressed storage is naturally idempotent).
CREATE TABLE guidance_contents (
    hash       TEXT PRIMARY KEY,
    contents   TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
