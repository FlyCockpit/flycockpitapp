-- 0002_sessions_fork.sql — session fork tree + auto-titling columns (GOALS §17).
--
-- Adds:
--   parent_session_id    — FK-style pointer to sessions(session_id). NULL = root.
--   fork_point_turn_id   — turn id in the parent where this fork branched off. NULL = root.
--   title                — utility-model-generated label (§17d). NULL until generated.
--   user_renamed         — 1 if the user manually set the title. Locks out auto-titling.
--   short_id             — 6-char Crockford base32 display id, unique within project_id.
--
-- We don't recreate the table — SQLite can't add a FOREIGN KEY to an existing
-- column without a full rebuild, and parent/fork integrity is enforced at the
-- application layer (see src/db/sessions.rs). The deletion-cascade rule for
-- forks is also app-side, since the user may choose to keep orphan forks when
-- pruning a parent.
--
-- `short_id` is left NULL for pre-migration rows; runtime code (the lazy
-- backfill in src/db/sessions.rs) populates it on next touch. The UNIQUE
-- index is partial so the NULL rows don't trip it.

ALTER TABLE sessions ADD COLUMN parent_session_id  TEXT;
ALTER TABLE sessions ADD COLUMN fork_point_turn_id TEXT;
ALTER TABLE sessions ADD COLUMN title              TEXT;
ALTER TABLE sessions ADD COLUMN user_renamed       INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN short_id           TEXT;

CREATE INDEX idx_sessions_parent ON sessions (parent_session_id);
CREATE UNIQUE INDEX idx_sessions_short_id_project
    ON sessions (project_id, short_id)
    WHERE short_id IS NOT NULL;
