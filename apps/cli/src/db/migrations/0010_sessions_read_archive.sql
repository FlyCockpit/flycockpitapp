-- 0010_sessions_read_archive.sql — read/unread marker + archive state for
-- the fullscreen session browser (`/resume` / `/sessions`, GOALS §17f).
--
-- Adds:
--   last_viewed_at  — epoch seconds the user last opened/resumed this
--                     session in a client. NULL = never viewed (so any
--                     agent activity reads as unread). Set on Attach.
--                     A session is UNREAD when the latest agent-produced
--                     event (max timestamp across tool_call_events /
--                     inference_calls) is newer than this marker.
--   archived_at     — epoch seconds the session was archived (recoverable
--                     soft-delete). NULL = live. Archived sessions are
--                     hidden from the browser by default; a toggle reveals
--                     them, and unarchive clears this column. Archive
--                     cascades the fork subtree (app-side recursive walk in
--                     src/db/sessions.rs), mirroring delete_session's
--                     cascade semantics.
--
-- Both default NULL on existing rows: every prior session reads as
-- "viewed at the epoch" only via the explicit NULL check (never-viewed →
-- unread iff it has agent activity), and as not-archived.

ALTER TABLE sessions ADD COLUMN last_viewed_at INTEGER;
ALTER TABLE sessions ADD COLUMN archived_at    INTEGER;

CREATE INDEX idx_sessions_archived ON sessions (archived_at);
