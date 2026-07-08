-- 0017_sessions_ephemeral.sql — ephemeral side-conversation flag (`/side`).
--
-- Adds:
--   ephemeral — 1 for a throwaway side-conversation fork (`/side`). An
--               ephemeral session is excluded from every session-list query,
--               never auto-titled, never surfaced as resumable, and is
--               discarded (row + cascade) when the side conversation ends or
--               its owning process exits. The daemon also sweeps any orphaned
--               ephemeral rows on boot (the SIGKILL backstop).
--
-- Defaults 0 so every existing row stays a normal, persisted session.

ALTER TABLE sessions ADD COLUMN ephemeral INTEGER NOT NULL DEFAULT 0;

CREATE INDEX idx_sessions_ephemeral ON sessions (ephemeral);
