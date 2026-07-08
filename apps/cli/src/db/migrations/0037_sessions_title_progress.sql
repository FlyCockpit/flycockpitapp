-- 0037_sessions_title_progress.sql — persisted auto-title progress.
--
-- Auto-titling (GOALS §17d) originally ran as an eager pass plus a
-- token-threshold refine pass. The same persisted columns now support the
-- bounded turn-slot schedule: title after user turn 1, refresh after turns
-- 2, 4, 8, and 16. The running token estimate remains useful for stats and
-- compatibility; title_stage stores the last consumed scheduled slot so a
-- resumed session never repeats the same automatic title opportunity.
--
-- Adds:
--   user_content_tokens — running cl100k_base estimate of RAW typed user
--                         content (pre-skill-injection). Defaults 0.
--   title_stage         — auto-title progress: last consumed scheduled slot
--                         (0, 1, 2, 4, 8, or 16). Defaults 0.
--
-- Both default 0 so every existing row resumes as "no title work done yet";
-- the trigger re-evaluates on the next user message.

ALTER TABLE sessions ADD COLUMN user_content_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN title_stage         INTEGER NOT NULL DEFAULT 0;
