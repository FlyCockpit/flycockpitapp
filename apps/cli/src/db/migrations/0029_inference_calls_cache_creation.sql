-- Cache-creation input tokens (prompt `prompt-caching-strategy.md`): the
-- portion of an inference call's input that was *written into* the prompt
-- cache on a miss (Anthropic `cache_creation`), as distinct from
-- `cached_input_tokens` (the portion served from cache on a hit). Recorded
-- per call so the pruning policy's cache-hit expectation (GOALS §10) is
-- validatable against measured reality.
--
-- Defaults to 0; pre-migration calls therefore record no cache-write cost
-- (no backfill).
ALTER TABLE inference_calls ADD COLUMN cache_creation_input_tokens INTEGER NOT NULL DEFAULT 0;
