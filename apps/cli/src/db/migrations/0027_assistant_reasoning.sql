-- 0027_assistant_reasoning.sql — persist assistant-turn reasoning
-- separately from the body (inline-think-tag-handling).
--
-- Some openai-compatible models (MiniMax-M2 / DeepSeek-R1 / Qwen) emit
-- their reasoning as literal `<think>…</think>` tags inside the regular
-- content stream rather than the `reasoning_content` channel. The engine
-- now extracts that inline reasoning (and any channel reasoning), stores
-- the body with the tags stripped, and persists the reasoning on its own
-- field of the `assistant_message` event's `data_json` (`$.reasoning`).
-- This keeps reasoning out of the model's context while letting the
-- thinking chip survive resume and appear in exports.
--
-- Per the `session_events` design (0009), per-type fields ride in
-- `data_json` so the schema stays stable as the event set grows — the
-- reasoning lives there. This migration adds a VIRTUAL generated column
-- projecting `$.reasoning` out of `data_json`, so queries and exports can
-- read the reasoning column-wise without parsing JSON (the same idiom the
-- FTS triggers use against `$.text`). VIRTUAL (not STORED) because SQLite's
-- `ALTER TABLE … ADD COLUMN` only permits virtual generated columns; the
-- value is computed on read from the existing `data_json`, so it is purely
-- additive and needs no backfill — rows with no `$.reasoning` read NULL.

ALTER TABLE session_events
    ADD COLUMN reasoning TEXT
    GENERATED ALWAYS AS (json_extract(data_json, '$.reasoning')) VIRTUAL;
