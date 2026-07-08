-- 0039_tool_calls_hint.sql — add the post-result hint column to
-- tool_call_events (implementation note).
--
-- hint TEXT DEFAULT NULL — a JSON object `{ kind, text, severity }` set when
-- the `bash` post-result hint layer (`engine::bash_hints`) matched a rule on a
-- bash call. `kind` is the rule id, `text` is the one-line user chip, and
-- `severity` is "info" / "warn". NULL on clean calls, every non-`bash` tool,
-- and historical rows (pre-0039). The session-export `tool_call` event already
-- carries the same value under `data.hint`, so no export schema changes.

ALTER TABLE tool_call_events ADD COLUMN hint TEXT DEFAULT NULL;
