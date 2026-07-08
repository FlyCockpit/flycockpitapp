-- 0032_tool_calls_version_and_mode.sql — add cockpit_version and llm_mode
-- columns to tool_call_events for tool-call mining across versions.
--
-- cockpit_version TEXT DEFAULT NULL — stores env!("CARGO_PKG_VERSION") at
-- call time. NULL for historical rows (pre-0032).
--
-- llm_mode TEXT DEFAULT '' — stores the LLM steering mode (defensive/normal)
-- at call time. Empty string for historical rows.

ALTER TABLE tool_call_events ADD COLUMN cockpit_version TEXT DEFAULT NULL;
ALTER TABLE tool_call_events ADD COLUMN llm_mode TEXT DEFAULT '';
