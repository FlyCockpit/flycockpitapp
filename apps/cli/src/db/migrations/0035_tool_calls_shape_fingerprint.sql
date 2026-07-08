-- 0035_tool_calls_shape_fingerprint.sql — add the §12 repair shape
-- fingerprint to tool_call_events (implementation note).
--
-- shape_fingerprint TEXT DEFAULT NULL — a short stable hash of the malformed
-- input shape (tool :: sorted[ instance_path | error_code | expected |
-- received ]). Structurally-identical bad calls (differing only in concrete
-- values) share a fingerprint, so `cockpit debug failed-calls` can group and
-- count failures by model + fingerprint. NULL for clean calls and for
-- historical rows (pre-0035). The `model` column (since 0001) carries the
-- model dimension this groups against.

ALTER TABLE tool_call_events ADD COLUMN shape_fingerprint TEXT DEFAULT NULL;
