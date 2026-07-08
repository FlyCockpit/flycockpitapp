-- 0009_session_log.sql — session-log export capture (session-log-export).
--
-- Two always-on capture surfaces feeding `cockpit export <session>`:
--
--   * inference_requests — the FULL assembled outbound request body for
--     every inference call (model + provider + params + system + tools +
--     full history), captured at the engine→provider boundary AFTER
--     redaction (we store exactly what hit the wire — see the export
--     spec's leak-detection use case). Keyed by the SAME `call_id` the
--     `inference_calls` metadata row uses, so the two join. Payloads are
--     large, so they live here rather than inline on `inference_calls`.
--
--   * session_events — a per-session event timeline. `seq` is a globally
--     monotonic INTEGER (AUTOINCREMENT rowid) — the authoritative sort and
--     correlation key across the whole fork tree. `ts_ms` is millisecond
--     resolution (the epoch-SECONDS columns elsewhere are too coarse to
--     order events within one turn; those tables are left unchanged). The
--     `type` discriminant aligns with the engine `TurnEvent` vocabulary;
--     per-type fields ride in `data_json` so the schema stays stable as
--     the event set grows. `call_id` is surfaced as its own column for the
--     inference_request ↔ inference_requests / tool_call ↔ inference_calls
--     correlations the export depends on.
--
-- A retention / eviction policy for these payload-heavy tables is out of
-- scope here (noted as a future follow-up in the export spec).

CREATE TABLE inference_requests (
    call_id      TEXT    PRIMARY KEY,           -- == inference_calls.call_id
    session_id   TEXT    NOT NULL,
    ts_ms        INTEGER NOT NULL,              -- epoch milliseconds
    payload_json TEXT    NOT NULL,              -- full post-redaction request
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_ireq_session ON inference_requests (session_id);

CREATE TABLE session_events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT, -- globally monotonic order
    session_id  TEXT    NOT NULL,
    ts_ms       INTEGER NOT NULL,                  -- epoch milliseconds
    type        TEXT    NOT NULL,                  -- TurnEvent-aligned discriminant
    agent       TEXT,                              -- emitting agent, when known
    call_id     TEXT,                              -- correlation key, when applicable
    data_json   TEXT    NOT NULL DEFAULT '{}',     -- per-type payload
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_sevents_session_seq ON session_events (session_id, seq);
CREATE INDEX idx_sevents_call        ON session_events (call_id);
