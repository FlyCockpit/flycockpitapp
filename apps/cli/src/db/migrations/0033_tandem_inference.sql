-- 0033_tandem_inference.sql — model-comparison tandem (shadow) inference
-- (implementation note).
--
-- Session-only "model comparison" mode shadows every SUBSTANTIVE inference
-- request to one or more user-selected tandem `(provider, model)` pairs on
-- other providers. Each tandem call is a pure observer — it never feeds back
-- into the agentic loop — and its captured outcome is persisted here so a
-- later `/export debug` ships it alongside the main model's request, letting
-- `analyze-session-logs` compare strong-vs-weak behavior on identical inputs.
--
-- Unlike `inference_requests` (which stores ONLY the request body), a tandem
-- record additionally stores the FULL raw completion (`response_json`) and
-- token usage (`usage_json`), because the whole point is the comparison
-- against what the tandem model actually emitted on the same input.
--
--   * parent_call_id — the MAIN inference call this tandem shadows
--     (== inference_requests.call_id / inference_calls.call_id), so the
--     export lines the tandem response up against the main call.
--   * parent_seq / agent — the same timeline context as the shadowed call
--     so it slots into the seq-ordered export timeline under the right agent.
--   * status — lifecycle: completed | errored | timed_out | cancelled |
--     pending. An in-flight tandem request unsettled at export time reads
--     back `pending` (the export does not block waiting for it).
--   * request_json — the EXACT post-redaction/post-repair body the tandem
--     model was sent (identical assembly to the main call: same system /
--     history / prompt / tools / params).
--
-- Multiple tandem models can shadow the same parent call, so the primary key
-- is a per-row id, not `parent_call_id`. The request body is already
-- post-redaction (reused from the main call's assembled body), so no second
-- redaction pass is applied on read-back.

CREATE TABLE tandem_inference (
    id            TEXT    PRIMARY KEY,              -- per (parent call, tandem model)
    session_id    TEXT    NOT NULL,
    parent_call_id TEXT   NOT NULL,                 -- == the main call this shadows
    parent_seq    INTEGER,                          -- main call's timeline seq, when known
    agent         TEXT,                             -- agent that ran the shadowed turn
    provider      TEXT    NOT NULL,                 -- tandem provider id
    model         TEXT    NOT NULL,                 -- tandem model id
    ts_ms         INTEGER NOT NULL,                 -- epoch milliseconds (dispatch)
    request_json  TEXT    NOT NULL,                 -- full post-redaction request body
    response_json TEXT,                             -- full raw completion (text + tool calls)
    usage_json    TEXT,                             -- provider-reported token usage
    status        TEXT    NOT NULL DEFAULT 'pending',
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_tandem_session ON tandem_inference (session_id);
CREATE INDEX idx_tandem_parent  ON tandem_inference (parent_call_id);
