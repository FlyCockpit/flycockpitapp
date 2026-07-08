-- Durable retrieval records for compressed/truncated non-file tool results.

CREATE TABLE compressed_tool_results (
    hash                  TEXT    NOT NULL,
    session_id            TEXT    NOT NULL,
    agent_id              TEXT    NOT NULL,
    tool                  TEXT    NOT NULL,
    call_id               TEXT    NOT NULL,
    original_byte_len     INTEGER NOT NULL,
    compressed_byte_len   INTEGER,
    created_at            INTEGER NOT NULL,
    kind                  TEXT    NOT NULL,
    content               TEXT    NOT NULL,
    PRIMARY KEY (session_id, hash),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_ctr_session_created ON compressed_tool_results (session_id, created_at);
CREATE INDEX idx_ctr_hash ON compressed_tool_results (hash);
