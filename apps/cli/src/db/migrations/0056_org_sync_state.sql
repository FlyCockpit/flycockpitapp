-- 0056_org_sync_state.sql - enterprise org-policy session log sync state.
--
-- One row per control-plane org/server pair. The cursor is the last
-- session_events.seq the daemon has fully considered for upload. Rows skipped
-- by org policy filters still advance the cursor so disabled event kinds do
-- not block future batches.

CREATE TABLE sync_state (
    server_url        TEXT    NOT NULL,
    org_id            TEXT    NOT NULL,
    cursor_seq        INTEGER NOT NULL DEFAULT 0,
    policy_version    TEXT,
    policy_json       TEXT,
    enabled           INTEGER NOT NULL DEFAULT 0,
    last_synced_at_ms INTEGER,
    last_error        TEXT,
    updated_at_ms     INTEGER NOT NULL,
    PRIMARY KEY (server_url, org_id)
);

CREATE INDEX idx_sync_state_server ON sync_state (server_url, enabled);
