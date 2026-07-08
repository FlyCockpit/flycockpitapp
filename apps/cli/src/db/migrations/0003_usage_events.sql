-- Frequency tally for autocomplete tie-breaking (models, slash
-- commands, @ tags). One row per accepted pick; a rolling 30-day
-- window is applied at aggregation time, and rows older than the
-- window are pruned on daemon startup.
CREATE TABLE usage_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT    NOT NULL,   -- 'model' | 'slash' | 'tag'
    key         TEXT    NOT NULL,   -- 'provider/model' | command name | relative tag path
    project_id  TEXT,               -- NULL for model+slash (global); set for tag
    ts          INTEGER NOT NULL    -- unix seconds
);
CREATE INDEX idx_usage_kind_ts      ON usage_events (kind, ts);
CREATE INDEX idx_usage_kind_proj_ts ON usage_events (kind, project_id, ts);
