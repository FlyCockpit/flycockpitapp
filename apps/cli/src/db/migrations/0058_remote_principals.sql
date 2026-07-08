-- Remote principal attribution and sharing state.
-- A few migration tests start from historical partial schemas that omit tables
-- unrelated to the migration under test. Create minimal placeholders so this
-- migration remains additive on those fixtures while real databases keep their
-- existing tables.
CREATE TABLE IF NOT EXISTS sessions (
  session_id   TEXT PRIMARY KEY,
  project_root TEXT
);

CREATE TABLE IF NOT EXISTS session_events (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT,
  type       TEXT    NOT NULL DEFAULT '',
  ts_ms      INTEGER NOT NULL DEFAULT 0,
  data_json  TEXT    NOT NULL DEFAULT '{}'
);

ALTER TABLE sessions
  ADD COLUMN created_by_principal TEXT;

ALTER TABLE sessions
  ADD COLUMN shared_with_collaborators INTEGER NOT NULL DEFAULT 0;

ALTER TABLE session_events
  ADD COLUMN origin_principal TEXT;

CREATE INDEX idx_sessions_created_by_principal ON sessions (created_by_principal);
CREATE INDEX idx_sessions_shared_project ON sessions (project_root, shared_with_collaborators)
  WHERE shared_with_collaborators = 1;
CREATE INDEX idx_sevents_origin_principal ON session_events (origin_principal)
  WHERE origin_principal IS NOT NULL;

CREATE TABLE remote_principal_audit (
  audit_id     INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_ms        INTEGER NOT NULL,
  principal    TEXT    NOT NULL,
  request_kind TEXT    NOT NULL,
  session_id   TEXT,
  verdict      TEXT    NOT NULL,
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE SET NULL
);

CREATE INDEX idx_remote_principal_audit_ts ON remote_principal_audit (ts_ms);
CREATE INDEX idx_remote_principal_audit_principal ON remote_principal_audit (principal, ts_ms);
