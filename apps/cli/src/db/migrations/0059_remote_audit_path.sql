-- Path attribution for remote project-file audit rows.
ALTER TABLE remote_principal_audit
  ADD COLUMN path TEXT;

CREATE INDEX idx_remote_principal_audit_path ON remote_principal_audit (path);
