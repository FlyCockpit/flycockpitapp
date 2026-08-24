-- Physical local-v0.1 schema boundary. Foreign-key enforcement is disabled by
-- the migration runner while this profile is applied, then the retained graph
-- is checked before commit. Keep this list in lockstep with
-- schema-ownership.toml and the `remote` Cargo capability.
DROP TABLE remote_attachment_outbox_deliveries;
DROP TABLE remote_attachment_outbox_snapshots;
DROP TABLE remote_attachment_outbox;
DROP TABLE remote_rename_artifact_cleanup_intents;
DROP TABLE remote_rename_journal;
DROP TABLE remote_attachment_lifecycle;
DROP TABLE remote_attachment_operations;
DROP TABLE remote_audit_upload_state;
DROP TABLE remote_principal_audit;
DROP TABLE remote_daemon_custody_records;
DROP TABLE remote_daemon_custody_generation_seq;
DROP TABLE connector_state;
DROP TABLE sync_state;
