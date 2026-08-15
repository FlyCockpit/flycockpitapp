-- Remaining-store unification: per-store authority + import sagas.
-- Makes sealed_values.value nullable so literals can leave the column.
-- Do not edit 0001–0003. Append-only.

CREATE TABLE secret_vault_store_state (
    store           TEXT    PRIMARY KEY CHECK (store IN (
        'credentials',
        'sealed_compartment',
        'session_sealed_value',
        'redaction_table'
    )),
    authoritative   TEXT    NOT NULL CHECK (authoritative IN ('legacy', 'vault')),
    updated_at      INTEGER NOT NULL
);

CREATE TABLE secret_vault_import_sagas (
    op_id       TEXT    PRIMARY KEY,
    store       TEXT    NOT NULL CHECK (store IN (
        'credentials',
        'sealed_compartment',
        'session_sealed_value',
        'redaction_table'
    )),
    phase       TEXT    NOT NULL CHECK (phase IN (
        'prepared',
        'activated',
        'source_deleted',
        'complete'
    )),
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

-- Rebuild sealed_values so `value` may be NULL after vault import.
-- Session deletion still cascades via the sessions FK.
CREATE TABLE sealed_values_new (
    session_id TEXT NOT NULL,
    value_id   TEXT NOT NULL,
    value      TEXT,
    reason     TEXT NOT NULL,
    origin     TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (session_id, value_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

INSERT INTO sealed_values_new (session_id, value_id, value, reason, origin, created_at)
SELECT session_id, value_id, value, reason, origin, created_at FROM sealed_values;

DROP TABLE sealed_values;
ALTER TABLE sealed_values_new RENAME TO sealed_values;

CREATE INDEX idx_sealed_values_session_created
    ON sealed_values(session_id, created_at ASC, value_id ASC);
