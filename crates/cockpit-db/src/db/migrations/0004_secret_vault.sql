-- Wrap-key secret vault. Coordination + AEAD ciphertext + wrapped DEKs only.
-- KEK bytes and DEK plaintext never live in SQLite. First-run always persists
-- intent=database / active_placement=database; keyring is an explicit migrate.
--
-- This is intentionally append-only instead of being folded into 0001–0003:
-- deployed databases persist the SHA-256 of those immutable migrations.

-- Installation-scoped authority singleton. No secret bytes.
CREATE TABLE secret_vault_authority (
    id                    INTEGER PRIMARY KEY CHECK (id = 1),
    intent                TEXT    NOT NULL CHECK (intent IN ('database', 'keyring')),
    active_placement      TEXT    NOT NULL CHECK (active_placement IN ('database', 'keyring')),
    kek_fingerprint       TEXT    NOT NULL,
    kek_version           INTEGER NOT NULL CHECK (kek_version >= 1),
    wrap_version          INTEGER NOT NULL CHECK (wrap_version = 1),
    unification_complete  INTEGER NOT NULL CHECK (unification_complete IN (0, 1)),
    updated_at            INTEGER NOT NULL
);

-- Wrapped DEKs. No KEK bytes. No DEK plaintext.
CREATE TABLE secret_vault_keys (
    key_version   INTEGER PRIMARY KEY CHECK (key_version >= 1),
    kek_version   INTEGER NOT NULL CHECK (kek_version >= 1),
    wrap_version  INTEGER NOT NULL CHECK (wrap_version = 1),
    algorithm     TEXT    NOT NULL CHECK (algorithm = 'chacha20poly1305'),
    wrap_nonce    BLOB    NOT NULL CHECK (length(wrap_nonce) = 12),
    wrapped_dek   BLOB    NOT NULL CHECK (length(wrapped_dek) = 48),
    active        INTEGER NOT NULL CHECK (active IN (0, 1)),
    created_at    INTEGER NOT NULL
);
CREATE UNIQUE INDEX secret_vault_keys_wrap_nonce ON secret_vault_keys(wrap_nonce);
CREATE UNIQUE INDEX secret_vault_keys_one_active ON secret_vault_keys(active) WHERE active = 1;

-- AEAD items. AAD is rebuilt from columns + installation_identity; no stored AAD blob.
CREATE TABLE secret_vault_items (
    kind          TEXT    NOT NULL CHECK (kind IN (
        'secure_key_root',
        'secure_key_manifest',
        'sealed_state',
        'credential_record',
        'named_secret',
        'subscription_ack',
        'sealed_compartment',
        'session_sealed_value',
        'redaction_table'
    )),
    item_id       TEXT    NOT NULL,
    key_version   INTEGER NOT NULL REFERENCES secret_vault_keys(key_version),
    nonce         BLOB    NOT NULL CHECK (length(nonce) = 12),
    ciphertext    BLOB    NOT NULL CHECK (length(ciphertext) >= 16),
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    PRIMARY KEY (kind, item_id)
);
CREATE UNIQUE INDEX secret_vault_items_key_nonce ON secret_vault_items(key_version, nonce);

-- Durable KEK-placement migrate + later store import. Coordination only; no secret bytes.
CREATE TABLE secret_vault_sagas (
    op_id              TEXT    PRIMARY KEY,
    source_placement   TEXT    NOT NULL CHECK (source_placement IN ('database', 'keyring')),
    dest_placement     TEXT    NOT NULL CHECK (dest_placement IN ('database', 'keyring')),
    kek_fingerprint    TEXT    NOT NULL,
    phase              TEXT    NOT NULL CHECK (phase IN (
        'prepared',
        'activated',
        'source_deleted',
        'complete'
    )),
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL
);
