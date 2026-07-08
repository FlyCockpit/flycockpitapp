-- 0013_session_search_fts.sql — cross-session full-text recall
-- (`session_search` / `session_read`, prompt `search-old-sessions.md`).
--
-- A single FTS5 virtual table indexes the *searchable* surface of every
-- session: the session TITLE plus the text of `user_message` /
-- `assistant_message` events. Tool outputs, tool-call args, and raw
-- inference payloads are deliberately NOT indexed — they're noise for
-- recall and a token/privacy hazard.
--
-- Layout choice: a contentless FTS5 table (`content=''`) with one indexed
-- text column. We do NOT use the `content=<table>` external-content mode
-- because the searchable text is spread across two base tables
-- (sessions.title + session_events.data_json) and lives inside a JSON blob
-- in the events case — there is no single column FTS5 could shadow. A small
-- side table maps FTS rowids back to a thread (`session_id`) and, for
-- message rows, an in-thread location (`seq`); it stores identifiers only,
-- never a second copy of searchable text.
--
--   row_kind   — 'title' | 'message'. Distinguishes a title hit from a
--                message hit so `session_read` can window correctly.
--   session_id — the owning session (UUID text). Always present.
--   seq        — session_events.seq for a message row; NULL for a title.
--   body       — the indexed text (title text, or the message's
--                data_json `text` field).
--
-- Sync is trigger-driven (see below) AND backfilled here for all
-- pre-existing rows, so old sessions are searchable immediately after
-- migration — not just events created afterward.

CREATE VIRTUAL TABLE session_fts USING fts5(
    body,
    content=''
);

CREATE TABLE session_fts_docs (
    rowid      INTEGER PRIMARY KEY,
    row_kind   TEXT NOT NULL CHECK (row_kind IN ('title', 'message')),
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    seq        INTEGER REFERENCES session_events(seq) ON DELETE CASCADE,
    UNIQUE(row_kind, session_id, seq)
);

CREATE UNIQUE INDEX session_fts_docs_one_title
    ON session_fts_docs(session_id)
    WHERE row_kind = 'title';

CREATE INDEX session_fts_docs_session_idx
    ON session_fts_docs(session_id);

-- ---- message-event sync -----------------------------------------------------
-- Only `user_message` / `assistant_message` rows carry conversational
-- text; every other event type is skipped at the trigger so the index
-- stays clean. The text lives at data_json.'$.text'. Because the FTS table
-- is contentless, UPDATE/DELETE use FTS5's special delete command with the
-- old canonical text, then reconcile the identifier-only rowid mapping.

CREATE TRIGGER session_fts_events_ai AFTER INSERT ON session_events
WHEN new.type IN ('user_message', 'assistant_message')
     AND json_extract(new.data_json, '$.text') IS NOT NULL
BEGIN
    INSERT INTO session_fts_docs (row_kind, session_id, seq)
    VALUES ('message', new.session_id, new.seq);
    INSERT INTO session_fts (rowid, body)
    VALUES (last_insert_rowid(), json_extract(new.data_json, '$.text'));
END;

CREATE TRIGGER session_fts_events_ad AFTER DELETE ON session_events
WHEN old.type IN ('user_message', 'assistant_message')
BEGIN
    INSERT INTO session_fts (session_fts, rowid, body)
    SELECT 'delete', rowid, json_extract(old.data_json, '$.text')
    FROM session_fts_docs
    WHERE row_kind = 'message' AND seq = old.seq;
    DELETE FROM session_fts_docs
    WHERE row_kind = 'message' AND seq = old.seq;
END;

CREATE TRIGGER session_fts_events_au AFTER UPDATE ON session_events
WHEN old.type IN ('user_message', 'assistant_message')
     OR new.type IN ('user_message', 'assistant_message')
BEGIN
    INSERT INTO session_fts (session_fts, rowid, body)
    SELECT 'delete', rowid, json_extract(old.data_json, '$.text')
    FROM session_fts_docs
    WHERE row_kind = 'message' AND seq = old.seq;
    DELETE FROM session_fts_docs
    WHERE row_kind = 'message' AND seq = old.seq;
    INSERT INTO session_fts_docs (row_kind, session_id, seq)
    SELECT 'message', new.session_id, new.seq
    WHERE new.type IN ('user_message', 'assistant_message')
      AND json_extract(new.data_json, '$.text') IS NOT NULL;
    INSERT INTO session_fts (rowid, body)
    SELECT last_insert_rowid(), json_extract(new.data_json, '$.text')
    WHERE new.type IN ('user_message', 'assistant_message')
      AND json_extract(new.data_json, '$.text') IS NOT NULL;
END;

-- ---- title sync -------------------------------------------------------------
-- A session's title is searchable too. Titles change via UPDATE (set /
-- auto-title / rename) and arrive NULL on insert, so we cover insert +
-- update and reconcile the single title row per session.

CREATE TRIGGER session_fts_title_ai AFTER INSERT ON sessions
WHEN new.title IS NOT NULL AND new.title <> ''
BEGIN
    INSERT INTO session_fts_docs (row_kind, session_id, seq)
    VALUES ('title', new.session_id, NULL);
    INSERT INTO session_fts (rowid, body)
    VALUES (last_insert_rowid(), new.title);
END;

CREATE TRIGGER session_fts_title_au AFTER UPDATE OF title ON sessions
BEGIN
    INSERT INTO session_fts (session_fts, rowid, body)
    SELECT 'delete', rowid, old.title
    FROM session_fts_docs
    WHERE row_kind = 'title' AND session_id = old.session_id;
    DELETE FROM session_fts_docs
    WHERE row_kind = 'title' AND session_id = old.session_id;
    INSERT INTO session_fts_docs (row_kind, session_id, seq)
    SELECT 'title', new.session_id, NULL
    WHERE new.title IS NOT NULL AND new.title <> '';
    INSERT INTO session_fts (rowid, body)
    SELECT last_insert_rowid(), new.title
    WHERE new.title IS NOT NULL AND new.title <> '';
END;

CREATE TRIGGER session_fts_sessions_ad AFTER DELETE ON sessions
BEGIN
    INSERT INTO session_fts (session_fts, rowid, body)
    SELECT 'delete', d.rowid,
           CASE d.row_kind
             WHEN 'title' THEN old.title
             ELSE json_extract(e.data_json, '$.text')
           END
    FROM session_fts_docs AS d
    LEFT JOIN session_events AS e ON e.seq = d.seq
    WHERE d.session_id = old.session_id;
    DELETE FROM session_fts_docs WHERE session_id = old.session_id;
END;

-- ---- backfill ---------------------------------------------------------------
-- Index every pre-existing session's title + message events so old
-- threads are searchable the moment this migration lands.

INSERT INTO session_fts_docs (row_kind, session_id, seq)
SELECT 'message', session_id, seq
FROM session_events
WHERE type IN ('user_message', 'assistant_message')
  AND json_extract(data_json, '$.text') IS NOT NULL;

INSERT INTO session_fts (rowid, body)
SELECT d.rowid, json_extract(e.data_json, '$.text')
FROM session_fts_docs AS d
JOIN session_events AS e ON e.seq = d.seq
WHERE d.row_kind = 'message';

INSERT INTO session_fts_docs (row_kind, session_id, seq)
SELECT 'title', session_id, NULL
FROM sessions
WHERE title IS NOT NULL AND title <> '';

INSERT INTO session_fts (rowid, body)
SELECT d.rowid, s.title
FROM session_fts_docs AS d
JOIN sessions AS s ON s.session_id = d.session_id
WHERE d.row_kind = 'title';
