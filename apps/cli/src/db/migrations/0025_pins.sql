-- 0025_pins.sql — pinned messages (pinned-messages).
--
-- A pin is a lightweight "come back to this later" reference the TUI lets
-- the user place on any conversation message (user or assistant) in a
-- session. Pins are TUI/DB state ONLY — they never enter the outbound
-- model prompt (token economy, priority #2).
--
-- A pin stores a REFERENCE to the message by its stable id, never a
-- snapshot of the text: `(session_id, seq)` where `seq` is the
-- `session_events.seq` PRIMARY KEY of the user/assistant message row.
-- `/prune` and `/compact` never mutate `session_events` (they touch only
-- the in-memory wire payload), so the original full message text in
-- `session_events.data_json` stays durable and a pin always renders its
-- original text — even after pruning/compaction.
--
-- The pin row CASCADE-deletes with both its session and its referenced
-- event, so a pin can never dangle. `(session_id, seq)` is UNIQUE so
-- pinning is idempotent: a message is either pinned or not.

CREATE TABLE pins (
    session_id  TEXT    NOT NULL,
    seq         INTEGER NOT NULL,             -- == session_events.seq
    pinned_ms   INTEGER NOT NULL,             -- epoch milliseconds (pin order)
    PRIMARY KEY (session_id, seq),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY (seq)        REFERENCES session_events(seq)  ON DELETE CASCADE
);

CREATE INDEX idx_pins_session ON pins (session_id, pinned_ms);
