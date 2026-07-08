-- Project-scoped scratchpad notes (prompt `notes-scratchpad.md`).
--
-- A floating TUI dialog lets the user jot/organize markdown notes while
-- working. Notes are scoped to the **project root** (the git/worktree root,
-- or the launch cwd when not in a repo), NOT to a single session — the same
-- notes are visible across every session opened in that project. They live
-- in the same global cockpit DB as sessions; they are TUI/DB state only and
-- never enter any outbound model prompt (token economy, GOALS §10).
--
-- `project_root` is the absolute path of the project root, used as the
-- scoping key. `(project_root, name)` is unique so a name disambiguates a
-- note within its project; the TUI suffixes a duplicate name to keep it
-- non-empty + unique. `position` gives a stable sidebar ordering independent
-- of name/timestamps.
CREATE TABLE project_notes (
    id           TEXT PRIMARY KEY,
    project_root TEXT NOT NULL,
    name         TEXT NOT NULL,
    -- Markdown source. Empty string for a freshly-created, not-yet-edited
    -- note.
    content      TEXT NOT NULL DEFAULT '',
    position     INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    UNIQUE (project_root, name)
);

CREATE INDEX project_notes_root ON project_notes(project_root);
