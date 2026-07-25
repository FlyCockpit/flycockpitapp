//! Project-scoped scratchpad notes (prompt `notes-scratchpad.md`, migration
//! 0024).
//!
//! Notes are keyed by **project root** (the git/worktree root, or the launch
//! cwd when not in a repo) rather than by session, so the same set of notes
//! is visible across every session opened in that project. They live in the
//! global cockpit DB alongside sessions; they are pure TUI/DB state and never
//! enter any outbound model prompt (token economy, GOALS §10).
//!
//! Each note has a non-empty `name` (unique within its project) and markdown
//! `content`. The CRUD here is the single authority for create/list/rename/
//! delete; the TUI dialog is a view over it.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

/// A single scratchpad note: a name plus markdown content, scoped to a
/// project root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectNote {
    pub id: Uuid,
    /// Absolute project-root path this note is scoped to.
    pub project_root: String,
    pub name: String,
    /// Markdown source. Empty for a freshly-created, not-yet-edited note.
    pub content: String,
}

impl Db {
    /// Every note for `project_root`, ordered by sidebar `position` (stable
    /// authoring order, independent of name/timestamps). Empty when the
    /// project has no notes yet.
    pub async fn list_project_notes(&self, project_root: &str) -> Result<Vec<ProjectNote>> {
        let project_root = project_root.to_owned();
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, project_root, name, content
                     FROM project_notes
                     WHERE project_root = ?1
                     ORDER BY position ASC, created_at ASC",
                )
                .context("preparing list_project_notes")?;
            let rows = stmt
                .query_map([project_root], |row| {
                    let id: String = row.get(0)?;
                    Ok((
                        id,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .context("querying project_notes")?;
            let mut out = Vec::new();
            for r in rows {
                let (id, project_root, name, content) = r.context("reading project_note row")?;
                let id = Uuid::parse_str(&id).context("parsing note id")?;
                out.push(ProjectNote {
                    id,
                    project_root,
                    name,
                    content,
                });
            }
            Ok(out)
        })
        .await
    }

    /// Create a new note in `project_root` with `name` and empty content.
    /// The name is required non-empty (trimmed); a blank name is rejected.
    /// A duplicate name is disambiguated by appending ` (2)`, ` (3)`, … so
    /// the create always succeeds with a unique, non-empty name. Returns the
    /// stored note (with its final, possibly-suffixed name).
    pub async fn create_project_note(&self, project_root: &str, name: &str) -> Result<ProjectNote> {
        let base = name.trim();
        if base.is_empty() {
            anyhow::bail!("note name must not be empty");
        }
        let now = Utc::now().timestamp();
        let id = Uuid::new_v4();
        let project_root = project_root.to_owned();
        let name = base.to_owned();
        self.write(move |conn| {
            let unique = disambiguate_name(conn, &project_root, &name, None)?;
            // Append after any existing notes for stable sidebar order.
            let next_pos: i64 = conn
                .query_row(
                    "SELECT COALESCE(MAX(position), -1) + 1 FROM project_notes WHERE project_root = ?1",
                    [&project_root],
                    |row| row.get(0),
                )
                .context("computing next note position")?;
            conn.execute(
                "INSERT INTO project_notes
                     (id, project_root, name, content, position, created_at, updated_at)
                 VALUES (?1, ?2, ?3, '', ?4, ?5, ?5)",
                params![id.to_string(), project_root, unique, next_pos, now],
            )
            .context("inserting project_note")?;
            Ok(ProjectNote {
                id,
                project_root: project_root.to_string(),
                name: unique,
                content: String::new(),
            })
        })
        .await
    }

    /// Overwrite a note's markdown `content`. No-op (Ok) if the note id
    /// doesn't exist. Bumps `updated_at`.
    pub async fn set_project_note_content(&self, id: Uuid, content: &str) -> Result<()> {
        let now = Utc::now().timestamp();
        let content = content.to_owned();
        self.write(move |conn| {
            conn.execute(
                "UPDATE project_notes SET content = ?1, updated_at = ?2 WHERE id = ?3",
                params![content, now, id.to_string()],
            )
            .context("updating project_note content")?;
            Ok(())
        })
        .await
    }

    /// Rename a note. The new name is required non-empty (trimmed); a blank
    /// name is rejected. A collision with another note in the same project
    /// is disambiguated by suffixing (skipping the note being renamed).
    /// Returns the final, possibly-suffixed name. Errors if the note id
    /// doesn't exist.
    pub async fn rename_project_note(&self, id: Uuid, name: &str) -> Result<String> {
        let base = name.trim();
        if base.is_empty() {
            anyhow::bail!("note name must not be empty");
        }
        let now = Utc::now().timestamp();
        let name = base.to_owned();
        self.write(move |conn| {
            let project_root: Option<String> = conn
                .query_row(
                    "SELECT project_root FROM project_notes WHERE id = ?1",
                    [id.to_string()],
                    |row| row.get(0),
                )
                .optional()
                .context("looking up note for rename")?;
            let project_root =
                project_root.ok_or_else(|| anyhow::anyhow!("note `{id}` not found"))?;
            let unique = disambiguate_name(conn, &project_root, &name, Some(id))?;
            conn.execute(
                "UPDATE project_notes SET name = ?1, updated_at = ?2 WHERE id = ?3",
                params![unique, now, id.to_string()],
            )
            .context("renaming project_note")?;
            Ok(unique)
        })
        .await
    }

    /// Delete a note by id. No-op (Ok) if it doesn't exist.
    pub async fn delete_project_note(&self, id: Uuid) -> Result<()> {
        self.write(move |conn| {
            conn.execute("DELETE FROM project_notes WHERE id = ?1", [id.to_string()])
                .context("deleting project_note")?;
            Ok(())
        })
        .await
    }
}

/// Return a name unique within `project_root`: `base` itself if free, else
/// `base (2)`, `base (3)`, … `exclude` is the id of a note to ignore when
/// checking collisions (the note being renamed, so renaming to its own name
/// is a no-op rather than a forced suffix).
fn disambiguate_name(
    conn: &rusqlite::Connection,
    project_root: &str,
    base: &str,
    exclude: Option<Uuid>,
) -> Result<String> {
    let exclude_s = exclude.map(|u| u.to_string());
    let taken = |candidate: &str| -> Result<bool> {
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM project_notes
                 WHERE project_root = ?1 AND name = ?2 AND (?3 IS NULL OR id != ?3)",
                params![project_root, candidate, exclude_s],
                |row| row.get(0),
            )
            .context("checking note name collision")?;
        Ok(n > 0)
    };
    if !taken(base)? {
        return Ok(base.to_string());
    }
    // Suffix until free. Bounded by row count + 2 so it always terminates.
    for i in 2.. {
        let candidate = format!("{base} ({i})");
        if !taken(&candidate)? {
            return Ok(candidate);
        }
    }
    unreachable!("disambiguation loop is unbounded and always finds a free name")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "/home/u/proj";
    const OTHER: &str = "/home/u/other";

    #[tokio::test]
    async fn create_list_round_trip() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.list_project_notes(ROOT).await.unwrap().is_empty());
        let a = db.create_project_note(ROOT, "ideas").await.unwrap();
        let b = db.create_project_note(ROOT, "todo").await.unwrap();
        let notes = db.list_project_notes(ROOT).await.unwrap();
        assert_eq!(notes.len(), 2);
        // Position order: creation order preserved.
        assert_eq!(notes[0].name, "ideas");
        assert_eq!(notes[1].name, "todo");
        assert_eq!(notes[0].id, a.id);
        assert_eq!(notes[1].id, b.id);
        assert_eq!(notes[0].content, "");
    }

    #[tokio::test]
    async fn content_persists_and_updates() {
        let db = Db::open_in_memory().unwrap();
        let n = db.create_project_note(ROOT, "scratch").await.unwrap();
        db.set_project_note_content(n.id, "# Heading\n\nbody")
            .await
            .unwrap();
        let got = &db.list_project_notes(ROOT).await.unwrap()[0];
        assert_eq!(got.content, "# Heading\n\nbody");
        db.set_project_note_content(n.id, "replaced").await.unwrap();
        let got = &db.list_project_notes(ROOT).await.unwrap()[0];
        assert_eq!(got.content, "replaced");
    }

    #[tokio::test]
    async fn notes_are_scoped_by_project_root() {
        let db = Db::open_in_memory().unwrap();
        db.create_project_note(ROOT, "a").await.unwrap();
        db.create_project_note(OTHER, "b").await.unwrap();
        let here = db.list_project_notes(ROOT).await.unwrap();
        let there = db.list_project_notes(OTHER).await.unwrap();
        assert_eq!(here.len(), 1);
        assert_eq!(there.len(), 1);
        assert_eq!(here[0].name, "a");
        assert_eq!(there[0].name, "b");
    }

    #[tokio::test]
    async fn persists_across_sessions_same_db_file() {
        // "Across sessions" = separate Db handles to the same on-disk file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cockpit.db");
        let id;
        {
            let db = Db::open(&path).unwrap();
            let n = db.create_project_note(ROOT, "persistent").await.unwrap();
            db.set_project_note_content(n.id, "kept").await.unwrap();
            id = n.id;
        }
        // Fresh handle — a different "session" in the same project.
        {
            let db = Db::open(&path).unwrap();
            let notes = db.list_project_notes(ROOT).await.unwrap();
            assert_eq!(notes.len(), 1);
            assert_eq!(notes[0].id, id);
            assert_eq!(notes[0].name, "persistent");
            assert_eq!(notes[0].content, "kept");
        }
    }

    #[tokio::test]
    async fn blank_name_rejected_on_create_and_rename() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.create_project_note(ROOT, "").await.is_err());
        assert!(db.create_project_note(ROOT, "   ").await.is_err());
        let n = db.create_project_note(ROOT, "real").await.unwrap();
        assert!(db.rename_project_note(n.id, "").await.is_err());
        assert!(db.rename_project_note(n.id, "  ").await.is_err());
        // Name is trimmed.
        let t = db.create_project_note(ROOT, "  spaced  ").await.unwrap();
        assert_eq!(t.name, "spaced");
    }

    #[tokio::test]
    async fn duplicate_name_disambiguated() {
        let db = Db::open_in_memory().unwrap();
        let a = db.create_project_note(ROOT, "notes").await.unwrap();
        let b = db.create_project_note(ROOT, "notes").await.unwrap();
        let c = db.create_project_note(ROOT, "notes").await.unwrap();
        assert_eq!(a.name, "notes");
        assert_eq!(b.name, "notes (2)");
        assert_eq!(c.name, "notes (3)");
        // All three coexist.
        assert_eq!(db.list_project_notes(ROOT).await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn rename_and_collision_disambiguation() {
        let db = Db::open_in_memory().unwrap();
        let a = db.create_project_note(ROOT, "alpha").await.unwrap();
        let b = db.create_project_note(ROOT, "beta").await.unwrap();
        // Rename b → alpha collides with a → suffixed.
        let final_name = db.rename_project_note(b.id, "alpha").await.unwrap();
        assert_eq!(final_name, "alpha (2)");
        // Renaming a note to its own current name is a no-op (no suffix).
        let same = db.rename_project_note(a.id, "alpha").await.unwrap();
        assert_eq!(same, "alpha");
        // A clean rename keeps the requested name.
        let renamed = db.rename_project_note(a.id, "gamma").await.unwrap();
        assert_eq!(renamed, "gamma");
    }

    #[tokio::test]
    async fn rename_missing_note_errors() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.rename_project_note(Uuid::new_v4(), "x").await.is_err());
    }

    #[tokio::test]
    async fn delete_removes_note() {
        let db = Db::open_in_memory().unwrap();
        let a = db.create_project_note(ROOT, "a").await.unwrap();
        let b = db.create_project_note(ROOT, "b").await.unwrap();
        db.delete_project_note(a.id).await.unwrap();
        let notes = db.list_project_notes(ROOT).await.unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, b.id);
        // Deleting a missing id is a no-op.
        db.delete_project_note(Uuid::new_v4()).await.unwrap();
    }

    #[tokio::test]
    async fn db_async_intel_project_notes_roundtrip_through_async_api() {
        let db = Db::open_in_memory().unwrap();
        let note = db.create_project_note(ROOT, "runbook").await.unwrap();

        db.set_project_note_content(note.id, "async notes")
            .await
            .unwrap();
        let final_name = db.rename_project_note(note.id, "ops").await.unwrap();
        let notes = db.list_project_notes(ROOT).await.unwrap();

        assert_eq!(final_name, "ops");
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, note.id);
        assert_eq!(notes[0].name, "ops");
        assert_eq!(notes[0].content, "async notes");

        db.delete_project_note(note.id).await.unwrap();
        assert!(db.list_project_notes(ROOT).await.unwrap().is_empty());
    }
}
