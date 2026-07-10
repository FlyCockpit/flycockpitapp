//! Package-registry CRUD (migration 0006).
//!
//! Cockpit's own, user-global registry of third-party dependency source
//! clones the `docs` agent reads from (prompt `docs-agent.md`,
//! GOALS §3a). It is intentionally one-way importable from kcl
//! (`cockpit kcl import`) but never reads kcl's index or writes back to
//! kcl's DB. `prepare_scope` is registry metadata imported from kcl's
//! portable manifest; it is stored for future prepare behavior but not
//! shown by `cockpit packages list` yet.
//!
//! Dedupe is on two axes:
//!   - `identifier` (UNIQUE) — the canonical name (`cargo:tokio`,
//!     `tokio`, `@tanstack/query`). [`Db::upsert_package`] is idempotent
//!     on it.
//!   - `source_url` — Git packages cloned from the same repo reuse the
//!     first clone's on-disk `path` ([`Db::package_by_source_url`]), so a
//!     monorepo isn't cloned once per crate.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

/// Source kind for a registered package. Lowercase string in the DB keeps
/// legacy kcl rows and manifest imports normalized the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    /// A Git clone cockpit (or kcl) made; `source_url` is the repo.
    Git,
    /// A directory already on disk; no clone, `source_url` may be NULL.
    Local,
}

impl SourceType {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceType::Git => "git",
            SourceType::Local => "local",
        }
    }

    /// Parse a stored `source_type` string. Anything that isn't `git`
    /// is treated as `local` — kcl only emits `git`/`local`, and a
    /// non-clone row is the safe default.
    pub fn from_str(s: &str) -> Self {
        if s.eq_ignore_ascii_case("git") {
            SourceType::Git
        } else {
            SourceType::Local
        }
    }
}

/// One registered package.
#[derive(Debug, Clone)]
pub struct PackageRow {
    pub id: Uuid,
    pub identifier: String,
    pub display_name: String,
    pub source_type: SourceType,
    /// Repo URL for `Git`; usually NULL for `Local`.
    pub source_url: Option<String>,
    pub source_branch: Option<String>,
    /// Absolute on-disk location of the package's source.
    pub path: String,
    pub shallow: bool,
    /// Imported kcl prepare metadata. Cockpit stores it now, but the
    /// current list/docs flows do not display or act on it yet.
    #[allow(dead_code)]
    pub prepare_scope: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl PackageRow {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        let id: String = row.get("id")?;
        let id = Uuid::parse_str(&id).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?;
        let source_type: String = row.get("source_type")?;
        let shallow: i64 = row.get("shallow")?;
        Ok(Self {
            id,
            identifier: row.get("identifier")?,
            display_name: row.get("display_name")?,
            source_type: SourceType::from_str(&source_type),
            source_url: row.get("source_url")?,
            source_branch: row.get("source_branch")?,
            path: row.get("path")?,
            shallow: shallow != 0,
            prepare_scope: row.get("prepare_scope")?,
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

/// Fields needed to register a package. `id`/timestamps are assigned by
/// the insert.
#[derive(Debug, Clone)]
pub struct NewPackage {
    pub identifier: String,
    pub display_name: String,
    pub source_type: SourceType,
    pub source_url: Option<String>,
    pub source_branch: Option<String>,
    pub path: String,
    pub shallow: bool,
    pub prepare_scope: String,
}

impl Db {
    /// Look a package up by its canonical `identifier`.
    pub fn package_by_identifier(&self, identifier: &str) -> Result<Option<PackageRow>> {
        self.read_blocking(|conn| {
            conn.query_row(
                "SELECT * FROM packages WHERE identifier = ?1",
                params![identifier],
                PackageRow::from_row,
            )
            .optional()
            .context("query package_by_identifier")
        })
    }

    /// Look a Git package up by its `source_url` — the repo-dedupe key.
    /// Returns the first match (a monorepo cloned once is reused).
    pub fn package_by_source_url(&self, source_url: &str) -> Result<Option<PackageRow>> {
        self.read_blocking(|conn| {
            conn.query_row(
                "SELECT * FROM packages WHERE source_url = ?1 ORDER BY created_at LIMIT 1",
                params![source_url],
                PackageRow::from_row,
            )
            .optional()
            .context("query package_by_source_url")
        })
    }

    /// Every registered package, alphabetical by identifier.
    pub fn list_packages(&self) -> Result<Vec<PackageRow>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare("SELECT * FROM packages ORDER BY identifier")
                .context("preparing list_packages")?;
            let rows = stmt
                .query_map([], PackageRow::from_row)
                .context("querying list_packages")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding package row")?);
            }
            Ok(out)
        })
    }

    /// Insert `pkg`, or update the existing row with the same
    /// `identifier`. Idempotent on `identifier`; returns the resolved
    /// row. Concurrent callers adding the same identifier converge on
    /// one row (the UNIQUE constraint + upsert serialize them).
    pub fn upsert_package(&self, pkg: &NewPackage) -> Result<PackageRow> {
        let now = Utc::now().timestamp();
        let pkg = pkg.clone();
        self.write_blocking(move |conn| upsert_package_inner(conn, &pkg, now))
    }

    /// Insert `pkg` only if no row with its `identifier` exists yet.
    /// Returns `(row, inserted)` — `inserted = false` means the existing
    /// row was kept untouched. This is the import primitive: it never
    /// overwrites a row cockpit already has.
    pub fn insert_package_if_absent(&self, pkg: &NewPackage) -> Result<(PackageRow, bool)> {
        let now = Utc::now().timestamp();
        let pkg = pkg.clone();
        self.write_blocking(move |conn| {
            if let Some(existing) = conn
                .query_row(
                    "SELECT * FROM packages WHERE identifier = ?1",
                    params![pkg.identifier],
                    PackageRow::from_row,
                )
                .optional()
                .context("checking existing package")?
            {
                return Ok((existing, false));
            }
            let row = insert_package_inner(conn, &pkg, now)?;
            Ok((row, true))
        })
    }
}

fn upsert_package_inner(conn: &Connection, pkg: &NewPackage, now: i64) -> Result<PackageRow> {
    if let Some(existing) = conn
        .query_row(
            "SELECT * FROM packages WHERE identifier = ?1",
            params![pkg.identifier],
            PackageRow::from_row,
        )
        .optional()
        .context("checking existing package for upsert")?
    {
        conn.execute(
            "UPDATE packages SET display_name = ?2, source_type = ?3, source_url = ?4, \
             source_branch = ?5, path = ?6, shallow = ?7, prepare_scope = ?8, updated_at = ?9 WHERE id = ?1",
            params![
                existing.id.to_string(),
                pkg.display_name,
                pkg.source_type.as_str(),
                pkg.source_url,
                pkg.source_branch,
                pkg.path,
                pkg.shallow as i64,
                pkg.prepare_scope,
                now,
            ],
        )
        .context("updating package")?;
        return Ok(PackageRow {
            id: existing.id,
            identifier: pkg.identifier.clone(),
            display_name: pkg.display_name.clone(),
            source_type: pkg.source_type,
            source_url: pkg.source_url.clone(),
            source_branch: pkg.source_branch.clone(),
            path: pkg.path.clone(),
            shallow: pkg.shallow,
            prepare_scope: pkg.prepare_scope.clone(),
            created_at: existing.created_at,
            updated_at: now,
        });
    }
    insert_package_inner(conn, pkg, now)
}

fn insert_package_inner(conn: &Connection, pkg: &NewPackage, now: i64) -> Result<PackageRow> {
    let id = Uuid::new_v4();
    conn.execute(
        "INSERT INTO packages \
         (id, identifier, display_name, source_type, source_url, source_branch, path, shallow, prepare_scope, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
        params![
            id.to_string(),
            pkg.identifier,
            pkg.display_name,
            pkg.source_type.as_str(),
            pkg.source_url,
            pkg.source_branch,
            pkg.path,
            pkg.shallow as i64,
            pkg.prepare_scope,
            now,
        ],
    )
    .context("inserting package")?;
    Ok(PackageRow {
        id,
        identifier: pkg.identifier.clone(),
        display_name: pkg.display_name.clone(),
        source_type: pkg.source_type,
        source_url: pkg.source_url.clone(),
        source_branch: pkg.source_branch.clone(),
        path: pkg.path.clone(),
        shallow: pkg.shallow,
        prepare_scope: pkg.prepare_scope.clone(),
        created_at: now,
        updated_at: now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(identifier: &str, url: Option<&str>) -> NewPackage {
        NewPackage {
            identifier: identifier.to_string(),
            display_name: identifier.to_string(),
            source_type: if url.is_some() {
                SourceType::Git
            } else {
                SourceType::Local
            },
            source_url: url.map(str::to_string),
            source_branch: url.map(|_| "main".to_string()),
            path: format!("/clones/{identifier}"),
            shallow: true,
            prepare_scope: "global".to_string(),
        }
    }

    #[test]
    fn insert_and_lookup_by_identifier() {
        let db = Db::open_in_memory().unwrap();
        let row = db
            .upsert_package(&sample(
                "cargo:tokio",
                Some("https://github.com/tokio-rs/tokio"),
            ))
            .unwrap();
        assert_eq!(row.identifier, "cargo:tokio");
        assert_eq!(row.source_type, SourceType::Git);
        let got = db.package_by_identifier("cargo:tokio").unwrap().unwrap();
        assert_eq!(got.id, row.id);
        assert!(got.shallow);
        assert_eq!(got.prepare_scope, "global");
    }

    #[test]
    fn upsert_is_idempotent_on_identifier() {
        let db = Db::open_in_memory().unwrap();
        let a = db.upsert_package(&sample("tokio", Some("u1"))).unwrap();
        let b = db.upsert_package(&sample("tokio", Some("u1"))).unwrap();
        assert_eq!(a.id, b.id, "same identifier must reuse the same row id");
        assert_eq!(db.list_packages().unwrap().len(), 1);
    }

    #[test]
    fn lookup_by_source_url_dedupes_repo() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_package(&sample("crate-a", Some("https://repo")))
            .unwrap();
        let hit = db.package_by_source_url("https://repo").unwrap();
        assert!(hit.is_some());
        assert!(db.package_by_source_url("https://other").unwrap().is_none());
    }

    #[test]
    fn insert_if_absent_never_overwrites() {
        let db = Db::open_in_memory().unwrap();
        let (first, inserted) = db.insert_package_if_absent(&sample("x", None)).unwrap();
        assert!(inserted);
        // Second call with a different path must keep the original row.
        let mut other = sample("x", None);
        other.path = "/different".to_string();
        other.prepare_scope = "branch".to_string();
        let (second, inserted2) = db.insert_package_if_absent(&other).unwrap();
        assert!(!inserted2);
        assert_eq!(second.id, first.id);
        assert_eq!(second.path, "/clones/x");
        assert_eq!(second.prepare_scope, "global");
    }
}
