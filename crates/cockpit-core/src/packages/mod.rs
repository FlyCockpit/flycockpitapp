//! Package registry operations for the `docs` agent (GOALS §3a, prompt
//! `docs-agent.md` components A + decision 4).
//!
//! This module owns the side-effecting half of the registry: resolving
//! the cockpit clone directory, deriving collision-safe identifiers and
//! directory names, looking a dependency's source repo up from official
//! package-registry metadata (never a guessed URL — decision 4), shallow
//! Git clones, and the one-way `cockpit kcl import`. The pure DB CRUD
//! lives in [`crate::db::packages`].

pub mod resolve;

mod clone;
mod import;
mod prune;

#[allow(unused_imports)]
pub use self::clone::{clone_dir, percent_encode_identifier};
pub use self::import::{import_from_kcl, import_package, import_package_directory};
pub use self::prune::prune_package_clones;

#[cfg(test)]
use self::clone::{build_git_clone_command, clone_destination_in_dir, encoded_identifier_segment};
use self::clone::{clone_destination, git_clone, lexically_contains};
use self::import::{add_git_with_prepare_scope, default_prepare_scope};
#[cfg(test)]
use self::import::{derive_package_identifier, import_from_legacy_kcl_db, import_kcl_manifest};
#[cfg(test)]
use self::prune::prune_package_clones_in_dir;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::db::Db;
use crate::db::packages::{NewPackage, PackageRow, SourceType};
use crate::packages::resolve::normalize_repo_url;

/// Default cockpit clone directory when `packages_directory` is unset.
/// Distinct from kcl's `~/src/kcl-packages` so the two registries never
/// fight over a clone tree.
pub const DEFAULT_CLONE_SUBDIR: &str = "src/cockpit-packages";
pub const DEFAULT_PRUNE_DAYS: u32 = 30;

/// Supported ecosystems for autonomous repo resolution + identifier
/// slugging (prompt component A + decision 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Cargo,
    Npm,
    Pip,
}

impl Ecosystem {
    /// The identifier prefix (`cargo`, `npm`, `pip`).
    pub fn prefix(self) -> &'static str {
        match self {
            Ecosystem::Cargo => "cargo",
            Ecosystem::Npm => "npm",
            Ecosystem::Pip => "pip",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cargo" | "crates" | "rust" => Some(Ecosystem::Cargo),
            "npm" | "node" => Some(Ecosystem::Npm),
            "pip" | "pypi" | "python" => Some(Ecosystem::Pip),
            _ => None,
        }
    }

    /// The official registry the source repo is resolved from
    /// (`resolve.rs`) — used to ground the package-add approval rationale so
    /// it names the exact registry that declared the repo, never a guess.
    pub fn registry_label(self) -> &'static str {
        match self {
            Ecosystem::Cargo => "crates.io",
            Ecosystem::Npm => "npm",
            Ecosystem::Pip => "PyPI",
        }
    }
}

/// Derive the ecosystem-prefixed identifier slug for an autonomous add
/// (`cargo:tokio`, `npm:@tanstack/query`, `pip:requests`). Avoids
/// cross-ecosystem collisions (decision: "preserve kcl's identifiers
/// verbatim on import" — that path doesn't go through here).
pub fn ecosystem_slug(eco: Ecosystem, name: &str) -> String {
    format!("{}:{name}", eco.prefix())
}

/// Register a Local package: an absolute on-disk `path`, no clone. The
/// identifier defaults to the path's final component when not given.
pub fn add_local(db: &Db, identifier: &str, path: &Path) -> Result<PackageRow> {
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("resolving local package path `{}`", path.display()))?;
    if !canonical.is_dir() {
        bail!("local package path `{}` is not a directory", path.display());
    }
    db.upsert_package(&NewPackage {
        identifier: identifier.to_string(),
        display_name: identifier.to_string(),
        source_type: SourceType::Local,
        source_url: None,
        source_branch: None,
        path: canonical.to_string_lossy().into_owned(),
        shallow: false,
        prepare_scope: "global".to_string(),
    })
}

/// Register a Git package: shallow-clone `url` (unless `shallow` is
/// false) into the clone dir under a percent-encoded identifier, then
/// upsert. Deduped by `source_url`: if a package with the same repo is
/// already registered, its clone is reused (no second clone) and the
/// new identifier points at the same on-disk `path`.
///
/// `branch` is recorded so a future `cockpit packages update` can pull
/// the right ref; when `Some`, the clone is restricted to that branch.
pub fn add_git(
    db: &Db,
    cwd: &Path,
    identifier: &str,
    url: &str,
    branch: Option<&str>,
    shallow: bool,
) -> Result<PackageRow> {
    add_git_with_prepare_scope(db, cwd, identifier, url, branch, shallow, "global")
}

#[derive(Debug, Clone)]
pub struct PackagePruneOptions {
    pub days: u32,
    pub dry_run: bool,
}

impl Default for PackagePruneOptions {
    fn default() -> Self {
        Self {
            days: DEFAULT_PRUNE_DAYS,
            dry_run: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackagePruneReport {
    pub deleted: Vec<PrunedPackageClone>,
    pub skipped_groups: usize,
    pub missing_dirs: usize,
    pub failures: Vec<PackagePruneFailure>,
}

impl PackagePruneReport {
    pub fn bytes_reclaimed(&self) -> u64 {
        self.deleted.iter().map(|entry| entry.bytes).sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrunedPackageClone {
    pub path: PathBuf,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagePruneFailure {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Debug)]
struct PruneCandidate {
    path: PathBuf,
    updated_at: i64,
}

#[derive(Debug)]
struct PruneGroup {
    path: PathBuf,
    rows: Vec<PruneCandidate>,
}

enum PrunePath {
    Inside(PathBuf),
    MissingInside,
    Skip,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PackageImportSummary {
    pub imported: u32,
    pub deduped: u32,
    pub skipped: u32,
    pub warnings: Vec<String>,
    pub failures: Vec<PackageImportFailure>,
}

impl PackageImportSummary {
    pub fn failed(&self) -> usize {
        self.failures.len()
    }

    fn add_outcome(&mut self, outcome: PackageImportOutcome) {
        match outcome {
            PackageImportOutcome::Imported => self.imported += 1,
            PackageImportOutcome::Deduped => self.deduped += 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageImportFailure {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageImportOutcome {
    Imported,
    Deduped,
}

#[cfg(test)]
mod clone_command_tests {
    use super::*;

    fn clone_args(branch: Option<&str>, shallow: bool) -> Vec<String> {
        build_git_clone_command(
            "https://example.com/repo.git",
            Path::new("/tmp/cockpit-packages/repo"),
            branch,
            shallow,
        )
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
    }

    #[test]
    fn shallow_git_clone_uses_depth_and_no_single_branch() {
        let args = clone_args(None, true);
        assert!(args.windows(2).any(|pair| pair == ["--depth", "1"]));
        assert!(args.iter().any(|arg| arg == "--no-single-branch"));
    }

    #[test]
    fn deep_git_clone_omits_shallow_flags() {
        let args = clone_args(None, false);
        assert!(!args.iter().any(|arg| arg == "--depth"));
        assert!(!args.iter().any(|arg| arg == "--no-single-branch"));
    }

    #[test]
    fn shallow_git_clone_keeps_branch_arg() {
        let args = clone_args(Some("main"), true);
        assert!(args.windows(2).any(|pair| pair == ["--branch", "main"]));
    }
}

#[derive(Debug, Deserialize)]
struct KclPackageManifest {
    version: u32,
    packages: Vec<KclPackageEntry>,
}

#[derive(Debug, Deserialize)]
struct KclPackageEntry {
    identifier: String,
    git: String,
    branch: Option<String>,
    #[allow(dead_code)]
    harness: Option<String>,
    #[allow(dead_code)]
    auto_pull: bool,
    #[serde(default)]
    shallow: bool,
    #[serde(default = "default_prepare_scope")]
    prepare_scope: String,
}

/// Outcome of [`import_from_kcl`].
#[derive(Debug)]
pub enum KclImport {
    /// kcl's DB was found; `n` packages were added.
    Imported(u32),
    /// No kcl DB at the resolved path — clean no-op, not an error.
    NoKclDb(PathBuf),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encode_keeps_unreserved_escapes_rest() {
        assert_eq!(percent_encode_identifier("tokio"), "tokio");
        assert_eq!(percent_encode_identifier("cargo:tokio"), "cargo%3Atokio");
        assert_eq!(
            percent_encode_identifier("npm:@tanstack/query"),
            "npm%3A%40tanstack%2Fquery"
        );
        // The result is a single flat path segment.
        assert!(!percent_encode_identifier("npm:@tanstack/query").contains('/'));
    }

    #[test]
    fn encoded_identifier_segment_rejects_dot_segments() {
        let dot = encoded_identifier_segment(".").unwrap_err().to_string();
        assert!(dot.contains("invalid package identifier `.`"), "{dot}");
        assert!(dot.contains("escape"), "{dot}");

        let dotdot = encoded_identifier_segment("..").unwrap_err().to_string();
        assert!(
            dotdot.contains("invalid package identifier `..`"),
            "{dotdot}"
        );
        assert!(dotdot.contains("escape"), "{dotdot}");
    }

    #[test]
    fn clone_destination_keeps_encoded_identifier_inside_clone_dir() {
        let clone_root = PathBuf::from("/tmp/cockpit-package-clones");

        let scoped = clone_destination_in_dir(&clone_root, "npm:@tanstack/query").unwrap();
        assert_eq!(scoped, clone_root.join("npm%3A%40tanstack%2Fquery"));
        assert!(lexically_contains(&clone_root, &scoped));

        let traversal = clone_destination_in_dir(&clone_root, "../../evil").unwrap();
        assert_eq!(traversal, clone_root.join("..%2F..%2Fevil"));
        assert!(lexically_contains(&clone_root, &traversal));
    }

    #[test]
    fn clone_destination_rejects_dot_segments() {
        let clone_root = PathBuf::from("/tmp/cockpit-package-clones");
        assert!(clone_destination_in_dir(&clone_root, ".").is_err());
        assert!(clone_destination_in_dir(&clone_root, "..").is_err());
    }

    #[test]
    fn ecosystem_slug_prefixes() {
        assert_eq!(ecosystem_slug(Ecosystem::Cargo, "tokio"), "cargo:tokio");
        assert_eq!(
            ecosystem_slug(Ecosystem::Npm, "@tanstack/query"),
            "npm:@tanstack/query"
        );
        assert_eq!(ecosystem_slug(Ecosystem::Pip, "requests"), "pip:requests");
    }

    #[test]
    fn git_clone_command_denies_dangerous_protocols_before_url() {
        let dest = PathBuf::from("/tmp/cockpit-package-clones/repo");
        let cmd = build_git_clone_command("https://github.com/org/repo.git", &dest, None, true);
        let args = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            args,
            vec![
                "-c",
                "protocol.ext.allow=never",
                "-c",
                "protocol.file.allow=never",
                "clone",
                "--depth",
                "1",
                "--no-single-branch",
                "--",
                "https://github.com/org/repo.git",
                "/tmp/cockpit-package-clones/repo",
            ]
        );
    }

    #[test]
    fn add_git_dedupes_by_source_url() {
        let db = Db::open_in_memory().unwrap();
        // Pre-register a repo with a known on-disk path (no real clone).
        db.upsert_package(&NewPackage {
            identifier: "first".into(),
            display_name: "first".into(),
            source_type: SourceType::Git,
            source_url: Some("https://example.invalid/repo".into()),
            source_branch: Some("main".into()),
            path: "/existing/clone".into(),
            shallow: true,
            prepare_scope: "global".into(),
        })
        .unwrap();
        // Adding a second identifier for the same URL must reuse the path
        // and NOT attempt a clone (the URL is unreachable; a clone would
        // error). This exercises the dedupe branch.
        let tmp = tempfile::tempdir().unwrap();
        let row = add_git(
            &db,
            tmp.path(),
            "second",
            "https://example.invalid/repo",
            None,
            true,
        )
        .unwrap();
        assert_eq!(row.path, "/existing/clone");
        assert_eq!(row.identifier, "second");
    }

    #[test]
    fn add_git_rejects_invalid_identifier_before_dedupe_db_write() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_package(&NewPackage {
            identifier: "first".into(),
            display_name: "first".into(),
            source_type: SourceType::Git,
            source_url: Some("https://example.invalid/repo".into()),
            source_branch: Some("main".into()),
            path: "/existing/clone".into(),
            shallow: true,
            prepare_scope: "global".into(),
        })
        .unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let err = add_git(
            &db,
            tmp.path(),
            "..",
            "https://example.invalid/repo",
            None,
            true,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("invalid package identifier `..`"), "{err}");
        assert!(
            db.package_by_identifier("..").unwrap().is_none(),
            "invalid identifier must not be inserted even when source URL dedupes"
        );
    }

    fn write_file(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn init_git_repo(path: &Path, remote: Option<&str>) {
        std::fs::create_dir_all(path).unwrap();
        let status = Command::new("git")
            .arg("init")
            .arg("--quiet")
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success());
        if let Some(remote) = remote {
            let status = Command::new("git")
                .arg("-C")
                .arg(path)
                .args(["remote", "add", "origin", remote])
                .status()
                .unwrap();
            assert!(status.success());
        }
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db-async-intel-and-knowledge"
    )]
    fn register_package_with_timestamp(
        db: &Db,
        identifier: &str,
        source_type: SourceType,
        path: &Path,
        updated_at: i64,
    ) {
        db.upsert_package(&NewPackage {
            identifier: identifier.into(),
            display_name: identifier.into(),
            source_type,
            source_url: (source_type == SourceType::Git)
                .then(|| format!("https://example.invalid/{identifier}.git")),
            source_branch: None,
            path: path.to_string_lossy().into_owned(),
            shallow: true,
            prepare_scope: "global".into(),
        })
        .unwrap();
        let identifier = identifier.to_owned();
        db.write_blocking(move |conn| {
            conn.execute(
                "UPDATE packages SET updated_at = ?1 WHERE identifier = ?2",
                rusqlite::params![updated_at, identifier],
            )
            .unwrap();
            Ok(())
        })
        .unwrap();
    }

    fn package_rows(db: &Db) -> Vec<PackageRow> {
        db.list_packages().unwrap()
    }

    fn write_bytes(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn prune_deletes_stale_git_clone_under_clone_dir_and_keeps_row() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let clone_root = tmp.path().join("clones");
        let clone = clone_root.join("tokio");
        write_bytes(&clone.join("src/lib.rs"), b"hello");
        register_package_with_timestamp(&db, "tokio", SourceType::Git, &clone, 10);

        let report = prune_package_clones_in_dir(&package_rows(&db), &clone_root, 100, false)
            .expect("prune");

        assert_eq!(report.deleted.len(), 1);
        assert_eq!(report.bytes_reclaimed(), 5);
        assert!(!clone.exists());
        assert!(db.package_by_identifier("tokio").unwrap().is_some());
    }

    #[test]
    fn prune_skips_fresh_git_clone() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let clone_root = tmp.path().join("clones");
        let clone = clone_root.join("fresh");
        write_bytes(&clone.join("README.md"), b"fresh");
        register_package_with_timestamp(&db, "fresh", SourceType::Git, &clone, 200);

        let report = prune_package_clones_in_dir(&package_rows(&db), &clone_root, 100, false)
            .expect("prune");

        assert!(report.deleted.is_empty());
        assert_eq!(report.skipped_groups, 1);
        assert!(clone.exists());
    }

    #[test]
    fn prune_shared_clone_only_when_every_row_is_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let clone_root = tmp.path().join("clones");
        let clone = clone_root.join("shared");
        write_bytes(&clone.join("Cargo.toml"), b"shared");
        register_package_with_timestamp(&db, "stale", SourceType::Git, &clone, 10);
        register_package_with_timestamp(&db, "fresh", SourceType::Git, &clone, 200);

        let report = prune_package_clones_in_dir(&package_rows(&db), &clone_root, 100, false)
            .expect("prune");

        assert!(report.deleted.is_empty());
        assert_eq!(report.skipped_groups, 1);
        assert!(clone.exists());
    }

    #[test]
    fn prune_skips_local_path_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let clone_root = tmp.path().join("clones");
        let local = clone_root.join("local");
        write_bytes(&local.join("package.json"), b"{}");
        register_package_with_timestamp(&db, "local", SourceType::Local, &local, 10);

        let report = prune_package_clones_in_dir(&package_rows(&db), &clone_root, 100, false)
            .expect("prune");

        assert!(report.deleted.is_empty());
        assert_eq!(report.skipped_groups, 1);
        assert!(local.exists());
    }

    #[test]
    fn prune_skips_git_paths_outside_clone_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let clone_root = tmp.path().join("clones");
        std::fs::create_dir_all(&clone_root).unwrap();
        let outside = tmp.path().join("elsewhere/repo");
        write_bytes(&outside.join("README.md"), b"outside");
        register_package_with_timestamp(&db, "outside", SourceType::Git, &outside, 10);

        let report = prune_package_clones_in_dir(&package_rows(&db), &clone_root, 100, false)
            .expect("prune");

        assert!(report.deleted.is_empty());
        assert_eq!(report.skipped_groups, 1);
        assert!(outside.exists());
    }

    #[test]
    fn prune_dry_run_reports_without_deleting() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let clone_root = tmp.path().join("clones");
        let clone = clone_root.join("dry-run");
        write_bytes(&clone.join("README.md"), b"dry");
        register_package_with_timestamp(&db, "dry-run", SourceType::Git, &clone, 10);

        let report =
            prune_package_clones_in_dir(&package_rows(&db), &clone_root, 100, true).expect("prune");

        assert_eq!(report.deleted.len(), 1);
        assert_eq!(report.bytes_reclaimed(), 3);
        assert!(clone.exists());
    }

    #[test]
    fn prune_missing_clone_is_already_pruned_not_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let clone_root = tmp.path().join("clones");
        std::fs::create_dir_all(&clone_root).unwrap();
        let missing = clone_root.join("missing");
        register_package_with_timestamp(&db, "missing", SourceType::Git, &missing, 10);

        let report = prune_package_clones_in_dir(&package_rows(&db), &clone_root, 100, false)
            .expect("prune");

        assert!(report.deleted.is_empty());
        assert_eq!(report.missing_dirs, 1);
        assert!(report.failures.is_empty());
    }

    #[test]
    fn package_identifier_derivation_prefers_metadata_then_basename() {
        let tmp = tempfile::tempdir().unwrap();
        let cargo = tmp.path().join("cargo-dir");
        write_file(
            &cargo.join("Cargo.toml"),
            "[package]\nname = \"cargo-name\"\n",
        );
        assert_eq!(derive_package_identifier(&cargo), "cargo-name");

        let npm = tmp.path().join("npm-dir");
        write_file(&npm.join("package.json"), r#"{"name":"@scope/pkg"}"#);
        assert_eq!(derive_package_identifier(&npm), "@scope/pkg");

        let py = tmp.path().join("py-dir");
        write_file(
            &py.join("pyproject.toml"),
            "[project]\nname = \"py-name\"\n",
        );
        assert_eq!(derive_package_identifier(&py), "py-name");

        let fallback = tmp.path().join("fallback-name");
        std::fs::create_dir_all(&fallback).unwrap();
        assert_eq!(derive_package_identifier(&fallback), "fallback-name");
    }

    #[test]
    fn import_package_path_registers_exact_local_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let package = tmp.path().join("private");
        write_file(&package.join("package.json"), r#"{"name":"private-core"}"#);

        let summary = import_package(&db, tmp.path(), &package, None, true).unwrap();
        assert_eq!(summary.imported, 1);
        assert_eq!(summary.deduped, 0);
        let row = db.package_by_identifier("private-core").unwrap().unwrap();
        assert_eq!(row.source_type, SourceType::Local);
        assert_eq!(
            row.path,
            std::fs::canonicalize(&package)
                .unwrap()
                .to_string_lossy()
                .to_string()
        );
    }

    #[test]
    fn import_package_git_uses_remote_and_dedupes_without_source_path() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let package = tmp.path().join("tokio");
        init_git_repo(&package, Some("https://github.com/tokio-rs/tokio.git"));
        write_file(&package.join("Cargo.toml"), "[package]\nname = \"tokio\"\n");
        db.upsert_package(&NewPackage {
            identifier: "existing".into(),
            display_name: "existing".into(),
            source_type: SourceType::Git,
            source_url: Some("https://github.com/tokio-rs/tokio.git".into()),
            source_branch: None,
            path: "/cockpit/owned/tokio".into(),
            shallow: true,
            prepare_scope: "global".into(),
        })
        .unwrap();

        let summary = import_package(&db, tmp.path(), &package, None, false).unwrap();
        assert_eq!(summary.imported, 0);
        assert_eq!(summary.deduped, 1);
        let row = db.package_by_identifier("tokio").unwrap().unwrap();
        assert_eq!(row.source_type, SourceType::Git);
        assert_eq!(row.path, "/cockpit/owned/tokio");
        assert_ne!(row.path, package.to_string_lossy());
    }

    #[test]
    fn import_package_git_without_remote_suggests_path() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let package = tmp.path().join("no-remote");
        init_git_repo(&package, None);

        let summary = import_package(&db, tmp.path(), &package, None, false).unwrap();
        assert_eq!(summary.imported, 0);
        assert_eq!(summary.failed(), 1);
        assert!(summary.failures[0].reason.contains("pass `--path`"));
    }

    #[test]
    fn import_directory_path_mode_imports_dirs_and_skips_files() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let root = tmp.path().join("deps");
        write_file(
            &root.join("a/Cargo.toml"),
            "[package]\nname = \"a-crate\"\n",
        );
        write_file(&root.join("b/package.json"), r#"{"name":"b-pkg"}"#);
        write_file(&root.join("README.md"), "not a package dir");

        let summary = import_package_directory(&db, tmp.path(), &root, true).unwrap();
        assert_eq!(summary.imported, 2);
        assert_eq!(summary.skipped, 1);
        assert_eq!(summary.failed(), 0);
        assert!(db.package_by_identifier("a-crate").unwrap().is_some());
        assert!(db.package_by_identifier("b-pkg").unwrap().is_some());
    }

    #[test]
    fn import_directory_git_mode_skips_non_git_and_dedupes_remote() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open_in_memory().unwrap();
        let root = tmp.path().join("deps");
        let git_pkg = root.join("git-pkg");
        init_git_repo(&git_pkg, Some("https://github.com/example/repo.git"));
        write_file(
            &git_pkg.join("pyproject.toml"),
            "[project]\nname = \"git-pkg\"\n",
        );
        std::fs::create_dir_all(root.join("plain-dir")).unwrap();
        write_file(&root.join("file.txt"), "not a directory");
        db.upsert_package(&NewPackage {
            identifier: "existing".into(),
            display_name: "existing".into(),
            source_type: SourceType::Git,
            source_url: Some("https://github.com/example/repo.git".into()),
            source_branch: None,
            path: "/cockpit/owned/repo".into(),
            shallow: true,
            prepare_scope: "global".into(),
        })
        .unwrap();

        let summary = import_package_directory(&db, tmp.path(), &root, false).unwrap();
        assert_eq!(summary.imported, 0);
        assert_eq!(summary.deduped, 1);
        assert_eq!(summary.skipped, 2);
        assert_eq!(summary.failed(), 0);
        assert!(summary.warnings.iter().any(|w| w.contains("non-Git")));
        assert!(summary.warnings.iter().any(|w| w.contains("non-directory")));
    }

    #[test]
    fn manifest_import_preserves_prepare_scope_and_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        let clone_dir = tmp.path().join("packages");
        std::fs::write(
            &config_path,
            serde_json::json!({ "packages_directory": clone_dir.to_string_lossy() }).to_string(),
        )
        .unwrap();
        std::fs::create_dir_all(clone_dir.join("pkg-a/.git")).unwrap();
        std::fs::create_dir_all(clone_dir.join("pkg-b/.git")).unwrap();
        let config_override = crate::test_env::lock();
        config_override.set_cockpit_config(&config_path);

        let db = Db::open_in_memory().unwrap();
        let result = import_kcl_manifest(
            &db,
            tmp.path(),
            r#"{
                "version": 1,
                "packages": [
                    {
                        "identifier": "pkg-a",
                        "git": "https://example.invalid/a",
                        "branch": "main",
                        "harness": null,
                        "auto_pull": false,
                        "shallow": true,
                        "prepare_scope": "branch"
                    },
                    {
                        "identifier": "pkg-b",
                        "git": "https://example.invalid/b",
                        "branch": null,
                        "harness": null,
                        "auto_pull": false
                    }
                ]
            }"#,
        )
        .unwrap();

        assert!(matches!(result, KclImport::Imported(2)));
        let a = db.package_by_identifier("pkg-a").unwrap().unwrap();
        assert_eq!(a.prepare_scope, "branch");
        assert!(a.shallow);
        let b = db.package_by_identifier("pkg-b").unwrap().unwrap();
        assert_eq!(b.prepare_scope, "global");
        assert!(!b.shallow);
    }

    #[test]
    fn manifest_import_rejects_unknown_version_and_scope() {
        let db = Db::open_in_memory().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let version_err = import_kcl_manifest(&db, tmp.path(), r#"{"version": 2, "packages": []}"#)
            .unwrap_err()
            .to_string();
        assert!(version_err.contains("unsupported `kcl packages export` manifest version 2"));

        let scope_err = import_kcl_manifest(
            &db,
            tmp.path(),
            r#"{
                "version": 1,
                "packages": [{
                    "identifier": "pkg",
                    "git": "https://example.invalid/pkg",
                    "branch": null,
                    "harness": null,
                    "auto_pull": false,
                    "prepare_scope": "workspace"
                }]
            }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(scope_err.contains("invalid package prepare_scope `workspace`"));
        assert!(db.package_by_identifier("pkg").unwrap().is_none());
    }

    #[test]
    fn legacy_import_missing_kcl_db_is_clean() {
        // Point XDG_DATA_HOME at an empty dir so kcl.db is absent.
        let tmp = tempfile::tempdir().unwrap();
        let env = crate::test_env::lock();
        env.set_var("XDG_DATA_HOME", tmp.path());
        let db = Db::open_in_memory().unwrap();
        let result = import_from_legacy_kcl_db(&db).unwrap();
        assert!(matches!(result, KclImport::NoKclDb(_)));
    }
}
