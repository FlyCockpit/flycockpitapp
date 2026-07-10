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

/// Resolve the directory cockpit clones Git packages into. Honors the
/// `packages_directory` config key (tilde-expanded), else
/// `~/src/cockpit-packages/`.
pub fn clone_dir(cwd: &Path) -> Result<PathBuf> {
    if let Some(dir) = configured_clone_dir(cwd) {
        return Ok(dir);
    }
    let home = dirs::home_dir().context("could not locate home dir")?;
    Ok(home.join(DEFAULT_CLONE_SUBDIR))
}

/// Read `packages_directory` from the first layered `config.json`
/// that sets it, tilde-expanded. `None` when unset.
fn configured_clone_dir(cwd: &Path) -> Option<PathBuf> {
    crate::config::extended::load_for_cwd(cwd)
        .packages_directory
        .map(|p| {
            let expanded = shellexpand::tilde(&p.to_string_lossy()).into_owned();
            PathBuf::from(expanded)
        })
}

/// Percent-encode an identifier for use as a directory name. Encodes
/// every byte that isn't an unreserved URL char (`A-Za-z0-9._-`), so
/// `npm:@tanstack/query` becomes a single flat, filesystem-safe segment
/// — matching kcl's clone-dir scheme.
pub fn percent_encode_identifier(identifier: &str) -> String {
    let mut out = String::with_capacity(identifier.len());
    for &b in identifier.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-');
        if unreserved {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(hex_upper(b >> 4));
            out.push(hex_upper(b & 0xf));
        }
    }
    out
}

fn encoded_identifier_segment(identifier: &str) -> Result<String> {
    let encoded = percent_encode_identifier(identifier);
    if encoded == "." || encoded == ".." {
        bail!(
            "invalid package identifier `{identifier}`: encoded clone directory segment `{encoded}` would escape the package clone directory"
        );
    }
    Ok(encoded)
}

fn clone_destination(cwd: &Path, identifier: &str) -> Result<(PathBuf, PathBuf)> {
    let dir = clone_dir(cwd)?;
    let dest = clone_destination_in_dir(&dir, identifier)?;
    Ok((dir, dest))
}

fn clone_destination_in_dir(dir: &Path, identifier: &str) -> Result<PathBuf> {
    let segment = encoded_identifier_segment(identifier)?;
    let dest = dir.join(segment);
    if !lexically_contains(dir, &dest) {
        bail!(
            "invalid package identifier `{identifier}`: clone destination `{}` escapes package clone directory `{}`",
            dest.display(),
            dir.display()
        );
    }
    Ok(dest)
}

fn lexically_contains(base: &Path, candidate: &Path) -> bool {
    let base = lexical_normalize(base);
    let candidate = lexical_normalize(candidate);
    candidate.starts_with(&base) && candidate != base
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn hex_upper(nibble: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    HEX[nibble as usize] as char
}

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

pub fn prune_package_clones(
    db: &Db,
    cwd: &Path,
    options: &PackagePruneOptions,
) -> Result<PackagePruneReport> {
    let clone_root = clone_dir(cwd)?;
    let rows = db.list_packages()?;
    let cutoff = chrono::Utc::now().timestamp() - i64::from(options.days) * 24 * 60 * 60;
    prune_package_clones_in_dir(&rows, &clone_root, cutoff, options.dry_run)
}

fn prune_package_clones_in_dir(
    rows: &[PackageRow],
    clone_root: &Path,
    stale_before: i64,
    dry_run: bool,
) -> Result<PackagePruneReport> {
    let mut report = PackagePruneReport::default();
    let mut groups: BTreeMap<PathBuf, PruneGroup> = BTreeMap::new();

    for row in rows {
        if row.source_type != SourceType::Git {
            report.skipped_groups += 1;
            continue;
        }
        let row_path = PathBuf::from(&row.path);
        match normalize_prune_candidate_path(clone_root, &row_path) {
            PrunePath::Inside(path) => {
                groups
                    .entry(path.clone())
                    .or_insert_with(|| PruneGroup {
                        path,
                        rows: Vec::new(),
                    })
                    .rows
                    .push(PruneCandidate {
                        path: row_path,
                        updated_at: row.updated_at,
                    });
            }
            PrunePath::MissingInside => {
                report.missing_dirs += 1;
            }
            PrunePath::Skip => {
                report.skipped_groups += 1;
            }
        }
    }

    for group in groups.into_values() {
        if group.rows.iter().any(|row| row.updated_at > stale_before) {
            report.skipped_groups += 1;
            continue;
        }
        if group.rows.iter().any(|row| path_is_symlink(&row.path)) {
            report.skipped_groups += 1;
            continue;
        }
        let bytes = match directory_size(&group.path) {
            Ok(bytes) => bytes,
            Err(err) => {
                report.failures.push(PackagePruneFailure {
                    path: group.path.clone(),
                    reason: err.to_string(),
                });
                continue;
            }
        };
        if !dry_run && let Err(err) = fs::remove_dir_all(&group.path) {
            report.failures.push(PackagePruneFailure {
                path: group.path.clone(),
                reason: err.to_string(),
            });
            continue;
        }
        report.deleted.push(PrunedPackageClone {
            path: group.path,
            bytes,
        });
    }

    Ok(report)
}

enum PrunePath {
    Inside(PathBuf),
    MissingInside,
    Skip,
}

fn normalize_prune_candidate_path(clone_root: &Path, candidate: &Path) -> PrunePath {
    if candidate == clone_root {
        return PrunePath::Skip;
    }

    match fs::symlink_metadata(candidate) {
        Ok(meta) => {
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return PrunePath::Skip;
            }
            let Ok(root) = fs::canonicalize(clone_root) else {
                return PrunePath::Skip;
            };
            let Ok(path) = fs::canonicalize(candidate) else {
                return PrunePath::Skip;
            };
            if path.starts_with(&root) && path != root {
                PrunePath::Inside(path)
            } else {
                PrunePath::Skip
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if lexically_contains(clone_root, candidate) {
                PrunePath::MissingInside
            } else {
                PrunePath::Skip
            }
        }
        Err(_) => PrunePath::Skip,
    }
}

fn path_is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
}

fn directory_size(path: &Path) -> Result<u64> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("reading metadata for `{}`", path.display()))?;
    if meta.is_file() {
        return Ok(meta.len());
    }
    if !meta.is_dir() {
        return Ok(0);
    }
    let mut total = 0;
    for entry in fs::read_dir(path).with_context(|| format!("reading `{}`", path.display()))? {
        let entry = entry.with_context(|| format!("reading entry in `{}`", path.display()))?;
        total += directory_size(&entry.path())?;
    }
    Ok(total)
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

/// Import one local directory as either a Git-managed package (default) or
/// an exact local/path package (`as_path`). Git imports read metadata from the
/// source checkout but store a Cockpit-owned clone path.
pub fn import_package(
    db: &Db,
    cwd: &Path,
    package_dir: &Path,
    id: Option<&str>,
    as_path: bool,
) -> Result<PackageImportSummary> {
    let mut summary = PackageImportSummary::default();
    match import_one(db, cwd, package_dir, id, as_path) {
        Ok(outcome) => summary.add_outcome(outcome),
        Err(err) => summary.failures.push(PackageImportFailure {
            path: package_dir.to_path_buf(),
            reason: err.to_string(),
        }),
    }
    Ok(summary)
}

/// Import immediate child directories from `dir`. This intentionally does not
/// recurse; non-directories and non-Git children are skipped with warnings.
pub fn import_package_directory(
    db: &Db,
    cwd: &Path,
    dir: &Path,
    as_path: bool,
) -> Result<PackageImportSummary> {
    let mut summary = PackageImportSummary::default();
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("reading `{}`", dir.display()))? {
        match entry {
            Ok(entry) => entries.push(entry.path()),
            Err(err) => {
                summary.skipped += 1;
                summary
                    .warnings
                    .push(format!("skipped unreadable directory entry: {err}"));
            }
        }
    }
    entries.sort();

    for path in entries {
        if !path.is_dir() {
            summary.skipped += 1;
            summary
                .warnings
                .push(format!("skipped non-directory `{}`", path.display()));
            continue;
        }
        if !as_path && !is_git_checkout(&path) {
            summary.skipped += 1;
            summary
                .warnings
                .push(format!("skipped non-Git directory `{}`", path.display()));
            continue;
        }
        if !as_path && git_origin_url(&path)?.is_none() {
            summary.skipped += 1;
            summary.warnings.push(format!(
                "skipped Git directory without usable remote `{}`",
                path.display()
            ));
            continue;
        }
        match import_one(db, cwd, &path, None, as_path) {
            Ok(outcome) => summary.add_outcome(outcome),
            Err(err) => summary.failures.push(PackageImportFailure {
                path,
                reason: err.to_string(),
            }),
        }
    }
    Ok(summary)
}

fn import_one(
    db: &Db,
    cwd: &Path,
    package_dir: &Path,
    id: Option<&str>,
    as_path: bool,
) -> Result<PackageImportOutcome> {
    let identifier = id
        .map(str::to_string)
        .unwrap_or_else(|| derive_package_identifier(package_dir));
    if as_path {
        add_local(db, &identifier, package_dir)?;
        return Ok(PackageImportOutcome::Imported);
    }

    if !is_git_checkout(package_dir) {
        bail!(
            "`{}` is not a Git repository; pass `--path` to register it as a local package",
            package_dir.display()
        );
    }
    let remote = git_origin_url(package_dir)?.with_context(|| {
        format!(
            "`{}` has no usable Git remote URL; pass `--path` to register it as a local package",
            package_dir.display()
        )
    })?;
    let branch = git_current_branch(package_dir);
    let deduped = db.package_by_source_url(&remote)?.is_some();
    add_git(db, cwd, &identifier, &remote, branch.as_deref(), true)?;
    Ok(if deduped {
        PackageImportOutcome::Deduped
    } else {
        PackageImportOutcome::Imported
    })
}

fn derive_package_identifier(package_dir: &Path) -> String {
    package_name_from_cargo(package_dir)
        .or_else(|| package_name_from_package_json(package_dir))
        .or_else(|| package_name_from_pyproject(package_dir))
        .unwrap_or_else(|| {
            package_dir
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| !name.trim().is_empty())
                .unwrap_or("package")
                .to_string()
        })
}

fn package_name_from_cargo(package_dir: &Path) -> Option<String> {
    let text = fs::read_to_string(package_dir.join("Cargo.toml")).ok()?;
    let parsed = toml::from_str::<toml::Value>(&text).ok()?;
    parsed
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn package_name_from_package_json(package_dir: &Path) -> Option<String> {
    let text = fs::read_to_string(package_dir.join("package.json")).ok()?;
    let parsed = serde_json::from_str::<serde_json::Value>(&text).ok()?;
    parsed
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn package_name_from_pyproject(package_dir: &Path) -> Option<String> {
    let text = fs::read_to_string(package_dir.join("pyproject.toml")).ok()?;
    let parsed = toml::from_str::<toml::Value>(&text).ok()?;
    parsed
        .get("project")
        .and_then(|project| project.get("name"))
        .and_then(toml::Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn is_git_checkout(path: &Path) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .is_some_and(|stdout| stdout.trim() == "true")
}

fn git_origin_url(path: &Path) -> Result<Option<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["config", "--get", "remote.origin.url"])
        .output()
        .with_context(|| format!("reading Git remote for `{}`", path.display()))?;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8(output.stdout)
        .with_context(|| format!("decoding Git remote for `{}`", path.display()))?;
    let remote = stdout.trim();
    if remote.is_empty() {
        return Ok(None);
    }
    normalize_repo_url(remote)
        .with_context(|| format!("normalizing Git remote `{remote}`"))
        .map(Some)
}

fn git_current_branch(path: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let branch = stdout.trim();
    if branch.is_empty() || branch == "HEAD" {
        None
    } else {
        Some(branch.to_string())
    }
}

fn add_git_with_prepare_scope(
    db: &Db,
    cwd: &Path,
    identifier: &str,
    url: &str,
    branch: Option<&str>,
    shallow: bool,
    prepare_scope: &str,
) -> Result<PackageRow> {
    validate_prepare_scope(prepare_scope)?;
    let (dir, dest) = clone_destination(cwd, identifier)?;

    // Repo dedupe: reuse an existing clone for the same URL.
    if let Some(existing) = db.package_by_source_url(url)? {
        return db.upsert_package(&NewPackage {
            identifier: identifier.to_string(),
            display_name: identifier.to_string(),
            source_type: SourceType::Git,
            source_url: Some(url.to_string()),
            source_branch: branch
                .map(str::to_string)
                .or(existing.source_branch.clone()),
            path: existing.path.clone(),
            shallow: existing.shallow,
            prepare_scope: prepare_scope.to_string(),
        });
    }

    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating clone dir `{}`", dir.display()))?;

    // Concurrency: if the destination already holds a clone (a racing
    // caller got there first), reuse it rather than re-cloning.
    if dest.join(".git").is_dir() {
        return db.upsert_package(&NewPackage {
            identifier: identifier.to_string(),
            display_name: identifier.to_string(),
            source_type: SourceType::Git,
            source_url: Some(url.to_string()),
            source_branch: branch.map(str::to_string),
            path: dest.to_string_lossy().into_owned(),
            shallow,
            prepare_scope: prepare_scope.to_string(),
        });
    }

    git_clone(url, &dest, branch, shallow)
        .with_context(|| format!("cloning `{url}` into `{}`", dest.display()))?;

    db.upsert_package(&NewPackage {
        identifier: identifier.to_string(),
        display_name: identifier.to_string(),
        source_type: SourceType::Git,
        source_url: Some(url.to_string()),
        source_branch: branch.map(str::to_string),
        path: dest.to_string_lossy().into_owned(),
        shallow,
        prepare_scope: prepare_scope.to_string(),
    })
}

/// Run `git clone`. Shallow (`--depth 1`) by default to bound disk/time
/// for large dependencies (prompt decision 4). A non-zero exit surfaces
/// the captured stderr as the error (clean failure, no panic).
fn git_clone(url: &str, dest: &Path, branch: Option<&str>, shallow: bool) -> Result<()> {
    let mut cmd = build_git_clone_command(url, dest, branch, shallow);
    let output = cmd
        .output()
        .context("spawning `git clone` (is git installed and on PATH?)")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git clone failed: {}", stderr.trim());
    }
    Ok(())
}

fn build_git_clone_command(
    url: &str,
    dest: &Path,
    branch: Option<&str>,
    shallow: bool,
) -> std::process::Command {
    let mut cmd = std::process::Command::new("git");
    cmd.arg("-c")
        .arg("protocol.ext.allow=never")
        .arg("-c")
        .arg("protocol.file.allow=never");
    cmd.arg("clone");
    if shallow {
        cmd.arg("--depth").arg("1").arg("--no-single-branch");
    }
    if let Some(b) = branch {
        cmd.arg("--branch").arg(b);
    }
    cmd.arg("--").arg(url).arg(dest);
    cmd
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

/// Import packages from kcl's registry that cockpit doesn't already have.
/// Prefers kcl's portable `kcl packages export` v1 manifest, which has no
/// clone path, so Git entries are cloned or source-url-deduped into
/// cockpit's own `packages_directory`. If the export command is unavailable,
/// falls back to kcl's legacy `~/.local/share/kcl/kcl.db` (honoring
/// `$XDG_DATA_HOME`) and references those old on-disk paths as-is. One-way:
/// never writes to kcl's DB. Returns the number of packages added.
///
/// Dedupe matches the registry's own: by `identifier`, and additionally
/// by `source_url` for Git packages (so a repo cockpit already tracks
/// under a different identifier isn't re-imported).
pub fn import_from_kcl(db: &Db, cwd: &Path) -> Result<KclImport> {
    if let Some(manifest) = export_kcl_packages()? {
        return import_kcl_manifest(db, cwd, &manifest);
    }
    import_from_legacy_kcl_db(db)
}

fn export_kcl_packages() -> Result<Option<String>> {
    let output = match Command::new("kcl").args(["packages", "export"]).output() {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("spawning `kcl packages export`"),
    };
    if !output.status.success() {
        return Ok(None);
    }
    String::from_utf8(output.stdout)
        .context("decoding `kcl packages export` output as UTF-8")
        .map(Some)
}

fn import_kcl_manifest(db: &Db, cwd: &Path, manifest: &str) -> Result<KclImport> {
    let manifest: KclPackageManifest =
        serde_json::from_str(manifest).context("parsing `kcl packages export` manifest")?;
    if manifest.version != 1 {
        bail!(
            "unsupported `kcl packages export` manifest version {}; expected 1",
            manifest.version
        );
    }

    let mut added = 0u32;
    for entry in manifest.packages {
        validate_prepare_scope(&entry.prepare_scope)?;
        if db.package_by_identifier(&entry.identifier)?.is_some() {
            continue;
        }
        if db.package_by_source_url(&entry.git)?.is_some() {
            continue;
        }
        add_git_with_prepare_scope(
            db,
            cwd,
            &entry.identifier,
            &entry.git,
            entry.branch.as_deref(),
            entry.shallow,
            &entry.prepare_scope,
        )?;
        added += 1;
    }
    Ok(KclImport::Imported(added))
}

fn validate_prepare_scope(scope: &str) -> Result<()> {
    match scope {
        "global" | "branch" => Ok(()),
        _ => bail!("invalid package prepare_scope `{scope}`; expected `global` or `branch`"),
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

fn default_prepare_scope() -> String {
    "global".to_string()
}

fn import_from_legacy_kcl_db(db: &Db) -> Result<KclImport> {
    let kcl_db_path = kcl_db_path()?;
    if !kcl_db_path.exists() {
        return Ok(KclImport::NoKclDb(kcl_db_path));
    }

    let conn = rusqlite::Connection::open_with_flags(
        &kcl_db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .with_context(|| format!("opening kcl db at {}", kcl_db_path.display()))?;

    let mut stmt = conn
        .prepare(
            "SELECT identifier, display_name, source_type, source_url, source_branch, path, shallow \
             FROM packages",
        )
        .context("preparing kcl packages query")?;
    let rows = stmt
        .query_map([], |row| {
            let shallow: i64 = row.get(6)?;
            Ok(NewPackage {
                identifier: row.get(0)?,
                display_name: row.get(1)?,
                source_type: SourceType::from_str(&row.get::<_, String>(2)?),
                source_url: row.get(3)?,
                source_branch: row.get(4)?,
                path: row.get(5)?,
                shallow: shallow != 0,
                prepare_scope: "global".to_string(),
            })
        })
        .context("querying kcl packages")?;

    let mut added = 0u32;
    for row in rows {
        let pkg = row.context("decoding kcl package row")?;
        // Skip if we already have this identifier, or (for Git) this repo.
        if db.package_by_identifier(&pkg.identifier)?.is_some() {
            continue;
        }
        if pkg.source_type == SourceType::Git
            && let Some(url) = &pkg.source_url
            && db.package_by_source_url(url)?.is_some()
        {
            continue;
        }
        let (_, inserted) = db.insert_package_if_absent(&pkg)?;
        if inserted {
            added += 1;
        }
    }
    Ok(KclImport::Imported(added))
}

/// Outcome of [`import_from_kcl`].
#[derive(Debug)]
pub enum KclImport {
    /// kcl's DB was found; `n` packages were added.
    Imported(u32),
    /// No kcl DB at the resolved path — clean no-op, not an error.
    NoKclDb(PathBuf),
}

/// Resolve kcl's DB path: `$XDG_DATA_HOME/kcl/kcl.db` if set, else
/// `~/.local/share/kcl/kcl.db`.
fn kcl_db_path() -> Result<PathBuf> {
    if let Ok(s) = std::env::var("XDG_DATA_HOME")
        && !s.trim().is_empty()
    {
        return Ok(PathBuf::from(s).join("kcl").join("kcl.db"));
    }
    let home = dirs::home_dir().context("could not locate home dir")?;
    Ok(home.join(".local/share/kcl/kcl.db"))
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
        let _override = crate::config::dirs::test_support::CockpitConfigOverride::new(&config_path);

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
        let prev = std::env::var("XDG_DATA_HOME").ok();
        unsafe { std::env::set_var("XDG_DATA_HOME", tmp.path()) };
        let db = Db::open_in_memory().unwrap();
        let result = import_from_legacy_kcl_db(&db).unwrap();
        unsafe {
            match prev {
                Some(v) => std::env::set_var("XDG_DATA_HOME", v),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
        }
        assert!(matches!(result, KclImport::NoKclDb(_)));
    }
}
