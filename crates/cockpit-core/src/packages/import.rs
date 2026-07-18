use super::*;

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

pub(super) fn derive_package_identifier(package_dir: &Path) -> String {
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

pub(super) fn add_git_with_prepare_scope(
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

pub(super) fn import_kcl_manifest(db: &Db, cwd: &Path, manifest: &str) -> Result<KclImport> {
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

pub(super) fn validate_prepare_scope(scope: &str) -> Result<()> {
    match scope {
        "global" | "branch" => Ok(()),
        _ => bail!("invalid package prepare_scope `{scope}`; expected `global` or `branch`"),
    }
}

pub(super) fn default_prepare_scope() -> String {
    "global".to_string()
}

pub(super) fn import_from_legacy_kcl_db(db: &Db) -> Result<KclImport> {
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
                source_type: row
                    .get::<_, String>(2)?
                    .parse()
                    .unwrap_or(SourceType::Local),
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

/// Resolve kcl's DB path: `$XDG_DATA_HOME/kcl/kcl.db` if set, else
/// `~/.local/share/kcl/kcl.db`.
pub(super) fn kcl_db_path() -> Result<PathBuf> {
    if let Ok(s) = std::env::var("XDG_DATA_HOME")
        && !s.trim().is_empty()
    {
        return Ok(PathBuf::from(s).join("kcl").join("kcl.db"));
    }
    let home = dirs::home_dir().context("could not locate home dir")?;
    Ok(home.join(".local/share/kcl/kcl.db"))
}
