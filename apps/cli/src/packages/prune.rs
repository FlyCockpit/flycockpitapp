use super::*;

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

pub(super) fn prune_package_clones_in_dir(
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
