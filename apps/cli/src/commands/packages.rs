//! `cockpit packages {list,add,import,prune}` — thin CLI over the package registry
//! (prompt `docs-agent.md` component A).

use anyhow::{Result, bail};

use crate::cli::{PackagesAddArgs, PackagesCommand, PackagesImportArgs, PackagesPruneArgs};
use crate::db::Db;

pub async fn run(cmd: PackagesCommand) -> Result<()> {
    match cmd {
        PackagesCommand::List => list().await,
        PackagesCommand::Add(args) => add(args).await,
        PackagesCommand::Import(args) => import(args).await,
        PackagesCommand::Prune(args) => prune(args).await,
    }
}

async fn list() -> Result<()> {
    let db = Db::open_default()?;
    let packages = db.list_packages()?;
    if packages.is_empty() {
        println!(
            "No packages registered. Add one with `cockpit packages add` or `cockpit kcl import`."
        );
        return Ok(());
    }
    for p in &packages {
        let kind = p.source_type.as_str();
        // Show the display name only when it differs from the identifier
        // (kcl imports often carry a friendlier name).
        let label = if p.display_name == p.identifier {
            p.identifier.clone()
        } else {
            format!("{} ({})", p.identifier, p.display_name)
        };
        match &p.source_url {
            Some(url) => println!("{label}  [{kind}]  {url}  -> {}", p.path),
            None => println!("{label}  [{kind}]  -> {}", p.path),
        }
    }
    println!("\n{} package(s).", packages.len());
    Ok(())
}

async fn add(args: PackagesAddArgs) -> Result<()> {
    if args.git.is_some() && args.path.is_some() {
        bail!("pass either `--git` or `--path`, not both");
    }
    let cwd = std::env::current_dir()?;
    let db = Db::open_default()?;
    let shallow = !args.deep;

    if let Some(url) = args.git {
        let row = crate::packages::add_git(
            &db,
            &cwd,
            &args.identifier,
            &url,
            args.branch.as_deref(),
            shallow,
        )?;
        println!("Registered `{}` (git) at {}", row.identifier, row.path);
    } else if let Some(path) = args.path {
        let row = crate::packages::add_local(&db, &args.identifier, &path)?;
        println!("Registered `{}` (local) at {}", row.identifier, row.path);
    } else {
        bail!("`packages add` needs either `--git <url>` or `--path <dir>`");
    }
    Ok(())
}

async fn import(args: PackagesImportArgs) -> Result<()> {
    let package = args.package.or(args.package_path);
    if args.dir.is_none() && package.is_none() {
        bail!("`packages import` needs either `--dir <directory>` or `--package <dir>`");
    }
    if args.dir.is_some() && args.id.is_some() {
        bail!("`--id` can only be used with `--package`, not `--dir`");
    }

    let cwd = std::env::current_dir()?;
    let db = Db::open_default()?;
    let single_package = package.is_some();
    let summary = if let Some(dir) = args.dir {
        crate::packages::import_package_directory(&db, &cwd, &dir, args.path)?
    } else if let Some(package_dir) = package {
        crate::packages::import_package(&db, &cwd, &package_dir, args.id.as_deref(), args.path)?
    } else {
        unreachable!("checked above")
    };
    print_import_summary(&summary);
    if single_package && summary.failed() > 0 {
        bail!("package import failed");
    }
    Ok(())
}

async fn prune(args: PackagesPruneArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let db = Db::open_default()?;
    let report = crate::packages::prune_package_clones(
        &db,
        &cwd,
        &crate::packages::PackagePruneOptions {
            days: args.days,
            dry_run: args.dry_run,
        },
    )?;
    print_prune_summary(&report, args.dry_run);
    Ok(())
}

fn print_import_summary(summary: &crate::packages::PackageImportSummary) {
    for warning in &summary.warnings {
        eprintln!("warning: {warning}");
    }
    for failure in &summary.failures {
        eprintln!("failed: {}: {}", failure.path.display(), failure.reason);
    }
    println!(
        "Imported {} package(s); deduped {}; skipped {}; failed {}.",
        summary.imported,
        summary.deduped,
        summary.skipped,
        summary.failed()
    );
}

fn print_prune_summary(report: &crate::packages::PackagePruneReport, dry_run: bool) {
    if dry_run {
        for entry in &report.deleted {
            println!(
                "Would delete {} ({} bytes)",
                entry.path.display(),
                entry.bytes
            );
        }
        println!(
            "Would delete {} clone directories; reclaim approximately {} bytes; skipped {}; already missing {}; failures {}.",
            report.deleted.len(),
            report.bytes_reclaimed(),
            report.skipped_groups,
            report.missing_dirs,
            report.failures.len()
        );
    } else {
        println!(
            "Deleted {} clone directories; reclaimed {} bytes; skipped {}; already missing {}; failures {}.",
            report.deleted.len(),
            report.bytes_reclaimed(),
            report.skipped_groups,
            report.missing_dirs,
            report.failures.len()
        );
    }
    for failure in &report.failures {
        eprintln!("failed: {}: {}", failure.path.display(), failure.reason);
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::cli::{Cli, Command, PackagesCommand};

    #[test]
    fn package_add_parses_singular_alias_with_git_before_identifier() {
        let cli = Cli::try_parse_from([
            "cockpit",
            "package",
            "add",
            "--git",
            "https://github.com/tokio-rs/tokio",
            "tokio",
        ])
        .unwrap();
        let Some(Command::Packages(PackagesCommand::Add(args))) = cli.command else {
            panic!("expected package alias add command");
        };
        assert_eq!(args.identifier, "tokio");
        assert_eq!(
            args.git.as_deref(),
            Some("https://github.com/tokio-rs/tokio")
        );
        assert!(!args.deep);
    }

    #[test]
    fn package_list_parses_singular_alias() {
        let cli = Cli::try_parse_from(["cockpit", "package", "list"]).unwrap();
        let Some(Command::Packages(PackagesCommand::List)) = cli.command else {
            panic!("expected package alias list command");
        };
    }

    #[test]
    fn packages_add_deep_flag_parses_full_clone() {
        let cli = Cli::try_parse_from([
            "cockpit",
            "packages",
            "add",
            "tokio",
            "--git",
            "https://github.com/tokio-rs/tokio",
            "--deep",
        ])
        .unwrap();
        let Some(Command::Packages(PackagesCommand::Add(args))) = cli.command else {
            panic!("expected packages add command");
        };
        assert_eq!(args.identifier, "tokio");
        assert!(args.deep);
    }

    #[test]
    fn dependencies_alias_parses_package_surface() {
        let cli = Cli::try_parse_from(["cockpit", "dependencies", "list"]).unwrap();
        let Some(Command::Packages(PackagesCommand::List)) = cli.command else {
            panic!("expected packages list command through dependencies alias");
        };
    }

    #[test]
    fn packages_prune_parses_days_and_dry_run() {
        let cli = Cli::try_parse_from(["cockpit", "packages", "prune", "--days", "7", "--dry-run"])
            .unwrap();
        let Some(Command::Packages(PackagesCommand::Prune(args))) = cli.command else {
            panic!("expected packages prune command");
        };
        assert_eq!(args.days, 7);
        assert!(args.dry_run);
    }

    #[test]
    fn package_prune_parses_singular_alias() {
        let cli = Cli::try_parse_from(["cockpit", "package", "prune"]).unwrap();
        let Some(Command::Packages(PackagesCommand::Prune(args))) = cli.command else {
            panic!("expected package alias prune command");
        };
        assert_eq!(args.days, crate::packages::DEFAULT_PRUNE_DAYS);
        assert!(!args.dry_run);
    }

    #[test]
    fn packages_import_rejects_id_with_dir_at_parse_time() {
        let err = Cli::try_parse_from([
            "cockpit", "packages", "import", "--dir", "deps", "--id", "x",
        ])
        .unwrap_err()
        .to_string();
        assert!(err.contains("cannot be used with"), "{err}");
    }

    #[test]
    fn singular_package_import_parses_single_package_form() {
        let cli =
            Cli::try_parse_from(["cockpit", "package", "import", "deps/tokio", "--path"]).unwrap();
        let Some(Command::Packages(PackagesCommand::Import(args))) = cli.command else {
            panic!("expected package alias import command");
        };
        assert_eq!(args.package, Some(std::path::PathBuf::from("deps/tokio")));
        assert!(args.path);
    }

    #[test]
    fn canonical_packages_import_parses_dir_form() {
        let cli = Cli::try_parse_from(["cockpit", "packages", "import", "--dir", "deps"]).unwrap();
        let Some(Command::Packages(PackagesCommand::Import(args))) = cli.command else {
            panic!("expected packages import command");
        };
        assert_eq!(args.dir, Some(std::path::PathBuf::from("deps")));
        assert!(args.package.is_none());
        assert!(args.package_path.is_none());
    }

    #[test]
    fn package_merge_aliases() {
        for root in ["packages", "package", "dependency", "dependencies"] {
            let cli = Cli::try_parse_from(["cockpit", root, "list"]).unwrap();
            assert!(
                matches!(cli.command, Some(Command::Packages(PackagesCommand::List))),
                "{root} should parse to canonical packages command"
            );
        }

        let cli = Cli::try_parse_from(["cockpit", "packages", "import", "--package", "deps/tokio"])
            .unwrap();
        let Some(Command::Packages(PackagesCommand::Import(args))) = cli.command else {
            panic!("expected packages import command");
        };
        assert_eq!(
            args.package_path,
            Some(std::path::PathBuf::from("deps/tokio"))
        );
        assert!(args.package.is_none());
    }
}
