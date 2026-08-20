//! `cockpit packages {list,add,import,prune}` — thin CLI over the package registry
//! (prompt `docs-agent.md` component A). The daemon owns the registry; these
//! commands are socket clients for the owner-remoted package RPCs and never
//! open SQLite.

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::cli::{PackagesAddArgs, PackagesCommand, PackagesImportArgs, PackagesPruneArgs};
use crate::daemon::client::ensure_persistent_daemon;
use crate::daemon::proto::{Request, Response};

pub async fn run(cmd: PackagesCommand) -> Result<()> {
    match cmd {
        PackagesCommand::List => list().await,
        PackagesCommand::Add(args) => add(args).await,
        PackagesCommand::Import(args) => import(args).await,
        PackagesCommand::Prune(args) => prune(args).await,
    }
}

/// Non-secret projection of one registered package row, as returned by the
/// daemon's `list_packages` / `add_package` responses.
#[derive(Debug, Deserialize)]
struct PackageRowView {
    identifier: String,
    display_name: String,
    source_type: String,
    #[serde(default)]
    source_url: Option<String>,
    path: String,
}

/// Projection of the `import_package` summary.
#[derive(Debug, Deserialize)]
struct PackageImportSummaryView {
    imported: usize,
    deduped: usize,
    skipped: usize,
    failed: usize,
    #[serde(default)]
    warnings: Vec<String>,
    #[serde(default)]
    failures: Vec<PackageFailureView>,
}

#[derive(Debug, Deserialize)]
struct PackageFailureView {
    path: String,
    reason: String,
}

/// Projection of the `prune_packages` report.
#[derive(Debug, Deserialize)]
struct PackagePruneReportView {
    #[serde(default)]
    deleted: Vec<PackagePruneEntryView>,
    bytes_reclaimed: u64,
    skipped_groups: usize,
    missing_dirs: usize,
    #[serde(default)]
    failures: Vec<PackageFailureView>,
}

#[derive(Debug, Deserialize)]
struct PackagePruneEntryView {
    path: String,
    bytes: u64,
}

async fn list() -> Result<()> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for package registry")?;
    let response = daemon
        .client
        .request(Request::ListPackages)
        .await
        .context("requesting package list from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected package list: {error}"))?;
    let Response::Packages { packages_json } = response else {
        bail!("daemon returned unexpected response to package list: {response:?}");
    };
    let packages: Vec<PackageRowView> =
        serde_json::from_str(&packages_json).context("parsing package list")?;
    print!("{}", format_package_list(&packages));
    Ok(())
}

fn format_package_list(packages: &[PackageRowView]) -> String {
    if packages.is_empty() {
        return "No packages registered. Add one with `cockpit packages add` or `cockpit kcl import`.\n".to_string();
    }
    let mut out = String::new();
    for p in packages {
        let kind = p.source_type.as_str();
        // Show the display name only when it differs from the identifier
        // (kcl imports often carry a friendlier name).
        let label = if p.display_name == p.identifier {
            p.identifier.clone()
        } else {
            format!("{} ({})", p.identifier, p.display_name)
        };
        match &p.source_url {
            Some(url) => out.push_str(&format!("{label}  [{kind}]  {url}  -> {}\n", p.path)),
            None => out.push_str(&format!("{label}  [{kind}]  -> {}\n", p.path)),
        }
    }
    out.push_str(&format!("\n{} package(s).\n", packages.len()));
    out
}

async fn add(args: PackagesAddArgs) -> Result<()> {
    if args.git.is_some() && args.path.is_some() {
        bail!("pass either `--git` or `--path`, not both");
    }
    if args.git.is_none() && args.path.is_none() {
        bail!("`packages add` needs either `--git <url>` or `--path <dir>`");
    }
    let cwd = std::env::current_dir()?;
    let is_git = args.git.is_some();
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for package registry")?;
    let response = daemon
        .client
        .request(Request::AddPackage {
            project_root: cwd.display().to_string(),
            identifier: args.identifier,
            git: args.git,
            branch: args.branch,
            local_path: args.path.map(|path| path.display().to_string()),
            deep: args.deep,
        })
        .await
        .context("requesting package add from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected package add: {error}"))?;
    let Response::PackageAdded { package_json } = response else {
        bail!("daemon returned unexpected response to package add: {response:?}");
    };
    let row: PackageRowView =
        serde_json::from_str(&package_json).context("parsing added package")?;
    let kind = if is_git { "git" } else { "local" };
    println!("Registered `{}` ({kind}) at {}", row.identifier, row.path);
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
    let single_package = package.is_some();
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for package registry")?;
    let response = daemon
        .client
        .request(Request::ImportPackage {
            project_root: cwd.display().to_string(),
            dir: args.dir.map(|dir| dir.display().to_string()),
            package: package.map(|package| package.display().to_string()),
            id: args.id,
            as_path: args.path,
        })
        .await
        .context("requesting package import from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected package import: {error}"))?;
    let Response::PackageImported { summary_json } = response else {
        bail!("daemon returned unexpected response to package import: {response:?}");
    };
    let summary: PackageImportSummaryView =
        serde_json::from_str(&summary_json).context("parsing package import summary")?;
    print_import_summary(&summary);
    if single_package && summary.failed > 0 {
        bail!("package import failed");
    }
    Ok(())
}

async fn prune(args: PackagesPruneArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for package registry")?;
    let response = daemon
        .client
        .request(Request::PrunePackages {
            project_root: cwd.display().to_string(),
            days: args.days,
            dry_run: args.dry_run,
        })
        .await
        .context("requesting package prune from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected package prune: {error}"))?;
    let Response::PackagesPruned { report_json } = response else {
        bail!("daemon returned unexpected response to package prune: {response:?}");
    };
    let report: PackagePruneReportView =
        serde_json::from_str(&report_json).context("parsing package prune report")?;
    print_prune_summary(&report, args.dry_run);
    Ok(())
}

fn print_import_summary(summary: &PackageImportSummaryView) {
    for warning in &summary.warnings {
        eprintln!("warning: {warning}");
    }
    for failure in &summary.failures {
        eprintln!("failed: {}: {}", failure.path, failure.reason);
    }
    println!(
        "Imported {} package(s); deduped {}; skipped {}; failed {}.",
        summary.imported, summary.deduped, summary.skipped, summary.failed
    );
}

fn print_prune_summary(report: &PackagePruneReportView, dry_run: bool) {
    if dry_run {
        for entry in &report.deleted {
            println!("Would delete {} ({} bytes)", entry.path, entry.bytes);
        }
        println!(
            "Would delete {} clone directories; reclaim approximately {} bytes; skipped {}; already missing {}; failures {}.",
            report.deleted.len(),
            report.bytes_reclaimed,
            report.skipped_groups,
            report.missing_dirs,
            report.failures.len()
        );
    } else {
        println!(
            "Deleted {} clone directories; reclaimed {} bytes; skipped {}; already missing {}; failures {}.",
            report.deleted.len(),
            report.bytes_reclaimed,
            report.skipped_groups,
            report.missing_dirs,
            report.failures.len()
        );
    }
    for failure in &report.failures {
        eprintln!("failed: {}: {}", failure.path, failure.reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    use crate::cli::{Cli, Command, PackagesCommand};

    #[test]
    fn package_list_hides_matching_display_name_and_shows_url() {
        let rows = vec![
            PackageRowView {
                identifier: "tokio".into(),
                display_name: "tokio".into(),
                source_type: "git".into(),
                source_url: Some("https://github.com/tokio-rs/tokio".into()),
                path: "/clones/tokio".into(),
            },
            PackageRowView {
                identifier: "kcl:std".into(),
                display_name: "Standard Library".into(),
                source_type: "local".into(),
                source_url: None,
                path: "/local/std".into(),
            },
        ];
        let rendered = format_package_list(&rows);
        // Matching identifier/display_name collapses to a single label; the URL
        // is only shown when present.
        assert!(
            rendered
                .contains("tokio  [git]  https://github.com/tokio-rs/tokio  -> /clones/tokio\n")
        );
        assert!(rendered.contains("kcl:std (Standard Library)  [local]  -> /local/std\n"));
        assert!(rendered.contains("\n2 package(s).\n"));
    }

    #[test]
    fn empty_package_list_prints_guidance() {
        assert!(
            format_package_list(&[]).contains("No packages registered."),
            "an empty registry must guide the user to add/import"
        );
    }

    #[test]
    fn import_summary_parses_daemon_projection() {
        let summary: PackageImportSummaryView = serde_json::from_str(
            r#"{"imported":2,"deduped":1,"skipped":0,"failed":1,"warnings":["w"],"failures":[{"path":"/a","reason":"boom"}]}"#,
        )
        .unwrap();
        assert_eq!(summary.imported, 2);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.failures[0].reason, "boom");
    }

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
