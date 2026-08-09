//! Offline drift tests for cargo-dist configuration, generated docs, and release glue.

const DIST: &str = include_str!("../../../dist-workspace.toml");
const WORKFLOW: &str = include_str!("../../../.github/workflows/release.yml");
const README: &str = include_str!("../README.md");
const DOCS: &str = include_str!("../../docs/src/content/docs/reference/runtime-prerequisites.md");
const CATALOG: &str = include_str!("../../../crates/cockpit-core/src/external_runtime/adapters.rs");
const GENERATOR: &str = include_str!("../scripts/generate-release-assets.sh");

#[test]
fn runtime_release_contract_tests() {
    for target in [
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "aarch64-unknown-linux-gnu",
        "x86_64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
    ] {
        assert!(DIST.contains(target));
    }
    assert!(DIST.contains("installers = [\"shell\", \"powershell\", \"homebrew\"]"));
    assert!(README.contains("SHA-256 checksum"));
}

#[test]
fn installer_atomic_rollback() {
    for guarantee in [
        "private temporary directory",
        "preserve an existing installation",
        "verification, extraction",
        "single `cockpit` executable",
    ] {
        assert!(README.contains(guarantee));
    }
}

#[test]
fn installer_destination_and_completion() {
    assert!(DIST.contains("install-path = \"CARGO_HOME\""));
    assert!(!README.contains("FLYCOCKPIT_INSTALL_DIR"));
    for term in [
        "do not edit shell startup files",
        "completions/",
        "man/",
        "uninstall",
    ] {
        assert!(README.contains(term));
    }
}

#[test]
fn external_dependency_installer_warning() {
    assert!(DIST.contains("Missing Bubblewrap"));
    assert!(DOCS.contains("never makes installation fail"));
    assert!(DOCS.contains("never\nruns a package manager"));
}

#[test]
fn runtime_docs_catalog_drift() {
    for value in [
        "cockpit doctor --dependencies-json",
        "Settings → Dependencies",
        "https://ffmpeg.org/download.html",
        "verify",
        "refresh",
        "Uninstall",
    ] {
        assert!(DOCS.contains(value));
    }
}

#[test]
fn media_runtime_matrix() {
    for format in [
        "PNG", "JPEG", "GIF", "WebP", "WAV", "MP3", "M4A", "FLAC", "Ogg", "MP4", "WebM", "MOV",
    ] {
        assert!(DOCS.contains(format));
    }
    for id in [
        "media.ffmpeg",
        "media.ffprobe",
        "ffmpeg-ffprobe-compatible-pair",
    ] {
        assert!(CATALOG.contains(id));
    }
    assert!(DOCS.contains("Selection fails closed"));
    assert!(DOCS.contains("does not download, bundle, or install"));
}

#[test]
fn release_generation_reuses_repository_target() {
    assert!(WORKFLOW.contains("CARGO_TARGET_DIR: target"));
    assert!(!WORKFLOW.contains("apps/cli/target"));
    assert!(GENERATOR.contains("target/dist|target/distrib"));
    assert!(GENERATOR.contains("must be the repository-owned target directory"));
}

#[test]
fn cargo_dist_monorepo_configuration() {
    assert!(DIST.contains("members = [\"cargo:apps/cli\"]"));
    assert!(DIST.contains("apps/cli/scripts/install-shell-assets.sh"));
    assert!(!WORKFLOW.contains("working-directory: apps/cli"));
    assert!(WORKFLOW.contains("path: target/distrib/"));
}
