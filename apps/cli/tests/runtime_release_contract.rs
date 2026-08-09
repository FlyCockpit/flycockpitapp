//! Offline drift tests for cargo-dist configuration, generated docs, and release glue.

const DIST: &str = include_str!("../../../dist-workspace.toml");
const WORKFLOW: &str = include_str!("../../../.github/workflows/release.yml");
const README: &str = include_str!("../README.md");
const DOCS: &str = include_str!("../../docs/src/content/docs/reference/runtime-prerequisites.md");
const CATALOG: &str = include_str!("../../../crates/cockpit-core/src/external_runtime/adapters.rs");
const GENERATOR: &str = include_str!("../scripts/generate-release-assets.sh");
const SHELL_INSTALLER_FIXTURE: &str = include_str!("fixtures/generated-installer.sh");
const POWERSHELL_INSTALLER_FIXTURE: &str = include_str!("fixtures/generated-installer.ps1");

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
fn generated_installer_fixtures_are_both_executable_programs() {
    assert!(SHELL_INSTALLER_FIXTURE.starts_with("#!/bin/sh\n"));
    assert!(POWERSHELL_INSTALLER_FIXTURE.starts_with("$ErrorActionPreference"));
}

#[cfg(unix)]
#[test]
fn generated_posix_installer_is_hermetic_and_transactional() {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::Command,
    };

    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/dist")
        .join(format!("installer fixture {}", std::process::id()));
    let _cleanup = Cleanup(root.clone());
    fs::create_dir_all(&root).unwrap();
    let installer = root.join("cockpit-cli-installer.sh");
    fs::write(&installer, SHELL_INSTALLER_FIXTURE).unwrap();
    fs::set_permissions(&installer, fs::Permissions::from_mode(0o755)).unwrap();

    fn archive(root: &Path, name: &str, executables: usize) -> PathBuf {
        let payload = root.join(format!("{name} payload"));
        fs::create_dir_all(&payload).unwrap();
        for n in 0..executables {
            let dir = payload.join(format!("bin{n}"));
            fs::create_dir_all(&dir).unwrap();
            let bin = dir.join("cockpit");
            fs::write(&bin, "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(bin, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let out = root.join(format!("{name}.tar.gz"));
        assert!(
            Command::new("tar")
                .args(["-czf"])
                .arg(&out)
                .arg("-C")
                .arg(&payload)
                .arg(".")
                .status()
                .unwrap()
                .success()
        );
        out
    }
    fn digest(path: &Path) -> String {
        let out = Command::new("sha256sum").arg(path).output().unwrap();
        String::from_utf8(out.stdout)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .into()
    }
    fn run(
        installer: &Path,
        archive: &Path,
        sum: &str,
        dest: &Path,
        stage: &Path,
        arch: &str,
    ) -> std::process::Output {
        fs::create_dir_all(stage).unwrap();
        Command::new("sh")
            .arg(installer)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("COCKPIT_FIXTURE_ARCHIVE", archive)
            .env("COCKPIT_FIXTURE_SHA256", sum)
            .env("COCKPIT_FIXTURE_DEST", dest)
            .env("COCKPIT_FIXTURE_STAGE_ROOT", stage)
            .env("COCKPIT_FIXTURE_ARCH", arch)
            .output()
            .unwrap()
    }
    fn empty(path: &Path) -> bool {
        fs::read_dir(path).unwrap().next().is_none()
    }

    let good = archive(&root, "valid archive", 1);
    let sum = digest(&good);
    let dest = root.join("destination with spaces");
    let stage = root.join("stage with spaces");
    let ok = run(&installer, &good, &sum, &dest, &stage, "x86_64");
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert_eq!(fs::read_dir(&dest).unwrap().count(), 1);
    assert!(dest.join("cockpit").is_file());
    assert!(empty(&stage));

    for (name, input, checksum, arch) in [
        ("checksum", good.clone(), "00".repeat(32), "x86_64"),
        ("unsupported", good.clone(), sum.clone(), "mips64"),
    ] {
        let d = root.join(format!("{name} dest"));
        let s = root.join(format!("{name} stage"));
        assert!(
            !run(&installer, &input, &checksum, &d, &s, arch)
                .status
                .success()
        );
        assert!(empty(&s));
        assert!(!d.join("cockpit").exists());
    }
    let corrupt = root.join("corrupt.tar.gz");
    fs::write(&corrupt, "not an archive").unwrap();
    let s = root.join("extract stage");
    let d = root.join("extract dest");
    assert!(
        !run(&installer, &corrupt, &digest(&corrupt), &d, &s, "x86_64")
            .status
            .success()
    );
    assert!(empty(&s));
    let existing = root.join("existing dest");
    fs::create_dir_all(&existing).unwrap();
    fs::write(existing.join("cockpit"), "original").unwrap();
    let s = root.join("existing stage");
    assert!(
        !run(&installer, &good, &sum, &existing, &s, "x86_64")
            .status
            .success()
    );
    assert_eq!(
        fs::read_to_string(existing.join("cockpit")).unwrap(),
        "original"
    );
    assert!(empty(&s));
    for count in [0, 2] {
        let a = archive(&root, &format!("count {count}"), count);
        let s = root.join(format!("count {count} stage"));
        assert!(
            !run(
                &installer,
                &a,
                &digest(&a),
                &root.join(format!("count {count} dest")),
                &s,
                "x86_64"
            )
            .status
            .success()
        );
        assert!(empty(&s));
    }
}

#[cfg(unix)]
#[test]
fn bubblewrap_notice_is_conditional_read_only_and_infallible() {
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/distrib")
        .join(format!("notice fixture {}", std::process::id()));
    let _cleanup = Cleanup(root.clone());
    let tools = root.join("tools");
    fs::create_dir_all(&tools).unwrap();
    let notice = root.join("runtime-prerequisite-notice.sh");
    fs::write(
        &notice,
        include_str!("../scripts/runtime-prerequisite-notice.sh"),
    )
    .unwrap();
    let marker = root.join("remedy-ran");
    for tool in ["apt", "apt-get", "dnf", "yum", "pacman", "brew", "sudo"] {
        let path = tools.join(tool);
        fs::write(
            &path,
            format!("#!/bin/sh\necho ran >> '{}'\nexit 99\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let invoke = |uname: &str, os: &str, with_bwrap: bool| {
        let os_release = root.join("os-release");
        fs::write(&os_release, os).unwrap();
        let bwrap = tools.join("bwrap");
        let _ = fs::remove_file(&bwrap);
        if with_bwrap {
            fs::write(&bwrap, "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(&bwrap, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Command::new("/bin/sh")
            .arg(&notice)
            .env_clear()
            .env("PATH", &tools)
            .env("COCKPIT_INSTALLER_TEST_UNAME", uname)
            .env("COCKPIT_INSTALLER_TEST_OS_RELEASE", &os_release)
            .output()
            .unwrap()
    };
    let present = invoke("Linux", "ID=debian\n", true);
    assert!(present.status.success());
    assert!(present.stderr.is_empty());
    let non_linux = invoke("Darwin", "ID=debian\n", false);
    assert!(non_linux.status.success());
    assert!(non_linux.stderr.is_empty());
    for (identity, expected) in [
        ("ID=debian\n", "Debian/Ubuntu"),
        ("ID=fedora\n", "Fedora/RHEL"),
        ("ID=arch\n", "Arch"),
        ("ID=gentoo\n", "github.com/containers/bubblewrap"),
    ] {
        let out = invoke("Linux", identity, false);
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains(expected));
    }
    assert!(
        !marker.exists(),
        "notice invoked a remedy or package manager"
    );
}

#[test]
fn powershell_fixture_covers_missing_localappdata_and_cleans_staging() {
    use std::{
        fs,
        path::{Path, PathBuf},
        process::Command,
    };
    let shell = ["pwsh", "powershell"].into_iter().find(|name| {
        Command::new(name)
            .arg("-NoProfile")
            .arg("-Command")
            .arg("exit 0")
            .status()
            .is_ok()
    });
    let Some(shell) = shell else {
        return;
    }; // Exercised on Windows and CI images that provide PowerShell.
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/distrib")
        .join(format!(
            "powershell installer fixture {}",
            std::process::id()
        ));
    let _cleanup = Cleanup(root.clone());
    fs::create_dir_all(&root).unwrap();
    let installer = root.join("cockpit-cli-installer.ps1");
    fs::write(&installer, POWERSHELL_INSTALLER_FIXTURE).unwrap();
    let payload = root.join("payload");
    fs::create_dir_all(&payload).unwrap();
    fs::write(payload.join("cockpit.exe"), "fixture executable").unwrap();
    let archive = root.join("archive.tar.gz");
    assert!(
        Command::new("tar")
            .args(["-czf"])
            .arg(&archive)
            .arg("-C")
            .arg(&payload)
            .arg(".")
            .status()
            .unwrap()
            .success()
    );
    let digest = Command::new(shell)
        .args(["-NoProfile", "-Command"])
        .arg(format!(
            "(Get-FileHash -LiteralPath '{}' -Algorithm SHA256).Hash.ToLowerInvariant()",
            archive.display()
        ))
        .output()
        .unwrap();
    let checksum = String::from_utf8(digest.stdout).unwrap().trim().to_owned();
    let destination = root.join("destination with spaces");
    let stage = root.join("stage with spaces");
    fs::create_dir_all(&stage).unwrap();
    let invoke = |archive: &Path, checksum: &str, destination: &Path, stage: &Path, arch: &str| {
        fs::create_dir_all(stage).unwrap();
        Command::new(shell)
            .args(["-NoProfile", "-File"])
            .arg(&installer)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("COCKPIT_FIXTURE_ARCHIVE", archive)
            .env("COCKPIT_FIXTURE_SHA256", checksum)
            .env("COCKPIT_FIXTURE_DEST", destination)
            .env("COCKPIT_FIXTURE_STAGE_ROOT", stage)
            .env("COCKPIT_FIXTURE_ARCH", arch)
            .env_remove("HOME")
            .env_remove("LOCALAPPDATA")
            .output()
            .unwrap()
    };
    let output = invoke(&archive, &checksum, &destination, &stage, "x64");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(destination.join("cockpit.exe").is_file());
    assert!(fs::read_dir(&stage).unwrap().next().is_none());
    for (name, supplied_checksum, arch) in [
        ("checksum", "00".repeat(32), "x64"),
        ("architecture", checksum.clone(), "mips64"),
    ] {
        let d = root.join(format!("{name} destination"));
        let s = root.join(format!("{name} stage"));
        assert!(
            !invoke(&archive, &supplied_checksum, &d, &s, arch)
                .status
                .success()
        );
        assert!(!d.join("cockpit.exe").exists());
        assert!(fs::read_dir(s).unwrap().next().is_none());
    }
    let corrupt = root.join("corrupt archive.tar.gz");
    fs::write(&corrupt, "not an archive").unwrap();
    let corrupt_digest = Command::new(shell)
        .args(["-NoProfile", "-Command"])
        .arg(format!(
            "(Get-FileHash -LiteralPath '{}' -Algorithm SHA256).Hash.ToLowerInvariant()",
            corrupt.display()
        ))
        .output()
        .unwrap();
    let corrupt_sum = String::from_utf8(corrupt_digest.stdout).unwrap();
    let s = root.join("extract stage");
    assert!(
        !invoke(
            &corrupt,
            corrupt_sum.trim(),
            &root.join("extract destination"),
            &s,
            "x64"
        )
        .status
        .success()
    );
    assert!(fs::read_dir(s).unwrap().next().is_none());
    let existing = root.join("existing destination");
    fs::create_dir_all(&existing).unwrap();
    fs::write(existing.join("cockpit.exe"), "original").unwrap();
    let s = root.join("existing stage");
    assert!(
        !invoke(&archive, &checksum, &existing, &s, "x64")
            .status
            .success()
    );
    assert_eq!(
        fs::read_to_string(existing.join("cockpit.exe")).unwrap(),
        "original"
    );
    assert!(fs::read_dir(s).unwrap().next().is_none());
    let second = payload.join("nested");
    fs::create_dir_all(&second).unwrap();
    fs::write(second.join("cockpit.exe"), "second").unwrap();
    let multiple = root.join("multiple.tar.gz");
    assert!(
        Command::new("tar")
            .args(["-czf"])
            .arg(&multiple)
            .arg("-C")
            .arg(&payload)
            .arg(".")
            .status()
            .unwrap()
            .success()
    );
    let multiple_digest = Command::new(shell)
        .args(["-NoProfile", "-Command"])
        .arg(format!(
            "(Get-FileHash -LiteralPath '{}' -Algorithm SHA256).Hash.ToLowerInvariant()",
            multiple.display()
        ))
        .output()
        .unwrap();
    let multiple_sum = String::from_utf8(multiple_digest.stdout).unwrap();
    let s = root.join("multiple stage");
    assert!(
        !invoke(
            &multiple,
            multiple_sum.trim(),
            &root.join("multiple destination"),
            &s,
            "x64"
        )
        .status
        .success()
    );
    assert!(fs::read_dir(s).unwrap().next().is_none());
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
