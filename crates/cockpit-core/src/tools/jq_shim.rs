use std::collections::HashMap;
use std::path::Path;

use crate::tools::shell_sandbox::{ExtraSandboxPath, SandboxPathAccess};

const JQ_SHIM_KIND: &str = "jq-shim";
const CURRENT_EXE_KIND: &str = "cockpit-current-exe-dir";

pub(crate) fn prepare_host_jq_shim(
    session: &crate::session::Session,
    env: &mut HashMap<String, String>,
) -> Vec<ExtraSandboxPath> {
    if jq_on_path(effective_path(env).as_deref()) {
        return Vec::new();
    }

    match prepare_host_jq_shim_inner(session, env) {
        Ok(paths) => paths,
        Err(e) => {
            tracing::warn!(error = %e, "preparing bundled jq host shim failed");
            Vec::new()
        }
    }
}

fn prepare_host_jq_shim_inner(
    session: &crate::session::Session,
    env: &mut HashMap<String, String>,
) -> anyhow::Result<Vec<ExtraSandboxPath>> {
    let Some(shim_dir) = session.host_shim_dir() else {
        return Ok(Vec::new());
    };
    let current_exe = std::env::current_exe()?;
    prepare_host_jq_shim_for_paths(env, &shim_dir, &current_exe)
}

fn prepare_host_jq_shim_for_paths(
    env: &mut HashMap<String, String>,
    shim_dir: &Path,
    current_exe: &Path,
) -> anyhow::Result<Vec<ExtraSandboxPath>> {
    if jq_on_path(effective_path(env).as_deref()) {
        return Ok(Vec::new());
    }

    install_jq_shim(shim_dir, current_exe)?;
    prepend_path(env, shim_dir)?;

    let mut paths = Vec::new();
    paths.push(ExtraSandboxPath {
        kind: JQ_SHIM_KIND.to_string(),
        path: shim_dir.to_path_buf(),
        access: SandboxPathAccess::Read,
    });
    if let Some(exe_dir) = current_exe.parent() {
        paths.push(ExtraSandboxPath {
            kind: CURRENT_EXE_KIND.to_string(),
            path: exe_dir.to_path_buf(),
            access: SandboxPathAccess::Read,
        });
    }
    Ok(paths)
}

fn install_jq_shim(shim_dir: &Path, current_exe: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(shim_dir)?;
    let shim = shim_dir.join(jq_shim_name());
    if shim.exists() {
        std::fs::remove_file(&shim)?;
    }

    // The host jaq/container jq split is deliberate: the host shim treats jaq
    // as jq-equivalent, while container images keep real jq. Revisit if real
    // divergences surface. Parity watchpoints include NaN rendering, division
    // by zero, float indices, cross-file slurp grouping, and negative limits.
    link_or_copy(current_exe, &shim)
}

#[cfg(unix)]
fn link_or_copy(current_exe: &Path, shim: &Path) -> anyhow::Result<()> {
    Ok(std::os::unix::fs::symlink(current_exe, shim).or_else(|_| {
        std::fs::hard_link(current_exe, shim)
            .or_else(|_| std::fs::copy(current_exe, shim).map(|_| ()))
    })?)
}

#[cfg(not(unix))]
fn link_or_copy(current_exe: &Path, shim: &Path) -> anyhow::Result<()> {
    std::fs::hard_link(current_exe, shim)
        .or_else(|_| std::fs::copy(current_exe, shim).map(|_| ()))
        .map_err(Into::into)
}

fn prepend_path(env: &mut HashMap<String, String>, shim_dir: &Path) -> anyhow::Result<()> {
    let base_path = effective_path(env).unwrap_or_default();
    let paths = std::iter::once(shim_dir.to_path_buf()).chain(std::env::split_paths(&base_path));
    let path = std::env::join_paths(paths)?;
    env.insert("PATH".to_string(), path.to_string_lossy().into_owned());
    Ok(())
}

fn effective_path(env: &HashMap<String, String>) -> Option<String> {
    env.get("PATH")
        .cloned()
        .or_else(|| std::env::var("PATH").ok())
}

fn jq_on_path(path: Option<&str>) -> bool {
    let Some(path) = path else {
        return false;
    };
    std::env::split_paths(path).any(|dir| {
        jq_candidate_names()
            .iter()
            .any(|name| is_executable(&dir.join(name)))
    })
}

fn jq_candidate_names() -> &'static [&'static str] {
    #[cfg(windows)]
    {
        &["jq.exe", "jq.cmd", "jq.bat", "jq"]
    }
    #[cfg(not(windows))]
    {
        &["jq"]
    }
}

fn jq_shim_name() -> &'static str {
    #[cfg(windows)]
    {
        "jq.exe"
    }
    #[cfg(not(windows))]
    {
        "jq"
    }
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.is_file()
        && path
            .metadata()
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_existing_jq_on_session_path() {
        let temp = tempfile::tempdir().unwrap();
        let jq = temp.path().join(jq_shim_name());
        std::fs::write(&jq, "").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&jq, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        assert!(jq_on_path(Some(temp.path().to_str().unwrap())));
    }

    #[test]
    fn prepends_shim_path_and_marks_sandbox_allowlist_kind() {
        let temp = tempfile::tempdir().unwrap();
        let shim_dir = temp.path().join("data/cockpit/session-shims/session/bin");
        let exe = temp.path().join("cockpit");
        std::fs::write(&exe, "").unwrap();

        install_jq_shim(&shim_dir, &exe).unwrap();
        let mut env = HashMap::from([("PATH".to_string(), "/usr/bin".to_string())]);
        prepend_path(&mut env, &shim_dir).unwrap();
        let paths = [
            ExtraSandboxPath {
                kind: JQ_SHIM_KIND.to_string(),
                path: shim_dir.clone(),
                access: SandboxPathAccess::Read,
            },
            ExtraSandboxPath {
                kind: CURRENT_EXE_KIND.to_string(),
                path: exe.parent().unwrap().to_path_buf(),
                access: SandboxPathAccess::Read,
            },
        ];

        let first = std::env::split_paths(env.get("PATH").unwrap())
            .next()
            .unwrap();
        assert_eq!(first, shim_dir);
        assert!(shim_dir.join(jq_shim_name()).exists());
        assert!(
            paths
                .iter()
                .any(|path| path.kind == JQ_SHIM_KIND && path.path == shim_dir)
        );
    }

    #[test]
    fn prepare_does_not_create_shim_when_jq_exists_on_path() {
        let temp = tempfile::tempdir().unwrap();
        let path_dir = temp.path().join("path-bin");
        std::fs::create_dir_all(&path_dir).unwrap();
        let jq = path_dir.join(jq_shim_name());
        std::fs::write(&jq, "").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&jq, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let shim_dir = temp.path().join("data/cockpit/session-shims/session/bin");
        let exe = temp.path().join("cockpit");
        std::fs::write(&exe, "").unwrap();
        let original_path = path_dir.to_string_lossy().to_string();
        let mut env = HashMap::from([("PATH".to_string(), original_path.clone())]);

        let paths = prepare_host_jq_shim_for_paths(&mut env, &shim_dir, &exe).unwrap();

        assert!(paths.is_empty());
        assert_eq!(env.get("PATH"), Some(&original_path));
        assert!(!shim_dir.exists());
    }

    #[test]
    fn prepare_creates_shim_when_jq_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let path_dir = temp.path().join("path-bin");
        std::fs::create_dir_all(&path_dir).unwrap();
        let shim_dir = temp.path().join("data/cockpit/session-shims/session/bin");
        let exe = temp.path().join("cockpit");
        std::fs::write(&exe, "").unwrap();
        let mut env = HashMap::from([("PATH".to_string(), path_dir.to_string_lossy().to_string())]);

        let paths = prepare_host_jq_shim_for_paths(&mut env, &shim_dir, &exe).unwrap();

        let first = std::env::split_paths(env.get("PATH").unwrap())
            .next()
            .unwrap();
        assert_eq!(first, shim_dir);
        assert!(shim_dir.join(jq_shim_name()).exists());
        assert!(
            paths
                .iter()
                .any(|path| path.kind == JQ_SHIM_KIND && path.path == shim_dir)
        );
        assert!(paths.iter().any(|path| path.kind == CURRENT_EXE_KIND));
    }
}
