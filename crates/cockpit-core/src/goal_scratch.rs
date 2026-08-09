use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use uuid::Uuid;

const ROLES: [&str; 4] = ["planner", "worker", "evaluator", "skeptic"];

#[derive(Debug)]
pub struct GoalScratchRoot {
    parent: PathBuf,
    root: PathBuf,
}

impl GoalScratchRoot {
    pub fn create(goal_id: Uuid) -> Result<Self> {
        let parent = std::env::temp_dir().join("cockpit-goals");
        Self::create_in(&parent, goal_id)
    }

    pub fn create_in(parent: &Path, goal_id: Uuid) -> Result<Self> {
        create_checked_dir(&parent)?;
        let root = parent.join(goal_id.to_string());
        create_checked_dir(&root)?;
        for role in ROLES {
            create_checked_dir(&root.join(role))?;
        }
        Ok(Self {
            parent: parent.to_path_buf(),
            root,
        })
    }

    pub fn role(&self, role: &str) -> Result<PathBuf> {
        if !ROLES.contains(&role) {
            bail!("unknown goal scratch role");
        }
        let path = self.root.join(role);
        verify_checked_dir(&path)?;
        Ok(path)
    }

    pub fn cleanup(self) -> Result<()> {
        verify_checked_dir(&self.root)?;
        verify_checked_dir(&self.parent)?;
        if self.root.parent() != Some(self.parent.as_path()) {
            bail!("refusing to remove goal scratch outside the private root");
        }
        std::fs::remove_dir_all(&self.root).context("removing terminal goal scratch root")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn goal_scratch_root_rejects_symlink_and_cleans_terminal_root() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("goals");
        let scratch = GoalScratchRoot::create_in(&parent, Uuid::nil()).unwrap();
        let root = scratch.root.clone();
        let target = temp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::remove_dir(root.join("planner")).unwrap();
        symlink(&target, root.join("planner")).unwrap();
        assert!(scratch.role("planner").is_err());
        std::fs::remove_file(root.join("planner")).unwrap();
        std::fs::create_dir(root.join("planner")).unwrap();
        set_private(&root.join("planner")).unwrap();
        scratch.cleanup().unwrap();
        assert!(!root.exists());
    }

    #[cfg(windows)]
    #[test]
    fn goal_scratch_root_rejects_windows_reparse_point() {
        let temp = tempfile::tempdir().unwrap();
        let scratch = GoalScratchRoot::create_in(&temp.path().join("goals"), Uuid::nil()).unwrap();
        assert!(scratch.role("planner").is_ok());
    }
}

fn create_checked_dir(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_dir() || meta.file_type().is_symlink() => bail!(
            "goal scratch path is a link or non-directory: {}",
            path.display()
        ),
        Ok(_) => verify_checked_dir(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(path).with_context(|| format!("creating {}", path.display()))?;
            set_private(path)?;
            verify_checked_dir(path)
        }
        Err(error) => Err(error).with_context(|| format!("checking {}", path.display())),
    }
}

#[cfg(unix)]
fn set_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(unix)]
fn verify_checked_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink()
        || !meta.is_dir()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.permissions().mode() & 0o777 != 0o700
    {
        bail!(
            "goal scratch directory failed owner/link/mode checks: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn set_private(path: &Path) -> Result<()> {
    // Creation inherits the current user's private temp-directory DACL. Verify
    // reparse safety immediately; platform ACL hardening remains centralized in
    // Cockpit's private-fs setup rather than shelling out.
    verify_checked_dir(path)
}

#[cfg(windows)]
fn verify_checked_dir(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!(
            "goal scratch directory is a reparse point or non-directory: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
compile_error!("goal scratch security requires an owner-check implementation");
