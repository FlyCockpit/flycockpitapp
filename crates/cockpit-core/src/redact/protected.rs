use std::collections::HashMap;
use std::path::Path;

/// Filesystem paths that must never enter the redaction matcher.
#[derive(Clone, Debug, Default)]
pub(crate) struct ProtectedPaths {
    paths: Vec<String>,
}

impl ProtectedPaths {
    pub(crate) fn from_session(cwd: &Path, env: &HashMap<String, String>) -> Self {
        let mut paths = Vec::new();
        collect_path_and_ancestors(cwd, &mut paths);
        if let Some(root) = crate::git::find_worktree_root(cwd) {
            collect_path_and_ancestors(&root, &mut paths);
        }
        for key in ["HOME", "TMPDIR"] {
            if let Some(value) = env.get(key) {
                collect_path_and_ancestors(Path::new(value), &mut paths);
            }
        }
        Self::from_persisted(paths)
    }

    pub(crate) fn from_persisted(paths: Vec<String>) -> Self {
        let mut paths: Vec<String> = paths.into_iter().filter(|path| !path.is_empty()).collect();
        paths.sort();
        paths.dedup();
        Self { paths }
    }

    pub(crate) fn union(&self, other: &Self) -> Self {
        let mut paths = self.paths.clone();
        paths.extend(other.paths.iter().cloned());
        Self::from_persisted(paths)
    }

    pub(crate) fn to_persisted(&self) -> Vec<String> {
        self.paths.clone()
    }

    pub(crate) fn contains_value(&self, value: &str) -> bool {
        !value.is_empty() && self.paths.iter().any(|path| path.contains(value))
    }
}

pub(crate) fn is_existing_absolute_path(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute() && std::fs::symlink_metadata(path).is_ok()
}

fn collect_path_and_ancestors(path: &Path, out: &mut Vec<String>) {
    for ancestor in path.ancestors() {
        let value = ancestor.to_string_lossy().into_owned();
        if !value.is_empty() {
            out.push(value);
        }
    }
}
