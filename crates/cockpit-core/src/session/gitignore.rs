use super::*;

impl Session {
    /// The session-scoped gitignore read-allowlist globs added via the
    /// approval flow's "Approve for this session" choice
    /// (implementation note). Cloned out so the caller can
    /// union it with the persisted per-layer config without holding the lock.
    pub fn gitignore_session_allow(&self) -> Vec<String> {
        self.gitignore_session_allow.lock().unwrap().clone()
    }

    /// Add `glob` to the session allowlist (idempotent — a duplicate is
    /// ignored). Called when the user approves a gitignored read "for this
    /// session" (implementation note).
    pub fn add_gitignore_session_allow(&self, glob: impl Into<String>) {
        let glob = glob.into();
        let mut set = self.gitignore_session_allow.lock().unwrap();
        if !set.contains(&glob) {
            set.push(glob);
        }
    }

    /// Whether `path` (a resolved target string) was rejected for a gitignored
    /// read earlier this session (implementation note).
    pub fn gitignore_rejected(&self, path: &str) -> bool {
        self.gitignore_session_reject.lock().unwrap().contains(path)
    }

    /// Remember that the user declined a gitignored read of `path` (a resolved
    /// target string) so a retry gets the same refusal with no re-prompt.
    pub fn remember_gitignore_reject(&self, path: impl Into<String>) {
        self.gitignore_session_reject
            .lock()
            .unwrap()
            .insert(path.into());
    }
}
