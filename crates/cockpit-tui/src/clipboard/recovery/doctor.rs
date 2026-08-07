//! Metadata-only `/doctor` reporting for the clipboard recovery artifact.
//!
//! Every line here comes from [`super::artifact_status`], which never opens
//! the artifact for reading — only directory listing and per-entry
//! `stat`/security metadata. No line in this module's output can ever
//! contain clipboard content: there is no code path from a content byte to
//! any `String` returned here.

use super::{ArtifactStatus, ClipboardRecovery};

/// Render the clipboard-recovery `/doctor` section. `dir` is the resolved
/// recovery directory (see [`super::recovery_dir_path`]); passed in so
/// tests can point this at a scratch directory instead of the real one.
pub fn doctor_lines(mode: ClipboardRecovery, dir: &std::path::Path) -> (Vec<String>, bool) {
    if mode == ClipboardRecovery::Off {
        return (vec!["clipboard recovery: off (no artifact ever written)".to_string()], false);
    }

    match super::artifact_status(dir) {
        Ok(status) => (render(&status, dir), false),
        Err(error) => (
            vec![format!("clipboard recovery: status unavailable ({error})")],
            true,
        ),
    }
}

fn render(status: &ArtifactStatus, dir: &std::path::Path) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("clipboard recovery: private-file".to_string());
    lines.push(format!("  directory: {}", dir.display()));
    if status.present {
        let age = status.age.unwrap_or_default();
        let size = status.size_bytes.unwrap_or_default();
        lines.push(format!(
            "  artifact: present, {size} bytes, age {}s{}",
            age.as_secs(),
            if status.expired { " (expired)" } else { "" }
        ));
    } else {
        lines.push("  artifact: none".to_string());
    }
    if status.unsafe_entries_reported > 0 {
        lines.push(format!(
            "  unsafe entries ignored: {} (never opened or deleted)",
            status.unsafe_entries_reported
        ));
    }
    lines
}
