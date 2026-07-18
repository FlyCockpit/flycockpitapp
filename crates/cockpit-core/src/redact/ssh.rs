use super::*;

/// Filenames in the SSH dir that are never private keys and are skipped
/// without reading their content: public keys, the known-hosts cache, the
/// authorized-keys list, and the SSH client `config`. The content check
/// alone already excludes these (none carries a PEM private-key header), but
/// skipping by name avoids reading files we know aren't keys.
fn is_ssh_non_key_name(name: &str) -> bool {
    name.ends_with(".pub")
        || name.starts_with("known_hosts")
        || name == "authorized_keys"
        || name == "config"
}

/// `true` when `content` begins (after leading whitespace) with a PEM
/// private-key header.
pub(super) fn is_pem_private_key(content: &str) -> bool {
    let trimmed = content.trim_start();
    PEM_PRIVATE_KEY_HEADERS
        .iter()
        .any(|h| trimmed.starts_with(h))
}

/// Collect `(value, origin)` candidates for every private SSH key under the
/// configured dir (`ssh_key_dir` override, else the user's `~/.ssh`). A
/// missing/unreadable dir is skipped silently (no error). For each regular
/// file (symlinks followed to their target) whose content is a PEM private
/// key, the trimmed full key text is registered with origin `$ssh:<file>`;
/// a newline-normalized (`\r\n`→`\n`) variant is added when it differs so a
/// CRLF/LF echo both match. The caller treats these as forced/non-prunable.
pub(super) fn collect_ssh_key_candidates(ssh_key_dir: Option<&Path>) -> Vec<(String, String)> {
    let dir = match ssh_key_dir {
        Some(d) => d.to_path_buf(),
        None => {
            let Some(home) = dirs::home_dir() else {
                return Vec::new();
            };
            home.join(".ssh")
        }
    };

    let Ok(read_dir) = std::fs::read_dir(&dir) else {
        // Missing / unreadable `~/.ssh` → skip silently.
        return Vec::new();
    };

    let mut out: Vec<(String, String)> = Vec::new();
    for entry in read_dir.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if is_ssh_non_key_name(&name) {
            continue;
        }
        // `fs::metadata` follows symlinks — we want the target's content if
        // it's a regular file (it's the key *material* being redacted).
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            // Binary / unreadable file: not a PEM key.
            continue;
        };
        if !is_pem_private_key(&content) {
            continue;
        }
        let origin = format!("$ssh:{name}");
        let trimmed = content.trim().to_string();
        if !trimmed.is_empty() {
            let normalized = trimmed.replace("\r\n", "\n");
            if normalized != trimmed {
                out.push((normalized.clone(), origin.clone()));
            }
            for line in normalized
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
            {
                out.push((line.to_string(), origin.clone()));
            }
            out.push((trimmed, origin));
        }
    }
    out
}
