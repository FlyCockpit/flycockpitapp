//! Operating-system probe for the system-prompt injection (GOALS §17g).
//!
//! Returns a short human-readable OS+version string suitable for the
//! cached system block. The string is generated once per process via
//! the per-platform path below; we don't bother caching it ourselves
//! because callers run it at agent-construction time (rare) rather
//! than per-turn.

/// One-line OS identification for the system prompt. Shape:
///
/// - Linux / macOS: `uname -srm` output (e.g. `Linux 6.8.0 x86_64`,
///   `Darwin 24.0.0 arm64`).
/// - Windows: `cmd /C ver` output (e.g. `Microsoft Windows [Version
///   10.0.22631.4317]`).
/// - Any failure path: `std::env::consts::OS` (e.g. `linux`).
pub fn os_string() -> String {
    #[cfg(unix)]
    {
        match std::process::Command::new("uname").arg("-srm").output() {
            Ok(out) if out.status.success() => {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if s.is_empty() {
                    std::env::consts::OS.to_string()
                } else {
                    s
                }
            }
            _ => std::env::consts::OS.to_string(),
        }
    }
    #[cfg(windows)]
    {
        match std::process::Command::new("cmd")
            .args(["/C", "ver"])
            .output()
        {
            Ok(out) if out.status.success() => {
                let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if s.is_empty() {
                    "Windows".to_string()
                } else {
                    s
                }
            }
            _ => "Windows".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_string_nonempty() {
        let s = os_string();
        assert!(!s.is_empty());
    }
}
