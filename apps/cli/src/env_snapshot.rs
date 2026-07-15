use std::collections::{BTreeSet, HashMap};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

pub use crate::daemon::proto::{
    EnvDiffSummary, EnvDriftPolicy, EnvSnapshotMeta, EnvSnapshotSource, EnvSnapshotWire,
};

#[derive(Debug, Clone)]
pub struct EnvSnapshot {
    source: EnvSnapshotSource,
    vars: HashMap<String, String>,
    digest: String,
}

impl EnvSnapshot {
    pub fn new(source: EnvSnapshotSource, vars: HashMap<String, String>) -> Self {
        let digest = digest_env(&vars);
        Self {
            source,
            vars,
            digest,
        }
    }

    pub fn from_process(source: EnvSnapshotSource) -> Self {
        Self::new(source, std::env::vars().collect())
    }

    pub fn from_wire(wire: EnvSnapshotWire) -> Self {
        let snapshot = Self::new(wire.source, wire.vars);
        if snapshot.digest != wire.digest {
            tracing::debug!(
                sent = %wire.digest,
                computed = %snapshot.digest,
                "environment snapshot digest mismatch; using computed digest"
            );
        }
        snapshot
    }

    pub fn to_wire(&self) -> EnvSnapshotWire {
        EnvSnapshotWire {
            source: self.source,
            digest: self.digest.clone(),
            vars: self.vars.clone(),
        }
    }

    pub fn meta(&self) -> EnvSnapshotMeta {
        EnvSnapshotMeta {
            source: self.source,
            digest: self.digest.clone(),
            key_count: self.vars.len(),
            path_entry_count: path_entries(self.vars.get("PATH")).len(),
        }
    }

    pub fn vars(&self) -> &HashMap<String, String> {
        &self.vars
    }

    pub fn into_vars(self) -> HashMap<String, String> {
        self.vars
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

pub fn diff_summary(baseline: &EnvSnapshot, candidate: &EnvSnapshot) -> Option<EnvDiffSummary> {
    if baseline.digest() == candidate.digest() {
        return None;
    }
    let baseline_keys: BTreeSet<&str> = baseline.vars.keys().map(String::as_str).collect();
    let candidate_keys: BTreeSet<&str> = candidate.vars.keys().map(String::as_str).collect();
    let added_keys = candidate_keys.difference(&baseline_keys).count();
    let removed_keys = baseline_keys.difference(&candidate_keys).count();
    let mut changed_keys = 0usize;
    let mut changed_secret_keys = Vec::new();
    for key in baseline_keys.intersection(&candidate_keys) {
        if baseline.vars.get(*key) != candidate.vars.get(*key) {
            changed_keys += 1;
            if crate::redact::env_scrub_patterns(key) {
                changed_secret_keys.push((*key).to_string());
            }
        }
    }
    let baseline_path: BTreeSet<String> = path_entries(baseline.vars.get("PATH"))
        .into_iter()
        .collect();
    let candidate_path: BTreeSet<String> = path_entries(candidate.vars.get("PATH"))
        .into_iter()
        .collect();
    Some(EnvDiffSummary {
        baseline_digest: baseline.digest.clone(),
        candidate_digest: candidate.digest.clone(),
        added_keys,
        removed_keys,
        changed_keys,
        changed_secret_keys,
        path_added: candidate_path.difference(&baseline_path).cloned().collect(),
        path_removed: baseline_path.difference(&candidate_path).cloned().collect(),
    })
}

pub const SHELL_ENV_BEGIN: &str = "__COCKPIT_ENV_BEGIN__";
pub const SHELL_ENV_END: &str = "__COCKPIT_ENV_END__";

pub fn parse_framed_nul_env(output: &[u8]) -> Result<HashMap<String, String>, String> {
    let begin = SHELL_ENV_BEGIN.as_bytes();
    let end = SHELL_ENV_END.as_bytes();
    let begin_at = find_subslice(output, begin).ok_or("missing environment begin sentinel")?;
    if !output[..begin_at].iter().all(u8::is_ascii_whitespace) {
        return Err("shell emitted output before environment frame".to_string());
    }
    let payload_start = begin_at + begin.len();
    let end_at = find_subslice(&output[payload_start..], end)
        .map(|idx| payload_start + idx)
        .ok_or("missing environment end sentinel")?;
    if !output[end_at + end.len()..]
        .iter()
        .all(u8::is_ascii_whitespace)
    {
        return Err("shell emitted output after environment frame".to_string());
    }
    let payload = trim_ascii_ws(&output[payload_start..end_at]);
    let mut vars = HashMap::new();
    for raw in payload.split(|b| *b == 0) {
        if raw.is_empty() {
            continue;
        }
        let Some(eq) = raw.iter().position(|b| *b == b'=') else {
            return Err("environment entry did not contain '='".to_string());
        };
        let key = std::str::from_utf8(&raw[..eq])
            .map_err(|_| "environment key was not utf-8")?
            .to_string();
        let value = std::str::from_utf8(&raw[eq + 1..])
            .map_err(|_| "environment value was not utf-8")?
            .to_string();
        vars.insert(key, value);
    }
    Ok(vars)
}

type CaptureResult = (EnvSnapshot, Option<String>);

static TUI_SHELL_ENV_CACHE: OnceLock<CaptureResult> = OnceLock::new();

pub fn capture_tui_shell_env() -> CaptureResult {
    capture_tui_shell_env_cached(&TUI_SHELL_ENV_CACHE, capture_tui_shell_env_uncached)
}

fn capture_tui_shell_env_cached(
    cache: &OnceLock<CaptureResult>,
    capture: impl FnOnce() -> CaptureResult,
) -> CaptureResult {
    cache.get_or_init(capture).clone()
}

fn capture_tui_shell_env_uncached() -> CaptureResult {
    #[cfg(windows)]
    {
        return (
            EnvSnapshot::from_process(EnvSnapshotSource::TuiProcessFallback),
            Some("using process environment on Windows".to_string()),
        );
    }

    #[cfg(not(windows))]
    {
        match capture_shell_env_unix() {
            Ok(vars) => (EnvSnapshot::new(EnvSnapshotSource::TuiShell, vars), None),
            Err(reason) => (
                EnvSnapshot::from_process(EnvSnapshotSource::TuiProcessFallback),
                Some(format!(
                    "could not capture login shell environment; using process environment ({reason})"
                )),
            ),
        }
    }
}

#[cfg(not(windows))]
fn capture_shell_env_unix() -> Result<HashMap<String, String>, String> {
    let shell = std::env::var_os("SHELL").ok_or("$SHELL is unset")?;
    let shell_path = PathBuf::from(shell);
    let shell_name = shell_path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("sh")
        .to_ascii_lowercase();
    let script = format!(
        "printf '\\n{}\\n'; env -0; printf '\\n{}\\n'",
        SHELL_ENV_BEGIN, SHELL_ENV_END
    );
    let mut command = std::process::Command::new(&shell_path);
    if shell_name.contains("fish") {
        command.args(["--login", "--interactive", "--command", &script]);
    } else {
        command.arg("-lic").arg(&script);
    }
    detach_command_from_terminal(&mut command);
    let output = command
        .output()
        .map_err(|e| format!("failed to run {}: {e}", shell_path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} exited with {}",
            shell_path.display(),
            output.status
        ));
    }
    parse_framed_nul_env(&output.stdout)
}

#[cfg(not(windows))]
fn detach_command_from_terminal(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;

    // SAFETY: the child runs only `setsid` before exec, which is async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

pub fn user_runtime_read_paths_from_path(path_value: Option<&str>) -> Vec<PathBuf> {
    let Some(path_value) = path_value else {
        return Vec::new();
    };
    let home = std::env::var_os("HOME").map(PathBuf::from);
    path_value
        .split(':')
        .filter_map(|entry| runtime_manager_root(entry, home.as_deref()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn runtime_manager_root(entry: &str, home: Option<&Path>) -> Option<PathBuf> {
    let path = Path::new(entry);
    let home = home?;
    let stripped = path.strip_prefix(home).ok()?;
    let first = stripped.components().next()?.as_os_str().to_string_lossy();
    if matches!(
        first.as_ref(),
        ".nvm" | ".fnm" | ".asdf" | ".mise" | ".rbenv" | ".local" | ".pnpm"
    ) {
        return Some(home.join(first.as_ref()));
    }
    None
}

fn path_entries(value: Option<&String>) -> Vec<String> {
    value
        .map(|path| {
            path.split(':')
                .filter(|entry| !entry.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn digest_env(vars: &HashMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    let mut entries: Vec<_> = vars.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    for (key, value) in entries {
        hasher.update(key.as_bytes());
        hasher.update([0]);
        hasher.update(value.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn trim_ascii_ws(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|idx| idx + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn digest_is_stable_regardless_of_map_order() {
        let a = EnvSnapshot::new(
            EnvSnapshotSource::ExplicitCli,
            HashMap::from([("B".into(), "2".into()), ("A".into(), "1".into())]),
        );
        let b = EnvSnapshot::new(
            EnvSnapshotSource::ExplicitCli,
            HashMap::from([("A".into(), "1".into()), ("B".into(), "2".into())]),
        );
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn parser_accepts_strict_framed_nul_payload() {
        let raw = format!("\n{SHELL_ENV_BEGIN}\nA=1\0PATH=/bin:/usr/bin\0\n{SHELL_ENV_END}\n");
        let parsed = parse_framed_nul_env(raw.as_bytes()).unwrap();
        assert_eq!(parsed.get("A").map(String::as_str), Some("1"));
        assert_eq!(
            parsed.get("PATH").map(String::as_str),
            Some("/bin:/usr/bin")
        );
    }

    #[test]
    fn parser_rejects_shell_noise_outside_frame() {
        let raw = format!("hello\n{SHELL_ENV_BEGIN}\nA=1\0\n{SHELL_ENV_END}\n");
        assert!(parse_framed_nul_env(raw.as_bytes()).is_err());
    }

    #[test]
    fn capture_cache_reuses_successful_snapshot() {
        let cache = OnceLock::new();
        let calls = AtomicUsize::new(0);

        for _ in 0..3 {
            let (snapshot, diagnostic) = capture_tui_shell_env_cached(&cache, || {
                calls.fetch_add(1, Ordering::SeqCst);
                (
                    EnvSnapshot::new(
                        EnvSnapshotSource::TuiShell,
                        HashMap::from([("PATH".to_string(), "/bin".to_string())]),
                    ),
                    None,
                )
            });
            assert_eq!(snapshot.meta().source, EnvSnapshotSource::TuiShell);
            assert!(diagnostic.is_none());
        }

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn capture_cache_reuses_fallback_snapshot() {
        let cache = OnceLock::new();
        let calls = AtomicUsize::new(0);

        for _ in 0..3 {
            let (snapshot, diagnostic) = capture_tui_shell_env_cached(&cache, || {
                calls.fetch_add(1, Ordering::SeqCst);
                (
                    EnvSnapshot::new(
                        EnvSnapshotSource::TuiProcessFallback,
                        HashMap::from([("PATH".to_string(), "/usr/bin".to_string())]),
                    ),
                    Some("could not capture login shell environment".to_string()),
                )
            });
            assert_eq!(
                snapshot.meta().source,
                EnvSnapshotSource::TuiProcessFallback
            );
            assert!(diagnostic.is_some());
        }

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detached_shell_env_command_runs_in_new_session() {
        let parent_sid = proc_stat_session_id(std::process::id()).unwrap();
        let mut command = std::process::Command::new("/bin/sh");
        command.arg("-c").arg("cat /proc/self/stat");
        detach_command_from_terminal(&mut command);

        let output = command.output().unwrap();
        assert!(output.status.success());
        let stat = String::from_utf8(output.stdout).unwrap();
        let child_sid = parse_proc_stat_session_id(&stat).unwrap();

        assert_ne!(child_sid, parent_sid);
    }

    #[cfg(target_os = "linux")]
    fn proc_stat_session_id(pid: u32) -> Result<i32, String> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|e| format!("failed to read proc stat: {e}"))?;
        parse_proc_stat_session_id(&stat)
    }

    #[cfg(target_os = "linux")]
    fn parse_proc_stat_session_id(stat: &str) -> Result<i32, String> {
        let after_comm = stat
            .rsplit_once(") ")
            .ok_or_else(|| "missing proc stat comm terminator".to_string())?
            .1;
        let fields: Vec<_> = after_comm.split_whitespace().collect();
        fields
            .get(3)
            .ok_or_else(|| "missing session field".to_string())?
            .parse()
            .map_err(|e| format!("invalid session field: {e}"))
    }

    #[test]
    fn diff_summary_does_not_include_secret_values() {
        let baseline = EnvSnapshot::new(
            EnvSnapshotSource::DaemonStart,
            HashMap::from([
                ("PATH".into(), "/usr/bin".into()),
                ("OPENAI_API_KEY".into(), "old".into()),
            ]),
        );
        let candidate = EnvSnapshot::new(
            EnvSnapshotSource::TuiShell,
            HashMap::from([
                (
                    "PATH".into(),
                    "/usr/bin:/home/me/.nvm/versions/node/v20/bin".into(),
                ),
                ("OPENAI_API_KEY".into(), "new-secret-value".into()),
            ]),
        );
        let summary = diff_summary(&baseline, &candidate).unwrap();
        assert_eq!(summary.changed_secret_keys, vec!["OPENAI_API_KEY"]);
        let serialized = serde_json::to_string(&summary).unwrap();
        assert!(!serialized.contains("new-secret-value"));
    }
}
