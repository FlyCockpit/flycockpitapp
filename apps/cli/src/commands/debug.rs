use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tokio::io::AsyncReadExt as _;
use tokio::process::{ChildStdout, Command};

use crate::cli::{DebugCommand, FailedCallsArgs};
use crate::daemon::proto::{Request, Response};
use crate::daemon::{DaemonStatus, discover};
use crate::db::Db;
use crate::session::project_id_for;
use cockpit_client::DaemonClient;

const DIAGNOSTIC_FAILED_CALLS_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DIAGNOSTIC_FAILED_CALLS_BYTES: usize = 1024 * 1024;

pub async fn run(cmd: DebugCommand) -> Result<()> {
    match cmd {
        DebugCommand::FailedCalls(args) => failed_calls(args).await,
        DebugCommand::Paths => paths(),
        DebugCommand::Config => config(),
        DebugCommand::Context => context().await,
    }
}

fn cwd() -> Result<std::path::PathBuf> {
    std::env::current_dir().map_err(Into::into)
}

fn exists(path: &std::path::Path) -> &'static str {
    if path.exists() { "present" } else { "absent" }
}

fn paths() -> Result<()> {
    let cwd = cwd()?;
    let db = Db::default_path()?;
    let daemon = crate::daemon::DaemonPaths::resolve_canonical()?;
    let log = dirs::cache_dir()
        .ok_or_else(|| anyhow::anyhow!("could not locate cache directory"))?
        .join("cockpit/cockpit.log");
    println!("database: {} ({})", db.display(), exists(&db));
    println!("config directories (least to most specific):");
    for path in config_dirs_in_precedence(&cwd) {
        println!("  {} ({})", path.display(), exists(&path));
    }
    println!(
        "daemon socket: {} ({})",
        daemon.socket.display(),
        exists(&daemon.socket)
    );
    println!("log: {} ({})", log.display(), exists(&log));
    Ok(())
}

/// Show the locations Cockpit can load from, including locations that have
/// not been created yet. `config_file_paths_for_load` intentionally excludes
/// absent files, which is right for loading but unhelpful in a diagnostic.
fn config_dirs_in_precedence(cwd: &std::path::Path) -> Vec<std::path::PathBuf> {
    if let Some(path) = std::env::var_os(crate::config::config::dirs::COCKPIT_CONFIG_ENV)
        && !path.is_empty()
    {
        return vec![std::path::PathBuf::from(path)];
    }

    let mut paths: Vec<_> = crate::config::config::dirs::creatable_config_dirs()
        .into_iter()
        .map(|dir| dir.path)
        .collect();
    let cwd_scoped = crate::config::config::dirs::cwd_scoped_creatable_dirs(cwd);
    if let Some(local) = cwd_scoped
        .iter()
        .find(|dir| dir.kind == crate::config::config::dirs::ConfigDirKind::MachineLocal)
    {
        paths.push(local.path.clone());
    }

    paths.extend(
        crate::config::config::dirs::walk_up_to_stops(cwd)
            .into_iter()
            .rev()
            .map(|dir| dir.join(".cockpit")),
    );
    paths
}

fn redact_config(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let header_value = map.contains_key("name") && map.contains_key("value");
            for (key, value) in map {
                let lower = key.to_ascii_lowercase();
                if lower.contains("secret")
                    || lower.contains("credential")
                    || lower.contains("token")
                    || lower.contains("api_key")
                    || lower == "key"
                    || lower == "auth"
                    || (header_value && lower == "value")
                {
                    *value = serde_json::Value::String("[redacted]".into());
                } else {
                    redact_config(value);
                }
            }
        }
        serde_json::Value::Array(values) => values.iter_mut().for_each(redact_config),
        _ => {}
    }
}

fn effective_config() -> Result<serde_json::Value> {
    let cwd = cwd()?;
    let mut value = serde_json::json!({
        "providers": crate::config::config::providers::ConfigDoc::load_effective(&cwd),
        "extended": crate::config::config::extended::load_for_cwd(&cwd),
    });
    redact_config(&mut value);
    Ok(value)
}

fn config() -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&effective_config()?)?);
    Ok(())
}

const CONTEXT_OUTPUT_LIMIT: usize = 16 * 1024;

async fn context() -> Result<()> {
    let cwd = cwd()?;
    let config = crate::config::config::extended::load_for_cwd(&cwd);
    let env = crate::env_snapshot::EnvSnapshot::from_process(
        crate::env_snapshot::EnvSnapshotSource::ExplicitCli,
    );
    let redact =
        crate::redact::RedactionTable::build_with_env_and_store(&config.redact, &cwd, env.vars())?;
    let mut rendered = format!(
        "System prompt:\n{}",
        crate::engine::builtin::default_chat_system_prompt(&cwd, "")
    );
    if let Some((path, guidance)) = crate::engine::builtin::load_agent_guidance(&cwd) {
        rendered.push_str("\n\nProject guidance (user-role prelude): ");
        rendered.push_str(&path.display().to_string());
        rendered.push('\n');
        rendered.push_str(&guidance);
    }
    let output = truncate_for_debug(&redact.scrub(&rendered), CONTEXT_OUTPUT_LIMIT);
    println!("assembled context (fresh-session baseline):\n{output}");
    Ok(())
}

fn truncate_for_debug(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let cut = text
        .char_indices()
        .take_while(|(index, _)| *index < limit)
        .map(|(index, ch)| index + ch.len_utf8())
        .last()
        .unwrap_or(0);
    format!("{}\n[truncated at {limit} bytes]", &text[..cut])
}

/// Non-secret projection of one failed/recovered tool-call row as returned by
/// the daemon's `list_failed_tool_calls` response. Mirrors the daemon-side
/// `failed_tool_call_json` shape. Carries tool inputs/outputs (never vault
/// secrets). `recovery_kind`/`recovery_stage` are the raw DB fields; the
/// daemon projection also sets `recovery_unknown` when the persisted recovery
/// kind/stage was not recognized by the producing binary (a newer/renamed/
/// downgraded build), which the CLI annotates so it is not mistaken for a
/// recognized recovery.
#[derive(Debug, Deserialize)]
struct FailedCallView {
    timestamp: i64,
    model: String,
    agent: String,
    session_id: String,
    tool: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    hard_fail: bool,
    #[serde(default)]
    shape_fingerprint: Option<String>,
    #[serde(default)]
    recovery_kind: Option<String>,
    #[serde(default)]
    recovery_stage: Option<String>,
    #[serde(default)]
    recovery_unknown: bool,
    #[serde(default)]
    original_input: serde_json::Value,
    #[serde(default)]
    wire_input: serde_json::Value,
    #[serde(default)]
    output: String,
}

/// `cockpit debug failed-calls` — see GOALS §12. Pulls recent rows where
/// the tool either hard-failed or fired a recovery and prints them in a
/// form designed for pattern-spotting (original arguments + brief
/// output snippet), so the user can decide which patterns are worth
/// turning into new repair-catalog entries.
async fn failed_calls(args: FailedCallsArgs) -> Result<()> {
    let project_id = args
        .project
        .as_ref()
        .map(|project| project_id_for(project.as_path()))
        .transpose()?;
    let since_epoch = Utc::now().timestamp() - (args.days as i64) * 86_400;
    let probe = discover().await;
    let calls_json = match probe.status {
        DaemonStatus::Running => {
            match list_failed_calls_from_running_daemon(
                &probe.paths.socket,
                since_epoch,
                args.tool.clone(),
                args.model.clone(),
                project_id.clone(),
                args.include_recovered,
                args.limit,
            )
            .await
            {
                Ok(calls_json) => calls_json,
                Err(error) => diagnostic_failed_calls_worker(
                    since_epoch,
                    args.tool.as_deref(),
                    args.model.as_deref(),
                    project_id.as_deref(),
                    args.include_recovered,
                    args.limit,
                )
                .await
                .with_context(|| {
                    format!(
                        "live daemon became unreachable ({error:#}); diagnostic worker also failed"
                    )
                })?,
            }
        }
        DaemonStatus::NotRunning | DaemonStatus::Stale => diagnostic_failed_calls_worker(
            since_epoch,
            args.tool.as_deref(),
            args.model.as_deref(),
            project_id.as_deref(),
            args.include_recovered,
            args.limit,
        )
        .await
        .context("reading failed tool calls via diagnostic worker")?,
        DaemonStatus::IncompatibleProtocol
        | DaemonStatus::LivePidSocketUnreachable
        | DaemonStatus::UnverifiedPid => {
            bail!(
                "cannot inspect failed calls while a shared daemon is live but unreachable; run `cockpit daemon status`"
            )
        }
    };

    if args.json {
        // NDJSON: re-emit each row as the daemon's projection (byte-identical
        // to the former direct-DB `--json` output, which used the same shape).
        let values: Vec<serde_json::Value> =
            serde_json::from_str(&calls_json).context("parsing failed tool calls")?;
        for value in &values {
            println!("{}", serde_json::to_string(value)?);
        }
        return Ok(());
    }

    let rows: Vec<FailedCallView> =
        serde_json::from_str(&calls_json).context("parsing failed tool calls")?;
    print!("{}", format_failed_calls(&rows, args.days));
    Ok(())
}

async fn list_failed_calls_from_running_daemon(
    socket: &std::path::Path,
    since_epoch: i64,
    tool: Option<String>,
    model: Option<String>,
    project_id: Option<String>,
    include_recovered: bool,
    limit: u32,
) -> Result<String> {
    let client = DaemonClient::connect(socket)
        .await
        .context("connecting to the running daemon")?;
    let Response::FailedToolCalls { calls_json } = client
        .request(Request::ListFailedToolCalls {
            since_epoch,
            tool,
            model,
            project_id,
            include_recovered,
            limit,
        })
        .await
        .context("requesting failed tool calls from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected failed tool call query: {error}"))?
    else {
        bail!("daemon returned unexpected response to failed tool call query");
    };
    Ok(calls_json)
}

async fn diagnostic_failed_calls_worker(
    since_epoch: i64,
    tool: Option<&str>,
    model: Option<&str>,
    project_id: Option<&str>,
    include_recovered: bool,
    limit: u32,
) -> Result<String> {
    let executable = std::env::current_exe().context("locating cockpit executable")?;
    let mut command = Command::new(executable);
    command
        .arg("daemon")
        .arg("diagnostic-failed-calls")
        .arg("--since-epoch")
        .arg(since_epoch.to_string())
        .arg("--limit")
        .arg(limit.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some(tool) = tool {
        command.arg("--tool").arg(tool);
    }
    if let Some(model) = model {
        command.arg("--model").arg(model);
    }
    if let Some(project_id) = project_id {
        command.arg("--project-id").arg(project_id);
    }
    if include_recovered {
        command.arg("--include-recovered");
    }

    let mut child = command
        .spawn()
        .context("starting diagnostic failed-calls worker")?;
    let stdout = child
        .stdout
        .take()
        .context("diagnostic failed-calls worker stdout was not captured")?;
    let completed = tokio::time::timeout(DIAGNOSTIC_FAILED_CALLS_TIMEOUT, async {
        tokio::try_join!(read_bounded_stdout(stdout), async {
            Ok::<_, anyhow::Error>(child.wait().await?)
        },)
    })
    .await;
    let (stdout, status) = match completed {
        Ok(result) => result?,
        Err(_) => {
            let _ = child.kill().await;
            anyhow::bail!("diagnostic failed-calls worker timed out")
        }
    };
    if !status.success() {
        anyhow::bail!("diagnostic failed-calls worker exited unsuccessfully")
    }
    String::from_utf8(stdout).context("parsing diagnostic failed-calls worker output")
}

async fn read_bounded_stdout(mut stdout: ChildStdout) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = stdout.read(&mut chunk).await?;
        if read == 0 {
            return Ok(output);
        }
        let new_len = output
            .len()
            .checked_add(read)
            .context("diagnostic failed-calls worker output length overflow")?;
        if new_len > MAX_DIAGNOSTIC_FAILED_CALLS_BYTES {
            anyhow::bail!("diagnostic failed-calls worker output exceeded its size limit")
        }
        output.extend_from_slice(&chunk[..read]);
    }
}

fn format_failed_calls(rows: &[FailedCallView], days: u32) -> String {
    if rows.is_empty() {
        return format!(
            "No matching rows in the last {} day{}.\n",
            days,
            if days == 1 { "" } else { "s" }
        );
    }
    let mut out = format!(
        "{} row{} (last {} day{}):\n\n",
        rows.len(),
        if rows.len() == 1 { "" } else { "s" },
        days,
        if days == 1 { "" } else { "s" }
    );
    for row in rows {
        out.push_str(&format_row(row));
        out.push('\n');
    }
    out
}

fn format_row(r: &FailedCallView) -> String {
    let ts = DateTime::<Utc>::from_timestamp(r.timestamp, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| r.timestamp.to_string());

    let status = row_status(
        r.hard_fail,
        r.recovery_kind.as_deref(),
        r.recovery_stage.as_deref(),
        r.recovery_unknown,
    );

    let mut out = format!(
        "{ts}  {tool:<12} {model}  [{status}]\n",
        ts = ts,
        tool = r.tool,
        model = r.model,
        status = status
    );
    if let Some(fp) = &r.shape_fingerprint {
        out.push_str(&format!("  shape: {fp}\n"));
    }
    out.push_str(&format!(
        "  agent: {}  session: {}\n",
        r.agent, r.session_id
    ));
    if let Some(p) = &r.path {
        out.push_str(&format!("  path: {p}\n"));
    }
    let args_pretty = serde_json::to_string_pretty(&r.original_input)
        .unwrap_or_else(|_| r.original_input.to_string());
    out.push_str("  original_input:\n");
    for line in args_pretty.lines() {
        out.push_str(&format!("    {line}\n"));
    }
    if r.wire_input != r.original_input {
        let wire_pretty = serde_json::to_string_pretty(&r.wire_input)
            .unwrap_or_else(|_| r.wire_input.to_string());
        out.push_str("  wire_input (rewritten):\n");
        for line in wire_pretty.lines() {
            out.push_str(&format!("    {line}\n"));
        }
    }
    out.push_str("  output:\n");
    for line in r.output.lines().take(8) {
        out.push_str(&format!("    {line}\n"));
    }
    let extra = r.output.lines().count().saturating_sub(8);
    if extra > 0 {
        out.push_str(&format!("    ... [{extra} more lines]\n"));
    }
    out
}

fn row_status(hard_fail: bool, kind: Option<&str>, stage: Option<&str>, unknown: bool) -> String {
    // An unrecognized recovery kind/stage still carries a raw `kind`/`stage`
    // string, so annotate it so it is not read as a recognized recovery.
    let suffix = if unknown {
        " (unrecognized recovery)"
    } else {
        ""
    };
    if hard_fail {
        format!("HARD FAIL{suffix}")
    } else {
        match (kind, stage) {
            (Some(k), Some(s)) => format!("recovered ({k}/{s}){suffix}"),
            (Some(k), None) => format!("recovered ({k}){suffix}"),
            _ => format!("recovered{suffix}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hard_fail_and_recovered_statuses_render() {
        assert_eq!(row_status(true, None, None, false), "HARD FAIL");
        assert_eq!(
            row_status(false, Some("json"), Some("parse"), false),
            "recovered (json/parse)"
        );
        assert_eq!(
            row_status(false, Some("json"), None, false),
            "recovered (json)"
        );
        assert_eq!(row_status(false, None, None, false), "recovered");
    }

    #[test]
    fn unrecognized_recovery_is_annotated() {
        // An unknown persisted recovery kind/stage still carries a raw
        // `kind`/`stage`; the status must flag it as unrecognized so it is not
        // mistaken for a recognized recovery.
        assert_eq!(
            row_status(false, Some("future_kind"), Some("future_stage"), true),
            "recovered (future_kind/future_stage) (unrecognized recovery)"
        );
        assert_eq!(
            row_status(true, None, None, true),
            "HARD FAIL (unrecognized recovery)"
        );
    }

    #[test]
    fn failed_call_view_parses_daemon_projection() {
        // The projection is exactly what the daemon's `failed_tool_call_json`
        // emits; a wrong field name here would drop the value on render.
        let view: FailedCallView = serde_json::from_str(
            r#"{"event_id":"e","session_id":"11111111-1111-1111-1111-111111111111","timestamp":0,"model":"m","provider":"p","project_id":"pid","agent":"Build","tool":"edit","path":"src/x.rs","hard_fail":true,"shape_fingerprint":"shape-a","recovery_kind":"json","recovery_stage":"parse","original_input":{"a":1},"wire_input":{"a":2},"output":"line1\nline2","truncated":false,"duration_ms":5}"#,
        )
        .unwrap();
        assert_eq!(view.session_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(view.shape_fingerprint.as_deref(), Some("shape-a"));
        assert_ne!(view.wire_input, view.original_input);
    }

    #[test]
    fn format_row_shows_status_shape_path_and_wire_rewrite() {
        let view = FailedCallView {
            timestamp: 0,
            model: "model".into(),
            agent: "Build".into(),
            session_id: "sid".into(),
            tool: "edit".into(),
            path: Some("src/x.rs".into()),
            hard_fail: true,
            shape_fingerprint: Some("shape-a".into()),
            recovery_kind: None,
            recovery_stage: None,
            recovery_unknown: false,
            original_input: serde_json::json!({"a": 1}),
            wire_input: serde_json::json!({"a": 2}),
            output: "l1\nl2".into(),
        };
        let rendered = format_row(&view);
        assert!(rendered.starts_with("1970-01-01 00:00:00 UTC  edit"));
        assert!(rendered.contains("model  [HARD FAIL]\n"));
        assert!(rendered.contains("  shape: shape-a\n"));
        assert!(rendered.contains("  agent: Build  session: sid\n"));
        assert!(rendered.contains("  path: src/x.rs\n"));
        // A distinct wire_input triggers the rewritten section.
        assert!(rendered.contains("  wire_input (rewritten):\n"));
        assert!(rendered.contains("  output:\n"));
    }

    #[test]
    fn empty_failed_calls_reports_no_rows() {
        assert_eq!(
            format_failed_calls(&[], 7),
            "No matching rows in the last 7 days.\n"
        );
        assert_eq!(
            format_failed_calls(&[], 1),
            "No matching rows in the last 1 day.\n"
        );
    }
}
