use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::cli::{DebugCommand, FailedCallsArgs};
use crate::db::Db;
use crate::db::tool_calls::Recovery;
use crate::db::tool_calls::{FailedCallsFilter, ToolCallEvent};
use crate::session::project_id_for;

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

/// `cockpit debug failed-calls` — see GOALS §12. Pulls recent rows where
/// the tool either hard-failed or fired a recovery and prints them in a
/// form designed for pattern-spotting (original arguments + brief
/// output snippet), so the user can decide which patterns are worth
/// turning into new repair-catalog entries.
async fn failed_calls(args: FailedCallsArgs) -> Result<()> {
    let db = Db::open_default()?;
    let project_id = args
        .project
        .as_ref()
        .map(|project| project_id_for(project.as_path()));
    let since_epoch = Utc::now().timestamp() - (args.days as i64) * 86_400;

    let rows = db
        .list_failed_tool_calls(FailedCallsFilter {
            since_epoch,
            tool: args.tool.clone(),
            model: args.model.clone(),
            project_id,
            include_recovered: args.include_recovered,
            limit: args.limit as usize,
        })
        .await?;

    if args.json {
        for r in &rows {
            println!("{}", serde_json::to_string(&row_as_json(r))?);
        }
        return Ok(());
    }

    if rows.is_empty() {
        println!(
            "No matching rows in the last {} day{}.",
            args.days,
            if args.days == 1 { "" } else { "s" }
        );
        return Ok(());
    }

    println!(
        "{} row{} (last {} day{}):\n",
        rows.len(),
        if rows.len() == 1 { "" } else { "s" },
        args.days,
        if args.days == 1 { "" } else { "s" }
    );
    for r in &rows {
        print_row(r);
        println!();
    }
    Ok(())
}

fn print_row(r: &ToolCallEvent) {
    let ts = DateTime::<Utc>::from_timestamp(r.timestamp, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| r.timestamp.to_string());

    let status = row_status(r);

    println!(
        "{ts}  {tool:<12} {model}  [{status}]",
        ts = ts,
        tool = r.tool,
        model = r.model,
        status = status
    );
    if let Some(fp) = &r.shape_fingerprint {
        println!("  shape: {fp}");
    }
    println!("  agent: {}  session: {}", r.agent, r.session_id);
    if let Some(p) = &r.path {
        println!("  path: {p}");
    }
    let args_pretty = serde_json::to_string_pretty(&r.original_input_json)
        .unwrap_or_else(|_| r.original_input_json.to_string());
    println!("  original_input:");
    for line in args_pretty.lines() {
        println!("    {line}");
    }
    if r.wire_input_json != r.original_input_json {
        let wire_pretty = serde_json::to_string_pretty(&r.wire_input_json)
            .unwrap_or_else(|_| r.wire_input_json.to_string());
        println!("  wire_input (rewritten):");
        for line in wire_pretty.lines() {
            println!("    {line}");
        }
    }
    println!("  output:");
    for line in r.output.lines().take(8) {
        println!("    {line}");
    }
    let extra = r.output.lines().count().saturating_sub(8);
    if extra > 0 {
        println!("    ... [{extra} more lines]");
    }
}

fn row_status(r: &ToolCallEvent) -> String {
    if r.hard_fail {
        "HARD FAIL".to_string()
    } else {
        let (kind, stage) = r.recovery.raw_db_fields();
        match (kind, stage) {
            (Some(k), Some(s)) if matches!(r.recovery, Recovery::Unknown { .. }) => {
                format!("recovered (unknown: {k}/{s})")
            }
            (Some(k), None) if matches!(r.recovery, Recovery::Unknown { .. }) => {
                format!("recovered (unknown: {k})")
            }
            (Some(k), Some(s)) => format!("recovered ({k}/{s})"),
            (Some(k), None) => format!("recovered ({k})"),
            _ => "recovered".to_string(),
        }
    }
}

fn row_as_json(r: &ToolCallEvent) -> serde_json::Value {
    let (kind, stage) = r.recovery.raw_db_fields();
    serde_json::json!({
        "event_id":         r.event_id,
        "session_id":       r.session_id,
        "timestamp":        r.timestamp,
        "model":            r.model,
        "provider":         r.provider,
        "project_id":       r.project_id,
        "agent":            r.agent,
        "tool":             r.tool,
        "path":             r.path,
        "hard_fail":        r.hard_fail,
        "shape_fingerprint": r.shape_fingerprint,
        "recovery_kind":    kind,
        "recovery_stage":   stage,
        "original_input":   r.original_input_json,
        "wire_input":       r.wire_input_json,
        "output":           r.output,
        "truncated":        r.truncated,
        "duration_ms":      r.duration_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    fn row_with_recovery(recovery: Recovery) -> ToolCallEvent {
        ToolCallEvent {
            event_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            call_id: "call-1".into(),
            parent_call_id: None,
            parent_child_index: None,
            provider_item_id: None,
            provider_call_id: None,
            provider_call_id_source: None,
            wire_api: None,
            provider_family: None,
            timestamp: 0,
            model: "model".into(),
            provider: "provider".into(),
            project_id: "project".into(),
            project_root: "/project".into(),
            agent: "Build".into(),
            tool: "tool".into(),
            mcp_server: None,
            path: None,
            recovery,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            original_input_json: json!({"a": 1}),
            wire_input_json: json!({"a": 1}),
            output: String::new(),
            truncated: false,
            duration_ms: 0,
            cockpit_version: None,
            llm_mode: None,
            shape_fingerprint: None,
            hint: None,
        }
    }

    #[test]
    fn json_row_preserves_unknown_recovery_fields() {
        let row = row_with_recovery(Recovery::Unknown {
            kind: "future_kind".into(),
            stage: Some("future_stage".into()),
        });

        let value = row_as_json(&row);

        assert_eq!(value["recovery_kind"], "future_kind");
        assert_eq!(value["recovery_stage"], "future_stage");
    }

    #[test]
    fn unknown_recovery_status_is_not_clean() {
        let row = row_with_recovery(Recovery::Unknown {
            kind: "future_kind".into(),
            stage: Some("future_stage".into()),
        });
        assert_eq!(
            row_status(&row),
            "recovered (unknown: future_kind/future_stage)"
        );
    }
}
