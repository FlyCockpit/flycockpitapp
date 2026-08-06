use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{NaiveDate, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::cli::{OutputFormat, SessionAnswerArgs, SessionCommand, SessionListArgs};
use crate::daemon::client::{LifecycleMode, probe_or_spawn};
use crate::daemon::proto::{InterruptQuestion, Request, ResolveResponse, Response};
use crate::db::Db;

pub async fn run(cmd: SessionCommand) -> Result<()> {
    match cmd {
        SessionCommand::Answer(args) => answer(args).await,
        SessionCommand::Show { session_id, json } => show(&session_id, json),
        SessionCommand::List(args) => list(args).await,
        SessionCommand::Delete { session_id, yes } => delete(&session_id, yes).await,
        SessionCommand::Purge {
            before,
            dry_run,
            yes,
        } => purge(&before, dry_run, yes).await,
    }
}

async fn delete(session: &str, yes: bool) -> Result<()> {
    confirm_destructive(yes, "Delete this session and all local data")?;
    let session_id = Uuid::parse_str(session).context("parsing session id")?;
    refuse_direct_write_while_daemon_running().await?;
    let db = Db::open_default().context("opening cockpit DB")?;
    let session = db
        .get_session(session_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("session {session_id} not found"))?;
    if session.ended_at.is_none() {
        bail!("session {session_id} is active; end it before deleting");
    }
    db.delete_session(session_id).await?;
    println!("deleted session {session_id} and all associated local data");
    Ok(())
}

async fn purge(before: &str, dry_run: bool, yes: bool) -> Result<()> {
    let cutoff = parse_purge_before(before)?;
    refuse_direct_write_while_daemon_running().await?;
    let db = Db::open_default().context("opening cockpit DB")?;
    let sessions = db
        .read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT session_id FROM sessions WHERE ended_at IS NOT NULL AND ended_at < ?1",
            )?;
            statement
                .query_map([cutoff], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(Into::into)
        })
        .await?;
    if dry_run {
        println!("would delete {} ended session(s)", sessions.len());
        return Ok(());
    }
    confirm_destructive(yes, &format!("Delete {} ended session(s)", sessions.len()))?;
    for id in sessions {
        db.delete_session(Uuid::parse_str(&id)?).await?;
    }
    println!("deleted ended sessions before {before}");
    Ok(())
}

fn parse_purge_before(input: &str) -> Result<i64> {
    if let Some(days) = input
        .strip_suffix("d")
        .and_then(|value| value.parse::<i64>().ok())
    {
        if days <= 0 {
            bail!("relative duration must be a positive number of days, such as 30d");
        }
        return Ok(Utc::now().timestamp() - days * 86_400);
    }
    let date = NaiveDate::parse_from_str(input, "%Y-%m-%d")
        .context("--before must be YYYY-MM-DD or a relative duration such as 30d")?;
    Ok(date
        .and_hms_opt(0, 0, 0)
        .expect("midnight is valid")
        .and_utc()
        .timestamp())
}

async fn refuse_direct_write_while_daemon_running() -> Result<()> {
    if matches!(
        crate::daemon::discover().await.status,
        crate::daemon::DaemonStatus::Running
    ) {
        bail!("a daemon is running; stop it before using session delete or purge");
    }
    Ok(())
}

fn confirm_destructive(yes: bool, prompt: &str) -> Result<()> {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stderr = std::io::stderr();
    let mut output = stderr.lock();
    confirm_destructive_with_io(yes, prompt, stdin.is_terminal(), &mut input, &mut output)
}

fn confirm_destructive_with_io(
    yes: bool,
    prompt: &str,
    stdin_is_terminal: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !stdin_is_terminal {
        bail!("{prompt} is irreversible; rerun with --yes in non-interactive mode");
    }
    write!(output, "{prompt}? [y/N] ")?;
    output.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer)?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        bail!("deletion cancelled");
    }
    Ok(())
}

async fn list(args: SessionListArgs) -> Result<()> {
    let db = Db::open_default().context("opening cockpit DB")?;
    let sessions = if let Some(assistant) = args.assistant.as_deref() {
        let assistant = assistant.to_string();
        let assistant_label = assistant.clone();
        db.write(move |conn| Db::list_sessions_for_assistant_conn(conn, &assistant, false, 100))
            .await
            .with_context(|| format!("listing sessions for assistant `{assistant_label}`"))?
    } else {
        db.write(move |conn| Db::list_sessions_conn(conn, false, 100))
            .await
            .context("listing sessions")?
    };
    if sessions.is_empty() {
        println!("no sessions");
        return Ok(());
    }
    for session in sessions {
        let display_id = session
            .short_id
            .as_deref()
            .map(str::to_owned)
            .unwrap_or_else(|| session.session_id.to_string());
        let title = session.title.as_deref().unwrap_or("(untitled)");
        println!(
            "{display_id}\t{}\t{title}\t{}",
            session.session_id, session.project_root
        );
    }
    Ok(())
}

fn show(session: &str, json_mode: bool) -> Result<()> {
    let session_id = Uuid::parse_str(session).context("parsing session id")?;
    let db = Db::open_default().context("opening cockpit DB")?;
    let compactions = db.blocking_for_sync_cli(move |conn| {
        Db::get_session_conn(conn, session_id)
            .context("loading session")?
            .ok_or_else(|| anyhow::anyhow!("session {session_id} not found"))?;
        Ok(Db::list_session_events_conn(conn, session_id)
            .context("loading session timeline")?
            .into_iter()
            .filter(|event| event.kind == "session_compacted")
            .collect::<Vec<_>>())
    })?;

    if json_mode {
        let values = compactions
            .iter()
            .map(|event| {
                json!({
                    "seq": event.seq,
                    "ts_ms": event.ts_ms,
                    "source": event.data.get("source"),
                    "trigger_ctx_pct": event.data.get("trigger_ctx_pct"),
                    "tokens_before": event.data.get("tokens_before"),
                    "tokens_after": event.data.get("tokens_after"),
                    "turns_summarized": event.data.get("turns_summarized"),
                    "tail_kept": event.data.get("tail_kept"),
                    "tail_trimmed": event.data.get("tail_trimmed"),
                    "handoff": event.data.get("handoff_text"),
                })
            })
            .collect::<Vec<_>>();
        return emit_json(&json!({
            "session_id": session_id,
            "compactions": values,
        }));
    }

    if compactions.is_empty() {
        println!("no compactions recorded for session {session_id}");
        return Ok(());
    }
    for event in compactions {
        let source = event
            .data
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or("manual");
        let before = event
            .data
            .get("tokens_before")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let after = event
            .data
            .get("tokens_after")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        println!(
            "compact #{} source={source} tokens={before}→{after}",
            event.seq
        );
        println!(
            "{}",
            event
                .data
                .get("handoff_text")
                .and_then(Value::as_str)
                .unwrap_or("(handoff unavailable)")
        );
    }
    Ok(())
}

async fn answer(args: SessionAnswerArgs) -> Result<()> {
    let json_mode = args.json;
    let result = answer_inner(&args).await;
    match result {
        Ok(()) => Ok(()),
        Err(e) if json_mode => {
            emit_json(&json!({
                "event": "error",
                "code": "command_failed",
                "message": e.to_string()
            }))?;
            std::process::exit(1);
        }
        Err(e) => Err(e),
    }
}

async fn answer_inner(args: &SessionAnswerArgs) -> Result<()> {
    let session_id = Uuid::parse_str(&args.session).context("parsing --session")?;
    let interrupt_id = Uuid::parse_str(&args.interrupt).context("parsing --interrupt")?;
    let response = response_from_args(args)?;
    let db = Db::open_default().context("opening cockpit DB")?;
    let row = db
        .get_interrupt(interrupt_id)
        .await
        .context("loading interrupt")?
        .ok_or_else(|| anyhow::anyhow!("interrupt {interrupt_id} not found"))?;
    if row.session_id != session_id {
        bail!(
            "interrupt {interrupt_id} belongs to session {}, not {session_id}",
            row.session_id
        );
    }
    if row.resolved_at.is_some() {
        ensure_repeat_response_matches(interrupt_id, &row.response, &response)?;
        if args.json {
            emit_json(&json!({
                "event": "interrupt_resolved",
                "session_id": session_id,
                "interrupt_id": interrupt_id,
                "status": "already_resolved"
            }))?;
        } else {
            println!("interrupt {interrupt_id} is already resolved");
        }
        return Ok(());
    }
    validate_response(&row, &response)?;

    let daemon = probe_or_spawn(LifecycleMode::AttachOrEphemeral).await?;
    let client = daemon.client.clone();
    let env_snapshot = crate::env_snapshot::EnvSnapshot::from_process(
        crate::env_snapshot::EnvSnapshotSource::ExplicitCli,
    );
    let attached = client
        .request_ok(Request::Attach {
            session_id: Some(session_id),
            since_seq: None,
            project_root: Some(std::env::current_dir()?.to_string_lossy().into_owned()),
            initial_model: None,
            no_sandbox: false,
            interactive: false,
            model_override: None,
            client_protocol_version: client.negotiated().version,
            env_snapshot: Some(env_snapshot.to_wire()),
            env_policy: crate::env_snapshot::EnvDriftPolicy::Daemon,
        })
        .await?;
    match attached {
        Response::Attached { session_id: id, .. } if id == session_id => {}
        other => bail!("unexpected attach response: {other:?}"),
    }
    client
        .request_ok(Request::ResolveInterrupt {
            interrupt_id,
            response,
        })
        .await
        .context("resolving interrupt")?;

    if args.json {
        emit_json(&json!({
            "event": "interrupt_resolved",
            "session_id": session_id,
            "interrupt_id": interrupt_id,
            "status": "resolved"
        }))?;
    } else {
        println!("interrupt {interrupt_id} resolved");
    }

    if args.follow {
        let format = if args.json {
            OutputFormat::Json
        } else {
            OutputFormat::Default
        };
        crate::commands::run::pump_events(&client, session_id, format, args.json, &[], false, None)
            .await?;
    }
    Ok(())
}

fn ensure_repeat_response_matches(
    interrupt_id: Uuid,
    existing: &Option<ResolveResponse>,
    response: &ResolveResponse,
) -> Result<()> {
    if let Some(existing) = existing {
        let existing = serde_json::to_value(existing).context("serializing stored response")?;
        let current = serde_json::to_value(response).context("serializing response")?;
        if existing != current {
            bail!("interrupt {interrupt_id} is already resolved with a different response");
        }
    }
    Ok(())
}

fn response_from_args(args: &SessionAnswerArgs) -> Result<ResolveResponse> {
    let supplied = [
        args.choice.is_some(),
        args.choices.is_some(),
        args.text.is_some(),
        args.answers_json.is_some(),
        args.cancel,
    ]
    .into_iter()
    .filter(|b| *b)
    .count();
    if supplied != 1 {
        bail!("provide exactly one of --choice, --choices, --text, --answers-json, or --cancel");
    }
    if let Some(choice) = &args.choice {
        return Ok(ResolveResponse::Single {
            selected_id: choice.clone(),
        });
    }
    if let Some(choices) = &args.choices {
        return Ok(ResolveResponse::Multi {
            selected_ids: choices
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
        });
    }
    if let Some(text) = &args.text {
        return Ok(ResolveResponse::Freetext { text: text.clone() });
    }
    if let Some(source) = &args.answers_json {
        return parse_answers_json(source);
    }
    Ok(ResolveResponse::Cancel)
}

fn parse_answers_json(source: &str) -> Result<ResolveResponse> {
    let body = if Path::new(source).exists() {
        std::fs::read_to_string(source).with_context(|| format!("reading answers JSON {source}"))?
    } else {
        source.to_string()
    };
    let value: Value = serde_json::from_str(&body).context("parsing answers JSON")?;
    if let Ok(response) = serde_json::from_value::<ResolveResponse>(value.clone()) {
        return Ok(response);
    }
    let responses = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("answers JSON must be a ResolveResponse or compact array"))?
        .iter()
        .map(parse_compact_answer)
        .collect::<Result<Vec<_>>>()?;
    Ok(ResolveResponse::Batch { responses })
}

fn parse_compact_answer(value: &Value) -> Result<ResolveResponse> {
    let kind = value
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("compact answer is missing `type`"))?;
    match kind {
        "single" | "choice" => Ok(ResolveResponse::Single {
            selected_id: required_str(value, "selected_id")?.to_string(),
        }),
        "multi" | "choices" => Ok(ResolveResponse::Multi {
            selected_ids: value
                .get("selected_ids")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow::anyhow!("multi answer needs `selected_ids` array"))?
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| anyhow::anyhow!("selected_ids entries must be strings"))
                })
                .collect::<Result<Vec<_>>>()?,
        }),
        "text" | "freetext" => Ok(ResolveResponse::Freetext {
            text: required_str(value, "text")?.to_string(),
        }),
        "cancel" => Ok(ResolveResponse::Cancel),
        other => bail!("unknown compact answer type `{other}`"),
    }
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("compact answer is missing `{key}`"))
}

fn validate_response(
    row: &crate::db::needs_attention::NeedsAttentionRow,
    response: &ResolveResponse,
) -> Result<()> {
    let questions = match (&row.questions, &row.question) {
        (Some(set), _) => set.questions.as_slice(),
        (None, Some(question)) => std::slice::from_ref(question),
        (None, None) => return Ok(()),
    };
    let responses = match response {
        ResolveResponse::Batch { responses } => {
            if responses.len() != questions.len() {
                bail!(
                    "batch answer has {} responses but interrupt expects {}",
                    responses.len(),
                    questions.len()
                );
            }
            responses.as_slice()
        }
        ResolveResponse::Cancel => return Ok(()),
        other if questions.len() == 1 => std::slice::from_ref(other),
        _ => bail!("interrupt expects a batch answer"),
    };
    for (question, response) in questions.iter().zip(responses) {
        validate_one(question, response)?;
    }
    Ok(())
}

fn validate_one(question: &InterruptQuestion, response: &ResolveResponse) -> Result<()> {
    match (question, response) {
        (InterruptQuestion::Single { options, .. }, ResolveResponse::Single { selected_id }) => {
            validate_option(options, selected_id)
        }
        (InterruptQuestion::Multi { options, .. }, ResolveResponse::Multi { selected_ids }) => {
            for id in selected_ids {
                validate_option(options, id)?;
            }
            Ok(())
        }
        (InterruptQuestion::Freetext { .. }, ResolveResponse::Freetext { .. }) => Ok(()),
        (_, ResolveResponse::Cancel) => Ok(()),
        (_, ResolveResponse::Batch { .. }) => bail!("nested batch answers are not allowed"),
        (InterruptQuestion::Single { .. }, _) => bail!("interrupt expects a single choice answer"),
        (InterruptQuestion::Multi { .. }, _) => bail!("interrupt expects a multi-choice answer"),
        (InterruptQuestion::Freetext { .. }, _) => bail!("interrupt expects a text answer"),
    }
}

fn validate_option(
    options: &[crate::daemon::proto::InterruptOption],
    selected_id: &str,
) -> Result<()> {
    if options.iter().any(|option| option.id == selected_id) {
        Ok(())
    } else {
        bail!("unknown option id `{selected_id}`")
    }
}

fn emit_json(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::proto::{InterruptOption, InterruptQuestionSet};
    use crate::session::Session;

    fn option(id: &str) -> InterruptOption {
        InterruptOption {
            id: id.to_string(),
            label: id.to_string(),
            description: None,
            secondary: false,
        }
    }

    async fn single_row() -> (Db, Uuid, Uuid) {
        let db = Db::open_in_memory().unwrap();
        let session = Session::create(db.clone(), std::env::temp_dir(), "Build").unwrap();
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Pick".into(),
                options: vec![option("yes"), option("no")],
                allow_freetext: true,
                command_detail: None,
                permission: false,
                approval_class: None,
                sandbox_escalation: None,
            }],
        };
        let interrupt_id = db
            .raise_interrupt_questions(session.id, "Build", "Pick", &set)
            .await
            .unwrap();
        (db, session.id, interrupt_id)
    }

    #[test]
    fn compact_batch_json_normalizes_to_response_batch() {
        let response = parse_answers_json(
            r#"[{"type":"single","selected_id":"yes"},{"type":"text","text":"Use daemon"}]"#,
        )
        .unwrap();
        match response {
            ResolveResponse::Batch { responses } => {
                assert!(matches!(responses[0], ResolveResponse::Single { .. }));
                assert!(matches!(responses[1], ResolveResponse::Freetext { .. }));
            }
            other => panic!("expected batch, got {other:?}"),
        }
    }

    #[test]
    fn protocol_batch_json_parses() {
        let response = parse_answers_json(
            r#"{"kind":"batch","data":{"responses":[{"kind":"single","data":{"selected_id":"yes"}}]}}"#,
        )
        .unwrap();
        assert!(matches!(response, ResolveResponse::Batch { .. }));
    }

    #[tokio::test]
    async fn validates_option_ids_against_pending_question() {
        let (db, _session_id, interrupt_id) = single_row().await;
        let row = db.get_interrupt(interrupt_id).await.unwrap().unwrap();
        validate_response(
            &row,
            &ResolveResponse::Single {
                selected_id: "yes".into(),
            },
        )
        .unwrap();
        let err = validate_response(
            &row,
            &ResolveResponse::Single {
                selected_id: "maybe".into(),
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown option id"));
    }

    #[test]
    fn ambiguous_answer_flags_are_rejected() {
        let args = SessionAnswerArgs {
            session: Uuid::new_v4().to_string(),
            interrupt: Uuid::new_v4().to_string(),
            choice: Some("yes".into()),
            choices: None,
            text: Some("also".into()),
            answers_json: None,
            cancel: false,
            json: true,
            follow: false,
        };
        let err = response_from_args(&args).unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn already_resolved_response_mismatch_is_rejected() {
        let interrupt_id = Uuid::new_v4();
        let existing = ResolveResponse::Single {
            selected_id: "yes".into(),
        };
        let current = ResolveResponse::Single {
            selected_id: "no".into(),
        };
        let err = ensure_repeat_response_matches(interrupt_id, &Some(existing), &current)
            .unwrap_err()
            .to_string();
        assert!(err.contains("different response"));
    }
    #[test]
    fn purge_before_argument_parsing() {
        assert!(parse_purge_before("2026-01-01").is_ok());
        assert!(parse_purge_before("30d").is_ok());
        assert!(parse_purge_before("0d").is_err());
        assert!(parse_purge_before("tomorrow").is_err());
    }

    #[test]
    fn delete_noninteractive_without_yes_refuses() {
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        let error = confirm_destructive_with_io(
            false,
            "Delete this session and all local data",
            false,
            &mut input,
            &mut output,
        )
        .unwrap_err();

        assert!(error.to_string().contains("rerun with --yes"));
        assert!(output.is_empty());
    }
}
