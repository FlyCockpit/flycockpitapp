use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{NaiveDate, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::cli::{OutputFormat, SessionAnswerArgs, SessionCommand, SessionListArgs};
use crate::daemon::client::{OwnedSessionMode, ensure_persistent_daemon};
use crate::daemon::proto::{Request, ResolveResponse, Response};

pub async fn run(cmd: SessionCommand) -> Result<()> {
    match cmd {
        SessionCommand::Answer(args) => answer(args).await,
        SessionCommand::Show { session_id, json } => show(&session_id, json).await,
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
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for session delete")?;
    let client = daemon.client.clone();
    match client
        .request(Request::DeleteSession { session_id })
        .await
        .context("requesting session delete from daemon")?
    {
        Ok(Response::Ack) => {}
        Ok(other) => bail!("daemon returned unexpected response to session delete: {other:?}"),
        Err(error) => {
            // The daemon rejects an active session with a typed Conflict
            // error. Surface it the same way the CLI's old direct-DB path
            // did ("session is active; end it before deleting").
            bail!("{error}");
        }
    }
    println!("deleted session {session_id} and all associated local data");
    Ok(())
}

async fn purge(before: &str, dry_run: bool, yes: bool) -> Result<()> {
    let cutoff = parse_purge_before(before)?;
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for session purge")?;
    if dry_run {
        // The daemon owns session storage; `PurgeEndedSessions` deletes and has
        // no non-destructive count. Fail closed rather than open SQLite from the
        // CLI or invent a preview count.
        bail!(
            "session purge --dry-run is not available through the daemon (no non-destructive ended-session count); rerun without --dry-run to purge"
        );
    }
    confirm_destructive(yes, &format!("Delete all ended sessions before {before}"))?;
    let response = daemon
        .client
        .request(Request::PurgeEndedSessions { before: cutoff })
        .await
        .context("requesting session purge from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected session purge: {error}"))?;
    let Response::EndedSessionsPurged { purged, .. } = response else {
        bail!("daemon returned unexpected response to session purge: {response:?}");
    };
    println!("deleted {purged} ended session(s) before {before}");
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
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for session list")?;
    let client = daemon.client.clone();
    let response = client
        .request(Request::ListSessions {
            project_id: None,
            parent_session_id: None,
            assistant_id: args.assistant.clone(),
        })
        .await
        .context("requesting session list from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected session list request: {error}"))?;
    let sessions = match response {
        Response::Sessions { sessions } => sessions,
        other => bail!("daemon returned unexpected response to session list: {other:?}"),
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

/// Projection of one `session_compacted` event as returned by the daemon's
/// `get_session_compactions` response. Carries the complete event payload.
#[derive(Debug, serde::Deserialize)]
struct CompactionView {
    seq: i64,
    ts_ms: i64,
    #[serde(default)]
    data: Value,
}

async fn show(session: &str, json_mode: bool) -> Result<()> {
    let session_id = Uuid::parse_str(session).context("parsing session id")?;
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for session show")?;
    let response = daemon
        .client
        .request(Request::GetSessionCompactions { session_id })
        .await
        .context("requesting session compactions from daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected session show: {error}"))?;
    let Response::SessionCompactions {
        compactions_json, ..
    } = response
    else {
        bail!("daemon returned unexpected response to session show: {response:?}");
    };
    let compactions: Vec<CompactionView> =
        serde_json::from_str(&compactions_json).context("parsing session compactions")?;

    if json_mode {
        return emit_json(&render_compactions_json(session_id, &compactions));
    }
    print!("{}", render_compactions_text(session_id, &compactions));
    Ok(())
}

fn render_compactions_json(session_id: Uuid, compactions: &[CompactionView]) -> Value {
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
    json!({
        "session_id": session_id,
        "compactions": values,
    })
}

fn render_compactions_text(session_id: Uuid, compactions: &[CompactionView]) -> String {
    if compactions.is_empty() {
        return format!("no compactions recorded for session {session_id}\n");
    }
    let mut out = String::new();
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
        out.push_str(&format!(
            "compact #{} source={source} tokens={before}→{after}\n",
            event.seq
        ));
        out.push_str(
            event
                .data
                .get("handoff_text")
                .and_then(Value::as_str)
                .unwrap_or("(handoff unavailable)"),
        );
        out.push('\n');
    }
    out
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
    let json = args.json;
    let follow = args.follow;

    crate::daemon::client::run_owned_daemon(OwnedSessionMode::AttachOrEphemeral, |client| {
        Box::pin(async move {
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
                    session_entry_mode: None,
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

            if json {
                emit_json(&json!({
                    "event": "interrupt_resolved",
                    "session_id": session_id,
                    "interrupt_id": interrupt_id,
                    "status": "resolved"
                }))?;
            } else {
                println!("interrupt {interrupt_id} resolved");
            }

            if follow {
                let format = if json {
                    OutputFormat::Json
                } else {
                    OutputFormat::Default
                };
                crate::commands::run::pump_events(
                    &client,
                    session_id,
                    format,
                    json,
                    &[],
                    false,
                    None,
                )
                .await?;
            }
            Ok(())
        })
    })
    .await
    .map_err(|error| error.into_inner())
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
fn validate_one(
    question: &crate::daemon::proto::InterruptQuestion,
    response: &ResolveResponse,
) -> Result<()> {
    use crate::daemon::proto::InterruptQuestion;
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

#[cfg(test)]
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
    use crate::daemon::proto::{InterruptOption, InterruptQuestion, InterruptQuestionSet};
    use crate::db::Db;
    use crate::session::Session;

    #[test]
    fn compactions_json_projects_every_planted_field() {
        let session_id = Uuid::nil();
        let compactions = vec![
            CompactionView {
                seq: 1,
                ts_ms: 100,
                data: json!({
                    "source": "auto",
                    "tokens_before": 900,
                    "tokens_after": 300,
                    "handoff_text": "carry these facts",
                }),
            },
            CompactionView {
                seq: 2,
                ts_ms: 200,
                data: json!({}),
            },
        ];
        let value = render_compactions_json(session_id, &compactions);
        // The complete list appears (distinct from a paginated read); a
        // dropped element would shrink the array.
        assert_eq!(value["compactions"].as_array().unwrap().len(), 2);
        assert_eq!(value["compactions"][0]["source"], "auto");
        assert_eq!(value["compactions"][0]["tokens_before"], 900);
        assert_eq!(value["compactions"][0]["handoff"], "carry these facts");
        // A missing field is projected as null, not dropped.
        assert!(value["compactions"][1]["handoff"].is_null());
    }

    #[test]
    fn compactions_text_renders_source_tokens_and_handoff() {
        let text = render_compactions_text(
            Uuid::nil(),
            &[CompactionView {
                seq: 3,
                ts_ms: 0,
                data: json!({
                    "source": "auto",
                    "tokens_before": 800,
                    "tokens_after": 250,
                    "handoff_text": "keep going",
                }),
            }],
        );
        assert!(text.contains("compact #3 source=auto tokens=800→250\n"));
        assert!(text.contains("keep going\n"));
    }

    #[test]
    fn compactions_text_empty_is_explicit() {
        let text = render_compactions_text(Uuid::nil(), &[]);
        assert_eq!(
            text,
            format!("no compactions recorded for session {}\n", Uuid::nil())
        );
    }

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
        // Run the actor startup off the async worker: it blocks on the
        // secure-key readiness channel (`blocking_recv`), which panics on a
        // Tokio worker thread.
        let (secure_key_actor, resolver) = {
            let db = db.clone();
            tokio::task::spawn_blocking(move || {
                crate::redact::start_fake_redaction_key_resolver(&db)
            })
            .await
            .unwrap()
            .unwrap()
        };
        let session =
            Session::create_for_test(db.clone(), std::env::temp_dir(), "Build", resolver).unwrap();
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
        let session_id = session.id;
        // The actor's Drop blocks on its worker channel (`blocking_recv`), which
        // panics on a Tokio worker thread; drain it off the async worker.
        tokio::task::spawn_blocking(move || drop(secure_key_actor))
            .await
            .unwrap();
        (db, session_id, interrupt_id)
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
