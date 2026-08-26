//! `cockpit invocation status|cancel` — durable run-invocation recovery.

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::cli::{InvocationCancelArgs, InvocationCommand, InvocationStatusArgs, OutputFormat};
use crate::daemon::client::{OwnedDaemonSession, OwnedSessionMode};
use crate::daemon::proto::{self, Request, Response};

pub async fn run(cmd: InvocationCommand) -> Result<()> {
    match cmd {
        InvocationCommand::Status(args) => status(args).await,
        InvocationCommand::Cancel(args) => cancel(args).await,
    }
}

async fn status(args: InvocationStatusArgs) -> Result<()> {
    let id = parse_canonical_uuid(&args.client_submission_id).map_err(|e| {
        exit_usage(2, &e);
    })?;
    let daemon = OwnedDaemonSession::connect(OwnedSessionMode::AttachOrEphemeral)
        .await
        .map_err(|e| exit_transport(4, &format!("{e:#}")))?;
    let result = match daemon
        .client()
        .request(Request::GetRunInvocationStatus {
            client_submission_id: id,
        })
        .await
    {
        Ok(Ok(Response::RunInvocationStatus { status })) => print_status(args.format, &status),
        Ok(Ok(other)) => {
            Err(InvocationCommandError::transport(format!("unexpected response: {other:?}")).into())
        }
        Ok(Err(error)) => Err(map_daemon_error(&error).into()),
        Err(error) => Err(InvocationCommandError::transport(error.to_string()).into()),
    };
    finish_invocation_result(daemon.finish(result).await)
}

async fn cancel(args: InvocationCancelArgs) -> Result<()> {
    let id = parse_canonical_uuid(&args.client_submission_id).map_err(|e| {
        exit_usage(2, &e);
    })?;
    let daemon = OwnedDaemonSession::connect(OwnedSessionMode::AttachOrEphemeral)
        .await
        .map_err(|e| exit_transport(4, &format!("{e:#}")))?;
    let result = match daemon
        .client()
        .request(Request::CancelRunInvocation {
            client_submission_id: id,
        })
        .await
    {
        Ok(Ok(Response::RunInvocationCancelResult { result })) => {
            print_cancel(args.format, &result)
        }
        Ok(Ok(other)) => {
            Err(InvocationCommandError::transport(format!("unexpected response: {other:?}")).into())
        }
        Ok(Err(error)) => Err(map_daemon_error(&error).into()),
        Err(error) => Err(InvocationCommandError::transport(error.to_string()).into()),
    };
    finish_invocation_result(daemon.finish(result).await)
}

/// Accept only the canonical lowercase hyphenated UUID spelling.
pub fn parse_canonical_uuid(raw: &str) -> Result<Uuid, String> {
    if raw.len() != 36
        || raw.as_bytes()[8] != b'-'
        || raw.as_bytes()[13] != b'-'
        || raw.as_bytes()[18] != b'-'
        || raw.as_bytes()[23] != b'-'
        || raw.chars().any(|c| c.is_ascii_uppercase())
        || !raw.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
    {
        return Err(format!(
            "client_submission_id must be a canonical lowercase hyphenated UUID; got `{raw}`"
        ));
    }
    Uuid::parse_str(raw).map_err(|_| {
        format!("client_submission_id must be a canonical lowercase hyphenated UUID; got `{raw}`")
    })
}

fn print_status(format: OutputFormat, status: &proto::RunInvocationStatusV1) -> Result<()> {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string(status).context("serializing status")?
            );
        }
        OutputFormat::Default => {
            let max_turns = status
                .max_turns
                .map(|n| n.to_string())
                .unwrap_or_else(|| "unbounded".into());
            let timeout_ms = status
                .timeout_ms
                .map(|n| n.to_string())
                .unwrap_or_else(|| "unbounded".into());
            let remaining_ms = status
                .remaining_ms
                .map(|n| n.to_string())
                .unwrap_or_else(|| "unbounded".into());
            println!(
                "invocation {}: {} (state_version={}, reserved_turns={}, max_turns={}, timeout_ms={}, remaining_ms={})",
                status.client_submission_id,
                status.state.as_str(),
                status.state_version,
                status.reserved_turns,
                max_turns,
                timeout_ms,
                remaining_ms
            );
        }
    }
    Ok(())
}

fn print_cancel(format: OutputFormat, result: &proto::RunInvocationCancelResultV1) -> Result<()> {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string(result).context("serializing cancel result")?
            );
        }
        OutputFormat::Default => {
            let line = match result.outcome {
                proto::RunInvocationCancelOutcome::CancellationRequested => {
                    format!(
                        "invocation {}: cancellation_requested",
                        result.client_submission_id
                    )
                }
                proto::RunInvocationCancelOutcome::AlreadyCancelled => {
                    format!(
                        "invocation {}: already_cancelled",
                        result.client_submission_id
                    )
                }
                proto::RunInvocationCancelOutcome::AlreadyTerminal => {
                    format!(
                        "invocation {}: already_terminal:{}",
                        result.client_submission_id,
                        result.state.as_str()
                    )
                }
                proto::RunInvocationCancelOutcome::NotFound => {
                    format!("invocation {}: not_found", result.client_submission_id)
                }
            };
            println!("{line}");
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
struct InvocationCommandError {
    exit_code: i32,
    message: String,
}

impl InvocationCommandError {
    fn transport(message: String) -> Self {
        Self {
            exit_code: 4,
            message,
        }
    }
}

fn map_daemon_error(error: &proto::ErrorPayload) -> InvocationCommandError {
    let exit_code = match error.code {
        proto::ErrorCode::InvocationNotFound => 5,
        proto::ErrorCode::InvocationLookupBusy
        | proto::ErrorCode::InvocationCapacityExceeded
        | proto::ErrorCode::ClientSubmissionIdUnavailable
        | proto::ErrorCode::Authorization
        | proto::ErrorCode::ProtocolVersion
        | proto::ErrorCode::Unavailable => 4,
        _ => 4,
    };
    InvocationCommandError {
        exit_code,
        message: if exit_code == 5 {
            "invocation not found".to_string()
        } else {
            error.message.clone()
        },
    }
}

fn finish_invocation_result(result: Result<()>) -> Result<()> {
    match result {
        Err(error) if error.downcast_ref::<InvocationCommandError>().is_some() => {
            let command = error
                .downcast_ref::<InvocationCommandError>()
                .expect("invocation command error checked above");
            eprintln!("{}", command.message);
            std::process::exit(command.exit_code);
        }
        result => result,
    }
}

fn exit_usage(code: i32, message: &str) -> ! {
    eprintln!("error: {message}");
    std::process::exit(code);
}

fn exit_transport(code: i32, message: &str) -> ! {
    eprintln!("error: {message}");
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::proto::{
        RunInvocationCancelOutcome, RunInvocationCancelResultV1, RunInvocationLifecycleState,
        RunInvocationStatusV1,
    };

    #[test]
    fn invocation_cli_contract() {
        // Canonical UUID accepted; uppercase/braced/non-hyphen rejected before daemon.
        let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        assert!(parse_canonical_uuid(id).is_ok());
        assert!(parse_canonical_uuid("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA").is_err());
        assert!(parse_canonical_uuid("aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa").is_err());
        assert!(parse_canonical_uuid("not-a-uuid").is_err());
        assert!(parse_canonical_uuid("").is_err());

        let status = RunInvocationStatusV1 {
            schema_version: 1,
            client_submission_id: Uuid::parse_str(id).unwrap(),
            state: RunInvocationLifecycleState::Queued,
            state_version: 2,
            created_at_wall_ms: 1,
            updated_at_wall_ms: 2,
            max_turns: None,
            timeout_ms: Some(1000),
            remaining_ms: Some(500),
            reserved_turns: 0,
            terminal_at_wall_ms: None,
            terminal_reason: None,
        };
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert!(json.get("prompt").is_none());
        assert!(json.get("session_id").is_none());
        assert!(json.get("output").is_none());

        let cancel = RunInvocationCancelResultV1 {
            schema_version: 1,
            client_submission_id: Uuid::parse_str(id).unwrap(),
            outcome: RunInvocationCancelOutcome::AlreadyTerminal,
            state: RunInvocationLifecycleState::Succeeded,
            state_version: 4,
        };
        let cancel_json = serde_json::to_value(&cancel).unwrap();
        assert_eq!(cancel_json["outcome"], "already_terminal");
        assert_eq!(cancel_json["state"], "succeeded");
    }
}
