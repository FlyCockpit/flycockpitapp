//! `cockpit schedule` subcommands.

use anyhow::{Result, bail};

use crate::cli::{ScheduleCommand, ScheduleCreateArgs, ScheduleListArgs};
use crate::daemon::client::{LifecycleMode, probe_or_spawn};
use crate::daemon::proto::{
    MissedRunPolicy, Request, Response, ScheduledJobCreate, ScheduledJobPayload,
    ScheduledJobSchedule, ScheduledJobSummary,
};

pub async fn run(cmd: ScheduleCommand) -> Result<()> {
    match cmd {
        ScheduleCommand::Create(args) => create(args).await,
        ScheduleCommand::List(args) => list(args).await,
        ScheduleCommand::Enable { id } => set_enabled(&id, true).await,
        ScheduleCommand::Disable { id } => set_enabled(&id, false).await,
        ScheduleCommand::Run { id } => run_now(&id).await,
    }
}

async fn client() -> Result<crate::daemon::client::DaemonClient> {
    Ok(probe_or_spawn(LifecycleMode::AttachOrAutoPromote)
        .await?
        .client)
}

async fn list(args: ScheduleListArgs) -> Result<()> {
    let response = client()
        .await?
        .request_ok(Request::ListScheduledJobs { owner: args.owner })
        .await?;
    let Response::ScheduledJobs { jobs } = response else {
        bail!("unexpected schedule list response: {response:?}");
    };
    if jobs.is_empty() {
        println!("no scheduled jobs");
        return Ok(());
    }
    for job in jobs {
        println!("{}", format_job(&job));
    }
    Ok(())
}

async fn create(args: ScheduleCreateArgs) -> Result<()> {
    let job = build_create(args)?;
    let response = client()
        .await?
        .request_ok(Request::CreateScheduledJob { job })
        .await?;
    let Response::ScheduledJob { job } = response else {
        bail!("unexpected schedule create response: {response:?}");
    };
    println!("{}", format_job(&job));
    Ok(())
}

fn build_create(args: ScheduleCreateArgs) -> Result<ScheduledJobCreate> {
    Ok(ScheduledJobCreate {
        id: args.id,
        owner: args.owner,
        schedule: serde_json::from_str(&args.schedule_json)
            .map_err(|error| anyhow::anyhow!("invalid --schedule-json: {error}"))?,
        payload: serde_json::from_str(&args.payload_json)
            .map_err(|error| anyhow::anyhow!("invalid --payload-json: {error}"))?,
        enabled: !args.disabled,
        missed_run_policy: parse_missed_run_policy(&args.missed_run_policy)?,
    })
}

fn parse_missed_run_policy(raw: &str) -> Result<MissedRunPolicy> {
    match raw {
        "skip" => Ok(MissedRunPolicy::Skip),
        "run_once_on_start" => Ok(MissedRunPolicy::RunOnceOnStart),
        other => bail!("invalid missed-run policy `{other}`"),
    }
}

async fn set_enabled(id: &str, enabled: bool) -> Result<()> {
    let response = client()
        .await?
        .request_ok(Request::SetScheduledJobEnabled {
            id: id.to_string(),
            enabled,
        })
        .await?;
    let Response::ScheduledJob { job } = response else {
        bail!("unexpected schedule enable response: {response:?}");
    };
    println!("{}", format_job(&job));
    Ok(())
}

async fn run_now(id: &str) -> Result<()> {
    let response = client()
        .await?
        .request_ok(Request::RunScheduledJob { id: id.to_string() })
        .await?;
    let Response::ScheduledJobRunQueued { id } = response else {
        bail!("unexpected schedule run response: {response:?}");
    };
    println!("{id}: queued");
    Ok(())
}

fn format_job(job: &ScheduledJobSummary) -> String {
    let state = if job.enabled { "enabled" } else { "disabled" };
    let next = job
        .next_run_at
        .map(|ts| ts.to_string())
        .unwrap_or_else(|| "-".to_string());
    let result = job
        .last_result
        .as_ref()
        .map_or("never".to_string(), |result| {
            let status = if result.ok { "ok" } else { "failed" };
            format!("{status}: {}", result.summary)
        });
    format!(
        "{}  owner={}  {}  next={}  schedule={}  payload={}  last={}",
        job.id,
        job.owner,
        state,
        next,
        format_schedule(&job.schedule),
        format_payload(&job.payload),
        result
    )
}

fn format_schedule(schedule: &ScheduledJobSchedule) -> String {
    match schedule {
        ScheduledJobSchedule::Cron { expr } => format!("cron({expr})"),
        ScheduledJobSchedule::Every { seconds } => format!("every({seconds}s)"),
        ScheduledJobSchedule::Once { at } => format!("once({at})"),
        ScheduledJobSchedule::Idle {
            min_idle_seconds,
            max_age_seconds,
        } => format!("idle(min_idle={min_idle_seconds}s,max_age={max_age_seconds}s)"),
    }
}

fn format_payload(payload: &ScheduledJobPayload) -> String {
    match payload {
        ScheduledJobPayload::RunPrompt {
            assistant,
            project_root,
            ..
        } => format!("run_prompt(assistant={assistant},project={project_root})"),
        ScheduledJobPayload::Callback { subsystem } => format!("callback({subsystem})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_subcommand_builds_rpc_job() {
        let job = build_create(ScheduleCreateArgs {
            id: "job-1".to_string(),
            owner: "system:test".to_string(),
            schedule_json: r#"{"type":"every","seconds":60}"#.to_string(),
            payload_json: r#"{"type":"callback","subsystem":"test"}"#.to_string(),
            disabled: false,
            missed_run_policy: "run_once_on_start".to_string(),
        })
        .unwrap();

        assert_eq!(job.id, "job-1");
        assert_eq!(job.owner, "system:test");
        assert_eq!(job.schedule, ScheduledJobSchedule::Every { seconds: 60 });
        assert_eq!(
            job.payload,
            ScheduledJobPayload::Callback {
                subsystem: "test".to_string()
            }
        );
        assert!(job.enabled);
        assert_eq!(job.missed_run_policy, MissedRunPolicy::RunOnceOnStart);
    }

    #[test]
    fn create_subcommand_rejects_bad_json() {
        let error = build_create(ScheduleCreateArgs {
            id: "job-1".to_string(),
            owner: "system:test".to_string(),
            schedule_json: "not json".to_string(),
            payload_json: r#"{"type":"callback","subsystem":"test"}"#.to_string(),
            disabled: false,
            missed_run_policy: "skip".to_string(),
        })
        .unwrap_err();

        assert!(error.to_string().contains("--schedule-json"));
    }
}
