//! `cockpit schedule` subcommands.

use anyhow::{Result, bail};

use crate::cli::{ScheduleCommand, ScheduleListArgs};
use crate::daemon::client::{LifecycleMode, probe_or_spawn};
use crate::daemon::proto::{
    Request, Response, ScheduledJobPayload, ScheduledJobSchedule, ScheduledJobSummary,
};

pub async fn run(cmd: ScheduleCommand) -> Result<()> {
    match cmd {
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
    let Response::ScheduledJobRun { id, result } = response else {
        bail!("unexpected schedule run response: {response:?}");
    };
    let status = if result.ok { "ok" } else { "failed" };
    println!("{id}: {status}: {}", result.summary);
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
