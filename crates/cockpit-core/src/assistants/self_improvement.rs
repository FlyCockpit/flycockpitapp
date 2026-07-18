//! Background assistant skill self-improvement review.
//!
//! The review runs only at idle boundaries for persistent assistant sessions.
//! It uses the normal agent turn loop with a local scratch session and a
//! caged tool context, so reviewer prompts/tool turns do not enter the real
//! conversation while `skill_manage` writes still land on the configured skill
//! roots with `background_review` provenance.

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::engine::agent::{Agent, TurnEvent, TurnOutcome, turn_with_backup};
use crate::engine::message::{Message, extract_text, extract_user_text};
use crate::engine::tool::{ContextUsageSnapshot, ReviewCage, ToolBox};

pub const DEFAULT_SKILL_REVIEW_INTERVAL: u32 = 4;

pub fn default_skill_review_interval() -> u32 {
    DEFAULT_SKILL_REVIEW_INTERVAL
}

#[derive(Debug, Default, Clone)]
pub struct ReviewSchedule {
    assistant_name: Option<String>,
    completed_since_review: u32,
}

impl ReviewSchedule {
    pub fn record_idle_boundary(&mut self, assistant_name: &str, interval: u32) -> bool {
        if interval == 0 {
            return false;
        }
        if self.assistant_name.as_deref() != Some(assistant_name) {
            self.assistant_name = Some(assistant_name.to_string());
            self.completed_since_review = 0;
        }
        self.completed_since_review = self.completed_since_review.saturating_add(1);
        if self.completed_since_review >= interval {
            self.completed_since_review = 0;
            true
        } else {
            false
        }
    }
}

pub struct RunningReview {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

impl RunningReview {
    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }

    pub fn abort(&self) {
        self.cancel.cancel();
        self.handle.abort();
    }
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_review(
    assistant_name: String,
    root_agent: Agent,
    recent_history: Vec<Message>,
    cwd: std::path::PathBuf,
    redact: Arc<crate::redact::RedactionTable>,
    tx: mpsc::Sender<TurnEvent>,
) -> Option<RunningReview> {
    let digest = recent_history_digest(&recent_history);
    let prompt = build_review_prompt(&assistant_name, &digest)?;
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let handle = tokio::spawn(async move {
        match run_review_turn(root_agent, cwd, redact, prompt, task_cancel, &tx).await {
            Ok(Some(summary)) => {
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: format!("self-improvement: {summary}"),
                    })
                    .await;
            }
            Ok(None) => {}
            Err(error) => {
                tracing::debug!(%error, "background skill review skipped");
            }
        }
    });
    Some(RunningReview { cancel, handle })
}

pub fn build_review_prompt(assistant_name: &str, digest: &str) -> Option<String> {
    if digest.trim().is_empty() || should_skip_capture(digest) {
        return None;
    }
    Some(format!(
        r#"You are a caged background reviewer for assistant `{assistant_name}`.

Review the recent transcript digest and decide whether it taught a reusable,
assistant-specific procedure worth saving as an Agent Skill.

Hard rules:
- You may use only `skill` and `skill_manage`.
- Prefer patching an existing relevant skill before creating a new one.
- Before patching, editing, deleting, writing a support file, or removing a
  support file for an existing skill, load that skill with `skill`.
- Do not capture one-off facts, secrets, user preferences, project-specific
  paths, transient environment failures, credentials, or anything that depends
  on this machine's current state.
- It is valid to do nothing. If no reusable procedure exists, answer with one
  short no-op summary and make no tool calls.
- If you do write, finish with one short summary of what changed.

Recent transcript digest:

{digest}"#
    ))
}

pub fn should_skip_capture(digest: &str) -> bool {
    let lower = digest.to_ascii_lowercase();
    [
        "only on my machine",
        "local environment",
        "environment-specific",
        "env var",
        "environment variable",
        "missing secret",
        "credential",
        "api key",
        "network outage",
        "transient network",
        "path-specific",
        "my path",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

async fn run_review_turn(
    root_agent: Agent,
    cwd: std::path::PathBuf,
    redact: Arc<crate::redact::RedactionTable>,
    prompt: String,
    cancel: CancellationToken,
    tx: &mpsc::Sender<TurnEvent>,
) -> Result<Option<String>> {
    let session = scratch_session(&cwd)?;
    let locks = Arc::new(crate::locks::LockManager::from_db(session.db.clone())?);
    let cage = ReviewCage::skills_review();
    let agent = review_agent_from(root_agent);
    let mut history = Vec::new();
    let mut next_prompt = Message::user(prompt);

    for _ in 0..=16 {
        if cancel.is_cancelled() {
            return Ok(None);
        }
        let outcome = turn_with_backup(
            &agent,
            None,
            &mut history,
            next_prompt,
            session.clone(),
            locks.clone(),
            redact.clone(),
            cwd.clone(),
            Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            cancel.clone(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            false,
            crate::skills::manage::SkillWriteOrigin::BackgroundReview,
            Some(cage.clone()),
            ContextUsageSnapshot::unavailable(),
            crate::engine::deferred::DeferredLog::new(),
            crate::engine::seed_collector::SeedCollector::new(),
            uuid::Uuid::new_v4(),
            None,
            None,
            tx,
        )
        .await?;
        match outcome {
            TurnOutcome::Continue => {
                next_prompt = history
                    .pop()
                    .context("background review requested continuation with empty history")?;
            }
            TurnOutcome::Done => return Ok(last_assistant_summary(&history)),
            _ => return Ok(None),
        }
    }
    Ok(None)
}

fn review_agent_from(root_agent: Agent) -> Agent {
    Agent {
        name: "background_review".to_string(),
        system: REVIEW_SYSTEM.to_string(),
        role_prompt: REVIEW_SYSTEM.to_string(),
        tools: review_tools(),
        model: root_agent.model,
        params: root_agent.params,
        scan_tool_results: false,
        llm_mode: root_agent.llm_mode,
        delegated: false,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        env_overlay: root_agent.env_overlay,
    }
}

fn review_tools() -> ToolBox {
    ToolBox::new()
        .with(Arc::new(crate::tools::skill::SkillTool))
        .with(Arc::new(crate::tools::skill_manage::SkillManageTool))
}

fn recent_history_digest(history: &[Message]) -> String {
    history
        .iter()
        .rev()
        .take(12)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .filter_map(message_digest_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn message_digest_line(message: &Message) -> Option<String> {
    match message {
        Message::User { content } => {
            Some(format!("User: {}", truncate(extract_user_text(content))))
        }
        Message::Assistant { content, .. } => {
            Some(format!("Assistant: {}", truncate(extract_text(content))))
        }
        Message::System { .. } => None,
    }
}

fn truncate(mut text: String) -> String {
    const MAX: usize = 1_200;
    text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.len() > MAX {
        text.truncate(MAX);
        text.push('…');
    }
    text
}

fn last_assistant_summary(history: &[Message]) -> Option<String> {
    history.iter().rev().find_map(|message| match message {
        Message::Assistant { content, .. } => {
            let summary = truncate(extract_text(content));
            (!summary.trim().is_empty()).then_some(summary)
        }
        _ => None,
    })
}

fn scratch_session(cwd: &std::path::Path) -> Result<Arc<crate::session::Session>> {
    let db = crate::db::Db::open_in_memory()?;
    Ok(Arc::new(crate::session::Session::create(
        db,
        cwd.to_path_buf(),
        "background_review",
    )?))
}

const REVIEW_SYSTEM: &str = "You are an isolated background skill-review subagent. You may only preserve reusable procedures by using the skill tools. Never ask for approvals.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_triggers_at_boundary() {
        let mut schedule = ReviewSchedule::default();
        assert!(!schedule.record_idle_boundary("helper", 2));
        assert!(schedule.record_idle_boundary("helper", 2));
        assert!(!schedule.record_idle_boundary("helper", 2));
        assert!(!schedule.record_idle_boundary("helper", 0));
        assert!(!schedule.record_idle_boundary("other", 2));
    }

    #[test]
    fn review_skips_env_dependent_failure() {
        let digest =
            "User hit a transient network outage caused by a missing secret in local environment.";
        assert!(should_skip_capture(digest));
        assert!(build_review_prompt("helper", digest).is_none());
    }

    #[test]
    fn review_scratch_not_persisted() {
        let tmp = tempfile::tempdir().unwrap();
        let real_db = crate::db::Db::open_in_memory().unwrap();
        let real =
            crate::session::Session::create(real_db.clone(), tmp.path().to_path_buf(), "helper")
                .unwrap();
        let scratch = scratch_session(tmp.path()).unwrap();

        assert_ne!(real.id, scratch.id);
        scratch
            .record_event(
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("background_review"),
                None,
                &serde_json::json!({"text": "scratch only"}),
            )
            .unwrap();
        assert!(real_db.list_session_events(real.id).unwrap().is_empty());
    }
}
