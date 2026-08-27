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
    config: crate::daemon::session_worker::SessionConfigHandle,
    redact: Arc<crate::redact::RedactionTable>,
    resolver: Arc<dyn crate::redact::protected_redaction_history::RedactionKeyResolver>,
    tx: mpsc::Sender<TurnEvent>,
) -> Option<RunningReview> {
    let digest = recent_history_digest(&recent_history);
    let prompt = build_review_prompt(&assistant_name, &digest)?;
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let handle = tokio::spawn(async move {
        match run_review_turn(
            root_agent,
            cwd,
            config,
            redact,
            resolver,
            prompt,
            task_cancel,
            &tx,
        )
        .await
        {
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
- You may use only `skill`, `skill_manage`, `read`, `edit`, and `write`.
- Prefer updating an existing relevant skill before creating a new one.
- Before deleting or removing a support file for an existing skill, load that
  skill with `skill`.
- To change SKILL.md or write support files, first load the skill with `skill`,
  then use `read` and `edit` or `write` on the package path shown by `skill`.
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

#[allow(clippy::too_many_arguments)]
async fn run_review_turn(
    root_agent: Agent,
    cwd: std::path::PathBuf,
    config: crate::daemon::session_worker::SessionConfigHandle,
    redact: Arc<crate::redact::RedactionTable>,
    resolver: Arc<dyn crate::redact::protected_redaction_history::RedactionKeyResolver>,
    prompt: String,
    cancel: CancellationToken,
    tx: &mpsc::Sender<TurnEvent>,
) -> Result<Option<String>> {
    let session = scratch_session(&cwd, resolver)?;
    // This caged background utility intentionally retains its isolated
    // in-memory database; a daemon journal is bound to a different DB and
    // cannot safely be attached.
    session.allow_unjournaled_inference(
        crate::session::UnjournaledInferenceReason::CagedSelfReviewUtility,
    );
    let locks = Arc::new(crate::locks::LockManager::from_db(session.db.clone()).await?);
    let cage = ReviewCage::skills_review_with_package_roots(review_package_roots(
        &cwd,
        &config.extended().skills,
    ));
    let max_dispatches = cage.max_dispatches();
    let agent = review_agent_from(root_agent);
    let mut history = Vec::new();
    let mut next_prompt = Message::user(prompt);

    for _ in 0..max_dispatches {
        if cancel.is_cancelled() {
            return Ok(None);
        }
        let outcome = turn_with_backup(
            &agent,
            None,
            &[],
            &mut history,
            next_prompt,
            session.clone(),
            locks.clone(),
            redact.clone(),
            cwd.clone(),
            config.clone(),
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
            uuid::Uuid::new_v4(),
            None,
            None,
            None,
            tx,
            None,
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
        tool_steering: root_agent.tool_steering,
        posture: root_agent.posture.clone(),
        context_policy: None,
        lock_identity: root_agent.lock_identity,
        assistant_identity_prefix: root_agent.assistant_identity_prefix,
        write_scope: root_agent.write_scope,
        delegated: false,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        vnext_grant: None,
        env_overlay: root_agent.env_overlay,
    }
}

fn review_tools() -> ToolBox {
    ToolBox::new()
        .with(Arc::new(crate::tools::edit::EditTool))
        .with(Arc::new(crate::tools::read::ReadTool))
        .with(Arc::new(crate::tools::skill::SkillTool))
        .with(Arc::new(crate::tools::skill_manage::SkillManageTool))
        .with(Arc::new(crate::tools::write::WriteTool))
}

fn review_package_roots(
    cwd: &std::path::Path,
    skills: &crate::config::extended::SkillsConfig,
) -> Vec<std::path::PathBuf> {
    crate::skills::discover(cwd, skills)
        .unwrap_or_default()
        .into_iter()
        .map(|skill| crate::skills::package_root(&skill).to_path_buf())
        .collect()
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

fn scratch_session(
    cwd: &std::path::Path,
    resolver: Arc<dyn crate::redact::protected_redaction_history::RedactionKeyResolver>,
) -> Result<Arc<crate::session::Session>> {
    let db = crate::db::Db::open_in_memory()?;
    let vault = crate::secure_key::open_for_db(&db)
        .map_err(|e| anyhow::anyhow!("opening isolated review vault: {e}"))?;
    Ok(Arc::new(crate::session::Session::create(
        db,
        cwd.to_path_buf(),
        "background_review",
        resolver,
        vault,
    )?))
}

const REVIEW_SYSTEM: &str = "You are an isolated background skill-review subagent. You may preserve reusable procedures with `skill`, `skill_manage`, `read`, `edit`, and `write` only. Never ask for approvals.";

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[tokio::test]
    async fn review_triggers_at_boundary() {
        let mut schedule = ReviewSchedule::default();
        assert!(!schedule.record_idle_boundary("helper", 2));
        assert!(schedule.record_idle_boundary("helper", 2));
        assert!(!schedule.record_idle_boundary("helper", 2));
        assert!(!schedule.record_idle_boundary("helper", 0));
        assert!(!schedule.record_idle_boundary("other", 2));
    }

    #[tokio::test]
    async fn review_skips_env_dependent_failure() {
        let digest =
            "User hit a transient network outage caused by a missing secret in local environment.";
        assert!(should_skip_capture(digest));
        assert!(build_review_prompt("helper", digest).is_none());
    }

    #[tokio::test]
    async fn review_scratch_not_persisted() {
        let tmp = tempfile::tempdir().unwrap();
        let real_db = crate::db::Db::open_in_memory().unwrap();
        let real = crate::session::Session::create_for_test(
            real_db.clone(),
            tmp.path().to_path_buf(),
            "helper",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let scratch =
            scratch_session(tmp.path(), crate::session::test_redaction_key_resolver()).unwrap();

        assert_ne!(real.id, scratch.id);
        scratch
            .record_event(
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("background_review"),
                None,
                &serde_json::json!({"text": "scratch only"}),
            )
            .await
            .unwrap();
        assert!(
            real_db
                .list_session_events(real.id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn review_toolbox_is_exactly_the_expected_set() {
        let toolbox = review_tools();
        let names: BTreeSet<&str> = toolbox.names().into_iter().collect();
        assert_eq!(
            names,
            BTreeSet::from(["edit", "read", "skill", "skill_manage", "write"])
        );
    }

    #[test]
    fn review_prompt_describes_file_tool_flow() {
        let prompt = build_review_prompt("helper", "Assistant learned a reusable workflow.")
            .expect("prompt");
        assert!(prompt.contains("`skill`, `skill_manage`, `read`, `edit`, and `write`"));
        assert!(prompt.contains("first load the skill with `skill`"));
        assert!(prompt.contains("use `read` and `edit` or `write`"));
        assert!(REVIEW_SYSTEM.contains("`read`, `edit`, and `write`"));
    }
}
