use super::{App, Overlay};
use crate::tui::agent_runner::AttachedRequest;
use crate::tui::async_action::{
    AsyncActionKey, AsyncActionKind, AsyncActionPayload, AsyncActionPolicy,
};
use crate::tui::skills_pane::{self, SkillsPane, SkillsPaneFetchResult, SkillsPaneSource};
use cockpit_config::extended::SkillsConfig;
use cockpit_core::daemon::proto::{Request, Response, SkillSummary};
use std::path::PathBuf;
use tokio::sync::{mpsc, oneshot};

const SKILLS_LIST_ACTION: &str = "skills.list";

impl App {
    pub(super) fn open_skills_pane(&mut self) {
        let generation = self.next_skills_pane_generation();
        let cwd = self.launch.cwd.clone();
        let skills_config = self.config_snapshot.extended.skills.clone();
        let agent_name = self.launch.agent_name.clone();
        let attached_request_tx = self
            .agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok())
            .map(|runner| runner.attached_request_tx.clone());

        if let Some(attached_request_tx) = attached_request_tx {
            self.overlay = Overlay::Skills(SkillsPane::loading(generation));
            self.start_skills_list_action(
                generation,
                attached_request_tx,
                cwd,
                skills_config,
                agent_name,
            );
            return;
        }

        self.async_actions
            .abort_key(&AsyncActionKey::new(SKILLS_LIST_ACTION));
        let skills = skills_pane::local_skill_summaries(&cwd, &skills_config, &agent_name);
        self.overlay = Overlay::Skills(SkillsPane::ready(
            generation,
            SkillsPaneSource::Local,
            skills,
        ));
    }

    fn next_skills_pane_generation(&mut self) -> u64 {
        self.skills_pane_generation = self.skills_pane_generation.saturating_add(1);
        self.skills_pane_generation
    }

    fn start_skills_list_action(
        &mut self,
        generation: u64,
        attached_request_tx: mpsc::Sender<AttachedRequest>,
        cwd: PathBuf,
        skills_config: SkillsConfig,
        agent_name: String,
    ) {
        self.async_actions.start(
            AsyncActionKind::DaemonRpc(SKILLS_LIST_ACTION),
            AsyncActionPolicy::Replace(AsyncActionKey::new(SKILLS_LIST_ACTION)),
            async move {
                Ok(AsyncActionPayload::Skills(
                    fetch_attached_or_local_skills(
                        generation,
                        attached_request_tx,
                        cwd,
                        skills_config,
                        agent_name,
                    )
                    .await,
                ))
            },
        );
    }
}

async fn fetch_attached_or_local_skills(
    generation: u64,
    attached_request_tx: mpsc::Sender<AttachedRequest>,
    cwd: PathBuf,
    skills_config: SkillsConfig,
    agent_name: String,
) -> SkillsPaneFetchResult {
    match request_attached_skills(&attached_request_tx, &cwd).await {
        Ok(skills) => SkillsPaneFetchResult {
            generation,
            source: SkillsPaneSource::Session,
            skills: Ok(skills),
        },
        Err(_) => SkillsPaneFetchResult {
            generation,
            source: SkillsPaneSource::Local,
            skills: local_skill_summaries_async(cwd, skills_config, agent_name).await,
        },
    }
}

async fn request_attached_skills(
    attached_request_tx: &mpsc::Sender<AttachedRequest>,
    cwd: &std::path::Path,
) -> Result<Vec<SkillSummary>, String> {
    let (response_tx, response_rx) = oneshot::channel();
    attached_request_tx
        .send(AttachedRequest {
            request: Request::ListSkills {
                project_root: cwd.to_string_lossy().into_owned(),
            },
            response_tx,
        })
        .await
        .map_err(|_| "daemon client task has stopped".to_string())?;
    match response_rx
        .await
        .map_err(|_| "daemon client dropped reply channel".to_string())??
    {
        Response::Skills { skills } => Ok(skills),
        other => Err(format!("unexpected daemon response: {other:?}")),
    }
}

async fn local_skill_summaries_async(
    cwd: PathBuf,
    skills_config: SkillsConfig,
    agent_name: String,
) -> Result<Vec<SkillSummary>, String> {
    tokio::task::spawn_blocking(move || {
        skills_pane::local_skill_summaries(&cwd, &skills_config, &agent_name)
    })
    .await
    .map_err(|error| format!("local skill discovery task failed: {error}"))?
}
