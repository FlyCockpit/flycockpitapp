use super::{App, Overlay};
use crate::tui::agent_runner::AttachedRequestBinding;
use crate::tui::async_action::{
    AsyncActionKey, AsyncActionKind, AsyncActionPayload, AsyncActionPolicy,
};
use crate::tui::skills_pane::{self, SkillsPane, SkillsPaneFetchResult, SkillsPaneSource};
use cockpit_config::extended::SkillsConfig;
use cockpit_core::daemon::proto::{Request, Response, SkillSummary};
use std::path::PathBuf;

const SKILLS_LIST_ACTION: &str = "skills.list";

impl App {
    pub(super) fn open_skills_pane(&mut self) {
        let generation = self.next_skills_pane_generation();
        let cwd = self.launch.cwd.clone();
        let skills_config = self.config_snapshot.extended.skills.clone();
        let agent_name = self.launch.agent_name.clone();
        let trust_policy = cockpit_config::trust::current_workspace_trust_policy();
        let attached_request = self
            .agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok())
            .map(|runner| runner.attached_request_binding());

        if let Some(attached_request) = attached_request {
            self.overlay = Overlay::Skills(SkillsPane::loading(generation));
            self.start_skills_list_action(
                generation,
                attached_request,
                cwd,
                skills_config,
                agent_name,
                trust_policy,
            );
            return;
        }

        self.async_actions
            .abort_key(&AsyncActionKey::new(SKILLS_LIST_ACTION));
        let skills =
            local_skill_summaries_with_policy(&cwd, &skills_config, &agent_name, trust_policy);
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
        attached_request: AttachedRequestBinding,
        cwd: PathBuf,
        skills_config: SkillsConfig,
        agent_name: String,
        trust_policy: Option<cockpit_config::trust::WorkspaceTrustPolicy>,
    ) {
        self.async_actions.start(
            AsyncActionKind::DaemonRpc(SKILLS_LIST_ACTION),
            AsyncActionPolicy::Replace(AsyncActionKey::new(SKILLS_LIST_ACTION)),
            async move {
                Ok(AsyncActionPayload::Skills(
                    fetch_attached_or_local_skills(
                        generation,
                        attached_request,
                        cwd,
                        skills_config,
                        agent_name,
                        trust_policy,
                    )
                    .await,
                ))
            },
        );
    }
}

async fn fetch_attached_or_local_skills(
    generation: u64,
    attached_request: AttachedRequestBinding,
    cwd: PathBuf,
    skills_config: SkillsConfig,
    agent_name: String,
    trust_policy: Option<cockpit_config::trust::WorkspaceTrustPolicy>,
) -> SkillsPaneFetchResult {
    match request_attached_skills(&attached_request, &cwd).await {
        Ok(skills) => SkillsPaneFetchResult {
            generation,
            source: SkillsPaneSource::Session,
            skills: Ok(skills),
        },
        Err(_) => SkillsPaneFetchResult {
            generation,
            source: SkillsPaneSource::Local,
            skills: local_skill_summaries_async(cwd, skills_config, agent_name, trust_policy).await,
        },
    }
}

async fn request_attached_skills(
    attached_request: &AttachedRequestBinding,
    cwd: &std::path::Path,
) -> Result<Vec<SkillSummary>, String> {
    let response = attached_request
        .request(Request::ListSkills {
            project_root: cwd.to_string_lossy().into_owned(),
        })
        .await?;
    match response {
        Response::Skills { skills } => Ok(skills),
        other => Err(format!("unexpected daemon response: {other:?}")),
    }
}

async fn local_skill_summaries_async(
    cwd: PathBuf,
    skills_config: SkillsConfig,
    agent_name: String,
    trust_policy: Option<cockpit_config::trust::WorkspaceTrustPolicy>,
) -> Result<Vec<SkillSummary>, String> {
    tokio::task::spawn_blocking(move || {
        local_skill_summaries_with_policy(&cwd, &skills_config, &agent_name, trust_policy)
    })
    .await
    .map_err(|error| format!("local skill discovery task failed: {error}"))?
}

fn local_skill_summaries_with_policy(
    cwd: &std::path::Path,
    skills_config: &SkillsConfig,
    agent_name: &str,
    trust_policy: Option<cockpit_config::trust::WorkspaceTrustPolicy>,
) -> Result<Vec<SkillSummary>, String> {
    match trust_policy {
        Some(policy) => cockpit_config::trust::with_workspace_trust_policy(policy, || {
            skills_pane::local_skill_summaries(cwd, skills_config, agent_name)
        }),
        None => skills_pane::local_skill_summaries(cwd, skills_config, agent_name),
    }
}
