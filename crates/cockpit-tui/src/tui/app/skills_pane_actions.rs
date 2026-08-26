use super::{App, Overlay};
use crate::tui::agent_runner::AttachedRequestBinding;
use crate::tui::async_action::{
    AsyncActionKey, AsyncActionKind, AsyncActionPayload, AsyncActionPolicy,
};
use crate::tui::skills_pane::{SkillsPane, SkillsPaneFetchResult, SkillsPaneSource};
use cockpit_proto::{Request, Response};
use std::path::PathBuf;

const SKILLS_LIST_ACTION: &str = "skills.list";

fn next_skills_fetch_generation(current: u64) -> u64 {
    current
        .checked_add(1)
        .expect("skills pane fetch generation exhausted")
}

impl App {
    pub(super) fn open_skills_pane(&mut self) {
        let generation = self.next_skills_pane_generation();
        let cwd = self.launch.cwd.clone();
        let agent_name = self.launch.agent_name.clone();
        let attached_request = self
            .agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok())
            .map(|runner| runner.attached_request_binding());

        if let Some(attached_request) = attached_request {
            self.overlay = Overlay::Skills(SkillsPane::loading(generation));
            self.start_skills_list_action(generation, attached_request, cwd, agent_name);
            return;
        }

        self.async_actions
            .abort_key(&AsyncActionKey::new(SKILLS_LIST_ACTION));
        // Pre-attach: inventory is explicitly unavailable (no local walk).
        self.overlay = Overlay::Skills(SkillsPane::ready(
            generation,
            SkillsPaneSource::Session,
            Err("inventory unavailable until attached".into()),
        ));
        // ready() does not need a bundle field; fetch result does.
    }

    fn next_skills_pane_generation(&mut self) -> u64 {
        self.skills_pane_generation = next_skills_fetch_generation(self.skills_pane_generation);
        self.skills_pane_generation
    }

    fn start_skills_list_action(
        &mut self,
        generation: u64,
        attached_request: AttachedRequestBinding,
        cwd: PathBuf,
        agent_name: String,
    ) {
        self.async_actions.start(
            AsyncActionKind::DaemonRpc(SKILLS_LIST_ACTION),
            AsyncActionPolicy::Replace(AsyncActionKey::new(SKILLS_LIST_ACTION)),
            async move {
                Ok(AsyncActionPayload::Skills(
                    fetch_attached_skills(generation, attached_request, cwd, agent_name).await,
                ))
            },
        );
    }
}

#[cfg(test)]
mod generation_tests {
    use super::next_skills_fetch_generation;

    #[test]
    fn skills_fetch_generation_never_saturates_or_reuses_maximum() {
        assert_eq!(next_skills_fetch_generation(0), 1);
        assert_eq!(next_skills_fetch_generation(u64::MAX - 1), u64::MAX);
        assert!(
            std::panic::catch_unwind(|| next_skills_fetch_generation(u64::MAX)).is_err(),
            "exhaustion must fail closed before a stale generation can be reused"
        );
    }
}

async fn fetch_attached_skills(
    generation: u64,
    attached_request: AttachedRequestBinding,
    cwd: PathBuf,
    agent_name: String,
) -> SkillsPaneFetchResult {
    match request_attached_bundle(&attached_request, &cwd, &agent_name).await {
        Ok(response) => {
            let skills = match &response {
                Response::InventoryBundle { skills, .. } => Ok(skills.clone()),
                other => Err(format!("unexpected daemon response: {other:?}")),
            };
            SkillsPaneFetchResult {
                generation,
                source: SkillsPaneSource::Session,
                skills,
            }
        }
        Err(error) => SkillsPaneFetchResult {
            generation,
            source: SkillsPaneSource::Session,
            skills: Err(error),
        },
    }
}

async fn request_attached_bundle(
    attached_request: &AttachedRequestBinding,
    cwd: &std::path::Path,
    agent_name: &str,
) -> Result<Response, String> {
    attached_request
        .request(Request::GetInventoryBundle {
            project_root: cwd.to_string_lossy().into_owned(),
            session_id: attached_request.session_id(),
            selected_agent: agent_name.to_string(),
        })
        .await
}
