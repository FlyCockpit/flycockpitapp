use super::*;

impl App {
    pub(super) fn sync_active_agent(&mut self) {
        let (name, path) = {
            let Some(Ok(runner)) = self.agent_runner.as_ref() else {
                return;
            };
            (
                cockpit_core::sync::lock_or_recover(&runner.active_agent).clone(),
                cockpit_core::sync::lock_or_recover(&runner.active_agent_path).clone(),
            )
        };
        let mut changed = false;
        if name != self.launch.agent_name {
            self.launch.agent_name = name;
            changed = true;
        }
        if !path.is_empty() && path != self.agent_path {
            self.agent_path = path;
        }
        if changed {
            self.refresh_skill_commands();
        }
    }

    /// Return the skill inventory visible to the current agent. Once attached,
    /// the daemon publishes names filtered against the exact live toolbox;
    /// before that point discovery uses the agent definition as a best-effort
    /// startup approximation.
    pub(super) fn visible_skills(&self) -> Vec<cockpit_core::skills::Skill> {
        let extended = &self.config_snapshot.extended;
        let exact_names = self
            .agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok())
            .and_then(|runner| runner.skill_inventory_names.lock().unwrap().clone());
        if let Some(exact_names) = exact_names {
            cockpit_core::skills::discover(&self.launch.cwd, &extended.skills)
                .unwrap_or_default()
                .into_iter()
                .filter(|skill| exact_names.contains(&skill.frontmatter.name))
                .collect()
        } else {
            cockpit_core::skills::discover_for_agent(
                &self.launch.cwd,
                &extended.skills,
                &self.launch.agent_name,
            )
            .unwrap_or_default()
        }
    }

    /// Rebuild conditional skill slash entries after the root agent changes.
    /// The active agent's declared tool grant is the pre-spawn inventory seam;
    /// actual skill loading rechecks against the live toolbox.
    pub(super) fn refresh_skill_commands(&mut self) {
        self.skill_commands = bare_skill_commands_from(self.visible_skills());
    }

    pub(super) fn push_agent_path_child(&mut self, parent: &str, child: &str) {
        if let Some(parent_idx) = self.agent_path.iter().position(|name| name == parent) {
            self.agent_path.truncate(parent_idx + 1);
        } else {
            self.agent_path.clear();
            self.agent_path.push(self.launch.agent_name.clone());
        }
        self.agent_path.push(child.to_string());
        self.launch.agent_name = child.to_string();
        self.refresh_skill_commands();
    }

    pub(super) fn pop_agent_path_for_report(&mut self, agent: &str) {
        if let Some(agent_idx) = self.agent_path.iter().position(|name| name == agent) {
            self.agent_path.truncate(agent_idx);
        } else {
            self.agent_path.pop();
        }
        if self.agent_path.is_empty() {
            self.agent_path.push(self.launch.agent_name.clone());
        }
        if let Some(current) = self.agent_path.last() {
            self.launch.agent_name = current.clone();
            self.refresh_skill_commands();
        }
    }
}
