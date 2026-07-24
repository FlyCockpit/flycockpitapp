use std::collections::HashMap;

use crate::config::extended::HarnessConfig;

const BASE_ENV_KEYS: &[&str] = &[
    "PATH",
    "HOME",
    "LANG",
    "TMPDIR",
    "XDG_RUNTIME_DIR",
    "XDG_STATE_HOME",
    "XDG_DATA_HOME",
];

pub fn harness_child_env(
    cfg: &HarnessConfig,
    session_overlay: Option<&HashMap<String, String>>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for key in BASE_ENV_KEYS {
        push_current_env(&mut out, key);
    }
    for key in &cfg.auth_env_vars {
        push_allowed_value(&mut out, key, env_value_for(key, session_overlay));
    }
    if let Some(overlay) = session_overlay {
        let mut keys: Vec<&String> = overlay.keys().collect();
        keys.sort();
        for key in keys {
            push_allowed_value(&mut out, key, overlay.get(key).cloned());
        }
    }
    out
}

pub fn harness_auth_env_present(
    cfg: &HarnessConfig,
    session_overlay: Option<&HashMap<String, String>>,
) -> bool {
    cfg.auth_env_vars.iter().any(|key| {
        env_value_for(key, session_overlay)
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    })
}

fn env_value_for(key: &str, session_overlay: Option<&HashMap<String, String>>) -> Option<String> {
    session_overlay
        .and_then(|overlay| overlay.get(key).cloned())
        .or_else(|| std::env::var(key).ok())
}

fn push_current_env(out: &mut Vec<(String, String)>, key: &str) {
    if let Ok(value) = std::env::var(key) {
        push_allowed_value(out, key, Some(value));
    }
}

fn push_allowed_value(out: &mut Vec<(String, String)>, key: &str, value: Option<String>) {
    let Some(value) = value else {
        return;
    };
    if out.iter().any(|(existing, _)| existing == key) {
        return;
    }
    out.push((key.to_string(), value));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::extended::{ArgvOverflowBehavior, PromptInputMode};

    fn cfg(auth_env_vars: Vec<&str>) -> HarnessConfig {
        HarnessConfig {
            command: "sh".to_string(),
            args: vec![],
            prompt_input: PromptInputMode::Stdin,
            argv_overflow: ArgvOverflowBehavior::SpillToTempfile,
            model_args: vec![],
            default_model: None,
            models: vec![],
            model_list_args: vec![],
            supports_json_output: false,
            json_output_args: vec![],
            supports_agent_file: false,
            agent_file_args: vec![],
            agent_file_env: None,
            auth_env_vars: auth_env_vars.into_iter().map(str::to_string).collect(),
            auth_probe_args: vec![],
            always_allow: false,
            timeout_secs: 60,
        }
    }

    #[test]
    fn excludes_process_secret_unless_declared() {
        let guard = crate::test_env::lock();
        guard.set_var("SECRET_API_KEY", "secret");
        let env = harness_child_env(&cfg(vec![]), None);
        assert!(!env.iter().any(|(key, _)| key == "SECRET_API_KEY"));
    }

    #[test]
    fn declared_auth_var_is_included() {
        let guard = crate::test_env::lock();
        guard.set_var("SECRET_API_KEY", "secret");
        let env = harness_child_env(&cfg(vec!["SECRET_API_KEY"]), None);
        assert!(
            env.iter()
                .any(|(key, value)| key == "SECRET_API_KEY" && value == "secret")
        );
    }

    #[test]
    fn session_overlay_overrides_process_env() {
        let guard = crate::test_env::lock();
        guard.set_var("TOKEN", "process");
        let mut overlay = HashMap::new();
        overlay.insert("TOKEN".to_string(), "overlay".to_string());
        let env = harness_child_env(&cfg(vec!["TOKEN"]), Some(&overlay));
        assert!(
            env.iter()
                .any(|(key, value)| key == "TOKEN" && value == "overlay")
        );
    }
}
