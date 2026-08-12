use std::collections::HashMap;

use crate::config::extended::HarnessConfig;
use crate::redact::{env_scrub_patterns, is_secret_shaped_key};

const BASE_ENV_KEYS: &[&str] = &[
    "PATH",
    "HOME",
    "LANG",
    "TMPDIR",
    "XDG_RUNTIME_DIR",
    "XDG_STATE_HOME",
    "XDG_DATA_HOME",
];

/// Build the child environment for an external harness subprocess.
///
/// External harnesses receive **no Cockpit-provided secret environment
/// value**, regardless of trust custody. This holds for both trusted and
/// untrusted harnesses: a trusted harness may receive its raw prompt
/// (including sensitive/sealed literals), but it never receives secret
/// environment values, credential-store entries, sealed bindings, or former
/// auth-env sentinels. Non-secret session-overlay entries may remain
/// available.
///
/// Filtering is independent of prompt custody so a trusted harness does not
/// become a broad subprocess-secret bypass.
pub fn harness_child_env(
    _cfg: &HarnessConfig,
    session_overlay: Option<&HashMap<String, String>>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for key in BASE_ENV_KEYS {
        push_current_env(&mut out, key);
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

/// Push a session-overlay or base env value into the child environment,
/// filtering out secret-shaped keys, sealed bindings, and shell-injection
/// names. A non-secret overlay entry remains available.
fn push_allowed_value(out: &mut Vec<(String, String)>, key: &str, value: Option<String>) {
    let Some(value) = value else {
        return;
    };
    // No Cockpit-provided secret environment value reaches a harness child.
    // This filters secret-shaped keys (TOKEN/SECRET/KEY/PASSWORD/...),
    // sealed bindings (SEALED_*), and shell-injection names (BASH_ENV, ...).
    if is_secret_env_key(key) {
        return;
    }
    if out.iter().any(|(existing, _)| existing == key) {
        return;
    }
    out.push((key.to_string(), value));
}

/// `true` when `key` names a secret environment variable that must never
/// reach a harness child. Combines the redaction module's secret-shape and
/// shell-injection predicates so the filter stays in lockstep with the
/// redaction table's own secret detection.
fn is_secret_env_key(key: &str) -> bool {
    env_scrub_patterns(key) || is_secret_shaped_key(key)
}

/// Whether a secret environment variable is present in the overlay or
/// process env. Retained for diagnostics; never used to forward a secret.
#[allow(dead_code)]
pub fn harness_secret_env_present(session_overlay: Option<&HashMap<String, String>>) -> bool {
    if let Some(overlay) = session_overlay {
        for key in overlay.keys() {
            if is_secret_env_key(key) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::extended::{ArgvOverflowBehavior, HarnessTrust, PromptInputMode};

    fn cfg() -> HarnessConfig {
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
            trust: HarnessTrust::Untrusted,
            auth_probe_args: vec![],
            always_allow: false,
            timeout_secs: 60,
        }
    }

    #[test]
    fn excludes_process_secret_unless_declared() {
        let guard = crate::test_env::lock();
        guard.set_var("SECRET_API_KEY", "secret");
        let env = harness_child_env(&cfg(), None);
        assert!(!env.iter().any(|(key, _)| key == "SECRET_API_KEY"));
    }

    #[test]
    fn external_harness_never_receives_secret_environment_from_process() {
        // A secret-shaped process env var never reaches the child, even
        // though it is set in the process environment.
        let guard = crate::test_env::lock();
        guard.set_var("OPENAI_API_KEY", "sk-process-secret");
        guard.set_var("ANTHROPIC_API_KEY", "sk-process-secret-2");
        guard.set_var("GITHUB_TOKEN", "ghs_process_token");
        let env = harness_child_env(&cfg(), None);
        assert!(
            !env.iter().any(|(key, _)| key == "OPENAI_API_KEY"),
            "OPENAI_API_KEY reached harness: {env:?}"
        );
        assert!(
            !env.iter().any(|(key, _)| key == "ANTHROPIC_API_KEY"),
            "ANTHROPIC_API_KEY reached harness: {env:?}"
        );
        assert!(
            !env.iter().any(|(key, _)| key == "GITHUB_TOKEN"),
            "GITHUB_TOKEN reached harness: {env:?}"
        );
    }

    #[test]
    fn external_harness_never_receives_secret_environment_from_overlay() {
        // Secret-shaped overlay entries are filtered; a non-secret overlay
        // entry remains available.
        let mut overlay = HashMap::new();
        overlay.insert(
            "OPENAI_API_KEY".to_string(),
            "sk-overlay-secret".to_string(),
        );
        overlay.insert("MY_SERVICE_TOKEN".to_string(), "tok-overlay".to_string());
        overlay.insert("DATABASE_PASSWORD".to_string(), "pw-overlay".to_string());
        overlay.insert("APP_LOCALE".to_string(), "ok-value".to_string());
        overlay.insert("PROJECT_NAME".to_string(), "my-project".to_string());
        let env = harness_child_env(&cfg(), Some(&overlay));
        assert!(
            !env.iter().any(|(key, _)| key == "OPENAI_API_KEY"),
            "OPENAI_API_KEY reached harness: {env:?}"
        );
        assert!(
            !env.iter().any(|(key, _)| key == "MY_SERVICE_TOKEN"),
            "MY_SERVICE_TOKEN reached harness: {env:?}"
        );
        assert!(
            !env.iter().any(|(key, _)| key == "DATABASE_PASSWORD"),
            "DATABASE_PASSWORD reached harness: {env:?}"
        );
        assert!(
            env.iter()
                .any(|(key, value)| key == "APP_LOCALE" && value == "ok-value"),
            "non-secret overlay entry was filtered: {env:?}"
        );
        assert!(
            env.iter()
                .any(|(key, value)| key == "PROJECT_NAME" && value == "my-project"),
            "non-secret overlay entry was filtered: {env:?}"
        );
    }

    #[test]
    fn external_harness_never_receives_secret_environment_for_trusted_harness() {
        // A trusted harness also receives no secret environment value.
        // Trusted prompt custody never permits secret environment delivery.
        let mut overlay = HashMap::new();
        overlay.insert(
            "OPENAI_API_KEY".to_string(),
            "sk-trusted-secret".to_string(),
        );
        overlay.insert("ALLOWED_NONSECRET".to_string(), "visible".to_string());
        let mut trusted_cfg = cfg();
        trusted_cfg.trust = HarnessTrust::Trusted;
        let env = harness_child_env(&trusted_cfg, Some(&overlay));
        assert!(
            !env.iter().any(|(key, _)| key == "OPENAI_API_KEY"),
            "trusted harness received OPENAI_API_KEY: {env:?}"
        );
        assert!(
            env.iter()
                .any(|(key, value)| key == "ALLOWED_NONSECRET" && value == "visible"),
            "trusted harness filtered non-secret: {env:?}"
        );
    }

    #[test]
    fn sealed_bindings_and_noninference_process_egress_are_absent_for_harness() {
        let mut overlay = HashMap::new();
        overlay.insert(
            "SEALED_PROD_TOKEN".to_string(),
            "very-secret-sentinel-value".to_string(),
        );
        overlay.insert("TOKEN".to_string(), "ok".to_string());
        let env = harness_child_env(&cfg(), Some(&overlay));
        assert!(
            !env.iter().any(|(key, _)| key.starts_with("SEALED_")),
            "harness child must never receive SEALED_* keys: {env:?}"
        );
        assert!(
            !env.iter()
                .any(|(_, value)| value.contains("very-secret-sentinel-value"))
        );
        // TOKEN is secret-shaped (ends with _TOKEN), so it is filtered too.
        assert!(
            !env.iter().any(|(key, _)| key == "TOKEN"),
            "harness child must not receive secret-shaped TOKEN: {env:?}"
        );
    }

    #[test]
    fn former_auth_env_sentinels_are_filtered() {
        // Former auth-env sentinels (ANTHROPIC_API_KEY, OPENAI_API_KEY,
        // COPILOT_GITHUB_TOKEN, GH_TOKEN, GITHUB_TOKEN) never reach the child.
        let mut overlay = HashMap::new();
        overlay.insert("ANTHROPIC_API_KEY".to_string(), "sk-ant".to_string());
        overlay.insert("OPENAI_API_KEY".to_string(), "sk-oai".to_string());
        overlay.insert(
            "COPILOT_GITHUB_TOKEN".to_string(),
            "ghs_copilot".to_string(),
        );
        overlay.insert("GH_TOKEN".to_string(), "ghs_gh".to_string());
        overlay.insert("GITHUB_TOKEN".to_string(), "ghs_github".to_string());
        let env = harness_child_env(&cfg(), Some(&overlay));
        for key in [
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "COPILOT_GITHUB_TOKEN",
            "GH_TOKEN",
            "GITHUB_TOKEN",
        ] {
            assert!(
                !env.iter().any(|(k, _)| k == key),
                "former auth-env sentinel {key} reached harness: {env:?}"
            );
        }
    }

    #[test]
    fn shell_injection_names_are_filtered() {
        let mut overlay = HashMap::new();
        overlay.insert("BASH_ENV".to_string(), "evil".to_string());
        overlay.insert("ENV".to_string(), "evil2".to_string());
        overlay.insert("NODE_OPTIONS".to_string(), "evil3".to_string());
        overlay.insert("SAFE_VAR".to_string(), "ok".to_string());
        let env = harness_child_env(&cfg(), Some(&overlay));
        assert!(!env.iter().any(|(k, _)| k == "BASH_ENV"), "{env:?}");
        assert!(!env.iter().any(|(k, _)| k == "ENV"), "{env:?}");
        assert!(!env.iter().any(|(k, _)| k == "NODE_OPTIONS"), "{env:?}");
        assert!(
            env.iter().any(|(k, v)| k == "SAFE_VAR" && v == "ok"),
            "{env:?}"
        );
    }
}
