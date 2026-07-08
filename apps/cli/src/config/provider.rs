//! Provider/model detection.
//!
//! Resolution order, first wins:
//!   1. `COCKPIT_PROVIDER` + `COCKPIT_MODEL` env vars (or `COCKPIT_MODEL`
//!      alone if it's in `provider/model` form).
//!   2. The effective layered provider config: `active_model`, then the first
//!      configured provider/model from `providers/*.json`.

use std::env;
use std::path::Path;

use crate::config::providers::ConfigDoc;

/// Detected (provider, model) pair, or `None` if nothing is configured.
pub fn detect_provider_model(cwd: &Path) -> Option<(String, String)> {
    detect_from_env().or_else(|| detect_from_configs(cwd))
}

fn detect_from_env() -> Option<(String, String)> {
    let provider = env::var("COCKPIT_PROVIDER")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let model = env::var("COCKPIT_MODEL")
        .ok()
        .filter(|s| !s.trim().is_empty());

    match (provider, model) {
        (Some(provider), Some(model)) => Some((provider, model)),
        (None, Some(model)) => split_provider_model(&model),
        _ => None,
    }
}

fn detect_from_configs(cwd: &Path) -> Option<(String, String)> {
    let cfg = ConfigDoc::load_effective(cwd);
    if let Some(active) = cfg.active_model {
        return Some((active.provider, active.model));
    }
    for (provider, entry) in cfg.providers {
        if let Some(model) = entry.models.first() {
            return Some((provider, model.id.clone()));
        }
    }
    None
}

/// Split a canonical `provider/model` selector into its two halves,
/// trimming each. Returns `None` for a malformed string (no `/`, or an
/// empty provider or model). The slash form is the uniform model-string
/// convention across plans, agent frontmatter, and config.
pub fn split_provider_model(value: &str) -> Option<(String, String)> {
    let (provider, model) = value.split_once('/')?;
    let provider = provider.trim();
    let model = model.trim();
    if provider.is_empty() || model.is_empty() {
        return None;
    }
    Some((provider.to_string(), model.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_detection_uses_active_model_from_config_json() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&cockpit).unwrap();
        std::fs::write(
            cockpit.join("config.json"),
            r#"{"active_model":{"provider":"openai","model":"gpt-5"}}"#,
        )
        .unwrap();
        let _guard = crate::config::dirs::test_support::CockpitConfigOverride::new(
            &cockpit.join("config.json"),
        );

        assert_eq!(
            detect_from_configs(tmp.path()),
            Some(("openai".to_string(), "gpt-5".to_string()))
        );
    }

    #[test]
    fn config_detection_falls_back_to_first_provider_file_model() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        let providers = cockpit.join("providers");
        std::fs::create_dir_all(&providers).unwrap();
        std::fs::write(cockpit.join("config.json"), "{}").unwrap();
        std::fs::write(
            providers.join("anthropic.json"),
            r#"{"url":"https://a","models":[{"id":"opus"},{"id":"haiku"}]}"#,
        )
        .unwrap();
        let _guard = crate::config::dirs::test_support::CockpitConfigOverride::new(
            &cockpit.join("config.json"),
        );

        assert_eq!(
            detect_from_configs(tmp.path()),
            Some(("anthropic".to_string(), "opus".to_string()))
        );
    }

    #[test]
    fn config_detection_ignores_inline_provider_map() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&cockpit).unwrap();
        std::fs::write(
            cockpit.join("config.json"),
            r#"{"providers":{"legacy":{"url":"https://x","models":[{"id":"old"}]}}}"#,
        )
        .unwrap();
        let _guard = crate::config::dirs::test_support::CockpitConfigOverride::new(
            &cockpit.join("config.json"),
        );

        assert_eq!(detect_from_configs(tmp.path()), None);
    }
}
