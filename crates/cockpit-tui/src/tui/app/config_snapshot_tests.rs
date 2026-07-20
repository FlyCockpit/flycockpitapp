//! Tests for the daemon-pushed config snapshot the TUI renders from
//! (`tui-config-single-source`).
//!
//! `config_snapshot_values_match_previous_resolution` is a **characterization
//! test**: the expected values below were captured against the *client-side*
//! resolution (`load_for_cwd` / `ordered_model_choices`) before any call site
//! was converted to read from the held snapshot. After conversion the same
//! fixtures must resolve identically off the snapshot — this pins behavior
//! parity (criterion 8).

use std::collections::HashMap;
use std::path::Path;

use cockpit_config::extended::LlmMode;

/// The fixed config tree the characterization test resolves against. Written
/// once; both the pre-conversion (client-side) and post-conversion (snapshot)
/// resolutions must produce the committed fixtures below.
fn write_fixture_tree(root: &Path) {
    let cockpit = root.join(".cockpit");
    std::fs::create_dir_all(&cockpit).unwrap();
    std::fs::write(
        cockpit.join("config.json"),
        r#"{"llm_mode":"normal","experimentalMode":true,"dialog":{"lockout_ms":2500},"tui":{"use_emojis":false}}"#,
    )
    .unwrap();
    let provider_path =
        cockpit_config::providers::provider_file_path_for_config(&cockpit.join("config.json"), "p")
            .unwrap();
    std::fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
    std::fs::write(
        &provider_path,
        r#"{"url":"https://example.test","models":[{"id":"a","favorite":true},{"id":"b"}]}"#,
    )
    .unwrap();
}

// ---- Committed fixtures (captured from the client-side resolution) ----------

/// `load_for_cwd(cwd).llm_mode`
const FIXTURE_GLOBAL_LLM_MODE: LlmMode = LlmMode::Normal;
/// `load_for_cwd(cwd).dialog.lockout_ms`
const FIXTURE_DIALOG_LOCKOUT_MS: u64 = 2500;
/// `load_for_cwd(cwd).tui.use_emojis`
const FIXTURE_USE_EMOJIS: bool = false;
/// `load_for_cwd(cwd).experimental_mode`
const FIXTURE_EXPERIMENTAL_MODE: bool = true;
/// `ordered_model_choices(cwd, &counts)` → `(provider_id, model_id, is_favorite, mode)`
fn fixture_model_ordering() -> Vec<(String, String, bool, LlmMode)> {
    vec![
        ("p".to_string(), "a".to_string(), true, LlmMode::Normal),
        ("p".to_string(), "b".to_string(), false, LlmMode::Normal),
    ]
}

#[test]
fn config_snapshot_values_match_previous_resolution() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = cockpit_config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    write_fixture_tree(tmp.path());
    let cwd = tmp.path();

    // NOTE: captured through the *current client-side path*. When the call
    // sites move to the held daemon snapshot this body resolves off the
    // snapshot instead; the committed fixtures above stay identical.
    let extended = cockpit_config::extended::load_for_cwd(cwd);
    assert_eq!(extended.llm_mode, FIXTURE_GLOBAL_LLM_MODE);
    assert_eq!(extended.dialog.lockout_ms, FIXTURE_DIALOG_LOCKOUT_MS);
    assert_eq!(extended.tui.use_emojis, FIXTURE_USE_EMOJIS);
    assert_eq!(extended.experimental_mode, FIXTURE_EXPERIMENTAL_MODE);

    let choices = crate::tui::model_picker::ordered_model_choices(cwd, &HashMap::new()).unwrap();
    let ordering: Vec<(String, String, bool, LlmMode)> = choices
        .into_iter()
        .map(|c| (c.provider_id, c.model_id, c.is_favorite, c.mode))
        .collect();
    assert_eq!(ordering, fixture_model_ordering());
}
