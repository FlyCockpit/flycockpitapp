//! Static contract for the hermetic offline/no-account process harness.
//! The stronger-machine validation agent executes these scenarios; this test
//! keeps their required coverage and network policy from silently shrinking.

const PLAN: &str = include_str!("fixtures/offline-no-account-scenarios-v1.json");
const HERMETIC: &str = include_str!("e2e/support/hermetic.rs");

#[test]
fn offline_no_account_plan_is_complete_and_hermetic() {
    let plan: serde_json::Value = serde_json::from_str(PLAN).unwrap();
    assert_eq!(plan["profile"], "local-v0.1");
    assert_eq!(plan["environment"]["freshHome"], true);
    assert_eq!(
        plan["environment"]["flycockpitEndpoints"],
        "poison-loopback"
    );
    let scenarios = plan["scenarios"].as_array().unwrap();
    for required in [
        "local-help-has-no-account-sync-relay",
        "missing-provider-is-stable-and-does-not-contact-flycockpit",
        "fake-loopback-provider-is-the-only-network-peer",
        "daemon-start-and-tui-first-paint",
        "daemon-restart-and-session-resume",
        "settings-save-through-daemon",
        "redacted-session-export",
        "data-directories-and-uninstall-disclosure",
    ] {
        assert!(
            scenarios.iter().any(|value| value == required),
            "missing {required}"
        );
    }
    for seam in [
        "env_clear()",
        "DUMMY_PROVIDER_URL",
        "EXCLUDED_POISON_KEYS",
        "IsolatedHome",
    ] {
        assert!(HERMETIC.contains(seam), "hermetic launcher lacks {seam}");
    }
    assert!(plan["forbiddenNetworkLabels"].as_array().unwrap().len() >= 5);
}
