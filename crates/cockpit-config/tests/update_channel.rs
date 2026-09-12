//! Closed update-channel parsing contract.

use std::fs;

use cockpit_config::config::dirs::{CONFIG_FILE, global_config_dir};
use cockpit_config::config::update_channel::{COCKPIT_UPDATES_ENV, UpdateChannel};
use cockpit_config::extended::load_installation_update_channel;

#[test]
fn closed_channel_parse() {
    assert_eq!(
        UpdateChannel::from_label("auto").unwrap(),
        UpdateChannel::Auto
    );
    assert_eq!(
        UpdateChannel::from_label("notify").unwrap(),
        UpdateChannel::Notify
    );
    assert_eq!(
        UpdateChannel::from_label("off").unwrap(),
        UpdateChannel::Off
    );
    assert_eq!(
        UpdateChannel::from_label("AUTO").unwrap(),
        UpdateChannel::Auto
    );

    for invalid in ["", "on", "auto-notify", "disabled", "cargo-dist"] {
        assert!(
            UpdateChannel::from_label(invalid).is_err(),
            "expected rejection for `{invalid}`"
        );
    }

    let guard = cockpit_test_support::TestEnvGuard::blocking_lock();
    guard.set_var(COCKPIT_UPDATES_ENV, "off");
    assert_eq!(
        UpdateChannel::resolve_effective(UpdateChannel::Auto).unwrap(),
        UpdateChannel::Off
    );
    guard.set_var(COCKPIT_UPDATES_ENV, "notify");
    assert_eq!(
        UpdateChannel::resolve_effective(UpdateChannel::Auto).unwrap(),
        UpdateChannel::Notify
    );
    guard.set_var(COCKPIT_UPDATES_ENV, "disabled");
    assert!(
        UpdateChannel::resolve_effective(UpdateChannel::Auto).is_err(),
        "unsupported COCKPIT_UPDATES values must fail closed"
    );
    guard.set_var(COCKPIT_UPDATES_ENV, "");
    assert!(
        UpdateChannel::resolve_effective(UpdateChannel::Auto).is_err(),
        "empty COCKPIT_UPDATES values must fail closed"
    );
    guard.set_var(COCKPIT_UPDATES_ENV, "   ");
    assert!(
        UpdateChannel::resolve_effective(UpdateChannel::Auto).is_err(),
        "whitespace-only COCKPIT_UPDATES values must fail closed"
    );
    guard.remove_var(COCKPIT_UPDATES_ENV);
    assert_eq!(
        UpdateChannel::resolve_effective(UpdateChannel::Auto).unwrap(),
        UpdateChannel::Auto
    );
}

#[test]
fn installation_update_channel_honors_closed_parser_spellings() {
    let guard = cockpit_test_support::TestEnvGuard::blocking_lock();
    guard.remove_var(COCKPIT_UPDATES_ENV);

    let config_dir = global_config_dir().expect("global config dir");
    fs::create_dir_all(&config_dir).expect("create global config dir");
    fs::write(config_dir.join(CONFIG_FILE), r#"{"updates":"AUTO"}"#)
        .expect("write installation config");

    assert_eq!(
        load_installation_update_channel().expect("load installation update channel"),
        UpdateChannel::Auto
    );
}
