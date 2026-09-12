//! Closed update-channel parsing contract.

use cockpit_config::config::update_channel::{COCKPIT_UPDATES_ENV, UpdateChannel};

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
        UpdateChannel::resolve_effective(UpdateChannel::Auto),
        UpdateChannel::Off
    );
    guard.remove_var(COCKPIT_UPDATES_ENV);
    assert_eq!(
        UpdateChannel::resolve_effective(UpdateChannel::Auto),
        UpdateChannel::Auto
    );
}
