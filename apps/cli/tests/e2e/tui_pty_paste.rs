use std::time::Duration;

use crate::support::{
    COMPOSER_PLACEHOLDER, HermeticCockpit, HermeticProfile, fragmented_bracketed_paste,
};

#[test]
fn tui_pty_bracketed_paste_protocol() {
    let mut session = HermeticCockpit::launch_ready(HermeticProfile::Default);
    assert!(
        session.snapshot().contains(COMPOSER_PLACEHOLDER),
        "ready composer required before paste"
    );

    let payload = "pty-paste-literal-xyz";
    for frame in fragmented_bracketed_paste(&["pty-paste-", "literal-xyz"]) {
        session.write_bytes(&frame);
    }

    session
        .wait_until_screen(
            "reconstructed literal paste in composer",
            Duration::from_secs(5),
            |screen| screen.contains(payload),
        )
        .expect("bracketed paste reconstructed");
    let contents = session.snapshot().contents();
    assert!(
        contents.contains(payload),
        "composer must show the reconstructed literal payload:\n{contents}"
    );
    assert_eq!(
        contents.matches(payload).count(),
        1,
        "payload must appear once before submit:\n{contents}"
    );
}
