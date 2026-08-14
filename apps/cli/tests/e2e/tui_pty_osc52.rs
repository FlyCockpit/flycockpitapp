use std::fs;

use cockpit_proto::terminal::OSC52_MAX_SEQUENCE_BYTES;

use crate::support::{Osc52Observer, direct_osc52_frame, sha256_hex, tmux_osc52_frame};

#[test]
fn tui_pty_osc52_observer_is_content_safe() {
    let payload = b"observer-only-payload";
    let expected_digest = sha256_hex(payload);
    let expected_len = payload.len();

    let mut observer = Osc52Observer::new();
    observer.feed(&direct_osc52_frame('c', payload));
    observer.feed(&tmux_osc52_frame('c', payload));
    observer.finish();

    assert_eq!(observer.frame_count(), 2);
    for frame in observer.frames() {
        assert_eq!(frame.selector, 'c');
        assert_eq!(frame.decoded_len, expected_len);
        assert_eq!(frame.sha256, expected_digest);
    }

    let debug = format!("{observer:?}");
    assert!(
        !debug
            .as_bytes()
            .windows(payload.len())
            .any(|w| w == payload),
        "Debug output must not contain clipboard plaintext"
    );
    let b64 = base64_std(payload);
    assert!(
        !debug.contains(&b64),
        "Debug output must not contain the base64 payload"
    );

    let mut incomplete = Osc52Observer::new();
    incomplete.feed(b"\x1b]52;c;YWJj");
    assert_eq!(incomplete.frame_count(), 0);
    incomplete.finish();
    assert_eq!(incomplete.rejected_incomplete(), 1);
    assert_eq!(incomplete.frame_count(), 0);

    let mut over_limit = Osc52Observer::new();
    over_limit.feed(b"\x1b]52;c;");
    let chunk = vec![b'A'; 4096];
    let mut fed = 0usize;
    while fed < OSC52_MAX_SEQUENCE_BYTES + 2048 {
        over_limit.feed(&chunk);
        fed += chunk.len();
    }
    assert!(
        over_limit.rejected_over_limit() >= 1,
        "over-limit frames must be rejected"
    );
    assert_eq!(over_limit.frame_count(), 0);
    let debug_over = format!("{over_limit:?}");
    assert!(
        !debug_over.contains(&"A".repeat(64)),
        "over-limit path must not retain payload bytes in Debug"
    );

    let scratch = tempfile::tempdir().expect("observer scratch dir");
    let listed = fs::read_dir(scratch.path()).expect("list observer scratch");
    assert_eq!(listed.count(), 0, "observer must not persist payload files");

    let mut many = Osc52Observer::new();
    for i in 0..40u8 {
        many.feed(&direct_osc52_frame('c', &[b'n', i]));
    }
    assert_eq!(many.frame_count(), 40);
    assert_eq!(many.frames().len(), 32);
    assert_eq!(many.dropped_frames(), 8);
}

fn base64_std(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
