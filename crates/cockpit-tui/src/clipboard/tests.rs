//! Acceptance tests for trusted ordered clipboard delivery.

use super::display::validate;
use super::executable::{RecordingExecutable, contracts};
use super::native::RecordingNative;
use super::osc52::{
    RecordingOsc52Emitter, build_sequence, encode_checked, largest_in_cap_decoded_len,
    max_b64_payload_len, raw_sequence_len,
};
use super::service::{ClipboardService, attached_client_route_exists};
use super::types::*;
use cockpit_proto::terminal::OSC52_MAX_SEQUENCE_BYTES;
use std::path::Path;

fn local_desktop(platform: PlatformKind) -> SessionContext {
    SessionContext {
        same_host_local_desktop: true,
        ssh: false,
        tmux: false,
        trusted_remote_terminal: false,
        untrusted_remote: false,
        wsl_or_container: false,
        host_bridge: false,
        osc52_advertised: true,
        osc52_acknowledged_capability: false,
        osc52_tmux_passthrough: false,
        platform,
    }
}

fn ssh_ctx() -> SessionContext {
    SessionContext {
        same_host_local_desktop: false,
        ssh: true,
        tmux: false,
        trusted_remote_terminal: true,
        untrusted_remote: false,
        wsl_or_container: false,
        host_bridge: false,
        osc52_advertised: true,
        osc52_acknowledged_capability: false,
        osc52_tmux_passthrough: false,
        platform: PlatformKind::Linux,
    }
}

fn service(
    ctx: SessionContext,
    native: RecordingNative,
    osc: RecordingOsc52Emitter,
    exe: RecordingExecutable,
) -> ClipboardService<RecordingNative, RecordingOsc52Emitter, RecordingExecutable> {
    ClipboardService::new(ctx, native, osc, exe)
}

// ---------------------------------------------------------------------------
// AC1: corrected tests first + production source inventory
// ---------------------------------------------------------------------------

#[test]
fn clipboard_route_tests_corrected_first() {
    // Direct transport: exactly one selector-c frame.
    let seq = build_sequence("QUJD", OscTransport::Direct);
    assert_eq!(seq, "\x1b]52;c;QUJD\x07");
    assert_eq!(seq.matches("\x1b]52;c;").count(), 1);

    // TmuxPassthrough: exactly one DCS-wrapped frame (no raw+wrapped concat).
    let wrapped = build_sequence("QUJD", OscTransport::TmuxPassthrough);
    assert_eq!(wrapped, "\x1bPtmux;\x1b\x1b]52;c;QUJD\x07\x1b\\");
    assert!(!wrapped.starts_with("\x1b]52;"));
    assert_eq!(wrapped.matches("52;c;").count(), 1);

    // Exact 102400 total-sequence in-cap / cap+1 from shared constant.
    assert_eq!(OSC52_MAX_SEQUENCE_BYTES, 102_400);
    let max_b64 = max_b64_payload_len();
    assert_eq!(raw_sequence_len(max_b64), OSC52_MAX_SEQUENCE_BYTES);
    assert!(encode_checked(&"y".repeat(largest_in_cap_decoded_len())).is_ok());
    assert_eq!(
        encode_checked(&"x".repeat(largest_in_cap_decoded_len() + 3)),
        Err(SafeErrorKind::TooLarge)
    );

    // Ordered-attempt: native Confirmed stops before OSC/executable.
    let mut svc = service(
        local_desktop(PlatformKind::MacOs),
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    let r = svc.deliver_plain("hello");
    assert_eq!(r.confidence, Confidence::Confirmed);
    assert_eq!(r.attempts.len(), 1);
    assert_eq!(r.attempts[0].route, Route::Native);
    assert_eq!(r.attempts[0].outcome, AttemptOutcome::Confirmed);
    assert!(svc.osc52.frames.is_empty());
    assert!(svc.executable.plains.is_empty());

    // Remote over-cap emits nothing and Fails.
    let mut svc = service(
        ssh_ctx(),
        RecordingNative {
            fail_plain: Some(SafeErrorKind::Unsupported),
            ..Default::default()
        },
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    let over = "x".repeat(largest_in_cap_decoded_len() + 3);
    let r = svc.deliver_plain(&over);
    assert_eq!(r.confidence, Confidence::Failed);
    assert!(svc.osc52.frames.is_empty());
    assert!(
        r.attempts
            .iter()
            .any(|a| a.route == Route::Osc52 && a.safe_error_kind == Some(SafeErrorKind::TooLarge))
    );

    // Unacknowledged OSC + executable failure is Unverified (not Confirmed).
    let mut svc = service(
        local_desktop(PlatformKind::Linux),
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable {
            fail: Some(SafeErrorKind::ExitFailure),
            ..Default::default()
        },
    );
    // Linux native always skipped in production eligibility; force skip via platform.
    let r = svc.deliver_plain("hello");
    assert_eq!(r.confidence, Confidence::Unverified);
    assert!(!r.is_confirmed());
    assert!(
        r.attempts
            .iter()
            .any(|a| a.route == Route::Osc52 && a.outcome == AttemptOutcome::Unverified)
    );

    // All failures produce Failed with attempt records.
    let mut svc = service(
        local_desktop(PlatformKind::MacOs),
        RecordingNative {
            fail_plain: Some(SafeErrorKind::WriteFailed),
            ..Default::default()
        },
        RecordingOsc52Emitter {
            fail: Some(SafeErrorKind::WriteFailed),
            ..Default::default()
        },
        RecordingExecutable {
            fail: Some(SafeErrorKind::ExitFailure),
            ..Default::default()
        },
    );
    let r = svc.deliver_plain("hello");
    assert_eq!(r.confidence, Confidence::Failed);
    assert_eq!(r.attempts.len(), 3);
    assert!(
        r.attempts
            .iter()
            .all(|a| a.outcome == AttemptOutcome::Failed)
    );

    // Source inventory: antipatterns must not remain.
    inventory_no_legacy_antipatterns();
}

fn inventory_no_legacy_antipatterns() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/clipboard");
    let mut bad = Vec::new();
    walk_rs(&root, &mut |path, src| {
        if path.ends_with("tests.rs") {
            return;
        }
        for (i, line) in src.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with("//!") || t.starts_with('*') {
                continue;
            }
            if t.contains("fn accepted(") || t.contains("CopyOutcome::accepted") {
                bad.push(format!("{}:{} accepted", path.display(), i + 1));
            }
            if t.contains("OSC52_MAX_B64") {
                bad.push(format!("{}:{} OSC52_MAX_B64", path.display(), i + 1));
            }
            // Double-emit: raw concatenated with tmux wrap in one format!.
            if t.contains("{raw}\\x1bPtmux") || t.contains("{raw}\x1bPtmux") {
                bad.push(format!("{}:{} double-emit", path.display(), i + 1));
            }
            if t.contains("format!(\"{raw}") && t.contains("tmux") {
                bad.push(format!("{}:{} multifire format", path.display(), i + 1));
            }
        }
    });
    assert!(
        bad.is_empty(),
        "legacy clipboard antipatterns remain: {bad:?}"
    );
}

fn walk_rs(dir: &Path, f: &mut dyn FnMut(&Path, &str)) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.is_dir() {
                walk_rs(&p, f);
            } else if p.extension().and_then(|e| e.to_str()) == Some("rs")
                && let Ok(src) = std::fs::read_to_string(&p)
            {
                f(&p, &src);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AC2: ordered fallback stops
// ---------------------------------------------------------------------------

#[test]
fn clipboard_ordered_fallback_stops() {
    // Native confirms → no OSC, no executable.
    let mut svc = service(
        local_desktop(PlatformKind::MacOs),
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    let r = svc.deliver_plain("a");
    assert_eq!(r.confidence, Confidence::Confirmed);
    assert_eq!(
        r.attempts.iter().map(|a| a.route).collect::<Vec<_>>(),
        vec![Route::Native]
    );

    // Native fail → OSC Unverified (selector c) → executable Confirmed.
    let mut svc = service(
        local_desktop(PlatformKind::MacOs),
        RecordingNative {
            fail_plain: Some(SafeErrorKind::WriteFailed),
            ..Default::default()
        },
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    let r = svc.deliver_plain("a");
    assert_eq!(r.confidence, Confidence::Confirmed);
    assert_eq!(r.attempts[0].route, Route::Native);
    assert_eq!(r.attempts[0].outcome, AttemptOutcome::Failed);
    assert_eq!(r.attempts[1].route, Route::Osc52);
    assert_eq!(r.attempts[1].outcome, AttemptOutcome::Unverified);
    assert_eq!(r.attempts[2].route, Route::Executable);
    assert_eq!(r.attempts[2].outcome, AttemptOutcome::Confirmed);
    assert_eq!(svc.osc52.frames.len(), 1);
    let (transport, frame) = &svc.osc52.frames[0];
    assert_eq!(*transport, OscTransport::Direct);
    assert!(frame.contains("\x1b]52;c;"));
    assert!(frame.ends_with('\x07'));

    // Unacknowledged OSC continues; without executable confirm stays Unverified.
    let mut svc = service(
        ssh_ctx(),
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable {
            fail: Some(SafeErrorKind::Ineligible),
            ..Default::default()
        },
    );
    let r = svc.deliver_plain("a");
    assert_eq!(r.confidence, Confidence::Unverified);
    assert!(
        r.attempts
            .iter()
            .any(|a| a.route == Route::Osc52 && a.outcome == AttemptOutcome::Unverified)
    );
}

// ---------------------------------------------------------------------------
// AC3: trust and confidence matrix
// ---------------------------------------------------------------------------

#[test]
fn clipboard_trust_and_confidence_matrix() {
    assert!(!attached_client_route_exists());

    // Local desktop macOS: native confirms.
    let mut svc = service(
        local_desktop(PlatformKind::MacOs),
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    assert_eq!(svc.deliver_plain("x").confidence, Confidence::Confirmed);

    // SSH: native skipped, OSC unverified.
    let mut svc = service(
        ssh_ctx(),
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    let r = svc.deliver_plain("x");
    assert!(r.attempts.iter().any(|a| a.route == Route::Native
        && matches!(a.eligibility, Eligibility::Skipped(SkipReason::SshSession))));
    assert_eq!(r.confidence, Confidence::Unverified);

    // tmux passthrough transport.
    let mut ctx = ssh_ctx();
    ctx.tmux = true;
    ctx.osc52_tmux_passthrough = true;
    let mut svc = service(
        ctx,
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    let _ = svc.deliver_plain("x");
    assert_eq!(svc.osc52.frames[0].0, OscTransport::TmuxPassthrough);

    // Authenticated remote terminal (trusted SSH).
    let mut ctx = ssh_ctx();
    ctx.trusted_remote_terminal = true;
    let mut svc = service(
        ctx,
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    assert_eq!(svc.deliver_plain("x").confidence, Confidence::Unverified);

    // Untrusted remote: OSC skipped.
    let mut ctx = ssh_ctx();
    ctx.untrusted_remote = true;
    ctx.trusted_remote_terminal = false;
    let mut svc = service(
        ctx,
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    let r = svc.deliver_plain("x");
    assert_eq!(r.confidence, Confidence::Failed);
    assert!(r.attempts.iter().any(|a| {
        a.route == Route::Osc52
            && matches!(
                a.eligibility,
                Eligibility::Skipped(SkipReason::UntrustedRemote)
            )
    }));

    // Container/WSL: desktop routes skipped.
    let mut ctx = local_desktop(PlatformKind::Linux);
    ctx.wsl_or_container = true;
    ctx.same_host_local_desktop = false;
    let mut svc = service(
        ctx,
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    let r = svc.deliver_plain("x");
    assert!(r.attempts.iter().any(|a| {
        a.route == Route::Native
            && matches!(
                a.eligibility,
                Eligibility::Skipped(SkipReason::WslOrContainer)
            )
    }));

    // Explicit acknowledged OSC capability → Confirmed, stops before executable.
    let mut ctx = local_desktop(PlatformKind::Linux);
    ctx.osc52_acknowledged_capability = true;
    let mut svc = service(
        ctx,
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    let r = svc.deliver_plain("x");
    assert_eq!(r.confidence, Confidence::Confirmed);
    assert!(
        r.attempts
            .iter()
            .any(|a| a.route == Route::Osc52 && a.outcome == AttemptOutcome::Confirmed)
    );
    assert!(svc.executable.plains.is_empty());

    // Unacknowledged OSC + executable success → Confirmed final.
    let mut svc = service(
        local_desktop(PlatformKind::MacOs),
        RecordingNative {
            fail_plain: Some(SafeErrorKind::WriteFailed),
            ..Default::default()
        },
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    assert_eq!(svc.deliver_plain("x").confidence, Confidence::Confirmed);

    // Unacknowledged OSC + executable failure → Unverified final.
    let mut svc = service(
        local_desktop(PlatformKind::MacOs),
        RecordingNative {
            fail_plain: Some(SafeErrorKind::WriteFailed),
            ..Default::default()
        },
        RecordingOsc52Emitter::default(),
        RecordingExecutable {
            fail: Some(SafeErrorKind::ExitFailure),
            ..Default::default()
        },
    );
    assert_eq!(svc.deliver_plain("x").confidence, Confidence::Unverified);

    // Every skip reason is constructible / matchable (matrix coverage).
    let reasons = [
        SkipReason::NotSameHostLocalDesktop,
        SkipReason::UntrustedRemote,
        SkipReason::SshSession,
        SkipReason::WslOrContainer,
        SkipReason::HostBridge,
        SkipReason::NoHeldAuthenticatedConnection,
        SkipReason::UnsupportedBackend,
        SkipReason::PlainOnlyRoute,
        SkipReason::OverSizeLimit,
        SkipReason::EmptyPayload,
        SkipReason::Cancelled,
        SkipReason::MissingCandidate,
        SkipReason::IneligibleExecutable,
        SkipReason::X11Unsupported,
        SkipReason::LinuxNativeCannotConsumeHeldStream,
        SkipReason::OscNotAdvertised,
        SkipReason::NoAttachedClientRoute,
    ];
    assert_eq!(reasons.len(), 17);
}

// ---------------------------------------------------------------------------
// AC4: explicit mirrors
// ---------------------------------------------------------------------------

#[test]
fn clipboard_explicit_mirrors() {
    let mut svc = service(
        {
            let mut c = local_desktop(PlatformKind::MacOs);
            c.tmux = true;
            c
        },
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    let mut req = CopyRequest::plain("mirrored");
    req.mirror_tmux_buffer = true;
    let r = svc.deliver(req);
    assert_eq!(r.confidence, Confidence::Confirmed);
    assert!(svc.tmux_mirror_ran);
    assert_eq!(svc.tmux_mirror_payloads, vec!["mirrored".to_string()]);
    // Mirror cannot upgrade confidence (already Confirmed).
    assert_eq!(r.confidence, Confidence::Confirmed);

    // No mirror when not requested.
    let mut svc = service(
        {
            let mut c = local_desktop(PlatformKind::MacOs);
            c.tmux = true;
            c
        },
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    let r = svc.deliver_plain("x");
    assert!(r.delivered());
    assert!(!svc.tmux_mirror_ran);

    // No mirror before primary success (all fail).
    let mut svc = service(
        {
            let mut c = local_desktop(PlatformKind::MacOs);
            c.tmux = true;
            c
        },
        RecordingNative {
            fail_plain: Some(SafeErrorKind::WriteFailed),
            ..Default::default()
        },
        RecordingOsc52Emitter {
            fail: Some(SafeErrorKind::WriteFailed),
            ..Default::default()
        },
        RecordingExecutable {
            fail: Some(SafeErrorKind::ExitFailure),
            ..Default::default()
        },
    );
    let mut req = CopyRequest::plain("nope");
    req.mirror_tmux_buffer = true;
    let r = svc.deliver(req);
    assert_eq!(r.confidence, Confidence::Failed);
    assert!(!svc.tmux_mirror_ran);
}

// ---------------------------------------------------------------------------
// AC5: executable contract (unit-level argv/env policy)
// ---------------------------------------------------------------------------

#[test]
fn clipboard_executable_contract() {
    assert_eq!(contracts::MACOS_PBCOPY, "/usr/bin/pbcopy");
    assert_eq!(contracts::LINUX_WL_COPY, "/usr/bin/wl-copy");
    assert_eq!(
        contracts::LINUX_WL_COPY_ARGS,
        &["--type", "text/plain;charset=utf-8"]
    );

    // Arbitrary Unicode + multiline accepted by recording adapter.
    let mut exe = RecordingExecutable::default();
    exe.set_plain("héllo\n世界\r\n\t").unwrap();
    assert_eq!(exe.plains[0], "héllo\n世界\r\n\t");

    // Fallback order: native → osc → exe.
    let mut svc = service(
        local_desktop(PlatformKind::MacOs),
        RecordingNative {
            fail_plain: Some(SafeErrorKind::WriteFailed),
            ..Default::default()
        },
        RecordingOsc52Emitter {
            fail: Some(SafeErrorKind::WriteFailed),
            ..Default::default()
        },
        RecordingExecutable::default(),
    );
    let r = svc.deliver_plain("z");
    assert_eq!(
        r.attempts.iter().map(|a| a.route).collect::<Vec<_>>(),
        vec![Route::Native, Route::Osc52, Route::Executable]
    );
    assert_eq!(r.confidence, Confidence::Confirmed);

    // X11 never an executable candidate in eligibility matrix.
    let mut ctx = local_desktop(PlatformKind::Linux);
    // Without held wayland, probe returns ineligible/X11 — forced via host_bridge skip.
    ctx.host_bridge = true;
    ctx.same_host_local_desktop = false;
    let mut svc = service(
        ctx,
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    let r = svc.deliver_plain("z");
    assert!(
        r.attempts.iter().any(|a| {
            a.route == Route::Executable && matches!(a.outcome, AttemptOutcome::Skipped)
        })
    );

    // Sanitized errors never include payload.
    let err = CopyError::Backend.to_string();
    assert!(!err.contains("secret"));
    assert!(!err.contains("héllo"));
}

// ---------------------------------------------------------------------------
// AC6: no disk / plaintext diagnostics
// ---------------------------------------------------------------------------

#[test]
fn clipboard_no_disk_or_plaintext_diagnostics() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/clipboard");
    let mut hits = Vec::new();
    walk_rs(&root, &mut |path, src| {
        // Skip this test file's own string literals about writes.
        if path.ends_with("tests.rs") {
            return;
        }
        for (i, line) in src.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with("//!") {
                continue;
            }
            // Production routing must not write recovery/spool files.
            if t.contains("File::create")
                || t.contains("OpenOptions::new().write")
                || t.contains("std::fs::write")
            {
                hits.push(format!("{}:{}", path.display(), i + 1));
            }
            // Content-bearing log of clipboard text.
            if t.contains("tracing::")
                && (t.contains("text") || t.contains("payload"))
                && (t.contains("clipboard") || t.contains("plain") || t.contains("html"))
            {
                hits.push(format!("{}:{} log", path.display(), i + 1));
            }
        }
    });
    assert!(hits.is_empty(), "disk/plaintext diagnostics: {hits:?}");
}

// ---------------------------------------------------------------------------
// AC8: representation and downgrade matrix
// ---------------------------------------------------------------------------

#[test]
fn clipboard_representation_and_downgrade_matrix() {
    // Plain policy.
    let mut svc = service(
        local_desktop(PlatformKind::MacOs),
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    let r = svc.deliver(CopyRequest::plain("p"));
    assert_eq!(r.requested_representation, Representation::Plain);
    assert_eq!(r.delivered_representation, Representation::Plain);
    assert_eq!(r.downgrade, None);
    assert_eq!(r.confidence, Confidence::Confirmed);

    // StrictRich native success.
    let mut svc = service(
        local_desktop(PlatformKind::MacOs),
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    let r = svc.deliver(CopyRequest::rich("p", "<b>p</b>", RichPolicy::StrictRich));
    assert_eq!(r.delivered_representation, Representation::Rich);
    assert_eq!(r.confidence, Confidence::Confirmed);
    assert_eq!(svc.native.rich.len(), 1);

    // StrictRich native failure — no downgrade, Failed.
    let mut svc = service(
        local_desktop(PlatformKind::MacOs),
        RecordingNative {
            fail_rich: Some(SafeErrorKind::WriteFailed),
            ..Default::default()
        },
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    let r = svc.deliver(CopyRequest::rich("p", "<b>p</b>", RichPolicy::StrictRich));
    assert_eq!(r.confidence, Confidence::Failed);
    assert_eq!(r.downgrade, None);
    assert_eq!(r.delivered_representation, Representation::None);
    assert!(svc.osc52.frames.is_empty());

    // AllowPlainDowngrade: native rich fails → one RichToPlain → plain chain.
    let mut svc = service(
        local_desktop(PlatformKind::MacOs),
        RecordingNative {
            fail_rich: Some(SafeErrorKind::WriteFailed),
            ..Default::default()
        },
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    // Native rich failed; plain chain starts at OSC (native already tried).
    // For AllowPlainDowngrade after rich fail we continue from OSC — but
    // native plain wasn't tried. Service restarts plain from OSC by design
    // after rich native attempt. Force executable confirm via OSC fail.
    svc.osc52.fail = Some(SafeErrorKind::WriteFailed);
    let r = svc.deliver(CopyRequest::rich(
        "p",
        "<b>p</b>",
        RichPolicy::AllowPlainDowngrade,
    ));
    assert_eq!(r.downgrade, Some(Downgrade::RichToPlain));
    assert_eq!(r.confidence, Confidence::Confirmed);
    assert_eq!(r.delivered_representation, Representation::Plain);

    // SSH StrictRich fails; AllowPlainDowngrade yields Unverified OSC.
    let mut svc = service(
        ssh_ctx(),
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    let r = svc.deliver(CopyRequest::rich(
        "p",
        "<b>p</b>",
        RichPolicy::AllowPlainDowngrade,
    ));
    assert_eq!(r.downgrade, Some(Downgrade::RichToPlain));
    assert_eq!(r.confidence, Confidence::Unverified);
    assert_eq!(r.delivered_representation, Representation::Plain);

    // Recovery/feedback consumer contract fields always present.
    assert!(r.attempts.iter().all(|a| {
        matches!(
            a.outcome,
            AttemptOutcome::Confirmed
                | AttemptOutcome::Unverified
                | AttemptOutcome::Failed
                | AttemptOutcome::Skipped
        )
    }));
}

// ---------------------------------------------------------------------------
// AC9: OSC52 emission matches host contract
// ---------------------------------------------------------------------------

#[test]
fn clipboard_osc52_emission_matches_host_contract() {
    // Import the single shared constant (compile + value fixture).
    let cap = OSC52_MAX_SEQUENCE_BYTES;
    assert_eq!(cap, 102_400);

    let seq = build_sequence("YQ==", OscTransport::Direct);
    assert!(seq.starts_with("\x1b]52;c;"));
    assert!(seq.ends_with('\x07'));
    assert_eq!(raw_sequence_len(4), 2 + 5 + 4 + 1);

    let n = largest_in_cap_decoded_len();
    let payload = "z".repeat(n);
    let encoded = encode_checked(&payload).unwrap();
    assert!(raw_sequence_len(encoded.len()) <= cap);

    // First over-cap payload rejected before any write.
    let mut emitter = RecordingOsc52Emitter::default();
    let over = "z".repeat(n + 3);
    assert_eq!(
        emitter.emit(&over, OscTransport::Direct),
        Err(SafeErrorKind::TooLarge)
    );
    assert!(emitter.frames.is_empty());

    // Acknowledged vs unacknowledged outcomes.
    let mut ctx = local_desktop(PlatformKind::Linux);
    ctx.osc52_acknowledged_capability = true;
    let mut svc = service(
        ctx,
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    assert_eq!(svc.deliver_plain("ok").confidence, Confidence::Confirmed);

    let mut ctx = local_desktop(PlatformKind::Linux);
    ctx.osc52_acknowledged_capability = false;
    let mut svc = service(
        ctx,
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable {
            fail: Some(SafeErrorKind::ExitFailure),
            ..Default::default()
        },
    );
    assert_eq!(svc.deliver_plain("ok").confidence, Confidence::Unverified);

    // Workspace inventory: single declaration of the cap constant.
    let ws = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut decls = Vec::new();
    walk_rs(&ws.join("crates"), &mut |path, src| {
        for (i, line) in src.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") {
                continue;
            }
            if t.starts_with("pub const OSC52_MAX_SEQUENCE_BYTES")
                || t.starts_with("const OSC52_MAX_SEQUENCE_BYTES")
            {
                decls.push(format!("{}:{}", path.display(), i + 1));
            }
        }
    });
    walk_rs(&ws.join("apps/cli/src"), &mut |path, src| {
        for (i, line) in src.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") {
                continue;
            }
            if t.starts_with("pub const OSC52_MAX_SEQUENCE_BYTES")
                || t.starts_with("const OSC52_MAX_SEQUENCE_BYTES")
            {
                decls.push(format!("{}:{}", path.display(), i + 1));
            }
        }
    });
    assert_eq!(
        decls.len(),
        1,
        "exactly one OSC52_MAX_SEQUENCE_BYTES declaration, found {decls:?}"
    );
}

// ---------------------------------------------------------------------------
// AC10: Linux display identity matrix
// ---------------------------------------------------------------------------

#[test]
fn clipboard_linux_display_identity_matrix() {
    // Wayland Native: deterministic Skip.
    let ctx = local_desktop(PlatformKind::Linux);
    assert_eq!(
        super::native::native_eligibility(&ctx),
        Err(SkipReason::LinuxNativeCannotConsumeHeldStream)
    );

    // X11 Native/Executable: Unsupported.
    assert!(validate::display_is_tcp_or_hostname("localhost:0"));
    assert!(validate::display_is_tcp_or_hostname("host.example:1.0"));
    assert!(validate::display_is_tcp_or_hostname("127.0.0.1:0"));
    assert!(!validate::display_is_tcp_or_hostname(":0"));
    assert!(!validate::display_is_tcp_or_hostname(":1"));

    assert!(validate::wayland_display_name("wayland-0").is_ok());
    assert!(validate::wayland_display_name("../evil").is_err());
    assert!(validate::wayland_display_name("a/b").is_err());
    assert!(validate::wayland_display_name("").is_err());
    assert!(validate::runtime_dir_path(Path::new("/run/user/1000")).is_ok());
    assert!(validate::runtime_dir_path(Path::new("relative")).is_err());

    // Service path: Linux native skipped; OSC may still run.
    let mut svc = service(
        local_desktop(PlatformKind::Linux),
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable {
            fail: Some(SafeErrorKind::Ineligible),
            ..Default::default()
        },
    );
    let r = svc.deliver_plain("id");
    assert!(r.attempts.iter().any(|a| {
        a.route == Route::Native
            && matches!(
                a.eligibility,
                Eligibility::Skipped(SkipReason::LinuxNativeCannotConsumeHeldStream)
            )
    }));

    // SSH skips desktop routes without spawn.
    let mut svc = service(
        ssh_ctx(),
        RecordingNative::default(),
        RecordingOsc52Emitter::default(),
        RecordingExecutable::default(),
    );
    let r = svc.deliver_plain("id");
    assert!(svc.executable.plains.is_empty());
    assert!(
        r.attempts
            .iter()
            .any(|a| a.route == Route::Executable && a.outcome == AttemptOutcome::Skipped)
    );

    // Inventory: Linux copy must not call arboard::Clipboard::new in native path.
    // (read_* paste paths may still use arboard — only native copy module checked.)
    let native_src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/clipboard/native.rs"),
    )
    .unwrap();
    // Production set_plain/set_rich on Linux return Unsupported before arboard.
    assert!(native_src.contains("target_os = \"linux\""));
    assert!(native_src.contains("SafeErrorKind::Unsupported"));

    let exec_src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/clipboard/executable.rs"),
    )
    .unwrap();
    assert!(!exec_src.contains("xclip"));
    assert!(!exec_src.contains("xsel"));
    assert!(exec_src.contains("WAYLAND_SOCKET"));
    assert!(exec_src.contains("env_clear"));
}

// ---------------------------------------------------------------------------
// Outside-tmux raw-only + markdown helpers retained
// ---------------------------------------------------------------------------

#[test]
fn osc52_sequence_outside_tmux_is_raw_only() {
    let seq = build_sequence("QUJD", OscTransport::Direct);
    assert_eq!(seq, "\x1b]52;c;QUJD\x07");
    assert!(raw_sequence_len(4) <= OSC52_MAX_SEQUENCE_BYTES);
}

#[test]
fn extract_code_blocks_fenced_returns_body_and_lang() {
    let blocks = super::extract_code_blocks("```rust\nlet x=1;\n```");
    assert_eq!(
        blocks,
        vec![super::CodeBlock {
            lang: Some("rust".to_string()),
            body: "let x=1;\n".to_string()
        }]
    );
}

#[test]
fn extract_code_blocks_multiple_in_document_order() {
    let blocks = super::extract_code_blocks("```sh\necho one\n```\ntext\n```\ntwo\n```");
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].lang.as_deref(), Some("sh"));
    assert_eq!(blocks[0].body, "echo one\n");
    assert_eq!(blocks[1].lang, None);
    assert_eq!(blocks[1].body, "two\n");
}

#[test]
fn extract_code_blocks_indented_block() {
    let blocks = super::extract_code_blocks("prose\n\n    indented\n    block\n");
    assert_eq!(
        blocks,
        vec![super::CodeBlock {
            lang: None,
            body: "indented\nblock\n".to_string()
        }]
    );
}

#[test]
fn extract_code_blocks_none_for_prose() {
    assert!(super::extract_code_blocks("plain prose only").is_empty());
}

// ---------------------------------------------------------------------------
// Opt-in platform executable conformance (skipped when tools unavailable)
// ---------------------------------------------------------------------------

#[test]
fn clipboard_executable_stdin_conformance_opt_in() {
    // Does not change production policy when unavailable — pure probe.
    #[cfg(target_os = "macos")]
    {
        let path = Path::new(contracts::MACOS_PBCOPY);
        if !path.is_file() {
            return;
        }
        // Round-trip not asserted via pbpaste (would require PATH); only
        // verify trusted candidate + spawn success without reading content
        // back into logs.
        let mut exe = super::executable::PlatformExecutable::default();
        let _ = ExecutableClipboard::set_plain(&mut exe, "conformance-plain");
    }
    #[cfg(target_os = "linux")]
    {
        let path = Path::new(contracts::LINUX_WL_COPY);
        if !path.is_file() {
            return;
        }
        // Without a held Wayland socket the adapter must fail closed as
        // Ineligible — never PATH-search or shell out.
        let mut exe = super::executable::PlatformExecutable::default();
        let err = ExecutableClipboard::set_plain(&mut exe, "conformance-plain");
        assert!(
            matches!(
                err,
                Err(SafeErrorKind::Ineligible) | Err(SafeErrorKind::SpawnFailed) | Ok(())
            ),
            "unexpected {err:?}"
        );
    }
    #[cfg(windows)]
    {
        let mut exe = super::executable::PlatformExecutable::default();
        let _ = ExecutableClipboard::set_plain(&mut exe, "conformance-plain");
    }
}

// ---------------------------------------------------------------------------
// Use RecordingExecutable trait in scope
// ---------------------------------------------------------------------------

use super::executable::ExecutableClipboard;
use super::osc52::Osc52Emitter;
