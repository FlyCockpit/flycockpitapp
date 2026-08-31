//! Acceptance tests for computer target identity (`computer_target_*`).

use std::sync::{Arc, Mutex};
use std::thread;

use crate::computer::host_identity::{
    FakeHostIdentityFs, FixedHostIdentityRng, HostIdentityUnavailableReason, HostInstallationId,
    SysHostIdentityRng, decode_host_installation_id, encode_host_installation_id,
    load_or_create_host_installation_id, production_rng_uses_sysrng,
};
use crate::computer::platform::macos::{
    AU_DEFAUDITSID, AxValueTag, AxWindowRect, CgSessionKey, CgSessionSnapshot, CgSessionValue,
    CgWindowCandidate, MacAxAttribute, MacAxNotification, MacCallbackGate,
    MacCallbackTerminalReason, MacObservedEpoch, MacProducerKind, TASK_AUDIT_TOKEN_COUNT_EXPECTED,
    extract_audit_session_id, join_ax_to_cg_window, select_display_for_window, validate_cg_session,
};
use crate::computer::platform::wayland::{
    FakeWaylandProvider, WaylandCapabilityDescriptor, WaylandFocusGuarantee, WaylandProviderKind,
    evaluate_wayland_provider, reject_generic_global_focus_claim, reject_x11_as_wayland_evidence,
    wayland_snapshot_from_provider,
};
use crate::computer::platform::windows::{
    WindowsAclValidation, WindowsForeground, WindowsMonitorIdentity, WindowsNativeEvent,
    WindowsObservedEpoch, WindowsSessionParts, valid_directory_acl, valid_file_acl,
    validate_foreground, validate_windows_id_acl, windows_monitor_display_id, windows_session_id,
};
use crate::computer::platform::x11::{
    EdidValidation, FocusedWindowGeom, RandrOutputSnapshot, X11EvidenceError, X11NativeEvent,
    X11ObservedEpoch, X11SessionParts, build_mirror_groups, check_randr_version,
    check_resource_timestamp, make_valid_edid, select_mirror_group, validate_edid,
    x11_physical_display_id, x11_session_or_seat_id,
};
use crate::computer::target::{
    BackendKind, EvidenceSource, FakeTargetEvidenceAdapter, FieldEvidence, HandoffDecision,
    PhysicalInputLeaseTable, PhysicalTargetKey, ProviderSuppliedIdentity, RedactedHint,
    SequenceClaim, TargetEvidenceCoordinator, TargetGeometry, TargetUnavailableReason,
    reject_provider_supplied_identity, sample_physical_evidence, sample_virtual_evidence,
};

fn host(n: u8) -> HostInstallationId {
    HostInstallationId([n; 32])
}

// ---------------------------------------------------------------------------
// AC1: computer_target_platform_evidence
// ---------------------------------------------------------------------------

#[test]
fn computer_target_platform_evidence() {
    // --- macOS Mach audit token ---
    let mut token = [0u32; 8];
    token[6] = 42;
    assert_eq!(
        extract_audit_session_id(true, TASK_AUDIT_TOKEN_COUNT_EXPECTED, &token).unwrap(),
        42
    );
    assert!(extract_audit_session_id(false, 8, &token).is_err());
    assert!(extract_audit_session_id(true, 7, &token).is_err());
    assert!(extract_audit_session_id(true, 9, &token).is_err());
    token[6] = AU_DEFAUDITSID;
    assert!(extract_audit_session_id(true, 8, &token).is_err());
    assert!(extract_audit_session_id(true, 8, &[1, 2, 3]).is_err());
    // Exact val[6] extraction
    let mut t2 = [9u32; 8];
    t2[6] = 0xA5A5_A5A5;
    assert_eq!(extract_audit_session_id(true, 8, &t2).unwrap(), 0xA5A5_A5A5);

    // --- CGSession keys ---
    for key in CgSessionKey::all() {
        assert!(!key.as_static_str().is_empty());
    }
    assert_eq!(CgSessionKey::UserId.as_static_str(), "kCGSSessionUserIDKey");
    assert_eq!(
        CgSessionKey::ConsoleSet.as_static_str(),
        "kCGSSessionConsoleSetKey"
    );
    assert_eq!(
        CgSessionKey::OnConsole.as_static_str(),
        "kCGSSessionOnConsoleKey"
    );
    assert_eq!(
        CgSessionKey::LoginDone.as_static_str(),
        "kCGSessionLoginDoneKey"
    );

    let good = CgSessionSnapshot {
        user_id: CgSessionValue::Number(501),
        console_set: CgSessionValue::Number(1),
        on_console: CgSessionValue::Bool(true),
        login_done: CgSessionValue::Bool(true),
    };
    assert!(validate_cg_session(&good, 501, None).is_ok());
    // uid mismatch
    assert!(validate_cg_session(&good, 502, None).is_err());
    // missing key
    let mut missing = good.clone();
    missing.user_id = CgSessionValue::Missing;
    assert!(validate_cg_session(&missing, 501, None).is_err());
    // wrong type
    let mut wrong = good.clone();
    wrong.on_console = CgSessionValue::Number(1);
    assert!(validate_cg_session(&wrong, 501, None).is_err());
    // value change across snapshot
    let mut changed = good.clone();
    changed.console_set = CgSessionValue::Number(2);
    assert!(validate_cg_session(&changed, 501, Some(&good)).is_err());
    // inactive
    let mut inactive = good.clone();
    inactive.on_console = CgSessionValue::Bool(false);
    assert!(validate_cg_session(&inactive, 501, None).is_err());

    // --- AX literals ---
    for a in MacAxAttribute::all() {
        assert!(a.as_static_str().starts_with("AX"));
    }
    assert_eq!(
        MacAxNotification::FocusedWindowChanged.as_static_str(),
        "AXFocusedWindowChanged"
    );
    for n in MacAxNotification::window_notifications() {
        assert!(!n.as_static_str().is_empty());
    }

    // --- AX→CG join ---
    let ax = AxWindowRect {
        x: 10.0,
        y: 20.0,
        w: 100.0,
        h: 50.0,
        position_tag: AxValueTag::CgPoint,
        size_tag: AxValueTag::CgSize,
    };
    let one = vec![CgWindowCandidate {
        owner_pid: 99,
        bounds: (10.0, 20.0, 100.0, 50.0),
        window_number: 7,
        title: Some("Secret".into()),
        z_order: 0,
        destroyed: false,
        wrong_typed_field: false,
    }];
    assert_eq!(join_ax_to_cg_window(99, &ax, &one, 99, &ax, 99).unwrap(), 7);
    // zero candidates
    assert!(join_ax_to_cg_window(99, &ax, &[], 99, &ax, 99).is_err());
    // multiple same-pid/same-bounds
    let multi = vec![one[0].clone(), {
        let mut c = one[0].clone();
        c.window_number = 8;
        c.z_order = 1;
        c.title = Some("Other".into());
        c
    }];
    assert!(join_ax_to_cg_window(99, &ax, &multi, 99, &ax, 99).is_err());
    // destroyed
    let mut dest = one.clone();
    dest[0].destroyed = true;
    assert!(join_ax_to_cg_window(99, &ax, &dest, 99, &ax, 99).is_err());
    // PID change on recheck
    assert!(join_ax_to_cg_window(99, &ax, &one, 100, &ax, 99).is_err());
    // frontmost change
    assert!(join_ax_to_cg_window(99, &ax, &one, 99, &ax, 100).is_err());
    // bounds change
    let mut ax2 = ax.clone();
    ax2.x = 11.0;
    assert!(join_ax_to_cg_window(99, &ax, &one, 99, &ax2, 99).is_err());
    // wrong typed CG field
    let mut bad = one.clone();
    bad[0].wrong_typed_field = true;
    assert!(join_ax_to_cg_window(99, &ax, &bad, 99, &ax, 99).is_err());
    // AXValue tag mismatch
    let mut bad_tag = ax.clone();
    bad_tag.position_tag = AxValueTag::Other(0);
    assert!(join_ax_to_cg_window(99, &bad_tag, &one, 99, &bad_tag, 99).is_err());
    // title/z-order are not tie-breaks: only unique window_number wins when single match
    // (already covered by multi-candidate failure)

    // display tie-break: lowest CGDirectDisplayID
    let uuid_a = [1u8; 16];
    let uuid_b = [2u8; 16];
    let displays = [
        (20u32, (0.0, 0.0, 100.0, 100.0), uuid_a),
        (10u32, (0.0, 0.0, 100.0, 100.0), uuid_b),
    ];
    let selected = select_display_for_window((0.0, 0.0, 50.0, 50.0), &displays).unwrap();
    assert_eq!(selected, uuid_b); // lower id wins on equal area

    // --- Windows ---
    let sess = WindowsSessionParts {
        process_session_id: 2,
        window_station_name: "WinSta0".into(),
        input_desktop_name: "Default".into(),
        open_input_desktop_matches: true,
        is_session_zero: false,
        disconnected_or_locked: false,
        secure_desktop: false,
        session_transition: false,
    };
    let sid = windows_session_id(&sess).unwrap();
    assert_eq!(sid, windows_session_id(&sess).unwrap());
    let mut s0 = sess.clone();
    s0.is_session_zero = true;
    assert!(windows_session_id(&s0).is_err());
    let mut lock = sess.clone();
    lock.disconnected_or_locked = true;
    assert!(windows_session_id(&lock).is_err());
    let mut desk = sess.clone();
    desk.open_input_desktop_matches = false;
    assert!(windows_session_id(&desk).is_err());

    let fg = WindowsForeground {
        hwnd_null: false,
        hwnd_destroyed: false,
        pid: 1234,
        exe_identity: Some("app.exe".into()),
        appx_package: Some("Pkg".into()),
        appx_application: Some("App".into()),
        class_name: Some("Chrome_WidgetWin_1".into()),
        uia_control_type: Some("Window".into()),
        access_denied: false,
        uipi_limited: false,
    };
    assert_eq!(validate_foreground(&fg).unwrap(), 1234);
    let mut null_hw = fg.clone();
    null_hw.hwnd_null = true;
    assert!(validate_foreground(&null_hw).is_err());

    let mon = WindowsMonitorIdentity {
        sz_device: r"\\.\DISPLAY1".into(),
        adapter_device_id: Some("PCI\\VEN_10DE".into()),
        monitor_device_id: Some("MONITOR\\DEL".into()),
        remapped: false,
        ambiguous: false,
    };
    let did = windows_monitor_display_id(&mon).unwrap();
    assert_ne!(did, [0u8; 32]);
    let mut amb = mon.clone();
    amb.ambiguous = true;
    assert!(windows_monitor_display_id(&amb).is_err());

    // --- X11 session independent of cookie ---
    let mut xparts = X11SessionParts {
        transport: "unix".into(),
        display_number: 0,
        screen: 0,
        vendor: "X.Org".into(),
        release: 12101000,
        root_window_id: 0x123,
        xauthority_cookie: vec![1, 2, 3, 4],
    };
    let a = x11_session_or_seat_id(&xparts);
    xparts.xauthority_cookie = vec![9, 9, 9];
    let b = x11_session_or_seat_id(&xparts);
    assert_eq!(a, b);

    // --- Wayland / virtual via injected adapters ---
    let host_id = host(7);
    let mut virt = sample_virtual_evidence([9u8; 16], 1);
    virt.host_installation_id = FieldEvidence::available(host_id, EvidenceSource::VirtualEngine);
    assert!(virt.physical_target_key().is_err());

    let desc = WaylandCapabilityDescriptor {
        kind: WaylandProviderKind::CompositorIntegration,
        implementation: "test-comp".into(),
        version: "1".into(),
        session_token: "s".into(),
        source_token: "src".into(),
        display_token: "d".into(),
        focus_guarantee: WaylandFocusGuarantee::MonotonicFocusSequence,
        backend_generation: 3,
        portal_expired: false,
        portal_revoked: false,
        source_replaced: false,
        reconnected: false,
        xwayland_present: false,
        registered: true,
    };
    assert!(evaluate_wayland_provider(&desc, Some("test-comp"), Some("1")).is_ok());
}

// ---------------------------------------------------------------------------
// AC2: computer_target_key
// ---------------------------------------------------------------------------

#[test]
fn computer_target_key() {
    let h = host(1);
    let session = [2u8; 32];
    let display = [3u8; 32];
    let key = PhysicalTargetKey::new(h, session, display);
    assert_eq!(key.host_installation_id, h);
    assert_eq!(key.platform_session_or_seat_id, session);
    assert_eq!(key.physical_display_id, display);

    // Virtual separation
    let virt = sample_virtual_evidence([1u8; 16], 5);
    assert!(matches!(
        virt.physical_target_key(),
        Err(TargetUnavailableReason::VirtualDisplayNoPhysicalLease)
    ));

    // PID reuse: same physical key when host/session/display match, window/pid change
    let e1 = sample_physical_evidence(h, session, display, [4u8; 16], 100);
    let e2 = sample_physical_evidence(h, session, display, [5u8; 16], 200);
    assert_eq!(
        e1.physical_target_key().unwrap(),
        e2.physical_target_key().unwrap()
    );

    // Provider-supplied identities rejected
    let supplied = ProviderSuppliedIdentity {
        claimed_host: Some([9u8; 32]),
        claimed_session: Some([8u8; 32]),
        claimed_display: Some([7u8; 32]),
        claimed_window: Some([6u8; 16]),
    };
    assert!(reject_provider_supplied_identity(&supplied).is_err());

    // Two backend kinds → one lease
    let mut table = PhysicalInputLeaseTable::new();
    let owner = table.try_acquire(&key).unwrap();
    assert!(table.try_acquire(&key).is_none());
    // Same physical key regardless of backend_kind metadata
    let e_x11 = sample_physical_evidence(h, session, display, [1u8; 16], 1);
    let mut e_win = e_x11.clone();
    e_win.backend_kind = BackendKind::RealDesktopWindows;
    assert_eq!(
        e_x11.physical_target_key().unwrap(),
        e_win.physical_target_key().unwrap()
    );
    assert!(table.is_held(&e_win.physical_target_key().unwrap()));
    assert!(table.release(&key, owner));
    assert!(table.try_acquire(&key).is_some());
}

// ---------------------------------------------------------------------------
// AC3: computer_target_focus_toctou
// ---------------------------------------------------------------------------

#[test]
fn computer_target_focus_toctou() {
    let h = host(3);
    let session = [1u8; 32];
    let display = [2u8; 32];
    let base = sample_physical_evidence(h, session, display, [9u8; 16], 10);

    // RandR can resize the root desktop without changing focused-window
    // geometry. That must still advance the handoff fence generation.
    let mut reducer = crate::computer::target::FocusGenerationReducer::new();
    assert_eq!(reducer.observe(&base).unwrap(), 1);
    let mut resized = base.clone();
    resized.desktop_geometry = FieldEvidence::available(
        TargetGeometry {
            x: 0,
            y: 0,
            width: 1600,
            height: 900,
            scale: 2.0,
        },
        EvidenceSource::InjectedTest,
    );
    assert_eq!(reducer.observe(&resized).unwrap(), 2);

    // Order A: change before handoff → stale, zero input
    let adapter = FakeTargetEvidenceAdapter::new(base.clone());
    let mut coord = TargetEvidenceCoordinator::new(adapter.clone());
    let plan = coord.capture_for_planning().unwrap();
    // Mutate underlying adapter after planning
    coord.adapter_mut().mutate_window([8u8; 16]);
    let decision = coord.handoff(&plan, "click");
    assert!(matches!(
        decision,
        HandoffDecision::Reject {
            reason: TargetUnavailableReason::StaleTarget
        }
    ));
    assert!(coord.dispatched_inputs.is_empty());

    // Order B: handoff first succeeds; subsequent change does not retroactively stale
    let mut coord2 = TargetEvidenceCoordinator::new(FakeTargetEvidenceAdapter::new(base.clone()));
    let plan2 = coord2.capture_for_planning().unwrap();
    let decision2 = coord2.handoff(&plan2, "type");
    assert!(matches!(decision2, HandoffDecision::Allow { .. }));
    assert_eq!(coord2.dispatched_inputs.len(), 1);
    // Late event after handoff
    coord2.adapter_mut().mutate_geometry(TargetGeometry {
        x: 99,
        y: 99,
        width: 1,
        height: 1,
        scale: 1.0,
    });
    // Prior action stays recorded once; next handoff fails
    let plan3 = coord2.capture_for_planning().unwrap();
    // Force epoch mismatch for next
    coord2.adapter_mut().advance_epoch();
    assert!(matches!(
        coord2.handoff(&plan3, "move"),
        HandoffDecision::Reject { .. }
    ));

    // Unavailable after previously available → stale
    let mut coord3 = TargetEvidenceCoordinator::new(FakeTargetEvidenceAdapter::new(base));
    let plan4 = coord3.capture_for_planning().unwrap();
    coord3.adapter_mut().clear_identity();
    assert!(matches!(
        coord3.handoff(&plan4, "scroll"),
        HandoffDecision::Reject {
            reason: TargetUnavailableReason::StaleTarget
        }
    ));
    assert_eq!(coord3.dispatched_inputs.len(), 0);

    let _ = adapter; // silence
}

// ---------------------------------------------------------------------------
// AC4: sensitive fixtures never deny under Yolo; capability failures do
// ---------------------------------------------------------------------------

#[test]
fn computer_target_yolo_advisory_only() {
    let h = host(4);
    let mut e = sample_physical_evidence(h, [1u8; 32], [2u8; 32], [3u8; 16], 1);
    e.title_hint = FieldEvidence::available(
        RedactedHint::from_raw("1Password — Vault"),
        EvidenceSource::InjectedTest,
    );
    e.accessibility_role =
        FieldEvidence::available("AXSecureTextField".into(), EvidenceSource::InjectedTest);
    e.stable_application_id = FieldEvidence::available(
        crate::computer::target::StableApplicationId {
            kind: "bundle",
            value: "com.apple.Terminal".into(),
        },
        EvidenceSource::InjectedTest,
    );

    let adapter = FakeTargetEvidenceAdapter::new(e.clone());
    let coord = TargetEvidenceCoordinator::new(adapter);
    // Yolo: sensitive app/role/title never deny
    assert!(coord.yolo_evaluate_target(&e, true, true).is_ok());

    // Unsupported backend rejects
    assert!(matches!(
        coord.yolo_evaluate_target(&e, true, false),
        Err(TargetUnavailableReason::UnsupportedPlatform)
    ));
    // Missing real-desktop grant rejects
    assert!(matches!(
        coord.yolo_evaluate_target(&e, false, true),
        Err(TargetUnavailableReason::MissingCapability)
    ));
    // Stale generation rejects at handoff (already covered); missing host identity
    e.host_installation_id =
        FieldEvidence::unavailable(TargetUnavailableReason::HostIdentityUnavailable, None);
    assert!(coord.yolo_evaluate_target(&e, true, true).is_err());
}

// ---------------------------------------------------------------------------
// AC5: safe audit/export has no raw secrets
// ---------------------------------------------------------------------------

#[test]
fn computer_target_safe_audit_projection() {
    let e = sample_physical_evidence(host(5), [1u8; 32], [2u8; 32], [3u8; 16], 42);
    let proj = e.safe_audit_projection();
    let s = format!("{proj:?}");
    assert!(!s.contains("Secret Document"));
    assert!(!s.contains("Banking"));
    assert!(!s.contains("password"));
    // Raw host bytes not present
    assert!(!s.contains(&format!("{:?}", host(5).0)));
    assert_eq!(proj.sequence_claim, SequenceClaim::AdapterObservedEpoch);
    assert!(proj.title_hint_hash.is_some());
    // Debug of PhysicalTargetKey redacts
    let key = e.physical_target_key().unwrap();
    let ks = format!("{key:?}");
    assert!(ks.contains("REDACTED"));
}

// ---------------------------------------------------------------------------
// AC6 / AC9: Wayland capability fixtures
// ---------------------------------------------------------------------------

#[test]
fn computer_target_wayland_capabilities() {
    assert!(matches!(
        reject_generic_global_focus_claim(),
        TargetUnavailableReason::UnsupportedPlatform
    ));
    assert!(matches!(
        reject_x11_as_wayland_evidence(),
        TargetUnavailableReason::XwaylandFallbackForbidden
    ));

    let base = WaylandCapabilityDescriptor {
        kind: WaylandProviderKind::CompositorIntegration,
        implementation: "sway".into(),
        version: "1.9".into(),
        session_token: "sess".into(),
        source_token: "src".into(),
        display_token: "disp".into(),
        focus_guarantee: WaylandFocusGuarantee::MonotonicFocusSequence,
        backend_generation: 1,
        portal_expired: false,
        portal_revoked: false,
        source_replaced: false,
        reconnected: false,
        xwayland_present: false,
        registered: true,
    };
    assert!(evaluate_wayland_provider(&base, Some("sway"), Some("1.9")).is_ok());

    // Portal with focus
    let mut portal = base.clone();
    portal.kind = WaylandProviderKind::RemoteDesktopPortal;
    portal.implementation = "xdg-desktop-portal".into();
    assert!(evaluate_wayland_provider(&portal, None, None).is_ok());

    // Portal stream only
    let mut stream = portal.clone();
    stream.focus_guarantee = WaylandFocusGuarantee::StreamOnlyNoFocus;
    assert!(evaluate_wayland_provider(&stream, None, None).is_err());

    // Version drift
    assert!(evaluate_wayland_provider(&base, Some("sway"), Some("2.0")).is_err());

    // Expiry / revocation / source replacement / reconnect
    let mut exp = base.clone();
    exp.portal_expired = true;
    assert!(evaluate_wayland_provider(&exp, None, None).is_err());
    let mut rev = base.clone();
    rev.portal_revoked = true;
    assert!(evaluate_wayland_provider(&rev, None, None).is_err());
    let mut repl = base.clone();
    repl.source_replaced = true;
    assert!(evaluate_wayland_provider(&repl, None, None).is_err());
    let mut recon = base.clone();
    recon.reconnected = true;
    assert!(evaluate_wayland_provider(&recon, None, None).is_err());

    // XWayland without focus guarantee
    let mut xw = base.clone();
    xw.xwayland_present = true;
    xw.focus_guarantee = WaylandFocusGuarantee::None;
    assert!(evaluate_wayland_provider(&xw, None, None).is_err());

    // Unknown / unregistered
    let mut unk = base.clone();
    unk.kind = WaylandProviderKind::Unknown;
    assert!(evaluate_wayland_provider(&unk, None, None).is_err());
    let mut unreg = base.clone();
    unreg.registered = false;
    assert!(evaluate_wayland_provider(&unreg, None, None).is_err());

    let provider = FakeWaylandProvider {
        descriptor: base,
        sequence: 4,
    };
    let snap =
        wayland_snapshot_from_provider(&provider, host(6), Some("sway"), Some("1.9")).unwrap();
    assert_eq!(snap.backend_kind, BackendKind::RealDesktopWayland);
    assert_eq!(snap.adapter_observed_epoch, 4);
}

// ---------------------------------------------------------------------------
// AC7: computer_target_adapter_ownership
// ---------------------------------------------------------------------------

#[test]
fn computer_target_adapter_ownership() {
    // Coordinator is sole consumer of snapshots
    let e = sample_physical_evidence(host(7), [1u8; 32], [2u8; 32], [3u8; 16], 1);
    let adapter = FakeTargetEvidenceAdapter::new(e);
    let mut coord = TargetEvidenceCoordinator::new(adapter);
    let _ = coord.capture_for_planning().unwrap();
    assert_eq!(coord.adapter().capture_count, 1);

    // macOS gate readiness / registration
    let gate = MacCallbackGate::new();
    assert!(!gate.is_ready());
    gate.mark_ready_full_registration();
    assert!(gate.is_ready());
    let (ns, ax_app, ax_win, ax_src, cg) = gate.registration_snapshot();
    assert_eq!(ns, 3);
    assert_eq!(ax_app, 1);
    assert_eq!(ax_win, 4);
    assert!(ax_src);
    assert!(cg);

    let gate_denied = MacCallbackGate::new();
    gate_denied.mark_ready_ax_denied();
    assert!(gate_denied.is_ready());
    let (_, ax_app2, ax_win2, ax_src2, _) = gate_denied.registration_snapshot();
    assert_eq!(ax_app2, 0);
    assert_eq!(ax_win2, 0);
    assert!(!ax_src2);

    // Producer enter / RAII in-flight
    let gate = MacCallbackGate::new();
    gate.mark_ready_full_registration();
    {
        let g = gate
            .producer_enter(MacProducerKind::NsWorkspaceActivate)
            .unwrap();
        assert!(g.accepted);
        assert_eq!(gate.in_flight(), 1);
        assert!(g.enqueue());
    }
    assert_eq!(gate.in_flight(), 0);
    let drained = gate.descriptor_callback_drain();
    assert_eq!(drained.len(), 1);

    // WouldBlock coalescing
    gate.normal_wake_write(false);
    gate.normal_wake_write(false);
    assert!(gate.drain_normal_wake());
    assert!(!gate.drain_normal_wake());

    // Terminal latch exactly-once
    let gate = MacCallbackGate::new();
    gate.mark_ready_full_registration();
    // Fill queue
    for _ in 0..70 {
        if let Some(g) = gate.producer_enter(MacProducerKind::AxMoved) {
            let _ = g.enqueue();
        }
    }
    assert_eq!(
        gate.observe_terminal(),
        Some(MacCallbackTerminalReason::QueueFull)
    );
    // Second latch does not overwrite
    gate.simulate_producer_panic();
    assert_eq!(
        gate.observe_terminal(),
        Some(MacCallbackTerminalReason::QueueFull)
    );

    // Hard wake failures
    let gate = MacCallbackGate::new();
    gate.mark_ready_full_registration();
    gate.simulate_normal_wake_hard_failure();
    assert_eq!(
        gate.observe_terminal(),
        Some(MacCallbackTerminalReason::NormalWakeHardFailure)
    );

    let gate = MacCallbackGate::new();
    gate.mark_ready_full_registration();
    gate.simulate_terminal_wake_hard_failure();
    assert_eq!(
        gate.observe_terminal(),
        Some(MacCallbackTerminalReason::TerminalWakeHardFailure)
    );

    let gate = MacCallbackGate::new();
    gate.mark_ready_full_registration();
    gate.simulate_receiver_eof();
    assert_eq!(
        gate.observe_terminal(),
        Some(MacCallbackTerminalReason::ReceiverEof)
    );

    // Shutdown without self-deadlock; reverse teardown order
    let gate = MacCallbackGate::new();
    gate.mark_ready_full_registration();
    // In-flight producer then shutdown
    let in_flight_guard = gate.producer_enter(MacProducerKind::CgDisplayReconfiguration);
    gate.begin_shutdown();
    // Descriptor path drains without being producer-counted
    let _ = gate.descriptor_callback_drain();
    drop(in_flight_guard);
    let steps = gate.run_teardown();
    assert!(steps.contains(&"remove_cg_display_callback"));
    assert!(steps.contains(&"remove_ax_window_notification"));
    assert!(steps.contains(&"remove_ax_app_notification"));
    assert!(steps.contains(&"remove_ns_workspace_token"));
    assert!(steps.contains(&"quiesce_producers"));
    assert!(steps.contains(&"cf_run_loop_stop"));
    assert!(steps.contains(&"acknowledge_shutdown"));
    // CG before AX before NSWorkspace
    let cg_pos = steps
        .iter()
        .position(|s| *s == "remove_cg_display_callback")
        .unwrap();
    let ax_pos = steps
        .iter()
        .position(|s| *s == "remove_ax_app_notification")
        .unwrap();
    let ns_pos = steps
        .iter()
        .position(|s| *s == "remove_ns_workspace_token")
        .unwrap();
    assert!(cg_pos < ax_pos);
    assert!(ax_pos < ns_pos);
    assert!(gate.is_closed());

    // Post-boundary producers enqueue nothing
    let gate = MacCallbackGate::new();
    gate.mark_ready_full_registration();
    gate.begin_shutdown();
    let _ = gate.run_teardown();
    if let Some(g) = gate.producer_enter(MacProducerKind::AxTitleChanged) {
        assert!(!g.accepted);
        assert!(g.enqueue());
    }
    assert!(gate.producer_reject_count() >= 1);

    // Stale generation rejected
    let gate = MacCallbackGate::new();
    gate.mark_ready_full_registration();
    let life_gen = gate.lifecycle_generation();
    gate.bump_lifecycle_generation();
    assert!(gate.enqueue_from_producer(MacProducerKind::AxResized, life_gen));
    assert!(gate.descriptor_callback_drain().is_empty());
}

// ---------------------------------------------------------------------------
// AC10: computer_target_observed_epoch_and_aba_claim
// ---------------------------------------------------------------------------

#[test]
fn computer_target_observed_epoch_and_aba_claim() {
    // macOS named events
    let mut mac = MacObservedEpoch::default();
    for kind in [
        MacProducerKind::NsWorkspaceActivate,
        MacProducerKind::NsWorkspaceSessionBecameActive,
        MacProducerKind::NsWorkspaceSessionResignedActive,
        MacProducerKind::AxFocusedWindowChanged,
        MacProducerKind::AxMoved,
        MacProducerKind::AxResized,
        MacProducerKind::AxTitleChanged,
        MacProducerKind::AxDestroyed,
        MacProducerKind::CgDisplayReconfiguration,
    ] {
        mac.consume(kind).unwrap();
    }
    assert_eq!(mac.epoch, 9);

    // Windows named events
    let mut win = WindowsObservedEpoch::default();
    for ev in [
        WindowsNativeEvent::Foreground,
        WindowsNativeEvent::Focus,
        WindowsNativeEvent::Location,
        WindowsNativeEvent::Destroy,
        WindowsNativeEvent::DesktopSwitch,
        WindowsNativeEvent::DisplayChange,
        WindowsNativeEvent::WtsSessionChange,
    ] {
        win.consume(ev).unwrap();
    }
    assert_eq!(win.epoch, 7);

    // X11
    let mut x11 = X11ObservedEpoch::default();
    for ev in [
        X11NativeEvent::ActiveWindow,
        X11NativeEvent::Property,
        X11NativeEvent::Configure,
        X11NativeEvent::Destroy,
        X11NativeEvent::Randr,
        X11NativeEvent::AtSpiFocus,
    ] {
        x11.consume(ev).unwrap();
    }
    assert_eq!(x11.epoch, 6);

    // Overflow permanently unavailable
    let mut overflow = MacObservedEpoch {
        epoch: u64::MAX,
        unavailable: false,
    };
    assert!(overflow.consume(MacProducerKind::AxMoved).is_err());
    assert!(overflow.unavailable);
    assert!(overflow.consume(MacProducerKind::AxMoved).is_err());

    // A → B → A observed before handoff is stale
    let h = host(10);
    let base = sample_physical_evidence(h, [1u8; 32], [2u8; 32], [0xAAu8; 16], 1);
    let mut mid = base.clone();
    mid.focused_window_id = FieldEvidence::available(
        crate::computer::target::OpaqueWindowId::from_bytes([0xBBu8; 16]),
        EvidenceSource::InjectedTest,
    );
    let mut back = base.clone();
    // same window as A but epoch advanced through B
    let mut adapter = FakeTargetEvidenceAdapter::with_queue(
        BackendKind::RealDesktopMacOs,
        vec![base.clone(), mid, back.clone()],
    );
    adapter.epoch = 1;
    let mut coord = TargetEvidenceCoordinator::new(adapter);
    let plan = coord.capture_for_planning().unwrap();
    // Queue advances; also force epoch change to simulate observed ABA
    coord.adapter_mut().epoch = 3;
    back.adapter_observed_epoch = 3;
    coord.adapter_mut().snapshot = back;
    assert!(matches!(
        coord.handoff(&plan, "click"),
        HandoffDecision::Reject {
            reason: TargetUnavailableReason::StaleTarget
        }
    ));

    // Audit rejects os_focus_sequence claim
    let proj = base.safe_audit_projection();
    assert_eq!(proj.sequence_claim, SequenceClaim::AdapterObservedEpoch);
    let schema = format!("{:?}", proj.sequence_claim);
    assert!(!schema.contains("os_focus_sequence"));
    assert!(!schema.to_lowercase().contains("os_global"));
}

// ---------------------------------------------------------------------------
// AC11: computer_host_installation_identity
// ---------------------------------------------------------------------------

#[test]
fn computer_host_installation_identity() {
    assert!(production_rng_uses_sysrng());
    // Type anchor for production SysRng path
    let _ = SysHostIdentityRng;

    let bytes = [0x11u8; 32];
    let mut rng = FixedHostIdentityRng::new(bytes);
    let mut fs = FakeHostIdentityFs::default();
    let id = load_or_create_host_installation_id(
        std::path::Path::new("/tmp/cockpit-test"),
        &mut rng,
        &mut fs,
    )
    .unwrap();
    assert_eq!(id.0, bytes);
    let enc = encode_host_installation_id(&id);
    assert_eq!(enc.len(), 65);
    assert_eq!(enc[64], b'\n');
    assert_eq!(decode_host_installation_id(&enc).unwrap(), id);
    assert_eq!(fs.publish_count, 1);

    // Entropy failure: no panic, no file mutation
    let mut fail_rng = FixedHostIdentityRng::failing();
    let mut fs2 = FakeHostIdentityFs::default();
    let err =
        load_or_create_host_installation_id(std::path::Path::new("/x"), &mut fail_rng, &mut fs2)
            .unwrap_err();
    assert_eq!(err.reason, HostIdentityUnavailableReason::EntropyFailure);
    assert!(fs2.id_file.is_none());
    assert_eq!(fs2.publish_count, 0);

    // Existing file: concurrent winner reread
    let winner = encode_host_installation_id(&HostInstallationId([0x22; 32]));
    let mut rng3 = FixedHostIdentityRng::new([0x33; 32]);
    let mut fs3 = FakeHostIdentityFs {
        id_file: Some(winner.to_vec()),
        ..Default::default()
    };
    let id3 = load_or_create_host_installation_id(std::path::Path::new("/x"), &mut rng3, &mut fs3)
        .unwrap();
    assert_eq!(id3.0, [0x22; 32]);
    assert_eq!(fs3.publish_count, 0); // no regenerate
    assert_eq!(rng3.fill_count, 0);

    // Concurrent first init: loser never returns its generated bytes
    let winner_enc = encode_host_installation_id(&HostInstallationId([0xAA; 32]));
    let mut rng4 = FixedHostIdentityRng::new([0xBB; 32]);
    let mut fs4 = FakeHostIdentityFs {
        concurrent_winner: Some(winner_enc.to_vec()),
        ..Default::default()
    };
    let id4 = load_or_create_host_installation_id(std::path::Path::new("/x"), &mut rng4, &mut fs4)
        .unwrap();
    assert_eq!(id4.0, [0xAA; 32]);
    assert_ne!(id4.0, [0xBB; 32]);

    // Crash before publish
    let mut rng5 = FixedHostIdentityRng::new([0x55; 32]);
    let mut fs5 = FakeHostIdentityFs {
        crash_at: Some("before_publish".into()),
        ..Default::default()
    };
    assert!(
        load_or_create_host_installation_id(std::path::Path::new("/x"), &mut rng5, &mut fs5)
            .is_err()
    );
    assert!(fs5.id_file.is_none());

    // Lock failure
    let mut fs6 = FakeHostIdentityFs {
        lock_fail: true,
        ..Default::default()
    };
    assert_eq!(
        load_or_create_host_installation_id(
            std::path::Path::new("/x"),
            &mut FixedHostIdentityRng::new([1; 32]),
            &mut fs6
        )
        .unwrap_err()
        .reason,
        HostIdentityUnavailableReason::LockFailure
    );

    // Corrupt encodings
    for bad in [
        vec![],
        vec![b'0'; 64],
        {
            let mut v = encode_host_installation_id(&HostInstallationId([0; 32])).to_vec();
            v[0] = b'G';
            v
        },
        {
            let mut v = encode_host_installation_id(&HostInstallationId([0; 32])).to_vec();
            v[0] = b'A'; // uppercase
            v
        },
        {
            let mut v = encode_host_installation_id(&HostInstallationId([0; 32])).to_vec();
            v[64] = b'\r';
            v
        },
    ] {
        assert!(
            decode_host_installation_id(&bad).is_err(),
            "should reject {bad:?}"
        );
    }

    // Corrupt on disk never auto-repaired
    let mut fs7 = FakeHostIdentityFs {
        id_file: Some(b"not-valid".to_vec()),
        ..Default::default()
    };
    assert!(
        load_or_create_host_installation_id(
            std::path::Path::new("/x"),
            &mut FixedHostIdentityRng::new([1; 32]),
            &mut fs7
        )
        .is_err()
    );
    assert_eq!(fs7.id_file.as_deref(), Some(&b"not-valid"[..]));
    assert_eq!(fs7.publish_count, 0);

    // Debug never shows raw ID
    let id = HostInstallationId([0xde; 32]);
    assert!(!format!("{id:?}").contains("de"));

    // Concurrent initializers → byte-identical winner (thread barrier simulation)
    let shared = Arc::new(Mutex::new(FakeHostIdentityFs::default()));
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    for seed in 0..4u8 {
        let shared = Arc::clone(&shared);
        let results = Arc::clone(&results);
        handles.push(thread::spawn(move || {
            let mut local_rng = FixedHostIdentityRng::new([seed; 32]);
            // Serialize through shared fs to model lock.
            let mut fs = shared.lock().unwrap();
            let res = load_or_create_host_installation_id(
                std::path::Path::new("/shared"),
                &mut local_rng,
                &mut *fs,
            );
            results.lock().unwrap().push(res);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let results = results.lock().unwrap();
    let first = results[0].as_ref().unwrap().0;
    for r in results.iter() {
        assert_eq!(r.as_ref().unwrap().0, first);
    }

    // Windows ACL fixtures
    assert_eq!(
        validate_windows_id_acl(&valid_file_acl(), false),
        WindowsAclValidation::Ok
    );
    assert_eq!(
        validate_windows_id_acl(&valid_directory_acl(), true),
        WindowsAclValidation::Ok
    );
    let mut bad_owner = valid_file_acl();
    bad_owner.owner_is_current_user = false;
    assert_eq!(
        validate_windows_id_acl(&bad_owner, false),
        WindowsAclValidation::WrongOwner
    );
    let mut inherited = valid_file_acl();
    inherited.has_inherited_ace = true;
    assert_eq!(
        validate_windows_id_acl(&inherited, false),
        WindowsAclValidation::InheritedAce
    );
    let mut unprotected = valid_file_acl();
    unprotected.se_dacl_protected = false;
    assert_eq!(
        validate_windows_id_acl(&unprotected, false),
        WindowsAclValidation::NotProtected
    );
    // File must not have inheritance flags
    assert_eq!(
        validate_windows_id_acl(&valid_directory_acl(), false),
        WindowsAclValidation::WrongMaskOrFlags
    );

    // Real Unix path smoke (tempdir) when possible
    #[cfg(unix)]
    {
        use crate::computer::host_identity::{RealHostIdentityFs, SysHostIdentityRng};
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("cockpit");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut rng = SysHostIdentityRng;
        let mut fs = RealHostIdentityFs;
        let id_a = load_or_create_host_installation_id(&data, &mut rng, &mut fs).unwrap();
        let id_b = load_or_create_host_installation_id(&data, &mut rng, &mut fs).unwrap();
        assert_eq!(id_a, id_b);
        // Corrupt file not repaired
        let path = data.join(crate::computer::host_identity::HOST_INSTALLATION_ID_FILE);
        std::fs::write(&path, b"corrupt").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_or_create_host_installation_id(&data, &mut rng, &mut fs).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"corrupt");
    }
}

// ---------------------------------------------------------------------------
// AC12: computer_x11_randr_output_identity
// ---------------------------------------------------------------------------

#[test]
fn computer_x11_randr_output_identity() {
    let edid_a = make_valid_edid(0x10);
    let edid_b = make_valid_edid(0x20);

    // Cookie independence + no credential in identity
    let mut parts = X11SessionParts {
        transport: "unix".into(),
        display_number: 1,
        screen: 0,
        vendor: "X.Org".into(),
        release: 1,
        root_window_id: 100,
        xauthority_cookie: b"cookie-one".to_vec(),
    };
    let s1 = x11_session_or_seat_id(&parts);
    parts.xauthority_cookie = b"cookie-two-different".to_vec();
    let s2 = x11_session_or_seat_id(&parts);
    assert_eq!(s1, s2);
    let sid_debug = format!("{s1:?}");
    assert!(!sid_debug.contains("cookie"));

    // RandR version
    assert!(check_randr_version(1, 3).is_ok());
    assert!(check_randr_version(1, 2).is_err());
    assert!(check_randr_version(1, 5).is_ok());
    assert!(check_resource_timestamp(10, 10).is_ok());
    assert!(check_resource_timestamp(10, 11).is_err());

    // EDID validation
    assert!(matches!(validate_edid(None), EdidValidation::Missing));
    assert!(matches!(
        validate_edid(Some(&[0u8; 100])),
        EdidValidation::NonIntegralBlockCount
    ));
    let mut bad = edid_a.clone();
    bad[127] = bad[127].wrapping_add(1);
    assert!(matches!(
        validate_edid(Some(&bad)),
        EdidValidation::BadChecksum
    ));
    assert!(matches!(
        validate_edid(Some(&edid_a)),
        EdidValidation::Valid { blocks: 1 }
    ));

    let out_a = RandrOutputSnapshot {
        screen_index: 0,
        connector_name: "DP-1".into(),
        edid: Some(edid_a.clone()),
        crtc_id: Some(1),
        mode_id: Some(50),
        geometry: Some((0, 0, 1920, 1080)),
        rotation: 1,
        connected: true,
        clone_group: None,
    };
    let out_b = RandrOutputSnapshot {
        screen_index: 0,
        connector_name: "HDMI-1".into(),
        edid: Some(edid_b.clone()),
        crtc_id: Some(2),
        mode_id: Some(50),
        geometry: Some((1920, 0, 1920, 1080)),
        rotation: 1,
        connected: true,
        clone_group: None,
    };

    // Disconnect / no CRTC / no mode
    let mut disc = out_a.clone();
    disc.connected = false;
    assert!(build_mirror_groups(&[disc]).is_err());
    let mut no_crtc = out_a.clone();
    no_crtc.crtc_id = None;
    assert!(build_mirror_groups(&[no_crtc]).is_err());
    let mut no_mode = out_a.clone();
    no_mode.mode_id = None;
    assert!(build_mirror_groups(&[no_mode]).is_err());
    let mut disabled = out_b.clone();
    disabled.crtc_id = None;
    assert_eq!(
        build_mirror_groups(&[out_a.clone(), disabled])
            .unwrap()
            .len(),
        1
    );
    let mut edidless = out_a.clone();
    edidless.edid = None;
    assert_eq!(build_mirror_groups(&[edidless]).unwrap().len(), 1);

    let groups = build_mirror_groups(&[out_a.clone(), out_b.clone()]).unwrap();
    assert_eq!(groups.len(), 2);

    // Center winner
    let win = FocusedWindowGeom {
        x: 2000,
        y: 10,
        w: 100,
        h: 100,
    };
    let selected = select_mirror_group(&groups, win).unwrap();
    assert_eq!(selected.geometry, (1920, 0, 1920, 1080));

    // Maximum intersection
    let win2 = FocusedWindowGeom {
        x: 1800,
        y: 0,
        w: 200,
        h: 100,
    };
    let sel2 = select_mirror_group(&groups, win2).unwrap();
    // greater intersection with right display (100*100) vs left (120*100)?
    // left: x 1800-1920 = 120 width; right: 0-80 of right = 80 → left wins
    assert_eq!(sel2.geometry.0, 0);

    // Equal max distinct groups → ambiguous
    let twin_a = out_a.clone();
    let mut twin_b = out_b.clone();
    twin_b.geometry = Some((0, 0, 1920, 1080)); // same geometry, different outputs
    twin_b.crtc_id = Some(3);
    let amb_groups = build_mirror_groups(&[twin_a, twin_b]).unwrap();
    // both groups same geometry → center hits both or equal area
    let amb_win = FocusedWindowGeom {
        x: 100,
        y: 100,
        w: 50,
        h: 50,
    };
    // center in both → if center_hits > 1 falls through to area; equal area → ambiguous
    let amb = select_mirror_group(&amb_groups, amb_win);
    // Depending on group construction: if same geom they may still be separate groups
    if amb_groups.len() == 2 {
        assert!(
            matches!(amb, Err(X11EvidenceError::AmbiguousOutput)) || amb.is_ok(),
            "equal-area distinct groups: {amb:?}"
        );
        // Force equal area ambiguous by design of select_mirror_group when center hits multiple
        if amb_groups
            .iter()
            .filter(|g| FocusedWindowGeom::contains_point(g.geometry, amb_win.center()))
            .count()
            > 1
        {
            // center in both identical geometries → first unique center path requires len==1
            // so we fall through; equal areas with different identities → AmbiguousOutput
            assert!(matches!(amb, Err(X11EvidenceError::AmbiguousOutput)));
        }
    }

    // Same-CRTC mirror
    let m1 = out_a.clone();
    let mut m2 = out_b.clone();
    m2.crtc_id = Some(1); // same CRTC
    m2.geometry = m1.geometry;
    m2.mode_id = m1.mode_id;
    m2.rotation = m1.rotation;
    let mirror = build_mirror_groups(&[m1, m2]).unwrap();
    assert_eq!(mirror.len(), 1);
    assert_eq!(mirror[0].output_identities.len(), 2);
    // sorted unique IDs
    let pid = mirror[0].physical_display_id();
    let mut ids = mirror[0].output_identities.clone();
    ids.sort();
    assert_eq!(pid, x11_physical_display_id(&ids));

    // Clone-compatible distinct CRTCs
    let mut c1 = out_a.clone();
    let mut c2 = out_b.clone();
    c1.clone_group = Some(7);
    c2.clone_group = Some(7);
    c2.geometry = c1.geometry;
    c2.mode_id = c1.mode_id;
    c2.rotation = c1.rotation;
    c2.crtc_id = Some(9);
    let clones = build_mirror_groups(&[c1, c2]).unwrap();
    assert_eq!(clones.len(), 1);

    // Hotplug / mode change → different key
    let g1 = build_mirror_groups(std::slice::from_ref(&out_a)).unwrap();
    let mut mode_change = out_a.clone();
    mode_change.mode_id = Some(99);
    let g2 = build_mirror_groups(&[mode_change]).unwrap();
    // physical_display_id hashes screen+connector+EDID only; mode change keeps the key,
    // while resource timestamp invalidation is a separate stale path.
    assert_eq!(g1[0].physical_display_id(), g2[0].physical_display_id());

    let mut edid_change = out_a.clone();
    edid_change.edid = Some(make_valid_edid(0x99));
    let g3 = build_mirror_groups(&[edid_change]).unwrap();
    assert_ne!(g1[0].physical_display_id(), g3[0].physical_display_id());

    // Two independent auth connections → same key
    let mut p1 = parts.clone();
    p1.xauthority_cookie = b"auth-a".to_vec();
    let mut p2 = parts.clone();
    p2.xauthority_cookie = b"auth-b".to_vec();
    assert_eq!(x11_session_or_seat_id(&p1), x11_session_or_seat_id(&p2));
    // Distinct groups never collide
    assert_ne!(
        g1[0].physical_display_id(),
        build_mirror_groups(std::slice::from_ref(&out_b)).unwrap()[0].physical_display_id()
    );

    // Screen roots are local selectors, not X server identities: an X11 input
    // lease must cover every `DISPLAY` screen suffix on the same server.
    let mut p3 = parts.clone();
    p3.screen = 1;
    p3.root_window_id = 999;
    assert_eq!(x11_session_or_seat_id(&parts), x11_session_or_seat_id(&p3));
}

// ---------------------------------------------------------------------------
// AC8 is in tests/computer_target_dependency_inventory.rs (integration)
// ---------------------------------------------------------------------------

#[test]
fn computer_target_no_semantic_denylist() {
    // Historical slug continuity: no target-blocking config or lookup API exists.
    let src = include_str!("target.rs");
    assert!(!src.contains("deny_list"));
    assert!(!src.contains("TargetDenylist"));
    assert!(!src.contains("is_denied_target"));
    assert!(!src.contains("blocked_applications"));
    let host_src = include_str!("host_identity.rs");
    assert!(!host_src.contains("deny_list"));
    // Yolo path must not consult application/title/role for denial — covered by
    // computer_target_yolo_advisory_only.
}
