//! Static production-wiring ratchets for the computer-use live loop.
//!
//! AC5 unit tests call `handle_native_computer_items` in isolation and would
//! still compile if the driver loops stopped invoking the production
//! registration. These source inspections lock that registration, the
//! Continue-injection collapse at every consumer, and open-before-advertise
//! detach on paths that cannot own a coordinator.

#[test]
fn computer_live_production_loop_registers_handle_retained() {
    let driver = include_str!("../src/engine/driver/mod.rs");
    let noninteractive = include_str!("../src/engine/driver/noninteractive.rs");
    let native = include_str!("../src/engine/driver/computer_native.rs");

    assert!(
        native.contains("async fn handle_native_computer_items"),
        "AC5 binds tests to the named production registration symbol"
    );
    let driver_hits = driver
        .matches("handle_retained_native_computer_items")
        .count();
    assert!(
        driver_hits >= 3,
        "interactive driver must define and call handle_retained_native_computer_items from both turn loops, got {driver_hits}"
    );
    assert!(
        noninteractive.contains("handle_retained_native_computer_items"),
        "noninteractive loop must invoke the same production registration"
    );
}

#[test]
fn computer_live_continue_consumers_require_injection_payload() {
    let driver = include_str!("../src/engine/driver/mod.rs");
    let noninteractive = include_str!("../src/engine/driver/noninteractive.rs");
    let review = include_str!("../src/assistants/self_improvement.rs");
    let loop_runner = include_str!("../src/engine/schedule/loop_runner.rs");
    let swarm = include_str!("../src/engine/schedule/swarm.rs");
    let turn_phases = include_str!("../src/engine/agent/turn_phases.rs");

    assert!(
        turn_phases.contains("has_retained_native_computer_items"),
        "native-only Continue is decided in turn_phases"
    );
    for (name, source) in [
        ("driver", driver),
        ("noninteractive", noninteractive),
        ("self_improvement", review),
        ("loop_runner", loop_runner),
        ("swarm", swarm),
    ] {
        assert!(
            source.contains("collapse_continue_without_injection"),
            "{name} must not pop Continue unless an injection payload is queued"
        );
    }
}

#[test]
fn computer_live_forks_and_reviews_detach_inherited_geometry() {
    let loop_runner = include_str!("../src/engine/schedule/loop_runner.rs");
    let review = include_str!("../src/assistants/self_improvement.rs");
    assert!(
        loop_runner.contains("detach_inherited_native_computer"),
        "scheduled-loop forks must not re-advertise a parent's opened geometry"
    );
    assert!(
        review.contains("detach_inherited_native_computer"),
        "background review must not re-advertise the root's opened geometry"
    );
}

#[test]
fn computer_live_default_geometry_helper_is_gone() {
    let builtin = include_str!("../src/engine/builtin/mod.rs");
    assert!(
        !builtin.contains("fn default_computer_geometry"),
        "open-before-advertise forbids a hardcoded default geometry"
    );
}

#[test]
fn computer_live_non_loop_completions_cannot_advertise_opened_geometry() {
    let native = include_str!("../src/engine/driver/computer_native.rs");
    let build = include_str!("../src/engine/model/build.rs");
    let model = include_str!("../src/engine/model/mod.rs");
    let dispatch = include_str!("../src/engine/model/dispatch.rs");
    let shrink = include_str!("../src/engine/deleg_shrink.rs");
    let compact = include_str!("../src/engine/driver/context_reduction.rs");
    let driver = include_str!("../src/engine/driver/mod.rs");
    let noninteractive = include_str!("../src/engine/driver/noninteractive.rs");

    assert!(
        !native.contains("geometry: Some(coordinator.geometry()"),
        "successful open must not persist opened geometry onto long-lived Agent.params"
    );
    assert!(
        native.contains("fn with_live_loop_native_computer_geometry"),
        "live-loop overlay must copy opened geometry onto a request-local agent"
    );
    assert!(
        driver
            .matches("with_live_loop_native_computer_geometry")
            .count()
            >= 2,
        "both interactive turn loops must overlay geometry only onto the live-turn agent"
    );
    assert!(
        noninteractive.contains("with_live_loop_native_computer_geometry"),
        "noninteractive live turns must overlay geometry only onto the turn-local agent"
    );
    assert!(
        build.contains("native_computer_live_turn_active"),
        "wire advertisement must require the live-loop injection scope, not geometry alone"
    );
    assert!(
        model.contains("params.detach_inherited_native_computer();"),
        "utility_params_for must strip inherited native computer advertisement"
    );
    assert!(
        dispatch.contains("params.detach_inherited_native_computer();"),
        "compact utility dispatch must strip inherited native computer advertisement"
    );
    assert!(
        shrink.contains("params.detach_inherited_native_computer();"),
        "delegation-shrink briefs must strip inherited native computer advertisement"
    );
    assert!(
        compact.contains("params.detach_inherited_native_computer();"),
        "compact brief drafts must strip inherited native computer advertisement"
    );
}
