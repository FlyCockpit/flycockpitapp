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
        native.contains("pub async fn handle_native_computer_items"),
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
