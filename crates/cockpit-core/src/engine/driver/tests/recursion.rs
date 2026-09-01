use super::*;

#[test]
fn task_recursion_rejects_delegated_child_without_budget() {
    let (mut driver, _tmp) = test_driver(1);
    set_active_delegated_recursion(
        &mut driver,
        crate::engine::builtin::DelegationRecursionContext::default(),
    );

    let err = driver
        .resolve_task_recursion("explore", Some(0), &None)
        .expect_err("no recursive budget");
    assert!(
        err.contains("not allowed") || err.contains("no remaining"),
        "{err}"
    );
}

#[test]
fn agent_vnext_runtime_uses_effective_grant_not_legacy_recursion_context() {
    let (mut driver, tmp) = test_driver(1);
    let definition = crate::agents::parse_agent(
        r#"---
description: Bounded root delegate
schemaVersion: 1
agentId: authored/root
roles: [code]
modelSlots:
  primary:
    purpose: Delegate bounded work
    minContextTokens: 1
    requiredCapabilities: [text_generation]
    locality: any
    allowDefaultFallback: false
delegation:
  allowedChildren:
    - kind: portable_ref
      ref: authored/child
  maxDescendantDepth: 2
  maxConcurrentChildren: 1
  targets: [same_root]
---
body
"#,
        "root",
        tmp.path().join("root.md"),
    )
    .unwrap();
    let grant = definition
        .vnext
        .as_ref()
        .unwrap()
        .resolve_grant(&crate::agents::VnextHostPolicy::for_session_config(
            &driver.config.extended(),
        ))
        .unwrap();
    let mut agent = (*driver.stack[0].agent).clone();
    agent.delegated = true;
    // A launch-v1 frame can carry a deliberately hostile legacy context without
    // changing its authority: task admission uses the effective grant below.
    agent.delegation_recursion = crate::engine::builtin::DelegationRecursionContext {
        enabled: false,
        remaining_depth: 0,
        allowed_targets: Vec::new(),
        same_model_only: true,
    };
    agent.vnext_grant = Some(grant);
    driver.stack[0].agent = Arc::new(agent);

    let recursion = driver
        .resolve_task_recursion("child", Some(99), &None)
        .expect("launch-v1 does not consult legacy recursion context");
    assert_eq!(
        recursion,
        crate::engine::builtin::DelegationRecursionContext::default()
    );
}

#[test]
fn task_recursion_must_reduce_inherited_depth() {
    let (mut driver, _tmp) = test_driver(1);
    set_active_delegated_recursion(
        &mut driver,
        crate::engine::builtin::DelegationRecursionContext {
            enabled: true,
            remaining_depth: 1,
            allowed_targets: vec!["explore".to_string()],
            same_model_only: true,
        },
    );

    let err = driver
        .resolve_task_recursion("explore", Some(1), &None)
        .expect_err("child depth must be lower than parent depth");
    assert!(err.contains("exceeds"), "{err}");

    let child = driver
        .resolve_task_recursion("explore", Some(0), &None)
        .expect("leaf explore recursion allowed");
    assert_eq!(child.remaining_depth, 0);
    assert!(child.same_model_only);
    assert_eq!(child.allowed_targets, vec!["explore".to_string()]);
}

#[test]
fn task_recursion_rejects_model_selector_for_same_model_special_case() {
    let (mut driver, _tmp) = test_driver(1);
    set_active_delegated_recursion(
        &mut driver,
        crate::engine::builtin::DelegationRecursionContext {
            enabled: true,
            remaining_depth: 1,
            allowed_targets: vec!["explore".to_string()],
            same_model_only: true,
        },
    );
    let model =
        crate::engine::model_roles::DelegationModelSelector::from_value(Some(&serde_json::json!({
            "kind": "category",
            "category": "cheap_code"
        })))
        .unwrap();

    let err = driver
        .resolve_task_recursion("explore", Some(0), &model)
        .expect_err("same-model recursion rejects model selector");
    assert!(err.contains("must omit `model`"), "{err}");
}

#[test]
fn task_recursion_rejects_deepthink_depth() {
    let (driver, _tmp) = test_driver(1);
    let err = driver
        .resolve_task_recursion("deepthink", Some(1), &None)
        .expect_err("deepthink is always a leaf");
    assert!(err.contains("tool-free leaf"), "{err}");

    let leaf = driver
        .resolve_task_recursion("deepthink", Some(0), &None)
        .expect("leaf deepthink delegation is allowed");
    assert_eq!(leaf.remaining_depth, 0);
    assert!(leaf.allowed_targets.is_empty());
}

#[tokio::test]
async fn quick_recursion_override_off_rejects_root_recursive_depth() {
    let (mut driver, tmp) = test_driver(1);
    write_recursion_policy(tmp.path());
    driver.refresh_config_from_disk_for_tests();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

    driver
        .run_control(
            DriverControl::SetDelegationRecursion {
                enabled: false,
                default_depth: 0,
            },
            &tx,
        )
        .await;

    let err = driver
        .resolve_task_recursion("Build", Some(1), &None)
        .expect_err("quick off disables root recursion");
    assert!(err.contains("disabled"), "{err}");
}

#[tokio::test]
async fn quick_recursion_override_depths_apply_without_bypassing_policy() {
    for depth in 1..=6 {
        let (mut driver, tmp) = test_driver(1);
        write_recursion_policy(tmp.path());
        driver.refresh_config_from_disk_for_tests();
        let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

        driver
            .run_control(
                DriverControl::SetDelegationRecursion {
                    enabled: true,
                    default_depth: depth,
                },
                &tx,
            )
            .await;

        let ctx = driver
            .resolve_task_recursion("Build", None, &None)
            .expect("default depth grants allowed recursive child");
        assert_eq!(ctx.remaining_depth, depth);
        assert!(ctx.enabled);

        let err = driver
            .resolve_task_recursion("Plan", None, &None)
            .expect_err("override must not bypass allowed-target policy");
        assert!(err.contains("may not grant"), "{err}");
    }
}
