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
