use super::*;

#[tokio::test]
async fn learn_saves_conformant_foreground_skill() {
    let (mut driver, tmp, root, requests) = learn_driver(false, "learned-workflow", 2);
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let (turn_tx, _turn_rx) = mpsc::channel(64);
    let prompt = crate::skills::build_learn_prompt("");

    driver
        .run_user_input(UserSubmission::text(prompt.clone()), &queue, &turn_tx)
        .await
        .unwrap();

    let first_request = requests
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    assert!(first_request.contains("cockpit verify --local"));
    assert!(first_request.contains("local verification completed successfully"));
    assert!(first_request.contains("Create a reusable Agent Skill"));
    assert!(first_request.contains("skill_manage"));
    requests
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();

    let config = crate::config::extended::load_for_cwd(tmp.path());
    let skills = crate::skills::discover(tmp.path(), &config.skills).unwrap();
    let skill = crate::skills::find_by_name(&skills, "learned-workflow").unwrap();
    crate::skills::validate_conformant_package(skill).unwrap();
    let provenance: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("learned-workflow/.cockpit-provenance.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(provenance["created_origin"], "foreground");
}

#[tokio::test]
async fn learn_respects_write_gate() {
    let (mut driver, _tmp, root, requests) = learn_driver(true, "gated-learn", 1);
    let db = driver.session.db.clone();
    let session_id = driver.session.id;
    let (events, _event_rx) = tokio::sync::broadcast::channel(8);
    let hub = Arc::new(crate::engine::interrupt::InterruptHub::new(
        events,
        Arc::new(std::sync::RwLock::new(Arc::new(
            crate::redact::RedactionTable::empty(),
        ))),
        Arc::new(std::sync::atomic::AtomicUsize::new(1)),
        db.clone(),
        session_id,
    ));
    driver.set_interrupt_hub(hub.clone());
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let (turn_tx, _turn_rx) = mpsc::channel(64);
    let task = tokio::spawn(async move {
        driver
            .run_user_input(
                UserSubmission::text(crate::skills::build_learn_prompt("our verified workflow")),
                &queue,
                &turn_tx,
            )
            .await
    });

    loop {
        if !db.list_open_interrupts(session_id).unwrap().is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(hub.park_all_registered(), 1);
    task.await.unwrap().unwrap();
    assert!(!root.join("gated-learn/SKILL.md").exists());
    let row = db.list_open_interrupts(session_id).unwrap().remove(0);
    let parked = row.parked.unwrap();
    assert_eq!(parked.tool, "skill_manage");
    assert_eq!(parked.call_id, "learn-save");
    assert_eq!(parked.args, learn_tool_args("gated-learn"));
    assert_eq!(
        parked.resume.call_origin,
        crate::db::needs_attention::InterruptCallOrigin::Foreground
    );
    let first_request = requests
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    assert!(first_request.contains("cockpit verify --local"));
    assert!(first_request.contains("our verified workflow"));
}
