use std::collections::VecDeque;

use cockpit_proto::{Request, Response, WorkspaceTrustMode};

use super::BlockingDaemonRequestError;
use super::set_workspace_trust_with_retry;

#[test]
fn trust_requires_exact_ack_and_returns_authoritative_generation() {
    let mut replies = VecDeque::from([Ok(Response::WorkspaceTrustSet {
        config_generation: 12,
    })]);
    let generation = set_workspace_trust_with_retry("/repo", WorkspaceTrustMode::Trust, 10, |_| {
        replies.pop_front().unwrap()
    })
    .unwrap();
    assert_eq!(generation, 12);

    let error = set_workspace_trust_with_retry("/repo", WorkspaceTrustMode::Trust, 10, |_| {
        Ok(Response::Ack)
    })
    .unwrap_err();
    assert!(error.contains("unexpected workspace trust response"));
}

#[test]
fn trust_conflict_refreshes_generation_and_retries_once() {
    let mut requests = Vec::new();
    let mut replies = VecDeque::from([
        Err(BlockingDaemonRequestError::Conflict("stale".into())),
        Ok(Response::StartupDisclosures {
            org_sync: None,
            connector: None,
            config_generation: 20,
        }),
        Ok(Response::WorkspaceTrustSet {
            config_generation: 21,
        }),
    ]);
    let generation =
        set_workspace_trust_with_retry("/repo", WorkspaceTrustMode::IgnoreConfig, 10, |request| {
            requests.push(request);
            replies.pop_front().unwrap()
        })
        .unwrap();

    assert_eq!(generation, 21);
    assert!(matches!(requests[1], Request::GetStartupDisclosures { .. }));
    assert!(matches!(
        requests[2],
        Request::SetWorkspaceTrust {
            expected_config_generation: 20,
            ..
        }
    ));
}

#[test]
fn trust_non_conflict_failure_does_not_retry() {
    let mut calls = 0;
    let error = set_workspace_trust_with_retry("/repo", WorkspaceTrustMode::Untrusted, 10, |_| {
        calls += 1;
        Err(BlockingDaemonRequestError::Other("offline".into()))
    })
    .unwrap_err();
    assert_eq!(calls, 1);
    assert_eq!(error, "offline");
}
