use std::collections::BTreeSet;

use super::*;
use crate::config::extended::ApprovalMode;

#[test]
fn acquisition_definition_requests_but_does_not_self_grant_capture() {
    let definition = crate::agents::embedded_internal_default(ACQUISITION_AGENT).unwrap();
    assert!(
        definition
            .vnext
            .as_ref()
            .unwrap()
            .capabilities
            .contains(&crate::agents::AgentCapability::SealedAcquisitionCapture)
    );
    assert!(
        !crate::agents::PostureResolution::from_def(&definition)
            .grants()
            .contains(&crate::agents::AgentCapability::SealedAcquisitionCapture),
        "definition request must not become runtime authority"
    );
    assert_eq!(definition.tools.as_ref().unwrap().len(), 6);
}

#[tokio::test]
async fn acquisition_approval_posture_is_narrowed_without_mutating_session() {
    for (parent, expected) in [
        (ApprovalMode::Yolo, ApprovalMode::Yolo),
        (ApprovalMode::Auto, ApprovalMode::Manual),
        (ApprovalMode::Manual, ApprovalMode::Manual),
    ] {
        let runtime = AcquisitionRuntime::new(BTreeSet::new(), parent);
        let actual = with_acquisition_runtime(runtime, async {
            crate::tools::trusted_child_acquisition::effective_approval_mode(parent)
        })
        .await;
        assert_eq!(actual, expected);
    }
}

#[test]
fn steering_is_bounded_and_never_requests_the_value() {
    assert!((1..=2).contains(&MAX_TERMINAL_NUDGES));
    assert!(TERMINAL_NUDGE.contains("exactly one terminal move"));
    assert!(!TERMINAL_NUDGE.contains("tell me the value"));
}
