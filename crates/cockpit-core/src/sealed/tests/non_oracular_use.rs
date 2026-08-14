//! AC5 `use_sealed_value_is_non_oracular`
//!
//! A live exact grant reaches only the declared opaque host-action interface,
//! carrying bounded typed parameters, and returns only that action's declared
//! safe result. Concrete adapter execution is owned by
//! `sealed-value-owner-management`.

use std::sync::Arc;

use super::*;
use crate::sealed::action::SealedParamValue;
use crate::sealed::runtime::{RecordingRedactionSink, SealedRuntime};
use crate::sealed::store::IssueSealedGrant;
use crate::sealed::{
    SEALED_USE_DENIED_MESSAGE, SealedActionId, SealedActionRevision, UseSealedValueRequest,
};

const GENERATION: u64 = 3;
const NOW: i64 = 20_000;

async fn grant_for(fixture: &SealedFixture, record_id: crate::sealed::identity::SealedRecordId) {
    fixture
        .directory()
        .issue_action_grant(
            SealedFixture::owner(),
            IssueSealedGrant {
                record_id,
                value_version: 1,
                project_key: fixture.project_key.clone(),
                session_id: fixture.session_id,
                session_generation: GENERATION,
                action_id: SealedActionId::parse(PROBE_ACTION).expect("action id"),
                action_revision: SealedActionRevision::new(1).expect("revision"),
                issued_at_ms: 1_000,
                expires_at_ms: None,
            },
        )
        .await
        .expect("grant issued");
}

fn request(record_id: crate::sealed::identity::SealedRecordId) -> UseSealedValueRequest {
    UseSealedValueRequest {
        sealed_value_id: record_id,
        action_id: SealedActionId::parse(PROBE_ACTION).expect("action id"),
        parameters: valid_params(),
    }
}

#[tokio::test]
async fn use_sealed_value_is_non_oracular() {
    // ---- the happy path reaches only the declared interface ----------------
    let fixture = SealedFixture::new().await;
    let seeded = fixture
        .seed_value(
            SealedScopeRef::Project(fixture.project_key.clone()),
            "deploy_token",
        )
        .await;
    grant_for(&fixture, seeded.record_id).await;

    let probe = Arc::new(ProbeAction::new(1));
    let runtime = SealedRuntime::new(
        fixture.db.clone(),
        fixture.compartment.clone(),
        registry_with(vec![probe.clone() as Arc<dyn SealedHostAction>]),
    );
    let sink = RecordingRedactionSink::new();

    let projection = runtime
        .use_sealed_value(
            &request(seeded.record_id),
            &use_context(&fixture, GENERATION, NOW),
            &sink,
            &crate::sealed::runtime::FixedProjectTrust(SealedProjectTrust::Trusted),
        )
        .await
        .expect("a live exact grant is usable");

    // The action ran exactly once and saw the literal only through its handle.
    assert_eq!(probe.invocations(), 1);
    assert_eq!(probe.saw_literal().as_deref(), Some(TEST_LITERAL));
    assert_eq!(runtime.literal_reads(), 1, "exactly one secret read");

    // Redaction was registered *before* the action ran, under the canonical
    // typed origin.
    let origins = sink.origins();
    assert_eq!(origins.len(), 1, "the literal was redacted before use");
    let identity = crate::sealed::identity::parse_sealed_redaction_origin(&origins[0])
        .expect("origin carries canonical typed identity");
    assert_eq!(identity.record_id, Some(seeded.record_id));
    assert_eq!(identity.name.as_str(), "deploy_token");
    assert_eq!(identity.version, 1);

    // The result is exactly the declared safe projection: no more fields, no
    // fewer, and nothing derived from the literal.
    // The response is the descriptor's constant, not anything the action chose.
    assert_eq!(projection.len(), 1);
    assert_eq!(
        projection.get("outcome").map(|value| value.as_str()),
        Some("accepted")
    );
    // The action did receive its bounded typed parameter — it just has no way
    // to report anything about it.
    assert_eq!(
        probe
            .saw_params()
            .and_then(|params| params.get("retries").cloned()),
        Some(SealedParamValue::Integer(2))
    );
    let rendered = format!("{projection:?}");
    assert!(!rendered.contains(TEST_LITERAL));
    assert!(!rendered.contains(&TEST_LITERAL.len().to_string()));

    // ---- a bounded parameter is really bounded ------------------------------
    let mut over_bound = request(seeded.record_id);
    over_bound
        .parameters
        .insert("retries".to_string(), SealedParamValue::Integer(9_999));
    let denied = runtime
        .use_sealed_value(
            &over_bound,
            &use_context(&fixture, GENERATION, NOW),
            &sink,
            &crate::sealed::runtime::FixedProjectTrust(SealedProjectTrust::Trusted),
        )
        .await
        .expect_err("an out-of-band parameter is refused");
    assert_eq!(denied.to_string(), SEALED_USE_DENIED_MESSAGE);
    assert_eq!(probe.invocations(), 1, "the action was never reached");

    // ---- THE DECISIVE CASE: an action cannot signal a bit of the literal ----
    // Closing the result *type* only bounds bandwidth; selection among closed
    // values is still selection. So the caller-visible response is owned by
    // the runtime and fixed by the descriptor. Here two sealed values differ
    // in the bit an adversarial action reads, and the action tries to signal
    // it by succeeding on one and failing on the other. The caller must not be
    // able to tell them apart.
    let mut observed = Vec::new();
    for (literal, name) in [
        ("secret-alpha-high-entropy-0001", "bit_one"),
        ("0xdeadbeef-high-entropy-000002", "bit_zero"),
    ] {
        // Sanity: the two literals really do differ in the signalled bit.
        assert_ne!(
            SignallingAction::literal_bit("secret-alpha-high-entropy-0001"),
            SignallingAction::literal_bit("0xdeadbeef-high-entropy-000002")
        );

        let fixture = SealedFixture::new().await;
        let seeded = fixture
            .directory()
            .create(
                SealedFixture::owner(),
                crate::sealed::CreateSealedValue {
                    scope: SealedScopeRef::Project(fixture.project_key.clone()),
                    name: SealedName::canonical(name).expect("name"),
                    description: SealedDescription::parse("credential").expect("description"),
                    owner_principal: "owner".to_string(),
                },
                SealedLiteral::new(literal),
                1_000,
            )
            .await
            .expect("seeded");
        grant_for(&fixture, seeded.record_id).await;

        let action = Arc::new(SignallingAction::new(SignalStyle::ErrOnBit));
        let runtime = SealedRuntime::new(
            fixture.db.clone(),
            fixture.compartment.clone(),
            registry_with(vec![action as Arc<dyn SealedHostAction>]),
        );
        let sink = RecordingRedactionSink::new();
        let response = runtime
            .use_sealed_value(
                &request(seeded.record_id),
                &use_context(&fixture, GENERATION, NOW),
                &sink,
                &crate::sealed::runtime::FixedProjectTrust(SealedProjectTrust::Trusted),
            )
            .await;
        observed.push(match response {
            Ok(projection) => format!("ok:{projection:?}"),
            Err(denied) => format!("err:{denied}"),
        });
    }
    assert_eq!(
        observed[0], observed[1],
        "an action must not be able to signal a bit of the literal through \
         its result, its failure, or the difference between them"
    );
    assert!(
        observed[0].starts_with("ok:"),
        "the fixed completion is returned even when the action failed"
    );
    assert!(
        !observed[0].contains("secret-alpha") && !observed[0].contains("deadbeef"),
        "the completion carries no literal material"
    );

    // Returning the literal from `invoke` is inert: the signature has no
    // channel for it, so this is a type error the compiler already prevented
    // and a runtime no-op besides.
    {
        let fixture = SealedFixture::new().await;
        let seeded = fixture
            .seed_value(
                SealedScopeRef::Project(fixture.project_key.clone()),
                "deploy_token",
            )
            .await;
        grant_for(&fixture, seeded.record_id).await;
        let action = Arc::new(SignallingAction::new(SignalStyle::ReturnLiteral));
        let runtime = SealedRuntime::new(
            fixture.db.clone(),
            fixture.compartment.clone(),
            registry_with(vec![action as Arc<dyn SealedHostAction>]),
        );
        let sink = RecordingRedactionSink::new();
        let projection = runtime
            .use_sealed_value(
                &request(seeded.record_id),
                &use_context(&fixture, GENERATION, NOW),
                &sink,
                &crate::sealed::runtime::FixedProjectTrust(SealedProjectTrust::Trusted),
            )
            .await
            .expect("completes");
        assert!(!format!("{projection:?}").contains(TEST_LITERAL));
    }

    // ---- structural: a destination is unrepresentable, not merely filtered ---
    let mut descriptor = probe_descriptor(1);
    descriptor.parameters.insert(
        "url".to_string(),
        crate::sealed::SealedParamSpec::Choice {
            allowed: vec!["primary".to_string()],
        },
    );
    assert!(
        descriptor.validate().is_ok(),
        "a closed choice is safe whatever it is named"
    );
    let mut attacker = valid_params();
    attacker.insert(
        "url".to_string(),
        SealedParamValue::Text("https://exfil.example/steal".to_string()),
    );
    assert!(
        descriptor.bind_parameters(&attacker).is_err(),
        "a caller can never author the string that reaches an adapter"
    );

    // The completion is a constant, so there is no per-call choice to make.
    assert_eq!(descriptor.completion.len(), 1);
    assert_eq!(descriptor.completion.get("outcome"), Some("accepted"));

    // ---- an empty registry means no action is reachable at all --------------
    let empty = crate::sealed::SealedActionRegistry::empty();
    assert!(
        empty
            .resolve(&SealedActionId::parse(PROBE_ACTION).expect("action id"))
            .is_none()
    );
}

/// An action cannot signal a bit through how long it takes.
///
/// The caller-visible duration is the descriptor's declared constant. The
/// runtime bounds the action by that deadline *and* waits for it, so an action
/// that sleeps twenty times the deadline on a set bit is indistinguishable
/// from one that returns immediately.
#[tokio::test]
async fn an_action_cannot_signal_through_latency() {
    let mut observed = Vec::new();
    for literal in [
        "secret-alpha-high-entropy-0001", // bit set   -> action sleeps long
        "0xdeadbeef-high-entropy-000002", // bit clear -> action returns at once
    ] {
        let fixture = SealedFixture::new().await;
        let seeded = fixture
            .directory()
            .create(
                SealedFixture::owner(),
                crate::sealed::CreateSealedValue {
                    scope: SealedScopeRef::Project(fixture.project_key.clone()),
                    name: SealedName::canonical("latency_probe").expect("name"),
                    description: SealedDescription::parse("credential").expect("description"),
                    owner_principal: "owner".to_string(),
                },
                SealedLiteral::new(literal),
                1_000,
            )
            .await
            .expect("seeded");
        grant_for(&fixture, seeded.record_id).await;

        let action = Arc::new(SignallingAction::new(SignalStyle::SleepOnBit));
        let runtime = SealedRuntime::new(
            fixture.db.clone(),
            fixture.compartment.clone(),
            registry_with(vec![action as Arc<dyn SealedHostAction>]),
        );
        let sink = RecordingRedactionSink::new();
        let started = std::time::Instant::now();
        runtime
            .use_sealed_value(
                &request(seeded.record_id),
                &use_context(&fixture, GENERATION, NOW),
                &sink,
                &crate::sealed::runtime::FixedProjectTrust(SealedProjectTrust::Trusted),
            )
            .await
            .expect("completes");
        observed.push(started.elapsed());
    }

    // Both land at the declared deadline. The generous ceiling absorbs host
    // scheduler jitter; what matters is that the 20x sleep does not show up.
    let deadline = std::time::Duration::from_millis(PROBE_RESPONSE_MS);
    for elapsed in &observed {
        assert!(
            *elapsed >= deadline,
            "a use must not return before the declared deadline: {elapsed:?}"
        );
        assert!(
            *elapsed < deadline * 10,
            "a slow action must not extend the caller-visible duration: {elapsed:?}"
        );
    }
}

/// AC1: an action cannot signal a bit by BLOCKING its executor thread.
///
/// This is the decisive case the cooperative `tokio::time::timeout` could not
/// cover. The action does a non-yielding `std::thread::sleep` (20x the
/// deadline) when a bit of the literal is set. A timeout that shares the
/// caller's task can never fire against it, so the pre-fix runtime lets the
/// blocking action push the caller-visible completion out to ~20x the deadline
/// — encoding the bit. The preemptible executor runs the action off the
/// caller's async worker threads, so the fixed deadline still wins and both the
/// bit-set and bit-clear uses complete within a tight window of `response_after`
/// and of each other.
///
/// Multi-thread flavour so the blocking action and the caller's deadline timer
/// have independent threads to make progress on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocking_action_cannot_signal_through_latency() {
    let mut observed = Vec::new();
    for literal in [
        "secret-alpha-high-entropy-0001", // bit set   -> action BLOCKS long
        "0xdeadbeef-high-entropy-000002", // bit clear -> action returns at once
    ] {
        // Sanity: the two literals really do differ in the signalled bit.
        assert_ne!(
            SignallingAction::literal_bit("secret-alpha-high-entropy-0001"),
            SignallingAction::literal_bit("0xdeadbeef-high-entropy-000002")
        );

        let fixture = SealedFixture::new().await;
        let seeded = fixture
            .directory()
            .create(
                SealedFixture::owner(),
                crate::sealed::CreateSealedValue {
                    scope: SealedScopeRef::Project(fixture.project_key.clone()),
                    name: SealedName::canonical("blocking_probe").expect("name"),
                    description: SealedDescription::parse("credential").expect("description"),
                    owner_principal: "owner".to_string(),
                },
                SealedLiteral::new(literal),
                1_000,
            )
            .await
            .expect("seeded");
        grant_for(&fixture, seeded.record_id).await;

        let action = Arc::new(SignallingAction::new(SignalStyle::BlockOnBit));
        let runtime = SealedRuntime::new(
            fixture.db.clone(),
            fixture.compartment.clone(),
            registry_with(vec![action as Arc<dyn SealedHostAction>]),
        );
        let sink = RecordingRedactionSink::new();
        // Monotonic clock; measure only the padded use window.
        let started = std::time::Instant::now();
        let projection = runtime
            .use_sealed_value(
                &request(seeded.record_id),
                &use_context(&fixture, GENERATION, NOW),
                &sink,
                &crate::sealed::runtime::FixedProjectTrust(SealedProjectTrust::Trusted),
            )
            .await
            .expect("completes");
        // The response is still the descriptor's fixed completion on both paths.
        assert_eq!(
            projection.get("outcome").map(|value| value.as_str()),
            Some("accepted")
        );
        observed.push(started.elapsed());
    }

    let deadline = std::time::Duration::from_millis(PROBE_RESPONSE_MS);
    // Each use both waits for the floor and is bounded by the ceiling. The
    // ceiling is the property under test: the 20x BLOCK (1200ms) must not show
    // up. A generous 10x window absorbs host scheduler jitter and the private
    // runtime spin-up while still being far below the 20x a leak would need.
    for elapsed in &observed {
        assert!(
            *elapsed >= deadline,
            "a use must not return before the declared deadline: {elapsed:?}"
        );
        assert!(
            *elapsed < deadline * 10,
            "a blocking action must not extend the caller-visible duration: {elapsed:?}"
        );
    }
    // Decisively: the bit-set (blocking) and bit-clear uses are within a tight
    // bound of each other, so the completion time carries no bit of the literal.
    let (a, b) = (observed[0], observed[1]);
    let spread = a.max(b) - a.min(b);
    assert!(
        spread < deadline * 4,
        "blocking-vs-nonblocking completion times must not encode the bit: \
         bit_set={a:?} bit_clear={b:?} spread={spread:?}"
    );
}

/// Trust withdrawn between authorization and release denies, and reads no
/// secret. A snapshot taken at authorization time is not good enough.
#[tokio::test]
async fn trust_withdrawn_before_release_denies_without_reading_the_secret() {
    struct WithdrawnTrust;
    #[async_trait::async_trait]
    impl crate::sealed::runtime::SealedProjectTrustSource for WithdrawnTrust {
        async fn current_trust(&self) -> anyhow::Result<SealedProjectTrust> {
            Ok(SealedProjectTrust::Untrusted)
        }
    }

    let fixture = SealedFixture::new().await;
    let seeded = fixture
        .seed_value(
            SealedScopeRef::Project(fixture.project_key.clone()),
            "deploy_token",
        )
        .await;
    grant_for(&fixture, seeded.record_id).await;
    let probe = Arc::new(ProbeAction::new(1));
    let runtime = SealedRuntime::new(
        fixture.db.clone(),
        fixture.compartment.clone(),
        registry_with(vec![probe.clone() as Arc<dyn SealedHostAction>]),
    );
    let sink = RecordingRedactionSink::new();

    // Authorization runs against Trusted; the live source says otherwise.
    let denied = runtime
        .use_sealed_value(
            &request(seeded.record_id),
            &use_context(&fixture, GENERATION, NOW),
            &sink,
            &WithdrawnTrust,
        )
        .await
        .expect_err("withdrawn trust must deny");
    assert_eq!(denied.to_string(), SEALED_USE_DENIED_MESSAGE);
    assert_eq!(
        runtime.literal_reads(),
        0,
        "a trust withdrawal must deny before the secret is read"
    );
    assert_eq!(probe.invocations(), 0);
    assert!(sink.origins().is_empty(), "nothing was registered for use");
}
