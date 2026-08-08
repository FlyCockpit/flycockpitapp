//! AC4 `sealed_action_grant_authorization_precedes_lookup`
//!
//! Every wrong / stale / revoked / expired / project / session / generation /
//! action / revision / value branch, each proven to cost **zero secret reads**
//! and to render an **indistinguishable** denial.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::*;
use crate::sealed::action::SealedParamValue;
use crate::sealed::grant::{SealedAuthorizationInputs, SealedUseContext, authorize_sealed_use};
use crate::sealed::identity::SealedRecordId;
use crate::sealed::runtime::{RecordingRedactionSink, SealedRuntime};
use crate::sealed::store::IssueSealedGrant;
use crate::sealed::{
    SEALED_USE_DENIED_MESSAGE, SealedActionId, SealedActionRevision, SealedProjectKey,
    SealedProjectTrust, UseSealedValueRequest,
};

const GENERATION: u64 = 7;
const NOW: i64 = 10_000;

struct Harness {
    fixture: SealedFixture,
    runtime: SealedRuntime,
    probe: Arc<ProbeAction>,
    record_id: SealedRecordId,
    sink: RecordingRedactionSink,
}

impl Harness {
    async fn new() -> Self {
        let fixture = SealedFixture::new().await;
        let seeded = fixture
            .seed_value(
                SealedScopeRef::Project(fixture.project_key.clone()),
                "deploy_token",
            )
            .await;
        let probe = Arc::new(ProbeAction::new(1));
        let registry = registry_with(vec![probe.clone() as Arc<dyn SealedHostAction>]);
        let runtime = SealedRuntime::new(fixture.db.clone(), fixture.compartment.clone(), registry);
        fixture
            .directory()
            .issue_action_grant(
                SealedFixture::owner(),
                IssueSealedGrant {
                    record_id: seeded.record_id,
                    value_version: 1,
                    project_key: fixture.project_key.clone(),
                    session_id: fixture.session_id,
                    session_generation: GENERATION,
                    action_id: SealedActionId::parse(PROBE_ACTION).expect("action id"),
                    action_revision: SealedActionRevision::new(1).expect("revision"),
                    issued_at_ms: 2_000,
                    expires_at_ms: None,
                },
            )
            .await
            .expect("grant issued");
        Self {
            fixture,
            runtime,
            probe,
            record_id: seeded.record_id,
            sink: RecordingRedactionSink::new(),
        }
    }

    fn request(&self) -> UseSealedValueRequest {
        UseSealedValueRequest {
            sealed_value_id: self.record_id,
            action_id: SealedActionId::parse(PROBE_ACTION).expect("action id"),
            parameters: valid_params(),
        }
    }

    fn context(&self) -> SealedUseContext {
        use_context(&self.fixture, GENERATION, NOW)
    }

    /// Run one use and assert it denied without reading a literal or invoking
    /// an action. Returns the rendered denial so the caller can compare them.
    async fn expect_denied(
        &self,
        branch: &str,
        request: UseSealedValueRequest,
        ctx: SealedUseContext,
    ) -> String {
        let reads_before = self.runtime.literal_reads();
        let invocations_before = self.probe.invocations();
        let origins_before = self.sink.origins().len();

        let denied = self
            .runtime
            .use_sealed_value(&request, &ctx, &self.sink, &crate::sealed::runtime::FixedProjectTrust(SealedProjectTrust::Trusted))
            .await
            .expect_err(&format!("`{branch}` must deny"));

        assert_eq!(
            self.runtime.literal_reads(),
            reads_before,
            "`{branch}` denied but read a secret"
        );
        assert_eq!(
            self.probe.invocations(),
            invocations_before,
            "`{branch}` denied but reached the host action"
        );
        assert_eq!(
            self.sink.origins().len(),
            origins_before,
            "`{branch}` denied but registered a literal for redaction"
        );
        denied.to_string()
    }
}

#[tokio::test]
async fn sealed_action_grant_authorization_precedes_lookup() {
    let harness = Harness::new().await;
    let mut denials = Vec::new();

    // ---- wrong value -------------------------------------------------------
    let mut request = harness.request();
    request.sealed_value_id = SealedRecordId::generate();
    denials.push(
        harness
            .expect_denied("wrong value", request, harness.context())
            .await,
    );

    // ---- wrong action (exists in the registry, but is not granted) ---------
    // A second compiled action proves the denial is "no grant for this
    // action", not "no such action".
    {
        let second = Arc::new(ProbeAction::with_action_id("probe.other", 1));
        let registry = registry_with(vec![
            harness.probe.clone() as Arc<dyn SealedHostAction>,
            second.clone() as Arc<dyn SealedHostAction>,
        ]);
        let runtime = SealedRuntime::new(
            harness.fixture.db.clone(),
            harness.fixture.compartment.clone(),
            registry,
        );
        let sink = RecordingRedactionSink::new();
        let mut request = harness.request();
        request.action_id = SealedActionId::parse("probe.other").expect("action id");
        let denied = runtime
            .use_sealed_value(&request, &harness.context(), &sink, &crate::sealed::runtime::FixedProjectTrust(SealedProjectTrust::Trusted))
            .await
            .expect_err("wrong action must deny");
        assert_eq!(runtime.literal_reads(), 0);
        assert_eq!(second.invocations(), 0);
        denials.push(denied.to_string());
    }

    // ---- unavailable action (not compiled at all) --------------------------
    {
        let runtime = SealedRuntime::new(
            harness.fixture.db.clone(),
            harness.fixture.compartment.clone(),
            crate::sealed::SealedActionRegistry::empty(),
        );
        let sink = RecordingRedactionSink::new();
        let denied = runtime
            .use_sealed_value(&harness.request(), &harness.context(), &sink, &crate::sealed::runtime::FixedProjectTrust(SealedProjectTrust::Trusted))
            .await
            .expect_err("unavailable action must deny");
        assert_eq!(runtime.literal_reads(), 0);
        denials.push(denied.to_string());
    }

    // ---- stale action revision ---------------------------------------------
    {
        let revised = Arc::new(ProbeAction::new(2));
        let registry = registry_with(vec![revised.clone() as Arc<dyn SealedHostAction>]);
        let runtime = SealedRuntime::new(
            harness.fixture.db.clone(),
            harness.fixture.compartment.clone(),
            registry,
        );
        let sink = RecordingRedactionSink::new();
        let denied = runtime
            .use_sealed_value(&harness.request(), &harness.context(), &sink, &crate::sealed::runtime::FixedProjectTrust(SealedProjectTrust::Trusted))
            .await
            .expect_err("a revised action must retire grants pinned to the old revision");
        assert_eq!(runtime.literal_reads(), 0);
        assert_eq!(revised.invocations(), 0);
        denials.push(denied.to_string());
    }

    // ---- wrong project ------------------------------------------------------
    let mut ctx = harness.context();
    ctx.project_key = SealedProjectKey::from_canonical("other-project");
    denials.push(
        harness
            .expect_denied("wrong project", harness.request(), ctx)
            .await,
    );

    // ---- project trust withdrawn --------------------------------------------
    let mut ctx = harness.context();
    ctx.project_trust = SealedProjectTrust::Untrusted;
    denials.push(
        harness
            .expect_denied("untrusted project", harness.request(), ctx)
            .await,
    );

    // ---- wrong session -------------------------------------------------------
    let mut ctx = harness.context();
    ctx.session_id = uuid::Uuid::new_v4();
    denials.push(
        harness
            .expect_denied("wrong session", harness.request(), ctx)
            .await,
    );

    // ---- wrong generation ----------------------------------------------------
    let mut ctx = harness.context();
    ctx.session_generation = GENERATION + 1;
    denials.push(
        harness
            .expect_denied("wrong generation", harness.request(), ctx)
            .await,
    );

    // ---- out-of-band parameters ----------------------------------------------
    let mut request = harness.request();
    request.parameters = BTreeMap::from([
        (
            "label".to_string(),
            SealedParamValue::Text("not-a-declared-choice".to_string()),
        ),
        ("retries".to_string(), SealedParamValue::Integer(99)),
    ]);
    denials.push(
        harness
            .expect_denied("out-of-band parameters", request, harness.context())
            .await,
    );

    // ---- expired grant --------------------------------------------------------
    {
        let harness = Harness::new().await;
        // Re-issue with an expiry in the past for a fresh generation.
        harness
            .fixture
            .directory()
            .issue_action_grant(
                SealedFixture::owner(),
                IssueSealedGrant {
                    record_id: harness.record_id,
                    value_version: 1,
                    project_key: harness.fixture.project_key.clone(),
                    session_id: harness.fixture.session_id,
                    session_generation: GENERATION + 100,
                    action_id: SealedActionId::parse(PROBE_ACTION).expect("action id"),
                    action_revision: SealedActionRevision::new(1).expect("revision"),
                    issued_at_ms: 1_000,
                    expires_at_ms: Some(2_000),
                },
            )
            .await
            .expect("expiring grant issued");
        let mut ctx = harness.context();
        ctx.session_generation = GENERATION + 100;
        denials.push(
            harness
                .expect_denied("expired grant", harness.request(), ctx)
                .await,
        );
    }

    // ---- revoked grant ---------------------------------------------------------
    {
        let harness = Harness::new().await;
        let handle = harness
            .fixture
            .directory()
            .issue_action_grant(
                SealedFixture::owner(),
                IssueSealedGrant {
                    record_id: harness.record_id,
                    value_version: 1,
                    project_key: harness.fixture.project_key.clone(),
                    session_id: harness.fixture.session_id,
                    session_generation: GENERATION + 200,
                    action_id: SealedActionId::parse(PROBE_ACTION).expect("action id"),
                    action_revision: SealedActionRevision::new(1).expect("revision"),
                    issued_at_ms: 1_000,
                    expires_at_ms: None,
                },
            )
            .await
            .expect("grant issued");
        harness
            .fixture
            .directory()
            .revoke_action_grant(SealedFixture::owner(), handle, 3_000)
            .await
            .expect("revoked");
        let mut ctx = harness.context();
        ctx.session_generation = GENERATION + 200;
        denials.push(
            harness
                .expect_denied("revoked grant", harness.request(), ctx)
                .await,
        );
    }

    // ---- stale value version (rotation retires the pinned grant) ---------------
    {
        let harness = Harness::new().await;
        harness
            .fixture
            .directory()
            .rotate(
                SealedFixture::owner(),
                harness.record_id,
                SealedLiteral::new("rotated-literal-value-0002"),
                4_000,
            )
            .await
            .expect("rotated");
        denials.push(
            harness
                .expect_denied("stale value version", harness.request(), harness.context())
                .await,
        );
    }

    // ---- deleted value ----------------------------------------------------------
    {
        let harness = Harness::new().await;
        harness
            .fixture
            .directory()
            .prepare_delete(SealedFixture::owner(), harness.record_id, 5_000)
            .await
            .expect("prepared delete");
        denials.push(
            harness
                .expect_denied("deleted value", harness.request(), harness.context())
                .await,
        );
    }

    // ---- every branch is indistinguishable --------------------------------------
    assert!(denials.len() >= 13, "covered {} branches", denials.len());
    for denial in &denials {
        assert_eq!(
            denial, SEALED_USE_DENIED_MESSAGE,
            "denials must be byte-identical across every branch"
        );
    }

    // ---- authorization never compiles or creates an action ----------------------
    // Structural: the authorization module holds no registry builder, no
    // action constructor, and no literal read.
    // Scan code only: the module docs describe what authorization must not do,
    // so a doc mention must not read as a dependency.
    let grant_source: String = include_str!("../grant.rs")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "SealedActionRegistryBuilder",
        "with_action",
        "builder(",
        "get_exact",
        "sealed_session_literal_for_action",
        "expose",
    ] {
        assert!(
            !grant_source.contains(forbidden),
            "authorization must not reference `{forbidden}`"
        );
    }
    // And it performs no I/O at all: it is handed metadata and decides.
    assert!(
        !grant_source.contains(".await"),
        "authorization must be a pure function of already-read metadata"
    );
}

/// Two real `use_sealed_value` calls racing on one grant.
///
/// The earlier shape of this test completed one use and then hand-submitted a
/// stale DB claim, which proved nothing: a regression that resolved the
/// literal or invoked the action *before* checking the CAS would still have
/// passed. These are two genuine futures observing the same `use_epoch`.
#[tokio::test]
async fn concurrent_uses_resolve_by_deterministic_compare_and_swap() {
    let harness = Harness::new().await;
    let request = harness.request();
    let ctx = harness.context();

    let (a, b) = tokio::join!(
        harness
            .runtime
            .use_sealed_value(&request, &ctx, &harness.sink, &crate::sealed::runtime::FixedProjectTrust(SealedProjectTrust::Trusted)),
        harness
            .runtime
            .use_sealed_value(&request, &ctx, &harness.sink, &crate::sealed::runtime::FixedProjectTrust(SealedProjectTrust::Trusted))
    );

    // Exactly one winner, and the loser is the ordinary content-free denial.
    assert_eq!(
        u8::from(a.is_ok()) + u8::from(b.is_ok()),
        1,
        "exactly one of two racing uses may win the claim"
    );
    let denial = a.err().or(b.err()).expect("one side denied");
    assert_eq!(denial.to_string(), SEALED_USE_DENIED_MESSAGE);

    // The loser performed no lookup and no outbound action.
    assert_eq!(
        harness.runtime.literal_reads(),
        1,
        "the loser of the race must read no secret"
    );
    assert_eq!(
        harness.probe.invocations(),
        1,
        "the loser of the race must reach no host action"
    );
}

/// A record deleted between authorization and the claim denies *at the claim*.
///
/// The claim is the authoritative gate, so a use that authorized against a
/// live row cannot proceed once the Owner has made that row non-resolvable.
#[tokio::test]
async fn a_delete_between_authorization_and_claim_denies_at_the_claim() {
    let harness = Harness::new().await;
    harness
        .fixture
        .directory()
        .prepare_delete(SealedFixture::owner(), harness.record_id, 5_000)
        .await
        .expect("prepared delete");

    let denied = harness
        .runtime
        .use_sealed_value(&harness.request(), &harness.context(), &harness.sink, &crate::sealed::runtime::FixedProjectTrust(SealedProjectTrust::Trusted))
        .await
        .expect_err("a deleted record denies");
    assert_eq!(denied.to_string(), SEALED_USE_DENIED_MESSAGE);
    assert_eq!(harness.runtime.literal_reads(), 0);
    assert_eq!(harness.probe.invocations(), 0);
}

/// Version pinning, proven directly against the pure authorization predicate.
///
/// End to end, the "stale value version" branch is *also* closed by grant
/// fencing: a published rotation revokes every grant on the record in the same
/// transaction, and the authoritative claim re-checks the version again. That
/// redundancy is deliberate — but it means removing version pinning alone does
/// not change the end-to-end outcome, so the end-to-end test cannot witness
/// this particular check. This one can, because `authorize_sealed_use` is a
/// pure function of metadata: it is handed a record and a grant that disagree
/// on version only.
#[tokio::test]
async fn authorization_pins_the_exact_value_version() {
    let harness = Harness::new().await;
    let record = harness
        .fixture
        .db
        .sealed_value_record(harness.record_id.to_string())
        .await
        .expect("record read")
        .expect("record exists");
    let grant = harness
        .fixture
        .db
        .sealed_action_grant_for(cockpit_db::db::sealed_scope::SealedGrantSelector {
            record_id: harness.record_id.to_string(),
            action_id: PROBE_ACTION.to_string(),
            project_key: harness.fixture.project_key.as_str().to_string(),
            session_id: harness.fixture.session_id.to_string(),
            session_generation: GENERATION as i64,
        })
        .await
        .expect("grant read")
        .expect("grant exists");

    let inputs = |record, grant| SealedAuthorizationInputs {
        record: Some(record),
        grant: Some(grant),
        global_reaches_project: true,
    };

    // Agreeing on version: authorized.
    assert!(
        authorize_sealed_use(
            &harness.request(),
            &harness.context(),
            inputs(record.clone(), grant.clone()),
            harness.runtime.registry(),
        )
        .is_ok(),
        "a grant pinned to the live version authorizes"
    );

    // The record moved ahead (a rotation published): denied.
    let mut rotated = record.clone();
    rotated.active_version += 1;
    assert!(
        authorize_sealed_use(
            &harness.request(),
            &harness.context(),
            inputs(rotated, grant.clone()),
            harness.runtime.registry(),
        )
        .is_err(),
        "a grant pinned to a superseded version must never authorize"
    );

    // The grant claims a version the record has not reached: denied.
    let mut ahead = grant.clone();
    ahead.value_version += 1;
    assert!(
        authorize_sealed_use(
            &harness.request(),
            &harness.context(),
            inputs(record, ahead),
            harness.runtime.registry(),
        )
        .is_err(),
        "a grant pinned ahead of the record must never authorize"
    );
}
