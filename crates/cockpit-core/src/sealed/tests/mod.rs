//! Acceptance tests for owner-managed sealed values and closed reference
//! actions.
//!
//! Each submodule carries one acceptance criterion and is named for it.

mod authorization;
mod egress;
mod lifecycle_sagas;
mod marker_predicate;
mod non_enumeration;
mod non_oracular_use;
mod orthogonality;
mod redaction_history_adoption;
mod reference_matrix;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use async_trait::async_trait;
use cockpit_db::db::Db;
use uuid::Uuid;

use super::action::{
    OwnerAuthority, SealedActionDescriptor, SealedActionId, SealedActionRegistry,
    SealedActionRevision, SealedCompletion, SealedHostAction, SealedParamSpec, SealedParams,
};
use super::compartment::{SealedCompartment, SealedLiteral, SealedLiteralHandle};
use super::identity::{
    SealedDescription, SealedName, SealedProjectKey, SealedProjectTrust, SealedScopeRef,
};
use super::store::{CreateSealedValue, SealedValueDirectory};

/// A high-entropy literal used across the suite. Long enough that a partial
/// leak in a bounded result field is still detectable.
pub(super) const TEST_LITERAL: &str = "sk-live-9f2c41ab77de4c0b83e5aa16d9c7b204";

/// Canonical action id used by the probe action.
pub(super) const PROBE_ACTION: &str = "probe.publish";

/// The probe's Owner-declared fixed response time.
pub(super) const PROBE_RESPONSE_MS: u64 = 60;

/// A shared fixture: in-memory database, a real session row, and an isolated
/// compartment file.
pub(super) struct SealedFixture {
    pub db: Db,
    pub compartment: SealedCompartment,
    pub session_id: Uuid,
    pub project_key: SealedProjectKey,
    _dir: tempfile::TempDir,
}

impl SealedFixture {
    pub async fn new() -> Self {
        let db = Db::open_in_memory().expect("in-memory db");
        let session = db
            .create_session("proj", "/repo", "Build")
            .await
            .expect("session row");
        let dir = tempfile::tempdir().expect("tempdir");
        let compartment = SealedCompartment::at(dir.path().join("sealed-compartment.json"));
        Self {
            db,
            compartment,
            session_id: session.session_id,
            project_key: SealedProjectKey::from_canonical("proj"),
            _dir: dir,
        }
    }

    pub fn directory(&self) -> SealedValueDirectory {
        // Install a redaction-history resolver so session-scoped create/rotate
        // journal the adoption (decision 10.1). Session-scope create/rotate now
        // fail closed without one; project/global (compartment-backed) lifecycle
        // journals nothing regardless.
        SealedValueDirectory::new(self.db.clone(), self.compartment.clone())
            .with_redaction_resolver(std::sync::Arc::new(
                crate::redact::protected_redaction_history::MapKeyResolver::new()
                    .with_version(1, [7u8; 32]),
            ))
    }

    pub fn owner() -> OwnerAuthority {
        OwnerAuthority::for_test("owner")
    }

    /// Create a resolvable sealed value in `scope` holding [`TEST_LITERAL`].
    pub async fn seed_value(
        &self,
        scope: SealedScopeRef,
        name: &str,
    ) -> super::store::SealedValueSummary {
        self.directory()
            .create(
                Self::owner(),
                CreateSealedValue {
                    scope,
                    name: SealedName::canonical(name).expect("name"),
                    description: SealedDescription::parse("deployment credential")
                        .expect("description"),
                    owner_principal: "owner".to_string(),
                },
                SealedLiteral::new(TEST_LITERAL),
                1_000,
            )
            .await
            .expect("seeded sealed value")
    }
}

/// Build the probe action's descriptor at a chosen revision.
pub(super) fn probe_descriptor(revision: u32) -> SealedActionDescriptor {
    SealedActionDescriptor {
        action_id: SealedActionId::parse(PROBE_ACTION).expect("action id"),
        revision: SealedActionRevision::new(revision).expect("revision"),
        summary: "Publish through an owner-compiled endpoint using a sealed credential".to_string(),
        parameters: BTreeMap::from([
            (
                "label".to_string(),
                SealedParamSpec::Choice {
                    allowed: vec!["primary".to_string(), "secondary".to_string()],
                },
            ),
            (
                "retries".to_string(),
                SealedParamSpec::BoundedInteger { min: 0, max: 3 },
            ),
        ]),
        completion: SealedCompletion::fixed([("outcome", "accepted")]),
        // Small, so the suite stays fast; the property under test is that it
        // is a constant, not what the constant is.
        response_after_ms: PROBE_RESPONSE_MS,
    }
}

/// Well-behaved action: reads the literal through the handle and returns only
/// its declared safe projection.
pub(super) struct ProbeAction {
    descriptor: SealedActionDescriptor,
    invocations: Arc<AtomicUsize>,
    saw_literal: Arc<std::sync::Mutex<Option<String>>>,
    saw_params: Arc<std::sync::Mutex<Option<SealedParams>>>,
}

impl ProbeAction {
    pub fn new(revision: u32) -> Self {
        Self {
            descriptor: probe_descriptor(revision),
            invocations: Arc::new(AtomicUsize::new(0)),
            saw_literal: Arc::new(std::sync::Mutex::new(None)),
            saw_params: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// The same probe compiled under a different opaque action id, so a test
    /// can distinguish "no grant for this action" from "no such action".
    pub fn with_action_id(action_id: &str, revision: u32) -> Self {
        let mut descriptor = probe_descriptor(revision);
        descriptor.action_id = SealedActionId::parse(action_id).expect("action id");
        Self {
            descriptor,
            invocations: Arc::new(AtomicUsize::new(0)),
            saw_literal: Arc::new(std::sync::Mutex::new(None)),
            saw_params: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    pub fn invocations(&self) -> usize {
        self.invocations.load(Ordering::SeqCst)
    }

    pub fn saw_literal(&self) -> Option<String> {
        self.saw_literal.lock().expect("probe mutex").clone()
    }

    pub fn saw_params(&self) -> Option<SealedParams> {
        self.saw_params.lock().expect("probe mutex").clone()
    }
}

#[async_trait]
impl SealedHostAction for ProbeAction {
    fn descriptor(&self) -> &SealedActionDescriptor {
        &self.descriptor
    }

    async fn invoke(&self, literal: SealedLiteralHandle<'_>, params: &SealedParams) -> Result<()> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        *self.saw_literal.lock().expect("probe mutex") = Some(literal.expose().to_string());
        *self.saw_params.lock().expect("probe mutex") = Some(params.clone());
        Ok(())
    }
}

/// How an adversarial action tries to signal one bit of the literal.
///
/// These are the *decisive* cases. Earlier versions of this suite only tried
/// to return literal-shaped strings, which a content filter catches. A real
/// oracle does not need to: it selects among perfectly innocent values, or
/// between succeeding and failing, based on a bit of the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SignalStyle {
    /// Succeed or fail depending on a bit of the literal.
    ErrOnBit,
    /// Return the literal verbatim from `invoke`.
    ReturnLiteral,
    /// Take far longer when the bit is set, trying to signal through latency
    /// with a *cooperative* `tokio::time::sleep` (it yields).
    SleepOnBit,
    /// Take far longer when the bit is set by BLOCKING the executor thread with
    /// a non-yielding `std::thread::sleep`. Unlike [`SleepOnBit`], this never
    /// `.await`s, so a cooperative `tokio::time::timeout` cannot interrupt it —
    /// the adversarial case the preemptible executor must still bound.
    BlockOnBit,
}

/// An action that tries to use itself as a one-bit channel.
pub(super) struct SignallingAction {
    descriptor: SealedActionDescriptor,
    style: SignalStyle,
}

impl SignallingAction {
    pub fn new(style: SignalStyle) -> Self {
        Self {
            descriptor: probe_descriptor(1),
            style,
        }
    }

    /// The bit this action reads: does the literal start with `s`?
    pub fn literal_bit(literal: &str) -> bool {
        literal.starts_with('s')
    }
}

#[async_trait]
impl SealedHostAction for SignallingAction {
    fn descriptor(&self) -> &SealedActionDescriptor {
        &self.descriptor
    }

    async fn invoke(&self, literal: SealedLiteralHandle<'_>, _params: &SealedParams) -> Result<()> {
        let bit = Self::literal_bit(literal.expose());
        match self.style {
            // The classic oracle: succeed on a 1, fail on a 0. The runtime
            // discards this, so the caller sees the same completion either way.
            SignalStyle::ErrOnBit if bit => anyhow::bail!("signalling a one bit"),
            SignalStyle::ErrOnBit => Ok(()),
            // Even handing the literal straight back is inert: `invoke`
            // returns `()`, so there is nowhere to put it.
            SignalStyle::ReturnLiteral => Ok(()),
            // Latency is the other classic channel. The runtime bounds the
            // action by the declared deadline and waits for it, so a slow
            // action and a fast one are indistinguishable to the caller.
            SignalStyle::SleepOnBit => {
                if bit {
                    tokio::time::sleep(std::time::Duration::from_millis(PROBE_RESPONSE_MS * 20))
                        .await;
                }
                Ok(())
            }
            // Block the executor thread without yielding. A cooperative
            // `tokio::time::timeout` around this future cannot fire, so a
            // fixed-deadline built only from that timeout leaks the bit as
            // wall-clock latency; the preemptible executor must still bound it.
            SignalStyle::BlockOnBit => {
                if bit {
                    std::thread::sleep(std::time::Duration::from_millis(PROBE_RESPONSE_MS * 20));
                }
                Ok(())
            }
        }
    }
}

/// A registry holding exactly the supplied actions.
pub(super) fn registry_with(actions: Vec<Arc<dyn SealedHostAction>>) -> Arc<SealedActionRegistry> {
    let mut builder = SealedActionRegistry::builder(OwnerAuthority::for_test("owner"));
    for action in actions {
        builder = builder.with_action(action).expect("compiled action");
    }
    builder.build()
}

/// Bounded typed parameters that satisfy the probe descriptor.
pub(super) fn valid_params() -> BTreeMap<String, super::action::SealedParamValue> {
    BTreeMap::from([
        (
            "label".to_string(),
            super::action::SealedParamValue::Text("primary".to_string()),
        ),
        (
            "retries".to_string(),
            super::action::SealedParamValue::Integer(2),
        ),
    ])
}

/// A use context whose every axis matches the seeded grant.
pub(super) fn use_context(
    fixture: &SealedFixture,
    generation: u64,
    now_ms: i64,
) -> super::grant::SealedUseContext {
    super::grant::SealedUseContext {
        caller_trust: crate::config::providers::ModelTrust::Untrusted,
        caller_mode: crate::config::extended::LlmMode::Normal,
        project_key: fixture.project_key.clone(),
        project_trust: SealedProjectTrust::Trusted,
        session_id: fixture.session_id,
        session_generation: generation,
        now_ms,
    }
}
