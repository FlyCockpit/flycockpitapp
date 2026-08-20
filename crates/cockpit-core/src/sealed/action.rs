//! Immutable action instances and the closed runtime registry.
//!
//! An untrusted agent may *select* a granted action by sealed-value id and
//! bounded typed parameters. It may never supply an endpoint, a command, an
//! environment key, a header, a request template, or an output projection.
//! That rule is enforced here, structurally, in two places:
//!
//! * [`SealedActionDescriptor::validate`] rejects any parameter or result
//!   field whose name is a targeting concept, and bounds every type. A
//!   descriptor that could carry a destination cannot be built at all.
//! * [`SealedActionRegistry`] is *closed*: it is built once behind an
//!   [`OwnerAuthority`] token and frozen. The built registry has no
//!   registration method and no enumeration method, so project config,
//!   plugins, environment, remote services, tools, and model arguments have no
//!   path to create or retarget an action.
//!
//! # The action is not an oracle
//!
//! Closing the parameter and result *types* bounds bandwidth; it does not
//! remove the channel, because selection among closed values is still
//! selection. An action holding the literal and choosing which allowed
//! constant to return leaks one bit per call, and a bounded integer parameter
//! selects the bit offset — reuse the grant and the whole secret walks out.
//!
//! So a host action returns **nothing caller-visible at all**. It gets the
//! literal, it performs its Owner-defined effect, and its answer is discarded.
//! What the caller sees is [`SealedActionDescriptor::completion`]: a fixed
//! constant the Owner declared when the instance was compiled, before any
//! literal existed. It is identical on success and on failure, so neither the
//! action's result nor its error can encode anything.
//!
//! The same reasoning applies to *how long* the call takes:
//! [`SealedActionDescriptor::response_after_ms`] is a declared constant, and
//! the runtime both bounds the action by it and waits for it, so duration is
//! a constant of the descriptor too.
//!
//! Owner creation schemas, CLI/TUI administration, concrete adapter
//! definitions, and the revision lifecycle belong to
//! `sealed-value-owner-management`. This module defines only the runtime
//! capability interface those instances plug into.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use anyhow::{Result, bail};
use async_trait::async_trait;

use super::compartment::SealedLiteralHandle;

/// Most parameters one action may declare.
pub const MAX_SEALED_ACTION_PARAMS: usize = 8;
/// Most predeclared constants one parameter may offer as choices.
pub const MAX_SEALED_PARAM_CHOICES: usize = 32;
/// Longest single predeclared constant, in bytes. A constant is authored by
/// the Owner, never by a caller, so this bounds Owner prose rather than
/// caller-supplied content.
pub const MAX_SEALED_CHOICE_BYTES: usize = 256;
/// Widest integer band a *parameter* may declare. Narrow enough that a
/// parameter cannot carry a packed address, port pair, or handle.
pub const MAX_SEALED_PARAM_INTEGER_SPAN: i64 = 4_096;
/// Most fields one action's fixed completion may declare.
///
/// The covert-channel budget is now exactly **zero bits per call**: the
/// completion is a constant, so its size bounds only how much Owner-authored
/// prose the caller sees, not how much it can learn.
pub const MAX_SEALED_COMPLETION_FIELDS: usize = 4;
/// Longest single completion constant, in bytes.
pub const MAX_SEALED_COMPLETION_BYTES: usize = 256;

/// Bounds on an action's declared fixed response time, in milliseconds.
///
/// The lower bound keeps the deadline meaningful; the upper bound keeps a
/// misdeclared action from pinning a caller indefinitely.
pub const MIN_SEALED_RESPONSE_MS: u64 = 1;
/// Upper bound on an action's declared fixed response time, in milliseconds.
pub const MAX_SEALED_RESPONSE_MS: u64 = 30_000;

/// The opaque identifier of an immutable action instance.
///
/// Authorization validates this as an opaque token only. It never parses a
/// destination out of it and never compiles or creates an action from it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SealedActionId(String);

impl SealedActionId {
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.len() > 64 {
            bail!("sealed action id must be 1..64 bytes");
        }
        if !trimmed.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
        }) {
            bail!("sealed action id must be lowercase alphanumeric with '-', '_', or '.'");
        }
        Ok(Self(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SealedActionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedActionId({:?})", self.0)
    }
}

impl fmt::Display for SealedActionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The revision of an immutable action instance. Any change to what an action
/// does mints a new revision, which invalidates every grant pinned to the old
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SealedActionRevision(u32);

impl SealedActionRevision {
    pub fn new(revision: u32) -> Result<Self> {
        if revision == 0 {
            bail!("sealed action revision starts at 1");
        }
        Ok(Self(revision))
    }

    pub fn get(self) -> u32 {
        self.0
    }
}

/// A bounded typed parameter declaration.
///
/// Every variant is *closed*. There is deliberately no free-form text form:
/// that is what makes "a caller may never supply an endpoint, a command, an
/// environment key, a header, a request template, or an output projection" a
/// property of the type system rather than of a field-name filter. A denylist
/// of destination-shaped names would have missed `server`, `callback`,
/// `webhook`, `origin`, and `base_url` — the failure mode is spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedParamSpec {
    /// A choice among constants the Owner predeclared. The caller selects an
    /// alternative; it can never author one, so no attacker-chosen string
    /// reaches an adapter through this parameter.
    Choice { allowed: Vec<String> },
    /// An integer confined to an inclusive, span-bounded band.
    BoundedInteger { min: i64, max: i64 },
    /// A boolean flag.
    Flag,
}

/// A caller-supplied parameter value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedParamValue {
    Text(String),
    Integer(i64),
    Flag(bool),
}

/// A validated parameter bundle. Constructing one proves it matched the
/// action's declared bounded types.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SealedParams(BTreeMap<String, SealedParamValue>);

impl SealedParams {
    pub fn from_map(values: BTreeMap<String, SealedParamValue>) -> Self {
        Self(values)
    }

    pub fn get(&self, name: &str) -> Option<&SealedParamValue> {
        self.0.get(name)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }
}

/// A value in an action's fixed completion.
///
/// A newtype over an Owner-authored constant. There is no constructor a host
/// action can reach at completion time and no variant that could hold a
/// computed value, so nothing derived from a literal has a representation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SealedSafeValue(String);

impl SealedSafeValue {
    pub(super) fn constant(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SealedSafeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The fixed, Owner-declared completion a caller sees.
///
/// Every field maps to exactly one constant. There is no choice set, no
/// integer, no flag, and no free text — a completion is a value, not a
/// selection — so the caller-visible response is a pure function of the
/// compiled descriptor and carries zero bits about the literal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SealedCompletion {
    fields: BTreeMap<String, String>,
}

impl SealedCompletion {
    /// Declare the constant this action always answers with.
    pub fn fixed(fields: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>) -> Self {
        Self {
            fields: fields
                .into_iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
        }
    }

    pub fn field_names(&self) -> impl Iterator<Item = &str> {
        self.fields.keys().map(String::as_str)
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Render the caller-visible response.
    ///
    /// Called by the runtime and only by the runtime, from the descriptor
    /// alone. No literal, no action outcome, and no parameter is in scope.
    pub(super) fn render(&self) -> SealedActionResult {
        SealedActionResult::new(
            self.fields
                .iter()
                .map(|(name, value)| (name.clone(), SealedSafeValue::constant(value)))
                .collect(),
        )
    }
}

/// The caller-visible response. Built by the runtime from the descriptor's
/// fixed completion; a host action can neither construct nor influence one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SealedActionResult {
    fields: BTreeMap<String, SealedSafeValue>,
}

impl SealedActionResult {
    pub(super) fn new(fields: BTreeMap<String, SealedSafeValue>) -> Self {
        Self { fields }
    }

    pub fn get(&self, name: &str) -> Option<&SealedSafeValue> {
        self.fields.get(name)
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn entries(&self) -> impl Iterator<Item = (&str, &SealedSafeValue)> {
        self.fields.iter().map(|(k, v)| (k.as_str(), v))
    }
}

/// The immutable declaration of one action instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedActionDescriptor {
    pub action_id: SealedActionId,
    pub revision: SealedActionRevision,
    /// Safe, model-visible prose. Never a destination.
    pub summary: String,
    pub parameters: BTreeMap<String, SealedParamSpec>,
    /// The fixed response every caller receives, win or lose.
    pub completion: SealedCompletion,
    /// How long a call to this action takes, always.
    ///
    /// Owner-declared at compile time, like the completion. The runtime runs
    /// the action under this as a hard deadline and returns at exactly this
    /// point whether the action finished early, finished late, or failed — so
    /// the caller-visible duration is a constant of the descriptor rather than
    /// a function of what the action did with the literal.
    ///
    /// A *floor* would not do: it only hides variation below itself, leaving
    /// an action free to signal a bit by taking 30ms versus 1s.
    pub response_after_ms: u64,
}

impl SealedActionDescriptor {
    /// Enforce every structural bound. An action that fails this cannot be
    /// registered, so no live action can accept a caller-supplied destination
    /// or return an unbounded channel.
    pub fn validate(&self) -> Result<()> {
        if self.summary.chars().count() > 512 {
            bail!("sealed action summary must be at most 512 characters");
        }
        if self.summary.chars().any(char::is_control) {
            bail!("sealed action summary must not contain control characters");
        }
        if self.parameters.len() > MAX_SEALED_ACTION_PARAMS {
            bail!("sealed action declares more than {MAX_SEALED_ACTION_PARAMS} parameters");
        }
        if !(MIN_SEALED_RESPONSE_MS..=MAX_SEALED_RESPONSE_MS).contains(&self.response_after_ms) {
            bail!(
                "sealed action fixed response time must be \
                 {MIN_SEALED_RESPONSE_MS}..={MAX_SEALED_RESPONSE_MS}ms"
            );
        }
        if self.completion.len() > MAX_SEALED_COMPLETION_FIELDS {
            bail!(
                "sealed action declares more than {MAX_SEALED_COMPLETION_FIELDS} completion fields"
            );
        }
        for (name, spec) in &self.parameters {
            check_field_name(name)?;
            match spec {
                SealedParamSpec::Choice { allowed } => {
                    check_choice_set(name, allowed, MAX_SEALED_PARAM_CHOICES)?;
                }
                SealedParamSpec::BoundedInteger { min, max } => {
                    if min > max {
                        bail!("sealed action parameter `{name}` has an empty integer band");
                    }
                    let span = max.checked_sub(*min).unwrap_or(i64::MAX);
                    if span > MAX_SEALED_PARAM_INTEGER_SPAN {
                        bail!(
                            "sealed action parameter `{name}` integer band exceeds \
                             {MAX_SEALED_PARAM_INTEGER_SPAN}; a wider band could carry a \
                             packed destination"
                        );
                    }
                }
                SealedParamSpec::Flag => {}
            }
        }
        for name in self.completion.field_names() {
            check_field_name(name)?;
            let value = self
                .completion
                .get(name)
                .expect("completion field just enumerated");
            if value.len() > MAX_SEALED_COMPLETION_BYTES {
                bail!(
                    "sealed action completion `{name}` exceeds {MAX_SEALED_COMPLETION_BYTES} bytes"
                );
            }
            if value.chars().any(char::is_control) {
                bail!("sealed action completion `{name}` must not contain control characters");
            }
        }
        Ok(())
    }

    /// Validate caller-supplied parameters against this declaration.
    ///
    /// Runs *before* any authorization lookup and before any literal read, so
    /// a malformed request costs zero secret reads.
    pub fn bind_parameters(
        &self,
        supplied: &BTreeMap<String, SealedParamValue>,
    ) -> Result<SealedParams> {
        if supplied.len() > self.parameters.len() {
            bail!("sealed action received undeclared parameters");
        }
        for name in supplied.keys() {
            if !self.parameters.contains_key(name) {
                bail!("sealed action received undeclared parameter `{name}`");
            }
        }
        let mut bound = BTreeMap::new();
        for (name, spec) in &self.parameters {
            let Some(value) = supplied.get(name) else {
                bail!("sealed action requires parameter `{name}`");
            };
            match (spec, value) {
                (SealedParamSpec::Choice { allowed }, SealedParamValue::Text(text)) => {
                    // Exact membership. A caller selects a predeclared
                    // constant; it never authors the string that reaches the
                    // adapter, so no destination can be smuggled through.
                    if !allowed.iter().any(|choice| choice == text) {
                        bail!(
                            "sealed action parameter `{name}` is not one of its declared choices"
                        );
                    }
                }
                (
                    SealedParamSpec::BoundedInteger { min, max },
                    SealedParamValue::Integer(value),
                ) => {
                    if value < min || value > max {
                        bail!("sealed action parameter `{name}` is outside its declared band");
                    }
                }
                (SealedParamSpec::Flag, SealedParamValue::Flag(_)) => {}
                _ => bail!("sealed action parameter `{name}` has the wrong type"),
            }
            bound.insert(name.clone(), value.clone());
        }
        Ok(SealedParams::from_map(bound))
    }

    /// The caller-visible response for this action.
    ///
    /// A pure function of the compiled descriptor. It takes no literal, no
    /// parameters, and no action outcome, so there is no input from which a
    /// secret-dependent answer could be produced.
    pub(super) fn completion_response(&self) -> SealedActionResult {
        self.completion.render()
    }

    /// The constant wall time a call to this action occupies.
    pub(super) fn response_after(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.response_after_ms)
    }
}

fn check_field_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 48 {
        bail!("sealed action field name must be 1..48 bytes");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        bail!("sealed action field name must be lowercase alphanumeric with '_'");
    }
    // Deliberately no denylist of "destination-shaped" names. A field named
    // `url` is exactly as harmless as one named `mode`, because neither can
    // hold caller-authored text; and a denylist would have missed `server`,
    // `callback`, `address`, and `base_url` anyway.
    Ok(())
}

/// Validate one closed choice set.
///
/// A closed field must offer at least one constant (an empty set makes the
/// action uncallable) and at most `max_choices` (the covert-channel budget).
/// Duplicates are rejected so the declared budget is the real one.
fn check_choice_set(name: &str, allowed: &[String], max_choices: usize) -> Result<()> {
    if allowed.is_empty() {
        bail!("sealed action field `{name}` declares an empty choice set");
    }
    if allowed.len() > max_choices {
        bail!("sealed action field `{name}` declares more than {max_choices} choices");
    }
    let mut seen = std::collections::BTreeSet::new();
    for choice in allowed {
        if choice.len() > MAX_SEALED_CHOICE_BYTES {
            bail!(
                "sealed action field `{name}` declares a choice beyond {MAX_SEALED_CHOICE_BYTES} bytes"
            );
        }
        if choice.chars().any(char::is_control) {
            bail!("sealed action field `{name}` declares a choice with control characters");
        }
        if !seen.insert(choice.as_str()) {
            bail!("sealed action field `{name}` declares a duplicate choice");
        }
    }
    Ok(())
}

/// The opaque host-action interface.
///
/// This is the only thing a live grant can reach. The literal arrives as a
/// borrowed [`SealedLiteralHandle`] that cannot outlive the call.
///
/// **`invoke` returns nothing caller-visible, by signature.** It cannot select
/// a response, and its `Err` is discarded rather than surfaced, so neither its
/// result nor its failure mode can encode a bit of the literal. The caller
/// always receives [`SealedActionDescriptor::completion`], a constant fixed
/// when the Owner compiled the instance.
///
/// This is deliberately restrictive. An action that needs to report an outcome
/// must do so out of band to the Owner — never through its untrusted caller.
///
/// Concrete adapter execution is owned by `sealed-value-owner-management`.
#[async_trait]
pub trait SealedHostAction: Send + Sync {
    /// The immutable declaration this instance was compiled from.
    fn descriptor(&self) -> &SealedActionDescriptor;

    /// Perform the Owner-defined effect. The return value is host-side only:
    /// the runtime discards it, including the error, without inspecting it.
    async fn invoke(&self, literal: SealedLiteralHandle<'_>, params: &SealedParams) -> Result<()>;
}

/// The fixed local Owner principal string.
///
/// This is the sealed-owner identity *everywhere* in production — the capability
/// stamp, the stored `owner_principal`, and the authority-comparison value are
/// all this constant. It is deliberately **not** derived from
/// `local_principal_name()` / `$USER`; the sealed channel has exactly one local
/// Owner identity.
pub const OWNER_PRINCIPAL: &str = "owner";

/// Proof that a caller is the local Owner, carrying that Owner's verified
/// principal identity.
///
/// The only ways to obtain one are a genuine Owner principal and (in tests) an
/// explicit constructor. Agents and remote clients cannot forge it, which is
/// what keeps action compilation and value lifecycle out of their reach.
///
/// The carried principal is what makes wrong-owner rejection expressible: a
/// capability minted under one authority records that authority's principal,
/// and an apply under a different authority is rejected before any literal is
/// touched. Production identity is always [`OWNER_PRINCIPAL`]; a synthetic
/// mismatched principal can be minted only through the `#[cfg(test)]`
/// constructor.
#[derive(Debug, Clone, Copy)]
pub struct OwnerAuthority {
    principal: &'static str,
}

impl OwnerAuthority {
    /// `Some` only for the local Owner principal. The carried identity is
    /// always the fixed [`OWNER_PRINCIPAL`] string, never `$USER`.
    pub fn from_principal(principal: &crate::daemon::principal::ClientPrincipal) -> Option<Self> {
        principal.is_owner().then_some(Self {
            principal: OWNER_PRINCIPAL,
        })
    }

    /// Authority for a daemon request the command table already declared
    /// `owner_only`.
    ///
    /// The transport check happens before dispatch, so by the time a handler
    /// runs the caller is known to be the Owner; this names that fact instead
    /// of re-deriving it. Restricted to the daemon so no agent-reachable code
    /// can reach for it. The carried principal is the fixed [`OWNER_PRINCIPAL`].
    pub(crate) fn for_owner_request() -> Self {
        Self {
            principal: OWNER_PRINCIPAL,
        }
    }

    /// The verified Owner principal this authority carries. Safe to compare and
    /// to store; it is never a secret.
    pub fn principal(&self) -> &'static str {
        self.principal
    }

    /// Test-only constructor. Never compiled into a shipping binary. Pass
    /// `"owner"` for happy-path coverage, or a synthetic string (e.g. `"alice"`)
    /// to exercise wrong-owner rejection in unit tests.
    #[cfg(test)]
    pub fn for_test(principal: &'static str) -> Self {
        Self { principal }
    }
}

/// Builder for the closed registry. Exists only behind an [`OwnerAuthority`].
pub struct SealedActionRegistryBuilder {
    actions: BTreeMap<String, Arc<dyn SealedHostAction>>,
}

impl SealedActionRegistryBuilder {
    /// Compile one immutable action instance into the registry.
    pub fn with_action(mut self, action: Arc<dyn SealedHostAction>) -> Result<Self> {
        let descriptor = action.descriptor();
        descriptor.validate()?;
        let key = descriptor.action_id.as_str().to_string();
        if self.actions.contains_key(&key) {
            bail!("sealed action `{key}` is already compiled; instances are immutable");
        }
        self.actions.insert(key, action);
        Ok(self)
    }

    /// Freeze the registry. After this there is no registration path at all.
    pub fn build(self) -> Arc<SealedActionRegistry> {
        Arc::new(SealedActionRegistry {
            actions: self.actions,
        })
    }
}

impl fmt::Debug for SealedActionRegistryBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedActionRegistryBuilder")
            .field("compiled", &self.actions.len())
            .finish()
    }
}

/// The closed runtime registry of immutable action instances.
///
/// Frozen at construction. There is deliberately no `register`, no `insert`,
/// no `names`, and no `iter`: a caller can only ask whether one exact opaque
/// action id resolves, which is all authorization needs.
pub struct SealedActionRegistry {
    actions: BTreeMap<String, Arc<dyn SealedHostAction>>,
}

impl SealedActionRegistry {
    /// Begin building a registry. Requires Owner authority.
    pub fn builder(_owner: OwnerAuthority) -> SealedActionRegistryBuilder {
        SealedActionRegistryBuilder {
            actions: BTreeMap::new(),
        }
    }

    /// A registry with no actions. Every use against it denies.
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            actions: BTreeMap::new(),
        })
    }

    /// Exact lookup by opaque action id. This never compiles or creates an
    /// action; it only resolves one that the Owner already compiled.
    pub fn resolve(&self, action_id: &SealedActionId) -> Option<&Arc<dyn SealedHostAction>> {
        self.actions.get(action_id.as_str())
    }
}

impl fmt::Debug for SealedActionRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedActionRegistry")
            .field("compiled", &self.actions.len())
            .finish()
    }
}
// The old process-global install-once `OnceLock` registry was retired
// (`sealed-owner-persistence-and-executor` inc3b). The registry is no longer a
// process-global installed once at boot; it is rebuilt on read from the current
// persisted snapshots by `crate::sealed::action_admin::build_live_registry`,
// which keeps it always live and per-database isolated. Use
// [`SealedActionRegistry::empty`] where a deny-all registry is needed.
