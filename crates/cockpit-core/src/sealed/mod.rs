//! Owner-managed sealed values and closed reference actions.
//!
//! # The invariant
//!
//! A raw sensitive value must never reach an untrusted model. The invariant is
//! one-directional: [`ModelTrust`](crate::config::providers::ModelTrust) is
//! the *sole* custody gate for releasing a raw literal, and harness-steering
//! posture is an independent axis that never widens custody. See [`custody`].
//!
//! # The shape
//!
//! * [`identity`] — canonical typed identity. Safe metadata only.
//! * [`custody`] — the raw-literal custody predicate.
//! * [`compartment`] — the sealed-value-only credential compartment holding
//!   Project and Global literals under random opaque exact keys. Session
//!   literals stay in SQLite.
//! * [`action`] — immutable action instances and the closed runtime registry.
//! * [`grant`] — the exact grant tuple and authorization-before-lookup.
//! * [`runtime`] — `use_sealed_value`, the sole use mechanism.
//! * [`store`] — Owner-only lifecycle, sagas, and safe inventory.
//! * [`marker`] — the typed predicate downstream renderers and exports read.
//!
//! # What an untrusted agent can do
//!
//! Exactly one thing: name a sealed value it was granted, name an action it
//! was granted, supply bounded typed parameters, and receive that action's
//! declared safe projection. It cannot enumerate values, supply a destination,
//! observe a denial reason, or obtain a literal — under any steering posture.
//!
//! # What is owned elsewhere
//!
//! `/sealed` transport and command grammar, action-instance administration,
//! concrete adapter execution, and recovery UX belong to
//! `sealed-value-owner-management`. Provider-wire marker rendering belongs to
//! `sealed-value-untrusted-inference-marker`. Portable export behavior belongs
//! to `portable-redacted-debug-export`. Trusted-child acquisition belongs to
//! its own coordinator prompt.

pub mod action;
pub mod action_admin;
pub mod compartment;
pub mod custody;
pub mod egress;
pub mod grant;
pub mod identity;
pub mod marker;
pub mod owner;
pub mod owner_commands;
pub mod runtime;
pub mod store;

#[cfg(test)]
mod tests;

pub use action::{
    OWNER_PRINCIPAL, OwnerAuthority, SealedActionDescriptor, SealedActionId, SealedActionRegistry,
    SealedActionRegistryBuilder, SealedActionResult, SealedActionRevision, SealedCompletion,
    SealedHostAction, SealedParamSpec, SealedParamValue, SealedParams, SealedSafeValue,
};
pub use action_admin::{
    CreateSealedAction, HTTPS_MAX_ORIGIN_BYTES, HTTPS_MAX_ORIGINS, HTTPS_MAX_RESPONSE_BYTES,
    HTTPS_TIMEOUT_MS, HttpsCredentialPlacement, HttpsOrigin, HttpsOriginAllowlist,
    ReviseSealedAction, SealedActionDirectory, SealedActionInstanceSummary, SealedActionKind,
    SealedActionSnapshot, SealedParamSpecJson, SealedProjectionId,
};
pub use compartment::{
    SealedCompartment, SealedCompartmentKey, SealedLiteral, SealedLiteralHandle,
};
pub use custody::{
    SealedCustodyRequest, SealedLiteralCustody, sealed_literal_custody,
    sealed_literal_custody_for_trust,
};
pub use egress::active_sealed_value_ids;
pub use grant::{
    SEALED_USE_DENIED_MESSAGE, SealedUseContext, SealedUseDenied, UseSealedValueRequest,
};
pub use identity::{
    SealedDescription, SealedName, SealedProjectKey, SealedProjectTrust, SealedRecordId,
    SealedRedactionIdentity, SealedScopeKind, SealedScopeRef, parse_sealed_redaction_origin,
};
pub use marker::{
    SealedCapabilityState, SealedMarkerIdentity, SealedMarkerPredicate,
    historical_redaction_inventory,
};
pub use owner::{
    BeginResult, BeginSensitiveInput, BeginSensitiveOwnerOperation, CAPABILITY_TTL_MS,
    MAX_SENSITIVE_FRAME_BYTES, OneUseCapability, SensitiveFrameKind, SensitiveFrameOutcome,
    SensitiveOwnerDisposition, SensitiveOwnerFrame, SensitiveOwnerOperation, VersionBinding,
};
pub use runtime::{SealedRedactionSink, SealedRuntime, SessionRedactionSink};
pub use store::{
    CreateSealedValue, IssueSealedGrant, SealedGrantHandle, SealedRecoveryReport,
    SealedValueDirectory, SealedValueSummary,
};

/// The exact JSON argument schema of `use_sealed_value`.
///
/// One definition, shared by the built-in tool and the Monty builtin, so the
/// two surfaces cannot drift. Three properties, `additionalProperties: false`:
/// there is no field in which a caller could supply an endpoint, a command, an
/// environment key, a header, a request template, or an output projection.
pub fn use_sealed_value_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "sealed_value_id": {
                "type": "string",
                "description": "Opaque id of a sealed value you were granted. Never its content."
            },
            "action_id": {
                "type": "string",
                "description": "Opaque id of an action instance you were granted for that value."
            },
            "parameters": {
                "type": "array",
                "description": "Bounded typed parameters the action instance declared. Give exactly one of text/number/flag per entry.",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Parameter name the action declared."
                        },
                        "text": {
                            "type": "string",
                            "description": "Value for a choice parameter; must be one of that parameter's declared choices."
                        },
                        "number": {
                            "type": "integer",
                            "description": "Value for a bounded-integer parameter."
                        },
                        "flag": {
                            "type": "boolean",
                            "description": "Value for a flag parameter."
                        }
                    },
                    "required": ["name"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["sealed_value_id", "action_id", "parameters"],
        "additionalProperties": false
    })
}

/// The model-facing name of the sole sealed use mechanism.
pub const USE_SEALED_VALUE_TOOL: &str = "use_sealed_value";

/// The three argument keys `use_sealed_value` accepts, and the only three.
pub const USE_SEALED_VALUE_ARG_KEYS: [&str; 3] = ["sealed_value_id", "action_id", "parameters"];

/// Parse a `use_sealed_value` argument object into the typed request.
///
/// Rejects any key outside [`USE_SEALED_VALUE_ARG_KEYS`]. Parameters arrive as
/// a **bounded array of closed entries**, not a free-form object: the wire
/// shape mirrors the closed parameter type model, so there is no open map in
/// which a request template or output projection could be smuggled, and the
/// schema is strict-wire compatible.
pub fn parse_use_sealed_value_args(
    args: &serde_json::Value,
) -> anyhow::Result<UseSealedValueRequest> {
    use anyhow::{Context, bail};

    let object = args
        .as_object()
        .context("`use_sealed_value` requires an object argument")?;
    for key in object.keys() {
        if !USE_SEALED_VALUE_ARG_KEYS.contains(&key.as_str()) {
            bail!("`use_sealed_value` does not accept `{key}`");
        }
    }
    let sealed_value_id = object
        .get("sealed_value_id")
        .and_then(serde_json::Value::as_str)
        .context("`use_sealed_value` requires `sealed_value_id`")?;
    let action_id = object
        .get("action_id")
        .and_then(serde_json::Value::as_str)
        .context("`use_sealed_value` requires `action_id`")?;
    let entries = object
        .get("parameters")
        .and_then(serde_json::Value::as_array)
        .context("`use_sealed_value` requires `parameters` as an array")?;

    let mut bound = std::collections::BTreeMap::new();
    for entry in entries {
        let entry = entry
            .as_object()
            .context("each sealed action parameter must be an object")?;
        for key in entry.keys() {
            if !matches!(key.as_str(), "name" | "text" | "number" | "flag") {
                bail!("sealed action parameter entries do not accept `{key}`");
            }
        }
        let name = entry
            .get("name")
            .and_then(serde_json::Value::as_str)
            .context("each sealed action parameter needs a `name`")?;

        let text = entry.get("text").map(|value| {
            value
                .as_str()
                .map(|text| SealedParamValue::Text(text.to_string()))
                .context("sealed action parameter `text` must be a string")
        });
        let number = entry.get("number").map(|value| {
            value
                .as_i64()
                .map(SealedParamValue::Integer)
                .context("sealed action parameter `number` must be a whole number")
        });
        let flag = entry.get("flag").map(|value| {
            value
                .as_bool()
                .map(SealedParamValue::Flag)
                .context("sealed action parameter `flag` must be a boolean")
        });

        let mut supplied = [text, number, flag].into_iter().flatten();
        let value = supplied
            .next()
            .with_context(|| format!("sealed action parameter `{name}` has no value"))??;
        if supplied.next().is_some() {
            bail!("sealed action parameter `{name}` must give exactly one of text/number/flag");
        }
        if bound.insert(name.to_string(), value).is_some() {
            bail!("sealed action parameter `{name}` was given twice");
        }
    }

    Ok(UseSealedValueRequest {
        sealed_value_id: SealedRecordId::parse(sealed_value_id)?,
        action_id: SealedActionId::parse(action_id)?,
        parameters: bound,
    })
}
