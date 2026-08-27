//! ArtifactWrite verification: policy resolution, candidate generation, and
//! gate/revise application for `write`/`edit` (and granted plan variants).
//!
//! ToolClass is not yet a declared field on standard tool definitions. The
//! classifier in [`classify`] is therefore hardcoded: `write`/`edit` (and
//! plan variants when those tools are granted) map to
//! [`crate::agents::ToolClass::ArtifactWrite`]. Everything else is
//! unclassified and cannot match a verification rule. A future change should
//! make `ToolClass` a declared field on standard tool definitions.

pub(crate) mod budget;
pub(crate) mod classify;
pub(crate) mod estimate;
pub(crate) mod generate;
pub(crate) mod intercept;
pub(crate) mod recipe;

pub(crate) use classify::classify_tool;
pub(crate) use intercept::{InterceptInput, VerificationOutcome, intercept_ordinary_call};
