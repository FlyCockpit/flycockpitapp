//! Daemon-owned, credential-free session-setup inventory DTOs.
//!
//! This is a presentation snapshot, not a mutation capability. Provider
//! profile handles, credentials, workspace paths, and client-derived
//! compatibility guesses never cross this boundary.

use serde::{Deserialize, Serialize};

use crate::{
    AgentInstallationChoiceV1, AgentInstallationRecordV1,
    AgentInstallationUnmatchedRecommendationV1,
};

pub const SESSION_SETUP_DTO_VERSION: u32 = 1;

/// One daemon-derived installed-agent candidate. Scope remains part of the
/// record so same-name global and workspace installations remain distinct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSetupAgentCandidateV1 {
    pub installation: AgentInstallationRecordV1,
    pub selected: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slots: Vec<SessionSetupModelSlotV1>,
    /// Fixed daemon-owned reason. It never carries parser, filesystem, or
    /// provider-profile details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locked_reason: Option<SessionSetupLockedReasonV1>,
}

/// One vNext model slot. Choices are ordered by author recommendation, exact
/// alias, then stable daemon offering identity. Unmatched recommendations are
/// retained visibly rather than fuzzy-matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSetupModelSlotV1 {
    pub slot_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<AgentInstallationChoiceV1>,
    /// Exact opaque route identity for each setup choice. Display
    /// provider/model labels are intentionally not route identities: two
    /// credential profiles may share both labels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choice_routes: Vec<SessionSetupModelChoiceRouteV1>,
    /// The subset of `choices` backed by the installation's current live
    /// binding set. Compatible-but-unbound choices remain visible in setup,
    /// but must not receive slot-first picker ordering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_choice_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmatched_recommendations: Vec<AgentInstallationUnmatchedRecommendationV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<SessionSetupUnavailableReasonV1>,
    /// Marks the slot's default model among `choices`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_choice_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSetupModelChoiceRouteV1 {
    pub choice_id: String,
    /// Matches `AgentModelRefV1.choice_id` for the same daemon-held route. It
    /// is a one-way digest, never a provider profile handle.
    pub route_choice_id: String,
    /// Exact position in the daemon-held provider configuration captured by
    /// `SessionSetupSnapshotV1::config_generation`. This is nonsecret mapping
    /// identity: clients use it only against the same held config snapshot,
    /// never as provider routing authority.
    pub config_provider_index: u32,
}

/// Closed reasons rendered by clients. Missing capability evidence never
/// becomes a client-side fallback or an authority grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionSetupUnavailableReasonV1 {
    NoHardCompatibleLocalModel,
    RebindRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionSetupLockedReasonV1 {
    DefinitionUnavailable,
    RebindRequired,
}

/// The attached session's daemon-owned setup projection. `revision` is an
/// opaque snapshot label for the later override-mutation increment; this
/// read-only endpoint does not accept it from clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSetupSnapshotV1 {
    pub dto_version: u32,
    pub session_id: String,
    /// Daemon-owned configuration generation captured with the provider
    /// capability projection. It makes the authority epoch explicit without
    /// exposing provider profiles, credentials, or filesystem paths.
    pub config_generation: u64,
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_installation_id: Option<String>,
    pub candidates: Vec<SessionSetupAgentCandidateV1>,
}
