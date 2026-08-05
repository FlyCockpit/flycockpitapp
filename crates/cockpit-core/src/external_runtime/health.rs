//! Immutable generation-tagged health snapshots.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::schema::{
    DependencyImportance, ExternalRuntimeId, HostPlatform, RemedyKind, RequirementGroup,
};
use crate::capabilities::ExecutionTarget;

/// Closed set of health states. Unknown never means healthy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum HealthState {
    Pending,
    Available {
        resolved_path: Option<PathBuf>,
        version_evidence: Option<String>,
    },
    Missing,
    Incompatible {
        detail: String,
    },
    TimedOut,
    Failed {
        cause: HealthCause,
    },
    Unknown {
        cause: HealthCause,
    },
    NotApplicable,
}

impl HealthState {
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    pub fn is_available(&self) -> bool {
        self.is_healthy()
    }

    /// Fail-closed: only Available is usable for launch gates.
    pub fn is_usable(&self) -> bool {
        self.is_healthy()
    }
}

/// Typed non-secret failure cause (never raw environment dumps or OS paths).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum HealthCause {
    SpawnFailed { failure: SpawnFailureKind },
    NonZeroExit { code: Option<i32> },
    OutputParseFailed,
    Cancellation,
    Internal { message: String },
    ResolutionFailed,
    NotSpawnable,
}

/// Coarse spawn failure class without platform path/text leakage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpawnFailureKind {
    NotFound,
    PermissionDenied,
    Other,
}

/// One runtime's health row inside a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthEntry {
    pub id: ExternalRuntimeId,
    pub state: HealthState,
    pub importance: DependencyImportance,
    pub target: ExecutionTarget,
    pub remedy: Option<RemedyKind>,
    pub platform: HostPlatform,
}

/// Immutable, generation-tagged health snapshot. Never persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalRuntimeSnapshot {
    pub generation: u64,
    pub platform: HostPlatform,
    pub entries: BTreeMap<String, HealthEntry>,
    pub groups: BTreeMap<String, GroupHealth>,
}

impl ExternalRuntimeSnapshot {
    pub fn empty(generation: u64, platform: HostPlatform) -> Self {
        Self {
            generation,
            platform,
            entries: BTreeMap::new(),
            groups: BTreeMap::new(),
        }
    }

    pub fn get(&self, id: &str) -> Option<&HealthEntry> {
        self.entries.get(id)
    }

    pub fn evaluate_group(&self, group: &RequirementGroup) -> GroupHealth {
        evaluate_requirement_group(group, self)
    }
}

/// Aggregated health of an all_of / any_of group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupHealth {
    Pending,
    Available,
    Missing,
    Incompatible,
    TimedOut,
    Failed,
    Unknown,
    NotApplicable,
}

impl GroupHealth {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }
}

fn state_to_group(state: &HealthState) -> GroupHealth {
    match state {
        HealthState::Pending => GroupHealth::Pending,
        HealthState::Available { .. } => GroupHealth::Available,
        HealthState::Missing => GroupHealth::Missing,
        HealthState::Incompatible { .. } => GroupHealth::Incompatible,
        HealthState::TimedOut => GroupHealth::TimedOut,
        HealthState::Failed { .. } => GroupHealth::Failed,
        HealthState::Unknown { .. } => GroupHealth::Unknown,
        HealthState::NotApplicable => GroupHealth::NotApplicable,
    }
}

/// Rank for all_of aggregation: higher is worse / more blocking.
fn group_rank(h: &GroupHealth) -> u8 {
    match h {
        GroupHealth::Available => 0,
        GroupHealth::NotApplicable => 1,
        GroupHealth::Pending => 2,
        GroupHealth::Unknown => 3,
        GroupHealth::TimedOut => 4,
        GroupHealth::Failed => 5,
        GroupHealth::Incompatible => 6,
        GroupHealth::Missing => 7,
    }
}

fn merge_all_of(a: GroupHealth, b: GroupHealth) -> GroupHealth {
    if group_rank(&a) >= group_rank(&b) {
        a
    } else {
        b
    }
}

fn merge_any_of(states: &[GroupHealth]) -> GroupHealth {
    if states.is_empty() {
        return GroupHealth::NotApplicable;
    }
    if states.iter().any(|s| matches!(s, GroupHealth::Available)) {
        return GroupHealth::Available;
    }
    // Prefer most informative failure; NotApplicable only if all N/A.
    if states
        .iter()
        .all(|s| matches!(s, GroupHealth::NotApplicable))
    {
        return GroupHealth::NotApplicable;
    }
    states
        .iter()
        .filter(|s| !matches!(s, GroupHealth::NotApplicable))
        .cloned()
        .max_by_key(group_rank)
        .unwrap_or(GroupHealth::Unknown)
}

pub fn evaluate_requirement_group(
    group: &RequirementGroup,
    snapshot: &ExternalRuntimeSnapshot,
) -> GroupHealth {
    match group {
        RequirementGroup::Leaf(id) => snapshot
            .get(id.as_str())
            .map(|e| state_to_group(&e.state))
            .unwrap_or(GroupHealth::Unknown),
        RequirementGroup::AllOf(nodes) => {
            if nodes.is_empty() {
                return GroupHealth::NotApplicable;
            }
            nodes
                .iter()
                .map(|n| evaluate_requirement_group(n, snapshot))
                .reduce(merge_all_of)
                .unwrap_or(GroupHealth::Unknown)
        }
        RequirementGroup::AnyOf(nodes) => {
            let child: Vec<_> = nodes
                .iter()
                .map(|n| evaluate_requirement_group(n, snapshot))
                .collect();
            merge_any_of(&child)
        }
    }
}

/// In-memory store with atomic generation publish. Late generations discarded.
#[derive(Debug, Default)]
pub struct HealthSnapshotStore {
    inner: Mutex<StoreInner>,
}

#[derive(Debug, Default)]
struct StoreInner {
    /// Highest generation number reserved via [`HealthSnapshotStore::begin_refresh`].
    next_generation: u64,
    current: Option<Arc<ExternalRuntimeSnapshot>>,
}

impl HealthSnapshotStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve a generation number for an in-flight refresh.
    pub fn begin_refresh(&self) -> u64 {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.next_generation = inner.next_generation.saturating_add(1);
        inner.next_generation
    }

    /// Publish a completed snapshot only when it is the latest reserved generation
    /// and strictly newer than any already-published snapshot.
    ///
    /// Returns true when the snapshot became current. Older in-flight refreshes
    /// that complete after a newer refresh was reserved are discarded even if
    /// nothing has been published yet.
    pub fn publish(&self, snapshot: ExternalRuntimeSnapshot) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        // Must be the latest reserved generation — supersedes older in-flight work.
        if snapshot.generation != inner.next_generation {
            return false;
        }
        if let Some(current) = &inner.current
            && snapshot.generation <= current.generation
        {
            return false;
        }
        inner.current = Some(Arc::new(snapshot));
        true
    }

    /// Readers observe only complete published generations.
    pub fn current(&self) -> Option<Arc<ExternalRuntimeSnapshot>> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.current.clone()
    }

    /// Atomically assign a new generation, merge `entry` into the published
    /// snapshot, and return `(published_snapshot, generation)`.
    ///
    /// Used by live launch gates so concurrent multi-id handoffs each publish
    /// a strictly newer generation without racing `begin_refresh` reservations
    /// (full Settings/doctor refreshes still use begin_refresh + publish).
    pub fn publish_live_entry(
        &self,
        entry: HealthEntry,
        platform: HostPlatform,
    ) -> (Arc<ExternalRuntimeSnapshot>, u64) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.next_generation = inner.next_generation.saturating_add(1);
        let generation = inner.next_generation;
        let mut snapshot = if let Some(current) = &inner.current {
            let mut snap = (**current).clone();
            snap.generation = generation;
            snap.platform = platform;
            snap
        } else {
            ExternalRuntimeSnapshot::empty(generation, platform)
        };
        snapshot
            .entries
            .insert(entry.id.as_str().to_string(), entry);
        let arc = Arc::new(snapshot);
        inner.current = Some(arc.clone());
        (arc, generation)
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.current = None;
    }
}
