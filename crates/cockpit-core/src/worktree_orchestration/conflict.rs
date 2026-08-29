//! Isolated conflict specialist: left/right patches plus an integration lease.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::git::UncommittedPatch;
use crate::workspace_lease::WorkspaceLease;

/// Closed verdict a conflict specialist may return. The parent orchestrator
/// decides whether to apply it; the specialist never writes the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConflictSpecialistVerdict {
    Combined,
    ChooseLeft,
    ChooseRight,
    Unresolved,
}

impl ConflictSpecialistVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Combined => "combined",
            Self::ChooseLeft => "choose_left",
            Self::ChooseRight => "choose_right",
            Self::Unresolved => "unresolved",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "combined" => Ok(Self::Combined),
            "choose_left" => Ok(Self::ChooseLeft),
            "choose_right" => Ok(Self::ChooseRight),
            "unresolved" => Ok(Self::Unresolved),
            other => bail!("unknown conflict-specialist verdict `{other}`"),
        }
    }
}

/// Conflict-specialist child. Authority is the integration lease only:
/// sibling and primary trees outside that lease are not readable.
#[derive(Debug, Clone)]
pub struct ConflictSpecialist {
    lease: WorkspaceLease,
    isolated_base: PathBuf,
    request: Option<ConflictSpecialistRequest>,
    resolution: Option<ConflictResolution>,
}

/// Bounded data handed from the parent to the isolated specialist.  It names
/// one lease and one ordered pair only; a result for any other pair is
/// rejected by the parent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConflictSpecialistRequest {
    pub lease_id: uuid::Uuid,
    pub left: UncommittedPatch,
    pub right: UncommittedPatch,
}

/// The specialist returns data, not an instruction to concatenate two
/// incompatible diffs.  `Combined` is valid only with a complete replacement
/// patch authored by the specialist and selected by the parent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConflictResolution {
    pub verdict: ConflictSpecialistVerdict,
    pub combined_patch: Option<UncommittedPatch>,
}

impl ConflictSpecialist {
    pub(crate) fn bounded_by(lease: WorkspaceLease) -> Self {
        Self {
            isolated_base: lease.visibility_root.clone(),
            lease,
            request: None,
            resolution: None,
        }
    }

    pub(crate) fn with_handoff(
        lease: WorkspaceLease,
        request: ConflictSpecialistRequest,
        resolution: ConflictResolution,
    ) -> Result<Self> {
        if request.lease_id != lease.id {
            bail!("conflict-specialist result is not bound to its integration lease");
        }
        request.left.validate_paths()?;
        request.right.validate_paths()?;
        if let Some(patch) = &resolution.combined_patch {
            patch.validate_paths()?;
        }
        Ok(Self {
            isolated_base: lease.visibility_root.clone(),
            lease,
            request: Some(request),
            resolution: Some(resolution),
        })
    }

    #[cfg(test)]
    pub fn with_injected_verdict(mut self, verdict: ConflictSpecialistVerdict) -> Self {
        self.resolution = Some(ConflictResolution {
            verdict,
            combined_patch: None,
        });
        self
    }

    #[cfg(test)]
    pub fn with_resolved_patch(mut self, patch: UncommittedPatch) -> Result<Self> {
        patch.validate_paths()?;
        self.resolution = Some(ConflictResolution {
            verdict: ConflictSpecialistVerdict::Combined,
            combined_patch: Some(patch),
        });
        Ok(self)
    }

    pub fn lease(&self) -> &WorkspaceLease {
        &self.lease
    }

    /// Capture the specialist result from its isolated checkout. `Combined`
    /// never receives a caller-provided patch: the patch is derived directly
    /// from the bounded worktree that was issued for this handoff.
    pub fn capture_resolution(
        &self,
        request: &ConflictSpecialistRequest,
        verdict: ConflictSpecialistVerdict,
    ) -> Result<ConflictResolution> {
        if request.lease_id != self.lease.id {
            bail!("conflict-specialist request is not bound to this lease");
        }
        request.left.validate_paths()?;
        request.right.validate_paths()?;
        let combined_patch = match verdict {
            ConflictSpecialistVerdict::Combined => {
                let patch = crate::git::capture_uncommitted_patch(&self.isolated_base)?;
                patch.validate_paths()?;
                Some(patch)
            }
            ConflictSpecialistVerdict::ChooseLeft
            | ConflictSpecialistVerdict::ChooseRight
            | ConflictSpecialistVerdict::Unresolved => None,
        };
        Ok(ConflictResolution {
            verdict,
            combined_patch,
        })
    }

    /// Read a path only when it is inside the integration lease.
    pub fn read_path(&self, path: &Path) -> Result<Vec<u8>> {
        if !self.lease.allows_read() || !self.lease.covers_path(path) {
            bail!(
                "conflict specialist cannot access `{}` outside integration lease `{}`",
                path.display(),
                self.lease.visibility_root.display()
            );
        }
        Ok(std::fs::read(path)?)
    }

    /// Resolve left/right patches. Disjoint paths combine; overlapping paths
    /// stay unresolved unless the isolated specialist returned a resolution.
    pub fn resolve(
        &self,
        left: &UncommittedPatch,
        right: &UncommittedPatch,
    ) -> ConflictSpecialistVerdict {
        if let Some(resolution) = &self.resolution {
            return resolution.verdict;
        }
        if paths_disjoint(left, right) {
            ConflictSpecialistVerdict::Combined
        } else {
            ConflictSpecialistVerdict::Unresolved
        }
    }

    pub fn compose(
        &self,
        left: &UncommittedPatch,
        right: &UncommittedPatch,
        verdict: ConflictSpecialistVerdict,
    ) -> Result<UncommittedPatch> {
        let Some(request) = &self.request else {
            bail!("conflict specialist has no durable parent handoff");
        };
        if request.left != *left || request.right != *right {
            bail!("conflict-specialist result does not match this ordered artifact pair");
        }
        match verdict {
            ConflictSpecialistVerdict::ChooseLeft => Ok(left.clone()),
            ConflictSpecialistVerdict::ChooseRight => Ok(right.clone()),
            ConflictSpecialistVerdict::Combined => {
                let Some(resolution) = &self.resolution else {
                    bail!("combined conflict result omitted the resolved patch")
                };
                let Some(patch) = &resolution.combined_patch else {
                    bail!("combined conflict result omitted the resolved patch")
                };
                patch.validate_paths()?;
                let derived = crate::git::derive_patch_manifest_on_isolated_base(
                    &self.isolated_base,
                    &patch.diff,
                )?;
                if derived.diff.is_empty() {
                    bail!("combined conflict patch is a no-op on the isolated base");
                }
                if !same_manifest(patch, &derived) {
                    bail!(
                        "combined conflict patch declared paths differ from the exact isolated-base manifest"
                    );
                }
                if !constrained_to_inputs(&derived, left, right) {
                    bail!("combined conflict patch changes a path outside the input artifacts");
                }
                if !covers_inputs(&derived, left, right) {
                    bail!("combined conflict patch does not represent both input manifests")
                }
                Ok(UncommittedPatch {
                    diff: patch.diff.clone(),
                    touched_paths: derived.touched_paths,
                    untracked_paths: derived.untracked_paths,
                })
            }
            ConflictSpecialistVerdict::Unresolved => {
                bail!(
                    "conflict specialist returned unresolved; parent must not discard either side"
                )
            }
        }
    }
}

fn paths_disjoint(left: &UncommittedPatch, right: &UncommittedPatch) -> bool {
    !left
        .touched_paths
        .iter()
        .any(|path| right.touched_paths.iter().any(|other| other == path))
}

fn covers_inputs(
    resolved: &UncommittedPatch,
    left: &UncommittedPatch,
    right: &UncommittedPatch,
) -> bool {
    left.touched_paths
        .iter()
        .chain(&right.touched_paths)
        .all(|path| {
            resolved
                .touched_paths
                .iter()
                .any(|candidate| candidate == path)
        })
        && left
            .untracked_paths
            .iter()
            .chain(&right.untracked_paths)
            .all(|path| {
                resolved
                    .untracked_paths
                    .iter()
                    .any(|candidate| candidate == path)
            })
}

fn same_manifest(left: &UncommittedPatch, right: &UncommittedPatch) -> bool {
    fn set(paths: &[String]) -> std::collections::BTreeSet<&String> {
        paths.iter().collect()
    }
    set(&left.touched_paths) == set(&right.touched_paths)
        && set(&left.untracked_paths) == set(&right.untracked_paths)
}

fn constrained_to_inputs(
    resolved: &UncommittedPatch,
    left: &UncommittedPatch,
    right: &UncommittedPatch,
) -> bool {
    let allowed = left
        .touched_paths
        .iter()
        .chain(&left.untracked_paths)
        .chain(&right.touched_paths)
        .chain(&right.untracked_paths)
        .collect::<std::collections::BTreeSet<_>>();
    resolved
        .touched_paths
        .iter()
        .chain(&resolved.untracked_paths)
        .all(|path| allowed.contains(path))
}
