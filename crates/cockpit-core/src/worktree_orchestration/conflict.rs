//! Isolated conflict specialist: left/right patches plus an integration lease.

use std::path::Path;

use anyhow::{Result, bail};

use crate::git::UncommittedPatch;
use crate::workspace_lease::WorkspaceLease;

/// Closed verdict a conflict specialist may return. The parent orchestrator
/// decides whether to apply it; the specialist never writes the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    injected: Option<ConflictSpecialistVerdict>,
}

impl ConflictSpecialist {
    pub fn bounded_by(lease: WorkspaceLease) -> Self {
        Self {
            lease,
            injected: None,
        }
    }

    pub fn with_injected_verdict(mut self, verdict: ConflictSpecialistVerdict) -> Self {
        self.injected = Some(verdict);
        self
    }

    pub fn lease(&self) -> &WorkspaceLease {
        &self.lease
    }

    /// Read a path only when it is inside the integration lease.
    pub fn read_path(&self, path: &Path) -> Result<Vec<u8>> {
        if !self.lease.covers_path(path) {
            bail!(
                "conflict specialist cannot access `{}` outside integration lease `{}`",
                path.display(),
                self.lease.visibility_root.display()
            );
        }
        Ok(std::fs::read(path)?)
    }

    /// Resolve left/right patches. Disjoint paths combine; overlapping paths
    /// stay unresolved unless a parent-injected verdict is supplied.
    pub fn resolve(
        &self,
        left: &UncommittedPatch,
        right: &UncommittedPatch,
    ) -> ConflictSpecialistVerdict {
        if let Some(injected) = self.injected {
            return injected;
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
        match verdict {
            ConflictSpecialistVerdict::ChooseLeft => Ok(left.clone()),
            ConflictSpecialistVerdict::ChooseRight => Ok(right.clone()),
            ConflictSpecialistVerdict::Combined => Ok(concatenate_patches(left, right)),
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

fn concatenate_patches(left: &UncommittedPatch, right: &UncommittedPatch) -> UncommittedPatch {
    let mut diff = left.diff.clone();
    if !diff.ends_with('\n') && !diff.is_empty() && !right.diff.is_empty() {
        diff.push('\n');
    }
    diff.push_str(&right.diff);
    let mut touched = left.touched_paths.clone();
    for path in &right.touched_paths {
        if !touched.iter().any(|existing| existing == path) {
            touched.push(path.clone());
        }
    }
    let mut untracked = left.untracked_paths.clone();
    for path in &right.untracked_paths {
        if !untracked.iter().any(|existing| existing == path) {
            untracked.push(path.clone());
        }
    }
    UncommittedPatch {
        diff,
        touched_paths: touched,
        untracked_paths: untracked,
    }
}
