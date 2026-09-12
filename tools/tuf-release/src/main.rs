//! Private release-tooling seam for canonical fake-fixture evidence validation.
//!
//! This binary never loads production roots, signing keys, HTTP clients, or
//! publication paths. Activation issues own the real ceremony tooling.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FakeFixtureEvidence {
    release_tag: String,
    commit: String,
    targets: Vec<FakeFixtureTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FakeFixtureTarget {
    version: String,
    platform: String,
    path: String,
    length: u64,
    sha256: String,
}

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 || args[0] != "validate-fixture" {
        bail!("usage: cockpit-tuf-release validate-fixture <evidence.json>");
    }
    let path = PathBuf::from(&args[1]);
    let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let evidence: FakeFixtureEvidence =
        serde_json::from_slice(&bytes).context("parsing fake fixture evidence")?;
    validate(&evidence)?;
    println!("fixture evidence ok: tag={} commit={}", evidence.release_tag, evidence.commit);
    Ok(())
}

fn validate(evidence: &FakeFixtureEvidence) -> Result<()> {
    if evidence.release_tag.trim().is_empty() {
        bail!("release_tag must be non-empty");
    }
    if evidence.commit.trim().is_empty() {
        bail!("commit must be non-empty");
    }
    if evidence.targets.is_empty() {
        bail!("targets must not be empty");
    }

    let mut identities = HashSet::new();
    let mut paths = HashSet::new();
    let mut canonical = evidence.targets.clone();
    canonical.sort_by(|left, right| {
        left.version
            .cmp(&right.version)
            .then_with(|| left.platform.cmp(&right.platform))
            .then_with(|| left.path.cmp(&right.path))
    });
    if canonical != evidence.targets {
        bail!("targets must be listed in canonical version/platform/path order");
    }

    for target in &evidence.targets {
        if target.version.trim().is_empty()
            || target.platform.trim().is_empty()
            || target.path.trim().is_empty()
        {
            bail!("target entries must include version, platform, and path");
        }
        if target.length == 0 {
            bail!("target length must be non-zero");
        }
        if target.sha256.len() != 64 || !target.sha256.chars().all(|ch| ch.is_ascii_hexdigit()) {
            bail!("target sha256 must be a 64-character hex digest");
        }
        if target.sha256.chars().any(|ch| ch.is_ascii_uppercase()) {
            bail!("target sha256 must use lowercase hex digits");
        }
        if !identities.insert((target.version.clone(), target.platform.clone())) {
            bail!(
                "duplicate target identity for version `{}` on platform `{}`",
                target.version,
                target.platform
            );
        }
        if !paths.insert(target.path.clone()) {
            bail!("duplicate target path `{}`", target.path);
        }
    }

    let inventory: BTreeSet<(String, String, String)> = evidence
        .targets
        .iter()
        .map(|target| {
            (
                target.version.clone(),
                target.platform.clone(),
                target.path.clone(),
            )
        })
        .collect();
    if inventory.len() != evidence.targets.len() {
        bail!("target inventory must contain unique version/platform/path tuples");
    }

    Ok(())
}
