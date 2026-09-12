//! Canonical fake-fixture evidence shared by private release tooling and tests.
//!
//! This crate intentionally carries only serde-backed schema types and validation.
//! It must not depend on HTTP clients, production metadata paths, or the installed
//! updater composition.

use serde::{Deserialize, Serialize};

/// Authorized target descriptor selected from current trusted targets metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateTargetDescriptor {
    pub version: String,
    pub platform: String,
    pub path: String,
    pub length: u64,
    pub sha256: String,
}

/// Canonical fake-fixture evidence validated by private release tooling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FakeFixtureEvidence {
    pub release_tag: String,
    pub commit: String,
    pub targets: Vec<UpdateTargetDescriptor>,
}

/// Validate canonical fake-fixture evidence before offline signing or publication.
pub fn validate_fake_fixture_evidence(evidence: &FakeFixtureEvidence) -> Result<(), String> {
    use std::collections::{BTreeSet, HashSet};

    if evidence.release_tag.trim().is_empty() {
        return Err("release_tag must be non-empty".to_string());
    }
    if evidence.commit.trim().is_empty() {
        return Err("commit must be non-empty".to_string());
    }
    if evidence.targets.is_empty() {
        return Err("targets must not be empty".to_string());
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
        return Err("targets must be listed in canonical version/platform/path order".to_string());
    }

    for target in &evidence.targets {
        if target.version.trim().is_empty()
            || target.platform.trim().is_empty()
            || target.path.trim().is_empty()
        {
            return Err("target entries must include version, platform, and path".to_string());
        }
        if target.length == 0 {
            return Err("target length must be non-zero".to_string());
        }
        if target.sha256.len() != 64 || !target.sha256.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err("target sha256 must be a 64-character hex digest".to_string());
        }
        if target.sha256.chars().any(|ch| ch.is_ascii_uppercase()) {
            return Err("target sha256 must use lowercase hex digits".to_string());
        }
        if !identities.insert((target.version.clone(), target.platform.clone())) {
            return Err(format!(
                "duplicate target identity for version `{}` on platform `{}`",
                target.version, target.platform
            ));
        }
        if !paths.insert(target.path.clone()) {
            return Err(format!("duplicate target path `{}`", target.path));
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
        return Err(
            "target inventory must contain unique version/platform/path tuples".to_string(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{FakeFixtureEvidence, UpdateTargetDescriptor, validate_fake_fixture_evidence};

    #[test]
    fn fake_fixture_evidence_roundtrips_through_json() {
        let evidence = FakeFixtureEvidence {
            release_tag: "v0.1.0".to_string(),
            commit: "abc123".to_string(),
            targets: vec![UpdateTargetDescriptor {
                version: "0.1.0".to_string(),
                platform: "x86_64-unknown-linux-gnu".to_string(),
                path: "cockpit-x86_64-unknown-linux-gnu.tar.gz".to_string(),
                length: 42,
                sha256: "a".repeat(64),
            }],
        };
        let json = serde_json::to_string(&evidence).expect("serialize fake fixture evidence");
        let decoded: FakeFixtureEvidence =
            serde_json::from_str(&json).expect("deserialize fake fixture evidence");
        assert_eq!(decoded, evidence);
        validate_fake_fixture_evidence(&decoded).expect("canonical evidence validates");
    }
}
