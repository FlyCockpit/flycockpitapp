//! Private release-tooling seam for canonical fake-fixture evidence validation.
//!
//! This binary never loads production roots, signing keys, HTTP clients, or
//! publication paths. Activation issues own the real ceremony tooling.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use cockpit_updater_evidence::{FakeFixtureEvidence, validate_fake_fixture_evidence};

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    run(&args)
}

fn run(args: &[String]) -> Result<()> {
    if args.len() != 2 || args[0] != "validate-fixture" {
        bail!("usage: cockpit-tuf-release validate-fixture <evidence.json>");
    }
    let path = PathBuf::from(&args[1]);
    let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let evidence: FakeFixtureEvidence =
        serde_json::from_slice(&bytes).context("parsing fake fixture evidence")?;
    validate_fake_fixture_evidence(&evidence)
        .map_err(|error| anyhow::anyhow!(error))
        .context("validating fake fixture evidence")?;
    println!(
        "fixture evidence ok: tag={} commit={}",
        evidence.release_tag, evidence.commit
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_updater_evidence::UpdateTargetDescriptor;

    #[test]
    fn command_validates_the_canonical_fixture_schema() {
        let evidence = FakeFixtureEvidence {
            release_tag: "v9.9.9".into(),
            commit: "fixture-commit".into(),
            targets: vec![UpdateTargetDescriptor {
                version: "9.9.9".into(),
                platform: "x86_64-linux".into(),
                path: "cockpit.tar.gz".into(),
                length: 7,
                sha256: "a".repeat(64),
            }],
        };
        let path =
            std::env::temp_dir().join(format!("cockpit-tuf-fixture-{}.json", std::process::id()));
        std::fs::write(&path, serde_json::to_vec(&evidence).unwrap()).unwrap();
        let result = run(&[
            "validate-fixture".into(),
            path.to_string_lossy().into_owned(),
        ]);
        std::fs::remove_file(path).unwrap();
        result.unwrap();
    }
}
