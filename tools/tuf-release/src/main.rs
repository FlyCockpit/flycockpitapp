//! Private release-tooling seam for canonical fake-fixture evidence validation.
//!
//! This binary never loads production roots, signing keys, HTTP clients, or
//! publication paths. Activation issues own the real ceremony tooling.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use cockpit_core::updater::{FakeFixtureEvidence, validate_fake_fixture_evidence};

fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
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
