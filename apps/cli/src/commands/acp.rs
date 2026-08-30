//! `cockpit acp` command entry point.

use anyhow::Result;

pub async fn run() -> Result<()> {
    crate::acp::server::run().await
}
