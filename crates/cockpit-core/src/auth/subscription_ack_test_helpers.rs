use anyhow::Result;

use super::{acknowledged_in, record_in};
use crate::credentials::CredentialStore;

pub fn acknowledged(provider: &str) -> Result<bool> {
    Ok(acknowledged_in(&CredentialStore::open_default()?, provider))
}

pub fn record(provider: &str) -> Result<()> {
    let mut store = CredentialStore::open_default()?;
    record_in(&mut store, provider)
}
