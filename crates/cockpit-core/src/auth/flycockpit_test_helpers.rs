use anyhow::Result;

use super::{
    StoredFlycockpitCredential, clear_credential_in_vault, load_credential_from_store,
    maybe_load_credential_from_store, store_credential_in_vault, store_relay_choice_in_vault,
};
use crate::auth::flycockpit::RelayChoice;
use crate::credentials::CredentialStore;

pub fn load_credential() -> Result<StoredFlycockpitCredential> {
    load_credential_from_store(&CredentialStore::open_default()?)
}

pub fn load_credential_from_path(path: std::path::PathBuf) -> Result<StoredFlycockpitCredential> {
    load_credential_from_store(&CredentialStore::open(path)?)
}

pub fn maybe_load_credential() -> Option<StoredFlycockpitCredential> {
    maybe_load_credential_from_store(&CredentialStore::open_default().ok()?)
}

pub fn store_credential(credential: &StoredFlycockpitCredential) -> Result<()> {
    let db = crate::db::Db::open_default()?;
    let vault = crate::secure_key::vault_for_db(&db)
        .map_err(|e| anyhow::anyhow!("opening test vault: {e}"))?;
    store_credential_in_vault(vault, credential)
}

pub fn clear_credential() -> Result<()> {
    let db = crate::db::Db::open_default()?;
    let vault = crate::secure_key::vault_for_db(&db)
        .map_err(|e| anyhow::anyhow!("opening test vault: {e}"))?;
    clear_credential_in_vault(vault)
}

pub fn store_relay_choice(
    credential: &StoredFlycockpitCredential,
    choice: Option<RelayChoice>,
) -> Result<StoredFlycockpitCredential> {
    let db = crate::db::Db::open_default()?;
    let vault = crate::secure_key::vault_for_db(&db)
        .map_err(|e| anyhow::anyhow!("opening test vault: {e}"))?;
    store_relay_choice_in_vault(vault, credential, choice)
}
