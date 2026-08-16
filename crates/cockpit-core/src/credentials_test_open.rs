impl CredentialStore {
    pub fn open_default() -> Result<Self> {
        let db =
            crate::db::Db::open_default().context("opening cockpit DB for credential vault")?;
        let vault = crate::secure_key::vault_for_db(&db)
            .map_err(|e| anyhow::anyhow!("opening secret vault for credentials: {e}"))?;
        Self::from_vault(vault)
    }

    pub fn open_default_readonly() -> Result<Self> {
        Self::open_default()
    }
}
