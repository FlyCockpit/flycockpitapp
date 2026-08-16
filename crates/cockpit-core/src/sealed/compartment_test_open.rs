impl SealedCompartment {
    pub fn open_default() -> Result<Self> {
        let db = crate::db::Db::open_default().context("opening cockpit DB for sealed vault")?;
        let vault = crate::secure_key::vault_for_db(&db)
            .map_err(|e| anyhow::anyhow!("opening secret vault for sealed compartment: {e}"))?;
        Ok(Self::from_vault(vault))
    }
}
