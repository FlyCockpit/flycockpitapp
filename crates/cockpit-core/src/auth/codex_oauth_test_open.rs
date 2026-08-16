fn open_store(store_path: Option<&Path>) -> Result<CredentialStore> {
    if let Some(path) = store_path {
        return CredentialStore::open(path.to_path_buf());
    }
    anyhow::bail!("OAuth store path-open is test-only; inject a vault-backed store")
}
