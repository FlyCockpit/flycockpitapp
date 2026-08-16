fn open_secret_store_impl(store_path: Option<&Path>) -> Result<CredentialStore> {
    if let Some(path) = store_path {
        return CredentialStore::open(path.to_path_buf());
    }
    CredentialStore::open_default()
}
