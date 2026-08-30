//! Daemon-memory-only ACP-forwarded MCP catalogs.
//!
//! Forwarded declarations deliberately do not implement `Serialize` and are
//! never converted to [`super::config::ServerConfig`]. This keeps editor env
//! and headers out of persistent config, the credential vault, the normal
//! disk cache, and durable approval grants.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result, bail};
use cockpit_proto::{
    AcpForwardedMcpDeclarationV1, AcpForwardedMcpIngressV1, AcpForwardedMcpTransportV1,
    CodeRootAttachmentCapabilityV1,
};
use reqwest::header::{HeaderName, HeaderValue};
use tokio_util::sync::CancellationToken;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use super::protocol::ToolDescriptor;

pub const SOURCE_ACP_FORWARDED: &str = "acp_forwarded";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcpForwardedStdioV1 {
    command: PathBuf,
    args: Vec<String>,
    env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcpForwardedRemoteV1 {
    url: String,
    headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcpForwardedTransportV1 {
    Stdio(AcpForwardedStdioV1),
    Http(AcpForwardedRemoteV1),
    Sse(AcpForwardedRemoteV1),
}

/// One normalized, memory-only catalog entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcpForwardedMcpEntryV1 {
    name: String,
    transport: AcpForwardedTransportV1,
}

impl AcpForwardedMcpEntryV1 {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn transport_kind(&self) -> &'static str {
        match self.transport {
            AcpForwardedTransportV1::Stdio(_) => "stdio",
            AcpForwardedTransportV1::Http(_) => "http",
            AcpForwardedTransportV1::Sse(_) => "sse",
        }
    }

    /// The approval/session-audit display label is deliberately independent
    /// of the editor-controlled server name.  A declaration name can itself
    /// contain secret-like text, so even a truncated copy is not safe to
    /// project into durable interrupt or audit records.
    pub fn redacted_display_name(&self) -> &'static str {
        "editor-provided MCP server"
    }

    pub(crate) fn transport(&self) -> &AcpForwardedTransportV1 {
        &self.transport
    }

    /// A bounded, credential-free approval identity.
    pub fn safe_display_identity(&self) -> String {
        match &self.transport {
            AcpForwardedTransportV1::Stdio(stdio) => stdio
                .command
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("executable")
                .chars()
                .take(128)
                .collect(),
            AcpForwardedTransportV1::Http(remote) | AcpForwardedTransportV1::Sse(remote) => {
                url::Url::parse(&remote.url)
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_owned))
                    .unwrap_or_else(|| "https endpoint".to_string())
                    .chars()
                    .take(128)
                    .collect()
            }
        }
    }
}

impl AcpForwardedStdioV1 {
    pub(crate) fn command(&self) -> &Path {
        &self.command
    }
    pub(crate) fn args(&self) -> &[String] {
        &self.args
    }
    pub(crate) fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }
}

impl AcpForwardedRemoteV1 {
    pub(crate) fn url(&self) -> &str {
        &self.url
    }
    pub(crate) fn headers(&self) -> &BTreeMap<String, String> {
        &self.headers
    }
}

/// Epoch-local grant decision. There is no conversion to a durable grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochGrantDecision {
    Allow,
    Reject,
}

/// Root-scoped epoch owning its memory cache, grants and final effect gate.
pub struct AcpForwardedMcpCatalogV1 {
    root_id: Uuid,
    epoch: Uuid,
    entries: BTreeMap<String, Arc<AcpForwardedMcpEntryV1>>,
    /// This is the converted representation, not the ingress bytes.  The
    /// latter retain non-canonical spellings (notably NFC names and URLs).
    /// Epoch sharing is defined over the semantic representation.
    normalized_entries: BTreeMap<String, Arc<AcpForwardedMcpEntryV1>>,
    state: RwLock<EpochState>,
    cancellation: CancellationToken,
}

#[derive(Default)]
struct EpochState {
    cache: HashMap<String, Arc<Vec<ToolDescriptor>>>,
    grants: HashMap<(String, String), EpochGrantDecision>,
    released: bool,
}

impl AcpForwardedMcpCatalogV1 {
    pub fn root_id(&self) -> Uuid {
        self.root_id
    }
    pub fn epoch(&self) -> Uuid {
        self.epoch
    }
    pub fn entry(&self, name: &str) -> Option<Arc<AcpForwardedMcpEntryV1>> {
        (!self.is_released())
            .then(|| self.entries.get(name).cloned())
            .flatten()
    }
    pub fn entries(&self) -> impl Iterator<Item = (&str, Arc<AcpForwardedMcpEntryV1>)> + '_ {
        self.entries
            .iter()
            .map(|(name, entry)| (name.as_str(), entry.clone()))
    }
    pub fn is_released(&self) -> bool {
        self.state.read().map_or(true, |state| state.released)
    }
    pub fn recheck_effect_gate(&self) -> Result<()> {
        if self.is_released() {
            bail!("acp_mcp_catalog_released");
        }
        Ok(())
    }
    pub(crate) fn cached_tools(&self, name: &str) -> Option<Arc<Vec<ToolDescriptor>>> {
        let state = self.state.read().ok()?;
        (!state.released)
            .then(|| state.cache.get(name).cloned())
            .flatten()
    }
    pub(crate) fn cache_tools(&self, name: &str, tools: Vec<ToolDescriptor>) {
        if let Ok(mut state) = self.state.write()
            && !state.released
        {
            state.cache.insert(name.to_string(), Arc::new(tools));
        }
    }
    pub fn grant(&self, server: &str, tool: &str) -> Option<EpochGrantDecision> {
        let state = self.state.read().ok()?;
        (!state.released)
            .then(|| {
                state
                    .grants
                    .get(&(server.to_string(), tool.to_string()))
                    .copied()
            })
            .flatten()
    }
    pub fn record_epoch_grant(
        &self,
        server: &str,
        tool: &str,
        decision: EpochGrantDecision,
    ) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| anyhow::anyhow!("forwarded MCP epoch lock poisoned"))?;
        if state.released {
            bail!("acp_mcp_catalog_released");
        }
        state
            .grants
            .insert((server.to_string(), tool.to_string()), decision);
        Ok(())
    }
    fn normalized_equivalent(
        &self,
        declarations: &[AcpForwardedMcpDeclarationV1],
        persistent_names: impl IntoIterator<Item = String>,
    ) -> Result<bool> {
        Ok(self.normalized_entries == validate_and_convert(declarations, persistent_names)?)
    }
    pub(crate) fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }
    fn revoke(&self) {
        // One write lock is the final-release linearization point for every
        // cache/grant writer and reader.  Cancelling it also poisons any
        // stdio request that was already handed to the transport.
        if let Ok(mut state) = self.state.write() {
            state.released = true;
            state.cache.clear();
            state.grants.clear();
        }
        self.cancellation.cancel();
    }
}

/// Read-only slot shared by a root worker and every descendant `ToolCtx`.
#[derive(Default)]
pub struct ForwardedCatalogSlot {
    active: RwLock<Option<Arc<AcpForwardedMcpCatalogV1>>>,
}

impl ForwardedCatalogSlot {
    pub fn active(&self) -> Option<Arc<AcpForwardedMcpCatalogV1>> {
        self.active.read().ok()?.clone()
    }
    fn publish(&self, epoch: Arc<AcpForwardedMcpCatalogV1>) {
        if let Ok(mut active) = self.active.write() {
            *active = Some(epoch);
        }
    }
    fn clear_if(&self, epoch: Uuid) {
        if let Ok(mut active) = self.active.write()
            && active.as_ref().is_some_and(|active| active.epoch == epoch)
        {
            *active = None;
        }
    }
}

struct RootEpochState {
    catalog: Arc<AcpForwardedMcpCatalogV1>,
    slot: Arc<ForwardedCatalogSlot>,
    bindings: HashSet<String>,
}

/// Boot-local daemon authority for root epochs and attachment bindings.
#[derive(Default)]
pub struct AcpForwardedMcpRegistryV1 {
    roots: std::sync::Mutex<HashMap<Uuid, RootEpochState>>,
}

impl AcpForwardedMcpRegistryV1 {
    pub fn validate(
        &self,
        ingress: &AcpForwardedMcpIngressV1,
        persistent_names: impl IntoIterator<Item = String>,
    ) -> Result<()> {
        if ingress.declarations.is_empty() {
            return Ok(());
        }
        validate_and_convert(&ingress.declarations, persistent_names).map(|_| ())
    }

    pub fn bind(
        &self,
        root_id: Uuid,
        attachment: &CodeRootAttachmentCapabilityV1,
        ingress: &AcpForwardedMcpIngressV1,
        persistent_names: impl IntoIterator<Item = String>,
        slot: Arc<ForwardedCatalogSlot>,
    ) -> Result<Option<Arc<AcpForwardedMcpCatalogV1>>> {
        let persistent_names: Vec<String> = persistent_names.into_iter().collect();
        let mut roots = crate::sync::lock_or_recover(&self.roots);
        if let Some(active) = roots.get_mut(&root_id) {
            if ingress.declarations.is_empty()
                || !active.catalog.normalized_equivalent(
                    &ingress.declarations,
                    persistent_names.iter().cloned(),
                )?
            {
                bail!("acp_mcp_catalog_conflict");
            }
            active
                .bindings
                .insert(attachment.expose_opaque().to_string());
            active.slot.publish(active.catalog.clone());
            return Ok(Some(active.catalog.clone()));
        }
        if ingress.declarations.is_empty() {
            return Ok(None);
        }
        let entries = validate_and_convert(&ingress.declarations, persistent_names)?;
        let catalog = Arc::new(AcpForwardedMcpCatalogV1 {
            root_id,
            epoch: Uuid::new_v4(),
            entries,
            normalized_entries: entries.clone(),
            state: RwLock::new(EpochState::default()),
            cancellation: CancellationToken::new(),
        });
        slot.publish(catalog.clone());
        roots.insert(
            root_id,
            RootEpochState {
                catalog: catalog.clone(),
                slot,
                bindings: HashSet::from([attachment.expose_opaque().to_string()]),
            },
        );
        Ok(Some(catalog))
    }

    pub fn release_attachment(
        &self,
        root_id: Uuid,
        attachment: &CodeRootAttachmentCapabilityV1,
    ) -> bool {
        let mut roots = crate::sync::lock_or_recover(&self.roots);
        let Some(active) = roots.get_mut(&root_id) else {
            return false;
        };
        if !active.bindings.remove(attachment.expose_opaque()) {
            return false;
        }
        if !active.bindings.is_empty() {
            return true;
        }
        let active = roots.remove(&root_id).expect("root epoch was present");
        active.catalog.revoke();
        active.slot.clear_if(active.catalog.epoch);
        true
    }

    pub fn revoke_root(&self, root_id: Uuid) -> bool {
        let mut roots = crate::sync::lock_or_recover(&self.roots);
        let Some(active) = roots.remove(&root_id) else {
            return false;
        };
        active.catalog.revoke();
        active.slot.clear_if(active.catalog.epoch);
        true
    }
}

fn validate_and_convert(
    declarations: &[AcpForwardedMcpDeclarationV1],
    persistent_names: impl IntoIterator<Item = String>,
) -> Result<BTreeMap<String, Arc<AcpForwardedMcpEntryV1>>> {
    let persistent_names: HashSet<String> = persistent_names.into_iter().collect();
    let mut entries = BTreeMap::new();
    for declaration in declarations {
        declaration
            .validate()
            .map_err(|_| anyhow::anyhow!("acp_mcp_invalid_declaration"))?;
        let name: String = declaration.name.nfc().collect();
        if name == super::builtin::BUILTIN_SERVER_ID || persistent_names.contains(&name) {
            bail!("acp_mcp_catalog_name_collision");
        }
        if entries.contains_key(&name) {
            bail!("acp_mcp_duplicate_name");
        }
        let transport = match &declaration.transport {
            AcpForwardedMcpTransportV1::Stdio { command, args, env } => {
                let command = validate_stdio_command(command)?;
                if args.iter().any(|arg| contains_expansion(arg)) {
                    bail!("acp_mcp_stdio_expansion_refused");
                }
                let mut explicit = BTreeMap::new();
                let mut normalized = HashSet::new();
                for pair in env {
                    validate_env_name(&pair.name)?;
                    if contains_expansion(&pair.value) {
                        bail!("acp_mcp_stdio_expansion_refused");
                    }
                    if !normalized.insert(platform_env_key(&pair.name)) {
                        bail!("acp_mcp_duplicate_environment");
                    }
                    explicit.insert(pair.name.clone(), pair.value.clone());
                }
                AcpForwardedTransportV1::Stdio(AcpForwardedStdioV1 {
                    command,
                    args: args.clone(),
                    env: explicit,
                })
            }
            AcpForwardedMcpTransportV1::Http { url, headers } => {
                AcpForwardedTransportV1::Http(validate_remote(url, headers)?)
            }
            AcpForwardedMcpTransportV1::Sse { url, headers } => {
                AcpForwardedTransportV1::Sse(validate_remote(url, headers)?)
            }
        };
        entries.insert(
            name.clone(),
            Arc::new(AcpForwardedMcpEntryV1 { name, transport }),
        );
    }
    Ok(entries)
}

fn validate_stdio_command(command: &str) -> Result<PathBuf> {
    let path = Path::new(command);
    if !path.is_absolute() {
        bail!("acp_mcp_stdio_command_not_absolute");
    }
    let canonical = path
        .canonicalize()
        .context("acp_mcp_stdio_command_unavailable")?;
    if canonical != path {
        bail!("acp_mcp_stdio_command_not_canonical");
    }
    let metadata = canonical
        .metadata()
        .context("acp_mcp_stdio_command_unavailable")?;
    if !metadata.is_file() {
        bail!("acp_mcp_stdio_command_not_regular");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // The centralized external-runtime launch gate rechecks host policy.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o111 == 0 {
            bail!("acp_mcp_stdio_command_not_owner_executable");
        }
    }
    Ok(canonical)
}

fn contains_expansion(value: &str) -> bool {
    value.as_bytes().windows(2).any(|pair| {
        pair[0] == b'$' && (pair[1] == b'{' || pair[1] == b'_' || pair[1].is_ascii_alphabetic())
    })
}

fn validate_env_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let valid = chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric());
    if !valid || name.starts_with("SEALED_") {
        bail!("acp_mcp_invalid_environment_name");
    }
    Ok(())
}

fn platform_env_key(name: &str) -> String {
    if cfg!(windows) {
        name.to_ascii_uppercase()
    } else {
        name.to_string()
    }
}

fn validate_remote(
    raw_url: &str,
    headers: &[cockpit_proto::AcpNameValuePairV1],
) -> Result<AcpForwardedRemoteV1> {
    let url = super::transport::timeout::validate_remote_endpoint(raw_url)
        .map_err(|_| anyhow::anyhow!("acp_mcp_invalid_https_endpoint"))?;
    if url.scheme() != "https" {
        bail!("acp_mcp_invalid_https_endpoint");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("acp_mcp_endpoint_userinfo_refused");
    }
    let mut normalized = HashSet::new();
    let mut validated = BTreeMap::new();
    for pair in headers {
        let name = HeaderName::from_bytes(pair.name.as_bytes())
            .map_err(|_| anyhow::anyhow!("acp_mcp_invalid_header"))?;
        HeaderValue::from_bytes(pair.value.as_bytes())
            .map_err(|_| anyhow::anyhow!("acp_mcp_invalid_header"))?;
        let lower = name.as_str().to_ascii_lowercase();
        if is_hop_by_hop(&lower) || !normalized.insert(lower) {
            bail!("acp_mcp_header_refused");
        }
        validated.insert(name.as_str().to_string(), pair.value.clone());
    }
    Ok(AcpForwardedRemoteV1 {
        url: url.to_string(),
        headers: validated,
    })
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ingress(declarations: Vec<AcpForwardedMcpDeclarationV1>) -> AcpForwardedMcpIngressV1 {
        AcpForwardedMcpIngressV1 {
            version: 1,
            declarations,
            client_provenance_id: cockpit_proto::OpaqueAsciiId128V1::new("editor").unwrap(),
            ingress_request_id: cockpit_proto::OpaqueAsciiId128V1::new("request").unwrap(),
        }
    }
    fn remote(name: &str, url: &str) -> AcpForwardedMcpDeclarationV1 {
        AcpForwardedMcpDeclarationV1 {
            name: name.to_string(),
            transport: AcpForwardedMcpTransportV1::Http {
                url: url.to_string(),
                headers: vec![],
            },
        }
    }

    #[test]
    fn binding_is_idempotent_refcounted_and_conflict_closed() {
        let registry = AcpForwardedMcpRegistryV1::default();
        let root = Uuid::new_v4();
        let slot = Arc::new(ForwardedCatalogSlot::default());
        let first = CodeRootAttachmentCapabilityV1::new_opaque("first").unwrap();
        let second = CodeRootAttachmentCapabilityV1::new_opaque("second").unwrap();
        let declarations = ingress(vec![remote("docs", "https://example.com/mcp")]);
        let epoch = registry
            .bind(root, &first, &declarations, Vec::new(), slot.clone())
            .unwrap()
            .unwrap();
        let retry = registry
            .bind(root, &first, &declarations, Vec::new(), slot.clone())
            .unwrap()
            .unwrap();
        assert_eq!(retry.epoch(), epoch.epoch());
        let shared = registry
            .bind(root, &second, &declarations, Vec::new(), slot.clone())
            .unwrap()
            .unwrap();
        assert_eq!(shared.epoch(), epoch.epoch());
        let conflict = registry
            .bind(root, &second, &ingress(vec![]), Vec::new(), slot.clone())
            .err()
            .expect("active epoch rejects an empty vector");
        assert!(conflict.to_string().contains("acp_mcp_catalog_conflict"));
        assert!(registry.release_attachment(root, &first));
        assert!(!epoch.is_released());
        assert!(registry.release_attachment(root, &second));
        assert!(epoch.is_released());
        assert!(slot.active().is_none());
    }

    #[test]
    fn normalized_equivalent_declarations_share_the_active_epoch() {
        let registry = AcpForwardedMcpRegistryV1::default();
        let root = Uuid::new_v4();
        let slot = Arc::new(ForwardedCatalogSlot::default());
        let first = CodeRootAttachmentCapabilityV1::new_opaque("first").unwrap();
        let second = CodeRootAttachmentCapabilityV1::new_opaque("second").unwrap();
        let composed = ingress(vec![remote("caf\u{e9}", "https://example.com/mcp")]);
        let decomposed = ingress(vec![remote("cafe\u{301}", "https://example.com/mcp")]);

        let epoch = registry
            .bind(root, &first, &composed, Vec::new(), slot.clone())
            .unwrap()
            .unwrap();
        let shared = registry
            .bind(root, &second, &decomposed, Vec::new(), slot)
            .unwrap()
            .unwrap();

        assert_eq!(shared.epoch(), epoch.epoch());
    }

    #[test]
    fn final_release_linearizes_epoch_state_writers() {
        let registry = AcpForwardedMcpRegistryV1::default();
        let root = Uuid::new_v4();
        let slot = Arc::new(ForwardedCatalogSlot::default());
        let attachment = CodeRootAttachmentCapabilityV1::new_opaque("attachment").unwrap();
        let epoch = registry
            .bind(
                root,
                &attachment,
                &ingress(vec![remote("docs", "https://example.com/mcp")]),
                Vec::new(),
                slot,
            )
            .unwrap()
            .unwrap();

        assert!(registry.release_attachment(root, &attachment));
        epoch.cache_tools("docs", vec![]);
        let error = epoch
            .record_epoch_grant("docs", "read", EpochGrantDecision::Allow)
            .unwrap_err();
        assert!(error.to_string().contains("acp_mcp_catalog_released"));
        assert!(epoch.cached_tools("docs").is_none());
        assert!(epoch.grant("docs", "read").is_none());
        assert!(epoch.cancellation_token().is_cancelled());
    }

    #[test]
    fn remote_policy_refuses_secret_bearing_invalid_input_without_echo() {
        for declaration in [
            remote("docs", "http://secret.example/mcp"),
            remote("docs", "https://user:password@example.com/mcp"),
            AcpForwardedMcpDeclarationV1 {
                name: "docs".to_string(),
                transport: AcpForwardedMcpTransportV1::Http {
                    url: "https://example.com/mcp".to_string(),
                    headers: vec![cockpit_proto::AcpNameValuePairV1 {
                        name: "Connection".to_string(),
                        value: "secret-value".to_string(),
                    }],
                },
            },
        ] {
            let rendered = validate_and_convert(&[declaration], Vec::new())
                .unwrap_err()
                .to_string();
            assert!(!rendered.contains("secret"));
            assert!(!rendered.contains("password"));
        }
        assert!(
            validate_and_convert(
                &[remote("persistent", "https://example.com/mcp")],
                ["persistent".to_string()]
            )
            .is_err()
        );
    }

    #[test]
    fn forwarded_values_do_not_name_persistent_sinks() {
        let production = include_str!("forwarded.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            "McpConfig::write_private",
            "cache::save",
            "cache::load",
            "CredentialStore",
            "SecretVault",
            "GrantStore",
            "session_log",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden sink {forbidden}"
            );
        }
    }
}
