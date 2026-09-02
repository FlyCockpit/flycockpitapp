//! First-party onboarding agent catalog.
//!
//! `index.json` is discovery-only.  Its `definition` member uses the exact
//! unified frontmatter type, but installation always parses the pinned
//! `agent.md` and requires byte-semantic equality with that advisory copy.

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use cockpit_config::config::providers::ProvidersConfig;
use futures::StreamExt;
use serde::{Deserialize, Serialize};

pub const FIRST_PARTY_REPOSITORY: &str = "FlyCockpit/agents";
pub const FIRST_PARTY_DEFAULT_BRANCH: &str = "main";
pub const BUNDLED_FRONTIER_SLUG: &str = "frontier-coding";
/// Commit from which the in-binary first-run snapshot was generated. Keeping
/// this immutable identity alongside the bytes makes offline installation as
/// auditable and replayable as an online catalog install.
pub const BUNDLED_CATALOG_REVISION: &str = "464140ba6ee9e1669ef1c3f37d82de8c7edd83d7";
const CATALOG_FETCH_LIMIT: usize = 1024 * 1024;
const CATALOG_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCatalogIndex {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u8,
    pub catalog: AgentCatalogIdentity,
    pub agents: Vec<AgentCatalogEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCatalogIdentity {
    pub name: String,
    pub repository: String,
    #[serde(rename = "defaultBranch")]
    pub default_branch: String,
    pub license: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCatalogEntry {
    pub definition: crate::agents::AgentDefinitionFrontmatter,
    pub catalog: AgentCatalogEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCatalogEnvelope {
    pub slug: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "definitionPath")]
    pub definition_path: String,
    pub distribution: AgentCatalogDistribution,
    pub hardware: AgentCatalogHardware,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCatalogDistribution {
    BundledSnapshot,
    RepositoryOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentCatalogHardware {
    Any,
    Gpu {
        #[serde(rename = "gpuModel")]
        gpu_model: String,
        #[serde(rename = "gpuCount")]
        gpu_count: u32,
    },
    DgxSpark {
        #[serde(rename = "gpuCount")]
        gpu_count: u32,
    },
}

impl AgentCatalogIndex {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let catalog: Self = serde_json::from_slice(bytes).context("decoding agent catalog")?;
        catalog.validate()?;
        Ok(catalog)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "agent catalog schemaVersion must be 1");
        ensure!(
            self.catalog.repository == FIRST_PARTY_REPOSITORY
                && self.catalog.default_branch == FIRST_PARTY_DEFAULT_BRANCH,
            "agent catalog repository identity is not the first-party catalog"
        );
        let mut slugs = BTreeSet::new();
        for entry in &self.agents {
            entry.validate()?;
            ensure!(
                slugs.insert(entry.catalog.slug.as_str()),
                "agent catalog contains duplicate slug `{}`",
                entry.catalog.slug
            );
        }
        Ok(())
    }

    /// Suggestions whose primary slot has at least one compatible configured
    /// model. The bundled frontier fallback remains discoverable even when
    /// offline, but it is not presented as usable until a route exists.
    pub fn suggestions_for_models(&self, providers: &ProvidersConfig) -> Vec<&AgentCatalogEntry> {
        let offerings = super::agent_installation::setup_offerings(providers);
        self.agents
            .iter()
            .filter(|entry| {
                entry
                    .definition
                    .model_slots
                    .get("primary")
                    .is_some_and(|slot| {
                        !crate::agents::ranked_compatible_offerings(slot, &offerings, providers)
                            .is_empty()
                    })
            })
            .collect()
    }

    pub fn entry(&self, slug: &str) -> Option<&AgentCatalogEntry> {
        self.agents.iter().find(|entry| entry.catalog.slug == slug)
    }
}

impl AgentCatalogEntry {
    fn validate(&self) -> Result<()> {
        ensure!(
            valid_slug(&self.catalog.slug),
            "agent catalog slug is invalid"
        );
        ensure!(
            !self.catalog.display_name.trim().is_empty(),
            "agent catalog displayName must be non-empty"
        );
        ensure!(
            self.catalog.definition_path == format!("agents/{}/agent.md", self.catalog.slug),
            "agent catalog definitionPath must be the slug's agent.md"
        );
        self.definition
            .validate_catalog_definition()
            .context("invalid catalog agent definition")?;
        ensure!(
            self.definition.agent_id.rsplit('/').next() == Some(self.catalog.slug.as_str()),
            "catalog slug must match the unified agentId"
        );
        match &self.catalog.hardware {
            AgentCatalogHardware::Any => {}
            AgentCatalogHardware::Gpu {
                gpu_model,
                gpu_count,
            } => ensure!(
                !gpu_model.trim().is_empty() && *gpu_count > 0,
                "GPU hardware requires a model and positive count"
            ),
            AgentCatalogHardware::DgxSpark { gpu_count } => {
                ensure!(*gpu_count > 0, "DGX Spark hardware count must be positive")
            }
        }
        Ok(())
    }

    /// Re-validate the pinned package's authoritative `agent.md`. The index
    /// is advisory and cannot substitute different tools, capabilities, or
    /// model requirements at install time.
    pub fn validate_fetched_agent_markdown(&self, markdown: &[u8]) -> Result<crate::agents::AgentDef> {
        let text = std::str::from_utf8(markdown).context("catalog agent.md is not UTF-8")?;
        let parsed = crate::agents::parse_daemon_agent_snapshot(
            text,
            &self.catalog.slug,
            PathBuf::from("<pinned-agent-catalog>/agent.md"),
        )
        .context("invalid pinned catalog agent.md")?;
        ensure!(
            parsed.definition_frontmatter().as_ref() == Some(&self.definition),
            "pinned agent.md does not equal its advisory catalog definition"
        );
        Ok(parsed)
    }

    pub fn pinned_source_locator(&self, revision: &str) -> Result<String> {
        ensure!(
            revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "catalog install revision must be an immutable commit SHA"
        );
        Ok(format!(
            "{}@{}:{}",
            FIRST_PARTY_REPOSITORY, revision, self.catalog.definition_path
        ))
    }
}

fn valid_slug(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub fn cached_catalog() -> Result<AgentCatalogIndex> {
    AgentCatalogIndex::parse(include_bytes!("assets/agent_catalog/index.json"))
}

pub fn bundled_frontier_markdown() -> &'static [u8] {
    include_bytes!("assets/agent_catalog/frontier-coding.md")
}

pub fn bundled_frontier_entry() -> Result<AgentCatalogEntry> {
    let catalog = cached_catalog()?;
    let entry = catalog
        .entry(BUNDLED_FRONTIER_SLUG)
        .context("cached catalog omits bundled frontier agent")?
        .clone();
    ensure!(
        entry.catalog.distribution == AgentCatalogDistribution::BundledSnapshot,
        "cached frontier agent is not marked bundled_snapshot"
    );
    entry.validate_fetched_agent_markdown(bundled_frontier_markdown())?;
    Ok(entry)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentCatalogOrigin {
    Live,
    Cached,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedAgentCatalog {
    pub revision: String,
    pub origin: AgentCatalogOrigin,
    pub index: AgentCatalogIndex,
}

/// Prefer the live first-party catalog, falling back to the in-binary snapshot
/// for offline first-run. The returned live revision is always a resolved
/// commit SHA; callers must use it in the eventual install locator.
pub async fn preferred_catalog() -> Result<ResolvedAgentCatalog> {
    match fetch_live_catalog().await {
        Ok(catalog) => Ok(catalog),
        Err(_) => Ok(ResolvedAgentCatalog {
            revision: BUNDLED_CATALOG_REVISION.to_string(),
            origin: AgentCatalogOrigin::Cached,
            index: cached_catalog()?,
        }),
    }
}

pub async fn fetch_live_catalog() -> Result<ResolvedAgentCatalog> {
    let client = catalog_http_client()?;
    let commit_bytes = fetch_bounded(
        &client,
        "https://api.github.com/repos/FlyCockpit/agents/commits/main",
    )
    .await
    .context("resolving live agent catalog revision")?;
    let commit: serde_json::Value =
        serde_json::from_slice(&commit_bytes).context("decoding catalog commit response")?;
    let revision = commit
        .get("sha")
        .and_then(serde_json::Value::as_str)
        .context("catalog commit response omitted sha")?;
    fetch_catalog_at_revision_with_client(&client, revision, AgentCatalogOrigin::Live).await
}

pub async fn fetch_catalog_at_revision(revision: &str) -> Result<ResolvedAgentCatalog> {
    let client = catalog_http_client()?;
    fetch_catalog_at_revision_with_client(&client, revision, AgentCatalogOrigin::Live).await
}

async fn fetch_catalog_at_revision_with_client(
    client: &reqwest::Client,
    revision: &str,
    origin: AgentCatalogOrigin,
) -> Result<ResolvedAgentCatalog> {
    ensure!(valid_commit_sha(revision), "catalog revision must be a commit SHA");
    let url = format!(
        "https://raw.githubusercontent.com/FlyCockpit/agents/{revision}/index.json"
    );
    let bytes = fetch_bounded(client, &url)
        .await
        .context("fetching pinned agent catalog index")?;
    Ok(ResolvedAgentCatalog {
        revision: revision.to_string(),
        origin,
        index: AgentCatalogIndex::parse(&bytes)?,
    })
}

fn catalog_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(CATALOG_FETCH_TIMEOUT)
        .user_agent("flycockpit-agent-catalog")
        .build()
        .context("building agent catalog client")
}

async fn fetch_bounded(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let response = tokio::time::timeout(CATALOG_FETCH_TIMEOUT, client.get(url).send())
        .await
        .context("agent catalog request timed out")??;
    ensure!(
        response.status().is_success(),
        "agent catalog request failed"
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= CATALOG_FETCH_LIMIT as u64),
        "agent catalog response exceeds 1MiB"
    );
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("streaming agent catalog response")?;
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= CATALOG_FETCH_LIMIT,
            "agent catalog response exceeds 1MiB"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn valid_commit_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
