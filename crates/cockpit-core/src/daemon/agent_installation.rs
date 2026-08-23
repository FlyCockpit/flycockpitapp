//! Daemon-owned installed-agent file/operation coordinator.
//!
//! The CLI/TUI only render `cockpit_proto::AgentInstallation*V1` values. This
//! module owns source parsing, workspace authorization, staged files, and the
//! durable idempotency/journal state. The prerequisite DB installation module
//! remains the sole binding/snapshot/revision mutation authority.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use base64::Engine;
use cockpit_config::config::providers::ProvidersConfig;
#[cfg(debug_assertions)]
use cockpit_config::config::providers::{ModelCapabilities, ModelEntry, ProviderEntry};
use cockpit_db::db::Db;
use cockpit_db::db::agent_installations::{
    AgentInstallationInput, AgentInstallationRow, AgentInstallationScope,
    AgentReplacementCompensationReceipt, InstallAgentOutcome,
};
use cockpit_db::db::installation_operations::{
    BeginInstallationOperation, InstallationJournalCheckpoint, InstallationJournalRow,
    InstallationOperationKind, InstallationOperationState,
};
use cockpit_proto::{
    AGENT_INSTALLATION_DTO_VERSION, AgentInstallationBeginV1, AgentInstallationBindingOutcomeV1,
    AgentInstallationChoiceV1, AgentInstallationErrorCodeV1, AgentInstallationErrorV1,
    AgentInstallationExecutionKindV1, AgentInstallationOperationKind, AgentInstallationReadV1,
    AgentInstallationReceiptStatusV1, AgentInstallationRecordV1, AgentInstallationResultV1,
    AgentInstallationScopeWire, AgentInstallationSlotBindingStateV1, AgentInstallationSlotStatusV1,
    AgentInstallationSubmitChoiceV1, AgentInstallationUnmatchedRecommendationV1,
};
use futures::StreamExt;
use futures::stream::BoxStream;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MAX_AGENT_MARKDOWN_BYTES: usize = 1024 * 1024;
const GITHUB_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

#[derive(serde::Serialize, serde::Deserialize)]
struct BindChoiceSet {
    installation_id: String,
    definition_digest: String,
    choices: Vec<AgentInstallationChoiceV1>,
    unmatched_recommendations: Vec<AgentInstallationUnmatchedRecommendationV1>,
    /// Server-only route lookup. Profile handles are daemon-local credential
    /// owners and must never be reconstructed from, or exposed as, provider
    /// aliases in the wire DTO.
    routes: Vec<DurableBindingRoute>,
    #[serde(default)]
    parent_receipt_status: Option<AgentInstallationReceiptStatusV1>,
    #[serde(default)]
    parent_source_revision: Option<String>,
    /// The exact choice selected by a `--yes` request. This is durable so a
    /// retry never re-ranks a changed local provider catalog or asks the user
    /// to finish a previously non-interactive operation manually.
    #[serde(default)]
    auto_choice_id: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DurableBindingRoute {
    choice_id: String,
    provider_profile_handle: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct JournalStagedSource {
    target_name: String,
    digest: String,
    commit_sha: String,
    markdown_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalAgentSource {
    pub owner: String,
    pub repository: String,
    pub requested_revision: Option<String>,
    pub markdown_path: String,
}

impl CanonicalAgentSource {
    pub fn parse(locator: &str) -> Result<Self> {
        ensure!(
            !locator.contains("://") && !locator.contains('\\'),
            "source must be OWNER/REPO[@REV]:PATH, not a URL or filesystem path"
        );
        let (repo_ref, markdown_path) = locator
            .split_once(':')
            .context("source must contain one ':' before its Markdown path")?;
        ensure!(
            !markdown_path.is_empty() && markdown_path.ends_with(".md"),
            "source path must be a non-empty Markdown path"
        );
        ensure!(
            !markdown_path.contains(':')
                && !markdown_path.starts_with('/')
                && !markdown_path.split('/').any(|part| {
                    part.is_empty()
                        || part == "."
                        || part == ".."
                        || !part.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                        })
                }),
            "source path must not traverse"
        );
        let (repo, requested_revision) = match repo_ref.split_once('@') {
            Some((repo, revision)) => {
                ensure!(
                    !revision.is_empty()
                        && revision.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                        }),
                    "source revision is invalid"
                );
                (repo, Some(revision.to_owned()))
            }
            None => (repo_ref, None),
        };
        let (owner, repository) = repo
            .split_once('/')
            .context("source repository must be OWNER/REPO")?;
        ensure!(
            !owner.is_empty() && !repository.is_empty() && !repository.contains('/'),
            "source repository must be OWNER/REPO"
        );
        for value in [owner, repository] {
            ensure!(
                value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
                "source owner/repository contains unsupported characters"
            );
        }
        Ok(Self {
            owner: owner.to_owned(),
            repository: repository.to_owned(),
            requested_revision,
            markdown_path: markdown_path.to_owned(),
        })
    }
    pub fn identity(&self) -> String {
        format!("{}/{}:{}", self.owner, self.repository, self.markdown_path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedAgentSource {
    pub commit_sha: String,
    pub markdown: Vec<u8>,
}

#[async_trait]
pub trait AgentInstallationFetcher: Send + Sync {
    /// Resolve through an HTTPS-only GitHub transport. Implementations must
    /// reject redirects and use daemon-local credential-store auth if needed.
    async fn fetch_github_markdown(
        &self,
        source: &CanonicalAgentSource,
    ) -> Result<FetchedAgentSource>;
}

#[async_trait]
pub trait AgentWorkspaceAuthorizer: Send + Sync {
    /// The input is client-provided only at this boundary. Return an opaque
    /// canonical workspace id and a daemon-owned canonical path for writes.
    async fn authorize_workspace(&self, client_path: &str) -> Result<(String, PathBuf)>;
}

/// Default local-daemon workspace authority. The socket authentication layer
/// has already established local-owner identity before this runs; canonical
/// paths are used only internally and are hashed before becoming the opaque
/// DB/protocol workspace identity.
pub struct LocalDaemonWorkspaceAuthorizer {
    authorized_roots: Vec<PathBuf>,
}

impl LocalDaemonWorkspaceAuthorizer {
    /// The daemon dispatcher supplies roots it has already authorized for the
    /// owner principal. This boundary never treats an arbitrary canonical
    /// client string as workspace authority.
    pub fn new(authorized_roots: Vec<PathBuf>) -> Result<Self> {
        let authorized_roots = authorized_roots
            .into_iter()
            .map(|path| std::fs::canonicalize(&path).context("canonicalizing authorized workspace"))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !authorized_roots.is_empty(),
            "daemon has no authorized workspace roots"
        );
        Ok(Self { authorized_roots })
    }
}

#[async_trait]
impl AgentWorkspaceAuthorizer for LocalDaemonWorkspaceAuthorizer {
    async fn authorize_workspace(&self, client_path: &str) -> Result<(String, PathBuf)> {
        let path =
            std::fs::canonicalize(client_path).context("canonicalizing requested workspace")?;
        ensure!(path.is_dir(), "requested workspace is not a directory");
        ensure!(
            self.authorized_roots.iter().any(|root| root == &path),
            "requested workspace is not authorized for this daemon client"
        );
        let identity = sha256_hex(path.to_string_lossy().as_bytes());
        Ok((format!("workspace:{identity}"), path))
    }
}

/// HTTPS-only GitHub fetcher. Redirects are disabled rather than followed;
/// GitHub private-source authorization failures remain a redacted daemon
/// error. Credential injection is intentionally a separate daemon vault
/// adapter, never a DTO field.
pub struct GithubHttpsAgentFetcher {
    transport: Arc<dyn GithubHttpTransport>,
    /// Read once from daemon custody. It never crosses a DTO, journal, DB
    /// record, error string, or tracing field.
    authorization: Option<String>,
}

/// Internal request boundary for the concrete GitHub fetcher. This is not a
/// protocol DTO and deliberately has no serializer or Debug implementation:
/// `authorization` stays in daemon process memory and never reaches a
/// journal, operation receipt, error, or tracing field.
struct GithubHttpRequest {
    url: String,
    authorization: Option<String>,
    timeout: std::time::Duration,
}

struct GithubHttpResponse {
    status: u16,
    content_length: Option<u64>,
    body: BoxStream<'static, Result<Vec<u8>>>,
}

#[async_trait]
trait GithubHttpTransport: Send + Sync {
    async fn get(&self, request: GithubHttpRequest) -> Result<GithubHttpResponse>;
}

struct ReqwestGithubHttpTransport {
    client: reqwest::Client,
}

#[async_trait]
impl GithubHttpTransport for ReqwestGithubHttpTransport {
    async fn get(&self, request: GithubHttpRequest) -> Result<GithubHttpResponse> {
        ensure!(
            request.url.starts_with("https://"),
            "GitHub source transport only permits HTTPS"
        );
        let request_builder = match request.authorization {
            Some(header) => self
                .client
                .get(&request.url)
                .header(reqwest::header::AUTHORIZATION, header),
            None => self.client.get(&request.url),
        };
        // Keep an explicit per-request deadline in addition to the client
        // default so a future transport/client configuration change cannot
        // silently remove the 20-second daemon fetch bound.
        let response = tokio::time::timeout(request.timeout, request_builder.send())
            .await
            .context("GitHub source request exceeded 20-second timeout")??;
        let status = response.status().as_u16();
        let content_length = response.content_length();
        let body = response
            .bytes_stream()
            .map(|chunk| {
                chunk
                    .map(|bytes| bytes.to_vec())
                    .map_err(anyhow::Error::from)
            })
            .boxed();
        Ok(GithubHttpResponse {
            status,
            content_length,
            body,
        })
    }
}

impl GithubHttpsAgentFetcher {
    pub fn new(vault: Arc<crate::secure_key::SecretVault>) -> Result<Self> {
        let credentials = crate::credentials::CredentialStore::from_vault(vault)
            .context("opening daemon credential store for GitHub source access")?;
        // This is a daemon-local credential-store entry, deliberately not an
        // ambient GH_TOKEN/GITHUB_TOKEN fallback. A missing entry simply makes
        // a private source return the same redacted authorization error.
        let authorization = credentials
            .named_secret("github-source-token")
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned);
        Ok(Self {
            transport: Arc::new(ReqwestGithubHttpTransport {
                client: reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(GITHUB_FETCH_TIMEOUT)
                    .user_agent("flycockpit-agent-installation")
                    .build()
                    .context("building GitHub installation client")?,
            }),
            authorization,
        })
    }

    #[cfg(test)]
    fn with_transport(
        transport: Arc<dyn GithubHttpTransport>,
        authorization: Option<String>,
    ) -> Self {
        Self {
            transport,
            authorization,
        }
    }

    async fn request(&self, url: String) -> Result<GithubHttpResponse> {
        self.transport
            .get(GithubHttpRequest {
                url,
                authorization: self
                    .authorization
                    .as_ref()
                    .map(|token| format!("Bearer {token}")),
                timeout: GITHUB_FETCH_TIMEOUT,
            })
            .await
    }
}

async fn read_github_response_body(response: GithubHttpResponse) -> Result<Vec<u8>> {
    ensure!(
        response
            .content_length
            .is_none_or(|length| length <= MAX_AGENT_MARKDOWN_BYTES as u64),
        "GitHub response exceeds 1MiB"
    );
    let mut bytes = Vec::new();
    let mut body = response.body;
    while let Some(chunk) = body.next().await {
        let chunk = chunk.context("streaming GitHub response")?;
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_AGENT_MARKDOWN_BYTES,
            "GitHub response exceeds 1MiB"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[async_trait]
impl AgentInstallationFetcher for GithubHttpsAgentFetcher {
    async fn fetch_github_markdown(
        &self,
        source: &CanonicalAgentSource,
    ) -> Result<FetchedAgentSource> {
        let revision = source.requested_revision.as_deref().unwrap_or("HEAD");
        let commit_url = format!(
            "https://api.github.com/repos/{}/{}/commits/{}",
            source.owner, source.repository, revision
        );
        let commit = self
            .request(commit_url)
            .await
            .context("requesting GitHub commit")?;
        ensure!(
            (200..300).contains(&commit.status),
            "GitHub source authorization or commit resolution failed"
        );
        let value: serde_json::Value = serde_json::from_slice(
            &read_github_response_body(commit)
                .await
                .context("reading GitHub commit response")?,
        )
        .context("decoding GitHub commit response")?;
        let commit_sha = value
            .get("sha")
            .and_then(serde_json::Value::as_str)
            .context("GitHub commit response did not contain a SHA")?
            .to_owned();
        ensure!(
            is_commit_sha(&commit_sha),
            "GitHub commit response contained invalid SHA"
        );
        let raw_url = format!(
            "https://raw.githubusercontent.com/{}/{}/{}/{}",
            source.owner, source.repository, commit_sha, source.markdown_path
        );
        let response = self
            .request(raw_url)
            .await
            .context("requesting GitHub agent Markdown")?;
        ensure!(
            (200..300).contains(&response.status),
            "GitHub agent source authorization or fetch failed"
        );
        let bytes = read_github_response_body(response)
            .await
            .context("reading GitHub agent Markdown")?;
        Ok(FetchedAgentSource {
            commit_sha,
            markdown: bytes,
        })
    }
}

pub struct AgentInstallationService {
    db: Db,
    daemon_agents_dir: PathBuf,
    fetcher: Arc<dyn AgentInstallationFetcher>,
    workspaces: Arc<dyn AgentWorkspaceAuthorizer>,
    providers: ProvidersConfig,
}

/// Development-only process-boundary fixture switch.  It is deliberately
/// compiled out of release artifacts: production daemons always construct the
/// HTTPS/vault-backed service and cannot be redirected by an environment
/// variable.  The fixture file is test data, not a user configuration format.
#[cfg(debug_assertions)]
pub const DEBUG_AGENT_INSTALLATION_FIXTURE_ENV: &str = "COCKPIT_DEBUG_AGENT_INSTALLATION_FIXTURE";

#[cfg(debug_assertions)]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DebugAgentInstallationFixture {
    commit_sha: String,
    markdown: String,
    workspace_path: PathBuf,
    #[serde(default)]
    providers: std::collections::BTreeMap<String, DebugFixtureProvider>,
}

#[cfg(debug_assertions)]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DebugFixtureProvider {
    #[serde(default)]
    template: Option<String>,
    #[serde(default)]
    models: Vec<DebugFixtureModel>,
}

#[cfg(debug_assertions)]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DebugFixtureModel {
    id: String,
    #[serde(default)]
    context_length: Option<u32>,
    #[serde(default)]
    capabilities: ModelCapabilities,
}

#[cfg(debug_assertions)]
struct DebugFixtureFetcher {
    source: FetchedAgentSource,
}

#[cfg(debug_assertions)]
#[async_trait]
impl AgentInstallationFetcher for DebugFixtureFetcher {
    async fn fetch_github_markdown(
        &self,
        _source: &CanonicalAgentSource,
    ) -> Result<FetchedAgentSource> {
        Ok(self.source.clone())
    }
}

#[cfg(debug_assertions)]
struct DebugFixtureWorkspaceAuthorizer {
    workspace: PathBuf,
}

#[cfg(debug_assertions)]
#[async_trait]
impl AgentWorkspaceAuthorizer for DebugFixtureWorkspaceAuthorizer {
    async fn authorize_workspace(&self, client_path: &str) -> Result<(String, PathBuf)> {
        let requested = std::fs::canonicalize(client_path)
            .context("canonicalizing debug fixture workspace request")?;
        ensure!(
            requested == self.workspace,
            "debug fixture workspace request is not authorized"
        );
        Ok(("workspace:debug-fixture".to_owned(), self.workspace.clone()))
    }
}

/// Construct the immutable scripted coordinator used by debug integration
/// daemons.  The JSON contains only markdown, a commit SHA, provider catalog
/// data, and an authorized workspace path; credentials and HTTP routing are
/// intentionally not representable here.
#[cfg(debug_assertions)]
pub fn debug_fixture_daemon_service(
    db: Db,
    daemon_paths: &crate::daemon::DaemonPaths,
) -> Result<Option<AgentInstallationService>> {
    let Some(path) = std::env::var_os(DEBUG_AGENT_INSTALLATION_FIXTURE_ENV) else {
        return Ok(None);
    };
    let raw = std::fs::read(&path).context("reading debug agent-installation fixture")?;
    let fixture: DebugAgentInstallationFixture =
        serde_json::from_slice(&raw).context("decoding debug agent-installation fixture")?;
    ensure!(
        is_commit_sha(&fixture.commit_sha),
        "debug agent-installation fixture commit SHA is invalid"
    );
    ensure!(
        fixture.markdown.len() <= MAX_AGENT_MARKDOWN_BYTES,
        "debug agent-installation fixture Markdown exceeds 1MiB"
    );
    let workspace = std::fs::canonicalize(&fixture.workspace_path)
        .context("canonicalizing debug fixture workspace")?;
    ensure!(
        workspace.is_dir(),
        "debug fixture workspace is not a directory"
    );
    let state = daemon_paths
        .pid_file
        .parent()
        .context("daemon pid file has no state directory")?;
    let providers = ProvidersConfig {
        providers: fixture
            .providers
            .into_iter()
            .map(|(profile, provider)| {
                ensure!(
                    !profile.trim().is_empty(),
                    "debug fixture provider profile must not be empty"
                );
                let mut entry = ProviderEntry::default();
                entry.template = provider.template;
                entry.models = provider
                    .models
                    .into_iter()
                    .map(|model| ModelEntry {
                        id: model.id,
                        context_length: model.context_length,
                        capabilities: model.capabilities,
                        ..ModelEntry::default()
                    })
                    .collect();
                Ok((profile, entry))
            })
            .collect::<Result<_>>()?,
        ..ProvidersConfig::default()
    };
    Ok(Some(AgentInstallationService::new(
        db,
        state.join("agents"),
        Arc::new(DebugFixtureFetcher {
            source: FetchedAgentSource {
                commit_sha: fixture.commit_sha,
                markdown: fixture.markdown.into_bytes(),
            },
        }),
        Arc::new(DebugFixtureWorkspaceAuthorizer { workspace }),
        providers,
    )))
}

impl AgentInstallationService {
    pub fn new(
        db: Db,
        daemon_agents_dir: PathBuf,
        fetcher: Arc<dyn AgentInstallationFetcher>,
        workspaces: Arc<dyn AgentWorkspaceAuthorizer>,
        providers: ProvidersConfig,
    ) -> Self {
        Self {
            db,
            daemon_agents_dir,
            fetcher,
            workspaces,
            providers,
        }
    }

    pub async fn begin(
        &self,
        request: AgentInstallationBeginV1,
        now_unix_ms: i64,
    ) -> AgentInstallationResultV1 {
        match self.begin_inner(request, now_unix_ms).await {
            Ok(result) => result,
            Err(error) => redacted_error(error),
        }
    }

    async fn begin_inner(
        &self,
        request: AgentInstallationBeginV1,
        now: i64,
    ) -> Result<AgentInstallationResultV1> {
        ensure!(
            request.dto_version == AGENT_INSTALLATION_DTO_VERSION,
            "unsupported installation DTO version"
        );
        validate_idempotency_key(&request.idempotency_key)?;
        let (workspace_id, workspace_root) = self
            .resolve_scope(request.scope, request.workspace_path.as_deref())
            .await?;
        // Read before fetching so a retry with a durable journal can recover
        // its pinned staged source rather than consulting a mutable ref. For a
        // fresh shared request, an existing file is reconciled (not blindly
        // refused) before any operation/journal/installation mutation.
        let existing_operation = self
            .db
            .installation_operation(request.idempotency_key.clone())
            .await?;
        // A fresh update authorizes its explicit target before it asks a
        // remote source anything (or creates an idempotency row). This makes
        // a wrong scope, workspace, source, or UUID a pure refusal. A replay
        // deliberately skips this branch: its durable operation/journal is
        // the source of truth and a terminal receipt always wins.
        let fresh_update_target = if existing_operation.is_none()
            && request.operation == AgentInstallationOperationKind::Update
        {
            ensure!(
                request.replace_acknowledged,
                "update requires explicit replacement acknowledgement"
            );
            Some(
                self.validate_update_target(&request, workspace_id.as_deref())
                    .await?,
            )
        } else {
            None
        };
        // Parse and fetch all fresh install/update requests before creating an
        // operation. In particular, an invalid manifest must never leave an
        // orphan operation or owned file behind. Nonterminal recovery never
        // enters this branch and instead uses its pinned staged bytes below.
        let fresh_prefetched = if existing_operation.is_none()
            && matches!(
                request.operation,
                AgentInstallationOperationKind::Install | AgentInstallationOperationKind::Update
            ) {
            Some(
                self.prefetch_fresh_source(
                    &request,
                    fresh_update_target
                        .as_ref()
                        .map(|target| target.source_agent_id.as_str()),
                )
                .await?,
            )
        } else {
            None
        };
        let fresh_staged_journal = fresh_prefetched
            .as_ref()
            .map(|fetched| staged_source_journal_metadata(&request.source_locator, fetched))
            .transpose()?;
        if existing_operation.is_none()
            && request.scope == AgentInstallationScopeWire::WorkspaceShared
            && matches!(
                request.operation,
                AgentInstallationOperationKind::Install | AgentInstallationOperationKind::Update
            )
        {
            self.preflight_shared_collision(
                &request,
                workspace_id.as_deref(),
                workspace_root.as_deref(),
                fresh_prefetched
                    .as_ref()
                    .expect("fresh install/update source was prefetched"),
            )
            .await?;
        }
        let fingerprint = request_fingerprint(&request, workspace_id.as_deref());
        let kind = operation_kind(request.operation);
        let begun = match fresh_staged_journal {
            Some((staged_file_metadata_json, expected_digest)) => {
                self.db
                    .begin_installation_operation_with_staged_journal(
                        request.idempotency_key.clone(),
                        fingerprint,
                        kind,
                        workspace_id.clone(),
                        staged_file_metadata_json,
                        expected_digest,
                        now,
                    )
                    .await?
            }
            None => {
                self.db
                    .begin_installation_operation(
                        request.idempotency_key.clone(),
                        fingerprint,
                        kind,
                        workspace_id.clone(),
                        now,
                    )
                    .await?
            }
        };
        let created = match begun {
            BeginInstallationOperation::KeyConflict => {
                bail!("idempotency key was previously used for a different request")
            }
            BeginInstallationOperation::Replay(operation) => {
                if operation.terminal_receipt_json.is_some() {
                    return replay_operation(operation.terminal_receipt_json.as_deref());
                }
                if let Some(continuation) = self
                    .db
                    .installation_continuation_for_operation(operation.operation_id)
                    .await?
                {
                    let choice_set: BindChoiceSet =
                        serde_json::from_str(&continuation.choice_set_json)
                            .context("stored installation choice set is corrupt")?;
                    validate_durable_choice_set(&choice_set)?;
                    if let Some(choice_id) = choice_set.auto_choice_id {
                        ensure!(
                            continuation.submitted_choice_id.as_deref().is_none()
                                || continuation.submitted_choice_id.as_deref()
                                    == Some(choice_id.as_str()),
                            "durable automatic choice was claimed by a different choice"
                        );
                        // A crash can occur after the continuation claim and
                        // before binding or terminalization. Resume this exact
                        // durable selection; never refetch or rerank.
                        return Ok(self
                            .submit_choice(
                                AgentInstallationSubmitChoiceV1 {
                                    dto_version: AGENT_INSTALLATION_DTO_VERSION,
                                    continuation_token: continuation.continuation_token.to_string(),
                                    choice_id: Some(choice_id),
                                    defer: false,
                                },
                                now,
                            )
                            .await);
                    }
                    if operation.state == InstallationOperationState::PendingChoice {
                        return Ok(AgentInstallationResultV1::NeedsChoice {
                            continuation_token: continuation.continuation_token.to_string(),
                            choices: choice_set.choices,
                            unmatched_recommendations: choice_set.unmatched_recommendations,
                            expires_at_unix_ms: continuation.expires_at_unix_ms,
                        });
                    }
                }
                // A crash after durable begin is resumed under the original
                // operation id/fingerprint. The journal below decides which
                // file checkpoint remains; this never creates a second DB
                // binding/snapshot/revision mutation.
                false
            }
            BeginInstallationOperation::Created(_) => true,
        };
        match request.operation {
            AgentInstallationOperationKind::Install | AgentInstallationOperationKind::Update => {
                self.install_or_update(
                    request,
                    workspace_id,
                    workspace_root,
                    now,
                    created.then_some(fresh_update_target).flatten(),
                    created.then_some(fresh_prefetched).flatten(),
                )
                .await
            }
            AgentInstallationOperationKind::Create => {
                self.create(request, workspace_id, workspace_root, now)
                    .await
            }
            AgentInstallationOperationKind::Bind => {
                self.bind_begin(request, workspace_id, workspace_root, now, None, None, None)
                    .await
            }
        }
    }

    pub async fn submit_choice(
        &self,
        request: AgentInstallationSubmitChoiceV1,
        now: i64,
    ) -> AgentInstallationResultV1 {
        let result = async {
            ensure!(
                request.dto_version == AGENT_INSTALLATION_DTO_VERSION,
                "unsupported installation DTO version"
            );
            let token = Uuid::parse_str(&request.continuation_token)
                .context("invalid continuation token")?;
            let state = self
                .db
                .installation_continuation_state(token)
                .await?
                .context("unknown installation continuation")?;
            let mut continuation = state.continuation;
            // A terminal receipt wins every expiry/retry race.  Check it
            // before attempting the continuation CAS so a late submit never
            // manufactures a second outcome.
            let current_operation = state.operation;
            if let Some(receipt) = current_operation.terminal_receipt_json.as_deref() {
                return serde_json::from_str(receipt)
                    .context("stored installation receipt is corrupt");
            }
            let choice_set: BindChoiceSet = serde_json::from_str(&continuation.choice_set_json)
                .context("stored installation choice set is corrupt")?;
            validate_durable_choice_set(&choice_set)?;
            ensure!(
                request.defer ^ request.choice_id.is_some(),
                "submit exactly one installation choice or defer it"
            );
            let submitted_choice = if request.defer {
                "__deferred__"
            } else {
                request
                    .choice_id
                    .as_deref()
                    .context("missing installation choice")?
            };
            if !request.defer {
                // This must happen before either CAS. An unknown choice must
                // never wedge a still-pending continuation as claimed.
                ensure!(
                    choice_set
                        .choices
                        .iter()
                        .any(|choice| choice.choice_id == submitted_choice),
                    "unknown installation choice"
                );
            }
            let operation = if continuation.expires_at_unix_ms <= now {
                let timeout = receipt(
                    continuation.operation_id,
                    AgentInstallationReceiptStatusV1::TimedOut,
                    None,
                    None,
                );
                if let Some(operation) = self
                    .db
                    .expire_installation_continuation(token, now, serde_json::to_string(&timeout)?)
                    .await?
                {
                    return replay_operation(operation.terminal_receipt_json.as_deref());
                }
                let state = self
                    .db
                    .installation_continuation_state(token)
                    .await?
                    .context("installation continuation disappeared")?;
                if let Some(receipt) = state.operation.terminal_receipt_json.as_deref() {
                    return serde_json::from_str(receipt)
                        .context("stored installation receipt is corrupt");
                }
                ensure!(
                    state.continuation.submitted_choice_id.as_deref() == Some(submitted_choice),
                    "continuation expired or was claimed by another choice"
                );
                continuation = state.continuation;
                state.operation
            } else {
                match self
                    .db
                    .claim_installation_continuation(token, submitted_choice.to_owned(), now)
                    .await?
                {
                    Some(operation) => operation,
                    None => {
                        let state = self
                            .db
                            .installation_continuation_state(token)
                            .await?
                            .context("installation continuation disappeared")?;
                        if let Some(receipt) = state.operation.terminal_receipt_json.as_deref() {
                            return serde_json::from_str(receipt)
                                .context("stored installation receipt is corrupt");
                        }
                        ensure!(
                            state.continuation.submitted_choice_id.as_deref()
                                == Some(submitted_choice),
                            "unknown, expired, or already claimed installation choice"
                        );
                        continuation = state.continuation;
                        state.operation
                    }
                }
            };
            let choice_set: BindChoiceSet = serde_json::from_str(&continuation.choice_set_json)
                .context("stored installation choice set is corrupt")?;
            validate_durable_choice_set(&choice_set)?;
            if request.defer {
                let slot_id = choice_set
                    .choices
                    .first()
                    .context("stored choice set has no selectable choices")?
                    .slot_id
                    .as_str();
                let status = if slot_id == "primary" {
                    AgentInstallationReceiptStatusV1::PrimaryUnusable
                } else {
                    AgentInstallationReceiptStatusV1::OptionalUnbound
                };
                let installation_id = Uuid::parse_str(&choice_set.installation_id)
                    .context("stored installation id is invalid")?;
                let receipt = binding_terminal_receipt(
                    operation.operation_id,
                    choice_set.parent_receipt_status,
                    choice_set.parent_source_revision.clone(),
                    status,
                    installation_id,
                );
                self.db
                    .finish_installation_operation(
                        operation.operation_id,
                        serde_json::to_string(&receipt)?,
                        now,
                    )
                    .await?;
                return Ok(receipt);
            }
            let choice = choice_set
                .choices
                .iter()
                .find(|choice| choice.choice_id == submitted_choice)
                .context("submitted installation choice was not offered")?;
            let route = choice_set
                .routes
                .iter()
                .filter(|route| route.choice_id == submitted_choice)
                .collect::<Vec<_>>();
            ensure!(
                route.len() == 1 && !route[0].provider_profile_handle.trim().is_empty(),
                "stored installation choice has no exact daemon-local profile route"
            );
            let installation_id = Uuid::parse_str(&choice_set.installation_id)
                .context("stored installation id is invalid")?;
            let payload = serde_json::to_vec(choice)?;
            let outcome = self
                .db
                .bind_agent_model(
                    installation_id,
                    choice_set.definition_digest,
                    None,
                    operation.operation_id.to_string(),
                    operation.request_fingerprint.clone(),
                    cockpit_db::db::agent_installations::AgentBindingInput {
                        slot_id: choice.slot_id.clone(),
                        provider_profile_handle: route[0].provider_profile_handle.clone(),
                        model_id: choice.model_id.clone(),
                        provenance_digest: sha256_hex(&payload),
                        provenance_payload: payload,
                        hard_capability_verified: true,
                    },
                    now,
                )
                .await?;
            let refusal = terminal_bind_refusal_code(&outcome);
            if let Some(code) = refusal {
                // Claiming a continuation transfers responsibility for a
                // terminal outcome to this operation. A stale or incompatible
                // DB result is not a transport failure: persist the same
                // typed, redacted result before returning so replay, a
                // same-choice CAS loser, and an expiry race can never strand
                // it in `claimed`/`running`.
                let refusal = typed_installation_error(code);
                self.db
                    .finish_installation_operation(
                        operation.operation_id,
                        serde_json::to_string(&refusal)?,
                        now,
                    )
                    .await?;
                return Ok(refusal);
            }
            let receipt = binding_terminal_receipt(
                operation.operation_id,
                choice_set.parent_receipt_status,
                choice_set.parent_source_revision.clone(),
                AgentInstallationReceiptStatusV1::Bound,
                installation_id,
            );
            let json = serde_json::to_string(&receipt)?;
            self.db
                .finish_installation_operation(operation.operation_id, json, now)
                .await?;
            Ok(receipt)
        }
        .await;
        result.unwrap_or_else(redacted_error)
    }

    async fn bind_begin(
        &self,
        request: AgentInstallationBeginV1,
        workspace_id: Option<String>,
        workspace_root: Option<PathBuf>,
        now: i64,
        installed_id: Option<Uuid>,
        parent_receipt_status: Option<AgentInstallationReceiptStatusV1>,
        parent_source_revision: Option<String>,
    ) -> Result<AgentInstallationResultV1> {
        let operation = self
            .db
            .installation_operation(request.idempotency_key.clone())
            .await?
            .context("binding operation was not recorded")?;
        let installation_id = match installed_id {
            Some(id) => id,
            None => Uuid::parse_str(&request.source_locator)
                .context("bind source_locator must be an installation id")?,
        };
        let installation = self
            .db
            .agent_installation(installation_id)
            .await?
            .context("agent installation was not found")?;
        ensure!(
            installation.scope == db_scope(request.scope)
                && installation.canonical_workspace_id == workspace_id,
            "installation does not belong to requested scope"
        );
        let name = installation
            .source_agent_id
            .rsplit('/')
            .next()
            .context("invalid installed agent id")?;
        let target = owned_path(
            &self.daemon_agents_dir,
            workspace_root.as_deref(),
            request.scope,
            name,
        )?;
        ensure_no_reparse_components(target.parent().context("owned target missing parent")?)?;
        reject_reparse_leaf(&target)?;
        let definition = crate::agents::parse_agent(
            std::str::from_utf8(&read_owned_file(
                &target,
                "reading daemon-owned agent definition",
            )?)
            .context("daemon-owned agent definition is not UTF-8")?,
            name,
            target.clone(),
        )
        .context("loading daemon-owned agent definition")?;
        let vnext = definition
            .vnext
            .as_ref()
            .context("installed definition is not vNext")?;
        let slot_id = request.requested_slot.as_deref().unwrap_or("primary");
        let slot = vnext
            .model_slots
            .get(slot_id)
            .context("requested model slot does not exist")?;
        let offerings = self
            .providers
            .providers
            .iter()
            .enumerate()
            .flat_map(|(provider_index, (provider_profile_handle, entry))| {
                let provider_id = entry
                    .template
                    .clone()
                    // A custom-provider map key is a daemon-local profile
                    // handle, not a portable provider identity. It can never
                    // cross the choice DTO, even as a display fallback.
                    .unwrap_or_else(|| format!("configured-provider-{provider_index}"));
                entry
                    .models
                    .iter()
                    .enumerate()
                    .map(
                        move |(model_index, model)| crate::agents::AgentProfileModelOffering {
                            // This is an operation-local opaque display identity,
                            // never a derived profile handle. The durable route
                            // table below retains the only profile mapping.
                            offering_id: format!("offering-{provider_index}-{model_index}"),
                            provider_profile_handle: provider_profile_handle.clone(),
                            provider_id: provider_id.clone(),
                            model_id: model.id.clone(),
                        },
                    )
            })
            .collect::<Vec<_>>();
        let ranked = crate::agents::ranked_compatible_offerings(slot, &offerings, &self.providers);
        if ranked.is_empty() {
            let status = if slot_id == "primary" {
                AgentInstallationReceiptStatusV1::PrimaryUnusable
            } else {
                AgentInstallationReceiptStatusV1::OptionalUnbound
            };
            let receipt = binding_terminal_receipt(
                operation.operation_id,
                parent_receipt_status,
                parent_source_revision.clone(),
                status,
                installation_id,
            );
            self.db
                .finish_installation_operation(
                    operation.operation_id,
                    serde_json::to_string(&receipt)?,
                    now,
                )
                .await?;
            return Ok(receipt);
        }
        let (choices, unmatched_recommendations) = binding_choices(slot_id, slot, &ranked);
        let routes = durable_binding_routes(&ranked, &choices)?;
        let automatic_choice = if request.auto_select_first_exact {
            match first_exact_author_choice(&choices) {
                Some(choice) => Some(choice),
                None => {
                    let status = if slot_id == "primary" {
                        AgentInstallationReceiptStatusV1::PrimaryUnusable
                    } else {
                        AgentInstallationReceiptStatusV1::OptionalUnbound
                    };
                    let receipt = binding_terminal_receipt(
                        operation.operation_id,
                        parent_receipt_status,
                        parent_source_revision.clone(),
                        status,
                        installation_id,
                    );
                    self.db
                        .finish_installation_operation(
                            operation.operation_id,
                            serde_json::to_string(&receipt)?,
                            now,
                        )
                        .await?;
                    return Ok(receipt);
                }
            }
        } else {
            None
        };
        let continuation = self
            .db
            .create_installation_continuation(
                operation.operation_id,
                serde_json::to_string(&BindChoiceSet {
                    installation_id: installation_id.to_string(),
                    definition_digest: installation.source_digest.clone(),
                    choices: choices.clone(),
                    unmatched_recommendations: unmatched_recommendations.clone(),
                    routes,
                    parent_receipt_status,
                    parent_source_revision,
                    auto_choice_id: automatic_choice.clone(),
                })?,
                now + 600_000,
                now,
            )
            .await?;
        if let Some(choice_id) = automatic_choice {
            return Ok(self
                .submit_choice(
                    AgentInstallationSubmitChoiceV1 {
                        dto_version: AGENT_INSTALLATION_DTO_VERSION,
                        continuation_token: continuation.continuation_token.to_string(),
                        choice_id: Some(choice_id),
                        defer: false,
                    },
                    now,
                )
                .await);
        }
        Ok(AgentInstallationResultV1::NeedsChoice {
            continuation_token: continuation.continuation_token.to_string(),
            choices,
            unmatched_recommendations,
            expires_at_unix_ms: continuation.expires_at_unix_ms,
        })
    }

    pub async fn list(&self, request: AgentInstallationReadV1) -> AgentInstallationResultV1 {
        let result = async {
            ensure!(
                request.dto_version == AGENT_INSTALLATION_DTO_VERSION,
                "unsupported installation DTO version"
            );
            let (workspace_id, workspace_root) = self
                .resolve_scope(request.scope, request.workspace_path.as_deref())
                .await?;
            let rows = self
                .db
                .list_agent_installations(db_scope(request.scope), workspace_id.as_deref())
                .await?;
            let mut installations = Vec::with_capacity(rows.len());
            for row in rows {
                installations.push(self.record(row, workspace_root.as_deref()).await?);
            }
            Ok(AgentInstallationResultV1::Listed { installations })
        }
        .await;
        result.unwrap_or_else(redacted_error)
    }

    pub async fn inspect(&self, request: AgentInstallationReadV1) -> AgentInstallationResultV1 {
        let result = async {
            ensure!(
                request.dto_version == AGENT_INSTALLATION_DTO_VERSION,
                "unsupported installation DTO version"
            );
            let (workspace_id, workspace_root) = self
                .resolve_scope(request.scope, request.workspace_path.as_deref())
                .await?;
            let id = request
                .installation_id
                .context("inspect requires installation id")?;
            let installation_id = Uuid::parse_str(&id).context("invalid installation id")?;
            let row = self.db.agent_installation(installation_id).await?;
            let row = row.filter(|row| {
                row.scope == db_scope(request.scope) && row.canonical_workspace_id == workspace_id
            });
            Ok(AgentInstallationResultV1::Inspected {
                installation: match row {
                    Some(row) => Some(self.record(row, workspace_root.as_deref()).await?),
                    None => None,
                },
            })
        }
        .await;
        result.unwrap_or_else(redacted_error)
    }

    async fn validate_update_target(
        &self,
        request: &AgentInstallationBeginV1,
        workspace_id: Option<&str>,
    ) -> Result<AgentInstallationRow> {
        ensure!(
            request.operation == AgentInstallationOperationKind::Update,
            "only update has an installation target"
        );
        let source = CanonicalAgentSource::parse(&request.source_locator)?;
        let installation_id = Uuid::parse_str(
            request
                .target_installation_id
                .as_deref()
                .context("update requires target installation id")?,
        )
        .context("update target installation id is invalid")?;
        let installation = self
            .db
            .agent_installation(installation_id)
            .await?
            .context("update target installation was not found")?;
        ensure!(
            installation.scope == db_scope(request.scope)
                && installation.canonical_workspace_id.as_deref() == workspace_id,
            "update target installation does not belong to requested scope"
        );
        ensure!(
            installation.source_identity == source.identity(),
            "update source does not match target installation provenance"
        );
        Ok(installation)
    }

    /// Validate all immutable source facts that are knowable before an
    /// operation exists. The returned bytes are passed directly to staging so
    /// a valid fresh request fetches exactly once, while an invalid source or
    /// manifest has no durable side effects.
    async fn prefetch_fresh_source(
        &self,
        request: &AgentInstallationBeginV1,
        expected_agent_id: Option<&str>,
    ) -> Result<FetchedAgentSource> {
        let source = CanonicalAgentSource::parse(&request.source_locator)?;
        let name = source
            .markdown_path
            .rsplit('/')
            .next()
            .and_then(|value| value.strip_suffix(".md"))
            .filter(|value| !value.is_empty())
            .context("source Markdown path has no agent filename")?;
        let fetched = self
            .fetcher
            .fetch_github_markdown(&source)
            .await
            .context("fetching GitHub agent source")?;
        ensure!(
            is_commit_sha(&fetched.commit_sha),
            "source fetch did not resolve an immutable commit SHA"
        );
        ensure!(
            fetched.markdown.len() <= MAX_AGENT_MARKDOWN_BYTES,
            "fetched agent Markdown exceeds 1MiB"
        );
        let markdown = std::str::from_utf8(&fetched.markdown)
            .context("fetched agent Markdown is not UTF-8")?;
        let definition =
            crate::agents::parse_agent(markdown, name, PathBuf::from("<daemon-fetched-agent>"))
                .context("invalid fetched AgentDef")?;
        let vnext = definition
            .vnext
            .as_ref()
            .context("installed agent must be a vNext AgentDef")?;
        let defined_name = vnext
            .agent_id
            .rsplit('/')
            .next()
            .context("vNext agent id has no final name")?;
        ensure!(
            defined_name == name,
            "installed AgentDef id must use the source Markdown filename"
        );
        ensure!(
            !crate::agents::is_builtin_agent(defined_name),
            "daemon installation may not impersonate a protected builtin agent"
        );
        if let Some(expected_agent_id) = expected_agent_id {
            ensure!(
                vnext.agent_id == expected_agent_id,
                "update source AgentDef identity does not match target installation"
            );
        }
        Ok(fetched)
    }

    /// A fresh workspace-shared request may touch a user-visible path only
    /// after proving it is absent or byte/provenance-identical. The immutable
    /// source has already been fetched and validated before this check, so
    /// preflight cannot make an invalid manifest durable or refetch a moving
    /// revision.
    async fn preflight_shared_collision(
        &self,
        request: &AgentInstallationBeginV1,
        workspace_id: Option<&str>,
        workspace_root: Option<&Path>,
        fetched: &FetchedAgentSource,
    ) -> Result<()> {
        let source = CanonicalAgentSource::parse(&request.source_locator)?;
        let name = source
            .markdown_path
            .rsplit('/')
            .next()
            .and_then(|value| value.strip_suffix(".md"))
            .filter(|value| !value.is_empty())
            .context("source Markdown path has no agent filename")?;
        let target = owned_path(
            &self.daemon_agents_dir,
            workspace_root,
            AgentInstallationScopeWire::WorkspaceShared,
            name,
        )?;
        ensure_no_reparse_components(target.parent().context("owned target missing parent")?)?;
        reject_reparse_leaf(&target)?;
        if !owned_file_exists(&target, false)? {
            return Ok(());
        }
        ensure!(
            is_commit_sha(&fetched.commit_sha)
                && fetched.markdown.len() <= MAX_AGENT_MARKDOWN_BYTES,
            "shared collision source did not resolve an immutable bounded commit"
        );
        let markdown = std::str::from_utf8(&fetched.markdown)
            .context("shared collision source Markdown is not UTF-8")?;
        let definition = crate::agents::parse_agent(
            markdown,
            name,
            PathBuf::from("<daemon-shared-collision-check>"),
        )?;
        let vnext = definition
            .vnext
            .as_ref()
            .context("shared collision source is not a vNext AgentDef")?;
        let defined_name = vnext
            .agent_id
            .rsplit('/')
            .next()
            .context("shared collision AgentDef has no filename")?;
        ensure!(
            defined_name == name,
            "installed AgentDef id must use the source Markdown filename"
        );
        let definition_digest = sha256_hex(&definition.vnext_digest_bytes()?);
        let exact = target_digest(&target)? == sha256_hex(&fetched.markdown)
            && self
                .db
                .agent_installation_by_source(
                    AgentInstallationScope::WorkspaceShared,
                    workspace_id.map(str::to_owned),
                    vnext.agent_id.clone(),
                )
                .await?
                .is_some_and(|existing| {
                    existing.source_identity == source.identity()
                        && existing.source_revision.as_deref() == Some(fetched.commit_sha.as_str())
                        && existing.source_digest == definition_digest
                });
        ensure!(exact, "dirty shared owned agent file collision");
        Ok(())
    }

    async fn install_or_update(
        &self,
        request: AgentInstallationBeginV1,
        workspace_id: Option<String>,
        workspace_root: Option<PathBuf>,
        now: i64,
        update_target: Option<AgentInstallationRow>,
        prefetched: Option<FetchedAgentSource>,
    ) -> Result<AgentInstallationResultV1> {
        let source = CanonicalAgentSource::parse(&request.source_locator)?;
        let name = source
            .markdown_path
            .rsplit('/')
            .next()
            .and_then(|value| value.strip_suffix(".md"))
            .filter(|value| !value.is_empty())
            .context("source Markdown path has no agent filename")?;
        ensure!(
            !crate::agents::is_builtin_agent(name),
            "daemon installation may not overwrite a protected builtin agent"
        );
        let update_target_id = if request.operation == AgentInstallationOperationKind::Update {
            Some(
                Uuid::parse_str(
                    request
                        .target_installation_id
                        .as_deref()
                        .context("update requires target installation id")?,
                )
                .context("update target installation id is invalid")?,
            )
        } else {
            ensure!(
                request.target_installation_id.is_none(),
                "only update may include a target installation id"
            );
            None
        };
        let operation = self
            .db
            .installation_operation(request.idempotency_key.clone())
            .await?
            .context("installation operation was not recorded")?;
        let target = owned_path(
            &self.daemon_agents_dir,
            workspace_root.as_deref(),
            request.scope,
            name,
        )?;
        ensure_no_reparse_components(target.parent().context("owned target missing parent")?)?;
        reject_reparse_leaf(&target)?;
        let prior_journal = self.db.installation_journal(operation.operation_id).await?;
        // A freshly-created operation already has its immutable source journal
        // (atomically with the operation row), but has not yet observed the
        // owned target. Treat that narrow state like a fresh preflight on a
        // retry; once the observation is persisted, recovery uses it instead
        // of reinterpreting a published file as a new collision.
        let needs_owned_target_preflight = prior_journal.as_ref().is_none_or(|journal| {
            journal.checkpoint == InstallationJournalCheckpoint::Staged
                && journal.prior_file_metadata_json.is_none()
        });
        let fetched = match prior_journal.as_ref().and_then(journal_staged_source) {
            Some(source) => source?,
            None => match prefetched {
                Some(source) => source,
                None => self
                    .fetcher
                    .fetch_github_markdown(&source)
                    .await
                    .context("fetching GitHub agent source")?,
            },
        };
        ensure!(
            is_commit_sha(&fetched.commit_sha),
            "source fetch did not resolve an immutable commit SHA"
        );
        ensure!(
            fetched.markdown.len() <= MAX_AGENT_MARKDOWN_BYTES,
            "fetched agent Markdown exceeds 1MiB"
        );
        let markdown = std::str::from_utf8(&fetched.markdown)
            .context("fetched agent Markdown is not UTF-8")?;
        let definition =
            crate::agents::parse_agent(markdown, name, PathBuf::from("<daemon-fetched-agent>"))
                .context("invalid fetched AgentDef")?;
        ensure!(
            definition.vnext.is_some(),
            "installed agent must be a vNext AgentDef"
        );
        let defined_name = definition
            .vnext
            .as_ref()
            .expect("checked vnext")
            .agent_id
            .rsplit('/')
            .next()
            .context("vNext agent id has no final name")?;
        ensure!(
            defined_name == name,
            "installed AgentDef id must use the source Markdown filename"
        );
        ensure!(
            !crate::agents::is_builtin_agent(defined_name),
            "daemon installation may not impersonate a protected builtin agent"
        );
        if let Some(target) = update_target.as_ref() {
            ensure!(
                definition.vnext.as_ref().expect("checked vnext").agent_id
                    == target.source_agent_id,
                "update source AgentDef identity does not match target installation"
            );
        }
        let digest = sha256_hex(&fetched.markdown);
        let definition_digest = sha256_hex(&definition.vnext_digest_bytes()?);
        // A workspace-shared definition belongs to the workspace, not merely
        // to this daemon.  Detect a hand edit or a competing definition before
        // staging, journaling, or invoking the installation transaction.  The
        // one permitted collision is an exact already-installed copy, which
        // is a no-op even when a caller used a fresh operation key.
        if needs_owned_target_preflight
            && request.scope == AgentInstallationScopeWire::WorkspaceShared
            && owned_file_exists(&target, false)?
        {
            if target_digest(&target)? == digest {
                if let Some(existing) = self
                    .db
                    .agent_installation_by_source(
                        db_scope(request.scope),
                        workspace_id.clone(),
                        definition
                            .vnext
                            .as_ref()
                            .expect("checked vnext")
                            .agent_id
                            .clone(),
                    )
                    .await?
                {
                    if existing.source_identity == source.identity()
                        && existing.source_revision.as_deref() == Some(fetched.commit_sha.as_str())
                        && existing.source_digest == definition_digest
                    {
                        let install_status =
                            if request.operation == AgentInstallationOperationKind::Install {
                                AgentInstallationReceiptStatusV1::Installed
                            } else {
                                AgentInstallationReceiptStatusV1::Updated
                            };
                        let receipt = receipt(
                            operation.operation_id,
                            install_status,
                            Some(existing.installation_id.to_string()),
                            Some(fetched.commit_sha.clone()),
                        );
                        if request.auto_select_first_exact {
                            return self
                                .bind_begin(
                                    request,
                                    workspace_id,
                                    workspace_root,
                                    now,
                                    Some(existing.installation_id),
                                    Some(install_status),
                                    Some(fetched.commit_sha),
                                )
                                .await;
                        }
                        self.db
                            .finish_installation_operation(
                                operation.operation_id,
                                serde_json::to_string(&receipt)?,
                                now,
                            )
                            .await?;
                        return Ok(receipt);
                    }
                }
            }
            bail!("dirty shared owned agent file collision")
        }
        // Replacement is explicit, never permission to overwrite an edited
        // daemon-owned copy. `source_digest` is the canonical complete vNext
        // Markdown digest (including the prompt body), so this catches both
        // frontmatter and body edits before any stage/journal/DB mutation.
        if needs_owned_target_preflight
            && request.replace_acknowledged
            && owned_file_exists(&target, false)?
        {
            let existing = match update_target_id {
                Some(target_id) => self
                    .db
                    .agent_installation(target_id)
                    .await?
                    .context("replacement target installation disappeared")?,
                None => self
                    .db
                    .agent_installation_by_source(
                        db_scope(request.scope),
                        workspace_id.clone(),
                        definition
                            .vnext
                            .as_ref()
                            .expect("checked vnext")
                            .agent_id
                            .clone(),
                    )
                    .await?
                    .context("replacement target installation disappeared")?,
            };
            let current = crate::agents::parse_agent(
                std::str::from_utf8(&read_owned_file(
                    &target,
                    "reading owned agent before replacement",
                )?)
                .context("owned agent before replacement is not UTF-8")?,
                name,
                target.clone(),
            )?;
            let current_digest = sha256_hex(&current.vnext_digest_bytes()?);
            ensure!(
                current_digest == existing.source_digest,
                "dirty shared owned agent file collision"
            );
        }
        if needs_owned_target_preflight
            && owned_file_exists(&target, false)?
            && !request.replace_acknowledged
        {
            bail!("owned agent file collision requires explicit replacement acknowledgement")
        }
        let mut journal = prior_journal.unwrap_or(InstallationJournalRow {
            journal_id: Uuid::new_v4(),
            operation_id: operation.operation_id,
            checkpoint: InstallationJournalCheckpoint::Staged,
            staged_file_metadata_json: Some(serde_json::to_string(&JournalStagedSource {
                target_name: name.to_owned(),
                digest: digest.clone(),
                commit_sha: fetched.commit_sha.clone(),
                markdown_base64: base64::engine::general_purpose::STANDARD
                    .encode(&fetched.markdown),
            })?),
            prior_file_metadata_json: prior_file_metadata(&target, operation.operation_id)?,
            expected_digest: digest.clone(),
        });
        if journal.prior_file_metadata_json.is_none() {
            // This update is intentionally durable before staging: after a
            // crash, recovery can prove whether a user changed the owned
            // target rather than treating a file swap as the original copy.
            journal.prior_file_metadata_json =
                prior_file_metadata(&target, operation.operation_id)?;
            self.db
                .record_installation_journal(journal.clone(), now)
                .await?;
        }
        ensure!(
            journal.expected_digest == digest,
            "recovery source digest changed for the original installation request"
        );
        if checkpoint_rank(journal.checkpoint)
            >= checkpoint_rank(InstallationJournalCheckpoint::DbCommitted)
        {
            if let Some(replacement) = journal_replacement_receipt(&journal).transpose()? {
                if self
                    .db
                    .agent_replacement_is_compensated(replacement)
                    .await?
                {
                    // A prior publish failure was compensated atomically but
                    // the daemon crashed before writing its terminal receipt.
                    // Never repeat the replacement or touch its immutable
                    // historical snapshots during this recovery.
                    rollback_stage(&target, operation.operation_id);
                    discard_prior_backup(&target, operation.operation_id)?;
                    let receipt = receipt(
                        operation.operation_id,
                        AgentInstallationReceiptStatusV1::Refused,
                        None,
                        Some(fetched.commit_sha),
                    );
                    self.db
                        .record_installation_journal(
                            InstallationJournalRow {
                                checkpoint: InstallationJournalCheckpoint::Complete,
                                ..journal
                            },
                            now,
                        )
                        .await?;
                    self.db
                        .finish_installation_operation(
                            operation.operation_id,
                            serde_json::to_string(&receipt)?,
                            now,
                        )
                        .await?;
                    return Ok(receipt);
                }
            }
        }
        if journal.checkpoint == InstallationJournalCheckpoint::Staged {
            stage_file(&target, operation.operation_id, &fetched.markdown)?;
            self.db
                .record_installation_journal(journal.clone(), now)
                .await?;
        }
        if request.replace_acknowledged
            && journal.checkpoint == InstallationJournalCheckpoint::Staged
        {
            ensure!(
                prior_file_is_unchanged(&target, journal.prior_file_metadata_json.as_deref())?,
                "owned agent file changed after replacement was staged"
            );
        }
        let installation_input = AgentInstallationInput {
            installation_id: operation.operation_id,
            scope: db_scope(request.scope),
            canonical_workspace_id: workspace_id,
            source_agent_id: definition
                .vnext
                .as_ref()
                .expect("checked vnext")
                .agent_id
                .clone(),
            source_identity: source.identity(),
            source_revision: Some(fetched.commit_sha.clone()),
            source_digest: definition_digest,
            // The operation creation time is durable. Replays must never
            // substitute their retry clock into replacement provenance.
            fetched_at_unix_ms: operation.created_at_unix_ms,
        };
        // A process can die after replace_agent's atomic DB transaction but
        // before recording DbCommitted. The persisted replacement receipt is
        // the durable generation identity for that narrow window; recognize
        // the exact committed generation before considering any new mutation.
        let committed_replacement = if journal.checkpoint == InstallationJournalCheckpoint::Staged {
            match journal_replacement_receipt(&journal).transpose()? {
                Some(replacement) => {
                    ensure!(
                        replacement.replacement_operation_id == operation.operation_id,
                        "stored replacement receipt belongs to another operation"
                    );
                    (match update_target_id {
                        Some(target_id) => self.db.agent_installation(target_id).await?,
                        None => {
                            self.db
                                .agent_installation_by_source(
                                    installation_input.scope,
                                    installation_input.canonical_workspace_id.clone(),
                                    installation_input.source_agent_id.clone(),
                                )
                                .await?
                        }
                    })
                    .filter(|row| replacement_receipt_matches_committed(row, &replacement))
                }
                None => None,
            }
        } else {
            None
        };
        let installation = if checkpoint_rank(journal.checkpoint)
            >= checkpoint_rank(InstallationJournalCheckpoint::DbCommitted)
        {
            // The journal checkpoint is the replay authority: do not issue a
            // second install/replace transaction after a crash between its DB
            // commit and file publication.
            let row = (match update_target_id {
                Some(target_id) => self.db.agent_installation(target_id).await?,
                None => {
                    self.db
                        .agent_installation_by_source(
                            installation_input.scope,
                            installation_input.canonical_workspace_id.clone(),
                            installation_input.source_agent_id.clone(),
                        )
                        .await?
                }
            })
            .context("DB-committed installation disappeared during recovery")?;
            ensure!(
                row.source_identity == installation_input.source_identity
                    && row.source_revision == installation_input.source_revision
                    && row.source_digest == installation_input.source_digest
                    && row.deleted_at_unix_ms.is_none(),
                "DB-committed installation provenance changed during recovery"
            );
            row
        } else if let Some(row) = committed_replacement {
            row
        } else {
            // Update owns a concrete target id. Do not first ask the generic
            // source-identity insert path to discover a replacement target:
            // that lookup is appropriate only for an unaddressed Install.
            let outcome = match update_target_id {
                Some(_) => InstallAgentOutcome::Conflict,
                None => self.db.install_agent(installation_input.clone()).await?,
            };
            match outcome {
                InstallAgentOutcome::Installed(row)
                | InstallAgentOutcome::AlreadyInstalled(row) => row,
                InstallAgentOutcome::Conflict => {
                    ensure!(
                        request.replace_acknowledged,
                        "agent installation collides with a different installed definition; explicit replacement acknowledgement is required"
                    );
                    let existing = match update_target_id {
                        Some(target_id) => self
                            .db
                            .agent_installation(target_id)
                            .await?
                            .context("replacement target installation disappeared")?,
                        None => self
                            .db
                            .agent_installation_by_source(
                                installation_input.scope,
                                installation_input.canonical_workspace_id.clone(),
                                installation_input.source_agent_id.clone(),
                            )
                            .await?
                            .context("replacement target installation disappeared")?,
                    };
                    let replacement = match journal_replacement_receipt(&journal).transpose()? {
                        Some(receipt) => {
                            ensure!(
                                receipt.installation_id == existing.installation_id
                                    && receipt.replacement_source_identity
                                        == installation_input.source_identity
                                    && receipt.replacement_source_revision
                                        == installation_input.source_revision
                                    && receipt.replacement_source_digest
                                        == installation_input.source_digest
                                    && receipt.replacement_operation_id == operation.operation_id,
                                "stored replacement compensation receipt does not match recovery request"
                            );
                            receipt
                        }
                        None => {
                            self.db
                                .agent_replacement_compensation_receipt(
                                    existing.installation_id,
                                    installation_input.clone(),
                                    operation.created_at_unix_ms,
                                )
                                .await?
                        }
                    };
                    journal.prior_file_metadata_json = Some(with_replacement_receipt(
                        journal.prior_file_metadata_json.as_deref(),
                        &replacement,
                    )?);
                    // Persist the receipt before the replacement transaction.
                    // A DB-committed crash can then restore the exact prior
                    // mutable state without creating a second revision or
                    // binding.
                    self.db
                        .record_installation_journal(journal.clone(), now)
                        .await?;
                    match if let Some(target_id) = update_target_id {
                        self.db
                            .replace_agent_at(
                                target_id,
                                installation_input,
                                operation.created_at_unix_ms,
                            )
                            .await?
                    } else {
                        self.db
                            .replace_agent(installation_input, operation.created_at_unix_ms)
                            .await?
                    } {
                        InstallAgentOutcome::Installed(row)
                        | InstallAgentOutcome::AlreadyInstalled(row) => row,
                        InstallAgentOutcome::Conflict => {
                            bail!("agent installation replacement conflicted")
                        }
                    }
                }
            }
        };
        if let Some(target) = update_target.as_ref() {
            ensure!(
                installation.installation_id == target.installation_id,
                "update source resolves to a different installation"
            );
        }
        if checkpoint_rank(journal.checkpoint)
            < checkpoint_rank(InstallationJournalCheckpoint::DbCommitted)
        {
            self.db
                .record_installation_journal(
                    InstallationJournalRow {
                        checkpoint: InstallationJournalCheckpoint::DbCommitted,
                        ..journal.clone()
                    },
                    now,
                )
                .await?;
        }
        if checkpoint_rank(journal.checkpoint)
            < checkpoint_rank(InstallationJournalCheckpoint::FileRenamed)
        {
            if let Err(error) = publish_stage(
                &target,
                operation.operation_id,
                &digest,
                request.replace_acknowledged,
            ) {
                if let Some(replacement) = journal_replacement_receipt(&journal).transpose()? {
                    ensure!(
                        !owned_file_exists(
                            &prior_backup_path(&target, operation.operation_id)?,
                            false,
                        )?,
                        "publish failed while preserving the prior file backup; recovery must not discard it"
                    );
                    self.db.compensate_agent_replacement(replacement).await?;
                    rollback_stage(&target, operation.operation_id);
                    discard_prior_backup(&target, operation.operation_id)?;
                    let receipt = receipt(
                        operation.operation_id,
                        AgentInstallationReceiptStatusV1::Refused,
                        None,
                        Some(fetched.commit_sha),
                    );
                    self.db
                        .record_installation_journal(
                            InstallationJournalRow {
                                checkpoint: InstallationJournalCheckpoint::Complete,
                                ..journal
                            },
                            now,
                        )
                        .await?;
                    self.db
                        .finish_installation_operation(
                            operation.operation_id,
                            serde_json::to_string(&receipt)?,
                            now,
                        )
                        .await?;
                    return Ok(receipt);
                }
                return Err(error);
            }
            self.db
                .record_installation_journal(
                    InstallationJournalRow {
                        checkpoint: InstallationJournalCheckpoint::FileRenamed,
                        ..journal.clone()
                    },
                    now,
                )
                .await?;
        } else {
            ensure!(
                target_digest(&target)? == digest,
                "published installation file digest changed during recovery"
            );
        }
        let install_status = if request.operation == AgentInstallationOperationKind::Install {
            AgentInstallationReceiptStatusV1::Installed
        } else {
            AgentInstallationReceiptStatusV1::Updated
        };
        let receipt = receipt(
            operation.operation_id,
            install_status,
            Some(installation.installation_id.to_string()),
            Some(fetched.commit_sha.clone()),
        );
        self.db
            .record_installation_journal(
                InstallationJournalRow {
                    checkpoint: InstallationJournalCheckpoint::Complete,
                    ..journal
                },
                now,
            )
            .await?;
        if request.auto_select_first_exact {
            let result = self
                .bind_begin(
                    request,
                    workspace_id,
                    workspace_root,
                    now,
                    Some(installation.installation_id),
                    Some(install_status),
                    Some(fetched.commit_sha),
                )
                .await?;
            discard_prior_backup(&target, operation.operation_id)?;
            return Ok(result);
        }
        self.db
            .finish_installation_operation(
                operation.operation_id,
                serde_json::to_string(&receipt)?,
                now,
            )
            .await?;
        discard_prior_backup(&target, operation.operation_id)?;
        Ok(receipt)
    }

    async fn create(
        &self,
        request: AgentInstallationBeginV1,
        workspace_id: Option<String>,
        workspace_root: Option<PathBuf>,
        now: i64,
    ) -> Result<AgentInstallationResultV1> {
        // Create accepts a declarative identity, never a client filesystem
        // path. The daemon owns both the generated Markdown filename and its
        // destination below the authorized scope root.
        let agent_id = request
            .source_locator
            .strip_prefix("authored/")
            .filter(|name| !name.is_empty() && !name.contains('/'))
            .context("created agent identity must be authored/NAME")?;
        ensure!(
            !agent_id.is_empty()
                && agent_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
            "created agent id is invalid"
        );
        ensure!(
            !crate::agents::is_builtin_agent(agent_id),
            "daemon create may not overwrite a protected builtin agent"
        );
        let operation = self
            .db
            .installation_operation(request.idempotency_key.clone())
            .await?
            .context("installation operation was not recorded")?;
        let execution_kind = request
            .execution_kind
            .context("create requires an explicit execution kind")?;
        let primary_slot = request
            .primary_slot_id
            .as_deref()
            .context("create requires an explicit primary slot id")?;
        ensure!(
            !primary_slot.is_empty()
                && primary_slot.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'-'
                        || byte == b'_'
                }),
            "create primary slot id is invalid"
        );
        let markdown = minimal_template(agent_id, execution_kind, primary_slot);
        let digest = sha256_hex(markdown.as_bytes());
        let definition = crate::agents::parse_agent(
            &markdown,
            agent_id,
            PathBuf::from("<daemon-created-agent>"),
        )?;
        let definition_digest = sha256_hex(&definition.vnext_digest_bytes()?);
        let target = owned_path(
            &self.daemon_agents_dir,
            workspace_root.as_deref(),
            request.scope,
            agent_id,
        )?;
        ensure_no_reparse_components(target.parent().context("owned target missing parent")?)?;
        reject_reparse_leaf(&target)?;
        let prior_journal = self.db.installation_journal(operation.operation_id).await?;
        ensure!(
            prior_journal.is_some() || !owned_file_exists(&target, false)?,
            "agent create collision; refusing to overwrite an owned definition"
        );
        let journal = prior_journal.unwrap_or(InstallationJournalRow {
            journal_id: Uuid::new_v4(),
            operation_id: operation.operation_id,
            checkpoint: InstallationJournalCheckpoint::Staged,
            staged_file_metadata_json: Some(
                serde_json::json!({"target_name": agent_id, "digest": digest}).to_string(),
            ),
            prior_file_metadata_json: None,
            expected_digest: digest.clone(),
        });
        ensure!(
            journal.expected_digest == digest,
            "recovery template digest changed for the original create request"
        );
        if journal.checkpoint == InstallationJournalCheckpoint::Staged {
            stage_file(&target, operation.operation_id, markdown.as_bytes())?;
            self.db
                .record_installation_journal(journal.clone(), now)
                .await?;
        }
        let outcome = self
            .db
            .install_agent(AgentInstallationInput {
                installation_id: operation.operation_id,
                scope: db_scope(request.scope),
                canonical_workspace_id: workspace_id,
                source_agent_id: format!("authored/{agent_id}"),
                source_identity: format!("daemon-create:{agent_id}"),
                source_revision: None,
                source_digest: definition_digest,
                fetched_at_unix_ms: now,
            })
            .await?;
        let installation = match outcome {
            InstallAgentOutcome::Installed(row) | InstallAgentOutcome::AlreadyInstalled(row) => row,
            InstallAgentOutcome::Conflict => {
                rollback_stage(&target, operation.operation_id);
                bail!("agent create collision")
            }
        };
        if checkpoint_rank(journal.checkpoint)
            < checkpoint_rank(InstallationJournalCheckpoint::DbCommitted)
        {
            self.db
                .record_installation_journal(
                    InstallationJournalRow {
                        checkpoint: InstallationJournalCheckpoint::DbCommitted,
                        ..journal.clone()
                    },
                    now,
                )
                .await?;
        }
        if checkpoint_rank(journal.checkpoint)
            < checkpoint_rank(InstallationJournalCheckpoint::FileRenamed)
        {
            publish_stage(&target, operation.operation_id, &digest, false)?;
            self.db
                .record_installation_journal(
                    InstallationJournalRow {
                        checkpoint: InstallationJournalCheckpoint::FileRenamed,
                        ..journal.clone()
                    },
                    now,
                )
                .await?;
        } else {
            ensure!(
                target_digest(&target)? == digest,
                "published create file digest changed during recovery"
            );
        }
        let receipt = receipt(
            operation.operation_id,
            AgentInstallationReceiptStatusV1::Created,
            Some(installation.installation_id.to_string()),
            None,
        );
        self.db
            .record_installation_journal(
                InstallationJournalRow {
                    checkpoint: InstallationJournalCheckpoint::Complete,
                    ..journal
                },
                now,
            )
            .await?;
        self.db
            .finish_installation_operation(
                operation.operation_id,
                serde_json::to_string(&receipt)?,
                now,
            )
            .await?;
        discard_prior_backup(&target, operation.operation_id)?;
        Ok(receipt)
    }

    async fn resolve_scope(
        &self,
        scope: AgentInstallationScopeWire,
        path: Option<&str>,
    ) -> Result<(Option<String>, Option<PathBuf>)> {
        match scope {
            AgentInstallationScopeWire::Global => {
                ensure!(
                    path.is_none(),
                    "global installation must not include workspace path"
                );
                Ok((None, None))
            }
            AgentInstallationScopeWire::WorkspacePrivate
            | AgentInstallationScopeWire::WorkspaceShared => {
                let path = path.context("workspace installation requires workspace path")?;
                let (id, root) = self
                    .workspaces
                    .authorize_workspace(path)
                    .await
                    .context("workspace authorization failed")?;
                ensure!(
                    !id.is_empty(),
                    "workspace authorization returned empty identity"
                );
                Ok((Some(id), Some(root)))
            }
        }
    }

    async fn record(
        &self,
        row: cockpit_db::db::agent_installations::AgentInstallationRow,
        workspace_root: Option<&Path>,
    ) -> Result<AgentInstallationRecordV1> {
        // Shared definitions are portable by construction. Local provider
        // handles, effective bindings, and even their derived status belong
        // to a user's private daemon state and must not appear in a shared
        // list/inspect DTO (including an empty/unbound status inferred here).
        let bindings = if row.scope == AgentInstallationScope::WorkspaceShared {
            Vec::new()
        } else {
            let current_bindings = self
                .db
                .current_agent_bindings(row.installation_id, row.source_digest.clone())
                .await?
                .into_iter()
                .map(|binding| (binding.slot_id, binding.model_id))
                .collect::<std::collections::BTreeMap<_, _>>();
            let name = row
                .source_agent_id
                .rsplit('/')
                .next()
                .context("installed agent id has no filename")?;
            let path = owned_path(
                &self.daemon_agents_dir,
                workspace_root,
                match row.scope {
                    AgentInstallationScope::Global => AgentInstallationScopeWire::Global,
                    AgentInstallationScope::WorkspacePrivate => {
                        AgentInstallationScopeWire::WorkspacePrivate
                    }
                    AgentInstallationScope::WorkspaceShared => unreachable!("shared is handled"),
                },
                name,
            )?;
            let definition = crate::agents::parse_agent(
                std::str::from_utf8(&read_owned_file(&path, "reading installed agent status")?)?,
                name,
                path,
            )?;
            let observed_digest = sha256_hex(&definition.vnext_digest_bytes()?);
            let observation = self.db.agent_observation(row.installation_id).await?;
            let rebind_required = observation.is_none_or(|observation| {
                !observation.reviewed || observation.observed_digest != observed_digest
            });
            definition
                .vnext
                .context("installed agent is not a vNext definition")?
                .model_slots
                .iter()
                .map(|(slot_id, slot)| match current_bindings.get(slot_id) {
                    Some(model_id) => AgentInstallationSlotStatusV1 {
                        slot_id: slot_id.clone(),
                        state: if rebind_required {
                            AgentInstallationSlotBindingStateV1::RebindRequired
                        } else {
                            AgentInstallationSlotBindingStateV1::Bound
                        },
                        model_id: model_id.clone(),
                    },
                    None => AgentInstallationSlotStatusV1 {
                        slot_id: slot_id.clone(),
                        state: if rebind_required {
                            AgentInstallationSlotBindingStateV1::RebindRequired
                        } else if slot_id == "primary"
                            || slot.purpose.eq_ignore_ascii_case("primary")
                        {
                            AgentInstallationSlotBindingStateV1::PrimaryUnusable
                        } else {
                            AgentInstallationSlotBindingStateV1::OptionalUnbound
                        },
                        model_id: String::new(),
                    },
                })
                .collect()
        };
        Ok(AgentInstallationRecordV1 {
            installation_id: row.installation_id.to_string(),
            scope: match row.scope {
                AgentInstallationScope::Global => AgentInstallationScopeWire::Global,
                AgentInstallationScope::WorkspacePrivate => {
                    AgentInstallationScopeWire::WorkspacePrivate
                }
                AgentInstallationScope::WorkspaceShared => {
                    AgentInstallationScopeWire::WorkspaceShared
                }
            },
            source_agent_id: row.source_agent_id,
            source_identity: row.source_identity,
            source_revision: row.source_revision,
            source_digest: row.source_digest,
            installation_revision: row.installation_revision,
            bindings,
        })
    }
}

/// Construct the production daemon coordinator. The state directory is
/// daemon-owned; workspace-shared files are routed below the daemon-authorized
/// workspace root by `owned_path` and never returned over the protocol.
pub fn default_daemon_service(
    db: Db,
    daemon_paths: &crate::daemon::DaemonPaths,
    secret_vault: Arc<crate::secure_key::SecretVault>,
    providers: ProvidersConfig,
    authorized_workspace_roots: Vec<PathBuf>,
) -> Result<AgentInstallationService> {
    let state = daemon_paths
        .pid_file
        .parent()
        .context("daemon pid file has no state directory")?;
    Ok(AgentInstallationService::new(
        db,
        state.join("agents"),
        Arc::new(GithubHttpsAgentFetcher::new(secret_vault)?),
        Arc::new(LocalDaemonWorkspaceAuthorizer::new(
            authorized_workspace_roots,
        )?),
        providers,
    ))
}

fn operation_kind(value: AgentInstallationOperationKind) -> InstallationOperationKind {
    match value {
        AgentInstallationOperationKind::Install => InstallationOperationKind::Install,
        AgentInstallationOperationKind::Update => InstallationOperationKind::Update,
        AgentInstallationOperationKind::Bind => InstallationOperationKind::Bind,
        AgentInstallationOperationKind::Create => InstallationOperationKind::Create,
    }
}
fn db_scope(value: AgentInstallationScopeWire) -> AgentInstallationScope {
    match value {
        AgentInstallationScopeWire::Global => AgentInstallationScope::Global,
        AgentInstallationScopeWire::WorkspacePrivate => AgentInstallationScope::WorkspacePrivate,
        AgentInstallationScopeWire::WorkspaceShared => AgentInstallationScope::WorkspaceShared,
    }
}
fn request_fingerprint(request: &AgentInstallationBeginV1, workspace: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!(
        "v{}:{:?}:{:?}:{}:{}:{}:{}:{}",
        request.dto_version,
        request.operation,
        request.scope,
        workspace.unwrap_or(""),
        request.source_locator,
        request.target_installation_id.as_deref().unwrap_or(""),
        request.replace_acknowledged,
        request.requested_slot.as_deref().unwrap_or("")
    ));
    hasher.update(format!(
        ":{:?}:{}:{}",
        request.execution_kind,
        request.primary_slot_id.as_deref().unwrap_or(""),
        request.auto_select_first_exact,
    ));
    format!("{:x}", hasher.finalize())
}
fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn is_commit_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn validate_idempotency_key(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= 256,
        "invalid idempotency key"
    );
    Ok(())
}
fn owned_path(
    global: &Path,
    workspace: Option<&Path>,
    scope: AgentInstallationScopeWire,
    name: &str,
) -> Result<PathBuf> {
    ensure!(
        !name.contains('/') && !name.contains('\\') && !name.is_empty(),
        "invalid agent filename"
    );
    Ok(match scope {
        AgentInstallationScopeWire::Global => global.join(format!("{name}.md")),
        // Workspace-private definitions are daemon-owned state, not a
        // workspace file.  The daemon-authorized path only contributes a
        // stable opaque directory key and is never serialized or returned.
        AgentInstallationScopeWire::WorkspacePrivate => global
            .join("private")
            .join(sha256_hex(
                workspace
                    .context("missing workspace root")?
                    .to_string_lossy()
                    .as_bytes(),
            ))
            .join(format!("{name}.md")),
        AgentInstallationScopeWire::WorkspaceShared => workspace
            .context("missing workspace root")?
            .join(".cockpit/agents")
            .join(format!("{name}.md")),
    })
}
fn stage_path(target: &Path, operation: Uuid) -> Result<PathBuf> {
    let filename = target
        .file_name()
        .context("owned target missing filename")?
        .to_string_lossy();
    Ok(target.with_file_name(format!(".{filename}.{operation}.staged")))
}
fn stage_file(target: &Path, operation: Uuid, bytes: &[u8]) -> Result<()> {
    let staged = stage_path(target, operation)?;
    if owned_file_exists(&staged, true)? {
        ensure!(
            target_digest(&staged)? == sha256_hex(bytes),
            "existing staged agent definition differs from durable source"
        );
        return Ok(());
    }
    write_staged_nofollow(&staged, bytes)?;
    Ok(())
}
fn prior_backup_path(target: &Path, operation: Uuid) -> Result<PathBuf> {
    let filename = target
        .file_name()
        .context("owned target missing filename")?
        .to_string_lossy();
    Ok(target.with_file_name(format!(".{filename}.{operation}.prior")))
}
fn publish_stage(
    target: &Path,
    operation: Uuid,
    expected_digest: &str,
    replace: bool,
) -> Result<()> {
    let staged = stage_path(target, operation)?;
    ensure_no_reparse_components(target.parent().context("owned target missing parent")?)?;
    reject_reparse_leaf(&staged)?;
    reject_reparse_leaf(target)?;
    let bytes = read_owned_file(&staged, "reading staged daemon-owned agent definition")?;
    ensure!(
        sha256_hex(&bytes) == expected_digest,
        "staged agent digest changed before publish"
    );
    let backup = prior_backup_path(target, operation)?;
    reject_reparse_leaf(&backup)?;
    if owned_file_exists(target, false)? {
        if owned_file_exists(&backup, false)? && target_digest(target)? == expected_digest {
            return Ok(());
        }
        ensure!(
            !owned_file_exists(&backup, false)?,
            "owned prior backup name is already occupied"
        );
        ensure!(
            replace,
            "owned agent file became dirty/collided before publish"
        );
        rename_owned_file(target, &backup)
            .context("backing up prior daemon-owned agent definition")?;
    };
    if let Err(error) = rename_owned_file(&staged, target) {
        if owned_file_exists(&backup, false)? {
            ensure!(
                !owned_file_exists(target, false)?,
                "publish failed after creating an unexpected target; preserving prior backup"
            );
            rename_owned_file(&backup, target)
                .context("restoring prior daemon-owned agent definition after publish failure")?;
        }
        return Err(error).context("publishing daemon-owned agent definition");
    }
    Ok(())
}

fn ensure_no_reparse_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                let reparse = metadata.file_type().is_symlink()
                    || cfg!(windows) && {
                        #[cfg(windows)]
                        {
                            use std::os::windows::fs::MetadataExt;
                            metadata.file_attributes() & 0x400 != 0
                        }
                        #[cfg(not(windows))]
                        {
                            false
                        }
                    };
                ensure!(
                    !reparse,
                    "agent installation path contains a symlink or reparse point"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error).context("inspecting agent installation path"),
        }
    }
    Ok(())
}

fn reject_reparse_leaf(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let reparse = metadata.file_type().is_symlink()
                || cfg!(windows) && {
                    #[cfg(windows)]
                    {
                        use std::os::windows::fs::MetadataExt;
                        metadata.file_attributes() & 0x400 != 0
                    }
                    #[cfg(not(windows))]
                    {
                        false
                    }
                };
            ensure!(
                !reparse,
                "agent installation file is a symlink or reparse point"
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspecting agent installation file"),
    }
    Ok(())
}

fn write_staged_nofollow(path: &Path, bytes: &[u8]) -> Result<()> {
    write_owned_file_new(path, bytes, "creating no-follow staged agent definition")
}

#[cfg(unix)]
fn owned_parent(path: &Path, create: bool) -> Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let parent = path.parent().context("owned target missing parent")?;
    let root = CString::new("/").expect("literal has no NUL");
    // SAFETY: root is a valid NUL-terminated path and the returned descriptor
    // is immediately owned by File. Every descendant is opened relative to
    // that held descriptor with O_NOFOLLOW, so a pathname swap cannot redirect
    // a later read/write/rename outside the inspected directory identity.
    let root_fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    ensure!(
        root_fd >= 0,
        "opening filesystem root for owned agent path failed"
    );
    // SAFETY: open returned a unique owned descriptor above.
    let mut current = unsafe { std::fs::File::from_raw_fd(root_fd) };
    for component in parent.components() {
        use std::path::Component;
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => {
                let name =
                    CString::new(name.as_bytes()).context("owned agent path contains NUL")?;
                // SAFETY: current is a held directory descriptor and name is a
                // NUL-terminated single component (never an absolute path).
                let mut next = unsafe {
                    libc::openat(
                        std::os::fd::AsRawFd::as_raw_fd(&current),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    )
                };
                if next < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound
                    && create
                {
                    // SAFETY: mkdirat is anchored to the held parent and name
                    // is a validated one-component relative pathname.
                    let created = unsafe {
                        libc::mkdirat(
                            std::os::fd::AsRawFd::as_raw_fd(&current),
                            name.as_ptr(),
                            0o700,
                        )
                    };
                    if created < 0
                        && std::io::Error::last_os_error().kind()
                            != std::io::ErrorKind::AlreadyExists
                    {
                        return Err(std::io::Error::last_os_error())
                            .context("creating owned agent directory");
                    }
                    // SAFETY: same held parent/name as above.
                    next = unsafe {
                        libc::openat(
                            std::os::fd::AsRawFd::as_raw_fd(&current),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                        )
                    };
                }
                ensure!(
                    next >= 0,
                    "opening owned agent directory without following links failed"
                );
                // SAFETY: openat returned a unique owned descriptor.
                current = unsafe { std::fs::File::from_raw_fd(next) };
            }
            Component::ParentDir | Component::Prefix(_) => {
                bail!("owned agent path contains an unsupported component")
            }
        }
    }
    Ok(current)
}

#[cfg(unix)]
fn owned_leaf(path: &Path) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    let leaf = path
        .file_name()
        .context("owned agent path has no filename")?;
    std::ffi::CString::new(leaf.as_bytes()).context("owned agent filename contains NUL")
}

#[cfg(unix)]
fn owned_file_exists(path: &Path, create_parent: bool) -> Result<bool> {
    use std::os::fd::AsRawFd;
    let parent = match owned_parent(path, create_parent) {
        Ok(parent) => parent,
        Err(error) if !create_parent => {
            match std::fs::symlink_metadata(path.parent().context("owned target missing parent")?) {
                Err(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(false);
                }
                _ => return Err(error),
            }
        }
        Err(error) => return Err(error),
    };
    let leaf = owned_leaf(path)?;
    // SAFETY: held directory descriptor plus a one-component NUL pathname.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result < 0 {
        return match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::NotFound => Ok(false),
            _ => Err(std::io::Error::last_os_error()).context("inspecting owned agent file"),
        };
    }
    ensure!(
        stat.st_mode & libc::S_IFMT == libc::S_IFREG,
        "owned agent file is not a regular non-link file"
    );
    Ok(true)
}

#[cfg(unix)]
fn read_owned_file(path: &Path, context: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    let parent = owned_parent(path, false)?;
    let leaf = owned_leaf(path)?;
    // SAFETY: held directory descriptor plus a one-component NUL pathname.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    ensure!(fd >= 0, "{context}");
    // SAFETY: openat returned a unique owned descriptor.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata().context(context)?;
    ensure!(metadata.is_file(), "owned agent file is not regular");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).context(context)?;
    Ok(bytes)
}

#[cfg(unix)]
fn write_owned_file_new(path: &Path, bytes: &[u8], context: &str) -> Result<()> {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    let parent = owned_parent(path, true)?;
    let leaf = owned_leaf(path)?;
    // SAFETY: held directory descriptor plus a one-component NUL pathname.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    ensure!(fd >= 0, "{context}");
    // SAFETY: openat returned a unique owned descriptor.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(bytes).context(context)?;
    file.sync_all().context("syncing owned agent definition")?;
    Ok(())
}

#[cfg(unix)]
fn rename_owned_file(from: &Path, to: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;
    ensure!(
        from.parent() == to.parent(),
        "owned agent rename must stay within one held directory"
    );
    let parent = owned_parent(from, false)?;
    let from = owned_leaf(from)?;
    let to = owned_leaf(to)?;
    // `linkat` + `unlinkat` is a no-replace move for regular files. Unlike
    // renameat, it cannot overwrite a path an attacker creates after our
    // held-directory inspection; both names remain relative to one FD.
    // SAFETY: both names are one-component paths resolved by the held FD.
    let linked = unsafe {
        libc::linkat(
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            0,
        )
    };
    ensure!(
        linked == 0,
        "publishing owned agent file would overwrite an existing path"
    );
    // SAFETY: same held descriptor and one-component source name as above.
    let removed = unsafe { libc::unlinkat(parent.as_raw_fd(), from.as_ptr(), 0) };
    ensure!(removed == 0, "removing moved owned agent file failed");
    Ok(())
}

#[cfg(unix)]
fn remove_owned_file(path: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;
    let parent = owned_parent(path, false)?;
    let leaf = owned_leaf(path)?;
    // SAFETY: held directory descriptor plus a one-component NUL pathname.
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), leaf.as_ptr(), 0) };
    ensure!(result == 0, "removing owned agent file failed");
    Ok(())
}

// Windows has no openat equivalent in Win32.  Use NtCreateFile's RootDirectory
// with OBJ_DONT_REPARSE instead: every component and leaf is resolved from a
// still-held parent handle, never by re-walking the diagnostic path.
#[cfg(windows)]
mod held_windows_agent_files {
    use std::ffi::{OsStr, c_void};
    use std::io::{Read, Write};
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use std::path::{Component, Path, Prefix};
    use std::{fs::File, ptr};

    use anyhow::{Context, Result, bail, ensure};

    type Handle = *mut c_void;
    const INVALID_HANDLE: Handle = -1_isize as Handle;
    const OBJ_CASE_INSENSITIVE: u32 = 0x40;
    const OBJ_DONT_REPARSE: u32 = 0x1000;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const DELETE: u32 = 0x0001_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const FILE_SHARE_ALL: u32 = 0x7;
    const FILE_OPEN: u32 = 1;
    const FILE_CREATE: u32 = 2;
    const FILE_DIRECTORY_FILE: u32 = 0x1;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
    const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const OPEN_EXISTING: u32 = 3;
    const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: Handle,
        object_name: *const UnicodeString,
        attributes: u32,
        security_descriptor: *mut c_void,
        security_quality_of_service: *mut c_void,
    }
    #[repr(C)]
    struct IoStatusBlock {
        status: isize,
        information: usize,
    }
    #[repr(C)]
    struct ByHandleFileInformation {
        attributes: u32,
        creation_low: u32,
        creation_high: u32,
        access_low: u32,
        access_high: u32,
        write_low: u32,
        write_high: u32,
        volume_serial: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }
    #[repr(C)]
    struct FileRenameInformation {
        replace_if_exists: u8,
        root_directory: Handle,
        file_name_length: u32,
        file_name: [u16; 1],
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtCreateFile(
            file: *mut Handle,
            access: u32,
            attributes: *const ObjectAttributes,
            io: *mut IoStatusBlock,
            allocation: *const i64,
            file_attributes: u32,
            share: u32,
            disposition: u32,
            options: u32,
            ea: *const c_void,
            ea_len: u32,
        ) -> i32;
        fn NtSetInformationFile(
            file: Handle,
            io: *mut IoStatusBlock,
            information: *const c_void,
            length: u32,
            class: u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *mut c_void,
            creation: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn GetFileInformationByHandle(
            file: Handle,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }

    fn wide_component(value: &OsStr) -> Result<Vec<u16>> {
        let value = value.encode_wide().collect::<Vec<_>>();
        ensure!(
            !value.is_empty() && value.len() <= u16::MAX as usize / 2,
            "invalid Windows owned path component"
        );
        Ok(value)
    }
    fn verify_directory(file: &File) -> Result<()> {
        let mut info = unsafe { std::mem::zeroed::<ByHandleFileInformation>() };
        ensure!(
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } != 0,
            "querying held Windows directory identity failed"
        );
        ensure!(
            info.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 && file.metadata()?.is_dir(),
            "held Windows agent directory is a reparse point or not a directory"
        );
        Ok(())
    }
    fn verify_file(file: &File) -> Result<()> {
        let mut info = unsafe { std::mem::zeroed::<ByHandleFileInformation>() };
        ensure!(
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } != 0,
            "querying held Windows file identity failed"
        );
        ensure!(
            info.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 && file.metadata()?.is_file(),
            "held Windows agent file is a reparse point or not regular"
        );
        Ok(())
    }
    fn open_relative(
        parent: &File,
        name: &[u16],
        disposition: u32,
        kind: u32,
        access: u32,
    ) -> std::result::Result<File, i32> {
        let mut name = name.to_vec();
        let unicode = UnicodeString {
            length: (name.len() * 2) as u16,
            maximum_length: (name.len() * 2) as u16,
            buffer: name.as_mut_ptr(),
        };
        let attributes = ObjectAttributes {
            length: size_of::<ObjectAttributes>() as u32,
            root_directory: parent.as_raw_handle(),
            object_name: &unicode,
            attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        };
        let mut io = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let mut raw = ptr::null_mut();
        let status = unsafe {
            NtCreateFile(
                &mut raw,
                access,
                &attributes,
                &mut io,
                ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_ALL,
                disposition,
                kind | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                ptr::null(),
                0,
            )
        };
        if status < 0 || raw.is_null() {
            Err(status)
        } else {
            Ok(unsafe { File::from_raw_handle(raw) })
        }
    }
    fn parent(path: &Path, create: bool) -> Result<File> {
        let mut components = path
            .parent()
            .context("owned target missing parent")?
            .components();
        let drive = match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
                _ => bail!("owned Windows agent path must use a local drive"),
            },
            _ => bail!("owned Windows agent path must be absolute"),
        };
        ensure!(
            matches!(components.next(), Some(Component::RootDir)),
            "owned Windows agent path must be rooted"
        );
        let root = format!("{}:\\", char::from(drive));
        let root = OsStr::new(&root)
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let raw = unsafe {
            CreateFileW(
                root.as_ptr(),
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_ALL,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        ensure!(
            raw != INVALID_HANDLE,
            "opening held Windows volume root failed"
        );
        let mut current = unsafe { File::from_raw_handle(raw) };
        verify_directory(&current)?;
        for component in components {
            let Component::Normal(name) = component else {
                bail!("owned Windows agent path contains an unsupported component")
            };
            let name = wide_component(name)?;
            let next = match open_relative(
                &current,
                &name,
                FILE_OPEN,
                FILE_DIRECTORY_FILE,
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            ) {
                Ok(file) => file,
                Err(STATUS_OBJECT_NAME_NOT_FOUND) if create => open_relative(
                    &current,
                    &name,
                    FILE_CREATE,
                    FILE_DIRECTORY_FILE,
                    GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                )
                .map_err(|status| {
                    anyhow::anyhow!(
                        "creating held Windows agent directory failed with NTSTATUS {status:#x}"
                    )
                })?,
                Err(status) => {
                    bail!("opening held Windows agent directory failed with NTSTATUS {status:#x}")
                }
            };
            verify_directory(&next)?;
            current = next;
        }
        Ok(current)
    }
    fn leaf(path: &Path) -> Result<Vec<u16>> {
        wide_component(
            path.file_name()
                .context("owned Windows agent path has no filename")?,
        )
    }
    pub fn exists(path: &Path, create_parent: bool) -> Result<bool> {
        let parent = parent(path, create_parent)?;
        match open_relative(
            &parent,
            &leaf(path)?,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        ) {
            Ok(file) => {
                verify_file(&file)?;
                Ok(true)
            }
            Err(STATUS_OBJECT_NAME_NOT_FOUND) => Ok(false),
            Err(status) => {
                bail!("opening held Windows agent file failed with NTSTATUS {status:#x}")
            }
        }
    }
    pub fn read(path: &Path, context: &str) -> Result<Vec<u8>> {
        let parent = parent(path, false)?;
        let mut file = open_relative(
            &parent,
            &leaf(path)?,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        )
        .map_err(|status| anyhow::anyhow!("{context}: NTSTATUS {status:#x}"))?;
        verify_file(&file)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).context(context)?;
        Ok(bytes)
    }
    pub fn create(path: &Path, bytes: &[u8], context: &str) -> Result<()> {
        let parent = parent(path, true)?;
        let mut file = open_relative(
            &parent,
            &leaf(path)?,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE,
            GENERIC_WRITE | GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        )
        .map_err(|status| anyhow::anyhow!("{context}: NTSTATUS {status:#x}"))?;
        verify_file(&file)?;
        file.write_all(bytes).context(context)?;
        file.sync_all()
            .context("syncing owned Windows agent definition")?;
        Ok(())
    }
    pub fn rename(from: &Path, to: &Path) -> Result<()> {
        ensure!(
            from.parent() == to.parent(),
            "owned Windows agent rename must stay within one held directory"
        );
        let parent = parent(from, false)?;
        let source = open_relative(
            &parent,
            &leaf(from)?,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            GENERIC_READ | GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        )
        .map_err(|status| {
            anyhow::anyhow!("opening held Windows rename source failed with NTSTATUS {status:#x}")
        })?;
        verify_file(&source)?;
        let target = leaf(to)?;
        let offset = std::mem::offset_of!(FileRenameInformation, file_name);
        let mut buffer = vec![0u8; offset + target.len() * 2];
        unsafe {
            let info = buffer.as_mut_ptr().cast::<FileRenameInformation>();
            (*info).replace_if_exists = 0;
            (*info).root_directory = parent.as_raw_handle();
            (*info).file_name_length = (target.len() * 2) as u32;
            ptr::copy_nonoverlapping(
                target.as_ptr().cast::<u8>(),
                buffer.as_mut_ptr().add(offset),
                target.len() * 2,
            );
        }
        let mut io = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let status = unsafe {
            NtSetInformationFile(
                source.as_raw_handle(),
                &mut io,
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                10,
            )
        };
        ensure!(
            status >= 0,
            "held Windows no-replace agent rename failed with NTSTATUS {status:#x}"
        );
        Ok(())
    }
    pub fn remove(path: &Path) -> Result<()> {
        let parent = parent(path, false)?;
        let file = open_relative(
            &parent,
            &leaf(path)?,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        )
        .map_err(|status| {
            anyhow::anyhow!("opening held Windows removal target failed with NTSTATUS {status:#x}")
        })?;
        verify_file(&file)?;
        #[repr(C)]
        struct Disposition {
            delete_file: u8,
        }
        let value = Disposition { delete_file: 1 };
        let mut io = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let status = unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut io,
                (&raw const value).cast(),
                size_of::<Disposition>() as u32,
                13,
            )
        };
        ensure!(
            status >= 0,
            "held Windows agent removal failed with NTSTATUS {status:#x}"
        );
        Ok(())
    }
}

#[cfg(windows)]
fn owned_file_exists(path: &Path, create_parent: bool) -> Result<bool> {
    held_windows_agent_files::exists(path, create_parent)
}
#[cfg(windows)]
fn read_owned_file(path: &Path, context: &str) -> Result<Vec<u8>> {
    held_windows_agent_files::read(path, context)
}
#[cfg(windows)]
fn write_owned_file_new(path: &Path, bytes: &[u8], context: &str) -> Result<()> {
    held_windows_agent_files::create(path, bytes, context)
}
#[cfg(windows)]
fn rename_owned_file(from: &Path, to: &Path) -> Result<()> {
    held_windows_agent_files::rename(from, to)
}
#[cfg(windows)]
fn remove_owned_file(path: &Path) -> Result<()> {
    held_windows_agent_files::remove(path)
}

#[cfg(all(not(unix), not(windows)))]
fn owned_file_exists(path: &Path, _create_parent: bool) -> Result<bool> {
    ensure_no_reparse_components(path.parent().context("owned target missing parent")?)?;
    reject_reparse_leaf(path)?;
    Ok(path.exists())
}

#[cfg(all(not(unix), not(windows)))]
fn read_owned_file(path: &Path, context: &str) -> Result<Vec<u8>> {
    ensure!(owned_file_exists(path, false)?, "{context}");
    std::fs::read(path).context(context)
}

#[cfg(all(not(unix), not(windows)))]
fn write_owned_file_new(path: &Path, bytes: &[u8], context: &str) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    std::fs::create_dir_all(path.parent().context("owned target missing parent")?)?;
    let mut file = options.open(path).context(context)?;
    use std::io::Write;
    file.write_all(bytes).context(context)?;
    file.sync_all().context("syncing owned agent definition")?;
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn rename_owned_file(from: &Path, to: &Path) -> Result<()> {
    ensure!(
        owned_file_exists(from, false)?,
        "owned source file disappeared"
    );
    ensure_no_reparse_components(to.parent().context("owned target missing parent")?)?;
    reject_reparse_leaf(to)?;
    std::fs::hard_link(from, to).context("publishing owned agent file without replacement")?;
    std::fs::remove_file(from).context("removing moved owned agent file")
}

#[cfg(all(not(unix), not(windows)))]
fn remove_owned_file(path: &Path) -> Result<()> {
    ensure!(owned_file_exists(path, false)?, "owned file disappeared");
    std::fs::remove_file(path).context("removing owned agent file")
}
fn rollback_stage(target: &Path, operation: Uuid) {
    if let Ok(staged) = stage_path(target, operation) {
        let _ = remove_owned_file(&staged);
    }
}
fn prior_file_metadata(path: &Path, operation: Uuid) -> Result<Option<String>> {
    if !owned_file_exists(path, false)? {
        return Ok(Some(serde_json::json!({"present": false}).to_string()));
    };
    let bytes = read_owned_file(path, "reading existing owned agent file")?;
    Ok(Some(serde_json::json!({"present": true, "digest": sha256_hex(&bytes), "backup_name": prior_backup_path(path, operation)?.file_name().and_then(|name| name.to_str()).unwrap_or_default()}).to_string()))
}

fn with_replacement_receipt(
    prior_file_metadata_json: Option<&str>,
    receipt: &AgentReplacementCompensationReceipt,
) -> Result<String> {
    let mut metadata = prior_file_metadata_json
        .map(serde_json::from_str::<serde_json::Value>)
        .transpose()
        .context("decoding prior file metadata before replacement")?
        .unwrap_or_else(|| serde_json::json!({}));
    let object = metadata
        .as_object_mut()
        .context("prior file metadata must be a JSON object")?;
    object.insert(
        "replacement_compensation_receipt".into(),
        serde_json::to_value(receipt).context("encoding replacement compensation receipt")?,
    );
    serde_json::to_string(&metadata).context("encoding replacement file metadata")
}

fn journal_replacement_receipt(
    journal: &InstallationJournalRow,
) -> Option<Result<AgentReplacementCompensationReceipt>> {
    let metadata = journal.prior_file_metadata_json.as_deref()?;
    let parsed = match serde_json::from_str::<serde_json::Value>(metadata) {
        Ok(value) => value,
        Err(error) => return Some(Err(error).context("decoding prior file metadata")),
    };
    parsed
        .get("replacement_compensation_receipt")
        .cloned()
        .map(|value| {
            serde_json::from_value(value).context("decoding replacement compensation receipt")
        })
}

fn replacement_receipt_matches_committed(
    row: &cockpit_db::db::agent_installations::AgentInstallationRow,
    receipt: &AgentReplacementCompensationReceipt,
) -> bool {
    row.installation_id == receipt.installation_id
        && row.source_identity == receipt.replacement_source_identity
        && row.source_revision == receipt.replacement_source_revision
        && row.source_digest == receipt.replacement_source_digest
        && row.fetched_at_unix_ms == receipt.replacement_fetched_at_unix_ms
        && row.installation_revision == receipt.prior_installation_revision + 1
        && row.deleted_at_unix_ms.is_none()
}

fn discard_prior_backup(target: &Path, operation: Uuid) -> Result<()> {
    let backup = prior_backup_path(target, operation)?;
    if owned_file_exists(&backup, false)? {
        remove_owned_file(&backup).context("removing committed prior agent backup")?;
    }
    Ok(())
}
fn prior_file_is_unchanged(path: &Path, metadata: Option<&str>) -> Result<bool> {
    let Some(metadata) = metadata else {
        return Ok(!owned_file_exists(path, false)?);
    };
    let parsed = serde_json::from_str::<serde_json::Value>(metadata).ok();
    if parsed
        .as_ref()
        .and_then(|value| value.get("present"))
        .and_then(serde_json::Value::as_bool)
        == Some(false)
    {
        return Ok(!owned_file_exists(path, false)?);
    }
    let expected = parsed.and_then(|value| {
        value
            .get("digest")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    });
    Ok(expected.is_some_and(|expected| {
        owned_file_exists(path, false).unwrap_or(false)
            && target_digest(path)
                .map(|actual| actual == expected)
                .unwrap_or(false)
    }))
}
fn target_digest(path: &Path) -> Result<String> {
    Ok(sha256_hex(&read_owned_file(
        path,
        "reading published daemon-owned agent definition",
    )?))
}

/// Build the redacted immutable journal payload before the DB transaction
/// creates an operation. The source was already fully fetched and parsed; the
/// transaction below persists this exact SHA/byte sequence alongside the
/// operation so a crash cannot make a same-key retry consult a moving ref.
fn staged_source_journal_metadata(
    source_locator: &str,
    fetched: &FetchedAgentSource,
) -> Result<(String, String)> {
    let source = CanonicalAgentSource::parse(source_locator)?;
    let target_name = source
        .markdown_path
        .rsplit('/')
        .next()
        .and_then(|value| value.strip_suffix(".md"))
        .filter(|value| !value.is_empty())
        .context("source Markdown path has no agent filename")?;
    let digest = sha256_hex(&fetched.markdown);
    let metadata = serde_json::to_string(&JournalStagedSource {
        target_name: target_name.to_owned(),
        digest: digest.clone(),
        commit_sha: fetched.commit_sha.clone(),
        markdown_base64: base64::engine::general_purpose::STANDARD.encode(&fetched.markdown),
    })?;
    Ok((metadata, digest))
}
fn checkpoint_rank(value: InstallationJournalCheckpoint) -> u8 {
    match value {
        InstallationJournalCheckpoint::Staged => 0,
        InstallationJournalCheckpoint::DbCommitted => 1,
        InstallationJournalCheckpoint::FileRenamed => 2,
        InstallationJournalCheckpoint::Complete => 3,
    }
}

/// Recover the exact staged source before contacting a mutable ref again. The
/// journal stores only bounded Markdown bytes and an immutable resolved SHA;
/// credentials, URLs, workspace paths, and provider routes never enter it.
fn journal_staged_source(row: &InstallationJournalRow) -> Option<Result<FetchedAgentSource>> {
    let metadata = row.staged_file_metadata_json.as_deref()?;
    let decoded: JournalStagedSource = match serde_json::from_str(metadata) {
        Ok(value) => value,
        // Old/no-content test fixtures deliberately exercise the fetch path.
        Err(_) => return None,
    };
    Some((|| {
        ensure!(
            is_commit_sha(&decoded.commit_sha)
                && decoded.digest.len() == 64
                && !decoded.target_name.is_empty(),
            "stored staged source metadata is invalid"
        );
        let markdown = base64::engine::general_purpose::STANDARD
            .decode(decoded.markdown_base64)
            .context("decoding staged source Markdown")?;
        ensure!(
            markdown.len() <= MAX_AGENT_MARKDOWN_BYTES && sha256_hex(&markdown) == decoded.digest,
            "stored staged source digest is invalid"
        );
        Ok(FetchedAgentSource {
            commit_sha: decoded.commit_sha,
            markdown,
        })
    })())
}

/// Materialize a binding choice for every documented author-recommendation /
/// local-offering collision.  Do not collapse two author recommendations that
/// happen to name the same local offering: each has different provenance and
/// remains independently reviewable.  Conversely, an upstream identity is
/// display metadata only; exact `(provider_id, model_id)` aliases are the
/// sole matching mechanism.
fn binding_choices(
    slot_id: &str,
    slot: &crate::agents::ModelSlot,
    compatible: &[crate::agents::AgentProfileModelOffering],
) -> (
    Vec<AgentInstallationChoiceV1>,
    Vec<AgentInstallationUnmatchedRecommendationV1>,
) {
    let mut choices = Vec::new();
    let mut unmatched = Vec::new();
    let mut exact_offerings = std::collections::BTreeSet::new();
    let wire_offerings = compatible
        .iter()
        .enumerate()
        .map(|(index, offering)| {
            (
                offering.offering_id.as_str(),
                (
                    format!("offering-{index}"),
                    wire_provider_id(offering, index),
                ),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    for (recommendation_index, recommendation) in slot.suggested_models.iter().enumerate() {
        let before = choices.len();
        let mut recommendation_offerings = std::collections::BTreeSet::new();
        for alias in &recommendation.provider_aliases {
            for offering in compatible.iter().filter(|offering| {
                offering.provider_id == alias.provider_id && offering.model_id == alias.model_id
            }) {
                // One offering may appear through duplicate-looking route
                // metadata, but a recommendation has one selectable route.
                if !recommendation_offerings.insert(offering.offering_id.clone()) {
                    continue;
                }
                exact_offerings.insert(offering.offering_id.clone());
                let (offering_id, provider_id) = wire_offerings
                    .get(offering.offering_id.as_str())
                    .expect("compatible offering identity disappeared")
                    .clone();
                choices.push(AgentInstallationChoiceV1 {
                    choice_id: format!("choice-{recommendation_index}-{offering_id}"),
                    slot_id: slot_id.to_owned(),
                    offering_id,
                    provider_id,
                    model_id: offering.model_id.clone(),
                    recommendation_id: Some(recommendation.recommendation_id.clone()),
                    canonical_upstream_identity: Some(recommendation.upstream_identity.clone()),
                    author_label: recommendation.author_label.clone(),
                    rationale: recommendation.rationale.clone(),
                    author_suggested: true,
                    exact_alias_match: true,
                });
            }
        }
        if choices.len() == before {
            unmatched.push(AgentInstallationUnmatchedRecommendationV1 {
                recommendation_id: recommendation.recommendation_id.clone(),
                canonical_upstream_identity: recommendation.upstream_identity.clone(),
                author_label: recommendation.author_label.clone(),
                rationale: recommendation.rationale.clone(),
            });
        }
    }
    // `ranked_compatible_offerings` has already applied hard capability
    // checks and stable author/alias/offering ordering.  The remaining local
    // offerings are compatible but unsuggested; callers may select them
    // without an acknowledgement.
    for offering in compatible
        .iter()
        .filter(|offering| !exact_offerings.contains(&offering.offering_id))
    {
        let (offering_id, provider_id) = wire_offerings
            .get(offering.offering_id.as_str())
            .expect("compatible offering identity disappeared")
            .clone();
        choices.push(AgentInstallationChoiceV1 {
            choice_id: format!("choice-local-{offering_id}"),
            slot_id: slot_id.to_owned(),
            offering_id,
            provider_id,
            model_id: offering.model_id.clone(),
            recommendation_id: None,
            canonical_upstream_identity: None,
            author_label: None,
            rationale: None,
            author_suggested: false,
            exact_alias_match: false,
        });
    }
    (choices, unmatched)
}

/// Persist the daemon-local profile route selected while choices are built.
/// A wire choice only identifies the portable provider alias; a restart must
/// never infer a credential-owning profile from that alias again.
fn durable_binding_routes(
    compatible: &[crate::agents::AgentProfileModelOffering],
    choices: &[AgentInstallationChoiceV1],
) -> Result<Vec<DurableBindingRoute>> {
    let mut route_ids = std::collections::BTreeSet::new();
    let mut routes = Vec::with_capacity(choices.len());
    for choice in choices {
        ensure!(
            route_ids.insert(choice.choice_id.clone()),
            "daemon emitted duplicate installation choice id"
        );
        let matches = compatible
            .iter()
            .enumerate()
            .filter(|(index, offering)| {
                choice.provider_id == wire_provider_id(offering, index)
                    && choice.model_id == offering.model_id
                    && choice.offering_id == format!("offering-{index}")
            })
            .map(|(_, offering)| &offering.provider_profile_handle)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1 && !matches[0].trim().is_empty(),
            "selected installation choice has no exact daemon-local provider profile route"
        );
        routes.push(DurableBindingRoute {
            choice_id: choice.choice_id.clone(),
            provider_profile_handle: matches[0].clone(),
        });
    }
    Ok(routes)
}

fn wire_provider_id(
    offering: &crate::agents::AgentProfileModelOffering,
    offering_index: usize,
) -> String {
    if offering.provider_id == offering.provider_profile_handle {
        // The config-map key is the credential-owning profile handle for a
        // custom provider. Replace it with a deterministic display token.
        format!("configured-provider-{offering_index}")
    } else {
        offering.provider_id.clone()
    }
}

/// `--yes` is deliberately narrower than normal interactive ranking. A
/// locally available model is never an implicit default unless it preserves
/// both an author suggestion and its exact declared alias.
fn first_exact_author_choice(choices: &[AgentInstallationChoiceV1]) -> Option<String> {
    choices
        .iter()
        .find(|choice| choice.author_suggested && choice.exact_alias_match)
        .map(|choice| choice.choice_id.clone())
}

fn terminal_bind_refusal_code(
    outcome: &cockpit_db::db::agent_installations::BindAgentOutcome,
) -> Option<AgentInstallationErrorCodeV1> {
    use cockpit_db::db::agent_installations::BindAgentOutcome;
    match outcome {
        BindAgentOutcome::Bound(_) | BindAgentOutcome::AlreadyBound(_) => None,
        BindAgentOutcome::Incompatible => Some(AgentInstallationErrorCodeV1::IncompatibleModel),
        BindAgentOutcome::RebindRequired
        | BindAgentOutcome::Conflict
        | BindAgentOutcome::Deleted
        | BindAgentOutcome::NotFound => Some(AgentInstallationErrorCodeV1::StaleBinding),
    }
}

fn validate_durable_choice_set(choice_set: &BindChoiceSet) -> Result<()> {
    ensure!(
        !choice_set.installation_id.trim().is_empty()
            && !choice_set.definition_digest.trim().is_empty(),
        "stored installation choice set is incomplete"
    );
    let choice_ids = choice_set
        .choices
        .iter()
        .map(|choice| choice.choice_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        choice_ids.len() == choice_set.choices.len(),
        "stored installation choice set has duplicate choice ids"
    );
    if let Some(auto_choice_id) = choice_set.auto_choice_id.as_deref() {
        ensure!(
            choice_set.choices.iter().any(|choice| {
                choice.choice_id == auto_choice_id
                    && choice.author_suggested
                    && choice.exact_alias_match
            }),
            "stored automatic installation choice is not an exact author route"
        );
    }
    let mut route_ids = std::collections::BTreeSet::new();
    for route in &choice_set.routes {
        ensure!(
            choice_ids.contains(route.choice_id.as_str())
                && !route.provider_profile_handle.trim().is_empty()
                && route_ids.insert(route.choice_id.as_str()),
            "stored installation choice route is invalid"
        );
    }
    ensure!(
        route_ids.len() == choice_ids.len(),
        "stored installation choice set is missing a daemon-local profile route"
    );
    Ok(())
}

fn minimal_template(
    name: &str,
    execution_kind: AgentInstallationExecutionKindV1,
    primary_slot: &str,
) -> String {
    let execution_kind = match execution_kind {
        AgentInstallationExecutionKindV1::Assistant => "assistant",
        AgentInstallationExecutionKindV1::Coding => "coding",
        AgentInstallationExecutionKindV1::Computer => "computer",
    };
    format!(
        "---\nschemaVersion: 2\nagentId: authored/{name}\nexecutionKind: {execution_kind}\ndescription: Custom {name} agent\nmodelSlots:\n  {primary_slot}:\n    purpose: Primary model\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: true\n---\n\nYou are the `{name}` Cockpit agent.\n"
    )
}
fn receipt(
    operation_id: Uuid,
    status: AgentInstallationReceiptStatusV1,
    installation_id: Option<String>,
    source_revision: Option<String>,
) -> AgentInstallationResultV1 {
    AgentInstallationResultV1::Receipt {
        operation_id: operation_id.to_string(),
        status,
        installation_id,
        source_revision,
        binding_outcome: None,
    }
}
fn binding_terminal_receipt(
    operation_id: Uuid,
    parent_status: Option<AgentInstallationReceiptStatusV1>,
    parent_source_revision: Option<String>,
    binding_status: AgentInstallationReceiptStatusV1,
    installation_id: Uuid,
) -> AgentInstallationResultV1 {
    let Some(status) = parent_status else {
        return receipt(
            operation_id,
            binding_status,
            Some(installation_id.to_string()),
            None,
        );
    };
    let binding_outcome = match binding_status {
        AgentInstallationReceiptStatusV1::Bound => AgentInstallationBindingOutcomeV1::Bound,
        AgentInstallationReceiptStatusV1::OptionalUnbound => {
            AgentInstallationBindingOutcomeV1::OptionalUnbound
        }
        AgentInstallationReceiptStatusV1::PrimaryUnusable => {
            AgentInstallationBindingOutcomeV1::PrimaryUnusable
        }
        _ => unreachable!("binding continuations only use binding terminal statuses"),
    };
    AgentInstallationResultV1::Receipt {
        operation_id: operation_id.to_string(),
        status,
        installation_id: Some(installation_id.to_string()),
        source_revision: parent_source_revision,
        binding_outcome: Some(binding_outcome),
    }
}
fn replay_operation(receipt_json: Option<&str>) -> Result<AgentInstallationResultV1> {
    let receipt = receipt_json.context("installation operation is still in progress")?;
    serde_json::from_str(receipt).context("stored installation receipt is corrupt")
}
fn redacted_error(error: anyhow::Error) -> AgentInstallationResultV1 {
    let text = error.to_string();
    let code = if text.contains("idempotency") {
        AgentInstallationErrorCodeV1::IdempotencyConflict
    } else if text.contains("workspace authorization") {
        AgentInstallationErrorCodeV1::UnauthorizedWorkspace
    } else if text.contains("authorization") || text.contains("private") {
        AgentInstallationErrorCodeV1::PrivateSourceUnauthorized
    } else if text.contains("unknown installation choice") {
        AgentInstallationErrorCodeV1::UnknownChoice
    } else if text.contains("stale") || text.contains("rebind") || text.contains("claimed") {
        AgentInstallationErrorCodeV1::StaleBinding
    } else if text.contains("incompatible") {
        AgentInstallationErrorCodeV1::IncompatibleModel
    } else if text.contains("continuation") || text.contains("expired") {
        AgentInstallationErrorCodeV1::ContinuationExpired
    } else if text.contains("dirty shared") {
        AgentInstallationErrorCodeV1::DirtySharedFile
    } else if text.contains("collid") || text.contains("dirty") {
        AgentInstallationErrorCodeV1::Collision
    } else if text.contains("fetch") {
        AgentInstallationErrorCodeV1::FetchFailed
    } else if text.contains("vNext") || text.contains("Markdown") || text.contains("AgentDef") {
        AgentInstallationErrorCodeV1::InvalidDefinition
    } else {
        AgentInstallationErrorCodeV1::InvalidRequest
    };
    typed_installation_error(code)
}

fn typed_installation_error(code: AgentInstallationErrorCodeV1) -> AgentInstallationResultV1 {
    AgentInstallationResultV1::Error {
        error: AgentInstallationErrorV1 {
            code,
            message: "agent installation request was refused; inspect daemon logs for redacted diagnostics".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::{
        ModelCapability, ModelLocality, ModelRecommendation, ModelSlot, ProviderAlias,
    };
    use cockpit_config::config::providers::{ModelEntry, ProviderEntry};
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct RecordedGithubRequest {
        url: String,
        authorization: Option<String>,
        timeout: std::time::Duration,
    }

    struct ScriptedGithubTransport {
        responses: Mutex<VecDeque<GithubHttpResponse>>,
        requests: Mutex<Vec<RecordedGithubRequest>>,
    }

    impl ScriptedGithubTransport {
        fn new(responses: Vec<GithubHttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<RecordedGithubRequest> {
            std::mem::take(&mut *self.requests.lock().expect("request lock"))
        }
    }

    #[async_trait]
    impl GithubHttpTransport for ScriptedGithubTransport {
        async fn get(&self, request: GithubHttpRequest) -> Result<GithubHttpResponse> {
            self.requests
                .lock()
                .expect("request lock")
                .push(RecordedGithubRequest {
                    url: request.url,
                    authorization: request.authorization,
                    timeout: request.timeout,
                });
            self.responses
                .lock()
                .expect("response lock")
                .pop_front()
                .context("unexpected GitHub HTTP request")
        }
    }

    fn github_response(
        status: u16,
        content_length: Option<u64>,
        chunks: Vec<Vec<u8>>,
    ) -> GithubHttpResponse {
        GithubHttpResponse {
            status,
            content_length,
            body: futures::stream::iter(chunks.into_iter().map(Ok)).boxed(),
        }
    }

    fn github_commit_response(sha: &str) -> GithubHttpResponse {
        github_response(
            200,
            None,
            vec![format!(r#"{{"sha":"{sha}"}}"#).into_bytes()],
        )
    }

    fn github_source() -> CanonicalAgentSource {
        CanonicalAgentSource::parse("owner/repository@release-1:agents/helper.md")
            .expect("canonical GitHub source")
    }

    #[tokio::test]
    async fn agent_installation_daemon_github_fetcher_pins_commit_uses_timeout_and_keeps_auth_out_of_output()
     {
        let sha = "b".repeat(40);
        let transport = Arc::new(ScriptedGithubTransport::new(vec![
            github_commit_response(&sha),
            github_response(200, Some(5), vec![b"hello".to_vec()]),
        ]));
        let secret = "github-private-token-not-persisted";
        let fetcher =
            GithubHttpsAgentFetcher::with_transport(transport.clone(), Some(secret.to_owned()));

        let fetched = fetcher
            .fetch_github_markdown(&github_source())
            .await
            .expect("pinned fetch succeeds");
        assert_eq!(fetched.commit_sha, sha);
        assert_eq!(fetched.markdown, b"hello");
        assert!(!format!("{fetched:?}").contains(secret));

        let requests = transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].url,
            "https://api.github.com/repos/owner/repository/commits/release-1"
        );
        assert_eq!(
            requests[1].url,
            format!("https://raw.githubusercontent.com/owner/repository/{sha}/agents/helper.md")
        );
        for request in &requests {
            assert_eq!(
                request.authorization.as_deref(),
                Some(format!("Bearer {secret}").as_str())
            );
            assert_eq!(request.timeout, GITHUB_FETCH_TIMEOUT);
        }
    }

    #[tokio::test]
    async fn agent_installation_daemon_github_fetcher_rejects_redirects_without_leaking_auth() {
        let sha = "c".repeat(40);
        let secret = "github-redirect-token";
        let transport = Arc::new(ScriptedGithubTransport::new(vec![
            github_commit_response(&sha),
            github_response(302, Some(0), vec![]),
        ]));
        let fetcher =
            GithubHttpsAgentFetcher::with_transport(transport.clone(), Some(secret.to_owned()));

        let error = fetcher
            .fetch_github_markdown(&github_source())
            .await
            .expect_err("redirect must not be followed");
        assert!(
            error
                .to_string()
                .contains("GitHub agent source authorization or fetch failed")
        );
        assert!(!format!("{error:#}").contains(secret));
        assert_eq!(transport.requests().len(), 2);
    }

    #[tokio::test]
    async fn agent_installation_daemon_github_fetcher_enforces_content_length_and_stream_hard_caps()
    {
        let sha = "d".repeat(40);
        let declared_oversize = GithubHttpsAgentFetcher::with_transport(
            Arc::new(ScriptedGithubTransport::new(vec![
                github_commit_response(&sha),
                github_response(200, Some(MAX_AGENT_MARKDOWN_BYTES as u64 + 1), vec![]),
            ])),
            None,
        );
        let error = declared_oversize
            .fetch_github_markdown(&github_source())
            .await
            .expect_err("Content-Length above 1MiB must reject before body read");
        assert!(error.to_string().contains("exceeds 1MiB"));

        let streamed_oversize = GithubHttpsAgentFetcher::with_transport(
            Arc::new(ScriptedGithubTransport::new(vec![
                github_commit_response(&sha),
                github_response(
                    200,
                    None,
                    vec![vec![b'x'; MAX_AGENT_MARKDOWN_BYTES], vec![b'y']],
                ),
            ])),
            None,
        );
        let error = streamed_oversize
            .fetch_github_markdown(&github_source())
            .await
            .expect_err("stream crossing 1MiB must reject");
        assert!(error.to_string().contains("exceeds 1MiB"));
    }

    #[tokio::test]
    async fn agent_installation_daemon_github_fetcher_accepts_exactly_one_mib() {
        let sha = "e".repeat(40);
        let fetcher = GithubHttpsAgentFetcher::with_transport(
            Arc::new(ScriptedGithubTransport::new(vec![
                github_commit_response(&sha),
                github_response(
                    200,
                    Some(MAX_AGENT_MARKDOWN_BYTES as u64),
                    vec![vec![b'x'; MAX_AGENT_MARKDOWN_BYTES]],
                ),
            ])),
            None,
        );
        let fetched = fetcher
            .fetch_github_markdown(&github_source())
            .await
            .expect("exactly 1MiB is permitted");
        assert_eq!(fetched.commit_sha, sha);
        assert_eq!(fetched.markdown.len(), MAX_AGENT_MARKDOWN_BYTES);
    }

    #[derive(Clone)]
    enum FetchReply {
        Source(FetchedAgentSource),
        Failure(String),
    }

    #[derive(Clone)]
    struct MockFetcher {
        reply: Arc<Mutex<FetchReply>>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl AgentInstallationFetcher for MockFetcher {
        async fn fetch_github_markdown(
            &self,
            _source: &CanonicalAgentSource,
        ) -> Result<FetchedAgentSource> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.reply.lock().expect("mock fetcher lock").clone() {
                FetchReply::Source(source) => Ok(source),
                FetchReply::Failure(message) => bail!(message),
            }
        }
    }

    #[derive(Clone)]
    struct MockWorkspaceAuthorizer {
        root: PathBuf,
        allowed: bool,
    }

    #[async_trait]
    impl AgentWorkspaceAuthorizer for MockWorkspaceAuthorizer {
        async fn authorize_workspace(&self, client_path: &str) -> Result<(String, PathBuf)> {
            ensure!(
                self.allowed && client_path == "workspace-request",
                "mock workspace denied"
            );
            Ok(("workspace:test".into(), self.root.clone()))
        }
    }

    /// A deterministic daemon-service harness.  It supplies a source fetcher
    /// and workspace authority at the daemon boundary, so these tests never
    /// touch GitHub, a credential store, the caller's filesystem, or timing.
    struct ServiceHarness {
        _root: tempfile::TempDir,
        db: Db,
        service: AgentInstallationService,
        fetcher: MockFetcher,
    }

    impl ServiceHarness {
        fn new(reply: FetchReply) -> Self {
            Self::with_providers(reply, ProvidersConfig::default())
        }

        fn with_providers(reply: FetchReply, providers: ProvidersConfig) -> Self {
            let root = tempfile::tempdir().expect("temporary daemon root");
            let fetcher = MockFetcher {
                reply: Arc::new(Mutex::new(reply)),
                calls: Arc::new(AtomicUsize::new(0)),
            };
            let db = Db::open_in_memory().expect("test DB");
            let service = AgentInstallationService::new(
                db.clone(),
                root.path().join("daemon-agents"),
                Arc::new(fetcher.clone()),
                Arc::new(MockWorkspaceAuthorizer {
                    root: root.path().join("workspace"),
                    allowed: true,
                }),
                providers,
            );
            Self {
                _root: root,
                db,
                service,
                fetcher,
            }
        }

        fn request(key: &str) -> AgentInstallationBeginV1 {
            AgentInstallationBeginV1 {
                dto_version: AGENT_INSTALLATION_DTO_VERSION,
                idempotency_key: key.into(),
                operation: AgentInstallationOperationKind::Install,
                scope: AgentInstallationScopeWire::Global,
                workspace_path: None,
                source_locator: "owner/repo@main:agents/helper.md".into(),
                target_installation_id: None,
                replace_acknowledged: false,
                requested_slot: None,
                execution_kind: None,
                primary_slot_id: None,
                auto_select_first_exact: false,
            }
        }

        fn fetched() -> FetchedAgentSource {
            FetchedAgentSource {
                commit_sha: "a".repeat(40),
                markdown: b"---\ndescription: helper\nschemaVersion: 2\nagentId: authored/helper\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: primary\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n---\nbody\n".to_vec(),
            }
        }

        fn target(&self) -> PathBuf {
            self._root.path().join("daemon-agents/helper.md")
        }
    }

    fn binding_providers() -> ProvidersConfig {
        let mut providers = ProvidersConfig::default();
        for (profile, provider_id, model_id) in [
            ("profile-a", "vendor", "exact-a"),
            ("profile-b", "vendor", "exact-b"),
            ("profile-local", "local", "compatible"),
        ] {
            let mut entry = ProviderEntry::default();
            entry.template = Some(provider_id.into());
            entry.models.push(ModelEntry {
                id: model_id.into(),
                context_length: Some(128),
                ..ModelEntry::default()
            });
            providers.providers.insert(profile.into(), entry);
        }
        providers
    }

    fn fetched_with_binding_choices(required_capability: &str) -> FetchedAgentSource {
        FetchedAgentSource {
            commit_sha: "b".repeat(40),
            markdown: format!(
                "---\ndescription: helper\nschemaVersion: 2\nagentId: authored/helper\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: primary\n    minContextTokens: 1\n    requiredCapabilities: [{required_capability}]\n    locality: any\n    allowDefaultFallback: false\n    suggestedModels:\n      - recommendationId: first\n        upstreamIdentity: upstream/first\n        providerAliases:\n          - providerId: vendor\n            modelId: exact-a\n      - recommendationId: second\n        upstreamIdentity: upstream/second\n        providerAliases:\n          - providerId: vendor\n            modelId: exact-b\n      - recommendationId: missing\n        upstreamIdentity: upstream/missing\n  optional:\n    purpose: optional\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n    suggestedModels:\n      - recommendationId: first\n        upstreamIdentity: upstream/first\n        providerAliases:\n          - providerId: vendor\n            modelId: exact-a\n---\nbody\n"
            )
            .into_bytes(),
        }
    }

    fn fetched_definition_digest(fetched: &FetchedAgentSource) -> String {
        let markdown = std::str::from_utf8(&fetched.markdown).expect("fixture utf8");
        let definition =
            crate::agents::parse_agent(markdown, "helper", PathBuf::from("fixture.md"))
                .expect("fixture definition");
        sha256_hex(&definition.vnext_digest_bytes().expect("fixture digest"))
    }

    #[test]
    fn agent_installation_daemon_update_target_is_part_of_the_idempotency_fingerprint() {
        let mut first = ServiceHarness::request("update-target-fingerprint");
        first.operation = AgentInstallationOperationKind::Update;
        first.target_installation_id = Some("00000000-0000-0000-0000-000000000001".into());
        let mut second = first.clone();
        second.target_installation_id = Some("00000000-0000-0000-0000-000000000002".into());
        assert_ne!(
            request_fingerprint(&first, None),
            request_fingerprint(&second, None)
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_update_without_target_refuses_before_fetch_or_mutation() {
        let harness = ServiceHarness::new(FetchReply::Failure("must not fetch".into()));
        let mut request = ServiceHarness::request("update-requires-target");
        request.operation = AgentInstallationOperationKind::Update;
        request.replace_acknowledged = true;
        let AgentInstallationResultV1::Error { error } = harness.service.begin(request, 1).await
        else {
            panic!("update without durable target must be refused")
        };
        assert_eq!(error.code, AgentInstallationErrorCodeV1::InvalidRequest);
        assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn agent_installation_daemon_invalid_manifest_is_typed_and_creates_no_operation_or_file()
    {
        let harness = ServiceHarness::new(FetchReply::Source(FetchedAgentSource {
            commit_sha: "d".repeat(40),
            markdown: b"---\ndescription: invalid\nschemaVersion: 2\nagentId: authored/helper\nexecutionKind: coding\n---\nmissing slots\n".to_vec(),
        }));
        let result = harness
            .service
            .begin(ServiceHarness::request("invalid-manifest"), 1)
            .await;
        assert!(matches!(
            result,
            AgentInstallationResultV1::Error { error }
                if error.code == AgentInstallationErrorCodeV1::InvalidDefinition
        ));
        assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 1);
        assert!(
            harness
                .db
                .installation_operation("invalid-manifest".into())
                .await
                .expect("read invalid manifest operation")
                .is_none()
        );
        assert!(
            harness
                .db
                .list_agent_installations(AgentInstallationScope::Global, None)
                .await
                .expect("list invalid manifest installations")
                .is_empty()
        );
        assert!(!harness.target().exists());
    }

    #[tokio::test]
    async fn agent_installation_daemon_atomic_begin_replays_pinned_source_after_crash_without_refetch()
     {
        let harness = ServiceHarness::new(FetchReply::Source(ServiceHarness::fetched()));
        let request = ServiceHarness::request("atomic-begin-crash");
        let fetched = ServiceHarness::fetched();
        let (staged_file_metadata_json, expected_digest) =
            staged_source_journal_metadata(&request.source_locator, &fetched)
                .expect("serialize pinned staged source");
        let BeginInstallationOperation::Created(operation) = harness
            .db
            .begin_installation_operation_with_staged_journal(
                request.idempotency_key.clone(),
                request_fingerprint(&request, None),
                InstallationOperationKind::Install,
                None,
                staged_file_metadata_json,
                expected_digest,
                1,
            )
            .await
            .expect("atomic operation and journal")
        else {
            panic!("fixture must create an operation")
        };
        assert!(
            harness
                .db
                .installation_journal(operation.operation_id)
                .await
                .expect("read atomic journal")
                .is_some(),
            "there is no operation-created/journal-not-separate crash state"
        );
        *harness.fetcher.reply.lock().expect("fetcher reply") =
            FetchReply::Failure("moving ref must not be consulted on recovery".into());
        let result = harness.service.begin(request, 99).await;
        assert!(matches!(
            result,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Installed,
                source_revision: Some(ref revision),
                ..
            } if revision == &"a".repeat(40)
        ));
        assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn agent_installation_daemon_update_rejects_mismatched_target_without_mutation() {
        let harness = ServiceHarness::new(FetchReply::Failure("must not fetch".into()));
        let installation_id = Uuid::new_v4();
        harness
            .db
            .install_agent(AgentInstallationInput {
                installation_id,
                scope: AgentInstallationScope::Global,
                canonical_workspace_id: None,
                source_agent_id: "authored/helper".into(),
                source_identity: "owner/other:agents/helper.md".into(),
                source_revision: Some("b".repeat(40)),
                source_digest: "c".repeat(64),
                fetched_at_unix_ms: 1,
            })
            .await
            .expect("seed mismatched target");
        let mut request = ServiceHarness::request("update-target-mismatch");
        request.operation = AgentInstallationOperationKind::Update;
        request.target_installation_id = Some(installation_id.to_string());
        request.replace_acknowledged = true;
        let AgentInstallationResultV1::Error { error } = harness.service.begin(request, 2).await
        else {
            panic!("mismatched update target must be refused")
        };
        assert_eq!(error.code, AgentInstallationErrorCodeV1::InvalidRequest);
        assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
        assert!(
            harness
                .db
                .installation_operation("update-target-mismatch".into())
                .await
                .expect("read operation")
                .is_none(),
            "a mismatched target must not create an operation row"
        );
        assert_eq!(
            harness
                .db
                .agent_installation(installation_id)
                .await
                .expect("read target")
                .expect("target remains")
                .source_identity,
            "owner/other:agents/helper.md"
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_create_uses_authored_identity_and_refuses_collision() {
        let harness = ServiceHarness::new(FetchReply::Failure("create does not fetch".into()));
        let mut request = ServiceHarness::request("create-authored");
        request.operation = AgentInstallationOperationKind::Create;
        request.source_locator = "authored/new-helper".into();
        request.execution_kind = Some(AgentInstallationExecutionKindV1::Coding);
        request.primary_slot_id = Some("primary".into());
        let AgentInstallationResultV1::Receipt {
            status: AgentInstallationReceiptStatusV1::Created,
            installation_id: Some(installation_id),
            ..
        } = harness.service.begin(request, 1).await
        else {
            panic!("daemon create must accept authored/NAME")
        };
        assert!(Uuid::parse_str(&installation_id).is_ok());
        assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);

        let mut collision = ServiceHarness::request("create-authored-collision");
        collision.operation = AgentInstallationOperationKind::Create;
        collision.source_locator = "authored/new-helper".into();
        collision.execution_kind = Some(AgentInstallationExecutionKindV1::Coding);
        collision.primary_slot_id = Some("primary".into());
        let AgentInstallationResultV1::Error { error } = harness.service.begin(collision, 2).await
        else {
            panic!("same scope authored identity must not overwrite")
        };
        assert_eq!(error.code, AgentInstallationErrorCodeV1::Collision);
    }

    #[tokio::test]
    async fn agent_installation_daemon_bind_matrix_preserves_suggestions_allows_local_and_handles_defer_and_rebind()
     {
        let harness = ServiceHarness::with_providers(
            FetchReply::Source(fetched_with_binding_choices("text_generation")),
            binding_providers(),
        );
        let AgentInstallationResultV1::Receipt {
            installation_id: Some(installation_id),
            ..
        } = harness
            .service
            .begin(ServiceHarness::request("bind-matrix-install"), 1)
            .await
        else {
            panic!("scripted install must create an installation")
        };

        let bind = |key: &str, slot: &str| AgentInstallationBeginV1 {
            idempotency_key: key.into(),
            operation: AgentInstallationOperationKind::Bind,
            source_locator: installation_id.clone(),
            requested_slot: Some(slot.into()),
            ..ServiceHarness::request(key)
        };
        let AgentInstallationResultV1::NeedsChoice {
            continuation_token,
            choices,
            unmatched_recommendations,
            ..
        } = harness
            .service
            .begin(bind("bind-local", "primary"), 2)
            .await
        else {
            panic!("compatible routes must require a daemon choice")
        };
        assert_eq!(
            choices
                .iter()
                .map(|choice| choice.recommendation_id.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("first"), Some("second"), None]
        );
        assert!(choices[0].exact_alias_match && choices[0].author_suggested);
        assert!(choices[1].exact_alias_match && choices[1].author_suggested);
        assert!(!choices[2].author_suggested && !choices[2].exact_alias_match);
        assert_eq!(
            unmatched_recommendations[0].canonical_upstream_identity,
            "upstream/missing"
        );
        let local_choice = choices[2].choice_id.clone();
        assert!(matches!(
            harness
                .service
                .submit_choice(
                    AgentInstallationSubmitChoiceV1 {
                        dto_version: AGENT_INSTALLATION_DTO_VERSION,
                        continuation_token,
                        choice_id: Some(local_choice),
                        defer: false,
                    },
                    3,
                )
                .await,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Bound,
                ..
            }
        ));

        let AgentInstallationResultV1::NeedsChoice {
            continuation_token,
            choices,
            ..
        } = harness
            .service
            .begin(bind("bind-rebind", "primary"), 4)
            .await
        else {
            panic!("rebind must create a fresh daemon choice")
        };
        assert!(matches!(
            harness
                .service
                .submit_choice(
                    AgentInstallationSubmitChoiceV1 {
                        dto_version: AGENT_INSTALLATION_DTO_VERSION,
                        continuation_token,
                        choice_id: Some(choices[1].choice_id.clone()),
                        defer: false,
                    },
                    5,
                )
                .await,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Bound,
                ..
            }
        ));

        for (key, slot, status) in [
            (
                "bind-defer-optional",
                "optional",
                AgentInstallationReceiptStatusV1::OptionalUnbound,
            ),
            (
                "bind-defer-primary",
                "primary",
                AgentInstallationReceiptStatusV1::PrimaryUnusable,
            ),
        ] {
            let AgentInstallationResultV1::NeedsChoice {
                continuation_token, ..
            } = harness.service.begin(bind(key, slot), 6).await
            else {
                panic!("{slot} must offer a deferrable choice")
            };
            assert!(matches!(
                harness
                    .service
                    .submit_choice(
                        AgentInstallationSubmitChoiceV1 {
                            dto_version: AGENT_INSTALLATION_DTO_VERSION,
                            continuation_token,
                            choice_id: None,
                            defer: true,
                        },
                        7,
                    )
                    .await,
                AgentInstallationResultV1::Receipt { status: actual, .. } if actual == status
            ));
        }
    }

    #[tokio::test]
    async fn agent_installation_daemon_bind_refuses_unknown_hard_capability_without_mutating_bindings()
     {
        let harness = ServiceHarness::with_providers(
            FetchReply::Source(fetched_with_binding_choices("tool_calling")),
            binding_providers(),
        );
        let AgentInstallationResultV1::Receipt {
            installation_id: Some(installation_id),
            ..
        } = harness
            .service
            .begin(ServiceHarness::request("unknown-capability-install"), 1)
            .await
        else {
            panic!("install must succeed before the bind check")
        };
        let result = harness
            .service
            .begin(
                AgentInstallationBeginV1 {
                    idempotency_key: "unknown-capability-bind".into(),
                    operation: AgentInstallationOperationKind::Bind,
                    source_locator: installation_id,
                    requested_slot: Some("primary".into()),
                    ..ServiceHarness::request("unknown-capability-bind")
                },
                2,
            )
            .await;
        assert!(matches!(
            result,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::PrimaryUnusable,
                ..
            }
        ));
        assert_eq!(
            harness
                .db
                .read(|conn| {
                    Ok(
                        conn.query_row("SELECT COUNT(*) FROM agent_model_bindings", [], |row| {
                            row.get::<_, i64>(0)
                        })?,
                    )
                })
                .await
                .expect("binding count"),
            0
        );
    }

    fn slot(
        required: Vec<ModelCapability>,
        recommendations: Vec<ModelRecommendation>,
    ) -> ModelSlot {
        ModelSlot {
            purpose: "fixture slot".into(),
            min_context_tokens: 8,
            required_capabilities: required,
            locality: ModelLocality::Any,
            allow_default_fallback: false,
            suggested_models: recommendations,
        }
    }

    fn recommendation(id: &str, upstream: &str, aliases: &[(&str, &str)]) -> ModelRecommendation {
        ModelRecommendation {
            recommendation_id: id.into(),
            upstream_identity: upstream.into(),
            provider_aliases: aliases
                .iter()
                .map(|(provider_id, model_id)| ProviderAlias {
                    provider_id: (*provider_id).into(),
                    model_id: (*model_id).into(),
                })
                .collect(),
            author_label: Some(format!("label-{id}")),
            rationale: Some(format!("why-{id}")),
        }
    }

    fn providers_for(offerings: &[AgentProfileModelOffering]) -> ProvidersConfig {
        let mut providers = ProvidersConfig::default();
        for offering in offerings {
            providers
                .providers
                .entry(offering.provider_id.clone())
                .or_insert_with(ProviderEntry::default)
                .models
                .push(ModelEntry {
                    id: offering.model_id.clone(),
                    context_length: Some(128),
                    ..ModelEntry::default()
                });
        }
        providers
    }

    async fn prepare_recovery_checkpoint(
        harness: &ServiceHarness,
        request: &AgentInstallationBeginV1,
        checkpoint: InstallationJournalCheckpoint,
    ) -> Uuid {
        let operation = match harness
            .db
            .begin_installation_operation(
                request.idempotency_key.clone(),
                request_fingerprint(request, None),
                InstallationOperationKind::Install,
                None,
                1,
            )
            .await
            .expect("begin operation")
        {
            BeginInstallationOperation::Created(operation) => operation,
            _ => panic!("expected fresh operation"),
        };
        let fetched = ServiceHarness::fetched();
        let digest = sha256_hex(&fetched.markdown);
        let target = harness.target();
        stage_file(&target, operation.operation_id, &fetched.markdown).expect("stage fixture");
        let journal = InstallationJournalRow {
            journal_id: Uuid::new_v4(),
            operation_id: operation.operation_id,
            checkpoint: InstallationJournalCheckpoint::Staged,
            staged_file_metadata_json: Some(
                serde_json::to_string(&JournalStagedSource {
                    target_name: "helper".into(),
                    digest: digest.clone(),
                    commit_sha: fetched.commit_sha.clone(),
                    markdown_base64: base64::engine::general_purpose::STANDARD
                        .encode(&fetched.markdown),
                })
                .expect("staged source metadata"),
            ),
            prior_file_metadata_json: None,
            expected_digest: digest,
        };
        harness
            .db
            .record_installation_journal(journal.clone(), 2)
            .await
            .expect("staged journal");
        if checkpoint_rank(checkpoint)
            >= checkpoint_rank(InstallationJournalCheckpoint::DbCommitted)
        {
            harness
                .db
                .install_agent(AgentInstallationInput {
                    installation_id: operation.operation_id,
                    scope: AgentInstallationScope::Global,
                    canonical_workspace_id: None,
                    source_agent_id: "authored/helper".into(),
                    source_identity: "owner/repo:agents/helper.md".into(),
                    source_revision: Some(fetched.commit_sha.clone()),
                    source_digest: fetched_definition_digest(&fetched),
                    fetched_at_unix_ms: 1,
                })
                .await
                .expect("fixture installation");
            harness
                .db
                .record_installation_journal(
                    InstallationJournalRow {
                        checkpoint: InstallationJournalCheckpoint::DbCommitted,
                        ..journal.clone()
                    },
                    3,
                )
                .await
                .expect("DB checkpoint");
        }
        if checkpoint_rank(checkpoint)
            >= checkpoint_rank(InstallationJournalCheckpoint::FileRenamed)
        {
            publish_stage(
                &target,
                operation.operation_id,
                &sha256_hex(&fetched.markdown),
                false,
            )
            .expect("publish fixture");
            harness
                .db
                .record_installation_journal(
                    InstallationJournalRow {
                        checkpoint: InstallationJournalCheckpoint::FileRenamed,
                        ..journal
                    },
                    4,
                )
                .await
                .expect("rename checkpoint");
        }
        operation.operation_id
    }

    async fn prepare_pending_choice(
        harness: &ServiceHarness,
        key: &str,
        expires_at_unix_ms: i64,
        requested_operation: AgentInstallationOperationKind,
        auto: bool,
    ) -> (AgentInstallationBeginV1, Uuid, Uuid, String) {
        let installation_id = Uuid::new_v4();
        let definition_digest = "d".repeat(64);
        harness
            .db
            .install_agent(AgentInstallationInput {
                installation_id,
                scope: AgentInstallationScope::Global,
                canonical_workspace_id: None,
                source_agent_id: "authored/helper".into(),
                source_identity: "owner/repo:agents/helper.md".into(),
                source_revision: Some("a".repeat(40)),
                source_digest: definition_digest.clone(),
                fetched_at_unix_ms: 1,
            })
            .await
            .expect("fixture installation");
        let mut replay_request = ServiceHarness::request(key);
        replay_request.operation = requested_operation;
        replay_request.auto_select_first_exact = auto;
        if requested_operation == AgentInstallationOperationKind::Bind {
            replay_request.source_locator = installation_id.to_string();
        }
        let operation = match harness
            .db
            .begin_installation_operation(
                key.into(),
                request_fingerprint(&replay_request, None),
                operation_kind(requested_operation),
                None,
                1,
            )
            .await
            .expect("begin choice operation")
        {
            BeginInstallationOperation::Created(operation) => operation,
            _ => panic!("expected fresh choice operation"),
        };
        let choice_id = "choice-exact".to_owned();
        let choice_set = BindChoiceSet {
            installation_id: installation_id.to_string(),
            definition_digest,
            choices: vec![AgentInstallationChoiceV1 {
                choice_id: choice_id.clone(),
                slot_id: "primary".into(),
                offering_id: "local-route".into(),
                provider_id: "display-provider".into(),
                model_id: "model".into(),
                recommendation_id: Some("author-default".into()),
                canonical_upstream_identity: Some("upstream/model".into()),
                author_label: None,
                rationale: None,
                author_suggested: true,
                exact_alias_match: true,
            }],
            unmatched_recommendations: vec![],
            routes: vec![DurableBindingRoute {
                choice_id: choice_id.clone(),
                provider_profile_handle: "opaque-profile-handle".into(),
            }],
            parent_receipt_status: match requested_operation {
                AgentInstallationOperationKind::Install => {
                    Some(AgentInstallationReceiptStatusV1::Installed)
                }
                AgentInstallationOperationKind::Update => {
                    Some(AgentInstallationReceiptStatusV1::Updated)
                }
                AgentInstallationOperationKind::Bind | AgentInstallationOperationKind::Create => {
                    None
                }
            },
            parent_source_revision: matches!(
                requested_operation,
                AgentInstallationOperationKind::Install | AgentInstallationOperationKind::Update
            )
            .then(|| "a".repeat(40)),
            auto_choice_id: auto.then_some(choice_id.clone()),
        };
        let continuation = harness
            .db
            .create_installation_continuation(
                operation.operation_id,
                serde_json::to_string(&choice_set).expect("choice set JSON"),
                expires_at_unix_ms,
                1,
            )
            .await
            .expect("choice continuation");
        (
            replay_request,
            operation.operation_id,
            continuation.continuation_token,
            choice_id,
        )
    }
    #[test]
    fn agent_installation_daemon_source_parser_refuses_urls_traversal_and_non_markdown() {
        assert!(CanonicalAgentSource::parse("owner/repo@main:agents/helper.md").is_ok());
        for source in [
            "https://github.com/owner/repo:a.md",
            "owner/repo:../a.md",
            "owner/repo:a.txt",
            "owner/repo:a.md:extra",
            "owner/repo@main/next:agents/helper.md",
            "owner/repo@main?ref=x:agents/helper.md",
            "owner/repo@main%2fnext:agents/helper.md",
            "owner/repo:agents/helper?.md",
        ] {
            assert!(CanonicalAgentSource::parse(source).is_err(), "{source}");
        }
    }

    #[tokio::test]
    async fn agent_installation_daemon_refuses_source_filename_and_agent_id_mismatch() {
        let mut fetched = ServiceHarness::fetched();
        fetched.markdown = String::from_utf8(fetched.markdown)
            .expect("fixture UTF-8")
            .replace("agentId: authored/helper", "agentId: authored/different")
            .into_bytes();
        let harness = ServiceHarness::new(FetchReply::Source(fetched));
        let AgentInstallationResultV1::Error { error } = harness
            .service
            .begin(ServiceHarness::request("different-filename"), 1)
            .await
        else {
            panic!("filename mismatch must be refused")
        };
        assert_eq!(error.code, AgentInstallationErrorCodeV1::InvalidRequest);
    }
    #[test]
    fn agent_installation_daemon_template_is_minimal_and_provider_free() {
        let template = minimal_template(
            "helper",
            AgentInstallationExecutionKindV1::Coding,
            "primary",
        );
        assert!(template.contains("agentId: authored/helper"));
        assert!(!template.contains("provider"));
        assert!(!template.contains("credential"));
    }

    #[test]
    fn agent_installation_daemon_redacts_fetch_and_workspace_failures() {
        for detail in [
            "fetch failed: Bearer ghp_secret_value",
            "workspace authorization failed for /private/workspace",
        ] {
            let AgentInstallationResultV1::Error { error } =
                redacted_error(anyhow::anyhow!(detail))
            else {
                panic!("expected redacted error")
            };
            assert!(!error.message.contains("ghp_secret_value"));
            assert!(!error.message.contains("/private/workspace"));
        }
    }

    #[test]
    fn agent_installation_daemon_replacement_backup_names_are_operation_scoped() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("helper.md");
        let first = prior_backup_path(&target, Uuid::nil()).unwrap();
        let second = prior_backup_path(&target, Uuid::new_v4()).unwrap();
        assert_ne!(first, second);
        assert!(
            first
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains(".prior")
        );
    }

    #[cfg(unix)]
    #[test]
    fn agent_installation_daemon_owned_file_helpers_refuse_leaf_and_ancestor_symlink_swaps() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("root");
        let outside = tempfile::tempdir().expect("outside");
        let parent = root.path().join("agents");
        std::fs::create_dir_all(&parent).expect("parent");
        let target = parent.join("helper.md");
        std::fs::write(outside.path().join("helper.md"), "outside").expect("outside file");
        symlink(outside.path().join("helper.md"), &target).expect("leaf symlink");
        assert!(read_owned_file(&target, "test").is_err());
        std::fs::remove_file(&target).expect("remove leaf link");
        let moved = root.path().join("agents-old");
        std::fs::rename(&parent, &moved).expect("move parent");
        symlink(outside.path(), &parent).expect("ancestor symlink");
        assert!(write_owned_file_new(&target, b"owned", "test").is_err());
    }

    #[tokio::test]
    async fn agent_installation_daemon_mocked_fetch_private_auth_and_workspace_mismatch_are_redacted()
     {
        let harness = ServiceHarness::new(FetchReply::Failure(
            "private GitHub authorization rejected Bearer ghp_never_return_this".into(),
        ));
        let result = harness
            .service
            .begin(ServiceHarness::request("private"), 1)
            .await;
        let AgentInstallationResultV1::Error { error } = result else {
            panic!("private fetch must fail")
        };
        assert_eq!(
            error.code,
            AgentInstallationErrorCodeV1::PrivateSourceUnauthorized
        );
        assert!(!error.message.contains("ghp_never_return_this"));

        let denied = AgentInstallationService::new(
            harness.db.clone(),
            harness._root.path().join("other-agents"),
            Arc::new(harness.fetcher.clone()),
            Arc::new(MockWorkspaceAuthorizer {
                root: harness._root.path().join("workspace"),
                allowed: false,
            }),
            ProvidersConfig::default(),
        );
        let mut request = ServiceHarness::request("workspace-mismatch");
        request.scope = AgentInstallationScopeWire::WorkspaceShared;
        request.workspace_path = Some("workspace-request".into());
        let AgentInstallationResultV1::Error { error } = denied.begin(request, 2).await else {
            panic!("workspace mismatch must fail")
        };
        assert_eq!(
            error.code,
            AgentInstallationErrorCodeV1::UnauthorizedWorkspace
        );
        assert!(!error.message.contains("workspace-request"));
    }

    #[tokio::test]
    async fn agent_installation_daemon_local_workspace_authorizer_refuses_unlisted_root() {
        let allowed = tempfile::tempdir().expect("allowed workspace");
        let denied = tempfile::tempdir().expect("unlisted workspace");
        let authorizer = LocalDaemonWorkspaceAuthorizer::new(vec![allowed.path().to_path_buf()])
            .expect("authorizer");
        assert!(
            authorizer
                .authorize_workspace(denied.path().to_string_lossy().as_ref())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_recovers_each_file_checkpoint_without_duplicate_installation_mutation()
     {
        for (index, checkpoint) in [
            InstallationJournalCheckpoint::Staged,
            InstallationJournalCheckpoint::DbCommitted,
            InstallationJournalCheckpoint::FileRenamed,
        ]
        .into_iter()
        .enumerate()
        {
            let harness = ServiceHarness::new(FetchReply::Failure("must not refetch".into()));
            let request = ServiceHarness::request(&format!("checkpoint-{index}"));
            let operation = prepare_recovery_checkpoint(&harness, &request, checkpoint).await;
            let result = harness.service.begin(request.clone(), 10).await;
            assert!(matches!(
                result,
                AgentInstallationResultV1::Receipt {
                    status: AgentInstallationReceiptStatusV1::Installed,
                    ..
                }
            ));
            let journal = harness
                .db
                .installation_journal(operation)
                .await
                .expect("journal lookup")
                .expect("journal exists");
            assert_eq!(journal.checkpoint, InstallationJournalCheckpoint::Complete);
            let rows = harness
                .db
                .list_agent_installations(AgentInstallationScope::Global, None)
                .await
                .expect("list installs");
            assert_eq!(rows.len(), 1, "checkpoint {checkpoint:?}");
            assert_eq!(
                target_digest(&harness.target()).expect("published target"),
                sha256_hex(&ServiceHarness::fetched().markdown)
            );
            assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn agent_installation_daemon_db_committed_replacement_compensation_replays_refused_without_refetching()
     {
        let harness = ServiceHarness::new(FetchReply::Failure("must not refetch".into()));
        let request = ServiceHarness::request("replacement-compensation");
        let operation = match harness
            .db
            .begin_installation_operation(
                request.idempotency_key.clone(),
                request_fingerprint(&request, None),
                InstallationOperationKind::Install,
                None,
                1,
            )
            .await
            .expect("begin operation")
        {
            BeginInstallationOperation::Created(operation) => operation,
            _ => panic!("expected fresh operation"),
        };
        let fetched = ServiceHarness::fetched();
        let definition_digest = fetched_definition_digest(&fetched);
        let original = AgentInstallationInput {
            installation_id: Uuid::new_v4(),
            scope: AgentInstallationScope::Global,
            canonical_workspace_id: None,
            source_agent_id: "authored/helper".into(),
            source_identity: "owner/old:agents/helper.md".into(),
            source_revision: Some("b".repeat(40)),
            source_digest: "c".repeat(64),
            fetched_at_unix_ms: 1,
        };
        let original_id = original.installation_id;
        harness
            .db
            .install_agent(original.clone())
            .await
            .expect("original installation");
        let replacement = AgentInstallationInput {
            installation_id: operation.operation_id,
            scope: AgentInstallationScope::Global,
            canonical_workspace_id: None,
            source_agent_id: "authored/helper".into(),
            source_identity: "owner/repo:agents/helper.md".into(),
            source_revision: Some(fetched.commit_sha.clone()),
            source_digest: definition_digest,
            fetched_at_unix_ms: 2,
        };
        let compensation = harness
            .db
            .agent_replacement_compensation_receipt(original_id, replacement.clone(), 2)
            .await
            .expect("capture prior replacement state");
        harness
            .db
            .replace_agent(replacement, 2)
            .await
            .expect("replace installation");
        harness
            .db
            .compensate_agent_replacement(compensation.clone())
            .await
            .expect("compensate failed publish");
        let staged_digest = sha256_hex(&fetched.markdown);
        let journal = InstallationJournalRow {
            journal_id: Uuid::new_v4(),
            operation_id: operation.operation_id,
            checkpoint: InstallationJournalCheckpoint::DbCommitted,
            staged_file_metadata_json: Some(
                serde_json::to_string(&JournalStagedSource {
                    target_name: "helper".into(),
                    digest: staged_digest.clone(),
                    commit_sha: fetched.commit_sha.clone(),
                    markdown_base64: base64::engine::general_purpose::STANDARD
                        .encode(&fetched.markdown),
                })
                .expect("journal source"),
            ),
            prior_file_metadata_json: Some(
                with_replacement_receipt(None, &compensation).expect("compensation receipt"),
            ),
            expected_digest: staged_digest,
        };
        harness
            .db
            .record_installation_journal(journal, 3)
            .await
            .expect("DB-committed journal");
        assert!(matches!(
            harness.service.begin(request, 4).await,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Refused,
                ..
            }
        ));
        assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
        let restored = harness
            .db
            .agent_installation(original_id)
            .await
            .expect("installation read")
            .expect("original installation remains");
        assert_eq!(restored.source_identity, original.source_identity);
        assert_eq!(
            harness
                .db
                .installation_journal(operation.operation_id)
                .await
                .expect("journal read")
                .expect("journal exists")
                .checkpoint,
            InstallationJournalCheckpoint::Complete
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_recovers_replace_committed_before_checkpoint_at_a_later_retry_time()
     {
        let harness = ServiceHarness::new(FetchReply::Failure("must not refetch".into()));
        let mut request = ServiceHarness::request("replace-before-db-checkpoint");
        request.replace_acknowledged = true;
        let operation = match harness
            .db
            .begin_installation_operation(
                request.idempotency_key.clone(),
                request_fingerprint(&request, None),
                InstallationOperationKind::Install,
                None,
                1,
            )
            .await
            .expect("begin operation")
        {
            BeginInstallationOperation::Created(operation) => operation,
            _ => panic!("expected fresh operation"),
        };
        let old_markdown = b"old daemon-owned definition".to_vec();
        let original = AgentInstallationInput {
            installation_id: Uuid::new_v4(),
            scope: AgentInstallationScope::Global,
            canonical_workspace_id: None,
            source_agent_id: "authored/helper".into(),
            source_identity: "owner/old:agents/helper.md".into(),
            source_revision: Some("b".repeat(40)),
            source_digest: sha256_hex(&old_markdown),
            fetched_at_unix_ms: 0,
        };
        let original_id = original.installation_id;
        harness
            .db
            .install_agent(original.clone())
            .await
            .expect("original installation");
        std::fs::create_dir_all(
            harness
                .target()
                .parent()
                .expect("target has daemon-owned parent"),
        )
        .expect("create daemon-owned parent");
        std::fs::write(harness.target(), &old_markdown).expect("write owned fixture");

        let fetched = ServiceHarness::fetched();
        let replacement = AgentInstallationInput {
            installation_id: operation.operation_id,
            scope: AgentInstallationScope::Global,
            canonical_workspace_id: None,
            source_agent_id: "authored/helper".into(),
            source_identity: "owner/repo:agents/helper.md".into(),
            source_revision: Some(fetched.commit_sha.clone()),
            source_digest: fetched_definition_digest(&fetched),
            fetched_at_unix_ms: operation.created_at_unix_ms,
        };
        let compensation = harness
            .db
            .agent_replacement_compensation_receipt(
                original_id,
                replacement.clone(),
                operation.created_at_unix_ms,
            )
            .await
            .expect("replacement receipt");
        harness
            .db
            .replace_agent(replacement, operation.created_at_unix_ms)
            .await
            .expect("commit replacement before checkpoint");
        let digest = sha256_hex(&fetched.markdown);
        harness
            .db
            .record_installation_journal(
                InstallationJournalRow {
                    journal_id: Uuid::new_v4(),
                    operation_id: operation.operation_id,
                    checkpoint: InstallationJournalCheckpoint::Staged,
                    staged_file_metadata_json: Some(
                        serde_json::to_string(&JournalStagedSource {
                            target_name: "helper".into(),
                            digest: digest.clone(),
                            commit_sha: fetched.commit_sha.clone(),
                            markdown_base64: base64::engine::general_purpose::STANDARD
                                .encode(&fetched.markdown),
                        })
                        .expect("staged source"),
                    ),
                    prior_file_metadata_json: Some(
                        with_replacement_receipt(
                            prior_file_metadata(&harness.target(), operation.operation_id)
                                .expect("prior metadata")
                                .as_deref(),
                            &compensation,
                        )
                        .expect("replacement receipt metadata"),
                    ),
                    expected_digest: digest,
                },
                2,
            )
            .await
            .expect("persist staged journal before simulated crash");

        assert!(matches!(
            harness.service.begin(request, 99).await,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Installed,
                ..
            }
        ));
        let row = harness
            .db
            .agent_installation(original_id)
            .await
            .expect("read replacement")
            .expect("replacement exists");
        assert_eq!(row.source_revision, Some(fetched.commit_sha));
        assert_eq!(
            row.installation_revision, 2,
            "recovery must not replace twice"
        );
        assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn agent_installation_daemon_complete_checkpoint_replays_without_refetch_or_mutation() {
        let harness = ServiceHarness::new(FetchReply::Failure("must not fetch".into()));
        let request = ServiceHarness::request("complete-replay");
        let operation = match harness
            .db
            .begin_installation_operation(
                request.idempotency_key.clone(),
                request_fingerprint(&request, None),
                InstallationOperationKind::Install,
                None,
                1,
            )
            .await
            .expect("begin operation")
        {
            BeginInstallationOperation::Created(operation) => operation,
            _ => panic!("expected operation"),
        };
        let expected = receipt(
            operation.operation_id,
            AgentInstallationReceiptStatusV1::Installed,
            Some("existing-installation".into()),
            Some("a".repeat(40)),
        );
        harness
            .db
            .record_installation_journal(
                InstallationJournalRow {
                    journal_id: Uuid::new_v4(),
                    operation_id: operation.operation_id,
                    checkpoint: InstallationJournalCheckpoint::Complete,
                    staged_file_metadata_json: None,
                    prior_file_metadata_json: None,
                    expected_digest: "fixture-digest".into(),
                },
                2,
            )
            .await
            .expect("complete journal");
        harness
            .db
            .finish_installation_operation(
                operation.operation_id,
                serde_json::to_string(&expected).expect("receipt JSON"),
                2,
            )
            .await
            .expect("finish operation");
        assert_eq!(harness.service.begin(request, 3).await, expected);
        assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn agent_installation_daemon_unknown_choice_does_not_claim_and_valid_retry_binds() {
        let harness = ServiceHarness::new(FetchReply::Failure("fetch is irrelevant".into()));
        let (_, operation_id, token, choice_id) = prepare_pending_choice(
            &harness,
            "unknown-choice",
            100,
            AgentInstallationOperationKind::Bind,
            false,
        )
        .await;
        let unknown = harness
            .service
            .submit_choice(
                AgentInstallationSubmitChoiceV1 {
                    dto_version: AGENT_INSTALLATION_DTO_VERSION,
                    continuation_token: token.to_string(),
                    choice_id: Some("not-issued".into()),
                    defer: false,
                },
                2,
            )
            .await;
        assert!(matches!(
            unknown,
            AgentInstallationResultV1::Error {
                error: AgentInstallationErrorV1 {
                    code: AgentInstallationErrorCodeV1::UnknownChoice,
                    ..
                }
            }
        ));
        let pending = harness
            .db
            .installation_operation_by_id(operation_id)
            .await
            .expect("operation lookup")
            .expect("operation exists");
        assert_eq!(pending.state, InstallationOperationState::PendingChoice);
        assert_eq!(
            harness
                .db
                .installation_continuation(token)
                .await
                .expect("continuation lookup")
                .expect("continuation exists")
                .submitted_choice_id,
            None
        );
        assert!(matches!(
            harness
                .service
                .submit_choice(
                    AgentInstallationSubmitChoiceV1 {
                        dto_version: AGENT_INSTALLATION_DTO_VERSION,
                        continuation_token: token.to_string(),
                        choice_id: Some(choice_id),
                        defer: false,
                    },
                    3,
                )
                .await,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Bound,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn agent_installation_daemon_defer_is_terminal_and_same_choice_submit_replays_receipt() {
        let harness = ServiceHarness::new(FetchReply::Failure("fetch is irrelevant".into()));
        let (_, _, token, _) = prepare_pending_choice(
            &harness,
            "defer-choice",
            100,
            AgentInstallationOperationKind::Bind,
            false,
        )
        .await;
        let request = AgentInstallationSubmitChoiceV1 {
            dto_version: AGENT_INSTALLATION_DTO_VERSION,
            continuation_token: token.to_string(),
            choice_id: None,
            defer: true,
        };
        let (first, second) = tokio::join!(
            harness.service.submit_choice(request.clone(), 2),
            harness.service.submit_choice(request, 2),
        );
        for result in [first, second] {
            assert!(matches!(
                result,
                AgentInstallationResultV1::Receipt {
                    status: AgentInstallationReceiptStatusV1::PrimaryUnusable,
                    ..
                }
            ));
        }
    }

    #[test]
    fn agent_installation_daemon_every_non_successful_bind_outcome_has_a_typed_terminal_code() {
        use cockpit_db::db::agent_installations::BindAgentOutcome;

        for outcome in [
            BindAgentOutcome::RebindRequired,
            BindAgentOutcome::Conflict,
            BindAgentOutcome::Deleted,
            BindAgentOutcome::NotFound,
        ] {
            assert_eq!(
                terminal_bind_refusal_code(&outcome),
                Some(AgentInstallationErrorCodeV1::StaleBinding)
            );
        }
        assert_eq!(
            terminal_bind_refusal_code(&BindAgentOutcome::Incompatible),
            Some(AgentInstallationErrorCodeV1::IncompatibleModel)
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_claimed_stale_bind_terminalizes_and_replays() {
        let harness = ServiceHarness::new(FetchReply::Failure("fetch is irrelevant".into()));
        let (replay_request, operation_id, token, choice_id) = prepare_pending_choice(
            &harness,
            "stale-terminal",
            100,
            AgentInstallationOperationKind::Bind,
            false,
        )
        .await;
        let state = harness
            .db
            .installation_continuation_state(token)
            .await
            .expect("continuation state")
            .expect("continuation exists");
        let choices: BindChoiceSet =
            serde_json::from_str(&state.continuation.choice_set_json).expect("choice set");
        let installation_id = Uuid::parse_str(&choices.installation_id).expect("installation id");
        harness
            .db
            .delete_agent_installation(installation_id, 2)
            .await
            .expect("delete fixture installation");
        let request = AgentInstallationSubmitChoiceV1 {
            dto_version: AGENT_INSTALLATION_DTO_VERSION,
            continuation_token: token.to_string(),
            choice_id: Some(choice_id),
            defer: false,
        };
        let first = harness.service.submit_choice(request.clone(), 3).await;
        assert!(matches!(
            &first,
            AgentInstallationResultV1::Error {
                error: AgentInstallationErrorV1 {
                    code: AgentInstallationErrorCodeV1::StaleBinding,
                    ..
                }
            }
        ));
        let operation = harness
            .db
            .installation_operation_by_id(operation_id)
            .await
            .expect("operation read")
            .expect("operation exists");
        assert_eq!(operation.state, InstallationOperationState::Terminal);
        assert_eq!(harness.service.submit_choice(request, 4).await, first);
        let BeginInstallationOperation::Replay(replayed) = harness
            .db
            .begin_installation_operation(
                "stale-terminal".into(),
                request_fingerprint(&replay_request, None),
                InstallationOperationKind::Bind,
                None,
                4,
            )
            .await
            .expect("same-key begin replay")
        else {
            panic!("terminal same-key begin must replay")
        };
        assert_eq!(
            serde_json::from_str::<AgentInstallationResultV1>(
                replayed
                    .terminal_receipt_json
                    .as_deref()
                    .expect("terminal receipt")
            )
            .expect("redacted receipt"),
            first
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_shared_dirty_collision_refuses_before_installation_or_binding_mutation()
     {
        let harness = ServiceHarness::new(FetchReply::Source(ServiceHarness::fetched()));
        let workspace = harness._root.path().join("workspace/.cockpit/agents");
        std::fs::create_dir_all(&workspace).expect("shared agent dir");
        std::fs::write(workspace.join("helper.md"), "hand edited").expect("dirty file");
        let mut request = ServiceHarness::request("shared-dirty");
        request.scope = AgentInstallationScopeWire::WorkspaceShared;
        request.workspace_path = Some("workspace-request".into());
        let AgentInstallationResultV1::Error { error } = harness.service.begin(request, 1).await
        else {
            panic!("dirty shared file must refuse")
        };
        assert_eq!(error.code, AgentInstallationErrorCodeV1::DirtySharedFile);
        let installs = harness
            .db
            .list_agent_installations(
                AgentInstallationScope::WorkspaceShared,
                Some("workspace:test".into()),
            )
            .await
            .expect("list shared installs");
        assert!(installs.is_empty());
        let bindings = harness
            .db
            .read(|conn| {
                Ok(
                    conn.query_row("SELECT COUNT(*) FROM agent_model_bindings", [], |row| {
                        row.get::<_, i64>(0)
                    })?,
                )
            })
            .await
            .expect("binding count");
        assert_eq!(bindings, 0);
    }

    #[tokio::test]
    async fn agent_installation_daemon_dirty_update_never_overwrites_the_owned_copy() {
        let harness = ServiceHarness::new(FetchReply::Source(ServiceHarness::fetched()));
        let AgentInstallationResultV1::Receipt {
            installation_id: Some(installation_id),
            ..
        } = harness
            .service
            .begin(ServiceHarness::request("dirty-update-install"), 1)
            .await
        else {
            panic!("initial install must succeed")
        };
        std::fs::write(harness.target(), "locally modified agent").expect("modify owned copy");
        *harness.fetcher.reply.lock().expect("fetcher reply") = FetchReply::Source(FetchedAgentSource {
            commit_sha: "c".repeat(40),
            markdown: b"---\ndescription: refreshed helper\nschemaVersion: 2\nagentId: authored/helper\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: primary\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n---\nrefreshed\n".to_vec(),
        });
        let result = harness
            .service
            .begin(
                AgentInstallationBeginV1 {
                    idempotency_key: "dirty-update".into(),
                    operation: AgentInstallationOperationKind::Update,
                    source_locator: "owner/repo@main:agents/helper.md".into(),
                    target_installation_id: Some(installation_id.clone()),
                    replace_acknowledged: true,
                    ..ServiceHarness::request("dirty-update")
                },
                2,
            )
            .await;
        assert!(matches!(
            result,
            AgentInstallationResultV1::Error { error }
                if error.code == AgentInstallationErrorCodeV1::DirtySharedFile
        ));
        assert_eq!(
            std::fs::read_to_string(harness.target()).expect("owned copy remains readable"),
            "locally modified agent"
        );
        assert_eq!(
            harness
                .db
                .agent_installation(Uuid::parse_str(&installation_id).expect("installation id"))
                .await
                .expect("read installation")
                .expect("installation remains")
                .source_revision,
            Some("a".repeat(40))
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_shared_exact_ref_path_and_digest_replays_without_collision()
    {
        let harness = ServiceHarness::new(FetchReply::Source(ServiceHarness::fetched()));
        let mut first = ServiceHarness::request("shared-first");
        first.scope = AgentInstallationScopeWire::WorkspaceShared;
        first.workspace_path = Some("workspace-request".into());
        assert!(matches!(
            harness.service.begin(first, 1).await,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Installed,
                ..
            }
        ));
        let mut replay = ServiceHarness::request("shared-exact-replay");
        replay.scope = AgentInstallationScopeWire::WorkspaceShared;
        replay.workspace_path = Some("workspace-request".into());
        assert!(matches!(
            harness.service.begin(replay, 2).await,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Installed,
                ..
            }
        ));
        assert_eq!(
            harness
                .db
                .list_agent_installations(
                    AgentInstallationScope::WorkspaceShared,
                    Some("workspace:test".into()),
                )
                .await
                .expect("shared installations")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_install_yes_keeps_install_receipt_and_replays_it() {
        let harness = ServiceHarness::new(FetchReply::Source(ServiceHarness::fetched()));
        let mut request = ServiceHarness::request("install-yes-replay");
        request.auto_select_first_exact = true;
        let first = harness.service.begin(request.clone(), 1).await;
        assert!(matches!(
            &first,
            AgentInstallationResultV1::Receipt {
                status: AgentInstallationReceiptStatusV1::Installed,
                binding_outcome: Some(AgentInstallationBindingOutcomeV1::PrimaryUnusable),
                ..
            }
        ));
        assert_eq!(harness.service.begin(request, 2).await, first);
    }

    fn assert_yes_result_for_kind(
        kind: AgentInstallationOperationKind,
        result: &AgentInstallationResultV1,
    ) {
        match (kind, result) {
            (
                AgentInstallationOperationKind::Install,
                AgentInstallationResultV1::Receipt {
                    status: AgentInstallationReceiptStatusV1::Installed,
                    binding_outcome: Some(AgentInstallationBindingOutcomeV1::Bound),
                    ..
                },
            )
            | (
                AgentInstallationOperationKind::Update,
                AgentInstallationResultV1::Receipt {
                    status: AgentInstallationReceiptStatusV1::Updated,
                    binding_outcome: Some(AgentInstallationBindingOutcomeV1::Bound),
                    ..
                },
            )
            | (
                AgentInstallationOperationKind::Bind,
                AgentInstallationResultV1::Receipt {
                    status: AgentInstallationReceiptStatusV1::Bound,
                    binding_outcome: None,
                    ..
                },
            ) => {}
            _ => panic!("unexpected automatic result for {kind:?}: {result:?}"),
        }
    }

    #[tokio::test]
    async fn agent_installation_daemon_yes_replay_resumes_the_original_kind_and_exact_choice() {
        for (label, kind) in [
            ("install", AgentInstallationOperationKind::Install),
            ("update", AgentInstallationOperationKind::Update),
            ("bind", AgentInstallationOperationKind::Bind),
        ] {
            let harness = ServiceHarness::new(FetchReply::Failure("must not fetch".into()));
            let (request, operation_id, token, choice_id) = prepare_pending_choice(
                &harness,
                &format!("yes-before-submit-{label}"),
                100,
                kind,
                true,
            )
            .await;

            // Crash before automatic submission: a same-key begin must use
            // the persisted exact choice rather than call the fetcher or
            // recompute provider ranking.
            let result = harness.service.begin(request.clone(), 2).await;
            assert_yes_result_for_kind(kind, &result);
            assert_eq!(harness.service.begin(request.clone(), 3).await, result);
            let operation = harness
                .db
                .installation_operation_by_id(operation_id)
                .await
                .expect("operation read")
                .expect("operation exists");
            assert_eq!(operation.kind, operation_kind(kind));
            assert_eq!(
                operation.request_fingerprint,
                request_fingerprint(&request, None)
            );
            assert_eq!(operation.state, InstallationOperationState::Terminal);
            assert_eq!(
                serde_json::from_str::<AgentInstallationResultV1>(
                    operation
                        .terminal_receipt_json
                        .as_deref()
                        .expect("terminal receipt")
                )
                .expect("receipt JSON"),
                result
            );
            let continuation = harness
                .db
                .installation_continuation(token)
                .await
                .expect("continuation read")
                .expect("continuation exists");
            let persisted: BindChoiceSet =
                serde_json::from_str(&continuation.choice_set_json).expect("choice set");
            assert_eq!(
                persisted.auto_choice_id.as_deref(),
                Some(choice_id.as_str())
            );
            assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn agent_installation_daemon_yes_claim_crash_retries_the_original_kind_and_receipt() {
        for (label, kind) in [
            ("install", AgentInstallationOperationKind::Install),
            ("update", AgentInstallationOperationKind::Update),
            ("bind", AgentInstallationOperationKind::Bind),
        ] {
            let harness = ServiceHarness::new(FetchReply::Failure("must not fetch".into()));
            let (request, operation_id, token, choice_id) = prepare_pending_choice(
                &harness,
                &format!("yes-during-submit-{label}"),
                100,
                kind,
                true,
            )
            .await;

            // Simulate a process loss immediately after the continuation CAS
            // succeeds. The retry has to re-enter that exact claim instead of
            // treating the parent Install/Update as a fresh fetch operation.
            assert!(
                harness
                    .db
                    .claim_installation_continuation(token, choice_id.clone(), 2)
                    .await
                    .expect("claim continuation")
                    .is_some()
            );
            let result = harness.service.begin(request.clone(), 3).await;
            assert_yes_result_for_kind(kind, &result);
            assert_eq!(harness.service.begin(request.clone(), 4).await, result);
            let operation = harness
                .db
                .installation_operation_by_id(operation_id)
                .await
                .expect("operation read")
                .expect("operation exists");
            assert_eq!(operation.kind, operation_kind(kind));
            assert_eq!(
                operation.request_fingerprint,
                request_fingerprint(&request, None)
            );
            assert_eq!(operation.state, InstallationOperationState::Terminal);
            assert_eq!(
                serde_json::from_str::<AgentInstallationResultV1>(
                    operation
                        .terminal_receipt_json
                        .as_deref()
                        .expect("terminal receipt")
                )
                .expect("receipt JSON"),
                result
            );
            assert_eq!(harness.fetcher.calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn agent_installation_daemon_binding_choices_keep_author_collisions_alias_order_and_unsuggested_offerings_distinct()
     {
        let offerings = vec![
            AgentProfileModelOffering {
                offering_id: "a-route".into(),
                provider_profile_handle: "profile-a".into(),
                provider_id: "provider".into(),
                model_id: "exact".into(),
            },
            AgentProfileModelOffering {
                offering_id: "b-route".into(),
                provider_profile_handle: "profile-b".into(),
                provider_id: "provider".into(),
                model_id: "exact".into(),
            },
            AgentProfileModelOffering {
                offering_id: "fuzzy-route".into(),
                provider_profile_handle: "profile-c".into(),
                provider_id: "provider".into(),
                model_id: "exact-latest".into(),
            },
        ];
        let slot = slot(
            vec![ModelCapability::TextGeneration],
            vec![
                recommendation("first", "upstream/one", &[("provider", "exact")]),
                recommendation("second", "upstream/two", &[("provider", "exact")]),
                recommendation("unmatched", "upstream/three", &[("other", "missing")]),
            ],
        );
        let ranked = crate::agents::ranked_compatible_offerings(
            &slot,
            &offerings,
            &providers_for(&offerings),
        );
        let (choices, unmatched) = binding_choices("primary", &slot, &ranked);
        assert_eq!(
            choices
                .iter()
                .map(|choice| choice.choice_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "choice-0-offering-0",
                "choice-0-offering-1",
                "choice-1-offering-0",
                "choice-1-offering-1",
                "choice-local-offering-2",
            ]
        );
        assert!(choices[..4].iter().all(|choice| {
            choice.exact_alias_match
                && choice.author_suggested
                && choice.canonical_upstream_identity.is_some()
        }));
        assert!(!choices[4].author_suggested);
        assert!(
            !choices[4].exact_alias_match,
            "fuzzy names must not match aliases"
        );
        assert_eq!(unmatched.len(), 1);
        assert_eq!(unmatched[0].recommendation_id, "unmatched");
        assert_eq!(
            first_exact_author_choice(&choices).as_deref(),
            Some("choice-0-offering-0"),
            "--yes selects only the first ordered exact author route"
        );
        assert!(first_exact_author_choice(&choices[4..]).is_none());
    }

    #[test]
    fn agent_installation_daemon_binding_choices_refuse_unknown_hard_capabilities() {
        let offerings = vec![AgentProfileModelOffering {
            offering_id: "candidate".into(),
            provider_profile_handle: "profile".into(),
            provider_id: "provider".into(),
            model_id: "model".into(),
        }];
        let slot = slot(
            vec![
                ModelCapability::TextGeneration,
                ModelCapability::ToolCalling,
            ],
            vec![recommendation(
                "needs-tools",
                "upstream/tools",
                &[("provider", "model")],
            )],
        );
        let ranked = crate::agents::ranked_compatible_offerings(
            &slot,
            &offerings,
            &providers_for(&offerings),
        );
        assert!(
            ranked.is_empty(),
            "unknown host capability must fail closed"
        );
        let (choices, unmatched) = binding_choices("primary", &slot, &ranked);
        assert!(choices.is_empty());
        assert_eq!(unmatched[0].recommendation_id, "needs-tools");
    }

    #[test]
    fn agent_installation_daemon_choice_routes_preserve_exact_profile_handles_without_leaking_them()
    {
        let offerings = vec![
            AgentProfileModelOffering {
                offering_id: "profile-work:model".into(),
                provider_profile_handle: "profile-work".into(),
                provider_id: "vendor".into(),
                model_id: "model".into(),
            },
            AgentProfileModelOffering {
                offering_id: "profile-personal:model".into(),
                provider_profile_handle: "profile-personal".into(),
                provider_id: "vendor".into(),
                model_id: "model".into(),
            },
        ];
        let slot = slot(
            vec![ModelCapability::TextGeneration],
            vec![recommendation(
                "recommended",
                "upstream/vendor-model",
                &[("vendor", "model")],
            )],
        );
        let mut providers = ProvidersConfig::default();
        for profile_handle in ["profile-work", "profile-personal"] {
            let mut entry = ProviderEntry::default();
            entry.template = Some("vendor".into());
            entry.models.push(ModelEntry {
                id: "model".into(),
                context_length: Some(128),
                ..ModelEntry::default()
            });
            providers.providers.insert(profile_handle.into(), entry);
        }
        let ranked = crate::agents::ranked_compatible_offerings(&slot, &offerings, &providers);
        let (choices, _) = binding_choices("primary", &slot, &ranked);
        let routes = durable_binding_routes(&ranked, &choices).expect("exact durable routes");
        assert_eq!(routes.len(), 2);
        assert_eq!(
            routes
                .iter()
                .map(|route| route.provider_profile_handle.as_str())
                .collect::<Vec<_>>(),
            vec!["profile-personal", "profile-work"]
        );
        let wire = serde_json::to_string(&choices).expect("wire choices");
        assert!(!wire.contains("profile-work"));
        assert!(!wire.contains("profile-personal"));
        let needs_choice_wire = serde_json::to_string(&AgentInstallationResultV1::NeedsChoice {
            continuation_token: "redacted-continuation".into(),
            choices: choices.clone(),
            unmatched_recommendations: vec![],
            expires_at_unix_ms: 1,
        })
        .expect("wire result");
        assert!(!needs_choice_wire.contains("profile-work"));
        assert!(!needs_choice_wire.contains("profile-personal"));
        let error_wire = serde_json::to_string(&redacted_error(anyhow::anyhow!(
            "profile-work credential route failed"
        )))
        .expect("redacted error wire");
        assert!(!error_wire.contains("profile-work"));
        assert!(!error_wire.contains("credential route"));
        let durable = serde_json::to_string(&routes).expect("durable route mapping");
        assert!(durable.contains("profile-work"));
        assert!(durable.contains("profile-personal"));
        assert!(!durable.contains("credential"));
        let mut persisted = BindChoiceSet {
            installation_id: Uuid::new_v4().to_string(),
            definition_digest: "definition-digest".into(),
            choices,
            unmatched_recommendations: vec![],
            routes,
            parent_receipt_status: None,
            parent_source_revision: None,
            auto_choice_id: None,
        };
        assert!(validate_durable_choice_set(&persisted).is_ok());
        persisted.routes.push(DurableBindingRoute {
            choice_id: persisted.routes[0].choice_id.clone(),
            provider_profile_handle: "profile-other".into(),
        });
        assert!(validate_durable_choice_set(&persisted).is_err());
    }

    #[test]
    fn agent_installation_daemon_custom_profile_key_never_becomes_a_wire_provider_id() {
        let offerings = vec![AgentProfileModelOffering {
            offering_id: "profile-secret:model".into(),
            provider_profile_handle: "profile-secret".into(),
            provider_id: "profile-secret".into(),
            model_id: "model".into(),
        }];
        let slot = slot(vec![ModelCapability::TextGeneration], vec![]);
        let (choices, _) = binding_choices("primary", &slot, &offerings);
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].provider_id, "configured-provider-0");
        let wire = serde_json::to_string(&choices).expect("wire choices");
        assert!(!wire.contains("profile-secret"));
        let routes = durable_binding_routes(&offerings, &choices).expect("durable route");
        assert_eq!(routes[0].provider_profile_handle, "profile-secret");
    }

    /// This target is intentionally exercised by `cargo test --release` in
    /// the release matrix.  The fixture loader and its environment variable
    /// are both cfg(debug_assertions), so a release daemon has no selectable
    /// scripted-fetch path at all.
    #[cfg(not(debug_assertions))]
    #[test]
    fn agent_installation_daemon_release_build_compiles_out_debug_fixture_control() {
        assert!(!cfg!(debug_assertions));
    }

    #[cfg(debug_assertions)]
    #[test]
    fn agent_installation_daemon_debug_fixture_rejects_credential_or_transport_fields() {
        let commit_sha = "b".repeat(40);
        let value = serde_json::json!({
            "commit_sha": commit_sha,
            "markdown": "fixture",
            "workspace_path": ".",
            "providers": {
                "profile": {
                    "template": "vendor",
                    "headers": [{"name": "Authorization", "value": "not-allowed"}]
                }
            }
        });
        assert!(serde_json::from_value::<DebugAgentInstallationFixture>(value).is_err());
    }
}
