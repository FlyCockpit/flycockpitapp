//! Process-boundary invariants for the daemon-owned agent-management CLI.
//!
//! The detailed fetch, filesystem, binding-ranking, and recovery scenarios
//! belong to the daemon service. These tests freeze the CLI boundary: typed
//! DTO transport only, explicit command grammar, and secret-safe rendering.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use cockpit_cli::integration_test_api::agent_installation::{
    AgentInstallationFetcher, AgentInstallationService, AgentWorkspaceAuthorizer,
    CanonicalAgentSource, FetchedAgentSource,
};
use cockpit_config::config::providers::ProvidersConfig;
use cockpit_proto::{
    AGENT_INSTALLATION_DTO_VERSION, AgentInstallationBeginV1, AgentInstallationErrorCodeV1,
    AgentInstallationExecutionKindV1, AgentInstallationOperationKind, AgentInstallationReadV1,
    AgentInstallationReceiptStatusV1, AgentInstallationResultV1, AgentInstallationScopeWire,
    AgentInstallationSlotBindingStateV1,
};
use rusqlite::Connection;
use serde_json::json;

use crate::support::{SpawnedDaemon, output_text};

struct ScriptedFetcher;

#[async_trait]
impl AgentInstallationFetcher for ScriptedFetcher {
    async fn fetch_github_markdown(
        &self,
        _source: &CanonicalAgentSource,
    ) -> Result<FetchedAgentSource> {
        Ok(FetchedAgentSource {
            commit_sha: "a".repeat(40),
            markdown: b"---\ndescription: fixture\nschemaVersion: 1\nagentId: authored/helper\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: primary\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n---\nfixture\n".to_vec(),
        })
    }
}

struct FixtureWorkspace {
    root: PathBuf,
}

#[async_trait]
impl AgentWorkspaceAuthorizer for FixtureWorkspace {
    async fn authorize_workspace(&self, client_path: &str) -> Result<(String, PathBuf)> {
        anyhow::ensure!(
            client_path == "fixture-workspace",
            "workspace is not authorized"
        );
        Ok(("workspace:fixture".into(), self.root.clone()))
    }
}

fn fixture_service() -> (tempfile::TempDir, AgentInstallationService) {
    let root = tempfile::tempdir().expect("fixture root");
    let workspace = root.path().join("workspace");
    std::fs::create_dir_all(&workspace).expect("fixture workspace");
    let db = cockpit_cli::db::Db::open_in_memory().expect("fixture DB");
    let service = AgentInstallationService::new(
        db,
        root.path().join("agents"),
        Arc::new(ScriptedFetcher),
        Arc::new(FixtureWorkspace { root: workspace }),
        ProvidersConfig::default(),
    );
    (root, service)
}

fn begin(key: &str, operation: AgentInstallationOperationKind) -> AgentInstallationBeginV1 {
    AgentInstallationBeginV1 {
        dto_version: AGENT_INSTALLATION_DTO_VERSION,
        idempotency_key: key.into(),
        operation,
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

fn socket_fixture(exact_route: bool) -> serde_json::Value {
    let exact_models = if exact_route {
        json!([
            {"id": "exact-a", "context_length": 128},
            {"id": "exact-b", "context_length": 128}
        ])
    } else {
        json!([])
    };
    json!({
        "commit_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "workspace_path": ".",
        "markdown": "---\ndescription: socket fixture\nschemaVersion: 1\nagentId: authored/helper\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: primary\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n    suggestedModels:\n      - recommendationId: exact-a\n        upstreamIdentity: upstream/exact-a\n        providerAliases:\n          - providerId: vendor\n            modelId: exact-a\n      - recommendationId: exact-b\n        upstreamIdentity: upstream/exact-b\n        providerAliases:\n          - providerId: vendor\n            modelId: exact-b\n      - recommendationId: unmatched\n        upstreamIdentity: upstream/unmatched\n  optional:\n    purpose: optional\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n    suggestedModels:\n      - recommendationId: exact-a\n        upstreamIdentity: upstream/exact-a\n        providerAliases:\n          - providerId: vendor\n            modelId: exact-a\n  vision:\n    purpose: vision\n    minContextTokens: 1\n    requiredCapabilities: [vision]\n    locality: any\n    allowDefaultFallback: false\n---\nfixture\n",
        "providers": {
            "profile-exact": {
                "template": "vendor",
                "models": exact_models
            },
            "profile-local": {
                "template": "local",
                "models": [{"id": "compatible", "context_length": 128}]
            }
        }
    })
}

fn fixture_for_daemon(daemon_workspace: &std::path::Path, exact_route: bool) -> serde_json::Value {
    let mut fixture = socket_fixture(exact_route);
    fixture["workspace_path"] = json!(daemon_workspace);
    fixture
}

fn invalid_manifest_fixture(daemon_workspace: &std::path::Path) -> serde_json::Value {
    let mut fixture = fixture_for_daemon(daemon_workspace, true);
    // Intentionally syntactically valid frontmatter with no vNext contract.
    // This exercises the real socket fetch/parse path rather than a CLI-side
    // validation shortcut.
    fixture["markdown"] = json!(
        "---\ndescription: invalid socket fixture\nschemaVersion: 1\nagentId: authored/helper\nexecutionKind: coding\n---\nmissing model slots\n"
    );
    fixture
}

fn agent_mutation_counts(daemon: &SpawnedDaemon) -> (i64, i64) {
    let conn = Connection::open(daemon.db_path()).expect("open daemon database for assertion");
    let installations = conn
        .query_row("SELECT COUNT(*) FROM agent_installations", [], |row| {
            row.get(0)
        })
        .expect("count daemon installations");
    let operations = conn
        .query_row("SELECT COUNT(*) FROM installation_operations", [], |row| {
            row.get(0)
        })
        .expect("count daemon operations");
    (installations, operations)
}

fn current_binding_revision(daemon: &SpawnedDaemon) -> i64 {
    let conn = Connection::open(daemon.db_path()).expect("open daemon database for binding");
    conn.query_row(
        "SELECT binding_revision FROM agent_model_bindings WHERE retired_at_unix_ms IS NULL",
        [],
        |row| row.get(0),
    )
    .expect("read current binding revision")
}

fn transcript_field(output: &str, field: &str) -> String {
    output
        .lines()
        .find_map(|line| {
            line.split_whitespace()
                .find_map(|part| part.strip_prefix(field).map(str::to_owned))
        })
        .unwrap_or_else(|| panic!("missing {field} in transcript: {output}"))
}

fn receipt_payload(output: &str) -> &str {
    output
        .split_once(": ")
        .map(|(_, receipt)| receipt.trim())
        .unwrap_or_else(|| panic!("missing rendered receipt in transcript: {output}"))
}

fn fixture_revision(mut fixture: serde_json::Value, marker: char) -> serde_json::Value {
    fixture["commit_sha"] = json!(marker.to_string().repeat(40));
    let markdown = fixture["markdown"]
        .as_str()
        .expect("fixture Markdown")
        .replace("socket fixture", &format!("socket fixture {marker}"));
    fixture["markdown"] = json!(markdown);
    fixture
}

async fn replace_socket_fixture(daemon: &SpawnedDaemon, fixture: &serde_json::Value) {
    let path = daemon
        .home()
        .home_dir()
        .join("agent-installation-fixture.json");
    std::fs::write(
        path,
        serde_json::to_vec(fixture).expect("serialize replacement fixture"),
    )
    .expect("replace non-secret agent fixture");
    let restart = daemon
        .command()
        .args(["daemon", "restart", "--grace", "0"])
        .output()
        .expect("restart fixture daemon");
    assert!(restart.status.success(), "{}", output_text(&restart));
    daemon.wait_for_handshake().await;
}

fn installation_id(output: &str) -> String {
    output
        .split("installation=")
        .nth(1)
        .and_then(|value| value.split_whitespace().next())
        .expect("agent result renders daemon installation id")
        .to_owned()
}

#[tokio::test]
async fn agent_cli_management_daemon_install_malformed_source_and_create_collision() {
    let (_root, service) = fixture_service();
    let malformed = service
        .begin(
            AgentInstallationBeginV1 {
                source_locator: "not-a-github-locator".into(),
                ..begin("malformed", AgentInstallationOperationKind::Install)
            },
            1,
        )
        .await;
    assert!(matches!(
        malformed,
        AgentInstallationResultV1::Error { error }
            if error.code == AgentInstallationErrorCodeV1::InvalidRequest
    ));

    let installed = service
        .begin(
            begin(
                "install-provenance",
                AgentInstallationOperationKind::Install,
            ),
            2,
        )
        .await;
    assert!(matches!(
        installed,
        AgentInstallationResultV1::Receipt {
            status: AgentInstallationReceiptStatusV1::Installed,
            source_revision: Some(ref revision),
            ..
        } if revision == &"a".repeat(40)
    ));

    let mut create = begin("create", AgentInstallationOperationKind::Create);
    create.source_locator = "authored/local-helper".into();
    create.execution_kind = Some(AgentInstallationExecutionKindV1::Coding);
    create.primary_slot_id = Some("primary".into());
    assert!(matches!(
        service.begin(create, 2).await,
        AgentInstallationResultV1::Receipt {
            status: AgentInstallationReceiptStatusV1::Created,
            ..
        }
    ));
    let mut workspace_create = begin("create-workspace", AgentInstallationOperationKind::Create);
    workspace_create.scope = AgentInstallationScopeWire::WorkspaceShared;
    workspace_create.workspace_path = Some("fixture-workspace".into());
    workspace_create.source_locator = "authored/local-helper".into();
    workspace_create.execution_kind = Some(AgentInstallationExecutionKindV1::Coding);
    workspace_create.primary_slot_id = Some("primary".into());
    assert!(matches!(
        service.begin(workspace_create, 3).await,
        AgentInstallationResultV1::Receipt {
            status: AgentInstallationReceiptStatusV1::Created,
            ..
        }
    ));
    let listed = service
        .list(AgentInstallationReadV1 {
            dto_version: AGENT_INSTALLATION_DTO_VERSION,
            scope: AgentInstallationScopeWire::Global,
            workspace_path: None,
            installation_id: None,
        })
        .await;
    let AgentInstallationResultV1::Listed { installations } = listed else {
        panic!("list must return created provenance")
    };
    assert!(matches!(
        installations[0].bindings.as_slice(),
        [binding] if binding.slot_id == "primary"
            && binding.state == AgentInstallationSlotBindingStateV1::PrimaryUnusable
    ));
    let workspace_list = service
        .list(AgentInstallationReadV1 {
            dto_version: AGENT_INSTALLATION_DTO_VERSION,
            scope: AgentInstallationScopeWire::WorkspaceShared,
            workspace_path: Some("fixture-workspace".into()),
            installation_id: None,
        })
        .await;
    let AgentInstallationResultV1::Listed { installations } = workspace_list else {
        panic!("workspace list must return shared provenance")
    };
    assert_eq!(installations.len(), 1);
    assert_eq!(
        installations[0].scope,
        AgentInstallationScopeWire::WorkspaceShared
    );
    assert_eq!(installations[0].source_agent_id, "authored/local-helper");
    assert!(installations[0].bindings.is_empty());
    let workspace_installation_id = installations[0].installation_id.clone();
    let workspace_inspect = service
        .inspect(AgentInstallationReadV1 {
            dto_version: AGENT_INSTALLATION_DTO_VERSION,
            scope: AgentInstallationScopeWire::WorkspaceShared,
            workspace_path: Some("fixture-workspace".into()),
            installation_id: Some(workspace_installation_id),
        })
        .await;
    let AgentInstallationResultV1::Inspected {
        installation: Some(installation),
    } = workspace_inspect
    else {
        panic!("shared inspect must return provenance")
    };
    let workspace_json = serde_json::to_string(&installation).expect("shared record JSON");
    assert!(installation.bindings.is_empty());
    assert!(!workspace_json.contains("bindings"));
    let mut collision = begin("create-collision", AgentInstallationOperationKind::Create);
    collision.source_locator = "authored/local-helper".into();
    collision.execution_kind = Some(AgentInstallationExecutionKindV1::Coding);
    collision.primary_slot_id = Some("primary".into());
    let collision = service.begin(collision, 3).await;
    assert!(
        matches!(
            collision,
            AgentInstallationResultV1::Error { ref error }
                if error.code == AgentInstallationErrorCodeV1::Collision
        ),
        "unexpected create collision result: {collision:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_cli_management_socket_default_daemon_create_list_and_collision_render_daemon_state()
{
    let daemon = SpawnedDaemon::start().await;
    let missing_workspace = daemon
        .command()
        .args([
            "agent",
            "install",
            "owner/repo:agents/helper.md",
            "--scope",
            "workspace",
        ])
        .output()
        .expect("run missing-workspace validation");
    assert_eq!(missing_workspace.status.code(), Some(64));
    assert!(output_text(&missing_workspace).contains("--workspace is required"));

    let create = daemon
        .command()
        .args([
            "agent",
            "create",
            "socket-helper",
            "--scope",
            "global",
            "--execution-kind",
            "coding",
        ])
        .output()
        .expect("run daemon-backed create");
    assert!(create.status.success(), "{}", output_text(&create));
    let created = output_text(&create);
    assert!(created.contains("status=created"));
    let installation_id = created
        .split("installation=")
        .nth(1)
        .and_then(|value| value.split_whitespace().next())
        .expect("create renders daemon installation id")
        .to_owned();

    let inspect_text = daemon
        .command()
        .args(["agent", "inspect", &installation_id])
        .output()
        .expect("run daemon-backed inspect text");
    assert!(
        inspect_text.status.success(),
        "{}",
        output_text(&inspect_text)
    );
    assert!(output_text(&inspect_text).contains("scope=Global"));
    assert!(output_text(&inspect_text).contains("digest="));
    assert!(output_text(&inspect_text).contains("binding=primary=PrimaryUnusable"));

    let inspect_json = daemon
        .command()
        .args(["agent", "inspect", &installation_id, "--json"])
        .output()
        .expect("run daemon-backed inspect JSON");
    assert!(
        inspect_json.status.success(),
        "{}",
        output_text(&inspect_json)
    );
    let inspect_json = output_text(&inspect_json);
    assert!(inspect_json.contains("\"outcome\":\"inspected\""));
    assert!(inspect_json.contains("\"source_digest\""));
    assert!(inspect_json.contains("\"primary_unusable\""));

    let list = daemon
        .command()
        .args(["agent", "list", "--json"])
        .output()
        .expect("run daemon-backed list");
    assert!(list.status.success(), "{}", output_text(&list));
    let json = output_text(&list);
    assert!(json.contains("authored/socket-helper"));
    assert!(json.contains("primary_unusable"));
    assert!(!json.contains("provider_profile_handle"));

    let collision = daemon
        .command()
        .args([
            "agent",
            "create",
            "socket-helper",
            "--scope",
            "global",
            "--execution-kind",
            "coding",
        ])
        .output()
        .expect("run daemon-backed create collision");
    assert_eq!(
        collision.status.code(),
        Some(4),
        "{}",
        output_text(&collision)
    );
}

#[test]
fn agent_cli_management_non_tty_install_requires_explicit_scope_before_daemon_contact() {
    let home = crate::support::IsolatedHome::new();
    let result = home
        .cockpit()
        .args(["agent", "install", "owner/repo:agents/helper.md"])
        .output()
        .expect("run non-tty install without scope");
    assert_eq!(result.status.code(), Some(64), "{}", output_text(&result));
    assert!(output_text(&result).contains("--scope is required outside an interactive terminal"));
    assert!(
        !home.socket_path().exists(),
        "usage rejection must happen before attempting daemon startup"
    );
}

#[cfg(debug_assertions)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_cli_management_socket_invalid_manifest_is_typed_and_has_zero_mutation() {
    let bootstrap = crate::support::IsolatedHome::new();
    let workspace = bootstrap.project_path().to_path_buf();
    let daemon = SpawnedDaemon::start_with_home_agent_installation_fixture(
        bootstrap,
        &invalid_manifest_fixture(&workspace),
    )
    .await;
    let result = daemon
        .command()
        .args([
            "agent",
            "install",
            "owner/repo@main:agents/helper.md",
            "--scope",
            "global",
            "--operation-key",
            "invalid-manifest-socket",
        ])
        .output()
        .expect("request invalid manifest through socket daemon");
    assert_eq!(result.status.code(), Some(1), "{}", output_text(&result));
    assert!(
        output_text(&result).contains("agent installation request was refused"),
        "the CLI must render the daemon's fixed typed refusal"
    );
    assert_eq!(
        agent_mutation_counts(&daemon),
        (0, 0),
        "invalid source must create neither installation nor operation"
    );
    assert!(
        !daemon
            .home()
            .xdg_state_home()
            .join("cockpit/agents/helper.md")
            .exists(),
        "invalid source must not create an owned file"
    );
}

/// Exercises the public binary against a real socket daemon.  The daemon's
/// debug-only fixture provides deterministic fetch/catalog/workspace authority
/// without giving the CLI filesystem, credential, or provider-route access.
#[cfg(debug_assertions)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_cli_management_socket_bind_choice_defer_rebind_yes_and_capability_matrix() {
    let bootstrap = crate::support::IsolatedHome::new();
    let workspace = bootstrap.project_path().to_path_buf();
    let fixture = fixture_for_daemon(&workspace, true);
    let daemon =
        SpawnedDaemon::start_with_home_agent_installation_fixture(bootstrap, &fixture).await;

    let install = daemon
        .command()
        .args([
            "agent",
            "install",
            "owner/repo@main:agents/helper.md",
            "--scope",
            "global",
        ])
        .output()
        .expect("install fixture agent");
    assert!(install.status.success(), "{}", output_text(&install));
    let installation = installation_id(&output_text(&install));

    let needs_choice = daemon
        .command()
        .args(["agent", "bind", &installation, "--slot", "primary"])
        .output()
        .expect("render binding choices");
    assert_eq!(needs_choice.status.code(), Some(3));
    let choices = output_text(&needs_choice);
    assert!(choices.contains("provider=vendor model=exact-a"));
    assert!(choices.contains("provider=vendor model=exact-b"));
    assert!(choices.contains("provider=local model=compatible"));
    assert!(choices.contains("unmatched-recommendation=unmatched upstream=upstream/unmatched"));
    let exact_a = choices.find("model=exact-a").expect("first exact route");
    let exact_b = choices.find("model=exact-b").expect("second exact route");
    let local = choices.find("model=compatible").expect("local route");
    assert!(
        exact_a < exact_b && exact_b < local,
        "author exact aliases must retain recommendation order before compatible local routes: {choices}"
    );

    let unmatched = daemon
        .command()
        .args([
            "agent",
            "bind",
            &installation,
            "--slot",
            "primary",
            "--provider-profile",
            "vendor",
            "--model",
            "not-offered",
        ])
        .output()
        .expect("refuse unmatched displayed selector");
    assert_eq!(unmatched.status.code(), Some(5));
    assert!(output_text(&unmatched).contains("not a daemon-confirmed compatible choice"));

    let unsuggested = daemon
        .command()
        .args([
            "agent",
            "bind",
            &installation,
            "--slot",
            "optional",
            "--provider-profile",
            "local",
            "--model",
            "compatible",
        ])
        .output()
        .expect("bind unsuggested compatible route");
    assert!(
        unsuggested.status.success(),
        "{}",
        output_text(&unsuggested)
    );
    assert!(output_text(&unsuggested).contains("status=bound"));

    let exact = daemon
        .command()
        .args([
            "agent",
            "bind",
            &installation,
            "--slot",
            "primary",
            "--provider-profile",
            "vendor",
            "--model",
            "exact-a",
        ])
        .output()
        .expect("bind exact displayed route");
    assert!(exact.status.success(), "{}", output_text(&exact));

    let rebind = daemon
        .command()
        .args([
            "agent",
            "bind",
            &installation,
            "--slot",
            "primary",
            "--provider-profile",
            "vendor",
            "--model",
            "exact-b",
        ])
        .output()
        .expect("rebind a different exact displayed route");
    assert!(rebind.status.success(), "{}", output_text(&rebind));
    assert!(output_text(&rebind).contains("status=bound"));

    let deferred_optional = daemon
        .command()
        .args([
            "agent",
            "bind",
            &installation,
            "--slot",
            "optional",
            "--defer",
        ])
        .output()
        .expect("defer optional slot");
    assert_eq!(deferred_optional.status.code(), Some(6));
    assert!(output_text(&deferred_optional).contains("optional slot remains unbound"));

    let deferred_primary = daemon
        .command()
        .args([
            "agent",
            "bind",
            &installation,
            "--slot",
            "primary",
            "--defer",
        ])
        .output()
        .expect("defer primary slot");
    assert_eq!(deferred_primary.status.code(), Some(5));
    assert!(output_text(&deferred_primary).contains("primary slot remains unbound"));

    let exact_yes = daemon
        .command()
        .args(["agent", "bind", &installation, "--slot", "primary", "--yes"])
        .output()
        .expect("bind first exact author route with yes");
    assert!(exact_yes.status.success(), "{}", output_text(&exact_yes));
    assert!(output_text(&exact_yes).contains("status=bound"));
    let inspect_after_yes = daemon
        .command()
        .args(["agent", "inspect", &installation])
        .output()
        .expect("inspect first exact yes binding");
    assert!(
        inspect_after_yes.status.success(),
        "{}",
        output_text(&inspect_after_yes)
    );
    assert!(
        output_text(&inspect_after_yes).contains("binding=primary=Bound(exact-a)"),
        "--yes must bind the first exact author choice, not rerank a local route: {}",
        output_text(&inspect_after_yes)
    );

    let capability_refusal = daemon
        .command()
        .args(["agent", "bind", &installation, "--slot", "vision"])
        .output()
        .expect("refuse missing hard vision capability");
    assert_eq!(capability_refusal.status.code(), Some(6));
    assert!(output_text(&capability_refusal).contains("optional slot remains unbound"));
}

#[cfg(debug_assertions)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_cli_management_socket_submit_choice_transcript_replays_the_same_receipt_once() {
    let bootstrap = crate::support::IsolatedHome::new();
    let workspace = bootstrap.project_path().to_path_buf();
    let fixture = fixture_for_daemon(&workspace, true);
    let daemon =
        SpawnedDaemon::start_with_home_agent_installation_fixture(bootstrap, &fixture).await;
    let install = daemon
        .command()
        .args([
            "agent",
            "install",
            "owner/repo@main:agents/helper.md",
            "--scope",
            "global",
        ])
        .output()
        .expect("install transcript fixture");
    assert!(install.status.success(), "{}", output_text(&install));
    let installation = installation_id(&output_text(&install));

    let begin = daemon
        .command()
        .args([
            "agent",
            "bind",
            &installation,
            "--slot",
            "primary",
            "--operation-key",
            "socket-choice-replay",
        ])
        .output()
        .expect("begin socket continuation");
    assert_eq!(begin.status.code(), Some(3), "{}", output_text(&begin));
    let choice_text = output_text(&begin);
    let continuation = transcript_field(&choice_text, "continuation=");
    let choice_id = transcript_field(&choice_text, "choice=");

    let first = daemon
        .command()
        .args(["agent", "submit-choice", &continuation, &choice_id])
        .output()
        .expect("submit daemon-issued choice");
    assert!(first.status.success(), "{}", output_text(&first));
    let first_text = output_text(&first);
    assert_eq!(current_binding_revision(&daemon), 1);

    let repeated_submit = daemon
        .command()
        .args(["agent", "submit-choice", &continuation, &choice_id])
        .output()
        .expect("replay submitted daemon-issued choice");
    assert!(
        repeated_submit.status.success(),
        "{}",
        output_text(&repeated_submit)
    );
    let repeated_text = output_text(&repeated_submit);
    assert_eq!(
        receipt_payload(&repeated_text),
        receipt_payload(&first_text),
        "same continuation submit must replay its terminal receipt"
    );

    let replay_begin = daemon
        .command()
        .args([
            "agent",
            "bind",
            &installation,
            "--slot",
            "primary",
            "--operation-key",
            "socket-choice-replay",
        ])
        .output()
        .expect("replay same operation key");
    assert!(
        replay_begin.status.success(),
        "{}",
        output_text(&replay_begin)
    );
    let replay_text = output_text(&replay_begin);
    assert_eq!(
        receipt_payload(&replay_text),
        receipt_payload(&first_text),
        "same operation-key begin must replay the same terminal receipt"
    );
    assert_eq!(
        current_binding_revision(&daemon),
        1,
        "replays must not create a second binding revision"
    );
}

#[cfg(debug_assertions)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_cli_management_socket_yes_only_accepts_exact_author_choice() {
    let bootstrap = crate::support::IsolatedHome::new();
    let workspace = bootstrap.project_path().to_path_buf();
    let fixture = fixture_for_daemon(&workspace, false);
    let daemon =
        SpawnedDaemon::start_with_home_agent_installation_fixture(bootstrap, &fixture).await;
    let result = daemon
        .command()
        .args([
            "agent",
            "install",
            "owner/repo@main:agents/helper.md",
            "--scope",
            "global",
            "--yes",
        ])
        .output()
        .expect("install without exact default");
    assert_eq!(result.status.code(), Some(5));
    let output = output_text(&result);
    assert!(output.contains("status=installed"));
    assert!(output.contains("binding=primary-unusable"));
}

#[cfg(debug_assertions)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_cli_management_socket_hard_capability_refusal_preserves_primary_and_optional_exit_codes()
 {
    let bootstrap = crate::support::IsolatedHome::new();
    let workspace = bootstrap.project_path().to_path_buf();
    let mut fixture = fixture_for_daemon(&workspace, true);
    let markdown = fixture["markdown"]
        .as_str()
        .expect("fixture Markdown")
        .replacen(
            "requiredCapabilities: [text_generation]",
            "requiredCapabilities: [vision]",
            1,
        );
    fixture["markdown"] = json!(markdown);
    for provider in fixture["providers"]
        .as_object_mut()
        .expect("fixture providers")
        .values_mut()
    {
        for model in provider["models"].as_array_mut().expect("fixture models") {
            model["capabilities"] = json!({"image_input": "unsupported"});
        }
    }
    let daemon =
        SpawnedDaemon::start_with_home_agent_installation_fixture(bootstrap, &fixture).await;
    let install = daemon
        .command()
        .args([
            "agent",
            "install",
            "owner/repo@main:agents/helper.md",
            "--scope",
            "global",
        ])
        .output()
        .expect("install hard-capability fixture");
    assert!(install.status.success(), "{}", output_text(&install));
    let installation = installation_id(&output_text(&install));
    let primary = daemon
        .command()
        .args(["agent", "bind", &installation, "--slot", "primary"])
        .output()
        .expect("refuse unsupported primary vision route");
    assert_eq!(primary.status.code(), Some(5));
    assert!(output_text(&primary).contains("primary slot remains unbound"));
    let optional = daemon
        .command()
        .args(["agent", "bind", &installation, "--slot", "vision"])
        .output()
        .expect("refuse unsupported optional vision route");
    assert_eq!(optional.status.code(), Some(6));
    assert!(output_text(&optional).contains("optional slot remains unbound"));
}

#[cfg(debug_assertions)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_cli_management_socket_update_targets_exact_installation_and_never_overwrites_dirty_copy()
 {
    let bootstrap = crate::support::IsolatedHome::new();
    let workspace = bootstrap.project_path().to_path_buf();
    let first_fixture = fixture_revision(fixture_for_daemon(&workspace, true), 'b');
    let daemon =
        SpawnedDaemon::start_with_home_agent_installation_fixture(bootstrap, &first_fixture).await;
    let install = daemon
        .command()
        .args([
            "agent",
            "install",
            "owner/repo@main:agents/helper.md",
            "--scope",
            "global",
        ])
        .output()
        .expect("install initial update fixture");
    assert!(install.status.success(), "{}", output_text(&install));
    let installation = installation_id(&output_text(&install));
    let before = daemon
        .command()
        .args(["agent", "inspect", &installation])
        .output()
        .expect("inspect initial installation");
    assert!(before.status.success(), "{}", output_text(&before));
    let before = output_text(&before);
    assert!(before.contains(&"b".repeat(40)));

    let no_acknowledgement = daemon
        .command()
        .args([
            "agent",
            "update",
            &installation,
            "--source",
            "owner/repo@next:agents/helper.md",
        ])
        .output()
        .expect("require update replacement acknowledgement");
    assert!(!no_acknowledgement.status.success());
    assert!(output_text(&no_acknowledgement).contains("--replace"));

    let mismatch = daemon
        .command()
        .args([
            "agent",
            "update",
            &installation,
            "--source",
            "other/repo@next:agents/helper.md",
            "--replace",
            "--scope",
            "global",
        ])
        .output()
        .expect("reject mismatched target provenance");
    assert!(!mismatch.status.success());
    let after_mismatch = daemon
        .command()
        .args(["agent", "inspect", &installation])
        .output()
        .expect("inspect mismatch target");
    assert_eq!(output_text(&after_mismatch), before);

    // A source file can retain the same filename while changing its full
    // AgentDef identity. The target installation is authoritative: reject
    // that fetch before the update creates an operation or touches its copy.
    let mut changed_identity_fixture = fixture_revision(fixture_for_daemon(&workspace, true), 'e');
    let changed_identity_markdown = changed_identity_fixture["markdown"]
        .as_str()
        .expect("changed identity Markdown")
        .replace("agentId: authored/helper", "agentId: someone-else/helper");
    changed_identity_fixture["markdown"] = json!(changed_identity_markdown);
    replace_socket_fixture(&daemon, &changed_identity_fixture).await;
    let before_changed_identity_counts = agent_mutation_counts(&daemon);
    let changed_identity = daemon
        .command()
        .args([
            "agent",
            "update",
            &installation,
            "--source",
            "owner/repo@changed-id:agents/helper.md",
            "--replace",
            "--scope",
            "global",
            "--operation-key",
            "changed-agent-id-refusal",
        ])
        .output()
        .expect("reject changed fetched AgentDef identity");
    assert_eq!(
        changed_identity.status.code(),
        Some(1),
        "{}",
        output_text(&changed_identity)
    );
    assert_eq!(
        agent_mutation_counts(&daemon),
        before_changed_identity_counts,
        "changed AgentDef identity must not create an update operation"
    );
    let after_changed_identity = daemon
        .command()
        .args(["agent", "inspect", &installation])
        .output()
        .expect("inspect changed identity refusal");
    assert_eq!(output_text(&after_changed_identity), before);

    let second_fixture = fixture_revision(fixture_for_daemon(&workspace, true), 'c');
    replace_socket_fixture(&daemon, &second_fixture).await;
    let update = daemon
        .command()
        .args([
            "agent",
            "update",
            &installation,
            "--source",
            "owner/repo@next:agents/helper.md",
            "--replace",
            "--scope",
            "global",
        ])
        .output()
        .expect("update exact target");
    assert!(update.status.success(), "{}", output_text(&update));
    assert!(output_text(&update).contains("status=updated"));
    let after_update = daemon
        .command()
        .args(["agent", "inspect", &installation])
        .output()
        .expect("inspect updated target");
    assert!(
        after_update.status.success(),
        "{}",
        output_text(&after_update)
    );
    let after_update = output_text(&after_update);
    assert!(after_update.contains(&"c".repeat(40)));
    assert_ne!(after_update, before);

    let owned_copy = daemon
        .home()
        .xdg_state_home()
        .join("cockpit/agents/helper.md");
    let dirty_copy = format!(
        "{}\nLocally edited prompt body.\n",
        second_fixture["markdown"]
            .as_str()
            .expect("second fixture Markdown")
    );
    std::fs::write(&owned_copy, &dirty_copy).expect("dirty owned agent copy");
    let third_fixture = fixture_revision(fixture_for_daemon(&workspace, true), 'd');
    replace_socket_fixture(&daemon, &third_fixture).await;
    let dirty_update = daemon
        .command()
        .args([
            "agent",
            "update",
            &installation,
            "--source",
            "owner/repo@third:agents/helper.md",
            "--replace",
            "--scope",
            "global",
        ])
        .output()
        .expect("refuse dirty owned copy update");
    assert!(!dirty_update.status.success());
    assert_eq!(
        std::fs::read_to_string(&owned_copy).expect("read unchanged dirty owned copy"),
        dirty_copy
    );
    let after_dirty = daemon
        .command()
        .args(["agent", "inspect", &installation])
        .output()
        .expect("inspect after dirty refusal");
    assert!(
        after_dirty.status.success(),
        "{}",
        output_text(&after_dirty)
    );
    let after_dirty = output_text(&after_dirty);
    assert!(after_dirty.contains(&"c".repeat(40)));
    assert!(!after_dirty.contains(&"d".repeat(40)));
    assert!(after_dirty.contains("RebindRequired"));
}
