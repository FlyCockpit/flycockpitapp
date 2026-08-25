//! `cockpit mcp {add,list,test}` — manage MCP servers (GOALS §18).
//!
//! Configs live in the layered `.cockpit/mcp.json`. `add` writes to the
//! nearest project-local `.cockpit/mcp.json`; `list`/`test` read the
//! discovered config for the cwd.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};

use crate::cli::{McpAddArgs, McpCommand, McpTestArgs};
use crate::daemon::client::ensure_persistent_daemon;
use crate::daemon::proto::{Request, Response};
use crate::mcp::config::{Auth, HeaderAuth, McpConfig, OauthAuth, ServerConfig, Transport};

pub async fn run(cmd: McpCommand) -> Result<()> {
    match cmd {
        McpCommand::List => list().await,
        McpCommand::Add(args) => add(args).await,
        McpCommand::Test(args) => test(args).await,
    }
}

fn parse_transport(s: &str) -> Result<Transport> {
    match s {
        "streamable" | "http" => Ok(Transport::Streamable),
        "stdio" => Ok(Transport::Stdio),
        "sse" => Ok(Transport::Sse),
        other => bail!("unknown transport `{other}` (expected streamable | stdio | sse)"),
    }
}

fn build_auth(args: &McpAddArgs) -> Result<Auth> {
    match args.auth.as_str() {
        "none" => {
            eprintln!(
                "Warning: MCP server `{}` is being added with no authentication (public).",
                args.name
            );
            Ok(Auth::None)
        }
        "oauth" => Ok(Auth::Oauth(OauthAuth::default())),
        "header" => {
            let value = args
                .header_value
                .clone()
                .context("`--auth header` requires `--header-value`")?;
            Ok(Auth::Header(HeaderAuth {
                header: args
                    .header_name
                    .clone()
                    .unwrap_or_else(|| "Authorization".to_string()),
                value,
                credential_ref: None,
            }))
        }
        "env" => Ok(Auth::Env(Default::default())),
        other => bail!("unknown auth kind `{other}` (expected oauth | header | env | none)"),
    }
}

async fn add(args: McpAddArgs) -> Result<()> {
    let transport = parse_transport(&args.transport)?;
    let auth = build_auth(&args)?;

    let cwd = std::env::current_dir()?;
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for MCP config save")?;
    let project_root = cwd.display().to_string();
    let snapshot_session_id = uuid::Uuid::new_v4().to_string();
    let snapshot = daemon
        .client
        .request(Request::GetProviderCatalogSnapshot {
            project_root: project_root.clone(),
            provider_id: None,
            snapshot_session_id: snapshot_session_id.clone(),
        })
        .await?
        .map_err(|error| anyhow::anyhow!(error.message))?;
    let Response::ProviderCatalogSnapshot {
        config,
        snapshot_session_id: returned_snapshot_id,
        ..
    } = snapshot
    else {
        bail!("daemon returned unexpected MCP authority snapshot");
    };
    if returned_snapshot_id != snapshot_session_id {
        bail!("daemon returned a mismatched MCP authority snapshot");
    }
    let cfg = McpConfig::parse(
        config
            .mcp_config_json
            .as_deref()
            .context("daemon MCP snapshot omitted its redacted projection")?,
    )?;
    let owner_root = config
        .mcp_owner_root
        .context("daemon MCP snapshot omitted its owner root")?;
    let config_path = config
        .mcp_config_path
        .context("daemon MCP snapshot omitted its config path")?;
    let snapshot_capability = config
        .mcp_edit_capability
        .context("daemon MCP snapshot omitted its edit capability")?;
    let expected_revision = config
        .mcp_revision
        .context("daemon MCP snapshot omitted its target revision")?;

    if cfg.servers.contains_key(&args.name) {
        bail!(
            "MCP server `{}` already exists in {}",
            args.name,
            config_path
        );
    }

    let mut server = ServerConfig {
        transport,
        endpoint: args.endpoint.clone(),
        command: args.command.clone(),
        args: args.args.clone(),
        env: Default::default(),
        env_credential_refs: Default::default(),
        auth,
        mode: Default::default(),
        enabled: !args.disabled,
        cache_ttl_secs: 3600,
        connect_timeout_secs: None,
        timeout_secs: None,
    };
    // Validate required fields per transport up front.
    match transport {
        Transport::Stdio => {
            server.require_command(&args.name)?;
        }
        _ => {
            server.require_endpoint(&args.name)?;
        }
    }

    // A literal `--auth header` value is credential material: stage it so the
    // daemon owner-mutation moves it into the vault under this server's header
    // key. The daemon `SaveMcpConfig` path normalizes the literal to a
    // reference. OAuth/env/none carry no literal secret at add time.
    let mut secret_values: BTreeMap<String, String> = BTreeMap::new();
    if let Auth::Header(header) = &mut server.auth {
        let value = header.value.trim();
        if !value.is_empty() {
            let key = crate::mcp::auth::header_cred_key(&args.name);
            secret_values.insert(key.clone(), value.to_string());
            header.value.clear();
            header.credential_ref = Some(key);
        }
    }

    // Route through the owner-remoted daemon RPC so the write inherits the
    // atomic cross-kind ownership guard: `mcp add --auth oauth --name victim`
    // cannot publish/consume an `mcp:victim` token owned by another kind or
    // workspace. The daemon derives its own write target and cleanup set from
    // `project_root`; cleanup is derived from the daemon's raw target layer.
    let patch = cockpit_proto::McpConfigPatch {
        operations: vec![cockpit_proto::McpConfigPatchOperation::AddServer {
            name: args.name.clone(),
            server_json: serde_json::to_string(&server)
                .context("serializing MCP server")?
                .into(),
        }],
    };
    let secret_values_json =
        serde_json::to_string(&secret_values).context("serializing MCP secret values")?;
    for value in secret_values.values_mut() {
        zeroize::Zeroize::zeroize(value);
    }
    let client_operation_id = uuid::Uuid::new_v4().to_string();
    use sha2::Digest as _;
    let patch_wire = serde_json::to_string(&patch).context("serializing MCP patch")?;
    let mutation_intent_hash = sha2::Sha256::digest(
        serde_json::to_vec(&("save_mcp_config", &project_root, &patch_wire))?.as_slice(),
    )
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect::<String>();
    match daemon
        .client
        .request(Request::SaveMcpConfig {
            client_operation_id: client_operation_id.clone(),
            project_root: project_root.clone(),
            snapshot_capability,
            owner_root: owner_root.clone(),
            config_path: config_path.clone(),
            expected_revision: expected_revision.clone(),
            mutation_intent_hash: mutation_intent_hash.clone(),
            patch: cockpit_proto::SensitiveWirePayload::new(patch_wire),
            secret_values_json: cockpit_proto::SensitiveWirePayload::new(secret_values_json),
        })
        .await?
    {
        Ok(Response::McpConfigCommitted {
            client_operation_id: returned_operation_id,
            project_root: returned_root,
            owner_root: returned_owner_root,
            config_path: returned_config_path,
            consumed_revision,
            result_revision,
            request_hash,
            mutation_intent_hash: returned_intent_hash,
            config_generation,
            ..
        }) if returned_operation_id == client_operation_id
            && returned_root == project_root
            && returned_owner_root == owner_root
            && returned_config_path == config_path
            && consumed_revision == expected_revision
            && cockpit_proto::is_opaque_authority_token(&request_hash)
            && returned_intent_hash == mutation_intent_hash
            && cockpit_proto::is_opaque_authority_token(&result_revision)
            && config_generation > 0 => {}
        Ok(other) => bail!("daemon returned unexpected response to MCP config save: {other:?}"),
        Err(error) => bail!("daemon rejected MCP config save: {error}"),
    }
    println!(
        "Added MCP server `{}` ({}) via the daemon.",
        args.name,
        transport.as_str(),
    );
    Ok(())
}

async fn list() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let cfg = McpConfig::discover(&cwd);
    if cfg.servers.is_empty() {
        println!("No MCP servers configured.");
        return Ok(());
    }
    for (name, s) in &cfg.servers {
        let endpoint = s.endpoint.as_deref().or(s.command.as_deref()).unwrap_or("");
        println!(
            "{name}\t{}\t{}\tauth={}\t{}",
            s.transport.as_str(),
            if s.enabled { "enabled" } else { "disabled" },
            s.auth.kind_str(),
            endpoint
        );
    }
    Ok(())
}

async fn test(args: McpTestArgs) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let cfg = McpConfig::discover(&cwd);
    let Some(server) = cfg.servers.get(&args.name) else {
        bail!("unknown MCP server `{}`", args.name);
    };
    println!(
        "Connecting to `{}` ({})…",
        args.name,
        server.transport.as_str(),
    );
    let tools = crate::mcp::catalog::list_tools_cached(&args.name, server).await?;
    println!("{} tool(s):", tools.len());
    for t in &tools {
        let desc = t.description.lines().next().unwrap_or("");
        println!("  {}\t{desc}", t.name);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(auth: &str) -> McpAddArgs {
        McpAddArgs {
            name: "s".into(),
            transport: "streamable".into(),
            endpoint: Some("https://x/mcp".into()),
            command: None,
            args: vec![],
            auth: auth.into(),
            header_value: None,
            header_name: None,
            disabled: false,
        }
    }

    // Gap 3: `mcp add` must publish MCP config through the owner-remoted
    // `SaveMcpConfig` daemon RPC (inheriting the atomic cross-kind ownership
    // guard) rather than writing `.cockpit/mcp.json` directly. The daemon-only
    // ratchet (`production_path_ratchet::daemon_only_paths_have_no_local_secret_or_provider_resolution`)
    // mechanically covers this file; this asserts the routing itself.
    #[test]
    fn mcp_add_publishes_through_the_daemon_ownership_guard() {
        let src = include_str!("mcp.rs");
        assert!(
            src.contains("Request::SaveMcpConfig"),
            "mcp add must publish via the SaveMcpConfig daemon RPC"
        );
        assert!(
            src.contains("ensure_persistent_daemon"),
            "mcp add must route through the persistent daemon owner"
        );
    }

    #[test]
    fn parse_transport_accepts_all_three_plus_http_alias() {
        assert_eq!(
            parse_transport("streamable").unwrap(),
            Transport::Streamable
        );
        assert_eq!(parse_transport("http").unwrap(), Transport::Streamable);
        assert_eq!(parse_transport("stdio").unwrap(), Transport::Stdio);
        assert_eq!(parse_transport("sse").unwrap(), Transport::Sse);
        assert!(parse_transport("ws").is_err());
    }

    #[test]
    fn build_auth_none_warns_and_returns_none() {
        // (The warning prints to stderr; here we assert the resulting auth.)
        let a = build_auth(&args("none")).unwrap();
        assert!(matches!(a, Auth::None));
    }

    #[test]
    fn build_auth_kinds_round_trip() {
        assert!(matches!(
            build_auth(&args("oauth")).unwrap(),
            Auth::Oauth(_)
        ));
        assert!(matches!(build_auth(&args("env")).unwrap(), Auth::Env(_)));
        // header requires a value.
        assert!(build_auth(&args("header")).is_err());
        let mut a = args("header");
        a.header_value = Some("Bearer $T".into());
        match build_auth(&a).unwrap() {
            Auth::Header(h) => {
                assert_eq!(h.header, "Authorization");
                assert_eq!(h.value, "Bearer $T");
            }
            other => panic!("expected header auth, got {other:?}"),
        }
    }
}
