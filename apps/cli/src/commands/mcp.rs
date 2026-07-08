//! `cockpit mcp {add,list,test}` — manage MCP servers (GOALS §18).
//!
//! Configs live in the layered `.cockpit/mcp.json`. `add` writes to the
//! nearest project-local `.cockpit/mcp.json`; `list`/`test` read the
//! discovered config for the cwd.

use anyhow::{Context, Result, bail};

use crate::cli::{McpAddArgs, McpCommand, McpTestArgs};
use crate::mcp::config::{Auth, HeaderAuth, McpConfig, OauthAuth, ServerConfig, Transport};

pub async fn run(cmd: McpCommand) -> Result<()> {
    match cmd {
        McpCommand::List => list().await,
        McpCommand::Add(args) => add(args),
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

fn add(args: McpAddArgs) -> Result<()> {
    let transport = parse_transport(&args.transport)?;
    let auth = build_auth(&args)?;

    let cwd = std::env::current_dir()?;
    let dir = crate::config::dirs::cwd_scoped_creatable_dirs(&cwd)
        .into_iter()
        .next()
        .context("no writable .cockpit/ directory for the current dir")?;
    let path = dir.path.join("mcp.json");

    let mut cfg = if path.exists() {
        McpConfig::parse(&std::fs::read_to_string(&path)?)?
    } else {
        McpConfig::default()
    };

    if cfg.servers.contains_key(&args.name) {
        bail!(
            "MCP server `{}` already exists in {}",
            args.name,
            path.display()
        );
    }

    let server = ServerConfig {
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

    cfg.servers.insert(args.name.clone(), server);
    cfg.write_private(&path)?;
    println!(
        "Added MCP server `{}` ({}) to {}",
        args.name,
        transport.as_str(),
        path.display()
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
