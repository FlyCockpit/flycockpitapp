use std::fs;
use std::path::{Path, PathBuf};

use syn::{Item, Visibility};

fn collect_rust_files(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("read source directory") {
        let path = entry.expect("read source entry").path();
        if path.is_dir() {
            collect_rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

#[test]
fn cockpit_core_has_no_cli_or_acp_transport_schema_dependency() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rust_files(&root, &mut files);
    assert!(!files.is_empty());
    for path in files {
        let source = fs::read_to_string(&path).expect("read Rust source");
        for forbidden in [
            "apps::cli",
            "apps/cli",
            "agent_client_protocol",
            "jsonrpsee",
            "SessionAdmissionDto",
            "McpServerDto",
        ] {
            assert!(
                !source.contains(forbidden),
                "{} imports forbidden ACP/CLI boundary spelling {forbidden}",
                path.display()
            );
        }
    }
}

#[test]
fn proto_exposes_one_forwarded_mcp_ingress_and_no_public_catalog_lifecycle_rpc() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proto = manifest.join("../cockpit-proto/src");
    let mut files = Vec::new();
    collect_rust_files(&proto, &mut files);
    let mut public_mcp_ingress_types = Vec::new();
    for path in files {
        let source = fs::read_to_string(&path).expect("read proto source");
        let file = syn::parse_file(&source).expect("parse proto source");
        for item in file.items {
            let (is_public, ident) = match item {
                Item::Struct(item) => (matches!(item.vis, Visibility::Public(_)), item.ident),
                Item::Enum(item) => (matches!(item.vis, Visibility::Public(_)), item.ident),
                Item::Type(item) => (matches!(item.vis, Visibility::Public(_)), item.ident),
                _ => continue,
            };
            let name = ident.to_string();
            if is_public && name.contains("Mcp") && name.contains("Ingress") {
                public_mcp_ingress_types.push(name);
            }
        }
    }
    public_mcp_ingress_types.sort();
    assert_eq!(
        public_mcp_ingress_types,
        vec!["AcpForwardedMcpIngressV1".to_string()],
        "one public editor-MCP ingress is allowed"
    );

    let acp_path = proto.join("acp.rs");
    let acp_source = fs::read_to_string(&acp_path).expect("read ACP proto source");
    let acp_file = syn::parse_file(&acp_source).expect("parse ACP proto source");
    let mut forwarded_mcp_public_types = Vec::new();
    for item in acp_file.items {
        let (is_public, ident) = match item {
            Item::Struct(item) => (matches!(item.vis, Visibility::Public(_)), item.ident),
            Item::Enum(item) => (matches!(item.vis, Visibility::Public(_)), item.ident),
            Item::Type(item) => (matches!(item.vis, Visibility::Public(_)), item.ident),
            _ => continue,
        };
        let name = ident.to_string();
        if is_public && name.contains("Acp") && name.contains("Mcp") {
            forwarded_mcp_public_types.push(name);
        }
    }
    forwarded_mcp_public_types.sort();
    assert_eq!(
        forwarded_mcp_public_types,
        vec![
            "AcpForwardedMcpDeclarationV1".to_string(),
            "AcpForwardedMcpIngressV1".to_string(),
            "AcpForwardedMcpTransportV1".to_string(),
            "AcpNameValuePairV1".to_string(),
        ],
        "the closed ingress family is the only public ACP/MCP type family"
    );

    let request_path = proto.join("request.rs");
    let request_source = fs::read_to_string(&request_path).expect("read request proto source");
    let request_file = syn::parse_file(&request_source).expect("parse request proto source");
    let request_variants = request_file
        .items
        .into_iter()
        .find_map(|item| match item {
            Item::Enum(item) if item.ident == "Request" => Some(item.variants),
            _ => None,
        })
        .expect("Request enum is present");
    let public_catalog_lifecycle_routes = request_variants
        .into_iter()
        .map(|variant| variant.ident.to_string())
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            (lower.contains("mcp") || lower.contains("catalog"))
                && (lower.contains("install") || lower.contains("release"))
        })
        .collect::<Vec<_>>();
    assert!(
        public_catalog_lifecycle_routes.is_empty(),
        "catalog lifecycle must remain core-internal, not public Request variants: \
         {public_catalog_lifecycle_routes:?}"
    );
}

#[test]
fn forwarded_catalog_has_no_persistence_credential_or_adapter_execution_path() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source_root = manifest.join("src");
    let mut files = Vec::new();
    collect_rust_files(&source_root, &mut files);
    let production = files
        .iter()
        .map(|path| {
            let source = fs::read_to_string(path).expect("read Rust source");
            let source = source.split("#[cfg(test)]").next().unwrap_or(&source);
            (
                path.strip_prefix(&source_root)
                    .expect("path below source root"),
                source,
            )
        })
        .collect::<Vec<_>>();

    // This is the complete production capability graph for editor-provided
    // values.  A new helper, trait implementation, or renamed sink must first
    // become a declared graph member; the test then subjects that member to
    // the sink checks below instead of relying on a spelling next to ingress.
    let allowed_capability_files = [
        Path::new("approval/mod.rs"),
        Path::new("approval/policy.rs"),
        Path::new("daemon/acp_catalog_composition.rs"),
        Path::new("daemon/session_worker/handle.rs"),
        Path::new("mcp/catalog.rs"),
        Path::new("mcp/client.rs"),
        Path::new("mcp/forwarded.rs"),
        Path::new("session/lifecycle.rs"),
        Path::new("session/mod.rs"),
    ];
    let capability_markers = [
        "AcpForwarded",
        "ForwardedCatalogSlot",
        "ForwardedMcpTool",
        "ForwardedMcpServerConnect",
        "SOURCE_ACP_FORWARDED",
    ];
    let capability_paths = production
        .iter()
        .filter_map(|(path, source)| {
            capability_markers
                .iter()
                .any(|marker| source.contains(marker))
                .then_some((*path, *source))
        })
        .collect::<Vec<_>>();
    assert!(
        !capability_paths.is_empty(),
        "forwarded capability graph is empty"
    );
    for (path, _) in &capability_paths {
        assert!(
            allowed_capability_files.contains(path),
            "unreviewed forwarded capability consumer {} could bypass the audited funnel",
            path.display()
        );
    }

    // Raw ingress is confined to conversion/validation and composition.  No
    // persistence, credential, replay, cache, log, or durable-grant API may
    // enter either endpoint of that graph.
    let raw_declaration_paths = capability_paths
        .iter()
        .filter(|(_, source)| {
            source.contains("AcpForwardedMcpDeclarationV1")
                || source.contains("AcpForwardedMcpIngressV1")
        })
        .copied()
        .collect::<Vec<_>>();
    assert!(
        !raw_declaration_paths.is_empty(),
        "forwarded ingress has no audited producer"
    );
    for forbidden in [
        "McpConfig::write_private",
        "McpConfig::discover(",
        "cache::save",
        "cache::load",
        "CredentialStore",
        "SecretVault",
        "GrantStore",
        "record_mcp_tool_key",
        "record_mcp_server_connect_key",
        "insert_session_event",
        "write_session",
        "session_log",
        "serde::Serialize",
        "derive(Serialize",
    ] {
        for (path, source) in &raw_declaration_paths {
            assert!(
                !source.contains(forbidden),
                "{} lets ACP-forwarded declarations reach {forbidden}",
                path.display()
            );
        }
    }

    let client =
        fs::read_to_string(manifest.join("src/mcp/client.rs")).expect("read MCP client source");
    let forwarded_connect = client
        .split("pub async fn connect_forwarded(")
        .nth(1)
        .expect("forwarded connection function")
        .split("fn server_requires_secret_store")
        .next()
        .expect("forwarded connection boundary");
    let forwarded_connect_approval = client
        .split("async fn authorize_forwarded_connect(")
        .nth(1)
        .expect("forwarded connection approval function")
        .split("/// Connect a validated ACP-forwarded entry")
        .next()
        .expect("forwarded connection approval boundary");
    for forbidden in [
        "CredentialStore",
        "SecretVault",
        "oauth_bearer",
        "resolve_static_for_server",
        "server_requires_secret_store",
    ] {
        assert!(
            !forwarded_connect.contains(forbidden),
            "forwarded connection must bypass credential path {forbidden}"
        );
    }

    let catalog =
        fs::read_to_string(manifest.join("src/mcp/catalog.rs")).expect("read MCP catalog source");
    let forwarded_catalog = catalog
        .split("async fn list_tools_for_forwarded(")
        .nth(1)
        .expect("forwarded discovery function")
        .split("fn catalog_view")
        .next()
        .expect("forwarded discovery boundary");
    let forwarded_invoke = catalog
        .split("async fn invoke_forwarded(")
        .nth(1)
        .expect("forwarded invoke function")
        .split("pub(crate) fn connect_context")
        .next()
        .expect("forwarded invoke boundary");
    for forbidden in [
        "cache::save",
        "cache::load",
        "list_tools_cached",
        "McpConfig",
        "SecretVault",
        "GrantStore",
        "record_mcp_tool_key",
        "record_mcp_server_connect_key",
    ] {
        assert!(
            !forwarded_catalog.contains(forbidden) && !forwarded_invoke.contains(forbidden),
            "forwarded catalog path must not reach {forbidden}"
        );
    }

    // The only code that can await a forwarded approval is the two audited
    // funnels.  They must route it through the epoch cancellation gate, and
    // neither may reach the durable MCP grant store by a helper call.
    for (path, source, boundary) in [
        (
            Path::new("mcp/catalog.rs"),
            forwarded_invoke,
            "tool approval",
        ),
        (
            Path::new("mcp/client.rs"),
            forwarded_connect_approval,
            "connect approval",
        ),
    ] {
        assert!(
            source.contains(".await_approval("),
            "{} forwarded {boundary} bypasses epoch cancellation",
            path.display()
        );
        for forbidden in [
            "GrantStore",
            "record_mcp_tool",
            "record_mcp_server_connect",
            "self.store",
        ] {
            assert!(
                !source.contains(forbidden),
                "{} forwarded {boundary} reaches durable approval path {forbidden}",
                path.display()
            );
        }
    }

    let policy = fs::read_to_string(manifest.join("src/approval/policy.rs"))
        .expect("read approval policy source");
    let forwarded_approval = policy
        .split("pub(super) async fn approve_forwarded_mcp_inner")
        .nth(1)
        .expect("forwarded approval function")
        .split("pub fn new")
        .next()
        .expect("forwarded approval boundary");
    for forbidden in ["server: &str", "\"server\": server", "{server}"] {
        assert!(
            !forwarded_approval.contains(forbidden),
            "forwarded approval must project a redacted server display, not {forbidden}"
        );
    }
}

#[test]
fn forwarded_catalog_is_reachable_only_from_tool_context_session_and_monty_catalog() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let session = fs::read_to_string(manifest.join("src/session/mod.rs")).expect("session source");
    let catalog = fs::read_to_string(manifest.join("src/mcp/catalog.rs")).expect("catalog source");
    let mcp_module =
        fs::read_to_string(manifest.join("src/mcp/mod.rs")).expect("MCP module source");
    let mcp_tool =
        fs::read_to_string(manifest.join("src/tools/mcp_tool.rs")).expect("MCP tool source");
    assert!(mcp_module.contains("pub(crate) mod forwarded;"));
    assert!(session.contains("forwarded_mcp_catalog"));
    assert!(catalog.contains("ctx.session.forwarded_mcp_catalog()"));
    assert!(catalog.contains("invoke_forwarded"));
    assert!(catalog.contains("client::connect_forwarded"));
    assert!(!mcp_tool.contains("AcpForwardedMcp"));
    assert!(!mcp_tool.contains("connect_forwarded"));
}
