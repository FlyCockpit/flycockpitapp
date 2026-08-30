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
    let forwarded = fs::read_to_string(manifest.join("src/mcp/forwarded.rs"))
        .expect("read forwarded catalog source");
    let composition = fs::read_to_string(manifest.join("src/daemon/acp_catalog_composition.rs"))
        .expect("read catalog composition source");
    let inspected = format!("{forwarded}\n{composition}");
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
        assert!(
            !inspected.contains(forbidden),
            "ACP-forwarded declarations must not reach {forbidden}"
        );
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
}

#[test]
fn forwarded_catalog_is_reachable_only_from_tool_context_session_and_monty_catalog() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let session = fs::read_to_string(manifest.join("src/session/mod.rs")).expect("session source");
    let catalog = fs::read_to_string(manifest.join("src/mcp/catalog.rs")).expect("catalog source");
    let mcp_tool =
        fs::read_to_string(manifest.join("src/tools/mcp_tool.rs")).expect("MCP tool source");
    assert!(session.contains("forwarded_mcp_catalog"));
    assert!(catalog.contains("ctx.session.forwarded_mcp_catalog()"));
    assert!(catalog.contains("invoke_forwarded"));
    assert!(catalog.contains("client::connect_forwarded"));
    assert!(!mcp_tool.contains("AcpForwardedMcp"));
    assert!(!mcp_tool.contains("connect_forwarded"));
}
