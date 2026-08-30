use std::fs;
use std::path::{Path, PathBuf};

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
    let mut ingress_definitions = 0;
    let mut request_source = String::new();
    for path in files {
        let source = fs::read_to_string(&path).expect("read proto source");
        ingress_definitions += source
            .matches("pub struct AcpForwardedMcpIngressV1")
            .count();
        if path.file_name().is_some_and(|name| name == "request.rs") {
            request_source = source;
        }
    }
    assert_eq!(ingress_definitions, 1, "one closed editor-MCP ingress is allowed");
    for forbidden in [
        "InstallForwardedMcp",
        "ReleaseForwardedMcp",
        "InstallMcpCatalog",
        "ReleaseMcpCatalog",
    ] {
        assert!(
            !request_source.contains(forbidden),
            "catalog lifecycle must remain core-internal: {forbidden}"
        );
    }
}
