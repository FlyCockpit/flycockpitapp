//! Source-boundary ratchets for the ACP transport seam.

use std::fs;
use std::path::{Path, PathBuf};

fn cli_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn core_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/cockpit-core/src")
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn production_source(path: &Path) -> String {
    let raw = fs::read_to_string(path).unwrap_or_default();
    strip_test_modules(&raw)
}

fn strip_test_modules(src: &str) -> String {
    let mut out = String::new();
    let mut i = 0;
    let bytes = src.as_bytes();
    while i < src.len() {
        if let Some(rel) = src[i..].find("#[cfg(test)]") {
            out.push_str(&src[i..i + rel]);
            let after = i + rel + "#[cfg(test)]".len();
            if let Some(mod_rel) = src[after..].find('{') {
                let mut depth = 0;
                let mut j = after + mod_rel;
                while j < src.len() {
                    match bytes[j] {
                        b'{' => depth += 1,
                        b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                j += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                i = j;
            } else {
                i = after;
            }
            continue;
        }
        out.push_str(&src[i..]);
        break;
    }
    out
}

fn relative_cli(path: &Path) -> String {
    path.strip_prefix(cli_src())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acp_transport_boundary_only_bridge_converts_proto_ingress() {
        let mut files = Vec::new();
        collect_rs_files(&cli_src().join("acp"), &mut files);
        let mut hits = Vec::new();
        for path in files {
            let src = production_source(&path);
            if src.contains("AcpForwardedMcpIngressV1") {
                hits.push(relative_cli(&path));
            }
        }
        assert_eq!(
            hits,
            vec!["acp/bridge.rs".to_string()],
            "only the bridge facade may name AcpForwardedMcpIngressV1"
        );
    }

    #[test]
    fn acp_transport_boundary_adapter_envelope_import_no_proto_ingress() {
        for name in ["acp/adapter.rs", "acp/envelope.rs"] {
            let src = production_source(&cli_src().join(name));
            assert!(
                !src.contains("AcpForwardedMcpIngressV1"),
                "{name} must not import proto ingress"
            );
            assert!(
                !src.contains("Install") && !src.contains("Release"),
                "{name} must not call catalog Install*/Release* lifecycle APIs"
            );
        }
    }

    #[test]
    fn acp_transport_boundary_envelope_has_no_mcp_connection_or_tool_path() {
        let src = production_source(&cli_src().join("acp/envelope.rs"));
        for forbidden in [
            "mcp.connect",
            "connect_mcp",
            "InstallMcp",
            "tool_execute",
            "execute_tool",
            "tokio_tungstenite",
            "TcpListener",
            "Content-Length",
        ] {
            assert!(
                !src.contains(forbidden),
                "envelope must not contain {forbidden}"
            );
        }
    }

    #[test]
    fn acp_transport_boundary_core_imports_no_cli_acp_schema() {
        let mut files = Vec::new();
        collect_rs_files(&core_src(), &mut files);
        for path in files {
            let src = production_source(&path);
            assert!(
                !src.contains("cockpit_cli::acp")
                    && !src.contains("agent_client_protocol_schema")
                    && !src.contains("ACP_JSON_FRAME_MAX_BYTES_V1"),
                "{} must not import CLI ACP transport or schema types",
                path.display()
            );
        }
    }

    #[test]
    fn acp_transport_boundary_jsonrpsee_is_pinned_server_core_only() {
        let manifest =
            fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
        assert!(manifest.contains("jsonrpsee = { version = \"=0.24.11\""));
        assert!(manifest.contains("jsonrpsee-types = { version = \"=0.24.11\""));
        assert!(manifest.contains("features = [\"server-core\"]"));
        assert!(manifest.contains("agent-client-protocol-schema = { version = \"=1.7.0\""));
        assert!(
            fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/acp-jsonrpsee-audit.md")
            )
            .unwrap()
            .contains("0.24.11")
        );
    }
}
