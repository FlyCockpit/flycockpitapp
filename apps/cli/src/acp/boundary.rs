//! Source-boundary ratchets for the ACP transport seam.
//!
//! These tests close production *identifiers* and import paths, not comments
//! or string literals. Files that cannot be read or parsed fail the ratchet.
//! `#[cfg(test)]` items are skipped via the syn AST so later production
//! source is never dropped.

use std::fs;
use std::path::{Path, PathBuf};

use quote::ToTokens;
use syn::visit::Visit;

fn cli_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_required(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| {
        panic!(
            "ACP boundary ratchet could not read {}: {err}",
            path.display()
        )
    })
}

fn parse_required(path: &Path, src: &str) -> syn::File {
    syn::parse_file(src).unwrap_or_else(|err| {
        panic!(
            "ACP boundary ratchet could not parse {}: {err}",
            path.display()
        )
    })
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|err| {
        panic!(
            "ACP boundary ratchet could not read {}: {err}",
            dir.display()
        )
    });
    for entry in entries {
        let entry = entry.unwrap_or_else(|err| {
            panic!(
                "ACP boundary ratchet could not read an entry in {}: {err}",
                dir.display()
            )
        });
        let path = entry.path();
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            if name == "tests" || name == "target" {
                continue;
            }
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("");
            if name == "tests.rs" {
                continue;
            }
            out.push(path);
        }
    }
}

fn relative_cli(path: &Path) -> String {
    path.strip_prefix(cli_src())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn rust_src_roots_outside_cli() -> Vec<PathBuf> {
    let root = repo_root();
    let mut roots = Vec::new();
    let tenant = root.join("apps/tenant-authority/src");
    assert!(
        tenant.is_dir(),
        "ACP boundary ratchet expected {}",
        tenant.display()
    );
    roots.push(tenant);
    let crates = root.join("crates");
    let entries = fs::read_dir(&crates).unwrap_or_else(|err| {
        panic!(
            "ACP boundary ratchet could not read {}: {err}",
            crates.display()
        )
    });
    for entry in entries {
        let entry = entry.unwrap_or_else(|err| {
            panic!(
                "ACP boundary ratchet could not read an entry in {}: {err}",
                crates.display()
            )
        });
        let src = entry.path().join("src");
        if src.is_dir() {
            roots.push(src);
        }
    }
    roots.sort();
    roots
}

fn cfg_test_only(attributes: &[syn::Attribute]) -> bool {
    fn requires_test(meta: &syn::Meta) -> bool {
        match meta {
            syn::Meta::Path(path) => path.is_ident("test"),
            syn::Meta::List(list) if list.path.is_ident("all") => list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .is_ok_and(|items| items.iter().any(requires_test)),
            syn::Meta::List(list) if list.path.is_ident("any") => list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .is_ok_and(|items| !items.is_empty() && items.iter().all(requires_test)),
            syn::Meta::List(_) | syn::Meta::NameValue(_) => false,
        }
    }
    attributes.iter().any(|attribute| {
        if !attribute.path().is_ident("cfg") {
            return false;
        }
        let syn::Meta::List(cfg) = &attribute.meta else {
            return false;
        };
        cfg.parse_args::<syn::Meta>()
            .is_ok_and(|predicate| requires_test(&predicate))
    })
}

fn item_attributes(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(value) => &value.attrs,
        syn::Item::Enum(value) => &value.attrs,
        syn::Item::ExternCrate(value) => &value.attrs,
        syn::Item::Fn(value) => &value.attrs,
        syn::Item::ForeignMod(value) => &value.attrs,
        syn::Item::Impl(value) => &value.attrs,
        syn::Item::Macro(value) => &value.attrs,
        syn::Item::Mod(value) => &value.attrs,
        syn::Item::Static(value) => &value.attrs,
        syn::Item::Struct(value) => &value.attrs,
        syn::Item::Trait(value) => &value.attrs,
        syn::Item::TraitAlias(value) => &value.attrs,
        syn::Item::Type(value) => &value.attrs,
        syn::Item::Union(value) => &value.attrs,
        syn::Item::Use(value) => &value.attrs,
        _ => &[],
    }
}

fn impl_item_attributes(item: &syn::ImplItem) -> &[syn::Attribute] {
    match item {
        syn::ImplItem::Const(value) => &value.attrs,
        syn::ImplItem::Fn(value) => &value.attrs,
        syn::ImplItem::Type(value) => &value.attrs,
        syn::ImplItem::Macro(value) => &value.attrs,
        _ => &[],
    }
}

#[derive(Default)]
struct ProductionSymbols {
    idents: Vec<String>,
    paths: Vec<String>,
}

impl<'ast> Visit<'ast> for ProductionSymbols {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if cfg_test_only(item_attributes(item)) {
            return;
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        if cfg_test_only(impl_item_attributes(item)) {
            return;
        }
        syn::visit::visit_impl_item(self, item);
    }

    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        self.idents.push(ident.to_string());
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let joined = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        if !joined.is_empty() {
            self.paths.push(joined);
        }
        syn::visit::visit_path(self, path);
    }
}

fn production_symbols(path: &Path) -> ProductionSymbols {
    let raw = read_required(path);
    let file = parse_required(path, &raw);
    let mut visitor = ProductionSymbols::default();
    visitor.visit_file(&file);
    visitor
}

fn production_tokens(path: &Path) -> String {
    let raw = read_required(path);
    let file = parse_required(path, &raw);
    file.items
        .iter()
        .filter(|item| !cfg_test_only(item_attributes(item)))
        .map(|item| item.to_token_stream().to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

/// PascalCase catalog lifecycle identifiers: `Install`, `InstallMcp`,
/// `Release`, `ReleaseBinding`. Does not match `Released`,
/// `AgentInstallation`, or lowercase `release_by_id`.
fn is_catalog_lifecycle_ident(name: &str) -> bool {
    fn pascal_prefix(name: &str, prefix: &str) -> bool {
        name == prefix
            || name
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_uppercase()))
    }
    pascal_prefix(name, "Install") || pascal_prefix(name, "Release")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acp_transport_boundary_catalog_lifecycle_ident_detector() {
        assert!(is_catalog_lifecycle_ident("Install"));
        assert!(is_catalog_lifecycle_ident("InstallMcp"));
        assert!(is_catalog_lifecycle_ident("Release"));
        assert!(is_catalog_lifecycle_ident("ReleaseBinding"));
        assert!(!is_catalog_lifecycle_ident("Released"));
        assert!(!is_catalog_lifecycle_ident("AgentInstallation"));
        assert!(!is_catalog_lifecycle_ident("Installation"));
        assert!(!is_catalog_lifecycle_ident("release_by_id"));
        assert!(!is_catalog_lifecycle_ident("install"));
    }

    #[test]
    fn acp_transport_boundary_only_bridge_converts_proto_ingress() {
        let mut files = Vec::new();
        collect_rs_files(&cli_src(), &mut files);
        assert!(
            !files.is_empty(),
            "ACP boundary ratchet found no CLI source files"
        );
        let mut hits = Vec::new();
        for path in files {
            let symbols = production_symbols(&path);
            if symbols
                .idents
                .iter()
                .any(|ident| ident == "AcpForwardedMcpIngressV1")
            {
                hits.push(relative_cli(&path));
            }
        }
        hits.sort();
        assert_eq!(
            hits,
            vec!["acp/bridge.rs".to_string()],
            "only the bridge facade may name AcpForwardedMcpIngressV1"
        );
    }

    #[test]
    fn acp_transport_boundary_adapter_envelope_import_no_proto_ingress() {
        let mut files = Vec::new();
        collect_rs_files(&cli_src().join("acp"), &mut files);
        assert!(
            !files.is_empty(),
            "ACP boundary ratchet found no ACP source files"
        );
        for path in files {
            let name = relative_cli(&path);
            let symbols = production_symbols(&path);
            if name != "acp/bridge.rs" {
                assert!(
                    !symbols
                        .idents
                        .iter()
                        .any(|ident| ident == "AcpForwardedMcpIngressV1"),
                    "{name} must not import proto ingress"
                );
            }
            let lifecycle: Vec<&String> = symbols
                .idents
                .iter()
                .filter(|ident| is_catalog_lifecycle_ident(ident))
                .collect();
            assert!(
                lifecycle.is_empty(),
                "{name} must not call catalog Install*/Release* lifecycle APIs; found {lifecycle:?}"
            );
        }
    }

    #[test]
    fn acp_transport_boundary_envelope_has_no_mcp_connection_or_tool_path() {
        let envelope = cli_src().join("acp/envelope.rs");
        let symbols = production_symbols(&envelope);
        for forbidden in [
            "connect_mcp",
            "InstallMcp",
            "tool_execute",
            "execute_tool",
            "tokio_tungstenite",
            "TcpListener",
        ] {
            assert!(
                !symbols.idents.iter().any(|ident| ident == forbidden),
                "envelope must not contain identifier {forbidden}"
            );
        }
        let tokens = production_tokens(&envelope);
        for forbidden in ["mcp.connect", "Content-Length"] {
            assert!(
                !tokens.contains(forbidden),
                "envelope must not contain {forbidden}"
            );
        }
    }

    #[test]
    fn acp_transport_boundary_core_imports_no_cli_acp_schema() {
        let mut files = Vec::new();
        for root in rust_src_roots_outside_cli() {
            collect_rs_files(&root, &mut files);
        }
        assert!(
            !files.is_empty(),
            "ACP boundary ratchet found no non-CLI Rust source files"
        );
        for path in files {
            let symbols = production_symbols(&path);
            let imports_cli_acp = symbols
                .paths
                .iter()
                .any(|path| path == "cockpit_cli::acp" || path.starts_with("cockpit_cli::acp::"));
            let imports_schema = symbols
                .idents
                .iter()
                .any(|ident| ident == "agent_client_protocol_schema");
            let imports_frame_cap = symbols
                .idents
                .iter()
                .any(|ident| ident == "ACP_JSON_FRAME_MAX_BYTES_V1");
            assert!(
                !imports_cli_acp && !imports_schema && !imports_frame_cap,
                "{} must not import CLI ACP transport or schema types",
                path.display()
            );
        }
    }

    #[test]
    fn acp_transport_boundary_jsonrpsee_is_pinned_server_core_only() {
        let manifest = read_required(&Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"));
        assert!(manifest.contains("jsonrpsee = { version = \"=0.24.11\""));
        assert!(manifest.contains("jsonrpsee-types = { version = \"=0.24.11\""));
        assert!(manifest.contains("features = [\"server-core\"]"));
        assert!(manifest.contains("agent-client-protocol-schema = { version = \"=1.7.0\""));
        assert!(
            read_required(
                &Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/acp-jsonrpsee-audit.md")
            )
            .contains("0.24.11")
        );
    }
}
