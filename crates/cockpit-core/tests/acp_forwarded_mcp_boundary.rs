use std::fs;
use std::path::{Path, PathBuf};

use syn::spanned::Spanned;
use syn::visit::Visit;
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

fn production_source(path: &Path) -> String {
    let source = fs::read_to_string(path).expect("read Rust source");
    strip_test_only_items(&source)
}

fn strip_test_only_items(source: &str) -> String {
    let file = syn::parse_file(&source).expect("parse Rust source");
    let mut stripper = TestOnlyStripper::default();
    stripper.visit_file(&file);
    strip_source_ranges(&source, &stripper.ranges)
}

fn strip_source_ranges(source: &str, ranges: &[SourceRange]) -> String {
    let mut sorted = ranges.to_vec();
    sorted.sort_by_key(|range| (range.start_line, range.start_column));
    let line_starts = line_starts(source);
    let mut cursor = 0usize;
    let mut output = String::with_capacity(source.len());
    for range in sorted {
        let start = line_starts[range.start_line - 1] + range.start_column;
        let end = line_starts[range.end_line - 1] + range.end_column;
        if start < cursor || end < start || end > source.len() {
            continue;
        }
        output.push_str(&source[cursor..start]);
        cursor = end;
    }
    output.push_str(&source[cursor..]);
    output
}

fn line_starts(source: &str) -> Vec<usize> {
    let mut starts = vec![0usize];
    starts.extend(
        source
            .match_indices('\n')
            .map(|(idx, _)| idx + 1)
            .collect::<Vec<_>>(),
    );
    starts
}

#[derive(Clone, Copy)]
struct SourceRange {
    start_line: usize,
    start_column: usize,
    end_line: usize,
    end_column: usize,
}

#[derive(Default)]
struct TestOnlyStripper {
    ranges: Vec<SourceRange>,
}

impl TestOnlyStripper {
    fn record_item<T: Spanned>(&mut self, attrs: &[syn::Attribute], item: &T) -> bool {
        if attrs.iter().any(cfg_mentions_test) {
            let start = attrs
                .first()
                .map(Spanned::span)
                .unwrap_or_else(|| item.span())
                .start();
            let end = item.span().end();
            self.ranges.push(SourceRange {
                start_line: start.line,
                start_column: start.column,
                end_line: end.line,
                end_column: end.column,
            });
            true
        } else {
            false
        }
    }
}

impl<'ast> Visit<'ast> for TestOnlyStripper {
    fn visit_item(&mut self, item: &'ast Item) {
        if self.record_item(item_attrs(item), item) {
            return;
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if self.record_item(&item.attrs, item) {
            return;
        }
        syn::visit::visit_impl_item_fn(self, item);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if self.record_item(&item.attrs, item) {
            return;
        }
        syn::visit::visit_trait_item_fn(self, item);
    }
}

fn item_attrs(item: &Item) -> &[syn::Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        Item::Verbatim(_) => &[],
        _ => &[],
    }
}

fn cfg_mentions_test(attr: &syn::Attribute) -> bool {
    if !attr.path().is_ident("cfg") {
        return false;
    }
    let mut mentions_test = false;
    let _ = attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("test") {
            mentions_test = true;
        }
        Ok(())
    });
    mentions_test
}

#[test]
fn production_source_strips_each_test_only_item_without_truncating_later_production() {
    let source = r#"
        fn before() {}
        #[cfg(test)]
        fn test_only_sink() { let _ = "GrantStore"; }
        fn after() { let _ = "CredentialStore"; }
    "#;
    let production = strip_test_only_items(source);
    assert!(production.contains("fn before"));
    assert!(!production.contains("test_only_sink"));
    assert!(production.contains("fn after"));
    assert!(production.contains("CredentialStore"));
}

#[test]
fn cockpit_core_has_no_cli_or_acp_transport_schema_dependency() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rust_files(&root, &mut files);
    assert!(!files.is_empty());
    for path in files {
        // `engine/**/tests.rs` files are included only by a `#[cfg(test)]`
        // module in their production sibling. They do not take part in the
        // production core dependency graph, even though they are standalone
        // Rust files for the test compiler.
        if path.file_name().is_some_and(|name| name == "tests.rs") {
            continue;
        }
        // This is a dependency-boundary ratchet, not a documentation
        // ratchet: core may describe the CLI host in comments and test-only
        // contracts without depending on its transport schema.
        let source = production_source(&path)
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
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
        if is_public
            && name.contains("Acp")
            && (name.contains("Mcp") || name == "AcpNameValuePairV1")
        {
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
            let source = production_source(path);
            (
                path.strip_prefix(&source_root)
                    .expect("path below source root"),
                source,
            )
        })
        .collect::<Vec<_>>();

    // This is the complete production capability graph for editor-provided
    // values. A forwarded entry's private credential-bearing fields can leave
    // `mcp/forwarded.rs` only through the typed constructors below: catalog
    // dispatches `connect_forwarded`, which selects the typed stdio, HTTP, or
    // SSE constructor. A new helper or transport must therefore name a
    // forwarded type and become a declared graph member before it can receive
    // those values.
    let allowed_capability_files = [
        Path::new("approval/mod.rs"),
        Path::new("approval/policy.rs"),
        Path::new("daemon/acp_catalog_composition.rs"),
        Path::new("daemon/session_worker/handle.rs"),
        Path::new("mcp/catalog.rs"),
        Path::new("mcp/client.rs"),
        Path::new("mcp/forwarded.rs"),
        Path::new("mcp/transport/http.rs"),
        Path::new("mcp/transport/sse.rs"),
        Path::new("mcp/transport/stdio.rs"),
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
                .then_some((*path, source.as_str()))
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
    let mut actual_capability_files = capability_paths
        .iter()
        .map(|(path, _)| *path)
        .collect::<Vec<_>>();
    actual_capability_files.sort();
    let mut expected_capability_files = allowed_capability_files.to_vec();
    expected_capability_files.sort();
    assert_eq!(
        actual_capability_files, expected_capability_files,
        "the complete forwarded capability graph changed; audit every new or removed consumer"
    );

    // Keep the whole transitive transport set explicit. These constructors
    // are the only typed hand-offs of the endpoint/header and stdio
    // command/argument/environment values; ordinary persistent MCP calls use
    // the untagged constructors elsewhere in `mcp/client.rs`.
    let forwarded_connect = production
        .iter()
        .find_map(|(path, source)| (*path == Path::new("mcp/client.rs")).then_some(source.as_str()))
        .expect("MCP client is a production capability member")
        .split("pub async fn connect_forwarded(")
        .nth(1)
        .expect("forwarded connection function")
        .split("fn server_requires_secret_store")
        .next()
        .expect("forwarded connection boundary");
    for (path, constructor) in [
        (
            Path::new("mcp/transport/stdio.rs"),
            "StdioClient::spawn_forwarded",
        ),
        (
            Path::new("mcp/transport/http.rs"),
            "HttpClient::new_forwarded",
        ),
        (
            Path::new("mcp/transport/sse.rs"),
            "SseClient::new_forwarded",
        ),
    ] {
        let source = production
            .iter()
            .find_map(|(candidate, source)| (*candidate == path).then_some(source.as_str()))
            .unwrap_or_else(|| panic!("missing forwarded transport consumer {}", path.display()));
        assert!(
            capability_paths
                .iter()
                .any(|(candidate, _)| *candidate == path),
            "forwarded transport consumer {} is not marked by a forwarded type",
            path.display()
        );
        assert!(
            forwarded_connect.contains(constructor),
            "forwarded connection bypasses typed transport consumer {constructor}"
        );
        assert!(
            source.contains("AcpForwarded"),
            "typed forwarded transport consumer {} lost its closed source boundary",
            path.display()
        );
        for forbidden in [
            "cache::save",
            "cache::load",
            "CredentialStore",
            "SecretVault",
            "GrantStore",
            "serde::Serialize",
            "derive(Serialize",
            "insert_session_event",
            "write_session",
            "session_log",
        ] {
            assert!(
                !source.contains(forbidden),
                "forwarded transport consumer {} can retain values in {forbidden}",
                path.display()
            );
        }
    }
    // The forwarding-specific accessors are the only raw-value escape hatches
    // from their private fields. They may be called only by the typed
    // transport constructors above; an unmarked string/map helper would fail
    // this assertion instead of silently falling outside the graph.
    for (accessor, allowed_paths) in [
        (
            ".forwarded_command()",
            &[Path::new("mcp/transport/stdio.rs")][..],
        ),
        (
            ".forwarded_args()",
            &[Path::new("mcp/transport/stdio.rs")][..],
        ),
        (
            ".forwarded_env()",
            &[Path::new("mcp/transport/stdio.rs")][..],
        ),
        (
            ".forwarded_url()",
            &[
                Path::new("mcp/transport/http.rs"),
                Path::new("mcp/transport/sse.rs"),
            ][..],
        ),
        (
            ".forwarded_headers()",
            &[
                Path::new("mcp/transport/http.rs"),
                Path::new("mcp/transport/sse.rs"),
            ][..],
        ),
    ] {
        for (path, source) in &production {
            if source.contains(accessor) {
                assert!(
                    allowed_paths.contains(path),
                    "forwarded raw-value accessor {accessor} escaped the typed transport graph in {}",
                    path.display()
                );
            }
        }
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

    // Host approval/effect audit fields must never receive an
    // editor-controlled declaration name. Transport internals still use the
    // name as an in-memory lookup key, but the external-effect payloads use
    // the bounded host-owned display label.
    for boundary in [
        "acp_forwarded_mcp_stdio_spawn",
        "acp_forwarded_mcp_initialize",
    ] {
        let effect = forwarded_connect
            .split(boundary)
            .nth(1)
            .unwrap_or_else(|| panic!("missing forwarded effect boundary {boundary}"))
            .split(")],")
            .next()
            .expect("forwarded effect payload");
        assert!(effect.contains("entry.redacted_display_name()"));
        assert!(!effect.contains("entry.name()"));
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
    let tool_effect = forwarded_invoke
        .split("acp_forwarded_mcp_tools_call")
        .nth(1)
        .expect("forwarded tool effect boundary")
        .split(")],")
        .next()
        .expect("forwarded tool effect payload");
    assert!(tool_effect.contains("\"source\": super::forwarded::SOURCE_ACP_FORWARDED"));
    assert!(tool_effect.contains("\"opaque_ids\""));
    assert!(tool_effect.contains("\"transport\": entry.transport_kind()"));
    assert!(tool_effect.contains("\"server_label\": entry.redacted_display_name()"));
    assert!(!tool_effect.contains("entry.name()"));
    assert!(!tool_effect.contains("\"server\": entry.redacted_display_name()"));
    assert!(!tool_effect.contains("\"tool\": tool"));
    assert!(!tool_effect.contains("\"tool\":tool"));
    assert!(!tool_effect.contains("tool: tool"));
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
    let forwarded_prompt = forwarded_approval
        .split("let prompt =")
        .nth(1)
        .and_then(|tail| tail.split("let question =").next())
        .expect("forwarded durable prompt");
    for forbidden in ["{tool}", "Some(tool)"] {
        assert!(
            !forwarded_prompt.contains(forbidden),
            "forwarded durable approval prompt must not retain the remote tool name ({forbidden})"
        );
    }
    assert!(
        !forwarded_invoke.contains("\"tool\": tool") && !forwarded_invoke.contains("\"tool\":tool"),
        "forwarded external approval/effect payload must not carry a raw tool binding"
    );
}

#[test]
fn acp_catalog_binding_precedes_base_code_root_publication() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dispatch = fs::read_to_string(manifest.join("src/daemon/server/dispatch.rs"))
        .expect("read daemon dispatch source");

    let composed_create = dispatch
        .split("Request::CreateCodeRootWithAcpIngressV1(request) =>")
        .nth(1)
        .and_then(|tail| {
            tail.split("Request::AttachExistingCodeRootWithAcpIngressV1(request) =>")
                .next()
        })
        .expect("ACP create composition route");
    let composed_attach = dispatch
        .split("Request::AttachExistingCodeRootWithAcpIngressV1(request) =>")
        .nth(1)
        .and_then(|tail| {
            tail.split("Request::CloseAcpCodeRootAttachmentV1(request) =>")
                .next()
        })
        .expect("ACP attach composition route");
    for route in [composed_create, composed_attach] {
        assert!(route.contains("pending_acp_catalog_composition"));
        assert!(
            !route.contains("service.bind_catalog"),
            "the composed wrapper must install a pre-publication gate, not bind after base publication"
        );
    }

    for (base_route, receipt) in [
        (
            "Request::CreateCodeRootV1(request) =>",
            ".record_create(&request",
        ),
        (
            "Request::AttachExistingCodeRootV1(request) =>",
            ".record_attach(&request",
        ),
    ] {
        let base = dispatch
            .split(base_route)
            .nth(1)
            .and_then(|tail| {
                tail.split("Request::CloseCodeRootAttachmentV1(request) =>")
                    .next()
            })
            .expect("base Code-root route");
        let binding = base
            .find("bind_pending_acp_catalog_before_code_root_publication")
            .expect("catalog composition gate");
        let publication = base.find(receipt).expect("base publication receipt");
        assert!(
            binding < publication,
            "catalog binding must complete before the base attachment receipt is published"
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
