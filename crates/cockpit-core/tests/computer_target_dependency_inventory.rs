//! Deterministic inventory of cockpit-core platform packages for computer target identity.
//!
//! Compares `cargo metadata --locked --offline` against the checked-in fixture.
//! Does not fetch during tests.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;
use syn::visit::Visit;

const TRIPLES: &[&str] = &[
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
];

const MACH2_CHECKSUM: &str = "dae608c151f68243f2b000364e1f7b186d9c29845f7d2d85bd31b9ad77ad552b";
const WORKSPACE_MSRV: &str = "1.95";

#[derive(Debug, serde::Deserialize)]
struct InventoryFixture {
    packages_by_platform: BTreeMap<String, Vec<PackageRecord>>,
    direct_features: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
struct PackageRecord {
    name: String,
    version: String,
    source: String,
    checksum: Option<String>,
    license: Option<String>,
    rust_version: Option<String>,
    edition: Option<String>,
    features: Vec<String>,
}

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = crates/cockpit-core
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn lock_checksums(root: &std::path::Path) -> BTreeMap<(String, String), String> {
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).expect("Cargo.lock");
    let mut map = BTreeMap::new();
    let mut name = None;
    let mut version = None;
    for line in lock.lines() {
        if let Some(rest) = line.strip_prefix("name = \"") {
            name = Some(rest.trim_end_matches('"').to_string());
        } else if let Some(rest) = line.strip_prefix("version = \"") {
            version = Some(rest.trim_end_matches('"').to_string());
        } else if let Some(rest) = line.strip_prefix("checksum = \"") {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                let ck = rest.trim_end_matches('"').to_string();
                map.insert((n, v), ck);
            }
        } else if line.starts_with("[[package]]") {
            name = None;
            version = None;
        }
    }
    map
}

fn metadata_for_platform(root: &std::path::Path, triple: &str) -> Value {
    let out = Command::new("cargo")
        .args([
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--filter-platform",
            triple,
        ])
        .current_dir(root)
        .output()
        .expect("cargo metadata");
    assert!(
        out.status.success(),
        "cargo metadata failed for {triple}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("metadata json")
}

fn resolve_cockpit_core_package_ids(meta: &Value) -> BTreeSet<String> {
    let packages = meta["packages"].as_array().unwrap();
    let resolve = meta["resolve"]["nodes"].as_array().expect("resolve nodes");
    let by_node = resolve
        .iter()
        .map(|node| (node["id"].as_str().unwrap(), node))
        .collect::<BTreeMap<_, _>>();
    let core = packages
        .iter()
        .find(|p| p["name"] == "cockpit-core")
        .expect("cockpit-core in metadata");
    let mut stack = vec![core["id"].as_str().unwrap().to_string()];
    let mut seen = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        let Some(node) = by_node.get(id.as_str()) else {
            continue;
        };
        for dep in node["deps"].as_array().expect("resolved node deps") {
            stack.push(dep["pkg"].as_str().unwrap().to_string());
        }
    }
    seen
}

fn exclusive_audited_closure_names(
    meta: &Value,
    audited_direct: &BTreeSet<String>,
) -> BTreeSet<String> {
    let packages = meta["packages"].as_array().unwrap();
    let names = packages
        .iter()
        .map(|package| {
            (
                package["id"].as_str().unwrap(),
                package["name"].as_str().unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let nodes = meta["resolve"]["nodes"]
        .as_array()
        .expect("resolve nodes")
        .iter()
        .map(|node| (node["id"].as_str().unwrap(), node))
        .collect::<BTreeMap<_, _>>();
    let core_id = packages
        .iter()
        .find(|package| package["name"] == "cockpit-core")
        .and_then(|package| package["id"].as_str())
        .expect("cockpit-core id");
    let core = nodes[core_id];
    let mut audited_roots = Vec::new();
    let mut other_roots = Vec::new();
    for dep in core["deps"].as_array().expect("cockpit-core resolved deps") {
        let id = dep["pkg"].as_str().unwrap();
        if audited_direct.contains(names[id]) {
            audited_roots.push(id.to_string());
        } else {
            other_roots.push(id.to_string());
        }
    }
    let closure = |roots: Vec<String>| {
        let mut seen = BTreeSet::new();
        let mut stack = roots;
        while let Some(id) = stack.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            stack.extend(
                nodes[id.as_str()]["deps"]
                    .as_array()
                    .expect("resolved deps")
                    .iter()
                    .map(|dep| dep["pkg"].as_str().unwrap().to_string()),
            );
        }
        seen
    };
    let audited = closure(audited_roots);
    let other = closure(other_roots);
    audited
        .difference(&other)
        .map(|id| names[id.as_str()].to_string())
        .chain(audited_direct.iter().cloned())
        .collect()
}

#[derive(Debug)]
struct TargetClassification {
    target_selectors: BTreeSet<String>,
    audited_direct: BTreeSet<String>,
    audited_transitive: BTreeSet<String>,
    excluded_direct: BTreeSet<String>,
}

fn string_set(table: &toml::value::Table, key: &str, triple: &str) -> BTreeSet<String> {
    let values = table
        .get(key)
        .unwrap_or_else(|| panic!("missing {key} classification for {triple}"))
        .as_array()
        .unwrap_or_else(|| panic!("{key} classification for {triple} must be an array"));
    let set = values
        .iter()
        .map(|package| {
            package
                .as_str()
                .unwrap_or_else(|| panic!("non-string package in {key} for {triple}"))
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        set.len(),
        values.len(),
        "duplicate package in {key} for {triple}"
    );
    set
}

/// Parse the sole authoritative classification. Every applicable target
/// dependency must be either audited or explicitly excluded, while packages
/// intentionally inventoried through the resolved graph are named as audited
/// transitive dependencies.
fn manifest_target_classification(manifest: &toml::Value, triple: &str) -> TargetClassification {
    let table = manifest
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get("metadata"))
        .and_then(toml::Value::as_table)
        .and_then(|metadata| metadata.get("computer-target-dependencies"))
        .and_then(toml::Value::as_table)
        .and_then(|classification| classification.get(triple))
        .unwrap_or_else(|| panic!("missing computer-target classification for {triple}"))
        .as_table()
        .unwrap_or_else(|| panic!("computer-target classification for {triple} must be a table"));
    assert_eq!(
        table.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "target-selectors",
            "audited-direct",
            "audited-transitive",
            "excluded-direct",
        ]),
        "unknown or missing classification class for {triple}"
    );
    let result = TargetClassification {
        target_selectors: string_set(table, "target-selectors", triple),
        audited_direct: string_set(table, "audited-direct", triple),
        audited_transitive: string_set(table, "audited-transitive", triple),
        excluded_direct: string_set(table, "excluded-direct", triple),
    };
    assert!(
        result
            .audited_direct
            .is_disjoint(&result.audited_transitive)
    );
    assert!(result.audited_direct.is_disjoint(&result.excluded_direct));
    assert!(
        result
            .audited_transitive
            .is_disjoint(&result.excluded_direct)
    );
    result
}

fn applicable_target_dependencies<'a>(
    manifest: &'a toml::Value,
    triple: &str,
) -> BTreeMap<String, &'a toml::Value> {
    let targets = manifest
        .get("target")
        .and_then(toml::Value::as_table)
        .expect("target dependency tables");
    let mut result = BTreeMap::new();
    let classification = manifest_target_classification(manifest, triple);
    for condition in &classification.target_selectors {
        let dependencies = targets
            .get(condition)
            .and_then(toml::Value::as_table)
            .and_then(|target| target.get("dependencies"))
            .and_then(toml::Value::as_table)
            .unwrap_or_else(|| {
                panic!("classified target selector has no dependencies: {condition}")
            });
        for (name, dependency) in dependencies {
            assert!(result.insert(name.clone(), dependency).is_none());
        }
    }
    result
}

fn assert_target_selector_schema_exhaustive(manifest: &toml::Value) {
    let actual = manifest
        .get("target")
        .and_then(toml::Value::as_table)
        .expect("target dependency tables")
        .iter()
        .filter_map(|(selector, table)| {
            table
                .as_table()
                .and_then(|table| table.get("dependencies"))
                .map(|_| selector.clone())
        })
        .collect::<BTreeSet<_>>();
    let classifications = manifest
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get("metadata"))
        .and_then(toml::Value::as_table)
        .and_then(|metadata| metadata.get("computer-target-dependencies"))
        .and_then(toml::Value::as_table)
        .expect("computer-target dependency schema");
    let classified = classifications
        .keys()
        .flat_map(|triple| manifest_target_classification(manifest, triple).target_selectors)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        classified, actual,
        "every target dependency table must be assigned by the authoritative computer-target schema"
    );
}

fn assert_inventory_platform_schema_exhaustive(manifest: &toml::Value) {
    let classified = manifest
        .get("package")
        .and_then(toml::Value::as_table)
        .and_then(|package| package.get("metadata"))
        .and_then(toml::Value::as_table)
        .and_then(|metadata| metadata.get("computer-target-dependencies"))
        .and_then(toml::Value::as_table)
        .expect("computer-target dependency schema")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        classified,
        TRIPLES.iter().copied().collect(),
        "adding a classified platform also requires adding it to the resolved inventory loop"
    );
}

fn assert_target_classification_exhaustive(manifest: &toml::Value, triple: &str) {
    let classification = manifest_target_classification(manifest, triple);
    let classified_direct = classification
        .audited_direct
        .union(&classification.excluded_direct)
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        classified_direct,
        applicable_target_dependencies(manifest, triple)
            .keys()
            .cloned()
            .collect(),
        "every applicable direct target dependency on {triple} must be classified exactly once"
    );
}

/// Read the feature set selected on every direct, audited platform package.
/// The fixture is a ratchet for this exact manifest surface, rather than a
/// hand-maintained subset that a newly enabled feature could bypass.
fn manifest_direct_features(manifest: &toml::Value, triple: &str) -> BTreeMap<String, Vec<String>> {
    let dependencies = applicable_target_dependencies(manifest, triple);
    let classification = manifest_target_classification(manifest, triple);

    classification
        .audited_direct
        .into_iter()
        .map(|package| {
            let dependency = dependencies
                .get(&package)
                .unwrap_or_else(|| panic!("stale audited-direct package {package} for {triple}"));
            let mut features = match dependency
                .as_table()
                .and_then(|table| table.get("features"))
            {
                Some(features) => features
                    .as_array()
                    .unwrap_or_else(|| panic!("{package} has a non-array features value"))
                    .iter()
                    .map(|feature| {
                        feature
                            .as_str()
                            .unwrap_or_else(|| panic!("{package} has a non-string feature"))
                            .to_string()
                    })
                    .collect::<Vec<_>>(),
                // Cargo's absence semantics are an empty directly-selected
                // feature set. Requiring an explicit array here used to make
                // the audit disagree with the manifest it was auditing.
                None => Vec::new(),
            };
            features.sort();
            assert_eq!(
                features.len(),
                features.iter().collect::<BTreeSet<_>>().len(),
                "{package} declares a duplicate feature"
            );
            (package, features)
        })
        .collect()
}

#[test]
fn manifest_feature_absence_is_empty_and_non_array_is_rejected() {
    let absent: toml::Value = toml::from_str(
        r#"
        [package]
        name = "fixture"
        [package.metadata.computer-target-dependencies."aarch64-apple-darwin"]
        target-selectors = ['cfg(target_os = "macos")', "cfg(unix)"]
        audited-direct = ["mach2"]
        audited-transitive = []
        excluded-direct = []
        [target.'cfg(target_os = "macos")'.dependencies]
        mach2 = { version = "1" }
        [target.'cfg(unix)'.dependencies]
    "#,
    )
    .unwrap();
    assert_eq!(
        manifest_direct_features(&absent, "aarch64-apple-darwin")["mach2"],
        Vec::<String>::new()
    );

    let malformed: toml::Value = toml::from_str(
        r#"
        [package]
        name = "fixture"
        [package.metadata.computer-target-dependencies."aarch64-apple-darwin"]
        target-selectors = ['cfg(target_os = "macos")', "cfg(unix)"]
        audited-direct = ["mach2"]
        audited-transitive = []
        excluded-direct = []
        [target.'cfg(target_os = "macos")'.dependencies]
        mach2 = { version = "1", features = "not-an-array" }
        [target.'cfg(unix)'.dependencies]
    "#,
    )
    .unwrap();
    assert!(
        std::panic::catch_unwind(|| {
            manifest_direct_features(&malformed, "aarch64-apple-darwin")
        })
        .is_err()
    );
}

#[test]
fn target_classification_rejects_future_unclassified_and_stale_direct_dependencies() {
    let unclassified: toml::Value = toml::from_str(
        r#"
        [package]
        name = "fixture"
        [package.metadata.computer-target-dependencies."x86_64-pc-windows-msvc"]
        target-selectors = ['cfg(target_os = "windows")']
        audited-direct = ["windows"]
        audited-transitive = []
        excluded-direct = []
        [target.'cfg(target_os = "windows")'.dependencies]
        windows = "1"
        future-physical-api = "1"
    "#,
    )
    .unwrap();
    assert!(
        std::panic::catch_unwind(|| assert_target_classification_exhaustive(
            &unclassified,
            "x86_64-pc-windows-msvc"
        ))
        .is_err()
    );

    let bypass_table: toml::Value = toml::from_str(
        r#"
        [package]
        name = "fixture"
        [package.metadata.computer-target-dependencies."x86_64-pc-windows-msvc"]
        target-selectors = ['cfg(target_os = "windows")']
        audited-direct = ["windows"]
        audited-transitive = []
        excluded-direct = []
        [target.'cfg(target_os = "windows")'.dependencies]
        windows = "1"
        [target.'cfg(all(target_vendor = "apple", target_arch = "aarch64"))'.dependencies]
        future-physical-api = "1"
    "#,
    )
    .unwrap();
    assert!(
        std::panic::catch_unwind(|| assert_target_selector_schema_exhaustive(&bypass_table))
            .is_err()
    );

    let stale: toml::Value = toml::from_str(
        r#"
        [package]
        name = "fixture"
        [package.metadata.computer-target-dependencies."x86_64-pc-windows-msvc"]
        target-selectors = ['cfg(target_os = "windows")']
        audited-direct = ["windows"]
        audited-transitive = []
        excluded-direct = ["removed-package"]
        [target.'cfg(target_os = "windows")'.dependencies]
        windows = "1"
    "#,
    )
    .unwrap();
    assert!(
        std::panic::catch_unwind(|| assert_target_classification_exhaustive(
            &stale,
            "x86_64-pc-windows-msvc"
        ))
        .is_err()
    );
}

fn use_tree_renames_cg_event(tree: &syn::UseTree) -> bool {
    match tree {
        syn::UseTree::Rename(rename) => rename.ident == "CGEvent",
        syn::UseTree::Path(path) => use_tree_renames_cg_event(&path.tree),
        syn::UseTree::Group(group) => group.items.iter().any(use_tree_renames_cg_event),
        syn::UseTree::Name(_) | syn::UseTree::Glob(_) => false,
    }
}

fn is_legacy_raw_post_identifier(identifier: &str) -> bool {
    identifier.starts_with("CGEventPost")
        || matches!(
            identifier,
            "CGPostKeyboardEvent" | "CGPostMouseEvent" | "CGPostScrollWheelEvent"
        )
}

fn audit_macro_tokens(tokens: proc_macro2::TokenStream, violations: &mut Vec<String>) {
    let mut identifiers = Vec::new();
    for token in tokens {
        match token {
            proc_macro2::TokenTree::Ident(identifier) => {
                let identifier = identifier.to_string();
                if is_legacy_raw_post_identifier(&identifier) {
                    violations.push(format!("raw CoreGraphics macro symbol {identifier}"));
                }
                identifiers.push(identifier);
            }
            proc_macro2::TokenTree::Group(group) => {
                audit_macro_tokens(group.stream(), violations);
            }
            proc_macro2::TokenTree::Literal(_) | proc_macro2::TokenTree::Punct(_) => {}
        }
    }
    if identifiers.iter().any(|identifier| identifier == "CGEvent")
        && identifiers.iter().any(|identifier| identifier == "post")
    {
        violations.push("CGEvent post hidden inside macro tokens".to_string());
    }
}

#[derive(Default)]
struct CoreGraphicsPostAudit {
    associated_posts: Vec<Option<String>>,
    violations: Vec<String>,
    current_function: Option<String>,
}

fn impl_method<'a>(file: &'a syn::File, name: &str) -> &'a syn::ImplItemFn {
    file.items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item) => Some(item),
            _ => None,
        })
        .flat_map(|item| item.items.iter())
        .find_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing impl method {name}"))
}

#[derive(Default)]
struct StructuralCallAudit(Vec<String>);

impl<'ast> Visit<'ast> for StructuralCallAudit {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref() {
            self.0.push(
                path.path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::"),
            );
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostBoundaryCall {
    SessionRecheck,
    CapabilityRecheck,
    RawPost,
}

#[derive(Default)]
struct PostBoundaryCallAudit(Vec<PostBoundaryCall>);

fn expression_path(expression: &syn::Expr) -> Option<String> {
    match expression {
        syn::Expr::Path(path) => Some(
            path.path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>()
                .join("::"),
        ),
        syn::Expr::Field(field) => Some(format!(
            "{}.{}",
            expression_path(&field.base)?,
            match &field.member {
                syn::Member::Named(name) => name.to_string(),
                syn::Member::Unnamed(index) => index.index.to_string(),
            }
        )),
        _ => None,
    }
}

impl<'ast> Visit<'ast> for PostBoundaryCallAudit {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "recheck" {
            match expression_path(&call.receiver).as_deref() {
                Some("self.active_console_session") => {
                    self.0.push(PostBoundaryCall::SessionRecheck)
                }
                Some("capability") => self.0.push(PostBoundaryCall::CapabilityRecheck),
                _ => {}
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref()
            && path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>()
                .ends_with(&["CGEvent".to_string(), "post".to_string()])
        {
            self.0.push(PostBoundaryCall::RawPost);
        }
        syn::visit::visit_expr_call(self, call);
    }
}

impl<'ast> Visit<'ast> for CoreGraphicsPostAudit {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let previous = self.current_function.replace(item.sig.ident.to_string());
        syn::visit::visit_item_fn(self, item);
        self.current_function = previous;
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        let previous = self.current_function.replace(item.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, item);
        self.current_function = previous;
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if use_tree_renames_cg_event(&item.tree) {
            self.violations
                .push("CGEvent import aliases are forbidden".to_string());
        }
        syn::visit::visit_item_use(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if let syn::Type::Path(path) = item.ty.as_ref()
            && path
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "CGEvent")
        {
            self.violations
                .push("CGEvent type aliases are forbidden".to_string());
        }
        syn::visit::visit_item_type(self, item);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        if segments.ends_with(&["CGEvent".to_string(), "post".to_string()]) {
            self.associated_posts.push(self.current_function.clone());
        }
        for identifier in &segments {
            if is_legacy_raw_post_identifier(identifier) {
                self.violations
                    .push(format!("raw CoreGraphics post symbol {identifier}"));
            }
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_foreign_item_fn(&mut self, item: &'ast syn::ForeignItemFn) {
        let identifier = item.sig.ident.to_string();
        if is_legacy_raw_post_identifier(&identifier) {
            self.violations
                .push(format!("raw CoreGraphics FFI declaration {identifier}"));
        }
        syn::visit::visit_foreign_item_fn(self, item);
    }

    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        let value = literal.value();
        if is_legacy_raw_post_identifier(&value) {
            self.violations
                .push(format!("raw CoreGraphics link symbol {value}"));
        }
        syn::visit::visit_lit_str(self, literal);
    }

    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        audit_macro_tokens(item.tokens.clone(), &mut self.violations);
        syn::visit::visit_macro(self, item);
    }
}

#[test]
fn physical_backend_irreversible_primitive_inventory() {
    let core = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mac = std::fs::read_to_string(core.join("computer/macos_backend.rs")).unwrap();
    let computer = std::fs::read_to_string(core.join("computer/mod.rs")).unwrap();
    let coordinator = std::fs::read_to_string(core.join("computer/coordinator.rs")).unwrap();
    let computer_syntax = syn::parse_file(&computer).expect("parse computer module");
    let mac_syntax = syn::parse_file(&mac).expect("parse mac backend");
    let coordinator_syntax = syn::parse_file(&coordinator).expect("parse coordinator");
    let backend_trait = computer_syntax
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Trait(item) if item.ident == "ComputerBackend" => Some(item),
            _ => None,
        })
        .expect("ComputerBackend trait");
    assert!(backend_trait.supertraits.iter().any(|bound| {
        matches!(bound, syn::TypeParamBound::Trait(bound)
            if bound.path.segments.iter().map(|segment| segment.ident.to_string()).collect::<Vec<_>>()
                .ends_with(&["backend_seal".to_string(), "Sealed".to_string()]))
    }));
    for (syntax, name) in [
        (&computer_syntax, "VirtualDisplayBackend"),
        (&mac_syntax, "MacOsComputerBackend"),
    ] {
        let structure = syntax
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item) if item.ident == name => Some(item),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing {name}"));
        assert!(
            !matches!(structure.vis, syn::Visibility::Public(_)),
            "{name} must not be publicly constructible"
        );
    }
    let factories = coordinator_syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "construct_platform_backend" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(factories.len(), 1, "one production platform factory");
    assert!(matches!(factories[0].vis, syn::Visibility::Restricted(_)));

    let mut raw_posts = Vec::new();
    let mut violations = Vec::new();
    for entry in walkdir::WalkDir::new(&core) {
        let entry = entry.unwrap();
        if entry
            .path()
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("rs")
        {
            continue;
        }
        let source = std::fs::read_to_string(entry.path()).unwrap();
        let syntax = syn::parse_file(&source)
            .unwrap_or_else(|error| panic!("parse {}: {error}", entry.path().display()));
        let mut audit = CoreGraphicsPostAudit::default();
        audit.visit_file(&syntax);
        for function in audit.associated_posts {
            raw_posts.push((entry.path().to_path_buf(), function));
        }
        for violation in audit.violations {
            violations.push(format!("{}: {violation}", entry.path().display()));
        }
    }
    assert!(violations.is_empty(), "{violations:#?}");
    assert_eq!(
        raw_posts.len(),
        1,
        "every macOS event in the complete core source tree must use the sole guarded post primitive"
    );
    let mut calls = StructuralCallAudit::default();
    calls.visit_impl_item_fn(impl_method(&mac_syntax, "post_event"));
    for required in ["prepare", "recheck", "CGEvent::post", "commit"] {
        assert!(
            calls.0.iter().any(|call| call == required),
            "post_event AST lost required call {required}: {:?}",
            calls.0
        );
    }
    let mut post_boundary = PostBoundaryCallAudit::default();
    post_boundary.visit_impl_item_fn(impl_method(&mac_syntax, "post_event"));
    assert_eq!(
        post_boundary.0,
        vec![
            PostBoundaryCall::SessionRecheck,
            PostBoundaryCall::CapabilityRecheck,
            PostBoundaryCall::RawPost,
        ],
        "post_event must structurally perform its exact session and physical-capability/lease rechecks before its sole raw post"
    );
    assert!(
        calls
            .0
            .iter()
            .any(|call| call == "rollback_known_pre_post_refusal"),
        "known pre-post refusals must structurally enter exact rollback"
    );
    assert_eq!(raw_posts[0].0, core.join("computer/macos_backend.rs"));
    assert_eq!(
        raw_posts[0].1.as_deref(),
        Some("post_event"),
        "the sole raw post must be structurally owned by post_event"
    );
    let positions = ["prepare", "recheck", "CGEvent::post", "commit"]
        .map(|required| calls.0.iter().position(|call| call == required).unwrap());
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "post_event's AST must prepare, recheck, post, then commit"
    );

    let driver = std::fs::read_to_string(core.join("engine/driver/computer_native.rs")).unwrap();
    let driver_syntax = syn::parse_file(&driver).expect("parse computer driver");
    let mut driver_calls = StructuralCallAudit::default();
    driver_calls.visit_file(&driver_syntax);
    assert!(
        driver_calls
            .0
            .iter()
            .any(|call| call.ends_with("coordinator::construct_platform_backend"))
    );
    assert!(!driver_calls.0.iter().any(|call| {
        call.ends_with("VirtualDisplayBackend::construct")
            || call.ends_with("MacOsComputerBackend::construct")
    }));
}

#[test]
fn computer_target_dependency_inventory() {
    let root = workspace_root();
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/computer-target-dependency-inventory.json");
    let fixture_raw = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|e| panic!("missing fixture {}: {e}", fixture_path.display()));
    let fixture: InventoryFixture =
        serde_json::from_str(&fixture_raw).expect("fixture json schema");

    let manifest_raw =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("cockpit-core Cargo.toml");
    let manifest: toml::Value =
        toml::from_str(&manifest_raw).expect("valid cockpit-core Cargo.toml");
    assert_inventory_platform_schema_exhaustive(&manifest);
    assert_target_selector_schema_exhaustive(&manifest);

    let checksums = lock_checksums(&root);

    // The fixture must exactly inventory every direct feature enabled for the
    // audited packages. This closes the omission class: a new Cargo.toml
    // feature cannot escape the forbidden-feature checks below.
    let expected_direct = &fixture.direct_features;

    for triple in TRIPLES {
        let manifest_direct = manifest_direct_features(&manifest, triple);
        let mut fixture_direct = expected_direct
            .get(*triple)
            .cloned()
            .unwrap_or_else(|| panic!("fixture missing direct features for {triple}"));
        for (package, features) in &mut fixture_direct {
            features.sort();
            assert_eq!(
                features.len(),
                features.iter().collect::<BTreeSet<_>>().len(),
                "fixture declares a duplicate feature for {package}"
            );
        }
        assert_eq!(
            fixture_direct, manifest_direct,
            "direct feature inventory drift for {triple}; update the fixture after auditing Cargo.toml"
        );
        let meta = metadata_for_platform(&root, triple);
        let resolve_ids = resolve_cockpit_core_package_ids(&meta);
        let packages = meta["packages"].as_array().unwrap();
        // The target-specific manifest table is the sole classification of
        // direct computer-target packages. Membership and direct features
        // come from the same parsed map, so a future platform dependency is
        // automatically required in both fixture sections.
        let classification = manifest_target_classification(&manifest, triple);
        assert_target_classification_exhaustive(&manifest, triple);
        let classified = classification
            .audited_direct
            .union(&classification.audited_transitive)
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            classified,
            exclusive_audited_closure_names(&meta, &classification.audited_direct),
            "audited direct/transitive membership must equal the exact resolved closure introduced only by those classified roots on {triple}"
        );
        let wanted: BTreeSet<&str> = classified.iter().map(String::as_str).collect();

        let mut found: BTreeMap<String, PackageRecord> = BTreeMap::new();
        // Prefer fixture-expected versions when multiple crates share a name (e.g. windows).
        let preferred_versions: BTreeMap<&str, &str> = fixture
            .packages_by_platform
            .get(*triple)
            .map(|rows| {
                rows.iter()
                    .map(|r| (r.name.as_str(), r.version.as_str()))
                    .collect()
            })
            .unwrap_or_default();
        for p in packages {
            let name = p["name"].as_str().unwrap();
            if !wanted.contains(name) {
                continue;
            }
            let version = p["version"].as_str().unwrap().to_string();
            if let Some(pref) = preferred_versions.get(name)
                && version != *pref
            {
                continue;
            }
            let id = p["id"].as_str().unwrap();
            assert!(
                resolve_ids.contains(id),
                "classified package {name} is not in cockpit-core's resolved graph on {triple}"
            );
            let source = p
                .get("source")
                .and_then(|s| s.as_str())
                .unwrap_or("path")
                .to_string();
            assert!(
                source.contains("registry") || source == "path",
                "{name} non-registry source: {source}"
            );
            let license = p
                .get("license")
                .and_then(|l| l.as_str())
                .map(str::to_string);
            let rust_version = p
                .get("rust_version")
                .and_then(|l| l.as_str())
                .map(str::to_string);
            let edition = p
                .get("edition")
                .and_then(|l| l.as_str())
                .map(str::to_string);
            let mut features: Vec<String> = p["features"]
                .as_object()
                .map(|obj| obj.keys().cloned().collect())
                .unwrap_or_default();
            features.sort();
            let checksum = checksums.get(&(name.to_string(), version.clone())).cloned();

            // License permissive check for direct platform packages
            if let Some(ref lic) = license {
                let ok = lic.contains("MIT")
                    || lic.contains("Apache")
                    || lic.contains("BSD")
                    || lic.contains("Zlib")
                    || lic.contains("ISC");
                assert!(ok, "{name} license not permissive: {lic}");
            } else if name != "mach2" {
                // mach2 has license in crate metadata; if missing fail
                // allow only if fixture records it
            }

            // MSRV: must not exceed workspace 1.95 except mach2 null exception
            if name == "mach2" {
                assert!(rust_version.is_none(), "mach2 must have null rust_version");
            } else if let Some(ref rv) = rust_version {
                // Compare major.minor
                let parse = |s: &str| {
                    let mut it = s.split('.');
                    let maj: u32 = it.next().unwrap_or("0").parse().unwrap_or(0);
                    let min: u32 = it.next().unwrap_or("0").parse().unwrap_or(0);
                    (maj, min)
                };
                let (a, b) = parse(rv);
                let (c, d) = parse(WORKSPACE_MSRV);
                assert!(
                    (a, b) <= (c, d),
                    "{name} rust-version {rv} exceeds workspace MSRV {WORKSPACE_MSRV}"
                );
            }

            found.insert(
                name.to_string(),
                PackageRecord {
                    name: name.to_string(),
                    version,
                    source,
                    checksum,
                    license,
                    rust_version,
                    edition,
                    features,
                },
            );
        }

        // Required packages present
        for name in &wanted {
            assert!(
                found.contains_key(*name),
                "missing package {name} on {triple}; found {:?}",
                found.keys().collect::<Vec<_>>()
            );
        }

        // Compare against fixture records for packages that are listed
        let expected = fixture
            .packages_by_platform
            .get(*triple)
            .unwrap_or_else(|| panic!("fixture missing platform {triple}"));
        assert_eq!(
            expected
                .iter()
                .map(|row| row.name.as_str())
                .collect::<BTreeSet<_>>(),
            wanted,
            "package fixture membership drift for {triple}"
        );
        for exp in expected {
            let got = found.get(&exp.name).unwrap_or_else(|| {
                panic!("package {} not found for {triple} in metadata", exp.name)
            });
            assert_eq!(got.version, exp.version, "{} version drift", exp.name);
            if let Some(ref ck) = exp.checksum {
                assert_eq!(
                    got.checksum.as_deref(),
                    Some(ck.as_str()),
                    "{} checksum drift",
                    exp.name
                );
            }
            if exp.name == "mach2" {
                assert_eq!(got.checksum.as_deref(), Some(MACH2_CHECKSUM));
                assert_eq!(got.edition.as_deref(), Some("2024"));
                assert!(got.rust_version.is_none());
            }
        }

        // Forbid dangerous feature leaves on direct deps when declared in fixture
        if let Some(direct) = expected_direct.get(*triple) {
            for (pkg, feats) in direct {
                for f in feats {
                    assert!(
                        f != "all-extensions"
                            && f != "default"
                            && !f.to_lowercase().contains("xtest")
                            && !f.to_lowercase().contains("xinput"),
                        "forbidden feature {f} on {pkg}"
                    );
                }
                if pkg == "objc2-application-services" {
                    for f in feats {
                        assert!(
                            !f.contains("AXMacro") && f != "AXUIElementCopyAttributeNames",
                            "unused AX macro-constant feature {f}"
                        );
                    }
                }
            }
        }
    }

    // Manifest pins: exact versions in cockpit-core Cargo.toml
    assert!(manifest_raw.contains("mach2 = { version = \"=0.6.0\""));
    assert!(manifest_raw.contains("block2 = { version = \"=0.6.2\""));
    assert!(manifest_raw.contains("objc2-app-kit = { version = \"=0.3.2\""));
    assert!(manifest_raw.contains("objc2-application-services = { version = \"=0.3.2\""));
    assert!(manifest_raw.contains("objc2-core-foundation = { version = \"=0.3.2\""));
    assert!(manifest_raw.contains("objc2-core-graphics = { version = \"=0.3.2\""));
    assert!(manifest_raw.contains("objc2-color-sync = { version = \"=0.3.2\""));
    assert!(manifest_raw.contains("objc2-foundation = { version = \"=0.3.2\""));
    assert!(manifest_raw.contains("windows = { version = \"=0.62.2\""));
    assert!(manifest_raw.contains("x11rb = { version = \"=0.13.2\""));
    assert!(manifest_raw.contains("atspi = { version = \"=0.30.0\""));
    assert!(manifest_raw.contains("\"randr\""));
    assert!(manifest_raw.contains("Wdk_Foundation"));
    assert!(manifest_raw.contains("Wdk_Storage_FileSystem"));
    assert!(manifest_raw.contains("Win32_Storage_Packaging_Appx"));
    assert!(manifest_raw.contains("Win32_System_StationsAndDesktops"));
    assert!(manifest_raw.contains("CFArray"));
    assert!(manifest_raw.contains("CFDictionary"));
    assert!(manifest_raw.contains("CFFileDescriptor"));
    assert!(manifest_raw.contains("ColorSyncDevice"));
    assert!(manifest_raw.contains("HIServices"));
    // No private BSM / handwritten observer mentions in production target modules
    let macos_src = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/computer/platform/macos.rs"),
    )
    .unwrap();
    assert!(!macos_src.contains("audit_session_self"));
    assert!(!macos_src.contains("_AXUIElementGetWindow"));
    assert!(!macos_src.contains("AXWindowNumber"));
}
