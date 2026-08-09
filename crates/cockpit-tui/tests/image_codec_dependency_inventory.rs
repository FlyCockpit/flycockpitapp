use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Fixture {
    schema_version: u64,
    packages: BTreeMap<String, PackageFixture>,
    targets: TargetsFixture,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetsFixture {
    #[serde(rename = "x86_64-unknown-linux-gnu")]
    linux: TargetFixture,
    #[serde(rename = "aarch64-apple-darwin")]
    macos: TargetFixture,
    #[serde(rename = "x86_64-pc-windows-msvc")]
    windows: TargetFixture,
}

impl TargetsFixture {
    fn iter(&self) -> [(TargetTriple, &TargetFixture); 3] {
        [
            (TargetTriple::Linux, &self.linux),
            (TargetTriple::Macos, &self.macos),
            (TargetTriple::Windows, &self.windows),
        ]
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PackageFixture {
    checksum: String,
    raw_metadata_feature_union: Vec<String>,
    license: Option<String>,
    rust_version: Option<String>,
    source: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TargetFixture {
    arboard_features: Vec<String>,
    edges: Vec<EdgeFixture>,
    package_features: BTreeMap<String, Vec<String>>,
    packages: Vec<String>,
    probe_formats: Vec<String>,
    provenance_edges: Vec<EdgeFixture>,
    resolved_features: Vec<String>,
    tui_features: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
enum TargetTriple {
    #[serde(rename = "x86_64-unknown-linux-gnu")]
    Linux,
    #[serde(rename = "aarch64-apple-darwin")]
    Macos,
    #[serde(rename = "x86_64-pc-windows-msvc")]
    Windows,
}

impl TargetTriple {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "x86_64-unknown-linux-gnu",
            Self::Macos => "aarch64-apple-darwin",
            Self::Windows => "x86_64-pc-windows-msvc",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
enum Provenance {
    ImageDescendant,
    ImageRequester,
    TuiNormal,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct EdgeFixture {
    from: String,
    to: String,
    target: TargetTriple,
    provenance: Provenance,
}

fn cargo_tree(workspace: &Path, triple: &str, package: &str, edges: &str, format: &str) -> String {
    let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .current_dir(workspace)
        .args([
            "tree",
            "--locked",
            "--offline",
            "--target",
            triple,
            "-e",
            edges,
            "-p",
            package,
            "--prefix",
            "depth",
            "--format",
            format,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cargo tree failed for {package} on {triple}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn strip_optional_duplicate_marker<'a>(row: &'a str, context: &str) -> (&'a str, bool) {
    let Some(without_marker) = row.strip_suffix(" (*)") else {
        return (row, false);
    };
    assert!(
        !without_marker.ends_with(" (*)"),
        "{context} contains repeated duplicate markers: {row}"
    );
    (without_marker, true)
}

fn tree_package_key(row: &str) -> String {
    let (package, _) = strip_optional_duplicate_marker(row, "cargo tree package row");
    let (name, version) = package
        .rsplit_once(" v")
        .unwrap_or_else(|| panic!("unexpected cargo tree package row: {row}"));
    assert!(
        !name.is_empty(),
        "malformed cargo tree package row with empty name: {row}"
    );
    let version = version
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("malformed cargo tree package row with empty version: {row}"));
    assert_eq!(
        package,
        format!("{name} v{version}"),
        "malformed cargo tree package row with trailing tokens: {row}"
    );
    format!("{name}@{version}")
}

#[test]
#[should_panic(expected = "cargo tree package row with empty version: image v")]
fn tree_package_key_rejects_empty_versions_precisely() {
    tree_package_key("image v");
}

#[test]
#[should_panic(expected = "cargo tree package row with empty name:  v1.0.0")]
fn tree_package_key_rejects_empty_names_precisely() {
    tree_package_key(" v1.0.0");
}

#[test]
#[should_panic(expected = "package row with trailing tokens: image v0.25.10 unexpected")]
fn tree_package_key_rejects_trailing_tokens() {
    tree_package_key("image v0.25.10 unexpected");
}

#[test]
#[should_panic(expected = "package row contains repeated duplicate markers")]
fn tree_package_key_rejects_repeated_duplicate_markers() {
    tree_package_key("image v0.25.10 (*) (*)");
}

fn target_package_features(
    feature_tree: &str,
    graph_packages: &BTreeSet<String>,
    expected_root: &str,
) -> BTreeMap<String, BTreeSet<String>> {
    // `cargo tree -e features` does not print a package row when the package has
    // no activated features. Seed the inventory from the independently observed
    // normal/build graph so those packages still receive an authoritative empty
    // feature set.
    let mut package_features = graph_packages
        .iter()
        .cloned()
        .map(|package| (package, BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    let mut reported_packages = BTreeSet::new();
    let mut feature_nodes = Vec::<(usize, String, Option<String>, bool)>::new();
    let mut feature_ancestors = Vec::<bool>::new();

    for line in feature_tree.lines() {
        let depth_end = line
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or_else(|| panic!("cargo feature-tree row contains only a depth: {line}"));
        assert!(
            depth_end > 0,
            "cargo feature-tree row is missing a depth: {line}"
        );
        let depth = line[..depth_end].parse::<usize>().unwrap();
        assert_eq!(
            line[..depth_end],
            depth.to_string(),
            "cargo feature-tree row has a noncanonical depth: {line}"
        );
        if feature_ancestors.is_empty() {
            assert_eq!(
                depth, 0,
                "cargo feature-tree first row must have depth zero: {line}"
            );
        } else {
            assert!(
                depth > 0,
                "cargo feature-tree contains multiple roots: {line}"
            );
            assert!(
                depth <= feature_ancestors.len(),
                "cargo feature-tree depth jumps past its parent: {line}"
            );
        }
        if depth > 0 && feature_ancestors[depth - 1] {
            panic!("cargo feature-tree duplicate marker node has a child: {line}");
        }
        feature_ancestors.truncate(depth);
        let row = &line[depth_end..];
        let (row, duplicate) = strip_optional_duplicate_marker(row, "cargo feature-tree row");
        assert!(
            depth > 0 || !duplicate,
            "cargo feature-tree root cannot have a duplicate marker: {line}"
        );
        feature_ancestors.push(duplicate);
        if let Some((subject, features)) = row.split_once('|') {
            let Some((name, version)) = subject.rsplit_once(" v") else {
                panic!("unexpected cargo feature-tree package row: {row}");
            };
            let Some(version) = version.split_whitespace().next() else {
                panic!("malformed cargo feature-tree package row with empty version: {row}");
            };
            if name.is_empty() {
                panic!("malformed cargo feature-tree package row with empty name: {row}");
            }
            assert_eq!(
                subject,
                format!("{name} v{version}"),
                "malformed cargo feature-tree package row with trailing tokens: {row}"
            );
            let key = format!("{name}@{version}");
            if depth == 0 {
                assert_eq!(
                    key, expected_root,
                    "cargo feature-tree root package drift"
                );
            }
            let Some(actual) = package_features.get_mut(&key) else {
                panic!("cargo feature tree contains package outside normal/build graph: {key}");
            };
            let mut observed = BTreeSet::new();
            if !features.is_empty() {
                for feature in features.split(',') {
                    assert!(
                        !feature.is_empty(),
                        "malformed cargo feature list contains an empty token for {key}: {features}"
                    );
                    assert!(
                        observed.insert(feature.to_owned()),
                        "malformed cargo feature list contains duplicate token for {key}: {feature}"
                    );
                }
            }
            if !reported_packages.insert(key.clone()) && *actual != observed {
                panic!(
                    "cargo feature tree reported conflicting feature sets for {key}: \
                     {actual:?} and {observed:?}"
                );
            }
            *actual = observed;
            feature_nodes.push((depth, key, None, duplicate));
            continue;
        }

        // Cargo's synthetic feature-activation nodes do not honor the custom
        // package format, so validate their native spelling separately.
        let subject = row;
        let Some((package_name, feature)) = subject.split_once(" feature \"") else {
            panic!("unexpected cargo feature-tree subject: {subject}");
        };
        if package_name.is_empty()
            || feature.is_empty()
            || !feature.ends_with('"')
            || feature[..feature.len() - 1].contains('"')
        {
            panic!("malformed cargo feature activation row: {subject}");
        }
        let package_prefix = format!("{package_name}@");
        assert!(
            graph_packages
                .iter()
                .any(|package| package.starts_with(&package_prefix)),
            "cargo feature tree contains activation for package outside normal/build graph: {subject}"
        );
        assert!(depth > 0, "cargo feature-tree root must be a package row: {line}");
        feature_nodes.push((
            depth,
            package_name.to_owned(),
            Some(feature[..feature.len() - 1].to_owned()),
            duplicate,
        ));
    }

    let mut resolved_activations = BTreeMap::<(String, String), BTreeSet<String>>::new();
    for (index, (depth, package_name, feature, duplicate)) in feature_nodes.iter().enumerate() {
        let Some(feature) = feature else { continue };
        let identity = (package_name.clone(), feature.clone());
        if *duplicate {
            let matches = resolved_activations.get(&identity).cloned().unwrap_or_default();
            assert_eq!(
                matches.len(),
                1,
                "duplicate cargo feature activation does not identify one prior package: \
                 {package_name} feature \"{feature}\""
            );
            continue;
        }
        let Some((child_depth, child_key, child_feature, _)) = feature_nodes.get(index + 1) else {
            panic!("cargo feature activation has no package child: {package_name} feature \"{feature}\"");
        };
        assert!(
            child_feature.is_none() && *child_depth == depth + 1,
            "cargo feature activation has no immediate package child: {package_name} feature \"{feature}\""
        );
        let package_prefix = format!("{package_name}@");
        assert!(
            child_key.starts_with(&package_prefix),
            "cargo feature activation child package mismatch: {package_name} feature \"{feature}\" -> {child_key}"
        );
        assert!(
            package_features[child_key].contains(feature),
            "cargo feature activation is absent from child resolved feature set: {package_name} feature \"{feature}\" -> {child_key}"
        );
        resolved_activations
            .entry(identity)
            .or_default()
            .insert(child_key.clone());
    }

    assert!(
        !feature_ancestors.is_empty(),
        "cargo feature-tree graph is empty"
    );

    package_features
}

#[test]
fn target_package_feature_inventory_is_total_for_featureless_graph_packages() {
    let graph_packages = BTreeSet::from([
        "autocfg@1.5.1".to_owned(),
        "image@0.25.10".to_owned(),
        "png@0.18.0".to_owned(),
    ]);
    let feature_tree = concat!(
        "0image v0.25.10|png\n",
        "1png feature \"default\"\n",
        "2png v0.18.0|default,std\n",
    );

    assert_eq!(
        target_package_features(feature_tree, &graph_packages, "image@0.25.10"),
        BTreeMap::from([
            ("autocfg@1.5.1".to_owned(), BTreeSet::new()),
            (
                "image@0.25.10".to_owned(),
                BTreeSet::from(["png".to_owned()]),
            ),
            (
                "png@0.18.0".to_owned(),
                BTreeSet::from(["default".to_owned(), "std".to_owned()]),
            ),
        ])
    );
}

#[test]
#[should_panic(expected = "package outside normal/build graph: surprise@1.0.0")]
fn target_package_feature_inventory_rejects_unobserved_packages() {
    target_package_features(
        "0image v0.25.10|png\n1surprise v1.0.0|default\n",
        &BTreeSet::from(["image@0.25.10".to_owned()]),
        "image@0.25.10",
    );
}

#[test]
#[should_panic(expected =
    "feature activation is absent from child resolved feature set: png feature \"fake\""
)]
fn target_package_feature_inventory_rejects_unreported_activations() {
    target_package_features(
        "0image v0.25.10|png\n1png feature \"fake\"\n2png v0.18.0|default,std\n",
        &BTreeSet::from(["image@0.25.10".to_owned(), "png@0.18.0".to_owned()]),
        "image@0.25.10",
    );
}

#[test]
#[should_panic(expected = "package row with empty version: image v|png")]
fn target_package_feature_inventory_rejects_empty_versions_precisely() {
    target_package_features(
        "0image v|png\n",
        &BTreeSet::from(["image@0.25.10".to_owned()]),
        "image@0.25.10",
    );
}

#[test]
#[should_panic(expected = "feature list contains an empty token for image@0.25.10: png,,jpeg")]
fn target_package_feature_inventory_rejects_empty_feature_tokens() {
    target_package_features(
        "0image v0.25.10|png,,jpeg\n",
        &BTreeSet::from(["image@0.25.10".to_owned()]),
        "image@0.25.10",
    );
}

#[test]
#[should_panic(expected = "feature list contains duplicate token for image@0.25.10: png")]
fn target_package_feature_inventory_rejects_duplicate_feature_tokens() {
    target_package_features(
        "0image v0.25.10|png,png\n",
        &BTreeSet::from(["image@0.25.10".to_owned()]),
        "image@0.25.10",
    );
}

#[test]
#[should_panic(expected = "feature-tree package row with trailing tokens")]
fn target_package_feature_inventory_rejects_package_trailing_tokens() {
    target_package_features(
        "0image v0.25.10 unexpected|png\n",
        &BTreeSet::from(["image@0.25.10".to_owned()]),
        "image@0.25.10",
    );
}

#[test]
#[should_panic(expected = "feature-tree row is missing a depth: image v0.25.10|png")]
fn target_package_feature_inventory_requires_package_depths() {
    target_package_features(
        "image v0.25.10|png\n",
        &BTreeSet::from(["image@0.25.10".to_owned()]),
        "image@0.25.10",
    );
}

#[test]
#[should_panic(expected = "feature-tree row is missing a depth: png feature \"default\"")]
fn target_package_feature_inventory_requires_activation_depths() {
    target_package_features(
        "0image v0.25.10|png\npng feature \"default\"\n",
        &BTreeSet::from(["image@0.25.10".to_owned(), "png@0.18.0".to_owned()]),
        "image@0.25.10",
    );
}

#[test]
#[should_panic(expected = "cargo feature-tree root package drift")]
fn target_package_feature_inventory_requires_the_requested_root() {
    target_package_features(
        "0png v0.18.0|default\n",
        &BTreeSet::from(["image@0.25.10".to_owned(), "png@0.18.0".to_owned()]),
        "image@0.25.10",
    );
}

#[test]
#[should_panic(expected = "feature-tree duplicate marker node has a child")]
fn target_package_feature_inventory_requires_duplicate_markers_to_be_leaves() {
    target_package_features(
        "0image v0.25.10|png\n1png feature \"default\" (*)\n2png v0.18.0|default\n",
        &BTreeSet::from(["image@0.25.10".to_owned(), "png@0.18.0".to_owned()]),
        "image@0.25.10",
    );
}

fn dependency_tree_graph(
    tree: &str,
    target: TargetTriple,
    provenance: Provenance,
    expected_root: &str,
) -> (BTreeSet<String>, BTreeSet<EdgeFixture>) {
    let mut packages = BTreeSet::new();
    let mut edges = BTreeSet::new();
    let mut ancestors = Vec::<(String, bool)>::new();
    for line in tree.lines() {
        let depth_end = line
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or_else(|| panic!("cargo tree row contains only a depth: {line}"));
        assert!(depth_end > 0, "cargo tree row is missing a depth: {line}");
        let depth = line[..depth_end].parse::<usize>().unwrap();
        assert_eq!(
            line[..depth_end],
            depth.to_string(),
            "cargo tree row has a noncanonical depth: {line}"
        );
        if ancestors.is_empty() {
            assert_eq!(depth, 0, "cargo tree first row must have depth zero: {line}");
        } else {
            assert!(depth > 0, "cargo tree contains multiple roots: {line}");
            assert!(
                depth <= ancestors.len(),
                "cargo tree depth jumps past its parent: {line}"
            );
        }
        if depth > 0 && ancestors[depth - 1].1 {
            panic!("cargo tree duplicate marker node has a child: {line}");
        }
        let (row, duplicate) =
            strip_optional_duplicate_marker(&line[depth_end..], "cargo tree package row");
        assert!(
            depth > 0 || !duplicate,
            "cargo tree root cannot have a duplicate marker: {line}"
        );
        let package = tree_package_key(row);
        if depth == 0 {
            assert_eq!(package, expected_root, "cargo tree root package drift");
        }
        packages.insert(package.clone());
        ancestors.truncate(depth);
        if let Some((parent, _)) = ancestors.last() {
            edges.insert(EdgeFixture {
                from: parent.clone(),
                to: package.clone(),
                target,
                provenance,
            });
        }
        ancestors.push((package, duplicate));
    }
    assert!(!packages.is_empty(), "cargo tree graph is empty");
    (packages, edges)
}

#[test]
#[should_panic(expected = "cargo tree graph is empty")]
fn dependency_tree_graph_rejects_empty_graphs() {
    dependency_tree_graph(
        "",
        TargetTriple::Linux,
        Provenance::ImageDescendant,
        "image@0.25.10",
    );
}

#[test]
#[should_panic(expected = "cargo tree first row must have depth zero")]
fn dependency_tree_graph_rejects_nonzero_first_depth() {
    dependency_tree_graph(
        "1image v0.25.10\n",
        TargetTriple::Linux,
        Provenance::ImageDescendant,
        "image@0.25.10",
    );
}

#[test]
#[should_panic(expected = "cargo tree contains multiple roots")]
fn dependency_tree_graph_rejects_multiple_roots() {
    dependency_tree_graph(
        "0image v0.25.10\n0png v0.18.0\n",
        TargetTriple::Linux,
        Provenance::ImageDescendant,
        "image@0.25.10",
    );
}

#[test]
#[should_panic(expected = "cargo tree depth jumps past its parent")]
fn dependency_tree_graph_rejects_depth_jumps() {
    dependency_tree_graph(
        "0image v0.25.10\n2png v0.18.0\n",
        TargetTriple::Linux,
        Provenance::ImageDescendant,
        "image@0.25.10",
    );
}

#[test]
#[should_panic(expected = "cargo tree duplicate marker node has a child")]
fn dependency_tree_graph_requires_duplicate_markers_to_be_leaves() {
    dependency_tree_graph(
        "0image v0.25.10\n1png v0.18.0 (*)\n2miniz_oxide v0.8.0\n",
        TargetTriple::Linux,
        Provenance::ImageDescendant,
        "image@0.25.10",
    );
}

#[test]
#[should_panic(expected = "cargo tree root package drift")]
fn dependency_tree_graph_requires_the_requested_root() {
    dependency_tree_graph(
        "0png v0.18.0\n",
        TargetTriple::Linux,
        Provenance::ImageDescendant,
        "image@0.25.10",
    );
}

fn image_requester_subgraph(edges: &BTreeSet<EdgeFixture>) -> BTreeSet<EdgeFixture> {
    let mut ancestors = BTreeSet::from(["image@0.25.10".to_owned()]);
    loop {
        let prior = ancestors.len();
        for edge in edges {
            if ancestors.contains(&edge.to) {
                ancestors.insert(edge.from.clone());
            }
        }
        if ancestors.len() == prior {
            break;
        }
    }
    edges
        .iter()
        .filter(|edge| ancestors.contains(&edge.from) && ancestors.contains(&edge.to))
        .map(|edge| EdgeFixture {
            provenance: Provenance::ImageRequester,
            ..edge.clone()
        })
        .collect()
}

fn deserialize_toml_document(text: &str) -> toml::Value {
    toml::de::from_str::<toml::Value>(text).unwrap()
}

fn actual_dependency_name<'a>(key: &'a str, declaration: &'a toml::Value) -> &'a str {
    declaration
        .as_table()
        .and_then(|table| table.get("package"))
        .and_then(toml::Value::as_str)
        .unwrap_or(key)
}

fn image_declarations<'a>(manifest: &'a toml::Value) -> Vec<(&'a str, &'a toml::Value)> {
    let mut declarations = Vec::new();
    let root = manifest.as_table().unwrap();
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(table) = root.get(section).and_then(toml::Value::as_table) {
            declarations.extend(
                table
                    .iter()
                    .filter(|(key, value)| actual_dependency_name(key, value) == "image")
                    .map(|(key, value)| (key.as_str(), value)),
            );
        }
    }
    if let Some(targets) = root.get("target").and_then(toml::Value::as_table) {
        for target in targets.values() {
            let target = target.as_table().unwrap();
            for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(table) = target.get(section).and_then(toml::Value::as_table) {
                    declarations.extend(
                        table
                            .iter()
                            .filter(|(key, value)| actual_dependency_name(key, value) == "image")
                            .map(|(key, value)| (key.as_str(), value)),
                    );
                }
            }
        }
    }
    declarations
}

#[test]
fn tui_image_codec_dependency_inventory() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir.parent().unwrap().parent().unwrap();
    let root_text = fs::read_to_string(workspace.join("Cargo.toml")).unwrap();
    let root_manifest = deserialize_toml_document(&root_text);
    let tui_text = fs::read_to_string(manifest_dir.join("Cargo.toml")).unwrap();
    let tui_manifest = deserialize_toml_document(&tui_text);
    let workspace_dependencies = root_manifest["workspace"]["dependencies"]
        .as_table()
        .unwrap();
    let workspace_image_declarations = workspace_dependencies
        .iter()
        .filter(|(key, value)| actual_dependency_name(key, value) == "image")
        .collect::<Vec<_>>();
    assert_eq!(
        workspace_image_declarations.len(),
        1,
        "workspace dependencies must contain exactly one actual-name image declaration"
    );
    assert_eq!(
        workspace_image_declarations[0].0, "image",
        "the workspace image declaration must use its canonical package name"
    );
    let root_image = &root_manifest["workspace"]["dependencies"]["image"];
    assert_eq!(
        root_image
            .as_table()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["default-features", "features", "version"]),
        "workspace image declaration must remain exact"
    );
    assert_eq!(root_image["version"].as_str(), Some("=0.25.10"));
    assert_eq!(root_image["default-features"].as_bool(), Some(false));
    assert_eq!(
        root_image["features"],
        toml::Value::Array(vec!["png".into()])
    );
    let tui_dependencies = tui_manifest["dependencies"].as_table().unwrap();
    let direct_image_declarations = image_declarations(&tui_manifest);
    assert_eq!(
        direct_image_declarations.len(),
        1,
        "cockpit-tui must declare image exactly once across normal/dev/build and target sections"
    );
    assert_eq!(
        direct_image_declarations[0].0, "image",
        "the sole image dependency must use its canonical package name, not an alias"
    );
    let tui_image = &tui_dependencies["image"];
    assert_eq!(
        tui_image
            .as_table()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["features", "workspace"]),
        "cockpit-tui image declaration must remain exact"
    );
    assert_eq!(tui_image["workspace"].as_bool(), Some(true));
    assert_eq!(
        tui_image["features"],
        toml::Value::Array(vec![
            "png".into(),
            "jpeg".into(),
            "gif".into(),
            "webp".into()
        ])
    );
    assert!(tui_image.get("default-features").is_none());
    let prohibited_codec_packages = BTreeSet::from([
        "png",
        "jpeg-decoder",
        "gif",
        "webp",
        "image-webp",
        "tiff",
        "zune-jpeg",
        "ravif",
        "webp-animation",
    ]);
    for (dependency_key, declaration) in tui_dependencies {
        let actual_package = actual_dependency_name(dependency_key, declaration);
        assert!(
            !prohibited_codec_packages.contains(actual_package),
            "cockpit-tui dependency {dependency_key} aliases prohibited codec package {actual_package}"
        );
    }

    let fixture: Fixture = serde_json::from_str(include_str!(
        "fixtures/image-codec-dependency-inventory.json"
    ))
    .unwrap();
    assert_eq!(fixture.schema_version, 5);
    let lock_text = fs::read_to_string(workspace.join("Cargo.lock")).unwrap();
    let lock = deserialize_toml_document(&lock_text);
    let locked_packages = lock["package"].as_array().unwrap();
    let mut observed_fixture_rows = BTreeSet::new();

    for (target, expected) in fixture.targets.iter() {
        let triple = target.as_str();
        for edge in &expected.edges {
            assert_eq!(
                edge.target, target,
                "{triple} fixture contains a cross-target edge"
            );
            assert_eq!(
                edge.provenance,
                Provenance::ImageDescendant,
                "{triple} package edge has the wrong provenance class"
            );
        }
        for edge in &expected.provenance_edges {
            assert_eq!(
                edge.target, target,
                "{triple} fixture contains a cross-target provenance edge"
            );
            assert_eq!(
                edge.provenance,
                Provenance::ImageRequester,
                "{triple} requester edge has the wrong provenance class"
            );
        }
        let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .current_dir(workspace)
            .args([
                "metadata",
                "--locked",
                "--offline",
                "--format-version",
                "1",
                "--filter-platform",
                triple,
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "metadata failed for {triple}");
        let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let packages = metadata["packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|package| (package["id"].as_str().unwrap(), package))
            .collect::<BTreeMap<_, _>>();
        let nodes = metadata["resolve"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|node| (node["id"].as_str().unwrap(), node))
            .collect::<BTreeMap<_, _>>();
        // `cargo metadata --filter-platform` exposes the workspace-unified feature
        // set in resolve.nodes, so it cannot prove target-specific activation for
        // image (notably arboard's BMP/TIFF requests). `cargo tree --target` uses
        // Cargo's target-aware feature resolver and is the authoritative source for
        // packages whose feature set differs by target.
        // This target-resolved graph is observed without consulting the fixture.
        // Consequently a newly activated direct image dependency cannot be hidden
        // by a fixture-derived allowlist.
        // AC17 inventories the complete graph rooted at image, including build
        // dependencies.  In particular, num-traits selects autocfg through a
        // build edge; a normal-only view silently drops both that edge and its
        // package even though Cargo resolves and executes it for this graph.
        let dependency_tree = cargo_tree(workspace, triple, "image@0.25.10", "normal,build", "{p}");
        let (graph_packages, graph_edges) =
            dependency_tree_graph(
                &dependency_tree,
                target,
                Provenance::ImageDescendant,
                "image@0.25.10",
            );
        let feature_tree = cargo_tree(workspace, triple, "image@0.25.10", "features", "{p}|{f}");
        let target_package_features =
            target_package_features(&feature_tree, &graph_packages, "image@0.25.10");
        let image_tree_features = &target_package_features["image@0.25.10"];

        let resolved_features = expected
            .resolved_features
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            *image_tree_features,
            resolved_features
                .iter()
                .map(|feature| (*feature).to_string())
                .collect(),
            "{triple} target-resolved image feature drift"
        );
        for feature in &resolved_features {
            match *feature {
                "bmp" | "gif" | "jpeg" | "png" | "tiff" | "webp" => {}
                other => panic!("unaccounted image feature {other} for {triple}"),
            }
        }
        let expected_packages = expected.packages.iter().cloned().collect::<BTreeSet<_>>();
        let expected_edges = expected.edges.iter().cloned().collect::<BTreeSet<_>>();
        assert_eq!(graph_packages, expected_packages, "{triple} package drift");
        assert_eq!(graph_edges, expected_edges, "{triple} edge drift");
        assert_eq!(
            expected
                .package_features
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            expected_packages,
            "{triple} target feature inventory must cover every graph package"
        );

        for key in &graph_packages {
            let (name, version) = key.rsplit_once('@').unwrap();
            let (id, package) = packages
                .iter()
                .find(|(_, package)| package["name"] == name && package["version"] == version)
                .unwrap_or_else(|| panic!("metadata omitted target graph package {key}"));
            observed_fixture_rows.insert(key.clone());
            let expected_package = fixture
                .packages
                .get(key)
                .unwrap_or_else(|| panic!("missing fixture row for {key}"));
            assert_eq!(
                package["source"].as_str(),
                Some(expected_package.source.as_str()),
                "{key} source"
            );
            assert_eq!(
                package["license"].as_str(),
                expected_package.license.as_deref(),
                "{key} license"
            );
            assert_eq!(
                package["rust_version"].as_str(),
                expected_package.rust_version.as_deref(),
                "{key} declared MSRV"
            );
            assert!(
                expected_package.source.starts_with("registry+"),
                "{key} must retain its exact registry source"
            );
            if let Some(msrv) = expected_package.rust_version.as_deref() {
                let mut parts = msrv.split('.').map(|part| part.parse::<u32>().unwrap());
                let version = (parts.next().unwrap(), parts.next().unwrap_or_default());
                assert!(version <= (1, 95), "{key} requires Rust {msrv}");
            }
            let expected_features = expected
                .package_features
                .get(key)
                .unwrap_or_else(|| panic!("missing feature row for {key}"));
            let mut metadata_features = nodes[*id]["features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|feature| feature.as_str().unwrap().to_owned())
                .collect::<Vec<_>>();
            metadata_features.sort();
            assert_eq!(
                metadata_features, expected_package.raw_metadata_feature_union,
                "{key} raw metadata feature drift"
            );
            let actual_features = target_package_features[key]
                .iter()
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(actual_features, *expected_features, "{key} feature drift");
            let checksum = &expected_package.checksum;
            let locked = locked_packages
                .iter()
                .find(|locked| {
                    locked["name"].as_str() == package["name"].as_str()
                        && locked["version"].as_str() == package["version"].as_str()
                })
                .unwrap_or_else(|| panic!("missing exact lock package {key}"));
            assert_eq!(
                locked["checksum"].as_str(),
                Some(checksum.as_str()),
                "{key} checksum"
            );
        }

        let tui = metadata["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|package| package["name"] == "cockpit-tui")
            .unwrap();
        let direct_images = tui["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|dependency| dependency["name"] == "image")
            .collect::<Vec<_>>();
        assert_eq!(
            direct_images.len(),
            1,
            "{triple} graph must expose exactly one direct actual-name image dependency"
        );
        let tui_image = direct_images[0];
        assert_eq!(
            tui_image["rename"],
            serde_json::Value::Null,
            "{triple} image dependency must not be aliased"
        );
        assert_eq!(
            tui_image["kind"],
            serde_json::Value::Null,
            "{triple} image dependency must be normal, not dev/build"
        );
        assert_eq!(
            tui_image["target"],
            serde_json::Value::Null,
            "{triple} image dependency must be unconditional"
        );
        assert_eq!(tui_image["uses_default_features"], false);
        // Cargo metadata reports the additive workspace/member declarations as
        // one array and may retain the same leaf more than once (the workspace
        // and cockpit-tui both request png). Feature activation is set-valued,
        // so compare its normalized union while the manifest checks above keep
        // proving each declaration independently.
        let direct_feature_union = tui_image["features"]
            .as_array()
            .unwrap()
            .iter()
            .map(|feature| feature.as_str().unwrap())
            .collect::<BTreeSet<_>>();
        let expected_tui_features = expected
            .tui_features
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            direct_feature_union, expected_tui_features,
            "{triple} direct image feature union"
        );
        assert_eq!(expected.tui_features, ["gif", "jpeg", "png", "webp"]);
        assert_eq!(expected.probe_formats, ["gif", "jpeg", "png", "webp"]);

        // Metadata exposes the actual package name even when a manifest key is
        // an alias. This closes the alias escape hatch for every target-resolved
        // direct dependency, rather than relying only on TOML keys.
        for dependency in tui["dependencies"].as_array().unwrap() {
            let actual_name = dependency["name"].as_str().unwrap();
            assert!(
                !prohibited_codec_packages.contains(actual_name),
                "cockpit-tui resolves prohibited direct codec package {actual_name} on {triple}"
            );
        }

        let tui_tree = cargo_tree(workspace, triple, "cockpit-tui", "normal", "{p}");
        let (_, tui_edges) = dependency_tree_graph(
            &tui_tree,
            target,
            Provenance::TuiNormal,
            "cockpit-tui@0.1.0",
        );
        let observed_provenance = image_requester_subgraph(&tui_edges);
        let expected_provenance = expected
            .provenance_edges
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            observed_provenance, expected_provenance,
            "{triple} TUI/arboard image provenance drift"
        );

        let arboard = metadata["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|package| package["name"] == "arboard")
            .unwrap();
        let target_marker = match triple {
            "x86_64-unknown-linux-gnu" => "all(unix",
            "aarch64-apple-darwin" => "target_os = \"macos\"",
            "x86_64-pc-windows-msvc" => "windows",
            _ => unreachable!(),
        };
        let arboard_image = arboard["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|dependency| {
                dependency["name"] == "image"
                    && dependency["target"]
                        .as_str()
                        .is_some_and(|target| target.contains(target_marker))
            })
            .unwrap();
        let mut arboard_features = arboard_image["features"].as_array().unwrap().clone();
        arboard_features.sort_by_key(|feature| feature.as_str().unwrap().to_string());
        let mut expected_arboard = expected
            .arboard_features
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect::<Vec<_>>();
        expected_arboard.sort_by_key(|feature| feature.as_str().unwrap().to_string());
        assert_eq!(
            arboard_features, expected_arboard,
            "{triple} arboard provenance"
        );
    }
    assert_eq!(
        observed_fixture_rows,
        fixture.packages.keys().cloned().collect::<BTreeSet<_>>(),
        "fixture contains an unaccounted package row"
    );
}
