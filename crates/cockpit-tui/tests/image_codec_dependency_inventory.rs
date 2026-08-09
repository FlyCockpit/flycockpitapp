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

fn tree_package_key(row: &str) -> String {
    let package = row.trim_end_matches(" (*)");
    let (name, version) = package
        .rsplit_once(" v")
        .unwrap_or_else(|| panic!("unexpected cargo tree package row: {row}"));
    let version = version.split_whitespace().next().unwrap();
    format!("{name}@{version}")
}

fn target_package_features(
    feature_tree: &str,
    graph_packages: &BTreeSet<String>,
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
    let mut feature_activations = Vec::new();

    for line in feature_tree.lines() {
        let row = line.trim_start_matches(|character: char| character.is_ascii_digit());
        if let Some((subject, features)) = row.split_once('|') {
            let subject = subject.trim_end_matches(" (*)");
            let Some((name, version)) = subject.rsplit_once(" v") else {
                panic!("unexpected cargo feature-tree package row: {row}");
            };
            let Some(version) = version.split_whitespace().next() else {
                panic!("malformed cargo feature-tree package row with empty version: {row}");
            };
            if name.is_empty() {
                panic!("malformed cargo feature-tree package row with empty name: {row}");
            }
            let key = format!("{name}@{version}");
            let Some(actual) = package_features.get_mut(&key) else {
                panic!("cargo feature tree contains package outside normal/build graph: {key}");
            };
            let observed = features
                .trim_end_matches(" (*)")
                .split(',')
                .filter(|feature| !feature.is_empty())
                .map(ToOwned::to_owned)
                .collect::<BTreeSet<_>>();
            if !reported_packages.insert(key.clone()) && *actual != observed {
                panic!(
                    "cargo feature tree reported conflicting feature sets for {key}: \
                     {actual:?} and {observed:?}"
                );
            }
            *actual = observed;
            continue;
        }

        // Cargo's synthetic feature-activation nodes do not honor the custom
        // package format, so validate their native spelling separately.
        let subject = row.trim_end_matches(" (*)");
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
        feature_activations.push((subject.to_owned(), package_name, &feature[..feature.len() - 1]));
    }

    for (subject, package_name, feature) in feature_activations {
        let package_prefix = format!("{package_name}@");
        let matching_packages = reported_packages
            .iter()
            .filter(|package| package.starts_with(&package_prefix))
            .filter(|package| package_features[*package].contains(feature))
            .collect::<Vec<_>>();
        match matching_packages.as_slice() {
            [_] => {}
            [] => panic!(
                "cargo feature activation is absent from every reported resolved feature set: \
                 {subject}"
            ),
            packages => panic!(
                "cargo feature activation is ambiguous across package versions for {subject}: \
                 {packages:?}"
            ),
        }
    }

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
        target_package_features(feature_tree, &graph_packages),
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
    );
}

#[test]
#[should_panic(expected =
    "feature activation is absent from every reported resolved feature set: png feature \"fake\""
)]
fn target_package_feature_inventory_rejects_unreported_activations() {
    target_package_features(
        "0image v0.25.10|png\n1png feature \"fake\"\n2png v0.18.0|default,std\n",
        &BTreeSet::from(["image@0.25.10".to_owned(), "png@0.18.0".to_owned()]),
    );
}

#[test]
#[should_panic(expected = "package row with empty version: image v|png")]
fn target_package_feature_inventory_rejects_empty_versions_precisely() {
    target_package_features(
        "0image v|png\n",
        &BTreeSet::from(["image@0.25.10".to_owned()]),
    );
}

fn dependency_tree_graph(
    tree: &str,
    target: TargetTriple,
    provenance: Provenance,
) -> (BTreeSet<String>, BTreeSet<EdgeFixture>) {
    let mut packages = BTreeSet::new();
    let mut edges = BTreeSet::new();
    let mut ancestors = Vec::<String>::new();
    for line in tree.lines() {
        let depth_end = line
            .find(|character: char| !character.is_ascii_digit())
            .unwrap();
        let depth = line[..depth_end].parse::<usize>().unwrap();
        let package = tree_package_key(&line[depth_end..]);
        packages.insert(package.clone());
        ancestors.truncate(depth);
        if let Some(parent) = ancestors.last() {
            edges.insert(EdgeFixture {
                from: parent.clone(),
                to: package.clone(),
                target,
                provenance,
            });
        }
        ancestors.push(package);
    }
    (packages, edges)
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
            dependency_tree_graph(&dependency_tree, target, Provenance::ImageDescendant);
        let feature_tree = cargo_tree(workspace, triple, "image@0.25.10", "features", "{p}|{f}");
        let target_package_features = target_package_features(&feature_tree, &graph_packages);
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
        let (_, tui_edges) = dependency_tree_graph(&tui_tree, target, Provenance::TuiNormal);
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
