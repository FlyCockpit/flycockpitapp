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
    targets: BTreeMap<String, TargetFixture>,
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

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct EdgeFixture {
    from: String,
    to: String,
    target: String,
    provenance: String,
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

fn normal_tree_graph(
    tree: &str,
    target: &str,
    provenance: &str,
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
                target: target.to_owned(),
                provenance: provenance.to_owned(),
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
            provenance: "image-requester".to_owned(),
            ..edge.clone()
        })
        .collect()
}

#[test]
fn tui_image_codec_dependency_inventory() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir.parent().unwrap().parent().unwrap();
    let root_manifest = fs::read_to_string(workspace.join("Cargo.toml"))
        .unwrap()
        .parse::<toml::Value>()
        .unwrap();
    let tui_manifest = fs::read_to_string(manifest_dir.join("Cargo.toml"))
        .unwrap()
        .parse::<toml::Value>()
        .unwrap();
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
        let actual_package = declaration
            .as_table()
            .and_then(|table| table.get("package"))
            .and_then(toml::Value::as_str)
            .unwrap_or(dependency_key);
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
    assert_eq!(fixture.targets.len(), 3);
    let lock = fs::read_to_string(workspace.join("Cargo.lock"))
        .unwrap()
        .parse::<toml::Value>()
        .unwrap();
    let locked_packages = lock["package"].as_array().unwrap();
    let mut observed_fixture_rows = BTreeSet::new();

    for (triple, expected) in &fixture.targets {
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
        let tree = cargo_tree(workspace, triple, "image@0.25.10", "features", "{p}|{f}");
        let mut target_package_features = BTreeMap::new();
        for line in tree.lines() {
            let row = line.trim_start_matches(|character: char| character.is_ascii_digit());
            let Some((package, features)) = row.split_once('|') else {
                continue;
            };
            let Some((name, version)) = package.rsplit_once(" v") else {
                continue;
            };
            let key = format!("{name}@{version}");
            target_package_features.entry(key).or_insert_with(|| {
                features
                    .trim_end_matches(" (*)")
                    .split(',')
                    .filter(|feature| !feature.is_empty())
                    .map(ToOwned::to_owned)
                    .collect::<BTreeSet<_>>()
            });
        }
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

        // This target-resolved graph is observed without consulting the fixture.
        // Consequently a newly activated direct image dependency cannot be hidden
        // by a fixture-derived allowlist.
        let normal_tree = cargo_tree(workspace, triple, "image@0.25.10", "normal", "{p}");
        let (graph_packages, graph_edges) =
            normal_tree_graph(&normal_tree, triple, "image-descendant");
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
        let tui_image = tui["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|dependency| dependency["name"] == "image")
            .unwrap();
        assert_eq!(tui_image["uses_default_features"], false);
        assert_eq!(
            tui_image["features"],
            serde_json::json!(expected.tui_features)
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
        let (_, tui_edges) = normal_tree_graph(&tui_tree, triple, "tui-normal");
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
        let target_marker = match triple.as_str() {
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
