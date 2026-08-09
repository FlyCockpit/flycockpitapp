use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

fn package_key(package: &serde_json::Value) -> String {
    format!(
        "{}@{}",
        package["name"].as_str().unwrap(),
        package["version"].as_str().unwrap()
    )
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

fn normal_tree_graph(tree: &str) -> (BTreeSet<String>, BTreeSet<String>) {
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
            edges.insert(format!("{parent} -> {package}"));
        }
        ancestors.push(package);
    }
    (packages, edges)
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
    for second_codec in [
        "png",
        "jpeg-decoder",
        "jpeg_decoder",
        "gif",
        "webp",
        "image-webp",
        "tiff",
        "zune-jpeg",
        "zune_jpeg",
    ] {
        assert!(
            !tui_dependencies.contains_key(second_codec),
            "cockpit-tui must not directly depend on second image codec {second_codec}"
        );
    }

    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/image-codec-dependency-inventory.json"
    ))
    .unwrap();
    assert_eq!(fixture["schemaVersion"], 4);
    let targets = fixture["targets"].as_object().unwrap();
    let package_fixture = fixture["packages"].as_object().unwrap();
    assert_eq!(targets.len(), 3);
    let lock = fs::read_to_string(workspace.join("Cargo.lock")).unwrap();
    let mut observed_fixture_rows = BTreeSet::new();

    for (triple, expected) in targets {
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

        let resolved_features = expected["resolvedFeatures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
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
        let (graph_packages, graph_edges) = normal_tree_graph(&normal_tree);
        let expected_packages = expected["packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<BTreeSet<_>>();
        let expected_edges = expected["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(graph_packages, expected_packages, "{triple} package drift");
        assert_eq!(graph_edges, expected_edges, "{triple} edge drift");
        assert_eq!(
            expected["packageFeatures"]
                .as_object()
                .unwrap()
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
            let expected_package = &package_fixture[key];
            assert!(!expected_package.is_null(), "missing fixture row for {key}");
            assert_eq!(
                package["source"], expected_package["source"],
                "{key} source"
            );
            assert_eq!(
                package["license"], expected_package["license"],
                "{key} license"
            );
            assert_eq!(
                package["rust_version"], expected_package["rustVersion"],
                "{key} declared MSRV"
            );
            assert!(
                expected_package["source"]
                    .as_str()
                    .is_some_and(|source| source.starts_with("registry+")),
                "{key} must retain its exact registry source"
            );
            if let Some(msrv) = expected_package["rustVersion"].as_str() {
                let mut parts = msrv.split('.').map(|part| part.parse::<u32>().unwrap());
                let version = (parts.next().unwrap(), parts.next().unwrap_or_default());
                assert!(version <= (1, 95), "{key} requires Rust {msrv}");
            }
            let expected_features = &expected["packageFeatures"][&key];
            assert!(
                !expected_features.is_null(),
                "missing feature row for {key}"
            );
            let mut metadata_features = nodes[*id]["features"].as_array().unwrap().clone();
            metadata_features.sort_by_key(|feature| feature.as_str().unwrap().to_string());
            assert_eq!(
                serde_json::Value::Array(metadata_features),
                expected_package["rawMetadataFeatureUnion"],
                "{key} raw metadata feature drift"
            );
            let mut actual_features = target_package_features[key]
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect::<Vec<_>>();
            actual_features.sort_by_key(|feature| feature.as_str().unwrap().to_string());
            assert_eq!(
                serde_json::Value::Array(actual_features),
                *expected_features,
                "{key} feature drift"
            );
            let checksum = expected_package["checksum"].as_str().unwrap();
            let block = lock
                .split("[[package]]")
                .find(|block| {
                    block.contains(&format!("name = \"{}\"", package["name"].as_str().unwrap()))
                        && block.contains(&format!(
                            "version = \"{}\"",
                            package["version"].as_str().unwrap()
                        ))
                })
                .unwrap_or_else(|| panic!("missing exact lock package {key}"));
            assert!(
                block.contains(&format!("checksum = \"{checksum}\"")),
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
        assert_eq!(tui_image["features"], expected["tuiFeatures"]);
        assert_eq!(
            expected["tuiFeatures"],
            serde_json::json!(["gif", "jpeg", "png", "webp"])
        );
        assert_eq!(
            expected["probeFormats"],
            serde_json::json!(["gif", "jpeg", "png", "webp"])
        );

        let tui_tree = cargo_tree(workspace, triple, "cockpit-tui", "normal", "{p}");
        let (_, tui_edges) = normal_tree_graph(&tui_tree);
        let observed_provenance = tui_edges
            .iter()
            .filter(|edge| {
                matches!(
                    edge.as_str(),
                    "cockpit-tui@0.1.0 -> image@0.25.10"
                        | "cockpit-tui@0.1.0 -> arboard@3.6.1"
                        | "arboard@3.6.1 -> image@0.25.10"
                )
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        let expected_provenance = expected["provenanceEdges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| edge.as_str().unwrap().to_owned())
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
        let mut expected_arboard = expected["arboardFeatures"].as_array().unwrap().clone();
        expected_arboard.sort_by_key(|feature| feature.as_str().unwrap().to_string());
        assert_eq!(
            arboard_features, expected_arboard,
            "{triple} arboard provenance"
        );
    }
    assert_eq!(
        observed_fixture_rows,
        package_fixture.keys().cloned().collect::<BTreeSet<_>>(),
        "fixture contains an unaccounted package row"
    );
}
