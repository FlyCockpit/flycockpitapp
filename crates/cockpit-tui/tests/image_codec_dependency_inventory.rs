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

#[test]
fn tui_image_codec_dependency_inventory() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir.parent().unwrap().parent().unwrap();
    let root_manifest = fs::read_to_string(workspace.join("Cargo.toml")).unwrap();
    let tui_manifest = fs::read_to_string(manifest_dir.join("Cargo.toml")).unwrap();
    assert!(root_manifest.contains(
        "image = { version = \"=0.25.10\", default-features = false, features = [\"png\"] }"
    ));
    assert!(tui_manifest.contains(
        "image = { workspace = true, features = [\"png\", \"jpeg\", \"gif\", \"webp\"] }"
    ));

    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/image-codec-dependency-inventory.json"
    ))
    .unwrap();
    assert_eq!(fixture["schemaVersion"], 3);
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
        let image_id = packages
            .iter()
            .find(|(_, package)| package["name"] == "image" && package["version"] == "0.25.10")
            .map(|(id, _)| *id)
            .unwrap();

        // `cargo metadata --filter-platform` exposes the workspace-unified feature
        // set in resolve.nodes, so it cannot prove target-specific activation for
        // image (notably arboard's BMP/TIFF requests). `cargo tree --target` uses
        // Cargo's target-aware feature resolver and is the authoritative source for
        // packages whose feature set differs by target.
        let tree_output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .current_dir(workspace)
            .args([
                "tree",
                "--locked",
                "--offline",
                "--target",
                triple,
                "-e",
                "features",
                "-p",
                "image@0.25.10",
                "--prefix",
                "depth",
                "--format",
                "{p}|{f}",
            ])
            .output()
            .unwrap();
        assert!(
            tree_output.status.success(),
            "cargo tree failed for {triple}"
        );
        let tree = String::from_utf8(tree_output.stdout).unwrap();
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
        let mut permitted_image_deps =
            BTreeSet::from(["bytemuck", "byteorder_lite", "moxcms", "num_traits"]);
        for feature in &resolved_features {
            match *feature {
                "gif" => permitted_image_deps.extend(["gif", "color_quant"]),
                "jpeg" => permitted_image_deps.extend(["zune_core", "zune_jpeg"]),
                "png" => {
                    permitted_image_deps.insert("png");
                }
                "tiff" => {
                    permitted_image_deps.insert("tiff");
                }
                "webp" => {
                    permitted_image_deps.insert("image_webp");
                }
                "bmp" => {}
                other => panic!("unaccounted image feature {other} for {triple}"),
            }
        }

        let mut pending = vec![image_id];
        let mut graph_ids = BTreeSet::new();
        let mut graph_edges = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !graph_ids.insert(id) {
                continue;
            }
            for dep in nodes[id]["deps"].as_array().unwrap() {
                let dep_name = dep["name"].as_str().unwrap();
                if id == image_id && !permitted_image_deps.contains(dep_name) {
                    continue;
                }
                let dep_id = dep["pkg"].as_str().unwrap();
                graph_edges.insert(format!(
                    "{} -> {}",
                    package_key(packages[id]),
                    package_key(packages[dep_id])
                ));
                pending.push(dep_id);
            }
        }
        let graph_packages = graph_ids
            .iter()
            .map(|id| package_key(packages[id]))
            .collect::<BTreeSet<_>>();
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

        for id in graph_ids {
            let package = packages[id];
            let key = package_key(package);
            observed_fixture_rows.insert(key.clone());
            let expected_package = &package_fixture[&key];
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
            let mut metadata_features = nodes[id]["features"].as_array().unwrap().clone();
            metadata_features.sort_by_key(|feature| feature.as_str().unwrap().to_string());
            assert_eq!(
                serde_json::Value::Array(metadata_features),
                expected_package["features"],
                "{key} raw metadata feature drift"
            );
            let mut actual_features = target_package_features[&key]
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
        assert_eq!(
            tui_image["features"],
            serde_json::json!(["gif", "jpeg", "png", "webp"])
        );
        assert_eq!(
            expected["probeFormats"],
            serde_json::json!(["gif", "jpeg", "png", "webp"])
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
