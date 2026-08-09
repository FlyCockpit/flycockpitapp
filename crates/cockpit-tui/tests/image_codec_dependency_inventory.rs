use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::Command;

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
    assert_eq!(fixture["schemaVersion"], 1);
    let targets = fixture["targets"].as_object().unwrap();
    assert_eq!(targets.len(), 3);
    for target in targets.values() {
        assert_eq!(
            target["probeFormats"],
            serde_json::json!(["gif", "jpeg", "png", "webp"])
        );
    }
    let mut observed_packages = HashSet::new();
    for (triple, expected) in targets {
        assert_eq!(
            expected["tuiFeatures"],
            serde_json::json!(["gif", "jpeg", "png", "webp"])
        );
        let arboard = match triple.as_str() {
            "x86_64-unknown-linux-gnu" => serde_json::json!(["png"]),
            "aarch64-apple-darwin" => serde_json::json!(["tiff"]),
            "x86_64-pc-windows-msvc" => serde_json::json!(["bmp", "png"]),
            _ => unreachable!(),
        };
        assert_eq!(expected["arboardFeatures"], arboard);
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
        let package = metadata["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|package| package["name"] == "image" && package["version"] == "0.25.10")
            .unwrap();
        let image_id = package["id"].as_str().unwrap();
        let node = metadata["resolve"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|node| node["id"] == image_id)
            .unwrap();
        let mut resolved = node["features"].as_array().unwrap().clone();
        resolved.sort_by_key(|feature| feature.as_str().unwrap().to_string());
        let mut expected_features = expected["resolvedFeatures"].as_array().unwrap().clone();
        expected_features.sort_by_key(|feature| feature.as_str().unwrap().to_string());
        assert_eq!(resolved, expected_features, "{triple} image feature drift");
        for forbidden in ["default", "default-formats", "rayon", "avif", "exr"] {
            assert!(
                !resolved.iter().any(|feature| feature == forbidden),
                "{triple} unexpectedly enabled {forbidden}"
            );
        }
        let direct_children = node["deps"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|dep| dep["pkg"].as_str())
            .filter_map(|id| {
                metadata["packages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|package| package["id"] == id)
            })
            .map(|package| package["name"].as_str().unwrap())
            .collect::<HashSet<_>>();
        for required in ["png", "gif", "zune-jpeg", "image-webp"] {
            assert!(
                direct_children.contains(required),
                "{triple} missing image -> {required}"
            );
        }
        for expected_package in fixture["codecPackages"].as_array().unwrap() {
            let name = expected_package["name"].as_str().unwrap();
            let version = expected_package["version"].as_str().unwrap();
            if let Some(actual) = metadata["packages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|package| package["name"] == name && package["version"] == version)
            {
                observed_packages.insert((name.to_string(), version.to_string()));
                assert_eq!(
                    actual["license"], expected_package["license"],
                    "{name} license drift"
                );
                assert_eq!(
                    actual["rust_version"], expected_package["rustVersion"],
                    "{name} declared MSRV drift"
                );
                assert!(
                    actual["source"]
                        .as_str()
                        .is_some_and(|source| source.starts_with("registry+"))
                );
            }
        }
    }
    let lock = fs::read_to_string(workspace.join("Cargo.lock")).unwrap();
    for package in fixture["codecPackages"].as_array().unwrap() {
        let name = package["name"].as_str().unwrap();
        let version = package["version"].as_str().unwrap();
        let checksum = package["checksum"].as_str().unwrap();
        assert!(observed_packages.contains(&(name.to_string(), version.to_string())));
        let block = lock
            .split("[[package]]")
            .find(|block| {
                block.contains(&format!("name = \"{name}\""))
                    && block.contains(&format!("version = \"{version}\""))
            })
            .unwrap_or_else(|| panic!("missing exact lock package {name} {version}"));
        assert!(block.contains(&format!("checksum = \"{checksum}\"")));
    }
}
