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
        let resolved = node["features"].as_array().unwrap();
        for feature in expected["resolvedFeatures"].as_array().unwrap() {
            assert!(resolved.contains(feature), "{triple} missing {feature}");
        }
        for forbidden in ["default", "default-formats", "rayon", "avif", "exr"] {
            assert!(
                !resolved.iter().any(|feature| feature == forbidden),
                "{triple} unexpectedly enabled {forbidden}"
            );
        }
    }
    let lock = fs::read_to_string(workspace.join("Cargo.lock")).unwrap();
    for package in fixture["codecPackages"].as_array().unwrap() {
        let name = package["name"].as_str().unwrap();
        let version = package["version"].as_str().unwrap();
        let checksum = package["checksum"].as_str().unwrap();
        assert!(lock.contains(&format!("name = \"{name}\"")));
        assert!(lock.contains(&format!("version = \"{version}\"")));
        assert!(lock.contains(checksum));
    }
}
