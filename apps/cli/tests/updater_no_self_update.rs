//! Behavioural evidence for the Homebrew/package-manager build boundary.
#![cfg(feature = "no-self-update")]

use assert_cmd::cargo::cargo_bin;

#[test]
fn no_self_update_build_refuses_through_the_cli_command() {
    let output = std::process::Command::new(cargo_bin("cockpit"))
        .arg("update")
        .env("COCKPIT_UPDATES", "auto")
        .output()
        .expect("run feature-disabled cockpit update");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("installed by a package manager"),
        "{stderr}"
    );
    assert!(!stderr.contains("no production trust root"), "{stderr}");
}

#[test]
fn no_self_update_homebrew_build_prints_the_brew_command_successfully() {
    let binary = cargo_bin("cockpit");
    let prefix = binary.parent().unwrap().parent().unwrap();
    let before = std::fs::read(&binary).expect("read feature-disabled binary before update");
    let output = std::process::Command::new(&binary)
        .arg("update")
        .env("COCKPIT_UPDATES", "auto")
        .env("HOMEBREW_PREFIX", prefix)
        .output()
        .expect("run feature-disabled Homebrew update");

    assert!(output.status.success(), "{:?}", output.stderr);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "brew upgrade cockpit"
    );
    assert_eq!(std::fs::read(binary).unwrap(), before);
}
