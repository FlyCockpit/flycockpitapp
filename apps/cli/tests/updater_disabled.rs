//! Behavioural updater evidence for issue #442.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use assert_cmd::cargo::cargo_bin;
use async_trait::async_trait;
use cockpit_config::config::update_channel::UpdateChannel;
use cockpit_core::updater::fake::{
    FakeFixtureMetadataRepository, FakeFixtureTargetFetcher, FakeFixtureTrustRoot,
};
use cockpit_core::updater::{
    ActiveUpdater, BinaryReplacer, FakeFixtureEvidence, InstallationAuthorization,
    InstallationPaths, InstallationPolicy, ManualUpdateOutcome, MetadataRepository,
    PlatformBinaryReplacer, SupervisorMaintenanceClient, SupervisorMaintenanceRequest,
    TargetFetcher, TrustRoot, UntrustedRepositoryMetadata, UpdateApplyReceipt,
    UpdateApplyReceiptState, UpdateCheckResult, UpdateLockRecord, UpdateLockStore,
    UpdateStatusSnapshot, UpdateTargetDescriptor, Updater, UpdaterError,
    VerifiedRepositoryMetadata,
};
use sha2::{Digest, Sha256};

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn policy(
    current_exe: PathBuf,
    receipt: PathBuf,
    brew_prefix: Option<PathBuf>,
) -> InstallationPolicy {
    InstallationPolicy::new(InstallationPaths {
        current_exe,
        receipt,
        brew_prefix,
    })
}

fn write_receipt(path: &std::path::Path, install_prefix: &std::path::Path) {
    std::fs::write(
        path,
        serde_json::json!({ "install_prefix": install_prefix }).to_string(),
    )
    .unwrap();
}

#[test]
fn receipt_precedes_homebrew_and_authorizes_self_update() {
    let temp = tempfile::tempdir().unwrap();
    let prefix = temp.path().join("homebrew");
    let binary = prefix.join("bin/cockpit");
    let receipt = temp
        .path()
        .join("config/cockpit-cli/cockpit-cli-receipt.json");
    std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
    std::fs::create_dir_all(receipt.parent().unwrap()).unwrap();
    std::fs::write(&binary, b"old").unwrap();
    write_receipt(&receipt, &prefix);

    assert_eq!(
        policy(binary, receipt, Some(prefix)).authorize().unwrap(),
        InstallationAuthorization::SelfUpdate
    );
}

#[tokio::test]
async fn homebrew_branch_returns_command_and_leaves_binary_untouched() {
    let temp = tempfile::tempdir().unwrap();
    let prefix = temp.path().join("homebrew");
    let binary = prefix.join("bin/cockpit");
    std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
    std::fs::write(&binary, b"original-homebrew-binary").unwrap();
    let updater = updater_with_no_root(policy(
        binary.clone(),
        temp.path().join("missing-receipt.json"),
        Some(prefix),
    ));

    let outcome = updater
        .apply_manual(UpdateChannel::Auto, None)
        .await
        .unwrap();
    assert_eq!(
        outcome,
        ManualUpdateOutcome::Homebrew {
            command: "brew upgrade cockpit"
        }
    );
    assert_eq!(std::fs::read(binary).unwrap(), b"original-homebrew-binary");
}

#[test]
fn missing_receipt_outside_homebrew_refuses_package_manager_install() {
    let temp = tempfile::tempdir().unwrap();
    let error = policy(
        temp.path().join("usr/bin/cockpit"),
        temp.path().join("missing-receipt.json"),
        Some(temp.path().join("homebrew")),
    )
    .authorize()
    .unwrap_err();
    assert_eq!(error, UpdaterError::PackageManager);
    assert!(error.to_string().contains("installed by a package manager"));
}

#[derive(Debug)]
struct NeverRepository;

#[async_trait]
impl MetadataRepository for NeverRepository {
    async fn fetch_metadata(
        &self,
        _channel: UpdateChannel,
    ) -> Result<UntrustedRepositoryMetadata, UpdaterError> {
        panic!("repository must not run without a trust root")
    }
}

#[derive(Debug)]
struct NeverFetcher;

#[async_trait]
impl TargetFetcher for NeverFetcher {
    async fn download_target(
        &self,
        _target: &UpdateTargetDescriptor,
    ) -> Result<PathBuf, UpdaterError> {
        panic!("fetcher must not run without a trust root")
    }
}

#[derive(Debug)]
struct NeverReplacer;

#[async_trait]
impl BinaryReplacer for NeverReplacer {
    async fn stage_and_swap(
        &self,
        _staged: &PathBuf,
        _receipt: &mut UpdateApplyReceipt,
    ) -> Result<(), UpdaterError> {
        panic!("replacer must not run without a trust root")
    }
}

#[derive(Debug)]
struct NeverSupervisor;

#[async_trait]
impl SupervisorMaintenanceClient for NeverSupervisor {
    async fn request_maintenance(
        &self,
        _request: SupervisorMaintenanceRequest,
    ) -> Result<(), UpdaterError> {
        panic!("supervisor must not run without a trust root")
    }
}

#[derive(Debug, Default)]
struct MemoryLock;

#[async_trait]
impl UpdateLockStore for MemoryLock {
    async fn acquire_exclusive(&self, _record: &UpdateLockRecord) -> Result<(), UpdaterError> {
        Ok(())
    }

    async fn release(&self, _update_id: uuid::Uuid) -> Result<(), UpdaterError> {
        Ok(())
    }
}

fn updater_with_no_root(policy: InstallationPolicy) -> ActiveUpdater {
    ActiveUpdater::new(
        policy,
        "test-platform",
        None,
        Arc::new(NeverRepository),
        Arc::new(NeverFetcher),
        Arc::new(NeverReplacer),
        Arc::new(NeverSupervisor),
        Arc::new(MemoryLock),
    )
}

#[tokio::test]
async fn receipt_without_production_root_fails_closed_with_specific_reason() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("cockpit");
    let receipt = temp.path().join("cockpit-receipt.json");
    std::fs::write(&binary, b"old").unwrap();
    write_receipt(&receipt, temp.path());
    let updater = updater_with_no_root(policy(binary, receipt, None));

    assert_eq!(
        updater.check(UpdateChannel::Auto).await,
        UpdateCheckResult::Failed(UpdaterError::NoProductionTrustRoot)
    );
    assert_eq!(
        updater.status(UpdateChannel::Auto),
        UpdateStatusSnapshot::Unavailable {
            channel: UpdateChannel::Auto,
            reason: UpdaterError::NoProductionTrustRoot,
        }
    );
    let error = updater
        .apply_manual(UpdateChannel::Auto, None)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "no production trust root");
}

#[derive(Clone)]
struct RecordingRoot {
    inner: FakeFixtureTrustRoot,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl TrustRoot for RecordingRoot {
    fn verify_metadata(
        &self,
        metadata: &UntrustedRepositoryMetadata,
    ) -> Result<VerifiedRepositoryMetadata, UpdaterError> {
        let verified = self.inner.verify_metadata(metadata)?;
        self.events.lock().unwrap().push("metadata_verified");
        Ok(verified)
    }
}

struct RecordingReplacer {
    inner: PlatformBinaryReplacer,
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl BinaryReplacer for RecordingReplacer {
    async fn stage_and_swap(
        &self,
        staged: &PathBuf,
        receipt: &mut UpdateApplyReceipt,
    ) -> Result<(), UpdaterError> {
        self.inner.stage_and_swap(staged, receipt).await?;
        self.events.lock().unwrap().push("placed");
        Ok(())
    }
}

struct RecordingSupervisor {
    installed: PathBuf,
    expected: Vec<u8>,
    events: Arc<Mutex<Vec<&'static str>>>,
    maintenance_requests: Arc<Mutex<usize>>,
}

#[async_trait]
impl SupervisorMaintenanceClient for RecordingSupervisor {
    async fn request_maintenance(
        &self,
        _request: SupervisorMaintenanceRequest,
    ) -> Result<(), UpdaterError> {
        assert_eq!(std::fs::read(&self.installed).unwrap(), self.expected);
        assert_eq!(
            self.events.lock().unwrap().as_slice(),
            ["metadata_verified", "placed"]
        );
        *self.maintenance_requests.lock().unwrap() += 1;
        self.events.lock().unwrap().push("maintenance_requested");
        Ok(())
    }
}

#[derive(Default)]
struct RecordingLock {
    acquired: Arc<Mutex<usize>>,
    released: Arc<Mutex<usize>>,
}

#[async_trait]
impl UpdateLockStore for RecordingLock {
    async fn acquire_exclusive(&self, _record: &UpdateLockRecord) -> Result<(), UpdaterError> {
        *self.acquired.lock().unwrap() += 1;
        Ok(())
    }

    async fn release(&self, _update_id: uuid::Uuid) -> Result<(), UpdaterError> {
        *self.released.lock().unwrap() += 1;
        Ok(())
    }
}

#[tokio::test]
async fn receipt_fixture_tuf_target_places_binary_then_requests_maintenance_once() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("cockpit");
    let staged = temp.path().join("downloaded-cockpit");
    let receipt = temp.path().join("cockpit-receipt.json");
    let new_bytes = b"verified replacement binary".to_vec();
    std::fs::write(&binary, b"old binary").unwrap();
    std::fs::write(&staged, &new_bytes).unwrap();
    write_receipt(&receipt, temp.path());
    let target = UpdateTargetDescriptor {
        version: "9.9.9".into(),
        platform: "test-platform".into(),
        path: "cockpit-test.bin".into(),
        length: new_bytes.len() as u64,
        sha256: sha256(&new_bytes),
    };
    let fixture = FakeFixtureEvidence {
        release_tag: "v9.9.9".into(),
        commit: "fixture-commit".into(),
        targets: vec![target],
    };
    let fixture_root = FakeFixtureTrustRoot::new(fixture);
    let repository = FakeFixtureMetadataRepository {
        metadata: fixture_root.metadata(),
    };
    let events = Arc::new(Mutex::new(Vec::new()));
    let maintenance_requests = Arc::new(Mutex::new(0));
    let lock = Arc::new(RecordingLock::default());
    let updater = ActiveUpdater::new(
        policy(binary.clone(), receipt, None),
        "test-platform",
        Some(Arc::new(RecordingRoot {
            inner: fixture_root,
            events: events.clone(),
        })),
        Arc::new(repository),
        Arc::new(FakeFixtureTargetFetcher { path: staged }),
        Arc::new(RecordingReplacer {
            inner: PlatformBinaryReplacer::new(binary.clone()),
            events: events.clone(),
        }),
        Arc::new(RecordingSupervisor {
            installed: binary.clone(),
            expected: new_bytes.clone(),
            events: events.clone(),
            maintenance_requests: maintenance_requests.clone(),
        }),
        lock.clone(),
    );

    let outcome = updater
        .apply_manual(UpdateChannel::Auto, None)
        .await
        .unwrap();
    assert_eq!(
        outcome,
        ManualUpdateOutcome::Updated {
            version: "9.9.9".into()
        }
    );
    assert_eq!(std::fs::read(binary).unwrap(), new_bytes);
    assert_eq!(
        events.lock().unwrap().as_slice(),
        ["metadata_verified", "placed", "maintenance_requested"]
    );
    assert_eq!(*maintenance_requests.lock().unwrap(), 1);
    assert_eq!(*lock.acquired.lock().unwrap(), 1);
    assert_eq!(*lock.released.lock().unwrap(), 1);
}

#[tokio::test]
async fn corrupt_target_never_places_or_rolls() {
    let temp = tempfile::tempdir().unwrap();
    let binary = temp.path().join("cockpit");
    let staged = temp.path().join("downloaded-cockpit");
    let receipt = temp.path().join("cockpit-receipt.json");
    std::fs::write(&binary, b"old binary").unwrap();
    std::fs::write(&staged, b"corrupt").unwrap();
    write_receipt(&receipt, temp.path());
    let fixture = FakeFixtureEvidence {
        release_tag: "v9.9.9".into(),
        commit: "fixture-commit".into(),
        targets: vec![UpdateTargetDescriptor {
            version: "9.9.9".into(),
            platform: "test-platform".into(),
            path: "cockpit-test.bin".into(),
            length: 7,
            sha256: "0".repeat(64),
        }],
    };
    let root = FakeFixtureTrustRoot::new(fixture);
    let updater = ActiveUpdater::new(
        policy(binary.clone(), receipt, None),
        "test-platform",
        Some(Arc::new(root.clone())),
        Arc::new(FakeFixtureMetadataRepository {
            metadata: root.metadata(),
        }),
        Arc::new(FakeFixtureTargetFetcher { path: staged }),
        Arc::new(NeverReplacer),
        Arc::new(NeverSupervisor),
        Arc::new(MemoryLock),
    );

    assert_eq!(
        updater
            .apply_manual(UpdateChannel::Auto, None)
            .await
            .unwrap_err(),
        UpdaterError::TargetHash
    );
    assert_eq!(std::fs::read(binary).unwrap(), b"old binary");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_replacement_renames_a_sibling_temp_and_changes_inode() {
    use std::os::unix::fs::MetadataExt;

    let temp = tempfile::tempdir().unwrap();
    let installed = temp.path().join("cockpit");
    let staged = temp.path().join("staged");
    std::fs::write(&installed, b"old").unwrap();
    std::fs::write(&staged, b"new").unwrap();
    let before = std::fs::metadata(&installed).unwrap().ino();
    let mut receipt = UpdateApplyReceipt {
        update_id: uuid::Uuid::now_v7(),
        state: UpdateApplyReceiptState::VerifiedStaged,
        target: None,
        updated_at_unix_ms: 1,
    };

    PlatformBinaryReplacer::new(installed.clone())
        .stage_and_swap(&staged, &mut receipt)
        .await
        .unwrap();

    assert_eq!(std::fs::read(&installed).unwrap(), b"new");
    assert_ne!(before, std::fs::metadata(installed).unwrap().ino());
}

#[test]
fn cli_brew_refusal_is_successful_and_update_aliases_self_update() {
    let temp = tempfile::tempdir().unwrap();
    let binary = cargo_bin("cockpit");
    let before = std::fs::read(&binary).unwrap();
    let prefix = binary.parent().unwrap().parent().unwrap();
    for command in ["update", "self-update"] {
        let output = std::process::Command::new(&binary)
            .arg(command)
            .env("COCKPIT_UPDATES", "auto")
            .env("XDG_CONFIG_HOME", temp.path())
            .env("HOMEBREW_PREFIX", prefix)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "brew upgrade cockpit"
        );
    }
    assert_eq!(std::fs::read(binary).unwrap(), before);
}

#[test]
fn cli_without_receipt_refuses_generic_package_manager_install() {
    let temp = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(cargo_bin("cockpit"))
        .arg("update")
        .env("COCKPIT_UPDATES", "auto")
        .env("XDG_CONFIG_HOME", temp.path())
        .env("HOMEBREW_PREFIX", temp.path().join("not-the-prefix"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("installed by a package manager"));
}

#[test]
fn installed_cli_with_receipt_reports_missing_production_root() {
    let temp = tempfile::tempdir().unwrap();
    let binary = cargo_bin("cockpit");
    let receipt = temp.path().join("cockpit-cli/cockpit-cli-receipt.json");
    std::fs::create_dir_all(receipt.parent().unwrap()).unwrap();
    write_receipt(&receipt, binary.parent().unwrap().parent().unwrap());
    let output = std::process::Command::new(binary)
        .arg("update")
        .env("COCKPIT_UPDATES", "auto")
        .env("XDG_CONFIG_HOME", temp.path())
        .env("HOMEBREW_PREFIX", temp.path().join("not-the-prefix"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no production trust root"), "{stderr}");
    assert!(!stderr.contains("disabled"), "{stderr}");
}
