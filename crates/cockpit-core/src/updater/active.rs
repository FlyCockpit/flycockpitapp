//! Receipt-gated updater orchestration. Trust, repository, placement, locking,
//! and supervisor maintenance are injected so owner-only release artifacts are
//! never simulated by production code.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use async_trait::async_trait;
use cockpit_config::config::update_channel::UpdateChannel;
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::traits::{
    BinaryReplacer, MetadataRepository, SupervisorMaintenanceClient, TargetFetcher, TrustRoot,
    UpdateLockStore, Updater,
};
use super::types::{
    InstallationAuthorization, InstallationPaths, ManualUpdateOutcome,
    SupervisorMaintenanceRequest, UpdateApplyReceipt, UpdateApplyReceiptState, UpdateCheckResult,
    UpdateLockRecord, UpdateLockState, UpdateStatusSnapshot, UpdateTargetDescriptor, UpdaterError,
    VerifiedRepositoryMetadata,
};

pub const HOMEBREW_UPGRADE_COMMAND: &str = "brew upgrade cockpit";
/// cargo-dist's `app_name` is the distributable package name, not the binary
/// or Homebrew formula name. Keep receipt discovery on that exact contract.
pub const CARGO_DIST_APP_NAME: &str = "cockpit-cli";

#[derive(Debug, Clone)]
pub struct InstallationPolicy {
    paths: InstallationPaths,
}

impl InstallationPolicy {
    pub fn new(paths: InstallationPaths) -> Self {
        Self { paths }
    }

    pub fn production() -> Result<Self, UpdaterError> {
        let current_exe = std::env::current_exe()
            .map_err(|error| UpdaterError::io("resolving current executable", error))?;
        let receipt = cargo_dist_receipt_path()?;
        let brew_prefix = resolve_brew_prefix();
        Ok(Self::new(InstallationPaths {
            current_exe,
            receipt,
            brew_prefix,
        }))
    }

    pub fn authorize(&self) -> Result<InstallationAuthorization, UpdaterError> {
        if receipt_authorizes_executable(&self.paths.receipt, &self.paths.current_exe) {
            return Ok(InstallationAuthorization::SelfUpdate);
        }
        if self
            .paths
            .brew_prefix
            .as_ref()
            .is_some_and(|prefix| self.paths.current_exe.starts_with(prefix))
        {
            return Ok(InstallationAuthorization::Homebrew {
                command: HOMEBREW_UPGRADE_COMMAND,
            });
        }
        Err(UpdaterError::PackageManager)
    }

    pub fn current_exe(&self) -> &Path {
        &self.paths.current_exe
    }
}

pub fn cargo_dist_receipt_path() -> Result<PathBuf, UpdaterError> {
    #[cfg(windows)]
    let config_home = cargo_dist_config_home(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("LOCALAPPDATA"),
    );
    #[cfg(not(windows))]
    let config_home = cargo_dist_config_home(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    );
    config_home
        .map(|path| {
            path.join(CARGO_DIST_APP_NAME)
                .join(format!("{CARGO_DIST_APP_NAME}-receipt.json"))
        })
        .ok_or_else(|| UpdaterError::Io("could not resolve cargo-dist receipt directory".into()))
}

/// cargo-dist receipts are JSON and record the installation prefix. A receipt
/// only authorizes the executable that lives under that prefix; a touched file
/// at the conventional location is never sufficient.
fn receipt_authorizes_executable(receipt: &Path, current_exe: &Path) -> bool {
    let Ok(bytes) = std::fs::read(receipt) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    let Some(prefix) = value
        .get("install_prefix")
        .and_then(serde_json::Value::as_str)
    else {
        return false;
    };
    !prefix.is_empty() && current_exe.starts_with(prefix)
}

#[cfg(windows)]
fn cargo_dist_config_home(
    xdg_config_home: Option<std::ffi::OsString>,
    local_app_data: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    xdg_config_home.or(local_app_data).map(PathBuf::from)
}

#[cfg(not(windows))]
fn cargo_dist_config_home(
    xdg_config_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    xdg_config_home
        .map(PathBuf::from)
        .or_else(|| home.map(PathBuf::from).map(|path| path.join(".config")))
}

fn resolve_brew_prefix() -> Option<PathBuf> {
    if let Some(prefix) = std::env::var_os("HOMEBREW_PREFIX").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(prefix));
    }
    let output = Command::new("brew").arg("--prefix").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let prefix = String::from_utf8(output.stdout).ok()?;
    let prefix = prefix.trim();
    (!prefix.is_empty()).then(|| PathBuf::from(prefix))
}

pub struct ActiveUpdater {
    policy: InstallationPolicy,
    platform: Result<String, UpdaterError>,
    trust_root: Option<Arc<dyn TrustRoot>>,
    repository: Arc<dyn MetadataRepository>,
    fetcher: Arc<dyn TargetFetcher>,
    replacer: Arc<dyn BinaryReplacer>,
    supervisor: Arc<dyn SupervisorMaintenanceClient>,
    lock_store: Arc<dyn UpdateLockStore>,
}

impl ActiveUpdater {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy: InstallationPolicy,
        platform: impl Into<String>,
        trust_root: Option<Arc<dyn TrustRoot>>,
        repository: Arc<dyn MetadataRepository>,
        fetcher: Arc<dyn TargetFetcher>,
        replacer: Arc<dyn BinaryReplacer>,
        supervisor: Arc<dyn SupervisorMaintenanceClient>,
        lock_store: Arc<dyn UpdateLockStore>,
    ) -> Self {
        Self {
            policy,
            platform: Ok(platform.into()),
            trust_root,
            repository,
            fetcher,
            replacer,
            supervisor,
            lock_store,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_for_platform_result(
        policy: InstallationPolicy,
        platform: Result<String, UpdaterError>,
        trust_root: Option<Arc<dyn TrustRoot>>,
        repository: Arc<dyn MetadataRepository>,
        fetcher: Arc<dyn TargetFetcher>,
        replacer: Arc<dyn BinaryReplacer>,
        supervisor: Arc<dyn SupervisorMaintenanceClient>,
        lock_store: Arc<dyn UpdateLockStore>,
    ) -> Self {
        Self {
            policy,
            platform,
            trust_root,
            repository,
            fetcher,
            replacer,
            supervisor,
            lock_store,
        }
    }

    fn root(&self) -> Result<&dyn TrustRoot, UpdaterError> {
        self.trust_root
            .as_deref()
            .ok_or(UpdaterError::NoProductionTrustRoot)
    }

    fn platform(&self) -> Result<&str, UpdaterError> {
        self.platform.as_deref().map_err(Clone::clone)
    }

    async fn verified_metadata(
        &self,
        channel: UpdateChannel,
    ) -> Result<VerifiedRepositoryMetadata, UpdaterError> {
        let root = self.root()?;
        let untrusted = self.repository.fetch_metadata(channel).await?;
        root.verify_metadata(&untrusted)
    }

    fn select_target<'a>(
        &'a self,
        metadata: &'a VerifiedRepositoryMetadata,
        requested: Option<&str>,
    ) -> Result<&'a UpdateTargetDescriptor, UpdaterError> {
        let platform = self.platform()?;
        metadata
            .targets
            .iter()
            .filter(|target| target.platform == platform)
            .filter(|target| requested.is_none_or(|version| target.version == version))
            .max_by(|left, right| compare_versions(&left.version, &right.version))
            .ok_or_else(|| UpdaterError::TargetNotFound(requested.unwrap_or("latest").to_string()))
    }

    async fn apply_authorized(
        &self,
        channel: UpdateChannel,
        version: Option<&str>,
    ) -> Result<ManualUpdateOutcome, UpdaterError> {
        self.platform()?;
        let update_id = Uuid::now_v7();
        let installed_path_digest =
            hex_sha256(self.policy.current_exe().as_os_str().as_encoded_bytes());
        let lock = UpdateLockRecord {
            update_id,
            owner_pid: std::process::id(),
            owner_start_id: process_start_id(std::process::id())?,
            installed_path_digest: installed_path_digest.clone(),
            state: UpdateLockState::Held,
            revision: 1,
        };
        self.lock_store.acquire_exclusive(&lock).await?;
        let result = self
            .apply_while_locked(channel, version, update_id, installed_path_digest)
            .await;
        let release = self.lock_store.release(update_id).await;
        match (result, release) {
            (Ok(outcome), Ok(())) => Ok(outcome),
            (Err(error), _) => Err(error),
            // The committed replacement is durable even if lock cleanup was
            // interrupted. Do not turn a successful update into a failure.
            (Ok(outcome), Err(error)) => {
                tracing::warn!(error = %error, "updated binary but could not remove update lock");
                Ok(outcome)
            }
        }
    }

    async fn apply_while_locked(
        &self,
        channel: UpdateChannel,
        version: Option<&str>,
        update_id: Uuid,
        installed_path_digest: String,
    ) -> Result<ManualUpdateOutcome, UpdaterError> {
        let metadata = self.verified_metadata(channel).await?;
        let target = self.select_target(&metadata, version)?.clone();
        let mut receipt = UpdateApplyReceipt {
            update_id,
            state: UpdateApplyReceiptState::Selected,
            target: Some(target.clone()),
            updated_at_unix_ms: now_unix_ms(),
        };
        let staged = self.fetcher.download_target(&target).await?;
        verify_target(&staged, &target)?;
        let staged_binary = extract_executable(&staged, &target)?;
        receipt.state = UpdateApplyReceiptState::VerifiedStaged;
        receipt.updated_at_unix_ms = now_unix_ms();
        self.replacer
            .stage_and_swap(staged_binary.path(), &mut receipt)
            .await?;
        receipt.state = UpdateApplyReceiptState::Swapped;
        receipt.updated_at_unix_ms = now_unix_ms();
        if let Err(error) = self
            .supervisor
            .request_maintenance(SupervisorMaintenanceRequest {
                update_id,
                target_version: target.version.clone(),
                installed_path_digest,
            })
            .await
        {
            return Ok(ManualUpdateOutcome::PlacedSupervisorUnavailable {
                version: target.version,
                reason: error.to_string(),
            });
        }
        receipt.state = UpdateApplyReceiptState::MaintenanceRequested;
        Ok(ManualUpdateOutcome::Updated {
            version: target.version,
        })
    }
}

#[async_trait]
impl Updater for ActiveUpdater {
    async fn check(&self, channel: UpdateChannel) -> UpdateCheckResult {
        if channel == UpdateChannel::Off {
            return UpdateCheckResult::Off;
        }
        match self.policy.authorize() {
            Ok(InstallationAuthorization::Homebrew { .. }) => {
                return UpdateCheckResult::Failed(UpdaterError::PackageManager);
            }
            Err(error) => return UpdateCheckResult::Failed(error),
            Ok(InstallationAuthorization::SelfUpdate) => {}
        }
        let result = async {
            self.platform()?;
            let metadata = self.verified_metadata(channel).await?;
            let target = self.select_target(&metadata, None)?;
            Ok::<_, UpdaterError>(target.version.clone())
        }
        .await;
        match result {
            Ok(version) if version == env!("CARGO_PKG_VERSION") => UpdateCheckResult::Current,
            Ok(version) => UpdateCheckResult::Available { version },
            Err(error) => UpdateCheckResult::Failed(error),
        }
    }

    async fn apply_manual(
        &self,
        channel: UpdateChannel,
        version: Option<&str>,
    ) -> Result<ManualUpdateOutcome, UpdaterError> {
        if channel == UpdateChannel::Off {
            return Err(UpdaterError::Off);
        }
        match self.policy.authorize()? {
            InstallationAuthorization::SelfUpdate => self.apply_authorized(channel, version).await,
            InstallationAuthorization::Homebrew { command } => {
                Ok(ManualUpdateOutcome::Homebrew { command })
            }
        }
    }

    fn status(&self, channel: UpdateChannel) -> UpdateStatusSnapshot {
        if channel == UpdateChannel::Off {
            return UpdateStatusSnapshot::Off;
        }
        let result = self
            .policy
            .authorize()
            .and_then(|authorization| match authorization {
                InstallationAuthorization::SelfUpdate => self
                    .platform()
                    .map(|_| ())
                    .and_then(|()| self.root().map(|_| ())),
                InstallationAuthorization::Homebrew { .. } => Err(UpdaterError::PackageManager),
            });
        match result {
            Ok(()) => UpdateStatusSnapshot::Ready { channel },
            Err(reason) => UpdateStatusSnapshot::Unavailable { channel, reason },
        }
    }
}

enum StagedExecutable {
    Raw(PathBuf),
    Temporary(tempfile::NamedTempFile),
}

impl StagedExecutable {
    fn path(&self) -> &Path {
        match self {
            Self::Raw(path) => path,
            Self::Temporary(file) => file.path(),
        }
    }
}

fn extract_executable(
    staged: &Path,
    target: &UpdateTargetDescriptor,
) -> Result<StagedExecutable, UpdaterError> {
    if target.path.ends_with(".bin") {
        return Ok(StagedExecutable::Raw(staged.to_path_buf()));
    }
    if target.path.ends_with(".tar.gz") {
        return extract_tar_gz_executable(staged).map(StagedExecutable::Temporary);
    }
    if target.path.ends_with(".zip") {
        return extract_zip_executable(staged).map(StagedExecutable::Temporary);
    }
    Err(UpdaterError::UnsupportedArtifact(target.path.clone()))
}

fn extract_tar_gz_executable(staged: &Path) -> Result<tempfile::NamedTempFile, UpdaterError> {
    use std::io::Read;

    let source = std::fs::File::open(staged)
        .map_err(|error| UpdaterError::io("opening downloaded tarball", error))?;
    let mut archive = Vec::new();
    GzDecoder::new(source)
        .read_to_end(&mut archive)
        .map_err(|error| UpdaterError::InvalidArchive(format!("reading gzip stream: {error}")))?;
    extract_tar_member(&archive)
}

fn extract_tar_member(archive: &[u8]) -> Result<tempfile::NamedTempFile, UpdaterError> {
    const HEADER_SIZE: usize = 512;
    let mut offset = 0;
    let mut executable = None;
    while offset < archive.len() {
        let header_end = offset
            .checked_add(HEADER_SIZE)
            .ok_or_else(|| UpdaterError::InvalidArchive("tar header offset overflow".into()))?;
        let header = archive
            .get(offset..header_end)
            .ok_or_else(|| UpdaterError::InvalidArchive("truncated tar header".into()))?;
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let size = tar_octal(&header[124..136], "member size")?;
        let mode = tar_octal(&header[100..108], "member mode")?;
        let name = tar_name(header)?;
        let data_start = header_end;
        let data_end = data_start
            .checked_add(size)
            .ok_or_else(|| UpdaterError::InvalidArchive("tar member size overflow".into()))?;
        let data = archive.get(data_start..data_end).ok_or_else(|| {
            UpdaterError::InvalidArchive(format!("truncated tar member `{name}`"))
        })?;
        let is_executable = matches!(name.as_str(), "cockpit" | "cockpit-cli")
            && matches!(header[156], 0 | b'0')
            && mode & 0o111 != 0;
        if is_executable && executable.replace((data.to_vec(), mode)).is_some() {
            return Err(UpdaterError::InvalidArchive(
                "tarball contains more than one cockpit executable".into(),
            ));
        }
        let padded = size
            .checked_add(HEADER_SIZE - 1)
            .ok_or_else(|| UpdaterError::InvalidArchive("tar member padding overflow".into()))?
            / HEADER_SIZE
            * HEADER_SIZE;
        offset = data_start
            .checked_add(padded)
            .ok_or_else(|| UpdaterError::InvalidArchive("tar member offset overflow".into()))?;
    }
    let Some((bytes, mode)) = executable else {
        return Err(UpdaterError::InvalidArchive(
            "tarball contains no executable cockpit member".into(),
        ));
    };
    let mut output = tempfile::NamedTempFile::new()
        .map_err(|error| UpdaterError::io("creating extracted update staging file", error))?;
    use std::io::Write;
    output
        .write_all(&bytes)
        .map_err(|error| UpdaterError::io("writing extracted update staging file", error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(output.path(), std::fs::Permissions::from_mode(mode as u32))
            .map_err(|error| UpdaterError::io("setting extracted executable permissions", error))?;
    }
    Ok(output)
}

fn tar_octal(field: &[u8], label: &str) -> Result<usize, UpdaterError> {
    let value = std::str::from_utf8(field)
        .map_err(|_| UpdaterError::InvalidArchive(format!("tar {label} is not UTF-8")))?
        .trim_matches(['\0', ' ']);
    if value.is_empty() {
        return Ok(0);
    }
    usize::from_str_radix(value, 8)
        .map_err(|_| UpdaterError::InvalidArchive(format!("tar {label} is not octal")))
}

fn tar_name(header: &[u8]) -> Result<String, UpdaterError> {
    let name = std::str::from_utf8(&header[..100])
        .map_err(|_| UpdaterError::InvalidArchive("tar member name is not UTF-8".into()))?
        .trim_end_matches('\0');
    if name.is_empty() {
        return Err(UpdaterError::InvalidArchive(
            "tar member name is empty".into(),
        ));
    }
    Ok(name.to_owned())
}

#[cfg(windows)]
fn extract_zip_executable(staged: &Path) -> Result<tempfile::NamedTempFile, UpdaterError> {
    use std::io::{Read, Write};

    let source = std::fs::File::open(staged)
        .map_err(|error| UpdaterError::io("opening downloaded zip archive", error))?;
    let mut archive = zip::ZipArchive::new(source)
        .map_err(|error| UpdaterError::InvalidArchive(format!("reading zip archive: {error}")))?;
    let mut executable = None;
    for index in 0..archive.len() {
        let mut member = archive.by_index(index).map_err(|error| {
            UpdaterError::InvalidArchive(format!("reading zip member: {error}"))
        })?;
        if member.name() == "cockpit.exe" && member.is_file() {
            if executable.is_some() {
                return Err(UpdaterError::InvalidArchive(
                    "zip archive contains more than one cockpit.exe member".into(),
                ));
            }
            let mut bytes = Vec::new();
            member.read_to_end(&mut bytes).map_err(|error| {
                UpdaterError::InvalidArchive(format!("reading cockpit.exe member: {error}"))
            })?;
            executable = Some(bytes);
        }
    }
    let bytes = executable.ok_or_else(|| {
        UpdaterError::InvalidArchive("zip archive contains no cockpit.exe member".into())
    })?;
    let mut output = tempfile::NamedTempFile::new()
        .map_err(|error| UpdaterError::io("creating extracted update staging file", error))?;
    output
        .write_all(&bytes)
        .map_err(|error| UpdaterError::io("writing extracted update staging file", error))?;
    Ok(output)
}

#[cfg(not(windows))]
fn extract_zip_executable(_staged: &Path) -> Result<tempfile::NamedTempFile, UpdaterError> {
    Err(UpdaterError::UnsupportedArtifact(
        "zip artifacts are only supported on Windows".into(),
    ))
}

fn verify_target(path: &Path, target: &UpdateTargetDescriptor) -> Result<(), UpdaterError> {
    let bytes = std::fs::read(path)
        .map_err(|error| UpdaterError::io("reading downloaded update target", error))?;
    let actual = u64::try_from(bytes.len())
        .map_err(|_| UpdaterError::Io("downloaded update target length overflow".into()))?;
    if actual != target.length {
        return Err(UpdaterError::TargetLength {
            expected: target.length,
            actual,
        });
    }
    if hex_sha256(&bytes) != target.sha256 {
        return Err(UpdaterError::TargetHash);
    }
    Ok(())
}

pub(crate) fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

fn process_start_id(pid: u32) -> Result<String, UpdaterError> {
    let identity =
        cockpit_host::daemon_lifecycle::process_start_identity(pid).map_err(|error| {
            UpdaterError::Lock(format!("reading update lock owner identity: {error}"))
        })?;
    Ok(format!("{}:{}", identity.primary, identity.secondary))
}

pub fn current_platform() -> Result<String, UpdaterError> {
    cargo_dist_target_for(std::env::consts::ARCH, std::env::consts::OS)
        .map(str::to_owned)
        .ok_or(UpdaterError::UnsupportedPlatform)
}

fn cargo_dist_target_for(arch: &str, os: &str) -> Option<&'static str> {
    match (arch, os) {
        ("aarch64", "macos") => Some("aarch64-apple-darwin"),
        ("x86_64", "macos") => Some("x86_64-apple-darwin"),
        ("aarch64", "linux") => Some("aarch64-unknown-linux-gnu"),
        ("x86_64", "linux") => Some("x86_64-unknown-linux-gnu"),
        ("x86_64", "windows") => Some("x86_64-pc-windows-msvc"),
        _ => None,
    }
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    fn parsed(version: &str) -> Option<Vec<u64>> {
        version.split('.').map(|part| part.parse().ok()).collect()
    }
    match (parsed(left), parsed(right)) {
        (Some(left), Some(right)) => left.cmp(&right),
        // Metadata signatures authorize target membership, but malformed
        // version labels must not receive a surprising lexical preference.
        (Some(_), None) => std::cmp::Ordering::Greater,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::UntrustedRepositoryMetadata;
    use super::*;

    struct NeverRepository;

    #[async_trait]
    impl MetadataRepository for NeverRepository {
        async fn fetch_metadata(
            &self,
            _channel: UpdateChannel,
        ) -> Result<UntrustedRepositoryMetadata, UpdaterError> {
            panic!("unsupported platforms must not fetch metadata")
        }
    }

    struct NeverFetcher;

    #[async_trait]
    impl TargetFetcher for NeverFetcher {
        async fn download_target(
            &self,
            _target: &UpdateTargetDescriptor,
        ) -> Result<PathBuf, UpdaterError> {
            panic!("unsupported platforms must not download targets")
        }
    }

    struct NeverReplacer;

    #[async_trait]
    impl BinaryReplacer for NeverReplacer {
        async fn stage_and_swap(
            &self,
            _staged: &PathBuf,
            _receipt: &mut UpdateApplyReceipt,
        ) -> Result<(), UpdaterError> {
            panic!("unsupported platforms must not replace binaries")
        }
    }

    struct NeverSupervisor;

    #[async_trait]
    impl SupervisorMaintenanceClient for NeverSupervisor {
        async fn request_maintenance(
            &self,
            _request: SupervisorMaintenanceRequest,
        ) -> Result<(), UpdaterError> {
            panic!("unsupported platforms must not request maintenance")
        }
    }

    struct MemoryLock;

    #[async_trait]
    impl UpdateLockStore for MemoryLock {
        async fn acquire_exclusive(&self, _record: &UpdateLockRecord) -> Result<(), UpdaterError> {
            Ok(())
        }

        async fn release(&self, _update_id: Uuid) -> Result<(), UpdaterError> {
            Ok(())
        }
    }

    fn tar_gz(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        use std::io::Write;

        let mut tar = Vec::new();
        for (name, bytes, mode) in entries {
            let mut header = [0_u8; 512];
            header[..name.len()].copy_from_slice(name.as_bytes());
            write_tar_octal(&mut header[100..108], *mode as usize);
            write_tar_octal(&mut header[124..136], bytes.len());
            header[156] = b'0';
            tar.extend_from_slice(&header);
            tar.extend_from_slice(bytes);
            tar.resize((tar.len() + 511) & !511, 0);
        }
        tar.resize(tar.len() + 1024, 0);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar).unwrap();
        encoder.finish().unwrap()
    }

    fn write_tar_octal(field: &mut [u8], value: usize) {
        let encoded = format!("{value:0width$o}", width = field.len() - 1);
        field[..encoded.len()].copy_from_slice(encoded.as_bytes());
        field[field.len() - 1] = 0;
    }

    fn write_receipt(path: &Path, prefix: &Path) {
        std::fs::write(
            path,
            serde_json::json!({ "install_prefix": prefix }).to_string(),
        )
        .unwrap();
    }

    #[test]
    fn refusal_ladder_is_receipt_then_brew_then_generic() {
        let temp = tempfile::tempdir().unwrap();
        let prefix = temp.path().join("brew");
        let binary = prefix.join("bin/cockpit");
        let receipt = temp.path().join("cockpit-receipt.json");
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, b"binary").unwrap();
        write_receipt(&receipt, &prefix);

        let with_receipt = InstallationPolicy::new(InstallationPaths {
            current_exe: binary.clone(),
            receipt: receipt.clone(),
            brew_prefix: Some(prefix.clone()),
        });
        assert_eq!(
            with_receipt.authorize().unwrap(),
            InstallationAuthorization::SelfUpdate
        );

        std::fs::remove_file(receipt).unwrap();
        assert_eq!(
            with_receipt.authorize().unwrap(),
            InstallationAuthorization::Homebrew {
                command: HOMEBREW_UPGRADE_COMMAND
            }
        );

        let generic = InstallationPolicy::new(InstallationPaths {
            current_exe: temp.path().join("usr/bin/cockpit"),
            receipt: temp.path().join("missing.json"),
            brew_prefix: Some(prefix),
        });
        assert_eq!(generic.authorize(), Err(UpdaterError::PackageManager));
    }

    #[cfg(not(windows))]
    #[test]
    fn cargo_dist_receipt_home_matches_the_unix_installer_contract() {
        assert_eq!(
            cargo_dist_config_home(Some("/xdg".into()), Some("/home/user".into())),
            Some(PathBuf::from("/xdg"))
        );
        assert_eq!(
            cargo_dist_config_home(None, Some("/home/user".into())),
            Some(PathBuf::from("/home/user/.config"))
        );
    }

    #[test]
    fn cargo_dist_receipt_path_uses_the_package_app_name_contract() {
        assert_eq!(CARGO_DIST_APP_NAME, "cockpit-cli");
        let config = PathBuf::from("/xdg");
        assert_eq!(
            config
                .join(CARGO_DIST_APP_NAME)
                .join(format!("{CARGO_DIST_APP_NAME}-receipt.json")),
            PathBuf::from("/xdg/cockpit-cli/cockpit-cli-receipt.json")
        );
    }

    #[test]
    fn receipt_must_be_json_and_bind_the_current_install_prefix() {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("bin/cockpit");
        let receipt = temp.path().join("receipt.json");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, b"binary").unwrap();
        std::fs::write(&receipt, b"{}").unwrap();
        let policy = InstallationPolicy::new(InstallationPaths {
            current_exe: executable.clone(),
            receipt: receipt.clone(),
            brew_prefix: None,
        });
        assert_eq!(policy.authorize(), Err(UpdaterError::PackageManager));
        write_receipt(&receipt, temp.path());
        assert_eq!(
            policy.authorize(),
            Ok(InstallationAuthorization::SelfUpdate)
        );
    }

    #[test]
    fn cargo_dist_target_table_matches_every_release_target() {
        const DIST_WORKSPACE: &str = include_str!("../../../../dist-workspace.toml");
        let targets = [
            (("aarch64", "macos"), "aarch64-apple-darwin"),
            (("aarch64", "linux"), "aarch64-unknown-linux-gnu"),
            (("x86_64", "macos"), "x86_64-apple-darwin"),
            (("x86_64", "linux"), "x86_64-unknown-linux-gnu"),
            (("x86_64", "windows"), "x86_64-pc-windows-msvc"),
        ];
        for ((arch, os), target) in targets {
            assert!(
                DIST_WORKSPACE.contains(target),
                "dist-workspace target {target} must be represented by current_platform"
            );
            assert_eq!(cargo_dist_target_for(arch, os), Some(target));
        }
    }

    #[test]
    fn latest_target_uses_numeric_version_ordering() {
        assert!(compare_versions("10.0.0", "9.9.9").is_gt());
        assert!(compare_versions("9.9.10", "9.9.9").is_gt());
    }

    #[test]
    fn target_bytes_must_match_root_authorized_length_and_hash() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("target");
        std::fs::write(&path, b"verified").unwrap();
        let mut target = UpdateTargetDescriptor {
            version: "9.9.9".into(),
            platform: "test".into(),
            path: "target.bin".into(),
            length: 8,
            sha256: hex_sha256(b"verified"),
        };
        verify_target(&path, &target).unwrap();
        target.length = 7;
        assert_eq!(
            verify_target(&path, &target),
            Err(UpdaterError::TargetLength {
                expected: 7,
                actual: 8,
            })
        );
        target.length = 8;
        target.sha256 = "0".repeat(64);
        assert_eq!(verify_target(&path, &target), Err(UpdaterError::TargetHash));
    }

    #[tokio::test]
    async fn verified_tarball_places_its_executable_member_not_archive_bytes() {
        use super::super::platform::PlatformBinaryReplacer;

        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("cockpit.tar.gz");
        let installed = temp.path().join("cockpit");
        let executable = b"new executable member";
        let archive_bytes = tar_gz(&[("cockpit", executable, 0o755)]);
        std::fs::write(&archive, &archive_bytes).unwrap();
        std::fs::write(&installed, b"old executable").unwrap();
        let target = UpdateTargetDescriptor {
            version: "9.9.9".into(),
            platform: "test".into(),
            path: "cockpit.tar.gz".into(),
            length: archive_bytes.len() as u64,
            sha256: hex_sha256(&archive_bytes),
        };
        verify_target(&archive, &target).unwrap();
        let extracted = extract_executable(&archive, &target).unwrap();
        let mut receipt = UpdateApplyReceipt {
            update_id: Uuid::now_v7(),
            state: UpdateApplyReceiptState::VerifiedStaged,
            target: Some(target),
            updated_at_unix_ms: 1,
        };
        PlatformBinaryReplacer::new(installed.clone())
            .stage_and_swap(&extracted.path().to_path_buf(), &mut receipt)
            .await
            .unwrap();
        assert_eq!(std::fs::read(installed).unwrap(), executable);
    }

    #[test]
    fn tarball_without_exactly_one_executable_member_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        for (name, entries) in [
            ("zero", vec![("README", &b"text"[..], 0o644)]),
            (
                "two",
                vec![
                    ("cockpit", &b"first"[..], 0o755),
                    ("cockpit-cli", &b"second"[..], 0o755),
                ],
            ),
        ] {
            let archive = temp.path().join(format!("{name}.tar.gz"));
            std::fs::write(&archive, tar_gz(&entries)).unwrap();
            let target = UpdateTargetDescriptor {
                version: "9.9.9".into(),
                platform: "test".into(),
                path: format!("{name}.tar.gz"),
                length: std::fs::metadata(&archive).unwrap().len(),
                sha256: hex_sha256(&std::fs::read(&archive).unwrap()),
            };
            assert!(matches!(
                extract_executable(&archive, &target),
                Err(UpdaterError::InvalidArchive(_))
            ));
        }
    }

    #[tokio::test]
    async fn unsupported_platform_is_reported_without_target_lookup() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("cockpit");
        let receipt = temp.path().join("receipt.json");
        std::fs::write(&binary, b"binary").unwrap();
        write_receipt(&receipt, temp.path());
        let updater = ActiveUpdater::new_for_platform_result(
            InstallationPolicy::new(InstallationPaths {
                current_exe: binary,
                receipt,
                brew_prefix: None,
            }),
            Err(UpdaterError::UnsupportedPlatform),
            None,
            Arc::new(NeverRepository),
            Arc::new(NeverFetcher),
            Arc::new(NeverReplacer),
            Arc::new(NeverSupervisor),
            Arc::new(MemoryLock),
        );
        assert_eq!(
            updater.check(UpdateChannel::Auto).await,
            UpdateCheckResult::Failed(UpdaterError::UnsupportedPlatform)
        );
        assert_eq!(
            updater.status(UpdateChannel::Auto),
            UpdateStatusSnapshot::Unavailable {
                channel: UpdateChannel::Auto,
                reason: UpdaterError::UnsupportedPlatform,
            }
        );
        assert_eq!(
            updater.apply_manual(UpdateChannel::Auto, None).await,
            Err(UpdaterError::UnsupportedPlatform)
        );
    }
}
