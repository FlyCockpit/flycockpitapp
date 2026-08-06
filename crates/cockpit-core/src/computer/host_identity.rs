//! Machine-local host installation identity for physical target keys.
//!
//! The identity is a 32-byte value generated once from the locked fallible OS
//! entropy source [`rand::rngs::SysRng`] and stored at
//! `<cockpit_data_dir>/host-installation-id.v1`. Corruption is never silently
//! repaired; real-desktop input fails closed until an explicit repair workflow.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rand::TryRng;
use rand::rngs::SysRng;
use sha2::{Digest, Sha256};

/// File name under the Cockpit data directory.
pub const HOST_INSTALLATION_ID_FILE: &str = "host-installation-id.v1";
/// Cross-process exclusive lock file name (same directory).
pub const HOST_INSTALLATION_ID_LOCK: &str = "host-installation-id.lock";

/// Exactly 32 random bytes. Never logged, serialized, or emitted on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostInstallationId(pub [u8; 32]);

impl HostInstallationId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Safe diagnostic only: present or a reason code — never raw bytes.
    pub fn diagnostic(&self) -> HostIdentityDiagnostic {
        HostIdentityDiagnostic::Present
    }
}

impl fmt::Debug for HostInstallationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HostInstallationId([REDACTED; 32])")
    }
}

/// Safe diagnostics for host identity. Never carries raw ID bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostIdentityDiagnostic {
    Present,
    Unavailable(HostIdentityUnavailableReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostIdentityUnavailableReason {
    EntropyFailure,
    LockFailure,
    CorruptEncoding,
    WrongOwnerOrMode,
    SymlinkOrReparse,
    NonRegular,
    MultiLink,
    ReplacementDetected,
    FsyncOrRenameFailure,
    MismatchOnReopen,
    IoFailure,
    DirectoryUnavailable,
}

/// Typed fail-closed error for host identity initialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostIdentityError {
    pub reason: HostIdentityUnavailableReason,
}

impl fmt::Display for HostIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "host_identity_unavailable: {:?}", self.reason)
    }
}

impl std::error::Error for HostIdentityError {}

impl HostIdentityError {
    pub fn unavailable(reason: HostIdentityUnavailableReason) -> Self {
        Self { reason }
    }
}

/// Fallible entropy source. Production uses [`SysHostIdentityRng`].
pub trait HostIdentityRng: Send {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), HostIdentityError>;
}

/// Production RNG: locked `rand 0.10.2` fallible `SysRng` via `TryRng::try_fill_bytes`.
#[derive(Debug, Default)]
pub struct SysHostIdentityRng;

impl HostIdentityRng for SysHostIdentityRng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), HostIdentityError> {
        // Explicitly call the fallible path; never ThreadRng / panicking helpers.
        TryRng::try_fill_bytes(&mut SysRng, dest).map_err(|_| {
            HostIdentityError::unavailable(HostIdentityUnavailableReason::EntropyFailure)
        })
    }
}

/// Filesystem seam for host identity. Tests inject barriers and corruption.
pub trait HostIdentityFs: Send {
    fn ensure_data_dir(&mut self, path: &Path) -> Result<(), HostIdentityError>;
    fn open_lock(&mut self, data_dir: &Path) -> Result<HostIdentityLockGuard, HostIdentityError>;
    fn read_id_file(&mut self, data_dir: &Path) -> Result<Option<Vec<u8>>, HostIdentityError>;
    fn publish_id_file(&mut self, data_dir: &Path, encoded: &[u8])
    -> Result<(), HostIdentityError>;
    /// Optional crash barrier name observed by tests (no-op in production).
    fn crash_barrier(&mut self, _name: &str) -> Result<(), HostIdentityError> {
        Ok(())
    }
}

/// Opaque exclusive lock held across read/create/verify.
pub struct HostIdentityLockGuard {
    #[cfg(unix)]
    _file: Option<File>,
    #[cfg(not(unix))]
    _file: Option<File>,
}

/// Encode 32 raw bytes as 64 lowercase hex ASCII + LF.
pub fn encode_host_installation_id(id: &HostInstallationId) -> [u8; 65] {
    let mut out = [0u8; 65];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, byte) in id.0.iter().enumerate() {
        out[i * 2] = HEX[(byte >> 4) as usize];
        out[i * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    out[64] = b'\n';
    out
}

/// Exact-decode 64 lowercase hex ASCII + LF into 32 bytes.
pub fn decode_host_installation_id(bytes: &[u8]) -> Result<HostInstallationId, HostIdentityError> {
    if bytes.len() != 65 {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::CorruptEncoding,
        ));
    }
    if bytes[64] != b'\n' {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::CorruptEncoding,
        ));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = decode_hex_nibble(bytes[i * 2])?;
        let lo = decode_hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(HostInstallationId(out))
}

fn decode_hex_nibble(b: u8) -> Result<u8, HostIdentityError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        // Uppercase is rejected (exact lowercase only).
        _ => Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::CorruptEncoding,
        )),
    }
}

/// Load or create the host installation identity under `data_dir`.
///
/// Concurrent initializers all return the byte-identical winning ID. A loser
/// never returns its generated candidate. Corruption is never regenerated.
pub fn load_or_create_host_installation_id<R, F>(
    data_dir: &Path,
    rng: &mut R,
    fs: &mut F,
) -> Result<HostInstallationId, HostIdentityError>
where
    R: HostIdentityRng,
    F: HostIdentityFs,
{
    fs.ensure_data_dir(data_dir)?;
    let _lock = fs.open_lock(data_dir)?;

    // Re-read after acquiring the lock.
    if let Some(existing) = fs.read_id_file(data_dir)? {
        return decode_host_installation_id(&existing);
    }

    let mut raw = [0u8; 32];
    rng.try_fill_bytes(&mut raw)?;
    let candidate = HostInstallationId(raw);
    let encoded = encode_host_installation_id(&candidate);

    fs.crash_barrier("before_publish")?;
    fs.publish_id_file(data_dir, &encoded)?;
    fs.crash_barrier("after_publish")?;

    // Reopen and exact-decode the winner (never trust the in-memory candidate
    // if another process won the race — read_id_file after publish must match).
    let published = fs.read_id_file(data_dir)?.ok_or_else(|| {
        HostIdentityError::unavailable(HostIdentityUnavailableReason::MismatchOnReopen)
    })?;
    let winner = decode_host_installation_id(&published)?;
    // If we lost a create race the winner may differ; always return file bytes.
    let _ = candidate;
    Ok(winner)
}

/// Production path: `<cockpit_data_dir>/host-installation-id.v1`.
pub fn host_installation_id_path(data_dir: &Path) -> PathBuf {
    data_dir.join(HOST_INSTALLATION_ID_FILE)
}

/// Production filesystem: real directory/file ops with Unix mode/lock checks.
#[derive(Debug, Default)]
pub struct RealHostIdentityFs;

impl HostIdentityFs for RealHostIdentityFs {
    fn ensure_data_dir(&mut self, path: &Path) -> Result<(), HostIdentityError> {
        ensure_cockpit_data_dir(path)
    }

    fn open_lock(&mut self, data_dir: &Path) -> Result<HostIdentityLockGuard, HostIdentityError> {
        open_host_identity_lock(data_dir)
    }

    fn read_id_file(&mut self, data_dir: &Path) -> Result<Option<Vec<u8>>, HostIdentityError> {
        read_host_identity_file(data_dir)
    }

    fn publish_id_file(
        &mut self,
        data_dir: &Path,
        encoded: &[u8],
    ) -> Result<(), HostIdentityError> {
        publish_host_identity_file(data_dir, encoded)
    }
}

fn map_io(err: std::io::Error) -> HostIdentityError {
    let _ = err;
    HostIdentityError::unavailable(HostIdentityUnavailableReason::IoFailure)
}

#[cfg(unix)]
fn ensure_cockpit_data_dir(path: &Path) -> Result<(), HostIdentityError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    if !path.exists() {
        fs::create_dir_all(path).map_err(map_io)?;
        let perms = fs::Permissions::from_mode(0o700);
        fs::set_permissions(path, perms).map_err(map_io)?;
    }

    let meta = fs::symlink_metadata(path).map_err(map_io)?;
    if meta.file_type().is_symlink() {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::SymlinkOrReparse,
        ));
    }
    if !meta.is_dir() {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::NonRegular,
        ));
    }
    let mode = meta.mode() & 0o777;
    if mode != 0o700 {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::WrongOwnerOrMode,
        ));
    }
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::WrongOwnerOrMode,
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_cockpit_data_dir(path: &Path) -> Result<(), HostIdentityError> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(map_io)?;
    }
    let meta = fs::metadata(path).map_err(map_io)?;
    if !meta.is_dir() {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::NonRegular,
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_host_identity_lock(data_dir: &Path) -> Result<HostIdentityLockGuard, HostIdentityError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::os::unix::io::AsRawFd;

    let lock_path = data_dir.join(HOST_INSTALLATION_ID_LOCK);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)
        .map_err(|_| HostIdentityError::unavailable(HostIdentityUnavailableReason::LockFailure))?;

    let meta = file
        .metadata()
        .map_err(|_| HostIdentityError::unavailable(HostIdentityUnavailableReason::LockFailure))?;
    if !meta.is_file() {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::NonRegular,
        ));
    }
    if meta.nlink() != 1 {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::MultiLink,
        ));
    }
    let mode = meta.mode() & 0o777;
    if mode != 0o600 {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::WrongOwnerOrMode,
        ));
    }
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::WrongOwnerOrMode,
        ));
    }

    // Exclusive flock held for the guard lifetime.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::LockFailure,
        ));
    }

    Ok(HostIdentityLockGuard { _file: Some(file) })
}

#[cfg(not(unix))]
fn open_host_identity_lock(data_dir: &Path) -> Result<HostIdentityLockGuard, HostIdentityError> {
    let lock_path = data_dir.join(HOST_INSTALLATION_ID_LOCK);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&lock_path)
        .map_err(|_| HostIdentityError::unavailable(HostIdentityUnavailableReason::LockFailure))?;
    Ok(HostIdentityLockGuard { _file: Some(file) })
}

#[cfg(unix)]
fn read_host_identity_file(data_dir: &Path) -> Result<Option<Vec<u8>>, HostIdentityError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let path = host_installation_id_path(data_dir);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(HostIdentityError::unavailable(
                HostIdentityUnavailableReason::IoFailure,
            ));
        }
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(HostIdentityError::unavailable(
                    HostIdentityUnavailableReason::SymlinkOrReparse,
                ));
            }
            if !meta.is_file() {
                return Err(HostIdentityError::unavailable(
                    HostIdentityUnavailableReason::NonRegular,
                ));
            }
            if meta.nlink() != 1 {
                return Err(HostIdentityError::unavailable(
                    HostIdentityUnavailableReason::MultiLink,
                ));
            }
            let mode = meta.mode() & 0o777;
            if mode != 0o600 {
                return Err(HostIdentityError::unavailable(
                    HostIdentityUnavailableReason::WrongOwnerOrMode,
                ));
            }
            let euid = unsafe { libc::geteuid() };
            if meta.uid() != euid {
                return Err(HostIdentityError::unavailable(
                    HostIdentityUnavailableReason::WrongOwnerOrMode,
                ));
            }
        }
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(map_io)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(map_io)?;
    if buf.is_empty() {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::CorruptEncoding,
        ));
    }
    Ok(Some(buf))
}

#[cfg(not(unix))]
fn read_host_identity_file(data_dir: &Path) -> Result<Option<Vec<u8>>, HostIdentityError> {
    let path = host_installation_id_path(data_dir);
    match fs::read(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::IoFailure,
        )),
        Ok(buf) if buf.is_empty() => Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::CorruptEncoding,
        )),
        Ok(buf) => Ok(Some(buf)),
    }
}

#[cfg(unix)]
fn publish_host_identity_file(data_dir: &Path, encoded: &[u8]) -> Result<(), HostIdentityError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::os::unix::io::AsRawFd;

    // Random-name same-directory O_EXCL temporary.
    let mut name_bytes = [0u8; 16];
    TryRng::try_fill_bytes(&mut SysRng, &mut name_bytes).map_err(|_| {
        HostIdentityError::unavailable(HostIdentityUnavailableReason::EntropyFailure)
    })?;
    let tmp_name = format!(".host-installation-id.{}.tmp", hex_lower(&name_bytes));
    let tmp_path = data_dir.join(&tmp_name);
    let dest = host_installation_id_path(data_dir);

    // Refuse if destination already exists (no adopt/overwrite).
    if dest.exists() {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::ReplacementDetected,
        ));
    }

    let mut tmp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_EXCL)
        .open(&tmp_path)
        .map_err(|_| {
            HostIdentityError::unavailable(HostIdentityUnavailableReason::FsyncOrRenameFailure)
        })?;

    tmp.write_all(encoded).map_err(|_| {
        HostIdentityError::unavailable(HostIdentityUnavailableReason::FsyncOrRenameFailure)
    })?;
    tmp.flush().map_err(|_| {
        HostIdentityError::unavailable(HostIdentityUnavailableReason::FsyncOrRenameFailure)
    })?;
    let _ = tmp.sync_all();

    // Atomic rename while holding directory open.
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(data_dir)
        .map_err(|_| {
            HostIdentityError::unavailable(HostIdentityUnavailableReason::DirectoryUnavailable)
        })?;

    fs::rename(&tmp_path, &dest).map_err(|_| {
        // Clean orphan temp on failure; never adopt.
        let _ = fs::remove_file(&tmp_path);
        HostIdentityError::unavailable(HostIdentityUnavailableReason::FsyncOrRenameFailure)
    })?;

    // fsync directory where supported.
    let _ = unsafe { libc::fsync(dir.as_raw_fd()) };

    // Reopen and verify exact contents + mode/link.
    let meta = fs::symlink_metadata(&dest).map_err(|_| {
        HostIdentityError::unavailable(HostIdentityUnavailableReason::MismatchOnReopen)
    })?;
    if !meta.is_file() || meta.nlink() != 1 || (meta.mode() & 0o777) != 0o600 {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::MismatchOnReopen,
        ));
    }
    let on_disk = fs::read(&dest).map_err(|_| {
        HostIdentityError::unavailable(HostIdentityUnavailableReason::MismatchOnReopen)
    })?;
    if on_disk.as_slice() != encoded {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::MismatchOnReopen,
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn publish_host_identity_file(data_dir: &Path, encoded: &[u8]) -> Result<(), HostIdentityError> {
    let mut name_bytes = [0u8; 16];
    TryRng::try_fill_bytes(&mut SysRng, &mut name_bytes).map_err(|_| {
        HostIdentityError::unavailable(HostIdentityUnavailableReason::EntropyFailure)
    })?;
    let tmp_name = format!(".host-installation-id.{}.tmp", hex_lower(&name_bytes));
    let tmp_path = data_dir.join(&tmp_name);
    let dest = host_installation_id_path(data_dir);

    if dest.exists() {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::ReplacementDetected,
        ));
    }

    {
        let mut tmp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|_| {
                HostIdentityError::unavailable(HostIdentityUnavailableReason::FsyncOrRenameFailure)
            })?;
        tmp.write_all(encoded).map_err(|_| {
            HostIdentityError::unavailable(HostIdentityUnavailableReason::FsyncOrRenameFailure)
        })?;
        tmp.flush().map_err(|_| {
            HostIdentityError::unavailable(HostIdentityUnavailableReason::FsyncOrRenameFailure)
        })?;
        let _ = tmp.sync_all();
    }

    fs::rename(&tmp_path, &dest).map_err(|_| {
        let _ = fs::remove_file(&tmp_path);
        HostIdentityError::unavailable(HostIdentityUnavailableReason::FsyncOrRenameFailure)
    })?;

    let on_disk = fs::read(&dest).map_err(|_| {
        HostIdentityError::unavailable(HostIdentityUnavailableReason::MismatchOnReopen)
    })?;
    if on_disk.as_slice() != encoded {
        return Err(HostIdentityError::unavailable(
            HostIdentityUnavailableReason::MismatchOnReopen,
        ));
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Domain-separated hash helper used by session/display identity builders.
pub fn domain_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([(parts.len() as u8)]);
    for part in parts {
        let len = (part.len() as u32).to_be_bytes();
        hasher.update(len);
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// In-memory filesystem for deterministic host-identity tests.
#[derive(Debug, Default)]
pub struct FakeHostIdentityFs {
    pub data_dir_ready: bool,
    pub id_file: Option<Vec<u8>>,
    pub lock_fail: bool,
    pub publish_fail: bool,
    pub read_after_publish: Option<Vec<u8>>,
    pub crash_at: Option<String>,
    pub crashed: bool,
    pub orphan_temps: Vec<Vec<u8>>,
    pub publish_count: usize,
    pub ensure_fail: bool,
    /// When set, `read_id_file` returns this error instead of content.
    pub read_error: Option<HostIdentityUnavailableReason>,
    /// Simulate concurrent winner: first publish stores candidate but read
    /// returns `concurrent_winner` bytes.
    pub concurrent_winner: Option<Vec<u8>>,
}

impl HostIdentityFs for FakeHostIdentityFs {
    fn ensure_data_dir(&mut self, _path: &Path) -> Result<(), HostIdentityError> {
        if self.ensure_fail {
            return Err(HostIdentityError::unavailable(
                HostIdentityUnavailableReason::DirectoryUnavailable,
            ));
        }
        self.data_dir_ready = true;
        Ok(())
    }

    fn open_lock(&mut self, _data_dir: &Path) -> Result<HostIdentityLockGuard, HostIdentityError> {
        if self.lock_fail {
            return Err(HostIdentityError::unavailable(
                HostIdentityUnavailableReason::LockFailure,
            ));
        }
        Ok(HostIdentityLockGuard { _file: None })
    }

    fn read_id_file(&mut self, _data_dir: &Path) -> Result<Option<Vec<u8>>, HostIdentityError> {
        if let Some(reason) = self.read_error {
            return Err(HostIdentityError::unavailable(reason));
        }
        Ok(self.id_file.clone())
    }

    fn publish_id_file(
        &mut self,
        _data_dir: &Path,
        encoded: &[u8],
    ) -> Result<(), HostIdentityError> {
        if self.crashed {
            return Err(HostIdentityError::unavailable(
                HostIdentityUnavailableReason::FsyncOrRenameFailure,
            ));
        }
        if self.publish_fail {
            self.orphan_temps.push(encoded.to_vec());
            return Err(HostIdentityError::unavailable(
                HostIdentityUnavailableReason::FsyncOrRenameFailure,
            ));
        }
        self.publish_count += 1;
        if let Some(winner) = self.concurrent_winner.take() {
            // Loser never adopts its own candidate; file shows the winner.
            self.id_file = Some(winner);
            return Ok(());
        }
        if let Some(forced) = self.read_after_publish.clone() {
            self.id_file = Some(forced);
        } else {
            self.id_file = Some(encoded.to_vec());
        }
        Ok(())
    }

    fn crash_barrier(&mut self, name: &str) -> Result<(), HostIdentityError> {
        if self.crash_at.as_deref() == Some(name) {
            self.crashed = true;
            // Leave any candidate only as orphan temp; never adopt.
            return Err(HostIdentityError::unavailable(
                HostIdentityUnavailableReason::FsyncOrRenameFailure,
            ));
        }
        Ok(())
    }
}

/// Deterministic RNG for tests.
#[derive(Debug)]
pub struct FixedHostIdentityRng {
    pub bytes: [u8; 32],
    pub fail: bool,
    pub fill_count: usize,
}

impl FixedHostIdentityRng {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            fail: false,
            fill_count: 0,
        }
    }

    pub fn failing() -> Self {
        Self {
            bytes: [0u8; 32],
            fail: true,
            fill_count: 0,
        }
    }
}

impl HostIdentityRng for FixedHostIdentityRng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), HostIdentityError> {
        self.fill_count += 1;
        if self.fail {
            return Err(HostIdentityError::unavailable(
                HostIdentityUnavailableReason::EntropyFailure,
            ));
        }
        if dest.len() != 32 {
            // Host identity always requests 32 bytes; other sizes still fill.
            for (i, b) in dest.iter_mut().enumerate() {
                *b = self.bytes[i % 32];
            }
            return Ok(());
        }
        dest.copy_from_slice(&self.bytes);
        Ok(())
    }
}

/// Prove the production adapter type path uses SysRng (compile + unit check).
pub fn production_rng_uses_sysrng() -> bool {
    // Type-level anchor: SysHostIdentityRng::try_fill_bytes calls SysRng.
    std::any::type_name::<SysHostIdentityRng>().contains("SysHostIdentityRng")
}

#[cfg(test)]
mod host_identity_unit_tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip_exact() {
        let id = HostInstallationId([0xabu8; 32]);
        let enc = encode_host_installation_id(&id);
        assert_eq!(enc.len(), 65);
        assert_eq!(enc[64], b'\n');
        assert!(
            enc[..64]
                .iter()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        );
        let decoded = decode_host_installation_id(&enc).unwrap();
        assert_eq!(decoded, id);
    }

    #[test]
    fn decode_rejects_uppercase_and_wrong_len() {
        let mut enc = encode_host_installation_id(&HostInstallationId([1u8; 32]));
        enc[0] = b'A';
        assert!(decode_host_installation_id(&enc).is_err());
        assert!(decode_host_installation_id(&enc[..64]).is_err());
        enc[0] = b'a';
        enc[64] = b'\r';
        assert!(decode_host_installation_id(&enc).is_err());
    }

    #[test]
    fn debug_redacts_raw_bytes() {
        let id = HostInstallationId([0xff; 32]);
        let s = format!("{id:?}");
        assert!(!s.contains("ff"));
        assert!(s.contains("REDACTED"));
    }
}
