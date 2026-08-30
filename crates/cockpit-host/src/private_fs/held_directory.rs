//! Held directory authority for security-sensitive publication.
//!
//! Operational authority is the open directory handle, never the diagnostic
//! path retained for errors.  Callers persist [`DirectoryIdentity`] and must
//! carry this capability through every filesystem effect.

use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use sha2::{Digest as _, Sha256};
#[cfg(unix)]
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryIdentity {
    pub platform: &'static str,
    pub stable_digest: String,
    pub canonical_binding_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldArtifactEvidence {
    pub identity_digest: String,
    pub security_digest: String,
    pub byte_length: u64,
    pub sha256: String,
}
impl HeldArtifactEvidence {
    pub fn identity_digest(&self) -> &str {
        &self.identity_digest
    }
    pub fn security_digest(&self) -> &str {
        &self.security_digest
    }
    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Debug)]
pub struct HeldTemporaryArtifact {
    file: File,
    name: String,
    identity_digest: String,
    security_digest: String,
}

impl HeldTemporaryArtifact {
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn identity_digest(&self) -> &str {
        &self.identity_digest
    }
    pub fn security_digest(&self) -> &str {
        &self.security_digest
    }
}

#[derive(Debug)]
pub struct HeldSealedArtifact {
    file: File,
    name: String,
    evidence: HeldArtifactEvidence,
}

#[derive(Debug)]
pub enum HeldSealOutcome {
    Sealed(HeldSealedArtifact),
    Recoverable {
        artifact: HeldTemporaryArtifact,
        evidence: Option<HeldArtifactEvidence>,
        error: anyhow::Error,
    },
}

impl HeldSealedArtifact {
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
    pub fn evidence(&self) -> &HeldArtifactEvidence {
        &self.evidence
    }
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Debug)]
pub enum HeldDirectoryEffectOutcome {
    AppliedDurable(HeldDirectoryEffectEvidence),
    AppliedUnknown(HeldDirectoryRecovery),
    ProvenNotApplied(HeldSealedArtifact),
    SecurityAmbiguous(HeldDirectoryRecovery),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldDirectoryEffectEvidence {
    destination_name: Option<String>,
    artifact: HeldArtifactEvidence,
}
impl HeldDirectoryEffectEvidence {
    pub fn destination_name(&self) -> Option<&str> {
        self.destination_name.as_deref()
    }
    pub fn artifact(&self) -> &HeldArtifactEvidence {
        &self.artifact
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldDirectoryRecovery {
    destination_name: Option<String>,
    source_name: String,
    artifact: HeldArtifactEvidence,
    source_cleanup_required: bool,
}
impl HeldDirectoryRecovery {
    pub fn destination_name(&self) -> Option<&str> {
        self.destination_name.as_deref()
    }
    pub fn source_name(&self) -> &str {
        &self.source_name
    }
    pub fn artifact(&self) -> &HeldArtifactEvidence {
        &self.artifact
    }
    pub fn source_cleanup_required(&self) -> bool {
        self.source_cleanup_required
    }
}

#[derive(Debug)]
pub struct HeldDirectoryAuthority {
    imp: imp::HeldDirectory,
    identity: DirectoryIdentity,
}

/// Read-only authority for an attached workspace directory.  Unlike
/// [`HeldDirectoryAuthority`], this deliberately does not require a private
/// owner-only directory: a user workspace can be shared with their tools.
/// It still anchors every child lookup in the originally opened directory and
/// refuses symlink/reparse traversal, so a later pathname replacement cannot
/// change what an already-attached session reads.
#[derive(Debug)]
pub struct HeldWorkspaceDirectoryAuthority {
    imp: imp::HeldDirectory,
    identity: String,
}

/// A Windows-only lifetime lease for using a retained workspace as a child
/// process current directory. Windows' `CreateProcess` takes a path rather
/// than an open directory object, so the lease keeps every component from the
/// drive root through the workspace open without `FILE_SHARE_DELETE`.  That
/// makes a rename/delete substitution impossible from the final identity
/// verification until the child has exited.
#[cfg(windows)]
pub(crate) struct WindowsWorkspaceExecutionLease {
    chain: Vec<File>,
    canonical_path: PathBuf,
    expected_identity: String,
}

#[cfg(windows)]
impl WindowsWorkspaceExecutionLease {
    pub(crate) fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    /// Re-open the configured spelling through no-reparse, no-delete handles
    /// and compare the resulting FileId to the attach-time proof. The original
    /// chain remains live during this check and through child completion, so a
    /// successful check cannot be followed by a pathname substitution before
    /// `CreateProcess` consumes `canonical_path`.
    pub(crate) fn revalidate_before_spawn(&self) -> Result<()> {
        self.imp_revalidate()
    }

    fn imp_revalidate(&self) -> Result<()> {
        ensure!(
            !self.chain.is_empty(),
            "Windows workspace execution lease has no directory handle"
        );
        imp::revalidate_workspace_execution_lease(
            &self.chain,
            &self.canonical_path,
            &self.expected_identity,
        )
    }
}

#[cfg(windows)]
impl cockpit_config::config::extended::hooks::HookExecutionLease
    for WindowsWorkspaceExecutionLease
{
}

#[cfg(windows)]
impl cockpit_config::config::extended::hooks::RetainedWindowsHookWorkingDirectory
    for WindowsWorkspaceExecutionLease
{
    fn canonical_path(&self) -> &Path {
        WindowsWorkspaceExecutionLease::canonical_path(self)
    }

    fn revalidate_before_spawn(&self) -> std::result::Result<(), String> {
        WindowsWorkspaceExecutionLease::revalidate_before_spawn(self).map_err(|error| {
            format!("Windows retained hook cwd lease verification failed: {error:#}")
        })
    }
}

/// Exact bytes and executable eligibility read through a held workspace
/// directory. This is intentionally not serializable: it is only the bridge
/// from a no-follow source lookup to a daemon-private hook execution snapshot.
pub struct HeldWorkspaceExecutableFile {
    pub bytes: Vec<u8>,
    #[cfg(unix)]
    pub executable: bool,
}

impl HeldWorkspaceDirectoryAuthority {
    pub fn open_existing(path: &Path) -> Result<Self> {
        let imp = imp::HeldDirectory::open_existing_workspace(path)?;
        let identity = imp.workspace_identity()?;
        Ok(Self { imp, identity })
    }

    /// Stable platform identity only: Unix device/inode or Windows volume
    /// serial/file index.  Mutable metadata is intentionally excluded.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    pub fn read_regular_file_relative(&self, components: &[&str]) -> Result<Vec<u8>> {
        ensure!(
            !components.is_empty(),
            "held workspace read requires a relative file"
        );
        for component in components {
            validate_component(component)?;
        }
        self.imp.read_regular_file(components)
    }

    /// Return the opaque, directory-object-bound lifetime discriminator for a
    /// workspace, creating it if this directory has never had one.  This is
    /// deliberately stored in object metadata rather than a repository entry:
    /// deleting or editing untracked workspace files must not change history
    /// ownership for a still-live directory object.
    ///
    /// Creation is compare-and-create at the metadata layer.  A competing
    /// creator therefore either installs a complete value atomically or reads
    /// the complete value installed by the winner; no caller can observe a
    /// partially-written discriminator.
    pub fn workspace_birth_token(&self) -> Result<Vec<u8>> {
        self.imp.workspace_birth_token()
    }

    /// Open a regular descendant through the retained workspace directory.
    /// The returned descriptor is anchored beneath the held root and never
    /// follows a symlink/reparse component. Callers retain this descriptor;
    /// they must not reopen a diagnostic path spelling.
    pub fn open_regular_file_relative(&self, components: &[&str]) -> Result<File> {
        ensure!(
            !components.is_empty(),
            "held workspace open requires a relative file"
        );
        for component in components {
            validate_component(component)?;
        }
        self.imp.open_regular_file(components)
    }

    /// Return the stable platform identity selected by a metadata-only path
    /// lookup. The lookup never acquires content-read access and refuses a
    /// final symlink/reparse point.
    ///
    /// Callers compare this authorization identity with the no-follow
    /// descriptor returned by [`Self::open_regular_file_relative`]. Mutable
    /// metadata such as size and times is deliberately excluded.
    pub fn regular_file_authorization_identity(path: &Path) -> Result<String> {
        imp::regular_file_authorization_identity(path)
    }

    /// Return the stable platform identity of an already-held regular file.
    pub fn regular_file_identity(file: &File) -> Result<String> {
        imp::regular_file_identity(file)
    }

    /// Read a regular descendant through the retained directory capability,
    /// refusing an oversized file before allocating its full contents.  The
    /// streaming cap also protects against a file that grows after metadata
    /// is read.
    pub fn read_regular_file_relative_bounded(
        &self,
        components: &[&str],
        max_bytes: usize,
    ) -> Result<Vec<u8>> {
        ensure!(
            !components.is_empty(),
            "held workspace read requires a relative file"
        );
        for component in components {
            validate_component(component)?;
        }
        self.imp.read_regular_file_bounded(components, max_bytes)
    }

    /// Windows non-secret file read with the same retained workspace
    /// authority and no-reparse relative opens, while preserving ordinary
    /// repository ACLs. Absence is distinct from a security-ambiguous open.
    #[cfg(windows)]
    pub fn read_regular_file_relative_bounded_optional(
        &self,
        components: &[&str],
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>> {
        ensure!(
            !components.is_empty(),
            "held workspace read requires a relative file"
        );
        for component in components {
            validate_component(component)?;
        }
        self.imp
            .read_regular_file_bounded_optional(components, max_bytes)
    }

    /// Snapshot a bounded descendant directory tree through the retained
    /// workspace handle. Byte, entry-count, and nesting limits bound resource
    /// use. Every component and enumerated entry is opened relative to its
    /// held parent without following symlinks/reparse points.
    pub fn read_directory_tree_relative_bounded(
        &self,
        components: &[&str],
        per_file_limit: usize,
        total_limit: usize,
        max_entries: usize,
        max_depth: usize,
    ) -> Result<Option<std::collections::BTreeMap<String, Vec<u8>>>> {
        for component in components {
            validate_component(component)?;
        }
        ensure!(
            per_file_limit > 0 && total_limit >= per_file_limit && max_entries > 0,
            "held workspace tree limits are invalid"
        );
        self.imp.read_directory_tree(
            components,
            per_file_limit,
            total_limit,
            max_entries,
            max_depth,
        )
    }

    /// Read one executable descendant through the held root. On Unix this also
    /// preserves the source file's execute permission as an authority check so
    /// snapshotting never turns a non-executable workspace file into code.
    pub fn read_regular_executable_file_relative_bounded(
        &self,
        components: &[&str],
        max_bytes: usize,
    ) -> Result<HeldWorkspaceExecutableFile> {
        ensure!(
            !components.is_empty(),
            "held workspace executable read requires a relative file"
        );
        for component in components {
            validate_component(component)?;
        }
        self.imp
            .read_regular_executable_file_bounded(components, max_bytes)
    }

    /// Clone the retained root handle for a lower-layer, capability-neutral
    /// parser.  The caller receives no path authority: all descendant lookup
    /// remains relative to this exact directory object.
    pub fn retained_directory_handle(&self) -> Result<File> {
        self.imp.directory_handle_clone()
    }

    /// Acquire a Windows lease only at hook launch, not while the hook
    /// registry is loaded. That keeps attach and watcher refresh available
    /// when another process temporarily prevents a safe cwd lease, while the
    /// actual launch still fails closed rather than using a mutable path.
    #[cfg(windows)]
    pub(crate) fn acquire_windows_execution_lease(
        &self,
        canonical_path: &Path,
    ) -> Result<WindowsWorkspaceExecutionLease> {
        let chain = self
            .imp
            .open_workspace_execution_lease(canonical_path, &self.identity)?;
        Ok(WindowsWorkspaceExecutionLease {
            chain,
            canonical_path: canonical_path.to_path_buf(),
            expected_identity: self.identity.clone(),
        })
    }
}

impl HeldDirectoryAuthority {
    #[cfg(test)]
    pub fn force_next_directory_sync_failure(&self) {
        FORCE_DIRECTORY_SYNC_FAILURE.set(true);
    }
    pub fn open_existing(path: &Path) -> Result<Self> {
        let imp = imp::HeldDirectory::open_existing(path)?;
        let identity = imp.identity()?;
        Ok(Self { imp, identity })
    }

    pub fn identity(&self) -> &DirectoryIdentity {
        &self.identity
    }

    /// A diagnostic spelling only. It is never filesystem authority.
    pub fn diagnostic_path(&self) -> &Path {
        self.imp.diagnostic_path()
    }

    pub fn create_file_exclusive(&self, name: &str) -> Result<HeldTemporaryArtifact> {
        validate_component(name)?;
        let (file, identity_digest, security_digest) = self.imp.create_file_exclusive(name)?;
        Ok(HeldTemporaryArtifact {
            file,
            name: name.to_owned(),
            identity_digest,
            security_digest,
        })
    }

    pub fn seal(&self, artifact: HeldTemporaryArtifact) -> Result<HeldSealedArtifact> {
        match self.seal_recoverable(artifact) {
            HeldSealOutcome::Sealed(sealed) => Ok(sealed),
            HeldSealOutcome::Recoverable { error, .. } => Err(error),
        }
    }

    pub fn seal_recoverable(&self, mut artifact: HeldTemporaryArtifact) -> HeldSealOutcome {
        let result = (|| -> Result<HeldArtifactEvidence> {
            self.imp.revalidate_named(
                &artifact.name,
                &artifact.file,
                &artifact.identity_digest,
                &artifact.security_digest,
            )?;
            artifact.file.flush()?;
            artifact.file.sync_all()?;
            // Test-only one-shot cut: seal must return Recoverable and retain the
            // held temporary authority instead of dropping it on durability loss.
            if sync_failure_forced() {
                anyhow::bail!("directory sync failed while sealing held temporary");
            }
            artifact.file.seek(SeekFrom::Start(0))?;
            let mut hash = Sha256::new();
            let mut length = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let count = artifact.file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                length = length
                    .checked_add(count as u64)
                    .context("artifact length overflow")?;
                hash.update(&buffer[..count]);
            }
            self.imp.revalidate_named(
                &artifact.name,
                &artifact.file,
                &artifact.identity_digest,
                &artifact.security_digest,
            )?;
            Ok(HeldArtifactEvidence {
                identity_digest: artifact.identity_digest.clone(),
                security_digest: artifact.security_digest.clone(),
                byte_length: length,
                sha256: super::hex_lower(&hash.finalize()),
            })
        })();
        match result {
            Ok(evidence) => HeldSealOutcome::Sealed(HeldSealedArtifact {
                file: artifact.file,
                name: artifact.name,
                evidence,
            }),
            Err(error) => HeldSealOutcome::Recoverable {
                artifact,
                evidence: None,
                error,
            },
        }
    }

    pub fn rename_noreplace(
        &self,
        mut artifact: HeldSealedArtifact,
        to: &str,
    ) -> Result<HeldDirectoryEffectOutcome> {
        validate_component(to)?;
        if self
            .imp
            .revalidate_named(
                &artifact.name,
                &artifact.file,
                &artifact.evidence.identity_digest,
                &artifact.evidence.security_digest,
            )
            .is_err()
            || validate_contents(&mut artifact.file, &artifact.evidence).is_err()
        {
            return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                HeldDirectoryRecovery {
                    destination_name: Some(to.to_owned()),
                    source_name: artifact.name,
                    artifact: artifact.evidence,
                    source_cleanup_required: false,
                },
            ));
        }
        self.imp.rename_noreplace(artifact, to)
    }

    pub fn unlink(&self, mut artifact: HeldSealedArtifact) -> Result<HeldDirectoryEffectOutcome> {
        if self
            .imp
            .revalidate_named(
                &artifact.name,
                &artifact.file,
                &artifact.evidence.identity_digest,
                &artifact.evidence.security_digest,
            )
            .is_err()
            || validate_contents(&mut artifact.file, &artifact.evidence).is_err()
        {
            return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                HeldDirectoryRecovery {
                    destination_name: None,
                    source_name: artifact.name,
                    artifact: artifact.evidence,
                    source_cleanup_required: false,
                },
            ));
        }
        self.imp.unlink(artifact)
    }

    pub fn open_verified(
        &self,
        name: &str,
        evidence: &HeldArtifactEvidence,
    ) -> Result<HeldSealedArtifact> {
        validate_component(name)?;
        self.imp.open_verified(name, evidence)
    }

    pub fn reconcile(
        &self,
        recovery: &HeldDirectoryRecovery,
    ) -> Result<HeldDirectoryEffectOutcome> {
        self.imp.reconcile(recovery)
    }

    pub fn delete_recovered_destination(
        &self,
        recovery: &HeldDirectoryRecovery,
    ) -> Result<HeldDirectoryEffectOutcome> {
        self.imp.delete_recovered_destination(recovery)
    }
}

fn validate_contents(file: &mut File, evidence: &HeldArtifactEvidence) -> Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(count as u64)
            .context("artifact length overflow")?;
        hash.update(&buffer[..count]);
    }
    ensure!(
        length == evidence.byte_length && super::hex_lower(&hash.finalize()) == evidence.sha256,
        "held artifact length/checksum changed"
    );
    Ok(())
}

fn durable_evidence(
    destination_name: Option<String>,
    artifact: HeldArtifactEvidence,
) -> HeldDirectoryEffectOutcome {
    HeldDirectoryEffectOutcome::AppliedDurable(HeldDirectoryEffectEvidence {
        destination_name,
        artifact,
    })
}

fn unknown_recovery(
    destination_name: Option<String>,
    source_name: String,
    artifact: HeldArtifactEvidence,
    source_cleanup_required: bool,
) -> HeldDirectoryEffectOutcome {
    HeldDirectoryEffectOutcome::AppliedUnknown(HeldDirectoryRecovery {
        destination_name,
        source_name,
        artifact,
        source_cleanup_required,
    })
}

#[cfg(test)]
thread_local! { static FORCE_DIRECTORY_SYNC_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
thread_local! { static BEFORE_PUBLISH_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) }; }
#[cfg(test)]
thread_local! { static AFTER_PUBLISH_EFFECT_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) }; }
#[cfg(test)]
thread_local! { static FORCE_PUBLISH_NONCOLLISION_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
thread_local! { static FORCE_SOURCE_CLEANUP_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
thread_local! { static FORCE_POST_CLEANUP_METADATA_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
fn sync_failure_forced() -> bool {
    FORCE_DIRECTORY_SYNC_FAILURE.replace(false)
}
#[cfg(not(test))]
fn sync_failure_forced() -> bool {
    false
}
#[cfg(test)]
fn run_before_publish_hook() {
    if let Some(hook) = BEFORE_PUBLISH_HOOK.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}
#[cfg(all(not(test), target_os = "linux"))]
fn run_before_publish_hook() {}
#[cfg(test)]
fn run_after_publish_effect_hook() {
    if let Some(hook) = AFTER_PUBLISH_EFFECT_HOOK.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}
#[cfg(all(not(test), any(target_os = "linux", windows)))]
fn run_after_publish_effect_hook() {}
#[cfg(test)]
fn take_forced_failure(flag: &'static std::thread::LocalKey<std::cell::Cell<bool>>) -> bool {
    flag.with(|value| value.replace(false))
}
#[cfg(all(not(test), any(target_os = "linux", windows)))]
fn take_forced_publish_failure() -> bool {
    false
}
#[cfg(test)]
fn take_forced_publish_failure() -> bool {
    take_forced_failure(&FORCE_PUBLISH_NONCOLLISION_FAILURE)
}
#[cfg(all(not(test), any(target_os = "linux", windows)))]
fn take_forced_cleanup_failure() -> bool {
    false
}
#[cfg(test)]
fn take_forced_cleanup_failure() -> bool {
    take_forced_failure(&FORCE_SOURCE_CLEANUP_FAILURE)
}
#[cfg(all(not(test), unix))]
fn take_forced_metadata_failure() -> bool {
    false
}
#[cfg(test)]
fn take_forced_metadata_failure() -> bool {
    take_forced_failure(&FORCE_POST_CLEANUP_METADATA_FAILURE)
}

fn validate_component(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value != "." && value != ".." && !value.contains(['/', '\\', '\0']),
        "unsafe held-directory entry name"
    );
    Ok(())
}

fn digest(parts: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    super::hex_lower(&hash.finalize())
}

#[cfg(unix)]
mod imp {
    use std::ffi::{CString, OsStr};
    use std::io::{Read as _, Write as _};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;

    use super::*;
    use crate::private_fs::held_fd;

    #[cfg(target_os = "macos")]
    unsafe extern "C" {
        #[link_name = "fgetxattr"]
        fn macos_fgetxattr(
            fd: std::os::fd::RawFd,
            name: *const libc::c_char,
            value: *mut libc::c_void,
            size: libc::size_t,
            position: u32,
            options: i32,
        ) -> libc::ssize_t;
        #[link_name = "fsetxattr"]
        fn macos_fsetxattr(
            fd: std::os::fd::RawFd,
            name: *const libc::c_char,
            value: *const libc::c_void,
            size: libc::size_t,
            position: u32,
            options: i32,
        ) -> i32;
    }

    unsafe fn get_workspace_birth_token_xattr(
        fd: std::os::fd::RawFd,
        name: *const libc::c_char,
        value: *mut libc::c_void,
        size: libc::size_t,
    ) -> libc::ssize_t {
        #[cfg(target_os = "macos")]
        {
            unsafe { macos_fgetxattr(fd, name, value, size, 0, 0) }
        }
        #[cfg(not(target_os = "macos"))]
        {
            unsafe { libc::fgetxattr(fd, name, value, size) }
        }
    }

    unsafe fn set_workspace_birth_token_xattr_if_absent(
        fd: std::os::fd::RawFd,
        name: *const libc::c_char,
        value: *const libc::c_void,
        size: libc::size_t,
    ) -> i32 {
        #[cfg(target_os = "macos")]
        {
            unsafe { macos_fsetxattr(fd, name, value, size, 0, 1) }
        }
        #[cfg(not(target_os = "macos"))]
        {
            unsafe { libc::fsetxattr(fd, name, value, size, libc::XATTR_CREATE) }
        }
    }

    fn workspace_birth_token_missing(error: &std::io::Error) -> bool {
        #[cfg(target_os = "macos")]
        {
            error.raw_os_error() == Some(libc::ENOATTR)
        }
        #[cfg(not(target_os = "macos"))]
        {
            error.raw_os_error() == Some(libc::ENODATA)
        }
    }

    pub(super) fn regular_file_authorization_identity(path: &Path) -> Result<String> {
        let metadata = std::fs::symlink_metadata(path)?;
        ensure!(
            metadata.file_type().is_file(),
            "workspace source authorization did not select a regular file"
        );
        Ok(digest(&[
            b"held-workspace-file-unix-v1",
            &metadata.dev().to_be_bytes(),
            &metadata.ino().to_be_bytes(),
        ]))
    }

    pub(super) fn regular_file_identity(file: &File) -> Result<String> {
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file(),
            "held workspace source is not a regular file"
        );
        Ok(digest(&[
            b"held-workspace-file-unix-v1",
            &metadata.dev().to_be_bytes(),
            &metadata.ino().to_be_bytes(),
        ]))
    }

    #[derive(Debug)]
    pub(super) struct HeldDirectory {
        dir: File,
        diagnostic_path: PathBuf,
    }

    impl HeldDirectory {
        #[cfg(test)]
        pub(super) fn test_dir(&self) -> &File {
            &self.dir
        }
        pub(super) fn open_existing(path: &Path) -> Result<Self> {
            Self::open_existing_with_policy(path, true)
        }

        pub(super) fn open_existing_workspace(path: &Path) -> Result<Self> {
            Self::open_existing_with_policy(path, false)
        }

        fn open_existing_with_policy(path: &Path, require_private: bool) -> Result<Self> {
            ensure!(path.is_absolute(), "held directory path must be absolute");
            let mut names = Vec::new();
            for component in path.components() {
                match component {
                    Component::RootDir => {}
                    Component::Normal(name) => names.push(name.as_bytes().to_vec()),
                    _ => anyhow::bail!("held directory path is not canonical lexical input"),
                }
            }
            let mut dir = open_absolute_root()?;
            let mut walked = PathBuf::from("/");
            for bytes in &names {
                let name = CString::new(bytes.as_slice()).context("directory component has NUL")?;
                dir = held_fd::openat(
                    dir.as_raw_fd(),
                    &name,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
                .with_context(|| {
                    format!(
                        "opening held directory component {:?}",
                        OsStr::from_bytes(bytes)
                    )
                })?;
                walked.push(OsStr::from_bytes(bytes));
            }
            let metadata = dir.metadata()?;
            ensure!(metadata.is_dir(), "held authority is not a directory");
            if require_private {
                ensure!(
                    metadata.uid() == unsafe { libc::geteuid() },
                    "held directory owner differs from daemon user"
                );
                ensure!(
                    metadata.mode() & 0o777 == 0o700,
                    "held directory must have mode 0700"
                );
            }
            Ok(Self {
                dir,
                diagnostic_path: walked,
            })
        }

        pub(super) fn identity(&self) -> Result<DirectoryIdentity> {
            let metadata = self.dir.metadata()?;
            let dev = metadata.dev().to_be_bytes();
            let ino = metadata.ino().to_be_bytes();
            let uid = metadata.uid().to_be_bytes();
            let mode = (metadata.mode() & 0o7777).to_be_bytes();
            let stable_digest = digest(&[b"held-directory-unix-v1", &dev, &ino, &uid, &mode]);
            let canonical_binding_digest =
                digest(&[b"held-directory-binding-unix-v1", stable_digest.as_bytes()]);
            Ok(DirectoryIdentity {
                platform: "unix-v1",
                stable_digest,
                canonical_binding_digest,
            })
        }

        pub(super) fn workspace_identity(&self) -> Result<String> {
            let metadata = self.dir.metadata()?;
            Ok(digest(&[
                b"attached-workspace-unix-v1",
                &metadata.dev().to_be_bytes(),
                &metadata.ino().to_be_bytes(),
            ]))
        }

        pub(super) fn directory_handle_clone(&self) -> Result<File> {
            Ok(self.dir.try_clone()?)
        }

        pub(super) fn workspace_birth_token(&self) -> Result<Vec<u8>> {
            const ATTRIBUTE: &[u8] = b"user.cockpit.workspace-birth-token\0";
            const MAX_BYTES: usize = 64;

            fn read(fd: std::os::fd::RawFd) -> std::io::Result<Option<Vec<u8>>> {
                let name = ATTRIBUTE.as_ptr().cast();
                let size =
                    unsafe { get_workspace_birth_token_xattr(fd, name, std::ptr::null_mut(), 0) };
                if size < 0 {
                    let error = std::io::Error::last_os_error();
                    return if workspace_birth_token_missing(&error) {
                        Ok(None)
                    } else {
                        Err(error)
                    };
                }
                let size = usize::try_from(size).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "xattr size overflow")
                })?;
                if size == 0 || size > MAX_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "workspace birth-token xattr has an invalid length",
                    ));
                }
                let mut token = vec![0_u8; size];
                let read = unsafe {
                    get_workspace_birth_token_xattr(
                        fd,
                        name,
                        token.as_mut_ptr().cast(),
                        token.len(),
                    )
                };
                if read < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let read = usize::try_from(read).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "xattr read overflow")
                })?;
                if read != token.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "workspace birth-token xattr changed while reading",
                    ));
                }
                Ok(Some(token))
            }

            match read(self.dir.as_raw_fd()).context("reading workspace birth-token xattr")? {
                Some(token) => Ok(token),
                None => {
                    let generated = Uuid::new_v4().to_string();
                    let status = unsafe {
                        set_workspace_birth_token_xattr_if_absent(
                            self.dir.as_raw_fd(),
                            ATTRIBUTE.as_ptr().cast(),
                            generated.as_ptr().cast(),
                            generated.len(),
                        )
                    };
                    if status == 0 {
                        return Ok(generated.into_bytes());
                    }
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EEXIST) {
                        return read(self.dir.as_raw_fd())
                            .context("reading concurrently-created workspace birth-token xattr")?
                            .context("concurrent workspace birth-token xattr disappeared");
                    }
                    Err(error).context("creating workspace birth-token xattr")
                }
            }
        }

        pub(super) fn read_regular_file(&self, components: &[&str]) -> Result<Vec<u8>> {
            let (leaf, parents) = components
                .split_last()
                .context("held workspace read requires a leaf")?;
            let mut parent = self.dir.try_clone()?;
            for component in parents {
                let name = CString::new(*component).context("workspace component has NUL")?;
                parent = held_fd::openat(
                    parent.as_raw_fd(),
                    &name,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
                .context("opening held workspace directory component")?;
                ensure!(
                    parent.metadata()?.is_dir(),
                    "held workspace component is not a directory"
                );
            }
            let leaf = CString::new(*leaf).context("workspace leaf has NUL")?;
            let mut file = held_fd::openat(
                parent.as_raw_fd(),
                &leaf,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
            .context("opening held workspace definition")?;
            ensure!(
                file.metadata()?.is_file(),
                "held workspace definition is not a regular file"
            );
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .context("reading held workspace definition")?;
            Ok(bytes)
        }

        pub(super) fn open_regular_file(&self, components: &[&str]) -> Result<File> {
            let (leaf, parents) = components
                .split_last()
                .context("held workspace open requires a leaf")?;
            let mut parent = self.dir.try_clone()?;
            for component in parents {
                let name = CString::new(*component).context("workspace component has NUL")?;
                parent = held_fd::openat(
                    parent.as_raw_fd(),
                    &name,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
                .context("opening held workspace directory component")?;
                ensure!(
                    parent.metadata()?.is_dir(),
                    "held workspace component is not a directory"
                );
            }
            let leaf = CString::new(*leaf).context("workspace leaf has NUL")?;
            let file = held_fd::openat(
                parent.as_raw_fd(),
                &leaf,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
            .context("opening held workspace regular file")?;
            ensure!(
                file.metadata()?.is_file(),
                "held workspace source is not a regular file"
            );
            Ok(file)
        }

        pub(super) fn read_regular_file_bounded(
            &self,
            components: &[&str],
            max_bytes: usize,
        ) -> Result<Vec<u8>> {
            let (leaf, parents) = components
                .split_last()
                .context("held workspace read requires a leaf")?;
            let mut parent = self.dir.try_clone()?;
            for component in parents {
                let name = CString::new(*component).context("workspace component has NUL")?;
                parent = held_fd::openat(
                    parent.as_raw_fd(),
                    &name,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
                .context("opening held workspace directory component")?;
                ensure!(
                    parent.metadata()?.is_dir(),
                    "held workspace component is not a directory"
                );
            }
            let leaf = CString::new(*leaf).context("workspace leaf has NUL")?;
            let mut file = held_fd::openat(
                parent.as_raw_fd(),
                &leaf,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
            .context("opening held workspace definition")?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_file() && metadata.len() <= max_bytes as u64,
                "held workspace definition is not a bounded regular file"
            );
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            file.take(max_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .context("reading held workspace definition")?;
            ensure!(
                bytes.len() <= max_bytes,
                "held workspace definition exceeds the byte limit"
            );
            Ok(bytes)
        }

        pub(super) fn read_directory_tree(
            &self,
            components: &[&str],
            per_file_limit: usize,
            total_limit: usize,
            max_entries: usize,
            max_depth: usize,
        ) -> Result<Option<std::collections::BTreeMap<String, Vec<u8>>>> {
            let mut root = self.dir.try_clone()?;
            for component in components {
                let name = CString::new(*component).context("workspace component has NUL")?;
                root = match held_fd::openat(
                    root.as_raw_fd(),
                    &name,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
                .context("opening held workspace package component")
                {
                    Ok(root) => root,
                    Err(error) if is_exact_not_found(&error) => return Ok(None),
                    Err(error) => return Err(error),
                };
                ensure!(
                    root.metadata()?.is_dir(),
                    "held package component is not a directory"
                );
            }
            let mut files = std::collections::BTreeMap::new();
            let mut total = 0usize;
            let mut entries = 0usize;
            read_tree_from_directory(
                &root,
                "",
                0,
                per_file_limit,
                total_limit,
                max_entries,
                max_depth,
                &mut total,
                &mut entries,
                &mut files,
            )?;
            Ok(Some(files))
        }

        pub(super) fn read_regular_executable_file_bounded(
            &self,
            components: &[&str],
            max_bytes: usize,
        ) -> Result<HeldWorkspaceExecutableFile> {
            let (leaf, parents) = components
                .split_last()
                .context("held workspace executable read requires a leaf")?;
            let mut parent = self.dir.try_clone()?;
            for component in parents {
                let name = CString::new(*component).context("workspace component has NUL")?;
                parent = held_fd::openat(
                    parent.as_raw_fd(),
                    &name,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
                .context("opening held workspace executable directory component")?;
                ensure!(
                    parent.metadata()?.is_dir(),
                    "held workspace executable component is not a directory"
                );
            }
            let leaf = CString::new(*leaf).context("workspace executable leaf has NUL")?;
            let mut file = held_fd::openat(
                parent.as_raw_fd(),
                &leaf,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
            .context("opening held workspace executable")?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_file() && metadata.len() <= max_bytes as u64,
                "held workspace executable is not a bounded regular file"
            );
            let executable = metadata.mode() & 0o111 != 0;
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            file.take(max_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .context("reading held workspace executable")?;
            ensure!(
                bytes.len() <= max_bytes,
                "held workspace executable exceeds the byte limit"
            );
            Ok(HeldWorkspaceExecutableFile { bytes, executable })
        }

        pub(super) fn diagnostic_path(&self) -> &Path {
            &self.diagnostic_path
        }

        fn verify_directory_security(&self) -> Result<()> {
            let metadata = self.dir.metadata()?;
            ensure!(metadata.is_dir(), "held authority is no longer a directory");
            ensure!(
                metadata.uid() == unsafe { libc::geteuid() },
                "held directory owner changed"
            );
            ensure!(
                metadata.mode() & 0o777 == 0o700,
                "held directory mode changed"
            );
            Ok(())
        }

        pub(super) fn create_file_exclusive(&self, name: &str) -> Result<(File, String, String)> {
            self.verify_directory_security()?;
            let name = CString::new(name)?;
            let file = held_fd::openat_mode(
                self.dir.as_raw_fd(),
                &name,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
            .context("exclusive held-directory create")?;
            held_fd::fchmod(file.as_raw_fd(), 0o600).context("fchmod 0600 failed")?;
            let (identity, security) = file_evidence(&file)?;
            Ok((file, identity, security))
        }

        pub(super) fn revalidate_named(
            &self,
            name: &str,
            held: &File,
            identity: &str,
            security: &str,
        ) -> Result<()> {
            self.verify_directory_security()?;
            let reopened = open_named(&self.dir, name)?;
            let (held_identity, held_security) = file_evidence(held)?;
            let (named_identity, named_security) = file_evidence(&reopened)?;
            ensure!(
                held_identity == identity
                    && held_security == security
                    && named_identity == identity
                    && named_security == security,
                "held artifact name or security identity changed"
            );
            Ok(())
        }

        pub(super) fn rename_noreplace(
            &self,
            artifact: HeldSealedArtifact,
            to: &str,
        ) -> Result<HeldDirectoryEffectOutcome> {
            self.verify_directory_security()?;
            #[cfg(target_os = "linux")]
            {
                let mut artifact = artifact;
                run_before_publish_hook();
                let target = CString::new(to)?;
                let proc_source =
                    CString::new(format!("/proc/self/fd/{}", artifact.file.as_raw_fd()))?;
                ensure!(
                    std::path::Path::new(proc_source.to_str()?).exists(),
                    "fd-bound procfs publication is unavailable"
                );
                if take_forced_publish_failure() {
                    return Ok(unknown_recovery(
                        Some(to.to_owned()),
                        artifact.name,
                        artifact.evidence,
                        true,
                    ));
                }
                if let Err(error) = held_fd::linkat(
                    libc::AT_FDCWD,
                    &proc_source,
                    self.dir.as_raw_fd(),
                    &target,
                    libc::AT_SYMLINK_FOLLOW,
                ) {
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        return Ok(HeldDirectoryEffectOutcome::ProvenNotApplied(artifact));
                    }
                    return Ok(unknown_recovery(
                        Some(to.to_owned()),
                        artifact.name,
                        artifact.evidence,
                        true,
                    ));
                }
                let source = match CString::new(artifact.name.as_str()) {
                    Ok(value) => value,
                    Err(_) => {
                        return Ok(unknown_recovery(
                            Some(to.to_owned()),
                            artifact.name.clone(),
                            artifact.evidence.clone(),
                            true,
                        ));
                    }
                };
                if take_forced_cleanup_failure()
                    || held_fd::unlinkat(self.dir.as_raw_fd(), &source, 0).is_err()
                {
                    return Ok(unknown_recovery(
                        Some(to.to_owned()),
                        artifact.name.clone(),
                        artifact.evidence.clone(),
                        true,
                    ));
                }
                run_after_publish_effect_hook();
                if verify_published(self, to, &mut artifact).is_err() {
                    return Ok(unknown_recovery(
                        Some(to.to_owned()),
                        artifact.name.clone(),
                        artifact.evidence.clone(),
                        true,
                    ));
                }
                if sync_failure_forced() || self.dir.sync_all().is_err() {
                    return Ok(unknown_recovery(
                        Some(to.to_owned()),
                        artifact.name,
                        artifact.evidence,
                        false,
                    ));
                }
                Ok(durable_evidence(Some(to.to_owned()), artifact.evidence))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (artifact, to);
                anyhow::bail!(
                    "fd-bound no-replace publication is unsupported on this Unix platform"
                )
            }
        }

        pub(super) fn unlink(
            &self,
            artifact: HeldSealedArtifact,
        ) -> Result<HeldDirectoryEffectOutcome> {
            self.verify_directory_security()?;
            let name = CString::new(artifact.name.as_str())?;
            if held_fd::unlinkat(self.dir.as_raw_fd(), &name, 0).is_err() {
                if let Ok(mut source) = open_named(&self.dir, name.to_str()?)
                    && verify_expected_file(&source, &artifact.evidence, true).is_ok()
                    && validate_contents(&mut source, &artifact.evidence).is_ok()
                {
                    return Ok(HeldDirectoryEffectOutcome::ProvenNotApplied(artifact));
                }
                return Ok(unknown_recovery(
                    None,
                    artifact.name,
                    artifact.evidence,
                    true,
                ));
            }
            let Ok(metadata) = artifact.file.metadata() else {
                return Ok(unknown_recovery(
                    None,
                    artifact.name,
                    artifact.evidence,
                    true,
                ));
            };
            if metadata.nlink() != 0 {
                return Ok(unknown_recovery(
                    None,
                    artifact.name,
                    artifact.evidence,
                    true,
                ));
            }
            if self.verify_directory_security().is_err()
                || sync_failure_forced()
                || self.dir.sync_all().is_err()
            {
                return Ok(unknown_recovery(
                    None,
                    artifact.name,
                    artifact.evidence,
                    false,
                ));
            }
            Ok(durable_evidence(None, artifact.evidence))
        }

        pub(super) fn open_verified(
            &self,
            name: &str,
            evidence: &HeldArtifactEvidence,
        ) -> Result<HeldSealedArtifact> {
            self.verify_directory_security()?;
            let mut file = open_named(&self.dir, name)?;
            verify_expected_file(&file, evidence, true)?;
            validate_contents(&mut file, evidence)?;
            file.rewind()?;
            Ok(HeldSealedArtifact {
                file,
                name: name.to_owned(),
                evidence: evidence.clone(),
            })
        }

        pub(super) fn reconcile(
            &self,
            recovery: &HeldDirectoryRecovery,
        ) -> Result<HeldDirectoryEffectOutcome> {
            self.verify_directory_security()?;
            if let Some(destination) = &recovery.destination_name {
                let absent = match entry_absent(&self.dir, destination) {
                    Ok(absent) => absent,
                    Err(_) => {
                        return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                            recovery.clone(),
                        ));
                    }
                };
                if absent {
                    let Ok(mut source) = open_named(&self.dir, &recovery.source_name) else {
                        return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                            recovery.clone(),
                        ));
                    };
                    if verify_expected_file(&source, &recovery.artifact, true).is_err()
                        || validate_contents(&mut source, &recovery.artifact).is_err()
                    {
                        return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                            recovery.clone(),
                        ));
                    }
                    return Ok(HeldDirectoryEffectOutcome::ProvenNotApplied(
                        HeldSealedArtifact {
                            file: source,
                            name: recovery.source_name.clone(),
                            evidence: recovery.artifact.clone(),
                        },
                    ));
                }
                let mut destination_file = match open_named(&self.dir, destination) {
                    Ok(file) => file,
                    Err(_) => {
                        return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                            recovery.clone(),
                        ));
                    }
                };
                if verify_expected_file(&destination_file, &recovery.artifact, false).is_err()
                    || validate_contents(&mut destination_file, &recovery.artifact).is_err()
                {
                    return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                        recovery.clone(),
                    ));
                }
                if recovery.source_cleanup_required {
                    match open_named(&self.dir, &recovery.source_name) {
                        Ok(mut source) => {
                            if verify_expected_file(&source, &recovery.artifact, false).is_err()
                                || validate_contents(&mut source, &recovery.artifact).is_err()
                            {
                                return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                                    recovery.clone(),
                                ));
                            }
                            let name = match CString::new(recovery.source_name.as_str()) {
                                Ok(name) => name,
                                Err(_) => {
                                    return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                                        recovery.clone(),
                                    ));
                                }
                            };
                            if held_fd::unlinkat(self.dir.as_raw_fd(), &name, 0).is_err() {
                                return Ok(HeldDirectoryEffectOutcome::AppliedUnknown(
                                    recovery.clone(),
                                ));
                            }
                        }
                        Err(error) if is_exact_not_found(&error) => {}
                        Err(_) => {
                            return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                                recovery.clone(),
                            ));
                        }
                    }
                }
                if take_forced_metadata_failure() {
                    return Ok(HeldDirectoryEffectOutcome::AppliedUnknown(recovery.clone()));
                }
                let Ok(destination_metadata) = destination_file.metadata() else {
                    return Ok(HeldDirectoryEffectOutcome::AppliedUnknown(recovery.clone()));
                };
                if destination_metadata.nlink() != 1 {
                    return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                        recovery.clone(),
                    ));
                }
            } else {
                match open_named(&self.dir, &recovery.source_name) {
                    Ok(mut source) => {
                        if verify_expected_file(&source, &recovery.artifact, false).is_err()
                            || validate_contents(&mut source, &recovery.artifact).is_err()
                        {
                            return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                                recovery.clone(),
                            ));
                        }
                        return Ok(HeldDirectoryEffectOutcome::ProvenNotApplied(
                            HeldSealedArtifact {
                                file: source,
                                name: recovery.source_name.clone(),
                                evidence: recovery.artifact.clone(),
                            },
                        ));
                    }
                    Err(error) if is_exact_not_found(&error) => {}
                    Err(_) => {
                        return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                            recovery.clone(),
                        ));
                    }
                }
            }
            if sync_failure_forced() || self.dir.sync_all().is_err() {
                return Ok(HeldDirectoryEffectOutcome::AppliedUnknown(recovery.clone()));
            }
            Ok(durable_evidence(
                recovery.destination_name.clone(),
                recovery.artifact.clone(),
            ))
        }

        pub(super) fn delete_recovered_destination(
            &self,
            recovery: &HeldDirectoryRecovery,
        ) -> Result<HeldDirectoryEffectOutcome> {
            let Some(destination) = &recovery.destination_name else {
                anyhow::bail!("recovery has no destination")
            };
            let mut file = open_named(&self.dir, destination)?;
            verify_expected_file(&file, &recovery.artifact, true)?;
            validate_contents(&mut file, &recovery.artifact)?;
            let sealed = HeldSealedArtifact {
                file,
                name: destination.clone(),
                evidence: recovery.artifact.clone(),
            };
            self.unlink(sealed)
        }
    }

    #[cfg(target_os = "linux")]
    fn verify_published(
        dir: &HeldDirectory,
        name: &str,
        artifact: &mut HeldSealedArtifact,
    ) -> Result<()> {
        dir.verify_directory_security()?;
        ensure!(
            artifact.file.metadata()?.nlink() == 1,
            "published source cleanup is incomplete"
        );
        let mut published = open_named(&dir.dir, name)?;
        verify_expected_file(&published, &artifact.evidence, true)?;
        validate_contents(&mut artifact.file, &artifact.evidence)?;
        validate_contents(&mut published, &artifact.evidence)
    }

    fn verify_expected_file(
        file: &File,
        evidence: &HeldArtifactEvidence,
        require_single_link: bool,
    ) -> Result<()> {
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && (!require_single_link || metadata.nlink() == 1)
                && metadata.mode() & 0o777 == 0o600,
            "recovered artifact security differs"
        );
        let identity = digest(&[
            b"held-artifact-unix-v1",
            &metadata.dev().to_be_bytes(),
            &metadata.ino().to_be_bytes(),
        ]);
        ensure!(
            identity == evidence.identity_digest,
            "recovered artifact identity differs"
        );
        Ok(())
    }

    pub(super) fn open_named(dir: &File, name: &str) -> Result<File> {
        let name = CString::new(name)?;
        held_fd::openat(
            dir.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
        .context("reopening held artifact")
    }

    pub(super) fn entry_absent(dir: &File, name: &str) -> Result<bool> {
        let name = CString::new(name)?;
        match held_fd::fstatat_nofollow(dir.as_raw_fd(), &name) {
            Ok(_) => Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error).context("checking held-directory entry absence"),
        }
    }

    fn is_exact_not_found(error: &anyhow::Error) -> bool {
        error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>())
            .is_some_and(|value| value.kind() == std::io::ErrorKind::NotFound)
    }

    fn read_tree_from_directory(
        directory: &File,
        relative: &str,
        depth: usize,
        per_file_limit: usize,
        total_limit: usize,
        max_entries: usize,
        max_depth: usize,
        total: &mut usize,
        entries: &mut usize,
        files: &mut std::collections::BTreeMap<String, Vec<u8>>,
    ) -> Result<()> {
        use std::ffi::CStr;
        use std::os::fd::FromRawFd as _;

        let duplicate = unsafe { libc::dup(directory.as_raw_fd()) };
        ensure!(
            duplicate >= 0,
            "duplicating held package directory failed: {}",
            std::io::Error::last_os_error()
        );
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe { libc::close(duplicate) };
            anyhow::bail!("opening held package directory stream failed: {error}");
        }
        let result = (|| {
            loop {
                set_readdir_errno_zero();
                let entry = unsafe { libc::readdir(stream) };
                if entry.is_null() {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(0) {
                        break;
                    }
                    return Err(error).context("enumerating held package directory");
                }
                let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                *entries = entries
                    .checked_add(1)
                    .context("held package entry count overflow")?;
                ensure!(
                    *entries <= max_entries,
                    "held package exceeds its entry count limit"
                );
                ensure!(
                    !bytes.contains(&b'\\'),
                    "held package entry contains a cross-platform separator"
                );
                let name = std::str::from_utf8(bytes).context("held package entry is not UTF-8")?;
                validate_component(name)?;
                let cname = CString::new(bytes).context("held package entry has NUL")?;
                let raw = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        cname.as_ptr(),
                        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                ensure!(
                    raw >= 0,
                    "opening held package entry failed: {}",
                    std::io::Error::last_os_error()
                );
                let mut held = unsafe { File::from_raw_fd(raw) };
                let metadata = held.metadata()?;
                let key = if relative.is_empty() {
                    name.to_string()
                } else {
                    format!("{relative}/{name}")
                };
                if metadata.is_dir() {
                    ensure!(
                        depth < max_depth,
                        "held package exceeds its directory depth limit"
                    );
                    read_tree_from_directory(
                        &held,
                        &key,
                        depth + 1,
                        per_file_limit,
                        total_limit,
                        max_entries,
                        max_depth,
                        total,
                        entries,
                        files,
                    )?;
                } else {
                    ensure!(metadata.is_file(), "held package entry is not regular");
                    ensure!(
                        metadata.len() <= per_file_limit as u64,
                        "held package file exceeds its byte limit"
                    );
                    let mut bytes = Vec::with_capacity(metadata.len() as usize);
                    std::io::Read::by_ref(&mut held)
                        .take(per_file_limit as u64 + 1)
                        .read_to_end(&mut bytes)?;
                    ensure!(
                        bytes.len() <= per_file_limit,
                        "held package file exceeds its byte limit"
                    );
                    *total = total.saturating_add(bytes.len());
                    ensure!(
                        *total <= total_limit,
                        "held package exceeds its total byte limit"
                    );
                    ensure!(
                        files.insert(key, bytes).is_none(),
                        "held package path is duplicated"
                    );
                }
            }
            Ok(())
        })();
        unsafe { libc::closedir(stream) };
        result
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "dragonfly",
        target_os = "emscripten",
        target_os = "hurd",
        target_os = "redox"
    ))]
    fn set_readdir_errno_zero() {
        unsafe { *libc::__errno_location() = 0 }
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd",
    ))]
    fn set_readdir_errno_zero() {
        unsafe { *libc::__error() = 0 }
    }

    #[cfg(any(target_os = "android", target_os = "netbsd", target_os = "openbsd"))]
    fn set_readdir_errno_zero() {
        unsafe { *libc::__errno() = 0 }
    }

    fn file_evidence(file: &File) -> Result<(String, String)> {
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.nlink() == 1
                && metadata.mode() & 0o777 == 0o600,
            "held artifact is not private singly-linked regular file"
        );
        let dev = metadata.dev().to_be_bytes();
        let ino = metadata.ino().to_be_bytes();
        let uid = metadata.uid().to_be_bytes();
        let mode = (metadata.mode() & 0o777).to_be_bytes();
        Ok((
            digest(&[b"held-artifact-unix-v1", &dev, &ino]),
            digest(&[b"held-artifact-security-unix-v1", &uid, &mode]),
        ))
    }

    fn open_absolute_root() -> Result<File> {
        held_fd::open_fs_root().context("opening filesystem root")
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::io::{Read as _, Write as _};
    use std::mem::size_of;
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use std::ptr;

    use super::*;

    pub(super) fn regular_file_authorization_identity(path: &Path) -> Result<String> {
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_ALL,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        ensure!(
            raw != INVALID_HANDLE_VALUE,
            "opening Windows workspace source metadata failed: {}",
            std::io::Error::last_os_error()
        );
        let file = unsafe { File::from_raw_handle(raw) };
        regular_file_identity(&file)
    }

    pub(super) fn regular_file_identity(file: &File) -> Result<String> {
        verify_regular_handle(file)?;
        let info = handle_information(file)?;
        Ok(digest(&[
            b"held-workspace-file-windows-v1",
            &info.volume_serial.to_be_bytes(),
            &info.file_index_high.to_be_bytes(),
            &info.file_index_low.to_be_bytes(),
        ]))
    }

    type Handle = *mut c_void;
    const INVALID_HANDLE_VALUE: Handle = -1_isize as Handle;
    const STATUS_SUCCESS_MIN: i32 = 0;
    const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
    const STATUS_OBJECT_PATH_NOT_FOUND: i32 = 0xC000_003A_u32 as i32;
    const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035_u32 as i32;
    const STATUS_NO_MORE_FILES: i32 = 0x8000_0006_u32 as i32;
    const OBJ_CASE_INSENSITIVE: u32 = 0x40;
    const OBJ_DONT_REPARSE: u32 = 0x1000;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const DELETE: u32 = 0x0001_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
    const FILE_SHARE_ALL: u32 = 0x7;
    // The execution cwd lease deliberately permits normal read/write access
    // but refuses DELETE. Windows requires every existing handle to share
    // DELETE before a directory can be renamed or removed.
    const FILE_SHARE_READ_WRITE: u32 = 0x3;
    const FILE_OPEN: u32 = 1;
    const FILE_CREATE: u32 = 2;
    const FILE_DIRECTORY_FILE: u32 = 0x1;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
    const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    // FSCTL_CREATE_OR_GET_OBJECT_ID associates a durable 16-byte NTFS object
    // identifier with this directory.  Unlike a directory entry, it survives
    // repository cleanup and is never published in a partially-written form.
    const FSCTL_CREATE_OR_GET_OBJECT_ID: u32 = 0x0009_00c0;

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: Handle,
        object_name: *const UnicodeString,
        attributes: u32,
        security_descriptor: *mut c_void,
        security_quality_of_service: *mut c_void,
    }
    #[repr(C)]
    struct IoStatusBlock {
        status: isize,
        information: usize,
    }
    #[repr(C)]
    struct ByHandleFileInformation {
        attributes: u32,
        creation_low: u32,
        creation_high: u32,
        access_low: u32,
        access_high: u32,
        write_low: u32,
        write_high: u32,
        volume_serial: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }
    #[repr(C)]
    struct FileDispositionInformation {
        delete_file: u8,
    }
    #[repr(C)]
    struct FileNamesInformation {
        next_entry_offset: u32,
        file_index: u32,
        file_name_length: u32,
        file_name: [u16; 1],
    }
    enum RelativeProbe {
        Present(File),
        Absent,
        SecurityAmbiguous,
    }
    #[repr(C)]
    struct FileRenameInformation {
        replace_if_exists: u8,
        root_directory: Handle,
        file_name_length: u32,
        file_name: [u16; 1],
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtCreateFile(
            file: *mut Handle,
            access: u32,
            attributes: *const ObjectAttributes,
            io: *mut IoStatusBlock,
            allocation: *const i64,
            file_attributes: u32,
            share: u32,
            disposition: u32,
            options: u32,
            ea: *const c_void,
            ea_len: u32,
        ) -> i32;
        fn NtSetInformationFile(
            file: Handle,
            io: *mut IoStatusBlock,
            information: *const c_void,
            length: u32,
            class: u32,
        ) -> i32;
        fn NtQueryDirectoryFile(
            file: Handle,
            event: Handle,
            apc_routine: *mut c_void,
            apc_context: *mut c_void,
            io: *mut IoStatusBlock,
            information: *mut c_void,
            length: u32,
            information_class: u32,
            return_single_entry: u8,
            file_name: *const UnicodeString,
            restart_scan: u8,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *mut c_void,
            creation: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn GetFileInformationByHandle(
            file: Handle,
            information: *mut ByHandleFileInformation,
        ) -> i32;
        fn FlushFileBuffers(file: Handle) -> i32;
        fn DeviceIoControl(
            device: Handle,
            control_code: u32,
            input: *const c_void,
            input_len: u32,
            output: *mut c_void,
            output_len: u32,
            bytes_returned: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
    }

    #[derive(Debug)]
    pub(super) struct HeldDirectory {
        dir: File,
        diagnostic_path: PathBuf,
    }
    impl HeldDirectory {
        pub(super) fn open_existing(path: &Path) -> Result<Self> {
            Self::open_existing_with_policy(path, true)
        }

        pub(super) fn open_existing_workspace(path: &Path) -> Result<Self> {
            Self::open_existing_with_policy(path, false)
        }

        pub(super) fn open_workspace_execution_lease(
            &self,
            canonical_path: &Path,
            expected_identity: &str,
        ) -> Result<Vec<File>> {
            let chain = open_workspace_execution_lease(canonical_path, expected_identity)?;
            // The newly opened final component must agree with the authority
            // that was retained at attach, not merely with an independently
            // supplied digest.
            ensure!(
                workspace_identity_for_handle(
                    chain
                        .last()
                        .context("Windows workspace execution lease has no final handle")?
                )? == self.workspace_identity()?,
                "Windows workspace execution lease differs from retained authority"
            );
            Ok(chain)
        }

        fn open_existing_with_policy(path: &Path, require_private: bool) -> Result<Self> {
            use std::path::Prefix;
            ensure!(path.is_absolute(), "held directory path must be absolute");
            let mut components = path.components();
            let drive = match components.next() {
                Some(Component::Prefix(prefix)) => match prefix.kind() {
                    Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
                    _ => anyhow::bail!("only local Windows volumes support held authority"),
                },
                _ => anyhow::bail!("Windows held authority requires an absolute drive path"),
            };
            ensure!(
                matches!(components.next(), Some(Component::RootDir)),
                "Windows held authority requires rooted path"
            );
            let root = format!("{}:\\", char::from(drive));
            let root_wide = std::ffi::OsStr::new(&root)
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let raw = unsafe {
                CreateFileW(
                    root_wide.as_ptr(),
                    GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    FILE_SHARE_ALL,
                    ptr::null_mut(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    ptr::null_mut(),
                )
            };
            ensure!(
                raw != INVALID_HANDLE_VALUE,
                "opening held Windows volume root failed: {}",
                std::io::Error::last_os_error()
            );
            let mut dir = unsafe { File::from_raw_handle(raw) };
            for component in components {
                let Component::Normal(name) = component else {
                    anyhow::bail!("Windows held directory path is not lexical")
                };
                let wide = name.encode_wide().collect::<Vec<_>>();
                dir = open_relative(
                    &dir,
                    &wide,
                    FILE_OPEN,
                    FILE_DIRECTORY_FILE,
                    GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                )?;
                verify_directory_handle(&dir)?;
            }
            verify_directory_handle(&dir)?;
            if require_private {
                verify_private_dacl_handle(&dir)?;
            }
            Ok(Self {
                dir,
                diagnostic_path: path.to_path_buf(),
            })
        }
        pub(super) fn identity(&self) -> Result<DirectoryIdentity> {
            let info = handle_information(&self.dir)?;
            let volume = info.volume_serial.to_be_bytes();
            let high = info.file_index_high.to_be_bytes();
            let low = info.file_index_low.to_be_bytes();
            let stable_digest = digest(&[b"held-directory-windows-v1", &volume, &high, &low]);
            let canonical_binding_digest = digest(&[
                b"held-directory-binding-windows-v1",
                stable_digest.as_bytes(),
            ]);
            Ok(DirectoryIdentity {
                platform: "windows-v1",
                stable_digest,
                canonical_binding_digest,
            })
        }
        pub(super) fn workspace_identity(&self) -> Result<String> {
            workspace_identity_for_handle(&self.dir)
        }
        pub(super) fn directory_handle_clone(&self) -> Result<File> {
            Ok(self.dir.try_clone()?)
        }
        pub(super) fn workspace_birth_token(&self) -> Result<Vec<u8>> {
            // OBJECT_ID_BUFFER begins with the 16-byte object id; the
            // remaining birth/domain fields are irrelevant here.  The FSCTL
            // is atomic: if another caller creates the id first, both callers
            // receive that same fully initialized directory property.
            let mut object_id = [0_u8; 64];
            let mut returned = 0_u32;
            let ok = unsafe {
                DeviceIoControl(
                    self.dir.as_raw_handle(),
                    FSCTL_CREATE_OR_GET_OBJECT_ID,
                    ptr::null(),
                    0,
                    object_id.as_mut_ptr().cast(),
                    object_id.len() as u32,
                    &mut returned,
                    ptr::null_mut(),
                )
            };
            ensure!(
                ok != 0 && returned >= 16,
                "creating or reading Windows workspace object ID failed: {}",
                std::io::Error::last_os_error()
            );
            Ok(object_id[..16].to_vec())
        }
        pub(super) fn read_regular_file(&self, components: &[&str]) -> Result<Vec<u8>> {
            let (leaf, parents) = components
                .split_last()
                .context("held workspace read requires a leaf")?;
            let mut parent = self.dir.try_clone()?;
            for component in parents {
                let wide = std::ffi::OsStr::new(component)
                    .encode_wide()
                    .collect::<Vec<_>>();
                parent = open_relative(
                    &parent,
                    &wide,
                    FILE_OPEN,
                    FILE_DIRECTORY_FILE,
                    GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                )?;
                verify_directory_handle(&parent)?;
            }
            let wide = std::ffi::OsStr::new(leaf).encode_wide().collect::<Vec<_>>();
            let mut file = open_relative(
                &parent,
                &wide,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            )?;
            verify_regular_handle(&file)?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .context("reading held workspace definition")?;
            Ok(bytes)
        }
        pub(super) fn open_regular_file(&self, components: &[&str]) -> Result<File> {
            let (leaf, parents) = components
                .split_last()
                .context("held workspace open requires a leaf")?;
            let mut parent = self.dir.try_clone()?;
            for component in parents {
                let wide = std::ffi::OsStr::new(component)
                    .encode_wide()
                    .collect::<Vec<_>>();
                parent = open_relative(
                    &parent,
                    &wide,
                    FILE_OPEN,
                    FILE_DIRECTORY_FILE,
                    GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                )?;
                verify_directory_handle(&parent)?;
            }
            let wide = std::ffi::OsStr::new(leaf).encode_wide().collect::<Vec<_>>();
            let file = open_relative(
                &parent,
                &wide,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            )?;
            verify_regular_handle(&file)?;
            Ok(file)
        }
        pub(super) fn read_regular_file_bounded(
            &self,
            components: &[&str],
            max_bytes: usize,
        ) -> Result<Vec<u8>> {
            let (leaf, parents) = components
                .split_last()
                .context("held workspace read requires a leaf")?;
            let mut parent = self.dir.try_clone()?;
            for component in parents {
                let wide = std::ffi::OsStr::new(component)
                    .encode_wide()
                    .collect::<Vec<_>>();
                parent = open_relative(
                    &parent,
                    &wide,
                    FILE_OPEN,
                    FILE_DIRECTORY_FILE,
                    GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                )?;
                verify_directory_handle(&parent)?;
            }
            let wide = std::ffi::OsStr::new(leaf).encode_wide().collect::<Vec<_>>();
            let mut file = open_relative(
                &parent,
                &wide,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            )?;
            verify_regular_handle(&file)?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_file() && metadata.len() <= max_bytes as u64,
                "held workspace definition is not a bounded regular file"
            );
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            file.take(max_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .context("reading held workspace definition")?;
            ensure!(
                bytes.len() <= max_bytes,
                "held workspace definition exceeds the byte limit"
            );
            Ok(bytes)
        }
        pub(super) fn read_regular_file_bounded_optional(
            &self,
            components: &[&str],
            max_bytes: usize,
        ) -> Result<Option<Vec<u8>>> {
            let (leaf, parents) = components
                .split_last()
                .context("held workspace read requires a leaf")?;
            let mut parent = self.dir.try_clone()?;
            for component in parents {
                let wide = std::ffi::OsStr::new(component)
                    .encode_wide()
                    .collect::<Vec<_>>();
                let Some(opened) = open_optional_relative(
                    &parent,
                    &wide,
                    FILE_DIRECTORY_FILE,
                    GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                )?
                else {
                    return Ok(None);
                };
                parent = opened;
                verify_directory_handle(&parent)?;
            }
            let wide = std::ffi::OsStr::new(leaf).encode_wide().collect::<Vec<_>>();
            let Some(mut file) = open_optional_relative(
                &parent,
                &wide,
                FILE_NON_DIRECTORY_FILE,
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            )?
            else {
                return Ok(None);
            };
            verify_regular_handle(&file)?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.len() <= max_bytes as u64,
                "held workspace definition exceeds the byte limit"
            );
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            file.take(max_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .context("reading held workspace definition")?;
            ensure!(
                bytes.len() <= max_bytes,
                "held workspace definition exceeds the byte limit"
            );
            Ok(Some(bytes))
        }
        pub(super) fn read_directory_tree(
            &self,
            components: &[&str],
            per_file_limit: usize,
            total_limit: usize,
            max_entries: usize,
            max_depth: usize,
        ) -> Result<Option<std::collections::BTreeMap<String, Vec<u8>>>> {
            let mut root = self.dir.try_clone()?;
            for component in components {
                let wide = std::ffi::OsStr::new(component)
                    .encode_wide()
                    .collect::<Vec<_>>();
                let Some(opened) = open_optional_relative(
                    &root,
                    &wide,
                    FILE_DIRECTORY_FILE,
                    GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                )?
                else {
                    return Ok(None);
                };
                root = opened;
                verify_directory_handle(&root)?;
            }
            let mut files = std::collections::BTreeMap::new();
            let mut total = 0usize;
            let mut entries = 0usize;
            read_tree_from_directory(
                &root,
                "",
                0,
                per_file_limit,
                total_limit,
                max_entries,
                max_depth,
                &mut total,
                &mut entries,
                &mut files,
            )?;
            Ok(Some(files))
        }

        pub(super) fn read_regular_executable_file_bounded(
            &self,
            components: &[&str],
            max_bytes: usize,
        ) -> Result<HeldWorkspaceExecutableFile> {
            let (leaf, parents) = components
                .split_last()
                .context("held workspace executable read requires a leaf")?;
            let mut parent = self.dir.try_clone()?;
            for component in parents {
                let wide = std::ffi::OsStr::new(component)
                    .encode_wide()
                    .collect::<Vec<_>>();
                parent = open_relative(
                    &parent,
                    &wide,
                    FILE_OPEN,
                    FILE_DIRECTORY_FILE,
                    GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                )?;
                verify_directory_handle(&parent)?;
            }
            let wide = std::ffi::OsStr::new(leaf).encode_wide().collect::<Vec<_>>();
            let mut file = open_relative(
                &parent,
                &wide,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            )?;
            verify_regular_handle(&file)?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.len() <= max_bytes as u64,
                "held workspace executable exceeds the byte limit"
            );
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            file.take(max_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .context("reading held workspace executable")?;
            ensure!(
                bytes.len() <= max_bytes,
                "held workspace executable exceeds the byte limit"
            );
            Ok(HeldWorkspaceExecutableFile { bytes })
        }
        pub(super) fn diagnostic_path(&self) -> &Path {
            &self.diagnostic_path
        }
        fn verify_directory_security(&self) -> Result<()> {
            verify_directory_handle(&self.dir)?;
            verify_private_dacl_handle(&self.dir)
        }
        pub(super) fn create_file_exclusive(&self, name: &str) -> Result<(File, String, String)> {
            self.verify_directory_security()?;
            let wide = std::ffi::OsStr::new(name).encode_wide().collect::<Vec<_>>();
            let file = open_relative(
                &self.dir,
                &wide,
                FILE_CREATE,
                FILE_NON_DIRECTORY_FILE,
                GENERIC_READ
                    | GENERIC_WRITE
                    | DELETE
                    | SYNCHRONIZE
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES,
            )?;
            crate::goal_scratch::set_private_dacl_handle(&file)?;
            let (identity, security) = file_evidence(&file)?;
            Ok((file, identity, security))
        }
        pub(super) fn revalidate_named(
            &self,
            name: &str,
            held: &File,
            identity: &str,
            security: &str,
        ) -> Result<()> {
            self.verify_directory_security()?;
            let wide = std::ffi::OsStr::new(name).encode_wide().collect::<Vec<_>>();
            let reopened = open_relative(
                &self.dir,
                &wide,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            )?;
            let held_evidence = file_evidence(held)?;
            ensure!(
                held_evidence.0 == identity
                    && held_evidence.1 == security
                    && file_evidence(&reopened)? == held_evidence,
                "held Windows artifact name/FileId/security changed"
            );
            Ok(())
        }
        pub(super) fn rename_noreplace(
            &self,
            mut artifact: HeldSealedArtifact,
            to: &str,
        ) -> Result<HeldDirectoryEffectOutcome> {
            self.verify_directory_security()?;
            let target_name = to;
            let to = std::ffi::OsStr::new(target_name)
                .encode_wide()
                .collect::<Vec<_>>();
            // FILE_RENAME_INFORMATION: ReplaceIfExists=false, RootDirectory=held dir.
            let name_offset = std::mem::offset_of!(FileRenameInformation, file_name);
            let mut buffer = vec![0u8; name_offset + to.len() * 2];
            unsafe {
                let info = buffer.as_mut_ptr().cast::<FileRenameInformation>();
                (*info).replace_if_exists = 0;
                (*info).root_directory = self.dir.as_raw_handle();
                (*info).file_name_length = (to.len() * 2) as u32;
                ptr::copy_nonoverlapping(
                    to.as_ptr().cast::<u8>(),
                    buffer.as_mut_ptr().add(name_offset),
                    to.len() * 2,
                );
            }
            let mut io = IoStatusBlock {
                status: 0,
                information: 0,
            };
            let status = if take_forced_publish_failure() {
                -1
            } else {
                unsafe {
                    NtSetInformationFile(
                        artifact.file.as_raw_handle(),
                        &mut io,
                        buffer.as_ptr().cast(),
                        buffer.len() as u32,
                        10,
                    )
                }
            };
            if status < STATUS_SUCCESS_MIN {
                if status == STATUS_OBJECT_NAME_COLLISION {
                    return Ok(HeldDirectoryEffectOutcome::ProvenNotApplied(artifact));
                }
                return Ok(unknown_recovery(
                    Some(target_name.to_owned()),
                    artifact.name,
                    artifact.evidence,
                    true,
                ));
            }
            run_after_publish_effect_hook();
            let Ok(mut published) = open_relative(
                &self.dir,
                &to,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            ) else {
                return Ok(unknown_recovery(
                    Some(target_name.to_owned()),
                    artifact.name,
                    artifact.evidence,
                    true,
                ));
            };
            let Ok((identity, security)) = file_evidence(&published) else {
                return Ok(unknown_recovery(
                    Some(target_name.to_owned()),
                    artifact.name,
                    artifact.evidence,
                    true,
                ));
            };
            if identity != artifact.evidence.identity_digest
                || security != artifact.evidence.security_digest
                || validate_contents(&mut artifact.file, &artifact.evidence).is_err()
                || validate_contents(&mut published, &artifact.evidence).is_err()
                || self.verify_directory_security().is_err()
            {
                return Ok(unknown_recovery(
                    Some(target_name.to_owned()),
                    artifact.name,
                    artifact.evidence,
                    true,
                ));
            }
            if sync_failure_forced() || unsafe { FlushFileBuffers(self.dir.as_raw_handle()) } == 0 {
                return Ok(unknown_recovery(
                    Some(target_name.to_owned()),
                    artifact.name,
                    artifact.evidence,
                    false,
                ));
            }
            Ok(durable_evidence(
                Some(target_name.to_owned()),
                artifact.evidence,
            ))
        }
        pub(super) fn unlink(
            &self,
            artifact: HeldSealedArtifact,
        ) -> Result<HeldDirectoryEffectOutcome> {
            self.verify_directory_security()?;
            let info = FileDispositionInformation { delete_file: 1 };
            let mut io = IoStatusBlock {
                status: 0,
                information: 0,
            };
            let status = if take_forced_cleanup_failure() {
                -1
            } else {
                unsafe {
                    NtSetInformationFile(
                        artifact.file.as_raw_handle(),
                        &mut io,
                        (&info as *const FileDispositionInformation).cast(),
                        size_of::<FileDispositionInformation>() as u32,
                        13,
                    )
                }
            };
            if status < STATUS_SUCCESS_MIN {
                let source = std::ffi::OsStr::new(&artifact.name)
                    .encode_wide()
                    .collect::<Vec<_>>();
                if let Ok(RelativeProbe::Present(mut file)) = probe_relative(
                    &self.dir,
                    &source,
                    GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                ) && verify_expected_file(&file, &artifact.evidence).is_ok()
                    && validate_contents(&mut file, &artifact.evidence).is_ok()
                {
                    return Ok(HeldDirectoryEffectOutcome::ProvenNotApplied(artifact));
                }
                return Ok(unknown_recovery(
                    None,
                    artifact.name,
                    artifact.evidence,
                    true,
                ));
            }
            if self.verify_directory_security().is_err() {
                return Ok(unknown_recovery(
                    None,
                    artifact.name,
                    artifact.evidence,
                    true,
                ));
            }
            if sync_failure_forced() || unsafe { FlushFileBuffers(self.dir.as_raw_handle()) } == 0 {
                return Ok(unknown_recovery(
                    None,
                    artifact.name,
                    artifact.evidence,
                    false,
                ));
            }
            Ok(durable_evidence(None, artifact.evidence))
        }

        pub(super) fn open_verified(
            &self,
            name: &str,
            evidence: &HeldArtifactEvidence,
        ) -> Result<HeldSealedArtifact> {
            self.verify_directory_security()?;
            let wide = std::ffi::OsStr::new(name).encode_wide().collect::<Vec<_>>();
            let RelativeProbe::Present(mut file) = probe_relative(
                &self.dir,
                &wide,
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            )?
            else {
                anyhow::bail!("held artifact is absent")
            };
            verify_expected_file(&file, evidence)?;
            validate_contents(&mut file, evidence)?;
            file.rewind()?;
            Ok(HeldSealedArtifact {
                file,
                name: name.to_owned(),
                evidence: evidence.clone(),
            })
        }

        pub(super) fn reconcile(
            &self,
            recovery: &HeldDirectoryRecovery,
        ) -> Result<HeldDirectoryEffectOutcome> {
            self.verify_directory_security()?;
            if let Some(destination) = &recovery.destination_name {
                let wide = std::ffi::OsStr::new(destination)
                    .encode_wide()
                    .collect::<Vec<_>>();
                let destination_probe = match probe_relative(
                    &self.dir,
                    &wide,
                    GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                ) {
                    Ok(probe) => probe,
                    Err(_) => {
                        return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                            recovery.clone(),
                        ));
                    }
                };
                match destination_probe {
                    RelativeProbe::Present(mut file) => {
                        if verify_expected_file(&file, &recovery.artifact).is_err()
                            || validate_contents(&mut file, &recovery.artifact).is_err()
                        {
                            return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                                recovery.clone(),
                            ));
                        }
                    }
                    RelativeProbe::Absent => {
                        let source = std::ffi::OsStr::new(&recovery.source_name)
                            .encode_wide()
                            .collect::<Vec<_>>();
                        let source_probe = match probe_relative(
                            &self.dir,
                            &source,
                            GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                        ) {
                            Ok(probe) => probe,
                            Err(_) => {
                                return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                                    recovery.clone(),
                                ));
                            }
                        };
                        match source_probe {
                            RelativeProbe::Present(mut file) => {
                                if verify_expected_file(&file, &recovery.artifact).is_err()
                                    || validate_contents(&mut file, &recovery.artifact).is_err()
                                {
                                    return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                                        recovery.clone(),
                                    ));
                                }
                                return Ok(HeldDirectoryEffectOutcome::ProvenNotApplied(
                                    HeldSealedArtifact {
                                        file,
                                        name: recovery.source_name.clone(),
                                        evidence: recovery.artifact.clone(),
                                    },
                                ));
                            }
                            _ => {
                                return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                                    recovery.clone(),
                                ));
                            }
                        }
                    }
                    _ => {
                        return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                            recovery.clone(),
                        ));
                    }
                }
                if recovery.source_cleanup_required {
                    let source = std::ffi::OsStr::new(&recovery.source_name)
                        .encode_wide()
                        .collect::<Vec<_>>();
                    let source_probe = match probe_relative(
                        &self.dir,
                        &source,
                        GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    ) {
                        Ok(probe) => probe,
                        Err(_) => {
                            return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                                recovery.clone(),
                            ));
                        }
                    };
                    if !matches!(source_probe, RelativeProbe::Absent) {
                        return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                            recovery.clone(),
                        ));
                    }
                }
            } else {
                let wide = std::ffi::OsStr::new(&recovery.source_name)
                    .encode_wide()
                    .collect::<Vec<_>>();
                let source_probe = match probe_relative(
                    &self.dir,
                    &wide,
                    GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                ) {
                    Ok(probe) => probe,
                    Err(_) => {
                        return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                            recovery.clone(),
                        ));
                    }
                };
                match source_probe {
                    RelativeProbe::Absent => {}
                    RelativeProbe::Present(mut file) => {
                        if verify_expected_file(&file, &recovery.artifact).is_err()
                            || validate_contents(&mut file, &recovery.artifact).is_err()
                        {
                            return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                                recovery.clone(),
                            ));
                        }
                        return Ok(HeldDirectoryEffectOutcome::ProvenNotApplied(
                            HeldSealedArtifact {
                                file,
                                name: recovery.source_name.clone(),
                                evidence: recovery.artifact.clone(),
                            },
                        ));
                    }
                    _ => {
                        return Ok(HeldDirectoryEffectOutcome::SecurityAmbiguous(
                            recovery.clone(),
                        ));
                    }
                }
            }
            if sync_failure_forced() || unsafe { FlushFileBuffers(self.dir.as_raw_handle()) } == 0 {
                return Ok(HeldDirectoryEffectOutcome::AppliedUnknown(recovery.clone()));
            }
            Ok(durable_evidence(
                recovery.destination_name.clone(),
                recovery.artifact.clone(),
            ))
        }

        pub(super) fn delete_recovered_destination(
            &self,
            recovery: &HeldDirectoryRecovery,
        ) -> Result<HeldDirectoryEffectOutcome> {
            let Some(destination) = &recovery.destination_name else {
                anyhow::bail!("recovery has no destination")
            };
            let wide = std::ffi::OsStr::new(destination)
                .encode_wide()
                .collect::<Vec<_>>();
            let mut file = open_relative(
                &self.dir,
                &wide,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
                GENERIC_READ | DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
            )?;
            verify_expected_file(&file, &recovery.artifact)?;
            validate_contents(&mut file, &recovery.artifact)?;
            self.unlink(HeldSealedArtifact {
                file,
                name: destination.clone(),
                evidence: recovery.artifact.clone(),
            })
        }
    }

    fn workspace_identity_for_handle(file: &File) -> Result<String> {
        let info = handle_information(file)?;
        Ok(digest(&[
            b"attached-workspace-windows-v1",
            &info.volume_serial.to_be_bytes(),
            &info.file_index_high.to_be_bytes(),
            &info.file_index_low.to_be_bytes(),
        ]))
    }

    /// Open every component of `canonical_path` from its drive root through
    /// no-reparse relative opens, retaining every handle without DELETE share.
    /// Retaining the whole chain matters: holding only the final workspace
    /// directory still leaves an attacker able to rename an ancestor and reuse
    /// the canonical spelling for a replacement workspace before
    /// `CreateProcess` resolves its cwd path.
    fn open_workspace_execution_lease(
        canonical_path: &Path,
        expected_identity: &str,
    ) -> Result<Vec<File>> {
        use std::path::Prefix;

        ensure!(
            canonical_path.is_absolute(),
            "Windows workspace execution lease requires an absolute canonical path"
        );
        let mut components = canonical_path.components();
        let drive = match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
                _ => anyhow::bail!("Windows workspace execution lease requires a local drive"),
            },
            _ => anyhow::bail!("Windows workspace execution lease requires a drive path"),
        };
        ensure!(
            matches!(components.next(), Some(Component::RootDir)),
            "Windows workspace execution lease requires a rooted path"
        );
        let root = format!("{}:\\", char::from(drive));
        let root_wide = std::ffi::OsStr::new(&root)
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        // The root handle is also part of the chain. A drive root cannot be
        // renamed, so leave its normal share mode intact; denying DELETE on it
        // would needlessly conflict with unrelated volume handles. Every
        // mutable named component beneath it is opened without DELETE share.
        let raw = unsafe {
            CreateFileW(
                root_wide.as_ptr(),
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_ALL,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        ensure!(
            raw != INVALID_HANDLE_VALUE,
            "opening Windows workspace execution lease root failed: {}",
            std::io::Error::last_os_error()
        );
        let mut chain = vec![unsafe { File::from_raw_handle(raw) }];
        verify_directory_handle(
            chain
                .last()
                .context("Windows workspace execution lease root missing")?,
        )?;
        for component in components {
            let Component::Normal(name) = component else {
                anyhow::bail!("Windows workspace execution lease path is not lexical")
            };
            let wide = name.encode_wide().collect::<Vec<_>>();
            let next = open_relative_with_share(
                chain
                    .last()
                    .context("Windows workspace execution lease parent missing")?,
                &wide,
                FILE_OPEN,
                FILE_DIRECTORY_FILE,
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ_WRITE,
            )?;
            verify_directory_handle(&next)?;
            chain.push(next);
        }
        ensure!(
            workspace_identity_for_handle(
                chain
                    .last()
                    .context("Windows workspace execution lease final handle missing")?
            )? == expected_identity,
            "Windows workspace execution lease identity differs from attached workspace"
        );
        Ok(chain)
    }

    pub(super) fn revalidate_workspace_execution_lease(
        chain: &[File],
        canonical_path: &Path,
        expected_identity: &str,
    ) -> Result<()> {
        let held = chain
            .last()
            .context("Windows workspace execution lease has no final handle")?;
        verify_directory_handle(held)?;
        ensure!(
            workspace_identity_for_handle(held)? == expected_identity,
            "Windows workspace execution lease handle identity changed"
        );
        // Re-walk while the original no-delete chain remains live. This proves
        // the spelling passed to CreateProcess still reaches the attached
        // object. The original chain blocks a rename/delete race after this
        // revalidation through child exit.
        let observed = open_workspace_execution_lease(canonical_path, expected_identity)?;
        let observed_final = observed
            .last()
            .context("Windows workspace execution revalidation has no final handle")?;
        ensure!(
            workspace_identity_for_handle(observed_final)? == workspace_identity_for_handle(held)?,
            "Windows workspace execution lease path identity changed"
        );
        Ok(())
    }

    fn open_relative(
        parent: &File,
        name: &[u16],
        disposition: u32,
        kind: u32,
        access: u32,
    ) -> Result<File> {
        open_relative_with_share(parent, name, disposition, kind, access, FILE_SHARE_ALL)
    }

    fn open_optional_relative(
        parent: &File,
        name: &[u16],
        kind: u32,
        access: u32,
    ) -> Result<Option<File>> {
        ensure!(
            !name.is_empty() && name.len() <= (u16::MAX as usize / 2),
            "invalid Windows relative name"
        );
        let mut owned = name.to_vec();
        let unicode = UnicodeString {
            length: (owned.len() * 2) as u16,
            maximum_length: (owned.len() * 2) as u16,
            buffer: owned.as_mut_ptr(),
        };
        let attributes = ObjectAttributes {
            length: size_of::<ObjectAttributes>() as u32,
            root_directory: parent.as_raw_handle(),
            object_name: &unicode,
            attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        };
        let mut io = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let mut raw = ptr::null_mut();
        let status = unsafe {
            NtCreateFile(
                &mut raw,
                access,
                &attributes,
                &mut io,
                ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_ALL,
                FILE_OPEN,
                kind | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                ptr::null(),
                0,
            )
        };
        if matches!(
            status,
            STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND
        ) {
            return Ok(None);
        }
        ensure!(
            status >= STATUS_SUCCESS_MIN && !raw.is_null(),
            "held Windows optional relative open failed with NTSTATUS {status:#x}"
        );
        Ok(Some(unsafe { File::from_raw_handle(raw) }))
    }

    fn open_relative_with_share(
        parent: &File,
        name: &[u16],
        disposition: u32,
        kind: u32,
        access: u32,
        share: u32,
    ) -> Result<File> {
        open_relative_with_share_and_attributes(
            parent,
            name,
            disposition,
            kind,
            access,
            share,
            OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        )
    }

    /// Reopen an exact name returned by `NtQueryDirectoryFile`. A package
    /// directory may have case-sensitive NTFS semantics and contain both
    /// `agent.md` and `AGENT.md`; adding `OBJ_CASE_INSENSITIVE` here could open
    /// either sibling and digest bytes under the other sibling's enumerated
    /// name. The retained parent handle and `OBJ_DONT_REPARSE` remain the
    /// authority/no-follow boundary.
    fn open_enumerated_relative(
        parent: &File,
        name: &[u16],
        kind: u32,
        access: u32,
    ) -> Result<File> {
        open_relative_with_share_and_attributes(
            parent,
            name,
            FILE_OPEN,
            kind,
            access,
            FILE_SHARE_ALL,
            enumerated_relative_object_attributes(),
        )
    }

    pub(super) const fn enumerated_relative_object_attributes() -> u32 {
        OBJ_DONT_REPARSE
    }

    fn open_relative_with_share_and_attributes(
        parent: &File,
        name: &[u16],
        disposition: u32,
        kind: u32,
        access: u32,
        share: u32,
        object_attributes: u32,
    ) -> Result<File> {
        ensure!(
            !name.is_empty() && name.len() <= (u16::MAX as usize / 2),
            "invalid Windows relative name"
        );
        let mut owned = name.to_vec();
        let unicode = UnicodeString {
            length: (owned.len() * 2) as u16,
            maximum_length: (owned.len() * 2) as u16,
            buffer: owned.as_mut_ptr(),
        };
        let attributes = ObjectAttributes {
            length: size_of::<ObjectAttributes>() as u32,
            root_directory: parent.as_raw_handle(),
            object_name: &unicode,
            attributes: object_attributes,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        };
        let mut io = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let mut raw = ptr::null_mut();
        let status = unsafe {
            NtCreateFile(
                &mut raw,
                access,
                &attributes,
                &mut io,
                ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                share,
                disposition,
                kind | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                ptr::null(),
                0,
            )
        };
        ensure!(
            status >= STATUS_SUCCESS_MIN && !raw.is_null(),
            "held Windows relative open failed with NTSTATUS {status:#x}"
        );
        Ok(unsafe { File::from_raw_handle(raw) })
    }

    fn probe_relative(parent: &File, name: &[u16], access: u32) -> Result<RelativeProbe> {
        ensure!(
            !name.is_empty() && name.len() <= (u16::MAX as usize / 2),
            "invalid Windows relative name"
        );
        let mut owned = name.to_vec();
        let unicode = UnicodeString {
            length: (owned.len() * 2) as u16,
            maximum_length: (owned.len() * 2) as u16,
            buffer: owned.as_mut_ptr(),
        };
        let attributes = ObjectAttributes {
            length: size_of::<ObjectAttributes>() as u32,
            root_directory: parent.as_raw_handle(),
            object_name: &unicode,
            attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        };
        let mut io = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let mut raw = ptr::null_mut();
        let status = unsafe {
            NtCreateFile(
                &mut raw,
                access,
                &attributes,
                &mut io,
                ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_ALL,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                ptr::null(),
                0,
            )
        };
        if status >= STATUS_SUCCESS_MIN && !raw.is_null() {
            return Ok(RelativeProbe::Present(unsafe {
                File::from_raw_handle(raw)
            }));
        }
        if status == STATUS_OBJECT_NAME_NOT_FOUND {
            return Ok(RelativeProbe::Absent);
        }
        Ok(RelativeProbe::SecurityAmbiguous)
    }

    fn handle_information(file: &File) -> Result<ByHandleFileInformation> {
        let mut info = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } != 0,
            "querying held Windows identity failed: {}",
            std::io::Error::last_os_error()
        );
        Ok(info)
    }

    fn read_tree_from_directory(
        directory: &File,
        relative: &str,
        depth: usize,
        per_file_limit: usize,
        total_limit: usize,
        max_entries: usize,
        max_depth: usize,
        total: &mut usize,
        entries: &mut usize,
        files: &mut std::collections::BTreeMap<String, Vec<u8>>,
    ) -> Result<()> {
        const FILE_NAMES_INFORMATION_CLASS: u32 = 12;
        let mut restart = true;
        loop {
            // Use u64 backing storage so the native information record is
            // suitably aligned; names are still parsed by explicit byte
            // lengths and never treated as NUL-terminated.
            let mut storage = vec![0u64; 8 * 1024];
            let mut io = IoStatusBlock {
                status: 0,
                information: 0,
            };
            let status = unsafe {
                NtQueryDirectoryFile(
                    directory.as_raw_handle(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut io,
                    storage.as_mut_ptr().cast(),
                    (storage.len() * size_of::<u64>()) as u32,
                    FILE_NAMES_INFORMATION_CLASS,
                    1,
                    ptr::null(),
                    u8::from(restart),
                )
            };
            restart = false;
            if status == STATUS_NO_MORE_FILES {
                break;
            }
            ensure!(
                status >= STATUS_SUCCESS_MIN,
                "enumerating held Windows package directory failed with NTSTATUS {status:#x}"
            );
            let header_len = std::mem::offset_of!(FileNamesInformation, file_name);
            ensure!(
                io.information >= header_len,
                "held Windows package enumeration returned a truncated record"
            );
            let record = storage.as_ptr().cast::<FileNamesInformation>();
            ensure!(
                unsafe { (*record).next_entry_offset } == 0,
                "single-entry held Windows package enumeration returned a chained record"
            );
            let _file_index = unsafe { (*record).file_index };
            let name_bytes = unsafe { (*record).file_name_length as usize };
            ensure!(
                name_bytes % 2 == 0 && header_len + name_bytes <= io.information,
                "held Windows package enumeration returned an invalid name"
            );
            let name_units = unsafe {
                std::slice::from_raw_parts(
                    std::ptr::addr_of!((*record).file_name).cast::<u16>(),
                    name_bytes / 2,
                )
            };
            let os_name = std::ffi::OsString::from_wide(name_units);
            if os_name.as_os_str() == std::ffi::OsStr::new(".")
                || os_name.as_os_str() == std::ffi::OsStr::new("..")
            {
                continue;
            }
            *entries = entries
                .checked_add(1)
                .context("held Windows package entry count overflow")?;
            ensure!(
                *entries <= max_entries,
                "held Windows package exceeds its entry count limit"
            );
            let name = os_name
                .as_os_str()
                .to_str()
                .context("held Windows package entry is not UTF-8")?;
            validate_component(name)?;
            let held = open_enumerated_relative(
                directory,
                name_units,
                0,
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            )?;
            let info = handle_information(&held)?;
            ensure!(
                info.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
                "held Windows package entry is a reparse point"
            );
            let metadata = held.metadata()?;
            let key = if relative.is_empty() {
                name.to_string()
            } else {
                format!("{relative}/{name}")
            };
            if metadata.is_dir() {
                verify_directory_handle(&held)?;
                ensure!(
                    depth < max_depth,
                    "held Windows package exceeds its directory depth limit"
                );
                read_tree_from_directory(
                    &held,
                    &key,
                    depth + 1,
                    per_file_limit,
                    total_limit,
                    max_entries,
                    max_depth,
                    total,
                    entries,
                    files,
                )?;
            } else {
                ensure!(
                    metadata.is_file(),
                    "held Windows package entry is not regular"
                );
                ensure!(
                    metadata.len() <= per_file_limit as u64,
                    "held Windows package file exceeds its byte limit"
                );
                let mut held = held;
                let mut bytes = Vec::with_capacity(metadata.len() as usize);
                std::io::Read::by_ref(&mut held)
                    .take(per_file_limit as u64 + 1)
                    .read_to_end(&mut bytes)?;
                ensure!(
                    bytes.len() <= per_file_limit,
                    "held Windows package file exceeds its byte limit"
                );
                *total = total.saturating_add(bytes.len());
                ensure!(
                    *total <= total_limit,
                    "held Windows package exceeds its total byte limit"
                );
                ensure!(
                    files.insert(key, bytes).is_none(),
                    "held Windows package path is duplicated"
                );
            }
        }
        Ok(())
    }
    fn verify_directory_handle(file: &File) -> Result<()> {
        let info = handle_information(file)?;
        ensure!(
            info.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "held Windows directory is a reparse point"
        );
        ensure!(
            file.metadata()?.is_dir(),
            "held Windows authority component is not a directory"
        );
        Ok(())
    }
    fn verify_regular_handle(file: &File) -> Result<()> {
        let info = handle_information(file)?;
        ensure!(
            info.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                && info.links == 1
                && file.metadata()?.is_file(),
            "held Windows entry is not a singly-linked non-reparse regular file"
        );
        Ok(())
    }

    fn file_evidence(file: &File) -> Result<(String, String)> {
        verify_regular_handle(file)?;
        crate::goal_scratch::verify_private_dacl_handle(file)?;
        let info = handle_information(file)?;
        let identity = digest(&[
            b"held-artifact-windows-v1",
            &info.volume_serial.to_be_bytes(),
            &info.file_index_high.to_be_bytes(),
            &info.file_index_low.to_be_bytes(),
        ]);
        let security = digest(&[b"held-artifact-security-windows-v1", identity.as_bytes()]);
        Ok((identity, security))
    }

    fn verify_expected_file(file: &File, evidence: &HeldArtifactEvidence) -> Result<()> {
        let (identity, security) = file_evidence(file)?;
        ensure!(
            identity == evidence.identity_digest && security == evidence.security_digest,
            "recovered Windows artifact identity/security differs"
        );
        Ok(())
    }

    fn verify_private_dacl_handle(file: &File) -> Result<()> {
        crate::goal_scratch::verify_private_dacl_handle(file)
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::*;

    pub(super) fn regular_file_authorization_identity(_: &Path) -> Result<String> {
        anyhow::bail!("held directory authority is unavailable")
    }

    pub(super) fn regular_file_identity(_: &File) -> Result<String> {
        anyhow::bail!("held directory authority is unavailable")
    }
    #[derive(Debug)]
    pub(super) struct HeldDirectory;
    impl HeldDirectory {
        pub(super) fn open_existing(_: &Path) -> Result<Self> {
            anyhow::bail!("held directory authority is unavailable")
        }
        pub(super) fn open_existing_workspace(_: &Path) -> Result<Self> {
            anyhow::bail!("held workspace directory authority is unavailable")
        }
        pub(super) fn identity(&self) -> Result<DirectoryIdentity> {
            anyhow::bail!("held directory authority is unavailable")
        }
        pub(super) fn workspace_identity(&self) -> Result<String> {
            anyhow::bail!("held workspace directory authority is unavailable")
        }
        pub(super) fn directory_handle_clone(&self) -> Result<File> {
            anyhow::bail!("held workspace directory authority is unavailable")
        }
        pub(super) fn workspace_birth_token(&self) -> Result<Vec<u8>> {
            anyhow::bail!("held workspace directory authority is unavailable")
        }
        pub(super) fn read_regular_file(&self, _: &[&str]) -> Result<Vec<u8>> {
            anyhow::bail!("held workspace directory authority is unavailable")
        }
        pub(super) fn read_regular_file_bounded(&self, _: &[&str], _: usize) -> Result<Vec<u8>> {
            anyhow::bail!("held workspace directory authority is unavailable")
        }
        pub(super) fn read_directory_tree(
            &self,
            _: &[&str],
            _: usize,
            _: usize,
            _: usize,
            _: usize,
        ) -> Result<Option<std::collections::BTreeMap<String, Vec<u8>>>> {
            anyhow::bail!("held workspace directory-tree authority is unavailable")
        }
        pub(super) fn read_regular_executable_file_bounded(
            &self,
            _: &[&str],
            _: usize,
        ) -> Result<HeldWorkspaceExecutableFile> {
            anyhow::bail!("held workspace directory authority is unavailable")
        }
        pub(super) fn diagnostic_path(&self) -> &Path {
            Path::new("")
        }
        pub(super) fn create_file_exclusive(&self, _: &str) -> Result<(File, String, String)> {
            anyhow::bail!("held directory authority is unavailable")
        }
        pub(super) fn revalidate_named(&self, _: &str, _: &File, _: &str, _: &str) -> Result<()> {
            anyhow::bail!("held directory authority is unavailable")
        }
        pub(super) fn rename_noreplace(
            &self,
            _: HeldSealedArtifact,
            _: &str,
        ) -> Result<HeldDirectoryEffectOutcome> {
            anyhow::bail!("held directory authority is unavailable")
        }
        pub(super) fn unlink(&self, _: HeldSealedArtifact) -> Result<HeldDirectoryEffectOutcome> {
            anyhow::bail!("held directory authority is unavailable")
        }
        pub(super) fn open_verified(
            &self,
            _: &str,
            _: &HeldArtifactEvidence,
        ) -> Result<HeldSealedArtifact> {
            anyhow::bail!("held directory authority is unavailable")
        }
        pub(super) fn reconcile(
            &self,
            _: &HeldDirectoryRecovery,
        ) -> Result<HeldDirectoryEffectOutcome> {
            anyhow::bail!("held directory authority is unavailable")
        }
        pub(super) fn delete_recovered_destination(
            &self,
            _: &HeldDirectoryRecovery,
        ) -> Result<HeldDirectoryEffectOutcome> {
            anyhow::bail!("held directory authority is unavailable")
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::*;

    #[test]
    fn descriptor_walk_rejects_alias_and_survives_path_replacement() {
        let temp = tempfile::TempDir::new().unwrap();
        let target = temp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        let alias = temp.path().join("alias");
        symlink(&target, &alias).unwrap();
        assert!(HeldDirectoryAuthority::open_existing(&alias).is_err());
        let held = HeldDirectoryAuthority::open_existing(&target).unwrap();
        let original = held.identity().clone();
        std::fs::rename(&target, temp.path().join("moved")).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_ne!(
            original,
            HeldDirectoryAuthority::open_existing(&target)
                .unwrap()
                .identity()
                .clone()
        );
        let mut file = held.create_file_exclusive("proof.tmp").unwrap();
        file.file_mut().write_all(b"held").unwrap();
        assert!(temp.path().join("moved/proof.tmp").is_file());
        assert!(!target.join("proof.tmp").exists());
    }

    #[test]
    fn exclusive_publication_never_replaces_target() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = HeldDirectoryAuthority::open_existing(temp.path()).unwrap();
        let mut temp_file = held.create_file_exclusive("temp").unwrap();
        temp_file.file_mut().write_all(b"new").unwrap();
        let temp_file = held.seal(temp_file).unwrap();
        let mut output = held.create_file_exclusive("output").unwrap();
        output.file_mut().write_all(b"old").unwrap();
        let HeldDirectoryEffectOutcome::ProvenNotApplied(retained) =
            held.rename_noreplace(temp_file, "output").unwrap()
        else {
            panic!("collision must return retained source authority")
        };
        assert!(temp.path().join("temp").exists());
        assert_eq!(std::fs::read(temp.path().join("output")).unwrap(), b"old");
        assert!(matches!(
            held.unlink(retained).unwrap(),
            HeldDirectoryEffectOutcome::AppliedDurable(_)
        ));
        assert!(!temp.path().join("temp").exists());
    }

    #[test]
    fn sealed_artifact_rejects_link_chmod_content_and_name_swaps() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = HeldDirectoryAuthority::open_existing(temp.path()).unwrap();
        let mut artifact = held.create_file_exclusive("artifact").unwrap();
        artifact.file_mut().write_all(b"expected").unwrap();
        let artifact = held.seal(artifact).unwrap();
        std::fs::hard_link(temp.path().join("artifact"), temp.path().join("extra")).unwrap();
        assert!(matches!(
            held.rename_noreplace(artifact, "published").unwrap(),
            HeldDirectoryEffectOutcome::SecurityAmbiguous(_)
        ));

        let mut artifact = held.create_file_exclusive("third").unwrap();
        artifact.file_mut().write_all(b"expected").unwrap();
        let artifact = held.seal(artifact).unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            held.rename_noreplace(artifact, "published").unwrap(),
            HeldDirectoryEffectOutcome::SecurityAmbiguous(_)
        ));

        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut artifact = held.create_file_exclusive("fourth").unwrap();
        artifact.file_mut().write_all(b"expected").unwrap();
        let artifact = held.seal(artifact).unwrap();
        std::fs::write(temp.path().join("fourth"), b"mutated").unwrap();
        assert!(matches!(
            held.rename_noreplace(artifact, "published").unwrap(),
            HeldDirectoryEffectOutcome::SecurityAmbiguous(_)
        ));

        std::fs::remove_file(temp.path().join("extra")).unwrap();
        let mut artifact = held.create_file_exclusive("second").unwrap();
        artifact.file_mut().write_all(b"expected").unwrap();
        let artifact = held.seal(artifact).unwrap();
        std::fs::rename(temp.path().join("second"), temp.path().join("moved-second")).unwrap();
        std::fs::write(temp.path().join("second"), b"expected").unwrap();
        std::fs::set_permissions(
            temp.path().join("second"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(matches!(
            held.rename_noreplace(artifact, "published").unwrap(),
            HeldDirectoryEffectOutcome::SecurityAmbiguous(_)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn post_effect_sync_failure_reopens_and_reconciles_exact_destination() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = HeldDirectoryAuthority::open_existing(temp.path()).unwrap();
        let mut artifact = held.create_file_exclusive("temporary").unwrap();
        artifact.file_mut().write_all(b"exact").unwrap();
        let artifact = held.seal(artifact).unwrap();
        FORCE_DIRECTORY_SYNC_FAILURE.set(true);
        let HeldDirectoryEffectOutcome::AppliedUnknown(recovery) =
            held.rename_noreplace(artifact, "published").unwrap()
        else {
            panic!("sync cut must return recovery authority")
        };
        assert_eq!(
            std::fs::read(temp.path().join("published")).unwrap(),
            b"exact"
        );
        assert!(matches!(
            held.reconcile(&recovery).unwrap(),
            HeldDirectoryEffectOutcome::AppliedDurable(_)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn noncollision_publish_failure_retains_source_authority_for_retry() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = HeldDirectoryAuthority::open_existing(temp.path()).unwrap();
        let mut artifact = held.create_file_exclusive("temporary").unwrap();
        artifact.file_mut().write_all(b"exact").unwrap();
        let artifact = held.seal(artifact).unwrap();
        FORCE_PUBLISH_NONCOLLISION_FAILURE.set(true);
        let HeldDirectoryEffectOutcome::AppliedUnknown(recovery) =
            held.rename_noreplace(artifact, "published").unwrap()
        else {
            panic!("noncollision syscall failure must retain recovery authority")
        };
        let HeldDirectoryEffectOutcome::ProvenNotApplied(retained) =
            held.reconcile(&recovery).unwrap()
        else {
            panic!("exact absent destination and source must be retryable")
        };
        assert!(matches!(
            held.rename_noreplace(retained, "published").unwrap(),
            HeldDirectoryEffectOutcome::AppliedDurable(_)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_failure_and_metadata_after_cleanup_reconcile_without_generic_error() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = HeldDirectoryAuthority::open_existing(temp.path()).unwrap();
        let mut artifact = held.create_file_exclusive("temporary").unwrap();
        artifact.file_mut().write_all(b"exact").unwrap();
        let artifact = held.seal(artifact).unwrap();
        FORCE_SOURCE_CLEANUP_FAILURE.set(true);
        let HeldDirectoryEffectOutcome::AppliedUnknown(recovery) =
            held.rename_noreplace(artifact, "published").unwrap()
        else {
            panic!("source cleanup failure must retain recovery authority")
        };
        FORCE_POST_CLEANUP_METADATA_FAILURE.set(true);
        assert!(matches!(
            held.reconcile(&recovery).unwrap(),
            HeldDirectoryEffectOutcome::AppliedUnknown(_)
        ));
        assert!(!temp.path().join("temporary").exists());
        assert!(matches!(
            held.reconcile(&recovery).unwrap(),
            HeldDirectoryEffectOutcome::AppliedDurable(_)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn delete_sync_unknown_reconciles_exact_not_found_as_durable() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = HeldDirectoryAuthority::open_existing(temp.path()).unwrap();
        let mut artifact = held.create_file_exclusive("temporary").unwrap();
        artifact.file_mut().write_all(b"exact").unwrap();
        let artifact = held.seal(artifact).unwrap();
        FORCE_DIRECTORY_SYNC_FAILURE.set(true);
        let HeldDirectoryEffectOutcome::AppliedUnknown(recovery) = held.unlink(artifact).unwrap()
        else {
            panic!("post-delete sync failure must retain recovery authority")
        };
        assert!(matches!(
            held.reconcile(&recovery).unwrap(),
            HeldDirectoryEffectOutcome::AppliedDurable(_)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pre_syscall_name_swap_cannot_change_published_held_bytes() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = HeldDirectoryAuthority::open_existing(temp.path()).unwrap();
        let mut artifact = held.create_file_exclusive("temporary").unwrap();
        artifact.file_mut().write_all(b"held-exact").unwrap();
        let artifact = held.seal(artifact).unwrap();
        let root = temp.path().to_path_buf();
        BEFORE_PUBLISH_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(root.join("temporary"), root.join("attacker-moved")).unwrap();
                std::fs::write(root.join("temporary"), b"planted").unwrap();
                std::fs::set_permissions(
                    root.join("temporary"),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }))
        });
        assert!(matches!(
            held.rename_noreplace(artifact, "published").unwrap(),
            HeldDirectoryEffectOutcome::AppliedUnknown(_)
        ));
        assert_eq!(
            std::fs::read(temp.path().join("published")).unwrap(),
            b"held-exact"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn post_effect_same_inode_content_and_mode_races_are_not_routable() {
        for mutate in ["content", "mode"] {
            let temp = tempfile::TempDir::new().unwrap();
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let held = HeldDirectoryAuthority::open_existing(temp.path()).unwrap();
            let mut artifact = held.create_file_exclusive("temporary").unwrap();
            artifact.file_mut().write_all(b"exact").unwrap();
            let artifact = held.seal(artifact).unwrap();
            let root = temp.path().to_path_buf();
            AFTER_PUBLISH_EFFECT_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    if mutate == "content" {
                        std::fs::write(root.join("published"), b"changed").unwrap();
                    } else {
                        std::fs::set_permissions(
                            root.join("published"),
                            std::fs::Permissions::from_mode(0o644),
                        )
                        .unwrap();
                    }
                }))
            });
            assert!(
                matches!(
                    held.rename_noreplace(artifact, "published").unwrap(),
                    HeldDirectoryEffectOutcome::AppliedUnknown(_)
                ),
                "{mutate}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn successful_publish_and_unlink_return_exact_durable_evidence() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = HeldDirectoryAuthority::open_existing(temp.path()).unwrap();
        let mut artifact = held.create_file_exclusive("temporary").unwrap();
        artifact.file_mut().write_all(b"exact").unwrap();
        let artifact = held.seal(artifact).unwrap();
        let expected = artifact.evidence().clone();
        let HeldDirectoryEffectOutcome::AppliedDurable(applied) =
            held.rename_noreplace(artifact, "published").unwrap()
        else {
            panic!("publish must be durable")
        };
        assert_eq!(applied.destination_name(), Some("published"));
        assert_eq!(applied.artifact(), &expected);

        let file = imp::open_named(held.imp.test_dir(), "published").unwrap();
        let sealed = HeldSealedArtifact {
            file,
            name: "published".into(),
            evidence: expected.clone(),
        };
        let HeldDirectoryEffectOutcome::AppliedDurable(deleted) = held.unlink(sealed).unwrap()
        else {
            panic!("unlink must be durable")
        };
        assert_eq!(deleted.destination_name(), None);
        assert_eq!(deleted.artifact(), &expected);
        assert!(!temp.path().join("published").exists());
    }

    #[test]
    fn unix_absence_proof_is_only_exact_enoent() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = HeldDirectoryAuthority::open_existing(temp.path()).unwrap();
        assert!(imp::entry_absent(held.imp.test_dir(), "missing").unwrap());
        symlink(
            temp.path().join("missing-target"),
            temp.path().join("ambiguous"),
        )
        .unwrap();
        assert!(!imp::entry_absent(held.imp.test_dir(), "ambiguous").unwrap());
        assert!(imp::open_named(held.imp.test_dir(), "ambiguous").is_err());
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::os::windows::fs::symlink_dir;

    use super::*;

    #[test]
    fn held_windows_package_reopens_enumerated_names_case_sensitively() {
        let attributes = imp::enumerated_relative_object_attributes();
        assert_eq!(
            attributes & 0x40,
            0,
            "agent.md and AGENT.md must remain distinct after enumeration"
        );
        assert_ne!(
            attributes & 0x1000,
            0,
            "the exact-case reopen must retain the no-reparse boundary"
        );
    }

    #[test]
    fn held_windows_authority_rejects_reparse_and_publishes_noreplace() {
        let temp = tempfile::TempDir::new().unwrap();
        let output = temp.path().join("output");
        std::fs::create_dir(&output).unwrap();
        crate::goal_scratch::set_private(&output).unwrap();
        let held = HeldDirectoryAuthority::open_existing(&output).unwrap();
        let mut temporary = held.create_file_exclusive("temporary").unwrap();
        temporary.file_mut().write_all(b"new").unwrap();
        let temporary = held.seal(temporary).unwrap();
        let mut published = held.create_file_exclusive("published").unwrap();
        published.file_mut().write_all(b"old").unwrap();
        let HeldDirectoryEffectOutcome::ProvenNotApplied(retained) =
            held.rename_noreplace(temporary, "published").unwrap()
        else {
            panic!("collision must return retained source authority")
        };
        assert!(output.join("temporary").exists());
        assert_eq!(std::fs::read(output.join("published")).unwrap(), b"old");
        assert!(matches!(
            held.unlink(retained).unwrap(),
            HeldDirectoryEffectOutcome::AppliedDurable(_)
        ));
        assert!(!output.join("temporary").exists());
        let alias = temp.path().join("alias");
        if symlink_dir(&output, &alias).is_ok() {
            assert!(HeldDirectoryAuthority::open_existing(&alias).is_err());
        }
    }

    #[test]
    fn held_windows_capability_survives_name_replacement() {
        let temp = tempfile::TempDir::new().unwrap();
        let output = temp.path().join("output");
        std::fs::create_dir(&output).unwrap();
        crate::goal_scratch::set_private(&output).unwrap();
        let held = HeldDirectoryAuthority::open_existing(&output).unwrap();
        let original = held.identity().clone();
        let moved = temp.path().join("moved");
        std::fs::rename(&output, &moved).unwrap();
        std::fs::create_dir(&output).unwrap();
        crate::goal_scratch::set_private(&output).unwrap();
        assert_ne!(
            original,
            HeldDirectoryAuthority::open_existing(&output)
                .unwrap()
                .identity()
                .clone()
        );
        held.create_file_exclusive("proof").unwrap();
        assert!(moved.join("proof").is_file());
        assert!(!output.join("proof").exists());
    }

    #[test]
    fn held_windows_artifact_rejects_link_and_same_byte_file_id_swap() {
        let temp = tempfile::TempDir::new().unwrap();
        let output = temp.path().join("output");
        std::fs::create_dir(&output).unwrap();
        crate::goal_scratch::set_private(&output).unwrap();
        let held = HeldDirectoryAuthority::open_existing(&output).unwrap();
        let mut artifact = held.create_file_exclusive("artifact").unwrap();
        artifact.file_mut().write_all(b"same").unwrap();
        let artifact = held.seal(artifact).unwrap();
        std::fs::hard_link(output.join("artifact"), output.join("other-link")).unwrap();
        assert!(matches!(
            held.rename_noreplace(artifact, "published").unwrap(),
            HeldDirectoryEffectOutcome::SecurityAmbiguous(_)
        ));

        let mut artifact = held.create_file_exclusive("swap").unwrap();
        artifact.file_mut().write_all(b"same").unwrap();
        let artifact = held.seal(artifact).unwrap();
        std::fs::rename(output.join("swap"), output.join("moved-swap")).unwrap();
        std::fs::write(output.join("swap"), b"same").unwrap();
        crate::goal_scratch::set_private(&output.join("swap")).unwrap();
        assert!(matches!(
            held.rename_noreplace(artifact, "published").unwrap(),
            HeldDirectoryEffectOutcome::SecurityAmbiguous(_)
        ));
    }

    #[test]
    fn held_windows_post_effect_dacl_race_returns_recovery_authority() {
        let temp = tempfile::TempDir::new().unwrap();
        let output = temp.path().join("output");
        std::fs::create_dir(&output).unwrap();
        crate::goal_scratch::set_private(&output).unwrap();
        let held = HeldDirectoryAuthority::open_existing(&output).unwrap();
        let mut artifact = held.create_file_exclusive("temporary").unwrap();
        artifact.file_mut().write_all(b"exact").unwrap();
        let artifact = held.seal(artifact).unwrap();
        let root = output.clone();
        AFTER_PUBLISH_EFFECT_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                crate::goal_scratch::apply_test_windows_dacl(
                    &root.join("published"),
                    "D:(A;;FA;;;WD)",
                )
                .unwrap();
            }))
        });
        assert!(matches!(
            held.rename_noreplace(artifact, "published").unwrap(),
            HeldDirectoryEffectOutcome::AppliedUnknown(_)
        ));
    }

    #[test]
    fn held_windows_unknown_reconciles_and_mutation_blocks_reconcile() {
        let temp = tempfile::TempDir::new().unwrap();
        let output = temp.path().join("output");
        std::fs::create_dir(&output).unwrap();
        crate::goal_scratch::set_private(&output).unwrap();
        let held = HeldDirectoryAuthority::open_existing(&output).unwrap();
        let mut artifact = held.create_file_exclusive("temporary").unwrap();
        artifact.file_mut().write_all(b"exact").unwrap();
        let artifact = held.seal(artifact).unwrap();
        FORCE_DIRECTORY_SYNC_FAILURE.set(true);
        let HeldDirectoryEffectOutcome::AppliedUnknown(recovery) =
            held.rename_noreplace(artifact, "published").unwrap()
        else {
            panic!("sync cut must be recoverable")
        };
        assert!(matches!(
            held.reconcile(&recovery).unwrap(),
            HeldDirectoryEffectOutcome::AppliedDurable(_)
        ));
        std::fs::write(output.join("published"), b"changed").unwrap();
        assert!(matches!(
            held.reconcile(&recovery).unwrap(),
            HeldDirectoryEffectOutcome::SecurityAmbiguous(_)
        ));
        assert!(held.delete_recovered_destination(&recovery).is_err());
    }

    #[test]
    fn held_windows_rename_and_delete_failures_retain_retry_authority() {
        let temp = tempfile::TempDir::new().unwrap();
        let output = temp.path().join("output");
        std::fs::create_dir(&output).unwrap();
        crate::goal_scratch::set_private(&output).unwrap();
        let held = HeldDirectoryAuthority::open_existing(&output).unwrap();
        let mut artifact = held.create_file_exclusive("temporary").unwrap();
        artifact.file_mut().write_all(b"exact").unwrap();
        let artifact = held.seal(artifact).unwrap();
        FORCE_PUBLISH_NONCOLLISION_FAILURE.set(true);
        let HeldDirectoryEffectOutcome::AppliedUnknown(recovery) =
            held.rename_noreplace(artifact, "published").unwrap()
        else {
            panic!("rename failure must return recovery authority")
        };
        let HeldDirectoryEffectOutcome::ProvenNotApplied(retained) =
            held.reconcile(&recovery).unwrap()
        else {
            panic!("absent destination must recover the source")
        };
        FORCE_SOURCE_CLEANUP_FAILURE.set(true);
        let HeldDirectoryEffectOutcome::ProvenNotApplied(retained) = held.unlink(retained).unwrap()
        else {
            panic!("failed delete with exact source must retain it")
        };
        assert!(matches!(
            held.unlink(retained).unwrap(),
            HeldDirectoryEffectOutcome::AppliedDurable(_)
        ));
    }

    #[test]
    fn held_windows_delete_sync_unknown_reconciles_not_found() {
        let temp = tempfile::TempDir::new().unwrap();
        let output = temp.path().join("output");
        std::fs::create_dir(&output).unwrap();
        crate::goal_scratch::set_private(&output).unwrap();
        let held = HeldDirectoryAuthority::open_existing(&output).unwrap();
        let mut artifact = held.create_file_exclusive("temporary").unwrap();
        artifact.file_mut().write_all(b"exact").unwrap();
        let artifact = held.seal(artifact).unwrap();
        FORCE_DIRECTORY_SYNC_FAILURE.set(true);
        let HeldDirectoryEffectOutcome::AppliedUnknown(recovery) = held.unlink(artifact).unwrap()
        else {
            panic!("directory sync failure after delete must be recoverable")
        };
        assert!(matches!(
            held.reconcile(&recovery).unwrap(),
            HeldDirectoryEffectOutcome::AppliedDurable(_)
        ));
    }
}
