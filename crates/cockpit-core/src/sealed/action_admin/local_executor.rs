//! Command, environment, and file sealed-action sinks.
//!
//! Every target is part of the immutable Owner-authored action snapshot. The
//! model supplies only the action id and bounded declared parameters. Commands
//! are spawned directly (never through a shell), and argument/environment
//! injection never writes plaintext to disk. File injection is the deliberate
//! downgrade: the destination is pinned, mode 0600, git guarded, and ephemeral
//! unless the snapshot records explicit persistent approval. Linux keeps using
//! `$XDG_RUNTIME_DIR`; macOS falls back only to the OS-provided private user
//! temp root when XDG is absent. Other platforms fail closed rather than
//! placing ephemeral plaintext in a persistent or shared temp location.

use std::collections::BTreeMap;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{SealedActionKind, SealedActionSnapshot, SealedParamSpecJson};
use crate::sealed::action::{
    SealedActionDescriptor, SealedHostAction, SealedParamValue, SealedParams,
};
use crate::sealed::compartment::SealedLiteralHandle;

/// Exact token replaced by the sealed literal in an argument-injection action.
pub const SEALED_VALUE_ARG_PLACEHOLDER: &str = "{{sealed_value}}";
/// Exact token replaced by the materialized path in a file consumer action.
pub const SEALED_FILE_PATH_PLACEHOLDER: &str = "{{sealed_file}}";
const MAX_COMMAND_PARTS: usize = 128;
const MAX_COMMAND_PART_BYTES: usize = 4_096;

/// File destinations are named external resources, not invocation resources.
/// Serializing the complete write → consume → verify-delete sequence is the
/// ownership fence for pinned paths. Private-runtime destinations also receive
/// a fresh invocation directory, but share this fence so a future destination
/// implementation cannot accidentally reintroduce the same race.
static FILE_MATERIALIZATION_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

/// Mandatory approval copy for persistent materialization. Owner surfaces that
/// offer this downgrade must present this warning before constructing
/// [`FilePersistence::PersistentOwnerApproved`].
pub const PERSISTENT_FILE_APPROVAL_WARNING: &str = "Persistent materialization writes plaintext to the pinned path until you remove it. The consuming process can transform or exfiltrate the value (for example with base64), and redaction can only scrub known representations. Approve only this declared action and destination.";

/// Stable identity and byte digest for an approved executable. The canonical
/// path is only a locator: execution reopens it through no-follow rules and
/// proves both its platform identity and its exact approved contents before
/// using the object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableIdentity {
    stable_id: String,
    content_sha256: String,
}

impl ExecutableIdentity {
    /// Transient create-request value. `SealedActionDirectory::create` replaces
    /// it before validation/persistence; a persisted zero identity is rejected.
    pub fn unpinned() -> Self {
        Self {
            stable_id: String::new(),
            content_sha256: String::new(),
        }
    }

    fn capture(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt as _;
        #[cfg(windows)]
        use std::os::windows::fs::OpenOptionsExt as _;

        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        #[cfg(windows)]
        {
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            options
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut file = options.open(path).with_context(|| {
            format!(
                "opening sealed action executable without following its final component {}",
                path.display()
            )
        })?;
        Self::from_open_file(&mut file).with_context(|| {
            format!(
                "capturing sealed action executable identity {}",
                path.display()
            )
        })
    }

    fn from_open_file(file: &mut std::fs::File) -> Result<Self> {
        Ok(Self {
            stable_id:
                cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority::regular_file_identity(file)
                    .context("capturing opened sealed action file identity")?,
            content_sha256: sha256_file(file)
                .context("hashing opened sealed action executable contents")?,
        })
    }

    /// Copy the approved bytes into a caller-owned execution object while
    /// hashing the copy itself. The destination can subsequently be made
    /// immutable, closing the source-file write race between verification and
    /// exec without ever trusting the mutable source descriptor as executable
    /// authority.
    pub(crate) fn copy_approved_bytes(
        &self,
        source: &mut std::fs::File,
        destination: &mut std::fs::File,
    ) -> Result<()> {
        let source_id = cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority::regular_file_identity(source)
            .context("capturing sealed action source executable identity")?;
        if source_id != self.stable_id {
            bail!("sealed action executable identity changed");
        }
        source.seek(SeekFrom::Start(0))?;
        destination.seek(SeekFrom::Start(0))?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 32 * 1024];
        loop {
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            destination.write_all(&buffer[..read])?;
            hasher.update(&buffer[..read]);
        }
        destination.flush()?;
        destination.seek(SeekFrom::Start(0))?;
        if crate::intel::hex_lower(&hasher.finalize()) != self.content_sha256 {
            bail!("sealed action executable contents changed");
        }
        Ok(())
    }

    #[cfg(any(test, not(any(target_os = "linux", target_os = "android"))))]
    pub(crate) fn matches(&self, file: &mut std::fs::File) -> Result<bool> {
        let actual = Self::from_open_file(file)?;
        Ok(actual.stable_id == self.stable_id && actual.content_sha256 == self.content_sha256)
    }

    pub(crate) fn is_pinned(&self) -> bool {
        !self.stable_id.is_empty() && !self.content_sha256.is_empty()
    }
}

/// Runtime-only identity for a materialized file. Unlike an executable
/// identity it intentionally has no content digest: hashing the sealed bytes
/// would retain a password-derived value beyond the write/consume lifetime.
#[derive(Debug, Clone)]
struct MaterializedFileIdentity {
    stable_id: String,
}

impl MaterializedFileIdentity {
    fn from_file(file: &std::fs::File) -> Result<Self> {
        Ok(Self {
            stable_id:
                cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority::regular_file_identity(file)
                    .context("capturing opened sealed materialized-file identity")?,
        })
    }

    fn matches(&self, file: &std::fs::File) -> Result<bool> {
        Ok(Self::from_file(file)?.stable_id == self.stable_id)
    }
}

fn sha256_file(file: &mut std::fs::File) -> Result<String> {
    file.seek(SeekFrom::Start(0))
        .context("seeking sealed action executable for hashing")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .context("reading sealed action executable for hashing")?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))
        .context("rewinding sealed action executable after hashing")?;
    Ok(crate::intel::hex_lower(&hasher.finalize()))
}

/// Where a fixed command receives the sealed literal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandInjection {
    Argument,
    Environment { variable: String },
}

impl CommandInjection {
    pub fn sink_kind(&self) -> &'static str {
        match self {
            Self::Argument => "command_arg",
            Self::Environment { .. } => "process_env",
        }
    }
}

/// Owner-pinned destination policy for a file action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileDestination {
    /// Materialize below the platform's private runtime root: `$XDG_RUNTIME_DIR`
    /// on Linux/Android, or macOS's OS-provided per-user temp root when XDG is
    /// absent. The fixed filename may not contain separators.
    PrivateRuntime { filename: String },
    /// A fixed absolute path for a consumer that cannot accept another path.
    Pinned {
        /// Canonical parent plus one filename, captured before persistence.
        /// The identity is checked again through a held directory before any
        /// git inspection, materialization, consumer spawn, or cleanup.
        path: PathBuf,
        parent_identity: FileSystemIdentity,
    },
}

/// Stable identity for a filesystem object, persisted with an immutable action
/// snapshot. A pathname is merely a locator; this is the host's platform
/// identity digest (Unix device/inode, Windows volume/file-index).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSystemIdentity {
    stable_id: String,
}

impl FileSystemIdentity {
    /// Transient create-request value, replaced by `pin_file_destination` at
    /// the sole persistence entry point.
    pub fn unpinned() -> Self {
        Self {
            stable_id: String::new(),
        }
    }
    fn capture_directory(path: &Path) -> Result<Self> {
        let held = cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority::open_existing(path)
            .with_context(|| format!("opening pinned sealed-file parent {}", path.display()))?;
        Ok(Self {
            stable_id: held.identity().to_owned(),
        })
    }
}

/// Persistent materialization is a distinct Owner-approved action shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilePersistence {
    Ephemeral,
    /// The Owner RPC records the exact mandatory warning and the approval
    /// instant in the immutable action snapshot. A bare persistence label is
    /// deliberately not sufficient evidence of the downgrade ceremony.
    PersistentOwnerApproved(PersistentFileApproval),
}

/// Opaque evidence recorded in a persistent-file snapshot. Its fields are not
/// constructible outside this module; callers must use the acknowledgement
/// constructor, which rejects any text other than the mandatory warning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentFileApproval {
    acknowledged_at_ms: i64,
    warning: String,
}

impl PersistentFileApproval {
    pub fn acknowledge(acknowledged_at_ms: i64, warning: &str) -> Result<Self> {
        if acknowledged_at_ms <= 0 || warning != PERSISTENT_FILE_APPROVAL_WARNING {
            bail!(
                "persistent sealed-file action requires acknowledgement of the mandatory warning"
            );
        }
        Ok(Self {
            acknowledged_at_ms,
            warning: warning.to_string(),
        })
    }
}

impl FilePersistence {
    pub fn is_persistent(&self) -> bool {
        matches!(self, Self::PersistentOwnerApproved(_))
    }
}

pub fn validate_command_kind(
    argv_template: &[String],
    executable_identity: &ExecutableIdentity,
    injection: &CommandInjection,
    parameters: &BTreeMap<String, SealedParamSpecJson>,
) -> Result<()> {
    validate_argv(argv_template, SEALED_VALUE_ARG_PLACEHOLDER)?;
    if !executable_identity.is_pinned() {
        bail!("command action executable has not been identity-pinned");
    }
    if parameters.len() > super::MAX_SEALED_ACTION_PARAMS {
        bail!("command action declares too many parameters");
    }
    let placeholder_count = argv_template
        .iter()
        .filter(|part| part.as_str() == SEALED_VALUE_ARG_PLACEHOLDER)
        .count();
    match injection {
        CommandInjection::Argument if placeholder_count != 1 => {
            bail!("argument injection requires exactly one sealed-value placeholder")
        }
        CommandInjection::Environment { variable } => {
            if placeholder_count != 0 {
                bail!("environment injection must not contain an argument placeholder");
            }
            validate_environment_name(variable)?;
        }
        CommandInjection::Argument => {}
    }
    // Reuse the descriptor compiler as the authority for bounded parameter
    // validity; parameters are not interpolated into argv in this launch shape.
    for (name, spec) in parameters {
        let runtime = spec.to_spec();
        let descriptor = SealedActionDescriptor {
            action_id: crate::sealed::action::SealedActionId::parse("validation")?,
            revision: crate::sealed::action::SealedActionRevision::new(1)?,
            summary: String::new(),
            parameters: [(name.clone(), runtime)].into_iter().collect(),
            completion: crate::sealed::action::SealedCompletion::default(),
            response_after_ms: 1,
        };
        descriptor.validate()?;
    }
    Ok(())
}

/// Resolve the owner-selected executable exactly once, before the immutable
/// action snapshot is persisted. Later invocation never performs PATH lookup.
pub fn pin_argv_executable(argv: &mut [String]) -> Result<ExecutableIdentity> {
    let program = argv
        .first_mut()
        .context("sealed action argv must contain an executable")?;
    let path = Path::new(program);
    if !path.is_absolute() {
        bail!("sealed action executable must be an absolute path");
    }
    let canonical = std::fs::canonicalize(path).context("resolving sealed action executable")?;
    let identity = ExecutableIdentity::capture(&canonical)?;
    *program = canonical.to_string_lossy().into_owned();
    Ok(identity)
}

/// Canonicalize and identity-pin an owner-selected fixed file destination.
/// The path is reduced to a canonical parent and one plain filename; later
/// execution uses the parent identity, not a fresh pathname walk.
pub fn pin_file_destination(destination: &mut FileDestination) -> Result<()> {
    let FileDestination::Pinned {
        path,
        parent_identity,
    } = destination
    else {
        return Ok(());
    };
    let filename = path
        .file_name()
        .context("pinned sealed-file destination must name a file")?
        .to_os_string();
    let parent = path
        .parent()
        .context("pinned sealed-file destination has no parent")?;
    let canonical_parent =
        std::fs::canonicalize(parent).context("resolving pinned sealed-file destination parent")?;
    if !canonical_parent.is_dir() {
        bail!("pinned sealed-file destination parent is not a directory");
    }
    *parent_identity = FileSystemIdentity::capture_directory(&canonical_parent)?;
    *path = canonical_parent.join(filename);
    Ok(())
}

pub fn validate_file_kind(
    destination: &FileDestination,
    persistence: FilePersistence,
    consumer_argv: &[String],
    consumer_executable_identity: Option<&ExecutableIdentity>,
) -> Result<()> {
    if let FilePersistence::PersistentOwnerApproved(approval) = &persistence {
        PersistentFileApproval::acknowledge(approval.acknowledged_at_ms, &approval.warning)?;
    }
    match destination {
        FileDestination::PrivateRuntime { filename } => {
            if filename.is_empty()
                || filename.len() > 128
                || filename == "."
                || filename == ".."
                || filename.contains('/')
                || filename.contains('\\')
            {
                bail!("private-runtime filename must be one safe path component");
            }
        }
        FileDestination::Pinned {
            path,
            parent_identity,
        } => {
            if !path.is_absolute() {
                bail!("pinned sealed-file destination must be absolute");
            }
            if path.file_name().is_none() {
                bail!("pinned sealed-file destination must name a file");
            }
            if parent_identity.stable_id.is_empty() {
                bail!("pinned sealed-file destination has not been identity-pinned");
            }
        }
    }
    if persistence == FilePersistence::Ephemeral && consumer_argv.is_empty() {
        bail!("ephemeral file actions require a fixed consuming command");
    }
    if !consumer_argv.is_empty() {
        validate_argv(consumer_argv, SEALED_FILE_PATH_PLACEHOLDER)?;
        let identity = consumer_executable_identity
            .context("file consumer executable has not been identity-pinned")?;
        if !identity.is_pinned() {
            bail!("file consumer executable has not been identity-pinned");
        }
        if consumer_argv
            .iter()
            .filter(|part| part.as_str() == SEALED_FILE_PATH_PLACEHOLDER)
            .count()
            != 1
        {
            bail!("file consumer requires exactly one sealed-file placeholder");
        }
    }
    Ok(())
}

fn validate_argv(argv: &[String], allowed_placeholder: &str) -> Result<()> {
    if argv.is_empty() || argv.len() > MAX_COMMAND_PARTS {
        bail!("sealed action argv must contain 1..={MAX_COMMAND_PARTS} parts");
    }
    for part in argv {
        if part.is_empty() || part.len() > MAX_COMMAND_PART_BYTES || part.contains('\0') {
            bail!("sealed action argv contains an invalid part");
        }
        if part.contains("{{") && part != allowed_placeholder {
            bail!("sealed action argv contains an unknown placeholder");
        }
    }
    if !Path::new(&argv[0]).is_absolute() {
        bail!("sealed action executable must be an absolute, owner-pinned path");
    }
    Ok(())
}

fn validate_environment_name(name: &str) -> Result<()> {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        bail!("environment variable name must not be empty");
    };
    if !(first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || name.len() > 128
    {
        bail!("environment variable name is invalid");
    }
    Ok(())
}

#[derive(Debug)]
pub struct CommandSealedAction {
    descriptor: SealedActionDescriptor,
    argv_template: Vec<String>,
    executable_identity: ExecutableIdentity,
    injection: CommandInjection,
}

impl CommandSealedAction {
    pub fn from_snapshot(snapshot: &SealedActionSnapshot) -> Result<Self> {
        let SealedActionKind::Command {
            argv_template,
            executable_identity,
            injection,
            parameters,
        } = &snapshot.kind
        else {
            bail!("command executor requires a command action snapshot");
        };
        validate_command_kind(argv_template, executable_identity, injection, parameters)?;
        Ok(Self {
            descriptor: snapshot.kind.compile_descriptor(
                &snapshot.action_id,
                snapshot.revision,
                &snapshot.description,
            )?,
            argv_template: argv_template.clone(),
            executable_identity: executable_identity.clone(),
            injection: injection.clone(),
        })
    }
}

#[async_trait]
impl SealedHostAction for CommandSealedAction {
    fn descriptor(&self) -> &SealedActionDescriptor {
        &self.descriptor
    }

    fn sink_kind(&self) -> &'static str {
        self.injection.sink_kind()
    }

    async fn invoke(&self, literal: SealedLiteralHandle<'_>, params: &SealedParams) -> Result<()> {
        rebind_params(&self.descriptor, params)?;
        // The substituted argv copy is wiped when invocation finishes; only
        // the child process receives another OS-owned copy.
        let mut argv = zeroize::Zeroizing::new(self.argv_template.clone());
        let mut environment = None;
        match &self.injection {
            CommandInjection::Argument => {
                let part = argv
                    .iter_mut()
                    .find(|part| part.as_str() == SEALED_VALUE_ARG_PLACEHOLDER)
                    .context("sealed argument placeholder vanished")?;
                *part = literal.expose().to_string();
            }
            CommandInjection::Environment { variable } => {
                environment = Some((variable.as_str(), literal.expose()));
            }
        }
        run_command_scrubbed(
            &argv,
            environment,
            literal.expose(),
            Some(self.executable_identity.clone()),
        )
        .await
    }
}

#[derive(Debug)]
pub struct FileSealedAction {
    descriptor: SealedActionDescriptor,
    destination: FileDestination,
    persistence: FilePersistence,
    consumer_argv: Vec<String>,
    consumer_executable_identity: Option<ExecutableIdentity>,
}

impl FileSealedAction {
    pub fn from_snapshot(snapshot: &SealedActionSnapshot) -> Result<Self> {
        let SealedActionKind::File {
            destination,
            persistence,
            consumer_argv,
            consumer_executable_identity,
        } = &snapshot.kind
        else {
            bail!("file executor requires a file action snapshot");
        };
        validate_file_kind(
            destination,
            persistence.clone(),
            consumer_argv,
            consumer_executable_identity.as_ref(),
        )?;
        Ok(Self {
            descriptor: snapshot.kind.compile_descriptor(
                &snapshot.action_id,
                snapshot.revision,
                &snapshot.description,
            )?,
            destination: destination.clone(),
            persistence: persistence.clone(),
            consumer_argv: consumer_argv.clone(),
            consumer_executable_identity: consumer_executable_identity.clone(),
        })
    }
}

#[async_trait]
impl SealedHostAction for FileSealedAction {
    fn descriptor(&self) -> &SealedActionDescriptor {
        &self.descriptor
    }

    fn sink_kind(&self) -> &'static str {
        "file"
    }

    fn file_persistent(&self) -> bool {
        self.persistence.is_persistent()
    }

    async fn invoke(&self, literal: SealedLiteralHandle<'_>, _params: &SealedParams) -> Result<()> {
        // A destination may be externally pinned, so a UUID alone is not an
        // ownership proof. Acquire this *after* the sealed runtime slot and
        // before any filesystem/process work; no called path acquires it.
        let _destination_guard = FILE_MATERIALIZATION_LOCK
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await;
        let resolved = resolve_destination(&self.destination)?;
        let path = &resolved.path;
        git_leak_guard(&resolved).await?;
        // An ephemeral pinned target is always a new inode.  It must never
        // truncate or delete a pre-existing owner file merely because the
        // action happened to use the same declared pathname.
        let file_identity = write_private_file(
            &resolved,
            literal.expose(),
            !self.persistence.is_persistent(),
        )?;
        let cleanup = EphemeralFile::new(
            path.clone(),
            !self.persistence.is_persistent(),
            file_identity.clone(),
        );
        let held_materialized = hold_materialized_file(path, file_identity.clone())?;
        let consumer_path = retained_materialized_path(path, held_materialized.as_ref())?;
        let consume_result = if !self.consumer_argv.is_empty() {
            let rendered = zeroize::Zeroizing::new(
                self.consumer_argv
                    .iter()
                    .map(|part| {
                        if part == SEALED_FILE_PATH_PLACEHOLDER {
                            consumer_path.to_string_lossy().into_owned()
                        } else {
                            part.clone()
                        }
                    })
                    .collect::<Vec<_>>(),
            );
            resolved.revalidate_before_spawn()?;
            run_command_scrubbed(
                &rendered,
                None,
                literal.expose(),
                self.consumer_executable_identity.clone(),
            )
            .await
        } else {
            Ok(())
        };
        drop(held_materialized);
        // Completion is not reported until the consuming step's materialized
        // plaintext has been removed. `Drop` remains only cancellation/panic
        // backstop; its failure cannot turn a normal invocation into success.
        let cleanup_result = cleanup.remove();
        consume_result?;
        cleanup_result?;
        Ok(())
    }
}

fn rebind_params(descriptor: &SealedActionDescriptor, params: &SealedParams) -> Result<()> {
    let supplied: BTreeMap<String, SealedParamValue> = params
        .names()
        .filter_map(|name| {
            params
                .get(name)
                .map(|value| (name.to_string(), value.clone()))
        })
        .collect();
    descriptor.bind_parameters(&supplied)?;
    Ok(())
}

async fn run_command_scrubbed(
    argv: &[String],
    environment: Option<(&str, &str)>,
    literal: &str,
    executable_identity: Option<ExecutableIdentity>,
) -> Result<()> {
    let output =
        crate::secret_command::run_injected_process(argv, environment, executable_identity)
            .await
            .map_err(|error| anyhow::anyhow!(error.code()))?;
    // All captured output passes through the same literal/encoded-variant
    // scrub before it can be inspected or attached to a diagnostic. The action
    // currently discards it, but keeping this boundary explicit prevents a
    // future safe-projection adapter from accidentally bypassing redaction.
    let _stdout = scrub_output(&output.stdout, literal);
    let _stderr = scrub_output(&output.stderr, literal);
    if !output.success {
        bail!("sealed command exited unsuccessfully");
    }
    Ok(())
}

fn scrub_output(bytes: &[u8], literal: &str) -> String {
    crate::redact::RedactionTable::scrub_injected_output(&String::from_utf8_lossy(bytes), literal)
}

struct ResolvedDestination {
    path: PathBuf,
    git_guard: GitGuard,
    // Kept alive through git inspection, file creation, child spawn, and
    // cleanup. On Linux/Android `path` and the Git working directory are
    // rooted at this descriptor via procfs.
    _pinned_parent:
        Option<cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority>,
    #[cfg(windows)]
    _pinned_windows_execution_lease:
        Option<cockpit_host::private_fs::held_directory::WindowsWorkspaceExecutionLease>,
}

enum GitGuard {
    Skip,
    /// Both the Git working directory and the destination pathspec are
    /// derived from the retained parent.  A diagnostic spelling captured at
    /// approval must never become an operational Git authority.
    Inspect {
        repo_parent: PathBuf,
        destination_name: String,
    },
}

fn resolve_destination(destination: &FileDestination) -> Result<ResolvedDestination> {
    match destination {
        FileDestination::Pinned {
            path,
            parent_identity,
        } => {
            let parent = path
                .parent()
                .context("pinned sealed-file destination has no parent")?;
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .context("pinned sealed-file destination filename is not valid UTF-8")?
                .to_owned();
            let held = cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority::open_existing(parent)
                .context("opening pinned sealed-file parent through no-follow authority")?;
            if held.identity() != parent_identity.stable_id.as_str() {
                bail!("pinned sealed-file destination parent identity changed since approval");
            }
            #[cfg(windows)]
            let windows_execution_lease = Some(
                held.acquire_windows_execution_lease(parent)
                    .context("leasing pinned sealed-file parent for Windows consumer path")?,
            );
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let path = held
                .retained_relative_path(&name)
                .context("creating retained pinned sealed-file destination path")?;
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            let path = path.clone();
            // macOS has no procfs descriptor path, and the host layer does
            // not yet offer an equivalent retained-directory execution
            // capability. Re-opening the approved spelling would let a
            // parent replacement redirect the plaintext write, Git guard,
            // consumer path, or cleanup, so reject pinned destinations.
            #[cfg(target_os = "macos")]
            bail!(
                "pinned sealed-file destinations are unsupported on macOS until retained-directory execution is available"
            );
            #[cfg(not(any(
                target_os = "linux",
                target_os = "android",
                target_os = "macos",
                windows
            )))]
            bail!("pinned sealed-file destinations are unsupported on this platform");
            let repo_parent = path
                .parent()
                .context("retained pinned sealed-file destination has no parent")?
                .to_path_buf();
            Ok(ResolvedDestination {
                path,
                git_guard: GitGuard::Inspect {
                    repo_parent,
                    destination_name: name,
                },
                _pinned_parent: Some(held),
                #[cfg(windows)]
                _pinned_windows_execution_lease: windows_execution_lease,
            })
        }
        FileDestination::PrivateRuntime { filename } => {
            let runtime_dir = cockpit_host::private_fs::private_runtime_root().context(
                "sealed file materialization requires a private runtime root \
                 (absolute XDG_RUNTIME_DIR, or on macOS the OS-provided per-user temp root)",
            )?;
            let base = runtime_dir.join(format!(
                "flycockpit-sealed-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            cockpit_host::private_fs::ensure_private_dir(&base)
                .context("creating private sealed runtime directory")?;
            Ok(ResolvedDestination {
                path: base.join(filename),
                git_guard: GitGuard::Skip,
                _pinned_parent: None,
                #[cfg(windows)]
                _pinned_windows_execution_lease: None,
            })
        }
    }
}

impl ResolvedDestination {
    #[cfg(windows)]
    fn revalidate_before_spawn(&self) -> Result<()> {
        if let Some(lease) = &self._pinned_windows_execution_lease {
            lease.revalidate_before_spawn().context(
                "revalidating pinned sealed-file Windows execution lease before consumer spawn",
            )?;
        }
        Ok(())
    }

    #[cfg(not(windows))]
    fn revalidate_before_spawn(&self) -> Result<()> {
        let _ = self;
        Ok(())
    }
}

#[cfg(unix)]
fn write_private_file(
    resolved: &ResolvedDestination,
    literal: &str,
    exclusive: bool,
) -> Result<Option<MaterializedFileIdentity>> {
    let path = &resolved.path;
    if let Some(parent) = &resolved._pinned_parent {
        let name = path
            .file_name()
            .context("pinned sealed-file destination has no filename")?;
        let directory = parent
            .retained_directory_handle()
            .context("cloning retained pinned sealed-file parent")?;
        if exclusive {
            cockpit_host::private_fs::write_private_file_exclusive_in_dir_fd(
                &directory,
                name,
                path,
                literal.as_bytes(),
            )
            .context("writing private sealed file exclusively through retained parent")?;
        } else {
            cockpit_host::private_fs::write_private_file_in_dir_fd(
                &directory,
                name,
                path,
                literal.as_bytes(),
            )
            .map_err(|error| {
                let context = format!(
                    "atomically replacing private sealed file through retained parent: {error}"
                );
                error.context(context)
            })?;
        }
        let file = parent
            .open_regular_file_relative(&[name
                .to_str()
                .context("pinned sealed-file destination filename is not valid UTF-8")?])
            .context("opening materialized sealed file through retained parent")?;
        return Ok(Some(MaterializedFileIdentity::from_file(&file)?));
    }
    if exclusive {
        cockpit_host::private_fs::write_private_file_exclusive(path, literal.as_bytes())
            .context("writing private sealed file exclusively")?;
    } else {
        cockpit_host::private_fs::write_private_file(path, literal.as_bytes()).map_err(
            |error| {
                let context = format!("atomically replacing private sealed file: {error}");
                error.context(context)
            },
        )?;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .context("opening materialized private sealed file")?;
    Ok(Some(MaterializedFileIdentity::from_file(&file)?))
}

#[cfg(windows)]
fn write_private_file(
    resolved: &ResolvedDestination,
    literal: &str,
    exclusive: bool,
) -> Result<Option<MaterializedFileIdentity>> {
    let path = &resolved.path;
    if exclusive {
        cockpit_host::private_fs::write_private_file_exclusive(path, literal.as_bytes())
            .context("writing ACL-private sealed file exclusively")?;
    } else {
        cockpit_host::private_fs::write_private_file(path, literal.as_bytes())
            .context("writing ACL-private sealed file")?;
    }
    let file = open_windows_retained_materialized_file(path)
        .context("re-opening Windows sealed file after materialization")?;
    Ok(Some(
        MaterializedFileIdentity::from_file(&file)
            .context("reading created sealed-file identity")?,
    ))
}

#[cfg(not(any(unix, windows)))]
fn write_private_file(
    _resolved: &ResolvedDestination,
    _literal: &str,
    _exclusive: bool,
) -> Result<Option<MaterializedFileIdentity>> {
    bail!("sealed file materialization is unsupported on this platform")
}

async fn git_leak_guard(resolved: &ResolvedDestination) -> Result<()> {
    let GitGuard::Inspect {
        repo_parent: parent,
        destination_name,
    } = &resolved.git_guard
    else {
        return Ok(());
    };
    let mut inside_command = tokio::process::Command::new("git");
    inside_command
        .arg("-C")
        .arg(parent)
        .args(["rev-parse", "--is-inside-work-tree"])
        // Make the one status we classify below stable. All other Git errors,
        // including corrupt repository/configuration failures, remain
        // fail-closed and their text is never surfaced.
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANGUAGE", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", "/dev/null")
        .env("XDG_CONFIG_HOME", "/dev/null")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let inside = inside_command
        .output()
        .await
        .context("running sealed file git worktree inspection")?;
    if !inside.status.success() {
        // A directory outside Git cannot contain a tracked or ignored
        // destination, so it needs no Git guard. Do not treat exit status 128
        // alone as that state: Git also uses it for broken repositories and
        // configuration errors, which must remain fail-closed.
        if inside.status.code() == Some(128) && repository_metadata_absent(parent)? {
            return Ok(());
        }
        bail!("cannot establish sealed file git-guard state for destination");
    }
    if inside.stdout.as_slice() != b"true\n" {
        // A successful `false` result (for example a bare repository) is not
        // a working tree and therefore has no tracked worktree destination.
        // Any other successful response is malformed and must not disable the
        // leak guard.
        if inside.stdout.as_slice() == b"false\n" {
            return Ok(());
        }
        bail!("sealed file git worktree inspection returned an invalid result");
    }
    // `parent` is descriptor-backed for pinned Unix destinations, and this
    // relative pathspec is therefore evaluated inside that same retained
    // directory. Never pass the approval-time pathname to Git: it may have
    // been rebound after the parent was opened.
    let tracked = git_query_status(
        parent,
        &[
            "ls-files",
            "--error-unmatch",
            "--",
            destination_name.as_str(),
        ],
    )
    .await?;
    let ignored = git_query_status(
        parent,
        &["check-ignore", "-q", "--", destination_name.as_str()],
    )
    .await?;
    if tracked != GitQueryStatus::Negative || ignored != GitQueryStatus::Positive {
        bail!(
            "sealed file destination is tracked or not ignored; add the pinned path to .gitignore before approving materialization"
        );
    }
    Ok(())
}

/// Prove an explicit non-repository state without interpreting Git's error
/// prose. Any `.git` entry (directory, worktree file, symlink, or malformed
/// object) means repository state exists and a failed Git inspection remains
/// fail-closed. Metadata lookup errors likewise propagate rather than disable
/// the leak guard.
fn repository_metadata_absent(start: &Path) -> Result<bool> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if start.starts_with("/proc/self/fd") {
        return metadata_absent_from_retained_directory(start);
    }
    metadata_absent_in_ancestors(start)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn metadata_absent_from_retained_directory(start: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let mut directory = start.to_path_buf();
    for _ in 0..1024 {
        match std::fs::symlink_metadata(directory.join(".git")) {
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspecting Git metadata for sealed file"),
        }
        // Appending `..` to `/proc/self/fd/N` is resolved by the kernel from
        // the held directory object, so ancestor discovery remains anchored
        // even if an approved pathname is concurrently renamed or rebound.
        let here =
            std::fs::metadata(&directory).context("inspecting retained Git ancestor identity")?;
        let parent = directory.join("..");
        let above =
            std::fs::metadata(&parent).context("inspecting retained Git parent identity")?;
        if here.dev() == above.dev() && here.ino() == above.ino() {
            return Ok(true);
        }
        directory = parent;
    }
    bail!("Git metadata ancestor inspection exceeded its safety bound")
}

fn metadata_absent_in_ancestors(start: &Path) -> Result<bool> {
    for ancestor in start.ancestors() {
        match std::fs::symlink_metadata(ancestor.join(".git")) {
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspecting Git metadata for sealed file"),
        }
    }
    Ok(true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GitQueryStatus {
    Positive,
    Negative,
}

async fn git_query_status(parent: &Path, args: &[&str]) -> Result<GitQueryStatus> {
    let status = tokio::process::Command::new("git")
        .arg("-C")
        .arg(parent)
        .args(args)
        // Repository and configuration authority comes exclusively from the
        // descriptor-backed `-C` directory. Ambient GIT_DIR, GIT_WORK_TREE,
        // config, object-store, and identity variables must not redirect or
        // break either half of the materialization guard.
        .env_clear()
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", "/dev/null")
        .env("XDG_CONFIG_HOME", "/dev/null")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .context("running sealed file git guard")?;
    match status.code() {
        Some(0) => Ok(GitQueryStatus::Positive),
        // These two queries document 1 as their expected negative result.
        // Every other status is an operational failure, including repository
        // mutation between queries, and must remain distinct and fail closed.
        Some(1) => Ok(GitQueryStatus::Negative),
        _ => bail!("cannot establish sealed file Git query result"),
    }
}

struct EphemeralFile {
    path: PathBuf,
    remove: bool,
    identity: Option<MaterializedFileIdentity>,
}

impl EphemeralFile {
    fn new(path: PathBuf, remove: bool, identity: Option<MaterializedFileIdentity>) -> Self {
        Self {
            path,
            remove,
            identity,
        }
    }

    fn remove(mut self) -> Result<()> {
        if self.remove {
            remove_ephemeral_file_checked(&self.path, self.identity.clone())?;
            self.remove = false;
        }
        Ok(())
    }
}

impl Drop for EphemeralFile {
    fn drop(&mut self) {
        if self.remove {
            // Cancellation/panic cannot return an error to the caller. Normal
            // completion uses `remove` above; this is a best-effort backstop.
            let _ = remove_ephemeral_file_checked(&self.path, self.identity.clone());
        }
    }
}

fn remove_ephemeral_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    std::fs::remove_file(path).context("removing ephemeral sealed file")?;
    #[cfg(windows)]
    cockpit_host::private_fs::delete_private_file(path)
        .context("removing ephemeral sealed file")?;
    #[cfg(not(any(unix, windows)))]
    std::fs::remove_file(path).context("removing ephemeral sealed file")?;
    Ok(())
}

fn remove_ephemeral_file_checked(
    path: &Path,
    identity: Option<MaterializedFileIdentity>,
) -> Result<()> {
    #[cfg(unix)]
    if let Some(identity) = identity {
        return remove_ephemeral_file_if_identity(path, identity);
    }
    #[cfg(windows)]
    if let Some(identity) = identity.as_ref() {
        return remove_ephemeral_file_if_identity(path, identity);
    }
    remove_ephemeral_file(path)
}

/// Re-open the materialized file once through the retained parent path and
/// retain that descriptor through child completion. The fixed consumer is
/// handed a descriptor-backed pathname, so changing the destination leaf after
/// materialization cannot change which object receives the sealed value.
#[cfg(unix)]
fn hold_materialized_file(
    path: &Path,
    identity: Option<MaterializedFileIdentity>,
) -> Result<Option<RetainedMaterializedFile>> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let Some(identity) = identity else {
        return Ok(None);
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .context("opening materialized sealed file through retained destination")?;
    if !identity.matches(&file)? {
        bail!("materialized sealed-file identity changed before consumer execution");
    }
    Ok(Some(RetainedMaterializedFile::new(file)?))
}

#[cfg(windows)]
fn hold_materialized_file(
    path: &Path,
    identity: Option<MaterializedFileIdentity>,
) -> Result<Option<RetainedMaterializedFile>> {
    let Some(identity) = identity else {
        return Ok(None);
    };
    let file = open_windows_retained_materialized_file(path)
        .context("opening retained Windows materialized file")?;
    if !identity.matches(&file)? {
        bail!("materialized sealed-file identity changed before consumer execution");
    }
    Ok(Some(RetainedMaterializedFile::new(file)?))
}

#[cfg(not(any(unix, windows)))]
fn hold_materialized_file(
    _path: &Path,
    _identity: Option<MaterializedFileIdentity>,
) -> Result<Option<RetainedMaterializedFile>> {
    Ok(None)
}

fn retained_materialized_path(
    path: &Path,
    held: Option<&RetainedMaterializedFile>,
) -> Result<PathBuf> {
    #[cfg(windows)]
    if held.is_some() {
        return Ok(path.to_path_buf());
    }
    if let Some(held) = held {
        return held.path();
    }
    Ok(path.to_path_buf())
}

/// Never remove a replacement that appeared at the pinned name after this
/// invocation created its own ephemeral inode.  A mismatch is a fail-closed
/// cleanup error: the caller must not report success while the original
/// materialized value may still need operator recovery.
#[cfg(unix)]
fn remove_ephemeral_file_if_identity(
    path: &Path,
    expected: MaterializedFileIdentity,
) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .context("reopening ephemeral sealed file for identity-checked cleanup")?;
    if !expected.matches(&file)? {
        bail!("ephemeral sealed-file identity changed before cleanup");
    }
    std::fs::remove_file(path).context("removing ephemeral sealed file")
}

#[cfg(windows)]
fn remove_ephemeral_file_if_identity(
    path: &Path,
    expected: &MaterializedFileIdentity,
) -> Result<()> {
    let file = open_windows_retained_materialized_file(path)
        .context("reopening Windows ephemeral sealed file for cleanup")?;
    if !expected.matches(&file)? {
        bail!("ephemeral sealed-file identity changed before cleanup");
    }
    delete_windows_file_by_handle(&file)?;
    // Best-effort path cleanup after handle-marked deletion keeps the helper
    // behavior aligned with the Unix unlink contract when the last handle drops.
    let _ = std::fs::remove_file(path);
    Ok(())
}

struct RetainedMaterializedFile {
    file: std::fs::File,
}

impl RetainedMaterializedFile {
    fn new(file: std::fs::File) -> Result<Self> {
        #[cfg(unix)]
        clear_cloexec(&file)?;
        Ok(Self { file })
    }

    fn path(&self) -> Result<PathBuf> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::fd::AsRawFd as _;
            Ok(PathBuf::from(format!(
                "/proc/self/fd/{}",
                self.file.as_raw_fd()
            )))
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            use std::os::fd::AsRawFd as _;
            Ok(PathBuf::from(format!("/dev/fd/{}", self.file.as_raw_fd())))
        }
        #[cfg(windows)]
        {
            Err(anyhow::anyhow!(
                "Windows consumers use the retained verified pathname directly"
            ))
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            windows
        )))]
        {
            Err(anyhow::anyhow!(
                "descriptor-backed materialized file paths are unsupported on this platform"
            ))
        }
    }
}

#[cfg(unix)]
fn clear_cloexec(file: &std::fs::File) -> Result<()> {
    use std::os::fd::AsRawFd as _;

    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        bail!(
            "reading retained materialized file descriptor flags failed: {}",
            std::io::Error::last_os_error()
        );
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        bail!(
            "clearing CLOEXEC on retained materialized file failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn open_windows_retained_materialized_file(path: &Path) -> Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::DELETE;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;

    // This retained handle is reused for both identity verification and
    // handle-bound deletion via `delete_windows_file_by_handle`. Write sharing
    // allows the declared consumer, while omitting delete sharing preserves the
    // rename/delete fence alongside DELETE and read/write access.
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("opening Windows retained sealed file {}", path.display()))
}

#[cfg(windows)]
fn delete_windows_file_by_handle(file: &std::fs::File) -> Result<()> {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle as _;

    #[repr(C)]
    struct IoStatusBlock {
        status: isize,
        information: usize,
    }
    #[repr(C)]
    struct FileDispositionInformation {
        delete_file: u8,
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtSetInformationFile(
            file: *mut c_void,
            io: *mut IoStatusBlock,
            information: *const c_void,
            length: u32,
            class: u32,
        ) -> i32;
    }

    const FILE_DISPOSITION_INFORMATION: u32 = 13;
    // `open_windows_retained_materialized_file` is the only producer for the
    // cleanup handles below; that opener requests DELETE explicitly so this
    // `NtSetInformationFile(FileDispositionInformation)` call cannot receive an
    // incompatible read/write-only handle.
    let info = FileDispositionInformation { delete_file: 1 };
    let mut io = IoStatusBlock {
        status: 0,
        information: 0,
    };
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut io,
            (&info as *const FileDispositionInformation).cast(),
            size_of::<FileDispositionInformation>() as u32,
            FILE_DISPOSITION_INFORMATION,
        )
    };
    if status < 0 {
        bail!(
            "marking Windows sealed file for deletion by handle failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_injection_is_exactly_one_fixed_sink() {
        let mut argv = vec!["/bin/true".into(), SEALED_VALUE_ARG_PLACEHOLDER.into()];
        let identity = pin_argv_executable(&mut argv).unwrap();
        assert!(
            validate_command_kind(
                &argv,
                &identity,
                &CommandInjection::Argument,
                &BTreeMap::new(),
            )
            .is_ok()
        );
        assert!(
            validate_command_kind(
                &["/bin/true".into()],
                &identity,
                &CommandInjection::Argument,
                &BTreeMap::new(),
            )
            .is_err()
        );
        assert!(
            validate_command_kind(
                &["/bin/true".into()],
                &identity,
                &CommandInjection::Environment {
                    variable: "API_TOKEN".into(),
                },
                &BTreeMap::new(),
            )
            .is_ok()
        );
        assert!(
            validate_command_kind(
                &["/bin/true".into(), SEALED_VALUE_ARG_PLACEHOLDER.into()],
                &identity,
                &CommandInjection::Environment {
                    variable: "API_TOKEN".into(),
                },
                &BTreeMap::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn ephemeral_file_requires_a_fixed_consumer_and_placeholder() {
        let destination = FileDestination::PrivateRuntime {
            filename: "credential.pem".into(),
        };
        assert!(validate_file_kind(&destination, FilePersistence::Ephemeral, &[], None).is_err());
        let mut consumer = vec!["/bin/true".into(), SEALED_FILE_PATH_PLACEHOLDER.into()];
        let identity = pin_argv_executable(&mut consumer).unwrap();
        assert!(
            validate_file_kind(
                &destination,
                FilePersistence::Ephemeral,
                &consumer,
                Some(&identity),
            )
            .is_ok()
        );
    }

    #[test]
    fn persistent_file_is_an_explicit_approval_variant() {
        let destination = FileDestination::PrivateRuntime {
            filename: "credential.pem".into(),
        };
        assert!(
            validate_file_kind(
                &destination,
                FilePersistence::PersistentOwnerApproved(
                    PersistentFileApproval::acknowledge(1, PERSISTENT_FILE_APPROVAL_WARNING,)
                        .unwrap(),
                ),
                &[],
                None,
            )
            .is_ok()
        );
        assert!(PERSISTENT_FILE_APPROVAL_WARNING.contains("transform or exfiltrate"));
    }

    #[test]
    fn pinned_persistent_destination_remains_a_valid_owner_approved_fallback() {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut destination = FileDestination::Pinned {
            path: directory.path().join("credential.pem"),
            parent_identity: FileSystemIdentity::unpinned(),
        };
        pin_file_destination(&mut destination).expect("pin owner-selected destination");

        validate_file_kind(
            &destination,
            FilePersistence::PersistentOwnerApproved(
                PersistentFileApproval::acknowledge(1, PERSISTENT_FILE_APPROVAL_WARNING)
                    .expect("record explicit persistence approval"),
            ),
            &[],
            None,
        )
        .expect("owner-approved pinned persistence is supported");
    }

    #[cfg(unix)]
    #[test]
    fn persistent_materialization_repairs_mode_before_replacing_contents() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("credential.pem");
        std::fs::write(&path, b"old value").expect("seed destination");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("make seed destination broadly readable");

        let resolved = ResolvedDestination {
            path: path.clone(),
            git_guard: GitGuard::Skip,
            _pinned_parent: None,
        };
        write_private_file(&resolved, "sealed value", false)
            .expect("materialize persistent sealed file");

        assert_eq!(
            std::fs::metadata(&path)
                .expect("stat materialized file")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read materialized file"),
            "sealed value"
        );
    }

    #[cfg(unix)]
    #[test]
    fn executable_pin_rejects_in_place_content_changes() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("tempdir");
        let program = directory.path().join("consumer");
        std::fs::write(&program, b"#!/bin/sh\nexit 0\n").expect("write executable");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700))
            .expect("mark executable");
        let mut argv = vec![program.to_string_lossy().into_owned()];
        let identity = pin_argv_executable(&mut argv).expect("pin executable");

        // An in-place edit preserves device/inode, so this assertion exercises
        // the content digest rather than the existing identity check.
        std::fs::write(&program, b"#!/bin/sh\nexit 1\n").expect("mutate executable in place");
        let mut opened = std::fs::OpenOptions::new()
            .read(true)
            .open(&program)
            .expect("open changed executable");
        assert!(
            !identity
                .matches(&mut opened)
                .expect("compare executable identity and contents")
        );
    }

    #[cfg(unix)]
    #[test]
    fn persistent_materialization_rejects_an_existing_hard_link() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("credential.pem");
        let alias = directory.path().join("credential-copy.pem");
        std::fs::write(&path, b"owner data").expect("seed destination");
        std::fs::hard_link(&path, &alias).expect("create hard-linked alias");
        let resolved = ResolvedDestination {
            path: path.clone(),
            git_guard: GitGuard::Skip,
            _pinned_parent: None,
        };

        let error = write_private_file(&resolved, "sealed value", false)
            .expect_err("hard-linked persistent destination must be rejected");
        assert!(error.to_string().contains("hard links"));
        assert_eq!(
            std::fs::read_to_string(&alias).expect("read alias after rejected write"),
            "owner data"
        );
    }

    #[tokio::test]
    async fn git_guard_accepts_a_pinned_destination_in_a_bare_repository() {
        let directory = tempfile::tempdir().expect("isolated tempdir");
        let init = std::process::Command::new("git")
            .args(["init", "--bare", "-q"])
            .current_dir(directory.path())
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .status()
            .expect("initialize isolated bare repository");
        assert!(init.success());
        let resolved = ResolvedDestination {
            path: directory.path().join("credential.pem"),
            git_guard: GitGuard::Inspect {
                repo_parent: directory.path().to_path_buf(),
                destination_name: "credential.pem".to_string(),
            },
            _pinned_parent: None,
            #[cfg(windows)]
            _pinned_windows_execution_lease: None,
        };
        git_leak_guard(&resolved)
            .await
            .expect("bare repository has no worktree destination to protect");
    }

    #[tokio::test]
    async fn git_guard_ignores_malformed_ambient_git_dir_at_production_boundary() {
        const CHILD_MARKER: &str = "COCKPIT_GIT_GUARD_AMBIENT_CHILD";
        if std::env::var_os(CHILD_MARKER).is_none() {
            let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
                .args(["--exact", "sealed::action_admin::local_executor::tests::git_guard_ignores_malformed_ambient_git_dir_at_production_boundary", "--nocapture"])
                .env(CHILD_MARKER, "1")
                .env("GIT_DIR", "definitely-missing-git-directory")
                .output()
                .expect("run isolated environment test process");
            assert!(
                output.status.success(),
                "child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let directory = tempfile::tempdir().expect("isolated tempdir");
        let init = std::process::Command::new("git")
            .args(["init", "--bare", "-q"])
            .current_dir(directory.path())
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .status()
            .expect("initialize isolated bare repository");
        assert!(init.success());
        let resolved = ResolvedDestination {
            path: directory.path().join("credential.pem"),
            git_guard: GitGuard::Inspect {
                repo_parent: directory.path().to_path_buf(),
                destination_name: "credential.pem".to_string(),
            },
            _pinned_parent: None,
            #[cfg(windows)]
            _pinned_windows_execution_lease: None,
        };

        git_leak_guard(&resolved)
            .await
            .expect("ambient Git authority must not affect the materialization guard");
    }

    #[tokio::test]
    async fn git_guard_rejects_malformed_repository_metadata() {
        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::write(directory.path().join(".git"), b"not a gitdir declaration")
            .expect("write malformed Git metadata");
        let resolved = ResolvedDestination {
            path: directory.path().join("credential.pem"),
            git_guard: GitGuard::Inspect {
                repo_parent: directory.path().to_path_buf(),
                destination_name: "credential.pem".to_string(),
            },
            _pinned_parent: None,
            #[cfg(windows)]
            _pinned_windows_execution_lease: None,
        };

        let error = git_leak_guard(&resolved)
            .await
            .expect_err("broken repository metadata must fail closed");
        assert!(
            error
                .to_string()
                .contains("cannot establish sealed file git-guard state")
        );
    }

    #[tokio::test]
    async fn git_query_operational_failure_is_not_an_expected_negative() {
        let directory = tempfile::tempdir().expect("tempdir");
        let init = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(directory.path())
            .status()
            .expect("initialize repository");
        assert!(init.success());
        std::fs::write(directory.path().join(".gitignore"), b"credential.pem\n")
            .expect("write ignore rule");

        let query_error = git_query_status(directory.path(), &["ls-files", "--bad-option"])
            .await
            .expect_err("operational query failure must remain an error");
        assert!(
            query_error
                .to_string()
                .contains("cannot establish sealed file Git query result")
        );
        assert_eq!(
            git_query_status(
                directory.path(),
                &["check-ignore", "-q", "--", "credential.pem"]
            )
            .await
            .expect("later ignore query succeeds"),
            GitQueryStatus::Positive
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_pinned_destination_fails_closed_without_retained_execution() {
        let directory = tempfile::tempdir().expect("tempdir");
        let mut destination = FileDestination::Pinned {
            path: directory.path().join("credential.pem"),
            parent_identity: FileSystemIdentity::unpinned(),
        };
        pin_file_destination(&mut destination).expect("pin destination");

        let error = resolve_destination(&destination).expect_err("must fail closed on macOS");
        assert!(
            error
                .to_string()
                .contains("pinned sealed-file destinations are unsupported on macOS")
        );
    }

    #[test]
    fn injected_output_scrubs_plain_and_transformed_values() {
        use base64::Engine as _;
        let literal = "sealed token value";
        let encoded = base64::engine::general_purpose::STANDARD.encode(literal);
        let output = format!("plain={literal}\nbase64={encoded}");
        let scrubbed = crate::redact::RedactionTable::scrub_injected_output(&output, literal);
        assert!(!scrubbed.contains(literal));
        assert!(!scrubbed.contains(&encoded));
    }
}
