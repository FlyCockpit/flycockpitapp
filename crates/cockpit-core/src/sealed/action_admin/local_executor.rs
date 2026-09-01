//! Command, environment, and file sealed-action sinks.
//!
//! Every target is part of the immutable Owner-authored action snapshot. The
//! model supplies only the action id and bounded declared parameters. Commands
//! are spawned directly (never through a shell), and argument/environment
//! injection never writes plaintext to disk. File injection is the deliberate
//! downgrade: the destination is pinned, mode 0600, git guarded, and ephemeral
//! unless the snapshot records explicit persistent approval.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

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

/// Mandatory approval copy for persistent materialization. Owner surfaces that
/// offer this downgrade must present this warning before constructing
/// [`FilePersistence::PersistentOwnerApproved`].
pub const PERSISTENT_FILE_APPROVAL_WARNING: &str = "Persistent materialization writes plaintext to the pinned path until you remove it. The consuming process can transform or exfiltrate the value (for example with base64), and redaction can only scrub known representations. Approve only this declared action and destination.";

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
    /// Prefer `$XDG_RUNTIME_DIR`; fall back to a private directory under the
    /// platform temp directory. The fixed filename may not contain separators.
    PrivateRuntime { filename: String },
    /// A fixed absolute path for a consumer that cannot accept another path.
    Pinned { path: PathBuf },
}

/// Persistent materialization is a distinct Owner-approved action shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilePersistence {
    Ephemeral,
    PersistentOwnerApproved,
}

pub fn validate_command_kind(
    argv_template: &[String],
    injection: &CommandInjection,
    parameters: &BTreeMap<String, SealedParamSpecJson>,
) -> Result<()> {
    validate_argv(argv_template, SEALED_VALUE_ARG_PLACEHOLDER)?;
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

pub fn validate_file_kind(
    destination: &FileDestination,
    persistence: FilePersistence,
    consumer_argv: &[String],
) -> Result<()> {
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
        FileDestination::Pinned { path } => {
            if !path.is_absolute() {
                bail!("pinned sealed-file destination must be absolute");
            }
            if path.file_name().is_none() {
                bail!("pinned sealed-file destination must name a file");
            }
        }
    }
    if persistence == FilePersistence::Ephemeral && consumer_argv.is_empty() {
        bail!("ephemeral file actions require a fixed consuming command");
    }
    if !consumer_argv.is_empty() {
        validate_argv(consumer_argv, SEALED_FILE_PATH_PLACEHOLDER)?;
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
    injection: CommandInjection,
}

impl CommandSealedAction {
    pub fn from_snapshot(snapshot: &SealedActionSnapshot) -> Result<Self> {
        let SealedActionKind::Command {
            argv_template,
            injection,
            parameters,
        } = &snapshot.kind
        else {
            bail!("command executor requires a command action snapshot");
        };
        validate_command_kind(argv_template, injection, parameters)?;
        Ok(Self {
            descriptor: snapshot.kind.compile_descriptor(
                &snapshot.action_id,
                snapshot.revision,
                &snapshot.description,
            )?,
            argv_template: argv_template.clone(),
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
        run_command_scrubbed(&argv, environment, literal.expose()).await
    }
}

#[derive(Debug)]
pub struct FileSealedAction {
    descriptor: SealedActionDescriptor,
    destination: FileDestination,
    persistence: FilePersistence,
    consumer_argv: Vec<String>,
}

impl FileSealedAction {
    pub fn from_snapshot(snapshot: &SealedActionSnapshot) -> Result<Self> {
        let SealedActionKind::File {
            destination,
            persistence,
            consumer_argv,
        } = &snapshot.kind
        else {
            bail!("file executor requires a file action snapshot");
        };
        validate_file_kind(destination, *persistence, consumer_argv)?;
        Ok(Self {
            descriptor: snapshot.kind.compile_descriptor(
                &snapshot.action_id,
                snapshot.revision,
                &snapshot.description,
            )?,
            destination: destination.clone(),
            persistence: *persistence,
            consumer_argv: consumer_argv.clone(),
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
        self.persistence == FilePersistence::PersistentOwnerApproved
    }

    async fn invoke(&self, literal: SealedLiteralHandle<'_>, _params: &SealedParams) -> Result<()> {
        let path = resolve_destination(&self.destination)?;
        git_leak_guard(&path).await?;
        let cleanup = EphemeralFile::new(
            path.clone(),
            self.persistence == FilePersistence::Ephemeral,
        );
        // Arm cleanup before opening the destination: a partial write, flush
        // failure, cancellation, or panic must not strand an ephemeral file.
        write_private_file(&path, literal.expose()).await?;
        if !self.consumer_argv.is_empty() {
            let rendered = zeroize::Zeroizing::new(
                self.consumer_argv
                    .iter()
                    .map(|part| {
                        if part == SEALED_FILE_PATH_PLACEHOLDER {
                            path.to_string_lossy().into_owned()
                        } else {
                            part.clone()
                        }
                    })
                    .collect::<Vec<_>>(),
            );
            run_command_scrubbed(&rendered, None, literal.expose()).await?;
        }
        drop(cleanup);
        Ok(())
    }
}

fn rebind_params(descriptor: &SealedActionDescriptor, params: &SealedParams) -> Result<()> {
    let supplied: BTreeMap<String, SealedParamValue> = params
        .names()
        .filter_map(|name| params.get(name).map(|value| (name.to_string(), value.clone())))
        .collect();
    descriptor.bind_parameters(&supplied)?;
    Ok(())
}

async fn run_command_scrubbed(
    argv: &[String],
    environment: Option<(&str, &str)>,
    literal: &str,
) -> Result<()> {
    let output = crate::secret_command::run_injected_process(argv, environment)
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
    crate::redact::RedactionTable::scrub_injected_output(
        &String::from_utf8_lossy(bytes),
        literal,
    )
}

fn resolve_destination(destination: &FileDestination) -> Result<PathBuf> {
    match destination {
        FileDestination::Pinned { path } => Ok(path.clone()),
        FileDestination::PrivateRuntime { filename } => {
            let base = std::env::var_os("XDG_RUNTIME_DIR")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .unwrap_or_else(std::env::temp_dir)
                .join(format!("flycockpit-sealed-{}", std::process::id()));
            cockpit_host::private_fs::ensure_private_dir(&base)
                .context("creating private sealed runtime directory")?;
            Ok(base.join(filename))
        }
    }
}

#[cfg(unix)]
async fn write_private_file(path: &Path, literal: &str) -> Result<()> {
    let parent = path.parent().context("sealed file destination has no parent")?;
    if !parent.is_dir() {
        bail!("sealed file destination parent does not exist");
    }
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        bail!("sealed file destination must not be a symlink");
    }
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .await
        .context("opening sealed file destination")?;
    use tokio::io::AsyncWriteExt;
    file.write_all(literal.as_bytes())
        .await
        .context("writing sealed file")?;
    file.flush().await.context("flushing sealed file")?;
    drop(file);
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
async fn write_private_file(path: &Path, literal: &str) -> Result<()> {
    cockpit_host::private_fs::write_private_file(path, literal.as_bytes())
        .context("writing ACL-private sealed file")
}

#[cfg(not(any(unix, windows)))]
async fn write_private_file(_path: &Path, _literal: &str) -> Result<()> {
    bail!("sealed file materialization is unsupported on this platform")
}

async fn git_leak_guard(path: &Path) -> Result<()> {
    let parent = path.parent().context("sealed file destination has no parent")?;
    let mut inside_command = tokio::process::Command::new("git");
    inside_command
        .arg("-C")
        .arg(parent)
        .args(["rev-parse", "--is-inside-work-tree"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let inside = inside_command.status().await;
    if !matches!(inside, Ok(status) if status.success()) {
        return Ok(());
    }
    let path_text = path.to_string_lossy();
    let tracked = git_status(parent, &["ls-files", "--error-unmatch", "--", &path_text]).await?;
    let ignored = git_status(parent, &["check-ignore", "-q", "--", &path_text]).await?;
    if tracked || !ignored {
        bail!(
            "sealed file destination is tracked or not ignored; add the pinned path to .gitignore before approving materialization"
        );
    }
    Ok(())
}

async fn git_status(parent: &Path, args: &[&str]) -> Result<bool> {
    Ok(tokio::process::Command::new("git")
        .arg("-C")
        .arg(parent)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .context("running sealed file git guard")?
        .success())
}

struct EphemeralFile {
    path: PathBuf,
    remove: bool,
}

impl EphemeralFile {
    fn new(path: PathBuf, remove: bool) -> Self {
        Self { path, remove }
    }
}

impl Drop for EphemeralFile {
    fn drop(&mut self) {
        if self.remove {
            #[cfg(unix)]
            let _ = std::fs::remove_file(&self.path);
            #[cfg(windows)]
            let _ = cockpit_host::private_fs::delete_private_file(&self.path);
            #[cfg(not(any(unix, windows)))]
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_injection_is_exactly_one_fixed_sink() {
        assert!(
            validate_command_kind(
                &["program".into(), SEALED_VALUE_ARG_PLACEHOLDER.into()],
                &CommandInjection::Argument,
                &BTreeMap::new(),
            )
            .is_ok()
        );
        assert!(
            validate_command_kind(
                &["program".into()],
                &CommandInjection::Argument,
                &BTreeMap::new(),
            )
            .is_err()
        );
        assert!(
            validate_command_kind(
                &["program".into()],
                &CommandInjection::Environment {
                    variable: "API_TOKEN".into(),
                },
                &BTreeMap::new(),
            )
            .is_ok()
        );
        assert!(
            validate_command_kind(
                &["program".into(), SEALED_VALUE_ARG_PLACEHOLDER.into()],
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
        assert!(
            validate_file_kind(&destination, FilePersistence::Ephemeral, &[]).is_err()
        );
        assert!(
            validate_file_kind(
                &destination,
                FilePersistence::Ephemeral,
                &["consumer".into(), SEALED_FILE_PATH_PLACEHOLDER.into()],
            )
            .is_ok()
        );
    }

    #[test]
    fn persistent_file_is_an_explicit_approval_variant() {
        let destination = FileDestination::Pinned {
            path: PathBuf::from("/owner/pinned/credential.pem"),
        };
        assert!(
            validate_file_kind(
                &destination,
                FilePersistence::PersistentOwnerApproved,
                &[],
            )
            .is_ok()
        );
        assert!(PERSISTENT_FILE_APPROVAL_WARNING.contains("transform or exfiltrate"));
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
