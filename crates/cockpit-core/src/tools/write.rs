//! `write` — create or overwrite the file with `content` and release the lock.
//!
//! Pre-write invariant (plan §3c): existing files require that the agent has
//! read the file in this session, OR holds the lock. Missing files may be
//! created without a read record, using create-new semantics so they are never
//! overwritten by a stale absence check.

#[cfg(unix)]
use std::io::Write as _;

#[cfg(unix)]
use anyhow::Context;
use anyhow::Result;
#[cfg(not(windows))]
use anyhow::bail;
use async_trait::async_trait;
use serde_json::Value;

#[cfg(test)]
use crate::config::extended::ApprovalMode;
use crate::{
    engine::tool::{Tool, ToolCtx, ToolOutput, ToolPresentation, path_or_readable_args},
    tools::common::{detect_crlf, normalize_line_endings, resolve, write_and_release},
};

pub struct WriteTool;

/// The `Plan` agent's deliberately narrow `write` capability.  It retains the
/// ordinary tool name and schema so the model has one `read`/`write` mental
/// model, but it never enters the host-file writer.
pub struct PlanWriteTool;

#[async_trait]
impl Tool for WriteTool {
    fn name(&self) -> &str {
        "write"
    }

    fn description(&self) -> &str {
        "Write `content` as the file's COMPLETE new contents (omitted lines are deleted); `cockpit://session/<short_id>/plan` is the sole writable recall pseudofile; locking is automatic for host files"
    }

    fn verbose_description(&self) -> Option<String> {
        Some(
            "Replace a file's ENTIRE contents with the text you supply. Locking is automatic: \
             do not call a separate lock tool before writing. \
             `content` must be the complete new file from first line to last — anything you omit \
             is deleted, so include every line you want to keep, not just your changes. Use \
             `write` for new files or full rewrites; existing files require prior \
             read, or the write is rejected to guard against blind overwrites. Missing \
             parent directories are created for new files after path-access checks pass. For a \
             small change to a large file prefer \
             `edit` (targeted search/replace) so you don't have to restate the whole file. \
             New-file creation does not grant permission for later blind overwrites."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path":    { "type": "string", "x-cockpit-kind": "path", "x-cockpit-may-create": true, "x-cockpit-aliases": ["file_path", "filePath", "filepath", "pathname", "target_file", "file", "absolute_path"], "description": "Path to write" },
                "content": { "type": "string", "x-cockpit-aliases": ["text", "body", "data", "contents", "fileContent"], "description": "Entire new file content" },
                "expected_revision": { "type": "integer", "description": "Required to replace an existing `cockpit://.../plan`; use the revision returned by read. Ignored for host files." }
            },
            "required": ["path", "content"]
        })
    }

    fn verbose_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "path":    { "type": "string", "x-cockpit-kind": "path", "x-cockpit-may-create": true, "x-cockpit-aliases": ["file_path", "filePath", "filepath", "pathname", "target_file", "file", "absolute_path"], "description": "Path to create or overwrite, absolute or relative to the session working directory; existing files must be the same file you previously locked/read" },
                "content": { "type": "string", "x-cockpit-aliases": ["text", "body", "data", "contents", "fileContent"], "description": "The complete new contents of the file from the first line to the last. This REPLACES everything; any existing line you do not include here is lost" },
                "expected_revision": { "type": "integer", "description": "For an existing `cockpit://.../plan`, the revision returned by read; ignored for host files." }
            },
            "required": ["path", "content"]
        }))
    }

    fn presentation(&self, args: &Value) -> ToolPresentation {
        let (summary, full_input) = path_or_readable_args(args);
        ToolPresentation::with_parts(Some("🔓"), "write", summary, full_input)
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        // The recall provider owns its sole writable pseudofile (plan) and
        // must run before every host-path guard.
        if let Some(output) = crate::tools::recall::write(&args, ctx).await? {
            return Ok(output);
        }
        let path_arg = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::engine::tool::invalid_input("`path` is required"))?;
        let content = args
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::engine::tool::invalid_input("`content` is required"))?;
        let requested_path = resolve(path_arg, &ctx.cwd);
        enforce_requested_write_scope(ctx, &requested_path, self.name())?;

        // Native-tool boundary check (sandboxing part 2): an out-of-cwd
        // write target escalates (naming the path) before we touch disk.
        let path = crate::tools::sandbox::check_native_access(
            ctx,
            &requested_path,
            crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
        )
        .await?;
        enforce_write_scope(ctx, &path, self.name())?;
        let (identity_note, identity_write_preauthorized) =
            match crate::assistants::identity::check_identity_write(ctx, &path).await? {
                crate::assistants::identity::IdentityWriteGate::Allow {
                    note,
                    preauthorized,
                } => (note, preauthorized),
                crate::assistants::identity::IdentityWriteGate::Refuse(message) => {
                    return Ok(crate::assistants::identity::tool_refusal(message));
                }
            };

        // The early native check can park for approval.  Do not even inspect
        // target existence/content after a cancellation or revision won that
        // decision: claim the exact ReadWrite path immediately before this
        // first filesystem access.  The later content/mutation fence remains
        // the separate irreversible-write commitment.
        crate::tools::sandbox::recheck_native_access_effect_boundary(
            &path,
            crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
        )
        .await?;
        let exists = path.exists();
        let existing_before = if exists {
            Some(std::fs::read(&path)?)
        } else {
            None
        };
        let want_crlf = existing_before.as_deref().is_some_and(detect_crlf);
        let normalized = normalize_line_endings(content, want_crlf);
        if !identity_write_preauthorized
            && (existing_before
                .as_deref()
                .is_some_and(|bytes| !bytes.is_empty())
                || crate::tools::sandbox::is_workspace_cockpit_path(&ctx.cwd, &path))
        {
            authorize_existing_write(
                ctx,
                &path,
                existing_before.as_deref().unwrap_or_default(),
                normalized.as_bytes(),
            )
            .await?;
        }
        let acquire =
            crate::tools::lock_wait::acquire_waiting(ctx, &path, self.name(), false).await?;
        let write_guard = ctx
            .locks
            .begin_write_after_wait(
                &path,
                &ctx.lock_identity,
                ctx.session.id,
                self.name(),
                !acquire.preexisting_hold,
                exists,
            )
            .await?;

        // `authorize_existing_write` and lock acquisition can both wait.
        // Revalidate the already-claimed exact path before this stability
        // read, but deliberately leave the ready content mutation claim for
        // the immediately following irreversible-write fence.
        crate::tools::sandbox::recheck_claimed_native_access_stability_boundary(
            &path,
            crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
        )
        .await?;
        if let Some(previous) = &existing_before
            && std::fs::read(&path)? != *previous
        {
            return Err(anyhow::anyhow!(
                "`{}` changed while approval was pending; read it again before overwriting",
                path.display()
            ));
        }
        let config = ctx.config.extended();
        let skill_validation = crate::skills::validate_skill_package_write_for_paths(
            &requested_path,
            &path,
            &ctx.cwd,
            &config.skills,
            &normalized,
        )
        .map_err(|error| crate::engine::tool::invalid_input(error.to_string()))?;
        if let Some(validation) = &skill_validation
            && let Some(cage) = &ctx.review_cage
            && !cage.skill_package_was_viewed(&validation.package_root)
        {
            return Err(crate::engine::tool::invalid_input(format!(
                "background skill review must load `{}` with `skill` before writing its package files",
                validation.name
            )));
        }

        // Both concrete helpers mutate the filesystem before their first
        // await, so fence the capability immediately before selecting one.
        let concrete_effects = host_approval_filesystem_write_effects(
            &path,
            existing_before.as_deref(),
            normalized.as_bytes(),
        );
        crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
            "write_filesystem_mutation",
            &concrete_effects,
        )
        .await?;
        let (outcome, created_directories) = if exists {
            (
                write_and_release(ctx, &path, normalized.as_bytes(), write_guard).await?,
                None,
            )
        } else {
            create_new_and_release(&path, normalized.as_bytes(), write_guard).await?
        };
        crate::assistants::identity::record_identity_write(ctx, &path).await?;
        if skill_validation.is_some() {
            crate::skills::invalidate_catalog_cache(&ctx.cwd, &config.skills);
        }

        let mut message = format!(
            "wrote `{}` ({} bytes, {})",
            path.display(),
            normalized.len(),
            if want_crlf { "CRLF" } else { "LF" }
        );
        if let Some(created) = created_directories {
            message.push('\n');
            message.push_str(&created);
        }
        // Diagnostics can spawn or reuse an opaque LSP host.  A completed
        // native write does not make an attached KB writable to that host.
        if let Some(lsp) = &ctx.lsp
            && crate::knowledge::configured_local_knowledge_roots(&ctx.session, &ctx.cwd, &config)
                .await
                .is_empty()
        {
            message.push_str(&lsp.diagnostics_after_write(&ctx.cwd, &path, &config).await);
        }
        if let Some(note) =
            crate::tools::data_syntax::data_syntax_note(&path, &normalized, &config.data_syntax)
        {
            message.push_str(&note);
        }
        if let Some(advisory) = outcome.advisory() {
            message.push_str(advisory);
        }
        if let Some(note) = identity_note {
            message.push_str(&note);
        }
        if let Some(validation) = skill_validation {
            message.push_str(&validation.confirmation_note());
        }

        Ok(ToolOutput::text(message))
    }
}

#[async_trait]
impl Tool for PlanWriteTool {
    fn name(&self) -> &str {
        "write"
    }

    fn description(&self) -> &str {
        "Replace the current session's `cockpit://session/<short_id>/plan` pseudofile with `content`; no host files or other recall pseudofiles are writable"
    }

    fn verbose_description(&self) -> Option<String> {
        Some(
            "Replace the complete current-session plan document. Read it first, then pass its \
             revision as `expected_revision` when replacing an existing plan. This capability \
             cannot write workspace files or any other recall pseudofile."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "x-cockpit-kind": "path", "description": "The current session's plan pseudofile" },
                "content": { "type": "string", "description": "Entire new plan content" },
                "expected_revision": { "type": "integer", "description": "Required to replace an existing plan; use the revision returned by read." }
            },
            "required": ["path", "content"]
        })
    }

    fn verbose_parameters(&self) -> Option<Value> {
        Some(self.parameters())
    }

    fn presentation(&self, args: &Value) -> ToolPresentation {
        let (summary, full_input) = path_or_readable_args(args);
        ToolPresentation::with_parts(Some("🔓"), self.name(), summary, full_input)
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let path = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::engine::tool::invalid_input("`path` is required"))?;
        if !crate::tools::recall::is_recall_path(path) {
            return Err(crate::engine::tool::invalid_input(
                "Plan may write only its current session plan pseudofile",
            ));
        }
        crate::tools::recall::write(&args, ctx)
            .await?
            .ok_or_else(|| anyhow::anyhow!("recall plan write was not dispatched"))
    }
}

/// Reconstruct every approval candidate that can authorize a filesystem write
/// at its real mutation boundary. Both `write` and `edit` use this exact
/// projection so an approved path-access or previous/next-content commitment
/// cannot be consumed by a different in-process write helper.
pub(crate) fn host_approval_filesystem_write_effects(
    path: &std::path::Path,
    previous: Option<&[u8]>,
    next: &[u8],
) -> Vec<Value> {
    let mut effects = vec![serde_json::json!({
        "access": {
            "path": path.display().to_string(),
            "required_access": "ReadWrite",
        }
    })];
    if let Some(previous) = previous {
        effects.push(serde_json::json!({
            "write": {
                "path": path.display().to_string(),
                "previous": crate::approval::write_content_commitment(previous),
                "next": crate::approval::write_content_commitment(next),
            }
        }));
    }
    effects
}

pub(crate) fn enforce_write_scope(ctx: &ToolCtx, path: &std::path::Path, tool: &str) -> Result<()> {
    if let Some(lease) = ctx.workspace_lease.as_ref() {
        if !lease.is_live(crate::workspace_lease::now_unix_ms()) {
            return Err(crate::engine::tool::invalid_input(format!(
                "refused: `{tool}` workspace lease `{}` is expired or revoked",
                lease.id
            )));
        }
        if !lease.allows_write() {
            return Err(crate::engine::tool::invalid_input(format!(
                "refused: `{tool}` is not permitted by workspace lease `{}`",
                lease.id
            )));
        }
        if !lease.covers_path(path) {
            return Err(crate::engine::tool::invalid_input(format!(
                "refused: `{tool}` target `{}` is outside workspace lease visibility `{}`",
                path.display(),
                lease.visibility_root.display()
            )));
        }
    }
    let Some(scope) = ctx.write_scope.as_ref() else {
        return Ok(());
    };
    if cockpit_host::path_containment::contained_under(scope, path) {
        return Ok(());
    }
    Err(crate::engine::tool::invalid_input(format!(
        "refused: `{tool}` target `{}` is outside this child's write scope `{}`; keep writes inside it and report a needed shared-file edit up to your parent",
        path.display(),
        scope.display()
    )))
}

pub(crate) fn enforce_requested_write_scope(
    ctx: &ToolCtx,
    requested_path: &std::path::Path,
    tool: &str,
) -> Result<()> {
    if ctx.write_scope.is_none() {
        return Ok(());
    }
    let effective = cockpit_host::path_containment::effective_path(requested_path)
        .unwrap_or_else(|_| requested_path.to_path_buf());
    enforce_write_scope(ctx, &effective, tool)
}

/// Workspace parent directories created for a new file. Explicit rather than
/// umask-derived; applied through the held staged-directory inode.
#[cfg(unix)]
const CREATED_DIR_MODE: libc::mode_t = 0o755;
#[cfg(unix)]
const CREATED_DIR_INITIAL_MODE: libc::mode_t = 0o700;

#[cfg(test)]
thread_local! {
    #[cfg(unix)]
    static BEFORE_PARENT_CREATE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    #[cfg(unix)]
    static AFTER_PARENT_CREATE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    #[cfg(unix)]
    static AFTER_DIRECTORY_CREATE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    #[cfg(unix)]
    static BEFORE_STAGED_DIRECTORY_OPEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static BEFORE_FILE_CREATE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    #[cfg(any(unix, windows))]
    static AFTER_FILE_OPEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static FORCED_FILE_CREATE_ERROR: std::cell::RefCell<Option<std::io::Error>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
fn set_before_parent_create_hook(hook: impl FnOnce() + 'static) {
    BEFORE_PARENT_CREATE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(all(test, unix))]
fn set_after_parent_create_hook(hook: impl FnOnce() + 'static) {
    AFTER_PARENT_CREATE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(all(test, unix))]
fn set_after_directory_create_hook(hook: impl FnOnce() + 'static) {
    AFTER_DIRECTORY_CREATE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(all(test, unix))]
fn set_before_staged_directory_open_hook(hook: impl FnOnce() + 'static) {
    BEFORE_STAGED_DIRECTORY_OPEN.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(all(test, unix))]
fn set_before_file_create_hook(hook: impl FnOnce() + 'static) {
    BEFORE_FILE_CREATE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(all(test, any(unix, windows)))]
fn set_after_file_open_hook(hook: impl FnOnce() + 'static) {
    AFTER_FILE_OPEN.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(all(test, unix))]
fn set_forced_file_create_error(error: std::io::Error) {
    FORCED_FILE_CREATE_ERROR.with(|slot| *slot.borrow_mut() = Some(error));
}

#[cfg(unix)]
fn run_before_parent_create_hook() {
    #[cfg(test)]
    BEFORE_PARENT_CREATE.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(unix)]
fn run_after_parent_create_hook() {
    #[cfg(test)]
    AFTER_PARENT_CREATE.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(unix)]
fn run_after_directory_create_hook() {
    #[cfg(test)]
    AFTER_DIRECTORY_CREATE.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(unix)]
fn run_before_staged_directory_open_hook() {
    #[cfg(test)]
    BEFORE_STAGED_DIRECTORY_OPEN.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

fn run_before_file_create_hook() {
    #[cfg(test)]
    BEFORE_FILE_CREATE.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(any(unix, windows))]
fn run_after_file_open_hook() {
    #[cfg(test)]
    AFTER_FILE_OPEN.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

fn take_forced_file_create_error() -> Option<std::io::Error> {
    #[cfg(test)]
    {
        return FORCED_FILE_CREATE_ERROR.with(|slot| slot.borrow_mut().take());
    }
    #[cfg(not(test))]
    None
}

struct ParentPrep {
    disclosure: Option<String>,
    created: CreatedDirectories,
    #[cfg(unix)]
    parent_directory: Option<std::fs::File>,
    #[cfg(unix)]
    bindings: Vec<HeldDirectoryBinding>,
    #[cfg(windows)]
    parent_directory: Option<std::fs::File>,
    #[cfg(windows)]
    bindings: Vec<windows_parent::DirectoryBinding>,
}

#[derive(Default)]
struct CreatedDirectories {
    #[cfg(unix)]
    paths: Vec<std::path::PathBuf>,
    #[cfg(unix)]
    bindings: Vec<CreatedDirectoryBinding>,
    #[cfg(windows)]
    paths: Vec<std::path::PathBuf>,
    #[cfg(windows)]
    bindings: Vec<windows_parent::CreatedDirectoryBinding>,
}

#[cfg(unix)]
struct CreatedDirectoryBinding {
    parent: std::fs::File,
    name: std::ffi::CString,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
struct HeldDirectoryBinding {
    parent: std::fs::File,
    name: std::ffi::CString,
    device: u64,
    inode: u64,
}

impl CreatedDirectories {
    fn rollback(&self) {
        #[cfg(unix)]
        rollback_created_directory_bindings(&self.bindings);
        #[cfg(windows)]
        windows_parent::rollback(&self.bindings);
    }
}

#[cfg(unix)]
fn rollback_created_directory_bindings(bindings: &[CreatedDirectoryBinding]) {
    use std::os::fd::AsRawFd as _;
    for binding in bindings.iter().rev() {
        let Ok(stat) = cockpit_host::private_fs::held_fd::fstatat_nofollow(
            binding.parent.as_raw_fd(),
            &binding.name,
        ) else {
            continue;
        };
        if (stat.st_dev as u64, stat.st_ino as u64) != (binding.device, binding.inode) {
            continue;
        }
        let _ = cockpit_host::private_fs::held_fd::unlinkat(
            binding.parent.as_raw_fd(),
            &binding.name,
            libc::AT_REMOVEDIR,
        );
    }
}

impl ParentPrep {
    #[cfg(unix)]
    fn none() -> Self {
        Self {
            disclosure: None,
            created: CreatedDirectories::default(),
            #[cfg(unix)]
            parent_directory: None,
            #[cfg(unix)]
            bindings: Vec::new(),
            #[cfg(windows)]
            parent_directory: None,
            #[cfg(windows)]
            bindings: Vec::new(),
        }
    }
}

async fn create_new_and_release(
    path: &std::path::Path,
    bytes: &[u8],
    guard: crate::locks::WriteGuard<'_>,
) -> Result<(crate::tools::common::WriteReleaseOutcome, Option<String>)> {
    let prep = ensure_parent_dirs(path)?;
    run_before_file_create_hook();
    if let Err(error) = revalidate_prepared_parent(&prep) {
        prep.created.rollback();
        return Err(error);
    }
    let created: std::io::Result<CreatedFileIdentity> =
        if let Some(error) = take_forced_file_create_error() {
            Err(error)
        } else {
            create_new_file(&prep, path, bytes)
        };
    if created.is_err() {
        prep.created.rollback();
    }
    let created_identity = created.map_err(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!(
                "cannot create `{}` — file now exists; read it before overwriting",
                path.display()
            )
        } else {
            anyhow::anyhow!("create `{}`: {err}", path.display())
        }
    })?;
    if let Err(error) = revalidate_prepared_parent(&prep) {
        remove_new_file(&prep, path, &created_identity);
        prep.created.rollback();
        return Err(error);
    }
    let persist_ok = guard.release_after_write().await;
    Ok((
        crate::tools::common::WriteReleaseOutcome { persist_ok },
        prep.disclosure,
    ))
}

/// Name the created portion below the nearest pre-existing ancestor as
/// `created directories: <first-created>/…/<parent>`. A single created
/// component omits the ellipsis.
#[cfg(any(unix, windows))]
fn format_created_directories_line(created: &[std::path::PathBuf]) -> Option<String> {
    let first = created.first()?.file_name()?;
    let last = created.last()?.file_name()?;
    Some(if created.len() == 1 {
        format!("created directories: {}", first.to_string_lossy())
    } else {
        format!(
            "created directories: {}/…/{}",
            first.to_string_lossy(),
            last.to_string_lossy()
        )
    })
}

fn revalidate_prepared_parent(prep: &ParentPrep) -> Result<()> {
    #[cfg(not(any(unix, windows)))]
    let _ = prep;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;

        for binding in &prep.bindings {
            let stat = cockpit_host::private_fs::held_fd::fstatat_nofollow(
                binding.parent.as_raw_fd(),
                &binding.name,
            )
            .with_context(|| {
                format!(
                    "refused: prepared parent component {:?} changed identity (no longer bound to its held directory)",
                    binding.name
                )
            })?;
            if stat.st_dev as u64 != binding.device || stat.st_ino as u64 != binding.inode {
                bail!(
                    "refused: prepared parent component {:?} changed identity",
                    binding.name
                );
            }
        }
    }
    #[cfg(windows)]
    windows_parent::revalidate(&prep.bindings)?;
    Ok(())
}

#[cfg(unix)]
struct CreatedFileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(not(any(unix, windows)))]
struct CreatedFileIdentity;

#[cfg(windows)]
type CreatedFileIdentity = windows_parent::Identity;

#[cfg(unix)]
fn remove_new_file(prep: &ParentPrep, path: &std::path::Path, identity: &CreatedFileIdentity) {
    use std::os::fd::AsRawFd as _;

    let Some(parent) = prep.parent_directory.as_ref() else {
        return;
    };
    let Some(name) = path.file_name() else {
        return;
    };
    let Ok(name) = component_cstr(name) else {
        return;
    };
    let Ok(stat) = cockpit_host::private_fs::held_fd::fstatat_nofollow(parent.as_raw_fd(), &name)
    else {
        return;
    };
    if stat.st_dev as u64 != identity.device || stat.st_ino as u64 != identity.inode {
        return;
    }
    let _ = cockpit_host::private_fs::held_fd::unlinkat(parent.as_raw_fd(), &name, 0);
}

#[cfg(not(any(unix, windows)))]
fn remove_new_file(_prep: &ParentPrep, _path: &std::path::Path, _identity: &CreatedFileIdentity) {}

#[cfg(windows)]
fn remove_new_file(prep: &ParentPrep, path: &std::path::Path, identity: &CreatedFileIdentity) {
    if let (Some(parent), Some(name)) = (prep.parent_directory.as_ref(), path.file_name()) {
        windows_parent::remove_relative_if_identity(parent, name, false, *identity);
    }
}

#[cfg(unix)]
fn ensure_parent_dirs(path: &std::path::Path) -> Result<ParentPrep> {
    let Some(parent) = path.parent() else {
        return Ok(ParentPrep::none());
    };
    if parent.as_os_str().is_empty() {
        return Ok(ParentPrep::none());
    }
    if !path.is_absolute() {
        bail!("secure new-file target must be absolute");
    }
    for component in path.components() {
        if matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::Prefix(_)
        ) {
            bail!(
                "refused: secure new-file target `{}` contains unresolved traversal",
                path.display()
            );
        }
    }
    // `path` is the exact absolute spelling returned by the native-access gate.
    // Freeze that spelling as the authority: after approval no cwd, write
    // scope, temp directory, or external ancestor is canonicalized again. The
    // race seam is before acquisition so tests can prove that every component
    // is instead acquired no-follow from the non-substitutable filesystem root.
    // Existing components are opened for search, not read: `O_RDONLY` would
    // reject traverse-only ancestors (`0711` `/home`) that `create_dir_all`
    // and native-access canonicalization already accepted.
    run_before_parent_create_hook();

    let mut created = CreatedDirectories::default();
    let held_parent = {
        let root = cockpit_host::private_fs::held_fd::open_fs_root_search()
            .context("open trusted filesystem root for new-file creation")?;
        match create_parent_components(path, parent, root, parent, &mut created) {
            Ok(parent) => parent,
            Err(error) => {
                created.rollback();
                return Err(error);
            }
        }
    };

    run_after_parent_create_hook();
    let prep = ParentPrep {
        disclosure: format_created_directories_line(&created.paths),
        created,
        parent_directory: Some(held_parent.directory),
        bindings: held_parent.bindings,
    };
    if let Err(error) = revalidate_prepared_parent(&prep) {
        prep.created.rollback();
        return Err(error);
    }
    Ok(prep)
}

#[cfg(windows)]
fn ensure_parent_dirs(path: &std::path::Path) -> Result<ParentPrep> {
    windows_parent::prepare(path)
}

#[cfg(not(any(unix, windows)))]
fn ensure_parent_dirs(path: &std::path::Path) -> Result<ParentPrep> {
    if !path.is_absolute() {
        bail!("secure new-file target must be absolute");
    }
    bail!(
        "refused: secure new-file creation is unavailable on this platform because handle-relative no-link creation is not implemented"
    )
}

#[cfg(unix)]
struct HeldParent {
    directory: std::fs::File,
    bindings: Vec<HeldDirectoryBinding>,
}

#[cfg(unix)]
fn create_parent_components(
    path: &std::path::Path,
    parent: &std::path::Path,
    mut current: std::fs::File,
    created_relative: &std::path::Path,
    created: &mut CreatedDirectories,
) -> Result<HeldParent> {
    let mut built = std::path::PathBuf::from("/");
    let mut bindings = Vec::new();
    for component in created_relative.components() {
        match component {
            std::path::Component::Normal(name) => {
                built.push(name);
                let (next, binding) = open_or_create_directory_child(
                    &current, name, &built, created,
                )
                .with_context(|| {
                    format!(
                        "create parent directories for `{}` under `{}`",
                        path.display(),
                        parent.display()
                    )
                })?;
                bindings.push(binding);
                current = next;
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                bail!(
                    "cannot create `{}` — unresolved parent traversal in `{}`",
                    path.display(),
                    parent.display()
                );
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {}
        }
    }
    Ok(HeldParent {
        directory: current,
        bindings,
    })
}

#[cfg(unix)]
fn component_cstr(name: &std::ffi::OsStr) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt as _;
    if name.is_empty() || name == "." || name == ".." || name.as_bytes().contains(&b'/') {
        bail!("unsafe path component {name:?}");
    }
    std::ffi::CString::new(name.as_bytes()).context("path component contains NUL")
}

/// Open a directory component for search, not read. See
/// [`cockpit_host::private_fs::held_fd::directory_search_flags`].
#[cfg(unix)]
fn open_directory_child_search(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
) -> std::io::Result<std::fs::File> {
    use std::os::fd::AsRawFd as _;
    cockpit_host::private_fs::held_fd::openat(
        parent.as_raw_fd(),
        name,
        cockpit_host::private_fs::held_fd::directory_search_flags(),
    )
}

#[cfg(unix)]
fn open_or_create_directory_child(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    child_path: &std::path::Path,
    created: &mut CreatedDirectories,
) -> Result<(std::fs::File, HeldDirectoryBinding)> {
    use std::os::fd::AsRawFd as _;

    let cname = component_cstr(name)?;
    match open_directory_child_search(parent, &cname) {
        Ok(directory) => {
            let binding = verified_directory_binding(parent, &cname, &directory, None, child_path)?;
            Ok((directory, binding))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // Safety invariant: successful mkdirat under this unpredictable
            // private staging name is the creation-ownership basis. The first
            // no-follow identity observation anchors that claim; every later
            // chmod, publication, and rollback is gated on the same identity.
            let staged_name = std::ffi::CString::new(format!(
                ".cockpit-create-{}",
                uuid::Uuid::new_v4().simple()
            ))?;
            cockpit_host::private_fs::held_fd::mkdirat(
                parent.as_raw_fd(),
                &staged_name,
                CREATED_DIR_INITIAL_MODE,
            )
            .with_context(|| format!("staging directory component `{}`", child_path.display()))?;
            let staged_entry = match cockpit_host::private_fs::held_fd::fstatat_nofollow(
                parent.as_raw_fd(),
                &staged_name,
            ) {
                Ok(entry) if entry.st_mode & libc::S_IFMT == libc::S_IFDIR => entry,
                Ok(_) => bail!("refused: staged directory is not a directory"),
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("identify staged directory `{}`", child_path.display())
                    });
                }
            };
            let staged_identity = (staged_entry.st_dev as u64, staged_entry.st_ino as u64);
            run_before_staged_directory_open_hook();
            let staged = match open_directory_child_search(parent, &staged_name) {
                Ok(fd) => fd,
                Err(error) => {
                    remove_directory_if_identity_matches(parent, &staged_name, staged_identity);
                    return Err(refuse_symlink_or_non_dir(child_path, error));
                }
            };
            use std::os::unix::fs::MetadataExt as _;
            let metadata = match staged.metadata() {
                Ok(metadata) => metadata,
                Err(error) => {
                    remove_directory_if_identity_matches(parent, &staged_name, staged_identity);
                    return Err(error).context("inspect held staged directory");
                }
            };
            if (metadata.dev(), metadata.ino()) != staged_identity {
                remove_directory_if_identity_matches(parent, &staged_name, staged_identity);
                bail!("refused: staged directory changed identity while it was being acquired");
            }
            // Held-inode chmod after the identity check: Linux `O_PATH` fds
            // (needed when umask zeroed the staging mode) go through
            // `/proc/self/fd/{n}` rather than `fchmodat2`, which is missing
            // from aarch64 libc and from Ubuntu 22.04 kernels.
            if let Err(error) = cockpit_host::private_fs::held_fd::fchmod_held_inode(
                staged.as_raw_fd(),
                CREATED_DIR_MODE,
            ) {
                remove_directory_if_identity_matches(parent, &staged_name, staged_identity);
                return Err(error).with_context(|| {
                    format!(
                        "setting mode of staged directory `{}`",
                        child_path.display()
                    )
                });
            }
            if let Err(error) = cockpit_host::private_fs::held_fd::rename_noreplace(
                parent.as_raw_fd(),
                &staged_name,
                parent.as_raw_fd(),
                &cname,
            ) {
                remove_directory_if_identity_matches(parent, &staged_name, staged_identity);
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    let directory = open_directory_child_search(parent, &cname)
                        .map_err(|error| refuse_symlink_or_non_dir(child_path, error))?;
                    let binding =
                        verified_directory_binding(parent, &cname, &directory, None, child_path)?;
                    return Ok((directory, binding));
                }
                return Err(error).with_context(|| {
                    format!("publishing directory component `{}`", child_path.display())
                });
            }
            run_after_directory_create_hook();
            let directory = match open_directory_child_search(parent, &cname) {
                Ok(directory) => directory,
                Err(error) => {
                    remove_directory_if_identity_matches(parent, &cname, staged_identity);
                    return Err(refuse_symlink_or_non_dir(child_path, error));
                }
            };
            let binding = match verified_directory_binding(
                parent,
                &cname,
                &directory,
                Some(staged_identity),
                child_path,
            ) {
                Ok(binding) => binding,
                Err(error) => {
                    remove_directory_if_identity_matches(parent, &cname, staged_identity);
                    return Err(error);
                }
            };
            let rollback_parent = match parent.try_clone() {
                Ok(parent) => parent,
                Err(error) => {
                    remove_directory_if_identity_matches(parent, &cname, staged_identity);
                    return Err(error).context("retain rollback authority for created directory");
                }
            };
            created.paths.push(child_path.to_path_buf());
            created.bindings.push(CreatedDirectoryBinding {
                parent: rollback_parent,
                name: cname.clone(),
                device: staged_identity.0,
                inode: staged_identity.1,
            });
            Ok((directory, binding))
        }
        Err(err) => Err(refuse_symlink_or_non_dir(child_path, err)),
    }
}

#[cfg(unix)]
fn verified_directory_binding(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
    directory: &std::fs::File,
    expected: Option<(u64, u64)>,
    child_path: &std::path::Path,
) -> Result<HeldDirectoryBinding> {
    use std::os::{fd::AsRawFd as _, unix::fs::MetadataExt as _};

    let metadata = directory.metadata()?;
    let opened = (metadata.dev(), metadata.ino());
    let entry = cockpit_host::private_fs::held_fd::fstatat_nofollow(parent.as_raw_fd(), name)?;
    let entry_identity = (entry.st_dev as u64, entry.st_ino as u64);
    if entry.st_mode & libc::S_IFMT != libc::S_IFDIR
        || entry_identity != opened
        || expected.is_some_and(|expected| expected != opened)
    {
        bail!(
            "refused: directory component `{}` changed identity while it was being acquired",
            child_path.display()
        );
    }
    Ok(HeldDirectoryBinding {
        parent: parent.try_clone()?,
        name: name.to_owned(),
        device: opened.0,
        inode: opened.1,
    })
}

#[cfg(unix)]
fn remove_directory_if_identity_matches(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
    identity: (u64, u64),
) {
    use std::os::fd::AsRawFd as _;
    let Ok(stat) = cockpit_host::private_fs::held_fd::fstatat_nofollow(parent.as_raw_fd(), name)
    else {
        return;
    };
    if (stat.st_dev as u64, stat.st_ino as u64) == identity {
        let _ = cockpit_host::private_fs::held_fd::unlinkat(
            parent.as_raw_fd(),
            name,
            libc::AT_REMOVEDIR,
        );
    }
}

#[cfg(unix)]
fn refuse_symlink_or_non_dir(path: &std::path::Path, err: std::io::Error) -> anyhow::Error {
    match err.raw_os_error() {
        Some(code) if code == libc::ELOOP || code == libc::ENOTDIR => anyhow::anyhow!(
            "refused: intermediate path component `{}` is a symlink or is not a directory",
            path.display()
        ),
        _ => anyhow::Error::new(err).context(format!(
            "opening directory component `{}` without following links",
            path.display()
        )),
    }
}

#[cfg(unix)]
fn create_new_file(
    prep: &ParentPrep,
    path: &std::path::Path,
    bytes: &[u8],
) -> std::io::Result<CreatedFileIdentity> {
    use std::os::{fd::AsRawFd as _, unix::fs::MetadataExt as _};

    let parent = prep.parent_directory.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("missing held parent directory for `{}`", path.display()),
        )
    })?;
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("missing file name for `{}`", path.display()),
        )
    })?;
    let name = component_cstr(name).map_err(std::io::Error::other)?;
    let mut file = cockpit_host::private_fs::held_fd::openat_mode(
        parent.as_raw_fd(),
        &name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o666,
    )?;
    let metadata = file.metadata()?;
    let identity = CreatedFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    // Opening the leaf empty lets a failed chain check remove it without ever
    // disclosing `bytes`. Portable POSIX has no transaction that prevents a
    // process with rename authority over an ancestor from moving that ancestor
    // after this check; the final post-write check above is therefore cleanup,
    // not a claim of namespace atomicity. The checks bracket the irreversible
    // write as tightly as the available handle-relative API permits.
    run_after_file_open_hook();
    if let Err(error) = revalidate_prepared_parent(prep) {
        remove_new_file(prep, path, &identity);
        return Err(std::io::Error::other(error));
    }
    if let Err(error) = file.write_all(bytes) {
        remove_new_file(prep, path, &identity);
        return Err(error);
    }
    Ok(identity)
}

#[cfg(windows)]
fn create_new_file(
    prep: &ParentPrep,
    path: &std::path::Path,
    bytes: &[u8],
) -> std::io::Result<CreatedFileIdentity> {
    windows_parent::create_file(prep, path, bytes)
}

#[cfg(not(any(unix, windows)))]
fn create_new_file(
    _prep: &ParentPrep,
    _path: &std::path::Path,
    _bytes: &[u8],
) -> std::io::Result<CreatedFileIdentity> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure handle-relative new-file creation is unavailable on this platform",
    ))
}

// Win32 has no `openat`; the native equivalent is `NtCreateFile` with a held
// `RootDirectory`. `OBJ_DONT_REPARSE` makes each lookup fail closed if the
// named component is a reparse point. This mirrors the already-audited held
// Windows walk used by daemon agent installation.
#[cfg(windows)]
mod windows_parent {
    use std::{
        ffi::{OsStr, c_void},
        fs::File,
        io::Write as _,
        mem::size_of,
        os::windows::{
            ffi::OsStrExt as _,
            io::{AsRawHandle as _, FromRawHandle as _},
        },
        path::{Component, Path, PathBuf, Prefix},
        ptr,
    };

    use anyhow::{Context, Result, bail, ensure};

    use super::{
        CreatedDirectories, ParentPrep, format_created_directories_line, run_after_file_open_hook,
    };

    type Handle = *mut c_void;
    const INVALID_HANDLE: Handle = -1_isize as Handle;
    const OBJ_CASE_INSENSITIVE: u32 = 0x40;
    const OBJ_DONT_REPARSE: u32 = 0x1000;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const DELETE: u32 = 0x0001_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const FILE_SHARE_ALL: u32 = 0x7;
    const FILE_OPEN: u32 = 1;
    const FILE_CREATE: u32 = 2;
    const FILE_DIRECTORY_FILE: u32 = 0x1;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
    const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const OPEN_EXISTING: u32 = 3;
    const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
    const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035_u32 as i32;
    const STATUS_OBJECT_PATH_NOT_FOUND: i32 = 0xC000_003A_u32 as i32;

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
    struct Disposition {
        delete_file: u8,
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
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    pub(super) struct Identity {
        volume: u32,
        index: u64,
    }
    pub(super) struct DirectoryBinding {
        parent: File,
        name: Vec<u16>,
        identity: Identity,
    }
    pub(super) struct CreatedDirectoryBinding {
        parent: File,
        name: Vec<u16>,
        identity: Identity,
    }

    fn wide_component(value: &OsStr) -> Result<Vec<u16>> {
        let value = value.encode_wide().collect::<Vec<_>>();
        ensure!(
            !value.is_empty() && value.len() <= u16::MAX as usize / 2,
            "invalid Windows path component"
        );
        ensure!(!value.contains(&0), "Windows path component contains NUL");
        Ok(value)
    }

    fn identity(file: &File, directory: bool) -> Result<Identity> {
        let mut info = unsafe { std::mem::zeroed::<ByHandleFileInformation>() };
        ensure!(
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } != 0,
            "querying held Windows path identity failed"
        );
        ensure!(
            info.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "refused: held Windows path is a reparse point"
        );
        ensure!(
            if directory {
                file.metadata()?.is_dir()
            } else {
                file.metadata()?.is_file()
            },
            "refused: held Windows path has the wrong type"
        );
        Ok(Identity {
            volume: info.volume_serial,
            index: (u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low),
        })
    }

    fn open_relative(
        parent: &File,
        name: &[u16],
        disposition: u32,
        kind: u32,
        access: u32,
    ) -> std::result::Result<File, i32> {
        let mut name = name.to_vec();
        let unicode = UnicodeString {
            length: (name.len() * 2) as u16,
            maximum_length: (name.len() * 2) as u16,
            buffer: name.as_mut_ptr(),
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
                disposition,
                kind | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                ptr::null(),
                0,
            )
        };
        if status < 0 || raw.is_null() {
            Err(status)
        } else {
            Ok(unsafe { File::from_raw_handle(raw) })
        }
    }

    fn open_root(path: &Path) -> Result<(File, Vec<std::ffi::OsString>)> {
        let mut components = path.components();
        let prefix = match components.next() {
            Some(Component::Prefix(prefix)) => prefix,
            _ => bail!("secure new-file target must be an absolute Windows path"),
        };
        ensure!(
            matches!(components.next(), Some(Component::RootDir)),
            "secure new-file target must be rooted"
        );
        ensure!(
            matches!(
                prefix.kind(),
                Prefix::Disk(_)
                    | Prefix::VerbatimDisk(_)
                    | Prefix::UNC(_, _)
                    | Prefix::VerbatimUNC(_, _)
            ),
            "secure new-file target must use a drive or UNC root"
        );
        let mut root = PathBuf::from(prefix.as_os_str());
        root.push("\\");
        let wide = root
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_ALL,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        ensure!(
            raw != INVALID_HANDLE,
            "opening held Windows filesystem root failed"
        );
        let root = unsafe { File::from_raw_handle(raw) };
        identity(&root, true)?;
        let rest = components
            .map(|component| match component {
                Component::Normal(name) => Ok(name.to_os_string()),
                Component::CurDir => Ok(std::ffi::OsString::new()),
                _ => bail!("secure new-file target contains unresolved traversal"),
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((root, rest))
    }

    pub(super) fn prepare(path: &Path) -> Result<ParentPrep> {
        let parent = path
            .parent()
            .context("secure new-file target has no parent")?;
        let (mut current, components) = open_root(parent)?;
        let mut built = PathBuf::new();
        let mut created = CreatedDirectories::default();
        let mut bindings = Vec::new();
        let walk = (|| -> Result<()> {
            for name in components.into_iter().filter(|name| !name.is_empty()) {
                built.push(&name);
                let wide = wide_component(&name)?;
                let mut made = false;
                let next = match open_relative(&current, &wide, FILE_OPEN, FILE_DIRECTORY_FILE,
                    GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE) {
                    Ok(file) => file,
                    Err(STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND) => {
                        match open_relative(&current, &wide, FILE_CREATE, FILE_DIRECTORY_FILE,
                            GENERIC_READ | GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE) {
                            Ok(file) => { made = true; file }
                            Err(STATUS_OBJECT_NAME_COLLISION) => open_relative(&current, &wide, FILE_OPEN,
                                FILE_DIRECTORY_FILE, GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
                                .map_err(|status| anyhow::anyhow!("opening concurrently-created Windows directory failed with NTSTATUS {status:#x}"))?,
                            Err(status) => bail!("creating held Windows directory failed with NTSTATUS {status:#x}"),
                        }
                    }
                    Err(status) => bail!("opening held Windows directory failed with NTSTATUS {status:#x}"),
                };
                let id = match identity(&next, true) {
                    Ok(identity) => identity,
                    Err(error) => {
                        if made {
                            let _ = mark_delete(&next);
                        }
                        return Err(error);
                    }
                };
                if made {
                    let rollback_parent = match current.try_clone() {
                        Ok(parent) => parent,
                        Err(error) => {
                            remove_wide_if_identity(&current, &wide, true, id);
                            return Err(error.into());
                        }
                    };
                    created.paths.push(built.clone());
                    created.bindings.push(CreatedDirectoryBinding {
                        parent: rollback_parent,
                        name: wide.clone(),
                        identity: id,
                    });
                }
                bindings.push(DirectoryBinding {
                    parent: current.try_clone()?,
                    name: wide,
                    identity: id,
                });
                current = next;
            }
            Ok(())
        })();
        if let Err(error) = walk {
            created.rollback();
            return Err(error);
        }
        let disclosure = format_created_directories_line(&created.paths);
        let prep = ParentPrep {
            disclosure,
            created,
            parent_directory: Some(current),
            bindings,
        };
        if let Err(error) = revalidate(&prep.bindings) {
            prep.created.rollback();
            return Err(error);
        }
        Ok(prep)
    }

    pub(super) fn revalidate(bindings: &[DirectoryBinding]) -> Result<()> {
        for binding in bindings {
            let file = open_relative(
                &binding.parent,
                &binding.name,
                FILE_OPEN,
                FILE_DIRECTORY_FILE,
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            )
            .map_err(|status| {
                anyhow::anyhow!("refused: prepared Windows parent changed (NTSTATUS {status:#x})")
            })?;
            ensure!(
                identity(&file, true)? == binding.identity,
                "refused: prepared Windows parent component changed identity"
            );
        }
        Ok(())
    }

    fn mark_delete(file: &File) -> Result<()> {
        let disposition = Disposition { delete_file: 1 };
        let mut io = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let status = unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut io,
                (&raw const disposition).cast(),
                size_of::<Disposition>() as u32,
                13,
            )
        };
        ensure!(
            status >= 0,
            "held Windows deletion failed with NTSTATUS {status:#x}"
        );
        Ok(())
    }

    pub(super) fn remove_relative_if_identity(
        parent: &File,
        name: &OsStr,
        directory: bool,
        expected: Identity,
    ) {
        let Ok(name) = wide_component(name) else {
            return;
        };
        remove_wide_if_identity(parent, &name, directory, expected);
    }

    fn remove_wide_if_identity(parent: &File, name: &[u16], directory: bool, expected: Identity) {
        let kind = if directory {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        };
        let Ok(file) = open_relative(
            parent,
            name,
            FILE_OPEN,
            kind,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        ) else {
            return;
        };
        if identity(&file, directory).ok() == Some(expected) {
            let _ = mark_delete(&file);
        }
    }

    pub(super) fn rollback(bindings: &[CreatedDirectoryBinding]) {
        for binding in bindings.iter().rev() {
            remove_wide_if_identity(&binding.parent, &binding.name, true, binding.identity);
        }
    }

    pub(super) fn create_file(
        prep: &ParentPrep,
        path: &Path,
        bytes: &[u8],
    ) -> std::io::Result<Identity> {
        let parent = prep
            .parent_directory
            .as_ref()
            .ok_or_else(|| std::io::Error::other("missing held Windows parent"))?;
        let name = wide_component(
            path.file_name()
                .ok_or_else(|| std::io::Error::other("missing Windows filename"))?,
        )
        .map_err(std::io::Error::other)?;
        let mut file = open_relative(
            parent,
            &name,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE,
            GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        )
        .map_err(|status| {
            let kind = if status == STATUS_OBJECT_NAME_COLLISION {
                std::io::ErrorKind::AlreadyExists
            } else {
                std::io::ErrorKind::Other
            };
            std::io::Error::new(
                kind,
                format!("held Windows file create failed with NTSTATUS {status:#x}"),
            )
        })?;
        let result = (|| -> Result<Identity> {
            let id = match identity(&file, false) {
                Ok(identity) => identity,
                Err(error) => {
                    let _ = mark_delete(&file);
                    return Err(error);
                }
            };
            run_after_file_open_hook();
            if let Err(error) = revalidate(&prep.bindings) {
                let _ = mark_delete(&file);
                return Err(error);
            }
            if let Err(error) = file.write_all(bytes) {
                let _ = mark_delete(&file);
                return Err(error.into());
            }
            Ok(id)
        })();
        result.map_err(std::io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        db::Db,
        engine::{
            agent::TurnEvent,
            tool::{ToolFailKind, classify_failure},
        },
        tools::{
            common::{LOCK_BOOKKEEPING_ADVISORY, test_ctx, test_ctx_with_db},
            read::ReadTool,
        },
    };
    use std::{
        path::{Path, PathBuf},
        sync::Arc,
    };

    async fn fail_lock_state_deletes(db: &Db) {
        db.write(move |conn| {
            conn.execute_batch(
                "CREATE TEMP TRIGGER fail_lock_state_delete
                 BEFORE DELETE ON lock_state
                 BEGIN
                     SELECT RAISE(FAIL, 'forced lock_state delete failure');
                 END;",
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }

    async fn identity_refusal_ctx(
        home: &std::path::Path,
    ) -> (ToolCtx, crate::test_env::TestEnvGuard) {
        let env = crate::test_env::TestEnvGuard::isolate_cockpit_home_at_async(home).await;
        let canonical = crate::assistants::default_home_dir("helper").unwrap();
        std::fs::create_dir_all(&canonical).unwrap();
        crate::assistants::identity::seed_identity_files(&canonical).unwrap();
        let db = Db::open_in_memory().unwrap();
        let cfg = crate::assistants::AssistantConfig {
            agent_source: canonical.join("assistant.md").display().to_string(),
            soul_edit_mode: crate::assistants::identity::SoulEditMode::HumanOnly,
            soul_hash: crate::assistants::identity::hash_optional_file(
                &crate::assistants::identity::soul_path(&canonical),
            )
            .unwrap(),
            user_hash: crate::assistants::identity::hash_optional_file(
                &crate::assistants::identity::user_path(&canonical),
            )
            .unwrap(),
            ..crate::assistants::AssistantConfig::default()
        };
        db.upsert_assistant(
            "helper",
            &canonical.display().to_string(),
            &serde_json::to_string(&cfg).unwrap(),
            &"a".repeat(64),
        )
        .await
        .unwrap();
        let project_id = crate::session::project_id_for(&canonical).unwrap();
        let project_root = canonical.display().to_string();
        let session_row = db
            .write(move |conn| {
                crate::db::Db::insert_session_row_conn(
                    conn,
                    &crate::db::Db::build_new_assistant_session_row_conn(
                        conn,
                        &project_id,
                        &project_root,
                        "helper",
                        "helper",
                    )?,
                )
            })
            .await
            .unwrap();
        let session = crate::session::Session::resume_for_test(
            db.clone(),
            session_row.session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .unwrap();
        let locks = Arc::new(crate::locks::LockManager::in_memory(db.clone()));
        let redact = Arc::new(
            crate::redact::RedactionTable::build(
                &crate::config::extended::RedactConfig::default(),
                &canonical,
            )
            .unwrap(),
        );
        let ctx = ToolCtx {
            agent_id: "helper".to_string(),
            allowed_knowledge_bases: None,
            executing_model_trusted: false,
            knowledge_access_trusted: false,
            caller_model: None,
            agent_instance_id: None,
            lock_identity: "helper".to_string(),
            write_scope: None,
            dream_read_scope: std::sync::Arc::new(std::sync::RwLock::new(None)),
            workspace_lease: None,
            current_tool_call_id: None,
            tool_steering: crate::agents::ToolSteering::Terse,
            locks,
            session: Arc::new(session),
            cwd: canonical.clone(),
            redact,
            interrupts: Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            cancel: tokio_util::sync::CancellationToken::new(),
            shutdown_gate: crate::daemon::shutdown::ShutdownSignal::new(),
            ..crate::tools::common::test_ctx(&canonical)
        };
        (ctx, env)
    }

    fn skill_manifest(name: &str, description: &str, body: &str) -> String {
        format!("---\nname: {name}\ndescription: {description}\n---\n\n{body}\n")
    }

    fn skill_manifest_with_extra(name: &str, extra: &str) -> String {
        format!("---\nname: {name}\ndescription: d\n{extra}---\n\nBody\n")
    }

    fn write_skill_package(root: &Path, name: &str, manifest: &str) -> PathBuf {
        let package = root.join(".agents").join("skills").join(name);
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("SKILL.md"), manifest).unwrap();
        package
    }

    fn skill_test_ctx(root: &Path) -> ToolCtx {
        let mut ctx = test_ctx(root);
        let mut extended = crate::config::extended::ExtendedConfig::default();
        extended.skills.scan_dirs = vec![".agents/skills".to_string()];
        ctx.config = crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                0,
                crate::config::providers::ProvidersConfig::default(),
                extended,
            ),
        );
        ctx
    }

    async fn note_read(ctx: &ToolCtx, path: &Path) {
        ctx.locks
            .note_read(path, &ctx.lock_identity, ctx.session.id)
            .await;
    }

    fn trusted_policy(root: &Path) -> crate::config::trust::WorkspaceTrustPolicy {
        crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::TrustRoot {
                opened_path: root.to_path_buf(),
                root: root.to_path_buf(),
                kind: crate::config::trust::TrustRootKind::Directory,
            },
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        }
    }

    fn discover_skills(
        ctx: &ToolCtx,
        cfg: &crate::config::extended::SkillsConfig,
    ) -> anyhow::Result<Vec<crate::skills::Skill>> {
        crate::config::trust::with_workspace_trust_policy(trusted_policy(&ctx.cwd), || {
            crate::skills::discover(&ctx.cwd, cfg)
        })
    }

    fn catalog_cache_contains(ctx: &ToolCtx, cfg: &crate::config::extended::SkillsConfig) -> bool {
        crate::config::trust::with_workspace_trust_policy(trusted_policy(&ctx.cwd), || {
            crate::skills::catalog_cache_contains(&ctx.cwd, cfg)
        })
    }

    #[tokio::test]
    async fn plan_write_tool_cannot_fall_through_to_a_host_file() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let host_path = tmp.path().join("must-not-exist.txt");

        let error = PlanWriteTool
            .call(
                serde_json::json!({ "path": host_path, "content": "forbidden" }),
                &ctx,
            )
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("Plan may write only"));
        assert!(!tmp.path().join("must-not-exist.txt").exists());
    }

    #[test]
    fn filesystem_write_effects_bind_path_and_exact_content_commitments() {
        let path = Path::new("/workspace/.agents/skills/example/SKILL.md");
        let approved = host_approval_filesystem_write_effects(path, Some(b"before"), b"after");
        let altered = host_approval_filesystem_write_effects(path, Some(b"before"), b"different");

        assert_eq!(approved.len(), 2);
        assert_eq!(approved[0]["access"]["path"], path.display().to_string());
        assert_eq!(approved[0]["access"]["required_access"], "ReadWrite");
        assert_eq!(
            approved[1]["write"]["previous"],
            crate::approval::write_content_commitment(b"before")
        );
        assert_ne!(
            approved[1]["write"], altered[1]["write"],
            "a final write fence must reject changed content after approval"
        );
    }

    async fn load_skill(
        name: &str,
        ctx: &ToolCtx,
    ) -> anyhow::Result<crate::engine::tool::ToolOutput> {
        crate::config::trust::scope_workspace_trust_policy(trusted_policy(&ctx.cwd), async {
            crate::tools::skill::SkillTool
                .call(serde_json::json!({"name": name}), ctx)
                .await
        })
        .await
    }

    async fn write(path: &Path, content: &str, ctx: &ToolCtx) -> anyhow::Result<String> {
        crate::config::trust::scope_workspace_trust_policy(trusted_policy(&ctx.cwd), async {
            Ok(WriteTool
                .call(
                    serde_json::json!({
                        "path": path.display().to_string(),
                        "content": content
                    }),
                    ctx,
                )
                .await?
                .content
                .to_string())
        })
        .await
    }

    async fn edit(path: &Path, old: &str, new: &str, ctx: &ToolCtx) -> anyhow::Result<String> {
        crate::config::trust::scope_workspace_trust_policy(trusted_policy(&ctx.cwd), async {
            Ok(crate::tools::edit::EditTool
                .call(
                    serde_json::json!({
                        "path": path.display().to_string(),
                        "old_string": old,
                        "new_string": new
                    }),
                    ctx,
                )
                .await?
                .content
                .to_string())
        })
        .await
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn write_creates_new_file_without_prior_read() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());

        WriteTool
            .call(
                serde_json::json!({"path": "created.md", "content": "hello\n"}),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(tmp.path().join("created.md")).unwrap(),
            "hello\n"
        );
    }

    #[tokio::test]
    async fn write_rejects_invalid_skill_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let original = skill_manifest("bad", "d", "Body");
        let package = write_skill_package(tmp.path(), "bad", &original);
        let ctx = skill_test_ctx(tmp.path());
        let manifest = package.join("SKILL.md");
        note_read(&ctx, &manifest).await;

        let err = write(&manifest, "no frontmatter\n", &ctx)
            .await
            .unwrap_err();
        assert_eq!(classify_failure(&err), ToolFailKind::Invocation);
        let err = err.to_string();

        assert!(err.contains("YAML frontmatter"), "{err}");
        assert_eq!(std::fs::read_to_string(manifest).unwrap(), original);
    }

    #[tokio::test]
    async fn write_rejects_skill_manifest_rename() {
        let tmp = tempfile::tempdir().unwrap();
        let original = skill_manifest("stable", "d", "Body");
        let package = write_skill_package(tmp.path(), "stable", &original);
        let ctx = skill_test_ctx(tmp.path());
        let manifest = package.join("SKILL.md");
        note_read(&ctx, &manifest).await;

        let err = write(&manifest, &skill_manifest("renamed", "d", "Body"), &ctx)
            .await
            .unwrap_err()
            .to_string();

        assert!(err.contains("must remain `stable`"), "{err}");
        assert_eq!(std::fs::read_to_string(manifest).unwrap(), original);
    }

    #[tokio::test]
    async fn write_support_file_rule_matrix() {
        let tmp = tempfile::tempdir().unwrap();
        let package = write_skill_package(
            tmp.path(),
            "support",
            &skill_manifest("support", "d", "Body"),
        );
        let ctx = skill_test_ctx(tmp.path());

        let err = write(&package.join("notes").join("a.md"), "x", &ctx)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("support file must be under one of"), "{err}");

        let err = write(
            &package.join("references").join("..").join("escape.md"),
            "x",
            &ctx,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("parent traversal"), "{err}");

        let err = write(
            &package.join("references").join("large.md"),
            &"x".repeat(100_001),
            &ctx,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("100000 character limit"), "{err}");
    }

    #[tokio::test]
    async fn skill_package_protection_blocks_plain_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let cases = [
            (
                "hubbed",
                skill_manifest_with_extra("hubbed", "hub-installed: true\n"),
                "hub-installed skill `hubbed` is read-only",
            ),
            (
                "bundled",
                skill_manifest_with_extra("bundled", "bundled: true\n"),
                "bundled skill `bundled` is read-only",
            ),
            (
                "pinned",
                skill_manifest_with_extra("pinned", "pinned: true\n"),
                "pinned skill `pinned` is read-only",
            ),
        ];

        let packages: Vec<_> = cases
            .iter()
            .map(|(name, manifest, expected)| {
                (
                    *name,
                    write_skill_package(tmp.path(), name, manifest),
                    *expected,
                    manifest.clone(),
                )
            })
            .collect();
        let ctx = skill_test_ctx(tmp.path());

        for (name, package, expected, manifest) in packages {
            let skill_md = package.join("SKILL.md");
            note_read(&ctx, &skill_md).await;
            let write_err = write(&skill_md, &skill_manifest(name, "new", "Body"), &ctx)
                .await
                .unwrap_err()
                .to_string();
            assert!(write_err.contains(expected), "{write_err}");

            let edit_err = edit(&skill_md, "description: d", "description: new", &ctx)
                .await
                .unwrap_err()
                .to_string();
            assert!(edit_err.contains(expected), "{edit_err}");
            assert_eq!(std::fs::read_to_string(skill_md).unwrap(), manifest);
        }
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn write_refuses_symlinked_skill_target() {
        let tmp = tempfile::tempdir().unwrap();
        let package =
            write_skill_package(tmp.path(), "links", &skill_manifest("links", "d", "Body"));
        let ctx = skill_test_ctx(tmp.path());
        let refs = package.join("references");
        std::fs::create_dir_all(&refs).unwrap();
        let real = refs.join("real.md");
        let link = refs.join("link.md");
        std::fs::write(&real, "old").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        note_read(&ctx, &link).await;

        let err = write(&link, "new", &ctx).await.unwrap_err().to_string();

        assert!(err.contains("may not traverse symlinks"), "{err}");
        assert_eq!(std::fs::read_to_string(real).unwrap(), "old");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn write_validates_outside_symlink_to_skill_target() {
        let tmp = tempfile::tempdir().unwrap();
        let original = skill_manifest("outside-link", "d", "Body");
        let package = write_skill_package(tmp.path(), "outside-link", &original);
        let ctx = skill_test_ctx(tmp.path());
        let manifest = package.join("SKILL.md");
        let link = tmp.path().join("manifest-link.md");
        std::os::unix::fs::symlink(&manifest, &link).unwrap();
        note_read(&ctx, &manifest).await;

        let err = write(&link, "not frontmatter\n", &ctx).await.unwrap_err();

        assert_eq!(classify_failure(&err), ToolFailKind::Invocation);
        let err = err.to_string();
        assert!(err.contains("YAML frontmatter"), "{err}");
        assert_eq!(std::fs::read_to_string(manifest).unwrap(), original);
    }

    #[tokio::test]
    async fn valid_skill_write_invalidates_catalog_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let package =
            write_skill_package(tmp.path(), "valid", &skill_manifest("valid", "old", "Body"));
        let ctx = skill_test_ctx(tmp.path());
        let manifest = package.join("SKILL.md");
        note_read(&ctx, &manifest).await;
        let cfg = ctx.config.extended();
        let discovered = discover_skills(&ctx, &cfg.skills).unwrap();
        assert_eq!(discovered[0].frontmatter.description, "old");
        let before = crate::skills::catalog_generation();

        write(&manifest, &skill_manifest("valid", "new", "Body"), &ctx)
            .await
            .unwrap();

        assert!(crate::skills::catalog_generation() > before);
        let discovered = discover_skills(&ctx, &cfg.skills).unwrap();
        assert_eq!(discovered[0].frontmatter.description, "new");
    }

    #[tokio::test]
    async fn valid_skill_write_reports_validation_note() {
        let tmp = tempfile::tempdir().unwrap();
        let package =
            write_skill_package(tmp.path(), "note", &skill_manifest("note", "old", "Body"));
        let ctx = skill_test_ctx(tmp.path());
        let manifest = package.join("SKILL.md");
        note_read(&ctx, &manifest).await;

        let out = write(&manifest, &skill_manifest("note", "new", "Body"), &ctx)
            .await
            .unwrap();

        assert!(
            out.contains("[skill] validated note (manifest); catalog refreshed"),
            "{out}"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn caged_skill_write_requires_prior_view() {
        let tmp = tempfile::tempdir().unwrap();
        let package = write_skill_package(
            tmp.path(),
            "view-first",
            &skill_manifest("view-first", "old", "Body"),
        );
        let mut ctx = skill_test_ctx(tmp.path());
        ctx.review_cage = Some(
            crate::engine::tool::ReviewCage::skills_review_with_package_roots([package.clone()]),
        );
        let support = package.join("references").join("guide.md");

        let err = write(&support, "reviewed", &ctx)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("must load `view-first`"), "{err}");
        assert!(!support.exists());

        load_skill("view-first", &ctx).await.unwrap();
        let out = write(&support, "reviewed", &ctx).await.unwrap();
        assert!(out.contains("[skill] validated view-first"), "{out}");
        assert_eq!(std::fs::read_to_string(support).unwrap(), "reviewed");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn uncaged_skill_write_does_not_require_view() {
        let tmp = tempfile::tempdir().unwrap();
        let package =
            write_skill_package(tmp.path(), "plain", &skill_manifest("plain", "old", "Body"));
        let ctx = skill_test_ctx(tmp.path());
        let support = package.join("references").join("guide.md");

        write(&support, "foreground", &ctx).await.unwrap();

        assert_eq!(std::fs::read_to_string(support).unwrap(), "foreground");
    }

    #[tokio::test]
    async fn rejected_skill_write_leaves_lock_usable() {
        let tmp = tempfile::tempdir().unwrap();
        let original = skill_manifest("retry", "old", "Body");
        let package = write_skill_package(tmp.path(), "retry", &original);
        let ctx = skill_test_ctx(tmp.path());
        let manifest = package.join("SKILL.md");
        note_read(&ctx, &manifest).await;

        let err = write(&manifest, "broken", &ctx).await.unwrap_err();
        assert!(err.to_string().contains("YAML frontmatter"), "{err}");
        let out = write(&manifest, &skill_manifest("retry", "new", "Body"), &ctx)
            .await
            .unwrap();

        assert!(out.contains("[skill] validated retry"), "{out}");
        assert!(
            std::fs::read_to_string(manifest)
                .unwrap()
                .contains("description: new")
        );
    }

    #[tokio::test]
    async fn non_skill_write_is_unaffected() {
        let tmp = tempfile::tempdir().unwrap();
        write_skill_package(
            tmp.path(),
            "cached",
            &skill_manifest("cached", "old", "Body"),
        );
        let ctx = skill_test_ctx(tmp.path());
        let cfg = ctx.config.extended();
        let discovered = discover_skills(&ctx, &cfg.skills).unwrap();
        assert_eq!(discovered[0].frontmatter.description, "old");
        assert!(catalog_cache_contains(&ctx, &cfg.skills));
        let plain = tmp.path().join("plain.md");
        std::fs::write(&plain, "old").unwrap();
        note_read(&ctx, &plain).await;

        let out = write(&plain, "hello", &ctx).await.unwrap();

        assert!(!out.contains("[skill]"), "{out}");
        assert!(catalog_cache_contains(&ctx, &cfg.skills));
        assert_eq!(std::fs::read_to_string(plain).unwrap(), "hello");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn write_creating_new_file_needs_no_read_record() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let file = tmp.path().join("created.md");

        WriteTool
            .call(
                serde_json::json!({"path": "created.md", "content": "hello\n"}),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(std::fs::read_to_string(&file).unwrap(), "hello\n");
        assert!(ctx.locks.holder(&file).is_none());
        assert!(
            !ctx.locks
                .has_read(&file, &ctx.lock_identity, ctx.session.id)
        );
    }

    #[tokio::test]
    async fn write_outside_scope_hard_denied_read_unclamped() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = test_ctx(tmp.path());
        let scope = tmp.path().join("scope");
        let outside = tmp.path().join("outside.txt");
        std::fs::create_dir_all(&scope).unwrap();
        std::fs::write(&outside, "readable").unwrap();
        let inside = scope.join("inside.txt");
        std::fs::write(&inside, "old").unwrap();
        ctx.write_scope = Some(scope.clone());
        note_read(&ctx, &inside).await;

        let err = WriteTool
            .call(
                serde_json::json!({"path": "outside.txt", "content": "blocked"}),
                &ctx,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("outside this child's write scope"), "{err}");
        assert!(err.contains(&scope.display().to_string()), "{err}");
        assert!(ctx.locks.holder(&outside).is_none());

        WriteTool
            .call(
                serde_json::json!({"path": "scope/inside.txt", "content": "ok"}),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(inside).unwrap(), "ok");

        let read = ReadTool
            .call(serde_json::json!({"path": "outside.txt"}), &ctx)
            .await
            .unwrap();
        assert!(read.content.contains("readable"), "{}", read.content);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn missing_read_then_new_file_write_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());

        let _ = ReadTool
            .call(serde_json::json!({"path": "later.md"}), &ctx)
            .await;

        WriteTool
            .call(
                serde_json::json!({"path": "later.md", "content": "created\n"}),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(tmp.path().join("later.md")).unwrap(),
            "created\n"
        );
        assert!(!ctx.locks.has_read(
            &tmp.path().join("later.md"),
            &ctx.lock_identity,
            ctx.session.id
        ));
    }

    #[tokio::test]
    async fn existing_file_without_prior_read_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("existing.md"), "old\n").unwrap();
        let ctx = test_ctx(tmp.path());

        let err = WriteTool
            .call(
                serde_json::json!({"path": "existing.md", "content": "new\n"}),
                &ctx,
            )
            .await
            .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("read it first"), "{msg}");
        assert!(msg.contains("retry write"), "{msg}");
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("existing.md")).unwrap(),
            "old\n"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn new_file_write_creates_missing_parent_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());

        WriteTool
            .call(
                serde_json::json!({"path": "nested/deep/file.txt", "content": "body"}),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(tmp.path().join("nested/deep/file.txt")).unwrap(),
            "body"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn nested_write_discloses_created_parent_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());

        let out = WriteTool
            .call(
                serde_json::json!({"path": "nested/deep/file.txt", "content": "body"}),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(tmp.path().join("nested/deep/file.txt")).unwrap(),
            "body"
        );
        assert!(
            out.content.contains("created directories: nested/…/deep"),
            "{}",
            out.content
        );
        let wrote_idx = out.content.find("wrote `").expect("wrote line");
        let created_idx = out
            .content
            .find("created directories:")
            .expect("created-directories line");
        assert!(wrote_idx < created_idx, "{}", out.content);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn write_into_existing_directory_does_not_disclose_created_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        std::fs::create_dir_all(tmp.path().join("existing")).unwrap();

        let existing_dir_out = WriteTool
            .call(
                serde_json::json!({"path": "existing/file.txt", "content": "body"}),
                &ctx,
            )
            .await
            .unwrap();
        let cwd_out = WriteTool
            .call(
                serde_json::json!({"path": "plain.txt", "content": "body"}),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(tmp.path().join("existing/file.txt")).unwrap(),
            "body"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("plain.txt")).unwrap(),
            "body"
        );
        assert!(
            !existing_dir_out.content.contains("created directories:"),
            "{}",
            existing_dir_out.content
        );
        assert!(
            !cwd_out.content.contains("created directories:"),
            "{}",
            cwd_out.content
        );
        assert!(
            existing_dir_out.content.starts_with("wrote `"),
            "{}",
            existing_dir_out.content
        );
        assert!(
            cwd_out.content.starts_with("wrote `"),
            "{}",
            cwd_out.content
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn single_created_parent_directory_discloses_without_ellipsis() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());

        let out = WriteTool
            .call(
                serde_json::json!({"path": "nested/file.txt", "content": "body"}),
                &ctx,
            )
            .await
            .unwrap();

        assert!(
            out.content.contains("created directories: nested"),
            "{}",
            out.content
        );
        assert!(!out.content.contains("/…/"), "{}", out.content);
    }

    #[test]
    #[cfg(unix)]
    fn created_directories_line_names_first_and_parent_components() {
        assert_eq!(
            format_created_directories_line(&[PathBuf::from("nested")]).as_deref(),
            Some("created directories: nested")
        );
        assert_eq!(
            format_created_directories_line(&[
                PathBuf::from("nested"),
                PathBuf::from("nested/deep"),
            ])
            .as_deref(),
            Some("created directories: nested/…/deep")
        );
        assert_eq!(
            format_created_directories_line(&[
                PathBuf::from("a"),
                PathBuf::from("a/b"),
                PathBuf::from("a/b/c"),
            ])
            .as_deref(),
            Some("created directories: a/…/c")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    #[cfg(unix)]
    async fn write_refuses_symlinked_intermediate_planted_between_check_and_create() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = test_ctx(tmp.path());
        let scope = tmp.path().join("scope");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&scope).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        ctx.write_scope = Some(scope.clone());

        let nested = scope.join("nested");
        let outside_for_hook = outside.clone();
        set_before_parent_create_hook(move || {
            std::os::unix::fs::symlink(&outside_for_hook, &nested).unwrap();
        });

        let err = WriteTool
            .call(
                serde_json::json!({
                    "path": "scope/nested/deep/file.txt",
                    "content": "escaped"
                }),
                &ctx,
            )
            .await
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("symlink") || err.contains("not a directory"),
            "{err}"
        );
        assert!(!outside.join("deep").exists());
        assert!(!outside.join("deep/file.txt").exists());
        assert!(!scope.join("nested/deep/file.txt").exists());
        assert!(
            ctx.locks
                .holder(&scope.join("nested/deep/file.txt"))
                .is_none()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    #[cfg(unix)]
    async fn unscoped_write_refuses_existing_parent_component_swapped_after_authorization() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let outside = tempfile::tempdir().unwrap();
        let existing = tmp.path().join("existing");
        let parked = tmp.path().join("parked-existing");
        std::fs::create_dir_all(existing.join("deep")).unwrap();
        std::fs::create_dir_all(outside.path().join("deep")).unwrap();

        let existing_for_hook = existing.clone();
        let parked_for_hook = parked.clone();
        let outside_for_hook = outside.path().to_path_buf();
        set_before_parent_create_hook(move || {
            std::fs::rename(existing_for_hook, parked_for_hook).unwrap();
            std::os::unix::fs::symlink(outside_for_hook, existing).unwrap();
        });

        let error = WriteTool
            .call(
                serde_json::json!({
                    "path": "existing/deep/file.txt",
                    "content": "escaped"
                }),
                &ctx,
            )
            .await
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("symlink") || error.contains("not a directory"),
            "{error}"
        );
        assert!(!outside.path().join("deep/file.txt").exists());
        assert!(!parked.join("deep/file.txt").exists());
    }

    #[test]
    #[cfg(unix)]
    fn approved_external_target_refuses_ancestor_swapped_before_root_acquisition() {
        let holder = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let approved = holder.path().join("approved");
        let parked = holder.path().join("parked-approved");
        std::fs::create_dir_all(&approved).unwrap();
        let target = approved.join("nested/file.txt");

        let approved_for_hook = approved.clone();
        let outside_for_hook = outside.path().to_path_buf();
        set_before_parent_create_hook(move || {
            std::fs::rename(approved_for_hook, &parked).unwrap();
            std::os::unix::fs::symlink(outside_for_hook, approved).unwrap();
        });

        let error = ensure_parent_dirs(&target).err().unwrap().to_string();

        assert!(
            error.contains("symlink") || error.contains("not a directory"),
            "{error}"
        );
        assert!(!outside.path().join("nested").exists());
    }

    #[test]
    #[cfg(unix)]
    fn created_directory_reopen_refuses_substituted_entry_without_chmod_or_rollback() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("nested");
        let parked = tmp.path().join("parked-created");
        let nested_for_hook = nested.clone();
        let parked_for_hook = parked.clone();
        set_after_directory_create_hook(move || {
            std::fs::rename(&nested_for_hook, &parked_for_hook).unwrap();
            std::fs::create_dir(&nested_for_hook).unwrap();
            std::fs::set_permissions(&nested_for_hook, std::fs::Permissions::from_mode(0o711))
                .unwrap();
        });

        let error = ensure_parent_dirs(&tmp.path().join("nested/file.txt"))
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("changed identity"), "{error}");
        assert!(
            nested.is_dir(),
            "foreign replacement must not be rolled back"
        );
        assert_eq!(
            std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777,
            0o711,
            "foreign replacement must not be chmodded"
        );
        assert!(
            parked.is_dir(),
            "the displaced created inode remains untouched"
        );
    }

    #[test]
    #[cfg(unix)]
    fn staged_directory_substitution_is_never_chmodded_published_or_rollback_owned() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let parked = tmp.path().join("parked-stage");
        let foreign = tmp.path().join("foreign-stage");
        std::fs::create_dir(&foreign).unwrap();
        std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o711)).unwrap();
        set_before_staged_directory_open_hook(move || {
            let stage = std::fs::read_dir(&root)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".cockpit-create-")
                })
                .unwrap();
            std::fs::rename(&stage, &parked).unwrap();
            std::fs::rename(&foreign, &stage).unwrap();
        });
        let error = ensure_parent_dirs(&tmp.path().join("nested/file.txt"))
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("changed identity"), "{error}");
        assert!(!tmp.path().join("nested").exists());
        let replacement = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".cockpit-create-")
            })
            .unwrap();
        assert_eq!(
            std::fs::metadata(replacement).unwrap().permissions().mode() & 0o777,
            0o711
        );
        assert!(tmp.path().join("parked-stage").is_dir());
    }

    #[tokio::test(flavor = "current_thread")]
    #[cfg(unix)]
    async fn write_revalidates_parent_directory_after_mkdir() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = test_ctx(tmp.path());
        let scope = tmp.path().join("scope");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&scope).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        ctx.write_scope = Some(scope.clone());

        let nested = scope.join("nested");
        let parked = tmp.path().join("parked-nested");
        let outside_for_hook = outside.clone();
        set_after_parent_create_hook(move || {
            std::fs::rename(&nested, &parked).unwrap();
            std::fs::create_dir_all(outside_for_hook.join("deep")).unwrap();
            std::os::unix::fs::symlink(&outside_for_hook, &nested).unwrap();
        });

        let err = WriteTool
            .call(
                serde_json::json!({
                    "path": "scope/nested/deep/file.txt",
                    "content": "escaped"
                }),
                &ctx,
            )
            .await
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("changed") || err.contains("authorized root"),
            "{err}"
        );
        assert!(!outside.join("deep/file.txt").exists());
        assert!(!scope.join("nested/deep/file.txt").is_file());
    }

    #[tokio::test(flavor = "current_thread")]
    #[cfg(unix)]
    async fn leaf_create_refuses_held_parent_replaced_by_in_scope_decoy() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = test_ctx(tmp.path());
        let scope = tmp.path().join("scope");
        std::fs::create_dir_all(&scope).unwrap();
        ctx.write_scope = Some(scope.clone());

        let nested = scope.join("nested");
        let parked = tmp.path().join("parked-nested");
        let nested_for_hook = nested.clone();
        let parked_for_hook = parked.clone();
        set_before_file_create_hook(move || {
            std::fs::rename(&nested_for_hook, parked_for_hook).unwrap();
            std::fs::create_dir_all(nested_for_hook.join("deep")).unwrap();
        });

        let error = WriteTool
            .call(
                serde_json::json!({
                    "path": "scope/nested/deep/file.txt",
                    "content": "held"
                }),
                &ctx,
            )
            .await
            .unwrap_err()
            .to_string();

        assert!(!nested.join("deep/file.txt").exists());
        assert!(!parked.join("deep/file.txt").exists());
        assert!(error.contains("changed identity"), "{error}");
    }

    #[tokio::test(flavor = "current_thread")]
    #[cfg(unix)]
    async fn leaf_open_rechecks_parent_before_writing_content_and_removes_empty_leaf() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let parent = tmp.path().join("nested/deep");
        let parked = tmp.path().join("parked-deep");
        let parent_for_hook = parent.clone();
        let parked_for_hook = parked.clone();
        set_after_file_open_hook(move || {
            std::fs::rename(parent_for_hook, parked_for_hook).unwrap();
        });

        let error = WriteTool
            .call(
                serde_json::json!({
                    "path": "nested/deep/file.txt",
                    "content": "must not be disclosed"
                }),
                &ctx,
            )
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("changed identity"), "{error}");
        assert!(!parked.join("file.txt").exists());
        assert!(!parent.join("file.txt").exists());
    }

    #[tokio::test(flavor = "current_thread")]
    #[cfg(unix)]
    async fn concurrent_parent_creator_is_not_disclosed_as_ours() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let nested = tmp.path().join("nested/deep");
        set_before_parent_create_hook(move || std::fs::create_dir_all(nested).unwrap());

        let out = WriteTool
            .call(
                serde_json::json!({"path": "nested/deep/file.txt", "content": "body"}),
                &ctx,
            )
            .await
            .unwrap();

        assert!(
            !out.content.contains("created directories:"),
            "{}",
            out.content
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn unscoped_new_file_with_external_existing_parent_is_not_rejected() {
        let external = tempfile::tempdir().unwrap();
        let path = external.path().join("file.txt");
        let prep = ensure_parent_dirs(&path).unwrap();

        create_new_file(&prep, &path, b"body").unwrap();

        assert_eq!(std::fs::read_to_string(path).unwrap(), "body");
    }

    #[test]
    #[cfg(windows)]
    fn windows_new_file_creation_uses_held_parent_with_existing_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("new.txt");
        let prep = ensure_parent_dirs(&path).unwrap();

        create_new_file(&prep, &path, b"body").unwrap();

        assert_eq!(std::fs::read_to_string(path).unwrap(), "body");
        assert!(prep.disclosure.is_none());
    }

    #[test]
    #[cfg(windows)]
    fn windows_new_file_creation_creates_and_discloses_nested_parents() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested/deep/new.txt");
        let prep = ensure_parent_dirs(&path).unwrap();

        create_new_file(&prep, &path, b"body").unwrap();

        assert_eq!(std::fs::read_to_string(path).unwrap(), "body");
        assert_eq!(
            prep.disclosure.as_deref(),
            Some("created directories: nested/…/deep")
        );
    }

    #[test]
    #[cfg(windows)]
    fn windows_leaf_open_revalidates_parent_before_writing() {
        let tmp = tempfile::tempdir().unwrap();
        let parent = tmp.path().join("nested");
        let parked = tmp.path().join("parked-nested");
        let path = parent.join("new.txt");
        std::fs::create_dir(&parent).unwrap();
        let prep = ensure_parent_dirs(&path).unwrap();
        let parent_for_hook = parent.clone();
        let parked_for_hook = parked.clone();
        set_after_file_open_hook(move || {
            std::fs::rename(parent_for_hook, parked_for_hook).unwrap();
        });

        let error = create_new_file(&prep, &path, b"must not be disclosed")
            .unwrap_err()
            .to_string();

        assert!(error.contains("changed"), "{error}");
        assert!(!path.exists());
        assert!(!parked.join("new.txt").exists());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn failed_create_rolls_back_directories_this_call_created() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let path = tmp.path().join("nested/deep/file.txt");

        ctx.locks
            .acquire(&path, &ctx.lock_identity, ctx.session.id)
            .await
            .unwrap();
        let guard = ctx
            .locks
            .begin_write_after_wait(
                &path,
                &ctx.lock_identity,
                ctx.session.id,
                "write",
                true,
                false,
            )
            .await
            .unwrap();

        set_forced_file_create_error(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "forced create failure",
        ));
        let err = create_new_and_release(&path, b"new\n", guard)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("forced create failure"), "{err}");
        assert!(!tmp.path().join("nested/deep").exists());
        assert!(!tmp.path().join("nested").exists());
        assert!(ctx.locks.holder(&path).is_none());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn failed_create_does_not_remove_preexisting_ancestor() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        std::fs::create_dir_all(tmp.path().join("keep")).unwrap();
        std::fs::write(tmp.path().join("keep/marker.txt"), "stay").unwrap();
        let path = tmp.path().join("keep/nested/file.txt");

        ctx.locks
            .acquire(&path, &ctx.lock_identity, ctx.session.id)
            .await
            .unwrap();
        let guard = ctx
            .locks
            .begin_write_after_wait(
                &path,
                &ctx.lock_identity,
                ctx.session.id,
                "write",
                true,
                false,
            )
            .await
            .unwrap();

        set_forced_file_create_error(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "forced create failure",
        ));
        let _ = create_new_and_release(&path, b"new\n", guard)
            .await
            .unwrap_err();

        assert!(tmp.path().join("keep").is_dir());
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("keep/marker.txt")).unwrap(),
            "stay"
        );
        assert!(!tmp.path().join("keep/nested").exists());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn created_parent_directories_use_explicit_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        WriteTool
            .call(
                serde_json::json!({"path": "nested/deep/file.txt", "content": "body"}),
                &ctx,
            )
            .await
            .unwrap();

        let nested_mode = std::fs::metadata(tmp.path().join("nested"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let deep_mode = std::fs::metadata(tmp.path().join("nested/deep"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(nested_mode, 0o755);
        assert_eq!(deep_mode, 0o755);
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn restrictive_umask_does_not_leak_or_block_staged_parent_creation() {
        const CHILD_ROOT: &str = "COCKPIT_WRITE_RESTRICTIVE_UMASK_CHILD";

        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            struct UmaskRestore(libc::mode_t);
            impl Drop for UmaskRestore {
                fn drop(&mut self) {
                    // SAFETY: this exact test is isolated in a child process.
                    unsafe { libc::umask(self.0) };
                }
            }

            let root = std::path::PathBuf::from(root);
            std::fs::create_dir_all(&root).unwrap();
            // SAFETY: the parent runs only this test in the child process.
            let _restore = UmaskRestore(unsafe { libc::umask(0o700) });
            let prep = ensure_parent_dirs(&root.join("nested/deep/file.txt")).unwrap();
            create_new_file(&prep, &root.join("nested/deep/file.txt"), b"body").unwrap();
            assert_eq!(
                std::fs::read(root.join("nested/deep/file.txt")).unwrap(),
                b"body"
            );
            assert!(std::fs::read_dir(&root).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".cockpit-create-")
            }));
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let child_root = tmp.path().join("child");
        let test_name = std::thread::current()
            .name()
            .expect("test thread has a name")
            .to_string();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(test_name)
            .arg("--nocapture")
            .env(CHILD_ROOT, &child_root)
            .output()
            .expect("spawn isolated restrictive-umask regression test");
        assert!(
            output.status.success(),
            "isolated restrictive-umask test failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(child_root.join("nested/deep/file.txt").is_file());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn execute_only_existing_ancestor_does_not_block_parent_creation() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let traverse = tmp.path().join("home");
        let user = traverse.join("user");
        std::fs::create_dir_all(&user).unwrap();
        std::fs::set_permissions(&traverse, std::fs::Permissions::from_mode(0o111)).unwrap();
        struct RestoreMode<'a>(&'a std::path::Path);
        impl Drop for RestoreMode<'_> {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o755));
            }
        }
        let _restore = RestoreMode(&traverse);

        let ctx = test_ctx(tmp.path());
        WriteTool
            .call(
                serde_json::json!({
                    "path": "home/user/nested/file.txt",
                    "content": "body"
                }),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(user.join("nested/file.txt")).unwrap(),
            "body"
        );
        let nested_mode = std::fs::metadata(user.join("nested"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(nested_mode, 0o755);
    }

    #[tokio::test(flavor = "current_thread")]
    #[cfg(unix)]
    async fn scoped_nested_write_discloses_and_hardens() {
        // This is direct WriteTool coverage for scoped nested creation. It is
        // intentionally not described as verification-redispatch coverage:
        // issue #76's verification engine and revise mode are not implemented
        // in this branch, so no genuine dispatcher-level revise path exists yet.
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = test_ctx(tmp.path());
        let scope = tmp.path().join("scope");
        std::fs::create_dir_all(&scope).unwrap();
        ctx.write_scope = Some(scope.clone());

        let original = WriteTool
            .call(
                serde_json::json!({"path": "scope/original.txt", "content": "v1"}),
                &ctx,
            )
            .await
            .unwrap();
        assert!(
            !original.content.contains("created directories:"),
            "{}",
            original.content
        );
        assert_eq!(
            std::fs::read_to_string(scope.join("original.txt")).unwrap(),
            "v1"
        );

        let revised = WriteTool
            .call(
                serde_json::json!({
                    "path": "scope/revised/deep/file.txt",
                    "content": "v2"
                }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(
            revised
                .content
                .contains("created directories: revised/…/deep"),
            "{}",
            revised.content
        );
        assert_eq!(
            std::fs::read_to_string(scope.join("revised/deep/file.txt")).unwrap(),
            "v2"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let revised_mode = std::fs::metadata(scope.join("revised"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let deep_mode = std::fs::metadata(scope.join("revised/deep"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(revised_mode, 0o755);
            assert_eq!(deep_mode, 0o755);
        }

        #[cfg(unix)]
        {
            let outside = tmp.path().join("outside");
            std::fs::create_dir_all(&outside).unwrap();
            let nested = scope.join("trap");
            let outside_for_hook = outside.clone();
            set_before_parent_create_hook(move || {
                std::os::unix::fs::symlink(&outside_for_hook, &nested).unwrap();
            });
            let err = WriteTool
                .call(
                    serde_json::json!({
                        "path": "scope/trap/deep/file.txt",
                        "content": "escaped"
                    }),
                    &ctx,
                )
                .await
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("symlink") || err.contains("not a directory"),
                "{err}"
            );
            assert!(!outside.join("deep/file.txt").exists());
        }
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn new_file_create_does_not_grant_future_blind_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());

        WriteTool
            .call(
                serde_json::json!({"path": "created.md", "content": "first\n"}),
                &ctx,
            )
            .await
            .unwrap();

        let err = WriteTool
            .call(
                serde_json::json!({"path": "created.md", "content": "second\n"}),
                &ctx,
            )
            .await
            .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("read it first"), "{msg}");
        assert!(msg.contains("retry write"), "{msg}");
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("created.md")).unwrap(),
            "first\n"
        );
    }

    #[tokio::test]
    async fn write_acquires_and_releases_implicitly() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let file = tmp.path().join("existing.md");
        std::fs::write(&file, "old\n").unwrap();
        ctx.locks
            .note_read(&file, &ctx.lock_identity, ctx.session.id)
            .await;
        assert!(ctx.locks.holder(&file).is_none());

        WriteTool
            .call(
                serde_json::json!({"path": "existing.md", "content": "new\n"}),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(std::fs::read_to_string(&file).unwrap(), "new\n");
        assert!(ctx.locks.holder(&file).is_none());
        assert!(
            ctx.locks
                .has_read(&file, &ctx.lock_identity, ctx.session.id)
        );
    }

    #[tokio::test]
    async fn write_does_not_release_a_preexisting_hold() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let file = tmp.path().join("existing.md");
        std::fs::write(&file, "old\n").unwrap();
        ctx.locks
            .acquire(&file, &ctx.lock_identity, ctx.session.id)
            .await
            .unwrap();

        WriteTool
            .call(
                serde_json::json!({"path": "existing.md", "content": "new\n"}),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(std::fs::read_to_string(&file).unwrap(), "new\n");
        assert_eq!(
            ctx.locks.holder(&file),
            Some((ctx.session.id, ctx.lock_identity.clone()))
        );
    }

    #[tokio::test]
    async fn stale_read_record_rejects_implicit_write() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let file = tmp.path().join("existing.md");
        std::fs::write(&file, "old\n").unwrap();
        ctx.locks
            .note_read(&file, &ctx.lock_identity, ctx.session.id)
            .await;
        std::fs::write(&file, "changed\n").unwrap();

        let err = WriteTool
            .call(
                serde_json::json!({"path": "existing.md", "content": "new\n"}),
                &ctx,
            )
            .await
            .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("changed on disk since you read it"), "{msg}");
        assert!(msg.contains("read it again"), "{msg}");
        assert_eq!(classify_failure(&err), ToolFailKind::Invocation);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "changed\n");
        assert!(ctx.locks.holder(&file).is_none());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn create_new_race_reports_file_now_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let path = tmp.path().join("raced.md");

        ctx.locks
            .acquire(&path, &ctx.lock_identity, ctx.session.id)
            .await
            .unwrap();
        let guard = ctx
            .locks
            .begin_write_after_wait(
                &path,
                &ctx.lock_identity,
                ctx.session.id,
                "write",
                true,
                false,
            )
            .await
            .unwrap();

        let raced = path.clone();
        set_before_file_create_hook(move || std::fs::write(raced, "raced\n").unwrap());
        let err = create_new_and_release(&path, b"new\n", guard)
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("file now exists; read it before overwriting"),
            "{err}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "raced\n");
        assert!(ctx.locks.holder(&path).is_none());
    }

    #[tokio::test]
    async fn write_releases_lock_on_every_failure_path() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = test_ctx(tmp.path());

        let stale = tmp.path().join("stale.md");
        std::fs::write(&stale, "old\n").unwrap();
        ctx.locks
            .note_read(&stale, &ctx.lock_identity, ctx.session.id)
            .await;
        std::fs::write(&stale, "changed\n").unwrap();
        let err = WriteTool
            .call(
                serde_json::json!({"path": "stale.md", "content": "new\n"}),
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("changed on disk since you read it")
        );
        assert!(ctx.locks.holder(&stale).is_none());

        ctx.approver = None;
        let outside = tmp.path().parent().unwrap().join("outside-write-denied.md");
        let err = WriteTool
            .call(
                serde_json::json!({
                    "path": outside.display().to_string(),
                    "content": "new\n"
                }),
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("outside the session boundary and cannot be approved"),
            "{err}"
        );
        assert!(ctx.locks.holder(&outside).is_none());

        let identity_home = tempfile::tempdir().unwrap();
        let (identity_ctx, _identity_env) = identity_refusal_ctx(identity_home.path()).await;
        let soul = crate::assistants::identity::soul_path(&identity_ctx.cwd);
        let out = WriteTool
            .call(
                serde_json::json!({
                    "path": soul.display().to_string(),
                    "content": "model rewrite\n"
                }),
                &identity_ctx,
            )
            .await
            .unwrap();
        assert!(out.content.contains("soul_edit_mode=human_only"), "{out:?}");
        assert!(identity_ctx.locks.holder(&soul).is_none());

        #[cfg(unix)]
        {
            let blocked_parent = tmp.path().join("not-a-dir");
            std::fs::write(&blocked_parent, "file blocks directory creation").unwrap();
            let target = blocked_parent.join("child.txt");
            let err = WriteTool
                .call(
                    serde_json::json!({
                        "path": "not-a-dir/child.txt",
                        "content": "new\n"
                    }),
                    &ctx,
                )
                .await
                .unwrap_err();
            assert!(err.to_string().contains("not a directory"), "{err}");
            assert!(ctx.locks.holder(&target).is_none());
        }
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn new_file_write_reports_parent_not_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        std::fs::write(tmp.path().join("blocked"), "file blocks directory").unwrap();

        let err = WriteTool
            .call(
                serde_json::json!({"path": "blocked/file.md", "content": "body"}),
                &ctx,
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("is not a directory"), "{err}");
    }

    #[tokio::test]
    async fn write_reports_success_when_release_persist_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, db) = test_ctx_with_db(tmp.path());
        let file = tmp.path().join("existing.json");
        std::fs::write(&file, "{}\n").unwrap();
        ctx.locks
            .note_read(&file, &ctx.lock_identity, ctx.session.id)
            .await;
        fail_lock_state_deletes(&db).await;

        let out = WriteTool
            .call(
                serde_json::json!({"path": "existing.json", "content": "{\"ok\":true}\n"}),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(std::fs::read_to_string(&file).unwrap(), "{\"ok\":true}\n");
        assert!(out.content.contains("wrote `"), "{}", out.content);
        assert!(out.content.contains("syntax OK (JSON)"), "{}", out.content);
        assert!(
            out.content.contains("lock bookkeeping did not persist"),
            "{}",
            out.content
        );
        assert!(
            out.content.find("syntax OK (JSON)").unwrap()
                < out.content.find(LOCK_BOOKKEEPING_ADVISORY).unwrap(),
            "{}",
            out.content
        );
        assert!(out.content.ends_with(LOCK_BOOKKEEPING_ADVISORY));
        assert!(ctx.locks.holder(&file).is_none());
        assert!(
            ctx.locks
                .has_read(&file, &ctx.lock_identity, ctx.session.id)
        );
        ctx.locks
            .check_write_permitted(&file, &ctx.lock_identity, ctx.session.id)
            .unwrap();
    }

    #[tokio::test]
    async fn write_after_forced_release_reaches_staleness_guard() {
        let tmp = tempfile::tempdir().unwrap();
        let (ctx_a, db) = test_ctx_with_db(tmp.path());
        let file = tmp.path().join("shared.md");
        std::fs::write(&file, "base\n").unwrap();
        let s_b = db
            .create_session("p", &tmp.path().display().to_string(), "writer-b")
            .await
            .unwrap();
        let mut ctx_b = ctx_a.clone_for_dispatch();
        ctx_b.lock_identity = "writer-b".to_string();
        ctx_b.session = Arc::new(
            crate::session::Session::resume_for_test(
                db.clone(),
                s_b.session_id,
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap()
            .unwrap(),
        );

        ctx_a
            .locks
            .note_read(&file, &ctx_a.lock_identity, ctx_a.session.id)
            .await;
        ctx_b
            .locks
            .note_read(&file, &ctx_b.lock_identity, ctx_b.session.id)
            .await;
        fail_lock_state_deletes(&db).await;

        let out = WriteTool
            .call(
                serde_json::json!({"path": "shared.md", "content": "writer a\n"}),
                &ctx_a,
            )
            .await
            .unwrap();
        assert!(
            out.content.contains("lock bookkeeping did not persist"),
            "{out:?}"
        );
        assert!(ctx_a.locks.holder(&file).is_none());

        let err = WriteTool
            .call(
                serde_json::json!({"path": "shared.md", "content": "writer b\n"}),
                &ctx_b,
            )
            .await
            .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("changed on disk since you read it"), "{msg}");
        assert!(!msg.contains("lock_state acquire conflict"), "{msg}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "writer a\n");
        assert!(ctx_b.locks.holder(&file).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn write_waits_for_busy_path_and_emits_waiting_event() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = test_ctx(tmp.path());
        let file = tmp.path().join("busy.md");
        std::fs::write(&file, "old\n").unwrap();
        ctx.locks
            .note_read(&file, &ctx.lock_identity, ctx.session.id)
            .await;
        ctx.locks
            .acquire(&file, "holder", ctx.session.id)
            .await
            .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        ctx.events = Some(tx);
        let locks = ctx.locks.clone();
        let sid = ctx.session.id;
        let file_for_release = file.clone();

        let handle = tokio::spawn(async move {
            WriteTool
                .call(
                    serde_json::json!({"path": "busy.md", "content": "new\n"}),
                    &ctx,
                )
                .await
        });

        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        let start = rx.recv().await.expect("waiting start event");
        assert!(matches!(
            start,
            TurnEvent::WaitingForLock {
                ref path,
                ref holder_agent,
                waiting: true
            } if path == &file.display().to_string() && holder_agent == "holder"
        ));

        locks
            .release(&file_for_release, "holder", sid)
            .await
            .unwrap();
        let out = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("write resolves after release")
            .expect("join")
            .unwrap();
        assert!(out.content.contains("wrote `"), "{}", out.content);

        let clear = rx.recv().await.expect("waiting clear event");
        assert!(matches!(
            clear,
            TurnEvent::WaitingForLock {
                ref path,
                waiting: false,
                ..
            } if path == &file.display().to_string()
        ));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "new\n");
        assert!(locks.holder(&file).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn write_wait_cancels_on_turn_cancel_without_leaving_waiter() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = test_ctx(tmp.path());
        let file = tmp.path().join("busy.md");
        std::fs::write(&file, "old\n").unwrap();
        ctx.locks
            .acquire(&file, "holder", ctx.session.id)
            .await
            .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        ctx.events = Some(tx);
        let locks = ctx.locks.clone();
        let cancel = ctx.cancel.clone();
        let sid = ctx.session.id;
        let file_for_release = file.clone();

        let handle = tokio::spawn(async move {
            WriteTool
                .call(
                    serde_json::json!({"path": "busy.md", "content": "new\n"}),
                    &ctx,
                )
                .await
        });

        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        let start = rx.recv().await.expect("waiting start event");
        assert!(matches!(
            start,
            TurnEvent::WaitingForLock { waiting: true, .. }
        ));

        cancel.cancel();
        let err = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("cancel resolves promptly")
            .expect("join")
            .unwrap_err();
        assert!(err.to_string().contains("write cancelled"), "{err}");

        let clear = rx.recv().await.expect("waiting clear event");
        assert!(matches!(
            clear,
            TurnEvent::WaitingForLock { waiting: false, .. }
        ));
        assert_eq!(
            locks.holder(&file).map(|(_, agent)| agent),
            Some("holder".to_string())
        );
        locks
            .release(&file_for_release, "holder", sid)
            .await
            .unwrap();
        assert!(locks.holder(&file).is_none());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "old\n");
    }

    #[tokio::test]
    async fn write_json_syntax_notes_are_advisory() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let path = tmp.path().join("bad.json");
        std::fs::write(&path, "{}\n").unwrap();
        note_read(&ctx, &path).await;
        let out = WriteTool
            .call(
                serde_json::json!({"path": "bad.json", "content": "{\n"}),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(tmp.path().join("bad.json")).unwrap(),
            "{\n"
        );
        assert!(
            out.content.contains("warning: content is not valid JSON"),
            "{}",
            out.content
        );
        assert!(out.content.contains("line 2 column"), "{}", out.content);
    }

    #[tokio::test]
    async fn write_json_success_note() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let path = tmp.path().join("ok.json");
        std::fs::write(&path, "{\"old\":true}\n").unwrap();
        note_read(&ctx, &path).await;
        let out = WriteTool
            .call(
                serde_json::json!({"path": "ok.json", "content": "{}\n"}),
                &ctx,
            )
            .await
            .unwrap();

        assert!(out.content.contains("syntax OK (JSON)"), "{}", out.content);
    }
}

/// Existing non-empty files are destructive writes. Manual mode asks through
/// the central authorization chokepoint; Auto and Yolo are decided by the
/// dispatch safety gate (or intentionally bypass it) before this tool runs.
pub(crate) async fn authorize_existing_write(
    ctx: &ToolCtx,
    path: &std::path::Path,
    previous: &[u8],
    next: &[u8],
) -> Result<()> {
    let decision = if let Some(approver) = ctx.approver.as_ref() {
        approver
            .authorize(crate::approval::AuthorizationRequest::FileWrite {
                path,
                previous,
                next,
            })
            .await?
    } else {
        crate::approval::Decision::NoninteractiveDeny
    };
    match decision {
        crate::approval::Decision::Allow { .. } => Ok(()),
        crate::approval::Decision::NoninteractiveDeny => {
            Err(anyhow::anyhow!(crate::approval::NONINTERACTIVE_RUN_DENIAL))
        }
        crate::approval::Decision::Deny | crate::approval::Decision::StandingReject { .. } => {
            Err(anyhow::anyhow!("existing file modification denied"))
        }
    }
}

#[cfg(test)]
mod write_approval_regressions {
    use super::*;
    use crate::{engine::tool::Tool, tools::common::test_ctx};

    #[cfg(unix)]
    #[tokio::test]
    async fn creating_new_file_is_not_gated() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        ctx.session.set_approval_mode(ApprovalMode::Manual);
        WriteTool
            .call(serde_json::json!({"path":"new.txt","content":"new"}), &ctx)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("new.txt")).unwrap(),
            "new"
        );
    }

    #[tokio::test]
    async fn overwriting_empty_file_is_not_gated() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("empty.txt");
        std::fs::write(&path, "").unwrap();
        let ctx = test_ctx(tmp.path());
        ctx.session.set_approval_mode(ApprovalMode::Manual);
        ctx.locks
            .note_read(&path, &ctx.lock_identity, ctx.session.id)
            .await;
        WriteTool
            .call(
                serde_json::json!({"path":"empty.txt","content":"filled"}),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "filled");
    }

    #[tokio::test]
    async fn cockpit_dir_creation_requires_approval() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = test_ctx(tmp.path());
        ctx.approver = None;
        ctx.session.set_approval_mode(ApprovalMode::Manual);
        let args = serde_json::json!({"path": ".cockpit/mcp.json", "content": "{}"});
        let err = WriteTool.call(args, &ctx).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("noninteractive run: approval auto-denied"),
            "{err}"
        );
        assert!(!tmp.path().join(".cockpit/mcp.json").exists());
    }

    #[tokio::test]
    async fn write_without_approver_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("existing.txt");
        std::fs::write(&path, "before").unwrap();
        let mut ctx = test_ctx(tmp.path());
        ctx.approver = None;
        ctx.session.set_approval_mode(ApprovalMode::Manual);
        ctx.locks
            .note_read(&path, &ctx.lock_identity, ctx.session.id)
            .await;
        let err = WriteTool
            .call(
                serde_json::json!({"path":"existing.txt","content":"after"}),
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("noninteractive run: approval auto-denied"),
            "{err}"
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), "before");
    }
}
