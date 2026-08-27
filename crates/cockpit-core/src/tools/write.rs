//! `write` — create or overwrite the file with `content` and release the lock.
//!
//! Pre-write invariant (plan §3c): existing files require that the agent has
//! read the file in this session, OR holds the lock. Missing files may be
//! created without a read record, using create-new semantics so they are never
//! overwritten by a stale absence check.

use std::io::Write as _;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde_json::Value;

#[cfg(test)]
use crate::config::extended::ApprovalMode;
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, ToolPresentation, path_or_readable_args};
use crate::tools::common::{detect_crlf, normalize_line_endings, resolve, write_and_release};

pub struct WriteTool;

#[async_trait]
impl Tool for WriteTool {
    fn name(&self) -> &str {
        "write"
    }

    fn description(&self) -> &str {
        "Write `content` as the file's COMPLETE new contents (omitted lines are deleted); locking is automatic, so no separate lock call is needed before writing; existing files require prior read; prefer `edit` for small changes"
    }

    fn defensive_description(&self) -> Option<String> {
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
                "content": { "type": "string", "x-cockpit-aliases": ["text", "body", "data", "contents", "fileContent"], "description": "Entire new file content" }
            },
            "required": ["path", "content"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "path":    { "type": "string", "x-cockpit-kind": "path", "x-cockpit-may-create": true, "x-cockpit-aliases": ["file_path", "filePath", "filepath", "pathname", "target_file", "file", "absolute_path"], "description": "Path to create or overwrite, absolute or relative to the session working directory; existing files must be the same file you previously locked/read" },
                "content": { "type": "string", "x-cockpit-aliases": ["text", "body", "data", "contents", "fileContent"], "description": "The complete new contents of the file from the first line to the last. This REPLACES everything; any existing line you do not include here is lost" }
            },
            "required": ["path", "content"]
        }))
    }

    fn presentation(&self, args: &Value) -> ToolPresentation {
        let (summary, full_input) = path_or_readable_args(args);
        ToolPresentation::with_parts(Some("🔓"), "write", summary, full_input)
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
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
            create_new_and_release(
                &path,
                normalized.as_bytes(),
                write_guard,
                create_new_file,
                ctx.write_scope.as_deref().unwrap_or(&ctx.cwd),
            )
            .await?
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
        if let Some(lsp) = &ctx.lsp {
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
/// umask-derived; applied with `fchmod` on the held descriptor.
#[cfg(unix)]
const CREATED_DIR_MODE: libc::mode_t = 0o755;

#[cfg(test)]
thread_local! {
    static BEFORE_PARENT_CREATE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static AFTER_PARENT_CREATE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn set_before_parent_create_hook(hook: impl FnOnce() + 'static) {
    BEFORE_PARENT_CREATE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn set_after_parent_create_hook(hook: impl FnOnce() + 'static) {
    AFTER_PARENT_CREATE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

fn run_before_parent_create_hook() {
    #[cfg(test)]
    BEFORE_PARENT_CREATE.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

fn run_after_parent_create_hook() {
    #[cfg(test)]
    AFTER_PARENT_CREATE.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

struct ParentPrep {
    disclosure: Option<String>,
    created_paths: Vec<std::path::PathBuf>,
}

impl ParentPrep {
    fn none() -> Self {
        Self {
            disclosure: None,
            created_paths: Vec::new(),
        }
    }
}

async fn create_new_and_release(
    path: &std::path::Path,
    bytes: &[u8],
    guard: crate::locks::WriteGuard<'_>,
    create_file: impl FnOnce(&std::path::Path, &[u8]) -> std::io::Result<()>,
    contain_under: &std::path::Path,
) -> Result<(crate::tools::common::WriteReleaseOutcome, Option<String>)> {
    let prep = ensure_parent_dirs(path, contain_under)?;
    let created = create_file(path, bytes);
    if created.is_err() {
        rollback_created_dirs(&prep.created_paths);
    }
    created.map_err(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!(
                "cannot create `{}` — file now exists; read it before overwriting",
                path.display()
            )
        } else {
            anyhow::anyhow!("create `{}`: {err}", path.display())
        }
    })?;
    let persist_ok = guard.release_after_write().await;
    Ok((
        crate::tools::common::WriteReleaseOutcome { persist_ok },
        prep.disclosure,
    ))
}

/// Name the created portion below the nearest pre-existing ancestor as
/// `created directories: <first-created>/…/<parent>`. A single created
/// component omits the ellipsis.
fn format_created_directories_line(created_relative: &std::path::Path) -> String {
    let parts: Vec<&std::ffi::OsStr> = created_relative
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect();
    match parts.as_slice() {
        [] => "created directories: .".to_string(),
        [one] => format!("created directories: {}", one.to_string_lossy()),
        [first, .., last] => format!(
            "created directories: {}/…/{}",
            first.to_string_lossy(),
            last.to_string_lossy()
        ),
    }
}

fn rollback_created_dirs(created: &[std::path::PathBuf]) {
    for path in created.iter().rev() {
        let _ = std::fs::remove_dir(path);
    }
}

fn revalidate_parent_under_scope(
    parent: &std::path::Path,
    contain_under: &std::path::Path,
) -> Result<()> {
    let parent_canon = std::fs::canonicalize(parent).with_context(|| {
        format!(
            "revalidate parent directory `{}` after creation",
            parent.display()
        )
    })?;
    let scope_canon = std::fs::canonicalize(contain_under).with_context(|| {
        format!(
            "revalidate write scope `{}` after parent creation",
            contain_under.display()
        )
    })?;
    if parent_canon.starts_with(&scope_canon) {
        return Ok(());
    }
    bail!(
        "refused: parent directory `{}` canonicalizes outside write scope `{}`",
        parent.display(),
        contain_under.display()
    )
}

fn ensure_parent_dirs(
    path: &std::path::Path,
    contain_under: &std::path::Path,
) -> Result<ParentPrep> {
    let Some(parent) = path.parent() else {
        return Ok(ParentPrep::none());
    };
    if parent.as_os_str().is_empty() {
        return Ok(ParentPrep::none());
    }
    run_before_parent_create_hook();
    if parent.exists() && !parent.is_dir() {
        bail!(
            "cannot create `{}` — parent `{}` is not a directory",
            path.display(),
            parent.display()
        );
    }

    let mut created_paths = Vec::new();
    let disclosure = if parent.is_dir() {
        None
    } else {
        match create_missing_parent_chain(path, parent, &mut created_paths) {
            Ok(disclosure) => disclosure,
            Err(err) => {
                rollback_created_dirs(&created_paths);
                return Err(err);
            }
        }
    };

    run_after_parent_create_hook();
    if let Err(err) = revalidate_parent_under_scope(parent, contain_under) {
        rollback_created_dirs(&created_paths);
        return Err(err);
    }
    Ok(ParentPrep {
        disclosure,
        created_paths,
    })
}

fn create_missing_parent_chain(
    path: &std::path::Path,
    parent: &std::path::Path,
    created_paths: &mut Vec<std::path::PathBuf>,
) -> Result<Option<String>> {
    let ancestor =
        cockpit_host::path_containment::nearest_existing_prefix(parent).with_context(|| {
            format!(
                "locate existing ancestor of parent `{}` for `{}`",
                parent.display(),
                path.display()
            )
        })?;
    let ancestor_meta = std::fs::symlink_metadata(&ancestor).with_context(|| {
        format!(
            "stat existing ancestor `{}` for `{}`",
            ancestor.display(),
            path.display()
        )
    })?;
    if ancestor_meta.file_type().is_symlink() {
        bail!(
            "refused: intermediate path component `{}` is a symlink or not a directory",
            ancestor.display()
        );
    }
    if !ancestor_meta.is_dir() {
        bail!(
            "cannot create `{}` — parent `{}` is not a directory",
            path.display(),
            ancestor.display()
        );
    }
    let ancestor_canon = std::fs::canonicalize(&ancestor).with_context(|| {
        format!(
            "canonicalize existing ancestor `{}` for `{}`",
            ancestor.display(),
            path.display()
        )
    })?;
    let created_relative = parent.strip_prefix(&ancestor).unwrap_or(parent);
    let disclosure = if created_relative.as_os_str().is_empty() {
        None
    } else {
        Some(format_created_directories_line(created_relative))
    };
    create_parent_components(
        path,
        parent,
        &ancestor_canon,
        created_relative,
        created_paths,
    )?;
    Ok(disclosure)
}

#[cfg(unix)]
fn create_parent_components(
    path: &std::path::Path,
    parent: &std::path::Path,
    ancestor_canon: &std::path::Path,
    created_relative: &std::path::Path,
    created_paths: &mut Vec<std::path::PathBuf>,
) -> Result<()> {
    let mut current = open_directory_nofollow(ancestor_canon).with_context(|| {
        format!(
            "open existing ancestor `{}` for `{}`",
            ancestor_canon.display(),
            path.display()
        )
    })?;
    let mut built = ancestor_canon.to_path_buf();
    for component in created_relative.components() {
        match component {
            std::path::Component::Normal(name) => {
                built.push(name);
                current = open_or_create_directory_child(&current, name, &built, created_paths)
                    .with_context(|| {
                        format!(
                            "create parent directories for `{}` under `{}`",
                            path.display(),
                            parent.display()
                        )
                    })?;
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
    Ok(())
}

#[cfg(not(unix))]
fn create_parent_components(
    path: &std::path::Path,
    parent: &std::path::Path,
    ancestor_canon: &std::path::Path,
    created_relative: &std::path::Path,
    created_paths: &mut Vec<std::path::PathBuf>,
) -> Result<()> {
    let mut current = parent
        .strip_prefix(created_relative)
        .unwrap_or(parent)
        .to_path_buf();
    if current.as_os_str().is_empty() {
        current = ancestor_canon.to_path_buf();
    }
    for component in created_relative.components() {
        current.push(component);
        if !current.exists() {
            created_paths.push(current.clone());
        }
    }
    std::fs::create_dir_all(parent).with_context(|| {
        format!(
            "create parent directories for `{}` under `{}`",
            path.display(),
            parent.display()
        )
    })?;
    Ok(())
}

#[cfg(unix)]
fn open_directory_nofollow(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(unix)]
fn component_cstr(name: &std::ffi::OsStr) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt as _;
    if name.is_empty() || name == "." || name == ".." || name.as_bytes().contains(&b'/') {
        bail!("unsafe path component {name:?}");
    }
    std::ffi::CString::new(name.as_bytes()).context("path component contains NUL")
}

#[cfg(unix)]
fn open_or_create_directory_child(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    child_path: &std::path::Path,
    created_paths: &mut Vec<std::path::PathBuf>,
) -> Result<std::fs::File> {
    use std::os::fd::AsRawFd as _;

    let cname = component_cstr(name)?;
    match cockpit_host::private_fs::held_fd::openat(
        parent.as_raw_fd(),
        &cname,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    ) {
        Ok(directory) => Ok(directory),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let we_created = match cockpit_host::private_fs::held_fd::mkdirat(
                parent.as_raw_fd(),
                &cname,
                CREATED_DIR_MODE,
            ) {
                Ok(()) => true,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => false,
                Err(err) => {
                    return Err(err).context(format!(
                        "creating directory component `{}`",
                        child_path.display()
                    ));
                }
            };
            let directory = match cockpit_host::private_fs::held_fd::openat(
                parent.as_raw_fd(),
                &cname,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            ) {
                Ok(directory) => directory,
                Err(err) => {
                    if we_created {
                        let _ = cockpit_host::private_fs::held_fd::unlinkat(
                            parent.as_raw_fd(),
                            &cname,
                            libc::AT_REMOVEDIR,
                        );
                    }
                    return Err(refuse_symlink_or_non_dir(child_path, err));
                }
            };
            if we_created {
                cockpit_host::private_fs::held_fd::fchmod(directory.as_raw_fd(), CREATED_DIR_MODE)
                    .with_context(|| {
                        format!(
                            "setting mode of created directory `{}`",
                            child_path.display()
                        )
                    })?;
                created_paths.push(child_path.to_path_buf());
            }
            Ok(directory)
        }
        Err(err) => Err(refuse_symlink_or_non_dir(child_path, err)),
    }
}

#[cfg(unix)]
fn refuse_symlink_or_non_dir(path: &std::path::Path, err: std::io::Error) -> anyhow::Error {
    match err.raw_os_error() {
        Some(code) if code == libc::ELOOP || code == libc::ENOTDIR => anyhow::anyhow!(
            "refused: intermediate path component `{}` is a symlink or not a directory",
            path.display()
        ),
        _ => anyhow::Error::new(err).context(format!(
            "opening directory component `{}` without following links",
            path.display()
        )),
    }
}

fn create_new_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::engine::agent::TurnEvent;
    use crate::engine::tool::{ToolFailKind, classify_failure};
    use crate::tools::common::{LOCK_BOOKKEEPING_ADVISORY, test_ctx, test_ctx_with_db};
    use crate::tools::read::ReadTool;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

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
        let project_id = crate::session::project_id_for(&canonical);
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
            agent_instance_id: None,
            lock_identity: "helper".to_string(),
            write_scope: None,
            current_tool_call_id: None,
            llm_mode: crate::config::extended::LlmMode::Normal,
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
                .content)
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
                .content)
        })
        .await
    }

    #[tokio::test]
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

        let out = write(&tmp.path().join("plain.md"), "hello", &ctx)
            .await
            .unwrap();

        assert!(!out.contains("[skill]"), "{out}");
        assert!(catalog_cache_contains(&ctx, &cfg.skills));
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("plain.md")).unwrap(),
            "hello"
        );
    }

    #[tokio::test]
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
        ctx.write_scope = Some(scope.clone());

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
        assert_eq!(
            std::fs::read_to_string(scope.join("inside.txt")).unwrap(),
            "ok"
        );

        let read = ReadTool
            .call(serde_json::json!({"path": "outside.txt"}), &ctx)
            .await
            .unwrap();
        assert!(read.content.contains("readable"), "{}", read.content);
    }

    #[tokio::test]
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
    fn created_directories_line_names_first_and_parent_components() {
        assert_eq!(
            format_created_directories_line(Path::new("nested")),
            "created directories: nested"
        );
        assert_eq!(
            format_created_directories_line(Path::new("nested/deep")),
            "created directories: nested/…/deep"
        );
        assert_eq!(
            format_created_directories_line(Path::new("a/b/c")),
            "created directories: a/…/c"
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

        assert!(err.contains("canonicalizes outside write scope"), "{err}");
        assert!(!outside.join("deep/file.txt").exists());
        assert!(!scope.join("nested/deep/file.txt").is_file());
    }

    #[tokio::test]
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

        let err = create_new_and_release(
            &path,
            b"new\n",
            guard,
            |_, _| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "forced create failure",
                ))
            },
            tmp.path(),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("forced create failure"), "{err}");
        assert!(!tmp.path().join("nested/deep").exists());
        assert!(!tmp.path().join("nested").exists());
        assert!(ctx.locks.holder(&path).is_none());
    }

    #[tokio::test]
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

        let _ = create_new_and_release(
            &path,
            b"new\n",
            guard,
            |_, _| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "forced create failure",
                ))
            },
            tmp.path(),
        )
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

    #[tokio::test(flavor = "current_thread")]
    async fn revised_write_into_new_directory_discloses_and_hardens() {
        // Issue #76 revise mode redispatches through the same WriteTool, so
        // parent-dir disclosure and containment hardening apply by construction.
        // `x-cockpit-may-create` remains a repair-only annotation and is not
        // consulted here.
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

        let err = create_new_and_release(
            &path,
            b"new\n",
            guard,
            |path, _| {
                std::fs::write(path, "raced\n")?;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map(|_| ())
            },
            tmp.path(),
        )
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

    #[tokio::test]
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
        let mut ctx_b = ctx_a.clone();
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
    use crate::engine::tool::Tool;
    use crate::tools::common::test_ctx;

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
