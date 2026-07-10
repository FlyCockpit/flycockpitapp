//! `writeunlock` — create or overwrite the file with `content` and release the lock.
//!
//! Pre-write invariant (plan §3c): existing files require that the agent has
//! read the file in this session, OR holds the lock. Missing files may be
//! created without a read record, using create-new semantics so they are never
//! overwritten by a stale absence check.

use std::io::Write as _;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput};
use crate::tools::common::{detect_crlf, normalize_line_endings, resolve, write_and_release};

pub struct WriteunlockTool;

#[async_trait]
impl Tool for WriteunlockTool {
    fn name(&self) -> &str {
        "writeunlock"
    }

    fn description(&self) -> &str {
        "Use `writeunlock` for new files or full rewrites; existing files require prior read/readlock"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Replace a file's ENTIRE contents with the text you supply, then release the lock. \
             `content` must be the complete new file from first line to last — anything you omit \
             is deleted, so include every line you want to keep, not just your changes. Use \
             `writeunlock` for new files or full rewrites; existing files require prior \
             read/readlock, or the write is rejected to guard against blind overwrites. Missing \
             parent directories are created for new files after path-access checks pass. For a \
             small change to a large file prefer \
             `editunlock` (targeted search/replace) so you don't have to restate the whole file. \
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

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let path_arg = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::engine::tool::invalid_input("`path` is required"))?;
        let content = args
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::engine::tool::invalid_input("`content` is required"))?;
        let path = resolve(path_arg, &ctx.cwd);

        // Native-tool boundary check (sandboxing part 2): an out-of-cwd
        // write target escalates (naming the path) before we touch disk.
        let path = crate::tools::sandbox::check_native_access(ctx, &path).await?;

        let exists = path.exists();
        let write_guard = if exists {
            Some(
                ctx.locks
                    .begin_write(&path, &ctx.agent_id, ctx.session.id)?,
            )
        } else {
            None
        };

        // Decide line-ending mode based on the existing file (when
        // present). For new files default to LF on every platform —
        // Rust source, Markdown, JSON; the user's project is
        // overwhelmingly LF.
        let want_crlf = if exists {
            let existing = std::fs::read(&path)?;
            detect_crlf(&existing)
        } else {
            false
        };

        let normalized = normalize_line_endings(content, want_crlf);

        let outcome = if exists {
            write_and_release(ctx, &path, normalized.as_bytes(), write_guard.unwrap())?
        } else {
            create_new_and_release(ctx, &path, normalized.as_bytes(), create_new_file)?
        };

        let mut message = format!(
            "wrote `{}` ({} bytes, {})",
            path.display(),
            normalized.len(),
            if want_crlf { "CRLF" } else { "LF" }
        );
        if let Some(lsp) = &ctx.lsp {
            let config = crate::config::extended::load_for_cwd(&ctx.cwd);
            message.push_str(&lsp.diagnostics_after_write(&ctx.cwd, &path, &config).await);
        }
        if let Some(advisory) = outcome.advisory() {
            message.push_str(advisory);
        }

        Ok(ToolOutput::text(message))
    }
}

fn create_new_and_release(
    ctx: &ToolCtx,
    path: &std::path::Path,
    bytes: &[u8],
    create_file: impl FnOnce(&std::path::Path, &[u8]) -> std::io::Result<()>,
) -> Result<crate::tools::common::WriteReleaseOutcome> {
    ensure_parent_dirs(path)?;
    create_file(path, bytes).map_err(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!(
                "cannot create `{}` — file now exists; readlock it before overwriting",
                path.display()
            )
        } else {
            anyhow::anyhow!("create `{}`: {err}", path.display())
        }
    })?;
    let persist_ok = ctx
        .locks
        .release_force_memory(path, &ctx.agent_id, ctx.session.id);
    Ok(crate::tools::common::WriteReleaseOutcome { persist_ok })
}

fn ensure_parent_dirs(path: &std::path::Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.exists() && !parent.is_dir() {
        bail!(
            "cannot create `{}` — parent `{}` is not a directory",
            path.display(),
            parent.display()
        );
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
    use crate::tools::common::{LOCK_BOOKKEEPING_ADVISORY, test_ctx, test_ctx_with_db};
    use crate::tools::readlock::ReadlockTool;

    fn fail_lock_state_deletes(db: &Db) {
        db.write_blocking(move |conn| {
            conn.execute_batch(
                "CREATE TEMP TRIGGER fail_lock_state_delete
                 BEFORE DELETE ON lock_state
                 BEGIN
                     SELECT RAISE(FAIL, 'forced lock_state delete failure');
                 END;",
            )?;
            Ok(())
        })
        .unwrap();
    }

    #[tokio::test]
    async fn writeunlock_creates_new_file_without_prior_read() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());

        WriteunlockTool
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
    async fn missing_readlock_then_new_file_writeunlock_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());

        let _ = ReadlockTool
            .call(serde_json::json!({"path": "later.md"}), &ctx)
            .await;

        WriteunlockTool
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
        assert!(
            !ctx.locks
                .has_read(&tmp.path().join("later.md"), &ctx.agent_id, ctx.session.id)
        );
    }

    #[tokio::test]
    async fn existing_file_without_prior_readlock_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("existing.md"), "old\n").unwrap();
        let ctx = test_ctx(tmp.path());

        let err = WriteunlockTool
            .call(
                serde_json::json!({"path": "existing.md", "content": "new\n"}),
                &ctx,
            )
            .await
            .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("readlock it first"), "{msg}");
        assert!(msg.contains("retry writeunlock"), "{msg}");
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("existing.md")).unwrap(),
            "old\n"
        );
    }

    #[tokio::test]
    async fn new_file_writeunlock_creates_missing_parent_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());

        WriteunlockTool
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
    async fn new_file_create_does_not_grant_future_blind_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());

        WriteunlockTool
            .call(
                serde_json::json!({"path": "created.md", "content": "first\n"}),
                &ctx,
            )
            .await
            .unwrap();

        let err = WriteunlockTool
            .call(
                serde_json::json!({"path": "created.md", "content": "second\n"}),
                &ctx,
            )
            .await
            .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("readlock it first"), "{msg}");
        assert!(msg.contains("retry writeunlock"), "{msg}");
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("created.md")).unwrap(),
            "first\n"
        );
    }

    #[tokio::test]
    async fn existing_file_with_prior_read_uses_temporary_write_guard() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let file = tmp.path().join("existing.md");
        std::fs::write(&file, "old\n").unwrap();
        ctx.locks.note_read(&file, &ctx.agent_id, ctx.session.id);
        assert!(ctx.locks.holder(&file).is_none());

        WriteunlockTool
            .call(
                serde_json::json!({"path": "existing.md", "content": "new\n"}),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(std::fs::read_to_string(&file).unwrap(), "new\n");
        assert!(ctx.locks.holder(&file).is_none());
        assert!(ctx.locks.has_read(&file, &ctx.agent_id, ctx.session.id));
    }

    #[test]
    fn create_new_race_reports_file_now_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let path = tmp.path().join("raced.md");

        let err = create_new_and_release(&ctx, &path, b"new\n", |path, _| {
            std::fs::write(path, "raced\n")?;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map(|_| ())
        })
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("file now exists; readlock it before overwriting"),
            "{err}"
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), "raced\n");
    }

    #[tokio::test]
    async fn new_file_writeunlock_reports_parent_not_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        std::fs::write(tmp.path().join("blocked"), "file blocks directory").unwrap();

        let err = WriteunlockTool
            .call(
                serde_json::json!({"path": "blocked/file.md", "content": "body"}),
                &ctx,
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("is not a directory"), "{err}");
    }

    #[tokio::test]
    async fn writeunlock_reports_success_when_release_persist_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, db) = test_ctx_with_db(tmp.path());
        let file = tmp.path().join("existing.md");
        std::fs::write(&file, "old\n").unwrap();
        ctx.locks.note_read(&file, &ctx.agent_id, ctx.session.id);
        ctx.locks
            .acquire(&file, &ctx.agent_id, ctx.session.id)
            .unwrap();
        fail_lock_state_deletes(&db);

        let out = WriteunlockTool
            .call(
                serde_json::json!({"path": "existing.md", "content": "new\n"}),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(std::fs::read_to_string(&file).unwrap(), "new\n");
        assert!(out.content.contains("wrote `"), "{}", out.content);
        assert!(
            out.content.contains("lock bookkeeping did not persist"),
            "{}",
            out.content
        );
        assert!(out.content.ends_with(LOCK_BOOKKEEPING_ADVISORY));
        assert!(ctx.locks.holder(&file).is_none());
        assert!(ctx.locks.has_read(&file, &ctx.agent_id, ctx.session.id));
        ctx.locks
            .check_write_permitted(&file, &ctx.agent_id, ctx.session.id)
            .unwrap();
    }
}
