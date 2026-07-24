//! `readlock` — acquire-and-read.
//!
//! Acquires the exclusive lock on the file before reading; releases via
//! `writeunlock` / `editunlock` / `unlock`. Output identical to
//! [`crate::tools::read`].

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput, ToolPresentation, path_or_readable_args};
use crate::tools::common::resolve;
use crate::tools::read::ReadOutcome;

pub struct ReadlockTool;

#[async_trait]
impl Tool for ReadlockTool {
    fn name(&self) -> &str {
        "readlock"
    }

    fn description(&self) -> &str {
        "Acquire exclusive lock on a file and read it; release with writeunlock/editunlock/unlock"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Take an exclusive lock on one file AND read its current contents in a single step. \
             Do this BEFORE you change a file: the lock proves no one else is editing it and \
             records the exact bytes you are about to modify, which `writeunlock`/`editunlock` \
             require. Always read-lock immediately before writing — never write a file you have \
             not just locked-and-read. You hold the lock until you release it with `writeunlock` \
             (save changes), `editunlock` (save a search/replace), or `unlock` (abandon with no \
             change). Output is line-numbered and capped like `read`."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "path",
            "properties": {
                "path":   { "type": "string", "x-cockpit-kind": "path", "x-cockpit-aliases": ["file_path", "filePath", "filepath", "pathname", "target_file", "file", "absolute_path"], "description": "Path to lock and read" },
                "offset": { "type": "integer", "description": "1-indexed start line (default 1)" },
                "limit":  { "type": "integer", "description": "Max lines (default 2000)" }
            },
            "required": ["path"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "path",
            "properties": {
                "path":   { "type": "string", "x-cockpit-kind": "path", "x-cockpit-aliases": ["file_path", "filePath", "filepath", "pathname", "target_file", "file", "absolute_path"], "description": "Path to the single file to lock and read, absolute or relative to the session working directory; the file must already exist" },
                "offset": { "type": "integer", "description": "1-indexed line number to start reading from; defaults to 1. The lock always covers the whole file regardless of which lines you read" },
                "limit":  { "type": "integer", "description": "Maximum number of lines to return from `offset`; defaults to 2000" }
            },
            "required": ["path"]
        }))
    }

    fn presentation(&self, args: &Value) -> ToolPresentation {
        let (summary, full_input) = path_or_readable_args(args);
        ToolPresentation::with_parts(Some("🔒"), "readlock", summary, full_input)
    }

    fn honors_dispatch_cancel(&self) -> bool {
        true
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let path_arg = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::engine::tool::invalid_input("`path` is required"))?;
        let path = resolve(path_arg, &ctx.cwd);
        // Native-tool boundary check (sandboxing part 2) before taking
        // the lock — a denied path never acquires.
        let path = crate::tools::sandbox::check_native_access(
            ctx,
            &path,
            crate::tools::shell_sandbox::SandboxPathAccess::Read,
        )
        .await?;
        // Gitignore read-allowlist gate (read/readlock only), before acquiring
        // the lock — a refused read never locks the file.
        if let Some(refusal) = crate::tools::sandbox::check_gitignore_read(ctx, &path).await? {
            return Ok(refusal);
        }
        crate::tools::lock_wait::acquire_waiting(ctx, &path, self.name(), true).await?;
        finish_acquired_readlock(args, ctx, path, |path| std::fs::read(path))
    }
}

fn finish_acquired_readlock(
    args: Value,
    ctx: &ToolCtx,
    path: std::path::PathBuf,
    read_file: impl FnOnce(&std::path::Path) -> std::io::Result<Vec<u8>>,
) -> Result<ToolOutput> {
    match crate::tools::read::read_impl_outcome_with_path(args, ctx, true, path.clone(), read_file)
    {
        Ok(ReadOutcome::Content(out)) => Ok(out),
        Ok(ReadOutcome::NoContent(out)) => {
            ctx.locks
                .release_and_drop_read(&path, &ctx.agent_id, ctx.session.id)?;
            Ok(out)
        }
        Err(err) => {
            if let Err(release_err) =
                ctx.locks
                    .release_and_drop_read(&path, &ctx.agent_id, ctx.session.id)
            {
                tracing::warn!(
                    error = %release_err,
                    path = %path.display(),
                    "failed to release no-content readlock after read error"
                );
            }
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locks::LockManager;
    use crate::tools::common::{test_ctx, test_ctx_with_db};
    use crate::tools::writeunlock::WriteunlockTool;
    use std::sync::Arc;

    fn assert_no_lock_or_read(ctx: &ToolCtx, path: &std::path::Path) {
        assert!(ctx.locks.holder(path).is_none());
        assert!(!ctx.locks.has_read(path, &ctx.agent_id, ctx.session.id));
    }

    #[tokio::test]
    async fn readlock_on_directory_leaves_no_lock_and_no_read() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("subdir");
        std::fs::create_dir(&dir).unwrap();
        let ctx = test_ctx(tmp.path());

        let out = ReadlockTool
            .call(serde_json::json!({"path": "subdir"}), &ctx)
            .await
            .unwrap();

        assert!(out.content.contains("is a directory"), "{}", out.content);
        assert_no_lock_or_read(&ctx, &dir);
    }

    #[tokio::test]
    async fn readlock_on_missing_path_leaves_no_lock_and_no_read() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let missing = tmp.path().join("CONTRIBUTING.md");

        let out = ReadlockTool
            .call(serde_json::json!({"path": "CONTRIBUTING.md"}), &ctx)
            .await
            .unwrap();

        assert!(out.content.contains("does not exist"), "{}", out.content);
        assert_no_lock_or_read(&ctx, &missing);
    }

    #[tokio::test]
    async fn readlock_on_binary_leaves_no_lock_and_no_read() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("blob.bin");
        std::fs::write(&file, b"\0binary").unwrap();
        let ctx = test_ctx(tmp.path());

        let out = ReadlockTool
            .call(serde_json::json!({"path": "blob.bin"}), &ctx)
            .await
            .unwrap();

        assert!(out.content.contains("looks binary"), "{}", out.content);
        assert_no_lock_or_read(&ctx, &file);
    }

    #[tokio::test]
    async fn readlock_on_real_file_holds_lock_and_records_read() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("file.txt");
        std::fs::write(&file, "hello\n").unwrap();
        let ctx = test_ctx(tmp.path());

        let out = ReadlockTool
            .call(serde_json::json!({"path": "file.txt"}), &ctx)
            .await
            .unwrap();

        assert!(out.content.contains("1|hello"), "{}", out.content);
        assert_eq!(
            ctx.locks.holder(&file),
            Some((ctx.session.id, ctx.agent_id.clone()))
        );
        assert!(ctx.locks.has_read(&file, &ctx.agent_id, ctx.session.id));
    }

    #[tokio::test]
    async fn missing_readlock_then_writeunlock_create_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());

        let _ = ReadlockTool
            .call(serde_json::json!({"path": "later.md"}), &ctx)
            .await
            .unwrap();

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
        assert_no_lock_or_read(&ctx, &tmp.path().join("later.md"));
    }

    #[tokio::test]
    async fn readlock_hard_io_error_releases_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("file.txt");
        std::fs::write(&file, "hello\n").unwrap();
        let ctx = test_ctx(tmp.path());
        ctx.locks
            .acquire_wait(&file, &ctx.agent_id, ctx.session.id, &ctx.cancel, |_| {})
            .await
            .unwrap();

        let err = finish_acquired_readlock(
            serde_json::json!({"path": "file.txt"}),
            &ctx,
            file.clone(),
            |_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "blocked",
                ))
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("blocked"), "{err}");
        assert_no_lock_or_read(&ctx, &file);
    }

    #[test]
    fn release_and_drop_read_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("file.txt");
        std::fs::write(&file, "hello\n").unwrap();
        let (ctx, _) = test_ctx_with_db(tmp.path());
        ctx.locks
            .acquire(&file, &ctx.agent_id, ctx.session.id)
            .unwrap();

        ctx.locks
            .release_and_drop_read(&file, &ctx.agent_id, ctx.session.id)
            .unwrap();
        ctx.locks
            .release_and_drop_read(&file, &ctx.agent_id, ctx.session.id)
            .unwrap();

        assert_no_lock_or_read(&ctx, &file);
    }

    #[test]
    fn release_and_drop_read_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("file.txt");
        std::fs::write(&file, "hello\n").unwrap();
        let (ctx, db) = test_ctx_with_db(tmp.path());
        ctx.locks
            .acquire(&file, &ctx.agent_id, ctx.session.id)
            .unwrap();

        ctx.locks
            .release_and_drop_read(&file, &ctx.agent_id, ctx.session.id)
            .unwrap();
        let restored = Arc::new(LockManager::from_db(db).unwrap());

        assert!(restored.holder(&file).is_none());
        assert!(!restored.has_read(&file, &ctx.agent_id, ctx.session.id));
    }
}
