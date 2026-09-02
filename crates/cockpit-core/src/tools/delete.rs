//! `delete` — remove one regular file with the ordinary native-file guards.
//!
//! Shell is not the authority for file deletion: this keeps deletion available
//! when an Assistant's SOUL/USER files are protected from shell writes.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput, ToolPresentation, path_or_readable_args};
use crate::resource_limits::{existing_file_unchanged, read_existing_for_mutation};
use crate::tools::common::resolve;

pub struct DeleteTool;

#[async_trait]
impl Tool for DeleteTool {
    fn name(&self) -> &str {
        "delete"
    }

    fn description(&self) -> &str {
        "Delete one existing file; locking and the prior-read safety check are automatic"
    }

    fn verbose_description(&self) -> Option<String> {
        Some(
            "Delete one existing regular file. Read it first so Cockpit can protect against deleting a file that changed since inspection; locking is automatic. This tool does not delete directories."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "x-cockpit-kind": "path", "x-cockpit-aliases": ["file_path", "filePath", "filepath", "pathname", "target_file", "file", "absolute_path"], "description": "Existing file to delete" }
            },
            "required": ["path"]
        })
    }

    fn verbose_parameters(&self) -> Option<Value> {
        Some(self.parameters())
    }

    fn presentation(&self, args: &Value) -> ToolPresentation {
        let (summary, full_input) = path_or_readable_args(args);
        ToolPresentation::with_parts(Some("🗑️"), "delete", summary, full_input)
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let path_arg = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::engine::tool::invalid_input("`path` is required"))?;
        let requested_path = resolve(path_arg, &ctx.cwd);
        crate::tools::write::enforce_requested_write_scope(ctx, &requested_path, self.name())?;
        let path = crate::tools::sandbox::check_native_access(
            ctx,
            &requested_path,
            crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
        )
        .await?;
        crate::tools::write::enforce_write_scope(ctx, &path, self.name())?;
        match crate::assistants::identity::check_identity_write(ctx, &path).await? {
            crate::assistants::identity::IdentityWriteGate::Allow { .. } => {}
            crate::assistants::identity::IdentityWriteGate::Refuse(message) => {
                return Ok(crate::assistants::identity::tool_refusal(message));
            }
        }
        crate::tools::sandbox::recheck_native_access_effect_boundary(
            &path,
            crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
        )
        .await?;
        let previous = read_existing_for_mutation(&path)
            .map_err(|error| anyhow::anyhow!("read `{}`: {error}", path.display()))?;
        crate::tools::write::authorize_existing_write(ctx, &path, &previous, &[]).await?;
        let acquire =
            crate::tools::lock_wait::acquire_waiting(ctx, &path, self.name(), false).await?;
        let guard = ctx
            .locks
            .begin_write_after_wait(
                &path,
                &ctx.lock_identity,
                ctx.session.id,
                self.name(),
                !acquire.preexisting_hold,
                true,
            )
            .await?;
        crate::tools::sandbox::recheck_claimed_native_access_stability_boundary(
            &path,
            crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
        )
        .await?;
        if !existing_file_unchanged(&path, &previous)? {
            return Err(anyhow::anyhow!(
                "`{}` changed while approval was pending; read it again before deleting",
                path.display()
            ));
        }
        crate::engine::interrupt::recheck_current_host_approval_effect_boundary(
            "delete_filesystem_mutation",
            &crate::tools::write::host_approval_filesystem_write_effects(
                &path,
                Some(previous.as_slice()),
                &[],
            ),
        )
        .await?;
        std::fs::remove_file(&path)
            .map_err(|error| anyhow::anyhow!("delete `{}`: {error}", path.display()))?;
        let persist_ok = guard.release_after_write().await;
        ctx.locks
            .note_read(&path, &ctx.lock_identity, ctx.session.id)
            .await;
        crate::assistants::identity::record_identity_write(ctx, &path).await?;
        let advisory = (!persist_ok).then_some(crate::tools::common::LOCK_BOOKKEEPING_ADVISORY);
        Ok(ToolOutput::text(format!(
            "deleted `{}`{}",
            path.display(),
            advisory.unwrap_or_default()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tool::Tool;
    use crate::tools::common::test_ctx;

    #[tokio::test]
    async fn delete_rejects_an_existing_file_over_the_mutation_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let file = tmp.path().join("huge.txt");
        let handle = std::fs::File::create(&file).unwrap();
        handle
            .set_len(crate::resource_limits::ResourceLimits::defaults().fs_mutation_read_bytes + 1)
            .unwrap();
        drop(handle);
        ctx.locks
            .note_read(&file, &ctx.lock_identity, ctx.session.id)
            .await;
        let err = DeleteTool
            .call(serde_json::json!({"path": "huge.txt"}), &ctx)
            .await
            .expect_err("oversized existing file must fail closed");
        let msg = err.to_string();
        assert!(
            msg.contains("existing file") || msg.contains("byte limit"),
            "{msg}"
        );
        assert!(file.exists(), "delete must not remove an over-cap file");
    }
}
