//! `unlock` — recover from a held lock without writing.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput, ToolPresentation, path_or_readable_args};
use crate::tools::common::resolve;

pub struct UnlockTool;

#[async_trait]
impl Tool for UnlockTool {
    fn name(&self) -> &str {
        "unlock"
    }

    fn description(&self) -> &str {
        "Recovery-only: release a stuck held file lock without writing; normal `write`/`edit` calls unlock automatically"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Recovery-only lock cleanup. Use `unlock` when a prior failed, interrupted, or \
             abandoned tool call left this agent holding a file lock and you need to free it \
             without changing the file. Do not use it as part of the normal edit flow: \
             `write` and `edit` acquire and release their lock automatically. `unlock` writes \
             nothing and discards no on-disk changes."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "path",
            "properties": {
                "path": { "type": "string", "x-cockpit-kind": "path", "x-cockpit-aliases": ["file_path", "filePath", "filepath", "pathname", "target_file", "file", "absolute_path"], "description": "Path to unlock" }
            },
            "required": ["path"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "path",
            "properties": {
                "path": { "type": "string", "x-cockpit-kind": "path", "x-cockpit-aliases": ["file_path", "filePath", "filepath", "pathname", "target_file", "file", "absolute_path"], "description": "Path to the file whose lock to release, absolute or relative to the session working directory; must be a file you currently hold a lock on" }
            },
            "required": ["path"]
        }))
    }

    fn presentation(&self, args: &Value) -> ToolPresentation {
        let (summary, full_input) = path_or_readable_args(args);
        ToolPresentation::with_parts(Some("🔓"), self.name(), summary, full_input)
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let path_arg = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::engine::tool::invalid_input("`path` is required"))?;
        let path = resolve(path_arg, &ctx.cwd);
        ctx.locks
            .release(&path, &ctx.agent_id, ctx.session.id)
            .await?;
        Ok(ToolOutput::text(format!("unlocked `{}`", path.display())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::repair::{self, ALIASES_KEY, PATH_KIND_KEY, PRIMARY_FIELD_KEY};
    use crate::engine::tool::Tool;
    use crate::tools::common::test_ctx;
    use crate::tools::read::ReadTool;

    fn path_aliases(schema: &Value) -> Vec<String> {
        schema["properties"]["path"][ALIASES_KEY]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]

    async fn unlock_schema_carries_path_annotations() {
        let read = ReadTool;
        let unlock = UnlockTool;
        for schema in [
            unlock.parameters(),
            unlock.defensive_parameters().expect("defensive schema"),
        ] {
            assert_eq!(schema[PRIMARY_FIELD_KEY], "path");
            assert_eq!(schema["properties"]["path"][PATH_KIND_KEY], "path");
            assert_eq!(path_aliases(&schema), path_aliases(&read.parameters()));
        }
    }

    #[tokio::test]
    async fn unlock_repairs_file_path_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("locked.txt");
        std::fs::write(&file, "body").unwrap();
        let ctx = test_ctx(tmp.path());
        ctx.locks
            .acquire(&file, &ctx.agent_id, ctx.session.id)
            .await
            .unwrap();

        let tool = UnlockTool;
        let mut args = serde_json::json!({ "file_path": "locked.txt" });
        let repaired = repair::repair(&mut args, &tool.parameters(), tool.name());
        assert!(repaired.error.is_none(), "{repaired:?}");
        assert_eq!(args, serde_json::json!({ "path": "locked.txt" }));

        let output = tool.call(args, &ctx).await.unwrap();
        assert!(output.content.contains("locked.txt"), "{output:?}");
        assert!(ctx.locks.holder(&file).is_none());
    }

    #[tokio::test]
    async fn unlock_releases_held_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("locked.txt");
        std::fs::write(&file, "body").unwrap();
        let ctx = test_ctx(tmp.path());
        ctx.locks
            .acquire(&file, &ctx.agent_id, ctx.session.id)
            .await
            .unwrap();

        let output = UnlockTool
            .call(serde_json::json!({ "path": "locked.txt" }), &ctx)
            .await
            .unwrap();

        assert!(ctx.locks.holder(&file).is_none());
        assert!(output.content.contains("locked.txt"), "{output:?}");
    }

    #[tokio::test]

    async fn unlock_is_recovery_only_in_descriptions() {
        let tool = UnlockTool;
        let description = tool.description();
        let defensive = tool.defensive_description().expect("defensive description");

        for text in [description, defensive.as_str()] {
            assert!(text.contains("Recovery-only"), "{text}");
            assert!(text.contains("write") && text.contains("edit"), "{text}");
            assert!(text.contains("automatically"), "{text}");
            assert!(!text.contains("decided not to edit"), "{text}");
            assert!(!text.contains("normal edit flow: use `unlock`"), "{text}");
        }
    }
}
