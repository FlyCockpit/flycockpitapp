//! Recall authorization shared by the legacy tools and `cockpit://` provider.

use anyhow::Result;
use uuid::Uuid;

use crate::engine::tool::{ToolCtx, invalid_input};

/// The recall surface is a separate permission from host-file `read`.
/// `cockpit://` dispatchers must call this before parsing or listing history.
/// The allowlist preserves the pre-#129 posture: only recall-capable agent
/// surfaces (including Monty) may inspect durable session history.
pub(crate) fn require_recall_permission(ctx: &ToolCtx) -> Result<()> {
    let granted_by_surface = ctx.available_tools.contains("history_search")
        || matches!(ctx.agent_id.as_str(), "history" | "Monty" | "monty");
    if granted_by_surface {
        Ok(())
    } else {
        Err(invalid_input(
            "history recall is not permitted for this agent; `read` only grants host-file access",
        ))
    }
}

/// Resolve a target session only after enforcing both recall permission and
/// the per-workspace outbound/inbound AND policy. Same-workspace reads remain
/// available by default. Neither check observes execution sandbox state.
pub(crate) async fn require_session_access(ctx: &ToolCtx, target: Uuid) -> Result<()> {
    require_recall_permission(ctx)?;
    if ctx
        .session
        .db
        .session_access_allowed(&ctx.session.project_id, target)
        .await?
    {
        Ok(())
    } else {
        Err(invalid_input(
            "session is outside the current workspace and cross-workspace history consent is not enabled by both workspaces",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    use cockpit_db::db::history_scope::WorkspaceHistoryScope;

    #[tokio::test]
    async fn read_surface_without_recall_permission_is_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.agent_id = "docs-resolver".to_string();
        ctx.available_tools = Arc::new(HashSet::from(["read".to_string()]));

        let err = require_recall_permission(&ctx).unwrap_err();
        assert!(err.to_string().contains("history recall is not permitted"));
    }

    #[tokio::test]
    async fn session_access_requires_two_workspace_consents_and_ignores_sandbox() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.available_tools = Arc::new(HashSet::from(["history_search".to_string()]));
        let target = ctx
            .session
            .db
            .create_session("other-workspace", "/other", "Build")
            .await
            .unwrap();

        for (outbound, inbound, expected) in [
            (false, false, false),
            (false, true, false),
            (true, false, false),
            (true, true, true),
        ] {
            ctx.session
                .db
                .set_workspace_history_scope(
                    &ctx.session.project_id,
                    WorkspaceHistoryScope {
                        outbound,
                        inbound: false,
                    },
                )
                .await
                .unwrap();
            ctx.session
                .db
                .set_workspace_history_scope(
                    "other-workspace",
                    WorkspaceHistoryScope {
                        outbound: false,
                        inbound,
                    },
                )
                .await
                .unwrap();
            ctx.session.set_sandbox_enabled(false);
            let off = require_session_access(&ctx, target.session_id)
                .await
                .is_ok();
            ctx.session.set_sandbox_enabled(true);
            let on = require_session_access(&ctx, target.session_id)
                .await
                .is_ok();
            assert_eq!((off, on), (expected, expected));
        }
    }
}
