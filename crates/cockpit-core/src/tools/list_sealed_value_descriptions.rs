//! `list_sealed_value_descriptions` — scoped safe metadata for sealed values.
//!
//! This is deliberately narrower than owner inventory. It lists only the
//! current session's records, its canonical project's records, and Global
//! records explicitly granted to that project. The projection contains only
//! an opaque record id, canonical name, and safe description; literals and
//! scope or lifecycle metadata never cross the tool boundary.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};

pub struct ListSealedValueDescriptionsTool;

#[async_trait]
impl Tool for ListSealedValueDescriptionsTool {
    fn name(&self) -> &str {
        crate::sealed::LIST_SEALED_VALUE_DESCRIPTIONS_TOOL
    }

    fn description(&self) -> &str {
        "List the ids, names, and safe descriptions of sealed values referenceable in this session"
    }

    fn verbose_description(&self) -> Option<String> {
        Some(
            "List only sealed values referenceable from this session: session values, values in this project, and global values explicitly granted to this project. Each result has record_id, name, and safe description. Descriptions must not contain secrets. Values, locators, scope keys, lifecycle state, and records outside this scope are never returned. Takes no arguments."
                .to_string(),
        )
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }

    fn parameters(&self) -> Value {
        crate::sealed::list_sealed_value_descriptions_schema()
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        if args.as_object().is_none_or(|object| !object.is_empty()) {
            return Err(invalid_input(
                "`list_sealed_value_descriptions` takes no arguments",
            ));
        }

        let records = ctx
            .session
            .db
            .list_referenceable_sealed_value_metadata(
                ctx.session.id.to_string(),
                ctx.session.project_id.clone(),
            )
            .await?;
        let output: Vec<_> = records
            .into_iter()
            .map(|record| {
                serde_json::json!({
                    "record_id": record.record_id,
                    "name": record.name,
                    "description": record.description,
                })
            })
            .collect();
        Ok(ToolOutput::text(serde_json::to_string(&output)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lists_only_safe_metadata_for_the_current_scope() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        let project = ctx.session.project_id.clone();
        let visible = cockpit_db::db::sealed_scope::NewSealedValueRecord {
            record_id: uuid::Uuid::new_v4().to_string(),
            scope: cockpit_db::db::sealed_scope::SealedScopeKind::Project,
            scope_key: project.clone(),
            name: "deploy_token".to_string(),
            description: "deploy credential; do not put secrets here".to_string(),
            owner_principal: "owner".to_string(),
            created_at_ms: 1_000,
        };
        db.prepare_sealed_value_create(
            visible.clone(),
            "visible-create".to_string(),
            Some("visible-locator".to_string()),
        )
        .await
        .expect("prepare visible value");
        db.commit_sealed_value_create(
            visible.record_id.clone(),
            Some("visible-locator".to_string()),
            2_000,
        )
        .await
        .expect("commit visible value");

        let hidden = cockpit_db::db::sealed_scope::NewSealedValueRecord {
            record_id: uuid::Uuid::new_v4().to_string(),
            scope: cockpit_db::db::sealed_scope::SealedScopeKind::Project,
            scope_key: "another-project".to_string(),
            name: "other_token".to_string(),
            description: "other project credential".to_string(),
            owner_principal: "owner".to_string(),
            created_at_ms: 1_000,
        };
        db.prepare_sealed_value_create(
            hidden.clone(),
            "hidden-create".to_string(),
            Some("hidden-locator".to_string()),
        )
        .await
        .expect("prepare hidden value");
        db.commit_sealed_value_create(
            hidden.record_id.clone(),
            Some("hidden-locator".to_string()),
            2_000,
        )
        .await
        .expect("commit hidden value");

        let output = ListSealedValueDescriptionsTool
            .call(serde_json::json!({}), &ctx)
            .await
            .expect("listing succeeds");
        let items: Vec<serde_json::Value> =
            serde_json::from_str(&output.content).expect("tool returns JSON metadata");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["record_id"], visible.record_id);
        assert_eq!(items[0]["name"], "deploy_token");
        assert_eq!(
            items[0]["description"],
            "deploy credential; do not put secrets here"
        );
        assert!(
            !output.content.contains(&hidden.record_id)
                && !output.content.contains("hidden-locator"),
            "the tool must not disclose out-of-scope identity or locators"
        );
        assert!(
            ListSealedValueDescriptionsTool
                .call(serde_json::json!({"record_id": visible.record_id}), &ctx)
                .await
                .is_err(),
            "the listing takes no caller-controlled selector"
        );
    }
}
