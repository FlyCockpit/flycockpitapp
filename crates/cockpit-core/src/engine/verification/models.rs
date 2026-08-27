//! Immutable profile-slot model resolution for verification utilities.

use std::sync::Arc;

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::engine::model::Model;
use crate::engine::tool::ToolCtx;
use crate::session::Session;

pub(crate) async fn resolve_profile_utility_model(
    session: &Session,
    ctx: &ToolCtx,
    profile_snapshot_id: Uuid,
    slot: &str,
) -> Result<Arc<Model>> {
    if let Some(model) = session.profile_utility_model(profile_snapshot_id, slot) {
        return Ok(model);
    }
    // A child profile may become runnable after the worker installed its
    // startup directory. Resolve the same immutable binding lazily; never use
    // the foreground model as a fallback.
    let snapshot = session
        .db
        .agent_profile_snapshot_by_id(session.id, profile_snapshot_id)
        .await?
        .context("verification profile snapshot is absent")?
        .reconstruct()?;
    let binding = snapshot
        .bindings
        .iter()
        .find(|binding| binding.slot_id == slot && binding.hard_capability_verified)
        .with_context(|| {
            format!("verification profile has no verified binding for slot `{slot}`")
        })?;
    let providers = ctx.config.providers();
    let store = session.provider_credential_store(&providers).ok();
    let model = Model::for_provider_optional_store(
        &providers,
        &binding.selected_provider_alias.provider_id,
        &binding.selected_provider_alias.model_id,
        ctx.redact.clone(),
        store,
    )?;
    Ok(Arc::new(model))
}
