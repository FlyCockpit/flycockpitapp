//! Test/test-support session constructors. They open a vault for the given
//! `Db` so existing fixtures keep a four-argument `Session::create` shape.

use std::path::PathBuf;

use anyhow::Result;
use uuid::Uuid;

use super::Session;
use super::lifecycle::RedactionKeyResolverArc;
use crate::db::Db;

impl Session {
    pub fn create_for_test(
        db: Db,
        project_root: PathBuf,
        active_agent: &str,
        resolver: RedactionKeyResolverArc,
    ) -> Result<Self> {
        let vault = crate::secure_key::vault_for_db(&db)
            .map_err(|e| anyhow::anyhow!("opening test session vault: {e}"))?;
        Self::create_with_test_workspace_root(db, project_root, active_agent, resolver, vault)
    }

    pub fn create_deferred_for_test(
        db: Db,
        project_root: PathBuf,
        active_agent: &str,
        resolver: RedactionKeyResolverArc,
    ) -> Result<Self> {
        let vault = crate::secure_key::vault_for_db(&db)
            .map_err(|e| anyhow::anyhow!("opening test session vault: {e}"))?;
        Self::create_deferred_with_test_workspace_root(
            db,
            project_root,
            active_agent,
            resolver,
            vault,
        )
    }

    pub fn create_assistant_deferred_for_test(
        db: Db,
        project_root: PathBuf,
        active_agent: &str,
        assistant_name: &str,
        resolver: RedactionKeyResolverArc,
    ) -> Result<Self> {
        let vault = crate::secure_key::vault_for_db(&db)
            .map_err(|e| anyhow::anyhow!("opening test session vault: {e}"))?;
        Self::create_assistant_deferred_with_test_workspace_root(
            db,
            project_root,
            active_agent,
            assistant_name,
            resolver,
            vault,
        )
    }

    pub fn create_fork_for_test(
        db: Db,
        parent_session_id: Uuid,
        fork_point_turn_id: Option<String>,
        resolver: RedactionKeyResolverArc,
    ) -> Result<Self> {
        let vault = crate::secure_key::vault_for_db(&db)
            .map_err(|e| anyhow::anyhow!("opening test session vault: {e}"))?;
        Self::create_fork_with_test_workspace_root(
            db,
            parent_session_id,
            fork_point_turn_id,
            resolver,
            vault,
        )
    }

    pub fn resume_for_test(
        db: Db,
        session_id: Uuid,
        resolver: RedactionKeyResolverArc,
    ) -> Result<Option<Self>> {
        let vault = crate::secure_key::vault_for_db(&db)
            .map_err(|e| anyhow::anyhow!("opening test session vault: {e}"))?;
        Self::resume_with_test_workspace_root(db, session_id, resolver, vault)
    }
}
