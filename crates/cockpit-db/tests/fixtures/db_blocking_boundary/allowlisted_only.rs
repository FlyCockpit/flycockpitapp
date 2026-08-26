//! Fixture: only the exact reviewed allowlist reaches unguarded helpers.
//! Expected: gate accepts with that exact allowlist set.

struct Db;
struct AgentMutationJournalFence;
struct AgentEditorPublicationIntent;
type Result<T> = std::result::Result<T, ()>;

impl Db {
    fn read_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }

    fn write_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }

    /// Permanent guarded boundary for synchronous CLI one-shots.
    pub fn blocking_for_sync_cli<F, T>(&self, f: F) -> T {
        self.write_blocking_unguarded(f)
    }

    /// Temporary; owned for removal by db-sync-wrapper-migration.
    pub fn blocking_read_for_sync_ui<F, T>(&self, f: F) -> T {
        self.read_blocking_unguarded(f)
    }

    /// Temporary; owned for removal by db-sync-wrapper-migration.
    pub fn blocking_write_for_sync_ui<F, T>(&self, f: F) -> T {
        self.write_blocking_unguarded(f)
    }

    /// Temporary; owned for removal by db-sync-wrapper-migration.
    pub fn blocking_write_for_sync_event<F, T>(&self, f: F) -> T {
        self.write_blocking_unguarded(f)
    }

    /// Temporary; owned for removal by db-sync-wrapper-migration.
    pub fn blocking_write_for_sync_maintenance<F, T>(&self, f: F) -> T {
        self.write_blocking_unguarded(f)
    }

    /// Permanent typed agent-mutation journal publication bridge.
    pub fn insert_agent_mutation_journal_under_publication_lock(
        &self,
        _fence: AgentMutationJournalFence,
    ) -> Result<()> {
        self.write_blocking_unguarded(|| Ok(()))
    }

    /// Permanent typed editor-intent publication bridge.
    pub fn prepare_agent_editor_publication_under_publication_lock(
        &self,
        _intent: AgentEditorPublicationIntent,
    ) -> Result<()> {
        self.write_blocking_unguarded(|| Ok(()))
    }

    /// Permanent typed editor-result publication bridge.
    pub fn record_agent_editor_publication_under_publication_lock(
        &self,
        _lease_id: String,
        _completion_identity: [u8; 32],
        _completion_operation_id: String,
        _result_revision: String,
    ) -> Result<()> {
        self.write_blocking_unguarded(|| Ok(()))
    }
}
