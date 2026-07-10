use super::*;

impl LockManager {
    pub(super) fn clear_waiter(&self, waiter: &(Uuid, AgentId)) {
        let mut state = crate::sync::lock_or_recover(&self.inner);
        state.waiting.remove(waiter);
    }

    pub(super) fn wait_context(&self, waiter: &(Uuid, AgentId)) -> String {
        let state = crate::sync::lock_or_recover(&self.inner);
        match state.waiting.get(waiter) {
            Some(edge) => format!(
                " waiting for `{}` held by `{}` in session {}",
                edge.path.display(),
                edge.holder_agent,
                edge.holder_session
            ),
            None => String::new(),
        }
    }

    pub(super) fn record_wait_or_cycle(
        &self,
        waiter: &(Uuid, AgentId),
        path: &Path,
        holder: (Uuid, AgentId),
    ) -> Result<()> {
        let mut state = crate::sync::lock_or_recover(&self.inner);
        let edge = WaitingOn {
            path: path.to_path_buf(),
            holder_session: holder.0,
            holder_agent: holder.1.clone(),
        };
        state.waiting.insert(waiter.clone(), edge);
        if let Some(cycle) = wait_cycle(&state, waiter) {
            state.waiting.remove(waiter);
            bail!("lock wait cycle detected: {cycle}");
        }
        Ok(())
    }
}
