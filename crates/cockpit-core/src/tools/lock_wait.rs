use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;

use crate::engine::agent::TurnEvent;
use crate::engine::tool::ToolCtx;
use crate::locks::AcquireWait;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WaitingAcquire {
    pub(crate) preexisting_hold: bool,
}

pub(crate) async fn acquire_waiting(
    ctx: &ToolCtx,
    path: &Path,
    tool_name: &str,
    record_read: bool,
) -> Result<WaitingAcquire> {
    let preexisting_hold = matches!(ctx.locks.holder(path), Some((s, ref a)) if s == ctx.session.id && a == &ctx.agent_id);
    let events = ctx.events.clone();
    let waiting_path = path.display().to_string();
    let did_wait = Arc::new(AtomicBool::new(false));
    let outcome = if record_read {
        ctx.locks
            .acquire_wait(path, &ctx.agent_id, ctx.session.id, &ctx.cancel, {
                let events = events.clone();
                let waiting_path = waiting_path.clone();
                let did_wait = did_wait.clone();
                move |(_, holder_agent)| {
                    did_wait.store(true, Ordering::Relaxed);
                    if let Some(tx) = events.as_ref() {
                        let _ = tx.try_send(TurnEvent::WaitingForLock {
                            path: waiting_path.clone(),
                            holder_agent: holder_agent.clone(),
                            waiting: true,
                        });
                    }
                }
            })
            .await
    } else {
        ctx.locks
            .acquire_wait_without_read(path, &ctx.agent_id, ctx.session.id, &ctx.cancel, {
                let events = events.clone();
                let waiting_path = waiting_path.clone();
                let did_wait = did_wait.clone();
                move |(_, holder_agent)| {
                    did_wait.store(true, Ordering::Relaxed);
                    if let Some(tx) = events.as_ref() {
                        let _ = tx.try_send(TurnEvent::WaitingForLock {
                            path: waiting_path.clone(),
                            holder_agent: holder_agent.clone(),
                            waiting: true,
                        });
                    }
                }
            })
            .await
    };

    if did_wait.load(Ordering::Relaxed)
        && let Some(tx) = events.as_ref()
    {
        let _ = tx
            .send(TurnEvent::WaitingForLock {
                path: waiting_path,
                holder_agent: String::new(),
                waiting: false,
            })
            .await;
    }

    match outcome? {
        AcquireWait::Acquired => Ok(WaitingAcquire { preexisting_hold }),
        AcquireWait::Cancelled => Err(anyhow::anyhow!("{tool_name} cancelled")),
    }
}
