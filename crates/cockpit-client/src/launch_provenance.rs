//! Process-held daemon launch ticket (issue #337).
//!
//! The launch ticket is minted in the process that spawns a daemon and is
//! delivered to the daemon child through the spawn environment only; it is
//! never written to disk and never inherited by unrelated processes. The
//! daemon binds it to the spawning process's exact peer identity, so only
//! the launcher that created the daemon can exchange it for an owner-class
//! peer credential. An unconfined same-uid process that merely runs the
//! approved executable holds no ticket and stays table-governed.

use std::sync::Mutex;

/// Process-global: the launch ticket of the daemon this process most
/// recently spawned (if any). Kept in memory only — a fresh process always
/// starts without provenance.
static PROCESS_LAUNCH_TICKET: Mutex<Option<String>> = Mutex::new(None);

/// Record the launch ticket minted for the daemon this process spawned.
/// Called only by the daemon spawn paths after a successful child spawn, so
/// a cancelled spawn never installs a ticket.
pub fn set_process_launch_ticket(ticket: String) {
    *PROCESS_LAUNCH_TICKET
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(ticket);
}

/// The launch ticket this process holds, if it spawned the daemon it is
/// connecting to. Presented (and consumed) during the peer-credential
/// exchange.
pub fn process_launch_ticket() -> Option<String> {
    PROCESS_LAUNCH_TICKET
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Resolve the launch ticket for a socket connect: the in-memory ticket minted
/// by this process when it spawned the daemon, otherwise the daemon-private
/// persisted ticket for follower cockpit CLI processes on the same uid.
pub fn resolve_launch_ticket(socket: &std::path::Path) -> Option<String> {
    if let Some(ticket) = process_launch_ticket() {
        return Some(ticket);
    }
    load_persisted_launch_ticket(socket)
}

fn load_persisted_launch_ticket(socket: &std::path::Path) -> Option<String> {
    let path = launch_ticket_path(socket);
    let bytes = std::fs::read(&path).ok()?;
    let ticket = String::from_utf8(bytes).ok()?;
    let ticket = ticket.trim();
    if ticket.len() == 64
        && ticket
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Some(ticket.to_string())
    } else {
        None
    }
}

/// Same derivation the daemon uses: `{stem}.launch-ticket` next to the
/// control socket. Confined children are denied this path.
pub fn launch_ticket_path(control_socket: &std::path::Path) -> std::path::PathBuf {
    let stem = control_socket
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("cockpit");
    let file_name = format!("{stem}.launch-ticket");
    match control_socket.parent() {
        Some(parent) => parent.join(file_name),
        None => std::path::PathBuf::from(file_name),
    }
}

/// Test-only: restore the unset state so a test-installed ticket never
/// leaks into other client tests running in the same process.
#[cfg(test)]
pub fn clear_process_launch_ticket() {
    *PROCESS_LAUNCH_TICKET
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_ticket_round_trips_replaces_and_clears() {
        set_process_launch_ticket("a".repeat(64));
        assert_eq!(
            process_launch_ticket().as_deref(),
            Some("a".repeat(64).as_str())
        );
        set_process_launch_ticket("b".repeat(64));
        assert_eq!(
            process_launch_ticket().as_deref(),
            Some("b".repeat(64).as_str())
        );
        // Restore the unset state so this global never leaks into other
        // client tests running in the same process.
        clear_process_launch_ticket();
        assert_eq!(process_launch_ticket(), None);
    }
}
