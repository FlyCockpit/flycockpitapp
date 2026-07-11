---
title: Remote Sessions Web UI
---

Use this script to verify the browser remote-session surface against a real relay and cockpit-cli daemon.

## Setup

1. Start the web, server, relay, and a cockpit-cli daemon connected to the same account.
2. Open `/$lang/instances` and confirm the target instance is online.
3. Open the folder action for the instance, then choose a project.

## Manual E2E

1. Create a new session from the project view. Confirm it appears in the left session sidebar and opens in the main pane.
2. Send a message from the composer and confirm the optimistic user message reconciles when the daemon emits the recorded history entry.
3. Watch assistant text stream into the transcript and confirm tool calls render as expandable rows.
4. Trigger an approval or question. Confirm the interrupt card is highlighted from the `interrupt` deep-link query and resolving it updates the card for all viewers.
5. Rename, fork, archive, and unarchive the session. Confirm server rejections appear as toasts and successful changes update the sidebar/main header.
6. Stop the daemon or relay. Confirm the offline banner appears and the last in-memory snapshot remains visible. Restart it and confirm reattach reconciles gaps from the last sequence.
7. Check a narrow mobile viewport. The session list should scroll horizontally above the transcript, the composer should remain usable above the safe area, and no text should overlap controls.

## Notes

The web UI speaks the daemon protocol through the relay. It does not mirror transcripts into Prisma; reloads require the daemon to be reachable for fresh session data.
