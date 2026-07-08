# Presence-aware notifications

Use this script to verify daemon attention events through the relay, control plane, browser toast, web push, and inbox ledger.

## Setup

1. Start the web, server, relay, and a cockpit-cli daemon connected to the same account.
2. Configure VAPID keys and enable web push in **Settings -> Cockpit notifications**.
3. Set the relay ingest URL to the server endpoint, for example `RELAY_CONTROL_INGEST_URL=https://api.example.test/api/relay/control-ingest`.
4. If the relay runs as a separate process, set the same `RELAY_CONTROL_SECRET` on the server and relay so the server can publish toast frames back to `/ws/user`.

## Manual E2E

1. Open the app and keep the tab visible. Trigger an agent question or approval-needed event. Confirm the visible tab receives a toast, the inbox row is created, and no browser push is shown.
2. Close all app tabs. Trigger the same event type. Confirm the service worker shows one web push notification and clicking it opens the session deep link with `session` and `interrupt` query parameters.
3. Open the app, switch to another tab or hide the PWA, then trigger an event. Confirm the hidden tab does not count as present and the browser push is shown.
4. Trigger several events for the same session within one minute. Confirm only the first deliverable notification reaches toast or push and later rows are marked as duplicate-suppressed in the ledger.
5. Resolve the interrupt from the daemon/TUI, then open the inbox row. Confirm the UI shows the handled state instead of a dead actionable card.

## Notes

- Notification payloads must use daemon-provided fixed strings only. Transcript text, command output, and prompt text must not appear in the payload.
- iOS Safari web push requires an installed PWA; browser tabs alone cannot receive push notifications there.
