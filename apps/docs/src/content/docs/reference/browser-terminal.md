---
title: Browser terminal manual E2E
---

Use this script to verify the browser terminal against a real relay and daemon.

## Setup

1. Start the web, server, relay, and a cockpit-cli daemon connected to the same account.
2. Confirm the instance shows Online at `/instances`.
3. If the account has 2FA enabled, keep the authenticator app available for terminal step-up.

## Checks

1. Open `/instances`, choose the terminal icon for the online instance, complete step-up if prompted, and click Open terminal.
2. Run `ls` and confirm output streams into the browser terminal.
3. Run an OSC 52 copy command from the shell and confirm the browser writes the copied text to the system clipboard. If the browser blocks the async clipboard write, click the Copy text confirmation button.
4. Paste multiline text into the terminal and confirm it arrives as shell input.
5. Copy a screenshot to the OS clipboard, paste it into the terminal while a CLI agent is waiting for input, and confirm the host writes the image to a temporary file and pastes the remote path.
6. Kill network access or stop the relay briefly, restore it before the host TTL expires, and confirm the terminal offers a reattach path that repaints the screen.
7. Switch between light and dark themes and confirm the terminal surface remains readable.
8. Navigate away from the route while the terminal is live and confirm the app-shell live terminal banner remains visible.
