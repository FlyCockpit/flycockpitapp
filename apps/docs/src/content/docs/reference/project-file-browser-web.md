---
title: Project File Browser Web UI
---

Use this script to verify the browser project-file surface against a real relay and cockpit-cli daemon.

## Setup

1. Start the web, server, relay, and a cockpit-cli daemon connected to the same account.
2. Open `/$lang/instances`, confirm the target instance is online, then open a project.
3. Choose `Files` from the project view.

## Manual E2E

1. Browse the root and at least one nested folder. Toggle hidden files and confirm dotfiles appear only when enabled. Confirm gitignored entries are visually muted and blocked entries show the owner-policy message.
2. Open a text file. Edit it, save, then verify the changed content on disk in the project checkout.
3. Edit the same file on disk or from another client after loading it in the browser. Save the stale browser buffer and confirm the conflict/error state is shown without discarding the buffer.
4. Create a file and a folder from the current directory. Confirm the file opens after creation and the folder navigates after creation.
5. Rename a selected entry. Confirm the browser navigates to the renamed path and the old path is gone from the listing.
6. Delete a selected entry. Confirm type-to-confirm is required and the deleted path disappears after the mutation completes.
7. Make a git change from an agent or local shell. Confirm the changes panel updates dirty/untracked counts and the selected file diff renders unified diff text.
8. Test a grantee with the `project_files` scope. Confirm daemon-filtered secret entries render as blocked while owner-visible files remain browsable/editable according to daemon policy.
9. Check a narrow mobile viewport. The tree, viewer, and changes columns should stack without overlapping text or controls.

## Notes

The route is split by TanStack Router, so the browser/editor code loads with the file-browser route rather than the eager app shell. This implementation uses the existing text-area editor; adding CodeMirror requires an explicit dependency-install confirmation under the repo dependency policy.
