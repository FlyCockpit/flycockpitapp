---
title: Instance Access Sharing And Invites
---

# Instance access sharing and invites

Instance owners can share an instance by explicit email invitation. Grants are scoped per row: terminal, agent, agent read-only, or project files. Terminal grants are instance-wide and should be short-lived; other scopes can target a project root or all projects.

## Manual E2E script

1. Start the app, relay, Mailpit, and a local cockpit daemon connected to the same account.
2. Sign in as the owner and open **Instances**.
3. Open the sharing action for an active instance.
4. Invite a non-user email with `agent` on a specific project root and confirm the message appears in Mailpit.
5. Sign up with that invited email. Email verification and the normal signup policy must still apply.
6. Open **Instances** as the invitee, accept the pending invitation, then open the shared instance.
7. Create an agent session in the shared project and send a message.
8. Sign back in as the owner and verify the grant/audit log page shows the invite and acceptance events.
9. Revoke the grant while the grantee has the shared instance open. The relay should force-disconnect the grantee client and the UI should fail the next token mint.
10. Repeat with a terminal grant from an owner account with 2FA enabled; verify the grant defaults to a 7 day expiry and the grantee terminal token contains only `terminal` scope.

## Notes

- The daemon remains the enforcement authority for project roots and session visibility.
- The app persists grant lifecycle and audit rows, and mints relay client tokens from ACTIVE, non-expired grants only.
- Revocation publishes a relay `disconnect_user` control message scoped to the instance so access changes take effect immediately.
