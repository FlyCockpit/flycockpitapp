# Local daemon same-user boundary

**Decision:** The operating-system user account is Cockpit's local daemon
security boundary. A process running as the user can control the daemon; that
is the OS boundary.

This decision supersedes the proposed Windows contract in #398 that would have
treated agent children as less trusted than other processes running under the
same account. Child-denial measures may still reduce accidental access and
simple interference, but they are defense in depth, not a security boundary.

## Evidence

Windows object access checks use the caller's token. Restricted tokens, lower
integrity levels, and AppContainers intersect authority across every object;
granting an agent child the existing ability to run arbitrary executables and
write arbitrary user files also restores routes to same-user control planes.
A process-capable child can also escape Job- or marker-based schemes through
documented process brokers such as WMI, Task Scheduler, or DCOM. A same-user
process can duplicate and impersonate another same-user process's token without
`SeImpersonatePrivilege`, and further `CreateRestrictedToken` calls can
intersect away a proposed marker restricting SID. Relabeling objects requires
`SeRelabelPrivilege`, which normal desktop accounts do not have.

The full research report,
`fable-sep-15-audit/reports/research/report-research-windows-isolation.md`
§§1–4, is not distributed in this repository. Its evidence summary, citations,
and the owner's decision are recorded in
[#438](https://github.com/FlyCockpit/flycockpitapp/issues/438).

This model is consistent with mainstream same-user desktop daemons: local
processes running as the account are trusted as that account. Strong separation
requires a distinct OS account, service identity, virtual machine, or similarly
independent security principal and would change Cockpit's subprocess contract.

## What Cockpit promises

- Unix daemon sockets live under an owner-only `0700` directory, use a `0600`
  socket node, and validate the accepted peer's UID. The
  `ExchangeLocalPeerCredential` request issues role-scoped local credentials
  only after that OS peer check; the UID check is the Unix boundary.
- Windows daemon pipes use an owner-only protected DACL, a finite instance
  limit, `PIPE_REJECT_REMOTE_CLIENTS`, non-inheritable server handles, and
  `FILE_FLAG_FIRST_PIPE_INSTANCE` for the random pipe named by the owner-only
  identity file. Non-owner principals receive no
  `FILE_CREATE_PIPE_INSTANCE` right. The server and client also verify the
  connected process belongs to the current user.
- Discovery files, socket directories, socket nodes, and pipe names are
  hardened against cross-user access, replacement, and remote named-pipe
  connections.

These controls are enforced even though some overlap. They narrow exposure to
the selected OS account and provide defense in depth against mistakes and
ambient cross-user access.

## What Cockpit does not promise

- Cockpit does not isolate an agent child from the daemon, worker control
  planes, credentials, files, or processes that the same OS user can access.
- Job Objects, random pipe names, restricted tokens, peer process IDs, local
  credential roles, sandbox markers, and process ancestry do not turn a
  same-user process into a separate security principal.
- The Windows hardening does not prevent a malicious same-user process from
  acting with the account's authority, including replacing an identity file or
  interfering with same-user processes after gaining the necessary account
  access.
- Filesystem sandboxing and command approval are separate product controls.
  Their presence does not strengthen the local daemon boundary beyond the OS
  account.

Run mutually untrusted workloads under separate OS or machine identities. Do
not rely on Cockpit's child-denial defense in depth as containment between
processes running as one user.
