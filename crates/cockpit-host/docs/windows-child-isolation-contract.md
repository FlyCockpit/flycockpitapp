# Windows agent-child isolation conformance gate

**Issue:** #398
**Status:** **Blocked — no production activation**
**Checked:** 2026-09-12

This is an implementation-facing platform contract and a stop record, not a
runtime isolation backend. `cockpit-host` must not expose a Windows agent-child
launcher, and no supervisor or worker launch path may depend on this document
until every blocked item below is resolved by a real Windows conformance run.

## Result

No documented, normal-desktop-account policy currently both denies an
agent-controlled child access to Cockpit's supervisor/worker endpoints and
preserves all currently supported Windows agent subprocess routes. The proposed
restricted-token (`WinRestrictedCodeSid`) sketch correctly denies protected
objects when they omit its restricting SID, but it also denies every resource
that does not explicitly grant that SID. Cockpit has no finite, approved
resource set for the arbitrary approved and `/sandbox off` routes. Granting
`RC` broadly would be an unreviewed replacement for their existing authority,
not an implementation of the current product contract.

The only valid outcome for #398 is therefore **Blocked**. #399 remains deferred.
An unavailable Windows fixture is also a blocked result, never supervisor
activation evidence.

This stop result is based on the documented access-check semantics and the
current route inventory below. It is not a claim that a Windows machine ran a
restricted child. In particular, a test that proves only that RC cannot open
the two protected endpoints would leave every unrestricted resource class
untested and must not be reported as conformance.

## Native facts and rejected restricted-token candidate

Microsoft documents that a restricted token can delete privileges, make SIDs
deny-only, and carry restricting SIDs; the system grants access only when both
the ordinary SID check and the restricting-SID check allow it. A restricted
version of the caller's primary token can be passed to `CreateProcessAsUserW`
without `SeAssignPrimaryTokenPrivilege`.

- [Restricted Tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
- [CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)

The rejected candidate would have been constructed exactly as follows. This is
recorded to make the failure reproducible; it is **not** selected for product
use.

1. Open the current process primary token with `TOKEN_QUERY | TOKEN_DUPLICATE |
   TOKEN_ASSIGN_PRIMARY`. `CreateRestrictedToken` requires `TOKEN_DUPLICATE` on
   its source, preserves the source token type, and returns a handle with the
   source handle's access. `CreateProcessAsUserW` requires `TOKEN_QUERY |
   TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY` on its token handle.
2. Call `CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE`; do not use
   `SANDBOX_INERT`; use no deny-only SID list; supply `S-1-5-12`
   (`WinRestrictedCodeSid`, Restricted Code) as the sole restricting SID.
   `DISABLE_MAX_PRIVILEGE` leaves only `SeChangeNotifyPrivilege`; it does not
   itself deny access. `CreateRestrictedToken` intersects a new restricting
   list with an already restricted source token's list. Consequently a
   marker-plus-user restricting-SID workaround is prohibited: a later
   restriction can intersect the marker away.
3. Create the process with that primary token, an explicit executable path,
   `CREATE_SUSPENDED`, and the selected inheritance mode below. Do not use an
   alternate-account launch API: requiring another account, an OS user, or an
   installation privilege is a blocker for this product.

`CreateRestrictedToken` documents the intersection behavior and the
`TOKEN_DUPLICATE` source-handle requirement. The [well-known SID
table](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
identifies `S-1-5-12` as Restricted Code. The result makes an RC-only token
unable to use an object without an RC allow ACE. It is that necessary grant,
not a Job or a private pipe name, that makes this candidate infeasible for the
current resource model.

Restricted-token applications also need a separate desktop/window station to
avoid window-message attacks on unrestricted applications. This is a separate
mechanic, not an optional hardening flag. The current product has no defined
desktop/window-station policy for its interactive shell/PTY routes, which is a
second blocker.

## Endpoint templates required if a later product decision supplies a finite model

These are validation templates only. `{USER_SID}` means the ordinary,
unconfined current-user client principal. `SY` is LocalSystem. There is no
Cockpit Windows service identity in the current topology; no other service SID
may be added merely to make a test pass. `0x00100003` is exactly
`SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA`; it deliberately excludes
`FILE_APPEND_DATA` / `FILE_CREATE_PIPE_INSTANCE`.

| Object | Protected SDDL template | Rule |
| --- | --- | --- |
| Supervisor control pipe | `D:P(A;;0x00100003;;;{USER_SID})(A;;0x00100003;;;SY)` | `{USER_SID}` and SYSTEM may open a client endpoint only with `FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE` for an admission exchange. The supervisor owns its already-created server handle. |
| Admitted worker pipe | `D:P(A;;0x00100003;;;{USER_SID})(A;;0x00100003;;;SY)` | The same principal receives the post-admission direct-worker exchange with exactly `FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE`; there is no generic write ACE. |
| Supervisor process object | `D:P(A;;0x00100000;;;{USER_SID})(A;;0x00100000;;;SY)` | Only `SYNCHRONIZE` is permitted. It grants none of `PROCESS_DUP_HANDLE`, `PROCESS_CREATE_PROCESS`, VM access, `WRITE_DAC`, or `WRITE_OWNER`. The trusted supervisor retains its lifecycle handle. |
| Worker process object | `D:P(A;;0x00100000;;;{USER_SID})(A;;0x00100000;;;SY)` | Same denial rule; the trusted worker/supervisor retains needed lifecycle/private-control handles. |

[Named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
documents that both server and client access are checked against the pipe DACL,
and that `FILE_GENERIC_WRITE` confers `FILE_CREATE_PIPE_INSTANCE` because
`FILE_APPEND_DATA` and that right share a value. Therefore these templates use
individual rights, not `GW`, `GA`, `FILE_GENERIC_WRITE`, or a generic service
ACE. [Process security and access
rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
defines the process-object rights that the templates intentionally omit.

The existing `OwnerOnlyPipeSecurity` and both ordinary Cockpit named-pipe
client open helpers use this same `0x00100003` contract. They call
`CreateFileW` with `FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE`, rather
than `OpenOptions` or Tokio `ClientOptions`, because those helpers request
generic read/write and generic write would not match (or be safe under) this
template. This is a correction to the current ordinary-client control-pipe
contract, not supervisor activation.

For a restricted-token policy, neither protected pipe nor protected process
template contains an RC ACE. The ordinary user SID would pass the first token
check, but RC would fail the second. A later, non-token policy must provide an
equivalent protected-object denial rule and prove it in the fixture; it may not
reuse these templates by assertion alone.

## Exact inheritance, containment, and release sequence in the test-only fixture

The test-only temporary-object fixture below follows this sequence. It is not
wired to a production launch path.

1. Create and ACL a unique alternate window station and desktop before process
   creation. The window-station DACL and desktop DACL must admit only the
   trusted launcher identities plus the selected child principal's documented
   minimum window-station/desktop rights; for an RC-token experiment that
   means the separate RC access check must also be represented. The fixture
   must treat inability to construct those temporary objects under the current
   test-runner account as typed `Unavailable`, never fall back to `WinSta0` or
   `Default`. Form the `window-station\\desktop` string while it is live and set
   `STARTUPINFOW.lpDesktop` to its mutable, NUL-terminated buffer.
2. Create the security descriptors, pipes, Job, token, and any temporary
   child-side stdio/PTY duplicates before process creation. The launcher keeps
   the supervisor, worker, control-pipe, worker-pipe, token, Job, window
   station, desktop, and parent I/O ends. Retained launcher handles are
   non-inheritable; step 4 creates only the listed child duplicates as
   inheritable.
3. With no child-visible handles, call `CreateProcessAsUserW` with
   `bInheritHandles = FALSE`, no `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, and
   `CREATE_SUSPENDED`, passing the `STARTUPINFOW` whose `lpDesktop` identifies
   the alternate desktop. This is the required zero-handle mode.
4. For a supported stdio/PTY route, first duplicate only the child endpoints
   as inheritable. Build `STARTUPINFOEXW` and set
   `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` to exactly those endpoints; call
   `CreateProcessAsUserW` with `bInheritHandles = TRUE`,
   `EXTENDED_STARTUPINFO_PRESENT`, and `CREATE_SUSPENDED`. The documented
   handle-list attribute is valid only with `TRUE`, and every listed handle
   must already be inheritable. The `STARTUPINFOEXW.StartupInfo.lpDesktop` is
   the same alternate desktop. No Cockpit, token, process, Job, control-pipe,
   worker-pipe, window-station, or desktop handle is listed. Close temporary
   launcher duplicates before target resume; retain only trusted parent I/O
   ends.
5. While the initial thread is suspended, verify that `GetProcessId(hProcess)`
   equals `PROCESS_INFORMATION.dwProcessId`, verify the canonical image with
   `QueryFullProcessImageNameW`, then open **the child process token** with
   `TOKEN_QUERY` and inspect `GetTokenInformation(TokenRestrictedSids)` for the
   exact restricted-SID state expected of that child. Do not infer child token
   identity from the source or pre-launch token handle. Only then associate the
   process with the pre-created Job by calling
   `AssignProcessToJobObject` and prove membership with `IsProcessInJob`. A Job
   is a lifecycle fence only; it is not evidence of IPC or handle denial. Hold
   the Job/process/thread handles in the trusted launcher until the target has
   either been resumed and reaped or terminated on failure.
6. Then call
   `ResumeThread` on the returned primary-thread handle only after the
   descriptor, Job, identity, registration, and handle-closure checks have
   succeeded. Close the initial thread handle after resume; close the token
   after child-token inspection; keep the Job, lifecycle process,
   window-station, and desktop handles until quiescence.

Microsoft documents that `CREATE_SUSPENDED` prevents the initial thread from
running until `ResumeThread`, that `AssignProcessToJobObject` associates a
process with an existing Job, and that a handle list is an inheritance list
only when `bInheritHandles` is true:

- [Process creation flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)
- [AssignProcessToJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject)
- [UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)

The existing `ProcessTreeGuard` follows only the Job/suspended ordering. Its
Job neither blocks a named-pipe open nor process-handle access nor inherited
handles, so it cannot be cited as isolation conformance.

The process identity calls above are the required fixture evidence, rather
than an assertion inferred from a successful Job assignment. Their documented
access requirements are part of [Process security and access
rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
and [IsProcessInJob](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-isprocessinjob).

## Current Windows subprocess capability matrix

The source inventory in #398 is the evidence for these routes. “Unbounded”
means the product deliberately permits a command-selected executable/runtime,
its dependencies, and the caller-approved or unconfined filesystem/network
behavior. It is not a request to choose a Windows “full-access resource set.”
`BwrapNetworkMode::FullAccess` is Unix network sharing; `/sandbox off` is an
unconfined shell selection; native per-resource grant-or-ask remains separate.

| Current agent-child route | Required current Windows behavior | Finite RC/resource allow rule available? | Result |
| --- | --- | --- | --- |
| Foreground shell; background/adopted shell | Sandboxed or `/sandbox off` shell, workspace/session scratch, temp, command/runtime dependencies, configured network, approval result | No: unconfined command and dependencies are unbounded | Blocker: filesystem, executable/runtime, temp, configured network |
| Custom tools; skill `!` interpolation | Configured or skill command through shell, same approval/confinement branches | No | Blocker: configured executable/runtime and files |
| Worker-owned terminal child | Interactive shell plus PTY/stdin/stdout/stderr and the same command authority | No | Blocker: PTY handle route and unbounded command resources |
| Agent hooks | Configured executable/argv, retained workspace, approved effect, detached lifecycle | No | Blocker: configured executable/runtime and workspace/scratch |
| Harness invocation; auth/model probes | Configured executable/argv and probe dependencies when agent-triggered | No | Blocker: configured executable/runtime and configured network |
| MCP stdio servers | Configured server command, pipe stdio, workspace/config/runtime dependencies | No | Blocker: stdio plus executable/runtime/files |
| LSP servers and command actions | Configured server/recipe, workspace, diagnostics I/O | No | Blocker: configured executable/runtime and workspace |
| Command-resource introspection | Agent-derived developer binary and parsed arguments | No | Blocker: selected binary and its dependencies |
| Container runtime client | Docker/Podman client, configured network, backend-owned workload identity | No | Blocker: runtime socket/config and backend resource model |
| Media/audio/video runners | Selected argv runtime, media input/output/temp | No | Blocker: selected runtime and files/temp |
| Native computer helpers | Fixed host utilities, display/input/screenshot resources | No documented policy chosen | Blocker: desktop/window station and host utility dependencies |
| Git/GitHub/worktree helpers | Git/gh/validation wrapper, workspace, credentials configured by their owner path | No | Blocker: executable/runtime, workspace, owner-mediated resources |

This matrix is finite as an inventory of every currently supported route, but
the required authority inside several rows is intentionally unbounded. There
is no evidence-backed finite allow set for approved paths, session/workspace
scratch, executable/runtime dependencies, temp behavior, PTY/stdio, configured
network behavior, and native resource approval across all rows. A later product
prompt may deliberately narrow a route and then define its resources; this
prerequisite may not narrow it silently.

### Source evidence for the route inventory

The matrix is intentionally a route inventory rather than a claim of a
filesystem sandbox. These are the production seams reviewed in this checkout;
the static contract ratchet keeps every row represented until a later product
decision supplies a finite model.

| Matrix row | Production source evidence |
| --- | --- |
| Foreground and background shells | `crates/cockpit-core/src/tools/bash/mod.rs`; `crates/cockpit-core/src/engine/schedule/background.rs` |
| Custom tools and skill interpolation | `crates/cockpit-core/src/tools/custom.rs`; `crates/cockpit-core/src/skills/mod.rs` |
| Worker-owned terminal | `apps/cli/src/terminal_host.rs` |
| Agent hooks | `crates/cockpit-core/src/engine/agent/hooks.rs` |
| Harness invocation and probes | `crates/cockpit-core/src/harness/spawn.rs`; `crates/cockpit-core/src/harness/preflight.rs`; `crates/cockpit-core/src/harness/models.rs` |
| MCP stdio | `crates/cockpit-core/src/mcp/transport/stdio.rs` |
| LSP and command actions | `crates/cockpit-core/src/daemon/lsp.rs`; `crates/cockpit-core/src/tools/lsp.rs` |
| Command-resource introspection | `crates/cockpit-core/src/tools/command_resource_profiles/mod.rs` |
| Container runtime client | `crates/cockpit-core/src/container/mod.rs` |
| Media runners | `crates/cockpit-core/src/tools/audio_video/runner.rs`; `crates/cockpit-core/src/media_storage.rs` |
| Native computer helpers | `crates/cockpit-core/src/computer/mod.rs`; `crates/cockpit-core/src/computer/macos_backend.rs` |
| Git/GitHub/worktree helpers | `crates/cockpit-core/src/git/mod.rs`; `crates/cockpit-core/src/tools/intel/change_impact.rs`; `crates/cockpit-core/src/tools/worktree_orchestrate.rs` |

## Test-only temporary-object runner and evidence rule

`crates/cockpit-host/tests/windows_child_isolation_stop_record.rs` is a
test-only temporary-object fixture runner and evidence fixture. It does not
activate a production launch path. Run it on any host
with:

```text
cargo test -p cockpit-host --test windows_child_isolation_stop_record -- --nocapture
```

On a non-Windows host it reports the typed `Unavailable { WindowsHost }`
state. On Windows it first provisions and ACLs a unique alternate window
station and desktop. A real OS/API failure in required temporary-object, token,
launch, attribute-list, inspection, or Job setup is a typed `Unavailable`;
denial, DACL, identity, image, and inheritance assertion mismatches fail the
fixture. It then creates two unique temporary named pipes under the
existing test-runner account with the ordinary-client descriptor above, spawns
a second test-runner process, and measures its control admission and
direct-worker exchanges using exactly `FILE_READ_DATA | FILE_WRITE_DATA |
SYNCHRONIZE`. A successful temporary ordinary-client exchange is only an
endpoint observation. The runner then records `Blocked` with the unbounded
resource classes above, because endpoint evidence alone cannot activate a
production policy while executable/runtime, workspace, temp, PTY,
configured-network, and native-approval behavior have no finite allow rule.
It then creates two disposable ordinary test-runner holder processes as the
actual supervisor and worker process objects, and applies the protected
current-user-only `SYNCHRONIZE` DACL to those holders. It never changes the
test runner's process DACL. A separate disposable duplication-source holder
opens a worker handle before that worker DACL is tightened; its own protected
DACL grants the restricted child only `SYNCHRONIZE`. This gives the child a
real, non-null source-process handle and a known valid worker-handle value,
while `DuplicateHandle` is denied because that source handle lacks
`PROCESS_DUP_HANDLE`. The fixture also verifies a direct denied `OpenProcess`
for every forbidden supervisor/worker right: `PROCESS_DUP_HANDLE`,
`PROCESS_CREATE_PROCESS`, `PROCESS_VM_OPERATION`, `PROCESS_VM_READ`,
`PROCESS_VM_WRITE`, `WRITE_DAC`, and `WRITE_OWNER`.

It then creates two restricted-token children through the suspended test-only
launch path: one with `bInheritHandles = FALSE` and no handle list, and one
with `bInheritHandles = TRUE` and an exact three-endpoint standard-I/O handle
list. Both receive the alternate desktop through `lpDesktop`; before either
resume, the fixture verifies its token and image, protects its process DACL,
and assigns/checks Job membership. A denial or inheritance mismatch is a
fixture failure. Neither result activates a supervisor.

The temporary-object runner records each of:

1. ordinary-current-user supervisor admission and admitted direct-worker
   exchange with exactly the client pipe rights;
2. child denial for both pipe opens and pipe-instance creation;
3. child denial for `PROCESS_DUP_HANDLE`, `PROCESS_CREATE_PROCESS`,
   `PROCESS_VM_OPERATION`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `WRITE_DAC`,
   `WRITE_OWNER`, and an actual `DuplicateHandle` call using a non-null,
   deliberately under-righted source-process handle that owns a known protected
   worker handle;
4. zero-handle and exact standard-I/O inheritance modes, with no Cockpit
   handle inherited.

All fixture pipe accepts, pipe reads/writes, and child observations have a
finite timeout. On timeout the launcher terminates and reaps the affected
child before closing its kill-on-close Job or remaining handles.

It reports typed `Unavailable` only for a real required Windows setup API
failure, uses no
daemon, credentials, OS-user creation, privileged installation, persistent ACL
change, or production launch path, and preserve a typed pass/denied/unavailable
observation for every assertion. A Job-assignment success or a unit fake does
not activate the production policy.
