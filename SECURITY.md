# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately**, not via public issues
or pull requests: open a private advisory on the repository's
[Security tab → "Report a vulnerability"](../../security/advisories/new).

We aim to acknowledge reports within 72 hours.

## Supported versions

FlyCockpit ships from `main`. Only the latest code on `main` receives
security fixes; if you self-host, pull updates regularly.

## Cockpit CLI threat model

The Rust CLI (`apps/cli`) is a local coding harness with a persistent daemon.
Its security boundaries and limitations are deliberately explicit:

- Credentials are plaintext JSON in `credentials.json` under the XDG state
  directory (`$XDG_STATE_HOME/cockpit/`, normally `~/.local/state/cockpit/`).
  On Unix, the directory is kept at `0700` and the file at `0600`; writes are
  atomic and opening the store repairs broad permissions. Windows does not
  provide these Unix permission guarantees. This JSON store remains plaintext
  until the encrypted-secret-vault import lands.
- Cockpit-owned durable key roots (redaction-history, journal spool, reserved
  leak-report, sealed-state slots) live in SQLite as ChaCha20-Poly1305
  ciphertext under a wrapped DEK. The wrapping KEK is a `private_fs` owner-only
  file on every unconfigured first run. The OS keyring holds the KEK only after
  an explicit Settings promotion and a successful migrate. First-run never
  auto-selects keyring, even when a keyring probe is available. Database mode
  is weaker than keyring mode: the KEK is another local file. A copy of
  `cockpit.db` (including WAL) is ciphertext-only; decrypting it requires the
  file KEK (database mode) or a compromised keyring (keyring mode). DEK and KEK
  plaintext never persist in SQLite.
- Agent-run shell commands receive the session environment. Unconfined commands
  clear and reconstruct that environment, excluding explicit and name-matched
  sensitive variables; this is a heuristic, not an isolation boundary. Confined
  commands use the sandbox environment instead.
- The shell sandbox confines filesystem access only. It does **not** confine
  network access: sandboxed commands can still reach the internet. Confined
  commands are not separately approval-prompted because the filesystem sandbox
  is their execution boundary; unconfined execution follows the grant-or-ask
  path.
- There is no native Windows filesystem sandbox backend. Every Windows shell command is
  unconfined and follows grant-or-ask: it requires approval unless a matching session,
  project, or global grant exists. The Windows PowerShell installer does not change that
  limitation.
- On Unix, the daemon uses a `0600` socket under `$XDG_RUNTIME_DIR/cockpit/`
  when available (otherwise its private state directory), rather than `/tmp`,
  and validates the connecting peer's UID on every accepted connection.
- Cockpit has no telemetry, analytics, crash-reporting service, or self-update
  client. See the CLI [egress and local-storage disclosure](apps/cli/README.md#what-leaves-your-machine)
  for what can leave the machine.

## Security controls shipped by default

Defaults in this repository:

- pnpm 11 supply-chain hardening — release-age gate (7 d), exotic-subdep
  blocking, build-script allowlist, sha512-pinned package manager
  (`pnpm-workspace.yaml`, `package.json#packageManager`).
- SHA-pinned GitHub Actions kept current by Dependabot
  (`.github/dependabot.yml`).
- Trufflehog verified-secret scanning on every PR (`.github/workflows/pr-checks.yml`).
- Trivy HIGH/CRITICAL image scanning on every container build
  (`.github/workflows/build-image.yml`).
- `pnpm audit` on every PR with `--audit-level=high`.
- Non-root `USER node` in the production server and worker images.
- Tight Content-Security-Policy and `secureHeaders` middleware
  (`apps/server/src/index.ts`).
- Tiered rate limiting — signup (3/hour) stricter than auth (10/minute)
  (`apps/server/src/rate-limit.ts`).
- Hard production-boot guards in `packages/env/src/server.ts`:
  a weak `BETTER_AUTH_SECRET` refuses to start in production.
- Permission-checked asset URLs (authorize before returning asset URLs).

## Remote Noise binding boundary

`crates/cockpit-noise` is the sole owner of the remote
`Noise_NN_25519_ChaChaPoly_SHA256` state machine. Browser WASM, iOS/Android
UniFFI libraries, and the daemon use opaque handles into that crate; TypeScript
may frame and transport bytes but must not implement DH, Noise, record crypto,
or rekey. Production builds use fresh Snow/getrandom X25519 ephemeral keys and
the test-only deterministic-entropy feature is forbidden from release bundles.

Split transport state remains sealed until an injected authorization gate has
verified both signaling-owned durable-P256 final proofs against the exact
prologue and handshake transcript. Binding errors are stable categories and do
not contain key, proof, plaintext, transcript, or peer-controlled bytes. Handles
are removed on close and panic/poisoning maps to an internal error.

Limitations: Rust zeroizes its temporary plaintext buffers and drops opaque
state promptly, but copies may exist in Snow internals, browser linear memory,
FFI marshalling buffers, or managed Swift/Kotlin heaps until those runtimes
reclaim them. Generated bindings and WASM/native binaries are supply-chain and
memory-surface risks; their pinned inputs, tools, commands, and reproducibility
gates are recorded in `crates/cockpit-noise/PROVENANCE.json`. This is a design
and CI control record, not a claim of formal verification or third-party audit.

## Encrypted WebSocket fallback

The optional `flycockpit.remote-data.v1` gateway is an opaque carrier. The
TypeScript server validates single-use role tickets, durable certificate
signatures, committed signaling transitions, route generations, quotas, and
lease ownership, but never receives Noise keys or plaintext and never parses
logical lanes. Redis keys contain only bounded authentication digests and
opaque route coordinates; cross-replica Pub/Sub may contain one ephemeral
opaque ciphertext record and is not delivery acknowledgement or persistence.

Endpoint delivery, cumulative ACK/retry, duplicate detection, reordering, and
rekey remain in the shared Rust core. Redis, Pub/Sub, socket writes, and gateway
command completion cannot open application state or acknowledge endpoint
delivery. Any Redis/subscription/lease failure closes the affected transport;
there is no process-local authority or plaintext fallback. Operational logs
must use reason/size/route-class buckets only and must not include ticket,
certificate, proof, network, attachment, route, ciphertext, or application
material.

See `AGENTS.md` § "Safety" for the full list of guardrails a coding agent
must respect when working in this repo.

## Notes for self-hosted forks

The controls above work on **any repository**, public or private, with no
GitHub Advanced Security (GHAS) subscription. Two additional scanners are
free on public repositories but require GHAS on private ones, so private
self-hosted forks may want to budget for them:

- CodeQL (generic JS/TS SAST).
- GitHub Dependency Review Action.
