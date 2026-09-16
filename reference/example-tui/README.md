# excoc

Reference CLI for FlyCockpit's **attach-or-spawn ephemeral daemon**.

`excoc` is a teaching slice of `flycockpitapp`'s local daemon lifecycle, not a
product. The default command attaches to a shared daemon, starting one if this
is the first client. The daemon counts elapsed time from the moment it opened.
Later clients attach to that same clock. When the last client disconnects, the
daemon exits.

```text
terminal A                    daemon                     terminal B
──────────                    ──────                     ──────────
excoc ──spawn / attach──►  bind socket
       ◄── hello+ticks ──  opened_at = now
                                                     excoc ──attach──►
       ◄──────────── shared uptime ticks ────────────►
Ctrl-C (A disconnects)     still running (B attached)
                                                     Ctrl-C
                           last client gone → exit
```

## Run

```sh
cargo run
```

In a second terminal, with the same `EXCOC_HOME` if you overrode it:

```sh
cargo run
```

Both print `uptime Ns  clients K` from the same open time. Leave both with
Ctrl-C; the daemon stops after the last disconnect.

```sh
cargo run -- status            # hello-only probe; does not keep the daemon alive
cargo run -- reset             # hand off to a fresh daemon without losing uptime
cargo run -- onboard           # P-51 fly-in, then the add-provider form
cargo run -- onboard --skip    # provider form only
cargo run -- tui               # simulated agentic chat TUI (UX demo)
cargo test
```

## Constant uptime across a daemon handoff

`excoc reset` demonstrates a zero-downtime daemon swap: the running daemon
spawns a successor, hands it the open time, atomically moves it onto the shared
socket, tells attached clients to reconnect, then drains and exits. Uptime
never resets — only the pid changes.

Watch it live. In terminal A:

```sh
cargo run            # uptime climbs: 6s, 7s, 8s …
```

In terminal B (same `EXCOC_HOME`):

```sh
cargo run -- reset   # reset: daemon 41010 -> 41337 (uptime 8s continuous, clients 1)
```

Terminal A blips through `reconnecting`, reattaches to the new pid, and keeps
counting `9s, 10s, …` from the *original* open time.

How it stays gapless:

- **Inherited clock.** The successor boots with the predecessor's
  `opened_at_unix_ms`, so `elapsed_ms` is continuous. This is the only state the
  handoff carries.
- **Staging socket + atomic rename.** The successor first binds
  `excoc.sock.next` and reserves `excoc.pid.next`, so `reserve_pid_file` does
  not bail on the still-live predecessor. On `Promote` it renames the staging
  pair onto the canonical paths. `rename(2)` is atomic on one filesystem, so the
  canonical socket always resolves to a live listener — there is never a window
  where `attach_or_spawn` could spawn a rogue third daemon.
- **Redirect, then reconnect.** The predecessor broadcasts a `Reconnect` control
  frame; each client drops the connection and re-attaches, landing on the
  successor and re-negotiating hello. Because every client gets a fresh hello,
  a future self-upgrade may bump the protocol version. (The alternative —
  passing the listener fd via `SCM_RIGHTS` — is more seamless but hands
  already-open streams to a possibly newer binary, so this reference chooses
  reconnect.)
- **Confirm before commit.** The predecessor health-checks the successor
  (matching hello + inherited open time) before promoting. If the successor
  fails to boot, the handoff aborts, the successor is terminated, and the
  predecessor keeps serving untouched.
- **Drain, then exit.** After promotion the predecessor waits for its clients to
  reconnect away (bounded by a drain deadline), then exits. It is auto-reaped
  (SIGCHLD is ignored at the spawn site) so it never lingers as a zombie under
  the client that first started it.

**Future self-upgrade.** The only change needed for "Cockpit downloads a new
version of itself" is to launch the successor from the freshly downloaded binary
instead of the current one — every other step is identical.

## Supervised alternative: a stable wrapper owns the socket

`excoc reset` (above) is a **peer self-handoff**: the running daemon spawns and
promotes its own successor. The supervised design is the other shape — a
**stable wrapper (`excoc supervise`) owns the endpoint for its whole life while
an upgradable worker (`excoc worker`) does the work behind it**. This is the
"frozen launcher / rolling worker" pattern, the portable cousin of systemd
socket activation.

```text
                 excoc.sup.sock  (bound once, held for life)
excoc up ──────────────┐             ┌───────── worker gen N (excoc worker)
                       ▼             ▼            • inherits the listen fd (fd 3)
                 ┌───────────────────────┐        • inherits opened_at (the clock)
                 │  supervisor            │        • serves clients, ticks uptime
                 │  (excoc supervise)     │        • drains on SIGTERM
                 │  owns socket + pid     │──spawn─┘
                 │  owns opened_at        │
                 │  excoc.sup.ctl (admin) │◄── excoc upgrade / excoc sup-status
                 └───────────────────────┘
```

Watch it live. In terminal A:

```sh
cargo run -- up          # connected pid=… worker_v=1 gen=1 … then uptime climbs
```

In terminal B (same `EXCOC_HOME`):

```sh
cargo run -- upgrade     # upgrade: worker v1->v2 (gen 2) pid 41010 -> 41337, uptime 8s continuous
cargo run -- sup-status  # running  worker_pid=41337  v2  gen=2  uptime=9s
```

Terminal A blips through `reconnecting`, lands on the **v2** worker with a new
pid, and keeps counting from the *original* open time. Kill the worker
(`kill -9 <worker_pid>`) and the supervisor respawns it (a new generation, same
version, same clock) with no action from any client.

Why this is different from `reset`:

- **The socket never closes.** The supervisor binds `excoc.sup.sock` once and
  hands the *listening fd itself* down to each worker (fd 3, exactly like
  systemd's `LISTEN_FDS`). Across an upgrade or a crash the endpoint stays open,
  so new connections queue in the kernel backlog instead of being refused —
  there is no staging socket and no atomic rename, because nothing is ever
  swapped underneath clients.
- **Readiness is explicit, not raced.** A freshly spawned worker signals ready
  by writing one byte to an inherited pipe (fd 4, sd_notify-style). The
  supervisor waits for that byte before draining the previous generation, so it
  never promotes a worker that has not actually bound in.
- **Crash recovery is client-independent.** The supervisor polls its worker and
  respawns it on death. Background work survives a worker crash even when no TUI
  is attached — the case the reset design cannot cover, since there `reset` is
  driven by a client.
- **The frozen boundary is small and separate.** `excoc upgrade` /
  `excoc sup-status` talk to the supervisor over `excoc.sup.ctl` with a tiny
  admin protocol, deliberately kept apart from the public NDJSON proto. The
  wrapper is the piece meant to "never change once it is right"; a real system
  would add a re-exec escape hatch (à la `systemctl daemon-reexec`) so "never"
  is not load-bearing.

What it still does **not** do, on purpose:

- **Open connections still blip.** The *socket* survives, but a client already
  attached to the draining or killed worker must reconnect — its connection fd
  belonged to that process. The only state carried across is the open clock,
  inherited by env; real session state would live in a durable store (SQLite in
  Cockpit), which is what makes reconnect lossless. This is the honest limit of
  a wrapper: it preserves the *listener*, not live *connections*.
- **The supervisor is persistent here.** Reaping it when the worker reports zero
  lifetime clients is a natural extension (mirror
  `ephemeral_last_client_reaper`), but it must be suppressed during a roll or
  respawn to avoid tearing down in the reconnect gap. Left out so the demo
  stays focused on socket ownership, rolling upgrade, and crash recovery.

The two designs share `proto`, `client`, `host`, and `paths`; run whichever
mode you like in a given `EXCOC_HOME`. The classic daemon reports
`worker_v=0 gen=0`; a supervised worker reports the supervisor's rolling
counters.

## Mapping onto flycockpitapp

| this crate    | flycockpitapp analog |
|---------------|----------------------|
| `host`        | `crates/cockpit-host` — private dirs, pid claim, detached spawn |
| `paths`       | `DaemonPaths` — canonical socket + pid file |
| `proto`       | `crates/cockpit-proto` — NDJSON envelopes, exact version match |
| `client`      | `crates/cockpit-client` — connect, hello, subscribe; `Control` for one-shot verbs |
| `daemon`      | `cockpit-core` accept loop, `ephemeral_last_client_reaper`, and the reset/promote handoff |
| `lifecycle`   | `probe_or_spawn` — attach if running, else spawn |
| `supervisor`  | the "stable wrapper / rolling worker" alternative — socket-activation handoff, sd_notify readiness, crash respawn (an optional service/always-on shape layered on the same daemon) |

Patterns copied on purpose:

- The same binary is the client and the daemon (`excoc daemon` is the child).
- Discover, then attach; only spawn when nothing is hellos on the socket.
- Bind the socket only after boot (`opened_at` is recorded first). Clients that
  see a socket expect a hello on the first line.
- Hello-only probes (`excoc status`) do not count toward lifetime. The reaper
  waits until at least one `Subscribe` has happened, then tears down when the
  count returns to zero. No idle timeout.
- Pid file is reserved **before** unlinking the socket, so a losing starter
  cannot steal the winner's endpoint.
- The child is started in its own process group so Ctrl-C on a client does not
  signal the daemon.

`excoc onboard` is a first TUI slice: the P-51 from `cockpit-core::banner`
flies in from off-screen left, ASCII clouds parallax past it, and the
propeller tops blink through a slow rotation. Any key after the continue
prompt starts the onboarding wizard. `excoc onboard --skip` jumps straight
to the wizard. It does **not** spawn the daemon — that is the point of this
crate's first lesson.

Every screen is fully mouse-drivable as well as keyboard-drivable: a top-left
**‹ Back** button, clickable/scrollable lists, and a right-aligned action bar on
the help row carrying the primary action (**Continue** / **Choose** / **Save** /
**Retry** / **Done** / **Create agent**) plus any secondaries (**Reveal**, **Use
env var**, **Add subagent**, …). Text fields can be clicked to focus, and rows
that select-then-confirm (secrets, the provider list) also confirm on a second
click. Nothing in the flow requires the keyboard except typing itself.

The wizard walks these steps, each with a back button:

1. **Secure your secrets** — pick where the wrapping key lives (OS keyring,
   a password, or unencrypted).
2. **Let's add a provider** — a searchable, scrollable catalog of the
   providers Cockpit can add.
3. **Authenticate** — the screen follows the provider's credential kind.
   OAuth providers acknowledge the subscription risk, then either show a
   device code (`codex-oauth`, à la `auth.openai.com/codex/device`) or take a
   pasted browser callback (`grok-oauth`). API-key providers get a masked key
   field, offer a detected `$ENV_VAR`, and ask `openai-compatible` for a base
   URL.
4. **Verify** — probe `GET {base_url}/models` and show either the model list
   or a categorized error (rejected credential, missing endpoint, transport
   failure, unparsable body). A verified provider can loop back to step 2 to
   add another, or finish and move on to agent creation.

The `/models` probe runs off the UI thread (a worker thread here, the daemon
in the product) while a spinner animates. **API-key providers hit the network
for real** — enter a live key and you will see the provider's actual models or
its actual error. **OAuth logins are simulated** (this reference cannot
complete real third-party OAuth), so their verification returns a
representative catalog rather than a live call.

### Create your first agent

Once at least one provider is verified, onboarding builds a catalog from every
model it saw and runs a nested **agent-creation** wizard. This is a sketch of
`cockpit-core`'s agent definition surface (`AgentDef` plus launch-vNext
`delegation` / `verification` / `capabilities`); no agent is actually spawned.
Its screens, each with the same back/forward and mouse conventions:

1. **Name** — a blank name defaults to `pilot`.
2. **Models** — tick which models the agent may use and star one as the
   default. The default always stays an enabled model.
3. **Trust** — *untrusted* (default) redacts secrets and sealed values from
   the model; *trusted* sees them raw. Delegation to cloud models always routes
   through a redacted, untrusted child.
4. **Optimizations** — auto-prune (off), interactive subagents (on; they take
   the foreground and don't count against recursion depth), max subagent
   recursion, tool steering (terse/verbose), and goal-completion skeptics.
5. **Self-verify** (from optimizations) — configured independently per surface
   (writes/edits, commands, Monty). The surface list quick-dials the agent's own
   model with `←/→` (cheap: the cache stays warm); space opens a verifier panel
   where the agent's own model is the first row — labelled *reuses cache* —
   alongside every catalog model, each with a copy count and clickable `[−]`/`[+]`
   steppers. A surface is `off` only when every count is zero. The runtime sends
   one copy first and the rest after it lands, so extra copies re-use the warmed
   cache.
6. **Tools** — the whole catalog, ordered required → suggested → not suggested.
   Required tools (`read` / `write` / `shell`) are always on. Suggested tools
   include searching code, fetching URLs and web search, a task list,
   delegating to subagents (synchronously or in the background — see `task`),
   timers, background commands, asking the user (`question`), LSP diagnostics,
   and Monty. Not-suggested tools (`escalate`, `computer_use`, audio
   transcription) are off by default. Tools that need a model (e.g. a vision
   model to describe images) can't be enabled until one is chosen, and the
   choice shows inline.
7. **Subagents** — helpers the agent can delegate to, each with its own name,
   trust, models, and tools (reusing the same pickers). Every agent is
   pre-seeded with a suggested untrusted **runner** subagent that can read/edit
   code, search, run commands, use timers and background commands, and delegate
   further (bounded by the recursion depth from step 4). Keep it, edit it, or
   remove it — and this is also where you'd define a small **trusted** subagent
   whose only job is to set up a sealed value while the primary agent stays
   untrusted.
8. **Review** — the whole draft, read back; Enter creates it.

Everything after onboarding is echoed to stdout: the encryption choice, each
added provider, and the agent (name, trust, models, optimizations, self-verify,
granted tool ids, and subagents).

What this example still skips: real OAuth token exchange, actually spawning or
running the agent, protocol receipts against PID reuse, in-process transports,
and persistent (non-ephemeral) lifetime.

## `excoc tui` — the agentic chat UX

`excoc tui` is a **simulated** agentic chat client, a sketch of what
`flycockpitapp`'s TUI could feel like. Like `onboard` it touches no daemon and
calls no model — every response is scripted (`src/tui/scenario.rs`) — so it can
be handed to agents as a reference for the interaction design rather than the
plumbing. It mirrors the web console prototype under
`../agentic-chat-ui/apps/web`.

This slice implements these interactions and nothing else:

1. **Sticky user messages.** As a turn's answer scrolls, the request that
   started it stays pinned to the top of the transcript, so you never lose the
   question you asked. This is always on — there is no toggle. Every user and
   agent message carries a dim local `HH:MM` stamp, plus clickable **[Pin]** and
   **[Fork]** actions. Pin toggles a mark on that message (`[Unpin]` while it
   is pinned). Fork opens a new sidebar session that copies history through
   that message so you can take the conversation in another direction.
   **Click the sticky header** to step back a turn: the transcript scrolls up so
   the current turn comes into view and the *previous* turn becomes the sticky,
   so repeated clicks walk backwards through the conversation. The transcript
   **follows the tail** as the agent streams; scrolling up stops following and
   raises a **↓ Latest** chip in the bottom-right — click it to jump to the
   newest output and resume following.
2. **A hidable sidebar** of sessions, each with a red / yellow / green status
   dot — waiting on you, working, done (grey when idle) — and the datetime of
   its last activity. Hover a row for **[Pin]** / **[Unpin]**, **[Archive]**,
   and a wastebasket chip (U+1F5D1, instead of Delete). Pinned sessions stay at
   the top of the list, marked with a ★.
   **[Hide]** sits on the right of the sidebar header; when the sidebar is
   closed, **[Show]** sits in the terminal's top-left corner. **⌃B** still
   toggles it. Switch sessions with **Alt+↑/↓** or a click. When there are more
   sessions than fit, the list scrolls (wheel over the sidebar) and shows a
   scrollbar; changing session keeps the active row in view.
3. **Model and effort selection** from pills that sit *on the input box's bottom
   border* — `╰[Agent: Cockpit]─[GPT-5 Codex]─[Effort: Balanced]─[sandbox: on]────[Send]╯`
   on a wide row, collapsing to `╰[Cockpit]─[GPT-5 Codex]─[Balanced]─[on]────[Send]╯`
   when space is tight. Click a pill to pick an agent, model, effort, or sandbox
   mode. **⌃P** opens a
   two-level model picker (provider first, then that provider's models); **Esc**
   steps back from the model list to the provider list. **⌃E** opens the effort
   picker (Fast / Balanced / Thorough, which visibly changes pace and whether a
   reasoning pass is shown). Both pills and the send action are clickable; the
   wheel over an open picker moves its selection.
4. **A message queue.** Type while a turn is working and your message queues
   above the composer instead of interrupting. **Enter** on an empty composer
   escalates the whole batch one rung — *send when the turn finishes* →
   *cut in at the next step boundary* → *stop the agent and send now* — or set
   a single message's release point with the `[Queued]` / `[Boundary]` /
   `[Interrupt]` chips, or dismiss one with `[x]`.
5. **File writes and edits, shown as diffs.** When the agent touches a file it
   renders a diff — a header naming the file with its ±counts, then a
   left-guttered body (green additions, red removals, dim context). The first
   session opens on a completed write + edit so you can see it straight away;
   accepting its "Add tests…" suggestion writes a new file *live*, and the
   storefront session applies an edit live when you accept the rounding fix.
6. **Slash commands.** A bare **`/`** at the start of the composer opens a
   command palette (mirroring the web console's set). **↑/↓** navigate, **Tab**
   completes to `/name `, **Esc** dismisses without clearing, and **Enter** runs
   the highlighted command; rows are clickable too. `/new`, `/clear`, `/model`
   and `/effort` drive the real UI; the context/tooling commands (`/compact`,
   `/prune`, `/agents`, `/timers`, `/background`, `/export`) drop a simulated
   note into the transcript.
7. **A multi-line, wrapping composer.** **Shift+Enter** inserts a newline
   (**Alt+Enter** too, as a fallback for terminals that can't report
   Shift+Enter — the demo pushes keyboard-enhancement flags where supported);
   plain **Enter** still sends. The input box grows a row at a time as you type
   or wrap, up to eight rows, then scrolls internally to keep the caret in view.
   Long lines wrap rather than scroll sideways. The header carries the working
   directory's **live git state** after the repo — the current branch and
   whether the tree is clean or has *N* uncommitted changes — re-read on a slow
   timer (`src/tui/git.rs`).

Every control is mouse-drivable as well as keyboard-drivable. **⌃N** starts a
fresh session; **⌃C** quits. The runtime state machine that streams a turn,
lands a file diff, and decides where a queued message goes lives in
`src/tui/runner.rs`; the slash catalog is in `src/tui/command.rs`; the drawing
and its click-target map are in `src/tui/render.rs`.

## Environment

| variable        | purpose |
|-----------------|---------|
| `EXCOC_HOME`    | Directory for `excoc.sock`, `excoc.pid`, and `excoc.log` (plus the transient `excoc.sock.next` / `excoc.pid.next` during a handoff) |
| `EXCOC_TICK_MS` | Tick interval in milliseconds (default `1000`) |
| `EXCOC_INHERIT_OPENED_AT_MS` | Internal: set by a resetting daemon on its successor to inherit the open time. Not for manual use. |
