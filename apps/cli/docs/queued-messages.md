# Queued messages

While the agent is running, Enter does not start a second turn. The message is
queued and shown above the composer.

## Delivery classes

- **steering** — injected at the focused agent's next turn boundary (mid-run),
  as a separate user message with `SubmissionOrigin::ExternalRoot` (advances
  the activity epoch and fires UserPromptSubmit).
- **held** — delivered after the run completes.
- **send now** — an escalation, not a stored class. The in-flight tool is never
  killed. A live `bash` process transfers to async completion so the boundary
  arrives immediately and its result attaches when the process exits; other
  tools finish normally and deliver at the resulting safe point.

Visual order is delivery order: the **Steer** group on top, **Held** below.
Selecting a class moves the message between groups without reordering
siblings. Send-now and Steer items share that top group and retain their
original queue order relative to one another.

## Setting

`queuedMessagesAsSteering` (extended config, `/settings` → Behavior, default
**off** / Held):

- Off (default): Enter during a run classes the message `held`.
- On: Enter during a run classes it `steering` (explicit opt-in).

Empty-composer Enter never submits text. An empty queue is a no-op; a
Held-only or mixed queue promotes every Held item to Steering; a
steering-only queue then requests Send now. A mixed queue therefore
promotes first and requests send-now only on the next empty Enter.

Per-message and box-level Held / Steer / Send now controls override the
setting.

## Routing

Queued messages target the agent layer that was focused when they were
submitted. If a snapshot spans nested agent layers, Cockpit renders a separate
delivery batch for each target, focused/deepest first, matching the order in
which the agent stack will reach their boundaries.

## Controls

Box: `[Send now] [Steer] [Held] [edit] [cancel]`. These are atomic
whole-queue operations, including when queued items span a focus transition.

Per message (hover or keyboard focus): `[Send now] [Steer] [Held] [edit] [cancel]`.

Opening a per-message edit reserves that exact queue slot. Queue mutations are
serialized until the edit is committed or cancelled; reconnects retry the same
operation identity, so a lost acknowledgement cannot duplicate the message.
Existing image attachments remain attached when its text is edited. Explicitly
holding a message also clears any prior send-now escalation.

Edit-all merges messages into one buffer. The merged message takes the class of
the earliest-delivered member (steering if any member was steering). Per-message
edit keeps order and class.

See `crates/cockpit-tui/docs/keybindings.md` for keys.
