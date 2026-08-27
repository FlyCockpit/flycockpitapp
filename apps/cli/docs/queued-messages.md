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

Visual order is delivery order: the **steering · next turn** group on top,
**after completion** below. Toggling a class moves the message between groups
without reordering siblings.

## Setting

`queuedMessagesAsSteering` (extended config, `/settings` → Behavior, default
**on**):

- On: Enter during a run classes the message `steering`.
- Off: Enter during a run classes it `held`. Enter on an **empty** composer
  promotes the whole queue to `steering`.

Per-message and box-level toggles override the setting.

## Routing

Queued messages target the agent layer that was focused when they were
submitted. If a snapshot spans nested agent layers, Cockpit renders a separate
delivery batch for each target, focused/deepest first, matching the order in
which the agent stack will reach their boundaries.

## Controls

Box: `[send now] [steer all|hold all] [edit] [cancel]`. These are atomic
whole-queue operations, including when queued items span a focus transition.

Per message (hover or keyboard focus): `[send now] [steer|hold] [edit] [cancel]`.

Opening a per-message edit reserves that exact queue slot. Queue mutations are
serialized until the edit is committed or cancelled; reconnects retry the same
operation identity, so a lost acknowledgement cannot duplicate the message.
Existing image attachments remain attached when its text is edited. Explicitly
holding a message also clears any prior send-now escalation.

Edit-all merges messages into one buffer. The merged message takes the class of
the earliest-delivered member (steering if any member was steering). Per-message
edit keeps order and class.

See `crates/cockpit-tui/docs/keybindings.md` for keys.
