# Queued messages

While the agent is running, Enter does not start a second turn. The message is
queued and shown above the composer.

## Delivery classes

- **steering** — injected at the focused agent's next turn boundary (mid-run),
  as a separate user message with `SubmissionOrigin::ExternalRoot` (advances
  the activity epoch and fires UserPromptSubmit).
- **held** — delivered after the run completes.
- **send now** — an escalation, not a stored class. The in-flight tool is never
  killed. Backgroundable tools (`bash`) are intended to convert to async
  completion so the boundary arrives immediately; other tools wait for the next
  Continue/Done safe point.

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

Queued messages always target the focused agent layer. The box title names that
agent.

## Controls

Box: `[send now] [steer all|hold all] [edit] [cancel]`.

Per message (hover or keyboard focus): `[send now] [steer|hold] [edit] [cancel]`.

Edit-all merges messages into one buffer. The merged message takes the class of
the earliest-delivered member (steering if any member was steering). Per-message
edit keeps order and class.

See `crates/cockpit-tui/docs/keybindings.md` for keys.
