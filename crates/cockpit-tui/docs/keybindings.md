# Keybindings

Open the in-TUI keybinding overlay with `Ctrl+K` or `/keys`. `Esc`, `q`, or `Ctrl+K` closes it.

## Rules

Conversation rules are lineage-scoped advisory directives. `/rules` opens the panel; `/rule text` creates a user-attributed rule. `d` / `Space` revokes; `p` promotes the rule into the instructions file via a write-scoped subagent.

## Global

| Key | Action | Description |
| --- | --- | --- |
| `Ctrl+K` | keys | open/close this which-key overlay (also /keys) |
| `Ctrl+C` | interrupt | stop the running agent; press twice to quit |
| `Ctrl+D` | quit | exit when idle; guarded while work is active |
| `/` | commands | open the slash-command menu |

## Composer

| Key | Action | Description |
| --- | --- | --- |
| `Enter` | send | submit the message |
| `Ctrl+J` | newline | insert a newline |
| `Ctrl+T` | thinking | toggle reasoning blocks |
| `Ctrl+Y` | copy pick | pick a message or code block to copy |
| `Shift+Tab` | cycle agent | switch the primary agent |
| `@` | file tag | tag a file into the message |
| `↑/↓` | history | recall previously sent messages |
| `Alt+↑` | enter queue | on an empty composer, focus the queue box |
| `Esc` / `↓` | queue blur | return from a focused queued message to the composer |

## Queued messages

Messages submitted while a run is in flight sit in the queue box above the composer. `/settings` → **queued messages as steering** (default on) classes Enter-during-a-run as *steering* (next turn). Off classes them *held* (after completion); Enter on an empty composer then promotes the whole queue to steering.

| Key (queue focused) | Action | Description |
| --- | --- | --- |
| `s` | send now | deliver this message at the next safe boundary (never kills an in-flight tool) |
| `Shift+s` | send now all | deliver every queued message at the next safe boundary |
| `t` | toggle class | `[hold]` on a steering message, `[steer]` on a held one |
| `Shift+t` | steer/hold all | `[steer all]` when any message is held, `[hold all]` when all are steering |
| `e` | edit | edit this message in place |
| `↑` (above first row) | edit all | merge every queued message into the composer |
| `x` / `Delete` | cancel | drop this message; others stay queued |
| `Shift+x` / `Shift+Delete` | cancel all | drop every editable queued message |
| `Alt+↑` | enter queue | move focus from an empty composer into the queue |
| `↑/↓` | move | move among queued messages (next-turn group, then held) |

Box-level `[send now] [steer all\|hold all] [edit] [cancel]` also sit on the top border (mouse). Per-message buttons appear on hover or when that row is focused. Action keys never fire while the composer has focus.
| `PgUp/PgDn` | scroll | scroll the chat transcript; Shift+↑/↓ scrolls by line |
| `End` | live tail | jump to the newest messages |
| `Home` | sticky header | jump to the pinned previous user message when the composer is empty |
| `Ctrl+N` | scratchpad | open the project scratchpad |
| `Ctrl+G` | $EDITOR | edit the composer text in $EDITOR |
| `Esc` | normal/cancel | vim Normal mode, or cancel a slash query |

## Slash menu

| Key | Action | Description |
| --- | --- | --- |
| `↑/↓` | move | highlight a command |
| `Tab` | complete | complete / cycle the highlighted command |
| `Enter` | run | run the highlighted command |
| `Esc` | cancel | close the menu |

## Embedded pane

| Key | Action | Description |
| --- | --- | --- |
| `Ctrl+X` | close | force-close the embedded pane |
| `Ctrl+O` | focus | toggle focus between the pane and the composer |

## BTW pane

| Key | Action | Description |
| --- | --- | --- |
| `Ctrl+B` | focus | toggle focus between the btw pane and main composer |
| `F11` | zoom | toggle the btw pane full-screen |
| `Esc` | main focus | return to main composer when the side composer is idle |
| `Enter` | send | submit the side-pane message |

## Question

| Key | Action | Description |
| --- | --- | --- |
| `1-9` | select | choose a numbered option |
| `1-9/Enter` | select | select an approval option |
| `1-9/Space` | toggle | toggle a multiselect option |
| `↑/↓ or j/k` | move | highlight an option |
| `Enter` | choose | choose the highlighted answer |
| `Enter` | confirm | confirm a selected approval choice |
| `←/→ or h/l` | questions | move between question pages |
| `Space` | select/toggle | select or toggle without advancing |
| `Enter` | select/confirm | select, then confirm permission choices |
| `PgUp/PgDn` | prompt scroll | scroll dialog prompt content |
| `Shift+PgUp/PgDn` | chat scroll | scroll the transcript behind the dialog |
| `Ctrl+E` | expand | expand or collapse the dialog |
| `Ctrl+E` | collapse | collapse the dialog |
| `Esc` | cancel | cancel the dialog |
| `type` | answer | type a free-text answer |
| `Enter` | done | finish editing |
| `Enter` | submit | submit all answers |
| `←/h` | back | return to the previous question |

## Approval

| Key | Action | Description |
| --- | --- | --- |
| `1-9` | select | choose a numbered option |
| `1-9/Enter` | select | select an approval option |
| `1-9/Space` | toggle | toggle a multiselect option |
| `↑/↓ or j/k` | move | highlight an option |
| `Enter` | choose | choose the highlighted answer |
| `Enter` | confirm | confirm a selected approval choice |
| `←/→ or h/l` | questions | move between question pages |
| `Space` | select/toggle | select or toggle without advancing |
| `Enter` | select/confirm | select, then confirm permission choices |
| `PgUp/PgDn` | prompt scroll | scroll dialog prompt content |
| `Shift+PgUp/PgDn` | chat scroll | scroll the transcript behind the dialog |
| `Ctrl+E` | expand | expand or collapse the dialog |
| `Ctrl+E` | collapse | collapse the dialog |
| `Esc` | cancel | cancel the dialog |
| `type` | answer | type a free-text answer |
| `Enter` | done | finish editing |
| `Enter` | submit | submit all answers |
| `←/h` | back | return to the previous question |

## Model picker

| Key | Action | Description |
| --- | --- | --- |
| `↑/↓` | move | highlight a model |
| `type` | filter | filter the model list |
| `Enter` | select | switch to the highlighted model |
| `Ctrl+Enter` | make default | switch this session and save the future-session default |
| `Ctrl+A` | add model | add a model to the scoped provider |
| `Esc` | cancel | close without changing the model |

## Settings

| Key | Action | Description |
| --- | --- | --- |
| `↑/↓` | move | navigate settings |
| `Enter` | edit | open/toggle the highlighted setting |
| `Tab` | section | switch between settings sections |
| `Esc` | close | back out / close settings |

## Sessions

| Key | Action | Description |
| --- | --- | --- |
| `↑/↓` | move | highlight a session |
| `Enter` | resume | resume the highlighted session |
| `i` | inbox source | open the latest assistant inbox source thread |
| `n` | inbox | show notify and pending assistant inbox entries |
| `→/l` | forks | descend into a session's forks |
| `e` | windows | expand a compaction lineage |
| `←/h` | back | ascend to the parent level |
| `a` | archived | toggle showing archived sessions |
| `u / d` | archive | unarchive / archive the highlighted session |
| `q · Esc` | close | close the browser |

## Permissions

| Key | Action | Description |
| --- | --- | --- |
| `↑/↓` | move | highlight a grant |
| `d · Del` | delete | remove the highlighted grant |
| `q · Esc` | close | close the pane |

## Resources

| Key | Action | Description |
| --- | --- | --- |
| `↑/↓` | move | highlight a queued resource request |
| `Enter/Space` | promote | move the highlighted request to the front |
| `r` | refresh | reload scheduler state |
| `q/Esc` | close | close the resources pane |

## Quick settings

| Key | Action | Description |
| --- | --- | --- |
| `Tab/→/l` | next | switch to the next settings tab |
| `Shift+Tab/←/h` | previous | switch to the previous settings tab |
| `↑/↓/j/k` | move | highlight an option in the active tab |
| `Space` | stage | stage the highlighted option |
| `Enter` | commit | apply staged session-only changes |
| `Esc` | discard | close without applying staged changes |

## Scratchpad

| Key | Action | Description |
| --- | --- | --- |
| `↑/↓` | move | highlight a note (or the + new row) |
| `Enter · e` | edit | edit the highlighted note |
| `n` | new | create a new note |
| `r` | rename | rename the highlighted note |
| `d` | delete | delete the highlighted note |
| `Ctrl+S` | save | save + leave edit mode |
| `q · Esc` | close | close the scratchpad |

## Diff

| Key | Action | Description |
| --- | --- | --- |
| `↑/↓ j/k` | file | move between changed files |
| `PgUp/PgDn` | scroll | page the selected diff body |
| `Ctrl+U/D` | scroll | page up or down in the selected diff body |
| `g/G` | top/bottom | jump to the top or bottom of the diff body |
| `Tab` | source | cycle worktree, staged, and last edit |
| `w` | wrap | toggle soft wrapping |
| `s` | side-by-side | toggle side-by-side rendering when wide enough |
| `Esc/q` | close | close the diff pane |

## Pins

| Key | Action | Description |
| --- | --- | --- |
| `↑/↓ · j/k` | move | scan pins / move the pick arrow |
| `Enter` | pin | pin the selected message (pick mode) |
| `d · Space` | unpin | unpin the highlighted pin (review mode) |
| `Esc` | close | leave pins, refocus the composer |
